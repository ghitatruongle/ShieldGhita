use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tracing::info;

static DNS_OVERRIDDEN: AtomicBool = AtomicBool::new(false);
static MASTER_INTERNET_LOCKED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
pub enum AdapterDnsState {
    Dhcp,
    Static(Vec<String>),
}

static ORIGINAL_DNS_SETTINGS: RwLock<Option<HashMap<String, AdapterDnsState>>> = RwLock::new(None);
static ORIGINAL_IPV6_DNS_SETTINGS: RwLock<Option<HashMap<String, AdapterDnsState>>> =
    RwLock::new(None);
static CLEANUP_LOCK: Mutex<()> = Mutex::new(());

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub fn silent_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok() {
            let mut elevation = TOKEN_ELEVATION::default();
            let mut return_length = 0;
            let res = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            );
            let _ = windows::Win32::Foundation::CloseHandle(token);
            if res.is_ok() {
                return elevation.TokenIsElevated != 0;
            }
        }
    }
    // Fail closed: do not claim elevation when the token query fails.
    false
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    true
}

pub fn get_active_adapters() -> Vec<String> {
    let mut adapters = Vec::new();

    if let Ok(output) = silent_command("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(3) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let state = parts[3].to_lowercase();
                if state == "connected" || state == "connected." || state.contains("kết") {
                    let name = parts[4..].join(" ");
                    if is_valid_physical_adapter(&name) {
                        adapters.push(name);
                    }
                }
            }
        }
    }

    if adapters.is_empty() {
        if let Ok(output) = silent_command("powershell")
            .args(["-NoProfile", "-Command", "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let name = line.trim();
                if !name.is_empty() && is_valid_physical_adapter(name) {
                    adapters.push(name.to_string());
                }
            }
        }
    }

    if adapters.is_empty() {
        // Do not guess adapter names — configuring a non-existent "Wi-Fi" /
        // "Ethernet" via netsh fails or touches the wrong NIC. Return empty
        // and let callers (set_system_dns) surface a proper error.
        tracing::warn!(
            "DNS manager: no active physical adapters detected (netsh + Get-NetAdapter empty)"
        );
    }

    adapters.dedup();
    adapters
}

fn is_valid_physical_adapter(name: &str) -> bool {
    let lower = name.to_lowercase();
    !lower.contains("loopback")
        && !lower.contains("vmware")
        && !lower.contains("virtualbox")
        && !lower.contains("vbox")
        && !lower.contains("vethernet")
        && !lower.contains("bluetooth")
        && !lower.contains("local area connection*")
        && !lower.contains("pseudo")
        && !lower.is_empty()
}

pub fn get_current_adapter_dns(adapter: &str) -> AdapterDnsState {
    get_current_adapter_dns_inner(adapter, false)
}

fn get_current_adapter_dns_inner(adapter: &str, include_loopback: bool) -> AdapterDnsState {
    let output = match silent_command("netsh")
        .args([
            "interface",
            "ip",
            "show",
            "dns",
            &format!("name=\"{}\"", adapter),
        ])
        .output()
    {
        Ok(o) => o,
        Err(_) => return AdapterDnsState::Dhcp,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut static_servers = Vec::new();
    let mut is_static_section = false;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.to_lowercase().contains("dhcp") {
            is_static_section = false;
        } else if trimmed.to_lowercase().contains("statically")
            || trimmed.to_lowercase().contains("tĩnh")
        {
            is_static_section = true;
            if let Some(pos) = trimmed.find(':') {
                let ip = trimmed[pos + 1..].trim();
                if !ip.is_empty()
                    && ip != "None"
                    && (include_loopback || (ip != "127.0.0.1" && ip != "127.0.0.2"))
                {
                    // Only accept parseable IPs in the header line too.
                    if include_loopback || ip.parse::<std::net::IpAddr>().is_ok() {
                        static_servers.push(ip.to_string());
                    }
                }
            }
        } else if is_static_section {
            let ip = trimmed;
            if !ip.is_empty()
                && ip != "None"
                && (include_loopback || (ip != "127.0.0.1" && ip != "127.0.0.2"))
                && ip.parse::<std::net::IpAddr>().is_ok()
            {
                static_servers.push(ip.to_string());
            }
        }
    }

    if !static_servers.is_empty() {
        AdapterDnsState::Static(static_servers)
    } else {
        AdapterDnsState::Dhcp
    }
}

fn get_current_adapter_ipv6_dns(adapter: &str) -> AdapterDnsState {
    let output = match silent_command("netsh")
        .args([
            "interface",
            "ipv6",
            "show",
            "dnsservers",
            &format!("name=\"{}\"", adapter),
        ])
        .output()
    {
        Ok(o) => o,
        Err(_) => return AdapterDnsState::Dhcp,
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut servers = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.to_lowercase().contains("dns") || trimmed.contains("---") {
            continue;
        }
        // netsh ipv6 show dnsservers prints one address per line (may include zone id %).
        let candidate = trimmed.split_whitespace().next().unwrap_or("").trim();
        if candidate.is_empty() || candidate.eq_ignore_ascii_case("None") {
            continue;
        }
        let bare = candidate.split('%').next().unwrap_or(candidate);
        if bare.parse::<std::net::IpAddr>().is_ok() {
            servers.push(candidate.to_string());
        }
    }
    if !servers.is_empty() {
        AdapterDnsState::Static(servers)
    } else {
        AdapterDnsState::Dhcp
    }
}

pub fn flush_dns_cache() {
    let _ = silent_command("ipconfig").arg("/flushdns").output();
}

pub fn set_system_dns(dns_server: &str) -> Result<(), String> {
    let _guard = CLEANUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let adapters = get_active_adapters();
    if adapters.is_empty() {
        return Err("No active network adapters detected; refusing to guess".to_string());
    }
    let mut success_count = 0;
    let mut last_err = String::new();
    let mut failed_adapters: Vec<String> = Vec::new();

    {
        // Backup on every call for adapters missing from the map (new NICs,
        // VPNs, docks appearing after the first override).
        let mut orig_guard = ORIGINAL_DNS_SETTINGS
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if orig_guard.is_none() {
            *orig_guard = Some(HashMap::new());
        }
        if let Some(map) = orig_guard.as_mut() {
            for adapter in &adapters {
                if !map.contains_key(adapter) {
                    let state = get_current_adapter_dns(adapter);
                    map.insert(adapter.clone(), state);
                }
            }
        }
        let mut orig6_guard = ORIGINAL_IPV6_DNS_SETTINGS
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if orig6_guard.is_none() {
            *orig6_guard = Some(HashMap::new());
        }
        if let Some(map6) = orig6_guard.as_mut() {
            for adapter in &adapters {
                if !map6.contains_key(adapter) {
                    let state6 = get_current_adapter_ipv6_dns(adapter);
                    map6.insert(adapter.clone(), state6);
                }
            }
        }
    }

    let clean_server = dns_server.replace('\'', "''");

    for adapter in &adapters {
        let output = silent_command("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "dns",
                &format!("name=\"{}\"", adapter),
                "static",
                dns_server,
                "primary",
                "validate=no",
            ])
            .output();

        let mut adapter_ok = false;
        match output {
            Ok(o) if o.status.success() => {
                info!(
                    "Master DNS Controller: Netsh set IPv4 DNS to {} on '{}'",
                    dns_server, adapter
                );
                adapter_ok = true;
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                last_err = stderr.to_string();
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }

        if !adapter_ok {
            let clean_adapter = adapter.replace('\'', "''");
            let ps_script = format!(
                "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses ('{}') -ErrorAction SilentlyContinue",
                clean_adapter, clean_server
            );
            if let Ok(ps_out) = silent_command("powershell")
                .args(["-NoProfile", "-Command", &ps_script])
                .output()
            {
                if ps_out.status.success() {
                    info!(
                        "Master DNS Controller: PowerShell set IPv4 DNS to {} on '{}'",
                        dns_server, adapter
                    );
                    adapter_ok = true;
                } else {
                    let stderr = String::from_utf8_lossy(&ps_out.stderr);
                    if !stderr.trim().is_empty() {
                        last_err = stderr.to_string();
                    }
                }
            }
        }

        if adapter_ok {
            success_count += 1;
        } else {
            failed_adapters.push(adapter.clone());
        }

        let _ = silent_command("netsh")
            .args([
                "interface",
                "ipv6",
                "set",
                "dns",
                &format!("name=\"{}\"", adapter),
                "dhcp",
            ])
            .output();
    }

    flush_dns_cache();

    if !failed_adapters.is_empty() {
        tracing::warn!(
            "Master DNS Controller: partial failure setting DNS to {} — failed on: {} (succeeded on {}/{})",
            dns_server,
            failed_adapters.join(", "),
            success_count,
            adapters.len()
        );
    }

    if success_count > 0 {
        DNS_OVERRIDDEN.store(true, Ordering::SeqCst);
        if !failed_adapters.is_empty() {
            return Err(format!(
                "Partial failure setting DNS to {}: failed on [{}]; last error: {}",
                dns_server,
                failed_adapters.join(", "),
                last_err.trim()
            ));
        }
        Ok(())
    } else {
        Err(format!("Failed to set DNS: {}", last_err.trim()))
    }
}

pub fn restore_system_dns() -> Result<(), String> {
    restore_system_dns_inner(true)
}

/// Restore without taking `CLEANUP_LOCK` when called from a panic hook that
/// may already hold it on this thread (would deadlock).
fn restore_system_dns_inner(take_lock: bool) -> Result<(), String> {
    let _guard = if take_lock {
        Some(CLEANUP_LOCK.lock().unwrap_or_else(|e| e.into_inner()))
    } else {
        None
    };
    let adapters = get_active_adapters();
    let backup_map = {
        let mut orig_guard = ORIGINAL_DNS_SETTINGS
            .write()
            .unwrap_or_else(|e| e.into_inner());
        orig_guard.take()
    };

    // Only touch adapters we actually overrode. Forcing DHCP on unknown
    // adapters (VPN, dock NICs that appeared later) wipes intentional static DNS.
    let Some(backup_map) = backup_map else {
        DNS_OVERRIDDEN.store(false, Ordering::SeqCst);
        return Ok(());
    };

    let backup_map6 = {
        let mut orig6_guard = ORIGINAL_IPV6_DNS_SETTINGS
            .write()
            .unwrap_or_else(|e| e.into_inner());
        orig6_guard.take()
    };

    for adapter in &adapters {
        let Some(original_state) = backup_map.get(adapter).cloned() else {
            continue;
        };

        let clean_adapter = adapter.replace('\'', "''");

        match original_state {
            AdapterDnsState::Dhcp => {
                let _ = silent_command("netsh")
                    .args([
                        "interface",
                        "ip",
                        "set",
                        "dns",
                        &format!("name=\"{}\"", adapter),
                        "dhcp",
                    ])
                    .output();
                let _ = silent_command("powershell")
                    .args([
                        "-NoProfile", "-Command",
                        &format!("Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses -ErrorAction SilentlyContinue", clean_adapter)
                    ])
                    .output();
            }
            AdapterDnsState::Static(ref ips) => {
                if let Some(first_ip) = ips.first() {
                    let _ = silent_command("netsh")
                        .args([
                            "interface",
                            "ip",
                            "set",
                            "dns",
                            &format!("name=\"{}\"", adapter),
                            "static",
                            first_ip,
                            "primary",
                        ])
                        .output();

                    for (idx, next_ip) in ips.iter().skip(1).enumerate() {
                        let _ = silent_command("netsh")
                            .args([
                                "interface",
                                "ip",
                                "add",
                                "dns",
                                &format!("name=\"{}\"", adapter),
                                next_ip,
                                &format!("index={}", idx + 2),
                            ])
                            .output();
                    }
                } else {
                    let _ = silent_command("netsh")
                        .args([
                            "interface",
                            "ip",
                            "set",
                            "dns",
                            &format!("name=\"{}\"", adapter),
                            "dhcp",
                        ])
                        .output();
                }
            }
        }

        // IPv6: restore backed-up state instead of forcing DHCP.
        if let Some(map6) = backup_map6.as_ref() {
            if let Some(state6) = map6.get(adapter) {
                match state6 {
                    AdapterDnsState::Dhcp => {
                        let _ = silent_command("netsh")
                            .args([
                                "interface",
                                "ipv6",
                                "set",
                                "dns",
                                &format!("name=\"{}\"", adapter),
                                "dhcp",
                            ])
                            .output();
                    }
                    AdapterDnsState::Static(ips6) => {
                        if let Some(first6) = ips6.first() {
                            let _ = silent_command("netsh")
                                .args([
                                    "interface",
                                    "ipv6",
                                    "set",
                                    "dns",
                                    &format!("name=\"{}\"", adapter),
                                    "static",
                                    first6,
                                    "primary",
                                ])
                                .output();
                            for (idx, next6) in ips6.iter().skip(1).enumerate() {
                                let _ = silent_command("netsh")
                                    .args([
                                        "interface",
                                        "ipv6",
                                        "add",
                                        "dns",
                                        &format!("name=\"{}\"", adapter),
                                        next6,
                                        &format!("index={}", idx + 2),
                                    ])
                                    .output();
                            }
                        } else {
                            let _ = silent_command("netsh")
                                .args([
                                    "interface",
                                    "ipv6",
                                    "set",
                                    "dns",
                                    &format!("name=\"{}\"", adapter),
                                    "dhcp",
                                ])
                                .output();
                        }
                    }
                }
            }
        }
    }

    flush_dns_cache();
    DNS_OVERRIDDEN.store(false, Ordering::SeqCst);
    info!("Master DNS Controller: System DNS fully restored to original state");
    Ok(())
}

pub fn set_master_internet_lock(locked: bool) -> Result<(), String> {
    let prev = MASTER_INTERNET_LOCKED.load(Ordering::SeqCst);
    let target = if locked { "127.0.0.2" } else { "127.0.0.1" };
    match set_system_dns(target) {
        Ok(()) => {
            MASTER_INTERNET_LOCKED.store(locked, Ordering::SeqCst);
            if locked {
                info!("MASTER INTERNET LOCK ACTIVATED: All external DNS blackholed");
            } else {
                info!("MASTER INTERNET LOCK DEACTIVATED: Normal protection resumed");
            }
            Ok(())
        }
        Err(e) => {
            // Rollback flag on failure — only set after Ok.
            MASTER_INTERNET_LOCKED.store(prev, Ordering::SeqCst);
            Err(e)
        }
    }
}

pub fn is_master_internet_locked() -> bool {
    MASTER_INTERNET_LOCKED.load(Ordering::Relaxed)
}

#[allow(dead_code)]
pub fn is_dns_overridden() -> bool {
    DNS_OVERRIDDEN.load(Ordering::Relaxed)
}

fn system_dns_matches(target: &str) -> bool {
    let adapters = get_active_adapters();
    if adapters.is_empty() {
        return false;
    }
    for adapter in &adapters {
        // Must include loopback (127.0.0.1/127.0.0.2) — the guard enforces our
        // own listener as system DNS, so filtering loopback would never match
        // and cause a constant fight loop.
        match get_current_adapter_dns_inner(adapter, true) {
            AdapterDnsState::Static(ips) => {
                if !ips.iter().any(|ip| ip == target) {
                    return false;
                }
            }
            AdapterDnsState::Dhcp => return false,
        }
    }
    true
}

pub async fn start_dns_guard_watchdog(protection_enabled: Arc<AtomicBool>, listen_addr: String) {
    let mut interval_secs: u64 = 8;
    let mut fight_streak: u32 = 0;
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
        if !(protection_enabled.load(Ordering::Relaxed)
            && !MASTER_INTERNET_LOCKED.load(Ordering::Relaxed)
            && DNS_OVERRIDDEN.load(Ordering::Relaxed))
        {
            if fight_streak > 0 {
                info!(
                    "DNS guard: protection off, releasing enforcement (was fighting {} cycles)",
                    fight_streak
                );
                fight_streak = 0;
            }
            interval_secs = 8;
            continue;
        }
        if system_dns_matches(&listen_addr) {
            if fight_streak > 0 {
                info!(
                    "DNS guard: system DNS stable again after {} fight cycle(s)",
                    fight_streak
                );
                fight_streak = 0;
            }
            interval_secs = 8;
            continue;
        }
        // netsh/PowerShell are blocking; keep them off the async worker threads.
        let enforcement_addr = listen_addr.clone();
        let result = tokio::task::spawn_blocking(move || set_system_dns(&enforcement_addr))
            .await
            .unwrap_or_else(|e| Err(format!("dns guard task join: {}", e)));
        if let Err(e) = result {
            tracing::warn!("DNS guard: enforcement attempt failed: {}", e);
        }
        fight_streak += 1;
        if fight_streak >= 3 {
            tracing::warn!(
                "DNS guard: external change keeps reverting DNS ({} consecutive fixes). Backing off to reduce churn",
                fight_streak
            );
            interval_secs = (interval_secs * 2).min(300);
        }
    }
}

pub fn get_lan_ip_address() -> String {
    if let Some(ip) = crate::modules::monitor::lan_scanner::LanScanner::get_local_outbound_ip() {
        ip.to_string()
    } else {
        "127.0.0.1".to_string()
    }
}

pub fn configure_lan_dns_firewall(enable: bool) {
    if enable {
        let _ = silent_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=ShieldGhita_LAN_DNS",
                "dir=in",
                "action=allow",
                "protocol=UDP",
                "localport=53",
                "remoteip=LocalSubnet",
            ])
            .output();

        let _ = silent_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=ShieldGhita_LAN_DNS_TCP",
                "dir=in",
                "action=allow",
                "protocol=TCP",
                "localport=53",
                "remoteip=LocalSubnet",
            ])
            .output();
        info!("Windows Firewall rule configured: Port 53 UDP/TCP opened for LAN Network Adblock");
    } else {
        let _ = silent_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=ShieldGhita_LAN_DNS",
            ])
            .output();

        let _ = silent_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=ShieldGhita_LAN_DNS_TCP",
            ])
            .output();
        info!("Windows Firewall rule cleaned up: Port 53 LAN access closed");
    }
}

pub fn register_safety_cleanup() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        if DNS_OVERRIDDEN.load(Ordering::SeqCst) {
            eprintln!("[SHIELD GHITA EMERGENCY] Panic detected, restoring system DNS...");
            // Avoid re-entering CLEANUP_LOCK if the panic happened while a guard
            // was held on this thread — that would deadlock the emergency path.
            let _ = restore_system_dns_inner(false);
        }
        default_hook(panic_info);
    }));

    #[cfg(windows)]
    unsafe {
        use windows::Win32::System::Console::SetConsoleCtrlHandler;
        unsafe extern "system" fn ctrl_handler(_: u32) -> windows::Win32::Foundation::BOOL {
            if DNS_OVERRIDDEN.load(Ordering::SeqCst) {
                // Ctrl handlers run under severe restrictions; try a lock-free
                // restore and still report handled so Windows gives us a moment.
                let _ = restore_system_dns_inner(false);
            }
            // Return TRUE so the default handler (immediate terminate) is delayed
            // long enough for the restore attempt to finish.
            windows::Win32::Foundation::BOOL(1)
        }
        let _ = SetConsoleCtrlHandler(Some(ctrl_handler), true);
    }
}
