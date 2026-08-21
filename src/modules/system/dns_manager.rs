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
    true
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
        adapters = vec!["Wi-Fi".into(), "Ethernet".into()];
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
    let output = match silent_command("netsh")
        .args([
            "interface",
            "ip",
            "show",
            "dns",
            &format!("name={}", adapter),
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
                if !ip.is_empty() && ip != "None" && ip != "127.0.0.1" && ip != "127.0.0.2" {
                    static_servers.push(ip.to_string());
                }
            }
        } else if is_static_section {
            let ip = trimmed;
            if !ip.is_empty()
                && ip != "None"
                && ip != "127.0.0.1"
                && ip != "127.0.0.2"
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

pub fn flush_dns_cache() {
    let _ = silent_command("ipconfig").arg("/flushdns").output();
}

pub fn set_system_dns(dns_server: &str) -> Result<(), String> {
    let _guard = CLEANUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let adapters = get_active_adapters();
    let mut success_count = 0;
    let mut last_err = String::new();

    {
        let mut orig_guard = ORIGINAL_DNS_SETTINGS
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if orig_guard.is_none() {
            let mut backup_map = HashMap::new();
            for adapter in &adapters {
                let state = get_current_adapter_dns(adapter);
                backup_map.insert(adapter.clone(), state);
            }
            *orig_guard = Some(backup_map);
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
                &format!("name={}", adapter),
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
                }
            }
        }

        if adapter_ok {
            success_count += 1;
        }

        let _ = silent_command("netsh")
            .args([
                "interface",
                "ipv6",
                "set",
                "dns",
                &format!("name={}", adapter),
                "dhcp",
            ])
            .output();
    }

    flush_dns_cache();

    if success_count > 0 {
        DNS_OVERRIDDEN.store(true, Ordering::SeqCst);
        Ok(())
    } else {
        Err(format!("Failed to set DNS: {}", last_err.trim()))
    }
}

pub fn restore_system_dns() -> Result<(), String> {
    let _guard = CLEANUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let adapters = get_active_adapters();
    let backup_map = {
        let mut orig_guard = ORIGINAL_DNS_SETTINGS
            .write()
            .unwrap_or_else(|e| e.into_inner());
        orig_guard.take()
    };

    for adapter in &adapters {
        let original_state = backup_map
            .as_ref()
            .and_then(|m| m.get(adapter).cloned())
            .unwrap_or(AdapterDnsState::Dhcp);

        let clean_adapter = adapter.replace('\'', "''");

        match original_state {
            AdapterDnsState::Dhcp => {
                let _ = silent_command("netsh")
                    .args([
                        "interface",
                        "ip",
                        "set",
                        "dns",
                        &format!("name={}", adapter),
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
                            &format!("name={}", adapter),
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
                                &format!("name={}", adapter),
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
                            &format!("name={}", adapter),
                            "dhcp",
                        ])
                        .output();
                }
            }
        }

        let _ = silent_command("netsh")
            .args([
                "interface",
                "ipv6",
                "set",
                "dns",
                &format!("name={}", adapter),
                "dhcp",
            ])
            .output();
    }

    flush_dns_cache();
    DNS_OVERRIDDEN.store(false, Ordering::SeqCst);
    info!("Master DNS Controller: System DNS fully restored to original state");
    Ok(())
}

pub fn set_master_internet_lock(locked: bool) -> Result<(), String> {
    MASTER_INTERNET_LOCKED.store(locked, Ordering::SeqCst);
    if locked {
        info!("MASTER INTERNET LOCK ACTIVATED: All external DNS blackholed");
        set_system_dns("127.0.0.2")?;
    } else {
        info!("MASTER INTERNET LOCK DEACTIVATED: Normal protection resumed");
        set_system_dns("127.0.0.1")?;
    }
    Ok(())
}

pub fn is_master_internet_locked() -> bool {
    MASTER_INTERNET_LOCKED.load(Ordering::Relaxed)
}

#[allow(dead_code)]
pub fn is_dns_overridden() -> bool {
    DNS_OVERRIDDEN.load(Ordering::Relaxed)
}

pub async fn start_dns_guard_watchdog(protection_enabled: Arc<AtomicBool>, listen_addr: String) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(8)).await;
        if protection_enabled.load(Ordering::Relaxed)
            && !MASTER_INTERNET_LOCKED.load(Ordering::Relaxed)
            && DNS_OVERRIDDEN.load(Ordering::Relaxed)
        {
            let _ = set_system_dns(&listen_addr);
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
            let _ = restore_system_dns();
        }
        default_hook(panic_info);
    }));

    #[cfg(windows)]
    unsafe {
        use windows::Win32::System::Console::SetConsoleCtrlHandler;
        unsafe extern "system" fn ctrl_handler(_: u32) -> windows::Win32::Foundation::BOOL {
            if DNS_OVERRIDDEN.load(Ordering::SeqCst) {
                let _ = restore_system_dns();
            }
            windows::Win32::Foundation::BOOL(0)
        }
        let _ = SetConsoleCtrlHandler(Some(ctrl_handler), true);
    }
}
