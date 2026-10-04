use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

static DNS_OVERRIDDEN: AtomicBool = AtomicBool::new(false);
static MASTER_INTERNET_LOCKED: AtomicBool = AtomicBool::new(false);
static LAN_ONLY_MODE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdapterDnsState {
    Dhcp,
    Static(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsController {
    OtherLoopbackResolver {
        adapter: String,
        servers: Vec<String>,
    },
    KnownProduct {
        adapter: String,
    },
}

const AGENT_ADAPTER_HINTS: &[&str] = &[
    "warp",
    "cloudflare",
    "nordlynx",
    "wireguard",
    "tailscale",
    "zerotier",
    "adguard",
    "mullvad",
    "protonvpn",
    "expressvpn",
    "anyconnect",
    "forticlient",
    "zscaler",
    "kaspersky",
    "bitdefender",
    "norton",
    "sophos",
    "malwarebytes",
    "eset",
    "f-secure",
    "avast",
    "avg",
    "avira",
    "fortinet",
    "paloalto",
];

pub fn classify_dns_servers(adapter: &str, ips: &[String]) -> Option<DnsController> {
    for ip in ips {
        let Ok(parsed) = ip.trim().parse::<std::net::IpAddr>() else {
            continue;
        };
        if !parsed.is_loopback() {
            continue;
        }
        let normalized = ip.trim();
        if normalized == "127.0.0.1" || normalized == "127.0.0.2" {
            continue;
        }
        return Some(DnsController::OtherLoopbackResolver {
            adapter: adapter.to_string(),
            servers: ips.to_vec(),
        });
    }
    let lowered = adapter.to_lowercase();
    if AGENT_ADAPTER_HINTS
        .iter()
        .any(|hint| lowered.contains(hint))
    {
        return Some(DnsController::KnownProduct {
            adapter: adapter.to_string(),
        });
    }
    None
}

pub fn detect_dns_controller_conflict() -> Option<DnsController> {
    for adapter in get_active_adapters() {
        let AdapterDnsState::Static(ips) = get_current_adapter_dns_inner(&adapter, true) else {
            continue;
        };
        if let Some(found) = classify_dns_servers(&adapter, &ips) {
            return Some(found);
        }
    }
    None
}

pub fn describe_dns_controller(conflict: &DnsController) -> String {
    match conflict {
        DnsController::OtherLoopbackResolver { adapter, servers } => format!(
            "{} {} ({})",
            crate::modules::i18n::tr4(
                "Phát hiện xung đột:",
                "Conflict detected:",
                "检测到冲突：",
                "Обнаружен конфликт:"
            ),
            adapter,
            servers.join(", ")
        ),
        DnsController::KnownProduct { adapter } => format!(
            "{} {}",
            crate::modules::i18n::tr4(
                "Phát hiện VPN/phần mềm bảo mật:",
                "Detected VPN / security product:",
                "检测到 VPN/安全软件：",
                "Обнаружен VPN / средство защиты:"
            ),
            adapter
        ),
    }
}

pub fn set_lan_only_mode(enabled: bool) {
    LAN_ONLY_MODE.store(enabled, Ordering::SeqCst);
}

pub fn is_lan_only_mode() -> bool {
    LAN_ONLY_MODE.load(Ordering::Relaxed)
}

fn local_resolver_responsive(listen_addr: &str) -> bool {
    use std::net::UdpSocket;
    let bind: std::net::IpAddr = match listen_addr.parse() {
        Ok(ip) => ip,
        Err(_) => std::net::IpAddr::from([127, 0, 0, 1]),
    };
    let target = std::net::SocketAddr::new(bind, 53);
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return false;
    };
    if socket
        .set_read_timeout(Some(Duration::from_millis(400)))
        .is_err()
    {
        return false;
    }
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in "shieldghita-liveness-probe".split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    if socket.send_to(&query, target).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    matches!(socket.recv_from(&mut buf), Ok((size, _)) if size >= 12)
}

pub fn should_yield(fight_streak: u32, elapsed: Duration) -> bool {
    fight_streak >= 5 || elapsed >= Duration::from_secs(120)
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
        persist_override_backup();
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

#[derive(Serialize, Deserialize)]
struct OverrideBackupFile {
    ipv4: HashMap<String, AdapterDnsState>,
    ipv6: HashMap<String, AdapterDnsState>,
}

fn override_backup_path() -> std::path::PathBuf {
    let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(app_data)
        .join("ShieldGhita")
        .join("dns_override_backup.json")
}

fn persist_override_backup() {
    let ipv4 = ORIGINAL_DNS_SETTINGS
        .read()
        .ok()
        .and_then(|guard| guard.clone());
    let ipv6 = ORIGINAL_IPV6_DNS_SETTINGS
        .read()
        .ok()
        .and_then(|guard| guard.clone());
    let Some((ipv4_map, ipv6_map)) = ipv4.zip(ipv6) else {
        return;
    };
    let path = override_backup_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let payload = serde_json::to_string(&OverrideBackupFile {
        ipv4: ipv4_map,
        ipv6: ipv6_map,
    });
    let Ok(payload) = payload else {
        return;
    };
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, payload).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

fn clear_override_backup() {
    let _ = std::fs::remove_file(override_backup_path());
}

/// Restore the DNS state saved before the last override. Covers hard kills
/// (Task Manager, crash, power loss) where the in-memory backup is lost and
/// the system would otherwise keep pointing at a resolver nobody is serving.
pub fn recover_stale_override_on_startup() -> Option<String> {
    let path = override_backup_path();
    let text = std::fs::read_to_string(&path).ok()?;
    let parsed: OverrideBackupFile = serde_json::from_str(&text).ok()?;
    if parsed.ipv4.is_empty() {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    {
        let mut guard = ORIGINAL_DNS_SETTINGS
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *guard = Some(parsed.ipv4);
        let mut guard6 = ORIGINAL_IPV6_DNS_SETTINGS
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *guard6 = Some(parsed.ipv6);
    }
    let result = restore_system_dns_inner(false);
    clear_override_backup();
    match result {
        Ok(()) => Some(
            crate::modules::i18n::tr4(
                "Đã phục hồi DNS gốc từ phiên trước bị ngắt đột ngột.",
                "Recovered the original DNS from a previous interrupted session.",
                "已从上次中断的会话恢复原始 DNS。",
                "Исходные DNS восстановлены после прерванного сеанса.",
            )
            .to_string(),
        ),
        Err(e) => Some(format!("stale DNS recovery failed: {e}")),
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
        clear_override_backup();
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
    clear_override_backup();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_flags_foreign_loopback_resolver() {
        let found =
            classify_dns_servers("Wi-Fi", &["127.0.2.2".to_string(), "127.0.2.3".to_string()]);
        assert_eq!(
            found,
            Some(DnsController::OtherLoopbackResolver {
                adapter: "Wi-Fi".to_string(),
                servers: vec!["127.0.2.2".to_string(), "127.0.2.3".to_string()],
            })
        );
        assert!(classify_dns_servers("Ethernet", &["192.0.2.1".to_string()]).is_none());
    }

    #[test]
    fn test_classify_ignores_our_own_targets() {
        assert!(classify_dns_servers("Wi-Fi", &["127.0.0.1".to_string()]).is_none());
        assert!(classify_dns_servers("Wi-Fi", &["127.0.0.2".to_string()]).is_none());
    }

    #[test]
    fn test_classify_detects_known_product_by_adapter_name() {
        assert_eq!(
            classify_dns_servers("CloudflareWARP", &["192.0.2.53".to_string()]),
            Some(DnsController::KnownProduct {
                adapter: "CloudflareWARP".to_string()
            })
        );
        assert!(classify_dns_servers("Ethernet 2", &["192.0.2.1".to_string()]).is_none());
    }

    #[test]
    fn test_should_yield_thresholds() {
        assert!(!should_yield(0, Duration::from_secs(5)));
        assert!(!should_yield(4, Duration::from_secs(10)));
        assert!(should_yield(5, Duration::from_secs(1)));
        assert!(should_yield(1, Duration::from_secs(120)));
        assert!(should_yield(1, Duration::from_secs(300)));
    }

    #[test]
    fn test_lan_only_mode_toggle() {
        set_lan_only_mode(false);
        assert!(!is_lan_only_mode());
        set_lan_only_mode(true);
        assert!(is_lan_only_mode());
        set_lan_only_mode(false);
    }
}

pub async fn start_dns_guard_watchdog(protection_enabled: Arc<AtomicBool>, listen_addr: String) {
    let mut interval_secs: u64 = 8;
    let mut fight_streak: u32 = 0;
    let mut fight_started: Option<Instant> = None;
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
                fight_started = None;
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
                fight_started = None;
            }
            interval_secs = 8;
            continue;
        }
        // Never force the system back onto a resolver that cannot answer: check
        // our own listener first, and restore the original DNS when it is dead
        // (a dead 127.0.0.1 resolver blacks out the whole machine).
        {
            let probe_addr = listen_addr.clone();
            let alive = tokio::task::spawn_blocking(move || local_resolver_responsive(&probe_addr))
                .await
                .unwrap_or(false);
            if !alive {
                let restore = tokio::task::spawn_blocking(restore_system_dns)
                    .await
                    .unwrap_or_else(|e| Err(format!("join: {e}")));
                set_lan_only_mode(true);
                fight_streak = 0;
                fight_started = None;
                interval_secs = 8;
                match restore {
                    Ok(()) => warn!(
                        "DNS guard: local resolver stopped answering — original DNS restored, switched to LAN-only mode"
                    ),
                    Err(e) => error!(
                        "DNS guard: local resolver dead and DNS restore failed ({}). Run the emergency restore action.",
                        e
                    ),
                }
                continue;
            }
        }
        // netsh/PowerShell are blocking; keep them off the async worker threads.
        let enforcement_addr = listen_addr.clone();
        let result = tokio::task::spawn_blocking(move || set_system_dns(&enforcement_addr))
            .await
            .unwrap_or_else(|e| Err(format!("dns guard task join: {}", e)));
        if let Err(e) = &result {
            tracing::warn!("DNS guard: enforcement attempt failed: {}", e);
        }
        if result.is_ok() {
            fight_streak = 0;
            fight_started = None;
            interval_secs = 8;
            continue;
        }
        fight_streak += 1;
        if fight_started.is_none() {
            fight_started = Some(Instant::now());
        }
        let elapsed = fight_started
            .map(|started| started.elapsed())
            .unwrap_or_default();
        if should_yield(fight_streak, elapsed) {
            let restore = tokio::task::spawn_blocking(restore_system_dns)
                .await
                .unwrap_or_else(|e| Err(format!("join: {e}")));
            set_lan_only_mode(true);
            fight_streak = 0;
            fight_started = None;
            interval_secs = 8;
            match restore {
                Ok(()) => warn!(
                    "DNS guard: gave up after {} failed enforcement(s) over {}s — original DNS restored, switched to LAN-only mode",
                    fight_streak,
                    elapsed.as_secs()
                ),
                Err(e) => error!(
                    "DNS guard: enforcement kept failing and DNS restore failed ({}). Use the emergency restore button.",
                    e
                ),
            }
            continue;
        }
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
