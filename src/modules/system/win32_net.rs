use std::net::{IpAddr, Ipv4Addr};

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
    fn SendARP(dest_ip: u32, src_ip: u32, p_mac_addr: *mut u8, phy_addr_len: *mut u32) -> u32;
}

pub fn send_arp_probe(ip: Ipv4Addr) -> Option<String> {
    #[cfg(windows)]
    {
        let dest_ip = u32::from_ne_bytes(ip.octets());
        let mut mac = [0u8; 6];
        let mut len = 6u32;
        let res = unsafe { SendARP(dest_ip, 0, mac.as_mut_ptr(), &mut len) };
        if res == 0 && len == 6 {
            let mac_str = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
            if mac_str != "00:00:00:00:00:00" && mac_str != "FF:FF:FF:FF:FF:FF" {
                return Some(mac_str);
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        let _ = ip;
        None
    }
}

#[allow(dead_code)]
pub fn resolve_mac(ip: &IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => send_arp_probe(*v4),
        IpAddr::V6(_) => None,
    }
}

pub fn detect_default_gateway_ip() -> Option<String> {
    // Cached (60s TTL): netstat+PowerShell cost ~100ms+; hot paths like
    // classify_final call this per-device/per-packet and perf tests call it
    // 200k times. Never guess `.1` — return None when unknown.
    static CACHE: std::sync::OnceLock<
        std::sync::RwLock<(Option<String>, Option<std::time::Instant>)>,
    > = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::RwLock::new((None, None)));
    if let Ok(guard) = cache.read() {
        if let (Some(_), Some(at)) = (&guard.0, &guard.1) {
            if at.elapsed() < std::time::Duration::from_secs(60) {
                return guard.0.clone();
            }
        } else if let (None, Some(at)) = (&guard.0, &guard.1) {
            if at.elapsed() < std::time::Duration::from_secs(60) {
                return None;
            }
        }
    }
    let result = gateway_from_route_table();
    if let Ok(mut guard) = cache.write() {
        *guard = (result.clone(), Some(std::time::Instant::now()));
    }
    result
}

fn gateway_from_route_table() -> Option<String> {
    let output = crate::modules::system::silent_command("netstat")
        .args(["-rn"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut in_ipv4 = false;
    // Metric-aware: collect all default-route candidates, pick lowest metric.
    let mut candidates: Vec<(String, u32)> = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_lowercase();
        if lower.contains("ipv4") || lower.contains("internet destination") {
            in_ipv4 = true;
            continue;
        }
        if lower.contains("ipv6") {
            in_ipv4 = false;
            continue;
        }
        if lower.contains("active routes") && !in_ipv4 {
            continue;
        }
        if !in_ipv4 {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        // netstat -rn: Network Destination | Netmask | Gateway | Interface | Metric
        if parts.len() >= 3 {
            let dest = parts[0];
            let netmask = parts[1];
            let gw = parts[2];
            let is_default = dest == "0.0.0.0" || dest == "default";
            let is_default_mask = netmask == "0.0.0.0" || netmask == "0";
            if is_default && is_default_mask && gw.parse::<std::net::Ipv4Addr>().is_ok() {
                // Metric is column 5 (index 4) when present; default to MAX so
                // entries without metric lose to ones with a real metric.
                let metric: u32 = parts
                    .get(4)
                    .and_then(|m| m.parse().ok())
                    .unwrap_or(u32::MAX);
                candidates.push((gw.to_string(), metric));
            }
        }
    }
    if !candidates.is_empty() {
        candidates.sort_by_key(|(_, m)| *m);
        return Some(candidates[0].0.clone());
    }
    // Fallback: PowerShell Get-NetIPConfiguration (English + structured).
    // Prefer lowest-metric gateway when several exist.
    let ps = crate::modules::system::silent_command("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4DefaultGateway.NextHop",
        ])
        .output()
        .ok()?;
    let hop = String::from_utf8_lossy(&ps.stdout).trim().to_string();
    if hop.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(hop);
    }
    None
}
