use std::process::Command;
use tracing::{info, warn};

fn get_active_adapters() -> Vec<String> {
    let output = match Command::new("netsh")
        .args(["interface", "show", "interface"])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            warn!("Failed to list interfaces: {}", e);
            return vec!["Wi-Fi".into(), "Ethernet".into()];
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut adapters = Vec::new();
    for line in stdout.lines().skip(3) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[1] == "Connected" {
            let name = parts[3..].join(" ");
            if !name.is_empty() {
                adapters.push(name);
            }
        }
    }
    if adapters.is_empty() {
        adapters = vec!["Wi-Fi".into(), "Ethernet".into()];
    }
    adapters
}

pub fn set_system_dns(dns_server: &str) -> Result<(), String> {
    let adapters = get_active_adapters();
    let mut last_err = String::new();
    for adapter in &adapters {
        let output = Command::new("netsh")
            .args([
                "interface", "ip", "set", "dns",
                &format!("name={}", adapter),
                "static", dns_server, "primary",
            ])
            .output()
            .map_err(|e| format!("Failed to run netsh: {}", e))?;
        if output.status.success() {
            info!("System DNS set to {} on adapter '{}'", dns_server, adapter);
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("netsh failed for '{}': {}", adapter, stderr.trim());
        last_err = stderr.to_string();
    }
    Err(format!("Failed to set DNS on all adapters: {}", last_err.trim()))
}

pub fn restore_system_dns() -> Result<(), String> {
    let adapters = get_active_adapters();
    for adapter in &adapters {
        let output = Command::new("netsh")
            .args([
                "interface", "ip", "set", "dns",
                &format!("name={}", adapter),
                "dhcp",
            ])
            .output()
            .map_err(|e| format!("Failed to run netsh: {}", e))?;
        if output.status.success() {
            info!("DNS restored to DHCP on adapter '{}'", adapter);
            return Ok(());
        }
    }
    info!("System DNS restore attempted");
    Ok(())
}
