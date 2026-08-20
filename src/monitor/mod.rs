use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDevice {
    pub name: String,
    pub ip: String,
    pub mac: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl NetworkDevice {
    pub fn traffic_display(&self) -> String {
        let total = self.bytes_sent + self.bytes_received;
        if total > 1_073_741_824 {
            format!("{:.1} GB", total as f64 / 1_073_741_824.0)
        } else if total > 1_048_576 {
            format!("{:.1} MB", total as f64 / 1_048_576.0)
        } else if total > 1024 {
            format!("{:.1} KB", total as f64 / 1024.0)
        } else {
            format!("{} B", total)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub domain: String,
    pub source_ip: String,
    pub is_blocked: bool,
}

pub struct NetworkMonitor {
    devices: Arc<RwLock<HashMap<String, NetworkDevice>>>,
    logs: Arc<RwLock<Vec<LogEntry>>>,
    max_logs: usize,
    log_file_path: PathBuf,
}

impl NetworkMonitor {
    pub fn new(max_logs: usize) -> Self {
        let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        let log_dir = PathBuf::from(app_data).join("ShieldGhita");
        let _ = fs::create_dir_all(&log_dir);
        let log_file_path = log_dir.join("dns_log.json");

        let monitor = Self {
            devices: Arc::new(RwLock::new(HashMap::new())),
            logs: Arc::new(RwLock::new(Vec::new())),
            max_logs,
            log_file_path,
        };

        monitor.load_logs_from_disk();
        monitor
    }

    fn load_logs_from_disk(&self) {
        if self.log_file_path.exists() {
            match fs::read_to_string(&self.log_file_path) {
                Ok(content) => {
                    if let Ok(entries) = serde_json::from_str::<Vec<LogEntry>>(&content) {
                        if let Ok(mut logs) = self.logs.write() {
                            *logs = entries;
                            info!("Loaded {} log entries from disk", logs.len());
                        }
                    }
                }
                Err(e) => warn!("Failed to read log file: {}", e),
            }
        }
    }

    fn save_logs_to_disk(&self) {
        if let Ok(logs) = self.logs.read() {
            match serde_json::to_string_pretty(&*logs) {
                Ok(json) => {
                    if let Err(e) = fs::write(&self.log_file_path, json) {
                        warn!("Failed to save logs: {}", e);
                    }
                }
                Err(e) => warn!("Failed to serialize logs: {}", e),
            }
        }
    }

    pub fn add_log(&self, domain: &str, source_ip: &str, is_blocked: bool) {
        let entry = LogEntry {
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            domain: domain.to_string(),
            source_ip: source_ip.to_string(),
            is_blocked,
        };

        if let Ok(mut logs) = self.logs.write() {
            logs.insert(0, entry);
            if logs.len() > self.max_logs {
                logs.truncate(self.max_logs);
            }
        }
    }

    pub fn get_logs(&self) -> Vec<LogEntry> {
        self.logs.read().map(|l| l.clone()).unwrap_or_default()
    }

    pub fn get_filtered_logs(&self, filter_domain: &str, filter_ip: &str, filter_blocked: Option<bool>) -> Vec<LogEntry> {
        self.logs
            .read()
            .map(|logs| {
                logs.iter()
                    .filter(|l| {
                        let domain_match = filter_domain.is_empty()
                            || l.domain.to_lowercase().contains(&filter_domain.to_lowercase());
                        let ip_match = filter_ip.is_empty()
                            || l.source_ip.contains(filter_ip);
                        let blocked_match = filter_blocked.is_none_or(|b| l.is_blocked == b);
                        domain_match && ip_match && blocked_match
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn clear_logs(&self) {
        if let Ok(mut logs) = self.logs.write() {
            logs.clear();
        }
        self.save_logs_to_disk();
    }

    pub fn export_logs_csv(&self) -> Result<String, String> {
        let logs = self.logs.read().map_err(|e| e.to_string())?;
        let mut csv = String::from("timestamp,domain,source_ip,is_blocked\n");
        for l in logs.iter() {
            csv.push_str(&format!(
                "{},{},{},{}\n",
                l.timestamp, l.domain, l.source_ip, l.is_blocked
            ));
        }
        let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        let export_path = PathBuf::from(app_data)
            .join("ShieldGhita")
            .join(format!("dns_log_export_{}.csv", Local::now().format("%Y%m%d_%H%M%S")));
        fs::write(&export_path, &csv).map_err(|e| e.to_string())?;
        info!("Exported {} log entries to {:?}", logs.len(), export_path);
        Ok(export_path.to_string_lossy().to_string())
    }

    pub fn update_device_traffic(&self, ip: &str, mac: &str, bytes_sent: u64, bytes_received: u64) {
        if let Ok(mut devices) = self.devices.write() {
            let device = devices.entry(ip.to_string()).or_insert_with(|| NetworkDevice {
                name: format!("Thiết bị {}", ip),
                ip: ip.to_string(),
                mac: mac.to_string(),
                bytes_sent: 0,
                bytes_received: 0,
            });
            device.bytes_sent += bytes_sent;
            device.bytes_received += bytes_received;
        }
    }

    pub fn get_devices(&self) -> Vec<NetworkDevice> {
        self.devices
            .read()
            .map(|d| d.values().cloned().collect())
            .unwrap_or_default()
    }

    pub async fn scan_local_network(&self) -> Vec<NetworkDevice> {
        let output = match tokio::process::Command::new("arp")
            .arg("-a")
            .output()
            .await
        {
            Ok(o) => o,
            Err(e) => {
                warn!("Failed to run arp command: {}", e);
                return Vec::new();
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut devices = Vec::new();

        for line in stdout.lines() {
            let line = line.trim();
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let ip = parts[0].to_string();
                let mac_raw = parts[1];

                if ip.parse::<std::net::IpAddr>().is_err() {
                    continue;
                }

                let mac = mac_raw.replace('-', ":").to_uppercase();

                if mac == "FF:FF:FF:FF:FF:FF" || ip.ends_with(".255") {
                    continue;
                }

                let dev = NetworkDevice {
                    name: if ip.ends_with(".1") {
                        "Router/Gateway".to_string()
                    } else {
                        format!("Thiết bị {}", ip)
                    },
                    ip: ip.clone(),
                    mac,
                    bytes_sent: 0,
                    bytes_received: 0,
                };

                if let Ok(existing) = self.devices.read() {
                    if let Some(old) = existing.get(&ip) {
                        devices.push(NetworkDevice {
                            name: dev.name.clone(),
                            ip: dev.ip.clone(),
                            mac: dev.mac.clone(),
                            bytes_sent: old.bytes_sent,
                            bytes_received: old.bytes_received,
                        });
                    } else {
                        devices.push(dev.clone());
                    }
                } else {
                    devices.push(dev.clone());
                }
            }
        }

        if let Ok(mut existing) = self.devices.write() {
            for dev in &devices {
                let entry = existing.entry(dev.ip.clone()).or_insert_with(|| dev.clone());
                entry.mac = dev.mac.clone();
                entry.name = dev.name.clone();
            }
        }

        info!("ARP scan found {} devices", devices.len());
        devices
    }

    pub async fn start_traffic_monitor(self: Arc<Self>) {
        use std::time::Duration;

        info!("Traffic monitor started (using netsh interface stats)");

        loop {
            let output = tokio::process::Command::new("netsh")
                .args(["interface", "ipv4", "show", "subinterfaces"])
                .output()
                .await;

            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let line = line.trim();
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        if let (Ok(bytes_in), Ok(bytes_out)) = (
                            parts[parts.len() - 2].parse::<u64>(),
                            parts[parts.len() - 1].parse::<u64>(),
                        ) {
                            self.update_device_traffic("local", "LOCAL", bytes_in, bytes_out);
                        }
                    }
                }
            }

            self.save_logs_to_disk();

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

