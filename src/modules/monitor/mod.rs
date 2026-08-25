pub mod connections;
pub mod discovery;
pub mod lan_scanner;
pub mod oui_db;
pub mod port_scanner;

use chrono::Local;
use connections::{ActiveConnection, ConnectionTracker};
use lan_scanner::{LanDevice, LanScanner};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use sysinfo::{Networks, System};
use tracing::{info, warn};

use crate::modules::stats::BlockStats;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub domain: String,
    pub source_ip: String,
    pub is_blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainLogGroup {
    pub domain: String,
    pub total_queries: usize,
    pub blocked_queries: usize,
    pub is_blocked: bool,
    pub last_seen: String,
    pub last_ip: String,
}

pub struct NetworkMonitor {
    logs: Arc<RwLock<Vec<LogEntry>>>,
    filtered_cache: Arc<RwLock<Option<Vec<LogEntry>>>>,
    pub logs_version: Arc<AtomicU64>,
    max_logs: usize,
    log_file_path: PathBuf,
    system_info: Arc<RwLock<System>>,
    networks: Arc<RwLock<Networks>>,
    last_traffic_sample: Mutex<(std::time::Instant, u64)>,
    pub connection_tracker: Arc<ConnectionTracker>,
    pub lan_scanner: Arc<LanScanner>,
    pub security_engine: Arc<crate::modules::security::SecurityEngine>,
    pub block_stats: Arc<BlockStats>,
}

impl NetworkMonitor {
    pub fn new(max_logs: usize, sec_engine: Arc<crate::modules::security::SecurityEngine>) -> Self {
        let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        let log_dir = PathBuf::from(app_data).join("ShieldGhita");
        let _ = fs::create_dir_all(&log_dir);
        let log_file_path = log_dir.join("dns_log.json");

        let mut sys = System::new();
        sys.refresh_cpu();
        sys.refresh_memory();

        let mut nets = Networks::new_with_refreshed_list();
        nets.refresh();

        let monitor = Self {
            logs: Arc::new(RwLock::new(Vec::new())),
            filtered_cache: Arc::new(RwLock::new(None)),
            logs_version: Arc::new(AtomicU64::new(1)),
            max_logs,
            log_file_path,
            system_info: Arc::new(RwLock::new(sys)),
            networks: Arc::new(RwLock::new(nets)),
            last_traffic_sample: Mutex::new((std::time::Instant::now(), 0)),
            connection_tracker: Arc::new(ConnectionTracker::new(sec_engine.clone())),
            lan_scanner: Arc::new(LanScanner::new()),
            security_engine: sec_engine,
            block_stats: Arc::new(BlockStats::load_or_create()),
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

    pub fn save_logs_to_disk(&self) {
        if let Ok(logs) = self.logs.read() {
            match serde_json::to_string(&*logs) {
                Ok(json) => {
                    let _ = fs::write(&self.log_file_path, json);
                }
                Err(e) => warn!("Failed to serialize logs: {}", e),
            }
        }
    }

    pub fn add_log(&self, domain: &str, source_ip: &str, is_blocked: bool) {
        self.lan_scanner
            .record_activity(source_ip, domain, is_blocked, false);

        let entry = LogEntry {
            timestamp: Local::now().format("%H:%M:%S").to_string(),
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
        let _ = self.logs_version.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_logs(&self) -> Vec<LogEntry> {
        if let Ok(fc) = self.filtered_cache.read() {
            if let Some(ref filtered) = *fc {
                return filtered.clone();
            }
        }
        self.logs.read().map(|l| l.clone()).unwrap_or_default()
    }

    pub fn apply_filter(&self, filter_domain: &str, filter_ip: &str, filter_blocked: Option<bool>) {
        if filter_domain.is_empty() && filter_ip.is_empty() && filter_blocked.is_none() {
            if let Ok(mut fc) = self.filtered_cache.write() {
                *fc = None;
            }
            return;
        }

        let fd = filter_domain.trim().to_lowercase();
        let fip = filter_ip.trim().to_string();

        let filtered: Vec<LogEntry> = self
            .logs
            .read()
            .map(|logs| {
                logs.iter()
                    .filter(|l| {
                        let domain_match = fd.is_empty() || l.domain.to_lowercase().contains(&fd);
                        let ip_match = fip.is_empty() || l.source_ip.contains(&fip);
                        let blocked_match = filter_blocked.is_none_or(|b| l.is_blocked == b);
                        domain_match && ip_match && blocked_match
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        if let Ok(mut fc) = self.filtered_cache.write() {
            *fc = Some(filtered);
        }
        let _ = self.logs_version.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub fn clear_filter(&self) {
        if let Ok(mut fc) = self.filtered_cache.write() {
            *fc = None;
        }
    }

    pub fn clear_logs(&self) {
        if let Ok(mut logs) = self.logs.write() {
            logs.clear();
        }
        if let Ok(mut fc) = self.filtered_cache.write() {
            *fc = None;
        }
        let _ = self.logs_version.fetch_add(1, Ordering::Relaxed);
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
        let export_path = PathBuf::from(app_data).join("ShieldGhita").join(format!(
            "dns_log_export_{}.csv",
            Local::now().format("%Y%m%d_%H%M%S")
        ));
        fs::write(&export_path, &csv).map_err(|e| e.to_string())?;
        info!("Exported {} log entries to {:?}", logs.len(), export_path);
        Ok(export_path.to_string_lossy().to_string())
    }

    pub fn get_grouped_logs(&self) -> Vec<DomainLogGroup> {
        let logs = self.get_logs();
        let mut map: HashMap<String, (usize, usize, String, String)> = HashMap::new();

        for l in logs {
            let entry = map.entry(l.domain.clone()).or_insert((
                0,
                0,
                l.timestamp.clone(),
                l.source_ip.clone(),
            ));
            entry.0 += 1;
            if l.is_blocked {
                entry.1 += 1;
            }
        }

        let mut groups: Vec<DomainLogGroup> = map
            .into_iter()
            .map(|(domain, (total, blocked, last_seen, last_ip))| {
                let is_blocked = blocked > 0;
                DomainLogGroup {
                    domain,
                    total_queries: total,
                    blocked_queries: blocked,
                    is_blocked,
                    last_seen,
                    last_ip,
                }
            })
            .collect();

        groups.sort_by_key(|b| std::cmp::Reverse(b.total_queries));
        groups
    }

    pub fn get_active_connections(&self) -> Vec<ActiveConnection> {
        self.connection_tracker.get_active_connections()
    }

    pub fn get_lan_devices(&self) -> Vec<LanDevice> {
        self.lan_scanner.get_devices()
    }

    pub fn get_lan_device_count(&self) -> usize {
        self.lan_scanner.devices_len()
    }

    pub fn is_lan_scanning(&self) -> bool {
        self.lan_scanner.is_scanning()
    }

    pub fn get_system_metrics(&self) -> (f32, f32) {
        if let Ok(mut sys) = self.system_info.write() {
            sys.refresh_cpu();
            sys.refresh_memory();
            let cpu = sys.global_cpu_info().cpu_usage();
            let used_mem = sys.used_memory() as f64 / (1024.0 * 1024.0 * 1024.0);
            (cpu, used_mem as f32)
        } else {
            (0.0, 0.0)
        }
    }

    pub fn get_live_traffic_rate(&self) -> String {
        if let Ok(mut nets) = self.networks.write() {
            nets.refresh();
            let mut total = 0u64;
            for (interface_name, data) in nets.iter() {
                let name = interface_name.to_lowercase();
                if !name.contains("loopback") && !name.contains("pseudo") {
                    total += data.total_received() + data.total_transmitted();
                }
            }

            if let Ok(mut sample) = self.last_traffic_sample.lock() {
                let (last_instant, last_total) = *sample;
                if last_total == 0 {
                    *sample = (std::time::Instant::now(), total);
                    return "0 KB/s".to_string();
                }
                let elapsed = last_instant.elapsed().as_secs_f64();
                if elapsed < 0.1 {
                    return "0 KB/s".to_string();
                }
                let bytes_per_sec = if total >= last_total {
                    (total - last_total) as f64 / elapsed
                } else {
                    0.0
                };
                *sample = (std::time::Instant::now(), total);

                if bytes_per_sec > 1024.0 * 1024.0 {
                    format!("{:.1} MB/s", bytes_per_sec / (1024.0 * 1024.0))
                } else if bytes_per_sec > 1024.0 {
                    format!("{:.0} KB/s", bytes_per_sec / 1024.0)
                } else if bytes_per_sec > 0.0 {
                    format!("{:.0} B/s", bytes_per_sec)
                } else {
                    "0 KB/s".to_string()
                }
            } else {
                "0 KB/s".to_string()
            }
        } else {
            "0 KB/s".to_string()
        }
    }

    #[allow(clippy::manual_is_multiple_of)]
    pub async fn start_traffic_monitor(self: Arc<Self>) {
        use std::time::Duration;
        let mut cycle: u64 = 0;

        loop {
            if cycle % 2 == 0 {
                self.connection_tracker.refresh_connections();
            }

            if cycle > 0 && cycle % 100 == 0 {
                let scanner = self.lan_scanner.clone();
                let sec = self.security_engine.clone();
                tokio::spawn(async move {
                    let _ = scanner.scan_network(Some(sec)).await;
                });
            }

            if cycle > 0 && cycle % 20 == 0 {
                self.save_logs_to_disk();
                self.block_stats.flush_if_dirty();
            }

            if cycle > 0 && cycle % 200 == 0 {
                let (cpu, mem) = self.get_system_metrics();
                info!("Resource baseline: CPU {:.1}% | RAM {:.1} GB", cpu, mem);
            }

            cycle = cycle.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }
    }
}
