use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_TRACKED_DOMAINS: usize = 512;
const MAX_TRACKED_CLIENTS: usize = 128;
const MAX_HOURLY_BUCKETS: usize = 48;
const TOP_LIST_SIZE: usize = 10;
const MS_PER_HOUR: u64 = 3_600_000;
const MS_PER_DAY: u64 = 86_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMode {
    Default,
    Trusted,
    Strict,
}

impl ClientMode {
    pub fn id(self) -> i32 {
        match self {
            Self::Default => 0,
            Self::Trusted => 1,
            Self::Strict => 2,
        }
    }

    pub fn from_id(id: i32) -> Option<Self> {
        match id {
            0 => Some(Self::Default),
            1 => Some(Self::Trusted),
            2 => Some(Self::Strict),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Trusted => "trusted",
            Self::Strict => "strict",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "default" => Some(Self::Default),
            "trusted" => Some(Self::Trusted),
            "strict" => Some(Self::Strict),
            _ => None,
        }
    }

    pub fn localized_label(self) -> String {
        crate::modules::i18n::tr4("Mặc định", "Default", "默认", "Обычный").to_string()
    }
}

#[derive(Debug, Clone)]
pub struct AdBlockSnapshotItem {
    pub label: String,
    pub count: u64,
}

pub struct AdBlockSnapshot {
    pub total_blocked: u64,
    pub top_domains: Vec<AdBlockSnapshotItem>,
    pub top_clients: Vec<AdBlockSnapshotItem>,
    pub hourly: Vec<AdBlockSnapshotItem>,
    pub rules: Vec<(String, ClientMode)>,
}

pub struct AdBlockControls {
    pause_until_ms: AtomicU64,
    client_rules: Mutex<HashMap<IpAddr, ClientMode>>,
    total_blocked: AtomicU64,
    stats_day: AtomicU64,
    blocked_domains: Mutex<HashMap<String, u64>>,
    blocked_clients: Mutex<HashMap<String, u64>>,
    hourly: Mutex<Vec<(u64, u64)>>,
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn bump_entry(map: &mut HashMap<String, u64>, key: &str, cap: usize) {
    let entry = map.entry(key.to_string()).or_insert(0);
    *entry = entry.saturating_add(1);
    if map.len() > cap {
        let mut counts: Vec<(String, u64)> = map.drain().collect();
        counts.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.1));
        counts.truncate(cap / 2);
        map.extend(counts);
    }
}

fn top_entries(map: &mut HashMap<String, u64>, take: usize) -> Vec<AdBlockSnapshotItem> {
    let mut counts: Vec<(String, u64)> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    counts.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.1));
    counts.truncate(take);
    counts
        .into_iter()
        .map(|(label, count)| AdBlockSnapshotItem { label, count })
        .collect()
}

impl AdBlockControls {
    pub fn new() -> Self {
        Self {
            pause_until_ms: AtomicU64::new(0),
            client_rules: Mutex::new(HashMap::new()),
            total_blocked: AtomicU64::new(0),
            stats_day: AtomicU64::new(0),
            blocked_domains: Mutex::new(HashMap::new()),
            blocked_clients: Mutex::new(HashMap::new()),
            hourly: Mutex::new(Vec::new()),
        }
    }

    pub fn pause_minutes(&self, minutes: u64) {
        let until = unix_now_ms().saturating_add(minutes.saturating_mul(60_000));
        self.pause_until_ms.store(until, Ordering::SeqCst);
    }

    pub fn resume(&self) {
        self.pause_until_ms.store(0, Ordering::SeqCst);
    }

    pub fn is_paused(&self) -> bool {
        self.pause_remaining_secs() > 0
    }

    pub fn pause_remaining_secs(&self) -> u64 {
        let until = self.pause_until_ms.load(Ordering::Relaxed);
        until.saturating_sub(unix_now_ms()) / 1000
    }

    pub fn mode_for_client(&self, ip: &IpAddr) -> ClientMode {
        self.client_rules
            .lock()
            .map(|rules| rules.get(ip).copied().unwrap_or(ClientMode::Default))
            .unwrap_or(ClientMode::Default)
    }

    pub fn set_client_rule(&self, ip: IpAddr, mode: ClientMode) {
        if let Ok(mut rules) = self.client_rules.lock() {
            if mode == ClientMode::Default {
                rules.remove(&ip);
            } else {
                rules.insert(ip, mode);
            }
        }
    }

    pub fn remove_client_rule(&self, ip: &IpAddr) {
        if let Ok(mut rules) = self.client_rules.lock() {
            rules.remove(ip);
        }
    }

    pub fn rules_config(&self) -> Vec<String> {
        self.client_rules
            .lock()
            .map(|rules| {
                rules
                    .iter()
                    .map(|(ip, mode)| format!("{}|{}", ip, mode.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn load_rules_config(&self, entries: &[String]) {
        if let Ok(mut rules) = self.client_rules.lock() {
            rules.clear();
            for entry in entries {
                let Some((ip_part, mode_part)) = entry.split_once('|') else {
                    continue;
                };
                let (Ok(ip), Some(mode)) = (
                    ip_part.trim().parse::<IpAddr>(),
                    ClientMode::from_str(mode_part.trim()),
                ) else {
                    continue;
                };
                rules.insert(ip, mode);
            }
        }
    }

    pub fn total_blocked(&self) -> u64 {
        self.total_blocked.load(Ordering::Relaxed)
    }

    pub fn record_block(&self, domain: &str, client_ip: &str) {
        let now = unix_now_ms();
        let day = now / MS_PER_DAY;
        if self.stats_day.swap(day, Ordering::Relaxed) != day {
            self.total_blocked.store(0, Ordering::Relaxed);
            if let Ok(mut hourly) = self.hourly.lock() {
                hourly.clear();
            }
            if let Ok(mut clients) = self.blocked_clients.lock() {
                clients.clear();
            }
        }
        self.total_blocked.fetch_add(1, Ordering::Relaxed);

        let hour = now / MS_PER_HOUR;
        if let Ok(mut hourly) = self.hourly.lock() {
            match hourly.iter_mut().find(|(bucket, _)| *bucket == hour) {
                Some(entry) => entry.1 = entry.1.saturating_add(1),
                None => {
                    hourly.push((hour, 1));
                    if hourly.len() > MAX_HOURLY_BUCKETS {
                        hourly.remove(0);
                    }
                }
            }
        }

        if let Ok(mut domains) = self.blocked_domains.lock() {
            bump_entry(&mut domains, domain, MAX_TRACKED_DOMAINS);
        }
        if let Ok(mut clients) = self.blocked_clients.lock() {
            bump_entry(&mut clients, client_ip, MAX_TRACKED_CLIENTS);
        }
    }

    pub fn clear_stats(&self) {
        self.total_blocked.store(0, Ordering::Relaxed);
        if let Ok(mut domains) = self.blocked_domains.lock() {
            domains.clear();
        }
        if let Ok(mut clients) = self.blocked_clients.lock() {
            clients.clear();
        }
        if let Ok(mut hourly) = self.hourly.lock() {
            hourly.clear();
        }
    }

    pub fn snapshot(&self) -> AdBlockSnapshot {
        let mut domains_map_locked = self.blocked_domains.lock().ok();
        let mut clients_map_locked = self.blocked_clients.lock().ok();
        let top_domains = match domains_map_locked.as_deref_mut() {
            Some(map) => top_entries(map, TOP_LIST_SIZE),
            None => Vec::new(),
        };
        let top_clients = match clients_map_locked.as_deref_mut() {
            Some(map) => top_entries(map, TOP_LIST_SIZE),
            None => Vec::new(),
        };
        drop(domains_map_locked);
        drop(clients_map_locked);

        let hourly = self
            .hourly
            .lock()
            .map(|buckets| {
                let mut items: Vec<AdBlockSnapshotItem> = buckets
                    .iter()
                    .map(|(hour, count)| AdBlockSnapshotItem {
                        label: format_hour_label(*hour),
                        count: *count,
                    })
                    .collect();
                items.sort_unstable_by(|a, b| a.label.cmp(&b.label));
                items
            })
            .unwrap_or_default();

        AdBlockSnapshot {
            total_blocked: self.total_blocked(),
            top_domains,
            top_clients,
            hourly,
            rules: self
                .client_rules
                .lock()
                .map(|rules| {
                    rules
                        .iter()
                        .map(|(ip, mode)| (ip.to_string(), *mode))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

impl Default for AdBlockControls {
    fn default() -> Self {
        Self::new()
    }
}

fn format_hour_label(hour_epoch: u64) -> String {
    match chrono::DateTime::from_timestamp(
        (hour_epoch.saturating_mul(MS_PER_HOUR / 1000)) as i64,
        0,
    ) {
        Some(dt) => dt
            .with_timezone(&chrono::Local)
            .format("%d/%m %H:00")
            .to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_mode_id_roundtrip() {
        for id in 0..3 {
            let mode = ClientMode::from_id(id).unwrap();
            assert_eq!(mode.id(), id);
        }
        assert!(ClientMode::from_id(3).is_none());
        assert_eq!(ClientMode::from_str("trusted"), Some(ClientMode::Trusted));
        assert_eq!(ClientMode::from_str("bogus"), None);
    }

    #[test]
    fn test_pause_lifecycle() {
        let controls = AdBlockControls::new();
        assert!(!controls.is_paused());
        controls.pause_minutes(5);
        assert!(controls.is_paused());
        assert!(controls.pause_remaining_secs() <= 300);
        controls.resume();
        assert!(!controls.is_paused());
    }

    #[test]
    fn test_client_rules_config_roundtrip() {
        let controls = AdBlockControls::new();
        controls.set_client_rule("192.168.1.50".parse().unwrap(), ClientMode::Trusted);
        controls.set_client_rule("10.0.0.7".parse().unwrap(), ClientMode::Strict);
        let config = controls.rules_config();
        assert_eq!(config.len(), 2);

        let fresh = AdBlockControls::new();
        fresh.load_rules_config(&config);
        assert_eq!(
            fresh.mode_for_client(&"192.168.1.50".parse().unwrap()),
            ClientMode::Trusted
        );
        assert_eq!(
            fresh.mode_for_client(&"10.0.0.7".parse().unwrap()),
            ClientMode::Strict
        );
        assert_eq!(
            fresh.mode_for_client(&"172.16.0.1".parse().unwrap()),
            ClientMode::Default
        );

        controls.set_client_rule("10.0.0.7".parse().unwrap(), ClientMode::Default);
        assert_eq!(controls.rules_config().len(), 1);
        assert_eq!(
            controls.mode_for_client(&"10.0.0.7".parse().unwrap()),
            ClientMode::Default
        );
    }

    #[test]
    fn test_record_block_and_snapshot_ordering() {
        let controls = AdBlockControls::new();
        for _ in 0..5 {
            controls.record_block("ads.example.com", "192.168.1.10");
        }
        for _ in 0..2 {
            controls.record_block("tracker.example.net", "192.168.1.11");
        }
        controls.record_block("ads.example.com", "192.168.1.10");

        let snap = controls.snapshot();
        assert_eq!(snap.total_blocked, 8);
        assert_eq!(snap.top_domains.len(), 2);
        assert_eq!(snap.top_domains[0].label, "ads.example.com");
        assert_eq!(snap.top_domains[0].count, 6);
        assert_eq!(snap.top_clients[0].label, "192.168.1.10");
        assert_eq!(snap.top_clients[0].count, 6);
        assert_eq!(snap.hourly.len(), 1);
        assert_eq!(snap.hourly[0].count, 8);
    }

    #[test]
    fn test_clear_stats_resets_everything() {
        let controls = AdBlockControls::new();
        controls.record_block("ads.example.com", "192.168.1.10");
        controls.clear_stats();
        let snap = controls.snapshot();
        assert_eq!(snap.total_blocked, 0);
        assert!(snap.top_domains.is_empty());
        assert!(snap.top_clients.is_empty());
        assert!(snap.hourly.is_empty());
    }
}
