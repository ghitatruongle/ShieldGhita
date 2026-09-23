use crate::modules::i18n;
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing::{info, warn};

pub mod file_analyzer;
pub mod location_scan;
pub use file_analyzer::{pick_file_dialog, scan_file};
pub use location_scan::{pick_folder_dialog, scan_location, LocationScanOptions};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIncident {
    pub id: u64,
    pub time: String,
    pub incident_type: String,
    pub source_ip: String,
    pub details: String,
    pub severity: String,
    pub mitigation: String,
}

pub struct SecurityEngine {
    pub attack_detection_enabled: Arc<AtomicBool>,
    pub auto_block_enabled: Arc<AtomicBool>,
    pub arp_spoof_detection_enabled: Arc<AtomicBool>,
    pub dns_flood_rate_limit: Arc<RwLock<u32>>,
    ip_query_history: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    hard_query_history: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    pub hard_drop_count: Arc<AtomicU64>,
    blocked_ips: Arc<RwLock<HashMap<String, Instant>>>,
    incidents: Arc<RwLock<Vec<SecurityIncident>>>,
    incident_counter: Arc<AtomicU64>,
    last_known_gateway: Arc<RwLock<Option<(String, String)>>>,
    quarantine: RwLock<QuarantineInventory>,
    port_probe_history: PortProbeHistory,
    port_scan_alert_cooldown: Arc<RwLock<HashMap<String, Instant>>>,
    hard_flood_alert_cooldown: Arc<RwLock<HashMap<String, Instant>>>,
    flood_alert_cooldown: Arc<RwLock<HashMap<String, Instant>>>,
    pub alert_tx: broadcast::Sender<SecurityIncident>,
}

const PORT_SCAN_WINDOW: Duration = Duration::from_secs(60);
const PORT_SCAN_DISTINCT_PORTS: usize = 10;
const PORT_SCAN_ALERT_COOLDOWN: Duration = Duration::from_secs(600);
const HARD_FLOOD_ALERT_COOLDOWN: Duration = Duration::from_secs(60);
const FLOOD_ALERT_COOLDOWN: Duration = Duration::from_secs(60);
/// Hard cap on MAC-bound quarantine entries. LAN quarantine is an operator
/// tool for misbehaving clients, not a bulk firewall: unbounded growth would
/// let a spoofing client inflate memory via repeated UI actions.
const MAX_QUARANTINE_ENTRIES: usize = 256;

type PortProbeHistory = Arc<RwLock<HashMap<String, Vec<(u16, Instant)>>>>;

/// Why `quarantine_ip` refused an operator action. Surfaced to the UI so a
/// rejection is never a silent success. Ordered by diagnosis usefulness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineRejection {
    /// Text was not a parseable IP (typo, hostname pasted, empty field).
    InvalidAddress,
    /// Parseable but non-quarantinable: loopback, unspecified, multicast,
    /// IPv4 broadcast — blocking these has no protective value.
    ReservedAddress,
    /// The address is this host itself (loopback or the OS-selected local
    /// IPv4). Quarantining self would cut the operator's own management
    /// path; self-protection is handled by other mechanisms.
    SelfAddress,
    /// The address is the OS-reported default gateway. Cutting DNS to the
    /// gateway blackholes the whole LAN's upstream path.
    GatewayAddress,
    /// No passive ARP observation exists yet for this IP, so the MAC owner
    /// is unknown. Fail conservative: an IP-only quarantine could be evaded
    /// by simply leasing a new address; wait for inventory evidence.
    IdentityUnknown,
    InventoryUnavailable,
    CapacityReached,
}

impl QuarantineRejection {
    /// Localized one-line reason for the UI status text.
    pub fn message(self) -> String {
        match self {
            Self::InventoryUnavailable => i18n::tr4(
                "Thông tin mạng chưa có hoặc đã cũ; chờ cập nhật kiểm kê",
                "Network inventory unavailable or stale; wait for inventory refresh",
                "网络清单不可用或已过期；请等待刷新",
                "Сетевые данные недоступны или устарели; дождитесь обновления",
            ),
            Self::CapacityReached => i18n::tr4(
                "Đã đạt giới hạn cách ly",
                "Quarantine capacity reached",
                "已达到隔离数量上限",
                "Достигнут лимит карантина",
            ),
            Self::InvalidAddress => i18n::tr4(
                "Địa chỉ IP không hợp lệ, không thể cách ly",
                "Invalid IP address; quarantine refused",
                "IP 地址无效，无法隔离",
                "Недопустимый IP-адрес; карантин отклонён",
            ),
            Self::ReservedAddress => i18n::tr4(
                "Địa chỉ dành riêng (loopback/multicast/broadcast), không thể cách ly",
                "Reserved address (loopback/multicast/broadcast); quarantine refused",
                "保留地址（环回/组播/广播），无法隔离",
                "Зарезервированный адрес (loopback/multicast/broadcast); карантин отклонён",
            ),
            Self::SelfAddress => i18n::tr4(
                "Không thể cách ly chính máy này",
                "Cannot quarantine this machine itself",
                "无法隔离本机自身",
                "Нельзя поместить в карантин эту машину",
            ),
            Self::GatewayAddress => i18n::tr4(
                "Không thể cách ly gateway hệ thống",
                "Cannot quarantine the OS default gateway",
                "无法隔离系统默认网关",
                "Нельзя поместить в карантин системный шлюз",
            ),
            Self::IdentityUnknown => i18n::tr4(
                "Chưa có bằng chứng MAC thụ động cho IP này; không cách ly mù",
                "No passive MAC evidence for this IP yet; refusing blind quarantine",
                "尚未观测到该 IP 的被动 MAC 证据；拒绝盲目隔离",
                "Нет пассивных MAC-данных по этому IP; слепой карантин запрещён",
            ),
        }
        .to_string()
    }
}

/// A quarantine action with the MAC identity it was bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct QuarantineEntry {
    mac: String,
}

/// MAC-bound quarantine state plus the passive ARP inventory used to bind and
/// auto-release entries. `ips` keys are normalized `IpAddr::to_string()` form,
/// exactly what `is_quarantined` looks up (DNS hot path compares normalized
/// source IPs, so an un-normalized key would silently never match).
#[derive(Default)]
struct QuarantineInventory {
    /// Normalized IP -> bound MAC (uppercase, colon-separated).
    entries: HashMap<String, QuarantineEntry>,
    /// Passive ARP observations: normalized IP -> MAC (uppercase).
    inventory: HashMap<String, String>,
    self_ips: std::collections::HashSet<String>,
    gateways: std::collections::HashSet<String>,
    observed_at: Option<Instant>,
}

const QUARANTINE_INVENTORY_TTL: Duration = Duration::from_secs(300);

impl QuarantineInventory {
    /// Normalize a MAC the same way the ARP-table parser does so UI input,
    /// `SendARP` output and `arp -a` output compare equal. `None` when the
    /// string is not a well-formed 6-octet MAC (all-zero and broadcast MACs
    /// are also rejected: they carry no owner identity).
    fn normalize_mac(mac: &str) -> Option<String> {
        let cleaned: String = mac
            .trim()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        if cleaned.len() != 12 || !cleaned.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let upper = cleaned.to_uppercase();
        if upper == "000000000000" || upper == "FFFFFFFFFFFF" {
            return None;
        }
        let bytes: Vec<char> = upper.chars().collect();
        Some(
            bytes
                .chunks(2)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join(":"),
        )
    }

    /// Record/refresh a passive observation. Returns true when this is a NEW
    /// IP->MAC binding (owner change) as opposed to a refresh of a known one.
    fn observe(&mut self, ip: &str, mac: &str) -> bool {
        let Some(normalized_mac) = Self::normalize_mac(mac) else {
            return false;
        };
        let Some(normalized_ip) = Self::normalize_ip(ip) else {
            return false;
        };
        match self.inventory.get(&normalized_ip) {
            Some(existing) if *existing == normalized_mac => false,
            _ => {
                self.inventory.insert(normalized_ip, normalized_mac);
                true
            }
        }
    }

    fn inventory_mac(&self, normalized_ip: &str) -> Option<&str> {
        self.inventory.get(normalized_ip).map(|m| m.as_str())
    }

    /// Positive inventory observation that `ip` now answers with a DIFFERENT
    /// MAC than the one the quarantine bound to. Only positive evidence
    /// releases: absence/timeout of observations never does.
    fn owner_changed(&self, normalized_ip: &str) -> bool {
        match (
            self.entries.get(normalized_ip),
            self.inventory.get(normalized_ip),
        ) {
            (Some(entry), Some(current)) => *current != entry.mac,
            _ => false,
        }
    }

    /// Compact a normalized IP for map keying. Returns `None` for non-IPv4:
    /// the DNS quarantine gate and the passive ARP inventory are IPv4-only,
    /// so binding an IPv6 quarantine would be unenforceable theater.
    fn normalize_ip(ip: &str) -> Option<String> {
        let v4: std::net::Ipv4Addr = ip.trim().parse().ok()?;
        Some(v4.to_string())
    }
}

impl SecurityEngine {
    pub fn new() -> Self {
        let (alert_tx, _) = broadcast::channel(128);
        Self {
            attack_detection_enabled: Arc::new(AtomicBool::new(false)),
            auto_block_enabled: Arc::new(AtomicBool::new(false)),
            arp_spoof_detection_enabled: Arc::new(AtomicBool::new(false)),
            dns_flood_rate_limit: Arc::new(RwLock::new(80)),
            ip_query_history: Arc::new(RwLock::new(HashMap::new())),
            hard_query_history: Arc::new(RwLock::new(HashMap::new())),
            hard_drop_count: Arc::new(AtomicU64::new(0)),
            blocked_ips: Arc::new(RwLock::new(HashMap::new())),
            quarantine: RwLock::new(QuarantineInventory::default()),
            incidents: Arc::new(RwLock::new(Vec::new())),
            incident_counter: Arc::new(AtomicU64::new(1)),
            last_known_gateway: Arc::new(RwLock::new(None)),
            port_probe_history: Arc::new(RwLock::new(HashMap::new())),
            port_scan_alert_cooldown: Arc::new(RwLock::new(HashMap::new())),
            hard_flood_alert_cooldown: Arc::new(RwLock::new(HashMap::new())),
            flood_alert_cooldown: Arc::new(RwLock::new(HashMap::new())),
            alert_tx,
        }
    }

    pub fn is_detection_enabled(&self) -> bool {
        self.attack_detection_enabled.load(Ordering::Relaxed)
    }

    pub fn enforce_hard_rate_limit(&self, source_ip: &str) -> bool {
        let base = self.dns_flood_rate_limit.read().map(|g| *g).unwrap_or(80);
        let is_loopback = source_ip == "127.0.0.1" || source_ip == "::1";
        // Loopback is rate-limited too, with a higher threshold (base*10, capped at 2000).
        let hard_limit = if is_loopback {
            (base.saturating_mul(10)).clamp(200, 2000) as usize
        } else {
            (base.saturating_mul(4)).max(200) as usize
        };
        let now = Instant::now();

        let mut exceeded = false;
        if let Ok(mut hist) = self.hard_query_history.write() {
            if hist.len() > 1000 {
                // Evict expired entries first, then remove oldest 256 if still over budget.
                hist.retain(|_, v| {
                    v.iter()
                        .any(|t| now.duration_since(*t) < Duration::from_secs(2))
                });
                if hist.len() > 1000 {
                    Self::evict_oldest_ips(&mut hist, 256, now);
                }
            }
            let timestamps = hist.entry(source_ip.to_string()).or_default();
            timestamps.retain(|t| now.duration_since(*t) < Duration::from_secs(2));
            timestamps.push(now);
            if timestamps.len() > hard_limit {
                // Keep recent 10 for forensics instead of clearing everything.
                let len = timestamps.len();
                if len > 10 {
                    timestamps.drain(..len - 10);
                }
                exceeded = true;
            }
        }

        if exceeded {
            self.hard_drop_count.fetch_add(1, Ordering::SeqCst);
            // Cooldown per IP to avoid log/block spam on sustained floods.
            let should_alert = {
                if let Ok(mut cd) = self.hard_flood_alert_cooldown.write() {
                    let alert = !matches!(cd.get(source_ip), Some(last) if now.duration_since(*last) < HARD_FLOOD_ALERT_COOLDOWN);
                    if alert {
                        if cd.len() > 1024 {
                            let cutoff = now - HARD_FLOOD_ALERT_COOLDOWN;
                            cd.retain(|_, t| *t > cutoff);
                        }
                        cd.insert(source_ip.to_string(), now);
                    }
                    alert
                } else {
                    true
                }
            };
            if should_alert {
                // block_ip_temporarily intentionally exempts loopback (no-op there);
                // loopback floods are still dropped via the `true` return.
                self.block_ip_temporarily(source_ip, Duration::from_secs(60));
                warn!(
                    "Security Hard Rate Limit: {} exceeded {} queries/2s — isolating source for 60s",
                    source_ip, hard_limit
                );
            }
        }
        exceeded
    }

    fn evict_oldest_ips(hist: &mut HashMap<String, Vec<Instant>>, count: usize, _now: Instant) {
        if hist.len() <= count {
            return;
        }
        // Oldest = smallest most-recent timestamp (empty vec = oldest, evict first).
        let mut keys: Vec<(String, Option<Instant>)> = hist
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().max().copied()))
            .collect();
        keys.sort_by_key(|(_, t)| *t);
        for (k, _) in keys.into_iter().take(count) {
            hist.remove(&k);
        }
    }

    pub fn is_auto_block_enabled(&self) -> bool {
        self.auto_block_enabled.load(Ordering::Relaxed)
    }

    pub fn is_arp_detection_enabled(&self) -> bool {
        self.arp_spoof_detection_enabled.load(Ordering::Relaxed)
    }

    pub fn set_detection_enabled(&self, enabled: bool) {
        self.attack_detection_enabled
            .store(enabled, Ordering::SeqCst);
        info!(
            "Security Engine IDS changed: {}",
            if enabled { "ENABLED" } else { "DISABLED" }
        );
    }

    pub fn set_auto_block(&self, enabled: bool) {
        self.auto_block_enabled.store(enabled, Ordering::SeqCst);
        info!(
            "Security Engine IPS (Auto-block) changed: {}",
            if enabled { "ENABLED" } else { "DISABLED" }
        );
    }

    pub fn set_arp_detection(&self, enabled: bool) {
        self.arp_spoof_detection_enabled
            .store(enabled, Ordering::SeqCst);
        info!(
            "ARP Spoofing Watcher changed: {}",
            if enabled { "ENABLED" } else { "DISABLED" }
        );
    }

    pub fn is_ip_temporarily_blocked(&self, ip: &str) -> bool {
        // Fast path: read lock first.
        let expired_or_missing = match self.blocked_ips.read() {
            Ok(map) => match map.get(ip) {
                Some(exp) => Instant::now() >= *exp,
                None => return false,
            },
            Err(_) => return false,
        };
        if !expired_or_missing {
            return true;
        }
        // Slow path: take write lock only to expire/remove.
        if let Ok(mut map) = self.blocked_ips.write() {
            match map.get(ip) {
                Some(exp) if Instant::now() < *exp => true,
                Some(_) => {
                    map.remove(ip);
                    false
                }
                None => false,
            }
        } else {
            false
        }
    }

    pub fn block_ip_temporarily(&self, ip: &str, duration: Duration) {
        if ip == "127.0.0.1" || ip == "::1" {
            return;
        }
        if let Ok(mut map) = self.blocked_ips.write() {
            if map.len() > 500 {
                let now = Instant::now();
                map.retain(|_, exp| now < *exp);
            }
            map.insert(ip.to_string(), Instant::now() + duration);
            warn!(
                "Security IPS: Temporarily blocked IP {} for {:?}",
                ip, duration
            );
        }
    }

    #[allow(dead_code)]
    pub fn unblock_ip(&self, ip: &str) {
        if let Ok(mut map) = self.blocked_ips.write() {
            map.remove(ip);
        }
    }

    pub fn record_incident(
        &self,
        incident_type: &str,
        source_ip: &str,
        details: &str,
        severity: &str,
        mitigation: &str,
    ) -> SecurityIncident {
        let id = self.incident_counter.fetch_add(1, Ordering::SeqCst);
        let incident = SecurityIncident {
            id,
            time: Local::now().format("%H:%M:%S").to_string(),
            incident_type: incident_type.to_string(),
            source_ip: source_ip.to_string(),
            details: details.to_string(),
            severity: severity.to_string(),
            mitigation: mitigation.to_string(),
        };

        if let Ok(mut list) = self.incidents.write() {
            list.insert(0, incident.clone());
            if list.len() > 500 {
                list.truncate(500);
            }
        }

        let _ = self.alert_tx.send(incident.clone());
        warn!(
            "🚨 SECURITY ALERT [{}]: {} from {} - {}",
            severity, incident_type, source_ip, details
        );
        incident
    }

    pub fn get_incidents(&self) -> Vec<SecurityIncident> {
        self.incidents.read().map(|l| l.clone()).unwrap_or_default()
    }

    pub fn incidents_count(&self) -> usize {
        self.incidents.read().map(|l| l.len()).unwrap_or(0)
    }

    pub fn clear_incidents(&self) {
        if let Ok(mut list) = self.incidents.write() {
            list.clear();
        }
    }

    pub fn update_quarantine_inventory(
        &self,
        observations: &[(String, String)],
        self_ips: &[String],
        gateways: &[String],
    ) {
        let Ok(mut q) = self.quarantine.write() else {
            return;
        };
        q.inventory.clear();
        q.self_ips = self_ips
            .iter()
            .filter_map(|s| QuarantineInventory::normalize_ip(s))
            .collect();
        q.gateways = gateways
            .iter()
            .filter_map(|s| QuarantineInventory::normalize_ip(s))
            .collect();
        for (ip, mac) in observations.iter().take(4096) {
            q.observe(ip, mac);
        }
        q.observed_at = Some(Instant::now());
        let released: Vec<_> = q
            .entries
            .keys()
            .filter(|ip| {
                q.owner_changed(ip) || q.self_ips.contains(*ip) || q.gateways.contains(*ip)
            })
            .cloned()
            .collect();
        for ip in released {
            q.entries.remove(&ip);
            info!(
                "DNS quarantine released after identity or local route change: {}",
                ip
            );
        }
    }

    pub fn quarantine_ip(&self, ip: &str) -> Result<(), QuarantineRejection> {
        let address: std::net::Ipv4Addr = ip
            .trim()
            .parse()
            .map_err(|_| QuarantineRejection::InvalidAddress)?;
        if address.is_loopback()
            || address.is_unspecified()
            || address.is_multicast()
            || address.is_broadcast()
        {
            return Err(QuarantineRejection::ReservedAddress);
        }
        let clean = address.to_string();
        let mut q = self
            .quarantine
            .write()
            .map_err(|_| QuarantineRejection::InventoryUnavailable)?;
        if q.self_ips.contains(&clean) {
            return Err(QuarantineRejection::SelfAddress);
        }
        if q.gateways.contains(&clean) {
            return Err(QuarantineRejection::GatewayAddress);
        }
        if q.observed_at
            .is_none_or(|t| t.elapsed() > QUARANTINE_INVENTORY_TTL)
            || q.self_ips.is_empty()
            || q.gateways.is_empty()
        {
            return Err(QuarantineRejection::InventoryUnavailable);
        }
        let mac = q
            .inventory_mac(&clean)
            .ok_or(QuarantineRejection::IdentityUnknown)?
            .to_string();
        if q.entries.contains_key(&clean) {
            return Ok(());
        }
        if q.entries.len() >= MAX_QUARANTINE_ENTRIES {
            return Err(QuarantineRejection::CapacityReached);
        }
        q.entries.insert(clean.clone(), QuarantineEntry { mac });
        drop(q);
        self.record_incident(
            "DNS quarantine",
            &clean,
            "Administrator requested MAC-bound DNS blocking",
            "HIGH",
            "Only DNS through ShieldGhita blocked; other Internet access is unaffected",
        );
        Ok(())
    }

    pub fn unquarantine_ip(&self, ip: &str) {
        let Some(clean) = QuarantineInventory::normalize_ip(ip) else {
            return;
        };
        if let Ok(mut q) = self.quarantine.write() {
            q.entries.remove(&clean);
        }
    }

    pub fn is_quarantined(&self, ip: &str) -> bool {
        let Some(clean) = QuarantineInventory::normalize_ip(ip) else {
            return false;
        };
        self.quarantine
            .read()
            .map(|q| q.entries.contains_key(&clean))
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn get_quarantined_ips(&self) -> Vec<String> {
        self.quarantine
            .read()
            .map(|q| q.entries.keys().cloned().collect())
            .unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn inspect_rogue_dhcp(
        &self,
        server_ip: &str,
        server_mac: &str,
        expected_gateway: &str,
    ) -> Option<SecurityIncident> {
        if !self.is_detection_enabled() {
            return None;
        }
        if server_ip.is_empty() || server_ip == "0.0.0.0" || server_ip == "127.0.0.1" {
            return None;
        }

        if !expected_gateway.is_empty() && server_ip != expected_gateway {
            let details = match i18n::current_index() {
                i18n::EN => format!(
                    "Rogue DHCP server detected at IP {} ({})! Expected authorized gateway DHCP: {}",
                    server_ip, server_mac, expected_gateway
                ),
                i18n::ZH => format!(
                    "检测到非法 DHCP 服务器：IP {} ({})！预期授权网关 DHCP：{}",
                    server_ip, server_mac, expected_gateway
                ),
                i18n::RU => format!(
                    "Обнаружен нелегитимный DHCP-сервер: IP {} ({})! Ожидаемый шлюз DHCP: {}",
                    server_ip, server_mac, expected_gateway
                ),
                _ => format!(
                    "Phát hiện máy chủ DHCP giả mạo tại IP {} ({})! Gateway DHCP chính thức dự kiến: {}",
                    server_ip, server_mac, expected_gateway
                ),
            };

            let incident = self.record_incident(
                i18n::tr4(
                    "Máy chủ DHCP giả mạo (Rogue DHCP Server)",
                    "Rogue DHCP Server Detected",
                    "非法 DHCP 服务器 (Rogue DHCP)",
                    "Обнаружен нелегитимный DHCP-сервер",
                ),
                server_ip,
                &details,
                "CRITICAL",
                i18n::tr4(
                    "Cảnh báo: Nguy cơ chiếm quyền cấp phát IP và chuyển hướng mạng",
                    "Alert: Risk of IP allocation hijacking and traffic redirection",
                    "告警：存在 IP 分配劫持及流量重定向风险",
                    "Тревога: риск перехвата выдачи IP и перенаправления трафика",
                ),
            );
            return Some(incident);
        }

        None
    }

    pub fn calc_entropy(s: &str) -> f64 {
        let char_count = s.chars().count();
        if char_count == 0 {
            return 0.0;
        }
        let len = char_count as f64;
        if s.is_ascii() {
            let mut counts = [0u32; 128];
            for b in s.bytes() {
                counts[b as usize] += 1;
            }
            let mut entropy = 0.0;
            for count in counts {
                if count > 0 {
                    let p = f64::from(count) / len;
                    entropy -= p * p.log2();
                }
            }
            entropy
        } else {
            let mut map = HashMap::new();
            for ch in s.chars() {
                *map.entry(ch).or_insert(0usize) += 1;
            }
            let mut entropy = 0.0;
            for (_, count) in map {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
            entropy
        }
    }

    pub fn is_dga_domain(domain: &str) -> bool {
        let clean = domain.trim().trim_end_matches('.');
        let parts: Vec<&str> = clean.split('.').collect();
        if parts.len() < 2 {
            return false;
        }
        let sld = parts[parts.len() - 2];
        if sld.len() < 8 || sld.len() > 36 {
            return false;
        }
        let mut consonants = 0usize;
        let mut vowels = 0usize;
        let mut digits = 0usize;
        let mut max_consecutive_consonants = 0usize;
        let mut current_consonant_run = 0usize;

        for ch in sld.chars() {
            let lower = ch.to_ascii_lowercase();
            if matches!(lower, 'a' | 'e' | 'i' | 'o' | 'u') {
                vowels += 1;
                current_consonant_run = 0;
            } else if lower.is_ascii_alphabetic() {
                consonants += 1;
                current_consonant_run += 1;
                if current_consonant_run > max_consecutive_consonants {
                    max_consecutive_consonants = current_consonant_run;
                }
            } else if lower.is_ascii_digit() {
                digits += 1;
                current_consonant_run = 0;
            } else {
                // Non-alphanumeric (hyphen '-', underscore '_', etc.) breaks
                // consonant runs — e.g. "bcdfg-hjklm" must not count as 11.
                current_consonant_run = 0;
            }
        }

        if max_consecutive_consonants >= 6 {
            return true;
        }
        if sld.len() >= 12 && vowels == 0 {
            return true;
        }
        if sld.len() >= 14 && digits >= 3 && consonants >= 7 {
            let ent = Self::calc_entropy(sld);
            if ent >= 3.55 {
                return true;
            }
        }
        false
    }

    /// Policy: `.onion` (Tor), `.bit` (Namecoin/EmerDNS) and `.bazar`
    /// (EmerDNS/Bazar) are pseudo-TLDs that can never be resolved via standard
    /// DNS. They are routinely abused for botnet C2 / darknet exfiltration.
    ///
    /// Enforcement: **always NXDOMAIN**, even when `auto_block` is disabled.
    /// Rationale: NXDOMAIN for a non-routable pseudo-TLD cannot break legit
    /// browsing (no public resolver can answer it), so fail-closed dropping is
    /// safe. `.bit` / `.bazar` follow the **same always-block policy** as
    /// `.onion` for consistency.
    ///
    /// Callers (DNS dispatch) must check this helper *before* the generic
    /// `auto_block` gate and NXDOMAIN matching queries unconditionally.
    pub fn is_darknet_pseudo_tld(domain: &str) -> bool {
        let lower = domain.trim().trim_end_matches('.').to_lowercase();
        lower.ends_with(".onion")
            || lower == "onion"
            || lower.ends_with(".bit")
            || lower == "bit"
            || lower.ends_with(".bazar")
            || lower == "bazar"
    }

    /// Alias kept for readability at call sites: darknet pseudo-TLDs must
    /// always be answered with NXDOMAIN, regardless of IPS/auto-block state.
    pub fn must_nxdomain_darknet(domain: &str) -> bool {
        Self::is_darknet_pseudo_tld(domain)
    }

    pub fn inspect_hosts_file(&self) -> Option<SecurityIncident> {
        let hosts_path = if cfg!(windows) {
            std::path::PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
        } else {
            std::path::PathBuf::from("/etc/hosts")
        };

        if !hosts_path.exists() {
            return None;
        }

        let content = std::fs::read_to_string(&hosts_path).ok()?;
        let sensitive_targets = [
            "microsoft.com",
            "windowsupdate.com",
            "google.com",
            "bing.com",
            "kaspersky",
            "bitdefender",
            "symantec",
            "bank",
            "paypal",
            "binance",
        ];

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            // Strip inline comments: "IP host1 host2 # comment".
            let without_comment = trimmed.split('#').next().unwrap_or("").trim();
            if without_comment.is_empty() {
                continue;
            }
            // Hosts format: IP + one or more hostnames.
            let mut fields = without_comment.split_whitespace();
            let ip_field = match fields.next() {
                Some(f) => f,
                None => continue,
            };
            // First field must be an IP; otherwise skip malformed line.
            if ip_field.parse::<std::net::IpAddr>().is_err() {
                continue;
            }
            let hostnames: Vec<String> = fields
                .map(|h| h.trim().trim_end_matches('.').to_lowercase())
                .collect();
            if hostnames.is_empty() {
                continue;
            }
            for hostname in &hostnames {
                if hostname.is_empty() {
                    continue;
                }
                for target in &sensitive_targets {
                    let t = target.to_lowercase();
                    // Equality / suffix match on hostname boundaries — not a raw
                    // substring `contains` on the whole line (avoids false
                    // positives like "mybankexample.com" matching "bank").
                    let matched = hostname.as_str() == t.as_str()
                        || hostname.ends_with(&format!(".{t}"))
                        || hostname.starts_with(&format!("{t}."))
                        || hostname.contains(&format!(".{t}."));
                    if matched {
                        let incident = self.record_incident(
                            i18n::tr4(
                                "Phát hiện chỉnh sửa độc hại tệp Hosts (Hosts Tamper)",
                                "Hosts File Tampering / Malicious Hijack Detected",
                                "检测到恶意篡改 Hosts 文件 (Hosts Tamper)",
                                "Обнаружена подмена файла hosts",
                            ),
                            "127.0.0.1",
                            &format!(
                                "{}: '{}'",
                                i18n::tr4(
                                    "Tệp hosts chứa bản ghi chuyển hướng tên miền nhạy cảm",
                                    "Hosts file contains sensitive domain redirection",
                                    "Hosts 文件包含敏感域名重定向记录",
                                    "В hosts есть перенаправления чувствительных доменов"
                                ),
                                trimmed
                            ),
                            "CRITICAL",
                            i18n::tr4(
                                "Đề xuất: Khôi phục tệp hosts về trạng thái mặc định của Windows",
                                "Recommended: Restore hosts file to default Windows clean state",
                                "建议：将 hosts 文件恢复为 Windows 默认干净状态",
                                "Рекомендуется: восстановить hosts к чистому состоянию Windows",
                            ),
                        );
                        return Some(incident);
                    }
                }
            }
        }
        None
    }

    pub fn inspect_dns_query(&self, source_ip: &str, domain: &str) -> Option<SecurityIncident> {
        if !self.is_detection_enabled() {
            return None;
        }

        let auto_block = self.is_auto_block_enabled();

        let limit = self.dns_flood_rate_limit.read().map(|g| *g).unwrap_or(80);
        let now = Instant::now();
        let mut is_flooding = false;
        let mut query_count_last_sec = 0;

        if let Ok(mut history_map) = self.ip_query_history.write() {
            if history_map.len() > 1000 {
                // Retain only non-expired entries, then evict oldest 256 if still over budget.
                history_map.retain(|_, v| {
                    v.iter()
                        .any(|t| now.duration_since(*t) < Duration::from_secs(2))
                });
                if history_map.len() > 1000 {
                    Self::evict_oldest_ips(&mut history_map, 256, now);
                }
            }
            let timestamps = history_map.entry(source_ip.to_string()).or_default();
            timestamps.retain(|t| now.duration_since(*t) < Duration::from_secs(2));
            timestamps.push(now);
            query_count_last_sec = timestamps.len();

            if query_count_last_sec > limit as usize {
                is_flooding = true;
                // Keep recent 10 for forensics instead of clearing everything.
                let len = timestamps.len();
                if len > 10 {
                    timestamps.drain(..len - 10);
                }
            }
        }

        if is_flooding {
            // Cooldown per IP to avoid incident spam on sustained floods.
            // IPS mode (auto_block on) must still return an incident so the
            // caller drops (NXDOMAIN); throttling only suppresses duplicate
            // IDS alerts when auto_block is off (forwarding is intended there).
            if !auto_block {
                if let Ok(mut cd) = self.flood_alert_cooldown.write() {
                    if let Some(last) = cd.get(source_ip) {
                        if now.duration_since(*last) < FLOOD_ALERT_COOLDOWN {
                            return None;
                        }
                    }
                    if cd.len() > 1024 {
                        let cutoff = now - FLOOD_ALERT_COOLDOWN;
                        cd.retain(|_, t| *t > cutoff);
                    }
                    cd.insert(source_ip.to_string(), now);
                }
            } else if let Ok(mut cd) = self.flood_alert_cooldown.write() {
                if cd.len() > 1024 {
                    let cutoff = now - FLOOD_ALERT_COOLDOWN;
                    cd.retain(|_, t| *t > cutoff);
                }
                cd.insert(source_ip.to_string(), now);
            }
            let mitigation = if auto_block {
                self.block_ip_temporarily(source_ip, Duration::from_secs(300));
                i18n::tr4(
                    "Đã tự động khóa IP nguồn trong 5 phút (IPS Mitigation)",
                    "Source IP auto-blocked for 5 minutes (IPS Mitigation)",
                    "已自动封锁源 IP 5 分钟 (IPS 处置)",
                    "IP-источник автоматически заблокирован на 5 минут (IPS)",
                )
            } else {
                i18n::tr4(
                    "Cảnh báo bảo mật (Auto-block chưa kích hoạt)",
                    "Security alert (Auto-block not enabled)",
                    "安全告警 (未启用自动封锁)",
                    "Оповещение безопасности (автоблокировка выключена)",
                )
            };

            let details = match i18n::current_index() {
                i18n::EN => format!(
                    "Abnormal query rate: {} req/2s (threshold {}/s)",
                    query_count_last_sec, limit
                ),
                i18n::ZH => format!(
                    "异常查询频率：{} 次/2秒（超过阈值 {}/s）",
                    query_count_last_sec, limit
                ),
                i18n::RU => format!(
                    "Аномальная частота запросов: {} за 2 с (порог {}/с)",
                    query_count_last_sec, limit
                ),
                _ => format!(
                    "Tần suất truy vấn bất thường: {} yêu cầu/2s (vượt ngưỡng {}/s)",
                    query_count_last_sec, limit
                ),
            };

            return Some(self.record_incident(
                i18n::tr4(
                    "Tấn công từ chối dịch vụ (DNS Flood / DoS)",
                    "Denial-of-Service attack (DNS Flood / DoS)",
                    "拒绝服务攻击 (DNS Flood / DoS)",
                    "DoS-атака (DNS Flood / DoS)",
                ),
                source_ip,
                &details,
                "CRITICAL",
                mitigation,
            ));
        }

        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 3 {
            for sub in &parts[..parts.len() - 2] {
                if sub.len() >= 28 {
                    let entropy = Self::calc_entropy(sub);
                    if entropy >= 3.85 {
                        let mitigation = if auto_block {
                            self.block_ip_temporarily(source_ip, Duration::from_secs(180));
                            i18n::tr4(
                                "Đã hủy gói tin & cô lập kết nối nguồn 3 phút",
                                "Packets dropped & source isolated for 3 minutes",
                                "已丢弃数据包并隔离源连接 3 分钟",
                                "Пакеты отброшены; источник изолирован на 3 минуты",
                            )
                        } else {
                            i18n::tr4(
                                "Đã ghi nhận mối nguy rò rỉ dữ liệu",
                                "Data-exfiltration risk logged",
                                "已记录数据泄露风险",
                                "Риск утечки данных зарегистрирован",
                            )
                        };

                        let details = match i18n::current_index() {
                            i18n::EN => format!(
                                "Suspicious subdomain carries encoded payload: '{}' (Entropy: {:.2}, Length: {})",
                                sub, entropy, sub.len()
                            ),
                            i18n::ZH => format!(
                                "可疑子域名包含编码负载：'{}'（熵：{:.2}，长度：{}）",
                                sub, entropy, sub.len()
                            ),
                            i18n::RU => format!(
                                "Подозрительный поддомен с закодированной нагрузкой: '{}' (энтропия {:.2}, длина {})",
                                sub, entropy, sub.len()
                            ),
                            _ => format!(
                                "Subdomain nghi vấn chứa payload mã hóa: '{}' (Entropy: {:.2}, Độ dài: {})",
                                sub, entropy, sub.len()
                            ),
                        };

                        return Some(self.record_incident(
                            i18n::tr4(
                                "Phát hiện DNS Tunneling / Rò rỉ dữ liệu",
                                "DNS Tunneling / Data Exfiltration detected",
                                "检测到 DNS 隧道 / 数据泄露",
                                "Обнаружен DNS-туннель / утечка данных",
                            ),
                            source_ip,
                            &details,
                            "HIGH",
                            mitigation,
                        ));
                    }
                }
            }
        }

        if Self::is_dga_domain(domain) {
            let mitigation = if auto_block {
                self.block_ip_temporarily(source_ip, Duration::from_secs(120));
                i18n::tr4(
                    "Đã hủy gói tin & cô lập IP kết nối botnet",
                    "Dropped query & isolated botnet communication",
                    "已丢弃查询并隔离僵尸网络通信",
                    "Запрос отброшен; связь с ботнетом изолирована",
                )
            } else {
                i18n::tr4(
                    "Đã ghi nhận cảnh báo tên miền DGA",
                    "DGA domain alert logged",
                    "已记录 DGA 域名告警",
                    "Тревога DGA-домена зарегистрирована",
                )
            };
            let details = format!(
                "{}: '{}'",
                i18n::tr4(
                    "Tên miền có đặc tính sinh tự động từ Botnet DGA",
                    "Domain matches Botnet DGA characteristics",
                    "域名符合僵尸网络 DGA 特征",
                    "Домен соответствует признакам DGA-ботнета"
                ),
                domain
            );
            return Some(self.record_incident(
                i18n::tr4(
                    "Phát hiện tên miền Botnet DGA (Algorithmically Generated Domain)",
                    "Botnet DGA Domain Detected",
                    "检测到僵尸网络 DGA 域名",
                    "Обнаружен DGA-домен ботнета",
                ),
                source_ip,
                &details,
                "HIGH",
                mitigation,
            ));
        }

        // Policy: `.onion` (Tor), `.bit` (Namecoin/EmerDNS) and `.bazar`
        // (EmerDNS/Bazar) are pseudo-TLDs never resolvable via standard DNS
        // and frequently abused for C2/botnet. Enforcement is ALWAYS NXDOMAIN,
        // even when `auto_block` is off — returning NXDOMAIN for non-routable
        // pseudo-TLDs is safe (legit DNS can never resolve them) and prevents
        // silent leaks to upstream resolvers. `.bit`/`.bazar` follow the same
        // always-block policy as `.onion`.
        if Self::is_darknet_pseudo_tld(domain) {
            // Always NXDOMAIN — not gated on auto_block. See `is_darknet_pseudo_tld`
            // docs and the DNS dispatch path which must drop these even in IDS-only mode.
            let mitigation = i18n::tr4(
                "Đã tự động cách ly tên miền độc hại (NXDOMAIN Drop)",
                "Malicious domain auto-isolated (NXDOMAIN Drop)",
                "已自动隔离恶意域名 (NXDOMAIN 丢弃)",
                "Вредоносный домен изолирован (NXDOMAIN Drop)",
            );

            let details = match i18n::current_index() {
                i18n::EN => format!("Query to botnet underground domain detected: {}", domain),
                i18n::ZH => format!("检测到访问僵尸网络隐蔽域名的查询：{}", domain),
                i18n::RU => format!("Обнаружен запрос к подпольному домену ботнета: {}", domain),
                _ => format!(
                    "Phát hiện truy vấn domain thuộc mạng lưới ngầm botnet: {}",
                    domain
                ),
            };

            return Some(self.record_incident(
                i18n::tr4(
                    "Máy chủ điều khiển Botnet / C2 độc hại",
                    "Botnet / Malicious C2 Server",
                    "僵尸网络 / 恶意 C2 控制服务器",
                    "Сервер управления ботнетом / вредоносный C2",
                ),
                source_ip,
                &details,
                "HIGH",
                mitigation,
            ));
        }

        None
    }

    pub fn inspect_arp_gateway(
        &self,
        gateway_ip: &str,
        current_gateway_mac: &str,
    ) -> Option<SecurityIncident> {
        if !self.is_detection_enabled() || !self.is_arp_detection_enabled() {
            return None;
        }
        if gateway_ip.is_empty() {
            return None;
        }

        // Snapshot last known gateway, then drop the lock before recording
        // incidents (record_incident takes a different lock).
        let last = self.last_known_gateway.read().ok().and_then(|g| g.clone());
        if let Some((last_ip, last_mac)) = last {
            if last_ip == gateway_ip {
                if last_mac != current_gateway_mac
                    && !current_gateway_mac.is_empty()
                    && current_gateway_mac != "00:00:00:00:00:00"
                {
                    let details = match i18n::current_index() {
                        i18n::EN => format!(
                            "Gateway {} MAC suddenly changed from {} to {}. A rogue device may be sniffing traffic!",
                            gateway_ip, last_mac, current_gateway_mac
                        ),
                        i18n::ZH => format!(
                            "网关 {} 的 MAC 地址突然从 {} 变为 {}。疑似存在陌生设备正在窃听流量！",
                            gateway_ip, last_mac, current_gateway_mac
                        ),
                        _ => format!(
                            "Địa chỉ MAC của Gateway {} bất ngờ bị thay đổi từ {} sang {}. Nghi vấn có thiết bị lạ đang nghe lén dữ liệu!",
                            gateway_ip, last_mac, current_gateway_mac
                        ),
                    };
                    let incident = self.record_incident(
                        i18n::tr(
                            "Tấn công giả mạo địa chỉ ARP (ARP Spoofing / MITM)",
                            "ARP address spoofing attack (ARP Spoofing / MITM)",
                            "ARP 地址伪造攻击 (ARP 欺骗 / 中间人)",
                        ),
                        gateway_ip,
                        &details,
                        "CRITICAL",
                        i18n::tr(
                            "Cảnh báo khẩn cấp: Đã phát hiện cuộc tấn công chuyển hướng mạng",
                            "Emergency alert: Network redirection attack detected",
                            "紧急告警：检测到网络流量劫持攻击",
                        ),
                    );
                    if let Ok(mut gw_guard) = self.last_known_gateway.write() {
                        *gw_guard = Some((gateway_ip.to_string(), current_gateway_mac.to_string()));
                    }
                    return Some(incident);
                }
                return None;
            } else {
                // Gateway IP changed (DHCP renew, network switch, rogue DHCP).
                // Update to the new (ip, mac) and emit a single INFO incident —
                // do not permanently disable detection.
                if let Ok(mut gw_guard) = self.last_known_gateway.write() {
                    *gw_guard = Some((gateway_ip.to_string(), current_gateway_mac.to_string()));
                }
                let details = match i18n::current_index() {
                    i18n::EN => format!(
                        "Default gateway changed from {} ({}) to {} ({}). Network may have switched; monitoring continues.",
                        last_ip, last_mac, gateway_ip, current_gateway_mac
                    ),
                    i18n::ZH => format!(
                        "默认网关已从 {} ({}) 变更为 {} ({})。网络可能已切换；监控继续。",
                        last_ip, last_mac, gateway_ip, current_gateway_mac
                    ),
                    _ => format!(
                        "Gateway mặc định đã đổi từ {} ({}) sang {} ({}). Có thể mạng đã chuyển; vẫn tiếp tục giám sát.",
                        last_ip, last_mac, gateway_ip, current_gateway_mac
                    ),
                };
                let incident = self.record_incident(
                    i18n::tr(
                        "Gateway thay đổi (Gateway Changed)",
                        "Default Gateway Changed",
                        "默认网关变更",
                    ),
                    gateway_ip,
                    &details,
                    "INFO",
                    i18n::tr(
                        "Đã cập nhật gateway mới và tiếp tục giám sát",
                        "Updated to new gateway and continuing monitoring",
                        "已更新为新网关并继续监控",
                    ),
                );
                return Some(incident);
            }
        } else if !current_gateway_mac.is_empty() && current_gateway_mac != "00:00:00:00:00:00" {
            if let Ok(mut gw_guard) = self.last_known_gateway.write() {
                *gw_guard = Some((gateway_ip.to_string(), current_gateway_mac.to_string()));
            }
        }

        None
    }

    pub fn record_inbound_port_probe(
        &self,
        remote_ip: &str,
        local_port: u16,
    ) -> Option<SecurityIncident> {
        if !self.is_detection_enabled() || remote_ip.is_empty() {
            return None;
        }
        if remote_ip == "127.0.0.1" || remote_ip == "::1" || remote_ip == "0.0.0.0" {
            return None;
        }

        let now = Instant::now();
        let distinct_ports = {
            let mut hist = self.port_probe_history.write().ok()?;
            if hist.len() > 512 {
                hist.retain(|_, probes| {
                    probes
                        .iter()
                        .any(|(_, t)| now.duration_since(*t) < PORT_SCAN_WINDOW)
                });
            }
            let probes = hist.entry(remote_ip.to_string()).or_default();
            probes.retain(|(_, t)| now.duration_since(*t) < PORT_SCAN_WINDOW);
            if !probes.iter().any(|(p, _)| *p == local_port) {
                probes.push((local_port, now));
            }
            probes.len()
        };

        if distinct_ports < PORT_SCAN_DISTINCT_PORTS {
            return None;
        }

        {
            let mut cooldown = self.port_scan_alert_cooldown.write().ok()?;
            if let Some(last) = cooldown.get(remote_ip) {
                if now.duration_since(*last) < PORT_SCAN_ALERT_COOLDOWN {
                    return None;
                }
            }
            if cooldown.len() > 500 {
                // Evict expired entries instead of clearing everything.
                cooldown.retain(|_, t| now.duration_since(*t) < PORT_SCAN_ALERT_COOLDOWN);
                if cooldown.len() > 500 {
                    // Still over budget: remove oldest entries.
                    let mut oldest: Vec<(String, Instant)> =
                        cooldown.iter().map(|(k, v)| (k.clone(), *v)).collect();
                    oldest.sort_by_key(|(_, t)| *t);
                    for (k, _) in oldest.into_iter().take(128) {
                        cooldown.remove(&k);
                    }
                }
            }
            cooldown.insert(remote_ip.to_string(), now);
        }

        let auto_block = self.is_auto_block_enabled();
        let mitigation = if auto_block {
            self.block_ip_temporarily(remote_ip, Duration::from_secs(600));
            i18n::tr4(
                "Đã tự động cô lập IP quét cổng trong 10 phút (IPS Mitigation)",
                "Port-scanning IP auto-isolated for 10 minutes (IPS Mitigation)",
                "已自动隔离端口扫描 IP 10 分钟 (IPS 处置)",
                "IP сканера портов изолирован на 10 минут (IPS)",
            )
        } else {
            i18n::tr4(
                "Cảnh báo quét cổng (Auto-block chưa kích hoạt)",
                "Port-scan alert (Auto-block not enabled)",
                "端口扫描告警 (未启用自动封锁)",
                "Тревога сканирования портов (автоблокировка выключена)",
            )
        };

        let details = match i18n::current_index() {
            i18n::EN => format!(
                "{} distinct local ports probed from this host within {}s (latest: port {})",
                distinct_ports,
                PORT_SCAN_WINDOW.as_secs(),
                local_port
            ),
            i18n::ZH => format!(
                "该主机在 {} 秒内被探测了 {} 个不同的本机端口（最近：端口 {}）",
                PORT_SCAN_WINDOW.as_secs(),
                distinct_ports,
                local_port
            ),
            i18n::RU => format!(
                "С этого хоста за {} с просканировано {} различных локальных портов (последний: {})",
                PORT_SCAN_WINDOW.as_secs(),
                distinct_ports,
                local_port
            ),
            _ => format!(
                "Phát hiện {} cổng cục bộ khác nhau bị dò từ máy này trong {}s (mới nhất: cổng {})",
                distinct_ports,
                PORT_SCAN_WINDOW.as_secs(),
                local_port
            ),
        };

        Some(self.record_incident(
            i18n::tr4(
                "Phát hiện quét cổng hàng loạt (Inbound Port Scan)",
                "Mass port scanning detected (Inbound Port Scan)",
                "检测到批量端口扫描 (Inbound Port Scan)",
                "Обнаружено массовое сканирование портов",
            ),
            remote_ip,
            &details,
            "HIGH",
            mitigation,
        ))
    }

    pub fn export_incidents_csv(&self) -> Result<String, String> {
        // Clone under read lock, then drop guard before blocking fs I/O.
        let incidents: Vec<SecurityIncident> = self
            .incidents
            .read()
            .map(|l| l.clone())
            .map_err(|e| e.to_string())?;
        fn csv_escape(field: &str) -> String {
            let risky = field
                .chars()
                .next()
                .map(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r'))
                .unwrap_or(false);
            let mut s = field.replace('"', "\"\"");
            if risky {
                s = format!("'{}", s);
            }
            format!("\"{}\"", s)
        }
        let mut csv = String::from("time,severity,incident_type,source_ip,details,mitigation\n");
        for inc in incidents.iter() {
            csv.push_str(&format!(
                "{},{},{},{},{},{}\n",
                csv_escape(&inc.time),
                csv_escape(&inc.severity),
                csv_escape(&inc.incident_type),
                csv_escape(&inc.source_ip),
                csv_escape(&inc.details),
                csv_escape(&inc.mitigation),
            ));
        }
        let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        let path = std::path::PathBuf::from(app_data)
            .join("ShieldGhita")
            .join(format!(
                "incidents_export_{}.csv",
                // Millis suffix avoids collision on rapid double-exports.
                Local::now().format("%Y%m%d_%H%M%S_%3f")
            ));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&path, &csv).map_err(|e| e.to_string())?;
        info!("Exported {} incidents to {:?}", incidents.len(), path);
        Ok(path.to_string_lossy().to_string())
    }

    pub fn get_security_score(&self) -> i32 {
        let incident_count = self.incidents.read().map(|l| l.len()).unwrap_or(0);
        let detection_on = self.is_detection_enabled();
        let auto_block_on = self.is_auto_block_enabled();

        let mut base = 100i32;
        if !detection_on {
            base -= 25;
        }
        if !auto_block_on {
            base -= 15;
        }
        let penalty = (incident_count as i32) * 5;
        (base - penalty).clamp(10, 100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_binds_owner_and_protects_routes() {
        let sec = SecurityEngine::new();
        let self_ips = vec!["192.0.2.10".into()];
        let gateways = vec!["192.0.2.1".into()];
        let observed = vec![("192.0.2.24".into(), "02:00:00:00:00:24".into())];
        assert_eq!(
            sec.quarantine_ip("192.0.2.24"),
            Err(QuarantineRejection::InventoryUnavailable)
        );
        sec.update_quarantine_inventory(&observed, &self_ips, &gateways);
        assert_eq!(
            sec.quarantine_ip("192.0.2.10"),
            Err(QuarantineRejection::SelfAddress)
        );
        assert_eq!(
            sec.quarantine_ip("192.0.2.1"),
            Err(QuarantineRejection::GatewayAddress)
        );
        assert_eq!(
            sec.quarantine_ip("192.0.2.25"),
            Err(QuarantineRejection::IdentityUnknown)
        );
        for ip in [
            "invalid",
            "127.0.0.2",
            "::1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(sec.quarantine_ip(ip).is_err());
        }
        sec.quarantine_ip("192.0.2.24").unwrap();
        let count = sec.incidents_count();
        sec.quarantine_ip("192.0.2.24").unwrap();
        assert_eq!(sec.incidents_count(), count);
        assert!(sec.is_quarantined("192.0.2.24"));
        sec.update_quarantine_inventory(&[], &self_ips, &gateways);
        assert!(sec.is_quarantined("192.0.2.24"));
        sec.update_quarantine_inventory(
            &[("192.0.2.24".into(), "02:00:00:00:00:25".into())],
            &self_ips,
            &gateways,
        );
        assert!(!sec.is_quarantined("192.0.2.24"));
        sec.quarantine_ip("192.0.2.24").unwrap();
        sec.unquarantine_ip("192.0.2.24");
        assert!(!sec.is_quarantined("192.0.2.24"));
        sec.quarantine.write().unwrap().observed_at =
            Some(Instant::now() - Duration::from_secs(601));
        assert_eq!(
            sec.quarantine_ip("192.0.2.24"),
            Err(QuarantineRejection::InventoryUnavailable)
        );
    }

    #[test]
    fn test_entropy_calculation() {
        let low_entropy = SecurityEngine::calc_entropy("aaaaaaaaaa");
        assert_eq!(low_entropy, 0.0);

        let high_entropy = SecurityEngine::calc_entropy("9f8c2b7e1a0d3f6c8b4e2a1");
        assert!(high_entropy > 3.0);
    }

    #[test]
    fn test_dns_flood_detection() {
        let sec = SecurityEngine::new();
        sec.set_detection_enabled(true);
        sec.set_auto_block(true);

        let test_ip = "192.168.1.150";
        let mut alert = None;

        for _ in 0..100 {
            if let Some(inc) = sec.inspect_dns_query(test_ip, "google.com") {
                alert = Some(inc);
                break;
            }
        }

        assert!(alert.is_some());
        assert!(sec.is_ip_temporarily_blocked(test_ip));
    }

    #[test]
    fn test_dns_tunneling_detection() {
        let sec = SecurityEngine::new();
        sec.set_detection_enabled(true);

        let tunneling_domain = "a8f9c1b3e70d42fa89b2c3d4e5f6.exfil.attacker.com";
        let alert = sec.inspect_dns_query("192.168.1.55", tunneling_domain);
        assert!(alert.is_some());
        assert!(alert.unwrap().incident_type.contains("Tunneling"));
    }

    #[test]
    fn test_dga_domain_detection() {
        assert!(SecurityEngine::is_dga_domain("bcdfghjklmn.com"));
        assert!(SecurityEngine::is_dga_domain("x987bfdsklfjq93.biz"));
        assert!(!SecurityEngine::is_dga_domain("google.com"));
        assert!(!SecurityEngine::is_dga_domain("facebook.com"));
        assert!(!SecurityEngine::is_dga_domain("vnexpress.net"));
    }

    #[test]
    fn test_hard_rate_limit_without_ids() {
        let sec = SecurityEngine::new();
        sec.set_detection_enabled(false);

        let test_ip = "192.168.1.77";
        let mut tripped = false;
        for _ in 0..400 {
            if sec.enforce_hard_rate_limit(test_ip) {
                tripped = true;
                break;
            }
        }
        assert!(tripped);
        assert!(sec.is_ip_temporarily_blocked(test_ip));
        assert_eq!(sec.hard_drop_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_hard_rate_limit_ignores_loopback() {
        let sec = SecurityEngine::new();
        sec.set_detection_enabled(false);
        for _ in 0..500 {
            assert!(!sec.enforce_hard_rate_limit("127.0.0.1"));
        }
        assert_eq!(sec.hard_drop_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_inbound_port_scan_detection() {
        let sec = SecurityEngine::new();
        sec.set_detection_enabled(true);

        let scanner_ip = "192.0.2.77";
        let mut alert = None;
        for port in 40000u16..40100 {
            if let Some(inc) = sec.record_inbound_port_probe(scanner_ip, port) {
                alert = Some(inc);
                break;
            }
        }
        let alert = alert.expect("port scan must be flagged after threshold ports");
        assert!(alert.incident_type.contains("Port Scan"));

        assert!(sec.record_inbound_port_probe(scanner_ip, 50000).is_none());
        assert!(sec.record_inbound_port_probe("127.0.0.1", 60000).is_none());
    }

    #[test]
    fn test_port_scan_disabled_with_ids_off() {
        let sec = SecurityEngine::new();
        sec.set_detection_enabled(false);
        for port in 41000u16..41100 {
            assert!(sec.record_inbound_port_probe("192.0.2.90", port).is_none());
        }
    }

    #[test]
    fn test_perf_calc_entropy() {
        crate::modules::perf::measure("security::calc_entropy", 200_000, || {
            std::hint::black_box(SecurityEngine::calc_entropy(
                "xkf83kadfjw93jdakslfjq2984ujdkslfjq93udjasdk123",
            ));
        });
    }
}
