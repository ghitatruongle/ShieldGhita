use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::modules::i18n;

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
    quarantined_ips: Arc<RwLock<std::collections::HashSet<String>>>,
    port_probe_history: PortProbeHistory,
    port_scan_alert_cooldown: Arc<RwLock<HashMap<String, Instant>>>,
    pub alert_tx: broadcast::Sender<SecurityIncident>,
}

const PORT_SCAN_WINDOW: Duration = Duration::from_secs(60);
const PORT_SCAN_DISTINCT_PORTS: usize = 10;
const PORT_SCAN_ALERT_COOLDOWN: Duration = Duration::from_secs(600);

type PortProbeHistory = Arc<RwLock<HashMap<String, Vec<(u16, Instant)>>>>;

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
            quarantined_ips: Arc::new(RwLock::new(std::collections::HashSet::new())),
            incidents: Arc::new(RwLock::new(Vec::new())),
            incident_counter: Arc::new(AtomicU64::new(1)),
            last_known_gateway: Arc::new(RwLock::new(None)),
            port_probe_history: Arc::new(RwLock::new(HashMap::new())),
            port_scan_alert_cooldown: Arc::new(RwLock::new(HashMap::new())),
            alert_tx,
        }
    }

    pub fn is_detection_enabled(&self) -> bool {
        self.attack_detection_enabled.load(Ordering::Relaxed)
    }

    pub fn enforce_hard_rate_limit(&self, source_ip: &str) -> bool {
        if source_ip == "127.0.0.1" || source_ip == "::1" {
            return false;
        }
        let base = self.dns_flood_rate_limit.read().map(|g| *g).unwrap_or(80);
        let hard_limit = (base.saturating_mul(4)).max(200) as usize;
        let now = Instant::now();

        let mut exceeded = false;
        if let Ok(mut hist) = self.hard_query_history.write() {
            if hist.len() > 1000 {
                hist.retain(|_, v| {
                    v.iter()
                        .any(|t| now.duration_since(*t) < Duration::from_secs(2))
                });
            }
            let timestamps = hist.entry(source_ip.to_string()).or_default();
            timestamps.retain(|t| now.duration_since(*t) < Duration::from_secs(2));
            timestamps.push(now);
            if timestamps.len() > hard_limit {
                timestamps.clear();
                exceeded = true;
            }
        }

        if exceeded {
            self.hard_drop_count.fetch_add(1, Ordering::SeqCst);
            self.block_ip_temporarily(source_ip, Duration::from_secs(60));
            warn!(
                "Security Hard Rate Limit: {} exceeded {} queries/2s — isolating source for 60s",
                source_ip, hard_limit
            );
        }
        exceeded
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
        if let Ok(mut map) = self.blocked_ips.write() {
            if let Some(exp) = map.get(ip) {
                if Instant::now() < *exp {
                    return true;
                } else {
                    map.remove(ip);
                }
            }
        }
        false
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

    pub fn quarantine_ip(&self, ip: &str) {
        let clean = ip.trim().to_string();
        if clean.is_empty() || clean == "127.0.0.1" || clean == "::1" {
            return;
        }
        if let Ok(mut set) = self.quarantined_ips.write() {
            set.insert(clean.clone());
            info!("Device {} has been quarantined by administrator", clean);
        }
        self.record_incident(
            i18n::tr(
                "Thiết bị đã bị cô lập (Quarantined)",
                "Device Quarantined by Admin",
                "设备已被管理员隔离",
            ),
            &clean,
            &format!(
                "{} {}",
                i18n::tr(
                    "Quản trị viên đã đưa thiết bị vào chế độ cách ly kiểm dịch mạng:",
                    "Administrator isolated network device:",
                    "管理员已将网络设备隔离:"
                ),
                clean
            ),
            "HIGH",
            i18n::tr(
                "Đã ngắt toàn bộ quyền truy cập Internet/DNS",
                "All Internet & DNS access severed",
                "已阻断所有互联网与 DNS 访问",
            ),
        );
    }

    pub fn unquarantine_ip(&self, ip: &str) {
        let clean = ip.trim();
        if let Ok(mut set) = self.quarantined_ips.write() {
            set.remove(clean);
            info!("Device {} has been released from quarantine", clean);
        }
    }

    pub fn is_quarantined(&self, ip: &str) -> bool {
        self.quarantined_ips
            .read()
            .map(|s| s.contains(ip.trim()))
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn get_quarantined_ips(&self) -> Vec<String> {
        self.quarantined_ips
            .read()
            .map(|s| s.iter().cloned().collect())
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
                _ => format!(
                    "Phát hiện máy chủ DHCP giả mạo tại IP {} ({})! Gateway DHCP chính thức dự kiến: {}",
                    server_ip, server_mac, expected_gateway
                ),
            };

            let incident = self.record_incident(
                i18n::tr(
                    "Máy chủ DHCP giả mạo (Rogue DHCP Server)",
                    "Rogue DHCP Server Detected",
                    "非法 DHCP 服务器 (Rogue DHCP)",
                ),
                server_ip,
                &details,
                "CRITICAL",
                i18n::tr(
                    "Cảnh báo: Nguy cơ chiếm quyền cấp phát IP và chuyển hướng mạng",
                    "Alert: Risk of IP allocation hijacking and traffic redirection",
                    "告警：存在 IP 分配劫持及流量重定向风险",
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
            let lower = trimmed.to_lowercase();
            for target in &sensitive_targets {
                if lower.contains(target) {
                    let incident = self.record_incident(
                        i18n::tr(
                            "Phát hiện chỉnh sửa độc hại tệp Hosts (Hosts Tamper)",
                            "Hosts File Tampering / Malicious Hijack Detected",
                            "检测到恶意篡改 Hosts 文件 (Hosts Tamper)",
                        ),
                        "127.0.0.1",
                        &format!(
                            "{}: '{}'",
                            i18n::tr(
                                "Tệp hosts chứa bản ghi chuyển hướng tên miền nhạy cảm",
                                "Hosts file contains sensitive domain redirection",
                                "Hosts 文件包含敏感域名重定向记录"
                            ),
                            trimmed
                        ),
                        "CRITICAL",
                        i18n::tr(
                            "Đề xuất: Khôi phục tệp hosts về trạng thái mặc định của Windows",
                            "Recommended: Restore hosts file to default Windows clean state",
                            "建议：将 hosts 文件恢复为 Windows 默认干净状态",
                        ),
                    );
                    return Some(incident);
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
                history_map.retain(|_, v| {
                    v.iter()
                        .any(|t| now.duration_since(*t) < Duration::from_secs(2))
                });
                if history_map.len() > 1000 {
                    history_map.clear();
                }
            }
            let timestamps = history_map.entry(source_ip.to_string()).or_default();
            timestamps.retain(|t| now.duration_since(*t) < Duration::from_secs(2));
            timestamps.push(now);
            query_count_last_sec = timestamps.len();

            if query_count_last_sec > limit as usize {
                is_flooding = true;
                timestamps.clear();
            }
        }

        if is_flooding {
            let mitigation = if auto_block {
                self.block_ip_temporarily(source_ip, Duration::from_secs(300));
                i18n::tr(
                    "Đã tự động khóa IP nguồn trong 5 phút (IPS Mitigation)",
                    "Source IP auto-blocked for 5 minutes (IPS Mitigation)",
                    "已自动封锁源 IP 5 分钟 (IPS 处置)",
                )
            } else {
                i18n::tr(
                    "Cảnh báo bảo mật (Auto-block chưa kích hoạt)",
                    "Security alert (Auto-block not enabled)",
                    "安全告警 (未启用自动封锁)",
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
                _ => format!(
                    "Tần suất truy vấn bất thường: {} yêu cầu/2s (vượt ngưỡng {}/s)",
                    query_count_last_sec, limit
                ),
            };

            return Some(self.record_incident(
                i18n::tr(
                    "Tấn công từ chối dịch vụ (DNS Flood / DoS)",
                    "Denial-of-Service attack (DNS Flood / DoS)",
                    "拒绝服务攻击 (DNS Flood / DoS)",
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
                            i18n::tr(
                                "Đã hủy gói tin & cô lập kết nối nguồn 3 phút",
                                "Packets dropped & source isolated for 3 minutes",
                                "已丢弃数据包并隔离源连接 3 分钟",
                            )
                        } else {
                            i18n::tr(
                                "Đã ghi nhận mối nguy rò rỉ dữ liệu",
                                "Data-exfiltration risk logged",
                                "已记录数据泄露风险",
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
                            _ => format!(
                                "Subdomain nghi vấn chứa payload mã hóa: '{}' (Entropy: {:.2}, Độ dài: {})",
                                sub, entropy, sub.len()
                            ),
                        };

                        return Some(self.record_incident(
                            i18n::tr(
                                "Phát hiện DNS Tunneling / Rò rỉ dữ liệu",
                                "DNS Tunneling / Data Exfiltration detected",
                                "检测到 DNS 隧道 / 数据泄露",
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
                i18n::tr(
                    "Đã hủy gói tin & cô lập IP kết nối botnet",
                    "Dropped query & isolated botnet communication",
                    "已丢弃查询并隔离僵尸网络通信",
                )
            } else {
                i18n::tr(
                    "Đã ghi nhận cảnh báo tên miền DGA",
                    "DGA domain alert logged",
                    "已记录 DGA 域名告警",
                )
            };
            let details = format!(
                "{}: '{}'",
                i18n::tr(
                    "Tên miền có đặc tính sinh tự động từ Botnet DGA",
                    "Domain matches Botnet DGA characteristics",
                    "域名符合僵尸网络 DGA 特征"
                ),
                domain
            );
            return Some(self.record_incident(
                i18n::tr(
                    "Phát hiện tên miền Botnet DGA (Algorithmically Generated Domain)",
                    "Botnet DGA Domain Detected",
                    "检测到僵尸网络 DGA 域名",
                ),
                source_ip,
                &details,
                "HIGH",
                mitigation,
            ));
        }

        let lower = domain.to_lowercase();
        if lower.ends_with(".onion") || lower.ends_with(".bit") || lower.ends_with(".bazar") {
            let mitigation = if auto_block {
                i18n::tr(
                    "Đã tự động cách ly tên miền độc hại (NXDOMAIN Drop)",
                    "Malicious domain auto-isolated (NXDOMAIN Drop)",
                    "已自动隔离恶意域名 (NXDOMAIN 丢弃)",
                )
            } else {
                i18n::tr(
                    "Cảnh báo truy cập Darknet/Botnet",
                    "Darknet/Botnet access alert",
                    "Darknet/僵尸网络访问告警",
                )
            };

            let details = match i18n::current_index() {
                i18n::EN => format!("Query to botnet underground domain detected: {}", domain),
                i18n::ZH => format!("检测到访问僵尸网络隐蔽域名的查询：{}", domain),
                _ => format!(
                    "Phát hiện truy vấn domain thuộc mạng lưới ngầm botnet: {}",
                    domain
                ),
            };

            return Some(self.record_incident(
                i18n::tr(
                    "Máy chủ điều khiển Botnet / C2 độc hại",
                    "Botnet / Malicious C2 Server",
                    "僵尸网络 / 恶意 C2 控制服务器",
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

        let mut gw_guard = self.last_known_gateway.write().ok()?;
        if let Some((ref last_ip, ref last_mac)) = *gw_guard {
            if last_ip == gateway_ip
                && last_mac != current_gateway_mac
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
                *gw_guard = Some((gateway_ip.to_string(), current_gateway_mac.to_string()));
                return Some(incident);
            }
        } else if !current_gateway_mac.is_empty() && current_gateway_mac != "00:00:00:00:00:00" {
            *gw_guard = Some((gateway_ip.to_string(), current_gateway_mac.to_string()));
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
                cooldown.clear();
            }
            cooldown.insert(remote_ip.to_string(), now);
        }

        let auto_block = self.is_auto_block_enabled();
        let mitigation = if auto_block {
            self.block_ip_temporarily(remote_ip, Duration::from_secs(600));
            i18n::tr(
                "Đã tự động cô lập IP quét cổng trong 10 phút (IPS Mitigation)",
                "Port-scanning IP auto-isolated for 10 minutes (IPS Mitigation)",
                "已自动隔离端口扫描 IP 10 分钟 (IPS 处置)",
            )
        } else {
            i18n::tr(
                "Cảnh báo quét cổng (Auto-block chưa kích hoạt)",
                "Port-scan alert (Auto-block not enabled)",
                "端口扫描告警 (未启用自动封锁)",
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
            _ => format!(
                "Phát hiện {} cổng cục bộ khác nhau bị dò từ máy này trong {}s (mới nhất: cổng {})",
                distinct_ports,
                PORT_SCAN_WINDOW.as_secs(),
                local_port
            ),
        };

        Some(self.record_incident(
            i18n::tr(
                "Phát hiện quét cổng hàng loạt (Inbound Port Scan)",
                "Mass port scanning detected (Inbound Port Scan)",
                "检测到批量端口扫描 (Inbound Port Scan)",
            ),
            remote_ip,
            &details,
            "HIGH",
            mitigation,
        ))
    }

    pub fn export_incidents_csv(&self) -> Result<String, String> {
        let incidents = self.incidents.read().map_err(|e| e.to_string())?;
        let mut csv = String::from("time,severity,incident_type,source_ip,details,mitigation\n");
        for inc in incidents.iter() {
            csv.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                inc.time,
                inc.severity,
                inc.incident_type,
                inc.source_ip,
                inc.details.replace('"', "\"\""),
                inc.mitigation.replace('"', "\"\"")
            ));
        }
        let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        let path = std::path::PathBuf::from(app_data)
            .join("ShieldGhita")
            .join(format!(
                "incidents_export_{}.csv",
                Local::now().format("%Y%m%d_%H%M%S")
            ));
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
