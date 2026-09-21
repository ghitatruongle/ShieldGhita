use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Duration;
use tracing::info;

use super::port_scanner::{self, OpenPort, PortRisk};
use crate::modules::i18n;

const MAX_ARP_TABLE_ENTRIES: usize = 4096;

#[derive(Deserialize)]
struct AdapterIpv4 {
    address: Ipv4Addr,
    prefix: u8,
    gateway: Option<Ipv4Addr>,
}

fn read_adapter_ipv4() -> Vec<AdapterIpv4> {
    let script = "@(Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object { $g = @($_.IPv4DefaultGateway.NextHop)[0]; foreach ($a in $_.IPv4Address) { [pscustomobject]@{ address=$a.IPAddress; prefix=$a.PrefixLength; gateway=if ($g) { [string]$g } else { $null } } } }) | ConvertTo-Json -Compress";
    let Ok(output) = crate::modules::system::silent_command("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    serde_json::from_slice(&output.stdout).unwrap_or_default()
}

fn bounded_subnet_hosts(local: Ipv4Addr, prefix: u8, cap: usize) -> Vec<Ipv4Addr> {
    if prefix > 32 || local.is_loopback() || local.is_link_local() || local.is_unspecified() {
        return Vec::new();
    }
    let value = u32::from(local);
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    let network = value & mask;
    let broadcast = network | !mask;
    let (first, last) = if prefix >= 31 {
        (network, broadcast)
    } else {
        (network + 1, broadcast - 1)
    };
    let count = u64::from(last) - u64::from(first) + 1;
    let start = if count > cap as u64 {
        value.saturating_sub((cap / 2) as u32).max(first)
    } else {
        first
    };
    (u64::from(start)..=u64::from(last))
        .take(cap.min(254))
        .map(|n| Ipv4Addr::from(n as u32))
        .filter(|ip| *ip != local)
        .collect()
}

fn parse_arp_table(text: &str, limit: usize) -> (Vec<(String, String)>, usize) {
    let mut entries = Vec::new();
    let mut skipped = 0;
    for line in text.lines() {
        if entries.len() >= limit {
            break;
        }
        let mut parts = line.split_whitespace();
        let (Some(ip), Some(mac), Some(_kind)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let Ok(ip) = ip.parse::<Ipv4Addr>() else {
            continue;
        };
        let mac = mac.replace('-', ":").to_uppercase();
        let octets: Vec<_> = mac.split(':').collect();
        let valid_mac = octets.len() == 6
            && octets
                .iter()
                .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit()));
        if !valid_mac
            || ip.is_multicast()
            || ip.is_broadcast()
            || ip.is_unspecified()
            || ip.is_loopback()
            || mac == "FF:FF:FF:FF:FF:FF"
            || mac == "00:00:00:00:00:00"
        {
            skipped += 1;
            continue;
        }
        entries.push((ip.to_string(), mac));
    }
    (entries, skipped)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanDevice {
    pub name: String,
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub device_type: String,
    pub is_online: bool,
    pub latency_ms: i32,
    pub traffic: String,
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub threats_detected: u64,
    pub last_domain: String,
    pub last_active: String,
    pub risk_level: String,
    pub open_ports: Vec<OpenPort>,
    pub port_risk: String,
    pub port_advice: String,
    pub confidence: i32,
    pub custom_alias: String,
    pub os_name: String,
    pub is_quarantined: bool,
    pub bandwidth_rate: String,
}

pub type DeviceActivityMap = Arc<RwLock<HashMap<String, (u64, u64, u64, String, String)>>>;

pub struct LanScanner {
    devices: Arc<RwLock<Vec<LanDevice>>>,
    activity_map: DeviceActivityMap,
    notified_high_risk: Arc<RwLock<HashSet<String>>>,
    is_scanning: Arc<RwLock<bool>>,
}

impl LanScanner {
    pub fn new() -> Self {
        Self {
            devices: Arc::new(RwLock::new(Vec::new())),
            activity_map: Arc::new(RwLock::new(HashMap::new())),
            notified_high_risk: Arc::new(RwLock::new(HashSet::new())),
            is_scanning: Arc::new(RwLock::new(false)),
        }
    }

    pub fn is_scanning(&self) -> bool {
        *self.is_scanning.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn confidence_score(
        vendor_known: bool,
        has_tcp_service: bool,
        has_netbios: bool,
        has_mdns: bool,
        has_ssdp: bool,
    ) -> i32 {
        let mut score = 0i32;
        if vendor_known {
            score += 2;
        }
        if has_tcp_service {
            score += 3;
        }
        if has_netbios {
            score += 1;
        }
        if has_mdns {
            score += 2;
        }
        if has_ssdp {
            score += 2;
        }
        score * 10
    }

    pub fn record_activity(&self, ip: &str, domain: &str, is_blocked: bool, is_threat: bool) {
        let time_str = chrono::Local::now().format("%H:%M:%S").to_string();
        if let Ok(mut map) = self.activity_map.write() {
            // Cap map growth so long-running processes do not leak memory
            // when many ephemeral client IPs appear. Evict ~1024 entries
            // instead of clear() so long-lived device history survives.
            if map.len() > 4096 {
                let excess = map.len().saturating_sub(3072);
                let keys: Vec<String> = map.keys().take(excess).cloned().collect();
                for k in keys {
                    map.remove(&k);
                }
            }
            let entry =
                map.entry(ip.to_string())
                    .or_insert((0, 0, 0, "-".to_string(), "-".to_string()));
            entry.0 += 1;
            if is_blocked {
                entry.1 += 1;
            }
            if is_threat {
                entry.2 += 1;
            }
            entry.3 = domain.to_string();
            entry.4 = time_str;
        }
    }

    pub fn devices_len(&self) -> usize {
        self.devices.read().map(|d| d.len()).unwrap_or(0)
    }

    pub fn get_devices(&self) -> Vec<LanDevice> {
        let raw_devices = self.devices.read().map(|d| d.clone()).unwrap_or_default();
        let activity = self
            .activity_map
            .read()
            .map(|m| m.clone())
            .unwrap_or_default();

        raw_devices
            .into_iter()
            .map(|mut d| {
                if let Some((total, blocked, threats, last_domain, last_time)) = activity.get(&d.ip)
                {
                    d.total_queries = *total;
                    d.blocked_queries = *blocked;
                    d.threats_detected = *threats;
                    d.last_domain = last_domain.clone();
                    d.last_active = last_time.clone();
                    d.risk_level = if *threats > 0 {
                        i18n::tr(
                            "🚨 Nguy hiểm (Phát hiện mối đe dọa)",
                            "🚨 Dangerous (Threats detected)",
                            "🚨 危险 (检测到威胁)",
                        )
                        .to_string()
                    } else if *blocked > 10 {
                        i18n::tr(
                            "🛡️ An toàn (Đã lọc quảng cáo)",
                            "🛡️ Safe (Ads filtered)",
                            "🛡️ 安全 (已过滤广告)",
                        )
                        .to_string()
                    } else {
                        i18n::tr("🟢 An toàn", "🟢 Safe", "🟢 安全").to_string()
                    };
                } else if d.ip == "127.0.0.1" || d.mac.contains(i18n::tr("Local", "Local", "本地"))
                {
                    if let Some((total, blocked, threats, last_domain, last_time)) =
                        activity.get("127.0.0.1")
                    {
                        d.total_queries = *total;
                        d.blocked_queries = *blocked;
                        d.threats_detected = *threats;
                        d.last_domain = last_domain.clone();
                        d.last_active = last_time.clone();
                    }
                }
                d
            })
            .collect()
    }

    pub fn get_local_outbound_ip() -> Option<Ipv4Addr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        if let Ok(SocketAddr::V4(addr)) = socket.local_addr() {
            let ip = *addr.ip();
            if !ip.is_loopback() && !ip.is_unspecified() {
                return Some(ip);
            }
        }
        None
    }

    pub async fn query_netbios_name(ip: &str) -> Option<String> {
        let target_addr: SocketAddr = format!("{}:137", ip).parse().ok()?;
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().ok()?;
        let socket = UdpSocket::bind(bind_addr).await.ok()?;

        let packet = vec![
            0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43,
            0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
        ];

        let _ = socket.send_to(&packet, target_addr).await;

        let mut buf = [0u8; 1024];
        if let Ok(Ok((len, _))) =
            tokio::time::timeout(Duration::from_millis(250), socket.recv_from(&mut buf)).await
        {
            if len > 56 {
                let num_names = buf[56] as usize;
                let mut offset = 57;
                for _ in 0..num_names {
                    if offset + 18 <= len {
                        let name_bytes = &buf[offset..offset + 15];
                        let name_type = buf[offset + 15];
                        let flags = u16::from_be_bytes([buf[offset + 16], buf[offset + 17]]);
                        let is_group = (flags & 0x8000) != 0;
                        if name_type == 0x00 && !is_group {
                            let name = String::from_utf8_lossy(name_bytes).trim().to_string();
                            if !name.is_empty() && name != "IS~" {
                                return Some(name);
                            }
                        }
                        offset += 18;
                    }
                }
            }
        }
        None
    }

    pub async fn probe_device_services(ip: &str) -> (Option<&'static str>, Option<i32>) {
        let ports_and_types = [
            (
                554,
                i18n::tr(
                    "📷 Camera an ninh (RTSP/CCTV)",
                    "📷 Security Camera (RTSP/CCTV)",
                    "📷 安防摄像机 (IP Camera / RTSP)",
                ),
            ),
            (
                8000,
                i18n::tr(
                    "📷 Camera Hikvision / DVR",
                    "📷 Hikvision Camera / DVR",
                    "📷 海康威视摄像机 (Hikvision Camera / DVR)",
                ),
            ),
            (
                37777,
                i18n::tr(
                    "📷 Camera Dahua / KBVision",
                    "📷 Dahua / KBVision Camera",
                    "📷 大华摄像机 (Dahua / KBVision Camera)",
                ),
            ),
            (
                8899,
                i18n::tr(
                    "📷 Camera ONVIF IP",
                    "📷 ONVIF IP Camera",
                    "📷 ONVIF 网络摄像机 (ONVIF IP Camera)",
                ),
            ),
            (
                9100,
                i18n::tr(
                    "🖨️ Máy in mạng (Printer - RAW/JetDirect)",
                    "🖨️ Network Printer (RAW/JetDirect)",
                    "🖨️ 网络打印机 (Printer - RAW/JetDirect)",
                ),
            ),
            (
                631,
                i18n::tr(
                    "🖨️ Máy in mạng (Printer - IPP)",
                    "🖨️ Network Printer (IPP)",
                    "🖨️ 网络打印机 (Printer - IPP)",
                ),
            ),
            (
                8008,
                i18n::tr(
                    "📺 Smart TV / Google Cast",
                    "📺 Smart TV / Google Cast",
                    "📺 智能电视 (Smart TV / Google Cast)",
                ),
            ),
            (
                8009,
                i18n::tr(
                    "📺 Smart TV / Chromecast",
                    "📺 Smart TV / Chromecast",
                    "📺 智能电视 (Smart TV / Chromecast)",
                ),
            ),
            (
                7000,
                i18n::tr(
                    "📺 Smart TV / AirPlay",
                    "📺 Smart TV / AirPlay",
                    "📺 智能电视 (Smart TV / AirPlay)",
                ),
            ),
            (
                445,
                i18n::tr(
                    "💻 Máy tính (Windows PC)",
                    "💻 Computer (Windows PC)",
                    "💻 电脑 (Windows PC)",
                ),
            ),
            (
                139,
                i18n::tr(
                    "💻 Máy tính (PC - NetBIOS)",
                    "💻 Computer (PC - NetBIOS)",
                    "💻 电脑 (PC - NetBIOS)",
                ),
            ),
            (
                3389,
                i18n::tr(
                    "💻 Máy tính (PC - Remote Desktop)",
                    "💻 Computer (PC - Remote Desktop)",
                    "💻 电脑 (PC - 远程桌面)",
                ),
            ),
            (
                22,
                i18n::tr(
                    "🖥️ Máy chủ / Server (Linux/Mac)",
                    "🖥️ Computer / Server (Linux/Mac)",
                    "🖥️ 电脑 / 服务器 (Server - Linux/Mac)",
                ),
            ),
            (
                62078,
                i18n::tr(
                    "📱 iPhone / iPad (Apple iOS)",
                    "📱 iPhone / iPad (Apple iOS)",
                    "📱 iPhone / iPad (苹果 iOS)",
                ),
            ),
            (
                5555,
                i18n::tr(
                    "📱 Điện thoại Android (ADB)",
                    "📱 Android Phone (ADB)",
                    "📱 安卓手机 (Android Phone - ADB)",
                ),
            ),
            (
                80,
                i18n::tr(
                    "🌐 Thiết bị mạng / Web",
                    "🌐 Network Device / Web",
                    "🌐 网络设备 / Web",
                ),
            ),
            (
                443,
                i18n::tr(
                    "🌐 Thiết bị mạng (HTTPS)",
                    "🌐 Network Device (HTTPS)",
                    "🌐 网络设备 (HTTPS)",
                ),
            ),
            (
                8080,
                i18n::tr(
                    "🌐 Thiết bị thông minh (Web Port)",
                    "🌐 Smart Device (Web Port)",
                    "🌐 智能设备 (Web Port)",
                ),
            ),
        ];

        let mut join_set = tokio::task::JoinSet::new();

        for (port, dev_type) in ports_and_types {
            let addr = format!("{}:{}", ip, port);
            join_set.spawn(async move {
                // Per-port Instant: measuring from a shared scan start inflates
                // latency by join ordering instead of the actual connect time.
                let t0 = Instant::now();
                let connected =
                    tokio::time::timeout(Duration::from_millis(80), TcpStream::connect(&addr))
                        .await
                        .is_ok_and(|r| r.is_ok());
                (port, dev_type, connected, t0.elapsed().as_millis())
            });
        }

        let mut open_hits: Vec<(usize, &'static str, u128)> = Vec::new();
        while let Some(res) = join_set.join_next().await {
            if let Ok((port, dev_type, connected, elapsed_ms)) = res {
                if connected {
                    let priority = ports_and_types
                        .iter()
                        .position(|(p, _)| *p == port)
                        .unwrap_or(usize::MAX);
                    open_hits.push((priority, dev_type, elapsed_ms));
                }
            }
        }

        open_hits.sort_by_key(|(priority, _, _)| *priority);

        if let Some((_, dev_type, elapsed_ms)) = open_hits.first() {
            let latency = if *elapsed_ms == 0 {
                1
            } else {
                *elapsed_ms as i32
            };
            (Some(*dev_type), Some(latency))
        } else {
            (None, None)
        }
    }

    pub fn lookup_vendor(mac: &str) -> String {
        crate::modules::monitor::oui_db::lookup_vendor(mac)
    }

    /// True only when `ip` is the OS-reported default gateway. A bare
    /// `.1` / `.254` suffix is not sufficient — many LANs use .254/.250 or
    /// non-/24 layouts, and mislabeling a printer/NAS as "Router" poisons
    /// the ARP-spoof baseline.
    pub fn is_gateway_ip(ip: &str) -> bool {
        crate::modules::system::win32_net::detect_default_gateway_ip()
            .is_some_and(|gw| gw.trim() == ip.trim())
    }

    pub fn classify_final(
        ip: &str,
        vendor: &str,
        service_type: Option<&'static str>,
        hostname: Option<&str>,
    ) -> (&'static str, &'static str) {
        if Self::is_gateway_ip(ip) || vendor.contains("Router") || vendor.contains("Modem") {
            return (
                i18n::tr(
                    "📡 Router Wi-Fi / Gateway",
                    "📡 Wi-Fi Router / Gateway",
                    "📡 Wi-Fi 路由器 / 网关",
                ),
                "ROUTER",
            );
        }

        if let Some(st) = service_type {
            if st.contains("Camera") {
                return (
                    i18n::tr(
                        "📷 Camera an ninh (CCTV / IP Cam)",
                        "📷 Security Camera (CCTV / IP Cam)",
                        "📷 安防摄像头 (CCTV / IP Cam)",
                    ),
                    "CAMERA",
                );
            } else if st.contains("Printer") {
                return (
                    i18n::tr(
                        "🖨️ Máy in mạng (Printer)",
                        "🖨️ Network Printer",
                        "🖨️ 网络打印机",
                    ),
                    "PRINTER",
                );
            } else if st.contains("Smart TV") {
                return (
                    i18n::tr(
                        "📺 Smart TV / Thiết bị truyền hình",
                        "📺 Smart TV / TV Device",
                        "📺 智能电视 / 电视设备",
                    ),
                    "TV",
                );
            } else if st.contains("iPhone") || st.contains("Android") {
                return (
                    i18n::tr("📱 Điện thoại thông minh", "📱 Smartphone", "📱 智能手机"),
                    "PHONE",
                );
            } else if st.contains("PC") || st.contains("Server") {
                return (
                    i18n::tr(
                        "💻 Máy tính (PC / Laptop)",
                        "💻 Computer (PC / Laptop)",
                        "💻 电脑 (PC / 笔记本)",
                    ),
                    "PC",
                );
            }
        }

        if let Some(host) = hostname {
            let lower = host.to_lowercase();
            if lower.contains("cam")
                || lower.contains("cctv")
                || lower.contains("dvr")
                || lower.contains("nvr")
            {
                return (
                    i18n::tr("📷 Camera an ninh", "📷 Security Camera", "📷 安防摄像头"),
                    "CAMERA",
                );
            } else if lower.contains("phone")
                || lower.contains("iphone")
                || lower.contains("galaxy")
                || lower.contains("redmi")
                || lower.contains("xiaomi")
            {
                return (
                    i18n::tr("📱 Điện thoại thông minh", "📱 Smartphone", "📱 智能手机"),
                    "PHONE",
                );
            } else if lower.contains("desktop")
                || lower.contains("laptop")
                || lower.contains("pc")
                || lower.contains("macbook")
            {
                return (
                    i18n::tr(
                        "💻 Máy tính (PC / Laptop)",
                        "💻 Computer (PC / Laptop)",
                        "💻 电脑 (PC / 笔记本)",
                    ),
                    "PC",
                );
            } else if lower.contains("tv") || lower.contains("box") || lower.contains("chromecast")
            {
                return (i18n::tr("📺 Smart TV", "📺 Smart TV", "📺 智能电视"), "TV");
            } else if lower.contains("print") {
                return (
                    i18n::tr("🖨️ Máy in mạng", "🖨️ Network Printer", "🖨️ 网络打印机"),
                    "PRINTER",
                );
            }
        }

        if vendor.contains("Camera")
            || vendor.contains("Hikvision")
            || vendor.contains("Dahua")
            || vendor.contains("Ezviz")
            || vendor.contains("Imou")
        {
            (
                i18n::tr("📷 Camera an ninh", "📷 Security Camera", "📷 安防摄像头"),
                "CAMERA",
            )
        } else if vendor.contains("iPhone")
            || vendor.contains("Galaxy")
            || vendor.contains("OPPO")
            || vendor.contains("Vivo")
            || vendor.contains("Realme")
            || vendor.contains("Điện thoại")
        {
            (
                i18n::tr("📱 Điện thoại thông minh", "📱 Smartphone", "📱 智能手机"),
                "PHONE",
            )
        } else if vendor.contains("Dell")
            || vendor.contains("HP")
            || vendor.contains("ASUS")
            || vendor.contains("Acer")
            || vendor.contains("Lenovo")
            || vendor.contains("Intel")
        {
            (
                i18n::tr(
                    "💻 Máy tính (PC / Laptop)",
                    "💻 Computer (PC / Laptop)",
                    "💻 电脑 (PC / 笔记本)",
                ),
                "PC",
            )
        } else if vendor.contains("TV")
            || vendor.contains("Google")
            || vendor.contains("Sony")
            || vendor.contains("LG")
        {
            (
                i18n::tr(
                    "📺 Smart TV / Thiết bị thông minh",
                    "📺 Smart TV / Smart Device",
                    "📺 智能电视 / 智能设备",
                ),
                "TV",
            )
        } else if vendor.contains("Espressif") || vendor.contains("Tuya") {
            (
                i18n::tr(
                    "💡 Thiết bị thông minh (Smart Home)",
                    "💡 Smart Device (Smart Home)",
                    "💡 智能设备 (智能家居)",
                ),
                "IOT",
            )
        } else {
            (
                i18n::tr("🌐 Thiết bị mạng LAN", "🌐 LAN Device", "🌐 局域网设备"),
                "DEVICE",
            )
        }
    }

    pub fn estimate_os(
        vendor: &str,
        open_ports: &[OpenPort],
        service_type: Option<&str>,
        host: Option<&str>,
    ) -> String {
        let v = vendor.to_lowercase();
        let port_nums: Vec<u16> = open_ports.iter().map(|p| p.port).collect();

        if port_nums.contains(&445) || port_nums.contains(&3389) || port_nums.contains(&139) {
            return "Windows 11 / 10".to_string();
        }
        if port_nums.contains(&62078)
            || (v.contains("apple") && (v.contains("iphone") || v.contains("ipad")))
        {
            return "Apple iOS / iPadOS".to_string();
        }
        if v.contains("apple") && (v.contains("mac") || v.contains("macbook")) {
            return "Apple macOS".to_string();
        }
        if port_nums.contains(&5555)
            || v.contains("android")
            || v.contains("samsung")
            || v.contains("xiaomi")
            || v.contains("oppo")
            || v.contains("vivo")
            || v.contains("realme")
        {
            return "Android OS".to_string();
        }
        if v.contains("router")
            || v.contains("modem")
            || v.contains("tp-link")
            || v.contains("tenda")
            || v.contains("draytek")
            || v.contains("cisco")
            || v.contains("vnpt")
            || v.contains("viettel")
        {
            return "RouterOS / Embedded Linux".to_string();
        }
        if v.contains("camera")
            || v.contains("hikvision")
            || v.contains("dahua")
            || v.contains("ezviz")
            || v.contains("imou")
            || v.contains("axis")
            || port_nums.contains(&554)
            || port_nums.contains(&8899)
        {
            return "Embedded Linux (IP Camera)".to_string();
        }
        if v.contains("tv")
            || v.contains("lg")
            || v.contains("sony")
            || port_nums.contains(&8008)
            || port_nums.contains(&8009)
        {
            return "Smart TV OS (webOS / Tizen / Android TV)".to_string();
        }
        if port_nums.contains(&22) {
            return "Linux / Unix Server".to_string();
        }
        if let Some(h) = host {
            let lh = h.to_lowercase();
            if lh.contains("desktop")
                || lh.contains("laptop")
                || lh.contains("pc")
                || lh.contains("win")
            {
                return "Windows PC".to_string();
            }
            if lh.contains("iphone") || lh.contains("ipad") {
                return "Apple iOS".to_string();
            }
            if lh.contains("macbook") || lh.contains("imac") {
                return "macOS".to_string();
            }
        }
        if let Some(st) = service_type {
            if st.contains("Windows") {
                return "Windows PC".to_string();
            }
            if st.contains("iOS") || st.contains("iPhone") {
                return "Apple iOS".to_string();
            }
            if st.contains("Android") {
                return "Android OS".to_string();
            }
            if st.contains("Camera") {
                return "Embedded Linux".to_string();
            }
        }
        "Network Device OS".to_string()
    }

    pub async fn scan_network(
        &self,
        sec_engine: Option<Arc<crate::modules::security::SecurityEngine>>,
    ) -> Vec<LanDevice> {
        // Mutual exclusion: skip overlapping scans (manual + periodic).
        {
            let mut scanning = self.is_scanning.write().unwrap_or_else(|e| e.into_inner());
            if *scanning {
                info!("LAN scan already in progress; skipping concurrent request");
                return self.devices.read().map(|d| d.clone()).unwrap_or_default();
            }
            *scanning = true;
        }
        // Ensure the flag is cleared even if a later path returns early.
        struct ScanGuard<'a>(&'a std::sync::RwLock<bool>);
        impl Drop for ScanGuard<'_> {
            fn drop(&mut self) {
                if let Ok(mut g) = self.0.write() {
                    *g = false;
                }
            }
        }
        let _scan_guard = ScanGuard(&self.is_scanning);

        let scan_start = Instant::now();
        let mut discovered_map: HashMap<String, String> = HashMap::new();

        let local_ip_opt = Self::get_local_outbound_ip();
        let my_hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "This PC".to_string());

        let adapters = tokio::task::spawn_blocking(read_adapter_ipv4)
            .await
            .unwrap_or_default();
        if let Some(local_ip) = local_ip_opt {
            let targets = adapters
                .iter()
                .find(|a| a.address == local_ip)
                .map(|a| bounded_subnet_hosts(local_ip, a.prefix, 254))
                .unwrap_or_default();
            // Spawn all 253 probes immediately; each task acquires the
            // semaphore *inside* so the loop never blocks serially. Use
            // tokio::spawn (not spawn_blocking per IP) — SendARP is a short
            // FFI call, and the blocking pool would be exhausted by 253
            // simultaneous blocking tasks.
            let arp_semaphore = Arc::new(tokio::sync::Semaphore::new(64));
            let mut join_set = tokio::task::JoinSet::new();

            for target_ip in targets {
                if target_ip == local_ip {
                    continue;
                }
                let sem = arp_semaphore.clone();
                join_set.spawn(async move {
                    let Ok(_permit) = sem.acquire_owned().await else {
                        return (target_ip.to_string(), None);
                    };
                    // Offload the blocking SendARP call without occupying a
                    // blocking-pool thread while waiting for the permit.
                    let mac_res = tokio::task::spawn_blocking(move || {
                        crate::modules::system::win32_net::send_arp_probe(target_ip)
                    })
                    .await
                    .ok()
                    .flatten();
                    (target_ip.to_string(), mac_res)
                });
            }

            while let Some(res) = join_set.join_next().await {
                if let Ok((ip_str, Some(mac_str))) = res {
                    discovered_map.insert(ip_str, mac_str);
                }
            }
        }

        if let Ok(Ok(output)) = tokio::task::spawn_blocking(|| {
            crate::modules::system::silent_command("arp")
                .arg("-a")
                .output()
        })
        .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let (entries, skipped) = parse_arp_table(&stdout, MAX_ARP_TABLE_ENTRIES);
            for (ip, mac) in entries {
                discovered_map.entry(ip).or_insert(mac);
            }
            if skipped > 0 {
                info!(
                    "ARP table: accepted entries, skipped {} malformed/non-unicast lines",
                    skipped
                );
            }
        }

        if let Some(sec) = &sec_engine {
            let observations: Vec<_> = discovered_map
                .iter()
                .map(|(ip, mac)| (ip.clone(), mac.clone()))
                .collect();
            let self_ips: Vec<_> = adapters.iter().map(|a| a.address.to_string()).collect();
            let gateways: Vec<_> = adapters
                .iter()
                .filter_map(|a| a.gateway.map(|g| g.to_string()))
                .collect();
            sec.update_quarantine_inventory(&observations, &self_ips, &gateways);
        }

        let local_ip_str = local_ip_opt
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "127.0.0.1".into());

        let mut devices = Vec::new();

        devices.push(LanDevice {
            name: format!(
                "💻 {} ({})",
                my_hostname,
                i18n::tr("Máy tính này / This PC", "This PC", "本机")
            ),
            ip: local_ip_str.clone(),
            mac: i18n::tr("Cục bộ (Local Host)", "Local Host", "本地主机").into(),
            vendor: i18n::tr("Hệ thống máy này", "This System", "本机系统").into(),
            device_type: i18n::tr(
                "💻 Máy tính (PC / Laptop)",
                "💻 Computer (PC / Laptop)",
                "💻 电脑 (PC / 笔记本)",
            )
            .into(),
            is_online: true,
            latency_ms: 0,
            traffic: i18n::tr("Hoạt động", "Active", "活跃").into(),
            total_queries: 0,
            blocked_queries: 0,
            threats_detected: 0,
            last_domain: "-".into(),
            last_active: "-".into(),
            risk_level: i18n::tr("🟢 An toàn", "🟢 Safe", "🟢 安全").into(),
            open_ports: Vec::new(),
            port_risk: String::new(),
            port_advice: String::new(),
            confidence: 100,
            custom_alias: String::new(),
            os_name: "Windows 11 (Host OS)".into(),
            is_quarantined: false,
            bandwidth_rate: "0 KB/s".into(),
        });

        let hints = super::discovery::collect_hints().await;

        // Bound enrichment (probe + port scan per device) so a /24 full of
        // hosts cannot spawn hundreds of simultaneous heavy tasks.
        let enrich_sem = Arc::new(tokio::sync::Semaphore::new(24));
        let mut enrich_handles = Vec::new();
        for (ip, mac) in discovered_map {
            if ip == local_ip_str || ip == "127.0.0.1" {
                continue;
            }

            let hint = hints.get(&ip).cloned();
            let sem = enrich_sem.clone();

            enrich_handles.push(tokio::spawn(async move {
                let Ok(_permit) = sem.acquire_owned().await else {
                    return None;
                };
                let vendor = Self::lookup_vendor(&mac);
                let vendor_unknown = i18n::tr("Không xác định", "Unknown", "未知");
                let vendor_private_mac = i18n::tr("MAC riêng tư", "Private MAC", "随机 MAC");
                let vendor_lan_host =
                    i18n::tr("Thiết bị mạng (LAN Host)", "LAN Host", "局域网主机");
                let vendor_known = !vendor.contains(vendor_lan_host)
                    && !vendor.contains(vendor_unknown)
                    && !vendor.contains(vendor_private_mac);
                let (service_type, measured_latency) = Self::probe_device_services(&ip).await;
                let netbios_name = Self::query_netbios_name(&ip).await;

                let has_mdns = hint.as_ref().map(|h| h.source == "mDNS").unwrap_or(false);
                let has_ssdp = hint.as_ref().map(|h| h.source == "SSDP").unwrap_or(false);
                let confidence = Self::confidence_score(
                    vendor_known,
                    service_type.is_some(),
                    netbios_name.is_some(),
                    has_mdns,
                    has_ssdp,
                );

                let classify_hint = hint.as_ref().and_then(|h| h.keyword).or(service_type);

                let (device_label, _) =
                    Self::classify_final(&ip, &vendor, classify_hint, netbios_name.as_deref());

                let name = if Self::is_gateway_ip(&ip) {
                    format!("📡 Router Wi-Fi / Gateway ({})", vendor)
                } else if let Some(ref host) = netbios_name {
                    format!("{} - {}", host, device_label)
                } else {
                    format!("{} ({})", device_label, ip)
                };

                let ip_addr: IpAddr = ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
                let open_ports = port_scanner::scan_open_ports(ip_addr).await;
                let port_risk = port_scanner::highest_risk(&open_ports)
                    .map(|r| r.as_str().to_string())
                    .unwrap_or_default();
                let port_advice = port_scanner::worst_port_advice(&open_ports);
                let os_name =
                    Self::estimate_os(&vendor, &open_ports, service_type, netbios_name.as_deref());

                Some(LanDevice {
                    name,
                    ip,
                    mac,
                    vendor,
                    device_type: device_label.into(),
                    is_online: true,
                    latency_ms: measured_latency.unwrap_or(-1),
                    traffic: i18n::tr("Hoạt động", "Active", "活跃").into(),
                    total_queries: 0,
                    blocked_queries: 0,
                    threats_detected: 0,
                    last_domain: "-".into(),
                    last_active: "-".into(),
                    risk_level: "🟢 An toàn".into(),
                    open_ports,
                    port_risk,
                    port_advice,
                    confidence,
                    custom_alias: String::new(),
                    os_name,
                    is_quarantined: false,
                    bandwidth_rate: "0 KB/s".into(),
                })
            }));
        }

        for handle in enrich_handles {
            if let Ok(Some(dev)) = handle.await {
                devices.push(dev);
            }
        }

        if let Some(sec) = sec_engine {
            // Only the OS-reported default gateway feeds the ARP-spoof
            // baseline; guessing .1/.254 misattributes legitimate hosts.
            let gateway_ip = crate::modules::system::win32_net::detect_default_gateway_ip();
            for dev in &devices {
                let is_gw = match &gateway_ip {
                    Some(gw) => &dev.ip == gw,
                    None => false,
                };
                if is_gw
                    || dev.name.contains(i18n::tr("Router", "Router", "路由器"))
                        && Self::is_gateway_ip(&dev.ip)
                {
                    sec.inspect_arp_gateway(&dev.ip, &dev.mac);
                    break;
                }
            }

            let mut notified = self
                .notified_high_risk
                .write()
                .unwrap_or_else(|e| e.into_inner());
            for dev in &devices {
                if dev.port_risk == PortRisk::High.as_str() && !notified.contains(&dev.ip) {
                    notified.insert(dev.ip.clone());
                    let summary = port_scanner::format_ports_summary(&dev.open_ports);
                    sec.record_incident(
                        i18n::tr(
                            "Cổng rủi ro cao đang mở trên thiết bị LAN",
                            "High-risk ports open on LAN device",
                            "局域网设备存在高危开放端口",
                        ),
                        &dev.ip,
                        &format!(
                            "{} — {}{}",
                            dev.name,
                            i18n::tr("phát hiện cổng: ", "open ports: ", "发现开放端口: "),
                            summary
                        ),
                        "HIGH",
                        &dev.port_advice,
                    );
                }
            }
        }

        // Total-order sort key: gateway first, then this PC, then by IP.
        // The previous comparator returned Less in both directions when two
        // devices both looked like `.1` (or both named "This PC"), which can
        // panic in debug builds and produce unstable order in release.
        devices.sort_by_key(|d| {
            let is_gateway = if Self::is_gateway_ip(&d.ip) { 0u8 } else { 1u8 };
            let is_this_pc = if d.name.contains("This PC") { 0u8 } else { 1u8 };
            (is_gateway, is_this_pc, d.ip.clone())
        });

        info!(
            "Comprehensive Active LAN Scanner identified {} devices with full subnet mapping in {} ms",
            devices.len(),
            scan_start.elapsed().as_millis()
        );

        if let Ok(mut dev_guard) = self.devices.write() {
            *dev_guard = devices.clone();
        }

        devices
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_bounds_never_escape_selected_subnet() {
        let local = Ipv4Addr::new(192, 0, 2, 130);
        let hosts = bounded_subnet_hosts(local, 25, 254);
        assert_eq!(hosts.len(), 125);
        assert!(hosts
            .iter()
            .all(|ip| ip.octets()[3] >= 129 && ip.octets()[3] <= 254));
        assert!(bounded_subnet_hosts(local, 32, 254).is_empty());
        assert_eq!(
            bounded_subnet_hosts(local, 31, 254),
            vec![Ipv4Addr::new(192, 0, 2, 131)]
        );
        assert!(bounded_subnet_hosts(local, 33, 254).is_empty());
        assert!(bounded_subnet_hosts(local, 16, 254).len() <= 254);
        assert!(bounded_subnet_hosts(local, 16, 0).is_empty());
    }

    #[test]
    fn test_arp_table_validation_and_cap() {
        let text = "Internet Address Physical Address Type\n192.0.2.4 02-aa-bb-cc-dd-ee dynamic\n224.0.0.1 01-00-5e-00-00-01 static\n192.0.2.5 invalid dynamic\n192.0.2.6 02-11-22-33-44-55 dynamic";
        let (entries, skipped) = parse_arp_table(text, 8);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], ("192.0.2.4".into(), "02:AA:BB:CC:DD:EE".into()));
        assert_eq!(skipped, 2);
        assert_eq!(parse_arp_table(text, 1).0.len(), 1);
        assert!(parse_arp_table(text, 0).0.is_empty());
    }

    #[test]
    fn test_lookup_vendor() {
        assert!(LanScanner::lookup_vendor("00:17:F2:11:22:33").contains("Apple"));
        assert!(LanScanner::lookup_vendor("00:07:AB:44:55:66").contains("Samsung"));
        assert!(LanScanner::lookup_vendor("00:18:82:77:88:99").contains("Hikvision"));
        assert!(LanScanner::lookup_vendor("00:0A:3A:AA:BB:CC").contains("TP-Link"));
        assert!(LanScanner::lookup_vendor("00:00:00:00:00:00").contains("Cục bộ"));
    }

    #[test]
    fn test_confidence_score() {
        assert_eq!(
            LanScanner::confidence_score(true, true, true, true, true),
            100
        );
        assert_eq!(
            LanScanner::confidence_score(false, false, false, false, false),
            0
        );
        assert_eq!(
            LanScanner::confidence_score(true, true, false, false, false),
            50
        );
        assert_eq!(
            LanScanner::confidence_score(true, true, true, true, false),
            80
        );
    }

    #[test]
    fn test_classify_final() {
        // Deterministic: "192.0.2.1" is TEST-NET (never a live LAN gateway,
        // not even on CI runners), so ROUTER must come from the vendor string,
        // not from is_gateway_ip()'s live default-gateway lookup.
        let (label, tag) = LanScanner::classify_final("192.0.2.1", "TP-Link Router", None, None);
        assert_eq!(tag, "ROUTER");
        assert!(label.contains("Router"));

        let (label_cam, tag_cam) =
            LanScanner::classify_final("192.168.1.50", "Hikvision", None, None);
        assert_eq!(tag_cam, "CAMERA");
        assert!(label_cam.contains("Camera"));

        let (label_phone, tag_phone) =
            LanScanner::classify_final("192.168.1.100", "Apple Inc.", None, Some("iPhone-15"));
        assert_eq!(tag_phone, "PHONE");
        assert!(label_phone.contains("Điện thoại"));
    }

    #[test]
    fn test_perf_classify_final() {
        crate::modules::perf::measure("lan_scanner::classify_final", 200_000, || {
            std::hint::black_box(LanScanner::classify_final(
                "192.0.2.77",
                "Espressif Inc.",
                None,
                None,
            ));
        });
    }
}
