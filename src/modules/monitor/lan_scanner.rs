use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Duration;
use tracing::info;

use super::port_scanner::{self, OpenPort, PortRisk};

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
                        "🚨 Nguy hiểm (Phát hiện mối đe dọa)".to_string()
                    } else if *blocked > 10 {
                        "🛡️ An toàn (Đã lọc quảng cáo)".to_string()
                    } else {
                        "🟢 An toàn".to_string()
                    };
                } else if d.ip == "127.0.0.1" || d.mac.contains("Local") {
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
            (554, "📷 Camera an ninh (RTSP/CCTV)"),
            (8000, "📷 Camera Hikvision / DVR"),
            (37777, "📷 Camera Dahua / KBVision"),
            (8899, "📷 Camera ONVIF IP"),
            (9100, "🖨️ Máy in mạng (RAW/JetDirect)"),
            (631, "🖨️ Máy in mạng (IPP)"),
            (8008, "📺 Smart TV / Google Cast"),
            (8009, "📺 Smart TV / Chromecast"),
            (7000, "📺 Smart TV / AirPlay"),
            (445, "💻 Máy tính (Windows PC)"),
            (139, "💻 Máy tính (NetBIOS)"),
            (3389, "💻 Máy tính (Remote Desktop)"),
            (22, "🖥️ Máy tính / Server (Linux/Mac)"),
            (62078, "📱 iPhone / iPad (Apple iOS)"),
            (5555, "📱 Điện thoại Android (ADB)"),
            (80, "🌐 Thiết bị mạng / Web"),
            (443, "🌐 Thiết bị mạng (HTTPS)"),
            (8080, "🌐 Thiết bị thông minh (Web Port)"),
        ];

        let start = Instant::now();
        let mut join_set = tokio::task::JoinSet::new();

        for (port, dev_type) in ports_and_types {
            let addr = format!("{}:{}", ip, port);
            join_set.spawn(async move {
                let connected =
                    tokio::time::timeout(Duration::from_millis(80), TcpStream::connect(&addr))
                        .await
                        .is_ok_and(|r| r.is_ok());
                (port, dev_type, connected)
            });
        }

        let mut open_hits: Vec<(usize, &'static str, u128)> = Vec::new();
        while let Some(res) = join_set.join_next().await {
            if let Ok((port, dev_type, connected)) = res {
                if connected {
                    let priority = ports_and_types
                        .iter()
                        .position(|(p, _)| *p == port)
                        .unwrap_or(usize::MAX);
                    open_hits.push((priority, dev_type, start.elapsed().as_millis()));
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

    pub fn classify_final(
        ip: &str,
        vendor: &str,
        service_type: Option<&'static str>,
        hostname: Option<&str>,
    ) -> (&'static str, &'static str) {
        if ip.ends_with(".1")
            || ip.ends_with(".254")
            || vendor.contains("Router")
            || vendor.contains("Modem")
        {
            return ("📡 Router Wi-Fi / Gateway", "ROUTER");
        }

        if let Some(st) = service_type {
            if st.contains("Camera") {
                return ("📷 Camera an ninh (CCTV / IP Cam)", "CAMERA");
            } else if st.contains("Máy in") {
                return ("🖨️ Máy in mạng (Printer)", "PRINTER");
            } else if st.contains("Smart TV") {
                return ("📺 Smart TV / Thiết bị truyền hình", "TV");
            } else if st.contains("iPhone") || st.contains("Android") {
                return ("📱 Điện thoại thông minh", "PHONE");
            } else if st.contains("Máy tính") {
                return ("💻 Máy tính (PC / Laptop)", "PC");
            }
        }

        if let Some(host) = hostname {
            let lower = host.to_lowercase();
            if lower.contains("cam")
                || lower.contains("cctv")
                || lower.contains("dvr")
                || lower.contains("nvr")
            {
                return ("📷 Camera an ninh", "CAMERA");
            } else if lower.contains("phone")
                || lower.contains("iphone")
                || lower.contains("galaxy")
                || lower.contains("redmi")
                || lower.contains("xiaomi")
            {
                return ("📱 Điện thoại thông minh", "PHONE");
            } else if lower.contains("desktop")
                || lower.contains("laptop")
                || lower.contains("pc")
                || lower.contains("macbook")
            {
                return ("💻 Máy tính (PC / Laptop)", "PC");
            } else if lower.contains("tv") || lower.contains("box") || lower.contains("chromecast")
            {
                return ("📺 Smart TV", "TV");
            } else if lower.contains("print") {
                return ("🖨️ Máy in mạng", "PRINTER");
            }
        }

        if vendor.contains("Camera")
            || vendor.contains("Hikvision")
            || vendor.contains("Dahua")
            || vendor.contains("Ezviz")
            || vendor.contains("Imou")
        {
            ("📷 Camera an ninh", "CAMERA")
        } else if vendor.contains("iPhone")
            || vendor.contains("Galaxy")
            || vendor.contains("OPPO")
            || vendor.contains("Vivo")
            || vendor.contains("Realme")
            || vendor.contains("Điện thoại")
        {
            ("📱 Điện thoại thông minh", "PHONE")
        } else if vendor.contains("Dell")
            || vendor.contains("HP")
            || vendor.contains("ASUS")
            || vendor.contains("Acer")
            || vendor.contains("Lenovo")
            || vendor.contains("Intel")
        {
            ("💻 Máy tính (PC / Laptop)", "PC")
        } else if vendor.contains("TV")
            || vendor.contains("Google")
            || vendor.contains("Sony")
            || vendor.contains("LG")
        {
            ("📺 Smart TV / Thiết bị thông minh", "TV")
        } else if vendor.contains("Espressif") || vendor.contains("Tuya") {
            ("💡 Thiết bị thông minh (Smart Home)", "IOT")
        } else {
            ("🌐 Thiết bị mạng LAN", "DEVICE")
        }
    }

    pub async fn scan_network(
        &self,
        sec_engine: Option<Arc<crate::modules::security::SecurityEngine>>,
    ) -> Vec<LanDevice> {
        if let Ok(mut guard) = self.is_scanning.write() {
            *guard = true;
        }
        let scan_start = Instant::now();
        let mut discovered_map: HashMap<String, String> = HashMap::new();

        let local_ip_opt = Self::get_local_outbound_ip();
        let my_hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "This PC".to_string());

        if let Some(local_ip) = local_ip_opt {
            let octets = local_ip.octets();
            let mut join_handles = Vec::with_capacity(254);
            let arp_semaphore = Arc::new(tokio::sync::Semaphore::new(64));

            for i in 1..=254u8 {
                let target_ip = Ipv4Addr::new(octets[0], octets[1], octets[2], i);
                if target_ip == local_ip {
                    continue;
                }
                let permit = arp_semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("ARP semaphore closed");
                let handle = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let mac_res = crate::modules::system::win32_net::send_arp_probe(target_ip);
                    (target_ip.to_string(), mac_res)
                });
                join_handles.push(handle);
            }

            for handle in join_handles {
                if let Ok((ip_str, Some(mac_str))) = handle.await {
                    discovered_map.insert(ip_str, mac_str);
                }
            }
        }

        if let Ok(output) = crate::modules::system::silent_command("arp")
            .arg("-a")
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let ip = parts[0].to_string();
                    let mac_raw = parts[1];

                    if ip.parse::<IpAddr>().is_err() {
                        continue;
                    }

                    let mac = mac_raw.replace('-', ":").to_uppercase();
                    if mac == "FF:FF:FF:FF:FF:FF"
                        || mac == "00:00:00:00:00:00"
                        || ip.ends_with(".255")
                        || ip.starts_with("224.")
                        || ip.starts_with("239.")
                    {
                        continue;
                    }

                    discovered_map.entry(ip).or_insert(mac);
                }
            }
        }

        let local_ip_str = local_ip_opt
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "127.0.0.1".into());

        let mut devices = Vec::new();

        devices.push(LanDevice {
            name: format!("💻 {} (Máy tính này / This PC)", my_hostname),
            ip: local_ip_str.clone(),
            mac: "Cục bộ (Local Host)".into(),
            vendor: "Hệ thống máy này".into(),
            device_type: "💻 Máy tính (PC / Laptop)".into(),
            is_online: true,
            latency_ms: 0,
            traffic: "Hoạt động".into(),
            total_queries: 0,
            blocked_queries: 0,
            threats_detected: 0,
            last_domain: "-".into(),
            last_active: "-".into(),
            risk_level: "🟢 An toàn".into(),
            open_ports: Vec::new(),
            port_risk: String::new(),
            port_advice: String::new(),
            confidence: 100,
        });

        let hints = super::discovery::collect_hints().await;

        let mut enrich_handles = Vec::new();
        for (ip, mac) in discovered_map {
            if ip == local_ip_str || ip == "127.0.0.1" {
                continue;
            }

            let hint = hints.get(&ip).cloned();

            enrich_handles.push(tokio::spawn(async move {
                let vendor = Self::lookup_vendor(&mac);
                let vendor_known = !vendor.contains("Thiết bị mạng (LAN Host)")
                    && !vendor.contains("Không xác định")
                    && !vendor.contains("MAC riêng tư");
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

                let name = if ip.ends_with(".1") || ip.ends_with(".254") {
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

                LanDevice {
                    name,
                    ip,
                    mac,
                    vendor,
                    device_type: device_label.into(),
                    is_online: true,
                    latency_ms: measured_latency.unwrap_or(-1),
                    traffic: "Hoạt động".into(),
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
                }
            }));
        }

        for handle in enrich_handles {
            if let Ok(dev) = handle.await {
                devices.push(dev);
            }
        }

        if let Some(sec) = sec_engine {
            for dev in &devices {
                if dev.ip.ends_with(".1") || dev.ip.ends_with(".254") || dev.name.contains("Router")
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
                        "Cổng rủi ro cao đang mở trên thiết bị LAN",
                        &dev.ip,
                        &format!("{} — phát hiện cổng: {}", dev.name, summary),
                        "HIGH",
                        &dev.port_advice,
                    );
                }
            }
        }

        devices.sort_by(|a, b| {
            if a.ip.ends_with(".1") {
                std::cmp::Ordering::Less
            } else if b.ip.ends_with(".1") {
                std::cmp::Ordering::Greater
            } else if a.name.contains("This PC") {
                std::cmp::Ordering::Less
            } else if b.name.contains("This PC") {
                std::cmp::Ordering::Greater
            } else {
                a.ip.cmp(&b.ip)
            }
        });

        info!(
            "Comprehensive Active LAN Scanner identified {} devices with full subnet mapping in {} ms",
            devices.len(),
            scan_start.elapsed().as_millis()
        );

        if let Ok(mut dev_guard) = self.devices.write() {
            *dev_guard = devices.clone();
        }

        if let Ok(mut guard) = self.is_scanning.write() {
            *guard = false;
        }

        devices
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (label, tag) = LanScanner::classify_final("192.168.1.1", "TP-Link", None, None);
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
}
