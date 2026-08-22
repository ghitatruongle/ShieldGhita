use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PortRisk {
    Low,
    Medium,
    High,
}

impl PortRisk {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortRisk::High => "HIGH",
            PortRisk::Medium => "MEDIUM",
            PortRisk::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPort {
    pub port: u16,
    pub label: String,
    pub risk: PortRisk,
    pub advice: String,
}

const COMMON_PORTS: &[(u16, &str, PortRisk, &str)] = &[
    (
        21,
        "FTP",
        PortRisk::High,
        "Đóng FTP — giao thức truyền mật khẩu không mã hóa.",
    ),
    (
        23,
        "Telnet",
        PortRisk::High,
        "Đóng Telnet ngay — không mã hóa, dễ bị nghe lén.",
    ),
    (
        445,
        "SMB",
        PortRisk::High,
        "Hạn chế chia sẻ file SMB chỉ cho mạng tin cậy.",
    ),
    (
        3389,
        "RDP",
        PortRisk::High,
        "Đóng Remote Desktop nếu không dùng, hoặc bật Network Level Authentication.",
    ),
    (
        554,
        "RTSP",
        PortRisk::High,
        "Camera an ninh phát trực tiếp — đặt mật khẩu mạnh, isolate VLAN.",
    ),
    (
        5900,
        "VNC",
        PortRisk::High,
        "VNC không mã hóa — tắt hoặc chuyển sang tunnel SSH.",
    ),
    (
        5901,
        "VNC-alt",
        PortRisk::High,
        "VNC phiên bản phụ — tắt nếu không dùng.",
    ),
    (
        5555,
        "ADB",
        PortRisk::High,
        "Chế độ debug Android đang mở — tắt USB/Wi-Fi debugging.",
    ),
    (
        7547,
        "TR-069",
        PortRisk::High,
        "Cổng quản lý ISP trên router — liên hệ nhà mạng đóng (lỗ hổng Mirai).",
    ),
    (
        1433,
        "MSSQL",
        PortRisk::High,
        "Database SQL Server lộ ra LAN — giới hạn firewall.",
    ),
    (
        3306,
        "MySQL",
        PortRisk::High,
        "Database MySQL lộ ra LAN — giới hạn firewall.",
    ),
    (
        5432,
        "PostgreSQL",
        PortRisk::High,
        "Database PostgreSQL lộ ra LAN — giới hạn firewall.",
    ),
    (
        6379,
        "Redis",
        PortRisk::High,
        "Redis thường không mật khẩu — đóng ngay.",
    ),
    (
        27017,
        "MongoDB",
        PortRisk::High,
        "Database MongoDB lộ ra LAN — giới hạn firewall.",
    ),
    (
        5985,
        "WinRM",
        PortRisk::High,
        "Windows Remote Management HTTP — chỉ mở khi cần, ưu tiên HTTPS 5986.",
    ),
    (
        5986,
        "WinRM-TLS",
        PortRisk::High,
        "WinRM qua TLS — đảm bảo chứng chỉ hợp lệ.",
    ),
    (
        1723,
        "PPTP",
        PortRisk::High,
        "VPN PPTP lỗi thời — chuyển sang L2TP/WireGuard.",
    ),
    (
        8000,
        "Hikvision",
        PortRisk::High,
        "Web camera Hikvision — đổi mật khẩu mặc định, cập nhật firmware.",
    ),
    (
        37777,
        "Dahua",
        PortRisk::High,
        "Web camera Dahua/KBVision — đổi mật khẩu mặc định, cập nhật firmware.",
    ),
    (
        22,
        "SSH",
        PortRisk::Medium,
        "SSH mở — đảm bảo cấm đăng nhập root bằng mật khẩu.",
    ),
    (
        80,
        "HTTP",
        PortRisk::Medium,
        "Trang web quản trị thiết bị — kiểm tra cần thiết.",
    ),
    (
        443,
        "HTTPS",
        PortRisk::Medium,
        "Quản trị HTTPS của thiết bị — kiểm tra cần thiết.",
    ),
    (
        8080,
        "HTTP-alt",
        PortRisk::Medium,
        "Cổng web phụ — kiểm tra cần thiết.",
    ),
    (
        8081,
        "HTTP-alt2",
        PortRisk::Medium,
        "Cổng web phụ — kiểm tra cần thiết.",
    ),
    (
        8443,
        "HTTPS-alt",
        PortRisk::Medium,
        "Cổng web HTTPS phụ — kiểm tra cần thiết.",
    ),
    (
        8008,
        "Google-Cast",
        PortRisk::Medium,
        "Smart TV / Chromecast lắng nghe — bình thường nếu chủ động dùng.",
    ),
    (
        8009,
        "Chromecast",
        PortRisk::Medium,
        "Chromecast mở — bình thường nếu chủ động dùng.",
    ),
    (
        7000,
        "AirPlay",
        PortRisk::Medium,
        "AirPlay mở — bình thường nếu chủ động dùng.",
    ),
    (
        8899,
        "ONVIF",
        PortRisk::Medium,
        "Giao thức camera ONVIF — đặt mật khẩu mạnh.",
    ),
    (
        1883,
        "MQTT",
        PortRisk::Medium,
        "IoT MQTT không mã hóa — cân nhắc bật TLS.",
    ),
    (
        8883,
        "MQTT-TLS",
        PortRisk::Medium,
        "MQTT có mã hóa — đảm bảo chứng chỉ hợp lệ.",
    ),
    (
        5060,
        "SIP",
        PortRisk::Medium,
        "VoIP SIP — đảm bảo PBX có xác thực.",
    ),
    (
        111,
        "RPC",
        PortRisk::Medium,
        "portmap/rpcbind — thường không cần trên desktop.",
    ),
    (
        5000,
        "UPnP",
        PortRisk::Medium,
        "UPnP thiết bị — tắt trên router nếu không tin tưởng.",
    ),
    (
        631,
        "IPP",
        PortRisk::Low,
        "Máy in mạng (AirPrint/IPP) — bình thường.",
    ),
    (
        9100,
        "JetDirect",
        PortRisk::Low,
        "Cổng in thô — bình thường với máy in.",
    ),
    (
        139,
        "NetBIOS",
        PortRisk::Low,
        "NetBIOS Windows truyền thống — bình thường.",
    ),
    (
        62078,
        "iOS-Sync",
        PortRisk::Low,
        "Cổng đồng bộ iPhone/iPad — bình thường.",
    ),
    (
        5357,
        "WSD",
        PortRisk::Low,
        "Web Services for Devices — bình thường trên Windows.",
    ),
];

pub fn port_entry(port: u16) -> Option<&'static (u16, &'static str, PortRisk, &'static str)> {
    COMMON_PORTS.iter().find(|(p, _, _, _)| *p == port)
}

pub fn common_port_numbers() -> Vec<u16> {
    COMMON_PORTS.iter().map(|(p, _, _, _)| *p).collect()
}

pub fn highest_risk(ports: &[OpenPort]) -> Option<PortRisk> {
    ports.iter().map(|p| p.risk).max()
}

pub fn worst_port_advice(ports: &[OpenPort]) -> String {
    match ports.iter().max_by_key(|p| p.risk) {
        Some(p) => format!("{}: {}", p.label, p.advice),
        None => String::new(),
    }
}

pub fn format_ports_summary(ports: &[OpenPort]) -> String {
    if ports.is_empty() {
        return "Không có cổng rủi ro được phát hiện".to_string();
    }
    ports
        .iter()
        .map(|p| format!("{}/{}", p.port, p.label))
        .collect::<Vec<_>>()
        .join(", ")
}

pub async fn scan_open_ports(ip: IpAddr) -> Vec<OpenPort> {
    scan_ports_by_numbers(ip, &common_port_numbers()).await
}

pub async fn scan_ports_by_numbers(ip: IpAddr, ports: &[u16]) -> Vec<OpenPort> {
    let semaphore = Arc::new(Semaphore::new(32));
    let mut join_set = tokio::task::JoinSet::new();

    for &port in ports {
        let addr = SocketAddr::new(ip, port);
        let sem = semaphore.clone();
        join_set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let open = tokio::time::timeout(Duration::from_millis(60), TcpStream::connect(addr))
                .await
                .is_ok_and(|r| r.is_ok());
            if open {
                let (label, risk, advice) = match port_entry(port) {
                    Some((_, l, r, a)) => ((*l).to_string(), *r, (*a).to_string()),
                    None => (
                        format!("svc-{}", port),
                        PortRisk::Medium,
                        "Cổng mở bất thường — kiểm tra dịch vụ đang lắng nghe.".to_string(),
                    ),
                };
                Some(OpenPort {
                    port,
                    label,
                    risk,
                    advice,
                })
            } else {
                None
            }
        });
    }

    let mut open_ports = Vec::new();
    while let Some(res) = join_set.join_next().await {
        if let Ok(Some(p)) = res {
            open_ports.push(p);
        }
    }
    open_ports.sort_by_key(|p| p.port);
    open_ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_ports_table_sanity() {
        assert!(COMMON_PORTS.len() >= 38);
        let mut seen = std::collections::HashSet::new();
        for (port, label, _, _) in COMMON_PORTS {
            assert!(*port > 0, "port must be positive");
            assert!(!label.is_empty(), "label must not be empty");
            assert!(seen.insert(*port), "duplicate port {} in table", port);
        }
    }

    #[test]
    fn test_port_entry_lookup() {
        let rdp = port_entry(3389).expect("RDP entry");
        assert_eq!(rdp.1, "RDP");
        assert_eq!(rdp.2, PortRisk::High);
        let ipp = port_entry(631).expect("IPP entry");
        assert_eq!(ipp.2, PortRisk::Low);
        assert!(port_entry(65001).is_none());
    }

    #[test]
    fn test_highest_risk_and_advice() {
        let ports = vec![
            OpenPort {
                port: 22,
                label: "SSH".to_string(),
                risk: PortRisk::Medium,
                advice: "SSH advice".to_string(),
            },
            OpenPort {
                port: 23,
                label: "Telnet".to_string(),
                risk: PortRisk::High,
                advice: "Telnet advice".to_string(),
            },
        ];
        assert_eq!(highest_risk(&ports), Some(PortRisk::High));
        assert!(worst_port_advice(&ports).contains("Telnet"));
        assert_eq!(highest_risk(&[]), None);
    }

    #[test]
    fn test_format_ports_summary() {
        let ports = vec![OpenPort {
            port: 3389,
            label: "RDP".to_string(),
            risk: PortRisk::High,
            advice: "close".to_string(),
        }];
        assert_eq!(format_ports_summary(&ports), "3389/RDP");
        assert!(format_ports_summary(&[]).contains("Không có cổng"));
    }
}
