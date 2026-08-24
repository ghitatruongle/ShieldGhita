use crate::modules::i18n;
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

pub struct AdviceTexts {
    pub vi: &'static str,
    pub en: &'static str,
    pub zh: &'static str,
}

const COMMON_PORTS: &[(u16, &str, PortRisk, AdviceTexts)] = &[
    (
        21,
        "FTP",
        PortRisk::High,
        AdviceTexts {
            vi: "Đóng FTP — giao thức truyền mật khẩu không mã hóa.",
            en: "Close FTP — protocol transmits passwords unencrypted.",
            zh: "关闭 FTP — 明文传输密码的协议。",
        },
    ),
    (
        23,
        "Telnet",
        PortRisk::High,
        AdviceTexts {
            vi: "Đóng Telnet ngay — không mã hóa, dễ bị nghe lén.",
            en: "Disable Telnet immediately — unencrypted, easy to eavesdrop.",
            zh: "立即关闭 Telnet — 无加密，易被窃听。",
        },
    ),
    (
        445,
        "SMB",
        PortRisk::High,
        AdviceTexts {
            vi: "Hạn chế chia sẻ file SMB chỉ cho mạng tin cậy.",
            en: "Restrict SMB file sharing to trusted networks only.",
            zh: "仅在可信网络中开放 SMB 文件共享。",
        },
    ),
    (
        3389,
        "RDP",
        PortRisk::High,
        AdviceTexts {
            vi: "Đóng Remote Desktop nếu không dùng, hoặc bật Network Level Authentication.",
            en: "Close Remote Desktop if unused, or enable Network Level Authentication.",
            zh: "不使用时请关闭远程桌面，或启用网络级身份验证 (NLA)。",
        },
    ),
    (
        554,
        "RTSP",
        PortRisk::High,
        AdviceTexts {
            vi: "Camera an ninh phát trực tiếp — đặt mật khẩu mạnh, isolate VLAN.",
            en: "Security camera streaming live — set a strong password, isolate VLAN.",
            zh: "安防摄像头正在直播 — 设置强密码并隔离 VLAN。",
        },
    ),
    (
        5900,
        "VNC",
        PortRisk::High,
        AdviceTexts {
            vi: "VNC không mã hóa — tắt hoặc chuyển sang tunnel SSH.",
            en: "Unencrypted VNC — turn off or switch to SSH tunnel.",
            zh: "VNC 无加密 — 关闭或改用 SSH 隧道。",
        },
    ),
    (
        5901,
        "VNC-alt",
        PortRisk::High,
        AdviceTexts {
            vi: "VNC phiên bản phụ — tắt nếu không dùng.",
            en: "Secondary VNC port — disable if unused.",
            zh: "辅助 VNC 端口 — 不使用请关闭。",
        },
    ),
    (
        5555,
        "ADB",
        PortRisk::High,
        AdviceTexts {
            vi: "Chế độ debug Android đang mở — tắt USB/Wi-Fi debugging.",
            en: "Android debugging mode open — disable USB/Wi-Fi debugging.",
            zh: "Android 调试模式已开启 — 关闭 USB/Wi-Fi 调试。",
        },
    ),
    (
        7547,
        "TR-069",
        PortRisk::High,
        AdviceTexts {
            vi: "Cổng quản lý ISP trên router — liên hệ nhà mạng đóng (lỗ hổng Mirai).",
            en: "ISP management port on router — ask carrier to close (Mirai flaw).",
            zh: "路由器上的 ISP 管理端口 — 请联系运营商关闭 (Mirai 漏洞)。",
        },
    ),
    (
        1433,
        "MSSQL",
        PortRisk::High,
        AdviceTexts {
            vi: "Database SQL Server lộ ra LAN — giới hạn firewall.",
            en: "SQL Server database exposed to LAN — restrict with firewall.",
            zh: "SQL Server 数据库暴露于局域网 — 用防火墙限制。",
        },
    ),
    (
        3306,
        "MySQL",
        PortRisk::High,
        AdviceTexts {
            vi: "Database MySQL lộ ra LAN — giới hạn firewall.",
            en: "MySQL database exposed to LAN — restrict with firewall.",
            zh: "MySQL 数据库暴露于局域网 — 用防火墙限制。",
        },
    ),
    (
        5432,
        "PostgreSQL",
        PortRisk::High,
        AdviceTexts {
            vi: "Database PostgreSQL lộ ra LAN — giới hạn firewall.",
            en: "PostgreSQL database exposed to LAN — restrict with firewall.",
            zh: "PostgreSQL 数据库暴露于局域网 — 用防火墙限制。",
        },
    ),
    (
        6379,
        "Redis",
        PortRisk::High,
        AdviceTexts {
            vi: "Redis thường không mật khẩu — đóng ngay.",
            en: "Redis usually has no password — close immediately.",
            zh: "Redis 通常无密码 — 立即关闭。",
        },
    ),
    (
        27017,
        "MongoDB",
        PortRisk::High,
        AdviceTexts {
            vi: "Database MongoDB lộ ra LAN — giới hạn firewall.",
            en: "MongoDB database exposed to LAN — restrict with firewall.",
            zh: "MongoDB 数据库暴露于局域网 — 用防火墙限制。",
        },
    ),
    (
        5985,
        "WinRM",
        PortRisk::High,
        AdviceTexts {
            vi: "Windows Remote Management HTTP — chỉ mở khi cần, ưu tiên HTTPS 5986.",
            en: "Windows Remote Management HTTP — only when needed, prefer HTTPS 5986.",
            zh: "Windows 远程管理 HTTP — 非必要不开放，优先 HTTPS 5986。",
        },
    ),
    (
        5986,
        "WinRM-TLS",
        PortRisk::High,
        AdviceTexts {
            vi: "WinRM qua TLS — đảm bảo chứng chỉ hợp lệ.",
            en: "WinRM over TLS — ensure valid certificate.",
            zh: "基于 TLS 的 WinRM — 确保证书有效。",
        },
    ),
    (
        1723,
        "PPTP",
        PortRisk::High,
        AdviceTexts {
            vi: "VPN PPTP lỗi thời — chuyển sang L2TP/WireGuard.",
            en: "Outdated PPTP VPN — switch to L2TP/WireGuard.",
            zh: "过时的 PPTP VPN — 改用 L2TP/WireGuard。",
        },
    ),
    (
        8000,
        "Hikvision",
        PortRisk::High,
        AdviceTexts {
            vi: "Web camera Hikvision — đổi mật khẩu mặc định, cập nhật firmware.",
            en: "Hikvision camera web — change default password, update firmware.",
            zh: "海康威视摄像头网页 — 更改默认密码并升级固件。",
        },
    ),
    (
        37777,
        "Dahua",
        PortRisk::High,
        AdviceTexts {
            vi: "Web camera Dahua/KBVision — đổi mật khẩu mặc định, cập nhật firmware.",
            en: "Dahua/KBVision camera web — change default password, update firmware.",
            zh: "大华/KBVision 摄像头网页 — 更改默认密码并升级固件。",
        },
    ),
    (
        22,
        "SSH",
        PortRisk::Medium,
        AdviceTexts {
            vi: "SSH mở — đảm bảo cấm đăng nhập root bằng mật khẩu.",
            en: "SSH open — ensure root password login is disabled.",
            zh: "SSH 已开放 — 确保禁止 root 密码登录。",
        },
    ),
    (
        80,
        "HTTP",
        PortRisk::Medium,
        AdviceTexts {
            vi: "Trang web quản trị thiết bị — kiểm tra cần thiết.",
            en: "Device admin web page — verify necessity.",
            zh: "设备管理网页 — 按需检查。",
        },
    ),
    (
        443,
        "HTTPS",
        PortRisk::Medium,
        AdviceTexts {
            vi: "Quản trị HTTPS của thiết bị — kiểm tra cần thiết.",
            en: "Device HTTPS administration — verify necessity.",
            zh: "设备 HTTPS 管理 — 按需检查。",
        },
    ),
    (
        8080,
        "HTTP-alt",
        PortRisk::Medium,
        AdviceTexts {
            vi: "Cổng web phụ — kiểm tra cần thiết.",
            en: "Auxiliary web port — verify necessity.",
            zh: "辅助网页端口 — 按需检查。",
        },
    ),
    (
        8081,
        "HTTP-alt2",
        PortRisk::Medium,
        AdviceTexts {
            vi: "Cổng web phụ — kiểm tra cần thiết.",
            en: "Auxiliary web port — verify necessity.",
            zh: "辅助网页端口 — 按需检查。",
        },
    ),
    (
        8443,
        "HTTPS-alt",
        PortRisk::Medium,
        AdviceTexts {
            vi: "Cổng web HTTPS phụ — kiểm tra cần thiết.",
            en: "Auxiliary HTTPS web port — verify necessity.",
            zh: "辅助 HTTPS 网页端口 — 按需检查。",
        },
    ),
    (
        8008,
        "Google-Cast",
        PortRisk::Medium,
        AdviceTexts {
            vi: "Smart TV / Chromecast lắng nghe — bình thường nếu chủ động dùng.",
            en: "Smart TV / Chromecast listening — normal if intentionally used.",
            zh: "智能电视 / Chromecast 监听中 — 主动使用则属正常。",
        },
    ),
    (
        8009,
        "Chromecast",
        PortRisk::Medium,
        AdviceTexts {
            vi: "Chromecast mở — bình thường nếu chủ động dùng.",
            en: "Chromecast open — normal if intentionally used.",
            zh: "Chromecast 开放 — 主动使用则属正常。",
        },
    ),
    (
        7000,
        "AirPlay",
        PortRisk::Medium,
        AdviceTexts {
            vi: "AirPlay mở — bình thường nếu chủ động dùng.",
            en: "AirPlay open — normal if intentionally used.",
            zh: "AirPlay 开放 — 主动使用则属正常。",
        },
    ),
    (
        8899,
        "ONVIF",
        PortRisk::Medium,
        AdviceTexts {
            vi: "Giao thức camera ONVIF — đặt mật khẩu mạnh.",
            en: "ONVIF camera protocol — set a strong password.",
            zh: "ONVIF 摄像头协议 — 设置强密码。",
        },
    ),
    (
        1883,
        "MQTT",
        PortRisk::Medium,
        AdviceTexts {
            vi: "IoT MQTT không mã hóa — cân nhắc bật TLS.",
            en: "Unencrypted IoT MQTT — consider enabling TLS.",
            zh: "未加密的 IoT MQTT — 考虑启用 TLS。",
        },
    ),
    (
        8883,
        "MQTT-TLS",
        PortRisk::Medium,
        AdviceTexts {
            vi: "MQTT có mã hóa — đảm bảo chứng chỉ hợp lệ.",
            en: "Encrypted MQTT — ensure valid certificate.",
            zh: "加密的 MQTT — 确保证书有效。",
        },
    ),
    (
        5060,
        "SIP",
        PortRisk::Medium,
        AdviceTexts {
            vi: "VoIP SIP — đảm bảo PBX có xác thực.",
            en: "VoIP SIP — ensure PBX has authentication.",
            zh: "VoIP SIP — 确保 PBX 已启用认证。",
        },
    ),
    (
        111,
        "RPC",
        PortRisk::Medium,
        AdviceTexts {
            vi: "portmap/rpcbind — thường không cần trên desktop.",
            en: "portmap/rpcbind — rarely needed on desktops.",
            zh: "portmap/rpcbind — 桌面电脑通常不需要。",
        },
    ),
    (
        5000,
        "UPnP",
        PortRisk::Medium,
        AdviceTexts {
            vi: "UPnP thiết bị — tắt trên router nếu không tin tưởng.",
            en: "Device UPnP — disable on router if not trusted.",
            zh: "设备 UPnP — 不信任时请在路由器上关闭。",
        },
    ),
    (
        631,
        "IPP",
        PortRisk::Low,
        AdviceTexts {
            vi: "Máy in mạng (AirPrint/IPP) — bình thường.",
            en: "Network printer (AirPrint/IPP) — normal.",
            zh: "网络打印机 (AirPrint/IPP) — 属正常。",
        },
    ),
    (
        9100,
        "JetDirect",
        PortRisk::Low,
        AdviceTexts {
            vi: "Cổng in thô — bình thường với máy in.",
            en: "Raw printing port — normal for printers.",
            zh: "原始打印端口 — 对打印机属正常。",
        },
    ),
    (
        139,
        "NetBIOS",
        PortRisk::Low,
        AdviceTexts {
            vi: "NetBIOS Windows truyền thống — bình thường.",
            en: "Legacy Windows NetBIOS — normal.",
            zh: "传统 Windows NetBIOS — 属正常。",
        },
    ),
    (
        62078,
        "iOS-Sync",
        PortRisk::Low,
        AdviceTexts {
            vi: "Cổng đồng bộ iPhone/iPad — bình thường.",
            en: "iPhone/iPad sync port — normal.",
            zh: "iPhone/iPad 同步端口 — 属正常。",
        },
    ),
    (
        5357,
        "WSD",
        PortRisk::Low,
        AdviceTexts {
            vi: "Web Services for Devices — bình thường trên Windows.",
            en: "Web Services for Devices — normal on Windows.",
            zh: "Windows 设备 Web 服务 (WSD) — 属正常。",
        },
    ),
];

pub fn port_entry(port: u16) -> Option<&'static (u16, &'static str, PortRisk, AdviceTexts)> {
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
        return i18n::tr(
            "Không có cổng rủi ro được phát hiện",
            "No risky open ports detected",
            "未发现存在风险的开放端口",
        )
        .to_string();
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
                    Some((_, l, r, a)) => {
                        ((*l).to_string(), *r, i18n::tr(a.vi, a.en, a.zh).to_string())
                    }
                    None => (
                        format!("svc-{}", port),
                        PortRisk::Medium,
                        i18n::tr(
                            "Cổng mở bất thường — kiểm tra dịch vụ đang lắng nghe.",
                            "Unusual open port — check the listening service.",
                            "异常开放端口 — 请检查监听中的服务。",
                        )
                        .to_string(),
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
