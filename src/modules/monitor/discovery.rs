use crate::modules::i18n;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryHint {
    pub ip: String,
    pub source: &'static str,
    pub keyword: Option<&'static str>,
}

fn ssdp_keyword(server: &str) -> Option<&'static str> {
    let lower = server.to_lowercase();
    if lower.contains("chromecast") || lower.contains("googlecast") {
        Some(i18n::tr(
            "📺 Smart TV / Chromecast",
            "📺 Smart TV / Chromecast",
            "📺 智能电视 (Smart TV / Chromecast)",
        ))
    } else if lower.contains("bravia") || lower.contains("webos") || lower.contains("smarttv") {
        Some(i18n::tr(
            "📺 Smart TV / Thiết bị truyền hình",
            "📺 Smart TV / TV Device",
            "📺 智能电视 (Smart TV / 电视设备)",
        ))
    } else if lower.contains("printer") || lower.contains("ipp") || lower.contains("jetdirect") {
        Some(i18n::tr(
            "🖨️ Máy in mạng (Printer - AirPrint / IPP)",
            "🖨️ Network Printer (AirPrint / IPP)",
            "🖨️ 网络打印机 (Printer - AirPrint / IPP)",
        ))
    } else if lower.contains("ip-camera") || lower.contains("onvif") || lower.contains("dvr") {
        Some(i18n::tr(
            "📷 Camera an ninh (IP Cam)",
            "📷 Security Camera (IP Cam)",
            "📷 安防摄像机 (IP Camera)",
        ))
    } else if lower.contains("nas") || lower.contains("synology") {
        Some(i18n::tr(
            "💾 Thiết bị lưu trữ (NAS)",
            "💾 Storage Device (NAS)",
            "💾 存储设备 (NAS)",
        ))
    } else {
        None
    }
}

pub async fn probe_ssdp_hints() -> Vec<DiscoveryHint> {
    let mut hints = Vec::new();
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return hints,
    };

    let msg = "M-SEARCH * HTTP/1.1\r\n\
               HOST: 239.255.255.250:1900\r\n\
               MAN: \"ssdp:discover\"\r\n\
               MX: 2\r\n\
               ST: ssdp:all\r\n\r\n";
    let target: SocketAddr = "239.255.255.250:1900".parse().unwrap();
    if socket.send_to(msg.as_bytes(), target).await.is_err() {
        return hints;
    }

    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut seen_ips = std::collections::HashSet::new();
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            break;
        }
        match tokio::time::timeout(remain, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                let response = String::from_utf8_lossy(&buf[..len]).to_lowercase();
                let ip_str = src.ip().to_string();
                if !seen_ips.insert(ip_str.clone()) {
                    continue;
                }
                let mut server = String::new();
                for line in response.lines() {
                    if let Some(rest) = line.strip_prefix("server:") {
                        server = rest.trim().to_string();
                        break;
                    }
                }
                let keyword = if server.is_empty() {
                    None
                } else {
                    ssdp_keyword(&server)
                };
                hints.push(DiscoveryHint {
                    ip: ip_str,
                    source: "SSDP",
                    keyword,
                });
            }
            _ => break,
        }
    }
    hints
}

fn mdns_keyword(service: &str) -> Option<&'static str> {
    let lower = service.to_lowercase();
    if lower.contains("googlecast") {
        Some(i18n::tr(
            "📺 Smart TV / Chromecast",
            "📺 Smart TV / Chromecast",
            "📺 智能电视 (Smart TV / Chromecast)",
        ))
    } else if lower.contains("airplay") || lower.contains("raop") {
        Some(i18n::tr(
            "📺 Smart TV / AirPlay",
            "📺 Smart TV / AirPlay",
            "📺 智能电视 (Smart TV / AirPlay)",
        ))
    } else if lower.contains("ipp") || lower.contains("printer") || lower.contains("scanner") {
        Some(i18n::tr(
            "🖨️ Máy in mạng (Printer - AirPrint / IPP)",
            "🖨️ Network Printer (AirPrint / IPP)",
            "🖨️ 网络打印机 (Printer - AirPrint / IPP)",
        ))
    } else if lower.contains("smb") {
        Some(i18n::tr(
            "💻 Máy tính (PC - File Sharing)",
            "💻 Computer (PC - File Sharing)",
            "💻 电脑 (PC - 文件共享)",
        ))
    } else if lower.contains("ssh") || lower.contains("sftp") {
        Some(i18n::tr(
            "🖥️ Máy chủ / Server (Linux/Mac)",
            "🖥️ Computer / Server (Linux/Mac)",
            "🖥️ 电脑 / 服务器 (Server - Linux/Mac)",
        ))
    } else if lower.contains("homekit") || lower.contains("companion") {
        Some(i18n::tr(
            "📱 iPhone / iPad (Apple)",
            "📱 iPhone / iPad (Apple)",
            "📱 iPhone / iPad (苹果设备)",
        ))
    } else if lower.contains("hue") || lower.contains("tuya") || lower.contains("matter") {
        Some(i18n::tr(
            "💡 Thiết bị thông minh (Smart Home)",
            "💡 Smart Device (Smart Home)",
            "💡 智能设备 (智能家居)",
        ))
    } else {
        None
    }
}

pub fn read_dns_name(buf: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut p = *pos;
    let mut guard = 0;
    loop {
        guard += 1;
        if guard > 64 || p >= buf.len() {
            return None;
        }
        let l = buf[p];
        if l == 0 {
            p += 1;
            if !jumped {
                *pos = p;
            }
            break;
        }
        if l & 0xC0 == 0xC0 {
            if p + 1 >= buf.len() {
                return None;
            }
            let ptr = (((l & 0x3F) as usize) << 8) | buf[p + 1] as usize;
            if !jumped {
                *pos = p + 2;
            }
            jumped = true;
            p = ptr;
            continue;
        }
        if p + 1 + l as usize > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[p + 1..p + 1 + l as usize]).to_string());
        p += 1 + l as usize;
    }
    Some(labels.join("."))
}

pub fn extract_mdns_services(response: &[u8]) -> Vec<String> {
    let mut services = Vec::new();
    if response.len() < 12 {
        return services;
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        if read_dns_name(response, &mut pos).is_none() {
            return services;
        }
        pos += 4;
    }

    for _ in 0..ancount {
        if read_dns_name(response, &mut pos).is_none() {
            break;
        }
        if pos + 10 > response.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        if rdata_start + rdlength > response.len() {
            break;
        }
        if rr_type == 12 {
            let mut rpos = rdata_start;
            if let Some(service) = read_dns_name(response, &mut rpos) {
                if service.starts_with('_') && !services.contains(&service) {
                    services.push(service);
                }
            }
        }
        pos = rdata_start + rdlength;
    }
    services
}

pub async fn probe_mdns_hints() -> Vec<DiscoveryHint> {
    let mut hints = Vec::new();
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return hints,
    };

    // DNS header: TXID=0, flags=0, QDCOUNT=1, ANCOUNT=0, NS=0, AR=0.
    let mut query = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in ["_services", "_dns-sd", "_udp", "local"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);
    query.extend_from_slice(&12u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());

    // mDNS multicast is 224.0.0.251:5353 (224.0.0.252 is LLMNR, not mDNS).
    let target: SocketAddr = "224.0.0.251:5353".parse().unwrap();
    if socket.send_to(&query, target).await.is_err() {
        return hints;
    }

    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            break;
        }
        match tokio::time::timeout(remain, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                let ip_str = src.ip().to_string();
                for service in extract_mdns_services(&buf[..len]) {
                    hints.push(DiscoveryHint {
                        ip: ip_str.clone(),
                        source: "mDNS",
                        keyword: mdns_keyword(&service),
                    });
                }
            }
            _ => break,
        }
    }
    hints
}

/// Giải mã escape DNS trong tên (`\ `→space, `\.`→`.`, `\;`→`;`) —
/// mDNS escape khoảng trắng trong label bằng backslash.
pub fn unescape_dns_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(next) => out.push(next),
                None => out.push('\\'),
            }
        } else {
            out.push(c)
        }
    }
    out
}

/// Track 8 — Nhận diện thiết bị: hỏi mDNS PTR ngược cho `ip` trên 224.0.0.251:5353.
/// Điện thoại/máy tính/smart home tự khai báo tên mà chủ thiết bị đã đặt
/// (VD "Bàn của An @ iPhone") qua bản ghi PTR `x.x.x.x.in-addr.arpa`.
/// CHỈ hỏi multicast LAN, không mở surface mạng mới (cùng cổng/protocol
/// với probe_mdns_hints hiện có).
pub async fn probe_mdns_reverse_name(ip: &str) -> Option<String> {
    let octets: Vec<u8> = ip
        .trim()
        .parse::<std::net::IpAddr>()
        .ok()?
        .to_string()
        .split('.')
        .filter_map(|o| o.parse().ok())
        .collect();
    if octets.len() != 4 {
        return None;
    }

    // DNS header TXID=0, flags=0, QD=1 + PTR query cho in-addr.arpa.
    let mut query = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in [
        octets[3].to_string(),
        octets[2].to_string(),
        octets[1].to_string(),
        octets[0].to_string(),
        "in-addr".to_string(),
        "arpa".to_string(),
    ] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);
    query.extend_from_slice(&12u16.to_be_bytes()); // PTR
    query.extend_from_slice(&1u16.to_be_bytes()); // IN

    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let target: SocketAddr = "224.0.0.251:5353".parse().ok()?;
    if socket.send_to(&query, target).await.is_err() {
        return None;
    }

    let deadline = Instant::now() + Duration::from_millis(1200);
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            break;
        }
        match tokio::time::timeout(remain, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                // Chỉ nhận trả lời TỪ IP đang hỏi — probe chạy song song, nếu
                // thiết bị trả lời multicast thì socket này có thể nhận packet
                // của thiết bị khác → gán nhầm tên.
                if src.ip().to_string() != ip {
                    continue;
                }
                if let Some(name) = extract_ptr_name(&buf[..len]) {
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
            }
            _ => break,
        }
    }
    None
}

/// Tách PTR rdata đầu tiên từ gói mDNS trả lời — trả về tên (bỏ đuôi .local).
pub fn extract_ptr_name(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    // Bỏ qua question section (QDCOUNT tên + 4 byte mỗi câu).
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        read_dns_name(buf, &mut pos)?;
        pos += 4;
    }
    for _ in 0..ancount {
        read_dns_name(buf, &mut pos)?;
        if pos + 10 > buf.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        let rdata = pos + 10;
        if rdata + rdlength > buf.len() {
            return None;
        }
        if rr_type == 12 {
            let mut rpos = rdata;
            if let Some(ptr) = read_dns_name(buf, &mut rpos) {
                let name = unescape_dns_name(&ptr);
                // "Tên@iPhone._companion-link._tcp.local" → lấy tới trước service part
                let cut = name.find("._").unwrap_or(name.len());
                let device = name[..cut].trim_matches('.').to_string();
                let device = device.strip_suffix(".local").unwrap_or(&device).to_string();
                if !device.is_empty() && device.len() <= 64 {
                    return Some(device);
                }
            }
            return None;
        }
        pos = rdata + rdlength;
    }
    None
}

pub async fn collect_hints() -> HashMap<String, DiscoveryHint> {
    let (mdns, ssdp) = tokio::join!(probe_mdns_hints(), probe_ssdp_hints());
    let mut map: HashMap<String, DiscoveryHint> = HashMap::new();
    // Merge preferring whichever hint carries a device keyword: a keyworded
    // hint classifies the device, a bare one does not.
    let mut insert_prefer_keyword = |hint: DiscoveryHint| {
        map.entry(hint.ip.clone())
            .and_modify(|existing| {
                if existing.keyword.is_none() && hint.keyword.is_some() {
                    *existing = hint.clone();
                }
            })
            .or_insert(hint);
    };
    for hint in mdns {
        insert_prefer_keyword(hint);
    }
    for hint in ssdp {
        insert_prefer_keyword(hint);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unescape_dns_name() {
        assert_eq!(unescape_dns_name("B\\ àn\\ của\\ An"), "B àn của An");
        assert_eq!(unescape_dns_name("no-escape"), "no-escape");
    }

    #[test]
    fn test_extract_ptr_name_fixture() {
        // PTR answer: header(12) + question (name + 4) + answer:
        // name ptr + type 12 + class/ttl(8) + rdlength 2 + rdata ptr.
        // Question name = "1.0.0.127.in-addr.arpa" (compressed count hidden)
        // Xây fixture: question "5.1.168.192.in-addr.arpa" uncompressed.
        let mut buf = vec![0u8; 12];
        buf[4] = 0;
        buf[5] = 1; // QD=1
        buf[6] = 0;
        buf[7] = 1; // AN=1
        for label in ["5", "1", "168", "192", "in-addr", "arpa"] {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&0u16.to_be_bytes()); // type A? any
        buf.extend_from_slice(&1u16.to_be_bytes()); // class
                                                    // Answer: name = ptr to question (0xC00C), type 12, class 1, ttl 0, rdlength
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&12u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        let mut rdata = Vec::new();
        for label in ["Tên máy của An", "_companion-link", "_tcp", "local"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);
        let name = extract_ptr_name(&buf).expect("PTR name must extract");
        assert_eq!(name, "Tên máy của An");
    }

    #[test]
    fn test_ssdp_keyword() {
        assert_eq!(
            ssdp_keyword("Linux UPnP/1.0 Chromecast"),
            Some("📺 Smart TV / Chromecast")
        );
        assert_eq!(
            ssdp_keyword("HP Printer IPP Server"),
            Some("🖨️ Máy in mạng (Printer - AirPrint / IPP)")
        );
        assert_eq!(ssdp_keyword("Random Device"), None);
    }

    #[test]
    fn test_mdns_keyword() {
        assert!(mdns_keyword("_googlecast._tcp.local")
            .unwrap()
            .contains("Chromecast"));
        assert!(mdns_keyword("_ipp._tcp.local").unwrap().contains("Printer"));
        assert_eq!(mdns_keyword("_unknown._tcp.local"), None);
    }

    #[test]
    fn test_read_dns_name_plain() {
        let buf = b"\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00";
        let mut pos = 1usize;
        let name = read_dns_name(buf, &mut pos).unwrap();
        assert_eq!(name, "_services._dns-sd._udp.local");
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn test_read_dns_name_compression() {
        let mut buf = vec![0x00, 0x03, b'a', b'b', b'c', 0x00];
        buf.push(0xC0);
        buf.push(0x01);
        let mut pos = 6usize;
        let name = read_dns_name(&buf, &mut pos).unwrap();
        assert_eq!(name, "abc");
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn test_extract_mdns_services() {
        let mut resp = vec![
            0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in ["_services", "_dns-sd", "_udp", "local"] {
            resp.push(label.len() as u8);
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0x00);
        resp.extend_from_slice(&12u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&60u32.to_be_bytes());
        resp.extend_from_slice(&16u16.to_be_bytes());
        for label in ["_googlecast", "_tcp", "local"] {
            resp.push(label.len() as u8);
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0x00);

        let services = extract_mdns_services(&resp);
        assert_eq!(services, vec!["_googlecast._tcp.local".to_string()]);
    }
}
