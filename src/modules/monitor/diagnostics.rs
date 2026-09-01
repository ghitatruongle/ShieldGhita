use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBenchmarkResult {
    pub provider_name: String,
    pub ip: String,
    pub latency_ms: i32,
    pub status: String,
    pub is_fastest: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestResult {
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub ping_ms: i32,
    pub detail: String,
}

pub struct NetworkDiagnostics;

impl NetworkDiagnostics {
    /// Measures real Internet throughput via Cloudflare's speed endpoints:
    /// latency from a tiny download, download by streaming for ~8 seconds,
    /// upload by POSTing an adaptive payload sized from the download result.
    pub async fn run_speed_test() -> SpeedTestResult {
        let mut detail = String::new();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        // 1. Latency: two tiny downloads, keep the best round trip.
        let mut ping_ms: i32 = -1;
        for _ in 0..2 {
            let start = Instant::now();
            if let Ok(resp) = client
                .get("https://speed.cloudflare.com/__down?bytes=1")
                .send()
                .await
            {
                if resp.status().is_success() {
                    let _ = resp.bytes().await;
                    let ms = start.elapsed().as_millis() as i32;
                    if ping_ms < 0 || ms < ping_ms {
                        ping_ms = ms;
                    }
                }
            }
        }
        detail.push_str(&format!(
            "Ping Cloudflare: {}\n",
            if ping_ms >= 0 {
                format!("{} ms", ping_ms)
            } else {
                "timeout".to_string()
            }
        ));

        // 2. Download: stream up to 100MB but stop after 8 seconds.
        let mut download_mbps: f64 = -1.0;
        if let Ok(resp) = client
            .get("https://speed.cloudflare.com/__down?bytes=104857600")
            .send()
            .await
        {
            if resp.status().is_success() {
                let mut resp = resp;
                let start = Instant::now();
                let mut total: u64 = 0;
                loop {
                    if start.elapsed() >= Duration::from_secs(8) {
                        break;
                    }
                    match tokio::time::timeout(Duration::from_secs(2), resp.chunk()).await {
                        Ok(Ok(Some(chunk))) => total += chunk.len() as u64,
                        _ => break,
                    }
                }
                let secs = start.elapsed().as_secs_f64().max(0.001);
                download_mbps = (total as f64 * 8.0) / secs / 1_000_000.0;
                detail.push_str(&format!(
                    "Download: {:.1} Mbps ({} MB trong {:.1}s)\n",
                    download_mbps,
                    total / 1_048_576,
                    secs
                ));
            } else {
                detail.push_str(&format!("Download: HTTP {}\n", resp.status()));
            }
        } else {
            detail.push_str("Download: lỗi kết nối\n");
        }

        // 3. Upload: adaptive payload — aim for ~5s, clamp 1..24 MB.
        let mut upload_mbps: f64 = -1.0;
        let target_bytes = if download_mbps > 0.0 {
            ((download_mbps * 1_000_000.0 / 8.0) * 5.0) as usize
        } else {
            4_194_304
        };
        let upload_len = target_bytes.clamp(1_048_576, 25_165_824);
        let payload = vec![0u8; upload_len];
        let start = Instant::now();
        if let Ok(resp) = client
            .post("https://speed.cloudflare.com/__up")
            .body(payload)
            .send()
            .await
        {
            if resp.status().is_success() {
                let _ = resp.bytes().await;
                let secs = start.elapsed().as_secs_f64().max(0.001);
                upload_mbps = (upload_len as f64 * 8.0) / secs / 1_000_000.0;
                detail.push_str(&format!(
                    "Upload: {:.1} Mbps ({} MB trong {:.1}s)",
                    upload_mbps,
                    upload_len / 1_048_576,
                    secs
                ));
            } else {
                detail.push_str(&format!("Upload: HTTP {}", resp.status()));
            }
        } else {
            detail.push_str("Upload: lỗi kết nối");
        }

        SpeedTestResult {
            download_mbps,
            upload_mbps,
            ping_ms,
            detail,
        }
    }

    /// Measures DNS query resolution latency for top DNS servers
    pub async fn run_dns_benchmark(domain_to_test: &str) -> Vec<DnsBenchmarkResult> {
        let test_domain = if domain_to_test.trim().is_empty() {
            "google.com"
        } else {
            domain_to_test.trim()
        };

        let providers = [
            ("Shield Ghita (Local DNS)", "127.0.0.1:53"),
            ("Cloudflare (1.1.1.1)", "1.1.1.1:53"),
            ("Google Public DNS (8.8.8.8)", "8.8.8.8:53"),
            ("Quad9 Security (9.9.9.9)", "9.9.9.9:53"),
            ("OpenDNS (208.67.222.222)", "208.67.222.222:53"),
            ("NextDNS (45.90.28.0)", "45.90.28.0:53"),
            ("AdGuard DNS (94.140.14.14)", "94.140.14.14:53"),
        ];

        let mut results = Vec::new();

        for (name, addr_str) in providers {
            let latency = Self::test_single_dns(addr_str, test_domain).await;
            let (status, lat_val) = match latency {
                Some(ms) => (format!("{} ms", ms), ms),
                None => ("Timeout / Blocked".to_string(), 9999),
            };

            results.push(DnsBenchmarkResult {
                provider_name: name.to_string(),
                ip: addr_str.replace(":53", ""),
                latency_ms: lat_val,
                status,
                is_fastest: false,
            });
        }

        // Find fastest among successful queries
        if let Some(min_entry) = results
            .iter_mut()
            .filter(|r| r.latency_ms > 0 && r.latency_ms < 9999)
            .min_by_key(|r| r.latency_ms)
        {
            min_entry.is_fastest = true;
        }

        results.sort_by_key(|r| r.latency_ms);
        results
    }

    async fn test_single_dns(server_addr: &str, domain: &str) -> Option<i32> {
        let target: SocketAddr = server_addr.parse().ok()?;
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().ok()?;
        let socket = UdpSocket::bind(bind_addr).await.ok()?;

        // Build standard DNS Query for A record
        let mut packet = Vec::with_capacity(64);
        let tx_id = 0x1234u16;
        packet.extend_from_slice(&tx_id.to_be_bytes()); // ID
        packet.extend_from_slice(&[0x01, 0x00]); // Standard query + recursion desired
        packet.extend_from_slice(&[0x00, 0x01]); // 1 question
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        for part in domain.split('.') {
            if part.is_empty() {
                continue;
            }
            packet.push(part.len() as u8);
            packet.extend_from_slice(part.as_bytes());
        }
        packet.push(0); // End of name
        packet.extend_from_slice(&[0x00, 0x01]); // Type A
        packet.extend_from_slice(&[0x00, 0x01]); // Class IN

        let start = Instant::now();
        if socket.send_to(&packet, target).await.is_err() {
            return None;
        }

        let mut buf = [0u8; 512];
        match tokio::time::timeout(Duration::from_millis(1500), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) if len >= 12 => {
                let elapsed = start.elapsed().as_millis().max(1) as i32;
                Some(elapsed)
            }
            _ => None,
        }
    }
}
