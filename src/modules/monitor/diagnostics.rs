use crate::modules::i18n;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    pub target: String,
    pub min_ms: i32,
    pub avg_ms: i32,
    pub max_ms: i32,
    pub jitter_ms: i32,
    pub loss_pct: i32,
    pub status_text: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealthReport {
    pub gateway_status: String,
    pub dns_status: String,
    pub internet_status: String,
    pub stability_status: String,
    pub summary_score: i32,
    pub overall_text: String,
}

pub struct NetworkDiagnostics;

impl NetworkDiagnostics {
    pub async fn measure_fast_ping() -> i32 {
        let targets = [
            "1.1.1.1:443",
            "8.8.8.8:53",
            "9.9.9.9:53",
            "1.0.0.1:443",
            "8.8.4.4:53",
        ];
        let mut best: i32 = -1;
        for target in targets {
            let start = Instant::now();
            let addr_res = target.parse::<SocketAddr>();
            if let Ok(addr) = addr_res {
                if let Ok(Ok(_)) =
                    tokio::time::timeout(Duration::from_millis(600), TcpStream::connect(addr)).await
                {
                    let ms = start.elapsed().as_millis().max(1) as i32;
                    if best < 0 || ms < best {
                        best = ms;
                    }
                }
            }
        }
        best
    }

    #[allow(dead_code)]
    pub async fn run_speed_test() -> SpeedTestResult {
        Self::run_speed_test_with_progress(|_, _, _| {}).await
    }

    pub async fn run_speed_test_with_progress<F>(progress: F) -> SpeedTestResult
    where
        F: Fn(f64, f64, i32) + Send + Sync + 'static,
    {
        let mut detail = String::new();
        let ping_ms = Self::measure_fast_ping().await;
        progress(0.0, 0.0, ping_ms);

        let ping_str = if ping_ms >= 0 {
            format!("{} ms", ping_ms)
        } else {
            i18n::tr("Hết giờ (timeout)", "Timeout", "超时").to_string()
        };
        detail.push_str(&format!(
            "{}: {}\n",
            i18n::tr(
                "Độ trễ Ping Anycast",
                "Anycast Ping Latency",
                "Anycast Ping 延迟"
            ),
            ping_str
        ));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap_or_default();

        let mut download_mbps: f64 = -1.0;
        let mut downloaded_bytes: u64 = 0;
        let download_start = Instant::now();

        let dl_endpoints = [
            "https://speed.cloudflare.com/__down?bytes=52428800",
            "https://speed.hetzner.de/100MB.bin",
        ];

        let mut dl_success = false;
        for url in dl_endpoints {
            if let Ok(resp) = client.get(url).send().await {
                if resp.status().is_success() {
                    let mut stream = resp;
                    let mut last_progress_report = Instant::now();
                    while let Ok(Ok(Some(chunk))) =
                        tokio::time::timeout(Duration::from_millis(1500), stream.chunk()).await
                    {
                        downloaded_bytes += chunk.len() as u64;
                        let elapsed = download_start.elapsed().as_secs_f64().max(0.001);
                        download_mbps = (downloaded_bytes as f64 * 8.0) / elapsed / 1_000_000.0;
                        if last_progress_report.elapsed() >= Duration::from_millis(250) {
                            progress(download_mbps, 0.0, ping_ms);
                            last_progress_report = Instant::now();
                        }
                        if download_start.elapsed() >= Duration::from_secs(6) {
                            break;
                        }
                    }
                    if downloaded_bytes > 0 {
                        dl_success = true;
                        break;
                    }
                }
            }
        }

        let dl_secs = download_start.elapsed().as_secs_f64().max(0.001);
        if dl_success {
            download_mbps = (downloaded_bytes as f64 * 8.0) / dl_secs / 1_000_000.0;
            progress(download_mbps, 0.0, ping_ms);
            detail.push_str(&format!(
                "{} {:.1} Mbps ({} MB / {:.1}s)\n",
                i18n::tr("Tốc độ tải xuống:", "Download Speed:", "下载速度:"),
                download_mbps,
                downloaded_bytes / 1_048_576,
                dl_secs
            ));
        } else {
            detail.push_str(&format!(
                "{}\n",
                i18n::tr(
                    "Tải xuống: Gián đoạn hoặc lỗi kết nối",
                    "Download: Interrupted or connection error",
                    "下载: 中断或连接错误"
                )
            ));
        }

        let mut upload_mbps: f64 = -1.0;
        let target_bytes = if download_mbps > 0.0 {
            ((download_mbps * 1_000_000.0 / 8.0) * 3.5) as usize
        } else {
            3_145_728
        };
        let upload_len = target_bytes.clamp(1_048_576, 16_777_216);
        let payload = vec![0u8; upload_len];
        let up_start = Instant::now();

        if let Ok(resp) = client
            .post("https://speed.cloudflare.com/__up")
            .body(payload)
            .send()
            .await
        {
            if resp.status().is_success() {
                let _ = resp.bytes().await;
                let up_secs = up_start.elapsed().as_secs_f64().max(0.001);
                upload_mbps = (upload_len as f64 * 8.0) / up_secs / 1_000_000.0;
                progress(download_mbps, upload_mbps, ping_ms);
                detail.push_str(&format!(
                    "{} {:.1} Mbps ({} MB / {:.1}s)",
                    i18n::tr("Tốc độ tải lên:", "Upload Speed:", "上传速度:"),
                    upload_mbps,
                    upload_len / 1_048_576,
                    up_secs
                ));
            } else {
                detail.push_str(&format!(
                    "{} HTTP {}",
                    i18n::tr(
                        "Tải lên: Lỗi máy chủ",
                        "Upload: Server error",
                        "上传: 服务器错误"
                    ),
                    resp.status()
                ));
            }
        } else {
            detail.push_str(i18n::tr(
                "Tải lên: Gián đoạn kết nối",
                "Upload: Connection interrupted",
                "上传: 连接中断",
            ));
        }

        SpeedTestResult {
            download_mbps,
            upload_mbps,
            ping_ms,
            detail,
        }
    }

    pub async fn run_dns_benchmark(domain_to_test: &str) -> Vec<DnsBenchmarkResult> {
        let test_domain = if domain_to_test.trim().is_empty() {
            "google.com".to_string()
        } else {
            domain_to_test.trim().to_string()
        };

        let providers: [(&'static str, &'static str); 7] = [
            ("Shield Ghita (Local DNS)", "127.0.0.1:53"),
            ("Cloudflare (1.1.1.1)", "1.1.1.1:53"),
            ("Google Public DNS (8.8.8.8)", "8.8.8.8:53"),
            ("Quad9 Security (9.9.9.9)", "9.9.9.9:53"),
            ("OpenDNS (208.67.222.222)", "208.67.222.222:53"),
            ("NextDNS (45.90.28.0)", "45.90.28.0:53"),
            ("AdGuard DNS (94.140.14.14)", "94.140.14.14:53"),
        ];

        let mut join_set = JoinSet::new();
        for (name, addr_str) in providers {
            let domain_clone = test_domain.clone();
            join_set.spawn(async move {
                let latency = Self::test_single_dns(addr_str, &domain_clone).await;
                (name, addr_str, latency)
            });
        }

        let mut results = Vec::with_capacity(7);
        while let Some(res) = join_set.join_next().await {
            if let Ok((name, addr_str, latency)) = res {
                let (status, lat_val) = match latency {
                    Some(ms) => (format!("{} ms", ms), ms),
                    None => (
                        i18n::tr("Timeout / Bị chặn", "Timeout / Blocked", "超时 / 被拦截")
                            .to_string(),
                        9999,
                    ),
                };
                results.push(DnsBenchmarkResult {
                    provider_name: name.to_string(),
                    ip: addr_str.replace(":53", ""),
                    latency_ms: lat_val,
                    status,
                    is_fastest: false,
                });
            }
        }

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

        let mut packet = Vec::with_capacity(64);
        let tx_id = 0x1234u16;
        packet.extend_from_slice(&tx_id.to_be_bytes());
        packet.extend_from_slice(&[0x01, 0x00]);
        packet.extend_from_slice(&[0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        for part in domain.split('.') {
            if part.is_empty() {
                continue;
            }
            packet.push(part.len() as u8);
            packet.extend_from_slice(part.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x01]);

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

    pub async fn run_ping(target_input: &str, count: usize) -> PingResult {
        let cleaned = target_input
            .trim()
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string();

        let host = if cleaned.is_empty() {
            "1.1.1.1".to_string()
        } else {
            cleaned
        };

        let sample_count = count.clamp(3, 10);
        let mut latencies: Vec<i32> = Vec::with_capacity(sample_count);
        let mut failed = 0;

        let port_candidates = if host == "1.1.1.1" || host == "8.8.8.8" || host == "9.9.9.9" {
            vec![53, 443, 80]
        } else {
            vec![443, 80, 53, 22]
        };

        for i in 0..sample_count {
            let mut sample_ms: Option<i32> = None;
            for &port in &port_candidates {
                let target_str = format!("{}:{}", host, port);
                let start = Instant::now();
                match tokio::time::timeout(
                    Duration::from_millis(900),
                    TcpStream::connect(&target_str),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        let ms = start.elapsed().as_millis().max(1) as i32;
                        sample_ms = Some(ms);
                        break;
                    }
                    Ok(Err(_)) => {
                        let ms = start.elapsed().as_millis().max(1) as i32;
                        if ms < 20 {
                            sample_ms = Some(ms);
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }

            match sample_ms {
                Some(ms) => latencies.push(ms),
                None => failed += 1,
            }

            if i + 1 < sample_count {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        let loss_pct = ((failed as f32 / sample_count as f32) * 100.0).round() as i32;
        let (min_ms, avg_ms, max_ms, jitter_ms) = if !latencies.is_empty() {
            let min = *latencies.iter().min().unwrap_or(&0);
            let max = *latencies.iter().max().unwrap_or(&0);
            let sum: i32 = latencies.iter().sum();
            let avg = sum / latencies.len() as i32;

            let mut jitter_sum = 0;
            for w in latencies.windows(2) {
                jitter_sum += (w[1] - w[0]).abs();
            }
            let jitter = if latencies.len() > 1 {
                jitter_sum / (latencies.len() - 1) as i32
            } else {
                0
            };
            (min, avg, max, jitter)
        } else {
            (-1, -1, -1, 0)
        };

        let status_text = if loss_pct >= 100 {
            i18n::tr("Mất kết nối / Timeout", "Offline / Timeout", "离线 / 超时").to_string()
        } else if avg_ms <= 30 && loss_pct == 0 {
            i18n::tr(
                "Xuất sắc (Độ trễ rất thấp)",
                "Excellent (Ultra-low latency)",
                "极佳（超低延迟）",
            )
            .to_string()
        } else if avg_ms <= 70 && loss_pct <= 5 {
            i18n::tr("Tốt / Ổn định", "Good & Stable", "良好稳定").to_string()
        } else if avg_ms <= 150 {
            i18n::tr("Trung bình", "Fair", "一般").to_string()
        } else {
            i18n::tr("Độ trễ cao / Kém", "High Latency / Poor", "高延迟 / 较差").to_string()
        };

        let details = format!(
            "{} {}/{} | Min: {} ms | Avg: {} ms | Max: {} ms | Jitter: {} ms | Loss: {}%",
            i18n::tr("Gói nhận:", "Packets received:", "接收数据包:"),
            latencies.len(),
            sample_count,
            if min_ms >= 0 { min_ms } else { 0 },
            if avg_ms >= 0 { avg_ms } else { 0 },
            if max_ms >= 0 { max_ms } else { 0 },
            jitter_ms,
            loss_pct
        );

        PingResult {
            target: host,
            min_ms,
            avg_ms,
            max_ms,
            jitter_ms,
            loss_pct,
            status_text,
            details,
        }
    }

    pub async fn run_network_health_check() -> NetworkHealthReport {
        let (gw_status, gw_score) = {
            let gw_ip = crate::modules::system::win32_net::detect_default_gateway_ip()
                .unwrap_or_else(|| "192.168.1.1".to_string());
            let ping = Self::run_ping(&gw_ip, 3).await;
            if ping.loss_pct < 50 && ping.avg_ms >= 0 {
                (
                    format!(
                        "{} ({} ms)",
                        i18n::tr("Đã kết nối", "Connected", "已连接"),
                        ping.avg_ms
                    ),
                    25,
                )
            } else {
                (
                    i18n::tr("Không phản hồi", "Unresponsive", "未响应").to_string(),
                    5,
                )
            }
        };

        let (dns_status, dns_score) = {
            let local_test = Self::test_single_dns("127.0.0.1:53", "google.com").await;
            let cloudflare_test = Self::test_single_dns("1.1.1.1:53", "google.com").await;
            if local_test.is_some() || cloudflare_test.is_some() {
                let ms = local_test.or(cloudflare_test).unwrap_or(1);
                (
                    format!(
                        "{} ({} ms)",
                        i18n::tr("Hoạt động tốt", "Operational", "运行正常"),
                        ms
                    ),
                    25,
                )
            } else {
                (
                    i18n::tr("Lỗi phân giải", "Resolution Failed", "解析失败").to_string(),
                    0,
                )
            }
        };

        let (net_status, net_score) = {
            let ping = Self::measure_fast_ping().await;
            if (0..150).contains(&ping) {
                (
                    format!("{} ({} ms)", i18n::tr("Thông suốt", "Online", "畅通"), ping),
                    30,
                )
            } else if ping >= 150 {
                (
                    format!("{} ({} ms)", i18n::tr("Chậm", "High Latency", "较慢"), ping),
                    15,
                )
            } else {
                (
                    i18n::tr("Mất kết nối Internet", "No Internet", "无网络").to_string(),
                    0,
                )
            }
        };

        let (stab_status, stab_score) = {
            let ping = Self::run_ping("1.1.1.1", 4).await;
            if ping.loss_pct == 0 && ping.jitter_ms <= 15 {
                (
                    format!(
                        "{} (Loss: 0%, Jitter: {}ms)",
                        i18n::tr("Rất cao", "Very High", "极高"),
                        ping.jitter_ms
                    ),
                    20,
                )
            } else if ping.loss_pct <= 10 {
                (
                    format!(
                        "{} (Loss: {}%, Jitter: {}ms)",
                        i18n::tr("Khá", "Moderate", "良好"),
                        ping.loss_pct,
                        ping.jitter_ms
                    ),
                    12,
                )
            } else {
                (
                    format!(
                        "{} (Loss: {}%)",
                        i18n::tr("Kém", "Unstable", "不稳定"),
                        ping.loss_pct
                    ),
                    5,
                )
            }
        };

        let total_score = (gw_score + dns_score + net_score + stab_score).clamp(0, 100);
        let overall_text = if total_score >= 85 {
            i18n::tr(
                "Mạng hoạt động hoàn hảo, đường truyền ổn định và độ trễ thấp.",
                "Network is in optimal condition with low latency and high stability.",
                "网络运行完美，传输稳定且延迟低。",
            )
        } else if total_score >= 60 {
            i18n::tr(
                "Mạng khả dụng tốt, có thể có độ trễ nhẹ hoặc mất vài gói tin.",
                "Network is functional with minor latency or occasional packet drops.",
                "网络状态良好，可能存在轻微延迟或个别丢包。",
            )
        } else {
            i18n::tr(
                "Cảnh báo: Đường truyền mạng chập chờn hoặc mất kết nối Internet.",
                "Warning: Network connection is unstable or disconnected.",
                "警告：网络连接不稳定或已断开连接。",
            )
        };

        NetworkHealthReport {
            gateway_status: gw_status,
            dns_status,
            internet_status: net_status,
            stability_status: stab_status,
            summary_score: total_score,
            overall_text: overall_text.to_string(),
        }
    }
}
