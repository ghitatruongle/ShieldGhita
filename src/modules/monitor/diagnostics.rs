use crate::modules::i18n;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

#[repr(C)]
struct IpOptionInformation {
    ttl: u8,
    tos: u8,
    flags: u8,
    options_size: u8,
    options_data: *mut u8,
}

#[repr(C)]
struct IcmpEchoReply {
    address: u32,
    status: u32,
    round_trip_time: u32,
    data_size: u16,
    reserved: u16,
    data: *mut u8,
    options: IpOptionInformation,
}

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
    fn IcmpCreateFile() -> *mut std::ffi::c_void;
    fn IcmpSendEcho(
        icmp_handle: *mut std::ffi::c_void,
        destination_address: u32,
        request_data: *const u8,
        request_size: u16,
        request_options: *const IpOptionInformation,
        reply_buffer: *mut u8,
        reply_size: u32,
        timeout: u32,
    ) -> u32;
    fn IcmpCloseHandle(icmp_handle: *mut std::ffi::c_void) -> i32;
}

#[cfg(windows)]
fn icmp_ping_v4_native(ip: Ipv4Addr, timeout_ms: u32) -> Option<i32> {
    unsafe {
        let handle = IcmpCreateFile();
        if handle.is_null() || handle == usize::MAX as *mut std::ffi::c_void {
            return None;
        }
        let send_data = b"ShieldGhitaPingV010";
        let reply_size = std::mem::size_of::<IcmpEchoReply>() + send_data.len() + 32;
        let mut reply_buf = vec![0u8; reply_size];
        let dest_addr = u32::from_ne_bytes(ip.octets());
        let replies = IcmpSendEcho(
            handle,
            dest_addr,
            send_data.as_ptr(),
            send_data.len() as u16,
            std::ptr::null(),
            reply_buf.as_mut_ptr(),
            reply_size as u32,
            timeout_ms,
        );
        let res = if replies > 0 {
            // read_unaligned: the byte buffer carries no guarantee of the
            // struct's 8-byte alignment, so a reference cast would be UB.
            let reply = reply_buf.as_ptr().cast::<IcmpEchoReply>().read_unaligned();
            if reply.status == 0 {
                Some(reply.round_trip_time.max(1) as i32)
            } else {
                None
            }
        } else {
            None
        };
        IcmpCloseHandle(handle);
        res
    }
}

#[cfg(not(windows))]
fn icmp_ping_v4_native(_ip: Ipv4Addr, _timeout_ms: u32) -> Option<i32> {
    None
}

pub struct NetworkDiagnostics;

impl NetworkDiagnostics {
    pub async fn measure_fast_ping() -> i32 {
        let targets = [
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(9, 9, 9, 9),
            Ipv4Addr::new(1, 0, 0, 1),
        ];

        let mut set = JoinSet::new();
        for ip in targets {
            set.spawn(async move {
                tokio::task::spawn_blocking(move || icmp_ping_v4_native(ip, 350))
                    .await
                    .ok()
                    .flatten()
            });
        }

        let mut best: i32 = -1;
        while let Some(res) = set.join_next().await {
            if let Ok(Some(ms)) = res {
                if best < 0 || ms < best {
                    best = ms;
                }
            }
        }

        if best >= 0 {
            return best;
        }

        let fallback_addrs = ["1.1.1.1:443", "8.8.8.8:53", "9.9.9.9:53"];
        let mut tcp_set = JoinSet::new();
        for target in fallback_addrs {
            tcp_set.spawn(async move {
                if let Ok(addr) = target.parse::<SocketAddr>() {
                    let start = Instant::now();
                    if let Ok(Ok(_)) =
                        tokio::time::timeout(Duration::from_millis(400), TcpStream::connect(addr))
                            .await
                    {
                        return Some(start.elapsed().as_millis().max(1) as i32);
                    }
                }
                None
            });
        }
        while let Some(res) = tcp_set.join_next().await {
            if let Ok(Some(ms)) = res {
                if best < 0 || ms < best {
                    best = ms;
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
            i18n::tr4("Hết giờ (timeout)", "Timeout", "超时", "Тайм-аут").to_string()
        };
        detail.push_str(&format!(
            "{}: {}\n",
            i18n::tr4(
                "Độ trễ Ping Anycast",
                "Anycast Ping Latency",
                "Anycast Ping 延迟",
                "Задержка Anycast Ping",
            ),
            ping_str
        ));

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_static(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            ),
        );
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("*/*"),
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        let mut download_mbps: f64 = -1.0;
        let mut downloaded_bytes: u64 = 0;
        let mut dl_secs: f64 = 0.0;

        let dl_endpoints = [
            "https://speed.cloudflare.com/__down?bytes=10000000",
            "https://proof.ovh.net/files/10Mb.dat",
            "https://speed.hetzner.de/10MB.bin",
        ];

        let mut dl_success = false;
        for url in dl_endpoints {
            // Reset timing per endpoint (same as upload): a failed/slow first
            // endpoint must not inflate the next endpoint's elapsed time.
            let download_start = Instant::now();
            let mut ep_bytes: u64 = 0;
            if let Ok(resp) = client.get(url).send().await {
                if resp.status().is_success() {
                    let mut stream = resp;
                    let mut last_progress_report = Instant::now();
                    while let Ok(Ok(Some(chunk))) =
                        tokio::time::timeout(Duration::from_millis(4000), stream.chunk()).await
                    {
                        ep_bytes += chunk.len() as u64;
                        let elapsed = download_start.elapsed().as_secs_f64().max(0.001);
                        download_mbps = (ep_bytes as f64 * 8.0) / elapsed / 1_000_000.0;
                        if last_progress_report.elapsed() >= Duration::from_millis(200) {
                            progress(download_mbps, 0.0, ping_ms);
                            last_progress_report = Instant::now();
                        }
                        if download_start.elapsed() >= Duration::from_secs(5) {
                            break;
                        }
                    }
                    if ep_bytes > 0 {
                        downloaded_bytes = ep_bytes;
                        dl_secs = download_start.elapsed().as_secs_f64().max(0.001);
                        dl_success = true;
                        break;
                    }
                }
            }
        }

        if dl_success {
            download_mbps = (downloaded_bytes as f64 * 8.0) / dl_secs / 1_000_000.0;
            progress(download_mbps, 0.0, ping_ms);
            detail.push_str(&format!(
                "{} {:.1} Mbps ({} MB / {:.1}s)\n",
                i18n::tr4(
                    "Tốc độ tải xuống:",
                    "Download Speed:",
                    "下载速度:",
                    "Скорость загрузки:",
                ),
                download_mbps,
                downloaded_bytes / 1_048_576,
                dl_secs
            ));
        } else {
            detail.push_str(&format!(
                "{}\n",
                i18n::tr4(
                    "Tải xuống: Gián đoạn hoặc lỗi kết nối",
                    "Download: Interrupted or connection error",
                    "下载: 中断或连接错误",
                    "Загрузка: Прервано или ошибка соединения",
                )
            ));
        }

        let mut upload_mbps: f64 = -1.0;
        let upload_len = if download_mbps > 0.0 {
            ((download_mbps * 1_000_000.0 / 8.0) * 1.5) as usize
        } else {
            1_048_576
        }
        .clamp(262_144, 4_194_304);

        let payload = vec![0x55u8; upload_len];

        let up_endpoints = [
            "https://speed.cloudflare.com/__up",
            "https://httpbin.org/post",
        ];

        let mut up_success = false;
        for up_url in up_endpoints {
            // Timing must start per-attempt: a failed/slow first endpoint would
            // otherwise inflate the second endpoint's elapsed time and tank the
            // reported upload speed.
            let up_start = Instant::now();
            if let Ok(resp) = client
                .post(up_url)
                .body(payload.clone())
                .timeout(Duration::from_secs(6))
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
                        i18n::tr4(
                            "Tốc độ tải lên:",
                            "Upload Speed:",
                            "上传速度:",
                            "Скорость отдачи:",
                        ),
                        upload_mbps,
                        upload_len / 1_048_576,
                        up_secs
                    ));
                    up_success = true;
                    break;
                }
            }
        }

        if !up_success {
            // Do not fabricate an upload figure from download*0.85: report
            // "not measured" (-1) so the UI never shows a misleading estimate.
            upload_mbps = -1.0;
            progress(download_mbps, upload_mbps, ping_ms);
            detail.push_str(&format!(
                "{} ({})",
                i18n::tr4(
                    "Tốc độ tải lên: chưa đo được",
                    "Upload Speed: not measured",
                    "上传速度: 未测得",
                    "Скорость отдачи: не измерена",
                ),
                i18n::tr4(
                    "Cổng upload công cộng bị giới hạn",
                    "Public upload endpoint throttled",
                    "公共上传端口受限",
                    "Публичный узел ограничен",
                )
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

        let providers: [(&'static str, &'static str); 9] = [
            ("Shield Ghita (Local DNS)", "127.0.0.1:53"),
            ("Cloudflare Primary (1.1.1.1)", "1.1.1.1:53"),
            ("Cloudflare Secondary (1.0.0.1)", "1.0.0.1:53"),
            ("Google Primary (8.8.8.8)", "8.8.8.8:53"),
            ("Google Secondary (8.8.4.4)", "8.8.4.4:53"),
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

        let mut results = Vec::with_capacity(providers.len());
        while let Some(res) = join_set.join_next().await {
            if let Ok((name, addr_str, latency)) = res {
                let (status, lat_val) = match latency {
                    Some(ms) => (format!("{} ms", ms), ms),
                    None => (
                        i18n::tr4(
                            "Timeout / Bị chặn",
                            "Timeout / Blocked",
                            "超时 / 被拦截",
                            "Тайм-аут / Заблокировано",
                        )
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
        // Connect the UDP socket so only replies from the target are accepted
        // (and recv() can be used instead of recv_from).
        if socket.connect(target).await.is_err() {
            return None;
        }

        let mut packet = Vec::with_capacity(64);
        // Random transaction ID per query so stray / spoofed replies cannot
        // be mistaken for the current answer.
        let mut id_buf = [0u8; 2];
        if getrandom::fill(&mut id_buf).is_ok() {
            packet.extend_from_slice(&id_buf);
        } else {
            let fallback = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0x1234)
                ^ (std::process::id().wrapping_mul(0x9E37)) as u32)
                as u16;
            packet.extend_from_slice(&fallback.to_be_bytes());
        }
        let tx_id = [packet[0], packet[1]];
        packet.extend_from_slice(&[0x01, 0x00]);
        packet.extend_from_slice(&[0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        for part in domain.split('.') {
            if part.is_empty() {
                continue;
            }
            // DNS label limit is 63 octets; longer labels would truncate with
            // `as u8` and corrupt the query.
            if part.len() > 63 {
                return None;
            }
            packet.push(part.len() as u8);
            packet.extend_from_slice(part.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x01]);

        let start = Instant::now();
        if socket.send(&packet).await.is_err() {
            return None;
        }

        let mut buf = [0u8; 512];
        match tokio::time::timeout(Duration::from_millis(1800), socket.recv(&mut buf)).await {
            Ok(Ok(len)) if len >= 12 => {
                // Verify transaction ID and QR (response) bit; otherwise a
                // stray datagram could be counted as a valid answer.
                if buf[0] != tx_id[0] || buf[1] != tx_id[1] {
                    return None;
                }
                if buf[2] & 0x80 == 0 {
                    return None;
                }
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

        let resolved_ipv4: Option<Ipv4Addr> = if let Ok(ip) = host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => Some(v4),
                _ => None,
            }
        } else {
            // Async resolver: std's ToSocketAddrs would block a runtime worker
            // thread for the duration of the DNS lookup.
            tokio::net::lookup_host((host.as_str(), 80))
                .await
                .ok()
                .and_then(|mut addrs| {
                    addrs.find_map(|sa| match sa.ip() {
                        IpAddr::V4(v4) => Some(v4),
                        _ => None,
                    })
                })
        };

        let sample_count = count.clamp(3, 10);
        let mut latencies: Vec<i32> = Vec::with_capacity(sample_count);
        let mut failed = 0;

        for i in 0..sample_count {
            let mut sample_ms: Option<i32> = None;

            if let Some(ip) = resolved_ipv4 {
                let icmp_res =
                    tokio::task::spawn_blocking(move || icmp_ping_v4_native(ip, 400)).await;
                if let Ok(Some(ms)) = icmp_res {
                    sample_ms = Some(ms);
                }
            }

            if sample_ms.is_none() {
                let port_candidates = if host == "1.1.1.1" || host == "8.8.8.8" || host == "9.9.9.9"
                {
                    vec![53, 443, 80]
                } else {
                    vec![443, 80, 53]
                };

                for &port in &port_candidates {
                    let target_str = format!("{}:{}", host, port);
                    let start = Instant::now();
                    if let Ok(Ok(_)) = tokio::time::timeout(
                        Duration::from_millis(350),
                        TcpStream::connect(&target_str),
                    )
                    .await
                    {
                        let ms = start.elapsed().as_millis().max(1) as i32;
                        sample_ms = Some(ms);
                        break;
                    }
                }
            }

            match sample_ms {
                Some(ms) => latencies.push(ms),
                None => failed += 1,
            }

            if i + 1 < sample_count {
                tokio::time::sleep(Duration::from_millis(80)).await;
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
            i18n::tr4(
                "Mất kết nối / Timeout",
                "Offline / Timeout",
                "离线 / 超时",
                "Не в сети / Тайм-аут",
            )
            .to_string()
        } else if avg_ms <= 30 && loss_pct == 0 {
            i18n::tr4(
                "Xuất sắc (Độ trễ rất thấp)",
                "Excellent (Ultra-low latency)",
                "极佳（超低延迟）",
                "Отлично (Сверхнизкая задержка)",
            )
            .to_string()
        } else if avg_ms <= 70 && loss_pct <= 5 {
            i18n::tr4(
                "Tốt / Ổn định",
                "Good & Stable",
                "良好稳定",
                "Хорошо и стабильно",
            )
            .to_string()
        } else if avg_ms <= 150 {
            i18n::tr4("Trung bình", "Fair", "一般", "Удовлетворительно").to_string()
        } else {
            i18n::tr4(
                "Độ trễ cao / Kém",
                "High Latency / Poor",
                "高延迟 / 较差",
                "Высокая задержка / Плохо",
            )
            .to_string()
        };

        let details = format!(
            "{} {}/{} | Min: {} ms | Avg: {} ms | Max: {} ms | Jitter: {} ms | Loss: {}%",
            i18n::tr4(
                "Gói nhận:",
                "Packets received:",
                "接收数据包:",
                "Получено пакетов:",
            ),
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
        let gw_check = async {
            let gw_ip = crate::modules::system::win32_net::detect_default_gateway_ip()
                .unwrap_or_else(|| "192.168.1.1".to_string());
            let ping = Self::run_ping(&gw_ip, 3).await;
            if ping.loss_pct < 50 && ping.avg_ms >= 0 {
                (
                    format!(
                        "{} ({} ms)",
                        i18n::tr4("Đã kết nối", "Connected", "已连接", "Подключено"),
                        ping.avg_ms
                    ),
                    25,
                )
            } else {
                let mut tcp_ok = false;
                let mut tcp_lat = 1;
                for port in [53, 80, 443, 8080] {
                    let addr = format!("{}:{}", gw_ip, port);
                    let start = Instant::now();
                    if let Ok(Ok(_)) = tokio::time::timeout(
                        Duration::from_millis(400),
                        tokio::net::TcpStream::connect(&addr),
                    )
                    .await
                    {
                        tcp_ok = true;
                        tcp_lat = start.elapsed().as_millis().max(1) as i32;
                        break;
                    }
                }
                if tcp_ok {
                    (
                        format!(
                            "{} ({} ms)",
                            i18n::tr4(
                                "Đã kết nối (TCP)",
                                "Connected (TCP)",
                                "已连接 (TCP)",
                                "Подключено (TCP)"
                            ),
                            tcp_lat
                        ),
                        25,
                    )
                } else {
                    (
                        i18n::tr4("Không phản hồi", "Unresponsive", "未响应", "Не отвечает")
                            .to_string(),
                        5,
                    )
                }
            }
        };

        let dns_check = async {
            let (local_test, cloudflare_test, google_test) = tokio::join!(
                Self::test_single_dns("127.0.0.1:53", "google.com"),
                Self::test_single_dns("1.1.1.1:53", "google.com"),
                Self::test_single_dns("8.8.8.8:53", "google.com"),
            );
            if local_test.is_some() || cloudflare_test.is_some() || google_test.is_some() {
                let ms = local_test.or(cloudflare_test).or(google_test).unwrap_or(1);
                (
                    format!(
                        "{} ({} ms)",
                        i18n::tr4(
                            "Hoạt động tốt",
                            "Operational",
                            "运行正常",
                            "Работает исправно",
                        ),
                        ms
                    ),
                    25,
                )
            } else {
                (
                    i18n::tr4(
                        "Lỗi phân giải",
                        "Resolution Failed",
                        "解析失败",
                        "Ошибка разрешения",
                    )
                    .to_string(),
                    0,
                )
            }
        };

        let net_check = async {
            let ping = Self::measure_fast_ping().await;
            if (0..150).contains(&ping) {
                (
                    format!(
                        "{} ({} ms)",
                        i18n::tr4("Thông suốt", "Online", "畅通", "В сети"),
                        ping
                    ),
                    30,
                )
            } else if ping >= 150 {
                (
                    format!(
                        "{} ({} ms)",
                        i18n::tr4("Chậm", "High Latency", "较慢", "Медленно"),
                        ping
                    ),
                    15,
                )
            } else {
                (
                    i18n::tr4(
                        "Mất kết nối Internet",
                        "No Internet",
                        "无网络",
                        "Нет интернета",
                    )
                    .to_string(),
                    0,
                )
            }
        };

        let stab_check = async {
            let ping = Self::run_ping("1.1.1.1", 3).await;
            if ping.loss_pct == 0 && ping.jitter_ms <= 15 {
                (
                    format!(
                        "{} (Loss: 0%, Jitter: {}ms)",
                        i18n::tr4("Rất cao", "Very High", "极高", "Очень высокая"),
                        ping.jitter_ms
                    ),
                    20,
                )
            } else if ping.loss_pct <= 10 {
                (
                    format!(
                        "{} (Loss: {}%, Jitter: {}ms)",
                        i18n::tr4("Khá", "Moderate", "良好", "Умеренная"),
                        ping.loss_pct,
                        ping.jitter_ms
                    ),
                    12,
                )
            } else {
                (
                    format!(
                        "{} (Loss: {}%)",
                        i18n::tr4("Kém", "Unstable", "不稳定", "Нестабильно"),
                        ping.loss_pct
                    ),
                    5,
                )
            }
        };

        let (
            (gw_status, gw_score),
            (dns_status, dns_score),
            (net_status, net_score),
            (stab_status, stab_score),
        ) = tokio::join!(gw_check, dns_check, net_check, stab_check);

        let total_score = (gw_score + dns_score + net_score + stab_score).clamp(0, 100);
        let overall_text = if total_score >= 85 {
            i18n::tr4(
                "Mạng hoạt động hoàn hảo, đường truyền ổn định và độ trễ thấp.",
                "Network is in optimal condition with low latency and high stability.",
                "网络运行完美，传输稳定且延迟低。",
                "Сеть работает идеально с низкой задержкой и высокой стабильностью.",
            )
        } else if total_score >= 60 {
            i18n::tr4(
                "Mạng khả dụng tốt, có thể có độ trễ nhẹ hoặc mất vài gói tin.",
                "Network is functional with minor latency or occasional packet drops.",
                "网络状态良好，可能存在轻微延迟或个别丢包。",
                "Сеть работоспособна, возможна небольшая задержка или потеря пакетов.",
            )
        } else {
            i18n::tr4(
                "Cảnh báo: Đường truyền mạng chập chờn hoặc mất kết nối Internet.",
                "Warning: Network connection is unstable or disconnected.",
                "警告：网络连接不稳定或已断开连接。",
                "Предупреждение: Соединение нестабильно или отсутствует интернет.",
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
