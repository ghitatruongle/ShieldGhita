use super::*;

impl DnsBlocker {
    pub async fn run_dns_server(
        self: Arc<Self>,
        addr: &str,
        port: u16,
        doh_urls: Vec<String>,
        mon: Arc<crate::modules::monitor::NetworkMonitor>,
        ready_tx: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
    ) {
        let bind_addr = format!("{}:{}", addr, port);
        let socket = match UdpSocket::bind(&bind_addr).await {
            Ok(s) => {
                info!("Master DNS Proxy server running on UDP {}", bind_addr);
                if let Some(tx) = ready_tx {
                    let _ = tx.send(Ok(()));
                }
                Arc::new(s)
            }
            Err(e) => {
                let err_msg = format!("Cannot bind DNS server to {}: {}. Ensure app is run as Administrator and port 53 is not occupied.", bind_addr, e);
                error!("{}", err_msg);
                if let Some(tx) = ready_tx {
                    let _ = tx.send(Err(err_msg));
                }
                return;
            }
        };

        match tokio::net::TcpListener::bind(&bind_addr).await {
            Ok(listener) => {
                info!("Master DNS Proxy server running on TCP {}", bind_addr);
                let tcp_blocker = self.clone();
                let tcp_doh = doh_urls.clone();
                let tcp_mon = mon.clone();
                tokio::spawn(async move {
                    tcp_blocker.serve_tcp(listener, tcp_doh, tcp_mon).await;
                });
            }
            Err(e) => warn!(
                "DNS TCP listener unavailable on {}: {} — UDP keeps serving, but a client forced to retry a truncated answer (TC=1) will fail",
                bind_addr, e
            ),
        }

        let mut buf = [0u8; 4096];
        // Bound concurrent handlers so a LAN flood (network-wide mode binds
        // 0.0.0.0) cannot exhaust memory by spawning one task per datagram.
        let handler_sem = Arc::new(tokio::sync::Semaphore::new(256));

        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    log_recv_error(&e);
                    continue;
                }
            };

            let Ok(permit) = handler_sem.clone().try_acquire_owned() else {
                // Pool saturated — drop the packet rather than queue unbounded work.
                continue;
            };

            let packet = buf[..len].to_vec();
            let blocker = self.clone();
            let sock = socket.clone();
            let doh = doh_urls.clone();
            let monitor = mon.clone();

            tokio::spawn(async move {
                let _permit = permit;
                if let Some(resp) = blocker.build_response(packet, src, doh, monitor).await {
                    let _ = sock.send_to(&resp, src).await;
                }
            });
        }
    }

    async fn serve_tcp(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
        doh_urls: Vec<String>,
        mon: Arc<crate::modules::monitor::NetworkMonitor>,
    ) {
        let conn_sem = Arc::new(tokio::sync::Semaphore::new(64));
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    log_recv_error(&e);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
            };
            let Ok(permit) = conn_sem.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let blocker = self.clone();
            let doh = doh_urls.clone();
            let monitor = mon.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = blocker.handle_tcp_client(stream, peer, doh, monitor).await {
                    tracing::debug!("DNS TCP client {} finished: {}", peer, e);
                }
            });
        }
    }

    async fn handle_tcp_client(
        &self,
        mut stream: tokio::net::TcpStream,
        peer: SocketAddr,
        doh_urls: Vec<String>,
        mon: Arc<crate::modules::monitor::NetworkMonitor>,
    ) -> std::io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        const MAX_TCP_DNS_BYTES: usize = 4096;
        const TCP_IDLE: Duration = Duration::from_secs(10);

        loop {
            let mut len_buf = [0u8; 2];
            match tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(()),
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            if !(12..=MAX_TCP_DNS_BYTES).contains(&msg_len) {
                return Ok(());
            }
            let mut packet = vec![0u8; msg_len];
            match tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut packet)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(()),
            }

            let Some(resp) = self
                .build_response(packet, peer, doh_urls.clone(), mon.clone())
                .await
            else {
                continue;
            };
            if resp.len() > u16::MAX as usize {
                continue;
            }
            let mut framed = Vec::with_capacity(resp.len() + 2);
            framed.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            framed.extend_from_slice(&resp);
            match tokio::time::timeout(TCP_IDLE, stream.write_all(&framed)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(()),
            }
            let _ = tokio::time::timeout(TCP_IDLE, stream.flush()).await;
        }
    }

    async fn build_response(
        &self,
        pkt: Vec<u8>,
        src: SocketAddr,
        doh_urls: Vec<String>,
        mon: Arc<crate::modules::monitor::NetworkMonitor>,
    ) -> Option<Vec<u8>> {
        let (query_name, qtype) = match Self::parse_query_info(&pkt) {
            Some(info) => info,
            None => return None,
        };

        let src_ip = src.ip().to_string();

        if mon.security_engine.enforce_hard_rate_limit(&src_ip) {
            warn!(
                "Security Hard Rate Limit: dropping query burst from {}",
                src_ip
            );
            return None;
        }

        if mon.security_engine.is_ip_temporarily_blocked(&src_ip) {
            warn!(
                "Security IPS: Dropping query from blacklisted IP {}",
                src_ip
            );
            return None;
        }

        if mon.security_engine.is_quarantined(&src_ip) {
            warn!(
                "Quarantine Enforced: Dropping all DNS resolution for isolated device {}",
                src_ip
            );
            return Self::build_nxdomain(&pkt);
        }

        self.total_queries.fetch_add(1, Ordering::Relaxed);

        // Darknet pseudo-TLDs (.onion/.bit/.bazar): ALWAYS NXDOMAIN, even when
        // auto_block is off (and even when IDS detection is off) — these names
        // can never resolve via standard DNS, so fail-closed dropping is safe.
        // Policy documented on SecurityEngine::is_darknet_pseudo_tld.
        if crate::modules::security::SecurityEngine::must_nxdomain_darknet(&query_name) {
            let _ = mon.security_engine.inspect_dns_query(&src_ip, &query_name);
            mon.lan_scanner
                .record_activity(&src_ip, &query_name, true, true);
            self.blocked_count.fetch_add(1, Ordering::Relaxed);
            mon.add_log(&query_name, &src_ip, true);
            return Self::build_nxdomain(&pkt);
        }

        if let Some(_incident) = mon.security_engine.inspect_dns_query(&src_ip, &query_name) {
            mon.lan_scanner
                .record_activity(&src_ip, &query_name, true, true);
            if mon.security_engine.is_auto_block_enabled() {
                self.blocked_count.fetch_add(1, Ordering::Relaxed);
                mon.add_log(&query_name, &src_ip, true);
                return Self::build_nxdomain(&pkt);
            }
        }

        if let Some(over) = self.apply_response_policy(&src_ip, &query_name, qtype) {
            return if qtype == 1 {
                Self::build_sinkhole_a_record(&pkt, over.ipv4)
                    .or_else(|| Self::build_nxdomain(&pkt))
            } else if qtype == 28 {
                Self::build_sinkhole_aaaa_record(&pkt, over.ipv6)
                    .or_else(|| Self::build_nxdomain(&pkt))
            } else {
                Self::build_nxdomain(&pkt)
            };
        }

        // Strict mode never applies to this machine's own loopback traffic:
        // blocking every local query would look like a total network outage.
        let strict_applies = !src.ip().is_loopback();
        let ad_enforced = !self.adblock.is_paused()
            && match self.adblock.mode_for_client(&src.ip()) {
                ClientMode::Trusted => false,
                ClientMode::Strict => strict_applies,
                ClientMode::Default => self.should_block(&query_name),
            };
        if ad_enforced {
            self.adblock.record_block(&query_name, &src_ip);
            self.blocked_count.fetch_add(1, Ordering::Relaxed);
            mon.add_log(&query_name, &src_ip, true);
            mon.block_stats.record_block();

            let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
            let _ = self.blocked_events_tx.send((query_name.clone(), timestamp));

            return if qtype == 1 {
                if self.is_silent_sinkhole() {
                    Self::build_sinkhole_a_record(&pkt, [127, 0, 0, 1])
                        .or_else(|| Self::build_nxdomain(&pkt))
                } else {
                    Self::build_sinkhole_a_record(&pkt, [0, 0, 0, 0])
                        .or_else(|| Self::build_nxdomain(&pkt))
                }
            } else if qtype == 28 {
                Self::build_sinkhole_aaaa_record(&pkt, [0u8; 16])
                    .or_else(|| Self::build_nxdomain(&pkt))
            } else {
                Self::build_nxdomain(&pkt)
            };
        }

        mon.add_log(&query_name, &src_ip, false);

        if let Some(resp) = self.cached_response_for(&query_name, qtype, &pkt) {
            // A cached answer bypasses the fresh-response path below, so the
            // rebinding check must run here too or a poison (or pre-allowlist)
            // private answer could be served silently.
            if self.forwarded_answer_hits_private_space(&query_name, &resp) {
                warn!(
                    "DNS Rebinding (cached answer): domain '{}' private IP answer withheld for client {}",
                    query_name, src_ip
                );
                self.record_rebind_incident(&src_ip, &query_name, &mon);
                return Self::build_nxdomain(&pkt);
            }
            return Some(resp);
        }

        let fwd_resp = self.forward_parallel_racing(&pkt, &doh_urls).await;
        if let Some(mut resp) = fwd_resp {
            if self.forwarded_answer_hits_private_space(&query_name, &resp) {
                warn!(
                    "DNS Rebinding Attack detected: domain '{}' resolved to internal private IP space for client {}",
                    query_name, src_ip
                );
                self.record_rebind_incident(&src_ip, &query_name, &mon);
                if let Some(nx) = Self::build_nxdomain(&pkt) {
                    resp = nx;
                }
            } else {
                self.store_cache_response(&query_name, qtype, &resp);
            }
            return Some(resp);
        }

        Self::build_servfail(&pkt)
    }

    pub(super) fn forwarded_answer_hits_private_space(
        &self,
        query_name: &str,
        resp: &[u8],
    ) -> bool {
        if Self::is_legit_local_domain(query_name) {
            return false;
        }
        if !Self::is_private_ip_record(resp) {
            return false;
        }
        // Narrow custom allowlist exception: a domain (or parent of it) the
        // administrator explicitly allowlisted is trusted to answer with
        // private addresses (self-hosted services, LAN dashboards). The
        // default/global allowlist and every other protection stay intact —
        // all other public names keep the fail-closed rebinding block.
        let ca = self
            .custom_allowed
            .read()
            .unwrap_or_else(|e| e.into_inner());
        !Self::match_domain_hierarchy(&query_name.trim_end_matches('.').to_lowercase(), &ca)
    }

    /// One rebinding incident per (src_ip, domain) per cooldown window; the
    /// map is bounded by expiry-pruning plus a hard cap so a sustained attack
    /// from many (IP, domain) pairs cannot grow it without limit.
    pub(super) fn take_rebind_incident_slot(&self, src_ip: &str, query_name: &str) -> bool {
        let now = Instant::now();
        match self.rebind_incident_cooldown.lock() {
            Ok(mut cd) => {
                let key = (src_ip.to_string(), query_name.to_string());
                if let Some(last) = cd.get(&key) {
                    if now.duration_since(*last) < REBIND_INCIDENT_COOLDOWN {
                        return false;
                    }
                }
                if cd.len() >= MAX_REBIND_COOLDOWNS {
                    cd.retain(|_, t| now.duration_since(*t) < REBIND_INCIDENT_COOLDOWN);
                    if cd.len() >= MAX_REBIND_COOLDOWNS {
                        // Still saturated (flood of distinct pairs within one
                        // window): shed the oldest quarter instead of growing.
                        let mut oldest: Vec<((String, String), Instant)> =
                            cd.iter().map(|(k, v)| (k.clone(), *v)).collect();
                        oldest.sort_by_key(|(_, t)| *t);
                        let evict = cd.len() / 4;
                        for (k, _) in oldest.into_iter().take(evict) {
                            cd.remove(&k);
                        }
                    }
                }
                cd.insert(key, now);
                true
            }
            Err(_) => true,
        }
    }

    fn record_rebind_incident(
        &self,
        src_ip: &str,
        query_name: &str,
        mon: &crate::modules::monitor::NetworkMonitor,
    ) {
        if self.take_rebind_incident_slot(src_ip, query_name) {
            mon.security_engine.record_incident(
                crate::modules::i18n::tr(
                    "Tấn công DNS Rebinding (Private IP Leak)",
                    "DNS Rebinding Attack (Private IP Leak)",
                    "DNS 重绑定攻击 (Private IP Leak)",
                ),
                src_ip,
                &format!(
                    "{} '{}' {}",
                    crate::modules::i18n::tr("Tên miền công cộng", "Public domain", "公共域名"),
                    query_name,
                    crate::modules::i18n::tr(
                        "trả về địa chỉ IP nội bộ LAN (127.0.0.1 / 192.168.x / 10.x). Đã kích hoạt cơ chế tự vệ.",
                        "resolved to LAN private IP (127.0.0.1 / 192.168.x / 10.x). Self-defense triggered.",
                        "解析为局域网私有 IP (127.0.0.1 / 192.168.x / 10.x)。已触发防御机制。"
                    )
                ),
                "CRITICAL",
                crate::modules::i18n::tr(
                    "Đã chặn phân giải IP nội bộ giả mạo (Trả về NXDOMAIN)",
                    "Blocked forged internal IP answer (Returned NXDOMAIN)",
                    "已拦截伪造内网 IP 解析 (返回 NXDOMAIN)",
                ),
            );
        }
    }
}

#[cfg(test)]
mod tcp_transport_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_tcp_query_returns_length_prefixed_sinkhole() {
        let blocker = Arc::new(DnsBlocker::new());
        let sec = Arc::new(crate::modules::security::SecurityEngine::new());
        let mon = Arc::new(crate::modules::monitor::NetworkMonitor::new(50, sec));

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server_blocker = blocker.clone();
        let server_mon = mon.clone();
        let server_task = tokio::spawn(async move {
            server_blocker
                .run_dns_server(
                    "127.0.0.1",
                    15397,
                    vec!["https://1.1.1.1/dns-query".to_string()],
                    server_mon,
                    Some(ready_tx),
                )
                .await;
        });

        let bound = tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .expect("server startup timeout")
            .expect("ready channel closed");
        assert!(bound.is_ok(), "DNS test server failed to bind: {bound:?}");

        let query = DnsBlocker::build_a_query("s.youtube.com").expect("query builder");
        let mut stream = tokio::net::TcpStream::connect("127.0.0.1:15397")
            .await
            .expect("tcp connect");
        let mut request = Vec::new();
        request.extend_from_slice(&(query.len() as u16).to_be_bytes());
        request.extend_from_slice(&query);
        stream.write_all(&request).await.expect("tcp write");

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
            .await
            .expect("tcp read timeout")
            .expect("tcp read length");
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        assert!(resp_len > query.len(), "expected a sinkhole answer record");
        let mut resp = vec![0u8; resp_len];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut resp))
            .await
            .expect("tcp read timeout")
            .expect("tcp read body");

        assert_eq!(resp[0], query[0]);
        assert_eq!(resp[1], query[1]);
        assert_eq!(resp[2] & 0x80, 0x80, "QR bit must be set");
        let answer_ip = &resp[resp_len - 4..];
        assert!(
            answer_ip == [0, 0, 0, 0] || answer_ip == [127, 0, 0, 1],
            "unexpected sinkhole address: {answer_ip:?}"
        );

        server_task.abort();
    }
}
