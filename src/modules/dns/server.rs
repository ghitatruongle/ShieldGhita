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
                blocker
                    .handle_dns_packet(packet, src, sock, doh, monitor)
                    .await;
            });
        }
    }

    async fn handle_dns_packet(
        &self,
        pkt: Vec<u8>,
        src: SocketAddr,
        sock: Arc<UdpSocket>,
        doh_urls: Vec<String>,
        mon: Arc<crate::modules::monitor::NetworkMonitor>,
    ) {
        let (query_name, qtype) = match Self::parse_query_info(&pkt) {
            Some(info) => info,
            None => return,
        };

        let src_ip = src.ip().to_string();

        if mon.security_engine.enforce_hard_rate_limit(&src_ip) {
            warn!(
                "Security Hard Rate Limit: dropping query burst from {}",
                src_ip
            );
            return;
        }

        if mon.security_engine.is_ip_temporarily_blocked(&src_ip) {
            warn!(
                "Security IPS: Dropping query from blacklisted IP {}",
                src_ip
            );
            return;
        }

        if mon.security_engine.is_quarantined(&src_ip) {
            warn!(
                "Quarantine Enforced: Dropping all DNS resolution for isolated device {}",
                src_ip
            );
            if let Some(r) = Self::build_nxdomain(&pkt) {
                let _ = sock.send_to(&r, src).await;
            }
            return;
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
            if let Some(r) = Self::build_nxdomain(&pkt) {
                let _ = sock.send_to(&r, src).await;
            }
            return;
        }

        if let Some(_incident) = mon.security_engine.inspect_dns_query(&src_ip, &query_name) {
            mon.lan_scanner
                .record_activity(&src_ip, &query_name, true, true);
            if mon.security_engine.is_auto_block_enabled() {
                self.blocked_count.fetch_add(1, Ordering::Relaxed);
                mon.add_log(&query_name, &src_ip, true);
                if let Some(r) = Self::build_nxdomain(&pkt) {
                    let _ = sock.send_to(&r, src).await;
                }
                return;
            }
        }

        if let Some(over) = self.apply_response_policy(&src_ip, &query_name, qtype) {
            let resp = if qtype == 1 {
                Self::build_sinkhole_a_record(&pkt, over.ipv4)
                    .or_else(|| Self::build_nxdomain(&pkt))
            } else if qtype == 28 {
                Self::build_sinkhole_aaaa_record(&pkt, over.ipv6)
                    .or_else(|| Self::build_nxdomain(&pkt))
            } else {
                Self::build_nxdomain(&pkt)
            };
            if let Some(r) = resp {
                let _ = sock.send_to(&r, src).await;
            }
            return;
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

            let resp = if qtype == 1 {
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

            if let Some(r) = resp {
                let _ = sock.send_to(&r, src).await;
            }
            return;
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
                if let Some(nx) = Self::build_nxdomain(&pkt) {
                    let _ = sock.send_to(&nx, src).await;
                }
                return;
            }
            let _ = sock.send_to(&resp, src).await;
            return;
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
            let _ = sock.send_to(&resp, src).await;
        } else if let Some(servfail) = Self::build_servfail(&pkt) {
            let _ = sock.send_to(&servfail, src).await;
        }
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
