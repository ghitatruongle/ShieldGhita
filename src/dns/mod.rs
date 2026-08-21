use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

const BUILTIN_VIDEO_AUDIO_AD_DOMAINS: &[&str] = &[
    "s.youtube.com",
    "ad.youtube.com",
    "ads.youtube.com",
    "youtubei.googleapis.com",
    "video-stats.l.google.com",
    "pagead2.googlesyndication.com",
    "pagead2.googleadservices.com",
    "ade.googlesyndication.com",
    "googleads.g.doubleclick.net",
    "pubads.g.doubleclick.net",
    "securepubads.g.doubleclick.net",
    "static.doubleclick.net",
    "adclick.g.doubleclick.net",
    "adservice.google.com",
    "adservice.google.com.vn",
    "googleadservices.com",
    "googlesyndication.com",
    "doubleclick.net",
    "app-measurement.com",
    "spclient.wg.spotify.com",
    "audio-ak-spotify-com.akamaized.net",
    "heads4-ak-spotify-com.akamaized.net",
    "adstudio.spotify.com",
    "ads-fa.spotify.com",
    "crashdump.spotify.com",
    "ad.soundcloud.com",
    "ads.soundcloud.com",
    "promoted.soundcloud.com",
    "countess.twitch.tv",
    "ads.tiktok.com",
    "analytics.tiktok.com",
    "ib.tiktokv.com",
    "log.byteoversea.com",
    "mon.zijieapi.com",
    "an.facebook.com",
    "ads.facebook.com",
    "pixel.facebook.com",
    "tr.facebook.com",
    "ad.zadn.vn",
    "api.ad.zadn.vn",
    "tracking.zadn.vn",
    "qc.nct.vn",
    "media.zadn.vn",
    "adv.zing.vn",
    "fls-na.amazon.com",
    "aax-us-east.amazon-adsystem.com",
    "c.amazon-adsystem.com",
    "scorecardresearch.com",
    "adroll.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
];

pub struct DnsBlocker {
    blocked_domains: Arc<RwLock<HashSet<String>>>,
    allowed_domains: Arc<RwLock<HashSet<String>>>,
    custom_blocked: Arc<RwLock<HashSet<String>>>,
    custom_allowed: Arc<RwLock<HashSet<String>>>,
    dns_cache: Arc<RwLock<HashMap<String, (Vec<u8>, Instant)>>>,
    http_client: reqwest::Client,
    pub total_queries: Arc<AtomicU64>,
    pub blocked_count: Arc<AtomicU64>,
    pub silent_sinkhole_enabled: Arc<AtomicBool>,
    pub blocked_events_tx: tokio::sync::broadcast::Sender<(String, String)>,
}

impl DnsBlocker {
    pub fn new() -> Self {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(25)
            .pool_idle_timeout(Duration::from_secs(120));

        if let Ok(ip_cf) = "1.1.1.1:443".parse() {
            builder = builder
                .resolve("dns.cloudflare.com", ip_cf)
                .resolve("cloudflare-dns.com", ip_cf)
                .resolve("one.one.one.one", ip_cf);
        }
        if let Ok(ip_google) = "8.8.8.8:443".parse() {
            builder = builder
                .resolve("dns.google", ip_google)
                .resolve("dns.google.com", ip_google);
        }
        if let Ok(ip_quad9) = "9.9.9.9:443".parse() {
            builder = builder.resolve("dns.quad9.net", ip_quad9);
        }

        let client = builder.build().unwrap_or_else(|_| reqwest::Client::new());

        let mut initial_blocked = HashSet::new();
        for domain in BUILTIN_VIDEO_AUDIO_AD_DOMAINS {
            initial_blocked.insert(domain.to_string());
        }

        let (blocked_events_tx, _) = tokio::sync::broadcast::channel(256);

        Self {
            blocked_domains: Arc::new(RwLock::new(initial_blocked)),
            allowed_domains: Arc::new(RwLock::new(HashSet::new())),
            custom_blocked: Arc::new(RwLock::new(HashSet::new())),
            custom_allowed: Arc::new(RwLock::new(HashSet::new())),
            dns_cache: Arc::new(RwLock::new(HashMap::new())),
            http_client: client,
            total_queries: Arc::new(AtomicU64::new(0)),
            blocked_count: Arc::new(AtomicU64::new(0)),
            silent_sinkhole_enabled: Arc::new(AtomicBool::new(true)),
            blocked_events_tx,
        }
    }

    pub fn get_rules_count(&self) -> usize {
        let base = self.blocked_domains.read().map(|b| b.len()).unwrap_or(0);
        let custom = self.custom_blocked.read().map(|c| c.len()).unwrap_or(0);
        base + custom
    }

    fn cache_path() -> PathBuf {
        let d = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
        PathBuf::from(d).join("ShieldGhita").join("blocklist.cache")
    }

    pub fn load_cache(&self) -> Result<usize, String> {
        let p = Self::cache_path();
        if !p.exists() {
            return Err("no cache found".into());
        }
        let content = fs::read_to_string(&p).map_err(|e| e.to_string())?;
        let mut set: HashSet<String> = content
            .lines()
            .map(|l| l.trim().to_lowercase())
            .filter(|l| !l.is_empty())
            .collect();

        for domain in BUILTIN_VIDEO_AUDIO_AD_DOMAINS {
            set.insert(domain.to_string());
        }

        let count = set.len();
        if count == 0 {
            return Err("cache empty".into());
        }
        if let Ok(mut blocked) = self.blocked_domains.write() {
            *blocked = set;
        }
        info!("Loaded {} cached domains into blocker", count);
        Ok(count)
    }

    fn save_cache(&self) -> Result<(), String> {
        let p = Self::cache_path();
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let blocked = self.blocked_domains.read().map_err(|e| e.to_string())?;
        let list: Vec<&str> = blocked.iter().map(|s| s.as_str()).collect();
        fs::write(&p, list.join("\n")).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn parse_line(line: &str) -> Option<String> {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with('!') || l.starts_with('[') {
            return None;
        }
        if l.starts_with("||") {
            let d = l.trim_start_matches("||").trim_end_matches('^');
            let d = d.split('/').next().unwrap_or(d);
            let d = d.split('$').next().unwrap_or(d);
            let d = d.split('^').next().unwrap_or(d);
            if !d.is_empty() && !d.contains('*') {
                return Some(d.to_lowercase());
            }
            return None;
        }
        if l.starts_with('|') && l.ends_with('|') && l.len() > 2 {
            let d = &l[1..l.len() - 1];
            if !d.is_empty() && !d.contains('*') && !d.contains('/') {
                return Some(d.to_lowercase());
            }
            return None;
        }
        if let Some(pos) = l.find(|c: char| c.is_whitespace()) {
            let ip = &l[..pos];
            if ip == "0.0.0.0" || ip == "127.0.0.1" {
                let d = l[pos..]
                    .trim()
                    .split('#')
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .next()
                    .unwrap_or("");
                if !d.is_empty() && d != "localhost" && d != "broadcasthost" && d != "local" {
                    return Some(d.to_lowercase());
                }
            }
            return None;
        }
        if !l.contains(' ') && !l.contains('/') && !l.contains('*') && l.contains('.') {
            let d = l.split('#').next().unwrap_or(l).trim();
            if !d.is_empty() && d != "localhost" && d != "broadcasthost" {
                return Some(d.to_lowercase());
            }
        }
        None
    }

    pub async fn load_blocklists(&self, urls: &[String]) -> Result<usize, String> {
        let _ = self.load_cache();
        let mut set = HashSet::new();

        for domain in BUILTIN_VIDEO_AUDIO_AD_DOMAINS {
            set.insert(domain.to_string());
        }

        for url in urls {
            match self.http_client.get(url).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        if let Ok(text) = resp.text().await {
                            for line in text.lines() {
                                if let Some(d) = Self::parse_line(line) {
                                    set.insert(d);
                                }
                            }
                        }
                    } else {
                        warn!("HTTP {} for blocklist: {}", resp.status(), url);
                    }
                }
                Err(e) => warn!("Failed to fetch blocklist {}: {}", url, e),
            }
        }

        let count = set.len();
        if count > 0 {
            if let Ok(mut blocked) = self.blocked_domains.write() {
                *blocked = set;
            }
            let _ = self.save_cache();
            info!("Loaded {} unique domains into blocklist", count);
        }
        Ok(count)
    }

    pub fn set_custom_rules(&self, blocked: &[String], allowed: &[String]) {
        if let Ok(mut cb) = self.custom_blocked.write() {
            *cb = blocked
                .iter()
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(mut ca) = self.custom_allowed.write() {
            *ca = allowed
                .iter()
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }

    pub fn add_custom_domain(&self, domain: &str) -> Result<(), String> {
        let d = domain.trim().to_lowercase();
        if d.is_empty() {
            return Ok(());
        }
        let mut cb = self.custom_blocked.write().map_err(|e| e.to_string())?;
        cb.insert(d);
        Ok(())
    }

    pub fn remove_custom_domain(&self, domain: &str) -> Result<(), String> {
        let d = domain.trim().to_lowercase();
        let mut cb = self.custom_blocked.write().map_err(|e| e.to_string())?;
        cb.remove(&d);
        Ok(())
    }

    pub fn add_allowed_domain(&self, domain: &str) -> Result<(), String> {
        let d = domain.trim().to_lowercase();
        if d.is_empty() {
            return Ok(());
        }
        let mut ca = self.custom_allowed.write().map_err(|e| e.to_string())?;
        ca.insert(d);
        Ok(())
    }

    pub fn remove_allowed_domain(&self, domain: &str) -> Result<(), String> {
        let d = domain.trim().to_lowercase();
        let mut ca = self.custom_allowed.write().map_err(|e| e.to_string())?;
        ca.remove(&d);
        Ok(())
    }

    pub fn set_silent_sinkhole(&self, enabled: bool) {
        self.silent_sinkhole_enabled.store(enabled, Ordering::SeqCst);
    }

    pub fn is_silent_sinkhole(&self) -> bool {
        self.silent_sinkhole_enabled.load(Ordering::Relaxed)
    }

    pub fn should_block(&self, domain: &str) -> bool {
        let clean = domain.trim_end_matches('.').to_lowercase();
        if clean.is_empty() {
            return false;
        }

        {
            let ca = self.custom_allowed.read().unwrap();
            let ga = self.allowed_domains.read().unwrap();
            if Self::match_domain_hierarchy(&clean, &ca) || Self::match_domain_hierarchy(&clean, &ga) {
                return false;
            }
        }

        {
            let cb = self.custom_blocked.read().unwrap();
            if Self::match_domain_hierarchy(&clean, &cb) {
                return true;
            }
        }

        {
            let gb = self.blocked_domains.read().unwrap();
            if Self::match_domain_hierarchy(&clean, &gb) {
                return true;
            }
        }

        false
    }

    fn match_domain_hierarchy(domain: &str, set: &HashSet<String>) -> bool {
        if set.contains(domain) {
            return true;
        }
        let mut rest = domain;
        while let Some(dot_pos) = rest.find('.') {
            rest = &rest[dot_pos + 1..];
            if !rest.is_empty() && set.contains(rest) {
                return true;
            }
        }
        false
    }

    #[allow(dead_code)]
    pub fn blocked_count(&self) -> usize {
        let gb = self.blocked_domains.read().map(|d| d.len()).unwrap_or(0);
        let cb = self.custom_blocked.read().map(|d| d.len()).unwrap_or(0);
        gb + cb
    }

    pub fn parse_query_info(pkt: &[u8]) -> Option<(String, u16)> {
        if pkt.len() < 12 {
            return None;
        }
        let mut pos = 12;
        let mut labels = Vec::new();
        while pos < pkt.len() {
            let len = pkt[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1;
            if pos + len > pkt.len() {
                return None;
            }
            labels.push(std::str::from_utf8(&pkt[pos..pos + len]).ok()?.to_string());
            pos += len;
        }
        if labels.is_empty() || pos + 2 > pkt.len() {
            None
        } else {
            let qtype = ((pkt[pos] as u16) << 8) | (pkt[pos + 1] as u16);
            Some((labels.join("."), qtype))
        }
    }

    #[allow(dead_code)]
    pub fn parse_query_name(pkt: &[u8]) -> Option<String> {
        Self::parse_query_info(pkt).map(|(name, _)| name)
    }

    pub fn build_nxdomain(q: &[u8]) -> Option<Vec<u8>> {
        if q.len() < 12 {
            return None;
        }
        let mut r = q.to_vec();
        r[2] |= 0x80;
        r[3] = (r[3] & 0xF0) | 0x03;
        r[6..12].fill(0);
        Some(r)
    }

    pub fn build_sinkhole_a_record(q: &[u8], ip: [u8; 4]) -> Option<Vec<u8>> {
        if q.len() < 12 {
            return None;
        }
        let mut r = Vec::with_capacity(q.len() + 16);
        r.extend_from_slice(&q[0..2]);
        r.push(0x81);
        r.push(0x80);
        r.extend_from_slice(&q[4..6]);
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x00]);
        r.extend_from_slice(&[0x00, 0x00]);

        let mut pos = 12;
        while pos < q.len() {
            let len = q[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + len;
        }
        if pos + 4 > q.len() {
            return None;
        }
        pos += 4;
        r.extend_from_slice(&q[12..pos]);

        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x00, 0x00, 0x0A]);
        r.extend_from_slice(&[0x00, 0x04]);
        r.extend_from_slice(&ip);

        Some(r)
    }

    pub fn build_sinkhole_aaaa_record(q: &[u8], ip6: [u8; 16]) -> Option<Vec<u8>> {
        if q.len() < 12 {
            return None;
        }
        let mut r = Vec::with_capacity(q.len() + 28);
        r.extend_from_slice(&q[0..2]);
        r.push(0x81);
        r.push(0x80);
        r.extend_from_slice(&q[4..6]);
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x00]);
        r.extend_from_slice(&[0x00, 0x00]);

        let mut pos = 12;
        while pos < q.len() {
            let len = q[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + len;
        }
        if pos + 4 > q.len() {
            return None;
        }
        pos += 4;
        r.extend_from_slice(&q[12..pos]);

        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&[0x00, 0x1C]);
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x00, 0x00, 0x0A]);
        r.extend_from_slice(&[0x00, 0x10]);
        r.extend_from_slice(&ip6);

        Some(r)
    }

    pub fn build_servfail(q: &[u8]) -> Option<Vec<u8>> {
        if q.len() < 12 {
            return None;
        }
        let mut r = q.to_vec();
        r[2] |= 0x80;
        r[3] = (r[3] & 0xF0) | 0x02;
        r[6..12].fill(0);
        Some(r)
    }

    pub async fn run_dns_server(
        self: Arc<Self>,
        addr: &str,
        port: u16,
        doh_urls: Vec<String>,
        mon: Arc<crate::monitor::NetworkMonitor>,
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

        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    warn!("UDP recv error: {}", e);
                    continue;
                }
            };

            let packet = buf[..len].to_vec();
            let blocker = self.clone();
            let sock = socket.clone();
            let doh = doh_urls.clone();
            let monitor = mon.clone();

            tokio::spawn(async move {
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
        mon: Arc<crate::monitor::NetworkMonitor>,
    ) {
        let (query_name, qtype) = match Self::parse_query_info(&pkt) {
            Some(info) => info,
            None => return,
        };

        self.total_queries.fetch_add(1, Ordering::Relaxed);
        let src_ip = src.ip().to_string();

        if self.should_block(&query_name) {
            self.blocked_count.fetch_add(1, Ordering::Relaxed);
            mon.add_log(&query_name, &src_ip, true);

            let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
            let _ = self.blocked_events_tx.send((query_name.clone(), timestamp));

            let resp = if qtype == 1 {
                Self::build_sinkhole_a_record(&pkt, [0, 0, 0, 0])
                    .or_else(|| Self::build_nxdomain(&pkt))
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

        let cached_response = {
            let cache = self.dns_cache.read().unwrap();
            if let Some((cached_resp, instant)) = cache.get(&query_name) {
                if instant.elapsed() < Duration::from_secs(30) && cached_resp.len() >= 12 {
                    let mut resp = cached_resp.clone();
                    resp[0] = pkt[0];
                    resp[1] = pkt[1];
                    Some(resp)
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(resp) = cached_response {
            let _ = sock.send_to(&resp, src).await;
            return;
        }

        let fwd_resp = self.forward_parallel_racing(&pkt, &doh_urls).await;
        if let Some(resp) = fwd_resp {
            if let Ok(mut cache) = self.dns_cache.write() {
                if cache.len() > 3000 {
                    let now = Instant::now();
                    cache.retain(|_, (_, inst)| now.duration_since(*inst) < Duration::from_secs(60));
                    if cache.len() > 3000 {
                        cache.clear();
                    }
                }
                cache.insert(query_name, (resp.clone(), Instant::now()));
            }
            let _ = sock.send_to(&resp, src).await;
        } else if let Some(servfail) = Self::build_servfail(&pkt) {
            let _ = sock.send_to(&servfail, src).await;
        }
    }

    async fn forward_parallel_racing(&self, query_packet: &[u8], doh_urls: &[String]) -> Option<Vec<u8>> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);

        for url in doh_urls {
            let client = self.http_client.clone();
            let url = url.clone();
            let pkt = query_packet.to_vec();
            let tx_clone = tx.clone();

            tokio::spawn(async move {
                let res = tokio::time::timeout(
                    Duration::from_millis(800),
                    client
                        .post(&url)
                        .header("Content-Type", "application/dns-message")
                        .header("Accept", "application/dns-message")
                        .body(pkt)
                        .send(),
                )
                .await;

                if let Ok(Ok(resp)) = res {
                    if resp.status().is_success() {
                        if let Ok(bytes) = resp.bytes().await {
                            if bytes.len() >= 12 {
                                let _ = tx_clone.send(bytes.to_vec()).await;
                            }
                        }
                    }
                }
            });
        }

        let udp_resolvers = ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"];
        for resolver in udp_resolvers {
            let pkt = query_packet.to_vec();
            let tx_clone = tx.clone();

            tokio::spawn(async move {
                if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
                    if sock.send_to(&pkt, resolver).await.is_ok() {
                        let mut buf = [0u8; 4096];
                        if let Ok(Ok((len, _))) = tokio::time::timeout(
                            Duration::from_millis(800),
                            sock.recv_from(&mut buf),
                        )
                        .await
                        {
                            if len >= 12 {
                                let _ = tx_clone.send(buf[..len].to_vec()).await;
                            }
                        }
                    }
                }
            });
        }

        drop(tx);

        match tokio::time::timeout(Duration::from_millis(1200), rx.recv()).await {
            Ok(Some(resp)) => Some(resp),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line() {
        assert_eq!(
            DnsBlocker::parse_line("0.0.0.0 ads.example.com"),
            Some("ads.example.com".to_string())
        );
        assert_eq!(
            DnsBlocker::parse_line("127.0.0.1 tracker.telemetry.io # comment"),
            Some("tracker.telemetry.io".to_string())
        );
        assert_eq!(
            DnsBlocker::parse_line("||doubleclick.net^"),
            Some("doubleclick.net".to_string())
        );
        assert_eq!(
            DnsBlocker::parse_line("|badware.com|"),
            Some("badware.com".to_string())
        );
        assert_eq!(
            DnsBlocker::parse_line("malware.info"),
            Some("malware.info".to_string())
        );
        assert_eq!(DnsBlocker::parse_line("# this is a comment"), None);
        assert_eq!(DnsBlocker::parse_line("! ABP comment"), None);
        assert_eq!(DnsBlocker::parse_line("127.0.0.1 localhost"), None);
    }

    #[test]
    fn test_blocking_and_whitelist_precedence() {
        let blocker = DnsBlocker::new();
        let _ = blocker.add_custom_domain("ads.google.com");
        let _ = blocker.add_custom_domain("tracker.net");

        assert!(blocker.should_block("s.youtube.com"));
        assert!(blocker.should_block("ad.youtube.com"));
        assert!(blocker.should_block("spclient.wg.spotify.com"));
        assert!(blocker.should_block("ad.zadn.vn"));

        assert!(blocker.should_block("ads.google.com"));
        assert!(blocker.should_block("sub.tracker.net"));
        assert!(blocker.should_block("a.b.tracker.net"));

        assert!(!blocker.should_block("my-tracker.net"));
        assert!(!blocker.should_block("nottracker.net"));
        assert!(!blocker.should_block("google.com"));
        assert!(!blocker.should_block("github.com"));

        let _ = blocker.add_allowed_domain("ads.google.com");
        assert!(!blocker.should_block("ads.google.com"));
    }

    #[test]
    fn test_sinkhole_a_and_aaaa_record_builder() {
        let query_a = vec![
            0xAB, 0xCD,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x03, b'a', b'd', b's',
            0x06, b'g', b'o', b'o', b'g', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, 0x00, 0x01,
        ];

        let (name, qtype) = DnsBlocker::parse_query_info(&query_a).expect("Parse query info");
        assert_eq!(name, "ads.google.com");
        assert_eq!(qtype, 1);

        let sinkhole_a = DnsBlocker::build_sinkhole_a_record(&query_a, [0, 0, 0, 0])
            .expect("Build Sinkhole A record");
        assert_eq!(sinkhole_a[0], 0xAB);
        assert_eq!(sinkhole_a[1], 0xCD);
        assert_eq!(sinkhole_a[2], 0x81);
        assert_eq!(sinkhole_a[3], 0x80);
        let len_a = sinkhole_a.len();
        assert_eq!(&sinkhole_a[len_a - 4..len_a], &[0, 0, 0, 0]);

        let query_aaaa = vec![
            0xAB, 0xCD,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x03, b'a', b'd', b's',
            0x06, b'g', b'o', b'o', b'g', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x1C, 0x00, 0x01,
        ];

        let (_, qtype_aaaa) = DnsBlocker::parse_query_info(&query_aaaa).expect("Parse query info AAAA");
        assert_eq!(qtype_aaaa, 28);

        let sinkhole_aaaa = DnsBlocker::build_sinkhole_aaaa_record(&query_aaaa, [0u8; 16])
            .expect("Build Sinkhole AAAA record");
        let len_aaaa = sinkhole_aaaa.len();
        assert_eq!(&sinkhole_aaaa[len_aaaa - 16..len_aaaa], &[0u8; 16]);
    }
}
