use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
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
    "media.zadn.vn",
    "sdk.e.zadn.vn",
    "zalo-analytics.zadn.vn",
    "qc.nct.vn",
    "ad.nct.vn",
    "adv.zing.vn",
    "adt.zing.vn",
    "qc.coccoc.com",
    "adserver.coccoc.com",
    "dsp.coccoc.com",
    "tracking.shopee.vn",
    "criteo.shopee.vn",
    "fls-na.amazon.com",
    "aax-us-east.amazon-adsystem.com",
    "c.amazon-adsystem.com",
    "scorecardresearch.com",
    "adroll.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    "telemetry.microsoft.com",
    "vortex.data.microsoft.com",
    "watson.telemetry.microsoft.com",
];

pub type DnsCacheMap = Arc<RwLock<HashMap<(String, u16), (Vec<u8>, Instant, u32)>>>;

pub struct DnsBlocker {
    blocked_domains: Arc<RwLock<HashSet<String>>>,
    allowed_domains: Arc<RwLock<HashSet<String>>>,
    custom_blocked: Arc<RwLock<HashSet<String>>>,
    custom_allowed: Arc<RwLock<HashSet<String>>>,
    dns_cache: DnsCacheMap,
    http_client: reqwest::Client,
    etag_cache: Arc<Mutex<HashMap<String, String>>>,
    pub total_queries: Arc<AtomicU64>,
    pub blocked_count: Arc<AtomicU64>,
    pub silent_sinkhole_enabled: Arc<AtomicBool>,
    pub blocked_events_tx: tokio::sync::broadcast::Sender<(String, String)>,
    response_policy: Arc<RwLock<Option<ResponsePolicyFn>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseOverride {
    pub ipv4: [u8; 4],
    pub ipv6: [u8; 16],
}

pub type ResponsePolicyFn = Arc<dyn Fn(&str, &str, u16) -> Option<ResponseOverride> + Send + Sync>;

/// Outcome of one blocklist source fetch: (url, body-if-fetched, etag).
type BlocklistFetch = Result<(String, Option<String>, Option<String>), String>;

impl DnsBlocker {
    #[cfg_attr(not(feature = "admin"), allow(dead_code))]
    pub fn set_response_policy(&self, policy: ResponsePolicyFn) {
        if let Ok(mut guard) = self.response_policy.write() {
            *guard = Some(policy);
        }
    }

    fn apply_response_policy(
        &self,
        src_ip: &str,
        name: &str,
        qtype: u16,
    ) -> Option<ResponseOverride> {
        let guard = self.response_policy.read().ok()?;
        let policy = guard.as_ref()?;
        policy(src_ip, name, qtype)
    }
}

const BLOCKED_PUBLIC_SUFFIXES: &[&str] = &[
    "com.vn",
    "net.vn",
    "org.vn",
    "edu.vn",
    "gov.vn",
    "ac.vn",
    "co.uk",
    "org.uk",
    "com.au",
    "net.au",
    "co.jp",
    "com.cn",
    "com.br",
    "co.in",
    "com.mx",
    "github.io",
    "gitlab.io",
    "pages.dev",
    "vercel.app",
    "netlify.app",
];

impl DnsBlocker {
    pub fn validate_domain(domain: &str) -> Result<String, String> {
        use crate::modules::i18n;
        let d = domain.trim().trim_end_matches('.').to_lowercase();
        if d.is_empty() {
            return Err(i18n::tr("Tên miền trống", "Domain is empty", "域名为空").into());
        }
        if d.len() > 253 {
            return Err(i18n::tr(
                "Tên miền dài quá 253 ký tự",
                "Domain exceeds 253 characters",
                "域名超过 253 个字符",
            )
            .into());
        }
        if !d.contains('.') {
            let msg = match i18n::current_index() {
                i18n::EN => format!(
                    "'{}' is missing a dot — blocking a whole TLD would break all browsers",
                    d
                ),
                i18n::ZH => format!(
                    "'{}' 缺少点号 — 屏蔽整个顶级域名会导致所有浏览器无法上网",
                    d
                ),
                _ => format!(
                    "'{}' thiếu dấu chấm — chặn cả TLD sẽ làm gãy toàn bộ trình duyệt",
                    d
                ),
            };
            return Err(msg);
        }
        if BLOCKED_PUBLIC_SUFFIXES.contains(&d.as_str()) {
            let msg = match i18n::current_index() {
                i18n::EN => format!("'{}' is a public suffix — block scope too broad", d),
                i18n::ZH => format!("'{}' 属于公共后缀 — 屏蔽范围过宽", d),
                _ => format!("'{}' là public suffix — phạm vi chặn quá rộng", d),
            };
            return Err(msg);
        }
        for label in d.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(i18n::tr(
                    "Label không hợp lệ (rỗng hoặc dài hơn 63 ký tự)",
                    "Invalid label (empty or longer than 63 characters)",
                    "标签无效（为空或超过 63 个字符）",
                )
                .into());
            }
            if label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                continue;
            }
            return Err(i18n::tr(
                "Tên miền chứa ký tự không hợp lệ",
                "Domain contains invalid characters",
                "域名包含无效字符",
            )
            .into());
        }
        Ok(d)
    }

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
            etag_cache: Arc::new(Mutex::new(Self::read_etag_map_from(
                &Self::etag_store_path(),
            ))),
            total_queries: Arc::new(AtomicU64::new(0)),
            blocked_count: Arc::new(AtomicU64::new(0)),
            silent_sinkhole_enabled: Arc::new(AtomicBool::new(true)),
            blocked_events_tx,
            response_policy: Arc::new(RwLock::new(None)),
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

    fn etag_store_path() -> PathBuf {
        let d = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
        PathBuf::from(d)
            .join("ShieldGhita")
            .join("blocklist_etags.json")
    }

    fn read_etag_map_from(path: &Path) -> HashMap<String, String> {
        fs::read_to_string(path)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default()
    }

    fn write_etag_map_to(path: &Path, map: &HashMap<String, String>) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string(map) {
            let _ = fs::write(path, json);
        }
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
        let fetch_start = Instant::now();
        let _ = self.load_cache();
        let mut set: tokio::task::JoinSet<BlocklistFetch> = tokio::task::JoinSet::new();

        for url in urls {
            let client = self.http_client.clone();
            let url = url.clone();
            let etag = self
                .etag_cache
                .lock()
                .map(|g| g.get(&url).cloned())
                .unwrap_or(None);
            set.spawn(async move {
                let mut req = client.get(&url);
                if let Some(tag) = &etag {
                    req = req.header("If-None-Match", tag);
                }
                match req.send().await {
                    Ok(resp) => {
                        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
                            return Ok((url, None, None));
                        }
                        if resp.status().is_success() {
                            let etag = resp
                                .headers()
                                .get("ETag")
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string());
                            let text = resp.text().await.map_err(|e| format!("{}: {}", url, e))?;
                            Ok((url, Some(text), etag))
                        } else {
                            Err(format!("{}: HTTP {}", url, resp.status()))
                        }
                    }
                    Err(e) => Err(format!("{}: {}", url, e)),
                }
            });
        }

        let mut domains = HashSet::new();
        for domain in BUILTIN_VIDEO_AUDIO_AD_DOMAINS {
            domains.insert(domain.to_string());
        }

        let mut any_success = false;
        let mut unchanged = 0usize;
        let mut fetched = 0usize;
        let mut new_etags: HashMap<String, String> = self
            .etag_cache
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();

        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok((url, None, _))) => {
                    unchanged += 1;
                    let _ = url;
                }
                Ok(Ok((url, Some(text), etag))) => {
                    any_success = true;
                    fetched += 1;
                    if let Some(tag) = etag {
                        new_etags.insert(url, tag);
                    }
                    for line in text.lines() {
                        if let Some(d) = Self::parse_line(line) {
                            domains.insert(d);
                        }
                    }
                }
                Ok(Err(e)) => warn!("Failed to fetch blocklist: {}", e),
                Err(e) => warn!("Blocklist fetch task failed: {}", e),
            }
        }

        // Keep ETags only for URLs that answered this round; a failed or new URL
        // must be fully re-fetched next time instead of trusting a stale tag.
        if unchanged + fetched == urls.len() {
            new_etags.retain(|u, _| urls.iter().any(|x| x == u));
            *self.etag_cache.lock().unwrap_or_else(|e| e.into_inner()) = new_etags.clone();
            Self::write_etag_map_to(&Self::etag_store_path(), &new_etags);
        }

        if unchanged > 0 && fetched == 0 && !any_success && unchanged == urls.len() {
            // Every source answered HTTP 304 — the on-disk cache is already current.
            let count = self.blocked_domains.read().map(|b| b.len()).unwrap_or(0);
            if count > 0 {
                info!(
                    "Blocklists unchanged (ETag {} hits in {} ms): {} rules stay active",
                    unchanged,
                    fetch_start.elapsed().as_millis(),
                    count
                );
                return Ok(count);
            }
        }

        let count = domains.len();
        if count > 0 && any_success {
            if let Ok(mut blocked) = self.blocked_domains.write() {
                *blocked = domains;
            }
            let _ = self.save_cache();
            info!(
                "Loaded {} unique domains into blocklist in {} ms",
                count,
                fetch_start.elapsed().as_millis()
            );
        }
        Ok(count)
    }

    pub fn set_custom_rules(&self, blocked: &[String], allowed: &[String]) {
        if let Ok(mut cb) = self.custom_blocked.write() {
            *cb = blocked
                .iter()
                .filter_map(|s| Self::validate_domain(s).ok())
                .collect();
        }
        if let Ok(mut ca) = self.custom_allowed.write() {
            *ca = allowed
                .iter()
                .filter_map(|s| Self::validate_domain(s).ok())
                .collect();
        }
    }

    pub fn add_custom_domain(&self, domain: &str) -> Result<(), String> {
        let d = Self::validate_domain(domain)?;
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
        let d = Self::validate_domain(domain)?;
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
        self.silent_sinkhole_enabled
            .store(enabled, Ordering::SeqCst);
    }

    pub fn is_silent_sinkhole(&self) -> bool {
        self.silent_sinkhole_enabled.load(Ordering::Relaxed)
    }

    pub fn should_block(&self, domain: &str) -> bool {
        let trimmed = domain.trim_end_matches('.');
        if trimmed.is_empty() {
            return false;
        }
        let clean = if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
            std::borrow::Cow::Owned(trimmed.to_lowercase())
        } else {
            std::borrow::Cow::Borrowed(trimmed)
        };

        {
            let ca = self
                .custom_allowed
                .read()
                .unwrap_or_else(|e| e.into_inner());
            let ga = self
                .allowed_domains
                .read()
                .unwrap_or_else(|e| e.into_inner());
            if Self::match_domain_hierarchy(&clean, &ca)
                || Self::match_domain_hierarchy(&clean, &ga)
            {
                return false;
            }
        }

        {
            let cb = self
                .custom_blocked
                .read()
                .unwrap_or_else(|e| e.into_inner());
            if Self::match_domain_hierarchy(&clean, &cb) {
                return true;
            }
        }

        {
            let gb = self
                .blocked_domains
                .read()
                .unwrap_or_else(|e| e.into_inner());
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
        let mut loop_count = 0;
        while pos < pkt.len() {
            loop_count += 1;
            if loop_count > 128 {
                return None;
            }
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

    pub fn response_matches_query(resp: &[u8], query: &[u8]) -> bool {
        if resp.len() < 12 || query.len() < 12 {
            return false;
        }
        if resp[0] != query[0] || resp[1] != query[1] {
            return false;
        }
        if resp[2] & 0x80 == 0 {
            return false;
        }
        match (Self::parse_query_info(query), Self::parse_query_info(resp)) {
            (Some((q_name, q_type)), Some((r_name, r_type))) => {
                r_name == q_name && r_type == q_type
            }
            _ => false,
        }
    }

    pub fn extract_min_ttl(resp: &[u8]) -> Option<u32> {
        if resp.len() < 12 {
            return None;
        }
        let an_count = u16::from_be_bytes([resp[6], resp[7]]);
        if an_count == 0 {
            return None;
        }
        let mut pos = 12;
        let mut guard = 0;
        while pos < resp.len() {
            guard += 1;
            if guard > 128 {
                return None;
            }
            let len_byte = resp[pos];
            if len_byte & 0xC0 == 0xC0 {
                pos += 2;
                break;
            } else if len_byte == 0 {
                pos += 1;
                break;
            } else {
                pos += 1 + len_byte as usize;
            }
        }
        pos += 4;
        let mut min_ttl = u32::MAX;
        for _ in 0..an_count {
            guard += 1;
            if guard > 256 {
                break;
            }
            if pos >= resp.len() {
                break;
            }
            if resp[pos] & 0xC0 == 0xC0 {
                pos += 2;
            } else {
                let mut label_guard = 0;
                while pos < resp.len() {
                    label_guard += 1;
                    if label_guard > 128 {
                        return None;
                    }
                    let l = resp[pos];
                    if l == 0 {
                        pos += 1;
                        break;
                    }
                    pos += 1 + l as usize;
                }
            }
            if pos + 10 > resp.len() {
                break;
            }
            let ttl =
                u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
            min_ttl = min_ttl.min(ttl);
            let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
            pos += 10 + rdlength;
        }
        if min_ttl == u32::MAX {
            None
        } else {
            Some(min_ttl)
        }
    }

    fn cache_ttl_seconds(resp: &[u8]) -> u64 {
        let ttl = Self::extract_min_ttl(resp).unwrap_or(10);
        ttl.clamp(1, 60) as u64
    }

    pub fn cached_response_for(&self, name: &str, qtype: u16, pkt: &[u8]) -> Option<Vec<u8>> {
        let cache = self.dns_cache.read().unwrap_or_else(|e| e.into_inner());
        let (cached_resp, inserted, ttl) = cache.get(&(name.to_string(), qtype))?;
        if inserted.elapsed() < Duration::from_secs(*ttl as u64) && cached_resp.len() >= 12 {
            let mut resp = cached_resp.clone();
            resp[0] = pkt[0];
            resp[1] = pkt[1];
            Some(resp)
        } else {
            None
        }
    }

    pub fn store_cache_response(&self, name: &str, qtype: u16, resp: &[u8]) {
        if let Ok(mut cache) = self.dns_cache.write() {
            if cache.len() > 5000 {
                let now = Instant::now();
                cache.retain(|_, (_, inserted, ttl)| {
                    now.duration_since(*inserted) < Duration::from_secs((*ttl as u64).max(1))
                });
                if cache.len() > 5000 {
                    let mut entries: Vec<((String, u16), Instant)> = cache
                        .iter()
                        .map(|(k, (_, inserted, _))| (k.clone(), *inserted))
                        .collect();
                    entries.sort_by_key(|(_, inserted)| *inserted);
                    let excess = cache.len().saturating_sub(4000);
                    for (key, _) in entries.into_iter().take(excess) {
                        cache.remove(&key);
                    }
                }
            }
            let ttl = Self::cache_ttl_seconds(resp) as u32;
            cache.insert(
                (name.to_string(), qtype),
                (resp.to_vec(), Instant::now(), ttl),
            );
        }
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
        let mut loop_count = 0;
        while pos < q.len() {
            loop_count += 1;
            if loop_count > 128 {
                return None;
            }
            let len = q[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            if pos + 1 + len > q.len() {
                return None;
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
        let mut loop_count = 0;
        while pos < q.len() {
            loop_count += 1;
            if loop_count > 128 {
                return None;
            }
            let len = q[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            if pos + 1 + len > q.len() {
                return None;
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

        self.total_queries.fetch_add(1, Ordering::Relaxed);

        if let Some(over) = self.apply_response_policy(&src_ip, &query_name, qtype) {
            let resp = if qtype == 28 {
                Self::build_sinkhole_aaaa_record(&pkt, over.ipv6)
                    .or_else(|| Self::build_nxdomain(&pkt))
            } else {
                Self::build_sinkhole_a_record(&pkt, over.ipv4)
                    .or_else(|| Self::build_nxdomain(&pkt))
            };
            if let Some(r) = resp {
                let _ = sock.send_to(&r, src).await;
            }
            return;
        }

        if self.should_block(&query_name) {
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
            let _ = sock.send_to(&resp, src).await;
            return;
        }

        let fwd_resp = self.forward_parallel_racing(&pkt, &doh_urls).await;
        if let Some(resp) = fwd_resp {
            self.store_cache_response(&query_name, qtype, &resp);
            let _ = sock.send_to(&resp, src).await;
        } else if let Some(servfail) = Self::build_servfail(&pkt) {
            let _ = sock.send_to(&servfail, src).await;
        }
    }

    async fn forward_parallel_racing(
        &self,
        query_packet: &[u8],
        doh_urls: &[String],
    ) -> Option<Vec<u8>> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);

        for url in doh_urls.iter().take(2) {
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
                        .body(pkt.clone())
                        .send(),
                )
                .await;

                if let Ok(Ok(resp)) = res {
                    if resp.status().is_success() {
                        if let Ok(bytes) = resp.bytes().await {
                            if Self::response_matches_query(&bytes, &pkt) {
                                let _ = tx_clone.send(bytes.to_vec()).await;
                            }
                        }
                    }
                }
            });
        }

        {
            let pkt = query_packet.to_vec();
            let tx_clone = tx.clone();

            tokio::spawn(async move {
                let sock = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                if sock.connect("1.1.1.1:53").await.is_err() {
                    return;
                }
                if sock.send(&pkt).await.is_ok() {
                    let mut buf = [0u8; 4096];
                    if let Ok(Ok(len)) =
                        tokio::time::timeout(Duration::from_millis(800), sock.recv(&mut buf)).await
                    {
                        if Self::response_matches_query(&buf[..len], &pkt) {
                            let _ = tx_clone.send(buf[..len].to_vec()).await;
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
    fn test_etag_map_roundtrip_and_corruption_fallback() {
        let dir = std::env::temp_dir().join(format!("sg_etag_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("etags.json");

        let mut map = HashMap::new();
        map.insert("https://a.example/hosts".to_string(), "\"v1\"".to_string());
        DnsBlocker::write_etag_map_to(&path, &map);
        let loaded = DnsBlocker::read_etag_map_from(&path);
        assert_eq!(
            loaded.get("https://a.example/hosts").map(String::as_str),
            Some("\"v1\"")
        );

        std::fs::write(&path, "not json at all").unwrap();
        assert!(
            DnsBlocker::read_etag_map_from(&path).is_empty(),
            "corrupt etag store must fall back to empty"
        );

        let _ = fs::remove_dir_all(&dir);
    }

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
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
            b'd', b's', 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
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
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
            b'd', b's', 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x1C, 0x00, 0x01,
        ];

        let (_, qtype_aaaa) =
            DnsBlocker::parse_query_info(&query_aaaa).expect("Parse query info AAAA");
        assert_eq!(qtype_aaaa, 28);

        let sinkhole_aaaa = DnsBlocker::build_sinkhole_aaaa_record(&query_aaaa, [0u8; 16])
            .expect("Build Sinkhole AAAA record");
        let len_aaaa = sinkhole_aaaa.len();
        assert_eq!(&sinkhole_aaaa[len_aaaa - 16..len_aaaa], &[0u8; 16]);
    }

    #[test]
    fn test_response_policy_override_applied_per_source() {
        use std::sync::Arc;

        let blocker = DnsBlocker::new();
        assert!(blocker
            .apply_response_policy("192.0.2.50", "example.com", 1)
            .is_none());

        blocker.set_response_policy(Arc::new(|src_ip, _name, _qtype| {
            if src_ip == "192.0.2.50" {
                Some(crate::modules::dns::ResponseOverride {
                    ipv4: [192, 0, 2, 10],
                    ipv6: [0u8; 16],
                })
            } else {
                None
            }
        }));

        let over = blocker
            .apply_response_policy("192.0.2.50", "any.site", 28)
            .expect("policy must fire for targeted source");
        assert_eq!(over.ipv4, [192, 0, 2, 10]);
        assert_eq!(over.ipv6, [0u8; 16]);
        assert!(blocker
            .apply_response_policy("192.0.2.99", "any.site", 1)
            .is_none());

        let query = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let redirected = DnsBlocker::build_sinkhole_a_record(&query, over.ipv4)
            .expect("Build redirect A record");
        let len_r = redirected.len();
        assert_eq!(&redirected[len_r - 4..len_r], &[192, 0, 2, 10]);
    }

    #[tokio::test]
    async fn test_dns_server_applies_response_policy_live() {
        use std::sync::Arc;

        let blocker = Arc::new(DnsBlocker::new());
        blocker.set_response_policy(Arc::new(|src_ip, _name, _qtype| {
            if src_ip == "127.0.0.1" {
                Some(crate::modules::dns::ResponseOverride {
                    ipv4: [192, 0, 2, 123],
                    ipv6: [0u8; 16],
                })
            } else {
                None
            }
        }));

        let sec = Arc::new(crate::modules::security::SecurityEngine::new());
        let mon = Arc::new(crate::modules::monitor::NetworkMonitor::new(50, sec));

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server_blocker = blocker.clone();
        let server_mon = mon.clone();
        let server_task = tokio::spawn(async move {
            server_blocker
                .run_dns_server(
                    "127.0.0.1",
                    15395,
                    vec!["https://1.1.1.1/dns-query".to_string()],
                    server_mon,
                    Some(ready_tx),
                )
                .await;
        });

        let bound = tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx)
            .await
            .expect("server startup timeout")
            .expect("ready channel closed");
        assert!(bound.is_ok(), "DNS test server failed to bind: {:?}", bound);

        let query = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, b'r',
            b'e', b'd', b'i', b'r', b'e', b'c', b't', 0x04, b't', b'e', b's', b't', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("client bind");
        sock.send_to(&query, "127.0.0.1:15395").await.expect("send");

        let mut buf = vec![0u8; 512];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(3), sock.recv_from(&mut buf))
                .await
                .expect("response timeout")
                .expect("recv response");

        assert_eq!(&buf[len - 4..len], &[192, 0, 2, 123]);
        assert_eq!(buf[0], 0xAB);
        server_task.abort();
    }

    #[test]
    fn test_validate_domain() {
        assert!(DnsBlocker::validate_domain("ads.example.com").is_ok());
        assert_eq!(
            DnsBlocker::validate_domain("  Tracker.NET.  ").unwrap(),
            "tracker.net"
        );
        assert!(DnsBlocker::validate_domain("").is_err());
        assert!(DnsBlocker::validate_domain("com").is_err());
        assert!(DnsBlocker::validate_domain("com.vn").is_err());
        assert!(DnsBlocker::validate_domain("netlify.app").is_err());
        assert!(DnsBlocker::validate_domain("a..b").is_err());
        assert!(DnsBlocker::validate_domain("bad domain.com").is_err());
        assert!(DnsBlocker::validate_domain(&"x".repeat(300)).is_err());
    }

    #[test]
    fn test_add_custom_domain_rejects_invalid() {
        let blocker = DnsBlocker::new();
        assert!(blocker.add_custom_domain("com").is_err());
        assert!(blocker.add_custom_domain("").is_err());
        assert!(blocker.add_allowed_domain("com.vn").is_err());
        assert!(blocker.add_custom_domain("ads.example.com").is_ok());
    }

    #[test]
    fn test_set_custom_rules_filters_invalid_entries() {
        let blocker = DnsBlocker::new();
        let blocked = vec![
            "ads.example.com".to_string(),
            "com".to_string(),
            "tracker.test".to_string(),
        ];
        let allowed = vec!["ok.example.com".to_string(), "com.vn".to_string()];
        blocker.set_custom_rules(&blocked, &allowed);

        assert!(blocker.should_block("ads.example.com"));
        assert!(blocker.should_block("sub.tracker.test"));
        assert!(
            !blocker.should_block("anything.com"),
            "bare TLD 'com' must never be accepted from persisted config"
        );
        assert!(
            !blocker.should_block("site.com.vn"),
            "public suffix must never be accepted into whitelist"
        );
    }

    #[test]
    fn test_response_matches_query() {
        let query_a = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
            b'd', b's', 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        let query_aaaa = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
            b'd', b's', 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x1C, 0x00, 0x01,
        ];

        let resp = DnsBlocker::build_sinkhole_a_record(&query_a, [0, 0, 0, 0]).unwrap();
        assert!(DnsBlocker::response_matches_query(&resp, &query_a));

        let mut wrong_id = resp.clone();
        wrong_id[0] = 0xFF;
        assert!(!DnsBlocker::response_matches_query(&wrong_id, &query_a));

        assert!(!DnsBlocker::response_matches_query(&resp, &query_aaaa));

        assert!(!DnsBlocker::response_matches_query(&query_a, &query_a));
    }

    #[test]
    fn test_extract_min_ttl() {
        let query_a = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
            b'd', b's', 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        let resp = DnsBlocker::build_sinkhole_a_record(&query_a, [0, 0, 0, 0]).unwrap();
        assert_eq!(DnsBlocker::extract_min_ttl(&resp), Some(10));
        assert_eq!(DnsBlocker::extract_min_ttl(&query_a), None);
    }

    #[test]
    fn test_cache_keyed_by_qtype_and_ttl() {
        let blocker = DnsBlocker::new();
        let query_a = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
            b'd', b's', 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];
        let resp = DnsBlocker::build_sinkhole_a_record(&query_a, [0, 0, 0, 0]).unwrap();

        blocker.store_cache_response("ads.google.com", 1, &resp);

        let cached_a = blocker
            .cached_response_for("ads.google.com", 1, &query_a)
            .expect("A record must be cached under qtype 1");
        assert_eq!(cached_a[0], 0xAB);
        assert_eq!(cached_a[1], 0xCD);

        assert!(blocker
            .cached_response_for("ads.google.com", 28, &query_a)
            .is_none());

        let expired = Instant::now()
            .checked_sub(Duration::from_secs(61))
            .expect("checked_sub on Windows");
        blocker
            .dns_cache
            .write()
            .unwrap()
            .insert(("stale.test".to_string(), 1), (resp.clone(), expired, 60));
        assert!(blocker
            .cached_response_for("stale.test", 1, &query_a)
            .is_none());
    }

    #[test]
    fn test_perf_validate_domain() {
        crate::modules::perf::measure("dns::validate_domain", 200_000, || {
            let _ = std::hint::black_box(DnsBlocker::validate_domain("ads.example.com"));
        });
    }

    #[test]
    fn test_perf_should_block() {
        let blocker = DnsBlocker::new();
        blocker.set_custom_rules(&["ads.example.com".to_string()], &[]);
        crate::modules::perf::measure("dns::should_block", 500_000, || {
            std::hint::black_box(blocker.should_block("sub.ads.example.com"));
        });
    }
}
