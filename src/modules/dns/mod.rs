pub mod client_policy;
pub mod disk_store;

pub(super) use client_policy::{AdBlockControls, ClientMode};
pub(super) use disk_store::{DiskBlocklist, FastDomainCache};
pub(super) use std::collections::{HashMap, HashSet};
pub(super) use std::fs;
pub(super) use std::net::SocketAddr;
pub(super) use std::path::{Path, PathBuf};
pub(super) use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
pub(super) use std::sync::{Arc, Mutex, RwLock};
pub(super) use std::time::{Duration, Instant};
pub(super) use tokio::net::UdpSocket;
pub(super) use tracing::{error, info, warn};

const BUILTIN_VIDEO_AUDIO_AD_DOMAINS: &[&str] = &[
    // YouTube & Google Ads
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
    "partnerad.l.google.com",
    "admob.com",
    "analytics.google.com",
    "googletagmanager.com",
    "googletagservices.com",
    // Spotify & Audio streaming ads
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
    // TikTok, Douyin & ByteDance telemetry/ads
    "ads.tiktok.com",
    "analytics.tiktok.com",
    "ib.tiktokv.com",
    "log.byteoversea.com",
    "mon.zijieapi.com",
    "api-ad.tiktok.com",
    "toblog.byteoversea.com",
    // Facebook / Meta trackers & audience network
    "an.facebook.com",
    "ads.facebook.com",
    "pixel.facebook.com",
    "tr.facebook.com",
    "analytics.facebook.com",
    // Vietnam specific Ad networks & Telemetry (Zalo/ZADN, Zing, NCT, Cốc Cốc, Shopee, Tiki, Lazada)
    "ad.zadn.vn",
    "api.ad.zadn.vn",
    "tracking.zadn.vn",
    "media.zadn.vn",
    "sdk.e.zadn.vn",
    "zalo-analytics.zadn.vn",
    "logs.zadn.vn",
    "qc.nct.vn",
    "ad.nct.vn",
    "adv.zing.vn",
    "adt.zing.vn",
    "qc.coccoc.com",
    "adserver.coccoc.com",
    "dsp.coccoc.com",
    "catalog.coccoc.com",
    "tracking.shopee.vn",
    "criteo.shopee.vn",
    "api.affiliate.shopee.vn",
    "tracking.lazada.vn",
    "log.tiki.vn",
    "tracking.tiki.vn",
    // Global Ad giants & Telemetry (Amazon, Criteo, Taboola, Outbrain, Microsoft Telemetry)
    "fls-na.amazon.com",
    "aax-us-east.amazon-adsystem.com",
    "c.amazon-adsystem.com",
    "scorecardresearch.com",
    "adroll.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    "mgid.com",
    "adnxs.com",
    "rubiconproject.com",
    "openx.net",
    "pubmatic.com",
    "smartadserver.com",
    "telemetry.microsoft.com",
    "vortex.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "settings-win.data.microsoft.com",
    "diagnostics.support.microsoft.com",
];

const REBIND_INCIDENT_COOLDOWN: Duration = Duration::from_secs(60);
const MAX_REBIND_COOLDOWNS: usize = 1024;

pub type DnsCacheMap = Arc<RwLock<HashMap<(String, u16), (Vec<u8>, Instant, u32)>>>;

/// Identical UDP socket errors (adapter flapping, tether re-association)
/// arrive in bursts. Log one line per window with a count instead of one
/// line per datagram.
fn log_recv_error(err: &std::io::Error) {
    use std::sync::Mutex as StdMutex;
    static RECV_ERRORS: StdMutex<Option<(String, u64, Instant)>> = StdMutex::new(None);
    const WINDOW: Duration = Duration::from_secs(300);

    let text = err.to_string();
    let now = Instant::now();
    let mut guard = match RECV_ERRORS.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    match guard.as_mut() {
        Some((last_text, count, first_seen)) if *last_text == text => {
            *count += 1;
            if now.duration_since(*first_seen) >= WINDOW {
                warn!(
                    "UDP recv error x{} in the last 5 min: {}",
                    *count, last_text
                );
                *count = 0;
                *first_seen = now;
            }
        }
        _ => {
            *guard = Some((text, 1, now));
        }
    }
}

pub struct DnsBlocker {
    disk_store: Arc<RwLock<Option<DiskBlocklist>>>,
    fast_cache: Arc<FastDomainCache>,
    builtin_domains: Arc<RwLock<HashSet<String>>>,
    allowed_domains: Arc<RwLock<HashSet<String>>>,
    custom_blocked: Arc<RwLock<HashSet<String>>>,
    custom_allowed: Arc<RwLock<HashSet<String>>>,
    dns_cache: DnsCacheMap,
    http_client: reqwest::Client,
    etag_cache: Arc<Mutex<HashMap<String, String>>>,
    feed_status: Arc<Mutex<HashMap<String, String>>>,
    pub total_queries: Arc<AtomicU64>,
    pub blocked_count: Arc<AtomicU64>,
    pub silent_sinkhole_enabled: Arc<AtomicBool>,
    pub blocked_events_tx: tokio::sync::broadcast::Sender<(String, String)>,
    response_policy: Arc<RwLock<Option<ResponsePolicyFn>>>,
    pub rules_count: Arc<AtomicUsize>,
    rebind_incident_cooldown: Arc<Mutex<HashMap<(String, String), Instant>>>,
    pub adblock: Arc<AdBlockControls>,
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

        let bin_path = Self::disk_store_path();
        let (disk_store, initial_count) = if bin_path.exists() {
            if let Ok(disk) = DiskBlocklist::open(&bin_path) {
                let cnt = disk.total_domains();
                (Some(disk), cnt)
            } else {
                (None, 0)
            }
        } else {
            (None, 0)
        };

        let (blocked_events_tx, _) = tokio::sync::broadcast::channel(256);

        Self {
            disk_store: Arc::new(RwLock::new(disk_store)),
            fast_cache: Arc::new(FastDomainCache::new()),
            builtin_domains: Arc::new(RwLock::new(initial_blocked)),
            allowed_domains: Arc::new(RwLock::new(HashSet::new())),
            custom_blocked: Arc::new(RwLock::new(HashSet::new())),
            custom_allowed: Arc::new(RwLock::new(HashSet::new())),
            dns_cache: Arc::new(RwLock::new(HashMap::new())),
            http_client: client,
            etag_cache: Arc::new(Mutex::new(Self::read_etag_map_from(
                &Self::etag_store_path(),
            ))),
            feed_status: Arc::new(Mutex::new(HashMap::new())),
            total_queries: Arc::new(AtomicU64::new(0)),
            blocked_count: Arc::new(AtomicU64::new(0)),
            silent_sinkhole_enabled: Arc::new(AtomicBool::new(true)),
            blocked_events_tx,
            response_policy: Arc::new(RwLock::new(None)),
            rules_count: Arc::new(AtomicUsize::new(initial_count)),
            rebind_incident_cooldown: Arc::new(Mutex::new(HashMap::new())),
            adblock: Arc::new(AdBlockControls::new()),
        }
    }
}

pub mod blocklist;
pub mod cache;
pub mod packet;
pub mod resolve;
pub mod server;

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
    fn test_is_safe_blocklist_domain() {
        assert!(DnsBlocker::is_safe_blocklist_domain("ads.example.com"));
        assert!(DnsBlocker::is_safe_blocklist_domain("tracker.io"));
        // Single-label / public suffixes must never enter the remote store.
        assert!(!DnsBlocker::is_safe_blocklist_domain("com"));
        assert!(!DnsBlocker::is_safe_blocklist_domain("com.vn"));
        assert!(!DnsBlocker::is_safe_blocklist_domain("netlify.app"));
        assert!(!DnsBlocker::is_safe_blocklist_domain(""));
        assert!(!DnsBlocker::is_safe_blocklist_domain("a..b.com"));
        assert!(!DnsBlocker::is_safe_blocklist_domain(&"x".repeat(300)));
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
    fn test_dns_rebinding_detection() {
        assert!(DnsBlocker::is_legit_local_domain("router.local"));
        assert!(DnsBlocker::is_legit_local_domain("printer.lan"));
        assert!(DnsBlocker::is_legit_local_domain("localhost"));
        assert!(!DnsBlocker::is_legit_local_domain("evil-bank-phish.com"));

        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, b'e',
            b'v', b'i', b'l', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let forged_private_resp =
            DnsBlocker::build_sinkhole_a_record(&query, [192, 168, 1, 1]).unwrap();
        assert!(DnsBlocker::is_private_ip_record(&forged_private_resp));

        let public_resp = DnsBlocker::build_sinkhole_a_record(&query, [8, 8, 8, 8]).unwrap();
        assert!(!DnsBlocker::is_private_ip_record(&public_resp));
    }

    #[test]
    fn test_rebind_allowlist_exception_and_cooldown_bound() {
        // In-memory fixture: do not read the user's blocklist/ETags or start
        // a resolver. Constructing the HTTP client sends no requests.
        let (blocked_events_tx, _) = tokio::sync::broadcast::channel(1);
        let blocker = DnsBlocker {
            disk_store: Arc::new(RwLock::new(None)),
            fast_cache: Arc::new(FastDomainCache::new()),
            builtin_domains: Arc::new(RwLock::new(HashSet::new())),
            allowed_domains: Arc::new(RwLock::new(HashSet::new())),
            custom_blocked: Arc::new(RwLock::new(HashSet::new())),
            custom_allowed: Arc::new(RwLock::new(HashSet::new())),
            dns_cache: Arc::new(RwLock::new(HashMap::new())),
            http_client: reqwest::Client::new(),
            etag_cache: Arc::new(Mutex::new(HashMap::new())),
            feed_status: Arc::new(Mutex::new(HashMap::new())),
            total_queries: Arc::new(AtomicU64::new(0)),
            blocked_count: Arc::new(AtomicU64::new(0)),
            silent_sinkhole_enabled: Arc::new(AtomicBool::new(true)),
            blocked_events_tx,
            response_policy: Arc::new(RwLock::new(None)),
            rules_count: Arc::new(AtomicUsize::new(0)),
            rebind_incident_cooldown: Arc::new(Mutex::new(HashMap::new())),
            adblock: Arc::new(AdBlockControls::new()),
        };
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, b'e',
            b'v', b'i', b'l', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let private_resp = DnsBlocker::build_sinkhole_a_record(&query, [192, 168, 1, 7]).unwrap();

        // Default: first-seen private answer for a public name is blocked.
        assert!(blocker.forwarded_answer_hits_private_space("evil.com", &private_resp));

        // Explicit custom allowlist entry (exact or parent domain) is trusted
        // for self-hosted/LAN services; subdomains inherit the exemption.
        assert!(blocker.add_allowed_domain("selfhosted.example").is_ok());
        assert!(!blocker.forwarded_answer_hits_private_space("selfhosted.example", &private_resp));
        assert!(
            !blocker.forwarded_answer_hits_private_space("app.selfhosted.example.", &private_resp)
        );

        // The global allowlist must NOT grant this exception (admin opt-in
        // through custom rules only), so other names stay protected.
        blocker
            .allowed_domains
            .write()
            .unwrap()
            .insert("open.example".to_string());
        assert!(blocker.forwarded_answer_hits_private_space("open.example", &private_resp));

        // Public answers and legit local names are never flagged.
        let public_resp = DnsBlocker::build_sinkhole_a_record(&query, [8, 8, 8, 8]).unwrap();
        assert!(!blocker.forwarded_answer_hits_private_space("evil.com", &public_resp));
        assert!(!blocker.forwarded_answer_hits_private_space("router.local", &private_resp));

        // Cooldown map: repeat incidents for the same (ip, domain) inside 60s
        // are suppressed, and distinct pairs can never exceed the hard cap.
        assert!(blocker.take_rebind_incident_slot("203.0.113.9", "flood.test"));
        assert!(!blocker.take_rebind_incident_slot("203.0.113.9", "flood.test"));
        for i in 0..(MAX_REBIND_COOLDOWNS * 2) {
            blocker.take_rebind_incident_slot(
                &format!("203.0.113.{}", i % 200),
                &format!("flood{}.test", i % 997),
            );
        }
        let map = blocker.rebind_incident_cooldown.lock().unwrap();
        assert!(
            map.len() <= MAX_REBIND_COOLDOWNS,
            "rebind cooldown map must stay bounded"
        );
        // Oldest slots may be evicted under saturation; the hard bound, not
        // retention of every pair during a flood, is the invariant here.
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
