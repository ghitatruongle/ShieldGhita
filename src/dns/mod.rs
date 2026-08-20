use daachorse::DoubleArrayAhoCorasick;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

pub struct DnsBlocker {
    ac: Arc<RwLock<Option<DoubleArrayAhoCorasick<u32>>>>,
    blocked_domains: Arc<RwLock<Vec<String>>>,
    pub total_queries: Arc<AtomicU64>,
    pub blocked_count: Arc<AtomicU64>,
}

impl DnsBlocker {
    pub fn new() -> Self {
        Self { ac: Arc::new(RwLock::new(None)), blocked_domains: Arc::new(RwLock::new(Vec::new())), total_queries: Arc::new(AtomicU64::new(0)), blocked_count: Arc::new(AtomicU64::new(0)) }
    }
    fn cache_path() -> PathBuf { let d = std::env::var("APPDATA").unwrap_or_else(|_| ".".into()); PathBuf::from(d).join("ShieldGhita").join("blocklist.cache") }
    fn load_cache(&self) -> Result<usize, String> {
        let p = Self::cache_path(); if !p.exists() { return Err("none".into()); }
        let c = fs::read_to_string(&p).map_err(|e| e.to_string())?;
        let d: Vec<String> = c.lines().map(|l| l.trim().to_lowercase()).filter(|l| !l.is_empty()).collect();
        if d.is_empty() { return Err("empty".into()); }
        let n = d.len(); let ps: Vec<&str> = d.iter().map(|s| s.as_str()).collect();
        let ac = DoubleArrayAhoCorasick::<u32>::new(ps).map_err(|e| e.to_string())?;
        *self.blocked_domains.write().map_err(|e| e.to_string())? = d;
        *self.ac.write().map_err(|e| e.to_string())? = Some(ac);
        info!("Loaded {} cached domains", n); Ok(n)
    }
    fn save_cache(&self) -> Result<(), String> {
        let p = Self::cache_path(); if let Some(pp) = p.parent() { fs::create_dir_all(pp).map_err(|e| e.to_string())?; }
        let d = self.blocked_domains.read().map_err(|e| e.to_string())?;
        fs::write(&p, d.join("\n")).map_err(|e| e.to_string())?; Ok(())
    }
    fn parse_line(line: &str) -> Option<String> {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with('!') || l.starts_with('[') { return None; }
        if l.starts_with("||") { let d = l.trim_start_matches("||").trim_end_matches('^'); let d = d.split('/').next().unwrap_or(d); let d = d.split('$').next().unwrap_or(d); if !d.is_empty() && !d.contains('*') { return Some(d.to_lowercase()); } return None; }
        if l.starts_with('|') && l.ends_with('|') { let d = &l[1..l.len()-1]; if !d.is_empty() && !d.contains('*') && !d.contains('/') { return Some(d.to_lowercase()); } return None; }
        if let Some(pos) = l.find(|c: char| c.is_whitespace()) { let ip = &l[..pos]; if ip == "0.0.0.0" || ip == "127.0.0.1" { let d = l[pos..].trim().split('#').next().unwrap_or("").split_whitespace().next().unwrap_or(""); if !d.is_empty() && d != "localhost" && d != "broadcasthost" { return Some(d.to_lowercase()); } } return None; }
        if !l.contains(' ') && !l.contains('/') && !l.contains('*') { let d = l.split('#').next().unwrap_or(l).trim(); if !d.is_empty() && d != "localhost" && d != "broadcasthost" { return Some(d.to_lowercase()); } }
        None
    }
    pub async fn load_blocklists(&self, urls: &[String]) -> Result<usize, String> {
        let _ = self.load_cache();
        let mut all = Vec::new();
        for url in urls { match reqwest::get(url).await { Ok(r) => match r.text().await { Ok(b) => { for l in b.lines() { if let Some(d) = Self::parse_line(l) { all.push(d); } } } Err(e) => warn!("{}: {}", url, e) }, Err(e) => warn!("{}: {}", url, e) } }
        all.sort(); all.dedup(); let n = all.len();
        if n > 0 { let ps: Vec<&str> = all.iter().map(|s| s.as_str()).collect(); let ac = DoubleArrayAhoCorasick::<u32>::new(ps).map_err(|e| e.to_string())?; *self.blocked_domains.write().map_err(|e| e.to_string())? = all; *self.ac.write().map_err(|e| e.to_string())? = Some(ac); let _ = self.save_cache(); info!("Loaded {} domains", n); }
        Ok(n)
    }
    pub fn add_custom_domain(&self, domain: &str) -> Result<(), String> {
        let d = domain.trim().to_lowercase(); if d.is_empty() { return Ok(()); }
        let nd = { let mut ds = self.blocked_domains.write().map_err(|e| e.to_string())?; if !ds.contains(&d) { ds.push(d.clone()); ds.sort(); Some(ds.clone()) } else { None } };
        if let Some(ds) = nd { let ps: Vec<&str> = ds.iter().map(|s| s.as_str()).collect(); let ac = DoubleArrayAhoCorasick::<u32>::new(ps).map_err(|e| e.to_string())?; *self.ac.write().map_err(|e| e.to_string())? = Some(ac); let _ = self.save_cache(); }
        Ok(())
    }
    pub fn remove_custom_domain(&self, domain: &str) -> Result<(), String> {
        let d = domain.trim().to_lowercase();
        let nd = { let mut ds = self.blocked_domains.write().map_err(|e| e.to_string())?; let b = ds.len(); ds.retain(|x| x != &d); if ds.len() < b { Some(ds.clone()) } else { None } };
        if let Some(ds) = nd { let ps: Vec<&str> = ds.iter().map(|s| s.as_str()).collect(); let ac = DoubleArrayAhoCorasick::<u32>::new(ps).map_err(|e| e.to_string())?; *self.ac.write().map_err(|e| e.to_string())? = Some(ac); let _ = self.save_cache(); }
        Ok(())
    }
    pub fn should_block(&self, q: &str) -> bool { let ql = q.to_lowercase(); let g = self.ac.read().unwrap(); if let Some(ref ac) = *g { ac.find_iter(&ql).next().is_some() } else { false } }
    pub fn blocked_count(&self) -> usize { self.blocked_domains.read().map(|d| d.len()).unwrap_or(0) }
    fn parse_query_name(pkt: &[u8]) -> Option<String> {
        if pkt.len() < 12 { return None; } let mut pos = 12; let mut labels = Vec::new();
        while pos < pkt.len() { let len = pkt[pos] as usize; if len == 0 || len & 0xC0 == 0xC0 { break; } pos += 1; if pos + len > pkt.len() { return None; } labels.push(std::str::from_utf8(&pkt[pos..pos+len]).ok()?.to_string()); pos += len; }
        if labels.is_empty() { None } else { Some(labels.join(".")) }
    }
    fn build_nxdomain(q: &[u8]) -> Option<Vec<u8>> { if q.len() < 12 { return None; } let mut r = q.to_vec(); r[2] |= 0x80; r[3] = (r[3] & 0xF0) | 0x03; r[6..12].fill(0); Some(r) }
    pub async fn run_dns_server(self: Arc<Self>, addr: &str, port: u16, doh: Vec<String>, mon: Arc<crate::monitor::NetworkMonitor>) {
        let a = format!("{}:{}", addr, port);
        let sock = match UdpSocket::bind(&a).await { Ok(s) => s, Err(e) => { error!("Bind {}: {}", a, e); return; } };
        info!("DNS proxy on {}", a); let mut buf = [0u8; 4096];
        loop { let (len, src) = match sock.recv_from(&mut buf).await { Ok(r) => r, Err(e) => { warn!("recv: {}", e); continue; } };
            let pkt = &buf[..len]; let qn = match Self::parse_query_name(pkt) { Some(n) => n, None => continue };
            self.total_queries.fetch_add(1, Ordering::Relaxed); let sip = src.ip().to_string();
            if self.should_block(&qn) { self.blocked_count.fetch_add(1, Ordering::Relaxed); mon.add_log(&qn, &sip, true); if let Some(r) = Self::build_nxdomain(pkt) { let _ = sock.send_to(&r, src).await; } }
            else { mon.add_log(&qn, &sip, false); let fwd = self.fwd_doh(pkt, &doh).await; if let Some(r) = fwd { let _ = sock.send_to(&r, src).await; } else { let mut sf = pkt.to_vec(); if sf.len() >= 12 { sf[2] |= 0x80; sf[3] = (sf[3] & 0xF0) | 0x02; } let _ = sock.send_to(&sf, src).await; } }
        }
    }
    async fn fwd_doh(&self, q: &[u8], urls: &[String]) -> Option<Vec<u8>> {
        let c = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build().ok()?;
        for u in urls { match c.post(u).header("Content-Type","application/dns-message").header("Accept","application/dns-message").body(q.to_vec()).send().await { Ok(r) if r.status().is_success() => { if let Ok(b) = r.bytes().await { return Some(b.to_vec()); } } Ok(r) => { warn!("{}: {}", u, r.status()); } Err(e) => { warn!("{}: {}", u, e); } } }
        None
    }
}
