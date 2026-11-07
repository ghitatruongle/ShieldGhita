use super::*;

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
}

impl DnsBlocker {
    pub fn get_rules_count(&self) -> usize {
        let base = self.rules_count.load(Ordering::Relaxed);
        let custom = self.custom_blocked.read().map(|b| b.len()).unwrap_or(0);
        let builtin = self.builtin_domains.read().map(|b| b.len()).unwrap_or(0);
        base.max(builtin) + custom
    }

    fn record_feed_status(status: &Arc<Mutex<HashMap<String, String>>>, url: &str, state: &str) {
        if let Ok(mut guard) = status.lock() {
            guard.insert(url.to_string(), state.to_string());
        }
    }

    pub fn feed_status_summary(&self) -> String {
        let guard = match self.feed_status.lock() {
            Ok(g) => g,
            Err(_) => return String::new(),
        };
        if guard.is_empty() {
            return String::new();
        }
        let mut ok = 0usize;
        let mut failed: Vec<String> = Vec::new();
        for (url, state) in guard.iter() {
            match state.as_str() {
                "ok" | "unchanged" => ok += 1,
                "failed" => failed.push(Self::host_of(url).unwrap_or_else(|| url.clone())),
                _ => {}
            }
        }
        let total = guard.len();
        if failed.is_empty() {
            format!("{}/{} feeds OK", ok, total)
        } else {
            format!("{}/{} feeds OK, FAILED: {}", ok, total, failed.join(", "))
        }
    }

    pub(super) fn disk_store_path() -> PathBuf {
        let d = crate::modules::paths::data_base();
        PathBuf::from(d).join("ShieldGhita").join("blocklist.bin")
    }

    pub(super) fn cache_path() -> PathBuf {
        let d = crate::modules::paths::data_base();
        PathBuf::from(d).join("ShieldGhita").join("blocklist.cache")
    }

    pub(super) fn etag_store_path() -> PathBuf {
        let d = crate::modules::paths::data_base();
        PathBuf::from(d)
            .join("ShieldGhita")
            .join("blocklist_etags.json")
    }

    pub(super) fn read_etag_map_from(path: &Path) -> HashMap<String, String> {
        fs::read_to_string(path)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default()
    }

    pub(super) fn write_etag_map_to(path: &Path, map: &HashMap<String, String>) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string(map) {
            let _ = fs::write(path, json);
        }
    }

    pub fn load_cache(&self) -> Result<usize, String> {
        let bin_path = Self::disk_store_path();
        if bin_path.exists() {
            let disk = DiskBlocklist::open(&bin_path)?;
            let count = disk.total_domains();
            *self.disk_store.write().unwrap_or_else(|e| e.into_inner()) = Some(disk);
            self.fast_cache.clear();
            self.rules_count.store(count, Ordering::Relaxed);
            info!("Loaded {} cached domains into blocker from disk", count);
            return Ok(count);
        }

        let p = Self::cache_path();
        if p.exists() {
            if let Ok(content) = fs::read_to_string(&p) {
                let mut domains: Vec<String> = content
                    .lines()
                    .map(|l| l.trim().to_lowercase())
                    .filter(|l| !l.is_empty())
                    .collect();
                for d in BUILTIN_VIDEO_AUDIO_AD_DOMAINS {
                    domains.push(d.to_string());
                }
                if let Ok(count) = DiskBlocklist::build(&bin_path, domains) {
                    let _ = fs::remove_file(&p);
                    if let Ok(disk) = DiskBlocklist::open(&bin_path) {
                        *self.disk_store.write().unwrap_or_else(|e| e.into_inner()) = Some(disk);
                        self.fast_cache.clear();
                        self.rules_count.store(count, Ordering::Relaxed);
                        info!("Migrated legacy cache to disk blocklist: {} domains", count);
                        return Ok(count);
                    }
                }
            }
        }
        Err("no cache found".into())
    }

    #[allow(dead_code)]
    fn save_cache(&self) -> Result<(), String> {
        // Disk-backed blocklist is already persistent on disk
        Ok(())
    }

    /// Lightweight structural check for remote blocklist entries. Rejects
    /// single-label names (e.g. `com`) and public suffixes so hierarchy
    /// matching cannot block entire TLDs. Cheaper than `validate_domain`.
    pub(super) fn is_safe_blocklist_domain(d: &str) -> bool {
        if d.is_empty() || d.len() > 253 || !d.contains('.') {
            return false;
        }
        if BLOCKED_PUBLIC_SUFFIXES.contains(&d) {
            return false;
        }
        d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
    }

    pub fn parse_line(line: &str) -> Option<String> {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with('!') || l.starts_with('[') {
            return None;
        }
        // Reject a bare IP line (e.g. "1.2.3.4", "::1") — not a domain.
        if l.parse::<std::net::IpAddr>().is_ok() {
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
            if ip == "0.0.0.0"
                || ip == "127.0.0.1"
                || ip == "::"
                || ip == "::1"
                || ip == "0:0:0:0:0:0:0:0"
            {
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

    pub async fn load_blocklists(
        &self,
        urls: &[String],
        doh_urls: &[String],
    ) -> Result<usize, String> {
        let fetch_start = Instant::now();
        let doh = doh_urls.to_vec();
        let _ = self.load_cache();
        let mut set: tokio::task::JoinSet<BlocklistFetch> = tokio::task::JoinSet::new();

        for url in urls {
            let base_client = self.http_client.clone();
            let url = url.clone();
            let etag = self
                .etag_cache
                .lock()
                .map(|g| g.get(&url).cloned())
                .unwrap_or(None);
            let doh_for_task = doh.clone();
            set.spawn(async move {
                // Resolve the feed host through our own DoH-pinned path, then
                // pin it per-request. Without this the fetch would depend on
                // the very DNS setting the app itself overwrites (VPN or WARP
                // in the picture) and every list silently fails.
                let client = match Self::host_of(&url)
                    .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                {
                    Some(_pinned) => base_client,
                    None => {
                        let host = Self::host_of(&url).unwrap_or_default();
                        match Self::resolve_host_via_upstream(&base_client, &host, &doh_for_task)
                            .await
                        {
                            Some(ip) => {
                                match reqwest::Client::builder()
                                    .timeout(Duration::from_secs(20))
                                    .pool_max_idle_per_host(5)
                                    .resolve(&host, std::net::SocketAddr::new(ip, 443))
                                    .build()
                                {
                                    Ok(pinned_client) => pinned_client,
                                    Err(_) => base_client,
                                }
                            }
                            None => base_client,
                        }
                    }
                };
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
                            const MAX_BLOCKLIST_BYTES: usize = 64 * 1024 * 1024;
                            if let Some(cl) = resp.content_length() {
                                if cl as usize > MAX_BLOCKLIST_BYTES {
                                    return Err(format!(
                                        "{}: blocklist too large ({} bytes, max {})",
                                        url, cl, MAX_BLOCKLIST_BYTES
                                    ));
                                }
                            }
                            let etag = resp
                                .headers()
                                .get("ETag")
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string());
                            let bytes =
                                resp.bytes().await.map_err(|e| format!("{}: {}", url, e))?;
                            if bytes.len() > MAX_BLOCKLIST_BYTES {
                                return Err(format!(
                                    "{}: blocklist body exceeded cap ({} bytes)",
                                    url,
                                    bytes.len()
                                ));
                            }
                            let text = String::from_utf8_lossy(&bytes).into_owned();
                            // Free the raw bytes before moving the text out so
                            // peak memory is not held twice longer than needed.
                            drop(bytes);
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
        let mut failed = 0usize;
        let mut failed_urls: Vec<String> = Vec::new();
        let mut new_etags: HashMap<String, String> = self
            .etag_cache
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();

        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok((url, None, _))) => {
                    unchanged += 1;
                    Self::record_feed_status(&self.feed_status, &url, "unchanged");
                }
                Ok(Ok((url, Some(text), etag))) => {
                    any_success = true;
                    fetched += 1;
                    Self::record_feed_status(&self.feed_status, &url, "ok");
                    if let Some(tag) = etag {
                        new_etags.insert(url.clone(), tag);
                    } else {
                        // 200 without ETag: drop any stale tag for this URL.
                        new_etags.remove(&url);
                    }
                    for line in text.lines() {
                        if let Some(d) = Self::parse_line(line) {
                            if Self::is_safe_blocklist_domain(&d) {
                                domains.insert(d);
                            }
                        }
                    }
                    // `text` (potentially tens of MB) is dropped here per-iteration.
                }
                Ok(Err(e)) => {
                    failed += 1;
                    // Recover the failed URL from the "url: reason" envelope so
                    // only its ETag is invalidated, keeping fetched tags.
                    if let Some(matched) = urls.iter().find(|u| e.starts_with(u.as_str())) {
                        failed_urls.push(matched.clone());
                        Self::record_feed_status(&self.feed_status, matched, "failed");
                    }
                    warn!("Failed to fetch blocklist: {}", e);
                }
                Err(e) => {
                    failed += 1;
                    warn!("Blocklist fetch task failed: {}", e);
                }
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
            let count = self.get_rules_count();
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

        // Rebuilding the disk store from only the bodies we just fetched would
        // wipe domains belonging to 304 / failed sources. Only rebuild when
        // every source produced a fresh body. On partial success, keep the
        // existing disk and invalidate only the failed URLs' ETags so the
        // next refresh re-fetches just those.
        let incomplete = unchanged > 0 || failed > 0;
        if incomplete {
            if any_success {
                warn!(
                    "Skipping blocklist rebuild: {} unchanged, {} failed, {} fetched. Keeping existing on-disk rules; clearing ETags only for failed sources.",
                    unchanged, failed, fetched
                );
                for fu in &failed_urls {
                    new_etags.remove(fu);
                }
                *self.etag_cache.lock().unwrap_or_else(|e| e.into_inner()) = new_etags.clone();
                Self::write_etag_map_to(&Self::etag_store_path(), &new_etags);
            }
            let count = self.get_rules_count();
            return Ok(count);
        }

        let count = domains.len();
        if count > 0 && any_success {
            let (compacted, redundant) = Self::compact_covered_domains(domains);
            let count = compacted.len();
            let bin_path = Self::disk_store_path();
            info!(
                "Blocklist compaction: {} domains collapsed to {} blocking suffixes ({} redundant subdomains)",
                count + redundant,
                count,
                redundant
            );
            match DiskBlocklist::build(&bin_path, compacted.into_iter().collect()) {
                Ok(built_count) => {
                    if let Ok(disk) = DiskBlocklist::open(&bin_path) {
                        *self.disk_store.write().unwrap_or_else(|e| e.into_inner()) = Some(disk);
                        self.fast_cache.clear();
                        self.rules_count.store(built_count, Ordering::Relaxed);
                    }
                    crate::modules::system::trim_process_working_set();
                    info!(
                        "Loaded {} unique domains into disk blocklist in {} ms",
                        built_count,
                        fetch_start.elapsed().as_millis()
                    );
                    return Ok(built_count);
                }
                Err(e) => {
                    warn!("Failed to build disk blocklist: {}", e);
                    return Err(e);
                }
            }
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
        self.fast_cache.clear();
    }

    pub fn add_custom_domain(&self, domain: &str) -> Result<(), String> {
        let d = Self::validate_domain(domain)?;
        let mut cb = self.custom_blocked.write().map_err(|e| e.to_string())?;
        cb.insert(d);
        self.fast_cache.clear();
        Ok(())
    }

    pub fn remove_custom_domain(&self, domain: &str) -> Result<(), String> {
        let d = domain.trim().to_lowercase();
        let mut cb = self.custom_blocked.write().map_err(|e| e.to_string())?;
        cb.remove(&d);
        self.fast_cache.clear();
        Ok(())
    }

    pub fn add_allowed_domain(&self, domain: &str) -> Result<(), String> {
        let d = Self::validate_domain(domain)?;
        let mut ca = self.custom_allowed.write().map_err(|e| e.to_string())?;
        ca.insert(d);
        self.fast_cache.clear();
        Ok(())
    }

    pub fn remove_allowed_domain(&self, domain: &str) -> Result<(), String> {
        let d = domain.trim().to_lowercase();
        let mut ca = self.custom_allowed.write().map_err(|e| e.to_string())?;
        ca.remove(&d);
        self.fast_cache.clear();
        Ok(())
    }

    pub fn get_custom_rules(&self) -> Vec<String> {
        self.custom_blocked
            .read()
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_allowed_rules(&self) -> Vec<String> {
        self.custom_allowed
            .read()
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
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

        // 2. Custom blocked blacklist check
        {
            let cb = self
                .custom_blocked
                .read()
                .unwrap_or_else(|e| e.into_inner());
            if Self::match_domain_hierarchy(&clean, &cb) {
                return true;
            }
        }

        // 3. Builtin blacklist check
        {
            let bb = self
                .builtin_domains
                .read()
                .unwrap_or_else(|e| e.into_inner());
            if Self::match_domain_hierarchy(&clean, &bb) {
                return true;
            }
        }

        // 4. Fast in-memory cache check
        let h = disk_store::hash_domain(&clean);
        if let Some(res) = self.fast_cache.get(h) {
            return res;
        }

        // 5. Disk blocklist hierarchy check
        let is_blocked = self.check_disk_hierarchy(&clean);
        self.fast_cache.insert(h, is_blocked);
        is_blocked
    }

    fn check_disk_hierarchy(&self, domain: &str) -> bool {
        let guard = self.disk_store.read().unwrap_or_else(|e| e.into_inner());
        let Some(ref disk) = *guard else {
            return false;
        };
        if disk.contains(domain) {
            return true;
        }
        let mut rest = domain;
        while let Some(dot_pos) = rest.find('.') {
            rest = &rest[dot_pos + 1..];
            if !rest.is_empty() {
                let h = disk_store::hash_domain(rest);
                if let Some(cached) = self.fast_cache.get(h) {
                    if cached {
                        return true;
                    }
                } else {
                    let blocked = disk.contains(rest);
                    self.fast_cache.insert(h, blocked);
                    if blocked {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub(super) fn match_domain_hierarchy(domain: &str, set: &HashSet<String>) -> bool {
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

    fn compact_covered_domains(domains: HashSet<String>) -> (HashSet<String>, usize) {
        let original = domains.len();
        let all: HashSet<String> = domains
            .iter()
            .map(|d| d.trim_end_matches('.').to_lowercase())
            .collect();
        let kept: HashSet<String> = all
            .iter()
            .filter(|domain| {
                let mut rest = domain.as_str();
                while let Some(dot_pos) = rest.find('.') {
                    rest = &rest[dot_pos + 1..];
                    if rest.is_empty() {
                        break;
                    }
                    if all.contains(rest) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        let removed = original - kept.len();
        (kept, removed)
    }

    #[allow(dead_code)]
    pub fn blocked_count(&self) -> usize {
        self.get_rules_count()
    }
}
