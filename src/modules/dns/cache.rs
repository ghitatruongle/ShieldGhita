use super::*;

impl DnsBlocker {
    fn cache_ttl_seconds(resp: &[u8]) -> u64 {
        let ttl = Self::extract_min_ttl(resp).unwrap_or(10);
        ttl.clamp(1, 60) as u64
    }

    pub fn cached_response_for(&self, name: &str, qtype: u16, pkt: &[u8]) -> Option<Vec<u8>> {
        let cache = self.dns_cache.read().unwrap_or_else(|e| e.into_inner());
        let key = (name.to_lowercase(), qtype);
        let (cached_resp, inserted, ttl) = cache.get(&key)?;
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
                if cache.len() > 5500 {
                    // Evict oldest 500 by smallest timestamp without a full
                    // sort of the whole map each insert.
                    let mut oldest: Vec<((String, u16), Instant)> = Vec::new();
                    for (k, (_, inserted, _)) in cache.iter() {
                        oldest.push((k.clone(), *inserted));
                    }
                    // Partial selection: only sort when over threshold and
                    // drain down to 5000.
                    oldest.sort_by_key(|(_, inserted)| *inserted);
                    let excess = cache.len().saturating_sub(5000);
                    for (key, _) in oldest.into_iter().take(excess) {
                        cache.remove(&key);
                    }
                }
            }
            let ttl = Self::cache_ttl_seconds(resp) as u32;
            cache.insert(
                (name.to_lowercase(), qtype),
                (resp.to_vec(), Instant::now(), ttl),
            );
        }
    }
}
