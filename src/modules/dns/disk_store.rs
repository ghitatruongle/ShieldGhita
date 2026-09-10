use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

const HEADER_SIZE: usize = 4096;
const MAGIC: &[u8; 4] = b"SGBL";
const BUCKET_COUNT: usize = 256;
const RECORD_SIZE: usize = 14;

pub fn hash_domain(domain: &str) -> u64 {
    // 64-bit FNV-1a hash
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in domain.as_bytes() {
        let b_lower = if b.is_ascii_uppercase() { b + 32 } else { b };
        h ^= b_lower as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Fixed-size direct-mapped fast cache for domain lookup results (64 KB RAM).
pub struct FastDomainCache {
    entries: RwLock<[(u64, bool, bool); 4096]>,
}

impl FastDomainCache {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new([(0, false, false); 4096]),
        }
    }

    pub fn get(&self, hash: u64) -> Option<bool> {
        // Use an explicit occupied flag so hash value 0 is a valid key
        // instead of colliding with the empty sentinel.
        let h = hash.wrapping_add(1);
        let idx = (h as usize) & 4095;
        if let Ok(guard) = self.entries.read() {
            let (stored, blocked, occupied) = guard[idx];
            if occupied && stored == h {
                return Some(blocked);
            }
        }
        None
    }

    pub fn insert(&self, hash: u64, blocked: bool) {
        let h = hash.wrapping_add(1);
        let idx = (h as usize) & 4095;
        if let Ok(mut guard) = self.entries.write() {
            guard[idx] = (h, blocked, true);
        }
    }

    pub fn clear(&self) {
        if let Ok(mut guard) = self.entries.write() {
            *guard = [(0, false, false); 4096];
        }
    }
}

/// On-disk blocklist store: ~10MB on disk, ~2KB in RAM.
pub struct DiskBlocklist {
    file_path: PathBuf,
    total_domains: usize,
    buckets: [(u32, u32); BUCKET_COUNT], // (offset, count)
    strings_base_offset: u64,
}

impl DiskBlocklist {
    pub fn open(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Err("file does not exist".into());
        }
        let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
        let file_len = meta.len();
        if file_len < HEADER_SIZE as u64 {
            return Err("file too small for header".into());
        }
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let mut header = [0u8; HEADER_SIZE];
        file.read_exact(&mut header).map_err(|e| e.to_string())?;

        if &header[0..4] != MAGIC {
            return Err("invalid magic bytes".into());
        }
        let version = u32::from_le_bytes(
            header[4..8]
                .try_into()
                .map_err(|_| "truncated version field".to_string())?,
        );
        if version != 1 {
            return Err("unsupported version".into());
        }
        let total_domains = u32::from_le_bytes(
            header[8..12]
                .try_into()
                .map_err(|_| "truncated total_domains field".to_string())?,
        ) as usize;
        let mut buckets = [(0u32, 0u32); BUCKET_COUNT];
        let mut pos = 16;
        for bucket in &mut buckets {
            let off = u32::from_le_bytes(
                header[pos..pos + 4]
                    .try_into()
                    .map_err(|_| "truncated bucket offset".to_string())?,
            );
            let count = u32::from_le_bytes(
                header[pos + 4..pos + 8]
                    .try_into()
                    .map_err(|_| "truncated bucket count".to_string())?,
            );
            *bucket = (off, count);
            pos += 8;
        }

        let strings_base_offset = HEADER_SIZE as u64
            + (total_domains as u64)
                .checked_mul(RECORD_SIZE as u64)
                .ok_or_else(|| "total_domains * RECORD_SIZE overflow".to_string())?;
        if file_len < strings_base_offset {
            return Err("file truncated: shorter than index section".into());
        }

        // Validate: sum(counts) == total_domains
        let sum: u64 = buckets.iter().map(|(_, c)| *c as u64).sum();
        if sum != total_domains as u64 {
            return Err(format!(
                "corrupt header: sum(bucket counts) {} != total {}",
                sum, total_domains
            ));
        }
        // Validate each bucket range with overflow checks + monotonic offsets.
        let mut prev_end: Option<u64> = None;
        for (i, (off, count)) in buckets.iter().enumerate() {
            let off_u64 = *off as u64;
            if off_u64 < HEADER_SIZE as u64 {
                return Err(format!("corrupt header: bucket {} offset below header", i));
            }
            let rec_bytes = (*count as u64)
                .checked_mul(RECORD_SIZE as u64)
                .ok_or_else(|| format!("corrupt header: bucket {} count overflow", i))?;
            let end = off_u64
                .checked_add(rec_bytes)
                .ok_or_else(|| format!("corrupt header: bucket {} offset+len overflow", i))?;
            if end > strings_base_offset {
                return Err(format!(
                    "corrupt header: bucket {} extends past strings base",
                    i
                ));
            }
            if let Some(pe) = prev_end {
                if off_u64 < pe {
                    return Err(format!("corrupt header: bucket {} offset not monotonic", i));
                }
            }
            prev_end = Some(end);
        }

        Ok(Self {
            file_path: path.to_path_buf(),
            total_domains,
            buckets,
            strings_base_offset,
        })
    }

    pub fn total_domains(&self) -> usize {
        self.total_domains
    }

    pub fn contains(&self, domain: &str) -> bool {
        if self.total_domains == 0 || domain.is_empty() {
            return false;
        }
        const MAX_READ_BYTES: usize = 64 * 1024 * 1024;
        let target_hash = hash_domain(domain);
        let bucket_idx = (target_hash >> 56) as usize;
        let (offset, count) = self.buckets[bucket_idx];
        if count == 0 {
            return false;
        }
        // Cap per-bucket count to total_domains to avoid OOM on corrupt header.
        if (count as usize) > self.total_domains {
            return false;
        }

        let mut file = match File::open(&self.file_path) {
            Ok(f) => f,
            Err(_) => return false,
        };

        if file.seek(SeekFrom::Start(offset as u64)).is_err() {
            return false;
        }

        let read_bytes = match (count as usize).checked_mul(RECORD_SIZE) {
            Some(n) => n,
            None => return false,
        };
        if read_bytes > MAX_READ_BYTES {
            return false;
        }
        // Range must sit inside the index section.
        let end = match (offset as u64).checked_add(read_bytes as u64) {
            Some(e) => e,
            None => return false,
        };
        if (offset as u64) < HEADER_SIZE as u64 || end > self.strings_base_offset {
            return false;
        }
        let mut buf = vec![0u8; read_bytes];
        if file.read_exact(&mut buf).is_err() {
            return false;
        }

        // Binary search within bucket for target_hash
        let mut low = 0usize;
        let mut high = count as usize;
        let mut found_idx = None;

        // Helper to read a u64 hash without unwrap; None = malformed.
        let read_hash = |buf: &[u8], p: usize| -> Option<u64> {
            let s = buf.get(p..p + 8)?;
            let a: [u8; 8] = s.try_into().ok()?;
            Some(u64::from_le_bytes(a))
        };

        while low < high {
            let mid = low + (high - low) / 2;
            let p = match mid.checked_mul(RECORD_SIZE) {
                Some(v) => v,
                None => return false,
            };
            let mid_hash = match read_hash(&buf, p) {
                Some(h) => h,
                None => return false,
            };
            if mid_hash == target_hash {
                found_idx = Some(mid);
                break;
            } else if mid_hash < target_hash {
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        if let Some(idx) = found_idx {
            // Check for match and scan neighboring equal hashes if any
            let check_match = |cand_idx: usize| -> bool {
                let p = match cand_idx.checked_mul(RECORD_SIZE) {
                    Some(v) => v,
                    None => return false,
                };
                let cand_hash = match read_hash(&buf, p) {
                    Some(h) => h,
                    None => return false,
                };
                if cand_hash != target_hash {
                    return false;
                }
                let str_off = match buf.get(p + 8..p + 12) {
                    Some(s) => match s.try_into() {
                        Ok(a) => u32::from_le_bytes(a),
                        Err(_) => return false,
                    },
                    None => return false,
                };
                let str_len = match buf.get(p + 12..p + 14) {
                    Some(s) => match s.try_into() {
                        Ok(a) => u16::from_le_bytes(a) as usize,
                        Err(_) => return false,
                    },
                    None => return false,
                };

                if str_len != domain.len() {
                    return false;
                }

                let abs_off = match self.strings_base_offset.checked_add(str_off as u64) {
                    Some(v) => v,
                    None => return false,
                };
                let mut f = match File::open(&self.file_path) {
                    Ok(f) => f,
                    Err(_) => return false,
                };
                if f.seek(SeekFrom::Start(abs_off)).is_err() {
                    return false;
                }
                let mut str_buf = vec![0u8; str_len];
                if f.read_exact(&mut str_buf).is_err() {
                    return false;
                }
                str_buf.eq_ignore_ascii_case(domain.as_bytes())
            };

            if check_match(idx) {
                return true;
            }
            // Scan backwards
            let mut i = idx;
            while i > 0 {
                i -= 1;
                let p = match i.checked_mul(RECORD_SIZE) {
                    Some(v) => v,
                    None => break,
                };
                let h = match read_hash(&buf, p) {
                    Some(h) => h,
                    None => return false,
                };
                if h != target_hash {
                    break;
                }
                if check_match(i) {
                    return true;
                }
            }
            // Scan forwards
            let mut j = idx + 1;
            while j < count as usize {
                let p = match j.checked_mul(RECORD_SIZE) {
                    Some(v) => v,
                    None => break,
                };
                let h = match read_hash(&buf, p) {
                    Some(h) => h,
                    None => return false,
                };
                if h != target_hash {
                    break;
                }
                if check_match(j) {
                    return true;
                }
                j += 1;
            }
        }

        false
    }

    /// Builds a sorted on-disk database from an iterator of unique domain strings.
    pub fn build(out_path: &Path, mut domains: Vec<String>) -> Result<usize, String> {
        // Deduplicate and prepare
        domains.sort_unstable();
        domains.dedup();

        // Sort by (bucket, hash, domain)
        domains.sort_by(|a, b| {
            let ha = hash_domain(a);
            let hb = hash_domain(b);
            ha.cmp(&hb).then_with(|| a.cmp(b))
        });

        let total = domains.len();
        let total_u32 =
            u32::try_from(total).map_err(|_| "too many domains: exceeds u32 range".to_string())?;
        // Unique tmp path to avoid collisions between concurrent builds.
        let tmp_path = out_path.with_extension(format!("tmp-{}", std::process::id()));
        let res: Result<usize, String> = (|| {
            let file = File::create(&tmp_path).map_err(|e| e.to_string())?;
            let mut writer = BufWriter::with_capacity(65536, file);

            // Header placeholder
            let header = [0u8; HEADER_SIZE];
            writer.write_all(&header).map_err(|e| e.to_string())?;

            let mut bucket_counts = [0u32; BUCKET_COUNT];
            let mut bucket_offsets = [0u32; BUCKET_COUNT];

            // Partition by bucket
            let mut bucket_items: Vec<Vec<(u64, usize)>> = vec![Vec::new(); BUCKET_COUNT];
            for (i, d) in domains.iter().enumerate() {
                let h = hash_domain(d);
                let b = (h >> 56) as usize;
                bucket_items[b].push((h, i));
            }

            let mut cur_record_offset = HEADER_SIZE as u32;
            for b in 0..BUCKET_COUNT {
                let count = u32::try_from(bucket_items[b].len())
                    .map_err(|_| format!("bucket {} count exceeds u32 range", b))?;
                bucket_counts[b] = count;
                bucket_offsets[b] = cur_record_offset;
                let add = count
                    .checked_mul(RECORD_SIZE as u32)
                    .ok_or_else(|| format!("bucket {} index size overflow", b))?;
                cur_record_offset = cur_record_offset
                    .checked_add(add)
                    .ok_or_else(|| "index section size overflow".to_string())?;
            }

            // Build strings section in memory to compute offsets
            let mut str_offsets: Vec<u32> = Vec::with_capacity(total);
            let mut str_lens: Vec<u16> = Vec::with_capacity(total);
            let mut strings_bytes: Vec<u8> = Vec::new();

            for d in &domains {
                let off = u32::try_from(strings_bytes.len())
                    .map_err(|_| "strings section exceeds u32 range".to_string())?;
                let len = u16::try_from(d.len())
                    .map_err(|_| format!("domain too long ({} bytes): {}", d.len(), d))?;
                str_offsets.push(off);
                str_lens.push(len);
                strings_bytes.extend_from_slice(d.as_bytes());
            }

            // Write index records bucket by bucket
            for items in &bucket_items {
                for &(h, orig_idx) in items {
                    writer
                        .write_all(&h.to_le_bytes())
                        .map_err(|e| e.to_string())?;
                    writer
                        .write_all(&str_offsets[orig_idx].to_le_bytes())
                        .map_err(|e| e.to_string())?;
                    writer
                        .write_all(&str_lens[orig_idx].to_le_bytes())
                        .map_err(|e| e.to_string())?;
                }
            }

            // Write strings section
            writer
                .write_all(&strings_bytes)
                .map_err(|e| e.to_string())?;
            writer.flush().map_err(|e| e.to_string())?;
            // fsync data before header rewrite.
            {
                let inner = writer.get_mut();
                inner.flush().map_err(|e| e.to_string())?;
                inner.sync_all().map_err(|e| e.to_string())?;
            }
            drop(writer);

            // Update header
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&tmp_path)
                .map_err(|e| e.to_string())?;
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;

            let mut real_header = [0u8; HEADER_SIZE];
            real_header[0..4].copy_from_slice(MAGIC);
            real_header[4..8].copy_from_slice(&1u32.to_le_bytes());
            real_header[8..12].copy_from_slice(&total_u32.to_le_bytes());
            real_header[12..16].copy_from_slice(&(BUCKET_COUNT as u32).to_le_bytes());

            let mut pos = 16;
            for b in 0..BUCKET_COUNT {
                real_header[pos..pos + 4].copy_from_slice(&bucket_offsets[b].to_le_bytes());
                real_header[pos + 4..pos + 8].copy_from_slice(&bucket_counts[b].to_le_bytes());
                pos += 8;
            }

            file.write_all(&real_header).map_err(|e| e.to_string())?;
            file.flush().map_err(|e| e.to_string())?;
            // fsync file before rename so a crash cannot leave a torn DB.
            file.sync_all().map_err(|e| e.to_string())?;
            drop(file);

            // Atomic rename
            if let Some(parent) = out_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            // On Windows rename cannot replace an existing file, so remove
            // the destination first — but only when it exists.
            if out_path.exists() {
                std::fs::remove_file(out_path).map_err(|e| e.to_string())?;
            }
            std::fs::rename(&tmp_path, out_path).map_err(|e| e.to_string())?;

            Ok(total)
        })();
        if res.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disk_blocklist_build_and_query() {
        let temp_dir = std::env::temp_dir().join(format!("sg_disk_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let db_path = temp_dir.join("test_blocklist.bin");

        let domains = vec![
            "ads.example.com".to_string(),
            "TRACKER.io".to_string(),
            "doubleclick.net".to_string(),
            "malware.badsite.org".to_string(),
        ];

        let count = DiskBlocklist::build(&db_path, domains).expect("build disk blocklist");
        assert_eq!(count, 4);

        let disk = DiskBlocklist::open(&db_path).expect("open disk blocklist");
        assert_eq!(disk.total_domains(), 4);

        assert!(disk.contains("ads.example.com"));
        assert!(disk.contains("Ads.Example.Com"));
        assert!(disk.contains("tracker.io"));
        assert!(disk.contains("TRACKER.IO"));
        assert!(disk.contains("doubleclick.net"));
        assert!(disk.contains("malware.badsite.org"));

        assert!(!disk.contains("example.com"));
        assert!(!disk.contains("not-blocked.com"));
        assert!(!disk.contains("google.com"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_fast_domain_cache() {
        let cache = FastDomainCache::new();
        let h1 = hash_domain("test.com");
        let h2 = hash_domain("safe.org");

        assert_eq!(cache.get(h1), None);
        cache.insert(h1, true);
        cache.insert(h2, false);

        assert_eq!(cache.get(h1), Some(true));
        assert_eq!(cache.get(h2), Some(false));

        cache.clear();
        assert_eq!(cache.get(h1), None);
    }
}
