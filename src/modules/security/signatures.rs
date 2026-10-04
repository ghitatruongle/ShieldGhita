use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};

const MAX_SIGNATURE_DB_BYTES: usize = 4 * 1024 * 1024;

fn eicar_mark() -> Vec<u8> {
    let mut mark = Vec::new();
    mark.extend_from_slice(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR");
    mark.extend_from_slice(b"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
    mark
}

fn builtin_hashes() -> HashSet<String> {
    let mut set = HashSet::new();
    set.insert("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string());
    set
}

fn signature_store_path() -> PathBuf {
    let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(app_data)
        .join("ShieldGhita")
        .join("signatures.json")
}

static DB: OnceLock<RwLock<Arc<HashSet<String>>>> = OnceLock::new();

fn parse_db_text(text: &str) -> HashSet<String> {
    let mut set = builtin_hashes();
    for line in text.lines() {
        let entry = line
            .split('#')
            .next()
            .unwrap_or(line)
            .trim()
            .trim_matches(',')
            .trim_matches('"')
            .to_ascii_lowercase();
        if entry.len() == 64 && entry.bytes().all(|b| b.is_ascii_hexdigit()) {
            set.insert(entry);
        }
    }
    set
}

fn load() -> Arc<HashSet<String>> {
    let mut set = builtin_hashes();
    if let Ok(text) = std::fs::read_to_string(signature_store_path()) {
        if text.len() <= MAX_SIGNATURE_DB_BYTES {
            set.extend(parse_db_text(&text));
        }
    }
    Arc::new(set)
}

fn db_ref() -> Arc<HashSet<String>> {
    let cell = DB.get_or_init(|| RwLock::new(load()));
    cell.read()
        .map(|guard| guard.clone())
        .unwrap_or_else(|_| Arc::new(builtin_hashes()))
}

pub fn lookup_hash(sha256_hex: &str) -> bool {
    db_ref().contains(&sha256_hex.to_ascii_lowercase())
}

pub fn contains_eicar_mark(content: &[u8]) -> bool {
    let mark = eicar_mark();
    content
        .windows(mark.len())
        .any(|window| window == mark.as_slice())
}

pub fn reload() {
    if let Some(cell) = DB.get() {
        if let Ok(mut guard) = cell.write() {
            *guard = load();
        }
    }
}

pub fn count() -> usize {
    db_ref().len()
}

pub async fn update_from_url(client: &reqwest::Client, url: &str) -> Result<usize, String> {
    let resp = client
        .get(url)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("{url}: HTTP {}", resp.status()));
    }
    let bytes = resp.bytes().await.map_err(|e| format!("{url}: {e}"))?;
    if bytes.len() > MAX_SIGNATURE_DB_BYTES {
        return Err(format!(
            "{url}: signature DB too large ({} bytes)",
            bytes.len()
        ));
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let parsed = parse_db_text(&text);
    let total = parsed.len();
    let store = signature_store_path();
    if let Some(parent) = store.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let joined: Vec<String> = parsed.into_iter().collect();
    let payload = serde_json::to_string(&joined).map_err(|e| e.to_string())?;
    std::fs::write(&store, payload).map_err(|e| e.to_string())?;
    reload();
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_eicar_mark_hash_matches_builtin_signature() {
        let digest = Sha256::digest(eicar_mark());
        let hex = format!("{:x}", digest);
        assert!(builtin_hashes().contains(&hex));
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn test_lookup_finds_builtin_signature() {
        let digest = Sha256::digest(eicar_mark());
        let hex = format!("{:x}", digest);
        assert!(lookup_hash(&hex));
        assert!(!lookup_hash(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_contains_eicar_mark_finds_prefix_overlap() {
        let mut content = b"hello world ".to_vec();
        content.extend_from_slice(&eicar_mark());
        content.extend_from_slice(b" trailing");
        assert!(contains_eicar_mark(&content));
        assert!(!contains_eicar_mark(b"clean content"));
    }

    #[test]
    fn test_parse_db_text_accepts_hashes_and_skips_comments() {
        let parsed = parse_db_text(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\n# comment\nnot-a-hash\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
        );
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }
}
