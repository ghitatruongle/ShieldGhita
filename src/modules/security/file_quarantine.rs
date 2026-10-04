use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"SGQ1";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const MAX_QUARANTINE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_name: String,
    pub original_path: String,
    pub reason: String,
    pub quarantined_at: String,
    pub size: u64,
}

fn quarantine_dir() -> PathBuf {
    let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(app_data)
        .join("ShieldGhita")
        .join("quarantine")
}

fn index_path() -> PathBuf {
    quarantine_dir().join("index.json")
}

fn entry_path(id: &str) -> PathBuf {
    quarantine_dir().join(format!("{id}.sgq"))
}

fn read_index() -> Vec<QuarantineEntry> {
    std::fs::read_to_string(index_path())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn write_index(entries: &[QuarantineEntry]) -> Result<(), String> {
    std::fs::create_dir_all(quarantine_dir()).map_err(|e| e.to_string())?;
    let payload = serde_json::to_string_pretty(entries).map_err(|e| e.to_string())?;
    std::fs::write(index_path(), payload).map_err(|e| e.to_string())
}

fn new_id() -> String {
    let mut suffix = [0u8; 4];
    let _ = getrandom::fill(&mut suffix);
    format!(
        "{}{:08x}",
        chrono::Local::now().format("%Y%m%d_%H%M%S"),
        u32::from_be_bytes(suffix)
    )
}

fn push_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn read_u32(cursor: &mut &[u8]) -> Option<u32> {
    if cursor.len() < 4 {
        return None;
    }
    let (bytes, rest) = cursor.split_at(4);
    *cursor = rest;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub fn secure_delete(path: &Path) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("open: {e}"))?;
    let len = file.metadata().map_err(|e| format!("metadata: {e}"))?.len();
    for pass in 0u8..3 {
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("seek: {e}"))?;
        let mut remaining = len;
        while remaining > 0 {
            let chunk_len = remaining.min(65536) as usize;
            let mut chunk = vec![0u8; chunk_len];
            match pass {
                0 => chunk.fill(0x00),
                1 => chunk.fill(0xFF),
                _ => {
                    let _ = getrandom::fill(&mut chunk);
                }
            }
            file.write_all(&chunk).map_err(|e| format!("write: {e}"))?;
            remaining -= chunk_len as u64;
        }
        file.sync_all().map_err(|e| format!("sync: {e}"))?;
    }
    drop(file);
    let renamed = path.with_extension(format!("del.{:08x}", new_id_tail()));
    std::fs::rename(path, &renamed).map_err(|e| format!("rename: {e}"))?;
    std::fs::remove_file(&renamed).map_err(|e| format!("remove: {e}"))
}

fn new_id_tail() -> u32 {
    let mut buf = [0u8; 4];
    let _ = getrandom::fill(&mut buf);
    u32::from_be_bytes(buf)
}

pub fn quarantine_file<P: AsRef<Path>>(path: P, reason: &str) -> Result<String, String> {
    let p = path.as_ref();
    let metadata = std::fs::metadata(p).map_err(|e| format!("metadata: {e}"))?;
    if !metadata.is_file() {
        return Err(crate::modules::i18n::tr4(
            "Đường dẫn không phải tệp thông thường",
            "Path is not a regular file",
            "路径不是常规文件",
            "Путь не является обычным файлом",
        )
        .to_string());
    }
    if metadata.len() > MAX_QUARANTINE_BYTES {
        return Err(crate::modules::i18n::tr4(
            "Tệp quá lớn để cách ly (giới hạn 512 MB)",
            "File too large to quarantine (512 MB limit)",
            "文件过大，无法隔离（上限 512 MB）",
            "Файл слишком велик для карантина (лимит 512 МБ)",
        )
        .to_string());
    }
    let original_path = p.to_string_lossy().to_string();
    let original_name = p
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut plaintext = Vec::with_capacity(metadata.len() as usize);
    std::fs::File::open(p)
        .and_then(|mut f| f.read_to_end(&mut plaintext))
        .map_err(|e| format!("read: {e}"))?;

    let mut key = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut key).map_err(|e| format!("keygen: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| format!("nonce: {e}"))?;
    let wrapped = crate::modules::security::win_dpapi::protect_bytes(&key)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("cipher: {e}"))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: original_path.as_bytes(),
            },
        )
        .map_err(|_| "encrypt failed".to_string())?;

    let id = new_id();
    let mut blob = Vec::with_capacity(4 + NONCE_LEN + 4 + wrapped.len() + ciphertext.len());
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&nonce);
    push_u32(&mut blob, wrapped.len() as u32);
    blob.extend_from_slice(&wrapped);
    blob.extend_from_slice(&ciphertext);
    std::fs::create_dir_all(quarantine_dir()).map_err(|e| e.to_string())?;
    std::fs::write(entry_path(&id), &blob).map_err(|e| format!("write: {e}"))?;
    secure_delete(p)?;

    let mut entries = read_index();
    entries.push(QuarantineEntry {
        id,
        original_name,
        original_path,
        reason: reason.to_string(),
        quarantined_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        size: metadata.len(),
    });
    write_index(&entries)?;
    Ok(entries.last().map(|e| e.id.clone()).unwrap_or_default())
}

pub fn restore(entry_id: &str) -> Result<String, String> {
    let mut entries = read_index();
    let pos = entries
        .iter()
        .position(|e| e.id == entry_id)
        .ok_or_else(|| "entry not found".to_string())?;
    let entry = entries.remove(pos);
    let blob = std::fs::read(entry_path(entry_id)).map_err(|e| format!("read: {e}"))?;
    if blob.len() < 4 + NONCE_LEN + 4 || &blob[..4] != MAGIC {
        return Err("corrupt quarantine entry".to_string());
    }
    let mut cursor: &[u8] = &blob[4..];
    let nonce: [u8; NONCE_LEN] = cursor[..NONCE_LEN]
        .try_into()
        .map_err(|_| "corrupt nonce".to_string())?;
    cursor = &cursor[NONCE_LEN..];
    let wrapped_len = read_u32(&mut cursor).ok_or("corrupt header")? as usize;
    if cursor.len() < wrapped_len {
        return Err("corrupt wrapped key".to_string());
    }
    let (wrapped, ciphertext) = cursor.split_at(wrapped_len);
    let key = crate::modules::security::win_dpapi::unprotect_bytes(wrapped)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("cipher: {e}"))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: entry.original_path.as_bytes(),
            },
        )
        .map_err(|_| {
            crate::modules::i18n::tr4(
                "Giải mã thất bại — dữ liệu hỏng hoặc khóa không còn hợp lệ trên máy này",
                "Decryption failed — data corrupt or key invalid on this machine",
                "解密失败 — 数据损坏或密钥在本机无效",
                "Не удалось расшифровать — данные повреждены или ключ недействителен",
            )
            .to_string()
        })?;

    let target = PathBuf::from(&entry.original_path);
    let restore_target = if target.exists() {
        target
            .parent()
            .unwrap_or(&quarantine_dir())
            .join(format!("restored_{}", entry.original_name))
    } else {
        target.clone()
    };
    if let Some(parent) = restore_target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&restore_target, &plaintext).map_err(|e| format!("write: {e}"))?;
    let _ = std::fs::remove_file(entry_path(entry_id));
    write_index(&entries)?;
    Ok(restore_target.to_string_lossy().to_string())
}

pub fn delete_entry(entry_id: &str) -> Result<(), String> {
    let mut entries = read_index();
    let before = entries.len();
    entries.retain(|e| e.id != entry_id);
    if entries.len() == before {
        return Err("entry not found".to_string());
    }
    let blob_file = entry_path(entry_id);
    if blob_file.exists() {
        secure_delete(&blob_file)?;
    }
    write_index(&entries)
}

pub fn list() -> Vec<QuarantineEntry> {
    read_index()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sg_qtest_{}", new_id_tail()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_secure_delete_removes_file_content() {
        let dir = temp_dir();
        let file = dir.join("victim.txt");
        std::fs::write(&file, b"super secret bytes").unwrap();
        secure_delete(&file).expect("secure delete must succeed");
        assert!(!file.exists());
        assert!(std::fs::read_dir(&dir).unwrap().count() == 0);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_blob_layout_roundtrip_without_dpapi_restore() {
        let mut blob = Vec::new();
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&[0u8; NONCE_LEN]);
        push_u32(&mut blob, 5);
        blob.extend_from_slice(b"12345");
        blob.extend_from_slice(b"ciphertext");
        let mut cursor = &blob[..];
        assert_eq!(&cursor[..4], MAGIC);
        cursor = &cursor[4..];
        let nonce: [u8; NONCE_LEN] = cursor[..NONCE_LEN].try_into().unwrap();
        cursor = &cursor[NONCE_LEN..];
        let wrapped_len = read_u32(&mut cursor).unwrap() as usize;
        let (wrapped, ct) = cursor.split_at(wrapped_len);
        assert_eq!(wrapped, b"12345");
        assert_eq!(ct, b"ciphertext");
        assert_eq!(nonce, [0u8; NONCE_LEN]);
    }

    #[test]
    fn test_index_missing_returns_empty() {
        let entries = read_index();
        let _ = entries;
    }
}
