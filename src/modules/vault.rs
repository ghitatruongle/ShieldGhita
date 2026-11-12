use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Algorithm;
use argon2::Argon2;
use argon2::Params;
use argon2::Version;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 7] = b"SGVLT1\x01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const MAX_VAULT_BYTES: u64 = 512 * 1024 * 1024;
const ARGON_M_KIB: u32 = 64 * 1024;
const ARGON_T: u32 = 3;
const ARGON_P: u32 = 1;
const VAULT_EXTENSION: &str = "sgvault";

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let params = Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(KEY_LEN))
        .map_err(|e| format!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("argon2: {e}"))?;
    Ok(key)
}

pub struct VaultOutcome {
    pub input: PathBuf,
    pub output: PathBuf,
    pub bytes: u64,
}

pub fn encrypt_file(src: &Path, password: &str) -> Result<VaultOutcome, String> {
    if password.is_empty() {
        return Err(crate::modules::i18n::tr4(
            "Mật khẩu trống",
            "Password is empty",
            "密码为空",
            "Пароль пуст",
        )
        .to_string());
    }
    let meta = fs::metadata(src).map_err(|e| format!("metadata: {e}"))?;
    if !meta.is_file() {
        return Err(crate::modules::i18n::tr4(
            "Đường dẫn không phải tệp",
            "Path is not a file",
            "路径不是文件",
            "Путь не является файлом",
        )
        .to_string());
    }
    if meta.len() > MAX_VAULT_BYTES {
        return Err(crate::modules::i18n::tr4(
            "Tệp vượt 512 MB — vượt giới hạn Vault",
            "File exceeds 512 MB — above Vault limit",
            "文件超过 512 MB — 超出 Vault 限制",
            "Файл больше 512 МБ — превышен лимит",
        )
        .to_string());
    }
    let plaintext = fs::read(src).map_err(|e| format!("read: {e}"))?;
    let file_name = src
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|e| format!("salt: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| format!("nonce: {e}"))?;
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("cipher: {e}"))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: file_name.as_bytes(),
            },
        )
        .map_err(|_| "encrypt failed".to_string())?;

    let mut dest = src.to_path_buf();
    let mut new_name = file_name.clone();
    new_name.push('.');
    new_name.push_str(VAULT_EXTENSION);
    dest.set_file_name(new_name);

    let mut blob = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    fs::write(&dest, &blob).map_err(|e| format!("write: {e}"))?;
    crate::modules::security::file_quarantine::secure_delete(src)?;
    Ok(VaultOutcome {
        input: src.to_path_buf(),
        output: dest,
        bytes: meta.len(),
    })
}

pub fn decrypt_file(src: &Path, password: &str) -> Result<VaultOutcome, String> {
    if let Ok(meta) = fs::metadata(src) {
        if meta.len() > MAX_VAULT_BYTES + 4096 {
            return Err("vault blob exceeds the size limit".to_string());
        }
    }
    let blob = fs::read(src).map_err(|e| format!("read: {e}"))?;
    let header_len = MAGIC.len() + SALT_LEN + NONCE_LEN;
    if blob.len() < header_len || &blob[..MAGIC.len()] != MAGIC {
        return Err(crate::modules::i18n::tr4(
            "Không phải tệp .sgvault của ShieldGhita",
            "Not a ShieldGhita .sgvault file",
            "不是 ShieldGhita 的 .sgvault 文件",
            "Это не файл .sgvault от ShieldGhita",
        )
        .to_string());
    }
    let mut cursor = &blob[MAGIC.len()..];
    let salt: [u8; SALT_LEN] = cursor[..SALT_LEN]
        .try_into()
        .map_err(|_| "corrupt salt".to_string())?;
    cursor = &cursor[SALT_LEN..];
    let nonce: [u8; NONCE_LEN] = cursor[..NONCE_LEN]
        .try_into()
        .map_err(|_| "corrupt nonce".to_string())?;
    let ciphertext = &cursor[NONCE_LEN..];

    let raw_name = src
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let original_name = raw_name
        .strip_suffix(VAULT_EXTENSION)
        .and_then(|s| s.strip_suffix('.'))
        .unwrap_or(&raw_name)
        .to_string();
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("cipher: {e}"))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: original_name.as_bytes(),
            },
        )
        .map_err(|_| {
            crate::modules::i18n::tr4(
                "Sai mật khẩu hoặc tệp đã hỏng",
                "Wrong password or file corrupted",
                "密码错误或文件损坏",
                "Неверный пароль или файл повреждён",
            )
            .to_string()
        })?;

    let parent = src.parent().unwrap_or(Path::new("."));
    let mut dest = parent.join(&original_name);
    if dest.exists() {
        dest = parent.join(format!(
            "unlocked_{}_{}",
            chrono::Local::now().format("%Y%m%d_%H%M%S"),
            original_name
        ));
    }
    fs::write(&dest, &plaintext).map_err(|e| format!("write: {e}"))?;
    Ok(VaultOutcome {
        input: src.to_path_buf(),
        output: dest,
        bytes: plaintext.len() as u64,
    })
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 6 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out, depth + 1);
        } else {
            out.push(path);
        }
    }
}

pub struct FolderOutcome {
    pub processed: usize,
    pub failed: usize,
}

pub fn encrypt_folder(dir: &Path, password: &str) -> Result<FolderOutcome, String> {
    if !dir.is_dir() {
        return Err(crate::modules::i18n::tr4(
            "Đường dẫn không phải thư mục",
            "Path is not a folder",
            "路径不是文件夹",
            "Путь не является папкой",
        )
        .to_string());
    }
    let mut files = Vec::new();
    collect_files(dir, &mut files, 0);
    let files: Vec<PathBuf> = files
        .into_iter()
        .filter(|p| p.extension().map(|e| e != VAULT_EXTENSION).unwrap_or(true))
        .collect();
    let mut processed = 0usize;
    let mut failed = 0usize;
    for file in files {
        match encrypt_file(&file, password) {
            Ok(_) => processed += 1,
            Err(_) => failed += 1,
        }
    }
    Ok(FolderOutcome { processed, failed })
}

pub fn decrypt_folder(dir: &Path, password: &str) -> Result<FolderOutcome, String> {
    if !dir.is_dir() {
        return Err(crate::modules::i18n::tr4(
            "Đường dẫn không phải thư mục",
            "Path is not a folder",
            "路径不是文件夹",
            "Путь не является папкой",
        )
        .to_string());
    }
    let mut files = Vec::new();
    collect_files(dir, &mut files, 0);
    let files: Vec<PathBuf> = files
        .into_iter()
        .filter(|p| p.extension().map(|e| e == VAULT_EXTENSION).unwrap_or(false))
        .collect();
    let mut processed = 0usize;
    let mut failed = 0usize;
    for file in files {
        match decrypt_file(&file, password) {
            Ok(_) => processed += 1,
            Err(_) => failed += 1,
        }
    }
    Ok(FolderOutcome { processed, failed })
}

pub fn generate_password(length: usize, include_symbols: bool) -> Result<String, String> {
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"23456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*-_=+?";

    let mut charset = Vec::new();
    charset.extend_from_slice(LOWER);
    charset.extend_from_slice(UPPER);
    charset.extend_from_slice(DIGITS);
    if include_symbols {
        charset.extend_from_slice(SYMBOLS);
    }
    let len = length.clamp(8, 128).max(8);
    let set_len = charset.len() as u32;
    let limit = 256 - (256 % set_len);
    let mut out = String::with_capacity(len);
    let mut rng_byte = [0u8; 1];
    while out.len() < len {
        // Track 2: a CSPRNG failure here previously panicked the whole UI
        // (called straight from a Slint callback) — propagate instead.
        getrandom::fill(&mut rng_byte).map_err(|e| format!("CSPRNG unavailable: {e}"))?;
        let value = rng_byte[0] as u32;
        if value >= limit {
            continue;
        }
        out.push(charset[(value % set_len) as usize] as char);
    }
    Ok(out)
}

pub fn password_strength(password: &str) -> (i32, &'static str) {
    let mut score: i32 = 0;
    let len = password.chars().count();
    score += (len as i32 * 4).min(40);
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());
    for present in [has_lower, has_upper, has_digit, has_symbol] {
        if present {
            score += 12;
        }
    }
    if len >= 16 {
        score += 10;
    }
    if len > 0 && len < 8 {
        score -= 15;
    }
    if has_digit && !has_lower && !has_upper {
        score -= 10;
    }
    let weak_samples = [
        "123456", "password", "admin", "qwerty", "matkhau", "11022010", "888888", "iloveyou",
    ];
    let lowered = password.to_lowercase();
    if weak_samples.iter().any(|w| lowered.contains(w)) {
        score -= 25;
    }
    let score = score.clamp(0, 100);
    let label = if score >= 80 {
        "RẤT MẠNH"
    } else if score >= 55 {
        "MẠNH"
    } else if score >= 30 {
        "TRUNG BÌNH"
    } else {
        "YẾU"
    };
    (score, label)
}

/// SHA-256 hex of arbitrary bytes — used by tests; kept as public vault API.
#[allow(dead_code)]
pub fn content_digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

#[cfg(windows)]
mod clipboard {
    use windows::Win32::Foundation::{HANDLE, HGLOBAL};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

    const CF_UNICODETEXT: u32 = 13u32;

    fn read_clipboard_text() -> Option<String> {
        unsafe {
            let handle: HANDLE = GetClipboardData(CF_UNICODETEXT).ok()?;
            if handle.is_invalid() {
                return None;
            }
            let hglobal = HGLOBAL(handle.0);
            let ptr = GlobalLock(hglobal) as *const u16;
            if ptr.is_null() {
                return None;
            }
            let mut len = 0usize;
            while *ptr.add(len) != 0 {
                len += 1;
                if len > 1 << 20 {
                    break;
                }
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
            let _ = GlobalUnlock(hglobal);
            Some(text)
        }
    }

    pub fn copy_with_autoclear(text: &str, clear_after_secs: u64) -> Result<(), String> {
        unsafe {
            OpenClipboard(None).map_err(|e| format!("open clipboard: {e}"))?;
            let inner = (|| -> Result<(), String> {
                EmptyClipboard().map_err(|e| format!("empty clipboard: {e}"))?;
                let mut units: Vec<u16> = text.encode_utf16().collect();
                units.push(0);
                let byte_len = units.len() * 2;
                let hglobal: HGLOBAL =
                    GlobalAlloc(GMEM_MOVEABLE, byte_len).map_err(|e| format!("alloc: {e}"))?;
                let dst = GlobalLock(hglobal) as *mut u16;
                if dst.is_null() {
                    return Err("lock failed".to_string());
                }
                std::ptr::copy_nonoverlapping(units.as_ptr(), dst, units.len());
                let _ = GlobalUnlock(hglobal);
                SetClipboardData(CF_UNICODETEXT, HANDLE(hglobal.0))
                    .map_err(|e| format!("set: {e}"))?;
                Ok(())
            })();
            let _ = CloseClipboard();
            inner?;
        }
        let owned = text.to_string();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(clear_after_secs));
            unsafe {
                if OpenClipboard(None).is_ok() {
                    if read_clipboard_text().as_deref() == Some(owned.as_str()) {
                        let _ = EmptyClipboard();
                    }
                    let _ = CloseClipboard();
                }
            }
        });
        Ok(())
    }
}

#[cfg(not(windows))]
mod clipboard {
    pub fn copy_with_autoclear(_text: &str, _clear_after_secs: u64) -> Result<(), String> {
        Err("clipboard is only supported on Windows".to_string())
    }
}

pub fn copy_password_to_clipboard(password: &str) -> Result<(), String> {
    clipboard::copy_with_autoclear(password, 30)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sg_vault_{}",
            chrono::Local::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dir = temp_dir();
        let src = dir.join("secret.txt");
        fs::write(&src, b"ShieldGhita vault payload 123").unwrap();
        let outcome = encrypt_file(&src, "Master#Pass-2026").expect("encrypt must succeed");
        assert!(!outcome.input.exists());
        assert!(outcome.output.extension().unwrap() == VAULT_EXTENSION);
        let restored =
            decrypt_file(&outcome.output, "Master#Pass-2026").expect("decrypt must succeed");
        let content = fs::read(&restored.output).unwrap();
        assert_eq!(content, b"ShieldGhita vault payload 123");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_wrong_password_rejected() {
        let dir = temp_dir();
        let src = dir.join("doc.bin");
        fs::write(&src, b"data").unwrap();
        let sealed = encrypt_file(&src, "correct-horse").unwrap();
        assert!(decrypt_file(&sealed.output, "wrong").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let dir = temp_dir();
        let src = dir.join("tamper.bin");
        fs::write(&src, b"payload").unwrap();
        let sealed = encrypt_file(&src, "pw-123456").unwrap();
        let mut blob = fs::read(&sealed.output).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        fs::write(&sealed.output, &blob).unwrap();
        assert!(decrypt_file(&sealed.output, "pw-123456").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_folder_encrypt_decrypt_cycle() {
        let dir = temp_dir();
        let sub = dir.join("nested");
        fs::create_dir_all(&sub).unwrap();
        fs::write(dir.join("a.txt"), b"AAA").unwrap();
        fs::write(sub.join("b.txt"), b"BBB").unwrap();
        let encrypted = encrypt_folder(&dir, "folder-pass").unwrap();
        assert_eq!(encrypted.processed, 2);
        assert_eq!(encrypted.failed, 0);
        let decrypted = decrypt_folder(&dir, "folder-pass").unwrap();
        assert_eq!(decrypted.processed, 2);
        assert_eq!(fs::read(dir.join("a.txt")).unwrap(), b"AAA");
        assert_eq!(fs::read(sub.join("b.txt")).unwrap(), b"BBB");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_password_length_charset_and_uniqueness() {
        // Track 2: generate_password now returns Result — unwrap in tests.
        let a = generate_password(24, true).unwrap();
        let b = generate_password(24, true).unwrap();
        assert_eq!(a.len(), 24);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_graphic()));
        assert!(generate_password(4, false).unwrap().len() >= 8);
    }

    #[test]
    fn test_password_strength_orders_clearly() {
        let (weak, weak_label) = password_strength("123456");
        let (strong, strong_label) = password_strength("Tr0ng!Vault-2026#ShieldGhita");
        assert!(weak < strong);
        assert_eq!(strong_label, "RẤT MẠNH");
        assert!(matches!(weak_label, "YẾU" | "TRUNG BÌNH"));
    }

    #[test]
    fn test_derive_key_is_deterministic_and_salt_sensitive() {
        let k1 = derive_key("pw", b"0123456789abcdef").unwrap();
        let k2 = derive_key("pw", b"0123456789abcdef").unwrap();
        let k3 = derive_key("pw", b"fedcba9876543210").unwrap();
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_content_digest_matches_sha256() {
        assert_eq!(
            content_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
