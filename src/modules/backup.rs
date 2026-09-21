use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldGhitaBackupPackage {
    pub app_version: String,
    pub created_at: String,
    pub config_toml: String,
    pub custom_blocked_domains: Vec<String>,
    pub custom_allowed_domains: Vec<String>,
    pub known_devices: Vec<String>,
    /// Legacy length-prefixed byte-sum (pre-HMAC packages). Kept for restore.
    pub checksum: u32,
    /// Hex HMAC-SHA256 over package fields, keyed by a machine-bound secret.
    /// Absent on packages written before v0.1.1-alpha.
    #[serde(default)]
    pub mac: Option<String>,
}

pub struct ConfigBackupManager;

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let hashed = Sha256::digest(key);
        k[..hashed.len()].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let out = outer.finalize();
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&out);
    mac
}

fn wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn machine_bound_key() -> Vec<u8> {
    let mut material = Vec::new();
    #[cfg(windows)]
    {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
        };
        let subkey = wide_nul(r"SOFTWARE\Microsoft\Cryptography");
        let value = wide_nul("MachineGuid");
        unsafe {
            let mut hkey = Default::default();
            let open = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                0,
                KEY_READ,
                &mut hkey,
            );
            if open.is_ok() {
                let mut buf = [0u16; 128];
                let mut len = (buf.len() * 2) as u32;
                let mut ty = REG_SZ;
                let q = RegQueryValueExW(
                    hkey,
                    PCWSTR(value.as_ptr()),
                    None,
                    Some(&mut ty),
                    Some(buf.as_mut_ptr() as *mut u8),
                    Some(&mut len),
                );
                let _ = RegCloseKey(hkey);
                // REG_SZ length includes the trailing NUL in bytes.
                if q.is_ok() {
                    let nchars = (len as usize / 2).saturating_sub(1);
                    let guid: String = String::from_utf16_lossy(&buf[..nchars.min(buf.len())]);
                    let guid = guid.trim_end_matches('\0').trim().to_string();
                    if !guid.is_empty() {
                        material.extend_from_slice(b"SG-BACKUP-MAC-v1|MachineGuid|");
                        material.extend_from_slice(guid.as_bytes());
                    }
                }
            }
        }
    }
    if material.is_empty() {
        let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown-host".into());
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "unknown-user".into());
        material.extend_from_slice(b"SG-BACKUP-MAC-v1|fallback|");
        material.extend_from_slice(host.as_bytes());
        material.push(b'|');
        material.extend_from_slice(user.as_bytes());
    }
    material
}

fn mac_payload(
    cfg_toml: &str,
    blocked: &[String],
    allowed: &[String],
    devices: &[String],
    created_at: &str,
    app_version: &str,
) -> Vec<u8> {
    let mut msg = Vec::new();
    let mut feed = |bytes: &[u8]| {
        msg.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        msg.extend_from_slice(bytes);
    };
    feed(app_version.as_bytes());
    feed(created_at.as_bytes());
    feed(cfg_toml.as_bytes());
    for s in blocked.iter().chain(allowed.iter()).chain(devices.iter()) {
        feed(s.as_bytes());
    }
    msg
}

impl ConfigBackupManager {
    /// Legacy length-prefixed byte-sum. Corruption detection only — not a MAC.
    fn checksum(cfg_toml: &str, blocked: &[String], allowed: &[String], devices: &[String]) -> u32 {
        let mut sum: u32 = 0;
        let mut feed = |bytes: &[u8]| {
            sum = sum.wrapping_add(bytes.len() as u32);
            sum = sum.wrapping_mul(31);
            for b in bytes {
                sum = sum.wrapping_add(*b as u32);
                sum = sum.wrapping_mul(31);
            }
        };
        feed(cfg_toml.as_bytes());
        for s in blocked.iter().chain(allowed.iter()).chain(devices.iter()) {
            feed(s.as_bytes());
        }
        sum
    }

    fn compute_mac(
        cfg_toml: &str,
        blocked: &[String],
        allowed: &[String],
        devices: &[String],
        created_at: &str,
        app_version: &str,
    ) -> String {
        let key = machine_bound_key();
        let msg = mac_payload(cfg_toml, blocked, allowed, devices, created_at, app_version);
        hmac_sha256(&key, &msg)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Exports current configuration and custom rules into a `.sgconfig` backup file
    pub fn create_backup(
        cfg_toml: &str,
        blocked: &[String],
        allowed: &[String],
        devices: &[String],
    ) -> Result<PathBuf, String> {
        let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        let backup_dir = PathBuf::from(app_data).join("ShieldGhita").join("backups");
        let _ = fs::create_dir_all(&backup_dir);

        let sum = Self::checksum(cfg_toml, blocked, allowed, devices);
        let app_version = env!("CARGO_PKG_VERSION").to_string();
        let created_at = chrono::Local::now().to_rfc3339();
        let mac = Self::compute_mac(
            cfg_toml,
            blocked,
            allowed,
            devices,
            &created_at,
            &app_version,
        );

        let pkg = ShieldGhitaBackupPackage {
            app_version,
            created_at,
            config_toml: cfg_toml.to_string(),
            custom_blocked_domains: blocked.to_vec(),
            custom_allowed_domains: allowed.to_vec(),
            known_devices: devices.to_vec(),
            checksum: sum,
            mac: Some(mac),
        };

        let json = serde_json::to_string_pretty(&pkg).map_err(|e| e.to_string())?;

        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let pid = std::process::id();
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_millis())
            .unwrap_or(0);
        for attempt in 0..100 {
            let filename = if attempt == 0 {
                format!("shieldghita_backup_{timestamp}_{pid}_{millis:03}.sgconfig")
            } else {
                format!("shieldghita_backup_{timestamp}_{pid}_{millis:03}_{attempt}.sgconfig")
            };
            let target_path = backup_dir.join(filename);
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target_path)
            {
                Ok(mut f) => {
                    use std::io::Write;
                    f.write_all(json.as_bytes()).map_err(|e| e.to_string())?;
                    info!("Created configuration backup at {:?}", target_path);
                    return Ok(target_path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("Could not allocate a unique backup filename".to_string())
    }

    /// Restores configuration from a `.sgconfig` file.
    /// New packages must carry a valid machine-bound HMAC; pre-alpha packages
    /// fall back to the legacy checksum with an explicit warning.
    pub fn load_backup(path: &Path) -> Result<ShieldGhitaBackupPackage, String> {
        let content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read backup file: {}", e))?;
        let pkg: ShieldGhitaBackupPackage =
            serde_json::from_str(&content).map_err(|e| format!("Invalid backup format: {}", e))?;

        let sum = Self::checksum(
            &pkg.config_toml,
            &pkg.custom_blocked_domains,
            &pkg.custom_allowed_domains,
            &pkg.known_devices,
        );
        if sum != pkg.checksum {
            return Err(
                "Backup checksum mismatch — the file is corrupted or was modified".to_string(),
            );
        }

        match &pkg.mac {
            Some(expected) => {
                let actual = Self::compute_mac(
                    &pkg.config_toml,
                    &pkg.custom_blocked_domains,
                    &pkg.custom_allowed_domains,
                    &pkg.known_devices,
                    &pkg.created_at,
                    &pkg.app_version,
                );
                if !expected.eq_ignore_ascii_case(&actual) {
                    return Err(
                        "Backup HMAC verification failed — file was modified or was created on another machine"
                            .to_string(),
                    );
                }
            }
            None => {
                warn!(
                    "Backup {:?} has no HMAC (legacy package); accepting on checksum only",
                    path
                );
            }
        }

        if toml::from_str::<crate::modules::config::AppConfig>(&pkg.config_toml).is_err() {
            return Err(
                "Backup config section is not a valid ShieldGhita configuration".to_string(),
            );
        }

        info!(
            "Successfully loaded backup package from {:?} (created: {})",
            path, pkg.created_at
        );
        Ok(pkg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_is_deterministic_and_key_sensitive() {
        let msg = b"payload";
        let a = hmac_sha256(b"key-one", msg);
        let b = hmac_sha256(b"key-one", msg);
        let c = hmac_sha256(b"key-two", msg);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn mac_payload_length_prefixes_prevent_concatenation_ambiguity() {
        let p1 = mac_payload("ab", &["c".into()], &[], &[], "t", "v");
        let p2 = mac_payload("a", &["bc".into()], &[], &[], "t", "v");
        assert_ne!(p1, p2);
    }

    #[test]
    fn package_roundtrip_accepts_new_mac_field() {
        let blocked = vec!["ads.example.com".to_string()];
        let allowed = vec![];
        let devices = vec![];
        let cfg = "language = \"en\"\n";
        let created = "2026-01-01T00:00:00+00:00";
        let ver = "0.1.1-alpha";
        let sum = ConfigBackupManager::checksum(cfg, &blocked, &allowed, &devices);
        let mac = ConfigBackupManager::compute_mac(cfg, &blocked, &allowed, &devices, created, ver);
        let pkg = ShieldGhitaBackupPackage {
            app_version: ver.to_string(),
            created_at: created.to_string(),
            config_toml: cfg.to_string(),
            custom_blocked_domains: blocked,
            custom_allowed_domains: allowed,
            known_devices: devices,
            checksum: sum,
            mac: Some(mac.clone()),
        };
        let json = serde_json::to_string_pretty(&pkg).unwrap();
        let parsed: ShieldGhitaBackupPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mac.as_deref(), Some(mac.as_str()));
    }

    #[test]
    fn legacy_package_without_mac_field_deserializes() {
        let json = r#"{
            "app_version": "0.1.0",
            "created_at": "2026-01-01T00:00:00+00:00",
            "config_toml": "",
            "custom_blocked_domains": [],
            "custom_allowed_domains": [],
            "known_devices": [],
            "checksum": 0
        }"#;
        let pkg: ShieldGhitaBackupPackage = serde_json::from_str(json).unwrap();
        assert!(pkg.mac.is_none());
    }

    #[test]
    fn mac_detects_tampered_config() {
        let blocked = vec![];
        let allowed = vec![];
        let devices = vec![];
        let cfg = "language = \"en\"\n";
        let created = "2026-01-01T00:00:00+00:00";
        let ver = "0.1.1-alpha";
        let good =
            ConfigBackupManager::compute_mac(cfg, &blocked, &allowed, &devices, created, ver);
        let evil = ConfigBackupManager::compute_mac(
            "language = \"vi\"\n",
            &blocked,
            &allowed,
            &devices,
            created,
            ver,
        );
        assert_ne!(good, evil);
    }
}
