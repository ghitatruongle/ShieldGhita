use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldGhitaBackupPackage {
    pub app_version: String,
    pub created_at: String,
    pub config_toml: String,
    pub custom_blocked_domains: Vec<String>,
    pub custom_allowed_domains: Vec<String>,
    pub known_devices: Vec<String>,
    pub checksum: u32,
}

pub struct ConfigBackupManager;

impl ConfigBackupManager {
    /// Length-prefixed byte-sum over the package fields. NOTE: this is still
    /// not a MAC — it detects corruption / casual edits only, not a hostile
    /// editor. Do not treat backups as authenticated.
    /// TODO(security): migrate to HMAC-SHA256 with a machine-bound key or
    /// an authenticated container if backups ever leave the local machine.
    fn checksum(cfg_toml: &str, blocked: &[String], allowed: &[String], devices: &[String]) -> u32 {
        let mut sum: u32 = 0;
        let mut feed = |bytes: &[u8]| {
            // Length-prefix each field so ("ab","c") != ("a","bc").
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

        let pkg = ShieldGhitaBackupPackage {
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: chrono::Local::now().to_rfc3339(),
            config_toml: cfg_toml.to_string(),
            custom_blocked_domains: blocked.to_vec(),
            custom_allowed_domains: allowed.to_vec(),
            known_devices: devices.to_vec(),
            checksum: sum,
        };

        let json = serde_json::to_string_pretty(&pkg).map_err(|e| e.to_string())?;

        // Collision-proof name (second-granularity timestamps collide on
        // rapid double-click) + create_new loop so concurrent callers never
        // clobber each other.
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
    /// Verifies the integrity checksum and validates the embedded config
    /// before handing the package back to the caller.
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
