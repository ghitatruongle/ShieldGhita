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

        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let filename = format!("shieldghita_backup_{}.sgconfig", timestamp);
        let target_path = backup_dir.join(filename);

        let mut sum: u32 = 0;
        for b in cfg_toml.bytes() {
            sum = sum.wrapping_add(b as u32);
        }

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
        fs::write(&target_path, json).map_err(|e| e.to_string())?;

        info!("Created configuration backup at {:?}", target_path);
        Ok(target_path)
    }

    /// Restores configuration from a `.sgconfig` file.
    /// Verifies the integrity checksum and validates the embedded config
    /// before handing the package back to the caller.
    pub fn load_backup(path: &Path) -> Result<ShieldGhitaBackupPackage, String> {
        let content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read backup file: {}", e))?;
        let pkg: ShieldGhitaBackupPackage =
            serde_json::from_str(&content).map_err(|e| format!("Invalid backup format: {}", e))?;

        let mut sum: u32 = 0;
        for b in pkg.config_toml.bytes() {
            sum = sum.wrapping_add(b as u32);
        }
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
