use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub dns_listen_addr: String,
    pub dns_listen_port: u16,
    pub upstream_dns: Vec<String>,
    pub blocklist_urls: Vec<String>,
    pub custom_blocked_domains: Vec<String>,
    pub custom_allowed_domains: Vec<String>,
    pub protection_enabled: bool,
    pub log_max_entries: usize,
    pub auto_update_blocklist_hours: u64,
    pub last_blocklist_update: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            dns_listen_addr: "127.0.0.1".to_string(),
            dns_listen_port: 5353,
            upstream_dns: vec![
                "https://dns.cloudflare.com/dns-query".to_string(),
                "https://dns.google/dns-query".to_string(),
            ],
            blocklist_urls: vec![
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
                "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt".to_string(),
            ],
            custom_blocked_domains: Vec::new(),
            custom_allowed_domains: Vec::new(),
            protection_enabled: true,
            log_max_entries: 1000,
            auto_update_blocklist_hours: 24,
            last_blocklist_update: None,
        }
    }
}

impl AppConfig {
    pub fn config_path() -> PathBuf {
        let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(app_data).join("ShieldGhita").join("config.toml")
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => toml::from_str(&content).unwrap_or_default(),
                Err(_) => Self::default(),
            }
        } else {
            let config = Self::default();
            let _ = config.save();
            config
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}

