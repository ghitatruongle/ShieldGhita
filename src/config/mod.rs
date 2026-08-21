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
    #[serde(default = "default_true")]
    pub start_with_windows: bool,
    #[serde(default = "default_true")]
    pub minimize_to_tray: bool,
    #[serde(default = "default_language")]
    pub language: String,
    #[serde(default = "default_true")]
    pub enable_block_notifications: bool,
    pub log_max_entries: usize,
    pub auto_update_blocklist_hours: u64,
    pub last_blocklist_update: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_language() -> String {
    "vi".to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            dns_listen_addr: "127.0.0.1".to_string(),
            dns_listen_port: 53,
            upstream_dns: vec![
                "https://1.1.1.1/dns-query".to_string(),
                "https://8.8.8.8/dns-query".to_string(),
                "https://9.9.9.9/dns-query".to_string(),
            ],
            blocklist_urls: vec![
                "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt".to_string(),
                "https://small.oisd.nl".to_string(),
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
                "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt".to_string(),
            ],
            custom_blocked_domains: Vec::new(),
            custom_allowed_domains: Vec::new(),
            protection_enabled: true,
            start_with_windows: true,
            minimize_to_tray: true,
            language: "vi".to_string(),
            enable_block_notifications: true,
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
        let mut config = if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => toml::from_str(&content).unwrap_or_default(),
                Err(_) => Self::default(),
            }
        } else {
            let config = Self::default();
            let _ = config.save();
            config
        };

        if config.dns_listen_port == 5353 {
            config.dns_listen_port = 53;
            let _ = config.save();
        }

        config
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

    pub fn set_autostart_registry(enable: bool) {
        let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("shield_ghita.exe"));
        let exe_str = exe_path.to_string_lossy().to_string();

        let mut cmd = std::process::Command::new("reg");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
        }
        if enable {
            cmd.args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "ShieldGhita",
                "/t",
                "REG_SZ",
                "/d",
                &format!("\"{}\"", exe_str),
                "/f",
            ]);
        } else {
            cmd.args([
                "delete",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "ShieldGhita",
                "/f",
            ]);
        }
        let _ = cmd.output();
    }
}
