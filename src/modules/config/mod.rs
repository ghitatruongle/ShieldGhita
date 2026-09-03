use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_listen_addr")]
    pub dns_listen_addr: String,
    #[serde(default = "default_listen_port")]
    pub dns_listen_port: u16,
    #[serde(default = "default_upstream_dns")]
    pub upstream_dns: Vec<String>,
    #[serde(default = "default_blocklist_urls")]
    pub blocklist_urls: Vec<String>,
    #[serde(default)]
    pub custom_blocked_domains: Vec<String>,
    #[serde(default)]
    pub custom_allowed_domains: Vec<String>,
    #[serde(default = "default_true")]
    pub protection_enabled: bool,
    #[serde(default = "default_true")]
    pub start_with_windows: bool,
    #[serde(default = "default_true")]
    pub minimize_to_tray: bool,
    #[serde(default = "default_language")]
    pub language: String,
    #[serde(default = "default_true")]
    pub enable_block_notifications: bool,
    #[serde(default = "default_log_max_entries")]
    pub log_max_entries: usize,
    #[serde(default = "default_auto_update_hours")]
    pub auto_update_blocklist_hours: u64,
    #[serde(default)]
    pub last_blocklist_update: Option<String>,
    #[serde(default = "default_false")]
    pub network_wide_adblock_enabled: bool,
    #[serde(default = "default_false")]
    pub attack_detection_enabled: bool,
    #[serde(default = "default_false")]
    pub auto_block_attacks: bool,
    #[serde(default = "default_false")]
    pub arp_spoof_detection: bool,
    #[serde(default = "default_rate_limit")]
    pub dns_flood_rate_limit: u32,
    #[serde(default = "default_window_width")]
    pub window_width: u32,
    #[serde(default = "default_window_height")]
    pub window_height: u32,
    #[serde(default = "default_window_coord")]
    pub window_x: i32,
    #[serde(default = "default_window_coord")]
    pub window_y: i32,
    #[serde(default)]
    pub window_maximized: bool,
    #[serde(default = "default_true")]
    pub minimize_to_tray_on_minimize: bool,
    #[serde(default)]
    pub start_hidden_in_tray: bool,
    /// Admin Edition only: serve the LAN web panel on port 2525.
    /// Toggling requires an app restart (the listener binds once at startup).
    #[serde(default = "default_true")]
    pub admin_panel_enabled: bool,
    /// RAM Map: automatically purge the standby list when free RAM drops
    /// below the threshold. Off by default — the manual buttons always work.
    #[serde(default)]
    pub rammap_auto_clean_enabled: bool,
    /// Free-RAM threshold (MB) that triggers the RAM Map auto-clean purge.
    #[serde(default = "default_ram_clean_threshold_mb")]
    pub rammap_auto_clean_threshold_mb: u64,
}

fn default_ram_clean_threshold_mb() -> u64 {
    512
}

fn default_listen_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_listen_port() -> u16 {
    53
}

fn default_upstream_dns() -> Vec<String> {
    vec![
        "https://1.1.1.1/dns-query".to_string(),
        "https://8.8.8.8/dns-query".to_string(),
        "https://9.9.9.9/dns-query".to_string(),
    ]
}

fn default_blocklist_urls() -> Vec<String> {
    vec![
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt".to_string(),
        "https://small.oisd.nl".to_string(),
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
        "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt".to_string(),
        "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts".to_string(),
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt".to_string(),
    ]
}

fn default_log_max_entries() -> usize {
    1000
}

fn default_auto_update_hours() -> u64 {
    24
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_rate_limit() -> u32 {
    80
}

fn default_window_width() -> u32 {
    1160
}

fn default_window_height() -> u32 {
    800
}

fn default_window_coord() -> i32 {
    -1
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
                "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt"
                    .to_string(),
                "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts".to_string(),
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt"
                    .to_string(),
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
            network_wide_adblock_enabled: false,
            attack_detection_enabled: false,
            auto_block_attacks: false,
            arp_spoof_detection: false,
            dns_flood_rate_limit: 80,
            window_width: 1160,
            window_height: 800,
            window_x: -1,
            window_y: -1,
            window_maximized: false,
            minimize_to_tray_on_minimize: true,
            start_hidden_in_tray: false,
            admin_panel_enabled: true,
            rammap_auto_clean_enabled: false,
            rammap_auto_clean_threshold_mb: default_ram_clean_threshold_mb(),
        }
    }
}

impl AppConfig {
    pub fn config_path() -> PathBuf {
        let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(app_data)
            .join("ShieldGhita")
            .join("config.toml")
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        let mut config = if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => toml::from_str(&content).unwrap_or_default(),
                Err(_) => Self::default(),
            }
        } else {
            let config = Self {
                language: detect_first_run_language(),
                ..Self::default()
            };
            let _ = config.save();
            config
        };

        if config.dns_listen_port == 5353 {
            config.dns_listen_port = 53;
            let _ = config.save();
        }

        // Merge newly-added default blocklists into existing configs so
        // blocking effectiveness improves without a reinstall.
        let before = config.blocklist_urls.len();
        for url in default_blocklist_urls() {
            if !config.blocklist_urls.contains(&url) {
                config.blocklist_urls.push(url);
            }
        }
        if config.blocklist_urls.len() != before {
            info!(
                "Blocklist merge: added {} new default source(s)",
                config.blocklist_urls.len() - before
            );
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
        let exe_path =
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("shield_ghita.exe"));
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
                &format!("\"{}\" --autostart", exe_str),
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

const INSTALLER_LANGUAGE_KEY: &str = r"Software\ShieldGhita";

fn map_ui_language_to_code(langid: u16) -> String {
    match langid & 0x03ff {
        0x002a => "vi".to_string(),
        0x0004 => "zh".to_string(),
        _ => "en".to_string(),
    }
}

#[cfg(windows)]
fn read_installer_language_registry() -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_SZ};

    let subkey: Vec<u16> = INSTALLER_LANGUAGE_KEY
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let value_name: Vec<u16> = "Language"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut buf = [0u16; 32];
    let mut data_size = (buf.len() * 2) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut data_size),
        )
    };
    if status.is_err() {
        return None;
    }
    let chars_len = (data_size as usize / 2).min(buf.len());
    let text = String::from_utf16_lossy(&buf[..chars_len]);
    let text = text.trim_end_matches('\0').trim();
    match text {
        "vi" | "en" | "zh" => Some(text.to_string()),
        _ => None,
    }
}

#[cfg(windows)]
fn detect_first_run_language() -> String {
    if let Some(code) = read_installer_language_registry() {
        return code;
    }
    let langid = unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() };
    map_ui_language_to_code(langid)
}

#[cfg(not(windows))]
fn detect_first_run_language() -> String {
    "vi".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_fields_roundtrip() {
        let cfg = AppConfig {
            window_width: 1280,
            window_height: 720,
            window_x: 55,
            window_y: 66,
            window_maximized: true,
            minimize_to_tray_on_minimize: false,
            start_hidden_in_tray: true,
            ..AppConfig::default()
        };

        let serialized = toml::to_string_pretty(&cfg).unwrap();
        let parsed: AppConfig = toml::from_str(&serialized).unwrap();

        assert_eq!(parsed.window_width, 1280);
        assert_eq!(parsed.window_height, 720);
        assert_eq!(parsed.window_x, 55);
        assert_eq!(parsed.window_y, 66);
        assert!(parsed.window_maximized);
        assert!(!parsed.minimize_to_tray_on_minimize);
        assert!(parsed.start_hidden_in_tray);
    }

    #[test]
    fn test_legacy_config_without_window_fields_parses() {
        let legacy = r#"
dns_listen_addr = "127.0.0.1"
dns_listen_port = 53
upstream_dns = ["https://1.1.1.1/dns-query"]
blocklist_urls = ["https://example.invalid/hosts"]
custom_blocked_domains = []
custom_allowed_domains = []
protection_enabled = true
log_max_entries = 500
auto_update_blocklist_hours = 24
"#;
        let parsed: AppConfig = toml::from_str(legacy).expect("legacy config must parse");
        assert_eq!(parsed.window_width, 1160);
        assert_eq!(parsed.window_height, 800);
        assert_eq!(parsed.window_x, -1);
        assert_eq!(parsed.window_y, -1);
        assert!(!parsed.window_maximized);
        assert!(parsed.minimize_to_tray_on_minimize);
        assert!(!parsed.start_hidden_in_tray);
    }

    #[test]
    fn test_language_roundtrip_and_defaults() {
        use crate::modules::i18n::{code_to_index, EN, VI, ZH};
        for (code, expected) in [("vi", VI), ("en", EN), ("zh", ZH)] {
            let cfg = AppConfig {
                language: code.to_string(),
                ..AppConfig::default()
            };
            let serialized = toml::to_string_pretty(&cfg).unwrap();
            let parsed: AppConfig = toml::from_str(&serialized).unwrap();
            assert_eq!(parsed.language, code);
            assert_eq!(code_to_index(&parsed.language), expected);
        }

        let legacy = r#"
dns_listen_addr = "127.0.0.1"
dns_listen_port = 53
"#;
        let parsed: AppConfig = toml::from_str(legacy).unwrap();
        assert_eq!(parsed.language, "vi");
    }

    #[test]
    fn test_ui_language_mapping() {
        assert_eq!(map_ui_language_to_code(0x042a), "vi");
        assert_eq!(map_ui_language_to_code(0x0804), "zh");
        assert_eq!(map_ui_language_to_code(0x0c04), "zh");
        assert_eq!(map_ui_language_to_code(0x0409), "en");
        assert_eq!(map_ui_language_to_code(0x0419), "en");
        assert_eq!(map_ui_language_to_code(0x0000), "en");
    }

    #[test]
    #[cfg(windows)]
    fn test_detect_first_run_language_returns_supported_code() {
        let code = detect_first_run_language();
        assert!(code == "vi" || code == "en" || code == "zh");
    }
}
