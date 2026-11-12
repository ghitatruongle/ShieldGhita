use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub struct FixValue {
    pub key: &'static str,
    pub name: &'static str,
    pub dword: u32,
}

pub struct FixSpec {
    pub id: &'static str,
    pub title: &'static str,
    pub values: &'static [FixValue],
}

pub fn fix_specs() -> &'static [FixSpec] {
    &[
        FixSpec {
            id: "smbv1",
            title: "Tắt SMBv1 (chống WannaCry/EternalBlue)",
            values: &[FixValue {
                key: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                name: "SMB1",
                dword: 0,
            }],
        },
        FixSpec {
            id: "rdp_nla",
            title: "Bật Network Level Authentication cho RDP",
            values: &[FixValue {
                key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                name: "UserAuthentication",
                dword: 1,
            }],
        },
        FixSpec {
            id: "lsa_ppl",
            title: "Bật bảo vệ LSA (chống trộm credential)",
            values: &[FixValue {
                key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
                name: "RunAsPPL",
                dword: 1,
            }],
        },
        FixSpec {
            id: "uac_enable",
            title: "Bật UAC (EnableLUA)",
            values: &[FixValue {
                key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                name: "EnableLUA",
                dword: 1,
            }],
        },
        FixSpec {
            id: "autorun_off",
            title: "Tắt AutoRun trên mọi ổ đĩa (USB an toàn hơn)",
            values: &[FixValue {
                key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                name: "NoDriveTypeAutoRun",
                dword: 255,
            }],
        },
        FixSpec {
            id: "restrict_anon",
            title: "Chặn phiên đăng nhập ẩn danh (RestrictAnonymous)",
            values: &[FixValue {
                key: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
                name: "RestrictAnonymous",
                dword: 1,
            }],
        },
        FixSpec {
            id: "llmnr_off",
            title: "Tắt LLMNR (chặn bắt mật khẩu qua tên miền cục bộ)",
            values: &[FixValue {
                key: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
                name: "DisableMulticast",
                dword: 1,
            }],
        },
        FixSpec {
            id: "mdns_off",
            title: "Tắt mDNS của Windows (giảm lộ diện máy trên LAN)",
            values: &[FixValue {
                key: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters",
                name: "EnableMDNS",
                dword: 0,
            }],
        },
    ]
}

#[derive(Serialize, Deserialize, Clone)]
struct BackupValue {
    key: String,
    name: String,
    present: bool,
    dword: u32,
}

#[derive(Serialize, Deserialize, Clone)]
struct BackupEntry {
    fix_id: String,
    time: String,
    values: Vec<BackupValue>,
}

fn backup_path() -> PathBuf {
    crate::modules::paths::data_dir()
        .join("ShieldGhita")
        .join("hardening_backup.json")
}

fn find_spec(id: &str) -> Option<&'static FixSpec> {
    fix_specs().iter().find(|s| s.id == id)
}

fn silent_reg() -> std::process::Command {
    crate::modules::system::dns_manager::silent_command("reg")
}

fn reg_read_dword(key: &str, name: &str) -> Option<u32> {
    let output = silent_reg()
        .args(["query", key, "/v", name, "/reg:64"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.contains(name) && line.contains("REG_DWORD") {
            let raw = line.split_whitespace().next_back()?;
            let digits = raw.strip_prefix("0x").unwrap_or(raw);
            return u32::from_str_radix(digits, 16).ok();
        }
    }
    None
}

fn reg_write_dword(key: &str, name: &str, value: u32) -> Result<(), String> {
    let output = silent_reg()
        .args([
            "add",
            key,
            "/v",
            name,
            "/t",
            "REG_DWORD",
            "/d",
            &value.to_string(),
            "/f",
            "/reg:64",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn reg_delete_value(key: &str, name: &str) -> Result<(), String> {
    let output = silent_reg()
        .args(["delete", key, "/v", name, "/f", "/reg:64"])
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn load_backups() -> Vec<BackupEntry> {
    std::fs::read(backup_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_backups(entries: &[BackupEntry]) -> Result<(), String> {
    let path = backup_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(entries).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

pub fn apply_fix(id: &str) -> Result<String, String> {
    let Some(spec) = find_spec(id) else {
        return Err("unknown fix id".to_string());
    };
    let mut backup_values = Vec::new();
    for value in spec.values {
        backup_values.push(BackupValue {
            key: value.key.to_string(),
            name: value.name.to_string(),
            present: reg_read_dword(value.key, value.name).is_some(),
            dword: reg_read_dword(value.key, value.name).unwrap_or(0),
        });
    }
    let entry = BackupEntry {
        fix_id: spec.id.to_string(),
        time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        values: backup_values,
    };
    let mut backups = load_backups();
    backups.push(entry);
    save_backups(&backups)?;
    for value in spec.values {
        reg_write_dword(value.key, value.name, value.dword)?;
    }
    Ok(format!("✓ {}: đã áp dụng", spec.title))
}

pub fn rollback_fix(id: &str) -> Result<String, String> {
    let Some(spec) = find_spec(id) else {
        return Err("unknown fix id".to_string());
    };
    let mut backups = load_backups();
    let Some(index) = backups.iter().rposition(|entry| entry.fix_id == spec.id) else {
        return Err("không có bản backup nào để hoàn tác".to_string());
    };
    let entry = backups.remove(index);
    for value in &entry.values {
        if value.present {
            reg_write_dword(&value.key, &value.name, value.dword)?;
        } else {
            let _ = reg_delete_value(&value.key, &value.name);
        }
    }
    save_backups(&backups)?;
    Ok(format!("↩ {}: đã hoàn tác", spec.title))
}

/// Reads back the registry to report whether every value of the fix matches
/// its target. Kept for the test suite and as the public status API.
#[allow(dead_code)]
pub fn is_fix_applied(id: &str) -> bool {
    let Some(spec) = find_spec(id) else {
        return false;
    };
    spec.values
        .iter()
        .all(|v| reg_read_dword(v.key, v.name) == Some(v.dword))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fix_specs_ids_unique_and_nonempty() {
        let specs = fix_specs();
        assert!(specs.len() >= 5);
        let mut ids: Vec<&str> = specs.iter().map(|s| s.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), specs.len());
        for spec in specs {
            assert!(!spec.title.is_empty());
            assert!(!spec.values.is_empty());
        }
    }

    #[test]
    fn test_find_spec_and_unknown_id() {
        assert!(find_spec("smbv1").is_some());
        assert!(find_spec("nope").is_none());
        assert!(!is_fix_applied("nope"));
    }

    #[test]
    fn test_backup_entry_json_roundtrip() {
        let entry = BackupEntry {
            fix_id: "smbv1".to_string(),
            time: "2026-10-04 21:00:00".to_string(),
            values: vec![BackupValue {
                key: "HKLM\\X".to_string(),
                name: "SMB1".to_string(),
                present: false,
                dword: 0,
            }],
        };
        let json = serde_json::to_string(&vec![entry.clone()]).unwrap();
        let parsed: Vec<BackupEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].fix_id, "smbv1");
        assert!(!parsed[0].values[0].present);
    }

    #[test]
    fn test_rollback_without_backup_errors() {
        let saved = load_backups();
        let had_backup = saved.iter().any(|e| e.fix_id == "smbv1");
        if !had_backup {
            assert!(rollback_fix("smbv1").is_err());
        }
    }
}
