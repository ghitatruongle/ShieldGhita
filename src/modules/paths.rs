use std::path::{Path, PathBuf};

pub fn data_base() -> String {
    base_dir().to_string_lossy().to_string()
}

pub fn data_dir() -> PathBuf {
    base_dir().join("ShieldGhita")
}

fn base_dir() -> PathBuf {
    if let Ok(pd) = std::env::var("PROGRAMDATA") {
        let trimmed = pd.trim().to_string();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

const MIGRATION_MARKER: &str = ".migrated_programdata";
const STAY_IN_APPDATA: &[&str] = &["backups", "exports"];

pub fn migrate_legacy_appdata() {
    let new_dir = data_dir();
    let marker = new_dir.join(MIGRATION_MARKER);
    if marker.exists() {
        return;
    }
    let _ = std::fs::create_dir_all(&new_dir);
    if let Ok(legacy) = std::env::var("APPDATA").map(PathBuf::from) {
        let legacy_dir = legacy.join("ShieldGhita");
        if legacy_dir != new_dir {
            migrate_children(&legacy_dir, &new_dir);
        }
    }
    let stamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let _ = std::fs::write(&marker, stamp);
}

fn migrate_children(legacy_dir: &Path, new_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(legacy_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if STAY_IN_APPDATA.iter().any(|skip| skip == &name) {
            continue;
        }
        let target = new_dir.join(&name);
        if target.exists() {
            continue;
        }
        copy_recursive(&entry.path(), &target);
    }
}

fn copy_recursive(from: &Path, to: &Path) {
    if from.is_dir() {
        if std::fs::create_dir_all(to).is_err() {
            return;
        }
        if let Ok(children) = std::fs::read_dir(from) {
            for child in children.flatten() {
                copy_recursive(&child.path(), &to.join(child.file_name()));
            }
        }
    } else {
        let _ = std::fs::copy(from, to);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_dir_contains_shieldghita() {
        let dir = data_dir();
        assert!(dir.ends_with("ShieldGhita"));
    }

    #[test]
    fn test_copy_recursive_files_and_dirs() {
        let root = std::env::temp_dir().join(format!("sg_paths_test_{}", std::process::id()));
        let from = root.join("from");
        let to = root.join("to");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(from.join("sub")).unwrap();
        std::fs::write(from.join("a.txt"), "A").unwrap();
        std::fs::write(from.join("sub").join("b.txt"), "B").unwrap();
        copy_recursive(&from, &to);
        assert_eq!(std::fs::read_to_string(to.join("a.txt")).unwrap(), "A");
        assert_eq!(
            std::fs::read_to_string(to.join("sub").join("b.txt")).unwrap(),
            "B"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
