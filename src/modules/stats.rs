use chrono::Datelike;
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StatsFile {
    day: String,
    week: u32,
    day_count: u64,
    week_count: u64,
}

/// Persisted ad-block counters for today and the current ISO week.
/// Counters roll over to zero when the day/week key changes and are
/// flushed to `block_stats.json` on a debounced schedule by the monitor loop.
pub struct BlockStats {
    current_day: RwLock<String>,
    current_week: RwLock<u32>,
    day_count: AtomicU64,
    week_count: AtomicU64,
    dirty: AtomicBool,
    path: PathBuf,
}

impl BlockStats {
    fn today_key() -> String {
        Local::now().format("%Y-%m-%d").to_string()
    }

    fn week_key() -> u32 {
        Local::now().iso_week().week()
    }

    fn default_path() -> PathBuf {
        let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(app_data)
            .join("ShieldGhita")
            .join("block_stats.json")
    }

    pub fn load_or_create() -> Self {
        Self::load_from_dir(&Self::default_path())
    }

    fn load_from_dir(path: &Path) -> Self {
        let today = Self::today_key();
        let week = Self::week_key();

        let mut day_count = 0u64;
        let mut week_count = 0u64;
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(saved) = serde_json::from_str::<StatsFile>(&content) {
                if saved.day == today {
                    day_count = saved.day_count;
                }
                if saved.week == week {
                    week_count = saved.week_count;
                }
            }
        }

        Self {
            current_day: RwLock::new(today),
            current_week: RwLock::new(week),
            day_count: AtomicU64::new(day_count),
            week_count: AtomicU64::new(week_count),
            dirty: AtomicBool::new(false),
            path: path.to_path_buf(),
        }
    }

    /// Roll both counters over when the calendar day / ISO week changed.
    /// Cheap enough to run on every block hit and on every UI read.
    fn roll_if_new_period(&self) {
        let today = Self::today_key();
        let week = Self::week_key();

        if let Ok(mut day) = self.current_day.write() {
            if *day != today {
                *day = today;
                self.day_count.store(0, Ordering::Relaxed);
                self.dirty.store(true, Ordering::Relaxed);
            }
        }
        if let Ok(mut wk) = self.current_week.write() {
            if *wk != week {
                *wk = week;
                self.week_count.store(0, Ordering::Relaxed);
                self.dirty.store(true, Ordering::Relaxed);
            }
        }
    }

    pub fn record_block(&self) {
        self.roll_if_new_period();
        self.day_count.fetch_add(1, Ordering::Relaxed);
        self.week_count.fetch_add(1, Ordering::Relaxed);
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub fn day_count(&self) -> u64 {
        self.roll_if_new_period();
        self.day_count.load(Ordering::Relaxed)
    }

    pub fn week_count(&self) -> u64 {
        self.roll_if_new_period();
        self.week_count.load(Ordering::Relaxed)
    }

    /// Write counters to disk only when something changed since last flush.
    pub fn flush_if_dirty(&self) {
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return;
        }
        let snapshot = StatsFile {
            day: self
                .current_day
                .read()
                .map(|d| d.clone())
                .unwrap_or_default(),
            week: self.current_week.read().map(|w| *w).unwrap_or(0),
            day_count: self.day_count.load(Ordering::Relaxed),
            week_count: self.week_count.load(Ordering::Relaxed),
        };
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string(&snapshot) {
            Ok(json) => {
                let _ = std::fs::write(&self.path, json);
            }
            Err(_) => {
                self.dirty.store(true, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    static UNIQUE_DIR: AtomicU32 = AtomicU32::new(0);

    fn temp_stats(name: &str) -> (BlockStats, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "shieldghita_stats_test_{}_{}_{}",
            std::process::id(),
            UNIQUE_DIR.fetch_add(1, Ordering::Relaxed),
            name
        ));
        let _ = std::fs::create_dir_all(&dir);
        (
            BlockStats::load_from_dir(&dir.join("block_stats.json")),
            dir,
        )
    }

    #[test]
    fn test_counters_increment_and_persist() {
        let (stats, dir) = temp_stats("persist");

        stats.record_block();
        stats.record_block();
        stats.record_block();
        assert_eq!(stats.day_count(), 3);
        assert!(stats.week_count() >= 3);

        stats.flush_if_dirty();
        let content = std::fs::read_to_string(dir.join("block_stats.json")).unwrap();
        let saved: StatsFile = serde_json::from_str(&content).unwrap();
        assert_eq!(saved.day_count, 3);
        assert_eq!(saved.day, BlockStats::today_key());

        // Second load in the same period must restore counts.
        let reloaded = BlockStats::load_from_dir(&dir.join("block_stats.json"));
        assert_eq!(reloaded.day_count(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_day_rollover_resets_day_counter_only() {
        let (stats, dir) = temp_stats("rollover");

        stats.record_block();
        stats.record_block();
        assert_eq!(stats.day_count(), 2);

        // Simulate midnight passing while staying inside the same ISO week.
        *stats.current_day.write().unwrap() = "2000-01-01".to_string();
        assert_eq!(stats.day_count(), 0, "day counter must reset on new day");
        assert!(
            stats.week_count() >= 2,
            "week counter survives a day rollover within the same week"
        );
        stats.flush_if_dirty();
        let content = std::fs::read_to_string(dir.join("block_stats.json")).unwrap();
        let saved: StatsFile = serde_json::from_str(&content).unwrap();
        assert_ne!(saved.day, "2000-01-01");

        // Simulate a new ISO week as well.
        let real_week = BlockStats::week_key();
        *stats.current_week.write().unwrap() = real_week.wrapping_add(53);
        assert_eq!(stats.week_count(), 0, "week counter must reset on new week");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_flush_skipped_when_clean() {
        let (stats, dir) = temp_stats("clean");
        let path = dir.join("block_stats.json");

        stats.flush_if_dirty(); // nothing recorded yet — no file expected
        assert!(!path.exists(), "clean stats must not write a file");

        stats.record_block();
        stats.flush_if_dirty();
        assert!(path.exists());

        let before = std::fs::read(&path).unwrap();
        stats.flush_if_dirty(); // already flushed — content unchanged
        let after = std::fs::read(&path).unwrap();
        assert_eq!(before, after);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
