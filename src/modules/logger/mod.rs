use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Delete rotated `shield_ghita.log.*` files older than `keep_days` so the
/// logs directory cannot grow unbounded. The active file is never touched
/// because its modification time stays within the retention window.
pub fn cleanup_old_logs(dir: &std::path::Path, keep_days: i64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let cutoff = std::time::SystemTime::now()
        - std::time::Duration::from_secs(keep_days.max(0) as u64 * 86_400);
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        // Only dated rotations (shield_ghita.log.YYYYMMDD); the contains
        // check would also match unrelated "shield_ghita.logistics" files.
        if !name.starts_with("shield_ghita.log.") {
            continue;
        }
        // Never delete the active (unrotated) file — only dated rotations.
        if name == "shield_ghita.log" {
            continue;
        }
        // Skip unreadable metadata instead of deleting: an unknown mtime
        // must fail closed (keep), not default to UNIX_EPOCH (delete).
        let Ok(md) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = md.modified() else {
            continue;
        };
        if modified < cutoff && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        tracing::info!(
            "Log rotation cleanup: removed {} expired log files",
            removed
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConsoleLog {
    pub time: String,
    pub level: String,
    pub message: String,
}

pub struct AppLogBuffer {
    logs: Arc<RwLock<VecDeque<AppConsoleLog>>>,
    max_entries: usize,
    version: Arc<std::sync::atomic::AtomicU64>,
}

impl AppLogBuffer {
    pub fn new(max_entries: usize) -> Self {
        Self {
            logs: Arc::new(RwLock::new(VecDeque::new())),
            max_entries,
            version: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    pub fn version(&self) -> u64 {
        self.version.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn push(&self, level: &str, message: &str) {
        let entry = AppConsoleLog {
            time: Local::now().format("%H:%M:%S").to_string(),
            level: level.to_string(),
            message: message.to_string(),
        };

        if let Ok(mut list) = self.logs.write() {
            // Newest-first via push_front/pop_back (O(1)); insert(0) on a Vec
            // is O(n) and janked the UI at high log rates.
            list.push_front(entry);
            while list.len() > self.max_entries {
                list.pop_back();
            }
        }
        let _ = self
            .version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get_logs(&self) -> Vec<AppConsoleLog> {
        self.logs
            .read()
            .map(|l| l.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut list) = self.logs.write() {
            list.clear();
        }
        let _ = self
            .version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub struct InAppTracingLayer {
    pub buffer: Arc<AppLogBuffer>,
}

impl<S: Subscriber> Layer<S> for InAppTracingLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let level = event.metadata().level().as_str();
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);

        if !visitor.0.is_empty() {
            self.buffer.push(level, &visitor.0);
        }
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value).trim_matches('"').to_string();
        } else if self.0.is_empty() {
            self.0 = format!("{}: {:?}", field.name(), value);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }
}
