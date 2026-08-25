use chrono::Local;
use serde::{Deserialize, Serialize};
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
        if !name.starts_with("shield_ghita.log") {
            continue;
        }
        let modified = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
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
    logs: Arc<RwLock<Vec<AppConsoleLog>>>,
    max_entries: usize,
}

impl AppLogBuffer {
    pub fn new(max_entries: usize) -> Self {
        Self {
            logs: Arc::new(RwLock::new(Vec::new())),
            max_entries,
        }
    }

    pub fn push(&self, level: &str, message: &str) {
        let entry = AppConsoleLog {
            time: Local::now().format("%H:%M:%S").to_string(),
            level: level.to_string(),
            message: message.to_string(),
        };

        if let Ok(mut list) = self.logs.write() {
            list.insert(0, entry);
            if list.len() > self.max_entries {
                list.truncate(self.max_entries);
            }
        }
    }

    pub fn get_logs(&self) -> Vec<AppConsoleLog> {
        self.logs.read().map(|l| l.clone()).unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut list) = self.logs.write() {
            list.clear();
        }
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
