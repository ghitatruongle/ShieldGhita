use chrono::Local;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

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
