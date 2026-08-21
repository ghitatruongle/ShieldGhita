#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod modules;

use app::AppState;
use modules::logger::{AppLogBuffer, InAppTracingLayer};
use modules::system::dns_manager;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

slint::include_modules!();

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let log_buffer = Arc::new(AppLogBuffer::new(500));
    let in_app_layer = InAppTracingLayer {
        buffer: log_buffer.clone(),
    };

    let fmt_layer = tracing_subscriber::fmt::layer();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("shield_ghita=info".parse()?),
        )
        .with(fmt_layer)
        .with(in_app_layer)
        .init();

    info!("Starting Shield Ghita v0.0.5-beta1 Master Controller...");

    if !dns_manager::is_elevated() {
        tracing::warn!("Shield Ghita running without elevated Administrator token. Run as Administrator for full DNS & Firewall proxy enforcement.");
    }
    dns_manager::register_safety_cleanup();

    let state = AppState::new(log_buffer)?;
    let ui = AppWindow::new()?;

    let _tray_icon = app::ui_bridge::setup_ui_bridge(&ui, state)?;

    ui.run()?;

    let _ = dns_manager::restore_system_dns();
    Ok(())
}
