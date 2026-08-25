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
    let startup_started = std::time::Instant::now();
    let log_buffer = Arc::new(AppLogBuffer::new(500));
    let in_app_layer = InAppTracingLayer {
        buffer: log_buffer.clone(),
    };

    let fmt_layer = tracing_subscriber::fmt::layer();

    let logs_dir =
        std::path::PathBuf::from(std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string()))
            .join("ShieldGhita")
            .join("logs");
    let file_appender = tracing_appender::rolling::daily(&logs_dir, "shield_ghita.log");
    let (file_writer, log_guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(file_writer);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("shield_ghita=info".parse()?),
        )
        .with(fmt_layer)
        .with(file_layer)
        .with(in_app_layer)
        .init();

    modules::logger::cleanup_old_logs(&logs_dir, 14);

    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!("PANIC: {}", info);
        default_panic_hook(info);
    }));
    std::mem::forget(log_guard);

    info!(
        "Starting Shield Ghita v{} Master Controller...",
        env!("CARGO_PKG_VERSION")
    );

    if !dns_manager::is_elevated() {
        tracing::warn!("Shield Ghita running without elevated Administrator token. Run as Administrator for full DNS & Firewall proxy enforcement.");
    }
    dns_manager::register_safety_cleanup();

    let state = AppState::new(log_buffer)?;
    let ui = AppWindow::new()?;

    let _single_instance_guard = match modules::system::SingleInstanceGuard::try_acquire(
        ui.as_weak(),
    ) {
        Some(guard) => guard,
        None => {
            tracing::info!("Another instance of Shield Ghita is already running. Signaled existing instance to show window.");
            return Ok(());
        }
    };

    let args: Vec<String> = std::env::args().collect();
    let is_autostart = args
        .iter()
        .any(|arg| arg == "--autostart" || arg == "--hidden");

    let should_hide = is_autostart
        && state
            .config
            .read()
            .map(|c| c.start_hidden_in_tray)
            .unwrap_or(false);

    let _tray_icon = app::ui_bridge::setup_ui_bridge(&ui, state)?;
    info!(
        "Startup baseline: UI & services ready in {} ms",
        startup_started.elapsed().as_millis()
    );

    if !should_hide {
        ui.show()?;
        ui.window().set_minimized(false);
        app::ui_bridge::poller::WINDOW_VISIBLE.store(true, std::sync::atomic::Ordering::SeqCst);
    } else {
        app::ui_bridge::poller::WINDOW_VISIBLE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
    slint::run_event_loop_until_quit()?;

    let _ = dns_manager::restore_system_dns();
    Ok(())
}
