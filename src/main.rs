#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app_logger;
mod blocker;
mod config;
mod dns;
mod dns_manager;
mod monitor;
mod self_defense;
mod sinkhole;

use app_logger::{AppLogBuffer, InAppTracingLayer};
use blocker::WfpBlocker;
use chrono::Local;
use config::AppConfig;
use dns::DnsBlocker;
use monitor::NetworkMonitor;
use self_defense::SelfDefense;
use sinkhole::SilentSinkhole;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem},
    Icon, TrayIconBuilder,
};

slint::include_modules!();

struct AppState {
    blocker: Arc<DnsBlocker>,
    wfp_blocker: Arc<WfpBlocker>,
    monitor: Arc<NetworkMonitor>,
    sinkhole: Arc<SilentSinkhole>,
    log_buffer: Arc<AppLogBuffer>,
    config: Arc<RwLock<AppConfig>>,
    runtime: Arc<tokio::runtime::Runtime>,
    self_defense: Arc<RwLock<SelfDefense>>,
    protection_atomic: Arc<AtomicBool>,
}

fn create_default_icon() -> Result<Icon, Box<dyn std::error::Error>> {
    let width = 32u32;
    let height = 32u32;
    let mut rgba = Vec::with_capacity((width * height * 4) as usize);
    for y in 0..height {
        for x in 0..width {
            let cx = x as f32 - 16.0;
            let cy = y as f32 - 16.0;
            let dist = (cx * cx + cy * cy).sqrt();
            if dist <= 14.0 {
                rgba.extend_from_slice(&[56, 189, 248, 255]); // Sky Blue #38bdf8
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    Icon::from_rgba(rgba, width, height).map_err(|e| e.into())
}

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

    // Register emergency safety cleanup hook
    dns_manager::register_safety_cleanup();

    let cfg = AppConfig::load();
    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
    );

    let wfp_blocker = Arc::new(WfpBlocker::new());
    if let Err(e) = wfp_blocker.initialize() {
        tracing::warn!("WFP initialization non-critical notice: {}", e);
    }

    let mut self_def = SelfDefense::new();
    if cfg.protection_enabled {
        if let Err(e) = self_def.enable() {
            tracing::warn!("Self-defense enable non-critical notice: {}", e);
        }
    }

    let dns_blocker = Arc::new(DnsBlocker::new());
    dns_blocker.set_custom_rules(&cfg.custom_blocked_domains, &cfg.custom_allowed_domains);

    let sinkhole = Arc::new(SilentSinkhole::new());
    let protection_atomic = Arc::new(AtomicBool::new(cfg.protection_enabled));

    let state = Arc::new(AppState {
        blocker: dns_blocker,
        wfp_blocker,
        monitor: Arc::new(NetworkMonitor::new(cfg.log_max_entries)),
        sinkhole: sinkhole.clone(),
        log_buffer: log_buffer.clone(),
        config: Arc::new(RwLock::new(cfg.clone())),
        runtime: runtime.clone(),
        self_defense: Arc::new(RwLock::new(self_def)),
        protection_atomic: protection_atomic.clone(),
    });

    // Start Silent Sinkhole HTTP background dummy server (Requirement 5)
    {
        let sinkhole_clone = state.sinkhole.clone();
        let rt = state.runtime.clone();
        rt.spawn(async move {
            sinkhole_clone.start().await;
        });
    }

    // Start background network traffic & active connections tracker (Requirement 3)
    {
        let monitor = state.monitor.clone();
        let rt = state.runtime.clone();
        rt.spawn(async move {
            monitor.start_traffic_monitor().await;
        });
    }

    // Start DNS Guard Watchdog 24/7 (Requirement 4)
    {
        let prot = state.protection_atomic.clone();
        let listen_addr = cfg.dns_listen_addr.clone();
        let rt = state.runtime.clone();
        rt.spawn(async move {
            dns_manager::start_dns_guard_watchdog(prot, listen_addr).await;
        });
    }

    // Load initial blocklists & start Master DNS proxy server
    {
        let blocker = state.blocker.clone();
        let monitor = state.monitor.clone();
        let config = state.config.clone();
        let rt = state.runtime.clone();
        let protection_flag = state.protection_atomic.clone();
        let listen_addr = cfg.dns_listen_addr.clone();
        let listen_port = cfg.dns_listen_port;
        let upstream = cfg.upstream_dns.clone();
        let protection = cfg.protection_enabled;

        rt.spawn(async move {
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

            // 1. Start DNS proxy server on background task
            let blocker_srv = blocker.clone();
            let mon_srv = monitor.clone();
            let addr_srv = listen_addr.clone();
            let up_srv = upstream.clone();
            tokio::spawn(async move {
                blocker_srv
                    .run_dns_server(&addr_srv, listen_port, up_srv, mon_srv, Some(ready_tx))
                    .await;
            });

            // 2. Wait for DNS server socket bind confirmation
            match ready_rx.await {
                Ok(Ok(())) => {
                    info!("DNS Server successfully bound to {}:{}", listen_addr, listen_port);
                    if protection {
                        if let Err(e) = dns_manager::set_system_dns(&listen_addr) {
                            tracing::error!("Failed to set master system DNS: {}", e);
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::error!("DNS Server Bind Failed: {}. Protection disabled to prevent network blackout.", e);
                    protection_flag.store(false, Ordering::SeqCst);
                    if let Ok(mut cfg_guard) = config.write() {
                        cfg_guard.protection_enabled = false;
                        let _ = cfg_guard.save();
                    }
                }
                Err(e) => {
                    tracing::error!("DNS Server Task Error: {}", e);
                }
            }

            // 3. Load blocklists
            let urls = {
                let cfg_guard = config.read().unwrap();
                cfg_guard.blocklist_urls.clone()
            };
            match blocker.load_blocklists(&urls).await {
                Ok(count) => {
                    info!("Master Blocklist loaded: {} domains actively protected", count);
                    if let Ok(mut cfg_guard) = config.write() {
                        cfg_guard.last_blocklist_update =
                            Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                        let _ = cfg_guard.save();
                    }
                }
                Err(e) => tracing::error!("Failed to fetch blocklists: {}", e),
            }
        });
    }

    // Periodic auto-update blocklist timer
    {
        let s = state.clone();
        let rt = state.runtime.clone();
        rt.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                let should_update = {
                    let cfg_guard = s.config.read().unwrap();
                    match &cfg_guard.last_blocklist_update {
                        Some(last) => {
                            if let Ok(last_dt) =
                                chrono::NaiveDateTime::parse_from_str(last, "%Y-%m-%d %H:%M:%S")
                            {
                                let now = Local::now().naive_local();
                                let hours = cfg_guard.auto_update_blocklist_hours as i64;
                                (now - last_dt).num_hours() >= hours
                            } else {
                                true
                            }
                        }
                        None => true,
                    }
                };
                if should_update {
                    let urls = {
                        let cfg_guard = s.config.read().unwrap();
                        cfg_guard.blocklist_urls.clone()
                    };
                    match s.blocker.load_blocklists(&urls).await {
                        Ok(count) => {
                            info!("Auto-updated blocklists: {} domains active", count);
                            if let Ok(mut cfg_guard) = s.config.write() {
                                cfg_guard.last_blocklist_update =
                                    Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                                let _ = cfg_guard.save();
                            }
                        }
                        Err(e) => tracing::error!("Blocklist auto-update failed: {}", e),
                    }
                }
            }
        });
    }

    let ui = AppWindow::new()?;

    // Build System Tray
    let tray_menu = Menu::new();
    let item_show = MenuItem::new("Mở giao diện Shield Ghita", true, None);
    let item_toggle = MenuItem::new("Bật / Tắt bảo vệ", true, None);
    let item_quit = MenuItem::new("Thoát hoàn toàn", true, None);
    let _ = tray_menu.append(&item_show);
    let _ = tray_menu.append(&item_toggle);
    let _ = tray_menu.append(&item_quit);

    let _tray_icon = match create_default_icon() {
        Ok(icon) => TrayIconBuilder::new()
            .with_menu(Box::new(tray_menu))
            .with_tooltip("Shield Ghita v0.0.0+0 - Master Controller")
            .with_icon(icon)
            .build()
            .ok(),
        Err(e) => {
            tracing::warn!("Failed to initialize tray icon: {}", e);
            None
        }
    };

    let show_id = item_show.id().clone();
    let toggle_id = item_toggle.id().clone();
    let quit_id = item_quit.id().clone();

    // Wire UI Callbacks
    let s = state.clone();
    ui.on_toggle_protection(move |enabled| {
        s.protection_atomic.store(enabled, Ordering::SeqCst);
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.protection_enabled = enabled;
            let _ = cfg_guard.save();
        }
        if enabled {
            let addr = s
                .config
                .read()
                .map(|c| c.dns_listen_addr.clone())
                .unwrap_or_else(|_| "127.0.0.1".into());
            if let Err(e) = dns_manager::set_system_dns(&addr) {
                tracing::error!("Failed to enable master DNS: {}", e);
            }
            if let Err(e) = s.wfp_blocker.enable() {
                tracing::warn!("WFP enable notice: {}", e);
            }
            if let Ok(mut sd) = s.self_defense.write() {
                let _ = sd.enable();
            }
        } else {
            if let Err(e) = dns_manager::restore_system_dns() {
                tracing::error!("Failed to restore DNS: {}", e);
            }
            if let Err(e) = s.wfp_blocker.disable() {
                tracing::warn!("WFP disable notice: {}", e);
            }
            if let Ok(mut sd) = s.self_defense.write() {
                let _ = sd.disable();
            }
        }
    });

    ui.on_toggle_master_lock(move |locked| {
        if let Err(e) = dns_manager::set_master_internet_lock(locked) {
            tracing::error!("Failed to toggle master internet lock: {}", e);
        }
    });

    let s = state.clone();
    ui.on_toggle_silent_sinkhole(move |enabled| {
        s.blocker.set_silent_sinkhole(enabled);
        info!("Silent Sinkhole Mode changed: {}", if enabled { "ENABLED" } else { "DISABLED" });
    });

    let s = state.clone();
    ui.on_refresh_connections(move || {
        s.monitor.connection_tracker.refresh_connections();
    });

    let s = state.clone();
    ui.on_refresh_devices(move || {
        let monitor = s.monitor.clone();
        s.runtime.spawn(async move {
            let _ = monitor.lan_scanner.scan_network().await;
        });
    });

    let s = state.clone();
    ui.on_clear_logs(move || {
        s.monitor.clear_logs();
    });

    let s_log = state.clone();
    ui.on_clear_console_logs(move || {
        s_log.log_buffer.clear();
    });

    let s = state.clone();
    ui.on_add_custom_rule(move |rule| {
        let rule_str = rule.to_string();
        if rule_str.is_empty() {
            return;
        }
        if let Err(e) = s.blocker.add_custom_domain(&rule_str) {
            tracing::error!("Failed to add custom rule: {}", e);
        } else {
            info!("Added custom block rule: {}", rule_str);
        }
        if let Ok(mut cfg_guard) = s.config.write() {
            if !cfg_guard.custom_blocked_domains.contains(&rule_str) {
                cfg_guard.custom_blocked_domains.push(rule_str);
                let _ = cfg_guard.save();
            }
        }
    });

    let s = state.clone();
    ui.on_remove_custom_rule(move |rule| {
        let rule_str = rule.to_string();
        if let Err(e) = s.blocker.remove_custom_domain(&rule_str) {
            tracing::error!("Failed to remove custom rule: {}", e);
        }
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.custom_blocked_domains.retain(|d| d != &rule_str);
            let _ = cfg_guard.save();
        }
    });

    let s = state.clone();
    ui.on_add_allowed_rule(move |rule| {
        let rule_str = rule.to_string();
        if rule_str.is_empty() {
            return;
        }
        if let Err(e) = s.blocker.add_allowed_domain(&rule_str) {
            tracing::error!("Failed to add whitelist rule: {}", e);
        } else {
            info!("Added whitelist rule: {}", rule_str);
        }
        if let Ok(mut cfg_guard) = s.config.write() {
            if !cfg_guard.custom_allowed_domains.contains(&rule_str) {
                cfg_guard.custom_allowed_domains.push(rule_str);
                let _ = cfg_guard.save();
            }
        }
    });

    let s = state.clone();
    ui.on_remove_allowed_rule(move |rule| {
        let rule_str = rule.to_string();
        if let Err(e) = s.blocker.remove_allowed_domain(&rule_str) {
            tracing::error!("Failed to remove whitelist rule: {}", e);
        }
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.custom_allowed_domains.retain(|d| d != &rule_str);
            let _ = cfg_guard.save();
        }
    });

    let s = state.clone();
    ui.on_update_blocklist(move || {
        let state_clone = s.clone();
        s.runtime.spawn(async move {
            let urls = {
                let cfg_guard = state_clone.config.read().unwrap();
                cfg_guard.blocklist_urls.clone()
            };
            match state_clone.blocker.load_blocklists(&urls).await {
                Ok(count) => {
                    info!("Blocklists updated: {} domains active", count);
                    if let Ok(mut cfg_guard) = state_clone.config.write() {
                        cfg_guard.last_blocklist_update =
                            Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                        let _ = cfg_guard.save();
                    }
                }
                Err(e) => tracing::error!("Blocklist update failed: {}", e),
            }
        });
    });

    let s = state.clone();
    ui.on_export_logs(move || {
        match s.monitor.export_logs_csv() {
            Ok(path) => info!("Logs exported to CSV: {}", path),
            Err(e) => tracing::error!("Failed to export logs: {}", e),
        }
    });

    let s = state.clone();
    ui.on_filter_logs(move |domain, ip, blocked_flag| {
        let domain_str = domain.to_string();
        let ip_str = ip.to_string();
        let blocked_opt = if blocked_flag < 0 {
            None
        } else {
            Some(blocked_flag > 0)
        };
        s.monitor.apply_filter(&domain_str, &ip_str, blocked_opt);
    });

    // Trigger initial LAN scan and Connection scan
    {
        let monitor = state.monitor.clone();
        state.runtime.spawn(async move {
            let _ = monitor.lan_scanner.scan_network().await;
            monitor.connection_tracker.refresh_connections();
        });
    }

    // Periodic UI Update & Tray Event Loop Timer (1000ms)
    let ui_weak = ui.as_weak();
    let s = state.clone();
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(1000),
        move || {
            // Check Tray Menu Events
            if let Ok(event) = MenuEvent::receiver().try_recv() {
                if event.id == show_id {
                    if let Some(ui) = ui_weak.upgrade() {
                        let _ = ui.show();
                    }
                } else if event.id == toggle_id {
                    let current = s
                        .config
                        .read()
                        .map(|c| c.protection_enabled)
                        .unwrap_or(true);
                    let new_state = !current;
                    s.protection_atomic.store(new_state, Ordering::SeqCst);
                    if let Ok(mut cfg_guard) = s.config.write() {
                        cfg_guard.protection_enabled = new_state;
                        let _ = cfg_guard.save();
                    }
                    if new_state {
                        let addr = s
                            .config
                            .read()
                            .map(|c| c.dns_listen_addr.clone())
                            .unwrap_or_else(|_| "127.0.0.1".into());
                        let _ = dns_manager::set_system_dns(&addr);
                    } else {
                        let _ = dns_manager::restore_system_dns();
                    }
                } else if event.id == quit_id {
                    let _ = dns_manager::restore_system_dns();
                    std::process::exit(0);
                }
            }

            if let Some(ui) = ui_weak.upgrade() {
                let total = s.blocker.total_queries.load(Ordering::Relaxed);
                let blocked = s.blocker.blocked_count.load(Ordering::Relaxed);
                let absorbed = s.sinkhole.absorbed_count.load(Ordering::Relaxed);
                ui.set_total_queries(total as i32);
                ui.set_blocked_count(blocked as i32);
                ui.set_absorbed_count(absorbed as i32);

                let is_locked = dns_manager::is_master_internet_locked();
                ui.set_master_locked(is_locked);
                ui.set_silent_sinkhole(s.blocker.is_silent_sinkhole());

                let protection = s.protection_atomic.load(Ordering::Relaxed);
                ui.set_protection_enabled(protection);
                ui.set_status_text(if is_locked {
                    "🔒 Đã khóa Internet".into()
                } else if protection {
                    "🟢 Đang bảo vệ tối cao".into()
                } else {
                    "🔴 Đã tạm dừng".into()
                });

                // System metrics (CPU & RAM)
                let (cpu, mem) = s.monitor.get_system_metrics();
                ui.set_cpu_usage(cpu);
                ui.set_mem_usage(mem);

                // Last update timestamp
                let last_update = s
                    .config
                    .read()
                    .ok()
                    .and_then(|c| c.last_blocklist_update.clone())
                    .unwrap_or_else(|| "Chưa cập nhật".to_string());
                ui.set_last_update_text(format!("Cập nhật: {}", last_update).into());

                // Custom rules list (Blacklist)
                let custom_rules = s
                    .config
                    .read()
                    .map(|c| c.custom_blocked_domains.clone())
                    .unwrap_or_default();
                let rule_models: Vec<slint::SharedString> =
                    custom_rules.into_iter().map(|r| r.into()).collect();
                ui.set_custom_rules(ModelRc::new(VecModel::from(rule_models)));

                // Allowed rules list (Whitelist)
                let allowed_rules = s
                    .config
                    .read()
                    .map(|c| c.custom_allowed_domains.clone())
                    .unwrap_or_default();
                let allow_models: Vec<slint::SharedString> =
                    allowed_rules.into_iter().map(|r| r.into()).collect();
                ui.set_allowed_rules(ModelRc::new(VecModel::from(allow_models)));

                // Active Internet Connections list (Requirement 3)
                let conns = s.monitor.get_active_connections();
                let conn_models: Vec<ActiveConnection> = conns
                    .into_iter()
                    .map(|c| ActiveConnection {
                        process_name: c.process_name.into(),
                        pid: c.pid as i32,
                        local_addr: c.local_addr.into(),
                        remote_addr: c.remote_addr.into(),
                        protocol: c.protocol.into(),
                        state: c.state.into(),
                        is_safe: c.is_safe,
                    })
                    .collect();
                ui.set_connections(ModelRc::new(VecModel::from(conn_models)));

                // Network LAN Devices list (Requirement 2)
                let devices = s.monitor.get_lan_devices();
                let device_models: Vec<NetworkDevice> = devices
                    .into_iter()
                    .map(|d| NetworkDevice {
                        name: d.name.into(),
                        ip: d.ip.into(),
                        mac: d.mac.into(),
                        vendor: d.vendor.into(),
                        device_type: d.device_type.into(),
                        is_online: d.is_online,
                        latency: format!("{} ms", d.latency_ms).into(),
                        traffic: d.traffic.into(),
                    })
                    .collect();
                ui.set_devices(ModelRc::new(VecModel::from(device_models)));

                // DNS Logs list
                let logs = s.monitor.get_logs();
                let log_models: Vec<LogEntry> = logs
                    .into_iter()
                    .map(|l| LogEntry {
                        timestamp: l.timestamp.into(),
                        domain: l.domain.into(),
                        source_ip: l.source_ip.into(),
                        is_blocked: l.is_blocked,
                    })
                    .collect();
                ui.set_logs(ModelRc::new(VecModel::from(log_models)));

                // In-App Console Logs list (Requirement 1)
                let clogs = s.log_buffer.get_logs();
                let clog_models: Vec<ConsoleLogEntry> = clogs
                    .into_iter()
                    .map(|cl| ConsoleLogEntry {
                        time: cl.time.into(),
                        level: cl.level.into(),
                        message: cl.message.into(),
                    })
                    .collect();
                ui.set_console_logs(ModelRc::new(VecModel::from(clog_models)));
            }
        },
    );

    // Minimize to System Tray when user clicks Close (X)
    let ui_weak_close = ui.as_weak();
    ui.window().on_close_requested(move || {
        if let Some(ui) = ui_weak_close.upgrade() {
            let _ = ui.hide();
        }
        slint::CloseRequestResponse::KeepWindowShown
    });

    std::mem::forget(timer);

    ui.run()?;

    // Final clean up on normal window loop exit
    let _ = dns_manager::restore_system_dns();
    Ok(())
}
