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
            let u = x as f32 / 32.0;
            let v = y as f32 / 32.0;
            let nx = (u - 0.5) * 2.0;
            let ny = (v - 0.5) * 2.0;

            let abs_x = nx.abs();
            let mut bound = 0.0;
            if ny >= -0.85 && ny <= 0.0 {
                bound = 0.82 - (ny + 0.85) * 0.05;
            } else if ny > 0.0 && ny <= 0.92 {
                let t = ny / 0.92;
                bound = 0.82 * (1.0 - t * t * 0.95).max(0.0).sqrt();
            }

            let dist = bound - abs_x;
            if dist > 0.0 {
                if dist < 0.12 {
                    rgba.extend_from_slice(&[56, 189, 248, 255]);
                } else if dist < 0.18 {
                    rgba.extend_from_slice(&[34, 197, 94, 255]);
                } else {
                    rgba.extend_from_slice(&[15, 23, 42, 255]);
                }
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

    info!("Starting Shield Ghita v0.0.1 Master Controller...");

    if !dns_manager::is_elevated() {
        tracing::warn!("Shield Ghita running without elevated Administrator token. Run as Administrator for full DNS proxy enforcement.");
    }
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

    {
        let sinkhole_clone = state.sinkhole.clone();
        let rt = state.runtime.clone();
        rt.spawn(async move {
            sinkhole_clone.start().await;
        });
    }

    {
        let monitor = state.monitor.clone();
        let rt = state.runtime.clone();
        rt.spawn(async move {
            monitor.start_traffic_monitor().await;
        });
    }

    {
        let prot = state.protection_atomic.clone();
        let listen_addr = cfg.dns_listen_addr.clone();
        let rt = state.runtime.clone();
        rt.spawn(async move {
            dns_manager::start_dns_guard_watchdog(prot, listen_addr).await;
        });
    }

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

            let blocker_srv = blocker.clone();
            let mon_srv = monitor.clone();
            let addr_srv = listen_addr.clone();
            let up_srv = upstream.clone();
            tokio::spawn(async move {
                blocker_srv
                    .run_dns_server(&addr_srv, listen_port, up_srv, mon_srv, Some(ready_tx))
                    .await;
            });

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

    ui.set_is_vi(cfg.language == "vi");
    ui.set_enable_notifications(cfg.enable_block_notifications);
    ui.set_app_version("0.0.1".into());

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
            .with_tooltip("Shield Ghita v0.0.1 - Master Controller")
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

    AppConfig::set_autostart_registry(cfg.start_with_windows);

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
    ui.on_toggle_autostart(move |enabled| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.start_with_windows = enabled;
            let _ = cfg_guard.save();
        }
        AppConfig::set_autostart_registry(enabled);
        info!("Autostart with Windows set to: {}", if enabled { "ENABLED" } else { "DISABLED" });
    });

    let s = state.clone();
    ui.on_toggle_minimize_to_tray(move |enabled| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.minimize_to_tray = enabled;
            let _ = cfg_guard.save();
        }
        info!("Minimize to tray on close set to: {}", if enabled { "ENABLED" } else { "DISABLED" });
    });

    let s = state.clone();
    let ui_weak_lang = ui.as_weak();
    ui.on_change_language(move |lang| {
        let lang_str = lang.to_string();
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.language = lang_str.clone();
            let _ = cfg_guard.save();
        }
        if let Some(ui_inst) = ui_weak_lang.upgrade() {
            ui_inst.set_is_vi(lang_str == "vi");
        }
        info!("Language preference set to: {}", lang_str);
    });

    let s = state.clone();
    let ui_weak_notif = ui.as_weak();
    ui.on_toggle_notifications(move |enabled| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.enable_block_notifications = enabled;
            let _ = cfg_guard.save();
        }
        if let Some(ui_inst) = ui_weak_notif.upgrade() {
            ui_inst.set_enable_notifications(enabled);
        }
        info!("Ad blocking notifications set to: {}", if enabled { "ENABLED" } else { "DISABLED" });
    });

    let ui_weak_toast = ui.as_weak();
    ui.on_dismiss_toast(move || {
        if let Some(ui_inst) = ui_weak_toast.upgrade() {
            ui_inst.set_show_toast(false);
        }
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

    // Blocked domain toast notification subscriber
    {
        let mut rx = state.blocker.blocked_events_tx.subscribe();
        let ui_weak = ui.as_weak();
        let config = state.config.clone();
        state.runtime.spawn(async move {
            while let Ok((domain, time)) = rx.recv().await {
                let notify_enabled = config
                    .read()
                    .map(|c| c.enable_block_notifications)
                    .unwrap_or(true);
                if !notify_enabled {
                    continue;
                }
                let domain_clone = domain.clone();
                let time_clone = time.clone();
                let ui_weak_inner = ui_weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui_inst) = ui_weak_inner.upgrade() {
                        ui_inst.set_toast_domain(domain_clone.into());
                        ui_inst.set_toast_time(time_clone.into());
                        ui_inst.set_show_toast(true);
                    }
                });

                // Auto dismiss toast after 3.5s
                let ui_weak_timer = ui_weak.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(3500)).await;
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui_inst) = ui_weak_timer.upgrade() {
                            ui_inst.set_show_toast(false);
                        }
                    });
                });
            }
        });
    }

    {
        let monitor = state.monitor.clone();
        state.runtime.spawn(async move {
            let _ = monitor.lan_scanner.scan_network().await;
            monitor.connection_tracker.refresh_connections();
        });
    }

    let ui_weak = ui.as_weak();
    let s = state.clone();
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(1000),
        move || {
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
                let rules_count = s.blocker.get_rules_count();
                ui.set_total_queries(total as i32);
                ui.set_blocked_count(blocked as i32);
                ui.set_absorbed_count(absorbed as i32);
                ui.set_active_rules_count(rules_count as i32);

                let is_locked = dns_manager::is_master_internet_locked();
                ui.set_master_locked(is_locked);
                ui.set_silent_sinkhole(s.blocker.is_silent_sinkhole());

                let is_vi = s.config.read().map(|c| c.language == "vi").unwrap_or(true);
                ui.set_is_vi(is_vi);

                let protection = s.protection_atomic.load(Ordering::Relaxed);
                ui.set_protection_enabled(protection);
                ui.set_status_text(if is_locked {
                    if is_vi { "🔒 Đã khóa Internet".into() } else { "🔒 Internet Locked".into() }
                } else if protection {
                    if is_vi { "🟢 Đang bảo vệ tối cao".into() } else { "🟢 Active Protection".into() }
                } else {
                    if is_vi { "🔴 Đã tạm dừng".into() } else { "🔴 Paused".into() }
                });

                let (autostart, minimize, notify) = s
                    .config
                    .read()
                    .map(|c| (c.start_with_windows, c.minimize_to_tray, c.enable_block_notifications))
                    .unwrap_or((true, true, true));
                ui.set_autostart_enabled(autostart);
                ui.set_minimize_to_tray_enabled(minimize);
                ui.set_enable_notifications(notify);

                let (cpu, mem) = s.monitor.get_system_metrics();
                ui.set_cpu_usage(cpu);
                ui.set_mem_usage(mem);
                ui.set_live_traffic_rate(s.monitor.get_live_traffic_rate().into());

                let last_update = s
                    .config
                    .read()
                    .ok()
                    .and_then(|c| c.last_blocklist_update.clone())
                    .unwrap_or_else(|| if is_vi { "Chưa cập nhật".to_string() } else { "Not updated".to_string() });
                ui.set_last_update_text(if is_vi { format!("Cập nhật: {}", last_update).into() } else { format!("Updated: {}", last_update).into() });

                let custom_rules = s
                    .config
                    .read()
                    .map(|c| c.custom_blocked_domains.clone())
                    .unwrap_or_default();
                let rule_models: Vec<slint::SharedString> =
                    custom_rules.into_iter().map(|r| r.into()).collect();
                ui.set_custom_rules(ModelRc::new(VecModel::from(rule_models)));

                let allowed_rules = s
                    .config
                    .read()
                    .map(|c| c.custom_allowed_domains.clone())
                    .unwrap_or_default();
                let allow_models: Vec<slint::SharedString> =
                    allowed_rules.into_iter().map(|r| r.into()).collect();
                ui.set_allowed_rules(ModelRc::new(VecModel::from(allow_models)));

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

                let grp_conns = s.monitor.connection_tracker.get_grouped_connections();
                let grp_conn_models: Vec<AppConnectionGroup> = grp_conns
                    .into_iter()
                    .map(|g| AppConnectionGroup {
                        process_name: g.process_name.into(),
                        pid: g.pid as i32,
                        connection_count: g.connection_count as i32,
                        destinations_summary: g.destinations_summary.into(),
                        protocol_summary: g.protocol_summary.into(),
                        state_summary: g.state_summary.into(),
                        is_safe: g.is_safe,
                    })
                    .collect();
                ui.set_grouped_connections(ModelRc::new(VecModel::from(grp_conn_models)));

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

                let grp_logs = s.monitor.get_grouped_logs();
                let grp_log_models: Vec<DomainLogGroup> = grp_logs
                    .into_iter()
                    .map(|g| DomainLogGroup {
                        domain: g.domain.into(),
                        total_queries: g.total_queries as i32,
                        blocked_queries: g.blocked_queries as i32,
                        is_blocked: g.is_blocked,
                        last_seen: g.last_seen.into(),
                        last_ip: g.last_ip.into(),
                    })
                    .collect();
                ui.set_grouped_logs(ModelRc::new(VecModel::from(grp_log_models)));

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

    let ui_weak_close = ui.as_weak();
    let s_close = state.clone();
    ui.window().on_close_requested(move || {
        let minimize = s_close
            .config
            .read()
            .map(|c| c.minimize_to_tray)
            .unwrap_or(true);
        if minimize {
            if let Some(ui) = ui_weak_close.upgrade() {
                let _ = ui.hide();
            }
            slint::CloseRequestResponse::KeepWindowShown
        } else {
            let _ = dns_manager::restore_system_dns();
            std::process::exit(0);
        }
    });

    std::mem::forget(timer);

    ui.run()?;

    let _ = dns_manager::restore_system_dns();
    Ok(())
}
