use crate::app::AppState;
use crate::modules::config::AppConfig;
use crate::modules::system::dns_manager;
use chrono::Local;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tracing::info;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem},
    Icon, TrayIcon, TrayIconBuilder,
};

pub fn create_default_icon() -> Result<Icon, Box<dyn std::error::Error>> {
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
            if (-0.85..=0.0).contains(&ny) {
                bound = 0.82 - (ny + 0.85) * 0.05;
            } else if (0.0..=0.92).contains(&ny) {
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

pub fn setup_ui_bridge(
    ui: &crate::AppWindow,
    state: Arc<AppState>,
) -> Result<Option<TrayIcon>, Box<dyn std::error::Error>> {
    let cfg = state
        .config
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    ui.set_is_vi(cfg.language == "vi");
    ui.set_enable_notifications(cfg.enable_block_notifications);
    ui.set_app_version("0.0.5-beta1".into());
    ui.set_host_lan_ip(dns_manager::get_lan_ip_address().into());
    ui.set_network_wide_adblock(cfg.network_wide_adblock_enabled);
    ui.set_attack_detection_enabled(cfg.attack_detection_enabled);
    ui.set_auto_block_attacks(cfg.auto_block_attacks);
    ui.set_arp_spoof_detection(cfg.arp_spoof_detection);

    #[cfg(feature = "admin")]
    ui.set_is_admin_edition(true);

    #[cfg(not(feature = "admin"))]
    ui.set_is_admin_edition(false);

    let tray_menu = Menu::new();
    let item_show = MenuItem::new("Mở giao diện Shield Ghita", true, None);
    let item_toggle = MenuItem::new("Bật / Tắt bảo vệ", true, None);
    let item_quit = MenuItem::new("Thoát hoàn toàn", true, None);
    let _ = tray_menu.append(&item_show);
    let _ = tray_menu.append(&item_toggle);
    let _ = tray_menu.append(&item_quit);

    let tray_icon = match create_default_icon() {
        Ok(icon) => TrayIconBuilder::new()
            .with_menu(Box::new(tray_menu))
            .with_tooltip("Shield Ghita v0.0.5-beta1 - Master Controller")
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
            if let Err(e) = dns_manager::set_system_dns("127.0.0.1") {
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
        info!(
            "Silent Sinkhole Mode changed: {}",
            if enabled { "ENABLED" } else { "DISABLED" }
        );
    });

    let s = state.clone();
    ui.on_toggle_network_wide_adblock(move |enabled| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.network_wide_adblock_enabled = enabled;
            let _ = cfg_guard.save();
        }
        dns_manager::configure_lan_dns_firewall(enabled);
        info!(
            "Network-wide Adblock changed: {}",
            if enabled {
                "ENABLED (Port 53 opened on LAN)"
            } else {
                "DISABLED"
            }
        );
    });

    let s = state.clone();
    ui.on_toggle_attack_detection(move |enabled| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.attack_detection_enabled = enabled;
            let _ = cfg_guard.save();
        }
        s.security_engine.set_detection_enabled(enabled);
    });

    let s = state.clone();
    ui.on_toggle_auto_block_attacks(move |enabled| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.auto_block_attacks = enabled;
            let _ = cfg_guard.save();
        }
        s.security_engine.set_auto_block(enabled);
    });

    let s = state.clone();
    ui.on_toggle_arp_spoof_detection(move |enabled| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.arp_spoof_detection = enabled;
            let _ = cfg_guard.save();
        }
        s.security_engine.set_arp_detection(enabled);
    });

    let s = state.clone();
    ui.on_toggle_autostart(move |enabled| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.start_with_windows = enabled;
            let _ = cfg_guard.save();
        }
        AppConfig::set_autostart_registry(enabled);
        info!(
            "Autostart with Windows set to: {}",
            if enabled { "ENABLED" } else { "DISABLED" }
        );
    });

    let s = state.clone();
    ui.on_toggle_minimize_to_tray(move |enabled| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.minimize_to_tray = enabled;
            let _ = cfg_guard.save();
        }
        info!(
            "Minimize to tray on close set to: {}",
            if enabled { "ENABLED" } else { "DISABLED" }
        );
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
        info!(
            "Ad blocking notifications set to: {}",
            if enabled { "ENABLED" } else { "DISABLED" }
        );
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
        let monitor_ref = s.monitor.clone();
        let sec = s.security_engine.clone();
        s.runtime.spawn(async move {
            let _ = monitor_ref.lan_scanner.scan_network(Some(sec)).await;
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

    let s_sec = state.clone();
    ui.on_clear_security_incidents(move || {
        s_sec.security_engine.clear_incidents();
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
                let cfg_guard = state_clone.config.read().unwrap_or_else(|e| e.into_inner());
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
    ui.on_export_logs(move || match s.monitor.export_logs_csv() {
        Ok(path) => info!("Logs exported to CSV: {}", path),
        Err(e) => tracing::error!("Failed to export logs: {}", e),
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

    let s = state.clone();
    let ui_weak_ip = ui.as_weak();
    ui.on_filter_logs_by_ip(move |ip| {
        let ip_str = ip.to_string();
        s.monitor.apply_filter("", &ip_str, None);
        if let Some(ui_inst) = ui_weak_ip.upgrade() {
            ui_inst.set_monitor_subview_mode(1);
        }
    });

    #[cfg(feature = "admin")]
    {
        let s_scan = state.clone();
        ui.on_trigger_proximity_scan(move || {
            let rt = s_scan.runtime.clone();
            let mgr = s_scan.local_manager.clone();
            rt.spawn(async move {
                mgr.trigger_proximity_sweep().await;
            });
        });

        let s_ref = state.clone();
        let ui_ref = ui.as_weak();
        ui.on_refresh_admin_data(move || {
            if let Some(ui_win) = ui_ref.upgrade() {
                update_admin_ui(&ui_win, &s_ref);
            }
        });
    }

    #[cfg(not(feature = "admin"))]
    {
        ui.on_trigger_proximity_scan(|| {});
        ui.on_refresh_admin_data(|| {});
    }

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
                let is_vi = config.read().map(|c| c.language == "vi").unwrap_or(true);
                let title = if is_vi {
                    "ĐÃ CHẶN QUẢNG CÁO & TRACKER"
                } else {
                    "AD & TRACKER BLOCKED"
                }
                .to_string();

                let ui_weak_inner = ui_weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui_inst) = ui_weak_inner.upgrade() {
                        ui_inst.set_toast_title(title.into());
                        ui_inst.set_toast_domain(domain_clone.into());
                        ui_inst.set_toast_time(time_clone.into());
                        ui_inst.set_toast_is_threat(false);
                        ui_inst.set_show_toast(true);
                    }
                });

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
        let mut rx_alert = state.security_engine.alert_tx.subscribe();
        let ui_weak = ui.as_weak();
        state.runtime.spawn(async move {
            while let Ok(incident) = rx_alert.recv().await {
                let ui_weak_inner = ui_weak.clone();
                let title = format!("🚨 {}", incident.incident_type);
                let domain_msg = format!("{} [{}]", incident.details, incident.source_ip);
                let time_str = incident.time.clone();

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui_inst) = ui_weak_inner.upgrade() {
                        ui_inst.set_toast_title(title.into());
                        ui_inst.set_toast_domain(domain_msg.into());
                        ui_inst.set_toast_time(time_str.into());
                        ui_inst.set_toast_is_threat(true);
                        ui_inst.set_show_toast(true);
                    }
                });

                let ui_weak_timer = ui_weak.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(5000)).await;
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
        let monitor_init = state.monitor.clone();
        let sec = state.security_engine.clone();
        state.runtime.spawn(async move {
            let _ = monitor_init.lan_scanner.scan_network(Some(sec)).await;
            monitor_init.connection_tracker.refresh_connections();
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
                    if let Some(ui_win) = ui_weak.upgrade() {
                        let _ = ui_win.show();
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
                        let _ = dns_manager::set_system_dns("127.0.0.1");
                    } else {
                        let _ = dns_manager::restore_system_dns();
                    }
                } else if event.id == quit_id {
                    let _ = dns_manager::restore_system_dns();
                    std::process::exit(0);
                }
            }

            if let Some(ui_win) = ui_weak.upgrade() {
                let total = s.blocker.total_queries.load(Ordering::Relaxed);
                let blocked = s.blocker.blocked_count.load(Ordering::Relaxed);
                let absorbed = s.sinkhole.absorbed_count.load(Ordering::Relaxed);
                let rules_count = s.blocker.get_rules_count();
                ui_win.set_total_queries(total as i32);
                ui_win.set_blocked_count(blocked as i32);
                ui_win.set_absorbed_count(absorbed as i32);
                ui_win.set_active_rules_count(rules_count as i32);

                let is_locked = dns_manager::is_master_internet_locked();
                ui_win.set_master_locked(is_locked);
                ui_win.set_silent_sinkhole(s.blocker.is_silent_sinkhole());

                let is_vi = s.config.read().map(|c| c.language == "vi").unwrap_or(true);
                ui_win.set_is_vi(is_vi);

                let protection = s.protection_atomic.load(Ordering::Relaxed);
                ui_win.set_protection_enabled(protection);
                ui_win.set_status_text(if is_locked {
                    if is_vi {
                        "🔒 Đã khóa Internet".into()
                    } else {
                        "🔒 Internet Locked".into()
                    }
                } else if protection {
                    if is_vi {
                        "🟢 Đang bảo vệ tối cao".into()
                    } else {
                        "🟢 Active Protection".into()
                    }
                } else {
                    if is_vi {
                        "🔴 Đã tạm dừng".into()
                    } else {
                        "🔴 Paused".into()
                    }
                });

                let (autostart, minimize, notify, net_adblock, attack_det, auto_blk, arp_det) = s
                    .config
                    .read()
                    .map(|c| {
                        (
                            c.start_with_windows,
                            c.minimize_to_tray,
                            c.enable_block_notifications,
                            c.network_wide_adblock_enabled,
                            c.attack_detection_enabled,
                            c.auto_block_attacks,
                            c.arp_spoof_detection,
                        )
                    })
                    .unwrap_or((true, true, true, false, false, false, false));

                ui_win.set_autostart_enabled(autostart);
                ui_win.set_minimize_to_tray_enabled(minimize);
                ui_win.set_enable_notifications(notify);
                ui_win.set_network_wide_adblock(net_adblock);
                ui_win.set_attack_detection_enabled(attack_det);
                ui_win.set_auto_block_attacks(auto_blk);
                ui_win.set_arp_spoof_detection(arp_det);

                let (cpu, mem) = s.monitor.get_system_metrics();
                ui_win.set_cpu_usage(cpu);
                ui_win.set_mem_usage(mem);
                ui_win.set_live_traffic_rate(s.monitor.get_live_traffic_rate().into());

                let sec_score = s.security_engine.get_security_score();
                ui_win.set_security_score(sec_score);

                let incidents = s.security_engine.get_incidents();
                ui_win.set_threats_blocked_count(incidents.len() as i32);

                let last_update = s
                    .config
                    .read()
                    .ok()
                    .and_then(|c| c.last_blocklist_update.clone())
                    .unwrap_or_else(|| {
                        if is_vi {
                            "Chưa cập nhật".to_string()
                        } else {
                            "Not updated".to_string()
                        }
                    });
                ui_win.set_last_update_text(if is_vi {
                    format!("Cập nhật: {}", last_update).into()
                } else {
                    format!("Updated: {}", last_update).into()
                });

                let custom_rules = s
                    .config
                    .read()
                    .map(|c| c.custom_blocked_domains.clone())
                    .unwrap_or_default();
                let rule_models: Vec<slint::SharedString> =
                    custom_rules.into_iter().map(|r| r.into()).collect();
                ui_win.set_custom_rules(ModelRc::new(VecModel::from(rule_models)));

                let allowed_rules = s
                    .config
                    .read()
                    .map(|c| c.custom_allowed_domains.clone())
                    .unwrap_or_default();
                let allow_models: Vec<slint::SharedString> =
                    allowed_rules.into_iter().map(|r| r.into()).collect();
                ui_win.set_allowed_rules(ModelRc::new(VecModel::from(allow_models)));

                let conns = s.monitor.get_active_connections();
                let conn_models: Vec<crate::ActiveConnection> = conns
                    .into_iter()
                    .map(|c| crate::ActiveConnection {
                        process_name: c.process_name.into(),
                        pid: c.pid as i32,
                        local_addr: c.local_addr.into(),
                        remote_addr: c.remote_addr.into(),
                        protocol: c.protocol.into(),
                        state: c.state.into(),
                        is_safe: c.is_safe,
                    })
                    .collect();
                ui_win.set_connections(ModelRc::new(VecModel::from(conn_models)));

                let grp_conns = s.monitor.connection_tracker.get_grouped_connections();
                let grp_conn_models: Vec<crate::AppConnectionGroup> = grp_conns
                    .into_iter()
                    .map(|g| crate::AppConnectionGroup {
                        process_name: g.process_name.into(),
                        pid: g.pid as i32,
                        connection_count: g.connection_count as i32,
                        destinations_summary: g.destinations_summary.into(),
                        protocol_summary: g.protocol_summary.into(),
                        state_summary: g.state_summary.into(),
                        is_safe: g.is_safe,
                    })
                    .collect();
                ui_win.set_grouped_connections(ModelRc::new(VecModel::from(grp_conn_models)));

                let devices = s.monitor.get_lan_devices();
                ui_win.set_lan_devices_count(devices.len() as i32);
                let device_models: Vec<crate::NetworkDevice> = devices
                    .into_iter()
                    .map(|d| crate::NetworkDevice {
                        name: d.name.into(),
                        ip: d.ip.into(),
                        mac: d.mac.into(),
                        vendor: d.vendor.into(),
                        device_type: d.device_type.into(),
                        is_online: d.is_online,
                        latency: format!("{} ms", d.latency_ms).into(),
                        traffic: d.traffic.into(),
                        total_queries: d.total_queries as i32,
                        blocked_queries: d.blocked_queries as i32,
                        threats_detected: d.threats_detected as i32,
                        last_domain: d.last_domain.into(),
                        last_active: d.last_active.into(),
                        risk_level: d.risk_level.into(),
                    })
                    .collect();
                ui_win.set_devices(ModelRc::new(VecModel::from(device_models)));

                let logs = s.monitor.get_logs();
                let log_models: Vec<crate::LogEntry> = logs
                    .into_iter()
                    .map(|l| crate::LogEntry {
                        timestamp: l.timestamp.into(),
                        domain: l.domain.into(),
                        source_ip: l.source_ip.into(),
                        is_blocked: l.is_blocked,
                    })
                    .collect();
                ui_win.set_logs(ModelRc::new(VecModel::from(log_models)));

                let grp_logs = s.monitor.get_grouped_logs();
                let grp_log_models: Vec<crate::DomainLogGroup> = grp_logs
                    .into_iter()
                    .map(|g| crate::DomainLogGroup {
                        domain: g.domain.into(),
                        total_queries: g.total_queries as i32,
                        blocked_queries: g.blocked_queries as i32,
                        is_blocked: g.is_blocked,
                        last_seen: g.last_seen.into(),
                        last_ip: g.last_ip.into(),
                    })
                    .collect();
                ui_win.set_grouped_logs(ModelRc::new(VecModel::from(grp_log_models)));

                let clogs = s.log_buffer.get_logs();
                let clog_models: Vec<crate::ConsoleLogEntry> = clogs
                    .into_iter()
                    .map(|cl| crate::ConsoleLogEntry {
                        time: cl.time.into(),
                        level: cl.level.into(),
                        message: cl.message.into(),
                    })
                    .collect();
                ui_win.set_console_logs(ModelRc::new(VecModel::from(clog_models)));

                let incident_models: Vec<crate::SecurityIncident> = incidents
                    .into_iter()
                    .map(|inc| crate::SecurityIncident {
                        id: inc.id as i32,
                        time: inc.time.into(),
                        incident_type: inc.incident_type.into(),
                        source_ip: inc.source_ip.into(),
                        details: inc.details.into(),
                        severity: inc.severity.into(),
                        mitigation: inc.mitigation.into(),
                    })
                    .collect();
                ui_win.set_security_incidents(ModelRc::new(VecModel::from(incident_models)));

                #[cfg(feature = "admin")]
                {
                    update_admin_ui(&ui_win, &s);
                }
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
            if let Some(ui_inst) = ui_weak_close.upgrade() {
                let _ = ui_inst.hide();
            }
            slint::CloseRequestResponse::KeepWindowShown
        } else {
            let _ = dns_manager::restore_system_dns();
            std::process::exit(0);
        }
    });

    std::mem::forget(timer);
    Ok(tray_icon)
}

#[cfg(feature = "admin")]
fn update_admin_ui(ui_win: &crate::AppWindow, state: &Arc<AppState>) {
    let pdevs = state.local_manager.get_devices();
    ui_win.set_proximity_devices_count(pdevs.len() as i32);
    let pdev_models: Vec<crate::ProximityDeviceItem> = pdevs
        .into_iter()
        .map(|d| crate::ProximityDeviceItem {
            id: d.id.into(),
            name: d.name.into(),
            ip: d.ip.into(),
            mac: d.mac.into(),
            vendor: d.vendor.into(),
            discovery_method: d.discovery_method.into(),
            signal_info: d.signal_info.into(),
            last_seen: d.last_seen.into(),
            latency_ms: d.latency_ms,
            is_online: d.is_online,
            open_ports_str: if d.open_ports.is_empty() {
                "Không có cổng mở".into()
            } else {
                d.open_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
                    .into()
            },
        })
        .collect();
    ui_win.set_proximity_devices(ModelRc::new(VecModel::from(pdev_models)));

    let profiles = state.local_manager.get_profiles();
    ui_win.set_behavior_profiles_count(profiles.len() as i32);
    ui_win.set_high_risk_count(state.local_manager.get_high_risk_count() as i32);
    ui_win.set_wifi_nodes_count(state.local_manager.get_wifi_nodes().len() as i32);

    let profile_models: Vec<crate::BehaviorProfileItem> = profiles
        .into_iter()
        .map(|p| crate::BehaviorProfileItem {
            ip: p.ip.into(),
            hostname: p.hostname.into(),
            total_queries: p.total_queries as i32,
            blocked_queries: p.blocked_queries as i32,
            threat_queries: p.threat_queries as i32,
            burst_qps: format!("{:.1} qps", p.burst_qps).into(),
            risk_score: p.risk_score as i32,
            category: p.category.to_string().into(),
            last_seen: p.last_seen.into(),
        })
        .collect();
    ui_win.set_behavior_profiles(ModelRc::new(VecModel::from(profile_models)));
}
