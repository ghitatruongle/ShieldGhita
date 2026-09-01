use crate::app::AppState;
use crate::modules::system::dns_manager;
use chrono::Local;
use slint::ComponentHandle;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tracing::info;

static APPLY_PROTECTION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn apply_protection(s: &Arc<AppState>, enabled: bool) {
    let _sequence_guard = APPLY_PROTECTION_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
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
}

pub fn register(ui: &crate::AppWindow, state: &Arc<AppState>) {
    let s = state.clone();
    ui.on_toggle_protection(move |enabled| {
        apply_protection(&s, enabled);
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
        crate::modules::config::AppConfig::set_autostart_registry(enabled);
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
    ui.on_toggle_minimize_to_tray_on_minimize(move |enabled| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.minimize_to_tray_on_minimize = enabled;
            let _ = cfg_guard.save();
        }
        info!(
            "Minimize-to-tray behavior set to: {}",
            if enabled { "TRAY" } else { "TASKBAR" }
        );
    });

    let s = state.clone();
    ui.on_toggle_start_hidden_in_tray(move |enabled| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.start_hidden_in_tray = enabled;
            let _ = cfg_guard.save();
        }
        info!(
            "Start hidden in tray set to: {}",
            if enabled { "ENABLED" } else { "DISABLED" }
        );
    });

    let s = state.clone();
    let ui_weak_lang = ui.as_weak();
    ui.on_change_language(move |lang| {
        let lang_str = match lang.as_str() {
            "en" => "en".to_string(),
            "zh" => "zh".to_string(),
            _ => "vi".to_string(),
        };
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.language = lang_str.clone();
            let _ = cfg_guard.save();
        }
        crate::modules::i18n::set_language(&lang_str);
        if let Some(ui_inst) = ui_weak_lang.upgrade() {
            ui_inst
                .global::<crate::I18n>()
                .set_lang(crate::modules::i18n::current_index() as i32);
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

    let s_exp = state.clone();
    ui.on_export_incidents(move || match s_exp.security_engine.export_incidents_csv() {
        Ok(path) => info!("Incidents exported to CSV: {}", path),
        Err(e) => tracing::error!("Failed to export incidents: {}", e),
    });

    let s = state.clone();
    ui.on_add_custom_rule(move |rule| {
        let rule_str = rule.to_string();
        if rule_str.is_empty() {
            return;
        }
        let normalized = match crate::modules::dns::DnsBlocker::validate_domain(&rule_str) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(
                    "{}: {}",
                    crate::modules::i18n::tr(
                        "Từ chối rule chặn không hợp lệ",
                        "Rejected invalid block rule",
                        "拒绝了无效的屏蔽规则"
                    ),
                    e
                );
                return;
            }
        };
        if let Err(e) = s.blocker.add_custom_domain(&normalized) {
            tracing::error!("Failed to add custom rule: {}", e);
            return;
        }
        info!("Added custom block rule: {}", normalized);
        if let Ok(mut cfg_guard) = s.config.write() {
            if !cfg_guard.custom_blocked_domains.contains(&normalized) {
                cfg_guard.custom_blocked_domains.push(normalized);
                let _ = cfg_guard.save();
            }
            s.rules_dirty.store(true, Ordering::SeqCst);
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
        s.rules_dirty.store(true, Ordering::SeqCst);
    });

    let s = state.clone();
    ui.on_add_allowed_rule(move |rule| {
        let rule_str = rule.to_string();
        if rule_str.is_empty() {
            return;
        }
        let normalized = match crate::modules::dns::DnsBlocker::validate_domain(&rule_str) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(
                    "{}: {}",
                    crate::modules::i18n::tr(
                        "Từ chối rule cho phép không hợp lệ",
                        "Rejected invalid allow rule",
                        "拒绝了无效的允许规则"
                    ),
                    e
                );
                return;
            }
        };
        if let Err(e) = s.blocker.add_allowed_domain(&normalized) {
            tracing::error!("Failed to add whitelist rule: {}", e);
            return;
        }
        info!("Added whitelist rule: {}", normalized);
        if let Ok(mut cfg_guard) = s.config.write() {
            if !cfg_guard.custom_allowed_domains.contains(&normalized) {
                cfg_guard.custom_allowed_domains.push(normalized);
                let _ = cfg_guard.save();
            }
            s.rules_dirty.store(true, Ordering::SeqCst);
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
        s.rules_dirty.store(true, Ordering::SeqCst);
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

    ui.on_open_latest_release(move || {
        const RELEASES_URL: &str = "https://github.com/ghitatruongle/ShieldGhita/releases/latest";
        match crate::modules::system::open_url_in_default_browser(RELEASES_URL) {
            Ok(()) => info!("Opened latest release page in default browser"),
            Err(e) => tracing::error!("Failed to open release page: {}", e),
        }
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_run_speed_test(move || {
        let ui_weak = ui_weak.clone();
        s.runtime.spawn(async move {
            let res =
                crate::modules::monitor::diagnostics::NetworkDiagnostics::run_speed_test().await;
            if let Some(ui_inst) = ui_weak.upgrade() {
                ui_inst.set_is_running_speed(false);
                ui_inst.set_speed_download(res.download_mbps as f32);
                ui_inst.set_speed_upload(res.upload_mbps as f32);
                ui_inst.set_speed_ping_ms(res.ping_ms);
                ui_inst.set_speed_detail(res.detail.into());
            }
        });
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_run_dns_benchmark(move |domain| {
        let domain_str = if domain.is_empty() {
            "google.com".to_string()
        } else {
            domain.to_string()
        };
        let ui_weak = ui_weak.clone();
        s.runtime.spawn(async move {
            let results =
                crate::modules::monitor::diagnostics::NetworkDiagnostics::run_dns_benchmark(
                    &domain_str,
                )
                .await;
            if let Some(ui_inst) = ui_weak.upgrade() {
                ui_inst.set_is_running_benchmark(false);
                let items: Vec<crate::DnsBenchmarkItem> = results
                    .into_iter()
                    .map(|r| crate::DnsBenchmarkItem {
                        provider_name: r.provider_name.into(),
                        ip: r.ip.into(),
                        response_ms: r.latency_ms,
                        status: r.status.into(),
                        is_fastest: r.is_fastest,
                    })
                    .collect();
                ui_inst.set_dns_benchmarks(slint::ModelRc::new(slint::VecModel::from(items)));
            }
        });
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_toggle_device_quarantine(move |ip, quarantine| {
        let ip_str = ip.to_string();
        if quarantine {
            s.security_engine.quarantine_ip(&ip_str);
        } else {
            s.security_engine.unquarantine_ip(&ip_str);
        }
        if let Some(ui_inst) = ui_weak.upgrade() {
            super::refresh::refresh_ui_state(&ui_inst, &s);
        }
    });

    let s = state.clone();
    ui.on_export_config_backup(move || {
        let cfg_toml = {
            let cfg_guard = s.config.read().unwrap_or_else(|e| e.into_inner());
            toml::to_string(&*cfg_guard).unwrap_or_default()
        };
        let blocked = s.blocker.get_custom_rules();
        let allowed = s.blocker.get_allowed_rules();
        let devices = s
            .monitor
            .get_lan_devices()
            .into_iter()
            .map(|d| d.ip)
            .collect::<Vec<_>>();
        match crate::modules::backup::ConfigBackupManager::create_backup(
            &cfg_toml, &blocked, &allowed, &devices,
        ) {
            Ok(p) => info!("Configuration backup saved successfully to {:?}", p),
            Err(e) => tracing::error!("Failed to create backup: {}", e),
        }
    });

    let s = state.clone();
    let ui_restore = ui.as_weak();
    ui.on_import_config_backup(move || {
        let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        let backup_dir = std::path::PathBuf::from(app_data)
            .join("ShieldGhita")
            .join("backups");
        if let Ok(entries) = std::fs::read_dir(&backup_dir) {
            let mut backups: Vec<std::path::PathBuf> = entries
                .filter_map(|e| e.ok().map(|d| d.path()))
                .filter(|p| p.extension().map(|ext| ext == "sgconfig").unwrap_or(false))
                .collect();
            backups.sort();
            if let Some(latest) = backups.last() {
                match crate::modules::backup::ConfigBackupManager::load_backup(latest) {
                    Ok(pkg) => {
                        info!("Restored backup package created at {}", pkg.created_at);
                        // Apply the full config section (already checksum- and
                        // format-verified by load_backup) to memory + disk so
                        // the restore covers more than the custom rules.
                        match toml::from_str::<crate::modules::config::AppConfig>(&pkg.config_toml)
                        {
                            Ok(new_cfg) => {
                                let cfg_info = format!(
                                    "listening {}, {} blocklist sources",
                                    new_cfg.dns_listen_port,
                                    new_cfg.blocklist_urls.len()
                                );
                                *s.config.write().unwrap_or_else(|e| e.into_inner()) =
                                    new_cfg.clone();
                                if let Err(e) = new_cfg.save() {
                                    tracing::error!("Failed to persist restored config: {}", e);
                                }
                                info!("Restored full config ({})", cfg_info);
                            }
                            Err(e) => {
                                tracing::error!("Restored config_toml failed to parse: {}", e)
                            }
                        }
                        for r in &pkg.custom_blocked_domains {
                            let _ = s.blocker.add_custom_domain(r);
                        }
                        for r in &pkg.custom_allowed_domains {
                            let _ = s.blocker.add_allowed_domain(r);
                        }
                        s.rules_dirty.store(true, Ordering::SeqCst);
                        if let Some(ui_inst) = ui_restore.upgrade() {
                            super::refresh::refresh_ui_state(&ui_inst, &s);
                        }
                    }
                    Err(e) => tracing::error!("Failed to restore backup: {}", e),
                }
            }
        }
    });
}
