use super::*;

pub(super) fn register(ui: &crate::AppWindow, state: &Arc<AppState>) {
    let s = state.clone();
    ui.on_toggle_autostart(move |enabled| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.start_with_windows = enabled;
            let _ = cfg_guard.save();
        }
        // reg.exe blocks; keep it off the Slint event-loop thread.
        std::thread::spawn(move || {
            crate::modules::config::AppConfig::set_autostart_registry(enabled);
        });
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
    ui.on_toggle_admin_panel(move |enabled| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.admin_panel_enabled = enabled;
            let _ = cfg_guard.save();
        }
        info!(
            "Admin web panel set to: {} (applied on app restart)",
            if enabled { "ENABLED" } else { "DISABLED" }
        );
    });

    let s = state.clone();
    let ui_weak_lang = ui.as_weak();
    ui.on_change_language(move |lang| {
        let lang_str = match lang.as_str() {
            "en" => "en".to_string(),
            "zh" => "zh".to_string(),
            "ru" => "ru".to_string(),
            _ => "vi".to_string(),
        };
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.language = lang_str.clone();
            let _ = cfg_guard.save();
        }
        crate::modules::i18n::set_language(&lang_str);
        crate::app::ui_bridge::update_tray_menu_language();
        if let Some(ui_inst) = ui_weak_lang.upgrade() {
            ui_inst
                .global::<crate::I18n>()
                .set_lang(crate::modules::i18n::current_index() as i32);
            crate::app::ui_bridge::refresh::refresh_ui_state(&ui_inst, &s);
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

    let ui_weak_onboard = ui.as_weak();
    let s_onboard = state.clone();
    ui.on_dismiss_onboarding(move || {
        if let Some(ui_inst) = ui_weak_onboard.upgrade() {
            ui_inst.set_show_onboarding(false);
        }
        if let Ok(mut cfg) = s_onboard.config.write() {
            cfg.onboarding_done = true;
            let _ = cfg.save();
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
        if crate::modules::service::remote_mode() {
            remote_send(crate::modules::service::protocol::CoreRequest::CustomRule {
                domain: normalized.clone(),
                allow: false,
                add: true,
            });
            info!("Added custom block rule via service: {}", normalized);
        } else if let Err(e) = s.blocker.add_custom_domain(&normalized) {
            tracing::error!("Failed to add custom rule: {}", e);
            return;
        } else {
            info!("Added custom block rule: {}", normalized);
        }
        if let Ok(mut cfg_guard) = s.config.write() {
            if !cfg_guard.custom_blocked_domains.contains(&normalized) {
                cfg_guard.custom_blocked_domains.push(normalized);
                let _ = cfg_guard.save();
            }
        }
        // Set outside the config lock so a failed lock cannot skip UI refresh.
        s.rules_dirty.store(true, Ordering::SeqCst);
    });

    let s = state.clone();
    ui.on_remove_custom_rule(move |rule| {
        let rule_str = rule.to_string();
        // Normalize (trim/lowercase) so " Example.COM " matches stored form.
        let normalized = crate::modules::dns::DnsBlocker::validate_domain(&rule_str)
            .unwrap_or_else(|_| rule_str.trim().trim_end_matches('.').to_lowercase());
        if normalized.is_empty() {
            return;
        }
        if crate::modules::service::remote_mode() {
            remote_send(crate::modules::service::protocol::CoreRequest::CustomRule {
                domain: normalized.clone(),
                allow: false,
                add: false,
            });
        } else if let Err(e) = s.blocker.remove_custom_domain(&normalized) {
            tracing::error!("Failed to remove custom rule: {}", e);
        }
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard
                .custom_blocked_domains
                .retain(|d| d != &normalized);
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
        if crate::modules::service::remote_mode() {
            remote_send(crate::modules::service::protocol::CoreRequest::CustomRule {
                domain: normalized.clone(),
                allow: true,
                add: true,
            });
            info!("Added whitelist rule via service: {}", normalized);
        } else {
            if let Err(e) = s.blocker.add_allowed_domain(&normalized) {
                tracing::error!("Failed to add whitelist rule: {}", e);
                return;
            }
            info!("Added whitelist rule: {}", normalized);
        }
        if let Ok(mut cfg_guard) = s.config.write() {
            if !cfg_guard.custom_allowed_domains.contains(&normalized) {
                cfg_guard.custom_allowed_domains.push(normalized);
                let _ = cfg_guard.save();
            }
        }
        // Set outside the config lock so a failed lock cannot skip UI refresh.
        s.rules_dirty.store(true, Ordering::SeqCst);
    });

    let s = state.clone();
    ui.on_remove_allowed_rule(move |rule| {
        let rule_str = rule.to_string();
        let normalized = crate::modules::dns::DnsBlocker::validate_domain(&rule_str)
            .unwrap_or_else(|_| rule_str.trim().trim_end_matches('.').to_lowercase());
        if normalized.is_empty() {
            return;
        }
        if crate::modules::service::remote_mode() {
            remote_send(crate::modules::service::protocol::CoreRequest::CustomRule {
                domain: normalized.clone(),
                allow: true,
                add: false,
            });
        } else if let Err(e) = s.blocker.remove_allowed_domain(&normalized) {
            tracing::error!("Failed to remove whitelist rule: {}", e);
        }
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard
                .custom_allowed_domains
                .retain(|d| d != &normalized);
            let _ = cfg_guard.save();
        }
        s.rules_dirty.store(true, Ordering::SeqCst);
    });

    let s = state.clone();
    ui.on_update_blocklist(move || {
        if crate::modules::service::remote_mode() {
            if let Err(e) = crate::app::control_plane::CoreClient::send(
                crate::modules::service::protocol::CoreRequest::UpdateBlocklists,
                std::time::Duration::from_secs(10),
            ) {
                tracing::error!("Service blocklist update request failed: {}", e);
                return;
            }
            info!("Blocklist update requested via service");
            if let Ok(mut cfg_guard) = s.config.write() {
                cfg_guard.last_blocklist_update =
                    Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                let _ = cfg_guard.save();
            }
            return;
        }
        let state_clone = s.clone();
        s.runtime.spawn(async move {
            let urls = {
                let cfg_guard = state_clone.config.read().unwrap_or_else(|e| e.into_inner());
                cfg_guard.blocklist_urls.clone()
            };
            let doh_sources = {
                let cfg_guard = state_clone.config.read().unwrap_or_else(|e| e.into_inner());
                cfg_guard.upstream_dns.clone()
            };
            match state_clone
                .blocker
                .load_blocklists(&urls, &doh_sources)
                .await
            {
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
            // Keep the filter textbox in sync so Filter/Clear round-trips.
            ui_inst.set_filter_ip_text(ip_str.into());
        }
    });

    ui.on_open_latest_release(move || {
        const RELEASES_URL: &str = "https://github.com/ghitatruongle/ShieldGhita/releases/latest";
        match crate::modules::system::open_url_in_default_browser(RELEASES_URL) {
            Ok(()) => info!("Opened latest release page in default browser"),
            Err(e) => tracing::error!("Failed to open release page: {}", e),
        }
    });
}
