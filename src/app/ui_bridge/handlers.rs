use crate::app::AppState;
use crate::modules::system::dns_manager;
use chrono::Local;
use slint::ComponentHandle;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tracing::info;

static APPLY_PROTECTION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn register_quarantine_callback(
    ui: &crate::AppWindow,
    engine: Arc<crate::modules::security::SecurityEngine>,
    refresh: impl Fn() + 'static,
) {
    let weak = ui.as_weak();
    ui.on_toggle_device_quarantine(move |ip, quarantine| {
        let result = if quarantine {
            engine.quarantine_ip(ip.as_str())
        } else {
            engine.unquarantine_ip(ip.as_str());
            Ok(())
        };
        refresh();
        if let Err(reason) = result {
            if let Some(window) = weak.upgrade() {
                window.set_status_text(reason.message().into());
            }
        }
    });
}

/// Saturating usize/u64 -> i32 for Slint properties (avoids `as i32` wrap).
fn sat_i32_usize(v: usize) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

fn sat_i32_u64(v: u64) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

fn u64_to_f32_sat(v: u64) -> f32 {
    const F32_MAX_AS_U64: u64 = 16_777_216 * 16_777_216 * 256; // 2^~128 approx guard
    if v > F32_MAX_AS_U64 {
        f32::MAX
    } else {
        v as f32
    }
}

/// Human-readable file size (e.g. "1.2 MB") for status lines.
#[allow(dead_code)]
fn bytes_to_mb_string(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}

pub fn apply_protection(s: &Arc<AppState>, enabled: bool) {
    let _sequence_guard = APPLY_PROTECTION_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    s.protection_atomic.store(enabled, Ordering::SeqCst);
    if let Ok(mut cfg_guard) = s.config.write() {
        cfg_guard.protection_enabled = enabled;
        let _ = cfg_guard.save();
    }
    // Refresh WFP rule lists from config before enable/disable so custom
    // IP/port rules always match the last saved config.toml.
    let (wfp_ips, wfp_ports) = s
        .config
        .read()
        .map(|c| (c.wfp_blocked_ips.clone(), c.wfp_blocked_ports.clone()))
        .unwrap_or_default();
    s.wfp_blocker.set_blocked_ips(wfp_ips);
    s.wfp_blocker.set_blocked_ports(wfp_ports);
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

/// Raw HWND of the main window (null when unavailable), used to parent the
/// Win32 file picker so it can never open BEHIND the app window.
fn main_window_hwnd(ui_weak: &slint::Weak<crate::AppWindow>) -> *mut std::ffi::c_void {
    use raw_window_handle::HasWindowHandle as _;
    ui_weak
        .upgrade()
        .and_then(|u| {
            u.window()
                .window_handle()
                .window_handle()
                .ok()
                .and_then(|h| match h.as_raw() {
                    raw_window_handle::RawWindowHandle::Win32(w) => {
                        Some(w.hwnd.get() as *mut std::ffi::c_void)
                    }
                    _ => None,
                })
        })
        .unwrap_or(std::ptr::null_mut())
}

/// Render a successful File Analyzer scan into the UI properties.
/// `file_path`/`findings` are cleared on error, so the success path must
/// overwrite the previous result (done inside `set_file_scan_result`).
fn fa_render_result(
    ui_inst: &crate::AppWindow,
    report: crate::modules::security::file_analyzer::FileScanReport,
) {
    let greeting_done = match crate::modules::i18n::current_index() {
        0 => format!(
            "👋 Hoàn tất phân tích tệp: {} (Mức độ: {})",
            report.file_name, report.risk_level
        ),
        1 => format!(
            "👋 Analysis complete: {} (Risk: {})",
            report.file_name, report.risk_level
        ),
        2 => format!(
            "👋 分析完成：{} (风险级别: {})",
            report.file_name, report.risk_level
        ),
        _ => format!(
            "👋 Анализ завершен: {} (Уровень риска: {})",
            report.file_name, report.risk_level
        ),
    };
    ui_inst.set_file_scan_status(greeting_done.into());

    let res_item = crate::FileScanResult {
        file_path: report.file_path.into(),
        file_name: report.file_name.into(),
        file_size_bytes: u64_to_f32_sat(report.file_size_bytes),
        md5: report.md5.into(),
        sha1: report.sha1.into(),
        sha256: report.sha256.into(),
        entropy: report.entropy as f32,
        risk_score: report.risk_score,
        risk_level: report.risk_level.into(),
        is_pe: report.is_pe,
        is_packed: report.is_packed,
        findings_count: sat_i32_usize(report.findings.len()),
        summary_text: report.summary_text.into(),
    };
    let finding_items: Vec<crate::FileScanFindingItem> = report
        .findings
        .into_iter()
        .map(|f| crate::FileScanFindingItem {
            severity: f.severity.into(),
            category: f.category.into(),
            description: f.description.into(),
            snippet: f.snippet.into(),
        })
        .collect();

    ui_inst.set_file_scan_result(res_item);
    ui_inst.set_file_scan_findings(slint::ModelRc::new(slint::VecModel::from(finding_items)));
}

/// Render a File Analyzer scan failure. Localized (vi/en/zh/ru) — previously
/// the "❌ Lỗi:" prefix was Vietnamese-only.
fn fa_render_error(ui_inst: &crate::AppWindow, err_msg: &str, reset_result: bool) {
    let label = crate::modules::i18n::tr4("❌ Lỗi:", "❌ Error:", "❌ 错误：", "❌ Ошибка:");
    ui_inst.set_file_scan_status(format!("{label} {err_msg}").into());
    if reset_result {
        let empty_res = crate::FileScanResult {
            summary_text: format!("✗ {err_msg}").into(),
            ..Default::default()
        };
        ui_inst.set_file_scan_result(empty_res);
        ui_inst.set_file_scan_findings(slint::ModelRc::new(slint::VecModel::default()));
    }
}

pub fn register(ui: &crate::AppWindow, state: &Arc<AppState>) {
    let s = state.clone();
    ui.on_toggle_protection(move |enabled| {
        // Offload blocking DNS/WFP/self-defense work so the Slint event loop
        // stays responsive; apply_protection serializes via its internal lock.
        let s2 = s.clone();
        std::thread::spawn(move || {
            apply_protection(&s2, enabled);
        });
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
        super::update_tray_menu_language();
        if let Some(ui_inst) = ui_weak_lang.upgrade() {
            ui_inst
                .global::<crate::I18n>()
                .set_lang(crate::modules::i18n::current_index() as i32);
            super::refresh::refresh_ui_state(&ui_inst, &s);
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
        if let Err(e) = s.blocker.remove_custom_domain(&normalized) {
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
        if let Err(e) = s.blocker.remove_allowed_domain(&normalized) {
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

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_run_speed_test(move || {
        let ui_weak = ui_weak.clone();
        s.runtime.spawn(async move {
            let ui_weak_progress = ui_weak.clone();
            let res = crate::modules::monitor::diagnostics::NetworkDiagnostics::run_speed_test_with_progress(
                move |dl, up, ping| {
                    let u = ui_weak_progress.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui_inst) = u.upgrade() {
                            if dl > 0.0 {
                                ui_inst.set_speed_download(dl as f32);
                            }
                            if up > 0.0 {
                                ui_inst.set_speed_upload(up as f32);
                            }
                            if ping >= 0 {
                                ui_inst.set_speed_ping_ms(ping);
                            }
                        }
                    });
                },
            )
            .await;
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui_inst) = ui_weak.upgrade() {
                    ui_inst.set_is_running_speed(false);
                    ui_inst.set_speed_download(res.download_mbps as f32);
                    ui_inst.set_speed_upload(res.upload_mbps as f32);
                    ui_inst.set_speed_ping_ms(res.ping_ms);
                    ui_inst.set_speed_detail(res.detail.into());
                }
            });
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
            let _ = slint::invoke_from_event_loop(move || {
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
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_run_ping(move |target| {
        let target_str = target.to_string();
        let ui_weak = ui_weak.clone();
        s.runtime.spawn(async move {
            let res =
                crate::modules::monitor::diagnostics::NetworkDiagnostics::run_ping(&target_str, 4)
                    .await;
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui_inst) = ui_weak.upgrade() {
                    ui_inst.set_is_running_ping(false);
                    ui_inst.set_ping_result(crate::PingResultItem {
                        target: res.target.into(),
                        min_ms: res.min_ms,
                        avg_ms: res.avg_ms,
                        max_ms: res.max_ms,
                        jitter_ms: res.jitter_ms,
                        loss_pct: res.loss_pct,
                        status_text: res.status_text.into(),
                        details: res.details.into(),
                    });
                }
            });
        });
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_run_network_health(move || {
        let ui_weak = ui_weak.clone();
        s.runtime.spawn(async move {
            let rep =
                crate::modules::monitor::diagnostics::NetworkDiagnostics::run_network_health_check(
                )
                .await;
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui_inst) = ui_weak.upgrade() {
                    ui_inst.set_is_running_health(false);
                    ui_inst.set_health_report(crate::NetworkHealthReport {
                        gateway_status: rep.gateway_status.into(),
                        dns_status: rep.dns_status.into(),
                        internet_status: rep.internet_status.into(),
                        stability_status: rep.stability_status.into(),
                        summary_score: rep.summary_score,
                        overall_text: rep.overall_text.into(),
                    });
                }
            });
        });
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    register_quarantine_callback(ui, s.security_engine.clone(), move || {
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

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_ram_empty(move |idx| {
        let op = match idx {
            0 => crate::modules::rammap::EmptyOp::WorkingSets,
            1 => crate::modules::rammap::EmptyOp::SystemWorkingSet,
            2 => crate::modules::rammap::EmptyOp::ModifiedPageList,
            3 => crate::modules::rammap::EmptyOp::StandbyList,
            _ => crate::modules::rammap::EmptyOp::Priority0StandbyList,
        };
        let ui_weak = ui_weak.clone();
        s.runtime.spawn(async move {
            let busy_weak = ui_weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui_inst) = busy_weak.upgrade() {
                    ui_inst.set_ram_is_busy(true);
                }
            });
            let result = tokio::task::spawn_blocking(move || crate::modules::rammap::empty(op))
                .await
                .unwrap_or_else(|e| Err(format!("join error: {e}")));
            let msg = match result {
                Ok(freed) => format!(
                    "✓ {} — {} ~{} MB",
                    op.label(),
                    crate::modules::i18n::tr("đã giải phóng", "freed", "已释放"),
                    freed
                ),
                Err(e) => format!("✗ {e}"),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui_inst) = ui_weak.upgrade() {
                    ui_inst.set_ram_is_busy(false);
                    ui_inst.set_ram_last_action(msg.into());
                }
            });
        });
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_ram_scan_memory(move || {
        let ui_weak = ui_weak.clone();
        let s2 = s.clone();
        s.runtime.spawn(async move {
            let busy_weak = ui_weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui_inst) = busy_weak.upgrade() {
                    ui_inst.set_ram_is_busy(true);
                }
            });
            let scan_res = tokio::task::spawn_blocking(|| {
                crate::modules::rammap::scan_suspicious_processes_report(40, 4.0)
            })
            .await
            .unwrap_or_else(|e| {
                crate::modules::rammap::MemoryScanReport {
                    error: Some(format!("task error: {e}")),
                    ..Default::default()
                }
            });
            let n = scan_res.findings.len();
            for sp in &scan_res.findings {
                let severity = if sp.rwx_regions > 0 { "HIGH" } else { "MEDIUM" };
                s2.security_engine.record_incident(
                    "Memory Injection Suspect",
                    &format!("PID {}", sp.pid),
                    &format!(
                        "{} — {} {} (~{:.0} MB){}",
                        sp.name,
                        sp.regions,
                        crate::modules::i18n::tr(
                            "vùng nhớ riêng thực thi được",
                            "executable private regions",
                            "个可执行私有内存区"
                        ),
                        sp.total_mb,
                        if sp.rwx_regions > 0 {
                            crate::modules::i18n::tr(
                                " · có vùng RWX",
                                " · contains RWX",
                                " · 含RWX区域",
                            )
                        } else {
                            ""
                        }
                    ),
                    severity,
                    crate::modules::i18n::tr(
                        "RAM Map scan — hãy quét tiến trình này bằng phần mềm diệt virus",
                        "RAM Map scan — scan this process with antivirus",
                        "RAM Map 扫描 — 请使用杀毒软件扫描此进程",
                    ),
                );
            }
            // Coverage-aware status: "no findings" may only be claimed when at
            // least one process was actually CHECKED and NOTHING was skipped,
            // denied, errored, or left partial. Otherwise the message must
            // disclose the unfinished coverage instead of claiming safety.
            let checked = scan_res.count(crate::modules::rammap::ScanStatus::Checked);
            let denied = scan_res.count(crate::modules::rammap::ScanStatus::AccessDenied);
            let partial = scan_res.count(crate::modules::rammap::ScanStatus::Partial);
            let errored = scan_res.count(crate::modules::rammap::ScanStatus::Error);
            let skipped = scan_res.count(crate::modules::rammap::ScanStatus::Skipped);
            let msg = if let Some(err) = &scan_res.error {
                format!("✗ {err}")
            } else if n > 0 {
                format!(
                    "{} {} {}",
                    crate::modules::i18n::tr("⚠ Phát hiện", "⚠ Detected", "⚠ 发现"),
                    n,
                    crate::modules::i18n::tr(
                        "tiến trình có vùng nhớ đáng ngờ — xem tab An ninh",
                        "suspect process(es) with suspicious memory — see Security tab",
                        "个存在可疑内存的进程 — 请查看安全选项卡",
                    )
                )
            } else if denied + partial + errored > 0 {
                // Even with some coverage, access failures block a "Safe" claim.
                crate::modules::i18n::tr4(
                    "⚠ Quét chưa đầy đủ — một số tiến trình không truy cập được, không thể kết luận an toàn",
                    "⚠ Scan incomplete: some processes were inaccessible; no safety conclusion",
                    "⚠ 扫描未完成：部分进程无法访问，无法判定安全",
                    "⚠ Скан неполный: часть процессов недоступна; вывод о безопасности невозможен",
                )
                .to_string()
            } else if checked > 0 {
                format!(
                    "{} ({} {})",
                    crate::modules::i18n::tr(
                        "Không có phát hiện trong phần đã kiểm tra; không chứng minh an toàn",
                        "No findings in checked scope; not proof of safety",
                        "已检查范围内无发现；不代表安全",
                    ),
                    checked,
                    crate::modules::i18n::tr(
                        "tiến trình đã kiểm tra đầy đủ",
                        "process(es) fully checked",
                        "个进程已完整检查",
                    ),
                )
            } else {
                crate::modules::i18n::tr(
                    "⚠ Không có tiến trình nào được kiểm tra — thử lại",
                    "⚠ No process could be checked — retry",
                    "⚠ 无法检查任何进程 — 请重试",
                )
                .to_string()
            };
            let suffix = {
                let mut parts: Vec<String> = Vec::new();
                let fmt = |cnt: usize, vi: &'static str, en: &'static str, zh: &'static str| -> Option<String> {
                    (cnt > 0).then(|| {
                        format!("{cnt} {}", crate::modules::i18n::tr(vi, en, zh))
                    })
                };
                if let Some(s) = fmt(denied, "bị từ chối truy cập", "access denied", "个拒绝访问") {
                    parts.push(s);
                }
                if let Some(s) = fmt(partial, "quét một phần", "partial", "个部分扫描") {
                    parts.push(s);
                }
                if let Some(s) = fmt(errored, "lỗi", "error", "个出错") {
                    parts.push(s);
                }
                if let Some(s) = fmt(skipped, "bỏ qua (hệ thống)", "skipped (system)", "个跳过（系统）") {
                    parts.push(s);
                }
                if scan_res.not_selected > 0 {
                    parts.push(format!(
                        "{} {}",
                        scan_res.not_selected,
                        crate::modules::i18n::tr(
                            "ngoài top tiến trình RAM",
                            "outside top-RAM sample",
                            "个未在RAM前列样本内",
                        )
                    ));
                }
                if parts.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", parts.join(", "))
                }
            };
            let msg = format!("{msg}{suffix}");
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui_inst) = ui_weak.upgrade() {
                    ui_inst.set_ram_is_busy(false);
                    ui_inst.set_ram_threat_count(sat_i32_usize(n));
                    ui_inst.set_ram_last_action(msg.into());
                }
            });
        });
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_ram_toggle_auto_clean(move |on| {
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.rammap_auto_clean_enabled = on;
            let _ = cfg_guard.save();
        }
        if let Some(ui_inst) = ui_weak.upgrade() {
            ui_inst.set_ram_auto_clean(on);
        }
        tracing::info!(
            "RAM Map auto-clean {}",
            if on { "enabled" } else { "disabled" }
        );
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_ram_set_auto_clean_threshold(move |th| {
        // Slint passes `custom-threshold-text.to-float()` coerced to int; a
        // non-numeric string becomes 0 and NaN/negative must not clamp to 64
        // (which would silently enable aggressive purging). Reject <= 0.
        if th <= 0 {
            if let Some(ui_inst) = ui_weak.upgrade() {
                ui_inst.set_ram_last_action(
                    crate::modules::i18n::tr(
                        "✗ Ngưỡng không hợp lệ (phải > 0 MB)",
                        "✗ Invalid threshold (must be > 0 MB)",
                        "✗ 无效阈值（必须 > 0 MB）",
                    )
                    .into(),
                );
            }
            return;
        }
        let Ok(raw) = u64::try_from(th) else { return };
        let valid_th = raw.clamp(64, 65536);
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.rammap_auto_clean_threshold_mb = valid_th;
            let _ = cfg_guard.save();
        }
        if let Some(ui_inst) = ui_weak.upgrade() {
            ui_inst.set_ram_auto_clean_threshold_mb(sat_i32_u64(valid_th));
        }
        tracing::info!("RAM Map auto-clean threshold set to {} MB", valid_th);
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_ram_terminate_process(move |pid| {
        // Guard: `pid as u32` would wrap negatives to huge PIDs.
        if pid <= 0 {
            return;
        }
        let pid_u32 = pid as u32;
        let ui_weak_inner = ui_weak.clone();
        s.runtime.spawn(async move {
            let res = tokio::task::spawn_blocking(move || {
                crate::modules::rammap::terminate_process_by_pid(pid_u32)
            })
            .await
            .unwrap_or_else(|e| Err(format!("task error: {e}")));

            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui_inst) = ui_weak_inner.upgrade() {
                    let msg = match res {
                        Ok(()) => crate::modules::i18n::tr4(
                            "✓ Đã dừng tiến trình thành công",
                            "✓ Process terminated successfully",
                            "✓ 已成功结束进程",
                            "✓ Процесс успешно завершён",
                        )
                        .to_string(),
                        Err(e) => format!("✗ {e}"),
                    };
                    ui_inst.set_ram_last_action(msg.into());
                }
            });
        });
    });

    ui.on_ram_open_process_folder(move |path| {
        let _ = crate::modules::rammap::open_process_folder(path.as_str());
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_pick_file_and_scan(move || {
        let s = s.clone();
        let ui_weak = ui_weak.clone();
        // The dialog must run on the event-loop thread with the main window
        // as owner: previously it ran on a spawn_blocking thread with a null
        // owner and could open behind the app. GetOpenFileNameW pumps its own
        // modal message loop, so the UI stays responsive while it is open.
        let owner = main_window_hwnd(&ui_weak);
        let picked = crate::modules::security::pick_file_dialog(owner);
        if let Some(path_str) = picked {
            s.runtime.spawn(async move {
                let busy_weak = ui_weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui_inst) = busy_weak.upgrade() {
                        ui_inst.set_file_scan_is_busy(true);
                        ui_inst.set_file_scan_status(
                            crate::modules::i18n::tr4(
                                "👋 Xin chào! Bắt đầu phân tích an toàn tệp...",
                                "👋 Hello! Commencing safe static file analysis...",
                                "👋 您好！正在启动安全静态文件分析...",
                                "👋 Здравствуйте! Запуск безопасного анализа файла...",
                            )
                            .into(),
                        );
                    }
                });
                let path_to_scan = path_str.clone();
                let report_res = tokio::task::spawn_blocking(move || {
                    crate::modules::security::scan_file(&path_to_scan)
                })
                .await
                .unwrap_or_else(|e| Err(format!("Task failure: {e}")));

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui_inst) = ui_weak.upgrade() {
                        match report_res {
                            Ok(report) => fa_render_result(&ui_inst, report),
                            Err(err_msg) => fa_render_error(&ui_inst, &err_msg, true),
                        }
                        ui_inst.set_file_scan_is_busy(false);
                    }
                });
            });
        }
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_rescan_current_file(move || {
        let s = s.clone();
        let ui_weak = ui_weak.clone();
        let cur_path = ui_weak
            .upgrade()
            .map(|u| u.get_file_scan_result().file_path.to_string())
            .unwrap_or_default();
        if cur_path.is_empty() {
            return;
        }
        s.runtime.spawn(async move {
            let busy_weak = ui_weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui_inst) = busy_weak.upgrade() {
                    ui_inst.set_file_scan_is_busy(true);
                    ui_inst.set_file_scan_status(
                        crate::modules::i18n::tr4(
                            "👋 Xin chào! Bắt đầu quét lại tệp...",
                            "👋 Hello! Rescanning file...",
                            "👋 您好！正在重新分析文件...",
                            "👋 Здравствуйте! Повторный анализ файла...",
                        )
                        .into(),
                    );
                }
            });
            let path_clone = cur_path.clone();
            let report_res = tokio::task::spawn_blocking(move || {
                crate::modules::security::scan_file(&path_clone)
            })
            .await
            .unwrap_or_else(|e| Err(format!("Task failure: {e}")));

            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui_inst) = ui_weak.upgrade() {
                    match report_res {
                        Ok(report) => fa_render_result(&ui_inst, report),
                        Err(err_msg) => fa_render_error(&ui_inst, &err_msg, false),
                    }
                    ui_inst.set_file_scan_is_busy(false);
                }
            });
        });
    });
}

#[cfg(test)]
mod quarantine_tests {
    use super::*;

    #[test]
    fn callback_action_updates_device_quarantine_state() {
        use slint::Model;
        i_slint_backend_testing::init_no_event_loop();
        let ui = crate::AppWindow::new().unwrap();
        let engine = Arc::new(crate::modules::security::SecurityEngine::new());
        engine.update_quarantine_inventory(
            &[("192.0.2.24".into(), "02:00:00:00:00:24".into())],
            &["192.0.2.10".into()],
            &["192.0.2.1".into()],
        );
        let weak = ui.as_weak();
        let state = engine.clone();
        register_quarantine_callback(&ui, engine.clone(), move || {
            let row = crate::NetworkDevice {
                ip: "192.0.2.24".into(),
                is_quarantined: state.is_quarantined("192.0.2.24"),
                ..Default::default()
            };
            weak.unwrap()
                .set_devices(slint::ModelRc::new(slint::VecModel::from(vec![row])));
        });
        ui.invoke_toggle_device_quarantine("192.0.2.24".into(), true);
        assert!(engine.is_quarantined("192.0.2.24"));
        assert!(ui.get_devices().row_data(0).unwrap().is_quarantined);
        ui.invoke_toggle_device_quarantine("192.0.2.24".into(), false);
        assert!(!engine.is_quarantined("192.0.2.24"));
        assert!(!ui.get_devices().row_data(0).unwrap().is_quarantined);
    }
}
