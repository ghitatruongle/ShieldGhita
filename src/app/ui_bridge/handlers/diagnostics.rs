use super::*;

pub(super) fn register(ui: &crate::AppWindow, state: &Arc<AppState>) {
    let ui_weak = ui.as_weak();
    let s = state.clone();
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
            crate::app::ui_bridge::refresh::refresh_ui_state(&ui_inst, &s);
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
                            crate::app::ui_bridge::refresh::refresh_ui_state(&ui_inst, &s);
                        }
                    }
                    Err(e) => tracing::error!("Failed to restore backup: {}", e),
                }
            }
        }
    });
}
