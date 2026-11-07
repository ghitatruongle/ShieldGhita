use super::*;

pub(super) fn register(ui: &crate::AppWindow, state: &Arc<AppState>) {
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
        if crate::modules::service::remote_mode() {
            let request = crate::modules::service::protocol::CoreRequest::Lock { on: locked };
            if let Err(e) = crate::app::control_plane::CoreClient::call(
                request,
                std::time::Duration::from_secs(5),
            ) {
                tracing::error!("Service master-lock call failed: {}", e);
            }
            return;
        }
        if let Err(e) = dns_manager::set_master_internet_lock(locked) {
            tracing::error!("Failed to toggle master internet lock: {}", e);
        }
    });

    fn spawn_service_action(
        state: &Arc<AppState>,
        ui: &slint::Weak<crate::AppWindow>,
        busy: &'static str,
        action: impl FnOnce() -> Result<String, String> + Send + 'static,
    ) {
        if let Some(u) = ui.upgrade() {
            u.set_service_status(busy.into());
        }
        let runtime = state.runtime.clone();
        let ui_weak = ui.clone();
        runtime.spawn(async move {
            let result = tokio::task::spawn_blocking(action)
                .await
                .unwrap_or_else(|e| Err(format!("task: {e}")));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    match result {
                        Ok(msg) => u.set_service_status(msg.into()),
                        Err(e) => u.set_service_status(format!("❌ {e}").into()),
                    }
                }
            });
        });
    }

    {
        let s_sv = state.clone();
        let ui_sv = ui.as_weak();
        ui.on_service_install(move || {
            spawn_service_action(
                &s_sv,
                &ui_sv,
                "⏳ Installing ShieldGhitaCore service...",
                || crate::modules::service::install::install(true),
            );
        });
    }
    {
        let s_sv = state.clone();
        let ui_sv = ui.as_weak();
        ui.on_service_stop(move || {
            spawn_service_action(
                &s_sv,
                &ui_sv,
                "⏳ Stopping service...",
                crate::modules::service::install::stop,
            );
        });
    }
    {
        let s_sv = state.clone();
        let ui_sv = ui.as_weak();
        ui.on_service_start(move || {
            spawn_service_action(
                &s_sv,
                &ui_sv,
                "⏳ Starting ShieldGhitaCore service...",
                crate::modules::service::install::start,
            );
        });
    }
    {
        let s_sv = state.clone();
        let ui_sv = ui.as_weak();
        ui.on_service_uninstall(move || {
            spawn_service_action(
                &s_sv,
                &ui_sv,
                "⏳ Uninstalling service...",
                crate::modules::service::install::uninstall,
            );
        });
    }
    {
        let s_sr = state.clone();
        let ui_sr = ui.as_weak();
        ui.on_service_refresh(move || {
            if let Some(u) = ui_sr.upgrade() {
                u.set_service_status(
                    crate::modules::i18n::tr4(
                        "⏳ Đang kiểm tra service...",
                        "⏳ Checking service...",
                        "⏳ 正在检查服务...",
                        "⏳ Проверка службы...",
                    )
                    .into(),
                );
            }
            let ui_weak = ui_sr.clone();
            s_sr.runtime.spawn(async move {
                let diag = tokio::task::spawn_blocking(|| {
                    let t0 = std::time::Instant::now();
                    let ipc = crate::app::control_plane::CoreClient::handshake(
                        std::time::Duration::from_secs(3),
                    );
                    let ms = t0.elapsed().as_millis();
                    let mut lines: Vec<String> = Vec::new();
                    match ipc {
                        Ok(()) => lines.push(format!("IPC ✓ ({} ms)", ms)),
                        Err(e) => lines.push(format!("IPC ✗ ({} ms): {}", ms, e)),
                    }
                    let data_dir = crate::modules::paths::data_dir();
                    lines.push(format!("Data: {}", data_dir.display()));
                    lines.push(format!(
                        "Migration: {}",
                        if data_dir.join(".migrated_programdata").exists() {
                            "✓ ProgramData"
                        } else {
                            "chưa chuyển / APPDATA"
                        }
                    ));
                    let errors = crate::app::control_plane::last_ipc_errors();
                    if !errors.is_empty() {
                        lines.push(format!(
                            "{} {}",
                            crate::modules::i18n::tr(
                                "Lỗi gần nhất:",
                                "Recent errors:",
                                "最近的错误："
                            ),
                            errors.join(" | ")
                        ));
                    }
                    lines.join("  •  ")
                })
                .await
                .unwrap_or_default();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(u) = ui_weak.upgrade() {
                        u.set_service_status(
                            format!("{}  •  {}", service_state_text(), diag).into(),
                        );
                    }
                });
            });
        });
        if let Some(u) = ui.as_weak().upgrade() {
            u.set_service_status(service_state_text().into());
        }
    }
    {
        let s_sl = state.clone();
        let ui_sl = ui.as_weak();
        ui.on_service_switch_local(move || {
            if let Some(u) = ui_sl.upgrade() {
                u.set_service_status(
                    crate::modules::i18n::tr4(
                        "⏳ Đang chuyển về chế độ Local...",
                        "⏳ Switching to local mode...",
                        "⏳ 正在切换到本地模式...",
                        "⏳ Переключение на локальный режим...",
                    )
                    .into(),
                );
            }
            let ui_weak = ui_sl.clone();
            let s2 = s_sl.clone();
            s_sl.runtime.spawn(async move {
                let result =
                    tokio::task::spawn_blocking(move || crate::app::switch_to_local_mode(&s2))
                        .await
                        .unwrap_or_else(|e| Err(format!("task: {e}")));
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(u) = ui_weak.upgrade() {
                        match result {
                            Ok(()) => {
                                u.set_service_down(false);
                                u.set_service_status(
                                    crate::modules::i18n::tr4(
                                        "🟢 Đã chuyển về chế độ Local — bảo vệ chạy trong app.",
                                        "🟢 Switched to Local mode — protection runs in-app.",
                                        "🟢 已切换到本地模式 — 保护在应用内运行。",
                                        "🟢 Локальный режим — защита в приложении.",
                                    )
                                    .into(),
                                );
                            }
                            Err(e) => u.set_service_status(format!("❌ {e}").into()),
                        }
                    }
                });
            });
        });
    }

    let s = state.clone();
    ui.on_toggle_silent_sinkhole(move |enabled| {
        if remote_send(crate::modules::service::protocol::CoreRequest::Sinkhole { on: enabled }) {
            return;
        }
        s.blocker.set_silent_sinkhole(enabled);
        info!(
            "Silent Sinkhole Mode changed: {}",
            if enabled { "ENABLED" } else { "DISABLED" }
        );
    });

    let s = state.clone();
    ui.on_toggle_network_wide_adblock(move |enabled| {
        if remote_send(crate::modules::service::protocol::CoreRequest::NetworkWide { on: enabled })
        {
            return;
        }
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
        if remote_config_patch("attack_detection", enabled) {
            return;
        }
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.attack_detection_enabled = enabled;
            let _ = cfg_guard.save();
        }
        s.security_engine.set_detection_enabled(enabled);
    });

    let s = state.clone();
    ui.on_toggle_auto_block_attacks(move |enabled| {
        if remote_config_patch("auto_block", enabled) {
            return;
        }
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.auto_block_attacks = enabled;
            let _ = cfg_guard.save();
        }
        s.security_engine.set_auto_block(enabled);
    });

    let s = state.clone();
    ui.on_toggle_arp_spoof_detection(move |enabled| {
        if remote_config_patch("arp_spoof", enabled) {
            return;
        }
        if let Ok(mut cfg_guard) = s.config.write() {
            cfg_guard.arp_spoof_detection = enabled;
            let _ = cfg_guard.save();
        }
        s.security_engine.set_arp_detection(enabled);
    });
}
