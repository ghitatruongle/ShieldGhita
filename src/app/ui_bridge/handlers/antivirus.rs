use super::*;

pub(super) fn register(ui: &crate::AppWindow, state: &Arc<AppState>) {
    let s_av = state.clone();
    ui.on_av_toggle_realtime(move |enabled| {
        if remote_config_patch("av_realtime", enabled) {
            return;
        }
        s_av.realtime_guard.set_enabled(enabled);
        if let Ok(mut cfg_guard) = s_av.config.write() {
            cfg_guard.av_realtime_enabled = enabled;
            let _ = cfg_guard.save();
        }
        info!("Real-time Guard: {}", if enabled { "ON" } else { "OFF" });
    });

    let s_av = state.clone();
    ui.on_av_toggle_auto_quarantine(move |enabled| {
        if remote_config_patch("av_auto_quarantine", enabled) {
            return;
        }
        s_av.realtime_guard.set_auto_quarantine(enabled);
        if let Ok(mut cfg_guard) = s_av.config.write() {
            cfg_guard.av_auto_quarantine_critical = enabled;
            let _ = cfg_guard.save();
        }
        info!(
            "Auto-quarantine CRITICAL: {}",
            if enabled { "ON" } else { "OFF" }
        );
    });

    let s_av = state.clone();
    let ui_av_pick = ui.as_weak();
    let ui_av_busy = ui.as_weak();
    ui.on_av_quarantine_pick(move || {
        let owner = main_window_hwnd(&ui_av_pick);
        let Some(path_str) = crate::modules::security::pick_file_dialog(owner) else {
            return;
        };
        if let Some(u) = ui_av_busy.upgrade() {
            u.set_av_is_busy(true);
        }
        let ui_weak = ui_av_busy.clone();
        s_av.runtime.spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                crate::modules::security::file_quarantine::quarantine_file(
                    std::path::Path::new(&path_str),
                    crate::modules::i18n::tr4(
                        "Cách ly thủ công từ tab Diệt Virus",
                        "Manual quarantine from Antivirus tab",
                        "从杀毒选项卡手动隔离",
                        "Ручной карантин из вкладки Антивирус",
                    ),
                )
            })
            .await
            .unwrap_or_else(|e| Err(format!("task: {e}")));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    let status = match &result {
                        Ok(id) => format!(
                            "🔒 {} {}",
                            crate::modules::i18n::tr4(
                                "Đã cách ly, mã bản ghi:",
                                "Quarantined, entry ID:",
                                "已隔离，记录 ID:",
                                "Изолировано, ID записи:"
                            ),
                            id
                        ),
                        Err(e) => format!(
                            "❌ {}: {}",
                            crate::modules::i18n::tr4(
                                "Lỗi cách ly",
                                "Quarantine failed",
                                "隔离失败",
                                "Ошибка карантина"
                            ),
                            e
                        ),
                    };
                    u.set_av_status(status.into());
                    u.set_av_is_busy(false);
                }
            });
        });
    });

    let s_av = state.clone();
    let ui_av = ui.as_weak();
    ui.on_av_restore_quarantine(move |entry_id| {
        let entry_id = entry_id.to_string();
        let ui_weak = ui_av.clone();
        s_av.runtime.spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                crate::modules::security::file_quarantine::restore(&entry_id)
            })
            .await
            .unwrap_or_else(|e| Err(format!("task: {e}")));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    let status = match &result {
                        Ok(target) => format!(
                            "↩ {}: {}",
                            crate::modules::i18n::tr4(
                                "Đã khôi phục về",
                                "Restored to",
                                "已恢复至",
                                "Восстановлено в"
                            ),
                            target
                        ),
                        Err(e) => format!(
                            "❌ {}: {}",
                            crate::modules::i18n::tr4(
                                "Lỗi khôi phục",
                                "Restore failed",
                                "恢复失败",
                                "Ошибка восстановления"
                            ),
                            e
                        ),
                    };
                    u.set_av_status(status.into());
                }
            });
        });
    });

    let s_av = state.clone();
    let ui_av = ui.as_weak();
    ui.on_av_delete_quarantine(move |entry_id| {
        let entry_id = entry_id.to_string();
        let ui_weak = ui_av.clone();
        s_av.runtime.spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                crate::modules::security::file_quarantine::delete_entry(&entry_id)
            })
            .await
            .unwrap_or_else(|e| Err(format!("task: {e}")));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    let status = match &result {
                        Ok(()) => crate::modules::i18n::tr4(
                            "🔥 Đã xóa vĩnh viễn tệp trong cách ly (ghi đè an toàn).",
                            "🔥 Quarantined file permanently deleted (secure overwrite).",
                            "🔥 已永久删除隔离文件（安全覆写）。",
                            "🔥 Файл в карантине удалён навсегда (безопасная перезапись).",
                        )
                        .to_string(),
                        Err(e) => format!("❌ {e}"),
                    };
                    u.set_av_status(status.into());
                }
            });
        });
    });

    let s_can = state.clone();
    ui.on_av_toggle_canary_autolock(move |enabled| {
        if remote_config_patch("av_canary_autolock", enabled) {
            return;
        }
        s_can.realtime_guard.set_canary_autolock(enabled);
        if let Ok(mut cfg_guard) = s_can.config.write() {
            cfg_guard.av_canary_autolock = enabled;
            let _ = cfg_guard.save();
        }
    });

    let s_can = state.clone();
    ui.on_av_toggle_canary_in_folders(move |enabled| {
        if remote_config_patch("av_canary_in_folders", enabled) {
            return;
        }
        s_can.realtime_guard.set_watch_canary_in_folders(enabled);
        if let Ok(mut cfg_guard) = s_can.config.write() {
            cfg_guard.av_canary_in_folders = enabled;
            let _ = cfg_guard.save();
        }
    });

    let s_un = state.clone();
    let ui_un = ui.as_weak();
    ui.on_av_unlock(move || {
        s_un.realtime_guard.force_unlock();
        if let Some(u) = ui_un.upgrade() {
            u.set_av_status(
                crate::modules::i18n::tr4(
                    "🔓 Đã mở khoá mạng và trả DNS về bình thường.",
                    "🔓 Network unlocked and DNS returned to normal.",
                    "🔓 已解除网络锁定并还原 DNS。",
                    "🔓 Сеть разблокирована, DNS восстановлен.",
                )
                .into(),
            );
        }
    });

    ui.on_av_open_folder(move || {
        let dir =
            std::path::PathBuf::from(std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string()))
                .join("ShieldGhita")
                .join("quarantine");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::process::Command::new("explorer")
            .arg(dir.as_os_str())
            .spawn();
    });

    let s_av = state.clone();
    let ui_av = ui.as_weak();
    ui.on_av_update_signatures(move || {
        let url = {
            let cfg_guard = s_av.config.read().unwrap_or_else(|e| e.into_inner());
            cfg_guard.av_signature_url.trim().to_string()
        };
        if url.is_empty() {
            if let Some(u) = ui_av.upgrade() {
                u.set_av_status(
                    crate::modules::i18n::tr4(
                        "ℹ️ Chưa cấu hình nguồn chữ ký (av_signature_url trong config.toml) — đang dùng chữ ký tích hợp.",
                        "ℹ️ No signature source configured (av_signature_url in config.toml) — built-in signatures in use.",
                        "ℹ️ 未配置特征源（config.toml 中 av_signature_url）— 正在使用内置特征。",
                        "ℹ️ Источник сигнатур не настроен (av_signature_url в config.toml) — используются встроенные сигнатуры.",
                    )
                    .into(),
                );
            }
            return;
        };
        let ui_weak = ui_av.clone();
        s_av.runtime.spawn(async move {
            let client = reqwest::Client::new();
            let result =
                crate::modules::security::signatures::update_from_url(&client, url.trim()).await;
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    let status = match &result {
                        Ok(count) => format!(
                            "⬇ {}: {}",
                            crate::modules::i18n::tr4("Đã nạp chữ ký", "Signatures loaded", "已加载特征", "Сигнатур загружено"),
                            count
                        ),
                        Err(e) => format!(
                            "❌ {}: {}",
                            crate::modules::i18n::tr4("Cập nhật chữ ký thất bại", "Signature update failed", "特征库更新失败", "Не удалось обновить сигнатуры"),
                            e
                        ),
                    };
                    u.set_av_status(status.into());
                }
            });
        });
    });

    let s_vu = state.clone();
    let ui_vu = ui.as_weak();
    ui.on_vuln_audit_local(move || {
        if let Some(u) = ui_vu.upgrade() {
            u.set_vuln_is_busy(true);
            u.set_vuln_status(
                crate::modules::i18n::tr4(
                    "⏳ Đang kiểm tra cấu hình Windows...",
                    "⏳ Auditing Windows configuration...",
                    "⏳ 正在审计 Windows 配置...",
                    "⏳ Аудит конфигурации Windows...",
                )
                .into(),
            );
        }
        let ui_weak = ui_vu.clone();
        s_vu.runtime.spawn(async move {
            let findings =
                tokio::task::spawn_blocking(crate::modules::security::vulnscan::audit_local)
                    .await
                    .unwrap_or_default();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    render_vuln_findings(&u, findings);
                    u.set_vuln_is_busy(false);
                }
            });
        });
    });

    let s_vu = state.clone();
    let ui_vu = ui.as_weak();
    ui.on_vuln_audit_lan(move || {
        let target = if let Some(u) = ui_vu.upgrade() {
            u.get_vuln_target_ip().to_string()
        } else {
            return;
        };
        let Ok(ip) = target.trim().parse::<std::net::IpAddr>() else {
            if let Some(u) = ui_vu.upgrade() {
                u.set_vuln_status(
                    crate::modules::i18n::tr4(
                        "❌ IP không hợp lệ. Ví dụ: 192.168.1.1",
                        "❌ Invalid IP. Example: 192.168.1.1",
                        "❌ IP 无效。示例：192.168.1.1",
                        "❌ Неверный IP. Пример: 192.168.1.1",
                    )
                    .into(),
                );
            }
            return;
        };
        if let Some(u) = ui_vu.upgrade() {
            u.set_vuln_is_busy(true);
            u.set_vuln_status(
                crate::modules::i18n::tr4(
                    "⏳ Đang quét cổng dịch vụ trên thiết bị (có thể mất ~30s)...",
                    "⏳ Scanning service ports on the device (may take ~30s)...",
                    "⏳ 正在扫描设备服务端口（约需 30 秒）...",
                    "⏳ Сканирование портов устройства (может занять ~30 с)...",
                )
                .into(),
            );
        }
        let ui_weak = ui_vu.clone();
        s_vu.runtime.spawn(async move {
            let findings = crate::modules::security::vulnscan::audit_lan_device(ip).await;
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    render_vuln_findings(&u, findings);
                    u.set_vuln_is_busy(false);
                }
            });
        });
    });

    let ui_vu = ui.as_weak();
    ui.on_vuln_export_report(move || {
        let findings: Vec<crate::modules::security::vulnscan::VulnFinding> =
            if let Some(u) = ui_vu.upgrade() {
                use slint::Model as _;
                let model = u.get_vuln_findings();
                (0..model.row_count())
                    .filter_map(|index| model.row_data(index))
                    .map(|item| crate::modules::security::vulnscan::VulnFinding {
                        check_id: "UI".to_string(),
                        severity: item.severity.to_string(),
                        title: item.title.to_string(),
                        detail: item.detail.to_string(),
                        recommendation: item.recommendation.to_string(),
                    })
                    .collect()
            } else {
                return;
            };
        if findings.is_empty() {
            return;
        }
        match crate::modules::security::vulnscan::export_findings_csv(&findings) {
            Ok(path) => {
                if let Some(u) = ui_vu.upgrade() {
                    u.set_vuln_status(
                        format!(
                            "💾 {}: {}",
                            crate::modules::i18n::tr4(
                                "Đã xuất CSV",
                                "Exported CSV",
                                "已导出 CSV",
                                "CSV сохранён"
                            ),
                            path
                        )
                        .into(),
                    );
                }
            }
            Err(e) => {
                if let Some(u) = ui_vu.upgrade() {
                    u.set_vuln_status(format!("❌ {e}").into());
                }
            }
        }
    });

    let s_er = state.clone();
    let ui_er = ui.as_weak();
    ui.on_emergency_restore_network(move || {
        let s2 = s_er.clone();
        let ui_weak = ui_er.clone();
        std::thread::spawn(move || {
            let mut steps: Vec<String> = Vec::new();
            if let Err(e) = dns_manager::restore_system_dns() {
                steps.push(format!("DNS: {e}"));
            } else {
                steps.push("DNS".to_string());
            }
            if let Err(e) = dns_manager::set_master_internet_lock(false) {
                steps.push(format!("Lock: {e}"));
            }
            if let Err(e) = s2.wfp_blocker.disable() {
                steps.push(format!("WFP: {e}"));
            }
            dns_manager::set_lan_only_mode(false);
            s2.protection_atomic.store(false, Ordering::SeqCst);
            if let Ok(mut cfg_guard) = s2.config.write() {
                cfg_guard.protection_enabled = false;
                let _ = cfg_guard.save();
            }
            s2.security_engine.record_incident(
                "EMERGENCY_NETWORK_RESTORE",
                "LOCAL",
                "Operator used the emergency restore action",
                "MEDIUM",
                "Original DNS restored, protection turned off",
            );
            let summary = steps.join(" | ");
            if let Some(u) = ui_weak.upgrade() {
                u.set_network_override_active(false);
                u.set_network_status_text(
                    crate::modules::i18n::tr4(
                        "🆘 Đã khôi phục mạng: trả DNS gốc, tắt Bảo vệ",
                        "🆘 Network restored: original DNS back, protection off",
                        "🆘 已恢复网络：还原原始 DNS，关闭防护",
                        "🆘 Сеть восстановлена: исходный DNS, защита выключена",
                    )
                    .into(),
                );
            }
            info!("Emergency network restore finished: {}", summary);
        });
    });

    let s_cm = state.clone();
    ui.on_dns_conflict_mode_changed(move |mode_id| {
        let mode = if mode_id == 1 { "override" } else { "auto" };
        if let Ok(mut cfg_guard) = s_cm.config.write() {
            cfg_guard.dns_conflict_mode = mode.to_string();
            let _ = cfg_guard.save();
        }
        info!("DNS conflict mode set to {}", mode);
    });
}

fn render_vuln_findings(
    ui_inst: &crate::AppWindow,
    findings: Vec<crate::modules::security::vulnscan::VulnFinding>,
) {
    let count = findings.len();
    let items: Vec<crate::VulnFindingItem> = findings
        .into_iter()
        .map(|f| crate::VulnFindingItem {
            severity: f.severity.into(),
            title: f.title.into(),
            detail: f.detail.into(),
            recommendation: f.recommendation.into(),
        })
        .collect();
    ui_inst.set_vuln_findings(slint::ModelRc::new(slint::VecModel::from(items)));
    ui_inst.set_vuln_status(
        format!(
            "{} {} {}",
            crate::modules::i18n::tr4(
                "✔ Hoàn tất — phát hiện",
                "✔ Done — found",
                "✔ 完成 — 发现",
                "✔ Готово — найдено"
            ),
            count,
            crate::modules::i18n::tr4("mục.", "items.", "项。", "позиций.")
        )
        .into(),
    );
}
