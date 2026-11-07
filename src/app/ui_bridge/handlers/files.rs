use super::*;

pub(super) fn register(ui: &crate::AppWindow, state: &Arc<AppState>) {
    let ui_copy_hash = ui.as_weak();
    let ui_export = ui.as_weak();
    let ui_open_loc = ui.as_weak();
    let ui_export_loc = ui.as_weak();
    let toast_gen = state.toast_gen.clone();
    ui.on_copy_file_hash(move |kind| {
        let ui_ref = ui_copy_hash.clone();
        let kind = kind.to_string();
        let (md5, sha1, sha256) = ui_ref
            .upgrade()
            .map(|u| {
                let r = u.get_file_scan_result();
                (r.md5.to_string(), r.sha1.to_string(), r.sha256.to_string())
            })
            .unwrap_or_default();
        let value = match kind.as_str() {
            "md5" => md5,
            "sha1" => sha1,
            _ => sha256,
        };
        if !value.is_empty() {
            copy_text_to_clipboard(&value);
        }
    });

    let toast_gen_export = toast_gen.clone();
    ui.on_export_file_report(move || {
        let Some(ui_inst) = ui_export.upgrade() else {
            return;
        };
        if ui_inst.get_file_scan_is_busy() {
            return;
        }
        let res = ui_inst.get_file_scan_result();
        let path = res.file_path.to_string();
        if path.is_empty() {
            return;
        }
        ui_inst.set_file_scan_is_busy(true);
        let ui_toast = ui_export.clone();
        let toast_gen = toast_gen_export.clone();
        std::thread::spawn(move || {
            let report_res = crate::modules::security::scan_file(&path);
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui_inst) = ui_toast.upgrade() else {
                    return;
                };
                ui_inst.set_file_scan_is_busy(false);
                match report_res {
                    Ok(report) => match crate::modules::security::export_report_txt(&report) {
                        Ok(out) => {
                            show_app_toast(
                                &ui_inst,
                                &toast_gen,
                                crate::modules::i18n::tr4(
                                    "💾 Đã xuất báo cáo",
                                    "💾 Report exported",
                                    "💾 报告已导出",
                                    "💾 Отчёт сохранён",
                                )
                                .to_string(),
                                out,
                                false,
                            );
                        }
                        Err(e) => {
                            ui_inst.set_file_scan_status(format!("❌ {e}").into());
                        }
                    },
                    Err(e) => {
                        ui_inst.set_file_scan_status(format!("❌ {e}").into());
                    }
                }
            });
        });
    });

    ui.on_open_file_location(move || {
        let path = ui_open_loc
            .upgrade()
            .map(|u| u.get_file_scan_result().file_path.to_string())
            .unwrap_or_default();
        if !path.is_empty() {
            reveal_in_explorer(&path);
        }
    });

    let toast_gen_loc_exp = toast_gen.clone();
    ui.on_export_location_threats(move || {
        let Some(ui_inst) = ui_export_loc.upgrade() else {
            return;
        };
        let model = ui_inst.get_location_scan_threats();
        let threats: Vec<crate::modules::security::ThreatHit> = {
            use slint::Model as _;
            (0..model.row_count())
                .filter_map(|i| model.row_data(i))
                .map(|t| crate::modules::security::ThreatHit {
                    file_path: t.file_path.to_string(),
                    file_name: t.file_name.to_string(),
                    risk_score: t.risk_score,
                    risk_level: t.risk_level.to_string(),
                    top_category: t.category.to_string(),
                })
                .collect()
        };
        let report = crate::modules::security::LocationScanReport {
            root: ui_inst.get_location_scan_root().to_string(),
            files_scanned: 0,
            files_skipped: 0,
            directories_visited: 0,
            threats,
            cancelled: false,
            budget_reached: false,
            elapsed_ms: 0,
            progress_ratio: 1.0,
        };
        match crate::modules::security::export_threats_csv(&report) {
            Ok(out) => {
                show_app_toast(
                    &ui_inst,
                    &toast_gen_loc_exp,
                    crate::modules::i18n::tr4(
                        "💾 Đã xuất danh sách mối nguy",
                        "💾 Threat list exported",
                        "💾 威胁列表已导出",
                        "💾 Список угроз сохранён",
                    )
                    .to_string(),
                    out,
                    false,
                );
            }
            Err(e) => {
                ui_inst.set_location_scan_status(format!("❌ {e}").into());
            }
        }
    });

    ui.on_open_threat_file(move |path| {
        let p = path.to_string();
        if !p.is_empty() {
            reveal_in_explorer(&p);
        }
    });

    ui.on_copy_threat_path(move |path| {
        let p = path.to_string();
        if !p.is_empty() {
            copy_text_to_clipboard(&p);
        }
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    ui.on_rescan_threat_file(move |path| {
        let path_str = path.to_string();
        if path_str.is_empty() {
            return;
        }
        let s = s.clone();
        let ui_weak = ui_weak.clone();
        s.runtime.spawn(async move {
            let busy_weak = ui_weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui_inst) = busy_weak.upgrade() {
                    ui_inst.set_file_scan_is_busy(true);
                    ui_inst.set_file_scan_status(
                        crate::modules::i18n::tr4(
                            "👋 Xin chào! Đang soi tệp từ danh sách quét vị trí...",
                            "👋 Hello! Scanning file from location results...",
                            "👋 您好！正在分析位置扫描结果中的文件...",
                            "👋 Здравствуйте! Анализ файла из результатов сканирования...",
                        )
                        .into(),
                    );
                }
            });
            let report_res =
                tokio::task::spawn_blocking(move || crate::modules::security::scan_file(&path_str))
                    .await
                    .unwrap_or_else(|e| Err(format!("Task failure: {e}")));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui_inst) = ui_weak.upgrade() {
                    match report_res {
                        Ok(report) => fa_render_result(&ui_inst, report),
                        Err(err_msg) => fa_render_error(&ui_inst, &err_msg, true),
                    }
                    ui_inst.set_file_scan_is_busy(false);
                    ui_inst.set_active_tab(8);
                }
            });
        });
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    let toast_gen_pick = toast_gen.clone();
    ui.on_pick_file_and_scan(move || {
        let s = s.clone();
        let ui_weak = ui_weak.clone();
        let toast_gen = toast_gen_pick.clone();
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
                            Ok(report) => {
                                let level = report.risk_level.clone();
                                let name = report.file_name.clone();
                                fa_render_result(&ui_inst, report);
                                if level == "MALICIOUS" || level == "SUSPICIOUS" {
                                    show_app_toast(
                                        &ui_inst,
                                        &toast_gen,
                                        crate::modules::i18n::tr4(
                                            "🚨 Phát hiện tệp đáng ngờ",
                                            "🚨 Suspicious file detected",
                                            "🚨 发现可疑文件",
                                            "🚨 Обнаружен подозрительный файл",
                                        )
                                        .to_string(),
                                        name.to_string(),
                                        true,
                                    );
                                }
                            }
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
    let toast_gen_rescan = toast_gen.clone();
    ui.on_rescan_current_file(move || {
        let s = s.clone();
        let ui_weak = ui_weak.clone();
        let toast_gen = toast_gen_rescan.clone();
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
                        Ok(report) => {
                            let level = report.risk_level.clone();
                            let name = report.file_name.clone();
                            fa_render_result(&ui_inst, report);
                            if level == "MALICIOUS" || level == "SUSPICIOUS" {
                                show_app_toast(
                                    &ui_inst,
                                    &toast_gen,
                                    crate::modules::i18n::tr4(
                                        "🚨 Phát hiện tệp đáng ngờ",
                                        "🚨 Suspicious file detected",
                                        "🚨 发现可疑文件",
                                        "🚨 Обнаружен подозрительный файл",
                                    )
                                    .to_string(),
                                    name.to_string(),
                                    true,
                                );
                            }
                        }
                        Err(err_msg) => fa_render_error(&ui_inst, &err_msg, false),
                    }
                    ui_inst.set_file_scan_is_busy(false);
                }
            });
        });
    });

    let s = state.clone();
    let ui_weak = ui.as_weak();
    let toast_gen_folder = toast_gen.clone();
    ui.on_pick_folder_and_scan(move || {
        let s = s.clone();
        let ui_weak = ui_weak.clone();
        let toast_gen = toast_gen_folder.clone();
        if ui_weak
            .upgrade()
            .map(|u| u.get_location_scan_is_busy())
            .unwrap_or(false)
        {
            return;
        }
        let owner = main_window_hwnd(&ui_weak);
        let Some(root_str) = crate::modules::security::pick_folder_dialog(owner) else {
            return;
        };
        let root_path_pre = std::path::PathBuf::from(&root_str);

        let cancel = s.location_scan_cancel.clone();
        cancel.store(false, Ordering::SeqCst);
        let ui_ext = ui_weak
            .upgrade()
            .map(|u| u.get_location_extension_filter().to_string())
            .unwrap_or_default();
        let mut opts = s
            .config
            .read()
            .map(|c| crate::modules::security::LocationScanOptions {
                max_files: c.location_scan_max_files.clamp(1, 20_000),
                extensions: c.location_scan_extensions.clone(),
            })
            .unwrap_or_default();
        if !ui_ext.trim().is_empty() {
            opts.extensions = ui_ext
                .split([',', ';', ' '])
                .map(|x| x.trim().trim_start_matches('.').to_lowercase())
                .filter(|x| !x.is_empty())
                .collect();
        }

        let reset_weak = ui_weak.clone();
        let reset_root = root_str.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui_inst) = reset_weak.upgrade() {
                ui_inst.set_location_scan_is_busy(true);
                ui_inst.set_location_scan_root(reset_root.into());
                ui_inst.set_location_scan_progress(0.0);
                ui_inst.set_location_scan_found(0);
                ui_inst.set_location_scan_threats(slint::ModelRc::new(slint::VecModel::default()));
                ui_inst.set_location_scan_status(
                    crate::modules::i18n::tr4(
                        "👋 Xin chào! Bắt đầu quét vị trí (chỉ cảnh báo, không xoá)...",
                        "👋 Hello! Location scan started (alert only, nothing is deleted)...",
                        "👋 您好！位置扫描已开始（仅告警，不删除）...",
                        "👋 Здравствуйте! Сканирование начато (только оповещение)...",
                    )
                    .into(),
                );
            }
        });

        let sec = s.security_engine.clone();
        let root_path = root_path_pre;
        let ui_scan = ui_weak.clone();
        s.runtime.spawn(async move {
            let threat_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

            let ui_progress = ui_scan.clone();
            let sec_threat = sec.clone();
            let threat_count_progress = threat_count.clone();
            let threat_count_threat = threat_count.clone();

            let scan_result = tokio::task::spawn_blocking(move || {
                let estimated =
                    crate::modules::security::estimate_scannable_files(&root_path, &opts);
                let scan_started = std::time::Instant::now();
                crate::modules::security::scan_location(
                    &root_path,
                    &opts,
                    &cancel,
                    move |scanned, _found, ratio, _current| {
                        let found = threat_count_progress.load(Ordering::SeqCst);
                        if !crate::app::ui_bridge::poller::WINDOW_VISIBLE.load(Ordering::SeqCst) {
                            return;
                        }
                        let pct = (ratio * 100.0).clamp(0.0, 100.0);
                        let elapsed = scan_started.elapsed().as_secs_f64();
                        let rate = (scanned as f64 / elapsed.max(0.001)).max(0.001);
                        let denom = estimated.max(scanned).max(1);
                        let remain = denom.saturating_sub(scanned) as f64;
                        let eta_sec = (remain / rate).max(0.0);
                        let status = match crate::modules::i18n::current_index() {
                            1 => format!(
                                "🔎 Scanned {scanned}/{denom} files • {found} threat(s) • {pct:.0}% • ETA {eta:.0}s",
                                eta = eta_sec
                            ),
                            2 => format!(
                                "🔎 已扫描 {scanned}/{denom} 个文件 • 发现 {found} 个威胁 • {pct:.0}% • 剩余约 {eta:.0}s",
                                eta = eta_sec
                            ),
                            3 => format!(
                                "🔎 Просканировано {scanned}/{denom} • угроз: {found} • {pct:.0}% • ещё ~{eta:.0}s",
                                eta = eta_sec
                            ),
                            _ => format!(
                                "🔎 Đã quét {scanned}/{denom} tệp • {found} mối nguy • {pct:.0}% • còn ~{eta:.0}s",
                                eta = eta_sec
                            ),
                        };
                        let ui_cb = ui_progress.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui_inst) = ui_cb.upgrade() {
                                ui_inst.set_location_scan_progress(pct);
                                ui_inst.set_location_scan_status(status.into());
                                ui_inst.set_location_scan_found(found as i32);
                            }
                        });
                    },
                    move |scan| {
                        if scan.risk_level == "MALICIOUS" {
                            let top = scan
                                .findings
                                .first()
                                .map(|f| f.category.as_str())
                                .unwrap_or("-");
                            let details = format!(
                                "{} • {} • {}/100",
                                scan.file_path, top, scan.risk_score
                            );
                            sec_threat.record_incident(
                                crate::modules::i18n::tr4(
                                    "Phát hiện mã độc khi quét vị trí",
                                    "Malicious File Detected During Location Scan",
                                    "位置扫描发现恶意文件",
                                    "Вредоносный файл при сканировании положения",
                                ),
                                &scan.file_name,
                                &details,
                                "HIGH",
                                crate::modules::i18n::tr4(
                                    "Chỉ cảnh báo — vui lòng kiểm tra thủ công, ứng dụng không xoá tệp",
                                    "Alert only — review manually; the app does not delete files",
                                    "仅告警 — 请手动检查，应用不会删除文件",
                                    "Только оповещение — проверьте вручную, приложение не удаляет файлы",
                                ),
                            );
                        }
                        threat_count_threat.fetch_add(1, Ordering::SeqCst);
                    },
                )
            })
            .await;

            match scan_result {
                Ok(report) => {
                    let pct = (report.progress_ratio * 100.0).clamp(0.0, 100.0);
                    let items: Vec<crate::LocationThreatItem> = report
                        .threats
                        .iter()
                        .map(|t| crate::LocationThreatItem {
                            file_name: t.file_name.clone().into(),
                            file_path: t.file_path.clone().into(),
                            risk_score: t.risk_score,
                            risk_level: t.risk_level.clone().into(),
                            category: t.top_category.clone().into(),
                        })
                        .collect();
                    let prefix = if report.cancelled {
                        crate::modules::i18n::tr4(
                            "⏹ Đã dừng",
                            "⏹ Stopped",
                            "⏹ 已停止",
                            "⏹ Остановлено",
                        )
                    } else if report.budget_reached {
                        crate::modules::i18n::tr4(
                            "⚠ Đạt giới hạn tệp",
                            "⚠ File budget reached",
                            "⚠ 已达文件上限",
                            "⚠ Достигнут лимит файлов",
                        )
                    } else {
                        crate::modules::i18n::tr4(
                            "✅ Hoàn tất quét vị trí",
                            "✅ Location scan complete",
                            "✅ 位置扫描完成",
                            "✅ Сканирование завершено",
                        )
                    };
                    let stopped_at = if report.cancelled {
                        match crate::modules::i18n::current_index() {
                            1 => format!(" at {pct:.0}%", pct = pct),
                            2 => format!("（进度 {pct:.0}%）", pct = pct),
                            3 => format!(" на {pct:.0}%", pct = pct),
                            _ => format!(" lúc {pct:.0}%", pct = pct),
                        }
                    } else {
                        String::new()
                    };
                    let body = match crate::modules::i18n::current_index() {
                        1 => format!(
                            " — {scanned} files scanned, {threats} threat(s) ({malicious} malicious) in {:.1}s",
                            report.elapsed_ms as f64 / 1000.0,
                            scanned = report.files_scanned,
                            threats = report.threats.len(),
                            malicious = report.malicious_count(),
                        ),
                        2 => format!(
                            " — 已扫描 {scanned} 个文件，发现 {threats} 个威胁（{malicious} 个恶意），耗时 {:.1} 秒",
                            report.elapsed_ms as f64 / 1000.0,
                            scanned = report.files_scanned,
                            threats = report.threats.len(),
                            malicious = report.malicious_count(),
                        ),
                        3 => format!(
                            " — файлов: {scanned}, угроз: {threats} (вредоносных: {malicious}), время {:.1} с",
                            report.elapsed_ms as f64 / 1000.0,
                            scanned = report.files_scanned,
                            threats = report.threats.len(),
                            malicious = report.malicious_count(),
                        ),
                        _ => format!(
                            " — đã quét {scanned} tệp, {threats} mối nguy ({malicious} độc hại), thời gian {:.1} giây",
                            report.elapsed_ms as f64 / 1000.0,
                            scanned = report.files_scanned,
                            threats = report.threats.len(),
                            malicious = report.malicious_count(),
                        ),
                    };
                    let done_weak = ui_scan.clone();
                    let toast_title = prefix;
                    let toast_body = body.trim_start_matches(" — ").to_string();
                    let status_text = format!("{prefix}{stopped_at}{body}");
                    let threat_hit = report.malicious_count() > 0;
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui_inst) = done_weak.upgrade() {
                            ui_inst.set_location_scan_progress(pct);
                            ui_inst.set_location_scan_found(items.len() as i32);
                            ui_inst.set_location_scan_threats(slint::ModelRc::new(
                                slint::VecModel::from(items),
                            ));
                            ui_inst.set_location_scan_status(status_text.into());
                            ui_inst.set_location_scan_is_busy(false);
                            show_app_toast(
                                &ui_inst,
                                &toast_gen,
                                toast_title.to_string(),
                                toast_body,
                                threat_hit,
                            );
                        }
                    });
                }
                Err(e) => {
                    let err_weak = ui_scan.clone();
                    let label =
                        crate::modules::i18n::tr4("❌ Lỗi:", "❌ Error:", "❌ 错误：", "❌ Ошибка:")
                            .to_string();
                    let msg = format!("{label} {e}");
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui_inst) = err_weak.upgrade() {
                            ui_inst.set_location_scan_status(msg.into());
                            ui_inst.set_location_scan_is_busy(false);
                        }
                    });
                }
            }
        });
    });

    let cancel_stop = state.location_scan_cancel.clone();
    ui.on_stop_location_scan(move || {
        cancel_stop.store(true, Ordering::SeqCst);
    });
}
