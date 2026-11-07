use super::*;

pub(super) fn register(ui: &crate::AppWindow, state: &Arc<AppState>) {
    let ui_weak = ui.as_weak();
    let s = state.clone();
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
}
