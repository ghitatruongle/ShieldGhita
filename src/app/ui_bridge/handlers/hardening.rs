//! Track 3 (0.1.5-alpha1): "Chống Hack" handlers — audit + fix + rollback.
//! Moved from ui_bridge/admin.rs (admin-only) into the public edition: the
//! underlying modules (hardening/hardening_fix) are self-contained and touch
//! only registry/event-log reads plus the local hardening_backup.json.

use std::sync::Arc;

use slint::ComponentHandle;

use crate::app::AppState;

pub(super) fn register(ui: &crate::AppWindow, state: &Arc<AppState>) {
    let s_hd = state.clone();
    let ui_hd = ui.as_weak();
    ui.on_harden_audit_persistence(move || {
        if let Some(u) = ui_hd.upgrade() {
            u.set_harden_busy(true);
        }
        let ui_weak = ui_hd.clone();
        s_hd.runtime.spawn(async move {
            let findings =
                tokio::task::spawn_blocking(crate::modules::hardening::audit_persistence)
                    .await
                    .unwrap_or_default();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    render_harden_findings(&u, findings);
                    u.set_harden_busy(false);
                }
            });
        });
    });

    let s_hd = state.clone();
    let ui_hd = ui.as_weak();
    ui.on_harden_audit_eventlog(move || {
        if let Some(u) = ui_hd.upgrade() {
            u.set_harden_busy(true);
        }
        let ui_weak = ui_hd.clone();
        s_hd.runtime.spawn(async move {
            let findings = tokio::task::spawn_blocking(crate::modules::hardening::audit_event_log)
                .await
                .unwrap_or_default();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    render_harden_findings(&u, findings);
                    u.set_harden_busy(false);
                }
            });
        });
    });

    let s_hd = state.clone();
    let ui_hd = ui.as_weak();
    ui.on_harden_audit_usb(move || {
        if let Some(u) = ui_hd.upgrade() {
            u.set_harden_busy(true);
        }
        let ui_weak = ui_hd.clone();
        s_hd.runtime.spawn(async move {
            let findings =
                tokio::task::spawn_blocking(crate::modules::hardening::audit_usb_history)
                    .await
                    .unwrap_or_default();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    render_harden_findings(&u, findings);
                    u.set_harden_busy(false);
                }
            });
        });
    });

    let s_hd = state.clone();
    let ui_hd = ui.as_weak();
    ui.on_harden_selfhash(move || {
        if let Some(u) = ui_hd.upgrade() {
            u.set_harden_busy(true);
        }
        let ui_weak = ui_hd.clone();
        s_hd.runtime.spawn(async move {
            let finding = tokio::task::spawn_blocking(crate::modules::hardening::self_hash_check)
                .await
                .unwrap_or_else(|_| crate::modules::security::vulnscan::VulnFinding {
                    check_id: "SELF_HASH_ERROR".into(),
                    severity: "MEDIUM".into(),
                    title: "self-hash task failed".into(),
                    detail: String::new(),
                    recommendation: String::new(),
                });
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    render_harden_findings(&u, vec![finding]);
                    u.set_harden_busy(false);
                }
            });
        });
    });

    let s_hf = state.clone();
    let ui_hf = ui.as_weak();
    ui.on_harden_fix(move |id| {
        if let Some(u) = ui_hf.upgrade() {
            u.set_harden_busy(true);
        }
        let ui_weak = ui_hf.clone();
        let id_owned = id.to_string();
        s_hf.runtime.spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                crate::modules::hardening_fix::apply_fix(&id_owned)
            })
            .await
            .unwrap_or_else(|e| Err(format!("task: {e}")));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    match result {
                        Ok(message) => u.set_harden_status(message.into()),
                        Err(e) => u.set_harden_status(format!("❌ {e}").into()),
                    }
                    u.set_harden_busy(false);
                }
            });
        });
    });

    let s_hr = state.clone();
    let ui_hr = ui.as_weak();
    ui.on_harden_rollback(move |id| {
        if let Some(u) = ui_hr.upgrade() {
            u.set_harden_busy(true);
        }
        let ui_weak = ui_hr.clone();
        let id_owned = id.to_string();
        s_hr.runtime.spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                crate::modules::hardening_fix::rollback_fix(&id_owned)
            })
            .await
            .unwrap_or_else(|e| Err(format!("task: {e}")));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    match result {
                        Ok(message) => u.set_harden_status(message.into()),
                        Err(e) => u.set_harden_status(format!("❌ {e}").into()),
                    }
                    u.set_harden_busy(false);
                }
            });
        });
    });
}

fn render_harden_findings(
    ui_inst: &crate::AppWindow,
    findings: Vec<crate::modules::security::vulnscan::VulnFinding>,
) {
    let items: Vec<crate::PentestFindingItem> = findings
        .into_iter()
        .map(|f| crate::PentestFindingItem {
            target: f.check_id.into(),
            category: f.severity.clone().into(),
            severity: f.severity.into(),
            detail: f.title.into(),
            recommendation: format!("{} {}", f.detail, f.recommendation).into(),
        })
        .collect();
    ui_inst.set_harden_findings(slint::ModelRc::new(slint::VecModel::from(items)));
    ui_inst.set_harden_status(
        crate::modules::i18n::tr4(
            "✔ Kiểm tra hoàn tất — xem kết quả bên dưới.",
            "✔ Check complete — see results below.",
            "✔ 检查完成 — 见下方结果。",
            "✔ Проверка завершена — результаты ниже.",
        )
        .into(),
    );
}
