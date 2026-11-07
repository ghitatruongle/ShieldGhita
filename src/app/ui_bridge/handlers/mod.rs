pub(super) use crate::app::AppState;
pub(super) use crate::modules::blocker::WfpBlocker;
pub(super) use crate::modules::system::dns_manager;
pub(super) use chrono::Local;
pub(super) use slint::ComponentHandle;
pub(super) use std::sync::atomic::Ordering;
pub(super) use std::sync::Arc;
pub(super) use tracing::info;

static APPLY_PROTECTION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn register_quarantine_callback(
    ui: &crate::AppWindow,
    engine: Arc<crate::modules::security::SecurityEngine>,
    refresh: impl Fn() + 'static,
) {
    let weak = ui.as_weak();
    ui.on_toggle_device_quarantine(move |ip, quarantine| {
        if remote_send(crate::modules::service::protocol::CoreRequest::Quarantine {
            ip: ip.to_string(),
            on: quarantine,
        }) {
            refresh();
            return;
        }
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

fn remote_config_patch(field: &str, value: bool) -> bool {
    if !crate::modules::service::remote_mode() {
        return false;
    }
    let request = crate::modules::service::protocol::CoreRequest::ConfigPatch {
        field: field.to_string(),
        value,
    };
    if let Err(e) =
        crate::app::control_plane::CoreClient::send(request, std::time::Duration::from_secs(5))
    {
        tracing::error!("Service config patch {field} failed: {e}");
    }
    true
}

fn remote_send(request: crate::modules::service::protocol::CoreRequest) -> bool {
    if !crate::modules::service::remote_mode() {
        return false;
    }
    if let Err(e) =
        crate::app::control_plane::CoreClient::send(request, std::time::Duration::from_secs(5))
    {
        tracing::error!("Service action failed: {e}");
    }
    true
}

pub fn apply_protection(s: &Arc<AppState>, enabled: bool) {
    if crate::modules::service::remote_mode() {
        let request = crate::modules::service::protocol::CoreRequest::Protection { on: enabled };
        match crate::app::control_plane::CoreClient::call(
            request,
            std::time::Duration::from_secs(5),
        ) {
            Ok(_) => info!(
                "Protection {} delegated to ShieldGhitaCore service",
                enabled
            ),
            Err(e) => tracing::error!("Service protection call failed: {}", e),
        }
        s.protection_atomic.store(enabled, Ordering::SeqCst);
        return;
    }
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
        // Yield to a foreign DNS owner (WARP/VPN/security) unless the operator
        // explicitly chose "override" in settings.
        let conflict_mode = s
            .config
            .read()
            .map(|c| c.dns_conflict_mode.clone())
            .unwrap_or_else(|_| "auto".to_string());
        let conflict = dns_manager::detect_dns_controller_conflict();
        let yield_now = conflict.is_some() && conflict_mode != "override";
        dns_manager::set_lan_only_mode(yield_now);
        if yield_now {
            info!(
                "Protection enabled in LAN-only mode: {}",
                conflict
                    .as_ref()
                    .map(dns_manager::describe_dns_controller)
                    .unwrap_or_default()
            );
        } else if let Err(e) = dns_manager::set_system_dns("127.0.0.1") {
            tracing::error!("Failed to enable master DNS: {}", e);
        }
        if s.wfp_blocker.is_available() {
            if let Err(e) = s.wfp_blocker.enable() {
                tracing::warn!("WFP enable notice: {}", e);
            }
        } else {
            tracing::warn!("WFP rules skipped: {}", WfpBlocker::unavailable_reason());
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

fn copy_text_to_clipboard(text: &str) {
    let payload = text.to_string();
    std::thread::spawn(move || {
        let _ = crate::modules::system::dns_manager::silent_command("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Set-Clipboard -Value $env:SG_CLIP",
            ])
            .env("SG_CLIP", payload)
            .output();
    });
}

fn reveal_in_explorer(path: &str) {
    let _ = crate::modules::rammap::open_process_folder(path);
}

fn show_app_toast(
    ui: &crate::AppWindow,
    toast_gen: &std::sync::Arc<std::sync::atomic::AtomicU64>,
    title: String,
    body: String,
    is_threat: bool,
) {
    let my_gen = toast_gen.fetch_add(1, Ordering::SeqCst) + 1;
    ui.set_toast_title(title.into());
    ui.set_toast_domain(body.into());
    ui.set_toast_time(chrono::Local::now().format("%H:%M:%S").to_string().into());
    ui.set_toast_is_threat(is_threat);
    ui.set_show_toast(true);
    let ui_weak = ui.as_weak();
    let gen = toast_gen.clone();
    slint::Timer::single_shot(std::time::Duration::from_millis(4500), move || {
        if gen.load(Ordering::SeqCst) != my_gen {
            return;
        }
        if let Some(u) = ui_weak.upgrade() {
            u.set_show_toast(false);
        }
    });
}

/// Raw HWND of the main window (null when unavailable), used to parent the
/// Win32 file picker so it can never open BEHIND the app window.
pub(crate) fn main_window_hwnd(ui_weak: &slint::Weak<crate::AppWindow>) -> *mut std::ffi::c_void {
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

pub fn service_state_text() -> String {
    let state = crate::modules::service::install::query_state();
    service_state_text_for(state)
}

pub(crate) fn service_state_text_for(
    state: crate::modules::service::install::CoreServiceState,
) -> String {
    use crate::modules::service::install::CoreServiceState::*;
    let base = match state {
        NotInstalled => crate::modules::i18n::tr4(
            "⚪ Chưa cài — bảo vệ chạy cùng app",
            "⚪ Not installed — protection runs with the app",
            "⚪ 未安装 — 随应用运行",
            "⚪ Не установлена — защита вместе с приложением",
        ),
        Running => crate::modules::i18n::tr4(
            "🟢 Đang chạy — bảo vệ sống sót qua đăng xuất",
            "🟢 Running — protection survives logoff",
            "🟢 运行中 — 保护在注销后仍持续",
            "🟢 Работает — защита переживает выход",
        ),
        Stopped => crate::modules::i18n::tr4(
            "⚪ Đã cài — đang dừng",
            "⚪ Installed — stopped",
            "⚪ 已安装 — 已停止",
            "⚪ Установлена — остановлена",
        ),
        StartPending => crate::modules::i18n::tr4(
            "🟡 Đang khởi động...",
            "🟡 Start pending...",
            "🟡 正在启动...",
            "🟡 Запуск службы...",
        ),
        StopPending => crate::modules::i18n::tr4(
            "🟡 Đang dừng...",
            "🟡 Stop pending...",
            "🟡 正在停止...",
            "🟡 Остановка службы...",
        ),
        Paused => {
            crate::modules::i18n::tr4("🟡 Tạm dừng", "🟡 Paused", "🟡 已暂停", "🟡 Приостановлена")
        }
        Unknown => crate::modules::i18n::tr4(
            "❓ Không xác định",
            "❓ Unknown",
            "❓ 未知",
            "❓ Неизвестно",
        ),
    };
    if crate::modules::service::remote_mode() {
        format!(
            "{base} • {}",
            crate::modules::i18n::tr4(
                "UI đang điều khiển qua service",
                "UI controls via service",
                "UI 通过服务控制",
                "UI управляет через службу"
            )
        )
    } else {
        base.to_string()
    }
}

pub(super) mod adblock;
pub(super) mod antivirus;
pub(super) mod diagnostics;
pub(super) mod files;
pub(super) mod protection;
pub(super) mod ram;
pub(super) mod settings;

pub fn register(ui: &crate::AppWindow, state: &Arc<AppState>) {
    protection::register(ui, state);
    settings::register(ui, state);
    diagnostics::register(ui, state);
    ram::register(ui, state);
    files::register(ui, state);
    adblock::register(ui, state);
    antivirus::register(ui, state);
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
