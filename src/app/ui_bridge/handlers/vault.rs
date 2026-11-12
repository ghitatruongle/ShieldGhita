//! Track 4 (0.1.5-alpha1): Vault handlers — AES-256-GCM encrypted store —
//! moved from ui_bridge/admin.rs (admin-only) into the public edition. The
//! vault module is self-contained (aes-gcm + argon2 + secure-delete, all
//! public deps); no panel/service/pentest dependency.

use std::sync::Arc;

use slint::ComponentHandle;

use crate::app::AppState;

pub(super) fn register(ui: &crate::AppWindow, state: &Arc<AppState>) {
    let ui_vl = ui.as_weak();
    ui.on_vault_gen_password(move || {
        if let Some(u) = ui_vl.upgrade() {
            // Track 2: CSPRNG failure must surface as a toast/status, not a UI panic.
            let generated = match crate::modules::vault::generate_password(20, true) {
                Ok(g) => g,
                Err(e) => {
                    u.set_vault_status(format!("❌ {e}").into());
                    return;
                }
            };
            let (score, label) = crate::modules::vault::password_strength(&generated);
            u.set_vault_generated(generated.into());
            u.set_vault_strength(score);
            u.set_vault_strength_label(label.into());
        }
    });

    let ui_vl = ui.as_weak();
    ui.on_vault_copy_password(move || {
        if let Some(u) = ui_vl.upgrade() {
            let generated = u.get_vault_generated().to_string();
            match crate::modules::vault::copy_password_to_clipboard(&generated) {
                Ok(()) => u.set_vault_status(
                    crate::modules::i18n::tr4(
                        "📋 Đã copy — clipboard tự xóa sau 30 giây.",
                        "📋 Copied — clipboard auto-clears after 30 seconds.",
                        "📋 已复制 — 30 秒后自动清除剪贴板。",
                        "📋 Скопировано — буфер очистится через 30 секунд.",
                    )
                    .into(),
                ),
                Err(e) => u.set_vault_status(format!("❌ {e}").into()),
            }
        }
    });

    let s_vl = state.clone();
    let ui_vl = ui.as_weak();
    ui.on_vault_encrypt_file(move || {
        let Some(ui_inst) = ui_vl.upgrade() else {
            return;
        };
        let owner = crate::app::ui_bridge::handlers::main_window_hwnd(&ui_vl);
        let Some(path_str) = crate::modules::security::pick_file_dialog(owner) else {
            return;
        };
        let password = ui_inst.get_vault_password().to_string();
        ui_inst.set_vault_busy(true);
        let ui_weak = ui_vl.clone();
        s_vl.runtime.spawn(async move {
            let outcome = tokio::task::spawn_blocking(move || {
                crate::modules::vault::encrypt_file(std::path::Path::new(&path_str), &password)
            })
            .await
            .unwrap_or_else(|e| Err(format!("task: {e}")));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    finish_vault(&u, outcome, true);
                    u.set_vault_busy(false);
                }
            });
        });
    });

    let s_vl = state.clone();
    let ui_vl = ui.as_weak();
    ui.on_vault_decrypt_file(move || {
        let Some(ui_inst) = ui_vl.upgrade() else {
            return;
        };
        let owner = crate::app::ui_bridge::handlers::main_window_hwnd(&ui_vl);
        let Some(path_str) = crate::modules::security::pick_file_dialog(owner) else {
            return;
        };
        let password = ui_inst.get_vault_password().to_string();
        ui_inst.set_vault_busy(true);
        let ui_weak = ui_vl.clone();
        s_vl.runtime.spawn(async move {
            let outcome = tokio::task::spawn_blocking(move || {
                crate::modules::vault::decrypt_file(std::path::Path::new(&path_str), &password)
            })
            .await
            .unwrap_or_else(|e| Err(format!("task: {e}")));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    finish_vault(&u, outcome, false);
                    u.set_vault_busy(false);
                }
            });
        });
    });

    let s_vl = state.clone();
    let ui_vl = ui.as_weak();
    ui.on_vault_encrypt_folder(move || {
        let Some(ui_inst) = ui_vl.upgrade() else {
            return;
        };
        let owner = crate::app::ui_bridge::handlers::main_window_hwnd(&ui_vl);
        let Some(path_str) = crate::modules::security::pick_folder_dialog(owner) else {
            return;
        };
        let password = ui_inst.get_vault_password().to_string();
        ui_inst.set_vault_busy(true);
        let ui_weak = ui_vl.clone();
        s_vl.runtime.spawn(async move {
            let outcome = tokio::task::spawn_blocking(move || {
                crate::modules::vault::encrypt_folder(std::path::Path::new(&path_str), &password)
            })
            .await
            .unwrap_or_else(|e| Err(format!("task: {e}")));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    finish_vault_folder(&u, outcome, true);
                    u.set_vault_busy(false);
                }
            });
        });
    });

    let s_vl = state.clone();
    let ui_vl = ui.as_weak();
    ui.on_vault_decrypt_folder(move || {
        let Some(ui_inst) = ui_vl.upgrade() else {
            return;
        };
        let owner = crate::app::ui_bridge::handlers::main_window_hwnd(&ui_vl);
        let Some(path_str) = crate::modules::security::pick_folder_dialog(owner) else {
            return;
        };
        let password = ui_inst.get_vault_password().to_string();
        ui_inst.set_vault_busy(true);
        let ui_weak = ui_vl.clone();
        s_vl.runtime.spawn(async move {
            let outcome = tokio::task::spawn_blocking(move || {
                crate::modules::vault::decrypt_folder(std::path::Path::new(&path_str), &password)
            })
            .await
            .unwrap_or_else(|e| Err(format!("task: {e}")));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    finish_vault_folder(&u, outcome, false);
                    u.set_vault_busy(false);
                }
            });
        });
    });

    let s_vl = state.clone();
    let ui_vl = ui.as_weak();
    ui.on_vault_secure_delete(move || {
        let Some(ui_inst) = ui_vl.upgrade() else { return; };
        let owner = crate::app::ui_bridge::handlers::main_window_hwnd(&ui_vl);
        let Some(path_str) = crate::modules::security::pick_file_dialog(owner) else {
            return;
        };
        ui_inst.set_vault_busy(true);
        let ui_weak = ui_vl.clone();
        s_vl.runtime.spawn(async move {
            let outcome = tokio::task::spawn_blocking(move || {
                crate::modules::security::file_quarantine::secure_delete(std::path::Path::new(
                    &path_str,
                ))
            })
            .await
            .unwrap_or_else(|e| Err(format!("task: {e}")));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    match outcome {
                        Ok(()) => u.set_vault_status(
                            crate::modules::i18n::tr4(
                                "🔥 Đã xóa an toàn (ghi đè 3 vòng + đổi tên + xóa) — không thể khôi phục.",
                                "🔥 Securely deleted (3-pass overwrite + rename + remove) — unrecoverable.",
                                "🔥 已安全删除（3 轮覆写 + 改名 + 删除）— 无法恢复。",
                                "🔥 Безопасно удалено (3 прохода + переименование) — восстановление невозможно.",
                            )
                            .into(),
                        ),
                        Err(e) => u.set_vault_status(format!("❌ {e}").into()),
                    }
                    u.set_vault_busy(false);
                }
            });
        });
    });
}

fn finish_vault(
    ui_inst: &crate::AppWindow,
    outcome: Result<crate::modules::vault::VaultOutcome, String>,
    encrypted: bool,
) {
    match outcome {
        Ok(outcome) => {
            let verb = if encrypted {
                crate::modules::i18n::tr4(
                    "🔒 Đã mã hóa:",
                    "🔒 Encrypted:",
                    "🔒 已加密:",
                    "🔒 Зашифровано:",
                )
            } else {
                crate::modules::i18n::tr4(
                    "🔓 Đã giải mã:",
                    "🔓 Decrypted:",
                    "🔓 已解密:",
                    "🔓 Расшифровано:",
                )
            };
            ui_inst.set_vault_status(
                format!(
                    "{} {} ({} {}) → {}",
                    verb,
                    outcome.input.display(),
                    outcome.bytes,
                    crate::modules::i18n::tr4("byte", "bytes", "字节", "байт"),
                    outcome.output.display()
                )
                .into(),
            );
        }
        Err(e) => ui_inst.set_vault_status(format!("❌ {e}").into()),
    }
}

fn finish_vault_folder(
    ui_inst: &crate::AppWindow,
    outcome: Result<crate::modules::vault::FolderOutcome, String>,
    encrypted: bool,
) {
    match outcome {
        Ok(outcome) => {
            let verb = if encrypted {
                crate::modules::i18n::tr4(
                    "🔒 Mã hóa thư mục:",
                    "🔒 Folder encryption:",
                    "🔒 文件夹加密:",
                    "🔒 Шифрование папки:",
                )
            } else {
                crate::modules::i18n::tr4(
                    "🔓 Giải mã thư mục:",
                    "🔓 Folder decryption:",
                    "🔓 文件夹解密:",
                    "🔓 Расшифровка папки:",
                )
            };
            ui_inst.set_vault_status(
                format!(
                    "{} {} {}, {} {}",
                    verb,
                    outcome.processed,
                    crate::modules::i18n::tr4("tệp OK,", "files OK,", "个文件成功,", "файлов ОК,"),
                    outcome.failed,
                    crate::modules::i18n::tr4("lỗi", "failed", "失败", "ошибок")
                )
                .into(),
            );
        }
        Err(e) => ui_inst.set_vault_status(format!("❌ {e}").into()),
    }
}
