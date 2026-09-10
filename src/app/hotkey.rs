use crate::app::ui_bridge::handlers::apply_protection;
use crate::app::AppState;
use std::sync::Arc;
use tracing::info;
use windows::Win32::UI::Input::KeyboardAndMouse::{RegisterHotKey, MOD_ALT, MOD_CONTROL};
use windows::Win32::UI::WindowsAndMessaging::{GetMessageW, MSG, WM_HOTKEY};

const HOTKEY_ID: i32 = 1;
const VK_S: u32 = 0x53;

pub fn spawn_protection_hotkey(state: Arc<AppState>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || unsafe {
        if RegisterHotKey(None, HOTKEY_ID, MOD_CONTROL | MOD_ALT, VK_S).is_err() {
            tracing::warn!("Global hotkey Ctrl+Alt+S registration failed (key may be taken)");
            return;
        }
        info!("Global hotkey registered: Ctrl+Alt+S toggles protection");

        let mut msg = MSG::default();
        loop {
            // GetMessageW returns >0 for a message, 0 for WM_QUIT, -1 on error.
            // as_bool() would treat -1 as "true" and spin; handle explicitly.
            let ret = GetMessageW(&mut msg, None, 0, 0);
            if ret.0 == 0 {
                break; // WM_QUIT
            }
            if ret.0 == -1 {
                tracing::warn!("Global hotkey message loop error; retrying");
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            if msg.message == WM_HOTKEY && msg.wParam.0 == HOTKEY_ID as usize {
                let st = state.clone();
                std::thread::spawn(move || {
                    // Atomic invert avoids TOCTOU between load and apply when
                    // UI and hotkey fire near-simultaneously.
                    let new_state = !st
                        .protection_atomic
                        .fetch_xor(true, std::sync::atomic::Ordering::SeqCst);
                    info!(
                        "Hotkey Ctrl+Alt+S: protection -> {}",
                        if new_state { "ON" } else { "OFF" }
                    );
                    // apply_protection stores the flag again (idempotent) and
                    // performs DNS/WFP/self-defense side effects.
                    apply_protection(&st, new_state);
                });
            }
        }
    })
}
