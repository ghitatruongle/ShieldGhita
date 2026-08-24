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
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            if msg.message == WM_HOTKEY && msg.wParam.0 == HOTKEY_ID as usize {
                let st = state.clone();
                std::thread::spawn(move || {
                    let new_state = !st
                        .protection_atomic
                        .load(std::sync::atomic::Ordering::SeqCst);
                    info!(
                        "Hotkey Ctrl+Alt+S: protection -> {}",
                        if new_state { "ON" } else { "OFF" }
                    );
                    apply_protection(&st, new_state);
                });
            }
        }
    })
}
