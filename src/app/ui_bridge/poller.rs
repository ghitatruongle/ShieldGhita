use crate::app::AppState;
use crate::modules::system::dns_manager;
use slint::ComponentHandle;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tray_icon::menu::MenuEvent;
use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};

use super::TrayMenuIds;

pub static WINDOW_VISIBLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

#[derive(Debug, Clone, PartialEq)]
struct WindowGeom {
    w: u32,
    h: u32,
    x: i32,
    y: i32,
    maximized: bool,
}

fn sample_window_geom(ui: &crate::AppWindow) -> WindowGeom {
    let win = ui.window();
    let scale = win.scale_factor();
    let size = win.size();
    let pos = win.position();
    WindowGeom {
        w: (size.width as f32 / scale).round() as u32,
        h: (size.height as f32 / scale).round() as u32,
        x: (pos.x as f32 / scale).round() as i32,
        y: (pos.y as f32 / scale).round() as i32,
        maximized: win.is_maximized(),
    }
}

fn persist_window_geom(state: &AppState, geom: &WindowGeom) {
    if let Ok(mut cfg_guard) = state.config.write() {
        cfg_guard.window_width = geom.w;
        cfg_guard.window_height = geom.h;
        cfg_guard.window_x = geom.x;
        cfg_guard.window_y = geom.y;
        cfg_guard.window_maximized = geom.maximized;
        let _ = cfg_guard.save();
    }
}

pub fn save_window_state_now(ui: &crate::AppWindow, state: &AppState) {
    if ui.window().is_minimized() {
        return;
    }
    let mut geom = sample_window_geom(ui);
    if geom.maximized {
        let prev = state
            .config
            .read()
            .map(|c| (c.window_width, c.window_height, c.window_x, c.window_y))
            .unwrap_or((geom.w, geom.h, geom.x, geom.y));
        geom.w = prev.0;
        geom.h = prev.1;
        geom.x = prev.2;
        geom.y = prev.3;
    }
    persist_window_geom(state, &geom);
}

#[cfg(windows)]
fn virtual_desktop_px() -> Option<(i32, i32, i32, i32)> {
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN,
    };
    unsafe {
        let x = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        let w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if w > 0 && h > 0 {
            Some((x, y, w, h))
        } else {
            None
        }
    }
}

#[cfg(not(windows))]
fn virtual_desktop_px() -> Option<(i32, i32, i32, i32)> {
    None
}

pub fn restore_window_geom(ui: &crate::AppWindow, cfg: &crate::modules::config::AppConfig) {
    let win = ui.window();

    if cfg.window_width >= 640 && cfg.window_height >= 480 {
        win.set_size(slint::LogicalSize::new(
            cfg.window_width as f32,
            cfg.window_height as f32,
        ));
    }

    if cfg.window_x != -1 && cfg.window_y != -1 {
        let scale = win.scale_factor();
        let mut x = cfg.window_x as f32;
        let mut y = cfg.window_y as f32;
        if let Some((vx, vy, vw, vh)) = virtual_desktop_px() {
            let phys_w = cfg.window_width as f32 * scale;
            let phys_h = cfg.window_height as f32 * scale;
            let min_x = vx as f32;
            let max_x = (vx as f32 + vw as f32 - phys_w).max(min_x);
            let min_y = vy as f32;
            let max_y = (vy as f32 + vh as f32 - phys_h).max(min_y);
            x = (x * scale).clamp(min_x, max_x) / scale;
            y = (y * scale).clamp(min_y, max_y) / scale;
        }
        win.set_position(slint::LogicalPosition::new(x, y));
    }

    if cfg.window_maximized {
        win.set_maximized(true);
        win.set_minimized(false);
    }
}

pub fn start(ui: &crate::AppWindow, state: Arc<AppState>, menu_ids: TrayMenuIds) -> slint::Timer {
    let (show_id, toggle_id, quit_id) = menu_ids;
    let ui_weak = ui.as_weak();
    let mut last_seen_geom = sample_window_geom(ui);
    let mut geom_dirty_since: Option<Instant> = None;
    let mut tray_hide_armed = false;
    let mut geom_applied = false;

    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(1000),
        move || {
            let Some(ui_win) = ui_weak.upgrade() else {
                return;
            };

            if !geom_applied
                && WINDOW_VISIBLE.load(Ordering::SeqCst)
                && !ui_win.window().is_minimized()
            {
                if let Ok(cfg) = state.config.read() {
                    restore_window_geom(&ui_win, &cfg);
                }
                ui_win.window().set_minimized(false);
                geom_applied = true;
                tray_hide_armed = false;
            }

            handle_menu_events(&ui_win, &state, &show_id, &toggle_id, &quit_id);
            handle_tray_icon_events(&ui_win);
            handle_minimize_to_tray(&ui_win, &state, &mut tray_hide_armed);
            track_window_geom(&ui_win, &state, &mut last_seen_geom, &mut geom_dirty_since);
            super::refresh::refresh_ui_state(&ui_win, &state);
        },
    );
    timer
}

fn handle_menu_events(
    ui_win: &crate::AppWindow,
    s: &Arc<AppState>,
    show_id: &tray_icon::menu::MenuId,
    toggle_id: &tray_icon::menu::MenuId,
    quit_id: &tray_icon::menu::MenuId,
) {
    while let Ok(event) = MenuEvent::receiver().try_recv() {
        if event.id == *show_id {
            ui_win.window().set_minimized(false);
            let _ = ui_win.show();
            WINDOW_VISIBLE.store(true, Ordering::SeqCst);
        } else if event.id == *toggle_id {
            let current = s
                .config
                .read()
                .map(|c| c.protection_enabled)
                .unwrap_or(true);
            let new_state = !current;
            s.protection_atomic.store(new_state, Ordering::SeqCst);
            if let Ok(mut cfg_guard) = s.config.write() {
                cfg_guard.protection_enabled = new_state;
                let _ = cfg_guard.save();
            }
            if new_state {
                let _ = dns_manager::set_system_dns("127.0.0.1");
            } else {
                let _ = dns_manager::restore_system_dns();
            }
        } else if event.id == *quit_id {
            save_window_state_now(ui_win, s);
            let _ = dns_manager::restore_system_dns();
            std::process::exit(0);
        }
    }
}

fn handle_tray_icon_events(ui_win: &crate::AppWindow) {
    while let Ok(event) = TrayIconEvent::receiver().try_recv() {
        match event {
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } => {
                if WINDOW_VISIBLE.load(Ordering::SeqCst) {
                    tracing::info!("Tray click: window visible -> hiding to tray");
                    let _ = ui_win.hide();
                    WINDOW_VISIBLE.store(false, Ordering::SeqCst);
                } else {
                    tracing::info!("Tray click: window hidden -> showing");
                    ui_win.window().set_minimized(false);
                    let _ = ui_win.show();
                    WINDOW_VISIBLE.store(true, Ordering::SeqCst);
                }
            }
            TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } => {
                tracing::info!("Tray double-click: showing window");
                ui_win.window().set_minimized(false);
                let _ = ui_win.show();
                WINDOW_VISIBLE.store(true, Ordering::SeqCst);
            }
            _ => {}
        }
    }
}

fn handle_minimize_to_tray(
    ui_win: &crate::AppWindow,
    s: &Arc<AppState>,
    tray_hide_armed: &mut bool,
) {
    let is_min = ui_win.window().is_minimized();
    if is_min {
        let min_to_tray = s
            .config
            .read()
            .map(|c| c.minimize_to_tray_on_minimize)
            .unwrap_or(true);
        let visible = WINDOW_VISIBLE.load(Ordering::SeqCst);
        if *tray_hide_armed && visible && min_to_tray {
            tracing::info!("Window minimized while running: hiding to tray");
            let _ = ui_win.hide();
            WINDOW_VISIBLE.store(false, Ordering::SeqCst);
        }
    } else {
        *tray_hide_armed = true;
    }
}

fn track_window_geom(
    ui_win: &crate::AppWindow,
    s: &Arc<AppState>,
    last_seen: &mut WindowGeom,
    dirty_since: &mut Option<Instant>,
) {
    if ui_win.window().is_minimized() || !WINDOW_VISIBLE.load(Ordering::SeqCst) {
        return;
    }
    let mut geom = sample_window_geom(ui_win);
    if geom.maximized {
        geom.w = last_seen.w;
        geom.h = last_seen.h;
        geom.x = last_seen.x;
        geom.y = last_seen.y;
    }

    if geom != *last_seen {
        *last_seen = geom;
        if dirty_since.is_none() {
            *dirty_since = Some(Instant::now());
        }
    }

    if let Some(t) = *dirty_since {
        if t.elapsed() >= Duration::from_secs(3) {
            persist_window_geom(s, last_seen);
            *dirty_since = None;
        }
    }
}
