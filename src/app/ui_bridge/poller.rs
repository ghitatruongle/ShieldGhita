use crate::app::AppState;
use slint::ComponentHandle;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tray_icon::menu::MenuEvent;
use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};

use super::TrayMenuIds;

pub static WINDOW_VISIBLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
static RAM_PROCS_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
// Guards the periodic housekeeping job (working-set trim + hosts-file check)
// so two runs can never overlap; the tick simply skips while one is in flight.
static HOUSEKEEPING_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

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
    // Update in-memory synchronously (cheap), offload the fs::write so the
    // 1Hz Slint timer never blocks on disk I/O.
    let snapshot = if let Ok(mut cfg_guard) = state.config.write() {
        cfg_guard.window_width = geom.w;
        cfg_guard.window_height = geom.h;
        cfg_guard.window_x = geom.x;
        cfg_guard.window_y = geom.y;
        cfg_guard.window_maximized = geom.maximized;
        Some(cfg_guard.clone())
    } else {
        None
    };
    if let Some(cfg) = snapshot {
        std::thread::spawn(move || {
            let _ = cfg.save();
        });
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
    // Synchronous save: this runs on quit/close where the process exits
    // immediately after — an async spawn could be killed before flush.
    if let Ok(mut cfg_guard) = state.config.write() {
        cfg_guard.window_width = geom.w;
        cfg_guard.window_height = geom.h;
        cfg_guard.window_x = geom.x;
        cfg_guard.window_y = geom.y;
        cfg_guard.window_maximized = geom.maximized;
        let _ = cfg_guard.save();
    }
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

    let mut networks = sysinfo::Networks::new_with_refreshed_list();
    let mut ram_tick: u32 = 0;
    let mut trim_tick: u32 = 0;
    let mut last_auto_clean = Instant::now();
    // sysinfo 0.30.13 received()/transmitted() already subtract old counters.
    // Use cumulative totals for our own baseline, avoiding double subtraction
    // AND repeated stale deltas when Windows GetIfEntry2 fails a refresh.
    let mut prev_net: std::collections::HashMap<String, (u64, u64)> =
        std::collections::HashMap::new();
    let mut prev_net_t: Option<Instant> = None;

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
            if WINDOW_VISIBLE.load(Ordering::SeqCst) {
                super::refresh::refresh_ui_state(&ui_win, &state);
            }

            networks.refresh();
            // Per-interface rate over the real elapsed tick. Note we keep our
            // own CUMULATIVE baseline (`total_received/total_transmitted`):
            // `received()`/`transmitted()` are deltas vs sysinfo's internal
            // old-counter, so differencing those would double-subtract; and
            // when GetIfEntry2 fails, sysinfo keeps the STALE delta, which
            // would re-report the previous tick's traffic forever. A failed
            // tick yields zero because its cumulative counters are unchanged.
            let now = Instant::now();
            let is_first_tick = prev_net_t.is_none();
            let dt = prev_net_t
                .map(|t0| now.duration_since(t0).as_secs_f64().max(0.001))
                .unwrap_or(1.0);
            let mut best_down: f64 = 0.0;
            let mut best_up: f64 = 0.0;
            let mut best_name = String::new();
            for (if_name, data) in &networks {
                if if_name.to_lowercase().contains("loopback") {
                    continue;
                }
                let (rx, tx) = (data.total_received(), data.total_transmitted());
                let (prx, ptx) = prev_net.get(if_name).copied().unwrap_or((rx, tx));
                let drx = rx.saturating_sub(prx);
                let dtx = tx.saturating_sub(ptx);
                let (down, up) = compute_net_rate(drx, dtx, dt, is_first_tick);
                if down + up > best_down + best_up {
                    best_down = down;
                    best_up = up;
                    best_name = if_name.clone();
                }
            }
            // Snapshot for next tick (prune vanished interfaces).
            {
                let mut next: std::collections::HashMap<String, (u64, u64)> =
                    std::collections::HashMap::new();
                for (if_name, data) in &networks {
                    next.insert(
                        if_name.clone(),
                        (data.total_received(), data.total_transmitted()),
                    );
                }
                prev_net = next;
                prev_net_t = Some(now);
            }
            let (down_mbps, up_mbps) = if is_first_tick {
                (0.0, 0.0)
            } else {
                (best_down, best_up)
            };
            ui_win.set_net_down_mbps(down_mbps as f32);
            ui_win.set_net_up_mbps(up_mbps as f32);
            ui_win.set_net_if_name(best_name.into());

            ram_tick = ram_tick.wrapping_add(1);
            if ui_win.get_active_tab() == 7 {
                let b = crate::modules::rammap::snapshot();
                ui_win.set_ram_total_mb(b.total_mb as f32);
                ui_win.set_ram_available_mb(b.available_mb as f32);
                ui_win.set_ram_active_mb(b.active_mb as f32);
                ui_win.set_ram_standby_mb(b.standby_mb as f32);
                ui_win.set_ram_modified_mb(b.modified_mb as f32);
                ui_win.set_ram_free_mb(b.free_mb as f32);
                ui_win.set_ram_zero_mb(b.zero_mb as f32);
                ui_win.set_ram_page_cache_mb(b.page_cache_mb as f32);
                ui_win.set_ram_kernel_mb(b.kernel_mb as f32);
                ui_win.set_ram_commit_mb(b.commit_mb as f32);
                ui_win.set_ram_commit_limit_mb(b.commit_limit_mb as f32);
                ui_win.set_ram_lists_available(b.lists_available);
                if ram_tick.is_multiple_of(3) && !RAM_PROCS_BUSY.swap(true, Ordering::SeqCst) {
                    let ui_weak_bg = ui_weak.clone();
                    state.runtime.spawn(async move {
                        let procs =
                            tokio::task::spawn_blocking(crate::modules::rammap::all_processes)
                                .await
                                .unwrap_or_default();
                        let applied = slint::invoke_from_event_loop(move || {
                            if let Some(u) = ui_weak_bg.upgrade() {
                                let models: Vec<crate::RamProcessItem> = procs
                                    .into_iter()
                                    .map(|p| crate::RamProcessItem {
                                        pid: i32::try_from(p.pid).unwrap_or(i32::MAX),
                                        name: p.name.into(),
                                        working_set_mb: p.working_set_mb as f32,
                                        percent_ram: p.percent_ram as f32,
                                        exe_path: p.exe_path.into(),
                                        is_critical: p.is_critical,
                                    })
                                    .collect();
                                u.set_ram_processes(slint::ModelRc::new(slint::VecModel::from(
                                    models,
                                )));
                            }
                        });
                        // Always release the busy flag so a failed invoke cannot
                        // freeze the process list forever.
                        let _ = applied;
                        RAM_PROCS_BUSY.store(false, Ordering::SeqCst);
                    });
                }
            }

            let (auto_clean_on, threshold_mb) = state
                .config
                .read()
                .map(|c| {
                    (
                        c.rammap_auto_clean_enabled,
                        c.rammap_auto_clean_threshold_mb,
                    )
                })
                .unwrap_or((false, 512));
            // Re-clamp on READ: a hand-edited config_toml can carry any u64;
            // an absurd threshold would make the purge fire every 60s forever.
            let threshold_mb = threshold_mb.clamp(64, 65536);
            // get_available_ram_mb() returns 0 when GlobalMemoryStatusEx fails.
            // Treat 0 as "unknown" — never auto-purge on a failed probe.
            let available_mb = crate::modules::rammap::get_available_ram_mb();
            if auto_clean_on
                && available_mb > 0
                && available_mb < threshold_mb
                && last_auto_clean.elapsed() >= Duration::from_secs(60)
            {
                last_auto_clean = Instant::now();
                let rt = state.runtime.clone();
                rt.spawn(async move {
                    let res = tokio::task::spawn_blocking(|| {
                        crate::modules::rammap::empty(crate::modules::rammap::EmptyOp::StandbyList)
                    })
                    .await;
                    match res {
                        Ok(Ok(freed)) => tracing::info!("RAM Map auto-clean: freed ~{freed} MB"),
                        Ok(Err(e)) => tracing::warn!("RAM Map auto-clean failed: {e}"),
                        Err(e) => tracing::warn!("RAM Map auto-clean join error: {e}"),
                    }
                });
            }

            // Every ~30s: self working-set trim + hosts-file integrity check.
            // Both block (file IO / working-set calls), so they run on the
            // tokio blocking pool — never inside this 1Hz UI tick. The guard
            // makes housekeeping non-overlapping: the next check is skipped
            // while the previous job is still running, and the flag is always
            // released afterwards.
            trim_tick = trim_tick.wrapping_add(1);
            if trim_tick.is_multiple_of(30) && !HOUSEKEEPING_BUSY.swap(true, Ordering::SeqCst) {
                let state_bg = state.clone();
                state.runtime.spawn(async move {
                    let res = tokio::task::spawn_blocking(move || {
                        crate::modules::system::trim_process_working_set();
                        state_bg.security_engine.inspect_hosts_file();
                    })
                    .await;
                    if let Err(e) = res {
                        tracing::warn!("Housekeeping join error: {e}");
                    }
                    HOUSEKEEPING_BUSY.store(false, Ordering::SeqCst);
                });
            }
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
    // NOTE: tray menus are polled at 1Hz from the Slint timer (this fn) rather
    // than a dedicated blocking thread. A dedicated thread with blocking recv
    // + invoke_from_event_loop would be more immediate, but 1Hz keeps all UI
    // mutations on the event-loop thread and avoids cross-thread show/hide
    // races; toggle latency <=1s is acceptable for a tray menu.
    while let Ok(event) = MenuEvent::receiver().try_recv() {
        if event.id == *show_id {
            ui_win.window().set_minimized(false);
            let _ = ui_win.show();
            WINDOW_VISIBLE.store(true, Ordering::SeqCst);
        } else if event.id == *toggle_id {
            // Atomic invert avoids TOCTOU between load and apply when UI and
            // tray fire near-simultaneously (same pattern as hotkey).
            let new_state = !s.protection_atomic.fetch_xor(true, Ordering::SeqCst);
            // Offload blocking DNS/WFP work so the 1Hz UI timer stays smooth.
            let s2 = s.clone();
            std::thread::spawn(move || {
                crate::app::ui_bridge::handlers::apply_protection(&s2, new_state);
            });
        } else if event.id == *quit_id {
            save_window_state_now(ui_win, s);
            // Tear down WFP / self-defense before restoring DNS and exiting.
            let s2 = s.clone();
            // Quit path needs synchronous teardown before exit; run on this
            // thread (timer tick) then quit the event loop so main() can run
            // its graceful cleanup. Fall back to hard exit if loop already gone.
            crate::app::ui_bridge::handlers::apply_protection(&s2, false);
            slint::quit_event_loop().unwrap_or_else(|_| std::process::exit(0));
        }
    }
}

fn handle_tray_icon_events(ui_win: &crate::AppWindow) {
    // Same 1Hz polling rationale as handle_menu_events: keeps UI mutations on
    // the event-loop thread; a dedicated blocking-recv thread is possible but
    // unnecessary for click/show latency.
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

/// Pure rate computation: drx/dtx are saturating differences of cumulative
/// total_received()/total_transmitted() counters, not differences of sysinfo
/// received()/transmitted() deltas. Suppress the unbaselined first sample.
fn compute_net_rate(drx: u64, dtx: u64, dt_secs: f64, is_first_tick: bool) -> (f64, f64) {
    if is_first_tick || !dt_secs.is_finite() || dt_secs <= 0.0 {
        return (0.0, 0.0);
    }
    let dt = dt_secs.max(0.001);
    (
        drx as f64 * 8.0 / dt / 1_000_000.0,
        dtx as f64 * 8.0 / dt / 1_000_000.0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_net_rate_bytes_to_mbps() {
        // 1.5 MB received in exactly 1s = 12 Mbps.
        let (down, up) = compute_net_rate(1_500_000, 0, 1.0, false);
        assert!((down - 12.0).abs() < 1e-9);
        assert_eq!(up, 0.0);
    }

    #[test]
    fn test_net_rate_first_tick_is_zero() {
        // sysinfo's own delta may be garbage on the very first refresh; the
        // readout must stay at zero instead of reporting a startup spike.
        let (down, up) = compute_net_rate(9_999_999, 9_999_999, 1.0, true);
        assert_eq!((down, up), (0.0, 0.0));
    }

    #[test]
    fn test_net_rate_uses_actual_elapsed() {
        // Half a second between ticks doubles the rate (bytes/sec -> bits/s).
        let (down, _) = compute_net_rate(750_000, 0, 0.5, false);
        assert!((down - 12.0).abs() < 1e-9);
    }

    #[test]
    fn test_net_rate_rejects_non_positive_dt() {
        assert_eq!(compute_net_rate(1000, 1000, 0.0, false), (0.0, 0.0));
        assert_eq!(compute_net_rate(1000, 1000, -1.0, false), (0.0, 0.0));
        assert_eq!(compute_net_rate(1000, 1000, f64::NAN, false), (0.0, 0.0));
    }
}
