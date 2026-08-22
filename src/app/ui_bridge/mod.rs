macro_rules! declare_admin_bridge {
    () => {
        #[cfg(feature = "admin")]
        pub mod admin;
    };
}
declare_admin_bridge!();
pub mod handlers;
pub mod poller;
pub mod refresh;

use crate::app::AppState;
use crate::modules::system::dns_manager;
use slint::ComponentHandle;
use std::sync::Arc;
use tray_icon::{
    menu::{Menu, MenuId, MenuItem},
    Icon, TrayIcon, TrayIconBuilder,
};

pub fn load_official_icon() -> Result<Icon, Box<dyn std::error::Error>> {
    const OFFICIAL_LOGO_32_RGBA: &[u8] = include_bytes!("../../../assets/logo_32.rgba");
    let width = 32u32;
    let height = 32u32;
    let expected_len = (width * height * 4) as usize;
    if OFFICIAL_LOGO_32_RGBA.len() != expected_len {
        return Err(format!(
            "official logo rgba size mismatch: expected {} bytes, got {}",
            expected_len,
            OFFICIAL_LOGO_32_RGBA.len()
        )
        .into());
    }
    Icon::from_rgba(OFFICIAL_LOGO_32_RGBA.to_vec(), width, height).map_err(|e| e.into())
}

pub fn setup_ui_bridge(
    ui: &crate::AppWindow,
    state: Arc<AppState>,
) -> Result<Option<TrayIcon>, Box<dyn std::error::Error>> {
    let cfg = state
        .config
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    ui.set_is_vi(cfg.language == "vi");
    ui.set_enable_notifications(cfg.enable_block_notifications);
    ui.set_app_version(env!("CARGO_PKG_VERSION").into());
    ui.set_host_lan_ip(dns_manager::get_lan_ip_address().into());
    ui.set_network_wide_adblock(cfg.network_wide_adblock_enabled);
    ui.set_attack_detection_enabled(cfg.attack_detection_enabled);
    ui.set_auto_block_attacks(cfg.auto_block_attacks);
    ui.set_arp_spoof_detection(cfg.arp_spoof_detection);
    ui.set_minimize_to_tray_on_minimize(cfg.minimize_to_tray_on_minimize);
    ui.set_start_hidden_in_tray(cfg.start_hidden_in_tray);

    #[cfg(feature = "admin")]
    ui.set_is_admin_edition(true);

    #[cfg(not(feature = "admin"))]
    ui.set_is_admin_edition(false);

    poller::restore_window_geom(ui, &cfg);

    let tray_menu = Menu::new();
    let item_show = MenuItem::new("Mở giao diện Shield Ghita", true, None);
    let item_toggle = MenuItem::new("Bật / Tắt bảo vệ", true, None);
    let item_quit = MenuItem::new("Thoát hoàn toàn", true, None);
    let _ = tray_menu.append(&item_show);
    let _ = tray_menu.append(&item_toggle);
    let _ = tray_menu.append(&item_quit);

    let tray_icon = match load_official_icon() {
        Ok(icon) => TrayIconBuilder::new()
            .with_menu(Box::new(tray_menu))
            .with_tooltip(format!(
                "Shield Ghita v{} - Master Controller",
                env!("CARGO_PKG_VERSION")
            ))
            .with_icon(icon)
            .build()
            .ok(),
        Err(e) => {
            tracing::warn!("Failed to initialize tray icon: {}", e);
            None
        }
    };

    let show_id = item_show.id().clone();
    let toggle_id = item_toggle.id().clone();
    let quit_id = item_quit.id().clone();

    crate::modules::config::AppConfig::set_autostart_registry(cfg.start_with_windows);

    handlers::register(ui, &state);

    #[cfg(feature = "admin")]
    admin::register(ui, &state);

    #[cfg(not(feature = "admin"))]
    {
        ui.on_trigger_proximity_scan(|| {});
        ui.on_refresh_admin_data(|| {});
    }

    spawn_toast_forwarders(ui, &state);
    spawn_initial_scan(&state);

    let timer = poller::start(ui, state.clone(), (show_id, toggle_id, quit_id));
    std::mem::forget(timer);

    if cfg.start_hidden_in_tray {
        poller::WINDOW_VISIBLE.store(false, std::sync::atomic::Ordering::SeqCst);
        let ui_weak = ui.as_weak();
        slint::Timer::single_shot(std::time::Duration::from_millis(250), move || {
            if let Some(ui_inst) = ui_weak.upgrade() {
                let _ = ui_inst.hide();
            }
        });
    }

    let ui_weak_close = ui.as_weak();
    let s_close = state.clone();
    ui.window().on_close_requested(move || {
        if let Some(ui_inst) = ui_weak_close.upgrade() {
            poller::save_window_state_now(&ui_inst, &s_close);
        }
        let minimize = s_close
            .config
            .read()
            .map(|c| c.minimize_to_tray)
            .unwrap_or(true);
        if minimize {
            if let Some(ui_inst) = ui_weak_close.upgrade() {
                let _ = ui_inst.hide();
            }
            poller::WINDOW_VISIBLE.store(false, std::sync::atomic::Ordering::SeqCst);
            slint::CloseRequestResponse::KeepWindowShown
        } else {
            let _ = dns_manager::restore_system_dns();
            std::process::exit(0);
        }
    });

    Ok(tray_icon)
}

fn spawn_toast_forwarders(ui: &crate::AppWindow, state: &Arc<AppState>) {
    {
        let mut rx = state.blocker.blocked_events_tx.subscribe();
        let ui_weak = ui.as_weak();
        let config = state.config.clone();
        state.runtime.spawn(async move {
            while let Ok((domain, time)) = rx.recv().await {
                let notify_enabled = config
                    .read()
                    .map(|c| c.enable_block_notifications)
                    .unwrap_or(true);
                if !notify_enabled {
                    continue;
                }
                let domain_clone = domain.clone();
                let time_clone = time.clone();
                let is_vi = config.read().map(|c| c.language == "vi").unwrap_or(true);
                let title = if is_vi {
                    "ĐÃ CHẶN QUẢNG CÁO & TRACKER"
                } else {
                    "AD & TRACKER BLOCKED"
                }
                .to_string();

                let ui_weak_inner = ui_weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui_inst) = ui_weak_inner.upgrade() {
                        ui_inst.set_toast_title(title.into());
                        ui_inst.set_toast_domain(domain_clone.into());
                        ui_inst.set_toast_time(time_clone.into());
                        ui_inst.set_toast_is_threat(false);
                        ui_inst.set_show_toast(true);
                    }
                });

                let ui_weak_timer = ui_weak.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(3500)).await;
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui_inst) = ui_weak_timer.upgrade() {
                            ui_inst.set_show_toast(false);
                        }
                    });
                });
            }
        });
    }

    {
        let mut rx_alert = state.security_engine.alert_tx.subscribe();
        let ui_weak = ui.as_weak();
        state.runtime.spawn(async move {
            while let Ok(incident) = rx_alert.recv().await {
                let ui_weak_inner = ui_weak.clone();
                let title = format!("🚨 {}", incident.incident_type);
                let domain_msg = format!("{} [{}]", incident.details, incident.source_ip);
                let time_str = incident.time.clone();

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui_inst) = ui_weak_inner.upgrade() {
                        ui_inst.set_toast_title(title.into());
                        ui_inst.set_toast_domain(domain_msg.into());
                        ui_inst.set_toast_time(time_str.into());
                        ui_inst.set_toast_is_threat(true);
                        ui_inst.set_show_toast(true);
                    }
                });

                let ui_weak_timer = ui_weak.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(5000)).await;
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui_inst) = ui_weak_timer.upgrade() {
                            ui_inst.set_show_toast(false);
                        }
                    });
                });
            }
        });
    }
}

fn spawn_initial_scan(state: &Arc<AppState>) {
    let monitor_init = state.monitor.clone();
    let sec = state.security_engine.clone();
    state.runtime.spawn(async move {
        let _ = monitor_init.lan_scanner.scan_network(Some(sec)).await;
        monitor_init.connection_tracker.refresh_connections();
    });
}

pub type TrayMenuIds = (MenuId, MenuId, MenuId);
