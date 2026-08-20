mod blocker;
mod config;
mod dns;
mod dns_manager;
mod monitor;
mod self_defense;

use blocker::WfpBlocker;
use chrono::Local;
use config::AppConfig;
use dns::DnsBlocker;
use monitor::NetworkMonitor;
use self_defense::SelfDefense;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use tracing::info;

slint::include_modules!();

struct AppState {
    blocker: Arc<DnsBlocker>,
    wfp_blocker: Arc<WfpBlocker>,
    monitor: Arc<NetworkMonitor>,
    config: Arc<RwLock<AppConfig>>,
    runtime: Arc<tokio::runtime::Runtime>,
    self_defense: Arc<RwLock<SelfDefense>>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("shield_ghita=info".parse()?),
        )
        .init();

    let cfg = AppConfig::load();
    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
    );

    let wfp_blocker = Arc::new(WfpBlocker::new());
    if let Err(e) = wfp_blocker.initialize() {
        tracing::warn!("WFP initialization failed (non-critical): {}", e);
    }

    let mut self_def = SelfDefense::new();
    if cfg.protection_enabled {
        if let Err(e) = self_def.enable() {
            tracing::warn!("Self-defense enable failed (non-critical): {}", e);
        }
    }

    let state = Arc::new(AppState {
        blocker: Arc::new(DnsBlocker::new()),
        wfp_blocker,
        monitor: Arc::new(NetworkMonitor::new(cfg.log_max_entries)),
        config: Arc::new(RwLock::new(cfg.clone())),
        runtime,
        self_defense: Arc::new(RwLock::new(self_def)),
    });

    // Start traffic monitor
    {
        let monitor = state.monitor.clone();
        let rt = state.runtime.clone();
        rt.spawn(async move {
            monitor.start_traffic_monitor().await;
        });
    }

    // Load blocklists and start DNS server in background
    {
        let blocker = state.blocker.clone();
        let monitor = state.monitor.clone();
        let config = state.config.clone();
        let rt = state.runtime.clone();
        let listen_addr = cfg.dns_listen_addr.clone();
        let listen_port = cfg.dns_listen_port;
        let upstream = cfg.upstream_dns.clone();
        let protection = cfg.protection_enabled;

        rt.spawn(async move {
            let urls = {
                let cfg = config.read().unwrap();
                cfg.blocklist_urls.clone()
            };
            match blocker.load_blocklists(&urls).await {
                Ok(count) => {
                    info!("Blocklist loaded: {} domains", count);
                    if let Ok(mut cfg) = config.write() {
                        cfg.last_blocklist_update = Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                        let _ = cfg.save();
                    }
                }
                Err(e) => tracing::error!("Failed to load blocklists: {}", e),
            }

            if protection {
                if let Err(e) = dns_manager::set_system_dns(&listen_addr) {
                    tracing::error!("Failed to set system DNS: {}", e);
                }
                blocker
                    .run_dns_server(&listen_addr, listen_port, upstream, monitor)
                    .await;
            }
        });
    }

    // Auto-update blocklist timer (check every 60s, update if interval elapsed)
    {
        let s = state.clone();
        let rt = state.runtime.clone();
        rt.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let should_update = {
                    let cfg = s.config.read().unwrap();
                    match &cfg.last_blocklist_update {
                        Some(last) => {
                            if let Ok(last_dt) = chrono::NaiveDateTime::parse_from_str(last, "%Y-%m-%d %H:%M:%S") {
                                let now = Local::now().naive_local();
                                let hours = cfg.auto_update_blocklist_hours as i64;
                                (now - last_dt).num_hours() >= hours
                            } else {
                                true
                            }
                        }
                        None => true,
                    }
                };
                if should_update {
                    let urls = {
                        let cfg = s.config.read().unwrap();
                        cfg.blocklist_urls.clone()
                    };
                    match s.blocker.load_blocklists(&urls).await {
                        Ok(count) => {
                            info!("Auto-updated blocklist: {} domains", count);
                            if let Ok(mut cfg) = s.config.write() {
                                cfg.last_blocklist_update = Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                                let _ = cfg.save();
                            }
                        }
                        Err(e) => tracing::error!("Auto-update failed: {}", e),
                    }
                }
            }
        });
    }

    let ui = AppWindow::new()?;

    // Wire up callbacks
    let s = state.clone();
    ui.on_toggle_protection(move |enabled| {
        if let Ok(mut cfg) = s.config.write() {
            cfg.protection_enabled = enabled;
            let _ = cfg.save();
        }
        if enabled {
            let addr = s.config.read().map(|c| c.dns_listen_addr.clone()).unwrap_or_default();
            if let Err(e) = dns_manager::set_system_dns(&addr) {
                tracing::error!("Failed to set DNS on enable: {}", e);
            }
            if let Err(e) = s.wfp_blocker.enable() {
                tracing::warn!("WFP enable failed: {}", e);
            }
            if let Ok(mut sd) = s.self_defense.write() {
                if let Err(e) = sd.enable() {
                    tracing::warn!("Self-defense enable failed: {}", e);
                }
            }
        } else {
            if let Err(e) = dns_manager::restore_system_dns() {
                tracing::error!("Failed to restore DNS on disable: {}", e);
            }
            if let Err(e) = s.wfp_blocker.disable() {
                tracing::warn!("WFP disable failed: {}", e);
            }
            if let Ok(mut sd) = s.self_defense.write() {
                if let Err(e) = sd.disable() {
                    tracing::warn!("Self-defense disable failed: {}", e);
                }
            }
        }
    });

    let s = state.clone();
    ui.on_refresh_devices(move || {
        let monitor = s.monitor.clone();
        s.runtime.spawn(async move {
            let devices = monitor.scan_local_network().await;
            for d in &devices {
                monitor.update_device_traffic(&d.ip, &d.mac, d.bytes_sent, d.bytes_received);
            }
        });
    });

    let s = state.clone();
    ui.on_clear_logs(move || {
        s.monitor.clear_logs();
    });

    let s = state.clone();
    ui.on_add_custom_rule(move |rule| {
        let rule_str = rule.to_string();
        if rule_str.is_empty() {
            return;
        }
        if let Err(e) = s.blocker.add_custom_domain(&rule_str) {
            tracing::error!("Failed to add custom rule: {}", e);
        } else {
            info!("Added custom block rule: {}", rule_str);
        }
        if let Ok(mut cfg) = s.config.write() {
            if !cfg.custom_blocked_domains.contains(&rule_str) {
                cfg.custom_blocked_domains.push(rule_str);
                let _ = cfg.save();
            }
        }
    });

    let s = state.clone();
    ui.on_remove_custom_rule(move |rule| {
        let rule_str = rule.to_string();
        if let Err(e) = s.blocker.remove_custom_domain(&rule_str) {
            tracing::error!("Failed to remove custom rule: {}", e);
        }
        if let Ok(mut cfg) = s.config.write() {
            cfg.custom_blocked_domains.retain(|d| d != &rule_str);
            let _ = cfg.save();
        }
    });

    let s = state.clone();
    ui.on_update_blocklist(move || {
        let state_clone = s.clone();
        s.runtime.spawn(async move {
            let urls = {
                let cfg = state_clone.config.read().unwrap();
                cfg.blocklist_urls.clone()
            };
            match state_clone.blocker.load_blocklists(&urls).await {
                Ok(count) => {
                    info!("Blocklist updated: {} domains", count);
                    if let Ok(mut cfg) = state_clone.config.write() {
                        cfg.last_blocklist_update = Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                        let _ = cfg.save();
                    }
                }
                Err(e) => tracing::error!("Failed to update blocklists: {}", e),
            }
        });
    });

    let s = state.clone();
    ui.on_export_logs(move || {
        match s.monitor.export_logs_csv() {
            Ok(path) => info!("Logs exported to: {}", path),
            Err(e) => tracing::error!("Failed to export logs: {}", e),
        }
    });

    let s = state.clone();
    ui.on_filter_logs(move |domain, ip, blocked_flag| {
        let domain_str = domain.to_string();
        let ip_str = ip.to_string();
        let blocked_opt = if blocked_flag < 0 {
            None
        } else {
            Some(blocked_flag > 0)
        };
        let filtered = s.monitor.get_filtered_logs(&domain_str, &ip_str, blocked_opt);
        // Store filtered results back - the UI timer will pick them up
        // For now we just log
        info!("Filtered logs: {} entries matching domain='{}' ip='{}'", filtered.len(), domain_str, ip_str);
    });

    // Periodic UI update timer
    let ui_weak = ui.as_weak();
    let s = state.clone();
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(1000),
        move || {
            if let Some(ui) = ui_weak.upgrade() {
                let total = s.blocker.total_queries.load(Ordering::Relaxed);
                let blocked = s.blocker.blocked_count.load(Ordering::Relaxed);
                ui.set_total_queries(total as i32);
                ui.set_blocked_count(blocked as i32);

                let protection = s
                    .config
                    .read()
                    .map(|c| c.protection_enabled)
                    .unwrap_or(true);
                ui.set_protection_enabled(protection);
                ui.set_status_text(if protection {
                    "🟢 Đang hoạt động".into()
                } else {
                    "🔴 Đã tạm dừng".into()
                });

                // Last update text
                let last_update = s.config.read()
                    .ok()
                    .and_then(|c| c.last_blocklist_update.clone())
                    .unwrap_or_else(|| "Chưa cập nhật".to_string());
                ui.set_last_update_text(format!("Cập nhật lần cuối: {}", last_update).into());

                // Custom rules list
                let custom_rules = s.config.read()
                    .map(|c| c.custom_blocked_domains.clone())
                    .unwrap_or_default();
                let rule_models: Vec<slint::SharedString> = custom_rules
                    .iter()
                    .map(|r| r.clone().into())
                    .collect();
                ui.set_custom_rules(ModelRc::new(VecModel::from(rule_models)));

                // Logs
                let logs = s.monitor.get_logs();
                let log_models: Vec<LogEntry> = logs
                    .iter()
                    .map(|l| LogEntry {
                        timestamp: l.timestamp.clone().into(),
                        domain: l.domain.clone().into(),
                        source_ip: l.source_ip.clone().into(),
                        is_blocked: l.is_blocked,
                    })
                    .collect();
                ui.set_logs(ModelRc::new(VecModel::from(log_models)));

                // Devices
                let devices = s.monitor.get_devices();
                let device_models: Vec<NetworkDevice> = devices
                    .iter()
                    .map(|d| NetworkDevice {
                        name: d.name.clone().into(),
                        ip: d.ip.clone().into(),
                        mac: d.mac.clone().into(),
                        traffic: d.traffic_display().into(),
                    })
                    .collect();
                ui.set_devices(ModelRc::new(VecModel::from(device_models)));
            }
        },
    );

    // Minimize to tray on close
    let ui_weak_tray = ui.as_weak();
    ui.window().on_close_requested(move || {
        if let Some(ui) = ui_weak_tray.upgrade() {
            let _ = ui.hide();
        }
        slint::CloseRequestResponse::KeepWindowShown
    });

    std::mem::forget(timer);

    ui.run()?;
    Ok(())
}

