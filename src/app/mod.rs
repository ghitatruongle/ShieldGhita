pub mod control_plane;
pub mod hotkey;
pub mod ui_bridge;

use crate::modules::blocker::WfpBlocker;
use crate::modules::config::AppConfig;
use crate::modules::dns::DnsBlocker;
use crate::modules::logger::AppLogBuffer;
use crate::modules::monitor::NetworkMonitor;
use crate::modules::security::SecurityEngine;
use crate::modules::sinkhole::SilentSinkhole;
use crate::modules::system::dns_manager;
use crate::modules::system::SelfDefense;
use chrono::Local;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tracing::info;

static LOCAL_SERVICES_STARTED: AtomicBool = AtomicBool::new(false);

pub struct AppState {
    pub blocker: Arc<DnsBlocker>,
    pub wfp_blocker: Arc<WfpBlocker>,
    pub monitor: Arc<NetworkMonitor>,
    pub sinkhole: Arc<SilentSinkhole>,
    pub security_engine: Arc<SecurityEngine>,
    pub log_buffer: Arc<AppLogBuffer>,
    pub config: Arc<RwLock<AppConfig>>,
    pub runtime: Arc<tokio::runtime::Runtime>,
    pub self_defense: Arc<RwLock<SelfDefense>>,
    pub protection_atomic: Arc<AtomicBool>,
    pub rules_dirty: AtomicBool,
    pub logs_ui_version: AtomicU64,
    pub console_ui_version: AtomicU64,
    pub toast_gen: Arc<AtomicU64>,
    pub location_scan_cancel: Arc<AtomicBool>,
    pub realtime_guard: Arc<crate::modules::security::realtime_guard::RealtimeGuard>,
    #[cfg(feature = "admin")]
    pub local_manager: Arc<crate::modules::local::LocalManager>,
}

impl AppState {
    pub fn new(log_buffer: Arc<AppLogBuffer>) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let t0 = std::time::Instant::now();
        let cfg = AppConfig::load();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?,
        );
        tracing::info!(
            "Startup sub [config+runtime]: {} ms",
            t0.elapsed().as_millis()
        );

        let t1 = std::time::Instant::now();
        let wfp_blocker = Arc::new(WfpBlocker::new());
        if crate::modules::service::remote_mode() {
            tracing::info!(
                "Remote mode: WFP owned by ShieldGhitaCore service — local WFP init skipped"
            );
        } else if let Err(e) = wfp_blocker.initialize() {
            tracing::warn!("WFP initialization non-critical notice: {}", e);
        }
        wfp_blocker.set_blocked_ips(cfg.wfp_blocked_ips.clone());
        wfp_blocker.set_blocked_ports(cfg.wfp_blocked_ports.clone());
        tracing::info!("Startup sub [wfp-init]: {} ms", t1.elapsed().as_millis());

        let mut self_def = SelfDefense::new();
        if cfg.protection_enabled && !crate::modules::service::remote_mode() {
            if let Err(e) = self_def.enable() {
                tracing::warn!("Self-defense enable non-critical notice: {}", e);
            }
        }

        let security_engine = Arc::new(SecurityEngine::new());
        security_engine.set_detection_enabled(cfg.attack_detection_enabled);
        security_engine.set_auto_block(cfg.auto_block_attacks);
        security_engine.set_arp_detection(cfg.arp_spoof_detection);
        if let Ok(mut limit) = security_engine.dns_flood_rate_limit.write() {
            *limit = cfg.dns_flood_rate_limit;
        }

        let dns_blocker = Arc::new(DnsBlocker::new());
        dns_blocker.set_custom_rules(&cfg.custom_blocked_domains, &cfg.custom_allowed_domains);
        dns_blocker
            .adblock
            .load_rules_config(&cfg.adblock_client_rules);

        let sinkhole = Arc::new(
            SilentSinkhole::new().with_dns_flag(dns_blocker.silent_sinkhole_enabled.clone()),
        );
        let protection_atomic = Arc::new(AtomicBool::new(cfg.protection_enabled));
        let t2 = std::time::Instant::now();
        let monitor = Arc::new(NetworkMonitor::new(
            cfg.log_max_entries,
            security_engine.clone(),
        ));
        tracing::info!(
            "Startup sub [monitor-init]: {} ms",
            t2.elapsed().as_millis()
        );

        #[cfg(feature = "admin")]
        let local_manager = {
            let t = std::time::Instant::now();
            let lm = Arc::new(crate::modules::local::LocalManager::new(monitor.clone()));
            tracing::info!(
                "Startup sub [local-manager]: {} ms",
                t.elapsed().as_millis()
            );
            lm
        };

        #[cfg(feature = "admin")]
        local_manager.attach_dns_policy(&dns_blocker);

        let realtime_guard =
            Arc::new(crate::modules::security::realtime_guard::RealtimeGuard::new());
        realtime_guard.attach_engine(security_engine.clone());
        realtime_guard.set_auto_quarantine(cfg.av_auto_quarantine_critical);

        let state = Arc::new(Self {
            blocker: dns_blocker,
            wfp_blocker,
            monitor,
            sinkhole,
            security_engine,
            log_buffer,
            config: Arc::new(RwLock::new(cfg)),
            runtime,
            self_defense: Arc::new(RwLock::new(self_def)),
            protection_atomic,
            rules_dirty: AtomicBool::new(true),
            logs_ui_version: AtomicU64::new(0),
            console_ui_version: AtomicU64::new(0),
            toast_gen: Arc::new(AtomicU64::new(0)),
            location_scan_cancel: Arc::new(AtomicBool::new(false)),
            realtime_guard,
            #[cfg(feature = "admin")]
            local_manager,
        });

        let t4 = std::time::Instant::now();
        if crate::modules::service::remote_mode() {
            tracing::info!(
                "Remote mode: protection owned by ShieldGhitaCore service — local background services skipped"
            );
        } else {
            Self::start_background_services(&state);
        }
        tracing::info!("Startup sub [bg-services]: {} ms", t4.elapsed().as_millis());
        Ok(state)
    }

    pub fn start_background_services(state: &Arc<Self>) {
        if LOCAL_SERVICES_STARTED.swap(true, Ordering::SeqCst) {
            info!("Local background services already started — skipping duplicate start");
            return;
        }
        let cfg = state
            .config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        state
            .realtime_guard
            .set_canary_autolock(cfg.av_canary_autolock);
        state
            .realtime_guard
            .set_watch_canary_in_folders(cfg.av_canary_in_folders);
        if cfg.av_realtime_enabled {
            state.realtime_guard.set_enabled(true);
        }

        // Recover a DNS override left behind by a hard kill (Task Manager,
        // crash, power loss) before we bind our own resolver.
        if let Some(message) = dns_manager::recover_stale_override_on_startup() {
            info!("{}", message);
        }

        // Never fight another DNS owner (Cloudflare WARP, VPN, security suite).
        // In "auto" mode we yield: keep the resolver for LAN devices only and
        // leave the machine's system DNS to the other product.
        let dns_conflict = dns_manager::detect_dns_controller_conflict();
        let yield_to_lan_only =
            dns_conflict.is_some() && cfg.dns_conflict_mode.as_str() != "override";
        dns_manager::set_lan_only_mode(yield_to_lan_only);
        if let Some(found) = &dns_conflict {
            info!(
                "{} — mode={}, lan_only={}",
                dns_manager::describe_dns_controller(found),
                cfg.dns_conflict_mode,
                yield_to_lan_only
            );
        }

        #[cfg(feature = "admin")]
        {
            state.local_manager.start(&state.runtime);

            let local = state.local_manager.clone();
            let mon = state.monitor.clone();
            state.runtime.spawn(async move {
                let mut seen = 0usize;
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    let logs = mon.get_logs();
                    // get_logs() is newest-first (push_front): logs[..delta]
                    // holds the new entries, iterate rev() for chronological
                    // behavior profiling.
                    if logs.len() > seen {
                        let delta = logs.len() - seen;
                        for entry in logs[..delta].iter().rev() {
                            local.record_dns_event(
                                &entry.source_ip,
                                &entry.domain,
                                entry.is_blocked,
                                false,
                            );
                        }
                        seen = logs.len();
                    } else if logs.len() < seen {
                        seen = logs.len();
                    }
                }
            });
        }

        {
            let sinkhole_clone = state.sinkhole.clone();
            let rt = state.runtime.clone();
            rt.spawn(async move {
                sinkhole_clone.start().await;
            });
        }

        {
            let monitor_clone = state.monitor.clone();
            let rt = state.runtime.clone();
            rt.spawn(async move {
                monitor_clone.start_traffic_monitor().await;
            });
        }

        if !yield_to_lan_only {
            {
                let prot = state.protection_atomic.clone();
                // Watchdog must check the effective bind addr (0.0.0.0 when
                // network-wide mode is on), not just the loopback config value.
                let effective_watch_addr = if cfg.network_wide_adblock_enabled {
                    "0.0.0.0".to_string()
                } else {
                    cfg.dns_listen_addr.clone()
                };
                let rt = state.runtime.clone();
                rt.spawn(async move {
                    dns_manager::start_dns_guard_watchdog(prot, effective_watch_addr).await;
                });
            }
        } else {
            info!("DNS guard watchdog disabled: another DNS controller owns the system (LAN-only mode)");
        }

        {
            let blocker = state.blocker.clone();
            let monitor_srv = state.monitor.clone();
            let config = state.config.clone();
            let rt = state.runtime.clone();
            let protection_flag = state.protection_atomic.clone();

            let listen_addr = if cfg.network_wide_adblock_enabled || yield_to_lan_only {
                "0.0.0.0".to_string()
            } else {
                cfg.dns_listen_addr.clone()
            };
            let listen_port = cfg.dns_listen_port;
            let upstream = cfg.upstream_dns.clone();
            let protection = cfg.protection_enabled;
            let network_wide = cfg.network_wide_adblock_enabled;

            if network_wide {
                dns_manager::configure_lan_dns_firewall(true);
            }

            rt.spawn(async move {
                let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

                let blocker_srv = blocker.clone();
                let mon_srv = monitor_srv.clone();
                let addr_srv = listen_addr.clone();
                let up_srv = upstream.clone();
                tokio::spawn(async move {
                    blocker_srv
                        .run_dns_server(&addr_srv, listen_port, up_srv, mon_srv, Some(ready_tx))
                        .await;
                });

                match ready_rx.await {
                    Ok(Ok(())) => {
                        info!("DNS Server successfully bound to {}:{}", listen_addr, listen_port);
                        if protection && !yield_to_lan_only {
                            if let Err(e) = dns_manager::set_system_dns("127.0.0.1") {
                                tracing::error!("Failed to set master system DNS: {}", e);
                            }
                        } else if protection {
                            info!("Protection active in LAN-only mode — system DNS left untouched");
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::error!("DNS Server Bind Failed: {}. Protection disabled to prevent network blackout.", e);
                        protection_flag.store(false, Ordering::SeqCst);
                        if let Ok(mut cfg_guard) = config.write() {
                            cfg_guard.protection_enabled = false;
                            let _ = cfg_guard.save();
                        }
                    }
                    Err(e) => {
                        // Ready-channel failure means the server task died
                        // before binding — treat like a bind failure so we
                        // never leave protection ON with no DNS server.
                        tracing::error!("DNS Server Task Error: {}. Protection disabled to prevent network blackout.", e);
                        protection_flag.store(false, Ordering::SeqCst);
                        if let Ok(mut cfg_guard) = config.write() {
                            cfg_guard.protection_enabled = false;
                            let _ = cfg_guard.save();
                        }
                    }
                }

                let urls = {
                    let cfg_guard = config.read().unwrap_or_else(|e| e.into_inner());
                    cfg_guard.blocklist_urls.clone()
                };
                let doh_sources = {
                    let cfg_guard = config.read().unwrap_or_else(|e| e.into_inner());
                    cfg_guard.upstream_dns.clone()
                };
                match blocker.load_blocklists(&urls, &doh_sources).await {
                    Ok(count) => {
                        info!("Master Blocklist loaded: {} domains actively protected", count);
                        if let Ok(mut cfg_guard) = config.write() {
                            cfg_guard.last_blocklist_update =
                                Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                            let _ = cfg_guard.save();
                        }
                    }
                    Err(e) => tracing::error!("Failed to fetch blocklists: {}", e),
                }
            });
        }

        {
            let s = state.clone();
            let rt = state.runtime.clone();
            rt.spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                    let should_update = {
                        let cfg_guard = s.config.read().unwrap_or_else(|e| e.into_inner());
                        match &cfg_guard.last_blocklist_update {
                            Some(last) => {
                                if let Ok(last_dt) =
                                    chrono::NaiveDateTime::parse_from_str(last, "%Y-%m-%d %H:%M:%S")
                                {
                                    let now = Local::now().naive_local();
                                    let hours = cfg_guard.auto_update_blocklist_hours as i64;
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
                            let cfg_guard = s.config.read().unwrap_or_else(|e| e.into_inner());
                            cfg_guard.blocklist_urls.clone()
                        };
                        let doh_sources = {
                            let cfg_guard = s.config.read().unwrap_or_else(|e| e.into_inner());
                            cfg_guard.upstream_dns.clone()
                        };
                        match s.blocker.load_blocklists(&urls, &doh_sources).await {
                            Ok(count) => {
                                info!("Auto-updated blocklists: {} domains active", count);
                                if let Ok(mut cfg_guard) = s.config.write() {
                                    cfg_guard.last_blocklist_update =
                                        Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                                    let _ = cfg_guard.save();
                                }
                            }
                            Err(e) => tracing::error!("Blocklist auto-update failed: {}", e),
                        }
                    }
                }
            });
        }
    }
}

pub fn switch_to_local_mode(state: &Arc<AppState>) -> Result<(), String> {
    use crate::modules::service::install::CoreServiceState;
    match crate::modules::service::install::query_state() {
        CoreServiceState::Running | CoreServiceState::StartPending | CoreServiceState::Paused => {
            return Err(
                "Service ShieldGhitaCore vẫn đang chạy — dừng service trước khi chuyển Local."
                    .to_string(),
            );
        }
        _ => {}
    }
    crate::modules::service::set_remote_mode(false);
    AppState::start_background_services(state);
    #[cfg(feature = "admin")]
    {
        let panel_enabled = state
            .config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .admin_panel_enabled;
        if panel_enabled && !crate::modules::panel::panel_started() {
            crate::modules::panel::mark_panel_started();
            let panel_state = state.clone();
            state
                .runtime
                .spawn(async move { crate::modules::panel::PanelServer::serve(panel_state).await });
            info!("Admin panel started after switching to local mode");
        }
    }
    info!("Switched UI back to local protection mode");
    Ok(())
}
