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
    #[cfg(feature = "admin")]
    pub local_manager: Arc<crate::modules::local::LocalManager>,
}

impl AppState {
    pub fn new(log_buffer: Arc<AppLogBuffer>) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let cfg = AppConfig::load();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?,
        );

        let wfp_blocker = Arc::new(WfpBlocker::new());
        if let Err(e) = wfp_blocker.initialize() {
            tracing::warn!("WFP initialization non-critical notice: {}", e);
        }

        let mut self_def = SelfDefense::new();
        if cfg.protection_enabled {
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

        let sinkhole = Arc::new(SilentSinkhole::new());
        let protection_atomic = Arc::new(AtomicBool::new(cfg.protection_enabled));
        let monitor = Arc::new(NetworkMonitor::new(
            cfg.log_max_entries,
            security_engine.clone(),
        ));

        #[cfg(feature = "admin")]
        let local_manager = Arc::new(crate::modules::local::LocalManager::new(monitor.clone()));

        #[cfg(feature = "admin")]
        local_manager.attach_dns_policy(&dns_blocker);

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
            #[cfg(feature = "admin")]
            local_manager,
        });

        Self::start_background_services(&state);
        Ok(state)
    }

    fn start_background_services(state: &Arc<Self>) {
        let cfg = state
            .config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

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
                    if logs.len() > seen {
                        let delta = logs.len() - seen;
                        for entry in logs[..delta].iter() {
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

        {
            let prot = state.protection_atomic.clone();
            let listen_addr = cfg.dns_listen_addr.clone();
            let rt = state.runtime.clone();
            rt.spawn(async move {
                dns_manager::start_dns_guard_watchdog(prot, listen_addr).await;
            });
        }

        {
            let blocker = state.blocker.clone();
            let monitor_srv = state.monitor.clone();
            let config = state.config.clone();
            let rt = state.runtime.clone();
            let protection_flag = state.protection_atomic.clone();

            let listen_addr = if cfg.network_wide_adblock_enabled {
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
                        if protection {
                            if let Err(e) = dns_manager::set_system_dns("127.0.0.1") {
                                tracing::error!("Failed to set master system DNS: {}", e);
                            }
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
                        tracing::error!("DNS Server Task Error: {}", e);
                    }
                }

                let urls = {
                    let cfg_guard = config.read().unwrap_or_else(|e| e.into_inner());
                    cfg_guard.blocklist_urls.clone()
                };
                match blocker.load_blocklists(&urls).await {
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
                        match s.blocker.load_blocklists(&urls).await {
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
