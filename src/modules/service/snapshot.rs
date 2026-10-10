use super::protocol::{
    CoreSnapshot, SnapshotAdblockStats, SnapshotAv, SnapshotClientRule, SnapshotConn,
    SnapshotConnGroup, SnapshotConsoleLog, SnapshotCount, SnapshotDevice, SnapshotGroupedLog,
    SnapshotIncident, SnapshotLogEntry, SnapshotQuarantineEntry, CAP_CONNS, CAP_CONSOLE,
    CAP_DEVICES, CAP_GROUPED, CAP_INCIDENTS, CAP_LOGS, CAP_QUARANTINE, CAP_RULES, CAP_TOP,
};
#[cfg(feature = "admin")]
use super::protocol::{
    SnapshotAttack, SnapshotBehavior, SnapshotCamera, SnapshotProximity, CAP_ADMIN_LISTS,
};
use crate::app::AppState;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::Ordering;

fn take<T>(mut items: Vec<T>, cap: usize) -> Vec<T> {
    items.truncate(cap);
    items
}

pub fn build(state: &AppState, tab: i32, known_hash: u64) -> CoreSnapshot {
    let incidents_count = state.security_engine.incidents_count();
    let mut snap = CoreSnapshot {
        total_queries: state.blocker.total_queries.load(Ordering::Relaxed),
        blocked_count: state.blocker.blocked_count.load(Ordering::Relaxed),
        absorbed_count: state.sinkhole.absorbed_count.load(Ordering::Relaxed),
        rules_count: state.blocker.get_rules_count() as u64,
        blocked_today: state.monitor.block_stats.day_count(),
        blocked_week: state.monitor.block_stats.week_count(),
        protection: state.protection_atomic.load(Ordering::Relaxed),
        lock: crate::modules::system::dns_manager::is_master_internet_locked(),
        sinkhole: state.blocker.is_silent_sinkhole(),
        paused: state.blocker.adblock.is_paused(),
        pause_remaining_secs: state.blocker.adblock.pause_remaining_secs(),
        cpu: 0.0,
        mem: 0.0,
        live_traffic_rate: String::new(),
        sec_score: state.security_engine.get_security_score(),
        score_hint: state.security_engine.get_security_score_hint(),
        incidents_count: incidents_count as u64,
        lan_devices_count: state.monitor.get_lan_device_count() as u64,
        is_scanning: state.monitor.is_lan_scanning(),
        adblock_total_today: state.blocker.adblock.total_blocked(),
        lan_only: crate::modules::system::dns_manager::is_lan_only_mode(),
        wfp_available: state.wfp_blocker.is_available(),
        override_active: crate::modules::system::dns_manager::is_dns_overridden()
            || crate::modules::system::dns_manager::is_master_internet_locked(),
        uptime_secs: super::pipe::service_start_time().elapsed().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        ..Default::default()
    };
    let (cpu, mem) = state.monitor.get_system_metrics();
    snap.cpu = cpu;
    snap.mem = mem;
    snap.live_traffic_rate = state.monitor.get_live_traffic_rate();
    if let Ok(cfg) = state.config.read() {
        snap.attack_detection = cfg.attack_detection_enabled;
        snap.auto_block = cfg.auto_block_attacks;
        snap.arp_spoof = cfg.arp_spoof_detection;
        snap.network_wide = cfg.network_wide_adblock_enabled;
    }

    match tab {
        1 => {
            snap.devices = Some(build_devices(state));
            snap.incidents = Some(build_incidents(state));
        }
        2 => {
            let conns = state
                .monitor
                .get_active_connections()
                .into_iter()
                .take(CAP_CONNS)
                .map(|c| SnapshotConn {
                    process_name: c.process_name,
                    pid: c.pid,
                    local_addr: c.local_addr,
                    remote_addr: c.remote_addr,
                    protocol: c.protocol,
                    state: c.state,
                    is_safe: c.is_safe,
                })
                .collect();
            snap.connections = Some(conns);
            let groups = state
                .monitor
                .connection_tracker
                .get_grouped_connections()
                .into_iter()
                .take(CAP_CONNS)
                .map(|g| SnapshotConnGroup {
                    process_name: g.process_name,
                    pid: g.pid,
                    connection_count: g.connection_count as u32,
                    destinations_summary: g.destinations_summary,
                    protocol_summary: g.protocol_summary,
                    state_summary: g.state_summary,
                    is_safe: g.is_safe,
                })
                .collect();
            snap.conn_groups = Some(groups);
            let logs = state
                .monitor
                .get_logs()
                .into_iter()
                .take(CAP_LOGS)
                .map(|l| SnapshotLogEntry {
                    timestamp: l.timestamp,
                    domain: l.domain,
                    source_ip: l.source_ip,
                    is_blocked: l.is_blocked,
                })
                .collect();
            snap.logs = Some(logs);
            let grouped = state
                .monitor
                .get_grouped_logs()
                .into_iter()
                .take(CAP_GROUPED)
                .map(|g| SnapshotGroupedLog {
                    domain: g.domain,
                    total_queries: g.total_queries as u64,
                    blocked_queries: g.blocked_queries as u64,
                    is_blocked: g.is_blocked,
                    last_seen: g.last_seen,
                    last_ip: g.last_ip,
                })
                .collect();
            snap.grouped_logs = Some(grouped);
            let console = state
                .log_buffer
                .get_logs()
                .into_iter()
                .take(CAP_CONSOLE)
                .map(|c| SnapshotConsoleLog {
                    time: c.time,
                    level: c.level,
                    message: c.message,
                })
                .collect();
            snap.console_logs = Some(console);
        }
        5 => build_admin_lists(state, &mut snap),
        9 => {
            let raw = state.blocker.adblock.snapshot();
            snap.adblock = Some(SnapshotAdblockStats {
                top_domains: take(
                    raw.top_domains
                        .into_iter()
                        .map(|i| SnapshotCount {
                            label: i.label,
                            count: i.count,
                        })
                        .collect(),
                    CAP_TOP,
                ),
                top_clients: take(
                    raw.top_clients
                        .into_iter()
                        .map(|i| SnapshotCount {
                            label: i.label,
                            count: i.count,
                        })
                        .collect(),
                    CAP_TOP,
                ),
                hourly: take(
                    raw.hourly
                        .into_iter()
                        .map(|i| SnapshotCount {
                            label: i.label,
                            count: i.count,
                        })
                        .collect(),
                    CAP_TOP,
                ),
                rules: take(
                    raw.rules
                        .into_iter()
                        .map(|(ip, mode)| SnapshotClientRule {
                            ip,
                            mode_label: mode.localized_label(),
                            mode_id: mode.id(),
                        })
                        .collect(),
                    CAP_RULES,
                ),
            });
        }
        10 => {
            let quarantine = crate::modules::security::file_quarantine::list();
            snap.av = Some(SnapshotAv {
                signature_count: crate::modules::security::signatures::count() as u64,
                realtime_enabled: state.realtime_guard.is_enabled(),
                auto_quarantine: state.realtime_guard.is_auto_quarantine(),
                lock_active: state.realtime_guard.is_lock_active(),
                quarantine: take(
                    quarantine
                        .into_iter()
                        .map(|e| SnapshotQuarantineEntry {
                            entry_id: e.id,
                            original_name: e.original_name,
                            original_path: e.original_path,
                            reason: e.reason,
                            quarantined_at: e.quarantined_at,
                            size: e.size,
                        })
                        .collect(),
                    CAP_QUARANTINE,
                ),
            });
        }
        _ => {}
    }

    let mut hasher = DefaultHasher::new();
    tab.hash(&mut hasher);
    macro_rules! hash_list {
        ($list:expr) => {
            if let Some(items) = &$list {
                if let Ok(bytes) = serde_json::to_vec(items) {
                    bytes.hash(&mut hasher);
                }
            }
        };
    }
    hash_list!(snap.devices);
    hash_list!(snap.incidents);
    hash_list!(snap.connections);
    hash_list!(snap.conn_groups);
    hash_list!(snap.logs);
    hash_list!(snap.grouped_logs);
    hash_list!(snap.console_logs);
    hash_list!(snap.adblock);
    hash_list!(snap.av);
    hash_list!(snap.proximity);
    hash_list!(snap.behaviors);
    hash_list!(snap.attacks);
    hash_list!(snap.cameras);
    snap.lists_hash = hasher.finish();
    if known_hash != 0 && known_hash == snap.lists_hash {
        snap.devices = None;
        snap.incidents = None;
        snap.connections = None;
        snap.conn_groups = None;
        snap.logs = None;
        snap.grouped_logs = None;
        snap.console_logs = None;
        snap.adblock = None;
        snap.av = None;
        snap.proximity = None;
        snap.behaviors = None;
        snap.attacks = None;
        snap.cameras = None;
    }
    snap
}

fn build_devices(state: &AppState) -> Vec<SnapshotDevice> {
    take(
        state
            .monitor
            .get_lan_devices()
            .into_iter()
            .take(CAP_DEVICES)
            .map(|d| SnapshotDevice {
                is_quarantined: state.security_engine.is_quarantined(&d.ip),
                open_ports_str: crate::modules::monitor::port_scanner::format_ports_summary(
                    &d.open_ports,
                ),
                is_local: d.ip == "127.0.0.1"
                    || d.mac.contains("Local")
                    || d.mac.contains("Cục bộ")
                    || d.mac.contains("本地"),
                name: d.name,
                ip: d.ip,
                mac: d.mac,
                vendor: d.vendor,
                device_type: d.device_type,
                os_name: d.os_name,
                last_domain: d.last_domain,
                last_active: d.last_active,
                risk_level: d.risk_level,
                port_risk: d.port_risk,
                port_advice: d.port_advice,
                custom_alias: d.custom_alias,
                bandwidth_rate: d.bandwidth_rate,
                traffic: d.traffic,
                is_online: d.is_online,
                latency_ms: d.latency_ms,
                total_queries: d.total_queries,
                blocked_queries: d.blocked_queries,
                threats_detected: d.threats_detected,
                confidence: d.confidence,
            })
            .collect(),
        CAP_DEVICES,
    )
}

fn build_incidents(state: &AppState) -> Vec<SnapshotIncident> {
    take(
        state
            .security_engine
            .get_incidents()
            .into_iter()
            .take(CAP_INCIDENTS)
            .map(|inc| SnapshotIncident {
                id: inc.id,
                time: inc.time,
                incident_type: inc.incident_type,
                source_ip: inc.source_ip,
                details: inc.details,
                severity: inc.severity,
                mitigation: inc.mitigation,
            })
            .collect(),
        CAP_INCIDENTS,
    )
}

#[cfg(feature = "admin")]
fn build_admin_lists(state: &AppState, snap: &mut CoreSnapshot) {
    snap.high_risk_count = state.local_manager.get_high_risk_count() as u64;
    snap.wifi_nodes_count = state.local_manager.get_wifi_nodes().len() as u64;
    let proximity = take(
        state
            .local_manager
            .get_devices()
            .into_iter()
            .take(CAP_ADMIN_LISTS)
            .map(|d| SnapshotProximity {
                open_ports_str: if d.open_ports.is_empty() {
                    crate::modules::i18n::tr("Không có cổng mở", "No open ports", "无开放端口")
                        .to_string()
                } else {
                    d.open_ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                id: d.id,
                name: d.name,
                ip: d.ip,
                mac: d.mac,
                vendor: d.vendor,
                discovery_method: d.discovery_method,
                network_interface: d.network_interface,
                signal_info: d.signal_info,
                last_seen: d.last_seen,
                latency_ms: d.latency_ms,
                is_online: d.is_online,
            })
            .collect(),
        CAP_ADMIN_LISTS,
    );
    snap.proximity = Some(proximity);
    let behaviors = take(
        state
            .local_manager
            .get_profiles()
            .into_iter()
            .take(CAP_ADMIN_LISTS)
            .map(|p| SnapshotBehavior {
                burst_qps: p.burst_qps,
                risk_score: i32::from(p.risk_score),
                category: p.category.to_string(),
                ip: p.ip,
                hostname: p.hostname,
                total_queries: p.total_queries,
                blocked_queries: p.blocked_queries,
                threat_queries: p.threat_queries,
                last_seen: p.last_seen,
            })
            .collect(),
        CAP_ADMIN_LISTS,
    );
    snap.behaviors = Some(behaviors);
    let attacks = take(
        state
            .local_manager
            .get_attacks()
            .iter()
            .map(|e| SnapshotAttack {
                ip: e.ip.clone(),
                mode: e.mode,
                message: e.message.clone(),
                activated_at: e.activated_at.clone(),
                expires_at: e.expires_at.clone(),
                hit_count: e.hit_count,
            })
            .collect(),
        CAP_ADMIN_LISTS,
    );
    snap.attacks = Some(attacks);
    let cameras = take(
        state
            .local_manager
            .get_cameras()
            .into_iter()
            .take(CAP_ADMIN_LISTS)
            .map(|c| SnapshotCamera {
                vendor: c.vendor,
                model_hint: c.model_hint,
                ip: c.ip,
                rtsp_url: c.rtsp_url,
                source: c.source,
                snapshot_url: c.snapshot_url,
                rtsp_open: c.rtsp_open,
                is_default_password: c.is_default_password,
            })
            .collect(),
        CAP_ADMIN_LISTS,
    );
    snap.cameras = Some(cameras);
}

#[cfg(not(feature = "admin"))]
fn build_admin_lists(_state: &AppState, _snap: &mut CoreSnapshot) {}
