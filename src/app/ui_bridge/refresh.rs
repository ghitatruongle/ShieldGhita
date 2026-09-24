use crate::app::AppState;
use crate::modules::i18n;
use crate::modules::system::dns_manager;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::cell::RefCell;
use std::sync::atomic::Ordering;
use std::sync::Arc;

fn sat_i32_usize(v: usize) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

fn sat_i32_u64(v: u64) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

fn sat_i32_u32(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

#[derive(Default)]
struct UiTextCache {
    lang: String,
    last_update_src: Option<String>,
    status_tag: i8,
    traffic: String,
    initialized: bool,
}

thread_local! {
    static UI_TEXT_CACHE: RefCell<UiTextCache> =
        RefCell::new(UiTextCache { status_tag: -1, ..UiTextCache::default() });
}

fn cached_text_changed(slot: &mut String, incoming: &str) -> bool {
    if *slot == incoming {
        false
    } else {
        slot.clear();
        slot.push_str(incoming);
        true
    }
}

pub fn refresh_ui_state(ui_win: &crate::AppWindow, s: &Arc<AppState>) {
    let total = s.blocker.total_queries.load(Ordering::Relaxed);
    let blocked = s.blocker.blocked_count.load(Ordering::Relaxed);
    let absorbed = s.sinkhole.absorbed_count.load(Ordering::Relaxed);
    let rules_count = s.blocker.get_rules_count();
    ui_win.set_total_queries(sat_i32_u64(total));
    ui_win.set_blocked_count(sat_i32_u64(blocked));
    ui_win.set_blocked_today(sat_i32_u64(s.monitor.block_stats.day_count()));
    ui_win.set_blocked_week(sat_i32_u64(s.monitor.block_stats.week_count()));
    ui_win.set_absorbed_count(sat_i32_u64(absorbed));
    ui_win.set_active_rules_count(sat_i32_usize(rules_count));

    let is_locked = dns_manager::is_master_internet_locked();
    ui_win.set_master_locked(is_locked);
    ui_win.set_silent_sinkhole(s.blocker.is_silent_sinkhole());

    let protection = s.protection_atomic.load(Ordering::Relaxed);
    ui_win.set_protection_enabled(protection);

    let (cpu, mem) = s.monitor.get_system_metrics();
    ui_win.set_cpu_usage(cpu);
    ui_win.set_mem_usage(mem);

    let traffic = s.monitor.get_live_traffic_rate();
    let traffic_changed =
        UI_TEXT_CACHE.with(|c| cached_text_changed(&mut c.borrow_mut().traffic, &traffic));
    if traffic_changed {
        ui_win.set_live_traffic_rate(traffic.into());
    }

    let sec_score = s.security_engine.get_security_score();
    ui_win.set_security_score(sec_score);
    ui_win.set_threats_blocked_count(sat_i32_usize(s.security_engine.incidents_count()));
    ui_win.set_lan_devices_count(sat_i32_usize(s.monitor.get_lan_device_count()));
    ui_win.set_is_scanning(s.monitor.is_lan_scanning());

    {
        let cfg = s.config.read().unwrap_or_else(|e| e.into_inner());

        let first_run = UI_TEXT_CACHE.with(|c| !c.borrow().initialized);
        let lang_changed = UI_TEXT_CACHE.with(|c| c.borrow().lang != cfg.language);
        let force_text = first_run || lang_changed;
        if force_text {
            i18n::set_language(&cfg.language);
            ui_win
                .global::<crate::I18n>()
                .set_lang(i18n::current_index() as i32);
            UI_TEXT_CACHE.with(|c| {
                let mut cache = c.borrow_mut();
                cache.lang.clone_from(&cfg.language);
                cache.initialized = true;
            });
        }

        ui_win.set_security_score_hint(s.security_engine.get_security_score_hint().into());

        ui_win.set_autostart_enabled(cfg.start_with_windows);
        ui_win.set_minimize_to_tray_enabled(cfg.minimize_to_tray);
        ui_win.set_enable_notifications(cfg.enable_block_notifications);
        ui_win.set_network_wide_adblock(cfg.network_wide_adblock_enabled);
        ui_win.set_attack_detection_enabled(cfg.attack_detection_enabled);
        ui_win.set_auto_block_attacks(cfg.auto_block_attacks);
        ui_win.set_arp_spoof_detection(cfg.arp_spoof_detection);
        ui_win.set_minimize_to_tray_on_minimize(cfg.minimize_to_tray_on_minimize);
        ui_win.set_start_hidden_in_tray(cfg.start_hidden_in_tray);

        let status_tag: i8 = if is_locked {
            0
        } else if protection {
            1
        } else {
            2
        };
        let status_changed = UI_TEXT_CACHE.with(|c| {
            let mut cache = c.borrow_mut();
            let stale = cache.status_tag != status_tag || force_text;
            if stale {
                cache.status_tag = status_tag;
            }
            stale
        });
        if status_changed {
            let txt = if is_locked {
                i18n::tr(
                    "🔒 Đã khóa Internet",
                    "🔒 Internet Locked",
                    "🔒 已锁定互联网",
                )
            } else if protection {
                i18n::tr(
                    "🟢 Đang bảo vệ tối cao",
                    "🟢 Active Protection",
                    "🟢 高级防护中",
                )
            } else {
                i18n::tr("🔴 Đã tạm dừng", "🔴 Paused", "🔴 已暂停")
            };
            ui_win.set_status_text(txt.into());
        }

        let last_update_changed = UI_TEXT_CACHE.with(|c| {
            let mut cache = c.borrow_mut();
            let stale = cache.last_update_src != cfg.last_blocklist_update || force_text;
            if stale {
                cache.last_update_src.clone_from(&cfg.last_blocklist_update);
            }
            stale
        });
        if last_update_changed {
            let raw = cfg
                .last_blocklist_update
                .as_deref()
                .unwrap_or_else(|| i18n::tr("Chưa cập nhật", "Not updated", "尚未更新"));
            let text = if cfg.language == "vi" {
                format!("Cập nhật: {}", raw)
            } else if cfg.language == "zh" {
                format!("更新时间: {}", raw)
            } else {
                format!("Updated: {}", raw)
            };
            ui_win.set_last_update_text(text.into());
        }
    }

    let active_tab = ui_win.get_active_tab();
    match active_tab {
        1 => refresh_security_tab(ui_win, s),
        2 => refresh_monitor_tab(ui_win, s),
        3 => refresh_rules_tab(ui_win, s),
        #[cfg(feature = "admin")]
        5 => super::admin::update_admin_ui(ui_win, s),
        _ => {}
    }
}

fn refresh_security_tab(ui_win: &crate::AppWindow, s: &Arc<AppState>) {
    if ui_win.get_lan_subview_mode() != 1 {
        let devices = s.monitor.get_lan_devices();
        let device_models: Vec<crate::NetworkDevice> = devices
            .into_iter()
            .map(|d| {
                let open_ports =
                    crate::modules::monitor::port_scanner::format_ports_summary(&d.open_ports);
                let is_quarantined = s.security_engine.is_quarantined(&d.ip);
                let is_local = d.ip == "127.0.0.1"
                    || d.mac.contains("Local")
                    || d.mac.contains("Cục bộ")
                    || d.mac.contains("本地");
                crate::NetworkDevice {
                    name: d.name.into(),
                    ip: d.ip.into(),
                    mac: d.mac.into(),
                    vendor: d.vendor.into(),
                    device_type: d.device_type.into(),
                    is_online: d.is_online,
                    latency: if d.latency_ms < 0 {
                        "-".into()
                    } else {
                        format!("{} ms", d.latency_ms).into()
                    },
                    traffic: d.traffic.into(),
                    total_queries: sat_i32_u64(d.total_queries),
                    blocked_queries: sat_i32_u64(d.blocked_queries),
                    threats_detected: sat_i32_u64(d.threats_detected),
                    last_domain: d.last_domain.into(),
                    last_active: d.last_active.into(),
                    risk_level: d.risk_level.into(),
                    open_ports: open_ports.into(),
                    port_risk: d.port_risk.into(),
                    port_advice: d.port_advice.into(),
                    confidence: d.confidence,
                    custom_alias: d.custom_alias.into(),
                    os_name: d.os_name.into(),
                    is_quarantined,
                    bandwidth_rate: d.bandwidth_rate.into(),
                    is_local,
                }
            })
            .collect();
        ui_win.set_devices(ModelRc::new(VecModel::from(device_models)));
    } else {
        let query = ui_win.get_incident_search().to_string();
        let incidents = if query.trim().is_empty() {
            s.security_engine.get_incidents()
        } else {
            s.security_engine.filter_incidents(&query)
        };
        let incident_models: Vec<crate::SecurityIncident> = incidents
            .into_iter()
            .map(|inc| crate::SecurityIncident {
                id: sat_i32_u64(inc.id),
                time: inc.time.into(),
                incident_type: inc.incident_type.into(),
                source_ip: inc.source_ip.into(),
                details: inc.details.into(),
                severity: inc.severity.into(),
                mitigation: inc.mitigation.into(),
            })
            .collect();
        ui_win.set_security_incidents(ModelRc::new(VecModel::from(incident_models)));
    }
}

fn refresh_monitor_tab(ui_win: &crate::AppWindow, s: &Arc<AppState>) {
    match ui_win.get_monitor_subview_mode() {
        0 => {
            if ui_win.get_conn_view_mode() == 1 {
                let grp_conns = s.monitor.connection_tracker.get_grouped_connections();
                let grp_conn_models: Vec<crate::AppConnectionGroup> = grp_conns
                    .into_iter()
                    .map(|g| crate::AppConnectionGroup {
                        process_name: g.process_name.into(),
                        pid: sat_i32_u32(g.pid),
                        connection_count: sat_i32_usize(g.connection_count),
                        destinations_summary: g.destinations_summary.into(),
                        protocol_summary: g.protocol_summary.into(),
                        state_summary: g.state_summary.into(),
                        is_safe: g.is_safe,
                    })
                    .collect();
                ui_win.set_grouped_connections(ModelRc::new(VecModel::from(grp_conn_models)));
            } else {
                let conns = s.monitor.get_active_connections();
                let conn_models: Vec<crate::ActiveConnection> = conns
                    .into_iter()
                    .map(|c| crate::ActiveConnection {
                        process_name: c.process_name.into(),
                        pid: sat_i32_u32(c.pid),
                        local_addr: c.local_addr.into(),
                        remote_addr: c.remote_addr.into(),
                        protocol: c.protocol.into(),
                        state: c.state.into(),
                        is_safe: c.is_safe,
                    })
                    .collect();
                ui_win.set_connections(ModelRc::new(VecModel::from(conn_models)));
            }
        }
        1 => {
            let current_version = s.monitor.logs_version.load(Ordering::Relaxed);
            if s.logs_ui_version.load(Ordering::Relaxed) != current_version {
                let logs = s.monitor.get_logs();
                let log_models: Vec<crate::LogEntry> = logs
                    .clone()
                    .into_iter()
                    .map(|l| crate::LogEntry {
                        timestamp: l.timestamp.into(),
                        domain: l.domain.into(),
                        source_ip: l.source_ip.into(),
                        is_blocked: l.is_blocked,
                    })
                    .collect();
                ui_win.set_logs(ModelRc::new(VecModel::from(log_models)));

                let grp_logs = s.monitor.get_grouped_logs();
                let grp_log_models: Vec<crate::DomainLogGroup> = grp_logs
                    .into_iter()
                    .map(|g| crate::DomainLogGroup {
                        domain: g.domain.into(),
                        total_queries: sat_i32_usize(g.total_queries),
                        blocked_queries: sat_i32_usize(g.blocked_queries),
                        is_blocked: g.is_blocked,
                        last_seen: g.last_seen.into(),
                        last_ip: g.last_ip.into(),
                    })
                    .collect();
                ui_win.set_grouped_logs(ModelRc::new(VecModel::from(grp_log_models)));

                s.logs_ui_version.store(current_version, Ordering::Relaxed);
            }
        }
        _ => {
            // Gate console rebuilds on the log-buffer version so we avoid
            // cloning up to 500 entries every 1s tick when nothing changed.
            let cur = s.log_buffer.version();
            if s.console_ui_version.load(Ordering::Relaxed) != cur {
                let clogs = s.log_buffer.get_logs();
                let clog_models: Vec<crate::ConsoleLogEntry> = clogs
                    .into_iter()
                    .map(|cl| crate::ConsoleLogEntry {
                        time: cl.time.into(),
                        level: cl.level.into(),
                        message: cl.message.into(),
                    })
                    .collect();
                ui_win.set_console_logs(ModelRc::new(VecModel::from(clog_models)));
                s.console_ui_version.store(cur, Ordering::Relaxed);
            }
        }
    }
}

fn refresh_rules_tab(ui_win: &crate::AppWindow, s: &Arc<AppState>) {
    if !s.rules_dirty.swap(false, Ordering::SeqCst) {
        return;
    }
    let custom_rules = s
        .config
        .read()
        .map(|c| c.custom_blocked_domains.clone())
        .unwrap_or_default();
    let rule_models: Vec<slint::SharedString> =
        custom_rules.into_iter().map(|r| r.into()).collect();
    ui_win.set_custom_rules(ModelRc::new(VecModel::from(rule_models)));

    let allowed_rules = s
        .config
        .read()
        .map(|c| c.custom_allowed_domains.clone())
        .unwrap_or_default();
    let allow_models: Vec<slint::SharedString> =
        allowed_rules.into_iter().map(|r| r.into()).collect();
    ui_win.set_allowed_rules(ModelRc::new(VecModel::from(allow_models)));
}

#[cfg(test)]
mod tests {
    use super::cached_text_changed;

    #[test]
    fn reports_change_only_when_text_differs() {
        let mut slot = String::new();
        assert!(cached_text_changed(&mut slot, "a"));
        assert_eq!(slot, "a");
        assert!(!cached_text_changed(&mut slot, "a"));
        assert!(cached_text_changed(&mut slot, "b"));
        assert_eq!(slot, "b");
    }
}
