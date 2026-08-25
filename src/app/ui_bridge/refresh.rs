use crate::app::AppState;
use crate::modules::i18n;
use crate::modules::system::dns_manager;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub fn refresh_ui_state(ui_win: &crate::AppWindow, s: &Arc<AppState>) {
    let total = s.blocker.total_queries.load(Ordering::Relaxed);
    let blocked = s.blocker.blocked_count.load(Ordering::Relaxed);
    let absorbed = s.sinkhole.absorbed_count.load(Ordering::Relaxed);
    let rules_count = s.blocker.get_rules_count();
    ui_win.set_total_queries(total as i32);
    ui_win.set_blocked_count(blocked as i32);
    ui_win.set_blocked_today(s.monitor.block_stats.day_count() as i32);
    ui_win.set_blocked_week(s.monitor.block_stats.week_count() as i32);
    ui_win.set_absorbed_count(absorbed as i32);
    ui_win.set_active_rules_count(rules_count as i32);

    let is_locked = dns_manager::is_master_internet_locked();
    ui_win.set_master_locked(is_locked);
    ui_win.set_silent_sinkhole(s.blocker.is_silent_sinkhole());

    let (
        lang_code,
        autostart,
        minimize,
        notify,
        net_adblock,
        attack_det,
        auto_blk,
        arp_det,
        min_tray_mode,
        start_hidden,
        last_blocklist_update,
    ) = s
        .config
        .read()
        .map(|c| {
            (
                c.language.clone(),
                c.start_with_windows,
                c.minimize_to_tray,
                c.enable_block_notifications,
                c.network_wide_adblock_enabled,
                c.attack_detection_enabled,
                c.auto_block_attacks,
                c.arp_spoof_detection,
                c.minimize_to_tray_on_minimize,
                c.start_hidden_in_tray,
                c.last_blocklist_update.clone(),
            )
        })
        .unwrap_or((
            "vi".to_string(),
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            true,
            false,
            None,
        ));
    i18n::set_language(&lang_code);
    ui_win
        .global::<crate::I18n>()
        .set_lang(i18n::current_index() as i32);

    let protection = s.protection_atomic.load(Ordering::Relaxed);
    ui_win.set_protection_enabled(protection);
    ui_win.set_status_text(if is_locked {
        i18n::tr(
            "🔒 Đã khóa Internet",
            "🔒 Internet Locked",
            "🔒 已锁定互联网",
        )
        .into()
    } else if protection {
        i18n::tr(
            "🟢 Đang bảo vệ tối cao",
            "🟢 Active Protection",
            "🟢 高级防护中",
        )
        .into()
    } else {
        i18n::tr("🔴 Đã tạm dừng", "🔴 Paused", "🔴 已暂停").into()
    });

    ui_win.set_autostart_enabled(autostart);
    ui_win.set_minimize_to_tray_enabled(minimize);
    ui_win.set_enable_notifications(notify);
    ui_win.set_network_wide_adblock(net_adblock);
    ui_win.set_attack_detection_enabled(attack_det);
    ui_win.set_auto_block_attacks(auto_blk);
    ui_win.set_arp_spoof_detection(arp_det);
    ui_win.set_minimize_to_tray_on_minimize(min_tray_mode);
    ui_win.set_start_hidden_in_tray(start_hidden);

    let (cpu, mem) = s.monitor.get_system_metrics();
    ui_win.set_cpu_usage(cpu);
    ui_win.set_mem_usage(mem);
    ui_win.set_live_traffic_rate(s.monitor.get_live_traffic_rate().into());

    let sec_score = s.security_engine.get_security_score();
    ui_win.set_security_score(sec_score);
    ui_win.set_threats_blocked_count(s.security_engine.incidents_count() as i32);
    ui_win.set_lan_devices_count(s.monitor.get_lan_device_count() as i32);
    ui_win.set_is_scanning(s.monitor.is_lan_scanning());

    let last_update = last_blocklist_update
        .unwrap_or_else(|| i18n::tr("Chưa cập nhật", "Not updated", "尚未更新").to_string());
    ui_win.set_last_update_text(
        if lang_code == "vi" {
            format!("Cập nhật: {}", last_update)
        } else if lang_code == "zh" {
            format!("更新时间: {}", last_update)
        } else {
            format!("Updated: {}", last_update)
        }
        .into(),
    );

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
                    total_queries: d.total_queries as i32,
                    blocked_queries: d.blocked_queries as i32,
                    threats_detected: d.threats_detected as i32,
                    last_domain: d.last_domain.into(),
                    last_active: d.last_active.into(),
                    risk_level: d.risk_level.into(),
                    open_ports: open_ports.into(),
                    port_risk: d.port_risk.into(),
                    port_advice: d.port_advice.into(),
                    confidence: d.confidence,
                }
            })
            .collect();
        ui_win.set_devices(ModelRc::new(VecModel::from(device_models)));
    } else {
        let incidents = s.security_engine.get_incidents();
        let incident_models: Vec<crate::SecurityIncident> = incidents
            .into_iter()
            .map(|inc| crate::SecurityIncident {
                id: inc.id as i32,
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
                        pid: g.pid as i32,
                        connection_count: g.connection_count as i32,
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
                        pid: c.pid as i32,
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
                        total_queries: g.total_queries as i32,
                        blocked_queries: g.blocked_queries as i32,
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
