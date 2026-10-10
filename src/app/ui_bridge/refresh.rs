use crate::app::AppState;
use crate::modules::i18n;
use crate::modules::service::protocol::CoreSnapshot;
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
    adblock_pause: String,
    last_lan_only: Option<bool>,
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

    ui_win.set_adblock_total_today(sat_i32_u64(s.blocker.adblock.total_blocked()));
    let remaining_secs = s.blocker.adblock.pause_remaining_secs();
    let pause_left = if remaining_secs == 0 {
        String::new()
    } else {
        format!(
            "⏸ {}: {:02}:{:02}",
            i18n::tr4("Còn lại", "Remaining", "剩余", "Осталось"),
            remaining_secs / 60,
            remaining_secs % 60
        )
    };
    let pause_changed =
        UI_TEXT_CACHE.with(|c| cached_text_changed(&mut c.borrow_mut().adblock_pause, &pause_left));
    if pause_changed {
        ui_win.set_adblock_pause_left(pause_left.into());
    }

    let lan_only = dns_manager::is_lan_only_mode();
    let wfp_ok = s.wfp_blocker.is_available();
    ui_win.set_dns_lan_only(lan_only);
    ui_win.set_wfp_available(wfp_ok);
    ui_win.set_network_override_active(
        dns_manager::is_dns_overridden() || dns_manager::is_master_internet_locked(),
    );
    let conflict_changed = UI_TEXT_CACHE.with(|c| {
        let mut cache = c.borrow_mut();
        if cache.last_lan_only != Some(lan_only) {
            cache.last_lan_only = Some(lan_only);
            true
        } else {
            false
        }
    });
    if conflict_changed {
        let text = match dns_manager::detect_dns_controller_conflict() {
            Some(found) => {
                let mut text = dns_manager::describe_dns_controller(&found);
                text.push_str(" — ");
                text.push_str(i18n::tr4(
                    "Đang ở chế độ chỉ phục vụ LAN, DNS hệ thống để nguyên cho VPN.",
                    "Running in LAN-only mode; system DNS left to the VPN.",
                    "处于仅服务局域网模式，系统 DNS 保留给 VPN。",
                    "Режим только LAN; системный DNS оставлен VPN.",
                ));
                text
            }
            None => String::new(),
        };
        ui_win.set_dns_conflict_text(text.into());
    }

    if ui_win.get_active_tab() == 9 {
        let snap = s.blocker.adblock.snapshot();
        ui_win.set_adblock_top_domains(slint::ModelRc::new(slint::VecModel::from(
            snap.top_domains
                .iter()
                .map(|item| crate::AdStatItem {
                    label: item.label.clone().into(),
                    count: sat_i32_u64(item.count),
                })
                .collect::<Vec<_>>(),
        )));
        ui_win.set_adblock_top_clients(slint::ModelRc::new(slint::VecModel::from(
            snap.top_clients
                .iter()
                .map(|item| crate::AdStatItem {
                    label: item.label.clone().into(),
                    count: sat_i32_u64(item.count),
                })
                .collect::<Vec<_>>(),
        )));
        ui_win.set_adblock_hourly(slint::ModelRc::new(slint::VecModel::from(
            snap.hourly
                .iter()
                .map(|item| crate::AdStatItem {
                    label: item.label.clone().into(),
                    count: sat_i32_u64(item.count),
                })
                .collect::<Vec<_>>(),
        )));
        ui_win.set_adblock_rules(slint::ModelRc::new(slint::VecModel::from(
            snap.rules
                .iter()
                .map(|(ip, mode)| crate::ClientRuleItem {
                    ip: ip.clone().into(),
                    mode: mode.localized_label().into(),
                    mode_id: mode.id(),
                })
                .collect::<Vec<_>>(),
        )));
    }

    if ui_win.get_active_tab() == 10 {
        ui_win.set_av_realtime(s.realtime_guard.is_enabled());
        ui_win.set_av_auto_quarantine(s.realtime_guard.is_auto_quarantine());
        ui_win.set_av_lock_active(s.realtime_guard.is_lock_active());
        ui_win.set_av_signature_count(sat_i32_usize(crate::modules::security::signatures::count()));
        let entries = crate::modules::security::file_quarantine::list();
        ui_win.set_av_quarantine_list(slint::ModelRc::new(slint::VecModel::from(
            entries
                .iter()
                .map(|entry| crate::QuarantineItem {
                    entry_id: entry.id.clone().into(),
                    original_name: entry.original_name.clone().into(),
                    original_path: entry.original_path.clone().into(),
                    reason: entry.reason.clone().into(),
                    quarantined_at: entry.quarantined_at.clone().into(),
                    size_kb: sat_i32_u64(entry.size / 1024),
                })
                .collect::<Vec<_>>(),
        )));
    }

    refresh_config_and_texts(
        ui_win,
        s,
        is_locked,
        protection,
        &s.security_engine.get_security_score_hint(),
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

fn refresh_config_and_texts(
    ui_win: &crate::AppWindow,
    s: &Arc<AppState>,
    is_locked: bool,
    protection: bool,
    score_hint: &str,
) {
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

    ui_win.set_security_score_hint(score_hint.into());

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

pub fn apply_remote_snapshot(
    ui_win: &crate::AppWindow,
    s: &Arc<AppState>,
    snap: &crate::modules::service::protocol::CoreSnapshot,
) {
    ui_win.set_total_queries(sat_i32_u64(snap.total_queries));
    ui_win.set_blocked_count(sat_i32_u64(snap.blocked_count));
    ui_win.set_blocked_today(sat_i32_u64(snap.blocked_today));
    ui_win.set_blocked_week(sat_i32_u64(snap.blocked_week));
    ui_win.set_absorbed_count(sat_i32_u64(snap.absorbed_count));
    ui_win.set_active_rules_count(sat_i32_u64(snap.rules_count));
    ui_win.set_master_locked(snap.lock);
    ui_win.set_silent_sinkhole(snap.sinkhole);
    ui_win.set_protection_enabled(snap.protection);
    ui_win.set_cpu_usage(snap.cpu);
    ui_win.set_mem_usage(snap.mem);
    UI_TEXT_CACHE.with(|c| {
        let mut cache = c.borrow_mut();
        if cached_text_changed(&mut cache.traffic, &snap.live_traffic_rate) {
            ui_win.set_live_traffic_rate(snap.live_traffic_rate.as_str().into());
        }
    });
    ui_win.set_security_score(snap.sec_score);
    ui_win.set_threats_blocked_count(sat_i32_u64(snap.incidents_count));
    ui_win.set_lan_devices_count(sat_i32_u64(snap.lan_devices_count));
    ui_win.set_is_scanning(snap.is_scanning);
    ui_win.set_adblock_total_today(sat_i32_u64(snap.adblock_total_today));
    UI_TEXT_CACHE.with(|c| {
        let pause_left = if snap.pause_remaining_secs == 0 {
            String::new()
        } else {
            format!(
                "⏸ {}: {:02}:{:02}",
                i18n::tr4("Còn lại", "Remaining", "剩余", "Осталось"),
                snap.pause_remaining_secs / 60,
                snap.pause_remaining_secs % 60
            )
        };
        if cached_text_changed(&mut c.borrow_mut().adblock_pause, &pause_left) {
            ui_win.set_adblock_pause_left(pause_left.as_str().into());
        }
    });
    ui_win.set_dns_lan_only(snap.lan_only);
    ui_win.set_wfp_available(snap.wfp_available);
    ui_win.set_network_override_active(snap.override_active);

    refresh_config_and_texts(ui_win, s, snap.lock, snap.protection, &snap.score_hint);

    ui_win.set_attack_detection_enabled(snap.attack_detection);
    ui_win.set_auto_block_attacks(snap.auto_block);
    ui_win.set_arp_spoof_detection(snap.arp_spoof);
    ui_win.set_network_wide_adblock(snap.network_wide);

    let active_tab = ui_win.get_active_tab();
    match active_tab {
        1 => apply_remote_security_tab(ui_win, snap),
        2 => apply_remote_monitor_tab(ui_win, snap),
        #[cfg(feature = "admin")]
        5 => apply_remote_admin_tab(ui_win, snap),
        9 => apply_remote_adblock_tab(ui_win, snap),
        10 => apply_remote_av_tab(ui_win, snap),
        _ => {}
    }
}

fn apply_remote_security_tab(ui_win: &crate::AppWindow, snap: &CoreSnapshot) {
    if let Some(devices) = &snap.devices {
        if ui_win.get_lan_subview_mode() != 1 {
            let device_models: Vec<crate::NetworkDevice> = devices
                .iter()
                .map(|d| crate::NetworkDevice {
                    name: d.name.as_str().into(),
                    ip: d.ip.as_str().into(),
                    mac: d.mac.as_str().into(),
                    vendor: d.vendor.as_str().into(),
                    device_type: d.device_type.as_str().into(),
                    is_online: d.is_online,
                    latency: if d.latency_ms < 0 {
                        "-".into()
                    } else {
                        format!("{} ms", d.latency_ms).into()
                    },
                    traffic: d.traffic.as_str().into(),
                    total_queries: sat_i32_u64(d.total_queries),
                    blocked_queries: sat_i32_u64(d.blocked_queries),
                    threats_detected: sat_i32_u64(d.threats_detected),
                    last_domain: d.last_domain.as_str().into(),
                    last_active: d.last_active.as_str().into(),
                    risk_level: d.risk_level.as_str().into(),
                    open_ports: d.open_ports_str.as_str().into(),
                    port_risk: d.port_risk.as_str().into(),
                    port_advice: d.port_advice.as_str().into(),
                    confidence: d.confidence,
                    custom_alias: d.custom_alias.as_str().into(),
                    os_name: d.os_name.as_str().into(),
                    is_quarantined: d.is_quarantined,
                    bandwidth_rate: d.bandwidth_rate.as_str().into(),
                    is_local: d.is_local,
                })
                .collect();
            ui_win.set_devices(ModelRc::new(VecModel::from(device_models)));
            return;
        }
    }
    if ui_win.get_lan_subview_mode() == 1 {
        if let Some(incidents) = &snap.incidents {
            let query = ui_win.get_incident_search().to_string();
            let query_trimmed = query.trim();
            let incident_models: Vec<crate::SecurityIncident> = incidents
                .iter()
                .filter(|i| {
                    query_trimmed.is_empty()
                        || i.incident_type.contains(query_trimmed)
                        || i.source_ip.contains(query_trimmed)
                        || i.details.contains(query_trimmed)
                })
                .map(|inc| crate::SecurityIncident {
                    id: sat_i32_u64(inc.id),
                    time: inc.time.as_str().into(),
                    incident_type: inc.incident_type.as_str().into(),
                    source_ip: inc.source_ip.as_str().into(),
                    details: inc.details.as_str().into(),
                    severity: inc.severity.as_str().into(),
                    mitigation: inc.mitigation.as_str().into(),
                })
                .collect();
            ui_win.set_security_incidents(ModelRc::new(VecModel::from(incident_models)));
        }
    }
}

fn apply_remote_monitor_tab(ui_win: &crate::AppWindow, snap: &CoreSnapshot) {
    match ui_win.get_monitor_subview_mode() {
        0 => {
            if ui_win.get_conn_view_mode() == 1 {
                if let Some(groups) = &snap.conn_groups {
                    let models: Vec<crate::AppConnectionGroup> = groups
                        .iter()
                        .map(|g| crate::AppConnectionGroup {
                            process_name: g.process_name.as_str().into(),
                            pid: sat_i32_u32(g.pid),
                            connection_count: sat_i32_u32(g.connection_count),
                            destinations_summary: g.destinations_summary.as_str().into(),
                            protocol_summary: g.protocol_summary.as_str().into(),
                            state_summary: g.state_summary.as_str().into(),
                            is_safe: g.is_safe,
                        })
                        .collect();
                    ui_win.set_grouped_connections(ModelRc::new(VecModel::from(models)));
                }
            } else if let Some(conns) = &snap.connections {
                let models: Vec<crate::ActiveConnection> = conns
                    .iter()
                    .map(|c| crate::ActiveConnection {
                        process_name: c.process_name.as_str().into(),
                        pid: sat_i32_u32(c.pid),
                        local_addr: c.local_addr.as_str().into(),
                        remote_addr: c.remote_addr.as_str().into(),
                        protocol: c.protocol.as_str().into(),
                        state: c.state.as_str().into(),
                        is_safe: c.is_safe,
                    })
                    .collect();
                ui_win.set_connections(ModelRc::new(VecModel::from(models)));
            }
        }
        1 => {
            if let Some(logs) = &snap.logs {
                let log_models: Vec<crate::LogEntry> = logs
                    .iter()
                    .map(|l| crate::LogEntry {
                        timestamp: l.timestamp.as_str().into(),
                        domain: l.domain.as_str().into(),
                        source_ip: l.source_ip.as_str().into(),
                        is_blocked: l.is_blocked,
                    })
                    .collect();
                ui_win.set_logs(ModelRc::new(VecModel::from(log_models)));
            }
            if let Some(grouped) = &snap.grouped_logs {
                let grp_models: Vec<crate::DomainLogGroup> = grouped
                    .iter()
                    .map(|g| crate::DomainLogGroup {
                        domain: g.domain.as_str().into(),
                        total_queries: sat_i32_u64(g.total_queries),
                        blocked_queries: sat_i32_u64(g.blocked_queries),
                        is_blocked: g.is_blocked,
                        last_seen: g.last_seen.as_str().into(),
                        last_ip: g.last_ip.as_str().into(),
                    })
                    .collect();
                ui_win.set_grouped_logs(ModelRc::new(VecModel::from(grp_models)));
            }
        }
        _ => {
            if let Some(console) = &snap.console_logs {
                let models: Vec<crate::ConsoleLogEntry> = console
                    .iter()
                    .map(|c| crate::ConsoleLogEntry {
                        time: c.time.as_str().into(),
                        level: c.level.as_str().into(),
                        message: c.message.as_str().into(),
                    })
                    .collect();
                ui_win.set_console_logs(ModelRc::new(VecModel::from(models)));
            }
        }
    }
}

#[cfg(feature = "admin")]
fn apply_remote_admin_tab(ui_win: &crate::AppWindow, snap: &CoreSnapshot) {
    use std::sync::atomic::Ordering;
    static LAST_ADMIN_REMOTE_MS: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let last = LAST_ADMIN_REMOTE_MS.load(Ordering::Relaxed);
    if now_ms.wrapping_sub(last) < 3_000 && last != 0 {
        return;
    }
    LAST_ADMIN_REMOTE_MS.store(now_ms, Ordering::Relaxed);

    if let Some(proximity) = &snap.proximity {
        ui_win.set_proximity_devices_count(sat_i32_usize(proximity.len()));
        let models: Vec<crate::ProximityDeviceItem> = proximity
            .iter()
            .map(|d| crate::ProximityDeviceItem {
                id: d.id.as_str().into(),
                name: d.name.as_str().into(),
                ip: d.ip.as_str().into(),
                mac: d.mac.as_str().into(),
                vendor: d.vendor.as_str().into(),
                discovery_method: d.discovery_method.as_str().into(),
                network_interface: d.network_interface.as_str().into(),
                signal_info: d.signal_info.as_str().into(),
                last_seen: d.last_seen.as_str().into(),
                latency_ms: d.latency_ms,
                is_online: d.is_online,
                open_ports_str: d.open_ports_str.as_str().into(),
            })
            .collect();
        ui_win.set_proximity_devices(ModelRc::new(VecModel::from(models)));
    }
    if let Some(behaviors) = &snap.behaviors {
        ui_win.set_behavior_profiles_count(sat_i32_usize(behaviors.len()));
        ui_win.set_high_risk_count(sat_i32_u64(snap.high_risk_count));
        ui_win.set_wifi_nodes_count(sat_i32_u64(snap.wifi_nodes_count));
        let models: Vec<crate::BehaviorProfileItem> = behaviors
            .iter()
            .map(|p| crate::BehaviorProfileItem {
                ip: p.ip.as_str().into(),
                hostname: p.hostname.as_str().into(),
                total_queries: sat_i32_u64(p.total_queries),
                blocked_queries: sat_i32_u64(p.blocked_queries),
                threat_queries: sat_i32_u64(p.threat_queries),
                burst_qps: format!("{:.1} qps", p.burst_qps).into(),
                risk_score: p.risk_score,
                category: p.category.as_str().into(),
                last_seen: p.last_seen.as_str().into(),
            })
            .collect();
        ui_win.set_behavior_profiles(ModelRc::new(VecModel::from(models)));
    }
    if let Some(attacks) = &snap.attacks {
        ui_win.set_active_attacks_count(sat_i32_usize(attacks.len()));
        let models: Vec<crate::AttackHistoryItem> = attacks
            .iter()
            .map(|e| crate::AttackHistoryItem {
                target: e.ip.as_str().into(),
                mode_label: if e.mode == crate::modules::local::attack::MODE_WARNING {
                    crate::modules::i18n::tr("CẢNH BÁO", "WARNING", "警告").into()
                } else {
                    crate::modules::i18n::tr("CHẶN", "BLOCK", "拦截").into()
                },
                message: e.message.as_str().into(),
                window_label: format!("{} → {}", e.activated_at, e.expires_at).into(),
                hits_label: format!("⚡ {}", e.hit_count).into(),
                is_warning: e.mode == crate::modules::local::attack::MODE_WARNING,
            })
            .collect();
        ui_win.set_attack_history(ModelRc::new(VecModel::from(models)));
    }
    if let Some(cameras) = &snap.cameras {
        let models: Vec<crate::CameraItem> = cameras
            .iter()
            .map(|c| crate::CameraItem {
                vendor: c.vendor.as_str().into(),
                model: c.model_hint.as_str().into(),
                ip: c.ip.as_str().into(),
                rtsp_url: c.rtsp_url.as_str().into(),
                source: c.source.as_str().into(),
                is_online: c.rtsp_open,
                snapshot_url: c.snapshot_url.as_str().into(),
                has_default_pass: c.is_default_password,
                resolution: "-".into(),
            })
            .collect();
        ui_win.set_camera_list(ModelRc::new(VecModel::from(models)));
    }
}

fn apply_remote_adblock_tab(ui_win: &crate::AppWindow, snap: &CoreSnapshot) {
    if let Some(ad) = &snap.adblock {
        ui_win.set_adblock_top_domains(ModelRc::new(VecModel::from(
            ad.top_domains
                .iter()
                .map(|i| crate::AdStatItem {
                    label: i.label.as_str().into(),
                    count: sat_i32_u64(i.count),
                })
                .collect::<Vec<_>>(),
        )));
        ui_win.set_adblock_top_clients(ModelRc::new(VecModel::from(
            ad.top_clients
                .iter()
                .map(|i| crate::AdStatItem {
                    label: i.label.as_str().into(),
                    count: sat_i32_u64(i.count),
                })
                .collect::<Vec<_>>(),
        )));
        ui_win.set_adblock_hourly(ModelRc::new(VecModel::from(
            ad.hourly
                .iter()
                .map(|i| crate::AdStatItem {
                    label: i.label.as_str().into(),
                    count: sat_i32_u64(i.count),
                })
                .collect::<Vec<_>>(),
        )));
        ui_win.set_adblock_rules(ModelRc::new(VecModel::from(
            ad.rules
                .iter()
                .map(|r| crate::ClientRuleItem {
                    ip: r.ip.as_str().into(),
                    mode: r.mode_label.as_str().into(),
                    mode_id: r.mode_id,
                })
                .collect::<Vec<_>>(),
        )));
    }
}

fn apply_remote_av_tab(ui_win: &crate::AppWindow, snap: &CoreSnapshot) {
    if let Some(av) = &snap.av {
        ui_win.set_av_realtime(av.realtime_enabled);
        ui_win.set_av_auto_quarantine(av.auto_quarantine);
        ui_win.set_av_lock_active(av.lock_active);
        ui_win.set_av_signature_count(sat_i32_u64(av.signature_count));
        ui_win.set_av_quarantine_list(ModelRc::new(VecModel::from(
            av.quarantine
                .iter()
                .map(|e| crate::QuarantineItem {
                    entry_id: e.entry_id.as_str().into(),
                    original_name: e.original_name.as_str().into(),
                    original_path: e.original_path.as_str().into(),
                    reason: e.reason.as_str().into(),
                    quarantined_at: e.quarantined_at.as_str().into(),
                    size_kb: sat_i32_u64(e.size / 1024),
                })
                .collect::<Vec<_>>(),
        )));
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
