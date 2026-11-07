use super::*;

pub(super) fn register(ui: &crate::AppWindow, state: &Arc<AppState>) {
    let s_ab = state.clone();
    let ui_ab = ui.as_weak();
    ui.on_adblock_pause(move |minutes| {
        let mins = minutes.clamp(1, 720) as u64;
        s_ab.blocker.adblock.pause_minutes(mins);
        let msg = format!(
            "{} {} {}",
            crate::modules::i18n::tr4("⏸ Tạm dừng chặn", "⏸ Paused", "⏸ 已暂停", "⏸ Пауза"),
            mins,
            crate::modules::i18n::tr4("phút.", "min.", "分钟。", "мин.")
        );
        if let Some(u) = ui_ab.upgrade() {
            u.set_adblock_status(msg.into());
        }
        info!("Ad blocking paused for {} minutes", mins);
    });

    let s_ab = state.clone();
    let ui_ab = ui.as_weak();
    ui.on_adblock_resume(move || {
        s_ab.blocker.adblock.resume();
        if let Some(u) = ui_ab.upgrade() {
            u.set_adblock_status(
                crate::modules::i18n::tr4(
                    "▶ Đã tiếp tục chặn quảng cáo.",
                    "▶ Ad blocking resumed.",
                    "▶ 已恢复拦截广告。",
                    "▶ Блокировка возобновлена.",
                )
                .into(),
            );
        }
    });

    let s_ab = state.clone();
    let ui_ab = ui.as_weak();
    ui.on_adblock_set_rule(move || {
        let (ip_text, mode_id) = if let Some(u) = ui_ab.upgrade() {
            (
                u.get_adblock_rule_ip_input().to_string(),
                u.get_adblock_rule_mode(),
            )
        } else {
            return;
        };
        let ip_str = ip_text.trim().to_string();
        let parsed: std::net::IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                if let Some(u) = ui_ab.upgrade() {
                    u.set_adblock_status(
                        crate::modules::i18n::tr4(
                            "❌ IP không hợp lệ. Ví dụ: 192.168.1.50",
                            "❌ Invalid IP. Example: 192.168.1.50",
                            "❌ IP 无效。示例：192.168.1.50",
                            "❌ Неверный IP. Пример: 192.168.1.50",
                        )
                        .into(),
                    );
                }
                return;
            }
        };
        let Some(mode) = crate::modules::dns::client_policy::ClientMode::from_id(mode_id) else {
            return;
        };
        if crate::modules::service::remote_mode() {
            let ok = remote_send(crate::modules::service::protocol::CoreRequest::Policy {
                ip: ip_str.clone(),
                mode: mode_id,
                remove: false,
            });
            if let Some(u) = ui_ab.upgrade() {
                let label = mode.localized_label();
                u.set_adblock_status(
                    if ok {
                        format!("✅ {label}: {ip_str}")
                    } else {
                        format!("❌ {label}: {ip_str}")
                    }
                    .into(),
                );
            }
            return;
        }
        let own_lan_ip = dns_manager::get_lan_ip_address();
        let targets_self = parsed.is_loopback()
            || (!own_lan_ip.is_empty() && own_lan_ip == ip_str);
        if mode == crate::modules::dns::client_policy::ClientMode::Strict && targets_self {
            if let Some(u) = ui_ab.upgrade() {
                u.set_adblock_status(
                    crate::modules::i18n::tr4(
                        "❌ Không thể đặt chế độ Nghiêm ngặt cho chính máy này — sẽ tự chặn mất mạng.",
                        "❌ Strict mode cannot target this machine — it would cut off your own network.",
                        "❌ 严格模式不能作用于本机 — 会导致本机断网。",
                        "❌ Строгий режим нельзя применить к этой машине — это отрежет ей сеть.",
                    )
                    .into(),
                );
            }
            return;
        }
        s_ab.blocker.adblock.set_client_rule(parsed, mode);
        if let Ok(mut cfg_guard) = s_ab.config.write() {
            cfg_guard.adblock_client_rules = s_ab.blocker.adblock.rules_config();
            let _ = cfg_guard.save();
        }
        if let Some(u) = ui_ab.upgrade() {
            u.set_adblock_status(
                format!(
                    "✅ {} {}",
                    crate::modules::i18n::tr4(
                        "Đã áp dụng chế độ cho thiết bị",
                        "Mode applied for device",
                        "已为设备应用模式",
                        "Режим применён для устройства"
                    ),
                    ip_str
                )
                .into(),
            );
        }
        info!("Ad-block client rule set: {} -> {}", ip_str, mode.as_str());
    });

    let s_ab = state.clone();
    let ui_ab = ui.as_weak();
    ui.on_adblock_remove_rule(move |ip_text| {
        let ip_str = ip_text.trim().to_string();
        if remote_send(crate::modules::service::protocol::CoreRequest::Policy {
            ip: ip_str.clone(),
            mode: 0,
            remove: true,
        }) {
            return;
        }
        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
            s_ab.blocker.adblock.remove_client_rule(&ip);
        }
        if let Ok(mut cfg_guard) = s_ab.config.write() {
            cfg_guard.adblock_client_rules = s_ab.blocker.adblock.rules_config();
            let _ = cfg_guard.save();
        }
        if let Some(u) = ui_ab.upgrade() {
            u.set_adblock_status(
                format!(
                    "🗑️ {} {}",
                    crate::modules::i18n::tr4(
                        "Đã xoá luật của thiết bị",
                        "Rule removed for device",
                        "已删除设备规则",
                        "Правило удалено для устройства"
                    ),
                    ip_str
                )
                .into(),
            );
        }
    });

    let s_ab = state.clone();
    let ui_ab = ui.as_weak();
    ui.on_adblock_clear_stats(move || {
        s_ab.blocker.adblock.clear_stats();
        if let Some(u) = ui_ab.upgrade() {
            u.set_adblock_status(
                crate::modules::i18n::tr4(
                    "🧹 Đã xoá toàn bộ thống kê chặn.",
                    "🧹 All blocking statistics cleared.",
                    "🧹 已清除全部拦截统计。",
                    "🧹 Вся статистика очищена.",
                )
                .into(),
            );
        }
    });

    let s_ab = state.clone();
    let ui_ab = ui.as_weak();
    ui.on_adblock_export_stats(move || {
        let snap = s_ab.blocker.adblock.snapshot();
        let mut csv = String::from("section,label,count\n");
        csv.push_str(&format!(
            "total,{},{}\n",
            "session_blocked", snap.total_blocked
        ));
        for item in &snap.top_domains {
            csv.push_str(&format!(
                "domain,{},{}\n",
                item.label.replace(',', " "),
                item.count
            ));
        }
        for item in &snap.top_clients {
            csv.push_str(&format!(
                "client,{},{}\n",
                item.label.replace(',', " "),
                item.count
            ));
        }
        for item in &snap.hourly {
            csv.push_str(&format!(
                "hour,{},{}\n",
                item.label.replace(',', " "),
                item.count
            ));
        }
        for (ip, mode) in &snap.rules {
            csv.push_str(&format!("rule,{},{}\n", ip, mode.as_str()));
        }
        let exports_dir =
            std::path::PathBuf::from(std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string()))
                .join("ShieldGhita")
                .join("exports");
        let _ = std::fs::create_dir_all(&exports_dir);
        let path = exports_dir.join(format!(
            "adblock_stats_{}.csv",
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        ));
        let status = match std::fs::write(&path, csv) {
            Ok(()) => format!(
                "💾 {}: {}",
                crate::modules::i18n::tr4(
                    "Đã xuất CSV",
                    "Exported CSV",
                    "已导出 CSV",
                    "CSV сохранён"
                ),
                path.display()
            ),
            Err(e) => format!(
                "❌ {}: {}",
                crate::modules::i18n::tr4(
                    "Lỗi xuất CSV",
                    "Export failed",
                    "导出失败",
                    "Ошибка экспорта"
                ),
                e
            ),
        };
        if let Some(u) = ui_ab.upgrade() {
            u.set_adblock_status(status.into());
        }
    });

    let s_hh = state.clone();
    let ui_hh_busy = ui.as_weak();
    let ui_hh = ui.as_weak();
    ui.on_hosts_hygiene_check(move || {
        if let Some(u) = ui_hh_busy.upgrade() {
            u.set_hosts_checking(true);
        }
        let s2 = s_hh.clone();
        let ui_weak = ui_hh.clone();
        s_hh.runtime.spawn(async move {
            let engine = s2.security_engine.clone();
            let found = tokio::task::spawn_blocking(move || engine.inspect_hosts_file())
                .await
                .unwrap_or(None);
            let (text, warning) = match found {
                Some(inc) => (format!("⚠ {} — {}", inc.incident_type, inc.details), true),
                None => (
                    crate::modules::i18n::tr4(
                        "✅ File hosts hệ thống sạch, không có mục ghi đè DNS đáng ngờ.",
                        "✅ System hosts file is clean — no suspicious DNS-overriding entries.",
                        "✅ 系统 hosts 文件干净，无可疑 DNS 覆盖条目。",
                        "✅ Системный hosts-файл чист — подозрительных записей нет.",
                    )
                    .to_string(),
                    false,
                ),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    u.set_hosts_hygiene_text(text.into());
                    u.set_hosts_hygiene_warning(warning);
                    u.set_hosts_checking(false);
                }
            });
        });
    });
}
