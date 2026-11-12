use std::path::PathBuf;

use crate::modules::security::vulnscan::{dynamic_finding, finding, VulnFinding};

const SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services";
const USBSTOR_KEY: &str = r"SYSTEM\CurrentControlSet\Enum\USBSTOR";
const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
const RUNONCE_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
const MAX_LISTED_ITEMS: usize = 8;
const BRUTE_FORCE_EVENT_THRESHOLD: usize = 30;

pub fn audit_persistence() -> Vec<VulnFinding> {
    let mut findings = Vec::new();
    audit_run_keys(&mut findings);
    audit_scheduled_tasks(&mut findings);
    audit_suspicious_service_paths(&mut findings);
    if findings.is_empty() {
        findings.push(finding(
            "PERSISTENCE_CLEAN",
            "LOW",
            (
                "Không phát hiện điểm thường trú đáng ngờ",
                "No suspicious persistence mechanisms detected",
                "未发现可疑的持久化机制",
                "Подозрительных механизмов закрепления не найдено",
            ),
            (
                "Run keys, lịch tác vụ và dịch vụ đang ổn theo các kiểm tra hiện có.",
                "Run keys, scheduled tasks and services look clean per current checks.",
                "启动项、计划任务与服务在当前检查下正常。",
                "Ключи автозапуска, задачи и службы в норме.",
            ),
            (
                "Vẫn nên chạy lại kiểm tra định kỳ, đặc biệt sau khi cài phần mềm mới.",
                "Re-run periodically, especially after installing new software.",
                "安装新软件后应定期重新检查。",
                "Повторяйте проверку после установки нового ПО.",
            ),
        ));
    }
    findings
}

fn add_run_key_findings(
    findings: &mut Vec<VulnFinding>,
    hive_label: &str,
    names: Vec<String>,
    key: &str,
) {
    if names.is_empty() {
        return;
    }
    let shown: Vec<String> = names.iter().take(MAX_LISTED_ITEMS).cloned().collect();
    let extra = names.len().saturating_sub(MAX_LISTED_ITEMS);
    findings.push(dynamic_finding(
        "PERSISTENCE_RUN",
        "MEDIUM",
        format!(
            "{} {} ({})",
            tr_(
                "Nhóm Run có",
                "Run key has",
                "Run 键有",
                "Run-ключ содержит"
            ),
            names.len(),
            hive_label
        ),
        format!(
            "{}: {}{} • {} {}",
            tr_("Mục", "Entries", "条目", "Записи"),
            shown.join(", "),
            if extra > 0 {
                format!(" +{extra}")
            } else {
                String::new()
            },
            tr_("Khóa", "Key", "键", "Ключ"),
            key
        ),
        tr_(
            "Xác minh từng mục — xóa mục không rõ nguồn trong Registry/Task Manager.",
            "Verify each entry — remove unknown ones via Registry/Task Manager.",
            "逐项核实 — 在注册表/任务管理器中删除不明条目。",
            "Проверьте каждую запись — удалите неизвестные.",
        )
        .to_string(),
    ));
}

#[cfg(windows)]
fn audit_run_keys(findings: &mut Vec<VulnFinding>) {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let hkcu =
        crate::modules::security::vulnscan::registry::enum_value_names(HKEY_CURRENT_USER, RUN_KEY);
    let hklm =
        crate::modules::security::vulnscan::registry::enum_value_names(HKEY_LOCAL_MACHINE, RUN_KEY);
    add_run_key_findings(findings, "HKCU", hkcu, RUN_KEY);
    add_run_key_findings(findings, "HKLM", hklm, RUN_KEY);
    let hkcu_once = crate::modules::security::vulnscan::registry::enum_value_names(
        HKEY_CURRENT_USER,
        RUNONCE_KEY,
    );
    let hklm_once = crate::modules::security::vulnscan::registry::enum_value_names(
        HKEY_LOCAL_MACHINE,
        RUNONCE_KEY,
    );
    let total_once = hkcu_once.len() + hklm_once.len();
    if total_once > 0 {
        findings.push(dynamic_finding(
            "PERSISTENCE_RUNONCE",
            "MEDIUM",
            format!(
                "{} {}",
                tr_(
                    "RunOnce có",
                    "RunOnce has",
                    "RunOnce 有",
                    "RunOnce содержит"
                ),
                total_once
            ),
            tr_(
                "RunOnce chạy một lần ngay khi đăng nhập — chỗ ẩn phổ biến của loader.",
                "RunOnce executes once at logon — a common loader hiding spot.",
                "RunOnce 在登录时执行一次 — 常见加载器藏身处。",
                "RunOnce выполняется при входе — частое укрытие загрузчиков.",
            )
            .to_string(),
            tr_(
                "Rà soát và xóa mục lạ; đảm bảo phần mềm hợp lệ mới nằm ở đây.",
                "Review and remove unknown entries; only legitimate software should be here.",
                "检查并删除不明条目；此处只应存在合法软件。",
                "Проверьте и удалите неизвестные записи.",
            )
            .to_string(),
        ));
    }
}

#[cfg(not(windows))]
fn audit_run_keys(_findings: &mut Vec<VulnFinding>) {}

#[cfg(windows)]
fn audit_scheduled_tasks(findings: &mut Vec<VulnFinding>) {
    let output = crate::modules::system::dns_manager::silent_command("schtasks")
        .args(["/query", "/fo", "csv", "/nh"])
        .output();
    let Ok(out) = output else {
        return;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let count = text.lines().filter(|line| !line.trim().is_empty()).count();
    if count == 0 {
        return;
    }
    findings.push(dynamic_finding(
        "PERSISTENCE_TASKS",
        "LOW",
        format!(
            "{} {}",
            tr_("Số lượng lịch tác vụ", "Scheduled task count", "计划任务数量", "Количество задач"),
            count
        ),
        tr_(
            "Danh sách đầy đủ xem bằng: schtasks /query /fo LIST /v. Chú ý tác vụ chạy .exe từ thư mục tạm.",
            "Full list: schtasks /query /fo LIST /v. Watch for tasks running .exe from temp folders.",
            "完整列表：schtasks /query /fo LIST /v。注意从临时目录运行 exe 的任务。",
            "Полный список: schtasks /query /fo LIST /v. Обратите внимание на задачи из временных папок.",
        )
        .to_string(),
        tr_(
            "Rà soát tác vụ lạ không có mô tả, kích hoạt lúc nửa đêm hoặc trỏ tới %TEMP%/%APPDATA%.",
            "Review unknown tasks without description, midnight triggers or %TEMP%/%APPDATA% paths.",
            "检查无描述、午夜触发或指向 %TEMP%/%APPDATA% 的任务。",
            "Ищите задачи без описания, с ночным запуском или путями %TEMP%/%APPDATA%.",
        )
        .to_string(),
    ));
}

#[cfg(not(windows))]
fn audit_scheduled_tasks(_findings: &mut Vec<VulnFinding>) {}

#[cfg(windows)]
fn audit_suspicious_service_paths(findings: &mut Vec<VulnFinding>) {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    let keys = crate::modules::security::vulnscan::registry::enum_subkeys(
        HKEY_LOCAL_MACHINE,
        SERVICES_KEY,
    );
    let lowered_dirs = [
        "\\temp\\",
        "\\appdata\\",
        "\\programdata\\",
        "\\users\\public\\",
        "\\windows\\fonts\\",
    ];
    let mut suspicious: Vec<String> = Vec::new();
    for key in keys {
        let image_path_key = format!("{SERVICES_KEY}\\{key}");
        let Some(image_path) =
            crate::modules::security::vulnscan::registry::read_string(&image_path_key, "ImagePath")
        else {
            continue;
        };
        let lowered = image_path.to_lowercase();
        if lowered_dirs.iter().any(|dir| lowered.contains(dir)) {
            suspicious.push(format!("{key} → {image_path}"));
            if suspicious.len() >= MAX_LISTED_ITEMS {
                break;
            }
        }
    }
    if !suspicious.is_empty() {
        findings.push(dynamic_finding(
            "PERSISTENCE_SERVICE_PATH",
            "HIGH",
            format!(
                "{} {}",
                tr_("Dịch vụ chạy từ thư mục ghi được:", "Services running from writable folders:", "从可写目录运行的服务:", "Службы из записываемых папок:"),
                suspicious.len()
            ),
            suspicious.join(" • "),
            tr_(
                "Dịch vụ hợp lệ thường nằm trong Windows\\ hoặc Program Files. Kiểm tra kỹ từng đường dẫn trên.",
                "Legitimate services usually live in Windows\\ or Program Files. Verify each path above.",
                "合法服务通常位于 Windows\\ 或 Program Files。请逐条核实。",
                "Легитимные службы обычно в Windows\\ или Program Files. Проверьте пути.",
            )
            .to_string(),
        ));
    }
}

#[cfg(not(windows))]
fn audit_suspicious_service_paths(_findings: &mut Vec<VulnFinding>) {}

pub fn audit_event_log() -> Vec<VulnFinding> {
    let mut findings = Vec::new();
    let failed_logons = count_events("Security", 4625, 200);
    match failed_logons {
        Some(count) if count >= BRUTE_FORCE_EVENT_THRESHOLD => findings.push(dynamic_finding(
            "EVENT_BRUTE_FORCE",
            "HIGH",
            format!(
                "{} {}",
                tr_("Sự kiện đăng nhập thất bại gần nhất:", "Recent failed logon events (4625):", "最近的登录失败事件 (4625):", "Недавних неудачных входов (4625):"),
                count
            ),
            tr_(
                "Rất nhiều lần đăng nhập sai — dấu hiệu brute-force hoặc quên mật khẩu hàng loạt.",
                "Many failed logons — sign of brute-force or bulk forgotten passwords.",
                "大量登录失败 — 疑似暴力破解或批量忘记密码。",
                "Много неудачных входов — признак подбора пароля.",
            )
            .to_string(),
            tr_(
                "Kiểm tra Event Viewer → Security 4625 để xem máy nguồn; cân nhắc khóa tài khoản sau N lần sai.",
                "Check Event Viewer → Security 4625 for source machines; consider account lockout policy.",
                "在事件查看器 → 安全 4625 中查看来源机器；考虑账户锁定策略。",
                "Смотрите Event Viewer → Security 4625; настройте блокировку учётных записей.",
            )
            .to_string(),
        )),
        Some(_) => {}
        None => findings.push(dynamic_finding(
            "EVENT_LOG_UNAVAILABLE",
            "LOW",
            tr_(
                "Không đọc được Security log (cần chạy với quyền Administrator)",
                "Cannot read the Security log (Administrator required)",
                "无法读取安全日志（需要管理员权限）",
                "Журнал Security недоступен (нужны права администратора)",
            )
            .to_string(),
            tr_(
                "ShieldGhita cần quyền admin để truy vấn nhật ký bảo mật của Windows.",
                "ShieldGhita needs admin rights to query Windows security logs.",
                "ShieldGhita 需要管理员权限查询 Windows 安全日志。",
                "Для чтения журналов нужны права администратора.",
            )
            .to_string(),
            tr_(
                "Chạy lại ứng dụng với quyền Administrator.",
                "Re-run the application as Administrator.",
                "以管理员身份重新运行应用。",
                "Запустите приложение от имени администратора.",
            )
            .to_string(),
        )),
    }
    let new_services = count_events("System", 7045, 50);
    if let Some(count) = new_services {
        if count > 0 {
            findings.push(dynamic_finding(
                "EVENT_NEW_SERVICES",
                "MEDIUM",
                format!(
                    "{} {}",
                    tr_(
                        "Dịch vụ mới được cài gần đây (7045):",
                        "Recently installed services (7045):",
                        "最近安装的服务 (7045):",
                        "Недавно установленные службы (7045):"
                    ),
                    count
                ),
                tr_(
                    "Mỗi dịch vụ mới có thể là cài đặt hợp lệ hoặc cơ chế thường trú của mã độc.",
                    "Each new service may be legitimate or a malware persistence mechanism.",
                    "每个新服务可能是合法安装或恶意软件持久化机制。",
                    "Каждая новая служба может быть как легитимной, так и закреплением вредоноса.",
                )
                .to_string(),
                tr_(
                    "Đối chiếu từng 7045 với phần mềm bạn vừa cài trong Event Viewer → System.",
                    "Cross-check each 7045 against software you installed (Event Viewer → System).",
                    "在事件查看器 → 系统中逐条对照 7045 与刚安装的软件。",
                    "Сверьте 7045 с установленным ПО (Event Viewer → System).",
                )
                .to_string(),
            ));
        }
    }
    findings
}

fn count_events(log: &str, event_id: u32, limit: u32) -> Option<usize> {
    let query = format!("*[System[(EventID={event_id})]]");
    let output = crate::modules::system::dns_manager::silent_command("wevtutil")
        .args([
            "qe",
            log,
            &format!("/q:{query}"),
            &format!("/c:{limit}"),
            "/rd:true",
            "/f:xml",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let marker = format!("<EventID>{event_id}</EventID>");
    Some(text.matches(&marker).count())
}

pub fn audit_usb_history() -> Vec<VulnFinding> {
    let mut findings = Vec::new();
    #[cfg(windows)]
    {
        use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
        let keys = crate::modules::security::vulnscan::registry::enum_subkeys(
            HKEY_LOCAL_MACHINE,
            USBSTOR_KEY,
        );
        if !keys.is_empty() {
            let shown: Vec<String> = keys.iter().take(MAX_LISTED_ITEMS).cloned().collect();
            let extra = keys.len().saturating_sub(MAX_LISTED_ITEMS);
            findings.push(dynamic_finding(
                "USB_HISTORY",
                "MEDIUM",
                format!(
                    "{} {}",
                    tr_("Thiết bị USB đã từng cắm trên máy:", "USB devices previously attached:", "曾连接过的 USB 设备:", "Подключавшиеся USB-устройства:"),
                    keys.len()
                ),
                format!(
                    "{}{}",
                    shown.join(" • "),
                    if extra > 0 { format!(" +{extra}") } else { String::new() }
                ),
                tr_(
                    "Danh sách từ registry USBSTOR. Nếu có thiết bị lạ, coi như dữ liệu có thể đã bị sao chép.",
                    "From the USBSTOR registry. Unknown devices may mean data was copied.",
                    "来自 USBSTOR 注册表。若有陌生设备，数据可能已被复制。",
                    "Из реестра USBSTOR. Неизвестные устройства — возможна утечка данных.",
                )
                .to_string(),
            ));
        }
    }
    findings
}

pub fn self_hash_check() -> VulnFinding {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("shield_ghita.exe"));
    let Ok(content) = std::fs::read(&exe) else {
        return dynamic_finding(
            "SELF_HASH_ERROR",
            "MEDIUM",
            tr_(
                "Không kiểm tra được nguyên vẹn ứng dụng",
                "App integrity check unavailable",
                "无法检查应用完整性",
                "Проверка целостности недоступна",
            )
            .to_string(),
            tr_(
                "Không đọc được tệp thực thi để kiểm tra nguyên vẹn",
                "Could not read the executable for the integrity check",
                "无法读取可执行文件进行完整性检查",
                "Не удалось прочитать исполняемый файл для проверки целостности",
            )
            .to_string(),
            tr_(
                "Antivirus hoặc quyền hạn có thể đang khóa tệp — thử lại sau.",
                "An antivirus or permissions may be locking the file — retry later.",
                "Antivirus 或权限可能正在锁定文件 — 请稍后重试。",
                "Возможно, файл заблокирован — повторите позже.",
            )
            .to_string(),
        );
    };
    let digest: String = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&content);
        format!("{:x}", hasher.finalize())
    };
    let store = crate::modules::paths::data_dir()
        .join("ShieldGhita")
        .join("self_hash.txt");
    match std::fs::read_to_string(&store) {
        Ok(stored) => {
            let stored = stored.trim().to_string();
            if stored == digest {
                dynamic_finding(
                    "SELF_HASH_OK",
                    "LOW",
                    tr_(
                        "Tệp thực thi của ShieldGhita nguyên vẹn",
                        "ShieldGhita executable integrity verified",
                        "ShieldGhita 可执行文件完整性正常",
                        "Целостность ShieldGhita подтверждена",
                    )
                    .to_string(),
                    tr_(
                        "SHA-256 khớp với lần kiểm tra trước.",
                        "SHA-256 matches the previous check.",
                        "SHA-256 与上次检查一致。",
                        "SHA-256 совпадает с прошлой проверкой.",
                    ),
                    tr_(
                        "Không cần hành động.",
                        "No action needed.",
                        "无需操作。",
                        "Действий не требуется.",
                    ),
                )
            } else {
                dynamic_finding(
                    "SELF_HASH_CHANGED",
                    "MEDIUM",
                    tr_(
                        "Tệp thực thi ShieldGhita đã THAY ĐỔI so với lần chạy trước",
                        "ShieldGhita executable CHANGED since the previous run",
                        "ShieldGhita 可执行文件与上次运行相比已更改",
                        "Исполняемый файл ShieldGhita ИЗМЕНИЛСЯ",
                    )
                    .to_string(),
                    format!(
                        "{}\n{} {stored}\n{} {digest}",
                        tr_(
                            "Có thể là bản cập nhật hợp lệ, hoặc tệp bị thay thế.",
                            "Could be a legitimate update, or the file was replaced.",
                            "可能是正常更新，或文件被替换。",
                            "Возможно обновление, либо файл подменён.",
                        ),
                        tr_("Cũ:", "Old:", "旧:", "Старый:"),
                        tr_("Mới:", "New:", "新:", "Новый:")
                    ),
                    tr_(
                        "Nếu bạn không cập nhật ShieldGhita, quét máy ngay và tải lại bản cài chính thức.",
                        "If you did not update ShieldGhita, scan the PC and reinstall from the official build.",
                        "若非您主动更新，请立即扫描并从官方渠道重新安装。",
                        "Если вы не обновляли — проверьте ПК и переустановите официально.",
                    )
                    .to_string(),
                )
            }
        }
        Err(_) => {
            let _ = std::fs::write(&store, &digest);
            dynamic_finding(
                "SELF_HASH_BASELINE",
                "LOW",
                tr_(
                    "Đã ghi mốc nguyên vẹn đầu tiên của ShieldGhita",
                    "Recorded the first integrity baseline of ShieldGhita",
                    "已记录 ShieldGhita 的首个完整性基线",
                    "Записана первая базовая целостность",
                )
                .to_string(),
                tr_(
                    "SHA-256 hiện tại được lưu để so sánh ở các lần chạy sau.",
                    "The current SHA-256 is stored for comparison on later runs.",
                    "当前 SHA-256 已保存，供以后比较。",
                    "Текущий SHA-256 сохранён для сравнения.",
                ),
                tr_(
                    "Không cần hành động.",
                    "No action needed.",
                    "无需操作。",
                    "Действий не требуется.",
                ),
            )
        }
    }
}

fn tr_(vi: &'static str, en: &'static str, zh: &'static str, ru: &'static str) -> String {
    crate::modules::i18n::tr4(vi, en, zh, ru).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_events_rejects_bad_query() {
        let _ = count_events("NoSuchLog", 99999, 1);
    }

    #[test]
    fn test_self_hash_check_returns_finding() {
        let result = self_hash_check();
        assert!(
            result.check_id == "SELF_HASH_OK"
                || result.check_id == "SELF_HASH_BASELINE"
                || result.check_id == "SELF_HASH_CHANGED"
        );
    }

    #[test]
    fn test_persistence_audit_does_not_panic() {
        let findings = audit_persistence();
        assert!(!findings.is_empty());
    }
}
