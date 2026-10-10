use crate::modules::i18n::tr4;
use chrono::Local;
use serde::{Deserialize, Serialize};

const UPDATE_STALE_DAYS: i64 = 90;
const MAX_AUTORUN_LIST: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    pub check_id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub recommendation: String,
}

fn severity_label(severity: &str) -> String {
    match severity {
        "CRITICAL" => tr4("NGHIÊM TRỌNG", "CRITICAL", "严重", "КРИТИЧНО").to_string(),
        "HIGH" => tr4("CAO", "HIGH", "高", "ВЫСОКИЙ").to_string(),
        "MEDIUM" => tr4("TRUNG BÌNH", "MEDIUM", "中", "СРЕДНИЙ").to_string(),
        "LOW" => tr4("THẤP", "LOW", "低", "НИЗКИЙ").to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn finding(
    check_id: &str,
    severity: &str,
    title_vi: (&'static str, &'static str, &'static str, &'static str),
    detail_vi: (&'static str, &'static str, &'static str, &'static str),
    rec_vi: (&'static str, &'static str, &'static str, &'static str),
) -> VulnFinding {
    VulnFinding {
        check_id: check_id.to_string(),
        severity: severity_label(severity),
        title: tr4(title_vi.0, title_vi.1, title_vi.2, title_vi.3).to_string(),
        detail: tr4(detail_vi.0, detail_vi.1, detail_vi.2, detail_vi.3).to_string(),
        recommendation: tr4(rec_vi.0, rec_vi.1, rec_vi.2, rec_vi.3).to_string(),
    }
}

pub(crate) fn dynamic_finding(
    check_id: &str,
    severity: &str,
    title: String,
    detail: String,
    recommendation: String,
) -> VulnFinding {
    VulnFinding {
        check_id: check_id.to_string(),
        severity: severity_label(severity),
        title,
        detail,
        recommendation,
    }
}

#[cfg(windows)]
pub(crate) mod registry {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
    };

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn open_key(root: HKEY, subkey: &str) -> Option<HKEY> {
        let mut key = HKEY::default();
        let status =
            unsafe { RegOpenKeyExW(root, PCWSTR(wide(subkey).as_ptr()), 0, KEY_READ, &mut key) };
        if status.is_err() {
            None
        } else {
            Some(key)
        }
    }

    pub fn read_dword(subkey: &str, value_name: &str) -> Option<u32> {
        for root in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
            let mut data: u32 = 0;
            let mut size = std::mem::size_of::<u32>() as u32;
            let name = wide(value_name);
            let status = unsafe {
                RegGetValueW(
                    root,
                    PCWSTR(wide(subkey).as_ptr()),
                    PCWSTR(name.as_ptr()),
                    RRF_RT_REG_DWORD,
                    None,
                    Some(&mut data as *mut u32 as *mut _),
                    Some(&mut size),
                )
            };
            if status.is_ok() && size == 4 {
                return Some(data);
            }
        }
        None
    }

    pub fn read_string(subkey: &str, value_name: &str) -> Option<String> {
        for root in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
            let mut buf = [0u16; 512];
            let mut size = (buf.len() * 2) as u32;
            let name = wide(value_name);
            let status = unsafe {
                RegGetValueW(
                    root,
                    PCWSTR(wide(subkey).as_ptr()),
                    PCWSTR(name.as_ptr()),
                    RRF_RT_REG_SZ,
                    None,
                    Some(buf.as_mut_ptr().cast()),
                    Some(&mut size),
                )
            };
            if status.is_ok() {
                let chars_len = (size as usize / 2).min(buf.len());
                let text = String::from_utf16_lossy(&buf[..chars_len]);
                return Some(text.trim_end_matches('\0').to_string());
            }
        }
        None
    }

    pub fn enum_value_names(root: HKEY, subkey: &str) -> Vec<String> {
        let mut names = Vec::new();
        let Some(key) = open_key(root, subkey) else {
            return names;
        };
        let mut index = 0u32;
        loop {
            let mut name_buf = [0u16; 256];
            let mut name_len = name_buf.len() as u32;
            let status = unsafe {
                RegEnumValueW(
                    key,
                    index,
                    PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if status.is_err() {
                break;
            }
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            names.push(name);
            index += 1;
            if index > 256 {
                break;
            }
        }
        unsafe {
            let _ = RegCloseKey(key);
        }
        names
    }

    #[allow(dead_code)]
    pub fn enum_subkeys(root: HKEY, subkey: &str) -> Vec<String> {
        use windows::Win32::System::Registry::RegEnumKeyExW;
        let mut names = Vec::new();
        let Some(key) = open_key(root, subkey) else {
            return names;
        };
        let mut index = 0u32;
        loop {
            let mut name_buf = [0u16; 256];
            let mut name_len = name_buf.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    key,
                    index,
                    windows::core::PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    windows::core::PWSTR::null(),
                    None,
                    None,
                )
            };
            if status.is_err() {
                break;
            }
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            names.push(name);
            index += 1;
            if index > 1024 {
                break;
            }
        }
        unsafe {
            let _ = RegCloseKey(key);
        }
        names
    }
}

const SMB1_KEY: &str = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
const RDP_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
const RDP_NLA_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
const UAC_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const FIREWALL_ROOT: &str =
    r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
const WU_RESULT_KEY: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install";
const LSA_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

pub fn audit_local() -> Vec<VulnFinding> {
    let mut findings = Vec::new();
    #[cfg(windows)]
    {
        audit_smbv1(&mut findings);
        audit_rdp(&mut findings);
        audit_uac(&mut findings);
        audit_firewall(&mut findings);
        audit_update_age(&mut findings);
        audit_autoruns(&mut findings);
        audit_lsa(&mut findings);
    }
    #[cfg(not(windows))]
    {
        findings.push(finding(
            "platform",
            "LOW",
            (
                "Kiểm toán chỉ hỗ trợ đầy đủ trên Windows",
                "Full audit is only supported on Windows",
                "完整审计仅支持 Windows",
                "Полный аудит доступен только в Windows",
            ),
            (
                "Máy này không phải Windows nên bỏ qua kiểm tra registry.",
                "This machine is not Windows; registry checks skipped.",
                "非 Windows 系统跳过注册表检查。",
                "Реестр не проверяется: система не Windows.",
            ),
            (
                "Chạy ShieldGhita trên Windows để kiểm toán đầy đủ.",
                "Run ShieldGhita on Windows for the full audit.",
                "在 Windows 上运行以进行完整审计。",
                "Запустите ShieldGhita в Windows для полного аудита.",
            ),
        ));
    }
    findings
}

#[cfg(windows)]
fn audit_smbv1(findings: &mut Vec<VulnFinding>) {
    let Some(smb1) = registry::read_dword(SMB1_KEY, "SMB1") else {
        return;
    };
    if smb1 == 1 {
        findings.push(finding(
            "SMB1_ENABLED",
            "HIGH",
            (
                "SMBv1 vẫn đang được bật",
                "SMBv1 is still enabled",
                "SMBv1 仍然启用",
                "SMBv1 всё ещё включён",
            ),
            (
                "SMBv1 là giao thức cũ chứa lỗ hổng ransomware nổi tiếng (EternalBlue) và không nên bật.",
                "SMBv1 is a legacy protocol tied to infamous ransomware holes (EternalBlue) and should not be enabled.",
                "SMBv1 是与著名勒索漏洞（EternalBlue）相关的旧协议，不应启用。",
                "SMBv1 — устаревший протокол со знаменитыми уязвимостями (EternalBlue), его не следует включать.",
            ),
            (
                "Tắt SMBv1 trong Windows Features hoặc qua DISM, sau đó khởi động lại.",
                "Disable SMBv1 via Windows Features or DISM, then reboot.",
                "通过 Windows 功能或 DISM 禁用 SMBv1，然后重启。",
                "Отключите SMBv1 через компоненты Windows или DISM и перезагрузитесь.",
            ),
        ));
    }
}

#[cfg(windows)]
fn audit_rdp(findings: &mut Vec<VulnFinding>) {
    let Some(deny) = registry::read_dword(RDP_KEY, "fDenyTSConnections") else {
        return;
    };
    if deny == 0 {
        let nla = registry::read_dword(RDP_NLA_KEY, "UserAuthentication");
        match nla {
            Some(0) => findings.push(finding(
                "RDP_NO_NLA",
                "HIGH",
                (
                    "RDP bật nhưng KHÔNG yêu cầu xác thực mạng (NLA)",
                    "RDP enabled WITHOUT Network Level Authentication (NLA)",
                    "RDP 启用但未要求网络级身份验证（NLA）",
                    "RDP включён БЕЗ сетевой аутентификации (NLA)",
                ),
                (
                    "RDP không NLA dễ bị dò mật khẩu và các lỗ hổng pre-auth.",
                    "RDP without NLA is exposed to password guessing and pre-auth holes.",
                    "未启用 NLA 的 RDP 易受密码猜解和预认证漏洞攻击。",
                    "RDP без NLA уязвим к подбору пароля и pre-auth уязвимостям.",
                ),
                (
                    "Bật NLA: System Properties → Remote → 'Allow connections only from computers running Remote Desktop with NLA'.",
                    "Enable NLA: System Properties → Remote → 'Allow connections only from computers running Remote Desktop with NLA'.",
                    "启用 NLA：系统属性 → 远程 → 仅允许支持 NLA 的连接。",
                    "Включите NLA: Свойства системы → Удалённый доступ → только с NLA.",
                ),
            )),
            _ => findings.push(finding(
                "RDP_ENABLED",
                "MEDIUM",
                (
                    "Remote Desktop (RDP) đang bật",
                    "Remote Desktop (RDP) is enabled",
                    "远程桌面（RDP）已启用",
                    "Удалённый рабочий стол (RDP) включён",
                ),
                (
                    "RDP mở bề mặt tấn công dò mật khẩu, đặc biệt khi máy tiếp xúc Internet.",
                    "RDP widens the password-guessing attack surface, especially on Internet-facing machines.",
                    "RDP 扩大了密码猜解攻击面，尤其是连接互联网的机器。",
                    "RDP расширяет поверхность атаки, особенно для машин в Интернете.",
                ),
                (
                    "Nếu không dùng, tắt RDP; nếu dùng, giới hạn theo IP trên firewall + mật khẩu mạnh.",
                    "If unused, disable RDP; otherwise restrict by firewall IP rules + a strong password.",
                    "不使用请关闭 RDP；使用请用防火墙限制 IP + 强密码。",
                    "Если не используется — отключите; иначе ограничьте по IP и поставьте сильный пароль.",
                ),
            )),
        }
    }
}

#[cfg(windows)]
fn audit_uac(findings: &mut Vec<VulnFinding>) {
    let Some(enable_lua) = registry::read_dword(UAC_KEY, "EnableLUA") else {
        return;
    };
    if enable_lua == 0 {
        findings.push(finding(
            "UAC_DISABLED",
            "CRITICAL",
            (
                "User Account Control (UAC) đang TẮT",
                "User Account Control (UAC) is DISABLED",
                "用户账户控制（UAC）已关闭",
                "Контроль учётных записей (UAC) ОТКЛЮЧЁН",
            ),
            (
                "Tắt UAC cho phép mã độc âm thầm leo thang đặc quyền mà không hỏi người dùng.",
                "Disabling UAC lets malware silently escalate privileges without asking.",
                "关闭 UAC 后恶意软件可静默提权。",
                "Отключение UAC позволяет вредоносам тихо повышать привилегии.",
            ),
            (
                "Bật lại UAC trong Control Panel → User Accounts → Change User Account Control settings.",
                "Re-enable UAC in Control Panel → User Accounts → Change User Account Control settings.",
                "在控制面板 → 用户账户中重新开启 UAC。",
                "Включите UAC: Панель управления → Учётные записи.",
            ),
        ));
    }
}

#[cfg(windows)]
fn audit_firewall(findings: &mut Vec<VulnFinding>) {
    let profiles = [
        (
            "DomainProfile",
            tr4("Domain", "Domain", "域", "Домен").to_string(),
        ),
        (
            "StandardProfile",
            tr4("Private", "Private", "专用", "Частный").to_string(),
        ),
        (
            "PublicProfile",
            tr4("Public", "Public", "公用", "Общий").to_string(),
        ),
    ];
    let mut disabled: Vec<String> = Vec::new();
    for (sub, label) in profiles {
        let key = format!("{FIREWALL_ROOT}\\{sub}");
        if registry::read_dword(&key, "EnableFirewall") == Some(0) {
            disabled.push(label);
        }
    }
    if !disabled.is_empty() {
        findings.push(dynamic_finding(
            "FIREWALL_OFF",
            "HIGH",
            tr4(
                "Tường lửa Windows đang TẮT ở một số cấu hình mạng",
                "Windows Firewall is OFF for some network profiles",
                "Windows 防火墙在部分网络配置下已关闭",
                "Брандмауэр Windows выключен в некоторых профилях",
            )
            .to_string(),
            format!(
                "{}: {}",
                tr4(
                    "Các cấu hình đang tắt",
                    "Profiles disabled",
                    "已关闭的配置",
                    "Отключённые профили"
                ),
                disabled.join(", ")
            ),
            tr4(
                "Bật lại Windows Defender Firewall cho mọi cấu hình mạng.",
                "Re-enable Windows Defender Firewall for every network profile.",
                "为所有网络配置重新开启 Windows 防火墙。",
                "Включите брандмауэр для всех профилей сети.",
            )
            .to_string(),
        ));
    }
}

#[cfg(windows)]
fn audit_update_age(findings: &mut Vec<VulnFinding>) {
    let Some(last) = registry::read_string(WU_RESULT_KEY, "LastSuccessTime") else {
        return;
    };
    let Ok(last_dt) = chrono::NaiveDateTime::parse_from_str(&last, "%Y-%m-%d %H:%M:%S") else {
        return;
    };
    let days = (Local::now().naive_local() - last_dt).num_days();
    if days > UPDATE_STALE_DAYS {
        let ago = format!(
            "{} ({} {})",
            tr4("đã", "ago", "前", "назад"),
            days,
            tr4("ngày", "days", "天", "дн.")
        );
        let detail = format!(
            "{} {} {}",
            tr4(
                "Lần vá thành công cuối:",
                "Last successful update:",
                "上次成功更新:",
                "Последнее обновление:"
            ),
            last,
            ago
        );
        findings.push(dynamic_finding(
            "UPDATE_STALE",
            "MEDIUM",
            tr4(
                "Windows Update đã lâu không cài bản vá",
                "Windows updates are long overdue",
                "Windows 长期未安装更新",
                "Обновления Windows давно не устанавливались",
            )
            .to_string(),
            detail,
            tr4(
                "Chạy Windows Update và cài mọi bản vá bảo mật còn thiếu.",
                "Run Windows Update and install all pending security patches.",
                "运行 Windows Update 并安装所有待安装安全补丁。",
                "Запустите Windows Update и установите обновления безопасности.",
            )
            .to_string(),
        ));
    }
}

#[cfg(windows)]
fn audit_autoruns(findings: &mut Vec<VulnFinding>) {
    let names = registry::enum_value_names(
        windows::Win32::System::Registry::HKEY_LOCAL_MACHINE,
        RUN_KEY,
    );
    if names.is_empty() {
        return;
    }
    let shown: Vec<String> = names.iter().take(MAX_AUTORUN_LIST).cloned().collect();
    let extra = names.len().saturating_sub(MAX_AUTORUN_LIST);
    findings.push(dynamic_finding(
        "AUTORUNS_REVIEW",
        "MEDIUM",
        format!(
            "{} {}",
            tr4(
                "Danh sách tự khởi động có",
                "Startup list has",
                "启动项有",
                "Автозапуск содержит"
            ),
            names.len()
        ),
        format!(
            "{}: {}{}",
            tr4("Các mục", "Entries", "条目", "Записи"),
            shown.join(", "),
            if extra > 0 {
                format!(" +{}", extra)
            } else {
                String::new()
            }
        ),
        tr4(
            "Rà soát từng mục tự khởi động; xóa mục lạ không rõ nguồn (Task Manager → Startup).",
            "Review each startup entry; remove unknown items (Task Manager → Startup).",
            "逐项检查启动项；删除来源不明的项（任务管理器 → 启动）。",
            "Проверьте записи автозапуска; удалите неизвестные (Диспетчер задач → Автозагрузка).",
        )
        .to_string(),
    ));
}

#[cfg(windows)]
fn audit_lsa(findings: &mut Vec<VulnFinding>) {
    let run_as_ppl = registry::read_dword(LSA_KEY, "RunAsPPL");
    if run_as_ppl != Some(1) {
        findings.push(finding(
            "LSA_NO_PPL",
            "LOW",
            (
                "LSA chưa chạy ở chế độ bảo vệ (PPL)",
                "LSA is not running in protection mode (PPL)",
                "LSA 未以保护模式（PPL）运行",
                "LSA не работает в защищённом режиме (PPL)",
            ),
            (
                "Không bật PPL, mật khẩu Windows dễ bị trích xuất từ bộ nhớ bởi công cụdump credential.",
                "Without PPL, Windows credentials are easier to dump from memory.",
                "未启用 PPL 时，Windows 凭据更容易从内存中被提取。",
                "Без PPL пароли Windows легче извлечь из памяти.",
            ),
            (
                "Bật 'LSA Protection' theo hướng dẫn Microsoft (registry RunAsPPL=1 + khởi động lại).",
                "Enable 'LSA Protection' per Microsoft guidance (RunAsPPL=1 + reboot).",
                "按照微软指南启用 LSA 保护（RunAsPPL=1 + 重启）。",
                "Включите защиту LSA по документации Microsoft (RunAsPPL=1).",
            ),
        ));
    }
    let limit_blank = registry::read_dword(LSA_KEY, "limitblankpassworduse");
    if limit_blank == Some(0) {
        findings.push(finding(
            "BLANK_PASSWORD_REMOTE",
            "HIGH",
            (
                "Cho phép đăng nhập mạng không cần mật khẩu (blank password)",
                "Network logon with blank passwords is allowed",
                "允许空密码网络登录",
                "Разрешён сетевой вход с пустым паролем",
            ),
            (
                "Tài khoản không mật khẩu vẫn có thể đăng nhập qua mạng — cực nguy hiểm trong LAN.",
                "Accounts without a password can log on over the network — very dangerous in a LAN.",
                "无密码账户可通过网络登录 — 在局域网中极其危险。",
                "Учётные записи без пароля могут входить по сети — очень опасно в LAN.",
            ),
            (
                "Đặt mật khẩu cho mọi tài khoản; bật chính sách 'Accounts: Limit local account use of blank passwords'.",
                "Set a password on every account; enable 'Accounts: Limit local account use of blank passwords'.",
                "为所有账户设置密码；启用“限制空密码本地账户网络登录”。",
                "Задайте пароли всем учётным записям; включите политику ограничения пустых паролей.",
            ),
        ));
    }
}

pub async fn audit_lan_device(ip: std::net::IpAddr) -> Vec<VulnFinding> {
    let mut findings = Vec::new();
    let ports = crate::modules::monitor::port_scanner::scan_open_ports(ip).await;
    for port in ports {
        match port.port {
            23 => findings.push(dynamic_finding(
                "LAN_TELNET",
                "CRITICAL",
                format!("{} {}", tr4("Telnet mở trên", "Telnet open on", "Telnet 开放于", "Telnet открыт на"), ip),
                tr4(
                    "Telnet truyền mọi thứ (kể cả mật khẩu) dưới dạng văn bản thuần qua mạng.",
                    "Telnet transmits everything (including passwords) in cleartext.",
                    "Telnet 以明文传输所有内容（包括密码）。",
                    "Telnet передаёт всё (включая пароли) открытым текстом.",
                )
                .to_string(),
                tr4(
                    "Tắt Telnet trên thiết bị; dùng SSH thay thế.",
                    "Disable Telnet on the device; use SSH instead.",
                    "在设备上禁用 Telnet；改用 SSH。",
                    "Отключите Telnet на устройстве; используйте SSH.",
                )
                .to_string(),
            )),
            554 | 8554 => findings.push(dynamic_finding(
                "LAN_RTSP_EXPOSED",
                "MEDIUM",
                format!("{} {}", tr4("RTSP mở trên", "RTSP open on", "RTSP 开放于", "RTSP открыт на"), ip),
                tr4(
                    "Luồng RTSP thường dùng mật khẩu mặc định của hãng — nên đổi ngay và tắt khi không dùng.",
                    "RTSP streams often use vendor default passwords — change them now and disable when unused.",
                    "RTSP 常使用厂商默认密码 — 应立即更改并在不使用时关闭。",
                    "RTSP часто использует заводские пароли — смените их и отключите при неиспользовании.",
                )
                .to_string(),
                tr4(
                    "Đổi mật khẩu camera/NVR; bật ONVIF với mật khẩu riêng nếu cần xem từ xa.",
                    "Change the camera/NVR password; enable ONVIF with its own password if remote view is needed.",
                    "更改摄像头/NVR 密码；如需远程查看请启用带独立密码的 ONVIF。",
                    "Смените пароль камеры/NVR; включите ONVIF с отдельным паролем.",
                )
                .to_string(),
            )),
            3389 => findings.push(dynamic_finding(
                "LAN_RDP_EXPOSED",
                "MEDIUM",
                format!("{} {}", tr4("RDP mở trên", "RDP open on", "RDP 开放于", "RDP открыт на"), ip),
                tr4(
                    "RDP mở trong LAN vẫn là mục tiêu dò mật khẩu nếu máy nhiễm mã độc nội bộ.",
                    "RDP exposed on the LAN is still a password-guessing target if an internal machine is infected.",
                    "如果内网机器被感染，LAN 中的 RDP 仍是密码猜解目标。",
                    "Открытый в LAN RDP остаётся целью подбора пароля при заражении внутренней машины.",
                )
                .to_string(),
                tr4(
                    "Tắt RDP nếu không cần; bật NLA và giới hạn IP truy cập.",
                    "Disable RDP if unused; enable NLA and restrict access by IP.",
                    "不需要请关闭 RDP；启用 NLA 并限制访问 IP。",
                    "Отключите RDP при неиспользовании; включите NLA и ограничьте IP.",
                )
                .to_string(),
            )),
            445 => findings.push(dynamic_finding(
                "LAN_SMB_EXPOSED",
                "LOW",
                format!("{} {}", tr4("SMB (445) mở trên", "SMB (445) open on", "SMB (445) 开放于", "SMB (445) открыт на"), ip),
                tr4(
                    "Chia sẻ SMB cần mật khẩu mạnh + tắt chia sẻ ẩn danh; là cổng ransomware hay khai thác nhất.",
                    "SMB shares need strong passwords and no anonymous access; it is the port ransomware abuses most.",
                    "SMB 共享需强密码并禁用匿名访问；这是勒索软件最常利用的端口。",
                    "Общим SMB-ресурсам нужны сильные пароли; это самый эксплуатируемый шифровальщиками порт.",
                )
                .to_string(),
                tr4(
                    "Rà lại danh sách chia sẻ, tắt SMBv1, hạn chế theo nhóm máy được phép.",
                    "Audit shares, disable SMBv1, restrict access to allowed hosts only.",
                    "检查共享列表，禁用 SMBv1，仅允许指定主机访问。",
                    "Проверьте ресурсы, отключите SMBv1, ограничьте доступ по хостам.",
                )
                .to_string(),
            )),
            _ => {}
        }
    }
    if findings.is_empty() {
        findings.push(dynamic_finding(
            "LAN_CLEAN",
            "LOW",
            format!("{} {}", tr4("Không phát hiện cổng rủi ro trên", "No risky ports detected on", "未发现风险端口：", "Рискованных портов не найдено на"), ip),
            tr4(
                "Trong số các cổng phổ biến được quét, không có cổng Telnet/RDP/RTSP/SMB đáng ngại.",
                "Among scanned common ports, no concerning Telnet/RDP/RTSP/SMB was found.",
                "在扫描的常见端口中，未发现令人担忧的 Telnet/RDP/RTSP/SMB。",
                "Среди проверенных портов проблемных Telnet/RDP/RTSP/SMB не найдено.",
            )
            .to_string(),
            tr4(
                "Vẫn nên quét lại định kỳ sau khi thay đổi cấu hình thiết bị.",
                "Still rescan periodically after changing device configuration.",
                "更改设备配置后仍应定期重新扫描。",
                "Перепроверяйте периодически после изменений конфигурации.",
            )
            .to_string(),
        ));
    }
    findings
}

pub fn export_findings_csv(findings: &[VulnFinding]) -> Result<String, String> {
    fn csv_escape(field: &str) -> String {
        let mut s = field.replace('"', "\"\"");
        let risky = field
            .chars()
            .next()
            .map(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r'))
            .unwrap_or(false);
        if risky {
            s = format!("'{s}");
        }
        format!("\"{s}\"")
    }
    let mut csv = String::from("severity,check_id,title,detail,recommendation\n");
    for f in findings {
        csv.push_str(&format!(
            "{},{},{},{},{}\n",
            csv_escape(&f.severity),
            csv_escape(&f.check_id),
            csv_escape(&f.title),
            csv_escape(&f.detail),
            csv_escape(&f.recommendation),
        ));
    }
    let app_data = crate::modules::paths::data_base();
    let path = std::path::PathBuf::from(app_data)
        .join("ShieldGhita")
        .join(format!(
            "vuln_audit_{}.csv",
            Local::now().format("%Y%m%d_%H%M%S")
        ));
    std::fs::write(&path, &csv).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_label_marks_all_levels() {
        for (raw, localized) in [
            ("CRITICAL", severity_label("CRITICAL")),
            ("HIGH", severity_label("HIGH")),
            ("MEDIUM", severity_label("MEDIUM")),
            ("LOW", severity_label("LOW")),
        ] {
            assert!(!localized.is_empty(), "empty label for {raw}");
        }
        assert_eq!(severity_label("CUSTOM"), "CUSTOM");
    }

    #[test]
    fn test_export_findings_csv_writes_rows() {
        let findings = vec![finding(
            "TEST_CHECK",
            "HIGH",
            ("Tiêu đề", "Title", "标题", "Заголовок"),
            ("Chi tiết", "Detail", "详情", "Детали"),
            ("Khuyến nghị", "Recommendation", "建议", "Рекомендация"),
        )];
        let path = export_findings_csv(&findings).expect("export must succeed");
        let content = std::fs::read_to_string(&path).expect("csv must be readable");
        assert!(content.contains("TEST_CHECK"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_language_constants_are_distinct() {
        use crate::modules::i18n::{EN, RU, VI, ZH};
        assert_ne!(VI, EN);
        assert_ne!(EN, ZH);
        assert_ne!(ZH, RU);
    }
}
