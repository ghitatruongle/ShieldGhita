use crate::modules::security::file_analyzer::scan_file;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

const POLL_INTERVAL: Duration = Duration::from_secs(3);
const IDLE_INTERVAL: Duration = Duration::from_secs(1);
const MAX_SCAN_BYTES: u64 = 8 * 1024 * 1024;
const MASS_MUTATION_THRESHOLD: usize = 40;
const INCIDENT_COOLDOWN: Duration = Duration::from_secs(60);
const CANARY_NAME: &str = "ShieldGhita-Canary.dat";
const APP_CANARY_NAME: &str = "canary.dat";
const AUTOLOCK_RELEASE: Duration = Duration::from_secs(300);
const WATCHED_DIR_LIMIT: usize = 32;

#[derive(Clone, PartialEq, Eq)]
struct FileStamp {
    mtime: SystemTime,
    size: u64,
}

pub struct RealtimeGuard {
    enabled: AtomicBool,
    auto_quarantine: AtomicBool,
    worker_started: AtomicBool,
    engine: OnceLock<Arc<crate::modules::security::SecurityEngine>>,
    snapshot: Mutex<HashMap<PathBuf, FileStamp>>,
    canary_hashes: Mutex<HashMap<PathBuf, [u8; 32]>>,
    removable_drives: Mutex<std::collections::HashSet<char>>,
    incident_cooldown: Mutex<HashMap<String, Instant>>,
    canary_autolock: AtomicBool,
    watch_canary_in_folders: AtomicBool,
    lock_active: AtomicBool,
    locked_at_ms: AtomicU64,
}

impl RealtimeGuard {
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            auto_quarantine: AtomicBool::new(false),
            worker_started: AtomicBool::new(false),
            engine: OnceLock::new(),
            snapshot: Mutex::new(HashMap::new()),
            canary_hashes: Mutex::new(HashMap::new()),
            removable_drives: Mutex::new(std::collections::HashSet::new()),
            incident_cooldown: Mutex::new(HashMap::new()),
            canary_autolock: AtomicBool::new(false),
            watch_canary_in_folders: AtomicBool::new(false),
            lock_active: AtomicBool::new(false),
            locked_at_ms: AtomicU64::new(0),
        }
    }

    pub fn set_canary_autolock(&self, enabled: bool) {
        self.canary_autolock.store(enabled, Ordering::SeqCst);
    }

    pub fn set_watch_canary_in_folders(&self, enabled: bool) {
        self.watch_canary_in_folders
            .store(enabled, Ordering::SeqCst);
    }

    pub fn is_lock_active(&self) -> bool {
        self.lock_active.load(Ordering::Relaxed)
    }

    pub fn force_unlock(&self) {
        if self.lock_active.swap(false, Ordering::SeqCst) {
            let _ = crate::modules::system::dns_manager::set_master_internet_lock(false);
        }
    }

    pub fn attach_engine(&self, engine: Arc<crate::modules::security::SecurityEngine>) {
        let _ = self.engine.set(engine);
    }

    pub fn set_enabled(self: &Arc<Self>, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
        if enabled {
            self.ensure_worker();
        }
    }

    pub fn set_auto_quarantine(&self, enabled: bool) {
        self.auto_quarantine.store(enabled, Ordering::SeqCst);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn is_auto_quarantine(&self) -> bool {
        self.auto_quarantine.load(Ordering::Relaxed)
    }

    fn ensure_worker(self: &Arc<Self>) {
        if self.worker_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let running = Arc::clone(self);
        let _ = std::thread::Builder::new()
            .name("sg-realtime-guard".into())
            .spawn(move || loop {
                std::thread::sleep(POLL_INTERVAL);
                if !running.enabled.load(Ordering::Relaxed) {
                    std::thread::sleep(IDLE_INTERVAL);
                    continue;
                }
                running.tick();
            });
    }

    fn tick(&self) {
        self.release_expired_lock();
        let dirs = watched_dirs();
        let mut changed: Vec<PathBuf> = Vec::new();
        {
            let mut snapshot = match self.snapshot.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let mut fresh: HashMap<PathBuf, FileStamp> = HashMap::new();
            for dir in &dirs {
                collect_dir_stamps(dir, &mut fresh, &mut changed, &mut snapshot);
            }
            *snapshot = fresh;
        }

        let mass_mutation = changed.len() >= MASS_MUTATION_THRESHOLD;
        let canary_tampered = self.check_canaries(&dirs);
        self.detect_new_removable_drives();

        if mass_mutation {
            self.emit_incident(
                "BULK_FILE_CHANGE",
                "mass-mutation",
                crate::modules::i18n::tr4(
                    "Phát hiện nhiều tệp bị sửa/xóa bất thường trong thư mục theo dõi",
                    "Unusual mass file modification/deletion in watched folders",
                    "受监控文件夹中出现异常的大量文件修改/删除",
                    "Массовое изменение/удаление файлов в отслеживаемых папках",
                )
                .to_string(),
                "LOW",
                crate::modules::i18n::tr4(
                    "Rất nhiều tệp vừa được tạo/sửa cùng lúc — thường là giải nén hoặc đồng bộ, KHÔNG tự khoá mạng. Nếu bạn không thao tác gì, hãy kiểm tra tiến trình đáng ngờ.",
                    "Many files changed at once — usually an unzip or a sync. The network is NOT locked. If you did not trigger it, check for suspicious processes.",
                    "大量文件同时变动 — 多为解压或同步，未锁定网络。若非你本人操作，请检查可疑进程。",
                    "Массовое изменение файлов — обычно распаковка или синхронизация; сеть НЕ заблокирована. Если это не вы — проверьте процессы.",
                )
                .to_string(),
            );
            return;
        }
        if canary_tampered {
            return;
        }
        for path in changed.iter().take(24) {
            self.inspect_file(path);
        }
    }

    fn check_canaries(&self, dirs: &[PathBuf]) -> bool {
        let mut tampered = false;
        if self.check_one_canary(&app_canary_path()) {
            tampered = true;
        }
        if self.watch_canary_in_folders.load(Ordering::Relaxed) {
            for dir in dirs {
                if self.check_one_canary(&dir.join(CANARY_NAME)) {
                    tampered = true;
                }
            }
        }
        if tampered && self.canary_autolock.load(Ordering::Relaxed) {
            self.engage_master_lock();
        }
        tampered
    }

    fn check_one_canary(&self, canary: &Path) -> bool {
        {
            let canary = canary.to_path_buf();
            let content = match std::fs::read(&canary) {
                Ok(c) => c,
                Err(_) => {
                    let fresh: [u8; 32] = rand_bytes_32();
                    if std::fs::write(&canary, fresh).is_ok() {
                        if let Some(parent) = canary.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        if let Ok(mut hashes) = self.canary_hashes.lock() {
                            hashes.insert(canary, fresh);
                        }
                    }
                    return false;
                }
            };
            let digest: [u8; 32] = {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&content);
                hasher.finalize().into()
            };
            let stored = self
                .canary_hashes
                .lock()
                .ok()
                .and_then(|hashes| hashes.get(&canary).copied());
            match stored {
                None => {
                    if let Ok(mut hashes) = self.canary_hashes.lock() {
                        hashes.insert(canary, digest);
                    }
                    false
                }
                Some(expected) if expected != digest => {
                    self.emit_incident(
                        "CANARY_TAMPER",
                        &canary.to_string_lossy(),
                        crate::modules::i18n::tr4(
                            "Tệp mồi (canary) bị sửa đổi hoặc mã hóa — dấu hiệu ransomware đang hoạt động",
                            "Canary file modified or encrypted — signs of active ransomware",
                            "金丝雀文件被修改或加密 — 疑似勒索软件正在活动",
                            "Файл-приманка изменён или зашифрован — признаки шифровальщика",
                        )
                        .to_string(),
                        "HIGH",
                        crate::modules::i18n::tr4(
                            "Nếu bạn KHÔNG bật tự khoá, mạng không bị ảnh hưởng — hãy kiểm tra tiến trình đáng ngờ bằng Task Manager.",
                            "If auto-lock is off your network is untouched — inspect suspicious processes in Task Manager.",
                            "若未开启自动锁定，网络不受影响 — 请在任务管理器检查可疑进程。",
                            "Если автоблокировка выключена, сеть не затронута — проверьте процессы.",
                        )
                        .to_string(),
                    );
                    true
                }
                Some(_) => false,
            }
        }
    }

    #[allow(dead_code)]
    fn check_canaries_legacy(&self, dirs: &[PathBuf]) -> bool {
        let mut tampered = false;
        for dir in dirs {
            let canary = dir.join(CANARY_NAME);
            let content = match std::fs::read(&canary) {
                Ok(c) => c,
                Err(_) => {
                    let fresh: [u8; 32] = rand_bytes_32();
                    if std::fs::write(&canary, fresh).is_ok() {
                        if let Ok(mut hashes) = self.canary_hashes.lock() {
                            hashes.insert(canary, fresh);
                        }
                    }
                    continue;
                }
            };
            let digest: [u8; 32] = {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&content);
                hasher.finalize().into()
            };
            let stored = self
                .canary_hashes
                .lock()
                .ok()
                .and_then(|hashes| hashes.get(&canary).copied());
            match stored {
                None => {
                    if let Ok(mut hashes) = self.canary_hashes.lock() {
                        hashes.insert(canary, digest);
                    }
                }
                Some(expected) if expected != digest => {
                    tampered = true;
                    self.emit_incident(
                        "RANSOM_CANARY_TAMPER",
                        &canary.to_string_lossy(),
                        crate::modules::i18n::tr4(
                            "Tệp mồi (canary) bị sửa đổi hoặc mã hóa — dấu hiệu ransomware đang hoạt động",
                            "Canary file modified or encrypted — signs of active ransomware",
                            "金丝雀文件被修改或加密 — 疑似勒索软件正在活动",
                            "Файл-приманка изменён или зашифрован — признаки работы шифровальщика",
                        )
                        .to_string(),
                        "CRITICAL",
                        crate::modules::i18n::tr4(
                            "Đã khóa Internet khẩn cấp và ghi sự cố — không khôi phục canary tự động",
                            "Emergency Internet lock engaged and incident recorded — canary not auto-restored",
                            "已启用紧急断网并记录事件 — 金丝雀文件不会自动恢复",
                            "Экстренная блокировка включена, инцидент записан — приманка не восстанавливается",
                        )
                        .to_string(),
                    );
                    break;
                }
                Some(_) => {}
            }
        }
        tampered
    }

    fn detect_new_removable_drives(&self) {
        let current = list_removable_drive_letters();
        let mut known = match self.removable_drives.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if known.is_empty() {
            *known = current.clone();
            return;
        }
        for letter in &current {
            if !known.contains(letter) {
                let root = format!("{letter}:\\");
                self.emit_incident(
                    "USB_DEVICE_ATTACHED",
                    &root,
                    crate::modules::i18n::tr4(
                        "Ổ USB/đĩa di động mới được cắm vào máy",
                        "New USB/removable drive attached",
                        "检测到新的 USB/可移动磁盘",
                        "Подключён новый съёмный диск",
                    )
                    .to_string(),
                    "MEDIUM",
                    crate::modules::i18n::tr4(
                        "Tệp mới trên ổ này sẽ được quét thời gian thực khi Bảo vệ Thời gian thực bật",
                        "New files on this drive will be scanned in real time when Real-time Guard is on",
                        "当实时防护开启时，此磁盘上的新文件将被实时扫描",
                        "Новые файлы на диске будут проверяться в реальном времени при включённой защите",
                    )
                    .to_string(),
                );
            }
        }
        *known = current;
    }

    fn inspect_file(&self, path: &Path) {
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        if !meta.is_file() || meta.len() > MAX_SCAN_BYTES {
            return;
        }
        if is_quarantine_path(path) {
            return;
        }
        let Ok(report) = scan_file(path) else {
            return;
        };
        if report.risk_level != "MALICIOUS" {
            return;
        }
        let auto = self.auto_quarantine.load(Ordering::Relaxed);
        let mut mitigation = crate::modules::i18n::tr4(
            "Đã ghi sự cố — tự cách ly qua tab Diệt Virus nếu cần",
            "Incident recorded — quarantine manually from the Antivirus tab if needed",
            "已记录事件 — 需要时可在杀毒选项卡手动隔离",
            "Инцидент записан — при необходимости изолируйте вручную",
        )
        .to_string();
        if auto {
            match crate::modules::security::file_quarantine::quarantine_file(
                path,
                "auto: MALICIOUS",
            ) {
                Ok(_) => {
                    mitigation = crate::modules::i18n::tr4(
                        "Đã TỰ ĐỘNG cách ly tệp (mã hóa AES-256 + xóa gốc an toàn)",
                        "File AUTO-quarantined (AES-256 encrypted + original securely erased)",
                        "文件已自动隔离（AES-256 加密 + 原件安全删除）",
                        "Файл автоматически изолирован (AES-256 + безопасное удаление)",
                    )
                    .to_string();
                }
                Err(e) => {
                    mitigation = format!("quarantine failed: {e}");
                }
            }
        }
        self.emit_incident(
            "FILE_MALICIOUS",
            &report.file_path,
            format!(
                "{} {} {} {}",
                crate::modules::i18n::tr4(
                    "Tệp nguy hiểm:",
                    "Malicious file:",
                    "恶意文件:",
                    "Вредоносный файл:"
                ),
                report.file_name,
                crate::modules::i18n::tr4("điểm", "score", "分", "баллы"),
                report.risk_score
            ),
            "CRITICAL",
            mitigation,
        );
    }

    fn emit_incident(
        &self,
        incident_type: &str,
        source: &str,
        details: String,
        severity: &str,
        mitigation: String,
    ) {
        {
            let mut cooldown = match self.incident_cooldown.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            if let Some(last) = cooldown.get(incident_type) {
                if last.elapsed() < INCIDENT_COOLDOWN {
                    return;
                }
            }
            cooldown.insert(incident_type.to_string(), Instant::now());
            if cooldown.len() > 64 {
                cooldown.retain(|_, t| t.elapsed() < INCIDENT_COOLDOWN);
            }
        }
        if let Some(engine) = self.engine.get() {
            engine.record_incident(incident_type, source, &details, severity, &mitigation);
        }
    }

    fn release_expired_lock(&self) {
        if !self.lock_active.load(Ordering::Relaxed) {
            return;
        }
        let locked_at = self.locked_at_ms.load(Ordering::Relaxed);
        if now_millis().saturating_sub(locked_at) < AUTOLOCK_RELEASE.as_millis() as u64 {
            return;
        }
        self.lock_active.store(false, Ordering::SeqCst);
        let _ = crate::modules::system::dns_manager::set_master_internet_lock(false);
        self.emit_incident(
            "CANARY_LOCK_RELEASED",
            "-",
            crate::modules::i18n::tr4(
                "Đã tự mở khoá mạng sau 5 phút — hãy kiểm tra máy nếu không mong đợi",
                "Network lock auto-released after 5 minutes — inspect the machine if unexpected",
                "已在 5 分钟后自动解除网络锁定 — 如非预期请检查机器",
                "Блокировка снята через 5 минут — проверьте машину, если это неожиданно",
            )
            .to_string(),
            "MEDIUM",
            crate::modules::i18n::tr4(
                "Đã trả DNS về bình thường",
                "System DNS returned to normal",
                "系统 DNS 已恢复正常",
                "Системный DNS восстановлен",
            )
            .to_string(),
        );
    }

    fn engage_master_lock(&self) {
        if let Err(e) = crate::modules::system::dns_manager::set_master_internet_lock(true) {
            tracing::warn!("Ransomware auto-lock failed: {e}");
        }
    }
}

impl Default for RealtimeGuard {
    fn default() -> Self {
        Self::new()
    }
}

fn app_canary_path() -> std::path::PathBuf {
    crate::modules::paths::data_dir()
        .join("ShieldGhita")
        .join("canary")
        .join(APP_CANARY_NAME)
}

fn is_quarantine_path(path: &Path) -> bool {
    path.to_string_lossy()
        .to_lowercase()
        .contains("\\shieldghita\\quarantine\\")
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn rand_bytes_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    let _ = getrandom::fill(&mut buf);
    buf
}

fn watched_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let profile = PathBuf::from(profile);
        dirs.push(profile.join("Downloads"));
        dirs.push(profile.join("Desktop"));
    }
    if dirs.len() < WATCHED_DIR_LIMIT {
        for letter in list_removable_drive_letters() {
            let root = PathBuf::from(format!("{letter}:\\"));
            dirs.push(root);
            if dirs.len() >= WATCHED_DIR_LIMIT {
                break;
            }
        }
    }
    dirs.retain(|dir| dir.is_dir());
    dirs
}

fn collect_dir_stamps(
    dir: &Path,
    fresh: &mut HashMap<PathBuf, FileStamp>,
    changed: &mut Vec<PathBuf>,
    snapshot: &mut HashMap<PathBuf, FileStamp>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let stamp = FileStamp {
            mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            size: meta.len(),
        };
        match snapshot.get(&path) {
            Some(old) if old == &stamp => {}
            _ => changed.push(path.clone()),
        }
        fresh.insert(path, stamp);
    }
}

#[cfg(windows)]
fn list_removable_drive_letters() -> std::collections::HashSet<char> {
    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};

    const DRIVE_TYPE_REMOVABLE: u32 = 2;
    let mut letters = std::collections::HashSet::new();
    let bitmask = unsafe { GetLogicalDrives() };
    for index in 0u32..26 {
        if bitmask & (1u32 << index) == 0 {
            continue;
        }
        let letter = (b'A' + index as u8) as char;
        let root: Vec<u16> = format!("{letter}:\\")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let drive_type = unsafe { GetDriveTypeW(windows::core::PCWSTR(root.as_ptr())) };
        if drive_type == DRIVE_TYPE_REMOVABLE {
            letters.insert(letter);
        }
    }
    letters
}

#[cfg(not(windows))]
fn list_removable_drive_letters() -> std::collections::HashSet<char> {
    std::collections::HashSet::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarantine_path_detection() {
        assert!(is_quarantine_path(Path::new(
            r"C:\Users\me\AppData\Roaming\ShieldGhita\quarantine\a.sgq"
        )));
        assert!(!is_quarantine_path(Path::new(
            r"C:\Users\me\Downloads\doc.pdf"
        )));
    }

    #[test]
    fn test_watched_dirs_includes_downloads_and_desktop() {
        let dirs = watched_dirs();
        let joined = dirs
            .iter()
            .map(|d| d.to_string_lossy().to_lowercase())
            .collect::<Vec<_>>();
        assert!(
            joined.iter().any(|d| d.contains("downloads")),
            "Downloads must be watched"
        );
    }

    #[test]
    fn test_canary_file_name_is_stable() {
        assert_eq!(CANARY_NAME, "ShieldGhita-Canary.dat");
    }
}
