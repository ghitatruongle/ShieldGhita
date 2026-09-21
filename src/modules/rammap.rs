#![allow(dead_code)]

use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
// Use the OS-canonical struct instead of a hand-rolled replica: the custom
// layout drifted (missing alignment/packing guarantees) and risked UB in
// VirtualQueryEx.
use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION;

const SYSTEM_MEMORY_LIST_INFORMATION: i32 = 0x50;
const SYSTEM_FILE_CACHE_INFORMATION: i32 = 0x21;

const MEMORY_EMPTY_WORKING_SETS: u32 = 2;
const MEMORY_FLUSH_MODIFIED_LIST: u32 = 3;
const MEMORY_PURGE_STANDBY_LIST: u32 = 4;
const MEMORY_PURGE_LOW_PRIORITY_STANDBY_LIST: u32 = 5;

const MEMORY_PRIORITY_MAXIMUM: usize = 8;

const PAGE_SIZE: usize = 4096;
const MB: f64 = 1024.0 * 1024.0;

const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_PRIVATE: u32 = 0x0002_0000;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_TERMINATE: u32 = 0x0001;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PerformanceInformation {
    cb: u32,
    commit_total: usize,
    commit_limit: usize,
    commit_peak: usize,
    physical_total: usize,
    physical_available: usize,
    system_cache: usize,
    kernel_total: usize,
    kernel_paged: usize,
    kernel_nonpaged: usize,
    page_size: usize,
    handle_count: u32,
    process_count: u32,
    thread_count: u32,
}

#[link(name = "ntdll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn NtQuerySystemInformation(class: i32, info: *mut c_void, len: u32, retlen: *mut u32) -> i32;
    fn NtSetSystemInformation(class: i32, info: *const c_void, len: u32) -> i32;
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct MemoryStatusEx {
    dw_length: u32,
    dw_memory_load: u32,
    ull_total_phys: u64,
    ull_avail_phys: u64,
    ull_total_page_file: u64,
    ull_avail_page_file: u64,
    ull_total_virtual: u64,
    ull_avail_virtual: u64,
    ull_avail_extended_virtual: u64,
}

#[link(name = "kernel32", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn VirtualQueryEx(
        process: HANDLE,
        address: *const c_void,
        buffer: *mut MEMORY_BASIC_INFORMATION,
        length: usize,
    ) -> usize;
    fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
    fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> HANDLE;
    fn TerminateProcess(process: HANDLE, exit_code: u32) -> i32;
}

#[link(name = "psapi", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn GetPerformanceInfo(info: *mut PerformanceInformation, size: u32) -> i32;
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SystemMemoryListInfo {
    standby_by_priority: [usize; MEMORY_PRIORITY_MAXIMUM],
    repurposed_by_priority: [usize; MEMORY_PRIORITY_MAXIMUM],
    zero_page_count: usize,
    free_page_count: usize,
    modified_page_count: usize,
    modified_no_write_page_count: usize,
    bad_page_count: usize,
    modified_page_count_page_file: usize,
}

/// Available physical RAM in MB. Returns 0 when the OS probe fails — callers
/// must treat 0 as "unknown", not as "no free memory".
pub fn get_available_ram_mb() -> u64 {
    let mut ms = MemoryStatusEx {
        dw_length: size_of::<MemoryStatusEx>() as u32,
        ..Default::default()
    };
    if unsafe { GlobalMemoryStatusEx(&mut ms) } != 0 {
        ms.ull_avail_phys / (1024 * 1024)
    } else {
        0
    }
}

#[derive(Debug, Clone, Default)]
pub struct MemoryBreakdown {
    pub total_mb: f64,
    pub available_mb: f64,
    pub active_mb: f64,
    pub standby_mb: f64,
    pub modified_mb: f64,
    pub free_mb: f64,
    pub zero_mb: f64,
    pub page_cache_mb: f64,
    pub kernel_mb: f64,
    pub commit_mb: f64,
    pub commit_limit_mb: f64,

    pub lists_available: bool,
}

pub fn snapshot() -> MemoryBreakdown {
    let mut b = MemoryBreakdown::default();

    let mut ms = MemoryStatusEx {
        dw_length: size_of::<MemoryStatusEx>() as u32,
        ..Default::default()
    };
    if unsafe { GlobalMemoryStatusEx(&mut ms) } != 0 {
        b.total_mb = ms.ull_total_phys as f64 / MB;
        b.available_mb = ms.ull_avail_phys as f64 / MB;
    }
    let mut ps = PAGE_SIZE as f64;
    unsafe {
        let mut perf = PerformanceInformation {
            cb: size_of::<PerformanceInformation>() as u32,
            ..Default::default()
        };
        if GetPerformanceInfo(&mut perf, perf.cb) != 0 {
            if perf.page_size >= 1024 {
                ps = perf.page_size as f64;
            }
            b.page_cache_mb = perf.system_cache as f64 * ps / MB;
            b.kernel_mb = perf.kernel_total as f64 * ps / MB;
            b.commit_mb = perf.commit_total as f64 * ps / MB;
            b.commit_limit_mb = perf.commit_limit as f64 * ps / MB;
        }
    }

    b.active_mb = (b.total_mb - b.available_mb).max(0.0);
    ensure_privilege_once();
    unsafe {
        let mut data = SystemMemoryListInfo::default();
        let mut returned: u32 = 0;
        let status = NtQuerySystemInformation(
            SYSTEM_MEMORY_LIST_INFORMATION,
            &mut data as *mut _ as *mut c_void,
            size_of::<SystemMemoryListInfo>() as u32,
            &mut returned,
        );
        if status >= 0 && (returned == 0 || returned as usize == size_of::<SystemMemoryListInfo>())
        {
            let standby_pages: usize = data.standby_by_priority.iter().sum();
            b.standby_mb = standby_pages as f64 * ps / MB;
            b.modified_mb = data.modified_page_count as f64 * ps / MB;
            b.free_mb = data.free_page_count as f64 * ps / MB;
            b.zero_mb = data.zero_page_count as f64 * ps / MB;
            let reclaimable = b.standby_mb + b.free_mb + b.zero_mb + b.modified_mb;
            b.lists_available = b.total_mb > 0.0
                && b.standby_mb > 0.0
                && reclaimable <= b.total_mb
                && reclaimable > b.available_mb * 0.3;
            if !b.lists_available {
                warn_once(format!(
                    "RAM Map: page-list implausible (standby={:.0} free={:.0} zero={:.0} mod={:.0} vs available={:.0} / total={:.0})",
                    b.standby_mb, b.free_mb, b.zero_mb, b.modified_mb, b.available_mb, b.total_mb
                ));
            }
        } else {
            warn_once(format!(
                "RAM Map: page-list query unavailable (status {status:#010x}, returned {returned})"
            ));
        }
    }
    b
}

fn warn_once(msg: String) {
    use std::sync::Once;
    static WARN: Once = Once::new();
    WARN.call_once(|| tracing::warn!("{msg}"));
}

fn ensure_privilege_once() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        enable_privilege("SeProfileSingleProcessPrivilege");
        enable_privilege("SeIncreaseQuotaPrivilege");
        enable_privilege("SeDebugPrivilege");
    });
}

#[derive(Debug, Clone)]
pub struct ProcessMemory {
    pub pid: u32,
    pub name: String,
    pub working_set_mb: f64,
    pub percent_ram: f64,
    pub exe_path: String,
    pub is_critical: bool,
}

pub fn is_critical_process(pid: u32, name: &str) -> bool {
    if pid == 0 || pid == 4 || pid == std::process::id() {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    let critical_names = [
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        "registry",
        "memory compression",
        "shield_ghita.exe",
        "shield_ghita_admin.exe",
    ];
    critical_names.iter().any(|&c| lower == c)
}

pub fn all_processes() -> Vec<ProcessMemory> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(
            // `with_exe` is required: the default is UpdateKind::Never, which
            // leaves p.exe() empty and would silently break "Open folder".
            ProcessRefreshKind::new()
                .with_memory()
                .with_exe(UpdateKind::OnlyIfNotSet),
        ),
    );
    sys.refresh_processes();
    let total_ram = sys.total_memory() as f64;
    let mut rows: Vec<ProcessMemory> = sys
        .processes()
        .iter()
        .map(|(pid, p)| {
            let p_u32 = pid.as_u32();
            let name = p.name().to_string();
            let working_set_mb = p.memory() as f64 / MB;
            let percent_ram = if total_ram > 0.0 {
                ((p.memory() as f64 / total_ram) * 100.0).clamp(0.0, 100.0)
            } else {
                0.0
            };
            let exe_path = p
                .exe()
                .and_then(|path| path.to_str())
                .unwrap_or("")
                .to_string();
            let is_critical = is_critical_process(p_u32, &name);
            ProcessMemory {
                pid: p_u32,
                name,
                working_set_mb,
                percent_ram,
                exe_path,
                is_critical,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        b.working_set_mb
            .partial_cmp(&a.working_set_mb)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    rows
}

pub fn top_processes(limit: usize) -> Vec<ProcessMemory> {
    let mut rows = all_processes();
    rows.truncate(limit);
    rows
}

pub fn terminate_process_by_pid(pid: u32) -> Result<(), String> {
    if pid == 0 || pid == 4 || pid == std::process::id() {
        return Err("Cannot terminate core system process".to_string());
    }
    // Re-check criticality against the LIVE process name: the UI model is
    // refreshed every ~3s, so a PID clicked by the user may already have been
    // recycled onto a protected system process. Never trust the client flag.
    use sysinfo::{Pid, System};
    let key = Pid::from_u32(pid);
    let mut sys = System::new();
    if sys.refresh_process(key) {
        if let Some(p) = sys.process(key) {
            let name = p.name().to_string();
            if is_critical_process(pid, &name) {
                return Err(format!("Cannot terminate protected process '{name}'"));
            }
        }
    }
    enable_privilege("SeDebugPrivilege");
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_invalid() || handle.0.is_null() {
            return Err(format!("Failed to open process {pid}: access denied"));
        }
        let success = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);
        if success == 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("Failed to terminate process {pid}: {err}"));
        }
    }
    Ok(())
}

pub fn open_process_folder(path: &str) -> Result<(), String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Empty process path".to_string());
    }
    let p = std::path::Path::new(trimmed);
    if !p.exists() {
        return Err("Path does not exist on disk".to_string());
    }

    let _ = std::process::Command::new("explorer.exe")
        .arg(format!("/select,{}", p.display()))
        .spawn()
        .map_err(|e| format!("Failed to open explorer: {e}"))?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyOp {
    WorkingSets,
    SystemWorkingSet,
    ModifiedPageList,
    StandbyList,
    Priority0StandbyList,
}

impl EmptyOp {
    pub fn label(self) -> &'static str {
        match self {
            EmptyOp::WorkingSets => "Empty Working Sets",
            EmptyOp::SystemWorkingSet => "Empty System Working Set",
            EmptyOp::ModifiedPageList => "Empty Modified Page List",
            EmptyOp::StandbyList => "Empty Standby List",
            EmptyOp::Priority0StandbyList => "Empty Priority 0 Standby List",
        }
    }
}

fn enable_privilege(name: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GetLastError, ERROR_SUCCESS, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .is_err()
        {
            return false;
        }
        let mut luid = LUID::default();
        let ok = LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide.as_ptr()), &mut luid).is_ok();
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let adjusted = ok && AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None).is_ok();
        let _ = CloseHandle(token);
        // AdjustTokenPrivileges reports success even when the privilege was
        // not actually granted — GetLastError must be ERROR_SUCCESS.
        adjusted && GetLastError() == ERROR_SUCCESS
    }
}

pub fn empty_all_process_working_sets() -> usize {
    use windows::Win32::System::Threading::{
        OpenProcess, SetProcessWorkingSetSize, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA,
    };
    let mut count = 0;
    let my_pid = std::process::id();
    for proc in all_processes() {
        if proc.pid == 0 || proc.pid == 4 || proc.pid == my_pid {
            continue;
        }
        unsafe {
            if let Ok(handle) = OpenProcess(
                PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                proc.pid,
            ) {
                if !handle.is_invalid() && !handle.0.is_null() {
                    let ok = SetProcessWorkingSetSize(handle, usize::MAX, usize::MAX);
                    if ok.is_ok() {
                        count += 1;
                    }
                    let _ = CloseHandle(handle);
                }
            }
        }
    }
    count
}

pub fn empty(op: EmptyOp) -> Result<u64, String> {
    let _ = enable_privilege("SeProfileSingleProcessPrivilege");
    let _ = enable_privilege("SeIncreaseQuotaPrivilege");
    let _ = enable_privilege("SeDebugPrivilege");

    let before = snapshot();

    match op {
        EmptyOp::WorkingSets => {
            let (class, command): (i32, u32) =
                (SYSTEM_MEMORY_LIST_INFORMATION, MEMORY_EMPTY_WORKING_SETS);
            let status = unsafe {
                NtSetSystemInformation(
                    class,
                    &command as *const u32 as *const c_void,
                    size_of::<u32>() as u32,
                )
            };
            if status < 0 {
                return Err(format!(
                    "NtSetSystemInformation(EmptyWorkingSets) failed status=0x{:08X}",
                    status as u32
                ));
            }

            let _ = empty_all_process_working_sets();
        }
        EmptyOp::SystemWorkingSet => {
            // RAMMap's "Empty System Working Set": trim the file cache via
            // SetSystemFileCacheSize(MIN=-1, MAX=-1). Microsoft documents
            // these sizes as the flush sentinel and flags=0 as retaining the
            // current limit enablement. No persistent limit change to restore.
            // https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-setsystemfilecachesize
            // (The previous
            // NtSetSystemInformation(SystemFileCacheInformation, 0) passed a
            // bare u32 0 and never flushed anything.)
            use windows::Win32::System::Memory::SetSystemFileCacheSize;
            let ok = unsafe { SetSystemFileCacheSize(usize::MAX, usize::MAX, 0) };
            if ok.is_err() {
                let err = std::io::Error::last_os_error();
                return Err(format!(
                    "{} failed ({err}) — needs Administrator",
                    op.label()
                ));
            }
        }
        _ => {
            let (class, command): (i32, u32) = match op {
                EmptyOp::WorkingSets => unreachable!(),
                EmptyOp::ModifiedPageList => {
                    (SYSTEM_MEMORY_LIST_INFORMATION, MEMORY_FLUSH_MODIFIED_LIST)
                }
                EmptyOp::StandbyList => (SYSTEM_MEMORY_LIST_INFORMATION, MEMORY_PURGE_STANDBY_LIST),
                EmptyOp::Priority0StandbyList => (
                    SYSTEM_MEMORY_LIST_INFORMATION,
                    MEMORY_PURGE_LOW_PRIORITY_STANDBY_LIST,
                ),
                EmptyOp::SystemWorkingSet => unreachable!(),
            };
            let status = unsafe {
                NtSetSystemInformation(
                    class,
                    &command as *const u32 as *const c_void,
                    size_of::<u32>() as u32,
                )
            };
            if status < 0 {
                return Err(format!(
                    "{} failed (ntstatus {status:#010x}) — needs Administrator",
                    op.label()
                ));
            }
        }
    }

    std::thread::sleep(std::time::Duration::from_millis(150));

    let after = snapshot();
    let freed_category = match op {
        EmptyOp::StandbyList => (before.standby_mb - after.standby_mb)
            .max(after.free_mb - before.free_mb)
            .max(after.available_mb - before.available_mb),
        EmptyOp::Priority0StandbyList => {
            (before.standby_mb - after.standby_mb).max(after.free_mb - before.free_mb)
        }
        EmptyOp::WorkingSets => {
            (before.active_mb - after.active_mb).max(after.available_mb - before.available_mb)
        }
        EmptyOp::SystemWorkingSet => (before.page_cache_mb - after.page_cache_mb)
            .max(after.available_mb - before.available_mb),
        EmptyOp::ModifiedPageList => {
            (before.modified_mb - after.modified_mb).max(after.available_mb - before.available_mb)
        }
    };

    let freed = freed_category
        .max(after.available_mb - before.available_mb)
        .max(0.0);
    tracing::info!("RAM Map: {} freed ~{:.0} MB", op.label(), freed);
    Ok(freed.round() as u64)
}

#[derive(Debug, Clone)]
pub struct SuspiciousProcess {
    pub pid: u32,
    pub name: String,
    pub regions: usize,
    pub total_mb: f64,
    pub rwx_regions: usize,
}

fn is_executable(protect: u32) -> bool {
    let base = protect & !PAGE_GUARD;
    base & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0
}

fn is_rwx(protect: u32) -> bool {
    // Mask to the low protection byte: high bits (NOCACHE/WRITECOMBINE etc.)
    // must not affect the RWX classification.
    let base = protect & 0xFF;
    base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    Checked,
    Skipped,
    AccessDenied,
    Error,
    Partial,
}

#[derive(Debug, Clone)]
pub struct ProcessScanCoverage {
    pub pid: u32,
    pub status: ScanStatus,
    pub regions_checked: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryScanReport {
    pub findings: Vec<SuspiciousProcess>,
    pub coverage: Vec<ProcessScanCoverage>,
    /// Processes outside the requested top-N sample are not checked.
    pub not_selected: usize,
    pub error: Option<String>,
}

impl MemoryScanReport {
    pub fn count(&self, status: ScanStatus) -> usize {
        self.coverage.iter().filter(|p| p.status == status).count()
    }
}

fn query_stop_status(regions_checked: usize, error: u32) -> ScanStatus {
    // VirtualQueryEx documents ERROR_INVALID_PARAMETER above the highest
    // accessible address. Only accept it after a successful, contiguous walk;
    // the same error on the very first query must NOT mean "checked".
    if regions_checked > 0 && error == 87 {
        ScanStatus::Checked
    } else if regions_checked > 0 {
        ScanStatus::Partial
    } else if error == 5 {
        ScanStatus::AccessDenied
    } else {
        ScanStatus::Error
    }
}

fn next_region_address(address: usize, base: usize, size: usize) -> Option<usize> {
    let next = base.checked_add(size)?;
    (size > 0 && base <= address && next > address).then_some(next)
}

struct ScanHandle(HANDLE);
impl Drop for ScanHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Metadata-only heuristic: private executable mappings can also be legitimate
/// (including JIT). No browser exemption, memory writes, or automatic killing.
pub fn scan_suspicious_processes_report(
    max_processes: usize,
    min_region_mb: f64,
) -> MemoryScanReport {
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::System::Threading::{OpenProcess as WinOpenProcess, PROCESS_ACCESS_RIGHTS};
    let mut report = MemoryScanReport::default();
    if max_processes == 0 || !min_region_mb.is_finite() || min_region_mb < 0.0 {
        report.error = Some("Invalid scan limit or region threshold".into());
        return report;
    }
    let processes = all_processes();
    report.not_selected = processes.len().saturating_sub(max_processes);
    if processes.is_empty() {
        report.error = Some("No processes could be enumerated".into());
        return report;
    }
    for proc in processes.into_iter().take(max_processes) {
        let mut coverage = ProcessScanCoverage {
            pid: proc.pid,
            status: ScanStatus::Skipped,
            regions_checked: 0,
            detail: String::new(),
        };
        if proc.pid == std::process::id() || proc.pid == 0 || proc.pid == 4 {
            coverage.detail = "Self or core system process excluded".into();
            report.coverage.push(coverage);
            continue;
        }
        // VirtualQueryEx requires PROCESS_QUERY_INFORMATION, not LIMITED.
        let handle = match unsafe {
            WinOpenProcess(
                PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_INFORMATION),
                false,
                proc.pid,
            )
        } {
            Ok(h) if !h.is_invalid() && !h.0.is_null() => ScanHandle(h),
            Ok(_) => {
                coverage.status = ScanStatus::Error;
                coverage.detail = "OpenProcess returned an invalid handle".into();
                report.coverage.push(coverage);
                continue;
            }
            Err(e) => {
                coverage.status = if e.code() == windows::core::HRESULT::from_win32(5) {
                    ScanStatus::AccessDenied
                } else {
                    ScanStatus::Error
                };
                coverage.detail = format!("OpenProcess: {e}");
                report.coverage.push(coverage);
                continue;
            }
        };
        let mut found = SuspiciousProcess {
            pid: proc.pid,
            name: proc.name,
            regions: 0,
            total_mb: 0.0,
            rwx_regions: 0,
        };
        let mut address = 0usize;
        // Bound work on a changing process; exhausting the budget is partial,
        // never a clean bill of health. Native pointer width avoids x86 overflow.
        const MAX_QUERIES: usize = 262_144;
        coverage.status = ScanStatus::Partial;
        coverage.detail = "Region query budget exhausted".into();
        for _ in 0..MAX_QUERIES {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let bytes = unsafe {
                VirtualQueryEx(
                    handle.0,
                    address as *const c_void,
                    &mut mbi,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if bytes == 0 {
                let error = unsafe { GetLastError() }.0;
                coverage.status = query_stop_status(coverage.regions_checked, error);
                coverage.detail = if coverage.status == ScanStatus::Checked {
                    "Reached end of queryable address space".into()
                } else {
                    format!("VirtualQueryEx at {address:#x}: Win32 error {error}")
                };
                break;
            }
            if bytes != size_of::<MEMORY_BASIC_INFORMATION>() {
                coverage.status = if coverage.regions_checked > 0 {
                    ScanStatus::Partial
                } else {
                    ScanStatus::Error
                };
                coverage.detail = "VirtualQueryEx returned a short structure".into();
                break;
            }
            let Some(next) = next_region_address(address, mbi.BaseAddress as usize, mbi.RegionSize)
            else {
                coverage.detail = "Invalid, overflowing, or non-advancing memory region".into();
                break;
            };
            coverage.regions_checked += 1;
            if mbi.State.0 == MEM_COMMIT
                && mbi.Type.0 == MEM_PRIVATE
                && is_executable(mbi.Protect.0)
                && mbi.RegionSize as f64 / MB >= min_region_mb
            {
                found.regions += 1;
                found.total_mb += mbi.RegionSize as f64 / MB;
                if is_rwx(mbi.Protect.0) {
                    found.rwx_regions += 1;
                }
            }
            address = next;
        }
        if found.regions > 0 {
            // Findings from a partially queried process remain visible.
            report.findings.push(found);
        }
        report.coverage.push(coverage);
    }
    report.findings.sort_by(|a, b| {
        b.rwx_regions.cmp(&a.rwx_regions).then(
            b.total_mb
                .partial_cmp(&a.total_mb)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    report
}

/// Legacy findings-only API retained for the panel caller outside this file's
/// ownership. Consumers must migrate to the report API before claiming a scan
/// completed; an empty Vec is NOT evidence that inaccessible processes are safe.
pub fn scan_suspicious_processes(
    max_processes: usize,
    min_region_mb: f64,
) -> Vec<SuspiciousProcess> {
    let report = scan_suspicious_processes_report(max_processes, min_region_mb);
    if report.error.is_some()
        || report
            .coverage
            .iter()
            .any(|p| p.status != ScanStatus::Checked)
    {
        tracing::warn!("RAM scan has incomplete coverage: {:?}", report.coverage);
    }
    report.findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_failures_never_count_as_checked() {
        assert_eq!(query_stop_status(0, 5), ScanStatus::AccessDenied);
        assert_eq!(query_stop_status(0, 87), ScanStatus::Error);
        assert_eq!(query_stop_status(5, 5), ScanStatus::Partial);
        assert_eq!(query_stop_status(5, 6), ScanStatus::Partial);
        assert_eq!(query_stop_status(5, 87), ScanStatus::Checked);
    }

    #[test]
    fn region_walk_requires_forward_progress_without_overflow() {
        assert_eq!(next_region_address(4096, 4096, 4096), Some(8192));
        assert_eq!(next_region_address(4096, 0, 8192), Some(8192));
        assert_eq!(next_region_address(4096, 8192, 4096), None);
        assert_eq!(next_region_address(4096, 4096, 0), None);
        assert_eq!(next_region_address(4096, 0, 4096), None);
        assert_eq!(next_region_address(usize::MAX, usize::MAX, 1), None);
    }

    #[test]
    fn empty_report_has_no_checked_processes() {
        let report = MemoryScanReport::default();
        assert_eq!(report.count(ScanStatus::Checked), 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_snapshot_totals_are_plausible() {
        let b = snapshot();
        assert!(b.total_mb > 0.0, "total physical memory must be > 0");
        assert!(b.available_mb > 0.0);
        assert!(b.available_mb <= b.total_mb);
        assert!(b.commit_limit_mb >= b.commit_mb);
    }

    #[test]
    fn test_snapshot_page_lists_or_graceful_fallback() {
        let b = snapshot();
        if b.lists_available {
            assert!(b.standby_mb > 0.0);
            assert!(b.free_mb >= 0.0);
            let reclaimable = b.standby_mb + b.free_mb + b.zero_mb + b.modified_mb;
            assert!(reclaimable <= b.total_mb);
        }
    }

    #[test]
    fn test_top_processes_sorted_and_limited() {
        let rows = top_processes(10);
        assert!(!rows.is_empty(), "must see at least one process");
        assert!(rows.len() <= 10);
        for pair in rows.windows(2) {
            assert!(pair[0].working_set_mb >= pair[1].working_set_mb);
        }
        assert!(rows.iter().any(|r| !r.name.is_empty()));
    }

    #[test]
    fn test_empty_op_labels_unique() {
        let ops = [
            EmptyOp::WorkingSets,
            EmptyOp::SystemWorkingSet,
            EmptyOp::ModifiedPageList,
            EmptyOp::StandbyList,
            EmptyOp::Priority0StandbyList,
        ];
        let mut labels: Vec<_> = ops.iter().map(|o| o.label()).collect();
        labels.sort();
        labels.dedup();
        assert_eq!(labels.len(), 5);
    }

    #[test]
    fn test_executable_protect_classification() {
        assert!(is_executable(PAGE_EXECUTE_READWRITE));
        assert!(is_executable(PAGE_EXECUTE_READ));
        assert!(!is_executable(0x04));
        assert!(is_rwx(PAGE_EXECUTE_READWRITE | PAGE_GUARD));
        assert!(!is_rwx(PAGE_EXECUTE_READ));
    }

    #[test]
    fn test_critical_process_whitelist() {
        assert!(is_critical_process(0, "System Idle Process"));
        assert!(is_critical_process(4, "System"));
        assert!(is_critical_process(9999, "csrss.exe"));
        assert!(is_critical_process(8888, "dwm.exe"));
        assert!(!is_critical_process(12345, "notepad.exe"));
    }

    #[test]
    fn test_terminate_process_safety_guards() {
        assert!(terminate_process_by_pid(0).is_err());
        assert!(terminate_process_by_pid(4).is_err());
        assert!(terminate_process_by_pid(std::process::id()).is_err());
    }

    #[test]
    fn test_open_process_folder_nonexistent() {
        let res = open_process_folder("Z:\\NonExistentBinaryPath12345.exe");
        assert!(res.is_err());
    }

    #[test]
    fn test_all_processes_populates_exe_path() {
        // Regression guard: `with_exe(UpdateKind::OnlyIfNotSet)` must stay in
        // the refresh kind, otherwise p.exe() returns None and the UI's
        // "Open Process Folder" button silently never works.
        let me = all_processes()
            .into_iter()
            .find(|p| p.pid == std::process::id())
            .expect("current process missing from all_processes()");
        assert!(!me.exe_path.is_empty());
        assert!(me.working_set_mb > 0.0);
    }
}
