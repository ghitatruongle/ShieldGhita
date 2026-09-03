//! RAM Map — native physical-memory inspector & optimizer (all editions).
//!
//! A from-scratch Rust re-implementation of the useful parts of Microsoft's
//! Sysinternals RAMMap: a live "Use Counts" breakdown of physical memory
//! (active / standby / modified / free / zero / page cache / kernel), a
//! per-process working-set table, and the five "Empty" operations from
//! RAMMap's menu (Working Sets, System Working Set, Modified Page List,
//! Standby List, Priority 0 Standby List).
//!
//! Unlike RAMMap (a separate GUI exe), this runs inside ShieldGhita's own
//! 1-second poller, reports how many MB each cleanup actually freed, and
//! feeds the memory-protection scan results into the existing incident
//! feed + Security Score.
//!
//! The standby/modified/free/zero page counts come from the undocumented
//! `NtQuerySystemInformation(SystemMemoryListInformation)` — the same source
//! RAMMap uses. The struct layout is validated at runtime against the
//! documented totals; if it ever looks wrong (Windows update changing
//! internals) we degrade gracefully to the documented counters.
//!
//! FFI note: the handful of entry points we need (NtQuery/NtSet,
//! VirtualQueryEx, GetPerformanceInfo) are declared directly via
//! `raw-dylib` instead of enabling more `windows` crate features — the
//! windows crate is enormous to compile on low-RAM dev machines and these
//! signatures are stable.

#![allow(dead_code)]

use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Foundation::{CloseHandle, HANDLE};

/// SYSTEM_INFORMATION_CLASS values (ntifs.h).
const SYSTEM_MEMORY_LIST_INFORMATION: i32 = 0x50;
const SYSTEM_FILE_CACHE_INFORMATION: i32 = 0x21;

/// MEMORY_LIST_COMMAND values for NtSetSystemInformation.
const MEMORY_EMPTY_WORKING_SETS: u32 = 2;
const MEMORY_FLUSH_MODIFIED_LIST: u32 = 3;
const MEMORY_PURGE_STANDBY_LIST: u32 = 4;
const MEMORY_PURGE_LOW_PRIORITY_STANDBY_LIST: u32 = 5;

const MEMORY_PRIORITY_MAXIMUM: usize = 8;
/// Memory page size fallback (x86_64 Windows is always 4096).
const PAGE_SIZE: usize = 4096;
const MB: f64 = 1024.0 * 1024.0;

// ---- Virtual memory query constants (winnt.h) -----------------------------
const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_PRIVATE: u32 = 0x0002_0000;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct MemoryBasicInformation {
    base_address: *mut c_void,
    allocation_base: *mut c_void,
    allocation_protect: u32,
    partition_id: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    type_: u32,
}

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
        buffer: *mut MemoryBasicInformation,
        length: usize,
    ) -> usize;
    fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
}

#[link(name = "psapi", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn GetPerformanceInfo(info: *mut PerformanceInformation, size: u32) -> i32;
}

/// Layout of SYSTEM_MEMORY_LIST_INFORMATION as returned by Windows 11 24H2+
/// (build 26220): two per-priority arrays followed by six page counters —
/// 22 × SIZE_T = 176 bytes, verified empirically via the ReturnLength field.
/// Older Windows builds carried an extra Mcbp[8] array; the plausibility
/// guard in `snapshot` degrades gracefully if the layout ever shifts again.
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

/// Quick available physical RAM in megabytes without creating sysinfo::System.
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

/// One-second snapshot of physical memory, all values in megabytes.
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
    /// False when the undocumented page-list query failed or returned
    /// implausible numbers — the UI then hides the standby/modified rows.
    pub lists_available: bool,
}

/// Collect the full breakdown. Cheap enough for a 1-second poller tick.
pub fn snapshot() -> MemoryBreakdown {
    let mut b = MemoryBreakdown::default();

    // Fast Windows API: GlobalMemoryStatusEx (0 heap allocations, ~50ns)
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

    // Undocumented page-type breakdown (same source RAMMap reads).
    // "In use" is always derivable from the documented totals.
    b.active_mb = (b.total_mb - b.available_mb).max(0.0);
    // The page-list query can require SeProfileSingleProcessPrivilege to be
    // ENABLED on the token (elevated app tokens carry it disabled) — enable
    // it once, best-effort.
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
        // Some builds leave ReturnLength untouched (0) when the buffer fits.
        if status >= 0 && (returned == 0 || returned as usize == size_of::<SystemMemoryListInfo>())
        {
            let standby_pages: usize = data.standby_by_priority.iter().sum();
            b.standby_mb = standby_pages as f64 * ps / MB;
            b.modified_mb = data.modified_page_count as f64 * ps / MB;
            b.free_mb = data.free_page_count as f64 * ps / MB;
            b.zero_mb = data.zero_page_count as f64 * ps / MB;
            // Plausibility guard: the reclaimable buckets must roughly
            // explain the documented "available" figure.
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

/// One-shot WARN so the field logs explain a fallback without spamming
/// every poller tick.
fn warn_once(msg: String) {
    use std::sync::Once;
    static WARN: Once = Once::new();
    WARN.call_once(|| tracing::warn!("{msg}"));
}

/// Enable SeProfileSingleProcessPrivilege once per process (best-effort).
fn ensure_privilege_once() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        enable_privilege("SeProfileSingleProcessPrivilege");
    });
}

/// A process row in the RAM Map working-set table.
#[derive(Debug, Clone)]
pub struct ProcessMemory {
    pub pid: u32,
    pub name: String,
    pub working_set_mb: f64,
}

/// Top `limit` processes by working set (RAMMap "Processes" tab equivalent).
pub fn top_processes(limit: usize) -> Vec<ProcessMemory> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::new().with_memory()),
    );
    sys.refresh_processes();
    let mut rows: Vec<ProcessMemory> = sys
        .processes()
        .iter()
        .map(|(pid, p)| ProcessMemory {
            pid: pid.as_u32(),
            name: p.name().to_string(),
            working_set_mb: p.memory() as f64 / MB,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.working_set_mb
            .partial_cmp(&a.working_set_mb)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    rows.truncate(limit);
    drop(sys);
    crate::modules::system::trim_process_working_set();
    rows
}

/// The five cleanup operations from RAMMap's Empty menu.
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

/// Enable a named privilege on the current process token (e.g.
/// SeProfileSingleProcessPrivilege — required by the purge commands).
fn enable_privilege(name: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::LUID;
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
        adjusted
    }
}

/// Run one cleanup operation; returns megabytes of newly-available RAM
/// (clamped at 0 — other activity can mask the gain).
pub fn empty(op: EmptyOp) -> Result<u64, String> {
    // Purge commands need SeProfileSingleProcessPrivilege; the app normally
    // runs elevated (installer UAC), but the privilege still must be enabled.
    let _ = enable_privilege("SeProfileSingleProcessPrivilege");
    let before = snapshot().available_mb;
    let (class, command): (i32, u32) = match op {
        EmptyOp::WorkingSets => (SYSTEM_MEMORY_LIST_INFORMATION, MEMORY_EMPTY_WORKING_SETS),
        EmptyOp::SystemWorkingSet => (SYSTEM_FILE_CACHE_INFORMATION, 0),
        EmptyOp::ModifiedPageList => (SYSTEM_MEMORY_LIST_INFORMATION, MEMORY_FLUSH_MODIFIED_LIST),
        EmptyOp::StandbyList => (SYSTEM_MEMORY_LIST_INFORMATION, MEMORY_PURGE_STANDBY_LIST),
        EmptyOp::Priority0StandbyList => (
            SYSTEM_MEMORY_LIST_INFORMATION,
            MEMORY_PURGE_LOW_PRIORITY_STANDBY_LIST,
        ),
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
    let freed = (snapshot().available_mb - before).max(0.0);
    tracing::info!("RAM Map: {} freed ~{:.0} MB", op.label(), freed);
    Ok(freed as u64)
}

/// A process whose address space contains suspicious private executable
/// memory — the classic footprint of code injection / shellcode.
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
    let base = protect & !PAGE_GUARD;
    base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY
}

/// Walk the committed private regions of the top `max_processes` processes
/// and flag executable private memory ≥ `min_region_mb`. Read-only probing
/// (PROCESS_QUERY_LIMITED_INFORMATION) — never writes to other processes.
pub fn scan_suspicious_processes(
    max_processes: usize,
    min_region_mb: f64,
) -> Vec<SuspiciousProcess> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};
    let my_pid = std::process::id();
    let mut results = Vec::new();
    for proc in top_processes(max_processes) {
        if proc.pid == my_pid || proc.pid == 0 || proc.pid == 4 {
            continue;
        }
        let handle = match unsafe {
            OpenProcess(
                PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_LIMITED_INFORMATION),
                false,
                proc.pid,
            )
        } {
            Ok(h) => h,
            Err(_) => continue, // protected process — skip silently
        };
        let mut found = SuspiciousProcess {
            pid: proc.pid,
            name: proc.name.clone(),
            regions: 0,
            total_mb: 0.0,
            rwx_regions: 0,
        };
        let mut address = 0usize;
        let mut mbi = MemoryBasicInformation::default();
        unsafe {
            while VirtualQueryEx(
                handle,
                address as *const c_void,
                &mut mbi,
                size_of::<MemoryBasicInformation>(),
            ) >= size_of::<MemoryBasicInformation>()
            {
                if mbi.region_size == 0 {
                    break;
                }
                let committed_private = mbi.state == MEM_COMMIT && mbi.type_ == MEM_PRIVATE;
                if committed_private
                    && is_executable(mbi.protect)
                    && mbi.region_size as f64 / MB >= min_region_mb
                {
                    found.regions += 1;
                    found.total_mb += mbi.region_size as f64 / MB;
                    if is_rwx(mbi.protect) {
                        found.rwx_regions += 1;
                    }
                }
                address += mbi.region_size;
            }
            let _ = CloseHandle(handle);
        }
        if found.regions > 0 {
            results.push(found);
        }
    }
    results.sort_by(|a, b| {
        b.rwx_regions.cmp(&a.rwx_regions).then(
            b.total_mb
                .partial_cmp(&a.total_mb)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    results
}

#[cfg(test)]
mod tests {
    use super::*;

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
            // Verified strict on Windows 11 build 26220; other builds may
            // legitimately fall back to documented totals only.
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
        assert!(!is_executable(0x04)); // PAGE_READWRITE
                                       // RWX stays RWX even with PAGE_GUARD applied.
        assert!(is_rwx(PAGE_EXECUTE_READWRITE | PAGE_GUARD));
        assert!(!is_rwx(PAGE_EXECUTE_READ));
    }

    #[test]
    fn test_scan_suspicious_processes_runs_clean() {
        // On a healthy dev machine the scan must complete without panicking;
        // results depend on what's running, so only assert the type contract.
        let r = scan_suspicious_processes(15, 4.0);
        for s in &r {
            assert!(s.regions > 0);
            assert!(s.total_mb > 0.0);
        }
    }
}
