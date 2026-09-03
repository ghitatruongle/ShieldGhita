pub mod dns_manager;
pub mod self_defense;
pub mod single_instance;
pub mod win32_net;

pub use dns_manager::*;
pub use self_defense::*;
pub use single_instance::*;

/// Open a URL in the default browser via ShellExecuteW. This never spawns a
/// console window and hands the URL to the shell association handler, so the
/// user's own browser opens it.
#[cfg(windows)]
pub fn open_url_in_default_browser(url: &str) -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let verb: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
    let target: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(target.as_ptr()),
            None,
            None,
            SW_SHOWNORMAL,
        )
    };
    if (result.0 as isize) > 32 {
        Ok(())
    } else {
        Err(format!(
            "ShellExecuteW could not open URL (code {:?})",
            result.0
        ))
    }
}

#[cfg(not(windows))]
pub fn open_url_in_default_browser(_url: &str) -> Result<(), String> {
    Err("Opening URLs is only supported on Windows".to_string())
}

/// Trims physical memory pages of current process back to the OS (Working Set Trimming).
#[cfg(windows)]
pub fn trim_process_working_set() {
    unsafe {
        use windows::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};
        let _ = SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX);
    }
}

#[cfg(not(windows))]
pub fn trim_process_working_set() {}
