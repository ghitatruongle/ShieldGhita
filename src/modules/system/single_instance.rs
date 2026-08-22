#![allow(dead_code)]

#[cfg(windows)]
pub struct SingleInstanceGuard {
    _mutex: windows::Win32::Foundation::HANDLE,
    _event: windows::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl SingleInstanceGuard {
    pub fn try_acquire(ui_weak: slint::Weak<crate::AppWindow>) -> Option<Self> {
        use slint::ComponentHandle;
        use windows::core::w;
        use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
        use windows::Win32::System::Threading::{
            CreateEventW, CreateMutexW, OpenEventW, SetEvent, WaitForSingleObject,
            EVENT_MODIFY_STATE,
        };

        const MUTEX_NAME: windows::core::PCWSTR = w!("Local\\ShieldGhita_SingleInstanceMutex");
        const EVENT_NAME: windows::core::PCWSTR = w!("Local\\ShieldGhita_ShowWindowEvent");

        unsafe {
            let mutex = CreateMutexW(None, true, MUTEX_NAME).ok()?;
            if GetLastError() == ERROR_ALREADY_EXISTS {
                let _ = CloseHandle(mutex);
                if let Ok(event) = OpenEventW(EVENT_MODIFY_STATE, false, EVENT_NAME) {
                    let _ = SetEvent(event);
                    let _ = CloseHandle(event);
                }
                return None;
            }

            let event = CreateEventW(None, false, false, EVENT_NAME).unwrap_or(HANDLE::default());
            if !event.is_invalid() {
                let raw_handle = event.0 as usize;
                std::thread::spawn(move || {
                    let ev_handle = HANDLE(raw_handle as *mut core::ffi::c_void);
                    loop {
                        let res = WaitForSingleObject(
                            ev_handle,
                            windows::Win32::System::Threading::INFINITE,
                        );
                        if res == windows::Win32::Foundation::WAIT_OBJECT_0 {
                            let weak_clone = ui_weak.clone();
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(ui_inst) = weak_clone.upgrade() {
                                    ui_inst.window().set_minimized(false);
                                    let _ = ui_inst.show();
                                    crate::app::ui_bridge::poller::WINDOW_VISIBLE
                                        .store(true, std::sync::atomic::Ordering::SeqCst);
                                }
                            });
                        } else {
                            break;
                        }
                    }
                });
            }

            Some(Self {
                _mutex: mutex,
                _event: event,
            })
        }
    }
}

#[cfg(windows)]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        unsafe {
            if !self._event.is_invalid() {
                let _ = CloseHandle(self._event);
            }
            if !self._mutex.is_invalid() {
                let _ = CloseHandle(self._mutex);
            }
        }
    }
}

#[cfg(not(windows))]
pub struct SingleInstanceGuard;

#[cfg(not(windows))]
impl SingleInstanceGuard {
    pub fn try_acquire(_ui_weak: slint::Weak<crate::AppWindow>) -> Option<Self> {
        Some(Self)
    }
}
