#![allow(dead_code)]

#[cfg(windows)]
pub struct SingleInstanceGuard {
    _mutex: windows::Win32::Foundation::HANDLE,
    event: windows::Win32::Foundation::HANDLE,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    waiter: Option<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
impl SingleInstanceGuard {
    pub fn try_acquire(ui_weak: slint::Weak<crate::AppWindow>) -> Option<Self> {
        use slint::ComponentHandle;
        use std::sync::atomic::Ordering;
        use windows::core::w;
        use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
        use windows::Win32::System::Threading::{
            CreateEventW, CreateMutexW, OpenEventW, SetEvent, WaitForSingleObject,
            EVENT_MODIFY_STATE,
        };

        const MUTEX_NAME: windows::core::PCWSTR = w!("Local\\ShieldGhita_SingleInstanceMutex");
        const EVENT_NAME: windows::core::PCWSTR = w!("Local\\ShieldGhita_ShowWindowEvent");

        unsafe {
            // Single attempt: if another instance holds the mutex, signal it
            // and exit immediately. The old 21x300ms retry loop kept the
            // second process alive ~6s for no benefit.
            let mutex = CreateMutexW(None, true, MUTEX_NAME).unwrap_or_default();
            if mutex.is_invalid() {
                return None;
            }
            if GetLastError() == ERROR_ALREADY_EXISTS {
                if let Ok(event) = OpenEventW(EVENT_MODIFY_STATE, false, EVENT_NAME) {
                    let _ = SetEvent(event);
                    let _ = CloseHandle(event);
                }
                let _ = CloseHandle(mutex);
                return None;
            }

            let event = CreateEventW(None, false, false, EVENT_NAME).unwrap_or(HANDLE::default());
            let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let waiter = if !event.is_invalid() {
                let raw_handle = event.0 as usize;
                let shutdown_flag = shutdown.clone();
                Some(std::thread::spawn(move || {
                    let ev_handle = HANDLE(raw_handle as *mut core::ffi::c_void);
                    loop {
                        if shutdown_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        // Poll with timeout so shutdown is honoured promptly.
                        let res = WaitForSingleObject(ev_handle, 200);
                        if res == windows::Win32::Foundation::WAIT_OBJECT_0 {
                            let weak_clone = ui_weak.clone();
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(ui_inst) = weak_clone.upgrade() {
                                    tracing::info!(
                                        "Second instance detected: revealing existing window"
                                    );
                                    ui_inst.window().set_minimized(false);
                                    let _ = ui_inst.show();
                                    crate::app::ui_bridge::poller::WINDOW_VISIBLE
                                        .store(true, std::sync::atomic::Ordering::SeqCst);
                                }
                            });
                        } else if res != windows::Win32::Foundation::WAIT_TIMEOUT {
                            break;
                        }
                    }
                }))
            } else {
                None
            };

            Some(Self {
                _mutex: mutex,
                event,
                shutdown,
                waiter,
            })
        }
    }
}

#[cfg(windows)]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::SetEvent;
        unsafe {
            // Signal shutdown, join the waiter thread *before* closing the
            // event handle — closing while blocked on it is a Win32 race.
            self.shutdown.store(true, Ordering::Relaxed);
            if !self.event.is_invalid() {
                let _ = SetEvent(self.event);
            }
            if let Some(handle) = self.waiter.take() {
                let _ = handle.join();
            }
            if !self.event.is_invalid() {
                let _ = CloseHandle(self.event);
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
