use tracing::info;

pub struct SelfDefense {
    enabled: bool,
}

impl SelfDefense {
    pub fn new() -> Self {
        Self { enabled: false }
    }

    #[cfg(windows)]
    pub fn enable(&mut self) -> Result<(), String> {
        if self.enabled {
            return Ok(());
        }
        use windows::Win32::System::Threading::{
            GetCurrentProcess, SetPriorityClass, ABOVE_NORMAL_PRIORITY_CLASS,
        };
        unsafe {
            let handle = GetCurrentProcess();
            let _ = SetPriorityClass(handle, ABOVE_NORMAL_PRIORITY_CLASS);
        }
        info!("Self-defense enabled: process priority elevated to ABOVE_NORMAL");
        self.enabled = true;
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn enable(&mut self) -> Result<(), String> {
        self.enabled = true;
        Ok(())
    }

    #[cfg(windows)]
    pub fn disable(&mut self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        use windows::Win32::System::Threading::{
            GetCurrentProcess, SetPriorityClass, NORMAL_PRIORITY_CLASS,
        };
        unsafe {
            let handle = GetCurrentProcess();
            let _ = SetPriorityClass(handle, NORMAL_PRIORITY_CLASS);
        }
        info!("Self-defense disabled: process priority restored to NORMAL");
        self.enabled = false;
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn disable(&mut self) -> Result<(), String> {
        self.enabled = false;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Drop for SelfDefense {
    fn drop(&mut self) {
        let _ = self.disable();
    }
}
