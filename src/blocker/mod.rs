use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterDeleteById0,
};

pub struct WfpBlocker {
    enabled: Arc<AtomicBool>,
    #[cfg(windows)]
    engine_handle: std::sync::Mutex<Option<HANDLE>>,
    #[cfg(windows)]
    filter_ids: std::sync::Mutex<Vec<u64>>,
    blocked_ips: std::sync::RwLock<Vec<String>>,
    blocked_ports: std::sync::RwLock<Vec<u16>>,
}

#[cfg(windows)]
unsafe impl Send for WfpBlocker {}
#[cfg(windows)]
unsafe impl Sync for WfpBlocker {}

impl WfpBlocker {
    pub fn new() -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(false)),
            #[cfg(windows)]
            engine_handle: std::sync::Mutex::new(None),
            #[cfg(windows)]
            filter_ids: std::sync::Mutex::new(Vec::new()),
            blocked_ips: std::sync::RwLock::new(Vec::new()),
            blocked_ports: std::sync::RwLock::new(Vec::new()),
        }
    }

    #[cfg(windows)]
    pub fn initialize(&self) -> Result<(), String> {
        let mut handle = self.engine_handle.lock().map_err(|e| e.to_string())?;
        if handle.is_some() { return Ok(()); }
        let mut engine_handle = HANDLE::default();
        unsafe {
            let result = FwpmEngineOpen0(None, 0, None, None, &mut engine_handle);
            if result != 0 { return Err(format!("FwpmEngineOpen0 failed with error code: {}", result)); }
        }
        *handle = Some(engine_handle);
        info!("WFP engine initialized successfully");
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn initialize(&self) -> Result<(), String> {
        warn!("WFP is only available on Windows");
        Ok(())
    }

    pub fn add_blocked_ip(&self, ip: &str) -> Result<(), String> {
        let mut ips = self.blocked_ips.write().map_err(|e| e.to_string())?;
        if !ips.contains(&ip.to_string()) { ips.push(ip.to_string()); }
        Ok(())
    }

    pub fn remove_blocked_ip(&self, ip: &str) -> Result<(), String> {
        let mut ips = self.blocked_ips.write().map_err(|e| e.to_string())?;
        ips.retain(|i| i != ip);
        Ok(())
    }

    pub fn add_blocked_port(&self, port: u16) -> Result<(), String> {
        let mut ports = self.blocked_ports.write().map_err(|e| e.to_string())?;
        if !ports.contains(&port) { ports.push(port); }
        Ok(())
    }

    pub fn remove_blocked_port(&self, port: u16) -> Result<(), String> {
        let mut ports = self.blocked_ports.write().map_err(|e| e.to_string())?;
        ports.retain(|p| p != &port);
        Ok(())
    }

    pub fn get_blocked_ips(&self) -> Vec<String> {
        self.blocked_ips.read().map(|v| v.clone()).unwrap_or_default()
    }

    pub fn get_blocked_ports(&self) -> Vec<u16> {
        self.blocked_ports.read().map(|v| v.clone()).unwrap_or_default()
    }

    #[cfg(windows)]
    pub fn enable(&self) -> Result<(), String> {
        if self.enabled.load(Ordering::Relaxed) { return Ok(()); }
        self.initialize()?;
        self.clear_filters()?;
        let ips = self.get_blocked_ips();
        let ports = self.get_blocked_ports();
        info!("WFP blocker enabled with {} IPs and {} ports", ips.len(), ports.len());
        self.enabled.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn enable(&self) -> Result<(), String> {
        self.enabled.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(windows)]
    pub fn disable(&self) -> Result<(), String> {
        if !self.enabled.load(Ordering::Relaxed) { return Ok(()); }
        self.clear_filters()?;
        self.enabled.store(false, Ordering::SeqCst);
        info!("WFP blocker disabled");
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn disable(&self) -> Result<(), String> {
        self.enabled.store(false, Ordering::SeqCst);
        Ok(())
    }

    pub fn is_enabled(&self) -> bool { self.enabled.load(Ordering::Relaxed) }

    #[cfg(windows)]
    fn clear_filters(&self) -> Result<(), String> {
        let hg = self.engine_handle.lock().map_err(|e| e.to_string())?;
        let engine = match *hg { Some(h) => h, None => return Ok(()) };
        let mut fids = self.filter_ids.lock().map_err(|e| e.to_string())?;
        for id in fids.drain(..) { unsafe { let _ = FwpmFilterDeleteById0(engine, id); } }
        Ok(())
    }

    #[cfg(windows)]
    pub fn shutdown(&self) {
        let _ = self.disable();
        let mut handle = match self.engine_handle.lock() { Ok(h) => h, Err(_) => return };
        if let Some(h) = handle.take() { unsafe { let _ = FwpmEngineClose0(h); } }
    }

    #[cfg(not(windows))]
    pub fn shutdown(&self) { let _ = self.disable(); }
}

impl Drop for WfpBlocker {
    fn drop(&mut self) { self.shutdown(); }
}
