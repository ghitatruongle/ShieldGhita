use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::info;

#[cfg(windows)]
use windows::core::PWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0,
    FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_SUBLAYER_UNIVERSAL, FWP_ACTION_BLOCK, FWP_MATCH_EQUAL, FWP_UINT32,
};
#[cfg(windows)]
use windows::Win32::Security::PSECURITY_DESCRIPTOR;

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

#[cfg(windows)]
fn wide_static(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn parse_ipv4_host_order(ip: &str) -> Result<u32, String> {
    let addr: Ipv4Addr = ip
        .trim()
        .parse()
        .map_err(|_| format!("invalid IPv4 address: {ip}"))?;
    // WFP remote-address conditions use host-order UINT32.
    Ok(u32::from(addr))
}

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
        if handle.is_some() {
            return Ok(());
        }
        let mut engine_handle = HANDLE::default();
        unsafe {
            let result = FwpmEngineOpen0(None, 0, None, None, &mut engine_handle);
            if result != 0 {
                return Err(format!(
                    "FwpmEngineOpen0 failed with error code: {}",
                    result
                ));
            }
        }
        *handle = Some(engine_handle);
        info!("WFP engine initialized successfully");
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn initialize(&self) -> Result<(), String> {
        Ok(())
    }

    pub fn get_blocked_ips(&self) -> Vec<String> {
        self.blocked_ips
            .read()
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    pub fn get_blocked_ports(&self) -> Vec<u16> {
        self.blocked_ports
            .read()
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    pub fn set_blocked_ips(&self, ips: Vec<String>) {
        if let Ok(mut g) = self.blocked_ips.write() {
            *g = ips;
        }
    }

    pub fn set_blocked_ports(&self, ports: Vec<u16>) {
        if let Ok(mut g) = self.blocked_ports.write() {
            *g = ports;
        }
    }

    #[cfg(windows)]
    pub fn enable(&self) -> Result<(), String> {
        if self.enabled.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.initialize()?;
        self.clear_filters()?;
        let ips = self.get_blocked_ips();
        let ports = self.get_blocked_ports();

        if ips.is_empty() && ports.is_empty() {
            info!(
                "WFP engine ready (no custom IP/port rules configured — DNS blocker is the active enforcement path)"
            );
            self.enabled.store(true, Ordering::SeqCst);
            return Ok(());
        }

        let engine = {
            let hg = self.engine_handle.lock().map_err(|e| e.to_string())?;
            match *hg {
                Some(h) => h,
                None => return Err("WFP engine is not open".into()),
            }
        };

        let mut installed = 0usize;
        let mut failures: Vec<String> = Vec::new();

        for ip in &ips {
            let host = match parse_ipv4_host_order(ip) {
                Ok(v) => v,
                Err(e) => {
                    failures.push(e);
                    continue;
                }
            };
            let mut cond = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                ..Default::default()
            };
            cond.conditionValue.r#type = FWP_UINT32;
            cond.conditionValue.Anonymous.uint32 = host;
            let name = wide_static(&format!("ShieldGhita block IP {ip}"));
            let desc = wide_static("ShieldGhita custom IP block (ALE connect)");
            // Rebuild filter locally so name/desc live for the call.
            let mut filter = FWPM_FILTER0::default();
            filter.displayData.name = PWSTR(name.as_ptr() as *mut u16);
            filter.displayData.description = PWSTR(desc.as_ptr() as *mut u16);
            filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
            filter.action.r#type = FWP_ACTION_BLOCK;
            filter.numFilterConditions = 1;
            filter.filterCondition = &mut cond;
            let mut id: u64 = 0;
            let status = unsafe {
                FwpmFilterAdd0(
                    engine,
                    &filter,
                    PSECURITY_DESCRIPTOR::default(),
                    Some(&mut id),
                )
            };
            if status != 0 {
                failures.push(format!("FwpmFilterAdd0 IP {ip} failed: {status}"));
            } else {
                if let Ok(mut fids) = self.filter_ids.lock() {
                    fids.push(id);
                }
                installed += 1;
            }
        }

        for port in &ports {
            if *port == 0 {
                failures.push("port 0 is not a valid WFP block target".into());
                continue;
            }
            let mut cond = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_LOCAL_PORT,
                matchType: FWP_MATCH_EQUAL,
                ..Default::default()
            };
            cond.conditionValue.r#type = FWP_UINT32;
            cond.conditionValue.Anonymous.uint32 = u32::from(*port);
            let name = wide_static(&format!("ShieldGhita block local port {port}"));
            let desc = wide_static("ShieldGhita custom local-port block (ALE accept)");
            let mut filter = FWPM_FILTER0::default();
            filter.displayData.name = PWSTR(name.as_ptr() as *mut u16);
            filter.displayData.description = PWSTR(desc.as_ptr() as *mut u16);
            filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
            filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
            filter.action.r#type = FWP_ACTION_BLOCK;
            filter.numFilterConditions = 1;
            filter.filterCondition = &mut cond;
            let mut id: u64 = 0;
            let status = unsafe {
                FwpmFilterAdd0(
                    engine,
                    &filter,
                    PSECURITY_DESCRIPTOR::default(),
                    Some(&mut id),
                )
            };
            if status != 0 {
                failures.push(format!("FwpmFilterAdd0 port {port} failed: {status}"));
            } else {
                if let Ok(mut fids) = self.filter_ids.lock() {
                    fids.push(id);
                }
                installed += 1;
            }
        }

        if !failures.is_empty() {
            let _ = self.clear_filters();
            return Err(format!(
                "WFP custom rules incomplete ({installed} installed, {} failed): {}",
                failures.len(),
                failures.join("; ")
            ));
        }

        info!("WFP custom rules installed: {installed} filter(s)");
        self.enabled.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn enable(&self) -> Result<(), String> {
        let ips = self.get_blocked_ips();
        let ports = self.get_blocked_ports();
        if !ips.is_empty() || !ports.is_empty() {
            return Err("WFP custom IP/port rules are only available on Windows".into());
        }
        self.enabled.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(windows)]
    pub fn disable(&self) -> Result<(), String> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(());
        }
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

    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    #[cfg(windows)]
    fn clear_filters(&self) -> Result<(), String> {
        let hg = self.engine_handle.lock().map_err(|e| e.to_string())?;
        let engine = match *hg {
            Some(h) => h,
            None => return Ok(()),
        };
        let mut fids = self.filter_ids.lock().map_err(|e| e.to_string())?;
        for id in fids.drain(..) {
            unsafe {
                let _ = FwpmFilterDeleteById0(engine, id);
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    pub fn shutdown(&self) {
        let mut handle = match self.engine_handle.lock() {
            Ok(h) => h,
            Err(_) => return,
        };
        if let Some(engine) = *handle {
            if let Ok(mut fids) = self.filter_ids.lock() {
                for id in fids.drain(..) {
                    unsafe {
                        let _ = FwpmFilterDeleteById0(engine, id);
                    }
                }
            }
            if let Some(h) = handle.take() {
                unsafe {
                    let _ = FwpmEngineClose0(h);
                }
            }
        } else if let Ok(mut fids) = self.filter_ids.lock() {
            fids.clear();
        }
        self.enabled.store(false, Ordering::SeqCst);
    }

    #[cfg(not(windows))]
    pub fn shutdown(&self) {
        let _ = self.disable();
    }
}

impl Drop for WfpBlocker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn parse_ipv4_accepts_dotted_quad() {
        use super::parse_ipv4_host_order;
        assert_eq!(parse_ipv4_host_order("1.2.3.4").unwrap(), 0x01020304);
        assert!(parse_ipv4_host_order("not-an-ip").is_err());
        assert!(parse_ipv4_host_order("2001:db8::1").is_err());
    }

    #[test]
    fn empty_rules_do_not_claim_custom_enforcement() {
        let b = super::WfpBlocker::new();
        assert!(b.get_blocked_ips().is_empty());
        assert!(b.get_blocked_ports().is_empty());
        let _ = b;
    }

    #[test]
    fn set_blocked_lists_roundtrip() {
        let b = super::WfpBlocker::new();
        b.set_blocked_ips(vec!["10.0.0.1".into()]);
        b.set_blocked_ports(vec![445, 3389]);
        assert_eq!(b.get_blocked_ips(), vec!["10.0.0.1".to_string()]);
        assert_eq!(b.get_blocked_ports(), vec![445, 3389]);
    }
}
