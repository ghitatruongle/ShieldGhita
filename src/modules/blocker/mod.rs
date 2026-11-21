use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::info;

#[cfg(windows)]
use windows::core::PWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(any(windows, test))]
#[allow(dead_code)]
mod lockdown;

#[cfg(windows)]
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0,
    FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
    FWPM_SUBLAYER_UNIVERSAL, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE,
    FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_MATCH_EQUAL, FWP_UINT32, FWP_UINT8,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
};
#[cfg(windows)]
use windows::Win32::Security::PSECURITY_DESCRIPTOR;

pub struct WfpBlocker {
    enabled: Arc<AtomicBool>,
    available: Arc<AtomicBool>,
    lockdown: Arc<AtomicBool>,
    #[cfg(windows)]
    engine_handle: std::sync::Mutex<Option<HANDLE>>,
    #[cfg(windows)]
    filter_ids: std::sync::Mutex<Vec<u64>>,
    #[cfg(windows)]
    lockdown_filter_ids: std::sync::Mutex<Vec<u64>>,
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
            available: Arc::new(AtomicBool::new(false)),
            lockdown: Arc::new(AtomicBool::new(false)),
            #[cfg(windows)]
            engine_handle: std::sync::Mutex::new(None),
            #[cfg(windows)]
            filter_ids: std::sync::Mutex::new(Vec::new()),
            #[cfg(windows)]
            lockdown_filter_ids: std::sync::Mutex::new(Vec::new()),
            blocked_ips: std::sync::RwLock::new(Vec::new()),
            blocked_ports: std::sync::RwLock::new(Vec::new()),
        }
    }

    /// False when the WFP engine could not be opened (service stopped, policy,
    /// or not elevated). Callers must surface this instead of pretending the
    /// IP/port blocking is active.
    pub fn is_available(&self) -> bool {
        self.available.load(Ordering::SeqCst)
    }

    pub fn unavailable_reason() -> String {
        crate::modules::i18n::tr4(
            "Windows Filtering Platform không khả dụng — chặn IP/cổng bị tắt.",
            "Windows Filtering Platform unavailable — IP/port blocking is off.",
            "Windows 过滤平台不可用 — IP/端口拦截已关闭。",
            "Фильтрация Windows недоступна — блокировка IP/портов отключена.",
        )
        .to_string()
    }

    #[cfg(windows)]
    pub fn initialize(&self) -> Result<(), String> {
        let mut handle = self.engine_handle.lock().map_err(|e| e.to_string())?;
        if handle.is_some() {
            return Ok(());
        }
        let mut engine_handle = HANDLE::default();
        unsafe {
            let session =
                windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SESSION0 {
                    flags:
                        windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SESSION_FLAG_DYNAMIC,
                    ..Default::default()
                };
            // RPC_C_AUTHN_WINNT is the authn service BFE accepts; passing 0
            // (RPC_C_AUTHN_NONE) fails with error 50 on every machine.
            const RPC_C_AUTHN_WINNT: u32 = 10;
            let result = FwpmEngineOpen0(
                None,
                RPC_C_AUTHN_WINNT,
                None,
                Some(&session),
                &mut engine_handle,
            );
            if result != 0 {
                self.available.store(false, Ordering::SeqCst);
                return Err(format!(
                    "FwpmEngineOpen0 failed with error code: {}",
                    result
                ));
            }
        }
        *handle = Some(engine_handle);
        self.available.store(true, Ordering::SeqCst);
        info!("WFP engine initialized successfully");
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn initialize(&self) -> Result<(), String> {
        self.available.store(false, Ordering::SeqCst);
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
    fn add_block_filter(
        &self,
        engine: HANDLE,
        layer: windows::core::GUID,
        cond: FWPM_FILTER_CONDITION0,
        display_name: &str,
        description: &str,
    ) -> Result<u64, String> {
        let mut conditions = [cond];
        self.add_filter(
            engine,
            layer,
            &mut conditions,
            FWP_ACTION_BLOCK,
            None,
            display_name,
            description,
        )
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    fn add_filter(
        &self,
        engine: HANDLE,
        layer: windows::core::GUID,
        conditions: &mut [FWPM_FILTER_CONDITION0],
        action: FWP_ACTION_TYPE,
        weight: Option<u8>,
        display_name: &str,
        description: &str,
    ) -> Result<u64, String> {
        let name = wide_static(display_name);
        let desc = wide_static(description);
        let mut filter = FWPM_FILTER0::default();
        filter.displayData.name = PWSTR(name.as_ptr() as *mut u16);
        filter.displayData.description = PWSTR(desc.as_ptr() as *mut u16);
        filter.layerKey = layer;
        filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
        filter.action.r#type = action;
        if let Some(level) = weight {
            filter.weight.r#type = FWP_UINT8;
            filter.weight.Anonymous.uint8 = level;
        }
        filter.numFilterConditions = u32::try_from(conditions.len()).unwrap_or(u32::MAX);
        filter.filterCondition = if conditions.is_empty() {
            std::ptr::null_mut()
        } else {
            conditions.as_mut_ptr()
        };
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
            return Err(format!("FwpmFilterAdd0 {display_name} failed: {status}"));
        }
        Ok(id)
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
            match ip.trim().parse::<IpAddr>() {
                Ok(IpAddr::V4(_)) => {
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
                    match self.add_block_filter(
                        engine,
                        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        cond,
                        &format!("ShieldGhita block IP {ip}"),
                        "ShieldGhita custom IPv4 block (ALE connect)",
                    ) {
                        Ok(id) => {
                            if let Ok(mut fids) = self.filter_ids.lock() {
                                fids.push(id);
                            }
                            installed += 1;
                        }
                        Err(e) => failures.push(e),
                    }
                }
                Ok(IpAddr::V6(v6)) => {
                    let mut raw = FWP_BYTE_ARRAY16 {
                        byteArray16: v6.octets(),
                    };
                    let mut cond = FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        matchType: FWP_MATCH_EQUAL,
                        ..Default::default()
                    };
                    cond.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                    cond.conditionValue.Anonymous.byteArray16 = &mut raw;
                    match self.add_block_filter(
                        engine,
                        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                        cond,
                        &format!("ShieldGhita block IP {ip}"),
                        "ShieldGhita custom IPv6 block (ALE connect)",
                    ) {
                        Ok(id) => {
                            if let Ok(mut fids) = self.filter_ids.lock() {
                                fids.push(id);
                            }
                            installed += 1;
                        }
                        Err(e) => failures.push(e),
                    }
                }
                Err(_) => failures.push(format!("invalid IP address: {ip}")),
            }
        }

        for port in &ports {
            if *port == 0 {
                failures.push("port 0 is not a valid WFP block target".into());
                continue;
            }
            for layer in [
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            ] {
                let mut cond = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_LOCAL_PORT,
                    matchType: FWP_MATCH_EQUAL,
                    ..Default::default()
                };
                cond.conditionValue.r#type = FWP_UINT32;
                cond.conditionValue.Anonymous.uint32 = u32::from(*port);
                match self.add_block_filter(
                    engine,
                    layer,
                    cond,
                    &format!("ShieldGhita block local port {port}"),
                    "ShieldGhita custom local-port block (ALE accept, v4+v6)",
                ) {
                    Ok(id) => {
                        if let Ok(mut fids) = self.filter_ids.lock() {
                            fids.push(id);
                        }
                        installed += 1;
                    }
                    Err(e) => failures.push(e),
                }
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

    pub fn is_lockdown_active(&self) -> bool {
        self.lockdown.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    pub fn lockdown_unavailable_reason() -> String {
        crate::modules::i18n::tr4(
            "Chặn Internet bằng WFP không khả dụng (cần quyền Admin và dịch vụ BFE) — chỉ khóa DNS đang hoạt động.",
            "WFP internet lockdown unavailable (needs Administrator and the BFE service) — only the DNS lock is active.",
            "WFP 断网不可用（需要管理员权限和 BFE 服务）— 仅 DNS 锁定生效。",
            "Блокировка через WFP недоступна (нужны права администратора и служба BFE) — активна только блокировка DNS.",
        )
        .to_string()
    }

    #[cfg(windows)]
    pub fn enable_lockdown(&self) -> Result<(), String> {
        if lockdown::transition(self.lockdown.load(Ordering::SeqCst))
            == lockdown::Transition::AlreadyActive
        {
            return Ok(());
        }
        self.initialize()?;
        self.clear_lockdown_filters()?;
        let engine = self.engine()?;
        let rules = lockdown::plan();
        match lockdown::run(&rules, |rule| self.add_lockdown_rule(engine, rule)) {
            lockdown::Outcome::Armed(ids) => {
                let count = ids.len();
                if let Ok(mut stored) = self.lockdown_filter_ids.lock() {
                    stored.extend_from_slice(&ids);
                }
                self.lockdown.store(true, Ordering::SeqCst);
                info!(
                    "WFP lockdown armed: {count} filter(s) — local ranges permitted, all other outbound blocked"
                );
                Ok(())
            }
            lockdown::Outcome::RolledBack(installed, error) => {
                let rolled_back = installed.len();
                self.delete_filters(engine, &installed);
                self.lockdown.store(false, Ordering::SeqCst);
                Err(format!(
                    "WFP lockdown failed, {rolled_back} filter(s) rolled back: {error}"
                ))
            }
        }
    }

    #[cfg(not(windows))]
    pub fn enable_lockdown(&self) -> Result<(), String> {
        Err("WFP lockdown is only available on Windows".into())
    }

    #[cfg(windows)]
    pub fn disable_lockdown(&self) -> Result<(), String> {
        self.clear_lockdown_filters()?;
        self.lockdown.store(false, Ordering::SeqCst);
        info!("WFP lockdown released");
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn disable_lockdown(&self) -> Result<(), String> {
        self.lockdown.store(false, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(windows)]
    fn engine(&self) -> Result<HANDLE, String> {
        let hg = self.engine_handle.lock().map_err(|e| e.to_string())?;
        match *hg {
            Some(handle) => Ok(handle),
            None => Err("WFP engine is not open".into()),
        }
    }

    #[cfg(windows)]
    fn delete_filters(&self, engine: HANDLE, ids: &[u64]) {
        for id in ids {
            unsafe {
                let _ = FwpmFilterDeleteById0(engine, *id);
            }
        }
    }

    #[cfg(windows)]
    fn lockdown_layer_key(layer: lockdown::Layer) -> windows::core::GUID {
        match layer {
            lockdown::Layer::AuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            lockdown::Layer::AuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            lockdown::Layer::FlowEstablishedV4 => FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
            lockdown::Layer::FlowEstablishedV6 => FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
        }
    }

    #[cfg(windows)]
    fn add_lockdown_rule(&self, engine: HANDLE, rule: &lockdown::Rule) -> Result<u64, String> {
        match rule {
            lockdown::Rule::BlockAll(layer) => self.add_filter(
                engine,
                Self::lockdown_layer_key(*layer),
                &mut [],
                FWP_ACTION_BLOCK,
                Some(lockdown::BLOCK_WEIGHT),
                "ShieldGhita Master Lock (block all outbound)",
                "ShieldGhita Master Internet Lock: every outbound connection outside the local ranges is blocked",
            ),
            lockdown::Rule::PermitV4(layer, index) => {
                let range = lockdown::PERMIT_V4[*index];
                let mut address_mask = FWP_V4_ADDR_AND_MASK {
                    addr: range.addr,
                    mask: range.mask,
                };
                let mut condition = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    ..Default::default()
                };
                condition.conditionValue.r#type = FWP_V4_ADDR_MASK;
                condition.conditionValue.Anonymous.v4AddrMask = &mut address_mask;
                let mut conditions = [condition];
                let name = format!("ShieldGhita Master Lock allow {}", range.label);
                self.add_filter(
                    engine,
                    Self::lockdown_layer_key(*layer),
                    &mut conditions,
                    FWP_ACTION_PERMIT,
                    Some(lockdown::PERMIT_WEIGHT),
                    &name,
                    "ShieldGhita Master Internet Lock: local IPv4 traffic stays reachable",
                )
            }
            lockdown::Rule::PermitV6(layer, index) => {
                let range = lockdown::PERMIT_V6[*index];
                let mut address_mask = FWP_V6_ADDR_AND_MASK {
                    addr: range.addr,
                    prefixLength: range.prefix,
                };
                let mut condition = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    ..Default::default()
                };
                condition.conditionValue.r#type = FWP_V6_ADDR_MASK;
                condition.conditionValue.Anonymous.v6AddrMask = &mut address_mask;
                let mut conditions = [condition];
                let name = format!("ShieldGhita Master Lock allow {}", range.label);
                self.add_filter(
                    engine,
                    Self::lockdown_layer_key(*layer),
                    &mut conditions,
                    FWP_ACTION_PERMIT,
                    Some(lockdown::PERMIT_WEIGHT),
                    &name,
                    "ShieldGhita Master Internet Lock: local IPv6 traffic stays reachable",
                )
            }
        }
    }

    #[cfg(windows)]
    fn clear_lockdown_filters(&self) -> Result<(), String> {
        let engine = {
            let hg = self.engine_handle.lock().map_err(|e| e.to_string())?;
            *hg
        };
        let mut ids = self.lockdown_filter_ids.lock().map_err(|e| e.to_string())?;
        if let Some(handle) = engine {
            self.delete_filters(handle, &ids);
        }
        ids.clear();
        Ok(())
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
            if let Ok(mut lids) = self.lockdown_filter_ids.lock() {
                for id in lids.drain(..) {
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
        } else {
            if let Ok(mut fids) = self.filter_ids.lock() {
                fids.clear();
            }
            if let Ok(mut lids) = self.lockdown_filter_ids.lock() {
                lids.clear();
            }
        }
        self.enabled.store(false, Ordering::SeqCst);
        self.lockdown.store(false, Ordering::SeqCst);
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

    #[test]
    fn lockdown_defaults_to_inactive() {
        let b = super::WfpBlocker::new();
        assert!(!b.is_lockdown_active());
        assert!(!b.is_enabled());
    }

    #[test]
    fn disable_lockdown_is_idempotent_without_an_engine() {
        let b = super::WfpBlocker::new();
        assert!(b.disable_lockdown().is_ok());
        assert!(b.disable_lockdown().is_ok());
        assert!(!b.is_lockdown_active());
    }

    #[test]
    fn lockdown_unavailable_reason_is_user_facing() {
        let reason = super::WfpBlocker::lockdown_unavailable_reason();
        assert!(reason.len() > 20);
        assert!(reason.contains("WFP"));
    }

    #[test]
    fn lockdown_does_not_claim_availability_before_initialize() {
        let b = super::WfpBlocker::new();
        assert!(!b.is_available());
    }
}
