use serde::{Deserialize, Serialize};

pub const MAX_FRAME_BYTES: u32 = 262_144;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "t")]
pub enum CoreRequest {
    Hello {
        token: String,
    },
    Ping,
    Snapshot {
        tab: i32,
        known_hash: u64,
    },
    Protection {
        on: bool,
    },
    Lock {
        on: bool,
    },
    Pause {
        mins: u64,
    },
    Resume,
    Policy {
        ip: String,
        mode: i32,
        remove: bool,
    },
    Quarantine {
        ip: String,
        on: bool,
    },
    Sinkhole {
        on: bool,
    },
    NetworkWide {
        on: bool,
    },
    ConfigPatch {
        field: String,
        value: bool,
    },
    Rescan,
    Attack {
        ip: String,
        message: String,
        mode: u8,
        mins: i64,
    },
    AttackCancel {
        ip: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "t")]
pub enum CoreResponse {
    Ok,
    Err { code: String },
    Snapshot(Box<CoreSnapshot>),
}

pub const CAP_DEVICES: usize = 256;
pub const CAP_INCIDENTS: usize = 100;
pub const CAP_LOGS: usize = 300;
pub const CAP_GROUPED: usize = 100;
pub const CAP_CONSOLE: usize = 200;
pub const CAP_CONNS: usize = 300;
pub const CAP_QUARANTINE: usize = 100;
pub const CAP_TOP: usize = 10;
pub const CAP_RULES: usize = 100;
#[cfg(feature = "admin")]
pub const CAP_ADMIN_LISTS: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotDevice {
    pub name: String,
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub device_type: String,
    pub os_name: String,
    pub last_domain: String,
    pub last_active: String,
    pub risk_level: String,
    pub open_ports_str: String,
    pub port_risk: String,
    pub port_advice: String,
    pub custom_alias: String,
    pub bandwidth_rate: String,
    pub traffic: String,
    pub is_online: bool,
    pub latency_ms: i32,
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub threats_detected: u64,
    pub confidence: i32,
    pub is_quarantined: bool,
    pub is_local: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotIncident {
    pub id: u64,
    pub time: String,
    pub incident_type: String,
    pub source_ip: String,
    pub details: String,
    pub severity: String,
    pub mitigation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotLogEntry {
    pub timestamp: String,
    pub domain: String,
    pub source_ip: String,
    pub is_blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotGroupedLog {
    pub domain: String,
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub is_blocked: bool,
    pub last_seen: String,
    pub last_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotConsoleLog {
    pub time: String,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotConn {
    pub process_name: String,
    pub pid: u32,
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub state: String,
    pub is_safe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotConnGroup {
    pub process_name: String,
    pub pid: u32,
    pub connection_count: u32,
    pub destinations_summary: String,
    pub protocol_summary: String,
    pub state_summary: String,
    pub is_safe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotCount {
    pub label: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotClientRule {
    pub ip: String,
    pub mode_label: String,
    pub mode_id: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotQuarantineEntry {
    pub entry_id: String,
    pub original_name: String,
    pub original_path: String,
    pub reason: String,
    pub quarantined_at: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotAdblockStats {
    pub top_domains: Vec<SnapshotCount>,
    pub top_clients: Vec<SnapshotCount>,
    pub hourly: Vec<SnapshotCount>,
    pub rules: Vec<SnapshotClientRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotAv {
    pub signature_count: u64,
    pub realtime_enabled: bool,
    pub auto_quarantine: bool,
    pub lock_active: bool,
    pub quarantine: Vec<SnapshotQuarantineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotProximity {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub discovery_method: String,
    pub network_interface: String,
    pub signal_info: String,
    pub last_seen: String,
    pub open_ports_str: String,
    pub latency_ms: i32,
    pub is_online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotBehavior {
    pub ip: String,
    pub hostname: String,
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub threat_queries: u64,
    pub burst_qps: f32,
    pub risk_score: i32,
    pub category: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotAttack {
    pub ip: String,
    pub mode: u8,
    pub message: String,
    pub activated_at: String,
    pub expires_at: String,
    pub hit_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotCamera {
    pub vendor: String,
    pub model_hint: String,
    pub ip: String,
    pub rtsp_url: String,
    pub source: String,
    pub snapshot_url: String,
    pub rtsp_open: bool,
    pub is_default_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CoreSnapshot {
    pub total_queries: u64,
    pub blocked_count: u64,
    pub absorbed_count: u64,
    pub rules_count: u64,
    pub blocked_today: u64,
    pub blocked_week: u64,
    pub protection: bool,
    pub lock: bool,
    pub sinkhole: bool,
    pub paused: bool,
    pub pause_remaining_secs: u64,
    pub cpu: f32,
    pub mem: f32,
    pub live_traffic_rate: String,
    pub sec_score: i32,
    pub score_hint: String,
    pub incidents_count: u64,
    pub lan_devices_count: u64,
    pub is_scanning: bool,
    pub adblock_total_today: u64,
    pub lan_only: bool,
    pub wfp_available: bool,
    pub override_active: bool,
    pub high_risk_count: u64,
    pub wifi_nodes_count: u64,
    pub attack_detection: bool,
    pub auto_block: bool,
    pub arp_spoof: bool,
    pub network_wide: bool,
    pub uptime_secs: u64,
    pub lists_hash: u64,
    pub version: String,
    pub devices: Option<Vec<SnapshotDevice>>,
    pub incidents: Option<Vec<SnapshotIncident>>,
    pub connections: Option<Vec<SnapshotConn>>,
    pub conn_groups: Option<Vec<SnapshotConnGroup>>,
    pub logs: Option<Vec<SnapshotLogEntry>>,
    pub grouped_logs: Option<Vec<SnapshotGroupedLog>>,
    pub console_logs: Option<Vec<SnapshotConsoleLog>>,
    pub adblock: Option<SnapshotAdblockStats>,
    pub av: Option<SnapshotAv>,
    pub proximity: Option<Vec<SnapshotProximity>>,
    pub behaviors: Option<Vec<SnapshotBehavior>>,
    pub attacks: Option<Vec<SnapshotAttack>>,
    pub cameras: Option<Vec<SnapshotCamera>>,
}

pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() as u64 > MAX_FRAME_BYTES as u64 {
        return Err("frame too large".to_string());
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn decode_frame_prefix(prefix: &[u8; 4]) -> Option<usize> {
    let len = u32::from_le_bytes(*prefix);
    if len == 0 || len > MAX_FRAME_BYTES {
        return None;
    }
    Some(len as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_roundtrip_all_variants() {
        let cases = vec![
            CoreRequest::Hello {
                token: "a".repeat(64),
            },
            CoreRequest::Ping,
            CoreRequest::Snapshot {
                tab: 1,
                known_hash: 0,
            },
            CoreRequest::Protection { on: true },
            CoreRequest::Lock { on: false },
            CoreRequest::Pause { mins: 15 },
            CoreRequest::Resume,
            CoreRequest::Policy {
                ip: "192.0.2.50".into(),
                mode: 1,
                remove: false,
            },
            CoreRequest::Quarantine {
                ip: "192.0.2.50".into(),
                on: true,
            },
            CoreRequest::Sinkhole { on: true },
            CoreRequest::NetworkWide { on: false },
            CoreRequest::ConfigPatch {
                field: "attack_detection".into(),
                value: true,
            },
        ];
        for req in cases {
            let json = serde_json::to_vec(&req).unwrap();
            let parsed: CoreRequest = serde_json::from_slice(&json).unwrap();
            assert_eq!(parsed, req);
        }
    }

    #[test]
    fn test_response_roundtrip_all_variants() {
        let cases = vec![
            CoreResponse::Ok,
            CoreResponse::Err {
                code: "lock_failed".into(),
            },
            CoreResponse::Snapshot(Box::new(CoreSnapshot {
                protection: true,
                lock: false,
                paused: false,
                uptime_secs: 42,
                version: "0.1.3".into(),
                ..Default::default()
            })),
        ];
        for resp in cases {
            let json = serde_json::to_vec(&resp).unwrap();
            let parsed: CoreResponse = serde_json::from_slice(&json).unwrap();
            assert_eq!(parsed, resp);
        }
    }

    #[test]
    fn test_frame_encode_decode() {
        let payload = b"{\"t\":\"Ping\"}".to_vec();
        let frame = encode_frame(&payload).unwrap();
        assert_eq!(frame.len(), 4 + payload.len());
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&frame[..4]);
        assert_eq!(decode_frame_prefix(&prefix), Some(payload.len()));
        assert_eq!(&frame[4..], &payload[..]);
    }

    #[test]
    fn test_frame_rejects_oversize_and_zero() {
        let big = vec![0u8; (MAX_FRAME_BYTES + 1) as usize];
        assert!(encode_frame(&big).is_err());
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(decode_frame_prefix(&prefix), None);
        prefix.copy_from_slice(&(MAX_FRAME_BYTES + 1).to_le_bytes());
        assert_eq!(decode_frame_prefix(&prefix), None);
    }
}
