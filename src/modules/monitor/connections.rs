use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use sysinfo::System;
use tracing::warn;

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct MibTcpRowOwnerPid {
    dw_state: u32,
    dw_local_addr: u32,
    dw_local_port: u32,
    dw_remote_addr: u32,
    dw_remote_port: u32,
    dw_owning_pid: u32,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct MibUdpRowOwnerPid {
    dw_local_addr: u32,
    dw_local_port: u32,
    dw_owning_pid: u32,
}

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        p_tcp_table: *mut std::ffi::c_void,
        pdw_size: *mut u32,
        b_order: i32,
        ul_af: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;

    fn GetExtendedUdpTable(
        p_udp_table: *mut std::ffi::c_void,
        pdw_size: *mut u32,
        b_order: i32,
        ul_af: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveConnection {
    pub process_name: String,
    pub pid: u32,
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub state: String,
    pub is_safe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConnectionGroup {
    pub process_name: String,
    pub pid: u32,
    pub connection_count: usize,
    pub destinations_summary: String,
    pub protocol_summary: String,
    pub state_summary: String,
    pub is_safe: bool,
}

pub struct ConnectionTracker {
    connections: Arc<RwLock<Vec<ActiveConnection>>>,
    system: Arc<RwLock<System>>,
    proc_map_cache: Arc<RwLock<HashMap<u32, String>>>,
    last_proc_refresh: Arc<RwLock<Option<std::time::Instant>>>,
}

const PROC_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

impl ConnectionTracker {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_processes();
        Self {
            connections: Arc::new(RwLock::new(Vec::new())),
            system: Arc::new(RwLock::new(sys)),
            proc_map_cache: Arc::new(RwLock::new(HashMap::new())),
            last_proc_refresh: Arc::new(RwLock::new(None)),
        }
    }

    pub fn get_active_connections(&self) -> Vec<ActiveConnection> {
        self.connections
            .read()
            .map(|c| c.clone())
            .unwrap_or_default()
    }

    pub fn get_grouped_connections(&self) -> Vec<AppConnectionGroup> {
        let conns = self.get_active_connections();
        let mut map: HashMap<(String, u32), Vec<ActiveConnection>> = HashMap::new();
        for conn in conns {
            map.entry((conn.process_name.clone(), conn.pid))
                .or_default()
                .push(conn);
        }

        let mut groups: Vec<AppConnectionGroup> = map
            .into_iter()
            .map(|((proc_name, pid), list)| {
                let count = list.len();
                let is_safe = list.iter().all(|c| c.is_safe);

                let mut remotes: Vec<String> = Vec::new();
                for c in &list {
                    if !remotes.contains(&c.remote_addr) {
                        remotes.push(c.remote_addr.clone());
                    }
                }

                let destinations_summary = if remotes.len() <= 2 {
                    remotes.join(", ")
                } else {
                    format!(
                        "{}, {} (+{} khác)",
                        remotes[0],
                        remotes[1],
                        remotes.len() - 2
                    )
                };

                let has_tcp = list.iter().any(|c| c.protocol == "TCP");
                let has_udp = list.iter().any(|c| c.protocol == "UDP");
                let protocol_summary = if has_tcp && has_udp {
                    "TCP/UDP".to_string()
                } else if has_tcp {
                    "TCP".to_string()
                } else {
                    "UDP".to_string()
                };

                let state_summary = if list.iter().any(|c| c.state == "ESTABLISHED") {
                    "ESTABLISHED".to_string()
                } else if list.iter().any(|c| c.state == "ACTIVE") {
                    "ACTIVE".to_string()
                } else {
                    list.first()
                        .map(|c| c.state.clone())
                        .unwrap_or_else(|| "ACTIVE".into())
                };

                AppConnectionGroup {
                    process_name: proc_name,
                    pid,
                    connection_count: count,
                    destinations_summary,
                    protocol_summary,
                    state_summary,
                    is_safe,
                }
            })
            .collect();

        groups.sort_by_key(|b| std::cmp::Reverse(b.connection_count));
        groups
    }

    #[cfg(windows)]
    fn get_native_connections(
        &self,
        proc_map: &HashMap<u32, String>,
    ) -> Result<Vec<ActiveConnection>, String> {
        let mut list = Vec::with_capacity(128);

        let mut size = 0u32;
        unsafe {
            let _ = GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, 2, 5, 0);
        }

        if size >= 4 {
            let mut buf: Vec<u8> = vec![0; size as usize];
            let ret =
                unsafe { GetExtendedTcpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, 2, 5, 0) };

            if ret == 0 && buf.len() >= 4 {
                let num_entries = unsafe { *(buf.as_ptr() as *const u32) } as usize;
                let max_entries = (buf.len() - 4) / std::mem::size_of::<MibTcpRowOwnerPid>();
                let safe_entries = num_entries.min(max_entries);
                let rows_ptr = unsafe { buf.as_ptr().add(4) as *const MibTcpRowOwnerPid };

                for i in 0..safe_entries {
                    let row = unsafe { *rows_ptr.add(i) };
                    let pid = row.dw_owning_pid;
                    let local_ip = Ipv4Addr::from(row.dw_local_addr.to_ne_bytes());
                    let local_port = u16::from_be(row.dw_local_port as u16);
                    let remote_ip = Ipv4Addr::from(row.dw_remote_addr.to_ne_bytes());
                    let remote_port = u16::from_be(row.dw_remote_port as u16);

                    let remote_str = format!("{}:{}", remote_ip, remote_port);
                    if remote_ip.is_unspecified() && remote_port == 0 {
                        continue;
                    }

                    let state_str = match row.dw_state {
                        2 => "LISTENING",
                        3 => "SYN_SENT",
                        4 => "SYN_RCVD",
                        5 => "ESTABLISHED",
                        6 => "FIN_WAIT1",
                        7 => "FIN_WAIT2",
                        8 => "CLOSE_WAIT",
                        9 => "CLOSING",
                        10 => "LAST_ACK",
                        11 => "TIME_WAIT",
                        12 => "DELETE_TCB",
                        _ => "ACTIVE",
                    };

                    let proc_name = proc_map.get(&pid).cloned().unwrap_or_else(|| {
                        if pid == 0 {
                            "System Idle".into()
                        } else if pid == 4 {
                            "System Core".into()
                        } else {
                            format!("PID: {}", pid)
                        }
                    });

                    let is_safe = !proc_name.to_lowercase().contains("malware")
                        && !proc_name.to_lowercase().contains("trojan")
                        && !proc_name.to_lowercase().contains("miner");

                    list.push(ActiveConnection {
                        process_name: proc_name,
                        pid,
                        local_addr: format!("{}:{}", local_ip, local_port),
                        remote_addr: remote_str,
                        protocol: "TCP".to_string(),
                        state: state_str.to_string(),
                        is_safe,
                    });
                }
            }
        }

        let mut udp_size = 0u32;
        unsafe {
            let _ = GetExtendedUdpTable(std::ptr::null_mut(), &mut udp_size, 0, 2, 1, 0);
        }

        if udp_size >= 4 {
            let mut buf: Vec<u8> = vec![0; udp_size as usize];
            let ret = unsafe {
                GetExtendedUdpTable(buf.as_mut_ptr() as *mut _, &mut udp_size, 0, 2, 1, 0)
            };

            if ret == 0 && buf.len() >= 4 {
                let num_entries = unsafe { *(buf.as_ptr() as *const u32) } as usize;
                let max_entries = (buf.len() - 4) / std::mem::size_of::<MibUdpRowOwnerPid>();
                let safe_entries = num_entries.min(max_entries);
                let rows_ptr = unsafe { buf.as_ptr().add(4) as *const MibUdpRowOwnerPid };

                for i in 0..safe_entries {
                    let row = unsafe { *rows_ptr.add(i) };
                    let pid = row.dw_owning_pid;
                    let local_ip = Ipv4Addr::from(row.dw_local_addr.to_ne_bytes());
                    let local_port = u16::from_be(row.dw_local_port as u16);

                    let proc_name = proc_map.get(&pid).cloned().unwrap_or_else(|| {
                        if pid == 4 {
                            "System Core".into()
                        } else {
                            format!("PID: {}", pid)
                        }
                    });

                    list.push(ActiveConnection {
                        process_name: proc_name,
                        pid,
                        local_addr: format!("{}:{}", local_ip, local_port),
                        remote_addr: "*:*".to_string(),
                        protocol: "UDP".to_string(),
                        state: "ACTIVE".to_string(),
                        is_safe: true,
                    });
                }
            }
        }

        Ok(list)
    }

    pub fn refresh_connections(&self) {
        let need_refresh = self
            .last_proc_refresh
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .map(|t| t.elapsed() >= PROC_REFRESH_INTERVAL)
            .unwrap_or(true);

        if need_refresh {
            let mut proc_map: HashMap<u32, String> = HashMap::new();
            if let Ok(mut sys) = self.system.write() {
                sys.refresh_processes();
                for (pid, proc) in sys.processes() {
                    proc_map.insert(pid.as_u32(), proc.name().to_string());
                }
            }
            if let Ok(mut cache) = self.proc_map_cache.write() {
                *cache = proc_map;
            }
            if let Ok(mut last) = self.last_proc_refresh.write() {
                *last = Some(std::time::Instant::now());
            }
        }

        let proc_map = self
            .proc_map_cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        #[cfg(windows)]
        {
            if let Ok(mut list) = self.get_native_connections(&proc_map) {
                if list.len() > 150 {
                    list.truncate(150);
                }
                if let Ok(mut conns) = self.connections.write() {
                    *conns = list;
                }
                return;
            }
        }

        let output = match crate::modules::system::silent_command("netstat")
            .args(["-ano"])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                warn!("Failed to query netstat: {}", e);
                return;
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut list = Vec::new();

        for line in stdout.lines() {
            let line = line.trim();
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let proto = parts[0].to_uppercase();
            if proto == "TCP" && parts.len() >= 5 {
                let local = parts[1].to_string();
                let remote = parts[2].to_string();
                let state = parts[3].to_string();
                let pid_str = parts[4];
                let pid: u32 = pid_str.parse().unwrap_or(0);

                if remote == "*:*" || remote == "0.0.0.0:0" || remote == "[::]:0" {
                    continue;
                }

                let proc_name = proc_map.get(&pid).cloned().unwrap_or_else(|| {
                    if pid == 0 {
                        "System Idle".into()
                    } else if pid == 4 {
                        "System Core".into()
                    } else {
                        format!("PID: {}", pid)
                    }
                });

                let is_safe = !proc_name.to_lowercase().contains("malware")
                    && !proc_name.to_lowercase().contains("trojan")
                    && !proc_name.to_lowercase().contains("miner");

                list.push(ActiveConnection {
                    process_name: proc_name,
                    pid,
                    local_addr: local,
                    remote_addr: remote,
                    protocol: "TCP".to_string(),
                    state,
                    is_safe,
                });
            } else if proto == "UDP" && parts.len() >= 4 {
                let local = parts[1].to_string();
                let remote = parts[2].to_string();
                let pid_str = parts[3];
                let pid: u32 = pid_str.parse().unwrap_or(0);

                if remote == "*:*" {
                    continue;
                }

                let proc_name = proc_map.get(&pid).cloned().unwrap_or_else(|| {
                    if pid == 4 {
                        "System Core".into()
                    } else {
                        format!("PID: {}", pid)
                    }
                });

                list.push(ActiveConnection {
                    process_name: proc_name,
                    pid,
                    local_addr: local,
                    remote_addr: remote,
                    protocol: "UDP".to_string(),
                    state: "ACTIVE".to_string(),
                    is_safe: true,
                });
            }
        }

        if list.len() > 150 {
            list.truncate(150);
        }

        if let Ok(mut conns) = self.connections.write() {
            *conns = list;
        }
    }
}
