use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use sysinfo::System;
use tracing::warn;

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
}

impl ConnectionTracker {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_processes();
        Self {
            connections: Arc::new(RwLock::new(Vec::new())),
            system: Arc::new(RwLock::new(sys)),
        }
    }

    pub fn get_active_connections(&self) -> Vec<ActiveConnection> {
        self.connections.read().map(|c| c.clone()).unwrap_or_default()
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
                    format!("{}, {} (+{} khác)", remotes[0], remotes[1], remotes.len() - 2)
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
                    list.first().map(|c| c.state.clone()).unwrap_or_else(|| "ACTIVE".into())
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

        groups.sort_by(|a, b| b.connection_count.cmp(&a.connection_count));
        groups
    }

    pub fn refresh_connections(&self) {
        let mut proc_map: HashMap<u32, String> = HashMap::new();
        if let Ok(mut sys) = self.system.write() {
            sys.refresh_processes();
            for (pid, proc) in sys.processes() {
                proc_map.insert(pid.as_u32(), proc.name().to_string());
            }
        }

        let output = match crate::dns_manager::silent_command("netstat")
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
