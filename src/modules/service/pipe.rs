use super::protocol::{decode_frame_prefix, encode_frame, CoreRequest, CoreResponse};
use crate::app::AppState;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ServerOptions;
use tracing::{error, info, warn};

pub const PIPE_NAME: &str = r"\\.\pipe\ShieldGhitaCore";

static SERVICE_START: OnceLock<Instant> = OnceLock::new();

pub fn service_start_time() -> Instant {
    *SERVICE_START.get_or_init(Instant::now)
}

pub fn token_path() -> PathBuf {
    std::env::var("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("ShieldGhita")
        .join("core.token")
}

pub fn ensure_token() -> Result<String, String> {
    let path = token_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim().to_string();
        if trimmed.len() >= 64 {
            return Ok(trimmed);
        }
    }
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("csprng: {e}"))?;
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(&path, &token).map_err(|e| format!("write token: {e}"))?;
    let _ = crate::modules::system::dns_manager::silent_command("icacls")
        .args([
            path.to_string_lossy().as_ref(),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:F",
            "/grant:r",
            "*S-1-5-32-544:F",
        ])
        .output();
    Ok(token)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn read_frame<S>(stream: &mut S) -> std::io::Result<Option<Vec<u8>>>
where
    S: AsyncReadExt + Unpin,
{
    let mut prefix = [0u8; 4];
    match stream.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let Some(len) = decode_frame_prefix(&prefix) else {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "bad frame length",
        ));
    };
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

async fn write_frame<S>(stream: &mut S, response: &CoreResponse) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let payload = serde_json::to_vec(response).map_err(|e| std::io::Error::other(e.to_string()))?;
    let frame = encode_frame(&payload).map_err(std::io::Error::other)?;
    stream.write_all(&frame).await
}

pub async fn serve(state: Arc<AppState>) {
    let token = match tokio::task::spawn_blocking(ensure_token).await {
        Ok(Ok(token)) => token,
        _ => {
            warn!("Core IPC: cannot create pipe token — IPC disabled");
            return;
        }
    };
    let mut server = match ServerOptions::new()
        .first_pipe_instance(true)
        .create(PIPE_NAME)
    {
        Ok(server) => server,
        Err(e) => {
            warn!("Core IPC: cannot create pipe {PIPE_NAME} — {e}");
            return;
        }
    };
    info!("Core IPC pipe listening on {PIPE_NAME}");
    loop {
        if let Err(e) = server.connect().await {
            error!("Core IPC: connect error {e}");
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            continue;
        }
        let mut client = server;
        match ServerOptions::new().create(PIPE_NAME) {
            Ok(next) => server = next,
            Err(e) => {
                error!("Core IPC: cannot recreate pipe instance — stopping IPC: {e}");
                return;
            }
        }
        let state = state.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let _ = handle_client(&mut client, state, token).await;
        });
    }
}

async fn handle_client(
    pipe: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    state: Arc<AppState>,
    token: String,
) -> std::io::Result<()> {
    let Some(first) = read_frame(pipe).await? else {
        return Ok(());
    };
    let authenticated = match serde_json::from_slice::<CoreRequest>(&first) {
        Ok(CoreRequest::Hello { token: candidate }) => constant_time_eq(&candidate, &token),
        _ => false,
    };
    if !authenticated {
        warn!("Core IPC: rejected client with bad handshake token");
        write_frame(
            pipe,
            &CoreResponse::Err {
                code: "auth".into(),
            },
        )
        .await?;
        return Ok(());
    }
    write_frame(pipe, &CoreResponse::Ok).await?;
    loop {
        let Some(bytes) = read_frame(pipe).await? else {
            break;
        };
        let Ok(request) = serde_json::from_slice::<CoreRequest>(&bytes) else {
            write_frame(
                pipe,
                &CoreResponse::Err {
                    code: "bad_request".into(),
                },
            )
            .await?;
            continue;
        };
        let response = dispatch(&state, request).await;
        write_frame(pipe, &response).await?;
    }
    Ok(())
}

async fn dispatch(state: &Arc<AppState>, request: CoreRequest) -> CoreResponse {
    match request {
        CoreRequest::Ping => CoreResponse::Ok,
        CoreRequest::Hello { .. } => CoreResponse::Err {
            code: "already_authenticated".into(),
        },
        CoreRequest::Snapshot { tab, known_hash } => {
            CoreResponse::Snapshot(Box::new(super::snapshot::build(state, tab, known_hash)))
        }
        CoreRequest::Policy { ip, mode, remove } => {
            let result = apply_policy(state, &ip, mode, remove);
            info!(
                "Core IPC: policy {} mode={mode} remove={remove} → {:?}",
                ip, result
            );
            result_to_response(result)
        }
        CoreRequest::Quarantine { ip, on } => {
            let result = apply_quarantine(state, &ip, on);
            info!("Core IPC: quarantine {ip} on={on} → {:?}", result);
            result_to_response(result)
        }
        CoreRequest::Sinkhole { on } => {
            state.blocker.set_silent_sinkhole(on);
            info!("Core IPC: silent sinkhole set to {on}");
            CoreResponse::Ok
        }
        CoreRequest::NetworkWide { on } => {
            if let Ok(mut cfg_guard) = state.config.write() {
                cfg_guard.network_wide_adblock_enabled = on;
                let _ = cfg_guard.save();
            }
            crate::modules::system::dns_manager::configure_lan_dns_firewall(on);
            info!("Core IPC: network-wide adblock set to {on}");
            CoreResponse::Ok
        }
        CoreRequest::ConfigPatch { field, value } => {
            let result = apply_config_patch(state, &field, value);
            info!("Core IPC: config patch {field}={value} → {:?}", result);
            result_to_response(result)
        }
        CoreRequest::Rescan => {
            do_rescan(state).await;
            CoreResponse::Ok
        }
        CoreRequest::Attack {
            ip,
            message,
            mode,
            mins,
        } => {
            let result = apply_attack(state, &ip, &message, mode, mins);
            info!(
                "Core IPC: attack {ip} mode={mode} mins={mins} → {:?}",
                result
            );
            result_to_response(result)
        }
        CoreRequest::AttackCancel { ip } => {
            let result = do_cancel_attack(state, ip.trim());
            info!("Core IPC: attack-cancel {ip} → {:?}", result);
            result_to_response(result)
        }
        CoreRequest::Protection { on } => {
            let owned = state.clone();
            let _ = tokio::task::spawn_blocking(move || {
                crate::app::ui_bridge::handlers::apply_protection(&owned, on)
            })
            .await;
            info!("Core IPC: protection set to {on}");
            CoreResponse::Ok
        }
        CoreRequest::Lock { on } => {
            let result = tokio::task::spawn_blocking(move || {
                crate::modules::system::dns_manager::set_master_internet_lock(on)
            })
            .await;
            match result {
                Ok(Ok(())) => {
                    info!("Core IPC: master lock set to {on}");
                    CoreResponse::Ok
                }
                _ => CoreResponse::Err {
                    code: "lock_failed".into(),
                },
            }
        }
        CoreRequest::Pause { mins } => {
            if (1..=720).contains(&mins) {
                state.blocker.adblock.pause_minutes(mins);
                info!("Core IPC: adblock paused {mins}m");
                CoreResponse::Ok
            } else {
                CoreResponse::Err {
                    code: "bad_minutes".into(),
                }
            }
        }
        CoreRequest::Resume => {
            state.blocker.adblock.resume();
            info!("Core IPC: adblock resumed");
            CoreResponse::Ok
        }
    }
}

#[cfg(feature = "admin")]
async fn do_rescan(state: &AppState) {
    state.local_manager.trigger_proximity_sweep().await;
    state.local_manager.trigger_camera_scan().await;
    info!("Core IPC: rescan proximity + cameras done");
}

#[cfg(not(feature = "admin"))]
async fn do_rescan(_state: &AppState) {
    info!("Core IPC: rescan not available in public edition");
}

#[cfg(feature = "admin")]
fn do_cancel_attack(state: &AppState, ip: &str) -> Result<(), &'static str> {
    if state.local_manager.cancel_attack(ip) {
        Ok(())
    } else {
        Err("not_lan")
    }
}

#[cfg(not(feature = "admin"))]
fn do_cancel_attack(_state: &AppState, _ip: &str) -> Result<(), &'static str> {
    Err("not_available")
}

fn result_to_response(result: Result<(), &'static str>) -> CoreResponse {
    match result {
        Ok(()) => CoreResponse::Ok,
        Err(code) => CoreResponse::Err {
            code: code.to_string(),
        },
    }
}

fn apply_policy(
    state: &AppState,
    ip_raw: &str,
    mode_id: i32,
    remove: bool,
) -> Result<(), &'static str> {
    let ip: std::net::IpAddr = ip_raw.trim().parse().map_err(|_| "bad_ip")?;
    if remove {
        state.blocker.adblock.remove_client_rule(&ip);
        persist_client_rules(state);
        return Ok(());
    }
    let mode =
        crate::modules::dns::client_policy::ClientMode::from_id(mode_id).ok_or("bad_mode")?;
    let own_lan_ip = crate::modules::system::dns_manager::get_lan_ip_address();
    let targets_self = ip.is_loopback() || (!own_lan_ip.is_empty() && own_lan_ip == ip.to_string());
    if mode == crate::modules::dns::client_policy::ClientMode::Strict && targets_self {
        return Err("strict_self");
    }
    state.blocker.adblock.set_client_rule(ip, mode);
    persist_client_rules(state);
    Ok(())
}

fn persist_client_rules(state: &AppState) {
    if let Ok(mut cfg_guard) = state.config.write() {
        cfg_guard.adblock_client_rules = state.blocker.adblock.rules_config();
        let _ = cfg_guard.save();
    }
}

fn apply_quarantine(state: &AppState, ip_raw: &str, on: bool) -> Result<(), &'static str> {
    let ip: std::net::Ipv4Addr = ip_raw.trim().parse().map_err(|_| "bad_ip")?;
    let ip_str = ip.to_string();
    if on {
        state
            .security_engine
            .quarantine_ip(&ip_str)
            .map_err(|_| "quarantine_rejected")?;
    } else {
        state.security_engine.unquarantine_ip(&ip_str);
    }
    Ok(())
}

#[cfg(feature = "admin")]
fn apply_attack(
    state: &AppState,
    ip_raw: &str,
    message_raw: &str,
    mode: u8,
    minutes: i64,
) -> Result<(), &'static str> {
    let ip: std::net::IpAddr = ip_raw.trim().parse().map_err(|_| "bad_ip")?;
    let ip_str = ip.to_string();
    if !(1..=720).contains(&minutes) {
        return Err("bad_minutes");
    }
    let mode = mode.clamp(0, 2);
    let message = if message_raw.trim().is_empty() {
        crate::modules::local::attack::AttackRegistry::default_warning_message().to_string()
    } else {
        message_raw.chars().take(200).collect()
    };
    let mut found = None;
    for d in state.monitor.get_lan_devices() {
        if d.ip == ip_str {
            found = Some((d.mac.clone(), d.name.clone()));
            break;
        }
    }
    if found.is_none() {
        for d in state.local_manager.get_devices() {
            if d.ip == ip_str {
                found = Some((d.mac.clone(), d.name.clone()));
                break;
            }
        }
    }
    let Some((mac, hostname)) = found else {
        return Err("not_lan");
    };
    let entry = state
        .local_manager
        .launch_attack(&ip_str, &mac, &hostname, &message, mode, minutes);
    if entry.ip.is_empty() {
        return Err("attack_failed");
    }
    Ok(())
}

#[cfg(not(feature = "admin"))]
fn apply_attack(
    _state: &AppState,
    _ip_raw: &str,
    _message_raw: &str,
    _mode: u8,
    _minutes: i64,
) -> Result<(), &'static str> {
    Err("not_available")
}

fn apply_config_patch(state: &AppState, field: &str, value: bool) -> Result<(), &'static str> {
    match field {
        "attack_detection" => state.security_engine.set_detection_enabled(value),
        "auto_block" => state.security_engine.set_auto_block(value),
        "arp_spoof" => state.security_engine.set_arp_detection(value),
        "av_realtime" => state.realtime_guard.set_enabled(value),
        "av_auto_quarantine" => state.realtime_guard.set_auto_quarantine(value),
        "av_canary_autolock" => state.realtime_guard.set_canary_autolock(value),
        "av_canary_in_folders" => state.realtime_guard.set_watch_canary_in_folders(value),
        _ => return Err("bad_field"),
    }
    let apply_to_config = |cfg: &mut crate::modules::config::AppConfig| match field {
        "attack_detection" => cfg.attack_detection_enabled = value,
        "auto_block" => cfg.auto_block_attacks = value,
        "arp_spoof" => cfg.arp_spoof_detection = value,
        "av_realtime" => cfg.av_realtime_enabled = value,
        "av_auto_quarantine" => cfg.av_auto_quarantine_critical = value,
        "av_canary_autolock" => cfg.av_canary_autolock = value,
        "av_canary_in_folders" => cfg.av_canary_in_folders = value,
        _ => {}
    };
    if let Ok(mut cfg_guard) = state.config.write() {
        apply_to_config(&mut cfg_guard);
        let _ = cfg_guard.save();
    }
    Ok(())
}
