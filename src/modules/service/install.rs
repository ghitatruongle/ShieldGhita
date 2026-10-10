use crate::modules::service::{SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreServiceState {
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    Paused,
    Unknown,
}

fn run_sc(args: &[&str]) -> (i32, String, String) {
    match crate::modules::system::dns_manager::silent_command("sc")
        .args(args)
        .output()
    {
        Ok(output) => (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ),
        Err(e) => (-1, String::new(), e.to_string()),
    }
}

pub fn state_from_sc_output(code: i32, stdout: &str) -> CoreServiceState {
    if code == 1060 {
        return CoreServiceState::NotInstalled;
    }
    if stdout.contains("START_PENDING") {
        CoreServiceState::StartPending
    } else if stdout.contains("STOP_PENDING") {
        CoreServiceState::StopPending
    } else if stdout.contains("PAUSED") {
        CoreServiceState::Paused
    } else if stdout.contains("RUNNING") {
        CoreServiceState::Running
    } else if stdout.contains("STOPPED") {
        CoreServiceState::Stopped
    } else {
        CoreServiceState::Unknown
    }
}

pub fn query_state() -> CoreServiceState {
    let (code, stdout, _) = run_sc(&["query", SERVICE_NAME]);
    state_from_sc_output(code, &stdout)
}

pub fn install(start_after: bool) -> Result<String, String> {
    if query_state() != CoreServiceState::NotInstalled {
        return Err("service already installed".to_string());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let bin_path = format!("\"{}\" --service", exe.display());
    let (code, _, stderr) = run_sc(&[
        "create",
        SERVICE_NAME,
        "binPath=",
        &bin_path,
        "start=",
        "auto",
        "DisplayName=",
        SERVICE_DISPLAY_NAME,
        "obj=",
        "LocalSystem",
    ]);
    if code != 0 {
        return Err(format!("sc create failed: {stderr}"));
    }
    let _ = run_sc(&["description", SERVICE_NAME, SERVICE_DESCRIPTION]);
    let _ = run_sc(&[
        "failure",
        SERVICE_NAME,
        "reset=",
        "86400",
        "actions=",
        "restart/5000/restart/10000/restart/30000",
    ]);
    let _ = run_sc(&["config", SERVICE_NAME, "start=", "delayed-auto"]);
    if start_after {
        start()?;
    }
    Ok("✓ Service ShieldGhitaCore installed".to_string())
}

pub fn start() -> Result<String, String> {
    let (code, _, stderr) = run_sc(&["start", SERVICE_NAME]);
    if code != 0 && !stderr.contains("1056") {
        return Err(format!("sc start failed: {stderr}"));
    }
    Ok("✓ Service ShieldGhitaCore started".to_string())
}

pub fn stop() -> Result<String, String> {
    let (code, _, stderr) = run_sc(&["stop", SERVICE_NAME]);
    if code != 0 && !stderr.contains("1062") {
        return Err(format!("sc stop failed: {stderr}"));
    }
    for _ in 0..20 {
        if query_state() == CoreServiceState::Stopped {
            return Ok("✓ Service ShieldGhitaCore stopped".to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Ok("Service stop requested (still pending)".to_string())
}

pub fn uninstall() -> Result<String, String> {
    match query_state() {
        CoreServiceState::NotInstalled => {
            return Ok("service already absent".to_string());
        }
        CoreServiceState::Running | CoreServiceState::StartPending | CoreServiceState::Paused => {
            let _ = stop();
        }
        _ => {}
    }
    let (code, _, stderr) = run_sc(&["delete", SERVICE_NAME]);
    if code != 0 {
        return Err(format!("sc delete failed: {stderr}"));
    }
    Ok("✓ Service ShieldGhitaCore uninstalled".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_parsing_all_states() {
        assert_eq!(
            state_from_sc_output(
                0,
                "SERVICE_NAME: ShieldGhitaCore\r\n        STATE              : 4  RUNNING\r\n"
            ),
            CoreServiceState::Running
        );
        assert_eq!(
            state_from_sc_output(0, "STATE : 1  STOPPED"),
            CoreServiceState::Stopped
        );
        assert_eq!(
            state_from_sc_output(0, "STATE : 2  START_PENDING"),
            CoreServiceState::StartPending
        );
        assert_eq!(
            state_from_sc_output(0, "STATE : 3  STOP_PENDING"),
            CoreServiceState::StopPending
        );
        assert_eq!(
            state_from_sc_output(0, "STATE : 7  PAUSED"),
            CoreServiceState::Paused
        );
    }

    #[test]
    fn test_state_parsing_not_installed_and_unknown() {
        assert_eq!(
            state_from_sc_output(1060, "Locally, the specified service does not exist"),
            CoreServiceState::NotInstalled
        );
        assert_eq!(
            state_from_sc_output(1, "gibberish"),
            CoreServiceState::Unknown
        );
    }
}
