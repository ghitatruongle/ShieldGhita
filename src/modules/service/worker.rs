use crate::app::AppState;
use crate::modules::logger::AppLogBuffer;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

#[cfg(windows)]
pub fn dispatch_and_run() -> Result<(), Box<dyn std::error::Error>> {
    windows_service::service_dispatcher::start(
        crate::modules::service::SERVICE_NAME,
        ffi_service_main,
    )?;
    Ok(())
}

#[cfg(not(windows))]
pub fn dispatch_and_run() -> Result<(), Box<dyn std::error::Error>> {
    let stop_flag = Arc::new(AtomicBool::new(false));
    let log_buffer = Arc::new(AppLogBuffer::new(500));
    run_worker(&stop_flag, log_buffer);
    Ok(())
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(_args: Vec<std::ffi::OsString>) {
    let _ = run_as_service();
}

#[cfg(windows)]
fn run_as_service() -> windows_service::Result<()> {
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let stop_flag = Arc::new(AtomicBool::new(false));
    let handler_flag = stop_flag.clone();
    let event_handler = move |control: ServiceControl| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                handler_flag.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle =
        service_control_handler::register(crate::modules::service::SERVICE_NAME, event_handler)?;
    let report = |state: ServiceState, wait_hint: Option<Duration>| {
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: wait_hint.unwrap_or(Duration::ZERO),
            process_id: None,
        });
    };
    report(ServiceState::StartPending, Some(Duration::from_secs(30)));

    if !dns_port_available() {
        error!(
            "Shield Ghita Core: UDP port 53 is already owned by another process — refusing to start the protection stack so the running instance's protection state is not clobbered. Stop the other instance first."
        );
        report(ServiceState::Stopped, None);
        return Ok(());
    }

    let log_buffer = Arc::new(AppLogBuffer::new(500));
    let state = match AppState::new(log_buffer) {
        Ok(state) => state,
        Err(e) => {
            error!("Shield Ghita Core service worker failed to start: {}", e);
            report(ServiceState::Stopped, None);
            return Ok(());
        }
    };
    info!("Shield Ghita Core service running (protection owned by service, session 0)");
    report(ServiceState::Running, None);

    #[cfg(feature = "admin")]
    {
        let panel_enabled = state
            .config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .admin_panel_enabled;
        if panel_enabled {
            let panel_state = state.clone();
            state
                .runtime
                .spawn(async move { crate::modules::panel::PanelServer::serve(panel_state).await });
            info!("Admin panel 2525 started inside service");
        }
    }

    let ipc_state = state.clone();
    state
        .runtime
        .spawn(async move { crate::modules::service::pipe::serve(ipc_state).await });

    while !stop_flag.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(500));
    }
    info!("Service stop requested — restoring DNS and disabling WFP before exit");
    report(ServiceState::StopPending, Some(Duration::from_secs(15)));
    crate::app::ui_bridge::handlers::apply_protection(&state, false);
    let _ = crate::modules::system::dns_manager::restore_system_dns();
    info!("Shield Ghita Core service stopped cleanly");
    report(ServiceState::Stopped, None);
    Ok(())
}

fn dns_port_available() -> bool {
    std::net::UdpSocket::bind("0.0.0.0:53").is_ok()
}

#[cfg(not(windows))]
fn run_worker(stop: &AtomicBool, log_buffer: Arc<AppLogBuffer>) {
    if !dns_port_available() {
        error!(
            "Shield Ghita Core: UDP port 53 is already owned by another process — refusing to start the protection stack so the running instance's protection state is not clobbered. Stop the other instance first."
        );
        return;
    }
    let state = match AppState::new(log_buffer) {
        Ok(state) => state,
        Err(e) => {
            error!("Shield Ghita Core service worker failed to start: {}", e);
            return;
        }
    };
    info!("Shield Ghita Core worker running (non-Windows dev mode)");
    let ipc_state = state.clone();
    state
        .runtime
        .spawn(async move { crate::modules::service::pipe::serve(ipc_state).await });
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(500));
    }
    info!("Worker stop requested — restoring DNS and disabling WFP before exit");
    crate::app::ui_bridge::handlers::apply_protection(&state, false);
    let _ = crate::modules::system::dns_manager::restore_system_dns();
    info!("Shield Ghita Core worker stopped cleanly");
}
