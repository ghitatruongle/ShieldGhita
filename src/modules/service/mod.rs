pub mod install;
#[cfg(windows)]
pub mod pipe;
pub mod protocol;
pub mod snapshot;
pub mod worker;

use std::sync::atomic::{AtomicBool, Ordering};

pub const SERVICE_NAME: &str = "ShieldGhitaCore";
pub const SERVICE_DISPLAY_NAME: &str = "Shield Ghita Core";
pub const SERVICE_DESCRIPTION: &str = "ShieldGhita background protection core: DNS server, WFP firewall, watchdog and antivirus realtime guard. Installed by Shield Ghita.";

static REMOTE_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_remote_mode(on: bool) {
    REMOTE_MODE.store(on, Ordering::SeqCst);
}

pub fn remote_mode() -> bool {
    REMOTE_MODE.load(Ordering::SeqCst)
}

pub fn run_service_mode() -> Result<(), Box<dyn std::error::Error>> {
    worker::dispatch_and_run()
}
