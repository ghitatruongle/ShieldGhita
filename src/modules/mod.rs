pub mod backup;
pub mod blocker;
pub mod config;
pub mod dns;
// Track 3/4 (0.1.5-alpha1): these were admin-only under modules::local and are
// now public edition features — self-contained, no admin deps.
pub mod hardening;
pub mod hardening_fix;
pub mod i18n;
pub mod logger;
pub mod monitor;
pub mod paths;
pub mod perf;
pub mod rammap;
pub mod security;
pub mod service;
pub mod sinkhole;
pub mod stats;
pub mod system;
pub mod vault;

macro_rules! declare_admin_module {
    () => {
        #[cfg(feature = "admin")]
        pub mod local;
        #[cfg(feature = "admin")]
        pub mod panel;
    };
}
declare_admin_module!();
