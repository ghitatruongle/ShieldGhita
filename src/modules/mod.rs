pub mod backup;
pub mod blocker;
pub mod config;
pub mod dns;
pub mod i18n;
pub mod logger;
pub mod monitor;
pub mod perf;
pub mod rammap;
pub mod security;
pub mod sinkhole;
pub mod stats;
pub mod system;

macro_rules! declare_admin_module {
    () => {
        #[cfg(feature = "admin")]
        pub mod local;
        #[cfg(feature = "admin")]
        pub mod panel;
    };
}
declare_admin_module!();
