pub mod blocker;
pub mod config;
pub mod dns;
pub mod logger;
pub mod monitor;
pub mod security;
pub mod sinkhole;
pub mod system;

macro_rules! declare_admin_module {
    () => {
        #[cfg(feature = "admin")]
        pub mod local;
    };
}
declare_admin_module!();
