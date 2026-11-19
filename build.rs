fn main() {
    println!("cargo:rerun-if-changed=ui/app_window.slint");
    println!("cargo:rerun-if-changed=ui/common.slint");
    println!("cargo:rerun-if-changed=ui/widgets.slint");
    println!("cargo:rerun-if-changed=ui/rammap.slint");
    println!("cargo:rerun-if-changed=ui/file_analyzer.slint");
    println!("cargo:rerun-if-changed=ui/adblock_stats.slint");
    println!("cargo:rerun-if-changed=ui/antivirus.slint");
    println!("cargo:rerun-if-changed=ui/vulnscan.slint");
    println!("cargo:rerun-if-changed=ui/vault.slint");
    println!("cargo:rerun-if-changed=ui/pentest.slint");
    println!("cargo:rerun-if-changed=ui/hardening.slint");
    println!("cargo:rerun-if-changed=ui/chrome.slint");
    println!("cargo:rerun-if-changed=ui/tabs/admin_suite.slint");
    println!("cargo:rerun-if-changed=ui/tabs/diagnostics.slint");
    println!("cargo:rerun-if-changed=ui/tabs/filter_rules.slint");
    println!("cargo:rerun-if-changed=ui/tabs/modals.slint");
    println!("cargo:rerun-if-changed=ui/tabs/monitor.slint");
    println!("cargo:rerun-if-changed=ui/tabs/overlays.slint");
    println!("cargo:rerun-if-changed=ui/tabs/overview.slint");
    println!("cargo:rerun-if-changed=ui/tabs/security.slint");
    println!("cargo:rerun-if-changed=ui/tabs/settings.slint");
    slint_build::compile("ui/app_window.slint").expect("Slint build failed");
}
