fn main() {
    println!("cargo:rerun-if-changed=ui/app_window.slint");
    println!("cargo:rerun-if-changed=ui/common.slint");
    println!("cargo:rerun-if-changed=ui/widgets.slint");
    println!("cargo:rerun-if-changed=ui/rammap.slint");
    println!("cargo:rerun-if-changed=ui/file_analyzer.slint");
    slint_build::compile("ui/app_window.slint").expect("Slint build failed");
}
