fn main() {
    println!("cargo:rerun-if-changed=ui/app_window.slint");
    slint_build::compile("ui/app_window.slint").expect("Slint build failed");
}
