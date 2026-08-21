fn main() {
    slint_build::compile("ui/app_window.slint").expect("Slint build failed");

    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/app_icon.ico");
        res.set_manifest_file("app.manifest");
        res.set("ProductName", "Shield Ghita");
        res.set("FileDescription", "Shield Ghita - Master Internet Controller & Ad Blocker");
        res.set("LegalCopyright", "Copyright (C) 2026 ShieldGhita");
        let _ = res.compile();
    }
}