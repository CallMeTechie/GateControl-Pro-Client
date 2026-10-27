//! Windows: Symbol (Pro-Client-Icon aus ../build/icon.ico) und Versionsangaben in
//! die Exe. Das Symbol nutzt der Explorer-Eintrag der Sync-Root („<exe>,0“).

fn main() {
    println!("cargo:rerun-if-changed=../build/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    if std::path::Path::new("../build/icon.ico").exists() {
        res.set_icon("../build/icon.ico");
    }
    res.set("ProductName", "GateControl Drive")
        .set("FileDescription", "GateControl Drive – Dateien bei Bedarf")
        .set("CompanyName", "GateControl")
        .set("LegalCopyright", "Copyright 2026 GateControl")
        .set("OriginalFilename", "gc-drive-sync.exe");
    if let Err(e) = res.compile() {
        // Ohne Ressourcen-Compiler (rc.exe / windres) ohne Symbol bauen statt abbrechen.
        println!("cargo:warning=Windows-Ressourcen nicht eingebunden: {e}");
    }
}
