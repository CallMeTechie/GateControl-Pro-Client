//! gc-drive-sync.exe – siehe README.md und PROTOCOL.md.

#[cfg(windows)]
fn main() {
    std::process::exit(gc_drive_sync::win::main::run());
}

#[cfg(not(windows))]
fn main() {
    if std::env::args().any(|a| a == "--version") {
        println!("gc-drive-sync {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    eprintln!("gc-drive-sync läuft nur unter Windows (Cloud Files API).");
    std::process::exit(2);
}
