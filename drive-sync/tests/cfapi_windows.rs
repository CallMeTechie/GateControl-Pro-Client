//! Integrations-Test mit echter Sync-Root (nur Windows): registrieren,
//! Platzhalter anlegen, Datei aus einem anderen Prozess öffnen → FETCH_DATA
//! lädt vom Fake-Server, Speicher freigeben (dehydrieren), anheften → laden,
//! neue lokale Datei → Upload, abmelden.
//!
//! Ist die Cloud Files API nicht nutzbar (Server-SKU ohne Filtertreiber
//! cldflt), endet der Test mit der Zeile `CFAPI-SKIPPED: <Grund>` – die CI
//! macht daraus eine sichtbare Warnung. Gelungen: `CFAPI-RESULT: ok`.
#![cfg(windows)]

mod common;

use common::{FakeServer, TOKEN};
use gc_drive_sync::core::localfs::{LocalFs, Pin};
use gc_drive_sync::core::model::Role;
use gc_drive_sync::core::protocol::{parse_request, Command};
use gc_drive_sync::core::service::{http_remote, Service};
use gc_drive_sync::core::testing::FakeDrive;
use gc_drive_sync::win::{syncroot, winfs::WinFs, WinPlatform};
use std::path::Path;
use std::process::Command as Proc;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn wait_for(what: &str, f: impl Fn() -> bool) {
    let until = Instant::now() + Duration::from_secs(60);
    while Instant::now() < until {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("Zeitüberschreitung: {what}");
}

/// Datei aus einem anderen Prozess lesen (der Anbieter-Prozess selbst darf
/// Platzhalter nicht implizit laden).
fn read_via_other_process(src: &Path, tmp: &Path) -> Vec<u8> {
    let dst = tmp.join(format!("copy-{}", rand_hex()));
    let st = Proc::new("cmd").args(["/C", "copy", "/B", "/Y"]).arg(src).arg(&dst).status().expect("cmd");
    assert!(st.success(), "copy failed for {}", src.display());
    std::fs::read(&dst).unwrap()
}

fn rand_hex() -> String {
    format!("{:016x}", rand::random::<u64>())
}

#[test]
fn real_sync_root_roundtrip() {
    match syncroot::platform_info() {
        Ok((b, r, i)) => println!("CFAPI-INFO: build {b}.{r} integration {i}"),
        Err(e) => {
            println!("CFAPI-SKIPPED: Cloud Files API nicht verfügbar ({e})");
            return;
        }
    }
    let base = std::env::temp_dir().join(format!("gcds-it-{}", rand_hex()));
    let root = base.join("GateControl Drive Test");
    let data = base.join("data");
    let tmp = base.join("tmp");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&tmp).unwrap();

    let drive = Arc::new(FakeDrive::new());
    let mine = drive.add_area("mine:1", "Meine Dateien", Role::Manage);
    let small = drive.add_file(mine, "Hallo.txt", b"Hallo aus GateControl Drive");
    let big_data: Vec<u8> = (0..3_000_123u32).map(|i| (i % 251) as u8).collect();
    let big = drive.add_file(mine, "Gross.bin", &big_data);
    let srv = FakeServer::start(drive.clone());

    let id = format!("GateControlDriveTest!{}!default", rand_hex());
    let platform = Arc::new(WinPlatform::with_id(&id, root.clone(), data.clone()));
    let svc = Service::new(platform.clone(), http_remote());
    let cfg = parse_request(&format!(r#"{{"cmd":"configure","serverUrl":"{}","token":"{TOKEN}","deviceName":"CI"}}"#, srv.url)).unwrap().cmd;
    svc.handle(cfg).unwrap();
    if let Err(e) = svc.handle(Command::Start) {
        panic!("Start fehlgeschlagen (cfapi vorhanden): {} {}", e.code, e.message);
    }
    println!("CFAPI-INFO: registriert={}", syncroot::is_registered(&root));
    let fs = WinFs::new();
    let area = root.join("Meine Dateien");
    let p_small = area.join("Hallo.txt");
    let p_big = area.join("Gross.bin");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_for("Platzhalter", || fs.stat(&p_big).ok().flatten().is_some_and(|e| e.placeholder.is_some()));
        let e = fs.stat(&p_big).unwrap().unwrap();
        assert_eq!(e.size, big_data.len() as u64);
        let ph = e.placeholder.unwrap();
        assert!(ph.in_sync, "in sync");
        assert!(!ph.hydrated, "online only");
        assert_eq!(ph.identity.unwrap().node, big.id);

        // Öffnen → FETCH_DATA → Download mit Range
        assert_eq!(read_via_other_process(&p_small, &tmp), b"Hallo aus GateControl Drive");
        let got = read_via_other_process(&p_big, &tmp);
        assert_eq!(got.len(), big_data.len());
        assert!(got == big_data, "content differs");
        assert!(srv.requests.lock().unwrap().iter().any(|r| r.contains(&format!("/nodes/{}/content", small.id))));
        wait_for("hydratisiert", || fs.stat(&p_big).ok().flatten().and_then(|e| e.placeholder).is_some_and(|p| p.hydrated));

        // Speicher freigeben
        fs.dehydrate(&p_big).unwrap();
        assert!(!fs.stat(&p_big).unwrap().unwrap().placeholder.unwrap().hydrated);

        // „Immer auf diesem Gerät behalten“ → der Abgleich lädt
        set_pin(&p_big, Pin::Pinned);
        wait_for("angeheftet geladen", || fs.stat(&p_big).ok().flatten().and_then(|e| e.placeholder).is_some_and(|p| p.hydrated));

        // neue lokale Datei → Upload → Platzhalter
        let p_new = area.join("Neu vom PC.txt");
        std::fs::write(&p_new, b"lokal angelegt").unwrap();
        wait_for("Upload", || drive.find(mine, "Neu vom PC.txt").is_some());
        let n = drive.find(mine, "Neu vom PC.txt").unwrap();
        assert_eq!(drive.file_data(n.id).unwrap(), b"lokal angelegt");
        wait_for("in sync", || fs.stat(&p_new).ok().flatten().is_some_and(|e| e.in_sync()));

        // Server-Änderung → sync-now → neuer Platzhalter
        drive.add_file(mine, "Vom Server.txt", b"neu");
        svc.handle(Command::SyncNow).unwrap();
        wait_for("Server-Datei", || fs.stat(&area.join("Vom Server.txt")).ok().flatten().is_some());
    }));

    svc.handle(Command::Stop).unwrap();
    svc.handle(Command::Unregister).unwrap();
    let still = syncroot::is_registered(&root);
    let _ = std::fs::remove_dir_all(&base);
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
    assert!(!still, "nach unregister nicht mehr registriert");
    println!("CFAPI-RESULT: ok");
}

fn set_pin(path: &Path, pin: Pin) {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::CloudFilters::*;
    use windows::Win32::Storage::FileSystem::*;
    let w: Vec<u16> = path.as_os_str().encode_wide_null();
    unsafe {
        let h = CreateFileW(
            PCWSTR(w.as_ptr()),
            FILE_WRITE_ATTRIBUTES.0 | 0x0004_0000,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        .unwrap();
        let st = if pin == Pin::Pinned { CF_PIN_STATE_PINNED } else { CF_PIN_STATE_UNPINNED };
        CfSetPinState(h, st, CF_SET_PIN_FLAG_NONE, None).unwrap();
        let _ = windows::Win32::Foundation::CloseHandle(h);
    }
}

trait WideNull {
    fn encode_wide_null(&self) -> Vec<u16>;
}

impl WideNull for std::ffi::OsStr {
    fn encode_wide_null(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(std::iter::once(0)).collect()
    }
}
