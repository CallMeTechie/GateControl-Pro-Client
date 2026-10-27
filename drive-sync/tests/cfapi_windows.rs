//! Integrations-Test mit echter Sync-Root (nur Windows): registrieren,
//! Platzhalter anlegen, Datei aus einem anderen Prozess öffnen → FETCH_DATA
//! lädt vom Fake-Server, Speicher freigeben (dehydrieren), anheften → laden,
//! neue lokale Datei → Upload, Kontextmenü (Registry, Aktions-Pipe),
//! Massenlöschung aus einem anderen Prozess → Nachfrage → wiederherstellen,
//! Windows-Ordner verlegen und zurücklegen (Test-Ordner statt der echten
//! Windows-Ordner), Abmelden mit einer offenen, nicht hochgeladenen Datei
//! (abgelehnt), abmelden.
//!
//! Ist die Cloud Files API nicht nutzbar (Server-SKU ohne Filtertreiber
//! cldflt), endet der Test mit der Zeile `CFAPI-SKIPPED: <Grund>` – die CI
//! macht daraus eine sichtbare Warnung. Gelungen: `CFAPI-RESULT: ok`.
#![cfg(windows)]

mod common;

use common::{FakeServer, TOKEN};
use gc_drive_sync::core::localfs::{LocalFs, Pin};
use gc_drive_sync::core::model::Role;
use gc_drive_sync::core::protocol::{parse_request, Command, KnownFolder};
use gc_drive_sync::core::service::{http_remote, Service};
use gc_drive_sync::core::testing::FakeDrive;
use gc_drive_sync::win::{actions, shellmenu, syncroot, util::current_user_sid, winfs::WinFs, WinPlatform};
use std::path::Path;
use std::process::Command as Proc;
use std::sync::Arc;
use std::sync::Mutex;
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
    let profile = base.join("profile");
    std::fs::create_dir_all(profile.join("Music").join("Alben")).unwrap();
    std::fs::write(profile.join("Music").join("Lied.mp3"), b"la la la").unwrap();
    std::fs::write(profile.join("Music").join("Alben").join("Cover.jpg"), vec![9u8; 200_000]).unwrap();
    let verb = format!("GateControlDriveTest{}", rand_hex());
    let mut plat = WinPlatform::with_id(&id, root.clone(), data.clone()).with_fake_known(&profile);
    plat.menu_verb = verb.clone();
    let platform = Arc::new(plat);
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

        // ── Kontextmenü: Registry und Aktions-Pipe ──
        let cmd = shellmenu::command_of(&verb, false, "1share").expect("Eintrag „Link teilen“");
        assert!(cmd.contains("action share") && cmd.contains("%1"), "{cmd}");
        assert!(shellmenu::command_of(&verb, false, "3versions").is_some());
        assert!(shellmenu::command_of(&verb, true, "2portal").is_some());
        assert!(shellmenu::command_of(&verb, true, "3versions").is_none(), "Ordner haben keine Versionen");
        let cond = shellmenu::applies_of(&verb).unwrap();
        assert!(cond.contains(&*root.to_string_lossy()), "{cond}");
        println!("CFAPI-INFO: Kontextmenü {cond}");
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let ev2 = events.clone();
        svc.set_event_sink(Some(Arc::new(move |l: String| ev2.lock().unwrap().push(l))));
        let sid = current_user_sid().unwrap();
        actions::serve(svc.clone(), &sid);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(actions::client(&sid, "versions", &p_small.to_string_lossy()), 0);
        wait_for("Aktion", || events.lock().unwrap().iter().any(|l| l.contains(r#""event":"action""#) && l.contains(&format!(r#""node":{}"#, small.id))));
        println!("CFAPI-INFO: Aktions-Pipe ok");

        // ── Massenlöschung aus einem anderen Prozess → Nachfrage → wiederherstellen ──
        let fotos = drive.add_dir(mine, "Fotos");
        for i in 0..15 {
            drive.add_file(fotos.id, &format!("Bild {i}.jpg"), b"jpg");
        }
        svc.handle(Command::SyncNow).unwrap();
        let p_fotos = area.join("Fotos");
        wait_for("Fotos", || fs.stat(&p_fotos.join("Bild 14.jpg")).ok().flatten().is_some());
        let st = Proc::new("cmd").args(["/C", "rmdir", "/S", "/Q"]).arg(&p_fotos).status().unwrap();
        assert!(st.success());
        wait_for("Nachfrage", || svc.status().mass_delete.is_some());
        let md = svc.status().mass_delete.unwrap();
        println!("CFAPI-INFO: Massenlöschung erkannt: {} Dateien, {} Einträge", md.files, md.items);
        assert!(!drive.get(fotos.id).unwrap().deleted, "nichts an den Server gegeben");
        svc.handle(Command::Deletes { apply: false }).unwrap();
        wait_for("wiederhergestellt", || fs.stat(&p_fotos.join("Bild 7.jpg")).ok().flatten().is_some_and(|e| e.placeholder.is_some()));
        assert!(drive.live_children(fotos.id).len() == 15);

        // ── Windows-Ordner verlegen und zurücklegen (Test-Ordner) ──
        let r = svc.handle(Command::Relocate { folder: KnownFolder::Music, name: Some("Musik".into()) }).expect("verlegen");
        let musik = area.join("Musik");
        assert_eq!(Path::new(r["to"].as_str().unwrap()), musik);
        assert!(!profile.join("Music").exists());
        assert_eq!(std::fs::read(musik.join("Lied.mp3")).unwrap(), b"la la la");
        wait_for("verlegt hochgeladen", || {
            drive.find(mine, "Musik").and_then(|d| drive.find(d.id, "Alben")).and_then(|a| drive.find(a.id, "Cover.jpg")).is_some()
                && fs.stat(&musik.join("Alben").join("Cover.jpg")).ok().flatten().is_some_and(|e| e.in_sync())
        });
        // Speicher freigeben: Zurücklegen muss zuerst laden
        fs.dehydrate(&musik.join("Alben").join("Cover.jpg")).unwrap();
        let r = svc.handle(Command::Restore { folder: KnownFolder::Music }).expect("zurücklegen");
        assert_eq!(Path::new(r["to"].as_str().unwrap()), profile.join("Music"));
        assert_eq!(std::fs::read(profile.join("Music").join("Alben").join("Cover.jpg")).unwrap(), vec![9u8; 200_000]);
        assert!(fs.stat(&profile.join("Music").join("Lied.mp3")).unwrap().unwrap().placeholder.is_none(), "normale Datei");
        svc.handle(Command::SyncNow).unwrap();
        wait_for("Drive-Kopie nur online", || fs.stat(&musik.join("Lied.mp3")).ok().flatten().and_then(|e| e.placeholder).is_some_and(|p| !p.hydrated));
        let md = drive.find(mine, "Musik").unwrap();
        assert!(drive.find(md.id, "Lied.mp3").is_some_and(|n| !n.deleted), "auf dem Server nichts gelöscht");
        println!("CFAPI-INFO: Verlegen/Zurücklegen ok");

        // ── Abmelden mit einer offenen, nicht hochgeladenen Datei → abgelehnt ──
        let p_open = area.join("offen.txt");
        std::fs::write(&p_open, b"noch nicht oben").unwrap();
        let held = {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new().read(true).write(true).share_mode(0).open(&p_open).unwrap()
        };
        std::thread::sleep(Duration::from_secs(3));
        let e = svc.handle(Command::Unregister { force: false }).unwrap_err();
        assert_eq!(e.code, "unsynced", "{}", e.message);
        assert!(syncroot::is_registered(&root));
        drop(held);
        println!("CFAPI-INFO: Abmelden mit offener Datei abgelehnt");
    }));

    if result.is_err() {
        // Fehlersuche: Log des Dienstes und Anfragen an den Fake-Server
        println!("--- drive-sync.log ---\n{}", std::fs::read_to_string(data.join("drive-sync.log")).unwrap_or_default());
        println!("--- requests ---\n{}", srv.requests.lock().unwrap().join("\n"));
    }
    let unreg = svc.handle(Command::Unregister { force: false });
    if unreg.is_err() {
        let _ = svc.handle(Command::Unregister { force: true });
    }
    let still = syncroot::is_registered(&root);
    let menu_left = shellmenu::applies_of(&verb).is_some();
    let _ = shellmenu::unregister(&verb);
    let _ = std::fs::remove_dir_all(&base);
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
    if let Err(e) = unreg {
        panic!("Abmelden: {} {}", e.code, e.message);
    }
    assert!(!still, "nach unregister nicht mehr registriert");
    assert!(!menu_left, "Kontextmenü entfernt");
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
