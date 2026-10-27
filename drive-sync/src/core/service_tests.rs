use super::*;
use crate::core::localfs::LocalFs;
use crate::core::model::Role;
use crate::core::testing::{p, FakeDrive, FakeFs};
use std::sync::atomic::AtomicUsize;

type OnEvent = Box<dyn Fn(WatchEvent) + Send + Sync>;
type SinkData = Arc<Mutex<(Vec<u8>, Option<(u64, u64)>)>>;

struct FakePlatform {
    root: PathBuf,
    data: PathBuf,
    fs: Arc<FakeFs>,
    registered: AtomicBool,
    unregistered: AtomicUsize,
    callbacks: Mutex<Option<Arc<dyn Callbacks>>>,
    watcher: Mutex<Option<OnEvent>>,
    known: Arc<FakeKnown>,
    menu: Mutex<Vec<(bool, Option<String>)>>,
}

struct FakeKnown(Mutex<std::collections::HashMap<KnownFolder, PathBuf>>);

impl KnownFolders for FakeKnown {
    fn get(&self, f: KnownFolder) -> Result<PathBuf, String> {
        self.0.lock().unwrap().get(&f).cloned().ok_or_else(|| "unknown".into())
    }
    fn set(&self, f: KnownFolder, path: &Path) -> Result<(), String> {
        self.0.lock().unwrap().insert(f, path.to_path_buf());
        Ok(())
    }
    fn default_path(&self, f: KnownFolder) -> PathBuf {
        PathBuf::from("/home/max").join(f.default_leaf())
    }
}

impl Platform for FakePlatform {
    fn sync_root(&self) -> PathBuf {
        self.root.clone()
    }
    fn data_dir(&self) -> PathBuf {
        self.data.clone()
    }
    fn register(&self) -> Result<(), String> {
        self.registered.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn unregister(&self) -> Result<(), String> {
        self.registered.store(false, Ordering::SeqCst);
        self.unregistered.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn is_registered(&self) -> bool {
        self.registered.load(Ordering::SeqCst)
    }
    fn fs(&self) -> Arc<dyn LocalFs> {
        self.fs.clone()
    }
    fn connect(&self, cb: Arc<dyn Callbacks>) -> Result<Guard, String> {
        *self.callbacks.lock().unwrap() = Some(cb);
        Ok(Box::new(()))
    }
    fn watch(&self, on_event: Box<dyn Fn(WatchEvent) + Send + Sync>) -> Result<Guard, String> {
        *self.watcher.lock().unwrap() = Some(on_event);
        Ok(Box::new(()))
    }
    fn known(&self) -> Option<Arc<dyn KnownFolders>> {
        Some(self.known.clone())
    }
    fn context_menu(&self, on: bool, app_exe: Option<&str>, _lang: Option<&str>) -> Result<(), String> {
        self.menu.lock().unwrap().push((on, app_exe.map(str::to_string)));
        Ok(())
    }
}

struct Ctx {
    svc: Arc<Service<FakePlatform>>,
    plat: Arc<FakePlatform>,
    drive: Arc<FakeDrive>,
    mine: u64,
    _tmp: tempfile::TempDir,
}

fn ctx() -> Ctx {
    let tmp = tempfile::tempdir().unwrap();
    let root = PathBuf::from("/sync");
    let fs = Arc::new(FakeFs::new(&root));
    for x in ["/home", "/home/max", "/home/max/Music"] {
        fs.add_root(Path::new(x));
    }
    fs.user_write(Path::new("/home/max/Music/Lied.mp3"), b"la la la");
    let known = Arc::new(FakeKnown(Mutex::new(std::collections::HashMap::from([(KnownFolder::Music, PathBuf::from("/home/max/Music"))]))));
    let drive = Arc::new(FakeDrive::new());
    let mine = drive.add_area("mine:1", "Meine Dateien", Role::Manage);
    let plat = Arc::new(FakePlatform {
        root,
        data: tmp.path().to_path_buf(),
        fs,
        registered: AtomicBool::new(false),
        unregistered: AtomicUsize::new(0),
        callbacks: Mutex::new(None),
        watcher: Mutex::new(None),
        known,
        menu: Mutex::new(Vec::new()),
    });
    let d = drive.clone();
    let svc = Service::new(plat.clone(), Box::new(move |_c: &Config| Ok(d.clone() as Arc<dyn Remote>)));
    Ctx { svc, plat, drive, mine, _tmp: tmp }
}

fn configure() -> Command {
    match protocol::parse_request(r#"{"cmd":"configure","serverUrl":"https://gc.test","token":"geheim-123","deviceName":"PC"}"#).unwrap().cmd {
        c @ Command::Configure(_) => c,
        _ => unreachable!(),
    }
}

fn wait_for(f: impl Fn() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timeout");
}

#[test]
fn start_requires_configure() {
    let c = ctx();
    assert_eq!(c.svc.handle(Command::Start).unwrap_err().code, "not_configured");
    assert_eq!(c.svc.status().state, "unconfigured");
    assert_eq!(c.svc.handle(Command::SyncNow).unwrap_err().code, "not_running");
}

#[test]
fn start_syncs_and_stop_disconnects() {
    let c = ctx();
    c.drive.add_file(c.mine, "a.txt", b"a");
    c.svc.handle(configure()).unwrap();
    assert_eq!(c.svc.status().state, "stopped");
    c.svc.handle(Command::Start).unwrap();
    assert!(c.plat.is_registered());
    wait_for(|| c.svc.status().state == "idle");
    assert!(c.plat.fs.get(&p(&c.plat.root, &["Meine Dateien", "a.txt"])).is_some());
    assert!(c.svc.status().last_sync.is_some());

    // lokale Änderung über die Beobachtung
    c.plat.fs.user_write(&p(&c.plat.root, &["Meine Dateien", "neu.txt"]), b"neu");
    (c.plat.watcher.lock().unwrap().as_ref().unwrap())(WatchEvent::Changed(p(&c.plat.root, &["Meine Dateien", "neu.txt"])));
    wait_for(|| c.drive.find(c.mine, "neu.txt").is_some());

    // Server-Änderung + sync-now
    c.drive.add_file(c.mine, "b.txt", b"b");
    c.svc.handle(Command::SyncNow).unwrap();
    wait_for(|| c.plat.fs.get(&p(&c.plat.root, &["Meine Dateien", "b.txt"])).is_some());

    c.svc.handle(Command::Pause).unwrap();
    assert_eq!(c.svc.status().state, "paused");
    c.svc.handle(Command::Resume).unwrap();
    c.svc.handle(Command::Stop).unwrap();
    assert_eq!(c.svc.status().state, "stopped");
    // Zustand gespeichert, ohne Token
    let files: Vec<_> = std::fs::read_dir(&c.plat.data).unwrap().filter_map(|e| e.ok()).collect();
    let state = files.iter().find(|f| f.file_name().to_string_lossy().starts_with("state-")).expect("state file");
    let text = std::fs::read_to_string(state.path()).unwrap();
    assert!(text.contains("neu.txt"));
    for f in files {
        assert!(!std::fs::read_to_string(f.path()).unwrap_or_default().contains("geheim-123"));
    }
}

#[test]
fn callbacks_check_rights() {
    let c = ctx();
    let ro = c.drive.add_area("team:1", "Team", Role::Read);
    let f = c.drive.add_file(c.mine, "weg.txt", b"x");
    let r = c.drive.add_file(ro, "fest.txt", b"y");
    c.svc.handle(configure()).unwrap();
    c.svc.handle(Command::Start).unwrap();
    wait_for(|| c.svc.status().state == "idle");
    let cb = c.plat.callbacks.lock().unwrap().clone().unwrap();
    let id = |n: &crate::core::model::Node| Some(Identity::new(n.id, n.rev, &n.area_id, n.media_id.as_deref()));

    // Wurzel eines Bereichs
    assert!(!cb.notify_delete(Some(Identity::new(c.mine, 0, "mine:1", None)), p(&c.plat.root, &["Meine Dateien"])));
    // nur Lesen
    assert!(!cb.notify_delete(id(&r), p(&c.plat.root, &["Team", "fest.txt"])));
    assert!(!cb.notify_rename(id(&r), p(&c.plat.root, &["Team", "fest.txt"]), Some(p(&c.plat.root, &["Team", "x.txt"]))));
    // in einen Bereich nur zum Lesen hinein / direkt in den Sync-Root
    assert!(!cb.notify_rename(id(&f), p(&c.plat.root, &["Meine Dateien", "weg.txt"]), Some(p(&c.plat.root, &["Team", "weg.txt"]))));
    assert!(!cb.notify_rename(id(&f), p(&c.plat.root, &["Meine Dateien", "weg.txt"]), Some(p(&c.plat.root, &["weg.txt"]))));
    // fremde Dateien (keine Identität) immer
    assert!(cb.notify_delete(None, p(&c.plat.root, &["Meine Dateien", "x"])));
    // erlaubt → Papierkorb
    let path = p(&c.plat.root, &["Meine Dateien", "weg.txt"]);
    assert!(cb.notify_delete(id(&f), path.clone()));
    c.plat.fs.user_delete(&path);
    wait_for(|| c.drive.get(f.id).unwrap().deleted);
    c.svc.handle(Command::Stop).unwrap();
}

struct VecSink(SinkData);

impl TransferSink for VecSink {
    fn transfer(&mut self, offset: u64, data: &[u8]) -> Result<(), String> {
        let mut g = self.0.lock().unwrap();
        assert_eq!(offset as usize, g.0.len());
        g.0.extend_from_slice(data);
        Ok(())
    }
    fn progress(&mut self, _: u64, _: u64) {}
    fn fail(&mut self, o: u64, l: u64) {
        self.0.lock().unwrap().1 = Some((o, l));
    }
}

#[test]
fn fetch_data_through_pool() {
    let c = ctx();
    let f = c.drive.add_file(c.mine, "f.bin", &vec![7u8; 10_000]);
    c.svc.handle(configure()).unwrap();
    c.svc.handle(Command::Start).unwrap();
    let cb = c.plat.callbacks.lock().unwrap().clone().unwrap();
    let out = Arc::new(Mutex::new((Vec::new(), None)));
    let req = FetchRequest {
        identity: Some(Identity::new(f.id, f.rev, "mine:1", f.media_id.as_deref())),
        file_size: 10_000,
        required_offset: 0,
        required_length: 10_000,
        optional_offset: 0,
        optional_length: 0,
    };
    cb.fetch_data(1, req.clone(), Box::new(VecSink(out.clone())));
    wait_for(|| out.lock().unwrap().0.len() == 10_000);
    // veraltete Identität → Fehler an Windows
    c.drive.modify(f.id, b"neu");
    let out2 = Arc::new(Mutex::new((Vec::new(), None)));
    cb.fetch_data(2, req, Box::new(VecSink(out2.clone())));
    wait_for(|| out2.lock().unwrap().1.is_some());
    c.svc.handle(Command::Stop).unwrap();
}

#[test]
fn unregister_cleans_up() {
    let c = ctx();
    c.drive.add_file(c.mine, "a.txt", b"a");
    c.svc.handle(configure()).unwrap();
    c.svc.handle(Command::Start).unwrap();
    wait_for(|| c.svc.status().state == "idle");
    c.svc.handle(Command::Stop).unwrap();
    c.svc.handle(Command::Unregister { force: false }).unwrap();
    assert_eq!(c.plat.unregistered.load(Ordering::SeqCst), 1);
    assert!(c.plat.fs.get(&p(&c.plat.root, &["Meine Dateien", "a.txt"])).is_none());
    assert!(!std::fs::read_dir(&c.plat.data).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with("state-")));
}

/// Schreibziel für `serve` (gemeinsamer Puffer).
#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn serve_speaks_json_lines() {
    let c = ctx();
    let input = [
        r#"{"id":1,"cmd":"hello","version":"1.48.0"}"#,
        r#"{"id":2,"cmd":"configure","serverUrl":"https://gc.test","token":"geheim-123","deviceName":"PC"}"#,
        r#"{"id":3,"cmd":"status"}"#,
        "kaputt",
        r#"{"id":4,"cmd":"bogus"}"#,
        r#"{"id":5,"cmd":"shutdown"}"#,
        r#"{"id":6,"cmd":"status"}"#,
    ]
    .join("\n");
    let out = Buf::default();
    c.svc.serve(std::io::Cursor::new(input), out.clone());
    let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
    assert!(!text.contains("geheim-123"));
    let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let resp: Vec<&Value> = lines.iter().filter(|l| l.get("event").is_none()).collect();
    assert_eq!(resp.len(), 6, "{text}");
    assert_eq!(resp[0]["result"]["protocol"], 2);
    assert_eq!(resp[1]["result"]["configured"], true);
    assert_eq!(resp[2]["result"]["state"], "stopped");
    assert_eq!(resp[3]["error"]["code"], "bad_json");
    assert_eq!((resp[4]["id"].clone(), resp[4]["error"]["code"].clone()), (json!(4), json!("unknown_command")));
    assert_eq!(resp[5]["result"]["shutdown"], true);
    assert!(c.svc.quit.load(Ordering::SeqCst));
    // Logzeile des hello als Ereignis
    assert!(lines.iter().any(|l| l["event"] == "log"));
}

#[test]
fn state_file_per_server() {
    let a = state_file(Path::new("/d"), "https://A.example");
    let b = state_file(Path::new("/d"), "https://a.example");
    let c = state_file(Path::new("/d"), "https://b.example");
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert!(a.file_name().unwrap().to_string_lossy().starts_with("state-"));
}

fn started() -> Ctx {
    let c = ctx();
    c.svc.handle(configure()).unwrap();
    c.svc.handle(Command::Start).unwrap();
    wait_for(|| c.svc.status().state == "idle");
    c
}

#[test]
fn context_menu_follows_start_and_unregister() {
    let c = ctx();
    let hello = protocol::parse_request(r#"{"cmd":"hello","appExe":"C:\\GC\\GateControl Pro Client.exe"}"#).unwrap().cmd;
    c.svc.handle(hello).unwrap();
    c.svc.handle(configure()).unwrap();
    c.svc.handle(Command::Start).unwrap();
    wait_for(|| c.svc.status().state == "idle");
    c.svc.handle(Command::Unregister { force: false }).unwrap();
    let m = c.plat.menu.lock().unwrap().clone();
    assert_eq!(m, vec![(true, Some(r"C:\GC\GateControl Pro Client.exe".to_string())), (false, None)]);
}

#[test]
fn unregister_refuses_unsynced_changes_unless_forced() {
    let c = started();
    let f = p(&c.plat.root, &["Meine Dateien", "offen.txt"]);
    c.plat.fs.user_write(&f, b"noch nicht oben");
    c.plat.fs.lock(&f, true); // ein Programm hält die Datei offen → kann nicht hoch
    let e = c.svc.handle(Command::Unregister { force: false }).unwrap_err();
    assert_eq!(e.code, "unsynced");
    let d = e.data.unwrap();
    assert_eq!(d["count"], 1);
    assert!(d["paths"][0].as_str().unwrap().ends_with("offen.txt"));
    assert!(c.plat.is_registered(), "nichts abgemeldet");
    assert_eq!(c.svc.status().state, "idle", "Abgleich läuft weiter");

    // Datei frei → wird beim nächsten Versuch hochgeladen, dann klappt es
    c.plat.fs.lock(&f, false);
    c.svc.handle(Command::Unregister { force: false }).unwrap();
    assert!(c.drive.find(c.mine, "offen.txt").is_some());
    assert!(!c.plat.is_registered());
    // hochgeladen und geladen → bleibt als normale Datei
    assert_eq!(c.plat.fs.data(&f).unwrap(), b"noch nicht oben");
    assert!(c.plat.fs.get(&f).unwrap().placeholder.is_none());
}

#[test]
fn unregister_force_keeps_unsynced_files() {
    let c = started();
    let f = p(&c.plat.root, &["Meine Dateien", "offen.txt"]);
    c.plat.fs.user_write(&f, b"lokal");
    c.plat.fs.lock(&f, true);
    c.svc.handle(Command::Unregister { force: true }).unwrap();
    assert_eq!(c.plat.fs.data(&f).unwrap(), b"lokal");
    assert!(!c.plat.is_registered());
}

#[test]
fn unregister_refuses_while_a_windows_folder_is_in_the_drive() {
    let c = started();
    let r = c.svc.handle(Command::Relocate { folder: KnownFolder::Music, name: Some("Musik".into()) }).unwrap();
    assert_eq!(Path::new(r["to"].as_str().unwrap()), p(&c.plat.root, &["Meine Dateien", "Musik"]));
    let e = c.svc.handle(Command::Unregister { force: true }).unwrap_err();
    assert_eq!(e.code, "relocated");
    assert_eq!(e.data.unwrap()["folders"], json!(["music"]));
    // Liste der Windows-Ordner
    let l = c.svc.handle(Command::KnownFolders).unwrap();
    let music = l["folders"].as_array().unwrap().iter().find(|f| f["key"] == "music").unwrap().clone();
    assert_eq!(music["inDrive"], true);
    // hochgeladen
    wait_for(|| c.drive.find(c.mine, "Musik").is_some_and(|d| c.drive.find(d.id, "Lied.mp3").is_some()));
    // zurück, dann abmelden
    let r = c.svc.handle(Command::Restore { folder: KnownFolder::Music }).unwrap();
    assert_eq!(r["to"], "/home/max/Music");
    assert_eq!(c.plat.fs.data(Path::new("/home/max/Music/Lied.mp3")).unwrap(), b"la la la");
    c.svc.handle(Command::Unregister { force: false }).unwrap();
    // die Datei bleibt im Drive
    let d = c.drive.find(c.mine, "Musik").unwrap();
    assert!(c.drive.find(d.id, "Lied.mp3").is_some_and(|n| !n.deleted));
}

#[test]
fn relocate_needs_a_running_sync() {
    let c = ctx();
    assert_eq!(c.svc.handle(Command::Relocate { folder: KnownFolder::Music, name: None }).unwrap_err().code, "not_running");
}

#[test]
fn mass_delete_is_asked_and_restored() {
    let c = ctx();
    let fotos = c.drive.add_dir(c.mine, "Fotos");
    for i in 0..25 {
        c.drive.add_file(fotos.id, &format!("{i}.jpg"), b"x");
    }
    c.svc.handle(configure()).unwrap();
    c.svc.handle(Command::Start).unwrap();
    wait_for(|| c.svc.status().state == "idle" && c.plat.fs.get(&p(&c.plat.root, &["Meine Dateien", "Fotos", "3.jpg"])).is_some());
    let cb = c.plat.callbacks.lock().unwrap().clone().unwrap();
    let path = p(&c.plat.root, &["Meine Dateien", "Fotos"]);
    let id = Identity::new(fotos.id, fotos.rev, "mine:1", None);
    // Explorer: Ordner in den Papierkorb
    assert!(cb.notify_rename(Some(id), path.clone(), None));
    c.plat.fs.user_delete(&path);
    wait_for(|| c.svc.status().mass_delete.is_some());
    let md = c.svc.status().mass_delete.unwrap();
    assert_eq!((md.files, md.items, md.offline), (25, 1, false));
    assert!(!c.drive.get(fotos.id).unwrap().deleted);
    let r = c.svc.handle(Command::Deletes { apply: false }).unwrap();
    assert_eq!(r["decided"], 1);
    assert!(c.svc.status().mass_delete.is_none());
    wait_for(|| c.plat.fs.get(&p(&c.plat.root, &["Meine Dateien", "Fotos", "3.jpg"])).is_some());
    assert!(!c.drive.get(fotos.id).unwrap().deleted);
    let u = c.svc.handle(Command::Usage).unwrap();
    assert_eq!(u["files"], 25);
    c.svc.handle(Command::Stop).unwrap();
}

#[test]
fn context_menu_actions_become_events() {
    let c = started();
    let f = c.drive.add_file(c.mine, "x.pdf", b"x");
    c.svc.handle(Command::SyncNow).unwrap();
    let path = p(&c.plat.root, &["Meine Dateien", "x.pdf"]);
    wait_for(|| c.plat.fs.get(&path).is_some());
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let l2 = lines.clone();
    c.svc.set_event_sink(Some(Arc::new(move |s: String| l2.lock().unwrap().push(s))));
    assert_eq!(c.svc.handle_action("share", &path), Ok(true));
    let ev: Value = lines.lock().unwrap().iter().map(|l| serde_json::from_str::<Value>(l).unwrap()).find(|v| v["event"] == "action").unwrap();
    assert_eq!((ev["action"].as_str(), ev["node"].as_u64(), ev["isDir"].as_bool()), (Some("share"), Some(f.id), Some(false)));
    assert!(c.svc.handle_action("rm", &path).is_err());
    assert!(c.svc.handle_action("share", Path::new("/etc/passwd")).is_err());
    assert!(c.svc.handle_action("share", &c.plat.root).is_err());
    c.svc.handle(Command::Stop).unwrap();
}
