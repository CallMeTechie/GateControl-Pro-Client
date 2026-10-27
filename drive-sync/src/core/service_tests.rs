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
    c.svc.handle(Command::Unregister).unwrap();
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
    assert_eq!(resp[0]["result"]["protocol"], 1);
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
