use super::*;
use crate::core::engine::{EngineConfig, Shared};
use crate::core::localfs::{LocalFs, Pin};
use crate::core::model::Role;
use crate::core::state::State;
use crate::core::testing::{p, FakeDrive, FakeFs};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Windows-Ordner im Speicher; `fail_set`: SHSetKnownFolderPath schlägt fehl.
struct FakeKnown {
    paths: Mutex<HashMap<KnownFolder, PathBuf>>,
    fail_set: Mutex<bool>,
}

impl KnownFolders for FakeKnown {
    fn get(&self, f: KnownFolder) -> Result<PathBuf, String> {
        self.paths.lock().unwrap().get(&f).cloned().ok_or_else(|| "unknown".into())
    }
    fn set(&self, f: KnownFolder, path: &Path) -> Result<(), String> {
        if *self.fail_set.lock().unwrap() {
            return Err("access denied".into());
        }
        self.paths.lock().unwrap().insert(f, path.to_path_buf());
        Ok(())
    }
    fn default_path(&self, f: KnownFolder) -> PathBuf {
        PathBuf::from("/home/max").join(f.default_leaf())
    }
}

struct T {
    d: Arc<FakeDrive>,
    fs: Arc<FakeFs>,
    e: Engine,
    known: FakeKnown,
    data: tempfile::TempDir,
    mine: u64,
}

fn noop(_: &str, _: u64, _: u64) {}

fn setup() -> T {
    let d = Arc::new(FakeDrive::new());
    let mine = d.add_area("mine:1", "Meine Dateien", Role::Manage);
    let root = PathBuf::from("/sync");
    let fs = Arc::new(FakeFs::new(&root));
    let dd = d.clone();
    fs.set_hydrator(move |id| dd.file_data(id.node));
    for x in ["/home", "/home/max", "/home/max/Documents"] {
        fs.add_root(Path::new(x));
    }
    let docs = PathBuf::from("/home/max/Documents");
    fs.user_write(&docs.join("Brief.txt"), b"Hallo");
    fs.user_mkdir(&docs.join("Steuer"));
    fs.user_write(&docs.join("Steuer").join("2025.pdf"), b"%PDF-steuer");
    fs.user_write(&docs.join("desktop.ini"), b"[.ShellClassInfo]");
    let mut e = Engine::new(EngineConfig { root, device_name: "PC-Max".into() }, d.clone(), fs.clone(), State::new("acc"), Arc::new(Shared::default()));
    e.sync().unwrap();
    let known = FakeKnown { paths: Mutex::new(HashMap::from([(KnownFolder::Documents, docs)])), fail_set: Mutex::new(false) };
    T { d, fs, e, known, data: tempfile::tempdir().unwrap(), mine }
}

impl T {
    fn relocate(&mut self, name: Option<&str>) -> Result<Value, ProtoError> {
        let args =
            RelocateArgs { known: &self.known, data_dir: self.data.path(), folder: KnownFolder::Documents, name: name.map(str::to_string), device: "PC-Max" };
        relocate(&mut self.e, args, &noop)
    }
    fn restore(&mut self) -> Result<Value, ProtoError> {
        restore(&mut self.e, &self.known, self.data.path(), KnownFolder::Documents, "PC-Max", &noop)
    }
    fn path(&self, parts: &[&str]) -> PathBuf {
        p(Path::new("/sync"), parts)
    }
}

#[test]
fn relocate_moves_everything_and_uploads() {
    let mut t = setup();
    let r = t.relocate(Some("Dokumente")).unwrap();
    assert_eq!(r["moved"], 3);
    let target = t.path(&["Meine Dateien", "Dokumente"]);
    assert_eq!(t.known.get(KnownFolder::Documents).unwrap(), target);
    assert_eq!(t.fs.data(&target.join("Brief.txt")).unwrap(), b"Hallo");
    assert_eq!(t.fs.data(&target.join("Steuer").join("2025.pdf")).unwrap(), b"%PDF-steuer");
    assert!(t.fs.get(Path::new("/home/max/Documents")).is_none(), "leerer alter Ordner ist weg");
    assert_eq!(load_records(t.data.path())["documents"].from, PathBuf::from("/home/max/Documents"));

    // der Abgleich lädt hoch (desktop.ini bleibt nur lokal)
    t.e.process_local().unwrap();
    let dir = t.d.find(t.mine, "Dokumente").expect("Ordner im Drive");
    assert_eq!(t.d.file_data(t.d.find(dir.id, "Brief.txt").unwrap().id).unwrap(), b"Hallo");
    let steuer = t.d.find(dir.id, "Steuer").unwrap();
    assert!(t.d.find(steuer.id, "2025.pdf").is_some());
    assert!(t.d.find(dir.id, "desktop.ini").is_none());
    assert!(t.fs.get(&target.join("Brief.txt")).unwrap().in_sync());

    assert_eq!(t.relocate(None).unwrap_err().code, "already_relocated");
    let l = list(&t.known, Path::new("/sync"), t.data.path());
    let docs = l["folders"].as_array().unwrap().iter().find(|f| f["key"] == "documents").unwrap().clone();
    assert_eq!((docs["inDrive"].as_bool(), docs["from"].as_str()), (Some(true), Some("/home/max/Documents")));
}

#[test]
fn relocate_merges_with_an_existing_drive_folder() {
    let mut t = setup();
    // derselbe Ordner kommt schon von einem anderen PC
    let dir = t.d.add_dir(t.mine, "Documents");
    t.d.add_file(dir.id, "Brief.txt", b"vom Laptop");
    t.e.sync().unwrap();
    t.relocate(None).unwrap();
    let target = t.path(&["Meine Dateien", "Documents"]);
    // nichts überschrieben: die Datei des Laptops bleibt, die lokale bekommt einen Konfliktnamen
    assert!(t.fs.get(&target.join("Brief.txt")).unwrap().placeholder.is_some());
    let names: Vec<String> = t.fs.paths().into_iter().filter(|k| k.starts_with("/sync/meine dateien/documents/brief")).collect();
    assert_eq!(names.len(), 2, "{names:?}");
    t.e.process_local().unwrap();
    assert_eq!(t.d.live_children(dir.id).iter().filter(|n| n.name.starts_with("Brief")).count(), 2);
    assert_eq!(t.d.file_data(t.d.find(dir.id, "Brief.txt").unwrap().id).unwrap(), b"vom Laptop");
}

#[test]
fn relocate_rolls_back_when_a_file_is_in_use() {
    let mut t = setup();
    t.fs.lock(Path::new("/home/max/Documents/Steuer/2025.pdf"), true);
    let e = t.relocate(None).unwrap_err();
    assert_eq!(e.code, "move_failed");
    assert_eq!(e.data.as_ref().unwrap()["rolledBack"], true);
    // alles wieder am alten Ort, Windows-Ordner unverändert, kein Ziel-Ordner
    assert_eq!(t.fs.data(Path::new("/home/max/Documents/Brief.txt")).unwrap(), b"Hallo");
    assert!(t.fs.get(Path::new("/home/max/Documents/Steuer/2025.pdf")).is_some());
    assert_eq!(t.known.get(KnownFolder::Documents).unwrap(), PathBuf::from("/home/max/Documents"));
    assert!(t.fs.get(&t.path(&["Meine Dateien", "Documents"])).is_none());
    assert!(load_records(t.data.path()).is_empty());
}

#[test]
fn relocate_rolls_back_when_windows_refuses_the_new_path() {
    let mut t = setup();
    *t.known.fail_set.lock().unwrap() = true;
    assert_eq!(t.relocate(None).unwrap_err().code, "set_failed");
    assert_eq!(t.fs.data(Path::new("/home/max/Documents/Brief.txt")).unwrap(), b"Hallo");
    assert!(t.fs.get(&t.path(&["Meine Dateien", "Documents"])).is_none());
}

#[test]
fn relocate_needs_a_writable_personal_area() {
    let mut t = setup();
    t.d.set_area("mine:1", |a| a.role = Role::Read);
    t.e.sync().unwrap();
    assert_eq!(t.relocate(None).unwrap_err().code, "read_only");
    assert!(t.fs.get(Path::new("/home/max/Documents/Brief.txt")).is_some());
}

#[test]
fn restore_loads_everything_and_keeps_the_drive_copy() {
    let mut t = setup();
    t.relocate(None).unwrap();
    t.e.process_local().unwrap();
    let target = t.path(&["Meine Dateien", "Documents"]);
    // eine Datei ist nur online (Speicher freigegeben), ein Ordner angeheftet
    t.fs.dehydrate(&target.join("Brief.txt")).unwrap();
    t.fs.user_pin(&target.join("Steuer"), Pin::Pinned);
    let server_files = t.d.live_children(t.d.find(t.mine, "Documents").unwrap().id).len();
    t.d.clear_calls();

    let r = t.restore().unwrap();
    assert_eq!(r["to"], "/home/max/Documents");
    let docs = Path::new("/home/max/Documents");
    assert_eq!(t.known.get(KnownFolder::Documents).unwrap(), docs);
    let brief = t.fs.get(&docs.join("Brief.txt")).unwrap();
    assert!(brief.placeholder.is_none(), "normale Datei");
    assert_eq!(t.fs.data(&docs.join("Brief.txt")).unwrap(), b"Hallo");
    assert_eq!(t.fs.data(&docs.join("Steuer").join("2025.pdf")).unwrap(), b"%PDF-steuer");
    assert!(t.fs.get(&docs.join("desktop.ini")).is_some());
    assert!(load_records(t.data.path()).is_empty());

    // nichts auf dem Server gelöscht; der Drive-Ordner kommt als „nur online“ zurück
    t.e.sync().unwrap();
    let dir = t.d.find(t.mine, "Documents").unwrap();
    assert_eq!(t.d.live_children(dir.id).len(), server_files);
    let ph = t.fs.get(&target.join("Brief.txt")).unwrap().placeholder.unwrap();
    assert!(ph.in_sync && !ph.hydrated);
    assert!(!t.d.calls().iter().any(|c| c.starts_with("trash")), "{:?}", t.d.calls());
}

#[test]
fn restore_stops_before_anything_moves_when_a_file_cannot_load() {
    let mut t = setup();
    t.relocate(None).unwrap();
    t.e.process_local().unwrap();
    let target = t.path(&["Meine Dateien", "Documents"]);
    t.fs.dehydrate(&target.join("Brief.txt")).unwrap();
    t.fs.set_hydrator(|_| None); // Server nicht erreichbar
    let e = t.restore().unwrap_err();
    assert_eq!(e.code, "hydrate_failed");
    assert_eq!(t.known.get(KnownFolder::Documents).unwrap(), target);
    assert!(t.fs.get(&target.join("Steuer").join("2025.pdf")).unwrap().placeholder.is_some());
    assert!(t.fs.get(Path::new("/home/max/Documents")).is_none());
}

#[test]
fn restore_refuses_a_folder_that_is_not_in_the_drive() {
    let mut t = setup();
    assert_eq!(t.restore().unwrap_err().code, "not_relocated");
}

#[test]
fn usage_counts_local_and_online_files() {
    let mut t = setup();
    t.d.add_file(t.mine, "online.bin", &[7u8; 1000]);
    t.e.sync().unwrap();
    t.fs.user_write(&t.path(&["Meine Dateien", "lokal.txt"]), b"12345");
    let u = usage(t.fs.as_ref(), Path::new("/sync"));
    assert_eq!(u["files"], 2);
    assert_eq!(u["totalBytes"], 1005);
    assert_eq!(u["localBytes"], 5);
    assert_eq!(u["localFiles"], 1);
}

#[test]
fn paths_under() {
    assert!(is_under(Path::new(r"C:\Users\Max\GateControl Drive\Meine Dateien\Desktop"), Path::new(r"c:\users\max\gatecontrol drive")));
    assert!(is_under(Path::new("/sync"), Path::new("/sync/")));
    assert!(!is_under(Path::new(r"C:\Users\Max\GateControl Drive 2"), Path::new(r"C:\Users\Max\GateControl Drive")));
}
