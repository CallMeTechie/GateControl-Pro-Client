use super::*;
use crate::core::model::Role;
use crate::core::testing::{p, FakeDrive, FakeFs};
use chrono::TimeZone;

struct T {
    d: Arc<FakeDrive>,
    fs: Arc<FakeFs>,
    e: Engine,
    root: PathBuf,
    mine: u64,
}

fn root() -> PathBuf {
    PathBuf::from("/sync")
}

fn setup() -> T {
    let d = Arc::new(FakeDrive::new());
    let mine = d.add_area("mine:1", "Meine Dateien", Role::Manage);
    let fs = Arc::new(FakeFs::new(&root()));
    let dd = d.clone();
    fs.set_hydrator(move |id| dd.file_data(id.node));
    let mut e = Engine::new(EngineConfig { root: root(), device_name: "PC-Max".into() }, d.clone(), fs.clone(), State::new("acc"), Arc::new(Shared::default()));
    e.set_clock(|| chrono::Local.with_ymd_and_hms(2026, 10, 27, 14, 5, 0).unwrap());
    T { d, fs, e, root: root(), mine }
}

impl T {
    fn path(&self, parts: &[&str]) -> PathBuf {
        p(&self.root, parts)
    }
    fn ph(&self, parts: &[&str]) -> Placeholder {
        self.fs.get(&self.path(parts)).expect("exists").placeholder.expect("placeholder")
    }
    fn local_change(&mut self, parts: &[&str]) {
        let path = self.path(parts);
        self.e.queue_local(path);
        self.e.process_local().unwrap();
    }
}

#[test]
fn full_sync_builds_placeholder_tree() {
    let mut t = setup();
    let fotos = t.d.add_dir(t.mine, "Fotos");
    for i in 0..5 {
        t.d.add_file(fotos.id, &format!("Bild {i}.jpg"), format!("bild{i}").as_bytes());
    }
    let brief = t.d.add_file(t.mine, "Brief.pdf", b"%PDF");
    t.d.clear_calls();
    t.e.sync().unwrap();

    assert!(t.ph(&["Meine Dateien"]).in_sync);
    for i in 0..5 {
        let ph = t.ph(&["Meine Dateien", "Fotos", &format!("Bild {i}.jpg")]);
        assert!(ph.in_sync && !ph.hydrated);
    }
    let b = t.ph(&["Meine Dateien", "Brief.pdf"]);
    assert_eq!(b.identity.as_ref().unwrap().node, brief.id);
    assert_eq!(b.identity.unwrap().media, brief.media_id);
    assert_eq!(t.e.state.cursor, t.d.latest());
    assert!(t.e.state.last_sync.is_some());
    // nichts hochgeladen
    assert!(!t.d.calls().iter().any(|c| c == "upload" || c == "commit"));
}

#[test]
fn local_new_file_and_folder_go_up() {
    let mut t = setup();
    t.e.sync().unwrap();
    t.fs.user_write(&t.path(&["Meine Dateien", "Notiz.txt"]), b"hallo");
    t.fs.user_mkdir(&t.path(&["Meine Dateien", "Projekt"]));
    t.fs.user_write(&t.path(&["Meine Dateien", "Projekt", "a.txt"]), b"aaa");
    t.local_change(&["Meine Dateien", "Notiz.txt"]);
    t.local_change(&["Meine Dateien", "Projekt"]);

    let n = t.d.find(t.mine, "Notiz.txt").unwrap();
    assert_eq!(t.d.file_data(n.id).unwrap(), b"hallo");
    let ph = t.ph(&["Meine Dateien", "Notiz.txt"]);
    assert!(ph.in_sync);
    assert_eq!(ph.identity.unwrap().node, n.id);
    let proj = t.d.find(t.mine, "Projekt").unwrap();
    assert!(proj.is_dir);
    let a = t.d.find(proj.id, "a.txt").unwrap();
    assert_eq!(t.d.file_data(a.id).unwrap(), b"aaa");
    assert!(t.ph(&["Meine Dateien", "Projekt", "a.txt"]).in_sync);
    assert_eq!(t.e.pending(), 0);
}

#[test]
fn new_file_in_new_folder_creates_parent_first() {
    let mut t = setup();
    t.e.sync().unwrap();
    t.fs.user_mkdir(&t.path(&["Meine Dateien", "A"]));
    t.fs.user_mkdir(&t.path(&["Meine Dateien", "A", "B"]));
    t.fs.user_write(&t.path(&["Meine Dateien", "A", "B", "c.txt"]), b"c");
    // nur das Ereignis der Datei kommt an
    t.local_change(&["Meine Dateien", "A", "B", "c.txt"]);
    let a = t.d.find(t.mine, "A").unwrap();
    let b = t.d.find(a.id, "B").unwrap();
    assert!(t.d.find(b.id, "c.txt").is_some());
}

#[test]
fn ignored_and_empty_files_stay_local() {
    let mut t = setup();
    t.e.sync().unwrap();
    t.fs.user_write(&t.path(&["Meine Dateien", "~$Bericht.docx"]), b"lock");
    t.fs.user_write(&t.path(&["Meine Dateien", "Neu.txt"]), b"");
    t.local_change(&["Meine Dateien", "~$Bericht.docx"]);
    t.local_change(&["Meine Dateien", "Neu.txt"]);
    assert!(t.d.live_children(t.mine).is_empty());
    assert!(t.e.errors().is_empty());
}

#[test]
fn same_file_already_on_server_is_adopted_without_upload() {
    let mut t = setup();
    t.e.sync().unwrap();
    // gleiche Datei: auf dem Server angelegt, aber Platzhalter noch nicht da
    t.fs.user_write(&t.path(&["Meine Dateien", "x.bin"]), b"same");
    let n = t.d.add_file(t.mine, "x.bin", b"same");
    t.d.clear_calls();
    t.local_change(&["Meine Dateien", "x.bin"]);
    assert!(!t.d.calls().contains(&"upload".to_string()));
    assert_eq!(t.ph(&["Meine Dateien", "x.bin"]).identity.unwrap().node, n.id);
}

#[test]
fn remote_changes_are_applied() {
    let mut t = setup();
    let doc = t.d.add_file(t.mine, "Doc.txt", b"v1");
    let old = t.d.add_file(t.mine, "Alt.txt", b"alt");
    t.e.sync().unwrap();
    // geladen, damit das Umbenennen die Daten behält
    t.fs.hydrate(&t.path(&["Meine Dateien", "Doc.txt"])).unwrap();

    let neu = t.d.add_file(t.mine, "Neu.txt", b"neu");
    t.d.rename(doc.id, "Dokument.txt");
    t.d.delete(old.id);
    let ordner = t.d.add_dir(t.mine, "Ordner");
    t.e.sync().unwrap();

    assert!(t.fs.get(&t.path(&["Meine Dateien", "Doc.txt"])).is_none());
    let moved = t.fs.get(&t.path(&["Meine Dateien", "Dokument.txt"])).unwrap();
    assert_eq!(moved.placeholder.as_ref().unwrap().identity.as_ref().unwrap().node, doc.id);
    assert!(moved.placeholder.unwrap().hydrated, "rename keeps local data");
    assert!(t.fs.get(&t.path(&["Meine Dateien", "Alt.txt"])).is_none());
    assert_eq!(t.ph(&["Meine Dateien", "Neu.txt"]).identity.unwrap().node, neu.id);
    assert_eq!(t.ph(&["Meine Dateien", "Ordner"]).identity.unwrap().node, ordner.id);

    // neue Fassung von jemand anderem → Platzhalter dehydriert, neue Identität
    let v2 = t.d.modify(doc.id, b"version 2");
    t.e.sync().unwrap();
    let ph = t.ph(&["Meine Dateien", "Dokument.txt"]);
    assert!(!ph.hydrated && ph.in_sync);
    assert_eq!(ph.identity.unwrap().media, v2.media_id);
    assert_eq!(t.fs.get(&t.path(&["Meine Dateien", "Dokument.txt"])).unwrap().size, 9);
}

#[test]
fn remote_folder_with_content_arrives_complete() {
    let mut t = setup();
    let other = t.d.add_area("family:1", "Familie", Role::Write);
    let f = t.d.add_dir(other, "Urlaub");
    t.d.add_file(f.id, "1.jpg", b"1");
    t.d.add_file(f.id, "2.jpg", b"2");
    t.e.sync().unwrap();
    assert!(t.fs.get(&t.path(&["Familie", "Urlaub", "2.jpg"])).is_some());
    // aus einem anderen Bereich hereinverschoben: nur der Ordner steht im Protokoll
    t.d.move_to_area(f.id, t.mine);
    t.e.sync().unwrap();
    assert!(t.fs.get(&t.path(&["Familie", "Urlaub"])).is_none());
    assert!(t.fs.get(&t.path(&["Meine Dateien", "Urlaub", "1.jpg"])).is_some());
    assert!(t.fs.get(&t.path(&["Meine Dateien", "Urlaub", "2.jpg"])).is_some());
}

#[test]
fn local_edit_uploads_new_version_with_base_rev() {
    let mut t = setup();
    let n = t.d.add_file(t.mine, "Text.txt", b"eins");
    t.e.sync().unwrap();
    t.fs.user_write(&t.path(&["Meine Dateien", "Text.txt"]), b"zwei");
    assert!(!t.ph(&["Meine Dateien", "Text.txt"]).in_sync);
    t.local_change(&["Meine Dateien", "Text.txt"]);
    let now = t.d.get(n.id).unwrap();
    assert_eq!(now.rev, n.rev + 1);
    assert_eq!(t.d.file_data(n.id).unwrap(), b"zwei");
    let ph = t.ph(&["Meine Dateien", "Text.txt"]);
    assert!(ph.in_sync);
    assert_eq!(ph.identity.unwrap().rev, now.rev);
    // das eigene Update kommt im Protokoll zurück – nichts passiert
    t.fs.take_ops();
    t.e.sync().unwrap();
    assert!(t.fs.take_ops().iter().all(|o| !o.contains("dehydrate")));
}

#[test]
fn edit_conflict_keeps_both_versions() {
    let mut t = setup();
    let n = t.d.add_file(t.mine, "Plan.xlsx", b"original");
    t.e.sync().unwrap();
    t.fs.user_write(&t.path(&["Meine Dateien", "Plan.xlsx"]), b"lokal");
    t.d.modify(n.id, b"server");
    // lokale Änderung zuerst verarbeitet → 409 → Konfliktkopie
    t.local_change(&["Meine Dateien", "Plan.xlsx"]);
    let cname = "Plan (Konflikt PC-Max 2026-10-27 14-05).xlsx";
    let c = t.d.find(t.mine, cname).expect("conflict copy on server");
    assert_eq!(t.d.file_data(c.id).unwrap(), b"lokal");
    assert_eq!(t.d.file_data(n.id).unwrap(), b"server");
    assert!(t.ph(&["Meine Dateien", cname]).in_sync);
    let orig = t.ph(&["Meine Dateien", "Plan.xlsx"]);
    assert_eq!(orig.identity.unwrap().rev, t.d.get(n.id).unwrap().rev);
}

#[test]
fn edit_conflict_found_by_poll() {
    let mut t = setup();
    let n = t.d.add_file(t.mine, "Plan.txt", b"original");
    t.e.sync().unwrap();
    t.fs.user_write(&t.path(&["Meine Dateien", "Plan.txt"]), b"lokal");
    t.d.modify(n.id, b"server");
    // die Server-Änderung kommt zuerst an
    t.e.sync().unwrap();
    let cname = "Plan (Konflikt PC-Max 2026-10-27 14-05).txt";
    assert_eq!(t.fs.data(&t.path(&["Meine Dateien", cname])).unwrap(), b"lokal");
    let c = t.d.find(t.mine, cname).expect("uploaded");
    assert_eq!(t.d.file_data(c.id).unwrap(), b"lokal");
    assert_eq!(t.ph(&["Meine Dateien", "Plan.txt"]).identity.unwrap().node, n.id);
}

#[test]
fn new_local_file_with_taken_name_becomes_conflict_copy() {
    let mut t = setup();
    t.e.sync().unwrap();
    t.fs.user_write(&t.path(&["Meine Dateien", "Liste.txt"]), b"meine");
    let theirs = t.d.add_file(t.mine, "Liste.txt", b"deren");
    t.local_change(&["Meine Dateien", "Liste.txt"]);
    let cname = "Liste (Konflikt PC-Max 2026-10-27 14-05).txt";
    let c = t.d.find(t.mine, cname).unwrap();
    assert_eq!(t.d.file_data(c.id).unwrap(), b"meine");
    assert_eq!(t.ph(&["Meine Dateien", "Liste.txt"]).identity.unwrap().node, theirs.id);
}

#[test]
fn local_rename_and_move_go_to_server() {
    let mut t = setup();
    let dir = t.d.add_dir(t.mine, "Archiv");
    let f = t.d.add_file(t.mine, "a.txt", b"a");
    t.e.sync().unwrap();
    t.fs.user_rename(&t.path(&["Meine Dateien", "a.txt"]), &t.path(&["Meine Dateien", "Archiv", "b.txt"]));
    t.local_change(&["Meine Dateien", "Archiv", "b.txt"]);
    let now = t.d.get(f.id).unwrap();
    assert_eq!((now.parent_id, now.name.as_str()), (Some(dir.id), "b.txt"));
    assert_eq!(t.ph(&["Meine Dateien", "Archiv", "b.txt"]).identity.unwrap().rev, now.rev);
    assert_eq!(t.e.state.rel_path(f.id).unwrap(), p(Path::new("Meine Dateien"), &["Archiv", "b.txt"]));
}

#[test]
fn local_rename_onto_taken_server_name() {
    let mut t = setup();
    let f = t.d.add_file(t.mine, "a.txt", b"a");
    t.e.sync().unwrap();
    t.fs.user_rename(&t.path(&["Meine Dateien", "a.txt"]), &t.path(&["Meine Dateien", "b.txt"]));
    t.d.add_file(t.mine, "b.txt", b"b"); // gleichzeitig auf dem Server
    t.local_change(&["Meine Dateien", "b.txt"]);
    let now = t.d.get(f.id).unwrap();
    assert_eq!(now.name, "b (Konflikt PC-Max 2026-10-27 14-05).txt");
    assert!(t.fs.get(&t.path(&["Meine Dateien", "b (Konflikt PC-Max 2026-10-27 14-05).txt"])).is_some());
}

#[test]
fn delete_notification_trashes_on_server() {
    let mut t = setup();
    let f = t.d.add_file(t.mine, "weg.txt", b"x");
    t.e.sync().unwrap();
    let path = t.path(&["Meine Dateien", "weg.txt"]);
    t.fs.user_delete(&path);
    t.e.note_deleted(f.id, path);
    t.e.process_local().unwrap();
    assert!(t.d.get(f.id).unwrap().deleted);
    assert!(t.e.state.get(f.id).is_none());
    // Netzfehler: bleibt vorgemerkt
    let g = t.d.add_file(t.mine, "auch.txt", b"y");
    t.e.sync().unwrap();
    let path = t.path(&["Meine Dateien", "auch.txt"]);
    t.fs.user_delete(&path);
    t.e.note_deleted(g.id, path);
    t.d.fail_next("trash", ApiError::network("down"));
    assert!(t.e.process_local().is_err());
    assert_eq!(t.e.pending(), 1);
    t.e.process_local().unwrap();
    assert!(t.d.get(g.id).unwrap().deleted);
}

#[test]
fn read_only_area_is_not_uploaded() {
    let mut t = setup();
    let ro = t.d.add_area("team:1", "Team", Role::Read);
    t.d.add_file(ro, "r.txt", b"r");
    t.e.sync().unwrap();
    assert_eq!(t.e.shared.area_writable("team:1"), Some(false));
    assert!(t.e.shared.is_root(ro));
    t.fs.user_write(&t.path(&["Team", "neu.txt"]), b"n");
    t.local_change(&["Team", "neu.txt"]);
    assert!(t.d.find(ro, "neu.txt").is_none());
    assert!(t.e.errors().iter().any(|e| e.code == "read_only"));
}

#[test]
fn child_area_seen_as_parent_is_not_synced() {
    let mut t = setup();
    let c = t.d.add_area("child:5", "Kinder · Lena", Role::Read);
    t.d.set_area("child:5", |a| a.via = Some("parent".into()));
    t.d.add_file(c, "x.txt", b"x");
    t.e.sync().unwrap();
    assert!(t.fs.get(&t.path(&["Kinder · Lena"])).is_none());
    assert!(t.e.state.area("child:5").is_none());
}

#[test]
fn removed_area_folder_goes_but_local_changes_stay() {
    let mut t = setup();
    let fam = t.d.add_area("family:1", "Familie", Role::Write);
    t.d.add_file(fam, "a.txt", b"a");
    let b = t.d.add_file(fam, "b.txt", b"b");
    t.e.sync().unwrap();
    t.fs.user_write(&t.path(&["Familie", "b.txt"]), b"lokal geaendert");
    let _ = b;
    t.d.remove_area("family:1");
    t.e.sync().unwrap();
    assert!(t.fs.get(&t.path(&["Familie", "a.txt"])).is_none());
    let kept = t.fs.get(&t.path(&["Familie", "b.txt"])).unwrap();
    assert!(kept.placeholder.is_none(), "kept as a normal file");
    assert_eq!(t.fs.data(&t.path(&["Familie", "b.txt"])).unwrap(), b"lokal geaendert");
}

#[test]
fn pinning_hydrates_and_unpinning_frees_space() {
    let mut t = setup();
    t.d.add_file(t.mine, "Video.mp4", b"0123456789");
    t.e.sync().unwrap();
    let path = t.path(&["Meine Dateien", "Video.mp4"]);
    t.fs.user_pin(&path, Pin::Pinned);
    t.local_change(&["Meine Dateien", "Video.mp4"]);
    assert!(t.ph(&["Meine Dateien", "Video.mp4"]).hydrated);
    assert_eq!(t.fs.data(&path).unwrap(), b"0123456789");
    t.fs.user_pin(&path, Pin::Unpinned);
    t.local_change(&["Meine Dateien", "Video.mp4"]);
    assert!(!t.ph(&["Meine Dateien", "Video.mp4"]).hydrated);
}

#[test]
fn pinned_folder_hydrates_files_below() {
    let mut t = setup();
    let d = t.d.add_dir(t.mine, "Offline");
    t.d.add_file(d.id, "1.txt", b"1");
    t.d.add_file(d.id, "2.txt", b"2");
    t.e.sync().unwrap();
    t.fs.user_pin(&t.path(&["Meine Dateien", "Offline"]), Pin::Pinned);
    t.local_change(&["Meine Dateien", "Offline"]);
    assert!(t.ph(&["Meine Dateien", "Offline", "1.txt"]).hydrated);
    assert!(t.ph(&["Meine Dateien", "Offline", "2.txt"]).hydrated);
    // neue Fassung eines angehefteten Elements wird gleich wieder geladen
    let n = t.d.find(d.id, "1.txt").unwrap();
    t.d.modify(n.id, b"neu");
    t.e.sync().unwrap();
    assert_eq!(t.fs.data(&t.path(&["Meine Dateien", "Offline", "1.txt"])).unwrap(), b"neu");
}

#[test]
fn offline_delete_is_sent_after_restart() {
    let mut t = setup();
    let f = t.d.add_file(t.mine, "a.txt", b"a");
    for i in 0..20 {
        t.d.add_file(t.mine, &format!("f{i}.txt"), b"x");
    }
    t.e.sync().unwrap();
    t.fs.user_delete(&t.path(&["Meine Dateien", "a.txt"]));
    t.e.needs_full = true; // wie nach einem Neustart mit gespeichertem Zustand
    t.e.sync().unwrap();
    assert!(t.d.get(f.id).unwrap().deleted);
}

#[test]
fn mass_offline_delete_waits_for_an_answer() {
    let mut t = setup();
    for i in 0..30 {
        t.d.add_file(t.mine, &format!("f{i}.txt"), b"x");
    }
    t.e.sync().unwrap();
    for i in 0..20 {
        t.fs.user_delete(&t.path(&["Meine Dateien", &format!("f{i}.txt")]));
    }
    t.e.needs_full = true;
    t.e.sync().unwrap();
    // nicht übertragen, wartet auf die Antwort
    assert_eq!(t.d.live_children(t.mine).len(), 30);
    assert!(t.e.errors().iter().any(|e| e.code == "mass_delete"));
    let held = t.e.shared.held.read().unwrap().clone().expect("Nachfrage");
    assert_eq!((held.files, held.items, held.offline), (20, 20, true));
    // ein weiterer voller Abgleich zählt nicht doppelt
    t.e.needs_full = true;
    t.e.sync().unwrap();
    assert_eq!(t.e.shared.held.read().unwrap().as_ref().unwrap().items, 20);
    // „Wiederherstellen“: Platzhalter kommen zurück, nichts gelöscht
    assert_eq!(t.e.decide_deletes(false).unwrap(), 20);
    assert!(t.fs.get(&t.path(&["Meine Dateien", "f3.txt"])).unwrap().placeholder.is_some());
    assert!(t.e.shared.held.read().unwrap().is_none());
    assert!(!t.e.errors().iter().any(|e| e.code == "mass_delete"));
    t.e.sync().unwrap();
    assert_eq!(t.d.live_children(t.mine).len(), 30);
}

#[test]
fn mass_delete_in_explorer_is_sent_after_confirmation() {
    let mut t = setup();
    let ordner = t.d.add_dir(t.mine, "Fotos");
    for i in 0..30 {
        t.d.add_file(ordner.id, &format!("Bild {i}.jpg"), b"x");
    }
    t.d.add_file(t.mine, "a.txt", b"a");
    t.e.sync().unwrap();
    // Ordner in den Papierkorb des Explorers (ein NOTIFY_RENAME nach außen)
    let path = t.path(&["Meine Dateien", "Fotos"]);
    t.fs.user_delete(&path);
    t.e.note_deleted(ordner.id, path);
    t.e.process_local().unwrap();
    assert!(!t.d.get(ordner.id).unwrap().deleted, "noch nicht gelöscht");
    assert_eq!(t.e.shared.held.read().unwrap().as_ref().unwrap().files, 30);
    // weitere Löschungen während der Nachfrage warten mit
    let a = t.d.find(t.mine, "a.txt").unwrap();
    t.fs.user_delete(&t.path(&["Meine Dateien", "a.txt"]));
    t.e.note_deleted(a.id, t.path(&["Meine Dateien", "a.txt"]));
    t.e.process_local().unwrap();
    assert!(!t.d.get(a.id).unwrap().deleted);
    // „Löschen übertragen“
    assert_eq!(t.e.decide_deletes(true).unwrap(), 2);
    t.e.process_local().unwrap();
    assert!(t.d.get(ordner.id).unwrap().deleted);
    assert!(t.d.get(a.id).unwrap().deleted);
}

#[test]
fn few_deletes_go_through_without_asking() {
    let mut t = setup();
    for i in 0..40 {
        t.d.add_file(t.mine, &format!("f{i}.txt"), b"x");
    }
    t.e.sync().unwrap();
    for i in 0..3 {
        let n = t.d.find(t.mine, &format!("f{i}.txt")).unwrap();
        let path = t.path(&["Meine Dateien", &format!("f{i}.txt")]);
        t.fs.user_delete(&path);
        t.e.note_deleted(n.id, path);
    }
    t.e.process_local().unwrap();
    assert_eq!(t.d.live_children(t.mine).len(), 37);
    assert!(t.e.shared.held.read().unwrap().is_none());
}

#[test]
fn unsynced_lists_what_is_not_on_the_server() {
    let mut t = setup();
    t.d.add_file(t.mine, "a.txt", b"a");
    t.e.sync().unwrap();
    assert_eq!(t.e.unsynced(10).0, 0);
    t.fs.user_write(&t.path(&["Meine Dateien", "neu.txt"]), b"neu");
    t.fs.user_write(&t.path(&["Meine Dateien", "a.txt"]), b"geaendert");
    t.fs.user_write(&t.path(&["Meine Dateien", "~$sperre.docx"]), b"x");
    t.fs.user_mkdir(&t.path(&["Meine Dateien", "Leer"]));
    let (n, paths) = t.e.unsynced(10);
    assert_eq!(n, 3, "{paths:?}");
    assert_eq!(t.e.unsynced(1).1.len(), 1);
}

#[test]
fn moved_while_offline_is_a_move_not_a_delete() {
    let mut t = setup();
    let d = t.d.add_dir(t.mine, "Ziel");
    let f = t.d.add_file(t.mine, "a.txt", b"a");
    t.e.sync().unwrap();
    t.fs.user_rename(&t.path(&["Meine Dateien", "a.txt"]), &t.path(&["Meine Dateien", "Ziel", "a.txt"]));
    t.e.needs_full = true;
    t.e.sync().unwrap();
    let now = t.d.get(f.id).unwrap();
    assert!(!now.deleted);
    assert_eq!(now.parent_id, Some(d.id));
}

#[test]
fn existing_local_files_on_first_sync() {
    let mut t = setup();
    t.d.add_file(t.mine, "gleich.txt", b"gleich");
    t.d.add_file(t.mine, "anders.txt", b"server");
    t.fs.user_mkdir(&t.path(&["Meine Dateien"]));
    t.fs.user_write(&t.path(&["Meine Dateien", "gleich.txt"]), b"gleich");
    t.fs.user_write(&t.path(&["Meine Dateien", "anders.txt"]), b"lokal");
    t.fs.user_write(&t.path(&["Meine Dateien", "nur-lokal.txt"]), b"nl");
    t.e.sync().unwrap();
    assert!(t.ph(&["Meine Dateien", "gleich.txt"]).in_sync);
    assert!(t.ph(&["Meine Dateien", "gleich.txt"]).hydrated);
    assert!(t.d.find(t.mine, "nur-lokal.txt").is_some());
    let c = t.d.find(t.mine, "anders (Konflikt PC-Max 2026-10-27 14-05).txt").unwrap();
    assert_eq!(t.d.file_data(c.id).unwrap(), b"lokal");
}

#[test]
fn busy_file_is_retried() {
    let mut t = setup();
    t.e.sync().unwrap();
    let path = t.path(&["Meine Dateien", "offen.docx"]);
    t.fs.user_write(&path, b"wird geschrieben");
    t.fs.lock(&path, true);
    t.local_change(&["Meine Dateien", "offen.docx"]);
    assert_eq!(t.e.pending(), 1);
    assert!(t.d.find(t.mine, "offen.docx").is_none());
    t.fs.lock(&path, false);
    t.e.process_local().unwrap();
    assert!(t.d.find(t.mine, "offen.docx").is_some());
}

#[test]
fn files_outside_areas_are_reported() {
    let mut t = setup();
    t.e.sync().unwrap();
    t.fs.user_write(&t.path(&["lose.txt"]), b"x");
    t.local_change(&["lose.txt"]);
    assert!(t.e.errors().iter().any(|e| e.code == "outside_area"));
}

#[test]
fn network_errors_bubble_up_and_keep_work() {
    let mut t = setup();
    t.e.sync().unwrap();
    t.fs.user_write(&t.path(&["Meine Dateien", "n.txt"]), b"n");
    t.d.fail_next("check", ApiError::network("down"));
    t.e.queue_local(t.path(&["Meine Dateien", "n.txt"]));
    assert!(t.e.process_local().unwrap_err().offline());
    assert_eq!(t.e.pending(), 1);
    t.e.process_local().unwrap();
    assert!(t.d.find(t.mine, "n.txt").is_some());
}

#[test]
fn detach_removes_online_only_and_keeps_local_data() {
    let mut t = setup();
    t.d.add_file(t.mine, "online.txt", b"o");
    t.d.add_file(t.mine, "geladen.txt", b"g");
    t.e.sync().unwrap();
    t.fs.hydrate(&t.path(&["Meine Dateien", "geladen.txt"])).unwrap();
    t.e.detach_all().unwrap();
    assert!(t.fs.get(&t.path(&["Meine Dateien", "online.txt"])).is_none());
    let g = t.fs.get(&t.path(&["Meine Dateien", "geladen.txt"])).unwrap();
    assert!(g.placeholder.is_none());
    assert!(t.fs.get(&t.path(&["Meine Dateien"])).unwrap().placeholder.is_none());
    assert!(t.e.state.areas.is_empty());
}

#[test]
fn area_label_change_renames_folder() {
    let mut t = setup();
    t.d.add_file(t.mine, "a.txt", b"a");
    t.e.sync().unwrap();
    t.d.set_area("mine:1", |a| a.label = "Meine Ablage".into());
    t.e.sync().unwrap();
    assert!(t.fs.get(&t.path(&["Meine Ablage", "a.txt"])).is_some());
    assert!(t.fs.get(&t.path(&["Meine Dateien"])).is_none());
}

#[test]
fn duplicate_area_labels_get_unique_folders() {
    let mut t = setup();
    t.d.add_area("team:1", "Team", Role::Write);
    t.d.add_area("team:2", "Team", Role::Write);
    t.e.sync().unwrap();
    assert!(t.fs.get(&t.path(&["Team"])).is_some());
    assert!(t.fs.get(&t.path(&["Team (2)"])).is_some());
}

#[test]
fn stop_flag_cancels() {
    let mut t = setup();
    t.e.shared.stop.store(true, Ordering::SeqCst);
    assert_eq!(t.e.sync().unwrap_err().code, "cancelled");
}
