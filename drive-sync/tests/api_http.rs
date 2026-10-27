//! ApiClient (HTTP, reqwest/rustls) gegen den Fake-Server: Routen, Kopfzeilen,
//! Fehler, Upload (einfach und fortsetzbar), Range-Download, Abgleich über HTTP.

mod common;

use common::{FakeServer, TOKEN};
use gc_drive_sync::core::api::{ApiClient, RESUMABLE_FROM};
use gc_drive_sync::core::engine::{Engine, EngineConfig, Shared};
use gc_drive_sync::core::model::{CommitRequest, Role};
use gc_drive_sync::core::remote::Remote;
use gc_drive_sync::core::state::State;
use gc_drive_sync::core::testing::{p, FakeDrive, FakeFs};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

fn client(url: &str, token: &str) -> ApiClient {
    let mut h = BTreeMap::new();
    h.insert("X-Client-Version".to_string(), "1.48.0".to_string());
    h.insert("X-Machine-Fingerprint".to_string(), "abc".to_string());
    ApiClient::new(url, token, h).unwrap()
}

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[test]
fn json_routes_and_headers() {
    let drive = Arc::new(FakeDrive::new());
    let root = drive.add_area("mine:1", "Meine Dateien", Role::Manage);
    for i in 0..7 {
        drive.add_file(root, &format!("f{i}.txt"), b"x");
    }
    let srv = FakeServer::start(drive.clone());
    let c = client(&srv.url, TOKEN);
    let me = c.me().unwrap();
    assert_eq!(me.latest, 7);
    let h = srv.last_headers.lock().unwrap().clone();
    assert_eq!(h.get("x-api-token").unwrap(), TOKEN);
    assert_eq!(h.get("x-client-version").unwrap(), "1.48.0");
    assert_eq!(h.get("x-machine-fingerprint").unwrap(), "abc");
    assert!(h.get("user-agent").unwrap().starts_with("gc-drive-sync/"));

    let areas = c.areas().unwrap();
    assert_eq!(areas[0].root_id, root);
    let page = c.children(root, 0).unwrap();
    assert_eq!(page.total, 7);
    assert_eq!(page.next, Some(3));
    let ch = c.changes(0).unwrap();
    assert!(ch.more);
    assert_eq!(ch.changes.len(), 4);
    assert_eq!(ch.changes[0].node.as_ref().unwrap().name, "f0.txt");

    let dir = c.mkdir(root, "Neu").unwrap();
    assert!(dir.is_dir);
    let e = c.mkdir(root, "neu").unwrap_err();
    assert_eq!((e.status, e.code.as_str()), (Some(409), "exists"));
    assert_eq!(e.current.unwrap().id, dir.id);
    let moved = c.update_node(dir.id, Some("Umbenannt"), None).unwrap();
    assert_eq!(moved.name, "Umbenannt");
    c.trash(dir.id).unwrap();
    assert!(c.node(dir.id).unwrap_err().not_found());
}

#[test]
fn wrong_token_is_offline() {
    let srv = FakeServer::start(Arc::new(FakeDrive::new()));
    let e = client(&srv.url, "falsch").me().unwrap_err();
    assert_eq!(e.status, Some(401));
    assert!(e.offline());
    // nicht erreichbar
    let e = client("http://127.0.0.1:9", TOKEN).me().unwrap_err();
    assert!(e.offline() && e.transient());
}

#[test]
fn small_upload_commit_conflict_and_download() {
    let drive = Arc::new(FakeDrive::new());
    let root = drive.add_area("mine:1", "Meine Dateien", Role::Manage);
    let srv = FakeServer::start(drive.clone());
    let c = client(&srv.url, TOKEN);
    let data = b"Hallo Drive".to_vec();
    let media = c.upload(&mut Cursor::new(data.clone()), &sha(&data), &mut |_, _| {}).unwrap();
    assert!(srv.last_headers.lock().unwrap().get("repr-digest").unwrap().starts_with("sha-256=:"));
    let node = c
        .commit(&CommitRequest {
            media_id: media.clone(),
            parent_id: root,
            name: "a.txt".into(),
            base_rev: None,
            mtime: Some(1_700_000_000_000),
            on_conflict: None,
        })
        .unwrap();
    assert_eq!(node.size, Some(11));
    // falsche Prüfsumme: Datei hat sich geändert
    assert_eq!(c.upload(&mut Cursor::new(data.clone()), &sha(b"anders"), &mut |_, _| {}).unwrap_err().code, "changed");
    // gleicher Name ohne baseRev → 409 conflict mit current
    let m2 = c.upload(&mut Cursor::new(b"zwei".to_vec()), &sha(b"zwei"), &mut |_, _| {}).unwrap();
    let e =
        c.commit(&CommitRequest { media_id: m2.clone(), parent_id: root, name: "a.txt".into(), base_rev: None, mtime: None, on_conflict: None }).unwrap_err();
    assert_eq!(e.code, "conflict");
    assert_eq!(e.current.as_ref().unwrap().id, node.id);
    let v2 =
        c.commit(&CommitRequest { media_id: m2, parent_id: root, name: "a.txt".into(), base_rev: Some(node.rev), mtime: None, on_conflict: None }).unwrap();
    assert_eq!(v2.rev, node.rev + 1);
    // check
    let chk = c.check(root, "a.txt", &v2.sha256.clone().unwrap(), 4).unwrap();
    assert!(chk.exists && chk.same);
    // content + Range
    let content = c.content(node.id).unwrap();
    let mut got = Vec::new();
    let n = c
        .download(content.media_id.as_deref().unwrap(), 1, 3, &mut |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
    assert_eq!((n, got.as_slice()), (2, &b"we"[..]));
    assert_eq!(srv.last_headers.lock().unwrap().get("range").unwrap(), "bytes=1-2");
    // Abbruch durch das Ziel
    let e = c.download(content.media_id.as_deref().unwrap(), 0, 4, &mut |_| Err("stop".into())).unwrap_err();
    assert_eq!(e.code, "cancelled");
}

#[test]
fn resumable_upload_survives_a_failed_part() {
    let drive = Arc::new(FakeDrive::new());
    drive.add_area("mine:1", "Meine Dateien", Role::Manage);
    let srv = FakeServer::start(drive.clone());
    let c = client(&srv.url, TOKEN);
    let data: Vec<u8> = (0..(RESUMABLE_FROM as usize + 300_000)).map(|i| (i % 253) as u8).collect();
    srv.fail_next_part.store(true, Ordering::SeqCst);
    let mut last = (0, 0);
    let media = c.upload(&mut Cursor::new(data.clone()), &sha(&data), &mut |a, b| last = (a, b)).unwrap();
    assert_eq!(drive.media_data(&media).unwrap(), data);
    assert_eq!(last, (data.len() as u64, data.len() as u64));
    let reqs = srv.requests.lock().unwrap().clone();
    let parts = reqs.iter().filter(|r| r.starts_with("PUT") && r.contains("uploadId=")).count();
    assert!(parts >= 3, "{reqs:?}"); // 2 Teile + 1 Wiederholung
    assert!(reqs.iter().any(|r| r.contains("/media/uploads/")));
}

#[test]
fn engine_over_http() {
    let drive = Arc::new(FakeDrive::new());
    let root = drive.add_area("mine:1", "Meine Dateien", Role::Manage);
    let d = drive.add_dir(root, "Fotos");
    drive.add_file(d.id, "a.jpg", b"jpeg");
    let srv = FakeServer::start(drive.clone());
    let remote: Arc<dyn Remote> = Arc::new(client(&srv.url, TOKEN));
    let sroot = PathBuf::from("/sync");
    let fs = Arc::new(FakeFs::new(&sroot));
    let mut e = Engine::new(EngineConfig { root: sroot.clone(), device_name: "PC".into() }, remote, fs.clone(), State::new("x"), Arc::new(Shared::default()));
    e.sync().unwrap();
    assert!(fs.get(&p(&sroot, &["Meine Dateien", "Fotos", "a.jpg"])).is_some());
    fs.user_write(&p(&sroot, &["Meine Dateien", "Fotos", "b.jpg"]), b"neu");
    e.queue_local(p(&sroot, &["Meine Dateien", "Fotos", "b.jpg"]));
    e.process_local().unwrap();
    let b = drive.find(d.id, "b.jpg").unwrap();
    assert_eq!(drive.file_data(b.id).unwrap(), b"neu");
}
