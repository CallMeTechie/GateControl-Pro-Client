//! Start über den Starter (`gc-drive-sync.exe launch`), wie der Pro-Client es
//! macht (nur Windows): erste Zeile `ready` mit Pipe, Prozess-ID und Startweg,
//! Pipe nur für den Benutzer, `hello` → Antwort, `shutdown` → Kind und
//! Starter enden; ein beendeter Starter beendet das Kind (stdin).
//!
//! Auf einem Runner ohne Benutzerkontensteuerung wählt der Starter von sich
//! aus `inprocess`. Die beiden Wege mit eigenem Kindprozess (`token`:
//! CreateProcessWithTokenW mit dem Token der Shell, `parent`: Shell als
//! Elternprozess, Handles über den Explorer) werden deshalb zusätzlich mit
//! `GC_DRIVE_SYNC_FORCE_LAUNCH` erzwungen. Die Zeilen `LAUNCH-INFO` zeigen den
//! Weg.
#![cfg(windows)]

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn launch_hands_over_the_pipe() {
    run(None);
}

#[test]
fn launch_with_the_shell_token() {
    run(Some("token"));
}

#[test]
fn launch_with_the_shell_as_parent() {
    run(Some("parent"));
}

/// Kind und Starter beenden sich, wenn der Starter getötet wird (stdin schließt).
#[test]
fn killing_the_launcher_ends_the_child() {
    let base = std::env::temp_dir().join(format!("gcds-launch-k-{:016x}", rand::random::<u64>()));
    std::fs::create_dir_all(&base).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_gc-drive-sync"))
        .env("GC_DRIVE_SYNC_FORCE_LAUNCH", "token")
        .args(["launch", "--root"])
        .arg(base.join("root"))
        .arg("--data-dir")
        .arg(base.join("data"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut first).unwrap();
    let ready: Value = serde_json::from_str(first.trim()).unwrap_or(Value::Null);
    if ready["event"] != "ready" {
        let _ = child.kill();
        let _ = child.wait();
        panic!("Starter (token): {first}");
    }
    let pid = ready["pid"].as_u64().unwrap() as u32;
    child.kill().unwrap();
    let _ = child.wait();
    let until = Instant::now() + Duration::from_secs(20);
    while alive(pid) {
        assert!(Instant::now() < until, "Kind {pid} läuft nach dem Ende des Starters weiter");
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = std::fs::remove_dir_all(&base);
    println!("LAUNCH-INFO: Kind endet mit dem Starter");
}

fn alive(pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};
    unsafe {
        match OpenProcess(PROCESS_SYNCHRONIZE, false, pid) {
            Ok(h) => {
                let r = WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
                let _ = CloseHandle(h);
                r
            }
            Err(_) => false,
        }
    }
}

fn run(force: Option<&str>) {
    let base = std::env::temp_dir().join(format!("gcds-launch-{:016x}", rand::random::<u64>()));
    std::fs::create_dir_all(&base).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gc-drive-sync"));
    if let Some(f) = force {
        cmd.env("GC_DRIVE_SYNC_FORCE_LAUNCH", f);
    }
    let mut child = cmd
        .args(["launch", "--parent-pid", &std::process::id().to_string(), "--root"])
        .arg(base.join("root"))
        .arg("--data-dir")
        .arg(base.join("data"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    out.read_line(&mut first).unwrap();
    let ready: Value = serde_json::from_str(first.trim()).unwrap_or_else(|_| panic!("erste Zeile: {first}"));
    if ready["event"] != "ready" {
        let _ = child.wait();
        panic!("Starter ({force:?}): {first}");
    }
    println!("LAUNCH-INFO: {ready}");
    assert_eq!(ready["event"], "ready", "{first}");
    if let Some(f) = force {
        assert_eq!(ready["launch"], f, "erzwungener Weg");
        assert_ne!(ready["pid"].as_u64(), Some(child.id() as u64), "eigener Kindprozess");
    }
    let pipe = ready["pipe"].as_str().unwrap().to_string();
    assert!(pipe.starts_with(r"\\.\pipe\gatecontrol-drive-sync-S-1-"), "{pipe}");
    assert!(ready["pid"].as_u64().is_some());
    assert!(matches!(ready["launch"].as_str(), Some("token" | "parent" | "inprocess")), "{ready}");

    let f = std::fs::OpenOptions::new().read(true).write(true).open(&pipe).expect("Pipe öffnen");
    let mut w = f.try_clone().unwrap();
    let mut r = BufReader::new(f);
    writeln!(w, r#"{{"id":1,"cmd":"hello","version":"test","lang":"de"}}"#).unwrap();
    let mut line = String::new();
    loop {
        line.clear();
        r.read_line(&mut line).unwrap();
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        if v["id"] == 1 {
            assert_eq!(v["result"]["protocol"], 3);
            println!("LAUNCH-INFO: hello elevated={} knownFolders={}", v["result"]["elevated"], v["result"]["knownFolders"]);
            break;
        }
    }
    writeln!(w, r#"{{"id":2,"cmd":"shutdown"}}"#).unwrap();
    let until = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            assert!(st.success(), "Starter endet sauber: {st:?}");
            break;
        }
        assert!(Instant::now() < until, "Starter endet nicht");
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = std::fs::remove_dir_all(&base);
    println!("LAUNCH-RESULT: ok");
}
