//! Start über den Starter (`gc-drive-sync.exe launch`), wie der Pro-Client es
//! macht (nur Windows): erste Zeile `ready` mit Pipe, Prozess-ID und Startweg,
//! Pipe nur für den Benutzer, `hello` → Antwort, `shutdown` → Kind und
//! Starter enden. Auf einem Runner ohne Benutzerkontensteuerung läuft der
//! Dienst im selben Prozess (`launch: inprocess`); die Zeile `LAUNCH-INFO`
//! zeigt, welcher Weg genommen wurde.
#![cfg(windows)]

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn launch_hands_over_the_pipe() {
    let base = std::env::temp_dir().join(format!("gcds-launch-{:016x}", rand::random::<u64>()));
    std::fs::create_dir_all(&base).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_gc-drive-sync"))
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
    println!("LAUNCH-INFO: {ready}");
    assert_eq!(ready["event"], "ready", "{first}");
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
            assert_eq!(v["result"]["protocol"], 2);
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
