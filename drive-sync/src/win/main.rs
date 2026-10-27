//! Programmstart unter Windows.
//!
//!   gc-drive-sync.exe [run] [--parent-pid <pid>] [--pipe <name>] [--root <dir>] [--data-dir <dir>]
//!       Dienst: erzeugt die Pipe, schreibt eine Zeile
//!       {"event":"ready","pipe":"\\\\.\\pipe\\…","pid":…,"version":"…","protocol":1}
//!       auf stdout und bedient den Pro-Client (PROTOCOL.md). Endet mit
//!       `shutdown` oder wenn der Prozess `--parent-pid` endet.
//!   gc-drive-sync.exe unregister [--root <dir>] [--data-dir <dir>]
//!       Sync-Root abmelden (Deinstallation): Platzhalter „nur online“ weg,
//!       geladene/geänderte Dateien bleiben als normale Dateien.
//!   gc-drive-sync.exe info
//!       Ob die Cloud Files API hier nutzbar ist (JSON).
//!   gc-drive-sync.exe --version

use super::util::{current_user_sid, wide_str, OwnedHandle};
use super::{default_data_dir, default_root, pipe, syncroot, WinPlatform};
use crate::core::service::{http_remote, Service};
use serde_json::json;
use std::io::{BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
use windows::Win32::System::Threading::{CreateMutexW, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE};

struct Args {
    cmd: String,
    pipe: Option<String>,
    parent: Option<u32>,
    root: Option<PathBuf>,
    data: Option<PathBuf>,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args { cmd: "run".into(), pipe: None, parent: None, root: None, data: None };
    let mut it = argv.iter().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--pipe" => a.pipe = it.next().cloned(),
            "--parent-pid" => a.parent = it.next().and_then(|v| v.parse().ok()),
            "--root" => a.root = it.next().map(PathBuf::from),
            "--data-dir" => a.data = it.next().map(PathBuf::from),
            "run" | "unregister" | "info" | "--version" | "--help" => a.cmd = x.trim_start_matches('-').to_string(),
            other => return Err(format!("unbekannt: {other}")),
        }
    }
    Ok(a)
}

fn out(v: serde_json::Value) {
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "{v}");
    let _ = o.flush();
}

pub fn run() -> i32 {
    let argv: Vec<String> = std::env::args().collect();
    let args = match parse(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    match args.cmd.as_str() {
        "version" => {
            println!("gc-drive-sync {}", env!("CARGO_PKG_VERSION"));
            return 0;
        }
        "help" => {
            println!("gc-drive-sync [run|unregister|info] [--parent-pid N] [--pipe NAME] [--root DIR] [--data-dir DIR]");
            return 0;
        }
        "info" => {
            let root = args.root.clone().unwrap_or_else(default_root);
            let v = match syncroot::platform_info() {
                Ok((b, r, i)) => json!({ "cfapi": true, "build": b, "revision": r, "integration": i, "registered": syncroot::is_registered(&root) }),
                Err(e) => json!({ "cfapi": false, "error": e }),
            };
            out(v);
            return 0;
        }
        _ => {}
    }
    let sid = match current_user_sid() {
        Ok(s) => s,
        Err(e) => {
            out(json!({ "event": "error", "code": "sid", "message": e }));
            return 1;
        }
    };
    let root = args.root.clone().unwrap_or_else(default_root);
    let data = args.data.clone().unwrap_or_else(default_data_dir);
    let platform = Arc::new(WinPlatform::new(&sid, root, data));
    let svc = Service::new(platform, http_remote());

    if args.cmd == "unregister" {
        return match svc.unregister() {
            Ok(()) => {
                out(json!({ "unregistered": true }));
                0
            }
            Err(e) => {
                out(json!({ "unregistered": false, "error": e.message }));
                1
            }
        };
    }

    // eine Instanz je Benutzer
    let mname = wide_str(&format!("Local\\GateControlDriveSync-{sid}"));
    let _mutex = match unsafe { CreateMutexW(None, false, PCWSTR(mname.as_ptr())) } {
        Ok(h) => {
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                out(json!({ "event": "error", "code": "already_running", "message": "gc-drive-sync läuft bereits" }));
                return 3;
            }
            OwnedHandle(h)
        }
        Err(e) => {
            out(json!({ "event": "error", "code": "mutex", "message": e.to_string() }));
            return 1;
        }
    };

    let name = args.pipe.clone().unwrap_or_else(|| pipe::pipe_name(&sid));
    let server = match pipe::PipeServer::create(&name, &sid) {
        Ok(s) => s,
        Err(e) => {
            out(json!({ "event": "error", "code": "pipe", "message": e }));
            return 1;
        }
    };

    if let Some(pid) = args.parent {
        match unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) } {
            Ok(h) => {
                let h = OwnedHandle(h);
                let s = svc.clone();
                std::thread::spawn(move || {
                    let h = h;
                    unsafe { WaitForSingleObject(h.0, INFINITE) };
                    s.log("info", "Pro-Client beendet – gc-drive-sync endet");
                    s.stop_runner();
                    std::process::exit(0);
                });
            }
            Err(e) => {
                out(json!({ "event": "error", "code": "parent", "message": e.to_string() }));
                return 1;
            }
        }
    }

    out(
        json!({ "event": "ready", "pipe": server.name, "pid": std::process::id(), "version": env!("CARGO_PKG_VERSION"), "protocol": crate::core::protocol::PROTOCOL_VERSION }),
    );
    svc.log("info", &format!("gc-drive-sync {} bereit", env!("CARGO_PKG_VERSION")));

    while !svc.quit.load(Ordering::SeqCst) {
        match server.accept(&svc.quit) {
            Ok(Some(conn)) => {
                if let Some(pid) = server.client_pid() {
                    svc.log("info", &format!("Pipe verbunden (Prozess {pid})"));
                }
                svc.serve(BufReader::new(conn.clone()), conn);
                server.disconnect();
            }
            Ok(None) => break,
            Err(e) => {
                svc.log("warn", &format!("Pipe: {e}"));
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
    svc.stop_runner();
    0
}
