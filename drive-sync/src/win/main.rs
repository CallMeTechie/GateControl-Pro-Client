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
//!   gc-drive-sync.exe launch --parent-pid <pid>
//!       Wie `run`, aber mit den Rechten des angemeldeten Benutzers, auch wenn
//!       der Aufrufer erhöht läuft (launch.rs). Der Starter reicht die erste
//!       Zeile weiter und bleibt als Wächter, bis das Kind endet.
//!   gc-drive-sync.exe action <share|portal|versions> <Pfad>
//!       Explorer-Kontextmenü → laufender Dienst (actions.rs).
//!   gc-drive-sync.exe relocated
//!       Liegen Windows-Ordner im Drive? stdout {"relocated":[…]}; Exit-Code 0:
//!       keiner, 4: mindestens einer (der Deinstaller bricht dann ab).
//!   gc-drive-sync.exe info
//!       Ob die Cloud Files API hier nutzbar ist, Rechte, Kontextmenü (JSON).
//!   gc-drive-sync.exe --version
//!
//! Weitere Schalter für `run`: `--watch-stdin` (endet, wenn stdin schließt –
//! der Starter ist weg), `--client-sid <SID>` (Pipe zusätzlich für dieses Konto).

use super::util::{current_user_sid, wide_str, OwnedHandle};
use super::{actions, default_data_dir, default_root, launch, pipe, shellmenu, syncroot, WinPlatform};
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
    watch_stdin: bool,
    client_sid: Option<String>,
    /// `action <a> <Pfad>`
    action: Vec<String>,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args { cmd: "run".into(), pipe: None, parent: None, root: None, data: None, watch_stdin: false, client_sid: None, action: vec![] };
    let mut it = argv.iter().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--pipe" => a.pipe = it.next().cloned(),
            "--parent-pid" => a.parent = it.next().and_then(|v| v.parse().ok()),
            "--root" => a.root = it.next().map(PathBuf::from),
            "--data-dir" => a.data = it.next().map(PathBuf::from),
            "--watch-stdin" => a.watch_stdin = true,
            "--client-sid" => a.client_sid = it.next().filter(|s| pipe::valid_sid(s)).cloned(),
            "action" => {
                a.cmd = "action".into();
                a.action = it.by_ref().take(2).cloned().collect();
            }
            "run" | "launch" | "unregister" | "relocated" | "info" | "--version" | "--help" => a.cmd = x.trim_start_matches('-').to_string(),
            other => return Err(format!("unbekannt: {other}")),
        }
    }
    Ok(a)
}

/// Argumente für das Kind von `launch` (ohne `launch`).
fn child_args(a: &Args) -> Vec<String> {
    let mut v = vec!["run".to_string()];
    if let Some(p) = a.parent {
        v.extend(["--parent-pid".into(), p.to_string()]);
    }
    if let Some(r) = &a.root {
        v.extend(["--root".into(), r.to_string_lossy().to_string()]);
    }
    if let Some(d) = &a.data {
        v.extend(["--data-dir".into(), d.to_string_lossy().to_string()]);
    }
    v
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
            println!("gc-drive-sync [run|launch|unregister|relocated|info|action <a> <path>] [--parent-pid N] [--pipe NAME] [--root DIR] [--data-dir DIR]");
            return 0;
        }
        "info" => {
            let root = args.root.clone().unwrap_or_else(default_root);
            let mut v = match syncroot::platform_info() {
                Ok((b, r, i)) => json!({ "cfapi": true, "build": b, "revision": r, "integration": i, "registered": syncroot::is_registered(&root) }),
                Err(e) => json!({ "cfapi": false, "error": e }),
            };
            v["launch"] = launch::describe();
            v["menu"] = json!(shellmenu::applies_of(shellmenu::VERB).is_some());
            out(v);
            return 0;
        }
        "action" => {
            let (Some(a), Some(p)) = (args.action.first(), args.action.get(1)) else { return 2 };
            return match current_user_sid() {
                Ok(sid) => actions::client(&sid, a, p),
                Err(_) => 1,
            };
        }
        "launch" => match launch::plan(&child_args(&args)) {
            Ok(launch::Plan::Child(c)) => return launch::supervise(c, args.parent),
            Ok(launch::Plan::InProcess { elevated, why }) => return serve_main(args, elevated, Some(why)),
            Err(e) => {
                let code = if e.starts_with("wrong_user") { "wrong_user" } else { "launch" };
                out(json!({ "event": "error", "code": code, "message": e }));
                return 1;
            }
        },
        _ => {}
    }
    let elevated = launch::self_elevated();
    serve_main(args, elevated, None)
}

/// `run` (oder `launch` im selben Prozess).
fn serve_main(args: Args, elevated: bool, launch_note: Option<String>) -> i32 {
    let sid = match current_user_sid() {
        Ok(s) => s,
        Err(e) => {
            out(json!({ "event": "error", "code": "sid", "message": e }));
            return 1;
        }
    };
    let root = args.root.clone().unwrap_or_else(default_root);
    let data = args.data.clone().unwrap_or_else(default_data_dir);
    let mut platform = WinPlatform::new(&sid, root, data);
    platform.elevated = elevated;
    let platform = Arc::new(platform);
    let svc = Service::new(platform, http_remote());

    if args.cmd == "relocated" {
        let rel = svc.relocated();
        out(json!({ "relocated": rel }));
        return if rel.is_empty() { 0 } else { 4 };
    }
    if args.cmd == "unregister" {
        return match svc.unregister_cli() {
            Ok(()) => {
                out(json!({ "unregistered": true }));
                0
            }
            Err(e) if e.code == "relocated" => {
                out(json!({ "unregistered": false, "error": "relocated", "folders": e.data.as_ref().map(|d| d["folders"].clone()) }));
                4
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
    let extra: Vec<String> = args.client_sid.iter().cloned().collect();
    let server = match pipe::PipeServer::create(&name, &sid, &extra) {
        Ok(s) => s,
        Err(e) => {
            out(json!({ "event": "error", "code": "pipe", "message": e }));
            return 1;
        }
    };

    if args.watch_stdin {
        // Der Starter (launch) hält stdin offen; ist er weg, enden wir sauber.
        let s = svc.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            let mut stdin = std::io::stdin().lock();
            while std::io::Read::read(&mut stdin, &mut buf).is_ok_and(|n| n > 0) {}
            s.log("info", "Starter beendet – gc-drive-sync endet");
            s.stop_runner();
            std::process::exit(0);
        });
    }
    if let Some(pid) = args.parent.filter(|_| !args.watch_stdin) {
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

    actions::serve(svc.clone(), &sid);
    let mut ready = json!({ "event": "ready", "pipe": server.name, "pid": std::process::id(), "version": env!("CARGO_PKG_VERSION"), "protocol": crate::core::protocol::PROTOCOL_VERSION, "elevated": elevated });
    if launch_note.is_some() {
        ready["launch"] = json!("inprocess");
    }
    out(ready);
    svc.log("info", &format!("gc-drive-sync {} bereit{}", env!("CARGO_PKG_VERSION"), if elevated { " (mit Administratorrechten)" } else { "" }));
    if let Some(n) = launch_note {
        svc.log(if elevated { "warn" } else { "info" }, &format!("Start im selben Prozess: {n}"));
    }

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
