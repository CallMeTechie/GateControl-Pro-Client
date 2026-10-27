//! Aktions-Pipe für das Explorer-Kontextmenü.
//!
//! `gc-drive-sync.exe action <share|portal|versions> "<Pfad>"` (vom Explorer
//! mit den Rechten des Benutzers gestartet, ohne UAC-Abfrage) schreibt eine
//! Zeile `{"action":"share","path":"…"}` in die Pipe
//! `\\.\pipe\gatecontrol-drive-actions-<SID>` des laufenden gc-drive-sync;
//! das prüft Aktion und Pfad (im Sync-Root) und meldet sie dem Pro-Client als
//! Ereignis `action` (PROTOCOL.md). Die Pipe ist nur für den Benutzer
//! zugänglich; mehr als einen Dialog im Pro-Client kann ein Aufruf nicht
//! auslösen.
//!
//! Läuft gc-drive-sync nicht (dann läuft auch der Pro-Client nicht), startet
//! der Aufruf den Pro-Client mit `--drive-action <a> --drive-path <p>`
//! (Pfad aus `HKCU\Software\GateControl\DriveSync\AppExe`); der Pro-Client
//! braucht Administratorrechte, deshalb dann die UAC-Abfrage. Läuft der
//! Pro-Client schon, gibt Electron die Argumente an ihn weiter
//! (second-instance).

use super::pipe::PipeServer;
use super::shellmenu;
use super::util::wide_str;
use crate::core::protocol::ACTIONS;
use crate::core::service::{Platform, Service};
use serde_json::json;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::GENERIC_WRITE;
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE, OPEN_EXISTING};
use windows::Win32::System::Pipes::WaitNamedPipeW;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub fn pipe_name(sid: &str) -> String {
    format!(r"\\.\pipe\gatecontrol-drive-actions-{sid}")
}

/// Server im Dienst: bedient die Pipe, bis `quit` gesetzt ist.
pub fn serve<P: Platform>(svc: Arc<Service<P>>, sid: &str) {
    let name = pipe_name(sid);
    let server = match PipeServer::create(&name, sid, &[]) {
        Ok(s) => s,
        Err(e) => {
            svc.log("warn", &format!("Aktions-Pipe: {e}"));
            return;
        }
    };
    std::thread::Builder::new()
        .name("drive-actions".into())
        .spawn(move || loop {
            match server.accept(&svc.quit) {
                Ok(Some(conn)) => {
                    let mut line = String::new();
                    let _ = BufReader::new(conn.take(8 * 1024)).read_line(&mut line);
                    server.disconnect();
                    let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap_or_default();
                    let (Some(a), Some(p)) = (v["action"].as_str(), v["path"].as_str()) else { continue };
                    if let Err(e) = svc.handle_action(a, &PathBuf::from(p)) {
                        svc.log("warn", &format!("Kontextmenü abgelehnt: {a}: {e}"));
                    }
                }
                Ok(None) => break,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(500)),
            }
        })
        .ok();
}

/// `gc-drive-sync.exe action <a> <Pfad>` → Exit-Code.
pub fn client(sid: &str, action: &str, path: &str) -> i32 {
    if !ACTIONS.contains(&action) || path.is_empty() {
        return 2;
    }
    let line = format!("{}\n", json!({ "action": action, "path": path }));
    if send(&pipe_name(sid), &line).is_ok() {
        return 0;
    }
    // gc-drive-sync läuft nicht: Pro-Client starten (UAC), er öffnet den Dialog
    let Some(app) = shellmenu::get(shellmenu::SETTINGS_KEY, "AppExe") else { return 1 };
    let params = format!("--drive-action {action} --drive-path \"{}\"", path.replace('"', ""));
    let (op, f, p) = (wide_str("open"), wide_str(&app), wide_str(&params));
    let h = unsafe { ShellExecuteW(None, PCWSTR(op.as_ptr()), PCWSTR(f.as_ptr()), PCWSTR(p.as_ptr()), PCWSTR::null(), SW_SHOWNORMAL) };
    if h.0 as usize > 32 {
        0
    } else {
        1
    }
}

fn send(name: &str, line: &str) -> Result<(), String> {
    let n = wide_str(name);
    for _ in 0..3 {
        let h = unsafe { CreateFileW(PCWSTR(n.as_ptr()), GENERIC_WRITE.0, FILE_SHARE_NONE, None, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES(0), None) };
        match h {
            Ok(h) => {
                let mut f = unsafe { <std::fs::File as std::os::windows::io::FromRawHandle>::from_raw_handle(h.0 as _) };
                return f.write_all(line.as_bytes()).map_err(|e| e.to_string());
            }
            Err(_) => {
                // belegt (ein anderer Aufruf) oder nicht da
                if !unsafe { WaitNamedPipeW(PCWSTR(n.as_ptr()), 1500) }.as_bool() {
                    return Err("no server".into());
                }
            }
        }
    }
    Err("busy".into())
}
