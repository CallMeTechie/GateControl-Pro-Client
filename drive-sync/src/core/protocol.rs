//! Pipe-Protokoll zwischen Pro-Client und gc-drive-sync (siehe PROTOCOL.md):
//! eine JSON-Nachricht pro Zeile (UTF-8, `\n`), höchstens 64 KiB je Zeile.
//!
//!   Anfrage   {"id":1,"cmd":"configure","serverUrl":"https://…","token":"…","deviceName":"PC-Max"}
//!   Antwort   {"id":1,"ok":true,"result":{…}}  |  {"id":1,"ok":false,"error":{"code":"…","message":"…"}}
//!   Ereignis  {"event":"status",…}  |  {"event":"log","level":"info","message":"…","at":"…"}

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const PROTOCOL_VERSION: u32 = 3;
pub const MAX_LINE: usize = 64 * 1024;

/// Kopfzeilen, die der Pro-Client zusätzlich zum Token mitgeben darf
/// (dieselben wie core ApiClient.buildHeaders(), ohne X-API-Token).
pub const ALLOWED_HEADERS: &[&str] = &["X-Client-Version", "X-Client-Platform", "X-Client-Type", "X-Machine-Fingerprint"];

#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub server_url: String,
    pub token: String,
    pub device_name: String,
    pub headers: BTreeMap<String, String>,
}

impl std::fmt::Debug for Config {
    // Das Token erscheint nie in Logs oder Fehlermeldungen.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("server_url", &self.server_url)
            .field("token", &"***")
            .field("device_name", &self.device_name)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Windows-Ordner, die sich in den Drive verlegen lassen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KnownFolder {
    Desktop,
    Documents,
    Pictures,
    Videos,
    Music,
}

impl KnownFolder {
    pub const ALL: [KnownFolder; 5] = [KnownFolder::Desktop, KnownFolder::Documents, KnownFolder::Pictures, KnownFolder::Videos, KnownFolder::Music];

    pub fn key(self) -> &'static str {
        match self {
            KnownFolder::Desktop => "desktop",
            KnownFolder::Documents => "documents",
            KnownFolder::Pictures => "pictures",
            KnownFolder::Videos => "videos",
            KnownFolder::Music => "music",
        }
    }

    pub fn parse(s: &str) -> Option<KnownFolder> {
        KnownFolder::ALL.into_iter().find(|k| k.key() == s)
    }

    /// Name des Ordners unter `%USERPROFILE%` (Windows-Vorgabe).
    pub fn default_leaf(self) -> &'static str {
        match self {
            KnownFolder::Desktop => "Desktop",
            KnownFolder::Documents => "Documents",
            KnownFolder::Pictures => "Pictures",
            KnownFolder::Videos => "Videos",
            KnownFolder::Music => "Music",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Hello {
        version: Option<String>,
        app_exe: Option<String>,
        lang: Option<String>,
    },
    Configure(Config),
    Start,
    Stop,
    Pause,
    Resume,
    Status,
    /// `force`: nicht hochgeladene Änderungen bleiben als normale Dateien im Ordner
    /// (sonst Fehler `unsynced`).
    Unregister {
        force: bool,
    },
    SyncNow,
    Shutdown,
    /// Antwort auf eine Massenlöschung.
    Deletes {
        apply: bool,
    },
    KnownFolders,
    /// Windows-Ordner nach „Meine Dateien\<name>“ verlegen.
    Relocate {
        folder: KnownFolder,
        name: Option<String>,
    },
    /// Verlegten Windows-Ordner zurück an den alten Ort (vollständig lokal).
    Restore {
        folder: KnownFolder,
    },
    /// Belegter Platz auf diesem PC.
    Usage,
    /// Kontextmenü-Aufruf, den der Pro-Client per Argument bekam
    /// (`--drive-action`): wie über die Aktions-Pipe → Ereignis `action`.
    Action {
        action: String,
        path: String,
    },
    /// Drive 1.6 `guard` (vom Pro-Client): `locked` – Drive hat das Gerät gestoppt;
    /// `undo` – Drive hat die Änderungen rückgängig gemacht (Fassungen aus Drive holen).
    Guard {
        locked: bool,
        undo: bool,
    },
    /// Antwort auf die lokale Prüfung: `upload` (hochladen) | `keep` (pausiert lassen).
    Suspect {
        upload: bool,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub id: Value,
    pub cmd: Command,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProtoError {
    pub code: &'static str,
    pub message: String,
    /// Zusätzliche Angaben (z. B. `unsynced`: `{count, paths}`).
    pub data: Option<Value>,
}

impl ProtoError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        ProtoError { code, message: message.into(), data: None }
    }
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawConfigure {
    server_url: Option<String>,
    token: Option<String>,
    device_name: Option<String>,
    #[serde(default)]
    headers: Option<BTreeMap<String, String>>,
}

/// Eine Zeile → Anfrage. Bei Fehlern die `id` (soweit lesbar) mit dem Fehler.
pub fn parse_request(line: &str) -> Result<Request, (Value, ProtoError)> {
    if line.len() > MAX_LINE {
        return Err((Value::Null, ProtoError::new("too_large", "line too long")));
    }
    let v: Value = serde_json::from_str(line).map_err(|_| (Value::Null, ProtoError::new("bad_json", "not JSON")))?;
    let obj = v.as_object().ok_or((Value::Null, ProtoError::new("bad_json", "not an object")))?;
    let id = match obj.get("id") {
        Some(i @ Value::Number(_)) | Some(i @ Value::String(_)) => i.clone(),
        _ => Value::Null,
    };
    let fail = |code, msg: &str| (id.clone(), ProtoError::new(code, msg));
    let cmd = obj.get("cmd").and_then(Value::as_str).ok_or_else(|| fail("bad_request", "cmd missing"))?;
    let cmd = match cmd {
        "hello" => Command::Hello {
            version: obj.get("version").and_then(Value::as_str).map(|s| s.chars().take(40).collect()),
            app_exe: obj.get("appExe").and_then(Value::as_str).filter(|s| valid_app_exe(s)).map(str::to_string),
            lang: obj.get("lang").and_then(Value::as_str).filter(|l| matches!(*l, "de" | "en")).map(str::to_string),
        },
        "configure" => {
            let raw: RawConfigure = serde_json::from_value(v.clone()).map_err(|_| fail("invalid", "bad configure"))?;
            Command::Configure(validate_config(raw).map_err(|e| (id.clone(), e))?)
        }
        "start" => Command::Start,
        "stop" => Command::Stop,
        "pause" => Command::Pause,
        "resume" => Command::Resume,
        "status" => Command::Status,
        "unregister" => Command::Unregister { force: obj.get("force").and_then(Value::as_bool).unwrap_or(false) },
        "deletes" => match obj.get("decision").and_then(Value::as_str) {
            Some("apply") => Command::Deletes { apply: true },
            Some("restore") => Command::Deletes { apply: false },
            _ => return Err(fail("invalid", "decision")),
        },
        "known-folders" => Command::KnownFolders,
        "relocate" | "restore" => {
            let folder = obj.get("folder").and_then(Value::as_str).and_then(KnownFolder::parse).ok_or_else(|| fail("invalid", "folder"))?;
            if cmd == "restore" {
                Command::Restore { folder }
            } else {
                let name = match obj.get("name") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(n)) if super::names::is_valid_name(n.trim()) && n.trim().chars().count() <= 100 => Some(n.trim().to_string()),
                    _ => return Err(fail("invalid", "name")),
                };
                Command::Relocate { folder, name }
            }
        }
        "usage" => Command::Usage,
        "action" => {
            let action = obj.get("action").and_then(Value::as_str).filter(|a| ACTIONS.contains(a)).ok_or_else(|| fail("invalid", "action"))?;
            let path = obj.get("path").and_then(Value::as_str).filter(|p| !p.is_empty() && p.len() <= 4096).ok_or_else(|| fail("invalid", "path"))?;
            Command::Action { action: action.to_string(), path: path.to_string() }
        }
        "guard" => Command::Guard {
            locked: obj.get("locked").and_then(Value::as_bool).ok_or_else(|| fail("invalid", "locked"))?,
            undo: obj.get("undo").and_then(Value::as_bool).unwrap_or(false),
        },
        "suspect" => match obj.get("decision").and_then(Value::as_str) {
            Some("upload") => Command::Suspect { upload: true },
            Some("keep") => Command::Suspect { upload: false },
            _ => return Err(fail("invalid", "decision")),
        },
        "sync-now" => Command::SyncNow,
        "shutdown" => Command::Shutdown,
        _ => return Err(fail("unknown_command", "unknown cmd")),
    };
    Ok(Request { id, cmd })
}

/// Pfad der Pro-Client-Exe (für das Kontextmenü, wenn gc-drive-sync nicht läuft).
fn valid_app_exe(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() <= 1024
        && s.to_ascii_lowercase().ends_with(".exe")
        && !s.chars().any(|c| c.is_control() || c == '"')
        && ((b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')) || s.starts_with("\\\\"))
}

fn validate_config(raw: RawConfigure) -> Result<Config, ProtoError> {
    let server_url = raw.server_url.unwrap_or_default().trim().trim_end_matches('/').to_string();
    let parsed = url::Url::parse(&server_url).map_err(|_| ProtoError::new("invalid", "serverUrl"))?;
    if !(parsed.scheme() == "https" || parsed.scheme() == "http") || parsed.host_str().is_none() || server_url.len() > 2048 {
        return Err(ProtoError::new("invalid", "serverUrl"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(ProtoError::new("invalid", "serverUrl"));
    }
    let token = raw.token.unwrap_or_default();
    if token.is_empty() || token.len() > 4096 || !token.bytes().all(|b| (0x21..0x7f).contains(&b)) {
        return Err(ProtoError::new("invalid", "token"));
    }
    let device_name: String = raw.device_name.unwrap_or_default().trim().chars().filter(|c| !c.is_control()).take(100).collect();
    let mut headers = BTreeMap::new();
    for (k, v) in raw.headers.unwrap_or_default() {
        let Some(name) = ALLOWED_HEADERS.iter().find(|h| h.eq_ignore_ascii_case(&k)) else {
            return Err(ProtoError::new("invalid", "headers"));
        };
        if v.len() > 256 || !v.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err(ProtoError::new("invalid", "headers"));
        }
        headers.insert((*name).to_string(), v);
    }
    Ok(Config { server_url, token, device_name: if device_name.is_empty() { "PC".into() } else { device_name }, headers })
}

pub fn ok_line(id: &Value, result: Value) -> String {
    json!({ "id": id, "ok": true, "result": result }).to_string()
}

pub fn err_line(id: &Value, e: &ProtoError) -> String {
    let mut err = json!({ "code": e.code, "message": e.message });
    if let Some(d) = &e.data {
        err["data"] = d.clone();
    }
    json!({ "id": id, "ok": false, "error": err }).to_string()
}

/// Zustand für `status`-Antworten und -Ereignisse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// `unconfigured` | `stopped` | `starting` | `syncing` | `idle` | `paused` | `offline` | `error`
    pub state: String,
    /// Wartende Aufgaben (lokale Änderungen, die noch hoch müssen, u. a.).
    pub pending: u64,
    /// Laufende Übertragungen (Laden beim Öffnen und Hochladen).
    pub transferring: u64,
    pub errors: Vec<StatusError>,
    /// Letzter vollständiger Abgleich (ISO-8601) oder `null`.
    pub last_sync: Option<String>,
    pub sync_root: Option<String>,
    pub registered: bool,
    /// Zurückgehaltene Massenlöschung (Nachfrage) oder `null`.
    pub mass_delete: Option<MassDelete>,
    /// Läuft mit Administratorrechten (kein Start mit Benutzerrechten möglich).
    pub elevated: bool,
    /// Drive 1.6 `guard`: Drive hat dieses Gerät gestoppt (Zustand `locked`).
    #[serde(default)]
    pub locked: bool,
    /// Lokale Prüfung angeschlagen (Zustand `suspect`) oder `null`.
    #[serde(default)]
    pub suspect: Option<Suspect>,
    /// Nach „Rückgängig machen“ zurückgehaltene Dateien.
    #[serde(default)]
    pub held: u64,
}

/// Viele Dateien ungewöhnlich geändert (guard.rs) – nichts hochgeladen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Suspect {
    pub count: u64,
    /// Bis zu 5 Dateinamen.
    pub sample: Vec<String>,
    /// `entropy` | `extension`
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MassDelete {
    /// Dateien, die gelöscht würden (Ordner mit allem darunter).
    pub files: u64,
    /// Gelöschte Einträge (Dateien und Ordner) im Explorer.
    pub items: u64,
    /// Gelöscht, während das Programm nicht lief.
    pub offline: bool,
    /// Bis zu 5 Pfade.
    pub sample: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub at: String,
}

pub fn status_event(s: &Status) -> String {
    let mut v = serde_json::to_value(s).unwrap_or_else(|_| json!({}));
    if let Some(o) = v.as_object_mut() {
        o.insert("event".into(), json!("status"));
    }
    v.to_string()
}

pub fn log_event(level: &str, message: &str, at: &str) -> String {
    json!({ "event": "log", "level": level, "message": message, "at": at }).to_string()
}

/// Fortschritt eines längeren Befehls (`relocate`, `restore`, `unregister`).
pub fn progress_event(op: &str, folder: Option<&str>, phase: &str, done: u64, total: u64) -> String {
    json!({ "event": "progress", "op": op, "folder": folder, "phase": phase, "done": done, "total": total }).to_string()
}

/// Explorer-Kontextmenü → Pro-Client (`share` | `portal` | `versions`).
pub fn action_event(action: &str, path: &str, node: Option<u64>, area: Option<&str>, is_dir: bool) -> String {
    json!({ "event": "action", "action": action, "path": path, "node": node, "area": area, "isDir": is_dir }).to_string()
}

pub const ACTIONS: &[&str] = &["share", "portal", "versions"];

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Command, ProtoError> {
        parse_request(s).map(|r| r.cmd).map_err(|e| e.1)
    }

    #[test]
    fn simple_commands() {
        for (s, c) in [
            ("start", Command::Start),
            ("stop", Command::Stop),
            ("pause", Command::Pause),
            ("resume", Command::Resume),
            ("status", Command::Status),
            ("unregister", Command::Unregister { force: false }),
            ("known-folders", Command::KnownFolders),
            ("usage", Command::Usage),
            ("sync-now", Command::SyncNow),
            ("shutdown", Command::Shutdown),
        ] {
            assert_eq!(parse(&format!(r#"{{"id":1,"cmd":"{s}"}}"#)), Ok(c));
        }
        assert_eq!(parse(r#"{"cmd":"hello","version":"1.48.0"}"#), Ok(Command::Hello { version: Some("1.48.0".into()), app_exe: None, lang: None }));
        assert_eq!(
            parse(r#"{"cmd":"hello","appExe":"C:\\Program Files\\GateControl Pro\\GateControl Pro Client.exe"}"#),
            Ok(Command::Hello { version: None, app_exe: Some(r"C:\Program Files\GateControl Pro\GateControl Pro Client.exe".into()), lang: None })
        );
        assert_eq!(parse(r#"{"cmd":"hello","appExe":"calc"}"#), Ok(Command::Hello { version: None, app_exe: None, lang: None }));
        assert_eq!(parse(r#"{"cmd":"hello","lang":"en"}"#), Ok(Command::Hello { version: None, app_exe: None, lang: Some("en".into()) }));
        assert_eq!(parse(r#"{"cmd":"unregister","force":true}"#), Ok(Command::Unregister { force: true }));
        assert_eq!(parse(r#"{"cmd":"deletes","decision":"apply"}"#), Ok(Command::Deletes { apply: true }));
        assert_eq!(parse(r#"{"cmd":"deletes","decision":"restore"}"#), Ok(Command::Deletes { apply: false }));
        assert_eq!(parse(r#"{"cmd":"deletes","decision":"maybe"}"#).unwrap_err().code, "invalid");
        assert_eq!(parse(r#"{"cmd":"relocate","folder":"documents"}"#), Ok(Command::Relocate { folder: KnownFolder::Documents, name: None }));
        assert_eq!(
            parse(r#"{"cmd":"relocate","folder":"pictures","name":" Bilder "}"#),
            Ok(Command::Relocate { folder: KnownFolder::Pictures, name: Some("Bilder".into()) })
        );
        assert_eq!(parse(r#"{"cmd":"relocate","folder":"pictures","name":"a/b"}"#).unwrap_err().code, "invalid");
        assert_eq!(parse(r#"{"cmd":"relocate","folder":"windows"}"#).unwrap_err().code, "invalid");
        assert_eq!(parse(r#"{"cmd":"restore","folder":"music"}"#), Ok(Command::Restore { folder: KnownFolder::Music }));
        assert_eq!(parse(r#"{"cmd":"action","action":"share","path":"C:\\x"}"#), Ok(Command::Action { action: "share".into(), path: "C:\\x".into() }));
        assert_eq!(parse(r#"{"cmd":"action","action":"delete","path":"C:\\x"}"#).unwrap_err().code, "invalid");
        assert_eq!(parse(r#"{"cmd":"guard","locked":true}"#), Ok(Command::Guard { locked: true, undo: false }));
        assert_eq!(parse(r#"{"cmd":"guard","locked":false,"undo":true}"#), Ok(Command::Guard { locked: false, undo: true }));
        assert_eq!(parse(r#"{"cmd":"guard"}"#).unwrap_err().code, "invalid");
        assert_eq!(parse(r#"{"cmd":"suspect","decision":"upload"}"#), Ok(Command::Suspect { upload: true }));
        assert_eq!(parse(r#"{"cmd":"suspect","decision":"keep"}"#), Ok(Command::Suspect { upload: false }));
        assert_eq!(parse(r#"{"cmd":"suspect","decision":"x"}"#).unwrap_err().code, "invalid");
    }

    #[test]
    fn ids_are_echoed() {
        assert_eq!(parse_request(r#"{"id":"a7","cmd":"status"}"#).unwrap().id, json!("a7"));
        assert_eq!(parse_request(r#"{"id":{"x":1},"cmd":"status"}"#).unwrap().id, Value::Null);
        let (id, e) = parse_request(r#"{"id":9,"cmd":"rm -rf"}"#).unwrap_err();
        assert_eq!((id, e.code), (json!(9), "unknown_command"));
    }

    #[test]
    fn bad_lines() {
        assert_eq!(parse("not json").unwrap_err().code, "bad_json");
        assert_eq!(parse("[1]").unwrap_err().code, "bad_json");
        assert_eq!(parse(r#"{"id":1}"#).unwrap_err().code, "bad_request");
        assert_eq!(parse(&"x".repeat(MAX_LINE + 1)).unwrap_err().code, "too_large");
    }

    #[test]
    fn configure_validates() {
        let ok = parse(
            r#"{"id":2,"cmd":"configure","serverUrl":"https://gc.example.de/","token":"gc_abc123","deviceName":" PC-Max ",
                "headers":{"x-client-version":"1.48.0","X-Machine-Fingerprint":"ab12"}}"#,
        )
        .unwrap();
        let Command::Configure(c) = ok else { panic!() };
        assert_eq!(c.server_url, "https://gc.example.de");
        assert_eq!(c.device_name, "PC-Max");
        assert_eq!(c.headers.get("X-Client-Version").map(String::as_str), Some("1.48.0"));
        assert!(!format!("{c:?}").contains("gc_abc123"), "token must not show in Debug");

        for bad in [
            r#"{"cmd":"configure","serverUrl":"ftp://x","token":"t"}"#,
            r#"{"cmd":"configure","serverUrl":"https://u:p@x","token":"t"}"#,
            r#"{"cmd":"configure","serverUrl":"https://x?a=1","token":"t"}"#,
            r#"{"cmd":"configure","serverUrl":"https://x","token":""}"#,
            r#"{"cmd":"configure","serverUrl":"https://x","token":"a b"}"#,
            r#"{"cmd":"configure","serverUrl":"https://x","token":"t","headers":{"X-API-Token":"t"}}"#,
            r#"{"cmd":"configure","serverUrl":"https://x","token":"t","headers":{"X-Client-Type":"a\nb"}}"#,
            r#"{"cmd":"configure","token":"t"}"#,
        ] {
            assert_eq!(parse(bad).unwrap_err().code, "invalid", "{bad}");
        }
        let Command::Configure(c) = parse(r#"{"cmd":"configure","serverUrl":"http://10.0.0.1:3000","token":"t"}"#).unwrap() else { panic!() };
        assert_eq!(c.device_name, "PC");
    }

    #[test]
    fn output_lines() {
        assert_eq!(ok_line(&json!(1), json!({"a":1})), r#"{"id":1,"ok":true,"result":{"a":1}}"#);
        let e: Value = serde_json::from_str(&err_line(&Value::Null, &ProtoError::new("x", "y"))).unwrap();
        assert_eq!(e, json!({"id":null,"ok":false,"error":{"code":"x","message":"y"}}));
        let s = Status { state: "idle".into(), ..Default::default() };
        let v: Value = serde_json::from_str(&status_event(&s)).unwrap();
        assert_eq!(v["event"], "status");
        assert_eq!(v["state"], "idle");
        assert_eq!(v["lastSync"], Value::Null);
        let l: Value = serde_json::from_str(&log_event("warn", "x", "t")).unwrap();
        assert_eq!(l["event"], "log");
        assert_eq!(v["massDelete"], Value::Null);
        let e: Value = serde_json::from_str(&err_line(&json!(3), &ProtoError::new("unsynced", "x").with_data(json!({"count": 2})))).unwrap();
        assert_eq!(e["error"]["data"]["count"], 2);
        let a: Value = serde_json::from_str(&action_event("share", "C:\\x", Some(7), Some("mine:1"), false)).unwrap();
        assert_eq!((a["event"].as_str(), a["node"].as_u64()), (Some("action"), Some(7)));
        let p: Value = serde_json::from_str(&progress_event("restore", Some("music"), "load", 1, 3)).unwrap();
        assert_eq!(p["total"], 3);
    }
}
