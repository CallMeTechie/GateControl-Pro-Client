//! Pipe-Protokoll zwischen Pro-Client und gc-drive-sync (siehe PROTOCOL.md):
//! eine JSON-Nachricht pro Zeile (UTF-8, `\n`), höchstens 64 KiB je Zeile.
//!
//!   Anfrage   {"id":1,"cmd":"configure","serverUrl":"https://…","token":"…","deviceName":"PC-Max"}
//!   Antwort   {"id":1,"ok":true,"result":{…}}  |  {"id":1,"ok":false,"error":{"code":"…","message":"…"}}
//!   Ereignis  {"event":"status",…}  |  {"event":"log","level":"info","message":"…","at":"…"}

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const PROTOCOL_VERSION: u32 = 1;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Hello { version: Option<String> },
    Configure(Config),
    Start,
    Stop,
    Pause,
    Resume,
    Status,
    Unregister,
    SyncNow,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: Value,
    pub cmd: Command,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoError {
    pub code: &'static str,
    pub message: String,
}

impl ProtoError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        ProtoError { code, message: message.into() }
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
        "hello" => Command::Hello { version: obj.get("version").and_then(Value::as_str).map(|s| s.chars().take(40).collect()) },
        "configure" => {
            let raw: RawConfigure = serde_json::from_value(v.clone()).map_err(|_| fail("invalid", "bad configure"))?;
            Command::Configure(validate_config(raw).map_err(|e| (id.clone(), e))?)
        }
        "start" => Command::Start,
        "stop" => Command::Stop,
        "pause" => Command::Pause,
        "resume" => Command::Resume,
        "status" => Command::Status,
        "unregister" => Command::Unregister,
        "sync-now" => Command::SyncNow,
        "shutdown" => Command::Shutdown,
        _ => return Err(fail("unknown_command", "unknown cmd")),
    };
    Ok(Request { id, cmd })
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
    json!({ "id": id, "ok": false, "error": { "code": e.code, "message": e.message } }).to_string()
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
            ("unregister", Command::Unregister),
            ("sync-now", Command::SyncNow),
            ("shutdown", Command::Shutdown),
        ] {
            assert_eq!(parse(&format!(r#"{{"id":1,"cmd":"{s}"}}"#)), Ok(c));
        }
        assert_eq!(parse(r#"{"cmd":"hello","version":"1.48.0"}"#), Ok(Command::Hello { version: Some("1.48.0".into()) }));
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
    }
}
