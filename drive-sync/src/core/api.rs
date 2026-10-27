//! HTTP-Client für die App-Routen des Drive-Plugins
//! (`/api/v1/client/plugins/gatecontrol-drive/…`, README „API“), mit dem
//! Geräte-Token (`X-API-Token`) wie der Pro-Client.
//!
//! TLS: rustls mit `rustls-platform-verifier` – unter Windows prüft das die
//! Zertifikatskette über den Windows-Zertifikatspeicher wie jedes andere
//! Programm (auch firmeneigene Stammzertifikate). Proxy: Umgebung bzw.
//! Windows-Systemeinstellung (reqwest `system-proxy`).
//!
//! Hochladen wie core `gatedrop-api.js`: bis 8 MiB ein PUT mit `Repr-Digest`,
//! darüber fortsetzbar in Teilen zu 8 MiB (`?uploadId=&offset=` +
//! `Content-Range`, 409 `offset_mismatch`/`busy` → an `offset` weiter).
//! Herunterladen mit `Range` (206), ein 200 ohne Range wird bis zum Start übersprungen.

use super::model::*;
use super::remote::{ApiError, ReadAt, Remote};
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::RwLock;
use std::time::Duration;

pub const PLUGIN_ID: &str = "gatecontrol-drive";
pub const API_BASE: &str = "/api/v1/client/plugins/gatecontrol-drive/api/";
pub const MEDIA_PATH: &str = "/api/v1/client/plugins/gatecontrol-drive/media";
/// Größere Dateien gehen fortsetzbar hoch (wie core utils/drive.js RESUMABLE_FROM).
pub const RESUMABLE_FROM: u64 = 8 * 1024 * 1024;
/// Teilgröße fortsetzbarer Uploads (Vielfaches von 64 KiB).
pub const PART_SIZE: u64 = 8 * 1024 * 1024;
const RESUME_ATTEMPTS: u32 = 5;
const CHILDREN_LIMIT: u32 = 1000;
const CHANGES_LIMIT: u32 = 1000;

/// Medien-IDs wie core utils/drive.js (`/^[A-Za-z0-9_-]{6,128}$/`).
pub fn is_media_id(s: &str) -> bool {
    (6..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub struct ApiClient {
    base: String,
    token: RwLock<String>,
    headers: BTreeMap<String, String>,
    json: reqwest::blocking::Client,
    transfer: reqwest::blocking::Client,
    sleep: fn(Duration),
}

/// rustls braucht genau einen Krypto-Anbieter; einmal pro Prozess setzen.
pub fn init_tls() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

impl ApiClient {
    pub fn new(server_url: &str, token: &str, headers: BTreeMap<String, String>) -> Result<ApiClient, ApiError> {
        init_tls();
        let ua = format!("gc-drive-sync/{}", env!("CARGO_PKG_VERSION"));
        let build = |timeout: Duration| {
            reqwest::blocking::Client::builder()
                .user_agent(ua.clone())
                .connect_timeout(Duration::from_secs(15))
                .timeout(timeout)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| ApiError::new(None, "tls", e.to_string()))
        };
        Ok(ApiClient {
            base: server_url.trim_end_matches('/').to_string(),
            token: RwLock::new(token.to_string()),
            headers,
            json: build(Duration::from_secs(60))?,
            transfer: build(Duration::from_secs(15 * 60))?,
            sleep: std::thread::sleep,
        })
    }

    /// Neues Token (configure mit gleichem Server).
    pub fn set_token(&self, token: &str) {
        if let Ok(mut t) = self.token.write() {
            *t = token.to_string();
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    #[cfg(test)]
    fn no_sleep(mut self) -> Self {
        self.sleep = |_| {};
        self
    }

    fn req(&self, client: &reqwest::blocking::Client, method: reqwest::Method, path: &str) -> reqwest::blocking::RequestBuilder {
        let token = self.token.read().map(|t| t.clone()).unwrap_or_default();
        let mut r = client.request(method, format!("{}{}", self.base, path)).header("X-API-Token", token);
        for (k, v) in &self.headers {
            r = r.header(k.as_str(), v.as_str());
        }
        r
    }

    fn send(rb: reqwest::blocking::RequestBuilder) -> Result<reqwest::blocking::Response, ApiError> {
        rb.send().map_err(map_reqwest)
    }

    /// JSON-Aufruf unterhalb von …/gatecontrol-drive/api/.
    fn api<T: DeserializeOwned>(&self, method: reqwest::Method, p: &str, query: &[(&str, String)], body: Option<Value>) -> Result<T, ApiError> {
        let mut rb = self.req(&self.json, method, &format!("{API_BASE}{p}")).header("Accept", "application/json");
        if !query.is_empty() {
            rb = rb.query(query);
        }
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let res = Self::send(rb)?;
        let status = res.status().as_u16();
        let bytes = res.bytes().map_err(map_reqwest)?;
        if !(200..300).contains(&status) {
            return Err(error_from_body(status, &bytes));
        }
        let v: Value = serde_json::from_slice(&bytes).map_err(|_| ApiError::new(Some(status), "bad_response", "not JSON"))?;
        if v.get("ok") == Some(&Value::Bool(false)) {
            return Err(error_from_body(status, &bytes));
        }
        serde_json::from_value(v).map_err(|e| ApiError::new(Some(status), "bad_response", e.to_string()))
    }

    fn node_answer(&self, method: reqwest::Method, p: &str, body: Option<Value>) -> Result<Node, ApiError> {
        #[derive(serde::Deserialize)]
        struct A {
            node: Node,
        }
        Ok(self.api::<A>(method, p, &[], body)?.node)
    }

    fn put_part(&self, data: Vec<u8>, total: u64, start: u64, upload_id: Option<&str>, digest: Option<&[u8; 32]>) -> Result<(u16, Value), ApiError> {
        let len = data.len() as u64;
        let mut rb = self
            .req(&self.transfer, reqwest::Method::PUT, MEDIA_PATH)
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", len.to_string());
        if let Some(id) = upload_id {
            rb = rb
                .query(&[("uploadId", id.to_string()), ("offset", start.to_string())])
                .header("Content-Range", format!("bytes {}-{}/{}", start, start + len - 1, total));
        }
        if let Some(d) = digest {
            rb = rb.header("Repr-Digest", format!("sha-256=:{}:", base64::engine::general_purpose::STANDARD.encode(d)));
        }
        let res = Self::send(rb.body(data))?;
        let status = res.status().as_u16();
        let bytes = res.bytes().map_err(map_reqwest)?;
        if (200..300).contains(&status) || (upload_id.is_some() && status == 409) {
            let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            return Ok((status, v));
        }
        Err(error_from_body(status, &bytes))
    }

    /// Bereits angekommene Bytes eines fortsetzbaren Uploads (`GET media/uploads/<id>`).
    fn upload_offset(&self, upload_id: &str) -> Option<u64> {
        let res = Self::send(self.req(&self.json, reqwest::Method::GET, &format!("{MEDIA_PATH}/uploads/{upload_id}"))).ok()?;
        if res.status().as_u16() == 404 {
            return Some(0);
        }
        let v: Value = res.json().ok()?;
        v.get("offset").and_then(Value::as_u64)
    }
}

fn map_reqwest(e: reqwest::Error) -> ApiError {
    if e.is_timeout() {
        ApiError::new(None, "timeout", e.to_string())
    } else {
        ApiError::network(e.to_string())
    }
}

/// `{ ok: false, code, error, current? }` → ApiError.
pub fn error_from_body(status: u16, body: &[u8]) -> ApiError {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let code = v.get("code").and_then(Value::as_str).filter(|c| !c.is_empty() && c.len() <= 64).map(str::to_string).unwrap_or_else(|| format!("http_{status}"));
    let message = v.get("error").and_then(Value::as_str).unwrap_or("").chars().take(300).collect::<String>();
    let current = v.get("current").cloned().and_then(|c| serde_json::from_value::<Node>(c).ok()).map(Box::new);
    ApiError { status: Some(status), code, message, current }
}

fn random_upload_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 18];
    rand::rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b) // 24 Zeichen [A-Za-z0-9_-]
}

fn read_part(src: &mut dyn ReadAt, start: u64, len: u64) -> Result<Vec<u8>, ApiError> {
    let mut buf = vec![0u8; len as usize];
    let n = src.read_at(start, &mut buf).map_err(|e| ApiError::new(None, "read", e.to_string()))?;
    if n as u64 != len {
        return Err(ApiError::new(None, "changed", "file shrank while uploading"));
    }
    Ok(buf)
}

impl Remote for ApiClient {
    fn me(&self) -> Result<MeAnswer, ApiError> {
        self.api(reqwest::Method::GET, "me", &[], None)
    }

    fn areas(&self) -> Result<Vec<Area>, ApiError> {
        #[derive(serde::Deserialize)]
        struct A {
            #[serde(default)]
            areas: Vec<Value>,
        }
        let a: A = self.api(reqwest::Method::GET, "areas", &[], None)?;
        // Unlesbare Einträge überspringen statt alles abzulehnen.
        Ok(a.areas.into_iter().filter_map(|v| serde_json::from_value::<Area>(v).ok()).collect())
    }

    fn node(&self, id: u64) -> Result<Node, ApiError> {
        self.node_answer(reqwest::Method::GET, &format!("nodes/{id}"), None)
    }

    fn children(&self, id: u64, offset: u64) -> Result<ChildrenPage, ApiError> {
        self.api(
            reqwest::Method::GET,
            &format!("nodes/{id}/children"),
            &[("sort", "name".into()), ("offset", offset.to_string()), ("limit", CHILDREN_LIMIT.to_string())],
            None,
        )
    }

    fn changes(&self, since: u64) -> Result<ChangesPage, ApiError> {
        self.api(reqwest::Method::GET, "changes", &[("since", since.to_string()), ("limit", CHANGES_LIMIT.to_string())], None)
    }

    fn mkdir(&self, parent: u64, name: &str) -> Result<Node, ApiError> {
        self.node_answer(reqwest::Method::POST, "nodes", Some(json!({ "parentId": parent, "name": name })))
    }

    fn update_node(&self, id: u64, name: Option<&str>, parent: Option<u64>) -> Result<Node, ApiError> {
        let mut b = serde_json::Map::new();
        if let Some(n) = name {
            b.insert("name".into(), json!(n));
        }
        if let Some(p) = parent {
            b.insert("parentId".into(), json!(p));
        }
        self.node_answer(reqwest::Method::PATCH, &format!("nodes/{id}"), Some(Value::Object(b)))
    }

    fn trash(&self, id: u64) -> Result<(), ApiError> {
        self.api::<Value>(reqwest::Method::DELETE, &format!("nodes/{id}"), &[], None).map(|_| ())
    }

    fn check(&self, parent: u64, name: &str, sha256_hex: &str, size: u64) -> Result<UploadCheck, ApiError> {
        self.api(reqwest::Method::POST, "uploads/check", &[], Some(json!({ "parentId": parent, "name": name, "sha256": sha256_hex, "size": size })))
    }

    fn upload(&self, src: &mut dyn ReadAt, sha256: &[u8; 32], progress: &mut dyn FnMut(u64, u64)) -> Result<String, ApiError> {
        let size = src.len();
        if size == 0 {
            return Err(ApiError::new(None, "length_required", "empty file"));
        }
        let media_of = |v: &Value| v.get("mediaId").and_then(Value::as_str).filter(|m| is_media_id(m)).map(str::to_string);
        if size <= RESUMABLE_FROM {
            let data = read_part(src, 0, size)?;
            if Sha256::digest(&data).as_slice() != sha256 {
                return Err(ApiError::new(None, "changed", "file changed while uploading"));
            }
            let (_, v) = self.put_part(data, size, 0, None, Some(sha256))?;
            progress(size, size);
            return media_of(&v).ok_or_else(|| ApiError::new(Some(200), "bad_response", "no mediaId"));
        }
        let upload_id = random_upload_id();
        let mut hasher = Sha256::new();
        let mut hashed = 0u64; // Bytes, die schon in die Prüfsumme gingen (nur vorwärts)
        let mut offset = 0u64;
        let mut failures = 0u32;
        while offset < size {
            let end = (offset + PART_SIZE).min(size);
            let data = read_part(src, offset, end - offset)?;
            if offset == hashed {
                hasher.update(&data);
                hashed = end;
            }
            let r = self.put_part(data, size, offset, Some(&upload_id), None);
            let (status, v) = match r {
                Ok(x) => x,
                Err(e) if e.transient() && failures + 1 < RESUME_ATTEMPTS => {
                    failures += 1;
                    (self.sleep)(Duration::from_millis(1000 * 2u64.pow(failures - 1)).min(Duration::from_secs(30)));
                    if let Some(at) = self.upload_offset(&upload_id) {
                        if at <= size && at <= hashed {
                            offset = at;
                        }
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };
            if status == 409 {
                let at = v.get("offset").and_then(Value::as_u64);
                let code = v.get("code").and_then(Value::as_str).unwrap_or("busy");
                failures += 1;
                if failures >= RESUME_ATTEMPTS {
                    return Err(ApiError::new(Some(409), code, "upload busy"));
                }
                match at {
                    Some(at) if code != "busy" && at <= hashed => offset = at,
                    _ => (self.sleep)(Duration::from_millis(1000 * 2u64.pow(failures - 1)).min(Duration::from_secs(30))),
                }
                continue;
            }
            failures = 0;
            progress(end, size);
            if v.get("complete") == Some(&Value::Bool(true)) || (media_of(&v).is_some() && v.get("complete") != Some(&Value::Bool(false))) {
                if end < size {
                    return Err(ApiError::new(Some(status), "bad_response", "server completed early"));
                }
                if hasher.clone().finalize().as_slice() != sha256 {
                    return Err(ApiError::new(None, "changed", "file changed while uploading"));
                }
                return media_of(&v).ok_or_else(|| ApiError::new(Some(status), "bad_response", "no mediaId"));
            }
            let next = v.get("offset").and_then(Value::as_u64);
            offset = match next {
                Some(n) if n > offset && n <= hashed => n,
                _ => end,
            };
        }
        Err(ApiError::new(None, "bad_response", "upload not completed"))
    }

    fn commit(&self, req: &CommitRequest) -> Result<Node, ApiError> {
        let body = serde_json::to_value(req).map_err(|e| ApiError::new(None, "invalid", e.to_string()))?;
        #[derive(serde::Deserialize)]
        struct A {
            node: Node,
        }
        Ok(self.api::<A>(reqwest::Method::POST, "uploads/commit", &[], Some(body))?.node)
    }

    fn content(&self, id: u64) -> Result<Content, ApiError> {
        self.api(reqwest::Method::GET, &format!("nodes/{id}/content"), &[], None)
    }

    fn download(&self, media_id: &str, start: u64, end: u64, sink: &mut dyn FnMut(&[u8]) -> Result<(), String>) -> Result<u64, ApiError> {
        if !is_media_id(media_id) {
            return Err(ApiError::new(None, "invalid", "media id"));
        }
        if end <= start {
            return Ok(0);
        }
        let rb = self
            .req(&self.transfer, reqwest::Method::GET, &format!("{MEDIA_PATH}/{media_id}"))
            .header("Accept", "*/*")
            .header("Range", format!("bytes={}-{}", start, end - 1));
        let mut res = Self::send(rb)?;
        let status = res.status().as_u16();
        let mut skip = match status {
            206 => {
                let cr = res.headers().get("content-range").and_then(|h| h.to_str().ok()).unwrap_or("");
                let from = cr.strip_prefix("bytes ").and_then(|r| r.split('-').next()).and_then(|s| s.parse::<u64>().ok());
                if from != Some(start) {
                    return Err(ApiError::new(Some(206), "bad_response", "content-range"));
                }
                0
            }
            200 => start,
            _ => {
                let mut body = Vec::new();
                let _ = res.by_ref().take(64 * 1024).read_to_end(&mut body);
                return Err(error_from_body(status, &body));
            }
        };
        let want = end - start;
        let mut got = 0u64;
        let mut buf = vec![0u8; 256 * 1024];
        while got < want {
            let n = res.read(&mut buf).map_err(|e| ApiError::network(e.to_string()))?;
            if n == 0 {
                break;
            }
            let mut chunk = &buf[..n];
            if skip > 0 {
                let s = (skip as usize).min(chunk.len());
                chunk = &chunk[s..];
                skip -= s as u64;
            }
            let take = (want - got).min(chunk.len() as u64) as usize;
            if take > 0 {
                sink(&chunk[..take]).map_err(|m| ApiError::new(None, "cancelled", m))?;
                got += take as u64;
            }
        }
        if got < want {
            return Err(ApiError::network("download cut off"));
        }
        Ok(got)
    }
}

#[cfg(test)]
impl ApiClient {
    pub fn for_tests(server_url: &str, token: &str) -> ApiClient {
        ApiClient::new(server_url, token, BTreeMap::new()).unwrap().no_sleep()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_ids() {
        assert!(is_media_id("abcDEF_-12"));
        assert!(!is_media_id("abc"));
        assert!(!is_media_id("../../etc/passwd"));
        assert!(!is_media_id(&"a".repeat(129)));
    }

    #[test]
    fn errors_from_bodies() {
        let e = error_from_body(409, br#"{"ok":false,"code":"conflict","error":"Name exists","current":{"id":3,"name":"a","rev":2}}"#);
        assert_eq!(e.code, "conflict");
        assert_eq!(e.current.unwrap().rev, 2);
        let e = error_from_body(502, b"<html>");
        assert_eq!(e.code, "http_502");
        assert!(e.transient());
    }

    #[test]
    fn upload_ids() {
        let id = random_upload_id();
        assert_eq!(id.len(), 24);
        assert!(id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
    }
}
