//! HTTP-Fake des Drive-Plugins für Integrations-Tests: die App-Routen
//! (`/api/v1/client/plugins/gatecontrol-drive/…`) über `FakeDrive`, mit
//! Token-Prüfung, fortsetzbarem Upload und Range-Downloads.
#![allow(dead_code)]

use gc_drive_sync::core::model::CommitRequest;
use gc_drive_sync::core::remote::{ApiError, Remote};
use gc_drive_sync::core::testing::FakeDrive;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

pub const TOKEN: &str = "test-token-123";
const API: &str = "/api/v1/client/plugins/gatecontrol-drive/api/";
const MEDIA: &str = "/api/v1/client/plugins/gatecontrol-drive/media";

pub struct FakeServer {
    pub url: String,
    pub drive: Arc<FakeDrive>,
    pub requests: Arc<Mutex<Vec<String>>>,
    /// Kopfzeilen der letzten Anfrage (klein geschrieben).
    pub last_headers: Arc<Mutex<HashMap<String, String>>>,
    /// Nächster PUT eines Upload-Teils bricht mit 503 ab.
    pub fail_next_part: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn query(url: &str) -> HashMap<String, String> {
    url.split_once('?')
        .map(|(_, q)| q.split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect())
        .unwrap_or_default()
}

fn err_json(e: &ApiError) -> (u16, Value) {
    let mut v = json!({ "ok": false, "code": e.code, "error": e.message });
    if let Some(c) = &e.current {
        v["current"] = serde_json::to_value(c).unwrap();
    }
    (e.status.unwrap_or(500), v)
}

fn ok(v: Value) -> (u16, Value) {
    let mut v = v;
    v["ok"] = json!(true);
    (200, v)
}

struct Partial {
    data: Vec<u8>,
    total: u64,
}

impl FakeServer {
    pub fn start(drive: Arc<FakeDrive>) -> FakeServer {
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
        let port = server.server_addr().to_ip().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let last_headers = Arc::new(Mutex::new(HashMap::new()));
        let fail_next_part = Arc::new(AtomicBool::new(false));
        let (d, st, rq, lh, fp) = (drive.clone(), stop.clone(), requests.clone(), last_headers.clone(), fail_next_part.clone());
        let handle = std::thread::spawn(move || {
            let uploads: Mutex<HashMap<String, Partial>> = Mutex::new(HashMap::new());
            while !st.load(Ordering::SeqCst) {
                let Ok(Some(mut req)) = server.recv_timeout(Duration::from_millis(50)) else { continue };
                let method = req.method().to_string();
                let url = req.url().to_string();
                let headers: HashMap<String, String> =
                    req.headers().iter().map(|h| (h.field.as_str().as_str().to_lowercase(), h.value.as_str().to_string())).collect();
                rq.lock().unwrap().push(format!("{method} {url}"));
                *lh.lock().unwrap() = headers.clone();
                let mut body = Vec::new();
                let _ = req.as_reader().read_to_end(&mut body);
                if headers.get("x-api-token").map(String::as_str) != Some(TOKEN) {
                    let _ = req.respond(tiny_http::Response::from_string(r#"{"ok":false,"code":"unauthorized"}"#).with_status_code(401));
                    continue;
                }
                let path = url.split('?').next().unwrap().to_string();
                let q = query(&url);
                // ── Medien ──
                if let Some(rest) = path.strip_prefix(MEDIA) {
                    let rest = rest.trim_start_matches('/').to_string();
                    if method == "PUT" && rest.is_empty() {
                        if fp.swap(false, Ordering::SeqCst) {
                            let _ = req.respond(tiny_http::Response::from_string("{}").with_status_code(503));
                            continue;
                        }
                        let (status, v) = match q.get("uploadId") {
                            None => {
                                if let Some(dg) = headers.get("repr-digest") {
                                    use base64::Engine as _;
                                    use sha2::Digest;
                                    let want = format!("sha-256=:{}:", base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&body)));
                                    if dg != &want {
                                        let _ = req.respond(tiny_http::Response::from_string(r#"{"ok":false,"code":"digest_mismatch"}"#).with_status_code(400));
                                        continue;
                                    }
                                }
                                let id = d.put_media(body);
                                ok(json!({ "mediaId": id }))
                            }
                            Some(uid) => {
                                let off: u64 = q.get("offset").and_then(|o| o.parse().ok()).unwrap_or(0);
                                let cr = headers.get("content-range").cloned().unwrap_or_default();
                                let total: u64 = cr.rsplit('/').next().and_then(|t| t.parse().ok()).unwrap_or(0);
                                let mut ups = uploads.lock().unwrap();
                                let p = ups.entry(uid.clone()).or_insert(Partial { data: Vec::new(), total });
                                if off != p.data.len() as u64 {
                                    (409, json!({ "ok": false, "code": "offset_mismatch", "offset": p.data.len() }))
                                } else {
                                    p.data.extend_from_slice(&body);
                                    if p.data.len() as u64 >= p.total {
                                        let data = ups.remove(uid).unwrap().data;
                                        let id = d.put_media(data);
                                        ok(json!({ "complete": true, "mediaId": id }))
                                    } else {
                                        ok(json!({ "complete": false, "offset": p.data.len() }))
                                    }
                                }
                            }
                        };
                        let _ = req.respond(tiny_http::Response::from_string(v.to_string()).with_status_code(status));
                        continue;
                    }
                    if method == "GET" && rest.starts_with("uploads/") {
                        let uid = &rest["uploads/".len()..];
                        let ups = uploads.lock().unwrap();
                        let r = match ups.get(uid) {
                            Some(p) => tiny_http::Response::from_string(json!({ "ok": true, "offset": p.data.len(), "total": p.total }).to_string()),
                            None => tiny_http::Response::from_string("{}").with_status_code(404),
                        };
                        let _ = req.respond(r);
                        continue;
                    }
                    if method == "GET" {
                        let Some(data) = d.media_data(&rest) else {
                            let _ = req.respond(tiny_http::Response::from_string("{}").with_status_code(404));
                            continue;
                        };
                        let range = headers.get("range").and_then(|r| r.strip_prefix("bytes=")).and_then(|r| r.split_once('-')).map(|(a, b)| {
                            let a: usize = a.parse().unwrap_or(0);
                            let b: usize = b.parse().map(|x: usize| x + 1).unwrap_or(data.len()).min(data.len());
                            (a, b)
                        });
                        let resp = match range {
                            Some((a, b)) if a < b => tiny_http::Response::from_data(data[a..b].to_vec())
                                .with_status_code(206)
                                .with_header(tiny_http::Header::from_bytes("Content-Range", format!("bytes {}-{}/{}", a, b - 1, data.len())).unwrap()),
                            _ => tiny_http::Response::from_data(data),
                        };
                        let _ = req.respond(resp);
                        continue;
                    }
                }
                // ── JSON-API ──
                let (status, v) = if let Some(p) = path.strip_prefix(API) {
                    let b: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let segs: Vec<&str> = p.split('/').collect();
                    let num = |s: &str| s.parse::<u64>().unwrap_or(0);
                    let r: Result<(u16, Value), ApiError> = (|| {
                        Ok(match (method.as_str(), segs.as_slice()) {
                            ("GET", ["me"]) => {
                                let m = d.me()?;
                                ok(json!({ "me": { "id": m.me.id, "deviceId": m.me.device_id }, "latest": m.latest }))
                            }
                            ("GET", ["areas"]) => ok(json!({ "areas": d.areas()? })),
                            ("GET", ["nodes", id]) => ok(json!({ "node": d.node(num(id))? })),
                            ("GET", ["nodes", id, "children"]) => {
                                let pg = d.children(num(id), q.get("offset").map(|o| num(o)).unwrap_or(0))?;
                                ok(json!({ "items": pg.items, "total": pg.total, "next": pg.next, "role": "manage" }))
                            }
                            ("GET", ["nodes", id, "content"]) => {
                                let c = d.content(num(id))?;
                                ok(json!({ "mediaId": c.media_id, "size": c.size, "name": c.name, "url": "/x" }))
                            }
                            ("GET", ["changes"]) => {
                                let pg = d.changes(q.get("since").map(|o| num(o)).unwrap_or(0))?;
                                ok(json!({ "changes": pg.changes, "next": pg.next, "more": pg.more }))
                            }
                            ("POST", ["nodes"]) => ok(json!({ "node": d.mkdir(b["parentId"].as_u64().unwrap_or(0), b["name"].as_str().unwrap_or(""))? })),
                            ("PATCH", ["nodes", id]) => ok(json!({ "node": d.update_node(num(id), b["name"].as_str(), b["parentId"].as_u64())? })),
                            ("DELETE", ["nodes", id]) => {
                                d.trash(num(id))?;
                                ok(json!({ "id": num(id), "trashed": true }))
                            }
                            ("POST", ["uploads", "check"]) => {
                                let c = d.check(
                                    b["parentId"].as_u64().unwrap_or(0),
                                    b["name"].as_str().unwrap_or(""),
                                    b["sha256"].as_str().unwrap_or(""),
                                    b["size"].as_u64().unwrap_or(0),
                                )?;
                                ok(json!({ "exists": c.exists, "same": c.same, "node": c.node }))
                            }
                            ("POST", ["uploads", "commit"]) => {
                                let req = CommitRequest {
                                    media_id: b["mediaId"].as_str().unwrap_or("").into(),
                                    parent_id: b["parentId"].as_u64().unwrap_or(0),
                                    name: b["name"].as_str().unwrap_or("").into(),
                                    base_rev: b["baseRev"].as_u64(),
                                    mtime: b["mtime"].as_i64(),
                                    on_conflict: b["onConflict"].as_str().map(str::to_string),
                                };
                                ok(json!({ "node": d.commit(&req)?, "created": true }))
                            }
                            _ => (404, json!({ "ok": false, "code": "not_found" })),
                        })
                    })();
                    r.unwrap_or_else(|e| err_json(&e))
                } else {
                    (404, json!({ "ok": false, "code": "not_found" }))
                };
                let _ = req.respond(
                    tiny_http::Response::from_string(v.to_string())
                        .with_status_code(status)
                        .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap()),
                );
            }
        });
        FakeServer { url: format!("http://127.0.0.1:{port}"), drive, requests, last_headers, fail_next_part, stop, handle: Some(handle) }
    }
}
