//! Test-Doubles: ein Drive-Server im Speicher (`FakeDrive`, verhält sich wie
//! das Plugin bei Namen, `rev`, Konflikten, Papierkorb und Änderungsprotokoll)
//! und ein Dateisystem im Speicher mit Platzhaltern (`FakeFs`). `FakeDrive`
//! steckt auch hinter dem HTTP-Fake-Server der Integrations-Tests.

use super::identity::Identity;
use super::localfs::*;
use super::model::*;
use super::names;
use super::remote::{ApiError, ReadAt, Remote};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub fn sha_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ───────────────────────── FakeDrive ─────────────────────────

#[derive(Default)]
struct DriveInner {
    areas: Vec<Area>,
    nodes: BTreeMap<u64, Node>,
    media: HashMap<String, Vec<u8>>,
    log: Vec<(u64, String, String, u64)>, // seq, op, area, node
    next_id: u64,
    next_media: u64,
    clock: i64,
    calls: Vec<String>,
    fail: HashMap<String, ApiError>,
    /// Testaufbau: Rechte ignorieren („jemand anderes“ ändert).
    bypass: bool,
}

/// Ein Drive im Speicher.
#[derive(Default)]
pub struct FakeDrive {
    inner: Mutex<DriveInner>,
}

fn err(status: u16, code: &str) -> ApiError {
    ApiError::new(Some(status), code, code)
}

impl DriveInner {
    fn now(&mut self) -> String {
        self.clock += 1000;
        chrono::DateTime::from_timestamp_millis(1_790_000_000_000 + self.clock).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }
    fn record(&mut self, op: &str, id: u64) {
        let area = self.nodes.get(&id).map(|n| n.area_id.clone()).unwrap_or_default();
        let seq = self.log.len() as u64 + 1;
        self.log.push((seq, op.into(), area, id));
    }
    fn taken(&self, parent: u64, name: &str) -> Option<&Node> {
        self.nodes.values().find(|n| n.parent_id == Some(parent) && !n.deleted && names::same_name(&n.name, name))
    }
    fn area_of(&self, id: &str) -> Option<&Area> {
        self.areas.iter().find(|a| a.id == id)
    }
    fn live(&self, id: u64) -> Result<&Node, ApiError> {
        self.nodes.get(&id).filter(|n| !n.deleted).ok_or_else(|| err(404, "not_found"))
    }
    fn writable(&self, id: u64) -> Result<(), ApiError> {
        let n = self.live(id)?;
        if self.bypass {
            return Ok(());
        }
        match self.area_of(&n.area_id) {
            Some(a) if a.writable() => Ok(()),
            _ => Err(err(403, "forbidden")),
        }
    }
    fn new_media(&mut self, data: Vec<u8>) -> String {
        self.next_media += 1;
        let id = format!("media{:04}", self.next_media);
        self.media.insert(id.clone(), data);
        id
    }
    fn free_name(&self, parent: u64, name: &str) -> String {
        let (stem, ext) = names::split_ext(name);
        (2..).map(|i| format!("{stem} ({i}){ext}")).find(|n| self.taken(parent, n).is_none()).unwrap()
    }
    fn hit(&mut self, call: &str) -> Result<(), ApiError> {
        self.calls.push(call.to_string());
        if let Some(e) = self.fail.remove(call) {
            return Err(e);
        }
        Ok(())
    }
}

impl FakeDrive {
    pub fn new() -> FakeDrive {
        FakeDrive::default()
    }

    /// Bereich mit Wurzelordner → ID der Wurzel.
    pub fn add_area(&self, id: &str, label: &str, role: Role) -> u64 {
        let mut d = self.inner.lock().unwrap();
        d.next_id += 1;
        let root = d.next_id;
        let now = d.now();
        d.nodes.insert(
            root,
            Node { id: root, area_id: id.into(), parent_id: None, name: label.into(), is_dir: true, rev: 1, updated_at: Some(now), ..Default::default() },
        );
        d.areas.push(Area { id: id.into(), kind: "mine".into(), label: label.into(), role, via: Some("owner".into()), root_id: root, archived: false });
        root
    }

    pub fn set_area(&self, id: &str, f: impl FnOnce(&mut Area)) {
        let mut d = self.inner.lock().unwrap();
        if let Some(a) = d.areas.iter_mut().find(|a| a.id == id) {
            f(a);
        }
    }

    pub fn remove_area(&self, id: &str) {
        self.inner.lock().unwrap().areas.retain(|a| a.id != id);
    }

    fn as_admin<T>(&self, f: impl FnOnce() -> T) -> T {
        self.inner.lock().unwrap().bypass = true;
        let r = f();
        self.inner.lock().unwrap().bypass = false;
        r
    }

    pub fn add_dir(&self, parent: u64, name: &str) -> Node {
        self.as_admin(|| self.mkdir(parent, name).unwrap())
    }

    pub fn add_file(&self, parent: u64, name: &str, data: &[u8]) -> Node {
        let mid = self.inner.lock().unwrap().new_media(data.to_vec());
        self.as_admin(|| {
            self.commit(&CommitRequest { media_id: mid, parent_id: parent, name: name.into(), base_rev: None, mtime: None, on_conflict: None }).unwrap()
        })
    }

    /// Jemand anderes speichert eine neue Fassung.
    pub fn modify(&self, id: u64, data: &[u8]) -> Node {
        let n = self.get(id).unwrap();
        let mid = self.inner.lock().unwrap().new_media(data.to_vec());
        self.as_admin(|| {
            self.commit(&CommitRequest { media_id: mid, parent_id: n.parent_id.unwrap(), name: n.name, base_rev: Some(n.rev), mtime: None, on_conflict: None })
                .unwrap()
        })
    }

    pub fn rename(&self, id: u64, name: &str) -> Node {
        self.as_admin(|| self.update_node(id, Some(name), None).unwrap())
    }

    pub fn delete(&self, id: u64) {
        self.as_admin(|| self.trash(id).unwrap())
    }

    /// Knoten wandert in einen anderen Bereich (alter Bereich: `delete` mit `node: null`).
    pub fn move_to_area(&self, id: u64, new_parent: u64) {
        let mut d = self.inner.lock().unwrap();
        let area = d.nodes[&new_parent].area_id.clone();
        let old_area = d.nodes[&id].area_id.clone();
        let seq = d.log.len() as u64 + 1;
        d.log.push((seq, "delete".into(), old_area, id));
        let n = d.nodes.get_mut(&id).unwrap();
        n.parent_id = Some(new_parent);
        n.area_id = area;
        n.rev += 1;
        d.record("create", id);
    }

    pub fn file_data(&self, id: u64) -> Option<Vec<u8>> {
        let d = self.inner.lock().unwrap();
        let n = d.nodes.get(&id)?;
        d.media.get(n.media_id.as_ref()?).cloned()
    }

    pub fn find(&self, parent: u64, name: &str) -> Option<Node> {
        self.inner.lock().unwrap().taken(parent, name).cloned()
    }

    pub fn get(&self, id: u64) -> Option<Node> {
        self.inner.lock().unwrap().nodes.get(&id).cloned()
    }

    pub fn live_children(&self, parent: u64) -> Vec<Node> {
        let d = self.inner.lock().unwrap();
        d.nodes.values().filter(|n| n.parent_id == Some(parent) && !n.deleted).cloned().collect()
    }

    pub fn calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().calls.clone()
    }

    pub fn clear_calls(&self) {
        self.inner.lock().unwrap().calls.clear();
    }

    /// Der nächste Aufruf `call` (z. B. "commit", "changes") schlägt mit `e` fehl.
    pub fn fail_next(&self, call: &str, e: ApiError) {
        self.inner.lock().unwrap().fail.insert(call.into(), e);
    }

    /// Medien-Upload über HTTP (Fake-Server) → mediaId.
    pub fn put_media(&self, data: Vec<u8>) -> String {
        self.inner.lock().unwrap().new_media(data)
    }

    pub fn media_data(&self, media_id: &str) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().media.get(media_id).cloned()
    }

    pub fn latest(&self) -> u64 {
        self.inner.lock().unwrap().log.len() as u64
    }
}

impl Remote for FakeDrive {
    fn me(&self) -> Result<MeAnswer, ApiError> {
        let mut d = self.inner.lock().unwrap();
        d.hit("me")?;
        Ok(MeAnswer {
            me: Me { id: Some(1), name: Some("Max".into()), seat: Some("family".into()), device_id: Some("dev1".into()) },
            latest: d.log.len() as u64,
        })
    }

    fn areas(&self) -> Result<Vec<Area>, ApiError> {
        let mut d = self.inner.lock().unwrap();
        d.hit("areas")?;
        Ok(d.areas.clone())
    }

    fn node(&self, id: u64) -> Result<Node, ApiError> {
        let mut d = self.inner.lock().unwrap();
        d.hit("node")?;
        d.live(id).cloned()
    }

    fn children(&self, id: u64, offset: u64) -> Result<ChildrenPage, ApiError> {
        let mut d = self.inner.lock().unwrap();
        d.hit("children")?;
        let n = d.live(id)?;
        if !n.is_dir {
            return Err(err(400, "invalid"));
        }
        let mut all: Vec<Node> = d.nodes.values().filter(|c| c.parent_id == Some(id) && !c.deleted).cloned().collect();
        all.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        const LIMIT: usize = 3; // kleine Seiten, damit das Blättern getestet wird
        let total = all.len() as u64;
        let items: Vec<Node> = all.into_iter().skip(offset as usize).take(LIMIT).collect();
        let next = if offset + (items.len() as u64) < total { Some(offset + items.len() as u64) } else { None };
        Ok(ChildrenPage { items, total, next })
    }

    fn changes(&self, since: u64) -> Result<ChangesPage, ApiError> {
        let mut d = self.inner.lock().unwrap();
        d.hit("changes")?;
        const LIMIT: usize = 4;
        let visible: Vec<String> = d.areas.iter().map(|a| a.id.clone()).collect();
        let rows: Vec<_> = d.log.iter().filter(|(s, _, a, _)| *s > since && visible.contains(a)).cloned().collect();
        let page: Vec<_> = rows.iter().take(LIMIT).cloned().collect();
        let changes = page
            .iter()
            .map(|(seq, op, area, id)| {
                let node = d.nodes.get(id).filter(|n| &n.area_id == area).cloned();
                Change { seq: *seq, op: op.clone(), area_id: area.clone(), node_id: *id, device: None, node }
            })
            .collect::<Vec<_>>();
        let next = page.last().map(|p| p.0).unwrap_or_else(|| since.max(d.log.len() as u64));
        Ok(ChangesPage { changes, next, more: rows.len() > LIMIT })
    }

    fn mkdir(&self, parent: u64, name: &str) -> Result<Node, ApiError> {
        let mut d = self.inner.lock().unwrap();
        d.hit("mkdir")?;
        d.writable(parent)?;
        if !names::is_valid_name(name) {
            return Err(err(400, "invalid"));
        }
        if let Some(t) = d.taken(parent, name) {
            let mut e = err(409, "exists");
            e.current = Some(Box::new(t.clone()));
            return Err(e);
        }
        d.next_id += 1;
        let id = d.next_id;
        let area = d.nodes[&parent].area_id.clone();
        let now = d.now();
        d.nodes.insert(
            id,
            Node {
                id,
                area_id: area,
                parent_id: Some(parent),
                name: name.into(),
                is_dir: true,
                rev: 1,
                updated_at: Some(now.clone()),
                created_at: Some(now),
                ..Default::default()
            },
        );
        d.record("create", id);
        Ok(d.nodes[&id].clone())
    }

    fn update_node(&self, id: u64, name: Option<&str>, parent: Option<u64>) -> Result<Node, ApiError> {
        let mut d = self.inner.lock().unwrap();
        d.hit("update")?;
        d.writable(id)?;
        let cur = d.live(id)?.clone();
        let new_parent = parent.unwrap_or(cur.parent_id.unwrap_or(0));
        if parent.is_some() {
            d.writable(new_parent)?;
        }
        let new_name = name.unwrap_or(&cur.name).to_string();
        if !names::is_valid_name(&new_name) {
            return Err(err(400, "invalid"));
        }
        if let Some(t) = d.taken(new_parent, &new_name) {
            if t.id != id {
                let mut e = err(409, "exists");
                e.current = Some(Box::new(t.clone()));
                return Err(e);
            }
        }
        let area = d.nodes[&new_parent].area_id.clone();
        let now = d.now();
        let n = d.nodes.get_mut(&id).unwrap();
        n.name = new_name;
        n.parent_id = Some(new_parent);
        n.area_id = area;
        n.rev += 1;
        n.updated_at = Some(now);
        d.record("move", id);
        Ok(d.nodes[&id].clone())
    }

    fn trash(&self, id: u64) -> Result<(), ApiError> {
        let mut d = self.inner.lock().unwrap();
        d.hit("trash")?;
        d.writable(id)?;
        let mut stack = vec![id];
        while let Some(i) = stack.pop() {
            let kids: Vec<u64> = d.nodes.values().filter(|n| n.parent_id == Some(i) && !n.deleted).map(|n| n.id).collect();
            stack.extend(kids);
            if let Some(n) = d.nodes.get_mut(&i) {
                n.deleted = true;
            }
        }
        d.record("delete", id);
        Ok(())
    }

    fn check(&self, parent: u64, name: &str, sha256_hex: &str, size: u64) -> Result<UploadCheck, ApiError> {
        let mut d = self.inner.lock().unwrap();
        d.hit("check")?;
        d.live(parent)?;
        Ok(match d.taken(parent, name) {
            Some(n) => UploadCheck { exists: true, same: !n.is_dir && n.sha256.as_deref() == Some(sha256_hex) && n.size == Some(size), node: Some(n.clone()) },
            None => UploadCheck { exists: false, same: false, node: None },
        })
    }

    fn upload(&self, src: &mut dyn ReadAt, sha256: &[u8; 32], progress: &mut dyn FnMut(u64, u64)) -> Result<String, ApiError> {
        self.inner.lock().unwrap().hit("upload")?;
        let len = src.len();
        let mut data = vec![0u8; len as usize];
        let n = src.read_at(0, &mut data).map_err(|e| ApiError::new(None, "read", e.to_string()))?;
        if n as u64 != len || Sha256::digest(&data).as_slice() != sha256 {
            return Err(ApiError::new(None, "changed", "changed"));
        }
        progress(len, len);
        Ok(self.inner.lock().unwrap().new_media(data))
    }

    fn commit(&self, req: &CommitRequest) -> Result<Node, ApiError> {
        let mut d = self.inner.lock().unwrap();
        d.hit("commit")?;
        d.writable(req.parent_id)?;
        let data = d.media.get(&req.media_id).cloned().ok_or_else(|| err(400, "upload_invalid"))?;
        let mut name = req.name.clone();
        if !names::is_valid_name(&name) {
            return Err(err(400, "invalid"));
        }
        let now = d.now();
        let existing = d.taken(req.parent_id, &name).cloned();
        if let Some(ex) = &existing {
            let ok = !ex.is_dir && (req.base_rev == Some(ex.rev) || req.on_conflict.as_deref() == Some("version"));
            if !ok {
                if req.on_conflict.as_deref() != Some("rename") {
                    let mut e = err(409, if ex.is_dir { "exists" } else { "conflict" });
                    e.current = Some(Box::new(ex.clone()));
                    return Err(e);
                }
                name = d.free_name(req.parent_id, &name);
            } else {
                let n = d.nodes.get_mut(&ex.id).unwrap();
                n.media_id = Some(req.media_id.clone());
                n.size = Some(data.len() as u64);
                n.sha256 = Some(sha_hex(&data));
                n.rev += 1;
                n.mtime = req.mtime.and_then(chrono::DateTime::from_timestamp_millis).map(|t| t.to_rfc3339());
                n.updated_at = Some(now);
                let id = ex.id;
                d.record("update", id);
                return Ok(d.nodes[&id].clone());
            }
        }
        d.next_id += 1;
        let id = d.next_id;
        let area = d.nodes[&req.parent_id].area_id.clone();
        d.nodes.insert(
            id,
            Node {
                id,
                area_id: area,
                parent_id: Some(req.parent_id),
                name,
                is_dir: false,
                size: Some(data.len() as u64),
                sha256: Some(sha_hex(&data)),
                media_id: Some(req.media_id.clone()),
                mtime: req.mtime.and_then(chrono::DateTime::from_timestamp_millis).map(|t| t.to_rfc3339()),
                rev: 1,
                updated_at: Some(now.clone()),
                created_at: Some(now),
                deleted: false,
            },
        );
        d.record("create", id);
        Ok(d.nodes[&id].clone())
    }

    fn content(&self, id: u64) -> Result<Content, ApiError> {
        let mut d = self.inner.lock().unwrap();
        d.hit("content")?;
        let n = d.live(id)?.clone();
        Ok(Content { media_id: n.media_id, size: n.size, name: Some(n.name) })
    }

    fn download(&self, media_id: &str, start: u64, end: u64, sink: &mut dyn FnMut(&[u8]) -> Result<(), String>) -> Result<u64, ApiError> {
        let data = {
            let mut d = self.inner.lock().unwrap();
            d.hit("download")?;
            d.media.get(media_id).cloned().ok_or_else(|| err(404, "not_found"))?
        };
        let end = (end as usize).min(data.len());
        let start = (start as usize).min(end);
        for chunk in data[start..end].chunks(5000) {
            sink(chunk).map_err(|m| ApiError::new(None, "cancelled", m))?;
        }
        Ok((end - start) as u64)
    }
}

// ───────────────────────── FakeFs ─────────────────────────

#[derive(Debug, Clone)]
struct FNode {
    name: String,
    is_dir: bool,
    data: Vec<u8>,
    size: u64,
    mtime_ms: i64,
    ph: Option<Placeholder>,
    locked: bool,
}

type Hydrator = Box<dyn Fn(&Identity) -> Option<Vec<u8>> + Send + Sync>;

/// Dateisystem im Speicher mit Platzhaltern (Pfade ohne Groß/Klein).
pub struct FakeFs {
    nodes: Mutex<BTreeMap<String, FNode>>,
    hydrator: Mutex<Option<Hydrator>>,
    pub ops: Mutex<Vec<String>>,
}

fn k(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/").to_lowercase().trim_end_matches('/').to_string()
}

fn parent_key(key: &str) -> String {
    key.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_default()
}

fn nf() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "not found")
}

impl FakeFs {
    pub fn new(root: &Path) -> FakeFs {
        let fs = FakeFs { nodes: Mutex::new(BTreeMap::new()), hydrator: Mutex::new(None), ops: Mutex::new(Vec::new()) };
        fs.nodes.lock().unwrap().insert(k(root), FNode { name: "root".into(), is_dir: true, data: vec![], size: 0, mtime_ms: 0, ph: None, locked: false });
        fs
    }

    pub fn set_hydrator(&self, f: impl Fn(&Identity) -> Option<Vec<u8>> + Send + Sync + 'static) {
        *self.hydrator.lock().unwrap() = Some(Box::new(f));
    }

    fn op(&self, s: String) {
        self.ops.lock().unwrap().push(s);
    }

    pub fn take_ops(&self) -> Vec<String> {
        std::mem::take(&mut *self.ops.lock().unwrap())
    }

    fn entry(n: &FNode) -> LocalEntry {
        LocalEntry { name: n.name.clone(), is_dir: n.is_dir, size: n.size, mtime_ms: n.mtime_ms, placeholder: n.ph.clone() }
    }

    fn need_parent(m: &BTreeMap<String, FNode>, key: &str) -> io::Result<()> {
        match m.get(&parent_key(key)) {
            Some(p) if p.is_dir => Ok(()),
            _ => Err(nf()),
        }
    }

    // ── Benutzer-Aktionen ──
    pub fn user_write(&self, path: &Path, data: &[u8]) {
        let mut m = self.nodes.lock().unwrap();
        let key = k(path);
        Self::need_parent(&m, &key).expect("parent");
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let n = m.entry(key).or_insert(FNode { name, is_dir: false, data: vec![], size: 0, mtime_ms: 0, ph: None, locked: false });
        n.data = data.to_vec();
        n.size = data.len() as u64;
        n.mtime_ms += 1;
        if let Some(ph) = &mut n.ph {
            ph.in_sync = false;
            ph.hydrated = true;
        }
    }
    pub fn user_mkdir(&self, path: &Path) {
        let mut m = self.nodes.lock().unwrap();
        let key = k(path);
        Self::need_parent(&m, &key).expect("parent");
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        m.insert(key, FNode { name, is_dir: true, data: vec![], size: 0, mtime_ms: 0, ph: None, locked: false });
    }
    pub fn user_delete(&self, path: &Path) {
        let mut m = self.nodes.lock().unwrap();
        let key = k(path);
        m.retain(|kk, _| kk != &key && !kk.starts_with(&format!("{key}/")));
    }
    pub fn user_rename(&self, from: &Path, to: &Path) {
        self.rename(from, to).expect("rename");
    }
    pub fn user_pin(&self, path: &Path, pin: Pin) {
        let mut m = self.nodes.lock().unwrap();
        if let Some(ph) = m.get_mut(&k(path)).and_then(|n| n.ph.as_mut()) {
            ph.pin = pin;
        }
    }
    pub fn lock(&self, path: &Path, locked: bool) {
        if let Some(n) = self.nodes.lock().unwrap().get_mut(&k(path)) {
            n.locked = locked;
        }
    }
    pub fn data(&self, path: &Path) -> Option<Vec<u8>> {
        self.nodes.lock().unwrap().get(&k(path)).map(|n| n.data.clone())
    }
    pub fn get(&self, path: &Path) -> Option<LocalEntry> {
        self.nodes.lock().unwrap().get(&k(path)).map(Self::entry)
    }
    /// Alle Pfade (klein geschrieben, mit „/“) unterhalb von `root`.
    pub fn paths(&self) -> Vec<String> {
        self.nodes.lock().unwrap().keys().cloned().collect()
    }
}

impl LocalFs for FakeFs {
    fn stat(&self, path: &Path) -> io::Result<Option<LocalEntry>> {
        Ok(self.nodes.lock().unwrap().get(&k(path)).map(Self::entry))
    }

    fn list(&self, dir: &Path) -> io::Result<Vec<LocalEntry>> {
        let m = self.nodes.lock().unwrap();
        let key = k(dir);
        if !m.get(&key).is_some_and(|n| n.is_dir) {
            return Err(nf());
        }
        Ok(m.iter().filter(|(kk, _)| parent_key(kk) == key && **kk != key).map(|(_, n)| Self::entry(n)).collect())
    }

    fn create_placeholder(&self, dir: &Path, name: &str, meta: &PlaceholderMeta) -> io::Result<()> {
        let mut m = self.nodes.lock().unwrap();
        let path = dir.join(name);
        let key = k(&path);
        Self::need_parent(&m, &key)?;
        if m.contains_key(&key) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "exists"));
        }
        self.op(format!("create {}", key));
        m.insert(
            key,
            FNode {
                name: name.into(),
                is_dir: meta.is_dir,
                data: vec![],
                size: meta.size,
                mtime_ms: meta.mtime_ms,
                ph: Some(Placeholder { identity: Some(meta.identity.clone()), in_sync: true, pin: Pin::Unspecified, hydrated: meta.is_dir || meta.size == 0 }),
                locked: false,
            },
        );
        Ok(())
    }

    fn update_placeholder(&self, path: &Path, meta: &PlaceholderMeta, content_changed: bool) -> io::Result<()> {
        let mut m = self.nodes.lock().unwrap();
        let key = k(path);
        let n = m.get_mut(&key).ok_or_else(nf)?;
        let ph = n.ph.as_mut().ok_or_else(|| io::Error::other("not a placeholder"))?;
        self.op(format!("update {} {}", key, if content_changed { "dehydrate" } else { "meta" }));
        ph.identity = Some(meta.identity.clone());
        ph.in_sync = true;
        n.mtime_ms = meta.mtime_ms;
        if content_changed {
            ph.hydrated = meta.size == 0;
            n.data.clear();
            n.size = meta.size;
        }
        Ok(())
    }

    fn convert_to_placeholder(&self, path: &Path, identity: &Identity) -> io::Result<()> {
        let mut m = self.nodes.lock().unwrap();
        let key = k(path);
        let n = m.get_mut(&key).ok_or_else(nf)?;
        self.op(format!("convert {}", key));
        n.ph = Some(Placeholder { identity: Some(identity.clone()), in_sync: true, pin: Pin::Unspecified, hydrated: true });
        Ok(())
    }

    fn set_in_sync(&self, path: &Path, in_sync: bool) -> io::Result<()> {
        let mut m = self.nodes.lock().unwrap();
        if let Some(ph) = m.get_mut(&k(path)).and_then(|n| n.ph.as_mut()) {
            ph.in_sync = in_sync;
        }
        Ok(())
    }

    fn revert_placeholder(&self, path: &Path) -> io::Result<()> {
        let mut m = self.nodes.lock().unwrap();
        let key = k(path);
        let n = m.get_mut(&key).ok_or_else(nf)?;
        self.op(format!("revert {}", key));
        if n.ph.as_ref().is_some_and(|p| !p.hydrated) {
            return Err(io::Error::other("not hydrated"));
        }
        n.ph = None;
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let mut m = self.nodes.lock().unwrap();
        let (fk, tk) = (k(from), k(to));
        if !m.contains_key(&fk) {
            return Err(nf());
        }
        Self::need_parent(&m, &tk)?;
        if fk != tk && m.contains_key(&tk) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "exists"));
        }
        self.op(format!("rename {} -> {}", fk, tk));
        let moved: Vec<(String, FNode)> =
            m.iter().filter(|(kk, _)| **kk == fk || kk.starts_with(&format!("{fk}/"))).map(|(a, b)| (a.clone(), b.clone())).collect();
        for (kk, _) in &moved {
            m.remove(kk);
        }
        for (kk, mut n) in moved {
            if kk == fk {
                n.name = to.file_name().unwrap().to_string_lossy().to_string();
            }
            m.insert(format!("{tk}{}", &kk[fk.len()..]), n);
        }
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        let mut m = self.nodes.lock().unwrap();
        let key = k(path);
        match m.get(&key) {
            Some(n) if !n.is_dir => {
                self.op(format!("delete {}", key));
                m.remove(&key);
                Ok(())
            }
            _ => Err(nf()),
        }
    }

    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        let mut m = self.nodes.lock().unwrap();
        let key = k(path);
        if m.keys().any(|kk| kk.starts_with(&format!("{key}/"))) {
            return Err(io::Error::other("not empty"));
        }
        self.op(format!("rmdir {}", key));
        m.remove(&key).map(|_| ()).ok_or_else(nf)
    }

    fn open_read(&self, path: &Path) -> io::Result<Box<dyn ReadAt>> {
        let m = self.nodes.lock().unwrap();
        let n = m.get(&k(path)).ok_or_else(nf)?;
        if n.locked {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "sharing violation"));
        }
        Ok(Box::new(io::Cursor::new(n.data.clone())))
    }

    fn hydrate(&self, path: &Path) -> io::Result<()> {
        let id = {
            let m = self.nodes.lock().unwrap();
            m.get(&k(path)).and_then(|n| n.ph.as_ref()).and_then(|p| p.identity.clone()).ok_or_else(nf)?
        };
        let data = self.hydrator.lock().unwrap().as_ref().and_then(|h| h(&id)).ok_or_else(|| io::Error::other("no data"))?;
        let mut m = self.nodes.lock().unwrap();
        let n = m.get_mut(&k(path)).ok_or_else(nf)?;
        self.op(format!("hydrate {}", k(path)));
        n.data = data;
        if let Some(ph) = &mut n.ph {
            ph.hydrated = true;
        }
        Ok(())
    }

    fn dehydrate(&self, path: &Path) -> io::Result<()> {
        let mut m = self.nodes.lock().unwrap();
        let key = k(path);
        let n = m.get_mut(&key).ok_or_else(nf)?;
        self.op(format!("dehydrate {}", key));
        n.data.clear();
        if let Some(ph) = &mut n.ph {
            ph.hydrated = false;
        }
        Ok(())
    }
}

/// Pfad aus Teilen (Tests).
pub fn p(root: &Path, parts: &[&str]) -> PathBuf {
    parts.iter().fold(root.to_path_buf(), |acc, s| acc.join(s))
}
