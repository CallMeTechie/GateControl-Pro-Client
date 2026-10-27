//! Der Abgleich zwischen Drive und dem Sync-Root – ohne Windows-Abhängigkeit,
//! gegen `Remote` und `LocalFs` geschrieben (Tests: `testing::FakeDrive`,
//! `testing::FakeFs`).
//!
//! Ablauf:
//!   * `full_sync` – beim ersten Start, nach Fehlern im Zustand oder einem
//!     Überlauf der Dateisystem-Ereignisse: Bereiche → Ordner unter dem
//!     Sync-Root, dann jeder Ordner des Servers gegen den lokalen Ordner
//!     (Platzhalter anlegen/ändern, lokale neue Dateien hochladen, offline
//!     gelöschte Platzhalter in den Papierkorb – mit Bremse bei Massenlöschung).
//!   * `poll` – `GET changes?since=` ab dem Cursor, jede Änderung einzeln.
//!   * `process_local` – Pfade aus der Dateisystem-Beobachtung und den
//!     Rückrufen NOTIFY_DELETE/RENAME: neue Dateien/Ordner hoch, geänderte
//!     Platzhalter als neue Fassung (`baseRev`), Umbenennen/Verschieben,
//!     Löschen, Pin-Zustände (laden / Speicher freigeben).
//!
//! Konflikte gehen nie verloren: die lokale Fassung bleibt als
//! „Name (Konflikt <Gerät> <Datum>).ext“ und wird hochgeladen.

use super::identity::Identity;
use super::localfs::*;
use super::model::*;
use super::names;
use super::protocol::StatusError;
use super::remote::{ApiError, ReadAt, Remote};
use super::state::{AreaDir, Entry, State};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Mehr gleichzeitig offline gelöschte Dateien als das (oder mehr als 20 %)
/// werden nicht an den Server gegeben, sondern lokal wiederhergestellt.
pub const MASS_DELETE_MAX: usize = 500;
pub const MASS_DELETE_RATIO: f64 = 0.2;
const MAX_ERRORS: usize = 20;
/// Zusätzlich zum Änderungsprotokoll regelmäßig alles vergleichen (verpasste Ereignisse).
pub const FULL_SYNC_EVERY: std::time::Duration = std::time::Duration::from_secs(6 * 3600);
const FULL_SYNC_RETRY: std::time::Duration = std::time::Duration::from_secs(15 * 60);

pub struct EngineConfig {
    pub root: PathBuf,
    pub device_name: String,
}

/// Zustand, den der Abgleich mit Rückrufen und Status teilt.
#[derive(Default)]
pub struct Shared {
    /// Bereich → schreibbar? (für NOTIFY_DELETE/RENAME ohne Engine-Sperre)
    pub writable: RwLock<HashMap<String, bool>>,
    /// Wurzelordner der Bereiche (dürfen nicht gelöscht/umbenannt werden).
    pub roots: RwLock<HashSet<u64>>,
    /// Ordnername unter dem Sync-Root → Bereich.
    pub area_dirs: RwLock<HashMap<String, String>>,
    pub pending: AtomicU64,
    pub transferring: AtomicU64,
    /// Laufende Uploads/Durchläufe abbrechen (stop, pause, unregister).
    pub stop: AtomicBool,
}

impl Shared {
    pub fn area_writable(&self, area: &str) -> Option<bool> {
        self.writable.read().ok().and_then(|m| m.get(area).copied())
    }
    pub fn is_root(&self, node: u64) -> bool {
        self.roots.read().is_ok_and(|r| r.contains(&node))
    }
    /// Bereich, zu dem ein Ordnername unter dem Sync-Root gehört.
    pub fn area_of_dir(&self, dir: &str) -> Option<String> {
        self.area_dirs.read().ok().and_then(|m| m.get(&names::key(dir)).cloned())
    }
}

enum Outcome {
    Done,
    Descend,
    OfflineDelete,
}

type Clock = Box<dyn Fn() -> chrono::DateTime<chrono::Local> + Send>;
type Logger = Box<dyn Fn(&str, &str) + Send>;

pub struct Engine {
    pub cfg: EngineConfig,
    remote: Arc<dyn Remote>,
    fs: Arc<dyn LocalFs>,
    pub state: State,
    pub shared: Arc<Shared>,
    errors: VecDeque<StatusError>,
    /// Beim nächsten Durchlauf alles vergleichen.
    pub needs_full: bool,
    /// Lokaler Fehler beim Anwenden: beim nächsten regelmäßigen Vollabgleich nachholen.
    needs_full_later: bool,
    last_full: Option<std::time::Instant>,
    queue: BTreeSet<PathBuf>,
    /// Pfade, die gerade nicht lesbar waren (Programm schreibt noch).
    retry: BTreeSet<PathBuf>,
    /// NOTIFY_DELETE: Knoten → Pfad, noch an den Server zu geben.
    deletes: Vec<(u64, PathBuf)>,
    clock: Clock,
    log: Logger,
}

fn io_err(e: io::Error) -> ApiError {
    ApiError::new(None, "local_io", e.to_string())
}

fn ident(n: &Entry) -> Identity {
    Identity::new(n.id, n.rev, &n.area, n.media.as_deref())
}

fn meta(n: &Entry) -> PlaceholderMeta {
    PlaceholderMeta { identity: ident(n), is_dir: n.is_dir, size: n.size, mtime_ms: n.mtime_ms, ctime_ms: n.ctime_ms }
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
}

/// Bricht ein Hochladen ab, sobald `stop` gesetzt ist.
struct StopReader<'a> {
    inner: Box<dyn ReadAt>,
    stop: &'a AtomicBool,
}

impl ReadAt for StopReader<'_> {
    fn len(&self) -> u64 {
        self.inner.len()
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if self.stop.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "stopped"));
        }
        self.inner.read_at(offset, buf)
    }
}

impl Engine {
    pub fn new(cfg: EngineConfig, remote: Arc<dyn Remote>, fs: Arc<dyn LocalFs>, state: State, shared: Arc<Shared>) -> Engine {
        let needs_full = state.cursor == 0 || state.areas.is_empty();
        let e = Engine {
            cfg,
            remote,
            fs,
            state,
            shared,
            errors: VecDeque::new(),
            needs_full,
            needs_full_later: false,
            last_full: None,
            queue: BTreeSet::new(),
            retry: BTreeSet::new(),
            deletes: Vec::new(),
            clock: Box::new(chrono::Local::now),
            log: Box::new(|_, _| {}),
        };
        e.publish_roles();
        e
    }

    pub fn set_clock(&mut self, f: impl Fn() -> chrono::DateTime<chrono::Local> + Send + 'static) {
        self.clock = Box::new(f);
    }

    pub fn set_logger(&mut self, f: impl Fn(&str, &str) + Send + 'static) {
        self.log = Box::new(f);
    }

    pub fn errors(&self) -> Vec<StatusError> {
        self.errors.iter().cloned().collect()
    }

    pub fn pending(&self) -> u64 {
        (self.queue.len() + self.retry.len() + self.deletes.len()) as u64
    }

    fn update_pending(&self) {
        self.shared.pending.store(self.pending(), Ordering::Relaxed);
    }

    fn info(&self, msg: &str) {
        (self.log)("info", msg);
    }

    fn error(&mut self, code: &str, message: &str, path: Option<&Path>) {
        let path = path.map(|p| p.to_string_lossy().to_string());
        (self.log)("warn", &format!("{code}: {message}{}", path.as_deref().map(|p| format!(" ({p})")).unwrap_or_default()));
        self.errors.retain(|e| !(e.code == code && e.path == path));
        self.errors.push_back(StatusError { code: code.into(), message: message.chars().take(300).collect(), path, at: chrono::Utc::now().to_rfc3339() });
        while self.errors.len() > MAX_ERRORS {
            self.errors.pop_front();
        }
    }

    fn clear_error(&mut self, path: &Path) {
        let p = path.to_string_lossy();
        self.errors.retain(|e| e.path.as_deref() != Some(&*p));
    }

    /// Fehler ohne Pfad (Netz, Server) nach einem gelungenen Durchlauf entfernen.
    pub fn clear_general_errors(&mut self) {
        self.errors.retain(|e| e.path.is_some());
    }

    fn check_stop(&self) -> Result<(), ApiError> {
        if self.shared.stop.load(Ordering::Relaxed) {
            return Err(ApiError::new(None, "cancelled", "stopped"));
        }
        Ok(())
    }

    pub fn path_of(&self, id: u64) -> Option<PathBuf> {
        self.state.rel_path(id).map(|r| self.cfg.root.join(r))
    }

    fn rel<'a>(&self, path: &'a Path) -> Option<&'a Path> {
        path.strip_prefix(&self.cfg.root).ok()
    }

    fn publish_roles(&self) {
        if let Ok(mut m) = self.shared.writable.write() {
            m.clear();
            for a in &self.state.areas {
                m.insert(a.id.clone(), a.writable());
            }
        }
        if let Ok(mut r) = self.shared.roots.write() {
            *r = self.state.areas.iter().map(|a| a.root_id).collect();
        }
        if let Ok(mut d) = self.shared.area_dirs.write() {
            *d = self.state.areas.iter().map(|a| (names::key(&a.dir), a.id.clone())).collect();
        }
    }

    fn writable_area(&self, area: &str) -> bool {
        self.state.area(area).is_some_and(AreaDir::writable)
    }

    // ───────────────────────── Durchläufe ─────────────────────────

    /// Ein Durchlauf: voller Abgleich oder Änderungen seit dem Cursor, dann lokale Änderungen.
    pub fn sync(&mut self) -> Result<(), ApiError> {
        self.clear_general_errors();
        let periodic = self.last_full.is_none_or(|t| t.elapsed() >= FULL_SYNC_EVERY);
        if self.needs_full_later && self.last_full.is_none_or(|t| t.elapsed() >= FULL_SYNC_RETRY) {
            self.needs_full = true;
        }
        if self.needs_full || self.state.cursor == 0 || periodic {
            self.full_sync()?;
        } else {
            self.poll()?;
        }
        self.process_local()?;
        self.state.last_sync = Some(chrono::Utc::now().to_rfc3339());
        Ok(())
    }

    pub fn full_sync(&mut self) -> Result<(), ApiError> {
        self.check_stop()?;
        let had_state = self.state.cursor > 0 && !self.state.is_empty();
        let me = self.remote.me()?;
        self.sync_areas()?;
        let roots: Vec<u64> = self.state.areas.iter().map(|a| a.root_id).collect();
        let mut offline_deletes: Vec<(u64, PathBuf)> = Vec::new();
        let mut orphans: Vec<(Identity, PathBuf, LocalEntry)> = Vec::new();
        for root in roots {
            self.populate(root, had_state, &mut offline_deletes, &mut orphans)?;
        }
        self.resolve_after_scan(offline_deletes, orphans)?;
        self.state.cursor = self.state.cursor.max(me.latest);
        self.needs_full = false;
        self.needs_full_later = false;
        self.last_full = Some(std::time::Instant::now());
        self.info(&format!("Vollständiger Abgleich: {} Einträge", self.state.len()));
        Ok(())
    }

    pub fn poll(&mut self) -> Result<(), ApiError> {
        self.check_stop()?;
        self.sync_areas()?;
        for _ in 0..10_000 {
            let page = self.remote.changes(self.state.cursor)?;
            for c in &page.changes {
                self.check_stop()?;
                match self.apply_change(c) {
                    Ok(()) => {}
                    Err(e) if e.code == "local_io" => {
                        self.error(&e.code, &e.message, None);
                        self.needs_full_later = true;
                    }
                    Err(e) => return Err(e),
                }
                self.state.cursor = self.state.cursor.max(c.seq);
            }
            self.state.cursor = self.state.cursor.max(page.next);
            if !page.more || page.changes.is_empty() {
                break;
            }
        }
        if self.needs_full {
            self.full_sync()?;
        }
        Ok(())
    }

    // ───────────────────────── Bereiche ─────────────────────────

    fn unique_dir(&self, label: &str, area_id: &str) -> String {
        let base = names::dir_name_for_label(label);
        let taken = |d: &str| self.state.areas.iter().any(|a| a.id != area_id && names::same_name(&a.dir, d));
        if !taken(&base) {
            return base;
        }
        (2..).map(|i| format!("{base} ({i})")).find(|d| !taken(d)).unwrap()
    }

    fn sync_areas(&mut self) -> Result<(), ApiError> {
        // Kinder-Ordner, die ein Elternteil nur einsehen darf, werden nicht im
        // Hintergrund abgeglichen: jedes Auflisten meldet dem Kind „angesehen“.
        let areas: Vec<Area> = self.remote.areas()?.into_iter().filter(|a| a.via.as_deref() != Some("parent")).collect();
        let gone: Vec<AreaDir> = self.state.areas.iter().filter(|o| !areas.iter().any(|a| a.id == o.id && a.root_id == o.root_id)).cloned().collect();
        for g in gone {
            let path = self.cfg.root.join(&g.dir);
            self.info(&format!("Bereich {} nicht mehr verfügbar", g.id));
            self.remove_local_tree(&path)?;
            self.state.remove(g.root_id);
            self.state.areas.retain(|a| a.id != g.id);
        }
        for a in &areas {
            let existing = self.state.area(&a.id).cloned();
            let dir = match &existing {
                Some(e) if e.label == a.label => e.dir.clone(),
                _ => self.unique_dir(&a.label, &a.id),
            };
            if let Some(e) = &existing {
                if e.dir != dir {
                    let (from, to) = (self.cfg.root.join(&e.dir), self.cfg.root.join(&dir));
                    if self.fs.stat(&from).map_err(io_err)?.is_some() && self.fs.stat(&to).map_err(io_err)?.is_none() {
                        self.fs.rename(&from, &to).map_err(io_err)?;
                    }
                }
            }
            let ad = AreaDir { id: a.id.clone(), root_id: a.root_id, dir: dir.clone(), label: a.label.clone(), role: a.role, archived: a.archived };
            self.state.areas.retain(|x| x.id != a.id);
            self.state.areas.push(ad);
            let root_entry = Entry {
                id: a.root_id,
                parent: 0,
                area: a.id.clone(),
                name: dir.clone(),
                is_dir: true,
                rev: 0,
                size: 0,
                media: None,
                sha256: None,
                mtime_ms: 0,
                ctime_ms: 0,
            };
            self.state.upsert(root_entry.clone());
            let path = self.cfg.root.join(&dir);
            match self.fs.stat(&path).map_err(io_err)? {
                None => self.fs.create_placeholder(&self.cfg.root, &dir, &meta(&root_entry)).map_err(io_err)?,
                Some(l) if l.is_dir => match l.identity() {
                    None => self.fs.convert_to_placeholder(&path, &ident(&root_entry)).map_err(io_err)?,
                    Some(i) if i.node != a.root_id => self.fs.update_placeholder(&path, &meta(&root_entry), false).map_err(io_err)?,
                    Some(_) => {}
                },
                Some(_) => {
                    // eine Datei mit dem Namen des Bereichs: beiseite legen
                    let c = self.free_conflict_name(&self.cfg.root.clone(), &dir);
                    self.fs.rename(&path, &self.cfg.root.join(&c)).map_err(io_err)?;
                    self.fs.create_placeholder(&self.cfg.root, &dir, &meta(&root_entry)).map_err(io_err)?;
                }
            }
        }
        self.publish_roles();
        Ok(())
    }

    // ───────────────────────── Server → lokal ─────────────────────────

    fn list_all(&self, dir_id: u64) -> Result<Vec<Node>, ApiError> {
        let mut out = Vec::new();
        let mut offset = 0;
        for _ in 0..100_000 {
            let page = self.remote.children(dir_id, offset)?;
            let n = page.items.len() as u64;
            out.extend(page.items);
            match page.next {
                Some(next) if next > offset && n > 0 => offset = next,
                _ => break,
            }
        }
        Ok(out)
    }

    fn populate(
        &mut self,
        start: u64,
        had_state: bool,
        offline: &mut Vec<(u64, PathBuf)>,
        orphans: &mut Vec<(Identity, PathBuf, LocalEntry)>,
    ) -> Result<(), ApiError> {
        let mut queue = VecDeque::from([start]);
        while let Some(dir_id) = queue.pop_front() {
            self.check_stop()?;
            let Some(dir_path) = self.path_of(dir_id) else { continue };
            let remote = self.list_all(dir_id)?;
            let mut local: HashMap<String, LocalEntry> = self.fs.list(&dir_path).unwrap_or_default().into_iter().map(|l| (names::key(&l.name), l)).collect();
            let ids: HashSet<u64> = remote.iter().map(|n| n.id).collect();
            let stale: Vec<u64> = self.state.children_of(dir_id).iter().filter(|e| !ids.contains(&e.id)).map(|e| e.id).collect();
            let mut stale_entries: HashMap<u64, Entry> = HashMap::new();
            for id in stale {
                if let Some(e) = self.state.get(id).cloned() {
                    stale_entries.insert(id, e);
                }
                self.state.remove(id);
            }
            for r in &remote {
                if !names::is_valid_name(&r.name) {
                    self.error("name_unsupported", &format!("„{}“ ist unter Windows kein gültiger Name", r.name), Some(&dir_path));
                    continue;
                }
                let old = self.state.get(r.id).cloned();
                let l = local.remove(&names::key(&r.name));
                self.state.upsert(Entry::from_node(r));
                match self.reconcile(&dir_path, r, old.as_ref(), l, had_state) {
                    Ok(Outcome::Descend) => queue.push_back(r.id),
                    Ok(Outcome::OfflineDelete) => offline.push((r.id, dir_path.join(&r.name))),
                    Ok(Outcome::Done) => {}
                    // eine gesperrte Datei hält nicht den ganzen Abgleich auf
                    Err(e) if e.code == "local_io" => self.error(&e.code, &e.message, Some(&dir_path.join(&r.name))),
                    Err(e) => return Err(e),
                }
            }
            for (_, l) in local {
                let path = dir_path.join(&l.name);
                if names::is_ignored(&l.name) {
                    continue;
                }
                match l.identity().cloned() {
                    Some(id) => orphans.push((id, path, l)),
                    None => {
                        self.queue.insert(path);
                    }
                }
            }
        }
        Ok(())
    }

    /// Ein Server-Knoten `r` gegen das, was lokal unter seinem Namen liegt.
    fn reconcile(&mut self, dir: &Path, r: &Node, old: Option<&Entry>, local: Option<LocalEntry>, offline_delete_ok: bool) -> Result<Outcome, ApiError> {
        let path = dir.join(&r.name);
        let e = Entry::from_node(r);
        let Some(l) = local else {
            if let Some(o) = old {
                if offline_delete_ok && o.rev == r.rev && o.parent == e.parent && o.name == e.name {
                    return Ok(Outcome::OfflineDelete);
                }
            }
            self.fs.create_placeholder(dir, &r.name, &meta(&e)).map_err(io_err)?;
            return Ok(if r.is_dir { Outcome::Descend } else { Outcome::Done });
        };
        match l.identity().cloned() {
            Some(id) if id.node == r.id && l.is_dir == r.is_dir => {
                if r.is_dir {
                    if id.rev != r.rev || !l.in_sync() {
                        self.fs.update_placeholder(&path, &meta(&e), false).map_err(io_err)?;
                    }
                    return Ok(Outcome::Descend);
                }
                let content_changed = id.media != e.media;
                if id.rev == r.rev && !content_changed {
                    if !l.in_sync() {
                        self.queue.insert(path);
                    } else {
                        self.apply_pin(&path, &l);
                    }
                } else if !l.in_sync() && content_changed {
                    self.local_conflict(&path, &l, &e)?;
                } else if !l.in_sync() {
                    // Nur Name/Metadaten auf dem Server geändert, Inhalt lokal geändert: hochladen
                    self.queue.insert(path);
                } else {
                    self.fs.update_placeholder(&path, &meta(&e), content_changed).map_err(io_err)?;
                    if content_changed {
                        if let Some(l2) = self.fs.stat(&path).map_err(io_err)? {
                            self.apply_pin(&path, &l2);
                        }
                    }
                }
                Ok(Outcome::Done)
            }
            Some(_) => {
                // Platzhalter eines anderen Knotens unter diesem Namen
                if l.in_sync() && l.is_dir && r.is_dir {
                    self.fs.update_placeholder(&path, &meta(&e), false).map_err(io_err)?;
                    return Ok(Outcome::Descend);
                }
                if l.in_sync() && !l.is_dir {
                    self.fs.remove_file(&path).map_err(io_err)?;
                } else {
                    self.set_aside(&path, &l)?;
                }
                self.fs.create_placeholder(dir, &r.name, &meta(&e)).map_err(io_err)?;
                Ok(if r.is_dir { Outcome::Descend } else { Outcome::Done })
            }
            None => match (l.is_dir, r.is_dir) {
                (true, true) => {
                    self.fs.convert_to_placeholder(&path, &ident(&e)).map_err(io_err)?;
                    Ok(Outcome::Descend)
                }
                (false, false) => {
                    let same = match self.hash_file(&path) {
                        Ok((hex, _, size)) => Some(hex) == e.sha256 && size == e.size,
                        Err(_) => false,
                    };
                    if same {
                        self.fs.convert_to_placeholder(&path, &ident(&e)).map_err(io_err)?;
                    } else {
                        self.set_aside(&path, &l)?;
                        self.fs.create_placeholder(dir, &r.name, &meta(&e)).map_err(io_err)?;
                    }
                    Ok(Outcome::Done)
                }
                _ => {
                    self.set_aside(&path, &l)?;
                    self.fs.create_placeholder(dir, &r.name, &meta(&e)).map_err(io_err)?;
                    Ok(if r.is_dir { Outcome::Descend } else { Outcome::Done })
                }
            },
        }
    }

    /// Lokales Element unter einen Konfliktnamen legen und zum Hochladen vormerken.
    fn set_aside(&mut self, path: &Path, l: &LocalEntry) -> Result<PathBuf, ApiError> {
        let dir = path.parent().unwrap_or(&self.cfg.root).to_path_buf();
        if l.placeholder.is_some() {
            self.fs.revert_placeholder(path).map_err(io_err)?;
        }
        let c = self.free_conflict_name(&dir, &l.name);
        let to = dir.join(&c);
        self.fs.rename(path, &to).map_err(io_err)?;
        self.info(&format!("Konfliktkopie: {}", to.display()));
        self.queue.insert(to.clone());
        Ok(to)
    }

    /// Lokal geändert und auf dem Server geändert: lokale Fassung als Konfliktkopie, Server-Fassung an den Namen.
    fn local_conflict(&mut self, path: &Path, l: &LocalEntry, e: &Entry) -> Result<(), ApiError> {
        self.set_aside(path, l)?;
        let dir = path.parent().unwrap_or(&self.cfg.root).to_path_buf();
        self.fs.create_placeholder(&dir, &e.name, &meta(e)).map_err(io_err)?;
        Ok(())
    }

    fn free_conflict_name(&self, dir: &Path, name: &str) -> String {
        let stamp = names::conflict_stamp((self.clock)());
        for n in 1..1000 {
            let c = names::conflict_name(name, &self.cfg.device_name, &stamp, n);
            if self.fs.stat(&dir.join(&c)).ok().flatten().is_none() {
                return c;
            }
        }
        names::conflict_name(name, &self.cfg.device_name, &stamp, 1000)
    }

    /// Nach dem vollen Durchlauf: lokal verschobene Platzhalter, veraltete
    /// Platzhalter und offline gelöschte Dateien.
    fn resolve_after_scan(&mut self, mut offline: Vec<(u64, PathBuf)>, orphans: Vec<(Identity, PathBuf, LocalEntry)>) -> Result<(), ApiError> {
        for (id, path, l) in orphans {
            if let Some(pos) = offline.iter().position(|(n, _)| *n == id.node) {
                // verschoben, während das Programm nicht lief
                offline.remove(pos);
                self.queue.insert(path);
                continue;
            }
            if l.in_sync() && self.state.get(id.node).is_none_or(|e| self.path_of(e.id).is_some_and(|p| !same_path(&p, &path))) {
                self.remove_local_tree(&path)?;
            } else {
                if l.placeholder.as_ref().is_some_and(|p| p.hydrated || l.is_dir) {
                    self.fs.revert_placeholder(&path).map_err(io_err)?;
                    self.queue.insert(path);
                } else {
                    self.fs.remove_file(&path).map_err(io_err)?;
                }
            }
        }
        if offline.is_empty() {
            return Ok(());
        }
        let files = self.state.files().max(1);
        if offline.len() > MASS_DELETE_MAX || (offline.len() >= 10 && offline.len() as f64 > MASS_DELETE_RATIO * files as f64) {
            self.error(
                "mass_delete",
                &format!("{} Dateien wurden lokal gelöscht, während das Programm nicht lief – nicht übertragen, wiederhergestellt", offline.len()),
                None,
            );
            for (id, path) in offline {
                if let (Some(e), Some(dir)) = (self.state.get(id).cloned(), path.parent()) {
                    self.fs.create_placeholder(dir, &e.name, &meta(&e)).map_err(io_err)?;
                    if e.is_dir {
                        let (mut o, mut orph) = (Vec::new(), Vec::new());
                        self.populate(id, false, &mut o, &mut orph)?;
                    }
                }
            }
            return Ok(());
        }
        for (id, path) in offline {
            self.deletes.push((id, path));
        }
        Ok(())
    }

    fn apply_change(&mut self, c: &Change) -> Result<(), ApiError> {
        if self.state.area(&c.area_id).is_none() {
            return Ok(());
        }
        match &c.node {
            Some(n) if !n.deleted && n.area_id == c.area_id => self.remote_upsert(n),
            _ => self.remote_gone(c.node_id, &c.area_id),
        }
    }

    fn remote_gone(&mut self, id: u64, area: &str) -> Result<(), ApiError> {
        let Some(e) = self.state.get(id).cloned() else { return Ok(()) };
        if e.area != area {
            return Ok(()); // inzwischen in einem anderen Bereich
        }
        if let Some(path) = self.path_of(id) {
            if let Some(l) = self.fs.stat(&path).map_err(io_err)? {
                if l.identity().is_some_and(|i| i.node == id) {
                    self.remove_local_tree(&path)?;
                }
            }
        }
        self.state.remove(id);
        Ok(())
    }

    fn remote_upsert(&mut self, n: &Node) -> Result<(), ApiError> {
        let Some(parent) = n.parent_id else { return Ok(()) };
        if self.state.get(parent).is_none() {
            self.needs_full = true;
            return Ok(());
        }
        if !names::is_valid_name(&n.name) {
            self.error("name_unsupported", &format!("„{}“ ist unter Windows kein gültiger Name", n.name), None);
            return Ok(());
        }
        let old = self.state.get(n.id).cloned();
        let old_path = self.path_of(n.id);
        let Some(dir) = self.path_of(parent) else { return Ok(()) };
        let new_path = dir.join(&n.name);
        if let (Some(_), Some(op)) = (&old, &old_path) {
            if op != &new_path {
                if let Some(l) = self.fs.stat(op).map_err(io_err)? {
                    if l.identity().is_some_and(|i| i.node == n.id) {
                        match self.fs.stat(&new_path).map_err(io_err)? {
                            None => self.fs.rename(op, &new_path).map_err(io_err)?,
                            Some(t) if same_path(op, &new_path) && t.identity().is_some_and(|i| i.node == n.id) => {
                                self.fs.rename(op, &new_path).map_err(io_err)?; // nur Groß/Klein
                            }
                            Some(_) => {
                                self.needs_full = true;
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
        self.state.upsert(Entry::from_node(n));
        let local = self.fs.stat(&new_path).map_err(io_err)?;
        if let Outcome::Descend = self.reconcile(&dir, n, old.as_ref(), local, false)? {
            if old.is_none() {
                // neuer (oder hereinverschobener) Ordner: Inhalt holen
                let (mut o, mut orph) = (Vec::new(), Vec::new());
                self.populate(n.id, false, &mut o, &mut orph)?;
                self.resolve_after_scan(o, orph)?;
            }
        }
        Ok(())
    }

    /// Lokal entfernen, was abgeglichen ist; Geändertes und Neues bleibt
    /// (als normale Datei) und wird später neu hochgeladen.
    fn remove_local_tree(&mut self, path: &Path) -> Result<bool, ApiError> {
        let Some(l) = self.fs.stat(path).map_err(io_err)? else { return Ok(true) };
        if !l.is_dir {
            if l.in_sync() {
                self.fs.remove_file(path).map_err(io_err)?;
                return Ok(true);
            }
            if l.placeholder.is_some() {
                self.fs.revert_placeholder(path).map_err(io_err)?;
            }
            self.queue.insert(path.to_path_buf());
            return Ok(false);
        }
        let mut all = true;
        for c in self.fs.list(path).map_err(io_err)? {
            all &= self.remove_local_tree(&path.join(&c.name))?;
        }
        if all {
            self.fs.remove_dir(path).map_err(io_err)?;
        } else if l.placeholder.is_some() {
            self.fs.revert_placeholder(path).map_err(io_err)?;
        }
        Ok(all)
    }

    // ───────────────────────── lokal → Server ─────────────────────────

    /// Pfad aus der Dateisystem-Beobachtung vormerken.
    pub fn queue_local(&mut self, path: PathBuf) {
        self.queue.insert(path);
        self.update_pending();
    }

    /// NOTIFY_DELETE (bereits bestätigt): Knoten in den Papierkorb, sobald der Pfad weg ist.
    pub fn note_deleted(&mut self, node: u64, path: PathBuf) {
        self.deletes.push((node, path));
        self.update_pending();
    }

    /// Alle vorgemerkten Pfade abarbeiten (Eltern vor Kindern).
    pub fn process_local(&mut self) -> Result<(), ApiError> {
        let retry = std::mem::take(&mut self.retry);
        self.queue.extend(retry);
        while let Some(path) = self.queue.pop_first() {
            self.update_pending();
            self.check_stop()?;
            match self.process_path(&path) {
                Ok(()) => {}
                Err(e) if e.code == "busy" => {
                    self.retry.insert(path);
                }
                Err(e) if e.transient() || e.code == "cancelled" => {
                    self.queue.insert(path);
                    self.update_pending();
                    return Err(e);
                }
                Err(e) => self.error(&e.code, &e.message, Some(&path)),
            }
        }
        let deletes = std::mem::take(&mut self.deletes);
        for (i, (node, path)) in deletes.iter().enumerate() {
            if let Err(e) = self.process_delete(*node, path) {
                if e.transient() {
                    self.deletes.extend(deletes[i..].iter().cloned());
                    self.update_pending();
                    return Err(e);
                }
                self.error(&e.code, &e.message, Some(path));
            }
        }
        self.update_pending();
        Ok(())
    }

    fn process_delete(&mut self, node: u64, path: &Path) -> Result<(), ApiError> {
        if let Some(l) = self.fs.stat(path).map_err(io_err)? {
            if l.identity().is_some_and(|i| i.node == node) {
                return Ok(()); // doch noch da
            }
        }
        let Some(e) = self.state.get(node).cloned() else { return Ok(()) };
        if !self.writable_area(&e.area) {
            self.needs_full = true; // wiederherstellen
            return Err(ApiError::new(Some(403), "read_only", "Nur Lesen – nicht gelöscht"));
        }
        match self.remote.trash(node) {
            Ok(()) => {}
            Err(err) if err.not_found() => {}
            Err(err) if err.forbidden() => {
                self.needs_full = true;
                return Err(err);
            }
            Err(err) => return Err(err),
        }
        self.state.remove(node);
        self.info(&format!("Gelöscht (Papierkorb): {}", path.display()));
        Ok(())
    }

    fn process_path(&mut self, path: &Path) -> Result<(), ApiError> {
        let Some(rel) = self.rel(path).map(Path::to_path_buf) else { return Ok(()) };
        let comps: Vec<String> = rel.iter().map(|c| c.to_string_lossy().to_string()).collect();
        let Some(name) = comps.last().cloned() else { return Ok(()) };
        let Some(l) = self.fs.stat(path).map_err(io_err)? else { return Ok(()) };
        if comps.len() == 1 {
            if self.state.area_by_dir(&name).is_none() && !names::is_ignored(&name) {
                self.error("outside_area", "Nur in den Ordnern der Bereiche wird abgeglichen", Some(path));
            }
            if l.is_dir {
                if let Some(a) = self.state.area_by_dir(&name).cloned() {
                    self.pin_dir(&a.root_id.clone());
                }
            }
            return Ok(());
        }
        if names::is_ignored(&name) {
            return Ok(());
        }
        if !names::is_valid_name(&name) {
            self.error("name_unsupported", "Name wird vom Server nicht angenommen", Some(path));
            return Ok(());
        }
        let parent_path = path.parent().unwrap_or(&self.cfg.root).to_path_buf();
        let Some(parent_id) = self.dir_id_for(&parent_path)? else { return Ok(()) };
        let area = self.state.get(parent_id).map(|e| e.area.clone()).unwrap_or_default();
        let writable = self.writable_area(&area);
        match l.identity().cloned() {
            Some(id) => match self.state.get(id.node).cloned() {
                Some(e) => {
                    let cur = self.path_of(e.id);
                    if cur.as_ref().is_none_or(|c| c.as_os_str() != path.as_os_str()) {
                        if !writable || !self.writable_area(&e.area) {
                            self.error("read_only", "Nur Lesen – Umbenennen/Verschieben nicht übertragen", Some(path));
                            return Ok(());
                        }
                        self.remote_move(&e, parent_id, &name, path)?;
                    }
                    if !l.is_dir && !l.in_sync() {
                        if !writable {
                            self.error("read_only", "Nur Lesen – Änderung nicht hochgeladen", Some(path));
                            return Ok(());
                        }
                        self.upload_version(path, &l, &id)?;
                    } else if l.is_dir {
                        if !l.in_sync() {
                            self.fs.set_in_sync(path, true).map_err(io_err)?;
                        }
                        self.pin_dir(&e.id);
                    } else {
                        self.apply_pin(path, &l);
                    }
                    self.clear_error(path);
                    Ok(())
                }
                None => {
                    // Platzhalter eines unbekannten Knotens: als neue Datei behandeln
                    let hydrated = l.placeholder.as_ref().is_some_and(|p| p.hydrated);
                    if !l.is_dir && !hydrated {
                        self.fs.remove_file(path).map_err(io_err)?;
                        return Ok(());
                    }
                    self.fs.revert_placeholder(path).map_err(io_err)?;
                    let l = self.fs.stat(path).map_err(io_err)?.unwrap_or(l);
                    self.new_local(path, parent_id, &name, &l, writable)
                }
            },
            None => self.new_local(path, parent_id, &name, &l, writable),
        }
    }

    fn new_local(&mut self, path: &Path, parent_id: u64, name: &str, l: &LocalEntry, writable: bool) -> Result<(), ApiError> {
        if !writable {
            self.error("read_only", "Nur Lesen – nicht hochgeladen", Some(path));
            return Ok(());
        }
        if l.is_dir {
            self.adopt_new_dir(path, parent_id, name)?;
        } else {
            self.upload_new(path, parent_id, name, l)?;
        }
        self.clear_error(path);
        Ok(())
    }

    /// ID des Server-Ordners für einen lokalen Ordner (legt ihn bei Bedarf an).
    fn dir_id_for(&mut self, dir: &Path) -> Result<Option<u64>, ApiError> {
        if same_path(dir, &self.cfg.root) {
            return Ok(None);
        }
        let Some(l) = self.fs.stat(dir).map_err(io_err)? else { return Ok(None) };
        if !l.is_dir {
            return Ok(None);
        }
        if let Some(i) = l.identity() {
            if self.state.get(i.node).is_some_and(|e| e.is_dir) {
                return Ok(Some(i.node));
            }
        }
        if let Some(id) = self.rel(dir).and_then(|r| self.state.lookup(r)) {
            if self.state.get(id).is_some_and(|e| e.is_dir) {
                return Ok(Some(id));
            }
        }
        // ein neuer lokaler Ordner: zuerst er
        let depth = self.rel(dir).map(|r| r.components().count()).unwrap_or(0);
        if depth < 2 {
            return Ok(None);
        }
        self.process_path(dir)?;
        Ok(self.fs.stat(dir).map_err(io_err)?.and_then(|l| l.identity().map(|i| i.node)).filter(|id| self.state.get(*id).is_some()))
    }

    fn adopt_new_dir(&mut self, path: &Path, parent_id: u64, name: &str) -> Result<(), ApiError> {
        let node = match self.remote.mkdir(parent_id, name) {
            Ok(n) => n,
            Err(e) if e.code == "exists" => match e
                .current
                .clone()
                .map(|b| *b)
                .or_else(|| self.list_all(parent_id).ok().and_then(|v| v.into_iter().find(|n| names::same_name(&n.name, name))))
            {
                Some(c) if c.is_dir => c,
                _ => {
                    // eine Datei dieses Namens auf dem Server: Ordner lokal umbenennen
                    let l = self.fs.stat(path).map_err(io_err)?.ok_or_else(|| ApiError::new(None, "local_io", "gone"))?;
                    self.set_aside(path, &l)?;
                    return Ok(());
                }
            },
            Err(e) => return Err(e),
        };
        self.fs.convert_to_placeholder(path, &ident(&Entry::from_node(&node))).map_err(io_err)?;
        self.state.upsert(Entry::from_node(&node));
        self.info(&format!("Ordner angelegt: {}", path.display()));
        for c in self.fs.list(path).map_err(io_err)? {
            self.queue.insert(path.join(c.name));
        }
        Ok(())
    }

    fn hash_file(&self, path: &Path) -> Result<(String, [u8; 32], u64), ApiError> {
        let mut r = self.fs.open_read(path).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(32) || e.raw_os_error() == Some(33) {
                ApiError::new(None, "busy", "file in use")
            } else {
                io_err(e)
            }
        })?;
        let size = r.len();
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        let mut off = 0u64;
        while off < size {
            let n = r.read_at(off, &mut buf).map_err(io_err)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            off += n as u64;
        }
        let sha: [u8; 32] = h.finalize().into();
        Ok((sha.iter().map(|b| format!("{b:02x}")).collect(), sha, size))
    }

    fn upload_media(&mut self, path: &Path, sha: &[u8; 32]) -> Result<String, ApiError> {
        let inner = self.fs.open_read(path).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                ApiError::new(None, "busy", "file in use")
            } else {
                io_err(e)
            }
        })?;
        let shared = self.shared.clone();
        let mut r = StopReader { inner, stop: &shared.stop };
        shared.transferring.fetch_add(1, Ordering::Relaxed);
        let res = self.remote.upload(&mut r, sha, &mut |_, _| {});
        shared.transferring.fetch_sub(1, Ordering::Relaxed);
        match res {
            Err(e) if shared.stop.load(Ordering::Relaxed) => Err(ApiError { code: "cancelled".into(), ..e }),
            Err(e) if e.code == "changed" => Err(ApiError::new(None, "busy", "file changed while uploading")),
            r => r,
        }
    }

    /// Nach dem Hochladen: Platzhalter, wenn die Datei unverändert ist, sonst noch einmal.
    fn finish_upload(&mut self, path: &Path, before: &LocalEntry, node: &Node, existing_placeholder: bool) -> Result<(), ApiError> {
        let e = Entry::from_node(node);
        self.state.upsert(e.clone());
        let now = self.fs.stat(path).map_err(io_err)?;
        let unchanged = now.as_ref().is_some_and(|n| n.size == before.size && n.mtime_ms == before.mtime_ms);
        if now.is_none() {
            return Ok(());
        }
        if existing_placeholder {
            self.fs.update_placeholder(path, &meta(&e), false).map_err(io_err)?;
        } else {
            self.fs.convert_to_placeholder(path, &ident(&e)).map_err(io_err)?;
        }
        if !unchanged {
            // währenddessen erneut geändert: als neue Fassung auf dieser Grundlage
            self.fs.set_in_sync(path, false).map_err(io_err)?;
            self.queue.insert(path.to_path_buf());
        }
        Ok(())
    }

    fn upload_new(&mut self, path: &Path, parent_id: u64, name: &str, l: &LocalEntry) -> Result<(), ApiError> {
        if l.size == 0 {
            // Der Server nimmt keine leeren Dateien an; sobald Inhalt da ist, geht sie hoch.
            return Ok(());
        }
        let (hex, sha, size) = self.hash_file(path)?;
        let chk = self.remote.check(parent_id, name, &hex, size)?;
        if chk.same {
            if let Some(n) = chk.node {
                self.state.upsert(Entry::from_node(&n));
                self.fs.convert_to_placeholder(path, &ident(&Entry::from_node(&n))).map_err(io_err)?;
                return Ok(());
            }
        }
        let media = self.upload_media(path, &sha)?;
        let req =
            CommitRequest { media_id: media, parent_id, name: name.to_string(), base_rev: None, mtime: Some(l.mtime_ms).filter(|m| *m > 0), on_conflict: None };
        match self.remote.commit(&req) {
            Ok(node) => {
                self.info(&format!("Hochgeladen: {}", path.display()));
                self.finish_upload(path, l, &node, false)
            }
            Err(e) if e.status == Some(409) => self.commit_as_conflict(path, l, req, e.current.map(|b| *b), false),
            Err(e) => Err(e),
        }
    }

    /// Der Name ist auf dem Server belegt: lokale Fassung als Konfliktkopie
    /// hochladen, die Server-Fassung bekommt den Namen.
    fn commit_as_conflict(
        &mut self,
        path: &Path,
        l: &LocalEntry,
        mut req: CommitRequest,
        current: Option<Node>,
        was_placeholder: bool,
    ) -> Result<(), ApiError> {
        let dir = path.parent().unwrap_or(&self.cfg.root).to_path_buf();
        if was_placeholder {
            self.fs.revert_placeholder(path).map_err(io_err)?;
        }
        let cname = self.free_conflict_name(&dir, &l.name);
        let cpath = dir.join(&cname);
        self.fs.rename(path, &cpath).map_err(io_err)?;
        req.name = cname;
        req.base_rev = None;
        req.on_conflict = Some("rename".into());
        let node = self.remote.commit(&req)?;
        let mut final_path = cpath.clone();
        if !names::same_name(&node.name, &req.name) || node.name != req.name {
            final_path = dir.join(&node.name);
            self.fs.rename(&cpath, &final_path).map_err(io_err)?;
        }
        let before = LocalEntry { name: node.name.clone(), ..l.clone() };
        self.finish_upload(&final_path, &before, &node, false)?;
        self.info(&format!("Konflikt: lokale Fassung als {}", final_path.display()));
        match current {
            Some(cur) if !cur.deleted => {
                let e = Entry::from_node(&cur);
                self.state.upsert(e.clone());
                if self.fs.stat(path).map_err(io_err)?.is_none() {
                    self.fs.create_placeholder(&dir, &cur.name, &meta(&e)).map_err(io_err)?;
                }
            }
            _ => self.needs_full = true,
        }
        Ok(())
    }

    fn upload_version(&mut self, path: &Path, l: &LocalEntry, id: &Identity) -> Result<(), ApiError> {
        let Some(e) = self.state.get(id.node).cloned() else { return Ok(()) };
        let (hex, sha, size) = self.hash_file(path)?;
        if size == 0 {
            self.error("empty_file", "Leere Dateien werden nicht hochgeladen", Some(path));
            return Ok(());
        }
        if e.sha256.as_deref() == Some(hex.as_str()) && e.size == size {
            self.fs.update_placeholder(path, &meta(&e), false).map_err(io_err)?;
            return Ok(());
        }
        let media = self.upload_media(path, &sha)?;
        // Konflikt nur, wenn sich der Inhalt auf dem Server seit unserer Fassung geändert hat.
        let base = if e.media == id.media { e.rev } else { id.rev };
        let req = CommitRequest {
            media_id: media,
            parent_id: e.parent,
            name: e.name.clone(),
            base_rev: Some(base),
            mtime: Some(l.mtime_ms).filter(|m| *m > 0),
            on_conflict: None,
        };
        match self.remote.commit(&req) {
            Ok(node) => {
                self.info(&format!("Neue Fassung hochgeladen: {}", path.display()));
                self.finish_upload(path, l, &node, true)
            }
            Err(err) if err.status == Some(409) => self.commit_as_conflict(path, l, req, err.current.map(|b| *b), true),
            Err(err) => Err(err),
        }
    }

    fn remote_move(&mut self, e: &Entry, parent_id: u64, name: &str, path: &Path) -> Result<(), ApiError> {
        let name_arg = (e.name != name).then_some(name);
        let parent_arg = (e.parent != parent_id).then_some(parent_id);
        if name_arg.is_none() && parent_arg.is_none() {
            return Ok(());
        }
        match self.remote.update_node(e.id, name_arg, parent_arg) {
            Ok(node) => {
                let ne = Entry::from_node(&node);
                self.state.upsert(ne.clone());
                self.fs.update_placeholder(path, &meta(&ne), false).map_err(io_err)?;
                self.info(&format!("Verschoben/umbenannt: {}", path.display()));
                Ok(())
            }
            Err(err) if err.code == "exists" => {
                // Ziel auf dem Server belegt: lokal einen freien Namen nehmen und noch einmal
                let dir = path.parent().unwrap_or(&self.cfg.root).to_path_buf();
                let c = self.free_conflict_name(&dir, name);
                let to = dir.join(&c);
                self.fs.rename(path, &to).map_err(io_err)?;
                let node = self.remote.update_node(e.id, Some(&c), parent_arg)?;
                let ne = Entry::from_node(&node);
                self.state.upsert(ne.clone());
                self.fs.update_placeholder(&to, &meta(&ne), false).map_err(io_err)?;
                Ok(())
            }
            Err(err) if err.forbidden() => {
                if let Some(back) = self.path_of(e.id) {
                    if self.fs.stat(&back).map_err(io_err)?.is_none() {
                        let _ = self.fs.rename(path, &back);
                    }
                }
                Err(err)
            }
            Err(err) if err.not_found() => {
                self.needs_full = true;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    // ───────────────────────── Pin-Zustände ─────────────────────────

    fn effective_pin(&self, path: &Path, own: Pin) -> Pin {
        if matches!(own, Pin::Pinned | Pin::Unpinned) {
            return own;
        }
        let mut cur = path.parent();
        while let Some(p) = cur {
            if same_path(p, &self.cfg.root) || self.rel(p).is_none() {
                break;
            }
            match self.fs.stat(p).ok().flatten().and_then(|l| l.placeholder.map(|ph| ph.pin)) {
                Some(Pin::Pinned) => return Pin::Pinned,
                Some(Pin::Unpinned) => return Pin::Unpinned,
                _ => {}
            }
            cur = p.parent();
        }
        Pin::Unspecified
    }

    /// „Immer auf diesem Gerät behalten“ → laden; „Speicher freigeben“ → dehydrieren.
    fn apply_pin(&mut self, path: &Path, l: &LocalEntry) {
        let Some(ph) = &l.placeholder else { return };
        if l.is_dir {
            return;
        }
        match self.effective_pin(path, ph.pin) {
            Pin::Pinned if !ph.hydrated => {
                if let Err(e) = self.fs.hydrate(path) {
                    self.error("hydrate", &e.to_string(), Some(path));
                }
            }
            Pin::Unpinned if ph.hydrated && ph.in_sync && l.size > 0 => {
                if let Err(e) = self.fs.dehydrate(path) {
                    self.error("dehydrate", &e.to_string(), Some(path));
                }
            }
            _ => {}
        }
    }

    /// Ein Ordner wurde angeheftet/freigegeben: alle Dateien darunter prüfen.
    fn pin_dir(&mut self, id: &u64) {
        let Some(path) = self.path_of(*id) else { return };
        let pin = self.fs.stat(&path).ok().flatten().and_then(|l| l.placeholder.map(|p| p.pin)).unwrap_or_default();
        if !matches!(pin, Pin::Pinned | Pin::Unpinned) {
            return;
        }
        for d in self.state.descendants(*id) {
            if let (Some(e), Some(p)) = (self.state.get(d).cloned(), self.path_of(d)) {
                if !e.is_dir {
                    if let Ok(Some(l)) = self.fs.stat(&p) {
                        self.apply_pin(&p, &l);
                    }
                }
            }
        }
    }

    // ───────────────────────── Abmelden ─────────────────────────

    /// Vor dem Abmelden des Sync-Roots: nur-online-Platzhalter entfernen,
    /// geladene und geänderte Dateien als normale Dateien behalten.
    pub fn detach_all(&mut self) -> Result<(), ApiError> {
        for a in self.state.areas.clone() {
            let path = self.cfg.root.join(&a.dir);
            self.detach(&path)?;
        }
        self.state = State::new(&self.state.account);
        self.publish_roles();
        Ok(())
    }

    fn detach(&mut self, path: &Path) -> Result<(), ApiError> {
        let Some(l) = self.fs.stat(path).map_err(io_err)? else { return Ok(()) };
        if l.is_dir {
            for c in self.fs.list(path).map_err(io_err)? {
                self.detach(&path.join(&c.name))?;
            }
            if self.fs.list(path).map_err(io_err)?.is_empty() {
                self.fs.remove_dir(path).map_err(io_err)?;
            } else if l.placeholder.is_some() {
                self.fs.revert_placeholder(path).map_err(io_err)?;
            }
            return Ok(());
        }
        match &l.placeholder {
            Some(ph) if !ph.hydrated && ph.in_sync => self.fs.remove_file(path).map_err(io_err),
            Some(_) => self.fs.revert_placeholder(path).map_err(io_err),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
