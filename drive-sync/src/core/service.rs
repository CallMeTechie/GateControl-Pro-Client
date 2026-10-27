//! Der Dienst hinter der Pipe: Befehle des Pro-Clients (configure, start,
//! stop, pause, …), der Abgleich-Thread, die Rückrufe der Cloud Files API und
//! der Status. Plattformunabhängig – Windows liefert über `Platform` den
//! Sync-Root, die Platzhalter, die Rückrufe und die Dateisystem-Beobachtung.

use super::api::ApiClient;
use super::engine::{Engine, EngineConfig, Shared};
use super::hydrate::{self, FetchRequest, TransferSink};
use super::identity::Identity;
use super::localfs::LocalFs;
use super::protocol::{self, Command, Config, KnownFolder, ProtoError, Status, StatusError};
use super::relocate::{self, KnownFolders};
use super::remote::{ApiError, Remote};
use super::state::State;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Abstand der Abfragen `changes?since=` (zusätzlich: `sync-now` über die Pipe).
pub const POLL_INTERVAL: Duration = Duration::from_secs(45);
/// Eine lokale Änderung gilt als fertig, wenn so lange nichts mehr kam.
pub const SETTLE: Duration = Duration::from_secs(2);
const FETCH_WORKERS: usize = 4;

/// Ereignis der Dateisystem-Beobachtung.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchEvent {
    Changed(PathBuf),
    /// Zu viele Ereignisse – alles neu vergleichen.
    Overflow,
}

/// Rückrufe der Cloud Files API (aus deren Threads).
pub trait Callbacks: Send + Sync {
    /// FETCH_DATA: im Hintergrund laden, `sink` meldet an Windows.
    fn fetch_data(&self, key: i64, req: FetchRequest, sink: Box<dyn TransferSink + Send>);
    fn cancel_fetch(&self, key: i64);
    /// NOTIFY_DELETE → erlauben?
    fn notify_delete(&self, identity: Option<Identity>, path: PathBuf) -> bool;
    /// NOTIFY_RENAME (`to`: `None`, wenn das Ziel außerhalb des Sync-Roots liegt) → erlauben?
    fn notify_rename(&self, identity: Option<Identity>, from: PathBuf, to: Option<PathBuf>) -> bool;
}

pub type Guard = Box<dyn Any + Send>;

pub trait Platform: Send + Sync + 'static {
    fn sync_root(&self) -> PathBuf;
    fn data_dir(&self) -> PathBuf;
    /// Sync-Root registrieren (idempotent), Ordner anlegen.
    fn register(&self) -> Result<(), String>;
    fn unregister(&self) -> Result<(), String>;
    fn is_registered(&self) -> bool;
    fn fs(&self) -> Arc<dyn LocalFs>;
    /// CfConnectSyncRoot; Trennen beim Fallenlassen des Guards.
    fn connect(&self, cb: Arc<dyn Callbacks>) -> Result<Guard, String>;
    fn watch(&self, on_event: Box<dyn Fn(WatchEvent) + Send + Sync>) -> Result<Guard, String>;
    /// Windows-Ordner (Desktop, Dokumente, …) – `None`: nicht unterstützt.
    fn known(&self) -> Option<Arc<dyn KnownFolders>> {
        None
    }
    /// Läuft das Programm mit Administratorrechten?
    fn elevated(&self) -> bool {
        false
    }
    /// Explorer-Kontextmenü (Link teilen, Im Portal öffnen, Ältere Versionen) an/aus.
    fn context_menu(&self, _on: bool, _app_exe: Option<&str>, _lang: Option<&str>) -> Result<(), String> {
        Ok(())
    }
    /// Dem Explorer Änderungen an Ordnern melden (nach dem Verlegen).
    fn notify_shell(&self, _paths: &[PathBuf]) {}
}

/// Auftrag, der im Abgleich-Thread läuft (zwischen zwei Durchläufen).
pub type EngineJob = Box<dyn FnOnce(&mut Engine) -> Result<Value, ProtoError> + Send>;

pub type RemoteFactory = Box<dyn Fn(&Config) -> Result<Arc<dyn Remote>, ApiError> + Send + Sync>;

/// Standard: HTTP-Client.
pub fn http_remote() -> RemoteFactory {
    Box::new(|c: &Config| Ok(Arc::new(ApiClient::new(&c.server_url, &c.token, c.headers.clone())?) as Arc<dyn Remote>))
}

enum Msg {
    Job(EngineJob, Sender<Result<Value, ProtoError>>),
    SyncNow,
    Pause(bool),
    Local(PathBuf),
    Deleted(u64, PathBuf),
    Overflow,
    Stop,
}

type EventSink = Arc<dyn Fn(String) + Send + Sync>;

struct RunState {
    state: String,
    errors: Vec<StatusError>,
    last_sync: Option<String>,
}

struct Runner {
    tx: Sender<Msg>,
    handle: Option<JoinHandle<()>>,
    shared: Arc<Shared>,
    run: Arc<Mutex<RunState>>,
    _guards: Vec<Guard>,
    fetch: Arc<FetchPool>,
}

struct Inner {
    config: Option<Config>,
    runner: Option<Runner>,
    paused: bool,
    /// Pro-Client-Exe und Sprache (aus `hello`), für das Kontextmenü.
    app_exe: Option<String>,
    lang: Option<String>,
}

pub struct Service<P: Platform> {
    platform: Arc<P>,
    remote_factory: RemoteFactory,
    inner: Mutex<Inner>,
    events: Mutex<Option<EventSink>>,
    pub quit: AtomicBool,
    log_file: Option<PathBuf>,
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn hash16(s: &str) -> String {
    Sha256::digest(s.as_bytes()).iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Zustandsdatei je Server.
pub fn state_file(data_dir: &Path, server_url: &str) -> PathBuf {
    data_dir.join(format!("state-{}.json", hash16(&server_url.to_lowercase())))
}

impl<P: Platform> Service<P> {
    pub fn new(platform: Arc<P>, remote_factory: RemoteFactory) -> Arc<Self> {
        let log_file = Some(platform.data_dir().join("drive-sync.log"));
        Arc::new(Service {
            platform,
            remote_factory,
            inner: Mutex::new(Inner { config: None, runner: None, paused: false, app_exe: None, lang: None }),
            events: Mutex::new(None),
            quit: AtomicBool::new(false),
            log_file,
        })
    }

    /// Ziel der Ereignisse (`status`, `log`) – die gerade verbundene Pipe oder keins.
    pub fn set_event_sink(&self, sink: Option<EventSink>) {
        *self.events.lock().unwrap() = sink;
    }

    /// Eine Zeile an den verbundenen Pro-Client (Ereignis).
    pub fn emit(&self, line: String) {
        let sink = self.events.lock().unwrap().clone();
        if let Some(s) = sink {
            s(line);
        }
    }

    pub fn log(&self, level: &str, msg: &str) {
        let at = now_iso();
        if let Some(f) = &self.log_file {
            write_log_file(f, &format!("{at} {level} {msg}\n"));
        }
        self.emit(protocol::log_event(level, msg, &at));
    }

    pub fn status(&self) -> Status {
        let inner = self.inner.lock().unwrap();
        let mut s = Status {
            sync_root: Some(self.platform.sync_root().to_string_lossy().to_string()),
            registered: self.platform.is_registered(),
            elevated: self.platform.elevated(),
            ..Default::default()
        };
        match &inner.runner {
            None => s.state = if inner.config.is_some() { "stopped".into() } else { "unconfigured".into() },
            Some(r) => {
                let run = r.run.lock().unwrap();
                s.state = if inner.paused { "paused".into() } else { run.state.clone() };
                s.errors = run.errors.clone();
                s.last_sync = run.last_sync.clone();
                s.pending = r.shared.pending.load(Ordering::Relaxed);
                s.transferring = r.shared.transferring.load(Ordering::Relaxed) + r.fetch.active();
                s.mass_delete = r.shared.held.read().ok().and_then(|h| h.clone());
            }
        }
        s
    }

    fn publish(&self) {
        self.emit(protocol::status_event(&self.status()));
    }

    /// Eine Anfrage → Ergebnis (wird zur Antwortzeile).
    pub fn handle(self: &Arc<Self>, cmd: Command) -> Result<Value, ProtoError> {
        match cmd {
            Command::Hello { version, app_exe, lang } => {
                if let Some(v) = version {
                    self.log("info", &format!("Pro-Client {v} verbunden"));
                }
                let mut inner = self.inner.lock().unwrap();
                if app_exe.is_some() {
                    inner.app_exe = app_exe;
                }
                if lang.is_some() {
                    inner.lang = lang;
                }
                drop(inner);
                Ok(json!({
                    "protocol": protocol::PROTOCOL_VERSION,
                    "version": env!("CARGO_PKG_VERSION"),
                    "pid": std::process::id(),
                    "syncRoot": self.platform.sync_root().to_string_lossy(),
                    "state": self.status().state,
                    "elevated": self.platform.elevated(),
                    "knownFolders": self.platform.known().is_some(),
                }))
            }
            Command::Configure(c) => {
                let restart = {
                    let mut inner = self.inner.lock().unwrap();
                    let changed = inner.config.as_ref() != Some(&c);
                    inner.config = Some(c);
                    changed && inner.runner.is_some()
                };
                if restart {
                    self.stop_runner();
                    self.start()?;
                }
                Ok(json!({ "configured": true }))
            }
            Command::Start => {
                self.start()?;
                Ok(serde_json::to_value(self.status()).unwrap_or(Value::Null))
            }
            Command::Stop => {
                self.stop_runner();
                self.publish();
                Ok(json!({ "stopped": true }))
            }
            Command::Pause | Command::Resume => {
                let p = matches!(cmd, Command::Pause);
                let mut inner = self.inner.lock().unwrap();
                inner.paused = p;
                if let Some(r) = &inner.runner {
                    let _ = r.tx.send(Msg::Pause(p));
                }
                drop(inner);
                self.publish();
                Ok(json!({ "paused": p }))
            }
            Command::Status => Ok(serde_json::to_value(self.status()).unwrap_or(Value::Null)),
            Command::SyncNow => {
                let inner = self.inner.lock().unwrap();
                match &inner.runner {
                    Some(r) => {
                        let _ = r.tx.send(Msg::SyncNow);
                        Ok(json!({ "queued": true }))
                    }
                    None => Err(ProtoError::new("not_running", "not started")),
                }
            }
            Command::Unregister { force } => {
                self.unregister_checked(force)?;
                Ok(json!({ "unregistered": true }))
            }
            Command::Deletes { apply } => {
                let n = self.run_job(Box::new(move |eng: &mut Engine| {
                    eng.decide_deletes(apply).map(|n| json!(n)).map_err(|e| ProtoError::new("failed", e.to_string()))
                }))?;
                self.publish();
                Ok(json!({ "decided": n, "apply": apply }))
            }
            Command::KnownFolders => {
                let known = self.platform.known().ok_or(ProtoError::new("unsupported", "known folders"))?;
                Ok(relocate::list(known.as_ref(), &self.platform.sync_root(), &self.platform.data_dir()))
            }
            Command::Relocate { folder, name } => self.relocate(folder, name),
            Command::Restore { folder } => self.restore(folder),
            Command::Usage => Ok(relocate::usage(self.platform.fs().as_ref(), &self.platform.sync_root())),
            Command::Shutdown => {
                self.stop_runner();
                self.quit.store(true, Ordering::SeqCst);
                Ok(json!({ "shutdown": true }))
            }
        }
    }

    fn start(self: &Arc<Self>) -> Result<(), ProtoError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.runner.is_some() {
            return Ok(());
        }
        let config = inner.config.clone().ok_or(ProtoError::new("not_configured", "configure first"))?;
        let remote = (self.remote_factory)(&config).map_err(|e| ProtoError::new("client", e.to_string()))?;
        self.platform.register().map_err(|e| ProtoError::new("register_failed", e))?;
        if let Err(e) = self.platform.context_menu(true, inner.app_exe.as_deref(), inner.lang.as_deref()) {
            self.log("warn", &format!("Kontextmenü: {e}"));
        }
        let shared = Arc::new(Shared::default());
        let (tx, rx) = mpsc::channel::<Msg>();
        let lg = Arc::downgrade(self);
        let fetch = FetchPool::new(
            remote.clone(),
            FETCH_WORKERS,
            Arc::new(move |lvl: &str, msg: &str| {
                if let Some(s) = lg.upgrade() {
                    s.log(lvl, msg);
                }
            }),
        );
        let root = self.platform.sync_root();
        let cb = Arc::new(Handler { shared: shared.clone(), tx: Mutex::new(tx.clone()), fetch: fetch.clone(), root: root.clone() });
        let conn = self.platform.connect(cb).map_err(|e| ProtoError::new("connect_failed", e))?;
        let wtx = Mutex::new(tx.clone());
        let watcher = self
            .platform
            .watch(Box::new(move |ev| {
                let m = match ev {
                    WatchEvent::Changed(p) => Msg::Local(p),
                    WatchEvent::Overflow => Msg::Overflow,
                };
                let _ = wtx.lock().unwrap().send(m);
            }))
            .map_err(|e| ProtoError::new("watch_failed", e))?;
        let run = Arc::new(Mutex::new(RunState { state: "starting".into(), errors: vec![], last_sync: None }));
        let svc = Arc::downgrade(self);
        let paused = inner.paused;
        let (sh, rn, fs, data_dir) = (shared.clone(), run.clone(), self.platform.fs(), self.platform.data_dir());
        let handle = std::thread::Builder::new()
            .name("drive-sync-engine".into())
            .spawn(move || run_loop(svc, rx, remote, fs, sh, rn, config, root, data_dir, paused))
            .map_err(|e| ProtoError::new("thread", e.to_string()))?;
        inner.runner = Some(Runner { tx, handle: Some(handle), shared, run, _guards: vec![conn, watcher], fetch });
        drop(inner);
        self.log("info", "Abgleich gestartet");
        self.publish();
        Ok(())
    }

    /// Abgleich anhalten, Sync-Root trennen (Platzhalter bleiben).
    pub fn stop_runner(&self) {
        let runner = self.inner.lock().unwrap().runner.take();
        if let Some(mut r) = runner {
            r.shared.stop.store(true, Ordering::SeqCst);
            let _ = r.tx.send(Msg::Stop);
            if let Some(h) = r.handle.take() {
                let _ = h.join();
            }
            r.fetch.shutdown();
            drop(r); // Guards: Beobachtung beenden, CfDisconnectSyncRoot
            self.log("info", "Abgleich beendet");
        }
    }

    /// Einen Auftrag im Abgleich-Thread ausführen und auf das Ergebnis warten.
    pub fn run_job(&self, job: EngineJob) -> Result<Value, ProtoError> {
        let rx = {
            let inner = self.inner.lock().unwrap();
            let r = inner.runner.as_ref().ok_or(ProtoError::new("not_running", "not started"))?;
            let (tx, rx) = mpsc::channel();
            r.tx.send(Msg::Job(job, tx)).map_err(|_| ProtoError::new("not_running", "stopped"))?;
            rx
        };
        rx.recv().unwrap_or_else(|_| Err(ProtoError::new("cancelled", "stopped")))
    }

    fn progress_fn(self: &Arc<Self>, op: &'static str, folder: Option<&'static str>) -> impl Fn(&str, u64, u64) + Send + 'static {
        let w = Arc::downgrade(self);
        let last = Mutex::new(Instant::now() - Duration::from_secs(1));
        move |phase: &str, done: u64, total: u64| {
            let mut l = last.lock().unwrap();
            if done < total && l.elapsed() < Duration::from_millis(250) {
                return;
            }
            *l = Instant::now();
            if let Some(s) = w.upgrade() {
                s.emit(protocol::progress_event(op, folder, phase, done, total));
            }
        }
    }

    fn device_name(&self) -> String {
        self.inner.lock().unwrap().config.as_ref().map(|c| c.device_name.clone()).unwrap_or_else(|| "PC".into())
    }

    fn relocate(self: &Arc<Self>, folder: KnownFolder, name: Option<String>) -> Result<Value, ProtoError> {
        let known = self.platform.known().ok_or(ProtoError::new("unsupported", "known folders"))?;
        let (data, device, plat) = (self.platform.data_dir(), self.device_name(), self.platform.clone());
        let progress = self.progress_fn("relocate", Some(folder.key()));
        self.log("info", &format!("Windows-Ordner {} wird in den Drive verlegt", folder.key()));
        let r = self.run_job(Box::new(move |eng: &mut Engine| {
            let args = relocate::RelocateArgs { known: known.as_ref(), data_dir: &data, folder, name, device: &device };
            let r = relocate::relocate(eng, args, &progress)?;
            plat.notify_shell(&[PathBuf::from(r["from"].as_str().unwrap_or_default()), PathBuf::from(r["to"].as_str().unwrap_or_default())]);
            Ok(r)
        }));
        self.after_folder_job("verlegt", &r);
        r
    }

    fn restore(self: &Arc<Self>, folder: KnownFolder) -> Result<Value, ProtoError> {
        let known = self.platform.known().ok_or(ProtoError::new("unsupported", "known folders"))?;
        let (data, device, plat) = (self.platform.data_dir(), self.device_name(), self.platform.clone());
        let progress = self.progress_fn("restore", Some(folder.key()));
        self.log("info", &format!("Windows-Ordner {} wird zurückgelegt", folder.key()));
        let r = self.run_job(Box::new(move |eng: &mut Engine| {
            let r = relocate::restore(eng, known.as_ref(), &data, folder, &device, &progress)?;
            plat.notify_shell(&[PathBuf::from(r["from"].as_str().unwrap_or_default()), PathBuf::from(r["to"].as_str().unwrap_or_default())]);
            Ok(r)
        }));
        self.after_folder_job("zurückgelegt", &r);
        r
    }

    fn after_folder_job(&self, what: &str, r: &Result<Value, ProtoError>) {
        match r {
            Ok(v) => self.log("info", &format!("{} {what}: {} → {} ({} Einträge)", v["folder"], v["from"], v["to"], v["moved"])),
            Err(e) => self.log("warn", &format!("Nicht {what}: {} {}", e.code, e.message)),
        }
        self.publish();
    }

    /// Explorer-Kontextmenü (über die Aktions-Pipe): `share` | `portal` |
    /// `versions` für einen Pfad im Sync-Root → Ereignis `action` an den
    /// Pro-Client (mit Knoten-ID aus dem Platzhalter). → zugestellt?
    pub fn handle_action(&self, action: &str, path: &Path) -> Result<bool, String> {
        let Some(action) = protocol::ACTIONS.iter().find(|a| **a == action) else { return Err("unknown action".into()) };
        let root = self.platform.sync_root();
        if !relocate::is_under(path, &root) || path.strip_prefix(&root).map(|r| r.as_os_str().is_empty()).unwrap_or(true) {
            return Err("not in the sync root".into());
        }
        let l = self.platform.fs().stat(path).map_err(|e| e.to_string())?.ok_or("not found")?;
        let id = l.identity().cloned();
        let delivered = self.events.lock().unwrap().is_some();
        self.emit(protocol::action_event(action, &path.to_string_lossy(), id.as_ref().map(|i| i.node), id.as_ref().map(|i| i.area.as_str()), l.is_dir));
        self.log("info", &format!("Kontextmenü: {action} {}", path.display()));
        Ok(delivered)
    }

    /// Windows-Ordner, die gerade im Drive liegen.
    fn relocated(&self) -> Vec<&'static str> {
        let Some(k) = self.platform.known() else { return vec![] };
        let root = self.platform.sync_root();
        KnownFolder::ALL.into_iter().filter(|f| k.get(*f).is_ok_and(|p| relocate::is_under(&p, &root))).map(KnownFolder::key).collect()
    }

    /// Abmelden über die Pipe: zuerst prüfen, dass nichts verloren geht.
    ///   * verlegte Windows-Ordner → Fehler `relocated` (erst zurücklegen);
    ///   * ausstehende Änderungen hochladen; bleibt etwas übrig → Fehler
    ///     `unsynced` mit Anzahl und Pfaden – außer `force` (dann bleiben diese
    ///     Dateien als normale Dateien im Ordner);
    ///   * nicht vollständig geladene, aber geänderte Platzhalter vorher laden.
    pub fn unregister_checked(&self, force: bool) -> Result<(), ProtoError> {
        let rel = self.relocated();
        if !rel.is_empty() {
            return Err(ProtoError::new("relocated", "Windows-Ordner liegen im Drive – zuerst zurücklegen").with_data(json!({ "folders": rel })));
        }
        let running = self.inner.lock().unwrap().runner.is_some();
        let check = move |eng: &mut Engine| -> Result<Value, ProtoError> {
            if eng.state.areas.is_empty() {
                return Ok(json!({ "count": 0, "paths": [] }));
            }
            let _ = eng.process_local();
            let (count, paths) = eng.unsynced(20);
            if count > 0 && !force {
                let p: Vec<String> = paths.iter().map(|p| p.to_string_lossy().to_string()).collect();
                return Err(
                    ProtoError::new("unsynced", format!("{count} Änderungen sind noch nicht hochgeladen")).with_data(json!({ "count": count, "paths": p }))
                );
            }
            if force {
                // geänderte, aber nicht vollständig geladene Dateien: laden, damit sie vollständig bleiben
                let fs = eng.fs();
                for p in eng.not_hydrated(&eng.cfg.root.clone()) {
                    if fs.stat(&p).ok().flatten().is_some_and(|l| !l.in_sync()) {
                        let _ = fs.hydrate_now(&p);
                    }
                }
            }
            Ok(json!({ "count": count }))
        };
        if running {
            match self.run_job(Box::new(check)) {
                Ok(_) => {}
                // Server nie erreicht (keine Engine): wie ohne Abgleich prüfen
                Err(e) if e.code == "offline" => self.check_offline(force)?,
                Err(e) => return Err(e),
            }
        } else {
            self.check_offline(force)?;
        }
        self.unregister()
    }

    /// Ohne laufenden Abgleich: nur prüfen, ob lokal etwas aussteht.
    fn check_offline(&self, force: bool) -> Result<(), ProtoError> {
        if force {
            return Ok(());
        }
        let mut count = 0;
        let mut paths = Vec::new();
        for st in self.state_files() {
            let eng = Engine::new(
                EngineConfig { root: self.platform.sync_root(), device_name: String::new() },
                Arc::new(NoRemote),
                self.platform.fs(),
                load_any_state(&st),
                Arc::new(Shared::default()),
            );
            let (c, p) = eng.unsynced(20);
            count += c;
            paths.extend(p.into_iter().map(|p| p.to_string_lossy().to_string()));
        }
        if count > 0 {
            return Err(
                ProtoError::new("unsynced", format!("{count} Änderungen sind noch nicht hochgeladen")).with_data(json!({ "count": count, "paths": paths }))
            );
        }
        Ok(())
    }

    fn state_files(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.platform.data_dir())
            .map(|d| {
                d.filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("state-") && n.ends_with(".json")))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Platzhalter „nur online“ entfernen, Geladenes behalten, Sync-Root abmelden, Zustand löschen.
    /// (Deinstallation: ohne Rückfrage; über die Pipe: `unregister_checked`.)
    pub fn unregister(&self) -> Result<(), ProtoError> {
        self.stop_runner();
        let fs = self.platform.fs();
        if let Err(e) = self.platform.context_menu(false, None, None) {
            self.log("warn", &format!("Kontextmenü entfernen: {e}"));
        }
        if self.platform.is_registered() {
            let states = self.state_files();
            for sf in &states {
                let st = load_any_state(sf);
                let mut eng = Engine::new(
                    EngineConfig { root: self.platform.sync_root(), device_name: String::new() },
                    Arc::new(NoRemote),
                    fs.clone(),
                    st,
                    Arc::new(Shared::default()),
                );
                if let Err(e) = eng.detach_all() {
                    self.log("warn", &format!("Aufräumen: {e}"));
                }
            }
            self.platform.unregister().map_err(|e| ProtoError::new("unregister_failed", e))?;
            for sf in states {
                let _ = std::fs::remove_file(sf);
            }
        }
        self.log("info", "Sync-Root abgemeldet");
        self.publish();
        Ok(())
    }

    /// Eine Pipe-Verbindung bedienen, bis sie endet (oder `shutdown`).
    pub fn serve<R: BufRead, W: Write + Send + 'static>(self: &Arc<Self>, reader: R, writer: W) {
        let w = Arc::new(Mutex::new(writer));
        let wl = w.clone();
        self.set_event_sink(Some(Arc::new(move |line: String| {
            if let Ok(mut g) = wl.lock() {
                let _ = writeln!(g, "{line}");
                let _ = g.flush();
            }
        })));
        for line in reader.lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            let out = match protocol::parse_request(&line) {
                Ok(req) if is_slow(&req.cmd) => {
                    // lange Befehle im eigenen Thread: Status-Abfragen laufen weiter
                    let (svc, w2) = (self.clone(), w.clone());
                    std::thread::spawn(move || {
                        let out = match svc.handle(req.cmd) {
                            Ok(v) => protocol::ok_line(&req.id, v),
                            Err(e) => protocol::err_line(&req.id, &e),
                        };
                        if let Ok(mut g) = w2.lock() {
                            let _ = writeln!(g, "{out}").and_then(|_| g.flush());
                        }
                    });
                    continue;
                }
                Ok(req) => match self.handle(req.cmd) {
                    Ok(v) => protocol::ok_line(&req.id, v),
                    Err(e) => protocol::err_line(&req.id, &e),
                },
                Err((id, e)) => protocol::err_line(&id, &e),
            };
            if let Ok(mut g) = w.lock() {
                if writeln!(g, "{out}").and_then(|_| g.flush()).is_err() {
                    break;
                }
            }
            if self.quit.load(Ordering::SeqCst) {
                break;
            }
        }
        self.set_event_sink(None);
    }
}

fn is_slow(c: &Command) -> bool {
    matches!(
        c,
        Command::Unregister { .. } | Command::Deletes { .. } | Command::Relocate { .. } | Command::Restore { .. } | Command::Usage | Command::KnownFolders
    )
}

fn write_log_file(path: &Path, line: &str) {
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if std::fs::metadata(path).map(|m| m.len() > 1024 * 1024).unwrap_or(false) {
        let _ = std::fs::rename(path, path.with_extension("log.1"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
    }
}

fn load_any_state(path: &Path) -> State {
    let account = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.get("account").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default();
    State::load(path, &account)
}

/// Für das Abmelden ohne Server.
struct NoRemote;

impl Remote for NoRemote {
    fn me(&self) -> Result<super::model::MeAnswer, ApiError> {
        Err(ApiError::network("offline"))
    }
    fn areas(&self) -> Result<Vec<super::model::Area>, ApiError> {
        Err(ApiError::network("offline"))
    }
    fn node(&self, _: u64) -> Result<super::model::Node, ApiError> {
        Err(ApiError::network("offline"))
    }
    fn children(&self, _: u64, _: u64) -> Result<super::model::ChildrenPage, ApiError> {
        Err(ApiError::network("offline"))
    }
    fn changes(&self, _: u64) -> Result<super::model::ChangesPage, ApiError> {
        Err(ApiError::network("offline"))
    }
    fn mkdir(&self, _: u64, _: &str) -> Result<super::model::Node, ApiError> {
        Err(ApiError::network("offline"))
    }
    fn update_node(&self, _: u64, _: Option<&str>, _: Option<u64>) -> Result<super::model::Node, ApiError> {
        Err(ApiError::network("offline"))
    }
    fn trash(&self, _: u64) -> Result<(), ApiError> {
        Err(ApiError::network("offline"))
    }
    fn check(&self, _: u64, _: &str, _: &str, _: u64) -> Result<super::model::UploadCheck, ApiError> {
        Err(ApiError::network("offline"))
    }
    fn upload(&self, _: &mut dyn super::remote::ReadAt, _: &[u8; 32], _: &mut dyn FnMut(u64, u64)) -> Result<String, ApiError> {
        Err(ApiError::network("offline"))
    }
    fn commit(&self, _: &super::model::CommitRequest) -> Result<super::model::Node, ApiError> {
        Err(ApiError::network("offline"))
    }
    fn content(&self, _: u64) -> Result<super::model::Content, ApiError> {
        Err(ApiError::network("offline"))
    }
    fn download(&self, _: &str, _: u64, _: u64, _: &mut dyn FnMut(&[u8]) -> Result<(), String>) -> Result<u64, ApiError> {
        Err(ApiError::network("offline"))
    }
}

#[allow(clippy::too_many_arguments)]
fn run_loop<P: Platform>(
    svc: std::sync::Weak<Service<P>>,
    rx: mpsc::Receiver<Msg>,
    remote: Arc<dyn Remote>,
    fs: Arc<dyn LocalFs>,
    shared: Arc<Shared>,
    run: Arc<Mutex<RunState>>,
    config: Config,
    root: PathBuf,
    data_dir: PathBuf,
    mut paused: bool,
) {
    let log = |level: &str, msg: &str| {
        if let Some(s) = svc.upgrade() {
            s.log(level, msg);
        }
    };
    let publish = || {
        if let Some(s) = svc.upgrade() {
            s.publish();
        }
    };
    let set_state = |st: &str| {
        let changed = {
            let mut r = run.lock().unwrap();
            let c = r.state != st;
            r.state = st.to_string();
            c
        };
        if changed {
            publish();
        }
    };

    let state_path = state_file(&data_dir, &config.server_url);
    let mut engine: Option<Engine> = None;
    let mut jobs: Vec<(EngineJob, Sender<Result<Value, ProtoError>>)> = Vec::new();
    let make_engine = |me: super::model::MeAnswer| {
        let account = hash16(&format!("{}\n{}", config.server_url.to_lowercase(), me.me.id.unwrap_or(0)));
        let st = State::load(&state_path, &account);
        let mut e = Engine::new(EngineConfig { root: root.clone(), device_name: config.device_name.clone() }, remote.clone(), fs.clone(), st, shared.clone());
        let lg = svc.clone();
        e.set_logger(move |lvl, msg| {
            if let Some(s) = lg.upgrade() {
                s.log(lvl, msg);
            }
        });
        e
    };
    let mut settling: HashMap<PathBuf, Instant> = HashMap::new();
    // Löschungen aus dem Explorer sammeln, bis 2 s Ruhe ist: eine große Löschung
    // kommt so als Ganzes zur Prüfung auf Massenlöschung.
    let mut deleted: Vec<(u64, PathBuf)> = Vec::new();
    let mut last_delete = Instant::now();
    let mut next_poll = Instant::now();
    let mut backoff = Duration::from_secs(15);
    loop {
        // auf Nachrichten warten, bis zur nächsten Abfrage oder bis eine Änderung „fertig“ ist
        let now = Instant::now();
        let mut wait = next_poll.saturating_duration_since(now);
        if let Some(t) = settling.values().map(|t| (*t + SETTLE).saturating_duration_since(now)).min() {
            wait = wait.min(t);
        }
        if !deleted.is_empty() {
            wait = wait.min((last_delete + SETTLE).saturating_duration_since(now));
        }
        match rx.recv_timeout(wait.max(Duration::from_millis(50))) {
            Ok(Msg::Stop) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(Msg::Job(j, tx)) => jobs.push((j, tx)),
            Ok(Msg::SyncNow) => next_poll = Instant::now(),
            Ok(Msg::Pause(p)) => {
                paused = p;
                if !p {
                    next_poll = Instant::now();
                }
            }
            Ok(Msg::Local(p)) => {
                settling.insert(p, Instant::now());
            }
            Ok(Msg::Deleted(n, p)) => {
                deleted.push((n, p));
                last_delete = Instant::now();
            }
            Ok(Msg::Overflow) => {
                if let Some(e) = engine.as_mut() {
                    e.needs_full = true;
                }
                next_poll = Instant::now();
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
        // weitere Nachrichten ohne Warten einsammeln
        while let Ok(m) = rx.try_recv() {
            match m {
                Msg::Stop => {
                    save(&engine, &state_path);
                    return;
                }
                Msg::Local(p) => {
                    settling.insert(p, Instant::now());
                }
                Msg::Deleted(n, p) => {
                    deleted.push((n, p));
                    last_delete = Instant::now();
                }
                Msg::SyncNow | Msg::Overflow => next_poll = Instant::now(),
                Msg::Pause(p) => paused = p,
                Msg::Job(j, tx) => jobs.push((j, tx)),
            }
        }
        if !jobs.is_empty() {
            if engine.is_none() {
                if let Ok(me) = remote.me() {
                    engine = Some(make_engine(me));
                }
            }
            for (j, tx) in jobs.drain(..) {
                let r = match engine.as_mut() {
                    Some(e) => j(e),
                    None => Err(ProtoError::new("offline", "Server nicht erreichbar")),
                };
                let _ = tx.send(r);
            }
            if let Some(e) = engine.as_ref() {
                let mut r = run.lock().unwrap();
                r.errors = e.errors();
            }
            save(&engine, &state_path);
            publish();
            next_poll = Instant::now();
        }
        if paused {
            continue;
        }
        let now = Instant::now();
        let settled: Vec<PathBuf> = settling.iter().filter(|(_, t)| now.duration_since(**t) >= SETTLE).map(|(p, _)| p.clone()).collect();
        if !deleted.is_empty() && now.duration_since(last_delete) >= SETTLE {
            if let Some(e) = engine.as_mut() {
                for (n, p) in deleted.drain(..) {
                    e.note_deleted(n, p);
                }
                next_poll = now;
            }
        }
        let due = now >= next_poll;
        if settled.is_empty() && !due {
            continue;
        }
        // Engine anlegen, sobald der Server antwortet (Konto → Zustandsdatei)
        if engine.is_none() {
            match remote.me() {
                Ok(me) => engine = Some(make_engine(me)),
                Err(err) => {
                    log("warn", &format!("Server nicht erreichbar: {err}"));
                    set_state(if err.offline() { "offline" } else { "error" });
                    run.lock().unwrap().errors = vec![StatusError { code: err.code.clone(), message: err.message.clone(), path: None, at: now_iso() }];
                    publish();
                    next_poll = Instant::now() + backoff;
                    backoff = (backoff * 2).min(Duration::from_secs(300));
                    continue;
                }
            }
        }
        let Some(eng) = engine.as_mut() else { continue };
        for p in settled {
            settling.remove(&p);
            eng.queue_local(p);
        }
        set_state("syncing");
        let res = if due { eng.sync() } else { eng.process_local() };
        {
            let mut r = run.lock().unwrap();
            r.errors = eng.errors();
            r.last_sync = eng.state.last_sync.clone();
        }
        match res {
            Ok(()) => {
                backoff = Duration::from_secs(15);
                if due {
                    next_poll = Instant::now() + POLL_INTERVAL;
                }
                set_state("idle");
            }
            Err(e) if e.code == "cancelled" => {}
            Err(e) => {
                log("warn", &format!("Abgleich: {e}"));
                {
                    let mut r = run.lock().unwrap();
                    r.errors.push(StatusError { code: e.code.clone(), message: e.message.clone(), path: None, at: now_iso() });
                }
                set_state(if e.offline() { "offline" } else { "error" });
                next_poll = Instant::now() + backoff;
                backoff = (backoff * 2).min(Duration::from_secs(300));
            }
        }
        save(&engine, &state_path);
        publish();
    }
    save(&engine, &state_path);
}

fn save(engine: &Option<Engine>, path: &Path) {
    if let Some(e) = engine {
        let _ = e.state.save(path);
    }
}

// ───────────────────────── Rückrufe ─────────────────────────

struct Handler {
    shared: Arc<Shared>,
    tx: Mutex<Sender<Msg>>,
    fetch: Arc<FetchPool>,
    root: PathBuf,
}

impl Handler {
    fn send(&self, m: Msg) {
        let _ = self.tx.lock().unwrap().send(m);
    }

    /// Bereich eines Pfads unter dem Sync-Root (erster Ordner) und ob er schreibbar ist.
    fn area_of_path(&self, p: &Path) -> Option<(String, bool)> {
        let rel = p.strip_prefix(&self.root).ok()?;
        let first = rel.iter().next()?.to_str()?;
        let area = self.shared.area_of_dir(first)?;
        let w = self.shared.area_writable(&area).unwrap_or(false);
        Some((area, w))
    }
}

impl Callbacks for Handler {
    fn fetch_data(&self, key: i64, req: FetchRequest, sink: Box<dyn TransferSink + Send>) {
        self.fetch.submit(key, req, sink);
    }

    fn cancel_fetch(&self, key: i64) {
        self.fetch.cancel(key);
    }

    fn notify_delete(&self, identity: Option<Identity>, path: PathBuf) -> bool {
        let Some(id) = identity else { return true };
        if self.shared.is_root(id.node) {
            return false; // der Ordner eines Bereichs
        }
        if self.shared.area_writable(&id.area) == Some(false) {
            return false; // nur Lesen
        }
        self.send(Msg::Deleted(id.node, path));
        true
    }

    fn notify_rename(&self, identity: Option<Identity>, from: PathBuf, to: Option<PathBuf>) -> bool {
        let Some(id) = identity else { return true };
        if self.shared.is_root(id.node) || self.shared.area_writable(&id.area) == Some(false) {
            return false;
        }
        match to {
            None => {
                // aus dem Sync-Root hinaus: wie Löschen
                self.send(Msg::Deleted(id.node, from));
                true
            }
            Some(t) => match self.area_of_path(&t) {
                Some((_, true)) if t.strip_prefix(&self.root).map(|r| r.iter().count() >= 2).unwrap_or(false) => {
                    self.send(Msg::Local(t));
                    true
                }
                _ => false, // in einen Bereich nur zum Lesen oder direkt in den Sync-Root
            },
        }
    }
}

// ───────────────────────── Laden beim Öffnen ─────────────────────────

type FetchLog = Arc<dyn Fn(&str, &str) + Send + Sync>;

struct Job {
    key: i64,
    req: FetchRequest,
    sink: Box<dyn TransferSink + Send>,
}

pub struct FetchPool {
    tx: Mutex<Option<Sender<Job>>>,
    cancelled: Mutex<HashSet<i64>>,
    closing: AtomicBool,
    active: std::sync::atomic::AtomicU64,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

struct CancelSink {
    inner: Box<dyn TransferSink + Send>,
    key: i64,
    pool: Arc<FetchPool>,
}

impl TransferSink for CancelSink {
    fn transfer(&mut self, offset: u64, data: &[u8]) -> Result<(), String> {
        self.inner.transfer(offset, data)
    }
    fn progress(&mut self, total: u64, done: u64) {
        self.inner.progress(total, done)
    }
    fn fail(&mut self, offset: u64, length: u64) {
        if !self.cancelled() {
            self.inner.fail(offset, length)
        }
    }
    fn cancelled(&self) -> bool {
        self.pool.closing.load(Ordering::Relaxed) || self.pool.cancelled.lock().unwrap().contains(&self.key) || self.inner.cancelled()
    }
}

impl FetchPool {
    pub fn new(remote: Arc<dyn Remote>, n: usize, log: FetchLog) -> Arc<FetchPool> {
        let (tx, rx) = mpsc::channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        let pool = Arc::new(FetchPool {
            tx: Mutex::new(Some(tx)),
            cancelled: Mutex::new(HashSet::new()),
            closing: AtomicBool::new(false),
            active: Default::default(),
            workers: Mutex::new(Vec::new()),
        });
        for i in 0..n {
            let (rx, remote, weak, log) = (rx.clone(), remote.clone(), Arc::downgrade(&pool), log.clone());
            let h = std::thread::Builder::new()
                .name(format!("drive-fetch-{i}"))
                .spawn(move || loop {
                    let job = rx.lock().unwrap().recv();
                    let Ok(job) = job else { break };
                    let Some(pool) = weak.upgrade() else { break };
                    pool.active.fetch_add(1, Ordering::Relaxed);
                    let mut sink = CancelSink { inner: job.sink, key: job.key, pool: pool.clone() };
                    let (o, e) = hydrate::plan_range(&job.req);
                    let node = job.req.identity.as_ref().map(|i| i.node).unwrap_or(0);
                    let r = &job.req;
                    log(
                        "info",
                        &format!(
                            "FETCH_DATA Knoten {node}: Pflicht {}+{}, optional {}+{}, Größe {}",
                            r.required_offset, r.required_length, r.optional_offset, r.optional_length, r.file_size
                        ),
                    );
                    match hydrate::fetch(remote.as_ref(), &job.req, &mut sink) {
                        Ok(n) => log("info", &format!("Geladen: Knoten {node}, {n} Bytes ab {o}")),
                        Err(err) if err.code == "cancelled" => log("info", &format!("Laden abgebrochen: Knoten {node}")),
                        Err(err) => log("warn", &format!("Laden fehlgeschlagen: Knoten {node} [{o}, {e}): {err}")),
                    }
                    pool.cancelled.lock().unwrap().remove(&job.key);
                    pool.active.fetch_sub(1, Ordering::Relaxed);
                })
                .expect("thread");
            pool.workers.lock().unwrap().push(h);
        }
        pool
    }

    pub fn submit(&self, key: i64, req: FetchRequest, mut sink: Box<dyn TransferSink + Send>) {
        let tx = self.tx.lock().unwrap().clone();
        match tx {
            Some(tx) => {
                if let Err(e) = tx.send(Job { key, req, sink }) {
                    let mut job = e.0;
                    let (o, l) = hydrate::plan_range(&job.req);
                    job.sink.fail(o, (l - o).max(1));
                }
            }
            None => {
                let (o, l) = hydrate::plan_range(&req);
                sink.fail(o, (l - o).max(1));
            }
        }
    }

    pub fn cancel(&self, key: i64) {
        self.cancelled.lock().unwrap().insert(key);
    }

    pub fn active(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    pub fn shutdown(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.tx.lock().unwrap().take();
        let ws = std::mem::take(&mut *self.workers.lock().unwrap());
        for w in ws {
            let _ = w.join();
        }
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
