//! Windows: Cloud Files API, Sync-Root, Beobachtung, Pipe, Programmstart.

pub mod actions;
pub mod cfapi;
pub mod known;
pub mod launch;
pub mod main;
pub mod pipe;
pub mod shellmenu;
pub mod syncroot;
pub mod util;
pub mod watcher;
pub mod winfs;

use crate::core::localfs::LocalFs;
use crate::core::relocate::KnownFolders;
use crate::core::service::{Callbacks, Guard, Platform, WatchEvent};
use std::path::PathBuf;
use std::sync::Arc;

/// `%USERPROFILE%\GateControl Drive`
pub fn default_root() -> PathBuf {
    let home = std::env::var_os("USERPROFILE").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Users\Public"));
    home.join("GateControl Drive")
}

/// `%LOCALAPPDATA%\GateControl\drive-sync`
pub fn default_data_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    base.join("GateControl").join("drive-sync")
}

pub struct WinPlatform {
    pub spec: syncroot::SyncRootSpec,
    pub data: PathBuf,
    fs: Arc<winfs::WinFs>,
    known: Arc<known::WinKnown>,
    /// Schlüssel des Kontextmenüs (Tests: eigener, damit das echte unberührt bleibt).
    pub menu_verb: String,
    pub elevated: bool,
}

impl WinPlatform {
    pub fn new(sid: &str, root: PathBuf, data: PathBuf) -> WinPlatform {
        Self::with_id(&syncroot::sync_root_id(sid), root, data)
    }

    /// Eigene Sync-Root-ID (Tests: nie die echte Registrierung des Benutzers anfassen).
    pub fn with_id(id: &str, root: PathBuf, data: PathBuf) -> WinPlatform {
        let exe = std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
        WinPlatform {
            spec: syncroot::SyncRootSpec {
                id: id.to_string(),
                root,
                display_name: syncroot::PROVIDER_NAME.to_string(),
                icon: format!("{exe},0"),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            data,
            fs: Arc::new(winfs::WinFs::new()),
            known: Arc::new(known::WinKnown::real()),
            menu_verb: shellmenu::VERB.to_string(),
            elevated: false,
        }
    }

    /// Tests: Windows-Ordner unter `base` statt der echten.
    pub fn with_fake_known(mut self, base: &std::path::Path) -> WinPlatform {
        self.known = Arc::new(known::WinKnown::fake(base));
        self
    }
}

impl Platform for WinPlatform {
    fn sync_root(&self) -> PathBuf {
        self.spec.root.clone()
    }
    fn data_dir(&self) -> PathBuf {
        self.data.clone()
    }
    fn register(&self) -> Result<(), String> {
        syncroot::register(&self.spec).map(|_| ())
    }
    fn unregister(&self) -> Result<(), String> {
        syncroot::unregister(&self.spec.id, &self.spec.root)
    }
    fn is_registered(&self) -> bool {
        syncroot::is_registered(&self.spec.root)
    }
    fn fs(&self) -> Arc<dyn LocalFs> {
        self.fs.clone()
    }
    fn connect(&self, cb: Arc<dyn Callbacks>) -> Result<Guard, String> {
        cfapi::connect(&self.spec.root, cb).map(|c| Box::new(c) as Guard)
    }
    fn watch(&self, on_event: Box<dyn Fn(WatchEvent) + Send + Sync>) -> Result<Guard, String> {
        watcher::watch(self.spec.root.clone(), on_event).map(|w| Box::new(w) as Guard)
    }
    fn known(&self) -> Option<Arc<dyn KnownFolders>> {
        Some(self.known.clone())
    }
    fn elevated(&self) -> bool {
        self.elevated
    }
    fn context_menu(&self, on: bool, app_exe: Option<&str>, lang: Option<&str>) -> Result<(), String> {
        if on {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            shellmenu::register(&self.menu_verb, &self.spec.root, &exe, app_exe, lang)
        } else {
            shellmenu::unregister(&self.menu_verb)
        }
    }
    fn notify_shell(&self, paths: &[PathBuf]) {
        known::notify(paths);
    }
}
