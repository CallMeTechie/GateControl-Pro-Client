//! Was der Abgleich vom lokalen Dateisystem braucht. Unter Windows
//! (`win::winfs`) sind das Platzhalter der Cloud Files API; in Tests ein
//! Dateisystem im Speicher (`testing::FakeFs`).

use super::identity::Identity;
use super::remote::ReadAt;
use std::io;
use std::path::Path;

/// Pin-Zustand (Explorer: „Immer auf diesem Gerät behalten“ = `Pinned`,
/// „Speicher freigeben“ = `Unpinned`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Pin {
    #[default]
    Unspecified,
    Pinned,
    Unpinned,
    Excluded,
    Inherit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder {
    pub identity: Option<Identity>,
    pub in_sync: bool,
    pub pin: Pin,
    /// Alle Daten liegen lokal (keine „nur online“-Bereiche).
    pub hydrated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime_ms: i64,
    /// `None`: eine normale Datei / ein normaler Ordner (noch nicht abgeglichen).
    pub placeholder: Option<Placeholder>,
}

impl LocalEntry {
    pub fn identity(&self) -> Option<&Identity> {
        self.placeholder.as_ref().and_then(|p| p.identity.as_ref())
    }
    pub fn in_sync(&self) -> bool {
        self.placeholder.as_ref().is_some_and(|p| p.in_sync)
    }
}

/// Metadaten eines Platzhalters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceholderMeta {
    pub identity: Identity,
    pub is_dir: bool,
    pub size: u64,
    pub mtime_ms: i64,
    pub ctime_ms: i64,
}

pub trait LocalFs: Send + Sync {
    /// `None`, wenn es den Pfad nicht gibt.
    fn stat(&self, path: &Path) -> io::Result<Option<LocalEntry>>;
    fn list(&self, dir: &Path) -> io::Result<Vec<LocalEntry>>;
    /// Platzhalter (Datei „nur online“ oder Ordner) in `dir`, als abgeglichen markiert.
    fn create_placeholder(&self, dir: &Path, name: &str, meta: &PlaceholderMeta) -> io::Result<()>;
    /// Metadaten/Identität ändern; `content_changed`: lokale Daten verwerfen (dehydrieren).
    fn update_placeholder(&self, path: &Path, meta: &PlaceholderMeta, content_changed: bool) -> io::Result<()>;
    /// Normale Datei/Ordner → Platzhalter mit Identität, abgeglichen.
    fn convert_to_placeholder(&self, path: &Path, identity: &Identity) -> io::Result<()>;
    /// In-Sync-Zustand setzen (`false`: muss noch hochgeladen werden).
    fn set_in_sync(&self, path: &Path, in_sync: bool) -> io::Result<()>;
    /// Platzhalter → normale Datei (Daten bleiben).
    fn revert_placeholder(&self, path: &Path) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    /// Nur leere Ordner.
    fn remove_dir(&self, path: &Path) -> io::Result<()>;
    /// Liest die Datei zum Hochladen; schlägt fehl, solange ein Programm noch schreibt.
    fn open_read(&self, path: &Path) -> io::Result<Box<dyn ReadAt>>;
    /// Vollständig laden (angeheftete Datei). Darf im Hintergrund laufen.
    fn hydrate(&self, path: &Path) -> io::Result<()>;
    /// Lokale Daten verwerfen (Speicher freigeben).
    fn dehydrate(&self, path: &Path) -> io::Result<()>;
    /// Normalen Ordner anlegen (Eltern müssen existieren).
    fn create_dir(&self, path: &Path) -> io::Result<()>;
    /// Vollständig laden und warten, bis alles da ist (Zurücklegen, Abmelden).
    fn hydrate_now(&self, path: &Path) -> io::Result<()> {
        self.hydrate(path)
    }
    /// Datei oder Ordner verschieben – auch auf ein anderes Laufwerk (dann
    /// kopieren, und das Original erst löschen, wenn alles kopiert ist). Ziel
    /// darf nicht existieren.
    fn move_path(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.rename(from, to)
    }
}
