//! Was der Abgleich vom Server braucht – als Schnittstelle, damit er in Tests
//! gegen einen Server im Speicher läuft (`tests`), im Betrieb gegen
//! `api::ApiClient` (HTTP).

use super::model::*;
use std::io;

/// Fehler einer Server-Anfrage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// HTTP-Status, `None` bei Netzwerkfehlern.
    pub status: Option<u16>,
    /// Code des Plugins (`conflict`, `forbidden`, `not_found`, …), sonst
    /// `http_<status>`, `network`, `timeout`, `bad_response`, `cancelled`, `changed`.
    pub code: String,
    pub message: String,
    /// Bei `409 conflict`: der Knoten, wie er auf dem Server ist.
    pub current: Option<Box<Node>>,
}

impl ApiError {
    pub fn new(status: Option<u16>, code: &str, message: impl Into<String>) -> ApiError {
        ApiError { status, code: code.to_string(), message: message.into(), current: None }
    }
    pub fn network(message: impl Into<String>) -> ApiError {
        ApiError::new(None, "network", message)
    }
    /// Lohnt ein späterer neuer Versuch (Netz, Zeitüberschreitung, 5xx, 429)?
    pub fn transient(&self) -> bool {
        match self.status {
            None => self.code == "network" || self.code == "timeout",
            Some(s) => s >= 500 || s == 429 || s == 408,
        }
    }
    pub fn is(&self, code: &str) -> bool {
        self.code == code
    }
    pub fn not_found(&self) -> bool {
        self.status == Some(404) || self.code == "not_found"
    }
    pub fn forbidden(&self) -> bool {
        self.status == Some(403) || self.code == "forbidden"
    }
    /// Server nicht erreichbar oder Anmeldung abgelehnt → Zustand „offline“.
    pub fn offline(&self) -> bool {
        self.status.is_none() || self.status == Some(401)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(s) => write!(f, "{} ({}): {}", self.code, s, self.message),
            None => write!(f, "{}: {}", self.code, self.message),
        }
    }
}

impl std::error::Error for ApiError {}

/// Lesen an einer Stelle (lokale Datei beim Hochladen).
pub trait ReadAt: Send {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;
}

impl ReadAt for std::fs::File {
    fn len(&self) -> u64 {
        self.metadata().map(|m| m.len()).unwrap_or(0)
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::{Read, Seek, SeekFrom};
        self.seek(SeekFrom::Start(offset))?;
        let mut n = 0;
        while n < buf.len() {
            let r = self.read(&mut buf[n..])?;
            if r == 0 {
                break;
            }
            n += r;
        }
        Ok(n)
    }
}

impl ReadAt for io::Cursor<Vec<u8>> {
    fn len(&self) -> u64 {
        self.get_ref().len() as u64
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let data = self.get_ref();
        let start = (offset as usize).min(data.len());
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        Ok(n)
    }
}

pub trait Remote: Send + Sync {
    fn me(&self) -> Result<MeAnswer, ApiError>;
    fn areas(&self) -> Result<Vec<Area>, ApiError>;
    fn node(&self, id: u64) -> Result<Node, ApiError>;
    /// Eine Seite des Inhalts von Ordner `id` ab `offset` (höchstens 1000).
    fn children(&self, id: u64, offset: u64) -> Result<ChildrenPage, ApiError>;
    fn changes(&self, since: u64) -> Result<ChangesPage, ApiError>;
    /// Neuer Ordner genau mit diesem Namen (`409 exists`, wenn es ihn gibt).
    fn mkdir(&self, parent: u64, name: &str) -> Result<Node, ApiError>;
    /// Umbenennen und/oder Verschieben.
    fn update_node(&self, id: u64, name: Option<&str>, parent: Option<u64>) -> Result<Node, ApiError>;
    /// In den Papierkorb.
    fn trash(&self, id: u64) -> Result<(), ApiError>;
    fn check(&self, parent: u64, name: &str, sha256_hex: &str, size: u64) -> Result<UploadCheck, ApiError>;
    /// Medien-Upload (fortsetzbar ab 8 MiB) → `mediaId`. `sha256`: erwartete
    /// Prüfsumme; ändert sich die Datei währenddessen → Fehler `changed`.
    fn upload(&self, src: &mut dyn ReadAt, sha256: &[u8; 32], progress: &mut dyn FnMut(u64, u64)) -> Result<String, ApiError>;
    fn commit(&self, req: &CommitRequest) -> Result<Node, ApiError>;
    fn content(&self, id: u64) -> Result<Content, ApiError>;
    /// Bytes `[start, end)` der Medien-Datei an `sink` (HTTP Range) → Anzahl.
    fn download(&self, media_id: &str, start: u64, end: u64, sink: &mut dyn FnMut(&[u8]) -> Result<(), String>) -> Result<u64, ApiError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_and_offline() {
        assert!(ApiError::network("x").transient());
        assert!(ApiError::network("x").offline());
        assert!(ApiError::new(Some(503), "http_503", "").transient());
        assert!(!ApiError::new(Some(409), "conflict", "").transient());
        assert!(ApiError::new(Some(401), "unauthorized", "").offline());
        assert!(ApiError::new(Some(404), "http_404", "").not_found());
        assert!(ApiError::new(Some(403), "no_seat", "").forbidden());
        assert_eq!(ApiError::new(Some(409), "conflict", "Name").to_string(), "conflict (409): Name");
    }

    #[test]
    fn cursor_read_at() {
        let mut c = io::Cursor::new(b"hallo welt".to_vec());
        let mut b = [0u8; 4];
        assert_eq!(c.read_at(6, &mut b).unwrap(), 4);
        assert_eq!(&b, b"welt");
        assert_eq!(c.read_at(20, &mut b).unwrap(), 0);
        assert_eq!(ReadAt::len(&c), 10);
    }
}
