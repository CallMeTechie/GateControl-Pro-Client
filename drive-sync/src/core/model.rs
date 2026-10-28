//! Antworten des Drive-Plugins (`gatecontrol-drive`, README „API“) als Rust-Typen.
//!
//! Bewusst nachsichtig: unbekannte Felder werden ignoriert, fehlende bekommen
//! Standardwerte. Ein Knoten ohne `id` oder `name` ist unbrauchbar und wird
//! beim Einlesen verworfen (siehe `api.rs`).

use serde::{Deserialize, Serialize};

/// Rolle in einem Bereich (`read` | `write` | `manage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    #[default]
    Read,
    Write,
    Manage,
}

impl Role {
    pub fn parse(s: &str) -> Role {
        match s {
            "write" => Role::Write,
            "manage" => Role::Manage,
            _ => Role::Read,
        }
    }
    pub fn can_write(self) -> bool {
        matches!(self, Role::Write | Role::Manage)
    }
}

/// Ein Bereich (`GET areas`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Area {
    pub id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub label: String,
    #[serde(default, deserialize_with = "role_de")]
    pub role: Role,
    /// `owner` | `member` | `parent` | … – über `parent` sieht ein Elternteil den
    /// Kinder-Ordner; jedes Auflisten meldet dem Kind „angesehen“.
    #[serde(default)]
    pub via: Option<String>,
    pub root_id: u64,
    #[serde(default)]
    pub archived: bool,
}

impl Area {
    /// Schreiben erlaubt (Rolle und nicht archiviert).
    pub fn writable(&self) -> bool {
        self.role.can_write() && !self.archived
    }
}

fn role_de<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Role, D::Error> {
    let s: Option<String> = Option::deserialize(d)?;
    Ok(s.map(|s| Role::parse(&s)).unwrap_or_default())
}

/// Ein Knoten (Ordner oder Datei) wie in jeder Plugin-Antwort.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub id: u64,
    #[serde(default)]
    pub area_id: String,
    #[serde(default)]
    pub parent_id: Option<u64>,
    pub name: String,
    #[serde(default)]
    pub is_dir: bool,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub media_id: Option<String>,
    /// ISO-8601 (Server: `toISOString()`), `null` wenn unbekannt.
    #[serde(default)]
    pub mtime: Option<String>,
    #[serde(default)]
    pub rev: u64,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub deleted: bool,
}

impl Node {
    /// Änderungszeit in ms seit 1970 (mtime, sonst updatedAt, sonst 0).
    pub fn mtime_ms(&self) -> i64 {
        self.mtime.as_deref().or(self.updated_at.as_deref()).and_then(parse_iso_ms).unwrap_or(0)
    }
    pub fn created_ms(&self) -> i64 {
        self.created_at.as_deref().and_then(parse_iso_ms).unwrap_or_else(|| self.mtime_ms())
    }
}

pub fn parse_iso_ms(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.timestamp_millis())
}

/// `GET me`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MeAnswer {
    #[serde(default)]
    pub me: Me,
    /// Höchste `seq` des Änderungsprotokolls.
    #[serde(default)]
    pub latest: u64,
    /// Drive 1.5: Fähigkeiten (`emptyFiles`, `devices`, `deleteAfter`, …); ältere Drives: leer.
    #[serde(default)]
    pub features: Vec<String>,
    /// Drive 1.6 `guard`: hat Drive dieses Gerät gestoppt?
    #[serde(default)]
    pub guard: Option<GuardInfo>,
}

/// `me.guard` (Drive 1.6).
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct GuardInfo {
    #[serde(default)]
    pub locked: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Me {
    #[serde(default)]
    pub id: Option<u64>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub seat: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
}

/// `GET nodes/<id>/children`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ChildrenPage {
    #[serde(default)]
    pub items: Vec<Node>,
    #[serde(default)]
    pub total: u64,
    /// Offset der nächsten Seite, `null` am Ende.
    #[serde(default)]
    pub next: Option<u64>,
}

/// Eine Zeile des Änderungsprotokolls.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub seq: u64,
    #[serde(default)]
    pub op: String,
    #[serde(default)]
    pub area_id: String,
    pub node_id: u64,
    #[serde(default)]
    pub device: Option<String>,
    /// Der Knoten, wie er jetzt ist; `null` nach endgültigem Löschen oder wenn er
    /// in einen anderen Bereich verschoben wurde.
    #[serde(default)]
    pub node: Option<Node>,
}

/// `GET changes?since=`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ChangesPage {
    #[serde(default)]
    pub changes: Vec<Change>,
    #[serde(default)]
    pub next: u64,
    #[serde(default)]
    pub more: bool,
}

/// `POST uploads/check`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UploadCheck {
    #[serde(default)]
    pub exists: bool,
    #[serde(default)]
    pub same: bool,
    #[serde(default)]
    pub node: Option<Node>,
}

/// `GET nodes/<id>/content`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Content {
    #[serde(default)]
    pub media_id: Option<String>,
    /// Drive 1.5: leere Datei ohne Medium.
    #[serde(default)]
    pub empty: bool,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub name: Option<String>,
}

/// `POST uploads/commit`.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CommitRequest {
    /// `None` nur für leere Dateien (Drive 1.5 `emptyFiles`, dann `size: 0`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub parent_id: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_rev: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_conflict: Option<String>,
    /// Drive 1.6 `guard`: Entropie der ersten 64 KB (0 … 8), nur an solche Drives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_from_server_json() {
        let n: Node = serde_json::from_str(
            r#"{"id":7,"areaId":"mine:1","parentId":3,"name":"Brief.pdf","isDir":false,"size":12,
               "mime":"application/pdf","sha256":null,"mediaId":"abcdefgh","mtime":"2026-10-01T10:00:00.000Z",
               "rev":4,"createdAt":"2026-09-01T10:00:00.000Z","updatedAt":"2026-10-02T10:00:00.000Z","deleted":false,
               "preview":null}"#,
        )
        .unwrap();
        assert_eq!(n.id, 7);
        assert_eq!(n.parent_id, Some(3));
        assert_eq!(n.mtime_ms(), parse_iso_ms("2026-10-01T10:00:00Z").unwrap());
        assert_eq!(parse_iso_ms("1970-01-01T00:00:00.500Z"), Some(500));
        assert_eq!(n.rev, 4);
        assert!(n.created_ms() < n.mtime_ms());
    }

    #[test]
    fn mtime_falls_back_to_updated_at() {
        let n = Node { updated_at: Some("1970-01-01T00:00:01Z".into()), ..Default::default() };
        assert_eq!(n.mtime_ms(), 1000);
        assert_eq!(Node::default().mtime_ms(), 0);
    }

    #[test]
    fn area_roles() {
        let a: Area = serde_json::from_str(r#"{"id":"team:1","kind":"team","label":"T","role":"write","rootId":5,"archived":true}"#).unwrap();
        assert_eq!(a.role, Role::Write);
        assert!(!a.writable());
        let b: Area = serde_json::from_str(r#"{"id":"x","rootId":1,"role":"weird"}"#).unwrap();
        assert_eq!(b.role, Role::Read);
    }

    #[test]
    fn commit_body_skips_empty() {
        let c = CommitRequest {
            media_id: Some("m".into()),
            size: None,
            parent_id: 1,
            name: "a".into(),
            base_rev: None,
            mtime: Some(5),
            on_conflict: None,
            entropy: None,
        };
        assert_eq!(serde_json::to_string(&c).unwrap(), r#"{"mediaId":"m","parentId":1,"name":"a","mtime":5}"#);
        let c = CommitRequest { entropy: Some(7.25), ..c };
        assert_eq!(serde_json::to_string(&c).unwrap(), r#"{"mediaId":"m","parentId":1,"name":"a","mtime":5,"entropy":7.25}"#);
        let m: MeAnswer = serde_json::from_str(r#"{"features":["guard"],"guard":{"locked":true,"incident":{"id":4}}}"#).unwrap();
        assert_eq!(m.guard, Some(GuardInfo { locked: true }));
    }
}
