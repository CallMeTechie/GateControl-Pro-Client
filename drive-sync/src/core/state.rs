//! Lokaler Zustand: welche Knoten es gibt (Baum mit Namen, `rev`, Medien-ID),
//! welcher Bereich in welchem Ordner liegt, und der Cursor `since` des
//! Änderungsprotokolls. Gespeichert als JSON unter
//! `%LOCALAPPDATA%\GateControl\drive-sync\state-<konto>.json` – ohne Token.

use super::model::{Node, Role};
use super::names;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

pub const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: u64,
    /// 0 bei der Wurzel eines Bereichs.
    pub parent: u64,
    pub area: String,
    pub name: String,
    pub is_dir: bool,
    pub rev: u64,
    pub size: u64,
    #[serde(default)]
    pub media: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    pub mtime_ms: i64,
    #[serde(default)]
    pub ctime_ms: i64,
}

impl Entry {
    pub fn from_node(n: &Node) -> Entry {
        Entry {
            id: n.id,
            parent: n.parent_id.unwrap_or(0),
            area: n.area_id.clone(),
            name: n.name.clone(),
            is_dir: n.is_dir,
            rev: n.rev,
            size: if n.is_dir { 0 } else { n.size.unwrap_or(0) },
            media: n.media_id.clone(),
            sha256: n.sha256.clone(),
            mtime_ms: n.mtime_ms(),
            ctime_ms: n.created_ms(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AreaDir {
    pub id: String,
    pub root_id: u64,
    /// Ordnername unter dem Sync-Root.
    pub dir: String,
    pub label: String,
    pub role: Role,
    #[serde(default)]
    pub archived: bool,
}

impl AreaDir {
    pub fn writable(&self) -> bool {
        self.role.can_write() && !self.archived
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub version: u32,
    /// Server + Person (Hash), zu dem der Zustand gehört.
    pub account: String,
    pub cursor: u64,
    #[serde(default)]
    pub last_sync: Option<String>,
    #[serde(default)]
    pub areas: Vec<AreaDir>,
    #[serde(default)]
    entries: Vec<Entry>,
    #[serde(skip)]
    by_id: HashMap<u64, Entry>,
    #[serde(skip)]
    children: HashMap<u64, HashMap<String, u64>>,
}

impl State {
    pub fn new(account: &str) -> State {
        State { version: STATE_VERSION, account: account.to_string(), ..Default::default() }
    }

    /// Lädt den Zustand; fehlt die Datei, ist sie kaputt oder gehört sie zu
    /// einem anderen Konto, beginnt ein leerer (dann folgt ein voller Abgleich).
    pub fn load(path: &Path, account: &str) -> State {
        let Ok(bytes) = std::fs::read(path) else { return State::new(account) };
        match serde_json::from_slice::<State>(&bytes) {
            Ok(mut s) if s.version == STATE_VERSION && s.account == account => {
                let list = std::mem::take(&mut s.entries);
                for e in list {
                    s.upsert(e);
                }
                s
            }
            _ => State::new(account),
        }
    }

    /// Atomar speichern (temporäre Datei + Umbenennen).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let mut out = self.clone();
        out.entries = self.by_id.values().cloned().collect();
        out.entries.sort_by_key(|e| e.id);
        let data = serde_json::to_vec(&out).map_err(io::Error::other)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, path)
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    pub fn files(&self) -> usize {
        self.by_id.values().filter(|e| !e.is_dir).count()
    }

    pub fn get(&self, id: u64) -> Option<&Entry> {
        self.by_id.get(&id)
    }

    pub fn area(&self, id: &str) -> Option<&AreaDir> {
        self.areas.iter().find(|a| a.id == id)
    }

    pub fn area_by_root(&self, root_id: u64) -> Option<&AreaDir> {
        self.areas.iter().find(|a| a.root_id == root_id)
    }

    pub fn area_by_dir(&self, dir: &str) -> Option<&AreaDir> {
        self.areas.iter().find(|a| names::same_name(&a.dir, dir))
    }

    /// Eintrag setzen oder ändern (Name/Elternteil ändern den Index mit).
    pub fn upsert(&mut self, e: Entry) {
        if let Some(old) = self.by_id.get(&e.id) {
            if old.parent != e.parent || old.name != e.name {
                let (p, k) = (old.parent, names::key(&old.name));
                if let Some(m) = self.children.get_mut(&p) {
                    if m.get(&k) == Some(&e.id) {
                        m.remove(&k);
                    }
                }
            }
        }
        if e.parent != 0 {
            self.children.entry(e.parent).or_default().insert(names::key(&e.name), e.id);
        }
        self.by_id.insert(e.id, e);
    }

    /// Entfernt `id` mit allem darunter → die entfernten IDs.
    pub fn remove(&mut self, id: u64) -> Vec<u64> {
        let mut out = Vec::new();
        let mut stack = vec![id];
        while let Some(i) = stack.pop() {
            if let Some(kids) = self.children.remove(&i) {
                stack.extend(kids.into_values());
            }
            if let Some(e) = self.by_id.remove(&i) {
                if let Some(m) = self.children.get_mut(&e.parent) {
                    if m.get(&names::key(&e.name)) == Some(&i) {
                        m.remove(&names::key(&e.name));
                    }
                }
                out.push(i);
            }
        }
        out
    }

    pub fn child(&self, parent: u64, name: &str) -> Option<&Entry> {
        self.children.get(&parent).and_then(|m| m.get(&names::key(name))).and_then(|id| self.by_id.get(id))
    }

    pub fn children_of(&self, parent: u64) -> Vec<&Entry> {
        self.children.get(&parent).map(|m| m.values().filter_map(|id| self.by_id.get(id)).collect()).unwrap_or_default()
    }

    /// Alle IDs unterhalb von `id` (ohne `id`).
    pub fn descendants(&self, id: u64) -> Vec<u64> {
        let mut out = Vec::new();
        let mut stack = vec![id];
        while let Some(i) = stack.pop() {
            if let Some(m) = self.children.get(&i) {
                for c in m.values() {
                    out.push(*c);
                    stack.push(*c);
                }
            }
        }
        out
    }

    /// Pfad relativ zum Sync-Root (erste Komponente: Ordner des Bereichs).
    pub fn rel_path(&self, id: u64) -> Option<PathBuf> {
        let mut parts = Vec::new();
        let mut cur = id;
        for _ in 0..4096 {
            if let Some(a) = self.area_by_root(cur) {
                parts.push(a.dir.clone());
                parts.reverse();
                return Some(parts.iter().collect());
            }
            let e = self.by_id.get(&cur)?;
            parts.push(e.name.clone());
            cur = e.parent;
        }
        None
    }

    /// Knoten zu einem Pfad relativ zum Sync-Root.
    pub fn lookup(&self, rel: &Path) -> Option<u64> {
        let mut comps = rel.components().filter_map(|c| match c {
            std::path::Component::Normal(s) => s.to_str(),
            _ => None,
        });
        let first = comps.next()?;
        let mut cur = self.area_by_dir(first)?.root_id;
        for c in comps {
            cur = self.child(cur, c)?.id;
        }
        Some(cur)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(id: u64, parent: u64, name: &str, dir: bool) -> Entry {
        Entry { id, parent, area: "mine:1".into(), name: name.into(), is_dir: dir, rev: 1, size: 0, media: None, sha256: None, mtime_ms: 0, ctime_ms: 0 }
    }

    fn sample() -> State {
        let mut s = State::new("acc");
        s.areas.push(AreaDir {
            id: "mine:1".into(),
            root_id: 1,
            dir: "Meine Dateien".into(),
            label: "Meine Dateien".into(),
            role: Role::Manage,
            archived: false,
        });
        s.upsert(e(1, 0, "Meine Dateien", true));
        s.upsert(e(2, 1, "Fotos", true));
        s.upsert(e(3, 2, "Strand.jpg", false));
        s.upsert(e(4, 1, "Brief.pdf", false));
        s
    }

    #[test]
    fn paths_and_lookup() {
        let s = sample();
        assert_eq!(s.rel_path(3).unwrap(), PathBuf::from("Meine Dateien").join("Fotos").join("Strand.jpg"));
        assert_eq!(s.rel_path(1).unwrap(), PathBuf::from("Meine Dateien"));
        assert_eq!(s.lookup(&PathBuf::from("meine dateien").join("FOTOS").join("strand.jpg")), Some(3));
        assert_eq!(s.lookup(Path::new("Meine Dateien")), Some(1));
        assert_eq!(s.lookup(Path::new("Andere")), None);
        assert_eq!(s.files(), 2);
        assert_eq!(s.child(1, "brief.PDF").unwrap().id, 4);
    }

    #[test]
    fn rename_and_move_update_index() {
        let mut s = sample();
        let mut x = s.get(3).unwrap().clone();
        x.parent = 1;
        x.name = "Meer.jpg".into();
        s.upsert(x);
        assert!(s.child(2, "Strand.jpg").is_none());
        assert_eq!(s.child(1, "Meer.jpg").unwrap().id, 3);
        assert_eq!(s.rel_path(3).unwrap(), PathBuf::from("Meine Dateien").join("Meer.jpg"));
    }

    #[test]
    fn remove_subtree() {
        let mut s = sample();
        let mut gone = s.remove(2);
        gone.sort();
        assert_eq!(gone, vec![2, 3]);
        assert!(s.get(3).is_none());
        assert!(s.child(1, "Fotos").is_none());
        assert_eq!(s.descendants(1), vec![4]);
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub").join("state.json");
        let mut s = sample();
        s.cursor = 77;
        s.save(&p).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.to_lowercase().contains("token"));
        let l = State::load(&p, "acc");
        assert_eq!(l.cursor, 77);
        assert_eq!(l.len(), 4);
        assert_eq!(l.lookup(&PathBuf::from("Meine Dateien").join("Fotos")), Some(2));
        // anderes Konto oder kaputte Datei → leer
        assert_eq!(State::load(&p, "other").len(), 0);
        std::fs::write(&p, b"{kaputt").unwrap();
        assert_eq!(State::load(&p, "acc").cursor, 0);
    }
}
