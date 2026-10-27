//! Windows-Ordner (Desktop, Dokumente, Bilder, Videos, Musik) in den Drive
//! verlegen und zurücklegen – plattformunabhängig gegen `LocalFs` und
//! `KnownFolders` geschrieben (Windows: `SHGetKnownFolderPath` /
//! `SHSetKnownFolderPath`, Tests: Ordner im Speicher).
//!
//! Beides läuft im Abgleich-Thread (als Auftrag zwischen zwei Durchläufen),
//! damit der Abgleich nicht gleichzeitig dieselben Dateien anfasst.
//!
//! Verlegen (`relocate`):
//!   1. Prüfen: Ordner vorhanden, nicht schon im Sync-Root, „Meine Dateien“
//!      beschreibbar, Ziel kein Dateiname.
//!   2. Ziel `<Sync-Root>\<Meine Dateien>\<Name>` anlegen (gibt es ihn schon –
//!      z. B. von einem anderen PC –, wird zusammengeführt: belegte Namen
//!      bekommen einen Konfliktnamen, nichts wird überschrieben).
//!   3. Jeden Eintrag einzeln verschieben (gleiches Laufwerk: Umbenennen, sonst
//!      Kopieren und erst danach das Original löschen). Schlägt einer fehl,
//!      wandert alles schon Verschobene zurück und der Ordner bleibt, wo er war.
//!   4. `SHSetKnownFolderPath` auf das Ziel; schlägt das fehl: zurück wie in 3.
//!   5. Den leeren alten Ordner entfernen, den Ort merken (Zurücklegen), das Ziel
//!      dem Abgleich melden (Hochladen).
//!
//! Zurücklegen (`restore`):
//!   1. Ausstehende Änderungen hochladen (soweit möglich).
//!   2. Alle Dateien vollständig laden (`CfHydratePlaceholder`); scheitert eine,
//!      bricht es ab, bevor sich etwas ändert.
//!   3. Platzhalter in normale Dateien zurückverwandeln (von unten nach oben) –
//!      so löst das Herausschieben kein „gelöscht“ beim Server aus.
//!   4. Einträge an den alten Ort verschieben (Rückweg bei Fehlern), Pfad des
//!      Windows-Ordners zurücksetzen.
//!   5. Die Einträge aus dem Zustand nehmen: Der nächste Abgleich legt den
//!      Drive-Ordner wieder als Platzhalter „nur online“ an – die Dateien bleiben
//!      zusätzlich im Drive, auf dem Server wird nichts gelöscht.

use super::engine::Engine;
use super::localfs::LocalFs;
use super::names;
use super::protocol::{KnownFolder, ProtoError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Pfade der Windows-Ordner des angemeldeten Benutzers.
pub trait KnownFolders: Send + Sync {
    fn get(&self, f: KnownFolder) -> Result<PathBuf, String>;
    fn set(&self, f: KnownFolder, path: &Path) -> Result<(), String>;
    /// Vorgabe-Ort, wenn der alte Ort unbekannt ist (`%USERPROFILE%\Documents` …).
    fn default_path(&self, f: KnownFolder) -> PathBuf;
}

/// Gemerkter alter Ort eines verlegten Ordners (`relocations.json` im Datenordner).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Relocation {
    pub from: PathBuf,
    pub to: PathBuf,
    pub at: String,
}

pub type Records = BTreeMap<String, Relocation>;

pub fn records_file(data_dir: &Path) -> PathBuf {
    data_dir.join("relocations.json")
}

pub fn load_records(data_dir: &Path) -> Records {
    std::fs::read(records_file(data_dir)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn save_records(data_dir: &Path, r: &Records) -> std::io::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let f = records_file(data_dir);
    let tmp = f.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(r).unwrap_or_default())?;
    std::fs::rename(tmp, f)
}

fn key(p: &Path) -> String {
    p.to_string_lossy().replace('/', "\\").trim_end_matches('\\').to_lowercase()
}

/// Liegt `p` in `dir` (oder ist es)? Ohne Groß/Klein, `/` = `\`.
pub fn is_under(p: &Path, dir: &Path) -> bool {
    let (a, b) = (key(p), key(dir));
    !b.is_empty() && (a == b || a.starts_with(&format!("{b}\\")))
}

fn fail(code: &'static str, msg: impl Into<String>) -> ProtoError {
    ProtoError::new(code, msg)
}

type Progress<'a> = &'a dyn Fn(&str, u64, u64);

/// Ein freier Name in `dir` für `name` (belegt → Konfliktname mit Gerät und Zeit).
fn free_name(fs: &dyn LocalFs, dir: &Path, name: &str, device: &str) -> String {
    if fs.stat(&dir.join(name)).ok().flatten().is_none() {
        return name.to_string();
    }
    let stamp = names::conflict_stamp(chrono::Local::now());
    for n in 1..1000 {
        let c = names::conflict_name(name, device, &stamp, n);
        if fs.stat(&dir.join(&c)).ok().flatten().is_none() {
            return c;
        }
    }
    names::conflict_name(name, device, &stamp, 1000)
}

/// Alle Einträge von `from` nach `to` schieben; bei einem Fehler alles zurück.
/// → verschobene Paare (alt, neu)
fn move_children(fs: &dyn LocalFs, from: &Path, to: &Path, device: &str, progress: Progress) -> Result<Vec<(PathBuf, PathBuf)>, ProtoError> {
    let list = fs.list(from).map_err(|e| fail("local_io", format!("{}: {e}", from.display())))?;
    let total = list.len() as u64;
    let mut moved: Vec<(PathBuf, PathBuf)> = Vec::new();
    for (i, c) in list.into_iter().enumerate() {
        let src = from.join(&c.name);
        let dst = to.join(free_name(fs, to, &c.name, device));
        if let Err(e) = fs.move_path(&src, &dst) {
            let back = roll_back(fs, &moved);
            let mut err = fail("move_failed", format!("{}: {e}", src.display()));
            err.data = Some(json!({ "path": src.to_string_lossy(), "rolledBack": back.is_empty(), "left": back }));
            return Err(err);
        }
        moved.push((src, dst));
        progress("move", i as u64 + 1, total);
    }
    Ok(moved)
}

/// Schiebt zurück; → Pfade, die nicht zurück konnten (sie liegen am neuen Ort, nichts ist weg).
fn roll_back(fs: &dyn LocalFs, moved: &[(PathBuf, PathBuf)]) -> Vec<String> {
    let mut left = Vec::new();
    for (src, dst) in moved.iter().rev() {
        if fs.move_path(dst, src).is_err() {
            left.push(dst.to_string_lossy().to_string());
        }
    }
    left
}

pub struct RelocateArgs<'a> {
    pub known: &'a dyn KnownFolders,
    pub data_dir: &'a Path,
    pub folder: KnownFolder,
    /// Name im Drive (Vorgabe: Name des Ordners unter `%USERPROFILE%`).
    pub name: Option<String>,
    pub device: &'a str,
}

/// Windows-Ordner in den Drive verlegen → `{folder, from, to, moved}`.
pub fn relocate(eng: &mut Engine, a: RelocateArgs, progress: Progress) -> Result<Value, ProtoError> {
    let fs = eng.fs();
    let root = eng.cfg.root.clone();
    let src = a.known.get(a.folder).map_err(|e| fail("known_folder", e))?;
    if is_under(&src, &root) {
        return Err(fail("already_relocated", "liegt schon im Drive"));
    }
    if is_under(&root, &src) {
        return Err(fail("contains_root", "der Ordner enthält den Drive-Ordner"));
    }
    match fs.stat(&src).map_err(|e| fail("local_io", e.to_string()))? {
        Some(l) if l.is_dir => {}
        _ => return Err(fail("folder_missing", src.to_string_lossy())),
    }
    let area = eng.personal_area().cloned().ok_or_else(|| fail("no_area", "„Meine Dateien“ fehlt"))?;
    if !area.writable() {
        return Err(fail("read_only", "„Meine Dateien“ nur lesbar"));
    }
    let area_dir = root.join(&area.dir);
    if !fs.stat(&area_dir).ok().flatten().is_some_and(|l| l.is_dir) {
        return Err(fail("no_area", area_dir.to_string_lossy()));
    }
    let leaf = a.name.clone().unwrap_or_else(|| {
        src.file_name().map(|n| n.to_string_lossy().to_string()).filter(|n| names::is_valid_name(n)).unwrap_or_else(|| a.folder.default_leaf().to_string())
    });
    if !names::is_valid_name(&leaf) {
        return Err(fail("invalid", "name"));
    }
    let target = area_dir.join(&leaf);
    let created = match fs.stat(&target).map_err(|e| fail("local_io", e.to_string()))? {
        Some(l) if l.is_dir => false,
        Some(_) => return Err(fail("target_taken", target.to_string_lossy())),
        None => {
            fs.create_dir(&target).map_err(|e| fail("local_io", format!("{}: {e}", target.display())))?;
            true
        }
    };
    let undo_target = |fs: &dyn LocalFs| {
        if created {
            let _ = fs.remove_dir(&target);
        }
    };
    let moved = match move_children(fs.as_ref(), &src, &target, a.device, progress) {
        Ok(m) => m,
        Err(e) => {
            if e.data.as_ref().and_then(|d| d["rolledBack"].as_bool()) == Some(true) {
                undo_target(fs.as_ref());
            }
            return Err(e);
        }
    };
    if let Err(e) = a.known.set(a.folder, &target) {
        let left = roll_back(fs.as_ref(), &moved);
        if left.is_empty() {
            undo_target(fs.as_ref());
        }
        return Err(fail("set_failed", e).with_data(json!({ "left": left })));
    }
    // leerer alter Ordner: weg (Zurücklegen legt ihn wieder an)
    if fs.list(&src).map(|v| v.is_empty()).unwrap_or(false) {
        let _ = fs.remove_dir(&src);
    }
    let mut rec = load_records(a.data_dir);
    rec.insert(a.folder.key().into(), Relocation { from: src.clone(), to: target.clone(), at: chrono::Utc::now().to_rfc3339() });
    let _ = save_records(a.data_dir, &rec);
    eng.queue_local(target.clone());
    for (_, dst) in &moved {
        eng.queue_local(dst.clone());
    }
    Ok(json!({ "folder": a.folder.key(), "from": src.to_string_lossy(), "to": target.to_string_lossy(), "moved": moved.len() }))
}

/// Alle Einträge unter `dir`, Ordner nach ihrem Inhalt (für das Zurückverwandeln).
fn bottom_up(fs: &dyn LocalFs, dir: &Path) -> Vec<(PathBuf, bool, bool)> {
    let mut out = Vec::new();
    if let Ok(list) = fs.list(dir) {
        for l in list {
            let p = dir.join(&l.name);
            if l.is_dir {
                out.extend(bottom_up(fs, &p));
            }
            out.push((p, l.is_dir, l.placeholder.is_some()));
        }
    }
    out
}

/// Verlegten Windows-Ordner zurücklegen → `{folder, from, to, moved}`.
pub fn restore(
    eng: &mut Engine,
    known: &dyn KnownFolders,
    data_dir: &Path,
    folder: KnownFolder,
    device: &str,
    progress: Progress,
) -> Result<Value, ProtoError> {
    let fs = eng.fs();
    let root = eng.cfg.root.clone();
    let cur = known.get(folder).map_err(|e| fail("known_folder", e))?;
    if !is_under(&cur, &root) || key(&cur) == key(&root) {
        return Err(fail("not_relocated", cur.to_string_lossy()));
    }
    if !fs.stat(&cur).ok().flatten().is_some_and(|l| l.is_dir) {
        return Err(fail("folder_missing", cur.to_string_lossy()));
    }
    let mut rec = load_records(data_dir);
    let dest = rec.get(folder.key()).map(|r| r.from.clone()).filter(|f| !is_under(f, &root)).unwrap_or_else(|| known.default_path(folder));
    if is_under(&dest, &root) {
        return Err(fail("invalid", dest.to_string_lossy()));
    }
    // 1. was noch hoch muss, zuerst hoch (scheitert es, bleibt es trotzdem lokal erhalten)
    let _ = eng.process_local();
    // 2. alles vollständig laden
    let missing = eng.not_hydrated(&cur);
    let total = missing.len() as u64;
    for (i, p) in missing.iter().enumerate() {
        if let Err(e) = fs.hydrate_now(p) {
            return Err(fail("hydrate_failed", format!("{}: {e}", p.display())).with_data(json!({ "path": p.to_string_lossy() })));
        }
        progress("load", i as u64 + 1, total);
    }
    // 3. Platzhalter → normale Dateien (Kinder vor Eltern)
    for (p, _is_dir, ph) in bottom_up(fs.as_ref(), &cur) {
        if ph {
            if let Err(e) = fs.revert_placeholder(&p) {
                eng.needs_full = true; // der Abgleich macht wieder Platzhalter daraus
                return Err(fail("revert_failed", format!("{}: {e}", p.display())).with_data(json!({ "path": p.to_string_lossy() })));
            }
        }
    }
    // 4. an den alten Ort
    match fs.stat(&dest).map_err(|e| fail("local_io", e.to_string()))? {
        Some(l) if l.is_dir => {}
        Some(_) => {
            eng.needs_full = true;
            return Err(fail("target_taken", dest.to_string_lossy()));
        }
        None => fs.create_dir(&dest).map_err(|e| {
            eng.needs_full = true;
            fail("local_io", format!("{}: {e}", dest.display()))
        })?,
    }
    let moved = match move_children(fs.as_ref(), &cur, &dest, device, progress) {
        Ok(m) => m,
        Err(e) => {
            eng.needs_full = true;
            return Err(e);
        }
    };
    if let Err(e) = known.set(folder, &dest) {
        let left = roll_back(fs.as_ref(), &moved);
        eng.needs_full = true;
        return Err(fail("set_failed", e).with_data(json!({ "left": left })));
    }
    // 5. Drive-Ordner wieder „nur online“ (nichts auf dem Server löschen)
    let node =
        fs.stat(&cur).ok().flatten().and_then(|l| l.identity().map(|i| i.node)).or_else(|| cur.strip_prefix(&root).ok().and_then(|r| eng.state.lookup(r)));
    match node {
        Some(id) => eng.forget_below(id),
        None => eng.needs_full = true,
    }
    rec.remove(folder.key());
    let _ = save_records(data_dir, &rec);
    Ok(json!({ "folder": folder.key(), "from": cur.to_string_lossy(), "to": dest.to_string_lossy(), "moved": moved.len() }))
}

/// Die Windows-Ordner mit ihrem Ort → `[{key, path, inDrive, from}]`.
pub fn list(known: &dyn KnownFolders, root: &Path, data_dir: &Path) -> Value {
    let rec = load_records(data_dir);
    let items: Vec<Value> = KnownFolder::ALL
        .into_iter()
        .map(|f| {
            let path = known.get(f).ok();
            let in_drive = path.as_ref().is_some_and(|p| is_under(p, root));
            json!({
                "key": f.key(),
                "path": path.as_ref().map(|p| p.to_string_lossy().to_string()),
                "inDrive": in_drive,
                "from": if in_drive { rec.get(f.key()).map(|r| r.from.to_string_lossy().to_string()) } else { None },
            })
        })
        .collect();
    json!({ "folders": items, "syncRoot": root.to_string_lossy() })
}

/// Belegter Platz: Dateien, deren Daten auf diesem PC liegen, und alle Dateien im Drive-Ordner.
pub fn usage(fs: &dyn LocalFs, root: &Path) -> Value {
    let (mut local, mut total, mut files, mut local_files, mut pinned) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(d) = stack.pop() {
        let Ok(list) = fs.list(&d) else { continue };
        for l in list {
            seen += 1;
            if seen > 2_000_000 {
                break;
            }
            if l.is_dir {
                stack.push(d.join(&l.name));
                continue;
            }
            files += 1;
            total += l.size;
            let here = l.placeholder.as_ref().is_none_or(|p| p.hydrated);
            if here {
                local += l.size;
                local_files += 1;
            }
            if l.placeholder.as_ref().is_some_and(|p| p.pin == super::localfs::Pin::Pinned) {
                pinned += 1;
            }
        }
    }
    json!({ "localBytes": local, "totalBytes": total, "files": files, "localFiles": local_files, "pinnedFiles": pinned })
}

#[cfg(test)]
#[path = "relocate_tests.rs"]
mod tests;
