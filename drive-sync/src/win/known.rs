//! Windows-Ordner (Known Folders) des angemeldeten Benutzers:
//! `SHGetKnownFolderPath` / `SHSetKnownFolderPath` (wirkt auf HKCU – deshalb
//! muss gc-drive-sync mit den Rechten des Benutzers laufen, siehe launch.rs).
//!
//! Für Tests lässt sich statt der echten Ordner eine Tabelle setzen
//! (`WinKnown::fake`), dann bleibt die Registry unberührt.

use super::util::wide;
use crate::core::protocol::KnownFolder;
use crate::core::relocate::KnownFolders;
use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use windows::core::{GUID, PCWSTR};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::*;

pub fn folder_id(f: KnownFolder) -> GUID {
    match f {
        KnownFolder::Desktop => FOLDERID_Desktop,
        KnownFolder::Documents => FOLDERID_Documents,
        KnownFolder::Pictures => FOLDERID_Pictures,
        KnownFolder::Videos => FOLDERID_Videos,
        KnownFolder::Music => FOLDERID_Music,
    }
}

pub fn get_real(f: KnownFolder) -> Result<PathBuf, String> {
    unsafe {
        let p = SHGetKnownFolderPath(&folder_id(f), KF_FLAG_DONT_VERIFY, None).map_err(|e| e.to_string())?;
        let s = p.as_wide();
        let out = PathBuf::from(OsString::from_wide(s));
        CoTaskMemFree(Some(p.0 as _));
        Ok(out)
    }
}

pub fn set_real(f: KnownFolder, path: &Path) -> Result<(), String> {
    let w = wide(path);
    unsafe { SHSetKnownFolderPath(&folder_id(f), 0, None, PCWSTR(w.as_ptr())) }.map_err(|e| e.to_string())
}

pub struct WinKnown {
    fake: Option<Mutex<HashMap<KnownFolder, PathBuf>>>,
    profile: PathBuf,
}

impl WinKnown {
    pub fn real() -> WinKnown {
        let profile = std::env::var_os("USERPROFILE").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Users\Public"));
        WinKnown { fake: None, profile }
    }

    /// Tests: Ordner unter `base` statt der echten Windows-Ordner.
    pub fn fake(base: &Path) -> WinKnown {
        let m = KnownFolder::ALL.into_iter().map(|f| (f, base.join(f.default_leaf()))).collect();
        WinKnown { fake: Some(Mutex::new(m)), profile: base.to_path_buf() }
    }
}

impl KnownFolders for WinKnown {
    fn get(&self, f: KnownFolder) -> Result<PathBuf, String> {
        match &self.fake {
            Some(m) => m.lock().unwrap().get(&f).cloned().ok_or_else(|| "unknown".into()),
            None => get_real(f),
        }
    }
    fn set(&self, f: KnownFolder, path: &Path) -> Result<(), String> {
        match &self.fake {
            Some(m) => {
                m.lock().unwrap().insert(f, path.to_path_buf());
                Ok(())
            }
            None => set_real(f, path),
        }
    }
    fn default_path(&self, f: KnownFolder) -> PathBuf {
        self.profile.join(f.default_leaf())
    }
}

/// Dem Explorer melden, dass sich Ordner geändert haben (Desktop neu zeichnen).
pub fn notify(paths: &[PathBuf]) {
    unsafe {
        for p in paths {
            let w = wide(p);
            SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW | SHCNF_FLUSHNOWAIT, Some(w.as_ptr() as _), None);
        }
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST | SHCNF_FLUSHNOWAIT, None, None);
    }
}
