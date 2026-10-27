//! Explorer-Kontextmenü „GateControl Drive ›“ mit „Link teilen …“, „Im Portal
//! öffnen“ und „Ältere Versionen“ – ohne Shell-Erweiterungs-DLL: statische
//! Verben unter `HKCU\Software\Classes\*\shell` (Dateien) und
//! `…\Directory\shell` (Ordner), begrenzt auf den Sync-Root über `AppliesTo`
//! (`System.ItemPathDisplay:~<"<Sync-Root>"`). Jeder Eintrag ruft
//! `gc-drive-sync.exe action <share|portal|versions> "%1"` auf; das reicht
//! über die Aktions-Pipe (actions.rs) an den laufenden Pro-Client weiter.
//!
//! Unter HKCU, damit kein Administrator nötig ist und es nur den Benutzer
//! betrifft, dem die Sync-Root gehört. Entfernt beim Abmelden (`unregister`,
//! auch bei der Deinstallation). Unter Windows 11 erscheinen statische Verben im
//! klassischen Menü („Weitere Optionen anzeigen“); das neue Menü nimmt nur
//! Erweiterungen mit Paket-Identität (MSIX) auf.

use super::util::wide_str;
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::System::Registry::*;

pub const VERB: &str = "GateControlDrive";
/// Pro-Client-Exe für den Aufruf, wenn gc-drive-sync nicht läuft.
pub const SETTINGS_KEY: &str = r"Software\GateControl\DriveSync";

struct Labels {
    menu: &'static str,
    share: &'static str,
    portal: &'static str,
    versions: &'static str,
}

fn labels(lang: Option<&str>) -> Labels {
    if lang == Some("en") {
        Labels { menu: "GateControl Drive", share: "Share link …", portal: "Open in portal", versions: "Previous versions" }
    } else {
        Labels { menu: "GateControl Drive", share: "Link teilen …", portal: "Im Portal öffnen", versions: "Ältere Versionen" }
    }
}

fn set(sub: &str, name: Option<&str>, value: &str) -> Result<(), String> {
    let k = wide_str(sub);
    let v = wide_str(value);
    let n = name.map(wide_str);
    let r = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            PCWSTR(k.as_ptr()),
            n.as_ref().map(|n| PCWSTR(n.as_ptr())).unwrap_or(PCWSTR::null()),
            REG_SZ.0,
            Some(v.as_ptr() as _),
            (v.len() * 2) as u32,
        )
    };
    if r != ERROR_SUCCESS {
        return Err(format!("{sub}: {}", r.0));
    }
    Ok(())
}

fn delete_tree(sub: &str) -> Result<(), String> {
    let k = wide_str(sub);
    let r = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(k.as_ptr())) };
    if r != ERROR_SUCCESS && r != ERROR_FILE_NOT_FOUND {
        return Err(format!("{sub}: {}", r.0));
    }
    Ok(())
}

pub fn get(sub: &str, name: &str) -> Option<String> {
    let k = wide_str(sub);
    let n = wide_str(name);
    let mut buf = vec![0u16; 2048];
    let mut len = (buf.len() * 2) as u32;
    let r =
        unsafe { RegGetValueW(HKEY_CURRENT_USER, PCWSTR(k.as_ptr()), PCWSTR(n.as_ptr()), RRF_RT_REG_SZ, None, Some(buf.as_mut_ptr() as _), Some(&mut len)) };
    if r != ERROR_SUCCESS {
        return None;
    }
    let chars = (len as usize / 2).saturating_sub(1);
    Some(String::from_utf16_lossy(&buf[..chars.min(buf.len())]))
}

fn class_keys(verb: &str) -> [String; 2] {
    [format!(r"Software\Classes\*\shell\{verb}"), format!(r"Software\Classes\Directory\shell\{verb}")]
}

/// AQS-Bedingung: Pfad beginnt mit dem Sync-Root.
pub fn applies_to(root: &Path) -> String {
    let r = root.to_string_lossy().trim_end_matches('\\').replace('"', "");
    format!("System.ItemPathDisplay:~<\"{r}\"")
}

/// Menü anlegen (überschreibt einen alten Stand). `verb`: Schlüsselname (Tests: eigener).
pub fn register(verb: &str, root: &Path, exe: &Path, app_exe: Option<&str>, lang: Option<&str>) -> Result<(), String> {
    let l = labels(lang);
    let exe_s = exe.to_string_lossy().replace('"', "");
    let icon = format!("{exe_s},0");
    let cond = applies_to(root);
    for (i, base) in class_keys(verb).iter().enumerate() {
        let is_dir = i == 1;
        delete_tree(base)?;
        set(base, Some("MUIVerb"), l.menu)?;
        set(base, Some("Icon"), &icon)?;
        set(base, Some("AppliesTo"), &cond)?;
        set(base, Some("SubCommands"), "")?;
        set(base, Some("MultiSelectModel"), "Single")?;
        let mut items = vec![("1share", "share", l.share), ("2portal", "portal", l.portal)];
        if !is_dir {
            items.push(("3versions", "versions", l.versions));
        }
        for (key, action, label) in items {
            let k = format!(r"{base}\shell\{key}");
            set(&k, Some("MUIVerb"), label)?;
            set(&format!(r"{k}\command"), None, &format!("\"{exe_s}\" action {action} \"%1\""))?;
        }
    }
    if let Some(a) = app_exe {
        set(SETTINGS_KEY, Some("AppExe"), a)?;
    }
    Ok(())
}

pub fn unregister(verb: &str) -> Result<(), String> {
    for base in class_keys(verb) {
        delete_tree(&base)?;
    }
    if verb == VERB {
        delete_tree(SETTINGS_KEY)?;
    }
    Ok(())
}

/// Für Tests und `info`: Befehl eines Eintrags.
pub fn command_of(verb: &str, dir: bool, item: &str) -> Option<String> {
    let base = &class_keys(verb)[usize::from(dir)];
    get(&format!(r"{base}\shell\{item}\command"), "")
}

pub fn applies_of(verb: &str) -> Option<String> {
    get(&class_keys(verb)[0], "AppliesTo")
}
