//! Dateinamen: was Windows und der Server annehmen, Konfliktkopien,
//! Ordnernamen der Bereiche, Dateien, die nie hochgeladen werden.

/// Zeichen, die weder Windows noch das Plugin in Namen erlauben.
const BAD_CHARS: &[char] = &['/', '\\', ':', '*', '?', '"', '<', '>', '|'];

/// Unter Windows reservierte Gerätenamen (auch mit Endung, „CON.txt“).
const RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7",
    "lpt8", "lpt9",
];

/// Höchstlänge eines Namens (Zeichen) wie beim Plugin.
pub const MAX_NAME: usize = 255;

/// Ein Name, den Windows als Datei-/Ordnername annimmt und der Server auch.
pub fn is_valid_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." || name.chars().count() > MAX_NAME {
        return false;
    }
    if name.chars().any(|c| BAD_CHARS.contains(&c) || (c as u32) < 32) {
        return false;
    }
    if name.ends_with('.') || name.ends_with(' ') || name.starts_with(' ') {
        return false;
    }
    if name.eq_ignore_ascii_case(".gcdrive") {
        return false;
    }
    let stem = name.split('.').next().unwrap_or("").trim_end().to_ascii_lowercase();
    !RESERVED.contains(&stem.as_str())
}

/// Gleich unter Windows-Regeln (ohne Beachtung von Groß/Klein).
pub fn same_name(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b) || a.to_lowercase() == b.to_lowercase()
}

/// Schlüssel für Nachschlagen ohne Groß/Klein.
pub fn key(name: &str) -> String {
    name.to_lowercase()
}

/// Dateien, die Programme nur zwischendurch anlegen (Office-Sperrdateien,
/// Explorer-Metadaten, Download-Reste): werden nie hochgeladen.
pub fn is_ignored(name: &str) -> bool {
    let l = name.to_lowercase();
    l.starts_with("~$")
        || l.starts_with(".~lock.")
        || l == "desktop.ini"
        || l == "thumbs.db"
        || l == ".ds_store"
        || l.ends_with(".tmp")
        || l.ends_with(".crdownload")
        || l.ends_with(".partial")
        || l.ends_with(".gcpart")
        || (l.starts_with('~') && l.ends_with(".tmp"))
}

/// Ordnername für einen Bereich aus seiner Bezeichnung: verbotene Zeichen
/// werden zu „_“, Punkte/Leerzeichen am Ende entfallen; leer → „Bereich“.
pub fn dir_name_for_label(label: &str) -> String {
    let mut s: String = label.chars().map(|c| if BAD_CHARS.contains(&c) || (c as u32) < 32 { '_' } else { c }).collect();
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    let s = s.trim_start().to_string();
    let s: String = s.chars().take(80).collect();
    if s.is_empty() || !is_valid_name(&s) {
        if s.is_empty() {
            return "Bereich".to_string();
        }
        return format!("_{s}");
    }
    s
}

/// „Brief.pdf“ → („Brief“, „.pdf“); „Ordner“ → („Ordner“, „“). Wie das Plugin
/// (`numbered`): eine Endung zählt nur bis 16 Zeichen und nicht am Anfang.
pub fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(dot) if dot > 0 && name.len() - dot <= 16 => (&name[..dot], &name[dot..]),
        _ => (name, ""),
    }
}

/// Gerätename für Konfliktkopien: nur erlaubte Zeichen, höchstens 40.
pub fn clean_device(device: &str) -> String {
    let s: String = device.chars().filter(|c| !BAD_CHARS.contains(c) && (*c as u32) >= 32 && *c != '(' && *c != ')').take(40).collect();
    let s = s.trim().to_string();
    if s.is_empty() {
        "PC".to_string()
    } else {
        s
    }
}

/// „Name (Konflikt <Gerät> <Datum>).ext“ – `when` als „JJJJ-MM-TT HH-MM“
/// (Doppelpunkte sind in Windows-Namen verboten), `n` > 1 hängt „ n“ an.
/// Zu lange Namen werden am Stamm gekürzt.
pub fn conflict_name(name: &str, device: &str, when: &str, n: u32) -> String {
    let (stem, ext) = split_ext(name);
    let suffix = if n > 1 { format!(" (Konflikt {} {} {})", clean_device(device), when, n) } else { format!(" (Konflikt {} {})", clean_device(device), when) };
    let room = MAX_NAME.saturating_sub(suffix.chars().count() + ext.chars().count());
    let stem: String = stem.chars().take(room.max(1)).collect();
    let mut out = format!("{stem}{suffix}{ext}");
    while out.ends_with('.') || out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Datum für Konfliktnamen aus Ortszeit.
pub fn conflict_stamp(t: chrono::DateTime<chrono::Local>) -> String {
    t.format("%Y-%m-%d %H-%M").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert!(is_valid_name("Brief.pdf"));
        assert!(is_valid_name("Kinder · Lena"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("a:b"));
        assert!(!is_valid_name("a?"));
        assert!(!is_valid_name("ende."));
        assert!(!is_valid_name("ende "));
        assert!(!is_valid_name("CON"));
        assert!(!is_valid_name("con.txt"));
        assert!(!is_valid_name("LPT1.doc"));
        assert!(is_valid_name("console.txt"));
        assert!(!is_valid_name(".gcdrive"));
        assert!(!is_valid_name(&"x".repeat(256)));
        assert!(is_valid_name(&"x".repeat(255)));
        assert!(!is_valid_name("tab\tname"));
    }

    #[test]
    fn ignored() {
        assert!(is_ignored("~$Bericht.docx"));
        assert!(is_ignored("Thumbs.db"));
        assert!(is_ignored("desktop.ini"));
        assert!(is_ignored("x.TMP"));
        assert!(is_ignored(".~lock.Tabelle.ods#"));
        assert!(!is_ignored("Bericht.docx"));
    }

    #[test]
    fn same_name_ignores_case() {
        assert!(same_name("Brief.PDF", "brief.pdf"));
        assert!(same_name("Ärger", "ärger"));
        assert!(!same_name("a", "b"));
        assert_eq!(key("ÄB"), "äb");
    }

    #[test]
    fn area_dirs() {
        assert_eq!(dir_name_for_label("Meine Dateien"), "Meine Dateien");
        assert_eq!(dir_name_for_label("A/B: C"), "A_B_ C");
        assert_eq!(dir_name_for_label("Team. "), "Team");
        assert_eq!(dir_name_for_label(""), "Bereich");
        assert_eq!(dir_name_for_label("CON"), "_CON");
    }

    #[test]
    fn conflict_names() {
        assert_eq!(conflict_name("Bericht.docx", "PC-Max", "2026-10-27 14-05", 1), "Bericht (Konflikt PC-Max 2026-10-27 14-05).docx");
        assert_eq!(conflict_name("Notizen", "PC", "2026-10-27 14-05", 2), "Notizen (Konflikt PC 2026-10-27 14-05 2)");
        assert_eq!(conflict_name(".bashrc", "PC", "d", 1), ".bashrc (Konflikt PC d)");
        assert_eq!(conflict_name("a.b.tar.gz", "Büro: PC*1", "d", 1), "a.b.tar (Konflikt Büro PC1 d).gz");
        assert_eq!(conflict_name("x", "", "d", 1), "x (Konflikt PC d)");
        let long = conflict_name(&format!("{}.txt", "a".repeat(300)), "PC", "2026-10-27 14-05", 1);
        assert_eq!(long.chars().count(), MAX_NAME);
        assert!(long.ends_with(" (Konflikt PC 2026-10-27 14-05).txt"));
        assert!(is_valid_name(&long));
    }

    #[test]
    fn stamp_format() {
        use chrono::TimeZone;
        let t = chrono::Local.with_ymd_and_hms(2026, 10, 27, 14, 5, 9).unwrap();
        assert_eq!(conflict_stamp(t), "2026-10-27 14-05");
    }

    #[test]
    fn ext_split() {
        assert_eq!(split_ext("a.pdf"), ("a", ".pdf"));
        assert_eq!(split_ext(".env"), (".env", ""));
        assert_eq!(split_ext("noext"), ("noext", ""));
        assert_eq!(split_ext("a.verylongextensionname"), ("a.verylongextensionname", ""));
    }
}
