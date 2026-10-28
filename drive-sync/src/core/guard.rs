//! Schutz vor Erpressungstrojanern auf dem PC (Drive 1.6 `guard`), dieselben
//! Regeln wie core `utils/drive-guard.js` und die Schwellen des Servers:
//!
//!   * Entropie: Shannon-Entropie (Bit je Byte, 0 … 8) der ersten 64 KB einer
//!     Datei. Verschlüsselte Bytes liegen nahe 8. Geht mit jedem Commit mit
//!     (`entropy`, nur an Drives mit `guard`).
//!   * Eine geänderte Datei ist verdächtig, wenn ihr Inhalt jetzt hoch-entropisch
//!     ist (> 7,5), vorher aber nicht: die Entropie der letzten Fassung ist bekannt
//!     und < 7,0 – oder unbekannt und der Dateityp ist keiner, der ohnehin
//!     komprimiert ist (.docx, .zip, .jpg, .mp4, .pdf …).
//!   * Eine Datei, die eine bekannte Ransomware-Endung bekommt
//!     („Brief.docx“ → „Brief.docx.locked“), ist verdächtig.
//!   * Ein Durchlauf schlägt an bei mindestens 50 verdächtigen Dateien oder
//!     mindestens 20 % eines Ordners mit mindestens 20 Dateien: dann geht nichts
//!     hoch, der Pro-Client fragt („Hochladen“ / „Pausiert lassen“).

use std::collections::HashMap;

pub const ENTROPY_BYTES: usize = 64 * 1024;
pub const ENTROPY_HIGH: f64 = 7.5;
pub const ENTROPY_WAS_LOW: f64 = 7.0;
pub const GUARD_COUNT: usize = 50;
pub const GUARD_SHARE: f64 = 0.2;
pub const GUARD_DIR_MIN: usize = 20;
const SAMPLE_MAX: usize = 5;

const COMPRESSED_EXT: &[&str] = &[
    "zip", "7z", "rar", "gz", "tgz", "bz2", "xz", "zst", "lz", "lzma", "cab", "jar", "apk", "aab", "ipa", "msi", "msix", "appx", "dmg", "pkg", "deb", "rpm",
    "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "odt", "ods", "odp", "odg", "epub", "pages", "numbers", "key", "vsdx", "xps", "oxps", "pdf", "jpg", "jpeg",
    "png", "gif", "webp", "heic", "heif", "avif", "jxl", "jp2", "mp3", "m4a", "aac", "ogg", "oga", "opus", "flac", "wma", "mp4", "m4v", "mov", "mkv", "webm",
    "avi", "wmv", "3gp", "flv", "mts", "m2ts", "woff", "woff2", "kdbx", "gpg", "pgp", "asc", "p12", "pfx", "vhdx", "vmdk", "qcow2", "iso", "img",
];

const RANSOM_EXT: &[&str] = &[
    "locked",
    "locky",
    "encrypted",
    "enc",
    "crypt",
    "crypted",
    "crypto",
    "cryp1",
    "crypz",
    "cryptolocker",
    "encr",
    "enciphered",
    "cerber",
    "cerber2",
    "cerber3",
    "zepto",
    "odin",
    "thor",
    "aesir",
    "osiris",
    "wncry",
    "wnry",
    "wcry",
    "wncryt",
    "ryk",
    "ryuk",
    "conti",
    "lockbit",
    "lockbit3",
    "djvu",
    "djvuu",
    "krab",
    "gdcb",
    "crab",
    "sage",
    "dharma",
    "phobos",
    "eking",
    "makop",
    "clop",
    "cl0p",
    "hive",
    "avos",
    "avos2",
    "akira",
    "babyk",
    "royal_w",
    "rhysida",
    "8base",
    "medusa",
    "blacksuit",
    "basta",
    "xtbl",
    "vvv",
    "ecc",
    "ezz",
    "exx",
    "zzz",
    "ttt",
    "xxx",
    "ccc",
    "r5a",
    "r4a",
    "crinf",
    "lechiffre",
    "keybtc",
    "kraken",
    "nochance",
    "toxcrypt",
    "rokku",
    "zcrypt",
    "rdm",
    "rrk",
    "kkk",
    "btc",
    "gws",
    "ctbl",
    "ctb2",
    "cbf",
    "good",
    "weapologize",
    "lol!",
    "omg!",
    "petya",
    "globe",
    "purge",
    "darkness",
    "payms",
    "paymst",
    "paybtcs",
    "locklock",
    "coded",
    "payrms",
    "ha3",
    "nemty",
    "sodinokibi",
    "revil",
    "maze",
    "egregor",
    "ragnar",
    "mountlocker",
    "blackmatter",
    "darkside",
    "netwalker",
    "stop",
    "qlkm",
    "lokf",
    "pcqq",
];

/// Endung in Kleinbuchstaben (ohne Punkt), leer ohne Endung.
pub fn ext_of(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    match base.rfind('.') {
        Some(i) if i > 0 => base[i + 1..].to_lowercase(),
        _ => String::new(),
    }
}

/// Shannon-Entropie (Bit je Byte, auf drei Stellen); `None` ohne Inhalt.
pub fn entropy(buf: &[u8]) -> Option<f64> {
    if buf.is_empty() {
        return None;
    }
    let mut counts = [0u64; 256];
    for b in buf {
        counts[*b as usize] += 1;
    }
    let len = buf.len() as f64;
    let mut h = 0.0;
    for c in counts.iter().filter(|c| **c > 0) {
        let p = *c as f64 / len;
        h -= p * p.log2();
    }
    Some((h * 1000.0).round() / 1000.0)
}

/// Für den Zustand: Tausendstel Bit je Byte (0 … 8000).
pub fn milli(e: f64) -> u16 {
    (e.clamp(0.0, 8.0) * 1000.0).round() as u16
}

pub fn from_milli(m: u16) -> f64 {
    f64::from(m) / 1000.0
}

pub fn is_compressed(name: &str) -> bool {
    COMPRESSED_EXT.contains(&ext_of(name).as_str())
}

pub fn is_ransom_ext(name: &str) -> bool {
    RANSOM_EXT.contains(&ext_of(name).as_str())
}

/// Ist eine geänderte Datei mit diesem Inhalt verdächtig?
pub fn suspicious_change(name: &str, entropy: Option<f64>, prev: Option<f64>) -> bool {
    let Some(e) = entropy else { return false };
    if e <= ENTROPY_HIGH {
        return false;
    }
    match prev {
        Some(p) => p < ENTROPY_WAS_LOW,
        None => !is_compressed(name),
    }
}

/// Entstand `new_name` aus einem von `old_names` mit einer Ransomware-Endung?
pub fn ransom_rename(new_name: &str, old_names: &[String]) -> bool {
    let n = new_name.to_lowercase();
    if !is_ransom_ext(&n) {
        return false;
    }
    old_names.iter().any(|o| {
        let o = o.to_lowercase();
        !o.is_empty() && n != o && n.starts_with(&format!("{o}."))
    })
}

/// Ergebnis der Prüfung eines Durchlaufs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trip {
    pub trip: bool,
    pub count: usize,
    pub sample: Vec<String>,
}

/// `items`: verdächtige Änderungen (Ordner-Schlüssel, Name); `files_in`: Dateien eines Ordners.
pub fn trips(items: &[(String, String)], files_in: impl Fn(&str) -> usize) -> Trip {
    let count = items.len();
    let mut trip = count >= GUARD_COUNT;
    if !trip {
        let mut by_dir: HashMap<&str, usize> = HashMap::new();
        for (d, _) in items {
            *by_dir.entry(d.as_str()).or_default() += 1;
        }
        trip = by_dir.iter().any(|(d, n)| {
            let total = files_in(d).max(*n);
            total >= GUARD_DIR_MIN && *n as f64 >= GUARD_SHARE * total as f64
        });
    }
    Trip { trip, count, sample: items.iter().take(SAMPLE_MAX).map(|(_, n)| n.clone()).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_text_and_random() {
        assert_eq!(entropy(&[]), None);
        assert_eq!(entropy(&[7u8; 1000]), Some(0.0));
        let text = "Zeile: Das ist ein ganz normaler Brief mit Text.\n".repeat(200);
        assert!(entropy(text.as_bytes()).unwrap() < 5.0);
        let all: Vec<u8> = (0..65536u32).map(|i| (i % 256) as u8).collect();
        assert_eq!(entropy(&all), Some(8.0));
        assert_eq!(from_milli(milli(7.123)), 7.123);
        assert_eq!(milli(9.0), 8000);
    }

    #[test]
    fn suspicious_changes() {
        assert!(suspicious_change("Brief.txt", Some(7.99), None));
        assert!(suspicious_change("Brief.txt", Some(7.99), Some(4.2)));
        assert!(!suspicious_change("Brief.txt", Some(7.99), Some(7.9)));
        assert!(!suspicious_change("Brief.txt", Some(6.0), None));
        assert!(!suspicious_change("Foto.JPG", Some(7.99), None));
        assert!(suspicious_change("Bericht.docx", Some(7.95), Some(5.0)));
        assert!(!suspicious_change("Brief.txt", None, None));
    }

    #[test]
    fn ransom_renames() {
        let old = vec!["Brief.docx".to_string()];
        assert!(ransom_rename("brief.docx.locked", &old));
        assert!(ransom_rename("Brief.docx.id-1E2D.[x@y].eking", &old));
        assert!(!ransom_rename("Brief.docx.bak", &old));
        assert!(!ransom_rename("andere.docx.locked", &old));
        assert!(!ransom_rename("notes.enc", &[]));
        assert_eq!(ext_of("a/b.TXT"), "txt");
        assert_eq!(ext_of(".profile"), "");
    }

    #[test]
    fn thresholds() {
        let many = |n: usize, d: &str| (0..n).map(|i| (d.to_string(), format!("f{i}"))).collect::<Vec<_>>();
        assert!(trips(&many(50, "a"), |_| 100_000).trip);
        assert!(!trips(&many(49, "a"), |_| 100_000).trip);
        assert!(trips(&many(4, "a"), |_| 20).trip);
        assert!(!trips(&many(3, "a"), |_| 20).trip);
        assert!(!trips(&many(5, "a"), |_| 19).trip);
        let t = trips(&many(10, "a"), |_| 20);
        assert_eq!((t.count, t.sample.len()), (10, 5));
    }
}
