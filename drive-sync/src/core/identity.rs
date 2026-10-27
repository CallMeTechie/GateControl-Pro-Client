//! FileIdentity der Platzhalter: Windows speichert sie am Platzhalter und gibt
//! sie in jedem Rückruf (FETCH_DATA, NOTIFY_DELETE, …) wieder mit.
//!
//! Inhalt: Knoten-ID, `rev`, Bereich und Medien-ID der Fassung, die der
//! Platzhalter beschreibt. Damit weiß ein Rückruf ohne Nachschlagen, welche
//! Bytes er laden muss, und erkennt, wenn der Server inzwischen eine neuere
//! Fassung hat. Kodiert als kleines JSON (lesbar, erweiterbar, ≤ 4 KiB).

use serde::{Deserialize, Serialize};

/// Höchstlänge laut Cloud Files API (CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH).
pub const MAX_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Format-Version (1).
    #[serde(rename = "v")]
    pub version: u8,
    #[serde(rename = "n")]
    pub node: u64,
    #[serde(rename = "r")]
    pub rev: u64,
    #[serde(rename = "a")]
    pub area: String,
    #[serde(rename = "m", default, skip_serializing_if = "Option::is_none")]
    pub media: Option<String>,
}

impl Identity {
    pub fn new(node: u64, rev: u64, area: &str, media: Option<&str>) -> Identity {
        Identity { version: 1, node, rev, area: area.to_string(), media: media.map(str::to_string) }
    }

    pub fn encode(&self) -> Vec<u8> {
        let v = serde_json::to_vec(self).unwrap_or_default();
        debug_assert!(v.len() <= MAX_LEN);
        v
    }

    /// `None` für fremde oder kaputte Daten (z. B. Platzhalter einer älteren Fassung).
    pub fn decode(bytes: &[u8]) -> Option<Identity> {
        if bytes.is_empty() || bytes.len() > MAX_LEN {
            return None;
        }
        let id: Identity = serde_json::from_slice(bytes).ok()?;
        if id.version != 1 || id.node == 0 {
            return None;
        }
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let id = Identity::new(42, 3, "team:1", Some("abcDEF_-12"));
        let b = id.encode();
        assert_eq!(std::str::from_utf8(&b).unwrap(), r#"{"v":1,"n":42,"r":3,"a":"team:1","m":"abcDEF_-12"}"#);
        assert_eq!(Identity::decode(&b), Some(id));
        let dir = Identity::new(5, 1, "mine:2", None);
        assert_eq!(Identity::decode(&dir.encode()), Some(dir));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(Identity::decode(b""), None);
        assert_eq!(Identity::decode(b"\x01\x02"), None);
        assert_eq!(Identity::decode(br#"{"v":2,"n":1,"r":1,"a":"x"}"#), None);
        assert_eq!(Identity::decode(br#"{"v":1,"n":0,"r":1,"a":"x"}"#), None);
        assert_eq!(Identity::decode(&vec![b' '; MAX_LEN + 1]), None);
    }
}
