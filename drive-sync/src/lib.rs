//! gc-drive-sync – GateControl Drive im Windows-Explorer (Dateien bei Bedarf).
//!
//! `core`: alles ohne Windows (Abgleich, Zustand, Pipe-Protokoll, HTTP-Client,
//! Laden in Stücken) – mit `cargo test` auf jedem System prüfbar.
//! `win`: Cloud Files API, Sync-Root, Dateisystem-Beobachtung, benannte Pipe.

pub mod core {
    pub mod api;
    pub mod engine;
    pub mod guard;
    pub mod hydrate;
    pub mod identity;
    pub mod localfs;
    pub mod model;
    pub mod names;
    pub mod protocol;
    pub mod relocate;
    pub mod remote;
    pub mod service;
    pub mod state;
    pub mod testing;
}

#[cfg(windows)]
pub mod win;
