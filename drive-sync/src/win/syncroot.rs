//! Sync-Root registrieren / abmelden.
//!
//! Zuerst über WinRT (`StorageProviderSyncRootManager.Register`) – das legt den
//! Eintrag im Navigationsbereich des Explorers mit Namen und Symbol an. Klappt
//! das nicht (z. B. ohne Shell in einer Dienst-Sitzung), über
//! `CfRegisterSyncRoot` (Win32, ohne Explorer-Eintrag).
//!
//! Richtlinien:
//!   * Hydration „Progressive“: Ein Programm kann lesen, sobald der
//!     angefragte Bereich da ist (große Videos starten sofort); Windows fordert
//!     die Bereiche per FETCH_DATA an, wir laden sie mit HTTP Range.
//!   * Population „AlwaysFull“: Das Programm legt alle Platzhalter selbst an
//!     (aus `children` und dem Änderungsprotokoll), Windows ruft nie
//!     FETCH_PLACEHOLDERS. Begründung in README.md („Warum AlwaysFull“).

use super::util::{hstring, wide, wide_str};
use std::path::{Path, PathBuf};
use windows::core::{GUID, HSTRING, PCWSTR};
use windows::Security::Cryptography::{BinaryStringEncoding, CryptographicBuffer};
use windows::Storage::Provider::*;
use windows::Storage::StorageFolder;
use windows::Win32::Storage::CloudFilters::*;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

pub const PROVIDER_NAME: &str = "GateControl Drive";
/// Feste Anbieter-ID von GateControl Drive.
pub const PROVIDER_ID: GUID = GUID::from_u128(0x6c1f5d2e_8b4a_4f3e_9a7d_3e2b1c0d9f84);

#[derive(Debug, Clone)]
pub struct SyncRootSpec {
    pub id: String,
    pub root: PathBuf,
    pub display_name: String,
    /// „C:\…\gc-drive-sync.exe,0“
    pub icon: String,
    pub version: String,
}

/// „GateControlDrive!<SID>!default“ – eine Sync-Root je Windows-Benutzer.
pub fn sync_root_id(sid: &str) -> String {
    format!("GateControlDrive!{sid}!default")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registered {
    WinRt,
    Win32,
}

pub fn register(spec: &SyncRootSpec) -> Result<Registered, String> {
    std::fs::create_dir_all(&spec.root).map_err(|e| format!("Ordner: {e}"))?;
    match register_winrt(spec) {
        Ok(()) => Ok(Registered::WinRt),
        Err(e1) => match register_cf(spec) {
            Ok(()) => Ok(Registered::Win32),
            Err(e2) => Err(format!("StorageProviderSyncRootManager: {e1}; CfRegisterSyncRoot: {e2}")),
        },
    }
}

fn register_winrt(spec: &SyncRootSpec) -> windows::core::Result<()> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }
    let folder = StorageFolder::GetFolderFromPathAsync(&hstring(&spec.root))?.join()?;
    let info = StorageProviderSyncRootInfo::new()?;
    info.SetId(&HSTRING::from(spec.id.as_str()))?;
    info.SetPath(&folder)?;
    info.SetDisplayNameResource(&HSTRING::from(spec.display_name.as_str()))?;
    info.SetIconResource(&HSTRING::from(spec.icon.as_str()))?;
    info.SetHydrationPolicy(StorageProviderHydrationPolicy::Progressive)?;
    info.SetHydrationPolicyModifier(StorageProviderHydrationPolicyModifier::None)?;
    info.SetPopulationPolicy(StorageProviderPopulationPolicy::AlwaysFull)?;
    info.SetInSyncPolicy(StorageProviderInSyncPolicy::Default)?;
    info.SetHardlinkPolicy(StorageProviderHardlinkPolicy::None)?;
    info.SetVersion(&HSTRING::from(spec.version.as_str()))?;
    info.SetShowSiblingsAsGroup(false)?;
    info.SetProtectionMode(StorageProviderProtectionMode::Personal)?;
    info.SetAllowPinning(true)?;
    info.SetProviderId(PROVIDER_ID)?;
    let ctx = CryptographicBuffer::ConvertStringToBinary(&HSTRING::from(spec.id.as_str()), BinaryStringEncoding::Utf8)?;
    info.SetContext(&ctx)?;
    StorageProviderSyncRootManager::Register(&info)
}

fn register_cf(spec: &SyncRootSpec) -> windows::core::Result<()> {
    let name = wide_str(PROVIDER_NAME);
    let version = wide_str(&spec.version);
    let ident = spec.id.as_bytes();
    let reg = CF_SYNC_REGISTRATION {
        StructSize: std::mem::size_of::<CF_SYNC_REGISTRATION>() as u32,
        ProviderName: PCWSTR(name.as_ptr()),
        ProviderVersion: PCWSTR(version.as_ptr()),
        SyncRootIdentity: ident.as_ptr() as _,
        SyncRootIdentityLength: ident.len() as u32,
        FileIdentity: std::ptr::null(),
        FileIdentityLength: 0,
        ProviderId: PROVIDER_ID,
    };
    let policies = CF_SYNC_POLICIES {
        StructSize: std::mem::size_of::<CF_SYNC_POLICIES>() as u32,
        Hydration: CF_HYDRATION_POLICY { Primary: CF_HYDRATION_POLICY_PROGRESSIVE, Modifier: CF_HYDRATION_POLICY_MODIFIER_NONE },
        Population: CF_POPULATION_POLICY { Primary: CF_POPULATION_POLICY_ALWAYS_FULL, Modifier: CF_POPULATION_POLICY_MODIFIER_NONE },
        InSync: CF_INSYNC_POLICY_NONE,
        HardLink: CF_HARDLINK_POLICY_NONE,
        PlaceholderManagement: CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
    };
    let root = wide(&spec.root);
    unsafe {
        CfRegisterSyncRoot(PCWSTR(root.as_ptr()), &reg, &policies, CF_REGISTER_FLAG_NONE)
            .or_else(|_| CfRegisterSyncRoot(PCWSTR(root.as_ptr()), &reg, &policies, CF_REGISTER_FLAG_UPDATE))
    }
}

/// Ist `root` eine registrierte Sync-Root?
pub fn is_registered(root: &Path) -> bool {
    let w = wide(root);
    let mut buf = [0u8; 64];
    unsafe { CfGetSyncRootInfoByPath(PCWSTR(w.as_ptr()), CF_SYNC_ROOT_INFO_BASIC, buf.as_mut_ptr() as _, buf.len() as u32, None).is_ok() }
}

pub fn unregister(id: &str, root: &Path) -> Result<(), String> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }
    let winrt = StorageProviderSyncRootManager::Unregister(&HSTRING::from(id));
    if winrt.is_ok() && !is_registered(root) {
        return Ok(());
    }
    let w = wide(root);
    match unsafe { CfUnregisterSyncRoot(PCWSTR(w.as_ptr())) } {
        Ok(()) => Ok(()),
        Err(e) if !is_registered(root) => {
            let _ = e;
            Ok(())
        }
        Err(e) => Err(format!("{}; {e}", winrt.err().map(|x| x.to_string()).unwrap_or_default())),
    }
}

/// Ist die Cloud Files API hier nutzbar (Filtertreiber cldflt geladen)?
pub fn platform_info() -> Result<(u32, u32, u32), String> {
    unsafe { CfGetPlatformInfo().map(|i| (i.BuildNumber, i.RevisionNumber, i.IntegrationNumber)).map_err(|e| e.to_string()) }
}
