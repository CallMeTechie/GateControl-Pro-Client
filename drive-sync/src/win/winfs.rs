//! `LocalFs` mit Platzhaltern der Cloud Files API.

use super::util::{filetime_to_ms, ms_to_filetime, wide, wide_str, OwnedHandle};
use crate::core::identity::Identity;
use crate::core::localfs::*;
use crate::core::remote::ReadAt;
use std::collections::HashSet;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use windows::core::{HRESULT, PCWSTR};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Storage::CloudFilters::*;
use windows::Win32::Storage::FileSystem::*;

const WRITE_DAC: u32 = 0x0004_0000;
const ERROR_CLOUD_FILE_PINNED: i32 = 390;

pub fn werr(e: windows::core::Error) -> io::Error {
    let code = e.code().0 as u32;
    if code & 0xFFFF_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((code & 0xFFFF) as i32)
    } else {
        io::Error::other(format!("{e} (0x{code:08X})"))
    }
}

fn ft(f: FILETIME) -> i64 {
    ((f.dwHighDateTime as i64) << 32) | f.dwLowDateTime as i64
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub struct WinFs {
    hydrating: Arc<Mutex<HashSet<PathBuf>>>,
}

impl Default for WinFs {
    fn default() -> Self {
        Self::new()
    }
}

impl WinFs {
    pub fn new() -> WinFs {
        WinFs { hydrating: Arc::new(Mutex::new(HashSet::new())) }
    }

    fn open(path: &Path, access: u32) -> io::Result<OwnedHandle> {
        let w = wide(path);
        let h = unsafe {
            CreateFileW(
                PCWSTR(w.as_ptr()),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        }
        .map_err(werr)?;
        Ok(OwnedHandle(h))
    }

    fn find(path: &Path) -> io::Result<Option<WIN32_FIND_DATAW>> {
        let w = wide(path);
        let mut d = WIN32_FIND_DATAW::default();
        match unsafe { FindFirstFileW(PCWSTR(w.as_ptr()), &mut d) } {
            Ok(h) => {
                unsafe {
                    let _ = FindClose(h);
                }
                Ok(Some(d))
            }
            Err(e) => {
                let ioe = werr(e);
                match ioe.raw_os_error() {
                    Some(2) | Some(3) | Some(18) => Ok(None),
                    _ => Err(ioe),
                }
            }
        }
    }

    fn entry(path: &Path, d: &WIN32_FIND_DATAW) -> LocalEntry {
        let name_len = d.cFileName.iter().position(|c| *c == 0).unwrap_or(d.cFileName.len());
        let name = String::from_utf16_lossy(&d.cFileName[..name_len]);
        let attrs = d.dwFileAttributes;
        let is_dir = attrs & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
        let tag = if attrs & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 { d.dwReserved0 } else { 0 };
        let state = unsafe { CfGetPlaceholderStateFromAttributeTag(attrs, tag) };
        let placeholder = if state.0 != CF_PLACEHOLDER_STATE_INVALID.0 && state.0 & CF_PLACEHOLDER_STATE_PLACEHOLDER.0 != 0 {
            let offline = attrs & (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS.0 | FILE_ATTRIBUTE_OFFLINE.0) != 0 || state.0 & CF_PLACEHOLDER_STATE_PARTIAL.0 != 0;
            let mut ph = Placeholder {
                identity: None,
                in_sync: state.0 & CF_PLACEHOLDER_STATE_IN_SYNC.0 != 0,
                pin: if attrs & FILE_ATTRIBUTE_PINNED.0 != 0 {
                    Pin::Pinned
                } else if attrs & FILE_ATTRIBUTE_UNPINNED.0 != 0 {
                    Pin::Unpinned
                } else {
                    Pin::Unspecified
                },
                hydrated: is_dir || !offline,
            };
            if let Ok(h) = Self::open(path, FILE_READ_ATTRIBUTES.0) {
                let mut buf = vec![0u8; std::mem::size_of::<CF_PLACEHOLDER_STANDARD_INFO>() + crate::core::identity::MAX_LEN];
                let mut ret = 0u32;
                if unsafe { CfGetPlaceholderInfo(h.0, CF_PLACEHOLDER_INFO_STANDARD, buf.as_mut_ptr() as _, buf.len() as u32, Some(&mut ret)) }.is_ok() {
                    let info = unsafe { &*(buf.as_ptr() as *const CF_PLACEHOLDER_STANDARD_INFO) };
                    let off = std::mem::offset_of!(CF_PLACEHOLDER_STANDARD_INFO, FileIdentity);
                    let len = (info.FileIdentityLength as usize).min(buf.len() - off);
                    ph.identity = Identity::decode(&buf[off..off + len]);
                    ph.in_sync = info.InSyncState == CF_IN_SYNC_STATE_IN_SYNC;
                    ph.pin = match info.PinState {
                        CF_PIN_STATE_PINNED => Pin::Pinned,
                        CF_PIN_STATE_UNPINNED => Pin::Unpinned,
                        CF_PIN_STATE_EXCLUDED => Pin::Excluded,
                        CF_PIN_STATE_INHERIT => Pin::Inherit,
                        _ => Pin::Unspecified,
                    };
                }
            }
            Some(ph)
        } else {
            None
        };
        LocalEntry {
            name,
            is_dir,
            size: ((d.nFileSizeHigh as u64) << 32) | d.nFileSizeLow as u64,
            mtime_ms: filetime_to_ms(ft(d.ftLastWriteTime)),
            placeholder,
        }
    }

    fn fs_meta(meta: &PlaceholderMeta) -> CF_FS_METADATA {
        let m = if meta.mtime_ms > 0 { meta.mtime_ms } else { now_ms() };
        let c = if meta.ctime_ms > 0 { meta.ctime_ms } else { m };
        CF_FS_METADATA {
            BasicInfo: FILE_BASIC_INFO {
                CreationTime: ms_to_filetime(c),
                LastAccessTime: ms_to_filetime(m),
                LastWriteTime: ms_to_filetime(m),
                ChangeTime: ms_to_filetime(m),
                FileAttributes: if meta.is_dir { FILE_ATTRIBUTE_DIRECTORY.0 } else { FILE_ATTRIBUTE_NORMAL.0 },
            },
            FileSize: if meta.is_dir { 0 } else { meta.size as i64 },
        }
    }

    fn set_pin(path: &Path, pin: CF_PIN_STATE) -> io::Result<()> {
        let h = Self::open(path, WRITE_DAC | FILE_WRITE_ATTRIBUTES.0)?;
        unsafe { CfSetPinState(h.0, pin, CF_SET_PIN_FLAG_NONE, None) }.map_err(werr)
    }

    fn update(path: &Path, meta: &PlaceholderMeta, content_changed: bool) -> windows::core::Result<()> {
        let h = Self::open(path, WRITE_DAC | FILE_WRITE_ATTRIBUTES.0)
            .map_err(|e| windows::core::Error::new(HRESULT::from_win32(e.raw_os_error().unwrap_or(1) as u32), e.to_string()))?;
        let id = meta.identity.encode();
        let fsm = Self::fs_meta(meta);
        let mut flags = CF_UPDATE_FLAG_MARK_IN_SYNC;
        if content_changed {
            flags |= CF_UPDATE_FLAG_DEHYDRATE;
        }
        if meta.is_dir {
            flags |= CF_UPDATE_FLAG_DISABLE_ON_DEMAND_POPULATION;
        }
        // Metadaten nur, wenn sich der Inhalt ändert (sonst passt die Größe der geladenen Daten nicht).
        let fsm_arg = if content_changed || meta.is_dir { Some(&fsm as *const _) } else { None };
        unsafe { CfUpdatePlaceholder(h.0, fsm_arg, Some(id.as_ptr() as _), id.len() as u32, None, flags, None, None) }
    }
}

impl LocalFs for WinFs {
    fn stat(&self, path: &Path) -> io::Result<Option<LocalEntry>> {
        Ok(Self::find(path)?.map(|d| Self::entry(path, &d)))
    }

    fn list(&self, dir: &Path) -> io::Result<Vec<LocalEntry>> {
        let pattern = wide(&dir.join("*"));
        let mut d = WIN32_FIND_DATAW::default();
        let h = unsafe { FindFirstFileW(PCWSTR(pattern.as_ptr()), &mut d) }.map_err(werr)?;
        let mut out = Vec::new();
        loop {
            let len = d.cFileName.iter().position(|c| *c == 0).unwrap_or(0);
            let name = String::from_utf16_lossy(&d.cFileName[..len]);
            if name != "." && name != ".." {
                out.push(Self::entry(&dir.join(&name), &d));
            }
            if unsafe { FindNextFileW(h, &mut d) }.is_err() {
                break;
            }
        }
        unsafe {
            let _ = FindClose(h);
        }
        Ok(out)
    }

    fn create_placeholder(&self, dir: &Path, name: &str, meta: &PlaceholderMeta) -> io::Result<()> {
        let id = meta.identity.encode();
        let n = wide_str(name);
        let mut flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
        if meta.is_dir {
            flags |= CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION;
        }
        let mut info = [CF_PLACEHOLDER_CREATE_INFO {
            RelativeFileName: PCWSTR(n.as_ptr()),
            FsMetadata: Self::fs_meta(meta),
            FileIdentity: id.as_ptr() as _,
            FileIdentityLength: id.len() as u32,
            Flags: flags,
            Result: HRESULT(0),
            CreateUsn: 0,
        }];
        let d = wide(dir);
        unsafe { CfCreatePlaceholders(PCWSTR(d.as_ptr()), &mut info, CF_CREATE_FLAG_NONE, None) }.map_err(werr)?;
        info[0].Result.ok().map_err(werr)
    }

    fn update_placeholder(&self, path: &Path, meta: &PlaceholderMeta, content_changed: bool) -> io::Result<()> {
        match Self::update(path, meta, content_changed) {
            Ok(()) => Ok(()),
            Err(e) if content_changed && (e.code().0 & 0xFFFF) == ERROR_CLOUD_FILE_PINNED => {
                // angeheftet: kurz lösen, ersetzen, wieder anheften (der Abgleich lädt neu)
                Self::set_pin(path, CF_PIN_STATE_UNSPECIFIED)?;
                let r = Self::update(path, meta, true).map_err(werr);
                Self::set_pin(path, CF_PIN_STATE_PINNED)?;
                r
            }
            Err(e) => Err(werr(e)),
        }
    }

    fn convert_to_placeholder(&self, path: &Path, identity: &Identity) -> io::Result<()> {
        let h = Self::open(path, WRITE_DAC | FILE_WRITE_ATTRIBUTES.0)?;
        let id = identity.encode();
        unsafe { CfConvertToPlaceholder(h.0, Some(id.as_ptr() as _), id.len() as u32, CF_CONVERT_FLAG_MARK_IN_SYNC, None, None) }.map_err(werr)
    }

    fn set_in_sync(&self, path: &Path, in_sync: bool) -> io::Result<()> {
        let h = Self::open(path, WRITE_DAC | FILE_WRITE_ATTRIBUTES.0)?;
        let st = if in_sync { CF_IN_SYNC_STATE_IN_SYNC } else { CF_IN_SYNC_STATE_NOT_IN_SYNC };
        unsafe { CfSetInSyncState(h.0, st, CF_SET_IN_SYNC_FLAG_NONE, None) }.map_err(werr)
    }

    fn revert_placeholder(&self, path: &Path) -> io::Result<()> {
        let h = Self::open(path, WRITE_DAC | FILE_WRITE_ATTRIBUTES.0)?;
        unsafe { CfRevertPlaceholder(h.0, CF_REVERT_FLAG_NONE, None) }.map_err(werr)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let (f, t) = (wide(from), wide(to));
        unsafe { MoveFileExW(PCWSTR(f.as_ptr()), PCWSTR(t.as_ptr()), MOVE_FILE_FLAGS(0)) }.map_err(werr)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_dir(path)
    }

    fn open_read(&self, path: &Path) -> io::Result<Box<dyn ReadAt>> {
        // Nur Lesen erlaubt: schreibt ein Programm noch, schlägt das Öffnen fehl (32).
        let f = std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ.0).open(path)?;
        Ok(Box::new(f))
    }

    fn hydrate(&self, path: &Path) -> io::Result<()> {
        {
            let mut set = self.hydrating.lock().unwrap();
            if !set.insert(path.to_path_buf()) {
                return Ok(());
            }
        }
        let (p, set) = (path.to_path_buf(), self.hydrating.clone());
        // CfHydratePlaceholder wartet, bis alles geladen ist – im Hintergrund.
        std::thread::spawn(move || {
            if let Ok(h) = Self::open(&p, FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0) {
                let _ = unsafe { CfHydratePlaceholder(h.0, 0, -1, CF_HYDRATE_FLAG_NONE, None) };
            }
            set.lock().unwrap().remove(&p);
        });
        Ok(())
    }

    fn dehydrate(&self, path: &Path) -> io::Result<()> {
        let h = Self::open(path, WRITE_DAC | FILE_WRITE_ATTRIBUTES.0)?;
        unsafe { CfDehydratePlaceholder(h.0, 0, -1, CF_DEHYDRATE_FLAG_NONE, None) }.map_err(werr)
    }
}
