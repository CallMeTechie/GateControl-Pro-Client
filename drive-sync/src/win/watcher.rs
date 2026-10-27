//! Beobachtung des Sync-Roots mit ReadDirectoryChangesW (rekursiv, overlapped).
//! Meldet geänderte Pfade (neu, geändert, umbenannt – neuer Name, Attribute
//! wie der Pin-Zustand); ein Pufferüberlauf meldet `Overflow`.

use super::util::{from_wide_bytes, wide, OwnedHandle};
use super::winfs::werr;
use crate::core::service::WatchEvent;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

pub struct Watcher {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

pub fn watch(root: PathBuf, on_event: Box<dyn Fn(WatchEvent) + Send + Sync>) -> Result<Watcher, String> {
    let w = wide(&root);
    let dir = unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            FILE_LIST_DIRECTORY.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            None,
        )
    }
    .map_err(|e| werr(e).to_string())?;
    let dir = OwnedHandle(dir);
    let event = OwnedHandle(unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.map_err(|e| e.to_string())?);
    let stop = Arc::new(AtomicBool::new(false));
    let st = stop.clone();
    let handle = std::thread::Builder::new()
        .name("drive-watch".into())
        .spawn(move || {
            let (dir, event) = (dir, event);
            // DWORD-ausgerichteter Puffer (64 KiB)
            let mut buf = vec![0u32; 16 * 1024];
            let filter = FILE_NOTIFY_CHANGE_FILE_NAME
                | FILE_NOTIFY_CHANGE_DIR_NAME
                | FILE_NOTIFY_CHANGE_ATTRIBUTES
                | FILE_NOTIFY_CHANGE_SIZE
                | FILE_NOTIFY_CHANGE_LAST_WRITE;
            while !st.load(Ordering::SeqCst) {
                let mut ov = OVERLAPPED { hEvent: event.0, ..Default::default() };
                let r = unsafe { ReadDirectoryChangesW(dir.0, buf.as_mut_ptr() as _, (buf.len() * 4) as u32, true, filter, None, Some(&mut ov), None) };
                if r.is_err() {
                    on_event(WatchEvent::Overflow);
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    continue;
                }
                loop {
                    let w = unsafe { WaitForSingleObject(event.0, 500) };
                    if w == WAIT_OBJECT_0 {
                        break;
                    }
                    if w != WAIT_TIMEOUT || st.load(Ordering::SeqCst) {
                        unsafe {
                            let _ = CancelIoEx(dir.0, Some(&ov));
                            let mut n = 0u32;
                            let _ = GetOverlappedResult(dir.0, &ov, &mut n, true);
                        }
                        return;
                    }
                }
                let mut bytes = 0u32;
                if unsafe { GetOverlappedResult(dir.0, &ov, &mut bytes, false) }.is_err() || bytes == 0 {
                    on_event(WatchEvent::Overflow);
                    continue;
                }
                let base = buf.as_ptr() as *const u8;
                let mut off = 0usize;
                loop {
                    let info = unsafe { &*(base.add(off) as *const FILE_NOTIFY_INFORMATION) };
                    let name = unsafe { from_wide_bytes(info.FileName.as_ptr(), info.FileNameLength as usize) };
                    if info.Action != FILE_ACTION_REMOVED && info.Action != FILE_ACTION_RENAMED_OLD_NAME {
                        on_event(WatchEvent::Changed(root.join(name)));
                    }
                    if info.NextEntryOffset == 0 {
                        break;
                    }
                    off += info.NextEntryOffset as usize;
                }
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(Watcher { stop, handle: Some(handle) })
}
