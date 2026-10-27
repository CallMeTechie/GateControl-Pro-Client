//! Kleinigkeiten für Win32: Pfade als UTF-16, SID des Benutzers, Zeiten.

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Nullterminiertes UTF-16.
pub fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

pub fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn hstring(p: &Path) -> HSTRING {
    HSTRING::from(p.as_os_str())
}

/// UTF-16-Zeiger (nullterminiert) → Pfad.
///
/// # Safety
/// `p` muss null oder ein gültiger, nullterminierter String sein.
pub unsafe fn from_pcwstr(p: PCWSTR) -> Option<PathBuf> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { p.as_wide() };
    Some(PathBuf::from(OsString::from_wide(s)))
}

/// UTF-16 mit Länge in Bytes → String.
///
/// # Safety
/// `p` zeigt auf mindestens `len_bytes` lesbare Bytes.
pub unsafe fn from_wide_bytes(p: *const u16, len_bytes: usize) -> PathBuf {
    let s = unsafe { std::slice::from_raw_parts(p, len_bytes / 2) };
    PathBuf::from(OsString::from_wide(s))
}

/// Schließt den Handle beim Fallenlassen.
pub struct OwnedHandle(pub HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

/// SID des angemeldeten Benutzers als Text („S-1-5-21-…“).
pub fn current_user_sid() -> Result<String, String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(|e| e.to_string())?;
        let token = OwnedHandle(token);
        let mut len = 0u32;
        let _ = GetTokenInformation(token.0, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(token.0, TokenUser, Some(buf.as_mut_ptr() as _), len, &mut len).map_err(|e| e.to_string())?;
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut s).map_err(|e| e.to_string())?;
        let out = s.to_string().map_err(|e| e.to_string());
        let _ = LocalFree(Some(HLOCAL(s.0 as _)));
        out
    }
}

/// FILETIME-Zahl (100 ns seit 1601) ↔ ms seit 1970.
pub const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;

pub fn ms_to_filetime(ms: i64) -> i64 {
    if ms <= 0 {
        return 0;
    }
    ms.saturating_mul(10_000).saturating_add(EPOCH_DIFF_100NS)
}

pub fn filetime_to_ms(ft: i64) -> i64 {
    if ft <= EPOCH_DIFF_100NS {
        return 0;
    }
    (ft - EPOCH_DIFF_100NS) / 10_000
}
