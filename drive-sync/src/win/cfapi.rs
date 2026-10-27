//! CfConnectSyncRoot und die Rückrufe der Cloud Files API.
//!
//! Die Rückrufe kommen aus Threads von Windows. Sie arbeiten nie selbst am
//! Abgleich, sondern geben an `Callbacks` weiter:
//!   * FETCH_DATA → Laden im Hintergrund (`FetchPool`), Stücke per
//!     CfExecute TRANSFER_DATA, Fortschritt per CfReportProviderProgress.
//!   * CANCEL_FETCH_DATA → Laden abbrechen.
//!   * NOTIFY_DELETE / NOTIFY_RENAME → Rechte prüfen, sofort bestätigen oder
//!     ablehnen (CfExecute ACK_DELETE / ACK_RENAME); die Server-Änderung macht
//!     danach der Abgleich-Thread. Eigene Änderungen (Prozess-ID dieses
//!     Programms) werden ohne Prüfung bestätigt.

use super::util::from_pcwstr;
use crate::core::hydrate::{FetchRequest, TransferSink};
use crate::core::identity::Identity;
use crate::core::service::Callbacks;
use std::path::PathBuf;
use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};
use windows::Win32::Storage::CloudFilters::*;
use windows::Win32::System::Threading::GetCurrentProcessId;

/// STATUS_CLOUD_FILE_ACCESS_DENIED
const STATUS_CLOUD_FILE_ACCESS_DENIED: NTSTATUS = NTSTATUS(0xC000_CF18_u32 as i32);

struct Ctx {
    cb: Arc<dyn Callbacks>,
    pid: u32,
}

/// Verbindung; beim Fallenlassen CfDisconnectSyncRoot.
pub struct Connection {
    key: CF_CONNECTION_KEY,
    ctx: *mut Ctx,
}

unsafe impl Send for Connection {}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe {
            let _ = CfDisconnectSyncRoot(self.key);
            drop(Box::from_raw(self.ctx));
        }
    }
}

static TABLE: [CF_CALLBACK_REGISTRATION; 5] = [
    CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_FETCH_DATA, Callback: Some(on_fetch_data) },
    CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_CANCEL_FETCH_DATA, Callback: Some(on_cancel_fetch) },
    CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_NOTIFY_DELETE, Callback: Some(on_notify_delete) },
    CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_NOTIFY_RENAME, Callback: Some(on_notify_rename) },
    CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_NONE, Callback: None },
];

pub fn connect(root: &std::path::Path, cb: Arc<dyn Callbacks>) -> Result<Connection, String> {
    let ctx = Box::into_raw(Box::new(Ctx { cb, pid: unsafe { GetCurrentProcessId() } }));
    let w = super::util::wide(root);
    let flags = CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH | CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION;
    match unsafe { CfConnectSyncRoot(PCWSTR(w.as_ptr()), TABLE.as_ptr(), Some(ctx as *const _), flags) } {
        Ok(key) => Ok(Connection { key, ctx }),
        Err(e) => {
            unsafe { drop(Box::from_raw(ctx)) };
            Err(e.to_string())
        }
    }
}

unsafe fn ctx(info: &CF_CALLBACK_INFO) -> &Ctx {
    unsafe { &*(info.CallbackContext as *const Ctx) }
}

/// Voller Pfad: Laufwerk („C:“) + Pfad ab Volume-Wurzel.
unsafe fn full_path(info: &CF_CALLBACK_INFO, rel: PCWSTR) -> Option<PathBuf> {
    let vol = unsafe { from_pcwstr(info.VolumeDosName) }.unwrap_or_default();
    let p = unsafe { from_pcwstr(rel) }?;
    let mut s = vol.into_os_string();
    s.push(p.as_os_str());
    Some(PathBuf::from(s))
}

unsafe fn identity(info: &CF_CALLBACK_INFO) -> Option<Identity> {
    if info.FileIdentity.is_null() || info.FileIdentityLength == 0 {
        return None;
    }
    let b = unsafe { std::slice::from_raw_parts(info.FileIdentity as *const u8, info.FileIdentityLength as usize) };
    Identity::decode(b)
}

unsafe fn own_process(info: &CF_CALLBACK_INFO, c: &Ctx) -> bool {
    !info.ProcessInfo.is_null() && unsafe { (*info.ProcessInfo).ProcessId } == c.pid
}

fn op_info(info: &CF_CALLBACK_INFO, ty: CF_OPERATION_TYPE) -> CF_OPERATION_INFO {
    CF_OPERATION_INFO {
        StructSize: std::mem::size_of::<CF_OPERATION_INFO>() as u32,
        Type: ty,
        ConnectionKey: info.ConnectionKey,
        TransferKey: info.TransferKey,
        CorrelationVector: info.CorrelationVector,
        SyncStatus: std::ptr::null(),
        RequestKey: info.RequestKey,
    }
}

fn param_size<T>() -> u32 {
    (std::mem::offset_of!(CF_OPERATION_PARAMETERS, Anonymous) + std::mem::size_of::<T>()) as u32
}

unsafe extern "system" fn on_notify_delete(info: *const CF_CALLBACK_INFO, _params: *const CF_CALLBACK_PARAMETERS) {
    let info = unsafe { &*info };
    let c = unsafe { ctx(info) };
    let allow = if unsafe { own_process(info, c) } {
        true
    } else {
        let path = unsafe { full_path(info, info.NormalizedPath) }.unwrap_or_default();
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.cb.notify_delete(unsafe { identity(info) }, path))).unwrap_or(false)
    };
    let oi = op_info(info, CF_OPERATION_TYPE_ACK_DELETE);
    let mut p = CF_OPERATION_PARAMETERS { ParamSize: param_size::<CF_OPERATION_PARAMETERS_0_7>(), ..Default::default() };
    p.Anonymous.AckDelete = CF_OPERATION_PARAMETERS_0_7 {
        Flags: CF_OPERATION_ACK_DELETE_FLAG_NONE,
        CompletionStatus: if allow { STATUS_SUCCESS } else { STATUS_CLOUD_FILE_ACCESS_DENIED },
    };
    let _ = unsafe { CfExecute(&oi, &mut p) };
}

unsafe extern "system" fn on_notify_rename(info: *const CF_CALLBACK_INFO, params: *const CF_CALLBACK_PARAMETERS) {
    let info = unsafe { &*info };
    let c = unsafe { ctx(info) };
    let allow = if unsafe { own_process(info, c) } {
        true
    } else {
        let r = unsafe { (*params).Anonymous.Rename };
        let from = unsafe { full_path(info, info.NormalizedPath) }.unwrap_or_default();
        let to = if (r.Flags.0 & CF_CALLBACK_RENAME_FLAG_TARGET_IN_SCOPE.0) != 0 { unsafe { full_path(info, r.TargetPath) } } else { None };
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.cb.notify_rename(unsafe { identity(info) }, from, to))).unwrap_or(false)
    };
    let oi = op_info(info, CF_OPERATION_TYPE_ACK_RENAME);
    let mut p = CF_OPERATION_PARAMETERS { ParamSize: param_size::<CF_OPERATION_PARAMETERS_0_6>(), ..Default::default() };
    p.Anonymous.AckRename = CF_OPERATION_PARAMETERS_0_6 {
        Flags: CF_OPERATION_ACK_RENAME_FLAG_NONE,
        CompletionStatus: if allow { STATUS_SUCCESS } else { STATUS_CLOUD_FILE_ACCESS_DENIED },
    };
    let _ = unsafe { CfExecute(&oi, &mut p) };
}

unsafe extern "system" fn on_cancel_fetch(info: *const CF_CALLBACK_INFO, _params: *const CF_CALLBACK_PARAMETERS) {
    let info = unsafe { &*info };
    let c = unsafe { ctx(info) };
    c.cb.cancel_fetch(info.TransferKey);
}

unsafe extern "system" fn on_fetch_data(info: *const CF_CALLBACK_INFO, params: *const CF_CALLBACK_PARAMETERS) {
    let info = unsafe { &*info };
    let c = unsafe { ctx(info) };
    let f = unsafe { (*params).Anonymous.FetchData };
    let req = FetchRequest {
        identity: unsafe { identity(info) },
        file_size: info.FileSize.max(0) as u64,
        required_offset: f.RequiredFileOffset.max(0) as u64,
        required_length: f.RequiredLength.max(0) as u64,
        optional_offset: f.OptionalFileOffset.max(0) as u64,
        optional_length: f.OptionalLength.max(0) as u64,
    };
    let sink = WinSink { connection: info.ConnectionKey, transfer_key: info.TransferKey, request_key: info.RequestKey };
    c.cb.fetch_data(info.TransferKey, req, Box::new(sink));
}

/// Gibt geladene Stücke an Windows (CfExecute TRANSFER_DATA).
pub struct WinSink {
    pub connection: CF_CONNECTION_KEY,
    pub transfer_key: i64,
    pub request_key: i64,
}

unsafe impl Send for WinSink {}

impl WinSink {
    fn execute(&self, status: NTSTATUS, buf: *const u8, offset: u64, length: u64) -> windows::core::Result<()> {
        let oi = CF_OPERATION_INFO {
            StructSize: std::mem::size_of::<CF_OPERATION_INFO>() as u32,
            Type: CF_OPERATION_TYPE_TRANSFER_DATA,
            ConnectionKey: self.connection,
            TransferKey: self.transfer_key,
            CorrelationVector: std::ptr::null(),
            SyncStatus: std::ptr::null(),
            RequestKey: self.request_key,
        };
        let mut p = CF_OPERATION_PARAMETERS { ParamSize: param_size::<CF_OPERATION_PARAMETERS_0_0>(), ..Default::default() };
        p.Anonymous.TransferData = CF_OPERATION_PARAMETERS_0_0 {
            Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
            CompletionStatus: status,
            Buffer: buf as _,
            Offset: offset as i64,
            Length: length as i64,
        };
        unsafe { CfExecute(&oi, &mut p) }
    }
}

impl TransferSink for WinSink {
    fn transfer(&mut self, offset: u64, data: &[u8]) -> Result<(), String> {
        self.execute(STATUS_SUCCESS, data.as_ptr(), offset, data.len() as u64).map_err(|e| {
            // ERROR_CLOUD_FILE_REQUEST_CANCELED / …_REQUEST_ABORTED: Windows hat die Anfrage beendet
            let code = e.code().0 as u32;
            if code == 0x8007_018E || code == 0x8007_018D {
                format!("{}: {e}", crate::core::hydrate::CANCELLED)
            } else {
                e.to_string()
            }
        })
    }
    fn progress(&mut self, total: u64, done: u64) {
        unsafe {
            let _ = CfReportProviderProgress(self.connection, self.transfer_key, total as i64, done as i64);
        }
    }
    fn fail(&mut self, offset: u64, length: u64) {
        let _ = self.execute(STATUS_UNSUCCESSFUL, std::ptr::null(), offset, length);
    }
}
