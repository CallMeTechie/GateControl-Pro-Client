//! Benannte Pipe für den Pro-Client.
//!
//! Sicherheit:
//!   * DACL nur für den angemeldeten Benutzer (SID) und SYSTEM, geschützt
//!     (`D:P(A;;GA;;;<SID>)(A;;GA;;;SY)`); keine Netzwerk-Clients
//!     (PIPE_REJECT_REMOTE_CLIENTS).
//!   * FILE_FLAG_FIRST_PIPE_INSTANCE: Gibt es den Namen schon (ein anderer
//!     Prozess war schneller), startet das Programm nicht.
//!   * Der Name enthält eine Zufallszahl je Start und steht nur auf stdout des
//!     Programms – das liest allein der startende Pro-Client.
//!   * Eine Instanz: nach dem Ende einer Verbindung wird dieselbe Instanz mit
//!     DisconnectNamedPipe/ConnectNamedPipe wiederverwendet, der Name ist nie frei.
//!
//! Lesen und Schreiben laufen „overlapped“, damit Ereignisse (Schreiben aus
//! dem Abgleich-Thread) nicht hinter einem wartenden Lesen hängen.

use super::util::{wide_str, OwnedHandle};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HLOCAL, WAIT_OBJECT_0};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::*;
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

pub fn pipe_name(sid: &str) -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(r"\\.\pipe\gatecontrol-drive-sync-{sid}-{hex}")
}

/// „S-1-5-21-…“: nur Ziffern und Bindestriche hinter „S-1-“.
pub fn valid_sid(s: &str) -> bool {
    s.len() <= 184 && s.starts_with("S-1-") && s[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-') && !s.ends_with('-')
}

pub struct PipeServer {
    h: Arc<OwnedHandle>,
    pub name: String,
}

#[derive(Clone)]
pub struct PipeConn {
    h: Arc<OwnedHandle>,
}

fn last_err() -> io::Error {
    io::Error::from_raw_os_error(unsafe { GetLastError() }.0 as i32)
}

fn event() -> io::Result<OwnedHandle> {
    unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.map(OwnedHandle).map_err(|e| io::Error::other(e.to_string()))
}

impl PipeServer {
    /// `extra`: weitere SIDs mit Zugriff (der Pro-Client, wenn er als anderes
    /// Konto läuft – Administrator per „Als anderer Benutzer“).
    pub fn create(name: &str, sid: &str, extra: &[String]) -> Result<PipeServer, String> {
        let mut aces = format!("(A;;GA;;;{sid})(A;;GA;;;SY)");
        for x in extra {
            if !valid_sid(x) {
                return Err(format!("SID: {x}"));
            }
            if x != sid {
                aces.push_str(&format!("(A;;GA;;;{x})"));
            }
        }
        let sddl = wide_str(&format!("D:P{aces}"));
        let mut psd = PSECURITY_DESCRIPTOR::default();
        unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), 1, &mut psd, None) }.map_err(|e| format!("SDDL: {e}"))?;
        let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: psd.0, bInheritHandle: false.into() };
        let n = wide_str(name);
        let h = unsafe {
            CreateNamedPipeW(
                PCWSTR(n.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                0,
                Some(&sa),
            )
        };
        let err = last_err();
        unsafe {
            let _ = LocalFree(Some(HLOCAL(psd.0)));
        }
        if h.is_invalid() {
            return Err(format!("CreateNamedPipe: {err}"));
        }
        Ok(PipeServer { h: Arc::new(OwnedHandle(h)), name: name.to_string() })
    }

    /// Auf einen Client warten; `None`, wenn `quit` gesetzt wurde.
    pub fn accept(&self, quit: &AtomicBool) -> io::Result<Option<PipeConn>> {
        let ev = event()?;
        let mut ov = OVERLAPPED { hEvent: ev.0, ..Default::default() };
        if let Err(e) = unsafe { ConnectNamedPipe(self.h.0, Some(&mut ov)) } {
            let code = e.code().0 as u32 & 0xFFFF;
            if code == ERROR_PIPE_CONNECTED.0 {
                return Ok(Some(PipeConn { h: self.h.clone() }));
            }
            if code != ERROR_IO_PENDING.0 {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
        }
        loop {
            if unsafe { WaitForSingleObject(ev.0, 500) } == WAIT_OBJECT_0 {
                break;
            }
            if quit.load(Ordering::SeqCst) {
                unsafe {
                    let _ = CancelIoEx(self.h.0, Some(&ov));
                    let mut n = 0;
                    let _ = GetOverlappedResult(self.h.0, &ov, &mut n, true);
                }
                return Ok(None);
            }
        }
        let mut n = 0u32;
        unsafe { GetOverlappedResult(self.h.0, &ov, &mut n, false) }.map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Some(PipeConn { h: self.h.clone() }))
    }

    /// Verbindung beenden; die Instanz bleibt für den nächsten Client.
    pub fn disconnect(&self) {
        unsafe {
            let _ = DisconnectNamedPipe(self.h.0);
        }
    }

    pub fn client_pid(&self) -> Option<u32> {
        let mut pid = 0u32;
        unsafe { GetNamedPipeClientProcessId(self.h.0, &mut pid) }.ok().map(|_| pid)
    }
}

impl PipeConn {
    fn io(&self, read: bool, buf: *mut u8, len: usize) -> io::Result<usize> {
        let ev = event()?;
        let mut ov = OVERLAPPED { hEvent: ev.0, ..Default::default() };
        let r = unsafe {
            if read {
                ReadFile(self.h.0, Some(std::slice::from_raw_parts_mut(buf, len)), None, Some(&mut ov))
            } else {
                WriteFile(self.h.0, Some(std::slice::from_raw_parts(buf, len)), None, Some(&mut ov))
            }
        };
        if let Err(e) = r {
            let code = e.code().0 as u32 & 0xFFFF;
            if code == ERROR_BROKEN_PIPE.0 {
                return Ok(0);
            }
            if code != ERROR_IO_PENDING.0 {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
        }
        let mut n = 0u32;
        match unsafe { GetOverlappedResult(self.h.0, &ov, &mut n, true) } {
            Ok(()) => Ok(n as usize),
            Err(e) if (e.code().0 as u32 & 0xFFFF) == ERROR_BROKEN_PIPE.0 => Ok(0),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }
}

impl io::Read for PipeConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.io(true, buf.as_mut_ptr(), buf.len())
    }
}

impl io::Write for PipeConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.io(false, buf.as_ptr() as *mut u8, buf.len())?;
        if n == 0 && !buf.is_empty() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
