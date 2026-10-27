//! `gc-drive-sync.exe launch --parent-pid <pid>`: gc-drive-sync mit den Rechten
//! des angemeldeten Benutzers starten, obwohl der Pro-Client mit
//! Administratorrechten läuft (`requireAdministrator`).
//!
//! Warum: Dateien, die gc-drive-sync anlegt (Platzhalter, verlegte
//! Windows-Ordner), sollen dem Benutzer gehören, nicht der Gruppe
//! Administratoren; `SHSetKnownFolderPath` wirkt auf das HKCU des Benutzers.
//!
//! Wege, der Reihe nach:
//!   1. `token`: Token der Shell (Explorer, über `GetShellWindow`) duplizieren
//!      und `CreateProcessWithTokenW` – dafür reicht SeImpersonatePrivilege,
//!      das ein erhöhter Administrator hat; läuft über den Dienst „Sekundäre
//!      Anmeldung“ (seclogon). Umgebung aus dem Profil des Benutzers.
//!   2. `parent`: Ist seclogon abgeschaltet: `CreateProcessW` mit der Shell als
//!      Elternprozess (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) – der neue
//!      Prozess erbt dann deren Token. Die Standard-Handles werden dazu in den
//!      Explorer dupliziert und danach dort wieder geschlossen; Umgebung per
//!      `CreateEnvironmentBlock` aus dem Shell-Token.
//!   3. `inprocess`: Läuft schon nichts erhöht (Pro-Client im Test, UAC aus –
//!      dann hat auch der Explorer volle Rechte) oder gibt es keine Shell,
//!      läuft der Dienst in diesem Prozess. Ohne Shell nur, wenn der Pro-Client
//!      dasselbe Konto ist; sonst Fehler `wrong_user` (die Sync-Root läge im
//!      Profil des Administrators).
//!
//! Erwogen und verworfen: eine geplante Aufgabe „nur wenn Benutzer angemeldet“
//! mit niedrigster Berechtigung (wie der Autostart). Sie liefert weder stdout
//! (die Pipe-Adresse steht nur dort) noch die Prozess-ID, die Argumente je Start
//! stünden in der Aufgabe, und ein Start ist nur über den Aufgabendienst zu
//! steuern und zu beenden.
//!
//! Der Starter bleibt als Wächter laufen: Er reicht die erste Zeile des
//! Kindes (`ready`, mit `launch` und `elevated`) an den Pro-Client weiter,
//! prüft dabei die Prozess-ID, und endet mit dem Kind. Das Kind liest stdin
//! (`--watch-stdin`); endet der Starter – der Pro-Client hat ihn beendet oder
//! ist selbst weg –, schließt sich stdin und das Kind beendet sich sauber. Der
//! Pro-Client-Prozess selbst ist für das Kind (Benutzerrechte) nicht zu öffnen,
//! deshalb dieser Weg.

use super::util::{current_user_sid, wide, wide_str, OwnedHandle};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::FromRawHandle;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::*;
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::*;
use windows::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};

pub struct Child {
    pub process: OwnedHandle,
    pub pid: u32,
    pub stdout: OwnedHandle,
    /// Schreibende Seite von stdin des Kindes – schließen = Kind beendet sich.
    pub stdin: OwnedHandle,
    pub method: &'static str,
}

fn token_of(process: HANDLE, access: TOKEN_ACCESS_MASK) -> Result<OwnedHandle, String> {
    let mut t = HANDLE::default();
    unsafe { OpenProcessToken(process, access, &mut t) }.map_err(|e| format!("OpenProcessToken: {e}"))?;
    Ok(OwnedHandle(t))
}

pub fn token_elevated(token: HANDLE) -> bool {
    let mut e = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    unsafe { GetTokenInformation(token, TokenElevation, Some(&mut e as *mut _ as _), std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len) }.is_ok()
        && e.TokenIsElevated != 0
}

/// Läuft dieser Prozess erhöht?
pub fn self_elevated() -> bool {
    token_of(unsafe { GetCurrentProcess() }, TOKEN_QUERY).map(|t| token_elevated(t.0)).unwrap_or(false)
}

fn token_sid(token: HANDLE) -> Result<String, String> {
    unsafe {
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr() as _), len, &mut len).map_err(|e| e.to_string())?;
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut s).map_err(|e| e.to_string())?;
        let out = s.to_string().map_err(|e| e.to_string());
        let _ = LocalFree(Some(HLOCAL(s.0 as _)));
        out
    }
}

/// Prozess der Shell (Explorer) dieser Sitzung.
fn shell_process() -> Option<(u32, OwnedHandle)> {
    let hwnd = unsafe { GetShellWindow() };
    if hwnd.0.is_null() {
        return None;
    }
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    if pid == 0 {
        return None;
    }
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, false, pid) }.ok()?;
    Some((pid, OwnedHandle(h)))
}

/// Pipe: (lesende Seite, schreibende Seite); `inherit_read`/`inherit_write` steuern die Vererbbarkeit.
fn pipe(inherit_read: bool, inherit_write: bool) -> Result<(OwnedHandle, OwnedHandle), String> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let (mut r, mut w) = (HANDLE::default(), HANDLE::default());
    unsafe { CreatePipe(&mut r, &mut w, Some(&sa), 0) }.map_err(|e| format!("CreatePipe: {e}"))?;
    unsafe {
        let _ = SetHandleInformation(r, HANDLE_FLAG_INHERIT.0, if inherit_read { HANDLE_FLAG_INHERIT } else { HANDLE_FLAGS(0) });
        let _ = SetHandleInformation(w, HANDLE_FLAG_INHERIT.0, if inherit_write { HANDLE_FLAG_INHERIT } else { HANDLE_FLAGS(0) });
    }
    Ok((OwnedHandle(r), OwnedHandle(w)))
}

fn command_line(exe: &std::path::Path, args: &[String]) -> Vec<u16> {
    let mut s = format!("\"{}\"", exe.display());
    for a in args {
        if a.is_empty() || a.contains(' ') || a.contains('\t') {
            s.push_str(&format!(" \"{}\"", a.replace('"', "")));
        } else {
            s.push(' ');
            s.push_str(a);
        }
    }
    wide_str(&s)
}

/// Weg 1: CreateProcessWithTokenW mit dem Token der Shell.
fn with_token(shell_token: HANDLE, exe: &std::path::Path, args: &[String]) -> Result<Child, String> {
    let mut dup = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            shell_token,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut dup,
        )
    }
    .map_err(|e| format!("DuplicateTokenEx: {e}"))?;
    let dup = OwnedHandle(dup);
    let (in_r, in_w) = pipe(true, false)?;
    let (out_r, out_w) = pipe(false, true)?;
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: in_r.0,
        hStdOutput: out_w.0,
        hStdError: out_w.0,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    let mut cmd = command_line(exe, args);
    let dir = wide(exe.parent().unwrap_or(std::path::Path::new("C:\\")));
    unsafe {
        CreateProcessWithTokenW(
            dup.0,
            LOGON_WITH_PROFILE,
            PCWSTR::null(),
            Some(PWSTR(cmd.as_mut_ptr())),
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            None,
            PCWSTR(dir.as_ptr()),
            &si,
            &mut pi,
        )
    }
    .map_err(|e| format!("CreateProcessWithTokenW: {e}"))?;
    let _ = OwnedHandle(pi.hThread);
    drop((in_r, out_w));
    Ok(Child { process: OwnedHandle(pi.hProcess), pid: pi.dwProcessId, stdout: out_r, stdin: in_w, method: "token" })
}

/// Weg 2: Shell als Elternprozess.
fn with_parent(shell: HANDLE, shell_token: HANDLE, exe: &std::path::Path, args: &[String]) -> Result<Child, String> {
    let (in_r, in_w) = pipe(false, false)?;
    let (out_r, out_w) = pipe(false, false)?;
    // die Handles des Kindes müssen im Elternprozess (Explorer) liegen
    let me = unsafe { GetCurrentProcess() };
    let (mut r_in, mut r_out) = (HANDLE::default(), HANDLE::default());
    unsafe {
        DuplicateHandle(me, in_r.0, shell, &mut r_in, 0, true, DUPLICATE_SAME_ACCESS).map_err(|e| format!("DuplicateHandle: {e}"))?;
        if let Err(e) = DuplicateHandle(me, out_w.0, shell, &mut r_out, 0, true, DUPLICATE_SAME_ACCESS) {
            let _ = DuplicateHandle(shell, r_in, HANDLE::default(), std::ptr::null_mut(), 0, false, DUPLICATE_CLOSE_SOURCE);
            return Err(format!("DuplicateHandle: {e}"));
        }
    }
    let close_remote = || unsafe {
        let _ = DuplicateHandle(shell, r_in, HANDLE::default(), std::ptr::null_mut(), 0, false, DUPLICATE_CLOSE_SOURCE);
        let _ = DuplicateHandle(shell, r_out, HANDLE::default(), std::ptr::null_mut(), 0, false, DUPLICATE_CLOSE_SOURCE);
    };
    let result = (|| -> Result<PROCESS_INFORMATION, String> {
        let mut size = 0usize;
        let _ = unsafe { InitializeProcThreadAttributeList(None, 2, None, &mut size) };
        let mut buf = vec![0u8; size];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as _);
        unsafe { InitializeProcThreadAttributeList(Some(list), 2, None, &mut size) }.map_err(|e| format!("Attribute: {e}"))?;
        let parent = shell;
        let handles = [r_in, r_out];
        let r = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
                Some(&parent as *const _ as _),
                std::mem::size_of::<HANDLE>(),
                None,
                None,
            )
            .and_then(|_| {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    Some(handles.as_ptr() as _),
                    std::mem::size_of_val(&handles),
                    None,
                    None,
                )
            })
        };
        if let Err(e) = r {
            unsafe { DeleteProcThreadAttributeList(list) };
            return Err(format!("Attribute: {e}"));
        }
        let mut env: *mut core::ffi::c_void = std::ptr::null_mut();
        let have_env = unsafe { CreateEnvironmentBlock(&mut env, Some(shell_token), false) }.is_ok();
        let si = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: r_in,
                hStdOutput: r_out,
                hStdError: r_out,
                ..Default::default()
            },
            lpAttributeList: list,
        };
        let mut pi = PROCESS_INFORMATION::default();
        let mut cmd = command_line(exe, args);
        let dir = wide(exe.parent().unwrap_or(std::path::Path::new("C:\\")));
        let r = unsafe {
            CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(cmd.as_mut_ptr())),
                None,
                None,
                true,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                if have_env { Some(env as *const _) } else { None },
                PCWSTR(dir.as_ptr()),
                &si.StartupInfo,
                &mut pi,
            )
        };
        unsafe {
            if have_env {
                let _ = DestroyEnvironmentBlock(env);
            }
            DeleteProcThreadAttributeList(list);
        }
        r.map_err(|e| format!("CreateProcessW: {e}"))?;
        Ok(pi)
    })();
    close_remote();
    let pi = result?;
    let _ = OwnedHandle(pi.hThread);
    drop((in_r, out_w));
    Ok(Child { process: OwnedHandle(pi.hProcess), pid: pi.dwProcessId, stdout: out_r, stdin: in_w, method: "parent" })
}

pub enum Plan {
    /// In diesem Prozess laufen (`elevated`: mit Administratorrechten).
    InProcess {
        elevated: bool,
        why: String,
    },
    Child(Child),
}

/// Kind mit Benutzerrechten starten (oder sagen, warum hier).
/// `args`: Argumente für `run` (ohne Programmnamen).
pub fn plan(args: &[String]) -> Result<Plan, String> {
    if !self_elevated() {
        return Ok(Plan::InProcess { elevated: false, why: "nicht erhöht".into() });
    }
    let my_sid = current_user_sid()?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let Some((_pid, shell)) = shell_process() else {
        return Ok(Plan::InProcess { elevated: true, why: "keine Shell (Explorer) gefunden".into() });
    };
    let st = token_of(shell.0, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY)?;
    let shell_sid = token_sid(st.0)?;
    // Tests (CI-Runner ohne Benutzerkontensteuerung): einen Weg erzwingen, damit er auch dort läuft.
    let force = std::env::var("GC_DRIVE_SYNC_FORCE_LAUNCH").ok().filter(|f| f == "token" || f == "parent");
    if token_elevated(st.0) && force.is_none() {
        // UAC aus: der Benutzer hat ohnehin volle Rechte
        if shell_sid == my_sid {
            return Ok(Plan::InProcess { elevated: true, why: "Benutzerkontensteuerung aus".into() });
        }
    }
    let mut child_args = args.to_vec();
    child_args.push("--watch-stdin".into());
    if shell_sid != my_sid {
        // Pro-Client läuft als anderes Konto (Administrator): Pipe auch für dieses öffnen
        child_args.push("--client-sid".into());
        child_args.push(my_sid.clone());
    }
    match force.as_deref() {
        Some("token") => return with_token(st.0, &exe, &child_args).map(Plan::Child),
        Some("parent") => return with_parent(shell.0, st.0, &exe, &child_args).map(Plan::Child),
        _ => {}
    }
    let mut errs = Vec::new();
    match with_token(st.0, &exe, &child_args) {
        Ok(c) => return Ok(Plan::Child(c)),
        Err(e) => errs.push(e),
    }
    match with_parent(shell.0, st.0, &exe, &child_args) {
        Ok(c) => return Ok(Plan::Child(c)),
        Err(e) => errs.push(e),
    }
    if shell_sid != my_sid {
        return Err(format!("wrong_user: {}", errs.join("; ")));
    }
    Ok(Plan::InProcess { elevated: true, why: errs.join("; ") })
}

/// Wächter: erste Zeile prüfen und weiterreichen, dann warten. → Exit-Code
pub fn supervise(child: Child, parent_pid: Option<u32>) -> i32 {
    let out = unsafe { std::fs::File::from_raw_handle(child.stdout.0 .0 as _) };
    std::mem::forget(child.stdout); // gehört jetzt `out`
    let mut reader = BufReader::new(out);
    let mut first = String::new();
    let _ = reader.read_line(&mut first);
    let mut v: Value = serde_json::from_str(first.trim()).unwrap_or_else(|_| json!({ "event": "error", "code": "launch", "message": "keine Startzeile" }));
    if v["event"] == "ready" && v["pid"].as_u64() != Some(child.pid as u64) {
        v = json!({ "event": "error", "code": "launch", "message": "Prozess-ID passt nicht" });
        unsafe {
            let _ = TerminateProcess(child.process.0, 1);
        }
    } else if v["event"] == "ready" {
        v["launch"] = json!(child.method);
        v["elevated"] = json!(false);
    }
    {
        let mut o = std::io::stdout().lock();
        let _ = writeln!(o, "{v}");
        let _ = o.flush();
    }
    // weitere Ausgaben des Kindes (Fehler) nach stderr
    std::thread::spawn(move || {
        for line in reader.lines().map_while(Result::ok) {
            eprintln!("{line}");
        }
    });
    let parent = parent_pid.and_then(|p| unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, p) }.ok()).map(OwnedHandle);
    let mut handles = vec![child.process.0];
    if let Some(p) = &parent {
        handles.push(p.0);
    }
    let r = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
    if r.0 != WAIT_OBJECT_0.0 {
        // Pro-Client weg: stdin schließen → Kind beendet sich sauber
        drop(child.stdin);
        if unsafe { WaitForSingleObject(child.process.0, 15_000) } != WAIT_OBJECT_0 {
            unsafe {
                let _ = TerminateProcess(child.process.0, 1);
            }
        }
        return 0;
    }
    let mut code = 0u32;
    unsafe {
        let _ = GetExitCodeProcess(child.process.0, &mut code);
    }
    code as i32
}

/// Für `info`: wie würde gestartet? (ohne zu starten)
pub fn describe() -> Value {
    let elevated = self_elevated();
    let shell = shell_process();
    let shell_info = shell
        .as_ref()
        .and_then(|(pid, h)| token_of(h.0, TOKEN_QUERY).ok().map(|t| json!({ "pid": pid, "elevated": token_elevated(t.0), "sid": token_sid(t.0).ok() })));
    json!({ "elevated": elevated, "sid": current_user_sid().ok(), "shell": shell_info, "exe": std::env::current_exe().ok() })
}
