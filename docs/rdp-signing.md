# RDP File Signing — Suppressing the "Unbekannter Herausgeber" Warning

## Problem

When the Pro client launches `mstsc.exe` with a generated `.rdp` file, Windows
shows a prominent orange-red warning:

> **Vorsicht: Unbekannte Remoteverbindung**
> Der Herausgeber dieser Remoteverbindung konnte nicht überprüft werden.

This warning is independent of the *server-identity* warning ("Die Identität
des Remotecomputers kann nicht überprüft werden"), which is handled separately
by FQDN routing (`internal_dns` feature).

Crucially: **there is no registry-only bypass for this warning.** It is the
output of Authenticode validation against the `.rdp` *file itself*. The only
way to silence it is to attach a valid digital signature to the file via
`signscope:s:` and `signature:s:` fields, signed by a certificate whose chain
ends in a trust anchor on the user's machine.

A previous attempt to bypass it via `HKCU\…\Terminal Server Client\
AuthenticationLevelOverride=0` was a misnomer — that key relaxes
*server* authentication (NLA/CredSSP), not *file* signing. We keep it for
its actual purpose but no longer claim it touches the publisher warning.

## Solution

`RdpSigner` (`src/services/rdp/rdp-signer.js`) creates a self-signed
code-signing certificate the first time the client tries to launch RDP, and
imports its public part into three user-scoped certificate stores:

| Store | Purpose |
|---|---|
| `Cert:\CurrentUser\My`              | private key, used by `rdpsign.exe` |
| `Cert:\CurrentUser\Root`            | chain anchor — required because the cert is its own root |
| `Cert:\CurrentUser\TrustedPublisher` | Authenticode trust for code signing |

All three stores are **per-user**, so cert creation requires no admin/UAC
elevation. The thumbprint is persisted in
`%APPDATA%\gatecontrol-client-pro\rdp-signing\thumbprint.txt`. On subsequent
runs, the signer probes the store and only recreates the cert if it has been
removed manually.

## Locating `rdpsign.exe`

Normally `rdpsign.exe` ships in `C:\Windows\System32\` on every Windows
install. Some systems (debloat scripts, partial in-place upgrades from
older Windows versions, lean editions) end up missing it. The signer
resolves the binary via a memoized three-step chain on first signing
attempt:

1. **System32 / Sysnative** — `C:\Windows\System32\rdpsign.exe`. For 32-bit
   Electron builds on 64-bit Windows we use `Sysnative` to bypass File
   System Redirection (which would route to SysWOW64, where `rdpsign.exe`
   does **not** ship).
2. **User cache** — `<userData>\bin\rdpsign.exe` (populated by step 3 on
   a prior run).
3. **WinSxS auto-restore** — scan
   `C:\Windows\WinSxS\amd64_microsoft-windows-t..lishing-wmiprovider_*\`,
   pick the newest version (parsed from the `_a.b.c.d_` build number in
   the directory name), and copy `rdpsign.exe` into the user-cache
   location. Uses the user's own Microsoft-signed binary, so no
   redistribution concern, no Admin, no UAC.

If all three miss, the signer marks itself as unavailable, sets
`signingUnavailableReason = 'missing'`, and emits an `'unavailable'`
event exactly once. `RdpManager` re-emits `'signing-unavailable'`; the
main process shows a desktop Notification (`notify.rdpSigningUnavailable`)
and forwards an IPC message to the renderer, which displays a long-dwell
info toast pointing the user at `sfc /scannow` for repair.

A user can confirm the state with:

```powershell
Test-Path C:\Windows\System32\rdpsign.exe
Test-Path "$env:APPDATA\gatecontrol-client-pro\bin\rdpsign.exe"
Get-ChildItem C:\Windows\WinSxS\amd64_microsoft-windows-t..lishing-wmiprovider_*\rdpsign.exe
```

`RdpConfigBuilder` calls `signer.sign(filePath)` after writing each
`.rdp` file. `rdpsign.exe /sha256 <thumbprint> <file>` adds `signscope:s:s`
and `signature:s:<base64>` lines in place. The result: mstsc shows a calmer
"Vertrauenswürdiger Herausgeber" prompt with a **"Nicht erneut fragen"**
checkbox; on subsequent connects to the same publisher, it disappears
entirely.

## Failure modes

Signing is **best-effort, never fatal**. If any step fails, the connect still
proceeds with the unsigned file — the user just sees the original warning:

- PowerShell missing or `New-SelfSignedCertificate` cmdlet unavailable
  (Windows < 8.1): `ensureCertificate()` returns `null`.
- `rdpsign.exe` missing or rejects the file: `sign()` returns `false`.
- Either path logs a warning via `electron-log`.

## Trust scope

The cert is per-user and per-machine. Removing it cleanly:

```powershell
Get-ChildItem Cert:\CurrentUser\My, Cert:\CurrentUser\Root, Cert:\CurrentUser\TrustedPublisher `
  | Where-Object { $_.Subject -eq 'CN=GateControl RDP Signing' } `
  | Remove-Item
```

Then delete `%APPDATA%\GateControl Pro Client\rdp-signing\thumbprint.txt` so
the client recreates it on the next launch.

## Tests

- `test/rdp-signer.test.js` — covers cert creation, cache reuse, recreation
  on store eviction, malformed-output handling, sign-call shape, the
  in-flight-promise dedupe for concurrent callers, plus the path-resolver
  chain (System32 fast-path, cache hit, WinSxS restore picks newest
  version, total miss → null + single `unavailable` emission, sign()
  short-circuit when path is null, version sort).
- `test/rdp-config-builder.test.js` — adds two cases: signer is invoked once
  per generated file, and a throwing signer does not break the connect.
