'use strict';

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

const SUBJECT = 'CN=GateControl RDP Signing';
const CERT_FRIENDLY_NAME = 'GateControl RDP Signing';
const THUMBPRINT_FILE = 'thumbprint.txt';
const RDPSIGN_EXE = 'rdpsign.exe';

// rdpsign.exe ships in this WinSxS package. Real on-disk name (the '..' is
// literal — Windows truncates the long key name):
//   amd64_microsoft-windows-t..lishing-wmiprovider_<keyTag>_<version>_<lang>_<hash>
const WINSXS_PKG_PREFIX = /^amd64_microsoft-windows-t\.\.lishing-wmiprovider_/i;
// Used to pick the newest copy when more than one cumulative-update package
// is staged. WinSxS embeds the build version like "_10.0.26100.8328_".
const WINSXS_VERSION_RE = /_(\d+)\.(\d+)\.(\d+)\.(\d+)_/;

const REAL_FS = {
  existsSync: (...a) => fs.existsSync(...a),
  mkdirSync: (...a) => fs.mkdirSync(...a),
  readFileSync: (...a) => fs.readFileSync(...a),
  writeFileSync: (...a) => fs.writeFileSync(...a),
  copyFileSync: (...a) => fs.copyFileSync(...a),
  readdirSync: (...a) => fs.readdirSync(...a),
};

function defaultRunCmd(file, args, opts) {
  return new Promise((resolve, reject) => {
    execFile(file, args, opts, (err, stdout, stderr) => {
      if (err) {
        err.stdout = stdout;
        err.stderr = stderr;
        reject(err);
      } else {
        resolve({ stdout: String(stdout || ''), stderr: String(stderr || '') });
      }
    });
  });
}

/**
 * RdpSigner — manages a per-machine self-signed code-signing certificate
 * used to sign generated .rdp files via rdpsign.exe.
 *
 * Why: an unsigned .rdp file makes mstsc.exe show the orange-red
 * "Vorsicht: Unbekannte Remoteverbindung — Unbekannter Herausgeber"
 * warning. Signing with a cert that lives in the user's TrustedPublisher
 * store turns this into a calm "Trusted Publisher" prompt that supports
 * "do not ask again". No registry bypass exists for the file-signature
 * warning — only a valid signature suppresses it.
 *
 * rdpsign.exe is normally part of every Windows install. On systems where
 * it has been stripped from System32 (debloat scripts, partial in-place
 * upgrades), we transparently restore the user's own copy from the WinSxS
 * component store into a userData cache — no Admin and no redistribution
 * needed. If it can't be found anywhere, we emit 'unavailable' so callers
 * can surface a clear notice.
 *
 * Trust model: a self-signed code-signing cert is created in
 *   Cert:\CurrentUser\My              (private key, used by rdpsign.exe)
 *   Cert:\CurrentUser\Root            (chain anchor — required because the
 *                                      cert is its own root)
 *   Cert:\CurrentUser\TrustedPublisher (Authenticode trust for code signing)
 * All three stores are user-scoped, so creation works without admin/UAC.
 */
class RdpSigner {
  /**
   * @param {object} opts
   * @param {object} opts.log - electron-log instance
   * @param {string} opts.certDir - persistent dir for the thumbprint marker
   * @param {function} [opts.runCmd] - injectable execFile-as-promise (for tests)
   * @param {object}   [opts.fsImpl] - injectable fs (for tests)
   * @param {string}   [opts.winDir] - C:\Windows override (for tests)
   * @param {string}   [opts.binDir] - cache dir for restored rdpsign.exe
   */
  constructor({ log, certDir, runCmd, fsImpl, winDir, binDir }) {
    if (!certDir) throw new Error('RdpSigner requires certDir');
    this.log = log;
    this.certDir = certDir;
    this.runCmd = runCmd || defaultRunCmd;
    this.fs = fsImpl || REAL_FS;
    this.winDir = winDir || process.env.windir || process.env.SystemRoot || 'C:\\Windows';
    this.binDir = binDir || path.join(certDir, '..', 'bin');
    this.thumbprint = null;
    this._readyPromise = null;
    // undefined = not yet resolved, null = unavailable, string = absolute path
    this._rdpsignPath = undefined;
    // Set to 'missing' (no System32 + no WinSxS hit) or 'restore_failed'
    // (WinSxS hit but copy refused). Stays null while signing is healthy.
    this._unavailableReason = null;
    this._listeners = {};
  }

  /** @returns {string|null} 'missing' | 'restore_failed' | null */
  get signingUnavailableReason() { return this._unavailableReason; }

  /** Tiny event sink — only one event ('unavailable'), no need for EventEmitter. */
  on(event, fn) {
    (this._listeners[event] = this._listeners[event] || []).push(fn);
    return this;
  }
  _emit(event, ...args) {
    for (const fn of (this._listeners[event] || [])) {
      try { fn(...args); } catch (err) {
        this.log.warn(`signer event ${event} listener threw: ${err.message}`);
      }
    }
  }

  /**
   * Ensure a code-signing cert exists and is trusted. Idempotent and lazy:
   * concurrent callers share the same in-flight promise.
   * @returns {Promise<string|null>} thumbprint, or null if setup failed
   */
  async ensureCertificate() {
    if (this.thumbprint) return this.thumbprint;
    if (this._readyPromise) return this._readyPromise;

    this._readyPromise = (async () => {
      try {
        this.fs.mkdirSync(this.certDir, { recursive: true });
        const cached = this._readCachedThumbprint();
        if (cached && await this._certExistsInStore(cached)) {
          this.thumbprint = cached;
          this.log.debug(`RDP signing cert already trusted (${cached.slice(0, 12)}…)`);
          return cached;
        }

        const thumbprint = await this._createAndTrustCert();
        this._writeCachedThumbprint(thumbprint);
        this.thumbprint = thumbprint;
        this.log.info(`RDP signing cert created and trusted (${thumbprint.slice(0, 12)}…)`);
        return thumbprint;
      } catch (err) {
        this.log.warn('RDP signing setup failed; .rdp files will be unsigned:', err.message);
        return null;
      } finally {
        this._readyPromise = null;
      }
    })();

    return this._readyPromise;
  }

  /**
   * Resolve an absolute path to a usable rdpsign.exe. Memoized: the search
   * runs at most once per signer instance. Strategy:
   *   1. C:\Windows\System32\rdpsign.exe (Sysnative for 32-bit Electron)
   *   2. cached copy in <certDir>/../bin (from a prior WinSxS restore)
   *   3. WinSxS auto-restore — copy the newest Microsoft-shipped binary
   *      from the component store into the cache. Uses the user's own
   *      file, so no licensing concerns, no Admin, no UAC.
   *
   * Emits 'unavailable' once with { reason } if all three fail, so the
   * caller can show a single user-visible notice.
   *
   * @returns {Promise<string|null>}
   */
  async resolveRdpsignPath() {
    if (this._rdpsignPath !== undefined) return this._rdpsignPath;

    const sys = this._systemRdpsignPath();
    if (this._fileExists(sys)) {
      this._rdpsignPath = sys;
      return sys;
    }

    const cached = path.join(this.binDir, RDPSIGN_EXE);
    if (this._fileExists(cached)) {
      this._rdpsignPath = cached;
      this.log.debug(`Using cached rdpsign.exe at ${cached}`);
      return cached;
    }

    try {
      const restored = this._restoreFromWinSxS();
      if (restored) {
        this._rdpsignPath = restored;
        return restored;
      }
    } catch (err) {
      this.log.warn('rdpsign.exe WinSxS restore threw:', err.message);
    }

    this._rdpsignPath = null;
    this._unavailableReason = 'missing';
    this.log.warn(
      `rdpsign.exe not available; generated .rdp files will be unsigned ` +
      `and mstsc will show the "Unbekannter Herausgeber" warning. ` +
      `Repair: run 'sfc /scannow' as Administrator.`
    );
    this._emit('unavailable', { reason: this._unavailableReason });
    return null;
  }

  /**
   * Sign a .rdp file in place using rdpsign.exe. Non-fatal on failure —
   * the file remains usable, mstsc just shows the publisher warning.
   * @param {string} filePath - absolute path to the .rdp file
   * @returns {Promise<boolean>} true if signing succeeded
   */
  async sign(filePath) {
    const thumbprint = await this.ensureCertificate();
    if (!thumbprint) return false;

    const rdpsignPath = await this.resolveRdpsignPath();
    if (!rdpsignPath) return false;

    try {
      await this.runCmd(rdpsignPath, ['/sha256', thumbprint, filePath], { timeout: 10000 });
      this.log.debug(`RDP file signed: ${path.basename(filePath)}`);
      return true;
    } catch (err) {
      this.log.warn(`rdpsign.exe failed for ${path.basename(filePath)}:`, err.message);
      return false;
    }
  }

  // ── internals ────────────────────────────────────────────

  // System32 (or Sysnative for 32-bit Electron on 64-bit Windows so File
  // System Redirection doesn't send the lookup to SysWOW64, which has no
  // rdpsign.exe).
  _systemRdpsignPath() {
    const useSysnative = process.arch === 'ia32' && !!process.env.PROCESSOR_ARCHITEW6432;
    return path.win32.join(this.winDir, useSysnative ? 'Sysnative' : 'System32', RDPSIGN_EXE);
  }

  _fileExists(p) {
    try { return this.fs.existsSync(p); } catch { return false; }
  }

  // Find rdpsign.exe in WinSxS, copy the newest version into the userData
  // cache. Returns the cache path on success, null when no candidate exists
  // or copy refused. Throws are swallowed by the caller.
  _restoreFromWinSxS() {
    const winsxs = path.join(this.winDir, 'WinSxS');
    if (!this._fileExists(winsxs)) return null;

    let entries;
    try {
      entries = this.fs.readdirSync(winsxs, { withFileTypes: true });
    } catch (err) {
      this.log.debug(`Cannot read ${winsxs}: ${err.message}`);
      return null;
    }

    const candidates = [];
    for (const entry of entries) {
      // readdirSync returns Dirent in modern Node; mocks may yield strings.
      const name = typeof entry === 'string' ? entry : entry.name;
      if (!WINSXS_PKG_PREFIX.test(name)) continue;
      const candidate = path.join(winsxs, name, RDPSIGN_EXE);
      if (this._fileExists(candidate)) candidates.push({ name, fullPath: candidate });
    }
    if (candidates.length === 0) return null;

    candidates.sort((a, b) => this._compareWinSxsVersions(a.name, b.name));
    const newest = candidates[candidates.length - 1];

    try {
      this.fs.mkdirSync(this.binDir, { recursive: true });
      const dest = path.join(this.binDir, RDPSIGN_EXE);
      this.fs.copyFileSync(newest.fullPath, dest);
      this.log.info(`rdpsign.exe restored from WinSxS to ${dest} (source pkg: ${newest.name})`);
      return dest;
    } catch (err) {
      this.log.warn(`rdpsign.exe restore from WinSxS failed: ${err.message}`);
      return null;
    }
  }

  // Numeric ascending compare on the embedded "_a.b.c.d_" build number.
  // Anything without a parseable version sorts to the bottom.
  _compareWinSxsVersions(a, b) {
    const va = a.match(WINSXS_VERSION_RE);
    const vb = b.match(WINSXS_VERSION_RE);
    if (!va && !vb) return 0;
    if (!va) return -1;
    if (!vb) return 1;
    for (let i = 1; i <= 4; i++) {
      const da = parseInt(va[i], 10);
      const db = parseInt(vb[i], 10);
      if (da !== db) return da - db;
    }
    return 0;
  }

  _readCachedThumbprint() {
    try {
      const file = path.join(this.certDir, THUMBPRINT_FILE);
      if (!this.fs.existsSync(file)) return null;
      const value = this.fs.readFileSync(file, 'utf-8').trim();
      return /^[A-F0-9]{40}$/i.test(value) ? value.toUpperCase() : null;
    } catch {
      return null;
    }
  }

  _writeCachedThumbprint(thumbprint) {
    const file = path.join(this.certDir, THUMBPRINT_FILE);
    this.fs.writeFileSync(file, thumbprint, { encoding: 'utf-8', mode: 0o600 });
  }

  async _certExistsInStore(thumbprint) {
    try {
      const script = `if (Test-Path "Cert:\\CurrentUser\\My\\${thumbprint}") { 'yes' } else { 'no' }`;
      const { stdout } = await this.runCmd('powershell.exe',
        ['-NoProfile', '-NonInteractive', '-Command', script],
        { timeout: 10000 });
      return stdout.trim() === 'yes';
    } catch {
      return false;
    }
  }

  /**
   * Create a self-signed code-signing cert in CurrentUser\My and copy it
   * into CurrentUser\Root + TrustedPublisher so rdpsign and mstsc both
   * trust the chain. Returns the thumbprint.
   */
  async _createAndTrustCert() {
    const script = `
$ErrorActionPreference = 'Stop'
$cert = New-SelfSignedCertificate \`
  -Type CodeSigningCert \`
  -Subject '${SUBJECT}' \`
  -FriendlyName '${CERT_FRIENDLY_NAME}' \`
  -CertStoreLocation 'Cert:\\CurrentUser\\My' \`
  -KeyUsage DigitalSignature \`
  -KeyExportPolicy NonExportable \`
  -NotAfter (Get-Date).AddYears(10) \`
  -HashAlgorithm SHA256
foreach ($store in 'Root','TrustedPublisher') {
  $s = Get-Item "Cert:\\CurrentUser\\$store"
  $s.Open('ReadWrite')
  $s.Add($cert)
  $s.Close()
}
Write-Output $cert.Thumbprint
`.trim();

    const { stdout } = await this.runCmd('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { timeout: 60000 });

    const thumbprint = stdout.trim().toUpperCase();
    if (!/^[A-F0-9]{40}$/.test(thumbprint)) {
      throw new Error(`Unexpected thumbprint output: ${stdout.slice(0, 120)}`);
    }
    return thumbprint;
  }
}

module.exports = RdpSigner;
