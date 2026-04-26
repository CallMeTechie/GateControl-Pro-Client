'use strict';

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

const SUBJECT = 'CN=GateControl RDP Signing';
const CERT_FRIENDLY_NAME = 'GateControl RDP Signing';
const THUMBPRINT_FILE = 'thumbprint.txt';

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
   */
  constructor({ log, certDir, runCmd }) {
    if (!certDir) throw new Error('RdpSigner requires certDir');
    this.log = log;
    this.certDir = certDir;
    this.runCmd = runCmd || defaultRunCmd;
    this.thumbprint = null;
    this._readyPromise = null;
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
        fs.mkdirSync(this.certDir, { recursive: true });
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
   * Sign a .rdp file in place using rdpsign.exe. Non-fatal on failure —
   * the file remains usable, mstsc just shows the publisher warning.
   * @param {string} filePath - absolute path to the .rdp file
   * @returns {Promise<boolean>} true if signing succeeded
   */
  async sign(filePath) {
    const thumbprint = await this.ensureCertificate();
    if (!thumbprint) return false;

    try {
      await this.runCmd('rdpsign.exe', ['/sha256', thumbprint, filePath], { timeout: 10000 });
      this.log.debug(`RDP file signed: ${path.basename(filePath)}`);
      return true;
    } catch (err) {
      this.log.warn(`rdpsign.exe failed for ${path.basename(filePath)}:`, err.message);
      return false;
    }
  }

  // ── internals ────────────────────────────────────────────

  _readCachedThumbprint() {
    try {
      const file = path.join(this.certDir, THUMBPRINT_FILE);
      if (!fs.existsSync(file)) return null;
      const value = fs.readFileSync(file, 'utf-8').trim();
      return /^[A-F0-9]{40}$/i.test(value) ? value.toUpperCase() : null;
    } catch {
      return null;
    }
  }

  _writeCachedThumbprint(thumbprint) {
    const file = path.join(this.certDir, THUMBPRINT_FILE);
    fs.writeFileSync(file, thumbprint, { encoding: 'utf-8', mode: 0o600 });
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
