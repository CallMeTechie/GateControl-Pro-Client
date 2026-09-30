'use strict';

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

/**
 * Startup migration that undoes two machine-wide trust changes made by
 * older GateControl Pro versions (<= 1.22.0):
 *
 *  1. HKCU\SOFTWARE\Microsoft\Terminal Server Client\AuthenticationLevelOverride = 0
 *     This disabled the server-certificate warning for EVERY mstsc
 *     connection of the user, not just GateControl's. Server authentication
 *     is now configured per connection inside the generated .rdp file
 *     (see RdpConfigBuilder), so the global value is removed again.
 *
 *  2. The self-signed "CN=GateControl RDP Signing" code-signing certificate
 *     that RdpSigner put into CurrentUser\My, \Root and \TrustedPublisher to
 *     sign .rdp files. A trusted root with code-signing EKU lets anybody who
 *     obtains the key sign code that Windows trusts. .rdp signing has been
 *     dropped, so the certificate is removed from all three stores.
 *
 * Both steps are strictly scoped to what GateControl itself created; see the
 * comments at each step. Each step is recorded in electron-store once it has
 * completed successfully so it never runs again (and therefore never touches
 * a value the user sets deliberately later on). A failed step is retried on
 * the next start.
 */

const TSC_KEY = 'HKCU\\SOFTWARE\\Microsoft\\Terminal Server Client';
const OVERRIDE_VALUE = 'AuthenticationLevelOverride';

// Exactly what the old RdpSigner created (rdp-signer.js, removed).
const LEGACY_CERT_SUBJECT = 'CN=GateControl RDP Signing';
const LEGACY_CERT_FRIENDLY_NAME = 'GateControl RDP Signing';
const LEGACY_CERT_DIR = 'rdp-signing';
const LEGACY_THUMBPRINT_FILE = 'thumbprint.txt';
const CODE_SIGNING_EKU = '1.3.6.1.5.5.7.3.3';

const STORE_KEY_OVERRIDE = 'migrations.rdpAuthOverrideRemoved';
const STORE_KEY_CERT = 'migrations.rdpSigningCertRemoved';

const THUMBPRINT_RE = /^[A-F0-9]{40}$/;

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
 * Parse the DWORD printed by `reg query <key> /v <name>`.
 * @returns {number|null} the value, or null if not present / not a DWORD
 */
function parseRegDword(stdout, name) {
  const re = new RegExp(`^\\s*${name}\\s+REG_DWORD\\s+0x([0-9a-f]+)\\s*$`, 'im');
  const m = String(stdout || '').match(re);
  return m ? parseInt(m[1], 16) : null;
}

/**
 * Step 1: remove the global AuthenticationLevelOverride — but only if it
 * still holds the value we wrote (REG_DWORD 0).
 *
 * Decision: the old code always wrote exactly REG_DWORD 0 and there is no
 * marker that tells "set by GateControl" apart from "set by the user", so
 * value == 0 is treated as ours and deleted. Any other value (1, 2, other
 * type) was not written by us and is left untouched. Deleting instead of
 * restoring is correct because the value does not exist on a stock Windows
 * install (mstsc then falls back to its default, "warn") and the old code
 * never saved a previous value that could be restored.
 *
 * @returns {Promise<'removed'|'absent'|'kept'>}
 */
async function removeGlobalAuthLevelOverride({ runCmd = defaultRunCmd, log }) {
  let stdout;
  try {
    ({ stdout } = await runCmd('reg', ['query', TSC_KEY, '/v', OVERRIDE_VALUE], { timeout: 5000 }));
  } catch (err) {
    // reg.exe exits with 1 when the key or value does not exist.
    if (err && err.code === 1) return 'absent';
    throw err;
  }

  const value = parseRegDword(stdout, OVERRIDE_VALUE);
  if (value === null) {
    if (!new RegExp(OVERRIDE_VALUE, 'i').test(stdout)) return 'absent';
    log.info(`${OVERRIDE_VALUE} has a non-DWORD type; not written by GateControl, keeping it`);
    return 'kept';
  }
  if (value !== 0) {
    log.info(`${OVERRIDE_VALUE}=${value} was not set by GateControl; keeping it`);
    return 'kept';
  }

  await runCmd('reg', ['delete', TSC_KEY, '/v', OVERRIDE_VALUE, '/f'], { timeout: 5000 });
  log.info(`Removed global ${OVERRIDE_VALUE}=0 set by an older GateControl version`);
  return 'removed';
}

function readLegacyThumbprint(fsImpl, userDataDir) {
  try {
    const file = path.join(userDataDir, LEGACY_CERT_DIR, LEGACY_THUMBPRINT_FILE);
    if (!fsImpl.existsSync(file)) return null;
    const value = String(fsImpl.readFileSync(file, 'utf-8')).trim().toUpperCase();
    return THUMBPRINT_RE.test(value) ? value : null;
  } catch {
    return null;
  }
}

/**
 * Build the PowerShell script that removes the legacy signing cert.
 *
 * A certificate is only removed if ALL of these hold:
 *   - Subject is exactly 'CN=GateControl RDP Signing' and Issuer == Subject
 *     (self-signed, as created by New-SelfSignedCertificate)
 *   - FriendlyName is 'GateControl RDP Signing' (only checked in My: the
 *     friendly name is a per-store property and was not copied along into
 *     Root/TrustedPublisher)
 *   - its only EKU is Code Signing
 *   - if we still know the thumbprint we recorded at creation time, the
 *     thumbprint matches exactly
 * Nothing else in the stores is touched.
 *
 * Exported for tests.
 */
function buildCertCleanupScript(thumbprint) {
  if (thumbprint !== null && !THUMBPRINT_RE.test(thumbprint)) {
    throw new Error('invalid thumbprint');
  }
  const tpLiteral = thumbprint ? `'${thumbprint}'` : '$null';
  return `
$ErrorActionPreference = 'Stop'
$subject = '${LEGACY_CERT_SUBJECT}'
$friendly = '${LEGACY_CERT_FRIENDLY_NAME}'
$eku = '${CODE_SIGNING_EKU}'
$tp = ${tpLiteral}
$removed = 0
foreach ($name in 'Root','TrustedPublisher','My') {
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name, 'CurrentUser')
  $store.Open('ReadWrite')
  try {
    $hits = @($store.Certificates | Where-Object {
      $ekus = @($_.Extensions |
        Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
        ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
      $_.Subject -ceq $subject -and $_.Issuer -ceq $subject -and
      ($null -eq $tp -or $_.Thumbprint -eq $tp) -and
      ($name -ne 'My' -or $_.FriendlyName -ceq $friendly) -and
      ($ekus -join ',') -eq $eku
    })
    foreach ($c in $hits) {
      $store.Remove($c)
      $removed++
      Write-Output ("removed " + $name + " " + $c.Thumbprint)
    }
  } finally {
    $store.Close()
  }
}
Write-Output ("total " + $removed)
`.trim();
}

/**
 * Step 2: remove the legacy self-signed signing cert from CurrentUser\Root,
 * \TrustedPublisher and \My, then drop the thumbprint marker file.
 * @returns {Promise<number>} number of store entries removed
 */
async function removeLegacySigningCert({ runCmd = defaultRunCmd, fsImpl = fs, userDataDir, log }) {
  const thumbprint = readLegacyThumbprint(fsImpl, userDataDir);
  const script = buildCertCleanupScript(thumbprint);
  const { stdout } = await runCmd('powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', script],
    { timeout: 60000 });

  const m = String(stdout || '').match(/total\s+(\d+)/);
  if (!m) throw new Error(`unexpected cleanup output: ${String(stdout).slice(0, 120)}`);
  const removed = parseInt(m[1], 10);
  if (removed > 0) {
    log.info(`Removed legacy GateControl RDP signing certificate (${removed} store entries)`);
  }

  // Leftovers of the old signer: thumbprint marker dir and the rdpsign.exe
  // copy it may have restored from WinSxS into <userData>\bin.
  const leftovers = [
    path.join(userDataDir, LEGACY_CERT_DIR),
    path.join(userDataDir, 'bin', 'rdpsign.exe'),
  ];
  for (const p of leftovers) {
    try {
      if (fsImpl.existsSync(p)) fsImpl.rmSync(p, { recursive: true, force: true });
    } catch (err) {
      log.debug(`Could not delete ${p}: ${err.message}`);
    }
  }
  return removed;
}

/**
 * Run both migration steps once per installation (Windows only).
 * Never throws; failures are logged and retried on the next start.
 *
 * @param {object} opts
 * @param {object} opts.store - electron-store (get/set)
 * @param {object} opts.log
 * @param {string} opts.userDataDir - app.getPath('userData')
 * @param {string} [opts.platform]
 * @param {function} [opts.runCmd]
 * @param {object} [opts.fsImpl]
 */
async function runRdpTrustMigration({ store, log, userDataDir, platform = process.platform, runCmd, fsImpl }) {
  if (platform !== 'win32') return;

  if (!store.get(STORE_KEY_OVERRIDE, false)) {
    try {
      await removeGlobalAuthLevelOverride({ runCmd, log });
      store.set(STORE_KEY_OVERRIDE, true);
    } catch (err) {
      log.warn(`Could not clean up ${OVERRIDE_VALUE}: ${err.message}`);
    }
  }

  if (!store.get(STORE_KEY_CERT, false)) {
    try {
      await removeLegacySigningCert({ runCmd, fsImpl, userDataDir, log });
      store.set(STORE_KEY_CERT, true);
    } catch (err) {
      log.warn(`Could not remove legacy RDP signing certificate: ${err.message}`);
    }
  }
}

module.exports = {
  runRdpTrustMigration,
  removeGlobalAuthLevelOverride,
  removeLegacySigningCert,
  buildCertCleanupScript,
  parseRegDword,
  STORE_KEY_OVERRIDE,
  STORE_KEY_CERT,
};
