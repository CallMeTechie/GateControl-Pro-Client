/**
 * Device ID shown in Settings → About.
 *
 * The client sends the full machine fingerprint (64-hex SHA-256, core
 * utils/machine-id) as X-Machine-Fingerprint; the server's Users page shows
 * its first 8 hex characters as the device binding. Only that short form
 * ever leaves the main process: it is what the renderer displays and what
 * the support bundle carries. The full value is never returned or logged.
 */

'use strict';

const SHORT_LENGTH = 8;
const FINGERPRINT_RE = /^[0-9a-f]{64}$/;

/**
 * @param {Function} getFingerprint - () => 64-hex fingerprint (core getMachineFingerprint)
 * @param {object} [log]
 * @returns {string|null} first 8 lowercase hex characters, or null if unavailable
 */
function shortDeviceId(getFingerprint, log) {
  try {
    const fingerprint = String(getFingerprint() || '').trim().toLowerCase();
    if (!FINGERPRINT_RE.test(fingerprint)) throw new Error('unexpected fingerprint format');
    return fingerprint.slice(0, SHORT_LENGTH);
  } catch (err) {
    // Message only: never the fingerprint itself.
    log?.warn?.(`Device ID unavailable: ${err && err.message ? err.message : 'unknown error'}`);
    return null;
  }
}

/**
 * Wrap the core support-bundle collector so the bundle carries the short
 * device ID as client.deviceId (null if unavailable).
 * @param {Function} collect - core collectSupportBundle(ctx, opts)
 * @param {Function} getDeviceId - () => short ID or null
 */
function withDeviceId(collect, getDeviceId) {
  return async (ctx, opts) => {
    const bundle = await collect(ctx, opts);
    if (bundle && bundle.client && typeof bundle.client === 'object') {
      let deviceId = null;
      try { deviceId = getDeviceId(); } catch { /* unavailable */ }
      bundle.client.deviceId = deviceId || null;
    }
    return bundle;
  };
}

module.exports = { shortDeviceId, withDeviceId, SHORT_LENGTH };
