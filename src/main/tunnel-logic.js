'use strict';

/**
 * Pure, Electron-free decision logic for the tunnel/portal state machine.
 *
 * Extracted from main.js so it can be unit-tested under `node --test` without
 * an Electron runtime. main.js requires these helpers and the tests exercise
 * the same code — no logic is duplicated between app and test.
 */

/**
 * Exponential backoff delay (ms) for the Nth reconnect attempt (0-based),
 * capped so a long outage doesn't grow the wait unboundedly. Mirrors the
 * Community client's reconnect schedule.
 *
 * @param {number} attempt 0-based attempt index
 * @param {{base?: number, factor?: number, cap?: number}} [opts]
 * @returns {number} delay in milliseconds
 */
function reconnectDelay(attempt, { base = 2000, factor = 1.5, cap = 60000 } = {}) {
  return Math.min(base * Math.pow(factor, attempt), cap);
}

/**
 * Whether the portal should auto-open right now. Opens once per
 * *user-initiated* connect: requires a URL, the server's autoOpen flag, and a
 * connectedSince timestamp we have not already opened for. The reconnect path
 * never reaches this (it does not run the connect sequence), so a reconnect —
 * which mints a fresh connectedSince — cannot re-open the browser.
 *
 * @param {{portalUrl: ?string, autoOpenPortal: boolean, connectedSince: number, lastOpenedSince: ?number}} s
 * @returns {boolean}
 */
function shouldOpenPortal({ portalUrl, autoOpenPortal, connectedSince, lastOpenedSince }) {
  return Boolean(portalUrl) && autoOpenPortal === true && connectedSince !== lastOpenedSince;
}

module.exports = { reconnectDelay, shouldOpenPortal };
