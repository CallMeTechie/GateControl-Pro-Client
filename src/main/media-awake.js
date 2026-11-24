'use strict';

/**
 * Medien (Stufe 4g): no sleep while a film plays. The player of the page says 'playing' (also every few seconds
 * while it plays), 'paused' or 'stopped'; Windows may sleep (and turn the screen off) again one minute after a pause,
 * at once after the player closed — and on its own when the page stops saying 'playing' for two minutes (a page that
 * reloaded or died never keeps the PC awake). Electron's powerSaveBlocker 'prevent-display-sleep'.
 *
 * Kept free of module-level Electron access so it can be unit-tested (test/media-awake.test.js).
 */

const PAUSE_GRACE_MS = 60 * 1000;
const WATCHDOG_MS = 2 * 60 * 1000;
const STATES = ['playing', 'paused', 'stopped'];

/**
 * @param {object} opts
 * @param {object} opts.powerSaveBlocker - Electron's powerSaveBlocker (start, stop, isStarted)
 * @param {object} [opts.log]
 * @param {object} [opts.timers] - { setTimeout, clearTimeout } (tests)
 * @param {number} [opts.graceMs] - after a pause
 * @param {number} [opts.watchdogMs] - without 'playing'
 */
function createMediaAwake({ powerSaveBlocker, log = null, timers = { setTimeout, clearTimeout }, graceMs = PAUSE_GRACE_MS, watchdogMs = WATCHDOG_MS } = {}) {
  let id = null;
  let release = null;
  let watchdog = null;
  const clear = (t) => { if (t) timers.clearTimeout(t); return null; };

  function hold() {
    if (id !== null && powerSaveBlocker.isStarted(id)) return;
    try { id = powerSaveBlocker.start('prevent-display-sleep'); } catch (err) { id = null; if (log) log.warn(`Medien: sleep not blocked (${err.message})`); }
  }

  function free() {
    release = clear(release);
    watchdog = clear(watchdog);
    if (id === null) return;
    try { if (powerSaveBlocker.isStarted(id)) powerSaveBlocker.stop(id); } catch { /* gone */ }
    id = null;
  }

  /** 'playing' | 'paused' | 'stopped' → whether sleep is blocked now. */
  function set(state) {
    if (!STATES.includes(state)) return id !== null;
    if (state === 'playing') {
      release = clear(release);
      hold();
      watchdog = clear(watchdog);
      watchdog = timers.setTimeout(() => free(), watchdogMs);
    } else if (state === 'paused') {
      watchdog = clear(watchdog);
      if (id !== null && !release) release = timers.setTimeout(() => free(), graceMs);
    } else {
      free();
    }
    return id !== null;
  }

  return { set, stop: () => free(), get active() { return id !== null; } };
}

module.exports = { createMediaAwake, PAUSE_GRACE_MS, WATCHDOG_MS };
