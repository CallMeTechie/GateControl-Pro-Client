'use strict';

/**
 * No sleep while a film or a video plays (Electron's powerSaveBlocker 'prevent-display-sleep'), one blocker for all.
 *
 * - The Medien player (Stufe 4g, key 'player') says 'playing' (also every few seconds while it plays), 'paused' or
 *   'stopped'; Windows may sleep (and turn the screen off) again one minute after a pause, at once after the player
 *   closed.
 * - The other videos of the app (Drive's viewer, the vault's viewer, the clips of the cameras — renderer/video-awake.js,
 *   keys 'video:<n>') say the same, without the minute: the screen stays on only while one of them really plays
 *   (as on Android: paused, ended, an error, buffering, closed or another one shown — off).
 *
 * Each key counts for itself: the blocker is held while at least one key plays (or the player's minute runs), so one
 * video that stops never frees the screen of another that still plays. A key that stops saying 'playing' for two
 * minutes is dropped on its own (a page that reloaded or died never keeps the PC awake).
 *
 * Kept free of module-level Electron access so it can be unit-tested (test/media-awake.test.js).
 */

const PAUSE_GRACE_MS = 60 * 1000;
const WATCHDOG_MS = 2 * 60 * 1000;
const STATES = ['playing', 'paused', 'stopped'];
const PLAYER = 'player';

/**
 * @param {object} opts
 * @param {object} opts.powerSaveBlocker - Electron's powerSaveBlocker (start, stop, isStarted)
 * @param {object} [opts.log]
 * @param {object} [opts.timers] - { setTimeout, clearTimeout } (tests)
 * @param {number} [opts.graceMs] - the player after a pause
 * @param {number} [opts.watchdogMs] - a key without 'playing'
 */
function createMediaAwake({ powerSaveBlocker, log = null, timers = { setTimeout, clearTimeout }, graceMs = PAUSE_GRACE_MS, watchdogMs = WATCHDOG_MS } = {}) {
  let id = null;
  /** key → { release, watchdog } (timers); a key in here keeps the screen on */
  const holders = new Map();
  const clear = (t) => { if (t) timers.clearTimeout(t); return null; };

  function hold() {
    if (id !== null && powerSaveBlocker.isStarted(id)) return;
    try { id = powerSaveBlocker.start('prevent-display-sleep'); } catch (err) { id = null; if (log) log.warn(`Medien: sleep not blocked (${err.message})`); }
  }

  function freeBlocker() {
    if (id === null) return;
    try { if (powerSaveBlocker.isStarted(id)) powerSaveBlocker.stop(id); } catch { /* gone */ }
    id = null;
  }

  function drop(key) {
    const h = holders.get(key);
    if (h) { clear(h.release); clear(h.watchdog); holders.delete(key); }
    if (!holders.size) freeBlocker();
  }

  /**
   * 'playing' | 'paused' | 'stopped' of `key` (default the Medien player) → whether sleep is blocked now.
   * `grace`: how long a pause keeps the screen on (the player a minute, the other videos none).
   */
  function set(state, key = PLAYER, grace = key === PLAYER ? graceMs : 0) {
    if (!STATES.includes(state) || typeof key !== 'string' || !key) return id !== null;
    if (state === 'playing') {
      const h = holders.get(key) || { release: null, watchdog: null };
      h.release = clear(h.release);
      h.watchdog = clear(h.watchdog);
      h.watchdog = timers.setTimeout(() => drop(key), watchdogMs);
      holders.set(key, h);
      hold();
    } else if (state === 'paused' && grace > 0) {
      const h = holders.get(key);
      if (h) {
        h.watchdog = clear(h.watchdog);
        if (!h.release) h.release = timers.setTimeout(() => drop(key), grace);
      }
    } else {
      drop(key);
    }
    return id !== null;
  }

  function stop() {
    for (const key of [...holders.keys()]) drop(key);
    freeBlocker();
  }

  return {
    set,
    stop,
    get active() { return id !== null; },
    /** how many keys keep the screen on now (tests, the log) */
    get holders() { return holders.size; },
  };
}

module.exports = { createMediaAwake, PAUSE_GRACE_MS, WATCHDOG_MS };
