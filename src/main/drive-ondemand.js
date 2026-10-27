'use strict';

/**
 * Drive „Dateien bei Bedarf“ (W3a): startet und steuert gc-drive-sync.exe,
 * das Sync-Programm für den Explorer (Cloud Files API, drive-sync/README.md).
 *
 *   - Standardmäßig AUS (Einstellung `driveOnDemand.enabled`, Vorgabe false):
 *     ohne ausdrückliches Einschalten startet nichts und es entsteht kein
 *     Ordner „GateControl Drive“.
 *   - Start: `gc-drive-sync.exe run --parent-pid <pid>`; die erste Zeile auf
 *     stdout nennt die benannte Pipe ({"event":"ready","pipe":…}). Server-Adresse
 *     und Geräte-Token gehen nur über diese Pipe (`configure`), nie über die
 *     Kommandozeile oder die Umgebung; die Pipe ist nur für den angemeldeten
 *     Benutzer zugänglich (drive-sync/PROTOCOL.md).
 *   - Server/Token wie der übrige Client (store server.url / server.apiKey,
 *     Kopfzeilen von apiClient.buildHeaders()); ändern sie sich, folgt ein neues
 *     `configure`.
 *   - Endet das Programm unerwartet, wird es mit wachsendem Abstand neu
 *     gestartet (5 s … 5 min). Endet der Pro-Client, endet es auch (--parent-pid).
 *   - Status und Logzeilen gehen an `onStatus` / das Log; die IPC-Kanäle
 *     drive-ondemand:* (ipc-pro.js) und die Preload-Brücke
 *     `gatecontrol.driveOnDemand` reichen sie weiter. Keine Oberfläche (W3b).
 *
 * Nicht „drive-sync“ genannt, weil „Ordner sichern“ (W2) schon core
 * services/drive-sync.js, die Kanäle drive:sync:* und den Store-Schlüssel
 * `driveSync` belegt.
 *
 * Ohne Electron auf Modulebene (spawn, net, store, … werden übergeben), damit
 * test/drive-ondemand.test.js es mit einem Fake-Programm und einer Fake-Pipe prüft.
 */

const path = require('path');
const { EventEmitter } = require('events');

const STORE_KEY = 'driveOnDemand';
const PIPE_RE = /^\\\\\.\\pipe\\gatecontrol-drive-sync-[A-Za-z0-9-]{8,200}$/;
const REQUEST_TIMEOUT_MS = 30000;
const READY_TIMEOUT_MS = 20000;
const RESTART_DELAYS_MS = [5000, 15000, 30000, 60000, 120000, 300000];
const HEADER_ALLOW = ['X-Client-Version', 'X-Client-Platform', 'X-Client-Type', 'X-Machine-Fingerprint'];

/** Pfad der Exe: im Paket resources/drive-sync, sonst der Release-Build im Repo. */
function defaultExePath({ isPackaged, resourcesPath, appRoot }) {
  if (isPackaged) return path.join(resourcesPath, 'drive-sync', 'gc-drive-sync.exe');
  return path.join(appRoot, 'drive-sync', 'target', 'release', 'gc-drive-sync.exe');
}

/** Nur die erlaubten Kopfzeilen (nie das Token – das geht als `token`). */
function pickHeaders(h) {
  const out = {};
  if (!h || typeof h !== 'object') return out;
  for (const name of HEADER_ALLOW) {
    const v = h[name];
    if (typeof v === 'string' && v && v.length <= 256 && /^[\x20-\x7e]*$/.test(v)) out[name] = v;
  }
  return out;
}

function noopLog() { return { info() {}, warn() {}, error() {}, debug() {} }; }

/**
 * @param {object} o
 * @param {object} o.store - electron-store (driveOnDemand.enabled, server.*)
 * @param {object} [o.log]
 * @param {() => {url: string, apiKey: string}} o.getServer
 * @param {() => object} [o.getHeaders] - apiClient.buildHeaders()
 * @param {() => string} [o.getDeviceName] - os.hostname()
 * @param {string} o.exePath
 * @param {string} [o.appVersion]
 * @param {Function} [o.spawn] - child_process.spawn
 * @param {Function} [o.connect] - net.connect
 * @param {Function} [o.exists] - fs.existsSync
 * @param {string} [o.platform=process.platform]
 * @param {number} [o.parentPid=process.pid]
 * @param {RegExp} [o.pipePattern] - Tests: erlaubte Pipe-Namen
 * @param {(status: object) => void} [o.onStatus]
 * @param {{ setTimeout: Function, clearTimeout: Function }} [o.timers]
 */
function createDriveOnDemand({
  store, log = noopLog(), getServer, getHeaders = () => ({}), getDeviceName = () => require('os').hostname(),
  exePath, appVersion = '', spawn = require('child_process').spawn, connect = require('net').connect,
  exists = require('fs').existsSync, platform = process.platform, parentPid = process.pid,
  pipePattern = PIPE_RE, onStatus = () => {}, timers = { setTimeout, clearTimeout },
}) {
  const events = new EventEmitter();
  let child = null;
  let sock = null;
  let buf = '';
  let nextId = 1;
  const pending = new Map();
  let status = { state: 'disabled', pending: 0, transferring: 0, errors: [], lastSync: null };
  let restartTimer = null;
  let restarts = 0;
  let stopping = false;
  let lastConfig = '';

  const enabled = () => store.get(`${STORE_KEY}.enabled`, false) === true;

  function setStatus(s) {
    status = { ...status, ...s };
    try { onStatus(status); } catch { /* UI */ }
    events.emit('status', status);
  }

  function supported() {
    if (platform !== 'win32') return { ok: false, code: 'unsupported' };
    if (!exists(exePath)) return { ok: false, code: 'missing' };
    return { ok: true };
  }

  function configFromStore() {
    const s = getServer() || {};
    if (!s.url || !s.apiKey) return null;
    let headers = {};
    try { headers = pickHeaders(getHeaders()); } catch { headers = {}; }
    return { serverUrl: String(s.url), token: String(s.apiKey), deviceName: String(getDeviceName() || 'PC').slice(0, 100), headers };
  }

  function rejectAll(err) {
    for (const p of pending.values()) {
      timers.clearTimeout(p.timer);
      p.reject(err);
    }
    pending.clear();
  }

  /** Eine Anfrage über die Pipe → result (oder Fehler mit code). */
  function request(cmd, args = {}) {
    if (!sock) return Promise.reject(Object.assign(new Error('not running'), { code: 'not_running' }));
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const timer = timers.setTimeout(() => {
        pending.delete(id);
        reject(Object.assign(new Error(`${cmd}: timeout`), { code: 'timeout' }));
      }, REQUEST_TIMEOUT_MS);
      pending.set(id, { resolve, reject, timer });
      sock.write(`${JSON.stringify({ id, cmd, ...args })}\n`);
    });
  }

  function onLine(line) {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    if (!msg || typeof msg !== 'object') return;
    if (msg.event === 'status') {
      const { event, ...st } = msg; // eslint-disable-line no-unused-vars
      setStatus(st);
      return;
    }
    if (msg.event === 'log') {
      const level = ['info', 'warn', 'error'].includes(msg.level) ? msg.level : 'info';
      log[level](`[drive-sync] ${String(msg.message || '').slice(0, 500)}`);
      return;
    }
    const p = pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    timers.clearTimeout(p.timer);
    if (msg.ok) p.resolve(msg.result);
    else p.reject(Object.assign(new Error(msg.error?.message || 'failed'), { code: msg.error?.code || 'failed' }));
  }

  function attach(pipeName) {
    return new Promise((resolve, reject) => {
      const s = connect(pipeName);
      s.setEncoding('utf8');
      s.once('connect', () => { sock = s; resolve(); });
      s.once('error', (err) => { if (!sock) reject(err); });
      s.on('data', (d) => {
        buf += d;
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i).trim();
          buf = buf.slice(i + 1);
          if (line) onLine(line);
        }
        if (buf.length > 1024 * 1024) buf = '';
      });
      s.on('close', () => {
        if (sock === s) sock = null;
        rejectAll(Object.assign(new Error('pipe closed'), { code: 'not_running' }));
      });
    });
  }

  /** Programm starten, Pipe verbinden, configure + start. */
  async function launch() {
    const sup = supported();
    if (!sup.ok) { setStatus({ state: sup.code }); return false; }
    const cfg = configFromStore();
    if (!cfg) { setStatus({ state: 'unconfigured' }); return false; }
    stopping = false;
    setStatus({ state: 'starting' });
    const proc = spawn(exePath, ['run', '--parent-pid', String(parentPid)], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    child = proc;
    const pipeName = await new Promise((resolve, reject) => {
      let out = '';
      let done = false;
      const timer = timers.setTimeout(() => reject(new Error('no ready line')), READY_TIMEOUT_MS);
      proc.stdout.setEncoding?.('utf8');
      proc.stdout.on('data', (d) => {
        if (done) return; // nur die erste Zeile zählt
        out += d;
        const i = out.indexOf('\n');
        if (i < 0) return;
        done = true;
        const first = out.slice(0, i).trim();
        timers.clearTimeout(timer);
        try {
          const m = JSON.parse(first);
          if (m && m.event === 'ready' && typeof m.pipe === 'string' && pipePattern.test(m.pipe)) resolve(m.pipe);
          else reject(new Error(m && m.code ? `${m.code}: ${m.message || ''}` : 'unexpected first line'));
        } catch { reject(new Error('unexpected first line')); }
      });
      proc.once('exit', (code) => { timers.clearTimeout(timer); reject(new Error(`exited (${code})`)); });
      proc.once('error', (err) => { timers.clearTimeout(timer); reject(err); });
    }).catch((err) => { log.warn(`gc-drive-sync start failed: ${err.message}`); return null; });
    proc.stderr?.on('data', (d) => log.warn(`[drive-sync] ${String(d).trim().slice(0, 500)}`));
    proc.once('exit', (code) => onExit(proc, code));
    if (!pipeName) {
      try { proc.kill(); } catch { /* gone */ }
      return false;
    }
    try {
      await attach(pipeName);
      await request('hello', { version: appVersion });
      await request('configure', cfg);
      lastConfig = JSON.stringify(cfg);
      const st = await request('start');
      // Ein Status-Ereignis kann schon vor der Antwort angekommen sein – dann gilt es.
      if (st && typeof st === 'object' && status.state === 'starting') setStatus(st);
      restarts = 0;
      log.info('Drive „Dateien bei Bedarf“ gestartet');
      return true;
    } catch (err) {
      log.warn(`gc-drive-sync: ${err.code || ''} ${err.message}`);
      setStatus({ state: 'error', errors: [{ code: err.code || 'failed', message: err.message, at: new Date().toISOString() }] });
      return false;
    }
  }

  function onExit(proc, code) {
    if (child !== proc) return;
    child = null;
    if (sock) { try { sock.destroy(); } catch { /* closed */ } sock = null; }
    if (stopping || !enabled()) { setStatus({ state: 'disabled' }); return; }
    const delay = RESTART_DELAYS_MS[Math.min(restarts, RESTART_DELAYS_MS.length - 1)];
    restarts++;
    log.warn(`gc-drive-sync beendet (${code}) – Neustart in ${delay / 1000} s`);
    setStatus({ state: 'error', errors: [{ code: 'exited', message: `exit ${code}`, at: new Date().toISOString() }] });
    restartTimer = timers.setTimeout(() => { restartTimer = null; if (enabled() && !child) launch(); }, delay);
    restartTimer?.unref?.();
  }

  async function shutdown() {
    stopping = true;
    if (restartTimer) { timers.clearTimeout(restartTimer); restartTimer = null; }
    const proc = child;
    if (!proc) return;
    await request('shutdown').catch(() => {});
    await new Promise((resolve) => {
      if (child !== proc) return resolve();
      const t = timers.setTimeout(() => { try { proc.kill(); } catch { /* gone */ } resolve(); }, 5000);
      proc.once('exit', () => { timers.clearTimeout(t); resolve(); });
    });
  }

  /** Live-Ereignis `changed` des Plugins (Push-Strom) → sofort abgleichen. */
  function watchPush(pushClient) {
    if (!pushClient || typeof pushClient.on !== 'function') return () => {};
    const onEvent = (ev) => {
      if (!ev || ev.event !== 'plugin' || !ev.data || ev.data.plugin !== 'gatecontrol-drive' || ev.data.type !== 'changed') return;
      if (sock) request('sync-now').catch(() => {});
    };
    pushClient.on('event', onEvent);
    return () => pushClient.removeListener?.('event', onEvent);
  }

  return {
    events,
    watchPush,
    /** Beim App-Start: nur wenn eingeschaltet. */
    start() {
      if (!enabled()) { setStatus({ state: 'disabled' }); return Promise.resolve(false); }
      if (child) return Promise.resolve(true);
      return launch();
    },
    /** Beim Beenden der App. */
    stop: shutdown,
    isEnabled: enabled,
    status: () => ({ ...status, enabled: enabled(), supported: supported().ok }),
    async setEnabled(on) {
      store.set(`${STORE_KEY}.enabled`, on === true);
      if (on === true) return this.start();
      await shutdown();
      setStatus({ state: 'disabled' });
      return false;
    },
    /** Server-Adresse/Token geändert (server:setup, Anmeldung): neu konfigurieren. */
    async serverChanged() {
      if (!child || !sock) return;
      const cfg = configFromStore();
      if (!cfg) { await shutdown(); setStatus({ state: 'unconfigured' }); return; }
      if (JSON.stringify(cfg) === lastConfig) return;
      await request('configure', cfg).catch((err) => log.warn(`gc-drive-sync configure: ${err.message}`));
      lastConfig = JSON.stringify(cfg);
    },
    syncNow: () => request('sync-now'),
    pause: () => request('pause'),
    resume: () => request('resume'),
    /**
     * Sync-Root abmelden (Platzhalter „nur online“ weg, Geladenes bleibt) und
     * ausschalten. Läuft das Programm nicht, über `gc-drive-sync.exe unregister`.
     */
    async unregister() {
      store.set(`${STORE_KEY}.enabled`, false);
      if (child && sock) {
        stopping = true;
        const r = await request('unregister').catch((err) => ({ error: err.code || err.message }));
        await shutdown();
        setStatus({ state: 'disabled', registered: false });
        return r;
      }
      if (!supported().ok) return { error: supported().code };
      return new Promise((resolve) => {
        const p = spawn(exePath, ['unregister'], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
        let out = '';
        p.stdout.on('data', (d) => { out += d; });
        p.once('error', (err) => resolve({ error: err.message }));
        p.once('exit', (code) => {
          let r = null;
          try { r = JSON.parse(out.trim().split('\n').pop()); } catch { r = null; }
          setStatus({ state: 'disabled', registered: false });
          resolve(r || { unregistered: code === 0 });
        });
      });
    },
  };
}

/** drive-ondemand:* → Dienst; Fehler kommen als { ok: false, code } zurück. */
function driveOnDemandChannels(dod, log) {
  const call = (fn) => async (...args) => {
    if (!dod) return { ok: false, code: 'unsupported' };
    try {
      const result = await fn(...args);
      return { ok: true, result: result ?? null };
    } catch (err) {
      log.warn(`Drive on demand: ${err.message}`);
      return { ok: false, code: err.code || 'failed' };
    }
  };
  return {
    'drive-ondemand:status': () => (dod ? dod.status() : { state: 'unsupported', enabled: false, supported: false }),
    'drive-ondemand:set-enabled': call((_, on) => dod.setEnabled(on === true)),
    'drive-ondemand:sync-now': call(() => dod.syncNow()),
    'drive-ondemand:pause': call(() => dod.pause()),
    'drive-ondemand:resume': call(() => dod.resume()),
    'drive-ondemand:unregister': call(() => dod.unregister()),
  };
}

module.exports = { createDriveOnDemand, driveOnDemandChannels, defaultExePath, pickHeaders, STORE_KEY, PIPE_RE };
