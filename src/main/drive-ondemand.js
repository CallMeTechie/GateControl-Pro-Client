'use strict';

/**
 * Drive „Dateien bei Bedarf“: startet und steuert gc-drive-sync.exe, das
 * Sync-Programm für den Explorer (Cloud Files API, drive-sync/README.md).
 *
 *   - Standardmäßig AUS (Einstellung `driveOnDemand.enabled`, Vorgabe false):
 *     ohne ausdrückliches Einschalten startet nichts und es entsteht kein
 *     Ordner „GateControl Drive“.
 *   - Start: `gc-drive-sync.exe launch --parent-pid <pid>`. Der Starter startet
 *     den Dienst mit den Rechten des angemeldeten Benutzers (der Pro-Client
 *     läuft mit Administratorrechten), reicht dessen erste Zeile weiter
 *     ({"event":"ready","pipe":…,"launch":"token|parent|inprocess","elevated":…})
 *     und bleibt als Wächter. Server-Adresse und Geräte-Token gehen nur über
 *     die Pipe (`configure`), nie über die Kommandozeile oder die Umgebung;
 *     die Pipe ist nur für den angemeldeten Benutzer zugänglich
 *     (drive-sync/PROTOCOL.md).
 *   - Server/Token wie der übrige Client (store server.url / server.apiKey,
 *     Kopfzeilen von apiClient.buildHeaders()); ändern sie sich, folgt ein neues
 *     `configure`.
 *   - Endet das Programm unerwartet, wird es mit wachsendem Abstand neu
 *     gestartet (5 s … 5 min). Endet der Pro-Client, endet es auch.
 *   - Ausschalten = Sync-Root abmelden (`unregister`): gc-drive-sync lädt
 *     zuerst Ausstehendes hoch und lehnt ab, solange Windows-Ordner im Drive
 *     liegen (`relocated`) oder Änderungen nicht hochgeladen sind (`unsynced`,
 *     mit Pfaden) – dann bleibt alles eingeschaltet. Erst mit `force` bleiben
 *     solche Dateien als normale Dateien im Ordner (nichts wird gelöscht).
 *   - Windows-Ordner verlegen / zurücklegen, Massenlöschung (Nachfrage),
 *     belegter Platz, Kontextmenü (Ereignis `action` → `onAction`).
 *   - Drive 1.6 `guard`: hat Drive das Gerät gestoppt (Ereignis guard /
 *     me.guard im Pro-Client), geht `guard {locked}` an gc-drive-sync – es lädt
 *     sofort nichts mehr hoch; nach „War ich – freigeben“ / „Rückgängig machen“
 *     `guard {locked: false, undo}`. Die lokale Prüfung von gc-drive-sync
 *     (Zustand `suspect`) beantwortet `suspect('upload' | 'keep')`.
 *   - Status, Fortschritt und Logzeilen gehen an `onStatus` / das Log; die
 *     IPC-Kanäle drive-ondemand:* (ipc-pro.js) und die Preload-Brücke
 *     `gatecontrol.driveOnDemand` reichen sie weiter.
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
// Verlegen, Zurücklegen (lädt alles), Abmelden (lädt erst hoch): lange erlaubt
const LONG_TIMEOUT_MS = 6 * 60 * 60 * 1000;
const READY_TIMEOUT_MS = 30000;
const RESTART_DELAYS_MS = [5000, 15000, 30000, 60000, 120000, 300000];
const HEADER_ALLOW = ['X-Client-Version', 'X-Client-Platform', 'X-Client-Type', 'X-Machine-Fingerprint'];
const KNOWN = ['desktop', 'documents', 'pictures', 'videos', 'music'];
const ACTIONS = ['share', 'portal', 'versions'];

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

/** `--drive-action <a> --drive-path <p>` (Kontextmenü, als gc-drive-sync nicht lief) → { action, path } | null */
function parseActionArgv(argv) {
  if (!Array.isArray(argv)) return null;
  const i = argv.indexOf('--drive-action');
  const j = argv.indexOf('--drive-path');
  if (i < 0 || j < 0) return null;
  const action = argv[i + 1];
  const p = argv[j + 1];
  if (!ACTIONS.includes(action) || typeof p !== 'string' || !p || p.length > 4096) return null;
  return { action, path: p };
}

/** Liegt `p` in `dir` oder `dir` in `p` (Windows-Pfade, ohne Groß/Klein)? */
function overlaps(p, dir) {
  const norm = (x) => String(x || '').replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();
  const a = norm(p);
  const b = norm(dir);
  if (!a || !b) return false;
  return a === b || a.startsWith(`${b}\\`) || b.startsWith(`${a}\\`);
}

function noopLog() { return { info() {}, warn() {}, error() {}, debug() {} }; }

const err = (code, message, data) => Object.assign(new Error(message || code), { code, ...(data !== undefined ? { data } : {}) });

/**
 * @param {object} o
 * @param {object} o.store - electron-store (driveOnDemand.enabled, server.*)
 * @param {object} [o.log]
 * @param {() => {url: string, apiKey: string}} o.getServer
 * @param {() => object} [o.getHeaders] - apiClient.buildHeaders()
 * @param {() => string} [o.getDeviceName] - os.hostname()
 * @param {string} o.exePath
 * @param {string} [o.appVersion]
 * @param {string|null} [o.appExe] - Pro-Client-Exe (Kontextmenü, wenn gc-drive-sync nicht läuft)
 * @param {() => string} [o.getLang] - 'de' | 'en' (Texte des Kontextmenüs)
 * @param {(path: string) => string|null} [o.relocateBlocked] - Grund, warum ein Windows-Ordner nicht verlegt werden darf ('w2_active')
 * @param {(path: string) => Promise<string>} [o.openPath] - shell.openPath
 * @param {(a: { action, path, node, area, isDir }) => void} [o.onAction] - Kontextmenü
 * @param {Function} [o.spawn] - child_process.spawn
 * @param {Function} [o.connect] - net.connect
 * @param {Function} [o.exists] - fs.existsSync
 * @param {string} [o.platform=process.platform]
 * @param {number} [o.parentPid=process.pid]
 * @param {RegExp} [o.pipePattern] - Tests: erlaubte Pipe-Namen
 * @param {(status: object) => void} [o.onStatus]
 * @param {{ setTimeout: Function, clearTimeout: Function }} [o.timers]
 * @param {() => ({ locked: boolean } | null)} [o.getGuard] - Drive 1.6: ist das Gerät gerade gestoppt? (nach dem Start gemeldet)
 */
function createDriveOnDemand({
  store, log = noopLog(), getServer, getHeaders = () => ({}), getDeviceName = () => require('os').hostname(),
  exePath, appVersion = '', appExe = null, getLang = () => 'de', relocateBlocked = () => null, openPath = null, onAction = () => {},
  spawn = require('child_process').spawn, connect = require('net').connect,
  exists = require('fs').existsSync, platform = process.platform, parentPid = process.pid,
  pipePattern = PIPE_RE, onStatus = () => {}, timers = { setTimeout, clearTimeout }, getGuard = () => null,
}) {
  const events = new EventEmitter();
  let child = null;
  let sock = null;
  let buf = '';
  let nextId = 1;
  const pending = new Map();
  let status = { state: 'disabled', pending: 0, transferring: 0, errors: [], lastSync: null, massDelete: null, suspect: null, locked: false, held: 0, progress: null, busy: null };
  let restartTimer = null;
  let restarts = 0;
  let stopping = false;
  let lastConfig = '';
  let launching = null;
  let launchInfo = { launch: null, elevated: false };

  const enabled = () => store.get(`${STORE_KEY}.enabled`, false) === true;

  function supported() {
    if (platform !== 'win32') return { ok: false, code: 'unsupported' };
    if (!exists(exePath)) return { ok: false, code: 'missing' };
    return { ok: true };
  }

  function publicStatus() {
    return { ...status, ...launchInfo, enabled: enabled(), supported: supported().ok, running: !!sock };
  }

  function setStatus(s) {
    status = { ...status, ...s };
    const pub = publicStatus();
    try { onStatus(pub); } catch { /* UI */ }
    events.emit('status', pub);
  }

  function configFromStore() {
    const s = getServer() || {};
    if (!s.url || !s.apiKey) return null;
    let headers = {};
    try { headers = pickHeaders(getHeaders()); } catch { headers = {}; }
    return { serverUrl: String(s.url), token: String(s.apiKey), deviceName: String(getDeviceName() || 'PC').slice(0, 100), headers };
  }

  function rejectAll(e) {
    for (const p of pending.values()) {
      timers.clearTimeout(p.timer);
      p.reject(e);
    }
    pending.clear();
  }

  /** Eine Anfrage über die Pipe → result (oder Fehler mit code / data). */
  function request(cmd, args = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
    if (!sock) return Promise.reject(err('not_running', 'not running'));
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const timer = timers.setTimeout(() => {
        pending.delete(id);
        reject(err('timeout', `${cmd}: timeout`));
      }, timeoutMs);
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
      setStatus({ ...st, massDelete: st.massDelete || null, suspect: st.suspect || null, locked: st.locked === true, held: Number(st.held) || 0 });
      return;
    }
    if (msg.event === 'progress') {
      setStatus({ progress: { op: String(msg.op || ''), folder: msg.folder || null, phase: String(msg.phase || ''), done: Number(msg.done) || 0, total: Number(msg.total) || 0 } });
      return;
    }
    if (msg.event === 'action') {
      if (!ACTIONS.includes(msg.action)) return;
      try {
        onAction({ action: msg.action, path: String(msg.path || ''), node: Number.isSafeInteger(msg.node) && msg.node > 0 ? msg.node : null, area: msg.area || null, isDir: msg.isDir === true });
      } catch (e) { log.warn(`Drive action: ${e.message}`); }
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
    else p.reject(err(msg.error?.code || 'failed', msg.error?.message || 'failed', msg.error?.data));
  }

  function attach(pipeName) {
    return new Promise((resolve, reject) => {
      const s = connect(pipeName);
      s.setEncoding('utf8');
      s.once('connect', () => { sock = s; resolve(); });
      s.once('error', (e) => { if (!sock) reject(e); });
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
        rejectAll(err('not_running', 'pipe closed'));
      });
    });
  }

  /** Programm starten (über den Starter), Pipe verbinden, hello + configure + start. */
  async function launch() {
    const sup = supported();
    if (!sup.ok) { setStatus({ state: sup.code }); return false; }
    const cfg = configFromStore();
    if (!cfg) { setStatus({ state: 'unconfigured' }); return false; }
    stopping = false;
    setStatus({ state: 'starting' });
    const proc = spawn(exePath, ['launch', '--parent-pid', String(parentPid)], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    child = proc;
    const ready = await new Promise((resolve, reject) => {
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
          if (m && m.event === 'ready' && typeof m.pipe === 'string' && pipePattern.test(m.pipe)) resolve(m);
          else reject(Object.assign(new Error(m && m.code ? `${m.code}: ${m.message || ''}` : 'unexpected first line'), { code: (m && m.code) || 'launch' }));
        } catch { reject(new Error('unexpected first line')); }
      });
      proc.once('exit', (code) => { timers.clearTimeout(timer); reject(new Error(`exited (${code})`)); });
      proc.once('error', (e) => { timers.clearTimeout(timer); reject(e); });
    }).catch((e) => { log.warn(`gc-drive-sync start failed: ${e.message}`); return { error: e }; });
    proc.stderr?.on('data', (d) => log.warn(`[drive-sync] ${String(d).trim().slice(0, 500)}`));
    proc.once('exit', (code) => onExit(proc, code));
    if (!ready || ready.error) {
      try { proc.kill(); } catch { /* gone */ }
      const code = ready && ready.error && ready.error.code === 'wrong_user' ? 'wrong_user' : 'launch';
      setStatus({ state: 'error', errors: [{ code, message: ready && ready.error ? ready.error.message : 'launch', at: new Date().toISOString() }] });
      return false;
    }
    launchInfo = { launch: ['token', 'parent', 'inprocess'].includes(ready.launch) ? ready.launch : 'direct', elevated: ready.elevated === true };
    if (launchInfo.elevated) log.warn('gc-drive-sync läuft mit Administratorrechten (kein Start mit Benutzerrechten möglich)');
    try {
      await attach(ready.pipe);
      await request('hello', { version: appVersion, lang: getLang() === 'en' ? 'en' : 'de', ...(appExe ? { appExe } : {}) });
      await request('configure', cfg);
      lastConfig = JSON.stringify(cfg);
      const st = await request('start');
      // Ein Status-Ereignis kann schon vor der Antwort angekommen sein – dann gilt es.
      if (st && typeof st === 'object' && status.state === 'starting') setStatus(st);
      // Drive hat das Gerät schon gestoppt: sofort melden
      let g = null;
      try { g = getGuard(); } catch { g = null; }
      if (g && g.locked) await request('guard', { locked: true }).catch(() => {});
      restarts = 0;
      log.info(`Drive „Dateien bei Bedarf“ gestartet (${launchInfo.launch})`);
      return true;
    } catch (e) {
      log.warn(`gc-drive-sync: ${e.code || ''} ${e.message}`);
      setStatus({ state: 'error', errors: [{ code: e.code || 'failed', message: e.message, at: new Date().toISOString() }] });
      return false;
    }
  }

  function ensureRunning() {
    if (sock) return Promise.resolve(true);
    if (!launching) launching = launch().finally(() => { launching = null; });
    return launching;
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
    restartTimer = timers.setTimeout(() => { restartTimer = null; if (enabled() && !child) ensureRunning(); }, delay);
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

  /** Langer Befehl mit Markierung im Status (die Oberfläche zeigt „läuft …“). */
  async function busy(kind, folder, fn) {
    if (status.busy) throw err('busy', 'another operation runs');
    setStatus({ busy: { kind, folder: folder || null }, progress: null });
    try { return await fn(); } finally { setStatus({ busy: null, progress: null }); }
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

  /**
   * Abmelden über `gc-drive-sync.exe unregister` (nur, wenn das Programm nicht startet).
   * Liegen Windows-Ordner im Drive, lehnt es ab (Exit 4, `relocated`) – dann bleibt alles an.
   */
  function unregisterCli() {
    return new Promise((resolve, reject) => {
      const p = spawn(exePath, ['unregister'], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
      let out = '';
      p.stdout.on('data', (d) => { out += d; });
      p.once('error', (e) => resolve({ error: e.message }));
      p.once('exit', (code) => {
        let r = null;
        try { r = JSON.parse(out.trim().split('\n').pop()); } catch { r = null; }
        if (r && r.error === 'relocated') {
          reject(err('relocated', 'Windows folders lie in Drive', { folders: Array.isArray(r.folders) ? r.folders : [] }));
          return;
        }
        store.set(`${STORE_KEY}.enabled`, false);
        setStatus({ state: 'disabled', registered: false });
        resolve(r || { unregistered: code === 0 });
      });
    });
  }

  const api = {
    events,
    watchPush,
    /** Beim App-Start: nur wenn eingeschaltet. */
    start() {
      if (!enabled()) { setStatus({ state: 'disabled' }); return Promise.resolve(false); }
      if (child && sock) return Promise.resolve(true);
      return ensureRunning();
    },
    /** Beim Beenden der App. */
    stop: shutdown,
    isEnabled: enabled,
    status: () => publicStatus(),
    /** Ordner „GateControl Drive“ (Sync-Root) – bekannt, sobald das Programm ihn gemeldet hat. */
    syncRoot: () => (typeof status.syncRoot === 'string' && status.syncRoot ? status.syncRoot : null),
    /** Einschalten. */
    async enable() {
      store.set(`${STORE_KEY}.enabled`, true);
      return ensureRunning();
    },
    /**
     * Ausschalten: Sync-Root abmelden. Wirft `relocated` / `unsynced` (mit
     * `data`) – dann bleibt alles an. `force`: nicht hochgeladene Dateien
     * bleiben als normale Dateien im Ordner.
     */
    async disable({ force = false } = {}) {
      if (!sock && supported().ok && (enabled() || status.registered)) {
        await ensureRunning();
      }
      if (!sock) {
        // Programm startet nicht (z. B. ohne Server): abmelden ohne Abgleich
        if (!force && enabled() && supported().ok) throw err('not_running', 'gc-drive-sync does not start');
        if (!supported().ok) { store.set(`${STORE_KEY}.enabled`, false); setStatus({ state: 'disabled' }); return { unregistered: false }; }
        return unregisterCli();
      }
      const r = await busy('disable', null, () => request('unregister', { force: force === true }, LONG_TIMEOUT_MS));
      store.set(`${STORE_KEY}.enabled`, false);
      await shutdown();
      setStatus({ state: 'disabled', registered: false, massDelete: null, errors: [] });
      return r;
    },
    /** An = enable, aus = disable (mit Prüfung). */
    async setEnabled(on) {
      if (on === true) return api.enable();
      await api.disable();
      return false;
    },
    /** Server-Adresse/Token geändert (server:setup, Anmeldung): neu konfigurieren. */
    async serverChanged() {
      if (!child || !sock) return;
      const cfg = configFromStore();
      if (!cfg) { await shutdown(); setStatus({ state: 'unconfigured' }); return; }
      if (JSON.stringify(cfg) === lastConfig) return;
      await request('configure', cfg).catch((e) => log.warn(`gc-drive-sync configure: ${e.message}`));
      lastConfig = JSON.stringify(cfg);
    },
    syncNow: () => request('sync-now'),
    /**
     * Drive 1.6 `guard`: gestoppt / frei (`undo`: Drive hat die Änderungen rückgängig gemacht).
     * Läuft gc-drive-sync nicht, gibt es nichts zu tun.
     */
    guard(locked, undo = false) {
      if (!sock) return Promise.resolve(null);
      return request('guard', { locked: locked === true, undo: undo === true });
    },
    /** Antwort auf die lokale Prüfung: 'upload' (hochladen) | 'keep' (pausiert lassen). */
    suspect: (decision) => {
      if (!['upload', 'keep'].includes(decision)) return Promise.reject(err('invalid', 'decision'));
      return request('suspect', { decision });
    },
    pause: () => request('pause'),
    resume: () => request('resume'),
    /** Antwort auf die Massenlöschung: 'apply' (Löschen übertragen) | 'restore'. */
    deletes: (decision) => {
      if (!['apply', 'restore'].includes(decision)) return Promise.reject(err('invalid', 'decision'));
      return request('deletes', { decision }, LONG_TIMEOUT_MS);
    },
    usage: () => request('usage', {}, 5 * 60 * 1000),
    /** Windows-Ordner → { folders: [{ key, path, inDrive, from }], syncRoot } */
    knownFolders: () => request('known-folders'),
    /** Windows-Ordner verlegen (nur nach Zustimmung in der Oberfläche). */
    async relocate(folder, name = null) {
      if (!KNOWN.includes(folder)) throw err('invalid', 'folder');
      const list = await request('known-folders');
      const f = (list && Array.isArray(list.folders) ? list.folders : []).find((x) => x && x.key === folder);
      if (!f || !f.path) throw err('known_folder', 'unknown folder');
      const why = relocateBlocked(f.path);
      if (why) throw err(why, 'folder is backed up by "Ordner sichern"');
      const args = { folder, ...(typeof name === 'string' && name.trim() ? { name: name.trim().slice(0, 100) } : {}) };
      return busy('relocate', folder, () => request('relocate', args, LONG_TIMEOUT_MS));
    },
    async restore(folder) {
      if (!KNOWN.includes(folder)) throw err('invalid', 'folder');
      return busy('restore', folder, () => request('restore', { folder }, LONG_TIMEOUT_MS));
    },
    /** Den Ordner „GateControl Drive“ im Explorer öffnen. */
    async openRoot() {
      const root = api.syncRoot();
      if (!root || typeof openPath !== 'function') throw err('not_running', 'no sync root');
      const e = await openPath(root);
      if (e) throw err('failed', e);
      return { opened: true };
    },
    /** Kontextmenü-Aufruf aus den Argumenten (Pro-Client wurde dafür gestartet). */
    async action(a) {
      if (!a || !ACTIONS.includes(a.action)) throw err('invalid', 'action');
      if (!enabled()) throw err('disabled', 'Dateien bei Bedarf ist aus');
      await ensureRunning();
      return request('action', { action: a.action, path: a.path });
    },
    /**
     * Pfade, die „Ordner sichern“ (W2) nicht aufnehmen darf: der Ordner
     * „GateControl Drive“ (würde den Drive in sich selbst sichern und jede
     * Datei „nur online“ laden).
     */
    blockedPaths() {
      const root = api.syncRoot();
      return root && (enabled() || status.registered) ? [root] : [];
    },
    /** W3a-Name von `disable`. */
    unregister: (o) => api.disable(o),
  };
  return api;
}

/** drive-ondemand:* → Dienst; Fehler kommen als { ok: false, code, data? } zurück. */
function driveOnDemandChannels(dod, log) {
  const call = (fn) => async (...args) => {
    if (!dod) return { ok: false, code: 'unsupported' };
    try {
      const result = await fn(...args);
      return { ok: true, result: result ?? null };
    } catch (e) {
      log.warn(`Drive on demand: ${e.code || ''} ${e.message}`);
      return { ok: false, code: e.code || 'failed', ...(e.data !== undefined ? { data: e.data } : {}) };
    }
  };
  const str = (v) => (typeof v === 'string' ? v : '');
  return {
    'drive-ondemand:status': () => (dod ? dod.status() : { state: 'unsupported', enabled: false, supported: false }),
    'drive-ondemand:set-enabled': call((_, on) => dod.setEnabled(on === true)),
    'drive-ondemand:enable': call(() => dod.enable()),
    'drive-ondemand:disable': call((_, o) => dod.disable({ force: !!(o && o.force === true) })),
    'drive-ondemand:sync-now': call(() => dod.syncNow()),
    'drive-ondemand:pause': call(() => dod.pause()),
    'drive-ondemand:resume': call(() => dod.resume()),
    'drive-ondemand:unregister': call(() => dod.disable({ force: false })),
    'drive-ondemand:deletes': call((_, decision) => dod.deletes(str(decision))),
    'drive-ondemand:suspect': call((_, decision) => dod.suspect(str(decision))),
    'drive-ondemand:usage': call(() => dod.usage()),
    'drive-ondemand:known-folders': call(() => dod.knownFolders()),
    'drive-ondemand:relocate': call((_, folder, name) => dod.relocate(str(folder), typeof name === 'string' ? name : null)),
    'drive-ondemand:restore': call((_, folder) => dod.restore(str(folder))),
    'drive-ondemand:open-root': call(() => dod.openRoot()),
  };
}

module.exports = { createDriveOnDemand, driveOnDemandChannels, defaultExePath, pickHeaders, parseActionArgv, overlaps, STORE_KEY, PIPE_RE, KNOWN, ACTIONS };
