'use strict';

/**
 * GateControl – Fernzugriff stage 3: the SSH terminal of the Pro client
 *
 * The SSH devices of the plugin "Fernzugriff" stand on the page „Fernzugriff“ (the former „Remote Desktops“) next
 * to the RDP hosts; „Verbinden“ opens one terminal window for all sessions, a tab each (design questions 2 and 3).
 * The connection itself is core's RemoteTerm in this main process: ticket, single-use token, WebSocket gc-term.v1,
 * the backoff. The window only gets the terminal's bytes and the state, and sends what is typed.
 *
 * The window (terminal.html, xterm.js 5.5.0 bundled in the app) has its own preload (terminal-preload.js) with
 * contextIsolation and sandbox, no Node, CSP default-src 'self'. Its messages are accepted only from that window.
 * Before a recorded start (recording 'always', or the switch on) the tab shows the hint first; only „Verstanden,
 * verbinden“ asks the plugin for the ticket with record: true.
 *
 * Main window channels (./ipc-pro.js): remote-term:devices / :tmux / :tmux-kill / :tmux-kill-detached / :open / :list /
 * :focus; event remote-term:sessions. Ending tmux sessions and windows (Fernzugriff 1.8) sends only their numbers
 * ($n, @n); name and creation time come from core's last list, never from the renderer.
 * Terminal window: term:ready, term:input, term:resize, term:trust, term:reconnect, term:close, term:close-all,
 * term:confirm (the recording hint), term:font, term:ask-paste, term:clip-read, term:clip-write, term:select,
 * term:add; events term:init, term:status, term:data, term:pending, term:closing, term:focus.
 * Nothing of a ref, a token, a fingerprint or the terminal's content is logged.
 */

const FONT_MIN = 9;
const FONT_MAX = 28;
const FONT_DEFAULT = 14;
const TMUX_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;
const SESSION_ID_RE = /^\$\d{1,6}$/;
const WINDOW_ID_RE = /^@\d{1,6}$/;
const MAX_INPUT = 1024 * 1024;
const codeOf = (err) => (err && typeof err.code === 'string' && /^[a-z0-9_]{1,40}$/.test(err.code) ? err.code : 'failed');

/** The texts of the window, resolved here (the sandboxed window has no i18n of its own). */
const TEXT_KEYS = ['title', 'connecting', 'connectingTo', 'reconnecting', 'connected', 'offline', 'ended', 'recording', 'viewOnly', 'sessions',
  'lostTitle', 'lostText', 'tmuxKeeps', 'tryNow', 'offlineTitle', 'offlineText', 'offlineTmux', 'exitTitle', 'exitTmux', 'exitShell', 'exitAdmin',
  'exitLost', 'reconnect', 'closeTab', 'disconnect', 'closeWindow', 'closeAllTitle', 'closeAllText', 'cancel', 'hkTitle', 'hkLabel', 'hkText',
  'hkCopy', 'hkLeft', 'hkTrust', 'mismatchLabel', 'mismatchTitle', 'mismatchText', 'recTitle', 'recAlways', 'recOptional', 'recOk', 'copy',
  'paste', 'selectAll', 'fontBigger', 'fontSmaller', 'fontReset', 'pasteTitle', 'pasteText', 'pasteOk', 'pasteNever', 'tmuxMissing', 'add',
  'disconnectTitle', 'disconnectTmux', 'disconnectShell', 'copied', 'font', 'keyCtrl', 'keyCtrlShift'];
const ERROR_KEYS = ['host_key_mismatch', 'host_key_rejected', 'host_key_unpinned', 'auth', 'recording_unavailable', 'plugin_unavailable',
  'shell_refused', 'unreachable', 'limit', 'expired', 'no_right', 'maintenance', 'other'];

/**
 * @param {object} o
 * @param {object} o.core - { RemoteTerm } (core)
 * @param {object} o.apiClient
 * @param {object} o.log
 * @param {object} o.store
 * @param {Function} o.t - the app's texts
 * @param {Function} o.BrowserWindow
 * @param {object} o.ipcMain
 * @param {object} o.clipboard - Electron clipboard
 * @param {string} o.preload - terminal-preload.js
 * @param {string} o.html - terminal.html
 * @param {() => object|null} o.getMainWindow
 * @param {Function} [o.showMain] - brings the main window to the page „Fernzugriff“
 * @param {() => string} [o.getTheme] - 'dark' | 'light' (bars and dialogs follow it; the terminal stays dark)
 * @param {object} [o.term] - a RemoteTerm (tests)
 */
function setupTerminal({ core, apiClient, log, store, t, BrowserWindow, ipcMain, clipboard, preload, html, getMainWindow, showMain = () => {}, getTheme = () => 'dark', term = null }) {
  const rt = term || new core.RemoteTerm({ apiClient, serverUrl: () => (apiClient && apiClient.serverUrl) || '', log });
  let win = null;
  let ready = false;
  let closingConfirmed = false;
  let focusId = null;
  /** Tabs waiting for the recording hint: pendingId → { params, deviceName, always }. */
  const pending = new Map();
  let nextPending = 1;

  const fromWin = (e) => !!(win && !win.isDestroyed() && e && e.sender === win.webContents);
  const toWin = (ch, payload) => { if (win && !win.isDestroyed() && ready) win.webContents.send(ch, payload); };
  const toMain = (ch, payload) => { const w = getMainWindow(); if (w && !w.isDestroyed?.()) w.webContents.send(ch, payload); };

  function sessions() {
    return rt.list().map((s) => ({ id: s.id, deviceId: s.deviceId, deviceName: s.deviceName, tmux: s.tmux, state: s.state, recording: s.recording }));
  }

  rt.on('status', (s) => {
    toWin('term:status', s);
    toMain('remote-term:sessions', sessions());
  });
  rt.on('data', (d) => toWin('term:data', d));

  function fontPx() {
    const v = Number(store.get('terminal.fontPx', FONT_DEFAULT));
    return Number.isInteger(v) && v >= FONT_MIN && v <= FONT_MAX ? v : FONT_DEFAULT;
  }

  function texts() {
    return {
      ...Object.fromEntries(TEXT_KEYS.map((k) => [k, t(`terminal.${k}`)])),
      errors: Object.fromEntries(ERROR_KEYS.map((k) => [k, t(`terminal.errors.${k}`)])),
    };
  }

  function init() {
    return { theme: getTheme() === 'light' ? 'light' : 'dark', texts: texts(), fontPx: fontPx(), fontMin: FONT_MIN, fontMax: FONT_MAX, askPaste: store.get('terminal.askPaste', true) !== false,
      sessions: rt.list(), pending: [...pending].map(([id, p]) => ({ pendingId: id, deviceName: p.deviceName, always: p.always })), focus: focusId };
  }

  function createWindow() {
    ready = false;
    closingConfirmed = false;
    win = new BrowserWindow({
      width: 980, height: 640, minWidth: 560, minHeight: 360, show: false, title: t('terminal.title'), backgroundColor: '#0b0e13',
      autoHideMenuBar: true,
      webPreferences: { preload, nodeIntegration: false, contextIsolation: true, sandbox: true, spellcheck: false, webviewTag: false },
    });
    try { win.removeMenu(); } catch { /* older Electron */ }
    // no navigation and no other window from the terminal (links in the output stay text)
    win.webContents.on('will-navigate', (e) => e.preventDefault());
    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    win.once('ready-to-show', () => { if (win) win.show(); });
    win.on('close', (e) => {
      if (closingConfirmed || rt.list().every((s) => !live(s))) return;
      e.preventDefault();
      toWin('term:closing', { count: rt.list().filter(live).length });
    });
    win.on('closed', () => {
      win = null;
      ready = false;
      rt.closeAll();
      pending.clear();
      toMain('remote-term:sessions', []);
    });
    win.loadFile(html).catch((err) => log.warn('Terminal window not loaded:', err && err.message));
  }

  const live = (s) => ['connecting', 'hostkey', 'ready', 'reconnecting'].includes(s.state);

  function showWindow(id) {
    focusId = id || focusId;
    if (!win || win.isDestroyed()) createWindow();
    else {
      if (win.isMinimized()) win.restore();
      win.show();
      win.focus();
      if (id) toWin('term:focus', { id });
    }
  }

  async function startSession(params) {
    const st = await rt.open(params);
    focusId = st.id;
    showWindow(st.id);
    toWin('term:status', st);
    toMain('remote-term:sessions', sessions());
    return st;
  }

  function checkOpen(o) {
    const deviceId = Number(o && o.deviceId);
    if (!Number.isSafeInteger(deviceId) || deviceId <= 0) throw Object.assign(new Error('invalid device'), { code: 'invalid' });
    let tmux = null;
    if (o.tmux && typeof o.tmux === 'object') {
      const attach = o.tmux.attach != null;
      const raw = attach ? o.tmux.attach : o.tmux.create;
      const name = String(raw == null ? '' : raw);
      if (!TMUX_RE.test(name)) throw Object.assign(new Error('invalid tmux'), { code: 'invalid' });
      tmux = attach ? { attach: name } : { create: name };
    }
    const recording = ['off', 'optional', 'always'].includes(o.recording) ? o.recording : 'off';
    return { deviceId, deviceName: typeof o.deviceName === 'string' ? o.deviceName.slice(0, 100) : null, tmux, recording, record: o.record === true,
      cols: 100, rows: 28 };
  }

  const invalid = () => Object.assign(new Error('invalid'), { code: 'invalid' });

  /** „Beenden“ / „Schließen“ in the details: { session: '$n', window?: '@n' }. */
  function tmuxKill(deviceId, o) {
    const id = Number(deviceId);
    const session = o && o.session;
    const window = o && o.window != null ? o.window : null;
    if (!Number.isSafeInteger(id) || id <= 0 || typeof session !== 'string' || !SESSION_ID_RE.test(session)
      || (window !== null && (typeof window !== 'string' || !WINDOW_ID_RE.test(window)))) throw invalid();
    return rt.tmuxKill(id, window === null ? { session } : { session, window });
  }

  /** „Alle getrennten Sitzungen beenden“: the ticked ones (1–50). */
  function tmuxKillDetached(deviceId, ids) {
    const id = Number(deviceId);
    if (!Number.isSafeInteger(id) || id <= 0 || !Array.isArray(ids) || !ids.length || ids.length > 50
      || !ids.every((x) => typeof x === 'string' && SESSION_ID_RE.test(x))) throw invalid();
    return rt.tmuxKillDetached(id, [...ids]);
  }

  /** „Verbinden“ in the details: straight on, or the recording hint in a tab of the terminal window first. */
  async function open(o) {
    const p = checkOpen(o);
    const hint = p.recording === 'always' || (p.recording === 'optional' && p.record);
    if (!hint) return { session: await startSession(p) };
    const id = 'pending_' + nextPending++;
    pending.set(id, { params: p, deviceName: p.deviceName || '', always: p.recording === 'always' });
    showWindow(null);
    toWin('term:pending', { pendingId: id, deviceName: p.deviceName || '', always: p.recording === 'always' });
    return { pending: id };
  }

  const handlers = {
    'term:ready': () => { ready = true; return init(); },
    'term:input': (_e, id, data) => {
      if (typeof data !== 'string' || data.length > MAX_INPUT) return false;
      return rt.input(String(id), data);
    },
    'term:resize': (_e, id, cols, rows) => { rt.resize(String(id), Number(cols), Number(rows)); },
    'term:trust': (_e, id, yes) => rt.trust(String(id), yes === true),
    'term:reconnect': (_e, id) => rt.reconnect(String(id)),
    'term:close': (_e, id) => {
      const k = String(id);
      if (pending.delete(k)) return true;
      rt.close(k);
      if (focusId === k) focusId = null;
      return true;
    },
    'term:close-all': () => {
      closingConfirmed = true;
      rt.closeAll();
      pending.clear();
      if (win && !win.isDestroyed()) win.close();
    },
    'term:confirm': async (_e, pendingId, yes) => {
      const p = pending.get(String(pendingId));
      if (!p) return null;
      pending.delete(String(pendingId));
      if (yes !== true) return null;
      try {
        return { session: await startSession({ ...p.params, record: true }) };
      } catch (err) {
        return { error: codeOf(err) };
      }
    },
    'term:font': (_e, px) => {
      const v = Math.round(Number(px));
      if (Number.isInteger(v) && v >= FONT_MIN && v <= FONT_MAX) store.set('terminal.fontPx', v);
      return fontPx();
    },
    'term:ask-paste': (_e, on) => { store.set('terminal.askPaste', on === true); return on === true; },
    'term:clip-read': () => String(clipboard.readText() || '').slice(0, MAX_INPUT),
    'term:clip-write': (_e, text) => { if (typeof text === 'string' && text.length <= 8 * MAX_INPUT) clipboard.writeText(text); return true; },
    'term:select': (_e, id) => { focusId = String(id); },
    'term:add': () => { showMain(); },
  };

  for (const [ch, fn] of Object.entries(handlers)) {
    ipcMain.handle(ch, (e, ...args) => {
      if (!fromWin(e)) throw new Error('not the terminal window');
      return fn(e, ...args);
    });
  }

  // the main window (./ipc-pro.js registers these)
  // a refusal reaches the renderer as { error: code } (an Error thrown over IPC loses its code)
  const safe = (fn, fallback = {}) => async (...a) => {
    try { return await fn(...a); } catch (err) { return { ...fallback, error: codeOf(err) }; }
  };
  const channels = {
    'remote-term:devices': safe(() => rt.devices(), { devices: [], sshRight: false }),
    'remote-term:tmux': safe((_e, deviceId) => rt.tmux(Number(deviceId))),
    'remote-term:tmux-kill': safe((_e, deviceId, o) => tmuxKill(deviceId, o)),
    'remote-term:tmux-kill-detached': safe((_e, deviceId, ids) => tmuxKillDetached(deviceId, ids)),
    'remote-term:open': safe((_e, o) => open(o || {})),
    'remote-term:list': () => sessions(),
    'remote-term:focus': (_e, id) => { showWindow(typeof id === 'string' ? id : null); return true; },
  };

  return {
    term: rt,
    channels,
    open,
    get window() { return win; },
    stop() {
      rt.closeAll();
      if (win && !win.isDestroyed()) { closingConfirmed = true; win.destroy(); }
    },
  };
}

module.exports = { setupTerminal, FONT_MIN, FONT_MAX, FONT_DEFAULT, TEXT_KEYS, ERROR_KEYS };
