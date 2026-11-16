'use strict';

/**
 * GateControl – Fernzugriff stage 7: the bar at the top of the screen while "Bildschirm teilen" runs
 *
 * A small frameless window, always on top (above full-screen programs too), centred at the top of the shared display,
 * not in the taskbar, not closable and never taking the focus from the person's program. It says who watches
 * ("… sieht deinen Bildschirm") or controls ("… steuert deinen Bildschirm") and for how long, with "Nur ansehen"
 * (while controlled) and "Beenden" — both act at once in the main process (input stops before anything else).
 *
 * Its own preload (screen-bar-preload.js) exposes only the state and the two buttons; contextIsolation, sandbox,
 * nodeIntegration off. Texts come resolved from the main process (core i18n). Electron objects are passed in.
 */

const WIDTH = 600;
const HEIGHT = 44;
const SHOW = new Set(['connecting', 'waiting', 'live']);

/**
 * @param {object} o
 * @param {Function} o.BrowserWindow
 * @param {object} o.screen - Electron screen (the display to sit on)
 * @param {object} o.ipcMain
 * @param {string} o.preload - path of screen-bar-preload.js
 * @param {string} o.html - path of screen-bar.html
 * @param {(key: string, vars?: object) => string} o.t - the app's texts
 * @param {object} [o.log]
 */
function setupScreenBar({ BrowserWindow, screen, ipcMain, preload, html, t, log }) {
  let win = null;
  let last = null;
  const handlers = { stop: [], viewOnly: [] };

  const fromBar = (e) => !!(win && !win.isDestroyed() && e && e.sender === win.webContents);
  ipcMain.on('screen-bar:stop', (e) => { if (fromBar(e)) handlers.stop.forEach((fn) => fn()); });
  ipcMain.on('screen-bar:view-only', (e) => { if (fromBar(e)) handlers.viewOnly.forEach((fn) => fn()); });
  ipcMain.on('screen-bar:ready', (e) => { if (fromBar(e) && last) send(last); });

  function texts() {
    return {
      view: t('screenShare.barView'), control: t('screenShare.barControl'), waiting: t('screenShare.barWaiting'), connecting: t('screenShare.barConnecting'),
      paused: t('screenShare.barPaused'), stop: t('screenShare.stop'), viewOnly: t('screenShare.viewOnly'), somebody: t('remoteHost.requestSomebody'),
      label: t('screenShare.barLabel'),
    };
  }

  function bounds() {
    let d = null;
    try { d = screen.getPrimaryDisplay(); } catch { d = null; }
    const wa = (d && d.workArea) || { x: 0, y: 0, width: 1280, height: 720 };
    const w = Math.min(WIDTH, wa.width - 16);
    return { x: Math.round(wa.x + (wa.width - w) / 2), y: wa.y + 8, width: w, height: HEIGHT };
  }

  function create() {
    win = new BrowserWindow({
      ...bounds(), show: false, frame: false, resizable: false, movable: false, minimizable: false, maximizable: false, fullscreenable: false, closable: false,
      skipTaskbar: true, alwaysOnTop: true, focusable: false, transparent: true, hasShadow: false, title: 'GateControl',
      webPreferences: { preload, nodeIntegration: false, contextIsolation: true, sandbox: true, spellcheck: false },
    });
    try { win.setAlwaysOnTop(true, 'screen-saver'); } catch { /* older Electron */ }
    win.loadFile(html).catch((err) => { if (log) log.warn('Screen bar not loaded:', err && err.message); });
    win.on('closed', () => { win = null; });
  }

  function send(st) {
    if (win && !win.isDestroyed()) win.webContents.send('screen-bar:state', { ...st, texts: texts() });
  }

  /** The session of ScreenShare (or null): the bar shows while it runs. */
  function update(st) {
    const on = !!(st && SHOW.has(st.state));
    if (!on) {
      last = null;
      if (win && !win.isDestroyed()) win.hide();
      return;
    }
    last = { state: st.state, viewer: st.viewer || null, mode: st.mode === 'control' ? 'control' : 'view', since: st.since || null, paused: !!st.paused };
    if (!win || win.isDestroyed()) create();
    else win.setBounds(bounds());
    send(last);
    if (!win.isVisible()) win.showInactive();
  }

  function destroy() {
    last = null;
    if (win && !win.isDestroyed()) { win.setClosable(true); win.destroy(); }
    win = null;
  }

  return {
    update,
    destroy,
    onStop: (fn) => handlers.stop.push(fn),
    onViewOnly: (fn) => handlers.viewOnly.push(fn),
    get window() { return win; },
  };
}

module.exports = { setupScreenBar };
