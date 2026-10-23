/**
 * GateControl -- Vault quick search (Strg+Alt+P, mockup W2)
 *
 * A small frameless, always-on-top window over every program: type to find
 * an entry, Enter copies its password, Strg+B the user name, Strg+T the 2FA
 * code, Strg+O opens its website, Esc closes. While Vault is locked it asks
 * for the master password. The global shortcut is registered only while the
 * server offers Vault (VaultService status().state === 'available').
 *
 * The window has its own preload (vault-quick-preload.js) that exposes only
 * what it needs (status, unlock, the list, copy, 2FA code, open a website);
 * contextIsolation and sandbox like the main window. Its content is hidden
 * from screen capture. Electron objects are passed in (tests use fakes).
 */

'use strict';

const ACCELERATOR = 'Control+Alt+P';
const WIDTH = 640;
const HEIGHT = 440;

/**
 * @param {object} o
 * @param {Function} o.BrowserWindow
 * @param {object} o.globalShortcut
 * @param {object} o.screen
 * @param {object} o.ipcMain
 * @param {object} o.vault - VaultService
 * @param {string} o.preload - path of vault-quick-preload.js
 * @param {string} o.html - path of vault-quick.html
 * @param {() => 'dark'|'light'} o.getTheme
 * @param {() => string} o.getLocale
 * @param {(url: string) => boolean} [o.isWindowUrl] - may the window load this URL
 * @param {object} o.log
 * @param {string} [o.accelerator]
 * @param {boolean} [o.sandbox] - like the main window (false)
 */
function setupVaultQuick({
  BrowserWindow, globalShortcut, screen, ipcMain, vault, preload, html, getTheme, getLocale, log,
  accelerator = ACCELERATOR, sandbox = false,
}) {
  let win = null;
  let registered = false;
  let started = false;
  let quitting = false;

  const bg = () => (getTheme() === 'light' ? '#FFFFFF' : '#161B22');

  function create() {
    win = new BrowserWindow({
      width: WIDTH,
      height: HEIGHT,
      show: false,
      frame: false,
      resizable: false,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      skipTaskbar: true,
      alwaysOnTop: true,
      backgroundColor: bg(),
      title: 'GateControl Vault',
      webPreferences: {
        preload,
        nodeIntegration: false,
        contextIsolation: true,
        sandbox,
        spellcheck: false,
      },
    });
    if (typeof win.setAlwaysOnTop === 'function') win.setAlwaysOnTop(true, 'pop-up-menu');
    if (typeof win.setContentProtection === 'function') win.setContentProtection(true);
    const wc = win.webContents;
    if (wc) {
      if (typeof wc.setWindowOpenHandler === 'function') wc.setWindowOpenHandler(() => ({ action: 'deny' }));
      wc.on('will-navigate', (e) => e.preventDefault());
    }
    win.on('blur', () => hide());
    win.on('close', (e) => {
      if (quitting) return;
      e.preventDefault();
      hide();
    });
    win.on('closed', () => { win = null; });
    win.loadFile(html);
  }

  function place() {
    try {
      const point = screen.getCursorScreenPoint();
      const area = screen.getDisplayNearestPoint(point).workArea;
      const x = Math.round(area.x + (area.width - WIDTH) / 2);
      const y = Math.round(area.y + Math.max(40, area.height * 0.22));
      win.setBounds({ x, y, width: WIDTH, height: HEIGHT });
    } catch (err) {
      log.debug(`Vault quick search: placing failed: ${err.message}`);
    }
  }

  function show() {
    if (!win || (typeof win.isDestroyed === 'function' && win.isDestroyed())) create();
    place();
    if (typeof win.setBackgroundColor === 'function') win.setBackgroundColor(bg());
    const payload = { theme: getTheme(), locale: getLocale() };
    const send = () => { try { win.webContents.send('vault-quick:show', payload); } catch { /* closed */ } };
    if (typeof win.webContents.isLoading === 'function' && win.webContents.isLoading()) win.webContents.once('did-finish-load', send);
    else send();
    win.show();
    win.focus();
  }

  function hide() {
    if (win && !(typeof win.isDestroyed === 'function' && win.isDestroyed()) && win.isVisible()) {
      try { win.webContents.send('vault-quick:hide'); } catch { /* closed */ }
      win.hide();
    }
  }

  function toggle() {
    if (win && !(typeof win.isDestroyed === 'function' && win.isDestroyed()) && win.isVisible()) hide();
    else show();
  }

  /** Shortcut only while the server offers Vault. */
  function sync(st) {
    const want = started && !!st && st.state === 'available';
    if (want && !registered) {
      try {
        registered = globalShortcut.register(accelerator, toggle) === true;
      } catch (err) {
        registered = false;
        log.warn(`Vault quick search: ${accelerator} not registered: ${err.message}`);
      }
      if (!registered) log.warn(`Vault quick search: ${accelerator} is taken by another program`);
    } else if (!want && registered) {
      try { globalShortcut.unregister(accelerator); } catch { /* gone */ }
      registered = false;
      hide();
    }
  }

  const onState = (st) => sync(st);
  const onHide = (e) => { if (win && e && e.sender === win.webContents) hide(); };

  return {
    start() {
      if (started) return;
      started = true;
      vault.on('state', onState);
      ipcMain.on('vault-quick:hide', onHide);
      sync(vault.status());
    },
    stop() {
      started = false;
      quitting = true;
      vault.removeListener('state', onState);
      ipcMain.removeListener('vault-quick:hide', onHide);
      sync(null);
      if (win && !(typeof win.isDestroyed === 'function' && win.isDestroyed())) win.destroy();
      win = null;
    },
    toggle,
    show,
    hide,
    isRegistered: () => registered,
    window: () => win,
  };
}

module.exports = { setupVaultQuick, ACCELERATOR };
