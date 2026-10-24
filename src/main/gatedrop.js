'use strict';

/**
 * GateDrop wiring (plugin gatecontrol-gatedrop): the core GateDropService
 * (send, receive into Downloads\GateControl, LAN listener on TCP 47731,
 * presence) for the app's lifetime, plus the app-side glue:
 *
 *   - "Senden an → GateDrop" in the Explorer: a shortcut in the user's SendTo
 *     folder while GateDrop is available and the setting `gatedrop.sendTo`
 *     is on (core utils/gatedrop-shell.js); Explorer starts the app with
 *     `--gatedrop-send <files>`, the single-instance lock hands that argv to
 *     the running app (handleArgv) → the send dialog opens.
 *   - Tray entry "GateDrop – Dateien senden …" (file dialog → send dialog).
 *   - A stop that is safe to call twice.
 *
 * The IPC channels gatedrop:* come from the core handlers (registerBaseHandlers
 * with ctx.gatedrop / ctx.gatedropExplorer), so a server:setup resets it there.
 * Kept free of module-level Electron access (app, shell, dialog and the core
 * classes are passed in), so test/gatedrop.test.js can drive it with fakes.
 */

const path = require('path');

/**
 * @param {object} o
 * @param {object} o.app - Electron app (getPath, isPackaged, getAppPath)
 * @param {object} o.store - electron-store (gatedrop.sendTo, gatedropSaved)
 * @param {object} o.log
 * @param {object} o.apiClient
 * @param {object} o.notifications - result of setupNotifications() (pushClient, notificationCenter)
 * @param {Function} o.GateDropService - core class
 * @param {Function} [o.GateDropFirewall] - core class: checks / repairs the Windows
 *   Firewall rule of the LAN listener (block rules of the security prompt, missing
 *   allow rule); null: not checked (e2e runs, tests)
 * @param {'pro'|'community'} [o.edition='pro'] - name of the firewall rule (core editions.js)
 * @param {object} o.gatedropShell - core utils/gatedrop-shell.js
 * @param {object} [o.shell] - Electron shell
 * @param {object} [o.clipboard] - Electron clipboard
 * @param {object} [o.dialog] - Electron dialog (tray entry)
 * @param {string} o.protocol - toast protocol of the app
 * @param {string} [o.toastImagePath]
 * @param {Function} o.showWindow
 * @param {() => object|null} o.getMainWindow
 * @param {Function} [o.t] - i18n (shortcut description)
 * @param {boolean} [o.manageShortcut=true] - false in e2e runs
 * @param {string} [o.platform=process.platform]
 * @param {string} [o.execPath=process.execPath]
 * @param {object} [o.fs]
 * @param {Function} [o.onChange] - availability changed (tray refresh)
 */
function setupGateDrop({
  app, store, log, apiClient, notifications, GateDropService, gatedropShell,
  GateDropFirewall = null, edition = 'pro',
  shell = null, clipboard = null, dialog = null, protocol, toastImagePath = null,
  showWindow, getMainWindow, t = (k) => k, manageShortcut = true,
  platform = process.platform, execPath = process.execPath, fs = require('fs'),
  onChange = () => {}, service = null,
}) {
  const downloadsDir = () => {
    try { return path.join(app.getPath('downloads'), 'GateControl'); } catch { return path.join(require('os').homedir(), 'Downloads', 'GateControl'); }
  };

  const firewall = !service && GateDropFirewall && platform === 'win32' ? new GateDropFirewall({ log, edition, exePath: execPath }) : null;

  const gatedrop = service || new GateDropService({
    firewall,
    apiClient,
    log,
    store,
    notificationCenter: notifications && notifications.notificationCenter,
    pushClient: notifications && notifications.pushClient,
    downloadsDir,
    shell,
    clipboard,
    protocol,
    toastImagePath,
    showWindow,
  });

  const wantShortcut = () => store.get('gatedrop.sendTo', true) !== false;

  /** Create / remove the SendTo shortcut to match availability and the setting. */
  function syncShortcut() {
    if (!manageShortcut || platform !== 'win32') return 'skipped';
    const st = gatedrop.status().state;
    // Unknown / network trouble: leave it as it is.
    if (st !== 'available' && st !== 'unavailable') return 'skipped';
    let appPath = null;
    try { appPath = app.isPackaged ? null : app.getAppPath(); } catch { appPath = null; }
    let appData;
    try { appData = app.getPath('appData'); } catch { return 'failed'; }
    return gatedropShell.syncSendToShortcut({
      enabled: st === 'available' && wantShortcut(),
      shell,
      fs,
      appData,
      exePath: execPath,
      args: gatedropShell.shortcutArgs({ isPackaged: !!app.isPackaged, appPath }),
      description: t('gatedrop.sendTo'),
      log,
    });
  }

  const explorer = {
    get: () => wantShortcut(),
    set: (enabled) => {
      store.set('gatedrop.sendTo', enabled === true);
      syncShortcut();
      return wantShortcut();
    },
  };

  let lastAvailable = null;
  gatedrop.on('state', () => {
    syncShortcut();
    const now = gatedrop.available();
    if (now !== lastAvailable) {
      lastAvailable = now;
      try { onChange(); } catch (err) { log.warn(`GateDrop tray refresh failed: ${err.message}`); }
    }
  });
  // "Senden an" / drag & drop / tray: the send dialog lives in the window.
  gatedrop.on('compose', () => { try { showWindow(); } catch { /* window gone */ } });

  /** Tray entry: choose files → send dialog. */
  async function pickAndCompose() {
    showWindow();
    if (!dialog || typeof dialog.showOpenDialog !== 'function') return;
    const win = getMainWindow && getMainWindow();
    const opts = { properties: ['openFile', 'multiSelections'] };
    const r = win ? await dialog.showOpenDialog(win, opts) : await dialog.showOpenDialog(opts);
    if (r && !r.canceled && Array.isArray(r.filePaths) && r.filePaths.length) await gatedrop.compose(r.filePaths);
  }

  let started = false;
  let stopped = false;

  return {
    service: gatedrop,
    explorer,
    syncShortcut,

    /** Availability check, presence, LAN listener (call after window and tray exist). */
    start() {
      if (started || stopped) return;
      started = true;
      gatedrop.start();
    },

    /**
     * argv of a start / second start: `--gatedrop-send <files>` → the send
     * dialog. Returns true when it was one (the caller skips the rest).
     */
    handleArgv(argv) {
      return gatedrop.handleArgv(argv);
    },

    /** Tray entry "GateDrop – Dateien senden …" (only while the plugin is there). */
    menuItems(tr) {
      if (!gatedrop.available()) return [];
      return [{ label: tr('gatedrop.tray'), click: () => { pickAndCompose().catch((err) => log.warn(`GateDrop pick failed: ${err.message}`)); } }];
    },

    /** Stops the listener and timers; safe to call more than once. */
    stop() {
      if (stopped) return;
      stopped = true;
      try { gatedrop.stop(); } catch (err) { log.warn(`GateDrop stop failed: ${err.message}`); }
    },
  };
}

module.exports = { setupGateDrop };
