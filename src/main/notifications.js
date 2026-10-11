'use strict';

/**
 * Notification center wiring (push client, toasts, inbox, tray entries).
 *
 * The push layer lives in @gatecontrol/client-core (PushClient,
 * NotificationCenter, notifyMenuItems; docs/notification-center.md). This
 * module creates one instance of each for the app's lifetime and holds the
 * app-side glue: protocol activation of toast buttons, the tunnel-change
 * signal, the tray entries/badge and a stop that is safe to call twice.
 *
 * Kept free of module-level Electron access (app and the core classes are
 * passed in), so test/notifications.test.js can drive it with fakes and with
 * the real core classes.
 */

const path = require('path');

/**
 * Registers `<protocol>://` with Windows for the toast buttons. Packaged
 * builds register the installed exe; `electron .` (development) has to pass
 * the app path, otherwise Windows would start a bare Electron.
 * @returns {boolean}
 */
function registerProtocolClient(app, protocol, { argv = process.argv, execPath = process.execPath, log } = {}) {
  try {
    if (app.isPackaged) return app.setAsDefaultProtocolClient(protocol) !== false;
    const appPath = argv[1] ? path.resolve(argv[1]) : null;
    if (!appPath) return false;
    return app.setAsDefaultProtocolClient(protocol, execPath, [appPath]) !== false;
  } catch (err) {
    if (log) log.warn(`Protocol ${protocol}:// could not be registered: ${err.message}`);
    return false;
  }
}

/**
 * @param {object} o
 * @param {object} o.app - Electron app (setAsDefaultProtocolClient, isPackaged)
 * @param {object} o.store - electron-store with the core notificationsSchema
 * @param {object} o.log
 * @param {object} o.apiClient - ApiClient / ApiClientPro (configure() changes it in place)
 * @param {Function} o.PushClient - core class
 * @param {Function} o.NotificationCenter - core class
 * @param {Function} o.notifyMenuItems - core tray helper
 * @param {string} o.protocol - 'gatecontrol-pro' | 'gatecontrol-community'
 * @param {string} [o.toastImagePath] - app icon for the toasts
 * @param {Function} o.showWindow
 * @param {(portalPath: string) => Promise<boolean>} o.openPortal
 * @param {() => boolean} o.isTunnelUp
 * @param {() => boolean} o.isKillSwitchActive
 * @param {() => string|null} o.getWgConfigPath - WireGuard config (kill-switch path check)
 * @param {Function} [o.readFile] - (path) => Promise<string>
 * @param {boolean} [o.registerProtocol=true] - false in e2e mode
 * @param {Function} [o.onChange] - unread count / DND / push state changed (tray refresh)
 * @param {string[]} [o.argv] [o.execPath] - for the protocol registration (tests)
 */
function setupNotifications({
  app, store, log, apiClient,
  PushClient, NotificationCenter, notifyMenuItems,
  protocol, toastImagePath = null, showWindow, openPortal,
  isTunnelUp, isKillSwitchActive, getWgConfigPath,
  readFile = (file) => require('fs').promises.readFile(file, 'utf8'),
  registerProtocol = true, onChange = () => {},
  argv = process.argv, execPath = process.execPath,
}) {
  const pushClient = new PushClient({
    apiClient,
    store,
    log,
    isTunnelUp: () => !!isTunnelUp(),
    isKillSwitchActive: () => !!isKillSwitchActive(),
    getWgConfig: async () => {
      const file = getWgConfigPath();
      if (!file) return null;
      try { return await readFile(file); } catch { return null; }
    },
  });

  const notificationCenter = new NotificationCenter({
    store,
    log,
    pushClient,
    protocol,
    toastImagePath,
    icon: toastImagePath,
    showWindow,
    openPortal: (portalPath) => openPortal(portalPath),
  });

  const protocolRegistered = registerProtocol
    ? registerProtocolClient(app, protocol, { argv, execPath, log })
    : false;

  const changed = () => { try { onChange(); } catch (err) { log.warn(`Notification tray refresh failed: ${err.message}`); } };
  notificationCenter.on('unread', changed);
  notificationCenter.on('status', changed);

  let started = false;
  let stopped = false;
  let tunnelUp = null;

  return {
    pushClient,
    notificationCenter,
    protocolRegistered,

    /** Opens the stream (no-op while notifications are switched off). */
    start() {
      if (started || stopped) return;
      started = true;
      tunnelUp = !!isTunnelUp();
      notificationCenter.start();
    },

    /**
     * Tunnel state as sent to the renderer. Only a change (up ↔ down)
     * reconnects the stream, so the frequent stats broadcasts cost nothing.
     * @returns {boolean} true when the push client was told
     */
    tunnelChanged(connected) {
      const up = !!connected;
      if (tunnelUp === up) return false;
      tunnelUp = up;
      if (!started || stopped) return false;
      try { pushClient.networkChanged(); } catch (err) { log.warn(`Push network change failed: ${err.message}`); }
      return true;
    },

    /** second-instance argv / first start: true when it was a toast button (or our URL). */
    handleArgv(list) {
      try { return notificationCenter.handleArgv(list); } catch (err) {
        log.warn(`Notification activation failed: ${err.message}`);
        return false;
      }
    },

    /** Unread dot on the tray icon. */
    badge() {
      return notificationCenter.unreadCount() > 0;
    },

    /** "Mitteilungen · n neu" / "Nicht stören für 1 Stunde" (empty when switched off). */
    menuItems(t) {
      return notifyMenuItems({
        unread: notificationCenter.unreadCount(),
        dnd: notificationCenter.dndState(),
        enabled: notificationCenter.getPrefs().enabled,
        t,
        openInbox: () => notificationCenter.openInbox(),
        setDnd: (arg) => notificationCenter.setDnd(arg),
      });
    },

    /** Tooltip line for unread messages, or null. */
    tooltip(t) {
      const n = notificationCenter.unreadCount();
      return n > 0 ? t('push.tray.inboxUnread', { count: n }) : null;
    },

    /**
     * The app's own notifications ("VPN verbunden", update, …) through the
     * same wrapper: respects "Nicht stören" and the toast setting unless
     * `force`.
     */
    notify(opts) {
      try { return notificationCenter.notify(opts); } catch (err) {
        log.warn(`Notification failed: ${err.message}`);
        return null;
      }
    },

    /** Closes the stream and flushes delivery acks; safe to call more than once. */
    stop() {
      if (stopped) return;
      stopped = true;
      try { notificationCenter.stop(); } catch (err) { log.warn(`Notification center stop failed: ${err.message}`); }
    },
  };
}

module.exports = { setupNotifications, registerProtocolClient };
