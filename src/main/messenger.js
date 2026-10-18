'use strict';

/**
 * Chats wiring (GateControl Messenger): the core MessengerService (data,
 * live events, outbox) and ChatNotifier (chat toasts with reply field) for
 * the app's lifetime, plus the app-side glue: window visibility, tray badge
 * and menu entry, a stop that is safe to call twice.
 *
 * The messenger uses the push client of the notification center
 * (./notifications.js) for its live events; the IPC channels chat:* come
 * from the core handlers (registerBaseHandlers with ctx.messenger), so a
 * server:setup resets it there. Core docs/messenger.md.
 *
 * Kept free of module-level Electron access (the core classes are passed
 * in), so test/messenger.test.js can drive it with fakes and the real core.
 */

/**
 * @param {object} o
 * @param {object} o.store - electron-store (cache `messengerCache`, outbox `messengerOutbox`)
 * @param {object} o.log
 * @param {object} o.apiClient - ApiClient / ApiClientPro
 * @param {object} o.notifications - result of setupNotifications() (pushClient, notificationCenter)
 * @param {Function} o.MessengerService - core class
 * @param {Function} o.ChatNotifier - core class
 * @param {string} o.protocol - toast protocol of the app ('gatecontrol-pro' | 'gatecontrol-community')
 * @param {string} [o.toastImagePath] - app icon for chat toasts without a sender picture
 * @param {string} [o.dataDir] - app.getPath('userData') (files waiting in the outbox)
 * @param {string} [o.tmpDir] - app.getPath('temp') (sender pictures of toasts)
 * @param {Function} o.showWindow
 * @param {() => object|null} o.getMainWindow
 * @param {Function} [o.onChange] - unread count / availability changed (tray refresh)
 */
function setupMessenger({
  store, log, apiClient, notifications, MessengerService, ChatNotifier, protocol, toastImagePath = null,
  dataDir = null, tmpDir = null, showWindow, getMainWindow, onChange = () => {},
}) {
  const isWindowVisible = () => {
    const w = getMainWindow();
    if (!w || (typeof w.isDestroyed === 'function' && w.isDestroyed())) return false;
    return w.isVisible() && !w.isMinimized();
  };

  const messenger = new MessengerService({
    apiClient,
    pushClient: notifications.pushClient,
    store,
    dataDir,
    log,
    isWindowVisible,
  });

  const chatNotifier = new ChatNotifier({
    messenger,
    notificationCenter: notifications.notificationCenter,
    log,
    protocol,
    toastImagePath,
    tmpDir,
    showWindow,
  });

  let last = null;
  const changed = () => {
    const key = `${messenger.available()}:${messenger.unreadTotal()}`;
    if (key === last) return;
    last = key;
    try { onChange(); } catch (err) { log.warn(`Chat tray refresh failed: ${err.message}`); }
  };
  messenger.on('unread', changed);
  messenger.on('state', changed);

  let started = false;
  let stopped = false;

  const unread = () => (messenger.available() ? messenger.unreadTotal() : 0);

  return {
    messenger,
    chatNotifier,

    /** Chat toasts on, availability check, live events (call after window and tray exist). */
    start() {
      if (started || stopped) return;
      started = true;
      chatNotifier.start();
      messenger.start();
    },

    /** Unread chat messages (0 while the messenger is not available). */
    unread,

    /** Dot on the tray icon. */
    badge() {
      return unread() > 0;
    },

    /** Tray entry "Chats · n neu" (only while the server offers the messenger). */
    menuItems(t, openChats) {
      if (!messenger.available()) return [];
      const n = unread();
      return [{ label: n > 0 ? t('chat.tray.unread', { count: n }) : t('chat.title'), click: () => openChats() }];
    },

    /** Tooltip line for unread chat messages, or null. */
    tooltip(t) {
      const n = unread();
      return n > 0 ? t('chat.tray.unread', { count: n }) : null;
    },

    /** Saves the cache, leaves the open chat; safe to call more than once. */
    stop() {
      if (stopped) return;
      stopped = true;
      try { chatNotifier.stop(); } catch (err) { log.warn(`Chat notifier stop failed: ${err.message}`); }
      try { messenger.stop(); } catch (err) { log.warn(`Messenger stop failed: ${err.message}`); }
    },
  };
}

module.exports = { setupMessenger };
