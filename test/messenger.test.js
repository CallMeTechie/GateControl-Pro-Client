'use strict';

// Chats wiring (src/main/messenger.js) with fakes and with the real core
// classes, plus how main.js uses it (instances, IPC context, start/stop,
// tray badge / menu / tooltip).

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const Module = require('node:module');
const path = require('node:path');
const fs = require('node:fs');

const ROOT = path.join(__dirname, '..');
const MAIN_JS = fs.readFileSync(path.join(ROOT, 'src', 'main', 'main.js'), 'utf8');
const { setupMessenger } = require('../src/main/messenger');

function findCore() {
  try {
    return path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [ROOT] }));
  } catch { /* not installed */ }
  for (const dir of [path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) {
    if (fs.existsSync(path.join(dir, 'src', 'services', 'messenger.js'))) return dir;
  }
  return null;
}
const coreDir = findCore();
const hasMessenger = !!coreDir && fs.existsSync(path.join(coreDir, 'src', 'services', 'messenger.js'));
if (coreDir) {
  const realResolve = Module._resolveFilename;
  Module._resolveFilename = function (request, ...rest) {
    if (request === '@callmetechie/gatecontrol-config-hash') return path.join(__dirname, 'fixtures', 'config-hash-stub.js');
    return realResolve.call(this, request, ...rest);
  };
}
const quietLog = { info() {}, warn() {}, error() {}, debug() {} };
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);
const cleanups = [];
afterEach(() => { while (cleanups.length) cleanups.pop()(); });

function fakes() {
  const made = {};
  class FakeMessenger extends EventEmitter {
    constructor(opts) { super(); this.opts = opts; this.started = 0; this.stopped = 0; this.avail = false; this.unread = 0; made.messenger = this; }
    start() { this.started++; }
    stop() { this.stopped++; }
    available() { return this.avail; }
    unreadTotal() { return this.unread; }
  }
  class FakeNotifier extends EventEmitter {
    constructor(opts) { super(); this.opts = opts; this.started = 0; this.stopped = 0; made.notifier = this; }
    start() { this.started++; }
    stop() { this.stopped++; }
  }
  return { made, FakeMessenger, FakeNotifier };
}

function setup(extra = {}) {
  const { made, FakeMessenger, FakeNotifier } = fakes();
  const changes = [];
  let win = { isDestroyed: () => false, isVisible: () => true, isMinimized: () => false };
  const notifications = { pushClient: { id: 'push' }, notificationCenter: { id: 'nc' } };
  const chats = setupMessenger({
    store: {}, log: quietLog, apiClient: { id: 'api' }, notifications,
    MessengerService: FakeMessenger, ChatNotifier: FakeNotifier,
    protocol: 'gatecontrol-pro', toastImagePath: 'C:\\icon.png', dataDir: 'C:\\data', tmpDir: 'C:\\tmp',
    showWindow: () => changes.push('show'), getMainWindow: () => win, onChange: () => changes.push('change'),
    ...extra,
  });
  return { chats, made, changes, setWin: (w) => { win = w; } };
}

describe('setupMessenger (fakes)', () => {
  it('creates the messenger on the notification push client and the chat notifier on the center', () => {
    const { made } = setup();
    assert.equal(made.messenger.opts.pushClient.id, 'push');
    assert.equal(made.messenger.opts.apiClient.id, 'api');
    assert.equal(made.messenger.opts.dataDir, 'C:\\data');
    assert.equal(made.notifier.opts.notificationCenter.id, 'nc');
    assert.equal(made.notifier.opts.messenger, made.messenger);
    assert.equal(made.notifier.opts.protocol, 'gatecontrol-pro');
    assert.equal(made.notifier.opts.tmpDir, 'C:\\tmp');
  });

  it('window visibility: shown and not minimized', () => {
    const { made, setWin } = setup();
    const visible = made.messenger.opts.isWindowVisible;
    assert.equal(visible(), true);
    setWin({ isDestroyed: () => false, isVisible: () => true, isMinimized: () => true });
    assert.equal(visible(), false);
    setWin({ isDestroyed: () => false, isVisible: () => false, isMinimized: () => false });
    assert.equal(visible(), false);
    setWin(null);
    assert.equal(visible(), false);
  });

  it('start / stop once, notifier before the messenger', () => {
    const { chats, made } = setup();
    chats.start();
    chats.start();
    assert.equal(made.notifier.started, 1);
    assert.equal(made.messenger.started, 1);
    chats.stop();
    chats.stop();
    assert.equal(made.messenger.stopped, 1);
    assert.equal(made.notifier.stopped, 1);
    chats.start();
    assert.equal(made.messenger.started, 1, 'no restart after stop');
  });

  it('tray: badge, menu entry and tooltip only while available', () => {
    const { chats, made, changes } = setup();
    assert.equal(chats.badge(), false);
    assert.deepEqual(chats.menuItems(t, () => {}), []);
    made.messenger.avail = true;
    made.messenger.unread = 3;
    made.messenger.emit('unread', 3);
    assert.deepEqual(changes, ['change']);
    made.messenger.emit('unread', 3);
    assert.deepEqual(changes, ['change'], 'refreshed only on a change');
    assert.equal(chats.badge(), true);
    assert.equal(chats.tooltip(t), 'chat.tray.unread(3)');
    let opened = 0;
    const items = chats.menuItems(t, () => { opened++; });
    assert.equal(items[0].label, 'chat.tray.unread(3)');
    items[0].click();
    assert.equal(opened, 1);
    made.messenger.unread = 0;
    assert.equal(chats.menuItems(t, () => {})[0].label, 'chat.title');
    assert.equal(chats.tooltip(t), null);
  });
});

describe('setupMessenger (real core)', { skip: hasMessenger ? false : 'core with messenger not available' }, () => {
  it('wires MessengerService + ChatNotifier with the real NotificationCenter', () => {
    const { MessengerService, ChatNotifier, NotificationCenter } = {
      MessengerService: require(path.join(coreDir, 'src', 'services', 'messenger.js')),
      ChatNotifier: require(path.join(coreDir, 'src', 'services', 'chat-notifier.js')),
      NotificationCenter: require(path.join(coreDir, 'src', 'services', 'notification-center.js')),
    };
    const store = new Map();
    const memStore = { get: (k, d) => (store.has(k) ? store.get(k) : d), set: (k, v) => store.set(k, v), delete: (k) => store.delete(k) };
    const push = new EventEmitter();
    push.status = () => ({ state: 'stopped' });
    push.ack = async () => ({ ok: true });
    push.start = () => {};
    push.stop = () => {};
    class N extends EventEmitter { show() {} close() {} static isSupported() { return true; } }
    const nc = new NotificationCenter({ store: memStore, log: quietLog, pushClient: push, Notification: N, platform: 'win32' });
    const chats = setupMessenger({
      store: memStore, log: quietLog, apiClient: { client: null, serverUrl: '', apiKey: '' },
      notifications: { pushClient: push, notificationCenter: nc },
      MessengerService, ChatNotifier, protocol: 'gatecontrol-pro',
      showWindow() {}, getMainWindow: () => null,
    });
    cleanups.push(() => chats.stop());
    chats.start();
    // Windows without handleActivation (fake class) → protocol button; other systems: none
    assert.equal(chats.chatNotifier.mode, process.platform === 'win32' ? 'protocol' : 'none');
    // chat pushes now go to the notifier, not to the inbox
    push.emit('notification', { seq: 1, id: 2, kind: 'message', title: 'Anna', body: 'Hi', data: { conversation: { id: '12' }, sender: { id: 8, name: 'Anna' } } });
    assert.equal(nc.list().items.length, 0);
    assert.deepEqual(chats.chatNotifier.tracked().map((x) => x.conversationId), [12]);
    // not configured → not available, no tray entry
    assert.deepEqual(chats.menuItems(t, () => {}), []);
  });
});

describe('main.js chat wiring', () => {
  const index = (s) => { const i = MAIN_JS.indexOf(s); assert.ok(i >= 0, `${s} not found`); return i; };

  it('creates the messenger after the notification center, with the core classes', () => {
    assert.match(MAIN_JS, /\(\{ MessengerService, ChatNotifier \} = require\('@gatecontrol\/client-core'\)\);/);
    assert.ok(index('chats = setupMessenger({') > index('notifications = setupNotifications({'));
    assert.match(MAIN_JS, /protocol: 'gatecontrol-pro',[\s\S]{0,200}dataDir: app\.getPath\('userData'\),\s*tmpDir: app\.getPath\('temp'\),/);
  });

  it('passes it to the IPC handlers (chat:* channels, reset on server:setup)', () => {
    assert.match(MAIN_JS, /messenger: chats\?\.messenger,\s*chatNotifier: chats\?\.chatNotifier,/);
  });

  it('starts after the push stream, stops on quit', () => {
    assert.ok(index('chats.start();') > index('notifications.start();'));
    const quit = MAIN_JS.slice(index("app.on('before-quit', (e) => {"));
    assert.match(quit, /chats\?\.stop\(\);/);
  });

  it('tray: chat unread in the badge, tooltip and menu (opens the page)', () => {
    assert.match(MAIN_JS, /badge: !!notifications\?\.badge\(\) \|\| !!chats\?\.badge\(\)/);
    assert.match(MAIN_JS, /chats\?\.tooltip\(t\)/);
    assert.match(MAIN_JS, /chats\.menuItems\(t, \(\) => \{ showWindow\(\); mainWindow\?\.webContents\.send\('navigate', 'chats'\); \}\)/);
  });
});
