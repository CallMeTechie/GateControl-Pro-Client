'use strict';

// Notification center wiring (src/main/notifications.js) with fakes and with
// the real core classes, plus how main.js uses it (instances, schema, IPC,
// tunnel changes, protocol activation, tray, shutdown, local notifications).
//
// The real-core part needs @gatecontrol/client-core: node_modules (CI clones
// it to .core) or a sibling checkout ../gatecontrol-client-core.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const Module = require('node:module');
const path = require('node:path');
const fs = require('node:fs');

const ROOT = path.join(__dirname, '..');
const CORE_PKG = '@gatecontrol/client-core';
const MAIN_JS = fs.readFileSync(path.join(ROOT, 'src', 'main', 'main.js'), 'utf8');
const PROTOCOL = 'gatecontrol-pro';

const { setupNotifications, registerProtocolClient } = require('../src/main/notifications');

function findCore() {
  try {
    return path.dirname(require.resolve(`${CORE_PKG}/package.json`, { paths: [ROOT] }));
  } catch { /* not installed */ }
  for (const dir of [path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) {
    if (fs.existsSync(path.join(dir, 'src', 'services', 'notification-center.js'))) return dir;
  }
  return null;
}

const coreDir = findCore();
if (coreDir) {
  const realResolve = Module._resolveFilename;
  Module._resolveFilename = function (request, ...rest) {
    if (request === '@callmetechie/gatecontrol-config-hash') return path.join(__dirname, 'fixtures', 'config-hash-stub.js');
    return realResolve.call(this, request, ...rest);
  };
}
const coreSkip = coreDir ? false : 'gatecontrol-client-core not available';

const quietLog = { info() {}, warn() {}, error() {}, debug() {} };

/** electron-store stand-in with dot paths. */
function memoryStore(initial = {}) {
  const data = JSON.parse(JSON.stringify(initial));
  return {
    get(key, def) {
      const v = key.split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), data);
      return v === undefined ? def : v;
    },
    set(key, value) {
      const parts = key.split('.');
      let o = data;
      for (const p of parts.slice(0, -1)) o = o[p] = o[p] && typeof o[p] === 'object' ? o[p] : {};
      o[parts[parts.length - 1]] = value;
    },
    get store() { return data; },
  };
}

function fakes() {
  const calls = { push: [], center: [], protocol: [], networkChanged: 0, start: 0, stop: 0, argv: [] };
  class FakePushClient extends EventEmitter {
    constructor(opts) { super(); this.opts = opts; calls.push.push(this); }
    networkChanged() { calls.networkChanged++; }
  }
  class FakeCenter extends EventEmitter {
    constructor(opts) { super(); this.opts = opts; calls.center.push(this); this.unread = 0; }
    start() { calls.start++; }
    stop() { calls.stop++; }
    handleArgv(argv) { calls.argv.push(argv); return argv.some((a) => String(a).startsWith(`${PROTOCOL}:`)); }
    unreadCount() { return this.unread; }
    dndState() { return { active: false, until: null }; }
    getPrefs() { return { enabled: true }; }
    notify(o) { calls.notified = o; return { shown: true }; }
  }
  const app = {
    isPackaged: true,
    setAsDefaultProtocolClient: (...args) => { calls.protocol.push(args); return true; },
  };
  return { calls, FakePushClient, FakeCenter, app };
}

function setup(over = {}) {
  const f = fakes();
  let tunnel = false;
  const changes = [];
  const n = setupNotifications({
    app: f.app,
    store: memoryStore(),
    log: quietLog,
    apiClient: { serverUrl: '' },
    PushClient: f.FakePushClient,
    NotificationCenter: f.FakeCenter,
    notifyMenuItems: (o) => [{ label: `inbox ${o.unread}` }, { label: o.dnd.active ? 'dnd off' : 'dnd 1h' }],
    protocol: PROTOCOL,
    toastImagePath: '/app/resources/icons/app-icon.png',
    showWindow: () => {},
    openPortal: async (p) => { f.calls.portal = p; return true; },
    isTunnelUp: () => tunnel,
    isKillSwitchActive: () => true,
    getWgConfigPath: () => '/cfg/gatecontrol0.conf',
    readFile: async (p) => `config of ${p}`,
    onChange: () => changes.push(Date.now()),
    ...over,
  });
  return { n, ...f, changes, setTunnel: (v) => { tunnel = v; } };
}

describe('setupNotifications (fakes)', () => {
  it('creates one push client and one center with the app wiring', async () => {
    const { n, calls } = setup();
    assert.equal(calls.push.length, 1);
    assert.equal(calls.center.length, 1);
    const center = calls.center[0];
    assert.equal(center.opts.pushClient, calls.push[0]);
    assert.equal(center.opts.protocol, PROTOCOL);
    assert.equal(center.opts.toastImagePath, '/app/resources/icons/app-icon.png');
    assert.equal(n.notificationCenter, center);
    assert.equal(n.pushClient, calls.push[0]);
    // kill-switch path check reads the WireGuard config
    assert.equal(await calls.push[0].opts.getWgConfig(), 'config of /cfg/gatecontrol0.conf');
    assert.equal(calls.push[0].opts.isKillSwitchActive(), true);
    // open_portal actions go through the app's portal opener with the path
    await center.opts.openPortal('/notifications');
    assert.equal(calls.portal, '/notifications');
  });

  it('getWgConfig returns null when the file is missing', async () => {
    const { calls } = setup({ readFile: async () => { throw new Error('ENOENT'); } });
    assert.equal(await calls.push[0].opts.getWgConfig(), null);
    const none = setup({ getWgConfigPath: () => '' });
    assert.equal(await none.calls.push[0].opts.getWgConfig(), null);
  });

  it('registers the URL protocol of the toast buttons (packaged, dev, e2e)', () => {
    const packaged = setup();
    assert.deepEqual(packaged.calls.protocol, [[PROTOCOL]]);
    assert.equal(packaged.n.protocolRegistered, true);

    const dev = fakes();
    dev.app.isPackaged = false;
    assert.equal(registerProtocolClient(dev.app, PROTOCOL, { argv: ['electron.exe', '.'], execPath: 'electron.exe' }), true);
    assert.deepEqual(dev.calls.protocol, [[PROTOCOL, 'electron.exe', [path.resolve('.')]]]);

    const e2e = setup({ registerProtocol: false });
    assert.deepEqual(e2e.calls.protocol, []);
    assert.equal(e2e.n.protocolRegistered, false);

    const failing = { isPackaged: true, setAsDefaultProtocolClient: () => { throw new Error('denied'); } };
    assert.equal(registerProtocolClient(failing, PROTOCOL, { log: quietLog }), false);
  });

  it('start() opens the stream once; tunnel changes reconnect it only on up/down', () => {
    const { n, calls } = setup();
    assert.equal(n.tunnelChanged(true), false, 'not started yet');
    n.start();
    n.start();
    assert.equal(calls.start, 1);
    assert.equal(n.tunnelChanged(false), false, 'same state as at start');
    assert.equal(n.tunnelChanged(true), true);
    assert.equal(n.tunnelChanged(true), false, 'stats broadcasts do not reconnect');
    assert.equal(n.tunnelChanged(false), true);
    assert.equal(calls.networkChanged, 2);
  });

  it('second-instance argv: toast button URLs are handled, everything else is not', () => {
    const { n, calls } = setup();
    assert.equal(n.handleArgv(['app.exe', `${PROTOCOL}://notify/action?t=abc`]), true);
    assert.equal(n.handleArgv(['app.exe', '--hidden']), false);
    assert.equal(calls.argv.length, 2);
  });

  it('refreshes the tray on unread and status changes; badge, menu and tooltip', () => {
    const { n, calls, changes } = setup();
    const center = calls.center[0];
    assert.equal(n.badge(), false);
    assert.equal(n.tooltip((k, p) => `${k}:${p.count}`), null);
    center.unread = 2;
    center.emit('unread', 2);
    center.emit('status', {});
    assert.equal(changes.length, 2);
    assert.equal(n.badge(), true);
    assert.equal(n.tooltip((k, p) => `${k}:${p.count}`), 'push.tray.inboxUnread:2');
    assert.deepEqual(n.menuItems(() => '').map((i) => i.label), ['inbox 2', 'dnd 1h']);
  });

  it('stop() is safe to call twice (before-quit and quitApp)', () => {
    const { n, calls } = setup();
    n.start();
    n.stop();
    n.stop();
    assert.equal(calls.stop, 1);
    assert.equal(n.tunnelChanged(true), false, 'no reconnect after stop');
  });

  it('attachControl() creates one PushControl with the app services, started and stopped with the center', () => {
    const { n, calls } = setup();
    const made = [];
    class FakeControl extends EventEmitter {
      constructor(opts) { super(); this.opts = opts; this.started = 0; this.stopped = 0; made.push(this); }
      start() { this.started++; }
      stop() { this.stopped++; }
    }
    const clientPolicy = { id: 'policy' };
    const connectionMonitor = { id: 'monitor' };
    const onConfigChanged = async () => {};
    const modes = [];
    const pc = n.attachControl({ PushControl: FakeControl, clientPolicy, connectionMonitor, onConfigChanged, onModeChange: (m) => modes.push(m) });
    assert.equal(pc, made[0]);
    assert.equal(n.pushControl, pc);
    assert.equal(pc.opts.pushClient, calls.push[0]);
    assert.equal(pc.opts.clientPolicy, clientPolicy);
    assert.equal(pc.opts.connectionMonitor, connectionMonitor);
    assert.equal(pc.opts.onConfigChanged, onConfigChanged);
    assert.equal(pc.started, 1);
    pc.emit('mode', { relaxed: true });
    assert.deepEqual(modes, [{ relaxed: true }]);
    assert.equal(n.attachControl({ PushControl: FakeControl }), pc, 'only one instance');
    n.stop();
    assert.equal(pc.stopped, 1);
    assert.equal(setup().n.attachControl({}), null, 'older core without PushControl');
  });

  it('notify() passes the app notification through the center', () => {
    const { n, calls } = setup();
    n.notify({ title: 'GateControl Pro', body: 'VPN verbunden', collapseKey: 'tunnel' });
    assert.deepEqual(calls.notified, { title: 'GateControl Pro', body: 'VPN verbunden', collapseKey: 'tunnel' });
  });
});

describe('setupNotifications with the real core classes', { skip: coreSkip }, () => {
  let n = null;
  afterEach(() => { n?.stop(); n = null; });

  function realSetup(storeData = {}) {
    // The modules themselves (src/index.js would also load Electron-only parts).
    const core = {
      PushClient: require(path.join(coreDir, 'src', 'services', 'push-client.js')),
      NotificationCenter: require(path.join(coreDir, 'src', 'services', 'notification-center.js')),
      notifyMenuItems: require(path.join(coreDir, 'src', 'utils', 'notify-menu.js')).notifyMenuItems,
      i18n: require(path.join(coreDir, 'src', 'i18n')),
    };
    core.i18n.setLocale('de');
    const shown = [];
    const changes = [];
    n = setupNotifications({
      app: { isPackaged: true, setAsDefaultProtocolClient: () => true },
      store: memoryStore(storeData),
      log: quietLog,
      apiClient: { serverUrl: '', apiKey: '', buildHeaders: () => ({}) },
      PushClient: core.PushClient,
      NotificationCenter: core.NotificationCenter,
      notifyMenuItems: core.notifyMenuItems,
      protocol: PROTOCOL,
      showWindow: () => shown.push('window'),
      openPortal: async () => true,
      isTunnelUp: () => false,
      isKillSwitchActive: () => false,
      getWgConfigPath: () => null,
      registerProtocol: false,
      onChange: () => changes.push('tray'),
    });
    return { core, shown, changes, t: core.i18n.t };
  }

  it('without a server the stream stays off (calm state, no error)', () => {
    realSetup();
    n.start();
    const st = n.notificationCenter.status();
    assert.equal(st.state, 'disabled');
    assert.equal(st.reason, 'not_configured');
    assert.equal(st.unread, 0);
  });

  it('a stale toast button opens the inbox', () => {
    const { shown } = realSetup();
    const nav = [];
    n.notificationCenter.on('navigate', (e) => nav.push(e));
    assert.equal(n.handleArgv(['GateControl Pro Client.exe', `${PROTOCOL}://notify/action?t=AAAAAAAAAAAAAAAA`]), true);
    assert.deepEqual(nav, [{ route: 'inbox', id: null }]);
    assert.deepEqual(shown, ['window']);
    assert.equal(n.handleArgv(['GateControl Pro Client.exe', 'gatecontrol-community://notify/action?t=x']), false);
  });

  it('a push message sets the tray badge, tooltip and menu entry', () => {
    const { changes, t } = realSetup();
    assert.deepEqual(n.menuItems(t).map((i) => i.label), ['Mitteilungen', 'Nicht stören für 1 Stunde']);
    n.notificationCenter.handleNotification({
      seq: 7, id: 45, topic: 'devices', priority: 'critical', title: 'Gateway „Zuhause“ ist offline',
      body: 'Seit 2 Minuten kein Lebenszeichen', created_at: new Date().toISOString(),
    });
    assert.equal(n.badge(), true);
    assert.ok(changes.length >= 1, 'tray refreshed on the unread change');
    assert.equal(n.tooltip(t), 'Mitteilungen · 1 neu');
    const items = n.menuItems(t);
    assert.deepEqual(items.map((i) => i.label), ['Mitteilungen · 1 neu', 'Nicht stören für 1 Stunde']);
    items[1].click();
    assert.equal(n.notificationCenter.dndState().active, true);
    assert.equal(n.menuItems(t)[1].label, 'Nicht stören beenden');
  });

  it('push control: hello.state stretches the polls, control events reach policy, support and config', async () => {
    const http = require('node:http');
    const PushControl = require(path.join(coreDir, 'src', 'services', 'push-control.js'));
    const ClientPolicyService = require(path.join(coreDir, 'src', 'services', 'client-policy.js'));
    const ConnectionMonitor = require(path.join(coreDir, 'src', 'services', 'connection-monitor.js'));
    const ev = (event, data) => `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    const streams = new Set();
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      streams.add(res);
      res.write(ev('hello', { keepalive_s: 25, via: 'direct', unread: 0, topics: [],
        quiet: { from: '22:00', to: '07:00', tz: 'Europe/Berlin', critical_bypass: true },
        state: { policy_version: '3f9a0c1d22b4e7a8', peer_enabled: true, support_bundle_requested: false, support_bundle_requested_at: null, config_hash: null } }));
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const url = `http://127.0.0.1:${server.address().port}`;
    const policyCalls = [];
    const support = [];
    let configChecks = 0;
    const apiClient = {
      serverUrl: url, apiKey: 'gc_x', buildHeaders: () => ({ 'X-API-Token': 'gc_x' }),
      pushAck: async () => ({ ok: true }), pushPrefs: async () => ({ ok: true }), pushInbox: async () => ({ ok: true, items: [], unread: 0 }),
      getClientPolicy: async (v) => { policyCalls.push(v); return { notModified: false, data: { ok: true, version: policyCalls.length > 1 ? '0b7e5d2c91a4f360' : '3f9a0c1d22b4e7a8', policy: {} } }; },
    };
    const store = memoryStore({ notifications: { enabled: true, direct: true, mutedTopics: [] } });
    const core = {
      PushClient: class extends require(path.join(coreDir, 'src', 'services', 'push-client.js')) {
        constructor(o) { super({ ...o, allowHttp: true }); }
      },
      NotificationCenter: require(path.join(coreDir, 'src', 'services', 'notification-center.js')),
    };
    n = setupNotifications({
      app: { isPackaged: true, setAsDefaultProtocolClient: () => true }, store, log: quietLog, apiClient,
      PushClient: core.PushClient, NotificationCenter: core.NotificationCenter, notifyMenuItems: () => [],
      protocol: PROTOCOL, showWindow: () => {}, openPortal: async () => true,
      isTunnelUp: () => false, isKillSwitchActive: () => false, getWgConfigPath: () => null, registerProtocol: false,
    });
    const clientPolicy = new ClientPolicyService({ apiClient, store, log: quietLog, interval: 300000 });
    const connectionMonitor = new ConnectionMonitor({ apiClient, log: quietLog, wgService: {}, onSupportBundleRequest: (r) => support.push(r) });
    const pc = n.attachControl({ PushControl, clientPolicy, connectionMonitor, onConfigChanged: async () => { configChecks++; } });
    try {
      n.start();
      const until = async (fn, what) => { for (let i = 0; i < 300 && !fn(); i++) await new Promise((r) => setTimeout(r, 10)); assert.ok(fn(), what); };
      await until(() => pc.relaxed, 'relaxed after hello.state');
      assert.equal(clientPolicy.pollInterval(), 30 * 60 * 1000);
      assert.equal(connectionMonitor.peerCheckMode().ms, 15 * 60 * 1000);
      assert.deepEqual(n.notificationCenter.status().quiet, { from: '22:00', to: '07:00', tz: 'Europe/Berlin', criticalBypass: true });
      await until(() => policyCalls.length === 1, 'policy refresh on the first hello');
      for (const res of streams) {
        res.write(ev('control', { type: 'policy_changed', policy_version: '0b7e5d2c91a4f360' }));
        res.write(ev('control', { type: 'support_bundle_requested', requested_at: '2026-10-11 10:00:00' }));
        res.write(ev('control', { type: 'config_changed' }));
      }
      await until(() => policyCalls.length === 2 && configChecks === 1 && support.includes('2026-10-11 10:00:00'), 'control reactions');
      for (const res of streams) res.destroy();
      await until(() => !pc.relaxed, 'back to normal polling when the stream drops');
      assert.equal(clientPolicy.pollInterval(), 300000);
    } finally {
      n.stop();
      clientPolicy.stop();
      for (const res of streams) res.destroy();
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
    }
  });

  it('switched off: no tray entries', () => {
    const { t } = realSetup({ notifications: { enabled: false } });
    assert.deepEqual(n.menuItems(t), []);
  });
});

describe('main.js notification wiring', () => {
  const index = (needle) => {
    const i = MAIN_JS.indexOf(needle);
    assert.ok(i >= 0, `main.js: ${needle}`);
    return i;
  };

  it('merges the core notifications schema into the Pro store schema', () => {
    assert.match(MAIN_JS, /notificationsSchema \} = require\('@gatecontrol\/client-core'\)/);
    assert.match(MAIN_JS, /schema: \{ \.\.\.proSchema, \.\.\.notificationsSchema \}/);
  });

  it('creates the notification center once, after ClientPolicyService', () => {
    assert.equal(MAIN_JS.match(/setupNotifications\(\{/g).length, 1);
    assert.ok(index('clientPolicy = new ClientPolicyService(') < index('notifications = setupNotifications({'));
    assert.match(MAIN_JS, /protocol: 'gatecontrol-pro'/);
    assert.match(MAIN_JS, /registerProtocol: !e2e/);
    assert.match(MAIN_JS, /isTunnelUp: \(\) => tunnelState\.connected/);
  });

  it('hands the center to the core IPC handlers (notify:* + reset on server:setup)', () => {
    assert.match(MAIN_JS, /notificationCenter: notifications\?\.notificationCenter/);
    // Pro does not override server:setup, so the core handler resets the center.
    const ipcPro = fs.readFileSync(path.join(ROOT, 'src', 'main', 'ipc-pro.js'), 'utf8');
    assert.doesNotMatch(ipcPro, /'server:setup'/);
  });

  it('starts the stream after window and tray, handles a start from a toast', () => {
    assert.ok(index('createTray();\n') < index('notifications.start();'));
    assert.match(MAIN_JS, /notifications\.handleArgv\(process\.argv\)/);
  });

  it('tells the push client about tunnel up/down where tunnel-state is sent', () => {
    const fn = MAIN_JS.slice(index('function broadcastState('), index('async function connectTunnel('));
    assert.match(fn, /webContents\.send\('tunnel-state', state\);\s*\/\/[^\n]*\n[^\n]*\n\s*notifications\?\.tunnelChanged\(tunnelState\.connected\);/);
  });

  it('second-instance: toast button first, otherwise bring the window up', () => {
    assert.match(MAIN_JS, /app\.on\('second-instance', \(_event, argv\) => \{\s*if \(notifications\?\.handleArgv\(argv\)\) return;\s*showWindow\(\);\s*\}\);/);
  });

  it('attaches the push control after the connection monitor, with the config check', () => {
    assert.match(MAIN_JS, /\{ PushClient, NotificationCenter, PushControl, notifyMenuItems, notificationsSchema \} = require\('@gatecontrol\/client-core'\)/);
    assert.ok(index('connectionMonitor = new ConnectionMonitor({') < index('notifications.attachControl({'));
    const block = MAIN_JS.slice(index('notifications.attachControl({'), index('notifications.attachControl({') + 300);
    assert.match(block, /PushControl,\s*clientPolicy,\s*connectionMonitor,\s*onConfigChanged: \(\) => applyServerConfigChange\(\)/);
    const fn = MAIN_JS.slice(index('async function applyServerConfigChange()'), index('async function applyServerConfigChange()') + 700);
    assert.match(fn, /if \(!tunnelState\.connected \|\| isReconnecting\) return;/);
    assert.match(fn, /apiClient\.checkConfigUpdate\(\)/);
    assert.match(fn, /validateWgConfig\(config\)/);
    assert.match(fn, /await disconnectTunnel\(\);\s*await connectTunnel\(\);/);
  });

  it('portal:open passes { next } and push actions their target to the portal opener', () => {
    assert.match(MAIN_JS, /openPortal: \(opts\) => openPortalSafe\(opts\)/);
    assert.match(MAIN_JS, /openPortal: \(portalPath\) => openPortalSafe\(portalPath\)/);
    const fn = MAIN_JS.slice(index('function openPortalSafe(target)'), index('function openPortalSafe(target)') + 400);
    assert.match(fn, /typeof target === 'string'\) opts = \{ path: target \}/);
    assert.match(fn, /opts = \{ next: target\.next \}/);
  });

  it('stops the center on quit', () => {
    const quit = MAIN_JS.slice(index("app.on('before-quit', (e) => {"));
    assert.match(quit, /notifications\?\.stop\(\);/);
  });

  it('tray: unread dot and the notification menu entries', () => {
    assert.match(MAIN_JS, /createTrayIcon\(nativeImage, connState, \{ badge: !!notifications\?\.badge\(\) \|\| !!chats\?\.badge\(\) \}\)/);
    assert.match(MAIN_JS, /notifications\.menuItems\(t\)/);
    assert.match(MAIN_JS, /onChange: \(\) => updateTray\(trayState\)/);
  });

  it('local notifications go through the center (only the fallback creates one directly)', () => {
    assert.equal((MAIN_JS.match(/new Notification\(/g) || []).length, 1);
    assert.match(MAIN_JS, /notifications\.notify\(\{ title, body, priority, collapseKey, force, onClick \}\)/);
    // the mandatory update must always be shown and opens the window
    assert.match(MAIN_JS, /collapseKey: 'update', force: true,\s*onClick: \(\) => showWindow\(\)/);
  });

  it('sets the AppUserModelID of the installed shortcut (build.appId)', () => {
    const pkg = require('../package.json');
    // plain substring check: the appId is data, not a pattern
    assert.ok(MAIN_JS.includes(`app.setAppUserModelId('${pkg.build.appId}')`), `setAppUserModelId('${pkg.build.appId}') missing`);
  });

  it('the uninstaller removes the URL protocol, but not on updates', () => {
    const nsh = fs.readFileSync(path.join(ROOT, 'build', 'installer.nsh'), 'utf8');
    const body = nsh.slice(nsh.indexOf('!macro customUnInstall'), nsh.indexOf('!macroend', nsh.indexOf('!macro customUnInstall')));
    const del = body.indexOf(`DeleteRegKey HKCU "Software\\Classes\\${PROTOCOL}"`);
    assert.ok(del > 0, 'customUnInstall does not remove the protocol key');
    const start = body.indexOf('${IfNot} ${isUpdated}');
    assert.ok(start >= 0 && start < del && del < body.indexOf('${EndIf}', start));
  });
});
