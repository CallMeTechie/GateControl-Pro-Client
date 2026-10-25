/**
 * GateControl Pro Client -- Electron Main Process
 */

// ── Crash Log (absolute first — writes to file, no dependencies) ──
const _fs = require('fs');
const _os = require('os');
const _path = require('path');
const _crashLog = _path.join(_os.homedir(), 'gatecontrol-pro-crash.log');

function writeCrashLog(label, err) {
  try {
    const msg = `[${new Date().toISOString()}] ${label}: ${err && err.stack ? err.stack : err}\n`;
    _fs.appendFileSync(_crashLog, msg);
  } catch {}
}

process.on('uncaughtException', (err) => {
  writeCrashLog('uncaughtException', err);
  try {
    const { dialog: d } = require('electron');
    d.showErrorBox('GateControl Pro Error', `${err.message}\n\n${err.stack}`);
  } catch {}
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  writeCrashLog('unhandledRejection', reason);
});

writeCrashLog('STARTUP', 'Process starting...');

let app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, dialog, Notification, screen, shell, clipboard, safeStorage, powerMonitor, globalShortcut;
let createSupportBundleSender, loadUpdatePublicKey, reconnectDelay, shouldOpenPortal, createPortalOpener, recoverKillSwitch, createTrayIcon, updateMenuItems, updateToast;
let e2e = null; // E2E test hooks (unpackaged dev runs only, see e2e-guard.js)
let Store, log, validateWgConfig, registerProIpc, WireGuardService, KillSwitch, RdpAllowSvc, ApiClientPro, Updater, ConnectionMonitor, DnsPolicy, RdpManager, runRdpTrustMigration, RdpWolClient;
let ClientPolicyService, clientPolicyUtil, applyPolicyToStore;
let createUpdateInstaller, installErrorText;
let PushClient, NotificationCenter, PushControl, notifyMenuItems, notificationsSchema, setupNotifications;
let MessengerService, ChatNotifier, setupMessenger;
let SchoolService;
let VaultService, windowsHello, setupVaultQuick;
let GateDropService, GateDropFirewall, gatedropShell, setupGateDrop;
let getMachineFingerprint, collectSupportBundle, shortDeviceId, withDeviceId;
let installWindowGuard, autostartTask, createAutostart;

try {
  writeCrashLog('IMPORT', 'Loading electron...');
  ({ app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, dialog, Notification, screen, shell, clipboard, safeStorage, powerMonitor, globalShortcut } = require('electron'));
  // Chats "Standort senden": navigator.geolocation from the Windows location
  // service (Electron has no key for Google's network location).
  if (process.platform === 'win32') app.commandLine.appendSwitch('enable-features', 'WinrtGeolocationImplementation');

  // Before any core service is required; a packaged build never loads it.
  e2e = require('./e2e-guard').loadE2eHooks({ app });

  writeCrashLog('IMPORT', 'Loading electron-store...');
  // electron-store 9+ is ESM-only: require() gives the namespace, the class is its default.
  const electronStore = require('electron-store');
  Store = electronStore.default || electronStore;

  writeCrashLog('IMPORT', 'Loading electron-log...');
  log = require('electron-log');

  writeCrashLog('IMPORT', 'Loading core services...');
  WireGuardService = require('@gatecontrol/client-core/src/services/wireguard-native');
  ({ validateWgConfig } = require('@gatecontrol/client-core'));
  KillSwitch = require('@gatecontrol/client-core/src/services/killswitch');
  RdpAllowSvc = require('@gatecontrol/client-core/src/services/rdp-allow');

  writeCrashLog('IMPORT', 'Loading pro services...');
  ApiClientPro = require('../services/api-client-pro');
  Updater = require('@gatecontrol/client-core/src/services/updater');
  // Shared helpers from core: update key loader, pure tunnel/portal logic,
  // kill-switch startup recovery, tray icon (unit-tested in core).
  ({ loadUpdatePublicKey } = require('@gatecontrol/client-core/src/utils/update-public-key'));
  ({ reconnectDelay, shouldOpenPortal } = require('@gatecontrol/client-core/src/utils/tunnel-logic'));
  ({ createPortalOpener } = require('@gatecontrol/client-core/src/utils/portal'));
  ({ recoverKillSwitch } = require('@gatecontrol/client-core/src/lifecycle/killswitch-startup'));
  ({ createTrayIcon } = require('@gatecontrol/client-core/src/utils/tray-icon'));
  ({ updateMenuItems, updateToast } = require('@gatecontrol/client-core/src/utils/update-notice'));
  ({ createUpdateInstaller, installErrorText } = require('@gatecontrol/client-core/src/utils/update-install'));
  ConnectionMonitor = require('@gatecontrol/client-core/src/services/connection-monitor');
  DnsPolicy = require('@gatecontrol/client-core/src/services/dns-policy');
  // Client policies from the server (kill switch / auto-connect / autostart /
  // split modes / settings + server lock), cached for offline use.
  ClientPolicyService = require('@gatecontrol/client-core/src/services/client-policy');
  clientPolicyUtil = require('@gatecontrol/client-core/src/utils/client-policy');
  ({ applyPolicyToStore } = require('@gatecontrol/client-core/src/ipc/base-handlers'));
  // Notification center: push stream from the own server, toasts, inbox,
  // tray entries (core docs/notification-center.md).
  ({ PushClient, NotificationCenter, PushControl, notifyMenuItems, notificationsSchema } = require('@gatecontrol/client-core'));
  ({ setupNotifications } = require('./notifications'));
  // Chats (GateControl Messenger): data, live events, outbox, chat toasts
  // (core docs/messenger.md).
  ({ MessengerService, ChatNotifier } = require('@gatecontrol/client-core'));
  ({ setupMessenger } = require('./messenger'));
  // Schule (plugin gatecontrol-schule): WebUntis timetable (core services/school.js).
  ({ SchoolService } = require('@gatecontrol/client-core'));
  // Vault (plugin gatecontrol-vault): end-to-end encrypted password manager
  // (core docs/vault.md); quick search window on Strg+Alt+P.
  ({ VaultService, windowsHello } = require('@gatecontrol/client-core'));
  ({ setupVaultQuick } = require('./vault-quick'));
  // GateDrop (plugin gatecontrol-gatedrop): send / receive files, LAN listener,
  // "Senden an" in the Explorer (core services/gatedrop.js).
  ({ GateDropService, GateDropFirewall, gatedropShell } = require('@gatecontrol/client-core'));
  ({ setupGateDrop } = require('./gatedrop'));
  RdpManager = require('../services/rdp/rdp-manager');
  ({ runRdpTrustMigration } = require('../services/rdp/rdp-trust-migration'));
  RdpWolClient = require('../services/rdp/rdp-wol');
  ({ registerProIpc } = require('./ipc-pro'));
  ({ createSupportBundleSender } = require('@gatecontrol/client-core/src/support/sender'));
  ({ collectSupportBundle } = require('@gatecontrol/client-core/src/support/collector'));
  ({ getMachineFingerprint } = require('@gatecontrol/client-core/src/utils/machine-id'));
  ({ shortDeviceId, withDeviceId } = require('./device-id'));
  ({ installWindowGuard } = require('@gatecontrol/client-core/src/utils/window-guard'));
  autostartTask = require('@gatecontrol/client-core/src/utils/autostart-task');
  ({ createAutostart } = require('./autostart'));

  writeCrashLog('IMPORT', 'All imports successful');

  writeCrashLog('IMPORT', 'Loading i18n...');
  var _i18nModule = require('@gatecontrol/client-core').i18n;
} catch (err) {
  writeCrashLog('IMPORT_FAILED', err);
  try {
    const { dialog: d } = require('electron');
    d.showErrorBox('GateControl Pro Import Error', `${err.message}\n\n${err.stack}`);
  } catch {}
  process.exit(1);
}

const path = _path;

const { t, setLocale, getLocale, registerTranslations, resolveLocale } = _i18nModule;

// Register Pro-specific translations
registerTranslations('de', require('../i18n/de.json'));
registerTranslations('en', require('../i18n/en.json'));

// ── Logging ──────────────────────────────────────────────────
log.transports.file.level = 'info';
log.transports.file.maxSize = 1024 * 1024; // 1 MB
log.transports.console.level = 'debug';
writeCrashLog('STARTUP', 'Logging configured');

// ── Single Instance Lock ─────────────────────────────────────
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.exit(0);
}

// ── Fenster-Schutz ───────────────────────────────────────────
// Every window (main window, Vault quick search, …): only the app's own
// pages, http(s) links in the system browser, no new windows, no <webview>
// (core utils/window-guard). Links of the renderer go through
// shell:open-external and are not affected.
installWindowGuard(app, {
  appRoots: [path.join(__dirname, '..', 'renderer')],
  getShell: () => shell,
  log,
});

// ── Konfiguration ────────────────────────────────────────────
const crypto = require('crypto');
const fsSync = require('fs');
const { execFile: _execFile } = require('child_process');
const { promisify: _promisify } = require('util');
const execFileAsync = _promisify(_execFile);

const keyStore = new Store({ name: 'gatecontrol-pro-keyfile', encryptionKey: 'gc-pro-bootstrap' });

if (!keyStore.get('machineKey')) {
  const newKey = crypto.randomBytes(32).toString('hex');
  try {
    const configPath = path.join(app.getPath('userData'), 'gatecontrol-pro-config.json');
    if (fsSync.existsSync(configPath)) {
      fsSync.unlinkSync(configPath);
      log.info('Old config file removed (one-time key migration)');
    }
  } catch {}
  keyStore.set('machineKey', newKey);
}

// Pro schema plus the notification center fragment from core
// (notifications.*; the inbox cache lives under notificationsInbox).
const proSchema = {
  server: {
    type: 'object',
    properties: {
      url:    { type: 'string', default: '' },
      apiKey: { type: 'string', default: '' },
      peerId: { type: 'string', default: '' },
    },
    default: {},
  },
  tunnel: {
    type: 'object',
    properties: {
      interfaceName: { type: 'string', default: 'gatecontrol0' },
      autoConnect:   { type: 'boolean', default: true },
      killSwitch:    { type: 'boolean', default: false },
      rdpAllow:      { type: 'boolean', default: false },
      splitTunnel:   { type: 'boolean', default: false },
      splitRoutes:   { type: 'string', default: '' },
      configPath:    { type: 'string', default: '' },
      // { domain, server } from GET /client/config, null = internal DNS off
      internalDns:   { type: ['object', 'null'] },
    },
    default: {},
  },
  app: {
    type: 'object',
    properties: {
      startMinimized:  { type: 'boolean', default: true },
      startWithWindows: { type: 'boolean', default: true },
      theme:           { type: 'string', default: 'dark' },
      checkInterval:   { type: 'number', default: 30 },
      configPollInterval: { type: 'number', default: 300 },
    },
    default: {},
  },
  rdp: {
    type: 'object',
    properties: {
      panelPinned: { type: 'boolean', default: false },
    },
    default: {},
  },
};

const store = new Store({
  name: 'gatecontrol-pro-config',
  encryptionKey: keyStore.get('machineKey'),
  schema: { ...proSchema, ...notificationsSchema },
});

// ── Globale Referenzen ───────────────────────────────────────
let mainWindow = null;
let tray = null;
let wgService = null;
let killSwitchSvc = null;
let rdpAllowSvc = null;
let apiClient = null;
let connectionMonitor = null;
let updater = null;
let dnsPolicy = null;
let clientPolicy = null;
let rdpManager = null;
let rdpWolClient = null;
let supportBundle = null; // "Support-Paket senden" (core src/support/sender.js)
let notifications = null; // notification center (./notifications.js), one per app lifetime
let chats = null; // messenger (./messenger.js), one per app lifetime
let school = null; // Schule (core SchoolService), one per app lifetime
let vault = null; // Vault (core VaultService), one per app lifetime
let vaultQuick = null; // Vault quick search window (./vault-quick.js)
let gatedrop = null; // GateDrop (./gatedrop.js), one per app lifetime
let trayState = 'disconnected'; // last state drawn in the tray (refresh on unread / DND changes)
let pendingUpdate = null;
// Version for which the "Update erforderlich" notification was already shown
// in this session (shown again on every app start while still required).
let mandatoryNotifiedVersion = null;

// ── State ────────────────────────────────────────────────────
let tunnelState = {
  connected: false,
  interface: null,
  endpoint: null,
  handshake: null,
  rxBytes: 0,
  txBytes: 0,
  rxSpeed: 0,
  txSpeed: 0,
  uptime: 0,
  connectedSince: null,
};
let lastRxBytes = 0;
let lastTxBytes = 0;
let lastStatsTime = 0;
let isReconnecting = false;
let rdpPanelOpen = false;

// ── Portal state ─────────────────────────────────────────────
let portalUrl = null;
let autoOpenPortal = false;
let portalOpenedSince = null;

// ── Constants ────────────────────────────────────────────────
// Sidebar layout (240px navigation + content). Remote Desktops is a regular
// page now, so the window no longer grows for a slide-out panel.
const DEFAULT_WIDTH = 1280;
const DEFAULT_HEIGHT = 800;
const MIN_WIDTH = 1000;
const MIN_HEIGHT = 640;

// ── Pfade ────────────────────────────────────────────────────
const RESOURCES_PATH = app.isPackaged
  ? path.join(process.resourcesPath, 'resources')
  : path.join(__dirname, '..', '..', 'resources');

const WG_CONFIG_DIR = path.join(app.getPath('userData'), 'wireguard');
const WG_CONFIG_FILE = path.join(WG_CONFIG_DIR, 'gatecontrol0.conf');

// ── Helpers ──────────────────────────────────────────────────
// Opens the portal (https only). Asks the server for a fresh one-time login
// link right before every open and falls back to the plain portal URL
// (core utils/portal.js). Used by auto-open, tray and the "Portal öffnen" button,
// push actions (open_portal: target) and "Ruhezeiten im Portal ändern": a
// portal tab ('/portal#benachrichtigungen') goes to the server as `next`.
function openPortalSafe(target) {
  let opts;
  if (typeof target === 'string') opts = { path: target };
  else if (target && typeof target.next === 'string') opts = { next: target.next };
  return createPortalOpener({ apiClient, getPortalUrl: () => portalUrl, log })
    .open(opts)
    .catch(() => false);
}

// Push `config_changed` / a different config_hash in hello.state (core
// PushControl): while the tunnel is up, ask config/check and reconnect with
// the new configuration (connectTunnel fetches, validates and writes it).
// Without tunnel nothing to do — the next connect fetches the config anyway.
async function applyServerConfigChange() {
  if (!tunnelState.connected || isReconnecting) return;
  const config = await apiClient.checkConfigUpdate();
  if (!config) return;
  const validation = validateWgConfig(config);
  if (!validation.ok) {
    log.warn('Config update rejected: ' + validation.errors.join(', '));
    return;
  }
  log.info('New configuration on the server — reconnecting');
  await disconnectTunnel();
  await connectTunnel();
}

// The app's own notifications go through the notification center: same toast
// code as push messages, respects "Nicht stören" and "Windows-Benachrichtigung
// anzeigen" unless `force` (messages the user must see).
function notify(body, { title = 'GateControl Pro', priority = 'normal', collapseKey = null, force = false, onClick = null, actions = null } = {}) {
  if (!body) return null;
  if (!notifications) {
    // Before the services exist (should not happen) fall back to a plain toast.
    try { new Notification({ title, body }).show(); } catch { /* not supported */ }
    return null;
  }
  return notifications.notify({ title, body, priority, collapseKey, force, onClick, actions });
}

// ── Tray Icon (Sun/Star design, drawn by core) ──────────────
function getIcon(state) {
  return createTrayIcon(nativeImage, state);
}

function updateTray(connState) {
  trayState = connState;
  if (!tray) return;

  // Unread push notifications: dot on the tray icon.
  tray.setImage(createTrayIcon(nativeImage, connState, { badge: !!notifications?.badge() || !!chats?.badge() }));

  const statusText = connState === 'connected' ? t('status.connected')
    : connState === 'connecting' ? t('status.connecting')
    : t('status.disconnected');

  let tooltip = `GateControl Pro - ${statusText}`;
  if (tunnelState.connected && tunnelState.connectedSince) {
    const dur = Math.floor((Date.now() - new Date(tunnelState.connectedSince).getTime()) / 1000);
    const h = Math.floor(dur / 3600);
    const m = Math.floor((dur % 3600) / 60);
    tooltip += `\n${t('tray.connectedSince', { duration: `${h > 0 ? h + 'h ' : ''}${m}m` })}`;
  }

  // RDP active sessions count
  if (rdpManager) {
    const sessions = rdpManager.getActiveSessions();
    if (sessions.length > 0) {
      tooltip += `\n${t('rdp.sessions', { count: sessions.length })}`;
    }
  }

  const unreadLine = notifications?.tooltip(t);
  if (unreadLine) tooltip += `\n${unreadLine}`;
  const chatLine = chats?.tooltip(t);
  if (chatLine) tooltip += `\n${chatLine}`;

  tray.setToolTip(tooltip);

  // "Mitteilungen · n neu" and "Nicht stören für 1 Stunde" (core notifyMenuItems)
  const notifyItems = [
    ...(chats ? chats.menuItems(t, () => { showWindow(); mainWindow?.webContents.send('navigate', 'chats'); }) : []),
    ...(notifications ? notifications.menuItems(t) : []),
    ...(gatedrop ? gatedrop.menuItems(t) : []),
  ];

  // Build context menu with RDP status
  const rdpSessions = rdpManager ? rdpManager.getActiveSessions() : [];

  // Ready update: a mandatory one goes to the top, an optional one stays below
  const updateItems = updateMenuItems({
    update: pendingUpdate,
    mandatory: !!updater?.isMandatory(),
    t,
    install: () => installUpdateFromTray(),
  });

  const contextMenu = Menu.buildFromTemplate([
    { label: `GateControl Pro - ${statusText}`, enabled: false, icon: getIcon(connState) },
    { type: 'separator' },
    ...updateItems.top,
    ...(notifyItems.length ? [...notifyItems, { type: 'separator' }] : []),
    {
      label: connState === 'connected' ? t('action.disconnect') : t('action.connect'),
      // Always-on policy: no manual disconnect (hint in the label)
      enabled: !(connState === 'connected' && policyLocks().disconnect),
      click: () => connState === 'connected' ? disconnectTunnel() : connectTunnel(),
    },
    { type: 'separator' },
    {
      label: policyLocks().killSwitch ? `${t('killswitch.label')} (${t('policy.lockedHint')})` : t('killswitch.label'),
      type: 'checkbox',
      checked: store.get('tunnel.killSwitch', false),
      enabled: !policyLocks().killSwitch,
      click: (item) => toggleKillSwitch(item.checked),
    },
    ...(rdpSessions.length > 0 ? [
      { type: 'separator' },
      { label: `RDP Sessions (${rdpSessions.length})`, enabled: false },
      ...rdpSessions.map(s => ({
        label: `  ${s.host} (${Math.floor(s.duration / 60)}m)`,
        enabled: false,
      })),
    ] : []),
    { type: 'separator' },
    { label: t('tray.openWindow'), click: () => showWindow() },
    ...updateItems.bottom,
    ...(portalUrl ? [
      { type: 'separator' },
      { label: t('portal.open'), click: () => openPortalSafe() },
    ] : []),
    { type: 'separator' },
    {
      label: t('tray.checkUpdate'),
      click: async () => {
        if (!updater) return;
        const release = await updater.check();
        if (release) {
          pendingUpdate = release;
          updateTray(connState);
          if (mainWindow) mainWindow.webContents.send('update:ready', release);
        } else {
          notify(t('tray.noUpdateAvailable'), { collapseKey: 'update', force: true });
        }
      },
    },
    { type: 'separator' },
    { label: t('tray.quit'), click: () => quitApp() },
  ]);

  tray.setContextMenu(contextMenu);
}

function createTray() {
  tray = new Tray(getIcon('disconnected'));
  tray.setToolTip('GateControl Pro');
  updateTray('disconnected');
  tray.on('double-click', () => showWindow());
}

// ── Fenster ──────────────────────────────────────────────────
function createWindow() {
  const storedTheme = store.get('app.theme', 'dark');
  const lightBg = storedTheme === 'light'
    || (storedTheme === 'system' && !require('electron').nativeTheme.shouldUseDarkColors);
  mainWindow = new BrowserWindow({
    width: Math.max(MIN_WIDTH, store.get('app.windowWidth', DEFAULT_WIDTH)),
    minWidth: MIN_WIDTH,
    height: Math.max(MIN_HEIGHT, store.get('app.windowHeight', DEFAULT_HEIGHT)),
    minHeight: MIN_HEIGHT,
    resizable: true,
    frame: false,
    backgroundColor: lightBg ? '#F3F5F8' : '#0D1015',
    titleBarStyle: 'hidden',
    show: false,
    icon: app.isPackaged
      ? path.join(RESOURCES_PATH, 'icons', 'app-icon.png')
      : path.join(__dirname, '..', '..', 'build', 'icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  mainWindow.once('ready-to-show', () => {
    if (!store.get('app.startMinimized', true)) {
      mainWindow.show();
    }
  });

  mainWindow.on('resize', () => {
    const [width, height] = mainWindow.getSize();
    store.set('app.windowWidth', width);
    store.set('app.windowHeight', height);
  });

  mainWindow.on('close', (e) => {
    if (!app.isQuitting) {
      e.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Vault auto-lock "immediately" (0): the window goes to the tray / taskbar.
  mainWindow.on('hide', () => vault?.windowHidden());
  mainWindow.on('minimize', () => vault?.windowHidden());
}

/** The app's theme resolved to dark / light (Vault quick search window). */
function resolvedAppTheme() {
  const stored = store.get('app.theme', 'dark');
  if (stored === 'system') return require('electron').nativeTheme.shouldUseDarkColors ? 'dark' : 'light';
  return stored === 'light' ? 'light' : 'dark';
}

function showWindow() {
  if (mainWindow) {
    mainWindow.show();
    mainWindow.focus();
  }
}

function quitApp() {
  app.isQuitting = true;
  app.quit();
}

// ── Client-Richtlinie ────────────────────────────────────────
function policyLocks() {
  return clientPolicyUtil.locks(clientPolicy ? clientPolicy.getPolicy() : null);
}

/**
 * Apply the (cached or freshly fetched) client policy: force the store
 * values and act on what changed. Runs at start-up with the cached policy
 * (offline-safe) and on every policy change.
 */
async function applyClientPolicy({ startup = false } = {}) {
  if (!clientPolicy) return;
  const policy = clientPolicy.getPolicy();
  const changed = applyPolicyToStore(store, policy, log);
  if (Object.keys(changed).length) log.info(`Client policy applied: ${JSON.stringify(changed)}`);

  if (changed['tunnel.killSwitch'] === true && tunnelState.connected && !killSwitchSvc.enabled) {
    try { await killSwitchSvc.enable(WG_CONFIG_FILE); } catch (err) { log.error('Kill-switch (policy) failed:', err.message); }
  }
  if (Object.prototype.hasOwnProperty.call(changed, 'app.startWithWindows') && !e2e) {
    setAutostartTask(changed['app.startWithWindows']).catch((err) => log.warn('Autostart (policy) failed:', err.message));
  }
  if (!startup) {
    const hasServer = store.get('server.url', '') && store.get('server.apiKey', '');
    if (Object.prototype.hasOwnProperty.call(changed, 'tunnel.splitTunnel') && tunnelState.connected && !isReconnecting) {
      await disconnectTunnel();
      await connectTunnel();
    } else if (policy.autoConnect !== 'user' && hasServer && !tunnelState.connected && !isReconnecting) {
      connectTunnel().catch(() => {});
    }
  }
  broadcastState(tunnelState.connected ? 'connected' : 'disconnected');
  updateTray(tunnelState.connected ? 'connected' : 'disconnected');
  mainWindow?.webContents.send('policy:changed', clientPolicy.getState());
}

// ── Tunnel Functions (stubs -- delegate to core services) ─────
function broadcastState(status, error = null) {
  const state = {
    status,
    error,
    connected: tunnelState.connected,
    endpoint: store.get('server.url', '') || tunnelState.endpoint,
    handshake: tunnelState.handshake,
    rxBytes: tunnelState.rxBytes,
    txBytes: tunnelState.txBytes,
    rxSpeed: tunnelState.rxSpeed || 0,
    txSpeed: tunnelState.txSpeed || 0,
    connectedSince: tunnelState.connectedSince,
    killSwitch: store.get('tunnel.killSwitch', false),
    rdpAllow: store.get('tunnel.rdpAllow', false),
  };
  mainWindow?.webContents.send('tunnel-state', state);
  // Push stream follows the tunnel (path "via", mode vpn_only); only an
  // up/down change reconnects it, not the stats broadcasts.
  notifications?.tunnelChanged(tunnelState.connected);
}

async function connectTunnel() {
  // Block external (user/tray) connect calls while the reconnect loop owns the
  // tunnel; the reconnect loop drives wgService directly and never calls this.
  if (isReconnecting) {
    log.debug('Reconnect already in progress, skipping connectTunnel');
    return;
  }
  try {
    log.info('Establishing tunnel connection...');
    if (connectionMonitor) connectionMonitor.stop();
    updateTray('connecting');
    broadcastState('connecting');

    const serverUrl = store.get('server.url');
    const apiKey = store.get('server.apiKey');

    if (serverUrl && apiKey) {
      let config = null;
      try {
        config = await apiClient.fetchConfig();
      } catch (err) {
        log.warn('Config fetch failed, using local config:', err.message);
      }
      if (config) {
        // Fail-closed: a bad server answer must not clobber a good local
        // config (and must not become the tunnel config) — abort the connect.
        const validation = validateWgConfig(config);
        if (!validation.ok) {
          throw new Error('Invalid WireGuard config: ' + validation.errors.join(', '));
        }
        if (validation.warnings && validation.warnings.length > 0) {
          log.warn('Config warnings: ' + validation.warnings.join(', '));
        }
        await wgService.writeConfig(WG_CONFIG_FILE, config);
        store.set('tunnel.configPath', WG_CONFIG_FILE);
        rememberInternalDns();
        log.info('Configuration updated from server');
      }
    }

    if (store.get('tunnel.killSwitch', false)) {
      await killSwitchSvc.enable(WG_CONFIG_FILE);
    }

    await wgService.connect(WG_CONFIG_FILE, store.get('tunnel.splitTunnel') ? store.get('tunnel.splitRoutes', '') : null);

    // Verify handshake before declaring connected — a stale config can
    // create the adapter successfully but never complete a handshake.
    let handshakeOk = false;
    for (let i = 0; i < 5; i++) {
      await new Promise(r => setTimeout(r, 2000));
      const stats = await wgService.getStats();
      if (stats?.handshake) {
        handshakeOk = true;
        break;
      }
      log.debug(`Waiting for handshake (${i + 1}/5)...`);
    }

    if (!handshakeOk) {
      await wgService.disconnect();
      throw new Error(t('error.noHandshake') || 'No WireGuard handshake — config may be invalid');
    }

    tunnelState.connected = true;
    tunnelState.connectedSince = new Date();

    updateTray('connected');
    broadcastState('connected');

    // ── Portal auto-open ─────────────────────────────────────
    async function refreshPortalUrl() {
      await apiClient.getPermissions();
      portalUrl = apiClient.portalUrl;
      autoOpenPortal = apiClient.autoOpenPortal;
      // ponytail: getPermissions() catches internally; on failure portalUrl retains prior value
      if (!portalUrl) log.warn('portal url fetch returned empty');
    }
    await refreshPortalUrl();
    if (!portalUrl) { await new Promise(r => setTimeout(r, 1500)); await refreshPortalUrl(); }
    updateTray('connected'); // refresh so portal tray item appears
    if (mainWindow) mainWindow.webContents.send('portal-url', portalUrl);
    const since = tunnelState.connectedSince ? tunnelState.connectedSince.getTime() : Date.now();
    // Auto-open only on a user-initiated connect. The reconnect loop uses a
    // separate path that never runs this block, so a reconnect can't re-open.
    if (shouldOpenPortal({ portalUrl, autoOpenPortal, connectedSince: since, lastOpenedSince: portalOpenedSince })) {
      portalOpenedSince = since;
      openPortalSafe();
    }

    if (connectionMonitor) connectionMonitor.start();

    notify(t('notify.connected'), { collapseKey: 'tunnel' });
    log.info('Tunnel connected successfully');

    // Report OS hostname for internal DNS resolution (best-effort).
    // Server rate-limits to 3/min/token; calling once on connect is
    // within budget and populates the admin UI automatically.
    // ApiClientPro extends ApiClient, so the static helper is inherited.
    try {
      const os = require('os');
      const sanitized = ApiClientPro.sanitizeHostnameForDns(os.hostname());
      if (sanitized && apiClient) {
        apiClient.reportHostname(sanitized).catch(() => { /* best-effort */ });
      }
    } catch (err) {
      log.debug('Hostname report skipped:', err.message);
    }

    // Install NRPT rule so Windows routes *.<domain> peer-hostname queries
    // to the VPN-internal dnsmasq. Without this, Windows fans the
    // query out to all configured resolvers and caches the NXDOMAIN
    // that a public resolver returns first — which was exactly why the
    // RDP cred-SSP target (desktop-xxx.gc.internal) previously failed
    // to resolve and mstsc fell back to the IP (SPN mismatch again).
    try {
      if (DnsPolicy && !dnsPolicy) dnsPolicy = new DnsPolicy(log);
      if (dnsPolicy) {
        // dnsPolicy.add() is idempotent across legacy rule comments
        // (pre-1.17 'GateControl' tag) — see client-core dns-policy.js.
        installPeerDnsRule().catch((e) =>
          log.debug('NRPT install failed:', e && e.message));
      }
    } catch (err) {
      log.debug('NRPT skipped:', err.message);
    }

  } catch (err) {
    log.error('Tunnel connection failed:', err.message);
    updateTray('disconnected');
    broadcastState('error', err.message);
    notify(err.message, { title: t('notify.connectionError'), collapseKey: 'tunnel' });
  }
}

// Internal DNS as the server reported it with the config: { domain, server },
// null (off), or unset for servers that do not say — kept for connects
// where the config cannot be fetched.
function rememberInternalDns() {
  if (apiClient && apiClient.internalDns !== undefined) store.set('tunnel.internalDns', apiClient.internalDns);
  else store.delete('tunnel.internalDns');
}

// Peer hostnames (<host>.<domain>) → the server's dnsmasq, with the domain and
// resolver of this server (client-core DnsPolicy.ruleFor), not fixed values.
async function installPeerDnsRule() {
  const rule = DnsPolicy.ruleFor({
    internalDns: store.get('tunnel.internalDns'),
    wgConfig: await wgService.readConfig(WG_CONFIG_FILE),
  });
  if (rule) await dnsPolicy.add(rule.namespace, rule.nameServer);
}

async function disconnectTunnel() {
  try {
    log.info('Disconnecting tunnel...');

    if (connectionMonitor) connectionMonitor.stop();

    // Strip NRPT rule first so a stale *.<domain> -> resolver pin
    // doesn't linger after the tunnel is torn down (would block DNS).
    if (dnsPolicy) {
      try { await dnsPolicy.removeAll(); } catch (e) { log.debug('NRPT cleanup:', e.message); }
    }

    await wgService.disconnect();

    if (killSwitchSvc.enabled || store.get('tunnel.killSwitch', false)) {
      await killSwitchSvc.disable();
    }

    tunnelState.connected = false;
    tunnelState.connectedSince = null;
    tunnelState.rxBytes = 0;
    tunnelState.txBytes = 0;

    // Reset portal only on real disconnect, not during a reconnect transient
    if (!isReconnecting) {
      portalOpenedSince = null;
      portalUrl = null;
      if (mainWindow) mainWindow.webContents.send('portal-url', null);
    }

    updateTray('disconnected');
    broadcastState('disconnected');

    notify(t('notify.disconnected'), { collapseKey: 'tunnel' });
    log.info('Tunnel disconnected');

  } catch (err) {
    log.error('Error disconnecting:', err.message);
    broadcastState('error', err.message);
  }
}

async function toggleKillSwitch(enabled) {
  if (enabled) {
    await killSwitchSvc.enable(WG_CONFIG_FILE);
  } else {
    await killSwitchSvc.disable();
  }
  store.set('tunnel.killSwitch', enabled);
}

async function toggleRdpAllow(enabled) {
  store.set('tunnel.rdpAllow', enabled);
  if (enabled) {
    await rdpAllowSvc.enable(WG_CONFIG_FILE);
  } else {
    await rdpAllowSvc.disable();
  }
  broadcastState(tunnelState.connected ? 'connected' : 'disconnected');
}

// Toast of a ready update. A click on it (or "Jetzt installieren") runs the
// same install as the tray entry; the notification center keeps the
// Notification referenced, so the click still arrives later.
function notifyUpdate(info) {
  const o = updateToast(info, { t, install: () => installUpdateFromToast(), productName: 'GateControl Pro' });
  notify(o.body, o);
}

// "Update erforderlich" notification, once per version and app session.
function notifyMandatoryUpdate(info) {
  if (!info?.version || mandatoryNotifiedVersion === info.version) return;
  mandatoryNotifiedVersion = info.version;
  notifyUpdate({ ...info, mandatory: true });
}

// Installs the update the updater has downloaded and verified. Relies on the
// updater's state, not on pendingUpdate: a manual "check for updates" stores
// the release info without an installer path, so "Neustart" in the toast and
// the tray entry used to do nothing.
// Core utils/update-install.js: the installer is re-hashed BEFORE the tunnel
// goes down (failure → the VPN stays), then the tunnel is disconnected and
// the kill switch lifted (the kill-switch preference stays and applies again
// on the next connect), then the installer starts and is watched for a
// moment; a failed start reconnects the tunnel and returns the reason
// ({ ok:false, code, message, vpnRestored }) for the update card. Only a
// running installer ends the app.
let runUpdateInstall = null;
async function installUpdate() {
  if (!runUpdateInstall) {
    runUpdateInstall = createUpdateInstaller({
      getUpdater: () => updater,
      log,
      isConnected: () => tunnelState.connected,
      disconnect: () => disconnectTunnel(),
      reconnect: async () => {
        await connectTunnel();
        if (!tunnelState.connected) throw new Error('Tunnel nicht verbunden');
      },
      liftFirewall: async () => {
        if (killSwitchSvc?.enabled) await killSwitchSvc.disable();
      },
      quit: () => quitApp(),
      // Not downloaded / verified yet: it is fetched first — say so.
      onStatus: (state, info) => {
        if (state !== 'downloading') return;
        notify(t('update.downloading', { version: info.version || '' }), { collapseKey: 'update', force: true });
      },
    });
  }
  return runUpdateInstall();
}

// Tray entry: no window shows the result, a failure becomes a notification.
function installUpdateFromTray({ ignoreBusy = false } = {}) {
  installUpdate().then((result) => {
    if (ignoreBusy && result?.code === 'busy') return;
    const text = installErrorText(result, t);
    if (!text) return;
    notify(text, { title: `GateControl Pro - ${t('update.installFailed')}`, collapseKey: 'update', force: true, onClick: () => showWindow() });
  }).catch((err) => log.error('Update-Installation fehlgeschlagen:', err.message));
}

// Update toast (click / button): same as the tray; a second click while it
// runs (e.g. still downloading) is no error.
function installUpdateFromToast() {
  log.info('Update-Toast angeklickt – starte Installation');
  installUpdateFromTray({ ignoreBusy: true });
}

// ── Services initialisieren ──────────────────────────────────
function initializeServices() {
  const serverUrl = store.get('server.url', '');
  const apiKey = store.get('server.apiKey', '');
  const peerId = store.get('server.peerId', '');

  apiClient = new ApiClientPro(serverUrl, apiKey, log, peerId, {
    clientVersion: require('../../package.json').version,
    clientType: 'pro',
  });

  // Nur signierte Updates: ohne echten Public Key bleibt der Updater aus.
  updater = new Updater({
    serverUrl, apiKey, log, clientType: 'pro', product: 'pro',
    publicKey: loadUpdatePublicKey({ appRoot: path.join(__dirname, '..', '..') }),
  });

  clientPolicy = new ClientPolicyService({
    apiClient, store, log,
    interval: store.get('app.configPollInterval', 300) * 1000,
  });
  // Heartbeat / permissions answers carry the server's policy version.
  apiClient.onPolicyVersion = (v) => { clientPolicy.noteVersion(v); };
  clientPolicy.onChange(() => { applyClientPolicy().catch((err) => log.warn('Client policy apply failed:', err.message)); });

  // Notification center: one push client + center for the app's lifetime
  // (apiClient.configure() changes URL/token in place, a server:setup resets
  // the center through the core IPC handlers).
  notifications = setupNotifications({
    app, store, log, apiClient,
    PushClient, NotificationCenter, notifyMenuItems,
    protocol: 'gatecontrol-pro',
    toastImagePath: path.join(RESOURCES_PATH, 'icons', 'app-icon.png'),
    showWindow: () => showWindow(),
    openPortal: (portalPath) => openPortalSafe(portalPath),
    isTunnelUp: () => tunnelState.connected,
    isKillSwitchActive: () => !!(killSwitchSvc?.enabled || store.get('tunnel.killSwitch', false)),
    getWgConfigPath: () => store.get('tunnel.configPath', '') || WG_CONFIG_FILE,
    // E2E runs must not register a URL handler on the test machine.
    registerProtocol: !e2e,
    onChange: () => updateTray(trayState),
  });

  // Chats: messenger on the same push stream, chat toasts with reply field.
  chats = setupMessenger({
    store, log, apiClient, notifications,
    MessengerService, ChatNotifier,
    protocol: 'gatecontrol-pro',
    toastImagePath: path.join(RESOURCES_PATH, 'icons', 'app-icon.png'),
    dataDir: app.getPath('userData'),
    tmpDir: app.getPath('temp'),
    showWindow: () => showWindow(),
    getMainWindow: () => mainWindow,
    onChange: () => updateTray(trayState),
  });

  // Schule: shown while the server lists the plugin; its toasts open the page.
  school = SchoolService ? new SchoolService({
    apiClient, log,
    notificationCenter: notifications?.notificationCenter,
    pushClient: notifications?.pushClient,
  }) : null;

  // Vault: shown while the server lists the plugin. Keys and decrypted entries
  // stay in this process while unlocked; the offline copy is ciphertext only;
  // "Angemeldet bleiben" keeps the user key under DPAPI (safeStorage);
  // "Mit Windows Hello entsperren" wraps it under a Windows Hello signature
  // (core services/windows-hello.js, WinRT via koffi; core docs/vault.md).
  vault = VaultService ? new VaultService({
    apiClient,
    dir: path.join(app.getPath('userData'), 'vault'),
    protect: VaultService.safeStorageProtect(safeStorage),
    clipboard,
    notificationCenter: notifications?.notificationCenter,
    pushClient: notifications?.pushClient,
    powerMonitor,
    hello: windowsHello ? windowsHello.createWindowsHello({ log }) : null,
    helloName: 'GateControl Pro Vault',
    log,
  }) : null;
  vaultQuick = vault && setupVaultQuick ? setupVaultQuick({
    BrowserWindow, globalShortcut, screen, ipcMain, vault, log,
    preload: path.join(__dirname, 'vault-quick-preload.js'),
    html: path.join(__dirname, '..', 'renderer', 'vault-quick.html'),
    getTheme: () => resolvedAppTheme(),
    getLocale: () => getLocale(),
    isMainVisible: () => !!mainWindow && !mainWindow.isDestroyed() && mainWindow.isVisible() && !mainWindow.isMinimized(),
  }) : null;
  // E2E runs open the quick search without the global shortcut.
  if (e2e) e2e.vaultQuick = vaultQuick;

  // GateDrop: shown while the server lists the plugin; receives into
  // Downloads\GateControl, listens on TCP 47731 in private networks.
  gatedrop = GateDropService && setupGateDrop ? setupGateDrop({
    app, store, log, apiClient, notifications,
    GateDropService, gatedropShell,
    // Windows Firewall check / repair of the inbound rule (not in e2e runs:
    // they must not touch the firewall of the test machine).
    GateDropFirewall: e2e ? null : GateDropFirewall,
    edition: 'pro',
    shell, clipboard, dialog, t,
    protocol: 'gatecontrol-pro',
    toastImagePath: path.join(RESOURCES_PATH, 'icons', 'app-icon.png'),
    showWindow: () => showWindow(),
    getMainWindow: () => mainWindow,
    // E2E runs must not touch the SendTo folder of the test machine.
    manageShortcut: !e2e,
    onChange: () => updateTray(trayState),
  }) : null;

  wgService = new WireGuardService(log, { resourcesPath: RESOURCES_PATH });
  killSwitchSvc = new KillSwitch(log, { edition: 'pro' });
  rdpAllowSvc = new RdpAllowSvc(log, { edition: 'pro' });

  rdpManager = new RdpManager({
    apiClient,
    log,
    store,
    getTunnelState: () => tunnelState,
    getPeerInfo: () => apiClient.getPeerInfo(),
  });

  rdpWolClient = new RdpWolClient({ apiClient, log });

  connectionMonitor = new ConnectionMonitor({
    interval: store.get('app.checkInterval', 30) * 1000,
    apiClient,
    onDisconnect: async () => {
      if (isReconnecting) return;
      isReconnecting = true;
      log.warn('Connection lost, attempting reconnect...');
      tunnelState.connected = false;
      updateTray('connecting');
      broadcastState('reconnecting');

      const maxRetries = 10;
      const splitRoutes = store.get('tunnel.splitTunnel') ? store.get('tunnel.splitRoutes', '') : null;
      for (let i = 0; i < maxRetries; i++) {
        await new Promise(r => setTimeout(r, reconnectDelay(i)));
        log.info(`Reconnect attempt ${i + 1}/${maxRetries}...`);
        try {
          await wgService.disconnect().catch(() => {});
          await wgService.connect(WG_CONFIG_FILE, splitRoutes);
          tunnelState.connected = true;
          tunnelState.connectedSince = new Date();
          isReconnecting = false;
          updateTray('connected');
          broadcastState('connected');
          // Restore the portal button/tray after a reconnect, but do NOT
          // auto-open (FORK B: only user-initiated connects open the browser).
          if (mainWindow) mainWindow.webContents.send('portal-url', portalUrl);
          connectionMonitor.start();
          notify(t('notify.reconnected'), { collapseKey: 'tunnel' });
          log.info('Reconnect successful');
          return;
        } catch (err) {
          log.warn(`Reconnect attempt ${i + 1} failed: ${err.message}`);
        }
      }

      isReconnecting = false;
      updateTray('disconnected');
      broadcastState('error', t('notify.reconnectFailed'));
      notify(t('notify.reconnectFailed'), { collapseKey: 'tunnel', force: true });
      log.error('All reconnect attempts failed');
    },
    onPeerDisabled: async (peerInfo) => {
      log.warn(`Peer disabled on server (id: ${peerInfo?.id}, name: ${peerInfo?.name}) — disconnecting`);
      await disconnectTunnel();
      notify(t('notify.peerDisabled'), { collapseKey: 'tunnel', force: true });
    },
    onStats: (stats) => {
      const now = Date.now();
      const rx = stats.rxBytes || 0;
      const tx = stats.txBytes || 0;

      if (lastStatsTime > 0 && now > lastStatsTime) {
        const dt = (now - lastStatsTime) / 1000;
        tunnelState.rxSpeed = Math.max(0, (rx - lastRxBytes) / dt);
        tunnelState.txSpeed = Math.max(0, (tx - lastTxBytes) / dt);
      }

      lastRxBytes = rx;
      lastTxBytes = tx;
      lastStatsTime = now;
      tunnelState.rxBytes = rx;
      tunnelState.txBytes = tx;
      tunnelState.handshake = stats.handshake || null;
      tunnelState.handshakeTimestamp = stats.handshakeTimestamp || null;
      broadcastState('connected');
    },
    // Admin asked for a support bundle → ask the user (core sender).
    onSupportBundleRequest: (request) => supportBundle?.onServerRequest(request),
    wgService,
    log,
  });

  // Control events of the push stream (core PushControl): policy changes,
  // support-bundle requests, peer disabled and config changes arrive by push;
  // the policy (30 min) and peer-info (15 min) polls stay as the fallback.
  notifications.attachControl({
    PushControl,
    clientPolicy,
    connectionMonitor,
    onConfigChanged: () => applyServerConfigChange(),
  });

  // Forward RDP events to renderer
  rdpManager.on('session-start', (data) => {
    mainWindow?.webContents.send('rdp:session-start', data);
    updateTray(tunnelState.connected ? 'connected' : 'disconnected');
  });

  rdpManager.on('session-end', (data) => {
    mainWindow?.webContents.send('rdp:session-end', data);
    rdpManager.refreshServices();
    updateTray(tunnelState.connected ? 'connected' : 'disconnected');
  });

  rdpManager.on('session-error', (data) => {
    mainWindow?.webContents.send('rdp:session-error', data);
  });

  rdpManager.on('progress', (data) => {
    mainWindow?.webContents.send('rdp:progress', data);
  });

  rdpManager.on('services-update', (services) => {
    mainWindow?.webContents.send('rdp:services-update', services);
  });

  rdpManager.on('session-timeout-warning', (data) => {
    mainWindow?.webContents.send('rdp:session-timeout-warning', data);
    notify(t('rdp.sessionTimeout', { routeId: data.routeId, minutes: Math.round(data.gracePeriod / 60) }), {
      collapseKey: `rdp-timeout:${data.routeId}`, force: true,
    });
  });

  // Initialize locale from config, fallback to system locale
  const savedLocale = store.get('app.locale');
  if (savedLocale) {
    setLocale(savedLocale);
  } else {
    setLocale(resolveLocale(app.getLocale()));
  }
}

// ── IPC Handlers ─────────────────────────────────────────────
// Autostart via Task Scheduler (requireAdministrator: login items would not
// start the app elevated). Task from a task XML: no 3-day limit, runs on
// battery, normal priority (src/main/autostart.js).
const setAutostartTask = createAutostart({
  autostartTask,
  execFile: execFileAsync,
  getExePath: () => app.getPath('exe'),
  getTempPath: () => app.getPath('temp'),
  log,
});

// Which DNS server does the system use right now?
async function checkSystemDns() {
  try {
    const connected = tunnelState.connected;
    const ksActive = killSwitchSvc?.enabled || false;

    let dnsServer = null;
    let resolveOk = false;
    try {
      const { stdout } = await execFileAsync('nslookup', ['cloudflare.com'], { timeout: 5000 });
      const match = stdout.match(/Address:\s*([\d.]+)/);
      if (match) dnsServer = match[1];
      resolveOk = stdout.includes('Name:') || stdout.includes('Addresses:');
    } catch {
      resolveOk = false;
    }

    return { connected, killSwitch: ksActive, dnsServer, resolveOk };
  } catch (err) {
    log.warn('DNS system check failed:', err.message);
    return { connected: false, killSwitch: false, dnsServer: null, resolveOk: false };
  }
}

// Common channels come from the hardened core handlers (config:set allowlist,
// validated config imports, setup codes incl. setup QR, https-only server
// setup, http(s)-only shell:open-external); Pro adds/overrides the rest.
function registerIpcHandlers() {
  const ctx = {
    app,
    dialog,
    getMainWindow: () => mainWindow,
    store,
    wgService,
    apiClient,
    ApiClientClass: ApiClientPro,
    killSwitch: killSwitchSvc,
    clientPolicy,
    getUpdater: () => updater,
    log,
    connectTunnel,
    disconnectTunnel,
    toggleKillSwitch: async (enabled) => {
      try {
        await toggleKillSwitch(enabled === true);
      } catch (err) {
        log.error('Kill-switch failed:', err.message);
        notify(`Kill-Switch: ${err.message}`, { force: true });
      }
      // UI auf den tatsächlichen Zustand zurücksetzen (auch nach Fehler)
      broadcastState(tunnelState.connected ? 'connected' : 'disconnected');
    },
    toggleRdpAllow: async (enabled) => {
      try {
        await toggleRdpAllow(enabled === true);
      } catch (err) {
        log.error('RDP Allow failed:', err.message);
      }
    },
    installUpdate: async () => installUpdate(),
    // portal:open, optionally { next: '/portal#<tab>' } (validated by core)
    openPortal: (opts) => openPortalSafe(opts),
    getTunnelState: () => tunnelState,
    wgConfigFile: WG_CONFIG_FILE,
    setLocale,
    getLocale,
    onLocaleChanged: (locale) => {
      updateTray(tunnelState.connected ? 'connected' : 'disconnected');
      mainWindow?.webContents.send('locale:changed', locale);
    },
    checkSystemDns,
    setAutostart: setAutostartTask,
    rdpManager,
    rdpWolClient,
    setRdpPanelOpen: (open) => { rdpPanelOpen = open; },
    getMachineFingerprint,
    edition: 'pro',
    // notify:* channels + events, reset on server:setup (core, opt-in)
    notificationCenter: notifications?.notificationCenter,
    // chat:* channels + events, reset on server:setup (core, opt-in)
    messenger: chats?.messenger,
    chatNotifier: chats?.chatNotifier,
    // school:* channels + events, reset on server:setup (core, opt-in)
    school,
    // vault:* channels + events, reset on server:setup (core, opt-in)
    vault,
    // gatedrop:* channels + events, reset on server:setup (core, opt-in)
    gatedrop: gatedrop?.service,
    gatedropExplorer: gatedrop?.explorer,
    // Result of a bundle the admin requested (the button shows its own toast).
    onSupportResult: (res) => {
      if (!res || res.cancelled) return;
      notify(res.success ? t('support.success') : res.error, { force: true });
    },
  };
  // One sender for the Settings button and admin requests (connection monitor).
  // The bundle carries the short device ID (client.deviceId) for the admin.
  supportBundle = createSupportBundleSender(ctx, {
    collect: withDeviceId(collectSupportBundle, () => shortDeviceId(getMachineFingerprint, log)),
  });
  registerProIpc(ipcMain, { ...ctx, supportBundle });
}

// ── App Lifecycle ────────────────────────────────────────────
app.on('ready', () => {
  // Windows toasts (and their buttons) belong to the AppUserModelID of the
  // Start-menu shortcut, which electron-builder sets to build.appId.
  app.setAppUserModelId('com.gatecontrol.client-pro');
  initializeServices();

  // Ältere Versionen haben mstsc global die Zertifikatswarnung abgewöhnt
  // (AuthenticationLevelOverride) und ein selbstsigniertes Code-Signing-
  // Zertifikat in CurrentUser\Root installiert. Beides wird einmalig
  // zurückgebaut (nur was GateControl selbst angelegt hat).
  runRdpTrustMigration({
    store,
    log,
    userDataDir: app.getPath('userData'),
  }).catch(err => log.warn('RDP trust migration failed:', err.message));

  // Reste eines Absturzes (Regeln + Block-Policy) entfernen, bevor
  // irgendetwas verbindet; connectTunnel aktiviert den Kill-Switch neu.
  const killSwitchRecovery = recoverKillSwitch({ killSwitch: killSwitchSvc, store, wgService, log });

  // RDP-Freigabe mit der Einstellung abgleichen (verwaiste Regel nach
  // Absturz entfernen bzw. Regel wiederherstellen). Die alte gemeinsame
  // Regel GateControl_RDP_Allow_In_3389 entfernt der Core nur, wenn die
  // Community-Edition weder installiert ist noch laeuft.
  const rdpWanted = store.get('tunnel.rdpAllow', false);
  rdpAllowSvc.reconcile({ wanted: rdpWanted, configPath: WG_CONFIG_FILE })
    .then((active) => { if (rdpWanted && !active) store.set('tunnel.rdpAllow', false); })
    .catch(err => log.warn('RDP allow reconcile failed:', err.message));
  // Last known client policy first (works offline), then ask the server.
  applyClientPolicy({ startup: true }).catch((err) => log.warn('Client policy apply failed:', err.message));
  clientPolicy.start();

  // Always-on policy: bring the tunnel back when it is down (e.g. after the
  // reconnect loop gave up). Checked once a minute.
  let alwaysOnAttempt = null;
  setInterval(() => {
    if (clientPolicy.getPolicy().autoConnect !== 'always_on') return;
    if (tunnelState.connected || isReconnecting || alwaysOnAttempt) return;
    if (!(store.get('server.url', '') && store.get('server.apiKey', ''))) return;
    log.info('Always-on policy: tunnel is down, reconnecting');
    alwaysOnAttempt = connectTunnel().catch(() => {}).finally(() => { alwaysOnAttempt = null; });
  }, 60 * 1000).unref?.();

  registerIpcHandlers();
  createWindow();
  createTray();

  // Push stream (no-op while switched off or without a server).
  notifications.start();
  // Started by a toast button while the app was not running: the URL is in
  // argv; its one-time token is unknown to this process, so the inbox opens.
  if (notifications.handleArgv(process.argv)) log.info('Started from a notification');
  // Chats: availability check, live events, chat toasts.
  chats.start();
  // Schule: availability check, push → page.
  school?.start();
  // Vault: availability, sync, auto-lock; Strg+Alt+P while the server offers it.
  vault?.start();
  vaultQuick?.start();
  // GateDrop: availability, presence, LAN listener; started by
  // "Senden an → GateDrop" → the send dialog opens once the window is ready.
  gatedrop?.start();
  if (gatedrop?.handleArgv(process.argv)) log.info('Started from "Senden an → GateDrop"');

  // Autostart mit Windows synchronisieren (Task Scheduler; nicht im E2E-Test)
  if (!e2e && store.get('app.startWithWindows', true)) {
    setAutostartTask(true).catch(err => log.warn('Autostart sync failed:', err.message));
  } else if (!e2e && clientPolicy.getPolicy().autostart === 'forbidden') {
    setAutostartTask(false).catch(() => { /* task did not exist */ });
  }

  // Auto-Connect (Server-URL reicht, configPath nicht zwingend nötig)
  const hasServer = store.get('server.url', '') && store.get('server.apiKey', '');
  const hasConfig = !!store.get('tunnel.configPath', '');
  if (store.get('tunnel.autoConnect', true) && (hasServer || hasConfig)) {
    log.info(`Auto-Connect: server=${!!hasServer}, configPath=${hasConfig}`);
    const MAX_RETRIES = 5;
    const RETRY_DELAY = 5000;
    const attemptAutoConnect = async (attempt = 1) => {
      log.info(`Auto-Connect Versuch ${attempt}/${MAX_RETRIES}...`);
      await killSwitchRecovery;
      try {
        await connectTunnel();
        if (!tunnelState.connected) {
          throw new Error('Tunnel nicht verbunden nach connectTunnel()');
        }
      } catch (err) {
        log.error(`Auto-connect attempt ${attempt} failed: ${err.message}`);
        if (attempt < MAX_RETRIES) {
          setTimeout(() => attemptAutoConnect(attempt + 1), RETRY_DELAY);
        } else {
          log.error('Auto-connect permanently failed after all attempts');
          broadcastState('error', 'Auto-connect failed — please connect manually.');
        }
      }
    };
    if (mainWindow) {
      mainWindow.webContents.once('did-finish-load', () => attemptAutoConnect());
    } else {
      attemptAutoConnect();
    }
  } else {
    log.info(`Auto-connect skipped: autoConnect=${store.get('tunnel.autoConnect', true)}, server=${!!hasServer}, configPath=${hasConfig}`);
  }

  // Auto-Update (the updater exists from initializeServices on, so a setup
  // done later — e.g. with a setup code — configures it; checks without a
  // server are skipped by the updater itself)
  // Mandatory updates (server: below the minimum version) are never
  // installed automatically: the installer ends the app and the tunnel, so the
  // user starts it (banner, sidebar card, tray). The notice cannot be
  // dismissed and is shown again on every start while it is still required.
  if (updater) {
    updater.start((release) => {
      pendingUpdate = release;
      log.info(`Update ready: v${release.version}${release.mandatory ? ' (mandatory)' : ''}`);
      updateTray(tunnelState.connected ? 'connected' : 'disconnected');
      if (mainWindow) {
        mainWindow.webContents.send('update:ready', release);
      }
      if (release.mandatory) {
        notifyMandatoryUpdate(release);
      } else {
        notifyUpdate(release);
      }
    }, {
      onPolicyChange: (policy) => {
        if (mainWindow) mainWindow.webContents.send('update:policy', policy);
        updateTray(tunnelState.connected ? 'connected' : 'disconnected');
        if (policy.mandatory && pendingUpdate) {
          notifyMandatoryUpdate({ version: policy.version, minVersion: policy.minVersion });
        }
      },
    });
  }
});

// A second start (shortcut, autostart, or a toast button: <protocol>://notify/…)
// only brings this instance to the front or performs the toast action.
app.on('second-instance', (_event, argv) => {
  // "Senden an → GateDrop" (Explorer): open the send dialog with the files.
  if (gatedrop?.handleArgv(argv)) return;
  if (notifications?.handleArgv(argv)) return;
  showWindow();
});

// Firewall-Regeln beim Beenden entfernen. Electron wartet nicht auf async
// 'will-quit'-Handler — deshalb wird das Beenden einmal angehalten, bis
// Kill-Switch/RDP-Allow aufgeräumt sind (mit Zeitlimit). Die
// Kill-Switch-Einstellung bleibt erhalten; schlägt das Aufräumen fehl,
// erledigt es der nächste Start (Zustandsdatei im userData).
let quitCleanupDone = false;
async function releaseFirewallOnQuit() {
  if (killSwitchSvc?.enabled) {
    try {
      await killSwitchSvc.disable();
    } catch (err) {
      log.error('Kill-switch could not be disabled on quit:', err.message);
    }
  }
  if (rdpAllowSvc?.enabled) {
    try {
      await rdpAllowSvc.disable();
      store.set('tunnel.rdpAllow', false);
    } catch (err) {
      log.error('RDP allow could not be disabled on quit:', err.message);
    }
  }
}

app.on('before-quit', (e) => {
  app.isQuitting = true;
  if (quitCleanupDone) return;
  quitCleanupDone = true;

  // Close the push stream (flushes pending delivery confirmations).
  notifications?.stop();
  // Chats: save the cache, leave the open chat.
  chats?.stop();
  school?.stop();
  // Vault: forget the keys, stop timers, release Strg+Alt+P.
  vaultQuick?.stop();
  vault?.lock('quit');
  vault?.stop();
  // GateDrop: LAN listener and timers.
  gatedrop?.stop();

  // Critical: cleanup all RDP sessions
  if (rdpManager) {
    rdpManager.cleanupAll();
  }

  if (!killSwitchSvc?.enabled && !rdpAllowSvc?.enabled) return;
  e.preventDefault();
  const timeout = new Promise((resolve) => setTimeout(resolve, 15000));
  Promise.race([releaseFirewallOnQuit(), timeout]).finally(() => app.quit());
});
