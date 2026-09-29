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

// Pure tunnel/portal decision logic (unit-tested in test/tunnel-logic.test.js).
const { reconnectDelay, shouldOpenPortal } = require('./tunnel-logic');

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

let app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, dialog, Notification, screen;
let Store, log, validateWgConfig, registerProIpc, WireGuardService, KillSwitch, RdpAllowSvc, ApiClientPro, Updater, ConnectionMonitor, DnsPolicy, RdpManager, RdpSigner, RdpWolClient;

try {
  writeCrashLog('IMPORT', 'Loading electron...');
  ({ app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, dialog, Notification, screen } = require('electron'));

  writeCrashLog('IMPORT', 'Loading electron-store...');
  Store = require('electron-store');

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
  ConnectionMonitor = require('@gatecontrol/client-core/src/services/connection-monitor');
  DnsPolicy = require('@gatecontrol/client-core/src/services/dns-policy');
  RdpManager = require('../services/rdp/rdp-manager');
  RdpSigner = require('../services/rdp/rdp-signer');
  RdpWolClient = require('../services/rdp/rdp-wol');
  ({ registerProIpc } = require('./ipc-pro'));

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

// ── Konfiguration ────────────────────────────────────────────
const crypto = require('crypto');
const fsSync = require('fs');
const { execFile: _execFile } = require('child_process');
const { promisify: _promisify } = require('util');
const execFileAsync = _promisify(_execFile);

const keyStore = new (require('electron-store'))({ name: 'gatecontrol-pro-keyfile', encryptionKey: 'gc-pro-bootstrap' });

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

const store = new Store({
  name: 'gatecontrol-pro-config',
  encryptionKey: keyStore.get('machineKey'),
  schema: {
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
  },
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
let rdpManager = null;
let rdpWolClient = null;
let pendingUpdate = null;

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
function openPortalSafe() {
  if (portalUrl && /^https:\/\//i.test(portalUrl)) {
    require('electron').shell.openExternal(portalUrl).catch(() => {});
  }
}

function formatBytesShort(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

// ── Tray Icon (Sun/Star design — circle + 8 rays) ───────────
function getIcon(state) {
  const color = state === 'connected' ? [0x22, 0xC5, 0x5E]   // green
    : state === 'connecting' ? [0xF5, 0x9E, 0x0B]             // amber
    : [0xEF, 0x44, 0x44];                                      // red

  const size = 32;
  const buf = Buffer.alloc(size * size * 4, 0); // transparent RGBA
  const cx = size / 2;
  const cy = size / 2;

  function setPixel(px, py) {
    const x = Math.round(px);
    const y = Math.round(py);
    if (x < 0 || x >= size || y < 0 || y >= size) return;
    const i = (y * size + x) * 4;
    buf[i] = color[0]; buf[i + 1] = color[1]; buf[i + 2] = color[2]; buf[i + 3] = 255;
  }

  function setPixelAA(px, py, alpha) {
    const x = Math.round(px);
    const y = Math.round(py);
    if (x < 0 || x >= size || y < 0 || y >= size) return;
    const i = (y * size + x) * 4;
    if (buf[i + 3] >= alpha) return; // don't overwrite stronger pixel
    buf[i] = color[0]; buf[i + 1] = color[1]; buf[i + 2] = color[2]; buf[i + 3] = alpha;
  }

  // Draw ring (outer circle)
  const ringR = 5.0;
  const ringThick = 1.8;
  for (let a = 0; a < 360; a += 1) {
    const rad = a * Math.PI / 180;
    for (let t = -ringThick / 2; t <= ringThick / 2; t += 0.4) {
      setPixel(cx + (ringR + t) * Math.cos(rad), cy + (ringR + t) * Math.sin(rad));
    }
  }

  // Center dot
  for (let dx = -1.5; dx <= 1.5; dx += 0.5) {
    for (let dy = -1.5; dy <= 1.5; dy += 0.5) {
      if (dx * dx + dy * dy <= 2.0) setPixel(cx + dx, cy + dy);
    }
  }

  // 8 rays
  const rayInner = 8.5;
  const rayOuter = 13.5;
  const rayThick = 2.0;
  for (let i = 0; i < 8; i++) {
    const angle = i * 45 * Math.PI / 180;
    const cos = Math.cos(angle);
    const sin = Math.sin(angle);
    const perpCos = Math.cos(angle + Math.PI / 2);
    const perpSin = Math.sin(angle + Math.PI / 2);
    for (let d = rayInner; d <= rayOuter; d += 0.3) {
      for (let t = -rayThick / 2; t <= rayThick / 2; t += 0.4) {
        setPixel(cx + d * cos + t * perpCos, cy + d * sin + t * perpSin);
      }
    }
    // Rounded ray ends
    for (let dx = -rayThick / 2; dx <= rayThick / 2; dx += 0.4) {
      for (let dy = -rayThick / 2; dy <= rayThick / 2; dy += 0.4) {
        if (dx * dx + dy * dy <= (rayThick / 2) * (rayThick / 2)) {
          // Inner cap
          setPixel(cx + rayInner * cos + dx * perpCos + dy * cos, cy + rayInner * sin + dx * perpSin + dy * sin);
          // Outer cap
          setPixel(cx + rayOuter * cos + dx * perpCos + dy * cos, cy + rayOuter * sin + dx * perpSin + dy * sin);
        }
      }
    }
  }

  return nativeImage.createFromBuffer(buf, { width: size, height: size });
}

function updateTray(connState) {
  if (!tray) return;

  tray.setImage(getIcon(connState));

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

  tray.setToolTip(tooltip);

  // Build context menu with RDP status
  const rdpSessions = rdpManager ? rdpManager.getActiveSessions() : [];

  const contextMenu = Menu.buildFromTemplate([
    { label: `GateControl Pro - ${statusText}`, enabled: false, icon: getIcon(connState) },
    { type: 'separator' },
    {
      label: connState === 'connected' ? t('action.disconnect') : t('action.connect'),
      click: () => connState === 'connected' ? disconnectTunnel() : connectTunnel(),
    },
    { type: 'separator' },
    {
      label: t('killswitch.label'),
      type: 'checkbox',
      checked: store.get('tunnel.killSwitch', false),
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
    ...(pendingUpdate ? [
      { type: 'separator' },
      { label: t('tray.installUpdate', { version: pendingUpdate.version }), click: () => installUpdate() },
    ] : []),
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
          new Notification({ title: 'GateControl Pro', body: t('tray.noUpdateAvailable') }).show();
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

    new Notification({ title: 'GateControl Pro', body: t('notify.connected') }).show();
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

    // Install NRPT rule so Windows routes *.gc.internal queries to the
    // VPN-internal dnsmasq on 10.8.0.1. Without this, Windows fans the
    // query out to all configured resolvers and caches the NXDOMAIN
    // that a public resolver returns first — which was exactly why the
    // RDP cred-SSP target (desktop-xxx.gc.internal) previously failed
    // to resolve and mstsc fell back to the IP (SPN mismatch again).
    try {
      if (DnsPolicy && !dnsPolicy) dnsPolicy = new DnsPolicy(log);
      if (dnsPolicy) {
        // Keep the namespace hardcoded to match the server default.
        // If we later expose the domain via the config API, plug it
        // in here; for now it matches GC_DNS_DOMAIN's default.
        // dnsPolicy.add() is now idempotent across legacy rule comments
        // (pre-1.17 'GateControl' tag) — see client-core dns-policy.js.
        dnsPolicy.add('.gc.internal', '10.8.0.1').catch((e) =>
          log.debug('NRPT install failed:', e && e.message));
      }
    } catch (err) {
      log.debug('NRPT skipped:', err.message);
    }

  } catch (err) {
    log.error('Tunnel connection failed:', err.message);
    updateTray('disconnected');
    broadcastState('error', err.message);
    new Notification({ title: t('notify.connectionError'), body: err.message }).show();
  }
}

async function disconnectTunnel() {
  try {
    log.info('Disconnecting tunnel...');

    if (connectionMonitor) connectionMonitor.stop();

    // Strip NRPT rule first so a stale *.gc.internal -> 10.8.0.1 pin
    // doesn't linger after the tunnel is torn down (would block DNS).
    if (dnsPolicy) {
      try { await dnsPolicy.removeAll(); } catch (e) { log.debug('NRPT cleanup:', e.message); }
    }

    await wgService.disconnect();

    if (store.get('tunnel.killSwitch', false)) {
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

    new Notification({ title: 'GateControl Pro', body: t('notify.disconnected') }).show();
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

function installUpdate() {
  if (pendingUpdate?.installerPath) {
    const { shell } = require('electron');
    shell.openPath(pendingUpdate.installerPath);
    setTimeout(() => app.quit(), 1000);
  }
}

// ── Services initialisieren ──────────────────────────────────
function initializeServices() {
  const serverUrl = store.get('server.url', '');
  const apiKey = store.get('server.apiKey', '');
  const peerId = store.get('server.peerId', '');

  apiClient = new ApiClientPro(serverUrl, apiKey, log, peerId, {
    clientVersion: require('../../package.json').version,
  });

  updater = new Updater({ serverUrl, apiKey, log, clientType: 'pro' });

  wgService = new WireGuardService(log, { resourcesPath: RESOURCES_PATH });
  killSwitchSvc = new KillSwitch(log);
  rdpAllowSvc = new RdpAllowSvc(log);

  const rdpSigner = process.platform === 'win32'
    ? new RdpSigner({
        log,
        certDir: path.join(app.getPath('userData'), 'rdp-signing'),
      })
    : null;

  rdpManager = new RdpManager({
    apiClient,
    log,
    store,
    getTunnelState: () => tunnelState,
    getPeerInfo: () => apiClient.getPeerInfo(),
    signer: rdpSigner,
  });

  // One-time UI notice when rdpsign.exe is missing on this machine and
  // can't be auto-restored from WinSxS. Delivered via Notification (so
  // the user sees it even with the window minimized) AND IPC (so the
  // renderer can show an inline hint in the RDP view if it wants to).
  rdpManager.on('signing-unavailable', (data) => {
    log.warn(`RDP signing unavailable on this machine (${data?.reason || 'unknown'})`);
    try {
      new Notification({
        title: 'GateControl Pro',
        body: t('notify.rdpSigningUnavailable'),
      }).show();
    } catch (err) {
      log.debug('Failed to show signing-unavailable notification:', err.message);
    }
    if (mainWindow && mainWindow.webContents) {
      mainWindow.webContents.send('rdp:signing-unavailable', data);
    }
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
          new Notification({ title: 'GateControl Pro', body: t('notify.reconnected') }).show();
          log.info('Reconnect successful');
          return;
        } catch (err) {
          log.warn(`Reconnect attempt ${i + 1} failed: ${err.message}`);
        }
      }

      isReconnecting = false;
      updateTray('disconnected');
      broadcastState('error', t('notify.reconnectFailed'));
      new Notification({ title: 'GateControl Pro', body: t('notify.reconnectFailed') }).show();
      log.error('All reconnect attempts failed');
    },
    onPeerDisabled: async (peerInfo) => {
      log.warn(`Peer disabled on server (id: ${peerInfo?.id}, name: ${peerInfo?.name}) — disconnecting`);
      await disconnectTunnel();
      new Notification({
        title: 'GateControl Pro',
        body: t('notify.peerDisabled'),
      }).show();
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
      broadcastState('connected');
    },
    wgService,
    log,
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
    new Notification({
      title: 'GateControl Pro',
      body: t('rdp.sessionTimeout', { routeId: data.routeId, minutes: Math.round(data.gracePeriod / 60) }),
    }).show();
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
const AUTOSTART_TASK = 'GateControlProAutostart';

// Autostart via Task Scheduler (requireAdministrator: login items would not
// start the app elevated).
async function setAutostartTask(enabled) {
  if (enabled) {
    const exePath = app.getPath('exe');
    await execFileAsync('schtasks', [
      '/Create', '/F',
      '/TN', AUTOSTART_TASK,
      '/TR', `"${exePath}"`,
      '/SC', 'ONLOGON',
      '/RL', 'HIGHEST',
      '/DELAY', '0000:10',
    ]);
    log.info(`Autostart enabled: ${exePath}`);
  } else {
    await execFileAsync('schtasks', ['/Delete', '/F', '/TN', AUTOSTART_TASK]);
    log.info('Autostart disabled');
  }
}

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
  registerProIpc(ipcMain, {
    app,
    dialog,
    getMainWindow: () => mainWindow,
    store,
    wgService,
    apiClient,
    ApiClientClass: ApiClientPro,
    killSwitch: killSwitchSvc,
    getUpdater: () => updater,
    log,
    connectTunnel,
    disconnectTunnel,
    toggleKillSwitch: async (enabled) => {
      try {
        await toggleKillSwitch(enabled === true);
      } catch (err) {
        log.error('Kill-switch failed:', err.message);
      }
    },
    toggleRdpAllow: async (enabled) => {
      try {
        await toggleRdpAllow(enabled === true);
      } catch (err) {
        log.error('RDP Allow failed:', err.message);
      }
    },
    installUpdate: async () => installUpdate(),
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
  });
}

// ── App Lifecycle ────────────────────────────────────────────
app.on('ready', () => {
  initializeServices();
  registerIpcHandlers();
  createWindow();
  createTray();

  // Autostart mit Windows synchronisieren (Task Scheduler)
  if (store.get('app.startWithWindows', true)) {
    setAutostartTask(true).catch(err => log.warn('Autostart sync failed:', err.message));
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
  if (updater) {
    updater.start((release) => {
      pendingUpdate = release;
      log.info(`Update ready: v${release.version}`);
      updateTray(tunnelState.connected ? 'connected' : 'disconnected');
      if (mainWindow) {
        mainWindow.webContents.send('update:ready', release);
      }
      new Notification({
        title: 'GateControl Pro',
        body: t('update.available', { version: release.version }),
      }).show();
    });
  }
});

app.on('second-instance', () => showWindow());

app.on('before-quit', () => {
  app.isQuitting = true;

  // Critical: cleanup all RDP sessions
  if (rdpManager) {
    rdpManager.cleanupAll();
  }
});

app.on('will-quit', async () => {
  if (killSwitchSvc) await killSwitchSvc.disable();
  if (rdpAllowSvc?.enabled) {
    await rdpAllowSvc.disable().catch(() => {});
    store.set('tunnel.rdpAllow', false);
  }
});
