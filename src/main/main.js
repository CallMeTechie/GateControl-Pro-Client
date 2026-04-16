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

let app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, dialog, Notification, screen;
let Store, log, WireGuardService, KillSwitch, RdpAllowSvc, ApiClientPro, Updater, ConnectionMonitor, RdpManager, RdpWolClient;

try {
  writeCrashLog('IMPORT', 'Loading electron...');
  ({ app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, dialog, Notification, screen } = require('electron'));

  writeCrashLog('IMPORT', 'Loading electron-store...');
  Store = require('electron-store');

  writeCrashLog('IMPORT', 'Loading electron-log...');
  log = require('electron-log');

  writeCrashLog('IMPORT', 'Loading core services...');
  WireGuardService = require('@gatecontrol/client-core/src/services/wireguard-native');
  KillSwitch = require('@gatecontrol/client-core/src/services/killswitch');
  RdpAllowSvc = require('@gatecontrol/client-core/src/services/rdp-allow');

  writeCrashLog('IMPORT', 'Loading pro services...');
  ApiClientPro = require('../services/api-client-pro');
  Updater = require('@gatecontrol/client-core/src/services/updater');
  ConnectionMonitor = require('@gatecontrol/client-core/src/services/connection-monitor');
  RdpManager = require('../services/rdp/rdp-manager');
  RdpWolClient = require('../services/rdp/rdp-wol');

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

// ── Constants ────────────────────────────────────────────────
const BASE_WIDTH = 590;
const PANEL_WIDTH = 450;
const EXPANDED_WIDTH = BASE_WIDTH + PANEL_WIDTH; // 1040

// ── Pfade ────────────────────────────────────────────────────
const RESOURCES_PATH = app.isPackaged
  ? path.join(process.resourcesPath, 'resources')
  : path.join(__dirname, '..', '..', 'resources');

const WG_CONFIG_DIR = path.join(app.getPath('userData'), 'wireguard');
const WG_CONFIG_FILE = path.join(WG_CONFIG_DIR, 'gatecontrol0.conf');

// ── Helpers ──────────────────────────────────────────────────
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
  mainWindow = new BrowserWindow({
    width: BASE_WIDTH,
    minWidth: BASE_WIDTH,
    height: store.get('app.windowHeight', 800),
    minHeight: 500,
    resizable: true,
    frame: false,
    backgroundColor: store.get('app.theme', 'dark') === 'light' ? '#F8F9FB' : '#0F1117',
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
    const [, height] = mainWindow.getSize();
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

/**
 * Resize window for RDP panel open/close.
 */
function setWindowWidth(expanded) {
  if (!mainWindow) return;
  const [, height] = mainWindow.getSize();
  const targetWidth = expanded ? EXPANDED_WIDTH : BASE_WIDTH;

  mainWindow.setMinimumSize(targetWidth, 500);
  mainWindow.setMaximumSize(targetWidth, 99999);
  mainWindow.setSize(targetWidth, height, true);

  rdpPanelOpen = expanded;
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
      try {
        const config = await apiClient.fetchConfig();
        if (config) {
          await wgService.writeConfig(WG_CONFIG_FILE, config);
          store.set('tunnel.configPath', WG_CONFIG_FILE);
          log.info('Configuration updated from server');
        }
      } catch (err) {
        log.warn('Config fetch failed, using local config:', err.message);
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

    if (connectionMonitor) connectionMonitor.start();

    new Notification({ title: 'GateControl Pro', body: t('notify.connected') }).show();
    log.info('Tunnel connected successfully');

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

    await wgService.disconnect();

    if (store.get('tunnel.killSwitch', false)) {
      await killSwitchSvc.disable();
    }

    tunnelState.connected = false;
    tunnelState.connectedSince = null;
    tunnelState.rxBytes = 0;
    tunnelState.txBytes = 0;

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

  wgService = new WireGuardService(log, { resourcesPath: RESOURCES_PATH });
  killSwitchSvc = new KillSwitch(log);
  rdpAllowSvc = new RdpAllowSvc(log);

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
    onDisconnect: async () => {
      if (isReconnecting) return;
      isReconnecting = true;
      log.info('Connection lost, attempting reconnect...');
      try {
        await disconnectTunnel();
        await connectTunnel();
      } catch (err) {
        log.error('Reconnect failed:', err.message);
      }
      isReconnecting = false;
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
function registerIpcHandlers() {
  // ── Locale ─────────────────────────────────────────────
  ipcMain.handle('locale:set', (_, locale) => {
    setLocale(locale);
    store.set('app.locale', getLocale());
    updateTray(tunnelState.connected ? 'connected' : 'disconnected');
    mainWindow?.webContents.send('locale:changed', getLocale());
  });

  ipcMain.handle('locale:get', () => getLocale());

  // ── App ─────────────────────────────────────────────────
  ipcMain.handle('app:version', () => require('../../package.json').version);

  // ── Config ──────────────────────────────────────────────
  ipcMain.handle('config:get', (_, key) => store.get(key));
  ipcMain.handle('config:set', (_, key, value) => {
    try {
      store.set(key, value);
    } catch (err) {
      log.error(`Config set failed (${key}):`, err.message);
      throw err;
    }
  });
  ipcMain.handle('config:getAll', () => store.store);

  // ── Config Import ──────────────────────────────────────
  ipcMain.handle('config:import-file', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: t('dialog.importTitle'),
      filters: [
        { name: t('dialog.filterConfig'), extensions: ['conf'] },
        { name: t('dialog.filterAll'), extensions: ['*'] },
      ],
      properties: ['openFile'],
    });
    if (result.canceled) return { success: false };
    try {
      const content = fsSync.readFileSync(result.filePaths[0], 'utf-8');
      fsSync.mkdirSync(path.dirname(WG_CONFIG_FILE), { recursive: true });
      fsSync.writeFileSync(WG_CONFIG_FILE, content, { mode: 0o600 });
      store.set('tunnel.configPath', WG_CONFIG_FILE);
      log.info('Config imported:', result.filePaths[0]);
      return { success: true, path: result.filePaths[0] };
    } catch (err) {
      log.error('Config import failed:', err.message);
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle('config:import-qr', async (_, imageData) => {
    try {
      const jsQR = require('jsqr');
      const { data, width, height } = imageData;
      const code = jsQR(new Uint8ClampedArray(data), width, height);
      if (!code) return { success: false, error: t('server.qrTimeout') };
      fsSync.mkdirSync(path.dirname(WG_CONFIG_FILE), { recursive: true });
      fsSync.writeFileSync(WG_CONFIG_FILE, code.data, { mode: 0o600 });
      store.set('tunnel.configPath', WG_CONFIG_FILE);
      log.info('Config imported via QR code');
      return { success: true, config: code.data };
    } catch (err) {
      log.error('QR import failed:', err.message);
      return { success: false, error: err.message };
    }
  });

  // ── WireGuard ──────────────────────────────────────────
  ipcMain.handle('wireguard:check', () => ({
    installed: true,
    version: 'wireguard-nt (embedded)',
  }));

  // ── Kill-Switch ────────────────────────────────────────
  ipcMain.handle('killswitch:toggle', async (_, enabled) => {
    try {
      await toggleKillSwitch(enabled);
    } catch (err) {
      log.error('Kill-switch failed:', err.message);
    }
  });

  // ── RDP Allow ─────────────────────────────────────────
  ipcMain.handle('rdp-allow:toggle', async (_, enabled) => {
    try {
      await toggleRdpAllow(enabled);
    } catch (err) {
      log.error('RDP Allow failed:', err.message);
    }
  });

  // ── Permissions / Traffic / DNS / Peer-Info ─────────────
  ipcMain.handle('permissions:get', () => apiClient?.getPermissions());
  ipcMain.handle('traffic:stats', () => apiClient?.getTraffic());
  ipcMain.handle('dns:leak-test', () => apiClient?.dnsCheck());
  ipcMain.handle('dns:check-system', async () => {
    try {
      const connected = tunnelState.connected;
      const ksActive = killSwitchSvc?.enabled || false;

      // Run nslookup to determine which DNS server the system uses
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
  });
  ipcMain.handle('peer:info', () => apiClient?.getPeerInfo());

  // ── Window ──────────────────────────────────────────────
  ipcMain.on('window:minimize', () => mainWindow?.minimize());
  ipcMain.on('window:close', () => mainWindow?.hide());

  // ── Panel Resize ────────────────────────────────────────
  ipcMain.handle('panel:open', () => {
    setWindowWidth(true);
    return true;
  });

  ipcMain.handle('panel:close', () => {
    setWindowWidth(false);
    return true;
  });

  // ── RDP Handlers ────────────────────────────────────────
  ipcMain.handle('rdp:list', async () => {
    return rdpManager.refreshServices();
  });

  ipcMain.handle('rdp:connect', async (_, routeId, opts) => {
    return rdpManager.connect(routeId, opts);
  });

  ipcMain.handle('rdp:disconnect', async (_, routeId) => {
    rdpManager.disconnect(routeId);
    return true;
  });

  ipcMain.handle('rdp:detail', async (_, routeId) => {
    try {
      return await apiClient.getRdpConnect(routeId);
    } catch (err) {
      log.warn('RDP detail fetch failed:', err.message);
      return null;
    }
  });

  ipcMain.handle('rdp:wol', async (_, routeId) => {
    return rdpWolClient.wake(routeId);
  });

  ipcMain.handle('rdp:status', async (_, routeId) => {
    if (routeId) {
      return apiClient.getRdpStatus(routeId);
    }
    return apiClient.getRdpBulkStatus();
  });

  ipcMain.handle('rdp:active-sessions', () => {
    return rdpManager.getActiveSessions();
  });

  ipcMain.handle('rdp:pin-toggle', (_, pinned) => {
    store.set('rdp.panelPinned', pinned);
    return pinned;
  });

  // ── Tunnel ──────────────────────────────────────────────
  ipcMain.handle('tunnel:connect', async () => {
    await connectTunnel();
  });

  ipcMain.handle('tunnel:disconnect', async () => {
    await disconnectTunnel();
  });

  ipcMain.handle('tunnel:status', () => tunnelState);

  // ── Server ──────────────────────────────────────────────
  ipcMain.handle('server:setup', async (_, opts) => {
    try {
      apiClient.configure(opts.url, opts.apiKey);
      const result = await apiClient.register();
      store.set('server.url', opts.url);
      store.set('server.apiKey', opts.apiKey);
      store.set('server.peerId', String(result.peerId || ''));
      log.info(`Server registered: peerId=${result.peerId}`);
      return { success: true, peerId: String(result.peerId || '') };
    } catch (err) {
      log.error('Server registration failed:', err.message);
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle('server:test', async (_, opts) => {
    try {
      const testClient = new ApiClientPro(opts.url, opts.apiKey, log);
      await testClient.ping();
      return { success: true };
    } catch (err) {
      log.error('Server test failed:', err.message);
      return { success: false, error: err.message };
    }
  });

  // ── Shell ───────────────────────────────────────────────
  ipcMain.handle('shell:open-external', (_, url) => {
    const { shell } = require('electron');
    return shell.openExternal(url);
  });

  // ── Services ────────────────────────────────────────────
  ipcMain.handle('services:list', async () => {
    return apiClient.getServices();
  });

  // ── Logs ────────────────────────────────────────────────
  ipcMain.handle('logs:get', async (_, opts = {}) => {
    try {
      const logPath = log.transports.file.getFile().path;
      const fs = require('fs');
      const stat = fs.statSync(logPath);

      // Read max 1 MB from end of file
      const MAX_READ = 1024 * 1024;
      let content;
      if (stat.size > MAX_READ) {
        const fd = fs.openSync(logPath, 'r');
        const buf = Buffer.alloc(MAX_READ);
        fs.readSync(fd, buf, 0, MAX_READ, stat.size - MAX_READ);
        fs.closeSync(fd);
        content = buf.toString('utf-8');
        const firstNl = content.indexOf('\n');
        if (firstNl > 0) content = content.slice(firstNl + 1);
      } else {
        content = fs.readFileSync(logPath, 'utf-8');
      }

      let lines = content.split('\n').filter(l => l.trim());

      // Time filter
      if (opts && opts.period && opts.period !== 'all') {
        const hours = opts.period === '24h' ? 24 : opts.period === '12h' ? 12 : opts.period === '1h' ? 1 : 0;
        if (hours > 0) {
          const cutoff = new Date(Date.now() - hours * 3600000);
          lines = lines.filter(line => {
            const m = line.match(/\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/);
            if (!m) return true;
            return new Date(m[1]) >= cutoff;
          });
        }
      }

      // Reverse: newest first
      lines.reverse();
      return lines.join('\n');
    } catch {
      return t('logs.empty');
    }
  });

  ipcMain.handle('logs:export', async () => {
    try {
      return log.transports.file.getFile().path;
    } catch {
      return null;
    }
  });

  // ── Autostart (Task Scheduler wegen requireAdministrator) ──
  ipcMain.handle('autostart:set', async (_, enabled) => {
    const taskName = 'GateControlProAutostart';
    try {
      if (enabled) {
        const exePath = app.getPath('exe');
        await execFileAsync('schtasks', [
          '/Create', '/F',
          '/TN', taskName,
          '/TR', `"${exePath}"`,
          '/SC', 'ONLOGON',
          '/RL', 'HIGHEST',
          '/DELAY', '0000:10',
        ]);
        log.info(`Autostart enabled: ${exePath}`);
      } else {
        await execFileAsync('schtasks', ['/Delete', '/F', '/TN', taskName]);
        log.info('Autostart disabled');
      }
    } catch (err) {
      log.error('Autostart configuration failed:', err.message);
    }
    store.set('app.startWithWindows', enabled);
    return enabled;
  });

  // ── Update ──────────────────────────────────────────────
  ipcMain.handle('update:check', async () => {
    if (!updater) return null;
    return updater.check();
  });

  ipcMain.handle('update:install', async () => {
    installUpdate();
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
    const taskName = 'GateControlProAutostart';
    const exePath = app.getPath('exe');
    execFileAsync('schtasks', [
      '/Create', '/F', '/TN', taskName,
      '/TR', `"${exePath}"`,
      '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/DELAY', '0000:10',
    ]).catch(err => log.warn('Autostart sync failed:', err.message));
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

  // Auto-Update
  const serverUrl = store.get('server.url', '');
  const apiKey = store.get('server.apiKey', '');
  if (serverUrl && apiKey) {
    updater = new Updater({ serverUrl, apiKey, log, clientType: 'pro' });
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
