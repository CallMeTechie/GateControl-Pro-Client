/**
 * GateControl Pro Client -- Electron Main Process
 *
 * Extends the community client with RDP integration:
 * - RDP Manager (session lifecycle)
 * - Dynamic window width (590px base, 1040px with panel)
 * - RDP-specific IPC handlers
 */

const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, dialog, Notification, screen } = require('electron');
const path = require('path');
const Store = require('electron-store');
const log = require('electron-log');

const WireGuardService = require('@gatecontrol/client-core/src/services/wireguard-native');
const KillSwitch = require('@gatecontrol/client-core/src/services/killswitch');
const ApiClientPro = require('../services/api-client-pro');
const Updater = require('@gatecontrol/client-core/src/services/updater');
const ConnectionMonitor = require('@gatecontrol/client-core/src/services/connection-monitor');
const RdpManager = require('../services/rdp/rdp-manager');
const RdpWolClient = require('../services/rdp/rdp-wol');

// ── Logging ──────────────────────────────────────────────────
log.transports.file.level = 'info';
log.transports.file.maxSize = 5 * 1024 * 1024;
log.transports.console.level = 'debug';

// ── Global Error Handlers ────────────────────────────────────
process.on('uncaughtException', (err) => {
  log.error('Uncaught Exception:', err);
  dialog.showErrorBox('Error', `${err.message}\n\n${err.stack}`);
});
process.on('unhandledRejection', (reason) => {
  log.error('Unhandled Rejection:', reason);
});

// ── Single Instance Lock ─────────────────────────────────────
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
}

// ── Konfiguration ────────────────────────────────────────────
const crypto = require('crypto');
const fsSync = require('fs');

const keyStore = new (require('electron-store'))({ name: 'gatecontrol-pro-keyfile', encryptionKey: 'gc-pro-bootstrap' });

if (!keyStore.get('machineKey')) {
  const newKey = crypto.randomBytes(32).toString('hex');
  try {
    const configPath = path.join(app.getPath('userData'), 'gatecontrol-pro-config.json');
    if (fsSync.existsSync(configPath)) {
      fsSync.unlinkSync(configPath);
      log.info('Alte Config-Datei entfernt (einmalige Key-Migration)');
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
  uptime: 0,
  connectedSince: null,
};
let isReconnecting = false;
let rdpPanelOpen = false;

// ── Constants ────────────────────────────────────────────────
const BASE_WIDTH = 590;
const PANEL_WIDTH = 450;
const EXPANDED_WIDTH = BASE_WIDTH + PANEL_WIDTH; // 1040

// ── Pfade ────────────────────────────────────────────────────
const RESOURCES_PATH = app.isPackaged
  ? process.resourcesPath
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

// ── Tray Icon ────────────────────────────────────────────────
function getIcon(state) {
  const iconName = state === 'connected' ? 'tray-connected'
    : state === 'connecting' ? 'tray-connecting'
    : 'tray-disconnected';

  const iconPath = path.join(RESOURCES_PATH, 'icons', `${iconName}.png`);

  try {
    return nativeImage.createFromPath(iconPath);
  } catch {
    return createFallbackIcon(state);
  }
}

function createFallbackIcon(state) {
  const size = 16;
  const canvas = Buffer.alloc(size * size * 4);
  const color = state === 'connected' ? [0x22, 0xC5, 0x5E, 0xFF]
    : state === 'connecting' ? [0xF5, 0x9E, 0x0B, 0xFF]
    : [0x6B, 0x72, 0x80, 0xFF];

  for (let i = 0; i < size * size; i++) {
    const x = i % size;
    const y = Math.floor(i / size);
    const cx = size / 2;
    const cy = size / 2;
    const r = size / 2 - 1;
    if ((x - cx) ** 2 + (y - cy) ** 2 <= r ** 2) {
      canvas.set(color, i * 4);
    }
  }

  return nativeImage.createFromBuffer(canvas, { width: size, height: size });
}

function updateTray(connState) {
  if (!tray) return;

  tray.setImage(getIcon(connState));

  const statusText = connState === 'connected' ? 'Verbunden'
    : connState === 'connecting' ? 'Verbinde...'
    : 'Getrennt';

  let tooltip = `GateControl Pro - ${statusText}`;
  if (tunnelState.connected && tunnelState.connectedSince) {
    const dur = Math.floor((Date.now() - new Date(tunnelState.connectedSince).getTime()) / 1000);
    const h = Math.floor(dur / 3600);
    const m = Math.floor((dur % 3600) / 60);
    tooltip += `\nVerbunden seit: ${h > 0 ? h + 'h ' : ''}${m}m`;
  }

  // RDP active sessions count
  if (rdpManager) {
    const sessions = rdpManager.getActiveSessions();
    if (sessions.length > 0) {
      tooltip += `\nRDP: ${sessions.length} aktive Session(s)`;
    }
  }

  tray.setToolTip(tooltip);

  // Build context menu with RDP status
  const rdpSessions = rdpManager ? rdpManager.getActiveSessions() : [];

  const contextMenu = Menu.buildFromTemplate([
    { label: `GateControl Pro - ${statusText}`, enabled: false, icon: getIcon(connState) },
    { type: 'separator' },
    {
      label: connState === 'connected' ? 'Trennen' : 'Verbinden',
      click: () => connState === 'connected' ? disconnectTunnel() : connectTunnel(),
    },
    { type: 'separator' },
    {
      label: 'Kill-Switch',
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
    { label: 'Fenster oeffnen', click: () => showWindow() },
    ...(pendingUpdate ? [
      { type: 'separator' },
      { label: `Update v${pendingUpdate.version} installieren`, click: () => installUpdate() },
    ] : []),
    { type: 'separator' },
    { label: 'Beenden', click: () => quitApp() },
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
async function connectTunnel() {
  // Tunnel connect logic (same as community client)
}

async function disconnectTunnel() {
  // Tunnel disconnect logic (same as community client)
}

async function toggleKillSwitch(enabled) {
  if (enabled) {
    await killSwitchSvc.enable();
  } else {
    await killSwitchSvc.disable();
  }
  store.set('tunnel.killSwitch', enabled);
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

  apiClient = new ApiClientPro(serverUrl, apiKey, log, peerId);

  wgService = new WireGuardService(log, { resourcesPath: RESOURCES_PATH });
  killSwitchSvc = new KillSwitch(log);

  rdpManager = new RdpManager({
    apiClient,
    log,
    getTunnelState: () => tunnelState,
    getPeerInfo: () => apiClient.getPeerInfo(),
  });

  rdpWolClient = new RdpWolClient({ apiClient, log });

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
      body: `RDP-Sitzung laeuft ab (Route ${data.routeId}). Noch ${Math.round(data.gracePeriod / 60)} Minuten.`,
    }).show();
  });
}

// ── IPC Handlers ─────────────────────────────────────────────
function registerIpcHandlers() {
  // ── App ─────────────────────────────────────────────────
  ipcMain.handle('app:version', () => require('../../package.json').version);

  // ── Config ──────────────────────────────────────────────
  ipcMain.handle('config:get', (_, key) => store.get(key));
  ipcMain.handle('config:set', (_, key, value) => store.set(key, value));
  ipcMain.handle('config:getAll', () => store.store);

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
      store.set('server.peerId', result.peerId);
      return { success: true, peerId: result.peerId };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle('server:test', async (_, opts) => {
    try {
      const testClient = new ApiClientPro(opts.url, opts.apiKey, log);
      await testClient.ping();
      return { success: true };
    } catch (err) {
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
  ipcMain.handle('logs:get', async () => {
    try {
      const logPath = log.transports.file.getFile().path;
      return fsSync.readFileSync(logPath, 'utf-8');
    } catch {
      return 'Keine Logs verfuegbar.';
    }
  });

  // ── Autostart ───────────────────────────────────────────
  ipcMain.handle('autostart:set', (_, enabled) => {
    app.setLoginItemSettings({ openAtLogin: enabled });
    store.set('app.startWithWindows', enabled);
    return enabled;
  });

  // ── Kill-Switch ─────────────────────────────────────────
  ipcMain.handle('killswitch:toggle', async (_, enabled) => {
    await toggleKillSwitch(enabled);
    return enabled;
  });

  // ── Traffic ─────────────────────────────────────────────
  ipcMain.handle('traffic:stats', async () => {
    return apiClient.getTraffic();
  });

  // ── DNS ─────────────────────────────────────────────────
  ipcMain.handle('dns:leak-test', async () => {
    return apiClient.dnsCheck();
  });

  // ── Permissions ─────────────────────────────────────────
  ipcMain.handle('permissions:get', async () => {
    return apiClient.getPermissions();
  });

  // ── WireGuard Check ─────────────────────────────────────
  ipcMain.handle('wireguard:check', async () => {
    return wgService.check();
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
});
