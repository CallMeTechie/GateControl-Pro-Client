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

let app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, dialog, Notification, screen, shell, clipboard, safeStorage, powerMonitor, globalShortcut, protocol;
let createSupportBundleSender, loadUpdatePublicKey, reconnectDelay, shouldOpenPortal, connectSteps, waitForHandshake, explorerShell, userPath, createPortalOpener, recoverKillSwitch, createTrayIcon, updateMenuItems, updateToast;
let e2e = null; // E2E test hooks (unpackaged dev runs only, see e2e-guard.js)
let Store, log, validateWgConfig, registerProIpc, WireGuardService, KillSwitch, RdpAllowSvc, ApiClientPro, Updater, ConnectionMonitor, DnsPolicy, RdpManager, runRdpTrustMigration, RdpWolClient;
let ClientPolicyService, clientPolicyUtil, applyPolicyToStore;
let createUpdateInstaller, installErrorText;
let PushClient, NotificationCenter, PushControl, notifyMenuItems, notificationsSchema, setupNotifications;
let MessengerService, ChatNotifier, setupMessenger;
let SchoolService;
let FamilieService;
let DnsProtectService, dnsProtectUtil;
let PrintService;
let DriveService, DriveSync;
let MailService;
let NotesService;
let CamerasService;
let DriveStreamService;
let VaultService, windowsHello, windowsOcr, setupVaultQuick;
let GateDropService, GateDropFirewall, gatedropShell, setupGateDrop;
let createDriveOnDemand, driveOnDemandExePath, parseDriveActionArgv, drivePathsOverlap;
let getMachineFingerprint, collectSupportBundle, shortDeviceId, withDeviceId;
let installWindowGuard, autostartTask, createAutostart;

try {
  writeCrashLog('IMPORT', 'Loading electron...');
  ({ app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, dialog, Notification, screen, shell, clipboard, safeStorage, powerMonitor, globalShortcut, protocol } = require('electron'));
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
  ({ reconnectDelay, shouldOpenPortal, connectSteps, waitForHandshake } = require('@gatecontrol/client-core/src/utils/tunnel-logic'));
  // "Im Ordner anzeigen" through explorer.exe (the elevated app's showItemInFolder can do nothing)
  ({ explorerShell } = require('@gatecontrol/client-core/src/utils/reveal'));
  // the folders of the person signed in, also when another Windows user runs the app (UAC with an admin account)
  ({ userPath } = require('@gatecontrol/client-core/src/utils/user-folders'));
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
  // Familie (plugin gatecontrol-familie): "Internet zu Hause", rules, own presence (core services/familie.js).
  ({ FamilieService } = require('@gatecontrol/client-core'));
  // DNS-Schutz (the DNS filter of the VPN devices, plugin gatecontrol-dns): the card on the start page and the
  // tray entries (core services/dns-protect.js); absent in an older core.
  ({ DnsProtectService, dnsProtectUtil } = require('@gatecontrol/client-core'));
  // Drucken (plugin gatecontrol-print): the printers at home (core services/print.js); absent in an older core.
  ({ PrintService } = require('@gatecontrol/client-core'));
  // Drive (plugin gatecontrol-drive): the files of the person, the family and
  // the team on the own storage (core services/drive.js); absent in an older core.
  ({ DriveService, DriveSync } = require('@gatecontrol/client-core'));
  // Drive 1.14: die Texterkennung von Windows für durchsuchbare PDFs aus Scans (fehlt in einem älteren Core)
  ({ windowsOcr } = require('@gatecontrol/client-core'));
  // Mail (plugin gatecontrol-mail): the person's mail accounts on the own
  // server (core services/mail.js); absent in an older core.
  ({ MailService } = require('@gatecontrol/client-core'));
  // Notizen & Aufgaben (plugin gatecontrol-notizen): tasks, notes, Tresor notebooks and the "zu tun" of the other
  // plugins (core services/notes.js); absent in an older core.
  ({ NotesService } = require('@gatecontrol/client-core'));
  // Kameras im Heimnetz (plugin gatecontrol-door 1.6 "Tür & Kamera"): live picture, stills and
  // clips (core services/cameras.js); absent in an older core.
  ({ CamerasService } = require('@gatecontrol/client-core'));
  // Drive 1.21: the large view streams pictures and videos over gcdrive: (core services/drive-stream.js); absent in
  // an older core (then "Dateien" opens them in the default program as before).
  ({ DriveStreamService } = require('@gatecontrol/client-core'));
  // Vault (plugin gatecontrol-vault): end-to-end encrypted password manager
  // (core docs/vault.md); quick search window on Strg+Alt+P.
  ({ VaultService, windowsHello } = require('@gatecontrol/client-core'));
  ({ setupVaultQuick } = require('./vault-quick'));
  // GateDrop (plugin gatecontrol-gatedrop): send / receive files, LAN listener,
  // "Senden an" in the Explorer (core services/gatedrop.js).
  ({ GateDropService, GateDropFirewall, gatedropShell } = require('@gatecontrol/client-core'));
  ({ setupGateDrop } = require('./gatedrop'));
  // Drive „Dateien bei Bedarf“: gc-drive-sync.exe (drive-sync/), standardmäßig aus.
  ({ createDriveOnDemand, defaultExePath: driveOnDemandExePath, parseActionArgv: parseDriveActionArgv, overlaps: drivePathsOverlap } = require('./drive-ondemand'));
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

// Every service, IPC handler and window guard gets Electron's shell with
// showItemInFolder() through explorer.exe /select (core utils/reveal.js);
// e2e runs keep the recorded showItemInFolder of the test hooks.
shell = explorerShell(shell, { platform: e2e ? 'e2e' : process.platform, log: { warn: (...a) => log.warn(...a) } });

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

// Mail: the reading frame loads its pictures (img/<token>, cid/…) through
// gcmail: — served by the core MailService with the client's sign-in (the
// scheme has to be known before the app is ready).
// Kameras: the page's <img> / <video> load the camera media (/camera-media/<token>/…
// of the own server) through gccam: — served by the core CamerasService with the
// client's connection, streamed (live.mp4, clips with Range). Drive 1.21: the
// large view loads pictures and videos (/api/v1/client/plugins/gatecontrol-drive/
// media/<id>, with Range) through gcdrive: — core DriveStreamService.
// Drive plugin 1.22: the viewer of vault files reads gcvault:// (the core decrypts
// the chunks of each request in memory, only the ciphertext lies on the disk).
// Electron takes the privileged schemes in one call only.
if (protocol && typeof protocol.registerSchemesAsPrivileged === 'function') {
  const schemes = [];
  if (MailService) schemes.push({ scheme: MailService.SCHEME, privileges: { ...MailService.SCHEME_PRIVILEGES } });
  if (CamerasService && CamerasService.SCHEME) schemes.push({ scheme: CamerasService.SCHEME, privileges: { ...CamerasService.SCHEME_PRIVILEGES } });
  if (DriveStreamService && DriveStreamService.SCHEME) schemes.push({ scheme: DriveStreamService.SCHEME, privileges: { ...DriveStreamService.SCHEME_PRIVILEGES } });
  // Drive plugin 1.22: the viewer of vault files — gcvault://v/<token>, decrypted in memory by the core (drive-vault-view.js)
  const VaultViews = DriveService && DriveService.VaultViews;
  if (VaultViews && VaultViews.SCHEME) schemes.push({ scheme: VaultViews.SCHEME, privileges: { ...VaultViews.SCHEME_PRIVILEGES } });
  if (schemes.length) protocol.registerSchemesAsPrivileged(schemes);
}

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
      // { domain, server, domains?, primary? } from GET /client/config, null = internal DNS off
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
  // Drive „Dateien bei Bedarf“ (./drive-ondemand.js): nur auf ausdrücklichen Wunsch.
  driveOnDemand: {
    type: 'object',
    properties: {
      enabled: { type: 'boolean', default: false },
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
let familie = null; // Familie (core FamilieService), one per app lifetime
let dnsProtect = null; // DNS-Schutz (core DnsProtectService), one per app lifetime
let dnsProtectTray = '[]'; // what the tray entries of DNS-Schutz last showed
let print = null; // Drucken (core PrintService), one per app lifetime
let vault = null; // Vault (core VaultService), one per app lifetime
let vaultQuick = null; // Vault quick search window (./vault-quick.js)
let gatedrop = null; // GateDrop (./gatedrop.js), one per app lifetime
let drive = null; // Drive (core DriveService), one per app lifetime
let mail = null; // Mail (core MailService), one per app lifetime
let notes = null; // Notizen & Aufgaben (core NotesService), one per app lifetime
let cameras = null; // Kameras im Heimnetz (core CamerasService), one per app lifetime
let driveStream = null; // Drive 1.21: the large view's gcdrive: (core DriveStreamService)
let driveSync = null; // "Ordner sichern" (core DriveSync), runs in this process (also with the window closed)
let driveSyncTray = '';
let driveOnDemandLocked = false; // letzter Status von gc-drive-sync: von Drive gestoppt?
let driveGuard = null; // Drive 1.6 'guard': { locked } des letzten guard-Ereignisses
let driveOnDemand = null; // Drive „Dateien bei Bedarf“ (./drive-ondemand.js, gc-drive-sync.exe) // what the tray entry of "Ordner sichern" last showed
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
// The connect asks the server for the config at most this long while a local one is there.
const CONFIG_FETCH_LOCAL_MS = 6000;

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
  // The zones for device names come with every answer, also without a new
  // config (the admin can change them, the config hash stays the same).
  if (apiClient.internalDns !== undefined) rememberInternalDns();
  if (!config) {
    if (dnsPolicy && tunnelState.connected) await syncPeerDnsRules();
    return;
  }
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

// Tray: pause / resume the DNS protection. No window shows the result: the tray entry changes on success
// ('change' → updateTray), a refusal becomes a notification with the server's sentence.
function changeDnsProtect(run) {
  Promise.resolve().then(run).catch((err) => {
    log.warn(`DNS-Schutz: ${err.code || err.message}`);
    const refused = err.status >= 400 && err.status < 500 && /\s/.test(String(err.message));
    const error = refused ? err.message : t(err.code === 'network' || err.code === 'timeout' ? `dnsProtect.error.${err.code}` : 'dnsProtect.error.unavailable');
    notify(t('dnsProtect.toast.failed', { error }), { collapseKey: 'dns-protect', force: true });
  });
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
    // "Ordner sichern": pause / resume while folders are set up
    ...(driveSync && driveSyncTray ? [{
      label: t(driveSyncTray === 'resume' ? 'drive.sync.tray.resume' : 'drive.sync.tray.pause'),
      click: () => { try { driveSync.setPaused(null, driveSyncTray === 'pause'); } catch (err) { log.warn(`Drive sync pause failed: ${err.message}`); } },
    }] : []),
  ];

  // "DNS-Schutz: aktiv" with "DNS-Schutz unterbrechen" ▸ durations, or "… wieder einschalten" (core
  // dnsProtectMenuItems); nothing while the server reports no DNS protection
  const dnsItems = dnsProtect && dnsProtectUtil ? dnsProtectUtil.dnsProtectMenuItems({
    snapshot: dnsProtect.snapshot(),
    t,
    locale: getLocale(),
    pause: (how) => changeDnsProtect(() => dnsProtect.pause(how)),
    resume: () => changeDnsProtect(() => dnsProtect.resume()),
  }) : [];

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
    ...(dnsItems.length ? [{ type: 'separator' }, ...dnsItems] : []),
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
  // Drive 1.11: "Beim Verlassen sperren" locks the Drive vaults the same way.
  mainWindow.on('hide', () => { vault?.windowHidden(); drive?.windowHidden?.(); notes?.windowHidden?.(); });
  mainWindow.on('minimize', () => { vault?.windowHidden(); drive?.windowHidden?.(); notes?.windowHidden?.(); });
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
  // Each step's duration goes into the log ("Connect steps: …"), so a slow
  // connect shows where the time went.
  const steps = connectSteps();
  try {
    log.info('Establishing tunnel connection...');
    if (connectionMonitor) connectionMonitor.stop();
    updateTray('connecting');
    broadcastState('connecting');

    const serverUrl = store.get('server.url');
    const apiKey = store.get('server.apiKey');

    if (serverUrl && apiKey) {
      let config = null;
      // With a local config a slow or blocked server must not hold the
      // connect for the client's full 15–25 s: CONFIG_FETCH_LOCAL_MS, then
      // the local one (a changed config still comes with the next config check).
      const haveLocal = fsSync.existsSync(WG_CONFIG_FILE);
      let source = 'server';
      try {
        config = await apiClient.fetchConfig(haveLocal ? { timeout: CONFIG_FETCH_LOCAL_MS } : {});
      } catch (err) {
        source = /timeout/i.test(err.message || '') || err.code === 'ECONNABORTED' ? 'timeout, local' : 'failed, local';
        log.warn('Config fetch failed, using local config:', err.message);
      }
      steps.done('config', config ? source : (source === 'server' ? 'none' : source));
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
        steps.done('config-write');
      }
    }

    if (store.get('tunnel.killSwitch', false)) {
      await killSwitchSvc.enable(WG_CONFIG_FILE);
      steps.done('killswitch');
    }

    await wgService.connect(WG_CONFIG_FILE, store.get('tunnel.splitTunnel') ? store.get('tunnel.splitRoutes', '') : null);
    steps.done('adapter');

    // Verify handshake before declaring connected — a stale config can
    // create the adapter successfully but never complete a handshake.
    // Asked right away and every 250 ms (up to 10 s), not after 2 s first.
    const handshakeOk = await waitForHandshake(() => wgService.getStats(), { timeoutMs: 10000, intervalMs: 250 });
    steps.done('handshake', handshakeOk ? null : 'none');

    if (!handshakeOk) {
      await wgService.disconnect();
      throw new Error(t('error.noHandshake') || 'No WireGuard handshake — config may be invalid');
    }

    tunnelState.connected = true;
    tunnelState.connectedSince = new Date();

    updateTray('connected');
    broadcastState('connected');

    if (connectionMonitor) connectionMonitor.start();

    notify(t('notify.connected'), { collapseKey: 'tunnel' });
    log.info('Tunnel connected successfully');
    log.info(steps.summary());
    // DNS-Schutz: with the tunnel up the server may be reachable (again) — ask now, not at the next interval
    dnsProtect?.refresh().catch(() => {});

    // ── Portal auto-open ─────────────────────────────────────
    // Not in the connect's path any more: GET permissions (up to 15 s on a
    // slow server, twice) ran before "connected" was done.
    const since = tunnelState.connectedSince ? tunnelState.connectedSince.getTime() : Date.now();
    async function refreshPortalUrl() {
      await apiClient.getPermissions();
      portalUrl = apiClient.portalUrl;
      autoOpenPortal = apiClient.autoOpenPortal;
      // ponytail: getPermissions() catches internally; on failure portalUrl retains prior value
      if (!portalUrl) log.warn('portal url fetch returned empty');
    }
    (async () => {
      const t0 = Date.now();
      await refreshPortalUrl();
      if (!portalUrl) { await new Promise(r => setTimeout(r, 1500)); await refreshPortalUrl(); }
      log.info(`Portal URL after connect: ${Date.now() - t0} ms`);
      if (!tunnelState.connected || !tunnelState.connectedSince || tunnelState.connectedSince.getTime() !== since) return;
      updateTray('connected'); // refresh so portal tray item appears
      if (mainWindow) mainWindow.webContents.send('portal-url', portalUrl);
      // Auto-open only on a user-initiated connect. The reconnect loop uses a
      // separate path that never runs this block, so a reconnect can't re-open.
      if (shouldOpenPortal({ portalUrl, autoOpenPortal, connectedSince: since, lastOpenedSince: portalOpenedSince })) {
        portalOpenedSince = since;
        openPortalSafe();
      }
    })().catch((err) => log.warn('Portal URL after connect failed:', err.message));

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

    // Install the NRPT rules so Windows routes *.<zone> peer-hostname queries
    // to the VPN-internal dnsmasq — one rule per zone the server answers. Without this, Windows fans the
    // query out to all configured resolvers and caches the NXDOMAIN
    // that a public resolver returns first — which was exactly why the
    // RDP cred-SSP target (desktop-xxx.gc.internal) previously failed
    // to resolve and mstsc fell back to the IP (SPN mismatch again).
    try {
      if (DnsPolicy && !dnsPolicy) dnsPolicy = new DnsPolicy(log);
      if (dnsPolicy) {
        // force: also replaces rules a killed process left behind and the
        // legacy comment (pre-1.17 'GateControl' tag) — see client-core dns-policy.js.
        syncPeerDnsRules({ force: true }).catch((e) =>
          log.debug('NRPT install failed:', e && e.message));
      }
    } catch (err) {
      log.debug('NRPT skipped:', err.message);
    }

  } catch (err) {
    log.error('Tunnel connection failed:', err.message);
    log.info(steps.summary('Connect steps (failed)'));
    updateTray('disconnected');
    broadcastState('error', err.message);
    notify(err.message, { title: t('notify.connectionError'), collapseKey: 'tunnel' });
  }
}

// Internal DNS as the server reported it with the config or the config check:
// { domain, server, domains, primary }, null (off), or unset for servers that
// do not say — kept for connects where the config cannot be fetched.
function rememberInternalDns() {
  if (apiClient && apiClient.internalDns !== undefined) store.set('tunnel.internalDns', apiClient.internalDns);
  else store.delete('tunnel.internalDns');
}

// Peer hostnames (<host>.<zone>) → the server's dnsmasq, with the zones and
// resolver of this server (client-core DnsPolicy.rulesFor), not fixed values:
// one rule per zone, own rules for zones no longer listed are removed.
async function syncPeerDnsRules({ force = false } = {}) {
  const rules = DnsPolicy.rulesFor({
    internalDns: store.get('tunnel.internalDns'),
    wgConfig: await wgService.readConfig(WG_CONFIG_FILE),
  });
  // The tunnel may have gone down while the config was read.
  if (!tunnelState.connected) return;
  await dnsPolicy.sync(rules, { force });
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

  // Familie: shown while the server lists the plugin and the person is a member of a
  // family; the toasts of "Internet zu Hause" open the page.
  familie = FamilieService ? new FamilieService({
    apiClient, log,
    notificationCenter: notifications?.notificationCenter,
    pushClient: notifications?.pushClient,
  }) : null;

  // DNS-Schutz: the card and the tray entries exist only while the server reports a DNS protection. The tray
  // follows what its entries show (not every answer: an open menu is left alone); a filter that fails is
  // announced here (the plugin tells only admins).
  dnsProtect = DnsProtectService ? new DnsProtectService({
    apiClient, log,
    pushClient: notifications?.pushClient,
    getLocale: () => getLocale(),
  }) : null;
  if (dnsProtect) {
    dnsProtect.on('change', (snapshot) => {
      const key = JSON.stringify(dnsProtectUtil.dnsProtectMenuItems({ snapshot, t, locale: getLocale(), pause() {}, resume() {} }));
      if (key === dnsProtectTray) return;
      dnsProtectTray = key;
      updateTray(trayState);
    });
    dnsProtect.on('outage', () => notify(t('dnsProtect.toast.outageBody'), {
      title: t('dnsProtect.toast.outageTitle'),
      collapseKey: 'dns-protect',
      onClick: () => { showWindow(); mainWindow?.webContents.send('navigate', 'status'); },
    }));
  }

  // Drive: shown while the server lists the plugin; opened files go to
  // %TEMP%\gatecontrol-drive, the folder last picked for "In Drive speichern"
  // is kept per server in the store.
  drive = DriveService ? new DriveService({
    apiClient, log, store, shell, dialog,
    getMainWindow: () => mainWindow,
    tempDir: () => path.join(app.getPath('temp'), 'gatecontrol-drive'),
    getLang: () => getLocale(),
    pushClient: notifications?.pushClient,
    // Drive 1.8 / 1.9: ein Klick auf eine Fristen- oder Tresor-Mitteilung öffnet die Drive-Seite
    notificationCenter: notifications?.notificationCenter,
    // Drive 1.9 Tresor-Ordner: der private Geräteschlüssel nur unter DPAPI (safeStorage), nie im Klartext
    protect: typeof DriveService.safeStorageProtect === 'function' ? DriveService.safeStorageProtect(safeStorage) : null,
    deviceName: () => _os.hostname().slice(0, 80) || 'PC',
    // Drive 1.11 Tresor-Sperre: Windows Hello (UserConsentVerifier über WinRT/koffi) vor dem Entsperren; sperrt bei
    // Sitzungssperre / Standby (powerMonitor), nach Inaktivität und beim Verlassen (windowHidden oben)
    consent: windowsHello && typeof windowsHello.createConsentVerifier === 'function' ? windowsHello.createConsentVerifier({ log }) : null,
    powerMonitor,
    // Drive 1.14 'scanDocs': gedruckter Text wird auf diesem PC zum durchsuchbaren PDF (Windows.Media.Ocr über
    // WinRT/koffi, ohne KI); ohne OCR-Sprache macht Drive das PDF
    ocr: windowsOcr && typeof windowsOcr.createWindowsOcr === 'function' ? windowsOcr.createWindowsOcr({ log }) : null,
    // Drive 1.6 'links': „Im Portal öffnen“ nur auf dem Host des Servers oder des Portals
    allowedHosts: () => [store.get('server.url', ''), portalUrl].map((u) => { try { return u ? new URL(u).hostname : null; } catch { return null; } }).filter(Boolean),
  }) : null;

  // Drucken: shown while the server offers the plugin to the apps. Files reach it only through the file dialog,
  // a drop on the window or Drive (checked in the core: type, size, virus scan); where the files of the last jobs
  // lie ("Erneut drucken") is kept in the store per server.
  print = PrintService ? new PrintService({
    apiClient, log, store, dialog, drive,
    getMainWindow: () => mainWindow,
    notificationCenter: notifications?.notificationCenter,
    pushClient: notifications?.pushClient,
  }) : null;

  // Mail: shown while the server lists the plugin and lets the person in;
  // attachments open from %TEMP%\gatecontrol-mail, the offline cache lives in
  // %APPDATA%\…\mail-cache (only under DPAPI), the Microsoft sign-in runs in
  // the default browser.
  mail = MailService ? new MailService({
    apiClient, log, shell, dialog,
    getMainWindow: () => mainWindow,
    tempDir: () => path.join(app.getPath('temp'), 'gatecontrol-mail'),
    cacheDir: () => path.join(app.getPath('userData'), 'mail-cache'),
    protect: DriveService && typeof DriveService.safeStorageProtect === 'function' ? DriveService.safeStorageProtect(safeStorage) : null,
    getLang: () => getLocale(),
    pushClient: notifications?.pushClient,
    // ein Klick auf eine Mail-Mitteilung öffnet die Mail auf der Mail-Seite
    notificationCenter: notifications?.notificationCenter,
  }) : null;

  // Notizen & Aufgaben: shown while the server lists the plugin (licensed) and lets the person in; attachments open
  // from %TEMP%\gatecontrol-notizen; the Tresor notebooks' device key only under DPAPI (safeStorage), their lock asks
  // Windows Hello and locks with the session, after 15 minutes without use and when the window is left.
  notes = NotesService ? new NotesService({
    apiClient, log, store, shell, dialog,
    getMainWindow: () => mainWindow,
    tempDir: () => path.join(app.getPath('temp'), 'gatecontrol-notizen'),
    getLang: () => getLocale(),
    pushClient: notifications?.pushClient,
    // ein Klick auf eine Erinnerung öffnet die Aufgabe, eine Tresor-Anfrage den Tresor
    notificationCenter: notifications?.notificationCenter,
    protect: DriveService && typeof DriveService.safeStorageProtect === 'function' ? DriveService.safeStorageProtect(safeStorage) : null,
    deviceName: () => _os.hostname().slice(0, 80) || 'PC',
    consent: windowsHello && typeof windowsHello.createConsentVerifier === 'function' ? windowsHello.createConsentVerifier({ log }) : null,
    powerMonitor,
    // erkannter Text auf Bildern für die Suche (Windows.Media.Ocr, wenn eine OCR-Sprache da ist)
    ocr: windowsOcr && typeof windowsOcr.createWindowsOcr === 'function' ? windowsOcr.createWindowsOcr({ log }) : null,
  }) : null;

  // Kameras im Heimnetz: shown while the plugin has home cameras the person sees;
  // a camera toast shows its picture (from %TEMP%\gatecontrol-cameras) and opens the page.
  cameras = CamerasService ? new CamerasService({
    apiClient, log,
    notificationCenter: notifications?.notificationCenter,
    pushClient: notifications?.pushClient,
    tempDir: () => path.join(app.getPath('temp'), 'gatecontrol-cameras'),
  }) : null;

  // Drive 1.21: pictures and videos of the large view, streamed with Range (gcdrive:)
  driveStream = drive && DriveStreamService ? new DriveStreamService({ drive, log }) : null;

  // "Ordner sichern": folders of this PC backed up / synced with Drive. Runs
  // in the main process (tray), the state of each folder lives in
  // %APPDATA%\…\drive-sync (no tokens); deleted files go to the recycle bin.
  driveSync = drive && DriveSync ? new DriveSync({
    drive, store, log, shell, dialog,
    dir: path.join(app.getPath('userData'), 'drive-sync'),
    trashItem: (p) => shell.trashItem(p),
    getMainWindow: () => mainWindow,
    // „GateControl Drive“ (Dateien bei Bedarf) lässt sich nicht zusätzlich sichern
    blockedPaths: () => driveOnDemand?.blockedPaths() || [],
    // Drive 1.5: Version beim Anmelden des Geräts (PUT devices/<id>)
    appVersion: require('../../package.json').version,
    isVpnUp: () => tunnelState.connected,
    // the PC's stable short id (Settings → About), shown on the page (read once)
    getDeviceKey: (() => { let key; return () => (key === undefined ? (key = shortDeviceId(getMachineFingerprint, log)) : key); })(),
    // the folders of the person signed in, also when another Windows user runs the app (core utils/user-folders.js)
    knownFolders: () => ['desktop', 'documents', 'pictures', 'videos', 'music'].map((key) => {
      try { return { key, path: userPath(key) }; } catch { return null; }
    }).filter(Boolean),
    pushClient: notifications?.pushClient,
    ...(e2e ? { timing: { startMs: 1000, settleMs: 300, watchMs: 500 } } : {}),
  }) : null;
  // The tray entry (pause / resume) follows the folders and the pause.
  const driveSyncTrayKey = (st) => (st && st.folders && st.folders.length ? (st.paused ? 'resume' : 'pause') : '');
  if (driveSync) driveSyncTray = driveSyncTrayKey(driveSync.status());
  driveSync?.on('change', (st) => {
    const key = driveSyncTrayKey(st);
    if (key !== driveSyncTray) { driveSyncTray = key; updateTray(trayState); }
  });

  // Drive „Dateien bei Bedarf“: Explorer-Ordner „GateControl Drive“ über
  // gc-drive-sync.exe (Cloud Files API), gestartet mit den Rechten des
  // angemeldeten Benutzers. Aus, bis es jemand einschaltet. E2E-Läufe nehmen
  // ein Fake-Programm (test/e2e/support/drive-sync-fake.js): keine Sync-Root
  // auf dem Testrechner.
  driveOnDemand = createDriveOnDemand({
    store, log,
    getServer: () => ({ url: store.get('server.url', ''), apiKey: store.get('server.apiKey', '') }),
    getHeaders: () => apiClient.buildHeaders(),
    exePath: driveOnDemandExePath({ isPackaged: app.isPackaged, resourcesPath: process.resourcesPath, appRoot: path.join(__dirname, '..', '..') }),
    appVersion: require('../../package.json').version,
    appExe: app.isPackaged ? process.execPath : null,
    getLang: () => getLocale(),
    openPath: (p) => shell.openPath(p),
    // Ein Windows-Ordner, den „Ordner sichern“ (W2) sichert, wird nicht zusätzlich verlegt.
    relocateBlocked: (p) => {
      const st = driveSync ? driveSync.status() : null;
      const folders = st && Array.isArray(st.folders) ? st.folders : [];
      return folders.some((f) => f && f.path && drivePathsOverlap(f.path, p)) ? 'w2_active' : null;
    },
    onAction: (a) => handleDriveAction(a).catch((err) => log.warn(`Drive action failed: ${err.message}`)),
    // Drive 1.6 'guard': ist das Gerät gestoppt? (gleich nach dem Start an gc-drive-sync)
    getGuard: () => driveGuard,
    onStatus: (st) => {
      const w = mainWindow;
      if (w && !w.isDestroyed()) w.webContents.send('drive-ondemand:status', st);
      // gc-drive-sync bekam selbst ein 423 device_locked: die Drive-Seite fragt nach (Banner)
      const locked = !!(st && st.locked);
      if (locked && !driveOnDemandLocked) drive?.guard({ fresh: true }).catch(() => {});
      driveOnDemandLocked = locked;
    },
    ...(e2e && e2e.driveOnDemand ? e2e.driveOnDemand : {}),
  });
  driveOnDemand?.watchPush(notifications?.pushClient);
  // Drive 1.6 'guard': Drive hat dieses Gerät gestoppt / freigegeben → auch gc-drive-sync
  drive?.on('guard', (g) => {
    driveGuard = g && typeof g === 'object' ? { locked: g.locked === true } : null;
    driveOnDemand?.guard(g && g.locked === true, !!(g && g.decided === 'undo')).catch((err) => log.warn(`gc-drive-sync guard: ${err.code || err.message}`));
  });
  store.onDidChange('server', () => { driveOnDemand?.serverChanged().catch(() => {}); });

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
  // Downloads\GateControl of the person signed in (or the folder chosen on
  // the page), listens on TCP 47731 in private networks.
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
    // „Namen im VPN“: a name of the chosen zone only when Windows is pinned to the VPN resolver for it.
    hasDnsRuleFor: (name) => !!(dnsPolicy && dnsPolicy.coversName(name)),
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
    shell,
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
    // familie:* channels + events, reset on server:setup (core, opt-in)
    familie,
    // dnsprotect:* channels + event, reset on server:setup (core, opt-in)
    dnsProtect,
    // print:* channels + events, reset on server:setup (core, opt-in)
    print,
    // vault:* channels + events, reset on server:setup (core, opt-in)
    vault,
    // gatedrop:* channels + events, reset on server:setup (core, opt-in)
    gatedrop: gatedrop?.service,
    // drive:* channels + events, reset on server:setup (core, opt-in)
    drive,
    // drive:sync:* ("Ordner sichern"), reset on server:setup (core, opt-in with drive)
    driveSync,
    // drive:stream / drive:stream:end (Drive 1.21's large view), its addresses end on server:setup
    driveStream,
    // mail:* channels + events, reset on server:setup (core, opt-in)
    mail,
    // notes:* channels + events, reset on server:setup (core, opt-in)
    notes,
    // cameras:* channels + events, reset on server:setup (core, opt-in)
    cameras,
    gatedropExplorer: gatedrop?.explorer,
    // drive-ondemand:* (Pro, ./ipc-pro.js)
    driveOnDemand,
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
  // requireAdministrator: a UAC prompt answered with another account's
  // password runs the app as that Windows user (its %APPDATA%, %TEMP%;
  // Windows refuses the toasts). Files still go to the folders of the person
  // signed in (core utils/user-folders.js, resolved here once) — said in the log.
  try {
    const ra = require('@gatecontrol/client-core/src/utils/user-folders').userFolders();
    if (ra.differs) log.warn(`App runs as Windows user "${ra.processUser}", signed in is "${ra.sessionUser}" – files go to ${ra.downloads} (${ra.downloadsSource}), toasts may be refused`);
  } catch (err) { log.debug('Run-as check skipped:', err.message); }
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
  // Familie: member of a family? push → page.
  familie?.start();
  // DNS-Schutz: does the server report one? Its state for the card and the tray.
  dnsProtect?.start();
  // Drucken: is the plugin there for the apps? print pushes → page.
  print?.start();
  // Drive: availability check (the page shows while the server lists the plugin).
  drive?.start();
  // Drive plugin 1.22: the vault viewer's bytes (gcvault:) — only tokens the page opened, revoked on close and lock
  if (drive && typeof drive.handleVaultProtocol === 'function' && protocol && typeof protocol.handle === 'function') {
    try { protocol.handle(DriveService.VaultViews.SCHEME, (req) => drive.handleVaultProtocol(req)); } catch (err) { log.warn(`Vault viewer protocol not registered: ${err.message}`); }
  }
  // Mail: pictures of the reading frame (gcmail:), availability, live events.
  if (mail && protocol && typeof protocol.handle === 'function') {
    try { protocol.handle(MailService.SCHEME, (req) => mail.handleProtocol(req)); } catch (err) { log.warn(`Mail protocol not registered: ${err.message}`); }
  }
  mail?.start();
  notes?.start();
  // Kameras: media of the page (gccam:), availability, camera pushes → page / toast picture.
  if (cameras && protocol && typeof protocol.handle === 'function') {
    try { protocol.handle(CamerasService.SCHEME, (req) => cameras.handleProtocol(req)); } catch (err) { log.warn(`Camera protocol not registered: ${err.message}`); }
  }
  cameras?.start();
  // Drive 1.21: pictures and videos of the large view (gcdrive:), streamed from the own server with Range.
  if (driveStream && protocol && typeof protocol.handle === 'function') {
    try { protocol.handle(DriveStreamService.SCHEME, (req) => driveStream.handleProtocol(req)); } catch (err) { log.warn(`Drive protocol not registered: ${err.message}`); }
  }
  // "Ordner sichern": watches the folders, a full run shortly after start and every 15 min.
  driveSync?.start();
  // Drive „Dateien bei Bedarf“: startet gc-drive-sync.exe nur, wenn eingeschaltet.
  driveOnDemand?.start().catch((err) => log.warn(`Drive on demand start failed: ${err.message}`));
  if (handleDriveActionArgv(process.argv)) log.info('Started from the Explorer menu "GateControl Drive"');
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

// Explorer-Kontextmenü „GateControl Drive ›“ (gc-drive-sync → Ereignis action):
// „Im Portal öffnen“ öffnet bei Drive 1.6 ('links') die Seite der Datei / des
// Ordners im Portal (me.links.node, nur https auf dem Host von Server oder
// Portal, core DriveService.openInPortal), sonst wie bisher die Drive-Seite des
// Portals (angemeldet); „Link teilen …“ und „Ältere Versionen“ öffnen den
// Dialog der Drive-Seite.
async function handleDriveAction(a) {
  if (!a) return;
  if (a.action === 'portal') {
    let opened = false;
    if (a.node && drive && typeof drive.openInPortal === 'function') {
      const r = await drive.openInPortal(a.node).catch(() => null);
      opened = !!(r && r.ok);
    }
    if (!opened) await openPortalSafe({ next: '/portal#plg-gatecontrol-drive' });
    return;
  }
  let node = null;
  let code = null;
  if (!a.node) code = 'not_synced';
  else {
    try { node = drive && drive.api ? await drive.api.node(a.node) : null; } catch (err) { code = err.code || 'failed'; }
    if (!node && !code) code = 'failed';
  }
  showWindow();
  const send = () => mainWindow?.webContents.send('drive-ondemand:action', { action: a.action, node, code, path: a.path });
  if (mainWindow?.webContents.isLoading()) mainWindow.webContents.once('did-finish-load', send);
  else send();
}

/** `--drive-action` aus den Argumenten (Kontextmenü, als gc-drive-sync nicht lief). */
function handleDriveActionArgv(argv) {
  const a = parseDriveActionArgv ? parseDriveActionArgv(argv) : null;
  if (!a || !driveOnDemand) return false;
  driveOnDemand.action(a).catch((err) => log.warn(`Drive action from argv: ${err.code || ''} ${err.message}`));
  return true;
}

// A second start (shortcut, autostart, or a toast button: <protocol>://notify/…)
// only brings this instance to the front or performs the toast action.
app.on('second-instance', (_event, argv) => {
  // Explorer-Kontextmenü „GateControl Drive ›“, als gc-drive-sync nicht lief.
  if (handleDriveActionArgv(argv)) return;
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
  familie?.stop();
  dnsProtect?.stop();
  print?.stop();
  drive?.stop();
  // Mail: a waiting Microsoft sign-in ends, the offline cache is written.
  mail?.stop();
  notes?.stop();
  cameras?.stop();
  driveSync?.stop();
  // gc-drive-sync.exe beenden (endet sonst mit dem Prozess über --parent-pid).
  driveOnDemand?.stop().catch(() => {});
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
