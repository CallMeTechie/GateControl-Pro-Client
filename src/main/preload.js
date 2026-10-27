/**
 * GateControl Pro -- Preload Script
 * Common bridge from core (createBridgeApi) plus the Pro RDP channels.
 */

const { contextBridge, ipcRenderer, webUtils } = require('electron');
const { i18n, createBridgeApi, createSubscriber } = require('@gatecontrol/client-core');
const { registerTranslations } = i18n;

// Register Pro-specific translations
registerTranslations('de', require('../i18n/de.json'));
registerTranslations('en', require('../i18n/en.json'));

const subscribe = createSubscriber(ipcRenderer);

// Channels shared with Community (tunnel, config, logs, update, locale, …).
// Pro announces downloaded updates on 'update:ready'.
// webUtils: paths of files dropped on the window (GateDrop send dialog).
const api = createBridgeApi(ipcRenderer, i18n, { updateReadyChannel: 'update:ready', webUtils });

// Short device ID (first 8 hex of the machine fingerprint) or null.
api.getDeviceId = () => ipcRenderer.invoke('app:device-id');

// Pro: system DNS check (Settings → DNS)
api.dns.checkSystem = () => ipcRenderer.invoke('dns:check-system');

// ══════════════════════════════════════════════════════
//  PRO: RDP Channels
// ══════════════════════════════════════════════════════

api.rdp = {
  /** Fetch all RDP services available to this token */
  list: () => ipcRenderer.invoke('rdp:list'),

  /** Connect to an RDP host. opts: { password?, forceMaintenanceBypass? } */
  connect: (routeId, opts) => ipcRenderer.invoke('rdp:connect', routeId, opts),

  /** Disconnect an active RDP session */
  disconnect: (routeId) => ipcRenderer.invoke('rdp:disconnect', routeId),

  /** Get detail info for a specific RDP route */
  detail: (routeId) => ipcRenderer.invoke('rdp:detail', routeId),

  /** Send Wake-on-LAN for a route */
  wol: (routeId) => ipcRenderer.invoke('rdp:wol', routeId),

  /** Get status (single or bulk if no routeId) */
  status: (routeId) => ipcRenderer.invoke('rdp:status', routeId),

  /** Get active sessions */
  activeSessions: () => ipcRenderer.invoke('rdp:active-sessions'),

  /** Toggle pin state */
  pinToggle: (pinned) => ipcRenderer.invoke('rdp:pin-toggle', pinned),

  /** Remote Desktops page opened (starts host status polling) */
  panelOpen: () => ipcRenderer.invoke('panel:open'),

  /** Remote Desktops page closed (stops host status polling) */
  panelClose: () => ipcRenderer.invoke('panel:close'),

  // ── Events from Main ────────────────────────────────
  onSessionStart: (cb) => subscribe('rdp:session-start', cb),
  onSessionEnd: (cb) => subscribe('rdp:session-end', cb),
  onSessionError: (cb) => subscribe('rdp:session-error', cb),
  onProgress: (cb) => subscribe('rdp:progress', cb),
  onServicesUpdate: (cb) => subscribe('rdp:services-update', cb),
  onSessionTimeoutWarning: (cb) => subscribe('rdp:session-timeout-warning', cb),
};

// ══════════════════════════════════════════════════════
//  Drive „Dateien bei Bedarf“ (gc-drive-sync.exe, main/drive-ondemand.js)
//  Oberfläche: renderer/drive-ondemand-view.js. Standardmäßig aus.
// ══════════════════════════════════════════════════════

api.driveOnDemand = {
  /** { state, enabled, supported, running, pending, transferring, errors, lastSync, syncRoot, registered, massDelete, progress, busy, launch, elevated } */
  status: () => ipcRenderer.invoke('drive-ondemand:status'),
  /** Einschalten (registriert die Sync-Root, startet das Programm). */
  enable: () => ipcRenderer.invoke('drive-ondemand:enable'),
  /** Ausschalten = Sync-Root abmelden; Fehler `relocated` / `unsynced` (mit data) lassen alles an. */
  disable: (force) => ipcRenderer.invoke('drive-ondemand:disable', { force: force === true }),
  setEnabled: (on) => ipcRenderer.invoke('drive-ondemand:set-enabled', on === true),
  syncNow: () => ipcRenderer.invoke('drive-ondemand:sync-now'),
  pause: () => ipcRenderer.invoke('drive-ondemand:pause'),
  resume: () => ipcRenderer.invoke('drive-ondemand:resume'),
  /** Massenlöschung: 'apply' (Löschen übertragen) | 'restore' (Wiederherstellen). */
  deletes: (decision) => ipcRenderer.invoke('drive-ondemand:deletes', decision),
  /** { localBytes, totalBytes, files, localFiles, pinnedFiles } */
  usage: () => ipcRenderer.invoke('drive-ondemand:usage'),
  /** { folders: [{ key, path, inDrive, from }], syncRoot } */
  knownFolders: () => ipcRenderer.invoke('drive-ondemand:known-folders'),
  relocate: (folder, name) => ipcRenderer.invoke('drive-ondemand:relocate', folder, name),
  restore: (folder) => ipcRenderer.invoke('drive-ondemand:restore', folder),
  openRoot: () => ipcRenderer.invoke('drive-ondemand:open-root'),
  /** W3a-Name von disable(). */
  unregister: () => ipcRenderer.invoke('drive-ondemand:unregister'),
  onStatus: (cb) => subscribe('drive-ondemand:status', cb),
  /** Explorer-Kontextmenü: { action: 'share' | 'versions', node, path } (Portal öffnet main selbst). */
  onAction: (cb) => subscribe('drive-ondemand:action', cb),
};

contextBridge.exposeInMainWorld('gatecontrol', api);
