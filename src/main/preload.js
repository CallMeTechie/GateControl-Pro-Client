/**
 * GateControl Pro -- Preload Script
 * Extends community client preload with RDP channels.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('gatecontrol', {
  // ── App ──────────────────────────────────────────────
  getVersion: () => ipcRenderer.invoke('app:version'),

  // ── Tunnel ───────────────────────────────────────────
  tunnel: {
    connect:    () => ipcRenderer.invoke('tunnel:connect'),
    disconnect: () => ipcRenderer.invoke('tunnel:disconnect'),
    getStatus:  () => ipcRenderer.invoke('tunnel:status'),
    onState:    (cb) => {
      const handler = (_, state) => cb(state);
      ipcRenderer.on('tunnel-state', handler);
      return () => ipcRenderer.removeListener('tunnel-state', handler);
    },
  },

  // ── Server ───────────────────────────────────────────
  server: {
    setup: (opts) => ipcRenderer.invoke('server:setup', opts),
    test:  (opts) => ipcRenderer.invoke('server:test', opts),
  },

  // ── Config ───────────────────────────────────────────
  config: {
    get:        (key)        => ipcRenderer.invoke('config:get', key),
    set:        (key, value) => ipcRenderer.invoke('config:set', key, value),
    getAll:     ()           => ipcRenderer.invoke('config:getAll'),
    importFile: ()           => ipcRenderer.invoke('config:import-file'),
    importQR:   (imageData)  => ipcRenderer.invoke('config:import-qr', imageData),
  },

  // ── WireGuard ────────────────────────────────────────
  wireguard: {
    check: () => ipcRenderer.invoke('wireguard:check'),
  },

  // ── Kill-Switch ──────────────────────────────────────
  killSwitch: {
    toggle: (enabled) => ipcRenderer.invoke('killswitch:toggle', enabled),
  },

  // ── Autostart ────────────────────────────────────────
  autostart: {
    set: (enabled) => ipcRenderer.invoke('autostart:set', enabled),
  },

  // ── Logs ─────────────────────────────────────────────
  logs: {
    get: () => ipcRenderer.invoke('logs:get'),
  },

  // ── Peer ─────────────────────────────────────────────
  peer: {
    onExpiry: (cb) => {
      const handler = (_, info) => cb(info);
      ipcRenderer.on('peer-expiry', handler);
      return () => ipcRenderer.removeListener('peer-expiry', handler);
    },
  },

  // ── Permissions ──────────────────────────────────────
  permissions: {
    get: () => ipcRenderer.invoke('permissions:get'),
  },

  // ── Traffic ──────────────────────────────────────────
  traffic: {
    stats: () => ipcRenderer.invoke('traffic:stats'),
  },

  // ── Services ─────────────────────────────────────────
  services: {
    list: () => ipcRenderer.invoke('services:list'),
  },

  // ── DNS ──────────────────────────────────────────────
  dns: {
    leakTest: () => ipcRenderer.invoke('dns:leak-test'),
    checkSystem: () => ipcRenderer.invoke('dns:check-system'),
  },

  // ── Update ───────────────────────────────────────────
  update: {
    check:   () => ipcRenderer.invoke('update:check'),
    install: () => ipcRenderer.invoke('update:install'),
    onReady: (cb) => {
      const handler = (_, info) => cb(info);
      ipcRenderer.on('update:ready', handler);
      return () => ipcRenderer.removeListener('update:ready', handler);
    },
  },

  // ── Shell ────────────────────────────────────────────
  shell: {
    openExternal: (url) => ipcRenderer.invoke('shell:open-external', url),
  },

  // ── Fenster ──────────────────────────────────────────
  window: {
    minimize: () => ipcRenderer.send('window:minimize'),
    close:    () => ipcRenderer.send('window:close'),
  },

  // ── Navigation ───────────────────────────────────────
  onNavigate: (cb) => {
    const handler = (_, page) => cb(page);
    ipcRenderer.on('navigate', handler);
    return () => ipcRenderer.removeListener('navigate', handler);
  },

  // ══════════════════════════════════════════════════════
  //  PRO: RDP Channels
  // ══════════════════════════════════════════════════════

  rdp: {
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

    /** Panel open (triggers window resize) */
    panelOpen: () => ipcRenderer.invoke('panel:open'),

    /** Panel close (triggers window resize) */
    panelClose: () => ipcRenderer.invoke('panel:close'),

    // ── Events from Main ────────────────────────────────
    onSessionStart: (cb) => {
      const handler = (_, data) => cb(data);
      ipcRenderer.on('rdp:session-start', handler);
      return () => ipcRenderer.removeListener('rdp:session-start', handler);
    },

    onSessionEnd: (cb) => {
      const handler = (_, data) => cb(data);
      ipcRenderer.on('rdp:session-end', handler);
      return () => ipcRenderer.removeListener('rdp:session-end', handler);
    },

    onSessionError: (cb) => {
      const handler = (_, data) => cb(data);
      ipcRenderer.on('rdp:session-error', handler);
      return () => ipcRenderer.removeListener('rdp:session-error', handler);
    },

    onProgress: (cb) => {
      const handler = (_, data) => cb(data);
      ipcRenderer.on('rdp:progress', handler);
      return () => ipcRenderer.removeListener('rdp:progress', handler);
    },

    onServicesUpdate: (cb) => {
      const handler = (_, data) => cb(data);
      ipcRenderer.on('rdp:services-update', handler);
      return () => ipcRenderer.removeListener('rdp:services-update', handler);
    },

    onSessionTimeoutWarning: (cb) => {
      const handler = (_, data) => cb(data);
      ipcRenderer.on('rdp:session-timeout-warning', handler);
      return () => ipcRenderer.removeListener('rdp:session-timeout-warning', handler);
    },
  },
});
