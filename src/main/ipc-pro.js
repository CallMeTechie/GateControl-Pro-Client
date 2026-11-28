/**
 * GateControl Pro – IPC wiring
 *
 * The common channels (tunnel, config, server setup incl. setup codes,
 * config import with validation, shell:open-external filter, logs, …) come
 * from the hardened core registerBaseHandlers. Only Pro-specific channels and
 * the few Pro overrides are defined here and handed to core as `overrides`,
 * so every channel is registered exactly once (ipcMain.handle throws on a
 * second registration).
 *
 * Kept free of module-level Electron access so it can be unit-tested with a
 * fake ipcMain (test/ipc-pro.test.js).
 */

'use strict';

const { registerBaseHandlers } = require('@gatecontrol/client-core/src/ipc/base-handlers');
const { shortDeviceId } = require('./device-id');
const { driveOnDemandChannels } = require('./drive-ondemand');

/**
 * @param {Electron.IpcMain} ipcMain
 * @param {object} ctx - everything registerBaseHandlers needs, plus:
 * @param {Function} ctx.setLocale / ctx.getLocale / ctx.onLocaleChanged
 * @param {Function} ctx.checkSystemDns - async () => { connected, killSwitch, dnsServer, resolveOk }
 * @param {Function} ctx.setAutostart - async (enabled) => void (Task Scheduler)
 * @param {object} ctx.rdpManager
 * @param {object} ctx.rdpWolClient
 * @param {Function} ctx.setRdpPanelOpen - (open) => void
 * @param {Function} ctx.getMachineFingerprint - () => 64-hex fingerprint (core);
 *   only its 8-character short form is handed to the renderer
 * @param {object} [ctx.driveOnDemand] - ./drive-ondemand.js (drive-ondemand:* channels)
 * @param {object} [ctx.remoteHost] - ./remote-host.js (remote-host:* channels, Fernzugriff)
 * @param {object} [ctx.terminal] - ./terminal.js (remote-term:* channels, the SSH terminal)
 * @param {object} [ctx.mediaAwake] - ./media-awake.js (media-player:awake, Medien: no sleep while a film plays;
 *   video:awake, the same for the videos of Drive, the vault and the camera clips)
 * @returns {string[]} registered channels
 */
/** A video's key from renderer/video-awake.js ('v1', 'v2', …). */
const VIDEO_KEY = /^v[0-9]{1,9}$/;

const REMOTE_HOST_CHANNELS = ['remote-host:status', 'remote-host:share', 'remote-host:decide', 'remote-host:new-code', 'remote-host:enable-rdp',
  // stage 7: "Bildschirm teilen"
  'remote-host:screen', 'remote-host:screen-stop', 'remote-host:screen-view-only'];

const REMOTE_TERM_CHANNELS = ['remote-term:devices', 'remote-term:tmux', 'remote-term:tmux-kill', 'remote-term:tmux-kill-detached',
  'remote-term:open', 'remote-term:list', 'remote-term:focus'];

/** The remote-term:* channels (stage 3, the SSH terminal); without the service none of the devices and no session. */
function remoteTermChannels(term) {
  const off = {
    'remote-term:devices': () => ({ devices: [], sshRight: false }),
    'remote-term:tmux': () => ({ error: 'unavailable' }),
    'remote-term:tmux-kill': () => ({ error: 'unavailable' }),
    'remote-term:tmux-kill-detached': () => ({ error: 'unavailable' }),
    'remote-term:open': () => ({ error: 'unavailable' }),
    'remote-term:list': () => [],
    'remote-term:focus': () => false,
  };
  return Object.fromEntries(REMOTE_TERM_CHANNELS.map((c) => [c, term && term.channels && term.channels[c] ? term.channels[c] : off[c]]));
}

/** The remote-host:* channels; without the service each answers "off". */
function remoteHostChannels(rh) {
  const off = () => ({ enabled: false, status: 'off', code: null, request: null, legacy: false });
  return Object.fromEntries(REMOTE_HOST_CHANNELS.map((c) => [c, rh && rh.channels && rh.channels[c] ? rh.channels[c] : off]));
}

/** A route id from the renderer: a positive integer or a short id string. */
function validRouteId(id) {
  if (Number.isSafeInteger(id) && id > 0) return true;
  return typeof id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(id);
}

function registerProIpc(ipcMain, ctx) {
  const { store, log, apiClient, rdpManager, rdpWolClient } = ctx;
  const getUpdater = ctx.getUpdater || (() => null);

  const overrides = {
    // ── Locale ─────────────────────────────────────────────
    'locale:set': (_, locale) => {
      ctx.setLocale(locale);
      store.set('app.locale', ctx.getLocale());
      ctx.onLocaleChanged?.(ctx.getLocale());
    },
    'locale:get': () => ctx.getLocale(),

    // ── Pro overrides of core channels ─────────────────────
    // Renderer expects the raw server answer (vpnDns) and combines it with
    // dns:check-system itself.
    'dns:leak-test': () => apiClient?.dnsCheck(),
    // Manual check in Settings → About actively asks the server.
    'update:check': async () => {
      const updater = getUpdater();
      if (!updater) return null;
      return updater.check();
    },
    // requireAdministrator: login items don't start elevated apps → schtasks.
    'autostart:set': async (_, enabled) => {
      enabled = enabled === true;
      try {
        await ctx.setAutostart(enabled);
      } catch (err) {
        log.error('Autostart configuration failed:', err.message);
      }
      store.set('app.startWithWindows', enabled);
      return enabled;
    },

    // ── Pro-only channels ──────────────────────────────────
    'dns:check-system': () => ctx.checkSystemDns(),
    // Short device ID (first 8 hex) for Settings → About; never the full value.
    'app:device-id': () => shortDeviceId(ctx.getMachineFingerprint || (() => null), log),
    'peer:info': () => apiClient?.getPeerInfo(),

    // Host status is only polled while the Remote Desktops page is open.
    'panel:open': () => {
      ctx.setRdpPanelOpen?.(true);
      rdpManager?.startStatusPolling();
      return true;
    },
    'panel:close': () => {
      ctx.setRdpPanelOpen?.(false);
      rdpManager?.stopStatusPolling();
      return true;
    },

    'rdp:list': () => rdpManager.refreshServices(),
    'rdp:connect': (_, routeId, opts) => rdpManager.connect(routeId, opts),
    'rdp:disconnect': (_, routeId) => {
      rdpManager.disconnect(routeId);
      return true;
    },
    'rdp:detail': async (_, routeId) => {
      try {
        return await apiClient.getRdpConnect(routeId);
      } catch (err) {
        log.warn('RDP detail fetch failed:', err.message);
        return null;
      }
    },
    'rdp:wol': (_, routeId) => rdpWolClient.wake(routeId),
    'rdp:status': (_, routeId) => (routeId ? apiClient.getRdpStatus(routeId) : apiClient.getRdpBulkStatus()),
    'rdp:active-sessions': () => rdpManager.getActiveSessions(),
    // Remotedesktop im GateControl-Fenster (gc-rdp-host.exe): "Fenster anzeigen", „Auf diesem PC“ per host,
    // the app setting „Remotedesktop öffnen in“
    'rdp:focus': (_, routeId) => (validRouteId(routeId) ? rdpManager.focusWindow(routeId) : false),
    'rdp:local-get': (_, routeId) => (validRouteId(routeId)
      ? { local: rdpManager.getLocalSettings(routeId), hostAvailable: rdpManager.isHostAvailable() }
      : { local: {}, hostAvailable: false }),
    'rdp:local-set': (_, routeId, patch) => (validRouteId(routeId) && patch && typeof patch === 'object'
      ? rdpManager.setLocalSettings(routeId, patch) : {}),
    'rdp:open-in-get': () => ({ openIn: rdpManager.getOpenIn(), hostAvailable: rdpManager.isHostAvailable() }),
    'rdp:open-in-set': (_, mode) => rdpManager.setOpenIn(mode),
    'rdp:pin-toggle': (_, pinned) => {
      pinned = pinned === true;
      store.set('rdp.panelPinned', pinned);
      return pinned;
    },

    // ── Drive „Dateien bei Bedarf“ (gc-drive-sync.exe, ./drive-ondemand.js) ──
    // Immer registriert (die Preload-Brücke kennt sie); ohne Dienst „unsupported“.
    ...driveOnDemandChannels(ctx.driveOnDemand || null, log),

    // ── Fernzugriff: this PC as a host (./remote-host.js) ──
    // Always registered (the preload bridge knows them); without the service an answer of "off".
    ...remoteHostChannels(ctx.remoteHost || null),

    // ── Fernzugriff: the SSH terminal (./terminal.js) ──
    ...remoteTermChannels(ctx.terminal || null),

    // ── Medien: no sleep while a film plays (./media-awake.js): 'playing' | 'paused' | 'stopped' ──
    'media-player:awake': (_, state) => (ctx.mediaAwake ? ctx.mediaAwake.set(typeof state === 'string' ? state : '') : false),
    // the other videos (Drive, Tresor, camera clips — renderer/video-awake.js): the same blocker, each video its own
    // key (counted, one never frees another), no minute after a pause
    'video:awake': (_, key, state) => (ctx.mediaAwake && typeof key === 'string' && VIDEO_KEY.test(key)
      ? ctx.mediaAwake.set(typeof state === 'string' ? state : '', `video:${key}`, 0) : false),
  };

  return registerBaseHandlers(ipcMain, { ...ctx, getUpdater, overrides });
}

module.exports = { registerProIpc, REMOTE_HOST_CHANNELS, REMOTE_TERM_CHANNELS };
