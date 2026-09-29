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

/**
 * @param {Electron.IpcMain} ipcMain
 * @param {object} ctx - everything registerBaseHandlers needs, plus:
 * @param {Function} ctx.setLocale / ctx.getLocale / ctx.onLocaleChanged
 * @param {Function} ctx.checkSystemDns - async () => { connected, killSwitch, dnsServer, resolveOk }
 * @param {Function} ctx.setAutostart - async (enabled) => void (Task Scheduler)
 * @param {object} ctx.rdpManager
 * @param {object} ctx.rdpWolClient
 * @param {Function} ctx.setRdpPanelOpen - (open) => void
 * @returns {string[]} registered channels
 */
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
    'rdp:pin-toggle': (_, pinned) => {
      pinned = pinned === true;
      store.set('rdp.panelPinned', pinned);
      return pinned;
    },
  };

  return registerBaseHandlers(ipcMain, { ...ctx, getUpdater, overrides });
}

module.exports = { registerProIpc };
