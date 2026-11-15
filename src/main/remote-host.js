'use strict';

/**
 * Fernzugriff stage 2 (plugin gatecontrol-remote 1.1): the switch "Remote Desktop erlauben"
 * registers this PC (core services/remote-host.js). 3389 opens per session for exactly one
 * counterpart; the code, "Ohne Code für Berechtigte" and the question of an incoming request
 * show in Settings › Sicherheit.
 *
 * A server without the plugin 1.1 (status `unavailable`): the old way stays — rdp-allow.js opens
 * 3389 for the whole VPN, as before.
 *
 * Kept free of module-level Electron access (the core classes, the window and the store are
 * passed in), so test/remote-host.test.js drives it with fakes.
 *
 * Renderer channels: remote-host:status / :share / :decide / :new-code / :enable-rdp;
 * events remote-host:state (status()) and remote-host:request (the question, or null).
 */

/**
 * @param {object} o
 * @param {object} o.core - { RemoteHost, RemoteHostApi, RdpSessionFirewall, WindowsRdpInfo } (core)
 * @param {object} o.apiClient
 * @param {object} o.log
 * @param {object} o.store
 * @param {object} [o.notificationCenter]
 * @param {object} o.rdpAllow - core RdpAllow (the old way)
 * @param {string} o.configPath - WireGuard config (rdp-allow.js needs the VPN subnet)
 * @param {() => object|null} o.getMainWindow
 * @param {Function} [o.showWindow]
 * @param {string} [o.appVersion]
 * @param {object} [o.host] - a RemoteHost (tests)
 */
function setupRemoteHost({ core, apiClient, log, store, notificationCenter = null, rdpAllow, configPath, getMainWindow, showWindow = () => {}, appVersion = null, host = null }) {
  const rh = host || new core.RemoteHost({
    api: new core.RemoteHostApi({ apiClient, log }),
    firewall: new core.RdpSessionFirewall({ log }),
    info: new core.WindowsRdpInfo({ log }),
    notificationCenter,
    log,
    appVersion,
  });

  let legacy = false; // rdp-allow.js active (server without the plugin 1.1)

  const send = (channel, payload) => {
    const w = getMainWindow();
    if (w && !w.isDestroyed?.()) w.webContents.send(channel, payload);
  };

  async function useLegacy(on) {
    if (on === legacy) return;
    legacy = on;
    try {
      if (on) await rdpAllow.enable(configPath);
      else await rdpAllow.disable();
    } catch (err) {
      log.warn('RDP allow (old way) failed:', err.message);
    }
  }

  rh.on('state', (s) => {
    // the server turned out to have no plugin 1.1 (e.g. after being offline at start): the old way
    if (s.enabled && s.status === 'unavailable') useLegacy(true);
    else if (s.enabled && s.status !== 'starting' && s.status !== 'offline') useLegacy(false);
    send('remote-host:state', { ...s, legacy });
  });
  rh.on('request', (r) => {
    send('remote-host:request', r);
    if (r) {
      showWindow();
      try { getMainWindow()?.flashFrame?.(true); } catch { /* no window */ }
    }
  });

  /** The switch in Settings › Sicherheit. */
  async function toggle(enabled) {
    store.set('tunnel.rdpAllow', enabled === true);
    if (enabled) {
      const s = await rh.enable();
      await useLegacy(s.status === 'unavailable');
      return status();
    }
    await rh.disable();
    legacy = true; // make useLegacy(false) remove the rule in any case
    await useLegacy(false);
    return status();
  }

  /** App start: clean up the session rules, register when the switch is on. */
  async function start() {
    const wanted = store.get('tunnel.rdpAllow', false) === true;
    const s = await rh.start(wanted);
    if (wanted && s.status === 'unavailable') {
      legacy = true;
      await rdpAllow.reconcile({ wanted: true, configPath }).catch((err) => log.warn('RDP allow reconcile failed:', err.message));
    } else {
      // no rule for the whole VPN while the PC is registered (an orphan of an older version goes)
      await rdpAllow.reconcile({ wanted: false, configPath }).catch((err) => log.warn('RDP allow reconcile failed:', err.message));
    }
    return status();
  }

  function status() { return { ...rh.status(), legacy }; }

  const channels = {
    'remote-host:status': () => status(),
    'remote-host:share': async (_, mode) => { await rh.setShareMode(mode === 'open' ? 'open' : 'code'); return status(); },
    'remote-host:decide': async (_, requestId, decision, mode) => {
      await rh.decide(String(requestId || ''), decision === 'allow' ? 'allow' : 'deny', mode === 'view' ? 'view' : 'control');
      return status();
    },
    'remote-host:new-code': async () => { await rh.newCode(); return status(); },
    'remote-host:enable-rdp': async () => { await rh.enableRdpInWindows(); return status(); },
  };

  return { host: rh, toggle, start, status, channels, stop: () => rh.stop() };
}

module.exports = { setupRemoteHost };
