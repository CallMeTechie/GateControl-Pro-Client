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
 *
 * Stage 7 (plugin 1.5): the second switch "Bildschirm teilen" (also on Windows Home) — core ScreenShare sends this
 * PC's picture through GateControl's relay and, after "Ansehen und steuern" here, takes the helper's mouse and keyboard
 * (ScreenInput, SendInput). While a session runs, a bar at the top of the shared display (./screen-bar.js) says who
 * watches or controls, with "Nur ansehen" and "Beenden". Channels remote-host:screen (on/off), :screen-stop,
 * :screen-view-only; the switch is kept in the store (remote.screenShare).
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
 * @param {object} [o.electron] - { BrowserWindow, desktopCapturer, screen, session, powerMonitor } for "Bildschirm teilen"
 * @param {object} [o.bar] - the bar at the top (./screen-bar.js setupScreenBar), or null
 */
function setupRemoteHost({ core, apiClient, log, store, notificationCenter = null, rdpAllow, configPath, getMainWindow, showWindow = () => {}, appVersion = null, host = null,
  electron = null, bar = null }) {
  const api = host ? null : new core.RemoteHostApi({ apiClient, log });
  const screenShare = host ? null : createScreenShare({ core, api, apiClient, electron, log, appVersion });
  const rh = host || new core.RemoteHost({
    api,
    firewall: new core.RdpSessionFirewall({ log }),
    info: new core.WindowsRdpInfo({ log }),
    notificationCenter,
    screenShare,
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
    // stage 7: the bar at the top follows the session of "Bildschirm teilen"
    if (bar) {
      try { bar.update(s.screen ? s.screen.session : null); } catch (err) { log.warn('Screen bar failed:', err.message); }
    }
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

  /** Stage 7: "Bildschirm teilen" on / off (kept for the next start). */
  async function setScreen(on) {
    store.set('remote.screenShare', on === true);
    await rh.setScreen(on === true);
    return status();
  }

  /** App start: clean up the session rules, register when a switch is on. */
  async function start() {
    const wanted = store.get('tunnel.rdpAllow', false) === true;
    const screenWanted = store.get('remote.screenShare', false) === true;
    const s = await rh.start(wanted, screenWanted);
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
      // control only when the person chose it now ("Ansehen und steuern"); anything else is view
      await rh.decide(String(requestId || ''), decision === 'allow' ? 'allow' : 'deny', mode === 'control' ? 'control' : 'view');
      return status();
    },
    'remote-host:new-code': async () => { await rh.newCode(); return status(); },
    'remote-host:enable-rdp': async () => { await rh.enableRdpInWindows(); return status(); },
    'remote-host:screen': async (_, on) => setScreen(on === true),
    'remote-host:screen-stop': () => { rh.screenStop(); return status(); },
    'remote-host:screen-view-only': () => { rh.screenViewOnly(); return status(); },
  };

  // the bar's buttons act at once (input stops before anything goes over the network)
  if (bar) {
    bar.onStop(() => rh.screenStop());
    bar.onViewOnly(() => rh.screenViewOnly());
  }

  return { host: rh, toggle, start, status, channels, setScreen, stop: () => { rh.stop(); if (bar) bar.destroy(); if (screenShare) screenShare.capture.destroy(); } };
}

/**
 * Stage 7: the core parts of "Bildschirm teilen" — capture (a hidden window), SendInput (koffi), the sender of
 * gc-screen.v1. null without Electron or a core that does not have them (the switch is then not offered).
 */
function createScreenShare({ core, api, apiClient, electron, log, appVersion }) {
  if (!electron || !core.ScreenShare || !core.ScreenCapture || !core.ScreenInput) return null;
  let locked = false;
  try {
    if (electron.powerMonitor) {
      electron.powerMonitor.on('lock-screen', () => { locked = true; });
      electron.powerMonitor.on('unlock-screen', () => { locked = false; });
    }
  } catch { /* no lock events */ }
  const capture = new core.ScreenCapture({ electron, log });
  const input = new core.ScreenInput({ backend: core.ScreenInput.createWin32Backend(), isLocked: () => locked, log });
  return new core.ScreenShare({ api, capture, input, serverUrl: () => (apiClient && apiClient.serverUrl) || '', appVersion, log });
}

module.exports = { setupRemoteHost, createScreenShare };
