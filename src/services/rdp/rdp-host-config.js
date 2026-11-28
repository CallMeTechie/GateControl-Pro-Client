'use strict';

/**
 * Route of the server → the connect message for gc-rdp-host.exe (the successor of
 * RdpConfigBuilder.build for the GateControl window). Pure functions, covered by
 * test/rdp-host-config.test.js.
 *
 * Same target as the .rdp file of the mstsc way: the peer FQDN for internal routes (the server's
 * certificate CN, so CredSSP can send the credentials), the IP as the fallback the host tries when the
 * name does not resolve; the server-resolved connect_address for gateway / external routes.
 */

const GCRdpLocal = require('../../renderer/rdp-local-state');

/** { server, fallbackServer, port } as RdpConfigBuilder resolves full address / alternate full address. */
function targetOf(route) {
  const r = route || {};
  const ipHost = r.connect_address
    || (r.external_hostname && r.access_mode !== 'internal' ? r.external_hostname : r.host);
  const port = r.connect_port != null
    ? r.connect_port
    : (r.external_port && r.access_mode !== 'internal' ? r.external_port : (r.port || 3389));
  const useFqdn = r.access_mode !== 'external' && r.access_mode !== 'gateway' && !!r.peer_fqdn;
  const server = useFqdn ? r.peer_fqdn : ipHost;
  return { server, fallbackServer: useFqdn && ipHost && ipHost !== server ? ipHost : null, port: Number(port) || 3389 };
}

const PROFILE = { modem: 1, broadband: 2, lan: 7, auto: 7 };

/** The texts of the window in the app's language ({0}, {1} are filled in by the host). */
const TEXT_KEYS = [
  'title', 'connected', 'connecting', 'loggingIn', 'interrupted', 'disconnected', 'cancel', 'disconnect', 'clipboard',
  'clipboardPaused', 'clipboardTip', 'drivesOn', 'drivesOff', 'drivesTip', 'drivesAsk', 'cad', 'fullscreen', 'minimize',
  'window', 'windowTip', 'pin', 'fsHint', 'q4', 'q3', 'q2', 'q1', 'q0', 'stepVpn', 'stepReach', 'stepCreds', 'stepConnect',
  'stepLogin', 'memoryHint', 'reconnecting', 'errLabel', 'errTitle', 'errCode', 'retry', 'mstsc', 'close', 'remoteDesktop',
];

function hostTexts(t) {
  const out = {};
  if (typeof t !== 'function') return out;
  for (const k of TEXT_KEYS) {
    const key = `rdpWindow.host.${k}`;
    const v = t(key);
    if (typeof v === 'string' && v !== key) out[k] = v;
  }
  return out;
}

/**
 * The connect message. Credentials only in this message (stdin of the host), never on a command line.
 * @param {object} route     the server's connect data (peer_fqdn already picked)
 * @param {object} creds     { username, domain, password } (password may be null: the host asks)
 * @param {object} local     the local choice of this host ("Auf diesem PC"), restricted by the route
 * @param {object} [opts]    { theme, texts }
 */
function buildConnect(route, creds, local, opts = {}) {
  const r = route || {};
  const c = creds || {};
  const eff = GCRdpLocal.effective(r, local);
  const { server, fallbackServer, port } = targetOf(r);
  const gw = r.gateway_host ? { host: String(r.gateway_host), port: Number(r.gateway_port) || 443 } : null;
  return {
    type: 'connect',
    name: r.name || r.host || 'Remotedesktop',
    // shown at "Host erreichbar": the target in the network as the list shows it, never the server's address
    address: r.access_mode === 'gateway' ? '' : `${r.host}:${r.port || 3389}`,
    gateway_route: r.access_mode === 'gateway',
    server,
    fallbackServer,
    port,
    username: c.username || r.username || null,
    domain: c.domain || r.domain || null,
    password: c.password || null,
    promptForCredentials: !c.password,
    nla: r.nla_enabled !== false && r.nla_enabled !== 0,
    admin: GCRdpLocal.flag(r.admin_session, false),
    startProgram: !r.remote_app && typeof r.start_program === 'string' && r.start_program ? r.start_program : null,
    display: eff.display,
    keyboard: eff.keyboard,
    redirect: eff.redirect,
    allow: eff.allow,
    gateway: gw,
    performance: {
      connectionType: PROFILE[r.network_profile] || 7,
      bandwidthDetect: !r.bandwidth_limit,
      disableWallpaper: GCRdpLocal.flag(r.disable_wallpaper, false),
      disableThemes: GCRdpLocal.flag(r.disable_themes, false),
      disableAnimations: GCRdpLocal.flag(r.disable_animations, false),
    },
    theme: opts.theme === 'light' ? 'light' : 'dark',
    texts: opts.texts || {},
  };
}

/** A copy of the message for the log: no password, ever. */
function redact(msg) {
  if (!msg || typeof msg !== 'object') return msg;
  const { password, texts, ...rest } = msg; // eslint-disable-line no-unused-vars
  return { ...rest, password: password ? '***' : null };
}

// discReason values of the RDP control (IMsTscAxEvents::OnDisconnected) and ExtendedDisconnectReasonCode
const REASON = { dns: 260, timeout: 264, connectFailed: 516, socketClosed: 2308, logonFailed: 2055, noSuchUser: 2567, passwordExpired: 3335, accountLocked: 3591, accountRestricted: 2823 };
const EXT = { apiDisconnect: 1, apiLogoff: 2, idle: 3, logonTimeout: 4, replaced: 5, denied: 7, privileges: 9, freshCreds: 10 };

/**
 * Plain language for a disconnect the person did not cause (the error view of the window).
 * @returns {{ title: string, text: string, kind: string }}
 */
function describeDisconnect(reason, ext, controlText, t) {
  const tr = typeof t === 'function' ? t : (k) => k;
  const k = (kind) => ({ kind, title: tr(`rdpWindow.err.${kind}.title`), text: tr(`rdpWindow.err.${kind}.text`) });
  if (ext === EXT.replaced) return k('replaced');
  if (ext === EXT.idle) return k('idle');
  if (ext === EXT.apiDisconnect || ext === EXT.apiLogoff) return k('admin');
  if (ext === EXT.privileges || ext === EXT.denied) return k('denied');
  if (ext === EXT.logonTimeout) return k('logonTimeout');
  if (reason === REASON.logonFailed || reason === REASON.noSuchUser || ext === EXT.freshCreds) return k('logon');
  if (reason === REASON.passwordExpired || reason === REASON.accountLocked || reason === REASON.accountRestricted) return k('account');
  if (reason === REASON.dns || reason === REASON.timeout || reason === REASON.connectFailed) return k('unreachable');
  if (reason === REASON.socketClosed) return k('network');
  const generic = k('generic');
  if (typeof controlText === 'string' && controlText.trim()) generic.text = controlText.trim().slice(0, 500);
  return generic;
}

/** The end reason for the server's audit (≤ 40 characters). */
function endReasonOf(d) {
  if (!d) return 'error';
  if (d.byUser) return 'normal';
  if (d.ext === EXT.idle) return 'idle_timeout';
  if (d.ext === EXT.replaced) return 'replaced';
  if (d.reason === 3) return 'server';
  return 'error';
}

module.exports = { targetOf, buildConnect, redact, hostTexts, describeDisconnect, endReasonOf, TEXT_KEYS, REASON, EXT };
