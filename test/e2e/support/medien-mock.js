'use strict';

/**
 * The plugin "Medien" (gatecontrol-medien, app API v1) for the e2e suite of Medien (Medien-Plugin W2): the sources come
 * from the server, nothing is set up on the PC.
 *
 *   const md = server.setMedien({ jf, dav });   // support/jellyfin-mock.js, support/webdav-mock.js (each optional)
 *   md.tab = false                               // GET /api/v1/client/plugins names the plugin without `tab`
 *   md.log → [{ method, path, body }]
 *
 * GET v1/sources lists Jellyfin (localhost: "unterwegs" for the core, `away.mode: vpn`) and the WebDAV share;
 * v1/jellyfin/pair confirms the fake Jellyfin's Quick Connect (jf.state.qcConfirmed) as the plugin does with its API
 * key; v1/sources/{id}/secret gives the share's name and password. Names and addresses are made up.
 */

const BASE = 'plugins/gatecontrol-medien/api/';

function createMedien({ jf = null, dav = null } = {}) {
  const state = { tab: true, rev: 1, log: [], available: true, pairs: 0 };
  const sources = () => {
    const out = [];
    if (jf) {
      const address = `http://${jf.address}`;
      out.push({
        id: 'jf-1', kind: 'jellyfin', name: 'DS918+', serverId: 'e2e0server', version: '10.10.3', address, home: { address },
        away: { mode: 'vpn' }, user: { id: 'u1', name: 'mila' }, problem: null,
        device: { id: 'gc-e2eDevice0000000000', name: 'GateControl · Büro-PC' }, paired: state.pairs > 0, quickConnect: true, downloads: true, alwaysOriginal: false,
      });
    }
    if (dav) {
      out.push({ id: 'sh-1', kind: 'share', name: 'Filme', folder: 'filme', smb: null, webdav: { address: dav.address, certSha256: null }, user: dav.user, secretRev: 1, away: { mode: 'vpn' } });
    }
    return out;
  };
  state.entry = () => ({ id: 'gatecontrol-medien', name: 'Medien', version: '1.0.0', tab: state.tab ? { label: 'Medien' } : null });
  state.handle = ({ method, route, raw, query }, json) => {
    if (!route.startsWith(BASE)) return false;
    const send = (status, b) => { json(status, b); return true; };
    const path = route.slice(BASE.length);
    let body = null;
    try { body = raw && raw.length ? JSON.parse(raw.toString('utf8')) : null; } catch { body = null; }
    state.log.push({ method, path, body });
    if (!state.available) return send(404, { ok: false, code: 'not_found', reason: 'plugin_unavailable' });
    if (method === 'GET' && path === 'v1/sources') {
      const rev = `r${state.rev}`;
      if (query && query.since === rev) return send(200, { v: 1, rev, unchanged: true, at: new Date().toISOString() });
      return send(200, {
        v: 1, rev, at: new Date().toISOString(), media: true, maxOfflineDays: 90, offlineHintDays: 30,
        network: { rule: 'home_direct_away_vpn', vpnRequiredAway: true, home: { probes: [] } }, cast: { enabled: false }, sources: sources(),
      });
    }
    if (method === 'GET' && path === 'v1/sources/sh-1/secret' && dav) return send(200, { v: 1, user: dav.user, password: dav.password, rev: 1 });
    if (method === 'POST' && path === 'v1/jellyfin/pair' && jf) {
      state.pairs += 1;
      jf.state.qcConfirmed = true;
      return send(200, { v: 1, userId: 'u1', userName: 'mila', deviceId: 'gc-e2eDevice0000000000' });
    }
    if (method === 'POST' && (path === 'v1/jellyfin/paired' || /^v1\/sources\/[a-z0-9-]+\/report$/.test(path) || /^v1\/shares\/[a-z0-9-]+\/checked$/.test(path))) return send(200, { v: 1 });
    if (method === 'DELETE' && path === 'v1/jellyfin/device') return send(200, { v: 1, sources: [] });
    return send(404, { ok: false, v: 1, code: 'not_found' });
  };
  return state;
}

module.exports = { createMedien };
