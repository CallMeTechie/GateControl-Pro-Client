'use strict';

/**
 * The plugin "Medien" (gatecontrol-medien, app API v1) for the e2e suite of Medien (Medien-Plugin W2): the sources come
 * from the server, nothing is set up on the PC.
 *
 *   const md = server.setMedien({ jf, dav });   // support/jellyfin-mock.js, support/webdav-mock.js (each optional)
 *   md.tab = false                               // GET /api/v1/client/plugins names the plugin without `tab`
 *   md.log → [{ method, path, body }]
 *   md.version = '1.6.0'                         the plugin's version in the list (default 1.0.0)
 *   md.convert.items.set(itemId, { level, state, position, startsAt, percent, requested })   „Videos umwandeln“
 *                                                (v1/convert/status, v1/convert/request; only from version 1.6: else 404)
 *
 * GET v1/sources lists Jellyfin (localhost: "unterwegs" for the core, `away.mode: vpn`) and the WebDAV share;
 * v1/jellyfin/pair confirms the fake Jellyfin's Quick Connect (jf.state.qcConfirmed) as the plugin does with its API
 * key; v1/sources/{id}/secret gives the share's name and password. Names and addresses are made up.
 */

const BASE = 'plugins/gatecontrol-medien/api/';

function createMedien({ jf = null, dav = null } = {}) {
  const state = { tab: true, rev: 1, log: [], available: true, pairs: 0, version: '1.0.0', convert: { available: true, items: new Map() } };
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
  state.entry = () => ({ id: 'gatecontrol-medien', name: 'Medien', version: state.version, tab: state.tab ? { label: 'Medien' } : null });
  const convertOn = () => !/^1\.[0-5]\./.test(state.version) && !/^0\./.test(state.version);
  const convertItem = (id) => {
    const x = state.convert.items.get(id);
    if (!x) return null;
    return { id, sourceId: 'jf-1', level: x.level || null, reasons: x.reasons || [], devices: { phone: 'no', tv: 'no', windows: 'no' }, stalled: false,
      requested: x.requested === true, state: x.state || 'none', position: x.position ?? null, startsAt: x.startsAt ?? null, percent: x.percent ?? null };
  };
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
    if (convertOn() && method === 'GET' && path === 'v1/convert/status') {
      const ids = String((query && query.items) || '').split(',').filter(Boolean);
      if (ids.length > 100 || ids.some((x) => !/^[0-9a-f]{32}$/.test(x))) return send(400, { ok: false, v: 1, code: 'invalid', field: 'items' });
      const items = ids.map(convertItem).filter(Boolean);
      const states = Object.fromEntries(items.map((x) => [x.id, { state: x.state, position: x.position, startsAt: x.startsAt, percent: x.percent }]));
      return send(200, { ok: true, v: 1, available: state.convert.available, items, states });
    }
    if (convertOn() && method === 'POST' && path === 'v1/convert/request') {
      const x = body && typeof body.itemId === 'string' ? state.convert.items.get(body.itemId) : null;
      if (!x || !['convert', 'hint'].includes(x.level)) return send(404, { ok: false, v: 1, code: 'not_found' });
      x.requested = true;
      const it = convertItem(body.itemId);
      return send(200, { ok: true, v: 1, requested: true, requestedAt: new Date().toISOString(), state: it.state, position: it.position, startsAt: it.startsAt, percent: it.percent });
    }
    return send(404, { ok: false, v: 1, code: 'not_found' });
  };
  return state;
}

module.exports = { createMedien };
