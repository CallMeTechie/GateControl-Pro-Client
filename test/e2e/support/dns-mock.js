'use strict';

/**
 * The DNS protection of the VPN devices for the e2e mock server — what the
 * Windows app uses of the plugin gatecontrol-dns 1.0.0 (contract: the
 * plugin's README "App-API") and of the server from 1.264.0:
 *
 *   GET  /api/v1/client/permissions      `vpnDns: { plugin, state }` | null (the mock server adds it)
 *   GET  status                          state of this device, counters, top domains, `may`
 *   POST pause  { minutes } | { forever: true } | { extend }
 *   POST resume {}
 *
 *   const dns = mock.setDns({
 *     plugin: 'gatecontrol-dns',
 *     filter: 'filtering' | 'starting' | 'fallback' | null,   // null → permissions says `vpnDns: null`
 *     may: { durations: [5, 30, 60], maxMinutes: 60, forever: false, reason: null },
 *     device: { peerId, name, state, ownDns } | null,
 *     counters: { scope, queries, blocked, percent }, top: [...] | null,
 *     me: { userId, name },
 *   });
 *   dns.log → [{ method, route, body, lang }]
 *   dns.fail = { status, code, error }   // every plugin call is refused like this (null: none)
 *
 * Without `mock.setDns()` the permissions answer has no `vpnDns` field at
 * all (a server before 1.264.0). Times come from `dns.now()` (the real clock
 * unless the test sets `dns.clock`), so pauses are really "running".
 */

const MIN = 60000;

function createDns({
  plugin = 'gatecontrol-dns', filter = 'filtering',
  may = {}, device = { peerId: 21, name: 'Annas Laptop', platform: 'windows', state: 'filtered', ownDns: null },
  counters = { scope: 'device', queries: 2106, blocked: 318, percent: 15.1 },
  top = [{ domain: 'googlesyndication.com', count: 74 }, { domain: 'doubleclick.net', count: 61 }, { domain: 'scorecardresearch.com', count: 38 }],
  me = { userId: 2, name: 'Anna' }, outageSince = null,
} = {}) {
  const state = {
    plugin, filter, device, counters, top, me, outageSince,
    may: { durations: [5, 30, 60], maxMinutes: 60, forever: false, reason: null, ...may },
    pause: null, // { scope, until (ms | null), openEnd, since (ms), by }
    log: [], fail: null, clock: null,
  };
  state.now = () => (typeof state.clock === 'number' ? state.clock : Date.now());
  const iso = (ms) => new Date(ms).toISOString();
  const base = () => `plugins/${state.plugin}/api/`;

  /** What GET permissions says: null = no DNS protection. */
  state.vpnDns = () => (state.filter ? { plugin: state.plugin, state: state.filter } : null);

  function running() {
    const p = state.pause;
    if (p && !p.openEnd && p.until <= state.now()) state.pause = null;
    return state.pause;
  }

  state.status = () => {
    const p = running();
    const now = state.now();
    const unfiltered = !state.device || state.device.state !== 'filtered';
    const st = state.filter === 'fallback' ? 'fallback' : state.filter === 'starting' ? 'starting' : unfiltered ? 'unfiltered' : p ? 'paused' : 'active';
    const blocked = state.may.reason;
    const forAll = !!p && p.scope === 'all';
    const reason = st === 'fallback' ? 'fallback' : st === 'starting' ? 'off' : unfiltered ? (state.device ? 'not_filtered' : 'no_device') : forAll ? 'paused_for_all' : blocked;
    const can = st === 'active' && !blocked;
    return {
      state: st,
      enabled: true,
      device: state.device,
      profile: { id: 'p1a2b3c4d', name: 'Standard', safeSearch: false },
      pause: st === 'paused' ? {
        scope: p.scope, until: p.openEnd ? null : iso(p.until), openEnd: p.openEnd, since: iso(p.since), by: p.by, byMe: !!p.by && p.by.userId === state.me.userId,
        remainingSeconds: p.openEnd ? null : Math.max(0, Math.round((p.until - now) / 1000)),
      } : null,
      outage: st === 'fallback' ? { since: state.outageSince || iso(now - 17 * MIN) } : null,
      counters: state.counters,
      top: state.top,
      may: {
        pause: can, resume: st === 'paused' && !forAll, extend: st === 'paused' && !forAll && !p.openEnd && !blocked,
        reason: can ? null : reason || null, durations: state.may.durations, maxMinutes: state.may.maxMinutes, forever: state.may.forever,
      },
      today: [], devices: [], manage: false, log: { enabled: true, visible: true },
      serverTime: iso(now),
    };
  };

  /** → true when the request was ours (answered). */
  state.handle = ({ method, route, raw, query }, json) => {
    if (!route.startsWith(base())) return false;
    const path = route.slice(base().length);
    let body = {};
    try { body = raw && raw.length ? JSON.parse(raw.toString('utf8')) : {}; } catch { body = {}; }
    state.log.push({ method, route: path, body, lang: (query && query.lang) || null });
    const refuse = (status, code, extra = {}) => { json(status, { ok: false, code, error: code, ...extra }); return true; };
    const ok = (data) => { json(200, { ok: true, ...data }); return true; };
    if (state.fail) return refuse(state.fail.status, state.fail.code, state.fail.error ? { error: state.fail.error } : {});
    if (!state.filter) return refuse(409, 'off');

    if (path === 'status' && method === 'GET') return ok(state.status());

    if (path === 'pause' && method === 'POST') {
      const given = ['minutes', 'forever', 'extend'].filter((k) => body[k] !== undefined);
      if (given.length !== 1) return refuse(400, 'invalid');
      if (state.filter === 'fallback') return refuse(409, 'not_filtering', { error: 'Der Filter ist ausgefallen.' });
      if (state.may.reason) return refuse(403, 'not_allowed', { reason: state.may.reason, error: 'Unterbrechen ist für dich nicht erlaubt.' });
      const now = state.now();
      const by = { userId: state.me.userId, name: state.me.name };
      if (given[0] === 'forever') {
        if (!state.may.forever) return refuse(403, 'forever_not_allowed', { error: '„Bis ich wieder einschalte“ hat dein Admin nicht freigegeben.' });
        state.pause = { scope: 'peer', until: null, openEnd: true, since: now, by };
      } else {
        const n = body[given[0]];
        if (!Number.isInteger(n) || n < 1) return refuse(400, 'invalid');
        const p = running();
        const from = given[0] === 'extend' && p && !p.openEnd ? p.until : now;
        const until = from + n * MIN;
        if (until - (given[0] === 'extend' && p ? p.since : now) > state.may.maxMinutes * MIN) return refuse(403, 'too_long', { error: `Länger als ${state.may.maxMinutes} Minuten ist nicht erlaubt.` });
        state.pause = { scope: 'peer', until, openEnd: false, since: given[0] === 'extend' && p ? p.since : now, by };
      }
      const status = state.status();
      return ok({ pause: status.pause, status });
    }

    if (path === 'resume' && method === 'POST') {
      const p = running();
      if (p && p.scope === 'all') return refuse(403, 'not_allowed', { reason: 'paused_for_all', error: 'Nur ein Admin schaltet wieder ein.' });
      state.pause = null;
      return ok({ resumed: !!p, status: state.status() });
    }

    return refuse(404, 'not_found');
  };

  return state;
}

module.exports = { createDns };
