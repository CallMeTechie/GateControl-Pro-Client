'use strict';

/**
 * The plugin gatecontrol-familie for the e2e mock server — the part the
 * Windows app uses ("Internet zu Hause", plugin 1.20.0; contract: the
 * plugin's app API):
 *
 *   GET  me                                   member, role, modules (403 not_member)
 *   GET  internet                             the children's cards
 *   POST internet/<childId>/pause|resume|extend
 *   GET  rules · rules/options                PATCH rules/<id> { active } | { actions }
 *   GET  presence                             PUT presence/consent { share }
 *   GET  presence/wifi                        PUT presence/wifi { enabled } · presence/wifi/devices/<id> { counts }
 *
 *   const fam = mock.setFamilie({
 *     version: '1.20.0',
 *     me: { userId: 2, name: 'Anna', role: 'parent' },   // null = not a member (403 not_member)
 *     modules: { rules: true, presence: true },
 *     internet: { available: true, manage: true, timezone: 'Europe/Berlin', children: [...] } | null (no route: plugin < 1.18.0),
 *     rules: [...], options: { internet: { available, reason, children }, people },
 *     presence: { members: [...], me: { share, places, wifi } },
 *     wifi: { available, consent, since, devices: [...] } | null (no route),
 *   });
 *   fam.log → [{ method, route, body }]
 *
 * Times are computed from `fam.now()` (the real clock unless the test sets
 * `fam.clock`), so pauses the test sets are really "running".
 */

const BASE = 'plugins/gatecontrol-familie/api/';
const MIN = 60000;

function createFamilie({ version = '1.20.0', me = { userId: 2, name: 'Anna', role: 'parent' }, modules = { rules: true, presence: true }, internet = null, rules = [], options = null, presence = null, wifi = null } = {}) {
  const state = { version, me, modules, internet, rules, options, presence, wifi, log: [], clock: null };
  state.now = () => (typeof state.clock === 'number' ? state.clock : Date.now());
  const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

  state.entry = () => ({ id: 'gatecontrol-familie', name: 'Familie', version: state.version, tab: { label: 'Familie' } });

  const child = (id) => (state.internet && state.internet.children.find((c) => String(c.userId) === String(id))) || null;
  const by = (rule = null) => ({ userId: state.me.userId, name: state.me.name, at: iso(state.now()), rule });

  /** The view of an action as `rules` answers it. */
  function actionView(a) {
    if (a.type !== 'internet') return a;
    const kids = (state.options && state.options.internet && state.options.internet.children) || [];
    const kid = kids.find((k) => k.userId === a.userId);
    return { type: 'internet', op: a.op, userId: a.userId, name: kid ? kid.name : (a.name || null), minutes: a.minutes == null ? null : a.minutes, until: a.until == null ? null : a.until, available: !!kid, problem: kid ? null : 'not_found' };
  }

  /** → true when the request was ours (answered). */
  state.handle = ({ method, route, raw }, json) => {
    if (!route.startsWith(BASE)) return false;
    const path = route.slice(BASE.length);
    let body = {};
    try { body = raw && raw.length ? JSON.parse(raw.toString('utf8')) : {}; } catch { body = {}; }
    state.log.push({ method, route: path, body });
    const refuse = (status, code, extra = {}) => { json(status, { ok: false, code, error: code, ...extra }); return true; };
    const ok = (data) => { json(200, { ok: true, ...data }); return true; };
    if (!state.me) return refuse(403, 'not_member');
    const parent = state.me.role === 'parent';
    const seg = path.split('/');

    if (path === 'me' && method === 'GET') return ok({ me: state.me, modules: state.modules, members: [], serverTime: iso(state.now()) });

    if (seg[0] === 'internet') {
      if (!state.internet) return refuse(404, 'not_found');
      if (seg.length === 1 && method === 'GET') return ok({ internet: { serverTime: iso(state.now()), timezone: 'Europe/Berlin', ...state.internet } });
      if (seg.length === 3 && method === 'POST') {
        if (!parent) return refuse(403, 'parents_only');
        if (!state.internet.available) return refuse(409, 'unavailable');
        const c = child(seg[1]);
        if (!c) return refuse(404, 'not_found');
        const now = state.now();
        if (seg[2] === 'pause') {
          const given = ['minutes', 'until', 'add'].filter((k) => body[k] !== undefined);
          if (given.length !== 1) return refuse(400, 'invalid');
          if (given[0] === 'minutes') c.paused = iso(now + body.minutes * MIN);
          else if (given[0] === 'add') c.paused = iso((c.paused && Date.parse(c.paused) > now ? Date.parse(c.paused) : now) + body.add * MIN);
          else if (/^\d\d:\d\d$/.test(body.until)) {
            // the next such time (UTC here: the tests only check that it lies ahead)
            const d = new Date(now);
            const [h, m] = body.until.split(':').map(Number);
            d.setUTCHours(h, m, 0, 0);
            if (d.getTime() <= now) d.setUTCDate(d.getUTCDate() + 1);
            c.paused = iso(d.getTime());
          } else c.paused = body.until;
          c.pausedBy = by();
        } else if (seg[2] === 'resume') {
          c.paused = null;
          c.pausedBy = null;
        } else if (seg[2] === 'extend') {
          if (!Number.isInteger(body.minutes) || body.minutes < 0) return refuse(400, 'invalid');
          if (body.minutes === 0) { c.extended = null; c.extendedBy = null; } else {
            const running = c.extended && Date.parse(c.extended) > now ? Date.parse(c.extended) : null;
            const s = c.nextSchedule;
            const base = running || (!body.fromNow && s && !s.active && Date.parse(s.from) > now ? Date.parse(s.from) : now);
            c.extended = iso(base + body.minutes * MIN);
            c.extendedBy = by();
          }
        } else return refuse(404, 'not_found');
        return ok({ child: c });
      }
      return refuse(404, 'not_found');
    }

    if (seg[0] === 'rules') {
      if (!state.modules.rules) return refuse(403, 'module_off');
      const view = (r) => ({ ...r, actions: r.actions.map(actionView) });
      if (seg.length === 1 && method === 'GET') return ok({ rules: state.rules.map(view), log: [], can: { house: parent, personal: parent }, open: [] });
      if (seg.length === 2 && seg[1] === 'options' && method === 'GET') return ok(state.options || { people: [] });
      if (seg.length === 2 && (method === 'PATCH' || method === 'PUT')) {
        const r = state.rules.find((x) => String(x.id) === seg[1]);
        if (!r) return refuse(404, 'not_found');
        if (!parent) return refuse(403, 'parents_only');
        if (body.active !== undefined) r.active = body.active === true;
        if (body.actions !== undefined) {
          if (!Array.isArray(body.actions) || !body.actions.length || body.actions.length > 10) return refuse(400, 'invalid', { field: 'actions' });
          const kids = (state.options && state.options.internet && state.options.internet.children) || [];
          for (let i = 0; i < body.actions.length; i++) {
            const a = body.actions[i];
            if (a.type === 'internet' && a.op && !kids.some((k) => k.userId === a.userId)) return refuse(400, 'invalid', { field: `actions.${i}.userId` });
          }
          r.actions = body.actions;
          r.ownerId = state.me.userId;
          r.ownerName = state.me.name;
        }
        return ok({ rule: view(r) });
      }
      return refuse(404, 'not_found');
    }

    if (seg[0] === 'presence') {
      if (!state.modules.presence || !state.presence) return refuse(403, 'module_off');
      const mine = state.presence.members.find((m) => m.userId === state.me.userId);
      if (seg.length === 1 && method === 'GET') return ok({ ...state.presence, home: [] });
      if (seg.length === 2 && seg[1] === 'consent' && method === 'PUT') {
        if (typeof body.share !== 'boolean') return refuse(400, 'invalid');
        state.presence.me.share = body.share;
        return ok({ consent: { share: body.share, places: false }, state: mine ? { userId: mine.userId, state: mine.state, home: mine.state === 'home', since: mine.since, source: mine.source } : null });
      }
      if (seg[1] === 'wifi') {
        if (!state.wifi) return refuse(404, 'not_found');
        if (seg.length === 2 && method === 'GET') return ok({ wifi: state.wifi });
        if (!state.wifi.available) return refuse(409, 'unavailable');
        if (seg.length === 2 && method === 'PUT') {
          if (typeof body.enabled !== 'boolean') return refuse(400, 'invalid');
          state.wifi.consent = body.enabled;
          state.presence.me.wifi = body.enabled;
          // without the Wi-Fi only the app's report counts
          if (mine && mine.state === 'home') mine.source = body.enabled ? 'wifi' : 'app';
          return ok({ wifi: state.wifi });
        }
        if (seg.length === 4 && seg[2] === 'devices' && method === 'PUT') {
          const d = state.wifi.devices.find((x) => String(x.id) === seg[3]);
          if (!d) return refuse(404, 'not_found');
          if (typeof body.counts !== 'boolean') return refuse(400, 'invalid');
          d.counts = body.counts;
          return ok({ wifi: state.wifi });
        }
      }
      return refuse(404, 'not_found');
    }
    return refuse(404, 'not_found');
  };
  return state;
}

module.exports = { createFamilie };
