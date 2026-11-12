'use strict';

// View logic of the card "DNS-Schutz" on the start page (src/renderer/dns-state.js,
// no DOM): no card unless the server reports a DNS protection; the card in
// its states (active, paused with the time left, filter down, not filtered,
// starting, not reachable), the durations the server allows, the note of a
// pause, the top blocked domains, the text of a failure; how the page loads
// the scripts, that the view never uses innerHTML, how main wires the tray
// and the outage notification, and that every dnsProtect.* key that is used
// exists in the core locales.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const DS = require('../src/renderer/dns-state');

const ROOT = path.join(__dirname, '..');
const CORE_PKG = '@gatecontrol/client-core';
// Minimal t(): the key with its parameters; remembers what was asked.
const asked = new Set();
const t = (key, p) => { asked.add(key); return p ? `${key}(${Object.values(p).join(',')})` : key; };
const ms = (iso) => Date.parse(iso);
// Thursday, 12 November 2026, 14:48:00 on the server
const NOW = ms('2026-11-12T13:48:00Z');
const hm = (iso) => DS.hm(ms(iso), 'de');
const ctx = (o = {}) => ({ now: NOW, locale: 'de', connected: true, ...o });

const MAY = { pause: true, resume: false, extend: false, reason: null, durations: [5, 30, 60], maxMinutes: 60, forever: false };
const data = (o = {}) => ({
  state: 'active',
  device: { peerId: 21, name: 'Annas Laptop', state: 'filtered', ownDns: null },
  profile: { name: 'Standard', safeSearch: false },
  pause: null,
  outage: null,
  counters: { scope: 'device', queries: 2106, blocked: 318, percent: 15.1 },
  top: [{ domain: 'googlesyndication.com', count: 74 }, { domain: 'doubleclick.net', count: 1061 }],
  may: { ...MAY },
  manage: false,
  serverTime: NOW,
  ...o,
});
const snap = (d = data(), o = {}) => ({ state: 'available', reason: null, plugin: 'gatecontrol-dns', filter: 'filtering', checkedAt: NOW, data: d, fetchedAt: NOW, stale: false, error: null, ...o });
const PAUSE = { scope: 'peer', until: ms('2026-11-12T14:12:00Z'), openEnd: false, since: ms('2026-11-12T13:42:00Z'), by: { userId: 2, name: 'Anna' }, byMe: true };
const paused = (o = {}, may = {}) => data({ state: 'paused', pause: { ...PAUSE, ...o }, may: { ...MAY, pause: false, resume: true, extend: true, ...may } });

describe('time and numbers', () => {
  it('the time left follows the server\'s clock, not the PC\'s', () => {
    const s = snap(paused());
    assert.equal(DS.remainingMs(s, NOW), 24 * 60000);
    assert.equal(DS.remainingMs(s, NOW + 10000), 24 * 60000 - 10000);
    // a PC clock one hour ahead: the answer came at "its" time, the rest is the same
    const off = snap(paused(), { fetchedAt: NOW + 3600000 });
    assert.equal(DS.remainingMs(off, NOW + 3600000 + 10000), 24 * 60000 - 10000);
    assert.equal(DS.remainingMs(snap(paused()), NOW + 99 * 60000), 0);
    assert.equal(DS.remainingMs(snap(paused({ until: null, openEnd: true })), NOW), null);
    assert.equal(DS.remainingMs(snap(), NOW), null);
  });

  it('countdown, durations, counters', () => {
    assert.equal(DS.countdown(24 * 60000 + 8000), '24:08');
    assert.equal(DS.countdown(24 * 60000 + 7001), '24:08');
    assert.equal(DS.countdown(3600000 + 5 * 60000), '1:05:00');
    assert.equal(DS.countdown(0), '00:00');
    assert.equal(DS.countdown(null), '');
    assert.equal(DS.durationText(30, t), 'dnsProtect.duration.minutes(30)');
    assert.equal(DS.durationText(1, t), 'dnsProtect.duration.minute');
    assert.equal(DS.durationText(60, t), 'dnsProtect.duration.hour');
    assert.equal(DS.durationText(240, t), 'dnsProtect.duration.hours(4)');
    assert.equal(DS.durationText(90, t), 'dnsProtect.duration.hm(1,30)');
    assert.equal(DS.num(2106, 'de'), '2.106');
    assert.equal(DS.num(2106, 'en'), '2,106');
    assert.match(DS.percent(15.1, 'de'), /^15,1\s%$/);
    assert.equal(DS.percent(15.1, 'en'), '15.1%');
    assert.match(DS.percent(0, 'de'), /^0\s%$/);
  });

  it('a clock that is off by a minute or more is corrected for the times shown', () => {
    const until = PAUSE.until;
    assert.equal(DS.onLocalClock(until, snap(paused())), until);
    assert.equal(DS.onLocalClock(until, snap(paused(), { fetchedAt: NOW + 700 })), until);
    assert.equal(DS.onLocalClock(until, snap(paused(), { fetchedAt: NOW - 7200000 })), until - 7200000);
  });
});

describe('the card', () => {
  it('no card: no DNS protection, switched off, nothing known yet', () => {
    for (const s of [null, snap(null, { state: 'unknown' }), snap(null, { state: 'unavailable', reason: 'old_server' }), snap(null, { state: 'unavailable', reason: 'none' }),
      snap(null, { state: 'error', reason: 'network' }), snap(null), snap(data({ state: 'off' }))]) {
      assert.equal(DS.cardView(s, ctx(), t), null);
      assert.equal(DS.topView(s, 'de'), null);
    }
  });

  it('active: counters and the durations the server allows', () => {
    const v = DS.cardView(snap(), ctx(), t);
    assert.deepEqual([v.state, v.tone, v.icon, v.sub], ['active', 'ok', 'shield', 'dnsProtect.sub.active']);
    assert.deepEqual(v.chip, { text: 'dnsProtect.chip.active', tone: 'ok', countdown: null });
    assert.deepEqual(v.counters.items.map((c) => [c.key, c.value.replace(/\s/g, ' ')]), [['queries', '2.106'], ['blocked', '318'], ['percent', '15,1 %']]);
    assert.equal(v.counters.note, '');
    assert.equal(v.pause.label, 'dnsProtect.pauseFor.device');
    assert.deepEqual(v.pause.choices.map((c) => [c.key, c.how, c.disabled]), [
      ['5', { minutes: 5 }, false], ['30', { minutes: 30 }, false], ['60', { minutes: 60 }, false], ['forever', { forever: true }, true],
    ]);
    assert.equal(v.pause.hint, 'dnsProtect.hint.foreverOff');
    assert.deepEqual([v.banner, v.paused, v.notes, v.retry], [null, null, [], false]);
  });

  it('durations: missing ones are greyed, 4 h only when offered, "Bis ich wieder einschalte" with the admin\'s consent', () => {
    const few = DS.cardView(snap(data({ may: { ...MAY, durations: [5], maxMinutes: 5 } })), ctx(), t).pause.choices;
    assert.deepEqual(few.map((c) => [c.key, c.disabled, !!c.title]), [['5', false, false], ['30', true, true], ['60', true, true], ['forever', true, false]]);
    const all = DS.cardView(snap(data({ may: { ...MAY, durations: [5, 30, 60, 240], maxMinutes: 10080, forever: true } })), ctx(), t);
    assert.deepEqual(all.pause.choices.map((c) => [c.key, c.disabled]), [['5', false], ['30', false], ['60', false], ['240', false], ['forever', false]]);
    assert.equal(all.pause.hint, 'dnsProtect.hint.endsSelf');
    // a token without a device: "deine Geräte"; whose numbers
    const person = DS.cardView(snap(data({ device: null, counters: { scope: 'person', queries: 10, blocked: 1, percent: 10 } })), ctx(), t);
    assert.deepEqual([person.pause.label, person.counters.note], ['dnsProtect.pauseFor.devices', 'dnsProtect.scope.person']);
    assert.equal(DS.cardView(snap(data({ counters: { scope: 'server', queries: 10, blocked: 1, percent: 10 } })), ctx(), t).counters.note, 'dnsProtect.scope.server');
  });

  it('pausing not allowed: the reason instead of the buttons', () => {
    const v = DS.cardView(snap(data({ may: { ...MAY, pause: false, reason: 'profile' } })), ctx(), t);
    assert.equal(v.pause, null);
    assert.deepEqual(v.banner, { tone: 'info', icon: 'lock', title: 'dnsProtect.banner.notAllowedTitle', text: 'dnsProtect.banner.profile' });
    assert.equal(DS.cardView(snap(data({ may: { ...MAY, pause: false, reason: 'admins_only' } })), ctx(), t).banner.text, 'dnsProtect.banner.admins_only');
    // no reason the card explains: the state only
    const plain = DS.cardView(snap(data({ may: { ...MAY, pause: false, reason: null } })), ctx(), t);
    assert.deepEqual([plain.pause, plain.banner, plain.state], [null, null, 'active']);
  });

  it('paused: until when, the time left, who, and what the server allows', () => {
    const v = DS.cardView(snap(paused()), ctx({ now: NOW + 2000 }), t);
    assert.deepEqual([v.state, v.tone, v.icon], ['paused', 'warn', 'shieldPause']);
    assert.equal(v.sub, `dnsProtect.sub.pausedUntil(${hm('2026-11-12T14:12:00Z')})`);
    assert.deepEqual(v.chip, { text: 'dnsProtect.chip.paused', tone: 'warn', countdown: '23:58' });
    assert.deepEqual(v.paused, {
      resume: true, extend: true, countdown: '23:58',
      note: `dnsProtect.note.byMe(${hm('2026-11-12T13:42:00Z')},dnsProtect.duration.minutes(30)) dnsProtect.note.device`,
    });
    assert.equal(v.pause, null);
    assert.equal(v.counters.items.length, 3);
    // by someone else (a parent, an admin)
    const other = DS.cardView(snap(paused({ byMe: false, by: { userId: 3, name: 'Marc' } }, { extend: false })), ctx(), t);
    assert.equal(other.paused.note, `dnsProtect.note.byOther(${hm('2026-11-12T13:42:00Z')},Marc,dnsProtect.duration.minutes(30)) dnsProtect.note.device`);
    assert.equal(other.paused.extend, false);
    assert.match(DS.cardView(snap(paused({ byMe: false, by: null })), ctx(), t).paused.note, /^dnsProtect\.note\.plain\(/);
    assert.equal(DS.cardView(snap(paused({ since: null })), ctx(), t).paused.note, 'dnsProtect.note.device');
    // a token without a device: all of the person's devices
    assert.match(DS.cardView(snap({ ...paused(), device: null }), ctx(), t).paused.note, / dnsProtect\.note\.devices$/);
  });

  it('paused without an end, and for all devices by an admin', () => {
    const open = DS.cardView(snap(paused({ until: null, openEnd: true }, { extend: false })), ctx(), t);
    assert.equal(open.sub, 'dnsProtect.sub.pausedOpenMe');
    assert.deepEqual([open.chip.countdown, open.paused.countdown, open.paused.extend, open.paused.resume], [null, null, false, true]);
    assert.equal(open.paused.note, `dnsProtect.note.byMeOpen(${hm('2026-11-12T13:42:00Z')}) dnsProtect.note.device`);
    assert.equal(DS.cardView(snap(paused({ until: null, openEnd: true, byMe: false, by: { userId: 1, name: 'Admin' } })), ctx(), t).sub, 'dnsProtect.sub.pausedOpenBy(Admin)');
    assert.equal(DS.cardView(snap(paused({ until: null, openEnd: true, byMe: false, by: null })), ctx(), t).sub, 'dnsProtect.sub.pausedOpen');
    // for all: only an admin switches it back on
    const all = DS.cardView(snap(paused({ scope: 'all', byMe: false, by: { userId: 1, name: 'Admin' } }, { resume: false, extend: false, reason: 'paused_for_all' })), ctx(), t);
    assert.deepEqual([all.paused.resume, all.paused.extend, all.paused.note], [false, false, 'dnsProtect.note.all']);
    // … an admin who may sees the usual note
    assert.match(DS.cardView(snap(paused({ scope: 'all' })), ctx(), t).paused.note, /^dnsProtect\.note\.byMe\(/);
  });

  it('the filter is down: the warning, the counters, no buttons', () => {
    const d = data({ state: 'fallback', outage: { since: ms('2026-11-12T13:31:00Z') }, may: { ...MAY, pause: false, reason: 'fallback' } });
    const v = DS.cardView(snap(d, { filter: 'fallback' }), ctx(), t);
    assert.deepEqual([v.state, v.tone, v.icon, v.sub], ['fallback', 'err', 'shieldX', `dnsProtect.sub.fallbackSince(${hm('2026-11-12T13:31:00Z')})`]);
    assert.deepEqual(v.chip, { text: 'dnsProtect.chip.fallback', tone: 'err', countdown: null });
    assert.deepEqual(v.banner, { tone: 'err', icon: 'warn', title: 'dnsProtect.banner.fallbackTitle', text: 'dnsProtect.banner.fallbackText' });
    assert.deepEqual([v.pause, v.paused, v.counters.items.length], [null, null, 3]);
    assert.equal(DS.cardView(snap(data({ state: 'fallback', outage: { since: null } })), ctx(), t).sub, 'dnsProtect.sub.fallback');
  });

  it('not filtered and starting: one line, no counters, no buttons', () => {
    const sub = (device) => DS.cardView(snap(data({ state: 'unfiltered', device, may: { ...MAY, pause: false, reason: 'not_filtered' } })), ctx(), t);
    assert.equal(sub({ peerId: 3, name: 'PC', state: 'ownDns', ownDns: '1.1.1.1' }).sub, 'dnsProtect.sub.ownDns(1.1.1.1)');
    assert.equal(sub({ peerId: 3, name: 'PC', state: 'ownDns', ownDns: null }).sub, 'dnsProtect.sub.ownDnsPlain');
    assert.equal(sub({ peerId: 3, name: 'PC', state: 'excluded', ownDns: null }).sub, 'dnsProtect.sub.excluded');
    assert.equal(sub({ peerId: 3, name: 'PC', state: 'disabled', ownDns: null }).sub, 'dnsProtect.sub.disabled');
    assert.equal(sub({ peerId: 3, name: 'PC', state: 'filtered', ownDns: null }).sub, 'dnsProtect.sub.unfiltered');
    assert.equal(sub(null).sub, 'dnsProtect.sub.noDevice');
    const v = sub(null);
    assert.deepEqual([v.chip.text, v.counters, v.pause, v.banner, v.icon], ['dnsProtect.chip.unfiltered', null, null, null, 'shieldOff']);
    const st = DS.cardView(snap(data({ state: 'starting', may: { ...MAY, pause: false, reason: 'off' } }), { filter: 'starting' }), ctx(), t);
    assert.deepEqual([st.chip.text, st.sub, st.counters, st.pause], ['dnsProtect.chip.starting', 'dnsProtect.sub.starting', null, null]);
  });

  it('the plugin in trouble: "nicht erreichbar" with a retry, or the last state with a note', () => {
    const none = DS.cardView(snap(null, { error: 'not_running' }), ctx(), t);
    assert.deepEqual([none.state, none.sub, none.chip.text, none.retry, none.counters], ['error', 'dnsProtect.unreachable', 'dnsProtect.chip.error', true, null]);
    const stale = DS.cardView(snap(data(), { stale: true, error: 'plugin_error' }), ctx(), t);
    assert.deepEqual([stale.state, stale.notes, stale.retry], ['active', ['dnsProtect.stale'], false]);
    assert.ok(stale.pause);
  });

  it('the tunnel is down: a note that only a connected device is filtered', () => {
    assert.deepEqual(DS.cardView(snap(), ctx({ connected: false }), t).notes, ['dnsProtect.disconnected']);
    assert.deepEqual(DS.cardView(snap(paused()), ctx({ connected: false }), t).notes, ['dnsProtect.disconnected']);
    assert.deepEqual(DS.cardView(snap(), ctx({ connected: undefined }), t).notes, []);
    // not where it would only confuse
    assert.deepEqual(DS.cardView(snap(data({ state: 'fallback', outage: { since: null } })), ctx({ connected: false }), t).notes, []);
    assert.deepEqual(DS.cardView(snap(data({ state: 'unfiltered' })), ctx({ connected: false }), t).notes, []);
  });

  it('top blocked domains: the rows, none yet, or no card', () => {
    assert.deepEqual(DS.topView(snap(), 'de'), [{ domain: 'googlesyndication.com', count: '74' }, { domain: 'doubleclick.net', count: '1.061' }]);
    assert.deepEqual(DS.topView(snap(data({ top: [] })), 'de'), []);
    assert.equal(DS.topView(snap(data({ top: null })), 'de'), null);
    assert.equal(DS.topView(snap(data({ state: 'unfiltered' })), 'de'), null);
    assert.equal(DS.topView(snap(data({ state: 'starting' })), 'de'), null);
    assert.equal(DS.topView(snap(paused()), 'de').length, 2);
  });

  it('a failed change: the plugin\'s sentence for a refusal, an own one for trouble', () => {
    assert.equal(DS.errorText({ ok: false, code: 'not_allowed', status: 403, error: 'Für dein Profil hat der Admin das Unterbrechen gesperrt.', reason: 'profile' }, t), 'Für dein Profil hat der Admin das Unterbrechen gesperrt.');
    assert.equal(DS.errorText({ ok: false, code: 'too_long', status: 403, error: 'Länger als 60 Minuten ist nicht erlaubt.' }, t), 'Länger als 60 Minuten ist nicht erlaubt.');
    assert.equal(DS.errorText({ ok: false, code: 'unavailable', status: 503, error: 'Der Filter-Dienst antwortet nicht.' }, t), 'Der Filter-Dienst antwortet nicht.');
    // codes instead of sentences never reach the person
    assert.equal(DS.errorText({ ok: false, code: 'off', status: 409, error: 'off' }, t), 'dnsProtect.error.failed');
    assert.equal(DS.errorText({ ok: false, code: 'http_403', status: 403, error: 'HTTP 403' }, t), 'dnsProtect.error.failed');
    assert.equal(DS.errorText({ ok: false, code: 'plugin_error', status: 502, error: 'upstream connect error' }, t), 'dnsProtect.error.unavailable');
    assert.equal(DS.errorText({ ok: false, code: 'network', status: null, error: 'network error' }, t), 'dnsProtect.error.network');
    assert.equal(DS.errorText({ ok: false, code: 'timeout', status: null, error: 'timeout' }, t), 'dnsProtect.error.timeout');
    assert.equal(DS.errorText({ ok: false, code: 'rate_limited', status: 429, error: 'Too many requests, slow down' }, t), 'dnsProtect.error.rate_limited');
    assert.equal(DS.errorText(null, t), 'dnsProtect.error.failed');
  });
});

describe('the page and main', () => {
  const read = (...p) => fs.readFileSync(path.join(ROOT, 'src', ...p), 'utf8');
  const html = read('renderer', 'index.html');
  const view = read('renderer', 'dns-view.js');
  const state = read('renderer', 'dns-state.js');
  const renderer = read('renderer', 'renderer.js');
  const main = read('main', 'main.js');
  const code = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

  it('the cards sit on the start page, hidden until the server reports a DNS protection; state loads before the view', () => {
    const page = html.slice(html.indexOf('id="page-status"'), html.indexOf('id="page-rdp"'));
    assert.match(page, /<section class="card dnsp" id="dns-protect"[^>]* hidden><\/section>\s*<section class="card dnsp-top" id="dns-protect-top"[^>]* hidden><\/section>/);
    assert.ok(page.indexOf('id="dns-protect"') > page.indexOf('class="card prot"') && page.indexOf('id="dns-protect"') < page.indexOf('id="bandwidth-section"'));
    assert.ok(html.indexOf('<script src="dns-state.js">') > 0 && html.indexOf('<script src="dns-state.js">') < html.indexOf('<script src="dns-view.js">') && html.indexOf('<script src="dns-view.js">') < html.indexOf('<script src="renderer.js">'));
    assert.match(html, /href="styles\/dns\.css"/);
    // no entry in the sidebar: a card, not a page
    assert.doesNotMatch(html, /id="nav-dns/);
    assert.match(renderer, /dnsProtectApi && window\.GCDnsView/);
  });

  it('server text never goes through innerHTML', () => {
    assert.doesNotMatch(code(view), /innerHTML|insertAdjacentHTML|outerHTML|document\.write/);
    assert.doesNotMatch(code(state), /innerHTML|document\./);
  });

  it('the styles use the app\'s tokens: no colours of their own', () => {
    const css = read('renderer', 'styles', 'dns.css').replace(/\/\*[\s\S]*?\*\//g, '');
    assert.deepEqual([...css.matchAll(/#[0-9a-fA-F]{3,8}\b|rgba?\(/g)].map((m) => m[0]), []);
    assert.doesNotMatch(css, /!important/);
  });

  it('main: the service only with a core that has it; the tray follows it; an outage becomes a notification', () => {
    assert.match(main, /dnsProtect = DnsProtectService \? new DnsProtectService\(/);
    assert.match(main, /dnsProtect\.on\('change', \(snapshot\) => \{[^}]*dnsProtectMenuItems\(\{ snapshot,[\s\S]{0,200}?updateTray\(trayState\);/);
    assert.match(main, /dnsProtect\.on\('outage', \(\) => notify\(t\('dnsProtect\.toast\.outageBody'\)/);
    assert.match(main, /dnsProtect && dnsProtectUtil \? dnsProtectUtil\.dnsProtectMenuItems\(/);
    assert.match(main, /dnsProtect\?\.start\(\)/);
    assert.match(main, /dnsProtect\?\.stop\(\)/);
    // the registration of the IPC channels (core registerBaseHandlers, opt-in)
    assert.match(main, /^\s+dnsProtect,$/m);
  });

  it('every dnsProtect.* key that is used exists in the core locales (de and en), and none is left over', (t2) => {
    let dir = null;
    try { dir = path.dirname(require.resolve(`${CORE_PKG}/package.json`, { paths: [ROOT] })); } catch {
      for (const d of [path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) if (fs.existsSync(path.join(d, 'src', 'i18n', 'locales', 'de.json'))) { dir = d; break; }
    }
    const loc = (l) => (dir ? JSON.parse(fs.readFileSync(path.join(dir, 'src', 'i18n', 'locales', `${l}.json`), 'utf8')) : null);
    const de = loc('de');
    if (!de || !de.dnsProtect) { t2.skip('core without dnsProtect.* (core.ref before DNS-Schutz)'); return; }
    const en = loc('en');
    const get = (o, k) => k.split('.').reduce((x, p) => (x && typeof x === 'object' ? x[p] : undefined), o);
    // what the tests above asked for, what the sources name, and the keys built from a variable part
    const keys = new Set([...asked].filter((k) => k.startsWith('dnsProtect.')));
    for (const m of `${view}\n${state}\n${main}\n${html}`.matchAll(/['"`](dnsProtect\.[a-zA-Z0-9_.]+[a-zA-Z0-9_])['"`]/g)) keys.add(m[1]);
    for (const m of [5, 30, 60, 240]) { keys.add(`dnsProtect.dur.${m}`); keys.add(`dnsProtect.tray.minutes.${m}`); }
    for (const e of ['network', 'timeout', 'unavailable', 'rate_limited', 'failed']) keys.add(`dnsProtect.error.${e}`);
    for (const k of ['byMe', 'byOther', 'plain']) { keys.add(`dnsProtect.note.${k}`); keys.add(`dnsProtect.note.${k}Open`); }
    // the tray entries are built by the core (utils/dns-protect.js)
    for (const k of ['active', 'pausedUntil', 'paused', 'fallback', 'unfiltered', 'pause', 'resume']) keys.add(`dnsProtect.tray.${k}`);
    assert.ok(keys.size > 70, `found ${keys.size} keys`);
    for (const k of keys) {
      assert.equal(typeof get(de, k), 'string', `${k} missing in core de.json`);
      assert.equal(typeof get(en, k), 'string', `${k} missing in core en.json`);
    }
    const flat = (o, p, out = []) => { for (const [k, v] of Object.entries(o)) { if (v && typeof v === 'object') flat(v, `${p}.${k}`, out); else out.push(`${p}.${k}`); } return out; };
    assert.deepEqual(flat(de.dnsProtect, 'dnsProtect').filter((k) => !keys.has(k)), []);
  });
});
