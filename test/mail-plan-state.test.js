'use strict';

// Mail 1.9.0 (free/busy, shared calendars, resources): the pure helpers of mail-state.js — the window and bars of a day,
// who cannot at the chosen time, the suggestions' chips, the planner's query, resources and their rules in words,
// booking cards (pill, time, lines, buttons), the shared calendars as calendars, the refusals of 1.9.0 in words, resources
// among an event's attendees — and the wiring (only with the features of `me`, every text in de and en).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const MS = require('../src/renderer/mail-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, params) => (params ? `${key}(${Object.entries(params).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const at = (y, mo, d, h = 0, mi = 0) => new Date(y, mo - 1, d, h, mi).getTime();

describe('mail-state – working hours (Mail 1.9.0, `PUT calendar/settings { workHours }`)', () => {
  it('only what the server takes: days 1…7 sorted, from before to, 00:00 as the end is 24:00', () => {
    assert.deepEqual(MS.workHoursOf([5, 1, 3, 3], '07:30', '16:00'), { days: [1, 3, 5], from: '07:30', to: '16:00' });
    assert.deepEqual(MS.workHoursOf([6], '20:00', '00:00'), { days: [6], from: '20:00', to: '24:00' });
    assert.deepEqual(MS.workHoursOf([6], '20:00', '24:00'), { days: [6], from: '20:00', to: '24:00' });
    assert.equal(MS.workHoursOf([], '08:00', '18:00'), null, 'at least one day');
    assert.equal(MS.workHoursOf([1], '18:00', '08:00'), null, 'from after to');
    assert.equal(MS.workHoursOf([1], '08:00', '08:00'), null);
    assert.equal(MS.workHoursOf([8, 0], '08:00', '18:00'), null);
    assert.equal(MS.workHoursOf([1], '', '18:00'), null, 'an empty time field');
    assert.deepEqual(MS.DEFAULT_WORK_HOURS, { days: [1, 2, 3, 4, 5], from: '08:00', to: '18:00' });
  });

  it('the mail settings show „Arbeitszeit“ next to „Frei/Gebucht für alle“ (only with freeBusy); every text in de and en', () => {
    const view = read('src', 'renderer', 'mail-view.js');
    assert.match(view, /workHoursRow\(prefs\.workHours \|\| MS\.DEFAULT_WORK_HOURS\)/);
    assert.match(view, /api\.calSettings\(\{ workHours: next \}\)/);
    for (const lang of ['de', 'en']) {
      const j = JSON.parse(read('src', 'i18n', `${lang}.json`));
      for (const k of ['workHours', 'workHoursHint', 'workHoursDays', 'workHoursFrom', 'workHoursTo', 'workHoursBad', 'workHoursNoDay', 'workHoursSaved']) {
        assert.equal(typeof j.mail.fb[k], 'string', `${lang} mail.fb.${k}`);
      }
    }
  });
});

describe('mail-state – free/busy (mockup Planer)', () => {
  it('the window of a day: the working hours, widened to the chosen time from its full hour', () => {
    const day = at(2026, 11, 5);
    assert.deepEqual(MS.fbWindow(day, null), { from: at(2026, 11, 5, 8), to: at(2026, 11, 5, 18) });
    assert.deepEqual(MS.fbWindow(day, { days: [4], from: '09:00', to: '17:00' }, at(2026, 11, 5, 7, 30), at(2026, 11, 5, 19)), { from: at(2026, 11, 5, 7), to: at(2026, 11, 5, 19) });
    assert.deepEqual(MS.fbWindow(day, { from: '08:00', to: '24:00' }), { from: at(2026, 11, 5, 8), to: at(2026, 11, 6) });
    assert.deepEqual(MS.fbWindow(day, null, at(2026, 11, 6, 7), at(2026, 11, 6, 8)), { from: at(2026, 11, 5, 8), to: at(2026, 11, 5, 18) }, 'another day: not widened');
    assert.deepEqual(MS.scaleHours(at(2026, 11, 5, 8), at(2026, 11, 5, 18)), [8, 10, 12, 14, 16, 18]);
    assert.deepEqual(MS.scaleHours(at(2026, 11, 5, 6), at(2026, 11, 6)), [6, 10, 14, 18, 22]);
  });

  it('a bar: blocks clipped and in order, gaps free (unknown for a grey row)', () => {
    const from = 0;
    const to = 100;
    assert.deepEqual(MS.barSegments([{ start: 50, end: 70, status: 'busy' }, { start: -10, end: 10, status: 'tentative' }, { start: 60, end: 80, status: 'busy' }], from, to).map((s) => [s.status, s.start, s.end, s.pct]),
      [['tentative', 0, 10, 10], ['free', 10, 50, 40], ['busy', 50, 70, 20], ['busy', 70, 80, 10], ['free', 80, 100, 20]]);
    assert.deepEqual(MS.barSegments([], 0, 10, 'unknown').map((s) => s.status), ['unknown']);
    assert.deepEqual(MS.barSegments([], 5, 5), []);
  });

  it('who cannot: „14:00 passt nicht für Tom (gebucht)“, „Zu dieser Zeit können alle“, unknown ones named', () => {
    const rows = [
      { kind: 'self', name: 'Max', state: 'ok', blocks: [] },
      { kind: 'person', name: 'Sabine', state: 'ok', blocks: [{ start: at(2026, 11, 5, 13), end: at(2026, 11, 5, 14, 30), status: 'tentative' }] },
      { kind: 'person', name: 'Tom', state: 'ok', blocks: [{ start: at(2026, 11, 5, 14), end: at(2026, 11, 5, 15), status: 'busy' }] },
      { kind: 'external', name: '', email: 'kunde@mueller.de', state: 'unknown', blocks: [] },
    ];
    const bad = MS.fbMessage(rows, at(2026, 11, 5, 14), at(2026, 11, 5, 15), t);
    assert.deepEqual(bad, { ok: false, text: 'mail.fb.clash(time=14:00,list=Tom (mail.fb.status.busy), Sabine (mail.fb.status.tentative))' });
    assert.deepEqual(MS.fbMessage(rows, at(2026, 11, 5, 15), at(2026, 11, 5, 16), t), { ok: true, text: 'mail.fb.allKnownFree(list=kunde)' });
    assert.deepEqual(MS.fbMessage(rows.slice(0, 3), at(2026, 11, 5, 15), at(2026, 11, 5, 16), t), { ok: true, text: 'mail.fb.allFree' });
    assert.equal(MS.fbMessage([{ kind: 'self', state: 'ok', blocks: [{ start: 0, end: at(2027, 1, 1), status: 'busy' }] }], at(2026, 11, 5, 9), at(2026, 11, 5, 10), t).text, 'mail.fb.clash(time=09:00,list=mail.fb.you (mail.fb.status.busy))');
    assert.deepEqual([MS.fbLabel(rows[0], t), MS.fbLabel(rows[2], t), MS.fbLabel(rows[3], t)], ['mail.fb.you', 'Tom', 'kunde']);
  });

  it('suggestions: „Do 15:00“ on the day, „Fr 6.11. 9:00“ on another; the head of the section', () => {
    const day = at(2026, 11, 5);
    assert.equal(MS.suggestionLabel(at(2026, 11, 5, 15), day, 'de'), 'Do 15:00');
    assert.equal(MS.suggestionLabel(at(2026, 11, 6, 9), day, 'de'), 'Fr 6.11. 9:00');
    assert.equal(MS.fbHead(day, MS.fbWindow(day, null), 'de', t), 'Do 5.11. · mail.fb.hours(from=08:00,to=18:00)');
  });

  it('the planner\'s query: the day, the times, attendees and resources once, the duration', () => {
    const q = MS.plannerQuery({ allDay: false, startDate: '2026-11-05', startTime: '14:00', endDate: '2026-11-05', endTime: '15:30', attendees: [{ email: 'tim@firma.de' }, { email: 'kaputt' }], resources: [{ email: 'resource-12@resources.gatecontrol.invalid' }, { email: 'tim@firma.de' }] });
    assert.deepEqual(q, { day: at(2026, 11, 5), allDay: false, start: at(2026, 11, 5, 14), end: at(2026, 11, 5, 15, 30), attendees: ['tim@firma.de', 'resource-12@resources.gatecontrol.invalid'], duration: 90 });
    assert.deepEqual(MS.plannerQuery({ allDay: true, startDate: '2026-11-05', endDate: '2026-11-06' }), { day: at(2026, 11, 5), allDay: true, start: null, end: null, attendees: [], duration: 60 });
    assert.equal(MS.plannerQuery({ startDate: 'x', startTime: '10:00' }), null);
  });
});

describe('mail-state – resources and bookings (mockups Ressource, Anfragen)', () => {
  const car = { id: 11, name: 'Firmenwagen Kombi', kind: 'vehicle', location: null, seats: null, equipment: null, approval: 'approval', approvers: ['Fuhrpark'], rules: { maxMinutes: 1440 } };
  const room = { id: 12, name: 'Besprechungsraum 1', kind: 'room', location: '2. OG', seats: 8, equipment: 'Bildschirm', approval: 'auto', approvers: [], rules: { maxMinutes: null } };

  it('a resource\'s line, its rules, the kinds\' chips, its busy times', () => {
    assert.equal(MS.resourceSub(car, t), 'mail.res.by(who=Fuhrpark) · mail.res.max(limit=mail.res.day1)');
    assert.equal(MS.resourceSub(room, t), '2. OG · mail.res.seats(n=8) · Bildschirm · mail.res.auto');
    assert.equal(MS.resourceSub({ ...car, approvers: [] }, t), 'mail.res.by(who=mail.res.approvers) · mail.res.max(limit=mail.res.day1)');
    assert.deepEqual([MS.maxText(2880, t), MS.maxText(240, t), MS.maxText(90, t)], ['mail.res.days(n=2)', 'mail.res.hours(n=4)', 'mail.res.hours(n=1.5)']);
    assert.deepEqual([MS.ruleText({ rule: 'max_duration', limit: 1440 }, t), MS.ruleText({ rule: 'horizon', limit: 30 }, t), MS.ruleText({ rule: 'hours', from: '08:00', to: '18:00' }, t)],
      ['mail.res.ruleMax(limit=mail.res.day1)', 'mail.res.ruleHorizon(n=30)', 'mail.res.ruleHours(from=08:00,to=18:00)']);
    assert.deepEqual(MS.resourceKinds([car, room]), ['all', 'room', 'vehicle', 'device']);
    assert.deepEqual(MS.resourceKinds([{ kind: 'other' }]), ['all', 'room', 'vehicle', 'device', 'other'], 'Sonstiges only when there is one');
    assert.deepEqual(MS.resourceBlocks({ busy: [{ start: 1, end: 2, status: 'busy' }, { start: 3, end: 4, status: 'pending' }] }), [{ start: 1, end: 2, status: 'busy' }, { start: 3, end: 4, status: 'tentative' }]);
    assert.deepEqual(MS.resourceSpan('2026-11-05', '12:00', '15:00'), { start: at(2026, 11, 5, 12), end: at(2026, 11, 5, 15) });
    assert.equal(MS.resourceSpan('2026-11-05', '15:00', '12:00'), null);
    assert.ok(MS.isResourceAddress('resource-11@resources.gatecontrol.invalid') && !MS.isResourceAddress('raum@firma.de'));
  });

  it('a booking\'s card: pill, time, lines and buttons', () => {
    const open = { id: 801, state: 'pending', start: at(2026, 11, 5, 12), end: at(2026, 11, 5, 15), allDay: false, violations: [], conflicts: [], canDecide: true, day: [{ start: at(2026, 11, 5, 8), end: at(2026, 11, 5, 10), status: 'busy' }] };
    const clash = { id: 802, state: 'pending', allDay: true, startDate: '2026-11-06', endDate: '2026-11-07', start: at(2026, 11, 6), end: at(2026, 11, 8), violations: [{ rule: 'max_duration', limit: 1440 }], conflicts: [{ start: at(2026, 11, 6, 8), end: at(2026, 11, 6, 10) }], canDecide: true };
    assert.deepEqual([MS.bookingPill(open), MS.bookingPill(clash)], [{ tone: 'warn', key: 'waiting' }, { tone: 'err', key: 'conflict' }]);
    assert.deepEqual(['confirmed', 'declined', 'cancelled'].map((state) => MS.bookingPill({ state }).key), ['confirmed', 'declined', 'cancelled']);
    assert.equal(MS.bookingWhen(open, 'de', t), 'Do 5.11. · 12:00 – 15:00');
    assert.equal(MS.bookingWhen(clash, 'de', t), 'Fr 6.11. – Sa 7.11. · mail.cal.allDay');
    assert.deepEqual(MS.bookingLines(open, t, 'de'), ['mail.res.freeOk']);
    assert.deepEqual(MS.bookingLines(clash, t, 'de'), ['mail.res.breaks(list=mail.res.ruleMax(limit=mail.res.day1))', 'mail.res.taken(list=08:00–10:00)']);
    const done = { state: 'confirmed', decidedBy: { name: 'Max' }, decidedAt: at(2026, 11, 4, 9, 5), override: true, comment: 'Ausnahme' };
    assert.deepEqual(MS.bookingLines(done, t, 'de'), ['mail.res.decidedBy(name=Max,when=Mi 4.11. 09:05) · mail.res.override', '„Ausnahme“']);
    // Freigeben / Trotzdem freigeben (a broken rule) / none (a conflict); Absagen of an own one not over
    assert.deepEqual(MS.bookingActions(open, 'open'), { decide: true, approve: 'approve', cancel: false });
    assert.deepEqual(MS.bookingActions({ ...clash, conflicts: [] }, 'open'), { decide: true, approve: 'anyway', cancel: false });
    assert.deepEqual(MS.bookingActions(clash, 'open'), { decide: true, approve: null, cancel: false });
    assert.deepEqual(MS.bookingActions({ ...open, canDecide: false }, 'open').decide, false);
    assert.deepEqual(MS.bookingActions(open, 'mine', at(2026, 11, 5, 9)), { decide: false, approve: null, cancel: true });
    assert.equal(MS.bookingActions(open, 'mine', at(2026, 11, 5, 16)).cancel, false, 'over: no calling off');
    assert.deepEqual(MS.bookingTabs(['resources', 'bookingRequests']), ['open', 'done', 'mine']);
    assert.deepEqual(MS.bookingTabs(['resources']), ['mine']);
    assert.deepEqual(MS.requestBlocks(open).map((b) => b.status), ['busy', 'ask']);
    assert.equal(MS.bookingsToast([{ state: 'pending', resource: { name: 'Firmenwagen' } }, { state: 'confirmed', resource: { name: 'Raum 1' } }], t), 'mail.res.requested(name=Firmenwagen) · mail.res.booked(name=Raum 1)');
    assert.equal(MS.bookingsToast([], t), null);
  });

  it('resources among an event\'s attendees: kept apart in the form, sent with the role resource', () => {
    const cals = [{ id: 1, writable: true }];
    const f = MS.eventForm({ eventId: 7, calendarId: 1, title: 'Sprint', start: at(2026, 11, 5, 14), end: at(2026, 11, 5, 15), attendees: [{ email: 'tim@firma.de', name: 'Tom' }, { email: 'resource-12@resources.gatecontrol.invalid', name: 'Raum 1', role: 'resource' }] }, {}, cals);
    assert.deepEqual([f.attendees, f.resources], [[{ name: 'Tom', email: 'tim@firma.de' }], [{ name: 'Raum 1', email: 'resource-12@resources.gatecontrol.invalid' }]]);
    assert.deepEqual(MS.eventBody(f).attendees, [{ email: 'tim@firma.de', name: 'Tom' }, { email: 'resource-12@resources.gatecontrol.invalid', name: 'Raum 1', role: 'resource' }]);
    assert.deepEqual(MS.eventBody({ ...f, resources: [] }).attendees, [{ email: 'tim@firma.de', name: 'Tom' }]);
  });

  it('the refusals of 1.9.0 in words (the rules in brackets)', () => {
    assert.equal(MS.errorText({ code: 'rule_violation', detail: { violations: [{ rule: 'max_duration', limit: 480 }] } }, t, 'de'), 'mail.err.rule_violation (mail.res.ruleMax(limit=mail.res.hours(n=8)))');
    assert.equal(MS.errorText({ code: 'resource_busy', detail: { conflicts: [] } }, t, 'de'), 'mail.err.resource_busy');
    assert.equal(MS.errorText({ code: 'not_bookable' }, t, 'de'), 'mail.err.not_bookable');
    assert.equal(MS.errorText({ code: 'already_decided' }, t, 'de'), 'mail.err.already_decided');
    assert.equal(MS.errorText({ code: 'not_supported', detail: { what: 'shared_attendees' } }, t, 'de'), 'mail.err.sharedAttendees');
    assert.equal(MS.errorText({ code: 'not_supported', detail: { what: 'resource_series' } }, t, 'de'), 'mail.err.resourceSeries');
    assert.equal(MS.errorText({ code: 'not_supported', detail: { what: 'teams' } }, t, 'de'), 'mail.err.not_supported');
    assert.equal(MS.errorText({ code: 'invalid', detail: { field: 'start', reason: 'past' } }, t, 'de'), 'mail.err.past');
  });
});

describe('mail-state – shared calendars (mockup Teilen)', () => {
  it('the shared calendars as calendars: colour, writable at „Bearbeiten“, shown; in GET events', () => {
    const shared = [{ id: 50, name: 'Urlaube', color: '#F28CC2', owner: { userId: 7, name: 'Sabine' }, level: 'read', via: 'user', group: null, visible: true, accepted: true },
      { id: 51, name: 'Team', color: '#5FD3E0', owner: { userId: 8, name: 'Tom' }, level: 'write', via: 'group', group: 'Vertrieb', visible: false, accepted: false }];
    const as = MS.sharedAsCalendars(shared);
    assert.deepEqual(as.map((c) => [c.id, c.writable, c.shared, c.source, c.visible]), [[50, false, 'read', 'local', true], [51, true, 'write', 'local', false]]);
    assert.equal(MS.itemColor({ calendarId: 50 }, as, []), '#F28CC2');
    assert.deepEqual(MS.visibleIds([{ id: 1, visible: true }], [{ id: 'familie', visible: true }], shared), [1, 50, 'familie']);
    assert.deepEqual(MS.visibleIds([{ id: 1, visible: true }], []), [1], 'without shared calendars as before');
    assert.equal(MS.sharedInfo(as[1], t), 'mail.share.info(owner=Tom,level=mail.share.levels.write) · mail.share.via(group=Vertrieb)');
    assert.deepEqual([MS.shareSub({ type: 'user', state: 'accepted' }, t), MS.shareSub({ type: 'user', state: 'pending' }, t), MS.shareSub({ type: 'group', members: 4 }, t)],
      ['mail.share.state.accepted', 'mail.share.state.pending', 'mail.share.members(n=4)']);
    // the menu's items are calendars (their own kind private / business stays as calKind): its menu has „Teilen“
    const g = MS.calendarGroups([{ id: 1, name: 'Privat', kind: 'private', accountId: null }], [], { accounts: [] }, t);
    assert.deepEqual([g[0].items[0].kind, g[0].items[0].calKind], ['calendar', 'private']);
    assert.deepEqual([MS.itemOpens({ eventId: null, shared: 'freebusy' }), MS.itemOpens({ eventId: 950, shared: 'read' }), MS.itemOpens({ overlayId: 'familie' })], [false, true, true]);
  });
});

describe('mail 1.9.0 wiring', () => {
  it('everything new hangs on the features of `me` and never writes HTML', () => {
    const view = read('src', 'renderer', 'calendar-view.js');
    for (const f of ['freeBusy', 'calendarSharing', 'resources', 'bookingRequests']) assert.match(view, new RegExp(`has\\('${f}'\\)`), f);
    assert.doesNotMatch(view, /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(/);
    const mv = read('src', 'renderer', 'mail-view.js');
    assert.match(mv, /api\.onResources/);
    assert.match(mv, /context\.kind === 'requests'/);
    assert.match(mv, /has\('freeBusy'\) && calendar/, 'the switch in the Mail settings only with freeBusy');
  });

  it('every text of 1.9.0 exists in de and en (also the ones built at runtime)', () => {
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const src = ['calendar-view.js', 'mail-view.js', 'mail-state.js'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set();
    for (const m of src.matchAll(/['"`](mail\.(?:fb|res|share)[A-Za-z0-9_.-]*)['"`]/g)) if (!m[1].endsWith('.')) keys.add(m[1]);
    const add = (pre, list) => { for (const x of list) keys.add(`${pre}.${x}`); };
    add('mail.fb.legend', ['free', 'busy', 'tentative', 'unknown', 'sel']);
    add('mail.fb.status', ['busy', 'tentative']);
    add('mail.res.kind', ['all', 'room', 'vehicle', 'device', 'other']);
    add('mail.res.tab', ['open', 'done', 'mine']);
    add('mail.res.empty', ['open', 'done', 'mine']);
    add('mail.res.pill', ['waiting', 'conflict', 'confirmed', 'declined', 'cancelled']);
    add('mail.share.levels', ['freebusy', 'read', 'write']);
    add('mail.share.state', ['accepted', 'pending']);
    add('mail.err', ['not_bookable', 'resource_busy', 'rule_violation', 'already_decided', 'past', 'notSupportedResource', 'resourceSeries', 'sharedAttendees', 'notSupportedShare']);
    assert.ok(keys.size > 90, `only ${keys.size} keys found`);
    for (const k of keys) {
      assert.ok(k in de, `de: ${k}`);
      assert.ok(k in en, `en: ${k}`);
    }
  });
});
