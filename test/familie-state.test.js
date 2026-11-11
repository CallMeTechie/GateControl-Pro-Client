'use strict';

// View logic of the page "Familie" (src/renderer/familie-state.js, no DOM):
// the tabs of a parent and of a child, the card of a child in its states
// (pause → "Heute länger" → error → normal → not filtered) with its
// buttons, the note of a rule, the choices of "Pausieren" and "Heute
// länger", the rule list in words, the rule action "Internet zu Hause" —
// every other action of a rule stays as it is —, "Meine Anwesenheit", push
// targets; how the page loads the Familie scripts, that the view never uses
// innerHTML, and that every familie.* key it uses exists in the core locales.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const FS = require('../src/renderer/familie-state');

const ROOT = path.join(__dirname, '..');
const CORE_PKG = '@gatecontrol/client-core';
// Minimal t(): the key with its parameters.
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);
const ms = (iso) => Date.parse(iso);
// Wednesday, 11 November 2026, 17:52 in Berlin
const NOW = ms('2026-11-11T16:52:10Z');
const TZ = 'Europe/Berlin';
const ctx = (o = {}) => ({ now: NOW, tz: TZ, locale: 'de', manage: true, ...o });

const SCHEDULE = { from: ms('2026-11-11T20:00:00Z'), to: ms('2026-11-12T06:00:00Z'), block: 'categories', categories: ['social', 'games', 'video'], active: false };
const child = (o = {}) => ({
  userId: 4, name: 'Lea', avatarUrl: null, color: '#EAB308', initials: 'LE',
  presence: { state: 'home', since: ms('2026-11-11T15:40:00Z'), source: 'wifi' },
  paused: null, pausedBy: null, extended: null, extendedBy: null, nextSchedule: { ...SCHEDULE },
  profile: 'Kinder', devices: 2, filtered: true, error: null, ...o,
});

describe('time in the family\'s time zone', () => {
  it('hours, days and "tomorrow" follow the zone, not the PC', () => {
    assert.equal(FS.hm(NOW, TZ), '17:52');
    assert.equal(FS.hm(NOW, 'America/New_York'), '11:52');
    assert.equal(FS.dayOf(ms('2026-11-11T23:30:00Z'), TZ), '2026-11-12');
    assert.equal(FS.whenText(ms('2026-11-11T20:00:00Z'), ctx(), t), '21:00');
    assert.equal(FS.whenText(ms('2026-11-12T06:00:00Z'), ctx(), t), 'familie.when.tomorrow(07:00)');
    assert.equal(FS.whenText(ms('2026-11-10T21:10:00Z'), ctx(), t), 'familie.when.yesterday(22:10)');
    assert.match(FS.whenText(ms('2026-11-13T20:00:00Z'), ctx(), t), /^familie\.when\.day\(Fr\.?, 13\.11\.,21:00\)$/);
    assert.equal(FS.whenText(null, ctx(), t), '');
    assert.equal(FS.dateLong(NOW, ctx()), 'Mittwoch, 11. November');
    assert.equal(FS.dateLong(NOW, ctx({ locale: 'en' })), 'Wednesday 11 November');
    // an unknown zone name falls back to the PC's zone instead of throwing
    assert.match(FS.hm(NOW, 'Mars/Olympus'), /^\d\d:\d\d$/);
  });

  it('the server\'s clock decides: its time plus what passed since the answer', () => {
    const res = { internet: { serverTime: NOW }, fetchedAt: 1000 };
    assert.equal(FS.serverNow(res, 1000), NOW);
    assert.equal(FS.serverNow(res, 61000), NOW + 60000);
    assert.equal(FS.serverNow({ internet: { serverTime: null }, fetchedAt: 1000 }, 5000), 5000);
    assert.equal(FS.serverNow(null, 5000), 5000);
  });

  it('durations and lists in words', () => {
    assert.equal(FS.durationText(30, t), 'familie.dur.min(30)');
    assert.equal(FS.durationText(120, t), 'familie.dur.h(2)');
    assert.equal(FS.durationText(90, t), 'familie.dur.hm(1,30)');
    assert.equal(FS.durationText(0, t), '');
    assert.equal(FS.joinNames(['Tim'], t), 'Tim');
    assert.equal(FS.joinNames(['Tim', 'Lea', '', 'Mia'], t), 'Tim, Lea familie.and Mia');
  });
});

describe('tabs', () => {
  const status = (role, modules = { rules: true, presence: true }) => ({ state: 'available', me: { userId: 2, name: 'Anna', role }, modules });
  const net = (o) => ({ ok: true, internet: { available: true, manage: false, children: [], ...o } });

  it('parents: Internet zu Hause, Regeln, Meine Anwesenheit — as far as the modules are on', () => {
    assert.deepEqual(FS.tabsFor(status('parent'), null), ['internet', 'rules', 'presence']);
    assert.deepEqual(FS.tabsFor(status('parent', { rules: false, presence: true }), null), ['internet', 'presence']);
    assert.deepEqual(FS.tabsFor(status('parent', { rules: false, presence: false }), null), ['internet']);
  });

  it('a child sees its card only; without a card (grown up) its own presence', () => {
    assert.deepEqual(FS.tabsFor(status('child'), net({ children: [child()] })), ['internet']);
    assert.deepEqual(FS.tabsFor(status('child'), null), ['internet']);
    assert.deepEqual(FS.tabsFor(status('child'), net({ children: [] })), ['presence']);
    assert.deepEqual(FS.tabsFor(status('child', { rules: true, presence: false }), net({ children: [] })), ['internet']);
    // "Internet zu Hause" not on this server: the hint, not the presence tab
    assert.deepEqual(FS.tabsFor(status('child'), net({ available: false })), ['internet']);
    assert.deepEqual(FS.tabsFor(null, null), []);
    assert.deepEqual(FS.tabsFor(status('wall'), null), []);
  });
});

describe('the card of a child', () => {
  const paused = { paused: ms('2026-11-11T17:30:00Z'), pausedBy: { userId: 2, name: 'Anna', at: ms('2026-11-11T16:30:00Z'), rule: { id: 12, title: 'Abendessen' } } };
  const extended = { extended: ms('2026-11-11T20:30:00Z'), extendedBy: { userId: 3, name: 'Marc', at: ms('2026-11-11T15:50:00Z'), rule: null } };

  it('the state in the order of the portal card', () => {
    assert.equal(FS.cardState(child(), NOW), 'normal');
    assert.equal(FS.cardState(child(paused), NOW), 'paused');
    assert.equal(FS.cardState(child({ ...paused, ...extended, error: 'error', filtered: false }), NOW), 'paused');
    assert.equal(FS.cardState(child({ ...extended, error: 'error', filtered: false }), NOW), 'extended');
    assert.equal(FS.cardState(child({ error: 'unavailable', filtered: true }), NOW), 'error');
    assert.equal(FS.cardState(child({ filtered: false }), NOW), 'unfiltered');
    // a pause / extra time that is over does not count (the server's clock)
    assert.equal(FS.cardState(child(paused), ms('2026-11-11T17:30:00Z')), 'normal');
    assert.equal(FS.cardState(child({ ...extended, filtered: false }), ms('2026-11-11T21:00:00Z')), 'unfiltered');
  });

  it('buttons per state; none without the right to manage', () => {
    assert.deepEqual(FS.buttonsFor('normal', true), ['pause', 'extend']);
    assert.deepEqual(FS.buttonsFor('paused', true), ['resume', 'add30']);
    assert.deepEqual(FS.buttonsFor('extended', true), ['pause', 'extend30', 'endExtra']);
    assert.deepEqual(FS.buttonsFor('unfiltered', true), []);
    assert.deepEqual(FS.buttonsFor('error', true), ['reload']);
    for (const s of ['normal', 'paused', 'extended', 'error', 'unfiltered']) assert.deepEqual(FS.buttonsFor(s, false), []);
  });

  it('normal: Internet an, where the child is, the next blocked time, the number of devices', () => {
    const v = FS.cardView(child(), ctx(), t);
    assert.equal(v.state, 'normal');
    assert.deepEqual(v.chip, { cls: 'is-ok', text: 'familie.internet.chip.on' });
    assert.deepEqual(v.presence, { icon: 'wifi', text: 'familie.internet.presence.homeWifi' });
    assert.equal(v.sub, 'familie.internet.sub.next(21:00,familie.internet.cat.social, familie.internet.cat.games familie.and familie.internet.cat.video) · familie.internet.devices.other(2)');
    assert.equal(v.note, null);
    assert.deepEqual(v.buttons, ['pause', 'extend']);
    assert.equal(v.face.initials, 'LE');
    // everything blocked, one device, no times at all
    assert.match(FS.cardView(child({ devices: 1, nextSchedule: { ...SCHEDULE, block: 'all', categories: [] } }), ctx(), t).sub, /familie\.internet\.block\.all\) · familie\.internet\.devices\.one$/);
    assert.equal(FS.cardView(child({ nextSchedule: null, devices: 0 }), ctx(), t).sub, 'familie.internet.sub.noSchedule');
    // a blocked time that is running
    const run = FS.cardView(child({ nextSchedule: { ...SCHEDULE, from: ms('2026-11-11T15:00:00Z'), to: ms('2026-11-11T18:00:00Z'), active: true } }), ctx(), t);
    assert.deepEqual(run.chip, { cls: 'is-mute', text: 'familie.internet.chip.blocked(19:00)' });
    assert.deepEqual(run.buttons, ['pause', 'extend']);
  });

  it('presence: home with its source, away; nothing when it is not shared or unknown', () => {
    assert.deepEqual(FS.presenceChip({ state: 'home', source: 'app' }, t), { icon: 'phone', text: 'familie.internet.presence.homeApp' });
    assert.deepEqual(FS.presenceChip({ state: 'home', source: null }, t), { icon: 'home', text: 'familie.internet.presence.home' });
    assert.deepEqual(FS.presenceChip({ state: 'away', source: 'app' }, t), { icon: 'pin', text: 'familie.internet.presence.away' });
    assert.equal(FS.presenceChip({ state: 'not_shared' }, t), null);
    assert.equal(FS.presenceChip({ state: 'unknown' }, t), null);
    assert.equal(FS.presenceChip(null, t), null);
  });

  it('paused by a rule: the note names the rule, its owner and the time', () => {
    const v = FS.cardView(child({ ...paused, name: 'Tim' }), ctx(), t);
    assert.equal(v.state, 'paused');
    assert.deepEqual(v.chip, { cls: 'is-warn', text: 'familie.internet.chip.paused(18:30)' });
    assert.deepEqual(v.note, { ruleId: 12, text: 'familie.internet.byRule', title: 'familie.quoted(Abendessen)', tail: 'Anna · 17:30' });
    assert.equal(v.sub, 'familie.internet.pausedOn.other(2)');
    assert.deepEqual(v.buttons, ['resume', 'add30']);
    // a rule without a name
    const unnamed = FS.cardView(child({ paused: paused.paused, pausedBy: { ...paused.pausedBy, rule: { id: 13, title: '' } } }), ctx(), t);
    assert.deepEqual(unnamed.note, { ruleId: 13, text: 'familie.internet.byRuleUnnamed', title: null, tail: 'Anna · 17:30' });
  });

  it('paused by hand: only the person; set elsewhere (pausedBy null): nobody', () => {
    const v = FS.cardView(child({ paused: paused.paused, pausedBy: { userId: 3, name: 'Marc', at: ms('2026-11-11T16:30:00Z'), rule: null } }), ctx(), t);
    assert.equal(v.note, null);
    assert.equal(v.sub, 'familie.internet.pausedOn.other(2) familie.internet.by(Marc,17:30)');
    assert.equal(FS.cardView(child({ paused: paused.paused, devices: 1 }), ctx(), t).sub, 'familie.internet.pausedOn.one');
    // a pause only works at home
    assert.match(FS.cardView(child({ paused: paused.paused, presence: { state: 'away', since: null, source: 'app' } }), ctx(), t).sub, /familie\.internet\.awayPause\(Lea\)$/);
  });

  it('"Heute länger": until when, by whom, and that it works at home', () => {
    const v = FS.cardView(child({ ...extended, name: 'Mia', devices: 1, presence: { state: 'away', since: null, source: 'app' } }), ctx(), t);
    assert.equal(v.state, 'extended');
    assert.deepEqual(v.chip, { cls: 'is-info', text: 'familie.internet.chip.extended(21:30)' });
    assert.equal(v.sub, 'familie.internet.sub.suspended(21:00) · familie.internet.extBy(Marc,16:50) · familie.internet.devices.one · familie.internet.awayExtra(Mia)');
    assert.deepEqual(v.buttons, ['pause', 'extend30', 'endExtra']);
    assert.equal(FS.cardView(child({ ...extended, nextSchedule: null, extendedBy: null }), ctx(), t).sub, 'familie.internet.sub.suspendedAll · familie.internet.devices.other(2)');
  });

  it('not filtered and not readable: a hint, no pause buttons', () => {
    const none = FS.cardView(child({ filtered: false, devices: 0, presence: { state: 'not_shared', since: null, source: null }, nextSchedule: null }), ctx(), t);
    assert.deepEqual([none.state, none.chip.text, none.presence, none.sub, none.buttons], ['unfiltered', 'familie.internet.chip.unfiltered', null, 'familie.internet.sub.noDevices', []]);
    assert.equal(FS.cardView(child({ filtered: false, devices: 2 }), ctx(), t).sub, 'familie.internet.sub.noFilter(Lea)');
    const bad = FS.cardView(child({ error: 'unavailable' }), ctx(), t);
    assert.deepEqual([bad.state, bad.sub, bad.buttons, bad.presence], ['error', 'familie.internet.sub.error', ['reload'], null]);
  });

  it('a child (manage false) gets the same card without buttons', () => {
    for (const c of [child(), child(paused), child(extended), child({ error: 'error' })]) assert.deepEqual(FS.cardView(c, ctx({ manage: false }), t).buttons, []);
  });

  it('the next moment a card changes by itself', () => {
    assert.equal(FS.nextChange([child(), child(paused), child(extended)], NOW), paused.paused);
    assert.equal(FS.nextChange([child()], NOW), SCHEDULE.from);
    assert.equal(FS.nextChange([child({ nextSchedule: null })], NOW), null);
    assert.equal(FS.nextChange([child(paused)], paused.paused), SCHEDULE.from);
  });
});

describe('dialog "Pausieren"', () => {
  it('choices → what the API gets', () => {
    assert.deepEqual(FS.PAUSE_CHOICES, [30, 60, 120, 'until']);
    assert.deepEqual(FS.pauseArgs(30, ''), { minutes: 30 });
    assert.deepEqual(FS.pauseArgs(120, '19:00'), { minutes: 120 });
    assert.deepEqual(FS.pauseArgs('until', '19:00'), { until: '19:00' });
    assert.equal(FS.pauseArgs('until', ''), null);
    assert.equal(FS.pauseArgs('until', '24:00'), null);
    assert.equal(FS.pauseArgs(0, ''), null);
  });

  it('"bis Uhrzeit": the default lies ahead, a time already over means tomorrow', () => {
    assert.equal(FS.defaultUntil(NOW, TZ), '18:30');
    assert.equal(FS.defaultUntil(ms('2026-11-11T22:40:00Z'), TZ), '00:30');
    assert.equal(FS.untilTomorrow('19:00', NOW, TZ), false);
    assert.equal(FS.untilTomorrow('17:52', NOW, TZ), true);
    assert.equal(FS.untilTomorrow('07:00', NOW, TZ), true);
    assert.equal(FS.pauseHint('until', '19:00', 'Lea', ctx(), t), 'familie.pause.untilToday(19:00) familie.dialog.told(Lea)');
    assert.equal(FS.pauseHint('until', '07:00', 'Lea', ctx(), t), 'familie.pause.untilTomorrow(07:00) familie.dialog.told(Lea)');
    assert.equal(FS.pauseHint('until', '', 'Lea', ctx(), t), 'familie.pause.untilMissing');
    assert.equal(FS.pauseHint(30, '', 'Lea', ctx(), t), 'familie.pause.durHint(18:22) familie.dialog.told(Lea)');
  });
});

describe('dialog "Heute länger"', () => {
  it('a blocked time later today: from its start or from now', () => {
    assert.deepEqual(FS.EXTEND_CHOICES, [15, 30, 60]);
    assert.deepEqual(FS.extendPlan(child(), NOW, TZ), { choose: true, from: SCHEDULE.from, running: null });
    assert.equal(FS.hm(FS.extendEnd(child(), 30, false, NOW, TZ), TZ), '21:30');
    assert.equal(FS.hm(FS.extendEnd(child(), 30, true, NOW, TZ), TZ), '18:22');
    assert.equal(FS.extendHint(child(), 30, false, 'Lea', ctx(), t), 'familie.extend.hintSchedule(21:30) familie.dialog.told(Lea)');
    assert.equal(FS.extendHint(child(), 30, true, 'Lea', ctx(), t), 'familie.extend.hintNow(18:22) familie.dialog.told(Lea)');
  });

  it('no blocked time left today, one running, or an extra time running: no choice', () => {
    assert.equal(FS.extendPlan(child({ nextSchedule: null }), NOW, TZ).choose, false);
    assert.equal(FS.extendPlan(child({ nextSchedule: { ...SCHEDULE, from: ms('2026-11-12T20:00:00Z') } }), NOW, TZ).choose, false);
    assert.equal(FS.extendPlan(child({ nextSchedule: { ...SCHEDULE, from: ms('2026-11-11T15:00:00Z'), active: true } }), NOW, TZ).choose, false);
    assert.equal(FS.hm(FS.extendEnd(child({ nextSchedule: null }), 60, false, NOW, TZ), TZ), '18:52');
    // a running extra time is extended from its end
    const running = child({ extended: ms('2026-11-11T20:30:00Z') });
    assert.equal(FS.extendPlan(running, NOW, TZ).choose, false);
    assert.equal(FS.hm(FS.extendEnd(running, 30, false, NOW, TZ), TZ), '22:00');
  });
});

describe('rules', () => {
  const people = [{ userId: 2, name: 'Anna', role: 'parent' }, { userId: 4, name: 'Lea', role: 'child' }, { userId: 5, name: 'Tim', role: 'child' }, { userId: 6, name: 'Mia', role: 'child' }];
  const options = { people, internet: { available: true, reason: null, children: people.filter((p) => p.role === 'child') } };
  const net = (o) => ({ type: 'internet', op: 'pause', userId: 5, name: 'Tim', minutes: 30, until: null, available: true, problem: null, ...o });
  const withInput = (a, input) => ({ ...a, input });
  const rule = () => ({
    id: 12, title: 'Abendessen', scope: 'house', active: true, editable: true, pausable: true, ownerId: 2, ownerName: 'Anna',
    trigger: { type: 'schedule', weekdays: [1, 2, 3, 4, 5, 6, 7], time: '18:00' },
    actions: [
      withInput(net(), { type: 'internet', op: 'pause', userId: 5, minutes: 30 }),
      withInput({ type: 'quick_action', title: 'Küchenlicht', verb: 'Einschalten', available: null }, { type: 'quick_action', actionId: 'gatecontrol-smarthome/lamp.kitchen', title: 'Küchenlicht', state: 'on' }),
      withInput(net({ userId: 4, name: 'Lea', minutes: null, until: '18:30' }), { type: 'internet', op: 'pause', userId: 4, until: '18:30' }),
      withInput({ type: 'notify', to: [5, 4] }, { type: 'notify', to: [5, 4], text: 'Abendessen ist fertig', buttons: ['done'] }),
      withInput({ type: 'kaffee' }, { type: 'kaffee', machine: 3 }),
    ],
  });

  it('triggers in words', () => {
    const tr = (x) => FS.triggerText(x, people, 'de', t);
    assert.equal(tr({ type: 'schedule', weekdays: [1, 2, 3, 4, 5, 6, 7], time: '18:00' }), 'familie.rules.trig.daily(18:00)');
    assert.equal(tr({ type: 'schedule', weekdays: [1, 2, 3, 4, 5], time: '07:00' }), 'familie.rules.trig.days(Mo–Fr,07:00)');
    assert.equal(tr({ type: 'schedule', weekdays: [1, 3], time: '15:00' }), 'familie.rules.trig.days(Mo, Mi,15:00)');
    assert.equal(FS.triggerText({ type: 'schedule', weekdays: [6, 7], time: '09:00' }, people, 'en', t), 'familie.rules.trig.days(Sat, Sun,09:00)');
    assert.equal(tr({ type: 'person_home', userId: 6 }), 'familie.rules.trig.person_home(Mia)');
    assert.equal(tr({ type: 'person_away', userId: 99 }), 'familie.rules.trig.person_away(familie.rules.someone)');
    assert.equal(tr({ type: 'place_enter', placeName: 'Schule', userId: 5 }), 'familie.rules.trig.place_enter(Tim,Schule)');
    assert.equal(tr({ type: 'all_away', graceMinutes: 10 }), 'familie.rules.trig.all_away');
    assert.equal(tr({ type: 'school_change', userId: 4 }), 'familie.rules.trig.school(Lea)');
    assert.equal(tr({ type: 'school_change', userId: null }), 'familie.rules.trig.schoolAny');
    assert.equal(tr({ type: 'moon_phase' }), 'familie.rules.trig.other');
  });

  it('actions in words', () => {
    const a = (x) => FS.actionText(x, people, t);
    assert.equal(a(net()), 'familie.rules.act.pauseFor(Tim,familie.dur.min(30))');
    assert.equal(a(net({ minutes: null, until: '18:30' })), 'familie.rules.act.pauseUntil(Tim,18:30)');
    assert.equal(a(net({ op: 'resume' })), 'familie.rules.act.resume(Tim)');
    assert.equal(a(net({ name: null, userId: 6 })), 'familie.rules.act.pauseFor(Mia,familie.dur.min(30))');
    assert.equal(a({ type: 'notify', to: [5, 4] }), 'familie.rules.act.notifyTo(Tim familie.and Lea)');
    assert.equal(a({ type: 'notify', to: 'parents' }), 'familie.rules.act.notifyParents');
    assert.equal(a({ type: 'messenger', to: 'family' }), 'familie.rules.act.chatFamily');
    assert.equal(a({ type: 'quick_action', title: 'Küchenlicht', verb: 'Einschalten' }), 'familie.rules.act.quickVerb(Küchenlicht,Einschalten)');
    assert.equal(a({ type: 'quick_action', title: 'Tor', verb: null }), 'Tor');
    assert.equal(a({ type: 'kaffee' }), 'familie.rules.act.other');
  });

  it('a row: title, summary, switch and "Bearbeiten"', () => {
    const v = FS.ruleRow(rule(), options, 'de', t);
    assert.equal(v.title, 'Abendessen');
    assert.match(v.summary, /^familie\.rules\.trig\.daily\(18:00\) · familie\.rules\.act\.pauseFor\(Tim,/);
    assert.deepEqual([v.active, v.canToggle, v.canEdit, v.editOff, v.problems], [true, true, true, null, []]);
    assert.equal(FS.ruleRow({ ...rule(), title: ' ' }, options, 'de', t).title, 'familie.rules.untitled');
    // a child that is no minor of the family any more
    const gone = FS.ruleRow({ ...rule(), actions: [net({ userId: 9, name: 'Jonas', available: false, problem: 'not_found' })] }, options, 'de', t);
    assert.deepEqual(gone.problems, ['familie.rules.problem.not_found(Jonas)']);
    // another person's own rule: the switch only; a rule the person may not touch at all
    assert.deepEqual([FS.ruleRow({ ...rule(), editable: false }, options, 'de', t).canEdit, FS.ruleRow({ ...rule(), editable: false }, options, 'de', t).editOff], [false, 'readonly']);
    assert.equal(FS.ruleRow({ ...rule(), editable: false, pausable: false }, options, 'de', t).canToggle, false);
    // the action is not offered on this server (older plugin / GateControl) or to this person
    assert.equal(FS.ruleRow(rule(), { people, internet: { available: false, reason: 'unavailable', children: [] } }, 'de', t).editOff, 'unavailable');
    assert.equal(FS.ruleRow(rule(), { people, internet: { available: false, reason: 'parents_only', children: [] } }, 'de', t).editOff, 'parents_only');
    assert.equal(FS.ruleRow(rule(), null, 'de', t).editOff, 'unavailable');
    // ten other actions: no room for one more
    const full = { ...rule(), actions: new Array(10).fill(rule().actions[1]) };
    assert.equal(FS.ruleRow(full, options, 'de', t).editOff, 'full');
  });

  it('the form of the dialog ↔ the action', () => {
    assert.deepEqual(FS.internetActions(rule()).map((x) => x.index), [0, 2]);
    assert.deepEqual(FS.formOf(net(), options.internet.children), { userId: 5, op: 'pause', choice: 30, until: '' });
    assert.deepEqual(FS.formOf(net({ minutes: null, until: '18:30' }), []), { userId: 5, op: 'pause', choice: 'until', until: '18:30' });
    assert.deepEqual(FS.formOf(net({ op: 'resume', minutes: null }), []), { userId: 5, op: 'resume', choice: 30, until: '' });
    assert.deepEqual(FS.formOf(null, options.internet.children), { userId: 4, op: 'pause', choice: 30, until: '' });
    assert.deepEqual(FS.ruleChoices({ choice: 30 }), [30, 60, 120, 'until']);
    // a duration set elsewhere (45 min) stays selectable
    assert.deepEqual(FS.ruleChoices({ choice: 45 }), [30, 45, 60, 120, 'until']);
    assert.deepEqual(FS.actionBody({ userId: 5, op: 'pause', choice: 60, until: '' }), { type: 'internet', op: 'pause', userId: 5, minutes: 60 });
    assert.deepEqual(FS.actionBody({ userId: 5, op: 'pause', choice: 'until', until: '16:00' }), { type: 'internet', op: 'pause', userId: 5, until: '16:00' });
    assert.deepEqual(FS.actionBody({ userId: 5, op: 'resume', choice: 30, until: '16:00' }), { type: 'internet', op: 'resume', userId: 5 });
    assert.equal(FS.actionBody({ userId: 5, op: 'pause', choice: 'until', until: '' }), null);
    assert.equal(FS.actionBody({ userId: null, op: 'pause', choice: 30 }), null);
    assert.equal(FS.actionBody({ userId: 5, op: 'pause', choice: 1441 }), null);
  });

  it('saving changes one action; every other action goes back as the server sent it', () => {
    const r = rule();
    const body = { type: 'internet', op: 'pause', userId: 5, minutes: 60 };
    assert.deepEqual(FS.withAction(r, 0, body), [
      body,
      { type: 'quick_action', actionId: 'gatecontrol-smarthome/lamp.kitchen', title: 'Küchenlicht', state: 'on' },
      { type: 'internet', op: 'pause', userId: 4, until: '18:30' },
      { type: 'notify', to: [5, 4], text: 'Abendessen ist fertig', buttons: ['done'] },
      { type: 'kaffee', machine: 3 },
    ]);
    // a new action comes last, the order of the others stays
    const added = FS.withAction(r, null, { type: 'internet', op: 'resume', userId: 6 });
    assert.equal(added.length, 6);
    assert.deepEqual(added.slice(0, 5), r.actions.map((a) => a.input));
    assert.deepEqual(added[5], { type: 'internet', op: 'resume', userId: 6 });
    // removing one
    assert.deepEqual(FS.withAction(r, 2, null).map((a) => a.type), ['internet', 'quick_action', 'notify', 'kaffee']);
    // the rule itself is not touched
    assert.equal(r.actions.length, 5);
    assert.deepEqual(r.actions[0].input, { type: 'internet', op: 'pause', userId: 5, minutes: 30 });
  });

  it('never the wrong action, never an empty or too long list', () => {
    const r = rule();
    assert.equal(FS.withAction(r, 1, { type: 'internet', op: 'resume', userId: 5 }), null, 'index 1 is the lamp');
    assert.equal(FS.withAction(r, 9, null), null);
    assert.equal(FS.withAction(r, null, null), null);
    assert.equal(FS.withAction({ ...r, actions: [r.actions[0]] }, 0, null), null, 'the only action stays');
    assert.equal(FS.withAction({ ...r, actions: new Array(10).fill(r.actions[1]) }, null, { type: 'internet', op: 'resume', userId: 5 }), null);
    // an action without what the server needs back: nothing is saved rather than lost
    assert.equal(FS.withAction({ ...r, actions: [r.actions[0], { type: 'notify' }] }, 0, { type: 'internet', op: 'resume', userId: 5 }), null);
  });
});

describe('Meine Anwesenheit', () => {
  it('state and source', () => {
    assert.equal(FS.ownStateText({ state: 'home', since: ms('2026-11-11T15:40:00Z'), source: 'wifi' }, ctx(), t), 'familie.presence.state.homeSince(16:40)');
    assert.equal(FS.ownStateText({ state: 'away', since: null, source: 'app' }, ctx(), t), 'familie.presence.state.away');
    assert.equal(FS.ownStateText({ state: 'unknown' }, ctx(), t), 'familie.presence.state.unknown');
    assert.equal(FS.ownStateText(null, ctx(), t), 'familie.presence.state.not_shared');
    assert.equal(FS.sourceChip({ state: 'home', source: 'wifi' }, t).text, 'familie.presence.source.wifi');
    assert.equal(FS.sourceChip({ state: 'away', source: 'app' }, t).text, 'familie.presence.source.app');
    assert.equal(FS.sourceChip({ state: 'not_shared', source: null }, t), null);
    assert.equal(FS.sourceChip({ state: 'home', source: null }, t), null);
  });

  it('own devices: name, last seen, gateway, counts', () => {
    assert.deepEqual(FS.deviceRow({ id: 41, name: 'Annas Handy', lastSeen: ms('2026-11-11T16:50:00Z'), counts: true, gateway: 'Pi Keller' }, ctx(), t),
      { id: 41, name: 'Annas Handy', meta: 'familie.presence.devices.lastSeen(17:50) · Pi Keller', counts: true, countsText: 'familie.presence.devices.counts' });
    assert.deepEqual(FS.deviceRow({ id: 42, name: '', lastSeen: null, counts: false, gateway: null }, ctx(), t),
      { id: 42, name: 'familie.presence.devices.unnamed', meta: 'familie.presence.devices.never', counts: false, countsText: 'familie.presence.devices.countsNot' });
  });
});

describe('errors and push', () => {
  it('known codes have their text', () => {
    assert.equal(FS.errorText({ code: 'parents_only' }, t), 'familie.err.parents_only');
    assert.equal(FS.errorText({ code: 'http_502' }, t), 'familie.err.server');
    assert.equal(FS.errorText({ code: 'weird' }, t), 'familie.err.failed(weird)');
    assert.equal(FS.errorText(null, t), 'familie.err.failed(failed)');
  });

  it('an "Internet zu Hause" message is recognised, pause_over / extend_over included', () => {
    const entry = (kind, extra = {}) => ({ topic: 'plugin:gatecontrol-familie:internet', data: { route: 'plg-gatecontrol-familie', familie: { type: 'internet', kind, userId: 5, until: null, by: null, ...extra } } });
    assert.deepEqual(FS.entryContext(entry('pause', { ruleId: 12 })), { type: 'internet', kind: 'pause', userId: 5, ruleId: 12 });
    for (const kind of FS.PUSH_KINDS) assert.equal(FS.entryContext(entry(kind)).kind, kind);
    assert.ok(FS.PUSH_KINDS.includes('pause_over') && FS.PUSH_KINDS.includes('extend_over'));
    assert.deepEqual(FS.entryContext(entry('something_new')), { type: 'internet', kind: null, userId: 5, ruleId: null });
    // other topics of Familie and other plugins: not ours
    assert.equal(FS.entryContext({ topic: 'plugin:gatecontrol-familie:tasks', data: { route: 'plg-gatecontrol-familie', familie: { type: 'task' } } }), null);
    assert.equal(FS.entryContext({ topic: 'plugin:gatecontrol-schule:changes', data: { route: 'plg-gatecontrol-schule' } }), null);
    assert.equal(FS.entryContext(null), null);
  });

  it('where a context leads', () => {
    const all = ['internet', 'rules', 'presence'];
    assert.deepEqual(FS.openTarget({ type: 'internet', kind: 'pause_over', userId: 5 }, all), { tab: 'internet', childId: 5, ruleId: null });
    assert.deepEqual(FS.openTarget({ tab: 'rules', ruleId: 12 }, all), { tab: 'rules', childId: null, ruleId: 12 });
    assert.deepEqual(FS.openTarget({ tab: 'rules', ruleId: 12 }, ['internet']), { tab: 'internet', childId: null, ruleId: null });
    assert.deepEqual(FS.openTarget(null, ['presence']), { tab: 'presence', childId: null, ruleId: null });
    assert.deepEqual(FS.openTarget(null, []), { tab: 'internet', childId: null, ruleId: null });
  });
});

describe('page wiring', () => {
  const read = (...p) => fs.readFileSync(path.join(ROOT, 'src', 'renderer', ...p), 'utf8');
  const html = read('index.html');
  const view = read('familie-view.js');
  const state = read('familie-state.js');
  const renderer = read('renderer.js');

  it('loads state before view before renderer, has the page, the nav entry and the styles', () => {
    const i = (s) => html.indexOf(s);
    assert.ok(i('<script src="familie-state.js">') > 0);
    assert.ok(i('<script src="familie-state.js">') < i('<script src="familie-view.js">'));
    assert.ok(i('<script src="familie-view.js">') < i('<script src="renderer.js">'));
    assert.match(html, /id="page-familie"/);
    assert.match(html, /id="nav-familie"[^>]*data-page="familie"[^>]*hidden/);
    assert.match(html, /href="styles\/familie\.css"/);
    assert.ok(fs.existsSync(path.join(ROOT, 'src', 'renderer', 'styles', 'familie.css')));
  });

  it('the entry "Familie" sits between "Schule" and "GateDrop" and is hidden until the server offers it', () => {
    const navs = [...html.matchAll(/<button class="nav[^"]*" id="(nav-[a-z]+)"/g)].map((m) => m[1]);
    const at = navs.indexOf('nav-familie');
    assert.deepEqual(navs.slice(at - 1, at + 2), ['nav-schule', 'nav-familie', 'nav-gatedrop']);
    assert.match(renderer, /\$\('#nav-familie'\)\.hidden = !show/);
    assert.match(renderer, /const PAGES = \[[^\]]*'schule', 'familie', 'gatedrop'/);
  });

  it('server text never goes through innerHTML', () => {
    const code = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.doesNotMatch(code(view), /innerHTML|insertAdjacentHTML|outerHTML|document\.write/);
    assert.doesNotMatch(code(state), /innerHTML|document\./);
  });

  it('the styles use the app\'s tokens: no colours of their own beside the avatar', () => {
    const css = read('styles', 'familie.css').replace(/\/\*[\s\S]*?\*\//g, '');
    const hex = [...css.matchAll(/#[0-9a-fA-F]{3,8}\b/g)].map((m) => m[0].toUpperCase());
    assert.deepEqual([...new Set(hex)].sort(), ['#0B141C', '#64748B']);
    assert.doesNotMatch(css, /!important/);
  });

  it('every familie.* key of the view exists in the core locales (de and en)', (t2) => {
    let dir = null;
    try { dir = path.dirname(require.resolve(`${CORE_PKG}/package.json`, { paths: [ROOT] })); } catch {
      for (const d of [path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) if (fs.existsSync(path.join(d, 'src', 'i18n', 'locales', 'de.json'))) { dir = d; break; }
    }
    const loc = (l) => (dir ? JSON.parse(fs.readFileSync(path.join(dir, 'src', 'i18n', 'locales', `${l}.json`), 'utf8')) : null);
    const de = loc('de');
    if (!de || !de.familie) { t2.skip('core without familie.* (core.ref before Familie)'); return; }
    const en = loc('en');
    const get = (o, k) => k.split('.').reduce((x, p) => (x && typeof x === 'object' ? x[p] : undefined), o);
    const src = `${view}\n${state}\n${renderer}`;
    const keys = new Set([...src.matchAll(/['`](familie\.[a-zA-Z0-9_.]+[a-zA-Z0-9_])['`]/g)].map((m) => m[1]));
    // keys built from a variable part
    for (const tab of FS.TABS) keys.add(`familie.tab.${tab}`);
    for (const b of ['pause', 'extend', 'resume', 'add30', 'extend30', 'endExtra', 'reload']) keys.add(`familie.btn.${b}`);
    for (const c of ['social', 'games', 'video']) keys.add(`familie.internet.cat.${c}`);
    for (const k of ['byRule', 'extRule']) { keys.add(`familie.internet.${k}`); keys.add(`familie.internet.${k}Unnamed`); }
    for (const k of ['person_home', 'person_away', 'place_enter', 'place_exit']) keys.add(`familie.rules.trig.${k}`);
    for (const k of ['not_found', 'not_allowed', 'unavailable']) keys.add(`familie.rules.problem.${k}`);
    for (const k of ['readonly', 'parents_only', 'unavailable', 'full']) keys.add(`familie.rules.editOff.${k}`);
    for (const k of ['pause', 'resume']) keys.add(`familie.rules.dialog.op.${k}`);
    for (const k of ['home', 'homeSince', 'away', 'awaySince', 'unknown', 'not_shared']) keys.add(`familie.presence.state.${k}`);
    for (const e of ['network', 'timeout', 'forbidden', 'invalid', 'parents_only', 'not_found', 'unavailable', 'not_person', 'module_off', 'not_member', 'not_configured', 'auth', 'too_many', 'state_required', 'server', 'failed']) keys.add(`familie.err.${e}`);
    assert.ok(keys.size > 120, `found ${keys.size} keys`);
    for (const k of keys) {
      assert.equal(typeof get(de, k), 'string', `${k} missing in core de.json`);
      assert.equal(typeof get(en, k), 'string', `${k} missing in core en.json`);
    }
  });
});
