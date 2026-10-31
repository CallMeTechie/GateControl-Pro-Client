'use strict';

// Mail Phase 2 (calendar and contacts): the pure helpers of mail-state.js (ranges of the views, the day grid with
// overlapping events, times, recurrence and reminder texts, the event form and its body, the series' times,
// invitation states; letter sections, birthdays, the contact form, merge choices, suggestions) and the wiring of the
// areas (index.html, the views without HTML strings, every text in de and en).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const MS = require('../src/renderer/mail-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, params) => (params ? `${key}(${Object.entries(params).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const at = (y, mo, d, h = 0, mi = 0) => new Date(y, mo - 1, d, h, mi).getTime();
const HOUR = 3600000;

describe('mail-state – calendar', () => {
  it('ranges of the views: a week from Monday (or Sunday), the work week, the month as six weeks, the list', () => {
    const wed = at(2026, 11, 4, 15);
    const w = MS.viewRange('week', wed, { weekStart: 1 });
    assert.deepEqual([w.days.length, w.from, w.to], [7, at(2026, 11, 2), at(2026, 11, 9)]);
    assert.equal(MS.viewRange('week', wed, { weekStart: 0 }).from, at(2026, 11, 1));
    const ww = MS.viewRange('week', wed, { weekStart: 1, workWeek: true });
    assert.deepEqual([ww.days.length, ww.to], [5, at(2026, 11, 7)]);
    const m = MS.viewRange('month', wed, { weekStart: 1 });
    assert.deepEqual([m.days.length, m.from, m.month], [42, at(2026, 10, 26), 10]);
    assert.ok(m.to - m.from <= 62 * 24 * HOUR, 'one request');
    assert.deepEqual(MS.viewRange('day', wed), { from: at(2026, 11, 4), to: at(2026, 11, 5), days: [at(2026, 11, 4)] });
    assert.equal(MS.viewRange('list', wed).to, at(2026, 12, 4));
    // over the change to winter time the days stay midnights
    const dst = MS.viewRange('week', at(2026, 10, 25, 12), { weekStart: 1 });
    assert.ok(dst.days.every((d) => new Date(d).getHours() === 0));
    assert.equal(MS.shiftAnchor('month', at(2026, 1, 31), 1), at(2026, 2, 1), 'the 1st of the next month');
    assert.equal(new Date(MS.shiftAnchor('week', wed, -1)).getDate(), 28);
    assert.equal(new Date(MS.shiftAnchor('day', wed, 1)).getDate(), 5);
    assert.match(MS.rangeTitle('month', m, wed, 'de'), /November 2026/);
    assert.match(MS.rangeTitle('week', w, wed, 'de'), /^2\. – 8\. Nov\. 2026$/);
    assert.match(MS.rangeTitle('week', MS.viewRange('week', at(2026, 11, 30), { weekStart: 1 }), 0, 'de'), /30\. Nov\. – 6\. Dez\. 2026/);
  });

  it('the day grid: overlapping events side by side, at least 20 minutes, clipped to the day; all-day ones by date', () => {
    const day = at(2026, 11, 4);
    const ev = (key, h1, m1, h2, m2) => ({ key, start: at(2026, 11, 4, h1, m1), end: at(2026, 11, 4, h2, m2), allDay: false });
    const blocks = MS.layoutDay([ev('a', 10, 0, 11, 0), ev('b', 10, 30, 12, 0), ev('c', 11, 0, 11, 5), ev('d', 14, 0, 15, 0),
      { key: 'e', start: at(2026, 11, 3, 22), end: at(2026, 11, 4, 1), allDay: false }, { key: 'x', start: day, end: day + 24 * HOUR, allDay: true, startDate: '2026-11-04', endDate: '2026-11-04' }], day);
    const by = Object.fromEntries(blocks.map((b) => [b.item.key, b]));
    assert.equal(by.x, undefined, 'all-day ones not in the grid');
    assert.deepEqual([by.a.col, by.b.col, by.c.col, by.a.cols, by.b.cols, by.c.cols], [0, 1, 0, 2, 2, 2]);
    assert.deepEqual([by.c.top, by.c.height], [660, 20], 'a short one is 20 minutes high');
    assert.deepEqual([by.d.col, by.d.cols], [0, 1], 'a later one alone');
    assert.deepEqual([by.e.top, by.e.height], [0, 60], 'from the day before: from midnight');
    const multi = { allDay: true, startDate: '2026-11-03', endDate: '2026-11-05', title: 'Messe', start: at(2026, 11, 3), end: at(2026, 11, 6) };
    assert.equal(MS.allDayOn([multi], day).length, 1);
    assert.equal(MS.allDayOn([multi], at(2026, 11, 6)).length, 0, 'the end date is inclusive, not beyond');
    assert.deepEqual(MS.agenda([multi, ev('a', 10, 0, 11, 0)], at(2026, 11, 3), at(2026, 11, 7)).map((g) => [new Date(g.day).getDate(), g.items.length]), [[3, 1], [4, 2], [5, 1]]);
    assert.equal(MS.nowMinutes(at(2026, 11, 4, 9, 30), day), 570);
    assert.equal(MS.nowMinutes(at(2026, 11, 5, 9, 30), day), null);
    assert.deepEqual(MS.slotAt(day, 12 * 60 + 47), { start: at(2026, 11, 4, 12, 30), end: at(2026, 11, 4, 13, 30) });
  });

  it('texts: times, recurrence, reminders, answers', () => {
    assert.equal(MS.eventTimeText({ start: at(2026, 11, 4, 10), end: at(2026, 11, 4, 11) }, 'de', t), '10:00–11:00');
    assert.equal(MS.eventTimeText({ allDay: true, startDate: '2026-11-04', endDate: '2026-11-04' }, 'de', t), 'mail.cal.allDay');
    assert.match(MS.eventTimeText({ allDay: true, startDate: '2026-11-04', endDate: '2026-11-05' }, 'de', t), /4\. Nov\. – 5\. Nov\./);
    assert.match(MS.eventTimeText({ start: at(2026, 11, 3, 22), end: at(2026, 11, 4, 1) }, 'de', t), /22:00 – .*01:00/);
    assert.equal(MS.recurrenceText(null, t, 'de'), '');
    assert.equal(MS.recurrenceText({ freq: 'daily', interval: 1 }, t, 'de'), 'mail.cal.rec.daily');
    assert.equal(MS.recurrenceText({ freq: 'weekly', interval: 2, byDay: ['TU', 'TH'] }, t, 'de'), 'mail.cal.rec.weeklyNOn(n=2,days=Di, Do)');
    assert.equal(MS.recurrenceText({ freq: 'monthly', interval: 1, byMonthDay: [4] }, t, 'de'), 'mail.cal.rec.monthly mail.cal.rec.onDay(day=4)');
    assert.equal(MS.recurrenceText({ freq: 'monthly', interval: 1, byDay: ['TU'], bySetPos: -1 }, t, 'de'), 'mail.cal.rec.monthly mail.cal.rec.onPos(pos=mail.cal.rec.pos.-1,day=Dienstag)');
    assert.match(MS.recurrenceText({ freq: 'yearly', interval: 1, until: '2030-12-31' }, t, 'de'), /^mail\.cal\.rec\.yearly mail\.cal\.rec\.until\(date=31\.12\.2030\)$/);
    assert.equal(MS.recurrenceText({ freq: 'weekly', interval: 1, count: 5 }, t, 'de'), 'mail.cal.rec.weekly · mail.cal.rec.count(count=5)');
    assert.equal(MS.recurrenceText({ rrule: 'FREQ=WEEKLY;BYHOUR=9', freq: null }, t, 'de'), 'mail.cal.rec.custom');
    assert.equal(MS.reminderText(0, t), 'mail.cal.rem.atStart');
    assert.equal(MS.reminderText(15, t), 'mail.cal.rem.minutes(count=15)');
    assert.equal(MS.reminderText(60, t), 'mail.cal.rem.hour(count=1)');
    assert.equal(MS.reminderText(120, t), 'mail.cal.rem.hours(count=2)');
    assert.equal(MS.reminderText(1440, t), 'mail.cal.rem.day(count=1)');
    assert.equal(MS.reminderText(20160, t), 'mail.cal.rem.weeks(count=2)');
    assert.deepEqual(MS.responseCounts([{ response: 'accepted' }, { response: 'declined' }, { response: 'needs_action' }, { response: 'accepted', role: 'resource' }]), { accepted: 1, tentative: 0, declined: 1, needs_action: 1, total: 3 });
  });

  it('the menu\'s groups: GateControl, per account, shown here; the ids of GET events; colours', () => {
    const me = { accounts: [{ id: 2, name: 'Firma · M365' }] };
    const cals = [{ id: 1, name: 'Privat', accountId: null, visible: true, color: '#46E0A0' }, { id: 3, name: 'Kalender', accountId: 2, visible: false, color: '#B79CFF' }, { id: 9, name: 'Alt', accountId: 7, visible: true }];
    const ovs = [{ id: 'familie', name: 'Familie', visible: true, color: '#F5B544' }];
    const g = MS.calendarGroups(cals, ovs, me, t);
    assert.deepEqual(g.map((x) => [x.label, x.items.map((i) => i.id)]), [['mail.cal.groupOwn', [1]], ['Firma · M365', [3]], ['mail.cal.groupOther', [9]], ['mail.cal.groupOverlays', ['familie']]]);
    assert.deepEqual(MS.visibleIds(cals, ovs), [1, 9, 'familie']);
    assert.equal(MS.itemColor({ calendarId: 1 }, cals, ovs), '#46E0A0');
    assert.equal(MS.itemColor({ overlayId: 'familie' }, cals, ovs), '#F5B544');
    assert.equal(MS.itemColor({ calendarId: 99 }, cals, ovs), '#8C96A5');
  });

  it('the event form and its body: new, all-day, recurrence, attendees, the online link', () => {
    const cals = [{ id: 1, writable: true }, { id: 4, writable: false }];
    const prefs = { defaultCalendarId: 4, defaultReminder: 15, allDayReminder: 1080 };
    const f = MS.eventForm({ start: at(2026, 11, 4, 9), end: at(2026, 11, 4, 10) }, prefs, cals);
    assert.deepEqual([f.calendarId, f.startDate, f.startTime, f.endTime, f.reminders, f.recurrence.kind, f.recurrence.days], [1, '2026-11-04', '09:00', '10:00', [15], 'none', ['WE']]);
    assert.deepEqual(MS.eventBody({ ...f, title: ' ' }), { error: 'title' });
    assert.deepEqual(MS.eventBody({ ...f, title: 'X', endTime: '08:00' }), { error: 'end' });
    f.title = ' Planung ';
    f.attendees = [{ name: 'Tim', email: 'tim@firma.de' }, { name: null, email: 'kaputt' }];
    f.recurrence = { kind: 'weekly', interval: 2, days: ['FR', 'MO'], end: 'count', count: 4 };
    f.onlineUrl = 'https://zoom.us/j/1';
    const b = MS.eventBody(f);
    assert.deepEqual([b.title, b.start, b.end, b.allDay, b.online], ['Planung', at(2026, 11, 4, 9), at(2026, 11, 4, 10), false, { url: 'https://zoom.us/j/1' }]);
    assert.deepEqual(b.recurrence, { freq: 'weekly', interval: 2, byDay: ['MO', 'FR'], count: 4 });
    assert.deepEqual(b.attendees, [{ email: 'tim@firma.de', name: 'Tim' }]);
    const allDay = MS.eventBody({ ...f, allDay: true, startDate: '2026-11-04', endDate: '2026-11-06', recurrence: { kind: 'monthlyPos' }, teams: true });
    assert.deepEqual([allDay.startDate, allDay.endDate, allDay.start, allDay.online, allDay.recurrence], ['2026-11-04', '2026-11-06', undefined, { create: 'teams' }, { freq: 'monthly', interval: 1, byDay: ['WE'], bySetPos: 1 }]);
    assert.deepEqual(MS.monthPos(at(2026, 11, 25)), { pos: -1, day: 'WE' }, 'the last Wednesday');
    assert.equal(MS.eventBody({ ...f, recurrence: { kind: 'custom' } }).recurrence, undefined, 'a rule the form cannot show stays');
    assert.equal(MS.eventBody({ ...f, onlineUrl: '' }, { hadOnline: true }).online, null, 'the link removed');
    const ev = MS.eventForm({ eventId: 7, calendarId: 1, title: 'T', start: at(2026, 11, 4, 9), end: at(2026, 11, 4, 10), online: { url: 'https://teams.microsoft.com/x', provider: 'teams' }, reminders: [5, 60], attendees: [{ email: 'me@x.de', self: true }, { email: 'a@x.de', name: 'A' }], recurrence: { freq: 'monthly', interval: 1, byMonthDay: [4], until: '2027-01-01' }, etag: '"1-0"' }, prefs, cals);
    assert.deepEqual([ev.teams, ev.onlineUrl, ev.reminders, ev.attendees, ev.recurrence.kind, ev.recurrence.end, ev.etag], [true, '', [5, 60], [{ name: 'A', email: 'a@x.de' }], 'monthlyDay', 'until', '"1-0"']);
  });

  it('a changed time of the whole series: the shift at the occurrence in days and wall-clock minutes on `series` (Mail 1.3.0)', () => {
    const ev = { start: at(2026, 11, 10, 18), end: at(2026, 11, 10, 19, 30), series: { start: at(2026, 9, 1, 18), end: at(2026, 9, 1, 19, 30), allDay: false } };
    // one hour later and half an hour longer, one day later → the master likewise
    assert.deepEqual(MS.seriesTimes({ start: at(2026, 11, 11, 19), end: at(2026, 11, 11, 21) }, ev), { start: at(2026, 9, 2, 19), end: at(2026, 9, 2, 21) });
    // the occurrence's times unchanged → the series' times unchanged (across the change to winter time: wall clock, not ms)
    assert.deepEqual(MS.seriesTimes({ start: ev.start, end: ev.end }, ev), { start: at(2026, 9, 1, 18), end: at(2026, 9, 1, 19, 30) });
    assert.equal(MS.seriesTimes({ start: 1, end: 2 }, { start: 1, end: 2 }), null, 'Mail 1.2.0: no series times');
    const ad = { allDay: true, startDate: '2026-11-10', endDate: '2026-11-10', start: at(2026, 11, 10), end: at(2026, 11, 11), series: { start: at(2026, 9, 1), end: at(2026, 9, 2), allDay: true, startDate: '2026-09-01', endDate: '2026-09-01' } };
    assert.deepEqual(MS.seriesTimes({ allDay: true, startDate: '2026-11-11', endDate: '2026-11-12' }, ad), { startDate: '2026-09-02', endDate: '2026-09-03' });
    const view = read('src', 'renderer', 'calendar-view.js');
    assert.match(view, /seriesOk: !moved \|\| !!ev\.series/, 'without `series` only "Nur dieser Termin" for a changed time');
    assert.match(view, /series_shift/, 'the server\'s refusal of a shift gets its own text');
  });

  it('invitation states', () => {
    assert.deepEqual(MS.inviteStatus({ method: 'request', state: 'open', myResponse: 'needs_action' }), { key: 'open', tone: 'info' });
    assert.deepEqual(MS.inviteStatus({ method: 'request', state: 'answered', myResponse: 'declined' }), { key: 'answered.declined', tone: 'err' });
    assert.deepEqual(MS.inviteStatus({ method: 'request', state: 'outdated' }), { key: 'outdated', tone: 'muted' });
    assert.deepEqual(MS.inviteStatus({ method: 'cancel', state: 'open' }), { key: 'cancelled', tone: 'err' });
    assert.deepEqual(MS.inviteStatus({ method: 'reply', state: 'applied', from: { email: 'A@x.de' }, attendees: [{ email: 'a@x.de', response: 'tentative' }] }), { key: 'reply.tentative', tone: 'info' });
    assert.deepEqual(MS.inviteStatus({ method: 'counter', state: 'open' }), { key: 'counter', tone: 'info' });
    assert.deepEqual(MS.consentAccounts({ accounts: [{ id: 1, missingScopes: [] }, { id: 2, missingScopes: ['Calendars.ReadWrite'] }] }).map((a) => a.id), [2]);
  });
});

describe('mail-state – contacts', () => {
  it('sections, the row\'s second line, birthdays', () => {
    const s = MS.cardSections([{ id: 1, letter: 'A' }, { id: 2, letter: 'A' }, { id: 3, letter: 'K' }, { id: 4 }]);
    assert.deepEqual(s.map((x) => [x.letter, x.items.length]), [['A', 2], ['K', 1], ['#', 1]]);
    assert.equal(MS.cardSub({ company: 'Firma', emails: ['a@b.de'] }), 'Firma');
    assert.equal(MS.cardSub({ emails: ['a@b.de'], phone: '0170' }), 'a@b.de');
    assert.equal(MS.birthdayText('1981-03-14', at(2026, 11, 4), 'de', t), '14. März 1981 · mail.con.turns(age=46)');
    assert.equal(MS.birthdayText('1981-12-14', at(2026, 11, 4), 'de', t), '14. Dezember 1981 · mail.con.turns(age=45)');
    assert.equal(MS.birthdayText('--03-14', at(2026, 11, 4), 'de', t), '14. März');
    assert.equal(MS.birthdayText('nope', 0, 'de', t), '');
    assert.deepEqual(MS.birthdayInput('1981-03-14', 'de'), { day: '14.03.', year: '1981' });
    assert.deepEqual(MS.birthdayInput('--03-14', 'en'), { day: '14/03', year: '' });
    assert.equal(MS.birthdayValue('14.3.', ''), '--03-14');
    assert.equal(MS.birthdayValue('14/03', '1981'), '1981-03-14');
    assert.equal(MS.birthdayValue('', ''), null);
    assert.equal(MS.birthdayValue('31.02.', ''), undefined);
    assert.equal(MS.birthdayValue('14.03.', '81'), undefined);
  });

  it('the contact form and its body', () => {
    const f = MS.cardForm({ id: 4, etag: '"v2"', addressbookId: 1, name: { given: 'Tim', family: 'Brandt', display: 'Tim Brandt' }, emails: [{ value: 'tim@firma.de', type: 'work' }], phones: [], addresses: [], birthday: '--05-01', groups: [7] }, 'de');
    assert.deepEqual([f.given, f.bdayDay, f.bdayYear, f.groups], ['Tim', '01.05.', '', [7]]);
    f.emails.push({ value: ' ', type: 'home' }, { value: 'privat@tim.de', type: 'home' });
    f.phones.push({ value: '0170 1', type: 'mobile' });
    f.addresses.push({ type: 'work', street: ' Hansaring 12 ', postalCode: '50670', city: 'Köln', region: '', country: '' }, { type: 'home', street: '', postalCode: '', city: '', region: '', country: '' });
    const b = MS.cardBody(f);
    assert.deepEqual(b.emails, [{ value: 'tim@firma.de', type: 'work', primary: true }, { value: 'privat@tim.de', type: 'home', primary: false }]);
    assert.deepEqual(b.addresses, [{ type: 'work', street: 'Hansaring 12', postalCode: '50670', city: 'Köln', region: '', country: '' }]);
    assert.deepEqual([b.birthday, b.etag, b.addressbookId], ['--05-01', '"v2"', undefined]);
    assert.deepEqual(MS.cardBody({ ...f, emails: [{ value: 'kaputt' }] }), { error: 'email' });
    assert.deepEqual(MS.cardBody({ ...f, bdayDay: '99.99.' }), { error: 'birthday' });
    assert.deepEqual(MS.cardBody(MS.cardForm(null, 'de')), { error: 'name' });
    const fresh = MS.cardForm({ name: { display: 'Stadtwerke' }, emails: [{ value: 'r@s.de', type: 'work' }] }, 'de');
    fresh.addressbookId = 3;
    const nb = MS.cardBody(fresh);
    assert.deepEqual([nb.name, nb.addressbookId, nb.etag], [{ given: '', family: '', display: 'Stadtwerke' }, 3, undefined]);
    assert.deepEqual(MS.addressLines({ street: 'Hansaring 12', postalCode: '50670', city: 'Köln', country: 'DE' }), ['Hansaring 12', '50670 Köln', 'DE']);
    assert.equal(MS.mapUrl({ street: 'Hansaring 12', city: 'Köln' }), 'https://www.openstreetmap.org/search?query=Hansaring%2012%2C%20K%C3%B6ln');
    assert.equal(MS.mapUrl({}), null);
  });

  it('sources, suggestions with groups, merge choices', () => {
    const me = { accounts: [{ id: 2, name: 'Firma · M365', color: '#79B8FF' }] };
    assert.equal(MS.bookLabel({ name: 'Kontakte', accountId: 2 }, me), 'Firma · M365 · Kontakte');
    assert.equal(MS.bookLabel({ name: 'Firma · M365', accountId: 2 }, me), 'Firma · M365');
    assert.equal(MS.bookColor({ accountId: 2 }, me), '#79B8FF');
    assert.equal(MS.bookColor({ accountId: null }, me), null);
    assert.deepEqual(MS.suggestionRecipients({ source: 'group', members: [{ name: 'Oma', email: 'oma@x.de' }, { name: 'X', email: 'bad' }] }), [{ name: 'Oma', email: 'oma@x.de' }]);
    assert.deepEqual(MS.suggestionRecipients({ source: 'contact', name: 'Tim', email: 'tim@firma.de' }), [{ name: 'Tim', email: 'tim@firma.de' }]);
    const ch = MS.mergeChoices([{ id: 1, name: { display: 'Sabine Keller' }, company: 'Keller GmbH' }, { id: 2, name: { display: 'Sabine K.' }, company: 'Keller GmbH', title: 'PL' }]);
    assert.deepEqual(ch, [{ field: 'name', options: [{ id: 1, value: 'Sabine Keller' }, { id: 2, value: 'Sabine K.' }] }]);
  });
});

describe('mail areas wiring', () => {
  it('index.html loads the areas after the Mail view; they never write HTML into the page', () => {
    const html = read('src', 'renderer', 'index.html');
    const v = html.indexOf('src="mail-view.js"');
    assert.ok(v > 0 && html.indexOf('src="calendar-view.js"') > v && html.indexOf('src="contacts-view.js"') > v && html.indexOf('src="contacts-view.js"') < html.indexOf('src="renderer.js"'));
    for (const f of ['calendar-view.js', 'contacts-view.js']) {
      const src = read('src', 'renderer', f);
      assert.doesNotMatch(src, /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/, f);
      assert.doesNotMatch(src, /allow-scripts/, f);
    }
    const view = read('src', 'renderer', 'mail-view.js');
    assert.doesNotMatch(view, /icon\('plus', 18\)/, 'the "+" of the menu is gone');
    assert.match(view, /ml-foot-settings/);
  });

  it('every mail.* key of the areas exists in de and en (also the ones built at runtime)', () => {
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const src = ['calendar-view.js', 'contacts-view.js', 'mail-view.js', 'mail-state.js'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set();
    for (const m of src.matchAll(/['"`](mail\.(?:cal|con|consent|compose|inboxes|addAccountInSettings)[A-Za-z0-9_.-]*)['"`]/g)) if (!m[1].endsWith('.')) keys.add(m[1]);
    const add = (pre, list) => { for (const x of list) keys.add(`${pre}.${x}`); };
    add('mail.cal.view', ['day', 'week', 'month', 'list']);
    add('mail.cal.state', ['syncing', 'consent', 'auth_failed', 'unreachable']);
    add('mail.cal.resp', ['accepted', 'tentative', 'declined', 'needs_action']);
    add('mail.cal.busy', ['busy', 'tentative', 'free', 'oof']);
    add('mail.cal.answered', ['accepted', 'tentative', 'declined']);
    add('mail.cal.bad', ['title', 'start', 'end', 'seriesShift']);
    add('mail.cal.rec.pos', ['1', '2', '3', '4', '-1']);
    add('mail.cal.label', ['request', 'cancel', 'reply', 'counter']);
    add('mail.cal.inv', ['open', 'outdated', 'cancelled', 'cancelledRemoved', 'counter', 'counterDone', 'reply.accepted', 'reply.tentative', 'reply.declined', 'answered.accepted', 'answered.tentative', 'answered.declined']);
    add('mail.con.type.email', ['work', 'home', 'other']);
    add('mail.con.type.phone', ['mobile', 'work', 'home', 'fax', 'other']);
    add('mail.con.type.address', ['home', 'work', 'other']);
    add('mail.con.bad', ['birthday', 'email', 'phone', 'name']);
    add('mail.con.reason', ['email', 'phone', 'name']);
    add('mail.con.field', ['name', 'company', 'title', 'birthday']);
    add('mail.compose.src', ['contact', 'group', 'person', 'recent']);
    add('mail.err', ['conflict', 'read_only', 'feature_off', 'not_supported', 'send_failed', 'invitation_outdated', 'invalid_vcard', 'invalid_ics', 'dav_unavailable']);
    assert.ok(keys.size > 300, `only ${keys.size} keys found`);
    for (const k of keys) {
      assert.ok(k in de, `de: ${k}`);
      assert.ok(k in en, `en: ${k}`);
    }
  });
});
