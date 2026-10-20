'use strict';

// View logic of the page "Schule" (src/renderer/school-state.js, no DOM):
// weeks, lessons with their states, exams / homework, the change log,
// messages and absences, the child selector, tabs and push targets; how
// the page loads the Schule scripts, that the view never uses innerHTML,
// and that every school.* key it uses exists in the core locales.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SS = require('../src/renderer/school-state');

const ROOT = path.join(__dirname, '..');
const CORE_PKG = '@gatecontrol/client-core';
// Minimal t(): the key with its parameters.
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);
const TODAY = '2026-10-21'; // a Wednesday
const at = (iso, h, m) => { const [y, mo, d] = iso.split('-').map(Number); return new Date(y, mo - 1, d, h, m).getTime(); };

const lesson = (o = {}) => ({
  start: '08:00', end: '08:45', period: 1, periodEnd: null, subject: 'M', subjectLong: 'Mathematik', subjectOld: null,
  teacher: 'MUE', teacherOld: null, room: '201', roomOld: null, state: 'normal', info: null, substText: null, text: null, ...o,
});
const student = (o = {}) => ({ id: 3, name: 'Lena Muster', userId: 9, klasse: '5b', color: '#2FBF71', avatarUrl: null, days: [], ...o });

describe('weeks', () => {
  it('this and next week run Monday … Sunday', () => {
    assert.deepEqual(SS.weekRange(TODAY, 0), {
      from: '2026-10-19', to: '2026-10-25',
      dates: ['2026-10-19', '2026-10-20', '2026-10-21', '2026-10-22', '2026-10-23', '2026-10-24', '2026-10-25'],
    });
    assert.equal(SS.weekRange(TODAY, 1).from, '2026-10-26');
    assert.equal(SS.weekRange('2026-10-25', 0).from, '2026-10-19', 'Sunday belongs to the week before');
    assert.equal(SS.weekRange('2026-10-26', 1).to, '2026-11-08');
    assert.equal(SS.weekOffsetOf(TODAY, '2026-10-30'), 1);
    assert.equal(SS.weekOffsetOf(TODAY, '2026-10-19'), 0);
    assert.equal(SS.weekOffsetOf(TODAY, '2026-10-12'), -1);
    // DST change on 2026-10-25 does not shift days
    assert.equal(SS.addDays('2026-10-24', 2), '2026-10-26');
  });

  it('Saturday and Sunday only with something on them', () => {
    const r = SS.weekRange(TODAY, 0);
    assert.equal(SS.weekColumns(r.dates, student()).length, 5);
    const s = student({ days: [{ date: '2026-10-24', lessons: [lesson()], homework: [], exams: [] }, { date: '2026-10-25', holiday: 'Ferien', lessons: [], homework: [], exams: [] }] });
    const cols = SS.weekColumns(r.dates, s);
    assert.deepEqual(cols.map((c) => c.date), ['2026-10-19', '2026-10-20', '2026-10-21', '2026-10-22', '2026-10-23', '2026-10-24']);
    assert.equal(cols[5].day.lessons.length, 1);
    assert.equal(cols[0].day, null);
  });

  it('labels', () => {
    assert.equal(SS.dateShort('2026-10-05', 'de'), '05.10.');
    assert.equal(SS.dateShort('2026-10-05', 'en'), '05/10');
    assert.equal(SS.weekdayShort('2026-10-19', 'de'), 'Mo');
    assert.equal(SS.weekdayShort('2026-10-19', 'en'), 'Mon');
    const now = at(TODAY, 18, 0);
    assert.equal(SS.updatedText(at(TODAY, 7, 5), t, 'de', now), 'school.updated(school.todayAt(07:05))');
    assert.equal(SS.updatedText(at('2026-10-20', 7, 5), t, 'de', now), 'school.updated(20.10. 07:05)');
    assert.equal(SS.updatedText(null, t, 'de', now), 'school.updatedNever');
  });
});

describe('lessons, exams, homework', () => {
  it('normal lesson', () => {
    const v = SS.lessonView(lesson({ period: 3, periodEnd: 4 }), t);
    assert.equal(v.cls, 'is-normal');
    assert.equal(v.badge, null);
    assert.equal(v.time, '08:00–08:45');
    assert.equal(v.period, 'school.periods(3,4)');
    assert.equal(v.subject, 'Mathematik');
    assert.equal(v.subjectOld, null);
  });

  it('Entfällt / Vertretung with the old values / Zusatz', () => {
    const c = SS.lessonView(lesson({ state: 'cancelled', info: 'Lehrkraft krank' }), t);
    assert.deepEqual([c.cls, c.badge, c.note], ['is-cancelled', 'school.state.cancelled', 'Lehrkraft krank']);
    const v = SS.lessonView(lesson({ state: 'changed', subjectOld: 'D', teacher: 'SCH', teacherOld: 'MUE', room: '104', roomOld: '104', substText: 'Vertretung', info: 'Vertretung' }), t);
    assert.deepEqual([v.cls, v.badge, v.subjectOld, v.teacher, v.teacherOld, v.roomOld, v.note], ['is-changed', 'school.state.changed', 'D', 'SCH', 'MUE', null, 'Vertretung']);
    const x = SS.lessonView(lesson({ state: 'extra', period: null }), t);
    assert.deepEqual([x.cls, x.badge, x.period], ['is-extra', 'school.state.extra', '']);
    assert.equal(SS.lessonView(lesson({ state: 'bogus' }), t).cls, 'is-normal');
    assert.equal(SS.lessonView(lesson({ subject: '', subjectLong: null }), t).subject, '—');
  });

  it('exams and homework', () => {
    assert.deepEqual(SS.examView({ subject: 'D', subjectLong: 'Deutsch', name: 'Klassenarbeit 2', start: '10:45', end: '11:30', type: 'Klassenarbeit', text: null }, t),
      { title: 'Klassenarbeit 2', subject: 'Deutsch', type: 'Klassenarbeit', time: '10:45–11:30', text: null });
    assert.equal(SS.examView({ subject: 'E', name: '', type: null }, t).title, 'school.exam');
    assert.deepEqual(SS.homeworkView({ subject: 'M', subjectLong: null, text: 'S. 42', givenDate: '2026-10-17', completed: true }, t, 'de'),
      { subject: 'M', text: 'S. 42', done: true, given: 'school.homeworkGiven(17.10.)' });
  });

  it('week summary', () => {
    const cols = [{ day: { lessons: [lesson({ state: 'cancelled' }), lesson({ state: 'changed' }), lesson()], exams: [{}], homework: [{ completed: true }, {}] } }, { day: null }];
    assert.deepEqual(SS.weekSummary(cols), { cancelled: 1, changed: 1, extra: 0, exams: 1, homework: 1 });
  });
});

describe('children', () => {
  it('chips: colour, initials, class', () => {
    assert.deepEqual(SS.studentChip(student(), t), { id: 3, name: 'Lena Muster', sub: 'school.klasse(5b)', color: '#2FBF71', initials: 'LM', avatarUrl: null });
    assert.equal(SS.initials('Tom'), 'TO');
    assert.equal(SS.initials(''), '?');
    assert.ok(SS.PALETTE.includes(SS.studentColor({ id: 4, color: 'red' })));
  });

  it('keeps the chosen child while it exists', () => {
    const list = [student(), student({ id: 4 })];
    assert.equal(SS.pickStudent(list, 4), 4);
    assert.equal(SS.pickStudent(list, 99), 3);
    assert.equal(SS.pickStudent([], 4), null);
  });
});

describe('lists', () => {
  const changes = [
    { id: 1, studentId: 3, student: 'Lena', date: '2026-10-20', start: '09:50', end: '10:35', period: 3, kind: 'cancelled', subject: 'E', subjectLong: 'Englisch', detectedAt: at('2026-10-20', 6, 30), pushed: true },
    { id: 2, studentId: 4, student: 'Tom', date: '2026-10-21', start: '08:00', end: '08:45', kind: 'extra', subject: 'SP', detectedAt: at('2026-10-20', 7, 0) },
    { id: 3, studentId: 3, student: 'Lena', date: '2026-10-21', start: '08:00', end: '08:45', kind: 'changed', subject: 'M', teacher: 'SCH', teacherOld: 'MUE', substText: 'statt Deutsch', detectedAt: at(TODAY, 6, 0) },
  ];

  it('changes of one child, by day', () => {
    const mine = SS.forStudent(changes, 3, 'changes');
    assert.deepEqual(mine.map((c) => c.id), [1, 3]);
    const groups = SS.groupByDate(SS.sortChanges(mine));
    assert.deepEqual(groups.map((g) => [g.date, g.items.map((c) => c.id)]), [['2026-10-21', [3]], ['2026-10-20', [1]]]);
    const v = SS.changeView(changes[2], t, 'de', at(TODAY, 9, 0));
    assert.deepEqual([v.cls, v.label, v.teacher, v.teacherOld, v.note, v.detected], ['is-changed', 'school.change.changed', 'SCH', 'MUE', 'statt Deutsch', 'school.change.detected(school.todayAt(06:00))']);
    assert.equal(SS.changeView({ ...changes[0], kind: 'restored' }, t, 'de').cls, 'is-normal');
  });

  it('messages: of the child or of no child in particular', () => {
    const msgs = [{ id: 1, studentIds: [3] }, { id: 2, studentIds: [4] }, { id: 3, studentIds: [] }];
    assert.deepEqual(SS.forStudent(msgs, 3, 'messages').map((m) => m.id), [1, 3]);
    const v = SS.messageView({ id: 1, subject: '', sender: 'Frau Schulz', sentAt: at('2026-10-19', 8, 0), preview: 'Liebe Eltern', body: null, isNew: true, hasAttachments: true }, t, 'de', at(TODAY, 9, 0));
    assert.deepEqual(v, { id: 1, subject: 'school.messages.noSubject', sender: 'Frau Schulz', when: '19.10. 08:00', preview: 'Liebe Eltern', body: null, isNew: true, attachments: true });
  });

  it('absences: days, times, excused', () => {
    const a = SS.absenceView({ date: '2026-10-07', endDate: '2026-10-09', start: null, end: null, reason: 'Krank', excused: true }, t, 'de');
    assert.deepEqual(a, { days: 'school.abs.range(Mi 07.10.,Fr 09.10.)', time: 'school.abs.allDay', reason: 'Krank', text: null, status: { label: 'school.abs.excused', cls: 'is-ok' } });
    assert.equal(SS.absenceView({ date: '2026-10-14', start: '08:00', end: '09:30', excused: false }, t, 'de').time, '08:00–09:30');
    assert.equal(SS.absenceView({ date: '2026-10-14', start: '10:00', end: null, excused: false }, t, 'de').status.cls, 'is-err');
    assert.equal(SS.absenceView({ date: '2026-10-14', excused: null }, t, 'de').status.label, 'school.abs.open');
  });
});

describe('tabs, errors and push targets', () => {
  it('messages / absences only when the plugin has them', () => {
    assert.deepEqual(SS.tabsFor({ messages: true, absences: true }), ['week', 'changes', 'messages', 'absences']);
    assert.deepEqual(SS.tabsFor({ messages: null, absences: null }), ['week', 'changes', 'messages', 'absences']);
    assert.deepEqual(SS.tabsFor({ messages: false, absences: false }), ['week', 'changes']);
    assert.deepEqual(SS.tabsFor(null), ['week', 'changes', 'messages', 'absences']);
  });

  it('error texts', () => {
    assert.equal(SS.errorText({ code: 'network' }, t), 'school.err.network');
    assert.equal(SS.errorText({ code: 'http_502' }, t), 'school.err.server');
    assert.equal(SS.errorText({ code: 'FORBIDDEN' }, t), 'school.err.failed(FORBIDDEN)');
  });

  it('a push opens the week of its day, the message or the absences', () => {
    const all = { messages: true, absences: true };
    assert.deepEqual(SS.pushTarget({ kind: 'changes', studentId: 3, date: '2026-10-22' }, TODAY, all), { tab: 'week', studentId: 3, weekOffset: 0, date: '2026-10-22', messageId: null });
    assert.deepEqual(SS.pushTarget({ kind: 'exams', studentId: 4, date: '2026-10-27' }, TODAY, all), { tab: 'week', studentId: 4, weekOffset: 1, date: '2026-10-27', messageId: null });
    assert.deepEqual(SS.pushTarget({ kind: 'homework', studentId: 3, date: '2026-11-20' }, TODAY, all), { tab: 'week', studentId: 3, weekOffset: 1, date: null, messageId: null });
    assert.deepEqual(SS.pushTarget({ kind: 'messages', studentId: 3, messageId: 77 }, TODAY, all), { tab: 'messages', studentId: 3, weekOffset: 0, date: null, messageId: 77 });
    assert.deepEqual(SS.pushTarget({ kind: 'absences', studentId: 3 }, TODAY, all), { tab: 'absences', studentId: 3, weekOffset: 0, date: null, messageId: null });
    assert.equal(SS.pushTarget({ kind: 'messages' }, TODAY, { messages: false }).tab, 'week');
    assert.equal(SS.pushTarget({ kind: 'changes' }, TODAY, all).tab, 'changes');
    assert.equal(SS.pushTarget(null, TODAY, all).tab, 'week');
  });

  it('inbox entries of Schule (same rule as the core)', () => {
    assert.deepEqual(SS.entryContext({ topic: 'plugin:gatecontrol-schule:changes', data: { route: 'plg-gatecontrol-schule', schule: { studentId: 3, date: '2026-10-20' } } }),
      { kind: 'changes', studentId: 3, date: '2026-10-20', messageId: null });
    assert.deepEqual(SS.entryContext({ topic: 'plugin:gatecontrol-schule:default', data: { route: 'plg-gatecontrol-schule', schule: { kind: 'homework', date: 'x' } } }),
      { kind: 'homework', studentId: null, date: null, messageId: null });
    assert.equal(SS.entryContext({ topic: 'devices', data: { route: 'gateways' } }), null);
  });
});

describe('page wiring', () => {
  const html = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'index.html'), 'utf8');
  const view = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'school-view.js'), 'utf8');
  const state = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'school-state.js'), 'utf8');

  it('loads state before view before renderer, has the page, the nav entry and the styles', () => {
    const i = (s) => html.indexOf(s);
    assert.ok(i('<script src="school-state.js">') > 0);
    assert.ok(i('<script src="school-state.js">') < i('<script src="school-view.js">'));
    assert.ok(i('<script src="school-view.js">') < i('<script src="renderer.js">'));
    assert.match(html, /id="page-schule"/);
    assert.match(html, /id="nav-schule"[^>]*data-page="schule"[^>]*hidden|id="nav-schule"[^>]*hidden/);
    assert.match(html, /href="styles\/school\.css"/);
    assert.ok(fs.existsSync(path.join(ROOT, 'src', 'renderer', 'styles', 'school.css')));
  });

  it('server text never goes through innerHTML', () => {
    const code = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.doesNotMatch(code(view), /innerHTML|insertAdjacentHTML|outerHTML|document\.write/);
    assert.doesNotMatch(code(state), /innerHTML|document\./);
  });

  it('every school.* key of the view exists in the core locales (de and en)', (t2) => {
    let dir = null;
    try { dir = path.dirname(require.resolve(`${CORE_PKG}/package.json`, { paths: [ROOT] })); } catch {
      for (const d of [path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) if (fs.existsSync(path.join(d, 'src', 'i18n', 'locales', 'de.json'))) { dir = d; break; }
    }
    const loc = (l) => (dir ? JSON.parse(fs.readFileSync(path.join(dir, 'src', 'i18n', 'locales', `${l}.json`), 'utf8')) : null);
    const de = loc('de');
    if (!de || !de.school) { t2.skip('core without school.* (core.ref before Schule)'); return; }
    const en = loc('en');
    const get = (o, k) => k.split('.').reduce((x, p) => (x && typeof x === 'object' ? x[p] : undefined), o);
    const src = `${view}\n${state}\n${fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'renderer.js'), 'utf8')}`;
    const keys = new Set([...src.matchAll(/['`](school\.[a-zA-Z.]+[a-zA-Z])['`]/g)].map((m) => m[1]));
    // keys built from a variable part
    for (const tab of SS.TABS) keys.add(`school.tab.${tab}`);
    for (const s of ['cancelled', 'changed', 'extra']) keys.add(`school.state.${s}`);
    for (const k of ['cancelled', 'changed', 'extra', 'restored']) keys.add(`school.change.${k}`);
    for (const w of ['changes', 'messages', 'absences']) keys.add(`school.${w}.empty`);
    for (const e of ['network', 'timeout', 'forbidden', 'invalid', 'unsupported', 'not_configured', 'auth', 'server', 'failed']) keys.add(`school.err.${e}`);
    assert.ok(keys.size > 40, `found ${keys.size} keys`);
    for (const k of keys) {
      assert.equal(typeof get(de, k), 'string', `${k} missing in core de.json`);
      assert.equal(typeof get(en, k), 'string', `${k} missing in core en.json`);
    }
  });
});
