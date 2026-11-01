'use strict';

// Drive 1.17 on the page "Drive" (no DOM, drive-ki-state.js, 'deadlineMailCalendar'): deadlines into the family
// calendar or a calendar of the mail plugin — the choice of an area's target ("Fristen aus …"), grouped by account,
// "In Kalender eintragen" (asks only with more than one target, the area's target first), the button texts, the
// switch of Drive 1.14 as the fallback; every key in de and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const KS = require('../src/renderer/drive-ki-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);

const outlook = { id: 'acc-1', label: 'Outlook', kind: 'microsoft' };
const posteo = { id: 'acc-2', label: 'Posteo', kind: 'caldav' };
const CALS = {
  family: true,
  mail: [
    { id: 'cal-1', name: 'Kalender', account: outlook, color: '#3366ff' },
    { id: 'cal-3', name: 'Privat', account: posteo, color: null },
    { id: 'cal-2', name: 'Geburtstage', account: outlook, color: null },
  ],
};
const ME = { features: ['docAi', 'deadlineCalendar', 'deadlineMailCalendar'] };

describe('the target of an area ("Fristen aus …")', () => {
  it('off, the family calendar, then the mail calendars by account; values and texts', () => {
    const g = KS.targetChoices(CALS, { t, mail: true });
    assert.deepEqual(g.map((x) => x.account), [null, 'Outlook', 'Posteo']);
    assert.deepEqual(g[0].options.map((o) => [o.value, o.label]), [['off', 'drive.ki.dl.target.off'], ['family', 'drive.ki.dl.target.family']]);
    assert.deepEqual(g[1].options.map((o) => [o.value, o.label, o.name]), [['mail:cal-1', 'Outlook · Kalender', 'Kalender'], ['mail:cal-2', 'Outlook · Geburtstage', 'Geburtstage']]);
    assert.deepEqual(g[1].options[0].target, { kind: 'mail', calendarId: 'cal-1', label: 'Outlook · Kalender' });
    assert.equal(g[1].options[0].color, '#3366ff');
    // without Familie no family calendar; without the feature no mail calendars; a single deadline: no "off"
    assert.deepEqual(KS.targetChoices({ ...CALS, family: false }, { t, mail: false }).flatMap((x) => x.options.map((o) => o.value)), ['off']);
    assert.deepEqual(KS.targetChoices({ family: false, mail: [] }, { t, off: false }), []);
    assert.deepEqual(KS.targetChoices({ mail: [{ id: 'x', name: 'X' }] }, { t, mail: true })[1].account, 'drive.ki.dl.target.mail');

    assert.equal(KS.targetValue(null), 'off');
    assert.equal(KS.targetValue({ kind: 'family' }), 'family');
    assert.equal(KS.targetValue({ kind: 'mail', calendarId: 'cal-2' }), 'mail:cal-2');
    assert.equal(KS.targetValue({ kind: 'mail' }), 'off');
    assert.deepEqual(KS.targetFromValue('family', CALS), { kind: 'family' });
    assert.deepEqual(KS.targetFromValue('mail:cal-3', CALS), { kind: 'mail', calendarId: 'cal-3', label: 'Posteo · Privat' });
    assert.equal(KS.targetFromValue('mail:gone', CALS), null);
    assert.equal(KS.targetFromValue('off', CALS), null);

    assert.equal(KS.targetText(null, CALS, t), 'drive.ki.dl.target.off');
    assert.equal(KS.targetText({ kind: 'family' }, CALS, t), 'drive.ki.dl.target.family');
    assert.equal(KS.targetText({ kind: 'mail', calendarId: 'cal-1', label: 'alt' }, CALS, t), 'Outlook · Kalender');
    assert.equal(KS.targetText({ kind: 'mail', calendarId: 'gone', label: 'Outlook · Alt' }, CALS, t), 'Outlook · Alt');
    assert.equal(KS.targetText({ kind: 'mail', calendarId: 'gone' }, CALS, t), 'drive.ki.dl.target.mail');
    assert.equal(KS.mailLabel({ name: 'Kalender', account: { label: '' } }), 'Kalender');
  });

  it('the settings row under an area with AI: the target with Drive 1.17, else the switch of Drive 1.14 ("Fristen aus …")', () => {
    const mine = { id: 'mine:2', docAi: true, deadlinesToCalendar: false };
    const fam = { id: 'family:1', docAi: true, deadlinesToCalendar: true };
    const off = { id: 'team:1', docAi: false, deadlinesToCalendar: true };
    const targets = [{ areaId: 'mine:2', label: 'Meine Dateien', target: { kind: 'mail', calendarId: 'cal-1', label: 'Outlook · Kalender' } }];
    assert.deepEqual(KS.deadlineRow(mine, ME, targets), { areaId: 'mine:2', kind: 'target', target: targets[0].target });
    // an area not (yet) in the targets, or the targets not loaded: the switch
    assert.deepEqual(KS.deadlineRow(fam, ME, targets), { areaId: 'family:1', kind: 'switch', on: true });
    assert.deepEqual(KS.deadlineRow(mine, ME, null), { areaId: 'mine:2', kind: 'switch', on: false });
    assert.deepEqual(KS.deadlineRow(mine, { features: ['docAi', 'deadlineCalendar'] }, targets), { areaId: 'mine:2', kind: 'switch', on: false });
    assert.equal(KS.deadlineRow(off, ME, targets), null);
    assert.equal(KS.deadlineRow(mine, { features: ['docAi'] }, null), null);
    assert.equal(KS.deadlineRow({ id: 'x', docAi: true }, { features: ['deadlineCalendar'] }, null), null);
    assert.equal(KS.features(ME).mailCalendar, true);
    assert.equal(KS.features({ features: ['deadlineCalendar'] }).mailCalendar, false);
  });
});

describe('"In Kalender eintragen" of a single deadline', () => {
  it('asks only with more than one target; the area\'s target first, else the family calendar', () => {
    const all = KS.deadlineTargets(CALS, true);
    assert.deepEqual(all.map(KS.targetValue), ['family', 'mail:cal-1', 'mail:cal-2', 'mail:cal-3']);
    assert.equal(KS.asksTarget(all), true);
    assert.equal(KS.asksTarget(KS.deadlineTargets(CALS, false)), false);
    assert.equal(KS.asksTarget(KS.deadlineTargets({ family: false, mail: [CALS.mail[0]] }, true)), false);
    assert.equal(KS.asksTarget([]), false);

    const rows = [
      { areaId: 'mine:2', target: { kind: 'mail', calendarId: 'cal-3' } },
      { areaId: 'family:1', target: null },
      { areaId: 'team:1', target: { kind: 'mail', calendarId: 'gone' } },
    ];
    assert.equal(KS.targetValue(KS.preselect(rows, 'mine:2', all)), 'mail:cal-3');
    assert.equal(KS.targetValue(KS.preselect(rows, 'family:1', all)), 'family');
    assert.equal(KS.targetValue(KS.preselect(rows, 'team:1', all)), 'family');
    assert.equal(KS.targetValue(KS.preselect(null, null, all)), 'family');
    assert.equal(KS.targetValue(KS.preselect(rows, 'family:1', all.filter((x) => x.kind === 'mail'))), 'mail:cal-1');
    assert.equal(KS.preselect(rows, 'mine:2', []), null);
  });

  it('the button: "In Kalender eintragen" with a mail calendar, "Im Kalender · Outlook" after, the family calendar as before', () => {
    const node = { id: 6, name: 'Kfz.pdf', areaId: 'mine:2' };
    const card = KS.deadlineCard({ id: 2, kind: 'cancellation', date: '2099-11-30', label: 'Kfz', node }, { t, locale: 'de', calendar: true });
    assert.equal(card.areaId, 'mine:2');
    assert.equal(card.entry, null);
    assert.deepEqual(KS.calendarButton(card, t), { label: 'drive.ki.dl.toCalendar', done: false });
    assert.deepEqual(KS.calendarButton(card, t, { any: true }), { label: 'drive.ki.dl.toCalendarAny', done: false });
    const mail = KS.deadlineCard({ id: 2, kind: 'cancellation', date: '2099-11-30', node, calendar: { eventId: 'm', at: 1, target: { kind: 'mail', calendarId: null, label: 'Outlook · Kalender' } } }, { t, locale: 'de', calendar: true });
    assert.deepEqual(KS.calendarButton(mail, t, { any: true }), { label: 'drive.ki.dl.inCalendarAt(where=Outlook)', done: true });
    assert.deepEqual(KS.calendarButton({ calendar: true, entry: { kind: 'mail', label: null } }, t), { label: 'drive.ki.dl.inCalendarAny', done: true });
    assert.deepEqual(KS.calendarButton({ calendar: true, entry: { kind: 'family' } }, t, { any: true }), { label: 'drive.ki.dl.inCalendar', done: true });
    assert.equal(KS.deadlineCard({ id: 1, kind: 'payment', date: '2099-01-01' }, { t, locale: 'de' }).areaId, null);
  });
});

describe('the page (Drive 1.17)', () => {
  it('no innerHTML, every key in de and en', () => {
    for (const f of ['drive-ki-state.js', 'drive-ki-view.js', 'drive-settings-view.js']) {
      assert.doesNotMatch(read('src', 'renderer', f), /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/, f);
    }
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const keys = ['drive.ki.dl.from', 'drive.ki.dl.fromHint', 'drive.ki.dl.targetSet', 'drive.ki.dl.toCalendarAny', 'drive.ki.dl.inCalendarAt', 'drive.ki.dl.inCalendarAny',
      'drive.ki.dl.addedAny', 'drive.ki.dl.pickTitle', 'drive.ki.dl.pickOk', 'drive.ki.dl.target.off', 'drive.ki.dl.target.family', 'drive.ki.dl.target.mail', 'drive.err.mailUnavailable'];
    for (const k of keys) {
      assert.ok(typeof de[k] === 'string' && de[k], `de: ${k}`);
      assert.ok(typeof en[k] === 'string' && en[k], `en: ${k}`);
    }
    assert.equal(de['drive.ki.dl.from'], 'Fristen aus {{area}}');
  });
});
