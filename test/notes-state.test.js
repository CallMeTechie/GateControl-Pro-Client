'use strict';

// Notizen & Aufgaben in the Pro app (renderer, no DOM): the plugin's own quick entry and repeat rules as the page
// loads them (src/renderer/vendor/notizen, unchanged) against the plugin's frozen vectors (test/fixtures/notes), the
// note text read into a tree (notes-md.js — the same reading as the plugin's ui/notemd.js, never an HTML string, raw
// HTML stays text, links only http/https/mailto) and its toolbar, the view logic (notes-state.js: dates, the quick
// entry's chips and body, the repeat choices, where an item of another plugin opens), and that the page uses no
// innerHTML and every notes.* key it uses exists in both languages.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

global.self = global;
const ROOT = path.join(__dirname, '..');
const R = require('../src/renderer/vendor/notizen/repeat');
const Q = require('../src/renderer/vendor/notizen/quickparse');
global.GCRepeat = R;
global.GCQuickParse = Q;
// plugin 1.6.0: the plugin's second small module after the parser (several people, „reihum“, „wer zuerst“, stars)
const TW = require('../src/renderer/vendor/notizen/turnwords');
global.GCTurnWords = TW;
require('../src/renderer/notes-md');
require('../src/renderer/notes-state');
const MD = global.GCNotesMd;
const NS = global.GCNotesState;
const qv = require('./fixtures/notes/quickparse-vectors.json');
const rv = require('./fixtures/notes/repeat-vectors.json');
const tv = require('./fixtures/notes/turnwords-vectors.json');

function coreDir() {
  try {
    return path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [ROOT] }));
  } catch {
    for (const d of [path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) if (fs.existsSync(path.join(d, 'package.json'))) return d;
    return null;
  }
}

const de = JSON.parse(fs.readFileSync(path.join(ROOT, 'src', 'i18n', 'de.json'), 'utf8'));
const en = JSON.parse(fs.readFileSync(path.join(ROOT, 'src', 'i18n', 'en.json'), 'utf8'));
const get = (o, key) => key.split('.').reduce((x, k) => (x && typeof x === 'object' ? x[k] : undefined), o);
const t = (key, p) => {
  const s = get(de, key);
  if (typeof s !== 'string') return key;
  return p ? s.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, k) => String(p[k])) : s;
};

describe('the quick entry: the plugin\'s parser as the page loads it', () => {
  it('every vector of the plugin (test/vectors/quickparse.json)', () => {
    assert.ok(qv.cases.length >= 50);
    for (const c of qv.cases) {
      const p = Q.parse(c.input, qv.ctx);
      const got = { title: p.title, date: p.date, time: p.time, remind: p.remind, important: p.important, list: p.list, listName: p.listName, assignee: p.assignee, assigneeName: p.assigneeName, repeat: p.repeat };
      assert.deepEqual(got, c.expect, c.input);
      if (c.marks) assert.deepEqual(p.marks, c.marks, `${c.input} (marks)`);
    }
    // a weekday next to a calendar date belongs to it (plugin 1.8.1: the cases with their own marks)
    assert.ok(qv.cases.filter((c) => c.marks).length >= 20);
    assert.deepEqual(Q.parse(qv.cases[0].input, qv.ctx).marks, qv.marksOfFirst);
  });

  it('every repeat vector (test/vectors/repeat.json)', () => {
    for (const c of rv.next) assert.equal(R.next(c.rule, { due: c.due, done: c.done }), c.expect, JSON.stringify(c));
    for (const c of rv.first) assert.equal(R.first(c.rule, c.today), c.expect, JSON.stringify(c));
    for (const c of rv.describe) { assert.equal(R.describe(c.rule, 'de'), c.de); assert.equal(R.describe(c.rule, 'en'), c.en); }
    for (const r of rv.invalid) assert.equal(R.normalize(r), null, JSON.stringify(r));
  });

  it('the page\'s copies are the core\'s (the plugin\'s files, unchanged)', (t2) => {
    const core = coreDir();
    if (!core || !fs.existsSync(path.join(core, 'src', 'vendor', 'notizen', 'quickparse.js'))) { t2.skip('core without vendor/notizen'); return; }
    for (const f of ['quickparse.js', 'repeat.js', 'turnwords.js']) {
      if (f === 'turnwords.js' && !fs.existsSync(path.join(core, 'src', 'vendor', 'notizen', f))) continue;   // a core before plugin 1.6.0
      assert.equal(fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'vendor', 'notizen', f), 'utf8'), fs.readFileSync(path.join(core, 'src', 'vendor', 'notizen', f), 'utf8'), f);
    }
  });

  it('whose turn and stars: every vector of the plugin (test/vectors/turnwords.json), applied after the parser', () => {
    assert.equal(tv.cases.length, 16);
    for (const c of tv.cases) {
      const w = TW.apply(Q.parse(c.input, tv.ctx), { people: tv.ctx.people, stars: c.stars !== false });
      assert.deepEqual({ title: w.title, people: w.people.map((x) => x.id), turn: w.turn, stars: w.stars }, c.expect, `${c.input}${c.stars === false ? ' (no stars)' : ''}`);
    }
  });

  it('chips, the body of the new task, the context', () => {
    const ctx = NS.quickCtx({ today: '2026-11-08', time: '08:00', prefs: { times: {} } }, { lists: [{ id: 3, name: 'Gesundheit' }, { id: 5, name: 'Büro' }] }, [{ id: 12, name: 'Jenny Muster' }]);
    const p = NS.quickParse('Morgen 9 Uhr Zahnarzt anrufen, wichtig, #gesundheit @jenny', ctx);
    assert.equal(p.title, 'Zahnarzt anrufen');
    const chips = NS.quickChips(p, ctx, 'private', t, 'de');
    assert.deepEqual(chips.map((c) => [c.kind, c.text]), [['date', 'morgen, 09:00'], ['remind', 'Erinnerung 09:00'], ['important', 'Wichtig'], ['list', 'Liste: Gesundheit'], ['person', '@Jenny Muster'], ['area', 'Privat']]);
    const q2 = NS.quickParse('jeden Montag Müll raus #garage', ctx);
    assert.deepEqual(NS.quickChips(q2, ctx, 'work', t, 'de').map((c) => c.text), ['morgen', '↻ Jeden Montag', 'Neue Liste „garage“', 'Arbeit']);
    assert.deepEqual(NS.quickBody(' Brot kaufen ', null, { kind: 'smart', id: 'myday' }, 'private'), { text: 'Brot kaufen', area: 'private', createList: false, myDay: true });
    assert.deepEqual(NS.quickBody('x #garage', q2, { kind: 'list', id: 9 }, 'work'), { text: 'x #garage', area: 'work', createList: true });
    assert.deepEqual(NS.quickBody('x', NS.quickParse('x', ctx), { kind: 'list', id: 9 }, 'work'), { text: 'x', area: 'work', createList: false, listId: 9 });
    assert.equal(NS.quickParse('   ', ctx), null);
  });
});

describe('the text of a note: a tree, never an HTML string (notes-md.js)', () => {
  const corpus = [
    '# Werkstatt\n<script>alert(1)</script> **fett** [x](javascript:alert(1)) [ok](https://example.com)\n- [x] eins\n- [ ] zwei [Aufgabe](task:5)\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n![Bild](att:3) #auto #Werkstatt',
    'Winterreifen auf die Alufelgen, danach **Luftdruck 2,5 bar** prüfen. Mitnehmen:\n\n- [ ] Drehmomentschlüssel\n- [x] Reifen-Check\n- [ ] Ölfilter bestellen\n\n## Notizen vom letzten Mal\n\n- Profil vorne links 4 mm\n\n#auto #werkstatt',
    '> Zitat *kursiv* und _auch_ und ~~weg~~\n> zweite `code` Zeile\n\n1. eins\n2. zwei\n   - tief\n\n---\n```\n<b>roh</b>\n```\ntext mit https://example.com/a?b=1, und mailto:a@b.de [m](mailto:a@b.de)',
    'Tags: (#eins, #zwei;#drei) a#nein #123 `#code` ### Kein#Tag\n__fett__ *a* b*c* _x_y_ **a *b* c**',
    '| x \\| y | z |\n| :-- | --: |\n| [l](https://a.b) | ![p](att:9) [f](att:10) |',
    'Zeile 1\nZeile 2\n\n  - [X] groß\n\t- [ ] tab',
    '[`code` im Link](https://a.b) und ![](https://x.y/i.png) [t](task:77)',
    '"#zitat" & <b>#html</b> \'#apos\' <img src=x onerror=alert(1)>',
  ];
  const opts = { att: (id) => (id === 3 || id === 9 ? { url: '/plugin-media/t' + id, name: 'b.jpg', mime: 'image/jpeg' } : id === 10 ? { url: null, name: 'f.pdf', mime: 'application/pdf' } : null), task: (id) => (id === 5 ? { label: 'Aufgabe · Mi.', done: true } : null), checkable: true };

  it('reads the Markdown exactly like the plugin\'s ui/notemd.js (its HTML from the tree is the same)', (t2) => {
    const core = coreDir();
    const file = core && path.join(core, 'test', 'fixtures', 'notes', 'notemd.js');
    if (!file || !fs.existsSync(file)) { t2.skip('core without the notemd fixture'); return; }
    const NM = require(file);
    for (const md of corpus) assert.equal(MD.toHtml(MD.parse(md), opts), NM.render(md, opts), md);
  });

  it('raw HTML stays text, links only http / https / mailto, pictures only the note\'s attachments', () => {
    const tree = MD.parse(corpus[0] + '\n' + corpus[7]);
    const walk = (list, out = []) => { for (const n of list) { out.push(n); if (n.c) walk(n.c, out); if (n.lines) for (const l of n.lines) walk(l, out); if (n.items) for (const it of n.items) walk(it.c, out); if (n.head) for (const c of n.head) walk(c, out); if (n.rows) for (const r of n.rows) for (const c of r) walk(c, out); } return out; };
    const all = walk(tree);
    const links = all.filter((n) => n.t === 'link').map((n) => n.href);
    assert.deepEqual(links, ['https://example.com']);
    assert.ok(all.some((n) => n.t === 'text' && n.v.includes('<script>alert(1)</script>')));
    assert.ok(all.some((n) => n.t === 'text' && n.v.includes('<img src=x onerror=alert(1)>')));
    assert.ok(all.some((n) => n.t === 'span' && n.c[0].v.includes('javascript:alert(1)')));
    assert.deepEqual(all.filter((n) => n.t === 'img').map((n) => n.att), [3]);
    const check = tree.find((b) => b.t === 'list' && b.check);
    assert.deepEqual(check.items.map((i) => [i.line, i.done, i.label]), [[2, true, 'eins'], [3, false, 'zwei']]);
    assert.equal(MD.safeUrl('javascript:alert(1)'), null);
    assert.equal(MD.safeUrl('https://a.b/x'), 'https://a.b/x');
  });

  it('the toolbar: bold around the selection, list marks on every line (and off again), a table, a picture', () => {
    assert.deepEqual(MD.wrap({ value: 'Hallo Welt', start: 6, end: 10 }, '**', '**', 'fett'), { value: 'Hallo **Welt**', start: 8, end: 12 });
    assert.deepEqual(MD.wrap({ value: 'ab', start: 2, end: 2 }, '*', '*', 'kursiv'), { value: 'ab*kursiv*', start: 3, end: 9 });
    const two = MD.prefix({ value: 'eins\nzwei\ndrei', start: 1, end: 7 }, '- [ ] ');
    assert.equal(two.value, '- [ ] eins\n- [ ] zwei\ndrei');
    assert.equal(MD.prefix({ value: two.value, start: 2, end: 14 }, '- [ ] ').value, 'eins\nzwei\ndrei');
    assert.equal(MD.prefix({ value: '- a\n- b', start: 0, end: 7 }, '1. ').value, '1. a\n2. b');
    assert.equal(MD.prefix({ value: '## Alt', start: 0, end: 0 }, '- ').value, '- Alt');
    assert.equal(MD.insert({ value: 'Text', start: 4, end: 4 }, MD.tableText('Spalte')).value, 'Text\n| Spalte 1 | Spalte 2 |\n| --- | --- |\n|  |  |');
    assert.equal(MD.attachmentText(7, 'Bild [1].png', true), '![Bild 1.png](att:7)');
    assert.equal(MD.attachmentText(8, 'a.pdf', false), '[a.pdf](att:8)');
    // what the toolbar writes is read back as the plugin reads it
    const b = MD.parse(MD.wrap({ value: 'x', start: 0, end: 1 }, '**', '**').value)[0];
    assert.equal(b.lines[0][0].t, 'b');
  });
});

describe('notes-state.js', () => {
  it('days and times as the lists show them', () => {
    assert.equal(NS.dayText('2026-11-08', '2026-11-08', t), 'heute');
    assert.equal(NS.dayText('2026-11-09', '2026-11-08', t), 'morgen');
    assert.equal(NS.dayText('2026-11-07', '2026-11-08', t), 'gestern');
    assert.equal(NS.dayText('2026-11-13', '2026-11-08', t), 'Fr. 13. Nov.');
    assert.equal(NS.dayText('2027-01-04', '2026-11-08', t), 'Mo. 4. Jan. 2027');
    assert.equal(NS.longDate('2026-11-08', t), 'Sonntag, 8. November');
    assert.equal(NS.whenText({ type: 'task', due: { date: '2026-11-08', time: '09:00' } }, '2026-11-08', t), '9:00');
    assert.equal(NS.whenText({ type: 'source', kind: 'homework', due: { date: '2026-11-09', time: null } }, '2026-11-08', t), 'bis morgen');
    assert.equal(NS.whenText({ type: 'source', kind: 'event', due: { date: '2026-11-09' }, show: { date: '2026-11-08', time: '18:00' } }, '2026-11-08', t), '18:00');
    assert.equal(NS.localInput('2026-11-09T14:00:00+01:00'), '2026-11-09T14:00');
  });

  it('the chips and the grey line of a row', () => {
    const item = { type: 'source', kind: 'deadline', title: 'R', source: { plugin: 'gatecontrol-drive', label: 'Drive' }, meta: { amount: '84,20 €' } };
    assert.deepEqual(NS.sourceChip(item, t), { text: 'Drive · Frist', tone: 'ok' });
    assert.deepEqual(NS.metaLine(item, {}, t), ['84,20 €']);
    const task = { type: 'task', listId: 3, repeatText: 'Täglich', hasNote: true, attachments: 2, progress: { done: 1, total: 3 }, assignee: { id: 12, name: 'Jenny' } };
    assert.deepEqual(NS.metaLine(task, { userId: 1, lists: [{ id: 3, name: 'Gesundheit', area: 'private' }] }, t), ['Privat › Gesundheit', 'Jenny', '↻ Täglich', 'Notiz', '2 Anhänge', '1 von 3']);
    assert.equal(NS.sectionTitle({ id: 'done', title: 'Erledigt' }, 'myday', t), 'Erledigt heute');
  });

  it('plugin 1.3.0: the marks of a task and the calendar chip — only with the words of me.features', () => {
    const me = { today: '2026-11-08', features: ['tasks', 'reminderActions', 'taskCalendar'], calendar: { available: true, enabled: true, mine: true, name: 'Aufgaben' } };
    const task = { type: 'task', id: 41, done: false, snoozed: false, reminder: { tag: 'task:41:1794729600000', at: '2026-11-08T09:00:00+01:00', atMs: 1794729600000, mine: true, snoozed: false }, calendar: { state: 'synced', eventId: 912, calendarId: 7, mine: true } };
    assert.deepEqual(NS.taskMarks(task, me, t).map((k) => [k.kind, k.text]), [['reminder', 'Erinnerung'], ['calendar', 'im Kalender']]);
    assert.equal(NS.taskMarks(task, me, t)[1].long, 'Im Kalender „Aufgaben“ in Mail');
    // put off with „Später“: until when (today: the time, another day: the day too)
    assert.deepEqual(NS.taskMarks({ ...task, snoozed: true, reminder: { ...task.reminder, at: '2026-11-08T19:00:00+01:00' }, calendar: null }, me, t).map((k) => k.text), ['Später: 19:00']);
    assert.deepEqual(NS.taskMarks({ ...task, snoozed: true, reminder: { ...task.reminder, at: '2026-11-09T09:00:00+01:00' }, calendar: null }, me, t).map((k) => k.text), ['Später: morgen 9:00']);
    assert.equal(NS.taskMarks({ ...task, calendar: { ...task.calendar, state: 'pending' } }, me, t)[1].long, 'Wird gleich in den Kalender eingetragen');
    // done: no reminder to come; someone else's calendar: no mark
    assert.deepEqual(NS.taskMarks({ ...task, done: true, calendar: { ...task.calendar, mine: false } }, me, t), []);
    // the calendar needs all three: Mail offers it, the administrator's switch, the own switch
    for (const off of ['available', 'enabled', 'mine']) {
      const m = { ...me, calendar: { ...me.calendar, [off]: false } };
      assert.equal(NS.calendarName(m), null, off);
      assert.deepEqual(NS.taskMarks(task, m, t).map((k) => k.kind), ['reminder'], off);
    }
    // an older plugin: nothing, whatever the task says
    const old = { today: '2026-11-08', features: ['tasks'], calendar: me.calendar };
    assert.deepEqual(NS.taskMarks(task, old, t), []);
    assert.equal(NS.calendarName(old), null);
    assert.deepEqual(NS.taskMarks(task, null, t), []);
    assert.deepEqual(NS.taskMarks({ type: 'source', reminder: task.reminder }, me, t), []);

    const ctx = { today: '2026-11-08', now: '08:00', lists: [], people: [] };
    const kinds = (text, m) => NS.quickChips(NS.quickParse(text, ctx), ctx, 'private', t, 'de', m).map((c) => c.kind);
    assert.deepEqual(kinds('morgen 9 Uhr Mülltonne rausstellen', me), ['date', 'remind', 'calendar', 'area']);
    const chip = NS.quickChips(NS.quickParse('morgen 9 Uhr Mülltonne rausstellen', ctx), ctx, 'private', t, 'de', me).find((c) => c.kind === 'calendar');
    assert.equal(chip.text, 'Kalender: Aufgaben');
    assert.match(chip.title, /^Aufgaben mit Uhrzeit stehen als Termin im Kalender „Aufgaben“ in Mail\./);
    // a day without a time gets no event; an older plugin and a switched-off calendar get no chip
    assert.deepEqual(kinds('morgen Mülltonne rausstellen', me), ['date', 'area']);
    assert.deepEqual(kinds('morgen 9 Uhr Mülltonne rausstellen', old), ['date', 'remind', 'area']);
    assert.deepEqual(kinds('morgen 9 Uhr Mülltonne rausstellen', { ...me, calendar: { ...me.calendar, mine: false } }), ['date', 'remind', 'area']);
    assert.deepEqual(kinds('morgen 9 Uhr Mülltonne rausstellen', undefined), ['date', 'remind', 'area']);
  });

  it('plugin 1.3.0: „Gestern offen geblieben“ — the card, „Überfällig“ without its rows, the days of „Verschieben“', () => {
    const me = { today: '2026-11-19', features: ['tasks', 'yesterdayOpen'] };
    const a = { uid: 't:41', type: 'task', id: 41, title: 'Schrauben kaufen' };
    const b = { uid: 't:42', type: 'task', id: 42, title: 'Rezept abholen' };
    const c = { uid: 't:43', type: 'task', id: 43, title: 'Steuer' };
    const s = { uid: 's:203', type: 'source', id: 203, title: 'Rechnung' };
    const options = [{ to: 'tomorrow', date: '2026-11-20', label: 'Morgen' }, { to: 'weekend', date: '2026-11-21', label: 'Am Wochenende' }];
    const view = { view: 'myday', yesterday: { day: '2026-11-18', title: 'Gestern offen geblieben', count: 2, items: [a, b], moveOptions: options },
      sections: [{ id: 'overdue', title: 'Überfällig', count: 4, items: [a, s, b, c] }, { id: 'today', title: 'Heute', count: 1, items: [{ uid: 't:44' }] }] };
    const card = NS.yesterdayCard(view, me);
    assert.deepEqual([card.day, card.items.map((x) => x.uid)], ['2026-11-18', ['t:41', 't:42']]);
    const rest = NS.sectionsWithout(view.sections, card);
    assert.deepEqual(rest.map((x) => [x.id, x.count, x.items.map((y) => y.uid)]), [['overdue', 2, ['s:203', 't:43']], ['today', 1, ['t:44']]]);
    assert.equal(view.sections[0].items.length, 4);
    // no card: an older plugin (whatever the view says), nothing open, another view — the sections stay as they are
    assert.equal(NS.yesterdayCard(view, { today: '2026-11-19', features: ['tasks'] }), null);
    assert.equal(NS.yesterdayCard(view, null), null);
    assert.equal(NS.yesterdayCard({ ...view, yesterday: { ...view.yesterday, items: [] } }, me), null);
    assert.equal(NS.yesterdayCard({ ...view, yesterday: null }, me), null);
    assert.equal(NS.yesterdayCard({ ...view, view: 'planned' }, me), null);
    assert.equal(NS.sectionsWithout(view.sections, null), view.sections);

    assert.deepEqual(NS.moveChoices(options, t), [{ to: 'tomorrow', label: 'Morgen' }, { to: 'weekend', label: 'Am Wochenende' }]);
    assert.deepEqual(NS.moveChoices([], t), [{ to: 'tomorrow', label: 'Morgen' }, { to: 'weekend', label: 'Am Wochenende' }]);
    assert.deepEqual(NS.moveChoices([{ to: '2026-11-23', label: 'Montag' }, { to: 'today', label: 'Heute' }], t), [{ to: '2026-11-23', label: 'Montag' }]);
    // a button of the morning hint: what it named and is still open; it named nothing: all that is open; offline: what it named
    assert.deepEqual(NS.askedIds([41, 42, 99], [42, 41, 43]), [41, 42]);
    assert.deepEqual(NS.askedIds([], [42, 43]), [42, 43]);
    assert.deepEqual(NS.askedIds([41, 41, 'x'], null), [41]);
    assert.deepEqual(NS.askedIds([41], []), []);
  });

  it('plugin 1.4.0: the shopping lists, a task\'s list, the chip of the quick entry — only with the words of me.features', () => {
    const me = { today: '2026-11-08', features: ['tasks', 'shoppingLists', 'taskList'], user: { id: 1 } };
    const L = (o) => ({ id: 'list-einkauf-0001', listId: 12, name: 'Einkauf', icon: 'cart', area: 'private', family: false, shared: false, owner: { id: 1, name: 'Anna' }, members: [], open: 2, total: 3, tasks: [], ...o });
    const shop = { lists: [L({ family: true, shared: true }), L({ id: 'list-drogerie-0001', listId: 13, name: 'Drogerie', shared: true, members: [{ id: 2, name: 'Marc' }, { id: 3, name: 'Lena' }] }), L({ id: 'list-buero-000001', listId: 14, name: 'Büro', area: 'work' })],
      items: [{ id: 'i1', listId: 'list-einkauf-0001', text: 'Milch', checked: true }, { id: 'i2', listId: 'list-einkauf-0001', text: 'Brot', checked: false }, { id: 'i3', listId: 'list-drogerie-0001', text: 'Seife', checked: false }, { id: 'i4', listId: 'list-einkauf-0001', text: 'Äpfel', checked: false }] };
    // the menu: what the page holds for the area; before it is loaded, the menu's own rows
    assert.deepEqual(NS.shopNav(shop, null, 'private').map((l) => l.name), ['Einkauf', 'Drogerie']);
    assert.deepEqual(NS.shopNav(shop, null, 'work').map((l) => l.name), ['Büro']);
    assert.deepEqual(NS.shopNav(null, { shopping: [{ id: 'x', name: 'Einkauf' }] }, 'private').map((l) => l.name), ['Einkauf']);
    assert.deepEqual(NS.shopNav(null, { lists: [] }, 'private'), []);
    // a list's items: open first, each group in the order written
    assert.deepEqual(NS.shopItems(shop, 'list-einkauf-0001').map((i) => i.text), ['Brot', 'Äpfel', 'Milch']);
    assert.equal(NS.shopList(shop, 'nope'), null);
    // who it is shared with, the choice in a task's details, the line above the items
    assert.deepEqual(shop.lists.map((l) => NS.shopWith(l, 1, t)), ['Familie', 'Marc, Lena', 'nur ich']);
    assert.equal(NS.shopWith(L({ shared: true, owner: { id: 2, name: 'Marc' }, members: [{ id: 1, name: 'Anna' }] }), 1, t), 'Marc');
    assert.equal(NS.shopChoice(shop.lists[0], 1, t), 'Einkauf · Familie · 2 offen');
    assert.equal(NS.shopBelongs(L({}), t), null);
    assert.deepEqual(NS.shopBelongs(L({ open: 5, total: 8, tasks: [{ id: 41, title: 'Bei Lidl einkaufen' }] }), t), { text: 'gehört zu „Bei Lidl einkaufen“ · 3 von 8', taskId: 41 });
    assert.equal(NS.shopBelongs(L({ open: 8, total: 8, tasks: [{ id: 41, title: 'Bei Lidl einkaufen' }, { id: 42, title: 'x' }, { id: 43, title: 'y' }] }), t).text, 'gehört zu „Bei Lidl einkaufen“ und 2 weiteren · 0 von 8');
    assert.equal(NS.allTickedText([{ taskId: 41, title: 'Bei Lidl einkaufen' }], t), 'Alles abgehakt. „Bei Lidl einkaufen“ ist erledigt.');
    assert.equal(NS.allTickedText([{ taskId: 41, title: 'a' }, { taskId: 42, title: 'b' }], t), 'Alles abgehakt. 2 Aufgaben sind erledigt.');
    assert.equal(NS.allTickedText([], t), '');

    // the mark of a task: „Einkauf 0/8“ — after the reminder, before the calendar; not for an older plugin
    const al = { id: 12, uid: 'list-einkauf-0001', name: 'Einkauf', icon: 'cart', open: 8, total: 8, done: 0, family: true };
    const task = { type: 'task', id: 41, done: false, attachedList: al };
    assert.deepEqual(NS.taskMarks(task, me, t).map((k) => [k.kind, k.text, k.uid]), [['list', 'Einkauf 0/8', 'list-einkauf-0001']]);
    assert.deepEqual(NS.taskMarks({ ...task, attachedList: { ...al, open: 5, done: 3 } }, me, t)[0].text, 'Einkauf 3/8');
    assert.deepEqual(NS.taskMarks(task, { ...me, features: ['tasks', 'shoppingLists'] }, t), []);
    assert.deepEqual(NS.taskMarks({ ...task, attachedList: null }, me, t), []);

    // the quick entry: the server's suggestion and what the person did with the chip
    const drog = { ...al, id: 13, uid: 'list-drogerie-0001', name: 'Drogerie', open: 1 };
    const one = { via: 'word', word: 'einkaufen', list: al, lists: [al] };
    assert.deepEqual(NS.quickAttach(one, undefined), { list: al, lists: [al], tag: false });
    assert.equal(NS.quickAttach(one, null).list, null);
    assert.equal(NS.quickAttach(one, 12).list, al);
    const many = { via: 'word', word: 'einkaufen', list: null, lists: [al, drog] };
    assert.deepEqual([NS.quickAttach(many, undefined).list, NS.quickAttach(many, 13).list, NS.quickAttach(many, 99).list], [null, drog, null]);
    assert.deepEqual([NS.quickAttach(null, undefined), NS.quickAttach({ via: 'word', lists: [] }, undefined)], [null, null]);
    const ctx = { today: '2026-11-08', now: '08:00', lists: [], people: [] };
    const view = { kind: 'smart', id: 'myday' };
    const p = NS.quickParse('bei Lidl einkaufen', ctx);
    assert.deepEqual(NS.quickBody('bei Lidl einkaufen', p, view, 'private', NS.quickAttach(one, undefined)), { text: 'bei Lidl einkaufen', area: 'private', createList: false, attachedListId: 12, myDay: true });
    // the chip taken away, an older plugin: no field — the server attaches nothing by itself
    assert.deepEqual(NS.quickBody('bei Lidl einkaufen', p, view, 'private', NS.quickAttach(one, null)), { text: 'bei Lidl einkaufen', area: 'private', createList: false, myDay: true });
    assert.deepEqual(NS.quickBody('bei Lidl einkaufen', p, view, 'private'), { text: 'bei Lidl einkaufen', area: 'private', createList: false, myDay: true });
    // Enter before the suggestion came: the server decides
    assert.deepEqual(NS.quickBody('bei Lidl einkaufen', p, view, 'private', 'auto'), { text: 'bei Lidl einkaufen', area: 'private', createList: false, attach: 'auto', myDay: true });
    // „#einkauf“ names the shopping list: no task list „einkauf“ is made, no chip offers one
    const tagged = NS.quickParse('Milch holen #einkauf', ctx);
    const viaTag = NS.quickAttach({ via: 'tag', list: al, lists: [al] }, undefined);
    assert.equal(tagged.listName, 'einkauf');
    assert.deepEqual(NS.quickChips(tagged, ctx, 'private', t, 'de', me).map((c) => c.kind), ['list', 'area']);
    assert.deepEqual(NS.quickChips(tagged, ctx, 'private', t, 'de', me, viaTag).map((c) => c.kind), ['area']);
    assert.deepEqual(NS.quickBody('Milch holen #einkauf', tagged, view, 'private', viaTag), { text: 'Milch holen #einkauf', area: 'private', createList: false, attachedListId: 12, myDay: true });
    // … taken away again: the word is what the parser made of it
    assert.equal(NS.quickBody('Milch holen #einkauf', tagged, view, 'private', NS.quickAttach({ via: 'tag', list: al, lists: [al] }, null)).createList, true);
    assert.deepEqual(NS.quickChips(tagged, ctx, 'private', t, 'de', me, NS.quickAttach({ via: 'tag', list: al, lists: [al] }, null)).map((c) => c.kind), ['list', 'area']);
  });

  it('plugin 1.5.0: a task at a place — the mark, what the dialog sends, the chip of the quick entry, the hints; only with the words of me.features', () => {
    const places = { search: { state: 'on', enabled: true, mine: true }, nearby: true, quiet: null, perTask: 5, radius: { min: 50, max: 2000, default: 150 }, family: true };
    const me = { today: '2026-11-08', features: ['tasks', 'places', 'placeSearch'], user: { id: 1 }, places };
    const old = { today: '2026-11-08', features: ['tasks', 'shoppingLists', 'taskList'], user: { id: 1 } };
    const place = { mode: 'place', id: 1, name: 'Baumarkt Nord', address: 'Industriestraße 4, Berlin', lat: 52.539, lon: 13.424, radius: 150, ref: 'osm:W101', own: false, trigger: 'enter', key: 'kind:diy', label: 'Baumarkt', by: 1, consent: 'accepted', watch: true, nearby: true };
    const task = { type: 'task', id: 41, title: 'Schrauben kaufen', place };
    assert.deepEqual(NS.taskMarks(task, me, t), [{ kind: 'place', text: 'Baumarkt Nord', title: 'Baumarkt Nord · beim Ankommen' }]);
    assert.deepEqual(NS.taskMarks(task, old, t), []);
    assert.deepEqual(NS.taskMarks({ ...task, place: null }, me, t), []);
    assert.equal(NS.placeSummary({ ...place, trigger: 'exit' }, t), 'Baumarkt Nord · beim Verlassen');
    assert.deepEqual([NS.distText(2315, 'de'), NS.distText(2315, 'en'), NS.distText(320, 'de'), NS.distText(20, 'de'), NS.distText(null, 'de')], ['2,3 km', '2.3 km', '300 m', '50 m', '']);
    // the search: only with both words and `me.places.search.state`
    assert.deepEqual([NS.searchState(me), NS.searchState(old), NS.searchState({ ...me, features: ['places'] }), NS.searchState({ ...me, places: { ...places, search: { state: 'unavailable' } } }), NS.searchState({ ...me, places: { ...places, search: { state: 'off' } } })],
      ['on', 'off', 'off', 'unavailable', 'off']);
    // this PC has no position: a search is made near one of the person's places — the family's first
    const all = { family: [{ familyId: 'home', name: 'Zuhause' }, { familyId: 'place:3', name: 'Schule' }], places: [{ id: 2, name: 'Oma', address: 'Gartenweg 5', favFor: [] }, { id: 1, name: 'Baumarkt Nord', address: 'Industriestraße 4, Berlin', favFor: [{ key: 'kind:diy', label: 'Baumarkt' }] }] };
    assert.deepEqual(NS.nearOptions(all), [{ value: 'f:home', label: 'Zuhause' }, { value: 'f:place:3', label: 'Schule' }, { value: 'p:2', label: 'Oma' }, { value: 'p:1', label: 'Baumarkt Nord' }]);
    assert.deepEqual([NS.nearOptions(null), NS.nearArg('f:home'), NS.nearArg('f:place:3'), NS.nearArg('p:2'), NS.nearArg(''), NS.nearArg('p:x'), NS.nearArg(undefined)], [[], { nearFamilyId: 'home' }, { nearFamilyId: 'place:3' }, { nearPlaceId: 2 }, {}, {}, {}]);
    assert.deepEqual([NS.placeSub(all.places[0], t), NS.placeSub(all.places[1], t)], ['Gartenweg 5', 'Industriestraße 4, Berlin · gemerkt für „Baumarkt“']);

    // what the dialog sends as `place` of POST / PATCH tasks
    const hit = { ref: 'osm:W101', name: 'Baumarkt Nord', address: 'Industriestraße 4, Berlin', lat: 52.539, lon: 13.424, distanceM: 2315, minutes: 6, placeId: null, fav: false, uses: 0 };
    const o = { trigger: 'enter', key: 'kind:diy', label: 'Baumarkt', remember: true };
    assert.deepEqual(NS.placeChoiceArg({ type: 'hit', hit }, o), { trigger: 'enter', key: 'kind:diy', label: 'Baumarkt', remember: true, ref: 'osm:W101', name: 'Baumarkt Nord', address: 'Industriestraße 4, Berlin', lat: 52.539, lon: 13.424 });
    // a hit that is one of the own places already goes by its number
    assert.deepEqual(NS.placeChoiceArg({ type: 'hit', hit: { ...hit, placeId: 1, fav: true } }, { ...o, remember: false }), { trigger: 'enter', key: 'kind:diy', label: 'Baumarkt', placeId: 1 });
    assert.deepEqual(NS.placeChoiceArg({ type: 'own', placeId: 2 }, { trigger: 'exit', key: null }), { trigger: 'exit', key: null, placeId: 2 });
    assert.deepEqual(NS.placeChoiceArg({ type: 'family', familyId: 'home' }, o), { trigger: 'enter', familyId: 'home', key: null });
    assert.deepEqual(NS.placeChoiceArg({ type: 'any' }, { trigger: 'enter', key: 'name:lidl', label: 'Lidl', remember: true }), { trigger: 'enter', any: true, key: 'name:lidl', label: 'Lidl' });
    // an address hit has no kind: a point at the task; nothing chosen: only the trigger
    assert.deepEqual(NS.placeChoiceArg({ type: 'hit', hit: { ref: 'osm:W900', name: 'Ringstraße 21', address: '', lat: 52.5, lon: 13.3 } }, { trigger: 'enter', key: null }), { trigger: 'enter', key: null, ref: 'osm:W900', name: 'Ringstraße 21', lat: 52.5, lon: 13.3 });
    assert.deepEqual(NS.placeChoiceArg(null, { trigger: 'exit', key: 'kind:diy' }), { trigger: 'exit' });
    assert.deepEqual([NS.placeChoiceText({ type: 'hit', hit }, o, all, t), NS.placeChoiceText({ type: 'any' }, { label: 'Lidl' }, all, t), NS.placeChoiceText({ type: 'family', familyId: 'home' }, o, all, t), NS.placeChoiceText({ type: 'own', placeId: 2 }, o, all, t), NS.placeChoiceText(null, o, all, t)],
      ['Baumarkt Nord', 'Jeder Lidl', 'Zuhause', 'Oma', '']);

    // the hints under „Ort“
    assert.deepEqual(NS.placeHint(task, me, t), { kind: 'nearby', text: 'Kommt dein Handy an einem anderen Ort der Art „Baumarkt“ vorbei, meldet sich die Aufgabe auch dort.', ask: false });
    assert.equal(NS.placeHint({ ...task, place: { ...place, nearby: false } }, me, t), null);
    assert.equal(NS.placeHint(task, { ...me, places: { ...places, nearby: false } }, t), null);
    assert.equal(NS.placeHint(task, old, t), null);
    // someone else set the place at my task: I am asked; I set it for someone else: it waits
    const mine = NS.placeHint({ ...task, place: { ...place, by: 12, consent: 'pending', watch: false } }, me, t);
    assert.deepEqual([mine.kind, mine.ask], ['consentMe', true]);
    assert.deepEqual([NS.placeHint({ ...task, assignee: { id: 1 }, place: { ...place, by: 12, consent: 'pending' } }, me, t).kind, NS.placeHint({ ...task, assignee: { id: 12 }, place: { ...place, by: 1, consent: 'pending' } }, me, t).kind,
      NS.placeHint({ ...task, assignee: { id: 15 }, place: { ...place, by: 12, consent: 'pending' } }, me, t).ask, NS.placeHint({ ...task, place: { ...place, consent: 'declined' } }, me, t).kind], ['consentMe', 'consentWait', false, 'declined']);
    // „Jeder Lidl“ needs the search
    const anyPlace = { mode: 'any', name: 'Jeder Lidl', trigger: 'enter', key: 'name:lidl', label: 'Lidl', consent: 'accepted', nearby: false };
    assert.equal(NS.placeHint({ ...task, place: anyPlace }, { ...me, places: { ...places, search: { state: 'off' } } }, t).kind, 'needsSearch');
    assert.equal(NS.placeHint({ ...task, place: anyPlace }, me, t), null);

    // the quick entry: the server's suggestion and what the person did with the chip
    const sug = { via: 'kind', word: 'beim Baumarkt', query: 'Baumarkt', key: 'kind:diy', label: 'Baumarkt', title: 'Schrauben kaufen', certain: true, trigger: 'enter', place: null, uses: 0, options: [], search: 'on' };
    const ask = NS.quickPlace(sug, undefined, t);
    assert.deepEqual([ask.state, ask.text, ask.plain, ask.arg, ask.hint], ['ask', 'Ort: Baumarkt …', true, null, { key: 'kind:diy', label: 'Baumarkt', query: 'Baumarkt', trigger: 'enter' }]);
    assert.equal(NS.quickPlace(null, undefined, t), null);
    // the search is off: „Ort wählen“ (the remembered places stay)
    assert.deepEqual([NS.quickPlace({ ...sug, search: 'off' }, undefined, t).state, NS.quickPlace({ ...sug, search: 'unavailable' }, undefined, t).text], ['choose', 'Ort wählen']);
    // the remembered place stands; an own place and a place of the family likewise
    const own = { id: 1, name: 'Baumarkt Nord', address: 'Industriestraße 4, Berlin', lat: 52.539, lon: 13.424, radius: 150, named: false, ref: 'osm:W101' };
    const set = NS.quickPlace({ ...sug, place: own, uses: 6, options: [own] }, undefined, t);
    assert.deepEqual([set.state, set.text, set.plain, set.arg, /zuletzt 6-mal gewählt/.test(set.title)], ['set', 'Ort: Baumarkt Nord · beim Ankommen', false, { placeId: 1, key: 'kind:diy', trigger: 'enter' }, true]);
    assert.deepEqual(NS.quickPlace({ via: 'own', key: null, label: 'Oma', certain: true, trigger: 'enter', place: { id: 2, name: 'Oma' }, search: 'on' }, undefined, t).arg, { placeId: 2, trigger: 'enter' });
    assert.deepEqual(NS.quickPlace({ via: 'family', key: null, label: 'Zuhause', certain: true, trigger: 'enter', place: { familyId: 'home', name: 'Zuhause', family: true }, search: 'off' }, undefined, t).arg, { familyId: 'home', trigger: 'enter' });
    // not surely meant („Apotheke anrufen“): a suggestion, nothing is set
    const maybe = NS.quickPlace({ ...sug, key: 'kind:pharmacy', label: 'Apotheke', query: 'Apotheke', certain: false }, undefined, t);
    assert.deepEqual([maybe.state, maybe.text, maybe.arg, maybe.plain], ['maybe', 'Ort: Apotheke ?', null, true]);
    assert.deepEqual(NS.quickPlace({ ...sug, certain: false, place: own }, undefined, t).arg, null);
    // chosen in the dialog; taken away with ×
    const chosen = NS.quickPlace(sug, { arg: { trigger: 'exit', key: 'kind:diy', ref: 'osm:W102', name: 'Baumarkt am Ring', lat: 52.501, lon: 13.362 }, text: 'Baumarkt am Ring' }, t);
    assert.deepEqual([chosen.state, chosen.text, chosen.arg.ref], ['set', 'Ort: Baumarkt am Ring · beim Verlassen', 'osm:W102']);
    assert.deepEqual([NS.quickPlace({ ...sug, place: own }, null, t).state, NS.quickPlace({ ...sug, place: own }, null, t).arg], ['off', null]);

    // the body of POST tasks: the place that stands; taken away, not chosen or an older plugin: no field; before the suggestion came: 'auto'
    const view = { kind: 'smart', id: 'myday' };
    const ctx = { today: '2026-11-08', now: '08:00', lists: [], people: [] };
    const text = 'beim Baumarkt Schrauben kaufen';
    const p = NS.quickParse(text, ctx);
    // the parser on this PC knows nothing of the place: the title stays whole there
    assert.equal(p.title, text);
    assert.deepEqual(NS.quickBody(text, p, view, 'private', null, set), { text, area: 'private', createList: false, place: { placeId: 1, key: 'kind:diy', trigger: 'enter' }, myDay: true });
    assert.deepEqual(NS.quickBody(text, p, view, 'private', null, 'auto'), { text, area: 'private', createList: false, place: 'auto', myDay: true });
    for (const qp of [ask, maybe, NS.quickPlace(sug, null, t), null, undefined]) assert.deepEqual(NS.quickBody(text, p, view, 'private', null, qp), { text, area: 'private', createList: false, myDay: true });
    assert.deepEqual(NS.quickBody(text, p, view, 'private', 'auto', 'auto'), { text, area: 'private', createList: false, place: 'auto', attach: 'auto', myDay: true });
  });

  it('plugin 1.6.0: whose turn, stars, the family\'s list — the marks, the quick entry, what the details send; only with the words of me.features', () => {
    const fam = { available: true, bound: true, listId: 9, parent: true, stars: true, starsMax: 10, moved: { at: '2026-11-08T07:00:00Z', tasks: 12, places: 3, seen: false } };
    const me = { features: ['tasks', 'taskTurns', 'taskStars', 'familyTasks', 'doneFeedback', 'placeMine', 'places'], user: { id: 1, name: 'Max Muster' }, today: '2026-11-08', time: '08:00', prefs: { times: {} }, familyTasks: fam };
    const old = { ...me, features: ['tasks', 'places'], familyTasks: null };
    const child = { ...me, user: { id: 15, name: 'Noah Muster' }, familyTasks: { ...fam, parent: false } };
    const people = [{ id: 15, name: 'Noah Muster' }, { id: 16, name: 'Mia Muster' }];
    const rot = { type: 'task', id: 7, listId: 9, title: 'Spülmaschine ausräumen', turn: 'rotate', people, assignee: people[0], stars: 2, family: true, done: false, doneBy: null };

    // the family's list and who may give stars
    assert.deepEqual([NS.familyInfo(me).bound, NS.familyInfo(old).bound, NS.familyInfo({ ...me, familyTasks: { ...fam, bound: false } }).bound, NS.familyInfo({ ...me, features: ['familyTasks'] }).stars], [true, false, false, false]);
    assert.deepEqual([NS.isFamilyList(me, 9), NS.isFamilyList(me, 2), NS.isFamilyList(old, 9), NS.mayStar(me, 9), NS.mayStar(child, 9), NS.starsShown(child, 9), NS.mayStar(me, 2), NS.starsShown({ ...me, familyTasks: { ...fam, stars: false } }, 9)],
      [true, false, false, true, false, true, false, false]);
    assert.deepEqual([NS.starsText(1, t), NS.starsText(3, t), NS.starChoices({ ...me, familyTasks: { ...fam, starsMax: 3 } }, t).map((c) => c.label)], ['1 Stern', '3 Sterne', ['keine', '1 Stern', '2 Sterne', '3 Sterne']]);

    // the marks of a row
    assert.deepEqual(NS.taskMarks(rot, me, t).map((k) => [k.kind, k.text]), [['turn', 'Reihum · Noah ist dran'], ['stars', '2 Sterne']]);
    assert.deepEqual(NS.taskMarks(rot, child, t).map((k) => k.text), ['Reihum · du bist dran', '2 Sterne']);
    assert.deepEqual(NS.taskMarks({ ...rot, turn: 'first', assignee: null, stars: 0 }, me, t).map((k) => [k.kind, k.text, k.first]), [['turn', 'Wer zuerst', true]]);
    assert.deepEqual(NS.taskMarks(rot, old, t), []);
    // stars only in the family's list; „Erledigt von …“ for somebody else (or a task for several)
    assert.deepEqual(NS.taskMarks({ ...rot, listId: 2, turn: null, people: [] }, me, t), []);
    assert.deepEqual(NS.taskMarks({ ...rot, done: true, doneBy: people[0] }, me, t).map((k) => [k.kind, k.text]), [['stars', '2 Sterne'], ['doneby', 'Erledigt von Noah']]);
    assert.deepEqual([NS.doneByText({ ...rot, turn: null, done: true, doneBy: { id: 1, name: 'Max Muster' } }, me, t), NS.doneByText({ ...rot, turn: 'first', done: true, doneBy: { id: 1, name: 'Max Muster' } }, me, t), NS.doneByText({ ...rot, done: true, doneBy: people[0] }, old, t), NS.doneByText(rot, me, t)],
      ['', 'Erledigt von dir', '', '']);
    // the grey line does not name who is on a second time
    assert.deepEqual(NS.metaLine(rot, { userId: 1, lists: [], inList: true }, t), []);
    assert.deepEqual(NS.metaLine({ ...rot, turn: null }, { userId: 1, lists: [], inList: true }, t), ['Noah Muster']);

    // the quick entry: what the line says (the plugin's turnwords after the parser), the chips, „Wer ist dran?“
    const ctx = NS.quickCtx(me, { lists: [{ id: 9, name: 'Familie' }, { id: 2, name: 'Haus & Garten' }] }, [{ id: 12, name: 'Jenny Muster' }, ...people]);
    const line = '@Noah @Mia Spülmaschine ausräumen täglich 18 Uhr reihum 2 Sterne';
    const p = NS.quickParse(line, ctx);
    const inFam = { kind: 'list', id: 9 };
    const w = NS.quickWords(p, ctx, me, inFam);
    assert.deepEqual([w.title, w.people.map((x) => x.id), w.turn, w.stars], ['Spülmaschine ausräumen', [15, 16], 'rotate', 2]);
    assert.deepEqual(NS.quickTurn(w, undefined), { value: 'rotate', said: 'rotate' });
    assert.deepEqual(NS.quickChips(p, ctx, 'private', t, 'de', me, null, w, NS.quickTurn(w)).map((c) => [c.kind, c.text]),
      [['date', 'heute, 18:00'], ['remind', 'Erinnerung 18:00'], ['repeat', '↻ Täglich'], ['person', 'Noah, Mia'], ['turn', 'Reihum · zuerst Noah'], ['stars', '2 Sterne'], ['area', 'Privat']]);
    assert.deepEqual(NS.quickChips(p, ctx, 'private', t, 'de', me, null, w, NS.quickTurn(w, 'first')).filter((c) => c.kind === 'turn').map((c) => c.text), ['Wer zuerst']);
    assert.deepEqual(NS.quickChips(p, ctx, 'private', t, 'de', me, null, w, NS.quickTurn(w, 'one')).filter((c) => c.kind === 'turn'), []);
    // untouched: the server reads the line as this PC did; chosen otherwise: it goes with the task
    assert.deepEqual(NS.quickBody(line, p, inFam, 'private', null, null, w, NS.quickTurn(w)), { text: line, area: 'private', createList: false, listId: 9 });
    assert.deepEqual(NS.quickBody(line, p, inFam, 'private', null, null, w, NS.quickTurn(w, 'first')), { text: line, area: 'private', createList: false, turn: 'first', people: [15, 16], listId: 9 });
    assert.deepEqual(NS.quickBody(line, p, inFam, 'private', null, null, w, NS.quickTurn(w, 'one')), { text: line, area: 'private', createList: false, turn: null, listId: 9 });
    // two people without a word: „Eine Person“ until the person chooses
    const two = NS.quickWords(NS.quickParse('@Noah @Mia Zimmer aufräumen', ctx), ctx, me, inFam);
    assert.deepEqual([NS.quickTurn(two), NS.quickTurn(two, 'rotate')], [{ value: 'one', said: 'one' }, { value: 'rotate', said: 'one' }]);
    // one person: no choice; stars only where the person may give them: another list, a child, the list named with #
    assert.equal(NS.quickTurn(NS.quickWords(NS.quickParse('@Noah Zimmer aufräumen', ctx), ctx, me, inFam)), null);
    const hotel = NS.quickParse('Hotel 4 Sterne buchen', ctx);
    assert.deepEqual([NS.quickWords(hotel, ctx, me, { kind: 'smart', id: 'myday' }).title, NS.quickWords(hotel, ctx, me, { kind: 'list', id: 2 }).stars, NS.quickWords(hotel, ctx, child, inFam).stars, NS.quickWords(hotel, ctx, me, inFam).stars],
      ['Hotel 4 Sterne buchen', null, null, 4]);
    assert.equal(NS.quickWords(NS.quickParse('Zimmer aufräumen 2 Sterne #familie', ctx), ctx, me, { kind: 'smart', id: 'myday' }).stars, 2);
    assert.equal(NS.quickWords(NS.quickParse('Zimmer aufräumen 2 Sterne #haus', ctx), ctx, me, inFam).stars, null);
    // an older plugin: the page reads nothing of it and shows the chips as before
    assert.equal(NS.quickWords(p, ctx, old, inFam), null);
    assert.deepEqual(NS.quickChips(p, ctx, 'private', t, 'de', old, null, null, null).filter((c) => c.kind === 'person').map((c) => c.text), ['@Noah Muster']);
    assert.deepEqual(NS.quickBody(line, p, inFam, 'private', null, null, null, null), { text: line, area: 'private', createList: false, listId: 9 });

    // the details: what „Wer ist dran?“ sends
    const members = [{ id: 1, name: 'Max Muster' }, { id: 12, name: 'Jenny Muster' }, ...people];
    assert.deepEqual(NS.turnPatch(rot, 'one', []), { turn: null });
    assert.deepEqual(NS.turnPatch(rot, 'first', [15, 16, 16]), { turn: 'first', people: [15, 16] });
    assert.deepEqual(NS.turnPatch(rot, 'rotate', [16, 15]), { turn: 'rotate', people: [16, 15], assigneeId: 15 });
    assert.deepEqual(NS.turnPatch({ ...rot, assignee: { id: 12 } }, 'rotate', [16, 15]), { turn: 'rotate', people: [16, 15] });
    assert.equal(NS.turnPatch(rot, 'rotate', [15]), null);
    assert.deepEqual([NS.turnPeople(rot, members), NS.turnPeople({ ...rot, people: [] }, members)], [[15, 16], [1, 12, 15, 16]]);

    // who is asked to accept a place: the server says it (placeMine) — a third person only sees the state
    const place = { mode: 'place', name: 'Lidl', trigger: 'enter', by: 12, consent: 'pending' };
    const task = { type: 'task', id: 8, assignee: { id: 15 }, place };
    assert.deepEqual([NS.placeHint({ ...task, place: { ...place, mine: true, canConsent: true } }, me, t).ask, NS.placeHint({ ...task, assignee: null, place: { ...place, mine: false, canConsent: false } }, me, t).kind,
      NS.placeHint({ ...task, assignee: null, place: { ...place, mine: false, canConsent: false } }, me, t).ask], [true, 'consentWait', false]);
    assert.deepEqual([NS.placeHint({ ...task, place: { ...place, consent: 'declined', canConsent: true } }, me, t).ask, NS.placeHint({ ...task, place: { ...place, consent: 'declined', canConsent: false } }, me, t).ask], [true, false]);
    // without the word (or the field) as before: the person the task belongs to, when someone else set the place
    const before = { ...me, features: me.features.filter((f) => f !== 'placeMine') };
    assert.deepEqual([NS.placeHint({ ...task, assignee: null, place: { ...place, canConsent: false } }, before, t).ask, NS.placeHint({ ...task, assignee: null, place }, me, t).ask, NS.placeHint({ ...task, place: { ...place, consent: 'declined' } }, me, t).ask], [true, true, false]);

    // what the server refuses
    assert.deepEqual([NS.errText({ code: 'forbidden', reason: 'parents_only' }, t), NS.errText({ code: 'forbidden', reason: 'family' }, t), NS.errText({ code: 'invalid', reason: 'family' }, t), NS.errText({ code: 'not_member' }, t)],
      ['Das können nur die Eltern ändern.', 'Die Liste der Familie verwaltet das Familien-Plugin.', 'Sterne gibt es nur in der Liste der Familie.', 'Die Person ist nicht in dieser Liste.']);
  });

  it('where an item of another plugin opens (contract § 5)', () => {
    const all = ['mail', 'drive', 'schule', 'notizen'];
    assert.deepEqual(NS.openTarget({ plugin: 'gatecontrol-mail', route: 'message/4711' }, all), { page: 'mail', context: { kind: 'message', messageId: 4711, accountId: null } });
    assert.deepEqual(NS.openTarget({ plugin: 'gatecontrol-drive', route: 'node/501' }, all), { page: 'drive', context: { kind: 'deadline', nodeId: 501, deadlineId: null } });
    assert.deepEqual(NS.openTarget({ plugin: 'gatecontrol-schule', route: 'homework/90' }, all), { page: 'schule', context: null });
    assert.deepEqual(NS.openTarget({ plugin: 'gatecontrol-notizen', route: 'note/812' }, all), { page: 'notizen', note: 812 });
    assert.deepEqual(NS.openTarget({ plugin: 'gatecontrol-familie', route: 'task/31' }, all), { portal: '/portal#plg-gatecontrol-familie' });
    // Mail not on this server: its portal tab
    assert.deepEqual(NS.openTarget({ plugin: 'gatecontrol-mail', route: 'message/1' }, ['drive']), { portal: '/portal#plg-gatecontrol-mail' });
    assert.equal(NS.openTarget({ plugin: 'evil/../x', route: '' }, all), null);
  });

  it('the repeat choices, failures, Tresor states, an import', () => {
    const r = NS.repeatOptions({ due: { date: '2026-11-09' }, repeat: { type: 'weekly', interval: 1, days: [1] } }, '2026-11-08', t, 'de');
    assert.equal(r.value, 'weekly');
    assert.equal(r.options.find((o) => o.value === 'weekly').label, 'Jeden Montag');
    const c = NS.repeatOptions({ repeat: { type: 'after', interval: 3 } }, '2026-11-08', t, 'de');
    assert.equal(c.value, 'custom');
    assert.equal(c.options[c.options.length - 1].label, R.describe({ type: 'after', interval: 3 }, 'de'));
    assert.equal(NS.errText({ code: 'vault_locked' }, t), 'Der Tresor ist gesperrt.');
    assert.equal(NS.errText({ code: 'weird' }, t), 'Das hat nicht geklappt (weird).');
    assert.equal(NS.errText({ code: 'forbidden', reason: 'read_only' }, t), 'Das lässt sich nur dort abhaken.');
    assert.deepEqual(NS.vaultLocked('locked', t).actions, ['unlock', 'recover']);
    assert.deepEqual(NS.vaultLocked('none', t).actions, ['ask', 'recover']);
    assert.match(NS.importText({ state: 'done', notes: 3, skipped: 0, protectedSkipped: 1 }, t), /^3 Notizen übernommen, 1 übersprungen\. 1 geschützte/);
    assert.equal(NS.importText({ state: 'running', done: 2, total: 4 }, t), '2 von 4 Notizen …');
    assert.equal(NS.groupKey('gatecontrol-mail', 'account:2'), 'gatecontrol-mail|account:2');
    assert.equal(NS.formatBytes(1.4 * 1073741824, 'de'), '1,4 GB');
  });
});

describe('plugin 1.7.0: a task that reminds of a deadline of a file in Drive', () => {
  const me = { features: ['tasks', 'reminderActions', 'driveDeadlines'], user: { id: 1, name: 'Max Muster' }, today: '2026-11-08', time: '08:00', prefs: { times: {} } };
  const old = { ...me, features: ['tasks', 'reminderActions'] };
  const deadline = { date: '2026-11-30', kind: 'cancellation', file: 'Versicherungsschein.pdf', daysBefore: 3, open: { plugin: 'gatecontrol-drive', route: 'node/41' } };
  const task = { type: 'task', id: 77, listId: 1, title: 'Kfz-Versicherung kündigen', due: { date: '2026-11-30', time: null }, source: { plugin: 'gatecontrol-drive', id: 'deadline:12' }, deadline, done: false };

  it('the row: „Frist …“, the file, how many days before — only with the word, and not for any other task', () => {
    const ctx = { userId: 1, me, lists: [], inList: true };
    assert.deepEqual(NS.metaLine(task, ctx, t), ['Frist Mo. 30. Nov.', 'Versicherungsschein.pdf', '3 Tage vorher']);
    assert.deepEqual(NS.sourceChip(task, t), { text: 'Drive', tone: 'ok' });
    // a done task says no more when it would have rung
    assert.deepEqual(NS.metaLine({ ...task, done: true }, ctx, t), ['Frist Mo. 30. Nov.', 'Versicherungsschein.pdf']);
    assert.deepEqual([0, 1, 14].map((daysBefore) => NS.metaLine({ ...task, deadline: { ...deadline, daysBefore } }, ctx, t)[2]), ['Erinnerung am Tag selbst', '1 Tag vorher', '14 Tage vorher']);
    assert.deepEqual(NS.metaLine({ ...task, deadline: { ...deadline, date: '2026-11-09', file: null, daysBefore: null } }, ctx, t), ['Frist morgen']);
    // an older plugin (no word), an older app context (no me), a task without a deadline
    assert.deepEqual(NS.metaLine(task, { ...ctx, me: old }, t), []);
    assert.deepEqual(NS.metaLine(task, { userId: 1, lists: [], inList: true }, t), []);
    assert.deepEqual(NS.metaLine({ ...task, deadline: null }, ctx, t), []);
    assert.deepEqual([NS.deadlineBefore(null, t), NS.deadlineBefore(-1, t), NS.deadlineBefore(2.5, t)], ['', '', '']);
  });

  it('the details: the day, the file and where „Datei öffnen“ leads — the Drive page of this app', () => {
    const d = NS.deadlineInfo(task, me, t);
    assert.deepEqual(d, { line: 'Frist Mo. 30. Nov.', file: 'Versicherungsschein.pdf', before: '3 Tage vorher', open: deadline.open });
    assert.deepEqual(NS.openTarget(d.open, ['drive', 'notizen']), { page: 'drive', context: { kind: 'deadline', nodeId: 41, deadlineId: null } });
    // no Drive page in this app: the plugin's portal tab
    assert.deepEqual(NS.openTarget(d.open, ['notizen']), { portal: '/portal#plg-gatecontrol-drive' });
    // a file that cannot be named: no button
    assert.equal(NS.deadlineInfo({ ...task, deadline: { ...deadline, open: null } }, me, t).open, null);
    assert.equal(NS.deadlineInfo({ ...task, deadline: { ...deadline, open: { plugin: 'gatecontrol-drive', route: '' } } }, me, t).open, null);
    assert.equal(NS.deadlineInfo(task, old, t), null);
    assert.equal(NS.deadlineInfo({ ...task, deadline: undefined }, me, t), null);
    assert.equal(NS.deadlineInfo({ type: 'source', deadline }, me, t), null);
    assert.equal(t('notes.dl.deleteHint'), 'Löschen entfernt die Erinnerung an diese Frist. Die Frist bleibt in Drive.');
    assert.equal(get(en, 'notes.dl.deleteHint'), 'Deleting removes the reminder of this deadline. The deadline stays in Drive.');
  });

  it('a list the person only reads: no quick entry', () => {
    assert.deepEqual([NS.listWritable({ id: 2, role: 'read', canEdit: false }, me), NS.listWritable({ id: 2, role: 'write', canEdit: true }, me), NS.listWritable({ id: 2 }, me), NS.listWritable(null, me), NS.listWritable({ id: 2, canEdit: true }, { ...me, readOnly: true })],
      [false, true, true, true, false]);
  });
});

describe('the page', () => {
  const view = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'notes-view.js'), 'utf8');
  it('builds its DOM without HTML strings', () => {
    for (const f of ['notes-view.js', 'notes-state.js', 'notes-md.js']) {
      const src = fs.readFileSync(path.join(ROOT, 'src', 'renderer', f), 'utf8');
      assert.ok(!/\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|DOMParser|createContextualFragment/.test(src), f);
    }
    // a link of a note never becomes an href: the main process opens it
    assert.ok(!/setAttribute\('href'|\bhref:/.test(view));
  });

  it('index.html loads the plugin\'s parser before the page, every notes.* key exists in both languages', () => {
    const html = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'index.html'), 'utf8');
    const order = ['vendor/notizen/repeat.js', 'vendor/notizen/quickparse.js', 'vendor/notizen/turnwords.js', 'notes-md.js', 'notes-state.js', 'notes-view.js', 'renderer.js'].map((s) => html.indexOf(`<script src="${s}"></script>`));
    assert.ok(order.every((x, i) => x > 0 && (i === 0 || x > order[i - 1])), JSON.stringify(order));
    assert.match(html, /id="nav-notizen"[^>]*hidden/);
    const used = new Set();
    for (const f of ['notes-view.js', 'notes-state.js', 'renderer.js']) {
      const src = fs.readFileSync(path.join(ROOT, 'src', 'renderer', f), 'utf8');
      for (const m of src.matchAll(/t\('(notes\.[A-Za-z0-9_.]+)'/g)) used.add(m[1]);
    }
    assert.ok(used.size > 150);
    for (const k of used) {
      assert.equal(typeof get(de, k), 'string', `de: ${k}`);
      assert.equal(typeof get(en, k), 'string', `en: ${k}`);
    }
    for (const k of ['wd', 'wdl']) for (let i = 1; i <= 7; i++) assert.ok(get(de, `notes.${k}.${i}`) && get(en, `notes.${k}.${i}`));
    for (const k of ['mo', 'mol']) for (let i = 1; i <= 12; i++) assert.ok(get(de, `notes.${k}.${i}`) && get(en, `notes.${k}.${i}`));
  });
});
