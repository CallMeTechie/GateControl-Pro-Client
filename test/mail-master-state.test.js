'use strict';

// Mail 1.4.0 (contacts with the GC contact as the master, favourites, the start page): the pure helpers of
// mail-state.js (sources and their dots, the band of a conflict, writeBack, the duplicates view and its protocol, the
// pins of the start page, the tiles of the favourites, the days of the calendar widget) and the wiring (index.html
// loads home-view.js, no HTML strings, every text in de and en).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const MS = require('../src/renderer/mail-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, params) => (params ? `${key}(${Object.entries(params).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const at = (y, mo, d, h = 0, mi = 0) => new Date(y, mo - 1, d, h, mi).getTime();

const me = { accounts: [{ id: 2, name: 'Firma · M365', color: '#79B8FF' }, { id: 1, name: 'GMX', color: '#F5B544' }] };
const books = [
  { id: 1, name: 'Meine Kontakte', accountId: null },
  { id: 2, name: 'Kontakte', accountId: 2 },
  { id: 3, name: 'Adressbuch', accountId: 1 },
];

describe('mail-state – contacts with the GC contact as the master', () => {
  it('the server\'s kind, sources and their dots', () => {
    assert.equal(MS.hasMaster([{ id: 1, favorite: false }]), true);
    assert.equal(MS.hasMaster([{ id: 1, favorite: null }, { id: 2 }]), false, 'a server before 1.4.0');
    assert.equal(MS.sourceLabel({ addressbookId: 2, addressbook: 'Kontakte', account: 'ma.backes@outlook.com' }, books, me), 'Firma · M365 · Kontakte (ma.backes@outlook.com)');
    assert.equal(MS.sourceLabel({ addressbookId: 9, addressbook: 'Outlook', account: null }, books, me), 'Outlook', 'an address book not known: its name');
    assert.equal(MS.sourceLabel(null, books, me), '');
    const dots = MS.sourceColors({ addressbookId: 1, sources: [{ addressbookId: 1 }, { addressbookId: 2 }, { addressbookId: 3 }, { addressbookId: 2 }] }, books, me);
    assert.deepEqual(dots.map((x) => x.color), ['#79B8FF', '#F5B544'], 'one dot per account, the own address book none');
    assert.deepEqual(MS.sourceColors({ addressbookId: 3, sources: null }, books, me).map((x) => x.color), ['#F5B544'], 'without sources: its address book');
  });

  it('the band of a conflict: "Übernehmen", "Zusätzlich" where it fits', () => {
    const src = { addressbookId: 2, addressbook: 'Kontakte', account: 'ma.backes@outlook.com' };
    const a = MS.conflictText({ field: 'phones', type: 'mobile', value: { value: '0171 2345678' }, replaces: { value: '0170 1234567' }, source: src }, books, me, 'de', t);
    assert.equal(a.text, 'mail.con.cf.textWas(source=Firma · M365 · Kontakte (ma.backes@outlook.com),what=mail.con.cf.phone_mobile,value=0171 2345678,before=0170 1234567)');
    assert.equal(a.canAdd, true);
    const b = MS.conflictText({ field: 'company', value: 'Keller AG', replaces: null, source: src }, books, me, 'de', t);
    assert.deepEqual([b.text.startsWith('mail.con.cf.text('), b.canAdd], [true, false]);
    const c = MS.conflictText({ field: 'addresses', type: 'work', value: { street: 'Ring 1', postalCode: '50667', city: 'Köln' }, replaces: null, source: null }, books, me, 'de', t);
    assert.match(c.text, /what=mail\.con\.cf\.address_work,value=Ring 1, 50667 Köln/);
    assert.match(c.text, /source=mail\.con\.cf\.other/);
    assert.equal(c.canAdd, false, 'nothing replaced: "Übernehmen" adds');
    assert.equal(MS.conflictText({ field: 'phones', type: 'pager', value: { value: '1' }, source: src }, books, me, 'de', t).text.includes('phone_other'), true);
    assert.equal(MS.conflictValueText('birthday', '1981-03-14', 'de'), '14. März 1981');
    assert.equal(MS.conflictValueText('birthday', '--03-14', 'en'), '14 March');
    assert.equal(MS.conflictValueText('title', null, 'de'), '');
  });

  it('writeBack: the accounts a change went to, and the ones it did not reach', () => {
    const wb = [{ id: 7, addressbookId: 2, ok: true }, { id: 8, addressbookId: 3, ok: false, code: 'read_only' }, { id: 9, addressbookId: 3, ok: false }];
    assert.deepEqual(MS.writeBackDone(wb, books, me), ['Firma · M365 · Kontakte']);
    assert.deepEqual(MS.writeBackFailed(wb, books, me), ['GMX · Adressbuch']);
    assert.deepEqual([MS.writeBackDone(undefined, books, me), MS.writeBackFailed([], books, me)], [[], []]);
  });

  it('the duplicates: the uncertain cases, the fields of a card, the protocol', () => {
    const items = [{ key: '1-2', certain: false }, { key: '3-4', certain: true }];
    assert.deepEqual(MS.dupCases(items), { fresh: true, open: [items[0]] });
    const old = [{ key: '1-2', certain: null }];
    assert.deepEqual(MS.dupCases(old), { fresh: false, open: old }, 'a server before 1.4.0: the list as it is');
    assert.deepEqual(MS.dupFields({ phones: [{ value: '0172 3' }], emails: [{ value: 's@x.de' }], addresses: [{ street: 'Ring 3', postalCode: '50667', city: 'Köln' }] }),
      { phones: ['0172 3'], emails: ['s@x.de'], address: 'Ring 3, 50667 Köln' });
    assert.deepEqual(MS.dupFields(null), { phones: [], emails: [], address: '' });
    assert.equal(MS.cardName({ name: { display: 'Schatzimausi 💞', given: 'Sabrina' } }), 'Schatzimausi 💞');
    assert.equal(MS.cardName({ name: { given: 'Tim', family: 'Brandt' } }), 'Tim Brandt');
    const merges = [{ id: 1, mode: 'auto' }, { id: 2, mode: 'manual' }, { id: 3, mode: 'migrated' }, { id: 4, mode: 'auto', undoneAt: 5 }];
    assert.deepEqual(MS.autoMerges(merges).map((m) => m.id), [1, 3]);
    assert.equal(MS.mergeLine({ cards: [{ name: 'Sabine Keller', addressbook: 'Meine Kontakte' }, { name: 'Sabine Keller', addressbook: 'Firma · M365' }] }), 'Sabine Keller · Meine Kontakte + Firma · M365');
  });
});

describe('mail-state – the start page', () => {
  it('the pins of this PC: the calendar, at most 12 favourites', () => {
    assert.deepEqual(MS.homePins(null), { calendar: false, contacts: [] });
    assert.deepEqual(MS.homePins({ calendar: 'yes', contacts: [3, 3, -1, 'x', 4.5, 7] }), { calendar: false, contacts: [3, 7] });
    let p = MS.homePins({ calendar: true });
    for (let i = 1; i <= 14; i += 1) p = MS.pinContact(p, i, true);
    assert.deepEqual([p.calendar, p.contacts.length, p.contacts[0]], [true, 12, 1]);
    p = MS.pinContact(p, 1, false);
    assert.equal(p.contacts.includes(1), false);
    assert.deepEqual(MS.pinContact({ contacts: [5] }, 5, true).contacts, [5], 'no doubles');
  });

  it('the tiles: the favourites pinned in the favourites\' order, initials, the main number', () => {
    const favs = [
      { id: 402, name: 'Tim Brandt', phone: { value: '0170 1112223', type: 'mobile' }, photo: false },
      { id: 403, name: 'Anna Lang', phone: null, email: 'anna@x.de', photo: true, photoEtag: 'p1' },
      { id: 405, name: 'Schatzimausi 💞', phone: { value: '+49 172 3334444' } },
    ];
    const tiles = MS.favoriteTiles(favs, { contacts: [405, 402, 999] });
    assert.deepEqual(tiles.map((x) => [x.id, x.initials, x.phone]), [[402, 'TB', '0170 1112223'], [405, 'S', '+49 172 3334444']]);
    assert.deepEqual(MS.favoriteTiles(favs, { contacts: [403] })[0], { id: 403, name: 'Anna Lang', initials: 'AL', phone: null, email: 'anna@x.de', photo: true, photoEtag: 'p1' });
    assert.deepEqual(MS.favoriteTiles(null, { contacts: [1] }), []);
  });

  it('the calendar widget: today and tomorrow, all-day ones as such, a running one "jetzt"', () => {
    const now = at(2026, 10, 31, 10, 30);
    const res = { today: '2026-10-31', items: [
      { key: '301', eventId: 301, title: 'Projekt', start: at(2026, 10, 31, 10), end: at(2026, 10, 31, 11), allDay: false, day: '2026-10-31' },
      { key: '304:1', eventId: 304, title: 'Training', start: at(2026, 10, 31, 18), end: at(2026, 10, 31, 19), allDay: false, day: '2026-10-31' },
      { key: 'bday', overlayId: 'birthdays', title: 'Anna Lang (40)', start: at(2026, 11, 1), end: at(2026, 11, 2), allDay: true, startDate: '2026-11-01', day: '2026-11-01' },
      { key: '302', eventId: 302, title: 'Zahnarzt', start: at(2026, 11, 1, 14), end: at(2026, 11, 1, 14, 45), allDay: false, day: '2026-11-01' },
      { key: '305', eventId: 305, title: 'Messe', start: at(2026, 11, 3), end: at(2026, 11, 5), allDay: true, day: '2026-11-03' },
    ] };
    const days = MS.upcomingDays(res, now, 'de', t);
    assert.deepEqual(days.map((d) => [d.label, d.items.map((x) => [x.title, x.time])]), [
      ['home.cal.today', [['Projekt', 'home.cal.now'], ['Training', '18:00']]],
      ['home.cal.tomorrow', [['Anna Lang (40)', 'mail.cal.allDay'], ['Zahnarzt', '14:00']]],
      ['Dienstag, 3. Nov.', [['Messe', 'mail.cal.allDay']]],
    ]);
    assert.deepEqual(MS.upcomingDays({ items: [] }, now, 'de', t), []);
    assert.deepEqual(MS.upcomingDays(null, now, 'de', t), []);
  });
});

describe('start page wiring', () => {
  it('index.html loads home-view.js after the areas and before renderer.js; no HTML strings', () => {
    const html = read('src', 'renderer', 'index.html');
    const h = html.indexOf('src="home-view.js"');
    assert.ok(h > html.indexOf('src="contacts-view.js"') && h < html.indexOf('src="renderer.js"'));
    assert.match(html, /id="home-pins"[^>]*hidden/);
    const src = read('src', 'renderer', 'home-view.js');
    assert.doesNotMatch(src, /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/);
    assert.match(read('src', 'renderer', 'renderer.js'), /GCHomeView\.mount\(/);
  });

  it('every text of the master contacts and the start page exists in de and en', () => {
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const src = ['home-view.js', 'contacts-view.js', 'calendar-view.js', 'mail-state.js'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set();
    for (const m of src.matchAll(/['"`]((?:home|mail\.con)\.[A-Za-z0-9_.-]*)['"`]/g)) if (!m[1].endsWith('.')) keys.add(m[1]);
    for (const f of ['phone_mobile', 'phone_home', 'phone_work', 'phone_fax', 'phone_other', 'address_home', 'address_work', 'address_other', 'company', 'department', 'title', 'birthday']) keys.add(`mail.con.cf.${f}`);
    for (const m of ['auto', 'migrated', 'manual']) keys.add(`mail.con.mode.${m}`);
    assert.ok(keys.size > 60, `only ${keys.size} keys found`);
    for (const k of keys) {
      assert.ok(k in de, `de: ${k}`);
      assert.ok(k in en, `en: ${k}`);
    }
    // the same placeholders in both languages
    for (const k of Object.keys(de).filter((x) => x.startsWith('home.') || x.startsWith('mail.con.cf.'))) {
      const ph = (v) => [...String(v).matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).sort().join(',');
      assert.equal(ph(de[k]), ph(en[k]), k);
    }
  });
});
