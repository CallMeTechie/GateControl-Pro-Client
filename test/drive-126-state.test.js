'use strict';

// Drive plugin 1.26 "Erinnerungen" on the page "Drive" (no DOM, drive-memories-state.js): the sections in the order of
// the page, the words of a card, when the overview may open the page; that the page loads the scripts, never uses
// innerHTML there, belongs to "Fotos", and that every key exists in de and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const MS = require('../src/renderer/drive-memories-state');
const OS = require('../src/renderer/drive-overview-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);

const LIST = [
  { id: 'place:geonames:1', kind: 'place', count: 12, place: { key: 'geonames:1', name: 'Langenlonsheim' } },
  { id: 'year:2025', kind: 'year', count: 1234, year: 2025 },
  { id: 'month:2024-11', kind: 'month', count: 20, yearsAgo: 2, month: '2024-11' },
  { id: 'person:12', kind: 'person', count: 120, person: { id: 12, name: 'Noah' } },
  { id: 'trip:2025-07-10:2025-07-14', kind: 'trip', count: 87, places: ['Hamburg', 'Lübeck'], place: { name: 'Hamburg' }, days: 5, firstDay: '2025-07-10' },
  { id: 'day:2025-11-08', kind: 'day', count: 14, yearsAgo: 1, date: '2025-11-08' },
  { id: 'day:2023-11-08', kind: 'day', count: 11, yearsAgo: 3, date: '2023-11-08' },
];

describe('Erinnerungen: the words', () => {
  it('sections in the order of the page, empty kinds left out', () => {
    assert.deepEqual(MS.sections(LIST).map((s) => [s.kind, s.items.length]), [['day', 2], ['trip', 1], ['person', 1], ['month', 1], ['year', 1], ['place', 1]]);
    assert.deepEqual(MS.sections([LIST[0]]).map((s) => s.kind), ['place']);
    assert.deepEqual(MS.sections(null), []);
    assert.equal(MS.sectionTitle('trip', t), 'drive.mem.sec.trip');
  });

  it('a card: the title and the line with the count', () => {
    const c = (id) => MS.cardText(LIST.find((x) => x.id === id), { t, locale: 'de' });
    assert.deepEqual(c('day:2025-11-08'), { title: 'drive.ov.mem.today.one(count=1)', sub: '8. November 2025 · drive.photos.count.other(count=14)' });
    assert.deepEqual(c('trip:2025-07-10:2025-07-14'), { title: 'Hamburg, Lübeck', sub: 'drive.mem.days.other(count=5) · Juli 2025 · drive.photos.count.other(count=87)' });
    assert.deepEqual(c('person:12'), { title: 'drive.mem.with(name=Noah)', sub: 'drive.photos.count.other(count=120)' });
    assert.deepEqual(c('month:2024-11'), { title: 'drive.mem.monthAgo.other(count=2)', sub: 'November 2024 · drive.photos.count.other(count=20)' });
    assert.deepEqual(c('year:2025'), { title: 'drive.mem.year(year=2025)', sub: 'drive.photos.count.other(count=1.234)' });
    assert.deepEqual(c('place:geonames:1'), { title: 'Langenlonsheim', sub: 'drive.photos.count.other(count=12)' });
    assert.equal(MS.monthYear('2025-07', 'en'), 'July 2025');
    assert.equal(MS.fullDate('kaputt', 'de'), '');
  });

  it('the overview opens the page only with the feature and the core API', () => {
    const api = { memoryCollections() {} };
    assert.equal(MS.available({ features: ['photos', 'memoryCollections'] }, api), true);
    assert.equal(MS.available({ features: ['photos'] }, api), false);
    assert.equal(MS.available({ features: ['memoryCollections'] }, {}), false);
    assert.equal(MS.available(null, api), false);
  });

  it('the page belongs to "Fotos"', () => {
    assert.equal(OS.pageOf('memories'), 'photos');
  });
});

describe('Erinnerungen: the page', () => {
  it('loads its scripts after the overview, uses no innerHTML, and opens from "Alle" and a card', () => {
    const html = read('src', 'renderer', 'index.html');
    assert.ok(html.indexOf('drive-overview-view.js') < html.indexOf('drive-memories-state.js'));
    assert.ok(html.indexOf('drive-memories-state.js') < html.indexOf('drive-memories-view.js'));
    assert.ok(html.indexOf('drive-memories-view.js') < html.indexOf('drive-view.js"'));
    const view = read('src', 'renderer', 'drive-memories-view.js');
    assert.doesNotMatch(view, /\.(innerHTML|outerHTML)\b|insertAdjacentHTML\(/);
    const ov = read('src', 'renderer', 'drive-overview-view.js');
    assert.match(ov, /o\.openMemories\(null\)/);
    assert.match(ov, /o\.openMemories\(\{ id: m\.id, kind: 'day'/);
    const dv = read('src', 'renderer', 'drive-view.js');
    assert.match(dv, /DS\.hasFeature\(S\.me, 'memoryCollections'\)/);
  });

  it('every key in de and en', () => {
    const de = JSON.parse(read('src', 'i18n', 'de.json')).drive.mem;
    const en = JSON.parse(read('src', 'i18n', 'en.json')).drive.mem;
    const keys = (o, p = '') => Object.entries(o).flatMap(([k, v]) => (v && typeof v === 'object' ? keys(v, `${p}${k}.`) : [`${p}${k}`])).sort();
    assert.deepEqual(keys(de), keys(en));
    for (const k of ['title', 'private', 'none', 'empty', 'more', 'trip', 'with', 'year', 'days.one', 'days.other', 'monthAgo.one', 'monthAgo.other', ...MS.KINDS.map((x) => `sec.${x}`)]) assert.ok(keys(de).includes(k), k);
  });
});
