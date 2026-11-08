'use strict';

// Drive plugin 1.28 'memoryPicks' on the page "Drive" (no DOM): on a day without „Heute vor X Jahren“ the tile
// "Erinnerungen" shows the picks of the page "Erinnerungen" — titled as that page names them, with the photo count;
// a card opens its collection there, "Alle" the page. The core decides when the tile shows (utils/drive-overview.js).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const MS = require('../src/renderer/drive-memories-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);

/** The picks of the README's example (as the core cleans them) and a place. */
const PICKS = [
  { id: 'trip:2025-07-10:2025-07-14', kind: 'trip', count: 16, place: { key: 'geonames:2911298', name: 'Hamburg' }, places: ['Hamburg'], days: 5, firstDay: '2025-07-10', lastDay: '2025-07-14', cover: { id: 812 } },
  { id: 'person:7', kind: 'person', count: 11, person: { id: 7, name: 'Noah' }, cover: { id: 640 } },
  { id: 'month:2025-10', kind: 'month', count: 20, yearsAgo: 1, month: '2025-10', cover: { id: 901 } },
  { id: 'year:2024', kind: 'year', count: 71, year: 2024, cover: null },
  { id: 'place:geonames:1', kind: 'place', count: 1234, place: { key: 'geonames:1', name: 'Langenlonsheim' }, cover: null },
];

describe('Erinnerungen without „Heute vor X Jahren“: the picks', () => {
  it('a pick: the title of the page "Erinnerungen", the photo count below', () => {
    const tx = PICKS.map((c) => MS.pickText(c, { t, locale: 'de' }));
    assert.deepEqual(tx.map((x) => x.title), ['Hamburg', 'drive.mem.with(name=Noah)', 'drive.mem.monthAgo.one(count=1)', 'drive.mem.year(year=2024)', 'Langenlonsheim']);
    assert.deepEqual(tx.map((x) => x.sub), ['drive.photos.count.other(count=16)', 'drive.photos.count.other(count=11)', 'drive.photos.count.other(count=20)', 'drive.photos.count.other(count=71)', 'drive.photos.count.other(count=1.234)']);
    // the same title as the page's card
    for (const c of PICKS) assert.equal(MS.pickText(c, { t }).title, MS.cardText(c, { t }).title);
    // a place without a name: the tile's title, not nothing
    assert.equal(MS.pickText({ id: 'place:geonames:2', kind: 'place', count: 3, place: null }, { t }).title, 'drive.ov.mem.title');
    assert.equal(MS.pickText({ id: 'person:9', kind: 'person', count: 1, person: { id: 9, name: 'Lea' } }, { t, locale: 'en' }).sub, 'drive.photos.count.one(count=1)');
  });

  it('the tile: the days, else the core\'s picks; a card opens its collection, without the page "Fotos"', () => {
    const ov = read('src', 'renderer', 'drive-overview-view.js');
    assert.match(ov, /if \(d\.memories\.length\)/);
    assert.match(ov, /v\.memoryPicks \|\| \[\]/);
    assert.match(ov, /MS\.pickText\(c, \{ t, locale: locale\(\) \}\)/);
    assert.match(ov, /function openPick\(c\) \{\s*if \(!\(typeof o\.openMemories === 'function' && o\.openMemories\(c\)\)\) o\.openPhotos\(\{\}\);/);
    assert.doesNotMatch(ov, /\.(innerHTML|outerHTML)\b|insertAdjacentHTML\(/);
  });

  it('the words exist in de and en', () => {
    for (const lang of ['de', 'en']) {
      const d = JSON.parse(read('src', 'i18n', `${lang}.json`)).drive;
      assert.ok(d.ov.mem.title, `${lang}: drive.ov.mem.title`);
      assert.ok(d.photos.count.one && d.photos.count.other, `${lang}: drive.photos.count`);
    }
  });
});
