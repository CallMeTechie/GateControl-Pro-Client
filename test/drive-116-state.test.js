'use strict';

// Drive 1.16 "Orte und Personen" on the page "Drive" (no DOM, drive-places-people-state.js): the switch of "Fotos",
// the map (Web Mercator, the box of a view, a view that fits the places), "Orte im Bild", a place by day, the people
// (named / "Wer ist das?" / hidden, progress, faces cut out of a photo), a person, the names offered when naming, the
// suggestions while typing and the settings rows; that the page loads the new scripts, never uses innerHTML there,
// and that every key they use exists in de and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const PPS = require('../src/renderer/drive-places-people-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const at = (y, mo, d, h = 12) => new Date(y, mo - 1, d, h).getTime();
const ME = (f) => ({ features: f });

describe('the switch and the features', () => {
  it('Zeitachse | Karte | Personen (| Alben) only with what the Drive reports', () => {
    assert.deepEqual(PPS.features(ME(['photos', 'photoPlaces'])), { places: true, people: false });
    assert.deepEqual(PPS.segments(ME(['photos', 'albums', 'photoPlaces', 'photoPeople']), t).map((s) => s.key), ['timeline', 'map', 'people', 'albums']);
    assert.deepEqual(PPS.segments(ME(['photos', 'photoPeople']), t).map((s) => s.key), ['timeline', 'people']);
    assert.deepEqual(PPS.segments(ME(['photos']), t).map((s) => [s.key, s.label]), [['timeline', 'drive.pp.seg.timeline']]);
    assert.deepEqual(PPS.features(null), { places: false, people: false });
  });
});

describe('the map', () => {
  it('world pixels and back, tiles of a view, the box of a view, across the date line', () => {
    const p = PPS.worldPx(53.5511, 9.9937, 10);
    const back = PPS.lonLat(p.x, p.y, 10);
    assert.ok(Math.abs(back.lat - 53.5511) < 1e-6 && Math.abs(back.lon - 9.9937) < 1e-6);
    assert.deepEqual(PPS.worldPx(0, 0, 0), { x: 128, y: 128 });
    const tiles = PPS.tileGrid(128, 128, 0, 512, 300);
    assert.deepEqual([...new Set(tiles.map((x) => `${x.x}/${x.y}`))], ['0/0']);
    assert.equal(tiles.length, 3);
    const box = PPS.viewBbox(p.x, p.y, 10, 600, 400);
    assert.ok(box[0] < 9.9937 && box[2] > 9.9937 && box[1] < 53.5511 && box[3] > 53.5511, String(box));
    assert.deepEqual(PPS.viewBbox(128, 128, 0, 1200, 300).filter((_, i) => i % 2 === 0), [-180, 180]);
    assert.equal(PPS.clampZoom(25), 18);
    assert.equal(PPS.clampZoom(-1), 2);
    // a point just across the date line shows next to the centre, not a world away
    const c = PPS.worldPx(0, 179.9, 4);
    assert.ok(PPS.screenPos(0, -179.9, c.x, c.y, 4, 400, 300).x - 200 < 10);
  });

  it('a view that fits the places; Germany without places', () => {
    const v = PPS.fitView([{ lat: 53.55, lon: 9.99 }, { lat: 50.94, lon: 6.96 }], 660, 680);
    assert.ok(v.zoom >= 5 && v.zoom <= 8, String(v.zoom));
    assert.ok(Math.abs(v.lat - 52.245) < 0.01);
    assert.deepEqual(PPS.fitView([], 600, 400), { lat: 51.1657, lon: 10.4515, zoom: 5 });
    assert.equal(PPS.fitView([{ lat: 53.55, lon: 9.99 }], 600, 400, { maxZoom: 12 }).zoom, 12);
  });

  it('"Orte im Bild": clusters of one place together, the place\'s name and time span, most first', () => {
    const places = [
      { key: 'g:1', name: 'Hamburg', region: 'Hamburg', country: 'DE', from: at(2025, 7, 1), to: at(2026, 3, 14), cover: { id: 1 } },
      { key: 'g:2', name: 'Mallorca', region: 'Balearen', country: 'ES', from: at(2023, 8, 2), to: at(2023, 8, 20) },
      { key: 'g:3', name: 'Köln', region: 'NRW', country: 'DE', from: null, to: null },
    ];
    const rows = PPS.placeRows([{ key: 'g:2', count: 96 }, { key: 'g:1', count: 200 }, { key: 'g:1', count: 14, cover: { id: 9 } }, { key: null, count: 50 }, { key: 'g:3', count: 3 }, { key: 'g:9', count: 1 }], places, { locale: 'de' });
    assert.deepEqual(rows.map((r) => [r.name, r.count]), [['Hamburg', 214], ['Mallorca', 96], ['Köln', 3]]);
    assert.equal(rows[0].sub, '2025 – 2026');
    assert.equal(rows[0].cover.id, 9);
    assert.equal(rows[1].sub, 'August 2023');
    assert.equal(rows[2].sub, 'NRW · Deutschland');
    assert.equal(PPS.spanText(at(2026, 3, 1), at(2026, 7, 1), 'de'), 'März – Juli 2026');
    assert.equal(PPS.spanText(at(2026, 3, 1), at(2026, 7, 1), 'en'), 'March – July 2026');
    assert.equal(PPS.countryName('ES', 'en'), 'Spain');
    assert.equal(PPS.countryName('x', 'de'), '');
    assert.equal(PPS.placeWhere({ name: 'Hamburg', region: 'Hamburg', country: 'DE' }, 'de'), 'Deutschland');
  });

  it('a place: by day with the district of most photos, the line under its name, the people on its photos', () => {
    const geo = (district) => ({ lat: 1, lon: 1, place: { key: 'g:1', name: 'Hamburg', district } });
    const items = [
      { id: 1, takenAt: at(2026, 3, 14, 10), geo: geo('Landungsbrücken'), people: [3, 4] },
      { id: 2, takenAt: at(2026, 3, 14, 11), geo: geo('Landungsbrücken'), people: [3] },
      { id: 3, takenAt: at(2026, 3, 14, 12), geo: geo('Altona'), people: [5] },
      { id: 4, takenAt: at(2025, 7, 20), geo: geo(null), people: null },
      { id: 5, takenAt: null },
    ];
    const days = PPS.byDay(items, { locale: 'de', t });
    assert.deepEqual(days.map((d) => d.key), ['2026-03-14', '2025-07-20', 'none']);
    assert.match(days[0].label, /^Sa\.?, 14\. März 2026$/);
    assert.equal(days[0].sub, 'Landungsbrücken · 3');
    assert.equal(days[1].sub, '1');
    assert.equal(days[2].label, 'drive.photos.noDate');
    assert.equal(PPS.placeSub({ count: 1204, items, districts: [{ name: 'St. Pauli' }, { name: 'Altona' }, { name: 'HafenCity' }, { name: 'Ottensen' }] }, { t, locale: 'de' }),
      'drive.pp.photos.other(count=1.204) · drive.pp.days.other(count=2) · St. Pauli, Altona, HafenCity');
    const people = [{ id: 3, name: 'Mama' }, { id: 4, name: 'Lea' }, { id: 5, name: null }, { id: 6, name: 'Papa', hidden: true }];
    assert.deepEqual(PPS.peopleOn(items, people), [{ id: 3, name: 'Mama', count: 2 }, { id: 4, name: 'Lea', count: 1 }]);
  });
});

describe('people', () => {
  const list = [
    { id: 1, name: 'Lea', count: 812, hidden: false },
    { id: 2, name: null, count: 64, hidden: false },
    { id: 3, name: 'Mama', count: 530, hidden: false },
    { id: 4, name: null, count: 41, hidden: true },
    { id: 5, name: null, count: 18, hidden: false },
  ];

  it('named / "Wer ist das?" / hidden, the head line, the progress', () => {
    const g = PPS.groupPeople(list);
    assert.deepEqual(g.named.map((p) => p.id), [1, 3]);
    assert.deepEqual(g.unnamed.map((p) => p.id), [2, 5]);
    assert.deepEqual(g.hidden.map((p) => p.id), [4]);
    assert.equal(PPS.peopleSub(g, t, 'de'), 'drive.pp.people.named.other(count=2) · drive.pp.people.unnamedN.other(count=2)');
    assert.deepEqual(PPS.progressOf({ done: 4120, total: 6212 }, { t, locale: 'de' }), { text: 'drive.pp.progress.count(done=4.120,total=6.212)', pct: 66, done: false });
    assert.equal(PPS.progressOf({ done: 10, total: 10 }, { t }).done, true);
    assert.equal(PPS.progressOf({ done: 0, total: 0 }, { t }), null);
    assert.equal(PPS.progressOf(null, { t }), null);
    assert.equal(PPS.initials('Oma Gerda'), 'OG');
    assert.equal(PPS.initials('lea'), 'L');
    assert.equal(PPS.initials(''), '?');
    assert.equal(PPS.toneOf(7), PPS.toneOf('7'));
    assert.ok(PPS.toneOf('Lea') >= 0 && PPS.toneOf('Lea') < 5);
  });

  it('a face cut out of a photo: the face in the middle, the frame always covered', () => {
    // a face in the middle of a 1000 × 800 picture into 100 px
    const c = PPS.faceCrop([0.4, 0.4, 0.2, 0.2], 1000, 800, 100);
    const side = 200 * 1.7;
    const k = 100 / side;
    assert.deepEqual(c, { width: Math.round(1000 * k), height: Math.round(800 * k), left: Math.round(-(500 - side / 2) * k), top: Math.round(-(400 - side / 2) * k) });
    // a face at the very edge: the picture still covers the frame
    const e = PPS.faceCrop([0, 0, 0.1, 0.1], 1000, 1000, 100);
    assert.equal(e.left, 0);
    assert.equal(e.top, 0);
    const big = PPS.faceCrop([0, 0, 1, 1], 400, 300, 100);
    assert.ok(big.width >= 100 && big.height >= 100 && big.left <= 0 && big.top <= 0 && big.left + big.width >= 100 && big.top + big.height >= 100, JSON.stringify(big));
    assert.equal(PPS.faceCrop(null, 1, 1, 1), null);
    assert.equal(PPS.faceCrop([0, 0, 1, 1], 0, 10, 10), null);
  });

  it('a person: photos and years, the link, by year, "Ist das auch …?", the line of the naming dialog', () => {
    const d = { person: { id: 1, name: 'Lea', count: 812 }, years: { from: 2016, to: 2026 }, together: [{ id: 3, name: 'Mama', count: 230 }] };
    assert.equal(PPS.personSub(d, { t, locale: 'de' }), 'drive.pp.photos.other(count=812) · 2016 – 2026');
    assert.equal(PPS.yearsText({ from: 2026, to: 2026 }), '2026');
    assert.equal(PPS.yearsText(null), '');
    assert.equal(PPS.contactText({ kind: 'family', id: 7, name: 'Lea' }, t), 'drive.pp.person.linkedFamily(name=Lea)');
    assert.equal(PPS.contactText({ kind: 'contact', id: 9, name: 'Klaus' }, t), 'drive.pp.person.linkedContact(name=Klaus)');
    assert.equal(PPS.contactText(null, t), '');
    const ys = PPS.byYear([{ id: 1, takenAt: at(2025, 1, 1) }, { id: 2, takenAt: at(2026, 5, 1) }, { id: 3, takenAt: null }, { id: 4, takenAt: at(2026, 1, 1) }], t);
    assert.deepEqual(ys.map((g) => [g.key, g.items.length]), [['2026', 2], ['2025', 1], ['none', 1]]);
    assert.deepEqual(PPS.uncertainPreview([1, 2, 3, 4, 5, 6, 7], 4), { shown: [1, 2, 3, 4], more: 3 });
    assert.equal(PPS.nameSub({ person: { count: 64 }, years: { from: 2019, to: 2026 }, together: [{ id: 3, name: 'Mama' }] }, { t, locale: 'de' }), 'drive.pp.photos.other(count=64) · 2019 – 2026 · drive.pp.name.oftenWith(name=Mama)');
  });

  it('names to offer: people Drive knows, the family, contacts — what was typed, no name twice, not itself', () => {
    const people = [{ id: 1, name: 'Oma Gerda', count: 96, contact: { kind: 'family', id: 8, name: 'Gerda' } }, { id: 2, name: 'Tim', count: 120 }, { id: 3, name: 'Hidden', hidden: true, count: 1 }];
    const family = [{ id: 8, name: 'Opa Heinz' }, { id: 9, name: 'Tim' }];
    const contacts = [{ name: 'Klaus Kramer', email: 'k@x.de', contactId: 12 }, { name: 'Lea Lorenz', email: 'l@x.de' }];
    const all = PPS.nameChoices({ q: '', people, family, contacts, self: 2, max: 10 }, t);
    assert.deepEqual(all.map((x) => x.name), ['Oma Gerda', 'Opa Heinz', 'Tim', 'Klaus Kramer', 'Lea Lorenz']);
    assert.equal(all[0].sub, 'drive.pp.name.familyNamed(count=96)');
    assert.equal(all[0].personId, 1);
    assert.deepEqual(all[1].contact, { kind: 'family', id: 8, name: 'Opa Heinz' });
    assert.deepEqual(all[3].contact, { kind: 'contact', id: 12, name: 'Klaus Kramer' });
    assert.deepEqual(all[4].contact, { kind: 'contact', id: 'l@x.de', name: 'Lea Lorenz' });
    assert.deepEqual(PPS.nameChoices({ q: 'kr', people, family, contacts }, t).map((x) => x.name), ['Klaus Kramer']);
    assert.deepEqual(PPS.nameChoices({ q: 'o', people, family, contacts }, t).map((x) => x.name), ['Oma Gerda', 'Opa Heinz']);
    assert.equal(PPS.nameChoices({ q: '', people, family, contacts }, t).length, 3);
    assert.equal(PPS.nameError('  ', t), 'drive.pp.name.empty');
    assert.equal(PPS.nameError('x'.repeat(201), t), 'drive.pp.name.long');
    assert.equal(PPS.nameError('Lea', t), null);
  });
});

describe('search and settings', () => {
  it('suggestions while typing: people, places, what is on the photos; a label replaces the last word', () => {
    const rows = PPS.suggestionRows({ people: [{ id: 3, name: 'Mama', count: 530 }], places: [{ key: 'g:1', name: 'Hamburg', sub: 'St. Pauli, Altona', count: 214 }, { key: 'g:2', name: 'Hameln', sub: null, count: 2 }], labels: [{ label: 'hafen', text: 'Hafen', count: 1204 }] }, { t, locale: 'de' });
    assert.deepEqual(rows.map((r) => [r.kind, r.name, r.sub, r.count]), [
      ['person', 'Mama', 'drive.pp.sug.person', '530'],
      ['place', 'Hamburg', 'drive.pp.sug.placeIn(sub=St. Pauli, Altona)', '214'],
      ['place', 'Hameln', 'drive.pp.sug.place', '2'],
      ['label', 'Hafen', 'drive.pp.sug.label', '1.204'],
    ]);
    assert.deepEqual(PPS.suggestionRows(null, { t }), []);
    assert.equal(PPS.withLabel('mama ha', 'hafen'), 'mama hafen');
    assert.equal(PPS.withLabel('', 'hafen'), 'hafen');
  });

  it('the settings rows: stripGeoOnShare only when reported, the people\'s rows only while on', () => {
    const me = ME(['photoPlaces', 'photoPeople']);
    assert.deepEqual(PPS.settingsRows({ keepGeo: true, stripGeoOnShare: null, people: false }, me), { places: [{ key: 'keepGeo', on: true }], people: { on: false, rows: [] } });
    assert.deepEqual(PPS.settingsRows({ keepGeo: false, stripGeoOnShare: true, people: true, peopleKids: false }, me), { places: [{ key: 'keepGeo', on: false }, { key: 'stripGeoOnShare', on: true }], people: { on: true, rows: [{ key: 'peopleKids', on: false }] } });
    assert.deepEqual(PPS.settingsRows({}, ME(['photoPeople'])), { places: null, people: { on: false, rows: [] } });
  });
});

describe('the page', () => {
  it('loads the new scripts before the photos, no innerHTML, every key in de and en', () => {
    const html = read('src', 'renderer', 'index.html');
    const pos = (f) => html.indexOf(`<script src="${f}"></script>`);
    assert.ok(pos('drive-places-people-state.js') > pos('drive-photos-state.js'));
    assert.ok(pos('drive-places-people-view.js') > pos('drive-places-people-state.js'));
    assert.ok(pos('drive-photos-view.js') > pos('drive-places-people-view.js'));
    for (const f of ['drive-places-people-state.js', 'drive-places-people-view.js']) {
      assert.doesNotMatch(read('src', 'renderer', f), /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/, f);
    }
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const src = ['drive-places-people-view.js', 'drive-places-people-state.js', 'drive-photos-view.js', 'drive-settings-view.js'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set();
    for (const m of src.matchAll(/['"`](drive\.pp\.[A-Za-z0-9_.]+)['"`]/g)) if (!m[1].endsWith('.')) keys.add(m[1]);
    for (const k of ['keepGeo', 'stripGeoOnShare', 'peopleKids']) { keys.add(`drive.pp.set.${k}`); keys.add(`drive.pp.set.${k}Desc`); }
    for (const k of ['how1', 'how2', 'how3', 'how4']) keys.add(`drive.pp.set.${k}`);
    const plurals = ['drive.pp.photos', 'drive.pp.days', 'drive.pp.people.named', 'drive.pp.people.unnamedN', 'drive.pp.person.askText', 'drive.pp.person.confirmed', 'drive.pp.name.hiddenText', 'drive.pp.set.geoDeleted'];
    for (const p of plurals) { keys.delete(p); keys.add(`${p}.one`); keys.add(`${p}.other`); }
    assert.ok(keys.size > 120, `only ${keys.size} keys`);
    for (const k of keys) {
      assert.ok(typeof de[k] === 'string' && de[k], `de: ${k}`);
      assert.ok(typeof en[k] === 'string' && en[k], `en: ${k}`);
    }
    // the attribution of the map, as OpenStreetMap asks
    assert.equal(de['drive.pp.map.attribution'], '© OpenStreetMap-Mitwirkende');
    assert.equal(en['drive.pp.map.attribution'], '© OpenStreetMap contributors');
  });
});
