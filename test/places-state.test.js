'use strict';

// View logic of „Meine Orte“ (src/renderer/places-state.js, no DOM): the page's lists and lines, the editor's draft and
// what a change sends (only what differs, lat and lon together, an emptied address null), the radius in steps of 50,
// refusals in words; the one place choice of the forms ported from the Android app (PlacePicking.kt): chips, the
// groups „Zuletzt genutzt“ / „In der Nähe“ / A–Z — near the chosen place or „Zuhause“, this PC has no position —, the
// local search, address hits that are no place yet, the place of a Messenger event. And the wiring: the page loads its
// scripts, the view never uses innerHTML, every places.* key it uses exists in both languages.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const PS = require('../src/renderer/places-state');

const ROOT = path.join(__dirname, '..');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);

// the places of the mockup (made-up addresses), as core utils/places.js normalizes them
const place = (o) => ({ own: true, hasPoint: o.lat != null, icon: 'pin', radiusM: 150, visibility: 'self', address: null, usedBy: [], lastUsedAt: null, source: 'manual', ...o, ref: `profile:${o.id}` });
const ZUHAUSE = place({ id: 11, name: 'Zuhause', icon: 'home', lat: 50.05, lon: 8.6, address: 'Lindenweg 12, Musterstadt', visibility: 'family',
  usedBy: [{ plugin: 'gatecontrol-messenger', pluginName: 'Messenger', kind: 'location_message', count: 1 }, { plugin: 'gatecontrol-notizen', pluginName: 'Notizen', kind: 'task', count: 2 }] });
const ARBEIT = place({ id: 12, name: 'Arbeit', icon: 'work', lat: 50.110922, lon: 8.682127, radiusM: 200, address: 'Hafenstraße 4, Musterstadt' });
const STUDIO = place({ id: 13, name: 'Fitnessstudio', icon: 'gym', lat: 50.07, lon: 8.63, radiusM: 100, address: 'Am Markt 7, Musterstadt' });
const LEER = place({ id: 15, name: 'Ärztehaus', lat: null, lon: null, hasPoint: false });

describe('places-state: the page', () => {
  it('lists: own places by name (umlauts as letters), Familie places of the choice only, the count without a point', () => {
    const l = PS.pageLists({ places: [ZUHAUSE, ARBEIT, LEER, STUDIO] }, { places: [{ ref: 'place:3', source: 'familie', name: 'Grundschule', lat: 50.06, lon: 8.61 }, { ref: 'profile:11', source: 'profile', name: 'Zuhause' }] });
    assert.deepEqual(l.mine.map((p) => p.name), ['Arbeit', 'Ärztehaus', 'Fitnessstudio', 'Zuhause']);
    assert.deepEqual(l.familie.map((p) => p.name), ['Grundschule']);
    assert.equal(l.missing, 1);
    assert.deepEqual(PS.pageLists(null, null), { mine: [], familie: [], missing: 0 });
  });

  it('the grey line: address · radius · who sees it; „kein Standort“ without a point', () => {
    assert.equal(PS.placeLine(ZUHAUSE, t), 'Lindenweg 12, Musterstadt · places.radiusShort(m=150) · places.visShort.family');
    assert.equal(PS.placeLine(LEER, t), 'places.noPoint');
  });

  it('„Genutzt von“ in words, plurals by the count, unknown kinds as a number', () => {
    assert.deepEqual(PS.usedByLines(ZUHAUSE.usedBy, t), [
      { plugin: 'gatecontrol-messenger', text: 'places.useLine(plugin=Messenger,what=places.use.location_message_one(n=1))' },
      { plugin: 'gatecontrol-notizen', text: 'places.useLine(plugin=Notizen,what=places.use.task_other(n=2))' },
    ]);
    assert.deepEqual(PS.usedByLines([{ plugin: 'x-y', pluginName: null, kind: 'geofence', count: 3 }], t), [{ plugin: 'x-y', text: 'places.useLine(plugin=x-y,what=places.use.other(n=3))' }]);
    assert.equal(PS.pluginsUsing(ZUHAUSE), 2);
    assert.equal(PS.pluginsUsing(ARBEIT), 0);
  });

  it('the radius snaps to the slider: 50 … 2000 in steps of 50', () => {
    assert.equal(PS.snapRadius(120), 100);
    assert.equal(PS.snapRadius(130), 150);
    assert.equal(PS.snapRadius(10), 50);
    assert.equal(PS.snapRadius(5000), 2000);
    assert.equal(PS.snapRadius('x'), 150);
    assert.equal(PS.snapRadius(null, { radius: { min: 50, max: 2000, default: 200 } }), 200);
  });

  it('the draft and what keeps it from being saved', () => {
    assert.deepEqual(PS.draftOf(null), { name: '', icon: 'pin', lat: null, lon: null, radiusM: 150, address: '', visibility: 'self' });
    assert.deepEqual(PS.draftOf(ARBEIT), { name: 'Arbeit', icon: 'work', lat: 50.110922, lon: 8.682127, radiusM: 200, address: 'Hafenstraße 4, Musterstadt', visibility: 'self' });
    assert.equal(PS.draftProblem({ ...PS.draftOf(null), name: '  ' }), 'name');
    assert.equal(PS.draftProblem({ ...PS.draftOf(null), name: 'Bäckerei' }), 'point');
    assert.equal(PS.draftProblem({ ...PS.draftOf(null), name: 'Bäckerei', lat: 0, lon: 0 }), 'point');
    assert.equal(PS.draftProblem({ ...PS.draftOf(null), name: 'Bäckerei', lat: 50.1, lon: 0 }), null);
  });

  it('a new place: only the known keys, no empty address, 6 decimals', () => {
    assert.deepEqual(PS.createBody({ name: ' Bäckerei  am  Eck ', icon: 'shop', lat: 50.1234567, lon: 8.7654321, radiusM: 120, address: ' ', visibility: 'all' }),
      { name: 'Bäckerei am Eck', lat: 50.123457, lon: 8.765432, icon: 'shop', radiusM: 100, visibility: 'all' });
  });

  it('a change sends only what differs: lat and lon together, an emptied address null, nothing for no change', () => {
    assert.deepEqual(PS.diffBody(ARBEIT, PS.draftOf(ARBEIT)), {});
    assert.deepEqual(PS.diffBody(ARBEIT, { ...PS.draftOf(ARBEIT), name: 'Büro', radiusM: 250 }), { name: 'Büro', radiusM: 250 });
    assert.deepEqual(PS.diffBody(ARBEIT, { ...PS.draftOf(ARBEIT), lon: 8.69 }), { lat: 50.110922, lon: 8.69 });
    assert.deepEqual(PS.diffBody(ARBEIT, { ...PS.draftOf(ARBEIT), address: '' }), { address: null });
    assert.deepEqual(PS.diffBody(ARBEIT, { ...PS.draftOf(ARBEIT), icon: 'school', visibility: 'all' }), { icon: 'school', visibility: 'all' });
    // a place without a point gets one
    assert.deepEqual(PS.diffBody(LEER, { ...PS.draftOf(LEER), lat: 50.2, lon: 8.5 }), { lat: 50.2, lon: 8.5 });
  });

  it('„Familie“ is offered only in a family (or when the place has it already)', () => {
    assert.deepEqual(PS.visibilityChoices(false, 'self'), ['self', 'all']);
    assert.deepEqual(PS.visibilityChoices(true, 'self'), ['self', 'family', 'all']);
    assert.deepEqual(PS.visibilityChoices(false, 'family'), ['self', 'family', 'all']);
  });

  it('refusals in words', () => {
    assert.equal(PS.errorText({ code: 'duplicate', field: 'name' }, t), 'places.err.duplicate');
    assert.equal(PS.errorText({ code: 'limit' }, t, { places: 100 }), 'places.err.limit(n=100)');
    assert.equal(PS.errorText({ code: 'whatever' }, t), 'places.err.other');
    assert.equal(PS.searchErrorText({ code: 'rate_limited', retryAfter: 90 }, t), 'places.searchBusyMin_other(n=2)');
    assert.equal(PS.searchErrorText({ code: 'rate_limited', retryAfter: 30 }, t), 'places.searchBusyMin_one(n=1)');
    assert.equal(PS.searchErrorText({ code: 'invalid', field: 'q' }, t), 'places.searchMin');
    assert.equal(PS.searchErrorText({ code: 'search_unavailable' }, t), 'places.searchDown');
  });
});

describe('places-state: the place choice (PlacePicking)', () => {
  // the Messenger's order (GET places): own profile places and Familie's, most used first
  const PICK = [
    { ref: 'profile:12', source: 'profile', id: 12, name: 'Arbeit', icon: 'work', lat: 50.110922, lon: 8.682127, radiusM: 200, usageCount: 5, lastUsedAt: '2026-11-17T18:02:00.000Z' },
    { ref: 'profile:11', source: 'profile', id: 11, name: 'Zuhause', icon: 'home', lat: 50.05, lon: 8.6, radiusM: 150, usageCount: 2, lastUsedAt: '2026-11-18T07:31:00.000Z' },
    { ref: 'place:3', source: 'familie', id: 3, name: 'Grundschule', icon: 'school', lat: 50.06, lon: 8.61, radiusM: 150 },
    { ref: 'home', source: 'familie', id: 'home', name: 'Familie Zuhause', icon: 'home', lat: 50.05, lon: 8.6005, radiusM: 150 },
  ];
  const MINE = [ARBEIT, ZUHAUSE, STUDIO, LEER, place({ id: 14, name: 'Baumarkt', icon: 'shop', lat: 50.09, lon: 8.7, address: 'Industriestraße 20, Musterstadt' })];
  const OPTS = PS.mergeOptions(PICK, MINE);

  it('options: the plugin’s order and use win, the own places fill in; Familie places are marked', () => {
    assert.deepEqual(OPTS.map((o) => o.key), ['profile:12', 'profile:11', 'place:3', 'home', 'profile:13', 'profile:15', 'profile:14']);
    assert.deepEqual(OPTS.map((o) => o.familie), [false, false, true, true, false, false, false]);
    assert.equal(OPTS[0].profileId, 12);
    assert.equal(OPTS[2].id, 3);
    assert.equal(OPTS[5].hasPoint, false);
  });

  it('distance: haversine, „850 m“ / „3,4 km“ / „12 km“', () => {
    assert.equal(PS.distanceM(50, 8, 50, 8), 0);
    assert.ok(Math.abs(PS.distanceM(50.05, 8.6, 50.110922, 8.682127) - 8957) < 5);
    assert.equal(PS.distanceText(847, 'de'), '850 m');
    assert.equal(PS.distanceText(3420, 'de'), '3,4 km');
    assert.equal(PS.distanceText(3420, 'en'), '3.4 km');
    assert.equal(PS.distanceText(12400, 'de'), '12 km');
  });

  it('„In der Nähe“ from the chosen place, else from „Zuhause“, else none (this PC has no position)', () => {
    assert.deepEqual(PS.anchorOf(OPTS, OPTS[0]), { lat: 50.110922, lon: 8.682127, name: 'Arbeit' });
    assert.deepEqual(PS.anchorOf(OPTS, null), { lat: 50.05, lon: 8.6, name: 'Zuhause' });
    assert.deepEqual(PS.anchorOf(PS.mergeOptions([PICK[3]], []), null), { lat: 50.05, lon: 8.6005, name: 'Familie Zuhause' });
    assert.equal(PS.anchorOf(PS.mergeOptions([PICK[2]], []), null), null);
  });

  it('chips: the chosen one, then the most used, then the nearest; at most three; none without a point', () => {
    const here = PS.anchorOf(OPTS, null);
    assert.deepEqual(PS.chips(OPTS, null, here).map((o) => o.name), ['Arbeit', 'Zuhause', 'Familie Zuhause']);
    const studio = OPTS.find((o) => o.name === 'Fitnessstudio');
    assert.deepEqual(PS.chips(OPTS, studio, PS.anchorOf(OPTS, studio)).map((o) => o.name), ['Fitnessstudio', 'Arbeit', 'Zuhause']);
    assert.ok(!PS.chips(OPTS, null, null, 10).some((o) => o.name === 'Ärztehaus'));
  });

  it('groups: „Zuletzt genutzt“ (latest first), „In der Nähe“ (≤ 5 km, by distance), then A–Z with „#“ last', () => {
    const extra = PS.mergeOptions([...PICK, { ref: 'profile:20', name: '7 Zwerge Kita', lat: 52.5, lon: 13.4 }], MINE);
    const g = PS.groups(extra, PS.anchorOf(extra, null));
    assert.deepEqual(g.map((x) => (x.kind === 'letter' ? x.letter : x.kind)), ['recent', 'near', 'A', 'B', '#']);
    assert.deepEqual(g[0].items.map((o) => o.name), ['Zuhause', 'Arbeit']);
    assert.deepEqual(g[1].items.map((o) => o.name), ['Familie Zuhause', 'Grundschule', 'Fitnessstudio']);
    assert.deepEqual(g[2].items.map((o) => o.name), ['Ärztehaus']);
    // without an anchor: no „In der Nähe“
    assert.ok(!PS.groups(extra, null).some((x) => x.kind === 'near'));
  });

  it('the local search: name or address, accents and „ß“ ignored, a name that starts with it first', () => {
    assert.deepEqual(PS.search(OPTS, 'bau', null).map((o) => o.name), ['Baumarkt']);
    assert.deepEqual(PS.search(OPTS, 'industriestrasse', null).map((o) => o.name), ['Baumarkt']);
    assert.deepEqual(PS.search(OPTS, 'arzte', null).map((o) => o.name), ['Ärztehaus']);
    assert.deepEqual(PS.search(OPTS, 'zu', null).map((o) => o.name), ['Zuhause', 'Familie Zuhause']);
    assert.deepEqual(PS.search(OPTS, ' ', null), []);
  });

  it('addresses: only from 3 characters, and only hits that are no place yet (30 m)', () => {
    assert.equal(PS.searchable('ba'), false);
    assert.equal(PS.searchable(' bau '), true);
    const hits = [{ name: 'Bauhaus', address: 'Industriestraße 20, Musterstadt', lat: 50.0901, lon: 8.7002 }, { name: 'Baustoffhandel Nord', address: 'Kanalweg 3, Musterstadt', lat: 50.12, lon: 8.71 }];
    assert.deepEqual(PS.newHits(hits, OPTS).map((h) => h.name), ['Baustoffhandel Nord']);
    const h = PS.hitOption(hits[1]);
    assert.equal(h.ref, null);
    assert.equal(h.hit, true);
    assert.equal(PS.sourceLine(h, t), 'Kanalweg 3, Musterstadt · places.srcOsm');
  });

  it('the place of a Messenger event: Familie with familiePlaceId, a profile place or a hit as a copy', () => {
    assert.deepEqual(PS.eventPlace(OPTS[2]), { label: 'Grundschule', familiePlaceId: 3, lat: 50.06, lon: 8.61 });
    assert.deepEqual(PS.eventPlace(OPTS[0]), { label: 'Arbeit', lat: 50.110922, lon: 8.682127 });
    assert.deepEqual(PS.eventPlace(OPTS[5], 'Ärztehaus'), { label: 'Ärztehaus' });
    assert.equal(PS.eventPlace(null), null);
    assert.equal(PS.find(OPTS, 'place:3').name, 'Grundschule');
    assert.equal(PS.find(OPTS, 'profile:99'), null);
  });
});

describe('places: wiring', () => {
  const html = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'index.html'), 'utf8');
  const view = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'places-view.js'), 'utf8');
  const rich = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'chat-rich.js'), 'utf8');
  const notes = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'notes-view.js'), 'utf8');
  const chat = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'chat-view.js'), 'utf8');
  const main = fs.readFileSync(path.join(ROOT, 'src', 'main', 'main.js'), 'utf8');

  it('the page, its nav entry (hidden until the server knows the places) and its scripts after chat-state.js', () => {
    assert.match(html, /id="nav-orte"[^>]*data-page="orte"[^>]*hidden/);
    assert.match(html, /<section class="page" id="page-orte"/);
    assert.match(html, /href="styles\/places\.css"/);
    const at = (f) => html.indexOf(`<script src="${f}"></script>`);
    assert.ok(at('chat-state.js') >= 0 && at('chat-state.js') < at('places-state.js') && at('places-state.js') < at('places-view.js') && at('places-view.js') < at('renderer.js'));
  });

  it('main creates the service and hands it to the IPC', () => {
    assert.match(main, /new PlacesService\(\{ apiClient, log, pushClient: notifications\?\.pushClient, getLang: \(\) => getLocale\(\) \}\)/);
    assert.match(main, /places\?\.start\(\)/);
    assert.match(main, /\n\s+places,\n/);
  });

  it('no innerHTML in the view', () => {
    assert.ok(!/\.innerHTML\b|insertAdjacentHTML|outerHTML/.test(view));
  });

  it('every places.* key used exists in both languages', () => {
    const flat = (o, p = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = p ? `${p}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(fs.readFileSync(path.join(ROOT, 'src', 'i18n', 'de.json'), 'utf8')));
    const en = flat(JSON.parse(fs.readFileSync(path.join(ROOT, 'src', 'i18n', 'en.json'), 'utf8')));
    const keys = new Set();
    for (const src of [view, rich, notes, chat, fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'places-state.js'), 'utf8')]) {
      for (const m of src.matchAll(/t\('(places\.[A-Za-z0-9_.]+)'/g)) keys.add(m[1]);
    }
    for (const ic of PS.ICONS) keys.add(`places.icons.${ic}`);
    for (const v of PS.VISIBILITY) { keys.add(`places.vis.${v}`); keys.add(`places.visShort.${v}`); }
    for (const k of PS.KINDS) { keys.add(`places.use.${k}_one`); keys.add(`places.use.${k}_other`); }
    for (const k of ['count', 'missing', 'missingHint', 'usesPlugins', 'searchBusyMin']) { keys.add(`places.${k}_one`); keys.add(`places.${k}_other`); }
    for (const k of ['recent', 'near', 'mine', 'addresses']) keys.add(`places.group.${k}`);
    for (const k of ['duplicate', 'invalid', 'limit', 'not_found', 'offline', 'rate_limited', 'unsupported', 'other']) keys.add(`places.err.${k}`);
    for (const k of ['profileHint', 'openMine', 'notMoved_one', 'notMoved_other']) keys.add(`notes.place.${k}`);
    assert.ok(keys.size > 80, `only ${keys.size} keys`);
    for (const key of keys) {
      assert.ok(key in de, `de: ${key}`);
      assert.ok(key in en, `en: ${key}`);
    }
  });
});
