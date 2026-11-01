'use strict';

// Drive 1.18 "Übersicht" on the page "Drive" (no DOM, drive-overview-state.js): the switch Übersicht | Dateien | Fotos,
// the words of the tiles (deadlines, files opened lately, memories, "Neu in …", storage) — with the tiles and their
// numbers as the core computes them (utils/drive-overview.js) — that the page loads the new scripts, never uses
// innerHTML there, that the photos no longer show "Vor einem Jahr", and that every key exists in de and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const OS = require('../src/renderer/drive-overview-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const at = (y, mo, d, h = 12, mi = 0) => new Date(y, mo - 1, d, h, mi).getTime();

/** The core's overview and view, when the pinned core is there (CI: scripts/fetch-core.sh --link). */
function core() {
  try { return require('@gatecontrol/client-core/src/utils/drive-overview'); } catch { return null; }
}

describe('the switch', () => {
  it('Übersicht | Dateien | Fotos (Fotos only with the feature) and the page of each view', () => {
    assert.deepEqual(OS.pages({ overview: true, photos: true }, t).map((p) => p.key), ['overview', 'files', 'photos']);
    assert.deepEqual(OS.pages({ overview: true, photos: false }, t).map((p) => [p.key, p.label]), [['overview', 'drive.ov.page.overview'], ['files', 'drive.ov.page.files']]);
    assert.equal(OS.pageOf('overview'), 'overview');
    assert.equal(OS.pageOf('photos'), 'photos');
    for (const v of ['folder', 'search', 'trash', 'links', 'deadlines', 'ask']) assert.equal(OS.pageOf(v), 'files', v);
    for (const v of ['settings', 'sync', 'storage']) assert.equal(OS.pageOf(v), null, v);
  });
});

describe('the words of the tiles', () => {
  const now = at(2026, 11, 1, 9);

  it('times: "vor 4 Min.", "vor 2 Std.", "gestern", "vor 3 Tagen", else the date', () => {
    assert.equal(OS.ago(now - 20000, now, 'de', t), 'drive.ov.time.now');
    assert.equal(OS.ago(now - 4 * 60000, now, 'de', t), 'drive.ov.time.min(n=4)');
    assert.equal(OS.ago(now - 2 * 3600000, now, 'de', t), 'drive.ov.time.hours(n=2)');
    assert.equal(OS.ago(at(2026, 10, 31, 8), now, 'de', t), 'drive.ov.time.hours(n=25)'.replace('hours(n=25)', 'yesterday'));
    assert.equal(OS.ago(at(2026, 10, 29, 9), now, 'de', t), 'drive.ov.time.days(n=3)');
    assert.equal(OS.ago(at(2026, 9, 1), now, 'de', t), '01.09.2026');
    assert.equal(OS.ago(NaN, now, 'de', t), '');
  });

  it('a deadline: its title, "in 3 Tagen · Familie", the number on its square', () => {
    const d = { id: 1, kind: 'payment', date: '2026-11-04', label: 'Rechnung Stadtwerke zahlen', node: { id: 11, name: 'Rechnung.pdf', areaId: 'family:1' } };
    const r = OS.deadlineRow(d, { key: 'in', days: 3 }, { t, areaLabel: (id) => (id === 'family:1' ? 'Familie' : '') });
    assert.deepEqual(r, { title: 'Rechnung Stadtwerke zahlen', sub: 'drive.ov.due.in.other(count=3) · Familie', badge: '3' });
    assert.equal(OS.deadlineRow({ ...d, label: null }, { key: 'today', days: 0 }, { t }).title, 'Rechnung.pdf');
    assert.equal(OS.deadlineRow({ kind: 'cancellation' }, { key: 'past', days: -2 }, { t }).title, 'drive.deadline.kind.cancellation');
    assert.equal(OS.deadlineRow({ kind: 'cancellation' }, { key: 'past', days: -2 }, { t }).badge, '!');
    // far off: the calendar instead of a long number
    assert.equal(OS.deadlineRow({ kind: 'payment' }, { key: 'in', days: 400 }, { t }).badge, null);
  });

  it('files: the short type, "gestern · Familie"', () => {
    assert.deepEqual(OS.fileBadge('Steuerbescheid 2025.pdf'), { text: 'PDF', tone: 'red' });
    assert.deepEqual(OS.fileBadge('Elternbrief.docx'), { text: 'DOC', tone: 'blue' });
    assert.deepEqual(OS.fileBadge('Haushaltsbuch.xlsx'), { text: 'XLS', tone: 'green' });
    assert.deepEqual(OS.fileBadge('README'), { text: '', tone: 'muted' });
    assert.equal(OS.recentSub({ node: { name: 'a.pdf' }, openedAt: now - 3 * 3600000, areaLabel: 'Familie' }, { t, now }), 'drive.ov.time.hours(n=3) · Familie');
    assert.equal(OS.recentSub({ node: { name: 'a.pdf', mtime: now - 120000 }, openedAt: null, changedAt: null, areaLabel: null }, { t, now }), 'drive.ov.time.min(n=2)');
  });

  it('memories: "Heute vor 2 Jahren", "Vor einem Jahr", "An diesem Tag" and "30 Fotos · Mallorca"', () => {
    const m = { count: 30, cover: { geo: { place: { name: 'Mallorca' } } } };
    assert.deepEqual(OS.memoryText(m, { today: true, years: 2 }, { t }), { title: 'drive.ov.mem.today.other(count=2)', sub: 'drive.photos.count.other(count=30) · Mallorca' });
    assert.equal(OS.memoryText({ count: 1, cover: {} }, { today: false, years: 1 }, { t }).title, 'drive.ov.mem.ago.one(count=1)');
    assert.equal(OS.memoryText({ count: 1, cover: {} }, { today: false, years: 0 }, { t }).title, 'drive.ov.mem.day');
  });

  it('"Neu in …": the name bold, what they did, where and when; the heading', () => {
    const a = { at: now - 2 * 3600000, user: { id: 2, name: 'Mama' }, area: { label: 'Familie' } };
    assert.deepEqual(OS.activityText(a, { key: 'photos', n: 14, name: 'Mama', file: null, folder: 'Urlaub 2026' }, { t, now }),
      { name: 'Mama', rest: 'drive.ov.act.photos.other(count=14)', sub: 'Urlaub 2026 · drive.ov.time.hours(n=2)' });
    assert.equal(OS.activityText(a, { key: 'file', n: 1, name: null, file: 'Zeugnis Lea.pdf', folder: null }, { t, now }).rest, 'drive.ov.act.file(file=Zeugnis Lea.pdf)');
    assert.equal(OS.activityText(a, { key: 'file', n: 1, name: null, file: 'x.pdf', folder: null }, { t, now }).name, 'drive.ov.act.someone');
    // the top of the area: its name
    assert.match(OS.activityText(a, { key: 'changed', n: 3, name: 'Papa', file: null, folder: null }, { t, now }).sub, /^Familie · /);
    assert.equal(OS.activityTitle('Familie', t), 'drive.ov.act.title(area=Familie)');
    assert.equal(OS.activityTitle(null, t), 'drive.ov.act.titleShared');
  });

  it('storage, places, initials', () => {
    const fb = (n) => `${n / 1e9} GB`;
    assert.equal(OS.storageText({ used: 212e9, total: 1000e9, target: null }, { t, formatBytes: fb }), 'drive.ov.storage.of(used=212 GB,total=1000 GB)');
    assert.equal(OS.storageText({ used: 5e9, total: null, target: 'NAS' }, { t, formatBytes: fb }), 'drive.ov.storage.used(used=5 GB) · NAS');
    assert.equal(OS.storageText(null, { t }), '');
    assert.equal(OS.placesLine({ top: [{ name: 'Köln' }, { name: 'Hamburg' }, { name: 'Mallorca' }] }), 'Köln · Hamburg · Mallorca');
    assert.equal(OS.initials('Oma Gerda'), 'OG');
    assert.equal(OS.initials(''), '?');
    assert.equal(OS.fmt(3871, 'de'), '3.871');
  });

  it('with the core: the tiles and their numbers of an answer of GET overview', { skip: !core() }, () => {
    const OV = core();
    const ov = OV.normalizeOverview({
      todo: { deadlines: [{ id: 1, kind: 'payment', date: '2026-11-04', label: 'Rechnung', node: { id: 11, areaId: 'family:1', name: 'R.pdf' } }], deadlinesTotal: 1, review: 12, toFile: 3, toFileHint: 'Familie › Versicherungen' },
      recent: [{ id: 21, areaId: 'family:1', name: 'Steuerbescheid.pdf', openedAt: '2026-10-31T09:00:00Z', areaLabel: 'Familie' }],
      memories: [{ yearsAgo: 2, date: '2024-11-01', count: 30, cover: { id: 31, name: 'a.jpg', takenAt: new Date(2024, 10, 1, 10).toISOString() } }],
      people: { people: [{ id: 1, name: 'Lea', count: 3 }], unnamed: 2 },
      places: { top: [{ key: 'geonames:1', name: 'Köln', count: 1629 }], cluster: { lat: 50.94, lon: 6.96, count: 3871 }, total: 3871 },
      activity: [], storage: { used: 212e9, total: 1e12 },
    });
    const v = OV.overviewView(ov, now);
    // no activity: the storage is a tile of its own in the first row
    assert.deepEqual(v.tiles, ['todo', 'recent', 'storage', 'memories', 'people', 'places']);
    assert.equal(v.todoCount, 3);
    assert.deepEqual(v.deadlines[0].when, { key: 'in', days: 3 });
    assert.equal(OS.memoryText(ov.memories[0], v.memories[0], { t }).title, 'drive.ov.mem.today.other(count=2)');
    assert.equal(v.map.bubble.count, 3871);
  });
});

describe('the page', () => {
  it('loads the new scripts before drive-view.js, no innerHTML, "Vor einem Jahr" only on the overview, every key in de and en', () => {
    const html = read('src', 'renderer', 'index.html');
    const pos = (f) => html.indexOf(`<script src="${f}"></script>`);
    assert.ok(pos('drive-overview-state.js') > pos('drive-places-people-state.js'));
    assert.ok(pos('drive-overview-view.js') > pos('drive-overview-state.js'));
    assert.ok(pos('drive-view.js') > pos('drive-overview-view.js'));
    for (const f of ['drive-overview-state.js', 'drive-overview-view.js']) {
      assert.doesNotMatch(read('src', 'renderer', f), /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/, f);
    }
    // the photos no longer load the memories (they are a tile of the overview)
    assert.doesNotMatch(read('src', 'renderer', 'drive-photos-view.js'), /api\.memories\(/);
    // Drive opens on the overview
    assert.match(read('src', 'renderer', 'drive-view.js'), /view: 'overview',/);
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const src = ['drive-overview-view.js', 'drive-overview-state.js', 'drive-view.js'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set();
    for (const m of src.matchAll(/['"`](drive\.ov\.[A-Za-z0-9_.]+)['"`]/g)) if (!m[1].endsWith('.')) keys.add(m[1]);
    for (const k of ['time.now', 'time.min', 'time.hours', 'time.yesterday', 'time.days', 'act.file', 'act.changedOne']) keys.add(`drive.ov.${k}`);
    const plurals = ['drive.ov.todo.more', 'drive.ov.todo.review', 'drive.ov.todo.toFile', 'drive.ov.due.in', 'drive.ov.mem.today', 'drive.ov.mem.ago', 'drive.ov.act.photos', 'drive.ov.act.files', 'drive.ov.act.changed'];
    for (const p of plurals) { keys.delete(p); keys.add(`${p}.one`); keys.add(`${p}.other`); }
    assert.ok(keys.size > 40, `only ${keys.size} keys`);
    for (const k of keys) {
      assert.ok(typeof de[k] === 'string' && de[k], `de: ${k}`);
      assert.ok(typeof en[k] === 'string' && en[k], `en: ${k}`);
    }
    assert.equal(de['drive.ov.page.overview'], 'Übersicht');
    assert.equal(en['drive.ov.page.overview'], 'Overview');
  });
});
