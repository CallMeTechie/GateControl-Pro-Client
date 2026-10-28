'use strict';

// Drive 1.7 on the page "Drive" (no DOM): the time travel (drive-state.js: the
// menu entry only with 'timeTravel' and for folders one may write to, the
// quick choices and the date field, the preview / result texts and what
// happens to the folders of this PC), "Fotos" (drive-photos-state.js: months,
// "Vor einem Jahr", albums, the photo frame switch, selection, the preview
// limiter) and "Speicher" (drive-storage-state.js: totals, bars, duplicates –
// one copy always stays); that the page loads the new scripts in order, never
// uses innerHTML there, and that every key they use exists in de and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const DS = require('../src/renderer/drive-state');
const PS = require('../src/renderer/drive-photos-state');
const SS = require('../src/renderer/drive-storage-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const at = (y, mo, d, h = 0, m = 0) => new Date(y, mo - 1, d, h, m).getTime();
const NOW = at(2026, 10, 28, 9, 30);
const fmt = (n) => `${n}B`;

describe('time travel (drive-state.js)', () => {
  it('only for folders one may write to, on Drives with timeTravel', () => {
    const me = { features: ['timeTravel'] };
    const dir = { id: 10, isDir: true, name: 'Dokumente' };
    assert.equal(DS.actionsFor(dir, true, me).timeTravel, true);
    assert.equal(DS.actionsFor(dir, false, me).timeTravel, false);
    assert.equal(DS.actionsFor({ ...dir, isDir: false }, true, me).timeTravel, false);
    assert.equal(DS.actionsFor(dir, true, { features: ['links'] }).timeTravel, false);
    assert.equal(DS.actionsFor(dir, true, null).timeTravel, false);
    assert.equal(DS.hasFeature({ features: ['photos'] }, 'photos'), true);
  });

  it('quick choices, the date field, errors', () => {
    assert.deepEqual(DS.timeTravelPresets(NOW, t).map((p) => [p.key, NOW - p.at, p.label]), [
      ['hour', 3600000, 'drive.tt.preset.hour'], ['day', 86400000, 'drive.tt.preset.day'], ['week', 7 * 86400000, 'drive.tt.preset.week'], ['month', 30 * 86400000, 'drive.tt.preset.month'],
    ]);
    assert.equal(DS.localInputValue(at(2026, 10, 27, 14, 5)), '2026-10-27T14:05');
    assert.equal(DS.parseLocalInput('2026-10-27T14:05'), at(2026, 10, 27, 14, 5));
    assert.equal(DS.parseLocalInput(DS.localInputValue(NOW)), NOW);
    for (const bad of ['', '27.10.2026 14:05', '2026-02-31T10:00', null]) assert.equal(DS.parseLocalInput(bad), null, String(bad));
    assert.equal(DS.timeTravelError(null, NOW, t), 'drive.tt.err.when');
    assert.equal(DS.timeTravelError(NOW + 60000, NOW, t), 'drive.tt.err.future');
    assert.equal(DS.timeTravelError(NOW - 60000, NOW, t), null);
  });

  it('the preview: what changes, examples, "limited", the folders of this PC', () => {
    const v = DS.timeTravelView({ restore: 2, revert: 1, trash: 0, move: 1, total: 4, sample: [{ op: 'restore', name: 'a.txt', path: 'X/a.txt' }, { op: '??', name: 'b' }], limited: true, historySince: at(2026, 9, 1, 8, 0) }, { t, locale: 'de' });
    assert.deepEqual(v.lines, ['drive.tt.restore.other(count=2)', 'drive.tt.revert.one(count=1)', 'drive.tt.move.one(count=1)']);
    assert.deepEqual(v.sample, [{ op: 'drive.tt.op.restore', name: 'a.txt', path: 'X/a.txt' }, { op: '', name: 'b', path: '' }]);
    assert.equal(v.more, 2);
    assert.match(v.limited, /^drive\.tt\.limited\(since=.*2026, 08:00\)$/);
    assert.equal(v.empty, false);
    const e = DS.timeTravelView({ restore: 0, revert: 0, trash: 0, move: 0, total: 0, sample: [], limited: false }, { t, locale: 'de' });
    assert.equal(e.empty, true);
    assert.equal(e.limited, null);
    assert.deepEqual(DS.timeTravelLinked([{ mode: 'sync', name: 'Projekt' }, { mode: 'backup', path: 'C:\\Users\\a\\Bilder' }], t), [
      { mode: 'sync', name: 'Projekt', text: 'drive.tt.linkedSync(name=Projekt)' },
      { mode: 'backup', name: 'C:\\Users\\a\\Bilder', text: 'drive.tt.linkedBackup(name=C:\\Users\\a\\Bilder)' },
    ]);
    assert.deepEqual(DS.timeTravelLinked(undefined, t), []);
  });

  it('the result and "Rückgängig"', () => {
    assert.equal(DS.timeTravelResultText({ restored: 1, reverted: 2, trashed: 3, moved: 0, failed: 1 }, t),
      'drive.tt.done(what=drive.tt.restored.one(count=1), drive.tt.reverted.other(count=2), drive.tt.trashed.other(count=3), drive.tt.failed.one(count=1))');
    assert.equal(DS.timeTravelResultText({}, t, { undo: true }), 'drive.tt.undone(what=drive.tt.nothing)');
  });
});

describe('Fotos (drive-photos-state.js)', () => {
  const p = (id, ms, o = {}) => ({ id, name: `IMG_${id}.jpg`, kind: 'image', takenAt: ms, preview: true, mediaId: null, ...o });

  it('features from me', () => {
    assert.deepEqual(PS.features({ features: ['photos', 'albums'] }), { photos: true, albums: true, frame: false });
    assert.deepEqual(PS.features(null), { photos: false, albums: false, frame: false });
  });

  it('months: keys, labels, the start of a jump, groups with the counts of photos/months', () => {
    assert.equal(PS.monthKey(at(2026, 10, 3, 12)), '2026-10');
    assert.equal(PS.monthLabel('2026-10', 'de'), 'Oktober 2026');
    assert.equal(PS.monthLabel('2026-10', 'en'), 'October 2026');
    assert.equal(PS.monthLabel('x', 'de'), '');
    assert.equal(PS.monthStart('2026-10'), new Date(2026, 10, 1).toISOString());
    assert.equal(PS.monthStart('2026-12'), new Date(2027, 0, 1).toISOString());
    const items = [p(1, at(2026, 10, 20)), p(2, at(2026, 10, 2)), p(3, at(2026, 9, 30)), p(4, null)];
    const g = PS.groupByMonth(items, [{ month: '2026-10', count: 40 }, { month: '2026-09', count: 1 }], 'de', t);
    assert.deepEqual(g.map((x) => [x.key, x.count, x.items.map((i) => i.id)]), [['2026-10', 40, [1, 2]], ['2026-09', 1, [3]], ['none', 1, [4]]]);
    assert.equal(g[2].label, 'drive.photos.noDate');
    assert.deepEqual(PS.mergePage([p(1, 1), p(2, 2)], { items: [p(2, 2), p(3, 3)] }).map((x) => x.id), [1, 2, 3]);
  });

  it('"Vor einem Jahr", the time of a photo, the area filter', () => {
    const m = PS.memoriesView([{ yearsAgo: 1, date: '2025-10-28', items: [p(1, 1)] }, { yearsAgo: 3, items: [] }], { t, locale: 'de' });
    assert.equal(m.length, 1);
    assert.equal(m[0].title, 'drive.photos.yearsAgo.one(count=1)');
    assert.equal(m[0].sub, '28. Oktober 2025 · drive.photos.count.one(count=1)');
    assert.equal(PS.photoWhen(p(1, at(2026, 7, 14, 18, 3)), 'de'), '14. Juli 2026, 18:03');
    assert.equal(PS.photoWhen(p(1, null), 'de'), '');
    const label = (a) => a.label;
    assert.deepEqual(PS.areaChoices([{ id: 'mine:2', label: 'Meine' }], label, t), [{ id: '', label: 'drive.photos.allAreas' }, { id: 'mine:2', label: 'Meine' }]);
  });

  it('albums: cards, who may change them, the photo frame, names, areas', () => {
    const areas = [{ id: 'family:1', kind: 'family', label: 'Familie', writable: true, archived: false }, { id: 'team:1', label: 'Büro', writable: false }, { id: 'team:2', label: 'Alt', writable: true, archived: true }];
    const a = { id: 3, name: 'Urlaub', areaId: 'family:1', count: 4, coverId: 11, frame: true, canEdit: true };
    assert.deepEqual(PS.albumView(a, { areas, areaLabel: (x) => x.label, t }), { id: 3, name: 'Urlaub', sub: 'drive.photos.count.other(count=4) · Familie', coverId: 11, frame: true, canEdit: true });
    assert.deepEqual(PS.editableAlbums([a, { ...a, id: 4, canEdit: false }]).map((x) => x.id), [3]);
    assert.deepEqual(PS.albumAreas(areas).map((x) => x.id), ['family:1']);
    assert.equal(PS.albumNameError('  ', t), 'drive.photos.album.nameEmpty');
    assert.equal(PS.albumNameError('x'.repeat(201), t), 'drive.photos.album.nameLong');
    assert.equal(PS.albumNameError('Sommer', t), null);
    assert.equal(PS.frameSwitch(a, { features: ['albums', 'frame'] }), true);
    assert.equal(PS.frameSwitch(a, { features: ['albums'] }), false);
    assert.equal(PS.frameSwitch({ ...a, canEdit: false }, { features: ['frame'] }), false);
  });

  it('selection, ranges, parts of 500', () => {
    let sel = PS.toggle(new Set(), 1);
    sel = PS.toggle(sel, 2);
    sel = PS.toggle(sel, 1);
    assert.deepEqual([...sel], [2]);
    const items = [1, 2, 3, 4, 5].map((id) => p(id, id));
    assert.deepEqual([...PS.selectRange(new Set([2]), items, 2, 4)].sort(), [2, 3, 4]);
    assert.deepEqual([...PS.selectRange(new Set(), items, 9, 4)], [4]);
    assert.deepEqual(PS.chunks(Array.from({ length: 1201 }, (_, i) => i)).map((c) => c.length), [500, 500, 201]);
  });

  it('the limiter runs at most n jobs at a time', async () => {
    const l = PS.limiter(2);
    let active = 0;
    let most = 0;
    const job = (v) => () => new Promise((r) => { active++; most = Math.max(most, active); setTimeout(() => { active--; r(v); }, 5); });
    const out = await Promise.all([1, 2, 3, 4, 5].map((v) => l.run(job(v))));
    assert.deepEqual(out, [1, 2, 3, 4, 5]);
    assert.equal(most, 2);
    await assert.rejects(l.run(() => { throw new Error('x'); }));
    assert.equal(await l.run(() => 7), 7);
  });
});

describe('Speicher (drive-storage-state.js)', () => {
  const data = {
    total: { bytes: 600, files: 3, versionsBytes: 300, trashBytes: 100 }, limit: { maxBytes: 2000 },
    areas: [{ id: 'mine:2', label: 'Meine', kind: 'mine', bytes: 500, files: 2, versionsBytes: 300, trashBytes: 0 }, { id: 'family:1', label: 'Familie', kind: 'family', bytes: 100, files: 1, versionsBytes: 0, trashBytes: 100, quota: 1000 }],
    people: [{ user: 2, name: 'Marc', bytes: 600, files: 3 }],
  };

  it('the total with its parts and the limit', () => {
    const v = SS.totalView(data, { t, fmt });
    assert.equal(v.used, '1000B');
    assert.equal(v.of, '2000B');
    assert.equal(v.pct, 50);
    assert.deepEqual(v.parts.map((p) => [p.key, p.text, p.pct]), [['files', '600B', 30], ['versions', '300B', 15], ['trash', '100B', 5]]);
    assert.equal(v.files, 'drive.storage.files.other(count=3)');
    const n = SS.totalView({ total: { bytes: 10 } }, { t, fmt });
    assert.equal(n.of, null);
    assert.equal(n.pct, null);
    assert.equal(SS.pct(1, 300), 0.3);
    assert.equal(SS.pct(5, 0), 0);
  });

  it('areas and people as bars (an area with a quota against its quota)', () => {
    const rows = SS.barsView(data.areas, { t, fmt, areaLabel: (a) => a.label });
    assert.deepEqual(rows.map((r) => [r.id, r.label, r.text, r.pct]), [['mine:2', 'Meine', '800B', 100], ['family:1', 'Familie', 'drive.storage.ofQuota(used=200B,quota=1000B)', 20]]);
    assert.equal(rows[0].sub, 'drive.storage.files.other(count=2) · drive.storage.versionsOf(size=300B)');
    assert.deepEqual(SS.barsView(data.people, { t, fmt }).map((r) => [r.id, r.label]), [['u2', 'Marc']]);
    assert.equal(SS.placeOf({ name: 'a.jpg', path: 'Fotos/2026/a.jpg', areaId: 'mine:2' }, [{ id: 'mine:2', label: 'Meine Dateien' }], (a) => a.label, t), 'Meine Dateien › Fotos › 2026');
  });

  it('duplicates: the suggestion keeps the oldest copy, one copy always stays', () => {
    const g = { sha256: 'a'.repeat(64), size: 10, count: 3, wasted: 20, items: [
      { id: 1, name: 'a.jpg', updatedAt: 300, canDelete: true, size: 10 },
      { id: 2, name: 'a.jpg', updatedAt: 100, canDelete: true, size: 10 },
      { id: 3, name: 'a.jpg', updatedAt: 200, canDelete: false, size: 10 },
    ] };
    // a copy one may not delete is the one that stays
    assert.deepEqual([...SS.suggest(g)].sort(), [1, 2]);
    const g2 = { ...g, items: g.items.map((i) => ({ ...i, canDelete: true })) };
    assert.deepEqual([...SS.suggest(g2)].sort(), [1, 3]);
    assert.equal(SS.canTick(g2, new Set([1, 3]), 2), false); // the last one left
    assert.equal(SS.canTick(g2, new Set([1]), 2), true);
    assert.equal(SS.canTick(g, new Set(), 3), false); // read only
    assert.deepEqual(SS.toTrash([g2], new Set([1, 2, 3])), [1, 2]);
    assert.deepEqual(SS.toTrash([g], new Set([3])), []);
    assert.equal(SS.freed([g2], [1, 3]), 20);
    const v = SS.dupView(g, { t, fmt });
    assert.equal(v.title, 'a.jpg');
    assert.equal(v.sub, 'drive.storage.copies.other(count=3) · drive.storage.size(size=10B) · drive.storage.wasted(size=20B)');
  });
});

describe('page wiring (Drive 1.7)', () => {
  it('index.html loads the new state before its view, all before drive-view.js', () => {
    const html = read('src', 'renderer', 'index.html');
    const pos = (f) => html.indexOf(`src="${f}"`);
    for (const [s, v] of [['drive-photos-state.js', 'drive-photos-view.js'], ['drive-storage-state.js', 'drive-storage-view.js']]) {
      assert.ok(pos(s) > 0 && pos(v) > pos(s) && pos('drive-view.js') > pos(v), `${s} / ${v}`);
    }
  });

  it('the new views never use innerHTML / eval', () => {
    for (const f of ['drive-photos-view.js', 'drive-photos-state.js', 'drive-storage-view.js', 'drive-storage-state.js']) {
      assert.doesNotMatch(read('src', 'renderer', f), /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/, f);
    }
  });

  it('every drive.tt / drive.photos / drive.storage key exists in de and en', () => {
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const src = ['drive-view.js', 'drive-state.js', 'drive-photos-view.js', 'drive-photos-state.js', 'drive-storage-view.js', 'drive-storage-state.js'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set();
    for (const m of src.matchAll(/['"`](drive\.(?:tt|photos|storage)\.[A-Za-z0-9_.]+)['"`]/g)) if (!m[1].endsWith('.')) keys.add(m[1]);
    for (const k of ['hour', 'day', 'week', 'month']) keys.add(`drive.tt.preset.${k}`);
    for (const k of ['restore', 'revert', 'trash', 'move']) keys.add(`drive.tt.op.${k}`);
    for (const k of ['files', 'versions', 'trash']) keys.add(`drive.storage.part.${k}`);
    for (const k of ['drive.tt.linkedSync', 'drive.tt.linkedBackup', 'drive.tt.linkedSyncH', 'drive.tt.linkedBackupH', 'drive.tt.done', 'drive.tt.undone', 'drive.storage.intro', 'drive.storage.introAll', 'drive.storage.all', 'drive.storage.mine', 'drive.photos.album.frameOnDone', 'drive.photos.album.frameOffDone']) keys.add(k);
    const plurals = ['drive.tt.restore', 'drive.tt.revert', 'drive.tt.trash', 'drive.tt.move', 'drive.tt.restored', 'drive.tt.reverted', 'drive.tt.trashed', 'drive.tt.moved', 'drive.tt.failed',
      'drive.photos.addTitle', 'drive.photos.added', 'drive.photos.yearsAgo', 'drive.photos.count', 'drive.photos.album.removed',
      'drive.storage.files', 'drive.storage.copies', 'drive.storage.dupSelected', 'drive.storage.trashTitle', 'drive.storage.andMore', 'drive.storage.trashFailed'];
    for (const p of plurals) { keys.delete(p); keys.add(`${p}.one`); keys.add(`${p}.other`); }
    assert.ok(keys.size > 120, `only ${keys.size} keys found`);
    for (const k of keys) {
      assert.ok(k in de, `de: ${k}`);
      assert.ok(k in en, `en: ${k}`);
    }
  });
});
