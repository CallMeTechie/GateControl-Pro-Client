'use strict';

// Drive 1.11 on the page "Drive" (no DOM, drive-menu-state.js): the menu's head (name, seat), "Persönlich" /
// "Gemeinsam", the folder tree (unfold / fold, loaded only when unfolded, hasDirs, the folder shown highlighted, the
// unfolded nodes kept), the keys of the tree, the vault rows (only in the menu; locked without a name), "Wer darf ihn
// öffnen?", the bar of icons (only what the Drive has), the vault lock's texts and the settings' helpers; that the
// page loads the new scripts, never uses innerHTML there, keeps the old vault button out of the bar, and that every
// key they use exists in de and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const MS = require('../src/renderer/drive-menu-state');
const DS = require('../src/renderer/drive-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);

const AREAS = [
  { id: 'mine:2', kind: 'mine', label: 'Meine Dateien', rootId: 1, writable: true, archived: false },
  { id: 'family:1', kind: 'family', label: 'Familie Muster', rootId: 2, writable: true, archived: false },
  { id: 'child:7', kind: 'child', label: 'Lena', rootId: 3, writable: false, archived: false },
  { id: 'team:1', kind: 'team', label: 'Büro', rootId: 4, writable: true, archived: false },
  { id: 'team:2', kind: 'team', label: 'Archiv', rootId: 5, writable: true, archived: true },
];

describe('the menu\'s head and groups', () => {
  it('name, initial and seat', () => {
    assert.deepEqual(MS.meView({ me: { name: 'marc', seat: 'family' } }, t), { name: 'marc', initial: 'M', seat: 'drive.menu.seat.family' });
    assert.equal(MS.meView({ me: { name: 'A', seat: 'business' } }, t).seat, 'drive.menu.seat.business');
    assert.deepEqual(MS.meView(null, t), { name: '', initial: '?', seat: '' });
  });

  it('"Persönlich": Meine Dateien; "Gemeinsam": family, children, teams', () => {
    const g = MS.areaGroups(AREAS);
    assert.deepEqual(g.personal.map((a) => a.id), ['mine:2']);
    assert.deepEqual(g.shared.map((a) => a.id), ['family:1', 'child:7', 'team:1', 'team:2']);
  });
});

describe('the folder tree', () => {
  const base = { usage: () => '38 GB', areaLabel: (a) => a.label, areaHint: () => 'nur für dich' };

  it('areas folded: an arrow (unknown yet), nothing to load', () => {
    const r = MS.treeRows(AREAS.slice(0, 2), { ...base, nodes: new Map(), open: new Set(), current: 1 });
    assert.deepEqual(r.rows.map((x) => [x.key, x.level, x.expandable, x.expanded, x.current]), [['n:1', 1, true, false, true], ['n:2', 1, true, false, false]]);
    assert.equal(r.rows[0].sub, '38 GB · nur für dich');
    assert.deepEqual(r.needs, []);
    assert.deepEqual([r.rows[0].posinset, r.rows[0].setsize], [1, 2]);
  });

  it('unfolded but not loaded → to load; loaded → its folders one level deeper; hasDirs false: no arrow', () => {
    const open = new Set([1, 10]);
    let r = MS.treeRows(AREAS.slice(0, 1), { ...base, nodes: new Map(), open, current: null });
    assert.deepEqual(r.needs, [1]);
    assert.equal(r.rows[0].loading, true);
    const nodes = new Map([[1, { items: [{ id: 10, name: 'Dokumente', hasDirs: true }, { id: 11, name: 'Fotos', hasDirs: false }, { id: 12, name: 'Alt', hasDirs: null }] }]]);
    r = MS.treeRows(AREAS.slice(0, 1), { ...base, nodes, open, current: 11 });
    assert.deepEqual(r.rows.map((x) => [x.label, x.level, x.expandable, x.expanded, x.current]), [
      ['Meine Dateien', 1, true, true, false], ['Dokumente', 2, true, true, false], ['Fotos', 2, false, false, true], ['Alt', 2, true, false, false],
    ]);
    assert.deepEqual(r.needs, [10]);
    assert.equal(r.rows[1].parentKey, 'n:1');
    // an older Drive: a folder found empty when opened loses its arrow
    nodes.set(10, { items: [] });
    r = MS.treeRows(AREAS.slice(0, 1), { ...base, nodes, open, current: null });
    assert.equal(r.rows[1].expandable, false);
    assert.equal(r.rows.length, 4);
    // loading in flight / failed: not asked again from here
    nodes.set(12, { loading: true });
    r = MS.treeRows(AREAS.slice(0, 1), { ...base, nodes, open: new Set([1, 12]), current: null });
    assert.deepEqual(r.needs, []);
  });

  it('the unfolded nodes kept on this PC (ids only, at most 500); the folders above the one shown', () => {
    const set = MS.parseOpen('[1, 10, "x", -3, 2.5, 10]');
    assert.deepEqual([...set], [1, 10]);
    assert.equal(MS.serializeOpen(set), '[1,10]');
    assert.deepEqual([...MS.parseOpen('nope')], []);
    assert.equal(MS.parseOpen(JSON.stringify(Array.from({ length: 700 }, (_, i) => i + 1))).size, 500);
    assert.deepEqual(MS.ancestorsOf({ crumbs: [{ id: 1 }, { id: 10 }, { id: 30 }] }), [1, 10]);
    assert.deepEqual(MS.ancestorsOf(null), []);
  });

  it('keys: arrows, Home / End, right unfolds / steps in, left folds / steps out, Enter / Space open', () => {
    const rows = [
      { key: 'n:1', id: 1, level: 1, expandable: true, expanded: true, parentKey: null },
      { key: 'n:10', id: 10, level: 2, expandable: true, expanded: false, parentKey: 'n:1' },
      { key: 'n:11', id: 11, level: 2, expandable: false, expanded: false, parentKey: 'n:1' },
      { key: 'n:2', id: 2, level: 1, expandable: true, expanded: false, parentKey: null },
    ];
    assert.deepEqual(MS.treeKey('ArrowDown', rows, 0), { focus: 1 });
    assert.equal(MS.treeKey('ArrowDown', rows, 3), null);
    assert.deepEqual(MS.treeKey('ArrowUp', rows, 2), { focus: 1 });
    assert.deepEqual(MS.treeKey('Home', rows, 2), { focus: 0 });
    assert.deepEqual(MS.treeKey('End', rows, 0), { focus: 3 });
    assert.deepEqual(MS.treeKey('ArrowRight', rows, 1), { expand: 10 });
    assert.deepEqual(MS.treeKey('ArrowRight', rows, 0), { focus: 1 });
    assert.equal(MS.treeKey('ArrowRight', rows, 2), null);
    assert.deepEqual(MS.treeKey('ArrowLeft', rows, 0), { collapse: 1 });
    assert.deepEqual(MS.treeKey('ArrowLeft', rows, 2), { focus: 0 });
    assert.equal(MS.treeKey('ArrowLeft', rows, 3), null);
    assert.deepEqual(MS.treeKey('Enter', rows, 2), { open: 11 });
    assert.deepEqual(MS.treeKey(' ', rows, 0), { open: 1 });
    assert.equal(MS.treeKey('a', rows, 0), null);
  });
});

describe('vaults in the menu and "Neuer Tresor"', () => {
  it('rows: the name only while open, else by date; who it is for and its state; open ones first', () => {
    const created = new Date(2026, 2, 12).getTime();
    const rows = MS.vaultRows([
      { id: 'a', nodeId: 50, areaId: 'family:1', name: null, state: 'locked', createdAt: created },
      { id: 'b', nodeId: 51, areaId: 'mine:2', name: 'Steuer', state: 'open' },
      { id: 'c', nodeId: 52, areaId: 'team:1', name: null, state: 'pending' },
      { id: 'd', nodeId: 53, areaId: 'child:7', name: null, state: 'approved' },
    ], AREAS, { t, locale: 'de', currentVault: 'b' });
    assert.deepEqual(rows.map((r) => [r.vaultId, r.state, r.current]), [['b', 'open', true], ['a', 'locked', false], ['c', 'pending', false], ['d', 'locked', false]]);
    assert.equal(rows[0].name, 'Steuer');
    assert.equal(rows[0].sub, 'drive.menu.vault.private · drive.menu.vault.state.open');
    assert.equal(rows[1].name, 'drive.menu.vault.lockedName(date=12.03.2026)');
    assert.equal(rows[1].sub, 'drive.menu.vault.family · drive.menu.vault.state.locked');
    assert.equal(rows[2].name, 'drive.menu.vault.lockedNameNoDate');
    assert.equal(rows[2].sub, 'drive.area.team(name=Büro) · drive.menu.vault.state.pending');
    assert.equal(rows[3].sub, 'drive.area.child(name=Lena) · drive.menu.vault.state.locked');
    // "Freigegeben für": the vaults this PC has keys for (open or locked), not the pending one
    assert.deepEqual(MS.approvedVaults(rows), ['Steuer', 'drive.menu.vault.lockedName(date=12.03.2026)', 'drive.menu.vault.lockedNameNoDate']);
  });

  it('"Wer darf ihn öffnen?": only me; the family only with a family seat; teams one may write to with a business seat', () => {
    const fam = MS.vaultChoices({ me: { seat: 'family' } }, AREAS, t);
    assert.deepEqual(fam.map((c) => [c.areaId, c.label]), [['mine:2', 'drive.vault.create.onlyMe'], ['family:1', 'drive.vault.create.family']]);
    const biz = MS.vaultChoices({ me: { seat: 'business' } }, AREAS, t);
    assert.deepEqual(biz.map((c) => c.areaId), ['mine:2', 'team:1'], 'archived and read-only left out');
    assert.deepEqual(MS.vaultChoices(null, [], t), []);
  });
});

describe('the bar of icons', () => {
  it('only what this Drive / build has, the gear last', () => {
    const all = MS.toolItems({ me: { features: ['photos', 'storage', 'docAi', 'cloudImport'] }, photos: true, storage: true, sync: true, deadlines: true, importer: true }, t);
    assert.deepEqual(all.map((x) => x.key), ['photos', 'links', 'trash', 'storage', 'sync', 'deadlines', 'import', 'settings']);
    assert.ok(all.every((x) => x.label && x.icon));
    const few = MS.toolItems({ me: { features: [] }, photos: true, storage: true, sync: false, deadlines: true, importer: true }, t);
    assert.deepEqual(few.map((x) => x.key), ['links', 'trash', 'settings']);
  });
});

describe('the vault lock and the settings', () => {
  it('Windows Hello hints; when the card may unlock', () => {
    assert.equal(MS.helloHint({ available: true }, t), null);
    assert.deepEqual(MS.helloHint({ available: false, reason: 'not_set_up' }, t), { text: 'drive.lock.hello.notSetUp', setup: true });
    assert.equal(MS.helloHint({ available: false, reason: 'disabled_by_policy' }, t).setup, false);
    assert.equal(MS.helloHint({ available: false, reason: 'unsupported_os' }, t).text, 'drive.lock.hello.unavailable');
    assert.equal(MS.canUnlock(null), true);
    assert.equal(MS.canUnlock({ enforced: false }), true);
    assert.equal(MS.canUnlock({ enforced: true, settings: { hello: true }, hello: { available: false } }), false);
    assert.equal(MS.canUnlock({ enforced: true, settings: { hello: false }, hello: { available: false } }), true);
    assert.equal(MS.canUnlock({ enforced: true, settings: { hello: true }, hello: { available: true } }), true);
    assert.deepEqual(MS.autoLockOptions(t).map((o) => o.value), [1, 3, 5, 15, 0]);
    assert.equal(MS.autoLockOptions(t)[0].label, 'drive.lock.after.one(count=1)');
    assert.equal(MS.autoLockOptions(t)[4].label, 'drive.lock.after.never');
  });

  it('AI per area (write right, Drive says docAi); Drive\'s notification topics and the mute list', () => {
    const areas = [{ ...AREAS[0], docAi: true }, { ...AREAS[2], docAi: false }, { ...AREAS[4], docAi: true }, { ...AREAS[1], docAi: null }];
    assert.deepEqual(MS.docAiAreas(areas, { features: ['docAi'] }).map((x) => [x.areaId, x.on]), [['mine:2', true]]);
    assert.deepEqual(MS.docAiAreas(areas, { features: [] }), []);
    const topics = [{ id: 'plugin:gatecontrol-drive:deadline', label: 'Drive · Fristen' }, { id: 'plugin:gatecontrol-drive:vault' }, { id: 'plugin:other:x' }, { id: 'system' }];
    const rows = MS.notifyRows(topics, ['plugin:gatecontrol-drive:vault'], t);
    assert.deepEqual(rows.map((r) => [r.id, r.label, r.on]), [['plugin:gatecontrol-drive:deadline', 'drive.settings.notify.deadline', true], ['plugin:gatecontrol-drive:vault', 'drive.settings.notify.vault', false]]);
    assert.deepEqual(MS.toggleMuted(['a'], 'b', false), ['a', 'b']);
    assert.deepEqual(MS.toggleMuted(['a', 'b'], 'a', true), ['b']);
  });

  it('the vault lock\'s error codes have texts', () => {
    for (const code of ['hello_cancelled', 'hello_not_set_up', 'hello_policy', 'hello_busy', 'hello_retries', 'hello_unavailable', 'hello_failed']) {
      assert.notEqual(DS.errorText({ code }, t), `drive.err.generic(code=${code})`, code);
    }
  });
});

describe('the page', () => {
  it('loads the new scripts before drive-view.js; no innerHTML; the old buttons left the bar', () => {
    const html = read('src', 'renderer', 'index.html');
    const at = (f) => html.indexOf(`<script src="${f}"></script>`);
    for (const f of ['drive-menu-state.js', 'drive-settings-view.js']) {
      assert.ok(at(f) > 0, f);
      assert.ok(at(f) < at('drive-view.js'), `${f} before drive-view.js`);
    }
    for (const f of ['drive-menu-state.js', 'drive-settings-view.js', 'drive-view.js', 'drive-vault-view.js']) {
      assert.doesNotMatch(read('src', 'renderer', f), /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(/, f);
    }
    const v = read('src', 'renderer', 'drive-view.js');
    assert.doesNotMatch(v, /dv-vault-new/);
    assert.match(v, /role: 'tree'/);
    assert.match(v, /'aria-expanded'/);
    assert.match(v, /MS\.treeKey\(e\.key, rows, idx\)/);
  });

  it('every key the new code uses exists in de and en', () => {
    const de = JSON.parse(read('src', 'i18n', 'de.json'));
    const en = JSON.parse(read('src', 'i18n', 'en.json'));
    const get = (o, k) => k.split('.').reduce((x, p) => (x && typeof x === 'object' ? x[p] : undefined), o);
    const src = ['drive-menu-state.js', 'drive-settings-view.js', 'drive-view.js', 'drive-vault-view.js', 'drive-sync-view.js'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set([...src.matchAll(/['`](drive\.(?:menu|lock|settings|new|vault\.create|sync\.set\.moved)[A-Za-z0-9_.]*)['`]/g)].map((m) => m[1]));
    keys.add('drive.vault.create.lockHint.one');
    keys.add('drive.vault.create.lockHint.other');
    for (const k of keys) {
      if (k.endsWith('.')) continue;
      assert.equal(typeof get(de, k), 'string', `de ${k}`);
      assert.equal(typeof get(en, k), 'string', `en ${k}`);
    }
    for (const st of ['open', 'locked', 'pending', 'none', 'unsupported']) assert.ok(get(de, `drive.menu.vault.state.${st}`) && get(en, `drive.menu.vault.state.${st}`), st);
    for (const g of ['personal', 'shared']) assert.ok(get(de, `drive.menu.${g}`) && get(en, `drive.menu.${g}`), g);
  });
});
