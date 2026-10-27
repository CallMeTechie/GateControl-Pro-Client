'use strict';

// View logic of "Ordner sichern" on the page Drive (src/renderer/drive-sync-state.js, no DOM):
// the state of a folder and of the whole in words, the time of the last run, the Windows
// folders and "Weitere Ordner", the question after a mass delete, the size / bandwidth
// options, the add dialog's check and the error texts; that the page loads the scripts in
// order, never uses innerHTML, and that every drive.sync.* key exists in de and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SS = require('../src/renderer/drive-sync-state');

const ROOT = path.join(__dirname, '..');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const NOW = new Date(2026, 9, 27, 9, 30).getTime();
const ctx = { t, locale: 'de', now: NOW };

const folder = (o = {}) => ({
  id: 'abcdef0123456789', path: 'C:\\Users\\Marc\\Documents', name: 'Documents', mode: 'backup',
  target: { nodeId: 101, areaId: 'mine:2', label: 'Meine Dateien › Geräte › Desktop-PC › Documents' },
  paused: false, state: 'idle', reason: null, total: 0, done: 0, current: null, failed: 0, failure: null, confirm: null,
  files: 120, bytes: 5 * 1024 * 1024, skipped: 0, pendingDeletes: 0, conflicts: 0, watching: true, lastSyncAt: NOW - 120000, ...o,
});

describe('folders in words', () => {
  it('idle, running with progress, paused, waiting, errors, asking', () => {
    let v = SS.folderView(folder(), ctx);
    assert.equal(v.cls, 'ok');
    assert.equal(v.text, 'drive.sync.state.idleSince(when=drive.sync.ago.min(n=2))');
    assert.equal(v.modeText, 'drive.sync.mode.backup');
    assert.deepEqual(v.detail, ['drive.sync.files.other(count=120) · 5,0 MB']);

    v = SS.folderView(folder({ state: 'syncing', total: 10, done: 3, current: { name: 'Brief.pdf', sent: 50, total: 100 } }), ctx);
    assert.equal(v.cls, 'run');
    assert.equal(v.text, 'drive.sync.state.running(done=3,total=10)');
    assert.equal(v.pct, 35);
    assert.equal(v.detail[0], 'Brief.pdf');
    assert.equal(SS.folderView(folder({ state: 'syncing', total: 0 }), ctx).text, 'drive.sync.state.checking');

    assert.equal(SS.folderView(folder({ state: 'paused', reason: 'all' }), ctx).text, 'drive.sync.state.pausedAll');
    v = SS.folderView(folder({ state: 'waiting', reason: 'not_home' }), ctx);
    assert.equal(v.cls, 'warn');
    assert.equal(v.text, 'drive.sync.state.waiting(reason=drive.sync.reason.not_home)');
    assert.ok(v.detail.includes('drive.sync.last(when=drive.sync.ago.min(n=2))'));
    v = SS.folderView(folder({ state: 'error', reason: 'some_failed', failed: 2, failure: { name: 'x.iso', code: 'quota' } }), ctx);
    assert.equal(v.text, 'drive.sync.state.failed.other(count=2)');
    assert.ok(v.detail.includes('drive.sync.failure(name=x.iso,code=quota)'));
    assert.equal(SS.folderView(folder({ state: 'error', reason: 'weird' }), ctx).text, 'drive.sync.state.error(reason=drive.sync.reason.generic(code=weird))');
    assert.equal(SS.folderView(folder({ state: 'confirm' }), ctx).cls, 'ask');
    v = SS.folderView(folder({ pendingDeletes: 1, conflicts: 3, skipped: 2, lastSyncAt: null }), ctx);
    assert.equal(v.text, 'drive.sync.state.idle');
    assert.deepEqual(v.detail.slice(1), ['drive.sync.pendingDeletes.one(count=1)', 'drive.sync.conflicts.other(count=3)', 'drive.sync.skipped.other(count=2)']);
  });

  it('times: just now, minutes, hours, a date', () => {
    assert.equal(SS.ago(NOW - 10000, NOW, 'de', t), 'drive.sync.ago.now');
    assert.equal(SS.ago(NOW - 3 * 3600000, NOW, 'de', t), 'drive.sync.ago.hour(n=3)');
    assert.equal(SS.ago(new Date(2026, 9, 18, 8).getTime(), NOW, 'de', t), 'drive.sync.ago.date(date=18.10.2026)');
    assert.equal(SS.ago(null, NOW, 'de', t), '');
  });

  it('the pill: none, running, asking, waiting, error, paused, all up to date', () => {
    const st = (folders, o = {}) => ({ ok: true, paused: false, lastSyncAt: NOW - 60000, folders, known: [], ...o });
    assert.equal(SS.summary(st([]), ctx).cls, 'none');
    assert.deepEqual(SS.summary(st([folder({ state: 'syncing', total: 4, done: 1 }), folder({ state: 'syncing', total: 6, done: 6 })]), ctx), { cls: 'run', text: 'drive.sync.sum.running(done=7,total=10)' });
    assert.equal(SS.summary(st([folder({ state: 'confirm' }), folder({ state: 'syncing' })]), ctx).cls, 'ask');
    assert.equal(SS.summary(st([folder({ state: 'waiting', reason: 'offline' })]), ctx).text, 'drive.sync.sum.waiting(reason=drive.sync.reason.offline)');
    assert.equal(SS.summary(st([folder({ state: 'error' }), folder({ state: 'waiting' })]), ctx).cls, 'err');
    assert.equal(SS.summary(st([folder()], { paused: true }), ctx).cls, 'pause');
    assert.equal(SS.summary(st([folder({ state: 'paused' })]), ctx).cls, 'pause');
    assert.deepEqual(SS.summary(st([folder()]), ctx), { cls: 'ok', text: 'drive.sync.sum.okSince(when=drive.sync.ago.min(n=1))' });
  });

  it('Windows folders, more folders, mass deletes', () => {
    const a = folder({ id: 'a1a1a1a1a1a1a1a1' });
    const b = folder({ id: 'b2b2b2b2b2b2b2b2', path: 'D:\\Projekte', mode: 'sync', state: 'confirm', confirm: { count: 600, total: 900 } });
    const st = {
      folders: [a, b],
      known: [
        { key: 'music', path: 'C:\\Users\\Marc\\Music', folderId: null },
        { key: 'documents', path: 'C:\\Users\\Marc\\Documents', folderId: a.id },
        { key: 'other', path: 'C:\\X', folderId: null },
      ],
    };
    const rows = SS.knownRows(st, t);
    assert.deepEqual(rows.map((r) => [r.key, r.label, !!r.folder]), [['documents', 'drive.sync.known.documents', true], ['music', 'drive.sync.known.music', false]]);
    assert.deepEqual(SS.otherFolders(st).map((f) => f.id), [b.id]);
    assert.deepEqual(SS.confirms(st), [{ id: b.id, name: 'Documents', count: 600, total: 900, mode: 'sync', from: 'pc' }]);
    const fromDrive = { folders: [{ ...b, confirm: { count: 30, total: 40, from: 'drive' } }] };
    assert.equal(SS.confirms(fromDrive)[0].from, 'drive');
  });

  it('options, labels, the add check and error texts', () => {
    assert.deepEqual(SS.options([0, 512, 1024], 700), [512, 700, 1024, 0]);
    assert.deepEqual(SS.options(SS.SIZES, SS.GB * 10), SS.SIZES.filter((x) => x).concat([0]));
    assert.equal(SS.rateLabel(0, 'de', t), 'drive.sync.unlimited');
    assert.equal(SS.rateLabel(512, 'de', t), '512 KB/s');
    assert.equal(SS.rateLabel(2048, 'de', t), '2 MB/s');
    assert.equal(SS.rateLabel(5120 + 512, 'en', t), '5.5 MB/s');
    assert.equal(SS.sizeLabel(0, 'de', t), 'drive.sync.noLimit');
    assert.equal(SS.sizeLabel(SS.GB * 10, 'de', t), '10,0 GB');
    assert.deepEqual(SS.addCheck({}), { ok: false, code: 'path' });
    assert.deepEqual(SS.addCheck({ path: 'C:\\X', mode: 'backup' }), { ok: true, code: null });
    assert.deepEqual(SS.addCheck({ path: 'C:\\X', mode: 'sync' }), { ok: false, code: 'target' });
    assert.deepEqual(SS.addCheck({ path: 'C:\\X', mode: 'sync', targetId: 10 }), { ok: true, code: null });
    assert.equal(SS.errorText({ code: 'overlap' }, t), 'drive.sync.err.overlap');
    assert.equal(SS.errorText({ code: 'network' }, t), 'drive.sync.err.offline');
    assert.equal(SS.errorText({ code: 'boom' }, t), 'drive.sync.err.generic(code=boom)');
  });
});

describe('the page', () => {
  const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

  it('loads the scripts in order', () => {
    const html = read('src', 'renderer', 'index.html');
    const a = html.indexOf('src="drive-state.js"');
    const b = html.indexOf('src="drive-sync-state.js"');
    const c = html.indexOf('src="drive-sync-view.js"');
    const d = html.indexOf('src="drive-view.js"');
    assert.ok(a > 0 && b > a && c > b && d > c);
  });

  it('never uses innerHTML / insertAdjacentHTML / eval', () => {
    for (const f of ['drive-sync-view.js', 'drive-sync-state.js']) {
      assert.doesNotMatch(read('src', 'renderer', f), /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/, f);
    }
  });

  it('every drive.sync.* key exists in de and en (also those built at runtime)', () => {
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const src = ['drive-sync-view.js', 'drive-sync-state.js', 'drive-view.js'].map((f) => read('src', 'renderer', f)).join('\n') + read('src', 'main', 'main.js');
    const keys = new Set();
    for (const m of src.matchAll(/['"`](drive\.sync\.[A-Za-z0-9_.]+)['"`]/g)) if (!m[1].endsWith('.')) keys.add(m[1]);
    for (const m of SS.MODES) { keys.add(`drive.sync.mode.${m}`); keys.add(`drive.sync.mode.${m}Desc`); }
    for (const k of SS.KNOWN) keys.add(`drive.sync.known.${k}`);
    for (const r of ['all', 'folder', 'offline', 'unavailable', 'not_home', 'no_vpn', 'other_server', 'folder_missing', 'target_gone', 'no_seat', 'not_licensed', 'forbidden', 'quota', 'some_failed', 'mass_delete', 'generic']) keys.add(`drive.sync.reason.${r}`);
    for (const e of ['overlap', 'folder_missing', 'not_a_folder', 'drive_root', 'too_many', 'target_taken', 'forbidden', 'no_home', 'no_network', 'invalid', 'offline', 'not_found', 'generic']) keys.add(`drive.sync.err.${e}`);
    const plurals = ['drive.sync.state.failed', 'drive.sync.files', 'drive.sync.pendingDeletes', 'drive.sync.conflicts', 'drive.sync.skipped'];
    for (const p of plurals) { keys.delete(p); keys.add(`${p}.one`); keys.add(`${p}.other`); }
    assert.ok(keys.size > 80, `only ${keys.size} keys found`);
    for (const k of keys) {
      assert.ok(k in de, `de: ${k}`);
      assert.ok(k in en, `en: ${k}`);
    }
  });
});
