'use strict';

// View logic of "Dateien bei Bedarf" (src/renderer/drive-ondemand-state.js, no DOM):
// the state in words (aus / aktuell / lädt n / pausiert / Fehler mit Grund / wartet auf
// Antwort / läuft mit Administratorrechten), progress of moving and putting back, the
// space on this PC, the question after a mass delete, the Windows folders with the lock
// against "Ordner sichern" (both ways), the error texts; that the page loads the scripts
// in order, never uses innerHTML, and that every drive.od.* key exists in de and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const OS = require('../src/renderer/drive-ondemand-state');

const ROOT = path.join(__dirname, '..');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const on = (o = {}) => ({ enabled: true, supported: true, running: true, state: 'idle', pending: 0, transferring: 0, errors: [], massDelete: null, busy: null, progress: null, elevated: false, ...o });

const KNOWN = {
  syncRoot: 'C:\\Users\\Max\\GateControl Drive',
  folders: [
    { key: 'desktop', path: 'C:\\Users\\Max\\Desktop', inDrive: false },
    { key: 'documents', path: 'C:\\Users\\Max\\GateControl Drive\\Meine Dateien\\Dokumente', inDrive: true, from: 'C:\\Users\\Max\\Documents' },
    { key: 'pictures', path: 'C:\\Users\\Max\\Pictures', inDrive: false },
    { key: 'videos', path: 'D:\\Videos', inDrive: false },
    { key: 'music', path: null, inDrive: false },
  ],
};

describe('the state in words', () => {
  it('off, unsupported, missing', () => {
    assert.deepEqual(OS.summary({ enabled: false, supported: true, state: 'disabled' }, { t }), { cls: 'off', text: 'drive.od.state.off', detail: [], on: false, busy: false });
    assert.equal(OS.summary({ enabled: false, supported: false, state: 'unsupported' }, { t }).text, 'drive.od.state.unsupported');
    assert.equal(OS.summary({ enabled: true, supported: false, state: 'missing' }, { t }).text, 'drive.od.state.missing');
  });

  it('idle, loading, paused, offline, error with reason, pending, file errors, elevated', () => {
    assert.equal(OS.summary(on(), { t }).cls, 'ok');
    let s = OS.summary(on({ transferring: 3 }), { t });
    assert.equal(s.cls, 'run');
    assert.equal(s.text, 'drive.od.state.loading.other(count=3)');
    assert.equal(OS.summary(on({ state: 'paused' }), { t }).cls, 'pause');
    assert.equal(OS.summary(on({ state: 'offline' }), { t }).cls, 'warn');
    s = OS.summary(on({ state: 'error', errors: [{ code: 'http_502' }] }), { t });
    assert.equal(s.cls, 'err');
    assert.equal(s.text, 'drive.od.state.error(reason=drive.od.reason.http(code=502))');
    assert.equal(OS.summary(on({ state: 'error', errors: [{ code: 'launch' }] }), { t }).text, 'drive.od.state.error(reason=drive.od.reason.launch)');
    s = OS.summary(on({ pending: 1, errors: [{ code: 'read_only', path: 'C:\\x\\Team\\a.txt' }], elevated: true }), { t });
    assert.deepEqual(s.detail, ['drive.od.pending.one(count=1)', 'drive.od.fileError(name=a.txt,reason=drive.od.reason.read_only)', 'drive.od.elevated']);
  });

  it('a mass delete waits for an answer', () => {
    const st = on({ massDelete: { files: 600, items: 2, offline: false, sample: ['C:\\x\\Fotos', 'C:\\x\\Alt'] }, errors: [{ code: 'mass_delete' }] });
    assert.equal(OS.summary(st, { t }).cls, 'ask');
    assert.deepEqual(OS.massDelete(st), { files: 600, items: 2, offline: false, sample: ['Fotos', 'Alt'] });
    assert.equal(OS.massDelete(on()), null);
  });

  it('moving and putting back with progress', () => {
    let st = on({ busy: { kind: 'relocate', folder: 'documents' }, progress: { op: 'relocate', phase: 'move', done: 3, total: 12 } });
    const s = OS.summary(st, { t });
    assert.equal(s.cls, 'run');
    assert.equal(s.text, 'drive.od.busy.relocate(name=drive.sync.known.documents) · drive.od.busy.progress(done=3,total=12)');
    assert.equal(OS.progressPct(st), 25);
    st = on({ busy: { kind: 'restore', folder: 'music' }, progress: { phase: 'load', done: 1, total: 4 } });
    assert.match(OS.summary(st, { t }).text, /^drive\.od\.busy\.restoreLoad/);
    assert.equal(OS.progressPct(on()), null);
    assert.equal(OS.summary(on({ busy: { kind: 'disable' } }), { t }).text, 'drive.od.busy.disable');
  });

  it('space on this PC', () => {
    const u = OS.usageText({ localBytes: 3435973837, totalBytes: 197568495616, localFiles: 312 }, { t, locale: 'de' });
    assert.equal(u.local, '3,2 GB');
    assert.equal(u.total, '184 GB');
    assert.equal(OS.usageText(null, { t, locale: 'de' }), null);
  });
});

describe('Windows folders', () => {
  it('rows: in the Drive, on this PC, locked by "Ordner sichern", locked while busy or off', () => {
    const sync = { folders: [{ id: 'a', path: 'c:\\users\\max\\pictures' }] };
    const rows = OS.knownRows(KNOWN, sync, on(), t);
    assert.deepEqual(rows.map((r) => r.key), ['desktop', 'documents', 'pictures', 'videos']);
    const by = Object.fromEntries(rows.map((r) => [r.key, r]));
    assert.equal(by.desktop.canMove, true);
    assert.equal(by.documents.inDrive, true);
    assert.equal(by.documents.canRestore, true);
    assert.equal(by.documents.from, 'C:\\Users\\Max\\Documents');
    assert.equal(by.pictures.lock, 'w2');
    assert.equal(by.pictures.canMove, false);
    let busyRows = OS.knownRows(KNOWN, sync, on({ busy: { kind: 'relocate', folder: 'desktop' } }), t);
    assert.ok(busyRows.every((r) => !r.canMove && !r.canRestore));
    assert.equal(busyRows.find((r) => r.key === 'desktop').working, true);
    busyRows = OS.knownRows(KNOWN, sync, on({ running: false }), t);
    assert.ok(busyRows.every((r) => r.lock === 'off'));
    assert.deepEqual(OS.knownRows(null, sync, on(), t), []);
  });

  it('"Ordner sichern" cannot back up a folder that lies in the Drive', () => {
    assert.equal(OS.w2Lock('C:\\Users\\Max\\GateControl Drive\\Meine Dateien\\Dokumente', KNOWN), 'drive.od.known.lockedForW2');
    assert.equal(OS.w2Lock('C:\\Users\\Max\\GateControl Drive', KNOWN), 'drive.od.known.lockedForW2');
    assert.equal(OS.w2Lock('C:\\Users\\Max\\Desktop', KNOWN), null);
    assert.equal(OS.w2Lock('C:\\Users\\Max\\Desktop', null), null);
    assert.ok(OS.overlaps('C:\\A\\B', 'c:/a'));
    assert.ok(!OS.overlaps('C:\\AB', 'C:\\A'));
  });
});

describe('errors', () => {
  it('texts, unsynced with its paths', () => {
    assert.equal(OS.errorText({ code: 'relocated' }, t), 'drive.od.err.relocated');
    assert.equal(OS.errorText({ code: 'unsynced', data: { count: 3 } }, t), 'drive.od.err.unsynced.other(count=3)');
    assert.equal(OS.errorText({ code: 'network' }, t), 'drive.od.err.offline');
    assert.equal(OS.errorText({ code: 'boom' }, t), 'drive.od.err.generic(code=boom)');
    assert.deepEqual(OS.unsyncedList({ data: { paths: ['a', 'b', 'c'] } }, 2), ['a', 'b']);
    assert.deepEqual(OS.unsyncedList({}), []);
  });
});

describe('the page', () => {
  const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

  it('loads the scripts in order', () => {
    const html = read('src', 'renderer', 'index.html');
    const a = html.indexOf('src="drive-ondemand-state.js"');
    const b = html.indexOf('src="drive-ondemand-view.js"');
    const c = html.indexOf('src="drive-sync-view.js"');
    assert.ok(a > 0 && b > a && c > b);
  });

  it('never uses innerHTML / insertAdjacentHTML / eval', () => {
    for (const f of ['drive-ondemand-view.js', 'drive-ondemand-state.js']) {
      assert.doesNotMatch(read('src', 'renderer', f), /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/, f);
    }
  });

  it('every drive.od.* key exists in de and en (also those built at runtime)', () => {
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const src = ['drive-ondemand-view.js', 'drive-ondemand-state.js', 'drive-view.js', 'drive-sync-view.js'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set();
    for (const m of src.matchAll(/['"`](drive\.od\.[A-Za-z0-9_.]+)['"`]/g)) if (!m[1].endsWith('.')) keys.add(m[1]);
    const errs = ['relocated', 'not_running', 'w2_active', 'already_relocated', 'not_relocated', 'move_failed', 'set_failed', 'hydrate_failed', 'revert_failed',
      'target_taken', 'folder_missing', 'read_only', 'no_area', 'offline', 'busy', 'disabled', 'unsupported', 'known_folder', 'contains_root', 'timeout', 'not_synced', 'launch', 'wrong_user', 'generic'];
    for (const e of errs) keys.add(`drive.od.err.${e}`);
    for (const r of ['network', 'timeout', 'forbidden', 'quota', 'read_only', 'outside_area', 'name_unsupported', 'empty_file', 'mass_delete', 'local_io', 'hydrate', 'dehydrate',
      'register_failed', 'connect_failed', 'watch_failed', 'exited', 'launch', 'wrong_user', 'unauthorized', 'http', 'generic']) keys.add(`drive.od.reason.${r}`);
    for (const p of ['drive.od.pending', 'drive.od.state.loading', 'drive.od.err.unsynced']) { keys.delete(p); keys.add(`${p}.one`); keys.add(`${p}.other`); }
    keys.add('drive.sync.err.in_drive');
    assert.ok(keys.size > 90, `only ${keys.size} keys found`);
    for (const k of keys) {
      assert.ok(k in de, `de: ${k}`);
      assert.ok(k in en, `en: ${k}`);
    }
  });
});
