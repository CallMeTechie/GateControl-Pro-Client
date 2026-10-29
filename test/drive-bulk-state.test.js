'use strict';

// Drive 1.12 on the page "Drive" (no DOM, drive-bulk-state.js): the selection like in the Explorer (click, Strg,
// Umschalt, the head's tri-state, pruned after a reload), what a selection can do and why not (read only, vault,
// "Braucht Drive 1.12", a link with folders), the keys (never while typing), Strg+V, dragging onto a folder, "Ziel
// wählen" (not into itself, not where it is, only the same vault), the folders used last, the question for names there
// already, a job's progress and the note after it, "neu hier", "Alle / Keine" of a month in "Fotos"; that the page loads
// the new scripts in order, never uses innerHTML there, and every drive.bulk.* key exists in de and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const BS = require('../src/renderer/drive-bulk-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const me = (...features) => ({ features });

const F = (id, o = {}) => ({ id, name: `f${id}.pdf`, isDir: false, size: 1000, parentId: 10, ...o });
const D = (id, o = {}) => ({ id, name: `D${id}`, isDir: true, size: 0, parentId: 10, ...o });

describe('the selection', () => {
  const ids = [1, 2, 3, 4, 5];
  it('click: only this one; Strg: one more / out; Umschalt: the range from the anchor; Strg+Umschalt adds it', () => {
    let r = BS.click(new Set(), ids, 2);
    assert.deepEqual([...r.sel], [2]);
    assert.equal(r.anchor, 2);
    r = BS.click(r.sel, ids, 4, { ctrl: true, anchor: r.anchor });
    assert.deepEqual([...r.sel].sort(), [2, 4]);
    r = BS.click(r.sel, ids, 4, { ctrl: true, anchor: r.anchor });
    assert.deepEqual([...r.sel], [2]);
    r = BS.click(new Set([2]), ids, 5, { shift: true, anchor: 2 });
    assert.deepEqual([...r.sel].sort(), [2, 3, 4, 5]);
    assert.equal(r.anchor, 2, 'the anchor stays');
    r = BS.click(new Set([5]), ids, 1, { shift: true, anchor: 2 });
    assert.deepEqual([...r.sel].sort(), [1, 2]);
    r = BS.click(new Set([5]), ids, 1, { shift: true, ctrl: true, anchor: 2 });
    assert.deepEqual([...r.sel].sort(), [1, 2, 5]);
    // an anchor no longer shown: a plain click
    assert.deepEqual([...BS.click(new Set([1]), ids, 3, { shift: true, anchor: 99 }).sel], [3]);
  });

  it('the head\'s tri-state, toggle, prune', () => {
    assert.equal(BS.headState(new Set(), ids), 'none');
    assert.equal(BS.headState(new Set([1, 3]), ids), 'some');
    assert.equal(BS.headState(new Set(ids), ids), 'all');
    assert.equal(BS.headState(new Set([9]), ids), 'none');
    assert.deepEqual([...BS.toggle(new Set([1]), 2)].sort(), [1, 2]);
    assert.deepEqual([...BS.prune(new Set([1, 9]), ids)], [1]);
  });

  it('summary: "3 ausgewählt" · "2 Dateien, 1 Ordner"', () => {
    const s = BS.summary([F(1), F(2, { size: 2048 }), D(3)], t, 'de');
    assert.equal(s.title, 'drive.bulk.selected(count=3)');
    assert.equal(s.detail, 'drive.bulk.files.other(count=2), drive.bulk.folders.one(count=1)');
    assert.equal(s.size, '3 KB');
  });
});

describe('what a selection can do', () => {
  it('with Drive 1.12 everything; one link for files only', () => {
    const a = BS.actions([F(1), F(2)], { me: me('bulk', 'zip', 'multiLink', 'copyServer'), writable: true });
    for (const k of ['zip', 'move', 'copy', 'link', 'trash', 'cut', 'copyClip']) assert.equal(a[k].on, true, k);
    assert.equal(a.rename.on, false);
    assert.equal(a.rename.why, 'drive.bulk.why.one');
    assert.equal(a.undo, true);
    const mixed = BS.actions([F(1), D(2)], { me: me('bulk', 'zip', 'multiLink', 'copyServer'), writable: true });
    assert.deepEqual(mixed.link, { on: false, why: 'drive.bulk.why.mixed' });
    assert.deepEqual(mixed.zip, { on: false, why: 'drive.bulk.why.zipLimit' }, 'a ZIP: one folder or files');
    assert.equal(BS.actions([D(2)], { me: me('bulk', 'zip') }).zip.on, true);
    const many = Array.from({ length: 21 }, (_, i) => F(i + 1));
    assert.equal(BS.actions(many, { me: me('bulk', 'zip', 'multiLink') }).zip.why, 'drive.bulk.why.zipLimit');
    assert.equal(BS.actions(many, { me: me('bulk', 'zip', 'multiLink') }).link.why, 'drive.bulk.why.linkLimit');
    // 'zipMixed': mixed selections and large amounts
    const z = BS.actions([...many, D(99)], { me: me('bulk', 'zip', 'multiLink', 'zipMixed') });
    assert.equal(z.zip.on, true);
    assert.equal(z.link.on, true);
    // one folder: its own link as before
    assert.equal(BS.actions([D(2)], { me: me(), writable: true }).link.on, true);
  });

  it('copying needs GateControl\'s media copy; ZIP / links without GateControl\'s links: switched off', () => {
    const a = BS.actions([F(1), F(2)], { me: me('bulk'), writable: true });
    assert.deepEqual(a.copy, { on: false, why: 'drive.bulk.why.needsGc' });
    assert.deepEqual(a.zip, { on: false, why: 'drive.bulk.why.linksOff' });
    assert.deepEqual(a.link, { on: false, why: 'drive.bulk.why.linksOff' });
    assert.equal(BS.pasteState({ mode: 'copy', items: [F(1)] }, { node: { id: 20 }, writable: true }, me('bulk')).why, 'drive.bulk.why.needsGc');
  });

  it('an older Drive: move and trash (a loop here), no copy / ZIP / link for several, no undo', () => {
    const a = BS.actions([F(1), F(2)], { me: me(), writable: true });
    assert.equal(a.move.on, true);
    assert.equal(a.trash.on, true);
    assert.deepEqual(a.copy, { on: false, why: 'drive.bulk.why.needs112' });
    assert.deepEqual(a.zip, { on: false, why: 'drive.bulk.why.needs112' });
    assert.deepEqual(a.link, { on: false, why: 'drive.bulk.why.needs112' });
    assert.equal(a.undo, false);
  });

  it('read only (a child\'s folder of the parents): ZIP and copy yes, the rest greyed with the reason', () => {
    const a = BS.actions([F(1)], { me: me('bulk', 'zip', 'multiLink', 'copyServer'), writable: false });
    assert.equal(a.zip.on, true);
    assert.equal(a.copy.on, true);
    for (const k of ['move', 'trash', 'rename', 'link', 'cut']) assert.deepEqual(a[k], { on: false, why: 'drive.bulk.why.readOnly' }, k);
  });

  it('in a vault folder: move, rename, trash — never ZIP, copy or links', () => {
    const a = BS.actions([F(1, { encrypted: true }), F(2, { encrypted: true })], { me: me('bulk', 'zip', 'multiLink'), writable: true, vault: true });
    assert.equal(a.move.on, true);
    assert.equal(a.trash.on, true);
    for (const k of ['zip', 'copy', 'link', 'copyClip']) assert.equal(a[k].why, 'drive.bulk.why.vault', k);
    assert.equal(BS.actions([F(1, { encrypted: true, locked: true })], { me: me('bulk'), writable: true, vault: true }).move.why, 'drive.bulk.why.locked');
  });

  it('Strg+V: what is in the clipboard and where it may go', () => {
    const folder = (id, o = {}) => ({ node: { id, encrypted: false, ...o }, writable: true });
    assert.equal(BS.pasteState(null, folder(20), me('bulk')).why, 'drive.bulk.clip.nothing');
    const cut = { mode: 'cut', items: [F(1), F(2)], vault: null };
    assert.deepEqual(BS.pasteState(cut, folder(20), me()), { on: true, why: null, op: 'move', count: 2 });
    assert.equal(BS.pasteState(cut, folder(10), me()).why, 'drive.bulk.why.here');
    assert.equal(BS.pasteState({ ...cut, mode: 'copy' }, folder(20), me()).why, 'drive.bulk.why.needs112');
    assert.equal(BS.pasteState({ ...cut, mode: 'copy' }, folder(10), me('bulk', 'copyServer')).on, true, 'a copy into the same folder: "Beide behalten"');
    assert.equal(BS.pasteState(cut, { ...folder(20), writable: false }, me()).why, 'drive.bulk.why.readOnly');
    assert.equal(BS.pasteState(cut, folder(20, { encrypted: true, vaultId: 'v' }), me()).why, 'drive.bulk.why.vault');
  });
});

describe('keys', () => {
  it('Strg+A / X / C / V, Esc, Entf, F2 — never while typing', () => {
    const k = (key, o = {}) => BS.keyAction({ key, ...o });
    assert.equal(k('a', { ctrlKey: true }), 'all');
    assert.equal(k('A', { ctrlKey: true, shiftKey: true }), 'all');
    assert.equal(k('x', { ctrlKey: true }), 'cut');
    assert.equal(k('c', { metaKey: true }), 'copy');
    assert.equal(k('v', { ctrlKey: true }), 'paste');
    assert.equal(k('Escape'), 'clear');
    assert.equal(k('Delete'), 'trash');
    assert.equal(k('F2'), 'rename');
    assert.equal(k('Delete', { altKey: true }), null);
    assert.equal(k('z', { ctrlKey: true }), null);
    assert.equal(k('a'), null);
    assert.equal(BS.keyAction({ key: 'a', ctrlKey: true }, { target: { tag: 'input' } }), null);
    assert.equal(BS.keyAction({ key: 'Delete' }, { target: { editable: true } }), null);
  });
});

describe('dragging onto a folder', () => {
  const drag = { items: [F(1), D(2)] };
  it('not into one of them, not below a dragged folder, not where they all are (a move)', () => {
    assert.equal(BS.canDrop(drag, 30), true);
    assert.equal(BS.canDrop(drag, 2), false);
    assert.equal(BS.canDrop(drag, 31, { crumbs: [1, 2, 30] }), false);
    assert.equal(BS.canDrop(drag, 10), false);
    assert.equal(BS.canDrop(drag, 10, { copy: true }), true);
    assert.equal(BS.canDrop(null, 30), false);
    assert.equal(BS.dropText(3, false, t), 'drive.bulk.drop.move.other(count=3)');
    assert.equal(BS.dropText(1, true, t), 'drive.bulk.drop.copy.one(count=1)');
  });
});

describe('"Ziel wählen"', () => {
  const items = [F(1), D(2)];
  const folder = (id, o = {}) => ({ node: { id, parentId: 1, encrypted: false, ...o.node }, crumbs: o.crumbs || [{ id: 1 }], writable: o.writable !== false });
  it('a selected folder and what lies in it are greyed; the target must take them', () => {
    assert.deepEqual(BS.targetRow(D(2), items), { disabled: true, sub: 'drive.bulk.target.itself' });
    assert.deepEqual(BS.targetRow(D(5), items, { crumbIds: [1, 2] }), { disabled: true, sub: 'drive.bulk.target.itself' });
    assert.equal(BS.targetRow(D(5), items, { mode: 'copy', crumbIds: [2] }).sub, 'drive.bulk.target.itselfCopy');
    assert.deepEqual(BS.targetRow(D(5), items, { crumbIds: [1] }), { disabled: false, sub: null });
    assert.deepEqual(BS.targetOk(folder(30), items), { ok: true, why: null });
    assert.equal(BS.targetOk(folder(30, { writable: false }), items).why, 'drive.bulk.target.readOnly');
    assert.equal(BS.targetOk(folder(10), items).why, 'drive.bulk.why.here');
    assert.equal(BS.targetOk(folder(10), items, { mode: 'copy' }).ok, true);
    assert.equal(BS.targetOk(folder(40, { crumbs: [{ id: 1 }, { id: 2 }] }), items).why, 'drive.bulk.target.itself');
    // vaults: only the same one
    assert.equal(BS.targetOk(folder(30, { node: { encrypted: true, vaultId: 'v1' } }), items).why, 'drive.bulk.why.vault');
    assert.equal(BS.targetOk(folder(30, { node: { encrypted: true, vaultId: 'v1' } }), items, { vault: 'v1' }).ok, true);
    assert.equal(BS.targetOk(folder(30), items, { vault: 'v1' }).why, 'drive.bulk.why.vault');
  });

  it('the folders used last (kept on this PC, newest first, at most 5)', () => {
    let raw = '[]';
    for (let i = 1; i <= 7; i++) raw = BS.pushRecent(BS.parseRecent(raw), i, `Meine Dateien › A › F${i}`);
    raw = BS.pushRecent(BS.parseRecent(raw), 5, 'Meine Dateien › A › F5');
    assert.deepEqual(BS.parseRecent(raw).map((x) => x.id), [5, 7, 6, 4, 3]);
    assert.deepEqual(BS.parseRecent('{bad'), []);
    assert.deepEqual(BS.parseRecent('[{"id":-1,"path":"x"},{"id":2}]'), []);
    assert.equal(BS.shortPath('Meine Dateien › Steuern › 2025'), 'Steuern › 2025');
  });
});

describe('names the target has already', () => {
  const check = {
    conflicts: [
      { id: 1, name: 'Rechnung Handwerker.pdf', size: 380 * 1024, mtime: 1761000000000, existing: { id: 9, size: 412 * 1024, mtime: 1759500000000 }, same: false },
      { id: 2, name: 'Scan_2026-10-12.pdf', size: 1200000, existing: { id: 8, size: 1200000, mtime: 1760000000000 }, same: true },
      { id: 3, name: 'Versicherungen', isDir: true, existing: { id: 7, isDir: true } },
    ],
  };
  it('one question for all: the list, "gleicher Inhalt", merged folders, the example of "Beide behalten"', () => {
    const v = BS.conflictView(check, { t, locale: 'de', mode: 'move', target: 'Rechnungen', when: () => '03.10.2026' });
    assert.equal(v.title, 'drive.bulk.conflict.title.other(count=3)');
    assert.equal(v.intro, 'drive.bulk.conflict.intro(folder=Rechnungen)');
    assert.equal(v.rows[0].text, 'drive.bulk.conflict.there(what=412 KB, 03.10.2026) · drive.bulk.conflict.new(what=380 KB, 03.10.2026)');
    assert.match(v.rows[1].text, /new\(what=drive\.bulk\.conflict\.same\)/);
    assert.equal(v.rows[2].text, 'drive.bulk.conflict.merge');
    assert.deepEqual(v.sameNames, ['Scan_2026-10-12.pdf']);
    assert.equal(v.renameExample, '… (2).pdf');
    assert.equal(v.ask, true);
    assert.equal(v.skipText, 'drive.bulk.conflict.skipSub.other(count=2)');
    assert.equal(BS.conflictView({ conflicts: [check.conflicts[1]] }, { t }).ask, false, 'only the same content: nothing to ask');
    const many = { conflicts: Array.from({ length: 12 }, (_, i) => ({ id: i + 1, name: `n${i}.txt`, existing: {}, same: false })) };
    assert.equal(BS.conflictView(many, { t }).more, 'drive.bulk.conflict.more(count=4)');
  });

  it('what cannot go, grouped by reason', () => {
    assert.equal(BS.blockedText([], t), '');
    assert.equal(BS.blockedText([{ id: 1, reason: 'same_folder' }, { id: 2, reason: 'same_folder' }, { id: 3, reason: 'odd' }], t), 'drive.bulk.blocked.other(why=drive.bulk.reason.same_folder, drive.bulk.reason.failed,count=3)');
  });
});

describe('a job and the note after it', () => {
  const base = { opId: 'op1', kind: 'copy', name: 'Urlaub 2026', count: 1, targetName: 'Meine Dateien › Familie', state: 'running', total: 128, done: 58, bytesTotal: 3.1 * 1024 ** 3, bytesDone: 1.4 * 1024 ** 3 };
  it('running: the title, files and bytes, "Abbrechen", the note of the server', () => {
    const v = BS.opView(base, { t, locale: 'de' });
    assert.equal(v.title, 'drive.bulk.op.copyOne(name=Urlaub 2026,target=Familie)');
    assert.equal(v.text, 'drive.bulk.op.files(done=58,total=128) · drive.bulk.op.bytes(done=1,4 GB,total=3,1 GB)');
    assert.equal(v.pct, 45);
    assert.equal(v.cancel, true);
    assert.equal(v.server, true);
    assert.equal(BS.opView({ ...base, local: true }, { t }).server, false, 'a loop here ends with the app');
    assert.equal(BS.opTitle({ kind: 'move', count: 3, targetName: 'Rechnungen' }, t), 'drive.bulk.op.move.other(target=Rechnungen,count=3)');
    assert.equal(BS.opTitle({ kind: 'trash', count: 1, name: 'a.pdf' }, t), 'drive.bulk.op.trashOne(name=a.pdf,target=…)');
    assert.equal(BS.opTitle({ kind: 'move', undo: true }, t), 'drive.bulk.op.undo');
  });

  it('ended: done with what was skipped / failed, "Rückgängig" until undoUntil; cancelled; failed', () => {
    const now = 1000;
    const done = { ...base, state: 'done', results: { done: 1, skipped: 2, failed: [{ id: 4, reason: 'forbidden' }] }, undoable: true, undoUntil: 5000 };
    const v = BS.opView(done, { t, now });
    assert.equal(v.text, 'drive.bulk.op.done · drive.bulk.op.skipped(count=2) · drive.bulk.op.failedSome(count=1)');
    assert.equal(v.cls, 'is-warn');
    assert.equal(v.undo, true);
    assert.equal(BS.opView(done, { t, now: 6000 }).undo, false);
    assert.equal(BS.opView({ ...done, undone: true }, { t, now }).undo, false);
    assert.equal(BS.opView({ ...base, state: 'cancelled' }, { t }).text, 'drive.bulk.op.cancelled');
    assert.equal(BS.opView({ ...base, state: 'failed', code: 'quota' }, { t, errorText: (r) => `err:${r.code}` }).text, 'drive.bulk.op.failed(reason=err:quota)');
  });

  it('the note: "3 Elemente nach „Rechnungen“ verschoben · Rückgängig"; trash; undone; a failed job has none', () => {
    const now = 1000;
    const s = BS.snackView({ kind: 'move', state: 'done', count: 3, targetName: 'Meine Dateien › Rechnungen', undoable: true, undoUntil: 900000, results: { done: 3, skipped: 0, failed: [] } }, { t, now });
    assert.deepEqual(s, { text: 'drive.bulk.snack.move.other(target=Rechnungen,count=3)', undo: true, warn: false });
    assert.equal(BS.snackView({ kind: 'trash', state: 'done', count: 2 }, { t, now }).text, 'drive.bulk.snack.trash.other(count=2)');
    assert.equal(BS.snackView({ kind: 'trash', state: 'done', count: 2, undo: true, undoable: true, undoUntil: 9e9 }, { t, now }).undo, false);
    assert.equal(BS.snackView({ kind: 'move', state: 'failed' }, { t }), null);
    assert.equal(BS.snackView({ kind: 'move', state: 'running' }, { t }), null);
    assert.equal(BS.snackMs({ undoUntil: now + 900000 }, now), 12000);
    assert.equal(BS.snackMs({ undoUntil: now + 1000 }, now), 6000);
  });

  it('"neu hier": moved ones by id, copies by name, only in the target and for a while', () => {
    const now = 1000;
    const mv = BS.freshOf({ ids: [1, 2], names: ['a.pdf', 'B.pdf'], targetId: 30 }, { kind: 'move', state: 'done' }, now);
    assert.equal(BS.isFresh(mv, { id: 1, name: 'x' }, 30, now), true);
    assert.equal(BS.isFresh(mv, { id: 1, name: 'x' }, 31, now), false);
    assert.equal(BS.isFresh(mv, { id: 1, name: 'x' }, 30, now + BS.NEW_HERE_MS + 1), false);
    // Drive 1.12 names the new nodes
    const made = BS.freshOf({ ids: [1], names: ['a.pdf'], targetId: 30 }, { kind: 'copy', state: 'done', results: { resultIds: [501] } }, now);
    assert.equal(BS.isFresh(made, { id: 501, name: 'a (2).pdf' }, 30, now), true);
    const cp = BS.freshOf({ ids: [1, 2], names: ['a.pdf', 'B.pdf'], targetId: 30 }, { kind: 'copy', state: 'done' }, now);
    assert.equal(BS.isFresh(cp, { id: 77, name: 'b.pdf' }, 30, now), true);
    assert.equal(BS.isFresh(cp, { id: 1, name: 'other' }, 30, now), false);
    assert.equal(BS.freshOf({ ids: [1], targetId: 30 }, { kind: 'trash', state: 'done' }, now), null);
    assert.equal(BS.freshOf({ ids: [1], targetId: 30 }, { kind: 'move', state: 'done', undo: true }, now), null);
  });
});

describe('"Fotos": Alle / Keine of a month', () => {
  it('the month\'s state and selecting it', () => {
    const month = [{ id: 1 }, { id: 2 }];
    assert.equal(BS.monthState(new Set([1]), month), 'some');
    const all = BS.selectMonth(new Set([9]), month, true);
    assert.deepEqual([...all].sort(), [1, 2, 9]);
    assert.equal(BS.monthState(all, month), 'all');
    assert.deepEqual([...BS.selectMonth(all, month, false)], [9]);
  });
});

describe('page wiring', () => {
  it('index.html loads the state and the view before drive-view.js', () => {
    const html = read('src', 'renderer', 'index.html');
    const a = html.indexOf('src="drive-bulk-state.js"');
    const b = html.indexOf('src="drive-bulk-view.js"');
    const c = html.indexOf('src="drive-view.js"');
    assert.ok(a > 0 && b > a && c > b);
    // "Fotos" uses the state too
    assert.ok(a < html.indexOf('src="drive-photos-view.js"'));
  });

  it('the new views never use innerHTML / insertAdjacentHTML / eval', () => {
    for (const f of ['drive-bulk-view.js', 'drive-bulk-state.js', 'drive-photos-view.js']) {
      const src = read('src', 'renderer', f);
      assert.doesNotMatch(src, /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/, f);
    }
  });

  it('every drive.bulk.* key used exists in de and en (plurals with one / other)', () => {
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const src = ['drive-view.js', 'drive-bulk-view.js', 'drive-bulk-state.js', 'drive-photos-view.js'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set();
    for (const m of src.matchAll(/['"`](drive\.bulk\.[A-Za-z0-9_.]+)['"`]/g)) if (!m[1].endsWith('.')) keys.add(m[1]);
    // built at runtime
    for (const k of ['move', 'copy', 'trash', 'restore', 'purge']) { keys.add(`drive.bulk.op.${k}One`); keys.add(`drive.bulk.op.${k}`); }
    for (const r of [...BS.REASONS, 'failed']) keys.add(`drive.bulk.reason.${r}`);
    for (const m of ['move', 'copy']) keys.add(`drive.bulk.target.${m}`);
    keys.add('drive.bulk.drop.move');
    keys.add('drive.bulk.drop.copy');
    const plurals = new Set(['drive.bulk.files', 'drive.bulk.folders', 'drive.bulk.drop.move', 'drive.bulk.drop.copy', 'drive.bulk.clip.cut', 'drive.bulk.clip.copied',
      'drive.bulk.menuTitle', 'drive.bulk.menuLabel', 'drive.bulk.linkTitle', 'drive.bulk.trashConfirm', 'drive.bulk.target.from', 'drive.bulk.target.count',
      'drive.bulk.conflict.title', 'drive.bulk.conflict.merges', 'drive.bulk.conflict.skipSub', 'drive.bulk.conflict.skipSubCopy', 'drive.bulk.blocked', 'drive.bulk.snack.move', 'drive.bulk.snack.copy',
      'drive.bulk.snack.trash', 'drive.bulk.snack.restore', 'drive.bulk.op.move', 'drive.bulk.op.copy', 'drive.bulk.op.trash', 'drive.bulk.op.restore', 'drive.bulk.op.purge']);
    for (const p of plurals) { keys.delete(p); keys.add(`${p}.one`); keys.add(`${p}.other`); }
    assert.ok(keys.size > 90, `only ${keys.size} keys found`);
    for (const k of keys) {
      assert.ok(k in de, `de: ${k}`);
      assert.ok(k in en, `en: ${k}`);
    }
    for (const k of ['tooMany', 'tooManyJobs', 'intoItself']) assert.ok(`drive.err.${k}` in de && `drive.err.${k}` in en, k);
  });
});
