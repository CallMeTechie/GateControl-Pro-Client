'use strict';

// Mail 1.13 "Mehrfachauswahl + Wischaktionen": the pure helpers of the selection (src/renderer/mail-bulk-state.js —
// Strg / Umschalt clicks, Strg+A, "Alle N auswählen", what the selection is, the bar, the questions before deleting,
// the note with "Rückgängig", the folder picker, dragging onto a folder, the quick actions) and the page's wiring.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const MB = require('../src/renderer/mail-bulk-state');
const MS = require('../src/renderer/mail-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, params) => (params ? `${key}(${Object.entries(params).map(([k, v]) => `${k}=${v}`).join(',')})` : key);

const folders = { accounts: [
  { accountId: 1, folders: [{ id: 11, accountId: 1, name: 'Posteingang', role: 'inbox', path: 'INBOX' }, { id: 13, accountId: 1, name: 'Papierkorb', role: 'trash', path: 'Trash' }, { id: 15, accountId: 1, name: 'Rechnungen', role: null, path: 'Archive/Rechnungen' }, { id: 16, accountId: 1, name: '2026', role: null, path: 'Archive/Rechnungen/2026' }] },
  { accountId: 2, folders: [{ id: 21, accountId: 2, name: 'Inbox', role: 'inbox', path: 'INBOX' }] },
] };
const me = (features = [], settings = {}) => ({ features: ['mail', ...features], accounts: [{ id: 1 }, { id: 2 }], settings: { threads: true, swipeLeft: 'archive', swipeRight: 'read', confirmDelete: false, ...settings } });
const items = [
  { id: 1, accountId: 1, folderId: 11, unread: true, flagged: false, tab: 'relevant' },
  { id: 2, accountId: 1, folderId: 11, unread: false, flagged: true, tab: 'relevant' },
  { id: 3, accountId: 2, folderId: 21, unread: false, flagged: false, tab: 'other' },
  { id: 4, accountId: 1, folderId: 13, unread: false, flagged: false, tab: 'relevant' },
];
const ids = items.map((m) => m.id);

describe('mail-bulk-state', () => {
  it('clicks: plain opens, Strg ticks (the open mail with it), Umschalt a range', () => {
    assert.equal(MB.click(null, ids, 2, {}), null, 'a plain click opens the mail');
    const a = MB.click(null, ids, 3, { ctrl: true, current: 1 });
    assert.deepEqual([...a.ids], [1, 3]);
    const b = MB.click(a, ids, 1, { ctrl: true });
    assert.deepEqual([...b.ids], [3]);
    const c = MB.click({ ids: new Set([1]), anchor: 1 }, ids, 3, { shift: true });
    assert.deepEqual([...c.ids], [1, 2, 3]);
    // Umschalt without a selection: from the open mail
    assert.deepEqual([...MB.click(null, ids, 4, { shift: true, current: 2 }).ids], [2, 3, 4]);
    // Strg+Umschalt adds the range
    assert.deepEqual([...MB.click({ ids: new Set([4]), anchor: 1 }, ids, 2, { shift: true, ctrl: true }).ids].sort(), [1, 2, 4]);
    assert.deepEqual([...MB.toggle(null, 2, { current: 1, ids }).ids], [1, 2]);
    assert.deepEqual([...MB.selectLoaded(items).ids], [1, 2, 3, 4]);
  });

  it('"Alle N auswählen", prune, without, extend', () => {
    const all = MB.selectAll({ ids: [9, 2, 1, 8], total: 4000, truncated: true }, items);
    assert.deepEqual([...all.ids], [1, 2, 9, 8]);
    assert.deepEqual(all.all, { total: 4000, truncated: true });
    assert.equal(MB.prune(all, []), all, 'a selection from "Alle" keeps its ids');
    assert.deepEqual([...MB.prune({ ids: new Set([1, 7]), anchor: 7 }, items).ids], [1]);
    assert.equal(MB.prune({ ids: new Set([7]), anchor: 7 }, items), null);
    assert.equal(MB.without({ ids: new Set([1]), anchor: 1 }, [1]), null);
    assert.deepEqual([...MB.without({ ids: new Set([1, 2]), anchor: 1 }, [1]).ids], [2]);
    const e1 = MB.extend(null, ids, 'down', { current: 1 });
    assert.deepEqual([[...e1.ids], e1.focus], [[1, 2], 2]);
    const e2 = MB.extend(e1, ids, 'down', { focus: e1.focus });
    assert.deepEqual([...e2.ids], [1, 2, 3]);
    assert.deepEqual([...MB.extend(e2, ids, 'up', { focus: 3 }).ids], [1, 2]);
  });

  it('facts: one account or several, the trash, unread; mails not loaded belong to the list', () => {
    const f = MB.facts(new Set([1, 2]), items, { view: { kind: 'box', box: 'all' }, folders, me: me() });
    assert.deepEqual([f.count, f.accountId, f.mixed, f.inTrash, f.anyUnread, f.anyUnflagged], [2, 1, false, false, true, true]);
    const g = MB.facts([1, 3], items, { folders, me: me() });
    assert.deepEqual([g.mixed, g.accountId], [true, null]);
    const h = MB.facts([2, 4], items, { folders, me: me() });
    assert.deepEqual([h.inTrash, h.allTrash, h.anyUnread], [true, false, false]);
    // "Alle" in the trash of account 1: the ids not loaded are in the trash too
    const k = MB.facts([4, 99, 98], items, { view: { kind: 'box', box: 1, folderId: 13 }, folders, me: me() });
    assert.deepEqual([k.unknown, k.accountId, k.allTrash, k.anyUnread], [2, 1, true, true]);
    // "Alle" of all inboxes: any account → moving is not possible
    assert.equal(MB.facts([1, 99], items, { view: { kind: 'box', box: 'all' }, folders, me: me() }).mixed, true);
  });

  it('the bar: copy only with the feature, moving in one account, read / flag by what is ticked, the tab in inboxes', () => {
    const f = MB.facts([1, 2], items, { folders, me: me() });
    assert.deepEqual(MB.barActions(f, { me: me() }).map((a) => a.id), ['archive', 'delete', 'move', 'read', 'flag', 'junk']);
    assert.deepEqual(MB.barActions(f, { me: me(['copy']), inbox: true }).map((a) => a.id), ['archive', 'delete', 'move', 'copy', 'read', 'flag', 'junk', 'toOther']);
    assert.equal(MB.barActions(f, { me: me(), inbox: true, tab: 'other' }).at(-1).id, 'toRelevant');
    const read = MB.facts([2], items, { folders, me: me() });
    assert.deepEqual(MB.barActions(read, { me: me() }).filter((a) => ['unread', 'unflag'].includes(a.id)).map((a) => a.id), ['unread', 'unflag']);
    const mixed = MB.barActions(MB.facts([1, 3], items, { folders, me: me(['copy']) }), { me: me(['copy']) });
    assert.deepEqual(mixed.filter((a) => a.disabled).map((a) => [a.id, a.why]), [['move', 'mail.bulk.oneAccount'], ['copy', 'mail.bulk.oneAccount']]);
    assert.equal(MB.barActions(MB.facts([4], items, { folders }), {})[1].label, 'mail.bulk.purge');
    assert.deepEqual(MB.barCall('unread'), { flags: { unread: true } });
    assert.deepEqual(MB.barCall('toOther'), { act: 'tab', tab: 'other' });
    assert.deepEqual(MB.barCall('copy'), { pick: 'copy' });
    assert.equal(MB.barCall('teleport'), null);
  });

  it('asking before deleting: always in the trash, else by "Vor dem Löschen fragen"', () => {
    assert.equal(MB.confirmKind({ inTrash: true }, { confirmDelete: false }), 'purge');
    assert.equal(MB.confirmKind({ inTrash: false }, { confirmDelete: true }), 'delete');
    assert.equal(MB.confirmKind({ inTrash: false }, { confirmDelete: false }), null);
    assert.equal(MB.confirmKind({}, null), null);
  });

  it('threads with the conversation view in a box; keys', () => {
    assert.equal(MB.threadsFor({ kind: 'box' }, me()), true);
    assert.equal(MB.threadsFor({ kind: 'search' }, me()), false);
    assert.equal(MB.threadsFor({ kind: 'box' }, me([], { threads: false })), false);
    assert.equal(MB.keyAction({ key: 'a', ctrlKey: true }), 'all');
    assert.equal(MB.keyAction({ key: 'A', metaKey: true }), 'all');
    assert.equal(MB.keyAction({ key: 'Escape' }), 'clear');
    assert.equal(MB.keyAction({ key: 'Delete' }), 'delete');
    assert.equal(MB.keyAction({ key: 'ArrowDown', shiftKey: true }), 'extendDown');
    assert.equal(MB.keyAction({ key: 'ArrowDown' }), null);
    assert.equal(MB.keyAction({ key: 'a', ctrlKey: true, altKey: true }), null);
  });

  it('the note: "12 Mails nach „2026“ verschoben", undo by token or the opposite call', () => {
    assert.deepEqual(MB.doneView('move', { count: 12, folder: '2026', undo: { tokens: ['a'] }, t }), { text: 'mail.bulk.done.move.other(folder=2026,count=12)', undo: true });
    assert.deepEqual(MB.doneView('archive', { count: 1, undo: null, t }), { text: 'mail.bulk.done.archive.one(folder=,count=1)', undo: false });
    assert.deepEqual(MB.doneView('delete', { count: 2, purged: 2, t }), { text: 'mail.bulk.done.purged.other(count=2)', undo: false });
    assert.equal(MB.doneView('delete', { count: 3, purged: 1, undo: { tokens: ['x'] }, t }).text, 'mail.bulk.done.delete.other(folder=,count=2) · mail.bulk.done.purged.one(count=1)');
    assert.equal(MB.doneView('read', { count: 2, back: [{ ids: [1], flags: { unread: true } }], t }).undo, true);
    assert.deepEqual(MB.flagsBack(items.slice(0, 2), { unread: false }, [1, 2]), [{ ids: [1], flags: { unread: true } }]);
    assert.deepEqual(MB.flagsBack(items.slice(0, 2), { flagged: true }, [1, 2]), [{ ids: [1], flags: { flagged: false } }]);
    assert.equal(MB.flagsBack(items.slice(0, 1), { unread: false }, [1, 99]), null, 'a mail not loaded: its old state is unknown');
    assert.deepEqual(MB.tabBack(items.slice(0, 3), 'other'), [{ ids: [1, 2], tab: 'relevant' }]);
  });

  it('the folder picker: "Zuletzt" per account, search, the main button', () => {
    let raw = MB.pushRecent([], 15, 1);
    raw = MB.pushRecent(MB.parseRecent(raw), 16, 1);
    raw = MB.pushRecent(MB.parseRecent(raw), 15, 1);
    assert.deepEqual(MB.parseRecent(raw), [{ id: 15, accountId: 1 }, { id: 16, accountId: 1 }]);
    assert.deepEqual(MB.parseRecent('{nope'), []);
    for (let i = 0; i < 8; i += 1) raw = MB.pushRecent(MB.parseRecent(raw), 100 + i, 1);
    assert.equal(MB.parseRecent(raw).filter((x) => x.accountId === 1).length, MB.RECENT_MAX);
    const recent = [{ id: 16, accountId: 1 }, { id: 11, accountId: 1 }, { id: 21, accountId: 2 }, { id: 77, accountId: 1 }];
    assert.deepEqual(MB.recentFolders(recent, folders, 1, { here: 11 }).map((f) => f.id), [16]);
    assert.deepEqual(MB.recentFolders(recent, folders, 1, { here: 11, mode: 'copy' }).map((f) => f.id), [16, 11]);
    assert.deepEqual(MB.searchFolders(folders.accounts[0].folders, 'rech 26').map((f) => f.id), [16]);
    assert.deepEqual(MB.searchFolders(folders.accounts[0].folders, '  '), []);
    assert.equal(MB.pickGo('copy', '2026', t), 'mail.bulk.pick.goCopy(folder=2026)');
    assert.equal(MB.pickGo('move', '', t), 'mail.bulk.pick.choose');
  });

  it('dragging onto a folder: one account, not where they are, copy with the feature', () => {
    const drag = { ids: [1, 2], accountId: 1, mixed: false, folderIds: [11] };
    assert.equal(MB.canDrop(drag, { id: 15, accountId: 1 }, {}), true);
    assert.equal(MB.canDrop(drag, { id: 11, accountId: 1 }, {}), false, 'where they are');
    assert.equal(MB.canDrop(drag, { id: 11, accountId: 1 }, { copy: true, me: me(['copy']) }), true, 'a copy may: a duplicate');
    assert.equal(MB.canDrop(drag, { id: 15, accountId: 1 }, { copy: true, me: me() }), false, 'no copy without the feature');
    assert.equal(MB.canDrop(drag, { id: 21, accountId: 2 }, {}), false, 'another account');
    assert.equal(MB.canDrop({ ...drag, mixed: true }, { id: 15, accountId: 1 }, {}), false);
    assert.equal(MB.dropText(3, true, t), 'mail.bulk.drop.copy.other(count=3)');
  });

  it('quick actions: seven with swipeV2, four without; a row shows them all', () => {
    assert.deepEqual(MB.swipeChoices(me(['swipeV2'])), ['archive', 'delete', 'read', 'flag', 'move', 'junk', 'none']);
    assert.deepEqual(MB.swipeChoices(me()), ['archive', 'delete', 'read', 'none']);
    assert.deepEqual(MS.rowActions({ swipeRight: 'move', swipeLeft: 'junk' }, {}).map((a) => [a.action, a.icon, a.key]), [['move', 'move', 'mail.act.move'], ['junk', 'junk', 'mail.act.junk']]);
    assert.deepEqual(MS.rowActions({ swipeRight: 'flag', swipeLeft: 'teleport' }, { flagged: true }).map((a) => [a.action, a.key]), [['flag', 'mail.act.unflag']]);
  });

  it('the page: the script before mail-view.js, every text in both languages', () => {
    const html = read('src', 'renderer', 'index.html');
    const at = (f) => html.indexOf(`<script src="${f}"></script>`);
    assert.ok(at('mail-state.js') > 0 && at('mail-bulk-state.js') > at('mail-state.js') && at('mail-bulk-state.js') < at('mail-view.js'));
    const view = read('src', 'renderer', 'mail-view.js');
    const de = JSON.parse(read('src', 'i18n', 'de.json')).mail;
    const en = JSON.parse(read('src', 'i18n', 'en.json')).mail;
    const get = (o, k) => k.split('.').reduce((x, p) => (x && typeof x === 'object' ? x[p] : undefined), o);
    const src = `${view}\n${read('src', 'renderer', 'mail-bulk-state.js')}`;
    const keys = new Set([...src.matchAll(/'mail\.(bulk\.[A-Za-z.]+|settings\.(?:quick|confirm)[A-Za-z]*|swipe\.[a-z]+)'/g)].map((m) => m[1]));
    assert.ok(keys.size > 30);
    for (const k of keys) {
      for (const [lang, d] of [['de', de], ['en', en]]) {
        const v = get(d, k);
        assert.ok(typeof v === 'string' || (v && typeof v.one === 'string' && typeof v.other === 'string') || (v && typeof v === 'object'), `${lang}: mail.${k}`);
      }
    }
    for (const a of MB.SWIPES_V2) assert.ok(de.swipe[a] && en.swipe[a], a);
    // no server text into innerHTML
    assert.ok(!/innerHTML\s*=/.test(view));
  });
});
