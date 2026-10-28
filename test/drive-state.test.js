'use strict';

// View logic of the page "Drive" and of "In Drive speichern" (src/renderer/drive-state.js,
// no DOM): file kinds, sizes and dates, names Drive takes, area labels / hints / storage,
// the page's access state (seat, licence), rows of folder / search / trash, breadcrumbs,
// sorting, the row menu, link options and texts, the transfer list, the folder picker
// (writable areas / folders only, the folder picked last) and the error texts of Drive's
// codes; GateDrop's target "Mein Drive" (gatedrop-state.js) and the Schule attachments;
// that the page loads the Drive scripts, never uses innerHTML, and that every drive.* key
// the views use exists in both app locales.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const DS = require('../src/renderer/drive-state');
const GS = require('../src/renderer/gatedrop-state');

const ROOT = path.join(__dirname, '..');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const at = (y, mo, d, h, m) => new Date(y, mo - 1, d, h, m).getTime();
const NOW = at(2026, 10, 27, 9, 30);

const area = (o = {}) => ({ id: 'mine:2', kind: 'mine', label: 'Meine Dateien', role: 'manage', via: 'owner', rootId: 1, archived: false, writable: true, storage: null, ...o });
const node = (o = {}) => ({ id: 12, areaId: 'mine:2', parentId: 10, name: 'Brief.pdf', isDir: false, size: 1536, mime: 'application/pdf', mediaId: 'docMedia00000001', rev: 1, mtime: at(2026, 10, 20, 8, 15), preview: false, ...o });

describe('files', () => {
  it('kinds by type and extension, badge', () => {
    assert.equal(DS.kindOf(node({ isDir: true })), 'folder');
    assert.equal(DS.kindOf(node({ mime: 'image/heic', name: 'IMG_1.HEIC' })), 'image');
    assert.equal(DS.kindOf(node({ mime: null, name: 'Film.MP4' })), 'video');
    assert.equal(DS.kindOf(node({ mime: 'audio/ogg', name: 'x' })), 'audio');
    assert.equal(DS.kindOf(node()), 'pdf');
    assert.equal(DS.kindOf(node({ mime: null, name: 'Plan.xlsx' })), 'sheet');
    assert.equal(DS.kindOf(node({ mime: null, name: 'Brief.docx' })), 'doc');
    assert.equal(DS.kindOf(node({ mime: 'application/zip', name: 'a' })), 'archive');
    assert.equal(DS.kindOf(node({ mime: null, name: 'README' })), 'other');
    assert.equal(DS.badgeOf(node({ name: 'Plan.xlsx' })), 'XLSX');
    assert.equal(DS.badgeOf(node({ isDir: true })), '');
  });

  it('sizes and dates', () => {
    assert.equal(DS.formatBytes(512, 'de'), '512 B');
    assert.equal(DS.formatBytes(1536, 'de'), '2 KB');
    assert.equal(DS.formatBytes(1.5 * 1024 * 1024, 'de'), '1,5 MB');
    assert.equal(DS.formatBytes(1.5 * 1024 * 1024, 'en'), '1.5 MB');
    assert.equal(DS.formatBytes(200 * 1024 ** 3, 'de'), '200 GB');
    assert.equal(DS.formatBytes(-1, 'de'), '');
    assert.equal(DS.when(at(2026, 10, 27, 8, 5), NOW, 'de', t), 'drive.time.today(time=08:05)');
    assert.equal(DS.when(at(2026, 10, 26, 18, 1), NOW, 'de', t), 'drive.time.yesterday(time=18:01)');
    assert.equal(DS.when(at(2026, 10, 20, 8, 15), NOW, 'de', t), '20.10.2026');
    assert.equal(DS.when(null, NOW, 'de', t), '');
    assert.equal(DS.plural(t, 'drive.trash.files', 1), 'drive.trash.files.one(count=1)');
    assert.equal(DS.plural(t, 'drive.upload.rejected', 3, { names: 'a' }), 'drive.upload.rejected.other(names=a,count=3)');
  });

  it('names Drive takes', () => {
    assert.equal(DS.validName('Urlaub 2026'), true);
    assert.equal(DS.validName('a/b'), false);
    assert.equal(DS.validName('Was?'), false);
    assert.equal(DS.validName('Ende.'), false);
    assert.equal(DS.validName('.gcdrive'), false);
    assert.equal(DS.validName('x'.repeat(256)), false);
    assert.equal(DS.nameError('', t), 'drive.name.empty');
    assert.equal(DS.nameError('a:b', t), 'drive.name.invalid');
    assert.equal(DS.nameError('Belege', t), null);
  });
});

describe('areas and access', () => {
  it('labels, hints, storage', () => {
    assert.equal(DS.areaLabel(area(), t), 'drive.area.mine');
    assert.equal(DS.areaLabel(area({ kind: 'child', label: 'Lena' }), t), 'drive.area.child(name=Lena)');
    assert.equal(DS.areaLabel(area({ kind: 'team', label: 'Büro' }), t), 'drive.area.team(name=Büro)');
    assert.equal(DS.areaLabel(area({ kind: 'family', label: 'Familie Muster' }), t), 'Familie Muster');
    assert.equal(DS.areaHint(area({ kind: 'child', via: 'parent', writable: false }), t), 'drive.area.childParentHint');
    assert.equal(DS.areaHint(area({ kind: 'team', writable: false }), t), 'drive.area.teamReadHint');
    assert.equal(DS.areaHint(area({ kind: 'team', archived: true }), t), 'drive.area.archived');
    assert.equal(DS.usage(area({ storage: { bytes: 2 * 1024 ** 3, quota: 50 * 1024 ** 3 } }), t, 'de'), 'drive.area.usageOf(used=2,0 GB,quota=50,0 GB)');
    assert.equal(DS.usage(area({ storage: { bytes: 1024, quota: 0 } }), t, 'de'), '1 KB');
    assert.equal(DS.usage(area(), t, 'de'), null);
  });

  it('the area shown: the chosen one while it exists, else Meine Dateien', () => {
    const list = DS.sortAreas([area({ id: 'team:1', kind: 'team', label: 'Büro' }), area({ id: 'family:1', kind: 'family', label: 'Familie' }), area()]);
    assert.deepEqual(list.map((a) => a.id), ['mine:2', 'family:1', 'team:1']);
    assert.equal(DS.currentArea(list, 'family:1').id, 'family:1');
    assert.equal(DS.currentArea(list, 'gone:9').id, 'mine:2');
    assert.equal(DS.currentArea([], 'x'), null);
  });

  it('access: licence and seat decide', () => {
    assert.deepEqual(DS.accessOf({ ok: true, licence: { valid: false }, me: { seat: 'family' }, areas: [] }), { usable: false, key: 'drive.access.notLicensed' });
    assert.deepEqual(DS.accessOf({ ok: true, licence: { valid: true }, me: { seat: null }, areas: [] }), { usable: false, key: 'drive.access.noSeat' });
    assert.deepEqual(DS.accessOf({ ok: true, licence: { valid: true }, me: { seat: 'business' }, areas: [] }), { usable: true, key: 'drive.access.noAreas' });
    assert.deepEqual(DS.accessOf({ ok: true, licence: { valid: true }, me: { seat: 'family' }, areas: [area()] }), { usable: true, key: null });
    assert.deepEqual(DS.accessOf({ ok: false, code: 'network' }), { usable: false, key: null });
  });
});

describe('rows, crumbs, menu', () => {
  it('folder, search (path and snippet) and trash rows', () => {
    const r = DS.rowView(node({ preview: true, mime: 'image/jpeg', name: 'Foto.jpg' }), { t, locale: 'de', now: NOW });
    assert.deepEqual(r, { id: 12, name: 'Foto.jpg', kind: 'image', badge: 'JPG', sub: '', snippet: '', date: '20.10.2026', size: '2 KB', isDir: false, preview: true, mediaId: 'docMedia00000001' });
    const dir = DS.rowView(node({ isDir: true, name: 'Belege', size: 0, mediaId: null }), { t, locale: 'de', now: NOW });
    assert.equal(dir.size, '');
    assert.equal(dir.preview, false);
    const s = DS.rowView(node({ path: 'Dokumente', match: 'text', snippet: '… die Miete …' }), { t, locale: 'de', now: NOW, mode: 'search' });
    assert.equal(s.sub, 'drive.search.in(path=Dokumente) · … die Miete …');
    assert.equal(s.snippet, '… die Miete …');
    const tr = DS.rowView(node({ isDir: true, from: 'Meine Dateien/Alt', files: 3, deletedAt: at(2026, 10, 27, 7, 0) }), { t, locale: 'de', now: NOW, mode: 'trash' });
    assert.equal(tr.sub, 'drive.trash.from(path=Meine Dateien/Alt) · drive.trash.files.other(count=3)');
    assert.equal(tr.date, 'drive.time.today(time=07:00)');
  });

  it('breadcrumbs name the top folder like its area', () => {
    const f = { crumbs: [{ id: 2, name: 'Familie Muster' }, { id: 20, name: 'Belege' }] };
    assert.deepEqual(DS.crumbs(f, area({ kind: 'family', label: 'Familie Muster' }), t), [{ id: 2, name: 'Familie Muster', current: false }, { id: 20, name: 'Belege', current: true }]);
    assert.equal(DS.crumbs({ crumbs: [{ id: 1, name: 'x' }] }, area(), t)[0].name, 'drive.area.mine');
    assert.deepEqual(DS.crumbs(null, null, t), []);
  });

  it('sorting and the row menu', () => {
    assert.deepEqual(DS.sortQuery('name'), { sort: 'name', order: 'asc' });
    assert.deepEqual(DS.sortQuery('size'), { sort: 'size', order: 'desc' });
    assert.deepEqual(DS.sortQuery('weird'), { sort: 'name', order: 'asc' });
    assert.deepEqual(DS.actionsFor(node(), true), { open: true, saveAs: true, share: true, rename: true, move: true, versions: true, remove: true, portal: false, timeTravel: false });
    assert.deepEqual(DS.actionsFor(node({ isDir: true }), false), { open: true, saveAs: false, share: false, rename: false, move: false, versions: false, remove: false, portal: false, timeTravel: false });
  });
});

describe('links', () => {
  it('modes, PIN and the request', () => {
    assert.deepEqual(DS.linkModes(node()), ['view', 'download']);
    assert.deepEqual(DS.linkModes(node({ isDir: true })), ['view', 'download', 'upload']);
    assert.equal(DS.pinOk(''), true);
    assert.equal(DS.pinOk('1234'), true);
    assert.equal(DS.pinOk('12a4'), false);
    assert.equal(DS.pinOk('123'), false);
    assert.deepEqual(DS.linkRequest(node(), { mode: 'download', expires: '7d', pin: ' 4711 ' }), { nodeId: 12, mode: 'download', expires: '7d', pin: '4711' });
    assert.deepEqual(DS.linkRequest(node(), { mode: 'view', expires: 'never', pin: '' }), { nodeId: 12, mode: 'view', expires: 'never' });
    assert.equal(DS.linkRequest(node(), { mode: 'upload', expires: '7d' }), null);
    assert.equal(DS.linkRequest(node(), { mode: 'view', expires: '1h' }), null);
    assert.equal(DS.linkRequest(node(), { mode: 'view', expires: '7d', pin: '12' }), null);
  });

  it('a link in the list', () => {
    const v = DS.linkView({ token: 'tok', url: 'https://gc/s/tok', name: 'Brief.pdf', mode: 'download', active: true, expiresAt: at(2026, 11, 3, 10, 0), pin: true, opens: 2, downloads: 1 }, { t, locale: 'de', now: NOW });
    assert.deepEqual(v, { token: 'tok', url: 'https://gc/s/tok', title: 'Brief.pdf', meta: 'drive.link.mode.download · drive.link.until(date=03.11.2026) · drive.link.withPin · drive.link.stats(opens=2,downloads=1)', active: true });
    assert.match(DS.linkView({ token: 'x', active: true, expiresAt: null }, { t, locale: 'de', now: NOW }).meta, /drive\.link\.endless/);
    assert.match(DS.linkView({ token: 'x', active: false, endedWhy: 'moved' }, { t, locale: 'de', now: NOW }).meta, /drive\.link\.endedMoved/);
  });
});

describe('transfers', () => {
  it('rows and the summary', () => {
    assert.deepEqual(DS.transferView({ id: 'u1', dir: 'up', name: 'a.pdf', total: 2048, sent: 1024, state: 'running' }, t, 'de'),
      { id: 'u1', name: 'a.pdf', dir: 'up', pct: 50, text: 'drive.transfer.progress(sent=1 KB,total=2 KB)', cls: '', conflict: false, active: true, path: null });
    const c = DS.transferView({ id: 'u2', dir: 'up', name: 'b', total: 1, state: 'conflict' }, t, 'de');
    assert.equal(c.conflict, true);
    assert.equal(c.cls, 'is-warn');
    assert.equal(DS.transferView({ id: 'u3', state: 'failed', code: 'quota' }, t, 'de').text, 'drive.transfer.failed(reason=drive.err.quota)');
    assert.equal(DS.transferView({ id: 'd1', dir: 'down', state: 'done', path: 'C:\\x' }, t, 'de').text, 'drive.transfer.loaded');
    assert.equal(DS.transferView({ id: 'u4', state: 'same', total: 0 }, t, 'de').pct, 100);
    const rows = [{ dir: 'up', state: 'done' }, { dir: 'up', state: 'running' }, { dir: 'up', state: 'queued' }, { dir: 'down', state: 'running' }];
    assert.equal(DS.transfersSummary(rows, t), 'drive.transfer.summary(done=1,total=3)');
    assert.equal(DS.transfersSummary([{ dir: 'up', state: 'done' }], t), null);
  });
});

describe('folder picker ("In Drive speichern", "Verschieben")', () => {
  it('writable areas only; starts in the folder picked last; subfolders without the moved one', () => {
    const areas = [
      area(),
      area({ id: 'child:7', kind: 'child', label: 'Lena', role: 'read', writable: false }),
      area({ id: 'team:1', kind: 'team', label: 'Büro', role: 'write', writable: true, archived: true }),
      area({ id: 'family:1', kind: 'family', label: 'Familie', role: 'write', writable: true }),
    ];
    assert.deepEqual(DS.writableAreas(areas).map((a) => a.id), ['mine:2', 'family:1']);
    assert.equal(DS.pickerStart(17), 17);
    assert.equal(DS.pickerStart(null), null);
    assert.equal(DS.pickerStart(0), null);
    assert.equal(DS.canPick({ writable: true }), true);
    assert.equal(DS.canPick({ writable: false }), false);
    assert.equal(DS.canPick(null), false);
    const f = { writable: true, crumbs: [{ id: 1, name: 'Meine Dateien' }, { id: 10, name: 'Belege' }], items: [node({ id: 30, isDir: true, name: 'A' }), node({ id: 31, isDir: true, name: 'B' }), node()] };
    assert.deepEqual(DS.pickerFolders(f, 31).map((n) => n.id), [30]);
    assert.equal(DS.pickerPath(f, area(), t), 'drive.area.mine › Belege');
  });
});

describe('"In Drive speichern" in Chats, GateDrop, Schule', () => {
  it('chat: pictures, voice messages and files while the Messenger offers Drive', () => {
    const me = { integrations: { drive: true } };
    assert.equal(DS.chatCanSave({ kind: 'image', media: { id: 'm' } }, me), true);
    assert.equal(DS.chatCanSave({ kind: 'voice', media: { id: 'm' } }, me), true);
    assert.equal(DS.chatCanSave({ kind: 'file', media: { id: 'm' } }, me), true);
    assert.equal(DS.chatCanSave({ kind: 'text' }, me), false);
    assert.equal(DS.chatCanSave({ kind: 'image', media: { id: 'm' }, pending: true }, me), false);
    assert.equal(DS.chatCanSave({ kind: 'image', media: { id: 'm' } }, { integrations: { drive: false } }), false);
    assert.equal(DS.chatCanSave({ kind: 'image', media: { id: 'm' } }, null), false);
    assert.equal(DS.savedText({ where: 'Meine Dateien › Messenger › Foto.jpg' }, t), 'drive.save.done(where=Meine Dateien › Messenger › Foto.jpg)');
    assert.equal(DS.savedText({ name: 'Foto.jpg' }, t), 'drive.save.doneName(name=Foto.jpg)');
    assert.equal(DS.savedText(null, t), 'drive.save.doneShort');
  });

  it('GateDrop: "Mein Drive" only when offered, files only, a folder picked', () => {
    const targets = { drive: true, nas: [], devices: [], peopleDevices: [] };
    const sel = { ...GS.emptySelection(), drive: true };
    assert.deepEqual(GS.buildTo(sel, targets), { people: [], devices: [], nas: [], drive: true });
    assert.deepEqual(GS.buildTo({ ...sel, driveFolder: { folderId: 12, path: 'Familie › Belege' } }, targets).drive, { folderId: 12 });
    assert.equal(GS.buildTo(sel, { ...targets, drive: false }), null);
    assert.deepEqual(GS.canSend({ files: [], text: 'hallo', selection: sel, targets }), { ok: false, key: 'drive.gatedrop.needsFiles' });
    assert.deepEqual(GS.canSend({ files: [{ id: 'f1' }], text: '', selection: sel, targets }), { ok: true, key: null });
    assert.equal(GS.dialogTargets(targets).drive, true);
    assert.equal(GS.dialogTargets({}).drive, false);
    const v = GS.sentView({ deliveries: [{ kind: 'drive', target: 'mine', targetName: null, status: 'delivered' }] }, { t, locale: 'de', now: NOW });
    assert.equal(v.deliveries[0].label, 'drive.gatedrop.target');
    assert.equal(GS.errorText({ ok: false, code: 'drive_unavailable' }, t), 'drive.err.unavailable');
  });

  it('error texts of Drive and of the plugins passing its codes on', () => {
    const cases = {
      no_seat: 'drive.err.noSeat', not_licensed: 'drive.err.notLicensed', quota: 'drive.err.quota', forbidden: 'drive.err.forbidden',
      drive_unavailable: 'drive.err.unavailable', rate_limited: 'drive.err.rateLimited', offline: 'drive.err.offline', network: 'drive.err.offline',
      timeout: 'drive.err.offline', exists: 'drive.err.exists', not_found: 'drive.err.notFound', links_disabled: 'drive.err.linksDisabled',
      unsafe: 'drive.err.unsafe', SCHULE_UNTIS_UNAVAILABLE: 'drive.err.schoolOffline', http_429: 'drive.err.rateLimited',
    };
    for (const [code, key] of Object.entries(cases)) assert.equal(DS.errorText({ ok: false, code }, t), key, code);
    assert.equal(DS.errorText({ ok: false, code: 'weird' }, t), 'drive.err.generic(code=weird)');
    assert.equal(DS.errorText(null, t), 'drive.err.generic(code=failed)');
  });
});

describe('page wiring', () => {
  const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

  it('index.html loads state before view, the nav entry starts hidden', () => {
    const html = read('src', 'renderer', 'index.html');
    const a = html.indexOf('src="drive-state.js"');
    const b = html.indexOf('src="drive-view.js"');
    assert.ok(a > 0 && b > a && b < html.indexOf('src="renderer.js"'));
    assert.match(html, /href="styles\/drive\.css"/);
    assert.match(html, /id="nav-drive"[^>]*hidden/);
    assert.match(html, /id="page-drive"/);
  });

  it('views never use innerHTML / insertAdjacentHTML / eval', () => {
    for (const f of ['drive-view.js', 'drive-state.js']) {
      const src = read('src', 'renderer', f);
      assert.doesNotMatch(src, /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/, f);
    }
  });

  it('every drive.* key the views use exists in de and en', () => {
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const keys = new Set();
    const files = ['drive-view.js', 'drive-state.js', 'chat-view.js', 'school-view.js', 'gatedrop-view.js', 'gatedrop-state.js', 'renderer.js', 'index.html'].map((f) => read('src', 'renderer', f)).join('\n');
    // drive.tt / drive.photos / drive.storage (Drive 1.7, with their plurals): test/drive-17-state.test.js
    for (const m of files.matchAll(/['"`](drive\.[A-Za-z0-9_.]+)['"`]/g)) if (!m[1].endsWith('.') && !/^drive\.(tt|photos|storage)\./.test(m[1])) keys.add(m[1]);
    // built at runtime
    for (const s of DS.SORTS) keys.add(`drive.sort.${s}`);
    for (const x of DS.LINK_EXPIRES) keys.add(`drive.share.expires.${x}`);
    for (const m of ['view', 'download', 'upload']) keys.add(`drive.link.mode.${m}`);
    for (const k of Object.values(DS.ERROR_CODES)) keys.add(`drive.err.${k}`);
    keys.add('drive.err.generic');
    const plurals = new Set(['drive.trash.files', 'drive.upload.rejected', 'drive.guard.more', 'drive.guard.files', 'drive.upload.folders', 'drive.upload.files', 'drive.upload.skipped', 'drive.transfer.folderDone']);
    for (const p of plurals) { keys.delete(p); keys.add(`${p}.one`); keys.add(`${p}.other`); }
    assert.ok(keys.size > 150, `only ${keys.size} keys found`);
    for (const k of keys) {
      assert.ok(k in de, `de: ${k}`);
      assert.ok(k in en, `en: ${k}`);
    }
  });
});

describe('Drive 1.5 / 1.6: live, portal, guard, folders', () => {
  it('a change elsewhere reloads what it touches', () => {
    assert.equal(DS.liveRelevant({ areas: ['mine:2'], seq: 4 }, { view: 'folder', areaId: 'mine:2' }), true);
    assert.equal(DS.liveRelevant({ areas: ['family:1'] }, { view: 'folder', areaId: 'mine:2' }), false);
    assert.equal(DS.liveRelevant({ areas: null }, { view: 'folder', areaId: 'mine:2' }), true);
    assert.equal(DS.liveRelevant({ areas: ['family:1'] }, { view: 'trash' }), true);
    assert.equal(DS.liveRelevant({ areas: ['mine:2'] }, { view: 'sync' }), false);
  });

  it('throttles to one call per interval, the last request wins', () => {
    let t0 = 1000;
    const timers = [];
    let calls = 0;
    const th = DS.throttle(() => { calls++; }, 2000, { now: () => t0, setTimer: (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, clearTimer: () => {} });
    th.request();
    assert.equal(calls, 1);
    th.request();
    th.request();
    assert.equal(calls, 1);
    assert.equal(timers.length, 1);
    assert.equal(timers[0].ms, 2000);
    t0 += 2000;
    timers[0].fn();
    assert.equal(calls, 2);
    t0 += 5000;
    th.request();
    assert.equal(calls, 3);
  });

  it('"Im Portal öffnen" only with links; folder rows and the device_locked error', () => {
    const me = { features: ['links'], links: { node: 'https://gc.example.com/x/{id}' } };
    assert.equal(DS.actionsFor(node(), true, me).portal, true);
    assert.equal(DS.actionsFor(node(), true, { features: [], links: null }).portal, false);
    assert.equal(DS.actionsFor(node(), true, { features: ['links'], links: null }).portal, false);
    assert.equal(DS.transferView({ id: 'f1', dir: 'up', folder: true, state: 'running', total: 0, sent: 0 }, t, 'de').text, 'drive.transfer.folderMaking');
    assert.equal(DS.transferView({ id: 'f1', dir: 'up', folder: true, state: 'done', files: 3, total: 0, sent: 0 }, t, 'de').text, 'drive.transfer.folderDone.other(count=3)');
    assert.equal(DS.errorText({ code: 'device_locked' }, t), 'drive.err.locked');
    assert.equal(DS.folderQueuedText({ ok: true, folders: 2, queued: ['u1', 'u2', 'u3'], skipped: 1 }, t),
      'drive.upload.folderQueued(what=drive.upload.folders.other(count=2), drive.upload.files.other(count=3), drive.upload.skipped.one(count=1))');
    assert.equal(DS.folderQueuedText({ ok: true, folders: 0, queued: ['u1'] }, t), null);
  });

  it('the guard banner while Drive keeps the device stopped', () => {
    assert.equal(DS.guardView(null, { t, locale: 'de', now: NOW }), null);
    assert.equal(DS.guardView({ locked: false, incident: { id: 1 } }, { t, locale: 'de', now: NOW }), null);
    const v = DS.guardView({ locked: true, portal: true, incident: { id: 7001, files: 63, at: at(2026, 10, 27, 8, 5), deviceName: 'Büro-PC', sample: ['a.docx', 'b.xlsx', '', 'c', 'd', 'e', 'f'] } }, { t, locale: 'de', now: NOW });
    assert.equal(v.id, 7001);
    assert.deepEqual(v.sample, ['a.docx', 'b.xlsx', 'c', 'd', 'e']);
    assert.equal(v.more, 58);
    assert.equal(v.portal, true);
    assert.equal(v.text, 'drive.guard.text drive.guard.files.other(count=63) · drive.guard.at(when=drive.time.today(time=08:05)) · drive.guard.device(name=Büro-PC)');
    assert.equal(DS.guardView({ locked: true, incident: null }, { t, locale: 'de', now: NOW }).id, null);
  });
});
