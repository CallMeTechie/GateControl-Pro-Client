'use strict';

// GateDrop in the app: the view logic (src/renderer/gatedrop-state.js, no
// DOM), the main-process wiring (src/main/gatedrop.js: "Senden an" shortcut,
// argv, tray entry), how the page loads the GateDrop scripts, that the view
// never uses innerHTML and that every gatedrop.* key it uses exists in the
// core locales. The same file is used by Pro and Community.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const fs = require('node:fs');
const path = require('node:path');

const GS = require('../src/renderer/gatedrop-state');
const { setupGateDrop } = require('../src/main/gatedrop');

const ROOT = path.join(__dirname, '..');
const CORE_PKG = '@gatecontrol/client-core';
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);
const NOW = new Date(2026, 9, 21, 12, 0).getTime();

function coreDir() {
  try { return path.dirname(require.resolve(`${CORE_PKG}/package.json`, { paths: [ROOT] })); } catch { /* not installed */ }
  for (const d of [path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) {
    if (fs.existsSync(path.join(d, 'src', 'i18n', 'locales', 'de.json'))) return d;
  }
  return null;
}

describe('gatedrop-state', () => {
  it('sizes and percent', () => {
    assert.equal(GS.formatBytes(512, 'de'), '512 B');
    assert.equal(GS.formatBytes(1536, 'de'), '1,5 KB');
    assert.equal(GS.formatBytes(1536, 'en'), '1.5 KB');
    assert.equal(GS.formatBytes(2 * 1024 ** 3, 'en'), '2 GB');
    assert.equal(GS.percent(50, 200), 25);
    assert.equal(GS.percent(5, 0), 0);
  });

  it('dialog title from the files', () => {
    assert.equal(GS.dialogTitle([{ name: 'angebot-kueche.pdf' }], t), 'gatedrop.dialog.title(angebot-kueche.pdf)');
    assert.equal(GS.dialogTitle([{ name: 'a' }, { name: 'b' }], t), 'gatedrop.dialog.titleMany(2)');
    assert.equal(GS.dialogTitle([], t), 'gatedrop.dialog.titleText');
  });

  it('a lone URL is a link, anything else text', () => {
    assert.deepEqual(GS.splitTextLink(' https://example.org/a?b=1 '), { text: null, link: 'https://example.org/a?b=1' });
    assert.deepEqual(GS.splitTextLink('schau mal https://example.org'), { text: 'schau mal https://example.org', link: null });
    assert.deepEqual(GS.splitTextLink('javascript:alert(1)'), { text: 'javascript:alert(1)', link: null });
    assert.deepEqual(GS.splitTextLink('   '), { text: null, link: null });
  });

  it('selection → to of the send', () => {
    const targets = { nas: [{ id: 'n1', label: 'Fotos', path: '/Familie/Fotos' }] };
    const sel = { ...GS.emptySelection(), devices: ['tok_1'], people: GS.toggle(['8'], 'family'), nas: ['n1', 'gone'], link: true, expires: 'once', pin: true };
    assert.deepEqual(GS.buildTo(sel, targets), { people: ['8', 'family'], devices: ['tok_1'], nas: [{ id: 'n1', path: '/Familie/Fotos' }], link: { expires: 'once', pin: true } });
    assert.equal(GS.buildTo(GS.emptySelection(), targets), null);
    assert.deepEqual(GS.toggle(['8', 'family'], 'family'), ['8']);
  });

  it('what is missing before sending', () => {
    const files = [{ id: 'f1', name: 'a.pdf', size: 3 }];
    const one = { ...GS.emptySelection(), people: ['8'] };
    assert.deepEqual(GS.canSend({ files: [], text: '', selection: one }), { ok: false, key: 'gatedrop.dialog.empty' });
    assert.deepEqual(GS.canSend({ files, text: '', selection: GS.emptySelection() }), { ok: false, key: 'gatedrop.dialog.pickTarget' });
    assert.deepEqual(GS.canSend({ files: [], text: 'hi', selection: { ...GS.emptySelection(), link: true } }), { ok: false, key: 'gatedrop.dialog.linkNeedsFiles' });
    assert.deepEqual(GS.canSend({ files, text: '', selection: one }), { ok: true, key: null });
  });

  it('targets the dialog shows (link and NAS only when allowed)', () => {
    const tg = GS.dialogTargets({
      me: { canLink: true, canNas: false },
      people: [{ id: '9', name: 'Lena', kind: 'user' }, { id: 'family', name: 'Familie', kind: 'family' }],
      devices: [{ id: 'b', name: 'Büro-PC', online: false }, { id: 'a', name: 'Pixel', online: true, direct: true }, { id: 's', name: 'Ich', self: true }],
      nas: [{ id: 'n1', label: 'x', path: '/x' }],
      links: { enabled: false },
    });
    assert.deepEqual(tg.devices.map((d) => d.id), ['a', 'b']);
    assert.deepEqual(tg.people.map((p) => p.id), ['family', '9']);
    assert.deepEqual(tg.nas, []);
    assert.equal(tg.link, false);
    assert.deepEqual(tg.expires, ['1h', '1d', '7d', 'once']);
    assert.deepEqual(GS.dialogTargets({ limits: { linkExpires: ['once', '1d', 'forever'] } }).expires, ['1d', 'once']);
    assert.equal(GS.deviceMeta({ online: true, direct: true }, t), 'gatedrop.dialog.online · gatedrop.dialog.direct');
    // Offline own devices stay in the list (selectable): "offline · kommt an, sobald es online ist".
    const off = GS.dialogTargets({ devices: [{ id: 'p', name: 'Pixel', online: false, direct: false }, { id: 'l', name: 'Laptop', online: true }] });
    assert.deepEqual(off.devices.map((d) => d.id), ['l', 'p']);
    assert.equal(GS.deviceMeta(off.devices[1], t), 'gatedrop.dialog.offlineLater');
  });

  it('the send dialog never disables an offline device', () => {
    const src = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'gatedrop-view.js'), 'utf8');
    const row = src.slice(src.indexOf("nextId('gd-dev')"), src.indexOf("sectionLabel(t('gatedrop.dialog.people'))"));
    assert.match(row, /type: 'checkbox', checked, disabled: D\.busy,/);
    assert.doesNotMatch(row, /disabled: [^,]*online/);
  });

  it('sent list: `waiting` reads "Wartet, bis „<Gerät>“ online ist"', () => {
    const s = GS.sentView({ id: '7', items: [{ name: 'a' }], deliveries: [{ kind: 'device', target: '43', targetName: 'Pixel', status: 'waiting', via: null }, { kind: 'device', target: '44', status: 'delivered', via: 'server' }] }, { t, locale: 'de', now: NOW });
    assert.deepEqual(s.deliveries.map((d) => [d.status, d.tone, d.full]), [['waiting', 'muted', true], ['delivered', 'ok', false]]);
    assert.equal(s.deliveries[0].text, 'gatedrop.status.waiting(Pixel)');
    const dir = coreDir();
    if (dir) {
      const de = JSON.parse(fs.readFileSync(path.join(dir, 'src', 'i18n', 'locales', 'de.json'), 'utf8')).gatedrop;
      assert.equal(de.status.waiting.replace('{{device}}', 'Pixel'), 'Wartet, bis „Pixel“ online ist');
      assert.equal(de.dialog.offlineLater, 'offline · kommt an, sobald es online ist');
    }
  });

  it('list lines: received, sent, links', () => {
    const r = GS.receivedView({ id: '5', at: NOW - 3600000, from: { name: 'Anna' }, items: [{ name: 'a.pdf', bytes: 2048, mediaId: 'x'.repeat(32) }], local: [] }, { t, locale: 'de', now: NOW });
    assert.equal(r.title, 'a.pdf');
    assert.equal(r.meta, 'gatedrop.list.from(Anna) · gatedrop.list.today(11:00)');
    assert.equal(r.canSave, true);
    assert.equal(r.canShow, false);
    const s = GS.sentView({ id: '6', items: [{ name: 'a' }, { name: 'b' }], deliveries: [{ kind: 'device', target: 'tok', targetName: 'Pixel', status: 'delivered', via: 'direct' }, { kind: 'person', target: '8', status: 'failed' }] }, { t, locale: 'de', now: NOW });
    assert.equal(s.title, 'gatedrop.list.files(2)');
    assert.deepEqual(s.deliveries.map((d) => [d.label, d.tone]), [['Pixel', 'ok'], ['8', 'err']]);
    assert.equal(s.deliveries[0].text, 'gatedrop.status.delivered · gatedrop.via.direct');
    const active = { token: 'a'.repeat(22), expiresAt: NOW + 23 * 3600000, downloads: 1, pin: true, items: [{ name: 'x' }, { name: 'y' }] };
    const l = GS.linkView(active, { t, locale: 'de', now: NOW });
    assert.equal(l.state, 'active');
    assert.equal(l.title, 'gatedrop.list.files(2) · gatedrop.list.linkPin');
    assert.equal(GS.linkState({ ...active, locked: true }, NOW), 'locked');
    assert.equal(GS.linkState({ ...active, expiresAt: NOW - 1 }, NOW), 'expired');
    assert.equal(GS.linkState({ ...active, once: true, downloads: 1 }, NOW), 'expired');
    assert.deepEqual(GS.sortLinks([{ ...active, token: 'old', expiresAt: NOW - 5 }, active], NOW).map((x) => x.token), [active.token, 'old']);
  });

  it('progress, rejected files, errors, merging, navigation', () => {
    assert.equal(GS.progressText({ phase: 'upload', sent: 1, total: 4 }, t), 'gatedrop.progress.upload(25)');
    assert.equal(GS.progressText({ phase: 'done' }, t), null);
    // send toast
    assert.equal(GS.sendLabel([{ name: 'a.pdf' }], t), 'a.pdf');
    assert.equal(GS.sendLabel([{ name: 'a' }, { name: 'b' }], t), 'gatedrop.sendToast.files(2)');
    assert.equal(GS.sendLabel([], t), 'gatedrop.sendToast.text');
    assert.deepEqual(GS.sendToastView(null, t), { tone: 'busy', text: 'gatedrop.sendToast.preparing', percent: null });
    assert.deepEqual(GS.sendToastView({ phase: 'upload', sent: 1, total: 4 }, t), { tone: 'busy', text: 'gatedrop.progress.upload(25)', percent: 25 });
    assert.deepEqual(GS.sendToastView({ phase: 'sent' }, t), { tone: 'busy', text: 'gatedrop.sendToast.transferring', percent: null });
    assert.deepEqual(GS.sendToastView({ phase: 'direct', sent: 1, total: 2 }, t), { tone: 'busy', text: 'gatedrop.progress.direct(50)', percent: 50 });
    assert.equal(GS.sendToastView({ phase: 'failed' }, t).text, 'gatedrop.progress.failed');
    assert.deepEqual(GS.sendToastView({ phase: 'done', via: 'direct' }, t), { tone: 'ok', text: 'gatedrop.sendToast.doneDirect', percent: 100 });
    assert.equal(GS.sendToastView({ phase: 'done', via: 'server' }, t).text, 'gatedrop.sendToast.done');
    assert.deepEqual(GS.sendToastView({ phase: 'upload', error: 'Kein Netz' }, t), { tone: 'err', text: 'gatedrop.sendToast.failed: Kein Netz', percent: null });
    assert.deepEqual(GS.rejectedTexts([{ name: 'Ordner', reason: 'directory' }, { name: 'x', reason: 'weird' }], t), ['gatedrop.rejected.directory(Ordner)', 'gatedrop.rejected.invalid(x)']);
    assert.equal(GS.errorText({ ok: false, code: 'quota_exceeded' }, t), 'gatedrop.error.quota_exceeded');
    assert.equal(GS.errorText({ ok: false, code: 'http_500' }, t), 'gatedrop.error.failed(http_500)');
    const many = Array.from({ length: 19 }, (_, i) => ({ id: `f${i}` }));
    const m = GS.mergeFiles(many, [{ id: 'f1' }, { id: 'n1' }, { id: 'n2' }]);
    assert.equal(m.files.length, 20);
    assert.equal(m.dropped, 1);
    assert.deepEqual(GS.navContext({ tab: 'links', sendId: 7 }), { tab: 'links', sendId: '7' });
    assert.deepEqual(GS.navContext(null), { tab: 'received', sendId: null });
  });
});

describe('main/gatedrop.js', () => {
  function fakeService(state = 'available') {
    const s = new EventEmitter();
    s.state = state;
    s.calls = [];
    s.status = () => ({ state: s.state });
    s.available = () => s.state === 'available';
    s.start = () => s.calls.push('start');
    s.stop = () => s.calls.push('stop');
    s.compose = async (paths) => { s.calls.push(['compose', paths]); };
    s.handleArgv = (argv) => argv.includes('--gatedrop-send');
    return s;
  }
  function setup({ state = 'available', platform = 'win32', stored = {}, manageShortcut = true } = {}) {
    const svc = fakeService(state);
    const syncs = [];
    const store = { get: (k, d) => (k in stored ? stored[k] : d), set: (k, v) => { stored[k] = v; } };
    let shown = 0;
    const g = setupGateDrop({
      app: { isPackaged: true, getPath: (n) => (n === 'appData' ? 'C:\\Users\\a\\AppData\\Roaming' : 'C:\\Users\\a\\Downloads'), getAppPath: () => 'C:\\dev' },
      store, log: { info() {}, warn() {}, debug() {}, error() {} },
      service: svc,
      gatedropShell: { syncSendToShortcut: (o) => { syncs.push(o); return 'created'; }, shortcutArgs: () => '--gatedrop-send' },
      dialog: { showOpenDialog: async () => ({ canceled: false, filePaths: ['C:\\a.pdf'] }) },
      showWindow: () => { shown++; }, getMainWindow: () => null,
      protocol: 'gatecontrol-x', platform, execPath: 'C:\\GC\\app.exe', manageShortcut,
    });
    return { g, svc, syncs, stored, shown: () => shown };
  }

  it('keeps the SendTo shortcut in step with availability and the setting', () => {
    const { g, svc, syncs } = setup({ state: 'unknown' });
    svc.emit('state');
    assert.equal(syncs.length, 0, 'unknown state: no change');
    svc.state = 'available';
    svc.emit('state');
    assert.equal(syncs.at(-1).enabled, true);
    assert.equal(syncs.at(-1).exePath, 'C:\\GC\\app.exe');
    assert.equal(syncs.at(-1).appData, 'C:\\Users\\a\\AppData\\Roaming');
    assert.equal(g.explorer.set(false), false);
    assert.equal(syncs.at(-1).enabled, false);
    g.explorer.set(true);
    svc.state = 'unavailable';
    svc.emit('state');
    assert.equal(syncs.at(-1).enabled, false);
  });

  it('no shortcut outside Windows or in e2e runs', () => {
    const a = setup({ platform: 'linux' });
    a.svc.emit('state');
    assert.equal(a.syncs.length, 0);
    const b = setup({ manageShortcut: false });
    b.svc.emit('state');
    assert.equal(b.syncs.length, 0);
  });

  it('argv, tray entry, compose shows the window, stop once', async () => {
    const { g, svc, shown } = setup();
    assert.equal(g.handleArgv(['app.exe', '--gatedrop-send', 'C:\\x.pdf']), true);
    assert.equal(g.handleArgv(['app.exe']), false);
    svc.emit('compose', { files: [] });
    assert.equal(shown(), 1);
    const items = g.menuItems(t);
    assert.equal(items[0].label, 'gatedrop.tray');
    items[0].click();
    await new Promise((r) => setTimeout(r, 10));
    assert.deepEqual(svc.calls.find((c) => Array.isArray(c) && c[0] === 'compose'), ['compose', ['C:\\a.pdf']]);
    svc.state = 'unavailable';
    assert.deepEqual(g.menuItems(t), []);
    g.start(); g.start(); g.stop(); g.stop();
    assert.deepEqual(svc.calls.filter((c) => typeof c === 'string'), ['start', 'stop']);
  });
});

describe('GateDrop page wiring', () => {
  const html = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'index.html'), 'utf8');
  const view = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'gatedrop-view.js'), 'utf8');
  const state = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'gatedrop-state.js'), 'utf8');

  it('loads the state before the view, the stylesheet and a hidden nav entry', () => {
    const a = html.indexOf('<script src="gatedrop-state.js"></script>');
    const b = html.indexOf('<script src="gatedrop-view.js"></script>');
    const r = html.indexOf('<script src="renderer.js"></script>');
    assert.ok(a > 0 && a < b && b < r);
    assert.match(html, /<link rel="stylesheet" href="styles\/gatedrop\.css">/);
    assert.match(html, /id="nav-gatedrop"[^>]*hidden/);
    assert.match(html, /id="page-gatedrop"/);
  });

  it('the view never uses innerHTML', () => {
    assert.doesNotMatch(view, /\.(?:innerHTML|outerHTML)\b|insertAdjacentHTML/);
  });

  const core = coreDir();
  it('every gatedrop.* key exists in the core locales (de and en)', { skip: core ? false : 'core not available' }, () => {
    const flatten = (obj, prefix = '', out = {}) => {
      for (const [k, v] of Object.entries(obj)) {
        const key = prefix ? `${prefix}.${k}` : k;
        if (v && typeof v === 'object') flatten(v, key, out); else out[key] = v;
      }
      return out;
    };
    const de = flatten(JSON.parse(fs.readFileSync(path.join(core, 'src', 'i18n', 'locales', 'de.json'), 'utf8')));
    const en = flatten(JSON.parse(fs.readFileSync(path.join(core, 'src', 'i18n', 'locales', 'en.json'), 'utf8')));
    const keys = new Set();
    for (const src of [view, state, html]) for (const m of src.matchAll(/['"`](gatedrop\.[a-zA-Z0-9_.]+[a-zA-Z0-9_])['"`]/g)) keys.add(m[1]);
    for (const x of GS.EXPIRES) keys.add(`gatedrop.expires.${x}`);
    for (const x of GS.TABS) keys.add(`gatedrop.tab.${x}`);
    for (const x of ['pending', 'direct', 'delivered', 'opened', 'failed', 'expired']) keys.add(`gatedrop.status.${x}`);
    for (const x of ['direct', 'server']) keys.add(`gatedrop.via.${x}`);
    for (const x of ['device', 'person', 'nas', 'link']) keys.add(`gatedrop.kind.${x}`);
    for (const x of ['directory', 'too_large', 'empty', 'missing', 'too_many', 'invalid']) keys.add(`gatedrop.rejected.${x}`);
    for (const x of ['emptyReceived', 'emptySent', 'emptyLinks']) keys.add(`gatedrop.list.${x}`);
    assert.ok(keys.size > 60, `only ${keys.size} keys`);
    for (const k of keys) {
      assert.ok(k in de, `de: ${k}`);
      assert.ok(k in en, `en: ${k}`);
    }
  });
});
