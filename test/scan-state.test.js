'use strict';

// The host's virus scan in the plugin pages (GateControl 1.223.0; Drive 1.19, GateDrop 1.4, Mail 1.8, Messenger 1.11),
// no DOM: the chips („Wird geprüft …“, „Gesperrt – Schadsoftware“, „Gesperrt – nicht prüfbar“, „Warnung – Schadsoftware“,
// quiet „Nicht prüfbar“), what a blocked file no longer offers (open, save, share, office, to Drive) and the reason
// instead, the question before a marked file opens, the refusals (423 scan_pending with Retry-After, quarantined,
// scan_blocked, 422 infected, 503 scan_unavailable, 410 attachment_removed, 409 attachment_blocked) in words per plugin
// — and nothing new without `scan`. Plus: the page loads scan-state.js first, no innerHTML, every key in de and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SCAN = require('../src/renderer/scan-state');
const DS = require('../src/renderer/drive-state');
const SS = require('../src/renderer/drive-sync-state');
const GS = require('../src/renderer/gatedrop-state');
const MS = require('../src/renderer/mail-state');
const CS = require('../src/renderer/chat-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);

const INFECTED = { state: 'infected', blocked: true, finding: 'Eicar-Test-Signature' };
const PENDING = { state: 'pending', blocked: true, finding: null };
const UNSCANNABLE = { state: 'unscannable', blocked: true, finding: 'encrypted' };
const MARKED = { state: 'infected', blocked: false, finding: 'GC.Office.Macro' };
const QUIET = { state: 'unscannable', blocked: false, finding: 'too_large' };

describe('scan-state', () => {
  it('chips: kind, tone, short text, the long text as tooltip; nothing for clean / unchecked / no scan', () => {
    assert.deepEqual(SCAN.chip(PENDING, t), { kind: 'checking', tone: 'checking', text: 'scan.checkingShort', title: 'scan.checkingOpen' });
    assert.deepEqual(SCAN.chip(INFECTED, t), { kind: 'malware', tone: 'blocked', text: 'scan.malware', title: 'scan.quarantinedOf(finding=Eicar-Test-Signature)' });
    assert.deepEqual(SCAN.chip(UNSCANNABLE, t), { kind: 'unscannable', tone: 'blocked', text: 'scan.unscannableShort', title: 'scan.scanBlocked' });
    assert.deepEqual(SCAN.chip(MARKED, t), { kind: 'warning', tone: 'warning', text: 'scan.warning', title: 'scan.warningOf(finding=GC.Office.Macro)' });
    assert.deepEqual(SCAN.chip(QUIET, t), { kind: 'notCheckable', tone: 'quiet', text: 'scan.notCheckable', title: 'scan.notCheckable' });
    assert.equal(SCAN.chip({ ...INFECTED, removed: true }, t).text, 'scan.removed');
    assert.equal(SCAN.chip({ state: 'clean', blocked: false }, t), null);
    assert.equal(SCAN.chip({ state: 'unchecked', blocked: false }, t), null);
    assert.equal(SCAN.chip({ state: 'pending', blocked: false }, t), null, 'still checked, not blocked: nothing');
    assert.equal(SCAN.chip(undefined, t), null);
    assert.equal(SCAN.isBlocked({ state: 'clean', blocked: true }), true, 'blocked decides, not state');
    assert.equal(SCAN.isWarning(MARKED), true);
    assert.equal(SCAN.isWarning(INFECTED), false);
  });

  it('the refusals in words, Retry-After of scan_pending (bounded), skipped / sync texts', () => {
    assert.equal(SCAN.refusalText({ code: 'scan_pending', retryAfter: 5 }, t), 'scan.checkingOpen');
    assert.equal(SCAN.refusalText({ code: 'quarantined', finding: 'Eicar' }, t), 'scan.quarantinedOf(finding=Eicar)');
    assert.equal(SCAN.refusalText({ code: 'quarantined', scan: INFECTED }, t), 'scan.quarantinedOf(finding=Eicar-Test-Signature)');
    assert.equal(SCAN.refusalText({ code: 'scan_blocked' }, t), 'scan.scanBlocked');
    assert.equal(SCAN.refusalText({ code: 'scan_blocked', name: 'a.zip' }, t), 'scan.scanBlockedOf(name=a.zip)');
    assert.equal(SCAN.refusalText({ code: 'infected', name: 'Foto.jpg' }, t), 'scan.rejectedOf(name=Foto.jpg)');
    assert.equal(SCAN.refusalText({ code: 'infected' }, t), 'scan.rejected');
    assert.equal(SCAN.refusalText({ code: 'scan_unavailable' }, t), 'scan.unavailable');
    assert.equal(SCAN.refusalText({ code: 'attachment_removed' }, t), 'scan.attachmentRemoved');
    assert.equal(SCAN.refusalText({ code: 'attachment_blocked', detail: { name: 'b.exe' } }, t), 'scan.attachmentBlockedOf(name=b.exe)');
    assert.equal(SCAN.refusalText({ code: 'busy' }, t), null);
    assert.equal(SCAN.retryDelay({ code: 'scan_pending', retryAfter: 5 }, 0), 5000);
    assert.equal(SCAN.retryDelay({ code: 'scan_pending' }, 1), 5000);
    assert.equal(SCAN.retryDelay({ code: 'scan_pending', retryAfter: 900 }, 0), 60000);
    assert.equal(SCAN.retryDelay({ code: 'scan_pending', retryAfter: 5 }, 2), null, 'twice at most');
    assert.equal(SCAN.retryDelay({ code: 'quarantined' }, 0), null);
    assert.equal(SCAN.skippedText(0, t), null);
    assert.equal(SCAN.skippedText(1, t), 'scan.skippedOne');
    assert.equal(SCAN.skippedText(3, t), 'scan.skippedMany(count=3)');
    assert.deepEqual(SCAN.warnAsk(MARKED, 'Rechnung.docm', t), { title: 'scan.warningOf(finding=GC.Office.Macro)', text: 'scan.warningAsk(name=Rechnung.docm)', confirm: 'scan.openAnyway' });
  });
});

describe('Drive 1.19', () => {
  const node = (o = {}) => ({ id: 12, areaId: 'mine:2', parentId: 10, name: 'Brief.pdf', isDir: false, size: 14, mime: 'application/pdf', mediaId: 'abcdef1234567890', preview: true, ...o });
  const me = { features: ['office', 'links', 'scan'], links: { node: 'x' } };

  it('rows: the chip, no preview of a blocked file; an older Drive: nothing new', () => {
    const plain = DS.rowView(node(), { t, locale: 'de' });
    assert.equal(plain.scan, null);
    assert.equal(plain.preview, true);
    const blocked = DS.rowView(node({ scan: INFECTED }), { t, locale: 'de' });
    assert.equal(blocked.scan.kind, 'malware');
    assert.equal(blocked.preview, false);
    assert.equal(DS.rowView(node({ scan: MARKED }), { t, locale: 'de' }).scan.tone, 'warning');
    assert.equal(DS.rowView(node({ isDir: true, scan: INFECTED }), { t, locale: 'de' }).scan, null);
  });

  it('a blocked file: no open, save, share, office — the reason; a marked one asks before it opens', () => {
    const free = DS.actionsFor(node({ name: 'Brief.docx' }), true, me);
    assert.deepEqual([free.open, free.saveAs, free.share, free.office, free.blocked, free.warn], [true, true, true, 'edit', null, false]);
    const blocked = DS.actionsFor(node({ name: 'Brief.docx', scan: INFECTED }), true, me);
    assert.deepEqual([blocked.open, blocked.saveAs, blocked.share, blocked.office, blocked.blocked], [false, false, false, null, 'malware']);
    assert.equal(blocked.rename, true, 'renaming and the trash stay');
    assert.equal(blocked.remove, true);
    assert.equal(DS.actionsFor(node({ scan: PENDING }), true, me).blocked, 'checking');
    const marked = DS.actionsFor(node({ scan: MARKED }), true, me);
    assert.deepEqual([marked.open, marked.saveAs, marked.warn], [true, true, true]);
  });

  it('errors in words, the transfer row of a refused upload, the sync folder, a chat file to Drive', () => {
    assert.equal(DS.errorText({ code: 'quarantined', finding: 'Eicar' }, t), 'scan.quarantinedOf(finding=Eicar)');
    assert.equal(DS.errorText({ code: 'scan_unavailable' }, t), 'scan.unavailable');
    assert.equal(DS.errorText({ code: 'quota' }, t), 'drive.err.quota', 'the others as before');
    const row = DS.transferView({ id: 'u1', dir: 'up', name: 'virus.exe', state: 'failed', code: 'infected', total: 2, sent: 0 }, t, 'de');
    assert.match(row.text, /scan\.rejected/);
    const f = SS.folderView({ id: 'abcdef0123456789', path: 'C:\\D', name: 'D', mode: 'sync', target: {}, paused: false, state: 'idle', reason: null, failed: 0, blocked: 2, lastSyncAt: Date.now() }, { t, locale: 'de', now: Date.now() });
    assert.ok(f.detail.includes('scan.syncBlockedMany(count=2)'));
    const none = SS.folderView({ id: 'abcdef0123456789', path: 'C:\\D', name: 'D', mode: 'sync', target: {}, paused: false, state: 'idle', reason: null, failed: 0, lastSyncAt: Date.now() }, { t, locale: 'de', now: Date.now() });
    assert.equal(none.detail.some((d) => d.startsWith('scan.')), false);
    const meChat = { integrations: { drive: true } };
    assert.equal(DS.chatCanSave({ kind: 'file', media: { id: 'x' } }, meChat), true);
    assert.equal(DS.chatCanSave({ kind: 'file', media: { id: 'x', scan: INFECTED } }, meChat), false);
  });
});

describe('GateDrop 1.4', () => {
  const NOW = new Date(2026, 10, 3, 12).getTime();

  it('received: the files the virus scan checks or blocked, no "Speichern" for blocked only', () => {
    const items = [{ name: 'ok.pdf', bytes: 3, mediaId: 'a'.repeat(32) }, { name: 'virus.exe', bytes: 2, mediaId: null, available: false, scan: INFECTED }, { name: 'gross.zip', bytes: 9, mediaId: null, scan: PENDING }];
    const v = GS.receivedView({ id: '5', at: NOW, from: { name: 'Anna' }, items, local: [] }, { t, locale: 'de', now: NOW });
    assert.deepEqual(v.scan.map((x) => [x.name, x.chip.kind]), [['virus.exe', 'malware'], ['gross.zip', 'checking']]);
    assert.equal(v.canSave, true);
    const only = GS.receivedView({ id: '6', at: NOW, items: [items[1]], local: [] }, { t, locale: 'de', now: NOW });
    assert.equal(only.canSave, false);
    assert.deepEqual(GS.receivedView({ id: '7', at: NOW, items: [items[0]], local: [] }, { t, locale: 'de', now: NOW }).scan, []);
  });

  it('sending: "wird geprüft" while the host checks, the refused file named; a delivery that failed on the scan', () => {
    assert.equal(GS.progressText({ phase: 'scanning', sent: 0, total: 10 }, t), 'scan.sendWaiting');
    assert.deepEqual(GS.sendToastView({ phase: 'scanning', sent: 0, total: 10 }, t), { tone: 'busy', text: 'scan.sendWaiting', percent: null });
    assert.equal(GS.errorText({ code: 'infected', name: 'Rechnung.pdf' }, t), 'scan.rejectedOf(name=Rechnung.pdf)');
    assert.equal(GS.errorText({ code: 'scan_blocked', name: 'a.zip' }, t), 'scan.scanBlockedOf(name=a.zip)');
    assert.equal(GS.errorText({ code: 'quarantined' }, t), 'scan.quarantined');
    assert.equal(GS.errorText({ code: 'changed' }, t), 'gatedrop.error.changed');
    const s = GS.sentView({ id: '8', items: [{ name: 'a' }], deliveries: [{ kind: 'drive', target: 'drive', status: 'failed', error: 'quarantined' }, { kind: 'person', target: '8', status: 'failed', error: 'offline' }] }, { t, locale: 'de', now: NOW });
    assert.equal(s.deliveries[0].text, 'gatedrop.status.failed – scan.quarantined');
    assert.equal(s.deliveries[1].text, 'gatedrop.status.failed');
  });
});

describe('Mail 1.8', () => {
  it('attachments: blocked / removed → reason, marked → warn; the refusals and the outbox in words', () => {
    assert.deepEqual(MS.attScan({ id: 1, name: 'a.pdf' }, t), { chip: null, blocked: false, warn: false, reason: null });
    const b = MS.attScan({ id: 2, name: 'b.exe', scan: INFECTED }, t);
    assert.deepEqual([b.blocked, b.warn, b.chip.kind, b.reason], [true, false, 'malware', 'scan.quarantinedOf(finding=Eicar-Test-Signature)']);
    const r = MS.attScan({ id: 3, name: 'c.doc', scan: { state: 'infected', blocked: true, finding: null, removed: true } }, t);
    assert.deepEqual([r.blocked, r.chip.text, r.reason], [true, 'scan.removed', 'scan.attachmentRemoved']);
    const w = MS.attScan({ id: 4, name: 'd.docm', scan: MARKED }, t);
    assert.deepEqual([w.blocked, w.warn], [false, true]);
    assert.equal(MS.errorText({ code: 'attachment_blocked', attachmentId: 9, name: 'b.exe' }, t, 'de'), 'scan.attachmentBlockedOf(name=b.exe)');
    assert.equal(MS.errorText({ code: 'attachment_removed' }, t, 'de'), 'scan.attachmentRemoved');
    assert.equal(MS.errorText({ code: 'infected' }, t, 'de'), 'scan.rejected');
    assert.equal(MS.errorText({ code: 'busy' }, t, 'de'), 'mail.err.busy');
    assert.equal(MS.outboxError('attachment_blocked', t), 'scan.attachmentBlocked');
    assert.equal(MS.outboxError('SMTP 550', t), 'SMTP 550');
  });
});

describe('Messenger 1.11', () => {
  const msg = (scan, o = {}) => ({ id: 5, kind: 'file', meta: { fileName: 'a.pdf' }, media: { id: 'm1', mime: 'application/pdf', bytes: 3, ...(scan ? { scan } : {}) }, ...o });

  it('the file of a message: „Wird auf Viren geprüft …“, „Datei gesperrt“ + finding, not checkable; a warning line', () => {
    assert.equal(CS.mediaScan(msg(null), t), null);
    assert.deepEqual(CS.mediaScan(msg(PENDING), t), { kind: 'checking', blocked: true, warn: false, title: 'scan.checking', text: 'ui.scan.afterCheck' });
    assert.deepEqual(CS.mediaScan(msg(INFECTED), t), { kind: 'malware', blocked: true, warn: false, title: 'scan.fileBlocked', text: 'ui.scan.foundOf(finding=Eicar-Test-Signature)' });
    assert.deepEqual(CS.mediaScan(msg(UNSCANNABLE), t), { kind: 'unscannable', blocked: true, warn: false, title: 'scan.scanBlocked', text: '' });
    assert.deepEqual(CS.mediaScan(msg(MARKED), t), { kind: 'warning', blocked: false, warn: true, title: '', text: 'scan.warningOf(finding=GC.Office.Macro)' });
    assert.equal(CS.mediaScan(msg(QUIET), t).text, 'scan.notCheckable');
  });

  it('a message not sent because of its file; the errors in words', () => {
    assert.equal(CS.notSentText({ pending: true, failed: true, error: 'infected', finding: 'Eicar' }, t), 'scan.notSentOf(finding=Eicar)');
    assert.equal(CS.notSentText({ pending: true, failed: true, error: 'infected' }, t), 'scan.notSent');
    assert.equal(CS.notSentText({ pending: true, failed: true, error: 'scan_blocked' }, t), 'scan.notSentUnscannable');
    assert.equal(CS.notSentText({ pending: true, failed: true, error: 'readonly' }, t), null);
    assert.equal(CS.errorText({ code: 'quarantined' }, t), 'scan.quarantined');
    assert.equal(CS.errorText('scan_pending', t), 'scan.checkingOpen');
  });
});

describe('the page', () => {
  it('loads scan-state.js before every plugin page, no innerHTML in it', () => {
    const html = read('src', 'renderer', 'index.html');
    const pos = (f) => html.indexOf(`<script src="${f}"></script>`);
    assert.ok(pos('scan-state.js') > 0);
    for (const f of ['chat-state.js', 'gatedrop-state.js', 'drive-state.js', 'drive-sync-state.js', 'mail-state.js', 'drive-photos-view.js', 'drive-bulk-view.js']) assert.ok(pos('scan-state.js') < pos(f), f);
    assert.doesNotMatch(read('src', 'renderer', 'scan-state.js'), /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/);
  });

  it('every scan.* key the pages use exists in the core (de and en), the chat keys in the app', () => {
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const src = ['scan-state.js', 'drive-state.js', 'drive-view.js', 'drive-photos-view.js', 'drive-bulk-view.js', 'drive-sync-state.js', 'gatedrop-state.js', 'gatedrop-view.js', 'mail-state.js', 'mail-view.js', 'chat-state.js', 'chat-view.js']
      .map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set();
    for (const m of src.matchAll(/['"`]((?:scan|ui\.scan|mail\.warn)\.[A-Za-z0-9_.]+)['"`]/g)) keys.add(m[1]);
    assert.ok(keys.size > 25, `only ${keys.size} keys`);
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    let core = null;
    try {
      const dir = path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [ROOT] }));
      core = { de: flat(JSON.parse(fs.readFileSync(path.join(dir, 'src', 'i18n', 'locales', 'de.json'), 'utf8'))), en: flat(JSON.parse(fs.readFileSync(path.join(dir, 'src', 'i18n', 'locales', 'en.json'), 'utf8'))) };
    } catch { core = null; }
    for (const k of keys) {
      if (k.startsWith('scan.')) {
        if (!core) continue;
        assert.ok(k in core.de, `core de: ${k}`);
        assert.ok(k in core.en, `core en: ${k}`);
      } else if (k !== 'mail.warn.') {
        assert.ok(k in de, `de: ${k}`);
        assert.ok(k in en, `en: ${k}`);
      }
    }
    assert.ok(de['mail.warn.attachment_blocked'] && en['mail.warn.attachment_blocked']);
  });
});
