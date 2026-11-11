'use strict';

// View logic of the page "Drucken" (src/renderer/print-state.js, no DOM):
// which files Drive offers "Drucken …" for, the printers with their state,
// what the print dialog shows for the printer chosen (colour, double-sided,
// paper, tray, page limit, office hint), the printer and options used last,
// the rows of the job list (jobs in the making, stations, stop and wait
// reasons, actions), when an open job is asked for again and its backoff,
// error texts and push targets; how the page loads the print scripts, that
// the view never uses innerHTML and never names a file by its path, and that
// every print.* key exists in the core locales and is used.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const PS = require('../src/renderer/print-state');
const BS = require('../src/renderer/drive-bulk-state');

const ROOT = path.join(__dirname, '..');
const CORE_PKG = '@gatecontrol/client-core';
// Minimal t(): the key with its parameters.
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);
// Wednesday, 11 November 2026, 17:52 — in the time zone of the machine the test runs on
const local = (d, h, m) => new Date(2026, 10, d, h, m, 0).getTime();
const NOW = local(11, 17, 52) + 10000;
const o = (x = {}) => ({ now: NOW, locale: 'de', t, sources: new Set(), ...x });

const HP = {
  id: 'u:hp', name: 'HP OfficeJet 8020', location: 'Wohnzimmer', online: true, problem: null, state: 'idle', color: true, duplex: true, copiesMax: 99, office: true,
  media: { sizes: ['iso_a4_210x297mm', 'na_index-4x6_4x6in'], default: 'iso_a4_210x297mm', sources: ['main', 'photo'], sourceDefault: 'main' },
};
const BROTHER = {
  id: 'h:brother', name: 'Brother HL-L2350DW', location: 'Arbeitszimmer', online: false, problem: null, state: 'offline', color: false, duplex: true, copiesMax: 99, office: false,
  media: { sizes: ['iso_a4_210x297mm'], default: 'iso_a4_210x297mm', sources: ['main'], sourceDefault: 'main' },
};
const OLD = { id: 'u:old', name: 'Canon', location: null, online: true, problem: null, state: 'processing', color: true, duplex: false, copiesMax: 20, office: false, media: { sizes: [], default: null, sources: [], sourceDefault: null } };
const RIGHTS = { print: true, pagesPerDay: 20, bwOnly: false };
const job = (x = {}) => ({
  id: 'j1', name: 'Stromrechnung 2026-10.pdf', device: 'HP OfficeJet 8020', deviceId: 'u:hp', state: 'queued', open: true, error: null, message: null, pages: 2, copies: 1, color: true, duplex: true,
  media: null, source: null, at: local(11, 17, 49), updatedAt: local(11, 17, 50), expiresAt: local(12, 17, 49), doneAt: null, ...x,
});
const pdf = (x = {}) => ({ token: 'tok1', name: 'Stromrechnung 2026-10.pdf', size: 188416, type: 'application/pdf', kind: 'pdf', from: 'drive', vault: false, pages: 2, ...x });

describe('files', () => {
  it('Drive offers "Drucken …" for what the plugin prints — never a folder, a blocked file, a locked vault file', () => {
    const n = (x) => ({ id: 1, name: 'Brief.pdf', isDir: false, size: 1000, mime: 'application/pdf', scan: null, encrypted: false, locked: false, ...x });
    assert.equal(PS.printable(n()), true);
    for (const name of ['Foto.JPG', 'Bild.png', 'Neu.webp', 'iPhone.heic', 'Liste.txt', 'Brief.docx', 'Haushalt.xlsx', 'Vortrag.pptx', 'a.odt', 'b.ods', 'c.odp', 'd.rtf']) assert.equal(PS.printable(n({ name, mime: 'application/octet-stream' })), true, name);
    assert.equal(PS.printable(n({ name: 'Scan vom Handy', mime: 'application/pdf' })), true, 'by Drive\'s type');
    for (const name of ['setup.exe', 'Film.mp4', 'Anim.gif', 'Seite.html', 'archiv.zip', 'README']) assert.equal(PS.printable(n({ name, mime: 'application/octet-stream' })), false, name);
    assert.equal(PS.printable(n({ isDir: true, name: 'Ordner.pdf' })), false);
    assert.equal(PS.printable(n({ scan: { state: 'infected', blocked: true } })), false);
    assert.equal(PS.printable(n({ scan: { state: 'pending', blocked: true } })), false);
    assert.equal(PS.printable(n({ scan: { state: 'infected', blocked: false } })), true, 'marked only: the scan asks elsewhere');
    assert.equal(PS.printable(n({ size: 50 * 1024 * 1024 + 1 })), false);
    assert.equal(PS.printable(n({ encrypted: true, locked: true, name: 'x9f3…' })), false);
    assert.equal(PS.printable(n({ encrypted: true, locked: false, name: 'Pass.jpg', mime: 'application/octet-stream' })), true);
    assert.equal(PS.printable(null), false);
  });

  it('the line of a file in the dialog', () => {
    assert.equal(PS.fileLine(pdf(), t, 'de'), 'print.kind.pdf · print.meta.pages.other(2) · 184 KB · print.from.drive');
    assert.equal(PS.fileLine(pdf({ pages: 1, from: 'pc' }), t, 'de'), 'print.kind.pdf · print.meta.pages.one(1) · 184 KB · print.from.pc');
    assert.equal(PS.fileLine({ name: 'Elternbrief.docx', size: 41984, kind: 'office', from: 'pc', pages: null }, t, 'de'), 'print.kind.docx · 41 KB · print.from.pc');
    assert.equal(PS.fileLine({ name: 'Pass.jpg', size: 3984588, kind: 'image', from: 'drive', vault: true, pages: 1 }, t, 'de'), 'print.kind.image · 3,8 MB · print.from.vault');
    assert.equal(PS.sizeText(3984588, 'en'), '3.8 MB');
    assert.equal(PS.sizeText(512, 'de'), '512 B');
    assert.equal(PS.kindText({ name: 'x.unknown', kind: 'office' }, t), 'print.kind.office');
  });

  it('what a pick could not take: the first with its reason, the others counted; the vault question is no refusal', () => {
    assert.equal(PS.rejectedText([], t), '');
    assert.equal(PS.rejectedText([{ name: 'setup.exe', code: 'format' }], t), 'print.rejected.one(setup.exe,print.err.format)');
    assert.equal(PS.rejectedText([{ name: 'gross.pdf', code: 'too_large' }, { name: 'x', code: 'format' }, { name: '', code: 'folder' }], t), 'print.rejected.one(gross.pdf,print.err.too_large) print.rejected.more.other(2)');
    assert.equal(PS.rejectedText([{ name: '', code: 'quarantined' }], t), 'print.err.infected');
    assert.equal(PS.rejectedText([{ name: 'Pass.jpg', code: 'vault_confirm' }], t), '');
  });
});

describe('printers', () => {
  it('state, chip and what the row says', () => {
    assert.equal(PS.printerNote(HP), null);
    assert.equal(PS.printerNote(BROTHER), 'off');
    assert.equal(PS.printerNote(OLD), 'busy');
    assert.equal(PS.printerNote({ ...HP, state: 'stopped' }), 'stopped');
    assert.equal(PS.printerNote({ ...HP, problem: 'cert_changed' }), 'cert');
    assert.deepEqual(PS.printerChip(HP, t), { text: 'print.printer.ready', tone: 'ok' });
    assert.deepEqual(PS.printerChip(BROTHER, t), { text: 'print.printer.off', tone: 'mute' });
    assert.deepEqual(PS.printerChip(OLD, t), { text: 'print.printer.busy', tone: 'info' });
    assert.deepEqual(PS.printerChip({ ...BROTHER, problem: 'cert_changed' }, t), { text: 'print.printer.cert', tone: 'warn' });
    assert.equal(PS.printerSub(HP, t), 'Wohnzimmer · print.printer.color, print.printer.duplex');
    assert.equal(PS.printerSub(BROTHER, t), 'Arbeitszimmer · print.printer.bw, print.printer.duplex');
    assert.equal(PS.printerSub(BROTHER, t, { dialog: true }), 'Arbeitszimmer · print.printer.note.off');
    assert.equal(PS.printerSub(OLD, t, { dialog: true }), 'print.printer.note.busy');
  });

  it('banners: no printer on (printing still works), a changed certificate', () => {
    assert.deepEqual(PS.printerBanners([HP, BROTHER], t), []);
    assert.deepEqual(PS.printerBanners([BROTHER], t).map((b) => [b.key, b.tone]), [['allOff', 'info']]);
    const both = PS.printerBanners([{ ...HP, online: false }, { ...BROTHER, problem: 'cert_changed' }], t);
    assert.deepEqual(both.map((b) => [b.key, b.tone, b.title]), [['allOff', 'info', 'print.banner.allOff.title'], ['cert:h:brother', 'warn', 'Brother HL-L2350DW:']]);
    assert.deepEqual(PS.printerBanners([], t), []);
  });

  it('paper and tray in words', () => {
    assert.equal(PS.paperLabel('iso_a4_210x297mm', t), 'print.paper.a4');
    assert.equal(PS.paperLabel('na_index-4x6_4x6in', t), 'print.paper.photo10x15');
    assert.equal(PS.paperLabel('jis_b5_182x257mm', t), 'print.paper.size(182,257,mm)');
    assert.equal(PS.trayLabel('main', t), 'print.tray.main');
    assert.equal(PS.trayLabel('tray-2', t), 'print.tray.number(2)');
    assert.equal(PS.trayLabel('by-pass-tray', t), 'print.tray.bypass');
    assert.equal(PS.trayLabel('large-capacity', t), 'large-capacity');
  });
});

describe('the print dialog', () => {
  const model = (x = {}) => PS.dialogModel({ files: [pdf()], printers: [HP, BROTHER], rights: RIGHTS, pagesLeft: 14, sel: { copies: 1, color: true }, t, ...x });

  it('the normal case: the first ready printer, its options, the pages left', () => {
    const m = model();
    assert.equal(m.printer.id, 'u:hp');
    assert.deepEqual(m.printers.map((p) => [p.id, p.on, p.chip.tone]), [['u:hp', true, 'ok'], ['h:brother', false, 'mute']]);
    assert.deepEqual(m.copies, { value: 1, min: 1, max: 99, hint: 'print.dialog.copiesMax(99)' });
    assert.deepEqual(m.color, { value: true, disabled: false, hint: '' });
    assert.deepEqual([m.duplex.show, m.duplex.value, m.duplex.text], [true, false, 'print.dialog.duplexOff']);
    assert.deepEqual([m.paper.show, m.paper.disabled, m.paper.value], [true, false, 'iso_a4_210x297mm']);
    assert.deepEqual(m.paper.options.map((x) => x.label), ['print.paper.default(print.paper.a4)', 'print.paper.photo10x15']);
    assert.deepEqual([m.tray.show, m.tray.value, m.tray.options.length], [true, 'main', 2]);
    assert.equal(m.left, 'print.dialog.left(14,20)');
    assert.deepEqual([m.need, m.canSubmit, m.banners], [2, true, []]);
    // paper and tray go along only when they are not the printer's default
    assert.deepEqual(m.submit, { deviceId: 'u:hp', copies: 1, color: true, duplex: false });
    assert.deepEqual(model({ sel: { deviceId: 'u:hp', copies: 2, color: false, duplex: true, media: 'na_index-4x6_4x6in', source: 'photo' } }).submit,
      { deviceId: 'u:hp', copies: 2, color: false, duplex: true, media: 'na_index-4x6_4x6in', source: 'photo' });
  });

  it('only what the printer can: black and white, one paper, no tray; what does not fit is dropped', () => {
    const m = model({ sel: { deviceId: 'h:brother', copies: 3, color: true, duplex: true, media: 'na_index-4x6_4x6in', source: 'photo' } });
    assert.deepEqual(m.color, { value: false, disabled: true, hint: 'print.dialog.bwPrinter' });
    assert.deepEqual([m.duplex.show, m.duplex.value], [true, true]);
    assert.deepEqual([m.paper.show, m.paper.disabled, m.paper.value], [true, true, 'iso_a4_210x297mm']);
    assert.equal(m.tray.show, false);
    assert.deepEqual(m.submit, { deviceId: 'h:brother', copies: 3, color: false, duplex: true });
    // a printer of a plugin before paper / tray, without double-sided, at most 20 copies
    const old = model({ printers: [OLD], sel: { copies: 50, duplex: true } });
    assert.deepEqual([old.duplex.show, old.paper.show, old.tray.show, old.copies.value, old.copies.max], [false, false, false, 20, 20]);
    assert.deepEqual(old.submit, { deviceId: 'u:old', copies: 20, color: true, duplex: false });
    // "nur schwarz-weiß" of the person
    const bw = model({ rights: { ...RIGHTS, bwOnly: true } });
    assert.deepEqual(bw.color, { value: false, disabled: true, hint: 'print.dialog.bwOnly' });
    assert.equal(bw.submit.color, false);
  });

  it('the page limit: pages × copies of all files against what is left today', () => {
    assert.equal(model({ sel: { copies: 7 } }).canSubmit, true, '14 of 14');
    const over = model({ sel: { copies: 8 } });
    assert.deepEqual([over.need, over.canSubmit], [16, false]);
    assert.deepEqual(over.banners.map((b) => [b.key, b.tone, b.text]), [['limit', 'err', 'print.dialog.limit(16,14)']]);
    // pages not known (a file of Drive, a text): counted as at least one each
    const unknown = model({ files: [pdf({ pages: null }), pdf({ token: 'tok2', pages: null })], sel: { copies: 8 } });
    assert.deepEqual([unknown.need, unknown.banners[0].text], [16, 'print.dialog.limitAtLeast(16,14)']);
    // no limit: nothing to say
    const free = model({ rights: { ...RIGHTS, pagesPerDay: 0 }, pagesLeft: null, sel: { copies: 99 } });
    assert.deepEqual([free.left, free.canSubmit], ['', true]);
  });

  it('office files only where the printer\'s gateway converts them; a changed certificate; no printer', () => {
    const docx = { token: 'tok3', name: 'Elternbrief.docx', size: 41984, kind: 'office', from: 'pc', vault: false, pages: null };
    assert.equal(model({ files: [docx] }).canSubmit, true, 'HP: office on');
    const off = model({ files: [pdf(), docx], sel: { deviceId: 'h:brother', copies: 25 } });
    assert.equal(off.canSubmit, false);
    assert.deepEqual(off.banners.map((b) => [b.key, b.tone]), [['office', 'warn'], ['limit', 'err']]);
    assert.equal(off.banners[0].title, 'print.dialog.office.title');
    const cert = model({ printers: [{ ...HP, problem: 'cert_changed' }] });
    assert.deepEqual([cert.canSubmit, cert.banners[0].key], [false, 'cert']);
    const none = model({ printers: [] });
    assert.deepEqual([none.canSubmit, none.submit, none.printer, none.banners[0].key], [false, null, null, 'noPrinter']);
    assert.equal(model({ files: [] }).canSubmit, false);
  });

  it('the printer and options used last are kept on this PC — never the copies', () => {
    const text = PS.serializeLast({ deviceId: 'h:brother', copies: 25, color: false, duplex: true, media: 'iso_a4_210x297mm', source: 'main' });
    assert.deepEqual(JSON.parse(text), { deviceId: 'h:brother', color: false, duplex: true, media: 'iso_a4_210x297mm', source: 'main' });
    assert.deepEqual(PS.parseLast(text), { deviceId: 'h:brother', color: false, duplex: true, media: 'iso_a4_210x297mm', source: 'main' });
    assert.deepEqual(PS.parseLast('not json'), { deviceId: null, color: true, duplex: false, media: null, source: null });
    assert.deepEqual(PS.parseLast(JSON.stringify({ deviceId: 42, color: 'x', media: 'm'.repeat(100) })), { deviceId: null, color: true, duplex: false, media: null, source: null });
    assert.equal(PS.startPrinter([HP, BROTHER], 'h:brother').id, 'h:brother');
    assert.equal(PS.startPrinter([BROTHER, HP], 'u:gone').id, 'u:hp', 'the first that is ready');
    assert.equal(PS.startPrinter([BROTHER], null).id, 'h:brother');
    assert.equal(PS.startPrinter([], null), null);
    assert.equal(model({ sel: { ...PS.parseLast(text), copies: 1 } }).printer.id, 'h:brother');
  });
});

describe('the job list', () => {
  it('times: just now, today, yesterday, this week, older; "noch bis …"', () => {
    assert.equal(PS.whenText(NOW - 20000, NOW, 'de', t), 'print.meta.justNow');
    assert.equal(PS.whenText(local(11, 9, 41), NOW, 'de', t), '9:41');
    assert.equal(PS.whenText(local(10, 20, 12), NOW, 'de', t), 'print.meta.yesterday(20:12)');
    assert.match(PS.whenText(local(9, 9, 41), NOW, 'de', t), /^Mo\.?, 9:41$/);
    assert.match(PS.whenText(local(2, 9, 41), NOW, 'de', t), /^02\.11\.?, 9:41$/);
    assert.equal(PS.whenText(null, NOW, 'de', t), '');
    assert.equal(PS.untilText(local(11, 23, 5), NOW, 'de', t), 'print.meta.today(23:05)');
    assert.equal(PS.untilText(local(12, 17, 41), NOW, 'de', t), 'print.meta.tomorrow(17:41)');
    assert.match(PS.untilText(local(13, 17, 41), NOW, 'de', t), /^print\.meta\.at\(Fr\.?,17:41\)$/);
  });

  it('the phase of a job and its four stations', () => {
    const st = (x) => PS.steps(job(x));
    assert.deepEqual(st({ state: 'queued' }), ['done', 'current', 'todo', 'todo']);
    assert.deepEqual(st({ state: 'sending', message: 'converting' }), ['done', 'current', 'todo', 'todo']);
    assert.deepEqual(st({ state: 'sending', message: 'converting_office' }), ['done', 'current', 'todo', 'todo']);
    assert.deepEqual(st({ state: 'sending' }), ['done', 'done', 'current', 'todo']);
    assert.deepEqual(st({ state: 'printing' }), ['done', 'done', 'current', 'todo']);
    assert.deepEqual(st({ state: 'printing', message: 'media-empty' }), ['done', 'done', 'hold', 'todo']);
    assert.deepEqual(st({ state: 'waiting' }), ['done', 'current', 'todo', 'todo']);
    for (const state of ['done', 'failed', 'expired', 'canceled']) assert.equal(st({ state }), null, state);
    assert.deepEqual(['queued', 'sending', 'printing', 'waiting', 'done', 'failed', 'expired', 'canceled', 'future'].map((state) => PS.phase(job({ state }))),
      ['running', 'running', 'running', 'waiting', 'done', 'failed', 'failed', 'canceled', 'running']);
    assert.equal(PS.phase(job({ state: 'printing', message: 'door-open' })), 'stopped');
    assert.equal(PS.phase(job({ state: 'sending', message: 'door-open' })), 'running', 'a stop reason only while printing');
  });

  it('chips', () => {
    const chip = (x) => { const c = PS.jobChip(job(x), t); return `${c.text}/${c.tone}`; };
    assert.equal(chip({ state: 'queued' }), 'print.state.queued/info');
    assert.equal(chip({ state: 'sending' }), 'print.state.sending/info');
    assert.equal(chip({ state: 'sending', message: 'converting' }), 'print.state.converting/info');
    assert.equal(chip({ state: 'sending', message: 'converting_office' }), 'print.state.convertingOffice/info');
    assert.equal(chip({ state: 'printing' }), 'print.state.printing/info');
    assert.equal(chip({ state: 'printing', message: 'media-jam' }), 'print.state.stopped/warn');
    assert.equal(chip({ state: 'waiting' }), 'print.state.waiting/mute');
    assert.equal(chip({ state: 'done' }), 'print.state.done/ok');
    assert.equal(chip({ state: 'done', message: 'unconfirmed' }), 'print.state.doneUnconfirmed/ok');
    assert.equal(chip({ state: 'failed' }), 'print.state.failed/err');
    assert.equal(chip({ state: 'expired' }), 'print.state.expired/err');
    assert.equal(chip({ state: 'canceled' }), 'print.state.canceled/mute');
  });

  it('why a job stopped, waits (and until when), failed', () => {
    const why = (x, opts) => PS.jobWhy(job(x), o(opts));
    assert.equal(why({ state: 'printing', message: 'media-empty' }), 'print.stop.paper print.stop.resume');
    assert.equal(why({ state: 'printing', message: 'cover-open' }), 'print.stop.open print.stop.resume');
    assert.equal(why({ state: 'printing', message: 'marker-supply-empty' }), 'print.stop.ink print.stop.resume');
    assert.equal(why({ state: 'waiting', error: 'printer_offline', expiresAt: local(12, 17, 41) }), 'print.wait.until(print.wait.off,print.meta.tomorrow(17:41))');
    assert.equal(why({ state: 'waiting', error: 'printer_busy', expiresAt: local(11, 23, 0) }), 'print.wait.until(print.wait.busy,print.meta.today(23:00))');
    assert.equal(why({ state: 'waiting', error: 'cert_changed', expiresAt: null }), 'print.wait.plain(print.wait.cert)');
    // a plugin before 1.1.1 names no expiresAt: the sentence without a time, no error
    assert.equal(why({ state: 'waiting', error: null, expiresAt: null }), 'print.wait.plain(print.wait.off)');
    assert.equal(why({ state: 'failed', error: 'printer_rejected' }), 'print.fail.rejected');
    assert.equal(why({ state: 'failed', error: 'office_timeout' }), 'print.fail.officeTimeout');
    assert.equal(why({ state: 'failed', error: 'something_new' }), 'print.fail.failed');
    assert.equal(why({ state: 'expired' }), 'print.fail.expired');
    assert.equal(why({ state: 'done', message: 'unconfirmed' }), 'print.done.unconfirmed');
    assert.equal(why({ state: 'done' }), '');
    assert.equal(why({ state: 'printing' }), '');
  });

  it('a row: meta line, what can be done', () => {
    const r = PS.jobRow(job({ state: 'printing', message: 'media-empty' }), o());
    assert.deepEqual([r.key, r.kind, r.tone, r.open, r.actions, r.bar], ['j:j1', 'job', 'warn', true, ['cancel'], null]);
    assert.equal(r.meta, 'HP OfficeJet 8020 · print.meta.pages.other(2) · print.meta.color · print.meta.duplex · 17:49');
    assert.equal(PS.jobRow(job({ pages: 1, copies: 18, color: false, duplex: false, at: local(11, 17, 41) }), o()).meta,
      'HP OfficeJet 8020 · print.meta.times(print.meta.pages.one(1),print.meta.copies.other(18)) · print.meta.bw · 17:41');
    assert.match(PS.jobRow(job({ state: 'failed', media: 'na_index-4x6_4x6in', source: 'photo' }), o()).meta, /print\.paper\.photo10x15, print\.tray\.photo/);
    // the time a job ended, when the plugin names it (1.1.1)
    assert.match(PS.jobRow(job({ state: 'done', doneAt: local(11, 17, 51) }), o()).meta, /17:51$/);
    assert.deepEqual(PS.jobRow(job({ state: 'queued' }), o()).actions, ['cancel']);
    assert.deepEqual(PS.jobRow(job({ state: 'waiting' }), o()).actions, ['cancel']);
    assert.deepEqual(PS.jobRow(job({ state: 'printing' }), o()).actions, [], 'at the printer: too late');
    assert.deepEqual(PS.jobRow(job({ state: 'sending' }), o()).actions, []);
    assert.deepEqual(PS.jobRow(job({ state: 'done' }), o({ sources: new Set(['j1']) })).actions, []);
    assert.deepEqual(PS.jobRow(job({ state: 'failed' }), o()).actions, [], 'the file is not known any more');
    assert.deepEqual(PS.jobRow(job({ state: 'failed' }), o({ sources: new Set(['j1']) })).actions, ['again']);
    assert.deepEqual(PS.jobRow(job({ state: 'canceled' }), o({ sources: new Set(['j1']) })).actions, ['again']);
    assert.equal(PS.jobRow(job({ state: 'failed' }), o()).tone, 'err');
    // no connection: an open job says of when its state is
    const stale = PS.jobRow(job({ state: 'waiting', expiresAt: null }), o({ stale: true, fetchedAt: local(11, 17, 48) }));
    assert.equal(stale.why, 'print.wait.plain(print.wait.off) print.jobs.stale(17:48)');
    assert.equal(PS.jobRow(job({ state: 'done' }), o({ stale: true, fetchedAt: local(11, 17, 48) })).why, '');
  });

  it('jobs in the making: the upload in per cent, a failed one keeps its reason', () => {
    const tr = (x = {}) => ({ id: 't1', name: 'Haushaltsbuch 2026.xlsx', size: 1000, from: 'pc', device: 'HP OfficeJet 8020', deviceId: 'u:hp', copies: 1, color: true, duplex: false, media: null, source: null, phase: 'uploading', sent: 620, total: 1000, code: null, error: null, left: null, pages: null, at: NOW - 5000, ...x });
    const r = PS.transferRow(tr(), o());
    assert.deepEqual([r.key, r.kind, r.chip, r.bar, r.actions, r.open, r.steps], ['t:t1', 'transfer', { text: 'print.state.uploading(62)', tone: 'info' }, 62, ['cancel'], true, null]);
    assert.equal(r.meta, 'HP OfficeJet 8020 · print.meta.copies.one(1) · print.meta.color · print.meta.justNow');
    assert.deepEqual([PS.transferRow(tr({ phase: 'waiting', sent: 0 }), o()).chip.text, PS.transferRow(tr({ phase: 'waiting', sent: 0 }), o()).bar], ['print.state.queuedLocal', 0]);
    assert.equal(PS.transferRow(tr({ phase: 'loading' }), o()).chip.text, 'print.state.loading');
    assert.deepEqual([PS.transferRow(tr({ phase: 'sending', sent: 1000 }), o()).chip.text, PS.transferRow(tr({ phase: 'sending', sent: 1000 }), o()).bar], ['print.state.creating', 100]);
    const f = PS.transferRow(tr({ phase: 'failed', code: 'limit', left: 14, pages: 25 }), o());
    assert.deepEqual([f.tone, f.chip, f.why, f.bar, f.actions, f.open], ['err', { text: 'print.state.notSent', tone: 'err' }, 'print.err.limit(25,14)', null, ['again', 'remove'], false]);
    assert.equal(PS.percent({ sent: 5, total: 0 }), 0);
    assert.equal(PS.percent({ sent: 2000, total: 1000 }), 100);
  });

  it('the list: jobs in the making first, then the newest job; the number of open ones', () => {
    const jobs = [job({ id: 'a', at: local(11, 9, 0), state: 'done' }), job({ id: 'b', at: local(11, 17, 0) }), job({ id: 'c', at: local(11, 12, 0), state: 'failed' })];
    const transfers = [{ id: 't1', name: 'eins', phase: 'uploading', sent: 1, total: 2, copies: 1, at: NOW }, { id: 't2', name: 'zwei', phase: 'failed', code: 'format', copies: 1, at: NOW }];
    assert.deepEqual(PS.rows(o({ jobs, transfers })).map((r) => r.key), ['t:t2', 't:t1', 'j:b', 'j:c', 'j:a']);
    assert.equal(PS.openCount(jobs, transfers), 2);
    assert.equal(PS.openCount([], []), 0);
    assert.equal(PS.openCount(null, null), 0);
  });

  it('newer answers of single jobs replace the list\'s rows; jobs made since stand in front', () => {
    const list = [job({ id: 'a', updatedAt: 100, state: 'printing' }), job({ id: 'b', updatedAt: 100 })];
    const fresh = new Map([['a', job({ id: 'a', updatedAt: 200, state: 'done' })], ['b', job({ id: 'b', updatedAt: 50, state: 'failed' })], ['n', job({ id: 'n', updatedAt: 300 })]]);
    assert.deepEqual(PS.mergeJobs(list, fresh).map((j) => `${j.id}:${j.state}`), ['n:queued', 'a:done', 'b:queued']);
    assert.deepEqual(PS.mergeJobs(null, null), []);
  });
});

describe('asking for open jobs again', () => {
  it('often at first, then less; a waiting job every two minutes; a stopped one every 15 s', () => {
    assert.equal(PS.pollDelay(job({ state: 'queued' }), 0), 5000);
    assert.equal(PS.pollDelay(job({ state: 'printing' }), 119000), 5000);
    assert.equal(PS.pollDelay(job({ state: 'printing' }), 3 * 60000), 20000);
    assert.equal(PS.pollDelay(job({ state: 'sending' }), 20 * 60000), 60000);
    assert.equal(PS.pollDelay(job({ state: 'waiting' }), 0), 120000);
    assert.equal(PS.pollDelay(job({ state: 'printing', message: 'media-empty' }), 30 * 60000), 15000);
  });

  it('no answer: 5 s, 10 s, 20 s … at most 5 minutes', () => {
    assert.deepEqual([1, 2, 3, 4, 5, 6, 7, 8, 50].map(PS.backoff), [5000, 10000, 20000, 40000, 80000, 160000, 300000, 300000, 300000]);
    assert.equal(PS.backoff(0), 5000);
  });

  it('only open jobs are followed, and not for ever', () => {
    assert.equal(PS.tracked(job({ state: 'waiting' }), NOW), true);
    assert.equal(PS.tracked(job({ state: 'done' }), NOW), false);
    assert.equal(PS.tracked(job({ state: 'canceled' }), NOW), false);
    assert.equal(PS.tracked(job({ state: 'waiting', at: NOW - 26 * 3600000 }), NOW), false);
    assert.equal(PS.tracked(job({ state: 'queued', at: null }), NOW), true);
  });
});

describe('errors, states and notifications', () => {
  it('error codes in words: the plugin\'s, the upload\'s, the app\'s', () => {
    const e = (code, x = {}) => PS.errorText({ ok: false, code, ...x }, t);
    assert.equal(e('limit', { left: 14, pages: 25 }), 'print.err.limit(25,14)');
    assert.equal(e('limit'), 'print.err.limitPlain');
    assert.equal(e('office_off'), 'print.err.office_off');
    assert.equal(e('unsupported_type'), 'print.err.format');
    assert.equal(e('quarantined'), 'print.err.infected');
    assert.equal(e('scan_pending'), 'print.err.scan');
    assert.equal(e('quota_exceeded'), 'print.err.quota');
    assert.equal(e('forbidden'), 'print.err.no_right');
    assert.equal(e('missing'), 'print.err.read');
    assert.equal(e('network'), 'print.err.network');
    assert.equal(e('not_picked'), 'print.err.source_gone');
    // a code the app has no words for: the plugin's sentence, else the plain one
    assert.equal(e('brand_new', { error: 'Der Drucker schläft.', status: 409 }), 'Der Drucker schläft.');
    assert.equal(e('brand_new', { error: 'brand_new', status: 409 }), 'print.err.failed');
    assert.equal(e('http_500', { error: 'HTTP 500', status: 500 }), 'print.err.failed');
    assert.equal(PS.errorText(null, t), 'print.err.failed');
  });

  it('what the page shows instead of the list', () => {
    const ov = { rights: RIGHTS, printers: [HP], jobs: [] };
    assert.equal(PS.gate({ state: 'available' }, ov, null), null);
    assert.equal(PS.gate({ state: 'available' }, null, null), null, 'still loading');
    assert.equal(PS.gate({ state: 'unavailable' }, ov, null), 'unavailable');
    assert.equal(PS.gate({ state: 'available' }, null, { ok: false, code: 'unavailable', status: 404 }), 'unavailable');
    assert.equal(PS.gate({ state: 'available' }, null, { ok: false, code: 'network' }), 'error');
    assert.equal(PS.gate({ state: 'available' }, ov, { ok: false, code: 'network' }), null, 'the last copy stays');
    assert.equal(PS.gate({ state: 'available' }, { ...ov, rights: { ...RIGHTS, print: false }, printers: [] }, null), 'noRight');
    assert.equal(PS.gate({ state: 'available' }, { ...ov, printers: [] }, null), 'noPrinter');
  });

  it('the print context of an inbox entry', () => {
    assert.deepEqual(PS.entryContext({ topic: 'plugin:gatecontrol-print:print_done', collapse_key: 'print-j1' }), { type: 'print', kind: 'done', jobId: 'j1' });
    assert.deepEqual(PS.entryContext({ topic: 'plugin:gatecontrol-print:print_failed', collapse_key: null }), { type: 'print', kind: 'failed', jobId: null });
    assert.equal(PS.entryContext({ topic: 'plugin:gatecontrol-print:scan_done' }), null);
    assert.equal(PS.entryContext({ topic: 'plugin:gatecontrol-drive:deadline' }), null);
    assert.equal(PS.entryContext(null), null);
  });

  it('Strg+P in Drive is the selection\'s print key — never while typing, never with Umschalt', () => {
    assert.equal(BS.keyAction({ key: 'p', ctrlKey: true }), 'print');
    assert.equal(BS.keyAction({ key: 'P', metaKey: true }), 'print');
    assert.equal(BS.keyAction({ key: 'p', ctrlKey: true, shiftKey: true }), null);
    assert.equal(BS.keyAction({ key: 'p', ctrlKey: true, altKey: true }), null);
    assert.equal(BS.keyAction({ key: 'p' }), null);
    assert.equal(BS.keyAction({ key: 'p', ctrlKey: true }, { target: { editable: true } }), null);
  });
});

describe('page wiring', () => {
  const read = (...p) => fs.readFileSync(path.join(ROOT, 'src', 'renderer', ...p), 'utf8');
  const html = read('index.html');
  const view = read('print-view.js');
  const state = read('print-state.js');
  const renderer = read('renderer.js');
  const driveView = read('drive-view.js');
  const code = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

  it('loads state before view before Drive and the renderer, has the page, the nav entry with its number and the styles', () => {
    const i = (s) => html.indexOf(s);
    assert.ok(i('<script src="print-state.js">') > 0);
    assert.ok(i('<script src="print-state.js">') < i('<script src="print-view.js">'));
    assert.ok(i('<script src="print-view.js">') < i('<script src="drive-view.js">'));
    assert.ok(i('<script src="print-view.js">') < i('<script src="renderer.js">'));
    assert.match(html, /id="page-drucken"/);
    assert.match(html, /id="nav-drucken"[^>]*data-page="drucken"[^>]*hidden/);
    assert.match(html, /id="print-badge" hidden/);
    assert.match(html, /href="styles\/print\.css"/);
    assert.ok(fs.existsSync(path.join(ROOT, 'src', 'renderer', 'styles', 'print.css')));
  });

  it('the entry "Drucken" follows "Drive" and is hidden until the server offers the plugin', () => {
    const navs = [...html.matchAll(/<button class="nav[^"]*" id="(nav-[a-z]+)"/g)].map((m) => m[1]);
    const at = navs.indexOf('nav-drucken');
    assert.deepEqual(navs.slice(at - 1, at + 1), ['nav-drive', 'nav-drucken']);
    assert.match(renderer, /\$\('#nav-drucken'\)\.hidden = !show/);
    assert.match(renderer, /const PAGES = \[[^\]]*'drive', 'drucken'/);
    // Drive gets the print hook only while there is a print page
    assert.match(renderer, /print: printView \? \{ on: \(\) => printView\.usable\(\), can: \(n\) => printView\.canPrint\(n\), go: \(ids\) => printView\.printDrive\(ids\) \} : null/);
  });

  it('server text never goes through innerHTML', () => {
    assert.doesNotMatch(code(view), /innerHTML|insertAdjacentHTML|outerHTML|document\.write/);
    assert.doesNotMatch(code(state), /innerHTML|document\./);
  });

  it('the page never names a file by its path: tokens, File objects and Drive ids only', () => {
    const src = code(view);
    assert.doesNotMatch(src, /\.path\b|getPathForFile|file:\/\//);
    // the only ways a file reaches the core
    assert.deepEqual([...new Set([...src.matchAll(/api\.(pick|addDropped|addDrive|submit|again|forget)\(/g)].map((m) => m[1]))].sort(), ['addDrive', 'addDropped', 'again', 'forget', 'pick', 'submit']);
    assert.match(src, /api\.submit\(\{ tokens, \.\.\.m\.submit \}\)/);
  });

  it('Drive offers printing only through the hook, and never for what the scan blocks', () => {
    const src = code(driveView);
    assert.match(src, /if \(printHook && !acts\.blocked && printHook\.can\(n\)\) item\('print'/);
    assert.match(src, /if \(act === 'print'\) \{\s*if \(!printHook \|\| !printHook\.on\(\) \|\| !items\.length\) return;/);
    // without the plugin (or the right) neither the selection's entry nor the key hint shows
    assert.match(src, /\.\.\.\(printHook && printHook\.on\(\) \? \[\{ key: 'print'/);
    assert.match(src, /printHook && printHook\.on\(\) \? item\(\[k\(ctrl\), '\+', k\('P'\)\]/);
    assert.match(src, /can: \(n\) => !!n && !n\.isDir && o\.print\.can\(n\)/);
  });

  it('the styles use the app\'s tokens: no colours of their own', () => {
    const css = read('styles', 'print.css').replace(/\/\*[\s\S]*?\*\//g, '');
    assert.deepEqual([...css.matchAll(/#[0-9a-fA-F]{3,8}\b/g)].map((m) => m[0]), []);
    assert.doesNotMatch(css, /!important|rgba?\(/);
  });

  it('every print.* key of the app exists in the core locales (de and en), and every key there is used', (t2) => {
    let dir = null;
    try { dir = path.dirname(require.resolve(`${CORE_PKG}/package.json`, { paths: [ROOT] })); } catch {
      for (const d of [path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) if (fs.existsSync(path.join(d, 'src', 'i18n', 'locales', 'de.json'))) { dir = d; break; }
    }
    const loc = (l) => (dir ? JSON.parse(fs.readFileSync(path.join(dir, 'src', 'i18n', 'locales', `${l}.json`), 'utf8')) : null);
    const de = loc('de');
    if (!de || !de.print) { t2.skip('core without print.* (core.ref before Drucken)'); return; }
    const en = loc('en');
    const get = (obj, k) => k.split('.').reduce((x, p) => (x && typeof x === 'object' ? x[p] : undefined), obj);
    const src = `${view}\n${state}\n${renderer}\n${driveView}\n${read('drive-vault-viewer.js')}\n${read('drive-photos-view.js')}`;
    const keys = new Set([...src.matchAll(/['`](print\.[a-zA-Z0-9_.]+[a-zA-Z0-9_])['`]/g)].map((m) => m[1]));
    // keys built from a variable part
    const add = (prefix, list) => { for (const k of list) keys.add(`${prefix}.${k}`); };
    for (const k of ['navCount', 'jobs.open', 'jobs.foot', 'jobs.sent', 'meta.pages', 'meta.copies', 'dialog.files', 'rejected.more']) add(`print.${k}`, ['one', 'other']);
    add('print.kind', ['pdf', 'image', 'text', 'office', 'docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp', 'rtf']);
    add('print.printer.note', ['off', 'busy', 'stopped', 'cert']);
    add('print.steps', ['gc', 'gateway', 'printer', 'done']);
    add('print.stop', ['paper', 'jam', 'open', 'ink', 'tray', 'full', 'held', 'stopped']);
    add('print.wait', ['off', 'busy', 'notAccepting', 'cert', 'office']);
    add('print.fail', ['format', 'convert', 'convertLarge', 'office', 'officeTimeout', 'rejected', 'atPrinter', 'expired', 'device', 'failed']);
    add('print.err', ['network', 'timeout', 'not_configured', 'too_large', 'format', 'damaged', 'printer_format', 'gateway_update', 'convert_off', 'office_off', 'office_missing', 'quota', 'infected', 'scan',
      'no_right', 'read', 'empty', 'folder', 'too_many', 'unavailable', 'offline', 'cert_changed', 'not_found', 'busy', 'vault_locked', 'source_gone', 'invalid']);
    add('print.paper', ['a3', 'a4', 'a5', 'a6', 'letter', 'legal', 'photo10x15', 'photo13x18', 'photo9x13']);
    add('print.tray', ['auto', 'main', 'manual', 'photo', 'bypass', 'envelope', 'top', 'middle', 'bottom', 'rear', 'side']);
    for (const k of ['unavailable', 'noRight', 'noPrinter']) add(`print.empty.${k}`, ['title', 'text']);
    add('print.empty.error', ['title']);
    for (const k of ['cancel', 'again', 'remove']) { keys.add(`print.jobs.${k}`); keys.add(`print.jobs.${k}Of`); }
    assert.ok(keys.size > 150, `found ${keys.size} keys`);
    // a plural key names the object with its forms
    const there = (l, k) => { const v = get(l, k); return typeof v === 'string' || (!!v && typeof v.one === 'string' && typeof v.other === 'string'); };
    for (const k of keys) {
      assert.ok(there(de, k), `${k} missing in core de.json`);
      assert.ok(there(en, k), `${k} missing in core en.json`);
    }
    // … and nothing in the locales that the app never shows
    const flat = (obj, prefix, out = []) => { for (const [k, v] of Object.entries(obj)) { if (v && typeof v === 'object') flat(v, `${prefix}.${k}`, out); else out.push(`${prefix}.${k}`); } return out; };
    assert.deepEqual(flat(de.print, 'print').filter((k) => !keys.has(k)), []);
  });
});
