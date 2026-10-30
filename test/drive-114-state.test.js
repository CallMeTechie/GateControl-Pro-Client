'use strict';

// Drive 1.14 on the page "Drive" (no DOM, drive-ki-state.js): "Fristen" by month with the family calendar, the bar
// "Vorschlag · Ablegen als …" after an upload, "Scan prüfen" (formats per kind, the texts, name and folder), the
// question in the search field and its answer card, the chips of a photo search; that the page loads the new
// scripts, never uses innerHTML there, and that every key they use exists in de and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const KS = require('../src/renderer/drive-ki-state');
const DS = require('../src/renderer/drive-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const at = (y, mo, d, h = 0, m = 0) => new Date(y, mo - 1, d, h, m).getTime();
const NOW = at(2026, 11, 3, 9, 30);
const node = (id, name, parentId = 10) => ({ id, name, parentId, areaId: 'mine:2' });

describe('"Fristen" (D2)', () => {
  const list = [
    { id: 1, kind: 'payment', date: '2026-11-01', label: 'Stadtwerke', node: node(5, 'Alt.pdf') },
    { id: 2, kind: 'cancellation', date: '2026-11-30', label: 'Kfz-Versicherung kündigen', reminder: null, calendar: null, node: node(6, 'Versicherungsschein Kfz 2026.pdf') },
    { id: 3, kind: 'payment', date: '2026-11-28', label: null, node: node(7, 'Rechnung.pdf') },
    { id: 4, kind: 'warranty', date: '2026-12-12', label: 'Geschirrspüler', calendar: { eventId: 'e', at: 1 }, node: node(8, 'Kaufbeleg.pdf') },
    { id: 5, kind: 'renewal', date: '2027-01-31', label: 'Fitnessstudio', node: node(9, 'Vertrag.pdf') },
    { id: 6, kind: 'payment', date: '2027-01-31' },
  ];

  it('by month, overdue first; kind, day and "in N Tagen", the file, the family calendar only with the feature', () => {
    const m = KS.deadlineMonths(list, { t, locale: 'de', now: NOW, calendar: true });
    assert.deepEqual(m.map((g) => g.key), ['past', '2026-11', '2026-12', '2027-01']);
    assert.equal(m[0].title, 'drive.deadline.group.past');
    assert.match(m[1].title, /November 2026/);
    assert.deepEqual(m[1].items.map((c) => c.id), [3, 2]);
    const kfz = m[1].items[1];
    assert.equal(kfz.tag, 'drive.ki.dl.tag.cancellation');
    assert.match(kfz.day, /^Mo\.? 30\.11\.$/);
    assert.equal(kfz.when, 'drive.deadline.inDays(count=27)');
    assert.equal(kfz.title, 'Kfz-Versicherung kündigen');
    assert.equal(kfz.file, 'Versicherungsschein Kfz 2026.pdf');
    assert.equal(kfz.canCalendar, true);
    assert.equal(kfz.calendar, false);
    assert.deepEqual(KS.calendarButton(kfz, t), { label: 'drive.ki.dl.toCalendar', done: false });
    // a deadline without a label is called by its kind
    assert.equal(m[1].items[0].title, 'drive.ki.dl.tag.payment');
    assert.deepEqual(KS.calendarButton(m[2].items[0], t), { label: 'drive.ki.dl.inCalendar', done: true });
    // renewal: the day to cancel by; far away without "in N Tagen"
    assert.match(m[3].items[0].day, /^drive\.ki\.dl\.cancelBy\(day=So\.? 31\.01\.\)$/);
    assert.equal(m[3].items[0].when, '');
    assert.equal(m[0].items[0].past, true);
    assert.equal(m[0].items[0].canCalendar, false);
    assert.equal(KS.deadlineMonths(list, { t, locale: 'de', now: NOW }).every((g) => g.items.every((c) => !c.canCalendar)), true);
    assert.equal(KS.deadlineTag('birthday', t), 'drive.ki.dl.tag.other');
    assert.match(KS.shortDay('2026-11-30', 'en'), /^Mon 30 Nov$/);
  });
});

describe('"Ablegen" after an upload (D4)', () => {
  it('watches the newest document that went up now — not folders, not what was done before, only with docAi', () => {
    const me = { features: ['docAi'] };
    const seen = new Set(['u1']);
    const rows = [
      { id: 'u1', dir: 'up', state: 'done', nodeId: 1, name: 'Alt.pdf', folderId: 10 },
      { id: 'u2', dir: 'up', state: 'done', nodeId: 2, name: 'Scan.pdf', folderId: 10 },
      { id: 'u3', dir: 'up', state: 'done', nodeId: 3, name: 'Bilder', folderId: 10, folder: true, files: 3 },
      { id: 'u4', dir: 'up', state: 'running', name: 'Groß.pdf', folderId: 10 },
      { id: 'u5', dir: 'up', state: 'done', nodeId: 5, name: 'setup.exe', folderId: 10 },
      { id: 'd1', dir: 'down', state: 'done', nodeId: 6, name: 'x.pdf' },
    ];
    assert.deepEqual(KS.newUpload(rows, seen, { me }), { nodeId: 2, name: 'Scan.pdf', folderId: 10 });
    assert.equal(KS.newUpload(rows, seen, { me }), null);
    assert.equal(KS.newUpload([{ id: 'u9', dir: 'up', state: 'done', nodeId: 9, name: 'a.jpg' }], new Set(), { me: { features: [] } }), null);
  });

  it('the bar: name and folder of the suggestion, the payment to be reminded of; nothing when it is there already', () => {
    const ins = {
      status: 'ready', suggestion: { folderId: 22, folderPath: 'Finanzen/Strom', name: '2026-11-03 Stadtwerke Rechnung.pdf' },
      deadlines: [{ id: 7, kind: 'payment', date: '2099-11-28', reminder: null }],
    };
    const v = KS.fileBar(ins, node(2, 'Scan 2026-11-03 09.14.pdf'), { areaLabel: () => 'Meine Dateien', t, locale: 'de' });
    assert.deepEqual(v, { name: '2026-11-03 Stadtwerke Rechnung.pdf', renamed: true, folder: true, path: 'Meine Dateien › Finanzen › Strom', payment: { id: 7, day: '28.11.' } });
    assert.equal(KS.fileBar(ins, { ...node(2, '2026-11-03 Stadtwerke Rechnung.pdf', 22) }, { areaLabel: () => 'x', t }), null);
    assert.equal(KS.fileBar({ ...ins, status: 'pending' }, node(2, 'a.pdf'), { t }), null);
    const onlyName = KS.fileBar({ status: 'ready', suggestion: { folderId: null, name: 'Neu.pdf' }, deadlines: [{ id: 1, kind: 'payment', date: '2099-01-01', reminder: { daysBefore: 3 } }] }, node(2, 'a.pdf'), { t });
    assert.equal(onlyName.path, null);
    assert.equal(onlyName.payment, null);
  });
});

describe('"Scan prüfen" (D5)', () => {
  it('formats per kind: Excel only for tables, Word not for "nothing", "Nur Bild" only for one page', () => {
    assert.deepEqual(KS.scanFormats('table'), ['pdf', 'docx', 'xlsx', 'image']);
    assert.deepEqual(KS.scanFormats('whiteboard'), ['pdf', 'docx', 'image']);
    assert.deepEqual(KS.scanFormats('other'), ['pdf', 'image']);
    assert.deepEqual(KS.scanFormats('printed', 3), ['pdf', 'docx']);
    assert.deepEqual(['table', 'handwriting', 'whiteboard', 'printed', 'other'].map((k) => KS.scanDefault(k)), ['xlsx', 'docx', 'docx', 'pdf', 'image']);
    assert.equal(KS.scanDefault('other', 2), 'pdf');
    // no PDF possible (no OCR language, no pictures for Drive): the other formats
    assert.deepEqual(KS.scanFormats('printed', 1, false), ['docx', 'image']);
    assert.equal(KS.scanDefault('printed', 1, false), 'docx');
    const v = KS.scanView({ kind: 'printed', pages: 1, pdf: false }, 'pdf', t);
    assert.equal(v.format, 'docx');
    assert.equal(v.noPdf, 'drive.ki.scan.noPdf');
    assert.equal(KS.scanView({ kind: 'other', pages: 1, pdf: false }, null, t).format, 'image');
    assert.equal(KS.scanView({ kind: 'printed', pages: 1 }, null, t).noPdf, '');
  });

  it('the texts of the card, the preview, the cost line and the button', () => {
    const table = { kind: 'table', pages: 1, summary: '3 Spalten, 12 Zeilen, Summenzeile', classified: true, local: false };
    const v = KS.scanView(table, null, t);
    assert.equal(v.format, 'xlsx');
    assert.equal(v.title, 'drive.ki.scan.recognised(kind=drive.ki.scan.kind.table)');
    assert.equal(v.summary, '3 Spalten, 12 Zeilen, Summenzeile');
    assert.equal(v.ask, 'drive.ki.scan.ask.xlsx');
    assert.equal(v.preview, 'drive.ki.scan.preview.xlsx');
    assert.equal(v.cost, 'drive.ki.scan.cost.ai');
    assert.equal(v.save, 'drive.ki.scan.save.xlsx');
    assert.deepEqual(v.chips.map((c) => [c.key, c.on]), [['pdf', false], ['docx', false], ['xlsx', true], ['image', false]]);
    assert.equal(KS.scanView(table, 'docx', t).preview, 'drive.ki.scan.preview.docx.table');
    // printed on this PC: "Erkannt auf diesem PC, ohne KI"
    const printed = KS.scanView({ kind: 'printed', pages: 1, local: true, words: 42, classified: true }, 'pdf', t);
    assert.equal(printed.cost, 'drive.ki.scan.cost.local');
    assert.equal(printed.preview, 'drive.ki.scan.preview.pdfLocal');
    assert.equal(printed.summary, 'drive.ki.scan.words(count=42)');
    assert.equal(KS.scanView({ kind: 'printed', local: false }, 'pdf', t).cost, 'drive.ki.scan.cost.ai');
    assert.equal(KS.scanView({ kind: 'table' }, 'image', t).cost, 'drive.ki.scan.cost.none');
    // a format the kind does not have falls back
    assert.equal(KS.scanView({ kind: 'whiteboard' }, 'xlsx', t).format, 'docx');
    assert.equal(KS.scanView({ kind: 'other', classified: false }, null, t).title, 'drive.ki.scan.unknown');
  });

  it('which files, the name without extension, Drive\'s suggestion first', () => {
    const me = { features: ['scanDocs'] };
    const pic = { id: 1, name: 'Scan.JPG', mime: 'image/jpeg', isDir: false };
    assert.equal(KS.scanAvailable([pic], { me, writable: true }), true);
    assert.equal(KS.scanAvailable([pic], { me, writable: false }), false);
    assert.equal(KS.scanAvailable([pic], { me: { features: [] }, writable: true }), false);
    assert.equal(KS.scanAvailable([{ ...pic, encrypted: true }], { me, writable: true }), false);
    assert.equal(KS.scanAvailable([{ id: 2, name: 'a.pdf', mime: 'application/pdf' }], { me, writable: true }), false);
    assert.equal(KS.scanAvailable(new Array(8).fill(pic), { me, writable: true }), true);
    assert.equal(KS.scanAvailable(new Array(9).fill(pic), { me, writable: true }), false);
    // "Original-Scan behalten": this PC's choice, else Drive's setting, else on
    assert.equal(KS.scanKeep('0', { settings: { scanKeepOriginal: true } }), false);
    assert.equal(KS.scanKeep('1', { settings: { scanKeepOriginal: false } }), true);
    assert.equal(KS.scanKeep(null, { settings: { scanKeepOriginal: false } }), false);
    assert.equal(KS.scanKeep(null, null), true);
    assert.equal(KS.baseName('2026 Zählerstände.jpg'), '2026 Zählerstände');
    assert.equal(KS.baseName('Rechnung v1.2'), 'Rechnung v1.2');
    assert.equal(KS.scanExt('xlsx', 'a.jpg'), '.xlsx');
    assert.equal(KS.scanExt('image', 'a.png'), '.png');
    assert.deepEqual(KS.scanStart({ name: 'IMG_1', folderId: 1, suggestion: { name: '2026 Zählerstände.jpg', folderId: 10, folderPath: 'Haus/Zählerstände' } }), { name: '2026 Zählerstände', folderId: 10, folderPath: 'Haus/Zählerstände' });
    assert.deepEqual(KS.scanStart({ name: 'IMG_1', folderId: 1, suggestion: null }), { name: 'IMG_1', folderId: 1, folderPath: null });
  });
});

describe('questions (D1) and photos by content (D3)', () => {
  const me = { features: ['docAsk'] };
  it('the search field asks with the chip "Fragen" or "?" at the end; "Dateien" searches; never without docAsk', () => {
    assert.equal(KS.asks('Wann läuft die Kfz-Versicherung ab?', 'auto', me), true);
    assert.equal(KS.asks('Kfz Versicherung', 'auto', me), false);
    assert.equal(KS.asks('Kfz Versicherung', 'ask', me), true);
    assert.equal(KS.asks('Wann?', 'files', me), false);
    assert.equal(KS.asks('Wann?', 'ask', { features: [] }), false);
  });

  it('the answer card: sources with folder, page and quote; nothing found with what was searched where', () => {
    const a = { status: 'answered', answer: 'Bis 31.12.2026.', sources: [{ nodeId: 5, name: 'Versicherungsschein Kfz 2026.pdf', path: 'Versicherungen', page: 1, quote: '„Vertragslaufzeit: 01.01.2026 bis 31.12.2026“' }, { nodeId: 6, name: 'AVB.pdf', path: null, page: null, quote: null }], terms: [] };
    const v = KS.answerView(a, { t });
    assert.equal(v.found, true);
    assert.equal(v.count, 'drive.ki.ask.sources.other(count=2)');
    assert.deepEqual(v.sources[0], { nodeId: 5, name: 'Versicherungsschein Kfz 2026.pdf', where: 'Versicherungen · drive.ki.ask.page(page=1)', quote: '„Vertragslaufzeit: 01.01.2026 bis 31.12.2026“' });
    assert.equal(v.sources[1].where, '');
    const n = KS.answerView({ status: 'not_found', answer: null, sources: [], terms: ['Kfz', 'Versicherung'] }, { t, areas: [{ id: 'mine:2', label: 'Meine Dateien' }, { id: 'family:1', label: 'Familie' }], areaLabel: (ar) => ar.label });
    assert.equal(n.found, false);
    assert.equal(n.text, 'drive.ki.ask.nothing');
    assert.equal(n.searched, 'drive.ki.ask.searched(terms=Kfz, Versicherung,where=Meine Dateiendrive.ki.ask.andFamilie)');
    // where Drive says it searched
    assert.equal(KS.answerView({ status: 'not_found', terms: ['Miete'], areas: ['Familie Muster'] }, { t, areas: [{ label: 'x' }], areaLabel: (ar) => ar.label }).searched, 'drive.ki.ask.searched(terms=Miete,where=Familie Muster)');
    // "Frist in den Familienkalender": the next deadline of a source not in the calendar yet
    const dls = [
      { id: 1, date: '2099-12-31', node: { id: 5 } },
      { id: 2, date: '2099-11-30', node: { id: 5 } },
      { id: 3, date: '2099-10-01', node: { id: 5 }, calendar: { eventId: 'x' } },
      { id: 4, date: '2099-01-01', node: { id: 99 } },
    ];
    assert.equal(KS.answerDeadline(a, dls, NOW).id, 2);
    // the deadline Drive names with the answer comes first; one in the calendar already: no button
    assert.equal(KS.answerDeadline({ ...a, deadline: { id: 9, date: '2099-01-01', nodeId: 5, calendar: null } }, dls, NOW).id, 9);
    assert.equal(KS.answerDeadline({ ...a, deadline: { id: 9, date: '2099-01-01', nodeId: 5, calendar: { eventId: 'x' } } }, dls, NOW), null);
    assert.equal(KS.answerDeadline({ status: 'not_found' }, dls, NOW), null);
  });

  it('photo search: the words, the chips of the hits ("+ Meer"), a chip adds or takes out its word', () => {
    assert.deepEqual(KS.photoWords('  Strand  strand Meer '), ['Strand', 'Meer']);
    assert.deepEqual(KS.photoChips('Strand', [{ term: 'Meer', count: 12 }, 'Sonnenuntergang', { term: 'strand' }]), [
      { term: 'Strand', on: true, label: 'Strand' }, { term: 'Meer', on: false, label: '+ Meer' }, { term: 'Sonnenuntergang', on: false, label: '+ Sonnenuntergang' },
    ]);
    // Drive's chips: the term to add, the label to show
    assert.deepEqual(KS.photoChips('Strand', [{ term: 'sea', label: 'Meer', count: 2 }, { term: 'strand', label: 'Strand' }]), [
      { term: 'Strand', on: true, label: 'Strand' }, { term: 'sea', on: false, label: '+ Meer' },
    ]);
    assert.equal(KS.photoToggle('Strand', 'Meer'), 'Strand Meer');
    assert.equal(KS.photoToggle('Strand Meer', 'meer'), 'Strand');
  });
});

describe('Drive settings: new deadlines into the family calendar per area', () => {
  it('only with deadlineCalendar, where one writes, when Drive tells the state', () => {
    const areas = [
      { id: 'mine:2', writable: true, deadlinesToCalendar: false },
      { id: 'family:1', writable: true, deadlinesToCalendar: true },
      { id: 'child:7', writable: false, deadlinesToCalendar: false },
      { id: 'team:1', writable: true, archived: true, deadlinesToCalendar: false },
      { id: 'team:2', writable: true, deadlinesToCalendar: null },
    ];
    assert.deepEqual(KS.calendarAreas(areas, { features: ['deadlineCalendar'] }).map((x) => [x.areaId, x.on]), [['mine:2', false], ['family:1', true]]);
    assert.deepEqual(KS.calendarAreas(areas, { features: ['docAi'] }), []);
  });
});

describe('the page', () => {
  it('loads the new scripts before drive-view.js / the photos, no innerHTML, every key in de and en', () => {
    const html = read('src', 'renderer', 'index.html');
    const pos = (f) => html.indexOf(`<script src="${f}"></script>`);
    for (const f of ['drive-ki-state.js', 'drive-ki-view.js']) {
      assert.ok(pos(f) > pos('drive-docs-state.js') && pos(f) < pos('drive-view.js'), f);
      assert.doesNotMatch(read('src', 'renderer', f), /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/, f);
    }
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const src = ['drive-view.js', 'drive-ki-view.js', 'drive-ki-state.js', 'drive-photos-view.js', 'drive-settings-view.js'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set();
    for (const m of src.matchAll(/['"`](drive\.ki\.[A-Za-z0-9_.]+)['"`]/g)) if (!m[1].endsWith('.')) keys.add(m[1]);
    for (const k of [...KS.DEADLINE_KINDS, 'other']) { keys.add(`drive.ki.dl.tag.${k}`); keys.add(`drive.deadline.kind.${k}`); }
    for (const k of KS.SCAN_KINDS) keys.add(`drive.ki.scan.kind.${k}`);
    for (const f of ['pdf', 'docx', 'xlsx', 'image']) { keys.add(`drive.ki.scan.format.${f}`); keys.add(`drive.ki.scan.save.${f}`); keys.add(`drive.ki.scan.ask.${f}`); }
    for (const k of ['printed', 'handwriting', 'table', 'whiteboard']) keys.add(`drive.ki.scan.preview.docx.${k}`);
    for (const k of ['files', 'ask']) keys.add(`drive.ki.ask.mode.${k}`);
    for (const k of Object.values(DS.ERROR_CODES)) keys.add(`drive.err.${k}`);
    assert.ok(keys.size > 60);
    for (const k of keys) {
      assert.ok(typeof de[k] === 'string' && de[k], `de: ${k}`);
      assert.ok(typeof en[k] === 'string' && en[k], `en: ${k}`);
    }
  });
});
