'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive 1.14 on the page "Drive" (only with the features `me` reports; the plugin is the core's fake Drive server,
// support/drive-mock.js): "Fristen" by month with "In den Familienkalender", a question in the search field with its
// sources and the deadline of a source, "In Dokument umwandeln" ("Scan prüfen" → Excel by Drive, the original into the
// trash), the bar "Vorschlag · Ablegen als …" after an upload, photos by content with the chips of the hits.
// Selectors by id/class, texts in both languages.

const tool = (root, view) => root.locator(`.dv-tool[data-view="${view}"]`);

async function openDrive(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  return page.locator('#page-drive');
}

test.describe('drive 1.14', () => {
  test('nothing new on a Drive without the features', async ({ launchApp, mock }) => {
    await mock.setDrive({ features: ['docAi', 'photos'] });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(root.locator('.dv-row[data-id="11"]')).toBeVisible();
    await expect(root.locator('.dv-ki-modes')).toBeHidden();
    await root.locator('.dv-row[data-id="11"] .dv-more-btn').click();
    await expect(page.locator('.dv-menu-item', { hasText: /In Dokument umwandeln|Convert to document/ })).toHaveCount(0);
    await page.keyboard.press('Escape');
    await tool(root, 'deadlines').click();
    await expect(root.locator('.dv-ki-cal')).toHaveCount(0);
    await tool(root, 'photos').click();
    await expect(root.locator('.dpv-q')).toHaveCount(0);
  });

  test('"Fristen" by month, into the family calendar; a question with its sources and the deadline of a source', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['docAi', 'deadlineCalendar', 'docAsk'] });
    d.srv.setInsight(12, {
      kind: 'insurance', title: 'Kfz-Versicherung',
      deadlines: [{ kind: 'cancellation', date: '2099-11-30', label: 'Kfz-Versicherung kündigen' }, { kind: 'warranty', date: '2099-12-12', label: 'Geschirrspüler' }],
    });
    d.srv.answer = (q) => (/Kfz/.test(q) ? {
      status: 'answered', answer: 'Die Kfz-Versicherung läuft bis 31.12.2099. Kündigen kannst du bis 30.11.2099.', terms: ['Kfz'],
      sources: [{ nodeId: 12, name: 'Brief.pdf', path: 'Dokumente', page: 1, quote: 'Vertragslaufzeit bis 31.12.2099' }],
    } : null);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(root.locator('.dv-row[data-id="10"]')).toBeVisible();

    // "Fristen": a month each, the tags, the family calendar
    await tool(root, 'deadlines').click();
    await expect(root.locator('.dv-dl-group[data-month]')).toHaveCount(2);
    const kfz = root.locator('.dv-ki-dl').first();
    await expect(kfz.locator('.dv-ki-tag')).toHaveText(/Kündigung|Cancellation/);
    await expect(kfz.locator('.dv-ki-dl-title')).toHaveText('Kfz-Versicherung kündigen');
    await expect(kfz.locator('.dv-dl-file')).toHaveText(/Brief\.pdf/);
    await expect(root.locator('.dv-ki-dl').nth(1).locator('.dv-ki-tag')).toHaveText(/Garantieende|Warranty ends/);
    await page.screenshot({ path: test.info().outputPath('drive-fristen.png') });
    await kfz.locator('.dv-ki-cal').click();
    await expect(kfz.locator('.dv-ki-cal')).toHaveText(/Im Familienkalender|In family calendar/);
    await expect(kfz.locator('.dv-ki-cal')).toBeDisabled();
    expect(d.srv.state.calendarCalls.length).toBe(1);

    // a question: "?" at the end turns the chip to "Fragen", Enter asks
    const q = root.locator('.dv-search-in');
    await q.fill('Wann läuft die Kfz-Versicherung ab?');
    await expect(root.locator('.dv-ki-modes [data-mode="ask"]')).toHaveAttribute('aria-checked', 'true');
    await q.press('Enter');
    const card = root.locator('.dv-ki-answer');
    await expect(card.locator('.dv-ki-answer-tx')).toHaveText(/läuft bis 31\.12\.2099/);
    await expect(card.locator('.dv-ki-src')).toHaveCount(1);
    await expect(card.locator('.dv-ki-quote')).toHaveText('„Vertragslaufzeit bis 31.12.2099“');
    await expect(root.locator('.dv-ki-hint')).toHaveText(/Tresore werden nie durchsucht|Vaults are never searched/);
    // the source's other deadline (the first one is in the calendar already)
    await expect(card.locator('.dv-ki-cal')).toHaveText(/Frist in den Familienkalender|Add deadline to family calendar/);
    await page.screenshot({ path: test.info().outputPath('drive-ask.png') });
    await card.locator('.dv-ki-cal').click();
    await expect.poll(() => d.srv.state.calendarCalls.length).toBe(2);
    expect(d.srv.state.askCalls[0].q).toBe('Wann läuft die Kfz-Versicherung ab?');

    // nothing found: what was searched; the chip "Fragen" asks without "?"
    await root.locator('.dv-ki-modes [data-mode="ask"]').click();
    await q.fill('Wo liegt der Mietvertrag');
    await q.press('Enter');
    await expect(root.locator('.dv-ki-answer.is-none')).toContainText(/nichts gefunden|found nothing/);
    await expect(root.locator('.dv-ki-answer.is-none')).toContainText(/Mietvertrag/);
    // "Dateien": the file search again
    await root.locator('.dv-ki-modes [data-mode="files"]').click();
    await q.fill('Brief');
    await expect(root.locator('.dv-row[data-id="12"]')).toBeVisible();
    expect(d.srv.state.askCalls.length).toBe(2);
  });

  test('"In Dokument umwandeln": "Scan prüfen" with the formats, Excel by Drive, the original into the trash', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['scanDocs', 'docAi'] });
    d.srv.scanKind = 'table';
    d.srv.setInsight(11, { kind: 'statement', suggestion: { folderId: 10, folderPath: 'Dokumente', name: '2026 Zählerstände.jpg' } });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await root.locator('.dv-row[data-id="11"] .dv-more-btn').click();
    await page.locator('.dv-menu-item', { hasText: /In Dokument umwandeln|Convert to document/ }).click();
    const dlg = page.locator('.dv-dlg.dv-ki-scan');
    await expect(dlg.locator('.dv-ki-ok')).toHaveText(/Tabelle|Table/);
    await expect(dlg.locator('.dv-ki-kind')).toContainText('3 Spalten, 12 Zeilen, Summenzeile');
    await expect(dlg.locator('.dv-chip')).toHaveCount(4);
    await expect(dlg.locator('.dv-chip[data-format="xlsx"]')).toHaveAttribute('aria-checked', 'true');
    await expect(dlg.locator('.dv-ki-name-in')).toHaveValue('2026 Zählerstände');
    await expect(dlg.locator('.dv-ki-ext')).toHaveText('.xlsx');
    await expect(dlg.locator('.dv-ki-folder')).toHaveText(/Dokumente/);
    await expect(dlg.locator('.dv-ki-save')).toHaveText(/Als Excel-Datei speichern|Save as Excel file/);
    await expect(dlg.locator('.dv-ki-cost')).toHaveText(/KI-Anbieter|AI provider/);
    // the formats change the preview and the button
    await dlg.locator('.dv-chip[data-format="docx"]').click();
    await expect(dlg.locator('.dv-ki-preview')).toContainText(/Word-Tabelle|Word table/);
    await expect(dlg.locator('.dv-ki-save')).toHaveText(/Word/);
    await dlg.locator('.dv-chip[data-format="image"]').click();
    await expect(dlg.locator('.dv-ki-keep')).toHaveCount(0);
    await dlg.locator('.dv-chip[data-format="xlsx"]').click();
    await page.screenshot({ path: test.info().outputPath('drive-scan.png') });
    // "Original-Scan behalten" off
    await dlg.locator('.dv-ki-keep').click();
    await expect(dlg.locator('.dv-ki-keep')).toHaveAttribute('aria-checked', 'false');
    await dlg.locator('.dv-ki-save').click();
    await expect(dlg).toHaveCount(0);
    await expect.poll(() => d.srv.state.convertCalls.length).toBe(1);
    expect(d.srv.state.convertCalls[0]).toMatchObject({ target: 'xlsx', kind: 'table', folderId: 10, name: '2026 Zählerstände.xlsx', keepOriginal: false });
    await expect.poll(() => d.srv.state.nodes.get(11).deleted).toBe(true);
    expect(await page.evaluate(() => localStorage.getItem('gc.drive.scan.keep'))).toBe('0');
  });

  test('printed text → a searchable PDF: on Windows made on this PC (Windows OCR, no AI), elsewhere by Drive', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['scanDocs'] });
    d.srv.scanKind = 'printed';
    const jpeg = fs.readFileSync(path.join(__dirname, 'fixtures', 'scan-printed.jpg'));
    const pic = d.srv.mutate.photo(1, 'Brief Stadtwerke.jpg', { content: jpeg });
    const win = process.platform === 'win32';
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await root.locator(`.dv-row[data-id="${pic.id}"] .dv-more-btn`).click();
    await page.locator('.dv-menu-item', { hasText: /In Dokument umwandeln|Convert to document/ }).click();
    const dlg = page.locator('.dv-dlg.dv-ki-scan');
    await expect(dlg.locator('.dv-ki-ok')).toHaveText(/Gedruckter Text|Printed text/);
    await expect(dlg.locator('.dv-chip[data-format="pdf"]')).toHaveAttribute('aria-checked', 'true');
    await expect(dlg.locator('.dv-chip[data-format="xlsx"]')).toHaveCount(0);
    await expect(dlg.locator('.dv-ki-cost')).toHaveText(win ? /auf diesem PC|on this PC/ : /KI-Anbieter|AI provider/);
    // text first: on Windows the words read here go to classify
    const cls = d.srv.state.classifyCalls[0];
    if (win) expect(cls.text).toMatch(/Rechnung/);
    else expect(cls.text).toBeUndefined();
    await dlg.locator('.dv-ki-save').click();
    await expect(dlg).toHaveCount(0);
    const made = () => [...d.srv.state.nodes.values()].find((n) => n.name === 'Brief Stadtwerke.pdf');
    await expect.poll(() => !!made()).toBe(true);
    if (win) {
      expect(d.srv.state.convertCalls.length).toBe(0);
      const commit = d.srv.state.commits.find((c) => c.name === 'Brief Stadtwerke.pdf');
      expect(commit.text).toMatch(/Betrag 84[,.]20/);
      const pdf = d.srv.state.media.get(made().mediaId).data.toString('latin1');
      expect(pdf.startsWith('%PDF-1.4')).toBe(true);
      expect(pdf).toContain('/DCTDecode');
    } else {
      expect(d.srv.state.convertCalls[0]).toMatchObject({ target: 'pdf', kind: 'printed', name: 'Brief Stadtwerke.pdf' });
    }
    // the original stays ("Original-Scan behalten" is on by default)
    expect(d.srv.state.nodes.get(pic.id).deleted).toBe(false);
  });

  test('"Ablegen" after an upload: the suggestion with the payment reminder taken', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['docAi'] });
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-e2e-114-'));
    const scan = path.join(dir, 'Scan 2026-11-03 09.14.pdf');
    fs.writeFileSync(scan, '%PDF-1.4 Rechnung Stadtwerke');
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(root.locator('.dv-row[data-id="10"]')).toBeVisible();
    await page.evaluate((p) => window.gatecontrol.drive.upload(1, [p]), scan);
    let id = null;
    await expect.poll(() => { const n = [...d.srv.state.nodes.values()].find((x) => x.name === 'Scan 2026-11-03 09.14.pdf'); id = n ? n.id : null; return id; }).not.toBeNull();
    // Drive recognised it a moment later
    d.srv.setInsight(id, {
      kind: 'invoice', suggestion: { folderId: 10, folderPath: 'Dokumente', name: '2026-11-03 Stadtwerke Rechnung.pdf' },
      deadlines: [{ kind: 'payment', date: '2099-11-28', label: 'Stadtwerke' }],
    });
    const bar = root.locator('.dv-ki-bar');
    await expect(bar).toBeVisible({ timeout: 20000 });
    await expect(bar.locator('.dv-ki-name')).toHaveText('2026-11-03 Stadtwerke Rechnung.pdf');
    await expect(bar.locator('.dv-ki-path')).toHaveText(/Dokumente/);
    await expect(bar.locator('.dv-ki-check')).toContainText(/28\.11\.|28 Nov/);
    await page.screenshot({ path: test.info().outputPath('drive-ablegen.png') });
    await bar.locator('.dv-ki-take').click();
    await expect(bar).toBeHidden();
    await expect.poll(() => d.srv.state.nodes.get(id).parentId).toBe(10);
    expect(d.srv.state.nodes.get(id).name).toBe('2026-11-03 Stadtwerke Rechnung.pdf');
    await expect.poll(() => (d.srv.state.deadlines.find((x) => x.nodeId === id).reminder || {}).daysBefore).toBe(3);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('photos by content: the hits, the chips, a chip adds its word', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['photos', 'photoSearch'] });
    const a = d.srv.mutate.photo(1, 'Strand.jpg', { takenAt: Date.now() - 3600000 });
    const b = d.srv.mutate.photo(1, 'Abend.jpg', { takenAt: Date.now() - 7200000 });
    d.srv.mutate.photo(1, 'Hund.jpg');
    d.srv.state.labels.set(a.id, ['Strand', 'Meer']);
    d.srv.state.labels.set(b.id, ['Strand', 'Sonnenuntergang']);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await tool(root, 'photos').click();
    const pv = root.locator('.dpv');
    await expect(pv.locator('.dpv-tile').first()).toBeVisible();
    await pv.locator('.dpv-q').fill('Strand');
    await pv.locator('.dpv-q').press('Enter');
    await expect(pv.locator('.dpv-tile')).toHaveCount(2);
    await expect(pv.locator('.dpv-hits')).toContainText(/2 Fotos|2 photos/);
    await expect(pv.locator('.dpv-chips .dv-chip.is-on')).toHaveText('Strand');
    await expect(pv.locator('.dpv-chips .dv-chip[data-term="Meer"]')).toHaveText('+ Meer');
    await expect(pv.locator('.dpv-search-note')).toBeVisible();
    await page.screenshot({ path: test.info().outputPath('drive-photo-search.png') });
    await pv.locator('.dpv-chips .dv-chip[data-term="Meer"]').click();
    await expect(pv.locator('.dpv-q')).toHaveValue('Strand Meer');
    await expect(pv.locator('.dpv-tile')).toHaveCount(1);
    await pv.locator('.dpv-q').press('Escape');
    await expect(pv.locator('.dpv-month .dpv-tile')).toHaveCount(4);
  });
});
