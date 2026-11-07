'use strict';

const crypto = require('crypto');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// A PDF, a text or a Markdown of a normal Drive folder opens in the app's own viewer — the vault viewer's pages
// (drive-vault-viewer.js createDoc: pdf.js on <canvas>, text as text) with the file as "Öffnen" loads it (core
// DriveService.docView) — instead of the default program; "Mit anderem Programm öffnen" in the viewer opens it there
// (the same copy, no second download). A file that is no readable PDF says so and offers the same way out. (Names
// unlike the vault suite's: its check of the temp folder runs after this one.)

/** A small PDF of two pages (text and a blue box) — the bytes of a real document, made here. */
function pdfBytes() {
  const content = Buffer.from(`BT /F1 36 Tf 72 700 Td (Angebot 2026) Tj ET 0 0 1 rg 72 400 300 200 re f`);
  const objs = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R 5 0 R] /Count 2 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 6 0 R >> >> >>',
    null,
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 6 0 R >> >> >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let out = Buffer.from('%PDF-1.4\n');
  const offs = [];
  objs.forEach((o, i) => {
    offs.push(out.length);
    const body = o === null ? Buffer.concat([Buffer.from(`${i + 1} 0 obj\n<< /Length ${content.length} >>\nstream\n`), content, Buffer.from('\nendstream\nendobj\n')]) : Buffer.from(`${i + 1} 0 obj\n${o}\nendobj\n`);
    out = Buffer.concat([out, body]);
  });
  const x = out.length;
  let xref = `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (const o of offs) xref += `${String(o).padStart(10, '0')} 00000 n \n`;
  return Buffer.concat([out, Buffer.from(`${xref}trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${x}\n%%EOF\n`)]);
}

async function openDrive(page) {
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  const root = page.locator('#page-drive');
  const files = root.locator('.dv-pages [data-page="files"]');
  await expect(files.or(root.locator('.dv-gate:visible')).first()).toBeVisible();
  if (await files.isVisible()) await files.click();
  return root;
}

test.describe('drive: the viewer of PDFs and texts', () => {
  test('a PDF drawn by pdf.js, a text decoded, Markdown as text; another program only on purpose', async ({ launchApp, mock }, testInfo) => {
    const d = await mock.setDrive();
    const pdf = d.srv.mutate.photo(10, 'Angebot.pdf', { content: pdfBytes(), mime: 'application/pdf' });
    // "Grüße" from an old Windows editor (Windows-1252, not UTF-8)
    const note = Buffer.from([0x47, 0x72, 0xfc, 0xdf, 0x65, 0x20, 0x80]);
    const txt = d.srv.mutate.photo(10, 'Memo.txt', { content: note, mime: 'text/plain' });
    const md = d.srv.mutate.photo(10, 'Liste.md', { content: '# Liste\n\n- **eins** <script>alert(1)</script>', mime: 'text/markdown' });
    const { page, events } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await root.locator('.dv-row[data-id="10"] .dv-open').click();
    const row = (id) => root.locator(`.dv-row[data-id="${id}"]`);
    await expect(row(pdf.id)).toBeVisible();
    const viewer = page.locator('.dv-dlg.dv-vv[data-doc-viewer="1"]');
    const opened = () => events().filter((e) => e.type === 'shell.openPath' || e.type === 'drive.openPath');

    // a PDF: both pages on <canvas>, no default program, nothing of the vault (no lock, no "im Speicher")
    await row(pdf.id).locator('.dv-open').click();
    await expect(viewer.locator('canvas.dv-vv-page')).toHaveCount(2, { timeout: 30000 });
    await expect(viewer.locator('.dv-vv-tools')).toContainText(/2 Seiten|2 pages/);
    await expect(viewer.locator('.dv-vv-mem')).toHaveCount(0);
    await expect(viewer.locator('.dv-vv-lock')).toHaveCount(0);
    const blue = await viewer.locator('canvas.dv-vv-page').first().evaluate((c) => {
      const px = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
      let n = 0;
      for (let i = 0; i < px.length; i += 4) if (px[i + 2] > 200 && px[i] < 60) n++;
      return n;
    });
    expect(blue).toBeGreaterThan(1000);
    await page.screenshot({ path: testInfo.outputPath('drive-doc-viewer-pdf.png') });
    expect(opened()).toEqual([]);
    await page.keyboard.press('Escape');
    await expect(viewer).toHaveCount(0);

    // a text: decoded (Windows-1252), as text
    await row(txt.id).locator('.dv-open').click();
    await expect(viewer.locator('pre.dv-vv-text')).toHaveText('Grüße €');
    // "Mit anderem Programm öffnen": at once, the copy the viewer loaded
    const gets = d.srv.state.mediaGets.filter((g) => g.mediaId === txt.mediaId).length;
    await viewer.locator('.dv-vv-openwith').click();
    const sha = crypto.createHash('sha256').update(note).digest('hex');
    await expect.poll(() => opened().map((e) => e.sha256)).toContainEqual(sha);
    expect(d.srv.state.mediaGets.filter((g) => g.mediaId === txt.mediaId).length).toBe(gets);
    await expect(viewer).toHaveCount(0);

    // Markdown: elements, the <script> stays text
    await row(md.id).locator('.dv-open').click();
    await expect(viewer.locator('.dv-vv-md h2')).toHaveText('Liste');
    await expect(viewer.locator('.dv-vv-md strong')).toHaveText('eins');
    await expect(viewer.locator('.dv-vv-md script')).toHaveCount(0);
    await page.keyboard.press('Escape');

    // a file that is no readable PDF: the note, the way out stays
    await row(12).locator('.dv-open').click();
    await expect(viewer.locator('.dv-vv-note')).toContainText(/nicht anzeigen|cannot be shown/);
    await expect(viewer.locator('.dv-vv-openwith')).toBeVisible();
  });
});
