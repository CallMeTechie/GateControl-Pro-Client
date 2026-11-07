'use strict';

const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive plugin 1.22 on the page "Drive": a file of a vault opens in the app's own viewer (drive-vault-viewer.js, core
// services/drive-vault-view.js) — a picture through gcvault:, a PDF drawn by pdf.js (vendor/pdfjs), a text, a video
// that plays — with content protection on the window; no other program is started, nothing in plain text lies in the
// temp folder; the vault lock closes the viewer and revokes its URL; an office file gets the note and "Mit anderem
// Programm öffnen" asks first.

const SECRET = 'Tresor-Geheimnis 4711';

/** A small PDF of two pages (text and a blue box) — the bytes of a real document, made here. */
function pdfBytes() {
  const content = Buffer.from(`BT /F1 36 Tf 72 700 Td (${SECRET}) Tj ET 0 0 1 rg 72 400 300 200 re f`);
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

function filesIn(dir) {
  const out = [];
  const walk = (d) => {
    let list = [];
    try { list = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of list) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p); else out.push(p);
    }
  };
  walk(dir);
  return out;
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

test.describe('drive 1.22: the viewer of vault files', () => {
  test('picture, PDF, text, video in memory; content protection; lock closes it; office asks before another program', async ({ launchApp, mock }, testInfo) => {
    const d = await mock.setDrive({ features: ['vault', 'vaultsApart'] });
    const { app, page, events } = await launchApp();
    await app.evaluate(() => globalThis.__gcE2E.useFakeConsent());
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);

    // a vault with four files, uploaded encrypted by the app
    const made = await page.evaluate(() => window.gatecontrol.drive.vault.create(1, 'Privat'));
    expect(made.ok).toBe(true);
    const dir = testInfo.outputPath('src');
    fs.mkdirSync(dir, { recursive: true });
    const fx = path.join(__dirname, 'fixtures');
    fs.copyFileSync(path.join(fx, 'camera-still.jpg'), path.join(dir, 'Foto.jpg'));
    fs.copyFileSync(path.join(fx, 'clip.webm'), path.join(dir, 'Film.webm'));
    fs.writeFileSync(path.join(dir, 'Vertrag.pdf'), pdfBytes());
    fs.writeFileSync(path.join(dir, 'Notiz.md'), `# Zugang\n\n- Keller: **${SECRET}**\n<script>alert(1)</script>\n`);
    fs.writeFileSync(path.join(dir, 'Plan.xlsx'), `PK ${SECRET}`);
    const names = ['Foto.jpg', 'Film.webm', 'Vertrag.pdf', 'Notiz.md', 'Plan.xlsx'];
    await page.evaluate(([id, list]) => window.gatecontrol.drive.upload(id, list), [made.node.id, names.map((n) => path.join(dir, n))]);
    await expect.poll(() => [...d.srv.state.nodes.values()].filter((n) => n.parentId === made.node.id && !n.isDir).length, { timeout: 30000 }).toBe(5);

    // made through the bridge: the page loads its menu again
    await root.locator('.dv-head .dv-ib').first().click();
    const [vault] = [...d.srv.state.vaults.values()];
    const vrow = root.locator(`.dv-vault-item[data-vault="${vault.id}"]`);
    await vrow.click();
    const row = (name) => root.locator('.dv-row', { has: page.locator('.dv-c-name', { hasText: name }) });
    await expect(row('Foto.jpg')).toHaveCount(1);
    const viewer = page.locator('.dv-dlg.dv-vv');
    // content protection is Windows' and macOS' (a no-op on Linux): the calls on the window are recorded
    await app.evaluate(({ BrowserWindow }) => {
      const w = BrowserWindow.getAllWindows()[0];
      const real = w.setContentProtection.bind(w);
      globalThis.__vvProtect = [];
      w.setContentProtection = (on) => { globalThis.__vvProtect.push(on); return real(on); };
    });
    const isProtected = () => app.evaluate(() => { const p = globalThis.__vvProtect; return p.length ? p[p.length - 1] : null; });

    // a picture: through gcvault:, decoded by the page
    await row('Foto.jpg').locator('.dv-open').click();
    await expect(viewer).toBeVisible();
    const img = viewer.locator('img.dv-vv-img');
    await expect(img).toHaveAttribute('src', /^gcvault:\/\/v\/[0-9a-f]{32}$/);
    await expect.poll(() => img.evaluate((i) => i.naturalWidth)).toBeGreaterThan(0);
    await expect(viewer.locator('.dv-vv-mem')).toHaveText(/Nur im Speicher|in memory only/);
    await expect.poll(isProtected).toBe(true);
    await page.screenshot({ path: testInfo.outputPath('drive-vault-viewer-picture.png') });
    const picUrl = await img.getAttribute('src');
    await viewer.locator('.dv-dlg-head .dv-ib').click();
    await expect(viewer).toHaveCount(0);
    // closed: the URL is revoked
    await expect.poll(() => page.evaluate((u) => fetch(u).then((r) => r.status, () => 'failed'), picUrl)).not.toBe(200);
    await expect.poll(isProtected).toBe(false);

    // a PDF: pdf.js draws both pages
    await row('Vertrag.pdf').locator('.dv-open').click();
    await expect(viewer.locator('canvas.dv-vv-page')).toHaveCount(2, { timeout: 30000 });
    await expect(viewer.locator('.dv-vv-tools')).toContainText(/2 Seiten|2 pages/);
    const blue = await viewer.locator('canvas.dv-vv-page').first().evaluate((c) => {
      const d2 = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
      let n = 0;
      for (let i = 0; i < d2.length; i += 4) if (d2[i + 2] > 200 && d2[i] < 60) n++;
      return n;
    });
    expect(blue).toBeGreaterThan(1000);
    await page.screenshot({ path: testInfo.outputPath('drive-vault-viewer-pdf.png') });
    await page.keyboard.press('Escape');
    await expect(viewer).toHaveCount(0);

    // Markdown: as text — the <script> stays text
    await row('Notiz.md').locator('.dv-open').click();
    await expect(viewer.locator('.dv-vv-md h2')).toHaveText('Zugang');
    await expect(viewer.locator('.dv-vv-md strong')).toHaveText(SECRET);
    await expect(viewer.locator('.dv-vv-md script')).toHaveCount(0);
    await page.keyboard.press('Escape');

    // a video: plays from gcvault: (Range answers decrypted in memory)
    await row('Film.webm').locator('.dv-open').click();
    const video = viewer.locator('video.dv-vv-video');
    await expect(video).toHaveAttribute('src', /^gcvault:\/\/v\//);
    await expect.poll(() => video.evaluate((v) => v.readyState), { timeout: 20000 }).toBeGreaterThanOrEqual(1);
    const vurl = await video.getAttribute('src');

    // nothing in plain text in the temp folder, no other program started
    const temp = await app.evaluate(({ app: a }) => a.getPath('temp'));
    for (const f of filesIn(path.join(temp, 'gatecontrol-drive'))) {
      expect(fs.readFileSync(f).includes(Buffer.from(SECRET)), f).toBe(false);
      expect(path.basename(f)).not.toMatch(/Foto|Film|Vertrag|Notiz|Plan/);
    }
    expect(events().filter((e) => e.type === 'drive.openPath' || e.type === 'shell.openPath')).toEqual([]);

    // the lock closes the viewer and revokes its URL
    await viewer.locator('.dv-vv-lock').click();
    await expect(viewer).toHaveCount(0);
    await expect(root.locator('.dv-vgate.is-locked')).toBeVisible();
    await expect.poll(() => page.evaluate((u) => fetch(u).then((r) => r.status, () => 'failed'), vurl)).not.toBe(200);
    await expect.poll(() => filesIn(path.join(temp, 'gatecontrol-drive', 'vault-view')).length).toBe(0);

    // unlocked again: an office file gets the note; "Mit anderem Programm öffnen" asks first
    await root.locator('.dv-vgate.is-locked .dv-vault-unlock').click();
    await expect(row('Plan.xlsx')).toHaveCount(1);
    await row('Plan.xlsx').locator('.dv-open').click();
    await expect(viewer.locator('.dv-vv-note')).toContainText(/Office/);
    await viewer.locator('.dv-vv-openwith').click();
    const ask = page.locator('.dv-dlg').last();
    await expect(ask).toContainText(/unverschlüsselt|unencrypted/);
    await ask.locator('.btn-sec').click();
    expect(events().filter((e) => e.type === 'drive.openPath' || e.type === 'shell.openPath')).toEqual([]);
  });
});
