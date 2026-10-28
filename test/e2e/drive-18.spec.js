'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive 1.8 / 1.9 on the page "Drive" (only with the features `me` reports; the plugin is the core's fake Drive
// server, support/drive-mock.js): "Details" of a document (what Drive recognised, the suggestion taken, a deadline
// with a reminder), "Fristen", the kind of document in the list, "Aus Google Drive / OneDrive importieren (im
// Portal)", "Im Browser bearbeiten", and a vault folder end-to-end encrypted on this PC (DPAPI): made with its
// recovery key shown once, a file uploaded only as ciphertext and opened decrypted, another device approved after
// its safety number. Selectors by id/class, texts in both languages.

const side = (root, re) => root.locator('.dv-area', { hasText: re });

/** The core's vault format (the app's own core), for "another device" of the test. */
function vaultCrypto() {
  const root = path.join(__dirname, '..', '..');
  let dir;
  try { dir = path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [root] })); } catch { dir = path.join(root, '..', 'gatecontrol-client-core'); }
  return require(path.join(dir, 'src', 'utils', 'drive-vault.js'));
}

async function openDrive(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  return page.locator('#page-drive');
}

test.describe('drive 1.8 / 1.9', () => {
  test('nothing new on a Drive without the features', async ({ launchApp, mock }) => {
    await mock.setDrive();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(root.locator('.dv-row[data-id="10"]')).toBeVisible();
    await expect(side(root, /Fristen|Deadlines/)).toHaveCount(0);
    await expect(side(root, /importieren|Import/)).toHaveCount(0);
    await expect(root.locator('.dv-vault-new')).toHaveCount(0);
    await expect(root.locator('.dv-ai')).toHaveCount(0);
    await root.locator('.dv-row[data-id="10"] .dv-open').click();
    await root.locator('.dv-row[data-id="12"] .dv-more-btn').click();
    await expect(page.locator('.dv-menu-item', { hasText: /Details|Im Browser|in browser/ })).toHaveCount(0);
  });

  test('docAi: the kind in the list, "Details" with the suggestion taken and a reminder, "Fristen"', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['docAi'] });
    d.srv.setInsight(12, {
      kind: 'invoice', title: 'Stadtwerke Rechnung', date: '2026-03-14', sender: 'Stadtwerke', amount: 89.5, currency: 'EUR',
      suggestion: { folderId: null, folderPath: null, name: '2026-03-14 Stadtwerke Rechnung.pdf' },
      deadlines: [{ kind: 'payment', date: '2099-03-28', label: 'Zahlung' }],
    });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await root.locator('.dv-row[data-id="10"] .dv-open').click();
    await expect(root.locator('.dv-row[data-id="12"] .dv-doc[data-doc="invoice"]')).toHaveText(/Rechnung|Invoice/);
    await root.locator('.dv-row[data-id="12"] .dv-more-btn').click();
    await page.locator('.dv-menu-item', { hasText: /Details/ }).click();
    const dlg = page.locator('.dv-dlg.dv-docs');
    await expect(dlg.locator('dd[data-field="title"]')).toHaveText('Stadtwerke Rechnung');
    await expect(dlg.locator('dd[data-field="sender"]')).toHaveText('Stadtwerke');
    await expect(dlg.locator('dd[data-field="amount"]')).toHaveText(/89[,.]50/);
    await expect(dlg.locator('.dv-dl')).toHaveCount(1);
    await page.screenshot({ path: test.info().outputPath('drive-details.png') });
    // a reminder 7 days before
    await dlg.locator('.dv-dl-remind').selectOption('7');
    await expect.poll(() => d.srv.state.deadlines[0].reminder && d.srv.state.deadlines[0].reminder.daysBefore).toBe(7);
    // the suggested name taken
    await dlg.locator('.dv-ins-take[data-take="name"]').click();
    await expect.poll(() => d.srv.state.nodes.get(12).name).toBe('2026-03-14 Stadtwerke Rechnung.pdf');
    await expect(dlg.locator('.dv-dlg-h')).toHaveText(/2026-03-14 Stadtwerke Rechnung\.pdf/);
    await expect(dlg.locator('.dv-ins-take')).toHaveCount(0);
    // "Erneut erkennen"
    await dlg.locator('.dv-dlg-foot .btn-sec').click();
    await expect(dlg.locator('.dv-ins-status')).toHaveText(/erkannt|recognised/);
    await dlg.locator('.dv-dlg-foot .btn-pri').click();
    // "Fristen": the deadline with its file; the file opens its details
    await side(root, /^(Fristen|Deadlines)$/).click();
    await expect(root.locator('.dv-dl')).toHaveCount(1);
    await expect(root.locator('.dv-dl .dv-dl-file')).toHaveText(/Stadtwerke Rechnung/);
    await expect(root.locator('.dv-dl-remind')).toHaveValue('7');
    await root.locator('.dv-dl .dv-dl-file').click();
    await expect(page.locator('.dv-dlg.dv-docs .dv-dlg-h')).toHaveText(/Stadtwerke Rechnung/);
  });

  test('"KI für Dokumente" per area (write right only) and sorting by type', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['docAi'] });
    const doc = d.srv.mutate.file(1, 'Brief.docx', 'docx');
    const sheet = d.srv.mutate.file(1, 'Zahlen.xlsx', 'xlsx');
    const pdf = d.srv.mutate.file(1, 'Angebot.pdf', 'pdf');
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(root.locator('.dv-row[data-id="10"]')).toBeVisible();
    // Meine Dateien (manage): the switch, on
    const ai = root.locator('.dv-ai');
    await expect(ai).toHaveText(/KI für Dokumente|AI for documents/);
    const sw = ai.locator('.sw[role="switch"]');
    await expect(sw).toHaveAttribute('aria-checked', 'true');
    await sw.click();
    await expect.poll(() => d.srv.state.docAiOff.has('mine:2')).toBe(true);
    await expect(root.locator('.dv-ai .sw')).toHaveAttribute('aria-checked', 'false');
    await page.screenshot({ path: test.info().outputPath('drive-docai-switch.png') });
    await root.locator('.dv-ai .sw').click();
    await expect.poll(() => d.srv.state.docAiOff.has('mine:2')).toBe(false);
    await expect(root.locator('.dv-ai .sw')).toHaveAttribute('aria-checked', 'true');
    // "Typ": folders, documents, tables, PDF, images, others — remembered like the other sorts
    const ids = () => root.locator('.dv-row[data-id]').evaluateAll((rows) => rows.map((r) => r.getAttribute('data-id')));
    await root.locator('.dv-seg [data-sort="type"]').click();
    await expect(root.locator('.dv-seg [data-sort="type"]')).toHaveAttribute('aria-checked', 'true');
    await expect.poll(ids).toEqual(['10', String(doc.id), String(sheet.id), String(pdf.id), '11', '13']);
    expect(await page.evaluate(() => localStorage.getItem('gc.drive.sort'))).toBe('type');
    // a child's folder the parent only reads: no switch
    await side(root, /Lena/).click();
    await expect(root.locator('.dv-note')).toBeVisible();
    await expect(root.locator('.dv-ai')).toHaveCount(0);
  });

  test('cloudImport and office: the portal\'s import page and the editor in the default browser', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['links', 'cloudImport', 'office'] });
    d.srv.linksBase = mock.url.replace(/\/+$/, '');
    const plan = d.srv.mutate.file(10, 'Plan.xlsx', 'x');
    const { page, events } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    const opened = () => events().filter((e) => e.type === 'shell.openExternal').map((e) => e.url);
    await side(root, /importieren|Import/).click();
    await expect.poll(opened).toContainEqual(`${d.srv.linksBase}/portal?drive=import#plg-gatecontrol-drive`);
    await root.locator('.dv-area').first().click();
    await root.locator('.dv-row[data-id="10"] .dv-open').click();
    // a PDF has no office entry
    await root.locator('.dv-row[data-id="12"] .dv-more-btn').click();
    await expect(page.locator('.dv-menu-item', { hasText: /Im Browser|in browser/ })).toHaveCount(0);
    await page.keyboard.press('Escape');
    await root.locator(`.dv-row[data-id="${plan.id}"] .dv-more-btn`).click();
    await page.locator('.dv-menu-item', { hasText: /Im Browser bearbeiten|Edit in browser/ }).click();
    await expect.poll(opened).toContainEqual(`https://gc.example.com/plugin-public/gatecontrol-drive/office/open/${plan.id}?access_token=tok`);
    expect(d.srv.state.officeCalls).toEqual([plan.id]);
  });

  test('vault: made with its recovery key, a file only as ciphertext, opened decrypted, another device approved', async ({ launchApp, mock }, testInfo) => {
    const V = vaultCrypto();
    const d = await mock.setDrive({ features: ['vault'] });
    const { page, events } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(root.locator('.dv-row[data-id="10"]')).toBeVisible();
    await root.locator('.dv-vault-new').click();
    const dlg = page.locator('.dv-dlg.dv-vault-dlg');
    await dlg.locator('input').fill('Steuer');
    await dlg.locator('.dv-dlg-foot .btn-pri').click();
    // the recovery key: once, closing only after "notiert"
    await expect(dlg.locator('.dv-rk code')).toHaveCount(4);
    const keyText = (await dlg.locator('.dv-rk code').allTextContents()).join('-');
    expect(keyText).toMatch(/^([0-9A-Z]{4}-){13}[0-9A-Z]{4}$/);
    await page.screenshot({ path: testInfo.outputPath('drive-vault-recovery.png') });
    await expect(dlg.locator('.dv-dlg-foot .btn-pri')).toBeDisabled();
    await dlg.locator('.dv-check input').check();
    await dlg.locator('.dv-dlg-foot .btn-pri').click();
    await expect(page.locator('.dv-dlg')).toHaveCount(0);
    const [vault] = [...d.srv.state.vaults.values()];
    const vnode = d.srv.state.nodes.get(vault.nodeId);
    expect(vnode.name).toMatch(/^[0-9a-f]{32}$/);
    // its name decrypted on this PC
    const row = root.locator(`.dv-row[data-id="${vault.nodeId}"]`);
    await expect(row.locator('.dv-name')).toHaveText('Steuer');
    await row.locator('.dv-open').click();
    await expect(root.locator('.dv-note')).toHaveText(/Ende-zu-Ende|end-to-end/);
    // a file into it: only ciphertext reaches the server
    const SECRET = 'Kontoauszug IBAN DE02 1203 0000 0000 2020 51';
    const src = testInfo.outputPath('Kontoauszug.txt');
    fs.writeFileSync(src, SECRET);
    await page.evaluate(([id, p]) => window.gatecontrol.drive.upload(id, [p]), [vault.nodeId, src]);
    const fileRow = root.locator('.dv-row', { hasText: 'Kontoauszug.txt' });
    await expect(fileRow).toBeVisible();
    for (const m of d.srv.state.media.values()) expect(m.data.includes(Buffer.from('IBAN'))).toBe(false);
    const file = [...d.srv.state.nodes.values()].find((n) => n.parentId === vault.nodeId && !n.isDir);
    expect(file.mime).toBe('application/octet-stream');
    // opened: decrypted into a temporary folder
    await fileRow.locator('.dv-open').click();
    const sha = crypto.createHash('sha256').update(SECRET).digest('hex');
    await expect.poll(() => events().filter((e) => e.type === 'shell.openPath').map((e) => e.sha256)).toContainEqual(sha);
    // links and the time travel are not offered in a vault
    await fileRow.locator('.dv-more-btn').click();
    await expect(page.locator('.dv-menu-item', { hasText: /Link teilen|Share link/ })).toHaveCount(0);
    await page.keyboard.press('Escape');
    // another device asks; approved here after comparing its safety number
    const other = V.generateKeyPair();
    const did = d.srv.vaultAsk(vault.id, V.b64u(other.publicRaw), 'Pixel');
    await root.locator('.dv-head .dv-ib').first().click();
    await root.locator('.dv-vault-devices').click();
    const dev = page.locator(`.dv-vdev-row[data-device="${did}"]`);
    await expect(dev.locator('.dv-safety-n')).toHaveText(V.safetyNumber(other.publicRaw));
    await page.screenshot({ path: testInfo.outputPath('drive-vault-devices.png') });
    await expect(dev.locator('.dv-vault-approve')).toBeDisabled();
    await dev.locator('.dv-check input').check();
    await dev.locator('.dv-vault-approve').click();
    await expect.poll(() => vault.devices.get(did).state).toBe('approved');
    // the other device reads the vault's name with the key it got
    const tk = V.unwrapKey(vault.wraps.get(`${did}|1`), other.privateRaw, other.publicRaw, vault.id, 1);
    expect(V.decryptName({ 1: tk }, vault.id, vnode.nameCipher)).toBe('Steuer');
  });
});
