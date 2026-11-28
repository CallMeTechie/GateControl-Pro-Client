'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive plugin 1.32 'vaultLocal' („Tresor: Nur auf diesem Gerät“), only shown on Windows: a folder of a vault whose
// content lies only on a phone is a greyed placeholder „Nur auf Pixel 8“ (date „seit …“, size „–“); its menu offers
// only "Info" and "Platzhalter entfernen …"; a double click shows the note instead of opening; files dropped on it from
// the Explorer, an upload, a new folder or a move into it are refused naming the phone; "Platzhalter entfernen" sends
// this PC's vault device. Before the placeholder (an older plugin: no `local`) the folder is an ordinary one. The
// plugin is the core's fake Drive server (support/drive-mock.js: srv.setLocal). Selectors by id/class, texts in both
// languages.

async function openDrive(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  const root = page.locator('#page-drive');
  const files = root.locator('.dv-pages [data-page="files"]');
  await expect(files.or(root.locator('.dv-gate:visible')).first()).toBeVisible();
  if (await files.isVisible()) await files.click();
  return root;
}

const theme = (page, th) => page.evaluate((x) => { if (x === 'light') document.documentElement.setAttribute('data-theme', 'light'); else document.documentElement.removeAttribute('data-theme'); }, th);

/** Real files for a drop from the Explorer (the page's own drag events, as in drive-dnd.spec.js). */
async function dropFiles(page, target, files) {
  await page.evaluate(() => {
    if (document.getElementById('e2e-drop-files')) return;
    const i = document.createElement('input');
    i.type = 'file';
    i.multiple = true;
    i.id = 'e2e-drop-files';
    i.style.display = 'none';
    document.body.appendChild(i);
  });
  await page.locator('#e2e-drop-files').setInputFiles(files);
  return page.evaluate((sel) => {
    const el = document.querySelector(sel);
    const dt = new DataTransfer();
    for (const f of document.getElementById('e2e-drop-files').files) dt.items.add(f);
    const ev = (type) => new DragEvent(type, { bubbles: true, cancelable: true, dataTransfer: dt, clientX: 20, clientY: 20 });
    el.dispatchEvent(ev('dragenter'));
    el.dispatchEvent(ev('dragover'));
    const marked = [...document.querySelectorAll('#page-drive .dv-row.is-drop-target')].map((r) => r.dataset.id);
    el.dispatchEvent(ev('drop'));
    return { marked, effect: dt.dropEffect };
  }, target);
}

test.describe('drive 1.32: a vault folder only on another device', () => {
  test('greyed placeholder, its menu and note, nothing goes into it, "Platzhalter entfernen"', async ({ launchApp, mock }, testInfo) => {
    const d = await mock.setDrive({ features: ['vault', 'vaultsApart', 'bulk', 'offline'] });
    const { app, page } = await launchApp();
    await app.evaluate(() => globalThis.__gcE2E.useFakeConsent());
    await setupWithApiKey(page, mock);
    // the screenshots in German (the texts are checked in both languages)
    await page.evaluate(() => window.gatecontrol.locale.set('de'));
    const root = await openDrive(page);

    // a vault "Privat" with the folders "Steuer 2025", "Ausweise", "Verträge" and a file
    const made = await page.evaluate(() => window.gatecontrol.drive.vault.create(1, 'Privat'));
    expect(made.ok).toBe(true);
    const ids = {};
    for (const name of ['Steuer 2025', 'Ausweise', 'Verträge']) {
      const r = await page.evaluate(([id, n]) => window.gatecontrol.drive.mkdir(id, n), [made.node.id, name]);
      expect(r.ok).toBe(true);
      ids[name] = r.node.id;
    }
    const dir = testInfo.outputPath('src');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'Passwortliste.pdf'), '%PDF-1.4 geheim');
    await page.evaluate(([id, p]) => window.gatecontrol.drive.upload(id, [p]), [made.node.id, path.join(dir, 'Passwortliste.pdf')]);
    await expect.poll(() => [...d.srv.state.nodes.values()].filter((n) => n.parentId === made.node.id && !n.isDir).length, { timeout: 30000 }).toBe(1);

    await root.locator('.dv-head .dv-ib').first().click();
    const [vault] = [...d.srv.state.vaults.values()];
    await root.locator(`.dv-vault-item[data-vault="${vault.id}"]`).click();
    const row = (name) => root.locator('.dv-row', { has: page.locator('.dv-c-name', { hasText: name }) });
    const steuer = row('Steuer 2025');
    await expect(steuer).toHaveCount(1);
    // an older plugin (no `local`): an ordinary folder
    await expect(root.locator('.dv-row.is-local')).toHaveCount(0);
    await expect(root.locator('.dv-doc.dv-local')).toHaveCount(0);

    // the phone takes "Steuer 2025" (op local in the change log); the list loads again
    d.srv.setLocal(ids['Steuer 2025'], { deviceName: 'Pixel 8', platform: 'android', since: new Date(2026, 10, 27, 9, 30).getTime(), undo: false });
    await root.locator('.dv-head .dv-ib').first().click();
    await expect(steuer).toHaveClass(/is-local/);
    await expect(steuer.locator('.dv-doc.dv-local')).toHaveText(/Nur auf Pixel 8|Only on Pixel 8/);
    await expect(steuer.locator('.dv-c-date')).toHaveText(/(seit|since) 27\.11\.2026|since 27\/11\/2026/);
    await expect(steuer.locator('.dv-c-size')).toHaveText('–');
    await expect(steuer).not.toHaveAttribute('draggable', 'true');
    await expect(row('Ausweise')).not.toHaveClass(/is-local/);

    // its menu: the header, "Info", what does not go greyed, "Platzhalter entfernen …"
    await steuer.click({ button: 'right' });
    const menu = page.locator('.dv-menu');
    await expect(menu.locator('.dv-menu-h')).toHaveText(/Steuer 2025 · (nur auf|only on) Pixel 8/);
    await expect(menu.locator('[data-item="local-info"]')).toBeVisible();
    await expect(menu.locator('[data-item="local-forget"]')).toBeVisible();
    await expect(menu.locator('[data-item="open"]')).toHaveClass(/is-off/);
    await expect(menu.locator('button.dv-menu-item')).toHaveCount(2);
    await expect(menu.locator('.dv-menu-item', { hasText: /Teilen|Verschieben|In den Papierkorb|Share|Move|trash/ })).toHaveCount(0);
    await theme(page, 'light');
    await page.screenshot({ path: testInfo.outputPath('tresor-platzhalter-menue.png') });
    await theme(page, 'dark');
    await page.screenshot({ path: testInfo.outputPath('tresor-platzhalter-menue-dunkel.png') });
    await theme(page, 'light');
    await menu.locator('[data-item="local-info"]').click();

    // the note (W2)
    const note = page.locator('.dv-dlg.dv-local-dlg');
    await expect(note.locator('.dv-dlg-h')).toHaveText(/„Steuer 2025“ liegt nur auf Pixel 8|“Steuer 2025” is only on Pixel 8/);
    await expect(note.locator('.dv-local-text')).toContainText(/27\.11\.2026|27\/11\/2026/);
    await expect(note.locator('.dv-local-text')).toContainText(/Handy „Pixel 8“|phone “Pixel 8”/);
    await expect(note.locator('.dv-local-forget')).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath('tresor-platzhalter-info.png') });
    await note.locator('.dv-dlg-foot .btn-pri').click();
    await expect(note).toHaveCount(0);

    // a double click / a click on the name: the note, the folder does not open
    const crumbs = await root.locator('.dv-crumbs').textContent();
    await steuer.dblclick({ position: { x: 600, y: 10 } });
    await expect(note).toBeVisible();
    await page.keyboard.press('Escape');
    await steuer.locator('.dv-open').click();
    await expect(note).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(root.locator('.dv-crumbs')).toHaveText(crumbs);
    expect(d.srv.state.requests.some((r) => r.method === 'GET' && r.path.endsWith(`/nodes/${ids['Steuer 2025']}/children`))).toBe(false);

    // files from the Explorer dropped on it: not marked, refused with the phone named
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gc-e2e-local-')), 'Rechnung.txt');
    fs.writeFileSync(file, 'r');
    const dropped = await dropFiles(page, `#page-drive .dv-row[data-id="${ids['Steuer 2025']}"] .dv-name`, [file]);
    expect(dropped.marked).toEqual([]);
    await expect(page.locator('.toast-error').last()).toContainText(/nur auf „Pixel 8“|only on “Pixel 8”/);
    expect([...d.srv.state.nodes.values()].some((n) => n.parentId === ids['Steuer 2025'])).toBe(false);
    expect(fs.existsSync(file)).toBe(true);
    // an upload, a new folder, a move into it (bridge): 409 local_only with the phone
    const up = await page.evaluate(([id, p]) => window.gatecontrol.drive.upload(id, [p]), [ids['Steuer 2025'], file]);
    expect(up).toMatchObject({ ok: false, code: 'local_only', deviceName: 'Pixel 8' });
    const mk = await page.evaluate((id) => window.gatecontrol.drive.mkdir(id, 'Neu'), ids['Steuer 2025']);
    expect(mk).toMatchObject({ ok: false, code: 'local_only', deviceName: 'Pixel 8' });
    const mv = await page.evaluate(([id, target]) => window.gatecontrol.drive.ops.start('move', [id], { target }), [ids['Ausweise'], ids['Steuer 2025']]);
    expect(mv).toMatchObject({ ok: false, code: 'local_only', deviceName: 'Pixel 8' });

    // being moved to the phone: the chip says so, the folder still opens (read only)
    d.srv.setLocal(ids['Verträge'], { deviceName: 'Pixel 8', state: 'moving' });
    await root.locator('.dv-head .dv-ib').first().click();
    await expect(row('Verträge').locator('.dv-doc.dv-local')).toHaveText(/Wird gerade auf Pixel 8 verschoben|Being moved to Pixel 8/);
    await expect(row('Verträge')).not.toHaveClass(/is-local/);
    await page.screenshot({ path: testInfo.outputPath('tresor-platzhalter-liste.png') });

    // "Platzhalter entfernen …": asked first, this PC's vault device, the row goes
    await steuer.click({ button: 'right' });
    await menu.locator('[data-item="local-forget"]').click();
    const ask = page.locator('.dv-dlg', { hasText: /Platzhalter „Steuer 2025“ entfernen|Remove the placeholder “Steuer 2025”/ });
    await expect(ask).toContainText(/Pixel 8/);
    await page.screenshot({ path: testInfo.outputPath('tresor-platzhalter-entfernen.png') });
    await ask.locator('.btn-danger').click();
    await expect(steuer).toHaveCount(0);
    await page.evaluate(() => window.gatecontrol.locale.set('en'));
    const dev = [...vault.devices.values()].find((x) => x.state === 'approved');
    expect(d.srv.state.localForgets).toEqual([{ nodeId: ids['Steuer 2025'], deviceId: dev.deviceId, proof: null }]);
  });

  test('"Rückgängig" still possible: no "Platzhalter entfernen" yet', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['vault', 'vaultsApart', 'bulk'] });
    const { app, page } = await launchApp();
    await app.evaluate(() => globalThis.__gcE2E.useFakeConsent());
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    const made = await page.evaluate(() => window.gatecontrol.drive.vault.create(1, 'Privat'));
    const sub = await page.evaluate((id) => window.gatecontrol.drive.mkdir(id, 'Fotos Urlaub'), made.node.id);
    d.srv.setLocal(sub.node.id, { deviceName: null, platform: 'windows', undo: true, purgeAt: Date.now() + 3600000 });
    await root.locator('.dv-head .dv-ib').first().click();
    const [vault] = [...d.srv.state.vaults.values()];
    await root.locator(`.dv-vault-item[data-vault="${vault.id}"]`).click();
    const row = root.locator(`.dv-row[data-id="${sub.node.id}"]`);
    await expect(row.locator('.dv-doc.dv-local')).toHaveText(/Nur auf einem anderen Gerät|Only on another device/);
    await row.click({ button: 'right' });
    await expect(page.locator('.dv-menu [data-item="local-info"]')).toBeVisible();
    await expect(page.locator('.dv-menu [data-item="local-forget"]')).toHaveCount(0);
    await page.locator('.dv-menu [data-item="local-info"]').click();
    const note = page.locator('.dv-dlg.dv-local-dlg');
    await expect(note).toContainText(/(Platzhalter entfernen“ geht ab|Remove placeholder” is possible from)/);
    await expect(note.locator('.dv-local-forget')).toHaveCount(0);
  });
});
