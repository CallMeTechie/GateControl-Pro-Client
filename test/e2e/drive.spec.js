'use strict';

const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive (plugin gatecontrol-drive): shown only when the server lists the
// plugin; areas, folders with previews, new folder, rename, trash and
// restore, search in names and recognised text, share links with a PIN and
// the list of one's links, uploads with a taken name ("Neue Version"), the
// page for a person without a seat, and "In Drive speichern" of a Schule
// attachment through the folder picker (writable areas only, it remembers
// the folder); "Ordner sichern": a folder backed up into Geräte › <PC>, pause,
// the settings, a folder synced with a Drive folder picked in the picker. The
// plugin is the core's fake Drive server
// (support/drive-mock.js). Selectors by id/class, texts in both languages.

const rows = (root) => root.locator('.dv-row[data-id] .dv-name');
const menuItem = (page, re) => page.locator('.dv-menu-item', { hasText: re });

async function openDrive(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  return page.locator('#page-drive');
}

test.describe('drive', () => {
  test('no Drive plugin on the server: no "Drive" entry', async ({ launchApp, mock }) => {
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.count('/api/v1/client/plugins')).toBeGreaterThan(0);
    await expect(page.locator('#nav-drive')).toBeHidden();
  });

  test('areas, folders, new folder, rename, trash and restore, search', async ({ launchApp, mock }) => {
    await mock.setDrive();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);

    // Drive 1.11 menu: 4 areas in the tree (Meine Dateien unfolded), the icons "Geteilt", "Papierkorb",
    // "Ordner sichern", "Einstellungen"; Meine Dateien with a preview of the photo
    await expect(root.locator('.dv-tree-row.is-area')).toHaveCount(4);
    await expect(root.locator('.dv-tool')).toHaveCount(4);
    await expect(root.locator('.dv-tree-row.is-on .dv-area-name')).toHaveText(/^(Meine Dateien|My files)$/);
    await expect(rows(root)).toHaveText(['Dokumente', 'Foto.jpg', 'setup.exe']);
    await expect(root.locator('.dv-row[data-id="11"] .dv-thumb img')).toHaveCount(1);
    await page.screenshot({ path: test.info().outputPath('drive-root.png') });

    // into a folder, breadcrumbs
    await root.locator('.dv-row[data-id="10"] .dv-open').click();
    await expect(root.locator('.dv-crumb')).toHaveCount(2);
    await expect(rows(root)).toHaveText(['Brief.pdf']);

    // new folder: names Drive refuses are not taken
    await root.locator('.dv-bar .dv-new').click();
    await page.locator('.dv-menu-item[data-item="folder"]').click();
    const dlg = page.locator('.dv-dlg');
    await dlg.locator('input').fill('Reise/2026');
    await expect(dlg.locator('.btn-pri')).toBeDisabled();
    await dlg.locator('input').fill('Urlaub');
    await dlg.locator('.btn-pri').click();
    await expect(dlg).toHaveCount(0);
    await expect(rows(root)).toHaveText(['Urlaub', 'Brief.pdf']);

    // rename through the row menu
    await root.locator('.dv-row', { hasText: 'Urlaub' }).locator('.dv-more-btn').click();
    await menuItem(page, /^(Umbenennen|Rename)$/).click();
    await dlg.locator('input').fill('Reisen');
    await dlg.locator('.btn-pri').click();
    await expect(rows(root)).toHaveText(['Reisen', 'Brief.pdf']);

    // into the trash and back
    await root.locator('.dv-row', { hasText: 'Reisen' }).locator('.dv-more-btn').click();
    await menuItem(page, /^(In den Papierkorb|Move to trash)$/).click();
    await dlg.locator('.btn-danger').click();
    await expect(rows(root)).toHaveText(['Brief.pdf']);
    await root.locator('.dv-tool[data-view="trash"]').click();
    await expect(root.locator('.dv-row.is-trash .dv-name')).toHaveText(['Reisen']);
    await root.locator('.dv-row.is-trash .dv-trash-act .btn-sec').click();
    await expect(root.locator('.dv-row.is-trash')).toHaveCount(0);

    // search: name and recognised text with the words around the hit
    await root.locator('.dv-search-in').fill('Miete');
    await root.locator('.dv-search-in').press('Enter');
    await expect(root.locator('.dv-row[data-id="12"] .dv-row-sub')).toContainText('die Miete für Oktober');
    await root.locator('.dv-search-in').press('Escape');
    await expect(root.locator('.dv-crumb').first()).toBeVisible();
  });

  test('share a link with a PIN, the list of links, end it', async ({ launchApp, mock }) => {
    const d = await mock.setDrive();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);

    await root.locator('.dv-row[data-id="11"] .dv-more-btn').click();
    await menuItem(page, /^(Link teilen …|Share link …)$/).click();
    const dlg = page.locator('.dv-dlg');
    await dlg.locator('.dv-seg').first().locator('button').nth(1).click(); // ansehen und laden
    await dlg.locator('.dv-pin').fill('12');
    await expect(dlg.locator('.dv-dlg-foot .btn-pri')).toBeDisabled();
    await dlg.locator('.dv-pin').fill('4711');
    await dlg.locator('.dv-dlg-foot .btn-pri').click();
    await expect(dlg.locator('.dv-url')).toHaveValue(/^https:\/\/gc\.example\.com\/s\//);
    await expect(dlg.locator('.dv-share-links .dv-link')).toHaveCount(1);
    expect(d.srv.state.links[0]).toMatchObject({ nodeId: 11, mode: 'download', pin: true });
    await page.screenshot({ path: test.info().outputPath('drive-share.png') });
    await dlg.locator('.dv-dlg-foot .btn-sec').click();

    // "Geteilt": the person's links
    await root.locator('.dv-tool[data-view="links"]').click();
    await expect(root.locator('.dv-link')).toHaveCount(1);
    await expect(root.locator('.dv-link .dv-row-sub')).toContainText(/mit PIN|with PIN/);
    await root.locator('.dv-link .btn-sec').click();
    await expect(root.locator('.dv-link.is-ended')).toHaveCount(1);
  });

  test('uploads: a new file and a taken name as a new version', async ({ launchApp, mock }, testInfo) => {
    const d = await mock.setDrive();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(rows(root)).toHaveCount(3);

    const photo = testInfo.outputPath('Foto.jpg');
    const note = testInfo.outputPath('Neu.txt');
    fs.writeFileSync(photo, 'new photo bytes');
    fs.writeFileSync(note, 'hallo');
    await page.evaluate(([a, b]) => window.gatecontrol.drive.upload(1, [a, b]), [photo, note]);

    // the taken name asks
    const dlg = page.locator('.dv-dlg');
    await expect(dlg.locator('.dv-dlg-h')).toHaveText(/Foto\.jpg/);
    await dlg.locator('.dv-dlg-foot .btn-pri').click(); // Neue Version
    await expect(root.locator('.dv-tr.is-ok')).toHaveCount(2);
    await expect(rows(root)).toHaveText(['Dokumente', 'Foto.jpg', 'Neu.txt', 'setup.exe']);
    expect(d.srv.state.nodes.get(11).rev).toBe(3);
  });

  test('Ordner sichern: back up a folder, pause it, settings, sync a folder with a Drive folder', async ({ launchApp, mock }, testInfo) => {
    const d = await mock.setDrive();
    const { page, answerOpenDialogs, trayLabels } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await root.locator('.dv-tool[data-view="sync"]').click();
    const sv = root.locator('.dsv');
    await expect(sv).toBeVisible();
    await expect(sv.locator('.dsv-pill')).toHaveText(/Noch kein Ordner|No folder yet/);
    await expect(root.locator('.dv-list-wrap')).toBeHidden();

    // "Nur sichern": into Meine Dateien › Geräte › <PC> › Projekte, temporary files left out
    const projekte = testInfo.outputPath('Projekte');
    fs.mkdirSync(path.join(projekte, 'Plan'), { recursive: true });
    fs.writeFileSync(path.join(projekte, 'Angebot.txt'), 'Angebot');
    fs.writeFileSync(path.join(projekte, 'Plan', 'Skizze.txt'), 'Skizze');
    fs.writeFileSync(path.join(projekte, '~$Angebot.docx'), 'lock');
    const r = await page.evaluate((p) => window.gatecontrol.drive.sync.add({ path: p, mode: 'backup' }), projekte);
    expect(r.ok).toBe(true);
    const row = sv.locator('.dsv-row[data-folder]', { hasText: 'Projekte' });
    await expect(row.locator('.dsv-state-tx')).toHaveText(/^(Aktuell|Up to date)/, { timeout: 30000 });
    await expect(row.locator('.dsv-target-tx')).toHaveText(/Geräte › .+ › Projekte$/);
    const named = (name, parent) => [...d.srv.state.nodes.values()].find((n) => n.name === name && !n.deleted && (!parent || (n && n.parentId === parent.id)));
    const geraete = named('Geräte');
    expect(geraete && geraete.parentId).toBe(1);
    const top = named('Projekte');
    expect(top && d.srv.state.nodes.get(top.parentId).parentId).toBe(geraete.id);
    expect(named('Angebot.txt', top)).toBeTruthy();
    expect(named('Skizze.txt', named('Plan', top))).toBeTruthy();
    expect(named('~$Angebot.docx')).toBeFalsy();
    await expect(sv.locator('.dsv-pill')).toHaveText(/Alles aktuell|All up to date/);
    await expect.poll(async () => (await trayLabels()).join('|')).toMatch(/Drive-Sicherung pausieren|Pause Drive backup/);
    await page.screenshot({ path: test.info().outputPath('drive-sync.png') });

    // pause the folder, go on
    await row.locator('.dsv-act').first().click();
    await expect(row.locator('.dsv-state-tx')).toHaveText(/Pausiert|Paused/);
    await row.locator('.dsv-act').first().click();
    await expect(row.locator('.dsv-state-tx')).toHaveText(/^(Aktuell|Up to date)/);

    // settings: an upload limit — Drive 1.11: in the Drive settings (a line in "Ordner sichern" leads there)
    await expect(sv.locator('.dsv-set')).toHaveCount(0);
    await sv.locator('.dsv-set-link [data-key="open-settings"]').click();
    const set = root.locator('.dset');
    await expect(set).toBeVisible();
    await set.locator('.dsv-set select').nth(1).selectOption('512');
    await expect.poll(() => page.evaluate(() => window.gatecontrol.drive.sync.status().then((s) => s.settings.upKBs))).toBe(512);
    await set.locator('.dsv-set').scrollIntoViewIfNeeded();
    await page.screenshot({ path: test.info().outputPath('drive-sync-settings.png') });
    await set.locator('[data-key="open-sync"]').click();
    await expect(sv).toBeVisible();

    // "Abgleichen" with Meine Dateien › Dokumente, picked in Drive's folder picker
    const laptop = testInfo.outputPath('Laptop');
    fs.mkdirSync(laptop, { recursive: true });
    fs.writeFileSync(path.join(laptop, 'Notiz.txt'), 'vom PC');
    await answerOpenDialogs([laptop]);
    await sv.locator('.dsv-card-head .btn-pri').click();
    const dlg = page.locator('.dv-dlg').first();
    await expect(dlg.locator('.dv-dlg-foot .btn-pri')).toBeDisabled();
    await dlg.locator('.dsv-pick .btn').first().click();
    await expect(dlg.locator('.dsv-pick-val').first()).toHaveText(laptop);
    await dlg.locator('.dv-seg button').nth(1).click();
    await expect(dlg.locator('.dv-dlg-foot .btn-pri')).toBeDisabled();
    await dlg.locator('.dsv-pick .btn').nth(1).click();
    const picker = page.locator('.dv-dlg').last();
    await picker.locator('.dv-pick-row').first().click();
    await picker.locator('.dv-pick-row', { hasText: 'Dokumente' }).click();
    await expect(picker.locator('.dv-pick-path')).toHaveText(/Dokumente$/);
    await picker.locator('.dv-dlg-foot .btn-pri').click();
    await expect(dlg.locator('.dsv-pick-val').nth(1)).toHaveText(/Dokumente$/);
    await dlg.locator('.dv-dlg-foot .btn-pri').click();
    await expect(page.locator('.dv-dlg')).toHaveCount(0);
    const synced = sv.locator('.dsv-row[data-folder]', { hasText: 'Laptop' });
    await expect(synced.locator('.dsv-mode')).toHaveText(/Abgleichen|Sync/);
    await expect(synced.locator('.dsv-state-tx')).toHaveText(/^(Aktuell|Up to date)/, { timeout: 30000 });
    await expect.poll(() => fs.existsSync(path.join(laptop, 'Brief.pdf'))).toBe(true);
    expect(named('Notiz.txt', d.srv.state.nodes.get(10))).toBeTruthy();
    await synced.scrollIntoViewIfNeeded();
    await page.screenshot({ path: test.info().outputPath('drive-sync-more.png') });

    // removing stops it, nothing is deleted
    await synced.locator('.dsv-act.dv-danger').click();
    await page.locator('.dv-dlg .btn-danger').click();
    await expect(sv.locator('.dsv-row[data-folder]', { hasText: 'Laptop' })).toHaveCount(0);
    expect(fs.existsSync(path.join(laptop, 'Notiz.txt'))).toBe(true);
    expect(named('Notiz.txt', d.srv.state.nodes.get(10))).toBeTruthy();
  });

  test('a person without a seat sees why', async ({ launchApp, mock }) => {
    await mock.setDrive({ seat: null });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(root.locator('.dv-gate .dv-p')).toHaveText(/freigeschaltet|switched on/);
    await expect(root.locator('.dv-main')).toBeHidden();
  });

  test('Schule: an attachment into a folder picked in Drive; the picker remembers it', async ({ launchApp, mock }) => {
    await mock.setDrive();
    const sc = mock.setSchool({
      version: '1.7.0',
      drive: true,
      students: [{ id: 3, name: 'Lena Muster', klasse: '5b', color: '#2FBF71' }],
      messages: [{ id: 77, accountId: 1, studentIds: [3], subject: 'Elternbrief', preview: 'Liebe Eltern', body: 'Liebe Eltern', sender: 'Frau Schulz', sentAt: Date.now() - 3600000, hasAttachments: true, attachments: [{ id: 'a1', name: 'Elternbrief.pdf', size: 52000, mime: 'application/pdf' }] }],
    });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-schule').click();
    const school = page.locator('#page-schule');
    await school.locator('.sv-tabs button').nth(2).click();
    await school.locator('.sv-msg-head').click();
    await expect(school.locator('.sv-att-name')).toHaveText('Elternbrief.pdf');
    await school.locator('.sv-att .btn').click();

    // the picker: writable areas only (not the child's folder or the archived team folder)
    const dlg = page.locator('.dv-dlg');
    await expect(dlg.locator('.dv-pick-row')).toHaveCount(2);
    await dlg.locator('.dv-pick-row').first().click();
    await dlg.locator('.dv-pick-row', { hasText: 'Dokumente' }).click();
    await expect(dlg.locator('.dv-pick-path')).toHaveText(/Dokumente$/);
    await dlg.locator('.dv-dlg-foot .btn-pri').click();
    await expect(page.locator('.toast-text').last()).toHaveText(/Familie › Schule › Lena › Elternbrief\.pdf/);
    expect(sc.driveSaves[0]).toMatchObject({ messageId: '77', attachmentId: 'a1', body: { folderId: 10 } });

    // the next time it starts in that folder
    await school.locator('.sv-att .btn').click();
    await expect(dlg.locator('.dv-pick-path')).toHaveText(/Dokumente$/);
    await dlg.locator('.dv-dlg-foot .btn-pri').click();
    await expect.poll(() => sc.driveSaves.length).toBe(2);
    expect(sc.driveSaves[1].body).toEqual({ folderId: 10 });
  });
});
