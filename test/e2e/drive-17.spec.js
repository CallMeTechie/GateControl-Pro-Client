'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive 1.7 on the page "Drive" (only with the features `me` reports; the
// plugin is the core's fake Drive server, support/drive-mock.js): a folder
// back to an earlier state (preview, run, "Rückgängig"), "Fotos" (timeline
// with previews by the node, "Vor einem Jahr", the large view, photos into a
// new album, the album with the photo frame switch, deleting it) and
// "Speicher" (total, areas, largest files, duplicates into the trash).
// Selectors by id/class, texts in both languages.

const side = (root, re) => root.locator('.dv-area', { hasText: re });

async function openDrive(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  return page.locator('#page-drive');
}

test.describe('drive 1.7', () => {
  test('nothing new on a Drive without the features', async ({ launchApp, mock }) => {
    await mock.setDrive();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(root.locator('.dv-area')).toHaveCount(7);
    await expect(side(root, /^(Fotos|Photos)$/)).toHaveCount(0);
    await expect(root.locator('.dv-tt-btn')).toHaveCount(0);
    await root.locator('.dv-row[data-id="10"] .dv-more-btn').click();
    await expect(page.locator('.dv-menu-item', { hasText: /früheren Stand|earlier state/ })).toHaveCount(0);
  });

  test('a folder back to an earlier state, and "Rückgängig"', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['timeTravel'] });
    // since an hour ago: Brief.pdf changed, a new file
    const neu = d.srv.mutate.file(10, 'Neu.txt', 'neu');
    d.srv.mutate.change(12, 'Brief neu');
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await root.locator('.dv-row[data-id="10"] .dv-more-btn').click();
    await page.locator('.dv-menu-item', { hasText: /früheren Stand|earlier state/ }).click();
    const dlg = page.locator('.dv-dlg.dv-tt');
    await expect(dlg.locator('.dv-dlg-h')).toHaveText(/Dokumente/);
    await dlg.locator('.dv-tt-presets .btn').first().click(); // vor 1 Stunde
    await expect(dlg.locator('.dv-tt-sum li')).toHaveCount(2);
    await expect(dlg.locator('.dv-tt-row')).toHaveCount(2);
    await page.screenshot({ path: test.info().outputPath('drive-timetravel.png') });
    // the preview changed nothing
    expect(d.srv.state.nodes.get(neu.id).deleted).toBe(false);
    await dlg.locator('.dv-dlg-foot .btn-pri').click();
    await expect(dlg.locator('.dv-share-ok')).toHaveText(/Zurückgesetzt|Restored/);
    expect(d.srv.state.nodes.get(neu.id).deleted).toBe(true);
    expect(d.srv.state.nodes.get(12).size).toBe(14);
    // "Rückgängig": back to right before
    await dlg.locator('.dv-dlg-foot .btn-sec').click();
    await expect(dlg.locator('.dv-share-ok')).toHaveText(/Rückgängig gemacht|Undone/);
    expect(d.srv.state.nodes.get(neu.id).deleted).toBe(false);
    await dlg.locator('.dv-dlg-foot .btn-pri').click();
    await expect(page.locator('.dv-dlg')).toHaveCount(0);
    // the bar offers it for the folder shown
    await root.locator('.dv-row[data-id="10"] .dv-open').click();
    await expect(root.locator('.dv-tt-btn')).toBeVisible();
  });

  test('Fotos: timeline, "Vor einem Jahr", large view, a new album, the photo frame', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['photos', 'albums', 'frame', 'links'] });
    const bilder = d.srv.mutate.dir(1, 'Bilder');
    const now = new Date();
    for (let i = 0; i < 4; i++) d.srv.mutate.photo(bilder.id, `IMG_${i}.jpg`, { takenAt: Date.now() - i * 3600000 });
    const old = new Date(now.getFullYear() - 1, now.getMonth(), now.getDate(), 12).getTime();
    d.srv.mutate.photo(bilder.id, 'Damals.jpg', { takenAt: old });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await side(root, /^(Fotos|Photos)$/).click();
    const pv = root.locator('.dpv');
    await expect(pv).toBeVisible();
    await expect(root.locator('.dv-list-wrap')).toBeHidden();
    // 4 new photos, the one of a year ago, Foto.jpg (in the timeline and in "Vor einem Jahr")
    await expect(pv.locator('.dpv-month .dpv-tile')).toHaveCount(6);
    await expect(pv.locator('.dpv-mem .dpv-tile')).toHaveCount(1);
    await expect(pv.locator('.dpv-month .dpv-tile img').first()).toBeVisible();
    await page.screenshot({ path: test.info().outputPath('drive-photos.png') });

    // the large view
    await pv.locator('.dpv-month .dpv-tile').first().click();
    const light = page.locator('.dv-dlg.dpv-light');
    await expect(light.locator('.dpv-big img')).toBeVisible();
    await expect(light.locator('.dv-dlg-h')).toHaveText('IMG_0.jpg');
    await page.keyboard.press('ArrowRight');
    await expect(light.locator('.dv-dlg-h')).toHaveText('IMG_1.jpg');
    await page.keyboard.press('Escape');

    // two photos into a new album
    await pv.locator('.dpv-head .btn', { hasText: /Auswählen|Select/ }).click();
    await pv.locator('.dpv-month .dpv-tile').nth(0).click();
    await pv.locator('.dpv-month .dpv-tile').nth(1).click();
    await expect(pv.locator('.dpv-sel-n')).toHaveText(/2/);
    await pv.locator('.dpv-selbar .btn-pri').click();
    await page.locator('.dv-dlg .dv-dlg-foot .btn', { hasText: /Neues Album|New album/ }).click();
    const nd = page.locator('.dv-dlg');
    await nd.locator('input').fill('Herbst');
    await nd.locator('.dv-dlg-foot .btn-pri').click();
    await expect.poll(() => [...d.srv.state.albums.values()].map((a) => [a.name, a.items.length])).toEqual([['Herbst', 2]]);

    // the album: photo frame on, then deleted (the photos stay)
    await pv.locator('.dpv-head [role="tab"]').nth(1).click();
    await expect(pv.locator('.dpv-album')).toHaveCount(1);
    await pv.locator('.dpv-album').click();
    await expect(pv.locator('.dpv-grid .dpv-tile')).toHaveCount(2);
    await pv.locator('.dpv-frame .sw').click();
    await expect(pv.locator('.dpv-frame .sw')).toHaveAttribute('aria-checked', 'true');
    expect([...d.srv.state.albums.values()][0].frame).toBe(true);
    await page.screenshot({ path: test.info().outputPath('drive-album.png') });
    await pv.locator('.dpv-album-head .btn.dv-danger').click();
    await page.locator('.dv-dlg .btn-danger').click();
    await expect(pv.locator('.dpv-album')).toHaveCount(0);
    expect(d.srv.state.albums.size).toBe(0);
    expect(d.srv.state.nodes.get(bilder.id + 1).deleted).toBe(false);
  });

  test('Speicher: total, areas, largest files, duplicates into the trash', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['storage'] });
    const a = d.srv.mutate.file(10, 'Rechnung.pdf', 'doppelt doppelt');
    const b = d.srv.mutate.file(1, 'Rechnung (Kopie).pdf', 'doppelt doppelt');
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await side(root, /^(Speicher|Storage)$/).click();
    const sg = root.locator('.dsg');
    await expect(sg).toBeVisible();
    await expect(sg.locator('.dsg-big')).toBeVisible();
    await expect(sg.locator('.dsg-row').first()).toBeVisible();
    await expect(sg.locator('.dsg-file').first()).toBeVisible();
    await expect(sg.locator('.dsg-dup')).toHaveCount(1);
    await expect(sg.locator('.dsg-dup-row')).toHaveCount(2);
    await page.screenshot({ path: test.info().outputPath('drive-storage.png') });
    // never both: the suggestion keeps one
    await sg.locator('.dsg-dup-bar .btn', { hasText: /Vorschlag|Suggest/ }).click();
    await expect(sg.locator('.dsg-dup-row input:checked')).toHaveCount(1);
    await expect(sg.locator('.dsg-dup-row input:not(:checked)')).toBeDisabled();
    await sg.locator('.dsg-dup-bar .dv-danger').click();
    await page.locator('.dv-dlg .btn-danger').click();
    await expect(sg.locator('.dsg-dup')).toHaveCount(0);
    expect([a, b].filter((n) => d.srv.state.nodes.get(n.id).deleted)).toHaveLength(1);
  });
});
