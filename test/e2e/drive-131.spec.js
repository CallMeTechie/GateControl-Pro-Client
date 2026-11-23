'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive 1.31 'framePhotos' on the page "Drive" › "Fotos" (the core's fake Drive server, support/drive-mock.js):
// select photos, „Für Fotorahmen freigeben“ (the toast names a video left out), the mark on the tiles,
// „Aus Fotorahmen entfernen“ once the photos selected are shared, the large view's entry, 403 for an account
// that may not share; without the feature none of it. Selectors by id/class, texts in both languages.

const tool = (root, view) => root.locator(`.dv-tool[data-view="${view}"]`);

async function openPhotos(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  const root = page.locator('#page-drive');
  const files = root.locator('.dv-pages [data-page="files"]');
  await expect(files.or(root.locator('.dv-gate:visible')).first()).toBeVisible();
  if (await files.isVisible()) await files.click();
  await tool(root, 'photos').click();
  const pv = root.locator('.dpv');
  await expect(pv).toBeVisible();
  return pv;
}

async function photos(d) {
  const bilder = d.srv.mutate.dir(1, 'Bilder');
  const a = d.srv.mutate.photo(bilder.id, 'IMG_A.jpg', { takenAt: Date.now() - 1000 });
  const b = d.srv.mutate.photo(bilder.id, 'IMG_B.jpg', { takenAt: Date.now() - 2000 });
  const v = d.srv.mutate.photo(bilder.id, 'VID_C.mp4', { takenAt: Date.now() - 3000, mime: 'video/mp4', durationMs: 4000 });
  return { a, b, v };
}

const tile = (pv, id) => pv.locator(`.dpv-month .dpv-tile[data-id="${id}"]`);

test.describe('drive 1.31: photos for the photo frame', () => {
  test('nothing on a Drive without framePhotos', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['photos', 'albums', 'frame'] });
    const { a } = await photos(d);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const pv = await openPhotos(page);
    await pv.locator('.dpv-head .btn', { hasText: /Auswählen|Select/ }).click();
    await tile(pv, a.id).click();
    await expect(pv.locator('.dpv-sel-n')).toHaveText(/1/);
    await expect(pv.locator('.dpv-selbar [data-act^="frame-"]')).toHaveCount(0);
    await pv.locator('.dpv-selbar .btn-ghost').click();
    await tile(pv, a.id).click();
    await expect(page.locator('.dv-dlg.dpv-light .dv-dlg-h')).toHaveText('IMG_A.jpg');
    await expect(page.locator('.dv-dlg.dpv-light .dpv-frame-btn')).toHaveCount(0);
  });

  test('share, the mark, remove; the large view; videos only: no entry', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['photos', 'albums', 'framePhotos'] });
    const { a, b, v } = await photos(d);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const pv = await openPhotos(page);
    await expect(tile(pv, a.id)).toBeVisible();
    await expect(pv.locator('.dpv-framed')).toHaveCount(0);

    // only the video selected: no entry
    await pv.locator('.dpv-head .btn', { hasText: /Auswählen|Select/ }).click();
    await tile(pv, v.id).click();
    await expect(pv.locator('.dpv-sel-n')).toHaveText(/1/);
    await expect(pv.locator('.dpv-selbar [data-act^="frame-"]')).toHaveCount(0);

    // two pictures and the video: shared, the video left out (the toast says why)
    await tile(pv, a.id).click();
    await tile(pv, b.id).click();
    await expect(pv.locator('.dpv-sel-n')).toHaveText(/3/);
    await expect(pv.locator('.dpv-selbar [data-act="frame-remove"]')).toHaveCount(0);
    await pv.locator('.dpv-selbar [data-act="frame-add"]').click();
    await expect(page.locator('#toasts .toast').filter({ hasText: /2 Fotos für den Fotorahmen freigegeben\. 1 übersprungen: 1 Video\.|2 photos shared with the photo frame\. 1 skipped: 1 video\./ })).toBeVisible();
    await expect.poll(() => (d.srv.state.frame ? [...d.srv.state.frame.items].sort() : [])).toEqual([a.id, b.id].sort());
    await expect(pv.locator('.dpv-selbar')).toBeHidden();
    await expect(tile(pv, a.id).locator('.dpv-framed')).toHaveCount(1);
    await expect(tile(pv, b.id).locator('.dpv-framed')).toHaveCount(1);
    await expect(tile(pv, v.id).locator('.dpv-framed')).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath('drive-frame-photos.png') });

    // selected again: GET frame/photos?ids= → „Aus Fotorahmen entfernen“
    await pv.locator('.dpv-head .btn', { hasText: /Auswählen|Select/ }).click();
    await tile(pv, a.id).click();
    await expect(pv.locator('.dpv-selbar [data-act="frame-remove"]')).toBeVisible();
    await expect(pv.locator('.dpv-selbar [data-act="frame-add"]')).toHaveCount(0);
    await expect.poll(() => d.srv.state.frameCalls.some((c) => c.method === 'GET' && Array.isArray(c.ids) && c.ids.includes(a.id))).toBe(true);
    await pv.locator('.dpv-selbar [data-act="frame-remove"]').click();
    await expect(page.locator('#toasts .toast').filter({ hasText: /1 Foto aus dem Fotorahmen entfernt|1 photo removed from the photo frame/ })).toBeVisible();
    await expect.poll(() => d.srv.state.frame.items).toEqual([b.id]);
    await expect(tile(pv, a.id).locator('.dpv-framed')).toHaveCount(0);
    expect(d.srv.state.nodes.get(a.id).deleted).toBeFalsy();

    // the large view: B is shared → remove it there, then share it again
    await tile(pv, b.id).click();
    const light = page.locator('.dv-dlg.dpv-light');
    await expect(light.locator('.dv-dlg-h')).toHaveText('IMG_B.jpg');
    await expect(light.locator('.dpv-frame-btn')).toHaveAttribute('data-act', 'frame-remove');
    await light.locator('.dpv-frame-btn').click();
    await expect(light.locator('.dpv-frame-btn')).toHaveAttribute('data-act', 'frame-add');
    await expect.poll(() => d.srv.state.frame.items).toEqual([]);
    await light.locator('.dpv-frame-btn').click();
    await expect(light.locator('.dpv-frame-btn')).toHaveAttribute('data-act', 'frame-remove');
    await expect.poll(() => d.srv.state.frame.items).toEqual([b.id]);
    // a video in the large view: no entry
    await page.keyboard.press('Escape');
    await expect(light).toHaveCount(0);
    await tile(pv, v.id).click();
    await expect(light.locator('.dv-dlg-h')).toHaveText('VID_C.mp4');
    await expect(light.locator('.dpv-frame-btn')).toHaveCount(0);
  });

  test('403: this account may not share photos', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['photos', 'framePhotos'] });
    const { a } = await photos(d);
    d.srv.frameForbidden = true;
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const pv = await openPhotos(page);
    await pv.locator('.dpv-head .btn', { hasText: /Auswählen|Select/ }).click();
    await tile(pv, a.id).click();
    await pv.locator('.dpv-selbar [data-act="frame-add"]').click();
    await expect(page.locator('#toasts .toast-error').filter({ hasText: /Dieses Konto darf keine Fotos für den Fotorahmen freigeben|This account may not share photos with the photo frame/ })).toBeVisible();
    expect(d.srv.state.frame).toBe(null);
    // the selection stays for another try
    await expect(pv.locator('.dpv-sel-n')).toHaveText(/1/);
  });
});
