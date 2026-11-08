'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive 1.18 on the page "Drive" (mockup WinStart; the plugin is the core's fake Drive server, support/drive-mock.js):
// Drive opens on "Übersicht" (Übersicht | Dateien | Fotos next to the title); with 'overview' its tiles come from
// GET overview, without it the core builds them from what the Drive has ("Vor einem Jahr" from photos/memories). The
// page is not kept: back on Drive it is the overview again. Texts in both languages.

async function openDrive(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  return page.locator('#page-drive');
}

const node = (id, name, extra = {}) => ({ id, areaId: 'family:3', parentId: 1, name, isDir: false, size: 10, rev: 1, ...extra });

test.describe('drive 1.18', () => {
  test('the overview of GET overview: its tiles, and where they lead', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['docAi', 'photos', 'photoPlaces', 'photoPeople', 'overview'] });
    d.srv.overview = {
      todo: {
        deadlines: [{ id: 1, kind: 'payment', date: '2099-11-04', label: 'Rechnung Stadtwerke zahlen', node: node(10, 'Rechnung.pdf') }],
        deadlinesTotal: 1, review: 12, toFile: 3, toFileHint: 'Familie › Versicherungen',
      },
      recent: [{ ...node(21, 'Steuerbescheid 2025.pdf', { mime: 'application/pdf' }), openedAt: new Date(Date.now() - 86400000).toISOString(), areaLabel: 'Familie' }],
      memories: [],
      people: { people: [{ id: 1, name: 'Lea', count: 3 }], unnamed: 2 },
      places: { top: [{ key: 'geonames:2886242', name: 'Köln', count: 1629 }, { key: 'geonames:2911298', name: 'Hamburg', count: 214 }], cluster: { lat: 50.94, lon: 6.96, count: 3871 }, total: 3871 },
      activity: [{ at: new Date(Date.now() - 2 * 3600000).toISOString(), user: { id: 2, name: 'Mama' }, kind: 'added_photos', count: 14, area: { id: 'family:3', label: 'Familie' }, folder: { id: 1, path: 'Urlaub 2026' }, sample: null }],
      storage: { used: 212e9, total: 1e12, target: null },
    };
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);

    // Drive opens on "Übersicht"
    const pages = root.locator('.dv-pages');
    await expect(pages.locator('[data-page="overview"]')).toHaveAttribute('aria-selected', 'true');
    await expect(pages.locator('button')).toHaveCount(3);
    const ov = root.locator('.dov');
    await expect(ov).toBeVisible();
    await expect(root.locator('.dv-list-wrap')).toBeHidden();
    await expect(ov.locator('.dov-panel')).toHaveCount(5);
    await expect(ov.locator('[data-tile="todo"] .dov-n')).toHaveText('3');
    await expect(ov.locator('[data-tile="todo"] .dov-row')).toHaveCount(3);
    await expect(ov.locator('[data-tile="recent"] .dov-row-t')).toHaveText('Steuerbescheid 2025.pdf');
    await expect(ov.locator('[data-tile="activity"] .dov-h')).toHaveText(/Neu in Familie|New in Familie/);
    await expect(ov.locator('[data-tile="activity"] .dov-row-t')).toHaveText(/Mama (hat 14 Fotos hinzugefügt|added 14 photos)/);
    await expect(ov.locator('[data-tile="activity"] .dov-store')).toBeVisible();
    await expect(ov.locator('[data-tile="people"] .dov-face')).toHaveCount(2);
    await expect(ov.locator('[data-tile="people"] .dov-face.is-who')).toBeVisible();
    await expect(ov.locator('[data-tile="places"] .dov-place')).toHaveCount(2);
    await expect(ov.locator('[data-tile="places"] .dov-map-attr')).toHaveText(/OpenStreetMap/);
    // no memories: no tile
    await expect(ov.locator('[data-tile="memories"]')).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath('drive-overview.png') });

    // a person leads to "Fotos" at that person
    await ov.locator('[data-tile="people"] .dov-face[data-person="1"]').click();
    await expect(root.locator('.dpv')).toBeVisible();
    await expect(pages.locator('[data-page="photos"]')).toHaveAttribute('aria-selected', 'true');

    // "Dateien": the folder; "Übersicht" again
    await pages.locator('[data-page="files"]').click();
    await expect(root.locator('.dv-row[data-id="10"]')).toBeVisible();
    await expect(ov).toBeHidden();
    await pages.locator('[data-page="overview"]').click();
    await expect(ov).toBeVisible();
    await expect(root.locator('.dv-list-wrap')).toBeHidden();

    // the page is not kept: away and back, the overview
    await pages.locator('[data-page="files"]').click();
    await expect(root.locator('.dv-row[data-id="10"]')).toBeVisible();
    await page.locator('#nav-status').click();
    await openDrive(page);
    await expect(pages.locator('[data-page="overview"]')).toHaveAttribute('aria-selected', 'true');
    await expect(ov).toBeVisible();
  });

  test('without overview: the tiles the Drive can fill ("Vor einem Jahr" from the memories), nothing else', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['photos'] });
    const bilder = d.srv.mutate.dir(1, 'Bilder');
    const now = new Date();
    const ago = new Date(now.getFullYear() - 1, now.getMonth(), now.getDate(), 12).getTime();
    d.srv.mutate.photo(bilder.id, 'Damals.jpg', { takenAt: ago });
    // Drive plugin 1.26 (and the core for an older Drive): a memory only with more than 10 photos that day
    for (let i = 1; i <= 10; i++) d.srv.mutate.photo(bilder.id, `Damals ${i}.jpg`, { takenAt: ago + i * 60000 });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    const ov = root.locator('.dov');
    await expect(ov).toBeVisible();
    await expect(ov.locator('[data-tile="memories"] .dov-mem')).toHaveCount(1);
    await expect(ov.locator('[data-tile="memories"] .dov-mem b')).toHaveText(/Heute vor einem Jahr|Today one year ago/);
    await expect(ov.locator('[data-tile="recent"]')).toHaveCount(0);
    await expect(ov.locator('[data-tile="activity"]')).toHaveCount(0);
    // a memory shows its photos large
    await ov.locator('[data-tile="memories"] .dov-mem').click();
    await expect(page.locator('.dv-dlg.dpv-light .dv-dlg-h')).toHaveText(/^Damals( \d+)?\.jpg$/);
    await page.keyboard.press('Escape');
    // "Fotos": only the pictures, no "Vor einem Jahr"
    await root.locator('.dv-pages [data-page="photos"]').click();
    // the eleven of that day and the Foto.jpg of the fake
    await expect(root.locator('.dpv .dpv-month .dpv-tile')).toHaveCount(12);
    await expect(root.locator('.dpv-mem')).toHaveCount(0);
  });
});
