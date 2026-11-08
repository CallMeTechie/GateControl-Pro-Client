'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive plugin 1.26 on the page "Drive" (the plugin is the core's fake Drive server, support/drive-mock.js): with
// 'memoryCollections' the overview's "Alle" of "Erinnerungen" opens the page "Erinnerungen" — the collections of
// GET memories as cards by section; a card shows its photos (GET memories/photos), a tile the large view; a card of the
// overview opens its collection. Without the feature "Alle" opens "Fotos" as before.

async function openDrive(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  return page.locator('#page-drive');
}

function memories(d, ids) {
  const cover = { id: ids[0], areaId: 'family:3', parentId: 1, name: 'Strand 0.jpg', mime: 'image/jpeg', size: 10 };
  d.srv.overview = {
    todo: null, recent: [], people: null, places: null, activity: [], storage: { used: 1, total: null, target: null },
    memories: [{ yearsAgo: 1, date: '2025-11-08', count: 12, id: 'day:2025-11-08', cover }],
  };
  d.srv.memoryCollections = {
    date: '2026-11-08', home: { key: 'geonames:1', name: 'Langenlonsheim' },
    collections: [
      { id: 'day:2025-11-08', kind: 'day', yearsAgo: 1, date: '2025-11-08', count: 12, cover },
      { id: 'trip:2025-07-10:2025-07-14', kind: 'trip', place: { key: 'geonames:2', name: 'Hamburg' }, places: ['Hamburg'], days: 5, firstDay: '2025-07-10', lastDay: '2025-07-14', count: 12, cover },
      { id: 'place:geonames:1', kind: 'place', place: { key: 'geonames:1', name: 'Langenlonsheim' }, count: 12, cover },
    ],
  };
  d.srv.memoryPhotos = { 'day:2025-11-08': ids, 'trip:2025-07-10:2025-07-14': ids.slice(0, 4), 'place:geonames:1': ids };
}

test.describe('drive 1.26', () => {
  test('"Alle" opens "Erinnerungen": cards by section, a card its photos, a tile the large view', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['photos', 'overview', 'memoryCollections'] });
    const bilder = d.srv.mutate.dir(1, 'Bilder');
    const t0 = new Date(2025, 10, 8, 12).getTime();
    const ids = Array.from({ length: 12 }, (_, i) => d.srv.mutate.photo(bilder.id, `Strand ${i}.jpg`, { takenAt: t0 + i * 60000 }).id);
    memories(d, ids);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    const ov = root.locator('.dov');
    await expect(ov.locator('[data-tile="memories"] .dov-mem')).toHaveCount(1);

    // "Alle": the page, its sections, the note
    await ov.locator('[data-tile="memories"] .dov-link').click();
    const mm = root.locator('.dmm');
    await expect(mm).toBeVisible();
    await expect(ov).toBeHidden();
    await expect(root.locator('.dv-pages [data-page="photos"]')).toHaveAttribute('aria-selected', 'true');
    await expect(mm.locator('.dmm-sec')).toHaveCount(3);
    await expect(mm.locator('.dmm-sec').nth(0).locator('.dmm-h')).toHaveText(/Heute in früheren Jahren|On this day in earlier years/);
    await expect(mm.locator('.dmm-sec').nth(1).locator('.dmm-h')).toHaveText(/Ausflüge und Reisen|Trips and travels/);
    await expect(mm.locator('.dmm-sec').nth(2).locator('.dmm-h')).toHaveText(/Orte|Places/);
    await expect(mm.locator('.dmm-note')).toHaveText(/Nur private Fotos|Only private photos/);
    await expect(mm.locator('[data-memory="trip:2025-07-10:2025-07-14"] b')).toHaveText('Hamburg');
    await expect(mm.locator('[data-memory="place:geonames:1"] b')).toHaveText('Langenlonsheim');
    await page.screenshot({ path: test.info().outputPath('drive-memories.png') });

    // a card: its photos, the way back
    await mm.locator('[data-memory="trip:2025-07-10:2025-07-14"]').click();
    await expect(mm.locator('.dmm-grid .dpv-tile')).toHaveCount(4);
    await expect(mm.locator('.dmm-crumbs .dsv-h')).toHaveText('Hamburg');
    // a tile: the large view of "Fotos"
    await mm.locator('.dmm-grid .dpv-tile').first().click();
    await expect(page.locator('.dv-dlg.dpv-light .dv-dlg-h')).toHaveText(/^Strand \d+\.jpg$/);
    await page.keyboard.press('Escape');
    await mm.locator('.dmm-back').click();
    await expect(mm.locator('.dmm-sec')).toHaveCount(3);

    // a card of the overview: its collection right away
    await root.locator('.dv-pages [data-page="overview"]').click();
    await expect(ov).toBeVisible();
    await ov.locator('[data-tile="memories"] .dov-mem').click();
    await expect(mm).toBeVisible();
    await expect(mm.locator('.dmm-grid .dpv-tile')).toHaveCount(12);
  });

  test('an older Drive (no memoryCollections): "Alle" opens "Fotos"', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['photos', 'overview'] });
    const bilder = d.srv.mutate.dir(1, 'Bilder');
    const t0 = new Date(2025, 10, 8, 12).getTime();
    const ids = Array.from({ length: 12 }, (_, i) => d.srv.mutate.photo(bilder.id, `Strand ${i}.jpg`, { takenAt: t0 + i * 60000 }).id);
    memories(d, ids);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    const ov = root.locator('.dov');
    await ov.locator('[data-tile="memories"] .dov-link').click();
    await expect(root.locator('.dpv')).toBeVisible();
    await expect(root.locator('.dmm')).toBeHidden();
  });
});
