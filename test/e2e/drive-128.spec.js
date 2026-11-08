'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive plugin 1.28 on the page "Drive" (the plugin is the core's fake Drive server, support/drive-mock.js): on a day
// without „Heute vor X Jahren“ (`memories` empty) GET overview's `memoryPicks` fill the tile "Erinnerungen" — cards with
// the titles of the page "Erinnerungen"; a card opens its collection there (GET memories/photos), "Alle" the page. With
// a day the days show as before; with neither the tile stays out.

async function openDrive(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  return page.locator('#page-drive');
}

function overview(d, { memories = [], memoryPicks = [] } = {}) {
  d.srv.overview = {
    todo: null, recent: [], people: null, places: null, activity: [], storage: { used: 1, total: null, target: null },
    memories, memoryPicks,
  };
}

async function photos(d) {
  const bilder = d.srv.mutate.dir(1, 'Bilder');
  const t0 = new Date(2025, 6, 11, 12).getTime();
  return Array.from({ length: 6 }, (_, i) => d.srv.mutate.photo(bilder.id, `Hafen ${i}.jpg`, { takenAt: t0 + i * 60000 }).id);
}

const FEATURES = ['photos', 'overview', 'memoryCollections', 'memoryPicks'];

test.describe('drive 1.28', () => {
  test('without a day: the picks with the page\'s titles, a card its collection, "Alle" the page', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: FEATURES });
    const ids = await photos(d);
    const cover = { id: ids[0], areaId: 'family:3', parentId: 1, name: 'Hafen 0.jpg', mime: 'image/jpeg', size: 10 };
    const picks = [
      { id: 'trip:2025-07-10:2025-07-14', kind: 'trip', place: { key: 'geonames:2911298', name: 'Hamburg', region: 'Hamburg', country: 'DE' }, places: ['Hamburg'], days: 5, firstDay: '2025-07-10', lastDay: '2025-07-14', count: 6, cover, from: '2025-07-10T00:00:00.000Z', to: '2025-07-15T00:00:00.000Z' },
      { id: 'person:7', kind: 'person', person: { id: 7, name: 'Noah' }, count: 11, cover, from: '2024-01-01T11:00:00.000Z', to: '2024-01-21T11:00:00.000Z' },
      { id: 'year:2024', kind: 'year', year: 2024, count: 71, cover: null, from: '2024-01-01T00:00:00.000Z', to: '2025-01-01T00:00:00.000Z' },
    ];
    overview(d, { memoryPicks: picks });
    d.srv.memoryCollections = { date: '2026-11-08', home: { key: 'geonames:1', name: 'Langenlonsheim' }, collections: picks };
    d.srv.memoryPhotos = { 'trip:2025-07-10:2025-07-14': ids, 'person:7': ids.slice(0, 2), 'year:2024': ids.slice(0, 1) };
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    const ov = root.locator('.dov');
    const tile = ov.locator('[data-tile="memories"]');
    await expect(tile.locator('.dov-mem')).toHaveCount(3);
    await expect(tile.locator('[data-memory="trip:2025-07-10:2025-07-14"] b')).toHaveText('Hamburg');
    await expect(tile.locator('[data-memory="person:7"] b')).toHaveText(/^(Mit|With) Noah$/);
    await expect(tile.locator('[data-memory="year:2024"] b')).toHaveText(/^2024 (im Rückblick|in review)$/);
    await expect(tile.locator('[data-memory="trip:2025-07-10:2025-07-14"] .dov-mem-tx span')).toHaveText(/^6 (Fotos|photos)$/);
    await page.screenshot({ path: test.info().outputPath('drive-memory-picks.png') });

    // a card: its collection on the page "Erinnerungen", as a click there
    await tile.locator('[data-memory="trip:2025-07-10:2025-07-14"]').click();
    const mm = root.locator('.dmm');
    await expect(mm).toBeVisible();
    await expect(ov).toBeHidden();
    await expect(mm.locator('.dmm-crumbs .dsv-h')).toHaveText('Hamburg');
    await expect(mm.locator('.dmm-grid .dpv-tile')).toHaveCount(6);
    expect(d.srv.state.requests.some((r) => r.path.endsWith('/memories/photos') && r.query.id === 'trip:2025-07-10:2025-07-14')).toBe(true);
    await mm.locator('.dmm-back').click();
    await expect(mm.locator('.dmm-sec')).toHaveCount(3);

    // "Alle": the page
    await root.locator('.dv-pages [data-page="overview"]').click();
    await expect(ov).toBeVisible();
    await tile.locator('.dov-link').click();
    await expect(mm).toBeVisible();
    await expect(mm.locator('.dmm-sec')).toHaveCount(3);
  });

  test('a day: the days as before, the picks stay out; neither: no tile', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: FEATURES });
    const ids = await photos(d);
    const cover = { id: ids[0], areaId: 'family:3', parentId: 1, name: 'Hafen 0.jpg', mime: 'image/jpeg', size: 10 };
    overview(d, {
      memories: [{ yearsAgo: 1, date: '2025-11-08', count: 12, id: 'day:2025-11-08', cover }],
      memoryPicks: [{ id: 'person:7', kind: 'person', person: { id: 7, name: 'Noah' }, count: 11, cover }],
    });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    const tile = root.locator('.dov [data-tile="memories"]');
    await expect(tile.locator('.dov-mem')).toHaveCount(1);
    await expect(tile.locator('[data-memory="person:7"]')).toHaveCount(0);
    await expect(tile.locator('.dov-mem b')).toHaveText(/Jahr|year/);

    // neither days nor picks: the tile stays out (reloaded on the next visit)
    overview(d);
    await root.locator('.dv-pages [data-page="files"]').click();
    await root.locator('.dv-pages [data-page="overview"]').click();
    await expect(root.locator('.dov [data-tile="memories"]')).toHaveCount(0);
  });
});
