'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive 1.25 'mediaFilter' on the page "Drive": "Alle · Fotos · Videos" in "Fotos" (photos?media=, a video's length on
// its tile) and "Fotos" / "Videos" over the hits of the search (search?media=). Without the feature nothing of it shows.
// The plugin is the core's fake Drive server (support/drive-mock.js).

const tool = (root, view) => root.locator(`.dv-tool[data-view="${view}"]`);

async function openDrive(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  const root = page.locator('#page-drive');
  // Drive 1.18: Drive opens on "Übersicht"; these tests work in "Dateien"
  const files = root.locator('.dv-pages [data-page="files"]');
  await expect(files.or(root.locator('.dv-gate:visible')).first()).toBeVisible();
  if (await files.isVisible()) await files.click();
  return root;
}

function seed(d) {
  const bilder = d.srv.mutate.dir(1, 'Bilder');
  const t0 = Date.now() - 3600000;
  d.srv.mutate.photo(bilder.id, 'Urlaub.jpg', { takenAt: t0 });
  const v = d.srv.mutate.photo(bilder.id, 'Urlaub.mp4', { takenAt: t0 + 1000, mime: 'video/mp4', durationMs: 83000 });
  return { bilder, v };
}

test.describe('drive 1.25', () => {
  test('Fotos: Alle · Fotos · Videos, the length of a video', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['photos', 'mediaFilter'] });
    const { v } = seed(d);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await tool(root, 'photos').click();
    const pv = root.locator('.dpv');
    await expect(pv).toBeVisible();
    const seg = pv.locator('.dpv-media');
    await expect(seg.locator('button')).toHaveText([/Alle|All/, /Fotos|Photos/, /Videos/]);
    await expect(seg.locator('[data-media="all"]')).toHaveAttribute('aria-checked', 'true');
    await expect(pv.locator(`.dpv-tile[data-id="${v.id}"] .dpv-play`)).toHaveText('1:23');
    const before = await pv.locator('.dpv-tile').count();
    expect(before).toBeGreaterThan(1);
    await seg.locator('[data-media="video"]').click();
    await expect(pv.locator('.dpv-tile')).toHaveCount(1);
    await expect(pv.locator(`.dpv-tile[data-id="${v.id}"]`)).toBeVisible();
    await expect.poll(() => d.srv.state.requests.some((r) => r.path.endsWith('/photos') && r.query.media === 'video')).toBe(true);
    await expect.poll(() => d.srv.state.requests.some((r) => r.path.endsWith('/photos/months') && r.query.media === 'video')).toBe(true);
    await page.screenshot({ path: test.info().outputPath('drive-photos-videos.png') });
    await seg.locator('[data-media="image"]').click();
    await expect(pv.locator(`.dpv-tile[data-id="${v.id}"]`)).toHaveCount(0);
    await expect(pv.locator('.dpv-tile .dpv-play')).toHaveCount(0);
    await seg.locator('[data-media="all"]').click();
    await expect(pv.locator('.dpv-tile')).toHaveCount(before);
  });

  test('search: Fotos / Videos over the hits', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['photos', 'mediaFilter'] });
    seed(d);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await root.locator('.dv-search-in').fill('urlaub');
    await expect(root.locator('.dv-row', { hasText: 'Urlaub.jpg' })).toBeVisible();
    await expect(root.locator('.dv-row', { hasText: 'Urlaub.mp4' })).toBeVisible();
    const chips = root.locator('.dv-search-media');
    await chips.locator('[data-media="video"]').click();
    await expect(root.locator('.dv-row', { hasText: 'Urlaub.jpg' })).toHaveCount(0);
    await expect(root.locator('.dv-row', { hasText: 'Urlaub.mp4' })).toBeVisible();
    await expect(chips.locator('[data-media="video"]')).toHaveAttribute('aria-pressed', 'true');
    expect(d.srv.state.requests.some((r) => r.path.endsWith('/search') && r.query.media === 'video' && r.query.q === 'urlaub')).toBe(true);
    // a second click: every hit again
    await chips.locator('[data-media="video"]').click();
    await expect(root.locator('.dv-row', { hasText: 'Urlaub.jpg' })).toBeVisible();
  });

  test('an older Drive: no filter, no chips', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['photos'] });
    seed(d);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await root.locator('.dv-search-in').fill('urlaub');
    await expect(root.locator('.dv-row', { hasText: 'Urlaub.mp4' })).toBeVisible();
    await expect(root.locator('.dv-search-media')).toHaveCount(0);
    await tool(root, 'photos').click();
    await expect(root.locator('.dpv .dpv-tile').first()).toBeVisible();
    await expect(root.locator('.dpv-media')).toHaveCount(0);
    expect(d.srv.state.requests.some((r) => r.query && r.query.media)).toBe(false);
  });
});
