'use strict';

const { test, expect } = require('./support/fixtures');
const { launchWithMedien } = require('./support/medien');
const { startJellyfin } = require('./support/jellyfin-mock');

// „Videos umwandeln“ (gatecontrol-medien 1.6.0, Entwurf „umwandeln-entwurf“ Bild 5/6, Frage 100 b): the hint before
// playing on the detail of a film and on a series' page (the episode „S2 F4 weiter ab …“ plays) — only when this PC does
// not show the picture itself (the core's rule: H.264 in every bit depth plays directly) and the plugin knows the file.
// none + „convert“: „Für heute Nacht vormerken“ (only onto the list) → „Zum Umwandeln vorgemerkt“; queued: Platz / ab
// … Uhr; running: n %; done and H.264 files: nothing. Playing stays possible always. An older plugin: no hint, the route
// is not even asked. GC_E2E_SHOTS=<dir>: screenshots light and dark.

const SHOTS = process.env.GC_E2E_SHOTS || null;
const lang = (page, l) => page.evaluate((x) => window.gatecontrol.locale.set(x), l);
const theme = (page, th) => page.evaluate((x) => { if (x === 'light') document.documentElement.setAttribute('data-theme', 'light'); else document.documentElement.removeAttribute('data-theme'); }, th);
async function shots(page, name) {
  if (!SHOTS) return;
  for (const [th, suffix] of [['light', 'hell'], ['dark', 'dunkel']]) {
    await theme(page, th);
    await page.waitForTimeout(150);
    await page.screenshot({ path: `${SHOTS}/${name}-${suffix}.png` });
  }
  await theme(page, 'dark');
}

const page$ = (page) => page.locator('#page-medien');
const byName = (jf, name) => jf.lib.all().find((x) => x.Name === name);
const setCodec = (it, codec, range = 'SDR') => {
  const v = it.MediaSources[0].MediaStreams[0];
  Object.assign(v, { Codec: codec, VideoRangeType: range, VideoRange: range === 'SDR' ? 'SDR' : 'HDR' });
};

async function openMedien(page) {
  await expect(page.locator('#nav-medien')).toBeVisible();
  await page.locator('#nav-medien').click();
  await expect(page$(page)).toHaveClass(/active/);
}

test.describe('medien: Videos umwandeln', () => {
  let jf;
  test.beforeEach(async () => { jf = await startJellyfin(); });
  test.afterEach(async () => { await jf.close(); });

  test('the hint per state on the detail and the series page; vormerken; H.264 files and done without a hint; playing stays', async ({ launchApp, mock }) => {
    const moor = byName(jf, 'Moorlicht');
    setCodec(moor, 'vc1');
    const kobalt = byName(jf, 'Kobaltnacht'); // HEVC HDR10: this PC converts the picture (no decoder / SDR screen)
    const kupfer = byName(jf, 'Kupferstadt'); // H.264: plays here directly, whatever the plugin says
    const zug = byName(jf, 'Zugvogelzeit');
    setCodec(zug, 'mpeg2video');
    const polar = jf.lib.all().find((x) => x.Type === 'Episode' && x.SeriesName === 'Station Eisvogel' && x.ParentIndexNumber === 2 && x.IndexNumber === 4);
    setCodec(polar, 'mpeg2video');
    const tomorrow1 = new Date();
    tomorrow1.setDate(tomorrow1.getDate() + 1);
    tomorrow1.setHours(1, 0, 0, 0);

    const { page, md } = await launchWithMedien({ launchApp, mock, jf, version: '1.6.0' });
    md.convert.items.set(moor.Id, { level: 'convert', reasons: ['legacy_video'], state: 'none' });
    md.convert.items.set(kobalt.Id, { level: 'hint', reasons: ['hevc_10bit'], state: 'queued', position: 2, startsAt: tomorrow1.toISOString() });
    md.convert.items.set(kupfer.Id, { level: 'convert', reasons: ['h264_10bit'], state: 'none' });
    md.convert.items.set(zug.Id, { level: 'convert', reasons: ['legacy_video'], state: 'done' });
    md.convert.items.set(polar.Id, { level: 'convert', reasons: ['legacy_video'], state: 'running', percent: 47 });
    await lang(page, 'de');
    await openMedien(page);
    const p = page$(page);
    await expect.poll(() => md.pairs, { timeout: 30000 }).toBe(1);
    const det = p.locator('.md-det');
    const card = det.locator('.md-conv');

    // none + „convert“: the offer above the buttons; playing stays
    await p.locator('.md-tabs [data-tab="movies"]').click();
    await p.locator('.md-grid .md-pst', { hasText: 'Moorlicht' }).click();
    await expect(det.locator('.md-det-h')).toHaveText('Moorlicht');
    await expect(card).toHaveAttribute('data-kind', 'offer');
    await expect(card).toContainText(/(Wird beim Abspielen umgewandelt|Converted while playing)/);
    await expect(card).toContainText('VC-1');
    await expect(det.locator('.md-play')).toBeEnabled();
    await shots(page, 'detail-vormerken');
    await card.locator('.md-conv-btn').click();
    await expect(card).toHaveAttribute('data-kind', 'requested');
    await expect(card).toContainText(/(Zum Umwandeln vorgemerkt|Marked for converting)/);
    await expect(card.locator('.md-conv-btn')).toHaveCount(0);
    const req = md.log.filter((x) => x.method === 'POST' && x.path === 'v1/convert/request');
    expect(req.map((x) => x.body)).toEqual([{ itemId: moor.Id }]);
    await expect(det.locator('.md-play')).toBeEnabled();
    await shots(page, 'detail-vorgemerkt');

    // queued: Platz 2 · ab 01:00 Uhr (also for a „hint“ file the admin queued)
    await p.locator('.md-grid .md-pst', { hasText: 'Kobaltnacht' }).click();
    await expect(det.locator('.md-det-h')).toHaveText('Kobaltnacht');
    await expect(card).toHaveAttribute('data-kind', 'queued');
    await expect(card).toContainText(/(Wird heute Nacht umgewandelt · Platz 2 · ab 01:00 Uhr|Converted tonight · Position 2 · from 01:00)/);
    await expect(det.locator('.md-play')).toBeEnabled();
    await shots(page, 'detail-warteschlange');

    // H.264 (the plugin: „h264_10bit“) plays on this PC directly; done: nothing
    await p.locator('.md-grid .md-pst', { hasText: 'Kupferstadt' }).click();
    await expect(det.locator('.md-det-h')).toHaveText('Kupferstadt');
    await p.locator('.md-grid .md-pst', { hasText: 'Zugvogelzeit' }).click();
    await expect(det.locator('.md-det-h')).toHaveText('Zugvogelzeit');
    await expect(det.locator('.md-play')).toBeVisible();
    await page.waitForTimeout(800);
    await expect(card).toHaveCount(0);
    await p.locator('.md-grid .md-pst', { hasText: 'Kupferstadt' }).click();
    await expect(det.locator('.md-det-h')).toHaveText('Kupferstadt');
    await page.waitForTimeout(500);
    await expect(card).toHaveCount(0);

    // the series page: the episode that plays next (S2 F4) is being converted — n % with the bar
    await p.locator('.md-tabs [data-tab="series"]').click();
    await p.locator('.md-grid .md-pst', { hasText: 'Station Eisvogel' }).click();
    await expect(det.locator('.md-det-h')).toHaveText('Station Eisvogel');
    await expect(card).toHaveAttribute('data-kind', 'running');
    await expect(card).toContainText(/(Wird gerade umgewandelt – 47 %|Being converted now – 47 %)/);
    await expect(card.locator('.md-conv-bar > span')).toHaveAttribute('style', /width:47%/);
    await expect(det.locator('.md-play')).toBeEnabled();
    await expect(det.locator('.md-ep')).toHaveCount(6);
    await shots(page, 'folge-laeuft');

    // asked together, never per line: a handful of questions for all of it
    const asked = md.log.filter((x) => x.path === 'v1/convert/status').length;
    expect(asked).toBeGreaterThan(0);
    expect(asked).toBeLessThanOrEqual(8);
  });

  test('a plugin before 1.6.0: no hint and the route not asked', async ({ launchApp, mock }) => {
    const moor = byName(jf, 'Moorlicht');
    setCodec(moor, 'vc1');
    const { page, md } = await launchWithMedien({ launchApp, mock, jf });
    md.convert.items.set(moor.Id, { level: 'convert', state: 'none' });
    await openMedien(page);
    const p = page$(page);
    await expect.poll(() => md.pairs, { timeout: 30000 }).toBe(1);
    await p.locator('.md-tabs [data-tab="movies"]').click();
    await p.locator('.md-grid .md-pst', { hasText: 'Moorlicht' }).click();
    const det = p.locator('.md-det');
    await expect(det.locator('.md-det-h')).toHaveText('Moorlicht');
    await expect(det.locator('.md-play')).toBeVisible();
    await page.waitForTimeout(1000);
    await expect(det.locator('.md-conv')).toHaveCount(0);
    expect(md.log.some((x) => x.path.startsWith('v1/convert/'))).toBe(false);
  });
});
