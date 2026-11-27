'use strict';

const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// "Bildschirm bleibt an" for the videos outside the Medien player (renderer/video-awake.js → main/media-awake.js,
// Electron's powerSaveBlocker, counted by the e2e hooks: __gcE2E.awake()): on only while a video really plays —
// Drive's viewer (pause off, play on, closing off), a camera clip (on), the camera's live picture never.

const CLIP = path.join(__dirname, 'fixtures', 'clip.webm'); // 3 s, 320×180, VP8
const CAM1 = 'c0123456789abcde';
const ago = (min) => new Date(Date.now() - min * 60000).toISOString();

const awake = (app) => app.evaluate(() => globalThis.__gcE2E.awake());

test.describe('video: the screen stays on while it plays', () => {
  test('Drive\'s viewer: on while it plays, off on pause and when it closes', async ({ launchApp, mock }) => {
    const d = await mock.setDrive();
    d.srv.mutate.photo(1, 'Urlaub.webm', { content: fs.readFileSync(CLIP), mime: 'video/webm' });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-drive').click();
    const root = page.locator('#page-drive');
    const files = root.locator('.dv-pages [data-page="files"]');
    await expect(files.or(root.locator('.dv-gate:visible')).first()).toBeVisible();
    if (await files.isVisible()) await files.click();
    expect(await awake(app)).toBe(false);

    await root.locator('.dv-row[data-id="11"] .dv-open').click();
    const light = page.locator('.dv-dlg.dpv-light');
    await expect(light.locator('.dvw-pic')).toBeVisible();
    expect(await awake(app)).toBe(false);
    await page.keyboard.press('ArrowRight');
    const video = light.locator('video.dvw-player');
    await expect(video).toBeVisible();
    await expect.poll(() => video.evaluate((v) => v.readyState), { timeout: 20000 }).toBeGreaterThanOrEqual(2);
    // the clip is 3 s: it loops so it keeps playing
    await video.evaluate((v) => { v.loop = true; v.muted = true; return v.play(); });
    await expect.poll(() => awake(app)).toBe(true);
    await video.evaluate((v) => v.pause());
    await expect.poll(() => awake(app)).toBe(false);
    await video.evaluate((v) => v.play());
    await expect.poll(() => awake(app)).toBe(true);
    await page.keyboard.press('Escape');
    await expect(light).toHaveCount(0);
    await expect.poll(() => awake(app)).toBe(false);
  });

  test('cameras: a clip keeps the screen on, the live picture does not', async ({ launchApp, mock }) => {
    mock.setDoor({
      mode: 'live',
      cameras: [{ id: CAM1, name: 'Einfahrt', model: 'Reolink RLC-510A' }],
      clips: { [CAM1]: [{ id: 'e000000000000001', kind: 'person', kinds: ['person'], startedAt: ago(30), ms: 24000 }] },
    });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-kameras').click();
    const p = page.locator('#page-kameras');
    const video = p.locator('video.cm-media');
    await expect(video).toHaveAttribute('src', /live\.mp4$/);
    await expect.poll(() => video.evaluate((v) => v.readyState), { timeout: 20000 }).toBeGreaterThanOrEqual(2);
    await expect.poll(() => video.evaluate((v) => !v.paused || v.ended)).toBe(true);
    expect(await awake(app)).toBe(false);

    await p.locator('.cm-clip').first().click();
    await expect(video).toHaveAttribute('src', /clip\.mp4$/);
    await expect.poll(() => video.evaluate((v) => v.readyState), { timeout: 20000 }).toBeGreaterThanOrEqual(2);
    await video.evaluate((v) => { v.loop = true; return v.play(); });
    await expect.poll(() => awake(app)).toBe(true);
    // back to the live picture: off
    await p.locator('.cm-back').click();
    await expect.poll(() => awake(app)).toBe(false);
  });
});
