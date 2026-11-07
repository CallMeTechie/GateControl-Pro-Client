'use strict';

const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive 1.21 on the page "Drive": a picture in "Dateien" opens the large view (not the default program), the arrow
// keys go through the pictures and videos of the folder, + zooms, a video plays right there from gcdrive: (the core's
// DriveStreamService streams the fake Drive's media route with Range), Esc closes it; a video the virus scan holds
// back shows its reason and gets no address. The plugin is the core's fake Drive server (support/drive-mock.js).

const CLIP = path.join(__dirname, 'fixtures', 'clip.webm'); // 3 s, 320×180, VP8

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

test.describe('drive 1.21', () => {
  test('a picture opens large, → the video plays streamed with Range, Esc closes', async ({ launchApp, mock }) => {
    const d = await mock.setDrive();
    const clip = d.srv.mutate.photo(1, 'Urlaub.webm', { content: fs.readFileSync(CLIP), mime: 'video/webm' });
    const { page, events } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(root.locator('.dv-row[data-id="11"]')).toBeVisible();
    await root.locator('.dv-row[data-id="11"] .dv-open').click();
    const light = page.locator('.dv-dlg.dpv-light');
    await expect(light.locator('.dv-dlg-h')).toHaveText('Foto.jpg');
    await expect(light.locator('.dvw-pic')).toBeVisible();
    await expect(light.locator('.dpv-meta')).toContainText('1 / 2');
    // zoom
    await page.keyboard.press('+');
    await expect(light.locator('.dvw-pic')).toHaveClass(/is-zoomed/);
    await page.keyboard.press('0');
    await expect(light.locator('.dvw-pic')).not.toHaveClass(/is-zoomed/);
    // the next: the video, streamed from gcdrive:
    await page.keyboard.press('ArrowRight');
    await expect(light.locator('.dv-dlg-h')).toHaveText('Urlaub.webm');
    const video = light.locator('video.dvw-player');
    await expect(video).toBeVisible();
    await expect(video).toHaveAttribute('src', /^gcdrive:\/\/media\/[A-Za-z0-9_-]{24}$/);
    await expect.poll(() => video.evaluate((v) => v.readyState), { timeout: 20000 }).toBeGreaterThanOrEqual(2);
    await expect.poll(() => d.srv.state.mediaGets.filter((g) => g.mediaId === clip.mediaId).length).toBeGreaterThan(0);
    await page.screenshot({ path: test.info().outputPath('drive-viewer-video.png') });
    await page.keyboard.press('Escape');
    await expect(light).toHaveCount(0);
    // nothing went to the default program
    expect(events().filter((e) => e.type === 'shell.openPath')).toEqual([]);
  });

  test('a video the virus scan holds back: the reason, no address', async ({ launchApp, mock }) => {
    const d = await mock.setDrive();
    const v = d.srv.mutate.photo(1, 'Neu.webm', { content: fs.readFileSync(CLIP), mime: 'video/webm' });
    d.srv.state.nodes.get(v.id).scan = { state: 'pending', blocked: true, finding: null };
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await root.locator('.dv-row[data-id="11"] .dv-open').click();
    const light = page.locator('.dv-dlg.dpv-light');
    await expect(light.locator('.dv-dlg-h')).toHaveText('Foto.jpg');
    await page.keyboard.press('ArrowRight');
    await expect(light.locator('.dv-dlg-h')).toHaveText('Neu.webm');
    await expect(light.locator('.dpv-scan-reason')).toBeVisible();
    await expect(light.locator('video')).toHaveCount(0);
    expect(d.srv.state.mediaGets.filter((g) => g.mediaId === v.mediaId)).toEqual([]);
  });
});
