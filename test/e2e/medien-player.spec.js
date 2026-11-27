'use strict';

const { test, expect } = require('./support/fixtures');
const { launchWithMedien } = require('./support/medien');
const { startJellyfin } = require('./support/jellyfin-mock');

// Medien › Player (Stufe 4g): plays in the app's window with its own controls — a film played directly (the file
// through gcmedia: with Range), the info line, the keys (Leertaste, → ←, Esc), the panel with sound, subtitles and
// quality, the progress at Jellyfin (start, progress, stop with the position); HEVC without a decoder (only sound,
// videoWidth 0) → asked again, Jellyfin converts to HLS (hls.js from vendor/, through gcmedia:, no api_key in the
// page); a text subtitle as WebVTT <track>; the end of an episode → "Nächste Folge". Fake Jellyfin:
// support/jellyfin-mock.js; the films are made with ffmpeg (fixtures/media-*.webm, media-hls/).

const page$ = (page) => page.locator('#page-medien');

/** Medien from the server (plugin Medien): signed in at Jellyfin by itself, away through the (fake) VPN. */
async function signedIn(launchApp, mock, jf) {
  const { page, md } = await launchWithMedien({ launchApp, mock, jf });
  await page.locator('#nav-medien').click();
  const p = page$(page);
  await expect.poll(() => md.pairs, { timeout: 30000 }).toBe(1);
  return { page, p };
}

const video = (page) => page.locator('.mp video');
const time = (page) => video(page).evaluate((v) => v.currentTime);

test.describe('medien player', () => {
  let jf;
  test.beforeEach(async () => { jf = await startJellyfin(); });
  test.afterEach(async () => { await jf.close(); });

  test('a film played directly: info line, keys, panel, progress at Jellyfin, back with Esc', async ({ launchApp, mock }) => {
    const { page, p } = await signedIn(launchApp, mock, jf);
    await p.locator('.md-tabs [data-tab="movies"]').click();
    await p.locator('.md-grid .md-pst', { hasText: 'Achterwasser' }).click();
    await expect(p.locator('.md-det .md-det-h')).toHaveText('Achterwasser');
    await p.locator('.md-det .md-play').click();

    const mp = page.locator('.mp');
    await expect(mp).toBeVisible();
    await expect(mp.locator('.mp-title')).toHaveText('Achterwasser');
    await expect(video(page)).toHaveAttribute('src', /^gcmedia:\/\/media\//);
    await expect.poll(() => time(page), { timeout: 20000 }).toBeGreaterThan(1);
    await expect.poll(() => video(page).evaluate((v) => v.videoWidth)).toBe(320);
    await expect(mp.locator('.mp-info')).toContainText(/(Unterwegs|Away) · \d/);
    await expect(mp.locator('.mp-info')).toContainText('Original');
    await expect.poll(() => jf.reports.filter((r) => r.path === '/Sessions/Playing').length).toBe(1);
    // the access never in the page
    expect(await page.content()).not.toContain('e2e-jellyfin-token');

    // Leertaste: pause and on
    await page.keyboard.press('Space');
    await expect.poll(() => video(page).evaluate((v) => v.paused)).toBe(true);
    await expect.poll(() => jf.reports.filter((r) => r.path === '/Sessions/Playing/Progress').length).toBeGreaterThan(0);
    await page.keyboard.press('Space');
    await expect.poll(() => video(page).evaluate((v) => v.paused)).toBe(false);
    // → 10 s forward, ← back
    const before = await time(page);
    await page.keyboard.press('ArrowRight');
    await expect.poll(() => time(page)).toBeGreaterThan(before + 8);
    await page.keyboard.press('ArrowLeft');
    await expect.poll(() => time(page)).toBeLessThan(before + 8);

    // the panel: sound, subtitles, quality
    await mp.locator('.mp-panel-btn').click();
    await expect(mp.locator('.mp-panel')).toBeVisible();
    await expect(mp.locator('.mp-opt-audio')).toHaveCount(1);
    await expect(mp.locator('.mp-opt-sub.is-on')).toHaveText(/^(Aus|Off)/);
    await expect(mp.locator('.mp-opt-quality')).toHaveCount(7);
    await expect(mp.locator('.mp-opt-quality.is-on')).toContainText(/(Automatisch|Automatic)/);
    await page.keyboard.press('Escape');
    await expect(mp.locator('.mp-panel')).toBeHidden();

    // Esc: back to the page; Jellyfin gets the stop with the position
    await page.keyboard.press('Escape');
    await expect(mp).toBeHidden();
    await expect(p).toHaveClass(/active/);
    await expect.poll(() => jf.reports.filter((r) => r.path === '/Sessions/Playing/Stopped').length).toBe(1);
    const stopped = jf.reports.find((r) => r.path === '/Sessions/Playing/Stopped');
    expect(stopped.body.PositionTicks).toBeGreaterThan(0);
  });

  test('HEVC without a decoder: no picture → asked again, HLS through hls.js; a text subtitle as WebVTT', async ({ launchApp, mock }) => {
    const { page, p } = await signedIn(launchApp, mock, jf);
    await p.locator('.md-tabs [data-tab="movies"]').click();
    await p.locator('.md-grid .md-pst', { hasText: 'Kobaltnacht' }).click();
    await expect(p.locator('.md-det .md-play')).toContainText('42:10');
    await p.locator('.md-det .md-restart').click();

    const mp = page.locator('.mp');
    await expect(mp).toBeVisible();
    // the caps of this Chromium went to the core before the first PlaybackInfo
    await expect.poll(() => jf.state.playbackInfo.length).toBeGreaterThan(0);
    expect(jf.state.playbackInfo[0].body.DeviceProfile.DirectPlayProfiles.length).toBeGreaterThan(0);
    // only sound: the player asks again, Jellyfin converts (HLS in fMP4 through hls.js)
    await expect.poll(() => jf.state.playbackInfo.length, { timeout: 20000 }).toBe(2);
    await expect.poll(() => jf.state.hlsFiles.includes('seg0.m4s'), { timeout: 20000 }).toBe(true);
    await expect.poll(() => video(page).evaluate((v) => v.videoWidth), { timeout: 20000 }).toBe(320);
    await expect(video(page)).toHaveAttribute('src', /^blob:/);
    await expect(mp.locator('.mp-info')).toContainText(/(NAS rechnet um|NAS converts)/);
    expect(jf.log.some((x) => x.path.endsWith('/main.m3u8') && x.query.api_key)).toBe(false);

    // a text subtitle: asked again with it, beside the video as WebVTT
    await mp.locator('.mp-panel-btn').click();
    await mp.locator('.mp-opt-sub').nth(1).click();
    await expect.poll(() => jf.state.playbackInfo.length, { timeout: 20000 }).toBe(3);
    expect(jf.state.playbackInfo[2].body.SubtitleStreamIndex).toBe(4);
    await expect(page.locator('.mp video track')).toHaveAttribute('src', /^gcmedia:\/\/media\//);
    await expect.poll(() => video(page).evaluate((v) => v.textTracks.length && v.textTracks[0].mode)).toBe('showing');
    await expect(mp.locator('.mp-opt-sub.is-on')).toContainText('SRT');
    await page.keyboard.press('Escape');
    await page.keyboard.press('Escape');
    await expect(mp).toBeHidden();
  });

  test('the end of an episode: "Nächste Folge" plays the next one', async ({ launchApp, mock }) => {
    const { page, p } = await signedIn(launchApp, mock, jf);
    await p.locator('.md-tabs [data-tab="series"]').click();
    await p.locator('.md-grid .md-pst', { hasText: 'Station Eisvogel' }).click();
    await p.locator('.md-ep', { hasText: 'Tauwetter' }).locator('.md-ep-play').click();
    const mp = page.locator('.mp');
    await expect(mp.locator('.mp-title')).toHaveText('Station Eisvogel');
    await expect(mp.locator('.mp-sub')).toContainText('Tauwetter');
    // under the title no source name or server address (as Android #311)
    await expect(mp.locator('.mp-sub')).not.toContainText(/DS918\+|Jellyfin|localhost/);
    await expect.poll(() => time(page), { timeout: 20000 }).toBeGreaterThan(0.5);
    await expect(mp.locator('.mp-next')).toBeVisible();
    await video(page).evaluate((v) => { v.currentTime = v.duration - 0.5; });
    await expect(mp.locator('.mp-nextbox')).toBeVisible({ timeout: 15000 });
    await expect(mp.locator('.mp-nextbox')).toContainText('Abflug');
    await mp.locator('.mp-next-now').click();
    await expect(mp.locator('.mp-sub')).toContainText('Abflug');
    await expect.poll(() => time(page), { timeout: 20000 }).toBeGreaterThan(0.5);
    // the last episode of the season: no next one
    await expect(mp.locator('.mp-next')).toBeHidden();
    await mp.locator('.mp-back').click();
    await expect(mp).toBeHidden();
  });
});
