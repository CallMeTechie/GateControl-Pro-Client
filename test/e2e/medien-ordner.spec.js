'use strict';

const { test, expect } = require('./support/fixtures');
const { launchWithMedien } = require('./support/medien');
const { startJellyfin } = require('./support/jellyfin-mock');
const { startWebDav } = require('./support/webdav-mock');

// Medien › Ordner (Stufe 4h): a WebDAV share beside Jellyfin. Its films and series (from the file names, the poster
// beside the video) in the rows and the grid with the mark "NAS" — Kobaltnacht, which Jellyfin has too, once
// (Jellyfin's); the search over both; the folder view with the path, the way ("WebDAV · unterwegs": the fake is not
// in a LAN subnet), the titles and pictures from the names; a file plays straight from the share (always the
// original) and its place is kept on this PC ("Weiterschauen" over all sources); a file with DTS sound: the check
// before the start says so in the detail column and in the player, with "In VLC öffnen" when VLC is installed (else
// the note that VLC could play it — WebDAV has no path for Windows' apps) and "Trotzdem abspielen". The real core
// MediaService talks to a fake Jellyfin and a fake WebDAV share; the page sees only gcmedia:// addresses.

const page$ = (page) => page.locator('#page-medien');

test.describe('medien ordner', () => {
  let jf;
  let dav;
  test.beforeEach(async () => { jf = await startJellyfin(); dav = await startWebDav(); });
  test.afterEach(async () => { await jf.close(); await dav.close(); });

  test('a WebDAV share beside Jellyfin: NAS titles once, the folders, play and the place kept, the check before the start', async ({ launchApp, mock }) => {
    // Jellyfin and the WebDAV share from the server (plugin Medien): signed in by itself, the password from the plugin
    const { page, md } = await launchWithMedien({ launchApp, mock, jf, dav });
    await expect(page.locator('#nav-medien')).toBeVisible();
    await page.locator('#nav-medien').click();
    const p = page$(page);
    await expect.poll(() => md.pairs, { timeout: 30000 }).toBe(1);
    expect(md.log.some((x) => x.path === 'v1/sources/sh-1/secret')).toBe(true);
    expect(await page.content()).not.toContain(dav.password);

    // the overview: the share's chip; Leuchtfeuer from the NAS with its mark, Kobaltnacht once (Jellyfin's)
    await expect(p.locator('.md-src.is-share')).toHaveText(/^(NAS-Freigabe|NAS share)$/);
    await p.locator('.md-tabs [data-tab="movies"]').click();
    const grid = p.locator('.md-grid');
    const leucht = grid.locator('.md-pst', { hasText: 'Leuchtfeuer' });
    await expect(leucht).toBeVisible({ timeout: 20000 });
    await expect(leucht.locator('.md-mk').first()).toHaveText('NAS');
    await expect(grid.locator('.md-pst', { hasText: 'Kobaltnacht' })).toHaveCount(1);
    await expect(grid.locator('.md-pst', { hasText: 'Kobaltnacht' }).locator('.md-mk:not(.is-new)')).toHaveCount(0);
    // A–Z: Leuchtfeuer between the Jellyfin titles; its poster from the share through gcmedia://image/
    const names = await grid.locator('.md-pst b').allTextContents();
    expect(names.indexOf('Leuchtfeuer')).toBeGreaterThan(names.indexOf('Kupferstadt'));
    const img = leucht.locator('img');
    await expect(img).toHaveAttribute('src', /^gcmedia:\/\/image\/[A-Za-z0-9_-]{24}\/Leuchtfeuer%20\(2024\)\/poster\.jpg$/);
    await expect.poll(() => img.evaluate((i) => i.naturalWidth)).toBe(320);
    // its detail: the file as it is
    await leucht.click();
    const det = p.locator('.md-det');
    await expect(det.locator('.md-det-h')).toHaveText('Leuchtfeuer');
    await expect(det.locator('.md-det-chips')).toContainText('NAS');
    await expect(det.locator('.md-det-chips')).toContainText('WebDAV');
    await expect(det.locator('.md-orig')).toBeVisible();
    await expect(det.locator('.md-sel-quality')).toHaveCount(0);
    // a file with DTS: marked in the column before it starts, with the other app (or the note without VLC)
    await grid.locator('.md-pst', { hasText: 'Silvester am See' }).click();
    await expect(det.locator('.md-det-h')).toHaveText('Silvester am See');
    await expect(det.locator('.md-check')).toContainText(/(Ton DTS: am PC kein Ton|Audio DTS: no sound on this PC)/);
    await expect(det.locator('.md-ext-btn').or(det.locator('.md-ext .md-sel-n'))).toBeVisible();

    // Serien: Graufeld once (Jellyfin's, three seasons), Hafenlichter from the season folders of the share
    await p.locator('.md-tabs [data-tab="series"]').click();
    await expect(p.locator('.md-grid .md-pst', { hasText: 'Graufeld' })).toHaveCount(1);
    await p.locator('.md-grid .md-pst', { hasText: 'Graufeld' }).click();
    await expect(det.locator('.md-seasons .md-toggle')).toHaveCount(3);
    await p.locator('.md-grid .md-pst', { hasText: 'Hafenlichter' }).click();
    await expect(det.locator('.md-det-h')).toHaveText('Hafenlichter');
    await expect(det.locator('.md-seasons .md-toggle')).toHaveText([/(Staffel|Season) 1/]);
    await expect(det.locator('.md-ep')).toHaveCount(2);
    await expect(det.locator('.md-ep').first()).toContainText('Flut');

    // the search over both sources
    await p.locator('.md-tabs [data-tab="overview"]').click();
    await p.locator('.md-search-inp').fill('leucht');
    await expect(p.locator('.md-grid .md-pst').first()).toContainText('Leuchtfeuer');
    await p.locator('.md-search-inp').fill('');

    // Ordner: Jellyfin's libraries and the share as a list (as Android #301: beside libraries a share is not opened by
    // itself); the share: the root with its folders (no hidden ones), the way, a folder with its files
    await p.locator('.md-tabs [data-tab="folders"]').click();
    const fl = p.locator('.md-fl');
    await expect(fl.locator('.md-fr.is-lib b')).toHaveText(['Filme', 'Serien']);
    await expect(fl.locator('.md-fr.is-share')).toHaveCount(1);
    await expect(fl.locator('.md-fr.is-share small')).toHaveText(/WebDAV/);
    await fl.locator('.md-fr.is-share').click();
    await expect(fl.locator('.md-fr.is-dir')).toHaveCount(4);
    await expect(fl).not.toContainText('@eaDir');
    await expect(p.locator('.md-fv-way')).toContainText(/WebDAV · (unterwegs|away)/);
    // the root of the path: the share's name from the server, never its host or URL
    await expect(p.locator('.md-crumb.is-cur')).toHaveText('Filme');
    await expect(fl.locator('.md-fr.is-dir').first()).toBeVisible();
    await fl.locator('.md-fr.is-dir', { hasText: 'Leuchtfeuer (2024)' }).click();
    await expect(p.locator('.md-crumb.is-cur')).toHaveText('Leuchtfeuer (2024)');
    const row = fl.locator('.md-fr', { hasText: 'Leuchtfeuer' });
    await expect(row.locator('b')).toHaveText('Leuchtfeuer');
    await expect(row.locator('small')).toContainText('2024');
    await expect(row.locator('img')).toHaveAttribute('src', /^gcmedia:\/\/image\//);
    await expect(fl.locator('.md-fr')).toHaveCount(1, { timeout: 5000 });

    // play from the folder: straight from the share, the place kept on this PC
    await row.locator('.md-fr-play').click();
    const mp = page.locator('.mp');
    await expect(mp).toBeVisible();
    await expect(mp.locator('.mp-title')).toHaveText('Leuchtfeuer');
    await expect(mp.locator('.mp-info')).toContainText('WebDAV');
    await expect.poll(() => page.locator('.mp video').evaluate((v) => v.currentTime), { timeout: 20000 }).toBeGreaterThan(1);
    await page.locator('.mp video').evaluate((v) => { v.currentTime = 15; });
    await expect.poll(() => page.locator('.mp video').evaluate((v) => v.currentTime)).toBeGreaterThan(15);
    expect(dav.log.some((x) => x.method === 'GET' && x.path.endsWith('Leuchtfeuer (2024).webm') && x.range)).toBe(true);
    await page.keyboard.press('Escape');
    await expect(mp).toBeHidden();
    // "noch … Min." is no place under 30 s; the bar of the overview's Weiterschauen needs 30 s — the folder shows the length now
    await expect(row.locator('small')).toContainText(/(Min\.|min)/);

    // a file with DTS: the check before the start, "Trotzdem abspielen"
    await p.locator('.md-crumb').first().click();
    await fl.locator('.md-fr.is-dir', { hasText: 'Familie' }).click();
    await expect(fl.locator('.md-fr')).toHaveCount(1);
    await expect(fl).not.toContainText('Notizen');
    await fl.locator('.md-fr-play').click();
    await expect(mp.locator('.mp-center.is-hint')).toContainText(/(Ton DTS: am PC kein Ton|Audio DTS: no sound on this PC)/);
    const ext = mp.locator('.mp-ext');
    const noApp = mp.locator('.mp-hint-no');
    await expect(ext.or(noApp)).toBeVisible();
    if (await ext.count()) await expect(ext).toHaveAttribute('data-app', 'vlc');
    await mp.locator('.mp-anyway').click();
    await expect(mp.locator('.mp-center.is-hint')).toHaveCount(0);
    await mp.locator('.mp-back').click();
    await expect(mp).toBeHidden();
  });
});
