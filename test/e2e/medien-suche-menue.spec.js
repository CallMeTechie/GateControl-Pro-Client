'use strict';

const { test, expect } = require('./support/fixtures');
const { launchWithMedien } = require('./support/medien');
const { startJellyfin } = require('./support/jellyfin-mock');
const { startWebDav } = require('./support/webdav-mock');

// Medien › Ordner „Im Ordner suchen“ and the menu of a title (as Android: the magnifier of the folder page, the long
// press). In a Jellyfin library the folder's own folders and titles show at once, Jellyfin's search below it
// (parentId, recursive) after a moment; in a WebDAV share the folder's files and those of the folders below (the
// share's index, with where each lies). A right click, the context-menu key or Umschalt+F10 on a title (grid, the
// row Weiterschauen, a Jellyfin folder, a share's file) opens "Weiter ab … / Abspielen", "Von vorn" and "Als gesehen
// / ungesehen markieren" — Jellyfin keeps it (UserPlayedItems), a share's file this PC. A click still opens the detail.
// The real core MediaService talks to a fake Jellyfin and a fake WebDAV share.

const SHOTS = process.env.GC_E2E_SHOTS || null;
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` }); };
const page$ = (page) => page.locator('#page-medien');
const acts = (page) => page.locator('.md-menu .md-menu-item');

/** Medien shows no server address, host or URL — not in its text, not in a tooltip or label (the user's rule). */
async function noAddress(page, dav) {
  const host = new URL(dav.address).hostname;
  const seen = await page.locator('#page-medien').evaluate((root) => {
    const out = [root.innerText];
    for (const n of root.querySelectorAll('[title], [aria-label], [placeholder]')) out.push(n.getAttribute('title') || '', n.getAttribute('aria-label') || '', n.getAttribute('placeholder') || '');
    return out.join('\n');
  });
  expect(seen).not.toMatch(/https?:\/\/|\\\\|127\.0\.0\.1|smb:/);
  expect(seen).not.toContain(dav.address);
  expect(seen).not.toContain(host);
}

test.describe('medien suche und menü', () => {
  let jf;
  let dav;
  test.beforeEach(async () => { jf = await startJellyfin(); dav = await startWebDav(); });
  test.afterEach(async () => { await jf.close(); await dav.close(); });

  test('Jellyfin: im Ordner suchen (auch darunter), das Menü im Ordner, im Raster und in Weiterschauen', async ({ launchApp, mock }) => {
    const { page } = await launchWithMedien({ launchApp, mock, jf });
    await page.locator('#nav-medien').click();
    const p = page$(page);
    const filme = jf.lib.views[0];

    // Ordner › Filme: the search field beside the path
    await p.locator('.md-tabs [data-tab="folders"]').click();
    const fl = p.locator('.md-fl');
    await fl.locator('.md-fr.is-lib', { hasText: 'Filme' }).click();
    await expect(fl.locator('.md-fr.is-dir b')).toHaveText(['Kobalt-Reihe', 'Klassiker'].sort((a, b) => a.localeCompare(b, 'de')));
    const field = p.locator('.md-fs-inp');
    await expect(field).toHaveAttribute('placeholder', /(Im Ordner suchen|Search in folder)/);

    // the folder's own folder and title at once; Jellyfin asked below the library, in its folders too
    await field.fill('kobalt');
    await expect(fl.locator('.md-fr.is-dir b')).toHaveText(['Kobalt-Reihe']);
    await expect(fl.locator('.md-fr.is-title b')).toHaveText(['Kobaltnacht']);
    await expect.poll(() => jf.log.some((x) => x.path === '/Items' && x.query.parentId === filme.Id && x.query.searchTerm === 'kobalt' && x.query.recursive === 'true')).toBe(true);
    await expect(fl.locator('.md-fr.is-title b')).toHaveText(['Kobaltnacht'], { timeout: 5000 });
    // a film in the folder "Klassiker" below: only from Jellyfin's search
    await field.fill('pegel');
    const pegel = fl.locator('.md-fr.is-title', { hasText: 'Der Pegelwart' });
    await expect(pegel).toBeVisible();
    await expect(pegel).toHaveClass(/is-played/);
    await expect(fl.locator('.md-fr.is-dir')).toHaveCount(0);
    await expect(field).toBeFocused();
    await shot(page, 'medien-ordner-suche-jellyfin');

    // its menu (a right click): Abspielen, Als ungesehen markieren (it was seen) — Jellyfin forgets it
    await pegel.click({ button: 'right' });
    await expect(acts(page)).toHaveCount(2);
    await expect(acts(page).nth(0)).toHaveAttribute('data-act', 'play');
    await expect(acts(page).nth(1)).toHaveText(/(Als ungesehen markieren|Mark as unwatched)/);
    await expect(acts(page).nth(0)).toBeFocused();
    await shot(page, 'medien-menue-ordner-jellyfin');
    await acts(page).nth(1).click();
    await expect(page.locator('.md-menu')).toHaveCount(0);
    const pegelId = jf.lib.movies.find((m) => m.Name === 'Der Pegelwart').Id;
    await expect.poll(() => jf.log.some((x) => x.method === 'DELETE' && x.path === `/UserPlayedItems/${pegelId}`)).toBe(true);
    await expect(pegel).not.toHaveClass(/is-played/);

    // nothing found; Escape empties the field and the folder shows all again; another folder starts empty (as Android)
    await field.fill('xyzzy');
    await expect(fl.locator('.md-fs-none')).toHaveText(/(Keine Treffer in diesem Ordner|Nothing found in this folder)/);
    await field.press('Escape');
    await expect(field).toHaveValue('');
    await expect(fl.locator('.md-fr.is-dir')).toHaveCount(2);
    await field.fill('moor');
    await fl.locator('.md-fr.is-dir', { hasText: 'Klassiker' }).waitFor({ state: 'detached' });
    await field.fill('');
    await fl.locator('.md-fr.is-dir', { hasText: 'Klassiker' }).click();
    await expect(p.locator('.md-crumb.is-cur')).toHaveText('Klassiker');
    await field.fill('moor');
    await expect(fl.locator('.md-fr.is-title b')).toHaveText(['Moorlicht']);
    await p.locator('.md-fv-up').click();
    await expect(field).toHaveValue('');

    // the grid: Umschalt+F10 on a poster — Weiter ab 42:10, Von vorn, Als gesehen markieren; the arrows, Escape
    await p.locator('.md-tabs [data-tab="movies"]').click();
    const kobalt = p.locator('.md-grid .md-pst', { hasText: 'Kobaltnacht' });
    await expect(kobalt).toBeVisible({ timeout: 20000 });
    await kobalt.focus();
    await page.keyboard.press('Shift+F10');
    await expect(acts(page)).toHaveCount(3);
    await expect(acts(page).nth(0)).toHaveText(/(Weiter ab|Resume from) 42:10/);
    await expect(acts(page).nth(1)).toHaveAttribute('data-act', 'restart');
    await expect(acts(page).nth(2)).toHaveText(/(Als gesehen markieren|Mark as watched)/);
    await expect(acts(page).nth(0)).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await expect(acts(page).nth(1)).toBeFocused();
    await page.keyboard.press('ArrowUp');
    await page.keyboard.press('ArrowUp');
    await expect(acts(page).nth(2)).toBeFocused();
    await shot(page, 'medien-menue-raster');
    await page.keyboard.press('Escape');
    await expect(page.locator('.md-menu')).toHaveCount(0);
    await expect(kobalt).toBeFocused();
    // the context-menu key, then Enter on "Als gesehen markieren": Jellyfin keeps it, the poster shows it
    await page.keyboard.press('ContextMenu');
    await expect(acts(page)).toHaveCount(3);
    // Windows sends a contextmenu after the key to what has the focus then (the menu): it stays open
    await page.evaluate(() => document.activeElement.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true })));
    await expect(acts(page)).toHaveCount(3);
    await page.keyboard.press('End');
    await page.keyboard.press('Enter');
    await expect.poll(() => jf.log.some((x) => x.method === 'POST' && x.path === `/UserPlayedItems/${jf.lib.kobalt.Id}`)).toBe(true);
    await expect(p.locator('.md-grid .md-pst', { hasText: 'Kobaltnacht' })).toHaveClass(/is-played/);
    // a click still selects (the detail column), the right click on another poster selects it as well
    const moor = p.locator('.md-grid .md-pst', { hasText: 'Moorlicht' });
    await moor.click({ button: 'right' });
    await expect(p.locator('.md-det .md-det-h')).toHaveText('Moorlicht');
    await expect(acts(page).nth(0)).toHaveText(/^(Abspielen|Play)$/);
    await page.keyboard.press('Escape');

    // Weiterschauen: "Von vorn" from the menu starts at 0 (not at 72:30)
    await p.locator('.md-tabs [data-tab="overview"]').click();
    const paula = p.locator('.md-sec[data-row="resume"] .md-th', { hasText: 'Paulas Werkstatt' });
    await expect(paula).toBeVisible({ timeout: 20000 });
    await expect(p.locator('.md-sec[data-row="resume"] .md-th', { hasText: 'Kobaltnacht' })).toHaveCount(0);
    await paula.click({ button: 'right' });
    await expect(acts(page).nth(0)).toHaveText(/(Weiter ab|Resume from) 1:12:30/);
    await page.locator('.md-menu [data-act="restart"]').click();
    const mp = page.locator('.mp');
    await expect(mp).toBeVisible();
    await expect(mp.locator('.mp-title')).toHaveText('Paulas Werkstatt');
    await expect.poll(() => jf.reports.filter((r) => r.path === '/Sessions/Playing').length, { timeout: 20000 }).toBe(1);
    expect(jf.reports.find((r) => r.path === '/Sessions/Playing').body.PositionTicks).toBeLessThan(10 * 1000 * 10000);
    await page.keyboard.press('Escape');
    await expect(mp).toBeHidden();
  });

  test('NAS-Freigabe: im Ordner suchen mit Unterordnern, das Menü einer Datei (gesehen auf diesem PC)', async ({ launchApp, mock }) => {
    const { page } = await launchWithMedien({ launchApp, mock, dav });
    await page.locator('#nav-medien').click();
    const p = page$(page);
    await p.locator('.md-tabs [data-tab="folders"]').click();
    const fl = p.locator('.md-fl');
    await expect(fl.locator('.md-fr.is-dir')).toHaveCount(4, { timeout: 20000 });
    const field = p.locator('.md-fs-inp');

    // nothing at the root itself: the episodes of the season folders below, each with where it lies
    await field.fill('flut');
    const hits = fl.locator('.md-fr.is-hit');
    await expect(hits).toHaveCount(2, { timeout: 20000 });
    await expect(hits.locator('b')).toHaveText(['Flut', 'Flut']);
    await expect(hits.locator('.md-fr-in')).toHaveText(['in Serien/Graufeld/Staffel 1', 'in Serien/Hafenlichter/Staffel 1']);
    // a folder by its name at once, its file from the index
    await field.fill('leucht');
    await expect(fl.locator('.md-fr.is-dir b')).toHaveText(['Leuchtfeuer (2024)']);
    const hit = fl.locator('.md-fr.is-hit', { hasText: 'Leuchtfeuer' });
    await expect(hit.locator('.md-fr-in')).toHaveText('in Leuchtfeuer (2024)');
    await expect(hit.locator('img')).toHaveAttribute('src', /^gcmedia:\/\/image\//);
    await shot(page, 'medien-ordner-suche-nas');
    // no server address anywhere on the page (text, tooltips, labels): the share is "Filme", the root of its path
    await expect(p.locator('.md-crumb').first()).toHaveText('Filme');
    await noAddress(page, dav);

    // its menu: Abspielen, Als gesehen markieren (kept on this PC)
    await hit.click({ button: 'right' });
    await expect(acts(page)).toHaveCount(2);
    await expect(acts(page).nth(1)).toHaveText(/(Als gesehen markieren|Mark as watched)/);
    await shot(page, 'medien-menue-nas');
    await acts(page).nth(1).click();
    await expect(hit).toHaveClass(/is-played/);
    expect(dav.log.some((x) => x.method !== 'PROPFIND' && x.method !== 'GET')).toBe(false);

    // the folder itself: the mark is there (the core kept it); Umschalt+F10 on the row, Escape gives the focus back
    await field.press('Escape');
    await fl.locator('.md-fr.is-dir', { hasText: 'Leuchtfeuer (2024)' }).click();
    await expect(p.locator('.md-crumb.is-cur')).toHaveText('Leuchtfeuer (2024)');
    await expect(field).toHaveValue('');
    const row = fl.locator('.md-fr', { hasText: 'Leuchtfeuer' });
    await expect(row).toHaveClass(/is-played/);
    await row.locator('.md-fr-open').focus();
    await page.keyboard.press('Shift+F10');
    await expect(acts(page).nth(1)).toHaveText(/(Als ungesehen markieren|Mark as unwatched)/);
    await page.keyboard.press('Escape');
    await expect(page.locator('.md-menu')).toHaveCount(0);
    await expect(row.locator('.md-fr-open')).toBeFocused();
    await row.click({ button: 'right' });
    await page.locator('.md-menu [data-act="played"]').click();
    await expect(row).not.toHaveClass(/is-played/);

    // the chip of the overview and Quellen: no address either
    await p.locator('.md-tabs [data-tab="overview"]').click();
    await noAddress(page, dav);
    await p.locator('.md-srcbtn').click();
    await expect(p.locator('.md-srccard[data-kind]').first()).toBeVisible();
    await expect(p.locator('.md-srccard').first()).toContainText(/(NAS-Freigabe|NAS share) · Filme/);
    await noAddress(page, dav);
    await p.locator('.md-back').click();
    await p.locator('.md-tabs [data-tab="folders"]').click();

    // a hit plays straight from the share; a click on the row still plays (as before)
    await p.locator('.md-crumb').first().click();
    await field.fill('ebbe');
    await expect(fl.locator('.md-fr.is-hit')).toHaveCount(2, { timeout: 20000 });
    await fl.locator('.md-fr.is-hit').first().locator('.md-fr-play').click();
    const mp = page.locator('.mp');
    await expect(mp).toBeVisible();
    // an episode: its series as the title, the episode below (the first hit A–Z: Graufeld)
    await expect(mp.locator('.mp-title')).toHaveText('Graufeld');
    await expect(mp).toContainText('Ebbe');
    await page.keyboard.press('Escape');
    await expect(mp).toBeHidden();
  });
});
