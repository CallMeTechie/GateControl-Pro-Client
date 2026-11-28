'use strict';

const { test, expect } = require('./support/fixtures');
const { launchWithMedien } = require('./support/medien');
const { startJellyfin } = require('./support/jellyfin-mock');

// Medien (Stufe 4f; Medien-Plugin W2): the entry "Medien" in the sidebar only with the plugin's tab, the sources from
// the server (support/medien-mock.js) — the sign-in at Jellyfin runs by itself (Quick Connect confirmed by the
// plugin, no code shown), away the VPN is started for it ("VPN wird verbunden …"); Quellen only shows them, with
// "Immer Original" and "Weiterschauen auf der Übersicht"; the overview with the source
// chips, the way ("Unterwegs · … Mbit/s": the fake Jellyfin is not in a LAN subnet, so the core measures), the rows;
// Filme and Serien as a grid with sorting, filters and the detail column (sound with what the PC does with it,
// seasons and episodes); the search over all sources; "Ordner" with Jellyfin's libraries; the card "Weiterschauen" on the
// app's overview. The real core MediaService talks to a fake Jellyfin (support/jellyfin-mock.js) — tokens stay in
// the main process, the page only sees gcmedia:// addresses. Selectors by id/class/data attributes.

const page$ = (page) => page.locator('#page-medien');
const SHOTS = process.env.GC_E2E_SHOTS || null;
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` }); };

async function openMedien(page) {
  await expect(page.locator('#nav-medien')).toBeVisible();
  await page.locator('#nav-medien').click();
  await expect(page$(page)).toHaveClass(/active/);
}

test.describe('medien', () => {
  let jf;
  test.beforeEach(async () => { jf = await startJellyfin(); });
  test.afterEach(async () => { await jf.close(); });

  test('the sources from the server: signed in by itself through the VPN, the overview, Filme with the detail column, Serien, search, Ordner, Quellen, the card on the overview', async ({ launchApp, mock }) => {
    const { page, md } = await launchWithMedien({ launchApp, mock, jf });
    await openMedien(page);
    const p = page$(page);

    // signed in by itself: the code went to the plugin, never on the screen
    await expect.poll(() => md.pairs, { timeout: 30000 }).toBe(1);
    expect(md.log.some((x) => x.path === 'v1/jellyfin/paired')).toBe(true);
    await expect(page.locator('.md-qc-code')).toHaveCount(0);
    await expect(page.locator('.md-dlg')).toHaveCount(0);
    const init = jf.log.find((x) => x.path === '/QuickConnect/Initiate');
    expect(init).toBeTruthy();

    // the overview: chips, the way, the rows
    await expect(p.locator('.md-tabs [data-tab="overview"]')).toHaveClass(/on/);
    // the head (as Android #301): only the kind, no server name or address
    await expect(p.locator('.md-src.is-on')).toHaveText('Jellyfin');
    await expect(p.locator('.md-chips')).not.toContainText('DS918+');
    await expect(p.locator('.md-way')).toHaveClass(/is-away/);
    await expect(p.locator('.md-way')).toContainText(/(Unterwegs|Away) · \d/);
    await expect(page.locator('#statusbar .md-sb')).toContainText(/(Medien: Unterwegs|Media: away)/);
    const resume = p.locator('.md-sec').first();
    await expect(resume.locator('.md-th')).toHaveCount(3);
    // the one played last first: the episode of Station Eisvogel, then Kobaltnacht
    await expect(resume.locator('.md-th').first()).toContainText('Station Eisvogel');
    await expect(resume.locator('.md-th').first()).toContainText(/(Staffel 2 · Folge 4|Season 2 · Episode 4)/);
    const kobalt = resume.locator('.md-th', { hasText: 'Kobaltnacht' });
    await expect(kobalt.locator('.md-dur')).toHaveText(/1:06|1:05/);
    await expect(kobalt).toContainText(/(ab|from) 42:10/);
    // the poster of Kobaltnacht comes through gcmedia: (the fake's picture), the others are placeholders
    const img = kobalt.locator('img');
    await expect(img).toHaveAttribute('src', /^gcmedia:\/\/image\//);
    await expect.poll(() => img.evaluate((i) => i.naturalWidth)).toBe(320);
    // the overview "Ergänzt" (as Android #309): the rows in their order, each with its count
    await expect(p.locator('.md-sec')).toHaveCount(9);
    expect(await p.locator('.md-sec').evaluateAll((x) => x.map((e) => e.dataset.row))).toEqual(['resume', 'next', 'latest-movies', 'latest-episodes', 'favorites', 'movies', 'series', 'collections', 'genres']);
    // Als Nächstes: the episode after the one begun, "S2 · F5", not what Weiterschauen shows
    const next = p.locator('.md-sec[data-row="next"]');
    await expect(next.locator('.md-th')).toHaveCount(1);
    await expect(next.locator('.md-th')).toContainText('Station Eisvogel');
    await expect(next.locator('.md-th')).toContainText('Tauwetter');
    await expect(next.locator('.md-mk')).toHaveText(/^S2 · (F|E)5$/);
    await expect(next.locator('.md-lbl-s')).toHaveText('1');
    const latest = p.locator('.md-sec[data-row="latest-movies"]');
    await expect(latest.locator('.md-pst').first()).toContainText('Sternwarte 9');
    await expect(latest.locator('.md-pst').first().locator('.md-mk.is-new')).toBeVisible();
    await expect(latest.locator('.md-pst', { hasText: 'Station Eisvogel' })).toHaveCount(0);
    // Neue Folgen grouped per series: "6 neu"; the count in episodes
    const neweps = p.locator('.md-sec[data-row="latest-episodes"]');
    await expect(neweps.locator('.md-pst').first()).toContainText('Graufeld');
    await expect(neweps.locator('.md-pst').first().locator('.md-mk.is-own')).toHaveText(/^6 (neu|new)$/);
    await expect(neweps.locator('.md-lbl-s')).toHaveText('12');
    await expect(p.locator('.md-sec[data-row="favorites"] .md-pst')).toHaveCount(2);
    await expect(p.locator('.md-sec[data-row="movies"] .md-lbl-s')).toHaveText('12');
    await expect(p.locator('.md-sec[data-row="movies"] .md-pst').first()).toContainText('Achterwasser');
    await expect(p.locator('.md-sec[data-row="collections"] .md-pst')).toContainText('Kobalt-Reihe');
    await expect(p.locator('.md-sec[data-row="genres"] .md-genre-tile')).toHaveText(['Drama', 'Komödie', 'Krimi', 'Mystery', 'Science-Fiction']);
    await shot(page, 'medien-uebersicht');
    await p.locator('.md-ov').evaluate((e) => { e.scrollTop = e.scrollHeight; });
    await shot(page, 'medien-uebersicht-unten');
    // a genre's tile: Filme with that genre
    await p.locator('.md-genre-tile', { hasText: 'Krimi' }).click();
    await expect(p.locator('.md-tabs [data-tab="movies"]')).toHaveClass(/on/);
    await expect(p.locator('.md-filters .md-genre')).toHaveValue('Krimi');
    await expect(p.locator('.md-grid .md-pst')).toHaveCount(2);
    await expect(p.locator('.md-filters .md-count')).toHaveText(/^2 (Filme|movies)$/);
    // the collection: its films in the detail column
    await p.locator('.md-tabs [data-tab="overview"]').click();
    await p.locator('.md-sec[data-row="collections"] .md-pst').click();
    await expect(p.locator('.md-det .md-det-h')).toHaveText('Kobalt-Reihe');
    await expect(p.locator('.md-det .md-set .md-fr')).toHaveText([/Kobaltnacht/]);
    await shot(page, 'medien-sammlung');
    await p.locator('.md-tabs [data-tab="overview"]').click();
    // nothing of the access in the page
    const html = await page.content();
    expect(html).not.toContain('e2e-jellyfin-token');

    // Filme: the grid A–Z, the first selected, a click selects, the detail column
    await p.locator('.md-tabs [data-tab="movies"]').click();
    await p.locator('.md-filters .md-genre').selectOption('');
    await p.locator('.md-grid .md-pst').first().click();
    const grid = p.locator('.md-grid');
    await expect(grid.locator('.md-pst')).toHaveCount(12);
    await expect(grid.locator('.md-pst').first()).toContainText('Achterwasser');
    await expect(grid.locator('.md-pst').first()).toHaveClass(/is-cur/);
    await grid.locator('.md-pst', { hasText: 'Kobaltnacht' }).click();
    const det = p.locator('.md-det');
    await expect(det.locator('.md-det-h')).toHaveText('Kobaltnacht');
    await expect(det.locator('.md-det-meta')).toContainText('2025');
    await expect(det.locator('.md-det-meta')).toContainText('FSK 12');
    await expect(det.locator('.md-det-chips')).toContainText('4K · HDR10');
    await expect(det.locator('.md-det-chips')).toContainText('HEVC · mkv');
    await expect(det.locator('.md-det-chips .is-warn')).toBeVisible();
    await expect(det.locator('.md-sel-audio .md-sel-v')).toContainText('DTS 5.1');
    await expect(det.locator('.md-sel-audio .md-sel-n')).toContainText(/DTS.*AAC 5\.1/);
    await expect(det.locator('.md-sel-sub .md-sel-v')).toHaveText(/^(Aus|Off)$/);
    await expect(det.locator('.md-sel-sub option')).toHaveCount(3);
    await expect(det.locator('.md-sel-quality .md-sel-n')).toContainText(/(Automatisch|Automatic)/);
    await expect(det.locator('.md-prog')).toBeVisible();
    await expect(det).toContainText('Funkerin');
    await shot(page, 'medien-detail');
    // the heart (as Android #309): kept in Jellyfin, the filter "Favoriten"
    await expect(det.locator('.md-fav')).toHaveAttribute('aria-pressed', 'false');
    await det.locator('.md-fav').click();
    await expect(det.locator('.md-fav')).toHaveAttribute('aria-pressed', 'true');
    expect(jf.log.some((x) => x.method === 'POST' && /^\/UserFavoriteItems\//.test(x.path))).toBe(true);
    await p.locator('.md-filters .md-fav-filter').click();
    await expect(grid.locator('.md-pst')).toHaveText([/Kobaltnacht/, /Moorlicht/]);
    await p.locator('.md-filters .md-fav-filter').click();
    await grid.locator('.md-pst', { hasText: 'Kobaltnacht' }).click();
    // another sound: its note
    await det.locator('.md-sel-audio select').selectOption({ index: 2 });
    await expect(det.locator('.md-sel-audio .md-sel-n')).toHaveText(/(direkt|direct)/);
    // the arrow keys move through the grid
    await grid.locator('.md-pst', { hasText: 'Kobaltnacht' }).focus();
    await page.keyboard.press('ArrowRight');
    await expect(det.locator('.md-det-h')).toHaveText('Kupferstadt');
    await page.keyboard.press('ArrowLeft');
    await expect(det.locator('.md-det-h')).toHaveText('Kobaltnacht');
    // Gesehen: the mark at Jellyfin
    await det.locator('.md-played').click();
    await expect.poll(() => jf.log.filter((x) => x.method === 'POST' && /^\/UserPlayedItems\//.test(x.path)).length).toBe(1);
    await expect(grid.locator('.md-pst', { hasText: 'Kobaltnacht' })).toHaveClass(/is-played/);
    // filters: Ungesehen, sorting by year, the genres of the loaded titles
    await p.locator('.md-filters .md-toggle').first().click();
    await expect(grid.locator('.md-pst')).toHaveCount(10);
    await p.locator('.md-filters .md-toggle').first().click();
    await expect(grid.locator('.md-pst')).toHaveCount(12);
    await p.locator('.md-filters .md-sort').selectOption('year');
    await expect(grid.locator('.md-pst').first()).toContainText('Sternwarte 9');
    await p.locator('.md-filters .md-genre').selectOption('Krimi');
    await expect(grid.locator('.md-pst')).toHaveCount(2);
    await p.locator('.md-filters .md-genre').selectOption('');

    // Serien: seasons and episodes in the column, the season of the next episode open
    await p.locator('.md-tabs [data-tab="series"]').click();
    await p.locator('.md-grid .md-pst', { hasText: 'Station Eisvogel' }).click();
    await expect(det.locator('.md-det-h')).toHaveText('Station Eisvogel');
    await expect(det.locator('.md-seasons .md-toggle')).toHaveCount(2);
    await expect(det.locator('.md-seasons .md-toggle.is-on')).toHaveText(/(Staffel|Season) 2/);
    await expect(det.locator('.md-ep')).toHaveCount(6);
    await expect(det.locator('.md-ep.is-next')).toContainText('Polarnacht');
    await expect(det.locator('.md-ep.is-played')).toHaveCount(3);
    await det.locator('.md-seasons .md-toggle').first().click();
    await expect(det.locator('.md-ep.is-played')).toHaveCount(6);

    // search over all sources
    await p.locator('.md-tabs [data-tab="overview"]').click();
    await p.locator('.md-search-inp').fill('eis');
    await expect(p.locator('.md-searchhead')).toContainText('eis');
    await expect(p.locator('.md-grid .md-pst').first()).toContainText('Station Eisvogel');
    await expect(p.locator('.md-det .md-det-h')).toHaveText('Station Eisvogel');
    await p.locator('.md-search-inp').fill('');
    await expect(p.locator('.md-searchhead')).toHaveCount(0);

    // Ordner with Jellyfin alone (as Android #301): its libraries (no music), a library's folders and titles, back
    await p.locator('.md-tabs [data-tab="folders"]').click();
    const fl = p.locator('.md-fl');
    await expect(fl.locator('.md-fr.is-lib')).toHaveCount(2);
    await expect(fl.locator('.md-fr.is-lib b')).toHaveText(['Filme', 'Serien']);
    await expect(fl.locator('.md-fr.is-lib').first()).toContainText(/(Jellyfin-Bibliothek|Jellyfin library)/);
    await expect(p.locator('.md-folders')).toHaveCount(0);
    await shot(page, 'medien-ordner-bibliotheken');
    await fl.locator('.md-fr.is-lib', { hasText: 'Filme' }).click();
    await expect(p.locator('.md-crumb.is-cur')).toHaveText('Filme');
    // the folders first (a box set too), then the titles A–Z
    await expect(fl.locator('.md-fr.is-dir b')).toHaveText(['Klassiker', 'Kobalt-Reihe']);
    await expect(fl.locator('.md-fr.is-title').first()).toContainText('Achterwasser');
    await expect(fl.locator('.md-fr.is-title', { hasText: 'Kobaltnacht' }).locator('small')).toContainText('2025');
    await shot(page, 'medien-ordner-filme');
    await fl.locator('.md-fr.is-dir', { hasText: 'Klassiker' }).click();
    await expect(p.locator('.md-crumb')).toHaveText(['Filme', 'Klassiker']);
    await expect(fl.locator('.md-fr.is-title b')).toHaveText(['Der Pegelwart', 'Moorlicht', 'Zugvogelzeit']);
    await expect(fl.locator('.md-fr.is-title', { hasText: 'Der Pegelwart' }).locator('.md-seen')).toHaveCount(1);
    await p.locator('.md-crumb', { hasText: 'Filme' }).click();
    await expect(p.locator('.md-crumb.is-cur')).toHaveText('Filme');
    // a title opens its tab with the detail column
    await fl.locator('.md-fr.is-title', { hasText: 'Kupferstadt' }).locator('.md-fr-open').click();
    await expect(p.locator('.md-tabs [data-tab="movies"]')).toHaveClass(/on/);
    await expect(p.locator('.md-det .md-det-h')).toHaveText('Kupferstadt');
    // back in Ordner: the library is still open; up to the list of libraries
    await p.locator('.md-tabs [data-tab="folders"]').click();
    await expect(p.locator('.md-crumb.is-cur')).toHaveText('Filme');
    await p.locator('.md-fv-up').click();
    await expect(fl.locator('.md-fr.is-lib')).toHaveCount(2);
    expect(jf.log.some((x) => x.path === '/UserViews')).toBe(true);
    await p.locator('.md-srcbtn').click();
    await expect(p.locator('.md-sources')).toBeVisible();

    // Quellen: only shown, from the server — no "+", no dialog, no "Gerät anmelden"
    await expect(p.locator('.md-managed')).toBeVisible();
    await expect(p.locator('.md-add')).toHaveCount(0);
    await expect(p.locator('.md-authorize')).toHaveCount(0);
    const card = p.locator('.md-srccard[data-kind="jellyfin"]');
    await expect(card).toContainText('DS918+');
    await expect(card).toContainText('Mila');
    await expect(card).toContainText('GateControl · Büro-PC');
    await expect(card.locator('.md-src-state')).toHaveText(/(Unterwegs über VPN|Away through VPN)/);
    await expect(card.locator('.md-rule')).toHaveText(/(nur über VPN|only through the VPN)/);
    await expect(card.locator('button')).toHaveCount(0);

    // Immer Original
    await p.locator('.md-sw-original .sw').click();
    await expect(p.locator('.md-sw-original .sw')).toHaveAttribute('aria-checked', 'true');

    // the card "Weiterschauen" on the app's overview, switched off and on again in Quellen
    await page.locator('#nav-status').click();
    const home = page.locator('#media-home');
    await expect(home).toBeVisible();
    await expect(home.locator('.md-home-th')).toHaveCount(2);
    await expect(home.locator('.md-home-th').first()).toContainText('Station Eisvogel');
    await home.locator('.md-home-th').first().click();
    await expect(p).toHaveClass(/active/);
    // a click plays on at the place (the player of 4g); Esc goes back to the page
    await expect(page.locator('.mp')).toBeVisible();
    await expect(page.locator('.mp .mp-title')).toHaveText('Station Eisvogel');
    await page.keyboard.press('Escape');
    await expect(page.locator('.mp')).toBeHidden();
    await expect(p.locator('.md-sources')).toBeVisible();
    await p.locator('.md-sw-home .sw').click();
    await expect(p.locator('.md-sw-home .sw')).toHaveAttribute('aria-checked', 'false');
    await page.locator('#nav-status').click();
    await expect(home).toBeHidden();
    await page.locator('#nav-medien').click();
    await p.locator('.md-sw-home .sw').click();
    await page.locator('#nav-status').click();
    await expect(home).toBeVisible();

  });

  test('no tab of the plugin: no entry "Medien"', async ({ launchApp, mock }) => {
    const hidden = await launchWithMedien({ launchApp, mock, jf, tab: false });
    await expect.poll(() => hidden.md.log.some((x) => x.path === 'v1/sources'), { timeout: 20000 }).toBe(true);
    await expect(hidden.page.locator('#nav-status')).toBeVisible();
    await expect(hidden.page.locator('#nav-medien')).toBeHidden();
  });

  test('away without VPN nothing is sent: the banner with "VPN einschalten"', async ({ launchApp, mock }) => {
    const { page } = await launchWithMedien({ launchApp, mock, jf, tunnel: false });
    await openMedien(page);
    const p = page$(page);
    await expect(p.locator('.md-vpn.is-failed')).toBeVisible({ timeout: 30000 });
    await expect(p.locator('.md-vpn')).toContainText(/(Unterwegs nur über VPN|Away only through the VPN)/);
    await expect(p.locator('.md-vpn-on')).toBeVisible();
    expect(jf.log.length).toBe(0);
  });
});
