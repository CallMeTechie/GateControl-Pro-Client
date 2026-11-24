'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');
const { startJellyfin } = require('./support/jellyfin-mock');

// Medien (Stufe 4f): the entry "Medien" in the sidebar, the empty page with "Quelle hinzufügen", the dialog with the
// search in the LAN, the address, Quick Connect (the code confirmed in Jellyfin) and name and password; Quellen with
// "Abmelden", "Immer Original", "Weiterschauen auf der Übersicht" and "Gerät anmelden"; the overview with the source
// chips, the way ("Unterwegs · … Mbit/s": the fake Jellyfin is not in a LAN subnet, so the core measures), the rows;
// Filme and Serien as a grid with sorting, filters and the detail column (sound with what the PC does with it,
// seasons and episodes); the search over all sources; the placeholder of "Ordner"; the card "Weiterschauen" on the
// app's overview. The real core MediaService talks to a fake Jellyfin (support/jellyfin-mock.js) — tokens stay in
// the main process, the page only sees gcmedia:// addresses. Selectors by id/class/data attributes.

const page$ = (page) => page.locator('#page-medien');

async function openMedien(page) {
  await expect(page.locator('#nav-medien')).toBeVisible();
  await page.locator('#nav-medien').click();
  await expect(page$(page)).toHaveClass(/active/);
}

/** Medien › Quelle hinzufügen › Jellyfin at `address`, signed in with Quick Connect (confirmed in the fake server). */
async function addJellyfinQuick(page, jf) {
  const p = page$(page);
  await p.locator('.md-empty .btn-pri').click();
  const dlg = page.locator('.md-dlg');
  await expect(dlg).toBeVisible();
  await expect(dlg.locator('.md-kinds [data-kind="jellyfin"]')).toHaveClass(/on/);
  await dlg.locator('input.md-f-address').fill(jf.address);
  await dlg.locator('.md-next').click();
  await expect(dlg.locator('.md-server.is-static')).toContainText('DS918+');
  await expect(dlg.locator('.md-server.is-static')).toContainText('10.10.3');
  await expect(dlg.locator('.md-qc-code')).toHaveText('482 913');
  jf.state.qcConfirmed = true;
  await expect(dlg).toBeHidden({ timeout: 20000 });
}

test.describe('medien', () => {
  let jf;
  test.beforeEach(async () => { jf = await startJellyfin(); });
  test.afterEach(async () => { await jf.close(); });

  test('setup with Quick Connect, the overview, Filme with the detail column, Serien, search, Ordner, Quellen, the card on the overview', async ({ launchApp, mock }) => {
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await openMedien(page);
    const p = page$(page);

    // no source yet: the empty page; the card on the app's overview stays hidden
    await expect(p.locator('.md-empty')).toBeVisible();
    await expect(page.locator('#media-home')).toBeHidden();

    await addJellyfinQuick(page, jf);
    // Quellen: the new source, signed in as Mila, this PC's name
    await expect(p.locator('.md-srccard[data-kind="jellyfin"]')).toContainText('DS918+');
    await expect(p.locator('.md-srccard[data-kind="jellyfin"]')).toContainText('Mila');
    await p.locator('.md-back').click();

    // the overview: chips, the way, the rows
    await expect(p.locator('.md-tabs [data-tab="overview"]')).toHaveClass(/on/);
    await expect(p.locator('.md-src.is-on')).toContainText('Jellyfin · DS918+');
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
    const latest = p.locator('.md-sec').nth(1);
    await expect(latest.locator('.md-pst').first()).toContainText('Sternwarte 9');
    await expect(latest.locator('.md-pst').first().locator('.md-mk.is-new')).toBeVisible();
    // nothing of the access in the page
    const html = await page.content();
    expect(html).not.toContain('e2e-jellyfin-token');

    // Filme: the grid A–Z, the first selected, a click selects, the detail column
    await p.locator('.md-tabs [data-tab="movies"]').click();
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
    await p.locator('.md-filters .md-toggle').click();
    await expect(grid.locator('.md-pst')).toHaveCount(10);
    await p.locator('.md-filters .md-toggle').click();
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

    // Ordner: the placeholder until the folders come (4h)
    await p.locator('.md-tabs [data-tab="folders"]').click();
    await expect(p.locator('.md-folders')).toBeVisible();
    await p.locator('.md-folders .btn').click();
    await expect(p.locator('.md-sources')).toBeVisible();

    // Gerät anmelden: a wrong code, then the TV's code
    const az = p.locator('.md-authorize');
    await az.locator('.md-code-inp').fill('12345');
    await az.locator('.md-code-btn').click();
    await expect(az.locator('.md-code-note')).toHaveClass(/note-err/);
    await az.locator('.md-code-inp').fill('111 222');
    await az.locator('.md-code-btn').click();
    await expect(az.locator('.md-code-note')).toHaveClass(/note-err/);
    await az.locator('.md-code-inp').fill('731 205');
    await az.locator('.md-code-btn').click();
    await expect(az.locator('.md-code-note')).toHaveClass(/note-ok/);
    expect(jf.state.authorized).toEqual(['731205']);

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
    // without the player (4g) a click opens the title: the series with its column
    await expect(p.locator('.md-tabs [data-tab="series"]')).toHaveClass(/on/);
    await expect(p.locator('.md-det .md-det-h')).toHaveText('Station Eisvogel');
    await p.locator('.md-tabs [data-tab="overview"]').click();
    await p.locator('.md-srcbtn').click();
    await p.locator('.md-sw-home .sw').click();
    await expect(p.locator('.md-sw-home .sw')).toHaveAttribute('aria-checked', 'false');
    await page.locator('#nav-status').click();
    await expect(home).toBeHidden();
    await page.locator('#nav-medien').click();
    await p.locator('.md-sw-home .sw').click();
    await page.locator('#nav-status').click();
    await expect(home).toBeVisible();

    // Abmelden: this PC signs out at Jellyfin, the source goes
    await page.locator('#nav-medien').click();
    await p.locator('.md-srccard[data-kind="jellyfin"] .md-signout').click();
    await expect(p.locator('.md-srccard')).toHaveCount(0);
    expect(jf.state.loggedOut).toBe(1);
    await page.locator('#nav-status').click();
    await expect(home).toBeHidden();
  });

  test('name and password, a wrong password first; the SMB form with its hints', async ({ launchApp, mock }) => {
    jf.state.quickConnect = false;
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await openMedien(page);
    const p = page$(page);
    await p.locator('.md-empty .btn-pri').click();
    const dlg = page.locator('.md-dlg');
    await dlg.locator('input.md-f-address').fill(jf.address);
    await dlg.locator('input.md-f-address').press('Enter');
    // Quick Connect is off on this server: name and password
    await expect(dlg.locator('.md-methods [aria-selected="true"]')).toHaveText(/(Benutzer|User)/);
    await dlg.locator('input.md-f-user').fill('mila');
    await dlg.locator('input.md-f-password').fill('falsch');
    await dlg.locator('.md-signin').click();
    await expect(dlg.locator('.md-dlg-err')).toBeVisible();
    await dlg.locator('input.md-f-password').fill('geheim');
    await dlg.locator('.md-signin').click();
    await expect(dlg).toBeHidden();
    await expect(p.locator('.md-srccard[data-kind="jellyfin"]')).toContainText('Mila');
    const auth = jf.log.filter((x) => x.path === '/Users/AuthenticateByName');
    expect(auth.length).toBe(2);
    // the password is nowhere in the page afterwards
    expect(await page.content()).not.toContain('geheim');

    // SMB: a name instead of the IP → the hint; "Auch als WebDAV" suggests the address
    await p.locator('.md-add').click();
    await dlg.locator('.md-kinds [data-kind="smb"]').click();
    await dlg.locator('input.md-f-address').fill('\\\\nas\\filme');
    await expect(dlg.locator('.md-ip-hint')).toBeVisible();
    await expect(dlg.locator('.md-note')).toContainText('1219');
    await dlg.locator('input.md-also-webdav').check();
    await expect(dlg.locator('input.md-f-webdavAddress')).toHaveValue('https://nas:5006/filme');
    await dlg.locator('input.md-f-address').fill('\\\\192.168.1.20\\filme');
    await expect(dlg.locator('.md-ip-hint')).toBeHidden();
    await page.keyboard.press('Escape');
    await expect(dlg).toBeHidden();
  });
});
