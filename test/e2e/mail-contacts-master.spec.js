'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Mail 1.4.0 (contacts with the GC contact as the master, favourites, the calendar widget of the start page): the
// list shows only GC contacts with their source dots, the star and the hint dot; a different number at Outlook as a
// band with "Übernehmen"; the duplicates with the protocol of the automatic merges ("Rückgängig") and the uncertain
// case with each card's source and fields, "So wird der Kontakt", "Zusammenführen"; a favourite pinned to the start
// page (a click calls, the name opens it); the calendar widget pinned (today and tomorrow, a click opens the event,
// live events reload it, × removes it). The plugin is the core's fake Mail server with `contactsMaster`
// (support/mail-mock.js). Selectors by class, texts in both languages.

async function openContacts(page, app) {
  await app.evaluate(({ BrowserWindow }) => { const win = BrowserWindow.getAllWindows()[0]; win.unmaximize(); win.setSize(1440, 900); });
  await expect(page.locator('#nav-mail')).toBeVisible();
  await page.locator('#nav-mail').click();
  const root = page.locator('#page-mail');
  await expect(root).toHaveClass(/active/);
  await root.locator('.ml-foot-contacts').click();
  await expect(root.locator('.con-row').first()).toBeVisible();
  return root;
}

const DAY = 24 * 60 * 60 * 1000;

test.describe('mail – contacts with the GC contact as the master (Mail 1.4.0)', () => {
  test('duplicates: the automatic merge undone, the uncertain case with its sources and the preview merged', async ({ launchApp, mock }) => {
    const m = await mock.setMail({ contactsMaster: true });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openContacts(page, app);
    // only GC contacts: the linked Outlook card is no row of its own, Sabine has two source dots
    await expect(root.locator('.con-row[data-id="401"]')).toHaveCount(0);
    await expect(root.locator('.con-row[data-id="405"] .con-src')).toHaveCount(1);
    await expect(root.locator('.con-row[data-id="402"] .con-fav')).toBeVisible();
    await expect(root.locator('.con-dup-band')).toBeVisible();
    await root.locator('.con-dups-it').click();
    // "Automatisch zusammengeführt (1)" with "Rückgängig"
    const auto = root.locator('.con-auto');
    await expect(auto.locator('.con-auto-head')).toContainText(/Automatisch zusammengeführt \(1\)|Merged automatically \(1\)/);
    await auto.locator('.con-auto-head').click();
    await expect(auto.locator('.con-auto-row')).toContainText('Sabine Keller');
    // the uncertain case: each card with its source and fields, the preview
    const c = root.locator('.con-case');
    await expect(c).toHaveCount(1);
    await expect(c.locator('.con-case-card')).toHaveCount(2);
    await expect(c.locator('.con-case-card[data-id="407"] .con-origin')).toContainText('Firma · M365');
    await expect(c.locator('.con-case-card[data-id="407"]')).toContainText('+49 172 3334444');
    await expect(c.locator('.con-case-card[data-id="408"]')).toContainText('sabrina@example.com');
    await expect(c.locator('.con-case-card[data-id="408"]')).toContainText('Ringstraße 3, 50667 Köln');
    await expect(c.locator('.con-case-card[data-id="407"] .con-thumb img')).toHaveAttribute('src', /^data:image\/png;base64,/);
    await expect(c.locator('.con-preview-name')).toHaveText('Schatzimausi 💞');
    await expect(c.locator('.con-preview')).toContainText('0221 777888');
    await page.screenshot({ path: test.info().outputPath('dups-master.png') });
    // "Rückgängig" of the automatic merge: the Outlook card on its own again
    await auto.locator('.con-undo').click();
    await page.locator('.con-undo-ok').click();
    await expect.poll(() => m.srv.state.pim.cards.get(401).linkId).toBe(null);
    await expect(root.locator('.con-row[data-id="401"]')).toBeVisible();
    // "Zusammenführen": one GC contact, no primary chosen
    await root.locator('.con-case .con-merge').click();
    await expect(root.locator('.con-name')).toHaveText('Schatzimausi 💞');
    expect(m.srv.state.pim.lastMerge).toEqual({ ids: [407, 408] });
    await expect(root.locator('.con-sources .con-source')).toHaveCount(2);
    await expect(root.locator('.con-row[data-id="407"]')).toHaveCount(0);
  });

  test('a different number at Outlook: the band, "Übernehmen"; the hint dot goes', async ({ launchApp, mock }) => {
    const m = await mock.setMail({ contactsMaster: true });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openContacts(page, app);
    await expect(root.locator('.con-row[data-id="405"] .con-hint')).toBeVisible();
    await root.locator('.con-row[data-id="405"]').click();
    const band = root.locator('.con-cf');
    await expect(band).toHaveCount(1);
    await expect(band).toContainText('max@firma.de');
    await expect(band).toContainText('0171 2345678');
    await expect(band).toContainText('0170 1234567');
    await expect(band.locator('.con-cf-add')).toBeVisible();
    await expect(root.locator('.con-sources')).toContainText('Firma · M365');
    await page.screenshot({ path: test.info().outputPath('conflict-band.png') });
    await band.locator('.con-cf-accept').click();
    await expect(root.locator('.con-cf')).toHaveCount(0);
    await expect(root.locator('.con-fields')).toContainText('0171 2345678');
    await expect(root.locator('.con-fields')).not.toContainText('0170 1234567');
    expect(m.srv.state.pim.lastAccept.mode).toBe('replace');
    await expect(root.locator('.con-row[data-id="405"] .con-hint')).toHaveCount(0);
    // the main number of a contact
    await root.locator('.con-fields .con-set-main').first().click();
    await expect(root.locator('.con-fields .con-main')).toHaveCount(1);
    expect(m.srv.state.pim.lastCardBody).toEqual({ mainPhone: '0221 3004012' });
    // deleting with links: the linked entries stay at the provider unless ticked
    await root.locator('.ml-read-bar .con-del').click();
    await expect(page.locator('.con-del-linked')).not.toBeChecked();
    await page.locator('.con-del-ok').click();
    await expect.poll(() => m.srv.state.pim.lastDelete).toEqual({ id: 405, linked: 'keep' });
    await expect(root.locator('.con-row[data-id="401"]')).toBeVisible();
  });

  test('a favourite pinned to the start page: a click calls the main number, the name opens the contact', async ({ launchApp, mock }) => {
    await mock.setMail({ contactsMaster: true });
    const { app, page, events } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openContacts(page, app);
    await root.locator('.con-row[data-id="402"]').click();
    await expect(root.locator('.con-fav-btn')).toHaveAttribute('aria-pressed', 'true');
    await root.locator('.con-pin').click();
    await expect(root.locator('.con-pin')).toHaveAttribute('aria-pressed', 'true');
    // a new favourite: the star
    await root.locator('.con-row[data-id="405"]').click();
    await expect(root.locator('.con-pin')).toHaveCount(0);
    await root.locator('.con-fav-btn').click();
    await expect(root.locator('.con-fav-btn')).toHaveAttribute('aria-pressed', 'true');
    await expect(root.locator('.con-row[data-id="405"] .con-fav')).toBeVisible();
    await root.locator('.con-pin').click();
    // the start page: the tiles with initials / picture
    await page.locator('#nav-status').click();
    const pins = page.locator('#home-pins');
    await expect(pins).toBeVisible();
    await expect(pins.locator('.home-fav')).toHaveCount(2);
    const tim = pins.locator('.home-fav[data-id="402"]');
    await expect(tim.locator('.home-fav-av')).toHaveText('TB');
    await expect(pins.locator('.home-fav[data-id="405"] .home-fav-av img')).toHaveAttribute('src', /^data:image\/png;base64,/);
    await page.screenshot({ path: test.info().outputPath('home-favorites.png') });
    // a click calls (tel:, like "Anrufen")
    await tim.locator('.home-fav-call').click();
    await expect.poll(() => events().filter((e) => e.type === 'shell.openExternal').map((e) => e.url)).toContain('tel:01701112223');
    // the name opens the contact
    await tim.locator('.home-fav-name').click();
    await expect(page.locator('#page-mail')).toHaveClass(/active/);
    await expect(page.locator('#page-mail .con-name')).toHaveText('Tim Brandt');
    // a right click opens it as well; × loosens the tile
    await page.locator('#nav-status').click();
    await pins.locator('.home-fav[data-id="405"]').click({ button: 'right' });
    await expect(page.locator('#page-mail .con-name')).toHaveText('Sabine Keller');
    await page.locator('#nav-status').click();
    await pins.locator('.home-fav[data-id="405"]').hover();
    await pins.locator('.home-fav[data-id="405"] .home-x').click();
    await expect(pins.locator('.home-fav')).toHaveCount(1);
  });

  test('the calendar widget: pinned, today and tomorrow, a click opens the event, live events reload it, × removes it', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const m = await mock.setMail({ contactsMaster: true });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openContacts(page, app);
    await root.locator('.ml-foot-calendar').click();
    await root.locator('.cal-pin').click();
    await expect(root.locator('.cal-pin')).toHaveAttribute('aria-pressed', 'true');
    await page.locator('#nav-status').click();
    const cal = page.locator('#home-pins .home-cal');
    await expect(cal).toBeVisible();
    // tomorrow: the birthday (all day) first, then the dentist
    await expect(cal.locator('.home-cal-day')).toContainText([/Morgen|Tomorrow/]);
    await expect(cal.locator('.home-ev', { hasText: 'Zahnarzt' })).toContainText('14:00');
    await expect(cal.locator('.home-ev', { hasText: 'Anna Lang (40)' })).toBeVisible();
    await page.screenshot({ path: test.info().outputPath('home-calendar.png') });
    // a live event of the calendar: loaded again
    await expect.poll(() => mock.pushStreams()).toBe(1);
    const d = new Date(Date.now() + DAY);
    d.setHours(9, 0, 0, 0);
    const z = m.srv.state.pim.events.get(302);
    m.srv.state.pim.events.set(399, { ...z, id: 399, title: 'Frühstück', start: d.getTime(), end: d.getTime() + 3600000, reminders: [] });
    mock.pushPlugin('gatecontrol-mail', 'calendar', { kind: 'changed', calendarId: 1 });
    await expect(cal.locator('.home-ev', { hasText: 'Frühstück' })).toContainText('09:00');
    // a click opens the event in the calendar
    await cal.locator('.home-ev', { hasText: 'Zahnarzt' }).click();
    await expect(page.locator('#page-mail')).toHaveClass(/active/);
    await expect(page.locator('#page-mail .cal-sheet')).toContainText('Zahnarzt');
    // the head opens the calendar; × removes the widget
    await page.locator('#nav-status').click();
    await cal.locator('.home-cal-open').click();
    await expect(page.locator('#page-mail .ml-foot-calendar')).toHaveClass(/on/);
    await page.locator('#nav-status').click();
    await cal.locator('.home-x').click();
    await expect(page.locator('#home-pins')).toBeHidden();
  });

  test('a server before 1.4.0: no star, no pin, the duplicates as before', async ({ launchApp, mock }) => {
    await mock.setMail();
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openContacts(page, app);
    await root.locator('.con-row[data-id="402"]').click();
    await expect(root.locator('.con-name')).toHaveText('Tim Brandt');
    await expect(root.locator('.con-fav-btn, .con-pin, .con-set-main, .con-cf')).toHaveCount(0);
    await root.locator('.con-dups-it').click();
    await expect(root.locator('.con-dup .con-merge')).toBeVisible();
    await expect(root.locator('.con-auto, .con-case')).toHaveCount(0);
    await root.locator('.ml-foot-calendar').click();
    await expect(root.locator('.ml-side .cal-add').first()).toBeVisible();
    await expect(root.locator('.cal-pin')).toHaveCount(0);
    await page.locator('#nav-status').click();
    await expect(page.locator('#home-pins')).toBeHidden();
  });
});
