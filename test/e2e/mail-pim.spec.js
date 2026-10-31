'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Mail Phase 2 (calendar and contacts in the plugin gatecontrol-mail): the menu's new foot (settings left, contacts and
// calendar right, no "+"; "Noch kein Konto" leads to the settings), the calendar (week view, a new event by a click
// into free time, the event's sheet), the invitation card in a mail (answer → the server), the contacts (search,
// a contact, editing) and Microsoft "Neu anmelden". The plugin is the core's fake Mail server (support/mail-mock.js,
// Phase 2 in its fixtures/mail-pim-server.js). Selectors by class, texts in both languages.

async function openMail(page, app) {
  // a window wide enough for three columns (the CI's default one is narrow)
  if (app) await app.evaluate(({ BrowserWindow }) => { const win = BrowserWindow.getAllWindows()[0]; win.unmaximize(); win.setSize(1440, 900); });
  await expect(page.locator('#nav-mail')).toBeVisible();
  await page.locator('#nav-mail').click();
  await expect(page.locator('#page-mail')).toHaveClass(/active/);
  return page.locator('#page-mail');
}

test.describe('mail – calendar and contacts', () => {
  test('the menu\'s foot: settings left, contacts and calendar right, no "+"; the areas switch', async ({ launchApp, mock }) => {
    await mock.setMail();
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openMail(page, app);
    const foot = root.locator('.ml-side-foot .ml-foot-row');
    await expect(foot.locator('button')).toHaveCount(3);
    await expect(foot.locator('button').nth(0)).toHaveClass(/ml-foot-settings/);
    await expect(foot.locator('button').nth(1)).toHaveClass(/ml-foot-contacts/);
    await expect(foot.locator('button').nth(2)).toHaveClass(/ml-foot-calendar/);
    // the settings on the left, the two areas on the right
    const box = async (sel) => root.locator(sel).boundingBox();
    expect((await box('.ml-foot-settings')).x).toBeLessThan((await box('.ml-foot-contacts')).x - 40);
    await expect(root.locator('.ml-side-foot')).not.toContainText('+');
    for (const sel of ['.ml-foot-settings', '.ml-foot-contacts', '.ml-foot-calendar']) await expect(root.locator(sel)).toHaveAttribute('aria-label', /.+/);
    // the calendar: its menu with the calendars, "Posteingänge" back to Mail
    await root.locator('.ml-foot-calendar').click();
    await expect(root.locator('.ml-foot-calendar')).toHaveClass(/\bon\b/);
    await expect(root.locator('.ml-foot-calendar')).toHaveAttribute('aria-pressed', 'true');
    await expect(root.locator('.ml-side .cal-it')).toHaveCount(6);
    await expect(root.locator('.ml-side')).toContainText(/Eingeblendet|Shown here/);
    await expect(root.locator('.ml-list')).toBeHidden();
    await expect(root.locator('.ml-main .cal-head')).toBeVisible();
    await page.screenshot({ path: test.info().outputPath('pim-calendar-menu.png') });
    await root.locator('.ml-foot-contacts').click();
    await expect(root.locator('.ml-side')).toContainText(/Alle Kontakte|All contacts/);
    await expect(root.locator('.ml-side .con-book')).toHaveCount(3);
    await root.locator('.ml-side .ml-it').first().click();
    await expect(root.locator('.ml-list')).toBeVisible();
    await expect(root.locator('.ml-foot-calendar')).not.toHaveClass(/\bon\b/);
  });

  test('without the features no icons; "Noch kein Konto" opens the settings with "Konto hinzufügen"', async ({ launchApp, mock }) => {
    const m = await mock.setMail({ features: ['mail', 'ai', 'microsoft', 'drive', 'familyCalendar', 'images'] });
    m.srv.state.accounts = [];
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openMail(page, app);
    await expect(root.locator('.ml-side-foot .ml-foot-row button')).toHaveCount(1);
    await expect(root.locator('.ml-foot-calendar, .ml-foot-contacts')).toHaveCount(0);
    await root.locator('.ml-empty-settings').click();
    const add = page.locator('.ml-dlg .ml-set-add');
    await expect(add).toBeFocused();
    await expect(add).toHaveClass(/btn-pri/);
    await add.click();
    await expect(page.locator('.ml-dlg.ml-add .ml-prov').first()).toBeVisible();
  });

  test('the calendar: week with the events, a new event by a click into free time, its sheet; Monat and Liste', async ({ launchApp, mock }) => {
    const m = await mock.setMail();
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openMail(page, app);
    await root.locator('.ml-foot-calendar').click();
    // the week (the settings' view): today's events, the open invitation dashed, the overlay "nur ansehen", the now line
    await expect(root.locator('.cal-v-week')).toBeVisible();
    await expect(root.locator('.cal-ev', { hasText: 'Projektbesprechung' })).toBeVisible();
    await expect(root.locator('.cal-ev', { hasText: 'Tim abholen' })).toHaveClass(/is-overlay/);
    await expect(root.locator('.cal-col .cal-now')).toHaveCount(1);
    const week = m.srv.state.requests.filter((r) => r.path.endsWith('/api/events')).pop();
    expect(Number(week.query.to) - Number(week.query.from)).toBeGreaterThanOrEqual(6 * 86400000);
    expect(week.query.calendars.split(',')).toEqual(expect.arrayContaining(['1', '2', '3', 'familie', 'birthdays']));
    // the device's time zone went to the server once
    await expect.poll(() => m.srv.state.pim.lastCalSettings && m.srv.state.pim.lastCalSettings.timeZone).toBeTruthy();
    await page.screenshot({ path: test.info().outputPath('pim-week.png') });

    // a click into free time of today's column: a new event at that time
    const col = root.locator('.cal-col.is-today');
    await col.scrollIntoViewIfNeeded();
    const scroll = root.locator('.cal-scroll');
    await scroll.evaluate((s) => { s.scrollTop = 11 * 48; });
    await col.click({ position: { x: 10, y: 12 * 48 + 10 } });
    const dlg = page.locator('.ml-dlg.cal-edit');
    await expect(dlg).toBeVisible();
    await expect(dlg.locator('input[type="time"]').first()).toHaveValue('12:00');
    await dlg.locator('.cal-in-title').fill('Mittagessen mit Tim');
    await dlg.locator('.ml-rcpt-in').fill('tim');
    await expect(dlg.locator('.ml-sug-row').first()).toContainText('Tim Brandt');
    await dlg.locator('.ml-sug-row').first().click();
    await expect(dlg.locator('.ml-rcpt')).toHaveText(['Tim Brandt']);
    await expect(dlg.locator('.cal-via')).toContainText(/Privat · GMX/);
    await dlg.locator('.cal-save').click();
    await expect(dlg).toBeHidden();
    const body = m.srv.state.pim.lastEventBody;
    expect(body.title).toBe('Mittagessen mit Tim');
    expect(body.calendarId).toBe(1);
    expect(new Date(body.start).getHours()).toBe(12);
    expect(body.attendees).toEqual([{ email: 'tim@firma.de', name: 'Tim Brandt' }]);
    // the sheet of the new event; the grid has it
    await expect(root.locator('.cal-sheet .cal-sh-title')).toHaveText('Mittagessen mit Tim');
    await expect(root.locator('.cal-ev', { hasText: 'Mittagessen mit Tim' })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(root.locator('.cal-sheet')).toHaveCount(0);

    // an event of a series: "Nur dieser Termin" changes only this occurrence
    await root.locator('.cal-ev', { hasText: 'Training' }).first().click();
    await expect(root.locator('.cal-sheet')).toContainText(/Wöchentlich|Weekly/);
    await root.locator('.cal-sheet .cal-sh-acts .btn-sec').first().click();
    await page.locator('.ml-dlg.cal-edit .cal-in-title').fill('Training (Halle 2)');
    await page.locator('.ml-dlg.cal-edit .cal-save').click();
    await page.locator('.cal-scope-one').click();
    await expect.poll(() => m.srv.state.pim.lastEventBody && m.srv.state.pim.lastEventBody.scope).toBe('occurrence');
    expect(m.srv.state.pim.lastEventBody.title).toBe('Training (Halle 2)');
    expect(m.srv.state.pim.lastEventBody.start).toBeUndefined();

    // Monat and Liste
    await root.locator('.cal-head .seg button').nth(2).click();
    await expect(root.locator('.cal-mcell')).toHaveCount(42);
    await expect(root.locator('.cal-mitem', { hasText: 'Projektbesprechung' })).toBeVisible();
    await root.locator('.cal-head .seg button').nth(3).click();
    await expect(root.locator('.cal-ag-row', { hasText: 'Zahnarzt' })).toBeVisible();
    await page.screenshot({ path: test.info().outputPath('pim-list.png') });
  });

  test('an invitation in a mail: the card above the text, "Zusagen" into a chosen calendar', async ({ launchApp, mock }) => {
    const m = await mock.setMail({ invite: true });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openMail(page, app);
    const row = root.locator('.ml-row[data-id="106"]');
    await expect(row.locator('.ml-row-inv')).toHaveText(/Einladung|Invitation/);
    await row.click();
    const card = root.locator('.cal-inv');
    await expect(card).toBeVisible();
    await expect(card.locator('.cal-inv-title')).toHaveText('Sprint-Review');
    await expect(card.locator('.cal-inv-state')).toContainText('Sabine Keller');
    await expect(card.locator('.cal-inv-comment')).toHaveText('Bitte die Zahlen mitbringen.');
    await expect(card.locator('.cal-mini .cal-mini-b.is-new')).toBeVisible();
    // the card stands above the mail's text
    expect(await card.evaluate((c) => !!(c.compareDocumentPosition(document.querySelector('#page-mail .ml-frame-wrap')) & Node.DOCUMENT_POSITION_FOLLOWING))).toBe(true);
    await page.screenshot({ path: test.info().outputPath('pim-invitation.png') });
    await card.locator('.cal-inv-target select').selectOption('1');
    await card.locator('.cal-inv-more .btn').first().click();
    await card.locator('.cal-inv-cmt').fill('Bin dabei');
    await card.locator('.cal-inv-yes').click();
    await expect.poll(() => m.srv.state.pim.lastInviteRespond).toEqual({ response: 'accepted', comment: 'Bin dabei', calendarId: 1 });
    await expect(root.locator('.cal-inv .cal-inv-state')).toContainText(/Du hast zugesagt|You accepted/);
    await expect(root.locator('.cal-inv .cal-inv-change')).toBeVisible();
  });

  test('contacts: search, a contact with its mails, editing with the etag; read only; "Als Kontakt speichern"', async ({ launchApp, mock }) => {
    const m = await mock.setMail();
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openMail(page, app);
    await root.locator('.ml-foot-contacts').click();
    // the list: letter sections, the source's dot, possible duplicates
    await expect(root.locator('.con-row')).toHaveCount(6);
    await expect(root.locator('.con-letter').first()).toHaveText('A');
    await expect(root.locator('.con-dup-band')).toBeVisible();
    // search at once (on this PC): umlauts folded
    await root.locator('.con-list .ml-search-in').fill('otzi');
    await expect(root.locator('.con-row')).toHaveCount(1);
    await expect(root.locator('.con-row')).toContainText('Älbert Ötzi');
    await root.locator('.con-list .ml-search-in').fill('kel');
    await expect(root.locator('.con-row')).toHaveCount(2);
    expect(m.srv.state.pim.cardsAsked).toBe(1);
    // a contact: photo, position, the fields, its last mails
    await root.locator('.con-row[data-id="401"]').click();
    await expect(root.locator('.con-name')).toHaveText('Sabine Keller');
    await expect(root.locator('.con-job')).toHaveText('Projektleitung · Keller GmbH');
    await expect(root.locator('.con-hero .con-av img')).toHaveAttribute('src', /^data:image\/png;base64,/);
    await expect(root.locator('.con-fields')).toContainText('Hansaring 12');
    await expect(root.locator('.con-mail').first()).toContainText('Projektbesprechung');
    await page.screenshot({ path: test.info().outputPath('pim-contact.png') });
    // a read only source: no editing
    await root.locator('.con-list .ml-search-in').fill('albers');
    await root.locator('.con-row[data-id="404"]').click();
    await expect(root.locator('.con-edit')).toBeDisabled();
    // editing: company changed, sent with the etag
    await root.locator('.con-list .ml-search-in').fill('brandt');
    await root.locator('.con-row[data-id="402"]').click();
    await root.locator('.con-edit').click();
    const form = root.locator('.con-edit-form');
    await form.locator('input[aria-label="Firma"], input[aria-label="Company"]').fill('Brandt & Partner');
    await root.locator('.con-save').click();
    await expect(root.locator('.con-job')).toHaveText('Brandt & Partner');
    expect(m.srv.state.pim.lastCardBody.company).toBe('Brandt & Partner');
    expect(m.srv.state.pim.lastCardBody.etag).toMatch(/^"v\d+"$/);

    // "Als Kontakt speichern" from the sender of a mail: the draft of the server in the form
    await root.locator('.ml-side .ml-it').first().click();
    await root.locator('.ml-row[data-id="101"]').click();
    await root.locator('.ml-read-sender').click();
    await root.locator('.ml-sender-save').click();
    await expect(root.locator('.con-edit-form')).toBeVisible();
    await expect(root.locator('.con-edit-form input[type="email"]').first()).toHaveValue('rechnung@stadtwerke.de');
    await root.locator('.con-save').click();
    await expect(root.locator('.con-name')).toHaveText('Stadtwerke');
    expect(m.srv.state.pim.lastCardBody.emails[0].value).toBe('rechnung@stadtwerke.de');
  });

  test('Microsoft without the new rights: the band "freigeben", "Neu anmelden" with the account as hint', async ({ launchApp, mock }) => {
    const m = await mock.setMail();
    m.srv.state.accounts[1].missingScopes = ['Calendars.ReadWrite', 'Contacts.ReadWrite'];
    m.srv.state.grantScopes = false;
    const { app, page, events } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openMail(page, app);
    await root.locator('.ml-foot-calendar').click();
    const band = root.locator('.ml-main .ml-consent');
    await expect(band).toContainText('Firma · M365');
    await band.locator('.ml-consent-btn').click();
    let url = null;
    await expect.poll(() => { const e = events().find((x) => x.type === 'shell.openExternal'); url = e && e.url; return !!url; }).toBe(true);
    const u = new URL(url);
    expect(u.searchParams.get('login_hint')).toBe('max@firma.de');
    expect(u.searchParams.get('scope').split(' ')).toEqual(expect.arrayContaining(['Calendars.ReadWrite', 'Contacts.ReadWrite']));
    const code = m.srv.issueCode(u.searchParams.get('code_challenge'));
    const http = require('http');
    await new Promise((resolve, reject) => {
      http.get(`${u.searchParams.get('redirect_uri')}/?code=${encodeURIComponent(code)}&state=${encodeURIComponent(u.searchParams.get('state'))}`, (res) => { res.resume(); res.on('end', resolve); }).on('error', reject);
    });
    // the company still blocks them: the administrator's consent link to pass on
    await expect(page.locator('.ml-dlg.ml-admin-consent')).toBeVisible();
    await expect(page.locator('.ml-dlg.ml-admin-consent input')).toHaveValue(/adminconsent/);
  });
});
