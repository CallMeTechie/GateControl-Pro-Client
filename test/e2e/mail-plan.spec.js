'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Mail 1.9.0 (free/busy, shared calendars, resources): without the features of `me` the calendar stays as it was; with
// them the head has „Anfragen · n“ and „Ressource buchen“, the menu „Mit mir geteilt“, a free/busy item of a shared
// calendar only shows its time, the event dialog has „Frei/Gebucht“ with suggestions and resources, „Ressource buchen“
// books (mockup Ressource), „Buchungsanfragen“ decides (mockup Anfragen), „Teilen“ shares an own calendar (mockup Teilen)
// and the Mail settings have the free/busy switch. The plugin is the core's fake Mail server with `plan: true`
// (fixtures/mail-plan-server.js). Selectors by class, texts in both languages.

async function openCalendar(page, app) {
  if (app) await app.evaluate(({ BrowserWindow }) => { const win = BrowserWindow.getAllWindows()[0]; win.unmaximize(); win.setSize(1440, 900); });
  await expect(page.locator('#nav-mail')).toBeVisible();
  await page.locator('#nav-mail').click();
  const root = page.locator('#page-mail');
  await expect(root).toHaveClass(/active/);
  await root.locator('.ml-foot-calendar').click();
  await expect(root.locator('.cal-head')).toBeVisible();
  return root;
}

test.describe('mail – free/busy, shared calendars, resources (Mail 1.9.0)', () => {
  test('without the features nothing of 1.9.0 shows', async ({ launchApp, mock }) => {
    await mock.setMail();
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openCalendar(page, app);
    await expect(root.locator('.cal-book, .cal-requests, .cal-withme, .cal-it-shared')).toHaveCount(0);
    await root.locator('.cal-new').click();
    const dlg = page.locator('.ml-dlg.cal-edit');
    await expect(dlg).toBeVisible();
    await expect(dlg.locator('.cal-fb, .cal-res-add')).toHaveCount(0);
  });

  test('the calendar: „Anfragen · 2“, „Ressource buchen“, „Mit mir geteilt“; a free/busy item only shows its time', async ({ launchApp, mock }) => {
    const m = await mock.setMail({ plan: true });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openCalendar(page, app);
    await expect(root.locator('.cal-requests')).toContainText(/Anfragen · 2|Requests · 2/);
    await expect(root.locator('.cal-book')).toBeVisible();
    const shared = root.locator('.ml-side .cal-it-shared');
    await expect(shared).toHaveCount(2);
    await expect(shared.filter({ hasText: 'Urlaube' })).toContainText(/neu|new/);
    await expect(shared.filter({ hasText: 'Team' })).toHaveAttribute('aria-checked', 'true');
    // the shown shared calendar went along with GET events; its items have no titles
    const q = m.srv.state.requests.filter((r) => r.path.endsWith('/api/events')).pop();
    expect(q.query.calendars.split(',')).toContain('51');
    const busy = root.locator('.cal-ev.is-busyonly').first();
    await expect(busy).toBeVisible();
    await expect(busy).toHaveAttribute('title', /Team · (Frei\/Gebucht|Free\/busy)/);
    await busy.click();
    await expect(root.locator('.cal-sheet')).toContainText(/Nur belegt|Only taken/);
    await expect(root.locator('.cal-sheet .cal-sh-acts')).toHaveCount(0);
    await page.keyboard.press('Escape');
    // „Urlaube“ shown: PATCH shared, „neu“ is gone
    await shared.filter({ hasText: 'Urlaube' }).click();
    await expect.poll(() => m.srv.state.plan.shared.find((x) => x.id === 50).visible).toBe(true);
    await expect(shared.filter({ hasText: 'Urlaube' })).not.toContainText(/neu|new/);
    await page.screenshot({ path: test.info().outputPath('plan-calendar.png') });
  });

  test('the event dialog: „Frei/Gebucht“ with who cannot, a suggestion taken, a resource booked with the event', async ({ launchApp, mock }) => {
    const m = await mock.setMail({ plan: true });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openCalendar(page, app);
    await root.locator('.cal-new').click();
    const dlg = page.locator('.ml-dlg.cal-edit');
    await dlg.locator('.cal-in-title').fill('Sprint-Review');
    // today 14:00–15:00, with Tom (busy then)
    await dlg.locator('input[type="date"]').first().fill(await page.evaluate(() => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; }));
    await dlg.locator('input[type="time"]').first().fill('14:00');
    await dlg.locator('input[type="time"]').first().dispatchEvent('change');
    await dlg.locator('.ml-rcpt-in').fill('tim@firma.de,');
    const fb = dlg.locator('.cal-fb');
    await expect(fb.locator('.cal-fb-row:not(.is-scale)')).toHaveCount(2);
    await expect(fb.locator('.cal-fb-row').first()).toContainText(/Du|You/);
    await expect(fb.locator('.cal-fb-msg')).toContainText(/14:00 passt nicht für Tom|14:00 does not suit Tom/);
    await expect(fb.locator('.cal-fb-chip')).toHaveCount(4);
    expect(m.srv.state.plan.lastSuggest.duration).toBe(60);
    // a suggestion: tomorrow 15:00, the duration stays
    await fb.locator('.cal-fb-chip').first().click();
    await expect(dlg.locator('input[type="time"]').first()).toHaveValue('15:00');
    await expect(dlg.locator('input[type="time"]').nth(1)).toHaveValue('16:00');
    // a resource: the lilac chip, its row in free/busy
    const pick = dlg.locator('.cal-res-add');
    await expect(pick.locator('option')).toHaveCount(4);
    await pick.selectOption({ index: 1 });
    await expect(dlg.locator('.cal-res-chip')).toHaveText(['Firmenwagen Kombi']);
    await expect(fb.locator('.cal-fb-row.is-res')).toHaveCount(1);
    await page.screenshot({ path: test.info().outputPath('plan-planner.png') });
    await dlg.locator('.cal-save').click();
    await expect(dlg).toBeHidden();
    expect(m.srv.state.pim.lastEventBody.attendees).toEqual([{ email: 'tim@firma.de' }, { email: 'resource-11@resources.gatecontrol.invalid', name: 'Firmenwagen Kombi', role: 'resource' }]);
    await expect(page.locator('.toast-text').filter({ hasText: /Firmenwagen/ }).last()).toContainText(/Anfrage für Firmenwagen Kombi gesendet|Request for Firmenwagen Kombi sent/);
  });

  test('„Ressource buchen“: kinds, the day as bars, „Buchen“ and „Anfrage an Fuhrpark senden“', async ({ launchApp, mock }) => {
    const m = await mock.setMail({ plan: true });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openCalendar(page, app);
    await root.locator('.cal-book').click();
    const dlg = page.locator('.ml-dlg.cal-book-dlg');
    await expect(dlg.locator('.cal-res-card')).toHaveCount(3);
    await expect(dlg.locator('.cal-kinds .ml-chip')).toHaveText([/Alle|All/, /Räume|Rooms/, /Fahrzeuge|Vehicles/, /Geräte|Devices/]);
    await dlg.locator('.cal-kinds .ml-chip').nth(1).click();
    await expect(dlg.locator('.cal-res-card')).toHaveCount(1);
    await dlg.locator('.cal-kinds .ml-chip').first().click();
    const car = dlg.locator('.cal-res-card', { hasText: 'Firmenwagen' });
    await expect(car).toContainText(/Freigabe durch Fuhrpark|Approval by Fuhrpark/);
    await car.locator('.cal-res-head').click();
    await expect(car).toHaveClass(/\bon\b/);
    await expect(car.locator('.cal-res-book')).toContainText(/Anfrage an Fuhrpark senden|Send the request to Fuhrpark/);
    await dlg.locator('input[placeholder]').last().fill('Kunde Müller');
    await expect(car.locator('.cal-res-chosen')).toContainText('Kunde Müller');
    await page.screenshot({ path: test.info().outputPath('plan-book.png') });
    await car.locator('.cal-res-book').click();
    await expect(dlg).toBeHidden();
    expect(m.srv.state.plan.lastBook).toMatchObject({ resourceId: 11, title: 'Kunde Müller' });
    // the room is taken tomorrow 14–15: the refusal in words, the dialog stays
    await root.locator('.cal-book').click();
    const again = page.locator('.ml-dlg.cal-book-dlg');
    await again.locator('input[type="date"]').fill(await page.evaluate(() => { const d = new Date(); d.setDate(d.getDate() + 1); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; }));
    await again.locator('input[type="date"]').dispatchEvent('change');
    await again.locator('input[type="time"]').first().fill('14:00');
    await again.locator('input[type="time"]').nth(1).fill('15:00');
    await again.locator('input[type="time"]').nth(1).dispatchEvent('change');
    const room = again.locator('.cal-res-card', { hasText: 'Besprechungsraum' });
    await room.locator('.cal-res-head').click();
    await room.locator('.cal-res-book').click();
    await expect(again.locator('.ml-dlg-err')).toContainText(/schon gebucht|already booked/);
  });

  test('„Buchungsanfragen“: Freigeben, a conflict without Freigeben, Meine Buchungen with Absagen', async ({ launchApp, mock }) => {
    const m = await mock.setMail({ plan: true });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openCalendar(page, app);
    await root.locator('.cal-requests').click();
    const dlg = page.locator('.ml-dlg.cal-req-dlg');
    await expect(dlg.locator('.cal-req-tabs .ml-chip')).toHaveCount(3);
    await expect(dlg.locator('.cal-req')).toHaveCount(2);
    const free = dlg.locator('.cal-req[data-booking="801"]');
    await expect(free.locator('.cal-res-name')).toHaveText('Firmenwagen Kombi');
    await expect(free).toContainText('Markus B. · Kunde Müller');
    await expect(free.locator('.cal-pill')).toContainText(/wartet|waiting/);
    await expect(free).toContainText(/Frei · Regeln erfüllt|Free · rules kept/);
    const clash = dlg.locator('.cal-req[data-booking="802"]');
    await expect(clash.locator('.cal-pill')).toContainText(/Konflikt|Conflict/);
    await expect(clash.locator('.cal-req-approve, .cal-req-anyway')).toHaveCount(0);
    await expect(clash).toContainText(/Überschreitet|Breaks/);
    await page.screenshot({ path: test.info().outputPath('plan-requests.png') });
    await free.locator('.cal-req-approve').click();
    await expect(dlg.locator('.cal-req')).toHaveCount(1);
    expect(m.srv.state.plan.lastDecide).toMatchObject({ id: 801, decision: 'approve' });
    await expect(dlg.locator('.cal-req-tabs .ml-chip').first()).toContainText(/Offen · 1|Open · 1/);
    // the conflict gone: „Trotzdem freigeben“ (override)
    m.srv.state.plan.bookings.find((b) => b.id === 802).conflicts = [];
    await dlg.locator('.cal-req-tabs .ml-chip').nth(1).click();
    await dlg.locator('.cal-req-tabs .ml-chip').first().click();
    await dlg.locator('.cal-req[data-booking="802"] .cal-req-anyway').click();
    await expect.poll(() => m.srv.state.plan.lastDecide && m.srv.state.plan.lastDecide.override).toBe(true);
    // Meine Buchungen: Absagen
    await dlg.locator('.cal-req-tabs .ml-chip').nth(2).click();
    const mine = dlg.locator('.cal-req[data-booking="804"]');
    await expect(mine.locator('.cal-pill')).toContainText(/zugesagt|confirmed/);
    await mine.locator('.cal-req-cancel').click();
    await expect.poll(() => m.srv.state.plan.bookings.find((b) => b.id === 804).state).toBe('cancelled');
  });

  test('„Kalender teilen“: the shares, a person added, a level changed; „Mit mir geteilt“; the switch in the Mail settings', async ({ launchApp, mock }) => {
    const m = await mock.setMail({ plan: true });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openCalendar(page, app);
    await root.locator('.ml-side .cal-it').filter({ has: page.locator('.ml-it-tx', { hasText: /^Privat$/ }) }).click({ button: 'right' });
    await page.locator('.ml-menu .ml-menu-item', { hasText: /^(Teilen|Share)$/ }).click();
    const dlg = page.locator('.ml-dlg.cal-share-dlg');
    await expect(dlg.locator('.cal-share-head')).toContainText(/GateControl-Kalender|GateControl calendar/);
    const list = dlg.locator('.cal-share-list').first();
    await expect(list.locator('.cal-share-row')).toHaveCount(3);
    await expect(list.locator('.cal-share-row').first()).toContainText(/hat angenommen|accepted/);
    await expect(list.locator('.cal-share-row').nth(1)).toContainText(/4 Personen|4 people/);
    // Lisa at „Bearbeiten“
    await dlg.locator('.cal-share-add .seg button').nth(2).click();
    await dlg.locator('.cal-share-q').fill('lis');
    await dlg.locator('.cal-share-hits .ml-sug-row', { hasText: 'Lisa Maier' }).click();
    await expect(list.locator('.cal-share-row')).toHaveCount(4);
    expect(m.srv.state.plan.shares.find((s) => s.principalId === 9)).toMatchObject({ type: 'user', level: 'write' });
    await list.locator('.cal-share-row', { hasText: 'Tom Brandt' }).locator('select').selectOption('read');
    await expect.poll(() => m.srv.state.plan.shares.find((s) => s.id === 73).level).toBe('read');
    // „Mit mir geteilt“ in the same dialog
    const mine = dlg.locator('.cal-share-list').nth(1);
    await expect(mine).toContainText(/Urlaube · von Sabine Keller|Urlaube · from Sabine Keller/);
    await expect(mine).toContainText('team@firma.de');
    await page.screenshot({ path: test.info().outputPath('plan-share.png') });
    await dlg.locator('.ml-dlg-foot .btn-sec').click();
    // the Mail settings: „Frei/Gebucht für alle in GateControl“
    await root.locator('.ml-foot-settings').click();
    const set = page.locator('.ml-dlg .ml-set-fb');
    await expect(set).toContainText(/Frei\/Gebucht für alle|Free\/busy for everybody/);
    await set.locator('.sw').click();
    await expect.poll(() => m.srv.state.pim.calPrefs.freeBusy).toBe(false);
  });
});
