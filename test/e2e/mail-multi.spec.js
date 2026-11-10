'use strict';

// Mail 1.13 "Mehrfachauswahl + Wischaktionen" on the page "Mail": Strg+click ticks mails (the open one with them),
// Umschalt+click a range, Strg+A every loaded mail, "Alle im Ordner auswählen" (GET messages/ids), Esc ends it; the
// bar (Verschieben with the folder picker — Verschieben / Kopieren, Ordner suchen —, then "4 Mails nach „Rechnungen“
// verschoben · Rückgängig"), a right click on the ticked mails, "Vor dem Löschen fragen" with "Nicht mehr fragen",
// dragging the ticked mails onto a folder of the menu, the quick actions of the settings with seven actions; and the
// same page against an older Mail (≤ 1.12: no Kopieren, no Rückgängig, the old four quick actions). The plugin is the
// core's fake Mail server (support/mail-mock.js) with the features of Mail 1.13.

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

const BASE = ['mail', 'ai', 'microsoft', 'drive', 'familyCalendar', 'images', 'calendar', 'contacts', 'dav', 'familyOverlay'];
const V13 = [...BASE, 'copy', 'swipeV2', 'undo', 'bulkAll', 'threadScope'];

const row = (root, id) => root.locator(`.ml-row[data-id="${id}"]`);

async function open(launchApp, mock, { features = V13, settings = null, more = 0 } = {}) {
  const m = await mock.setMail({ features });
  if (settings) Object.assign(m.srv.state.settings, settings);
  const base = m.srv.state.messages.get(259);
  for (let i = 0; i < more; i += 1) m.srv.state.messages.set(3000 + i, { ...base, id: 3000 + i, threadId: 3000 + i, subject: `Ältere Mail ${i}`, date: base.date - (i + 1) * 3600000 });
  const { app, page } = await launchApp();
  await app.evaluate(({ BrowserWindow }) => { const win = BrowserWindow.getAllWindows()[0]; win.unmaximize(); win.setSize(1440, 900); });
  await setupWithApiKey(page, mock);
  await page.locator('#nav-mail').click();
  const root = page.locator('#page-mail');
  await expect(row(root, 101)).toBeVisible();
  return { m, page, root };
}

test.describe('mail: several mails at once (Mail 1.13)', () => {
  test('Strg / Umschalt clicks, the bar, moving with the picker and „Rückgängig“, Strg+A and „Alle im Ordner“, Esc', async ({ launchApp, mock }) => {
    // many pages of older mails: „Alle im Ordner“ has more than the list loaded
    const { m, page, root } = await open(launchApp, mock, { more: 240 });
    const bar = root.locator('.ml-selbar');

    // a click opens; Strg+click ticks the open mail and the one clicked; Umschalt+click the range
    await row(root, 204).click();
    await expect(root.locator('.ml-read-subj')).toHaveText('Alte Mail 4');
    await row(root, 207).click({ modifiers: ['Shift'] });
    await expect(bar).toBeVisible();
    await expect(bar.locator('.ml-selbar-n')).toHaveText(/^4 (ausgewählt|selected)$/);
    await row(root, 205).click({ modifiers: ['Control'] });
    await expect(bar.locator('.ml-selbar-n')).toHaveText(/^3 /);
    await expect(row(root, 205)).toHaveAttribute('aria-selected', 'false');
    await row(root, 205).click({ modifiers: ['Control'] });
    await expect(bar.locator('.ml-selbar-n')).toHaveText(/^4 /);
    await expect(root.locator('.ml-row.is-picked')).toHaveCount(4);
    await expect(row(root, 206)).toHaveAttribute('aria-selected', 'true');
    // the bar: Kopieren with Mail 1.13, „Nach Sonstige“ in the inbox
    await expect(bar.locator('[data-act="copy"]')).toBeVisible();
    await expect(bar.locator('[data-act="toOther"]')).toBeVisible();
    await page.screenshot({ path: test.info().outputPath('mail-multi-selected.png') });

    // Verschieben: the picker with Verschieben / Kopieren, the search, then „Nach „Rechnungen“ verschieben“
    await bar.locator('[data-act="move"]').click();
    const dlg = page.locator('.ml-dlg-pick');
    await expect(dlg.locator('.ml-dlg-h')).toHaveText(/^(4 Mails verschieben|Move 4 mails)$/);
    await expect(dlg.locator('.seg button')).toHaveCount(2);
    await expect(dlg.locator('.ml-pick-go')).toBeDisabled();
    await dlg.locator('.ml-pick-search').fill('rech');
    await dlg.locator('.ml-pick-row[data-folder="15"]').click();
    await expect(dlg.locator('.ml-pick-go')).toHaveText(/Rechnungen/);
    await page.screenshot({ path: test.info().outputPath('mail-multi-picker.png') });
    await dlg.locator('.ml-pick-go').click();
    await expect(row(root, 204)).toHaveCount(0);
    await expect(row(root, 207)).toHaveCount(0);
    for (const id of [204, 205, 206, 207]) expect(m.srv.state.messages.get(id).folderId).toBe(15);
    const note = root.locator('.ml-note-bar');
    await expect(note.locator('.ml-note-tx')).toHaveText(/4 (Mails nach „Rechnungen“ verschoben|mails moved to “Rechnungen”)/);
    await expect(bar).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath('mail-multi-undo.png') });
    // „Rückgängig“: back in the inbox
    await note.locator('.ml-note-undo').click();
    await expect.poll(() => [204, 205, 206, 207].map((id) => m.srv.state.messages.get(id).folderId)).toEqual([11, 11, 11, 11]);
    await expect(row(root, 205)).toBeVisible();
    // „Zuletzt“ in the picker now
    await row(root, 208).click();
    await row(root, 209).click({ modifiers: ['Control'] });
    await bar.locator('[data-act="move"]').click();
    await expect(dlg.locator('.ml-pick-recent .ml-chip')).toHaveText([/Rechnungen/]);
    await dlg.locator('.ml-dlg-head .ml-ib').click();

    // Strg+A: every mail loaded; „Alle im Ordner auswählen“ asks the server (more than one page)
    await root.locator('.ml-rows').focus();
    await page.keyboard.press('Control+a');
    const loaded = await root.locator('.ml-row').count();
    await expect(bar.locator('.ml-selbar-n')).toHaveText(new RegExp(`^${loaded} `));
    await bar.locator('.ml-selbar-every').click();
    await expect(bar.locator('.ml-selbar-all')).toBeVisible();
    const total = [...m.srv.state.messages.values()].filter((x) => x.folderId === 11 || x.folderId === 21).filter((x) => x.tab === 'relevant').length;
    await expect(bar.locator('.ml-selbar-n')).toHaveText(new RegExp(`^${total} `));
    // two accounts: no moving, the hint says why
    await expect(bar.locator('[data-act="move"]')).toBeDisabled();
    await expect(bar.locator('.ml-selbar-hint')).toBeVisible();
    await page.screenshot({ path: test.info().outputPath('mail-multi-all.png') });
    // Esc ends it
    await root.locator('.ml-rows').focus();
    await page.keyboard.press('Escape');
    await expect(bar).toHaveCount(0);
    await expect(root.locator('.ml-row.is-picked')).toHaveCount(0);
  });

  test('a right click on the ticked mails, „Vor dem Löschen fragen“ with „Nicht mehr fragen“, dragging onto a folder', async ({ launchApp, mock }) => {
    const { m, page, root } = await open(launchApp, mock, { settings: { confirmDelete: true } });
    const bar = root.locator('.ml-selbar');

    // the right click on a ticked mail: the menu is for both
    await row(root, 206).click();
    await row(root, 207).click({ modifiers: ['Control'] });
    await row(root, 207).click({ button: 'right' });
    await expect(page.locator('.ml-menu-item').filter({ hasText: /^(Auswahl aufheben|Clear selection)$/ })).toBeVisible();
    await page.locator('.ml-menu-item').filter({ hasText: /^(Archivieren|Archive)$/ }).click();
    await expect.poll(() => [206, 207].map((id) => m.srv.state.messages.get(id).folderId)).toEqual([14, 14]);
    await expect(root.locator('.ml-note-bar .ml-note-tx')).toHaveText(/2 (Mails archiviert|mails archived)/);

    // Löschen asks (confirmDelete); „Nicht mehr fragen“ turns it off on the server
    await row(root, 208).click();
    await row(root, 209).click({ modifiers: ['Control'] });
    await bar.locator('[data-act="delete"]').click();
    const ask = page.locator('.ml-dlg-ask');
    await expect(ask.locator('.ml-dlg-h')).toHaveText(/^(2 Mails löschen\?|Delete 2 mails\?)$/);
    await page.screenshot({ path: test.info().outputPath('mail-multi-confirm.png') });
    await ask.locator('.ml-dont-ask input').check();
    await ask.locator('.ml-ask-go').click();
    await expect.poll(() => [208, 209].map((id) => m.srv.state.messages.get(id).folderId)).toEqual([13, 13]);
    await expect.poll(() => m.srv.state.settings.confirmDelete).toBe(false);
    // the next one goes at once
    await row(root, 210).click();
    await root.locator('.ml-read-bar .ml-ib').nth(1).click();
    await expect.poll(() => m.srv.state.messages.get(210).folderId).toBe(13);
    await expect(page.locator('.ml-dlg-ask')).toHaveCount(0);

    // dragging two ticked mails onto „Rechnungen“ in the menu (the account's folders open)
    await root.locator('.ml-side .ml-acc').nth(0).locator('.ml-it-acc').click();
    await root.locator('.ml-side .ml-frow[data-folder="14"] .ml-ffold').click();
    const target = root.locator('.ml-side .ml-frow[data-folder="15"]');
    await expect(target).toBeVisible();
    await row(root, 211).click();
    await row(root, 212).click({ modifiers: ['Control'] });
    await row(root, 212).dragTo(target);
    await expect.poll(() => [211, 212].map((id) => m.srv.state.messages.get(id).folderId)).toEqual([15, 15]);
    await expect(row(root, 211)).toHaveCount(0);

    // mails in the trash: always asked, „endgültig löschen“
    await root.locator('.ml-side .ml-frow[data-folder="13"] .ml-it').click();
    await expect(row(root, 208)).toBeVisible();
    await row(root, 208).click();
    await row(root, 209).click({ modifiers: ['Control'] });
    await expect(bar.locator('[data-act="delete"]')).toHaveText(/Endgültig löschen|Delete for good/);
    await bar.locator('[data-act="delete"]').click();
    await expect(ask.locator('.ml-dlg-h')).toHaveText(/endgültig löschen\?|for good\?/);
    await expect(ask.locator('.ml-dont-ask')).toHaveCount(0);
    await ask.locator('.ml-ask-go').click();
    await expect.poll(() => [208, 209].map((id) => m.srv.state.messages.has(id))).toEqual([false, false]);
    await expect(root.locator('.ml-note-bar .ml-note-tx')).toHaveText(/2 (Mails endgültig gelöscht|mails deleted for good)/);
  });

  test('the quick actions: seven to choose, „Verschieben …“ opens the picker, „Vor dem Löschen fragen“', async ({ launchApp, mock }) => {
    const { m, page, root } = await open(launchApp, mock);
    await root.locator('.ml-foot-settings').click();
    const dlg = page.locator('.ml-dlg');
    const quick = dlg.locator('.ml-quick-sel');
    await expect(quick).toHaveCount(2);
    await expect(quick.first().locator('option')).toHaveCount(7);
    await quick.first().selectOption('move');
    await expect.poll(() => m.srv.state.settings.swipeRight).toBe('move');
    expect(m.srv.state.lastSettingsBody).toEqual({ swipe: { right: 'move' } });
    await expect(dlg.locator('.ml-set-confirm .sw')).toHaveAttribute('aria-checked', 'false');
    await page.screenshot({ path: test.info().outputPath('mail-multi-settings.png') });
    await dlg.locator('.ml-set-confirm .sw').click();
    await expect.poll(() => m.srv.state.settings.confirmDelete).toBe(true);
    await dlg.locator('.ml-dlg-head .ml-ib').click();
    // the row's first quick button is „Verschieben …“ now: the picker for this mail
    await row(root, 101).hover();
    await row(root, 101).locator('.ml-row-acts .ml-ib').first().click();
    await expect(page.locator('.ml-dlg-pick .ml-dlg-h')).toHaveText(/^(1 Mail verschieben|Move 1 mail)$/);
  });

  test('an older Mail (≤ 1.12): ticking works, no Kopieren, no „Rückgängig“, the old four quick actions', async ({ launchApp, mock }) => {
    const { m, page, root } = await open(launchApp, mock, { features: BASE });
    const bar = root.locator('.ml-selbar');
    await row(root, 200).click();
    await row(root, 201).click({ modifiers: ['Control'] });
    await expect(bar.locator('[data-act="copy"]')).toHaveCount(0);
    await bar.locator('[data-act="archive"]').click();
    await expect.poll(() => [200, 201].map((id) => m.srv.state.messages.get(id).folderId)).toEqual([14, 14]);
    await expect(root.locator('.ml-note-bar .ml-note-tx')).toHaveText(/2 (Mails archiviert|mails archived)/);
    await expect(root.locator('.ml-note-bar .ml-note-undo')).toHaveCount(0);
    // Strg+A: the loaded ones only (no „Alle im Ordner“)
    await root.locator('.ml-rows').focus();
    await page.keyboard.press('Control+a');
    await expect(bar.locator('.ml-selbar-every')).toHaveCount(0);
    await page.keyboard.press('Escape');
    await root.locator('.ml-foot-settings').click();
    await expect(page.locator('.ml-dlg .ml-quick-sel').first().locator('option')).toHaveCount(4);
    await expect(page.locator('.ml-dlg .ml-set-confirm')).toHaveCount(0);
  });
});
