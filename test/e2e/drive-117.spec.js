'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive 1.17 on the page "Drive" ('deadlineMailCalendar'; the plugin is the core's fake Drive server,
// support/drive-mock.js): in the Drive settings "Fristen aus <Bereich>" picks the family calendar or a calendar of the
// mail plugin; "In Kalender eintragen" of a deadline asks for the calendar (the area's target first) and then shows
// "Im Kalender · Outlook". Without the feature the switch "Fristen aus …" of Drive 1.14 stays. Texts in both languages.

const tool = (root, view) => root.locator(`.dv-tool[data-view="${view}"]`);

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

test.describe('drive 1.17', () => {
  test('"Fristen aus …" with a mail calendar, "In Kalender eintragen" asks with the area\'s target first', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['docAi', 'deadlineCalendar', 'deadlineMailCalendar'] });
    d.srv.setInsight(12, { kind: 'insurance', deadlines: [{ kind: 'cancellation', date: '2099-11-30', label: 'Kfz-Versicherung kündigen' }] });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(root.locator('.dv-row[data-id="10"]')).toBeVisible();

    // the settings: a choice per area under its AI switch, unique titles
    await tool(root, 'settings').click();
    const ai = root.locator('.dset [data-section="ai"]');
    const mine = ai.locator('[data-key="dlt-mine:2"]');
    await expect(mine).toBeVisible();
    await expect(ai.locator('.set-row-title', { hasText: /^(Fristen aus|Deadlines from) / })).toHaveCount(2);
    await expect(mine.locator('optgroup')).toHaveCount(2);
    await mine.selectOption('mail:cal-1');
    await expect.poll(() => (d.srv.state.targets.get('mine:2') || {}).calendarId).toBe('cal-1');
    await expect(ai.locator('[data-key="dlt-mine:2"]')).toHaveValue('mail:cal-1');

    // "Fristen": the calendar to choose, the area's target first
    await tool(root, 'deadlines').click();
    const kfz = root.locator('.dv-ki-dl').first();
    await expect(kfz.locator('.dv-ki-cal')).toHaveText(/In Kalender eintragen|Add to calendar/);
    await kfz.locator('.dv-ki-cal').click();
    const dlg = page.locator('.dv-dlg');
    await expect(dlg.locator('.dv-choice')).toHaveCount(3);
    await expect(dlg.locator('.dv-choice.is-on')).toHaveAttribute('data-choice', 'mail:cal-1');
    await dlg.locator('.dv-dlt-ok').click();
    await expect(kfz.locator('.dv-ki-cal')).toHaveText(/Im Kalender · Outlook|In the calendar · Outlook/);
    await expect(kfz.locator('.dv-ki-cal')).toBeDisabled();
    expect(d.srv.state.calendarBodies.at(-1)).toMatchObject({ target: { kind: 'mail', calendarId: 'cal-1' } });
  });

  test('without the feature: the switch "Fristen aus …" into the family calendar', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['docAi', 'deadlineCalendar'] });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(root.locator('.dv-row[data-id="10"]')).toBeVisible();
    await tool(root, 'settings').click();
    const ai = root.locator('.dset [data-section="ai"]');
    await expect(ai.locator('[data-key^="dlt-"]')).toHaveCount(0);
    await expect(ai.locator('.set-row-title', { hasText: /^(Fristen aus Meine Dateien|Deadlines from My files)$/ })).toHaveCount(1);
    await ai.locator('[data-key="cal-mine:2"]').click();
    await expect.poll(() => d.srv.state.toCalendar.has('mine:2')).toBe(true);
  });
});
