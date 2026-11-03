'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// The host's virus scan on the page "Drive" (Drive 1.19 'scan'; the plugin is the core's fake Drive server,
// support/drive-mock.js, whose nodes carry `scan` as set here): a blocked file shows „Gesperrt – Schadsoftware“, its
// menu the reason instead of "Öffnen" / "Speichern unter" / "Link teilen", a click on it the reason; a marked file
// asks before it opens. Texts in both languages.

const menuItem = (page, re) => page.locator('.dv-menu-item', { hasText: re });

async function openFiles(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  const root = page.locator('#page-drive');
  const files = root.locator('.dv-pages [data-page="files"]');
  if (await files.isVisible()) await files.click();
  return root;
}

test.describe('virus scan', () => {
  test('Drive: a blocked file has no open, save or share — the reason; a marked one asks first', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['links', 'scan'] });
    d.srv.state.nodes.get(11).scan = { state: 'infected', blocked: true, finding: 'Eicar-Test-Signature' };
    d.srv.state.nodes.get(13).scan = { state: 'infected', blocked: false, finding: 'GC.Office.Macro' };
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openFiles(page);

    const blocked = root.locator('.dv-row[data-id="11"]');
    await expect(blocked.locator('.scan-chip[data-tone="blocked"]')).toHaveText(/Gesperrt – Schadsoftware|Blocked – malware/);
    await expect(blocked.locator('.scan-chip')).toHaveAttribute('title', /Eicar-Test-Signature/);
    await expect(root.locator('.dv-row[data-id="13"] .scan-chip[data-tone="warning"]')).toHaveText(/Warnung – Schadsoftware|Warning – malware/);
    await expect(root.locator('.dv-row[data-id="10"] .scan-chip')).toHaveCount(0);

    await blocked.locator('.dv-more-btn').click();
    await expect(page.locator('.dv-menu-note')).toHaveText(/Schadsoftware gefunden \(Eicar-Test-Signature\)|malware found \(Eicar-Test-Signature\)/);
    await expect(menuItem(page, /^(Öffnen|Open)$/)).toHaveCount(0);
    await expect(menuItem(page, /^(Speichern unter …|Save as …)$/)).toHaveCount(0);
    await expect(menuItem(page, /^(Link teilen …|Share link …)$/)).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath('scan-menu.png') });
    await page.keyboard.press('Escape');

    // a click on the blocked file: the reason, nothing loaded
    await blocked.locator('.dv-open').click();
    await expect(page.locator('.toast-text').last()).toHaveText(/Schadsoftware gefunden|malware found/);
    expect(d.srv.state.requests.some((r) => r.path.endsWith('/nodes/11/content'))).toBe(false);

    // the marked one asks first
    await root.locator('.dv-row[data-id="13"] .dv-open').click();
    const dlg = page.locator('.dv-dlg');
    await expect(dlg).toContainText(/Nur öffnen, wenn du der Datei vertraust|Only open it if you trust the file/);
    await expect(dlg.locator('.btn-danger')).toHaveText(/Trotzdem öffnen|Open anyway/);
    await dlg.locator('.btn-sec', { hasText: /Abbrechen|Cancel/ }).click();
    await expect(dlg).toHaveCount(0);
  });
});
