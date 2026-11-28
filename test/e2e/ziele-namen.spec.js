'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Targets by name only (src/renderer/target-label.js): where a target has a name, the app shows no address —
//   - Dienste page and the quick tiles on Übersicht: the name, no domain / host line (without a name: the domain);
//   - Fernzugriff: list row and detail head without "IP:Port" (without a name: the address as the name);
//   - a running session: sidebar, the Fernzugriff card and the tray menu "RDP Sessions" show the host's name.
// Made-up names and addresses.

const SERVICES = [
  { id: 1, name: 'Wiki', domain: 'wiki.lan', url: 'https://wiki.lan/', protocol: 'HTTPS' },
  { id: 2, name: 'Fotos', domain: 'fotos.lan', url: 'https://fotos.lan:8443/', protocol: 'HTTPS' },
  { id: 3, name: '', domain: 'ohne-name.lan', url: 'https://ohne-name.lan/', protocol: 'HTTP' },
];

const ROUTES = [
  { id: 7, name: 'Buchhaltung-PC', host: '10.0.0.21', port: 3389, access_mode: 'gateway', credential_mode: 'full', resolution_mode: 'dynamic',
    redirect_clipboard: 1, redirect_drives: 0, redirect_printers: 0, multi_monitor: 0, audio_mode: 'local', nla_enabled: 1, tags: '[]' },
  { id: 9, name: '', host: '10.0.0.29', port: 3390, access_mode: 'gateway', credential_mode: 'full', resolution_mode: 'dynamic',
    redirect_clipboard: 1, audio_mode: 'local', nla_enabled: 1, tags: '[]' },
];

test.describe('Ziele nur mit Namen', () => {
  test('Dienste: only the name on the cards and tiles, the domain only without a name', async ({ launchApp, mock }) => {
    mock.setPermissions({ services: true });
    mock.setServices(SERVICES);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.evaluate(() => window.gatecontrol.locale.set('de'));
    await page.locator('#connect-btn').click();
    await expect(page.locator('#sb-conn-label')).toHaveText(/Verbunden|Connected/);

    // Übersicht: the quick tiles
    const quick = page.locator('#services-list');
    await expect(quick.locator('.svc-tile')).toHaveCount(3);
    await expect(quick.locator('.svc-name')).toHaveText(['Wiki', 'Fotos', 'ohne-name.lan']);
    await expect(quick.locator('.svc-host')).toHaveCount(0);
    await expect(quick).not.toContainText('wiki.lan');
    await expect(quick).not.toContainText('fotos.lan');

    // Dienste page: the cards
    await page.locator('#nav-services').click();
    await expect(page.locator('#page-services')).toHaveClass(/active/);
    const grid = page.locator('#services-grid');
    await expect(grid.locator('.svc-card')).toHaveCount(3);
    await expect(grid.locator('.svc-name')).toHaveText(['Wiki', 'Fotos', 'ohne-name.lan']);
    await expect(grid.locator('.svc-host')).toHaveCount(0);
    await expect(grid.locator('.svc-card').nth(0)).not.toContainText('wiki.lan');
    await expect(grid.locator('.svc-card').nth(1)).not.toContainText('fotos.lan');
    await expect(grid.locator('.svc-card').nth(1)).not.toContainText('8443');
    await expect(grid.locator('.svc-initial').nth(2)).toHaveText('o');
    await page.screenshot({ path: test.info().outputPath('dienste-nur-namen.png') });
  });

  test('Fernzugriff and the tray: the host\'s name, no "IP:Port" where a name is there', async ({ launchApp, mock }) => {
    mock.setRdp({ routes: ROUTES });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.evaluate(() => window.gatecontrol.locale.set('de'));
    await page.locator('#nav-rdp').click();
    await expect(page.locator('#page-rdp')).toHaveClass(/active/);

    // the list: the name only; the host without a name shows its address as the name
    const list = page.locator('#rdp-list');
    await expect(list.locator('[data-rdp="7"] .host-name')).toHaveText('Buchhaltung-PC');
    await expect(list.locator('[data-rdp="7"]')).not.toContainText('10.0.0.21');
    await expect(list.locator('[data-rdp="9"] .host-name')).toHaveText('10.0.0.29:3390');
    await expect(list.locator('.host-addr')).toHaveCount(0);

    // the detail head: no "IP:Port" below the name
    await list.locator('[data-rdp="7"]').click();
    const head = page.locator('#rdp-detail .rdp-detail-head');
    await expect(head.locator('.rdp-detail-name')).toHaveText('Buchhaltung-PC');
    await expect(head).not.toContainText('10.0.0.21');
    await expect(head).not.toContainText('3389');
    await page.screenshot({ path: test.info().outputPath('fernzugriff-nur-namen.png') });

    // a running session: the sidebar, the card of Fernzugriff and the tray show the name
    await page.locator('#rdp-connect').click();
    await expect(page.locator('#rdp-show-window')).toBeVisible();
    await expect(page.locator('#side-sessions-list')).toContainText('Buchhaltung-PC');
    await expect(page.locator('#side-sessions-list')).not.toContainText('10.0.0.21');
    await expect(page.locator('#rdp-sessions-list')).toContainText('Buchhaltung-PC');
    await expect(page.locator('#rdp-sessions-list')).not.toContainText('10.0.0.21');

    await expect.poll(() => app.evaluate(() => globalThis.__gcE2E.trayLabels().some((l) => /^RDP Sessions \(1\)$/.test(l || '')))).toBe(true);
    const labels = await app.evaluate(() => globalThis.__gcE2E.trayLabels());
    const rows = labels.filter((l) => /^ {2}.+ \(\d+m\)$/.test(l || ''));
    expect(rows).toEqual(['  Buchhaltung-PC (0m)']);
    expect(labels.join('\n')).not.toContain('10.0.0.21');

    await app.evaluate(() => globalThis.__gcE2E.rdpHostFake.disconnect(1, 0, true));
    await expect(page.locator('#rdp-show-window')).toHaveCount(0);
  });
});
