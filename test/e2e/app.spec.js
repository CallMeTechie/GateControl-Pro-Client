'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey, openSettingsTab } = require('./support/ui');

test.describe('app start', () => {
  test('starts in e2e mode and renders the main window', async ({ launchApp }) => {
    const { app, page, events } = await launchApp();

    // First run without a server → setup assistant.
    await expect(page.locator('#page-setup')).toHaveClass(/active/);
    await expect(page.locator('#setup-opt-code')).toBeVisible();
    expect(await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().length)).toBe(1);

    // Test hooks are active and nothing touched tunnel or firewall.
    const types = events().map((e) => e.type);
    expect(types).toContain('e2e.installed');
    expect(types).toContain('killswitch.recover');
    expect(types).not.toContain('wg.connect');
    expect(types).not.toContain('killswitch.enable');
    expect(types).not.toContain('rdpallow.enable');
    expect(await app.evaluate(({ app: a }) => a.isPackaged)).toBe(false);
  });

  test('settings page opens', async ({ launchApp }) => {
    const { page } = await launchApp();
    await page.locator('#setup-cancel').click();
    await expect(page.locator('#page-status')).toHaveClass(/active/);

    await openSettingsTab(page, 'conn');
    await expect(page.locator('#server-url')).toBeVisible();
    await openSettingsTab(page, 'about');
    await expect(page.locator('#nav-update')).toBeVisible();
    // Short device ID (first 8 hex of the machine fingerprint) next to the version.
    await expect(page.locator('#about-device-id')).toHaveText(/[0-9a-f]{8}…$/);
  });

  test('setup with an API key registers at the server', async ({ launchApp, mock }) => {
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);

    expect(mock.count('/api/v1/client/ping')).toBeGreaterThanOrEqual(1);
    expect(mock.count('/api/v1/client/register')).toBe(1);
    const reg = mock.requests.find((r) => r.path === '/api/v1/client/register');
    expect(reg.token).toBe(mock.token);

    await openSettingsTab(page, 'conn');
    await expect(page.locator('#server-url')).toHaveValue(mock.url);
  });

  test('no server address on the page: status bar, connection card, overview — only in the settings', async ({ launchApp, mock }) => {
    const launched = await launchApp();
    const { page } = launched;
    await launched.app.evaluate(() => { globalThis.__gcE2E.tunnelWorks = true; });
    await setupWithApiKey(page, mock);
    const host = new URL(mock.url).host;
    const hostname = new URL(mock.url).hostname;
    await page.locator('#nav-status').click();
    await expect(page.locator('#page-status')).toHaveClass(/active/);
    const shown = ['#statusbar', '.conn-card', '#overview-sub', '#hero'];
    const noHost = async () => {
      for (const sel of shown) {
        await expect(page.locator(sel).first()).not.toContainText(host);
        await expect(page.locator(sel).first()).not.toContainText(hostname);
      }
    };
    // disconnected: state and kill switch only
    await expect(page.locator('#sb-conn-label')).toHaveText(/Getrennt|Disconnected|Nicht verbunden|Not connected/);
    await expect(page.locator('#sb-endpoint')).toHaveCount(0);
    await expect(page.locator('#stat-endpoint')).toHaveCount(0);
    await expect(page.locator('#sb-ks')).toHaveText(/Kill-Switch|Kill switch/);
    await expect(page.locator('#conn-sub')).toHaveText('');
    await noHost();
    // connected: the duration in the card, no address after it
    await page.locator('#connect-btn').click();
    await expect(page.locator('#sb-conn-label')).toHaveText(/Verbunden|Connected/);
    await expect(page.locator('#conn-sub')).toHaveText(/^\d/);
    await expect(page.locator('#hero-sub')).toHaveText(/verschlüsselt durch den Tunnel|encrypted through the tunnel/);
    await noHost();
    await page.screenshot({ path: test.info().outputPath('status-no-host.png') });
    // the settings still show the URL entered there
    await openSettingsTab(page, 'conn');
    await expect(page.locator('#server-url')).toHaveValue(mock.url);
  });
});
