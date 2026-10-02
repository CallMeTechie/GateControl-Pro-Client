'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey, openSettingsTab } = require('./support/ui');

test.describe('client policy from the server', () => {
  test('locks the settings the admin set ("Vom Administrator festgelegt")', async ({ launchApp, mock }) => {
    mock.setPolicy({
      killSwitch: 'required',
      autoConnect: 'user',
      autostart: 'forbidden',
      splitTunnelModes: ['off', 'exclude'],
      splitTunnelLocked: false,
      lockSettings: false,
      lockServer: true,
    });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.count('/api/v1/client/policy')).toBeGreaterThanOrEqual(1);

    await openSettingsTab(page, 'sec');
    const ks = page.locator('#killswitch-toggle');
    await expect(ks).toBeDisabled();
    await expect(ks).toHaveAttribute('aria-checked', 'true');
    await expect(page.locator('#killswitch-row .policy-hint')).toBeVisible();
    // not covered by the policy → still free
    await expect(page.locator('#rdp-allow-toggle')).toBeEnabled();

    await openSettingsTab(page, 'app');
    await expect(page.locator('#opt-autostart')).toBeDisabled();
    await expect(page.locator('#opt-autostart')).toHaveAttribute('aria-checked', 'false');
    await expect(page.locator('#opt-autoconnect')).toBeEnabled();

    // Windows knows 'off' and 'include'; only 'off' is left
    await openSettingsTab(page, 'split');
    await expect(page.locator('#split-mode-split')).toBeDisabled();
    await expect(page.locator('#split-mode-all')).toBeEnabled();

    await openSettingsTab(page, 'conn');
    await expect(page.locator('#policy-server-hint')).toBeVisible();
    await expect(page.locator('#server-url')).toBeHidden();
    await expect(page.locator('#btn-open-setup')).toBeHidden();
    await expect(page.locator('#policy-banner')).toBeVisible();
  });

  test('an old server without the policy endpoint leaves everything unlocked', async ({ launchApp, mock }) => {
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await openSettingsTab(page, 'sec');
    await expect(page.locator('#killswitch-toggle')).toBeEnabled();
    await openSettingsTab(page, 'conn');
    await expect(page.locator('#server-url')).toBeVisible();
    await expect(page.locator('#policy-banner')).toBeHidden();
  });
});
