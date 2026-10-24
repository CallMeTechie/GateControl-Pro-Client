'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Vault (plugin gatecontrol-vault, end-to-end encrypted passwords): shown only
// when the server lists the plugin; setup with master password and recovery
// key (confirmed before the account is sent), a new login, the detail with a
// masked password that is revealed / copied on request, lock and unlock, and
// the quick search window (Strg+Alt+P). The server is the core's in-memory
// Vault fake (support/vault-mock.js). Selectors by id/class.

const MASTER = 'Sonnenblume-Kanu-Turm-47';

async function setupVault(page) {
  // the first account check after the server setup has answered (no account yet)
  await expect.poll(() => page.evaluate(() => window.gatecontrol.vault.status().then((s) => s.account))).toBe('none');
  await page.locator('#nav-vault').click();
  await expect(page.locator('#page-vault')).toHaveClass(/active/);
  await page.locator('#vault-setup-start').click();
  await expect(page.locator('#vault-setup-next')).toBeDisabled();
  await page.locator('#vault-pw-new').fill('kurz');
  await expect(page.locator('#vault-setup-next')).toBeDisabled();
  await page.locator('#vault-pw-new').fill(MASTER);
  await page.locator('#vault-pw-repeat').fill(MASTER);
  await expect(page.locator('#vault-setup-next')).toBeEnabled();
  await page.locator('#vault-setup-next').click();
  // recovery key first, account only after "kept safe"
  await expect(page.locator('#vault-recovery-key span')).toHaveCount(14);
  await expect(page.locator('#vault-recovery-next')).toBeDisabled();
  await page.locator('#vault-recovery-ok').check();
  await page.locator('#vault-recovery-next').click();
  await expect(page.locator('#vault-setup-finish')).toBeVisible();
  await page.locator('#vault-setup-finish').click();
  await expect(page.locator('#vault-list')).toBeVisible();
}

test.describe('vault', () => {
  test('no Vault plugin on the server: no "Vault" entry', async ({ launchApp, mock }) => {
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.count('/api/v1/client/plugins')).toBeGreaterThan(0);
    await expect(page.locator('#nav-vault')).toBeHidden();
  });

  test('setup, new login, reveal / copy, lock and unlock, quick search', async ({ launchApp, mock }) => {
    const v = mock.setVault();
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect(page.locator('#nav-vault')).toBeVisible();
    await setupVault(page);
    expect(v.srv.accounts.has(3)).toBe(true);

    // a new login
    await page.locator('#vault-new').click();
    await page.locator('.vt-menu .vt-mi').first().click();
    await page.locator('#vault-edit-title').fill('GitHub');
    await page.locator('#vault-edit-username').fill('marc');
    await page.locator('#vault-edit-password').fill('s3cr3t-Pa55word!');
    await page.locator('#vault-edit-url-0').fill('https://github.com');
    await page.locator('#vault-edit-save').click();
    await expect(page.locator('#vault-list .vt-row')).toHaveCount(1);
    await expect(page.locator('#vault-detail-title')).toHaveText('GitHub');
    // the server only ever sees ciphertext
    expect(JSON.stringify([...v.srv.items.values()])).not.toContain('s3cr3t');

    // masked until revealed; copied through main
    const pw = page.locator('#vault-detail .vt-secret[data-field="password"]');
    await expect(pw).not.toContainText('s3cr3t');
    await expect(page.locator('#page-vault')).not.toContainText('s3cr3t-Pa55word!');
    await page.locator('#vault-detail [data-copy="password"]').click();
    await expect.poll(() => app.evaluate(({ clipboard }) => clipboard.readText())).toBe('s3cr3t-Pa55word!');
    await pw.locator('xpath=following-sibling::div//button').first().click();
    await expect(pw).toHaveText('s3cr3t-Pa55word!');

    // the footer counts down while unlocked
    await expect(page.locator('#statusbar .vt-sb').first()).toContainText(/Vault/);

    // lock → unlock
    await page.locator('#vault-lock').click();
    await expect(page.locator('#vault-unlock-pw')).toBeVisible();
    await expect(page.locator('#page-vault')).not.toContainText('GitHub');
    await page.locator('#vault-unlock-pw').fill('falsch-falsch-falsch');
    await page.locator('#vault-unlock').click();
    await expect(page.locator('#page-vault .vt-err')).not.toBeEmpty();
    await page.locator('#vault-unlock-pw').fill(MASTER);
    await page.locator('#vault-unlock').click();
    await expect(page.locator('#vault-list .vt-row')).toHaveCount(1);

    // quick search window
    const quickOpened = app.waitForEvent('window');
    await app.evaluate(() => globalThis.__gcE2E.vaultQuick.show());
    const quick = await quickOpened;
    await quick.waitForLoadState('domcontentloaded');
    await quick.locator('#vq-input').fill('git');
    await expect(quick.locator('.vq-hit')).toHaveCount(1);
    await app.evaluate(({ clipboard }) => clipboard.writeText(''));
    await quick.locator('#vq-input').press('Control+b');
    await expect.poll(() => app.evaluate(({ clipboard }) => clipboard.readText())).toBe('marc');
    await expect.poll(() => app.evaluate(() => globalThis.__gcE2E.vaultQuick.window().isVisible())).toBe(false);
  });

  test('Wi-Fi entry: nearby networks, pick fills name / security / title, location hint', async ({ launchApp, mock }) => {
    mock.setVault();
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setupVault(page);

    // the real Native Wifi API of this machine (koffi → wlanapi.dll): a known answer, never a crash
    // (CI runners have no Wi-Fi: no_adapter / service_off)
    const real = await page.evaluate(() => window.gatecontrol.vault.wifiScan());
    expect(real.ok === true || ['no_adapter', 'service_off', 'radio_off', 'location_denied'].includes(real.code), JSON.stringify(real)).toBe(true);

    // a fixed answer for the dialog (an SSID with markup must stay text)
    const answer = async (res) => app.evaluate(({ ipcMain }, r) => {
      ipcMain.removeHandler('vault:wifi-scan');
      ipcMain.handle('vault:wifi-scan', async () => r);
    }, res);
    await answer({ ok: true, networks: [
      { ssid: 'FRITZ!Box 7590 XY', security: 'WPA2/WPA3', signal: 82, connected: true },
      { ssid: '<img src=x onerror=alert(1)>', security: 'Offen', signal: 30, connected: false },
    ] });

    await page.locator('#vault-new').click();
    await page.locator('.vt-menu .vt-mi').nth(4).click();   // login, 2FA, note, card, Wi-Fi, identity
    await expect(page.locator('#vault-edit-ssid')).toBeVisible();
    await page.locator('#vault-wifi-scan').click();
    const rows = page.locator('#vault-wifi-list .vt-wifi-row');
    await expect(rows).toHaveCount(2);
    await expect(rows.first()).toContainText('FRITZ!Box 7590 XY');
    await expect(rows.first().locator('.vt-person-state')).toBeVisible();
    await expect(rows.nth(1)).toContainText('<img src=x onerror=alert(1)>');
    await expect(page.locator('#vault-wifi-list img')).toHaveCount(0);
    await rows.first().click();
    await expect(page.locator('#vault-wifi-list')).toHaveCount(0);
    await expect(page.locator('#vault-edit-ssid')).toHaveValue('FRITZ!Box 7590 XY');
    await expect(page.locator('#vault-edit-security')).toHaveValue('WPA2/WPA3');
    await expect(page.locator('#vault-edit-title')).toHaveValue('FRITZ!Box 7590 XY');
    await expect(page.locator('#vault-edit-password')).toBeFocused();

    // empty, then Windows without location access: hint + settings button
    await answer({ ok: true, networks: [] });
    await page.locator('#vault-wifi-scan').click();
    await expect(page.locator('#vault-wifi-empty')).toBeVisible();
    await answer({ ok: false, code: 'location_denied' });
    await page.locator('#vault-wifi-again').click();
    await expect(page.locator('#vault-wifi-error')).toHaveAttribute('data-code', 'location_denied');
    await expect(page.locator('#vault-wifi-settings')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('#vault-wifi-list')).toHaveCount(0);
    await expect(page.locator('#vault-edit-ssid')).toHaveValue('FRITZ!Box 7590 XY');
  });
});
