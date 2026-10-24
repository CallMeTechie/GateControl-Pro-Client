'use strict';

const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Vault (plugin gatecontrol-vault, end-to-end encrypted passwords): shown only
// when the server lists the plugin; setup with master password and recovery
// key (confirmed before the account is sent), a new login, the detail with a
// masked password that is revealed / copied on request, lock and unlock, the
// quick search window (Strg+Alt+P) and Windows Hello unlock (real detection,
// then a fake provider, support/hello-fake.js). The server is the core's in-memory
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

  test('Windows Hello: real detection answers; on with the master password, unlock, too many tries → password, quick search, off', async ({ launchApp, mock }) => {
    mock.setVault();
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setupVault(page);

    // the real provider of this machine (koffi → WinRT; CI runners have no Hello, Linux has none): a known answer, no crash
    const real = await page.evaluate(() => window.gatecontrol.vault.helloCheck());
    expect(real.ok, JSON.stringify(real)).toBe(true);
    expect(real.available === true || ['unsupported_os', 'remote_session', 'not_set_up', 'error'].includes(real.reason), JSON.stringify(real)).toBe(true);

    // from here a fake Windows Hello (support/hello-fake.js); the core's wrapping and DPAPI run for real
    await app.evaluate(() => globalThis.__gcE2E.useFakeHello());
    const prompts = () => app.evaluate(() => globalThis.__gcE2E.hello.fake.prompts.length);
    const answer = (list) => app.evaluate((_e, l) => { globalThis.__gcE2E.hello.fake.answers.push(...l); }, list);
    const openSettings = async () => {
      await page.locator('#vault-more').click();
      await page.locator('.vt-menu .vt-mi').nth(4).click(); // Einstellungen / Settings
      await expect(page.locator('#vault-settings')).toBeVisible();
    };

    // not set up in Windows: the switch is off and disabled, with the reason and the way to the sign-in options
    await app.evaluate(() => { globalThis.__gcE2E.hello.fake.avail = { available: false, reason: 'not_set_up' }; });
    await openSettings();
    await expect(page.locator('#vault-hello')).toBeDisabled();
    await expect(page.locator('#vault-hello-setup')).toBeVisible();
    await page.locator('#vault-hello-setup').click();
    await expect.poll(() => app.evaluate(() => globalThis.__gcE2E.events.filter((e) => e.type === 'shell.openExternal').map((e) => e.url))).toContain('ms-settings:signinoptions');

    // set up: on with the master password (a wrong one asks Windows nothing), then Windows Hello
    await app.evaluate(() => { globalThis.__gcE2E.hello.fake.avail = { available: true, reason: null }; });
    await openSettings();
    await expect(page.locator('#vault-hello')).toBeEnabled();
    await expect(page.locator('#vault-hello')).toHaveAttribute('aria-checked', 'false');
    await page.locator('#vault-hello').click();
    await page.locator('#vault-hello-pw').fill('falsch-falsch-falsch');
    await page.locator('#vault-hello-confirm').click();
    await expect(page.locator('.vt-dialog .vt-err')).not.toBeEmpty();
    expect(await prompts()).toBe(0);
    await page.locator('#vault-hello-pw').fill(MASTER);
    await page.locator('#vault-hello-confirm').click();
    await expect(page.locator('#vault-hello')).toHaveAttribute('aria-checked', 'true');
    await expect(page.locator('#vault-remember')).toBeDisabled();
    expect(await prompts()).toBe(1);
    const status = await page.evaluate(() => window.gatecontrol.vault.status());
    expect([status.hello, status.helloAvailable, status.remember]).toEqual([true, true, false]);

    // locked on the page: Windows Hello is offered first (it does not ask by itself right after a lock)
    await page.locator('#vault-lock').click();
    await expect(page.locator('#vault-unlock-hello')).toBeVisible();
    await expect(page.locator('#vault-unlock-pw')).toBeVisible();
    await expect(page.locator('#vault-unlock-remember')).toHaveCount(0);
    expect(await prompts()).toBe(1);
    await page.locator('#vault-unlock-hello').click();
    await expect(page.locator('#vault-unlock-pw')).toBeHidden();
    await expect(page.locator('#vault-lock')).toBeVisible();
    expect(await prompts()).toBe(2);

    // three cancelled tries → only the master password
    await page.locator('#vault-lock').click();
    await answer(['cancelled', 'cancelled', 'cancelled']);
    for (let i = 1; i <= 3; i++) {
      await page.locator('#vault-unlock-hello').click();
      await expect.poll(prompts).toBe(2 + i);
    }
    await expect(page.locator('#vault-unlock-hello')).toHaveCount(0);
    await expect(page.locator('#vault-hello-hint')).toBeVisible();
    expect(await page.evaluate(() => window.gatecontrol.vault.status().then((s) => s.helloBlocked))).toBe(true);
    await page.locator('#vault-unlock-pw').fill(MASTER);
    await page.locator('#vault-unlock').click();
    await expect(page.locator('#vault-lock')).toBeVisible();

    // quick search while locked: Windows Hello asks right away, then the search works
    await page.locator('#vault-lock').click();
    await expect(page.locator('#vault-unlock-hello')).toBeVisible();
    const quickOpened = app.waitForEvent('window');
    await app.evaluate(() => globalThis.__gcE2E.vaultQuick.show());
    const quick = await quickOpened;
    await quick.waitForLoadState('domcontentloaded');
    await expect.poll(() => page.evaluate(() => window.gatecontrol.vault.status().then((s) => s.unlocked))).toBe(true);
    await expect(quick.locator('#vq-input')).toHaveAttribute('type', 'search');
    expect(await prompts()).toBe(6);
    await quick.locator('#vq-input').press('Escape');

    // off: record and Hello key go, "Angemeldet bleiben" is possible again
    await openSettings();
    await page.locator('#vault-hello').click();
    await expect(page.locator('#vault-hello')).toHaveAttribute('aria-checked', 'false');
    await expect(page.locator('#vault-remember')).toBeEnabled();
    expect(await app.evaluate(() => globalThis.__gcE2E.hello.fake.keys.size)).toBe(0);
    await page.locator('#vault-lock').click();
    await expect(page.locator('#vault-unlock-hello')).toHaveCount(0);
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

  test('Wi-Fi entry: „Freigabe auf Wandtablet“ with a duration and the warning, the running share, „Beenden“ (plugin 1.4.0)', async ({ launchApp, mock }) => {
    const v = mock.setVault();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setupVault(page);
    await page.locator('#vault-new').click();
    await page.locator('.vt-menu .vt-mi').nth(4).click();   // Wi-Fi
    await page.locator('#vault-edit-title').fill('Gäste');
    await page.locator('#vault-edit-ssid').fill('Gäste;WLAN');
    await page.locator('#vault-edit-password').fill('Korrekt:Pferd');
    await page.locator('#vault-edit-save').click();
    const block = page.locator('#vault-shares');
    await expect(block).toBeVisible();
    await expect(block.locator('[data-share-start="wall"]')).toBeVisible();
    await expect(block.locator('[data-share-start="portal"]')).toBeVisible();
    await block.locator('[data-share-start="wall"]').click();
    const dlg = page.locator('.vt-dialog');
    await expect(dlg.locator('input[type="radio"]')).toHaveCount(4);
    await expect(dlg.locator('input[value="1h"]')).toBeChecked();
    await expect(dlg.locator('.vt-note-warn')).toBeVisible();
    await dlg.locator('input[value="5m"]').check();
    await dlg.locator('.vt-dlg-actions .btn-pri').click();
    const row = block.locator('.vt-share[data-share="wall"]');
    await expect(row).toBeVisible();
    await expect(row.locator('.vt-share-left')).toHaveText(/\d:\d\d/);
    await expect(block.locator('[data-share-start="wall"]')).toHaveCount(0);
    // main sent the copy (the page never had the password)
    const share = [...v.srv.shares.values()][0];
    expect([share.target, share.ssid, share.security, share.password]).toEqual(['wall', 'Gäste;WLAN', 'WPA', 'Korrekt:Pferd']);
    await row.locator('.btn-danger').click();
    await expect(block.locator('.vt-share')).toHaveCount(0);
    expect(v.srv.shares.size).toBe(0);
  });

  test('2FA from a QR code: real clipboard / screen / file, then the dialog with fixed answers', async ({ launchApp, mock }) => {
    mock.setVault();
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setupVault(page);
    // fixtures/totp-qr.png holds exactly this text
    const URI = 'otpauth://totp/Example:anna%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example';
    const fixture = path.join(__dirname, 'fixtures', 'totp-qr.png');
    const png = fs.readFileSync(fixture).toString('base64');
    const qr = (source) => page.evaluate((s) => window.gatecontrol.vault.totpQr(s), source);

    // the real thing in the main process: clipboard image (Electron 44: ClipboardItem image/png) …
    await app.evaluate(async ({ clipboard, ClipboardItem, nativeImage }, b64) => {
      const buf = Buffer.from(b64, 'base64');
      if (typeof clipboard.writeImage === 'function') clipboard.writeImage(nativeImage.createFromBuffer(buf));
      else await clipboard.write([new ClipboardItem({ 'image/png': new Blob([buf], { type: 'image/png' }) })]);
    }, png);
    expect(await qr('clipboard')).toEqual({ ok: true, uris: [URI] });
    await app.evaluate(({ clipboard }) => clipboard.clear());
    expect((await qr('clipboard')).code).toBe('no_image');

    // … an image file (the open dialog answered) …
    await app.evaluate(({ dialog }, file) => {
      globalThis.__qrOpen = dialog.showOpenDialog;
      dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [file] });
    }, fixture);
    expect(await qr('file')).toEqual({ ok: true, uris: [URI] });
    await app.evaluate(({ dialog }) => { dialog.showOpenDialog = async () => ({ canceled: true, filePaths: [] }); });
    expect((await qr('file')).code).toBe('cancelled');
    await app.evaluate(({ dialog }) => { dialog.showOpenDialog = globalThis.__qrOpen; });

    // … and the screen: the QR code in another window, on top
    await app.evaluate(async ({ BrowserWindow }, b64) => {
      const w = new BrowserWindow({ x: 40, y: 40, width: 320, height: 320, frame: false, alwaysOnTop: true, show: true, webPreferences: { sandbox: true } });
      globalThis.__qrWin = w;
      const html = `<body style="margin:0;background:#fff;display:grid;place-items:center;height:100vh"><img src="data:image/png;base64,${b64}"></body>`;
      await w.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
    }, png);
    await expect.poll(() => qr('screen'), { timeout: 30000 }).toEqual({ ok: true, uris: [URI] });
    if (process.platform === 'win32') {
      // covered by the GateControl window: one more capture with the window transparent, then restored
      const covered = await app.evaluate(({ BrowserWindow }) => {
        const qrWin = globalThis.__qrWin;
        const main = BrowserWindow.getAllWindows().find((w) => w !== qrWin && w.isVisible() && /index\.html/.test(w.webContents.getURL()));
        if (!main) return false;
        const b = main.getContentBounds();
        qrWin.setAlwaysOnTop(false);
        qrWin.setBounds({ x: b.x + Math.round(b.width / 2) - 160, y: b.y + Math.round(b.height / 2) - 160, width: 320, height: 320 });
        main.moveTop();
        main.focus();
        return b.width >= 360 && b.height >= 360;
      });
      if (covered) {
        await expect.poll(() => qr('screen'), { timeout: 30000 }).toEqual({ ok: true, uris: [URI] });
        expect(await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().filter((w) => w !== globalThis.__qrWin).map((w) => w.getOpacity()))).not.toContain(0);
      }
    }
    await app.evaluate(() => { globalThis.__qrWin.destroy(); });

    // the dialog with fixed answers (labels with markup stay text)
    const answer = async (res) => app.evaluate(({ ipcMain }, r) => {
      ipcMain.removeHandler('vault:totp-qr');
      ipcMain.handle('vault:totp-qr', async (_e, arg) => ({ ...r, source: arg && arg.source }));
    }, res);
    const B = 'otpauth://totp/%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E:bob?secret=GEZDGNBVGY3TQOJQ&digits=8&period=60';
    await answer({ ok: true, uris: [URI, B] });

    await page.locator('#vault-new').click();
    await page.locator('.vt-menu .vt-mi').first().click();   // login
    await expect(page.locator('#vault-edit-totp')).toBeVisible();
    await page.locator('#vault-qr-scan').click();
    await expect(page.locator('#vault-qr-screen')).toBeVisible();
    await expect(page.locator('#vault-qr-clipboard')).toBeVisible();
    await expect(page.locator('#vault-qr-file')).toBeVisible();
    await page.locator('#vault-qr-screen').click();
    const rows = page.locator('#vault-qr-list .vt-qr-row');
    await expect(rows).toHaveCount(2);
    await expect(rows.first()).toContainText('Example');
    await expect(rows.first()).toContainText('anna@example.com');
    await expect(rows.nth(1)).toContainText('<img src=x onerror=alert(1)>');
    await expect(page.locator('#vault-qr-list img')).toHaveCount(0);
    await rows.first().click();
    await expect(page.locator('#vault-qr-list')).toHaveCount(0);
    await expect(page.locator('#vault-edit-totp')).toHaveValue(URI);
    await expect(page.locator('#vault-edit-title')).toHaveValue('Example');
    await expect(page.locator('#vault-edit-username')).toHaveValue('anna@example.com');

    // errors: nothing on the screen, HOTP; a cancelled file dialog closes quietly
    await answer({ ok: false, code: 'none_found' });
    await page.locator('#vault-qr-scan').click();
    await page.locator('#vault-qr-screen').click();
    await expect(page.locator('#vault-qr-error')).toHaveAttribute('data-code', 'none_found');
    await expect(page.locator('#vault-qr-error')).toContainText(/Kein 2FA-QR-Code auf dem Bildschirm gefunden|No 2FA QR code found on the screen/);
    await answer({ ok: false, code: 'hotp' });
    await page.locator('#vault-qr-again').click();
    await expect(page.locator('#vault-qr-error')).toHaveAttribute('data-code', 'hotp');
    await expect(page.locator('#vault-qr-error')).toContainText(/HOTP wird nicht unterstützt|HOTP is not supported/);
    await page.keyboard.press('Escape');
    await expect(page.locator('#vault-qr-list')).toHaveCount(0);
    await answer({ ok: false, code: 'cancelled' });
    await page.locator('#vault-qr-scan').click();
    await page.locator('#vault-qr-file').click();
    await expect(page.locator('#vault-qr-list')).toHaveCount(0);

    // one code (clipboard): taken over at once; own title and user name stay
    await page.locator('#vault-edit-title').fill('Mein Konto');
    await answer({ ok: true, uris: [B] });
    await page.locator('#vault-qr-scan').click();
    await page.locator('#vault-qr-clipboard').click();
    await expect(page.locator('#vault-edit-totp')).toHaveValue(B);
    await expect(page.locator('#vault-qr-list')).toHaveCount(0);
    await expect(page.locator('#vault-edit-title')).toHaveValue('Mein Konto');
    await expect(page.locator('#vault-edit-username')).toHaveValue('anna@example.com');

    // saved: the detail shows the live 2FA code (8 digits from the URI)
    await page.locator('#vault-edit-save').click();
    await expect(page.locator('#vault-totp-code')).toHaveText(/^\d{4} \d{4}$/);

    // a 2FA-code entry has the button too
    await page.locator('#vault-new').click();
    await page.locator('.vt-menu .vt-mi').nth(1).click();   // login, 2FA, note, card, Wi-Fi, identity
    await expect(page.locator('#vault-qr-scan')).toBeVisible();
  });
});
