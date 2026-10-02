'use strict';

const zlib = require('zlib');
const { test, expect, PRODUCT } = require('./support/fixtures');
const { setupWithApiKey, openSettingsTab } = require('./support/ui');

const UPLOAD = '/api/v1/client/support-bundle';

test.describe('support bundle (Settings → About)', () => {
  test('asks first, then uploads a redacted gzip bundle', async ({ launchApp, mock }) => {
    const { page, answerDialogs, dialogs } = await launchApp();
    await setupWithApiKey(page, mock);
    await openSettingsTab(page, 'about');

    await answerDialogs([0]); // "Senden"
    await page.locator('#support-send').click();
    await expect(page.locator('#toasts .toast-success')).toBeVisible();
    await expect(page.locator('#support-send')).toBeEnabled();

    const shown = await dialogs();
    expect(shown).toHaveLength(1);
    expect(shown[0].message).toContain('127.0.0.1');

    const uploads = mock.requests.filter((r) => r.path === UPLOAD);
    expect(uploads).toHaveLength(1);
    const [up] = uploads;
    expect(up.method).toBe('POST');
    expect(up.token).toBe(mock.token);
    expect(up.contentType).toBe('application/gzip');
    expect(up.query.peerId).toBe(String(mock.peerId));

    const text = zlib.gunzipSync(up.raw).toString('utf8');
    expect(text).not.toContain(mock.token);
    const bundle = JSON.parse(text);
    expect(bundle.schema).toBe(1);
    expect(bundle.client.product).toBe(PRODUCT);
    expect(bundle.client.platform).toBe('windows');
    expect(bundle.settings.server.apiKey).toBe('[REDACTED]');
    expect(Array.isArray(bundle.logs.lines)).toBe(true);
  });

  test('cancel sends nothing', async ({ launchApp, mock }) => {
    const { page, answerDialogs, dialogs } = await launchApp();
    await setupWithApiKey(page, mock);
    await openSettingsTab(page, 'about');

    await answerDialogs([1]); // "Abbrechen"
    await page.locator('#support-send').click();
    await expect.poll(async () => (await dialogs()).length).toBe(1);
    await expect(page.locator('#support-send')).toBeEnabled();
    expect(mock.count(UPLOAD)).toBe(0);
    await expect(page.locator('#toasts .toast-error')).toHaveCount(0);
  });
});
