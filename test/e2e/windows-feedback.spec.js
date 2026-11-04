'use strict';

// Rückmeldungen vom Windows-Client (Pro 1.68.0):
// - „Export“ der Protokolle speichert eine Kopie (Speichern-Dialog) und zeigt sie im Explorer;
// - Windows lehnt die Benachrichtigungen ab (E_ACCESSDENIED): die Meldung erscheint in der App, die Einstellungen sagen
//   warum und öffnen die Windows-Seite;
// - Mail: die Filter Ungelesen / Markiert / Mit Anhang ändern die Liste;
// - Mail: „Anderer Ordner“ beim Ablegen eines Anhangs öffnet auch den obersten Ordner eines Bereichs (vorher
//   „bad_response“: Drive schickt ihn ohne Namen — das Test-Drive antwortet jetzt wie das Plugin).
const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey, openSettingsTab } = require('./support/ui');

const row = (root, id) => root.locator(`.ml-row[data-id="${id}"]`);

async function openMail(page) {
  await expect(page.locator('#nav-mail')).toBeVisible();
  await page.locator('#nav-mail').click();
  await expect(page.locator('#page-mail')).toHaveClass(/active/);
  return page.locator('#page-mail');
}

test.describe('Windows-Rückmeldungen', () => {
  test('„Export“ der Protokolle: Kopie an den gewählten Ort, im Explorer gezeigt', async ({ launchApp }) => {
    const { app, page, dir, events } = await launchApp();
    await page.locator('#setup-cancel').click();
    await expect(page.locator('#page-status')).toHaveClass(/active/);
    const out = path.join(dir, 'export', 'protokoll.log');
    fs.mkdirSync(path.dirname(out), { recursive: true });
    await app.evaluate((_e, p) => { globalThis.__gcE2E.saveDialogPaths.push(p); }, out);

    await page.locator('#nav-logs').click();
    await expect(page.locator('#page-logs')).toHaveClass(/active/);
    await page.locator('#btn-export-logs').click();
    await expect(page.locator('#toasts .toast-success')).toContainText(out);
    expect(fs.existsSync(out)).toBe(true);
    expect(fs.readFileSync(out, 'utf8').length).toBeGreaterThan(0);
    const asked = await app.evaluate(() => globalThis.__gcE2E.saveDialogs);
    // the app's name (packaged: GateControl-Pro-Client), the local time
    expect(path.basename(asked.at(-1).defaultPath)).toMatch(/^[A-Za-z0-9-]+-(Protokoll|Log)-\d{4}-\d{2}-\d{2}-\d{4}\.log$/);
    await expect.poll(() => events().filter((e) => e.type === 'shell.showItemInFolder').map((e) => e.path)).toContain(out);
  });

  test('Windows lehnt Benachrichtigungen ab: die Meldung erscheint in der App, die Einstellungen erklären es', async ({ launchApp, mock, offerUpdate }) => {
    offerUpdate('valid');
    const { app, page, runScheduledUpdateCheck } = await launchApp();
    await setupWithApiKey(page, mock);
    // the "Update verfügbar" toast — as Electron reports it when the app's notifications are off in Windows
    await runScheduledUpdateCheck();
    await expect.poll(() => app.evaluate(() => globalThis.__gcE2E.toasts.length)).toBeGreaterThan(0);
    expect(await app.evaluate(() => globalThis.__gcE2E.failToast('.'))).toBe(true);
    await expect(page.locator('#toasts .toast-info')).toBeVisible();

    await openSettingsTab(page, 'notify');
    await expect(page.locator('#notify-toast-blocked')).toBeVisible();
    await page.locator('#notify-toast-settings').click();
    await expect.poll(() => app.evaluate(() => globalThis.__gcE2E.events.filter((e) => e.type === 'shell.openExternal').map((e) => e.url))).toContain('ms-settings:notifications');
  });

  test('Mail: die Filter Ungelesen, Markiert und Mit Anhang ändern die Liste', async ({ launchApp, mock }) => {
    const m = await mock.setMail();
    m.srv.state.messages.get(102).flagged = true;
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openMail(page);
    await expect(row(root, 101)).toBeVisible();
    await expect(row(root, 105)).toBeVisible();
    const filter = (i) => root.locator('.ml-filter').nth(i);

    await filter(0).click(); // Ungelesen
    await expect(filter(0)).toHaveAttribute('aria-pressed', 'true');
    await expect(row(root, 105)).toHaveCount(0);
    await expect(row(root, 101)).toBeVisible();
    await expect(row(root, 102)).toBeVisible();
    const asked = () => m.srv.state.requests.filter((r) => r.path.endsWith('/api/messages')).map((r) => r.query);
    expect(asked().at(-1).unread).toBe('1');

    await filter(1).click(); // + Markiert
    await expect(row(root, 101)).toHaveCount(0);
    await expect(row(root, 102)).toBeVisible();
    await filter(0).click();
    await filter(1).click();
    await filter(2).click(); // Mit Anhang
    await expect(row(root, 101)).toBeVisible();
    await expect(row(root, 102)).toHaveCount(0);
    expect(asked().at(-1).attachments).toBe('1');
    await filter(2).click();
    await expect(row(root, 105)).toBeVisible();
  });

  test('Mail: „Anderer Ordner“ öffnet den obersten Ordner eines Bereichs und legt den Anhang dort ab', async ({ launchApp, mock }) => {
    const m = await mock.setMail();
    await mock.setDrive();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openMail(page);
    await row(root, 101).click();
    await expect(root.locator('.ml-att-name').first()).toHaveText('Rechnung_2026_11.pdf');
    await root.locator('.ml-att .btn-sec', { hasText: /^(Anderer Ordner|Other folder)$/ }).first().click();
    const list = page.locator('.dv-pick-list').last();
    await list.locator('.dv-pick-row', { hasText: 'Familie Muster' }).click();
    // the top folder of the area: no "bad_response" any more, its label as the path
    await expect(page.locator('.dv-pick-path').last()).toHaveText('Familie Muster');
    await expect(page.locator('.dv-dlg-err').last()).toHaveText('');
    await page.locator('.btn-pri', { hasText: /^(Hier speichern|Save here)$/ }).last().click();
    await expect(page.locator('#toasts .toast-success')).toBeVisible();
    await expect.poll(() => m.srv.state.requests.some((r) => /attachments\/\d+\/drive\/save$/.test(r.path))).toBe(true);
  });
});
