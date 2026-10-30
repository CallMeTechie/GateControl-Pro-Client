'use strict';

const http = require('http');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Mail (plugin gatecontrol-mail, Phase 1): shown only when the server lists the plugin and lets the person in;
// the three columns (menu with accounts and folders | list with Relevant / Sonstige | reading pane), a mail with
// the AI bar, an attachment with its Drive suggestion, pictures blocked and then loaded through gcmail: in the
// sandboxed frame (no scripts), writing with recipient chips, sending with "Rückgängig", "Konto hinzufügen" with
// the provider's hint and the server's refusal, and the Microsoft sign-in in the browser (loopback, PKCE). The
// plugin is the core's fake Mail server (support/mail-mock.js). Selectors by id/class, texts in both languages.

async function openMail(page) {
  await expect(page.locator('#nav-mail')).toBeVisible();
  await page.locator('#nav-mail').click();
  await expect(page.locator('#page-mail')).toHaveClass(/active/);
  return page.locator('#page-mail');
}

const row = (root, id) => root.locator(`.ml-row[data-id="${id}"]`);

test.describe('mail', () => {
  test('no Mail plugin on the server: no "Mail" entry', async ({ launchApp, mock }) => {
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.count('/api/v1/client/plugins')).toBeGreaterThan(0);
    await expect(page.locator('#nav-mail')).toBeHidden();
  });

  test('not unlocked for the person: no "Mail" entry', async ({ launchApp, mock }) => {
    const m = await mock.setMail();
    m.srv.state.allowed = false;
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => m.srv.state.requests.filter((r) => r.path.endsWith('/api/me')).length).toBeGreaterThan(0);
    await expect(page.locator('#nav-mail')).toBeHidden();
  });

  test('inboxes, reading with AI and attachments, pictures through gcmail:, actions', async ({ launchApp, mock }) => {
    const m = await mock.setMail();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect(page.locator('#mail-badge')).toHaveText('3');
    const root = await openMail(page);

    // menu: Alle Posteingänge, Zum Ablegen, two accounts
    await expect(root.locator('.ml-side .ml-acc')).toHaveCount(2);
    // accounts as in the Outlook app (Mail 1.1.2): the Microsoft account's picture, GMX's mark, the address below the name
    await expect(root.locator('.ml-side .ml-acc').nth(1).locator('.ml-av-face img')).toHaveAttribute('src', /^data:image\/png;base64,/);
    await expect(root.locator('.ml-side .ml-acc').first().locator('.ml-av-face')).toHaveText('GMX');
    await expect(root.locator('.ml-side .ml-acc').first().locator('.ml-it-mail')).toHaveText('max@gmx.de');
    await expect(root.locator('.ml-it.on')).toContainText(/Alle Posteingänge|All inboxes/);
    // Relevant: the newest first; Sonstige: the newsletter
    await expect(row(root, 101)).toBeVisible();
    await expect(row(root, 102)).toBeVisible();
    await expect(row(root, 104)).toHaveCount(0);
    await root.locator('.ml-tab').nth(1).click();
    await expect(row(root, 104)).toBeVisible();
    await root.locator('.ml-tab').nth(0).click();
    // an account's inbox
    await root.locator('.ml-chip', { hasText: 'Firma · M365' }).click();
    await expect(row(root, 102)).toBeVisible();
    await expect(row(root, 101)).toHaveCount(0);
    await root.locator('.ml-chip').first().click();
    await page.screenshot({ path: test.info().outputPath('mail-list.png') });

    // read: marked read, AI summary, attachment with suggestion, pictures blocked
    await row(root, 101).click();
    await expect(root.locator('.ml-read-subj')).toHaveText('Ihre Rechnung November');
    await expect(root.locator('.ml-ai-sum')).toContainText('84,20 €');
    await expect(root.locator('.ml-att-name').first()).toHaveText('Rechnung_2026_11.pdf');
    await expect(root.locator('.ml-att-sugname')).toHaveText('2026-11-03 Stadtwerke Rechnung.pdf');
    await expect(root.locator('.ml-sug')).toHaveText(['Danke']);
    await expect.poll(() => m.srv.state.messages.get(101).unread).toBe(false);
    const frameEl = root.locator('iframe.ml-frame');
    await expect(frameEl).toHaveAttribute('sandbox', 'allow-same-origin allow-popups allow-popups-to-escape-sandbox');
    const frame = page.frameLocator('iframe.ml-frame');
    await expect(frame.locator('body')).toContainText('Sehr geehrte Kundin');
    await expect(frame.locator('img[data-gc-blocked]').first()).toBeAttached();
    // the embedded (cid:) picture loads through gcmail:
    await expect.poll(() => frame.locator('img[src^="gcmail://cid/"]').evaluate((img) => img.complete && img.naturalWidth)).toBe(1);
    await page.screenshot({ path: test.info().outputPath('mail-read.png') });

    // "Bilder laden": the proxied picture comes through gcmail: with the client's sign-in
    await root.locator('.ml-banner.is-info .btn-sec').click();
    await expect.poll(() => frame.locator('img[src="gcmail://img/tok_logo"]').evaluate((img) => img.complete && img.naturalWidth)).toBe(1);
    expect(m.srv.state.requests.some((r) => r.path.endsWith('/api/img/tok_logo'))).toBe(true);
    // no scripts in the frame, never a request to the internet
    expect(await frame.locator('body').evaluate(() => typeof window.gatecontrol)).toBe('undefined');

    // In Drive speichern with the suggestion
    await root.locator('.ml-att .btn-pri').first().click();
    await expect(root.locator('.ml-att-saved')).toContainText('Finanzen › Strom');

    // archive from the reading pane: gone from the list, on the server in the archive
    await root.locator('.ml-read-bar .ml-ib').first().click();
    await expect(row(root, 101)).toHaveCount(0);
    expect(m.srv.state.messages.get(101).folderId).toBe(14);
  });

  test('writing: recipients, send with "Rückgängig", the draft comes back', async ({ launchApp, mock }) => {
    const m = await mock.setMail();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openMail(page);
    await root.locator('.ml-new').click();
    const to = root.locator('.ml-rcpt-in').first();
    await to.fill('tim');
    await expect(root.locator('.ml-sug-row')).toHaveCount(1);
    await root.locator('.ml-sug-row').click();
    await expect(root.locator('.ml-rcpt')).toHaveText(['Tim Brandt']);
    await root.locator('.ml-subj-in').fill('Angebot Kunde Müller');
    const editor = page.frameLocator('iframe.ml-editor');
    await editor.locator('p').first().click();
    await editor.locator('body').pressSequentially('Hallo Tim, anbei das Angebot.');
    await expect(root.locator('iframe.ml-editor')).toHaveAttribute('sandbox', 'allow-same-origin');
    await page.screenshot({ path: test.info().outputPath('mail-compose.png') });
    await root.locator('.ml-split .btn-pri').first().click();
    const undo = page.locator('.ml-undo');
    await expect(undo).toBeVisible();
    await expect.poll(() => m.srv.state.outbox.size).toBe(1);
    const draft = [...m.srv.state.drafts.values()].pop();
    expect(draft.subject).toBe('Angebot Kunde Müller');
    expect(draft.to).toEqual([{ name: 'Tim Brandt', email: 'tim@firma.de' }]);
    expect(draft.html).toContain('Hallo Tim, anbei das Angebot.');
    // "Rückgängig": nothing is sent, the draft opens again
    await undo.locator('.btn').click();
    await expect.poll(() => m.srv.state.outbox.size).toBe(0);
    await expect(root.locator('.ml-subj-in')).toHaveValue('Angebot Kunde Müller');
    await expect(undo).toBeHidden();
  });

  test('Microsoft account: a file of this PC blocks sending with a hint; a body not on the server yet', async ({ launchApp, mock }, testInfo) => {
    const m = await mock.setMail();
    const { page, answerOpenDialogs } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openMail(page);
    // a mail whose body the server does not have: the note and "Erneut versuchen" instead of the frame
    await root.locator('.ml-chip', { hasText: 'Firma · M365' }).click();
    await row(root, 105).click();
    await expect(root.locator('.ml-read .ml-banner.is-info')).toBeVisible();
    await expect(root.locator('iframe.ml-frame')).toHaveCount(0);

    await root.locator('.ml-new').click();
    await root.locator('select.ml-from').selectOption('2');
    await root.locator('.ml-rcpt-in').first().fill('tim@firma.de,');
    await root.locator('.ml-subj-in').fill('Mit Anhang');
    const file = testInfo.outputPath('Angebot.pdf');
    require('fs').writeFileSync(file, '%PDF-1.4 Angebot');
    await answerOpenDialogs([file]);
    await root.locator('.ml-read-bar .btn-sec').first().click();
    await page.locator('.ml-menu-item').first().click();
    await expect(root.locator('.ml-catt-name')).toHaveText(['Angebot.pdf']);
    await expect(root.locator('.ml-cwarn .ml-banner.is-err')).toBeVisible();
    await root.locator('.ml-split .btn-pri').first().click();
    await expect(page.locator('.ml-undo')).toBeHidden();
    expect(m.srv.state.outbox.size).toBe(0);
    // removing the file lifts the block
    await root.locator('.ml-catt .ml-rcpt-x').click();
    await expect(root.locator('.ml-cwarn .ml-banner.is-err')).toHaveCount(0);
  });

  test('Konto hinzufügen: providers, the hint, the refusal; Microsoft in the browser', async ({ launchApp, mock }) => {
    const m = await mock.setMail();
    const { page, events } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openMail(page);
    await root.locator('.ml-side-foot .ml-ib').first().click();
    const dlg = page.locator('.ml-dlg.ml-add');
    await expect(dlg.locator('.ml-prov')).toHaveCount(4);
    await expect(dlg.locator('.ml-prov').first()).toContainText('Microsoft 365');
    await dlg.locator('.ml-prov', { hasText: 'GMX' }).click();
    await expect(dlg.locator('.ml-banner.is-warn')).toContainText(/IMAP/);
    const inputs = dlg.locator('.ml-add-form input.ml-input');
    await inputs.nth(0).fill('neu@gmx.de');
    await inputs.nth(1).fill('falsch');
    await dlg.locator('.ml-add-form .btn-pri').click();
    await expect(dlg.locator('.ml-dlg-err')).toContainText(/Passwort prüfen|Check the password/);
    await page.screenshot({ path: test.info().outputPath('mail-add.png') });

    // Microsoft: the browser gets the authorize URL; its answer reaches the loopback receiver
    await dlg.locator('.ml-prov').first().click();
    await dlg.locator('.ml-add-form .btn-pri').click();
    let url = null;
    await expect.poll(() => { const e = events().find((x) => x.type === 'shell.openExternal'); url = e && e.url; return !!url; }).toBe(true);
    const u = new URL(url);
    expect(u.origin + u.pathname).toBe('https://login.microsoftonline.com/common/oauth2/v2.0/authorize');
    expect(u.searchParams.get('redirect_uri')).toMatch(/^http:\/\/localhost:\d+$/);
    const code = m.srv.issueCode(u.searchParams.get('code_challenge'));
    await new Promise((resolve, reject) => {
      http.get(`${u.searchParams.get('redirect_uri')}/?code=${encodeURIComponent(code)}&state=${encodeURIComponent(u.searchParams.get('state'))}`, (res) => { res.resume(); res.on('end', resolve); }).on('error', reject);
    });
    await expect(dlg).toBeHidden();
    await expect(root.locator('.ml-side .ml-acc')).toHaveCount(3);
    expect(m.srv.state.microsoft[0].redirectUri).toBe(u.searchParams.get('redirect_uri'));
  });
});
