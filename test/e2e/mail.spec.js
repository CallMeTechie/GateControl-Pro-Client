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

  test('reading: a wide newsletter fits, the menu\'s folders fold, the conversation, the sender\'s page', async ({ launchApp, mock }) => {
    const m = await mock.setMail();
    // a newsletter with a fixed width (as IONOS sends it): wider than the pane
    m.srv.state.messages.get(104).html = '<div style="width:760px;background:#EEF1F5"><p>Newsletter mit fester Breite</p></div><table width="600"><tr><td width="600">Angebot</td></tr></table>';
    const { app, page } = await launchApp();
    // a window wide enough for a reading pane (the CI's default one leaves it ~160 px)
    await app.evaluate(({ BrowserWindow }) => { const win = BrowserWindow.getAllWindows()[0]; win.unmaximize(); win.setSize(1440, 900); });
    await setupWithApiKey(page, mock);
    const root = await openMail(page);

    // menu: a tap on the account opens its folders (Posteingang first), another closes them; each account for itself
    const firma = root.locator('.ml-side .ml-acc').nth(1).locator('.ml-it-acc');
    await expect(firma).toHaveAttribute('aria-expanded', 'false');
    await expect(root.locator('.ml-side .ml-it.sub')).toHaveCount(0);
    await firma.click();
    await expect(firma).toHaveAttribute('aria-expanded', 'true');
    await expect(root.locator('.ml-side .ml-it.sub').first()).toContainText(/Posteingang|Inbox/);
    await expect(root.locator('.ml-side .ml-it.sub')).toHaveCount(3);
    await firma.click();
    await expect(firma).toHaveAttribute('aria-expanded', 'false');
    await expect(root.locator('.ml-side .ml-it.sub')).toHaveCount(0);
    // the inbox from the tree: shown, the tree stays as it was
    await firma.click();
    await root.locator('.ml-side .ml-it.sub').first().click();
    await expect(row(root, 102)).toBeVisible();
    await expect(firma).toHaveAttribute('aria-expanded', 'true');
    await firma.click();
    await expect(firma).toHaveAttribute('aria-expanded', 'false', { timeout: 5000 });

    // the conversation: its line with the sender; a tap shows the older mail above this one, unfolding
    await row(root, 102).click();
    const conv = root.locator('.ml-conv');
    await expect(conv).toContainText('2');
    await expect(conv).toContainText('Sabine Keller');
    await expect(root.locator('.ml-thread')).toHaveCount(0);
    await conv.click();
    await expect(conv).toHaveAttribute('aria-expanded', 'true');
    await expect(root.locator('.ml-thread')).toHaveCount(1);
    await expect(root.locator('.ml-thread')).toHaveAttribute('data-id', '103');
    expect(await root.locator('.ml-thread').evaluate((card) => !!(card.compareDocumentPosition(document.querySelector('#page-mail .ml-read-from')) & Node.DOCUMENT_POSITION_FOLLOWING))).toBe(true);
    await root.locator('.ml-thread summary').click();
    await expect(page.frameLocator('.ml-thread iframe.ml-frame').locator('body')).toContainText('Hallo');
    await expect(root.locator('.ml-thread .ml-thread-foot .btn')).toBeVisible();
    expect(m.srv.state.requests.filter((r) => r.path.endsWith('/api/threads/900')).length).toBe(1);
    await conv.click();
    await expect(root.locator('.ml-thread')).toHaveCount(0);

    // the newsletter fits the pane: #gc-fit set smaller, nothing to scroll sideways, no script in the frame
    await root.locator('.ml-chip').first().click();
    await root.locator('.ml-tab').nth(1).click();
    await row(root, 104).click();
    const frame = page.frameLocator('.ml-frame-wrap iframe.ml-frame');
    await expect(frame.locator('body')).toContainText('Newsletter mit fester Breite');
    await expect.poll(() => frame.locator('#gc-fit').evaluate((b) => Number(b.style.zoom || 1))).toBeLessThan(1);
    const widths = await frame.locator('html').evaluate((h) => ({ scroll: h.scrollWidth, client: h.clientWidth, zoom: Number(h.ownerDocument.getElementById('gc-fit').style.zoom) }));
    // 760 px + the margins fit any pane of at least 222 px (zoom ≥ 25 %); a narrower one keeps the smallest zoom
    if (widths.client >= 230) expect(widths.scroll, JSON.stringify(widths)).toBeLessThanOrEqual(widths.client + 1);
    else expect(widths.zoom, JSON.stringify(widths)).toBe(0.25);
    expect(widths.zoom, JSON.stringify(widths)).toBeCloseTo(Math.max(0.25, Math.floor(((widths.client - 32) / 760) * 1000) / 1000), 1);
    expect(await frame.locator('body').evaluate(() => typeof window.gatecontrol)).toBe('undefined');
    await page.screenshot({ path: test.info().outputPath('mail-wide.png') });

    // the sender's page: name, address, "Mail schreiben", "Adresse kopieren", their mails in the account
    await root.locator('.ml-read-sender').click();
    await expect(root.locator('.ml-sender-name')).toHaveText('Elektromarkt');
    await expect(root.locator('.ml-sender-mail')).toHaveText('news@elektromarkt.de');
    await expect(root.locator('.ml-sender-rows .ml-row')).toHaveCount(1);
    const asked = m.srv.state.requests.filter((r) => r.path.endsWith('/api/search')).pop();
    expect(asked.query.from).toBe('news@elektromarkt.de');
    expect(asked.query.box).toBe('1');
    await expect(root.locator('.ml-sender-acts .btn')).toHaveCount(2);
    await page.screenshot({ path: test.info().outputPath('mail-sender.png') });
    await root.locator('.ml-sender-acts .btn-pri').click();
    await expect(root.locator('.ml-rcpt')).toHaveText(['Elektromarkt']);
  });

  test('a light mail in the dark app: shown dark, the sun shows it light, the setting and the light app keep it light', async ({ launchApp, mock }) => {
    const m = await mock.setMail();
    // a light newsletter: white table, black text, a red button with white text and a picture
    m.srv.state.messages.get(104).html = '<table bgcolor="#FFFFFF" width="100%"><tr><td id="cell" style="background:#FFFFFF;color:#000000">'
      + '<p id="txt">Heller Newsletter</p><a id="btn" style="background:#E30613;color:#FFFFFF" href="https://shop.example/">Zum Angebot</a>'
      + '<img id="pic" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="></td></tr></table>';
    const { app, page } = await launchApp();
    await app.evaluate(({ BrowserWindow }) => { const win = BrowserWindow.getAllWindows()[0]; win.unmaximize(); win.setSize(1440, 900); });
    await setupWithApiKey(page, mock);
    const root = await openMail(page);
    // the app is dark (its default)
    await page.evaluate(() => document.documentElement.removeAttribute('data-theme'));
    await root.locator('.ml-tab').nth(1).click();
    await row(root, 104).click();
    const frame = page.frameLocator('.ml-frame-wrap iframe.ml-frame');
    const look = () => frame.locator('#cell').evaluate((td) => {
      const css = (el, k) => el.ownerDocument.defaultView.getComputedStyle(el)[k];
      const d = td.ownerDocument;
      return { body: css(d.body, 'backgroundColor'), cell: css(td, 'backgroundColor'), text: css(d.getElementById('txt'), 'color'), btn: css(d.getElementById('btn'), 'backgroundColor'), btnText: css(d.getElementById('btn'), 'color'), pic: d.getElementById('pic').getAttribute('style'), scheme: css(d.documentElement, 'colorScheme') };
    });
    await expect(frame.locator('#txt')).toHaveText('Heller Newsletter');
    // dark: the page and the white cell the app's panel, black text light, the red button and the picture as they were
    await expect.poll(async () => (await look()).cell).toBe('rgb(22, 27, 34)');
    let l = await look();
    expect(l.body).toBe('rgb(22, 27, 34)');
    expect(l.text).toBe('rgb(230, 234, 240)');
    expect(l.btn).toBe('rgb(227, 6, 19)');
    expect(l.btnText).toBe('rgb(255, 255, 255)');
    expect(l.pic).toBeNull();
    expect(l.scheme).toBe('dark');
    await expect(root.locator('.ml-frame-wrap')).toHaveClass(/is-dark/);
    expect(await frame.locator('body').evaluate(() => typeof window.gatecontrol)).toBe('undefined');
    await page.screenshot({ path: test.info().outputPath('mail-dark.png') });

    // "Hell anzeigen": this mail as it was made
    const sun = root.locator('.ml-read-bar button[title="Hell anzeigen"], .ml-read-bar button[title="Show light"]');
    await expect(sun).toHaveCount(1);
    await sun.click();
    await expect.poll(async () => (await look()).cell).toBe('rgb(255, 255, 255)');
    l = await look();
    expect(l.text).toBe('rgb(0, 0, 0)');
    expect(l.scheme).toBe('light');
    await expect(root.locator('.ml-frame-wrap')).not.toHaveClass(/is-dark/);
    await page.screenshot({ path: test.info().outputPath('mail-dark-shown-light.png') });
    // the moon: dark again
    await root.locator('.ml-read-bar button[title="Dunkel anzeigen"], .ml-read-bar button[title="Show dark"]').click();
    await expect.poll(async () => (await look()).cell).toBe('rgb(22, 27, 34)');

    // another mail starts dark again; the light app shows mails light without the sun
    await root.locator('.ml-tab').nth(0).click();
    await row(root, 101).click();
    await expect(root.locator('.ml-frame-wrap')).toHaveClass(/is-dark/);
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'));
    await expect(root.locator('.ml-frame-wrap')).not.toHaveClass(/is-dark/);
    await expect(sun).toHaveCount(0);
    await page.evaluate(() => document.documentElement.removeAttribute('data-theme'));
    await expect(root.locator('.ml-frame-wrap')).toHaveClass(/is-dark/);

    // "Mails dunkel darstellen" off: light in the dark app too, no sun
    await root.locator('button[title="Mail-Einstellungen"], button[title="Mail settings"]').first().click();
    const setting = page.locator('.ml-dlg [role="switch"][aria-label="Mails dunkel darstellen"], .ml-dlg [role="switch"][aria-label="Show mails dark"]');
    await expect(setting).toHaveAttribute('aria-checked', 'true');
    await setting.click();
    await expect(setting).toHaveAttribute('aria-checked', 'false');
    await page.keyboard.press('Escape');
    await expect(root.locator('.ml-frame-wrap')).not.toHaveClass(/is-dark/);
    await expect(sun).toHaveCount(0);
    // kept on this PC
    expect(await page.evaluate(() => localStorage.getItem('gc.mail.darkMails'))).toBe('0');
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
    // a mail whose body the provider has not sent yet (Mail 1.1.2): the note, "Erneut versuchen" and the snippet
    await root.locator('.ml-chip', { hasText: 'Firma · M365' }).click();
    await row(root, 105).click();
    const note = root.locator('.ml-read .ml-banner.is-info');
    await expect(note).toBeVisible();
    await expect(page.frameLocator('iframe.ml-frame').locator('body')).toContainText('Inhalt fehlt');
    // the body has come: "Erneut versuchen" shows it, the note goes
    m.srv.state.messages.get(105).bodyMissing = false;
    m.srv.state.messages.get(105).text = 'Hier sind die alten Unterlagen.';
    await note.getByRole('button').click();
    await expect(page.frameLocator('iframe.ml-frame').locator('body')).toContainText('Hier sind die alten Unterlagen.');
    await expect(note).toHaveCount(0);

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
