'use strict';

// "Mit Firmenkonto anmelden" in the setup assistant (core signin:*, GateControl
// ≥ 1.201.0): the entry appears only when the server offers it; password (+ 2FA)
// and Microsoft (browser + loopback + handoff with PKCE) both end with a setup
// code that the app redeems at /api/v1/client/enroll like a typed code.

const fs = require('fs');
const path = require('path');
const http = require('http');
const { test, expect } = require('./support/fixtures');

const SECRET = 'Sommer-2026!';

function get(url) {
  return new Promise((resolve, reject) => {
    http.get(url, { agent: false }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    }).on('error', reject);
  });
}

function enrollCodes(mock) {
  return mock.requests.filter((r) => r.path === '/api/v1/client/enroll').map((r) => JSON.parse(r.raw.toString('utf8')).code);
}

/** No file the app wrote (logs, events, store) contains the secret. */
function assertNotWritten(dir, secrets) {
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(d, e.name);
    if (e.isDirectory()) return walk(p);
    return e.isFile() ? [p] : []; // skips Chromium's Singleton* symlinks
  });
  for (const file of walk(dir)) {
    const text = fs.readFileSync(file).toString('latin1');
    for (const s of secrets) expect(text.includes(s), `${s} in ${file}`).toBe(false);
  }
}

async function openCodeStep(page, mock) {
  await expect(page.locator('#page-setup')).toHaveClass(/active/);
  await page.locator('#setup-opt-code').click();
  await page.locator('#setup-url').fill(mock.url);
}

test.describe('company sign-in', () => {
  test('older server (404): only the setup code', async ({ launchApp, mock }) => {
    const { page } = await launchApp();
    await openCodeStep(page, mock);
    await expect.poll(() => mock.count('/api/v1/client/signin')).toBeGreaterThanOrEqual(1);
    await page.waitForTimeout(500);
    await expect(page.locator('#setup-signin-entry')).toBeHidden();
    await expect(page.locator('#setup-key')).toBeVisible();
  });

  test('password with 2FA sets the device up through the setup-code path', async ({ launchApp, mock }) => {
    const signin = mock.setSignin({ totp: '246810' });
    const { page, dir } = await launchApp();
    await openCodeStep(page, mock);

    await expect(page.locator('#setup-signin-entry')).toBeVisible();
    await page.locator('#setup-opt-signin').click();
    await expect(page.locator('#setup-signin')).toHaveClass(/active/);
    await expect(page.locator('#setup-signin-hint')).toHaveText('Firmenkonto (corp.local): mit dem Windows-Passwort anmelden');
    await expect(page.locator('#setup-signin-ms .opt')).toHaveCount(1);
    await expect(page.locator('#setup-signin-ms .opt-desc')).toHaveText('Contoso');

    // Wrong password
    await page.locator('#setup-signin-user').fill('anna@corp.local');
    await page.locator('#setup-signin-pass').fill('falsch');
    await page.locator('#setup-signin-submit').click();
    await expect(page.locator('#setup-signin-status')).toHaveClass(/error/);
    await expect(page.locator('#setup-signin-totp-field')).toBeHidden();

    // Right password → 2FA step
    await page.locator('#setup-signin-pass').fill(SECRET);
    await page.locator('#setup-signin-submit').click();
    await expect(page.locator('#setup-signin-totp-field')).toBeVisible();
    await expect(page.locator('#setup-signin-submit')).toBeDisabled();
    await page.locator('#setup-signin-totp').fill('246810');
    await page.locator('#setup-signin-totp').press('Enter');

    await expect(page.locator('#setup-done')).toHaveClass(/active/);
    expect(signin.issued).toHaveLength(1);
    expect(enrollCodes(mock)).toEqual(signin.issued);
    expect(signin.attempts.map((a) => a.totp)).toEqual([null, null, '246810']);
    expect(signin.attempts[0].hostname).toBeTruthy();
    expect(await page.locator('#setup-signin-pass').inputValue()).toBe('');

    await page.locator('#setup-later').click();
    await expect(page.locator('#page-status')).toHaveClass(/active/);
    assertNotWritten(dir, [SECRET, '246810', signin.issued[0]]);
  });

  test('Mit Microsoft anmelden: default browser, loopback answer, handoff', async ({ launchApp, mock }) => {
    const signin = mock.setSignin({ password: { enabled: false, hint: null }, microsoft: [{ id: 7, label: 'Contoso' }, { id: 9, label: 'Fabrikam' }] });
    const { page, events, dir } = await launchApp();
    await openCodeStep(page, mock);
    await page.locator('#setup-opt-signin').click();
    await expect(page.locator('#setup-signin-user-field')).toBeHidden();
    await expect(page.locator('#setup-signin-submit')).toBeHidden();
    await expect(page.locator('#setup-signin-ms .opt')).toHaveCount(2);

    await page.locator('#setup-signin-ms .opt').nth(1).click();
    await expect(page.locator('#setup-signin-cancel')).toBeVisible();
    const opened = () => events().filter((e) => e.type === 'shell.openExternal').map((e) => e.url);
    await expect.poll(() => opened().length).toBe(1);
    const start = new URL(opened()[0]);
    expect(`${start.origin}${start.pathname}`).toBe(`${mock.url}/auth/oidc/9/start`);
    const q = Object.fromEntries(start.searchParams);
    expect(q.client).toBe('app');
    expect(q.redirect_uri).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/signin$/);

    // The server after the Microsoft sign-in: redirect back with handoff + state.
    const handoff = signin.issueHandoff(q.challenge);
    const back = new URL(q.redirect_uri);
    back.searchParams.set('handoff', handoff);
    back.searchParams.set('state', q.state);
    const res = await get(back.toString());
    expect(res.status).toBe(200);
    expect(res.body).toContain('Anmeldung abgeschlossen – du kannst dieses Fenster schließen.');

    await expect(page.locator('#setup-done')).toHaveClass(/active/);
    expect(enrollCodes(mock)).toEqual(signin.issued);
    expect(mock.count('/api/v1/client/signin/handoff')).toBe(1);
    // The receiver took exactly one answer.
    await expect(get(back.toString())).rejects.toThrow();
    assertNotWritten(dir, [handoff, signin.issued[0]]);
  });

  test('Microsoft: a foreign state is refused, cancel ends the wait', async ({ launchApp, mock }) => {
    mock.setSignin();
    const { page, events } = await launchApp();
    await openCodeStep(page, mock);
    await page.locator('#setup-opt-signin').click();

    const opened = () => events().filter((e) => e.type === 'shell.openExternal').map((e) => e.url);
    await page.locator('#setup-signin-ms .opt').first().click();
    await expect.poll(() => opened().length).toBe(1);
    const q = Object.fromEntries(new URL(opened()[0]).searchParams);
    const res = await get(`${q.redirect_uri}?handoff=abc&state=not-the-state`);
    expect(res.status).toBe(400);
    await expect(page.locator('#setup-signin-status')).toHaveClass(/error/);
    expect(mock.count('/api/v1/client/signin/handoff')).toBe(0);

    // Second attempt, cancelled in the app.
    await page.locator('#setup-signin-ms .opt').first().click();
    await expect.poll(() => opened().length).toBe(2);
    await page.locator('#setup-signin-cancel').click();
    await expect(page.locator('#setup-signin-cancel')).toBeHidden();
    await expect(page.locator('#setup-signin-status')).toBeHidden();
    const q2 = Object.fromEntries(new URL(opened()[1]).searchParams);
    await expect(get(`${q2.redirect_uri}?handoff=abc&state=${q2.state}`)).rejects.toThrow();
    await expect(page.locator('#setup-signin')).toHaveClass(/active/);
  });
});
