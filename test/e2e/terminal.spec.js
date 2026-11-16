'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Fernzugriff stage 3 — the SSH terminal (the plugin, the core's term-token and the WebSocket gc-term.v1 are the
// core's test server, support/term-mock.js):
//   - the page is called „Fernzugriff“; SSH devices with the marks SSH / „Nur Browser“ (engine guac);
//   - details: the tmux sessions, the most recently active preselected, the name that cannot be attached counted;
//   - „Fortsetzen“ opens the terminal window (xterm.js from the app, CSP default-src 'self' without a violation):
//     the token only in the subprotocol, hello, output in the terminal, typing goes out, the sidebar lists it;
//   - recording switched on: the hint in the terminal window first, record: true only after „Verstanden, verbinden“;
//   - „Trennen“ asks (tmux keeps running) and says bye.

async function openRemote(page) {
  // the texts below are German (the main process resolves those of the terminal window, too)
  await page.evaluate(() => window.gatecontrol.locale.set('de'));
  await page.locator('#nav-rdp').click();
  await expect(page.locator('#page-rdp')).toHaveClass(/active/);
  await expect(page.locator('#nav-rdp')).toContainText('Fernzugriff');
}

async function terminalWindow(app, page, click) {
  const [win] = await Promise.all([app.waitForEvent('window'), click()]);
  await win.waitForLoadState('domcontentloaded');
  return win;
}

test('SSH devices, tmux choice, terminal window with xterm.js, typing, sidebar, bye', async ({ launchApp, mock }) => {
  const term = await mock.setTerm();
  const { app, page } = await launchApp();
  await setupWithApiKey(page, mock);
  await openRemote(page);

  const pi = page.locator('#rdp-list [data-ssh="2"]');
  await expect(pi).toContainText('pi-werkstatt');
  await expect(pi).toContainText('SSH');
  await expect(page.locator('#rdp-list [data-ssh="3"]')).toContainText('Nur Browser');

  await pi.click();
  const detail = page.locator('#rdp-detail');
  await expect(detail.locator('[data-opt="resume:tmux"]')).toHaveClass(/sel/);
  await expect(detail.locator('[data-opt="resume:build"]')).toContainText('angehängt');
  await expect(detail).toContainText('1 weitere Sitzung');
  await expect(page.locator('#ssh-connect')).toContainText('Fortsetzen');

  const csp = [];
  const win = await terminalWindow(app, page, () => page.locator('#ssh-connect').click());
  win.on('console', (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) csp.push(m.text()); });
  await expect(win.locator('#st-state')).toHaveText('Verbunden');
  await expect(win.locator('.tab.on')).toContainText('pi-werkstatt · tmux');

  expect(term.srv.connects[0]).toEqual({ via: 'app', protocol: 'ssh', tmux: { attach: 'tmux' }, record: false });
  expect(term.srv.urls[0]).toBe('/api/v1/remote/ssh-tunnel');
  expect(term.srv.protocols[0][0]).toBe('gc-term.v1');
  expect(term.srv.protocols[0][1]).toMatch(/^token\.T1/);
  expect(term.srv.received[0]).toMatchObject({ t: 'hello', term: 'xterm-256color' });

  term.srv.sockets[0].send(Buffer.from('pi@pi-werkstatt:~ $ '));
  await expect(win.locator('.xterm-rows')).toContainText('pi@pi-werkstatt:~ $');
  // the styles of xterm's DOM renderer arrived (constructed style sheets instead of <style> under the CSP)
  const display = await win.locator('.xterm-rows span').first().evaluate((e) => getComputedStyle(e).display);
  expect(display).toBe('inline-block');

  await win.locator('.xterm-helper-textarea').focus();
  await win.keyboard.type('ls');
  await win.keyboard.press('Enter');
  await expect.poll(() => term.srv.received.filter((m) => m.bin).map((m) => m.bin).join('')).toContain('ls\r');

  // the main window's sidebar lists the session
  await expect(page.locator('#side-sessions-list [data-term]')).toContainText('pi-werkstatt');

  // „Trennen“: asks (tmux keeps running), then bye
  await win.locator('#btn-disconnect').click();
  await expect(win.locator('#dlg-title')).toHaveText('Verbindung trennen?');
  await expect(win.locator('#dlg-body')).toContainText('läuft auf pi-werkstatt weiter');
  const closed = win.waitForEvent('close');
  await win.locator('#leave-ok').click();
  await closed;
  await expect.poll(() => term.srv.received.some((m) => m.t === 'bye')).toBe(true);
  expect(csp).toEqual([]);
});

test('recording switched on: the hint in the terminal window before the ticket', async ({ launchApp, mock }) => {
  const term = await mock.setTerm();
  const { app, page } = await launchApp();
  await setupWithApiKey(page, mock);
  await openRemote(page);
  await page.locator('#rdp-list [data-ssh="2"]').click();
  await page.locator('#rdp-detail [data-opt="new"]').click();
  await expect(page.locator('#ssh-new-name')).toHaveValue('tmux-2');
  await page.locator('#ssh-new-name').fill('bad.name');
  await expect(page.locator('#ssh-connect')).toBeDisabled();
  await page.locator('#ssh-new-name').fill('werk');
  await page.locator('#ssh-record').click();

  const win = await terminalWindow(app, page, () => page.locator('#ssh-connect').click());
  await expect(win.locator('#dlg-title')).toHaveText('Diese Sitzung wird aufgezeichnet');
  expect(term.srv.connects.length).toBe(0);
  await win.locator('#rec-ok').click();
  await expect(win.locator('#st-state')).toHaveText('Verbunden');
  expect(term.srv.connects[0]).toEqual({ via: 'app', protocol: 'ssh', tmux: { create: 'werk' }, record: true });
});
