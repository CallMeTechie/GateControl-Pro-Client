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
//   - „Trennen“ asks (tmux keeps running) and says bye;
//   - Fernzugriff 1.8 (kill: true): sessions open to their windows, „Beenden“, „Schließen“, all detached ones, always
//     with a question (red when someone is connected, the last window), tmux_gone reloads quietly; an older plugin
//     (kill: false) shows none of it.

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
  await expect(detail.locator('[data-kill]')).toHaveCount(0);
  await expect(page.locator('#ssh-kill-all')).toHaveCount(0);
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

test('tmux: end windows and sessions (Fernzugriff 1.8), questions first, quiet reload', async ({ launchApp, mock }) => {
  const term = await mock.setTerm();
  term.srv.tmuxKill = true;
  const { page } = await launchApp();
  await setupWithApiKey(page, mock);
  await openRemote(page);
  await page.locator('#rdp-list [data-ssh="2"]').click();
  const detail = page.locator('#rdp-detail');
  const dlg = page.locator('#ssh-kill-dialog');
  const sess = (id) => detail.locator(`[data-tmux-session="${id}"]`);

  // T1: every session with „Beenden“, the one that cannot be resumed too (instead of being only counted)
  await expect(sess('$2').locator('[data-opt="resume:tmux"]')).toHaveClass(/sel/);
  await expect(sess('$3')).toContainText('backup.alt');
  await expect(sess('$3')).toContainText('nicht fortsetzbar');
  await expect(detail).not.toContainText('weitere Sitzung');
  await expect(page.locator('#ssh-kill-all')).toHaveText('Alle getrennten Sitzungen beenden (2)');

  // the windows: index, name, active, command; „Schließen“ asks (T3)
  await sess('$2').locator('[data-toggle]').click();
  await expect(sess('$2').locator('[data-window]')).toHaveCount(3);
  await expect(sess('$2').locator('[data-window="@3"]')).toContainText('logs');
  await expect(sess('$2').locator('[data-window="@3"]')).toContainText('aktiv');
  await expect(sess('$2').locator('[data-window="@3"]')).toContainText('journalctl');
  await sess('$2').locator('[data-window="@4"] [data-kill="window"]').click();
  await expect(dlg).toBeVisible();
  await expect(page.locator('#ssh-kill-title')).toHaveText('Fenster „htop“ schließen?');
  await expect(page.locator('#ssh-kill-body')).toContainText('Laufende Programme darin werden beendet (gerade: htop).');
  await expect(page.locator('#ssh-kill-body')).toContainText('Die anderen 2 Fenster der Sitzung bleiben.');
  await expect(page.locator('#ssh-kill-ok')).toHaveText('Fenster schließen');
  await page.locator('#ssh-kill-ok').click();
  await expect(dlg).toBeHidden();
  await expect(sess('$2').locator('[data-window]')).toHaveCount(2);
  expect(term.srv.kills[0]).toEqual({ path: 'kill', body: { session: { id: '$2', name: 'tmux', created: 1763380000 }, window: { id: '@4', index: 2 } } });

  // T2: someone is connected → in red, „Trotzdem beenden“; „Abbrechen“ ends nothing
  await sess('$1').locator('[data-kill="session"]').click();
  await expect(page.locator('#ssh-kill-title')).toHaveText('Sitzung „build“ beenden?');
  await expect(page.locator('#ssh-kill-body')).toContainText('Laufende Programme darin werden beendet. Das lässt sich nicht rückgängig machen.');
  await expect(page.locator('#ssh-kill-warn')).toContainText('Gerade ist jemand verbunden');
  await expect(page.locator('#ssh-kill-warn')).toContainText('auf 1 Gerät(en) offen');
  await expect(page.locator('#ssh-kill-ok')).toHaveText('Trotzdem beenden');
  await page.locator('#ssh-kill-cancel').click();
  await expect(dlg).toBeHidden();
  expect(term.srv.kills.length).toBe(1);

  // T4: all detached ones, the list to untick; the attached one is named as kept
  await page.locator('#ssh-kill-all').click();
  await expect(page.locator('#ssh-kill-title')).toHaveText('2 getrennte Sitzungen beenden?');
  await expect(page.locator('#ssh-kill-body')).toContainText('Gerade verbunden und bleibt: „build“.');
  await expect(page.locator('#ssh-kill-body input[type="checkbox"]')).toHaveCount(2);
  await expect(page.locator('#ssh-kill-ok')).toHaveText('2 Sitzungen beenden');
  await page.locator('#ssh-kill-body input[value="$3"]').uncheck();
  await expect(page.locator('#ssh-kill-ok')).toHaveText('1 Sitzung beenden');
  await page.locator('#ssh-kill-ok').click();
  await expect(sess('$2')).toHaveCount(0);
  expect(term.srv.kills[1]).toEqual({ path: 'kill-detached', body: { sessions: [{ id: '$2', name: 'tmux', created: 1763380000 }] } });
  await expect(page.locator('#ssh-kill-all')).toHaveCount(0);

  // gone on the device meanwhile: tmux_gone → the list again, nothing in red
  term.srv.tmuxSessions = term.srv.tmuxSessions.filter((x) => x.id !== '$3');
  await sess('$3').locator('[data-kill="session"]').click();
  await expect(page.locator('#ssh-kill-title')).toHaveText('Sitzung „backup.alt“ beenden?');
  await expect(page.locator('#ssh-kill-ok')).toHaveText('Sitzung beenden');
  await page.locator('#ssh-kill-ok').click();
  await expect(sess('$3')).toHaveCount(0);
  await expect(detail.locator('.note-err')).toHaveCount(0);

  // the last window of a session ends the whole session
  await sess('$1').locator('[data-toggle]').click();
  await sess('$1').locator('[data-window="@1"] [data-kill="window"]').click();
  await expect(page.locator('#ssh-kill-body')).toContainText('Das ist das letzte Fenster. Damit endet die ganze Sitzung.');
  await expect(page.locator('#ssh-kill-warn')).toBeVisible();
  await page.locator('#ssh-kill-ok').click();
  await expect(sess('$1')).toHaveCount(0);
  await expect(detail.locator('[data-opt="default"]')).toHaveClass(/sel/);
});
