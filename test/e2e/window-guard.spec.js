'use strict';

// Window guard (core utils/window-guard, installed in main.js for every
// webContents): a page cannot navigate the app window away from the app's
// own files or open a new Electron window. http(s) links go to the system
// browser (shell.openExternal, recorded by the e2e hooks), everything else is
// blocked, and the window keeps running.

const { test, expect } = require('./support/fixtures');

test.describe('window guard', () => {
  test('navigation away from the app is blocked, the window keeps running', async ({ launchApp }) => {
    const { app, page, events } = await launchApp();
    const opened = () => events().filter((e) => e.type === 'shell.openExternal').map((e) => e.url);

    await expect(page.locator('.page.active').first()).toBeVisible();
    const startUrl = page.url();
    expect(startUrl).toMatch(/^file:\/\/.*\/renderer\/index\.html/);

    // Every webContents of the app carries the guard (main window and any other window).
    expect(await app.evaluate(({ webContents }) => webContents.getAllWebContents().every((wc) => wc.__gcWindowGuard === true))).toBe(true);

    // http(s): the app window stays, the link opens in the system browser.
    await page.evaluate(() => { window.location.href = 'https://example.com/e2e-navigate'; });
    await expect.poll(opened).toContain('https://example.com/e2e-navigate');
    expect(page.url()).toBe(startUrl);

    // Files outside the app: blocked, nothing opened.
    await page.evaluate(() => { window.location.href = 'file:///C:/Windows/win.ini'; });

    // window.open and target=_blank: no new window, http(s) to the browser.
    expect(await page.evaluate(() => window.open('https://example.com/e2e-popup') === null)).toBe(true);
    expect(await page.evaluate(() => window.open('file:///C:/Windows/System32/calc.exe') === null)).toBe(true);
    await page.evaluate(() => {
      const a = document.createElement('a');
      a.href = 'https://example.com/e2e-blank';
      a.target = '_blank';
      document.body.appendChild(a);
      a.click();
      a.remove();
    });
    await expect.poll(opened).toContain('https://example.com/e2e-popup');
    await expect.poll(opened).toContain('https://example.com/e2e-blank');

    // Plain link in the page: not followed inside the app window.
    await page.evaluate(() => {
      const a = document.createElement('a');
      a.href = 'https://example.com/e2e-link';
      document.body.appendChild(a);
      a.click();
      a.remove();
    });
    await expect.poll(opened).toContain('https://example.com/e2e-link');

    // The window is still the app: same page, not loading, one window.
    // (Playwright's locators would wait for the cancelled navigations to
    // "finish", so the state is read from Electron and the DOM directly.)
    await page.waitForTimeout(500);
    const state = await app.evaluate(({ BrowserWindow }) => {
      const wins = BrowserWindow.getAllWindows().filter((w) => !w.isDestroyed());
      const wc = wins[0].webContents;
      return { windows: wins.length, url: wc.getURL(), loading: wc.isLoading(), crashed: wc.isCrashed() };
    });
    expect(state).toEqual({ windows: 1, url: startUrl, loading: false, crashed: false });

    // ...and it still reacts: leave the setup assistant (Pro, first start), open Settings.
    const activeAfterClick = await page.evaluate(async () => {
      document.querySelector('#setup-cancel')?.click();
      await new Promise((r) => setTimeout(r, 300));
      document.querySelector('button[data-page="settings"]').click();
      await new Promise((r) => setTimeout(r, 300));
      return document.querySelector('.page.active')?.id;
    });
    expect(activeAfterClick).toBe('page-settings');
    // Only the http(s) URLs were handed to the system browser.
    expect(opened().filter((u) => !u.startsWith('https://example.com/e2e-'))).toEqual([]);
  });
});
