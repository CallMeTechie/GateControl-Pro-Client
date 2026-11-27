'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// The mouse wheel scrolls where the pointer is, without a click first: Mail's menu (the folders), the list and the
// reading pane — also with the pointer over the mail itself (its sandboxed frame, as tall as the mail: the pane
// scrolls, the frame is never squeezed to what is left of the pane) — and the same on "Notizen & Aufgaben".
// The plugins are the core's fakes (support/mail-mock.js, notes-mock.js).

/** The pointer onto `loc` (no click), the wheel down (dy < 0: up); → how far its scroll box moved. */
async function wheelOver(page, loc, box, { dy = 240, at = 0.5 } = {}) {
  const b = await loc.boundingBox();
  const vh = await page.evaluate(() => window.innerHeight);
  const x = b.x + b.width / 2;
  const y = Math.min(b.y + b.height * at, vh - 20);
  await page.mouse.move(x, y);
  const before = await box.evaluate((e) => e.scrollTop);
  await page.mouse.wheel(0, dy);
  await expect.poll(() => box.evaluate((e) => e.scrollTop)).not.toBe(before);
  return Math.sign(dy) * ((await box.evaluate((e) => e.scrollTop)) - before);
}

test.describe('scrolling with the mouse wheel, no click needed', () => {
  test('Mail: the folders, the list, the reading pane (also over the mail itself)', async ({ launchApp, mock }) => {
    const m = await mock.setMail();
    // a long mail, an inbox with many mails and many folders (the menu longer than the window)
    const long = m.srv.state.messages.get(102);
    long.html = Array.from({ length: 150 }, (_, i) => `<p>Absatz ${i + 1} der langen Mail</p>`).join('');
    const base = m.srv.state.messages.get(103);
    for (let i = 0; i < 40; i += 1) m.srv.state.messages.set(600 + i, { ...base, id: 600 + i, threadId: 600 + i, threadCount: 1, subject: `Ältere Mail ${i + 1}`, date: base.date - (i + 1) * 3600000 });
    for (let i = 0; i < 30; i += 1) m.srv.state.folders.push({ id: 400 + i, accountId: 2, name: `Ordner ${i + 1}`, path: `O${i}`, role: null, parentId: null });
    const { app, page } = await launchApp();
    await app.evaluate(({ BrowserWindow }) => { const win = BrowserWindow.getAllWindows()[0]; win.unmaximize(); win.setSize(1280, 720); });
    await setupWithApiKey(page, mock);
    await page.locator('#nav-mail').click();
    const root = page.locator('#page-mail');
    await expect(root.locator('.ml-row[data-id="102"]')).toBeVisible();
    await root.locator('.ml-side .ml-acc').nth(1).locator('.ml-it-acc').click();
    await expect(root.locator('.ml-side .ml-frow')).toHaveCount(33);
    await root.locator('.ml-row[data-id="102"]').click();
    const frame = root.locator('.ml-read iframe.ml-frame');
    await expect(page.frameLocator('.ml-read iframe.ml-frame').locator('body')).toContainText('Absatz 150');
    // the frame keeps the mail's height: the pane is what scrolls
    await expect.poll(() => frame.evaluate((f) => f.getBoundingClientRect().height)).toBeGreaterThan(1500);
    await expect.poll(() => root.locator('.ml-frame-wrap').evaluate((w) => w.getBoundingClientRect().height)).toBeGreaterThan(1500);
    // the pointer somewhere else (the nav), nothing focused in the columns
    await page.locator('#nav-mail').focus();
    const side = root.locator('.ml-side');
    const rows = root.locator('.ml-rows');
    const read = root.locator('.ml-read');
    for (const box of [side, rows, read]) expect(await box.evaluate((e) => e.scrollHeight > e.clientHeight)).toBe(true);

    expect(await wheelOver(page, side.locator('.ml-frow').nth(5), side)).toBeGreaterThan(0);
    expect(await wheelOver(page, rows.locator('.ml-row').first(), rows)).toBeGreaterThan(0);
    expect(await wheelOver(page, root.locator('.ml-read-subj'), read)).toBeGreaterThan(0);
    // over the mail itself (the sandboxed frame): the pane scrolls on
    expect(await wheelOver(page, frame, read, { at: 0.02 })).toBeGreaterThan(0);
    // and back up: the list and the menu still go by the wheel right away
    expect(await wheelOver(page, rows, rows, { dy: -120 })).toBeGreaterThan(0);
    expect(await wheelOver(page, side, side, { dy: -120 })).toBeGreaterThan(0);

    // drawn again (a change from the server — here the refresh button —, the app's theme): each stays where the
    // wheel left it; the open mail is not pulled back into view
    const tops = async () => ({ side: await side.evaluate((e) => e.scrollTop), rows: await rows.evaluate((e) => e.scrollTop), read: await read.evaluate((e) => e.scrollTop) });
    const before = await tops();
    expect(before.side).toBeGreaterThan(0);
    expect(before.rows).toBeGreaterThan(0);
    expect(before.read).toBeGreaterThan(0);
    const mes = () => m.srv.state.requests.filter((r) => r.path.endsWith('/api/me')).length;
    const n = mes();
    await root.locator('.ml-head .ml-ib').click();
    await expect.poll(mes).toBeGreaterThan(n);
    await page.waitForTimeout(1500);
    const after = await tops();
    expect(after.side).toBe(before.side);
    expect(Math.abs(after.rows - before.rows)).toBeLessThanOrEqual(2);
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', document.documentElement.getAttribute('data-theme') || 'dark'));
    await page.waitForTimeout(500);
    expect(Math.abs((await read.evaluate((e) => e.scrollTop)) - before.read)).toBeLessThanOrEqual(2);
  });

  test('Notizen & Aufgaben: the menu and the tasks', async ({ launchApp, mock }) => {
    await mock.setNotes();
    const { app, page } = await launchApp();
    await app.evaluate(({ BrowserWindow }) => { const win = BrowserWindow.getAllWindows()[0]; win.unmaximize(); win.setSize(1100, 600); });
    await setupWithApiKey(page, mock);
    await page.locator('#nav-notizen').click();
    const root = page.locator('#page-notizen');
    await expect(root.locator('.nz-sec').first()).toBeVisible();
    const side = root.locator('.nz-side');
    const main = root.locator('.nz-main');
    await expect.poll(() => main.evaluate((e) => e.scrollHeight > e.clientHeight)).toBe(true);
    expect(await wheelOver(page, main, main, { at: 0.3 })).toBeGreaterThan(0);
    if (await side.evaluate((e) => e.scrollHeight > e.clientHeight)) expect(await wheelOver(page, side, side, { at: 0.3 })).toBeGreaterThan(0);
  });
});
