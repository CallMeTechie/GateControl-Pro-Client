'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// The dividers between the columns (gc-split.js): Mitteilungen (the list 40 % of the page, 380–520 px) and
// Notizen & Aufgaben (the menu, the details 460 px, 520 px while a note is open). Hover shows the grip and the tip,
// dragging the size in px (yellow and stopped at a limit), a double click and Eingabe the standard, the arrow keys
// 16 px (Umschalt 64), Pos1 / Ende the least / most. Kept on this PC (gc.layout.*); a narrower window only limits
// what is shown. Screenshots with GC_E2E_SHOTS=<dir>.

const SHOTS = process.env.GC_E2E_SHOTS || null;
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` }); };
const setSize = (app, w, h) => app.evaluate(({ BrowserWindow }, s) => { const win = BrowserWindow.getAllWindows()[0]; win.unmaximize(); win.setSize(s.w, s.h); }, { w, h });
const width = (loc) => loc.evaluate((n) => Math.round(n.getBoundingClientRect().width));
const stored = (page, name) => page.evaluate((k) => JSON.parse(localStorage.getItem(`gc.layout.${k}`) || 'null'), name);

/** Drags a divider by dx (px) and holds it: → a function that lets go. */
async function dragBy(page, split, dx, dy = 0) {
  const b = await split.boundingBox();
  const x = b.x + b.width / 2;
  const y = b.y + b.height / 2;
  await page.mouse.move(x, y);
  await page.mouse.down();
  await page.mouse.move(x + dx / 2, y + dy / 2, { steps: 4 });
  await page.mouse.move(x + dx, y + dy, { steps: 4 });
  return () => page.mouse.up();
}

test.describe('layout dividers', () => {
  test('Mitteilungen: 40 % by default, dragged, limited, double click and keyboard, kept per PC', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [{ id: 'security', label: 'Sicherheit' }], items: [
      { id: 1, topic: 'security', priority: 'high', title: '4 IPs durch WAF gesperrt', body: 'Wiederholte Anmeldeversuche auf das Portal.\n\nDie Adressen bleiben 24 Stunden gesperrt.' },
      { id: 2, topic: 'security', title: 'Neue Anmeldung', body: 'Ein neues Gerät hat sich angemeldet.' },
    ] });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setSize(app, 1440, 900);
    await expect.poll(() => page.evaluate(() => window.innerWidth)).toBe(1440);
    await page.locator('#nav-inbox').click();
    await expect(page.locator('#page-inbox')).toHaveClass(/active/);
    const list = page.locator('#page-inbox > .rdp-list-col');
    const split = page.locator('#page-inbox > .gc-split');
    await expect(split).toHaveAttribute('role', 'separator');
    await expect(split).toHaveAttribute('aria-orientation', 'vertical');
    await expect(split).toHaveAttribute('aria-label', /^(Breite der Mitteilungsliste|Width of the notification list)$/);
    // 40 % of the page (1440 − 240 nav = 1200 → 480 px)
    await expect.poll(() => width(list)).toBe(480);
    await page.locator('#inbox-list .inbox-row').first().click();
    await expect(page.locator('#inbox-detail .inbox-body')).toBeVisible();
    // the text is kept to a readable line (≤ 720 px)
    expect(await width(page.locator('#inbox-detail'))).toBeLessThanOrEqual(720);

    // hover: the grip and the tip
    await split.hover();
    await expect(split.locator('.gc-grip')).toHaveCSS('opacity', '1');
    await expect(split.locator('.gc-tip')).toBeVisible();
    await expect(split.locator('.gc-tip-main')).toHaveText(/^(Ziehen: Breite ändern|Drag: change the width)$/);

    // dragging: the size in px, the list follows
    let up = await dragBy(page, split, 100);
    await expect(split).toHaveClass(/is-drag/);
    await expect(split.locator('.gc-badge')).toHaveText('580 px');
    await shot(page, 'teiler-mitteilungen-ziehen');
    await up();
    await expect(split).not.toHaveClass(/is-drag/);
    await expect(split.locator('.gc-badge')).toHaveCount(0);
    expect(await width(list)).toBe(580);
    expect(await stored(page, 'inbox')).toEqual({ w: { list: 580 } });

    // past the most: stopped at 640 px, yellow, the badge says so
    up = await dragBy(page, split, 300);
    await expect(split).toHaveClass(/is-limit/);
    await expect(split.locator('.gc-badge')).toHaveText(/^(Höchstbreite|Maximum width) 640 px$/);
    expect(await width(list)).toBe(640);
    await up();
    await expect(split).not.toHaveClass(/is-limit/);

    // a double click: the standard again (nothing stored)
    await split.dblclick();
    await expect.poll(() => width(list)).toBe(480);
    expect(await stored(page, 'inbox')).toBeNull();

    // the keyboard: Tab onto it, ← → 16 px, with Umschalt 64 px, Pos1 / Ende, Eingabe
    await split.focus();
    await page.keyboard.press('ArrowRight');
    expect(await width(list)).toBe(496);
    await expect(split.locator('.gc-badge')).toHaveText('496 px');
    await page.keyboard.press('Shift+ArrowLeft');
    expect(await width(list)).toBe(432);
    await expect(split).toHaveAttribute('aria-valuenow', '432');
    await page.keyboard.press('Home');
    expect(await width(list)).toBe(320);
    await expect(split).toHaveAttribute('aria-valuemin', '320');
    await page.keyboard.press('End');
    expect(await width(list)).toBe(640);
    await expect(split).toHaveAttribute('aria-valuemax', '640');
    await page.keyboard.press('Enter');
    await expect.poll(() => width(list)).toBe(480);
    await page.keyboard.press('Shift+ArrowLeft');
    await page.keyboard.press('Shift+ArrowLeft');
    expect(await width(list)).toBe(352);
    expect(await stored(page, 'inbox')).toEqual({ w: { list: 352 } });

    // a narrower window limits what is shown (the text keeps 420 px), the stored width stays
    await setSize(app, 1000, 680);
    await expect.poll(() => page.evaluate(() => window.innerWidth)).toBe(1000);
    await expect.poll(() => width(list)).toBe(339);
    expect(await width(page.locator('#page-inbox > .rdp-detail-col'))).toBeGreaterThanOrEqual(420);
    expect(await stored(page, 'inbox')).toEqual({ w: { list: 352 } });
    await setSize(app, 1440, 900);
    await expect.poll(() => width(list)).toBe(352);
    for (const th of ['dark', 'light']) {
      await page.evaluate((x) => { if (x === 'light') document.documentElement.setAttribute('data-theme', 'light'); else document.documentElement.removeAttribute('data-theme'); }, th);
      await split.hover();
      await page.waitForTimeout(800);
      await shot(page, `teiler-mitteilungen-${th}`);
    }
  });

  test('Notizen & Aufgaben: the menu and the details dragged, the details wider for a note', async ({ launchApp, mock }) => {
    await mock.setNotes();
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setSize(app, 1440, 900);
    await expect.poll(() => page.evaluate(() => window.innerWidth)).toBe(1440);
    await page.locator('#nav-notizen').click();
    const root = page.locator('#page-notizen');
    await expect(root.locator('.nz-sec').first()).toBeVisible();
    const side = root.locator('.nz-side');
    const detail = root.locator('.nz-detail');
    const splits = root.locator('.nz > .gc-split');
    await expect(splits).toHaveCount(2);
    await expect(splits.nth(0)).toHaveAttribute('data-split', 'notes.w.side');
    await expect(splits.nth(1)).toHaveAttribute('data-split', 'notes.w.detail');
    await expect.poll(() => width(side)).toBe(232);
    await expect.poll(() => width(detail)).toBe(460);

    // a note open: the details 520 px
    await root.locator('.nz-it[data-view="notes"]').click();
    await root.locator('.nz-nc[data-id="41"]').click();
    await expect(detail.locator('.nz-note-h')).toHaveText('Werkstatt Montag');
    await expect.poll(() => width(detail)).toBe(520);

    // the details' divider: dragged to the left makes them wider; the list keeps 360 px
    const up = await dragBy(page, splits.nth(1), -60);
    await expect(splits.nth(1).locator('.gc-badge')).toHaveText('580 px');
    await shot(page, 'teiler-notizen-ziehen');
    await up();
    expect(await width(detail)).toBe(580);
    expect(await stored(page, 'notes')).toEqual({ w: { detail: 580 } });
    const up2 = await dragBy(page, splits.nth(1), -400);
    await expect(splits.nth(1)).toHaveClass(/is-limit/);
    await up2();
    expect(await width(root.locator('.nz-main'))).toBeGreaterThanOrEqual(360);

    // the menu: the keyboard, Pos1 = 190 px
    await splits.nth(0).focus();
    await page.keyboard.press('Home');
    expect(await width(side)).toBe(190);
    await page.keyboard.press('ArrowRight');
    expect(await width(side)).toBe(206);
    expect((await stored(page, 'notes')).w.side).toBe(206);

    // a double click on the details' divider: the standard of a note again
    await splits.nth(1).dblclick();
    await expect.poll(() => width(detail)).toBe(520);
    expect((await stored(page, 'notes')).w.detail).toBeUndefined();
    for (const th of ['dark', 'light']) {
      await page.evaluate((x) => { if (x === 'light') document.documentElement.setAttribute('data-theme', 'light'); else document.documentElement.removeAttribute('data-theme'); }, th);
      await splits.nth(1).hover();
      await page.waitForTimeout(800);
      await shot(page, `teiler-notizen-${th}`);
    }
  });
});
