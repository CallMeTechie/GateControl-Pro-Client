'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Mail „Ansicht“ (the approved mockup „Ansicht & Größen“): the button beside the search opens the menu — reading
// pane right / below / off, folder bar full / narrow / off, density normal / compact, the AI line, „Spaltenbreiten
// zurücksetzen“; Strg+Umschalt+L. The dividers between the folder bar, the list and the reading pane (gc-split.js),
// below a divider across. Kept on this PC (gc.layout.mail); below 1100 px of window the folder bar is narrow for the
// time being without storing it. Screenshots with GC_E2E_SHOTS=<dir>.

const SHOTS = process.env.GC_E2E_SHOTS || null;
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` }); };
const setSize = (app, w, h) => app.evaluate(({ BrowserWindow }, s) => { const win = BrowserWindow.getAllWindows()[0]; win.unmaximize(); win.setSize(s.w, s.h); }, { w, h });
const setTheme = (page, th) => page.evaluate((x) => { if (x === 'light') document.documentElement.setAttribute('data-theme', 'light'); else document.documentElement.removeAttribute('data-theme'); }, th);
const box = (loc) => loc.evaluate((n) => { const r = n.getBoundingClientRect(); return { w: Math.round(r.width), h: Math.round(r.height) }; });
const stored = (page) => page.evaluate(() => JSON.parse(localStorage.getItem('gc.layout.mail') || 'null'));

async function openMail(page) {
  await expect(page.locator('#nav-mail')).toBeVisible();
  await page.locator('#nav-mail').click();
  await expect(page.locator('#page-mail')).toHaveClass(/active/);
  return page.locator('#page-mail');
}

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

test.describe('mail: Ansicht', () => {
  test('the menu, the reading pane right / below / off, the folder bar, density, AI line, dividers; kept on this PC', async ({ launchApp, mock }) => {
    await mock.setMail();
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setSize(app, 1440, 900);
    await expect.poll(() => page.evaluate(() => window.innerWidth)).toBe(1440);
    const root = await openMail(page);
    const ml = root.locator('.ml');
    const side = root.locator('.ml-side');
    const list = root.locator('.ml-list');
    const pane = root.locator('.ml-pane');
    const btn = root.locator('.ml-search-row .ml-view-btn');
    const split = (k) => root.locator(`.gc-split[data-split="mail.${k}"]`);
    await expect(root.locator('.ml-row[data-id="101"]')).toBeVisible();

    // standard: reading pane right, the folder bar 224 px, the list 360 px, two dividers
    await expect(btn).toBeVisible();
    await expect(btn).toHaveAttribute('title', /^(Ansicht \(Strg\+Umschalt\+L\)|View \(Ctrl\+Shift\+L\))$/);
    await expect(split('w.folders')).toBeVisible();
    await expect(split('w.list')).toBeVisible();
    await expect(split('h.list')).toBeHidden();
    await expect.poll(async () => (await box(side)).w).toBe(224);
    expect((await box(list)).w).toBe(360);
    await root.locator('.ml-row[data-id="101"]').click();
    await expect(pane.locator('.ml-read-subj')).toBeVisible();

    // the list's divider: dragged, the width in px; the reading pane keeps 420 px
    let up = await dragBy(page, split('w.list'), 52);
    await expect(split('w.list').locator('.gc-badge')).toHaveText('412 px');
    await shot(page, 'mail-teiler-ziehen');
    await up();
    expect((await box(list)).w).toBe(412);
    up = await dragBy(page, split('w.list'), 600);
    await expect(split('w.list')).toHaveClass(/is-limit/);
    await up();
    // 1200 px page − 224 folder bar − 2 dividers − 420 for the reading pane
    expect((await box(list)).w).toBe(554);
    expect((await box(pane)).w).toBeGreaterThanOrEqual(420);
    // the folder bar's divider: the keyboard
    await split('w.folders').focus();
    await page.keyboard.press('End');
    expect((await box(side)).w).toBe(320);
    await page.keyboard.press('Enter');
    await expect.poll(async () => (await box(side)).w).toBe(224);
    expect(await stored(page)).toEqual({ w: { list: 554 } });

    // the menu: Strg+Umschalt+L opens it, Esc closes it, the focus back on the button
    await root.locator('.ml-rows').focus();
    await page.keyboard.press('Control+Shift+L');
    const pop = page.locator('.vw-pop');
    await expect(pop).toBeVisible();
    await expect(btn).toHaveAttribute('aria-expanded', 'true');
    await expect(pop.locator('.vw-lay[data-reading="right"]')).toHaveAttribute('aria-checked', 'true');
    await expect(pop.locator('.vw-foot .ml-note')).toHaveText(/^(Gilt nur für diesen PC\.|Applies to this PC only\.)$/);
    await setTheme(page, 'light');
    await shot(page, 'mail-ansicht-menue-hell');
    await setTheme(page, 'dark');
    await shot(page, 'mail-ansicht-menue-dunkel');
    await page.keyboard.press('Escape');
    await expect(pop).toHaveCount(0);
    await expect(btn).toBeFocused();
    await expect(btn).toHaveAttribute('aria-expanded', 'false');

    // reading pane below: the list in one line with its column heads, the divider across (42 %)
    await btn.click();
    await pop.locator('.vw-lay[data-reading="bottom"]').click();
    await expect(ml).toHaveClass(/is-read-bottom/);
    await expect(root.locator('.ml-stack > .ml-list')).toHaveCount(1);
    await expect(root.locator('.ml-cols')).toBeVisible();
    await expect(root.locator('.ml-row.is-line[data-id="101"]')).toBeVisible();
    await expect(split('h.list')).toBeVisible();
    await expect(split('w.list')).toBeHidden();
    const stackH = (await box(root.locator('.ml-stack'))).h;
    await expect.poll(async () => (await box(list)).h).toBe(Math.round((stackH - 1) * 0.42));
    await expect(pane.locator('.ml-read-subj')).toBeVisible();
    await expect(root.locator('.ml-head .ml-search-row .ml-view-btn')).toBeVisible();
    await page.keyboard.press('Escape');
    up = await dragBy(page, split('h.list'), 0, 60);
    await expect(split('h.list').locator('.gc-badge')).toHaveText(/^\d+ %$/);
    await up();
    expect((await stored(page)).h.list).toBeGreaterThan(0.42);
    await split('h.list').dblclick();
    await expect.poll(async () => (await box(list)).h).toBe(Math.round((stackH - 1) * 0.42));

    // the folder bar narrow (icons, the count at the icon, the name as tooltip), density compact
    await btn.click();
    await pop.locator('[data-seg="folders"] button').nth(1).click();
    await pop.locator('[data-seg="density"] button').nth(1).click();
    await expect(ml).toHaveClass(/is-folders-narrow/);
    await expect(ml).toHaveClass(/is-compact/);
    expect((await box(side)).w).toBe(60);
    await expect(split('w.folders')).toBeHidden();
    await expect(side.locator('.ml-it').first()).toHaveAttribute('title', /Alle Posteingänge|All inboxes/);
    await expect(side.locator('.ml-it').first().locator('.ml-it-tx')).toBeHidden();
    await page.keyboard.press('Escape');
    for (const th of ['light', 'dark']) {
      await setTheme(page, th);
      await split('h.list').hover();
      await page.waitForTimeout(800);
      await shot(page, `mail-unten-schmal-kompakt-${th === 'light' ? 'hell' : 'dunkel'}`);
    }
    await page.mouse.move(5, 5);

    // the folder bar off, then the reading pane off: the list fills the page, a mail opens in full with „Zurück“
    await btn.click();
    await pop.locator('[data-seg="folders"] button').nth(2).click();
    await expect(side).toBeHidden();
    await pop.locator('[data-seg="folders"] button').nth(0).click();
    await pop.locator('.vw-lay[data-reading="off"]').click();
    await page.keyboard.press('Escape');
    await expect(ml).toHaveClass(/is-read-off/);
    await expect(root.locator('.ml-row.is-line')).toHaveCount(0);
    await expect(pane).toBeHidden();
    expect((await box(list)).w).toBeGreaterThan(900);
    await root.locator('.ml-row[data-id="102"]').click();
    await expect(pane.locator('.ml-read-subj')).toBeVisible();
    await expect(list).toBeHidden();
    await expect(pane.locator('.ml-read-back')).toBeVisible();
    await shot(page, 'mail-lesebereich-aus-offen');
    await pane.locator('.ml-read-back').click();
    await expect(list).toBeVisible();
    await expect(pane).toBeHidden();
    await expect(root.locator('.ml-row[data-id="102"]')).toBeFocused();
    await root.locator('.ml-row[data-id="101"]').click();
    await expect(list).toBeHidden();
    await page.keyboard.press('Escape');
    await expect(list).toBeVisible();

    // density normal, the AI line off; everything kept on this PC (the widths reset apart)
    await btn.click();
    await pop.locator('[data-seg="density"] button').nth(0).click();
    await expect(pop.locator('.vw-row .sw')).toHaveAttribute('aria-checked', 'true');
    await pop.locator('.vw-row .sw').click();
    await expect(ml).toHaveClass(/no-ai/);
    await pop.locator('.vw-lay[data-reading="right"]').click();
    await expect(ml).not.toHaveClass(/is-read-off/);
    expect(await stored(page)).toEqual({ w: { list: 554 }, reading: 'right', folders: 'full', density: 'normal', ai: false });
    await pop.locator('.vw-reset').click();
    expect(await stored(page)).toEqual({ reading: 'right', folders: 'full', density: 'normal', ai: false });
    await expect.poll(async () => (await box(list)).w).toBe(360);
    await page.keyboard.press('Escape');

    // a narrow window: the folder bar narrow for the time being (the menu says why), nothing stored
    await setSize(app, 1050, 800);
    await expect.poll(() => page.evaluate(() => window.innerWidth)).toBe(1050);
    await expect(ml).toHaveClass(/is-folders-narrow/);
    await btn.click();
    await expect(pop.locator('.vw-auto')).toBeVisible();
    await expect(pop.locator('[data-seg="folders"] button').nth(0)).toHaveAttribute('aria-checked', 'true');
    await page.keyboard.press('Escape');
    expect((await stored(page)).folders).toBe('full');
    expect((await box(pane)).w).toBeGreaterThanOrEqual(420);
    await setSize(app, 1440, 900);
    await expect(ml).not.toHaveClass(/is-folders-narrow/);
    await expect.poll(async () => (await box(side)).w).toBe(224);
    await setTheme(page, 'light');
    await root.locator('.ml-row[data-id="101"]').click();
    await split('w.list').hover();
    await page.waitForTimeout(800);
    await shot(page, 'mail-rechts-hell');
    await setTheme(page, 'dark');
    await shot(page, 'mail-rechts-dunkel');
  });
});
