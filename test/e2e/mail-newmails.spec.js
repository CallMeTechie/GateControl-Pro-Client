'use strict';

// New mails while the list is shown (report: „wenn neue Mails ankommen, muss ich immer zum Kopf scrollen“): with a
// mail open further down the list kept that mail in view after a reload, so the new mails in front were pushed
// above the view. At the top the list now stays at the top; further down the row in view keeps its place and the
// pill „↑ n neue Mails“ counts the new ones (a click goes to the top, it goes at the top). The plugin is the core's
// fake Mail server (support/mail-mock.js); new mails are put into its state, the list's refresh button reloads.

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

/** A new mail in GMX's inbox (Relevant), newest first. */
function add(m, id) {
  const base = m.srv.state.messages.get(102);
  m.srv.state.messages.set(id, { ...base, id, threadId: id, threadCount: 1, accountId: 1, folderId: 11, subject: `Neu ${id}`, date: Date.now(), unread: true });
}

/** The list's scroll position and the first row in view. */
const view = (page) => page.evaluate(() => {
  const rows = document.querySelector('#page-mail .ml-rows');
  const top = rows.getBoundingClientRect().top;
  const first = [...rows.querySelectorAll('.ml-row')].find((e) => e.getBoundingClientRect().bottom > top + 1);
  return { scrollTop: rows.scrollTop, first: first && first.dataset.id, off: first && Math.round(first.getBoundingClientRect().top - top) };
});

async function openMail(launch, mock) {
  const m = await mock.setMail();
  const { page: p } = await launch();
  await setupWithApiKey(p, mock);
  await p.locator('#nav-mail').click();
  const root = p.locator('#page-mail');
  await expect(root.locator('.ml-row[data-id="101"]')).toBeVisible();
  return { m, p, root };
}

async function reload(root, id) {
  await root.locator('.ml-head .ml-ib').click();
  await expect(root.locator(`.ml-row[data-id="${id}"]`)).toBeAttached();
}

test.describe('mail: new mails', () => {
  test('at the top the new mails are seen, also with a mail open further down', async ({ launchApp, mock }) => {
    const { m, p, root } = await openMail(launchApp, mock);
    add(m, 901);
    add(m, 902);
    await reload(root, 902);
    expect(await view(p)).toMatchObject({ scrollTop: 0, first: '902' });
    await expect(root.locator('.ml-newabove')).toHaveCount(0);

    // a mail open in the fifth row; five new ones would push it out of view: the list stays at the top
    await root.locator('.ml-row').nth(4).click();
    await expect(root.locator('.ml-row.on')).toHaveCount(1);
    for (let i = 0; i < 5; i += 1) add(m, 910 + i);
    await reload(root, 914);
    expect(await view(p)).toMatchObject({ scrollTop: 0, first: '914' });
    await expect(root.locator('.ml-newabove')).toHaveCount(0);
  });

  test('further down the list stays, the pill counts and leads to the top', async ({ launchApp, mock }) => {
    const { m, p, root } = await openMail(launchApp, mock);
    await p.evaluate(() => { document.querySelector('#page-mail .ml-rows').scrollTop = 600; });
    const before = await view(p);
    expect(before.scrollTop).toBeGreaterThan(0);
    add(m, 920);
    add(m, 921);
    await reload(root, 921);
    const after = await view(p);
    expect(after.first).toBe(before.first);
    expect(Math.abs(after.off - before.off)).toBeLessThanOrEqual(1);
    const pill = root.locator('.ml-newabove');
    await expect(pill).toHaveText(/2 (neue Mails|new emails)/);
    // one more: the pill adds it
    add(m, 922);
    await reload(root, 922);
    await expect(pill).toHaveText(/3 (neue Mails|new emails)/);
    await p.screenshot({ path: test.info().outputPath('mail-new-above.png') });
    await pill.click();
    await expect.poll(async () => (await view(p)).scrollTop).toBe(0);
    await expect(pill).toHaveCount(0);
    expect((await view(p)).first).toBe('922');
  });

  test('no pill after switching the tab, which starts at the top', async ({ launchApp, mock }) => {
    const { m, p, root } = await openMail(launchApp, mock);
    await p.evaluate(() => { document.querySelector('#page-mail .ml-rows').scrollTop = 600; });
    add(m, 930);
    await reload(root, 930);
    await expect(root.locator('.ml-newabove')).toHaveCount(1);
    await root.locator('.ml-tab').nth(1).click();
    await expect(root.locator('.ml-row[data-id="104"]')).toBeVisible();
    await expect(root.locator('.ml-newabove')).toHaveCount(0);
    await root.locator('.ml-tab').nth(0).click();
    await expect(root.locator('.ml-row[data-id="930"]')).toBeVisible();
    expect((await view(p)).scrollTop).toBe(0);
    await expect(root.locator('.ml-newabove')).toHaveCount(0);
  });
});
