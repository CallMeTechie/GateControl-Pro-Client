'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');
const { FEATURES_14, FEATURES_141 } = require('./support/messenger-mock');

// Messenger 1.4.0 in the Chats page: status strip and stories, the settings
// page, chat tools (archive, pins, lists, block, export, remind me,
// suggestions), polls, events, live arrivals, home actions and plugin cards,
// the "newer version" bubble for unknown kinds. Selectors by class / data-*,
// texts in both languages where needed.

const SHOTS = process.env.GC_E2E_SHOTS || null;
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` }); };

async function openChats(launchApp, mock) {
  const { page, app, events } = await launchApp();
  await setupWithApiKey(page, mock);
  await page.locator('#nav-chats').click();
  await expect(page.locator('#page-chats')).toHaveClass(/active/);
  return { page, app, events };
}

test.describe('chats – Messenger 1.4.0', () => {
  test('status strip, story viewer (seen, reply, reaction), own status and a text story', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_14, familie: true });
    const anna = ms.addConv();
    ms.addMsg(anna, { text: 'Hallo' });
    ms.addStory(8, { text: 'Mathe-Arbeit geschafft!', bg: '#7C3AED' });
    ms.setStatus(9, { preset: 'homeoffice' });
    const { page } = await openChats(launchApp, mock);

    const strip = page.locator('#page-chats .cv-strip');
    await expect(strip.locator('.cv-st')).toHaveCount(3);
    await expect(strip.locator('.cv-st.is-me .cv-st-cap')).toHaveText(/Mein Status|My status/);
    const annaSt = strip.locator('.cv-st[data-user="8"]');
    await expect(annaSt).toHaveClass(/is-unseen/);
    await expect(annaSt.locator('.cv-ring')).toHaveClass(/is-unseen/);
    await expect(strip.locator('.cv-st[data-user="9"]')).toHaveAttribute('title', /Lena: (Im Homeoffice|Working from home)/);
    await shot(page, '14-list-strip');

    // viewer: text, seen, reaction and reply
    await annaSt.click();
    const viewer = page.locator('#page-chats .cv-story');
    await expect(viewer.locator('.cv-story-text')).toHaveText('Mathe-Arbeit geschafft!');
    await expect.poll(() => ms.log.seen.length).toBe(1);
    await shot(page, '14-story-viewer');
    await viewer.locator('.cv-story-emojis button').first().click();
    await expect.poll(() => ms.log.storyReacts.map((r) => r.emoji)).toEqual(['👏']);
    await viewer.locator('.cv-story-reply').fill('Super gemacht!');
    await viewer.locator('.cv-story-reply').press('Enter');
    await expect.poll(() => ms.log.sent.at(-1) && ms.log.sent.at(-1).text).toBe('Super gemacht!');
    expect(ms.log.sent.at(-1).replyStory).toEqual({ storyId: 300 });
    await page.keyboard.press('Escape');
    await expect(viewer).toBeHidden();
    await expect(annaSt).not.toHaveClass(/is-unseen/);

    // own status: own avatar in the list head → "Dein Status"
    await page.locator('#page-chats .cv-me').click();
    const dlg = page.locator('#page-chats .cv-overlay').last();
    await dlg.locator('input').first().fill('Im Garten');
    await dlg.locator('.cv-preset[data-preset="dnd"]').click();
    await dlg.locator('.cv-chip-btn[data-key="1h"]').click();
    await dlg.locator('.cv-chip-btn[data-v="family"]').click();
    await shot(page, '14-status-dialog');
    await dlg.locator('.btn-pri').click();
    await expect.poll(() => ms.log.statusPuts.length).toBe(1);
    const put = ms.log.statusPuts[0];
    expect(put).toMatchObject({ preset: 'dnd', text: 'Im Garten', visibility: 'family' });
    expect(Date.parse(put.until)).toBeGreaterThan(Date.now());
    await expect(page.locator('#page-chats .cv-me')).toHaveAttribute('title', /Im Garten/);

    // a text story with "+" at "Mein Status" (no own stories yet: no ring)
    await expect(strip.locator('.cv-st.is-me .cv-ring')).toHaveClass(/is-none/);
    await strip.locator('.cv-st.is-me .cv-st-plus').click();
    const sdlg = page.locator('#page-chats .cv-overlay').last();
    // a 1.4.0 server takes no duration: "24 Std." as plain text, not a button
    await expect(sdlg.locator('.cv-story-dur-fixed')).toHaveText(/^(24 Std\.|24 h)$/);
    await expect(sdlg.locator('.cv-story-dur')).toHaveCount(0);
    await expect(sdlg.locator('button[data-h]')).toHaveCount(0);
    await sdlg.locator('.cv-story-input').fill('Grillen heute ab 18 Uhr');
    await sdlg.locator('.cv-story-color').nth(2).click();
    await shot(page, '14-story-compose');
    await sdlg.locator('.cv-dlg-foot .btn-pri').click();
    await expect.poll(() => ms.log.stories.length).toBe(1);
    expect(ms.log.stories[0]).toMatchObject({ kind: 'text', text: 'Grillen heute ab 18 Uhr', bg: '#7C3AED', font: 'sans' });
    expect(ms.log.stories[0]).not.toHaveProperty('durationH');
    await expect(sdlg).toBeHidden();
    // now with the ring; the avatar opens the own story
    await expect(strip.locator('.cv-st.is-me')).toHaveClass(/has-stories/);
    await expect(strip.locator('.cv-st.is-me .cv-ring')).toHaveClass(/is-own/);
    await strip.locator('.cv-st.is-me .cv-st-av').click();
    await expect(viewer.locator('.cv-story-text')).toHaveText('Grillen heute ab 18 Uhr');
    await expect(viewer.locator('.cv-story-viewers')).toHaveText(/(Gesehen von|Seen by) 0/);
    await page.keyboard.press('Escape');
    await expect(viewer).toBeHidden();
  });

  test('own active stories: ring in the strip and the list head, viewer with viewers, "Meine Storys"', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_141 });
    ms.addMsg(ms.addConv(), { text: 'Hallo' });
    const id = ms.addStory(7, { text: 'Schon unterwegs', bg: '#0F766E' });
    ms.st14.stories.find((x) => x.id === id).seen.add(8);
    ms.addStory(7, { text: 'Zweite Story', bg: '#1D4ED8' });
    const { page } = await openChats(launchApp, mock);

    const strip = page.locator('#page-chats .cv-strip');
    const own = strip.locator('.cv-st.is-me');
    await expect(own).toHaveClass(/has-stories/);
    const ring = own.locator('.cv-ring');
    await expect(ring).toHaveClass(/is-own/);
    expect(await ring.evaluate((n) => getComputedStyle(n).backgroundImage)).toContain('conic-gradient');
    await expect(page.locator('#page-chats .cv-me .cv-ring.is-own')).toBeVisible();
    await expect(page.locator('#page-chats .cv-me')).toHaveAttribute('title', /(2 Storys aktiv|2 stories active)/);
    await shot(page, '141-own-ring');

    // avatar → own stories in the viewer, with the viewers
    await own.locator('.cv-st-av').click();
    const viewer = page.locator('#page-chats .cv-story');
    await expect(viewer.locator('.cv-story-text')).toHaveText('Schon unterwegs');
    await expect(viewer.locator('.cv-story-bar')).toHaveCount(2);
    await expect(viewer.locator('.cv-story-viewers')).toHaveText(/(Gesehen von|Seen by) 1/);
    await viewer.locator('.cv-story-viewers').click();
    const vdlg = page.locator('#page-chats .cv-overlay:not(.cv-story)').last();
    await expect(vdlg.locator('.cv-member')).toHaveText(/Anna/);
    await vdlg.locator('.cv-dlg-foot .btn').click();
    await expect(vdlg).toBeHidden();
    await page.keyboard.press('Escape');
    await expect(viewer).toBeHidden();
    expect(ms.log.seen).toEqual([], 'own stories are not marked seen');

    // "Dein Status" → the card "Meine Storys" → "Ansehen"
    await page.locator('#page-chats .cv-me').click();
    const dlg = page.locator('#page-chats .cv-overlay:not(.cv-story)').last();
    const card = dlg.locator('.cv-mystories');
    await expect(card).toBeVisible();
    await expect(card).toContainText(/Meine Storys|My stories/);
    await expect(card).toContainText(/(2 Storys aktiv · Gesehen von 1|2 stories active · Seen by 1)/);
    await shot(page, '141-my-stories-card');
    await card.locator('button').click();
    await expect(dlg).toBeHidden();
    await expect(viewer.locator('.cv-story-text')).toHaveText('Schon unterwegs');
    await page.keyboard.press('Escape');
    await expect(viewer).toBeHidden();
  });

  test('story composer: duration (1.4.1), a failed post stays as an error, a posted story shows at once', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_141 });
    ms.addMsg(ms.addConv(), { text: 'Hallo' });
    const { page } = await openChats(launchApp, mock);
    const own = page.locator('#page-chats .cv-strip .cv-st.is-me');
    await expect(own).not.toHaveClass(/has-stories/);

    await own.locator('.cv-st-plus').click();
    const dlg = page.locator('#page-chats .cv-overlay').last();
    const dur = dlg.locator('.cv-story-dur .cv-chip-btn');
    await expect(dur).toHaveText([/^(1 Std\.|1 h)$/, /^(3 Std\.|3 h)$/, /^(6 Std\.|6 h)$/, /^(12 Std\.|12 h)$/, /^(24 Std\.|24 h)$/]);
    await expect(dlg.locator('.cv-story-dur .cv-chip-btn[data-h="24"]')).toHaveAttribute('aria-checked', 'true');
    await dlg.locator('.cv-story-dur .cv-chip-btn[data-h="3"]').click();
    await expect(dlg.locator('.cv-story-dur .cv-chip-btn[data-h="3"]')).toHaveAttribute('aria-checked', 'true');
    await expect(dlg.locator('.cv-note')).toContainText(/3 Std\.|3 h/);
    await dlg.locator('.cv-story-input').fill('Kurz im Garten');

    // the server refuses: the error stays in the composer, the text is kept
    ms.failStory('feature_off');
    await dlg.locator('.cv-dlg-foot .btn-pri').click();
    const err = dlg.locator('.cv-story-msg');
    await expect(err).toBeVisible();
    await expect(err).toHaveAttribute('data-type', 'error');
    await expect(err).toHaveText(/(Nicht geteilt|Not shared)/);
    await shot(page, '141-story-failed');
    await page.waitForTimeout(4500); // longer than a toast
    await expect(err).toBeVisible();
    await expect(dlg.locator('.cv-story-input')).toHaveValue('Kurz im Garten');
    await expect(dlg.locator('.cv-dlg-foot .btn-pri')).toBeEnabled();

    // second try while the feed cannot be fetched: the story still shows at once
    ms.st14.feedFail = true;
    await dlg.locator('.cv-dlg-foot .btn-pri').click();
    await expect(dlg).toBeHidden();
    expect(ms.log.stories.at(-1)).toMatchObject({ kind: 'text', text: 'Kurz im Garten', durationH: 3 });
    expect(ms.st14.stories.at(-1).durationH).toBe(3);
    await expect(own).toHaveClass(/has-stories/);
    await expect(own.locator('.cv-ring')).toHaveClass(/is-own/);
    await own.locator('.cv-st-av').click();
    const viewer = page.locator('#page-chats .cv-story');
    await expect(viewer.locator('.cv-story-text')).toHaveText('Kurz im Garten');
    await expect(viewer.locator('.cv-story-head small')).toContainText(/noch [23] Std\.|[23] h left/); // 3 h story
    await page.keyboard.press('Escape');
  });

  for (const theme of ['dark', 'light']) {
    test(`story composer is readable in the ${theme} theme`, async ({ launchApp, mock }) => {
      mock.setPush({ topics: [], items: [] });
      const ms = mock.setMessenger({ features: FEATURES_141 });
      ms.addMsg(ms.addConv(), { text: 'Hallo' });
      const { page } = await openChats(launchApp, mock);
      await page.evaluate((th) => { if (th === 'light') document.documentElement.setAttribute('data-theme', 'light'); else document.documentElement.removeAttribute('data-theme'); }, theme);
      await page.locator('#page-chats .cv-strip .cv-st.is-me .cv-st-plus').click();
      const dlg = page.locator('#page-chats .cv-overlay').last();
      await dlg.locator('.cv-story-input').fill('Lesbar?');
      // WCAG contrast of text against the nearest opaque background behind it
      const contrast = (sel) => dlg.locator(sel).first().evaluate((node) => {
        const rgb = (c) => { const m = c.match(/[\d.]+/g).map(Number); return { r: m[0], g: m[1], b: m[2], a: m.length > 3 ? m[3] : 1 }; };
        const lum = ({ r, g, b }) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
        let bg = null;
        for (let n = node; n && n.nodeType === 1; n = n.parentElement) { const c = rgb(getComputedStyle(n).backgroundColor); if (c.a >= 0.99) { bg = c; break; } }
        bg = bg || { r: 255, g: 255, b: 255 };
        const st = getComputedStyle(node);
        const fg = rgb(st.webkitTextFillColor && st.webkitTextFillColor !== 'currentcolor' ? st.webkitTextFillColor : st.color);
        const [a, b] = [lum(fg), lum(bg)].sort((x, y) => y - x);
        return (a + 0.05) / (b + 0.05);
      });
      expect(await contrast('.cv-story-input')).toBeGreaterThan(4.5);
      expect(await contrast('.cv-tabs button[aria-pressed="true"]')).toBeGreaterThan(4.5);
      expect(await contrast('.cv-tabs button[aria-pressed="false"]')).toBeGreaterThan(3);
      expect(await contrast('.cv-story-dur .cv-chip-btn[aria-checked="true"]')).toBeGreaterThan(3);
      expect(await contrast('.cv-story-dur .cv-chip-btn[aria-checked="false"]')).toBeGreaterThan(3);
      expect(await contrast('.cv-field > span')).toBeGreaterThan(3);
      expect(await contrast('.cv-note')).toBeGreaterThan(3);
      await shot(page, `141-compose-text-${theme}`);
      // picture tab without a file: the note on the dark preview and the caption field
      await page.evaluate(() => { HTMLInputElement.prototype.click = function () {}; });
      await dlg.locator('.cv-tabs button[data-kind="image"]').click();
      expect(await contrast('.cv-story-empty')).toBeGreaterThan(4.5);
      await dlg.locator('.cv-story-cap .cv-story-input').fill('Bildunterschrift');
      expect(await contrast('.cv-story-cap .cv-story-input')).toBeGreaterThan(4.5);
      // an error in the composer
      await dlg.locator('.cv-dlg-foot .btn-pri').click();
      await expect(dlg.locator('.cv-story-msg')).toBeVisible();
      expect(await contrast('.cv-story-msg')).toBeGreaterThan(4.5);
      await shot(page, `141-compose-image-${theme}`);
    });
  }

  test('settings page: privacy, notifications, chats (Enter sends), lists as chips, blocked people, storage, home actions', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_14 });
    const anna = ms.addConv();
    ms.addMsg(anna, { text: 'Hallo' });
    const fam = ms.addConv({ kind: 'group', members: [7, 8, 9], title: 'Familie' });
    ms.addMsg(fam, { senderId: 9, text: 'Hi' });
    ms.st14.blocks.add(9);
    const { page } = await openChats(launchApp, mock);

    await page.locator('#page-chats .cv-list-title .cv-ib-flat').first().click();
    const set = page.locator('#page-chats .cv-settings');
    await expect(set).toBeVisible();
    await expect(set.locator('.cv-set-item')).toHaveCount(8);
    await shot(page, '14-settings-account');

    // Datenschutz: server prefs privacy.*, blocked people
    await set.locator('.cv-set-item[data-section="privacy"]').click();
    await set.locator('[data-pref="lastSeen"] select').selectOption('nobody');
    await expect.poll(() => ms.log.prefs).toContainEqual({ privacy: { lastSeen: 'nobody' } });
    await set.locator('[data-pref="readReceipts"] .sw').click();
    await expect.poll(() => ms.log.prefs).toContainEqual({ readReceipts: false });
    await expect(set.locator('.cv-member', { hasText: 'Lena' })).toBeVisible();
    await shot(page, '14-settings-privacy');
    await set.locator('.cv-member', { hasText: 'Lena' }).locator('.btn').click();
    await expect.poll(() => ms.log.blocks).toContainEqual({ userId: 9, blocked: false });

    // Benachrichtigungen: notify.* and the sound of this PC
    await set.locator('.cv-set-item[data-section="notify"]').click();
    await set.locator('[data-pref="groupsMentionsOnly"] .sw').click();
    await expect.poll(() => ms.log.prefs).toContainEqual({ notify: { groupsMentionsOnly: true } });
    await set.locator('[data-pref="eventReminderMin"] select').selectOption('15');
    await expect.poll(() => ms.log.prefs).toContainEqual({ notify: { eventReminderMin: 15 } });
    await set.locator('[data-pref="sound"] .sw').click();
    expect(await page.evaluate(() => localStorage.getItem('gc.chat.sound'))).toBe('false');

    // Chats: Enter sends off (local), keep archived (server)
    await set.locator('.cv-set-item[data-section="chats"]').click();
    await set.locator('[data-pref="keepArchived"] .sw').click();
    await expect.poll(() => ms.log.prefs).toContainEqual({ chats: { keepArchived: false } });
    await set.locator('[data-pref="enterSends"] .sw').click();
    await set.locator('[data-pref="fontSize"] select').selectOption('large');

    // Listen: a list becomes a chip
    await set.locator('.cv-set-item[data-section="lists"]').click();
    await set.locator('.cv-set-card .btn-ghost').click();
    const ldlg = page.locator('#page-chats .cv-overlay').last();
    await ldlg.locator('input.inp').fill('Familie & Co');
    await ldlg.locator(`input[type=checkbox][value="${fam}"]`).check();
    await ldlg.locator('.btn-pri').click();
    await expect.poll(() => ms.log.lists.length).toBe(1);
    expect(ms.log.lists[0]).toEqual([{ id: 'familie-co', name: 'Familie & Co', conversationIds: [fam] }]);
    await expect(set.locator('[data-list="familie-co"]')).toBeVisible();

    // Speicher, Haus-Aktionen (local choice for the attach menu)
    await set.locator('.cv-set-item[data-section="storage"]').click();
    await expect(set.locator('[data-pref="quota"] .cv-chip')).toHaveText(/OK/);
    await set.locator('.cv-set-item[data-section="actions"]').click();
    await set.locator('[data-pref="action:light.living"] .sw').click();
    expect(JSON.parse(await page.evaluate(() => localStorage.getItem('gc.chat.hiddenActions')))).toEqual(['light.living']);
    await shot(page, '14-settings-actions');

    // back to the chats: the list chip filters, Enter does not send any more
    await set.locator('.cv-set-back').click();
    await expect(set).toBeHidden();
    await page.locator('#page-chats .cv-chip-btn[data-filter="list:familie-co"]').click();
    await expect(page.locator('#page-chats .cv-row[data-id]')).toHaveCount(1);
    await expect(page.locator('#page-chats .cv-row[data-id] .cv-row-name')).toHaveText('Familie');
    await page.locator('#page-chats .cv-chip-btn[data-filter="all"]').click();
    await page.locator(`#page-chats .cv-row[data-id="${anna}"]`).click();
    const input = page.locator('#page-chats .cv-input');
    await input.fill('Zeile 1');
    await input.press('Enter');
    await page.waitForTimeout(300);
    expect(ms.log.sent.length).toBe(0);
    await input.press('Control+Enter');
    await expect.poll(() => ms.log.sent.length).toBe(1);
    await expect(page.locator('#page-chats .cv-compose-hint')).toHaveText(/Strg\+Enter|Ctrl\+Enter/);

    // the attach menu offers only the actions switched on
    await page.locator('#page-chats .cv-attach-btn').click();
    await expect(page.locator('#page-chats .cv-menu-item[data-item="action:garage.open"]')).toBeVisible();
    await expect(page.locator('#page-chats .cv-menu-item[data-item="action:light.living"]')).toHaveCount(0);
  });

  test('chat tools: archive, pin, remind me, suggestions to Familie, export, block; last seen', async ({ launchApp, mock, }, testInfo) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_14, familie: true });
    const anna = ms.addConv();
    const msg = ms.addMsg(anna, { text: 'Kannst du morgen Milch, Brot und Kaffee mitbringen? Donnerstag um 15 Uhr Zahnarzt.' });
    const lena = ms.addConv({ members: [7, 9] });
    ms.addMsg(lena, { senderId: 9, text: 'Bis später' });
    ms.setPresence(8, { online: true });
    ms.setPresence(9, { online: false, lastSeenAt: new Date().toISOString() });
    ms.st14.suggest = { items: ['Milch', 'Brot', 'Kaffee'], dates: [{ startsAt: new Date(Date.now() + 3 * 86400000).toISOString(), label: 'Do., 15:00', title: 'Zahnarzt', allDay: false }] };
    const { page, app } = await openChats(launchApp, mock);
    // the size of a 1280 px window at 125 % scaling (the CI runners): the chat info lies over the chat
    await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setContentSize(1024, 760));
    await expect.poll(() => page.evaluate(() => window.innerWidth)).toBeLessThan(1181);

    await expect(page.locator(`#page-chats .cv-row[data-id="${anna}"] .cv-online`)).toBeVisible();
    await page.locator(`#page-chats .cv-row[data-id="${lena}"]`).click();
    await expect(page.locator('#page-chats .cv-head-sub')).toHaveText(/zuletzt online heute|last seen today/);
    await page.locator(`#page-chats .cv-row[data-id="${anna}"]`).click();
    await expect(page.locator('#page-chats .cv-head-sub')).toHaveText('online');

    // message menu: pin → bar; remind; suggestions
    const bub = page.locator('#page-chats .cv-msg.is-in .cv-bub').last();
    await bub.click({ button: 'right' });
    await page.locator('#page-chats .cv-menu-item', { hasText: /Anheften|^Pin$/ }).click();
    await expect.poll(() => ms.log.pins).toEqual([{ id: anna, messageId: msg.id, pinned: true }]);
    await expect(page.locator('#page-chats .cv-bar-pin')).toContainText('Milch');

    await bub.click({ button: 'right' });
    await page.locator('#page-chats .cv-menu-item', { hasText: /Erinnere mich|Remind me/ }).click();
    await page.locator('#page-chats .cv-overlay .cv-remind-opt').first().click();
    await expect.poll(() => ms.log.reminds.length).toBe(1);
    expect(Date.parse(ms.log.reminds[0].at) - Date.now()).toBeGreaterThan(50 * 60000);

    await bub.click({ button: 'right' });
    const toList = page.locator('#page-chats .cv-menu-item.is-suggest', { hasText: /Einkaufsliste|shopping list/ });
    await expect(toList).toContainText(/3 Punkte|3 items/);
    await shot(page, '14-menu-suggest');
    await toList.click();
    const ldlg = page.locator('#page-chats .cv-overlay').last();
    await ldlg.locator('input[type=checkbox][value="Kaffee"]').uncheck();
    await ldlg.locator('.btn-pri').click();
    await expect.poll(() => ms.log.toList.map((x) => x.items)).toEqual([['Milch', 'Brot']]);
    await bub.click({ button: 'right' });
    await page.locator('#page-chats .cv-menu-item.is-suggest', { hasText: /Termin anlegen|Create event/ }).click();
    const cdlg = page.locator('#page-chats .cv-overlay').last();
    await expect(cdlg.locator('input.inp').first()).toHaveValue('Zahnarzt');
    await cdlg.locator('.btn-pri').click();
    await expect.poll(() => ms.log.toCalendar.length).toBe(1);
    expect(ms.log.toCalendar[0]).toMatchObject({ title: 'Zahnarzt', allDay: false });

    // info pane: export (save dialog), archive, block
    const out = testInfo.outputPath('chat-export.txt');
    await app.evaluate(({ dialog }, file) => { dialog.showSaveDialog = async () => ({ canceled: false, filePath: file }); }, out);
    await page.locator('#page-chats .cv-head .cv-ib-flat[aria-label]').last().click();
    await page.locator('#page-chats .cv-tool[data-tool="export"]').click();
    await expect.poll(() => ms.log.exports.length).toBe(1);
    await expect.poll(() => require('fs').existsSync(out)).toBe(true);
    expect(require('fs').readFileSync(out, 'utf8')).toContain('Anna: Kannst du morgen Milch');

    await page.locator('#page-chats .cv-tool[data-tool="block"]').click();
    await page.locator('#page-chats .cv-overlay .cv-danger').click();
    await expect.poll(() => ms.log.blocks).toEqual([{ userId: 8, blocked: true }]);
    await expect(page.locator('#page-chats .cv-composer .cv-blocked')).toContainText(/blockiert|blocked/);
    // the info pane shows "Nicht mehr blockieren" now; in narrow windows it lies over the
    // chat (header and composer), so close it to use the composer's own button
    await expect(page.locator('#page-chats .cv-tool[data-tool="unblock"]')).toBeVisible();
    await page.locator('#page-chats .cv-info-head .cv-ib-flat').click(); // the pane's own close button
    await expect(page.locator('#page-chats .cv-info')).toBeHidden();
    await page.locator('#page-chats .cv-composer .cv-blocked .btn').click();
    await expect.poll(() => ms.log.blocks.at(-1)).toEqual({ userId: 8, blocked: false });
    await expect(page.locator('#page-chats .cv-composer .cv-input')).toBeVisible();

    await page.locator('#page-chats .cv-head .cv-ib-flat[aria-label]').last().click();
    await page.locator('#page-chats .cv-tool[data-tool="archive"]').click();
    await expect.poll(() => ms.log.archives).toEqual([{ id: anna, archived: true }]);
    await expect(page.locator('#page-chats .cv-archived')).toBeVisible();
    await expect(page.locator(`#page-chats .cv-row[data-id="${anna}"]`)).toHaveCount(0);
    await page.locator('#page-chats .cv-archived').click();
    await expect(page.locator(`#page-chats .cv-row[data-id="${anna}"]`)).toBeVisible();
    await shot(page, '14-archived');
  });

  test('polls: create from the attach menu, vote, add an answer, live update, close', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_14 });
    const fam = ms.addConv({ kind: 'group', members: [7, 8, 9], title: 'Familie' });
    const poll = ms.addMsg(fam, { senderId: 9, kind: 'poll', text: null, poll: { question: 'Was essen wir am Sonntag?', options: [{ id: 'o1', text: 'Grillen', count: 1, voters: [8], addedBy: null }, { id: 'o2', text: 'Lasagne', count: 0, voters: [], addedBy: null }], multi: false, anonymous: false, allowAdd: true, closesAt: new Date(Date.now() + 86400000).toISOString(), closed: false, closedAt: null, voterCount: 1, memberCount: 3, creatorId: 9, myVotes: [] } });
    const { page } = await openChats(launchApp, mock);
    await page.locator(`#page-chats .cv-row[data-id="${fam}"]`).click();
    const card = page.locator('#page-chats .cv-poll');
    await expect(card.locator('.cv-poll-q')).toHaveText('Was essen wir am Sonntag?');
    await expect(card.locator('.cv-poll-sub')).toContainText(/1 von 3|1 of 3/);
    await card.locator('.cv-poll-opt[data-option="o2"]').click();
    await expect.poll(() => ms.log.votes).toEqual([{ id: poll.id, optionIds: ['o2'] }]);
    await expect(card.locator('.cv-poll-opt[data-option="o2"]')).toHaveClass(/is-mine/);
    await shot(page, '14-poll');

    // someone else votes: poll.update → the counts change
    ms.update(poll.id, (m) => { m.poll.options[0].voters.push(9); m.poll.options[0].count = 2; m.poll.voterCount = 3; });
    await expect(card.locator('.cv-poll-opt[data-option="o1"] .cv-poll-n')).toHaveText('2');

    await card.locator('.cv-rich-tools .cv-link').first().click();
    const odlg = page.locator('#page-chats .cv-overlay').last();
    await odlg.locator('input').fill('Pizza');
    await odlg.locator('.btn-pri').click();
    await expect.poll(() => ms.log.pollOps).toContainEqual({ id: poll.id, op: 'option', text: 'Pizza' });
    await expect(card.locator('.cv-poll-opt')).toHaveCount(3);

    // own poll from the attach menu
    await page.locator('#page-chats .cv-attach-btn').click();
    await page.locator('#page-chats .cv-menu-item[data-item="poll"]').click();
    const dlg = page.locator('#page-chats .cv-overlay').last();
    await dlg.locator('.cv-field input').first().fill('Wer kommt mit zu Oma?');
    const opts = dlg.locator('.cv-poll-opts input');
    await opts.nth(0).fill('Ich');
    await opts.nth(1).fill('Ich nicht');
    await dlg.locator('.cv-pref .sw').first().click(); // multi
    await shot(page, '14-poll-create');
    await dlg.locator('.btn-pri').click();
    await expect.poll(() => ms.log.sent.at(-1) && ms.log.sent.at(-1).kind).toBe('poll');
    expect(ms.log.sent.at(-1).poll).toEqual({ question: 'Wer kommt mit zu Oma?', options: ['Ich', 'Ich nicht'], multi: true, anonymous: false, allowAdd: true });
    expect(ms.log.sent.at(-1).text).toBeUndefined();
    const mine = page.locator('#page-chats .cv-msg.is-out .cv-poll').last();
    await expect(mine.locator('.cv-poll-q')).toHaveText('Wer kommt mit zu Oma?');
    await mine.locator('.cv-rich-tools .cv-link', { hasText: /Beenden|Close/ }).click();
    await page.locator('#page-chats .cv-overlay').last().locator('.btn-pri').click();
    await expect.poll(() => ms.log.pollOps.map((x) => x.op)).toContain('close');
    await expect(mine).toHaveClass(/is-closed/);
  });

  test('events: create with a Familie place, RSVP with guests, checklist, next-event bar, edit and cancel', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_14, familie: true });
    const fam = ms.addConv({ kind: 'group', members: [7, 8, 9], title: 'Familie' });
    const starts = new Date(Date.now() + 8 * 86400000);
    starts.setHours(12, 30, 0, 0);
    const ev = ms.addMsg(fam, { senderId: 9, kind: 'event', text: null, event: { title: 'Sonntagsessen bei Oma', startsAt: starts.toISOString(), endsAt: null, allDay: false, place: { label: 'Oma Gisela' }, description: null, checklist: [{ id: 'c1', text: 'Salat', doneBy: null }, { id: 'c2', text: 'Nachtisch', doneBy: null }], rsvpEnabled: true, guests: true, rsvp: { yes: [{ userId: 8, guests: 1 }], maybe: [], no: [], mine: null, myGuests: 0 }, reminderMin: 60, familyCalendar: true, departureHint: false, cancelled: false, creatorId: 9 } });
    const { page } = await openChats(launchApp, mock);
    await page.locator(`#page-chats .cv-row[data-id="${fam}"]`).click();
    await expect(page.locator('#page-chats .cv-bar-event')).toContainText('Sonntagsessen bei Oma');
    const card = page.locator('#page-chats .cv-event');
    await expect(card.locator('.cv-event-place')).toHaveText('Oma Gisela');
    await expect(card.locator('.cv-rsvp-btn[data-answer="yes"] span')).toHaveText('2');
    await card.locator('.cv-rsvp-btn[data-answer="yes"]').click();
    await expect.poll(() => ms.log.rsvps[0]).toEqual({ id: ev.id, answer: 'yes', guests: 0 });
    await card.locator('.cv-guests .cv-ib').last().click();
    await expect.poll(() => ms.log.rsvps.at(-1)).toEqual({ id: ev.id, answer: 'yes', guests: 1 });
    await card.locator('.cv-event-item input').first().check();
    await expect.poll(() => ms.log.checks).toEqual([{ id: ev.id, itemId: 'c1', done: true }]);
    await expect(card.locator('.cv-event-item').first()).toHaveClass(/is-done/);
    await shot(page, '14-event');

    // own event with a Familie place
    await page.locator('#page-chats .cv-attach-btn').click();
    await page.locator('#page-chats .cv-menu-item[data-item="event"]').click();
    const dlg = page.locator('#page-chats .cv-overlay').last();
    await dlg.locator('input.inp').first().fill('Grillen');
    await dlg.locator('select[aria-label]').first().selectOption('oma');
    await dlg.locator('textarea').nth(1).fill('Kohle\nWürstchen');
    await shot(page, '14-event-create');
    await dlg.locator('.btn-pri').click();
    await expect.poll(() => ms.log.sent.at(-1) && ms.log.sent.at(-1).kind).toBe('event');
    const sent = ms.log.sent.at(-1).event;
    expect(sent).toMatchObject({ title: 'Grillen', place: { label: 'Oma Gisela', familiePlaceId: 'oma', lat: 50.2, lon: 7.2 }, checklist: ['Kohle', 'Würstchen'], rsvp: true, guests: false, reminderMin: 60 });
    const mine = page.locator('#page-chats .cv-msg.is-out .cv-event').last();
    await mine.locator('.cv-rich-tools .cv-link', { hasText: /Bearbeiten|Edit/ }).click();
    const edlg = page.locator('#page-chats .cv-overlay').last();
    await edlg.locator('input.inp').first().fill('Grillen im Garten');
    await edlg.locator('.btn-pri').click();
    await expect.poll(() => ms.log.eventEdits.length).toBe(1);
    expect(ms.log.eventEdits[0].title).toBe('Grillen im Garten');
    await mine.locator('.cv-rich-tools .cv-link.is-danger').click();
    await page.locator('#page-chats .cv-overlay').last().locator('.cv-danger').click();
    await expect.poll(() => ms.log.eventEdits.at(-1)).toMatchObject({ cancelled: true });
    await expect(mine).toHaveClass(/is-cancelled/);
  });

  test('live arrival, home actions (request, approve, deny, send), doorbell card, unknown kinds', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_14 });
    const fam = ms.addConv({ kind: 'group', members: [7, 8, 9], title: 'Familie' });
    const arr = ms.addMsg(fam, { senderId: 8, kind: 'arrival', text: null, arrival: { dest: { label: 'Zuhause', lat: 50.1, lon: 7.1, radiusM: 150 }, onArrive: null, state: 'live', etaAt: new Date(Date.now() + 9 * 60000).toISOString(), distanceM: 3100, progress: 0.4, lastAt: new Date().toISOString(), startedAt: new Date().toISOString(), endedAt: null, position: { lat: 50.12, lon: 7.1, accuracy: 12 } } });
    const req = ms.addMsg(fam, { senderId: 9, kind: 'action', text: null, action: { mode: 'request', actionId: 'garage.open', plugin: 'gatecontrol-garage', label: 'Garage öffnen', icon: 'M3 21V9l9-6 9 6v12H3z', needsConfirm: false, approverIds: null, grant: null, state: 'open', result: null, by: null, at: null } });
    const req2 = ms.addMsg(fam, { senderId: 9, kind: 'action', text: null, action: { mode: 'request', actionId: 'garage.open', plugin: 'gatecontrol-garage', label: 'Garage schließen', icon: null, needsConfirm: false, approverIds: null, grant: null, state: 'open', result: null, by: null, at: null } });
    const card = ms.addMsg(fam, { senderId: null, kind: 'card', text: 'Paketbote an der Haustür', card: { kind: 'doorbell', title: 'Haustür', text: 'Paketbote an der Haustür', image: { mime: 'image/png', bytes: 68 }, link: { label: 'Live-Bild', route: 'plg-gatecontrol-door', kind: 'live_view' }, actions: [{ plugin: 'gatecontrol-door', actionId: 'door.open', label: 'Tür öffnen', icon: null, needsConfirm: true, canRun: true }], lastRun: null } });
    const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');
    ms.setCardImage(card.id, 'image/png', png);
    ms.addMsg(fam, { senderId: 8, kind: 'hologram', text: 'x' });
    const { page } = await openChats(launchApp, mock);
    await page.locator(`#page-chats .cv-row[data-id="${fam}"]`).click();

    // arrival: map, ETA, live → arrived
    const a = page.locator('#page-chats .cv-arrival');
    await expect(a.locator('.cv-chip')).toHaveText(/Live/);
    await expect(a.locator('.cv-arrival-sub')).toContainText(/3,1 km|3.1 km/);
    await expect(a.locator('.cv-map-tile[src^="blob:"]').first()).toBeAttached();
    ms.update(arr.id, (m) => { m.arrival.state = 'arrived'; m.arrival.progress = 1; });
    await expect(a.locator('.cv-chip')).toHaveText(/Angekommen|Arrived/);

    // request: approve → done; another one: deny
    const r1 = page.locator(`#page-chats .cv-msg[data-id="${req.id}"] .cv-action`);
    await expect(r1.locator('.cv-rich-head')).toContainText(/Anfrage von Lena|Request from Lena/);
    await r1.locator('.btn[data-op="approve"]').click();
    await expect.poll(() => ms.log.actionOps[0]).toMatchObject({ id: req.id, op: 'approve' });
    await expect(r1).toHaveClass(/is-done/);
    await expect(r1.locator('.cv-action-state')).toHaveText(/Erledigt|Done/);
    const r2 = page.locator(`#page-chats .cv-msg[data-id="${req2.id}"] .cv-action`);
    await r2.locator('.btn[data-op="deny"]').click();
    await expect(r2).toHaveClass(/is-denied/);

    // doorbell card: picture from base64 bytes, confirmed button, Live-Bild link
    const c = page.locator(`#page-chats .cv-msg[data-id="${card.id}"] .cv-card`);
    await expect(c.locator('.cv-card-img img[src^="blob:"]')).toBeAttached();
    await expect(c.locator('.cv-text')).toHaveText('Paketbote an der Haustür');
    await c.locator('.btn[data-action="door.open"]').click();
    await page.locator('#page-chats .cv-overlay').last().locator('.btn-pri').click();
    await expect.poll(() => ms.log.actionOps.at(-1)).toMatchObject({ id: card.id, op: 'run', body: { actionId: 'door.open', plugin: 'gatecontrol-door' } });
    await expect(c.locator('.cv-card-last')).toBeVisible();
    await expect(c.locator('.cv-card-link')).toHaveAttribute('data-route', 'plg-gatecontrol-door');
    await expect(c.locator('.cv-card-link')).toHaveText('Live-Bild');
    // without the VPN there is no portal: the page says so instead of opening nothing
    await c.locator('.cv-card-link').click();
    await expect(page.getByText(/Portal ist gerade nicht erreichbar|portal cannot be reached/).first()).toBeVisible();

    // a kind this version does not know
    await expect(page.locator('#page-chats .cv-unsupported')).toHaveText(/neuere App-Version|newer app version/);
    await shot(page, '14-actions-card');

    // send a home action as a request from the attach menu
    await page.locator('#page-chats .cv-attach-btn').click();
    await page.locator('#page-chats .cv-menu-item[data-item="action:garage.open"]').click();
    const dlg = page.locator('#page-chats .cv-overlay').last();
    await dlg.locator('.cv-tabs button[data-mode="request"]').click();
    await dlg.locator('input[type=checkbox][value="8"]').check();
    await shot(page, '14-action-send');
    await dlg.locator('.btn-pri').click();
    await expect.poll(() => ms.log.sent.at(-1) && ms.log.sent.at(-1).kind).toBe('action');
    expect(ms.log.sent.at(-1).action).toEqual({ mode: 'request', actionId: 'garage.open', plugin: 'gatecontrol-garage', label: 'Garage öffnen', approverIds: [8] });
  });
});
