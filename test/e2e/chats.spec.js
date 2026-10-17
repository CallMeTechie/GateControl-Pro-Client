'use strict';

const path = require('path');
const fs = require('fs');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Chats (GateControl Messenger): shown only when the server has the plugin;
// list, chat, sending (outbox → POST with clientId), live events on the push
// stream (new message, "schreibt …", read ticks), reactions, file upload,
// chat pushes outside the inbox. Selectors by id/class, texts in both
// languages where needed.

test.describe('chats', () => {
  test('no Messenger plugin on the server: no "Chats" entry', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.count('/api/v1/client/plugins')).toBeGreaterThan(0);
    await expect(page.locator('#nav-chats')).toBeHidden();
  });

  test('list, open, send, live message, typing, read ticks, reaction', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [{ id: 51, topic: 'system', title: 'Klingel: Haustür', body: 'Es hat geklingelt.' }] });
    const ms = mock.setMessenger();
    const anna = ms.addConv();
    ms.addMsg(anna, { text: 'Bist du schon unterwegs?' });
    const family = ms.addConv({ kind: 'group', members: [7, 8, 9], title: 'Familie' });
    ms.addMsg(family, { senderId: 9, text: 'Wer holt mich ab?' });

    const { page, trayLabels } = await launchApp();
    await setupWithApiKey(page, mock);

    await expect(page.locator('#nav-chats')).toBeVisible();
    await expect(page.locator('#chats-badge')).toHaveText('2');
    await expect.poll(trayLabels).toContainEqual(expect.stringMatching(/^Chats · 2 (neu|new)$/));

    await page.locator('#nav-chats').click();
    await expect(page.locator('#page-chats')).toHaveClass(/active/);
    const rows = page.locator('#page-chats .cv-row');
    // pinned "GateControl" (inbox) + 2 chats
    await expect(rows).toHaveCount(3);
    await expect(rows.first()).toHaveClass(/is-pinned/);
    await expect(rows.first().locator('.cv-row-pv')).toHaveText('Klingel: Haustür');
    await expect(page.locator('#page-chats .cv-row[data-id] .cv-row-name')).toHaveText(['Familie', 'Anna']);

    // open Anna: messages, read mark + "active"
    await page.locator(`#page-chats .cv-row[data-id="${anna}"]`).click();
    await expect(page.locator('#page-chats .cv-head-tx b')).toHaveText('Anna');
    await expect(page.locator('#page-chats .cv-msg .cv-text')).toHaveText(['Bist du schon unterwegs?']);
    await expect.poll(() => ms.log.reads.some((r) => r.conversationId === anna)).toBe(true);
    await expect.poll(() => ms.log.actives.some((a) => a.conversationId === anna)).toBe(true);
    await expect(page.locator('#chats-badge')).toHaveText('1');

    // send: Enter → POST with clientId, appears with a tick
    const input = page.locator('#page-chats .cv-input');
    await input.fill('Gleich, noch 10 Minuten');
    await input.press('Enter');
    await expect.poll(() => ms.log.sent.map((s) => s.text)).toEqual(['Gleich, noch 10 Minuten']);
    expect(ms.log.sent[0].clientId).toMatch(/^[A-Za-z0-9_-]{8,64}$/);
    const mine = page.locator('#page-chats .cv-msg.is-out').last();
    await expect(mine.locator('.cv-text')).toHaveText('Gleich, noch 10 Minuten');
    await expect(mine.locator('.cv-tick')).toHaveClass(/is-sent/);
    await expect.poll(() => ms.log.typings.length).toBeGreaterThan(0);

    // live: Anna reads (blue ticks), types, answers
    const myId = ms.messages(anna).at(-1).id;
    ms.readBy(anna, 8, myId);
    await expect(mine.locator('.cv-tick')).toHaveClass(/is-read/);
    ms.typing(anna, 8);
    await expect(page.locator('#page-chats .cv-head-sub')).toHaveText(/schreibt|typing/);
    ms.receive(anna, { text: 'Kannst du Milch mitbringen?' });
    await expect(page.locator('#page-chats .cv-msg.is-in .cv-text').last()).toHaveText('Kannst du Milch mitbringen?');
    await expect(page.locator('#page-chats .cv-head-sub')).not.toHaveText(/schreibt|typing/);

    // reaction through the message menu
    await page.locator('#page-chats .cv-msg.is-in .cv-bub').last().click({ button: 'right' });
    await page.locator('#page-chats .cv-menu-emojis button').first().click();
    await expect.poll(() => ms.log.reactions.length).toBe(1);
    await expect(page.locator('#page-chats .cv-msg.is-in .cv-react').last()).toContainText('👍');

    // reply: quote travels as replyTo
    await page.locator('#page-chats .cv-msg.is-in .cv-bub').last().dblclick();
    await expect(page.locator('#page-chats .cv-replybar')).toBeVisible();
    await input.fill('Klar!');
    await input.press('Enter');
    await expect.poll(() => ms.log.sent.at(-1) && ms.log.sent.at(-1).replyTo).toBe(ms.messages(anna).find((m) => m.text === 'Kannst du Milch mitbringen?').id);
    await expect(page.locator('#page-chats .cv-msg.is-out').last().locator('.cv-quote')).toContainText('Kannst du Milch mitbringen?');
  });

  test('file upload: raw PUT, then the message with the media id; open the pinned inbox', async ({ launchApp, mock }, testInfo) => {
    mock.setPush({ topics: [], items: [{ id: 61, topic: 'system', title: 'Update verfügbar', body: 'GateControl 1.177.0' }] });
    const ms = mock.setMessenger();
    const anna = ms.addConv();
    ms.addMsg(anna, { text: 'Schick mir den Brief' });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-chats').click();
    await page.locator(`#page-chats .cv-row[data-id="${anna}"]`).click();

    const file = testInfo.outputPath('Elternbrief.pdf');
    fs.writeFileSync(file, '%PDF-1.4 e2e');
    await page.locator('#page-chats input[type=file][multiple]').setInputFiles(file);
    await expect.poll(() => ms.log.uploads.map((u) => u.mime)).toEqual(['application/pdf']);
    await expect.poll(() => ms.log.sent.at(-1) && ms.log.sent.at(-1).kind).toBe('file');
    expect(ms.log.sent.at(-1).mediaId).toBe(ms.log.uploads[0].mediaId);
    expect(ms.log.sent.at(-1).meta.fileName).toBe(path.basename(file));
    await expect(page.locator('#page-chats .cv-file b').last()).toHaveText('Elternbrief.pdf');
    await expect(page.locator('#page-chats .cv-file-badge').last()).toHaveText('PDF');

    // pinned "GateControl": the inbox as a chat, reading it marks it read
    await page.locator('#page-chats .cv-row.is-pinned').click();
    await expect(page.locator('#page-chats .cv-sysbub .cv-sys-title')).toHaveText(['Update verfügbar']);
    await expect.poll(() => mock.acks().some((a) => a.state === 'read')).toBe(true);
  });

  test('a chat push stays out of the inbox', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger();
    const anna = ms.addConv();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect(page.locator('#nav-chats')).toBeVisible();
    await expect.poll(() => mock.pushStreams()).toBe(1);
    const m = ms.receive(anna, { text: 'Hallo vom Handy' });
    mock.pushChat({
      title: 'Anna', body: 'Hallo vom Handy', collapse_key: `plugin:gatecontrol-messenger:chat:${anna}`,
      data: {
        route: 'plg-gatecontrol-messenger', messageId: m.id, conversation: { id: String(anna), title: null, isGroup: false },
        sender: { id: 8, name: 'Anna', avatarUrl: null },
        actions: [
          { id: 'reply', label: 'Antworten', type: 'reply', path: `conversations/${anna}/messages` },
          { id: 'mark_read', label: 'Gelesen', type: 'mark_read', path: `conversations/${anna}/read`, body: { upTo: m.id } },
        ],
      },
    });
    await expect(page.locator('#chats-badge')).toHaveText('1');
    await expect.poll(() => mock.acks().some((a) => a.state === 'delivered')).toBe(true);
    await page.locator('#nav-inbox').click();
    await expect(page.locator('#inbox-list .inbox-row')).toHaveCount(0);
    await expect(page.locator('#inbox-badge')).toBeHidden();
  });
});
