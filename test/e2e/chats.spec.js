'use strict';

const path = require('path');
const fs = require('fs');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Chats (GateControl Messenger): shown only when the server has the plugin;
// list, chat, sending (outbox → POST with clientId), live events on the push
// stream (new message, "schreibt …", read ticks), reactions, file upload,
// chat pushes outside the inbox, "Standort senden" (own position, a point on
// the map, an address; map previews), the pinned inbox read entry by entry,
// videos and file previews (Messenger 1.3.0), jumps with `around`, ticks from
// the read event and a released group (Messenger 1.1.0).
// Selectors by id/class, texts in both languages where needed.

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

  test('location: own position, a point on the map, an address; received ones with a map preview', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger();
    const anna = ms.addConv();
    ms.addMsg(anna, { kind: 'location', text: null, location: { lat: 48.137154, lon: 11.576124, label: 'Marienplatz', accuracy: 20 } });
    const { page, events } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-chats').click();
    await page.locator(`#page-chats .cv-row[data-id="${anna}"]`).click();

    // received: a small map (tiles from the main process as blob: images), label, coordinates
    const recv = page.locator('#page-chats .cv-msg.is-in .cv-loc').first();
    await expect(recv.locator('.cv-loc-tx b')).toHaveText('Marienplatz');
    await expect(recv.locator('.cv-loc-sub')).toContainText('48.13715, 11.57612');
    await expect(recv.locator('.cv-map-tile[src^="blob:"]').first()).toBeAttached();
    await expect(recv.locator('.cv-map-pin')).toBeVisible();
    expect(mock.requests.some((r) => /^\/osm\/15\/\d+\/\d+\.png$/.test(r.path))).toBe(true);
    await recv.locator('.cv-loc-map').click();
    await expect.poll(() => events().filter((e) => e.type === 'shell.openExternal').map((e) => e.url)).toContainEqual(expect.stringContaining('mlat=48.137154'));

    const dlg = page.locator('#page-chats .cv-overlay');
    const status = dlg.locator('.cv-loc-status');
    const label = dlg.locator('.cv-field input');
    const send = dlg.locator('.cv-dlg-foot .btn-pri');
    const geo = (mode) => page.evaluate((m) => {
      navigator.geolocation.getCurrentPosition = (ok, err) => setTimeout(() => {
        if (m === 'ok') ok({ coords: { latitude: 48.306123, longitude: 11.907123, accuracy: 25 } });
        else err({ code: m === 'denied' ? 1 : 2, message: m });
      }, 50);
    }, mode);

    // 1) own position (Windows location API via navigator.geolocation), address as label
    await geo('ok');
    await page.locator('#page-chats .cv-loc-btn').click();
    await expect(status).toHaveText(/± 25 m/);
    await expect(label).toHaveValue('Am Bahnhof 1, 85435 Erding');
    await send.click();
    await expect(dlg).toHaveCount(0);
    await expect.poll(() => ms.log.sent.length).toBe(1);
    expect(ms.log.sent[0].kind).toBe('location');
    expect(ms.log.sent[0].clientId).toMatch(/^[A-Za-z0-9_-]{8,64}$/);
    expect(ms.log.sent[0].location).toEqual({ lat: 48.306123, lon: 11.907123, label: 'Am Bahnhof 1, 85435 Erding', accuracy: 25 });
    await expect(page.locator('#page-chats .cv-msg.is-out .cv-loc .cv-loc-tx b').last()).toHaveText('Am Bahnhof 1, 85435 Erding');

    // 2) location access denied: a point on the map, own label
    await geo('denied');
    await page.locator('#page-chats .cv-loc-btn').click();
    await expect(status).toHaveAttribute('data-type', 'warn');
    await expect(status).toHaveText(/Datenschutz|Privacy/);
    await send.click();
    await expect(status).toHaveText(/Punkt auf der Karte|point on the map/);
    await dlg.locator('.cv-map').click({ position: { x: 120, y: 150 } });
    await expect(status).toHaveText(/Gewählter Punkt|Selected point/);
    await expect(dlg.locator('.cv-map-pin')).toBeVisible();
    await label.fill('Treffpunkt');
    await send.click();
    await expect.poll(() => ms.log.sent.length).toBe(2);
    const picked = ms.log.sent[1].location;
    expect(picked.label).toBe('Treffpunkt');
    expect(picked.accuracy).toBeUndefined();
    expect(Math.abs(picked.lat)).toBeLessThanOrEqual(90);
    expect(Math.abs(picked.lon)).toBeLessThanOrEqual(180);

    // 3) no position on this PC: address search
    await geo('unavailable');
    await page.locator('#page-chats .cv-loc-btn').click();
    await expect(status).toHaveText(/nicht verfügbar|not available/);
    await dlg.locator('input[type=search]').fill('Marienplatz');
    await dlg.locator('input[type=search]').press('Enter');
    await expect(dlg.locator('.cv-loc-hit')).toHaveText(['Marienplatz, 80331 München']);
    expect(mock.requests.find((r) => r.path === '/nominatim/search').query.q).toBe('Marienplatz');
    await dlg.locator('.cv-loc-hit').click();
    await expect(label).toHaveValue('Marienplatz, 80331 München');
    await send.click();
    await expect.poll(() => ms.log.sent.length).toBe(3);
    expect(ms.log.sent[2].location).toEqual({ lat: 48.137154, lon: 11.576124, label: 'Marienplatz, 80331 München' });
  });

  test('pinned inbox: entries are marked read one by one as they come into view', async ({ launchApp, mock }) => {
    // newest first, like the server's inbox; seq 101 = "Mitteilung 1" (the oldest)
    const items = Array.from({ length: 24 }, (_, i) => ({ id: 300 + i, topic: 'system', title: `Mitteilung ${i + 1}`, body: 'Zeile eins\nZeile zwei\nZeile drei' })).reverse();
    mock.setPush({ topics: [], items });
    mock.setMessenger().addConv();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-chats').click();
    await page.locator('#page-chats .cv-row.is-pinned').click();
    await expect(page.locator('#page-chats .cv-sysbub')).toHaveCount(24);
    const readSeqs = () => mock.acks().filter((a) => a.state === 'read').flatMap((a) => a.seqs);

    // opens at the first unread entry (the oldest): only what is in view is read
    await expect(page.locator('#page-chats .cv-msgs .cv-unread-line')).toBeVisible();
    await expect.poll(readSeqs).toContain(101);
    await page.waitForTimeout(800);
    expect(readSeqs()).not.toContain(124);
    expect(new Set(readSeqs()).size).toBeLessThan(24);

    // scrolling to the newest reads those as well, never everything at once
    await page.locator('#page-chats .cv-msgs').evaluate((n) => { n.scrollTop = n.scrollHeight; });
    await expect.poll(readSeqs).toContain(124);
    expect(mock.acks().filter((a) => a.state === 'read').every((a) => a.seqs.length < 24)).toBe(true);
    await expect(page.locator('#page-chats .cv-sysbub').last()).not.toHaveClass(/is-unread/);

    // entries skipped in between stay unread until "Alle als gelesen markieren"
    expect(new Set(readSeqs()).size).toBeLessThan(24);
    await expect(page.locator('#page-chats .cv-head')).not.toContainText('null');
    await page.locator('#page-chats .cv-inbox-readall').click();
    await expect.poll(() => new Set(readSeqs()).size).toBe(24);
    await expect(page.locator('#page-chats .cv-inbox-readall')).toHaveCount(0);
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

  const CLIP = path.join(__dirname, 'fixtures', 'clip.webm'); // 3 s, 320×180, VP8
  const FEATURES_13 = { direct: true, groups: true, voice: true, files: true, location: true, reactions: true, edit: true, search: true, disappearing: true, bridges: false, e2e: false, video_meta: true, file_thumbs: true };

  test('video: a frame as preview, length and size go along (Messenger 1.3.0); played in an overlay; Videos in the chat info', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_13 });
    const anna = ms.addConv();
    ms.addMsg(anna, { text: 'Zeig mal das Video' });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-chats').click();
    await page.locator(`#page-chats .cv-row[data-id="${anna}"]`).click();
    await expect(page.locator('#page-chats .cv-msg .cv-text')).toHaveText(['Zeig mal das Video']);

    await page.locator('#page-chats input[type=file][multiple]').setInputFiles(CLIP);
    await expect.poll(() => ms.log.sent.length).toBe(1);
    const sent = ms.log.sent[0];
    expect(sent.kind).toBe('file');
    // the preview is uploaded first, then the video
    expect(ms.log.uploads.map((u) => u.mime)).toEqual([expect.stringMatching(/^image\/(webp|jpeg)$/), 'video/webm']);
    expect(ms.log.uploads[0].bytes).toBeLessThanOrEqual(65536);
    expect(sent.thumbMediaId).toBe(ms.log.uploads[0].mediaId);
    expect(sent.mediaId).toBe(ms.log.uploads[1].mediaId);
    expect(sent.meta.fileName).toBe('clip.webm');
    expect(sent.video.width).toBe(320);
    expect(sent.video.height).toBe(180);
    expect(Math.abs(sent.video.durationMs - 3000)).toBeLessThan(250);

    const mine = page.locator('#page-chats .cv-msg.is-out .cv-video').last();
    await expect(mine.locator('img')).toBeAttached();
    await expect(mine.locator('.cv-video-dur')).toHaveText('0:03');
    await expect(page.locator(`#page-chats .cv-row[data-id="${anna}"] .cv-row-pv`)).toHaveText(/Video · 0:03$/);
    await mine.click();
    const player = page.locator('#page-chats .cv-player video');
    await expect(player).toBeVisible();
    await expect.poll(() => player.evaluate((v) => v.readyState)).toBeGreaterThan(0);
    await page.keyboard.press('Escape');
    await expect(player).toHaveCount(0);

    // received: a video with preview and length
    ms.receive(anna, { kind: 'file', text: null, mediaId: ms.log.uploads[1].mediaId, thumbMediaId: ms.log.uploads[0].mediaId, video: { durationMs: 65000, width: 320, height: 180 }, meta: { fileName: 'urlaub.webm' } });
    const recv = page.locator('#page-chats .cv-msg.is-in .cv-video').last();
    await expect(recv.locator('.cv-video-dur')).toHaveText('1:05');
    await expect(recv.locator('img')).toBeAttached();

    // chat info: Fotos / Videos / Dateien, Videos through kind=video
    await page.locator('#page-chats .cv-head-who').click();
    const tabs = page.locator('#page-chats .cv-media-tabs button');
    await expect(tabs).toHaveCount(3);
    await page.locator('#page-chats .cv-media-tabs button[data-kind="video"]').click();
    await expect.poll(() => ms.log.mediaLists.at(-1) && ms.log.mediaLists.at(-1).kind).toBe('video');
    await expect(page.locator('#page-chats .cv-grid-cell.is-video')).toHaveCount(2);
    await page.locator('#page-chats .cv-media-tabs button[data-kind="file"]').click();
    await expect(page.locator('#page-chats .cv-media-none')).toBeVisible();
  });

  test('video to an older Messenger: a plain file message (no preview, no video meta), still shown as a video', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger();
    const anna = ms.addConv();
    ms.addMsg(anna, { text: 'Hallo' });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-chats').click();
    await page.locator(`#page-chats .cv-row[data-id="${anna}"]`).click();
    await page.locator('#page-chats input[type=file][multiple]').setInputFiles(CLIP);
    await expect.poll(() => ms.log.sent.length).toBe(1);
    expect(ms.log.uploads.map((u) => u.mime)).toEqual(['video/webm']);
    expect(ms.log.sent[0].kind).toBe('file');
    expect(ms.log.sent[0].thumbMediaId).toBeUndefined();
    expect(ms.log.sent[0].video).toBeUndefined();
    const mine = page.locator('#page-chats .cv-msg.is-out .cv-video').last();
    await expect(mine).toBeVisible();
    await expect(mine.locator('.cv-video-dur')).toHaveCount(0);
    await page.locator('#page-chats .cv-head-who').click();
    await expect(page.locator('#page-chats .cv-media-tabs button')).toHaveCount(2);
  });

  test('jump to an old search hit (around) and back; ticks from the read event; a released group', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger();
    const anna = ms.addConv();
    const old = ms.addMsg(anna, { text: 'Treffpunkt am Brunnen' });
    for (let i = 0; i < 120; i++) ms.addMsg(anna, { text: `Nachricht ${i}` });
    const fam = ms.addConv({ kind: 'group', members: [7, 8, 9], title: 'Familie' });
    ms.addMsg(fam, { senderId: 9, text: 'Hallo zusammen' });
    ms.manage(fam, 'gatecontrol-familie');
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-chats').click();
    await page.locator(`#page-chats .cv-row[data-id="${anna}"]`).click();
    await expect(page.locator('#page-chats .cv-msg .cv-text').last()).toHaveText('Nachricht 119');

    // search → a hit far older than the loaded page → messages?around=
    await page.getByRole('button', { name: /^(Im Chat suchen|Search in chat)$/ }).click();
    await page.locator('#page-chats .cv-searchbar input').fill('Brunnen');
    await page.locator('#page-chats .cv-result').first().click();
    await expect.poll(() => ms.log.around.map((a) => a.around)).toContain(old.id);
    const hit = page.locator(`#page-chats .cv-msg[data-id="${old.id}"]`);
    await expect(hit).toBeVisible();
    await expect(hit.locator('.cv-text')).toHaveText('Treffpunkt am Brunnen');
    await expect(page.locator('#page-chats .cv-tolatest')).toBeVisible();
    // back to the newest messages
    await page.locator('#page-chats .cv-tolatest').click();
    await expect(page.locator('#page-chats .cv-msg .cv-text').last()).toHaveText('Nachricht 119');
    await expect(hit).toHaveCount(0);

    // ticks straight from the read event (no GET conversations/:id)
    const input = page.locator('#page-chats .cv-input');
    await input.fill('Bin gleich da');
    await input.press('Enter');
    const mine = page.locator('#page-chats .cv-msg.is-out').last();
    await expect(mine.locator('.cv-tick')).toHaveClass(/is-sent/);
    await page.waitForTimeout(800);
    const convGets = () => mock.requests.filter((r) => r.method === 'GET' && r.path === `/api/v1/client/plugins/gatecontrol-messenger/api/conversations/${anna}`).length;
    const before = convGets();
    ms.readBy(anna, 8, ms.messages(anna).at(-1).id);
    await expect(mine.locator('.cv-tick')).toHaveClass(/is-read/);
    await page.waitForTimeout(500);
    expect(convGets()).toBe(before);

    // the plugin hands its group over: system line, a normal group in the info
    await page.locator(`#page-chats .cv-row[data-id="${fam}"]`).click();
    await page.locator('#page-chats .cv-head-who').click();
    await expect(page.locator('#page-chats .cv-info-top .cv-dim')).toHaveText(/verwaltet von|managed by/);
    ms.release(fam);
    await expect(page.locator('#page-chats .cv-sys').last()).toHaveText(/GateControl hat die Gruppe freigegeben – sie ist jetzt eine normale Gruppe|GateControl released the group – it is a normal group now/);
    await expect(page.locator('#page-chats .cv-info-top .cv-dim')).not.toHaveText(/verwaltet von|managed by/);
    await expect(page.locator('#page-chats .cv-info-btns')).toBeVisible();
  });

  test('a server with chat functions this version does not know: a dismissible update hint, never blocking', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: { direct: true, groups: true, voice: true, files: true, location: true, reactions: true, edit: true, search: true, disappearing: true, bridges: false, e2e: false, video_meta: true, file_thumbs: true, polls: true } });
    const anna = ms.addConv();
    ms.addMsg(anna, { text: 'Hallo' });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-chats').click();
    const hint = page.locator('#page-chats .cv-hint');
    await expect(hint).toBeVisible();
    await expect(hint.locator('.cv-hint-tx')).toHaveText(/Für alle Chat-Funktionen gibt es eine neuere Version von GateControl|A newer version of GateControl is available for all chat features/);
    // the chats work as always
    await page.locator(`#page-chats .cv-row[data-id="${anna}"]`).click();
    await expect(page.locator('#page-chats .cv-msg .cv-text')).toHaveText(['Hallo']);

    // "Nach Updates suchen" → the app's update check
    const checks = mock.count('/api/v1/client/update/check');
    await hint.locator('.cv-hint-check').click();
    await expect(page.locator('#page-settings')).toHaveClass(/active/);
    await expect.poll(() => mock.count('/api/v1/client/update/check')).toBeGreaterThan(checks);

    // dismissed: gone, also for the next status (this set of features)
    await page.locator('#nav-chats').click();
    await hint.locator('.cv-hint-close').click();
    await expect(hint).toBeHidden();
    await expect.poll(() => page.evaluate(() => window.gatecontrol.chat.status().then((st) => st.updateHint))).toBeNull();
  });
});
