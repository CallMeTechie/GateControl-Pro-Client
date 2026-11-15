'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');
const { FEATURES_STAGE4C, FEATURES_V2A } = require('./support/messenger-mock');

// Messenger 1.20 (Chats v2, Teil A): WhatsApp channels on a page of their own (entry „Kanäle“ above the list, the page,
// the channel read only with its bell, bar and „Nur lesen“), groups where only admins write, format and clickable
// addresses in every chat (opened in the browser), link previews, the own reaction in a channel with its note and
// „Reagieren geht in Kanälen nicht“, „Erneut versuchen“ at a bridged file that failed, the messengers' logos instead of
// „WA“, „Mein Profil“ in the menu of the own picture. An older plugin (1.18) keeps the channel in the list. Texts are
// checked in German.

const SHOTS = process.env.GC_E2E_SHOTS || null;
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` }); };
const theme = (page, th) => page.evaluate((x) => { if (x === 'light') document.documentElement.setAttribute('data-theme', 'light'); else document.documentElement.removeAttribute('data-theme'); }, th);
const lang = (page, l) => page.evaluate((x) => window.gatecontrol.locale.set(x), l);
async function shots(page, name) {
  if (!SHOTS) return;
  for (const l of ['de', 'en']) {
    await lang(page, l);
    for (const th of ['dark', 'light']) {
      await theme(page, th);
      await page.waitForTimeout(150);
      await shot(page, `${name}-${th}-${l}`);
    }
  }
  await lang(page, 'de');
  await theme(page, 'dark');
}

const LINKED_LOGIN = { id: 'login1', name: '+49 1512 0000000', state: 'connected', since: '2026-11-02T10:00:00.000Z' };
const POST = 'Jetzt patchen: Für die Router-Serie X200 gibt es ein Update.\nDetails: https://sicherheit-kompakt.example/news/x200.';

function setup(mock, { features = FEATURES_V2A } = {}) {
  mock.setPush({ topics: [], items: [] });
  const ms = mock.setMessenger({ features });
  ms.bridge.networks[0].logins = [LINKED_LOGIN];
  ms.bridge.networks[0].consent = '2026-11-01T10:00:00.000Z';
  const kim = ms.addBridgeConv({ title: 'Kim Muster' });
  ms.addBridgeMsg(kim, { text: 'Schau mal www.beispiel.example/seite, *fett*', marks: [{ type: 'bold', start: 0, end: 9 }] });
  const chan = ms.addBridgeConv({ title: 'Sicherheit kompakt', channel: true });
  ms.addBridgeMsg(chan, { post: true, text: 'Willkommen im Kanal' });
  const mid = POST.indexOf('X200');
  ms.addBridgeMsg(chan, { post: true, text: POST, marks: [{ type: 'bold', start: 0, end: 13 }, { type: 'italic', start: mid, end: mid + 4 }],
    preview: { url: 'https://sicherheit-kompakt.example/news/x200', title: 'Kritische Lücke in VPN-Router X200', description: 'Angreifer können ohne Anmeldung Befehle ausführen.', site: 'sicherheit-kompakt.example', image: { mediaId: null, url: null, mime: 'image/jpeg', w: 640, h: 360, state: 'loading' } } });
  const admins = ms.addBridgeConv({ kind: 'group', title: 'Elternbeirat', readOnly: true });
  ms.addBridgeMsg(admins, { text: 'Treffen am Montag', contact: { contactId: 21, name: 'Frau Berg' } });
  return { ms, kim, chan, admins };
}

async function openChats(launchApp, mock) {
  const launched = await launchApp();
  await setupWithApiKey(launched.page, mock);
  await lang(launched.page, 'de');
  await launched.page.locator('#nav-chats').click();
  await expect(launched.page.locator('#page-chats')).toHaveClass(/active/);
  return launched;
}

test.describe('chats – WhatsApp channels, admins-only groups, format and links (Messenger 1.20)', () => {
  test('an older plugin (1.18): the channel stays a chat in the list, no entry „Kanäle“, no GET channels', async ({ launchApp, mock }) => {
    const { ms, chan } = setup(mock, { features: FEATURES_STAGE4C });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await expect(cv.locator(`.cv-row[data-id="${chan}"]`)).toBeVisible();
    await expect(cv.locator('.cv-row-chan')).toHaveCount(0);
    expect(ms.log.calls.some((c) => c.route === 'channels')).toBe(false);
    expect(ms.log.calls.filter((c) => c.route === 'conversations').every((c) => c.query.channels === undefined)).toBe(true);
    // the logo instead of „WA“
    await expect(cv.locator(`.cv-row[data-id="${chan}"] .cv-net-mark.is-net-whatsapp svg`)).toHaveCount(1);
    await expect(cv.locator('.cv-hint')).toBeHidden();
  });

  test('the entry „Kanäle“, the page, the channel read only with its bell, the preview, links, the own reaction', async ({ launchApp, mock }) => {
    const { ms, kim, chan, admins } = setup(mock);
    const { page, events } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    const entry = cv.locator('.cv-row-chan');
    await expect(entry).toBeVisible();
    await expect(entry.locator('.cv-row-name')).toHaveText('Kanäle');
    await expect(entry.locator('.cv-row-pv')).toHaveText('2 neue Beiträge');
    await expect(entry.locator('.cv-dot')).toHaveCount(1);
    await expect(entry).toHaveAttribute('aria-label', 'Kanäle, neue Beiträge');
    // the first row; the channel is not in the list, nor in the count
    await expect(cv.locator('.cv-rows > .cv-row').first()).toHaveClass(/cv-row-chan/);
    await expect(cv.locator(`.cv-row[data-id="${chan}"]`)).toHaveCount(0);
    await expect(cv.locator(`.cv-row[data-id="${kim}"]`)).toBeVisible();
    await expect(cv.locator('.cv-count')).toHaveText('2');
    expect(ms.log.calls.find((c) => c.route === 'conversations').query).toMatchObject({ bridged: '1', channels: '1' });
    // logos: at the picture and on the source chip
    await expect(cv.locator(`.cv-row[data-id="${kim}"] .cv-net-mark.is-net-whatsapp`)).toHaveAttribute('aria-label', 'über WhatsApp');
    await expect(cv.locator('.cv-chip-btn[data-filter="net:whatsapp"] .cv-chip-net svg')).toHaveCount(1);
    await expect(cv.locator('.cv-chip-btn[data-filter="gc"] .cv-chip-net.is-net-gatecontrol')).toHaveCount(1);
    await shots(page, 'v2a-liste');

    // the page „Kanäle“
    await entry.click();
    await expect(cv.locator('.cv-chan-head b')).toHaveText('Kanäle');
    await expect(cv.locator('.cv-chan-head small')).toHaveText('WhatsApp');
    const row = cv.locator(`.cv-row[data-id="${chan}"]`);
    await expect(row.locator('.cv-row-pv')).toHaveText(/^Jetzt patchen: Für die Router-Serie X200/);
    await expect(row.locator('.cv-row-muted')).toHaveCount(1);
    await expect(row.locator('.cv-badge.is-muted')).toHaveText('2');
    await expect(cv.locator('.cv-chan-hint')).toHaveText('Benachrichtigungen sind für Kanäle aus. Die Glocke im Kanal schaltet sie ein.');
    await expect(cv.locator(`.cv-row[data-id="${kim}"]`)).toHaveCount(0);
    await shots(page, 'v2a-kanaele');

    // the channel
    await row.click();
    const head = cv.locator('.cv-head');
    await expect(head.locator('.cv-head-sub')).toHaveText('Kanal · WhatsApp');
    const bell = head.locator('.cv-chan-bell');
    await expect(bell).toHaveAttribute('aria-label', 'Benachrichtigungen für diesen Kanal einschalten');
    await expect(cv.locator('.cv-chan-bar .cv-bc-tx')).toHaveText('Ein Kanal von WhatsApp. Hier liest du nur mit, Beiträge schreibt der Kanal. Benachrichtigungen sind für diesen Kanal aus.');
    await expect(cv.locator('.cv-bc-first')).toHaveCount(0);
    await expect(cv.locator('.cv-composer .cv-readonly[data-block="channel"]')).toHaveText('Nur lesen. In Kanälen schreibt nur der Kanal.');
    await expect(cv.locator('.cv-composer textarea')).toHaveCount(0);
    const bub = cv.locator('.cv-msg').last();
    await expect(bub.locator('.cv-sender')).toHaveCount(0);
    await expect(bub.locator('.cv-lp b')).toHaveText('Kritische Lücke in VPN-Router X200');
    await expect(bub.locator('.cv-lp small')).toHaveText('sicherheit-kompakt.example');
    await expect(bub.locator('.cv-lp-wait')).toHaveText('Bild wird geladen …');
    await expect(bub.locator('.cv-text b.cv-mk-bold')).toHaveText('Jetzt patchen');
    await expect(bub.locator('.cv-text i.cv-mk-italic')).toHaveText('X200');
    // the address without the full stop at its end
    await expect(bub.locator('.cv-text .cv-link')).toHaveText('https://sicherheit-kompakt.example/news/x200');
    await shots(page, 'v2a-kanal');
    await bub.locator('.cv-text .cv-link').click();
    await expect.poll(() => events().filter((e) => e.type === 'shell.openExternal').map((e) => e.url)).toContain('https://sicherheit-kompakt.example/news/x200');
    await bub.locator('.cv-lp').click();
    await expect.poll(() => events().filter((e) => e.type === 'shell.openExternal').length).toBe(2);

    // the bell: pushes on → the bar without the hint
    await cv.locator('.cv-chan-bar [data-act="bell-on"]').click();
    await expect.poll(() => ms.log.notifies).toEqual([{ id: chan, notify: 'all' }]);
    await expect(head.locator('.cv-chan-bell')).toHaveAttribute('aria-label', 'Benachrichtigungen für diesen Kanal ausschalten');
    await expect(cv.locator('.cv-chan-bar .cv-bc-tx')).toHaveText('Ein Kanal von WhatsApp. Hier liest du nur mit, Beiträge schreibt der Kanal.');
    await head.locator('.cv-chan-bell').click();
    await expect.poll(() => ms.log.notifies.length).toBe(2);
    expect(ms.log.notifies[1]).toEqual({ id: chan, notify: 'none' });

    // the own reaction: no „Antworten“ in the menu, the note under the bubble
    await bub.locator('.cv-bub').click({ button: 'right' });
    const menu = cv.locator('.cv-menu');
    await expect(menu.locator('.cv-menu-emojis button')).toHaveCount(6);
    await expect(menu.locator('.cv-menu-item', { hasText: 'Antworten' })).toHaveCount(0);
    await menu.locator('.cv-menu-emojis button').first().click();
    await expect.poll(() => ms.log.reactions.length).toBe(1);
    await expect(cv.locator('.cv-chan-note[data-note="reactions"] span')).toHaveText('Reaktionen anderer zeigt WhatsApp nur in der WhatsApp-App. Hier siehst du deine eigene.');
    await shots(page, 'v2a-reaktion');

    // the bridge refused one: reacting in channels off
    ms.setBridgeState(chan, { reactions: 'off' });
    await expect.poll(async () => {
      await bub.locator('.cv-bub').click({ button: 'right' });
      const n = await cv.locator('.cv-menu .cv-menu-emojis').count();
      await page.keyboard.press('Escape');
      return n;
    }).toBe(0);

    // back to the list: an admins-only group stays a chat, „Nur Admins“ instead of the composer, a link in a GC chat
    await cv.locator('.cv-chan-head .cv-ib').click();
    await expect(cv.locator('.cv-row-chan')).toBeVisible();
    await cv.locator(`.cv-row[data-id="${admins}"]`).click();
    const ok = cv.locator('.cv-bc-first [data-act="intro-ok"]');
    if (await ok.count()) await ok.click();
    await expect(cv.locator('.cv-composer .cv-readonly[data-block="admins_only"]')).toHaveText('Nur Admins schreiben in dieser Gruppe.');
    await expect(cv.locator('.cv-bc-state')).toHaveCount(0);
    await shots(page, 'v2a-nur-admins');
    await cv.locator(`.cv-row[data-id="${kim}"]`).click();
    const kimText = cv.locator('.cv-msg').last().locator('.cv-text');
    await expect(kimText.locator('.cv-link')).toHaveText('www.beispiel.example/seite');
    await expect(kimText.locator('b.cv-mk-bold')).toHaveText('Schau mal');
    await kimText.locator('.cv-link').click();
    await expect.poll(() => events().filter((e) => e.type === 'shell.openExternal').map((e) => e.url)).toContain('https://www.beispiel.example/seite');
    // a GateControl chat: the address is a link as well, the text is never HTML
    const anna = ms.addConv();
    ms.receive(anna, { text: '<b>kein HTML</b> siehe https://gatecontrol.example/hilfe' });
    await cv.locator(`.cv-row[data-id="${anna}"]`).click();
    const annaText = cv.locator('.cv-msg').last().locator('.cv-text');
    await expect(annaText).toHaveText('<b>kein HTML</b> siehe https://gatecontrol.example/hilfe');
    await expect(annaText.locator('b')).toHaveCount(0);
    await expect(annaText.locator('.cv-link')).toHaveText('https://gatecontrol.example/hilfe');
  });

  test('a bridged file that failed with retry: „Erneut versuchen“ → POST messages/:id/fetch', async ({ launchApp, mock }) => {
    const { ms, kim } = setup(mock);
    const m = ms.addBridgeMsg(kim, { text: null, placeholder: { kind: 'image', name: 'IMG-1.jpg', state: 'failed', reason: 'unavailable', retry: true } });
    ms.addBridgeMsg(kim, { text: null, placeholder: { kind: 'image', name: 'IMG-2.jpg', state: 'failed', reason: 'too_large' } });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${kim}"]`).click();
    const ok = cv.locator('.cv-bc-first [data-act="intro-ok"]');
    if (await ok.count()) await ok.click();
    await expect(cv.locator('.cv-head')).not.toContainText('null');
    const retry = cv.locator('[data-act="retry-file"]');
    await expect(retry).toHaveCount(1);
    await expect(retry).toHaveText('Erneut versuchen');
    await shots(page, 'v2a-retry');
    await retry.click();
    await expect.poll(() => ms.log.fetches).toEqual([m.id]);
    await expect(cv.locator(`.cv-msg[data-id="${m.id}"] .cv-bc-ph`)).toHaveAttribute('data-state', 'loading');
    await expect(retry).toHaveCount(0);
  });

  test('„Mein Profil“ in the menu of the own picture (no portal reachable: said)', async ({ launchApp, mock }) => {
    setup(mock);
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator('.cv-me').click();
    const item = cv.locator('.cv-menu-item[data-item="profile"]');
    await expect(item).toHaveText('Mein Profil');
    await expect(cv.locator('.cv-menu-item[data-item="status"]')).toHaveText('Dein Status');
    await item.click();
    await expect(page.locator('#toasts')).toContainText('Das Portal ist gerade nicht erreichbar');
  });
});
