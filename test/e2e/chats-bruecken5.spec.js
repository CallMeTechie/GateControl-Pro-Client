'use strict';

const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');
const { FEATURES_STAGE4, FEATURES_STAGE5 } = require('./support/messenger-mock');

// Messenger 1.17 (Stufe 5 der Brücken): „Älteren Verlauf laden“ in „Verknüpfte Dienste“ (Aus / Letzte 30 Tage /
// Alles, PUT bridges/history), older messages filed in at night (conversation.update reason history: the open chat
// loads again, no toast), files of the history on request („Laden“, POST messages/:id/fetch, its refusals), the
// warning „Handy seit N Tagen nicht gesehen“ and its push (topic bridge → „Verknüpfte Dienste“), „Brücke veraltet“
// by clientOutdated. An older plugin (1.16) keeps everything as it was. Texts are checked in German.

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

const PNG = fs.readFileSync(path.join(__dirname, '..', '..', 'resources', 'icons', 'tray-connected.png'));
const LINKED_LOGIN = { id: 'login1', name: '+49 1512 0000000', state: 'connected', since: '2026-11-02T10:00:00.000Z' };
const DAY = 86400000;

function setupStage5(mock, { features = FEATURES_STAGE5 } = {}) {
  mock.setPush({ topics: [{ id: 'plugin:gatecontrol-messenger:bridge', label: 'Messenger · Verknüpfte Dienste' }], items: [] });
  const ms = mock.setMessenger({ features });
  ms.bridge.media = true;
  ms.bridge.networks[0].logins = [LINKED_LOGIN];
  ms.bridge.networks[0].consent = '2026-11-01T10:00:00.000Z';
  return ms;
}

async function openChats(launchApp, mock) {
  const launched = await launchApp();
  await setupWithApiKey(launched.page, mock);
  await lang(launched.page, 'de');
  await launched.page.locator('#nav-chats').click();
  await expect(launched.page.locator('#page-chats')).toHaveClass(/active/);
  return launched;
}

async function openLinked(page) {
  await page.locator('#page-chats .cv-list-title .cv-ib-flat').first().click();
  const set = page.locator('#page-chats .cv-settings');
  await expect(set).toBeVisible();
  await set.locator('.cv-set-item[data-section="linked"]').click();
  await expect(set.locator('.cv-set-title')).toHaveText('Verknüpfte Dienste');
  return set;
}

const chatToasts = (app) => app.evaluate(() => globalThis.__gcE2E.toasts.map((x) => x.text).join('\n---\n'));

test.describe('chats – older history, the phone and „Brücke veraltet“ over a bridge (Messenger 1.17)', () => {
  test('an older plugin (1.16): no „Älteren Verlauf laden“, no „Laden“, no phone warning — nothing asked', async ({ launchApp, mock }) => {
    const ms = setupStage5(mock, { features: FEATURES_STAGE4 });
    const kim = ms.addBridgeConv({ title: 'Kim Muster' });
    ms.addBridgeMsg(kim, { text: null, placeholder: { kind: 'image', name: 'IMG-2041.jpg', state: null } });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${kim}"]`).click();
    await cv.locator('.cv-bc-first [data-act="intro-ok"]').click();
    await expect(cv.locator('.cv-bc-ph')).toHaveText('Bild · IMG-2041.jpg – folgt; in WhatsApp ansehen');
    await expect(cv.locator('[data-act="fetch"]')).toHaveCount(0);
    const set = await openLinked(page);
    await expect(set.locator('.cv-br-row[data-net="whatsapp"]')).toHaveAttribute('data-state', 'linked');
    await expect(set.locator('[data-pref="history"]')).toHaveCount(0);
    await expect(set.locator('.cv-br-phone-row')).toHaveCount(0);
    await expect(set.locator('.cv-note-lock')).toContainText('älterer Verlauf wird nicht geladen');
    expect(ms.log.calls.some((c) => c.route === 'bridges/history' || /\/fetch$/.test(c.route))).toBe(false);
    expect(ms.log.history).toEqual([]);
    // no "newer version" banner for the words it knows
    await expect(cv.locator('.cv-hint')).toBeHidden();
  });

  test('„Verknüpfte Dienste“: older history (choice, tonight, refused, switched off), the phone, „Brücke veraltet“', async ({ launchApp, mock }) => {
    const ms = setupStage5(mock);
    ms.addMsg(ms.addConv(), { text: 'Hallo' });
    const net = ms.bridge.networks[0];
    const { page } = await openChats(launchApp, mock);
    const set = await openLinked(page);
    const reload = async () => { await set.locator('.cv-set-item[data-section="account"]').click(); await set.locator('.cv-set-item[data-section="linked"]').click(); };
    const hist = set.locator('[data-pref="history"]');
    await expect(hist.locator('b')).toHaveText('Älteren Verlauf laden');
    await expect(hist.locator('small')).toHaveText('Nur beim Verknüpfen · Letzte 30 Tage');
    await expect(hist.locator('select option')).toHaveText(['Aus', 'Letzte 30 Tage', 'Alles']);
    await expect(hist.locator('select')).toHaveValue('30');
    // below the services, above „Läuft auf“
    const order = await set.locator('.cv-br-row, [data-pref="history"], [data-pref="runsOn"]').evaluateAll((els) => els.map((e) => e.dataset.pref || 'row'));
    expect(order).toEqual(['row', 'history', 'runsOn']);
    await expect(set.locator('.cv-note-lock')).toHaveText('Chats mit Kontakten des Dienstes erscheinen in deiner Chatliste, sobald dort eine neue Nachricht eintrifft; älteren Verlauf (oben gewählt) übernimmt GateControl nachts. Texte, Antworten, Reaktionen, Bilder, Videos, Sprachnachrichten und Dateien gehen in beide Richtungen.');

    // „Alles“ → PUT bridges/history; what waits for the night
    ms.bridge.history.pending = 412;
    await hist.locator('select').selectOption('-1');
    await expect(page.locator('#toasts')).toContainText('Gespeichert – gilt beim nächsten Verknüpfen');
    await expect(hist.locator('small')).toHaveText('Nur beim Verknüpfen · Alles · 412 kommen heute Nacht');
    expect(ms.log.history).toEqual([{ days: -1 }]);
    await shots(page, 'bc5-verlauf');

    // refused: said, the choice stays as it was
    ms.bridge.historyFails = { status: 403, code: 'feature_off' };
    await hist.locator('select').selectOption('0');
    await expect(page.locator('#toasts')).toContainText('Diese Funktion ist auf dem Server ausgeschaltet.');
    await expect(hist.locator('select')).toHaveValue('-1');
    expect(ms.log.history).toEqual([{ days: -1 }, { days: 0 }]);

    // switched off by the administrator: no choice
    ms.bridge.history = { ...ms.bridge.history, available: false };
    await reload();
    await expect(hist.locator('small')).toHaveText('Auf diesem Server abgeschaltet');
    await expect(hist.locator('select')).toHaveCount(0);
    ms.bridge.history = { ...ms.bridge.history, available: true, pending: 0, days: 30 };

    // the phone was not seen: a warning under the service, the link still „Verknüpft“
    net.phone = { offline: true, days: 12, leftDays: 2 };
    await reload();
    const phone = set.locator('.cv-br-phone-row[data-net="whatsapp"]');
    await expect(phone).toHaveText('Handy seit 12 Tagen nicht gesehen. Öffne WhatsApp auf deinem Handy – nach etwa 14 Tagen ohne Handy trennt WhatsApp die Verknüpfung.');
    await expect(set.locator('.cv-br-row[data-net="whatsapp"] .cv-br-pill')).toHaveText('Verknüpft');
    await shots(page, 'bc5-handy');
    net.phone = { offline: true, days: 15, leftDays: 0 };
    await reload();
    await expect(phone).toHaveText('Handy seit 15 Tagen nicht gesehen. Öffne WhatsApp auf deinem Handy – WhatsApp kann die Verknüpfung jederzeit trennen.');
    // signed out: no phone warning (the relink row says it)
    net.logins = [{ ...LINKED_LOGIN, state: 'logged_out' }];
    await reload();
    await expect(phone).toHaveCount(0);
    net.logins = [LINKED_LOGIN];
    net.phone = { offline: false, days: null, leftDays: null };

    // WhatsApp refuses the bridge's version: shown like `outdated`
    net.clientOutdated = true;
    await reload();
    await expect(set.locator('.cv-br-row[data-net="whatsapp"] .cv-br-pill')).toHaveText('Veraltet');
    await expect(set.locator('.cv-br-warn').first()).toContainText('Brücke veraltet');
    await expect(set.locator('[data-pref="runsOn"] small')).toHaveText('Server · Brücke veraltet');
    await expect(set.locator('.cv-note', { hasText: 'Das Aktualisieren macht dein Administrator' })).toBeVisible();
    await shots(page, 'bc5-veraltet');
  });

  test('a file of the history: „älterer Verlauf“ + „Laden“ → loading → the picture; refused, gone', async ({ launchApp, mock }) => {
    const ms = setupStage5(mock);
    const kim = ms.addBridgeConv({ title: 'Kim Muster' });
    const old = ms.addBridgeMsg(kim, { text: null, placeholder: { kind: 'image', name: 'IMG-2041.jpg', state: 'on_request', reason: null } });
    const doc = ms.addBridgeMsg(kim, { text: null, placeholder: { kind: 'file', name: 'Zeugnis.pdf', state: 'on_request', reason: null } });
    const gone = ms.addBridgeMsg(kim, { text: null, placeholder: { kind: 'video', name: 'urlaub.mp4', state: 'on_request', reason: null } });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${kim}"]`).click();
    await cv.locator('.cv-bc-first [data-act="intro-ok"]').click();
    const msg = (m) => cv.locator(`.cv-msg[data-id="${m.id}"]`);
    await expect(msg(old).locator('.cv-bc-ph')).toHaveText('Bild · IMG-2041.jpg – älterer Verlauf');
    await expect(msg(old).locator('[data-act="fetch"]')).toHaveText('Laden');
    await shots(page, 'bc5-abruf');

    // „Laden“ → POST messages/:id/fetch?bridged=1 → „wird geladen …“, then the file comes by itself
    await msg(old).locator('[data-act="fetch"]').click();
    await expect(msg(old).locator('.cv-bc-ph')).toHaveText('Bild · IMG-2041.jpg – wird geladen …');
    await expect(msg(old).locator('[data-act="fetch"]')).toHaveCount(0);
    expect(ms.log.fetches).toEqual([old.id]);
    const call = ms.log.calls.find((c) => c.route === `messages/${old.id}/fetch`);
    expect([call.method, call.query.bridged]).toEqual(['POST', '1']);
    ms.bridgeFileArrived(old.id, { kind: 'image', mediaId: ms.addMedia('image/png', PNG), meta: { w: 1, h: 1 } });
    await expect(msg(old).locator('.cv-img img')).toBeVisible();
    await expect(msg(old).locator('.cv-bc-ph')).toHaveCount(0);

    // nothing to fetch any more (400 invalid) / no connection: said, „Laden“ stays
    ms.bridge.fetchFails = { status: 400, code: 'invalid' };
    await msg(doc).locator('[data-act="fetch"]').click();
    await expect(page.locator('#toasts')).toContainText('Diese Datei lässt sich nicht mehr anfordern.');
    await expect(msg(doc).locator('[data-act="fetch"]')).toBeEnabled();
    ms.bridge.fetchFails = { status: 503, code: 'bridge_unreachable' };
    await msg(doc).locator('[data-act="fetch"]').click();
    await expect.poll(() => ms.log.fetches.length).toBe(3);
    await expect(msg(doc).locator('[data-act="fetch"]')).toBeEnabled();
    await expect(msg(doc).locator('.cv-bc-ph')).toHaveText('Datei · Zeugnis.pdf – älterer Verlauf');

    // very old: WhatsApp has it no more
    await msg(gone).locator('[data-act="fetch"]').click();
    await expect(msg(gone).locator('.cv-bc-ph')).toHaveAttribute('data-state', 'loading');
    ms.bridgeFileArrived(gone.id, { fail: { reason: 'gone' } });
    await expect(msg(gone).locator('.cv-bc-ph')).toHaveText('Video · urlaub.mp4 – bei WhatsApp nicht mehr abrufbar – in WhatsApp ansehen');
    await expect(msg(gone).locator('[data-act="fetch"]')).toHaveCount(0);
  });

  test('older messages at night: the open chat loads again (no toast), another chat shows them when opened', async ({ launchApp, mock }) => {
    const ms = setupStage5(mock);
    const kim = ms.addBridgeConv({ title: 'Kim Muster' });
    const first = ms.addBridgeMsg(kim, { text: 'Bis Samstag!' });
    first.createdAt = Date.now() - 3 * DAY;
    const group = ms.addBridgeConv({ kind: 'group', title: 'Elternrunde 4b' });
    const g0 = ms.addBridgeMsg(group, { contact: { contactId: 14, name: 'Robin' }, text: 'Wer bringt Kuchen mit?' });
    g0.createdAt = Date.now() - 5 * DAY;
    const { app, page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${kim}"]`).click();
    await cv.locator('.cv-bc-first [data-act="intro-ok"]').click();
    await expect(cv.locator('.cv-msg .cv-text')).toHaveText(['Bis Samstag!']);
    const toastsBefore = await chatToasts(app);

    ms.historyArrived(kim, [
      { text: 'Hast du die Fotos?', at: Date.now() - 2 * DAY },
      { text: null, placeholder: { kind: 'image', name: 'IMG-2041.jpg', state: 'on_request' }, at: Date.now() - 2 * DAY + 60000 },
    ]);
    await expect(cv.locator('.cv-msg .cv-text')).toHaveText(['Bis Samstag!', 'Hast du die Fotos?']);
    await expect(cv.locator('.cv-bc-ph')).toHaveText('Bild · IMG-2041.jpg – älterer Verlauf');
    await expect(cv.locator('.cv-row-pv').first()).toBeVisible();
    expect(await chatToasts(app)).toBe(toastsBefore);
    await shots(page, 'bc5-verlauf-chat');

    // a chat that is not open: its messages come when it opens
    ms.historyArrived(group, [{ contact: { contactId: 15, name: 'Sam' }, text: 'Elternabend ist am Dienstag', at: Date.now() - 4 * DAY }]);
    await cv.locator(`.cv-row[data-id="${group}"]`).click();
    await expect(cv.locator('.cv-msg .cv-text')).toHaveText(['Wer bringt Kuchen mit?', 'Elternabend ist am Dienstag']);
    expect(await chatToasts(app)).toBe(toastsBefore);
  });

  test('the push „WhatsApp: Handy seit 12 Tagen nicht gesehen“: a toast, its click opens „Verknüpfte Dienste“', async ({ launchApp, mock }) => {
    const ms = setupStage5(mock);
    ms.addMsg(ms.addConv(), { text: 'Hallo' });
    const { app, page, clickToast } = await openChats(launchApp, mock);
    await page.locator('.nav[data-page="status"]').click();
    ms.bridge.networks[0].phone = { offline: true, days: 12, leftDays: 2 };
    mock.pushNotification({
      topic: 'plugin:gatecontrol-messenger:bridge', title: 'WhatsApp: Handy seit 12 Tagen nicht gesehen',
      body: 'Öffne WhatsApp auf deinem Handy, sonst trennt WhatsApp die Verknüpfung mit GateControl in wenigen Tagen.',
      collapse_key: 'bridge-phone-whatsapp', data: { deepLink: 'bridges', bridge: 'whatsapp' },
    });
    await expect.poll(() => chatToasts(app), { timeout: 20000 }).toContain('Handy seit 12 Tagen nicht gesehen');
    expect(await clickToast('Handy seit 12 Tagen nicht gesehen')).toBe(true);
    await expect(page.locator('#page-chats')).toHaveClass(/active/);
    const set = page.locator('#page-chats .cv-settings');
    await expect(set.locator('.cv-set-title')).toHaveText('Verknüpfte Dienste');
    await expect(set.locator('.cv-br-phone-row[data-net="whatsapp"]')).toContainText('Handy seit 12 Tagen nicht gesehen');
    // with „Verknüpfte Dienste“ open, the next push shows the new state at once
    ms.bridge.networks[0].phone = { offline: true, days: 14, leftDays: 0 };
    mock.pushNotification({
      topic: 'plugin:gatecontrol-messenger:bridge', title: 'WhatsApp: Handy seit 14 Tagen nicht gesehen', body: '',
      collapse_key: 'bridge-phone-whatsapp', data: { deepLink: 'bridges', bridge: 'whatsapp' },
    });
    await expect(set.locator('.cv-br-phone-row[data-net="whatsapp"]')).toContainText('WhatsApp kann die Verknüpfung jederzeit trennen');
    await shots(page, 'bc5-push');
    // the inbox keeps the entry
    await page.locator('#nav-inbox').click();
    await expect(page.locator('#inbox-list .inbox-row', { hasText: 'Handy seit 14 Tagen nicht gesehen' })).toBeVisible();
  });
});
