'use strict';

const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');
const { FEATURES_BRIDGED, FEATURES_STAGE4 } = require('./support/messenger-mock');

// Messenger 1.15 / 1.16 (Stufe 4 der Brücken): files in chats over a bridge (only with `bridge.supports` /
// `mediaTypes`: paper clip, picture, file, the mic only for a type WhatsApp takes, 423 scan_pending sent again,
// a refused type), files coming in (loading, failed with the reason, a location on the map, then the file), the
// pictures of contacts, and the dialog „Neuer WhatsApp-Chat“ per phone number with all its states. An older plugin
// (1.14) keeps everything as it was. Texts are checked in German (the page is switched to it).

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

// a small real PNG (the tray icon)
const PNG = fs.readFileSync(path.join(__dirname, '..', '..', 'resources', 'icons', 'tray-connected.png'));
const LINKED_LOGIN = { id: 'login1', name: '+49 1512 0000000', state: 'connected', since: '2026-11-02T10:00:00.000Z' };

async function openChats(launchApp, mock) {
  const { page, app } = await launchApp();
  await setupWithApiKey(page, mock);
  await lang(page, 'de');
  await page.locator('#nav-chats').click();
  await expect(page.locator('#page-chats')).toHaveClass(/active/);
  return { page, app };
}

/**
 * A file picked with the paper clip (the file input's `change`, as the picker gives it). Playwright's setInputFiles
 * did not reach the hidden input reliably here after several re-renders of the composer.
 */
const pick = (page, name, type, bytes) => page.evaluate(([b64, n, ty]) => {
  const data = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const dt = new DataTransfer();
  dt.items.add(new File([data], n, { type: ty }));
  const input = document.querySelector('#page-chats input[type=file][multiple]');
  input.files = dt.files;
  input.dispatchEvent(new Event('change'));
}, [Buffer.from(bytes).toString('base64'), name, type]);

/** What MediaRecorder says it can record (Chromium: WebM; `mp4` adds audio/mp4). */
const recorder = (page, mp4) => page.evaluate((x) => {
  window.MediaRecorder.isTypeSupported = (m) => m.startsWith('audio/webm') || (x && m === 'audio/mp4');
}, mp4);

function setupStage4(mock, { features = FEATURES_STAGE4, media = true } = {}) {
  mock.setPush({ topics: [], items: [] });
  const ms = mock.setMessenger({ features });
  ms.bridge.media = media;
  ms.bridge.networks[0].logins = [LINKED_LOGIN];
  ms.bridge.networks[0].consent = '2026-11-01T10:00:00.000Z';
  return ms;
}

test.describe('chats – files, pictures and a new chat by number over a bridge (Messenger 1.15 / 1.16)', () => {
  test('an older plugin (1.14): text only, no paper clip, no mic, no „WhatsApp-Chat mit Nummer“', async ({ launchApp, mock }) => {
    const ms = setupStage4(mock, { features: FEATURES_BRIDGED, media: false });
    const marc = ms.addConv();
    ms.addMsg(marc, { text: 'Hallo' });
    const kim = ms.addBridgeConv({ title: 'Kim Muster' });
    ms.addBridgeMsg(kim, { text: 'Grillfoto', placeholder: { kind: 'image', name: 'grill.jpg' } });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await recorder(page, true);
    await cv.locator(`.cv-row[data-id="${kim}"]`).click();
    await expect(cv.locator('.cv-input')).toHaveAttribute('placeholder', 'Nachricht über WhatsApp');
    await expect(cv.locator('.cv-row-compose [aria-label="Datei oder Foto anhängen"]')).toHaveCount(0);
    await expect(cv.locator('.cv-row-compose [aria-label="Sprachnachricht aufnehmen"]')).toHaveCount(0);
    await expect(cv.locator('.cv-bc-ph')).toHaveText('Bild · grill.jpg – folgt; in WhatsApp ansehen');
    await cv.locator('.cv-bc-first [data-act="intro-ok"]').click();
    await cv.locator('[aria-label="Neuer Chat"]').click();
    await expect(cv.locator('.cv-dlg .cv-person').first()).toBeVisible();
    await expect(cv.locator('.cv-nc-row')).toHaveCount(0);
    expect(ms.log.calls.some((c) => c.route.startsWith('bridges'))).toBe(false);
  });

  test('files out: paper clip, picture and file, scan_pending sent again, a type WhatsApp does not take, the mic only for MP4', async ({ launchApp, mock }) => {
    const ms = setupStage4(mock);
    const marc = ms.addConv();
    ms.addMsg(marc, { text: 'Hallo' });
    const kim = ms.addBridgeConv({ title: 'Kim Muster' });
    ms.addBridgeMsg(kim, { text: 'Schick mal das Foto' });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await recorder(page, false);
    await cv.locator(`.cv-row[data-id="${kim}"]`).click();
    const first = cv.locator('.cv-bc-first');
    await expect(first.locator('li').nth(1)).toHaveText('Text, Bilder, Videos, Sprachnachrichten und Dateien gehen in beide Richtungen – mit Antworten, Reaktionen, Bearbeiten und Löschen.');
    await first.locator('[data-act="intro-ok"]').click();
    await expect(cv.locator('.cv-row-compose [aria-label="Datei oder Foto anhängen"]')).toBeVisible();
    // Chromium records WebM, WhatsApp takes none: no mic here — but in a GateControl chat as before
    await expect(cv.locator('.cv-row-compose [aria-label="Sprachnachricht aufnehmen"]')).toHaveCount(0);
    await cv.locator(`.cv-row[data-id="${marc}"]`).click();
    await expect(cv.locator('.cv-row-compose [aria-label="Sprachnachricht aufnehmen"]')).toBeVisible();
    await recorder(page, true);
    await cv.locator(`.cv-row[data-id="${kim}"]`).click();
    await expect(cv.locator('.cv-row-compose [aria-label="Sprachnachricht aufnehmen"]')).toBeVisible();
    await shots(page, 'bc4-eingabe');

    // a picture (the virus scan is still running twice: sent again with the same clientId, uploaded once)
    ms.bridge.scanPending = 2;
    await pick(page, 'grill.png', 'image/png', PNG);
    await expect.poll(() => ms.log.sent.filter((s) => s.kind === 'image').length, { timeout: 30000 }).toBe(1);
    expect(ms.log.scanPending).toBe(2);
    expect(ms.log.uploads.filter((u) => u.mime === 'image/webp').length).toBe(2); // the picture and its preview, once
    await expect(cv.locator('.cv-msg.is-out .cv-img').last()).toBeVisible();

    // a PDF, then a video WhatsApp does not take (WebM): refused before anything is uploaded
    await pick(page, 'Einladung.pdf', 'application/pdf', Buffer.from('%PDF-1.4 e2e'));
    await expect.poll(() => ms.log.sent.filter((s) => s.kind === 'file').length).toBe(1);
    await expect(cv.locator('.cv-file b').last()).toHaveText('Einladung.pdf');
    const uploads = ms.log.uploads.length;
    await pick(page, 'clip.webm', 'video/webm', Buffer.from('webm'));
    await expect(page.locator('#toasts')).toContainText('WhatsApp nimmt Videos nur als MP4 an.');
    expect(ms.log.uploads.length).toBe(uploads);
    expect(ms.log.calls.filter((c) => /^conversations\/\d+\/messages$/.test(c.route) && c.method === 'POST').every((c) => c.query.bridged === '1')).toBe(true);
    await shots(page, 'bc4-gesendet');
  });

  test('files in: loading, failed with the reason, a location, then the file; the pictures of contacts and groups', async ({ launchApp, mock }) => {
    const ms = setupStage4(mock);
    const kim = ms.addBridgeConv({ title: 'Kim Muster' });
    const loading = ms.addBridgeMsg(kim, { text: null, placeholder: { kind: 'image', name: 'grill.jpg', state: 'loading', reason: null } });
    ms.addBridgeMsg(kim, { text: null, placeholder: { kind: 'video', name: 'urlaub.mp4', state: 'failed', reason: 'too_large' } });
    ms.addBridgeMsg(kim, { text: null, placeholder: { kind: 'file', name: 'rechnung.exe', state: 'failed', reason: 'infected' } });
    ms.addBridgeMsg(kim, { text: 'Grillplatz am See', placeholder: { kind: 'location', name: null, state: null, reason: null, geo: { lat: 50.1, lon: 7.2 } } });
    const group = ms.addBridgeConv({ kind: 'group', title: 'Elternrunde 4b' });
    const robinPic = ms.addMedia('image/png', PNG);
    const g1 = ms.addBridgeMsg(group, { contact: { contactId: 14, name: 'Robin', avatarMediaId: robinPic }, text: 'Wer bringt Kuchen mit?' });
    expect(g1.id).toBeGreaterThan(0);
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${kim}"]`).click();
    await cv.locator('.cv-bc-first [data-act="intro-ok"]').click();
    const ph = cv.locator('.cv-bc-ph');
    await expect(ph.nth(0)).toHaveText('Bild · grill.jpg – wird geladen …');
    await expect(ph.nth(0)).toHaveAttribute('data-state', 'loading');
    await expect(ph.nth(1)).toHaveText('Video · urlaub.mp4 – zu groß, öffne es in WhatsApp');
    await expect(ph.nth(2)).toHaveText('Datei · rechnung.exe – gesperrt – Schadsoftware gefunden');
    await expect(cv.locator('.cv-loc b')).toHaveText('Grillplatz am See');
    await expect(cv.locator('.cv-loc-map')).toBeVisible();
    await shots(page, 'bc4-dateien-herein');

    // the file arrives (message.update { media: true }): the placeholder becomes the picture
    const img = ms.addMedia('image/png', PNG);
    ms.bridgeFileArrived(loading.id, { kind: 'image', mediaId: img, meta: { w: 1, h: 1 } });
    await expect(cv.locator(`.cv-msg[data-id="${loading.id}"] .cv-img img`)).toBeVisible();
    await expect(cv.locator(`.cv-msg[data-id="${loading.id}"] .cv-bc-ph`)).toHaveCount(0);

    // the contact's picture once fetched (conversation.update { reason: avatar }); a contact in a group
    await expect(cv.locator(`.cv-row[data-id="${kim}"] .cv-av-img`)).toHaveCount(0);
    ms.setBridgeAvatar(kim, ms.addMedia('image/png', PNG));
    await expect(cv.locator(`.cv-row[data-id="${kim}"] .cv-av-img`)).toBeVisible();
    await expect(cv.locator(`.cv-row[data-id="${kim}"] .cv-net-mark`)).toHaveAttribute('data-net', 'whatsapp');
    await cv.locator(`.cv-row[data-id="${group}"]`).click();
    await expect(cv.locator('.cv-msg.is-in .cv-msg-av .cv-av-img').first()).toBeVisible();
  });

  test('„Neuer WhatsApp-Chat“: the row, input, invalid, checking, found → the chat opens; exists, none, too many, not reachable', async ({ launchApp, mock }) => {
    const ms = setupStage4(mock);
    ms.bridge.networks[0].newChat = { available: true, reason: null, limit: { perHour: 10, left: 7, retryAfterS: 0 } };
    ms.bridge.numbers.set('+4915123456789', 'Lena Berger');
    const marc = ms.addConv();
    ms.addMsg(marc, { text: 'Hallo' });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator('[aria-label="Neuer Chat"]').click();
    const row = cv.locator('.cv-nc-row[data-net="whatsapp"]');
    await expect(row.locator('b')).toHaveText('WhatsApp-Chat mit Nummer');
    await expect(row.locator('small')).toHaveText('Nummer eingeben und prüfen');
    await expect(row.locator('.cv-net-mark')).toHaveAttribute('data-net', 'whatsapp');
    await shots(page, 'nc-einstieg');
    // not in the group tab
    await cv.locator('.cv-tabs button[data-mode="group"]').click();
    await expect(row).toHaveCount(0);
    await cv.locator('.cv-tabs button[data-mode="direct"]').click();
    await row.click();

    const dlg = cv.locator('.cv-nc-dlg');
    const body = dlg.locator('.cv-nc');
    await expect(dlg.locator('.cv-nc-ht b')).toHaveText('Neuer WhatsApp-Chat');
    await expect(dlg.locator('.cv-nc-cc')).toHaveValue('+49');
    await expect(dlg.locator('.cv-nc-num')).toBeFocused();
    await expect(dlg.locator('.cv-nc-priv')).toHaveText('Zum Prüfen geht die Nummer über deine Brücke an WhatsApp. GateControl schreibt sie nicht ins Protokoll; gespeichert wird sie nur, wenn du den Chat startest.');
    await expect(dlg.locator('[data-act="check"]')).toBeDisabled();
    // not asked while typing
    await dlg.locator('.cv-nc-num').fill('0151 234');
    await dlg.locator('[data-act="check"]').click();
    await expect(body).toHaveAttribute('data-state', 'invalid');
    await expect(dlg.locator('.cv-nc-hint')).toHaveText('Das ist keine vollständige Nummer – für ein deutsches Handy fehlen noch Ziffern.');
    await expect(dlg.locator('[data-act="check"]')).toBeDisabled();
    await shots(page, 'nc-ungueltig');
    expect(ms.log.bridge.filter((b) => b.op === 'resolve').length).toBe(0);
    await dlg.locator('.cv-nc-num').fill('0151 23456789');
    await expect(dlg.locator('.cv-nc-hint')).toHaveText('Wird geprüft als +49 151 23456789');
    await shots(page, 'nc-eingabe');

    // checking (slow bridge) → found
    ms.bridge.resolveDelayMs = SHOTS ? 8000 : 1500;
    await dlg.locator('[data-act="check"]').click();
    await expect(body).toHaveAttribute('data-state', 'checking');
    await expect(dlg.locator('.cv-nc-res b')).toHaveText('WhatsApp wird gefragt …');
    await shots(page, 'nc-pruefung');
    await expect(body).toHaveAttribute('data-state', 'found');
    ms.bridge.resolveDelayMs = 0;
    await expect(dlg.locator('.cv-nc-res b')).toHaveText('Lena Berger');
    await expect(dlg.locator('.cv-nc-numtx')).toHaveText('+49 151 23456789');
    await expect(dlg.locator('.cv-nc-tag')).toHaveText('Hat WhatsApp');
    await expect(dlg.locator('.cv-nc-ok')).toBeVisible();
    await shots(page, 'nc-gefunden');
    const resolve = ms.log.calls.filter((c) => c.route === 'bridges/whatsapp/resolve');
    expect(resolve.length).toBe(1);
    expect(resolve[0].query.bridged).toBeUndefined();

    // start → the chat is open (with the explanation on the first visit), and stays in the list
    await dlg.locator('[data-act="start"]').click();
    await expect(dlg).toHaveCount(0);
    await expect(cv.locator('.cv-head b')).toHaveText('Lena Berger');
    await expect(cv.locator('.cv-head-sub')).toHaveText('über WhatsApp');
    await expect(cv.locator('.cv-bc-first')).toBeVisible();
    await expect(cv.locator('.cv-input')).toHaveAttribute('placeholder', 'Nachricht über WhatsApp');
    await expect(cv.locator('.cv-sys[data-sys="new-chat"]')).toHaveText('Neuer Chat über WhatsApp mit +49 151 23456789. Lena Berger sieht deine Nachrichten in der gewohnten WhatsApp-App.');
    await shots(page, 'nc-chat-offen');
    const lena = [...ms.log.calls].reverse().find((c) => c.route === 'bridges/whatsapp/chats');
    expect(lena).toBeTruthy();
    await page.waitForTimeout(1500);
    await expect(cv.locator('.cv-row[data-id]')).toHaveCount(2);

    // the same number again: „Ihr habt schon einen Chat“ → open it
    await cv.locator('[aria-label="Neuer Chat"]').click();
    await row.click();
    await dlg.locator('.cv-nc-num').fill('+49 151 23456789');
    await dlg.locator('.cv-nc-num').press('Enter');
    await expect(body).toHaveAttribute('data-state', 'exists');
    await expect(dlg.locator('.cv-nc-tag')).toHaveText('Ihr habt schon einen Chat');
    await shots(page, 'nc-chat-gibt-es');
    // another number: not at WhatsApp
    await dlg.locator('[data-act="other"]').click();
    await expect(dlg.locator('.cv-nc-num')).toHaveValue('');
    await dlg.locator('.cv-nc-num').fill('0160 9876543');
    await dlg.locator('[data-act="check"]').click();
    await expect(body).toHaveAttribute('data-state', 'none');
    await expect(dlg.locator('.cv-nc-res b')).toHaveText('Kein WhatsApp unter dieser Nummer');
    await expect(dlg.locator('.cv-nc-res span').last()).toHaveText('+49 160 9876543 ist bei WhatsApp nicht registriert. Prüf die Ziffern oder frag nach der Nummer, die bei WhatsApp hinterlegt ist.');
    await shots(page, 'nc-kein-whatsapp');
    // the bridge does not answer → „Erneut versuchen“
    ms.bridge.resolveFails = { status: 503, code: 'bridge_unreachable', reason: 'timeout' };
    await dlg.locator('[data-act="check"]').click();
    await expect(body).toHaveAttribute('data-state', 'unreach');
    await expect(dlg.locator('.cv-nc-num')).toHaveValue('0160 9876543');
    await shots(page, 'nc-nicht-erreichbar');
    // too many checks
    ms.bridge.lookupMax = 0;
    await dlg.locator('[data-act="retry"]').click();
    await expect(body).toHaveAttribute('data-state', 'rate');
    await expect(dlg.locator('.cv-nc-res b')).toHaveText('Zu viele Prüfungen');
    await expect(dlg.locator('.cv-nc-res span').last()).toContainText('Du hast in der letzten Stunde 10 Nummern geprüft. Damit WhatsApp dein Konto nicht sperrt, geht die nächste Prüfung ab ');
    await expect(dlg.locator('.cv-nc-num')).toBeDisabled();
    await expect(dlg.locator('[data-act="check"]')).toBeDisabled();
    await shots(page, 'nc-zu-viele');
    await dlg.locator('[data-act="cancel"]').click();
    await expect(dlg).toHaveCount(0);
    // the number never in a URL
    expect(ms.log.calls.some((c) => /\d{6}/.test(c.route + JSON.stringify(c.query)))).toBe(false);
  });

  test('„Neuer WhatsApp-Chat“: signed out (link again), locked by the parents, switched off for the child (no row)', async ({ launchApp, mock }) => {
    const ms = setupStage4(mock);
    const net = ms.bridge.networks[0];
    net.logins = [{ ...LINKED_LOGIN, state: 'logged_out' }];
    net.newChat = { available: false, reason: 'logged_out', limit: null };
    ms.addMsg(ms.addConv(), { text: 'Hallo' });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    const dlg = cv.locator('.cv-nc-dlg');
    const open = async () => { await cv.locator('[aria-label="Neuer Chat"]').click(); await cv.locator('.cv-nc-row').click(); };
    await open();
    await expect(dlg.locator('.cv-nc')).toHaveAttribute('data-state', 'loggedout');
    await expect(dlg.locator('.cv-nc-field')).toBeHidden();
    await expect(dlg.locator('.cv-nc-res b')).toHaveText('WhatsApp ist abgemeldet');
    await shots(page, 'nc-abgemeldet');
    await dlg.locator('[data-act="relink"]').click();
    await expect(cv.locator('.cv-settings .cv-set-title')).toHaveText('Verknüpfte Dienste');
    await page.keyboard.press('Escape');

    net.logins = [LINKED_LOGIN];
    net.newChat = { available: false, reason: 'child_locked', limit: null };
    await open();
    await expect(dlg.locator('.cv-nc')).toHaveAttribute('data-state', 'locked');
    await expect(dlg.locator('.cv-nc-res b')).toHaveText('Von deinen Eltern gesperrt');
    await expect(dlg.locator('.cv-nc-foot .btn')).toHaveText(['Schließen']);
    await shots(page, 'nc-kind-gesperrt');
    await dlg.locator('[data-act="close"]').click();

    net.newChat = { available: false, reason: 'child_new_chat_off', limit: null };
    await cv.locator('[aria-label="Neuer Chat"]').click();
    await expect(cv.locator('.cv-dlg .cv-person').first()).toBeVisible();
    await expect(cv.locator('.cv-nc-row')).toHaveCount(0);
    expect(ms.log.bridge.filter((b) => b.op === 'resolve' || b.op === 'chats').length).toBe(0);
  });
});
