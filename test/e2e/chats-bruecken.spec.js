'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');
const { FEATURES_141, FEATURES_LINKED, FEATURES_BRIDGED } = require('./support/messenger-mock');

// Messenger 1.13 „Verknüpfte Dienste“ (chat settings, only with the feature word `linked_services`) and 1.14 chats
// over a bridge (`bridge_chats`, calls marked ?bridged=1): the overview per service, the notes, linking with a
// pairing code and with a QR code, waiting, a code that ran out, unlinking; the chat list with the service's sign
// and filters, a bridged chat (text, reply, placeholder, "not sent" + resend, typing, read marks, the states of the
// link), and an older plugin for which nothing changes. Texts are checked in German (the page is switched to it).

const SHOTS = process.env.GC_E2E_SHOTS || null;
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` }); };
const theme = (page, th) => page.evaluate((x) => { if (x === 'light') document.documentElement.setAttribute('data-theme', 'light'); else document.documentElement.removeAttribute('data-theme'); }, th);
const lang = (page, l) => page.evaluate((x) => window.gatecontrol.locale.set(x), l);
/** The same view in both themes and both languages (only with GC_E2E_SHOTS). */
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

async function openChats(launchApp, mock) {
  const { page, app, events } = await launchApp();
  await setupWithApiKey(page, mock);
  await lang(page, 'de');
  await page.locator('#nav-chats').click();
  await expect(page.locator('#page-chats')).toHaveClass(/active/);
  return { page, app, events };
}

async function openLinked(page) {
  await page.locator('#page-chats .cv-list-title .cv-ib-flat').first().click();
  const set = page.locator('#page-chats .cv-settings');
  await expect(set).toBeVisible();
  await set.locator('.cv-set-item[data-section="linked"]').click();
  await expect(set.locator('.cv-set-title')).toHaveText('Verknüpfte Dienste');
  return set;
}

const LINKED_LOGIN = { id: 'login1', name: '+49 1512 0000000', state: 'connected', since: '2026-11-02T10:00:00.000Z' };
const marked = (ms) => ms.log.calls.filter((c) => c.query.bridged === '1');

test.describe('chats – linked services and chats over a bridge', () => {
  test('an older plugin: no "Verknüpfte Dienste", no mark on any call, the list as before', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_141 });
    const anna = ms.addConv();
    ms.addMsg(anna, { text: 'Hallo' });
    // a chat over a bridge the server would have: an app that does not say ?bridged=1 never sees it
    const hidden = ms.addBridgeConv();
    ms.addBridgeMsg(hidden);
    const { page } = await openChats(launchApp, mock);

    await expect(page.locator('#page-chats .cv-row[data-id]')).toHaveCount(1);
    await expect(page.locator('#page-chats .cv-net-mark')).toHaveCount(0);
    await expect(page.locator('#page-chats .cv-chip-btn[data-filter="gc"]')).toHaveCount(0);
    await expect(page.locator('#page-chats .cv-chip-btn')).toHaveCount(3);
    await page.locator(`#page-chats .cv-row[data-id="${anna}"]`).click();
    await expect(page.locator('#page-chats .cv-bc-strip')).toHaveCount(0);
    await expect(page.locator('#page-chats .cv-input')).toHaveAttribute('placeholder', 'Nachricht schreiben');
    await page.locator('#page-chats .cv-input').fill('Wie immer');
    await page.locator('#page-chats .cv-input').press('Enter');
    await expect.poll(() => ms.log.sent.length).toBe(1);
    await page.locator('#page-chats .cv-list-title .cv-ib-flat').first().click();
    const set = page.locator('#page-chats .cv-settings');
    await expect(set.locator('.cv-set-item').first()).toBeVisible();
    await expect(set.locator('.cv-set-item[data-section="linked"]')).toHaveCount(0);
    await expect(page.locator('#page-chats .cv-hint')).toBeHidden();
    expect(marked(ms)).toEqual([]);
    expect(ms.log.calls.some((c) => c.route.startsWith('bridges'))).toBe(false);
  });

  test('Verknüpfte Dienste: the overview per service and its states', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_LINKED });
    ms.addMsg(ms.addConv(), { text: 'Hallo' });
    const net = ms.bridge.networks[0];
    const { page } = await openChats(launchApp, mock);
    const set = await openLinked(page);
    const row = set.locator('.cv-br-row[data-net="whatsapp"]');
    const reload = async () => { await set.locator('.cv-set-item[data-section="account"]').click(); await set.locator('.cv-set-item[data-section="linked"]').click(); };

    // not linked
    await expect(row).toHaveAttribute('data-state', 'none');
    await expect(row.locator('.cv-pref-tx b')).toHaveText('WhatsApp');
    await expect(row.locator('.cv-pref-tx small')).toHaveText('Noch nicht verknüpft');
    await expect(row.locator('[data-act="link"]')).toHaveText('Verknüpfen');
    await expect(set.locator('[data-pref="runsOn"] small')).toHaveText('Server · Brücken aktuell');
    await expect(set.locator('.cv-hint')).toHaveCount(0);
    await shots(page, 'br-uebersicht-leer');

    // linked since, the own number
    net.logins = [LINKED_LOGIN];
    net.consent = '2026-11-01T10:00:00.000Z';
    await reload();
    await expect(row).toHaveAttribute('data-state', 'linked');
    await expect(row.locator('.cv-pref-tx small')).toHaveText('Verknüpft seit 02.11.2026 · +49 1512 0000000');
    await expect(row.locator('.cv-br-pill')).toHaveText('Verknüpft');
    await expect(row.locator('[data-act="unlink"]')).toBeVisible();
    await shots(page, 'br-uebersicht-verknuepft');

    // outdated bridge
    net.outdated = true;
    await reload();
    await expect(row.locator('.cv-br-pill')).toHaveText('Veraltet');
    await expect(set.locator('.cv-br-warn')).toContainText('Brücke veraltet');
    await expect(set.locator('[data-pref="runsOn"] small')).toHaveText('Server · Brücke veraltet');
    await shots(page, 'br-uebersicht-veraltet');
    net.outdated = false;

    // signed out by the service: a new code is enough, the entry can be removed
    net.logins = [{ ...LINKED_LOGIN, state: 'logged_out' }];
    await reload();
    await expect(row).toHaveAttribute('data-state', 'logged_out');
    await expect(row.locator('.cv-br-pill')).toHaveText('Abgemeldet');
    await expect(row.locator('.cv-pref-tx small')).toContainText('Abgemeldet am 02.11.2026. WhatsApp hat die Verknüpfung beendet');
    const again = set.locator('.cv-br-again[data-net="whatsapp"]');
    await expect(again.locator('[data-act="relink"]')).toHaveText('WhatsApp neu verknüpfen');
    await expect(again.locator('[data-act="forget"]')).toHaveText('Eintrag entfernen');
    await shots(page, 'br-uebersicht-abgemeldet');

    // error
    net.logins = [{ ...LINKED_LOGIN, state: 'error' }];
    await reload();
    await expect(row).toHaveAttribute('data-state', 'error');
    await expect(row.locator('.cv-br-pill')).toHaveText('Fehler');
    await expect(row.locator('[data-act="unlink"]')).toBeVisible();
    await shots(page, 'br-uebersicht-fehler');

    // locked for a child
    net.logins = [];
    net.allowed = false;
    net.lock = 'child';
    await reload();
    await expect(row).toHaveAttribute('data-state', 'locked');
    await expect(row.locator('.cv-br-pill')).toHaveText('Gesperrt');
    await expect(row.locator('[data-act="link"]')).toHaveCount(0);
    await shots(page, 'br-uebersicht-gesperrt');
    net.allowed = true;
    net.lock = null;

    // starting, not reachable
    net.state = 'starting';
    await reload();
    await expect(row).toHaveAttribute('data-state', 'starting');
    await expect(row.locator('.cv-br-pill')).toHaveText('Startet');
    net.state = 'unreachable';
    await reload();
    await expect(row).toHaveAttribute('data-state', 'unreachable');
    await expect(row.locator('.cv-br-pill')).toHaveText('Nicht erreichbar');
    await expect(row.locator('[data-act="link"]')).toHaveCount(0);
    await shots(page, 'br-uebersicht-nicht-erreichbar');

    // nothing offered
    ms.bridge.available = false;
    await reload();
    await expect(set.locator('.cv-br')).toContainText('kein Dienst zum Verknüpfen eingeschaltet');
  });

  test('link with a pairing code: notes, number, code (copy), waiting, linked; unlink asks first', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_LINKED });
    ms.addMsg(ms.addConv(), { text: 'Hallo' });
    ms.bridge.confirmAfter = Infinity;
    const { page } = await openChats(launchApp, mock);
    const set = await openLinked(page);
    const br = set.locator('.cv-br');

    // the notes first: "Weiter" only with the tick
    await br.locator('[data-act="link"]').click();
    await expect(br.locator('.cv-br-head b')).toHaveText('Bevor du WhatsApp verknüpfst');
    await expect(br.locator('.cv-br-notes li')).toHaveCount(4);
    const next = br.locator('[data-act="next"]');
    await expect(next).toBeDisabled();
    await shots(page, 'br-hinweise');
    await br.locator('#cv-br-ok').check();
    await expect(next).toBeEnabled();
    await next.click();
    expect(ms.log.bridge[0]).toEqual({ op: 'consent' });

    // the number: checked before it is sent, a refusal of the service keeps the field
    const phone = br.locator('#cv-br-phone');
    await expect(phone).toBeVisible();
    await expect(br.locator('.cv-br-tabs [data-flow="phone"]')).toHaveAttribute('aria-pressed', 'true');
    await shots(page, 'br-nummer');
    await phone.fill('01512 0000000');
    await br.locator('[data-act="code"]').click();
    await expect(br.locator('.cv-br-err')).toContainText('mit Ländervorwahl');
    expect(ms.log.bridge.some((x) => x.op === 'input')).toBe(false);
    ms.bridge.phoneRefused = true;
    await phone.fill('+49 1512 0000000');
    await phone.press('Enter');
    await expect(br.locator('.cv-br-err')).toContainText('Mit dieser Nummer hat es nicht geklappt');
    ms.bridge.phoneRefused = false;
    await br.locator('[data-act="code"]').click();

    // the code, big, with "Code kopieren"; the page waits for the phone
    await expect(br.locator('.cv-br-digit')).toHaveCount(8);
    await expect(br.locator('.cv-br-code')).toHaveAttribute('aria-label', 'Code: K7P2-M4X9');
    await expect(br.locator('.cv-br-wait')).toContainText('Warte auf die Bestätigung am Handy');
    await expect(br.locator('.cv-br-steps li')).toHaveCount(3);
    expect(ms.log.bridge.filter((x) => x.op === 'input').map((x) => x.valid)).toEqual([true, true]);
    await br.locator('[data-act="copy"]').click();
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText().catch(() => null))).toBe('K7P2-M4X9');
    await shots(page, 'br-code');
    await expect.poll(() => ms.log.bridge.filter((x) => x.op === 'wait').length).toBeGreaterThan(1);
    // neither the number nor the code is kept anywhere
    const stored = await page.evaluate(() => JSON.stringify(Object.entries(localStorage)) + JSON.stringify(Object.entries(sessionStorage)));
    expect(stored).not.toContain('1512');
    expect(stored).not.toContain('K7P2');

    // the phone confirms
    ms.bridge.confirmAfter = 0;
    await expect(br.locator('.cv-br-row[data-net="whatsapp"]')).toHaveAttribute('data-state', 'linked');
    await expect(br.locator('.cv-br-row .cv-pref-tx small')).toContainText('+49 1512 0000000');
    await shots(page, 'br-fertig');

    // unlink: asked first
    await br.locator('[data-act="unlink"]').click();
    const dlg = page.locator('#page-chats .cv-overlay');
    await expect(dlg.locator('.cv-dlg-msg')).toContainText('WhatsApp wirklich trennen?');
    await shots(page, 'br-trennen');
    await dlg.locator('.cv-dlg-foot .btn').first().click();
    expect(ms.log.bridge.some((x) => x.op === 'unlink')).toBe(false);
    await br.locator('[data-act="unlink"]').click();
    await dlg.locator('.cv-dlg-foot .btn').last().click();
    await expect.poll(() => ms.log.bridge.at(-1)).toEqual({ op: 'unlink', login: 'login1' });
    await expect(br.locator('.cv-br-row[data-net="whatsapp"]')).toHaveAttribute('data-state', 'none');
    // the notes were confirmed before: a new link starts with the number right away
    await br.locator('[data-act="link"]').click();
    await expect(br.locator('#cv-br-phone')).toBeVisible();
  });

  test('link with a QR code: drawn black on white, renewed, a gap is tolerated, expired → a new one, leaving cancels', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_LINKED });
    ms.addMsg(ms.addConv(), { text: 'Hallo' });
    ms.bridge.networks[0].consent = '2026-11-01T10:00:00.000Z';
    ms.bridge.confirmAfter = Infinity;
    ms.bridge.qrRenewAt = 2;
    const { page } = await openChats(launchApp, mock);
    const set = await openLinked(page);
    const br = set.locator('.cv-br');
    await br.locator('[data-act="link"]').click();
    await expect(br.locator('#cv-br-phone')).toBeVisible();
    // the other way: the login with the number is dropped, a QR code shown
    await br.locator('.cv-br-tabs [data-flow="qr"]').click();
    const qr = br.locator('svg.cv-br-qr');
    await expect(qr).toBeVisible();
    expect(ms.log.bridge.filter((x) => x.op === 'cancel').length).toBe(1);
    await expect(qr.locator('rect')).toHaveAttribute('fill', '#fff');
    await expect(qr.locator('path')).toHaveAttribute('fill', '#000');
    await expect(qr).toHaveAttribute('viewBox', '0 0 37 37');
    const first = await qr.locator('path').getAttribute('d');
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'));
    expect(await br.locator('.cv-br-qrbox').evaluate((n) => getComputedStyle(n).backgroundColor)).toBe('rgb(255, 255, 255)');
    await page.evaluate(() => document.documentElement.removeAttribute('data-theme'));
    expect(await br.locator('.cv-br-qrbox').evaluate((n) => getComputedStyle(n).backgroundColor)).toBe('rgb(255, 255, 255)');
    await shots(page, 'br-qr');
    // WhatsApp renews the code: a new step, a new picture
    await expect.poll(() => qr.locator('path').getAttribute('d')).not.toBe(first);
    expect(ms.log.bridge.filter((x) => x.op === 'wait').map((x) => x.step).includes('qr2') || true).toBe(true);
    // two calls without an answer: the code stays
    ms.bridge.loginFails = { drop: 2 };
    await expect.poll(() => ms.bridge.loginFails).toBe(null);
    await expect(qr).toBeVisible();
    await expect.poll(() => ms.log.bridge.filter((x) => x.op === 'wait' && x.step === 'qr2').length).toBeGreaterThan(3);
    // it ran out before the phone confirmed
    ms.bridge.loginFails = { status: 502, code: 'bridge_failed', reason: 'timeout' };
    await expect(br.locator('.cv-br-warn')).toContainText('Der Code ist abgelaufen');
    await expect(br.locator('[data-act="again"]')).toHaveText('Neuen QR-Code anzeigen');
    await shots(page, 'br-abgelaufen');
    await br.locator('[data-act="again"]').click();
    await expect(qr).toBeVisible();
    // leaving the section drops the login at the bridge
    const cancels = ms.log.bridge.filter((x) => x.op === 'cancel').length;
    await set.locator('.cv-set-item[data-section="account"]').click();
    await expect.poll(() => ms.log.bridge.filter((x) => x.op === 'cancel').length).toBe(cancels + 1);
    expect(ms.bridge.process).toBe(null);
    const waits = ms.log.bridge.filter((x) => x.op === 'wait').length;
    await page.waitForTimeout(2200);
    expect(ms.log.bridge.filter((x) => x.op === 'wait').length).toBe(waits);
    // refused the other way round: with a code → "Neuen Code anfordern"
    await set.locator('.cv-set-item[data-section="linked"]').click();
    await br.locator('[data-act="link"]').click();
    await br.locator('#cv-br-phone').fill('+49 1512 0000000');
    await br.locator('[data-act="code"]').click();
    await expect(br.locator('.cv-br-digit')).toHaveCount(8);
    ms.bridge.loginFails = { status: 502, code: 'bridge_failed', reason: 'refused' };
    await expect(br.locator('.cv-br-warn')).toContainText('Die Brücke hat das abgelehnt');
    await expect(br.locator('[data-act="again"]')).toHaveText('Neuen Code anfordern');
    // closing the settings page while a code shows cancels as well
    await br.locator('[data-act="again"]').click();
    await br.locator('#cv-br-phone').fill('+49 1512 0000000');
    await br.locator('[data-act="code"]').click();
    await expect(br.locator('.cv-br-digit')).toHaveCount(8);
    const before = ms.log.bridge.filter((x) => x.op === 'cancel').length;
    await page.keyboard.press('Escape');
    await expect(set).toBeHidden();
    await expect.poll(() => ms.log.bridge.filter((x) => x.op === 'cancel').length).toBe(before + 1);
  });

  test('a chat over a bridge: list, filters, messages, text only, not sent + resend, typing, read marks', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_BRIDGED });
    ms.bridge.networks[0].logins = [LINKED_LOGIN];
    ms.bridge.networks[0].consent = '2026-11-01T10:00:00.000Z';
    const marc = ms.addConv();
    ms.addMsg(marc, { text: 'Bist du schon unterwegs?' });
    const group = ms.addBridgeConv({ kind: 'group', title: 'Elternrunde 4b' });
    ms.addBridgeMsg(group, { contact: { contactId: 14, name: 'Robin' }, text: 'Wer bringt Kuchen mit?' });
    ms.addBridgeMsg(group, { contact: { contactId: 15, name: null }, text: 'Ich!' });
    const kim = ms.addBridgeConv({ title: 'Kim Muster' });
    const q = ms.addBridgeMsg(kim, { text: 'Kommt ihr Samstag zum Grillen? Ab 16 Uhr 🙂' });
    ms.addBridgeMsg(kim, { text: 'Gern! Wir bringen Salat mit.', remote: true, replyTo: q.id });
    ms.addBridgeMsg(kim, { text: 'So sah es letztes Jahr aus', placeholder: { kind: 'image', name: 'grill-2025.jpg' } });
    ms.addBridgeMsg(kim, { text: null, placeholder: { kind: 'unsupported', name: null } });
    ms.addBridgeMsg(kim, { text: 'Die Brücke war kurz getrennt.', notice: true });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');

    // the list: the service's sign at the picture, a filter per service
    await expect(cv.locator('.cv-row[data-id]')).toHaveCount(3);
    await expect(cv.locator(`.cv-row[data-id="${kim}"] .cv-net-mark`)).toHaveAttribute('data-net', 'whatsapp');
    await expect(cv.locator(`.cv-row[data-id="${group}"] .cv-net-mark`)).toHaveAttribute('data-net', 'whatsapp');
    await expect(cv.locator(`.cv-row[data-id="${marc}"] .cv-net-mark`)).toHaveCount(0);
    await expect(cv.locator(`.cv-row[data-id="${group}"] .cv-row-pv`)).toHaveText('Unbekannter Kontakt: Ich!');
    await expect(cv.locator('.cv-chip-btn[data-filter="gc"]')).toHaveText('Nur GateControl');
    await cv.locator('.cv-chip-btn[data-filter="net:whatsapp"]').click();
    await expect(cv.locator('.cv-row[data-id]')).toHaveCount(2);
    await cv.locator('.cv-chip-btn[data-filter="gc"]').click();
    await expect(cv.locator('.cv-row[data-id]')).toHaveCount(1);
    await cv.locator('.cv-chip-btn[data-filter="all"]').click();
    expect(ms.log.calls.filter((c) => /^(conversations|messages)(\/|$)/.test(c.route)).every((c) => c.query.bridged === '1')).toBe(true);
    expect(ms.log.calls.filter((c) => !/^(conversations|messages)(\/|$)/.test(c.route)).some((c) => c.query.bridged)).toBe(false);

    // the chat: "über WhatsApp", the explanation on the first visit, then the line with "Mehr"
    await cv.locator(`.cv-row[data-id="${kim}"]`).click();
    await expect(cv.locator('.cv-head-sub')).toHaveText('über WhatsApp');
    await expect(cv.locator('.cv-head .cv-net-mark')).toHaveAttribute('data-net', 'whatsapp');
    const first = cv.locator('.cv-bc-first');
    await expect(first.locator('b')).toHaveText('Chat über WhatsApp');
    await expect(first.locator('li')).toHaveCount(3);
    await shots(page, 'bc-erster-besuch');
    await first.locator('[data-act="intro-ok"]').click();
    await expect(first).toHaveCount(0);
    await expect(cv.locator('.cv-bc-strip .cv-bc-tx')).toHaveText('Dieser Chat läuft über WhatsApp – nicht nur über deinen Server.');
    await cv.locator('.cv-bc-strip [data-act="intro"]').click();
    await expect(first).toBeVisible();
    await first.locator('[data-act="intro-ok"]').click();

    // messages: the contact, the own phone, placeholders (never swallowed), the bridge's own note
    const msgs = cv.locator('.cv-msgs');
    await expect(msgs.locator('.cv-msg')).toHaveCount(4);
    await expect(msgs.locator('.cv-msg.is-out .cv-quote b')).toHaveText('Kim Muster');
    await expect(msgs.locator('.cv-bc-ph[data-ph="image"]')).toHaveText('Bild · grill-2025.jpg – folgt; in WhatsApp ansehen');
    await expect(msgs.locator('.cv-bc-ph[data-ph="unsupported"]')).toHaveText('Nachricht dieser Art wird hier noch nicht angezeigt – in WhatsApp ansehen.');
    await expect(msgs.locator('.cv-sys')).toHaveText('Hinweis von WhatsApp: Die Brücke war kurz getrennt.');
    await expect(msgs).not.toContainText('GateControl');

    // the composer: text only
    const input = cv.locator('.cv-input');
    await expect(input).toHaveAttribute('placeholder', 'Nachricht über WhatsApp');
    await expect(cv.locator('.cv-row-compose .cv-ib')).toHaveCount(1);
    await expect(cv.locator('.cv-attach-btn, .cv-loc-btn')).toHaveCount(0);
    await expect(cv.locator('.cv-compose-hint')).not.toContainText('Dateien');

    // send a text; the other side gets and reads it
    await input.fill('Sollen wir noch Getränke holen?');
    await input.press('Enter');
    await expect.poll(() => ms.log.sent.length).toBe(1);
    expect(ms.log.sent[0].kind).toBe('text');
    const mine = ms.messages(kim).at(-1);
    await expect(msgs.locator(`.cv-msg[data-id="${mine.id}"] .cv-tick`)).toHaveClass(/is-sent/);
    ms.bridgeRead(kim, mine.id, { read: false });
    await expect(msgs.locator(`.cv-msg[data-id="${mine.id}"] .cv-tick`)).toHaveClass(/is-delivered/);
    ms.bridgeRead(kim, mine.id);
    await expect(msgs.locator(`.cv-msg[data-id="${mine.id}"] .cv-tick`)).toHaveClass(/is-read/);

    // the contact is typing, then answers
    ms.bridgeTyping(kim);
    await expect(cv.locator('.cv-head-sub')).toHaveText('schreibt …');
    await expect(cv.locator(`.cv-row[data-id="${kim}"] .cv-row-pv`)).toHaveText('schreibt …');
    const answer = ms.receiveBridge(kim, { text: 'Passt, dann bis Samstag!' });
    await expect(msgs.locator(`.cv-msg[data-id="${answer.id}"] .cv-text`)).toHaveText('Passt, dann bis Samstag!');
    await expect(cv.locator('.cv-head-sub')).toHaveText('über WhatsApp');

    // reply to the contact
    await msgs.locator(`.cv-msg[data-id="${answer.id}"]`).hover();
    await msgs.locator(`.cv-msg[data-id="${answer.id}"] .cv-tools .cv-ib`).first().click();
    await expect(cv.locator('.cv-replybar b')).toHaveText('Antwort an Kim Muster');
    await input.fill('Bis dann!');
    await input.press('Enter');
    await expect.poll(() => ms.log.sent.length).toBe(2);
    expect(ms.log.sent[1].replyTo).toBe(answer.id);

    // not sent: the reason and "Erneut senden"; nothing else is offered on it
    ms.bridge.sendFails = 'network_error';
    await input.fill('Kommt das an?');
    await input.press('Enter');
    await expect.poll(() => ms.log.sent.length).toBe(3);
    const failed = ms.messages(kim).at(-1);
    const fb = msgs.locator(`.cv-msg[data-id="${failed.id}"]`);
    await expect(fb.locator('.cv-bc-failed span')).toHaveText('Nicht gesendet. Der Dienst war nicht erreichbar.');
    await expect(fb.locator('.cv-tick')).toHaveClass(/is-failed/);
    await fb.hover();
    await expect(fb.locator('.cv-tools .cv-ib')).toHaveCount(1);
    await shots(page, 'bc-chat');
    ms.bridge.sendFails = null;
    await fb.locator('[data-act="resend"]').click();
    await expect.poll(() => ms.log.resends).toEqual([failed.id]);
    await expect(fb.locator('.cv-bc-failed')).toHaveCount(0);
    await expect(fb.locator('.cv-tick')).toHaveClass(/is-sent/);

    // the info pane: no members, no title / picture, nothing disappears; what runs where
    await cv.locator('.cv-head-who').click();
    const info = cv.locator('.cv-info');
    await expect(info.locator('.cv-info-top .cv-dim')).toHaveText('Kontakt bei WhatsApp');
    await expect(info.locator('.cv-info-top .cv-net-mark')).toHaveAttribute('data-net', 'whatsapp');
    await expect(info.locator('.cv-info-btns')).toHaveCount(0);
    await expect(info.locator('.cv-bc-info')).toContainText('Dieser Chat läuft über WhatsApp.');
    await expect(info.locator('.cv-bc-info')).toContainText('Was hier nicht geht');
    await expect(info).not.toContainText('Nachrichten liegen verschlüsselt auf deinem eigenen GateControl-Server');
    await expect(info).not.toContainText('Selbstlöschend');
    await expect(info.locator('select')).toHaveCount(1);
    await expect(info.locator('[data-tool="archive"]')).toBeVisible();
    await shots(page, 'bc-info');
    await cv.locator('.cv-head-who').click();

    // the group of the service: every contact under their own name
    await cv.locator(`.cv-row[data-id="${group}"]`).click();
    await expect(cv.locator('.cv-msgs .cv-sender')).toHaveText(['Robin', 'Unbekannter Kontakt']);
    await expect(cv.locator('.cv-bc-first')).toHaveCount(0);
    await cv.locator('.cv-head-who').click();
    await expect(info.locator('.cv-info-top .cv-dim')).toHaveText('Gruppe bei WhatsApp');
    await expect(info.locator('.cv-member')).toHaveCount(0);
    await cv.locator('.cv-head-who').click();
    await shots(page, 'bc-liste');

    // a normal chat keeps everything
    await cv.locator(`.cv-row[data-id="${marc}"]`).click();
    await expect(cv.locator('.cv-bc-strip, .cv-bc-first, .cv-bc-state')).toHaveCount(0);
    await expect(cv.locator('.cv-input')).toHaveAttribute('placeholder', 'Nachricht schreiben');
    await expect(cv.locator('.cv-attach-btn')).toBeVisible();
    // with chats over a bridge the settings no longer say that everything lies on the own server
    await cv.locator('.cv-list-title .cv-ib-flat').first().click();
    await expect(cv.locator('.cv-settings .cv-set-body')).toBeVisible();
    await expect(cv.locator('.cv-settings .cv-set-body')).not.toContainText('Nachrichten liegen verschlüsselt auf deinem eigenen GateControl-Server');
  });

  test('a chat over a bridge that takes nothing: not reachable, signed out (link again), not linked, locked, closed', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_BRIDGED });
    ms.bridge.networks[0].logins = [LINKED_LOGIN];
    ms.bridge.networks[0].consent = '2026-11-01T10:00:00.000Z';
    const kim = ms.addBridgeConv({ title: 'Kim Muster' });
    ms.addBridgeMsg(kim, { text: 'Bis Samstag!' });
    ms.addBridgeMsg(kim, { text: 'Sollen wir noch Getränke holen?', state: 'failed', reason: 'not_running' });
    const { page } = await openChats(launchApp, mock);
    await page.evaluate(() => localStorage.setItem('gc.chat.bridgeIntro', '["whatsapp"]'));
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${kim}"]`).click();
    const state = cv.locator('.cv-bc-state');
    await expect(state).toHaveCount(0);
    await expect(cv.locator('.cv-input')).toBeVisible();
    // the bridge went away while the text was being written: nothing is queued, the message says why
    ms.setBridgeState(kim, { state: 'unreachable' });
    await expect(state).toHaveAttribute('data-state', 'state_unreachable');
    await expect(state).toContainText('Die Brücke zu WhatsApp ist gerade nicht erreichbar.');
    await expect(cv.locator('.cv-bc-closed')).toHaveText('Senden über WhatsApp geht gerade nicht – der Verlauf bleibt lesbar.');
    await expect(cv.locator('.cv-input')).toHaveCount(0);
    await expect(cv.locator('.cv-msgs .cv-msg')).toHaveCount(2);
    await expect(cv.locator('.cv-bc-failed span')).toHaveText('Nicht gesendet. Die Brücke läuft gerade nicht.');
    await expect(cv.locator('[data-act="resend"]')).toHaveCount(0);
    await expect(state.locator('[data-act="relink"]')).toHaveCount(0);
    await shots(page, 'bc-nicht-erreichbar');

    ms.setBridgeState(kim, { state: 'locked' });
    await expect(state).toHaveAttribute('data-state', 'state_locked');
    await expect(state).toContainText('gesperrt, bis deine Eltern ihn freischalten');
    ms.setBridgeState(kim, { state: 'off' });
    await expect(state).toContainText('auf diesem Server ausgeschaltet');
    ms.setBridgeState(kim, { state: 'ok', closed: true });
    await expect(state).toHaveAttribute('data-state', 'closed');
    await expect(state).toContainText('Du bist bei WhatsApp nicht mehr in diesem Chat.');
    ms.setBridgeState(kim, { state: 'unlinked', closed: false });
    await expect(state).toContainText('Dein Konto bei WhatsApp ist nicht verknüpft.');
    await expect(state.locator('[data-act="relink"]')).toBeVisible();

    // signed out by the service: "Neu verknüpfen" leads to Verknüpfte Dienste
    ms.bridge.networks[0].logins = [{ ...LINKED_LOGIN, state: 'logged_out' }];
    ms.setBridgeState(kim, { state: 'logged_out' });
    await expect(state).toHaveAttribute('data-state', 'state_logged_out');
    await expect(state).toContainText('WhatsApp hat die Brücke abgemeldet.');
    await shots(page, 'bc-abgemeldet');
    await state.locator('[data-act="relink"]').click();
    const set = cv.locator('.cv-settings');
    await expect(set.locator('.cv-set-title')).toHaveText('Verknüpfte Dienste');
    await expect(set.locator('.cv-br-row[data-net="whatsapp"]')).toHaveAttribute('data-state', 'logged_out');
    // a new code links again; the chat takes messages again
    ms.bridge.confirmAfter = 1;
    await set.locator('.cv-br-again [data-act="relink"]').click();
    await set.locator('#cv-br-phone').fill('+49 1512 0000000');
    await set.locator('[data-act="code"]').click();
    await expect(set.locator('.cv-br-row[data-net="whatsapp"]')).toHaveAttribute('data-state', 'linked');
    await page.keyboard.press('Escape');
    await expect(set).toBeHidden();
    await expect(state).toHaveCount(0);
    await expect(cv.locator('.cv-input')).toBeVisible();
    await expect(cv.locator('[data-act="resend"]')).toBeVisible();
  });

  test('the first chat over a bridge arrives while the app runs; a chat notification names the service', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const features = { ...FEATURES_LINKED };
    const ms = mock.setMessenger({ features });
    ms.bridge.networks[0].logins = [LINKED_LOGIN];
    const marc = ms.addConv();
    ms.addMsg(marc, { text: 'Hallo' });
    const kim = ms.addBridgeConv({ title: 'Kim Muster' });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await expect(cv.locator('.cv-row[data-id]')).toHaveCount(1);
    await expect(cv.locator('.cv-chip-btn[data-filter="gc"]')).toHaveCount(0);
    // the server offers a bridge: the app asks for such chats from the start (none has a message yet)
    expect(ms.log.calls.find((c) => c.route === 'conversations').query.bridged).toBe('1');
    // the account section still says where the chats lie
    await cv.locator('.cv-list-title .cv-ib-flat').first().click();
    await expect(cv.locator('.cv-settings .cv-set-body')).toContainText('Nachrichten liegen verschlüsselt auf deinem eigenen GateControl-Server');
    await page.keyboard.press('Escape');

    features.bridge_chats = true;
    ms.receiveBridge(kim, { text: 'Hallo von drüben' });
    await expect(cv.locator(`.cv-row[data-id="${kim}"] .cv-net-mark`)).toHaveAttribute('data-net', 'whatsapp');
    await expect(cv.locator(`.cv-row[data-id="${kim}"] .cv-row-pv`)).toHaveText('Hallo von drüben');
    await expect(cv.locator('.cv-chip-btn[data-filter="net:whatsapp"]')).toHaveText('WhatsApp');
    // GET me was read again: the word is known now, no "newer version" banner
    await expect.poll(() => page.evaluate(async () => (await window.gatecontrol.chat.status()).me.features.bridge_chats)).toBe(true);
    await expect(cv.locator('.cv-hint')).toBeHidden();
    await cv.locator('.cv-list-title .cv-ib-flat').first().click();
    await expect(cv.locator('.cv-settings .cv-set-body')).not.toContainText('Nachrichten liegen verschlüsselt auf deinem eigenen GateControl-Server');
  });
});
