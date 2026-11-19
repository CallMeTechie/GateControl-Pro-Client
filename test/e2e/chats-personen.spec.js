'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');
const { FEATURES_V2A, FEATURES_V2B, FEATURES_V127 } = require('./support/messenger-mock');

// Messenger 1.21 (Chats v2, Teil B): persons — the chat with Anna's GateControl account and her WhatsApp chat
// („Schatzimausi 💕“) as ONE entry: the logos of the ways behind the name, found by every name, the shared history by
// time with the logo of each message's way, the source chips, the composer that names the way the server picks (no
// choice) with the line about WhatsApp's encryption, the suggestion card and its dialog with the choice of the name,
// „Nicht jetzt“, „Wege von …“ with „Trennen“ and the name, „Mit Person zusammenführen …“ in a WhatsApp chat, the
// question after linking WhatsApp. An older plugin (1.20) keeps the ways apart. Texts are checked in German.

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
const T0 = Date.now() - 3600000;
const SCHATZ = { contactId: 31, name: 'Schatzimausi 💕' };

function setup(mock, { features = FEATURES_V2B, person = true } = {}) {
  mock.setPush({ topics: [], items: [] });
  const ms = mock.setMessenger({ features });
  ms.bridge.networks[0].logins = [LINKED_LOGIN];
  ms.bridge.networks[0].consent = '2026-11-01T10:00:00.000Z';
  const gc = ms.addConv({ kind: 'direct', members: [7, 8] });
  const wa = ms.addBridgeConv({ title: 'Schatzimausi 💕' });
  const kim = ms.addBridgeConv({ title: 'Kim Muster' });
  const g1 = ms.at(ms.addMsg(gc, { senderId: 8, text: 'Kommst du heute?' }), T0);
  const w1 = ms.at(ms.addBridgeMsg(wa, { text: 'Bin unterwegs 🚗', contact: SCHATZ }), T0 + 60000);
  const g2 = ms.at(ms.addMsg(gc, { senderId: 7, text: 'Ja, um acht.' }), T0 + 120000);
  const w2 = ms.at(ms.addBridgeMsg(wa, { text: 'Bis gleich 💕', contact: SCHATZ }), T0 + 180000);
  ms.at(ms.addBridgeMsg(kim, { text: 'Hallo' }), T0 + 240000);
  const pid = person ? ms.addPerson({ convIds: [gc, wa], userId: 8 }) : null;
  return { ms, gc, wa, kim, pid, g1, w1, g2, w2 };
}

async function openChats(launchApp, mock) {
  const launched = await launchApp();
  await setupWithApiKey(launched.page, mock);
  await lang(launched.page, 'de');
  await launched.page.locator('#nav-chats').click();
  await expect(launched.page.locator('#page-chats')).toHaveClass(/active/);
  return launched;
}

test.describe('chats – persons (Messenger 1.21)', () => {
  test('an older plugin (1.20): the ways stay two chats, no ?people=1, no persons/…', async ({ launchApp, mock }) => {
    const { ms, gc, wa } = setup(mock, { features: FEATURES_V2A });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await expect(cv.locator(`.cv-row[data-id="${gc}"]`)).toBeVisible();
    await expect(cv.locator(`.cv-row[data-id="${wa}"]`)).toBeVisible();
    await expect(cv.locator('.cv-ways')).toHaveCount(0);
    expect(ms.log.calls.filter((c) => c.route === 'conversations').every((c) => c.query.people === undefined)).toBe(true);
    expect(ms.log.calls.some((c) => c.route.startsWith('persons'))).toBe(false);
  });

  test('one entry per person: logos behind the name, every name finds it, the shared history and the source chips', async ({ launchApp, mock }) => {
    const { ms, gc, wa, pid, g1, w1, g2, w2 } = setup(mock);
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    const row = cv.locator(`.cv-row[data-id="${gc}"]`);
    await expect(row).toBeVisible();
    await expect(cv.locator(`.cv-row[data-id="${wa}"]`)).toHaveCount(0);
    await expect(row.locator('.cv-row-name')).toHaveText('Anna');
    await expect(row.locator('.cv-ways .cv-way')).toHaveCount(2);
    await expect(row.locator('.cv-ways .cv-way').nth(1)).toHaveAttribute('aria-label', 'über WhatsApp');
    await expect(row.locator('.cv-net-mark')).toHaveCount(0);
    expect(ms.log.calls.find((c) => c.route === 'conversations').query.people).toBe('1');
    // „Schatz“ finds Anna
    await cv.locator('.cv-q').fill('Schatz');
    await expect(cv.locator('.cv-row[data-id]')).toHaveCount(1);
    await expect(cv.locator(`.cv-row[data-id="${gc}"]`)).toBeVisible();
    await cv.locator('.cv-q').fill('');
    await shots(page, 'person-liste');

    await row.click();
    // 1.27: under the name only the logos of the ways („GateControl · WhatsApp“ is their label)
    await expect(cv.locator('.cv-head .cv-head-sub')).toHaveAttribute('aria-label', 'GateControl · WhatsApp');
    await expect(cv.locator('.cv-head .cv-head-sub')).toHaveText('');
    await expect(cv.locator('.cv-head .cv-head-ways .cv-way')).toHaveCount(2);
    const ids = () => cv.locator('.cv-msgs .cv-msg').evaluateAll((l) => l.map((n) => Number(n.getAttribute('data-id'))));
    await expect.poll(ids).toEqual([g1.id, w1.id, g2.id, w2.id]);
    await expect(cv.locator(`.cv-msg[data-id="${w1.id}"] .cv-msg-way`)).toHaveAttribute('data-net', 'whatsapp');
    await expect(cv.locator(`.cv-msg[data-id="${g1.id}"] .cv-msg-way`)).toHaveAttribute('data-net', 'gatecontrol');
    expect(ms.log.calls.some((c) => c.route === `persons/${pid}/messages`)).toBe(true);
    // the source chips
    const chips = cv.locator('.cv-src .cv-chip-btn');
    await expect(chips).toHaveText(['Alle', 'GateControl', 'WhatsApp']);
    await expect(chips.first()).toHaveAttribute('aria-pressed', 'true');
    await shots(page, 'person-chat');
    await cv.locator('.cv-src [data-way="whatsapp"]').click();
    await expect.poll(ids).toEqual([w1.id, w2.id]);
    expect(ms.log.calls.filter((c) => c.route === `persons/${pid}/messages`).at(-1).query.way).toBe('whatsapp');
    await cv.locator('.cv-src [data-way="all"]').click();
    await expect.poll(ids).toEqual([g1.id, w1.id, g2.id, w2.id]);
    // read through persons/:id/read up to the newest message shown
    await expect.poll(() => ms.people21.reads.at(-1)).toEqual({ personId: pid, upTo: w2.id });
  });

  test('sending without a choice of way: „Nachricht über WhatsApp“ (no line above the composer), then back to GateControl', async ({ launchApp, mock }) => {
    const { ms, gc, wa } = setup(mock);
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${gc}"]`).click();
    const input = cv.locator('.cv-input');
    await expect(input).toHaveAttribute('placeholder', 'Nachricht über WhatsApp');
    // 1.27: the placeholder names the way — no line about WhatsApp's encryption above the composer
    await expect(cv.locator('.cv-wayhint')).toHaveCount(0);
    await expect(cv.locator('.cv-select-way, .cv-way-pick')).toHaveCount(0);
    await shots(page, 'person-senden');
    await input.fill('Bin gleich da');
    await input.press('Enter');
    await expect.poll(() => ms.messages(wa).some((m) => m.text === 'Bin gleich da')).toBe(true);
    expect(ms.messages(gc).some((m) => m.text === 'Bin gleich da')).toBe(false);
    expect(ms.log.calls.some((c) => c.method === 'POST' && /^persons\/\d+\/messages$/.test(c.route))).toBe(true);
    // Anna writes inside GateControl: the next answer goes there
    ms.receive(gc, { text: 'Ich warte am Eingang.' });
    await expect(input).toHaveAttribute('placeholder', 'Nachricht über GateControl');
    await expect(cv.locator('.cv-wayhint')).toHaveCount(0);
  });

  test('the suggestion card: „Ansehen“, the dialog with the name, „Nicht jetzt“, „Zusammenführen“', async ({ launchApp, mock }) => {
    const { ms, wa, kim } = setup(mock, { person: false });
    const sugg = (conversationId, userId, contact, account) => ({
      id: `${conversationId}-${userId}`, conversationId, userId, network: 'whatsapp', label: 'WhatsApp', strength: 'strong', via: 'own_whatsapp',
      contact: { name: contact, avatarUrl: null, avatarMediaId: null }, account: { name: account, avatarUrl: null, initials: account.slice(0, 2).toUpperCase(), colorHex: '#F97316' },
      text: `„${contact}“ bei WhatsApp ist vielleicht ${account}.`, reason: `${account} hat das eigene WhatsApp mit GateControl verknüpft, und es ist dein Kontakt „${contact}“.`,
    });
    ms.people21.suggestions = [sugg(kim, 9, 'Kim Muster', 'Lena'), sugg(wa, 8, 'Schatzimausi 💕', 'Anna')];
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    const card = cv.locator('.cv-sugg');
    await expect(card).toContainText('„Kim Muster“ bei WhatsApp ist vielleicht Lena.');
    await expect(card).toContainText('Zu einem Chat zusammenführen?');
    await shots(page, 'person-vorschlag');
    await card.locator('[data-act="sugg-open"]').click();
    const dlg = cv.locator('.cv-merge-dlg');
    await expect(dlg.locator('.cv-dlg-head')).toHaveText('Zu einer Person zusammenführen?');
    await expect(dlg.locator('.cv-why')).toContainText('Lena hat das eigene WhatsApp');
    await expect(dlg.locator('.cv-pn-opt input').first()).toBeChecked();
    await shots(page, 'person-dialog');
    await dlg.locator('.cv-dlg-foot .btn', { hasText: 'Nicht jetzt' }).click();
    await expect.poll(() => ms.people21.answers).toEqual([{ id: `${kim}-9`, action: 'later' }]);
    await expect(card).toContainText('„Schatzimausi 💕“ bei WhatsApp ist vielleicht Anna.');
    await card.locator('[data-act="sugg-open"]').click();
    // the contact's name instead of the account's
    await dlg.locator('.cv-pn-opt', { hasText: 'Schatzimausi 💕' }).locator('input').check();
    await dlg.locator('.cv-dlg-foot .btn', { hasText: 'Zusammenführen' }).click();
    await expect.poll(() => ms.people21.merges.at(-1)).toEqual({ conversationIds: [wa], userId: 8, name: wa });
    await expect(cv.locator('.cv-sugg')).toHaveCount(0);
    const head = cv.locator('.cv-head .cv-head-tx b');
    await expect(head).toHaveText('Schatzimausi 💕');
    // 1.27: under the name only the logos of the ways („GateControl · WhatsApp“ is their label)
    await expect(cv.locator('.cv-head .cv-head-sub')).toHaveAttribute('aria-label', 'GateControl · WhatsApp');
    await expect(cv.locator('.cv-head .cv-head-sub')).toHaveText('');
    await expect(cv.locator(`.cv-row[data-id="${wa}"]`)).toHaveCount(0);
  });

  test('„Wege von …“: the ways, the name, „Trennen“ (nothing lost); „Mit Person zusammenführen …“ in a WhatsApp chat', async ({ launchApp, mock }) => {
    const { ms, gc, wa, kim, pid } = setup(mock);
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${gc}"]`).click();
    await cv.locator('.cv-head-who').click();
    const info = cv.locator('.cv-info');
    await expect(info).toBeVisible();
    await expect(info.locator('.cv-info-top .cv-dim')).toHaveText('Nur für dich zusammengeführt – Anna sieht davon nichts.');
    const sec = info.locator('.cv-ways-sec');
    await expect(sec.locator('.cv-sec')).toHaveText('Wege von Anna');
    await expect(sec.locator('.cv-wrow')).toHaveCount(2);
    await expect(sec.locator('.cv-wrow[data-way="gatecontrol"] small')).toHaveText('Konto Anna');
    await expect(sec.locator('.cv-wrow[data-way="whatsapp"] small')).toHaveText('als „Schatzimausi 💕“');
    await shots(page, 'person-wege');
    // the name in the list
    await sec.locator('[data-act="person-name"]').selectOption(String(wa));
    await expect.poll(() => ms.people21.names.at(-1)).toBe(wa);
    await expect(cv.locator(`.cv-row[data-id="${gc}"] .cv-row-name`)).toHaveText('Schatzimausi 💕');
    // „Trennen“
    await sec.locator('.cv-wrow[data-way="whatsapp"] [data-act="split"]').click();
    const conf = cv.locator('.cv-overlay').last();
    await expect(conf).toContainText('Den WhatsApp-Chat wieder getrennt zeigen? Es geht keine Nachricht verloren.');
    await conf.locator('.cv-dlg-foot .btn').last().click();
    await expect.poll(() => ms.people21.splits).toEqual([{ personId: pid, conversationId: wa }]);
    await expect(cv.locator(`.cv-row[data-id="${wa}"]`)).toBeVisible();
    await expect(cv.locator(`.cv-row[data-id="${gc}"] .cv-ways`)).toHaveCount(0);

    // by hand: in Kim's WhatsApp chat, the account Lena
    await cv.locator(`.cv-row[data-id="${kim}"]`).click();
    if (!(await info.isVisible())) await cv.locator('.cv-head-who').click();
    await info.locator('[data-act="merge-person"]').click();
    const pick = cv.locator('.cv-overlay').last();
    await expect(pick).toContainText('Wähle ein GateControl-Konto oder einen anderen Chat mit derselben Person.');
    await expect(pick.locator('.cv-sec').first()).toHaveText('GateControl-Konten');
    await pick.locator('.cv-q, input[type="search"]').fill('Len');
    await expect(pick.locator('.cv-person')).toHaveCount(1);
    await shots(page, 'person-auswahl');
    await pick.locator('.cv-person[data-user="9"]').click();
    const named = cv.locator('.cv-merge-dlg');
    await expect(named.locator('.cv-pn-opt')).toHaveCount(2);
    await named.locator('.cv-dlg-foot .btn', { hasText: 'Zusammenführen' }).click();
    await expect.poll(() => ms.people21.merges.at(-1)).toEqual({ conversationIds: [kim], userId: 9, name: 'account' });
    await expect(cv.locator('.cv-head .cv-head-tx b')).toHaveText('Lena');
  });

  test('after linking WhatsApp, once: „Dürfen andere auf diesem Server dich an deinem WhatsApp erkennen?“', async ({ launchApp, mock }) => {
    const { ms } = setup(mock, { person: false });
    ms.bridge.networks[0].logins = [];
    ms.bridge.confirmAfter = 1;
    ms.people21.recognition = { asked: false, allowed: false };
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator('.cv-list-title .cv-ib-flat').first().click();
    const set = cv.locator('.cv-settings');
    await set.locator('.cv-set-item[data-section="linked"]').click();
    await set.locator('[data-act="link"]').click();
    await set.locator('#cv-br-phone').fill('+49 1512 0000000');
    await set.locator('[data-act="code"]').click();
    await expect(set.locator('.cv-br-rec-head')).toHaveText('Dürfen andere auf diesem Server dich an deinem WhatsApp erkennen?');
    await expect(set.locator('.cv-br')).toContainText('Du kannst das jederzeit in „Mein Profil“ unter „Erkennung“ ändern.');
    await shots(page, 'person-erkennung');
    await set.locator('[data-act="rec-yes"]').click();
    await expect.poll(() => ms.people21.recognition).toEqual({ asked: true, allowed: true });
    await expect(set.locator('.cv-br-row[data-net="whatsapp"]')).toHaveAttribute('data-state', 'linked');
    await expect(set.locator('.cv-br-rec-head')).toHaveCount(0);
  });
});

test.describe('chats – Versandweg, Plus-Menü (Messenger 1.27)', () => {
  test('„Nachrichten senden über“: Automatisch · gerade WhatsApp, „Immer GateControl“ → PUT persons/:id, the placeholder follows', async ({ launchApp, mock }) => {
    const { ms, gc, pid } = setup(mock, { features: FEATURES_V127 });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${gc}"]`).click();
    const input = cv.locator('.cv-input');
    await expect(input).toHaveAttribute('placeholder', 'Nachricht über WhatsApp');
    await cv.locator('.cv-head-who').click();
    const sec = cv.locator('.cv-info .cv-reply-sec');
    await expect(sec.locator('.cv-sec')).toHaveText('Nachrichten senden über');
    await expect(sec.locator('.cv-rp-opt b')).toHaveText(['Automatisch', 'Immer GateControl', 'Immer WhatsApp']);
    await expect(sec.locator('.cv-rp-opt[data-pref="auto"] small')).toHaveText('Weg der letzten Nachricht von Anna · gerade WhatsApp');
    await expect(sec.locator('.cv-rp-opt[data-pref="whatsapp"] small')).toHaveText('Ist WhatsApp nicht verbunden, geht es über GateControl');
    await expect(sec.locator('.cv-rp-opt[data-pref="auto"] input')).toBeChecked();
    await expect(sec.locator('.cv-note')).toHaveText('Antwortest du auf eine Nachricht, geht die Antwort weiter über deren Weg.');
    await shots(page, 'person-versandweg');
    await sec.locator('.cv-rp-opt[data-pref="gatecontrol"] input').check();
    await expect.poll(() => ms.people21.replyPrefs.at(-1)).toEqual({ personId: pid, method: 'PUT', replyPref: 'gatecontrol' });
    await expect(input).toHaveAttribute('placeholder', 'Nachricht über GateControl');
    await input.fill('Mach ich.');
    await input.press('Enter');
    await expect.poll(() => ms.messages(gc).some((m) => m.text === 'Mach ich.')).toBe(true);
  });

  test('„Immer WhatsApp“ while WhatsApp is signed out: the line „WhatsApp nicht verbunden …“, the text goes over GateControl', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const ms = mock.setMessenger({ features: FEATURES_V127 });
    ms.bridge.networks[0].logins = [LINKED_LOGIN];
    ms.bridge.networks[0].consent = '2026-11-01T10:00:00.000Z';
    const gc = ms.addConv({ kind: 'direct', members: [7, 8] });
    const wa = ms.addBridgeConv({ title: 'Schatzimausi 💕', state: 'logged_out' });
    ms.at(ms.addBridgeMsg(wa, { text: 'Bis gleich 💕', contact: SCHATZ }), T0);
    const pid = ms.addPerson({ convIds: [gc, wa], userId: 8 });
    ms.persons.get(pid).replyPref = 'whatsapp';
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${gc}"]`).click();
    await expect(cv.locator('.cv-input')).toHaveAttribute('placeholder', 'Nachricht über GateControl');
    await expect(cv.locator('.cv-wayhint.is-fallback')).toHaveText('WhatsApp nicht verbunden – die Nachricht geht über GateControl.');
    await shots(page, 'person-fallback');
  });

  test('the plus menu over WhatsApp: everything, GateControl’s own kinds with its logo', async ({ launchApp, mock }) => {
    const { gc } = setup(mock, { features: FEATURES_V127 });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${gc}"]`).click();
    await expect(cv.locator('.cv-input')).toHaveAttribute('placeholder', 'Nachricht über WhatsApp');
    await cv.locator('.cv-attach-btn').click();
    const menu = cv.locator('.cv-menu');
    // WhatsApp takes no files here (the mock's bridge without media) and no location: the location goes over GateControl
    await expect(menu.locator('.cv-menu-item[data-item="file"]')).toHaveCount(0);
    for (const id of ['location', 'poll', 'event']) await expect(menu.locator(`.cv-menu-item[data-item="${id}"] .cv-menu-gc`)).toHaveAttribute('aria-label', 'Geht über GateControl');
    await expect(menu.locator('.cv-menu-gcnote')).toHaveText('Mit Logo: geht über GateControl, auch wenn dein Text gerade über WhatsApp geht.');
    await shots(page, 'person-plusmenue');
  });

  test('„Nur diese Nachricht über …“: the small logo opens the choice, one message over GateControl, the default stays', async ({ launchApp, mock }) => {
    const { ms, gc, wa, pid } = setup(mock, { features: FEATURES_V127 });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${gc}"]`).click();
    const input = cv.locator('.cv-input');
    const btn = cv.locator('.cv-waybtn');
    await expect(input).toHaveAttribute('placeholder', 'Nachricht über WhatsApp');
    await expect(btn).toHaveAttribute('data-way', 'whatsapp');
    await expect(btn).toHaveAttribute('aria-label', 'Weg für die nächste Nachricht: WhatsApp – ändern');
    await expect(btn).not.toHaveClass(/is-once/);
    // a click only opens the choice: nothing changes yet
    await btn.click();
    const menu = cv.locator('.cv-menu');
    await expect(menu.locator('.cv-once-sec')).toHaveText('Nur diese Nachricht über');
    await expect(menu.locator('.cv-once-opt b')).toHaveText(['GateControl', 'WhatsApp']);
    await expect(menu.locator('.cv-once-opt small')).toHaveText(['alle Funktionen', 'Weg der letzten Nachricht']);
    await expect(menu.locator('.cv-once-opt[data-item="way:whatsapp"]')).toHaveAttribute('aria-checked', 'true');
    await expect(menu.locator('.cv-menu-item[data-item="way:change"]')).toHaveText('Standard für Anna ändern …');
    await expect(input).toHaveAttribute('placeholder', 'Nachricht über WhatsApp');
    await shots(page, 'person-schnellwechsel');
    await menu.locator('.cv-once-opt[data-item="way:gatecontrol"]').click();
    await expect(menu).toHaveCount(0);
    await expect(input).toHaveAttribute('placeholder', 'Nur diese Nachricht über GateControl');
    await expect(btn).toHaveAttribute('data-way', 'gatecontrol');
    await expect(btn).toHaveClass(/is-once/);
    await input.fill('Nur hier.');
    await input.press('Enter');
    await expect.poll(() => ms.messages(gc).some((m) => m.text === 'Nur hier.')).toBe(true);
    expect(ms.messages(wa).some((m) => m.text === 'Nur hier.')).toBe(false);
    expect(ms.log.calls.some((c) => c.method === 'POST' && c.route === `persons/${pid}/messages`)).toBe(false);
    // only that one message: the next one goes the usual way again, „Nachrichten senden über“ was not touched
    await expect(input).toHaveAttribute('placeholder', 'Nachricht über WhatsApp');
    await expect(btn).not.toHaveClass(/is-once/);
    expect(ms.people21.replyPrefs).toEqual([]);
    await input.fill('Wieder über WhatsApp.');
    await input.press('Enter');
    await expect.poll(() => ms.messages(wa).some((m) => m.text === 'Wieder über WhatsApp.')).toBe(true);
    // „Standard für Anna ändern …“ opens the chat info at „Nachrichten senden über“
    await btn.click();
    await cv.locator('.cv-menu .cv-menu-item[data-item="way:change"]').click();
    await expect(cv.locator('.cv-info .cv-reply-sec')).toBeVisible();
    await expect(cv.locator('.cv-info .cv-reply-sec .cv-rp-opt[data-pref="auto"] input')).toBeFocused();
  });

  test('without the plus menu „Standort senden“ is a button of its own — with GateControl’s logo when it goes there', async ({ launchApp, mock }) => {
    const { gc } = setup(mock, { features: { ...FEATURES_V127, polls: false, events: false, actions: false } });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${gc}"]`).click();
    await expect(cv.locator('.cv-input')).toHaveAttribute('placeholder', 'Nachricht über WhatsApp');
    const loc = cv.locator('.cv-loc-btn');
    await expect(loc).toHaveAttribute('aria-label', 'Standort senden · Geht über GateControl');
    await expect(loc.locator('.cv-loc-gc')).toHaveCount(1);
    await shots(page, 'person-standortknopf');
  });

  test('without the plus menu, a location the bridge sends: the button without the logo', async ({ launchApp, mock }) => {
    const { ms, gc } = setup(mock, { features: { ...FEATURES_V127, polls: false, events: false, actions: false } });
    ms.bridge.location = true;
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${gc}"]`).click();
    const loc = cv.locator('.cv-loc-btn');
    await expect(loc).toHaveAttribute('aria-label', 'Standort senden');
    await expect(loc.locator('.cv-loc-gc')).toHaveCount(0);
  });

  test('a location the bridge sends: in the menu without the logo', async ({ launchApp, mock }) => {
    const { ms, gc } = setup(mock, { features: FEATURES_V127 });
    ms.bridge.location = true;
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator(`.cv-row[data-id="${gc}"]`).click();
    await cv.locator('.cv-attach-btn').click();
    const menu = cv.locator('.cv-menu');
    await expect(menu.locator('.cv-menu-item[data-item="location"]')).toBeVisible();
    await expect(menu.locator('.cv-menu-item[data-item="location"] .cv-menu-gc')).toHaveCount(0);
    await expect(menu.locator('.cv-menu-item[data-item="poll"] .cv-menu-gc')).toHaveCount(1);
  });
});
