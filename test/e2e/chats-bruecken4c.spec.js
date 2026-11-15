'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');
const { FEATURES_STAGE5, FEATURES_STAGE4C } = require('./support/messenger-mock');

// Messenger 1.18 (Stufe 4c der Brücken): „Neuer Chat“ with contacts — one search, the sections GateControl, WhatsApp
// and „Aus deinem Adressbuch“, „Alle …“, a WhatsApp contact starts its chat at once, an address book number is checked
// on tap (which number, not at WhatsApp, too many checks, the bridge not reachable), „… bei WhatsApp prüfen“ for a
// number in the search, nobody found, the WhatsApp section not reachable / signed out, 409 contact_expired (the list
// anew) and „Nicht dabei? Nummer eingeben“. Without the word everything stays as in 1.16. Texts are checked in German.

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
const REF = (c) => `k${c.repeat(44)}`;

async function openChats(launchApp, mock) {
  const { page, app } = await launchApp();
  await setupWithApiKey(page, mock);
  await lang(page, 'de');
  await page.locator('#nav-chats').click();
  await expect(page.locator('#page-chats')).toHaveClass(/active/);
  return { page, app };
}

function setup(mock, { features = FEATURES_STAGE4C } = {}) {
  mock.setPush({ topics: [], items: [] });
  const ms = mock.setMessenger({ features });
  const B = ms.bridge;
  B.networks[0].logins = [LINKED_LOGIN];
  B.networks[0].consent = '2026-11-01T10:00:00.000Z';
  B.networks[0].newChat = { available: true, reason: null, limit: { perHour: 10, left: 7, retryAfterS: 0 } };
  B.contacts = [
    { ref: REF('a'), name: 'Lena Berger', alsoInAddressBook: true, addressBookId: 13 },
    { ref: REF('b'), name: 'Anna Albers' },
    { ref: REF('c'), name: 'Jonas Fischer' },
    { ref: REF('d'), name: 'Kim Muster' },
    { ref: REF('e'), name: 'Paul Schmidt' },
  ];
  B.book = [
    { contactId: 12, name: 'Sabine Wolf', phones: [
      { key: 'mobile', kind: 'mobile', number: '+49 151 23456780', e164: '+4915123456780', landline: false, notOnNetwork: false },
      { key: 'work', kind: 'work', number: '+49 89 4455667', e164: '+49894455667', landline: true, notOnNetwork: false },
      { key: 'home', kind: 'home', number: '+49 30 12345678', e164: '+493012345678', landline: true, notOnNetwork: false },
    ] },
    { contactId: 14, name: 'Tom Klein', phones: [{ key: 'mobile', kind: 'mobile', number: '+49 160 9876543', e164: '+491609876543', landline: false, notOnNetwork: false }] },
    { contactId: 15, name: 'Uwe Brandt', phones: [{ key: 'mobile', kind: 'mobile', number: '+49 170 1112223', e164: '+491701112223', landline: false, notOnNetwork: false }] },
    { contactId: 16, name: 'Vera Lang', phones: [{ key: 'mobile', kind: 'mobile', number: '+49 171 3334445', e164: '+491713334445', landline: false, notOnNetwork: false }] },
  ];
  B.numbers.set('+4915123456780', 'Sabine');
  return ms;
}

const contactCalls = (ms) => ms.log.calls.filter((c) => c.route === 'contacts/new-chat');

test.describe('chats – „Neuer Chat“ with contacts (Messenger 1.18)', () => {
  test('an older plugin (1.17): no sections, the row „WhatsApp-Chat mit Nummer“ as before', async ({ launchApp, mock }) => {
    const ms = setup(mock, { features: FEATURES_STAGE5 });
    ms.addMsg(ms.addConv(), { text: 'Hallo' });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator('[aria-label="Neuer Chat"]').click();
    await expect(cv.locator('.cv-nc-row[data-net="whatsapp"] b')).toHaveText('WhatsApp-Chat mit Nummer');
    await expect(cv.locator('.cv-ncc')).toHaveCount(0);
    await expect(cv.locator('.cv-new input[type=search]')).toHaveAttribute('placeholder', 'Person suchen');
    expect(contactCalls(ms).length).toBe(0);
  });

  test('the sections, „Alle …“, a WhatsApp contact starts its chat at once with its first line', async ({ launchApp, mock }) => {
    const ms = setup(mock);
    ms.bridge.contactsDelayMs = SHOTS ? 6000 : 1200;
    ms.addMsg(ms.addConv(), { text: 'Hallo' });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    await cv.locator('[aria-label="Neuer Chat"]').click();
    const dlg = cv.locator('.cv-ncc-dlg');
    await expect(dlg.locator('input[type=search]')).toHaveAttribute('placeholder', 'Name oder Nummer suchen');
    // loading: GateControl at once, WhatsApp as a skeleton
    await expect(dlg.locator('[data-sec="gatecontrol"] .cv-ncc-row')).toHaveCount(2);
    await expect(dlg.locator('[data-sec="whatsapp"] .cv-ncc-sk')).toHaveCount(3);
    await shots(page, 'ncc-laedt');
    await expect(dlg.locator('[data-sec="whatsapp"] .cv-ncc-sk')).toHaveCount(0);
    ms.bridge.contactsDelayMs = 0;
    await expect(dlg.locator('.cv-nc-row')).toHaveCount(0);
    await expect(dlg.locator('[data-sec="gatecontrol"] .cv-ncc-cap')).toHaveText('GateControl · 2');
    await expect(dlg.locator('[data-sec="gatecontrol"] [data-row="gc:8"] .cv-ncc-pill')).toHaveText('Chat öffnen');
    await expect(dlg.locator('[data-sec="whatsapp"] .cv-ncc-cap')).toHaveText('WhatsApp · 5');
    await expect(dlg.locator('[data-sec="whatsapp"] .cv-ncc-cap .cv-ncc-svc.is-net-whatsapp svg')).toHaveCount(1);
    const wa = dlg.locator('[data-sec="whatsapp"] .cv-ncc-row');
    await expect(wa).toHaveCount(3);
    await expect(wa.locator('.cv-ncc-name')).toHaveText(['Anna Albers', 'Jonas Fischer', 'Kim Muster']);
    await expect(wa.first().locator('small')).toHaveText('WhatsApp-Kontakt');
    await expect(dlg.locator('[data-more="wa"]')).toHaveText('Alle 5 WhatsApp-Kontakte');
    await expect(dlg.locator('[data-sec="book"] .cv-ncc-cap')).toHaveText('Aus deinem Adressbuch · 4');
    await expect(dlg.locator('[data-sec="book"] .cv-ncc-row').first().locator('small')).toHaveText('3 Nummern');
    await expect(dlg.locator('[data-sec="book"] [data-row="ab:14"] small')).toHaveText('Mobil · +49 160 9876543');
    await expect(dlg.locator('[data-more="ab"]')).toHaveText('Alle 4 mit Telefonnummer');
    await expect(dlg.locator('.cv-ncc-priv')).toHaveText('Deine WhatsApp-Kontakte bleiben auf deinem Server. Eine Nummer aus deinem Adressbuch geht nur dann an WhatsApp, wenn du den Kontakt antippst.');
    await expect(dlg.locator('.cv-ncc-nfoot')).toHaveText('Nicht dabei? Nummer eingeben');
    await shots(page, 'ncc-alles-da');
    await dlg.locator('[data-more="wa"]').click();
    await expect(wa).toHaveCount(5);
    await expect(wa.nth(3).locator('small')).toHaveText('auch in deinem Adressbuch');
    // group: the accounts with check boxes, no contacts
    await dlg.locator('.cv-tabs button[data-mode="group"]').click();
    await expect(dlg.locator('.cv-ncc')).toBeHidden();
    await expect(dlg.locator('.cv-ncc-foot')).toBeHidden();
    await expect(dlg.locator('.cv-person input[type=checkbox]')).toHaveCount(2);
    await dlg.locator('.cv-tabs button[data-mode="direct"]').click();
    await expect(dlg.locator('.cv-ncc')).toBeVisible();
    // a WhatsApp contact: the chat at once, nothing checked
    await wa.nth(3).click();
    await expect(dlg).toHaveCount(0);
    await expect(cv.locator('.cv-head b')).toHaveText('Lena Berger');
    await expect(cv.locator('.cv-sys[data-sys="new-chat"]')).toHaveText('Neuer Chat über WhatsApp mit Lena Berger. Die Nachrichten kommen in der gewohnten WhatsApp-App an.');
    await shots(page, 'ncc-wa-chat');
    expect(ms.bridge.lookups).toBe(0);
    const post = ms.log.calls.filter((c) => c.method === 'POST' && c.route === 'bridges/whatsapp/chats');
    expect(post.length).toBe(1);
    // again: „Chat öffnen“, no second chat
    await cv.locator('[aria-label="Neuer Chat"]').click();
    await dlg.locator('input[type=search]').fill('Lena');
    await expect(wa).toHaveCount(1);
    await expect(wa.locator('.cv-ncc-pill')).toHaveText('Chat öffnen');
    await wa.click();
    await expect(dlg).toHaveCount(0);
    await expect(cv.locator('.cv-head b')).toHaveText('Lena Berger');
  });

  test('an address book contact: which number, checking, found → the chat; not at WhatsApp; too many checks', async ({ launchApp, mock }) => {
    const ms = setup(mock);
    ms.addMsg(ms.addConv(), { text: 'Hallo' });
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    const dlg = cv.locator('.cv-ncc-dlg');
    await cv.locator('[aria-label="Neuer Chat"]').click();
    const book = dlg.locator('[data-sec="book"]');
    // one number, not at WhatsApp → greyed, the hint
    await book.locator('[data-row="ab:14"]').click();
    await expect(book.locator('[data-row="ab:14"] .cv-ncc-pill')).toHaveText('nicht bei WhatsApp');
    await expect(book.locator('.cv-ncc-note')).toHaveText('Unter +49 160 9876543 gibt es kein WhatsApp. Hat Tom eine andere Nummer, gib sie unten ein.');
    await expect(book.locator('[data-row="ab:14"]')).toHaveClass(/is-off/);
    await shots(page, 'ncc-nicht-bei-wa');
    expect(ms.bridge.lookups).toBe(1);
    // several numbers: „Welche Nummer?“, mobile first, landlines dim
    await book.locator('[data-row="ab:12"]').click();
    const pick = book.locator('.cv-ncc-pick');
    await expect(pick.locator('.cv-ncc-pkh')).toHaveText('Welche Nummer?');
    await expect(pick.locator('.cv-ncc-pk b')).toHaveText(['Mobil', 'Geschäftlich', 'Privat']);
    await expect(pick.locator('.cv-ncc-pk.is-dim small')).toHaveText(['Festnetz', 'Festnetz']);
    await shots(page, 'ncc-welche-nummer');
    // checking (slow bridge) → the chat opens with its first line
    ms.bridge.chatDelayMs = SHOTS ? 6000 : 1200;
    await pick.locator('[data-key="mobile"]').click();
    await expect(book.locator('[data-row="ab:12"] small')).toHaveText('Prüft bei WhatsApp …');
    await expect(book.locator('[data-row="ab:12"]')).toHaveClass(/is-tap/);
    await shots(page, 'ncc-pruefung');
    await expect(dlg).toHaveCount(0);
    ms.bridge.chatDelayMs = 0;
    await expect(cv.locator('.cv-head b')).toHaveText('Sabine Wolf');
    await expect(cv.locator('.cv-sys[data-sys="new-chat"]')).toHaveText('Neuer Chat über WhatsApp mit Sabine Wolf (+49 151 23456780, aus deinem Adressbuch). Die Nachrichten kommen in der gewohnten WhatsApp-App an.');
    await shots(page, 'ncc-adressbuch-chat');
    expect(ms.log.bridge.filter((b) => b.op === 'chat_book').map((b) => b.key)).toEqual(['mobile', 'mobile']);
    // too many checks: „ab HH:MM“ and the hint; WhatsApp contacts still go
    ms.bridge.lookupMax = ms.bridge.lookups;
    await cv.locator('[aria-label="Neuer Chat"]').click();
    await dlg.locator('[data-more="ab"]').click();
    await book.locator('[data-row="ab:15"]').click();
    await expect(book.locator('[data-row="ab:15"] .cv-ncc-pill')).toHaveText(/^ab \d\d:\d\d$/);
    await expect(book.locator('.cv-ncc-note.is-warn')).toHaveText('Du hast in der letzten Stunde 10 Nummern geprüft. WhatsApp-Kontakte und bestehende Chats gehen weiter.');
    await shots(page, 'ncc-zu-viele');
    // the bridge does not answer
    ms.bridge.chatFails = { status: 503, code: 'bridge_unreachable', reason: 'timeout' };
    await book.locator('[data-row="ab:16"]').click();
    await expect(book.locator('.cv-ncc-note.is-err')).toHaveText('Brücke nicht erreichbar. Versuch es gleich noch einmal.');
    // the number never in a URL
    expect(ms.log.calls.some((c) => /\d{6}/.test(c.route + JSON.stringify(c.query)))).toBe(false);
  });

  test('the search: filtered sections, „… bei WhatsApp prüfen“ for a number, nobody found, the number dialog', async ({ launchApp, mock }) => {
    const ms = setup(mock);
    ms.bridge.numbers.set('+491715550123', 'Max Neu');
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    const dlg = cv.locator('.cv-ncc-dlg');
    await cv.locator('[aria-label="Neuer Chat"]').click();
    const search = dlg.locator('input[type=search]');
    await search.fill('berg');
    await expect(dlg.locator('[data-sec="whatsapp"] .cv-ncc-cap')).toHaveText('WhatsApp');
    await expect(dlg.locator('[data-sec="whatsapp"] .cv-ncc-name')).toHaveText(['Lena Berger']);
    await expect(dlg.locator('[data-sec="gatecontrol"]')).toHaveCount(0);
    await expect(dlg.locator('[data-sec="book"]')).toHaveCount(0);
    await shots(page, 'ncc-suche');
    // nobody
    await search.fill('xyz');
    await expect(dlg.locator('.cv-ncc-empty b')).toHaveText('Niemand mit „xyz“ gefunden');
    await expect(dlg.locator('.cv-ncc-empty span').last()).toHaveText('Gesucht in GateControl, in deinen WhatsApp-Kontakten und in deinem Adressbuch.');
    await expect(dlg.locator('.cv-ncc-foot')).toBeHidden();
    await shots(page, 'ncc-kein-treffer');
    // a number: checked only on tap, in the number dialog at once
    await search.fill('0171 5550123');
    const row = dlg.locator('[data-row="number"]');
    await expect(row.locator('.cv-ncc-name')).toHaveText('+49 171 5550123 bei WhatsApp prüfen');
    await shots(page, 'ncc-nummer-suche');
    expect(ms.bridge.lookups).toBe(0);
    await row.click();
    const nc = cv.locator('.cv-nc-dlg');
    await expect(nc.locator('.cv-nc')).toHaveAttribute('data-state', 'found');
    await expect(nc.locator('.cv-nc-res b')).toHaveText('Max Neu');
    await page.keyboard.press('Escape');
    await expect(nc).toHaveCount(0);
    // the footer: the number dialog empty
    await cv.locator('[aria-label="Neuer Chat"]').click();
    await dlg.locator('.cv-ncc-nfoot').click();
    await expect(nc.locator('.cv-nc')).toHaveAttribute('data-state', 'input');
    await expect(nc.locator('.cv-nc-num')).toHaveValue('');
  });

  test('WhatsApp not reachable or signed out; 409 contact_expired loads the list again', async ({ launchApp, mock }) => {
    const ms = setup(mock);
    ms.bridge.listState = 'unreachable';
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    const dlg = cv.locator('.cv-ncc-dlg');
    await cv.locator('[aria-label="Neuer Chat"]').click();
    const waSec = dlg.locator('[data-sec="whatsapp"]');
    await expect(waSec.locator('.cv-ncc-res b')).toHaveText('WhatsApp-Kontakte gerade nicht verfügbar');
    await expect(waSec.locator('.cv-nc-rb > span')).toHaveText('Die Brücke antwortet nicht. GateControl-Konten gehen weiter.');
    await expect(dlg.locator('[data-sec="book"] .cv-ncc-note')).toHaveText('Antippen geht wieder, sobald WhatsApp erreichbar ist.');
    await expect(dlg.locator('[data-sec="book"] .cv-ncc-row').first()).toBeDisabled();
    await shots(page, 'ncc-bruecke-weg');
    // „Erneut versuchen“
    ms.bridge.listState = 'ok';
    const before = contactCalls(ms).length;
    await waSec.locator('.cv-ncc-link').click();
    await expect(waSec.locator('.cv-ncc-row')).toHaveCount(3);
    expect(contactCalls(ms).length).toBe(before + 1);
    // the reference ran out: the list anew, no chat
    ms.bridge.expired.add(REF('b'));
    const n = contactCalls(ms).length;
    await waSec.locator('.cv-ncc-row').first().click();
    await expect.poll(() => contactCalls(ms).length).toBe(n + 1);
    await expect(dlg).toHaveCount(1);
    await dlg.locator('[aria-label="Schließen"]').click();
    // signed out
    ms.bridge.networks[0].logins = [{ ...LINKED_LOGIN, state: 'logged_out' }];
    await cv.locator('[aria-label="Neuer Chat"]').click();
    await expect(waSec.locator('.cv-ncc-res b')).toHaveText('WhatsApp ist abgemeldet');
    await expect(dlg.locator('[data-sec="book"] .cv-ncc-note')).toHaveText('Antippen geht wieder, sobald WhatsApp neu verknüpft ist.');
    await shots(page, 'ncc-abgemeldet');
    await waSec.locator('.cv-ncc-link').click();
    await expect(dlg).toHaveCount(0);
    await expect(cv.locator('.cv-settings .cv-set-title')).toHaveText('Verknüpfte Dienste');
  });

  test('never linked (or a child without new chats): GateControl only, no address book, no number entry', async ({ launchApp, mock }) => {
    const ms = setup(mock);
    ms.bridge.networks[0].logins = [];
    const { page } = await openChats(launchApp, mock);
    const cv = page.locator('#page-chats');
    const dlg = cv.locator('.cv-ncc-dlg');
    await cv.locator('[aria-label="Neuer Chat"]').click();
    await expect(dlg.locator('[data-sec="gatecontrol"] .cv-ncc-row')).toHaveCount(2);
    await expect(dlg.locator('[data-sec="whatsapp"]')).toHaveCount(0);
    await expect(dlg.locator('[data-sec="book"]')).toHaveCount(0);
    await expect(dlg.locator('.cv-ncc-foot')).toBeHidden();
    await dlg.locator('input[type=search]').fill('xyz');
    await expect(dlg.locator('.cv-ncc-empty span').last()).toHaveText('Gesucht in den Konten auf deinem Server.');
    await expect(dlg.locator('.cv-ncc-empty button')).toHaveCount(0);
  });
});
