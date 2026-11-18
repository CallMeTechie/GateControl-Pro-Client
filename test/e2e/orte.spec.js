'use strict';

const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');
const { FEATURES_14 } = require('./support/messenger-mock');

// „Meine Orte“ (GateControl 1.299, Mein Profil › Meine Orte): the page — the list (own places with „Genutzt von“, Familie's
// only to look at) and the map —, a new place by the address search and by a click on the map (its address asked of
// the map service), the search of this PC while the server's is off, a change that sends only what differs, deleting a
// place in use (who uses it, then „Trotzdem löschen“), the push event `places` (the page loads again — Windows watches
// no place), a server before „Meine Orte“; the one place choice in the event dialog of Chats (Messenger 1.28
// `profilePlaces`) and the places of Notizen 1.8.0 (`profilePlaces`). Names and addresses are made up.

const SHOTS = process.env.GC_E2E_SHOTS || null;
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` }); };

const BASE = '/api/v1/client/me/profile/places';
const calls = (pl, method, re) => pl.srv.calls.filter((c) => c.method === method && re.test(c.path));
// a made-up address for the click on the map and for the search of this PC
const GEOCODE = {
  reverse: { display_name: 'Mühlenweg 5, 12345 Musterstadt, Deutschland', address: { road: 'Mühlenweg', house_number: '5', postcode: '12345', town: 'Musterstadt' } },
  search: [{ lat: '50.081', lon: '8.652', name: 'Café Lindenblatt', display_name: 'Café Lindenblatt, Lindenallee 9, 12345 Musterstadt, Deutschland', address: { road: 'Lindenallee', house_number: '9', postcode: '12345', town: 'Musterstadt' } }],
};

async function openPlaces(launchApp, mock) {
  const { page, app } = await launchApp();
  await setupWithApiKey(page, mock);
  await expect(page.locator('#nav-orte')).toBeVisible();
  await page.locator('#nav-orte').click();
  const root = page.locator('#page-orte');
  await expect(root).toHaveClass(/active/);
  await expect(root.locator('.mo-row').first()).toBeVisible();
  return { page, app, root };
}

test.describe('Meine Orte', () => {
  test('list and map, new by search and by a click on the map, a change, deleting a place in use', async ({ launchApp, mock }) => {
    mock.setGeocode(GEOCODE);
    const pl = await mock.setPlaces();
    const { page, root } = await openPlaces(launchApp, mock);

    // the list: by name, the grey line, how many plugins use a place; every place on the map with its circle
    const rows = root.locator('.mo-list .mo-row');
    await expect(rows.locator('b')).toHaveText(['Arbeit', 'Baumarkt', 'Fitnessstudio', 'Zuhause']);
    await expect(root.locator('[data-place="p:11"] .mo-row-sub')).toHaveText(/^Lindenweg 12, Musterstadt · 150 m · (Familie|family)$/);
    await expect(root.locator('[data-place="p:11"] [data-mark="used"]')).toHaveText(/2 Plugins|2 plugins/);
    await expect(root.locator('[data-place="p:13"] [data-mark="used"]')).toHaveCount(0);
    await expect(root.locator('.mo-sub')).toHaveText(/^(4 Orte|4 places)$/);
    const overview = root.locator('.mo-map[data-map="overview"]');
    await expect(overview.locator('.mo-map-pin')).toHaveCount(4);
    await expect(overview.locator('.mo-map-circle').first()).toBeVisible();
    await shot(page, 'orte-list');

    // new: the address search only on „Suchen“, from 3 characters, near „Zuhause“ (this PC has no position)
    await root.locator('[data-act="new"]').click();
    const ed = root.locator('.mo-ed[data-editor="new"]');
    await expect(ed).toBeVisible();
    await ed.locator('[data-f="q"]').fill('Ka');
    await ed.locator('[data-act="search"]').click();
    await expect(ed.locator('[data-state="search-min"]')).toBeVisible();
    expect(calls(pl, 'GET', /places\/search$/)).toEqual([]);
    await ed.locator('[data-f="q"]').fill('Kanalweg');
    await page.waitForTimeout(400);
    expect(calls(pl, 'GET', /places\/search$/)).toEqual([]);
    await ed.locator('[data-f="q"]').press('Enter');
    await expect(ed.locator('[data-state="attribution"]')).toHaveText('© OpenStreetMap');
    await ed.locator('[data-hit="Baustoffhandel Nord"]').click();
    expect(calls(pl, 'GET', /places\/search$/)[0].query).toEqual({ q: 'Kanalweg', near: '50.05,8.60' });
    await expect(ed.locator('[data-list="hits"]')).toBeHidden();
    await expect(ed.locator('[data-f="name"]')).toHaveValue('Baustoffhandel Nord');
    await expect(ed.locator('[data-f="address"]')).toHaveValue('Kanalweg 3, Musterstadt');
    await ed.locator('[data-icon="shop"]').click();
    await ed.locator('[data-f="radius"]').fill('300');
    // „Familie“ only in a family
    await expect(ed.locator('[data-vis]')).toHaveCount(2);
    await shot(page, 'orte-new-search');
    await ed.locator('[data-act="save"]').click();
    await expect(rows.locator('b')).toHaveText(['Arbeit', 'Baumarkt', 'Baustoffhandel Nord', 'Fitnessstudio', 'Zuhause']);
    expect(calls(pl, 'POST', /profile\/places$/).pop().body).toEqual({ name: 'Baustoffhandel Nord', lat: 50.12, lon: 8.71, icon: 'shop', radiusM: 300, visibility: 'self', address: 'Kanalweg 3, Musterstadt' });

    // new by a click on the map: the point, its address from the map service; without a name it is not saved
    await root.locator('[data-act="new"]').click();
    const ed2 = root.locator('.mo-ed[data-editor="new"]');
    await ed2.locator('[data-act="save"]').click();
    await expect(ed2.locator('[data-state="error"]')).toHaveText(/Namen|name/);
    await ed2.locator('[data-f="name"]').fill('Bäckerei Sonnenschein');
    await ed2.locator('[data-act="save"]').click();
    await expect(ed2.locator('[data-state="error"]')).toHaveText(/Punkt|point/);
    await ed2.locator('.mo-map[data-map="pick"]').click();
    await expect(ed2.locator('[data-f="address"]')).toHaveValue('Mühlenweg 5, 12345 Musterstadt');
    await expect(ed2.locator('.mo-map[data-map="pick"] .mo-map-pin')).toHaveCount(1);
    await ed2.locator('[data-act="save"]').click();
    await expect(rows.locator('b')).toHaveText(['Arbeit', 'Bäckerei Sonnenschein', 'Baumarkt', 'Baustoffhandel Nord', 'Fitnessstudio', 'Zuhause']);
    const made = calls(pl, 'POST', /profile\/places$/).pop().body;
    expect(made).toMatchObject({ name: 'Bäckerei Sonnenschein', icon: 'pin', radiusM: 150, visibility: 'self', address: 'Mühlenweg 5, 12345 Musterstadt' });
    expect(Math.abs(made.lat - 50.05)).toBeLessThan(0.01);
    expect(Math.abs(made.lon - 8.6)).toBeLessThan(0.01);

    // a change sends only what differs
    await root.locator('[data-place="p:12"]').click();
    const ed3 = root.locator('.mo-ed[data-editor="12"]');
    await expect(ed3.locator('[data-f="name"]')).toHaveValue('Arbeit');
    await expect(ed3.locator('[data-list="used-by"] li')).toHaveText([/^Messenger · 1 (Ortsnachricht|place message)$/]);
    await ed3.locator('[data-f="name"]').fill('Büro');
    await ed3.locator('[data-vis="all"]').click();
    await shot(page, 'orte-edit');
    await ed3.locator('[data-act="save"]').click();
    await expect(root.locator('[data-place="p:12"] b')).toHaveText('Büro');
    expect(calls(pl, 'PATCH', /profile\/places\/12$/).map((c) => c.body)).toEqual([{ name: 'Büro', visibility: 'all' }]);
    // nothing changed: nothing sent
    await root.locator('[data-place="p:12"]').click();
    await root.locator('.mo-ed [data-act="save"]').click();
    await expect(root.locator('.mo-ed')).toHaveCount(0);
    expect(calls(pl, 'PATCH', /profile\/places\/12$/)).toHaveLength(1);

    // deleting a place in use: who uses it, then „Trotzdem löschen“ (force)
    await root.locator('[data-place="p:11"]').click();
    await root.locator('.mo-ed [data-act="delete"]').click();
    await page.locator('.mo-dlg[data-dialog="place-delete"] [data-act="delete-yes"]').click();
    const inUse = page.locator('.mo-dlg[data-dialog="place-in-use"]');
    await expect(inUse.locator('[data-list="used-by"] li')).toHaveText([/^Messenger · 1 (Ortsnachricht|place message)$/, /^Notizen · 2 (Aufgaben|tasks)$/]);
    await shot(page, 'orte-in-use');
    await inUse.locator('[data-act="delete-force"]').click();
    await expect(root.locator('[data-place="p:11"]')).toHaveCount(0);
    expect(calls(pl, 'DELETE', /profile\/places\/11$/).map((c) => c.query)).toEqual([{}, { force: '1' }]);
    expect(pl.srv.state.places.has(11)).toBe(false);
    // not in use: gone after the question
    await root.locator('[data-place="p:13"]').click();
    await root.locator('.mo-ed [data-act="delete"]').click();
    await page.locator('.mo-dlg[data-dialog="place-delete"] [data-act="delete-yes"]').click();
    await expect(root.locator('[data-place="p:13"]')).toHaveCount(0);
    expect(calls(pl, 'DELETE', /profile\/places\/13$/).map((c) => c.query)).toEqual([{}]);
  });

  test('the server\'s search is off: this PC\'s address search answers, with the attribution', async ({ launchApp, mock }) => {
    mock.setGeocode(GEOCODE);
    const pl = await mock.setPlaces({ search: 'off' });
    const { page, root } = await openPlaces(launchApp, mock);
    await root.locator('[data-act="new"]').click();
    const ed = root.locator('.mo-ed[data-editor="new"]');
    await ed.locator('[data-f="q"]').fill('Lindenallee');
    await ed.locator('[data-act="search"]').click();
    await expect(ed.locator('[data-state="search-device"]')).toBeVisible();
    await expect(ed.locator('[data-state="attribution"]')).toHaveText('© OpenStreetMap');
    await shot(page, 'orte-search-off');
    await ed.locator('[data-hit="Café Lindenblatt"]').click();
    await ed.locator('[data-act="save"]').click();
    await expect(root.locator('.mo-row b', { hasText: 'Café Lindenblatt' })).toBeVisible();
    expect(calls(pl, 'GET', /places\/search$/)).toEqual([]);
    expect(calls(pl, 'POST', /profile\/places$/).pop().body).toMatchObject({ name: 'Café Lindenblatt', lat: 50.081, lon: 8.652, address: 'Café Lindenblatt, Lindenallee 9, 12345 Musterstadt' });

    // a server that says SEARCH_OFF only on the search: the same
    pl.srv.state.search = 'osm';
    await root.locator('[data-act="refresh"]').click();
    pl.srv.fail('/api/v1/client/me/places/search', 403, 'SEARCH_OFF');
    await root.locator('[data-act="new"]').click();
    const ed2 = root.locator('.mo-ed[data-editor="new"]');
    await ed2.locator('[data-f="q"]').fill('Lindenallee');
    await ed2.locator('[data-f="q"]').press('Enter');
    await expect(ed2.locator('[data-hit="Café Lindenblatt"]')).toBeVisible();
    await expect(ed2.locator('[data-state="search-device"]')).toBeVisible();
    expect(calls(pl, 'GET', /places\/search$/)).toHaveLength(1);
  });

  test('the push event `places` loads the page again; a server before „Meine Orte“ shows no entry', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const pl = await mock.setPlaces();
    const { root } = await openPlaces(launchApp, mock);
    await expect.poll(() => mock.pushStreams()).toBeGreaterThan(0);
    pl.srv.state.places.set(30, { id: 30, name: 'Kita Regenbogen', icon: 'school', lat: 50.065, lon: 8.62, radiusM: 150, address: 'Gartenstraße 2, Musterstadt', visibility: 'family', source: 'manual', usedBy: [], lastUsedAt: null });
    pl.srv.state.places.delete(14);
    mock.pushControl({ type: 'places', ids: [30, 14], deleted: false });
    await expect(root.locator('.mo-list .mo-row b')).toHaveText(['Arbeit', 'Fitnessstudio', 'Kita Regenbogen', 'Zuhause']);
  });

  test('an older server: no „Meine Orte“ in the menu, nothing asked again and again', async ({ launchApp, mock }) => {
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.count(BASE)).toBeGreaterThan(0);
    await page.waitForTimeout(800);
    await expect(page.locator('#nav-orte')).toBeHidden();
    expect(mock.count(BASE)).toBeLessThan(4);
  });

  test('Chats: the place of an event — chips, „Alle Orte…“ with groups and the search, a new place from an address', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [], items: [] });
    const pl = await mock.setPlaces();
    const ms = mock.setMessenger({ features: { ...FEATURES_14, profilePlaces: true }, familie: true });
    const fam = ms.addConv({ kind: 'group', members: [7, 8, 9], title: 'Familie' });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-chats').click();
    await page.locator(`#page-chats .cv-row[data-id="${fam}"]`).click();

    const openEvent = async () => {
      await page.locator('#page-chats .cv-attach-btn').click();
      await page.locator('#page-chats .cv-menu-item[data-item="event"]').click();
      const dlg = page.locator('#page-chats .cv-overlay').last();
      await expect(dlg.locator('.mo-pick')).toBeVisible();
      return dlg;
    };

    // chips: the most used first (Messenger's order), at most three, plus „Alle Orte…“; no old Familie select
    let dlg = await openEvent();
    const chips = dlg.locator('.mo-pick .mo-pchip:not(.is-all)');
    await expect(chips).toHaveText(['Arbeit', 'Zuhause', 'Grundschule']);
    await expect(dlg.locator('.mo-pick [data-ref="place:3"]')).toHaveClass(/is-familie/);
    await expect(dlg.locator('select[aria-label]').first()).toBeHidden();
    await dlg.locator('input.inp').first().fill('Teamessen');
    await dlg.locator('.mo-pick [data-ref="profile:12"]').click();
    await expect(dlg.locator('.cv-field input.inp').nth(3)).toHaveValue('Arbeit');
    await shot(page, 'orte-event-chips');
    await dlg.locator('.btn-pri').click();
    await expect.poll(() => ms.log.sent.at(-1) && ms.log.sent.at(-1).kind).toBe('event');
    expect(ms.log.sent.at(-1).event.place).toEqual({ label: 'Arbeit', lat: 50.110922, lon: 8.682127 });
    await expect.poll(() => calls(pl, 'POST', /profile\/places\/12\/used$/).length).toBe(1);

    // „Alle Orte…“: groups (recent, near „Zuhause“, A–Z), the local search; a Familie place goes as before
    dlg = await openEvent();
    await dlg.locator('input.inp').first().fill('Elternabend');
    await dlg.locator('.mo-pick [data-act="all"]').click();
    const sheet = page.locator('.mo-dlg[data-dialog="place-pick"]');
    await expect(sheet.locator('[data-group]').first()).toHaveAttribute('data-group', 'recent');
    await expect(sheet.locator('[data-group="near"]')).toHaveText(/Zuhause/);
    await shot(page, 'orte-event-sheet');
    await sheet.locator('[data-f="pick-q"]').fill('grund');
    await expect(sheet.locator('.mo-opt')).toHaveCount(1);
    await sheet.locator('.mo-opt[data-ref="place:3"]').click();
    await expect(sheet).toHaveCount(0);
    await dlg.locator('.btn-pri').click();
    await expect.poll(() => ms.log.sent.at(-1).event.title).toBe('Elternabend');
    expect(ms.log.sent.at(-1).event.place).toEqual({ label: 'Grundschule', familiePlaceId: 3, lat: 50.06, lon: 8.61 });

    // an address: „Als Ort speichern?“ — Speichern makes it one of „Meine Orte“
    dlg = await openEvent();
    await dlg.locator('input.inp').first().fill('Material holen');
    await dlg.locator('.mo-pick [data-act="all"]').click();
    await sheet.locator('[data-f="pick-q"]').fill('Kanalweg');
    await expect(sheet.locator('[data-state="local-none"]')).toBeVisible();
    await sheet.locator('[data-act="pick-search"]').click();
    await sheet.locator('[data-hit="Baustoffhandel Nord"]').click();
    const ask = page.locator('.mo-dlg[data-dialog="place-save-q"]');
    await expect(ask).toBeVisible();
    await shot(page, 'orte-event-save-q');
    await ask.locator('[data-act="save-place"]').click();
    await expect(sheet).toHaveCount(0);
    await expect(dlg.locator('.mo-pick .mo-pchip.on')).toHaveText('Baustoffhandel Nord');
    expect(calls(pl, 'POST', /profile\/places$/).pop().body).toEqual({ name: 'Baustoffhandel Nord', lat: 50.12, lon: 8.71, address: 'Kanalweg 3, Musterstadt', radiusM: 150, icon: 'pin', visibility: 'self' });
    await dlg.locator('.btn-pri').click();
    await expect.poll(() => ms.log.sent.at(-1).event.title).toBe('Material holen');
    expect(ms.log.sent.at(-1).event.place).toEqual({ label: 'Baustoffhandel Nord', lat: 50.12, lon: 8.71 });

    // „Mein Profil“ › „Meine Orte“: the page of this app
    await page.locator('#page-chats .cv-me').click();
    await page.locator('#page-chats .cv-menu-item[data-item="places"]').click();
    await expect(page.locator('#page-orte')).toHaveClass(/active/);
  });

  test('Notizen 1.8.0: the places of „Meine Orte“ — symbol, who sees it, in use, not moved, a task\'s place by its reference', async ({ launchApp, mock }) => {
    const coreDir = path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [path.join(__dirname, '..', '..')] }));
    const { FEATURES, STAGE1, STAGE2, STAGE3, STAGE4, STAGE5, STAGE6 } = require(path.join(coreDir, 'test', 'fixtures', 'notes-server.js'));
    await mock.setPlaces();
    const n = await mock.setNotes({ features: [...FEATURES, ...STAGE1, ...STAGE2, ...STAGE3, ...STAGE4, ...STAGE5, ...STAGE6] });
    const lager = n.srv.addPlace({ name: 'Baumarkt Nord', address: 'Industriestraße 4, Musterstadt', lat: 50.091, lon: 8.701, named: true });
    const lager2 = n.srv.state.places.get(lager.id);
    Object.assign(lager2, { icon: 'shop', visibility: 'all' });
    n.srv.state.placeUses.set(lager.id, [{ plugin: 'gatecontrol-messenger', pluginName: 'Messenger', kind: 'location_message', count: 1 }]);
    n.srv.state.notMoved.push({ name: 'Altes Lager', reason: 'invalid', field: 'lat' });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-notizen').click();
    const root = page.locator('#page-notizen');

    // a task's place of „Meine Orte“ goes by its reference
    await root.locator('.nz-row[data-uid="t:12"]').click();
    await root.locator('.nz-detail [data-act="place"]').click();
    const dlg = page.locator('.nz-dlg[data-dialog="place"]');
    await dlg.locator(`[data-list="mine"] [data-ref="p:${lager.id}"]`).click();
    await dlg.locator('[data-act="place-save"]').click();
    await expect.poll(() => mock.requests.filter((r) => /\/api\/tasks\/12$/.test(r.path) && r.method !== 'GET').length).toBeGreaterThan(0);
    const sent = JSON.parse(mock.requests.filter((r) => /\/api\/tasks\/12$/.test(r.path) && r.method !== 'GET').pop().raw.toString('utf8'));
    expect(sent.place).toEqual({ trigger: 'enter', key: null, ref: `profile:${lager.id}` });
    await expect.poll(() => (n.srv.state.taskPlace.get(12) || {}).placeId).toBe(lager.id);

    // „Quellen“ › „Meine Orte“: symbol and who sees it, the hint and the page of this app, what did not move
    await root.locator('.nz-it[data-view="sources"]').click();
    const mine = root.locator('[data-card="places"]');
    await expect(mine.locator('[data-box="profile"]')).toBeVisible();
    await expect(mine.locator('[data-box="not-moved"]')).toHaveText(/Altes Lager/);
    const row = mine.locator(`[data-place="p:${lager.id}"]`);
    await expect(row).toHaveAttribute('data-icon', 'shop');
    await expect(row.locator('.hint')).toHaveText(/Industriestraße 4, Musterstadt · (alle|everyone)/);
    await shot(page, 'orte-notizen');
    // deleting it: who uses it, then „Trotzdem löschen“
    await row.locator('[data-act="place-delete"]').click();
    await page.locator('.mo-dlg[data-dialog="place-delete"] [data-act="delete-yes"]').click();
    const inUse = page.locator('.mo-dlg[data-dialog="place-in-use"]');
    await expect(inUse.locator('[data-list="used-by"] li')).toHaveText([/^Messenger · 1 (Ortsnachricht|place message)$/]);
    await inUse.locator('[data-act="delete-force"]').click();
    await expect(row).toHaveCount(0);
    const dels = n.srv.state.requests.filter((r) => r.method === 'DELETE' && new RegExp(`/api/places/${lager.id}$`).test(r.path));
    expect(dels.length).toBe(2);
    // the page of this app
    await mine.locator('[data-act="open-places"]').click();
    await expect(page.locator('#page-orte')).toHaveClass(/active/);
  });
});
