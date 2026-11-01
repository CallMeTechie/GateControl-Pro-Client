'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive 1.16 "Orte und Personen" on the page "Drive" (only with the features `me` reports; the plugin is the core's
// fake Drive server, support/drive-mock.js): the switch Zeitachse | Karte | Personen, the map with "Orte im Bild" and a
// place by day, the search with suggestions and its marks ("Mama Hamburg"), people with naming and "Ist das auch …?",
// the settings "Orte und Personen" with "Alle Gesichtsdaten löschen" after asking. Selectors by id/class, texts in
// both languages.

const tool = (root, view) => root.locator(`.dv-tool[data-view="${view}"]`);
const PP = ['photos', 'albums', 'takenAt', 'photoPlaces', 'photoPeople', 'photoSearch'];

async function openDrive(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  return page.locator('#page-drive');
}

/** Photos in Hamburg (Altona, St. Pauli), Köln and one without a place; Lea on three, Mama on two, one without a name. */
function world(srv) {
  const day = 86400000;
  const now = Date.now();
  const p = {
    a: srv.addPhoto({ name: 'Altona.jpg', takenAt: now - 2 * day, geo: { lat: 53.5502, lon: 9.9351 } }),
    b: srv.addPhoto({ name: 'Pauli.jpg', takenAt: now - 3 * day, geo: { lat: 53.5561, lon: 9.9641 } }),
    c: srv.addPhoto({ name: 'Dom.jpg', takenAt: now - 40 * day, geo: { lat: 50.9413, lon: 6.9583 } }),
    d: srv.addPhoto({ name: 'Ohne.jpg', takenAt: now - 5 * day }),
  };
  const lea = srv.addPerson({ name: 'Lea', nodes: [p.a.id, p.b.id, p.c.id], uncertain: [p.d.id] });
  const mama = srv.addPerson({ name: 'Mama', nodes: [p.a.id, p.c.id] });
  const unnamed = srv.addPerson({ nodes: [p.b.id, p.d.id] });
  srv.state.labels.set(p.a.id, ['hafen']);
  srv.state.peopleProgress = { done: 3, total: 5 };
  srv.state.photoSettings.people = true;
  return { p, lea, mama, unnamed };
}

test.describe('drive 1.16: places and people', () => {
  test('nothing new on a Drive without the features', async ({ launchApp, mock }) => {
    await mock.setDrive({ features: ['photos', 'albums', 'photoSearch'] });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await tool(root, 'photos').click();
    const pv = root.locator('.dpv');
    await expect(pv.locator('.dpv-head [role="tab"]')).toHaveCount(2);
    await expect(pv.locator('[data-tab="map"], [data-tab="people"]')).toHaveCount(0);
    await expect(pv.locator('.dpv-q')).toHaveAttribute('placeholder', /Inhalt suchen|by content/);
    await tool(root, 'settings').click();
    await expect(root.locator('.dset-card[data-section="places"]')).toHaveCount(0);
  });

  test('the map with "Orte im Bild", a place by day with its people, the search with suggestions and marks', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: PP });
    world(d.srv);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await tool(root, 'photos').click();
    const pv = root.locator('.dpv');
    await expect(pv.locator('.dpv-head [role="tab"]')).toHaveText([/Zeitachse|Timeline/, /Karte|Map/, /Personen|People/, /Alben|Albums/]);
    await expect(pv.locator('.dpv-q')).toHaveAttribute('placeholder', /Ort, Person oder Inhalt|Place, person or content/);

    // the map: clusters and the list of the places in view; a cluster picks its row
    await pv.locator('[data-tab="map"]').click();
    await expect(pv.locator('.dpp-map')).toBeVisible();
    await expect(pv.locator('.dpp-map-attr')).toHaveText(/OpenStreetMap/);
    await expect(pv.locator('.dpp-aside .dpp-pl')).toHaveCount(2);
    await expect(pv.locator('.dpp-aside .dpp-pl-name')).toHaveText(['Hamburg', /Köln/]);
    const hh = pv.locator('.dpp-cl[data-key="geonames:2911298"]');
    await expect(hh).toHaveText('2');
    await hh.click();
    await expect(pv.locator('.dpp-pl[data-key="geonames:2911298"]')).toHaveAttribute('aria-pressed', 'true');
    await page.screenshot({ path: test.info().outputPath('drive-pp-map.png') });

    // the place: by day with the district, the people on its photos
    await pv.locator('.dpp-pl[data-key="geonames:2911298"]').click();
    await expect(pv.locator('.dpp-title')).toHaveText('Hamburg');
    await expect(pv.locator('.dpp-place-tx .dpp-sub')).toContainText(/2 Fotos · 2 Tage|2 photos · 2 days/);
    await expect(pv.locator('.dpv-month[data-day]')).toHaveCount(2);
    await expect(pv.locator('.dpv-month[data-day] .dpv-month-n').first()).toHaveText(/Altona · 1/);
    await expect(pv.locator('.dpp-pchip')).toHaveCount(2);
    await pv.locator('.dpp-pchip', { hasText: 'Mama' }).click();
    await expect(pv.locator('.dpv-tile')).toHaveCount(1);
    await page.screenshot({ path: test.info().outputPath('drive-pp-place.png') });
    await pv.locator('.dpp-back').click();
    await expect(pv.locator('.dpp-map')).toBeVisible();

    // the search: suggestions while typing; a place opens; "mama hamburg" with its marks
    await pv.locator('.dpv-q').fill('ha');
    await expect(pv.locator('.dpp-sug-row')).toHaveCount(2);
    await expect(pv.locator('.dpp-sug-row[data-kind="place"]')).toContainText('Hamburg');
    await page.screenshot({ path: test.info().outputPath('drive-pp-suggest.png') });
    await pv.locator('.dpv-q').press('ArrowDown');
    await pv.locator('.dpv-q').press('Enter');
    await expect(pv.locator('.dpp-title')).toHaveText('Hamburg');
    await pv.locator('.dpv-q').fill('mama hamburg');
    await pv.locator('.dpv-q').press('Enter');
    await expect(pv.locator('.dpv-tile')).toHaveCount(1);
    await expect(pv.locator('.dpp-marks .dpp-pchip > span:last-child')).toHaveText(['Mama', 'Hamburg']);
    await expect(pv.locator('[data-tab="timeline"]')).toHaveAttribute('aria-selected', 'true');
    // the lightbox names the place
    await pv.locator('.dpv-tile').first().click();
    await expect(page.locator('.dpv-meta')).toContainText('Hamburg · Altona');
  });

  test('people: named, "Wer ist das?" with naming, a person with "Ist das auch …?" and "Zusammen mit"', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: PP });
    const { lea, unnamed } = world(d.srv);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await tool(root, 'photos').click();
    const pv = root.locator('.dpv');
    await pv.locator('[data-tab="people"]').click();
    await expect(pv.locator('.dpp-progress')).toContainText(/3 von 5|3 of 5/);
    await expect(pv.locator('.dpp-pgrid').first().locator('.dpp-p-name')).toHaveText(['Lea', 'Mama']);
    await expect(pv.locator(`.dpp-p[data-person="${unnamed.id}"] .dpp-p-name`)).toHaveText(/Benennen|Name/);
    await expect(pv.locator('.dpp-note').last()).toHaveText(/Gesichter erkennen deine Handys|Your phones recognise/);
    await page.screenshot({ path: test.info().outputPath('drive-pp-people.png') });

    // "Wer ist das?": a name, then the confirmation with "Rückgängig"
    await pv.locator(`.dpp-p[data-person="${unnamed.id}"]`).click();
    const dlg = page.locator('.dpp-name-dlg');
    await expect(dlg).toBeVisible();
    await expect(dlg.locator('.dpp-alike')).toHaveCount(1);
    await dlg.locator('.dpp-name-in').fill('Oma Gerda');
    await page.screenshot({ path: test.info().outputPath('drive-pp-name.png') });
    await dlg.getByRole('button', { name: /^Speichern$|^Save$/ }).click();
    await expect(dlg.locator('.dpp-done')).toContainText(/„Oma Gerda“ gespeichert|“Oma Gerda” saved/);
    await expect.poll(() => d.srv.state.people.get(unnamed.id).name).toBe('Oma Gerda');
    await dlg.getByRole('button', { name: /Rückgängig|Undo/ }).click();
    await expect.poll(() => d.srv.state.people.get(unnamed.id).name).toBe(null);

    // a person: "Ist das auch Lea?" → "Ja, alle"; "Zusammen mit" Mama
    await pv.locator(`.dpp-p[data-person="${lea.id}"]`).click();
    await expect(pv.locator('.dpp-title')).toHaveText('Lea');
    await expect(pv.locator('.dpp-person-tx .dpp-sub').first()).toContainText(/3 Fotos|3 photos/);
    await expect(pv.locator('.dpp-ask')).toContainText(/Ist das auch Lea\?|Is this Lea too\?/);
    await page.screenshot({ path: test.info().outputPath('drive-pp-person.png') });
    await pv.locator('.dpp-ask .btn-pri').click();
    await expect(pv.locator('.dpp-ask')).toHaveCount(0);
    await expect(pv.locator('.dpp-person-tx .dpp-sub').first()).toContainText(/4 Fotos|4 photos/);
    await pv.locator('.dpp-pchip', { hasText: 'Mama' }).click();
    await expect(pv.locator('.dpv-tile')).toHaveCount(2);
  });

  test('settings "Orte und Personen": the place switches, "Alle Gesichtsdaten löschen" only after asking', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: PP });
    world(d.srv);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await tool(root, 'photos').click();
    const pv = root.locator('.dpv');
    await pv.locator('[data-tab="people"]').click();
    await pv.locator('.dpp-gear').click();
    const card = root.locator('.dset-card[data-section="places"]');
    await expect(card).toBeVisible();
    await expect(card.locator('[data-key="pp-keepGeo"]')).toHaveAttribute('aria-checked', 'true');
    await card.locator('[data-key="pp-keepGeo"]').click();
    await expect.poll(() => d.srv.state.photoSettings.keepGeo).toBe(false);
    // Drive 1.16.0 does not report stripGeoOnShare: no switch
    await expect(card.locator('[data-key="pp-stripGeoOnShare"]')).toHaveCount(0);
    await expect(card.locator('[data-key="pp-peopleKids"]')).toHaveCount(1);
    await page.screenshot({ path: test.info().outputPath('drive-pp-settings.png'), fullPage: true });
    await card.locator('[data-key="pp-delete-faces"]').click();
    const confirm = page.locator('[data-key="pp-confirm"]');
    await expect(confirm).toBeVisible();
    await page.keyboard.press('Escape');
    expect(d.srv.state.photoSettings.people).toBe(true);
    await card.locator('[data-key="pp-delete-faces"]').click();
    await confirm.click();
    await expect.poll(() => d.srv.state.photoSettings.people).toBe(false);
    expect(d.srv.state.people.size).toBe(0);
    await expect(card.locator('[data-key="pp-people"]')).toHaveAttribute('aria-checked', 'false');
    await expect(card.locator('.dset-how')).toBeVisible();
  });
});
