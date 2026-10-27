'use strict';

const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive „Dateien bei Bedarf“ (card on top of "Ordner sichern"): switched on and
// off, state, pause, "Im Explorer öffnen", the space on this PC, the question
// after a mass delete, a Windows folder moved into the Drive and put back (only
// after the explicit "yes"), the lock against "Ordner sichern", the Explorer menu
// ("Link teilen …" opens the share dialog of the page) and switching off that
// stops while changes are not uploaded. gc-drive-sync is the fake of
// support/drive-sync-fake.js (a real named pipe in the main process; no sync
// root, no registry, no Known Folder of the runner is touched). Selectors by
// id/class, texts in both languages.

async function openSync(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  const root = page.locator('#page-drive');
  await expect(root).toHaveClass(/active/);
  await root.locator('.dv-area').nth(6).click();
  const card = root.locator('.dod');
  await expect(card).toBeVisible();
  return { root, card };
}

const fake = (app) => app.evaluate(() => {
  const f = globalThis.__gcE2E.driveSyncFake;
  return { received: f.received, known: f.known };
});

test.describe('drive on demand', () => {
  test('on, state, folders into the Drive and back, mass delete, Explorer menu, off', async ({ launchApp, mock }) => {
    await mock.setDrive();
    const { app, page, dir } = await launchApp();
    await setupWithApiKey(page, mock);
    const { root, card } = await openSync(page);

    // off by default: nothing started
    const sw = card.locator('.dsv-card-head .sw');
    await expect(sw).toHaveAttribute('aria-checked', 'false');
    expect((await fake(app)).received).toEqual([]);
    await page.screenshot({ path: test.info().outputPath('ondemand-off.png') });

    // switch on → started over the launcher, token only in configure
    await sw.click();
    await expect(sw).toHaveAttribute('aria-checked', 'true');
    await expect(card.locator('.dsv-pill')).toHaveText(/^(Aktuell|Up to date)$/);
    let f = await fake(app);
    expect(f.received.map((m) => m.cmd).slice(0, 3)).toEqual(['hello', 'configure', 'start']);
    expect(JSON.stringify(f.received)).not.toContain(mock.apiKey || 'never-there');
    await expect(card.locator('.dod-usage-v').first()).toHaveText(/^3[,.]2 GB$/);
    await expect(card.locator('.dod-usage-v').nth(1)).toHaveText('184 GB');

    // pause / resume, open in the Explorer
    await card.locator('[data-key="od-pause"]').click();
    await expect(card.locator('.dsv-pill')).toHaveText(/Pausiert|Paused/);
    await card.locator('[data-key="od-pause"]').click();
    await expect(card.locator('.dsv-pill')).toHaveText(/^(Aktuell|Up to date)$/);
    await card.locator('[data-key="od-open"]').click();
    await expect.poll(() => app.evaluate(() => globalThis.__gcE2E.openedPaths.length)).toBe(1);
    expect(await app.evaluate(() => globalThis.__gcE2E.openedPaths[0])).toMatch(/GateControl Drive$/);

    // Windows folders: five rows; Bilder is backed up by "Ordner sichern" → locked
    const known = root.locator('.dod-known');
    await expect(known.locator('.dod-krow')).toHaveCount(5);
    const pictures = path.join(dir, 'profile', 'Pictures');
    fs.mkdirSync(pictures, { recursive: true });
    const add = await page.evaluate((p) => window.gatecontrol.drive.sync.add({ path: p, mode: 'backup' }), pictures);
    expect(add.ok).toBe(true);
    await expect(known.locator('[data-known="pictures"] .dod-lock')).toBeVisible();
    await expect(known.locator('[data-known="pictures"] .btn')).toBeDisabled();
    // and the main process refuses it too
    const refused = await page.evaluate(() => window.gatecontrol.driveOnDemand.relocate('pictures'));
    expect(refused).toEqual({ ok: false, code: 'w2_active' });

    // move Dokumente into the Drive: only after the explicit "yes"
    await known.locator('[data-known="documents"] .btn').click();
    const dlg = page.locator('.dv-dlg');
    await expect(dlg.locator('[data-key="od-move-go"]')).toBeDisabled();
    await dlg.locator('[data-key="od-move-agree"]').check();
    await page.screenshot({ path: test.info().outputPath('ondemand-move.png') });
    await dlg.locator('[data-key="od-move-go"]').click();
    await expect(known.locator('[data-known="documents"] .dsv-state-tx')).toHaveText(/^(Im Drive|In Drive)$/);
    f = await fake(app);
    const rel = f.received.find((m) => m.cmd === 'relocate');
    expect(rel.folder).toBe('documents');
    expect(rel.name).toMatch(/^(Dokumente|Documents)$/);
    await expect(known.locator('[data-known="documents"] .dsv-path')).toHaveText(/GateControl Drive.(Meine Dateien|My files)?.*(Dokumente|Documents)$/);

    // mass delete in the Explorer → question → "Wiederherstellen"
    await app.evaluate(() => globalThis.__gcE2E.driveSyncFake.massDelete(640));
    const ask = card.locator('.dod-ask');
    await expect(ask).toBeVisible();
    await expect(ask.locator('.dsv-ask-h')).toHaveText(/640/);
    await expect(card.locator('.dsv-pill')).toHaveText(/Antwort|answer/);
    await ask.locator('[data-key="od-ask-restore"]').click();
    await expect(ask).toHaveCount(0);
    expect((await fake(app)).received.find((m) => m.cmd === 'deletes').decision).toBe('restore');

    // Explorer menu "Link teilen …" → the share dialog of the page
    await app.evaluate(() => globalThis.__gcE2E.driveSyncFake.action('share', 11));
    await expect(page.locator('.dv-dlg .dv-share')).toBeVisible();
    await expect(page.locator('.dv-dlg')).toContainText('Foto.jpg');
    await page.locator('.dv-dlg .dv-dlg-head .dv-ib').click();
    await expect(page.locator('.dv-dlg')).toHaveCount(0);
    await root.locator('.dv-area').nth(6).click();

    // switch off while Dokumente lies in the Drive → refused, stays on
    await sw.click();
    await page.locator('.dv-dlg [data-key="od-off-go"]').click();
    await expect(page.locator('.dv-dlg .dod-off-err')).toContainText(/zurücklegen|put back/);
    await page.locator('.dv-dlg .btn-sec', { hasText: /Abbrechen|Cancel/ }).click();
    await expect(sw).toHaveAttribute('aria-checked', 'true');

    // put Dokumente back
    await known.locator('[data-known="documents"] .btn').click();
    await page.locator('.dv-dlg [data-key="od-restore-go"]').click();
    await expect(known.locator('[data-known="documents"] .dsv-state-tx')).toHaveText(/Auf diesem PC|On this PC/);

    // switch off with changes not uploaded → list, then "Trotzdem ausschalten"
    await app.evaluate(() => { globalThis.__gcE2E.driveSyncFake.unsynced = 2; });
    await sw.click();
    const off = page.locator('.dv-dlg');
    await off.locator('[data-key="od-off-go"]').click();
    await expect(off.locator('.dod-paths li')).toHaveText([/Notiz\.txt$/]);
    await page.screenshot({ path: test.info().outputPath('ondemand-unsynced.png') });
    await expect(sw).toHaveAttribute('aria-checked', 'true');
    await off.locator('button', { hasText: /Trotzdem ausschalten|Switch off anyway/ }).click();
    await expect(off).toHaveCount(0);
    await expect(sw).toHaveAttribute('aria-checked', 'false');
    const unreg = (await fake(app)).received.filter((m) => m.cmd === 'unregister');
    expect(unreg.map((m) => m.force)).toEqual([false, false, true]);
    await expect(known).toBeHidden();
  });
});
