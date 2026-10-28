'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive 1.11 on the page "Drive" (the plugin is the core's fake Drive server with 'vaultsApart', support/drive-mock.js):
// the menu on the left (name and seat, "Persönlich" / "Gemeinsam" as a folder tree loaded when unfolded, kept on this
// PC, worked with the keyboard; "Tresore"; the icons with their tooltips), a new vault only from "Neu" with "Wer darf ihn
// öffnen?" (always in the top folder of that area, never among the files or in a folder picker), the vault lock with
// Windows Hello (a fake confirmation, support/hello-fake.js: unlock, cancelled, not set up with the way to Windows'
// settings, locked again by hand and when the window is minimized) and the Drive settings (Sicherung with the settings
// of "Ordner sichern", Tresore, KI per area, Ansicht, Zwischenspeicher, Benachrichtigungen). Selectors by id/class,
// texts in both languages.

const tool = (root, view) => root.locator(`.dv-tool[data-view="${view}"]`);
const treeRow = (root, id) => root.locator(`.dv-tree-row[data-node="${id}"]`);

async function openDrive(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  return page.locator('#page-drive');
}

const useFakeConsent = (app) => app.evaluate(() => globalThis.__gcE2E.useFakeConsent());
const consent = (app) => app.evaluate(() => { const f = globalThis.__gcE2E.consent.fake; return { prompts: f.prompts.length, last: f.prompts[f.prompts.length - 1] || null }; });

test.describe('drive 1.11: menu, vaults, lock, settings', () => {
  test('the menu: who, groups, the folder tree with the keyboard, kept on this PC; the icons with tooltips', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['vault', 'vaultsApart', 'docAi', 'cloudImport'] });
    const steuern = d.srv.mutate.dir(10, 'Steuern');
    d.srv.mutate.dir(steuern.id, '2025');
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    const side = root.locator('.dv-side');
    await expect(side.locator('.dv-me-name')).toHaveText('Marc');
    await expect(side.locator('.dv-me-seat')).toHaveText(/Familien-Platz|Family seat/);
    await expect(side.locator('.dv-side-lbl')).toHaveText([/Persönlich|Personal/, /Gemeinsam|Shared/]);
    // Meine Dateien unfolded the first time, its folder Dokumente has subfolders (hasDirs)
    const mine = treeRow(root, 1);
    await expect(mine).toHaveAttribute('aria-expanded', 'true');
    await expect(mine).toHaveAttribute('aria-selected', 'true');
    const doks = treeRow(root, 10);
    await expect(doks).toHaveAttribute('aria-level', '2');
    await expect(doks).toHaveAttribute('aria-expanded', 'false');
    await expect(root.locator('.dv-tree-row.is-area')).toHaveCount(4);
    // the keyboard: down to Dokumente, right unfolds (loaded only now), down into it, Enter opens it
    await mine.focus();
    await page.keyboard.press('ArrowDown');
    await expect(doks).toBeFocused();
    const dirCalls = await d.srv.state.dirCalls;
    await page.keyboard.press('ArrowRight');
    await expect(doks).toHaveAttribute('aria-expanded', 'true');
    const st = treeRow(root, steuern.id);
    await expect(st).toBeVisible();
    expect(d.srv.state.dirCalls).toBeGreaterThan(dirCalls);
    await page.keyboard.press('ArrowRight');
    await expect(st).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(root.locator('.dv-crumb.is-current')).toHaveText('Steuern');
    await expect(st).toHaveAttribute('aria-selected', 'true');
    await expect(st).toHaveAttribute('aria-expanded', 'false');
    // left: to the parent, left again folds it
    await treeRow(root, steuern.id).focus();
    await page.keyboard.press('ArrowLeft');
    await expect(treeRow(root, 10)).toBeFocused();
    await page.keyboard.press('ArrowLeft');
    await expect(treeRow(root, 10)).toHaveAttribute('aria-expanded', 'false');
    await expect(treeRow(root, steuern.id)).toHaveCount(0);
    // the arrow by mouse unfolds the family area; the name opens it
    await treeRow(root, 2).locator('.dv-tw').click();
    // loaded: the family area has no folders (the arrow goes)
    await expect(treeRow(root, 2).locator('.dv-tw')).toHaveClass(/is-leaf/);
    await expect(treeRow(root, 2)).not.toHaveAttribute('aria-expanded', /.*/);
    await treeRow(root, 2).locator('.dv-area-name').click();
    await expect(root.locator('.dv-crumb.is-current')).toHaveText(/Familie/);
    // kept on this PC
    const kept = JSON.parse(await page.evaluate(() => localStorage.getItem('gc.drive.tree.open')));
    expect(kept).toContain(1);
    // the icons: tooltip and name for each
    const tools = root.locator('.dv-tool');
    await expect(tools).toHaveCount(6);
    for (const v of ['links', 'trash', 'sync', 'deadlines', 'import', 'settings']) {
      await expect(tool(root, v)).toHaveAttribute('title', /.+/);
      await expect(tool(root, v)).toHaveAttribute('aria-label', /.+/);
    }
    await page.screenshot({ path: test.info().outputPath('drive-menu.png') });
  });

  test('"Neuer Tresor" from "Neu": the area picked, its top folder, only in the menu; Windows Hello unlocks; locks', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['vault', 'vaultsApart'] });
    const { app, page, events } = await launchApp();
    await useFakeConsent(app);
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    // in Dokumente: "Neu" › "Neuer Tresor" with its hint
    await root.locator('.dv-row[data-id="10"] .dv-open').click();
    await root.locator('.dv-bar .dv-new').click();
    const item = page.locator('.dv-menu-item[data-item="vault"]');
    await expect(item).toContainText(/Erscheint im Menü|Shows in the menu/);
    await item.click();
    const dlg = page.locator('.dv-dlg.dv-vault-dlg');
    await expect(dlg.locator('input[type="radio"]')).toHaveCount(2);
    await dlg.locator('input[type="radio"][data-area="family:1"]').check();
    await expect(dlg.locator('.dv-note')).toContainText(/Windows Hello/);
    await dlg.locator('input[type="text"]').fill('Familien-Dokumente');
    await page.screenshot({ path: test.info().outputPath('drive-vault-new.png') });
    await dlg.locator('.dv-dlg-foot .btn-pri').click();
    await expect(dlg.locator('.dv-rk code')).toHaveCount(4);
    await dlg.locator('.dv-check input').check();
    await dlg.locator('.dv-dlg-foot .btn-pri').click();
    const [vault] = [...d.srv.state.vaults.values()];
    expect(d.srv.state.nodes.get(vault.nodeId).parentId).toBe(2);
    // only in the menu under "Tresore"
    const vrow = root.locator(`.dv-vault-item[data-vault="${vault.id}"]`);
    await expect(vrow.locator('.dv-area-name')).toHaveText('Familien-Dokumente');
    await expect(vrow.locator('.dv-area-sub')).toHaveText(/Mit Familie geteilt · entsperrt|Shared with the family · unlocked/);
    await treeRow(root, 2).locator('.dv-area-name').click();
    await expect(root.locator('.dv-crumb.is-current')).toHaveText(/Familie/);
    await expect(root.locator(`.dv-row[data-id="${vault.nodeId}"]`)).toHaveCount(0);
    // never in a folder picker ("Verschieben")
    await treeRow(root, 1).locator('.dv-area-name').click();
    await root.locator('.dv-row[data-id="11"] .dv-more-btn').click();
    await page.locator('.dv-menu-item', { hasText: /^(Verschieben|Move)$/ }).click();
    const picker = page.locator('.dv-dlg').last();
    await picker.locator('.dv-pick-row.is-back').click();
    await picker.locator('.dv-pick-row', { hasText: /Familie/ }).click();
    await expect(picker.locator('.dv-pick-note')).toHaveText(/Keine Unterordner|No subfolders/);
    await picker.locator('.dv-dlg-head .dv-ib').click();

    // the vault: open (made here); "Jetzt sperren" → the card; Windows Hello unlocks it
    await vrow.click();
    await expect(root.locator('.dv-note')).toHaveText(/Ende-zu-Ende|end-to-end/);
    await root.locator('.dv-vault-lock').click();
    const card = root.locator('.dv-vgate.is-locked');
    await expect(card).toBeVisible();
    await expect(vrow.locator('.dv-area-name')).toHaveText(/Tresor vom|Vault of/);
    await expect(vrow.locator('.dv-area-sub')).toHaveText(/gesperrt|locked/);
    await page.screenshot({ path: test.info().outputPath('drive-vault-locked.png') });
    // cancelled: stays locked, no prompt result shown as an error
    await app.evaluate(() => { globalThis.__gcE2E.consent.fake.answers.push('cancelled'); });
    await card.locator('.dv-vault-unlock').click();
    await expect.poll(async () => (await consent(app)).prompts).toBe(1);
    await expect(card).toBeVisible();
    await expect(card.locator('.dv-dlg-err')).toHaveCount(0);
    // verified (the dialog owned by the app window)
    await card.locator('.dv-vault-unlock').click();
    await expect(root.locator('.dv-vgate')).toHaveCount(0);
    const c = await consent(app);
    expect(c.prompts).toBe(2);
    expect(c.last.window).toBe(true);
    expect(c.last.message).toMatch(/Tresore entsperren|unlock vaults/);
    await expect(vrow.locator('.dv-area-name')).toHaveText('Familien-Dokumente');

    // the window closed into the tray → locked ("Beim Verlassen sperren")
    await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].hide());
    await expect(root.locator('.dv-vgate.is-locked')).toBeVisible();
    await app.evaluate(({ BrowserWindow }) => { const w = BrowserWindow.getAllWindows()[0]; w.show(); w.focus(); });

    // Windows Hello not set up: the card says so, offers Windows' sign-in options, no dialog
    await app.evaluate(() => { globalThis.__gcE2E.consent.fake.avail = { available: false, reason: 'not_set_up' }; });
    await root.locator('.dv-head .dv-ib').first().click();
    const hint = root.locator('.dv-vgate.is-locked .dv-hello-hint');
    await expect(hint).toContainText(/nicht eingerichtet|not set up/);
    await expect(root.locator('.dv-vgate.is-locked .dv-vault-unlock')).toHaveCount(0);
    await root.locator('.dv-vgate.is-locked .dv-hello-setup').click();
    await expect.poll(() => events().filter((e) => e.type === 'shell.openExternal').map((e) => e.url)).toContain('ms-settings:signinoptions');
    expect((await consent(app)).prompts).toBe(2);
  });

  test('Drive settings: backup (the settings of "Ordner sichern"), vault lock, AI per area, view, cache, notifications', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['vault', 'vaultsApart', 'docAi'] });
    mock.setPush({ topics: [{ id: 'plugin:gatecontrol-drive:deadline', label: 'Drive · Fristen' }, { id: 'plugin:gatecontrol-drive:vault', label: 'Drive · Tresore' }, { id: 'plugin:other:x', label: 'Anderes' }], items: [] });
    const { app, page } = await launchApp();
    await useFakeConsent(app);
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(root.locator('.dv-row[data-id="10"]')).toBeVisible();
    // "Ordner sichern" points to the settings; the gear opens them
    await tool(root, 'sync').click();
    await expect(root.locator('.dsv .dsv-set')).toHaveCount(0);
    await expect(root.locator('.dsv-set-link')).toBeVisible();
    await tool(root, 'settings').click();
    const set = root.locator('.dset');
    await expect(set.locator('.dset-card')).toHaveCount(6);
    await expect(set.locator('[data-section="backup"] .dsv-set select')).toHaveCount(3);
    // Tresore: Windows Hello on, 3 minutes, lock when leaving
    const vaults = set.locator('[data-section="vaults"]');
    await expect(vaults.locator('[data-key="lock-hello"]')).toHaveAttribute('aria-checked', 'true');
    await expect(vaults.locator('[data-key="lock-auto"]')).toHaveValue('3');
    await expect(vaults.locator('[data-key="lock-leave"]')).toHaveAttribute('aria-checked', 'true');
    await vaults.locator('[data-key="lock-auto"]').selectOption('15');
    await expect.poll(() => page.evaluate(() => window.gatecontrol.drive.vault.lockStatus().then((s) => s.settings.autoLockMinutes))).toBe(15);
    await vaults.locator('[data-key="lock-leave"]').click();
    await expect(vaults.locator('[data-key="lock-leave"]')).toHaveAttribute('aria-checked', 'false');
    // switching Windows Hello off asks Windows Hello first, then warns
    await vaults.locator('[data-key="lock-hello"]').click();
    await expect(vaults.locator('[data-key="lock-hello"]')).toHaveAttribute('aria-checked', 'false');
    expect((await consent(app)).last.message).toMatch(/ohne Windows Hello|without Windows Hello/);
    await expect(vaults.locator('.dset-warn')).toBeVisible();
    await vaults.locator('[data-key="lock-hello"]').click();
    await expect(vaults.locator('[data-key="lock-hello"]')).toHaveAttribute('aria-checked', 'true');
    // KI per area (write right): Meine Dateien, Familie
    const ai = set.locator('[data-section="ai"]');
    await expect(ai.locator('.sw')).toHaveCount(2);
    await ai.locator('[data-key="ai-family:1"]').click();
    await expect.poll(() => d.srv.state.docAiOff.has('family:1')).toBe(true);
    // Ansicht: the sorting of the lists
    await set.locator('[data-key="view-sort"]').selectOption('size');
    await expect.poll(() => page.evaluate(() => localStorage.getItem('gc.drive.sort'))).toBe('size');
    await expect(set).toBeVisible();
    // the cache: an opened file, cleared
    await page.evaluate(() => window.gatecontrol.drive.open(12));
    await root.locator('.dv-head .dv-ib').first().click();
    const data = set.locator('[data-section="data"]');
    await expect(data.locator('.set-row-desc').first()).toHaveText(/\d+(,\d+)?\s?(B|KB|kB)/);
    await data.locator('[data-key="cache-clear"]').click();
    await expect(page.locator('.toast-text').last()).toHaveText(/geleert|cleared/i);
    // Benachrichtigungen: Drive's topics only, switched on this PC
    const notify = set.locator('[data-section="notify"]');
    await expect(notify.locator('.sw')).toHaveCount(2);
    await notify.locator('[data-key="notify-plugin:gatecontrol-drive:vault"]').click();
    await expect.poll(() => page.evaluate(() => window.gatecontrol.notify.getPrefs().then((p) => p.mutedTopics))).toContain('plugin:gatecontrol-drive:vault');
    await page.screenshot({ path: test.info().outputPath('drive-settings.png'), fullPage: true });
  });
});
