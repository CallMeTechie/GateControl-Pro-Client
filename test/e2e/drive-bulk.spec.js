'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drive 1.12 on the page "Drive" (the plugin is the core's fake Drive server with 'bulk' / 'zip' / 'multiLink',
// support/drive-mock.js): the selection like in the Explorer (a click on a row, Strg / Umschalt, the check boxes and the
// head's tri-state, Strg+A, Esc), the green bar, "Ziel wählen" with the question for a name there already, the note
// "… verschoben · Rückgängig", the menu of a selection (right click), Strg+X / Strg+V, dragging onto a folder in the menu
// (Strg: copy), files from the Explorer still taken as an upload, a job running on the server in the transfer list with
// "Abbrechen", the ZIP ("Speichern unter …"), one link for several files, an older Drive (no copy, delete asks first, no
// "Rückgängig") and "Fotos" with "Alle / Keine" per month. Selectors by id/class, texts in both languages.

const BULK = ['bulk', 'zip', 'multiLink', 'copyServer', 'links'];
const row = (root, id) => root.locator(`.dv-row[data-id="${id}"]`);
const treeRow = (root, id) => root.locator(`.dv-tree-row[data-node="${id}"]`);
const names = (root) => root.locator('.dv-row[data-id] .dv-name');

/**
 * Drags the row `from` onto `to` with the page's own drag events (Playwright's native drag does not reach Electron's
 * renderer here) → the hint shown while over the target ("1 Element hierher verschieben").
 */
function dragOnto(page, from, to, { ctrl = false } = {}) {
  return page.evaluate(({ from, to, ctrl }) => {
    const a = document.querySelector(from);
    const b = document.querySelector(to);
    const dt = new DataTransfer();
    const ev = (type, o = {}) => new DragEvent(type, { bubbles: true, cancelable: true, dataTransfer: dt, ctrlKey: ctrl, clientX: 10, clientY: 10, ...o });
    a.dispatchEvent(ev('dragstart'));
    b.dispatchEvent(ev('dragenter'));
    b.dispatchEvent(ev('dragover'));
    const hint = document.querySelector('#page-drive .dv-drop-hint');
    const text = hint && !hint.hidden ? hint.textContent : null;
    b.dispatchEvent(ev('drop'));
    a.dispatchEvent(ev('dragend'));
    return text;
  }, { from, to, ctrl });
}

async function openDrive(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  return page.locator('#page-drive');
}

test.describe('drive 1.12: several files and folders at once', () => {
  test('select like in the Explorer; move with the question for a name there already; the note with "Rückgängig"', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: BULK });
    const ziel = d.srv.mutate.dir(1, 'Ziel');
    d.srv.mutate.file(ziel.id, 'Foto.jpg', 'andere bytes');
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(names(root)).toHaveText(['Dokumente', 'Ziel', 'Foto.jpg', 'setup.exe']);
    const bar = root.locator('.dv-selbar');
    await expect(bar).toBeHidden();
    await expect(root.locator('.dv-keys')).toBeVisible();
    await expect(root.locator('.dv-keys')).toContainText(/Esc/);

    // a click on the row selects; Strg+click one more; Umschalt+click a range
    await row(root, 11).locator('.dv-c-date').click();
    await expect(bar).toBeVisible();
    await expect(bar.locator('.dv-sel-n')).toHaveText(/1 ausgewählt · 1 Datei|1 selected · 1 file/);
    await expect(row(root, 11)).toHaveClass(/is-sel/);
    await row(root, 13).locator('.dv-c-size').click({ modifiers: ['Control'] });
    await expect(bar.locator('.dv-sel-n')).toHaveText(/2 ausgewählt · 2 Dateien|2 selected · 2 files/);
    const head = root.locator('.dv-cb-all');
    expect(await head.evaluate((x) => x.indeterminate)).toBe(true);
    await row(root, 10).locator('.dv-c-date').click({ modifiers: ['Shift'] });
    await expect(bar.locator('.dv-sel-n')).toHaveText(/4 ausgewählt · 2 Dateien, 2 Ordner|4 selected · 2 files, 2 folders/);
    await expect(head).toBeChecked();
    await page.keyboard.press('Escape');
    await expect(bar).toBeHidden();
    await page.keyboard.press('Control+a');
    await expect(root.locator('.dv-row.is-sel')).toHaveCount(4);
    await head.click();
    await expect(root.locator('.dv-row.is-sel')).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath('drive-bulk-list.png') });

    // the name still opens (as before)
    await row(root, 10).locator('.dv-open').click();
    await expect(root.locator('.dv-crumb.is-current')).toHaveText('Dokumente');
    await root.locator('.dv-crumb').first().click();
    await expect(names(root)).toHaveText(['Dokumente', 'Ziel', 'Foto.jpg', 'setup.exe']);

    // "Verschieben nach …": "Ziel wählen" → the question → the job
    await row(root, 11).locator('.dv-cb').check();
    await row(root, 13).locator('.dv-cb').check();
    await bar.locator('[data-act="move"]').click();
    const dlg = page.locator('.dv-dlg.dv-target');
    await expect(dlg.locator('.dv-target-sub')).toHaveText(/2 Elemente aus „Meine Dateien“|2 items from “My files”/);
    await expect(dlg.locator('.dv-target-mode [data-mode="move"]')).toHaveAttribute('aria-checked', 'true');
    await expect(dlg.locator('.dv-target-ok')).toBeDisabled();
    await expect(dlg.locator('.dv-target-to')).toContainText(/Liegt schon hier|Already here/);
    await dlg.locator(`.dv-pick-row[data-node="${ziel.id}"]`).click();
    await expect(dlg.locator('.dv-target-ok')).toHaveText(/Hierher verschieben \(2\)|Move here \(2\)/);
    await page.screenshot({ path: test.info().outputPath('drive-bulk-target.png') });
    await dlg.locator('.dv-target-ok').click();
    const cf = page.locator('.dv-dlg.dv-conflict');
    await expect(cf.locator('.dv-dlg-h')).toHaveText(/1 Name gibt es dort schon|1 name already exists there/);
    await expect(cf.locator('.dv-cf-name')).toHaveText(['Foto.jpg']);
    await expect(cf.locator('.dv-dlg-body')).not.toContainText('null');
    await expect(cf.locator('.dv-choice[data-choice="version"] input')).toBeChecked();
    await page.screenshot({ path: test.info().outputPath('drive-bulk-conflict.png') });
    await cf.locator('.dv-choice[data-choice="rename"]').click();
    await cf.locator('.dv-cf-ok').click();
    const snack = root.locator('.dv-snack');
    await expect(snack.locator('.dv-snack-tx')).toHaveText(/2 Elemente nach „Ziel“ verschoben|2 items moved to “Ziel”/);
    expect(d.srv.state.nodes.get(11).parentId).toBe(ziel.id);
    expect(d.srv.state.nodes.get(11).name).toBe('Foto (2).jpg');
    expect(d.srv.state.opCalls[0]).toEqual({ op: 'move', ids: [11, 13], target: ziel.id, onConflict: 'rename' });
    await expect(names(root)).toHaveText(['Dokumente', 'Ziel']);
    await expect(root.locator('.dv-tr.is-op')).toHaveCount(1);
    await expect(root.locator('.dv-tr.is-op .dv-tr-name')).toHaveText(/Verschiebe 2 Elemente nach Ziel|Moving 2 items to Ziel/);
    // "Rückgängig"
    await snack.locator('.dv-snack-act').click();
    await expect.poll(() => d.srv.state.nodes.get(13).parentId).toBe(1);
    await expect(names(root)).toHaveText(['Dokumente', 'Ziel', 'Foto.jpg', 'setup.exe']);

    // moved ones are "neu hier" in the target
    await row(root, 13).locator('.dv-cb').check();
    await bar.locator('[data-act="move"]').click();
    await dlg.locator(`.dv-pick-row[data-node="${ziel.id}"]`).click();
    await dlg.locator('.dv-target-ok').click();
    await expect(names(root)).toHaveText(['Dokumente', 'Ziel', 'Foto.jpg']);
    await treeRow(root, ziel.id).click();
    await expect(row(root, 13).locator('.dv-new')).toHaveText(/neu hier|new here/);
  });

  test('the menu of a selection, Kopieren nach …, Strg+X / Strg+V, dragging onto a folder (Strg: copy)', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: BULK });
    const ziel = d.srv.mutate.dir(1, 'Ziel');
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(names(root)).toHaveText(['Dokumente', 'Ziel', 'Foto.jpg', 'setup.exe']);

    // right click into a selection of two: its menu; "Umbenennen" only for one
    await row(root, 10).locator('.dv-cb').check();
    await row(root, 11).locator('.dv-cb').check();
    await row(root, 11).locator('.dv-c-date').click({ button: 'right' });
    const menu = page.locator('.dv-sel-menu');
    await expect(menu.locator('.dv-menu-h')).toHaveText(/2 Elemente \(Rechtsklick\)|2 items \(right click\)/);
    await expect(menu.locator('[data-item="rename"]')).toHaveAttribute('aria-disabled', 'true');
    await expect(menu.locator('[data-item="cut"] .dv-menu-kbd')).toHaveText(/Strg\+X|Ctrl\+X/);
    await page.screenshot({ path: test.info().outputPath('drive-bulk-menu.png') });
    await menu.locator('[data-item="copyTo"]').click();
    const dlg = page.locator('.dv-dlg.dv-target');
    await expect(dlg.locator('.dv-target-mode [data-mode="copy"]')).toHaveAttribute('aria-checked', 'true');
    // a selected folder is no target
    await expect(dlg.locator('.dv-pick-row[data-node="10"]')).toBeDisabled();
    await expect(dlg.locator('.dv-pick-row[data-node="10"] .dv-pick-sub')).toHaveText(/Wird kopiert – nicht in sich selbst|Being copied – not into itself/);
    await dlg.locator(`.dv-pick-row[data-node="${ziel.id}"]`).click();
    await expect(dlg.locator('.dv-target-ok')).toHaveText(/Hierher kopieren \(2\)|Copy here \(2\)/);
    await dlg.locator('.dv-target-ok').click();
    await expect(root.locator('.dv-snack .dv-snack-tx')).toHaveText(/2 Elemente nach „Ziel“ kopiert|2 items copied to “Ziel”/);
    const kids = () => [...d.srv.state.nodes.values()].filter((n) => n.parentId === ziel.id && !n.deleted).map((n) => n.name).sort();
    expect(kids()).toEqual(['Dokumente', 'Foto.jpg']);
    expect(d.srv.state.nodes.get(11).parentId).toBe(1);

    // Strg+X here, Strg+V in Ziel
    await page.keyboard.press('Escape');
    await row(root, 13).locator('.dv-c-date').click();
    await page.keyboard.press('Control+x');
    await expect(row(root, 13)).toHaveClass(/is-cut/);
    await row(root, ziel.id).locator('.dv-open').click();
    await expect(root.locator('.dv-crumb.is-current')).toHaveText('Ziel');
    await page.keyboard.press('Control+v');
    await expect.poll(() => d.srv.state.nodes.get(13).parentId).toBe(ziel.id);
    await expect(names(root)).toHaveText(['Dokumente', 'Foto.jpg', 'setup.exe']);

    // dragging a row onto a folder of the menu moves it; with Strg it copies
    await root.locator('.dv-crumb').first().click();
    await expect(names(root)).toHaveText(['Dokumente', 'Ziel', 'Foto.jpg']);
    expect(await dragOnto(page, '#page-drive .dv-row[data-id="11"]', '#page-drive .dv-tree-row[data-node="10"]')).toMatch(/1 Element hierher verschieben|Move 1 item here/);
    await expect.poll(() => d.srv.state.nodes.get(11).parentId).toBe(10);
    await expect(names(root)).toHaveText(['Dokumente', 'Ziel']);
    expect(await dragOnto(page, `#page-drive .dv-row[data-id="${ziel.id}"]`, '#page-drive .dv-tree-row[data-node="10"]', { ctrl: true })).toMatch(/1 Element hierher kopieren|Copy 1 item here/);
    // not into itself
    expect(await dragOnto(page, '#page-drive .dv-row[data-id="10"]', '#page-drive .dv-tree-row[data-node="10"]')).toBe(null);
    await expect.poll(() => [...d.srv.state.nodes.values()].filter((n) => n.parentId === 10 && n.name === 'Ziel' && !n.deleted).length).toBe(1);
    expect(d.srv.state.nodes.get(ziel.id).parentId).toBe(1);
    expect(d.srv.state.opCalls.map((c) => c.op)).toEqual(['copy', 'move', 'move', 'copy']);
  });

  test('files dragged in from the Explorer still mark the list for an upload; a dragged row never does', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: BULK });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(names(root)).toHaveText(['Dokumente', 'Foto.jpg', 'setup.exe']);
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gc-e2e-drop-')), 'Vom Explorer.txt');
    fs.writeFileSync(file, 'hallo');
    await page.evaluate(() => { const i = document.createElement('input'); i.type = 'file'; i.id = 'e2e-drop-file'; i.style.display = 'none'; document.body.appendChild(i); });
    await page.locator('#e2e-drop-file').setInputFiles(file);
    // files over the list: the page takes them (the upload of the folder shown, as before)
    const accepted = await page.evaluate(() => {
      const list = document.querySelector('#page-drive .dv-list');
      const dt = new DataTransfer();
      dt.items.add(document.getElementById('e2e-drop-file').files[0]);
      list.dispatchEvent(new DragEvent('dragenter', { bubbles: true, cancelable: true, dataTransfer: dt }));
      const over = new DragEvent('dragover', { bubbles: true, cancelable: true, dataTransfer: dt });
      list.dispatchEvent(over);
      return { prevented: over.defaultPrevented, marked: document.querySelector('#page-drive .dv').classList.contains('is-drop') };
    });
    expect(accepted).toEqual({ prevented: true, marked: true });
    await page.evaluate(() => document.querySelector('#page-drive .dv-list').dispatchEvent(new DragEvent('dragleave', { bubbles: true })));
    // a row dragged onto a file (no folder): nothing happens, no upload mark
    expect(await dragOnto(page, '#page-drive .dv-row[data-id="11"]', '#page-drive .dv-row[data-id="13"]')).toBe(null);
    await expect(root.locator('.dv')).not.toHaveClass(/is-drop/);
    await expect(names(root)).toHaveText(['Dokumente', 'Foto.jpg', 'setup.exe']);
    expect(d.srv.state.opCalls).toEqual([]);
    expect(d.srv.state.requests.some((r) => r.path.endsWith('/uploads/commit'))).toBe(false);
  });

  test('a job running on the server: progress in the transfer list, "Abbrechen"', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: BULK });
    d.srv.opAsync = true;
    const ziel = d.srv.mutate.dir(1, 'Ziel');
    d.srv.mutate.file(10, 'Zweit.txt', 'abcdefghijklmn');
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await row(root, 10).locator('.dv-cb').check();
    await root.locator('.dv-selbar [data-act="copy"]').click();
    const dlg = page.locator('.dv-dlg.dv-target');
    await dlg.locator(`.dv-pick-row[data-node="${ziel.id}"]`).click();
    await dlg.locator('.dv-target-ok').click();
    const op = root.locator('.dv-tr.is-op');
    await expect(op.locator('.dv-tr-name')).toHaveText(/Kopiere „Dokumente“ nach Ziel|Copying “Dokumente” to Ziel/);
    await expect(op.locator('.dv-tr-note')).toHaveText(/Läuft auf dem Server weiter|Keeps running on the server/);
    const opId = [...d.srv.state.ops.keys()][0];
    d.srv.progressOp(opId, 1, 14);
    await expect(op.locator('.dv-tr-state')).toHaveText(/1 von 2 Dateien · 14 B von 28 B|1 of 2 files · 14 B of 28 B/);
    await expect(op.locator('[role="progressbar"]')).toHaveAttribute('aria-valuenow', '50');
    await page.screenshot({ path: test.info().outputPath('drive-bulk-progress.png') });
    await op.locator('.dv-op-cancel').click();
    await expect(op.locator('.dv-tr-state')).toHaveText(/Abgebrochen|Cancelled/);
    expect(d.srv.state.ops.get(opId).state).toBe('cancelled');
  });

  test('ZIP into a path picked, one link for several files (not with a folder)', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: BULK });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    const dest = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gc-e2e-zip-')), 'Auswahl.zip');
    await app.evaluate((_e, p) => { globalThis.__gcE2E.saveDialogPaths.push(p); }, dest);
    await row(root, 10).locator('.dv-cb').check();
    await row(root, 11).locator('.dv-cb').check();
    const bar = root.locator('.dv-selbar');
    // a folder with files: no ZIP, no link for several (without 'zipMixed'), greyed with the reason
    await expect(bar.locator('[data-act="link"]')).toHaveAttribute('aria-disabled', 'true');
    await expect(bar.locator('[data-act="link"]')).toHaveAttribute('title', /nur mit Dateien|files only/);
    await expect(bar.locator('[data-act="zip"]')).toHaveAttribute('title', /einen Ordner oder bis zu 20 Dateien|one folder or up to 20 files/);
    await row(root, 10).locator('.dv-cb').uncheck();
    await row(root, 13).locator('.dv-cb').check();
    await bar.locator('[data-act="zip"]').click();
    await expect.poll(() => fs.existsSync(dest)).toBe(true);
    expect(fs.readFileSync(dest, 'utf8')).toContain('setup.exe');
    const asked = await app.evaluate(() => globalThis.__gcE2E.saveDialogs[0]);
    expect(asked.defaultPath).toMatch(/\.zip$/);
    await expect(root.locator('.dv-tr', { hasText: 'Auswahl.zip' })).toBeVisible();

    await bar.locator('[data-act="link"]').click();
    const ld = page.locator('.dv-dlg');
    await expect(ld.locator('.dv-dlg-h')).toHaveText(/Ein Link für 2 Dateien|One link for 2 files/);
    await ld.locator('.dv-pin').fill('2468');
    await ld.locator('.dv-dlg-foot .btn-pri').click();
    await expect(ld.locator('.dv-url')).toHaveValue(/^https:\/\/gc\.example\.com\/s\//);
    expect(d.srv.state.links[0].nodeIds).toEqual([11, 13]);
    expect(d.srv.state.links[0].pin).toBe(true);
  });

  test('an older Drive: move and delete one by one (delete asks first), no copy / ZIP / Rückgängig', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['links'] });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await row(root, 11).locator('.dv-cb').check();
    await row(root, 13).locator('.dv-cb').check();
    const bar = root.locator('.dv-selbar');
    for (const k of ['copy', 'zip', 'link']) {
      await expect(bar.locator(`[data-act="${k}"]`)).toHaveAttribute('aria-disabled', 'true');
      await expect(bar.locator(`[data-act="${k}"]`)).toHaveAttribute('title', /Braucht Drive 1\.12|Needs Drive 1\.12/);
    }
    await bar.locator('[data-act="copy"]').click({ force: true });
    await expect(page.locator('.dv-dlg')).toHaveCount(0);
    await page.keyboard.press('Delete');
    const ask = page.locator('.dv-dlg');
    await expect(ask.locator('.dv-dlg-h')).toHaveText(/2 Elemente in den Papierkorb\?|Move 2 items to the trash\?/);
    await ask.locator('.btn-danger').click();
    await expect(names(root)).toHaveText(['Dokumente']);
    await expect(root.locator('.dv-snack .dv-snack-tx')).toHaveText(/2 Elemente in den Papierkorb|2 items moved to the trash/);
    await expect(root.locator('.dv-snack .dv-snack-act')).toBeHidden();
    expect(d.srv.state.nodes.get(11).deleted).toBe(true);
    expect(d.srv.state.requests.some((r) => r.path.includes('/ops'))).toBe(false);
  });

  test('Fotos: Alle / Keine per month, the selection into a folder', async ({ launchApp, mock }) => {
    const d = await mock.setDrive({ features: ['photos', 'albums', ...BULK] });
    const bilder = d.srv.mutate.dir(1, 'Bilder');
    for (let i = 0; i < 3; i++) d.srv.mutate.photo(bilder.id, `IMG_${i}.jpg`, { takenAt: Date.now() - i * 3600000 });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await root.locator('.dv-tool[data-view="photos"]').click();
    const pv = root.locator('.dpv');
    await pv.locator('.dpv-head .btn', { hasText: /Auswählen|Select/ }).click();
    const month = pv.locator('.dpv-month').first();
    await month.locator('.dpv-month-sel').click();
    await expect(month.locator('.dpv-tile.is-sel')).toHaveCount(await month.locator('.dpv-tile').count());
    await expect(month.locator('.dpv-month-sel')).toHaveText(/Keine|None/);
    await month.locator('.dpv-month-sel').click();
    await expect(pv.locator('.dpv-tile.is-sel')).toHaveCount(0);
    await month.locator('.dpv-tile').nth(0).click();
    await month.locator('.dpv-tile').nth(1).click();
    await expect(pv.locator('.dpv-sel-n')).toHaveText(/2/);
    await expect(pv.locator('.dpv-selbar')).not.toContainText('null');
    await pv.locator('.dpv-selbar [data-act="move"]').click();
    const dlg = page.locator('.dv-dlg.dv-target');
    await dlg.locator('.dv-pick-row[data-node="10"]').click();
    await dlg.locator('.dv-target-ok').click();
    await expect.poll(() => [...d.srv.state.nodes.values()].filter((n) => n.parentId === 10 && /^IMG_/.test(n.name)).length).toBe(2);
    await expect(root.locator('.dv-snack .dv-snack-tx')).toHaveText(/2 Elemente nach „Dokumente“ verschoben|2 items moved to “Dokumente”/);
  });
});
