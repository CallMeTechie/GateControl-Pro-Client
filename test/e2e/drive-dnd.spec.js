'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drag & drop from the Explorer on the page "Drive" (the core's fake Drive server, support/drive-mock.js): the zone
// while files are dragged over the list (the folder shown, or the folder row under the pointer), files dropped on a
// folder row land in that folder, several taken names answered at once („Für alle … übernehmen“), "Abbrechen" of an
// upload in the transfer list. The drop uses the page's own drag events with real File objects (an <input type=file>;
// Playwright's native drag does not reach Electron's renderer); the core reads their paths via webUtils.
// Selectors by id/class, texts in both languages.

const names = (root) => root.locator('.dv-row[data-id] .dv-name');
const named = (d, parentId, name) => [...d.srv.state.nodes.values()].find((n) => n.parentId === parentId && n.name === name && !n.deleted);

async function openDrive(page) {
  await expect(page.locator('#nav-drive')).toBeVisible();
  await page.locator('#nav-drive').click();
  await expect(page.locator('#page-drive')).toHaveClass(/active/);
  const root = page.locator('#page-drive');
  const files = root.locator('.dv-pages [data-page="files"]');
  await expect(files.or(root.locator('.dv-gate:visible')).first()).toBeVisible();
  if (await files.isVisible()) await files.click();
  return root;
}

/** Real files for the drop: an <input type=file> holds them (the page's DataTransfer takes them from there). */
async function pickForDrop(page, files) {
  await page.evaluate(() => {
    if (document.getElementById('e2e-drop-files')) return;
    const i = document.createElement('input');
    i.type = 'file';
    i.multiple = true;
    i.id = 'e2e-drop-files';
    i.style.display = 'none';
    document.body.appendChild(i);
  });
  await page.locator('#e2e-drop-files').setInputFiles(files);
}

/** dragenter + dragover on `target` → what the page shows then; `drop`: dropped too. */
function dragFiles(page, target, { drop = false, stay = false } = {}) {
  return page.evaluate(({ target, drop, stay }) => {
    const el = document.querySelector(target);
    const dt = new DataTransfer();
    for (const f of document.getElementById('e2e-drop-files').files) dt.items.add(f);
    const ev = (type) => new DragEvent(type, { bubbles: true, cancelable: true, dataTransfer: dt, clientX: 20, clientY: 20 });
    el.dispatchEvent(ev('dragenter'));
    const over = ev('dragover');
    el.dispatchEvent(over);
    const zone = document.querySelector('#page-drive .dv-drop-zone');
    const seen = {
      prevented: over.defaultPrevented,
      zone: zone && getComputedStyle(zone).display !== 'none' ? zone.textContent : null,
      targets: [...document.querySelectorAll('#page-drive .dv-row.is-drop-target')].map((r) => r.dataset.id),
    };
    if (drop) el.dispatchEvent(ev('drop'));
    else if (!stay) el.dispatchEvent(new DragEvent('dragleave', { bubbles: true }));
    return seen;
  }, { target, drop, stay });
}

function tmpFiles(list) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-e2e-dnd-'));
  return list.map(([name, content]) => { const p = path.join(dir, name); fs.writeFileSync(p, content); return p; });
}

test.describe('drive: drag & drop from the Explorer', () => {
  test('the zone while dragging; files dropped on a folder row go into that folder', async ({ launchApp, mock }) => {
    const d = await mock.setDrive();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(names(root)).toHaveText(['Dokumente', 'Foto.jpg', 'setup.exe']);
    await pickForDrop(page, tmpFiles([['Rechnung.txt', 'r'], ['Vertrag.txt', 'v']]));

    // over an empty part of the list: the folder shown; over a file: still the folder shown
    const list = await dragFiles(page, '#page-drive .dv-list');
    expect(list).toEqual({ prevented: true, zone: expect.stringMatching(/Loslassen zum Hochladen in diesen Ordner|Drop to upload into this folder/), targets: [] });
    const file = await dragFiles(page, '#page-drive .dv-row[data-id="11"] .dv-name');
    expect(file.targets).toEqual([]);
    await expect(root.locator('.dv')).not.toHaveClass(/is-drop/);

    // over the folder "Dokumente": that row is marked, the zone names it
    const over = await dragFiles(page, '#page-drive .dv-row[data-id="10"] .dv-name');
    expect(over).toEqual({ prevented: true, zone: expect.stringMatching(/„Dokumente“|“Dokumente”/), targets: ['10'] });
    await expect(root.locator('.dv-row.is-drop-target')).toHaveCount(0);
    await dragFiles(page, '#page-drive .dv-row[data-id="10"] .dv-name', { stay: true });
    await expect(root.locator('.dv-drop-zone')).toBeVisible();
    await page.screenshot({ path: test.info().outputPath('drive-dnd-zone.png') });
    await page.evaluate(() => document.querySelector('#page-drive .dv-list').dispatchEvent(new DragEvent('dragleave', { bubbles: true })));
    await expect(root.locator('.dv-drop-zone')).toBeHidden();

    // dropped there: both files in Dokumente, nothing in the folder shown
    await dragFiles(page, '#page-drive .dv-row[data-id="10"] .dv-name', { drop: true });
    await expect.poll(() => [named(d, 10, 'Rechnung.txt'), named(d, 10, 'Vertrag.txt')].every(Boolean)).toBe(true);
    expect(named(d, 1, 'Rechnung.txt')).toBeFalsy();
    await expect(root.locator('.dv-tr.is-ok')).toHaveCount(2);
    await expect(root.locator('.dv')).not.toHaveClass(/is-drop/);
    await expect(names(root)).toHaveText(['Dokumente', 'Foto.jpg', 'setup.exe']);
  });

  test('several taken names answered at once; "Abbrechen" of one upload and of all', async ({ launchApp, mock }) => {
    const d = await mock.setDrive();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openDrive(page);
    await expect(names(root)).toHaveText(['Dokumente', 'Foto.jpg', 'setup.exe']);

    // two taken names dropped on the list: one question, „Für alle 2 … übernehmen“ → "Beide behalten" for both
    await pickForDrop(page, tmpFiles([['Foto.jpg', 'anderes Foto'], ['setup.exe', 'MZ anders']]));
    await dragFiles(page, '#page-drive .dv-list', { drop: true });
    const dlg = page.locator('.dv-dlg');
    await expect(dlg.locator('.dv-dlg-h')).toHaveText(/Foto\.jpg|setup\.exe/);
    await expect(dlg.locator('.dv-conflict-all')).toHaveText(/Für alle 2 Namenskonflikte übernehmen|Apply to all 2 name conflicts/);
    await page.screenshot({ path: test.info().outputPath('drive-dnd-conflicts.png') });
    await dlg.locator('.dv-conflict-all input').check();
    await dlg.locator('.dv-dlg-foot .btn-sec').click(); // Beide behalten
    await expect(dlg).toHaveCount(0);
    await expect(root.locator('.dv-tr.is-ok')).toHaveCount(2);
    await expect(names(root)).toHaveCount(5);
    expect(d.srv.state.nodes.get(11).rev).toBe(2);

    // uploads on their way (the fake holds every media upload): "Abbrechen" of the one waiting, then "Alle abbrechen"
    let release;
    d.srv.holdMedia = new Promise((r) => { release = r; });
    await pickForDrop(page, tmpFiles([['Erste.txt', 'eins'], ['Zweite.txt', 'zwei'], ['Dritte.txt', 'drei']]));
    await dragFiles(page, '#page-drive .dv-list', { drop: true });
    const tr = (name) => root.locator('.dv-tr', { has: page.locator('.dv-tr-name', { hasText: name }) });
    await expect(tr('Erste.txt').locator('.dv-tr-state')).toHaveText(/ von | of |läuft|running/);
    await expect(tr('Zweite.txt').locator('.dv-tr-state')).toHaveText(/wartet|queued|waiting/i);
    await tr('Zweite.txt').locator('.dv-tr-cancel').click();
    await expect(tr('Zweite.txt').locator('.dv-tr-state')).toHaveText(/abgebrochen|cancelled/);
    await expect(tr('Zweite.txt').locator('.dv-tr-cancel')).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath('drive-dnd-cancel.png') });
    await root.locator('.dv-tr-cancel-all').click();
    await expect(tr('Erste.txt').locator('.dv-tr-state')).toHaveText(/abgebrochen|cancelled/);
    await expect(tr('Dritte.txt').locator('.dv-tr-state')).toHaveText(/abgebrochen|cancelled/);
    await expect(root.locator('.dv-tr-cancel-all')).toHaveCount(0);
    release();
    d.srv.holdMedia = null;
    expect(['Erste.txt', 'Zweite.txt', 'Dritte.txt'].map((n) => named(d, 1, n)).filter(Boolean)).toEqual([]);
    await expect(names(root)).toHaveCount(5);
  });
});
