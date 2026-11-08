'use strict';

const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Notizen & Aufgaben (plugin gatecontrol-notizen 1.0.0): shown only when the server lists the plugin (with its
// licence) and lets the person in; the PC layout of the mockup "Windows" — the menu, Mein Tag with the items of the
// other plugins, the details; ticking off (a task, an item of another plugin), the quick entry with Strg+N from any
// page (the chips read on this PC with the plugin's own parser, created by the server with the same one), a note
// edited with the toolbar and shown as text (raw HTML stays text), a Tresor notebook (recovery key once, encrypted in
// the app, locked and unlocked with Windows Hello) and the moves from DS Note (.nsx read on this PC, a password for the
// protected notes) and Microsoft To Do (device code). The plugin is the core's fake server (support/notes-mock.js).

function coreDir() {
  const root = path.join(__dirname, '..', '..');
  try {
    return path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [root] }));
  } catch {
    return path.join(root, '..', 'gatecontrol-client-core');
  }
}

async function openNotes(page) {
  await expect(page.locator('#nav-notizen')).toBeVisible();
  await page.locator('#nav-notizen').click();
  await expect(page.locator('#page-notizen')).toHaveClass(/active/);
  const root = page.locator('#page-notizen');
  await expect(root.locator('.nz-sec').first()).toBeVisible();
  return root;
}

const row = (root, uid) => root.locator(`.nz-row[data-uid="${uid}"]`);
const useFakeConsent = (app) => app.evaluate(() => globalThis.__gcE2E.useFakeConsent());
const consentPrompts = (app) => app.evaluate(() => globalThis.__gcE2E.consent.fake.prompts.length);

test.describe('notizen', () => {
  test('no plugin, no licence or not let in: no "Notizen & Aufgaben" entry', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ plugin: false });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.count('/api/v1/client/plugins')).toBeGreaterThan(0);
    await expect(page.locator('#nav-notizen')).toBeHidden();
    // let in no more: GET me answers 403
    n.srv.state.plugin = true;
    n.srv.state.allowed = false;
    await page.evaluate(() => window.gatecontrol.notes.check());
    await expect.poll(() => n.srv.state.requests.filter((r) => r.path.endsWith('/api/me')).length).toBeGreaterThan(0);
    await expect(page.locator('#nav-notizen')).toBeHidden();
    // let in: the entry shows
    n.srv.state.allowed = true;
    await page.evaluate(() => window.gatecontrol.notes.check());
    await expect(page.locator('#nav-notizen')).toBeVisible();
  });

  test('Mein Tag: the sections, the other plugins, details, ticking off; the quick entry with Strg+N', async ({ launchApp, mock }) => {
    const n = await mock.setNotes();
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    // the menu (mockup "Windows"): Privat | Arbeit, the smart lists, the other plugins, my lists, notes
    await expect(root.locator('.nz-area button.on')).toHaveAttribute('data-area', 'private');
    await expect(root.locator('.nz-it[data-view="myday"]')).toHaveClass(/on/);
    await expect(root.locator('.nz-it[data-view="source:gatecontrol-mail"]')).toBeVisible();
    await expect(root.locator('.nz-it[data-view="list:2"]')).toContainText('Haus & Garten');
    await expect(page.locator('#notes-badge')).not.toBeHidden();
    // Mein Tag: Termine heute (Alltag on the evening before, Schule), Überfällig (Drive's deadline), Heute
    await expect(root.locator('.nz-sec[data-id="events"] .nz-row')).toHaveCount(2);
    await expect(root.locator('.nz-sec[data-id="events"]')).toContainText('Gelbe Tonne rausstellen');
    await expect(root.locator('.nz-sec[data-id="overdue"] .nz-row-title')).toHaveText(['Rechnung Stadtwerke bezahlen']);
    await expect(root.locator('.nz-sec[data-id="overdue"] .nz-src')).toHaveText(/Drive · (Frist|Deadline)/);
    await expect(row(root, 't:11').locator('.nz-when')).toHaveText('9:00');
    await expect(row(root, 's:204').locator('.nz-src')).toHaveText('Mail');
    await page.screenshot({ path: test.info().outputPath('notizen-myday.png') });

    // a task's details: sub tasks, the note
    await row(root, 't:12').click();
    const d = root.locator('.nz-detail');
    await expect(d.locator('.nz-d-title')).toHaveValue('Winterreifen-Termin ausmachen');
    await expect(d.locator('.nz-subt[data-id]')).toHaveCount(3);
    await expect(d.locator('.nz-note-plain')).toHaveValue('Rabatt ab 50 Stück nachfragen');
    // an item of another plugin: "Aus Mail", ticked off there
    await row(root, 's:204').click();
    await expect(d.locator('.nz-from')).toContainText(/Aus Mail|From Mail/);
    await row(root, 's:203').locator('.nz-ck').click();
    await expect.poll(() => n.srv.state.items.get(203).done).toBe(true);
    // tick off a task: done, under "Erledigt heute"
    await row(root, 't:11').locator('.nz-ck').click();
    await expect.poll(() => !!n.srv.state.tasks.get(11).doneAt).toBe(true);
    await expect(root.locator('.nz-sec[data-id="done"]')).toContainText(/\(2\)/);

    // Strg+N from another page: the quick entry, its chips read on this PC with the plugin's parser
    await page.locator('#nav-status').click();
    await expect(page.locator('#page-status')).toHaveClass(/active/);
    await page.keyboard.press('Control+N');
    await expect(page.locator('#page-notizen')).toHaveClass(/active/);
    const quick = root.locator('#nz-quick');
    await expect(quick).toBeFocused();
    await quick.fill('Morgen 9 Uhr Zahnarzt anrufen, wichtig, #gesundheit');
    await expect(root.locator('.nz-qchip[data-kind="date"]')).toHaveText(/(morgen|tomorrow), 09:00/);
    await expect(root.locator('.nz-qchip[data-kind="list"]')).toHaveText(/Gesundheit/);
    await expect(root.locator('.nz-qchip[data-kind="important"]')).toBeVisible();
    await page.screenshot({ path: test.info().outputPath('notizen-quick.png') });
    await quick.press('Enter');
    await expect.poll(() => [...n.srv.state.tasks.values()].find((x) => x.title === 'Zahnarzt anrufen' && x.id > 100) || null).not.toBeNull();
    const made = [...n.srv.state.tasks.values()].find((x) => x.title === 'Zahnarzt anrufen' && x.id > 100);
    expect([made.due, made.important, made.listId, n.srv.state.myDay.has(made.id)]).toEqual([{ date: '2026-11-09', time: '09:00' }, true, 3, true]);
    await expect(quick).toHaveValue('');
    await expect(root.locator(`.nz-row[data-uid="t:${made.id}"]`)).toBeVisible();
    // Arbeit: other lists
    await root.locator('.nz-area button[data-area="work"]').click();
    await expect(root.locator('.nz-it[data-view="list:5"]')).toContainText('Büro');
    await expect.poll(() => n.srv.state.prefs.area).toBe('work');
  });

  test('a note: check boxes, edited with the toolbar, raw HTML stays text', async ({ launchApp, mock }) => {
    const n = await mock.setNotes();
    n.srv.state.notes.get(42).body = 'Zutaten <img src=x onerror="window.gcXss=1"> <script>window.gcXss=2</script> [klick](javascript:alert(1))\n\n| Zutat | Menge |\n| --- | --- |\n| Hack | 500 g |';
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    await root.locator('.nz-it[data-view="notes"]').click();
    await expect(root.locator('.nz-nc')).toHaveCount(2);
    await expect(root.locator('.nz-nc[data-id="41"]')).toContainText('Werkstatt Montag');
    // the note with raw HTML: text only, no element made from it
    await root.locator('.nz-nc[data-id="42"]').click();
    const d = root.locator('.nz-detail');
    await expect(d.locator('.nz-md')).toContainText('<img src=x onerror="window.gcXss=1">');
    await expect(d.locator('.nz-md img, .nz-md script')).toHaveCount(0);
    await expect(d.locator('.nz-md .nm-link')).toHaveCount(0);
    await expect(d.locator('.nz-md table td').first()).toHaveText('Hack');
    expect(await page.evaluate(() => window.gcXss || null)).toBeNull();
    // the checklist note: a box ticks the line on the server
    await root.locator('.nz-nc[data-id="41"]').click();
    await expect(d.locator('.nz-note-h')).toHaveText('Werkstatt Montag');
    await expect(d.locator('.nm-box')).toHaveCount(3);
    await expect(d.locator('.nz-md strong')).toHaveText('Luftdruck 2,5 bar');
    await d.locator('.nm-box[data-line="2"]').check();
    await expect.poll(() => n.srv.state.notes.get(41).body.split('\n')[2]).toBe('- [x] Drehmomentschlüssel');
    // edit: the toolbar writes Markdown, "Fertig" saves (with its rev)
    await d.locator('[data-act="edit"]').click();
    const ta = d.locator('.nz-editor');
    await expect(ta).toBeVisible();
    await ta.press('Control+End');
    await ta.press('Enter');
    await d.locator('.nz-tool[data-tool="check"]').click();
    await ta.pressSequentially('Luftfilter');
    await ta.press('Enter');
    await d.locator('.nz-tool[data-tool="bold"]').click();
    await ta.pressSequentially('Werkstatt anrufen');
    await page.screenshot({ path: test.info().outputPath('notizen-editor.png') });
    await d.locator('[data-act="done"]').click();
    await expect.poll(() => n.srv.state.notes.get(41).body).toMatch(/- \[ \] Luftfilter\n\*\*Werkstatt anrufen\*\*$/);
    await expect(d.locator('.nm-box')).toHaveCount(4);
    await expect(d.locator('.nz-md strong').last()).toHaveText('Werkstatt anrufen');
    // a new note in "Haushalt"
    await root.locator('.nz-it[data-view="notebook:32"]').click();
    await root.locator('#nz-new-note').click();
    await expect(d.locator('.nz-ed-title')).toBeFocused();
    await d.locator('.nz-ed-title').fill('Einkauf');
    await d.locator('.nz-editor').fill('- [ ] Milch\n#einkauf');
    await d.locator('[data-act="done"]').click();
    await expect.poll(() => [...n.srv.state.notes.values()].find((x) => x.title === 'Einkauf') || null).not.toBeNull();
    await expect(root.locator('.nz-it[data-view="tag:einkauf"]')).toBeVisible();
  });

  test('a Tresor notebook: recovery key once, encrypted in the app, locked and unlocked with Windows Hello', async ({ launchApp, mock }) => {
    const n = await mock.setNotes();
    const { app, page } = await launchApp();
    await useFakeConsent(app);
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    await root.locator('.nz-it[data-view="new-notebook"]').click();
    const dlg = page.locator('.nz-dlg');
    await dlg.locator('button[data-kind="vault"]').click();
    await dlg.locator('input.inp').fill('Versicherungen');
    await dlg.locator('.btn-pri').click();
    // the recovery key: shown once, "Fertig" only after "aufbewahrt"
    const rec = page.locator('.nz-dlg:has([data-recovery])');
    await expect(rec.locator('[data-recovery]')).toHaveText(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){13}$/);
    const done = rec.locator('.btn-pri');
    await expect(done).toBeDisabled();
    await rec.locator('#nz-rec-kept').check();
    await done.click();
    await expect(rec).toHaveCount(0);
    const vid = [...n.srv.state.vaults.keys()][0];
    const nbId = n.srv.state.vaults.get(vid).notebookId;
    await expect(root.locator(`.nz-it[data-view="notebook:${nbId}"]`)).toContainText('Versicherungen');
    // a note in it: encrypted here, the server has no title and no text
    await root.locator('#nz-new-note').click();
    const d = root.locator('.nz-detail');
    await d.locator('.nz-ed-title').fill('Kfz-Police');
    await d.locator('.nz-editor').fill('Vertrag **4711**\n- [ ] prüfen');
    await d.locator('[data-act="done"]').click();
    await expect(d.locator('.nz-note-h')).toHaveText('Kfz-Police');
    const stored = () => [...n.srv.state.notes.values()].find((x) => x.notebookId === nbId);
    await expect.poll(() => !!(stored() && stored().titleCipher && stored().cipher && stored().keyVersion === 1)).toBe(true);
    expect(JSON.stringify(stored())).not.toMatch(/Kfz|4711|prüfen/);
    await expect(root.locator('.nz-nc .nz-nc-t')).toHaveText(['Kfz-Police']);
    // lock: no title, no text on the page
    await root.locator('[data-act="vault-lock"]').click();
    await expect(root.locator('.nz-main .nz-locked')).toBeVisible();
    await expect(root.locator(`.nz-it[data-view="notebook:${nbId}"]`)).toContainText(/Tresor \(gesperrt\)|Vault \(locked\)/);
    await expect(page.locator('#page-notizen')).not.toContainText('Kfz-Police');
    await page.screenshot({ path: test.info().outputPath('notizen-locked.png') });
    // unlock with Windows Hello
    const before = await consentPrompts(app);
    await root.locator('.nz-main [data-act="vault-unlock"]').click();
    await expect.poll(() => consentPrompts(app)).toBe(before + 1);
    await expect(root.locator('.nz-nc .nz-nc-t')).toHaveText(['Kfz-Police']);
    await expect(root.locator(`.nz-it[data-view="notebook:${nbId}"]`)).toContainText('Versicherungen');
    await root.locator('.nz-nc').first().click();
    await expect(d.locator('.nz-md strong')).toHaveText('4711');
    // a cancelled Windows Hello keeps it locked
    await root.locator('[data-act="vault-lock"]').click();
    await app.evaluate(() => { globalThis.__gcE2E.consent.fake.answers.push('cancelled'); });
    await root.locator('.nz-main [data-act="vault-unlock"]').click();
    await expect(page.locator('.toast-error')).toContainText(/Windows Hello/);
    await expect(root.locator('.nz-main .nz-locked')).toBeVisible();
  });

  test('moving over: DS Note read on this PC with the password, Microsoft To Do by device code', async ({ launchApp, mock }) => {
    const n = await mock.setNotes();
    n.srv.state.ms.interval = 1;
    const { app, page, answerOpenDialogs } = await launchApp();
    await useFakeConsent(app);
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    await root.locator('.nz-it[data-view="import"]').click();
    // DS Note: the export picked, read here; the protected note into a new Tresor (its key shown)
    await answerOpenDialogs([path.join(coreDir(), 'test', 'fixtures', 'notes', 'sample.nsx')]);
    const ds = root.locator('[data-import="dsnote"]');
    await ds.locator('[data-act="ds-pick"]').click();
    await expect(ds).toContainText('sample.nsx');
    await expect(ds.locator('.nz-stat b')).toHaveText(['2', '4', /\d/]);
    await ds.locator('#nz-ds-password').fill('geheim');
    await ds.locator('[data-act="ds-start"]').click();
    const rec = page.locator('.nz-dlg:has([data-recovery])');
    await expect(rec).toContainText('Rezepte & Dokumente (DS Note)');
    await rec.locator('#nz-rec-kept').check();
    await rec.locator('.btn-pri').click();
    await expect(ds.locator('[data-import-status]')).toContainText(/4 Notizen übernommen|4 notes taken over/);
    expect([...n.srv.state.notes.values()].some((x) => x.title === 'Gartenhaus Maße' && /!\[Bild\]\(att:\d+\)/.test(x.body))).toBe(true);
    const secret = [...n.srv.state.notes.values()].find((x) => x.titleCipher && x.ext === 'dsnote:N4note4');
    expect(secret && !JSON.stringify(secret).includes('4711')).toBe(true);
    // Microsoft To Do: the device code, Microsoft's page, then the preview and the job
    const ms = root.locator('[data-import="mstodo"]');
    await ms.locator('[data-act="consent"]').click();
    const code = page.locator('.nz-dlg [data-code]');
    await expect(code).toHaveText('ABCD-EFGH');
    await expect(ms.locator('.nz-imp-row')).toHaveCount(3, { timeout: 20000 });
    await expect(ms.locator('.nz-stat b').first()).toHaveText('3');
    await ms.locator('[data-act="ms-start"]').click();
    await expect(ms).toContainText(/19 Aufgaben in 2 Listen|19 tasks in 2 lists/, { timeout: 20000 });
    await page.screenshot({ path: test.info().outputPath('notizen-import.png') });
    // "Quellen": Mail switched off for this person → gone from the menu; a Mail account into "Arbeit"
    await root.locator('.nz-it[data-view="sources"]').click();
    const mail = root.locator('.nz-srccard[data-plugin="gatecontrol-mail"]');
    await mail.locator('.nz-set-h .sw').click();
    await expect.poll(() => n.srv.state.prefs.sources['gatecontrol-mail'] && n.srv.state.prefs.sources['gatecontrol-mail'].on).toBe(false);
    await expect(root.locator('.nz-it[data-view="source:gatecontrol-mail"]')).toHaveCount(0);
    await mail.locator('select[aria-label="Firma · M365"]').selectOption('work');
    await expect.poll(() => n.srv.state.prefs.groups['gatecontrol-mail|account:2']).toBe('work');
    await page.screenshot({ path: test.info().outputPath('notizen-sources.png') });
  });
});
