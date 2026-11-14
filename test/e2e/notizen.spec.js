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
// Plugin 1.3.0 (the words of me.features): the card "Gestern offen geblieben" above the sections of Mein Tag, a task's
// marks, the calendar chip of the quick entry, and the buttons of the morning hint that open the page.
// Plugin 1.4.0 (shoppingLists, taskList): the shopping lists in the menu, a list ticked off (items added, changed,
// deleted; "Alles abgehakt" with the way back), the list at a task (the mark, the details, the chip of the quick entry)
// and the reminder's button "Liste öffnen" that opens the list in the app. With an older plugin nothing of it shows.

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

// the words of plugin 1.3.0 in me.features (the core fake's default is an older plugin)
function stage1() {
  const { FEATURES, STAGE1 } = require(path.join(coreDir(), 'test', 'fixtures', 'notes-server.js'));
  return [...FEATURES, ...STAGE1];
}
const YESTERDAY = '2026-11-07'; // the fake's today is 2026-11-08, a Sunday

// … and the words of plugin 1.4.0
function stage2() {
  const { STAGE2 } = require(path.join(coreDir(), 'test', 'fixtures', 'notes-server.js'));
  return [...stage1(), ...STAGE2];
}
const EINKAUF = '6f1c2a90-1111-4c1d-9a00-000000000001';
const DROGERIE = '6f1c2a90-1111-4c1d-9a00-000000000002';
const POINTS = [['Milch', '2 l'], ['Brot'], ['Äpfel', '1 kg'], ['Butter'], ['Nudeln', '2 Pck.'], ['Kaffee'], ['Joghurt', '4'], ['Spülmittel']];
/** The family's list "Einkauf" of the mockup (8 open items) and the task "Bei Lidl einkaufen" that carries it. */
function seedShopping(n) {
  const list = n.srv.addShopList({ id: EINKAUF, name: 'Einkauf', family: true, items: POINTS.map(([text, qty]) => ({ text, qty })) });
  const task = n.srv.addTask({ title: 'Bei Lidl einkaufen', due: { date: '2026-11-08', time: null } });
  n.srv.state.attached.set(task.id, list.num);
  return { list, task };
}
const shopItem = (n, text) => [...n.srv.state.shopItems.values()].find((i) => i.text === text && !i.deleted) || null;
const posted = (n, re) => n.srv.state.requests.filter((r) => re.test(r.path));

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
  test('an older plugin: no card, no marks, no calendar chip', async ({ launchApp, mock }) => {
    const n = await mock.setNotes();
    const open = n.srv.addTask({ title: 'Schrauben kaufen', due: { date: YESTERDAY, time: null } });
    n.srv.state.tasks.get(11).remindAt = '2026-11-08T09:00:00+01:00';
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    await expect(root.locator('.nz-sec[data-id="overdue"] .nz-row-title')).toHaveText(['Rechnung Stadtwerke bezahlen', 'Schrauben kaufen']);
    await expect(row(root, `t:${open.id}`)).toBeVisible();
    await expect(root.locator('.nz-yd')).toHaveCount(0);
    await expect(root.locator('.nz-mark')).toHaveCount(0);
    await root.locator('#nz-quick').fill('morgen 9 Uhr Mülltonne rausstellen');
    await expect(root.locator('.nz-qchip[data-kind="remind"]')).toBeVisible();
    await expect(root.locator('.nz-qchip[data-kind="calendar"]')).toHaveCount(0);
    expect(n.srv.state.requests.some((r) => /\/api\/(yesterday|tasks\/\d+\/move)$/.test(r.path))).toBe(false);
  });

  test('plugin 1.3.0: "Gestern offen geblieben" above the sections, a task\'s marks, the calendar chip', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage1() });
    const a = n.srv.addTask({ title: 'Schrauben kaufen', listId: 2, due: { date: YESTERDAY, time: null } });
    const b = n.srv.addTask({ title: 'Rezept abholen', due: { date: YESTERDAY, time: '17:00' } });
    const c = n.srv.addTask({ title: 'Altglas wegbringen', due: { date: YESTERDAY, time: null } });
    const d = n.srv.addTask({ title: 'Pfand wegbringen', due: { date: YESTERDAY, time: null } });
    n.srv.state.tasks.get(11).remindAt = '2026-11-08T09:00:00+01:00';
    n.srv.state.tasks.get(17).remindAt = '2026-11-08T19:00:00+01:00';
    n.srv.state.tasks.get(17).listId = 1;
    n.srv.state.tasks.get(17).due = { date: '2026-11-08', time: null };
    n.srv.state.snoozed.add(17);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    // the card stands first, with every row and its three buttons; "Überfällig" does not show them a second time
    const card = root.locator('.nz-yd');
    await expect(root.locator('.nz-sec').first()).toHaveAttribute('data-id', 'yesterday');
    await expect(card.locator('.nz-yd-h span').first()).toHaveText(/^(Gestern offen geblieben|Left open yesterday)$/);
    await expect(card.locator('.nz-row-title')).toHaveText(['Rezept abholen', 'Altglas wegbringen', 'Pfand wegbringen', 'Schrauben kaufen']);
    await expect(card.locator(`.nz-row[data-uid="t:${b.id}"] .nz-yd-btn`)).toHaveText([/^(Erledigt|Done)$/, /^(Heute|Today)$/, /^(Verschieben|Move)$/]);
    await expect(root.locator('.nz-sec[data-id="overdue"] .nz-row-title')).toHaveText(['Rechnung Stadtwerke bezahlen']);
    // a task's marks: a reminder to come and the event in the calendar; put off with "Später"
    await expect(row(root, 't:11').locator('.nz-mark')).toHaveText([/^(Erinnerung|Reminder)$/, /^(im Kalender|in the calendar)$/]);
    await expect(row(root, 't:17').locator('.nz-mark')).toHaveText([/^(Später|Later): 19:00$/]);
    await expect(row(root, 't:12').locator('.nz-mark')).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath('notizen-yesterday.png') });

    // the quick entry: a day with a time also goes into the calendar "Aufgaben"
    const quick = root.locator('#nz-quick');
    await quick.fill('morgen 9 Uhr Mülltonne rausstellen');
    await expect(root.locator('.nz-qchip[data-kind="calendar"]')).toHaveText(/^(Kalender|Calendar): Aufgaben$/);
    await quick.fill('morgen Mülltonne rausstellen');
    await expect(root.locator('.nz-qchip[data-kind="date"]')).toBeVisible();
    await expect(root.locator('.nz-qchip[data-kind="calendar"]')).toHaveCount(0);
    await quick.fill('');

    // Heute
    await card.locator(`.nz-row[data-uid="t:${a.id}"] [data-act="today"]`).click();
    await expect.poll(() => n.srv.state.tasks.get(a.id).due.date).toBe('2026-11-08');
    await expect(card.locator('.nz-row')).toHaveCount(3);
    await expect(root.locator(`.nz-sec[data-id="today"] .nz-row[data-uid="t:${a.id}"]`)).toBeVisible();
    // Verschieben: Morgen · Am Wochenende · Anderes Datum
    await card.locator(`.nz-row[data-uid="t:${b.id}"] [data-act="move"]`).click();
    const dlg = page.locator('.nz-dlg');
    await expect(dlg.locator('.nz-dlg-title')).toHaveText(/^(Verschieben auf|Move to)$/);
    await expect(dlg.locator('.nz-yd-choices .btn')).toHaveText([/^(Morgen|Tomorrow)$/, /^(Am Wochenende|At the weekend)$/]);
    await page.screenshot({ path: test.info().outputPath('notizen-yesterday-move.png') });
    await dlg.locator('[data-to="weekend"]').click();
    await expect.poll(() => n.srv.state.tasks.get(b.id).due).toEqual({ date: '2026-11-14', time: '17:00' });
    await expect(card.locator('.nz-row')).toHaveCount(2);
    // … another date
    await card.locator(`.nz-row[data-uid="t:${c.id}"] [data-act="move"]`).click();
    await expect(dlg.locator('[data-act="date"]')).toBeDisabled();
    await dlg.locator('input[type="date"]').fill('2026-11-20');
    await dlg.locator('[data-act="date"]').click();
    await expect.poll(() => n.srv.state.tasks.get(c.id).due.date).toBe('2026-11-20');
    await expect(card.locator('.nz-row')).toHaveCount(1);
    // Erledigt
    const e = n.srv.addTask({ title: 'Leiter zurückgeben', due: { date: YESTERDAY, time: null } });
    await card.locator(`.nz-row[data-uid="t:${d.id}"] [data-act="done"]`).click();
    await expect.poll(() => !!n.srv.state.tasks.get(d.id).doneAt).toBe(true);
    await expect(card.locator('.nz-row-title')).toHaveText(['Leiter zurückgeben']);
    // Alle heute: the card goes when every row is decided
    await card.locator('.nz-yd-all').click();
    await expect.poll(() => n.srv.state.tasks.get(e.id).due.date).toBe('2026-11-08');
    await expect(root.locator('.nz-yd')).toHaveCount(0);
    expect(n.srv.state.requests.filter((r) => r.method === 'POST' && r.path.endsWith('/api/yesterday')).map((r) => r.body)).toEqual([{ action: 'today', area: 'private' }]);
  });

  test('plugin 1.3.0: the morning hint — "Erledigt" asks once, "Verschieben" offers the days, in the app instead of the portal', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage1() });
    const a = n.srv.addTask({ title: 'Schrauben kaufen', listId: 2, due: { date: YESTERDAY, time: null } });
    const b = n.srv.addTask({ title: 'Rezept abholen', due: { date: YESTERDAY, time: null } });
    const c = n.srv.addTask({ title: 'Altglas wegbringen', due: { date: YESTERDAY, time: null } });
    const d = n.srv.addTask({ title: 'Angebot prüfen', listId: 5, due: { date: YESTERDAY, time: null } });
    const topic = 'plugin:gatecontrol-notizen:reminders';
    const hint = (id, title, taskIds) => ({
      id, topic, title, body: 'Schrauben kaufen · Haus & Garten', collapse_key: 'yesterday',
      data: { notizen: { kind: 'yesterday', day: YESTERDAY, count: taskIds.length, taskIds, area: null }, actions: [
        { id: 'done_ask', label: 'Erledigt', type: 'open_portal', target: '/portal#plg-gatecontrol-notizen' },
        { id: 'today', label: 'Heute', type: 'callback' },
        { id: 'move', label: 'Verschieben', type: 'open_portal', target: '/portal#plg-gatecontrol-notizen' },
      ] },
    });
    mock.setPush({ topics: [{ id: topic, label: 'Notizen & Aufgaben · Erinnerungen an Aufgaben' }], items: [hint(71, 'Gestern offen geblieben: 2', [a.id, b.id])] });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect(page.locator('#nav-notizen')).toBeVisible();
    await expect(page.locator('#inbox-badge')).toHaveText('1');
    await page.locator('#nav-inbox').click();
    await page.locator('#inbox-list .inbox-row').first().click();
    await expect(page.locator('#inbox-detail .inbox-actions .btn')).toHaveText(['Erledigt', 'Heute', 'Verschieben']);
    const links = mock.count('/api/v1/client/portal-link');

    // "Erledigt": Mein Tag with the card, one question for the two tasks the message named
    await page.locator('#inbox-detail [data-action="done_ask"]').click();
    await expect(page.locator('#page-notizen')).toHaveClass(/active/);
    const root = page.locator('#page-notizen');
    await expect(root.locator('.nz-it[data-view="myday"]')).toHaveClass(/on/);
    await expect(root.locator('.nz-yd .nz-row')).toHaveCount(3);
    const dlg = page.locator('.nz-dlg');
    await expect(dlg.locator('.nz-dlg-title')).toHaveText(/^(Alle 2 abhaken\?|Tick off all 2\?)$/);
    await page.screenshot({ path: test.info().outputPath('notizen-yesterday-ask.png') });
    expect([!!n.srv.state.tasks.get(a.id).doneAt, !!n.srv.state.tasks.get(b.id).doneAt]).toEqual([false, false]);
    await dlg.locator('[data-act="confirm"]').click();
    await expect.poll(() => [a, b, c].map((x) => !!n.srv.state.tasks.get(x.id).doneAt)).toEqual([true, true, false]);
    await expect(root.locator('.nz-yd .nz-row-title')).toHaveText(['Altglas wegbringen']);
    await expect.poll(() => mock.acks().some((x) => x.action === 'done_ask')).toBe(true);
    expect(n.srv.state.requests.filter((r) => r.method === 'POST' && r.path.endsWith('/api/yesterday')).map((r) => r.body)).toEqual([{ action: 'done', ids: [a.id, b.id] }]);

    // "Verschieben" of a second hint (a task of each area): the days, then both at once
    mock.pushNotification(hint(72, 'Gestern offen geblieben: 2', [c.id, d.id]));
    await page.locator('#nav-inbox').click();
    await expect(page.locator('#inbox-list .inbox-row')).toHaveCount(2);
    await page.locator('#inbox-list .inbox-row').first().click();
    await expect(page.locator('#inbox-detail .inbox-detail-title')).toHaveText('Gestern offen geblieben: 2');
    await page.locator('#inbox-detail [data-action="move"]').click();
    await expect(page.locator('#page-notizen')).toHaveClass(/active/);
    await expect(dlg.locator('.nz-dlg-title')).toHaveText(/^(Verschieben auf|Move to)$/);
    await dlg.locator('[data-to="tomorrow"]').click();
    await expect.poll(() => [c, d].map((x) => n.srv.state.tasks.get(x.id).due.date)).toEqual(['2026-11-09', '2026-11-09']);
    await expect(root.locator('.nz-yd')).toHaveCount(0);
    // neither button went to the portal
    expect(mock.count('/api/v1/client/portal-link')).toBe(links);
  });

  test('an older plugin (1.3.0): no shopping lists, no list at a task, nothing new asked or sent', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage1() });
    const { task } = seedShopping(n);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    await expect(row(root, `t:${task.id}`)).toBeVisible();
    await expect(root.locator('.nz-it[data-view^="shopping:"]')).toHaveCount(0);
    await expect(root.locator('.nz-it[data-view="new-shopping"]')).toHaveCount(0);
    await expect(root.locator('.nz-mark[data-kind="list"]')).toHaveCount(0);
    await row(root, `t:${task.id}`).click();
    await expect(root.locator('.nz-detail .nz-d-title')).toHaveValue('Bei Lidl einkaufen');
    await expect(root.locator('.nz-detail .nz-attached')).toHaveCount(0);
    const quick = root.locator('#nz-quick');
    await quick.fill('bei Lidl einkaufen');
    await expect(root.locator('.nz-qchip[data-kind="area"]')).toBeVisible();
    await page.waitForTimeout(600);
    await expect(root.locator('.nz-qchip[data-kind="shopping"]')).toHaveCount(0);
    await quick.press('Enter');
    await expect.poll(() => posted(n, /\/api\/tasks$/).length).toBe(1);
    expect(posted(n, /\/api\/tasks$/)[0].body).toEqual({ text: 'bei Lidl einkaufen', area: 'private', createList: false, myDay: true });
    expect(posted(n, /\/api\/(shopping|parse)/)).toEqual([]);
  });

  test('plugin 1.4.0: a shopping list — ticked off, items added, changed and deleted; "Alles abgehakt" completes the task, and back', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage2() });
    const { list, task } = seedShopping(n);
    n.srv.addShopList({ id: DROGERIE, name: 'Drogerie', icon: 'heart', items: [{ text: 'Zahnpasta' }] });
    mock.setPush({ topics: [] });   // the push stream carries the plugin's live events
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    // the menu: the shopping lists of the area with what is open; the family's list is marked
    const nav = root.locator(`.nz-it[data-view="shopping:${EINKAUF}"]`);
    await expect(root.locator('.nz-it[data-view^="shopping:"] .nz-it-tx')).toHaveText(['Einkauf', 'Drogerie']);
    await expect(nav.locator('.nz-n')).toHaveText('8');
    await expect(nav.locator('.nz-it-mark')).toHaveCount(1);
    // Mein Tag: the task shows which list hangs at it and how far it is ticked off; the mark opens the list
    const mark = row(root, `t:${task.id}`).locator('.nz-mark[data-kind="list"]');
    await expect(mark).toHaveText('Einkauf 0/8');
    await page.screenshot({ path: test.info().outputPath('notizen-shopping-myday.png') });
    await mark.click();
    await expect(nav).toHaveClass(/on/);
    await expect(root.locator('.nz-main .nz-h')).toHaveText('Einkauf');
    await expect(root.locator('.nz-main .nz-sub')).toHaveText(/^(Familie|Family)$/);
    await expect(root.locator('.nz-shop-task')).toHaveText(/^(gehört zu „Bei Lidl einkaufen“ · 0 von 8|belongs to “Bei Lidl einkaufen” · 0 of 8)$/);
    const rows = root.locator('.nz-shop-row');
    await expect(rows.locator('.nz-row-title')).toHaveText(POINTS.map((x) => x[0]));
    await expect(rows.first().locator('.nz-shop-q')).toHaveText('2 l');
    await page.screenshot({ path: test.info().outputPath('notizen-shopping-list.png') });

    // tick off: at once, open ones stay on top
    await rows.first().locator('.nz-ck').click();
    await expect.poll(() => n.srv.state.shopItems.get(list.items[0]).checked).toBe(true);
    await expect(rows.locator('.nz-row-title')).toHaveText([...POINTS.slice(1).map((x) => x[0]), 'Milch']);
    await expect(rows.last()).toHaveClass(/is-done/);
    await expect(nav.locator('.nz-n')).toHaveText('7');
    await expect(root.locator('.nz-shop-task')).toHaveText(/1 (von|of) 8$/);
    // a new item with its quantity (Enter); its id is made on this PC
    await root.locator('#nz-shop-add').fill('Hefe');
    await root.locator('#nz-shop-qty').fill('1 Würfel');
    await root.locator('#nz-shop-qty').press('Enter');
    await expect.poll(() => (shopItem(n, 'Hefe') || {}).qty).toBe('1 Würfel');
    expect(shopItem(n, 'Hefe').id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-/);
    await expect(root.locator('#nz-shop-add')).toHaveValue('');
    await expect(root.locator('#nz-shop-add')).toBeFocused();
    await expect(rows).toHaveCount(9);
    // change it, delete it
    const brot = root.locator(`.nz-shop-row[data-item="${list.items[1]}"]`);
    await brot.hover();
    await brot.locator('[data-act="shop-edit"]').click();
    const dlg = page.locator('.nz-dlg');
    await dlg.locator('input').first().fill('Vollkornbrot');
    await dlg.locator('input').nth(1).fill('1');
    await dlg.locator('[data-act="save"]').click();
    await expect.poll(() => [n.srv.state.shopItems.get(list.items[1]).text, n.srv.state.shopItems.get(list.items[1]).qty]).toEqual(['Vollkornbrot', '1']);
    await expect(brot.locator('.nz-row-title')).toHaveText('Vollkornbrot');
    const hefe = root.locator(`.nz-shop-row[data-item="${shopItem(n, 'Hefe').id}"]`);
    await hefe.hover();
    await hefe.locator('[data-act="shop-delete"]').click();
    await expect.poll(() => shopItem(n, 'Hefe')).toBeNull();
    await expect(rows).toHaveCount(8);
    // what someone else writes at home shows here (the live event)
    n.srv.state.now += 5000;
    n.srv.state.shopItems.set('other-device-01', { id: 'other-device-01', list: EINKAUF, text: 'Salz', qty: null, checked: true, checkedBy: 12, updatedAt: n.srv.state.now, deleted: false, seq: 999 });
    mock.pushPlugin('gatecontrol-notizen', 'changed', { what: ['shopping'] });
    await expect(rows).toHaveCount(9);

    // the last open item: "Alles abgehakt" — the task is done, with the way back; no item is unticked by it
    for (const id of list.items.slice(1)) await root.locator(`.nz-shop-row[data-item="${id}"] .nz-ck`).click();
    await expect.poll(() => !!n.srv.state.tasks.get(task.id).doneAt).toBe(true);
    const toast = page.locator('#toasts .toast', { hasText: /Alles abgehakt|All ticked off/ });
    await expect(toast.locator('.toast-text')).toHaveText(/^(Alles abgehakt\. „Bei Lidl einkaufen“ ist erledigt\.|All ticked off\. “Bei Lidl einkaufen” is done\.)$/);
    await expect(nav.locator('.nz-n')).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath('notizen-shopping-done.png') });
    await toast.locator('.toast-act').click();
    await expect.poll(() => n.srv.state.tasks.get(task.id).doneAt).toBeNull();
    expect([...n.srv.state.shopItems.values()].filter((i) => i.list === EINKAUF && !i.deleted).every((i) => i.checked)).toBe(true);
    await expect(root.locator('.nz-shop-task')).toHaveText(/9 (von|of) 9$/);
    // "Abgehakte entfernen": the list is empty for the next time
    await root.locator('[data-act="shop-clear"]').click();
    await expect.poll(() => [...n.srv.state.shopItems.values()].filter((i) => i.list === EINKAUF && !i.deleted).length).toBe(0);
    await expect(root.locator('.nz-main .nz-empty')).toBeVisible();
    // every change went through POST shopping/ops, in the order made
    expect(posted(n, /\/api\/shopping\/ops$/).flatMap((r) => r.body.ops.map((o) => o.op))).toEqual(['item_check', 'item_add', 'item_edit', 'item_delete', ...list.items.slice(1).map(() => 'item_check'), 'clear_checked']);

    // a new list from the menu; renamed and deleted in its settings
    await root.locator('.nz-it[data-view="new-shopping"]').click();
    await dlg.locator('input').first().fill('Baumarkt');
    await dlg.locator('.btn-pri').click();
    await expect.poll(() => [...n.srv.state.shopLists.values()].some((l) => l.name === 'Baumarkt' && !l.deletedAt)).toBe(true);
    await expect(root.locator('.nz-main .nz-h')).toHaveText('Baumarkt');
    await expect(root.locator('.nz-main .nz-sub')).toHaveText(/^(nur ich|only me)$/);
    await root.locator('.nz-main .nz-head .nz-ib').click();
    await dlg.locator('[data-act="shop-remove"]').click();
    await expect.poll(() => [...n.srv.state.shopLists.values()].some((l) => l.name === 'Baumarkt' && !l.deletedAt)).toBe(false);
    await expect(root.locator('.nz-it[data-view="myday"]')).toHaveClass(/on/);
    await expect(root.locator('.nz-it[data-view^="shopping:"] .nz-it-tx')).toHaveText(['Einkauf', 'Drogerie']);
    // deleted by mistake: the toast brings it back
    const gone = page.locator('#toasts .toast', { hasText: /Baumarkt/ });
    await expect(gone.locator('.toast-text')).toHaveText(/^(Einkaufsliste „Baumarkt“ gelöscht\.|Shopping list “Baumarkt” deleted\.)$/);
    await gone.locator('.toast-act').click();
    await expect.poll(() => [...n.srv.state.shopLists.values()].some((l) => l.name === 'Baumarkt' && !l.deletedAt)).toBe(true);
    await expect(root.locator('.nz-it[data-view^="shopping:"] .nz-it-tx')).toHaveText(['Einkauf', 'Drogerie', 'Baumarkt']);
    await expect(root.locator('.nz-main .nz-h')).toHaveText('Baumarkt');
    // renamed and shared with one person in its settings
    await root.locator('.nz-main .nz-head .nz-ib').click();
    await dlg.locator('input[type="text"]').fill('Bauhaus');
    await dlg.locator('.nz-share .nz-check', { hasText: 'Jenny Muster' }).locator('input').check();
    await dlg.locator('.btn-pri').click();
    await expect.poll(() => { const l = [...n.srv.state.shopLists.values()].find((x) => x.name === 'Bauhaus'); return l ? l.members : null; }).toEqual([{ id: 12, role: 'write' }]);
    await expect(root.locator('.nz-main .nz-h')).toHaveText('Bauhaus');
    await expect(root.locator('.nz-main .nz-sub')).toHaveText('Jenny Muster');
  });

  test('plugin 1.4.0: a list at a task — suggested in the quick entry, chosen in the details, opened from there', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage2() });
    const { list } = seedShopping(n);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    // "bei Lidl einkaufen": the server suggests the list "Einkauf"; the chip stays → the task carries it
    const quick = root.locator('#nz-quick');
    const chip = root.locator('.nz-qchip[data-kind="shopping"]');
    await quick.fill('bei Lidl einkaufen');
    await expect(chip).toHaveText(/^(Liste|List): Einkauf · 8 (offen|open)$/);
    await page.screenshot({ path: test.info().outputPath('notizen-shopping-quick.png') });
    await quick.press('Enter');
    await expect.poll(() => posted(n, /\/api\/tasks$/).length).toBe(1);
    expect(posted(n, /\/api\/tasks$/)[0].body).toEqual({ text: 'bei Lidl einkaufen', area: 'private', createList: false, attachedListId: list.num, myDay: true });
    const made = [...n.srv.state.tasks.values()].find((x) => x.title === 'bei Lidl einkaufen');
    expect(n.srv.state.attached.get(made.id)).toBe(list.num);
    await expect(row(root, `t:${made.id}`).locator('.nz-mark[data-kind="list"]')).toHaveText('Einkauf 0/8');
    // the chip taken away: no list — the server attaches nothing by itself
    await quick.fill('Brot besorgen');
    await expect(chip).toHaveText(/Einkauf/);
    await chip.locator('.nz-qx').click();
    await expect(chip).toHaveClass(/plain/);
    await quick.press('Enter');
    await expect.poll(() => posted(n, /\/api\/tasks$/).length).toBe(2);
    expect(posted(n, /\/api\/tasks$/)[1].body).toEqual({ text: 'Brot besorgen', area: 'private', createList: false, myDay: true });
    await expect(quick).toHaveValue('');
    await expect(chip).toHaveCount(0);
    // a line that names no list: no chip
    await quick.fill('Rasen mähen');
    await expect.poll(() => posted(n, /\/api\/parse$/).some((r) => r.body.text === 'Rasen mähen')).toBe(true);
    await expect(chip).toHaveCount(0);
    await quick.fill('');

    // the details: "Angehängte Liste" — chosen, opened, taken off again
    await row(root, 't:12').click();
    const d = root.locator('.nz-detail');
    const sel = d.locator('.nz-attached select');
    await expect(sel.locator('option')).toHaveText([/^(Keine|None)$/, /^Einkauf · (Familie|Family) · 8 (offen|open)$/, /^(Neue Liste|New list) …$/]);
    await expect(d.locator('[data-act="open-list"]')).toHaveCount(0);
    await sel.selectOption(String(list.num));
    await expect.poll(() => n.srv.state.attached.get(12)).toBe(list.num);
    await expect(row(root, 't:12').locator('.nz-mark[data-kind="list"]')).toHaveText('Einkauf 0/8');
    await page.screenshot({ path: test.info().outputPath('notizen-shopping-detail.png') });
    await d.locator('[data-act="open-list"]').click();
    await expect(root.locator(`.nz-it[data-view="shopping:${EINKAUF}"]`)).toHaveClass(/on/);
    await expect(root.locator('.nz-shop-task')).toHaveText(/(und 2 weiteren|and 2 more) · 0 (von|of) 8$/);
    // the line above the items leads back to the task
    await root.locator('.nz-shop-task').click();
    await expect(d.locator('.nz-d-title')).toBeVisible();
    await d.locator('.nz-attached select').selectOption('');
    await expect.poll(() => n.srv.state.attached.has(12)).toBe(false);
    // a new list right from the details: made on this PC, then attached by its text id
    await root.locator('.nz-it[data-view="myday"]').click();
    await row(root, 't:11').click();
    await d.locator('.nz-attached select').selectOption('new');
    const dlg = page.locator('.nz-dlg');
    await dlg.locator('input').first().fill('Apotheke');
    await dlg.locator('.btn-pri').click();
    await expect.poll(() => { const l = [...n.srv.state.shopLists.values()].find((x) => x.name === 'Apotheke'); return !!l && n.srv.state.attached.get(11) === l.num; }).toBe(true);
    expect(posted(n, /\/api\/tasks\/11$/).pop().body).toEqual({ attachedListUid: [...n.srv.state.shopLists.values()].find((x) => x.name === 'Apotheke').uid });
    await expect(row(root, 't:11').locator('.nz-mark[data-kind="list"]')).toHaveText('Apotheke 0/0');
  });

  test('plugin 1.4.0: the reminder\'s button "Liste öffnen" opens the list in the app, not the portal', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage2() });
    const { list, task } = seedShopping(n);
    const topic = 'plugin:gatecontrol-notizen:reminders';
    mock.setPush({ topics: [{ id: topic, label: 'Notizen & Aufgaben · Erinnerungen an Aufgaben' }], items: [{
      id: 81, topic, title: 'Bei Lidl einkaufen', body: 'Fällig heute 10:00 · Aufgaben\nEinkauf · 8 Punkte: Milch, Brot, Äpfel, Butter …', collapse_key: `task:${task.id}`,
      data: { notizen: { kind: 'reminder', taskId: task.id, listId: 1, area: 'private', task: task.id, tag: `task:${task.id}:1794729600000`, attachedList: { id: list.num, uid: EINKAUF, name: 'Einkauf', open: 8, total: 8 } }, actions: [
        { id: 'open_list', label: 'Liste öffnen', type: 'open_app_route', target: 'plg-gatecontrol-notizen' },
        { id: 'done', label: 'Erledigt', type: 'callback' },
        { id: 'snooze_1h', label: 'In 1 Std.', type: 'callback' },
      ] },
    }] });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect(page.locator('#nav-notizen')).toBeVisible();
    await expect(page.locator('#inbox-badge')).toHaveText('1');
    await page.locator('#nav-inbox').click();
    await page.locator('#inbox-list .inbox-row').first().click();
    await expect(page.locator('#inbox-detail .inbox-actions .btn')).toHaveText(['Liste öffnen', 'Erledigt', 'In 1 Std.']);
    const links = mock.count('/api/v1/client/portal-link');
    await page.locator('#inbox-detail [data-action="open_list"]').click();
    await expect(page.locator('#page-notizen')).toHaveClass(/active/);
    const root = page.locator('#page-notizen');
    await expect(root.locator(`.nz-it[data-view="shopping:${EINKAUF}"]`)).toHaveClass(/on/);
    await expect(root.locator('.nz-main .nz-h')).toHaveText('Einkauf');
    await expect(root.locator('.nz-shop-row')).toHaveCount(8);
    // ready to tick off
    await root.locator('.nz-shop-row').first().locator('.nz-ck').click();
    await expect.poll(() => n.srv.state.shopItems.get(list.items[0]).checked).toBe(true);
    expect(mock.count('/api/v1/client/portal-link')).toBe(links);
    // the list is gone meanwhile: the button of a second reminder opens the task instead
    Object.assign(n.srv.state.shopLists.get(EINKAUF), { deletedAt: n.srv.state.now, was: [1] });
    mock.pushNotification({ id: 82, topic, title: 'Bei Lidl einkaufen', body: 'Fällig heute 10:00 · Aufgaben', collapse_key: `task:${task.id}`,
      data: { notizen: { kind: 'reminder', taskId: task.id, task: task.id, attachedList: { id: list.num, uid: EINKAUF, name: 'Einkauf', open: 7, total: 8 } }, actions: [{ id: 'open_list', label: 'Liste öffnen', type: 'open_app_route', target: 'plg-gatecontrol-notizen' }] } });
    await page.locator('#nav-inbox').click();
    await expect(page.locator('#inbox-list .inbox-row')).toHaveCount(2);
    await page.locator('#inbox-list .inbox-row').first().click();
    await page.locator('#inbox-detail [data-action="open_list"]').click();
    await expect(page.locator('#page-notizen')).toHaveClass(/active/);
    await expect(root.locator('.nz-detail .nz-d-title')).toHaveValue('Bei Lidl einkaufen');
    await expect(root.locator('.nz-it[data-view^="shopping:"]')).toHaveCount(0);
  });
});
