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
// Plugin 1.5.0 (places, placeSearch): a task at a place — the mark and the line "Ort", the dialog "Welcher …?" (the
// places near one of the person's places: this PC has no position and sends none; a search only when the person asks),
// the place chip of the quick entry (the server's suggestion), "Orte" on the page "Quellen" and the consent for a place
// someone else set. The phone reminds: the app never asks what to watch (places/watch, places/fired).
// Plugin 1.6.0 (taskTurns, taskStars, familyTasks, doneFeedback, placeMine): "Wer ist dran?" in the quick entry (read on
// this PC with the plugin's own turnwords after the parser) and in the details, the marks of a row (whose turn, the stars,
// "Erledigt von …"), the family's list (stars by parents only, a parent ticks off for a child and hands a task back, a
// child changes only what no parent made), the message "… hat '…' erledigt" with "Ansehen" / "Noch nicht fertig", the
// note "Umzug abgeschlossen" once, and the consent for a place only for who may give it.
// Plugin 1.7.0 (driveDeadlines) with Drive 1.30.0: "Notizen & Aufgaben" rings the reminders of Drive's deadlines — such a
// task shows the deadline at its row and in its details, "Datei öffnen" opens the file on the Drive page (from the task
// and from the reminder's fourth button), deleting it says what that means. And a list the person only reads.

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
// … and the words of plugin 1.5.0
function stage3() {
  const { STAGE3 } = require(path.join(coreDir(), 'test', 'fixtures', 'notes-server.js'));
  return [...stage2(), ...STAGE3];
}
const OSM_URL = 'https://www.openstreetmap.org/copyright';
// … and the words of plugin 1.6.0
function stage4() {
  const { STAGE4 } = require(path.join(coreDir(), 'test', 'fixtures', 'notes-server.js'));
  return [...stage3(), ...STAGE4];
}
// … and the word of plugin 1.7.0
function stage5() {
  const { STAGE5 } = require(path.join(coreDir(), 'test', 'fixtures', 'notes-server.js'));
  return [...stage4(), ...STAGE5];
}
/** A deadline of Brief.pdf (node 12) in Drive with the person's reminder, and the task the hub made for it. */
function seedDeadline(n, d, by) {
  d.srv.setInsight(12, { kind: 'insurance', title: 'Kfz-Versicherung', deadlines: [{ kind: 'cancellation', date: '2099-11-30', label: 'Kfz-Versicherung kündigen' }] });
  const dl = d.srv.state.deadlines[0];
  dl.reminder = { at: '2099-11-27T07:00:00.000Z', daysBefore: 3, sent: false, ...(by ? { by } : {}) };
  const task = n.srv.addDeadline({ title: 'Kfz-Versicherung kündigen', date: '2026-11-30', kind: 'cancellation', file: 'Brief.pdf', daysBefore: 3, nodeId: 12, deadlineId: dl.id });
  return { dl, task };
}
const NOAH = 15;
const MIA = 16;
/** A screenshot of the page in both themes (the toasts of earlier steps out of the way). */
async function shots(page, name) {
  await page.evaluate(() => { const box = document.querySelector('#toasts'); if (box) box.replaceChildren(); });
  await page.screenshot({ path: test.info().outputPath(`${name}-dark.png`) });
  await light(page);
  await page.screenshot({ path: test.info().outputPath(`${name}-light.png`) });
  await dark(page);
}
/** The server's suggestion for the typed line has come (else the page lets the server decide: attach / place 'auto'). */
async function suggested(n, page, text) {
  await expect.poll(() => posted(n, /\/api\/parse$/).some((r) => r.body.text === text)).toBe(true);
  await page.waitForTimeout(400);
}
/** The language the screenshots of plugin 1.6.0 are taken in (GC_NOTES_LANG=de|en); the assertions hold in both. */
const LANG = process.env.GC_NOTES_LANG || '';
const setLang = (page) => (LANG ? page.evaluate((l) => window.gatecontrol.locale.set(l), LANG) : Promise.resolve());
const light = (page) => page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'));
const dark = (page) => page.evaluate(() => document.documentElement.removeAttribute('data-theme'));
/** The family's list after the move (Max and Jenny are the parents, Noah and Mia the children) with three tasks. */
function seedFamily(n, opts = {}) {
  const fam = n.srv.addFamily(opts);
  const room = n.srv.addTask({ listId: fam.id, title: 'Zimmer aufräumen', assigneeId: NOAH, stars: 2, due: { date: '2026-11-08', time: '17:00' } });
  const rabbits = n.srv.addTask({ listId: fam.id, title: 'Hasen füttern', assigneeId: MIA });
  const flowers = n.srv.addTask({ listId: fam.id, title: 'Blumen gießen', turn: 'first', people: [12, NOAH, MIA] });
  return { fam, room, rabbits, flowers };
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

  test('an older plugin (1.4.0): no place at a task, no chip, no "Orte", nothing new asked or sent', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage2() });
    // what the server would hold stays unseen: an older plugin sends no `place`
    const nord = n.srv.addPlace({ name: 'Baumarkt Nord', address: 'Industriestraße 4, Berlin', lat: 52.539, lon: 13.424, named: false, ref: 'osm:W101', fav: 'kind:diy' });
    n.srv.setTaskPlace(12, { placeId: nord.id, key: 'kind:diy', label: 'Baumarkt' });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    await expect(row(root, 't:12')).toBeVisible();
    await expect(root.locator('.nz-mark[data-kind="place"]')).toHaveCount(0);
    await row(root, 't:12').click();
    await expect(root.locator('.nz-detail .nz-d-title')).toHaveValue('Winterreifen-Termin ausmachen');
    await expect(root.locator('.nz-detail .nz-attached')).toHaveCount(1);
    await expect(root.locator('.nz-detail .nz-place')).toHaveCount(0);
    const quick = root.locator('#nz-quick');
    await quick.fill('beim Baumarkt Schrauben kaufen');
    await expect.poll(() => posted(n, /\/api\/parse$/).some((r) => r.body.text === 'beim Baumarkt Schrauben kaufen')).toBe(true);
    await page.waitForTimeout(400);
    await expect(root.locator('.nz-qchip[data-kind="place"]')).toHaveCount(0);
    await quick.press('Enter');
    await expect.poll(() => posted(n, /\/api\/tasks$/).length).toBe(1);
    expect(posted(n, /\/api\/tasks$/)[0].body).toEqual({ text: 'beim Baumarkt Schrauben kaufen', area: 'private', createList: false, myDay: true });
    await root.locator('.nz-it[data-view="sources"]').click();
    await expect(root.locator('.nz-srccard').first()).toBeVisible();
    await expect(root.locator('[data-set="places"]')).toHaveCount(0);
    expect(posted(n, /\/api\/places|\/place\//)).toEqual([]);
  });

  test('plugin 1.5.0: a task at a place — chosen in "Welcher …?", shown at the task, changed and taken off; this PC watches nothing', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage3() });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    await row(root, 't:12').click();
    const d = root.locator('.nz-detail');
    const placeBtn = d.locator('[data-act="place"]');
    await expect(placeBtn).toHaveText(/^(Ort wählen|Choose a place)$/);
    await placeBtn.click();
    const dlg = page.locator('.nz-dlg[data-dialog="place"]');
    const title = dlg.locator('.nz-dlg-title');
    const save = dlg.locator('[data-act="place-save"]');
    await expect(title).toHaveText(/^(Ort|Place)$/);
    // this PC has no position: the search is made near one of the person's places — "Zuhause" first
    await expect(dlg.locator('[data-act="place-near"] option')).toHaveText([/^(in der Nähe von|near) Zuhause$/, /^(in der Nähe von|near) Schule$/]);
    await expect(dlg.locator('[data-list="mine"] .nz-pl-tx b')).toHaveText(['Zuhause', 'Schule']);
    await expect(save).toBeDisabled();
    await expect(dlg.locator('.nz-pl-phone')).toHaveText(/^(Erinnert wird am Handy|Your phone reminds)/);
    // typing searches nothing; Enter (or "Suchen") does
    await dlg.locator('[data-act="place-q"]').fill('Baumarkt');
    await page.waitForTimeout(600);
    expect(n.srv.state.placeSearches).toEqual([]);
    await dlg.locator('[data-act="place-q"]').press('Enter');
    const hits = dlg.locator('[data-list="hits"] .nz-pl-row');
    await expect(hits.locator('.nz-pl-tx b')).toHaveText(['Baumarkt Nord', 'Baumarkt am Ring', 'Baumarkt Süd', /^(Jeder|Any) Baumarkt$/]);
    await expect(title).toHaveText(/^(Welcher|Which) Baumarkt\?$/);
    // estimated minutes and the distance, the nearest first; the first hit is chosen
    await expect(hits.first().locator('.nz-pl-r')).toHaveText(/^6 (Min\.|min)\s*2[,.]\d km$/);
    await expect(hits.first()).toHaveAttribute('aria-checked', 'true');
    expect(n.srv.state.placeSearches).toEqual([{ q: 'Baumarkt', nearFamilyId: 'home' }]);
    // "© OpenStreetMap" stands where hits stand and opens in the browser
    await expect(dlg.locator('.nz-pl-attr')).toHaveText(/^(Fahrzeit geschätzt aus der Entfernung\. Kartendaten:|Travel time estimated from the distance\. Map data:)\s*© OpenStreetMap$/);
    await dlg.locator('[data-act="osm"]').click();
    await expect.poll(() => app.evaluate(() => globalThis.__gcE2E.events.filter((e) => e.type === 'shell.openExternal').map((e) => e.url))).toContain(OSM_URL);
    // the second one, on leaving, remembered as "mein Baumarkt"
    await hits.nth(1).click();
    await dlg.locator('[data-trigger="exit"]').click();
    await dlg.locator('[data-act="place-remember"]').check();
    await page.screenshot({ path: test.info().outputPath('notizen-place-dialog.png') });
    await save.click();
    await expect.poll(() => (n.srv.state.taskPlace.get(12) || {}).trigger).toBe('exit');
    expect(posted(n, /\/api\/tasks\/12$/).pop().body).toEqual({ place: { trigger: 'exit', key: 'kind:diy', label: 'Baumarkt', remember: true, ref: 'osm:W102', name: 'Baumarkt am Ring', address: 'Ringstraße 21, Berlin', lat: 52.501, lon: 13.362 } });
    await expect(placeBtn).toHaveText(/^Baumarkt am Ring · (beim Verlassen|on leaving)$/);
    await expect(row(root, 't:12').locator('.nz-mark[data-kind="place"]')).toHaveText('Baumarkt am Ring');
    await expect(d.locator('.nz-place-hint')).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath('notizen-place-detail.png') });

    // again: the remembered place is one of "Meine Orte" and chosen — only the trigger changes
    await placeBtn.click();
    await expect(title).toHaveText(/^(Welcher|Which) Baumarkt\?$/);
    await expect(dlg.locator('[data-list="mine"] .nz-pl-row[aria-checked="true"] .nz-pl-tx')).toHaveText(/^Baumarkt am Ring\s*Ringstraße 21, Berlin · (gemerkt für „Baumarkt“|remembered for “Baumarkt”)$/);
    await dlg.locator('[data-trigger="enter"]').click();
    await save.click();
    await expect.poll(() => (n.srv.state.taskPlace.get(12) || {}).trigger).toBe('enter');
    expect(posted(n, /\/api\/tasks\/12$/).pop().body.place.placeId).toBe(n.srv.state.taskPlace.get(12).placeId);
    await expect(d.locator('.nz-place-hint[data-kind="nearby"]')).toHaveText(/Baumarkt/);
    // "Jeder Baumarkt": the places of the kind, asked by its key with "Suchen"; the remembered one comes first
    await placeBtn.click();
    await expect(dlg.locator('[data-list="mine"] .nz-pl-row[aria-checked="true"]')).toHaveCount(1);
    await dlg.locator('[data-act="place-search"]').click();
    await expect(hits.locator('.nz-pl-tx b')).toHaveText(['Baumarkt am Ring', 'Baumarkt Nord', 'Baumarkt Süd', /^(Jeder|Any) Baumarkt$/]);
    expect(n.srv.state.placeSearches[1]).toEqual({ key: 'kind:diy', label: 'Baumarkt', nearFamilyId: 'home' });
    await dlg.locator('[data-ref="any"]').click();
    await save.click();
    await expect.poll(() => (n.srv.state.taskPlace.get(12) || {}).any).toBe(true);
    expect(posted(n, /\/api\/tasks\/12$/).pop().body).toEqual({ place: { trigger: 'enter', any: true, key: 'kind:diy', label: 'Baumarkt' } });
    await expect(placeBtn).toHaveText(/^Jeder Baumarkt · (beim Ankommen|on arriving)$/);
    // taken off
    await placeBtn.click();
    await dlg.locator('[data-act="place-none"]').click();
    await expect.poll(() => n.srv.state.taskPlace.has(12)).toBe(false);
    expect(posted(n, /\/api\/tasks\/12$/).pop().body).toEqual({ place: null });
    await expect(placeBtn).toHaveText(/^(Ort wählen|Choose a place)$/);
    await expect(row(root, 't:12').locator('.nz-mark[data-kind="place"]')).toHaveCount(0);

    // the map service is busy / not reachable: said in the dialog, nothing is lost
    await placeBtn.click();
    n.srv.state.fail['POST places/search'] = { status: 429, code: 'busy', extra: { retryAfter: 20, reason: 'limit' } };
    await dlg.locator('[data-act="place-q"]').fill('Lidl');
    await dlg.locator('[data-act="place-search"]').click();
    await expect(dlg.locator('.note-err')).toHaveText(/20 (Sekunden|seconds)/);
    delete n.srv.state.fail['POST places/search'];
    n.srv.state.placeCfg.down = true;
    await dlg.locator('[data-act="place-search"]').click();
    await expect(dlg.locator('.note-err')).toHaveText(/^(Der Kartendienst ist gerade nicht erreichbar|The map service cannot be reached right now)/);
    n.srv.state.placeCfg.down = false;
    await dlg.locator('[data-act="place-search"]').click();
    await expect(hits.locator('.nz-pl-tx b')).toHaveText(['Lidl Marktstraße', 'Lidl Bahnhofsplatz', /^(Jeder|Any) Lidl$/]);
    await page.keyboard.press('Escape');
    await expect(dlg).toHaveCount(0);
    // a PC watches no place and sends no position
    expect(posted(n, /\/api\/places\/(watch|fired)|\/place\/(skip|later)/)).toEqual([]);
    expect(posted(n, /\/api\/places\/search$/).every((r) => !('near' in r.body) && (r.body.nearFamilyId === 'home'))).toBe(true);
  });

  test('plugin 1.5.0: the quick entry — the place the line names: searched on a click, decided for an own place and home, taken away', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage3() });
    const oma = n.srv.addPlace({ name: 'Oma', address: 'Gartenweg 5', lat: 52.4, lon: 13.2 });
    mock.setPush({ topics: [] });   // the push stream carries the plugin's live events
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    const quick = root.locator('#nz-quick');
    const chip = root.locator('.nz-qchip[data-kind="place"]');
    const dlg = page.locator('.nz-dlg[data-dialog="place"]');
    const tasks = () => posted(n, /\/api\/tasks$/);
    // a kind of place: the chip offers the choice — nothing is searched while typing
    await quick.fill('beim Baumarkt Schrauben kaufen');
    await expect(chip).toHaveText(/^(Ort|Place): Baumarkt …$/);
    await expect(chip).toHaveAttribute('data-state', 'ask');
    await page.waitForTimeout(500);
    expect(n.srv.state.placeSearches).toEqual([]);
    await page.screenshot({ path: test.info().outputPath('notizen-place-quick.png') });
    // the chip opens "Welcher Baumarkt?" with the places near home (one search, asked for by the click)
    await chip.locator('.nz-qbtn').click();
    await expect(dlg.locator('.nz-dlg-title')).toHaveText(/^(Welcher|Which) Baumarkt\?$/);
    await expect(dlg.locator('[data-list="hits"] .nz-pl-row[aria-checked="true"] .nz-pl-tx b')).toHaveText('Baumarkt Nord');
    expect(n.srv.state.placeSearches).toEqual([{ key: 'kind:diy', label: 'Baumarkt', nearFamilyId: 'home' }]);
    await expect(dlg.locator('[data-act="place-none"]')).toHaveCount(0);
    // the list behind the dialog is drawn anew meanwhile (someone changed a task): the choice still reaches the line
    const views = posted(n, /\/api\/views\/myday$/).length;
    mock.pushPlugin('gatecontrol-notizen', 'changed', { what: ['tasks'] });
    await expect.poll(() => posted(n, /\/api\/views\/myday$/).length).toBeGreaterThan(views);
    await expect(quick).toHaveValue('beim Baumarkt Schrauben kaufen');
    await dlg.locator('[data-act="place-save"]').click();
    await expect(chip).toHaveText(/^(Ort: Baumarkt Nord · beim Ankommen|Place: Baumarkt Nord · on arriving)$/);
    await expect(quick).toBeFocused();
    await quick.press('Enter');
    await expect.poll(() => tasks().length).toBe(1);
    expect(tasks()[0].body).toEqual({ text: 'beim Baumarkt Schrauben kaufen', area: 'private', createList: false, myDay: true,
      place: { trigger: 'enter', key: 'kind:diy', label: 'Baumarkt', ref: 'osm:W101', name: 'Baumarkt Nord', address: 'Industriestraße 4, Berlin', lat: 52.539, lon: 13.424 } });
    // the words of the place leave the title; the task shows where it hangs
    const made = [...n.srv.state.tasks.values()].find((x) => x.title === 'Schrauben kaufen');
    expect(made).toBeTruthy();
    await expect(row(root, `t:${made.id}`).locator('.nz-mark[data-kind="place"]')).toHaveText('Baumarkt Nord');
    await expect(page.locator('#toasts .toast', { hasText: 'Baumarkt Nord' }).locator('.toast-text')).toHaveText(/^(Hinzugefügt: Schrauben kaufen – Ort: Baumarkt Nord|Added: Schrauben kaufen – place: Baumarkt Nord)$/);
    await expect(quick).toHaveValue('');
    await expect(chip).toHaveCount(0);

    // an own place by its name: decided without a search; taken away with × — the title then stays whole
    await quick.fill('bei Oma Leiter zurückgeben');
    await expect(chip).toHaveText(/^(Ort: Oma · beim Ankommen|Place: Oma · on arriving)$/);
    await expect(chip).toHaveAttribute('data-state', 'set');
    await chip.locator('.nz-qx').click();
    await expect(chip).toHaveAttribute('data-state', 'off');
    await quick.press('Enter');
    await expect.poll(() => tasks().length).toBe(2);
    expect(tasks()[1].body).toEqual({ text: 'bei Oma Leiter zurückgeben', area: 'private', createList: false, myDay: true });
    expect([...n.srv.state.tasks.values()].some((x) => x.title === 'bei Oma Leiter zurückgeben' && !n.srv.state.taskPlace.has(x.id))).toBe(true);
    // … left as it is: the task hangs on the own place
    await quick.fill('bei Oma Kuchen abholen');
    await expect(chip).toHaveAttribute('data-state', 'set');
    await quick.press('Enter');
    await expect.poll(() => tasks().length).toBe(3);
    expect(tasks()[2].body).toEqual({ text: 'bei Oma Kuchen abholen', area: 'private', createList: false, myDay: true, place: { placeId: oma.id, trigger: 'enter' } });
    // "zu Hause": the place of the family
    await quick.fill('zu Hause Blumen gießen');
    await expect(chip).toHaveText(/^(Ort: Zuhause · beim Ankommen|Place: Zuhause · on arriving)$/);
    await quick.press('Enter');
    await expect.poll(() => tasks().length).toBe(4);
    expect(tasks()[3].body.place).toEqual({ familyId: 'home', trigger: 'enter' });
    await expect.poll(() => [...n.srv.state.tasks.values()].some((x) => x.title === 'Blumen gießen')).toBe(true);
    // not surely meant ("Apotheke anrufen"): a suggestion only — nothing is set
    await quick.fill('Apotheke anrufen');
    await expect(chip).toHaveText(/^(Ort|Place): Apotheke \?$/);
    await expect(chip).toHaveClass(/plain/);
    await quick.press('Enter');
    await expect.poll(() => tasks().length).toBe(5);
    expect(tasks()[4].body).toEqual({ text: 'Apotheke anrufen', area: 'private', createList: false, myDay: true });
    // a line without a place: no chip
    await quick.fill('Rasen mähen');
    await expect.poll(() => posted(n, /\/api\/parse$/).some((r) => r.body.text === 'Rasen mähen')).toBe(true);
    await expect(chip).toHaveCount(0);
    // the only search was the one the click asked for; the parser's own chips are what they were
    expect(n.srv.state.placeSearches.length).toBe(1);
    expect(posted(n, /\/api\/places\/(watch|fired)/)).toEqual([]);
  });

  test('plugin 1.5.0: "Orte" on the page "Quellen" — the switches, "Meine Orte"; with the search off only remembered places', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage3() });
    const nord = n.srv.addPlace({ name: 'Baumarkt Nord', address: 'Industriestraße 4, Berlin', lat: 52.539, lon: 13.424, named: false, ref: 'osm:W101', fav: 'kind:diy', uses: 6 });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    await root.locator('.nz-it[data-view="sources"]').click();
    await expect(root.locator('[data-set="places"]')).toHaveText(/^(Orte|Places)$/);
    const sws = root.locator('[data-card="place-switches"] .sw');
    await expect(sws).toHaveCount(3);
    await expect(sws.nth(0)).toHaveAttribute('aria-checked', 'true');
    await expect(root.locator('.nz-places-phone')).toHaveText(/^(Erinnert wird auf deinem Handy, sobald es am Ort ankommt oder ihn verlässt\. Der Server erfährt nicht, wo du bist\.|Your phone reminds as soon as it arrives at the place or leaves it\. The server does not learn where you are\.)$/);
    const mine = root.locator('[data-card="places"]');
    await expect(mine.locator('.nz-place-row b')).toHaveText(['Zuhause', 'Schule', 'Baumarkt Nord']);
    await expect(mine.locator(`[data-place="p:${nord.id}"] .hint`)).toHaveText(/^Industriestraße 4, Berlin · (gemerkt für „Baumarkt“|remembered for “Baumarkt”)$/);
    await root.locator('.nz-main').evaluate((el) => { el.scrollTop = el.scrollHeight; });
    await page.screenshot({ path: test.info().outputPath('notizen-place-settings.png') });

    // a new place by its address (looked up through the server, near "Zuhause") — the hit fills latitude and longitude
    await mine.locator('[data-act="place-new"]').click();
    const ed = page.locator('.nz-dlg[data-dialog="place-edit"]');
    await ed.locator('[data-f="name"]').fill('Büro');
    await ed.locator('[data-f="address"]').fill('Ringstraße 21');
    await ed.locator('[data-act="addr-find"]').click();
    await ed.locator('[data-list="addresses"] .nz-pl-row').first().click();
    await expect(ed.locator('[data-f="lat"]')).toHaveValue('52.5012');
    await expect(ed.locator('[data-f="address"]')).toHaveValue('Ringstraße 21, 10115 Berlin');
    await ed.locator('[data-act="place-save"]').click();
    await expect(mine.locator('.nz-place-row b')).toHaveText(['Zuhause', 'Schule', 'Büro', 'Baumarkt Nord']);
    expect(posted(n, /\/api\/places\/search$/).pop().body).toEqual({ q: 'Ringstraße 21', address: true, nearFamilyId: 'home' });
    expect(posted(n, /\/api\/places$/).filter((r) => r.method === 'POST').pop().body).toEqual({ name: 'Büro', address: 'Ringstraße 21, 10115 Berlin', lat: 52.5012, lon: 13.3621, radius: 150, ref: 'osm:W900' });
    const buero = [...n.srv.state.places.values()].find((x) => x.name === 'Büro');
    // changed: the name and the radius; a point without a name is refused in the dialog
    await mine.locator(`[data-place="p:${buero.id}"] [data-act="place-edit"]`).click();
    await ed.locator('[data-f="name"]').fill('');
    await ed.locator('[data-act="place-save"]').click();
    await expect(ed.locator('.nz-err')).toHaveText(/^(Bitte einen Namen angeben\.|Please give it a name\.)$/);
    await ed.locator('[data-f="name"]').fill('Büro Mitte');
    await ed.locator('[data-f="radius"]').fill('300');
    await ed.locator('[data-act="place-save"]').click();
    await expect.poll(() => [n.srv.state.places.get(buero.id).name, n.srv.state.places.get(buero.id).radius]).toEqual(['Büro Mitte', 300]);
    await expect(mine.locator('.nz-place-row b')).toHaveText(['Zuhause', 'Schule', 'Büro Mitte', 'Baumarkt Nord']);
    // "nicht mehr merken": the place taken once leaves "Meine Orte"; an own place deleted
    await mine.locator(`[data-place="p:${nord.id}"] [data-act="place-forget"]`).click();
    await expect(mine.locator('.nz-place-row b')).toHaveText(['Zuhause', 'Schule', 'Büro Mitte']);
    expect(posted(n, /\/api\/places\/favs$/).pop().body).toEqual({ key: 'kind:diy', placeId: null });
    await mine.locator(`[data-place="p:${buero.id}"] [data-act="place-delete"]`).click();
    await expect(mine.locator('.nz-place-row b')).toHaveText(['Zuhause', 'Schule']);
    expect(n.srv.state.places.get(buero.id).deleted).toBe(true);

    // the hint "in der Nähe" off, the quiet hours changed and off — they steer the phone
    const prefs = () => posted(n, /\/api\/prefs$/).filter((r) => r.method === 'PUT').map((r) => r.body);
    await sws.nth(1).click();
    await expect.poll(() => n.srv.state.prefs.places.nearby).toBe(false);
    await root.locator('[data-card="place-switches"] input[type="time"]').first().fill('22:30');
    await root.locator('[data-card="place-switches"] input[type="time"]').first().blur();
    await expect.poll(() => n.srv.state.prefs.places.quiet).toEqual({ from: '22:30', to: '07:00' });
    await sws.nth(2).click();
    await expect.poll(() => n.srv.state.prefs.places.quiet).toBeNull();
    await expect(root.locator('[data-card="place-switches"] input[type="time"]')).toHaveCount(0);
    // the search switched off for this person: no search is offered any more, remembered places stay
    const searches = n.srv.state.placeSearches.length;
    await sws.nth(0).click();
    await expect.poll(() => n.srv.state.prefs.places.search).toBe(false);
    expect(prefs()).toEqual([{ places: { nearby: false } }, { places: { quiet: { from: '22:30', to: '07:00' } } }, { places: { quiet: null } }, { places: { search: false } }]);
    await expect(sws.nth(0)).toHaveAttribute('aria-checked', 'false');
    await root.locator('.nz-it[data-view="myday"]').click();
    const quick = root.locator('#nz-quick');
    const chip = root.locator('.nz-qchip[data-kind="place"]');
    await quick.fill('beim Baumarkt Farbe holen');
    await expect(chip).toHaveText(/^(Ort wählen|Choose a place)$/);
    await chip.locator('.nz-qbtn').click();
    const dlg = page.locator('.nz-dlg[data-dialog="place"]');
    await expect(dlg.locator('.nz-pl-search')).toBeHidden();
    await expect(dlg.locator('[data-state="search-off"]')).toHaveText(/^(Die Ortssuche im Internet ist ausgeschaltet\. Gemerkte Orte funktionieren weiter\.|The place search on the internet is switched off\. Remembered places keep working\.)$/);
    // what was chosen for the kind before is offered without a search
    await expect(dlg.locator('[data-list="mine"] .nz-pl-tx b')).toHaveText(['Zuhause', 'Schule', 'Baumarkt Nord']);
    await page.screenshot({ path: test.info().outputPath('notizen-place-search-off.png') });
    await dlg.locator(`[data-ref="p:${nord.id}"]`).click();
    await dlg.locator('[data-act="place-save"]').click();
    await expect(chip).toHaveText(/Baumarkt Nord/);
    await quick.press('Enter');
    await expect.poll(() => posted(n, /\/api\/tasks$/).length).toBe(1);
    expect(posted(n, /\/api\/tasks$/)[0].body.place).toEqual({ trigger: 'enter', key: 'kind:diy', label: 'Baumarkt', placeId: nord.id });
    expect(n.srv.state.placeSearches.length).toBe(searches);
    // switched off by the administrator: the switch says so and cannot be turned on
    n.srv.state.placeCfg.mode = 'off';
    await root.locator('.nz-it[data-view="sources"]').click();
    await expect(sws.nth(0)).toBeDisabled();
    await expect(root.locator('[data-card="place-switches"] .nz-f').first().locator('.hint')).toHaveText(/^(Vom Administrator ausgeschaltet|Switched off by the administrator)/);
  });

  test('plugin 1.5.0: a place someone else set — the push asks with "Annehmen" / "Ablehnen", the task asks in the app', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage3() });
    const lidl = n.srv.addPlace({ name: 'Lidl Marktstraße', address: 'Marktstraße 3, Berlin', lat: 52.526, lon: 13.401, named: false, ref: 'osm:N201' });
    const task = n.srv.addTask({ title: 'Milch mitbringen', due: { date: '2026-11-08', time: null } });
    const other = n.srv.addTask({ title: 'Paket abgeben', due: { date: '2026-11-08', time: null }, assigneeId: 12 });
    n.srv.setTaskPlace(task.id, { placeId: lidl.id, key: 'name:lidl', label: 'Lidl', by: 12, who: 1 });
    n.srv.setTaskPlace(other.id, { placeId: lidl.id, key: 'name:lidl', label: 'Lidl', by: 1, who: 12 });
    const topic = 'plugin:gatecontrol-notizen:shared';
    const push = (id) => ({ id, topic, title: 'Jenny Muster möchte dich erinnern', body: 'Milch mitbringen · beim Ankommen an Lidl Marktstraße', collapse_key: `place:${task.id}`,
      data: { notizen: { kind: 'place_consent', taskId: task.id, listId: 1, area: 'private', task: task.id }, actions: [{ id: 'place_accept', label: 'Annehmen', type: 'callback' }, { id: 'place_decline', label: 'Ablehnen', type: 'callback' }] } });
    mock.setPush({ topics: [{ id: topic, label: 'Notizen & Aufgaben · Geteiltes' }], items: [push(91)] });
    const { app, page, clickToast } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect(page.locator('#nav-notizen')).toBeVisible();
    await expect(page.locator('#inbox-badge')).toHaveText('1');
    // the buttons of the push are callbacks: answered from the inbox (and from the toast) without the page
    await page.locator('#nav-inbox').click();
    await page.locator('#inbox-list .inbox-row').first().click();
    await expect(page.locator('#inbox-detail .inbox-actions .btn')).toHaveText(['Annehmen', 'Ablehnen']);
    await page.locator('#inbox-detail [data-action="place_decline"]').click();
    await expect.poll(() => mock.acks().some((x) => x.action === 'place_decline')).toBe(true);
    // a second request: the toast carries the buttons; a click on the message opens the task
    mock.pushNotification(push(92));
    await expect.poll(() => app.evaluate(() => globalThis.__gcE2E.toasts.map((x) => x.text).filter((x) => x.includes('möchte dich erinnern')).length)).toBeGreaterThan(0);
    const xml = await app.evaluate(() => globalThis.__gcE2E.toasts.map((x) => x.text).filter((x) => x.includes('möchte dich erinnern')).pop());
    if (/<toast/.test(xml)) { expect(xml).toContain('Annehmen'); expect(xml).toContain('Ablehnen'); }
    expect(await clickToast('möchte dich erinnern')).toBe(true);
    await expect(page.locator('#page-notizen')).toHaveClass(/active/);
    const root = page.locator('#page-notizen');
    const d = root.locator('.nz-detail');
    await expect(d.locator('.nz-d-title')).toHaveValue('Milch mitbringen');
    // the place shows, with who is asked: this person
    await expect(d.locator('[data-act="place"]')).toHaveText(/^Lidl Marktstraße · (beim Ankommen|on arriving)$/);
    const ask = d.locator('.nz-place-hint.is-ask');
    await expect(ask).toHaveText(/^(Der Ort wurde von jemand anderem gesetzt\. Dein Handy achtet erst darauf, wenn du zustimmst\.|The place was set by someone else\. Your phone only watches it once you agree\.)/);
    await page.screenshot({ path: test.info().outputPath('notizen-place-consent.png') });
    await ask.locator('[data-act="place-accept"]').click();
    await expect.poll(() => n.srv.state.taskPlace.get(task.id).consent).toBe('accepted');
    expect(posted(n, /\/place\/consent$/).map((r) => r.body)).toEqual([{ accept: true }]);
    await expect(d.locator('.nz-place-hint.is-ask')).toHaveCount(0);
    await expect(page.locator('#toasts .toast', { hasText: /Angenommen|Accepted/ })).toBeVisible();
    // declined: the task stays, without a reminder at the place
    n.srv.state.taskPlace.get(task.id).consent = 'pending';
    await root.locator('.nz-it[data-view="planned"]').click();
    await row(root, `t:${task.id}`).click();
    await d.locator('[data-act="place-decline"]').click();
    await expect.poll(() => n.srv.state.taskPlace.get(task.id).consent).toBe('declined');
    await expect(d.locator('.nz-place-hint[data-kind="declined"]')).toBeVisible();
    // a place this person set for someone else: it waits, nobody is asked here
    await root.locator('.nz-it[data-view="planned"]').click();
    await row(root, `t:${other.id}`).click();
    await expect(d.locator('.nz-d-title')).toHaveValue('Paket abgeben');
    await expect(d.locator('.nz-place-hint[data-kind="consentWait"]')).toBeVisible();
    await expect(d.locator('[data-act="place-accept"]')).toHaveCount(0);
  });

  test('an older plugin (1.5.0): no "Wer ist dran?", no stars, no family list, nothing new asked or sent', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage3() });
    // what the server would hold stays unseen: an older plugin sends none of the new fields
    const { fam, room } = seedFamily(n);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page);
    // the list is an ordinary shared one
    const nav = root.locator(`.nz-it[data-view="list:${fam.id}"]`);
    await expect(nav).toContainText(/Familie · (geteilt|shared)/);
    await expect(nav.locator('.nz-it-mark')).toHaveCount(0);
    await nav.click();
    await expect(row(root, `t:${room.id}`)).toBeVisible();
    await expect(root.locator('.nz-mark[data-kind="turn"], .nz-mark[data-kind="stars"], .nz-mark[data-kind="doneby"]')).toHaveCount(0);
    await expect(row(root, `t:${room.id}`).locator('.nz-row-meta')).toContainText('Noah Muster');
    await row(root, `t:${room.id}`).click();
    const d = root.locator('.nz-detail');
    await expect(d.locator('.nz-d-title')).toHaveValue('Zimmer aufräumen');
    await expect(d.locator('[data-act="assignee"]')).toHaveCount(1);
    await expect(d.locator('[data-field="turn"], [data-field="stars"], [data-act="tick-for"], [data-act="not-done"]')).toHaveCount(0);
    // the quick entry: the first person as before, no choice, the line goes to the server as it is
    const quick = root.locator('#nz-quick');
    await quick.fill('@Noah @Jenny Müll rausbringen reihum 2 Sterne');
    await expect(root.locator('.nz-qchip[data-kind="person"]')).toHaveText('@Noah Muster');
    await expect(root.locator('.nz-qchip[data-kind="turn"], .nz-qchip[data-kind="stars"]')).toHaveCount(0);
    await expect(root.locator('.nz-qturn')).toBeHidden();
    await suggested(n, page, '@Noah @Jenny Müll rausbringen reihum 2 Sterne');
    await quick.press('Enter');
    await expect.poll(() => posted(n, /\/api\/tasks$/).length).toBe(1);
    expect(posted(n, /\/api\/tasks$/)[0].body).toEqual({ text: '@Noah @Jenny Müll rausbringen reihum 2 Sterne', area: 'private', createList: false, listId: fam.id });
    // ticking off sends what it always sent
    await row(root, `t:${room.id}`).locator('.nz-ck').click();
    await expect.poll(() => posted(n, /\/complete$/).map((r) => r.body)).toEqual([{ done: true }]);
    // the list can be shared and deleted here; no "Aufgaben der Familie" on "Quellen"
    await root.locator('.nz-head .nz-ib').click();
    await expect(root.locator('.nz-dlg .nz-share')).toHaveCount(1);
    await expect(root.locator('.nz-dlg .btn-danger')).toHaveCount(1);
    await expect(root.locator('.nz-dlg [data-hint="family-list"]')).toHaveCount(0);
    await page.keyboard.press('Escape');
    await root.locator('.nz-it[data-view="sources"]').click();
    await expect(root.locator('.nz-srccard').first()).toBeVisible();
    await expect(root.locator('[data-set="family"]')).toHaveCount(0);
    await expect(root.locator('[data-dlg="moved"]')).toHaveCount(0);
    expect(posted(n, /\/family\//)).toEqual([]);
  });

  test('plugin 1.6.0: "Wer ist dran?" — "reihum" from the typed line, "wer zuerst" chosen; ticked off, the next one is on', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage4() });
    const { fam, flowers } = seedFamily(n);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setLang(page);
    const root = await openNotes(page);
    const nav = root.locator(`.nz-it[data-view="list:${fam.id}"]`);
    await expect(nav.locator('.nz-it-mark')).toHaveCount(1);
    await nav.click();
    await expect(row(root, `t:${flowers.id}`).locator('.nz-mark[data-kind="turn"]')).toHaveText(/^(Wer zuerst|Whoever is first)$/);
    // the typed line: several people, "reihum", stars (a parent in the family's list) — read on this PC
    const quick = root.locator('#nz-quick');
    const line = '@Noah @Mia Spülmaschine ausräumen täglich 18 Uhr reihum 2 Sterne';
    await quick.fill(line);
    await expect(root.locator('.nz-qchip[data-kind="person"]')).toHaveText('Noah, Mia');
    await expect(root.locator('.nz-qchip[data-kind="turn"]')).toHaveText(/^(Reihum · zuerst Noah|In turns · Noah first)$/);
    await expect(root.locator('.nz-qchip[data-kind="stars"]')).toHaveText(/^2 (Sterne|stars)$/);
    const qturn = root.locator('.nz-qturn');
    await expect(qturn).toBeVisible();
    await expect(qturn.locator('button.on')).toHaveAttribute('data-turn', 'rotate');
    await expect(qturn.locator('.hint')).toHaveText(/^(Reihum: Nach dem Abhaken|In turns: after it is ticked off)/);
    await shots(page, 'notizen-turn-quick');
    await suggested(n, page, line);
    await quick.press('Enter');
    await expect.poll(() => posted(n, /\/api\/tasks$/).length).toBe(1);
    // untouched: the server reads the line as this PC did
    expect(posted(n, /\/api\/tasks$/)[0].body).toEqual({ text: line, area: 'private', createList: false, listId: fam.id });
    const dish = [...n.srv.state.tasks.values()].find((x) => x.title === 'Spülmaschine ausräumen');
    expect([dish.turn, dish.people, dish.assigneeId, dish.stars]).toEqual(['rotate', [NOAH, MIA], NOAH, 2]);
    await expect(row(root, `t:${dish.id}`).locator('.nz-mark[data-kind="turn"]')).toHaveText(/^(Reihum · Noah ist dran|In turns · Noah is on)$/);
    await expect(row(root, `t:${dish.id}`).locator('.nz-mark[data-kind="stars"]')).toHaveText(/^2 (Sterne|stars)$/);
    await expect(qturn).toBeHidden();
    // two people without a word: "Eine Person" — "Wer zuerst" chosen goes with the task
    await quick.fill('@Noah @Mia Tisch decken');
    await expect(qturn.locator('button.on')).toHaveAttribute('data-turn', 'one');
    await expect(root.locator('.nz-qchip[data-kind="turn"]')).toHaveCount(0);
    await qturn.locator('button[data-turn="first"]').click();
    await expect(root.locator('.nz-qchip[data-kind="turn"]')).toHaveText(/^(Wer zuerst|Whoever is first)$/);
    await expect(quick).toBeFocused();
    await suggested(n, page, '@Noah @Mia Tisch decken');
    await quick.press('Enter');
    await expect.poll(() => posted(n, /\/api\/tasks$/).length).toBe(2);
    expect(posted(n, /\/api\/tasks$/)[1].body).toEqual({ text: '@Noah @Mia Tisch decken', area: 'private', createList: false, turn: 'first', people: [NOAH, MIA], listId: fam.id });
    const table = [...n.srv.state.tasks.values()].find((x) => x.title === 'Tisch decken');
    expect([table.turn, table.assigneeId]).toEqual(['first', null]);
    await expect(row(root, `t:${table.id}`).locator('.nz-mark[data-kind="turn"]')).toHaveText(/^(Wer zuerst|Whoever is first)$/);

    // "reihum" ticked off (a parent ticks the child's task: for the child) — next time Mia is on
    await row(root, `t:${dish.id}`).locator('.nz-ck').click();
    await expect.poll(() => n.srv.state.tasks.get(dish.id).doneBy).toBe(NOAH);
    await expect(page.locator('#toasts .toast', { hasText: /Reihum · Mia ist dran|In turns · Mia is on/ })).toBeVisible();
    const next = [...n.srv.state.tasks.values()].find((x) => x.title === 'Spülmaschine ausräumen' && !x.doneAt);
    expect([next.assigneeId, next.due.date]).toEqual([MIA, '2026-11-09']);
    await expect(row(root, `t:${next.id}`).locator('.nz-mark[data-kind="turn"]')).toHaveText(/^(Reihum · Mia ist dran|In turns · Mia is on)$/);
    await root.locator('.nz-sec[data-id="done"] .nz-fold').click();
    await expect(row(root, `t:${dish.id}`).locator('.nz-mark[data-kind="doneby"]')).toHaveText(/^(Erledigt von Noah|Done by Noah)$/);

    // the details: "Wer zuerst" has nobody assigned; who takes part; "Reihum" and "Eine Person" chosen
    await row(root, `t:${flowers.id}`).click();
    const d = root.locator('.nz-detail');
    await expect(d.locator('.nz-d-title')).toHaveValue('Blumen gießen');
    const turn = d.locator('[data-field="turn"]');
    await expect(turn.locator('.seg button.on')).toHaveAttribute('data-turn', 'first');
    await expect(d.locator('[data-act="assignee"]')).toHaveCount(0);
    await expect(turn.locator('.nz-turn-who input:checked')).toHaveCount(3);
    await expect(turn.locator('.nz-turn-who input')).toHaveCount(4);
    await turn.scrollIntoViewIfNeeded();
    await shots(page, 'notizen-turn-detail');
    await turn.locator('button[data-turn="rotate"]').click();
    await expect.poll(() => n.srv.state.tasks.get(flowers.id).turn).toBe('rotate');
    expect(posted(n, new RegExp(`/api/tasks/${flowers.id}$`)).at(-1).body).toEqual({ turn: 'rotate', people: [12, NOAH, MIA] });
    // "reihum": the choice is who is on now, of those who take part
    const who = d.locator('[data-act="assignee"]');
    await expect(who.locator('option')).toHaveText(['Jenny Muster', 'Noah Muster', 'Mia Muster']);
    await expect(who).toHaveValue('12');
    // Jenny leaves: the two children take turns; one alone is not enough
    await turn.locator('.nz-turn-who input[data-person="12"]').uncheck();
    await expect.poll(() => n.srv.state.tasks.get(flowers.id).people).toEqual([NOAH, MIA]);
    await expect(turn.locator('.nz-turn-who input:checked')).toHaveCount(2);
    await turn.locator(`.nz-turn-who input[data-person="${MIA}"]`).click();
    await expect(page.locator('#toasts .toast', { hasText: /mindestens zwei Personen|at least two people/ })).toBeVisible();
    await expect(turn.locator('.nz-turn-who input:checked')).toHaveCount(2);
    expect(n.srv.state.tasks.get(flowers.id).people).toEqual([NOAH, MIA]);
    await turn.locator('button[data-turn="one"]').click();
    await expect.poll(() => n.srv.state.tasks.get(flowers.id).turn).toBe(null);
    expect(posted(n, new RegExp(`/api/tasks/${flowers.id}$`)).at(-1).body).toEqual({ turn: null });
    await expect(d.locator('[data-field="turn"] .nz-turn-who')).toHaveCount(0);
    await expect(d.locator('[data-field="turn"] .seg button.on')).toHaveAttribute('data-turn', 'one');
  });

  test('plugin 1.6.0: the family\'s list for a parent — stars, ticked off for a child, handed back; the list is managed by Familie; the message setting', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage4() });
    const { fam, room, rabbits } = seedFamily(n);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setLang(page);
    const root = await openNotes(page);
    await root.locator(`.nz-it[data-view="list:${fam.id}"]`).click();
    await expect(row(root, `t:${room.id}`).locator('.nz-mark[data-kind="stars"]')).toHaveText(/^2 (Sterne|stars)$/);
    // stars: a parent chooses them
    await row(root, `t:${room.id}`).click();
    const d = root.locator('.nz-detail');
    await expect(d.locator('.nz-d-title')).toHaveValue('Zimmer aufräumen');
    const stars = d.locator('[data-act="stars"]');
    await expect(stars).toHaveValue('2');
    await expect(stars.locator('option')).toHaveCount(11);
    await expect(d.locator('[data-field="stars"] .hint')).toHaveText(/Familien-Plugin|Family plugin/);
    await stars.selectOption('3');
    await expect.poll(() => n.srv.state.tasks.get(room.id).stars).toBe(3);
    expect(posted(n, new RegExp(`/api/tasks/${room.id}$`)).at(-1).body).toEqual({ stars: 3 });
    await expect(row(root, `t:${room.id}`).locator('.nz-mark[data-kind="stars"]')).toHaveText(/^3 (Sterne|stars)$/);
    await d.locator('[data-act="tick-for"]').scrollIntoViewIfNeeded();
    await shots(page, 'notizen-family-parent');
    // "Abhaken für": Mia did Noah's task — the stars are hers
    await d.locator('[data-act="tick-for"]').selectOption(String(MIA));
    await expect.poll(() => n.srv.state.tasks.get(room.id).doneBy).toBe(MIA);
    expect(posted(n, new RegExp(`/tasks/${room.id}/complete$`)).at(-1).body).toEqual({ done: true, userId: MIA });
    await expect(page.locator('#toasts .toast', { hasText: /Erledigt von Mia Muster|Done by Mia Muster/ })).toBeVisible();
    await expect(d.locator('.nz-doneby .nz-mark')).toHaveText(/^(Erledigt von Mia|Done by Mia)$/);
    await expect(d.locator('[data-act="tick-for"]')).toHaveCount(0);
    // … and back: "Noch nicht fertig"
    await d.locator('[data-act="not-done"]').click();
    await expect.poll(() => n.srv.state.tasks.get(room.id).doneAt).toBe(null);
    expect(posted(n, new RegExp(`/tasks/${room.id}/complete$`)).at(-1).body).toEqual({ done: false });
    await expect(d.locator('.nz-doneby')).toHaveCount(0);
    await expect(d.locator('[data-act="tick-for"]')).toHaveCount(1);
    // the tick in the list: a parent ticks the child's task off for the child
    await row(root, `t:${rabbits.id}`).locator('.nz-ck').click();
    await expect.poll(() => n.srv.state.tasks.get(rabbits.id).doneBy).toBe(MIA);
    expect(posted(n, new RegExp(`/tasks/${rabbits.id}/complete$`)).at(-1).body).toEqual({ done: true });

    // the list: colour and group here, the members in the Familie plugin
    await root.locator('.nz-head .nz-ib').click();
    const dlg = root.locator('.nz-dlg');
    await expect(dlg.locator('[data-hint="family-list"]')).toHaveText(/^(Die Liste der Familie verwaltet das Familien-Plugin\.|The family's list is managed by the Family plugin\.)$/);
    await expect(dlg.locator('.nz-colors')).toHaveCount(1);
    await expect(dlg.locator('.nz-share')).toHaveCount(0);
    await expect(dlg.locator('.btn-danger')).toHaveCount(0);
    await page.keyboard.press('Escape');
    expect(posted(n, /\/members$/)).toEqual([]);

    // "Quellen": the message when a child ticks off (parents only)
    await root.locator('.nz-it[data-view="sources"]').click();
    const fb = root.locator('[data-card="feedback"] [data-act="feedback"]');
    await expect(fb).toHaveValue('all');
    await expect(fb.locator('option')).toHaveText([/Bei jeder Aufgabe|For every task/, /Nur bei Aufgaben mit Sternen|Only for tasks with stars/, /^(Nie|Never)$/]);
    await root.locator('[data-set="family"]').scrollIntoViewIfNeeded();
    await page.screenshot({ path: test.info().outputPath('notizen-family-feedback.png') });
    await fb.selectOption('stars');
    await expect.poll(() => n.srv.state.prefs.feedback).toBe('stars');
    expect(posted(n, /\/api\/prefs$/).at(-1).body).toEqual({ feedback: 'stars' });
  });

  test('plugin 1.6.0: a child in the family\'s list — sees the stars, ticks off what is its, changes only what no parent made', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage4() });
    const { fam, room, rabbits, flowers } = seedFamily(n);
    n.srv.state.user = { id: NOAH, name: 'Noah Muster' };
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setLang(page);
    await expect(page.locator('#nav-notizen')).toBeVisible();
    await page.locator('#nav-notizen').click();
    const root = page.locator('#page-notizen');
    await root.locator(`.nz-it[data-view="list:${fam.id}"]`).click();
    // its own task and the one for everybody can be ticked off, Mia's cannot
    await expect(row(root, `t:${room.id}`).locator('.nz-ck')).toHaveCount(1);
    await expect(row(root, `t:${flowers.id}`).locator('.nz-ck')).toHaveCount(1);
    await expect(row(root, `t:${rabbits.id}`).locator('.nz-ck')).toHaveCount(0);
    await expect(row(root, `t:${room.id}`).locator('.nz-mark[data-kind="stars"]')).toHaveText(/^2 (Sterne|stars)$/);
    // a task a parent made: read, "Mein Tag" and the tick only
    await row(root, `t:${room.id}`).click();
    const d = root.locator('.nz-detail');
    await expect(d.locator('.nz-d-title')).toHaveValue('Zimmer aufräumen');
    await expect(d.locator('[data-hint="parents-only"]')).toHaveText(/^(Das können nur die Eltern ändern\.|Only the parents can change this\.)$/);
    await expect(d.locator('.nz-d-title')).toBeDisabled();
    await expect(d.locator('[data-field="stars"] .nz-mark')).toHaveText(/^2 (Sterne|stars)$/);
    await expect(d.locator('[data-act="stars"], [data-act="tick-for"], [data-act="not-done"], .nz-d-foot .btn-danger')).toHaveCount(0);
    await expect(d.locator('[data-field="turn"] .seg button').first()).toBeDisabled();
    await expect(d.locator('.nz-ck-lg')).toBeEnabled();
    await d.locator('[data-field="stars"]').scrollIntoViewIfNeeded();
    await shots(page, 'notizen-family-child');
    const myDay = d.locator('.nz-f[data-free] .sw');
    await expect(myDay).toBeEnabled();
    await myDay.click();
    await expect.poll(() => n.srv.state.myDay.has(room.id)).toBe(true);
    // the server refuses what the page does not offer: the star of the row
    await row(root, `t:${rabbits.id}`).locator('.nz-star').click();
    await expect(page.locator('#toasts .toast', { hasText: /Das können nur die Eltern ändern\.|Only the parents can change this\./ })).toBeVisible();
    expect(n.srv.state.tasks.get(rabbits.id).important).toBe(false);
    // a task of its own: no stars from a child — "3 Sterne" stays in the title
    const quick = root.locator('#nz-quick');
    await quick.fill('Fahrrad putzen 3 Sterne');
    await expect(root.locator('.nz-qchip[data-kind="area"]')).toBeVisible();
    await expect(root.locator('.nz-qchip[data-kind="stars"]')).toHaveCount(0);
    await quick.press('Enter');
    await expect.poll(() => [...n.srv.state.tasks.values()].some((x) => x.title === 'Fahrrad putzen 3 Sterne')).toBe(true);
    const bike = [...n.srv.state.tasks.values()].find((x) => x.title === 'Fahrrad putzen 3 Sterne');
    await row(root, `t:${bike.id}`).click();
    await expect(d.locator('.nz-d-title')).toHaveValue('Fahrrad putzen 3 Sterne');
    await expect(d.locator('.nz-d-title')).toBeEnabled();
    await expect(d.locator('[data-hint="parents-only"]')).toHaveCount(0);
    await expect(d.locator('.nz-d-foot .btn-danger')).toHaveCount(1);
    // ticking off its own task: for itself
    await row(root, `t:${room.id}`).locator('.nz-ck').click();
    await expect.poll(() => n.srv.state.tasks.get(room.id).doneBy).toBe(NOAH);
    expect(n.srv.state.feedback).toEqual([{ taskId: room.id, userId: NOAH, stars: 2 }]);
    // no setting of the parents on "Quellen"
    await root.locator('.nz-it[data-view="sources"]').click();
    await expect(root.locator('.nz-srccard').first()).toBeVisible();
    await expect(root.locator('[data-set="family"]')).toHaveCount(0);
  });

  test('plugin 1.6.0: "Umzug abgeschlossen" once; "… hat \'…\' erledigt" — "Ansehen" opens the task, "Noch nicht fertig" on the message and in the app', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage4() });
    const { fam, room } = seedFamily(n, { moved: { tasks: 12, places: 3 } });
    Object.assign(n.srv.state.tasks.get(room.id), { doneAt: n.srv.state.now, doneBy: NOAH });
    const topic = 'plugin:gatecontrol-notizen:shared';
    const push = (id) => ({ id, topic, title: 'Noah hat „Zimmer aufräumen“ erledigt', body: '2 Sterne gutgeschrieben · Familie', collapse_key: `done:${room.id}`,
      data: { notizen: { kind: 'done_feedback', taskId: room.id, listId: fam.id, area: 'private', task: room.id, userId: NOAH, stars: 2 },
        actions: [{ type: 'open_app_route', id: 'open', label: 'Ansehen', target: 'plg-gatecontrol-notizen' }, { type: 'callback', id: 'not_done', label: 'Noch nicht fertig' }] } });
    mock.setPush({ topics: [{ id: topic, label: 'Notizen & Aufgaben · Geteiltes' }], items: [push(95)] });
    const { app, page, clickToast } = await launchApp();
    await setupWithApiKey(page, mock);
    await setLang(page);
    await expect(page.locator('#nav-notizen')).toBeVisible();
    await expect(page.locator('#inbox-badge')).toHaveText('1');
    // the note of the move: once, with the numbers; "Ansehen" opens the family's list
    await page.locator('#nav-notizen').click();
    const root = page.locator('#page-notizen');
    const moved = root.locator('[data-dlg="moved"]');
    await expect(moved.locator('.nz-dlg-title')).toHaveText(/^(Umzug abgeschlossen|Move finished)$/);
    await expect(moved.locator('.nz-p')).toHaveText(/^(Aus Familie übernommen: 12 Aufgaben und 3 Orts-Erinnerungen\.|Taken over from Family: 12 tasks and 3 place reminders\.)$/);
    await expect(moved.locator('.nz-moved li')).toHaveCount(4);
    await shots(page, 'notizen-moved');
    await moved.locator('[data-act="moved-look"]').click();
    await expect.poll(() => posted(n, /\/family\/seen$/).length).toBe(1);
    await expect(moved).toHaveCount(0);
    await expect(root.locator(`.nz-it[data-view="list:${fam.id}"]`)).toHaveClass(/on/);
    // the message to the parents: the buttons in the inbox — "Noch nicht fertig" is a callback GateControl answers
    await page.locator('#nav-inbox').click();
    await page.locator('#inbox-list .inbox-row').first().click();
    await expect(page.locator('#inbox-detail .inbox-actions .btn')).toHaveText(['Ansehen', 'Noch nicht fertig']);
    await page.locator('#inbox-detail [data-action="not_done"]').click();
    await expect.poll(() => mock.acks().some((x) => x.action === 'not_done')).toBe(true);
    // a second message: the toast carries the buttons; a click on it opens the task in the app, not the portal
    const links = mock.count('/api/v1/client/portal-link');
    mock.pushNotification(push(96));
    await expect.poll(() => app.evaluate(() => globalThis.__gcE2E.toasts.map((x) => x.text).filter((x) => x.includes('Zimmer aufräumen')).length)).toBeGreaterThan(0);
    const xml = await app.evaluate(() => globalThis.__gcE2E.toasts.map((x) => x.text).filter((x) => x.includes('Zimmer aufräumen')).pop());
    if (/<toast/.test(xml)) { expect(xml).toContain('Ansehen'); expect(xml).toContain('Noch nicht fertig'); }
    expect(await clickToast('Zimmer aufräumen')).toBe(true);
    await expect(page.locator('#page-notizen')).toHaveClass(/active/);
    const d = root.locator('.nz-detail');
    await expect(d.locator('.nz-d-title')).toHaveValue('Zimmer aufräumen');
    expect(mock.count('/api/v1/client/portal-link')).toBe(links);
    await expect(root.locator('[data-dlg="moved"]')).toHaveCount(0);
    // … and in the app: "Erledigt von Noah" with the way back
    await expect(d.locator('.nz-doneby .nz-mark')).toHaveText(/^(Erledigt von Noah|Done by Noah)$/);
    await d.locator('[data-act="not-done"]').click();
    await expect.poll(() => n.srv.state.tasks.get(room.id).doneAt).toBe(null);
    await expect(page.locator('#toasts .toast', { hasText: /Zurückgegeben: Zimmer aufräumen|Handed back: Zimmer aufräumen/ })).toBeVisible();
    // the button "Ansehen" of the message does the same as the click
    await page.locator('#nav-inbox').click();
    await page.locator('#inbox-list .inbox-row').first().click();
    await page.locator('#inbox-detail [data-action="open"]').click();
    await expect(page.locator('#page-notizen')).toHaveClass(/active/);
    await expect(d.locator('.nz-d-title')).toHaveValue('Zimmer aufräumen');
    expect(posted(n, /\/family\/seen$/).length).toBe(1);
  });

  test('plugin 1.6.0: the consent for a place only for who may give it (place.canConsent)', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage4() });
    const lidl = n.srv.addPlace({ name: 'Lidl Marktstraße', address: 'Marktstraße 3, Berlin', lat: 52.526, lon: 13.401, named: false, ref: 'osm:N201' });
    // a shared list (Max and Jenny): Jenny's phone is to watch the place somebody else set — Max only sees the state.
    // Before 1.6.0 the page would have asked Max (the task is not assigned and he did not set the place)
    const theirs = n.srv.addTask({ listId: 2, title: 'Paket abgeben', due: { date: '2026-11-08', time: null } });
    n.srv.setTaskPlace(theirs.id, { placeId: lidl.id, key: 'name:lidl', label: 'Lidl', by: 15, who: 12 });
    const mine = n.srv.addTask({ listId: 2, title: 'Milch mitbringen', due: { date: '2026-11-08', time: null } });
    n.srv.setTaskPlace(mine.id, { placeId: lidl.id, key: 'name:lidl', label: 'Lidl', by: 12, who: 1 });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setLang(page);
    const root = await openNotes(page);
    await row(root, `t:${theirs.id}`).click();
    const d = root.locator('.nz-detail');
    await expect(d.locator('.nz-d-title')).toHaveValue('Paket abgeben');
    await expect(d.locator('.nz-place-hint[data-kind="consentWait"]')).toBeVisible();
    await expect(d.locator('[data-act="place-accept"], [data-act="place-decline"]')).toHaveCount(0);
    await row(root, `t:${mine.id}`).click();
    await expect(d.locator('.nz-d-title')).toHaveValue('Milch mitbringen');
    await expect(d.locator('.nz-place-hint.is-ask')).toBeVisible();
    await d.locator('[data-act="place-decline"]').click();
    await expect.poll(() => n.srv.state.taskPlace.get(mine.id).consent).toBe('declined');
    // declined by this person: the way back stays with them
    await expect(d.locator('.nz-place-hint[data-kind="declined"] [data-act="place-accept"]')).toBeVisible();
    await d.locator('[data-act="place-accept"]').click();
    await expect.poll(() => n.srv.state.taskPlace.get(mine.id).consent).toBe('accepted');
    await expect(d.locator('.nz-place-hint.is-ask')).toHaveCount(0);
    expect(posted(n, /\/place\/consent$/).map((r) => [r.path.includes(`/tasks/${mine.id}/`), r.body])).toEqual([[true, { accept: false }], [true, { accept: true }]]);
  });
  test('plugin 1.6.0 (no word of 1.7.0): a task of a deadline in Drive is a task like any other — no "Frist", no hint when it is deleted', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage4() });
    const d = await mock.setDrive({ features: ['docAi'] });
    const { task } = seedDeadline(n, d, null);
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setLang(page);
    const root = await openNotes(page);
    await root.locator('.nz-it[data-view="list:1"]').click();
    const r = row(root, `t:${task.id}`);
    await expect(r.locator('.nz-row-title')).toHaveText('Kfz-Versicherung kündigen');
    await expect(r.locator('.nz-row-meta-tx')).toHaveCount(0);
    await expect(r.locator('.nz-src')).toHaveText('Drive');
    await r.click();
    const det = root.locator('.nz-detail');
    await expect(det.locator('.nz-d-title')).toHaveValue('Kfz-Versicherung kündigen');
    await expect(det.locator('[data-box="deadline"], [data-hint="deadline-delete"], [data-act="open-file"]')).toHaveCount(0);
    await det.locator('.nz-d-foot .btn-danger').click();
    await expect.poll(() => n.srv.state.tasks.get(task.id).deleted).toBe(true);
    await expect(page.locator('#toasts .toast').last()).toHaveText(/^(Gelöscht\.|Deleted\.)$/);
    // Drive that names nobody: no "über Notizen & Aufgaben"
    await page.locator('#nav-drive').click();
    const drive = page.locator('#page-drive');
    await drive.locator('.dv-tool[data-view="deadlines"]').click();
    await expect(drive.locator('.dv-dl-remind')).toHaveValue('3');
    await expect(drive.locator('.dv-dl-by')).toBeHidden();
  });

  test('plugin 1.7.0: a task that reminds of a deadline in Drive — the row, the details, "Datei öffnen" on the Drive page, what deleting means', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage5() });
    const d = await mock.setDrive({ features: ['docAi', 'deadlineHub'] });
    const { dl, task } = seedDeadline(n, d, 'notizen');
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setLang(page);
    const root = await openNotes(page);
    await root.locator('.nz-it[data-view="list:1"]').click();
    // the row: the source, "Frist …", the file, how many days before
    const r = row(root, `t:${task.id}`);
    await expect(r.locator('.nz-src')).toHaveText('Drive');
    await expect(r.locator('.nz-row-meta-tx')).toHaveText(/^(Frist Mo\. 30\. Nov\. · Brief\.pdf · 3 Tage vorher|Deadline Mon 30\. Nov · Brief\.pdf · 3 days before)$/);
    // every other task: nothing of it
    await expect(row(root, 't:12').locator('.nz-row-meta')).not.toHaveText(/Frist|Deadline/);
    // the details
    await r.click();
    const det = root.locator('.nz-detail');
    const box = det.locator('[data-box="deadline"]');
    await expect(box.locator('.nz-from b')).toHaveText(/^(Aus Drive|From Drive)$/);
    await expect(box.locator('.nz-from-tx')).toHaveText(/^Brief\.pdf · (Datei öffnen|Open file)$/);
    await expect(box.locator('[data-kind="deadline"]')).toHaveText(/^(Frist Mo\. 30\. Nov\. · 3 Tage vorher|Deadline Mon 30\. Nov · 3 days before)$/);
    await expect(box.locator('[data-hint="deadline"]')).toHaveText(/^(Die Frist steht an der Datei in Drive\. Wie viele Tage vorher erinnert wird, stellst du dort ein; „Erledigt“ hakt sie auch in Drive ab\.|The deadline belongs to the file in Drive\. How many days before you are reminded is set there; “Done” ticks it off in Drive too\.)$/);
    await expect(det.locator('[data-hint="deadline-delete"]')).toHaveText(/^(Löschen entfernt die Erinnerung an diese Frist\. Die Frist bleibt in Drive\.|Deleting removes the reminder of this deadline\. The deadline stays in Drive\.)$/);
    await shots(page, 'notizen-deadline');
    await det.locator('[data-hint="deadline-delete"]').scrollIntoViewIfNeeded();
    await shots(page, 'notizen-deadline-delete');
    // it is a task: the reminder time and "Erledigt" are the task's
    await expect(det.locator('.nz-d-title')).toBeEnabled();
    await expect(det.locator('.nz-ck-lg')).toBeEnabled();
    // "Datei öffnen": the file on the Drive page of this app, not the portal
    const links = mock.count('/api/v1/client/portal-link');
    await box.locator('[data-act="open-file"]').click();
    await expect(page.locator('#page-drive')).toHaveClass(/active/);
    const dlg = page.locator('.dv-dlg.dv-docs');
    await expect(dlg.locator('.dv-dlg-h')).toHaveText(/Brief\.pdf/);
    expect(mock.count('/api/v1/client/portal-link')).toBe(links);
    // Drive's "Details": the reminder is rung by "Notizen & Aufgaben"
    await expect(dlg.locator('.dv-dl-remind')).toHaveValue('3');
    await expect(dlg.locator('.dv-dl-by')).toHaveText(/^(über Notizen & Aufgaben|through Notes & Tasks)$/);
    await shots(page, 'drive-deadline-details');
    await dlg.locator('.dv-dlg-foot .btn-pri').click();
    // "Fristen": the same; a reminder set while Drive reminds itself says nothing; removed: nothing either
    const drive = page.locator('#page-drive');
    await drive.locator('.dv-tool[data-view="deadlines"]').click();
    await expect(drive.locator('.dv-dl-by')).toHaveText(/^(über Notizen & Aufgaben|through Notes & Tasks)$/);
    await shots(page, 'drive-deadlines-by-hub');
    d.srv.remindBy = 'drive';
    await drive.locator('.dv-dl-remind').selectOption('7');
    await expect.poll(() => dl.reminder && dl.reminder.daysBefore).toBe(7);
    await expect(drive.locator('.dv-dl-by')).toBeHidden();
    d.srv.remindBy = 'notizen';
    await drive.locator('.dv-dl-remind').selectOption('14');
    await expect(drive.locator('.dv-dl-by')).toBeVisible();
    await drive.locator('.dv-dl-remind').selectOption('');
    await expect.poll(() => dl.reminder).toBe(null);
    await expect(drive.locator('.dv-dl-by')).toBeHidden();
    // back at the task: deleting it says what that means
    await page.locator('#nav-notizen').click();
    await row(root, `t:${task.id}`).click();
    await det.locator('.nz-d-foot .btn-danger').click();
    await expect.poll(() => n.srv.state.tasks.get(task.id).deleted).toBe(true);
    await expect(page.locator('#toasts .toast').last()).toHaveText(/^(Gelöscht\. Die Erinnerung an diese Frist ist entfernt, die Frist bleibt in Drive\.|Deleted\. The reminder of this deadline is removed, the deadline stays in Drive\.)$/);
    await expect(row(root, `t:${task.id}`)).toHaveCount(0);
    // nothing new was asked of the hub: no route of 1.7.0 exists
    expect(posted(n, /\/api\/(reminders|deadlines)/).length).toBe(0);
  });

  test('plugin 1.7.0: the reminder of a deadline — four buttons; "Datei öffnen" opens the file on the Drive page, a click the task', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage5() });
    const d = await mock.setDrive({ features: ['docAi', 'deadlineHub'] });
    const { task } = seedDeadline(n, d, 'notizen');
    const p = n.srv.reminderPush(task.id);
    const push = (id) => ({ id, topic: p.topic, title: p.title, body: p.body, collapse_key: p.collapseKey, data: p.data });
    mock.setPush({ topics: [{ id: p.topic, label: 'Notizen & Aufgaben · Erinnerungen' }], items: [push(97)] });
    const { app, page, clickToast } = await launchApp();
    await setupWithApiKey(page, mock);
    await setLang(page);
    await expect(page.locator('#nav-notizen')).toBeVisible();
    await expect(page.locator('#nav-drive')).toBeVisible();
    await expect(page.locator('#inbox-badge')).toHaveText('1');
    await page.locator('#nav-inbox').click();
    await page.locator('#inbox-list .inbox-row').first().click();
    await expect(page.locator('#inbox-detail')).toContainText('Frist in 3 Tagen: Kfz-Versicherung kündigen');
    await expect(page.locator('#inbox-detail')).toContainText('Kündigung bis 30.11.2026 · Brief.pdf');
    await expect(page.locator('#inbox-detail .inbox-actions .btn')).toHaveText(['Erledigt', 'In 1 Std.', 'Heute Abend', 'Datei öffnen']);
    await shots(page, 'inbox-deadline-reminder');
    // the fourth button: the file on the Drive page — no portal link is asked for
    const links = mock.count('/api/v1/client/portal-link');
    await page.locator('#inbox-detail [data-action="open_file"]').click();
    await expect(page.locator('#page-drive')).toHaveClass(/active/);
    await expect(page.locator('.dv-dlg.dv-docs .dv-dlg-h')).toHaveText(/Brief\.pdf/);
    expect(mock.count('/api/v1/client/portal-link')).toBe(links);
    expect(await app.evaluate(() => globalThis.__gcE2E.events.filter((e) => e.type === 'shell.openExternal').length)).toBe(0);
    await expect.poll(() => mock.acks().some((x) => x.action === 'open_file')).toBe(true);
    await page.locator('.dv-dlg.dv-docs .dv-dlg-foot .btn-pri').click();
    // "Erledigt" stays the callback GateControl answers
    await page.locator('#nav-inbox').click();
    await page.locator('#inbox-list .inbox-row').first().click();
    await page.locator('#inbox-detail [data-action="done"]').click();
    await expect.poll(() => mock.acks().some((x) => x.action === 'done')).toBe(true);
    // a second reminder: the toast carries the four buttons; a click on it opens the task
    mock.pushNotification(push(98));
    await expect.poll(() => app.evaluate(() => globalThis.__gcE2E.toasts.map((x) => x.text).filter((x) => x.includes('Kfz-Versicherung')).length)).toBeGreaterThan(0);
    const xml = await app.evaluate(() => globalThis.__gcE2E.toasts.map((x) => x.text).filter((x) => x.includes('Kfz-Versicherung')).pop());
    if (/<toast/.test(xml)) { expect(xml).toContain('Datei öffnen'); expect(xml).toContain('Heute Abend'); }
    expect(await clickToast('Kfz-Versicherung')).toBe(true);
    await expect(page.locator('#page-notizen')).toHaveClass(/active/);
    await expect(page.locator('#page-notizen .nz-detail .nz-d-title')).toHaveValue('Kfz-Versicherung kündigen');
    await expect(page.locator('#page-notizen .nz-detail [data-box="deadline"]')).toBeVisible();
  });

  test('plugin 1.7.0 without Drive in the app: "Datei öffnen" of the reminder stays the portal link the server sent — no page of the app opens', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage5() });
    const task = n.srv.addDeadline({ title: 'Kfz-Versicherung kündigen', date: '2026-11-30', kind: 'cancellation', file: 'Brief.pdf', daysBefore: 3, nodeId: 12 });
    const p = n.srv.reminderPush(task.id);
    mock.setPush({ topics: [{ id: p.topic, label: 'Notizen & Aufgaben · Erinnerungen' }], items: [{ id: 97, topic: p.topic, title: p.title, body: p.body, collapse_key: p.collapseKey, data: p.data }] });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect(page.locator('#nav-notizen')).toBeVisible();
    await expect(page.locator('#nav-drive')).toBeHidden();
    await page.locator('#nav-inbox').click();
    await page.locator('#inbox-list .inbox-row').first().click();
    await page.locator('#inbox-detail [data-action="open_file"]').click();
    // the button is answered as the portal link it is (the mock server names no portal address, so no browser opens
    // here — that the path goes to the portal unchanged is the core's test); no page of the app claims it
    await expect.poll(() => mock.acks().some((x) => x.action === 'open_file')).toBe(true);
    await expect(page.locator('#page-inbox')).toHaveClass(/active/);
    await expect(page.locator('#page-drive')).not.toHaveClass(/active/);
    await expect(page.locator('#page-notizen')).not.toHaveClass(/active/);
    expect(await app.evaluate(() => globalThis.__gcE2E.events.filter((e) => e.type === 'shell.openExternal').length)).toBe(0);
  });

  test('a list the person only reads: no quick entry, its tasks are shown but not changed; what is assigned to them is ticked off', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: stage5() });
    Object.assign(n.srv.state.lists.get(2), { ownerId: 12, readers: [1] });
    const hedge = n.srv.addTask({ listId: 2, title: 'Hecke schneiden' });
    const leaves = n.srv.addTask({ listId: 2, title: 'Laub rechen', assigneeId: 1 });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setLang(page);
    const root = await openNotes(page);
    await root.locator('.nz-it[data-view="list:2"]').click();
    await expect(row(root, `t:${hedge.id}`)).toBeVisible();
    await expect(root.locator('[data-hint="read-only"]')).toHaveText(/^(Du kannst diese Liste ansehen, aber nicht ändern\.|You can look at this list but not change it\.)$/);
    await expect(root.locator('#nz-quick')).toHaveCount(0);
    await expect(row(root, `t:${hedge.id}`).locator('.nz-ck')).toHaveCount(0);
    await expect(row(root, `t:${leaves.id}`).locator('.nz-ck')).toHaveCount(1);
    await row(root, `t:${hedge.id}`).click();
    const det = root.locator('.nz-detail');
    await expect(det.locator('.nz-d-title')).toHaveValue('Hecke schneiden');
    await expect(det.locator('.nz-d-title')).toBeDisabled();
    await expect(det.locator('[data-hint="read-only"]')).toHaveText(/^(In dieser Liste darfst du nur lesen\.|You may only read in this list\.)$/);
    await expect(det.locator('.nz-d-foot .btn-danger')).toHaveCount(0);
    await expect(det.locator('.nz-ck-lg')).toBeDisabled();
    await shots(page, 'notizen-read-only-list');
    // nothing was sent that the server would have refused
    expect(n.srv.state.requests.filter((q) => /^(POST|PATCH|DELETE)$/.test(q.method) && /\/api\/tasks/.test(q.path)).length).toBe(0);
    // what is assigned to the person is ticked off
    await row(root, `t:${leaves.id}`).locator('.nz-ck').click();
    await expect.poll(() => !!n.srv.state.tasks.get(leaves.id).doneAt).toBe(true);
    // a list the person writes in keeps the quick entry
    await root.locator('.nz-it[data-view="list:1"]').click();
    await expect(root.locator('#nz-quick')).toBeVisible();
    await expect(root.locator('[data-hint="read-only"]')).toHaveCount(0);
  });
});
