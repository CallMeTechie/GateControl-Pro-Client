'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Drucken (plugin gatecontrol-print, "Drucken & Scannen"): the entry only
// while the server offers the plugin to the apps; the page with the drop
// area, the printers and the jobs (stations, stop and wait reasons, "noch
// bis …"), the print dialog (only what the printer can, the printer used
// last, page limit, office hint), a file of this PC through the file dialog
// and through a drop, files of Drive (row menu, selection, Strg+P, viewer),
// open jobs followed until they end, "Abbrechen", "Erneut drucken", the
// states (no printer, no right, not available, no connection) and the print
// pushes. Selectors by id/class; texts in both languages.

// Wednesday, 11 November 2026, 17:52 — in the runner's own time zone, so the clock times shown do not depend on it
const NOW = new Date(2026, 10, 11, 17, 52, 10).getTime();
const at = (hhmm, day = 11) => { const [h, m] = hhmm.split(':').map(Number); return new Date(2026, 10, day, h, m, 0).toISOString(); };

const HP = 'u:0a1b2c3d4e5f60718293a4b5c6d7e8f9';
const BROTHER = 'h:1234567890abcdef';

function printers() {
  return [
    {
      id: HP, name: 'HP OfficeJet 8020', location: 'Wohnzimmer', online: true, problem: null,
      printer: {
        state: 'idle', color: true, duplex: true, copiesMax: 99, formats: ['image/urf', 'image/jpeg'], office: true,
        media: { sizes: ['iso_a4_210x297mm', 'iso_a5_148x210mm', 'na_index-4x6_4x6in'], default: 'iso_a4_210x297mm', sources: ['main', 'photo'], sourceDefault: 'main' },
      },
      scanner: null,
    },
    {
      id: BROTHER, name: 'Brother HL-L2350DW', location: 'Arbeitszimmer', online: false, problem: null,
      printer: { state: 'offline', color: false, duplex: true, copiesMax: 99, formats: ['application/pdf'], office: false, media: { sizes: ['iso_a4_210x297mm'], default: 'iso_a4_210x297mm', sources: ['main'], sourceDefault: 'main' } },
      scanner: null,
    },
  ];
}

const job = (id, name, state, extra = {}) => ({
  id, device: 'HP OfficeJet 8020', deviceId: HP, name, pages: 1, copies: 1, color: true, duplex: false, media: null, source: null, state, error: null, message: null,
  at: at('17:49'), updatedAt: at('17:50'), expiresAt: at('17:49', 12), doneAt: null, ...extra,
});

function jobs() {
  return [
    job('j1', 'Stromrechnung 2026-10.pdf', 'printing', { pages: 2, duplex: true, message: 'media-empty', at: at('17:49'), expiresAt: at('17:49', 12) }),
    job('j2', 'Elternbrief Klassenfahrt.pdf', 'waiting', { device: 'Brother HL-L2350DW', deviceId: BROTHER, copies: 18, color: false, error: 'printer_offline', at: at('17:41'), expiresAt: at('17:41', 12) }),
    job('j3', 'Urlaub Ostsee 014.jpg', 'failed', { error: 'printer_rejected', media: 'na_index-4x6_4x6in', source: 'photo', at: at('16:20'), doneAt: at('16:20') }),
    job('j4', 'Packliste <b>Skifreizeit</b>.txt', 'done', { color: false, at: at('09:41'), doneAt: at('09:41') }),
    job('j5', 'Mietvertrag Scan.pdf', 'canceled', { device: 'Brother HL-L2350DW', deviceId: BROTHER, pages: 6, color: false, at: at('20:12', 10), doneAt: at('20:12', 10) }),
  ];
}

function setPrint(mock, over = {}) {
  const pr = mock.setPrint({ rights: { print: true, scan: true, pagesPerDay: 20, bwOnly: false }, pagesLeft: 14, printers: printers(), jobs: jobs(), ...over });
  return pr;
}

/** The app's clock for the page (job times relative to "now" of the mockup). */
async function freeze(page) {
  await page.addInitScript((now) => {
    const RealDate = Date;
    const offset = now - RealDate.now();
    // eslint-disable-next-line no-global-assign
    Date = class extends RealDate {
      constructor(...a) { if (a.length) super(...a); else super(RealDate.now() + offset); }
      static now() { return RealDate.now() + offset; }
    };
  }, NOW);
}

/** The language the screenshots are taken in (GC_PRINT_LANG=de|en); the assertions hold in both. */
const LANG = process.env.GC_PRINT_LANG || '';
const setLang = (page) => (LANG ? page.evaluate((l) => window.gatecontrol.locale.set(l), LANG) : Promise.resolve());

async function openPrint(page, mock) {
  await setupWithApiKey(page, mock);
  await setLang(page);
  await expect(page.locator('#nav-drucken')).toBeVisible();
  await page.locator('#nav-drucken').click();
  await expect(page.locator('#page-drucken')).toHaveClass(/active/);
  return page.locator('#page-drucken');
}

const rowOf = (root, id) => root.locator(`.pv-job[data-id="${id}"]`);
const sent = (pr, method, route) => pr.log.filter((r) => r.method === method && r.route === route);
const dlg = (page) => page.locator('.pv-scrim:not([hidden]) .pv-dlg');
const SHOTS = process.env.GC_PRINT_SHOTS || '';
async function shot(page, name) {
  await page.screenshot({ path: test.info().outputPath(`${name}.png`) });
  if (SHOTS) await page.screenshot({ path: path.join(SHOTS, `${name}.png`) });
}
const theme = (page, th) => page.evaluate((x) => { if (x === 'light') document.documentElement.setAttribute('data-theme', 'light'); else document.documentElement.removeAttribute('data-theme'); }, th);

function tmpFile(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-e2e-print-'));
  const file = path.join(dir, name);
  fs.writeFileSync(file, content);
  return file;
}
const PDF2 = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>\nendobj\n%%EOF\n', 'latin1');
const DOCX = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(200, 7)]);

test.describe('drucken', () => {
  test('no plugin for the apps: no "Drucken" entry, nothing in Drive\'s menu', async ({ launchApp, mock }) => {
    await mock.setDrive({ features: ['bulk'] });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.count('/api/v1/client/plugins')).toBeGreaterThan(0);
    await expect(page.locator('#nav-drive')).toBeVisible();
    await expect(page.locator('#nav-drucken')).toBeHidden();
    await page.locator('#nav-drive').click();
    await page.locator('#page-drive .dv-pages [data-page="files"]').click();
    await page.locator('#page-drive .dv-row[data-id="11"]').click({ button: 'right' });
    await expect(page.locator('.dv-menu')).toBeVisible();
    await expect(page.locator('.dv-menu [data-item="print"]')).toHaveCount(0);
  });

  test('the page: drop area, printers, the jobs with their stations and reasons', async ({ launchApp, mock }) => {
    const pr = setPrint(mock);
    const { app, page } = await launchApp();
    await freeze(page);
    await page.reload();
    const root = await openPrint(page, mock);
    await expect(root.locator('.pv-h')).toHaveText(/^(Drucken|Print)$/);
    await expect(root.locator('.pv-drop')).toContainText(/14 von 20|14 of 20/);
    await expect(root.locator('.pv-prn')).toHaveCount(2);
    await expect(root.locator(`.pv-prn[data-printer="${HP}"] .pv-chip`)).toHaveClass(/is-ok/);
    await expect(root.locator(`.pv-prn[data-printer="${BROTHER}"] .pv-chip`)).toHaveClass(/is-mute/);
    await expect(root.locator('.pv-job')).toHaveCount(5);
    await expect(root.locator('[data-jobs-sub]')).toHaveText(/^(2 offen|2 open) · /);
    // the entry's number: the open jobs
    await expect(page.locator('#print-badge')).toHaveText('2');

    // stopped at the printer: the reason, station 3 on hold, "Abbrechen"
    const stopped = rowOf(root, 'j1');
    await expect(stopped).toHaveClass(/is-warn/);
    await expect(stopped.locator('.pv-chip')).toHaveText(/Angehalten|Stopped/);
    await expect(stopped.locator('.pv-why')).toHaveText(/Papier fehlt|Out of paper/);
    await expect(stopped.locator('.pv-steps i')).toHaveCount(4);
    await expect(stopped.locator('.pv-steps i.is-hold')).toHaveCount(1);
    await expect(stopped.locator('.pv-steps')).toHaveAttribute('aria-label', /3 (von|of) 4/);
    await expect(stopped.locator('[data-act="cancel"]')).toBeVisible();
    // waiting for the printer: until when (plugin 1.1.1 expiresAt)
    const waiting = rowOf(root, 'j2');
    await expect(waiting.locator('.pv-chip')).toHaveText(/Wartet|Waiting/);
    await expect(waiting.locator('.pv-why')).toHaveText(/(noch bis morgen, 17:41 Uhr|until tomorrow, 17:41)/);
    await expect(waiting.locator('.pv-meta')).toHaveText(/Brother HL-L2350DW · (1 Seite × 18 Kopien|1 page × 18 copies)/);
    await expect(waiting.locator('.pv-steps i.is-current')).toHaveCount(1);
    // failed: the reason, no stations; the file is not known here → no "Erneut drucken"
    const failed = rowOf(root, 'j3');
    await expect(failed).toHaveClass(/is-err/);
    await expect(failed.locator('.pv-why')).toHaveText(/abgelehnt|refused/);
    await expect(failed.locator('.pv-meta')).toHaveText(/(Foto 10 × 15 cm, Fotofach|Photo 4 × 6 in, Photo tray)/);
    await expect(failed.locator('.pv-steps')).toHaveCount(0);
    await expect(failed.locator('.btn')).toHaveCount(0);
    // server text is text
    await expect(rowOf(root, 'j4').locator('.pv-job-n b')).toHaveText('Packliste <b>Skifreizeit</b>.txt');
    await expect(rowOf(root, 'j4').locator('.pv-steps')).toHaveCount(0);
    await expect(rowOf(root, 'j5').locator('.pv-meta')).toHaveText(/(gestern, 20:12|yesterday, 20:12)/);
    await expect(root.locator('.pv-foot')).toContainText(/(letzten 5 Aufträge|last 5 jobs)/);
    await expect(page.locator('.toast-error')).toHaveCount(0);
    await shot(page, '01-seite-dunkel');
    await theme(page, 'light');
    await shot(page, '01-seite-hell');
    // a narrow window: nothing runs out of the page
    const size = await app.evaluate(({ BrowserWindow }) => { const w = BrowserWindow.getAllWindows()[0]; const b = w.getSize(); w.setMinimumSize(400, 400); w.setSize(760, 760); return b; });
    await expect.poll(() => page.evaluate(() => window.innerWidth)).toBeLessThan(800);
    expect(await page.evaluate(() => { const b = document.querySelector('#page-drucken .pv-body'); return b.scrollWidth <= b.clientWidth + 1; })).toBe(true);
    await shot(page, '01c-seite-schmal-hell');
    await app.evaluate(({ BrowserWindow }, b) => BrowserWindow.getAllWindows()[0].setSize(b[0], b[1]), size);
    await theme(page, 'dark');

    // open jobs are asked for one by one — the finished ones never
    await expect.poll(() => sent(pr, 'GET', 'jobs/j1').length, { timeout: 20000 }).toBeGreaterThan(0);
    expect(sent(pr, 'GET', 'jobs/j3').length + sent(pr, 'GET', 'jobs/j4').length + sent(pr, 'GET', 'jobs/j5').length).toBe(0);
    // the printer got its paper: the job ends, the list and the number follow without a reload
    pr.setJob('j1', { state: 'done', message: null, doneAt: new Date(NOW + 60000).toISOString() });
    await expect(rowOf(root, 'j1').locator('.pv-chip')).toHaveText(/^(Gedruckt|Printed)$/, { timeout: 30000 });
    await expect(page.locator('#print-badge')).toHaveText('1');

    // "Abbrechen" of the waiting job
    await rowOf(root, 'j2').locator('[data-act="cancel"]').click();
    await expect(rowOf(root, 'j2').locator('.pv-chip')).toHaveText(/Abgebrochen|Canceled/);
    expect(sent(pr, 'POST', 'jobs/j2/cancel')).toHaveLength(1);
    await expect(page.locator('#print-badge')).toBeHidden();
    // nothing open any more: nothing is asked for
    const n = pr.log.filter((r) => r.route.startsWith('jobs/')).length;
    await page.waitForTimeout(7000);
    expect(pr.log.filter((r) => r.route.startsWith('jobs/')).length).toBe(n);
  });

  test('a file of this PC: the dialog shows what the printer can, the upload, the job; the printer used last comes first', async ({ launchApp, mock }) => {
    const pr = setPrint(mock, { jobs: [] });
    const { page, answerOpenDialogs, dialogs } = await launchApp();
    const root = await openPrint(page, mock);
    await expect(root.locator('.pv-empty')).toBeVisible();
    const file = tmpFile('Stromrechnung 2026-10.pdf', PDF2);
    await answerOpenDialogs([file]);
    await root.locator('.pv-pick').click();
    const d = dlg(page);
    await expect(d).toBeVisible();
    await expect(d).toHaveAttribute('role', 'dialog');
    await expect(d).toHaveAttribute('aria-modal', 'true');
    await expect(d.locator('.pv-dlg-h')).toHaveText(/Zu Hause drucken|Print at home/);
    await expect(d.locator('.pv-file-tx b')).toHaveText('Stromrechnung 2026-10.pdf');
    await expect(d.locator('.pv-file-tx span')).toHaveText(/PDF · (2 Seiten|2 pages) · .* · (vom PC|from this PC)/);
    // the printers as radio buttons: the ready one is chosen, the focus is on it
    await expect(d.locator('[role="radiogroup"] [role="radio"]')).toHaveCount(2);
    await expect(d.locator(`[data-k="prn:${HP}"]`)).toHaveAttribute('aria-checked', 'true');
    await expect(d.locator(`[data-k="prn:${HP}"]`)).toBeFocused();
    await expect(d.locator(`[data-k="prn:${BROTHER}"] .pv-opt-tx span`)).toHaveText(/(druckt, sobald er an ist|prints as soon as it is on)/);
    // HP: colour, double-sided, three papers, two trays
    await expect(d.locator('[data-k="color-on"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(d.locator('[data-k="duplex"]')).toHaveAttribute('aria-checked', 'false');
    await expect(d.locator('[data-k="paper"] option')).toHaveCount(3);
    await expect(d.locator('[data-k="tray"] option')).toHaveCount(2);
    await expect(d.locator('.pv-left')).toHaveText(/(Heute noch 14 von 20 Seiten|14 of 20 pages left today)/);
    await expect(d.locator('[data-k="submit"]')).toBeEnabled();
    await shot(page, '02-dialog-dunkel');
    await theme(page, 'light');
    await shot(page, '02-dialog-hell');
    await theme(page, 'dark');

    // keyboard: arrows move the choice of the printer; Tab stays in the dialog
    await page.keyboard.press('ArrowDown');
    await expect(d.locator(`[data-k="prn:${BROTHER}"]`)).toHaveAttribute('aria-checked', 'true');
    await expect(d.locator(`[data-k="prn:${BROTHER}"]`)).toBeFocused();
    // the Brother prints black and white, has one paper and one tray: only what it can
    await expect(d.locator('[data-k="color-on"]')).toBeDisabled();
    await expect(d.locator('[data-k="color-off"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(d.locator('[data-color-hint]')).toHaveText(/schwarz-weiß|black and white/);
    await expect(d.locator('[data-k="paper"]')).toBeDisabled();
    await expect(d.locator('[data-k="tray"]')).toHaveCount(0);
    await page.keyboard.press('ArrowUp');
    await expect(d.locator(`[data-k="prn:${HP}"]`)).toBeFocused();
    await page.keyboard.press('Shift+Tab');
    await expect(d.locator('[data-k="submit"]')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(d.locator(`[data-k="prn:${HP}"]`)).toBeFocused();

    // the page limit: 2 pages × 8 copies are more than the 14 left
    await d.locator('[data-k="copies"]').fill('8');
    await expect(d.locator('[data-banner="limit"]')).toHaveText(/(Das wären 16 Seiten – heute gehen noch 14|That would be 16 pages – 14 left today)/);
    await expect(d.locator('[data-k="submit"]')).toBeDisabled();
    await d.locator('[data-k="less"]').click();
    await expect(d.locator('[data-k="copies"]')).toHaveValue('7');
    await expect(d.locator('[data-banner="limit"]')).toHaveCount(0);
    await d.locator('[data-k="copies"]').fill('3');
    await d.locator('[data-k="color-off"]').click();
    await d.locator('[data-k="duplex"]').click();
    await expect(d.locator('[data-k="duplex"]')).toHaveAttribute('aria-checked', 'true');
    await d.locator('[data-k="paper"]').selectOption('iso_a5_148x210mm');
    await d.locator('[data-k="tray"]').selectOption('photo');
    await d.locator('[data-k="submit"]').click();
    await expect(page.locator('.pv-scrim')).toBeHidden();

    // uploaded as a PDF, then POST print with exactly these options — and it is a job with its stations
    await expect.poll(() => sent(pr, 'POST', 'print').length).toBe(1);
    expect(pr.uploads).toHaveLength(1);
    expect(pr.uploads[0]).toMatchObject({ mime: 'application/pdf', bytes: PDF2.length });
    expect(pr.uploads[0].head.startsWith('%PDF-1.4')).toBe(true);
    expect(sent(pr, 'POST', 'print')[0].body).toEqual({ deviceId: HP, copies: 3, color: false, duplex: true, media: 'iso_a5_148x210mm', source: 'photo', mediaId: pr.uploads[0].mediaId, name: 'Stromrechnung 2026-10.pdf' });
    const row = rowOf(root, 'job1');
    await expect(row).toBeVisible();
    await expect(row.locator('.pv-chip')).toHaveText(/(Unterwegs nach Hause|On its way home)/);
    await expect(row.locator('.pv-steps i.is-current')).toHaveCount(1);
    await expect(page.locator('#print-badge')).toHaveText('1');
    await expect(root.locator('.pv-drop')).toContainText(/11 (von|of) 20/);
    // the file dialog was the main process' own, asked once
    expect((await dialogs()).length).toBe(0);

    // the next dialog starts with what was used last (not the copies)
    pr.setJob('job1', { state: 'done', doneAt: new Date().toISOString() });
    await answerOpenDialogs([file]);
    await root.locator('.pv-pick').click();
    await expect(d.locator('[data-k="copies"]')).toHaveValue('1');
    await expect(d.locator('[data-k="color-off"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(d.locator('[data-k="duplex"]')).toHaveAttribute('aria-checked', 'true');
    await expect(d.locator('[data-k="paper"]')).toHaveValue('iso_a5_148x210mm');
    await expect(d.locator('[data-k="tray"]')).toHaveValue('photo');
    // Escape closes it, nothing is sent, the focus goes back to the button
    await page.keyboard.press('Escape');
    await expect(page.locator('.pv-scrim')).toBeHidden();
    await expect(root.locator('.pv-pick')).toBeFocused();
    expect(sent(pr, 'POST', 'print')).toHaveLength(1);
    expect(pr.uploads).toHaveLength(1);
  });

  test('office file, printer off, refusals of the server; what cannot be printed is said; "Erneut drucken"', async ({ launchApp, mock }) => {
    const pr = setPrint(mock, { jobs: [] });
    const { page, answerOpenDialogs } = await launchApp();
    const root = await openPrint(page, mock);
    const d = dlg(page);
    // not a type the plugin prints: no dialog, the reason
    await answerOpenDialogs([tmpFile('setup.exe', 'MZ')]);
    await root.locator('.pv-pick').click();
    await expect(page.locator('.toast-error')).toContainText(/setup\.exe/);
    await expect(page.locator('.pv-scrim')).toBeHidden();
    // a "PDF" that is none
    await answerOpenDialogs([tmpFile('Getarnt.pdf', Buffer.from([0x4d, 0x5a, 0x00, 0x01]))]);
    await root.locator('.pv-pick').click();
    await expect(page.locator('.toast-error').last()).toContainText(/Getarnt\.pdf/);
    expect(pr.uploads).toHaveLength(0);

    // an office file: fine on the HP (its gateway converts), not on the Brother — with the page limit in one picture
    const docx = tmpFile('Elternbrief Klassenfahrt.docx', DOCX);
    await answerOpenDialogs([docx]);
    await root.locator('.pv-pick').click();
    await expect(d.locator('.pv-file-tx span')).toHaveText(/(Word-Datei|Word file) · .* · (vom PC|from this PC)/);
    await expect(d.locator('[data-banner="office"]')).toHaveCount(0);
    await d.locator(`[data-k="prn:${BROTHER}"]`).click();
    await expect(d.locator('[data-banner="office"]')).toHaveText(/(Office-Dateien sind für diesen Drucker nicht eingeschaltet|Office files are not switched on for this printer)/);
    await d.locator('[data-k="copies"]').fill('25');
    await expect(d.locator('[data-banner="limit"]')).toHaveText(/25 .* 14/);
    await expect(d.locator('[data-k="submit"]')).toBeDisabled();
    await shot(page, '03-dialog-grenzfaelle-dunkel');
    await theme(page, 'light');
    await shot(page, '03-dialog-grenzfaelle-hell');
    await theme(page, 'dark');

    // back on the HP with one copy: the server refuses (the page limit is its decision) — the job stays with its reason
    await d.locator(`[data-k="prn:${HP}"]`).click();
    await d.locator('[data-k="copies"]').fill('1');
    await expect(d.locator('[data-k="submit"]')).toBeEnabled();
    pr.refuse.print = { status: 409, code: 'limit', left: 0, pages: 3 };
    await d.locator('[data-k="submit"]').click();
    const failed = root.locator('.pv-job[data-kind="transfer"]');
    await expect(failed).toHaveClass(/is-err/);
    await expect(failed.locator('.pv-why')).toHaveText(/(Das wären 3 Seiten – heute gehen noch 0|That would be 3 pages – 0 left today)/);
    await expect(page.locator('#print-badge')).toBeHidden();
    await shot(page, '04-nicht-gesendet-dunkel');
    // "Erneut drucken": the same file and options again, the failed row goes
    await failed.locator('[data-act="again"]').click();
    await expect(d.locator('.pv-file-tx b')).toHaveText('Elternbrief Klassenfahrt.docx');
    await expect(d.locator(`[data-k="prn:${HP}"]`)).toHaveAttribute('aria-checked', 'true');
    await d.locator('[data-k="submit"]').click();
    await expect(rowOf(root, 'job1')).toBeVisible();
    await expect(root.locator('.pv-job[data-kind="transfer"]')).toHaveCount(0);
    expect(pr.uploads.map((u) => u.mime)).toEqual(Array(2).fill('application/vnd.openxmlformats-officedocument.wordprocessingml.document'));

    // a file that is still going up: its progress, "Abbrechen" — it never becomes a job
    pr.holdUploads = true;
    await answerOpenDialogs([tmpFile('Haushaltsbuch 2026.pdf', PDF2)]);
    await root.locator('.pv-pick').click();
    await d.locator('[data-k="submit"]').click();
    const going = root.locator('.pv-job[data-kind="transfer"]');
    await expect(going.locator('.pv-chip')).toHaveText(/(Geht an GateControl … 100 %|Going to GateControl … 100 %)/);
    await expect(going.locator('.pv-bar')).toHaveAttribute('aria-valuenow', '100');
    await expect(page.locator('#print-badge')).toHaveText('2');
    await shot(page, '04b-wird-hochgeladen-dunkel');
    await going.locator('[data-act="cancel"]').click();
    await expect(root.locator('.pv-job[data-kind="transfer"]')).toHaveCount(0);
    pr.releaseUploads();
    await page.waitForTimeout(800);
    expect(sent(pr, 'POST', 'print')).toHaveLength(2);
    await expect(page.locator('#print-badge')).toHaveText('1');

    // the virus scan of the server blocks the upload: said, "Entfernen"
    pr.refuse.upload = { status: 423, code: 'quarantined' };
    await answerOpenDialogs([tmpFile('Virus.pdf', PDF2)]);
    await root.locator('.pv-pick').click();
    await d.locator('[data-k="submit"]').click();
    const blocked = root.locator('.pv-job[data-kind="transfer"]');
    await expect(blocked.locator('.pv-why')).toHaveText(/(Virenscan|virus scan)/);
    await blocked.locator('[data-act="remove"]').click();
    await expect(root.locator('.pv-job[data-kind="transfer"]')).toHaveCount(0);
    expect(sent(pr, 'POST', 'print')).toHaveLength(2);

    // a failed job of the server whose file is known here: "Erneut drucken" opens the dialog with its options
    pr.setJob('job1', { state: 'failed', error: 'printer_rejected', doneAt: new Date().toISOString() });
    await root.locator('.pv-ib').click();
    await expect(rowOf(root, 'job1')).toHaveClass(/is-err/);
    await rowOf(root, 'job1').locator('[data-act="again"]').click();
    await expect(d.locator('.pv-file-tx b')).toHaveText('Elternbrief Klassenfahrt.docx');
    await page.keyboard.press('Escape');
    // the file is gone from the PC: said, no dialog
    fs.rmSync(docx);
    await rowOf(root, 'job1').locator('[data-act="again"]').click();
    await expect(page.locator('.toast-error').last()).toHaveText(/(liegt nicht mehr dort|not where it was)/);
    await expect(page.locator('.pv-scrim')).toBeHidden();
  });

  test('files dropped from the Explorer on the entry "Drucken" and on the page', async ({ launchApp, mock }) => {
    const pr = setPrint(mock, { jobs: [] });
    await mock.setDrive({ features: ['bulk'] });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setLang(page);
    await expect(page.locator('#nav-drucken')).toBeVisible();
    await page.locator('#nav-drive').click();
    const file = tmpFile('Vom Explorer.txt', 'Zahnbürste\nSocken\n');
    await page.evaluate(() => { const i = document.createElement('input'); i.type = 'file'; i.multiple = true; i.id = 'e2e-print-file'; i.style.display = 'none'; document.body.appendChild(i); });
    await page.locator('#e2e-print-file').setInputFiles([file, tmpFile('Film.mp4', 'xx')]);
    const drag = (sel, type) => page.evaluate(({ sel, type }) => {
      const dt = new DataTransfer();
      for (const f of document.getElementById('e2e-print-file').files) dt.items.add(f);
      const ev = new DragEvent(type, { bubbles: true, cancelable: true, dataTransfer: dt });
      document.querySelector(sel).dispatchEvent(ev);
      return ev.defaultPrevented;
    }, { sel, type });
    // over the entry in the side bar: it takes the files and says so
    expect(await drag('#nav-drucken', 'dragenter')).toBe(true);
    expect(await drag('#nav-drucken', 'dragover')).toBe(true);
    await expect(page.locator('#nav-drucken')).toHaveClass(/is-drop/);
    await shot(page, '05-ablegen-seitenleiste-dunkel');
    await drag('#nav-drucken', 'drop');
    await expect(page.locator('#nav-drucken')).not.toHaveClass(/is-drop/);
    const d = dlg(page);
    await expect(d.locator('.pv-file-tx b')).toHaveText('Vom Explorer.txt');
    await expect(d.locator('.pv-file-tx span')).toHaveText(/Text · .* · (vom PC|from this PC)/);
    // what could not be taken is named
    await expect(d.locator('[data-rejected]')).toContainText('Film.mp4');
    await d.locator('[data-k="submit"]').click();
    await expect.poll(() => sent(pr, 'POST', 'print').length).toBe(1);
    expect(pr.uploads[0]).toMatchObject({ mime: 'text/plain' });
    expect(pr.uploads[0].head.startsWith('Zahnb')).toBe(true);
    // Drive's own upload did not take them
    await expect(page.locator('#page-drive .dv')).not.toHaveClass(/is-drop/);

    // the drop area of the page
    await page.locator('#nav-drucken').click();
    const root = page.locator('#page-drucken');
    await expect(root.locator('.pv-drop')).toBeVisible();
    await drag('#page-drucken .pv-drop', 'dragenter');
    await drag('#page-drucken .pv-drop', 'dragover');
    await expect(root.locator('.pv-drop')).toHaveClass(/is-over/);
    await shot(page, '06-ablegen-seite-dunkel');
    await drag('#page-drucken .pv-drop', 'drop');
    await expect(d.locator('.pv-file-tx b')).toHaveText('Vom Explorer.txt');
    await d.locator('[data-k="cancel"]').click();
    await expect(root.locator('.pv-drop')).not.toHaveClass(/is-over/);
    expect(pr.uploads).toHaveLength(1);
    // a page script cannot name a path: a File it makes itself has none
    const forged = await page.evaluate(async () => {
      const r = await window.gatecontrol.print.addDropped([new File(['x'], 'C:\\Windows\\win.ini', { type: 'text/plain' })]);
      return { ok: r.ok, code: r.code };
    });
    expect(forged).toEqual({ ok: false, code: 'invalid' });
  });

  test('Drive: "Drucken …" in the row menu, the selection, Strg+P, the viewer; rows dragged onto "Drucken"', async ({ launchApp, mock }) => {
    const pr = setPrint(mock, { jobs: [] });
    const d = await mock.setDrive({ features: ['bulk'] });
    const pdf = d.srv.mutate.photo(1, 'Stromrechnung 2026-10.pdf', { content: PDF2, mime: 'application/pdf' });
    const txt = d.srv.mutate.photo(1, 'Packliste.txt', { content: 'Socken\n', mime: 'text/plain' });
    const bad = d.srv.mutate.photo(1, 'Virus.pdf', { content: PDF2, mime: 'application/pdf' });
    d.srv.state.nodes.get(bad.id).scan = { state: 'infected', blocked: true, finding: 'Eicar-Test-Signature' };
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await setLang(page);
    await expect(page.locator('#nav-drucken')).toBeVisible();
    await page.locator('#nav-drive').click();
    const root = page.locator('#page-drive');
    await root.locator('.dv-pages [data-page="files"]').click();
    const row = (id) => root.locator(`.dv-row[data-id="${id}"]`);
    await expect(row(pdf.id)).toBeVisible();
    const menu = page.locator('.dv-menu');
    const dialog = dlg(page);

    // a folder, a program and a file the virus scan blocks: no "Drucken …"
    for (const id of [10, 13, bad.id]) {
      await row(id).click({ button: 'right' });
      await expect(menu).toBeVisible();
      await expect(menu.locator('[data-item="print"]')).toHaveCount(0);
      await page.keyboard.press('Escape');
    }
    // a PDF: "Drucken …" with its key
    await row(pdf.id).click({ button: 'right' });
    await expect(menu.locator('[data-item="print"]')).toHaveText(/(Drucken …|Print …)\s*(Strg|Ctrl)\+P/);
    await shot(page, '07-drive-menue-dunkel');
    await menu.locator('[data-item="print"]').click();
    await expect(dialog.locator('.pv-file-tx b')).toHaveText('Stromrechnung 2026-10.pdf');
    await expect(dialog.locator('.pv-file-tx span')).toHaveText(/PDF · .* · (aus Drive|from Drive)/);
    await dialog.locator('[data-k="submit"]').click();
    // the app loads it from Drive and hands it to the print plugin
    await expect.poll(() => sent(pr, 'POST', 'print').length).toBe(1);
    expect(pr.uploads[0]).toMatchObject({ mime: 'application/pdf', bytes: PDF2.length });
    expect(sent(pr, 'POST', 'print')[0].body.name).toBe('Stromrechnung 2026-10.pdf');
    await expect(page.locator('#print-badge')).toHaveText('1');
    await expect(page.locator('.toast-success')).toHaveText(/(Auftrag angelegt|Job created)/);

    // a selection of several: "2 Dateien drucken …" — the folder and the blocked file do not count
    for (const id of [pdf.id, txt.id, 10, bad.id]) await row(id).locator('.dv-cb').check();
    await row(txt.id).click({ button: 'right' });
    await expect(page.locator('.dv-sel-menu [data-item="print"]')).toHaveText(/(2 Dateien drucken …|Print 2 files …)/);
    await shot(page, '08-drive-auswahl-dunkel');
    await page.locator('.dv-sel-menu [data-item="print"]').click();
    await expect(dialog.locator('.pv-file')).toHaveAttribute('data-files', '2');
    await expect(dialog.locator('.pv-file-tx b')).toHaveText(/(2 Dateien|2 files)/);
    await expect(dialog.locator('.pv-file-names')).toHaveText('Packliste.txt, Stromrechnung 2026-10.pdf');
    await shot(page, '09-dialog-mehrere-dunkel');
    await dialog.locator('[data-k="submit"]').click();
    await expect.poll(() => sent(pr, 'POST', 'print').length).toBe(3);
    expect(sent(pr, 'POST', 'print').slice(1).map((r) => r.body.name)).toEqual(['Packliste.txt', 'Stromrechnung 2026-10.pdf']);

    // Strg+P prints the selection
    await page.keyboard.press('Escape');
    await row(txt.id).locator('.dv-cb').check();
    await page.keyboard.press('Control+p');
    await expect(dialog.locator('.pv-file-tx b')).toHaveText('Packliste.txt');
    await page.keyboard.press('Escape');
    await expect(page.locator('.pv-scrim')).toBeHidden();
    // … and says so when nothing of it can be printed
    await row(txt.id).locator('.dv-cb').uncheck();
    await row(13).locator('.dv-cb').check();
    await page.keyboard.press('Control+p');
    await expect(page.locator('.toast-info').last()).toHaveText(/(nichts zum Drucken|Nothing here can be printed)/);

    // the viewer of a PDF: "Drucken" among its buttons — the whole file
    await row(pdf.id).locator('.dv-open').click();
    const viewer = page.locator('.dv-dlg.dv-vv');
    await expect(viewer.locator('.dv-vv-print')).toHaveText(/^(Drucken|Print)$/);
    await shot(page, '10-vorschau-knopf-dunkel');
    await viewer.locator('.dv-vv-print').click();
    await expect(dialog.locator('.pv-file-tx b')).toHaveText('Stromrechnung 2026-10.pdf');
    await dialog.locator('[data-k="cancel"]').click();
    await expect(viewer).toBeVisible();
    await page.keyboard.press('Escape');
    // the large view of a picture
    await row(11).locator('.dv-open').click();
    await expect(page.locator('.dpv-print')).toBeVisible();
    await page.keyboard.press('Escape');

    // rows dragged out of Drive onto the entry "Drucken"
    await row(13).locator('.dv-cb').uncheck();
    const over = await page.evaluate((id) => {
      const a = document.querySelector(`#page-drive .dv-row[data-id="${id}"]`);
      const b = document.querySelector('#nav-drucken');
      const dt = new DataTransfer();
      const ev = (type) => new DragEvent(type, { bubbles: true, cancelable: true, dataTransfer: dt, clientX: 10, clientY: 10 });
      a.dispatchEvent(ev('dragstart'));
      b.dispatchEvent(ev('dragenter'));
      const o = ev('dragover');
      b.dispatchEvent(o);
      const marked = b.classList.contains('is-drop');
      b.dispatchEvent(ev('drop'));
      a.dispatchEvent(ev('dragend'));
      return { prevented: o.defaultPrevented, marked };
    }, pdf.id);
    expect(over).toEqual({ prevented: true, marked: true });
    await expect(dialog.locator('.pv-file-tx b')).toHaveText('Stromrechnung 2026-10.pdf');
    await page.keyboard.press('Escape');
    expect(sent(pr, 'POST', 'print')).toHaveLength(3);
    // nothing was moved in Drive by that drop
    expect(d.srv.state.opCalls || []).toEqual([]);
  });

  test('a file of a vault is printed only after the question; it goes up decrypted, its copy is removed', async ({ launchApp, mock }, testInfo) => {
    const pr = setPrint(mock, { jobs: [] });
    const d = await mock.setDrive({ features: ['vault', 'vaultsApart'] });
    const { app, page, dir: appDir } = await launchApp();
    await app.evaluate(() => globalThis.__gcE2E.useFakeConsent());
    await setupWithApiKey(page, mock);
    await setLang(page);
    await page.locator('#nav-drive').click();
    const root = page.locator('#page-drive');
    await root.locator('.dv-pages [data-page="files"]').click();
    const made = await page.evaluate(() => window.gatecontrol.drive.vault.create(1, 'Privat'));
    expect(made.ok).toBe(true);
    const src = testInfo.outputPath('src');
    fs.mkdirSync(src, { recursive: true });
    const SECRET = 'Tresor-Geheimnis 4711\n';
    fs.writeFileSync(path.join(src, 'Zugang.txt'), SECRET);
    await page.evaluate(([id, list]) => window.gatecontrol.drive.upload(id, list), [made.node.id, [path.join(src, 'Zugang.txt')]]);
    await expect.poll(() => [...d.srv.state.nodes.values()].filter((n) => n.parentId === made.node.id && !n.isDir).length, { timeout: 30000 }).toBe(1);
    await root.locator('.dv-head .dv-ib').first().click();
    const [vault] = [...d.srv.state.vaults.values()];
    await root.locator(`.dv-vault-item[data-vault="${vault.id}"]`).click();
    const row = root.locator('.dv-row', { has: page.locator('.dv-c-name', { hasText: 'Zugang.txt' }) });
    await expect(row).toHaveCount(1);

    await row.click({ button: 'right' });
    await page.locator('.dv-menu [data-item="print"]').click();
    // the question first: the file leaves the vault decrypted
    const d2 = dlg(page);
    await expect(d2.locator('.pv-dlg-h')).toHaveText(/(Aus dem Tresor drucken\?|Print from the vault\?)/);
    await expect(d2.locator('[data-k="cancel"]')).toBeFocused();
    await shot(page, '11-tresor-nachfrage-dunkel');
    // no: nothing is loaded, nothing goes up
    await d2.locator('[data-k="cancel"]').click();
    await expect(page.locator('.pv-scrim')).toBeHidden();
    expect(pr.uploads).toHaveLength(0);
    // yes: the print dialog names where it comes from
    await row.click({ button: 'right' });
    await page.locator('.dv-menu [data-item="print"]').click();
    await d2.locator('[data-k="vault-yes"]').click();
    await expect(d2.locator('.pv-file-tx b')).toHaveText('Zugang.txt');
    await expect(d2.locator('.pv-file-tx span')).toHaveText(/(aus einem Tresor im Drive|from a vault in Drive)/);
    await d2.locator('[data-k="submit"]').click();
    await expect.poll(() => sent(pr, 'POST', 'print').length, { timeout: 30000 }).toBe(1);
    // the plain text reached the print plugin (as the person agreed) …
    expect(pr.uploads[0]).toMatchObject({ mime: 'text/plain', bytes: SECRET.length });
    expect(pr.uploads[0].head).toBe(SECRET.slice(0, 16));
    // … and no decrypted copy stays in the temp folder
    const walk = (dir) => { let out = []; try { for (const e of fs.readdirSync(dir, { withFileTypes: true })) out = out.concat(e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]); } catch { /* not there */ } return out; };
    const temp = await app.evaluate(({ app: a }) => a.getPath('temp'));
    await expect.poll(() => walk(path.join(temp, 'gatecontrol-drive', 'vault')).filter((f) => f.endsWith('Zugang.txt'))).toEqual([]);
    expect(appDir).toBeTruthy();
  });

  test('states: no printer, no right to print (earlier jobs stay), not available, no connection', async ({ launchApp, mock }) => {
    const pr = setPrint(mock, { printers: [], jobs: [] });
    await mock.setDrive({ features: ['bulk'] });
    const { page } = await launchApp();
    await freeze(page);
    await page.reload();
    const root = await openPrint(page, mock);
    // no printer found yet
    await expect(root.locator('[data-state="noPrinter"] strong')).toHaveText(/(Noch kein Drucker gefunden|No printer found yet)/);
    await expect(root.locator('.pv-pick')).toBeHidden();
    await expect(root.locator('.pv-drop')).toHaveCount(0);
    await shot(page, '12-kein-drucker-dunkel');

    // every printer off, one with a changed certificate: printing still works, the job will wait
    pr.printers = printers().map((p) => ({ ...p, online: false, printer: { ...p.printer, state: 'offline' } }));
    pr.printers[1].problem = 'cert_changed';
    await root.locator('[data-k="retry"]').click();
    await expect(root.locator('[data-banner="allOff"]')).toHaveText(/(Kein Drucker ist gerade an|No printer is on right now)/);
    await expect(root.locator(`[data-banner="cert:${BROTHER}"]`)).toHaveText(/Brother HL-L2350DW: .*(Zertifikat|certificate)/);
    await expect(root.locator(`.pv-prn[data-printer="${BROTHER}"] .pv-chip`)).toHaveClass(/is-warn/);
    await expect(root.locator('.pv-drop')).toContainText(/(wartet, bis der Drucker an ist|waits until the printer is on)/);
    await expect(root.locator('.pv-pick')).toBeVisible();
    await shot(page, '13-drucker-aus-dunkel');
    await theme(page, 'light');
    await shot(page, '13-drucker-aus-hell');
    await theme(page, 'dark');

    // no connection: the last list with its time, new jobs only with a connection
    pr.printers = printers();
    pr.jobs = jobs().slice(1, 2);
    await root.locator('.pv-ib').click();
    await expect(rowOf(root, 'j2')).toBeVisible();
    pr.down = true;
    await page.waitForTimeout(3200);
    await root.locator('.pv-ib').click();
    await expect(root.locator('[data-banner="offline"]')).toHaveText(/(Keine Verbindung zu GateControl|No connection to GateControl)/);
    await expect(rowOf(root, 'j2').locator('.pv-why')).toHaveText(/(läuft am Server weiter|goes on at the server)/);
    await expect(root.locator('.pv-pick')).toBeDisabled();
    await expect(page.locator('.toast-error')).toHaveCount(0);
    await shot(page, '14-keine-verbindung-dunkel');
    pr.down = false;
    await root.locator('[data-banner="offline"] [data-k="retry"]').click();
    await expect(root.locator('[data-banner="offline"]')).toHaveCount(0);
    await expect(root.locator('.pv-pick')).toBeEnabled();

    // the right to print is taken: said, the earlier jobs stay, Drive offers nothing
    pr.rights = { print: false, scan: true, pagesPerDay: 0, bwOnly: false };
    pr.jobs = jobs().slice(3, 4);
    await root.locator('.pv-ib').click();
    await expect(root.locator('[data-state="noRight"] strong')).toHaveText(/(Du darfst nicht drucken|You may not print)/);
    await expect(root.locator('.pv-job')).toHaveCount(1);
    await expect(root.locator('[data-jobs-sub]')).toHaveText(/^(keine offenen|none open)/);
    await expect(root.locator('.pv-pick')).toBeHidden();
    await expect(page.locator('#nav-drucken')).toBeVisible();
    await shot(page, '15-kein-recht-dunkel');
    await page.locator('#nav-drive').click();
    await page.locator('#page-drive .dv-pages [data-page="files"]').click();
    await page.locator('#page-drive .dv-row[data-id="11"]').click({ button: 'right' });
    await expect(page.locator('.dv-menu')).toBeVisible();
    await expect(page.locator('.dv-menu [data-item="print"]')).toHaveCount(0);
    await page.keyboard.press('Escape');

    // the plugin is stopped while the app runs: "nicht verfügbar", and once the list says so the entry goes
    await page.locator('#nav-drucken').click();
    pr.gone = true;
    await root.locator('.pv-ib').click();
    await expect(root.locator('[data-state="unavailable"] strong')).toHaveText(/(Drucken ist hier nicht verfügbar|Printing is not available here)/);
    await shot(page, '16-nicht-verfuegbar-dunkel');
    pr.listed = false;
    await root.locator('[data-k="retry"]').click();
    await expect(page.locator('#nav-drucken')).toBeHidden();
    await expect(page.locator('#page-status')).toHaveClass(/active/);
  });

  test('an older plugin (no jobs/<id>, no expiresAt / doneAt): the list works, no error', async ({ launchApp, mock }) => {
    const pr = setPrint(mock, { version: '1.0.3', jobRoute: false, times: false, jobs: jobs().slice(0, 2), printers: printers().map((p) => { const { media, office, ...rest } = p.printer; return { ...p, printer: rest }; }) });
    const { page, answerOpenDialogs } = await launchApp();
    await freeze(page);
    await page.reload();
    const root = await openPrint(page, mock);
    await expect(root.locator('.pv-job')).toHaveCount(2);
    // waiting, but until when is not known: the sentence without a time
    await expect(rowOf(root, 'j2').locator('.pv-why')).toHaveText(/(bis zu 24 Stunden|up to 24 hours)/);
    // the job is followed through the overview
    await expect.poll(() => sent(pr, 'GET', 'jobs/j1').length, { timeout: 20000 }).toBe(1);
    pr.setJob('j1', { state: 'done', message: null });
    await expect(rowOf(root, 'j1').locator('.pv-chip')).toHaveText(/^(Gedruckt|Printed)$/, { timeout: 40000 });
    expect(sent(pr, 'GET', 'jobs/j1').length).toBe(1);
    // the dialog of a printer that names no paper and no tray
    await answerOpenDialogs([tmpFile('a.pdf', PDF2)]);
    await root.locator('.pv-pick').click();
    const d = dlg(page);
    await expect(d.locator('[data-k="paper"]')).toHaveCount(0);
    await expect(d.locator('[data-k="tray"]')).toHaveCount(0);
    await d.locator('[data-k="submit"]').click();
    await expect.poll(() => sent(pr, 'POST', 'print').length).toBe(1);
    expect(sent(pr, 'POST', 'print')[0].body).not.toHaveProperty('media');
    await expect(page.locator('.toast-error')).toHaveCount(0);
  });

  test('"Druck fertig" / "Druck fehlgeschlagen": the list follows, the inbox entry and the toast open the page on the job', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [{ id: 'plugin:gatecontrol-print:print_done', label: 'Drucken & Scannen · Druck fertig' }, { id: 'plugin:gatecontrol-print:print_failed', label: 'Drucken & Scannen · Druck fehlgeschlagen' }], items: [] });
    const pr = setPrint(mock, { jobs: jobs().slice(0, 1).map((j) => ({ ...j, message: null })) });
    const { app, page } = await launchApp();
    const root = await openPrint(page, mock);
    await expect(rowOf(root, 'j1').locator('.pv-chip')).toHaveText(/(Wird gedruckt|Printing)/);
    pr.setJob('j1', { state: 'failed', error: 'printer_rejected', doneAt: new Date().toISOString() });
    mock.pushNotification({
      topic: 'plugin:gatecontrol-print:print_failed', title: 'Druck fehlgeschlagen', body: '„Stromrechnung 2026-10.pdf“: Der Drucker hat den Auftrag abgelehnt.',
      collapse_key: 'print-j1', data: { route: 'plg-gatecontrol-print' },
    });
    await expect(rowOf(root, 'j1')).toHaveClass(/is-err/);
    await expect(page.locator('#print-badge')).toBeHidden();
    // the inbox entry opens the page …
    await page.locator('#nav-inbox').click();
    await page.locator('#inbox-list .inbox-row').first().click();
    await page.locator('#inbox-detail .btn-pri').first().click();
    await expect(page.locator('#page-drucken')).toHaveClass(/active/);
    // … and so does a click on its toast the core claimed (notify:navigate with the print route)
    await page.locator('.nav[data-page="status"]').click();
    await app.evaluate(({ BrowserWindow }, ctx) => {
      BrowserWindow.getAllWindows()[0].webContents.send('notify:navigate', { route: 'plg-gatecontrol-print', id: 1, context: ctx });
    }, { type: 'print', kind: 'failed', jobId: 'j1' });
    await expect(page.locator('#page-drucken')).toHaveClass(/active/);
    // a message of the plugin the core did not claim keeps the inbox
    await app.evaluate(({ BrowserWindow }) => {
      BrowserWindow.getAllWindows()[0].webContents.send('notify:navigate', { route: 'plg-gatecontrol-print', id: 2 });
    });
    await expect(page.locator('#page-inbox')).toHaveClass(/active/);
  });
});
