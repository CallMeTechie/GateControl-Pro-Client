'use strict';

const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Notizen & Aufgaben, plugin 1.9.0 (the word calendarEvents of me.features): „Termin“ in the quick entry. The switch
// „Aufgabe | Termin | Notiz“, the question „Als Termin anlegen?“ (a date and a time; the app never switches by itself),
// the chips of an event (Tag, Zeit, Ort as text — the dashed suggestion and its dialog —, Kalender, Erinnerung), „Mehr
// Angaben …“ (Mail's own form of a new event, filled in), the card „Kein Kalender“ with „Als Aufgabe mit Datum
// speichern“, events in „Mein Tag“ / „Demnächst“ with the calendar's colour and no tick box (a click opens Mail's event),
// „Termine aus dem Kalender“ on the page „Quellen“, and an event that waits while Mail does not answer. The event is
// stored in the calendar of Mail only (the core's fake Notizen server, STAGE7). Screenshots in both themes
// (GC_SHOTS_DIR: copied there as well).

function coreDir() {
  const root = path.join(__dirname, '..', '..');
  try {
    return path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [root] }));
  } catch {
    return path.join(root, '..', 'gatecontrol-client-core');
  }
}
function features({ events = true } = {}) {
  const F = require(path.join(coreDir(), 'test', 'fixtures', 'notes-server.js'));
  return [...F.FEATURES, ...F.STAGE1, ...F.STAGE2, ...F.STAGE3, ...F.STAGE4, ...F.STAGE5, ...F.STAGE6, ...(events ? F.STAGE7 : [])];
}

async function openNotes(page, app) {
  if (app) await app.evaluate(({ BrowserWindow }) => { const win = BrowserWindow.getAllWindows()[0]; win.unmaximize(); win.setSize(1440, 900); });
  await page.evaluate(() => window.gatecontrol.locale.set('de'));
  await expect(page.locator('#nav-notizen')).toBeVisible();
  await page.locator('#nav-notizen').click();
  await expect(page.locator('#page-notizen')).toHaveClass(/active/);
  const root = page.locator('#page-notizen');
  await expect(root.locator('.nz-sec').first()).toBeVisible();
  return root;
}

const light = (page) => page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'));
const dark = (page) => page.evaluate(() => document.documentElement.removeAttribute('data-theme'));
/** A screenshot in both themes (`<name>-hell.png`, `<name>-dunkel.png`), the toasts of earlier steps out of the way. */
async function shots(page, name) {
  await page.evaluate(() => { const box = document.querySelector('#toasts'); if (box) box.replaceChildren(); });
  const out = [];
  await light(page);
  out.push([test.info().outputPath(`${name}-hell.png`)]);
  await page.screenshot({ path: out[0][0] });
  await dark(page);
  out.push([test.info().outputPath(`${name}-dunkel.png`)]);
  await page.screenshot({ path: out[1][0] });
  const dir = process.env.GC_SHOTS_DIR;
  if (dir) {
    const fs = require('fs');
    fs.mkdirSync(dir, { recursive: true });
    for (const [f] of out) fs.copyFileSync(f, path.join(dir, path.basename(f)));
  }
}
const events = (n) => [...n.srv.state.events.values()].filter((e) => e.hub);

test.describe('notizen – Termine (plugin 1.9.0)', () => {
  test('the switch, the question, the chips, the place as text, the calendar and the reminder; „Mehr Angaben …“ opens Mail\'s form', async ({ launchApp, mock }) => {
    await mock.setMail();
    const n = await mock.setNotes({ features: features() });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page, app);
    const quick = root.locator('#nz-quick');
    await expect(root.locator('.nz-qmode button')).toHaveText(['Aufgabe', 'Termin', 'Notiz']);
    await expect(root.locator('.nz-qmode button[data-mode="task"]')).toHaveAttribute('aria-pressed', 'true');

    // task mode: a date and a time — the app asks, never switches by itself
    await quick.fill('Freitag 13. November 14 Uhr Outlet Musterstadt');
    const ask = root.locator('.nz-evask[data-card="ask"]');
    await expect(ask).toBeVisible();
    await expect(root.locator('.nz-qmode button[data-mode="task"]')).toHaveAttribute('aria-pressed', 'true');
    await shots(page, '03-frage-als-termin');
    // „Aufgabe lassen“ holds for this line; without a time nobody asks
    await ask.locator('[data-act="keep-task"]').click();
    await expect(ask).toBeHidden();
    await quick.fill('Freitag Müll rausbringen');
    await expect(root.locator('.nz-evask')).toBeHidden();
    await quick.fill('');
    await quick.fill('Freitag 13. November 14 Uhr Outlet Musterstadt');
    await root.locator('.nz-evask [data-act="as-event"]').click();
    await expect(root.locator('.nz-qmode button[data-mode="event"]')).toHaveAttribute('aria-pressed', 'true');

    // Bild 1: the chips of the event (the reminder of the calendar, the dashed place)
    const chip = (k) => root.locator(`.nz-qchip-ev[data-kind="${k}"]`);
    await expect(chip('date')).toHaveText('Fr. 13. Nov.');
    await expect(chip('time')).toHaveText('14:00–15:00');
    await expect(chip('place')).toHaveText('Ort: Outlet Musterstadt?');
    await expect(chip('place')).toHaveClass(/is-suggest/);
    await expect(chip('calendar').locator('select')).toHaveValue('7');
    await expect(chip('reminder').locator('select option:checked')).toHaveText('15 Min. vorher');
    await expect(root.locator('.nz-qmore')).toBeVisible();
    await shots(page, '01-termin-bausteine');

    // the dashed chip takes the title as the place; the place is a text only (Bild 4)
    await chip('place').locator('button').click();
    await expect(chip('place')).toHaveText('Ort: Outlet Musterstadt');
    await chip('place').locator('button').click();
    const dlg = root.locator('.nz-dlg[data-dlg="ev-place"]');
    await expect(dlg).toBeVisible();
    await dlg.locator('input').fill('Outlet Musterstadt, Halle B');
    await shots(page, '04-ort-des-termins');
    await dlg.locator('[data-act="apply"]').click();
    await expect(chip('place')).toHaveText('Ort: Outlet Musterstadt, Halle B');
    // the calendar and the reminder chosen
    await chip('calendar').locator('select').selectOption('8');
    await chip('reminder').locator('select').selectOption('30');
    await expect(chip('reminder').locator('select option:checked')).toHaveText('30 Min. vorher');
    await quick.press('Enter');
    await expect.poll(() => events(n).length).toBe(1);
    const ev = events(n)[0];
    expect([ev.title, ev.date, ev.time, ev.endTime, ev.location, ev.calendarId, ev.reminder]).toEqual(['Outlet Musterstadt', '2026-11-13', '14:00', '15:00', 'Outlet Musterstadt, Halle B', 8, 30]);
    const sent = n.srv.state.requests.filter((r) => r.method === 'POST' && /\/api\/events$/.test(r.path)).pop().body;
    expect(sent.clientId).toMatch(/^[0-9a-f-]{36}$/);
    await expect(quick).toHaveValue('');
    // the switch stays where the person put it
    await expect(root.locator('.nz-qmode button[data-mode="event"]')).toHaveAttribute('aria-pressed', 'true');

    // Bild 2: no time — all day; the place after „im“; the reminder of an all-day event; nothing chosen goes out
    await quick.fill('Freitag 13. November Einkaufen im Outlet Musterstadt');
    await expect(chip('time')).toHaveText('Ganztägig');
    await expect(chip('place')).toHaveText('Ort: Outlet Musterstadt');
    await expect(chip('reminder').locator('select option:checked')).toHaveText('Vortag, 18:00');
    await shots(page, '02-ganztaegig-ort-mit-im');

    // „Mehr Angaben …“: Mail's own form of a new event, filled in — saved there
    await root.locator('.nz-qmore').click();
    await expect(page.locator('#page-mail')).toHaveClass(/active/);
    const form = page.locator('.ml-dlg.cal-edit');
    await expect(form).toBeVisible();
    await expect(form.locator('.cal-in-title')).toHaveValue('Einkaufen');
    await expect(form.locator('input.ml-input[maxlength="500"]').first()).toHaveValue('Outlet Musterstadt');
    await expect(form.locator('input[type="date"]').first()).toHaveValue('2026-11-13');
  });

  test('„Mein Tag“ with events (no tick box, the calendar\'s colour), a click opens Mail\'s event; „Termine aus dem Kalender“', async ({ launchApp, mock }) => {
    const m = await mock.setMail();
    const n = await mock.setNotes({ features: features() });
    const today = n.srv.state.today;
    const dentist = n.srv.addEvent({ title: 'Zahnarzt', date: today, time: '16:30', endTime: '17:15', location: 'Praxis am Markt' });
    n.srv.addEvent({ title: 'Outlet Musterstadt', date: '2026-11-13', time: '14:00', location: 'Outlet Musterstadt' });
    n.srv.addEvent({ calendarId: 9, title: 'Feiertag', date: '2026-11-11' });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page, app);
    const evToday = root.locator('.nz-sec[data-id="events"] .nz-ev');
    await expect(evToday).toHaveCount(1);
    await expect(evToday.locator('.nz-row-title')).toHaveText('Zahnarzt');
    await expect(evToday.locator('.nz-row-meta')).toHaveText('Praxis am Markt · Privat');
    await expect(evToday.locator('.nz-when')).toHaveText('16:30');
    await expect(evToday.locator('.nz-ck')).toHaveCount(0);
    await expect(evToday.locator('.nz-src')).toHaveCount(0);
    const soon = root.locator('.nz-sec[data-id="upcoming"] .nz-ev');
    await expect(soon.locator('.nz-row-title')).toHaveText(['Outlet Musterstadt']);
    await expect(soon.locator('.nz-row-meta')).toHaveText('Fr. 13. Nov. · Outlet Musterstadt · Privat');
    // Feiertage are off by default
    await expect(root.locator('.nz-ev', { hasText: 'Feiertag' })).toHaveCount(0);
    // the source Mail does not count the events
    await expect(root.locator('.nz-it[data-view="source:gatecontrol-mail"] .nz-n')).toHaveText('1');
    await root.locator('.nz-sec[data-id="upcoming"]').scrollIntoViewIfNeeded();
    await shots(page, '07-mein-tag-mit-terminen');

    // a click opens Mail's event page (not the details of the source)
    await evToday.click();
    await expect(page.locator('#page-mail')).toHaveClass(/active/);
    await expect.poll(() => m.srv.state.requests.some((r) => r.method === 'GET' && r.path.endsWith(`/api/events/${dentist.id}`))).toBe(true);

    // „Quellen“: Termine aus dem Kalender — Feiertage on
    await page.locator('#nav-notizen').click();
    await root.locator('.nz-it[data-view="sources"]').click();
    const card = root.locator('[data-card="calendars"]');
    await expect(card).toBeVisible();
    await expect(card.locator('.nz-evcal-row')).toHaveCount(5);
    await expect(card.locator('.nz-evcal-row[data-cal="cal:7"] .hint')).toHaveText('Standard für neue Termine');
    await expect(card.locator('.nz-evcal-row[data-cal="cal:10"] .sw')).toHaveAttribute('aria-checked', 'false');
    // the source Mail has no calendars as groups any more
    await expect(root.locator('.nz-srccard[data-plugin="gatecontrol-mail"]')).not.toContainText('Feiertage');
    await card.scrollIntoViewIfNeeded();
    await shots(page, '08-quellen-kalender');
    await card.locator('.nz-evcal-row[data-cal="cal:9"] .sw').click();
    await expect.poll(() => n.srv.state.prefs.groups['gatecontrol-mail|cal:9']).toBe('show');
    await card.locator('.nz-evcal-row[data-cal="cal:9"] .sw').click();
    await expect.poll(() => n.srv.state.prefs.groups['gatecontrol-mail|cal:9']).toBe(undefined);
  });

  test('no calendar: the switch stays, the reason and „Als Aufgabe mit Datum speichern“; Mail not answering: the event waits', async ({ launchApp, mock }) => {
    const n = await mock.setNotes({ features: features() });
    n.srv.state.eventsReason = 'no_mail';
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page, app);
    await root.locator('.nz-qmode button[data-mode="event"]').click();
    const quick = root.locator('#nz-quick');
    await quick.fill('Freitag 13. November 14 Uhr Outlet Musterstadt');
    const card = root.locator('.nz-evask[data-card="no-calendar"]');
    await expect(card).toBeVisible();
    await expect(card).toHaveAttribute('data-why', 'mail');
    await expect(card).toContainText('Kein Kalender vorhanden');
    await expect(root.locator('.nz-qchip-ev')).toHaveCount(0);
    await shots(page, '09-kein-kalender');
    await card.locator('[data-act="as-task"]').click();
    await expect.poll(() => [...n.srv.state.tasks.values()].find((x) => x.title === 'Outlet Musterstadt') || null).not.toBeNull();
    const task = [...n.srv.state.tasks.values()].find((x) => x.title === 'Outlet Musterstadt');
    expect(task.due).toEqual({ date: '2026-11-13', time: '14:00' });
    expect(events(n)).toHaveLength(0);
    // Bild 10: the overview runs on without the calendar
    await root.locator('.nz-qmode button[data-mode="task"]').click();
    await expect(root.locator('.nz-row:not(.nz-ev)', { hasText: 'Outlet Musterstadt' })).toHaveCount(1);
    await expect(root.locator('.nz-ev')).toHaveCount(0);
    await shots(page, '10-mein-tag-ohne-kalender');

    // Mail does not answer (503 unreachable): the event waits with its clientId and shows „wartet auf Verbindung“
    n.srv.state.eventsReason = 'unreachable';
    await root.locator('.nz-qmode button[data-mode="event"]').click();
    await quick.fill('Heute 18 Uhr Elternabend in der Schule');
    await expect(root.locator('.nz-qchip-ev[data-kind="place"]')).toHaveText('Ort: Schule');
    await quick.press('Enter');
    const waiting = root.locator('.nz-ev.is-pending');
    await expect(waiting).toHaveCount(1);
    await expect(waiting.locator('.nz-row-meta')).toContainText('wartet auf Verbindung');
    // Mail is back: the next event sends the waiting one first, once
    n.srv.state.eventsReason = null;
    await quick.fill('Samstag 14 bis 16 Uhr Flohmarkt bei Oma');
    await expect(root.locator('.nz-qchip-ev[data-kind="time"]')).toHaveText('14:00–16:00');
    await quick.press('Enter');
    await expect.poll(() => events(n).map((e) => e.title).sort()).toEqual(['Elternabend', 'Flohmarkt']);
    await expect(root.locator('.nz-ev.is-pending')).toHaveCount(0);
    // „Rückgängig“ of the hint: the event just made goes again (DELETE events/<id>)
    const undo = page.locator('#toasts .toast', { hasText: 'Flohmarkt' }).locator('.toast-act');
    await expect(undo).toHaveText('Rückgängig');
    await undo.click();
    await expect.poll(() => events(n).map((e) => e.title)).toEqual(['Elternabend']);
    // … and of a waiting event: it leaves the queue unsent
    n.srv.state.eventsReason = 'unreachable';
    await quick.fill('Morgen 9 Uhr Bäcker anrufen');
    await quick.press('Enter');
    await expect(root.locator('.nz-ev.is-pending')).toHaveCount(1);
    const undo2 = page.locator('#toasts .toast', { hasText: 'Bäcker anrufen' }).locator('.toast-act');
    await undo2.click();
    await expect(root.locator('.nz-ev.is-pending')).toHaveCount(0);
    n.srv.state.eventsReason = null;
    await quick.fill('Montag 10 Uhr Werkstatt');
    await quick.press('Enter');
    await expect.poll(() => events(n).map((e) => e.title).sort()).toEqual(['Elternabend', 'Werkstatt']);
  });

  test('an older plugin: no switch, no question — the quick entry stays as it was', async ({ launchApp, mock }) => {
    await mock.setNotes({ features: features({ events: false }) });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openNotes(page, app);
    await expect(root.locator('.nz-qmode')).toHaveCount(0);
    await root.locator('#nz-quick').fill('Freitag 13. November 14 Uhr Outlet Musterstadt');
    await expect(root.locator('.nz-qchip[data-kind="date"]')).toBeVisible();
    await expect(root.locator('.nz-evask')).toBeHidden();
  });
});
