'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Schule (plugin gatecontrol-schule, WebUntis): shown only when the server
// lists the plugin; child selector, this / next week as day columns with
// Entfällt / Vertretung / Zusatz, exams, homework, holidays; "Änderungen",
// and with plugin 1.4.0 "Nachrichten" and "Fehlzeiten" (hidden for older
// plugins); a Schule message in the inbox and a claimed toast click open
// the page on the child and day. Selectors by id/class.

const pad = (n) => String(n).padStart(2, '0');
const iso = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
function monday(offsetWeeks = 0) {
  const d = new Date();
  d.setHours(12, 0, 0, 0);
  d.setDate(d.getDate() - ((d.getDay() + 6) % 7) + 7 * offsetWeeks);
  return d;
}
const dayOf = (offsetWeeks, weekday) => { const d = monday(offsetWeeks); d.setDate(d.getDate() + weekday); return iso(d); };

const MON = dayOf(0, 0);
const TUE = dayOf(0, 1);
const WED = dayOf(0, 2);
const NEXT_MON = dayOf(1, 0);

function schoolData(version = '1.4.0') {
  return {
    version,
    students: [
      { id: 3, name: 'Lena Muster', klasse: '5b', color: '#2FBF71' },
      { id: 4, name: 'Tom Muster', klasse: '8a', color: '#3B82F6' },
    ],
    day: (sid, date) => {
      if (sid === 3 && date === MON) {
        return {
          lessons: [
            { start: '08:00', end: '08:45', period: 1, subject: 'M', subjectLong: 'Mathematik', teacher: 'MUE', room: '201', state: 'normal' },
            { start: '08:50', end: '09:35', period: 2, subject: 'E', subjectLong: 'Englisch', teacher: 'SCH', room: '104', state: 'cancelled', info: 'Lehrkraft krank' },
            { start: '09:50', end: '10:35', period: 3, subject: 'D', subjectLong: 'Deutsch', teacher: 'KLE', teacherOld: 'BRA', room: '105', roomOld: '201', state: 'changed', substText: 'Vertretung' },
            { start: '10:40', end: '11:25', period: 4, subject: 'SP', subjectLong: 'Sport', teacher: 'HOF', room: 'TH', state: 'extra' },
          ],
          exams: [{ subject: 'M', subjectLong: 'Mathematik', name: 'Klassenarbeit 2', start: '08:00', end: '08:45', type: 'Klassenarbeit' }],
          homework: [{ subject: 'D', subjectLong: 'Deutsch', text: 'Gedicht lernen <b>bold</b>', givenDate: MON }],
        };
      }
      if (sid === 3 && date === WED) return { holiday: 'Brückentag', lessons: [] };
      if (sid === 3 && date === NEXT_MON) return { lessons: [{ start: '08:00', end: '08:45', period: 1, subject: 'BIO', subjectLong: 'Biologie', teacher: 'KLE', room: 'NW1', state: 'normal' }] };
      if (sid === 4 && date === TUE) return { lessons: [{ start: '08:00', end: '08:45', period: 1, subject: 'PH', subjectLong: 'Physik', teacher: 'NEU', room: 'NW2', state: 'normal' }] };
      return null;
    },
    changes: [
      { id: 11, studentId: 3, student: 'Lena Muster', date: MON, start: '08:50', end: '09:35', period: 2, kind: 'cancelled', subject: 'E', subjectLong: 'Englisch', teacher: 'SCH', room: '104', detectedAt: Date.now() - 3600000, pushed: true },
      { id: 12, studentId: 4, student: 'Tom Muster', date: TUE, start: '08:00', end: '08:45', kind: 'extra', subject: 'PH', detectedAt: Date.now() - 7200000, pushed: false },
    ],
    messages: [
      { id: 77, accountId: 1, studentIds: [3], subject: 'Elternabend', preview: 'Liebe Eltern, am Montag …', body: 'Liebe Eltern,\nam Montag ist Elternabend.\n<script>alert(1)</script>', sender: 'Frau Schulz', sentAt: Date.now() - 86400000, hasAttachments: true, isNew: true },
    ],
    absences: [
      { id: 1, studentId: 3, date: MON, start: null, end: null, reason: 'Krank', excused: true },
      { id: 2, studentId: 3, date: TUE, start: '08:00', end: '09:30', excused: null, text: 'Arzttermin' },
    ],
  };
}

test.describe('schule', () => {
  test('no Schule plugin on the server: no "Schule" entry', async ({ launchApp, mock }) => {
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.count('/api/v1/client/plugins')).toBeGreaterThan(0);
    await expect(page.locator('#nav-schule')).toBeHidden();
  });

  test('week, states, children, changes, messages, absences', async ({ launchApp, mock }) => {
    const sc = mock.setSchool(schoolData());
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);

    await expect(page.locator('#nav-schule')).toBeVisible();
    await page.locator('#nav-schule').click();
    await expect(page.locator('#page-schule')).toHaveClass(/active/);
    const root = page.locator('#page-schule');

    // children, this week as columns (Mon … Fri)
    await expect(root.locator('.sv-kid')).toHaveCount(2);
    await expect(root.locator('.sv-kid.is-on b')).toHaveText('Lena Muster');
    await expect(root.locator('.sv-day')).toHaveCount(5);
    const mon = root.locator(`.sv-day[data-date="${MON}"]`);
    await expect(mon.locator('.sv-lesson')).toHaveCount(4);
    await expect(mon.locator('.sv-lesson.is-cancelled .sv-badge')).toHaveText(/^(Entfällt|Cancelled)$/);
    await expect(mon.locator('.sv-lesson.is-changed .sv-old')).toHaveText(['BRA', '201']);
    await expect(mon.locator('.sv-lesson.is-extra .sv-badge')).toHaveText(/^(Zusatz|Extra)$/);
    await expect(mon.locator('.sv-exam b')).toHaveText('Klassenarbeit 2');
    // server text stays text
    await expect(mon.locator('.sv-hw-text')).toHaveText('Gedicht lernen <b>bold</b>');
    await expect(root.locator(`.sv-day[data-date="${WED}"] .sv-holiday`)).toHaveText('Brückentag');
    expect(sc.log.some((r) => r.route === 'app/timetable' && r.query.from === MON)).toBe(true);
    await page.screenshot({ path: test.info().outputPath('schule-week.png') });

    // next week
    await root.locator('.sv-weeks button').nth(1).click();
    await expect(root.locator(`.sv-day[data-date="${NEXT_MON}"] .sv-lesson`)).toHaveCount(1);
    expect(sc.log.some((r) => r.route === 'app/timetable' && r.query.from === NEXT_MON)).toBe(true);
    await root.locator('.sv-weeks button').nth(0).click();

    // the other child
    await root.locator('.sv-kid').nth(1).click();
    await expect(root.locator(`.sv-day[data-date="${TUE}"] .sv-lesson`)).toHaveCount(1);
    await expect(root.locator(`.sv-day[data-date="${MON}"] .sv-free`)).toBeVisible();
    await root.locator('.sv-kid').nth(0).click();

    // tabs: Woche, Änderungen, Nachrichten, Fehlzeiten
    const tabs = root.locator('.sv-tabs button');
    await expect(tabs).toHaveCount(4);
    await tabs.nth(1).click();
    await expect(root.locator('.sv-change')).toHaveCount(1); // Lena's only
    await expect(root.locator('.sv-change .sv-badge')).toHaveText(/^(Entfällt|Cancelled)$/);
    await tabs.nth(2).click();
    await expect(root.locator('.sv-msg')).toHaveCount(1);
    await root.locator('.sv-msg-head').click();
    await expect(root.locator('.sv-msg-body')).toHaveText('Liebe Eltern,\nam Montag ist Elternabend.\n<script>alert(1)</script>');
    await page.screenshot({ path: test.info().outputPath('schule-messages.png') });
    await tabs.nth(3).click();
    await expect(root.locator('.sv-abs')).toHaveCount(2);
    await expect(root.locator('.sv-abs .sv-pill')).toHaveText([/^(Offen|Open)$/, /^(Entschuldigt|Excused)$/]);
  });

  test('plugin before 1.4.0: no messages / absences tabs', async ({ launchApp, mock }) => {
    mock.setSchool(schoolData('1.3.0'));
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-schule').click();
    const tabs = page.locator('#page-schule .sv-tabs button');
    await expect(tabs).toHaveCount(2);
  });

  test('a Schule message opens the page on its child and day', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [{ id: 'plugin:gatecontrol-schule:changes', label: 'Schule · Änderungen' }], items: [] });
    mock.setSchool(schoolData());
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect(page.locator('#nav-schule')).toBeVisible();
    mock.pushNotification({
      topic: 'plugin:gatecontrol-schule:changes', title: 'Tom: Physik zusätzlich', body: '1. Std.',
      data: { route: 'plg-gatecontrol-schule', schule: { studentId: 4, date: TUE } },
    });

    // inbox entry → "Im Stundenplan öffnen"
    await page.locator('#nav-inbox').click();
    await page.locator('#inbox-list .inbox-row').first().click();
    await page.locator('#inbox-detail .btn-pri').first().click();
    await expect(page.locator('#page-schule')).toHaveClass(/active/);
    await expect(page.locator('#page-schule .sv-kid.is-on b')).toHaveText('Tom Muster');
    await expect(page.locator(`#page-schule .sv-day.is-focus[data-date="${TUE}"]`)).toBeVisible();

    // a toast click the core claimed (notify:navigate with the Schule route)
    await page.locator('.nav[data-page="status"]').click();
    await app.evaluate(({ BrowserWindow }, ctx) => {
      BrowserWindow.getAllWindows()[0].webContents.send('notify:navigate', { route: 'plg-gatecontrol-schule', id: 1, context: ctx });
    }, { kind: 'messages', studentId: 3, date: null, messageId: 77 });
    await expect(page.locator('#page-schule')).toHaveClass(/active/);
    await expect(page.locator('#page-schule .sv-kid.is-on b')).toHaveText('Lena Muster');
    await expect(page.locator('#page-schule .sv-msg.is-open .sv-msg-body')).toBeVisible();
  });
});
