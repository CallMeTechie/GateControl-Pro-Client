'use strict';

// Drive plugin 1.30 on the page "Drive" (no DOM): who rings the reminder of a deadline. With `reminder.by: 'notizen'`
// the hub „Notizen & Aufgaben“ reminds (a task there, Drive sends no message of its own) — the pages "Fristen" and
// "Details" say "über Notizen & Aufgaben" beside "Erinnern N Tage vorher"; the select itself stays what it was. An
// older Drive names nobody: nothing changes. The page sets no alarm of its own for a deadline, with or without the hub.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const DD = require('../src/renderer/drive-docs-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const NOW = new Date(2026, 10, 8, 9, 30).getTime();

describe('who rings the reminder of a deadline', () => {
  const d = { id: 12, kind: 'cancellation', date: '2026-11-30', label: 'Kündigung', reminder: { at: 1, daysBefore: 3, sent: false, by: 'notizen' } };

  it('"über Notizen & Aufgaben" only while the hub rings; the select is unchanged', () => {
    const hub = DD.deadlineView(d, { t, locale: 'de', now: NOW });
    const own = DD.deadlineView({ ...d, reminder: { ...d.reminder, by: 'drive' } }, { t, locale: 'de', now: NOW });
    assert.deepEqual([hub.byHub, own.byHub], [true, false]);
    assert.deepEqual([hub.value, hub.reminder], [own.value, own.reminder]);
    assert.deepEqual([hub.value, hub.reminder], ['3', 'drive.deadline.remind.other(count=3)']);
    // an older Drive (no `by`), no reminder, nothing at all
    assert.equal(DD.deadlineView({ ...d, reminder: { at: 1, daysBefore: 3, sent: false } }, { t, now: NOW }).byHub, false);
    assert.equal(DD.deadlineView({ ...d, reminder: null }, { t, now: NOW }).byHub, false);
    assert.deepEqual([DD.remindedByHub(null), DD.remindedByHub({}), DD.remindedByHub({ reminder: { by: 'somebody' } }), DD.remindedByHub(d)], [false, false, false, true]);
    // "Erinnerung verschickt" also when the hub rang
    assert.equal(DD.deadlineView({ ...d, reminder: { ...d.reminder, sent: true } }, { t, now: NOW }).reminder, 'drive.deadline.reminded');
  });

  it('both pages show it beside the select and follow a change; no HTML strings', () => {
    for (const f of ['drive-docs-view.js', 'drive-ki-view.js']) {
      const src = read('src', 'renderer', f);
      assert.match(src, /class: 'dv-dl-by'/, f);
      assert.match(src, /t\('drive\.deadline\.byHub'\)/, f);
      assert.match(src, /DD\.remindedByHub\(d\)/, f);
      assert.doesNotMatch(src, /\.(innerHTML|outerHTML)\b|insertAdjacentHTML\(/, f);
    }
    assert.match(read('src', 'renderer', 'styles', 'drive.css'), /\.dv-dl-by\[hidden\] \{ display: none; \}/);
  });

  it('the Drive page sets no alarm of its own for a deadline (no timer, no notification from the renderer)', () => {
    for (const f of ['drive-docs-view.js', 'drive-docs-state.js', 'drive-ki-view.js', 'drive-ki-state.js']) {
      assert.doesNotMatch(read('src', 'renderer', f), /new Notification\(|setTimeout\([^)]*remind|setInterval\(/, f);
    }
  });

  it('the words exist in de and en', () => {
    const want = { de: ['über Notizen & Aufgaben', 'An diese Frist erinnert „Notizen & Aufgaben“ – mit „Erledigt“ und „Später“.'], en: ['through Notes & Tasks', '“Notes & Tasks” reminds of this deadline – with “Done” and “Later”.'] };
    for (const lang of ['de', 'en']) {
      const dl = JSON.parse(read('src', 'i18n', `${lang}.json`)).drive.deadline;
      assert.deepEqual([dl.byHub, dl.byHubHint], want[lang]);
    }
  });
});
