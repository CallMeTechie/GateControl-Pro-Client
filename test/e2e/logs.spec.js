'use strict';

// Page "Protokoll": electron-log ends lines with "\r\n" on Windows. Before,
// time and level stayed empty and the whole raw line was shown under
// "Meldung". Now the main process parses the file (core utils/log-parse.js):
// own columns, compact time, level chip, a stack trace stays with its entry,
// and the level filter and search work on the entries.
const fs = require('fs');
const { test, expect } = require('./support/fixtures');

const MARK = 'e2e-logmarker';

test.describe('Protokoll', () => {
  test('time, level and message in their own columns; filters and search work', async ({ launchApp }) => {
    const { page } = await launchApp();
    await page.locator('#setup-cancel').click();
    await expect(page.locator('#page-status')).toHaveClass(/active/);

    const file = await page.evaluate(() => window.gatecontrol.logs.export());
    expect(typeof file).toBe('string');
    fs.appendFileSync(file, [
      `[2026-10-24 20:58:32.553] [info]  ${MARK} Push connected (tunnel, control events)`,
      `[2026-10-24 20:58:33.100] [warn]  ${MARK} Update-Check fehlgeschlagen`,
      `[2026-10-24 20:58:34.250] [error] ${MARK} Update-Download fehlgeschlagen: ENOENT`,
      '    at Object.renameSync (node:fs:1032:11)',
      '',
    ].join('\r\n'));

    await page.locator('#nav-logs').click();
    await expect(page.locator('#page-logs')).toHaveClass(/active/);
    await page.locator('#log-search').fill(MARK);
    const rows = page.locator('#log-rows .log-row');
    await expect(rows).toHaveCount(3);

    // newest first: error (with its stack trace), warn, info
    const first = rows.nth(0);
    await expect(first.locator('.log-time')).toHaveText(/^(24\.10\.|10\/24) 20:58:34$/);
    await expect(first.locator('.log-time')).toHaveAttribute('title', '2026-10-24 20:58:34.250');
    await expect(first.locator('.log-level .chip')).toHaveText(/^(Fehler|Error)$/);
    await expect(first.locator('.log-msg')).toHaveText(`${MARK} Update-Download fehlgeschlagen: ENOENT\n    at Object.renameSync (node:fs:1032:11)`);
    await expect(rows.nth(2).locator('.log-time')).toHaveText(/^(24\.10\.|10\/24) 20:58:32$/);
    await expect(rows.nth(2).locator('.log-level .chip')).toHaveText(/^Info$/);
    await expect(rows.nth(2).locator('.log-msg')).toHaveText(`${MARK} Push connected (tunnel, control events)`);
    for (const msg of await page.locator('#log-rows .log-msg').allTextContents()) {
      expect(msg.startsWith('[')).toBe(false);
    }

    // the columns line up: the message starts right of time and level
    const [timeBox, levelBox, msgBox] = await Promise.all(['.log-time', '.log-level', '.log-msg'].map((s) => first.locator(s).boundingBox()));
    expect(levelBox.x).toBeGreaterThan(timeBox.x + timeBox.width - 1);
    expect(msgBox.x).toBeGreaterThan(levelBox.x + levelBox.width - 1);

    await page.locator('#log-level-filter [data-level="warn"]').click();
    await expect(rows).toHaveCount(1);
    await expect(rows.first().locator('.log-msg')).toHaveText(`${MARK} Update-Check fehlgeschlagen`);
    await page.locator('#log-level-filter [data-level="error"]').click();
    await expect(rows).toHaveCount(1);
    await page.locator('#log-level-filter [data-level="info"]').click();
    await expect(rows).toHaveCount(1);
    await page.locator('#log-level-filter [data-level="all"]').click();
    await page.locator('#log-search').fill('renameSync');
    await expect(rows).toHaveCount(1);
  });
});
