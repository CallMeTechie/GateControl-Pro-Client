'use strict';

// Page "Protokoll" (src/renderer/log-view.js, no DOM): entries parsed by the
// core (logs:get { format: 'entries' }) → compact time, level groups for the
// filter buttons, search. Together with core utils/log-parse.js this covers
// the bug where time and level stayed empty and the raw line ("\r\n" line
// ends on Windows) landed in "Meldung".

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const LV = require('../src/renderer/log-view');
const { parseLogText } = require('@gatecontrol/client-core/src/utils/log-parse');

const RAW = [
  '[2026-10-24 20:58:32.553] [info]  Push connected (tunnel, control events)',
  '[2026-10-24 20:58:33.000] [warn]  Update-Check fehlgeschlagen: timeout',
  '[2026-10-24 20:58:34.250] [error] Update-Download fehlgeschlagen: ENOENT',
  '    at Object.renameSync (node:fs:1032:11)',
  '[2026-10-24 20:58:35.000] [debug] details',
  '',
].join('\r\n');

// What logs:get returns: parsed in the main process, newest first.
const entries = () => LV.toEntries(parseLogText(RAW).reverse());

describe('log view', () => {
  it('compact time, full time as tooltip', () => {
    const [, , , first] = entries();
    assert.equal(LV.formatLogTime(first, 'de'), '24.10. 20:58:32');
    assert.equal(LV.formatLogTime(first, 'en'), '10/24 20:58:32');
    assert.equal(LV.fullLogTime(first), '2026-10-24 20:58:32.553');
    assert.equal(LV.formatLogTime({ date: '', time: '' }, 'de'), '');
    assert.equal(first.level, 'info');
    assert.equal(first.msg, 'Push connected (tunnel, control events)');
  });

  it('level filter: info includes debug; warn and error on their own', () => {
    const list = entries();
    const msgs = (level) => LV.filterLogEntries(list, { level }).map((e) => e.level);
    assert.deepEqual(msgs('all'), ['debug', 'error', 'warn', 'info']);
    assert.deepEqual(msgs('info'), ['debug', 'info']);
    assert.deepEqual(msgs('warn'), ['warn']);
    assert.deepEqual(msgs('error'), ['error']);
  });

  it('search finds message text, stack trace lines and the shown time', () => {
    const list = entries();
    const find = (query) => LV.filterLogEntries(list, { query, locale: 'de' }).map((e) => e.level);
    assert.deepEqual(find('push connected'), ['info']);
    assert.deepEqual(find('renameSync'), ['error']);
    assert.deepEqual(find('24.10. 20:58:33'), ['warn']);
    assert.deepEqual(find('2026-10-24 20:58:35'), ['debug']);
    assert.deepEqual(find('  '), ['debug', 'error', 'warn', 'info']);
    assert.deepEqual(LV.filterLogEntries(list, { level: 'warn', query: 'push' }), []);
  });

  it('toEntries: drops junk, a plain string (older main process) becomes rows without time', () => {
    assert.deepEqual(LV.toEntries(null), []);
    assert.deepEqual(LV.toEntries([null, { msg: 1 }, { msg: 'x', level: 'bogus', ts: 'x' }]),
      [{ ts: null, date: '', time: '', ms: '', level: null, msg: 'x' }]);
    assert.deepEqual(LV.toEntries('a\r\nb\n').map((e) => e.msg), ['a', 'b']);
  });

  it('levelGroup', () => {
    assert.equal(LV.levelGroup('debug'), 'info');
    assert.equal(LV.levelGroup('warn'), 'warn');
    assert.equal(LV.levelGroup(null), null);
  });
});
