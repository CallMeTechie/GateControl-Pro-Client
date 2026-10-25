'use strict';

// Autostart with Windows (Pro): a Task Scheduler task from a task XML (core
// utils/autostart-task) instead of `schtasks /SC ONLOGON` with the Task
// Scheduler defaults (3-day limit, not on battery, low priority).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createAutostart, AUTOSTART_TASK } = require('../src/main/autostart');

const autostartTask = require('@gatecontrol/client-core/src/utils/autostart-task');

const EXE = 'C:\\Program Files\\GateControl Pro Client\\GateControl Pro Client.exe';

function logDouble() {
  const lines = [];
  return { lines, info: (m) => lines.push(`info ${m}`), warn: (m) => lines.push(`warn ${m}`) };
}

/** Text of the first <tag> element. */
function tag(xml, name) {
  const m = xml.match(new RegExp(`<${name}(?: [^>]*)?>([^<]*)</${name}>`));
  return m ? m[1] : null;
}

describe('autostart task (Pro)', () => {
  it('enable: schtasks /Create /F /XML with the corrected settings, in a folder under %ProgramData%', async () => {
    const programData = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-programdata-'));
    const calls = [];
    const log = logDouble();
    const set = createAutostart({
      autostartTask,
      env: { ProgramData: programData, USERDOMAIN: 'PC01', USERNAME: 'maria' },
      getExePath: () => EXE,
      getTempPath: () => { throw new Error('temp must not be used'); },
      execFile: async (file, args, opts) => {
        const xmlPath = args[args.indexOf('/XML') + 1];
        calls.push({ file, args, opts, xmlPath, xml: fs.readFileSync(xmlPath).subarray(2).toString('utf16le') });
      },
      log,
    });

    await set(true);
    assert.equal(calls.length, 1);
    const c = calls[0];
    assert.equal(c.file, 'schtasks');
    assert.deepEqual(c.args, ['/Create', '/F', '/TN', AUTOSTART_TASK, '/XML', c.xmlPath]);
    assert.equal(AUTOSTART_TASK, 'GateControlProAutostart', 'installer.nsh deletes exactly this task');
    assert.deepEqual(c.opts, { windowsHide: true });
    assert.equal(path.dirname(path.dirname(c.xmlPath)), programData);
    assert.equal(tag(c.xml, 'ExecutionTimeLimit'), 'PT0S');
    assert.equal(tag(c.xml, 'DisallowStartIfOnBatteries'), 'false');
    assert.equal(tag(c.xml, 'StopIfGoingOnBatteries'), 'false');
    assert.equal(tag(c.xml, 'Priority'), '4');
    assert.equal(tag(c.xml, 'MultipleInstancesPolicy'), 'IgnoreNew');
    assert.equal(tag(c.xml, 'RunLevel'), 'HighestAvailable');
    assert.equal(tag(c.xml, 'Delay'), 'PT10S');
    assert.equal(tag(c.xml, 'Command'), EXE);
    assert.match(c.xml, /<UserId>PC01\\maria<\/UserId>/);
    assert.ok(log.lines.includes(`info Autostart enabled: ${EXE} (task xml)`), log.lines.join('\n'));
    assert.deepEqual(fs.readdirSync(programData), [], 'task XML removed');

    // every start: replaced again (existing installations get the new task)
    await set(true);
    assert.equal(calls.length, 2);
    assert.equal(calls[1].args[1], '/F');
    fs.rmSync(programData, { recursive: true, force: true });
  });

  it('enable without %ProgramData%: the temp folder', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-temp-'));
    const dirs = [];
    const set = createAutostart({
      autostartTask,
      env: { USERNAME: 'maria' },
      getExePath: () => EXE,
      getTempPath: () => tmp,
      execFile: async (file, args) => { dirs.push(path.dirname(path.dirname(args[args.indexOf('/XML') + 1]))); },
      log: logDouble(),
    });
    await set(true);
    assert.deepEqual(dirs, [tmp]);
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('disable: schtasks /Delete', async () => {
    const calls = [];
    const log = logDouble();
    const set = createAutostart({
      autostartTask, env: {}, getExePath: () => EXE, getTempPath: () => os.tmpdir(),
      execFile: async (file, args, opts) => { calls.push([file, args, opts]); },
      log,
    });
    await set(false);
    assert.deepEqual(calls, [['schtasks', ['/Delete', '/F', '/TN', 'GateControlProAutostart'], { windowsHide: true }]]);
    assert.ok(log.lines.includes('info Autostart disabled'));
  });

  it('XML rejected: the old registration keeps the autostart working', async () => {
    const programData = fs.mkdtempSync(path.join(os.tmpdir(), 'gc-programdata-'));
    const calls = [];
    const log = logDouble();
    const set = createAutostart({
      autostartTask,
      env: { ProgramData: programData, USERNAME: 'maria' },
      getExePath: () => EXE,
      getTempPath: () => os.tmpdir(),
      execFile: async (file, args) => { calls.push(args); if (args.includes('/XML')) throw new Error('ERROR: The task XML is malformed.'); },
      log,
    });
    await set(true);
    assert.equal(calls.length, 3);
    assert.deepEqual(calls[2], ['/Create', '/F', '/TN', 'GateControlProAutostart', '/TR', `"${EXE}"`, '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/DELAY', '0000:10']);
    assert.ok(log.lines.includes(`info Autostart enabled: ${EXE} (task legacy)`));
    fs.rmSync(programData, { recursive: true, force: true });
  });
});
