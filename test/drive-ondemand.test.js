'use strict';

// Drive „Dateien bei Bedarf“ (src/main/drive-ondemand.js) mit einem
// Fake-gc-drive-sync: spawn liefert ein Kindprozess-Double, das die
// Ready-Zeile schreibt; die „Pipe“ ist ein lokaler Socket mit dem
// JSON-Zeilen-Protokoll aus drive-sync/PROTOCOL.md.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { createDriveOnDemand, defaultExePath, pickHeaders, PIPE_RE } = require('../src/main/drive-ondemand');

const TOKEN = 'gc_secret_token_1';

function memStore(init = {}) {
  const data = { ...init };
  return { get: (k, d) => (k in data ? data[k] : d), set: (k, v) => { data[k] = v; }, data };
}

const servers = [];
const conns = [];
afterEach(() => {
  while (conns.length) conns.pop().destroy();
  while (servers.length) servers.pop().close();
});

/** Fake-Programm: Socket-Server + Kindprozess-Double. */
function fakeProgram({ ready = true, failCmd = null } = {}) {
  const prog = { spawned: [], received: [], args: null, child: null, conn: null };
  const spawn = (exe, args, opts) => {
    prog.spawned.push({ exe, args, opts });
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.killed = false;
    child.kill = () => { child.killed = true; setImmediate(() => child.emit('exit', 1)); };
    prog.child = child;
    if (args[0] === 'unregister') {
      setImmediate(() => { child.stdout.end('{"unregistered":true}\n'); child.emit('exit', 0); });
      return child;
    }
    const sockPath = process.platform === 'win32'
      ? `\\\\.\\pipe\\gcds-test-${process.pid}-${Math.random().toString(16).slice(2)}`
      : path.join(os.tmpdir(), `gcds-${process.pid}-${Math.random().toString(16).slice(2)}.sock`);
    const server = net.createServer((c) => {
      prog.conn = c;
      conns.push(c);
      let buf = '';
      c.setEncoding('utf8');
      c.on('data', (d) => {
        buf += d;
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const msg = JSON.parse(buf.slice(0, i));
          buf = buf.slice(i + 1);
          prog.received.push(msg);
          const reply = (result) => c.write(`${JSON.stringify({ id: msg.id, ok: true, result })}\n`);
          if (msg.cmd === failCmd) {
            c.write(`${JSON.stringify({ id: msg.id, ok: false, error: { code: 'register_failed', message: 'nope' } })}\n`);
            continue;
          }
          switch (msg.cmd) {
            case 'hello': reply({ protocol: 1, version: '0.1.0' }); break;
            case 'configure': reply({ configured: true }); break;
            case 'start':
              reply({ state: 'starting', pending: 0, transferring: 0, errors: [], lastSync: null });
              c.write(`${JSON.stringify({ event: 'status', state: 'idle', pending: 0, transferring: 0, errors: [], lastSync: '2026-10-27T10:00:00Z' })}\n`);
              c.write(`${JSON.stringify({ event: 'log', level: 'info', message: 'Abgleich gestartet' })}\n`);
              break;
            case 'shutdown':
              reply({ shutdown: true });
              setImmediate(() => { c.end(); server.close(); child.emit('exit', 0); });
              break;
            default: reply({ ok: msg.cmd });
          }
        }
      });
    });
    servers.push(server);
    server.listen(sockPath, () => {
      if (ready) child.stdout.write(`${JSON.stringify({ event: 'ready', pipe: sockPath, pid: 4242, version: '0.1.0', protocol: 1 })}\n`);
      else child.stdout.write('{"event":"error","code":"already_running","message":"läuft"}\n');
    });
    return child;
  };
  return { prog, spawn };
}

function make(extra = {}) {
  const store = extra.store || memStore({ 'server.url': 'https://gc.example.de', 'server.apiKey': TOKEN, 'driveOnDemand.enabled': true });
  const statuses = [];
  const logs = [];
  const log = { info: (m) => logs.push(m), warn: (m) => logs.push(m), error: (m) => logs.push(m), debug() {} };
  const { prog, spawn } = fakeProgram(extra.program);
  const dod = createDriveOnDemand({
    store, log,
    getServer: () => ({ url: store.get('server.url', ''), apiKey: store.get('server.apiKey', '') }),
    getHeaders: () => ({ 'X-API-Token': TOKEN, 'X-Client-Version': '1.49.0', 'X-Machine-Fingerprint': 'ab12', Evil: 'x' }),
    getDeviceName: () => 'PC-Max',
    exePath: 'C:\\Program Files\\GateControl Pro Client\\resources\\drive-sync\\gc-drive-sync.exe',
    appVersion: '1.49.0',
    spawn,
    exists: () => true,
    platform: 'win32',
    parentPid: 777,
    pipePattern: /.+/,
    onStatus: (s) => statuses.push(s),
    ...extra.opts,
  });
  return { dod, store, prog, statuses, logs };
}

const waitFor = async (f) => {
  for (let i = 0; i < 200; i++) {
    if (f()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error('timeout');
};

describe('drive-ondemand', () => {
  it('ist standardmäßig aus und startet dann nichts', async () => {
    const { dod, prog } = make({ store: memStore({ 'server.url': 'https://x', 'server.apiKey': TOKEN }) });
    assert.equal(dod.isEnabled(), false);
    assert.equal(await dod.start(), false);
    assert.equal(prog.spawned.length, 0);
    assert.equal(dod.status().state, 'disabled');
  });

  it('startet, schickt configure nur über die Pipe und leitet Status weiter', async () => {
    const { dod, prog, statuses, logs } = make();
    assert.equal(await dod.start(), true);
    const sp = prog.spawned[0];
    assert.deepEqual(sp.args, ['run', '--parent-pid', '777']);
    assert.ok(!JSON.stringify(sp).includes(TOKEN), 'token not on the command line');
    assert.ok(!sp.opts.env, 'no own environment with secrets');
    assert.deepEqual(prog.received.map((m) => m.cmd), ['hello', 'configure', 'start']);
    const cfg = prog.received[1];
    assert.equal(cfg.serverUrl, 'https://gc.example.de');
    assert.equal(cfg.token, TOKEN);
    assert.equal(cfg.deviceName, 'PC-Max');
    assert.deepEqual(cfg.headers, { 'X-Client-Version': '1.49.0', 'X-Machine-Fingerprint': 'ab12' });
    await waitFor(() => statuses.some((s) => s.state === 'idle'));
    assert.equal(dod.status().lastSync, '2026-10-27T10:00:00Z');
    assert.ok(logs.some((l) => l.includes('[drive-sync] Abgleich gestartet')));
    assert.ok(!logs.some((l) => l.includes(TOKEN)));

    const r = await dod.syncNow();
    assert.deepEqual(r, { ok: 'sync-now' });
    await dod.stop();
    assert.equal(prog.received.at(-1).cmd, 'shutdown');
  });

  it('konfiguriert neu, wenn sich Server oder Token ändern', async () => {
    const { dod, prog, store } = make();
    await dod.start();
    await dod.serverChanged(); // unverändert → nichts
    assert.equal(prog.received.filter((m) => m.cmd === 'configure').length, 1);
    store.set('server.apiKey', 'gc_new_token');
    await dod.serverChanged();
    const cfgs = prog.received.filter((m) => m.cmd === 'configure');
    assert.equal(cfgs.length, 2);
    assert.equal(cfgs[1].token, 'gc_new_token');
    await dod.stop();
  });

  it('ohne Server, ohne Windows oder ohne Exe: kein Start', async () => {
    let t = make({ store: memStore({ 'driveOnDemand.enabled': true }) });
    assert.equal(await t.dod.start(), false);
    assert.equal(t.dod.status().state, 'unconfigured');
    t = make({ opts: { platform: 'linux' } });
    assert.equal(await t.dod.start(), false);
    assert.equal(t.dod.status().state, 'unsupported');
    t = make({ opts: { exists: () => false } });
    assert.equal(await t.dod.start(), false);
    assert.equal(t.dod.status().state, 'missing');
    assert.equal(t.prog.spawned.length, 0);
  });

  it('setEnabled schaltet ein und aus', async () => {
    const { dod, prog, store } = make({ store: memStore({ 'server.url': 'https://x', 'server.apiKey': TOKEN }) });
    await dod.setEnabled(true);
    assert.equal(store.data['driveOnDemand.enabled'], true);
    assert.equal(prog.spawned.length, 1);
    await dod.setEnabled(false);
    assert.equal(store.data['driveOnDemand.enabled'], false);
    assert.equal(dod.status().state, 'disabled');
  });

  it('Fehler beim Start werden gemeldet', async () => {
    const { dod, statuses } = make({ program: { failCmd: 'start' } });
    assert.equal(await dod.start(), false);
    const last = statuses.at(-1);
    assert.equal(last.state, 'error');
    assert.equal(last.errors[0].code, 'register_failed');
  });

  it('eine unerwartete erste Zeile führt nicht zur Verbindung', async () => {
    const noTimers = { setTimeout: () => 0, clearTimeout() {} };
    const { dod, prog, logs } = make({ program: { ready: false }, opts: { timers: noTimers } });
    assert.equal(await dod.start(), false);
    assert.ok(prog.child.killed);
    assert.ok(logs.some((l) => l.includes('already_running')));
  });

  it('startet neu, wenn das Programm unerwartet endet', async () => {
    const timers = [];
    const { dod, prog } = make({ opts: { timers: { setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, clearTimeout() {} } } });
    // Die Bereit-Wartezeit nutzt dieselben Timer; die Antworten kommen vorher.
    await dod.start();
    prog.child.emit('exit', 5);
    const restart = timers.find((t) => t.ms === 5000);
    assert.ok(restart, 'restart scheduled after 5 s');
    assert.equal(dod.status().state, 'error');
    restart.fn();
    await waitFor(() => prog.spawned.length === 2);
  });

  it('unregister ohne laufendes Programm ruft „gc-drive-sync unregister“', async () => {
    const { dod, prog, store } = make({ store: memStore({ 'server.url': 'https://x', 'server.apiKey': TOKEN }) });
    const r = await dod.unregister();
    assert.deepEqual(r, { unregistered: true });
    assert.deepEqual(prog.spawned[0].args, ['unregister']);
    assert.equal(store.data['driveOnDemand.enabled'], false);
  });

  it('unregister bei laufendem Programm über die Pipe', async () => {
    const { dod, prog } = make();
    await dod.start();
    await dod.unregister();
    const cmds = prog.received.map((m) => m.cmd);
    assert.ok(cmds.includes('unregister'));
    assert.equal(cmds.at(-1), 'shutdown');
  });

  it('Push-Ereignis „changed“ des Plugins stößt sync-now an', async () => {
    const { dod, prog } = make();
    await dod.start();
    const push = new EventEmitter();
    dod.watchPush(push);
    push.emit('event', { event: 'plugin', data: { plugin: 'gatecontrol-vault', type: 'changed' } });
    push.emit('event', { event: 'plugin', data: { plugin: 'gatecontrol-drive', type: 'changed', areas: ['mine:1'] } });
    await waitFor(() => prog.received.some((m) => m.cmd === 'sync-now'));
    assert.equal(prog.received.filter((m) => m.cmd === 'sync-now').length, 1);
    await dod.stop();
  });

  it('Hilfsfunktionen', () => {
    assert.deepEqual(pickHeaders({ 'X-API-Token': 't', 'X-Client-Type': 'pro', 'X-Client-Version': 'a\nb' }), { 'X-Client-Type': 'pro' });
    assert.ok(PIPE_RE.test('\\\\.\\pipe\\gatecontrol-drive-sync-S-1-5-21-1-2-3-1001-0123456789abcdef0123456789abcdef'));
    assert.ok(!PIPE_RE.test('\\\\server\\pipe\\gatecontrol-drive-sync-x'));
    assert.ok(!PIPE_RE.test('\\\\.\\pipe\\other'));
    assert.equal(defaultExePath({ isPackaged: true, resourcesPath: 'R', appRoot: 'A' }), path.join('R', 'drive-sync', 'gc-drive-sync.exe'));
    assert.equal(defaultExePath({ isPackaged: false, resourcesPath: 'R', appRoot: 'A' }), path.join('A', 'drive-sync', 'target', 'release', 'gc-drive-sync.exe'));
  });

  it('package.json nimmt gc-drive-sync.exe in den Installer auf', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
    const e = pkg.build.extraResources.find((x) => x.to === 'drive-sync/');
    assert.ok(e, 'extraResources drive-sync');
    assert.deepEqual(e.filter, ['gc-drive-sync.exe']);
  });
});

describe('drive-ondemand IPC', () => {
  const { driveOnDemandChannels } = require('../src/main/drive-ondemand');
  const log = { warn() {} };

  it('ohne Dienst: unsupported', async () => {
    const ch = driveOnDemandChannels(null, log);
    assert.equal(ch['drive-ondemand:status']().state, 'unsupported');
    assert.deepEqual(await ch['drive-ondemand:sync-now'](), { ok: false, code: 'unsupported' });
  });

  it('leitet an den Dienst weiter, Fehler mit code', async () => {
    const calls = [];
    const dod = {
      status: () => ({ state: 'idle', enabled: true }),
      setEnabled: async (on) => { calls.push(['enabled', on]); return on; },
      syncNow: async () => { throw Object.assign(new Error('x'), { code: 'not_running' }); },
      pause: async () => ({ paused: true }),
      resume: async () => ({ paused: false }),
      unregister: async () => ({ unregistered: true }),
    };
    const ch = driveOnDemandChannels(dod, log);
    assert.equal(ch['drive-ondemand:status']().state, 'idle');
    assert.deepEqual(await ch['drive-ondemand:set-enabled']({}, 'yes'), { ok: true, result: false });
    assert.deepEqual(calls, [['enabled', false]]);
    assert.deepEqual(await ch['drive-ondemand:sync-now'](), { ok: false, code: 'not_running' });
    assert.deepEqual(await ch['drive-ondemand:pause'](), { ok: true, result: { paused: true } });
    assert.deepEqual(await ch['drive-ondemand:unregister'](), { ok: true, result: { unregistered: true } });
  });
});
