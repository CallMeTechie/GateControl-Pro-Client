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
const { createDriveOnDemand, defaultExePath, pickHeaders, parseActionArgv, overlaps, PIPE_RE } = require('../src/main/drive-ondemand');

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
function fakeProgram({ ready = true, failCmd = null, handlers = {}, readyExtra = {} } = {}) {
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
          if (handlers[msg.cmd]) {
            const fail = (code, data) => c.write(`${JSON.stringify({ id: msg.id, ok: false, error: { code, message: code, ...(data ? { data } : {}) } })}\n`);
            handlers[msg.cmd](msg, reply, fail, (ev) => c.write(`${JSON.stringify(ev)}\n`));
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
      if (ready) child.stdout.write(`${JSON.stringify({ event: 'ready', pipe: sockPath, pid: 4242, version: '0.1.0', protocol: 2, launch: 'token', elevated: false, ...readyExtra })}\n`);
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
    assert.deepEqual(sp.args, ['launch', '--parent-pid', '777']);
    assert.ok(!JSON.stringify(sp).includes(TOKEN), 'token not on the command line');
    assert.ok(!sp.opts.env, 'no own environment with secrets');
    assert.deepEqual(prog.received.map((m) => m.cmd), ['hello', 'configure', 'start']);
    assert.equal(prog.received[0].lang, 'de');
    assert.equal(dod.status().launch, 'token');
    assert.equal(dod.status().elevated, false);
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

  it('ausschalten, wenn es schon aus ist: „gc-drive-sync unregister“ räumt auf', async () => {
    const { dod, prog, store } = make({ store: memStore({ 'server.url': 'https://x', 'server.apiKey': TOKEN }) });
    const r = await dod.disable();
    assert.deepEqual(r, { unregistered: true });
    assert.deepEqual(prog.spawned[0].args, ['unregister']);
    assert.equal(store.data['driveOnDemand.enabled'], false);
  });

  it('ausschalten bei laufendem Programm: unregister über die Pipe, dann Ende', async () => {
    const { dod, prog, store } = make();
    await dod.start();
    await dod.disable();
    const cmds = prog.received.map((m) => m.cmd);
    assert.ok(cmds.includes('unregister'));
    assert.equal(prog.received.find((m) => m.cmd === 'unregister').force, false);
    assert.equal(cmds.at(-1), 'shutdown');
    assert.equal(store.data['driveOnDemand.enabled'], false);
  });

  it('ausschalten bricht ab, solange etwas nicht hochgeladen ist oder Windows-Ordner im Drive liegen', async () => {
    let answer = 'unsynced';
    const { dod, prog, store } = make({ program: { handlers: {
      unregister: (m, reply, fail) => {
        if (m.force) return reply({ unregistered: true });
        if (answer === 'unsynced') return fail('unsynced', { count: 2, paths: ['C:\\GateControl Drive\\a.txt', 'C:\\GateControl Drive\\b.txt'] });
        return fail('relocated', { folders: ['documents'] });
      },
    } } });
    await dod.start();
    await assert.rejects(dod.disable(), (e) => e.code === 'unsynced' && e.data.count === 2 && e.data.paths.length === 2);
    assert.equal(store.data['driveOnDemand.enabled'], true, 'bleibt an');
    assert.equal(dod.status().running, true);
    assert.equal(dod.status().busy, null);
    answer = 'relocated';
    await assert.rejects(dod.disable(), (e) => e.code === 'relocated' && e.data.folders[0] === 'documents');
    // ausdrücklich: Dateien bleiben als normale Dateien
    await dod.disable({ force: true });
    assert.equal(prog.received.filter((m) => m.cmd === 'unregister').at(-1).force, true);
    assert.equal(store.data['driveOnDemand.enabled'], false);
  });

  it('Windows-Ordner: Liste, Verlegen (nicht bei „Ordner sichern“), Zurücklegen, Fortschritt', async () => {
    const statuses = [];
    const known = { syncRoot: 'C:\\Users\\Max\\GateControl Drive', folders: [{ key: 'documents', path: 'C:\\Users\\Max\\Documents', inDrive: false }, { key: 'music', path: 'C:\\Users\\Max\\Music', inDrive: false }] };
    const { dod, prog } = make({
      opts: { relocateBlocked: (p) => (p.endsWith('Music') ? 'w2_active' : null), onStatus: (s) => statuses.push(s) },
      program: { handlers: {
        'known-folders': (m, reply) => reply(known),
        relocate: (m, reply, fail, ev) => { ev({ event: 'progress', op: 'relocate', folder: m.folder, phase: 'move', done: 1, total: 2 }); setTimeout(() => reply({ folder: m.folder, moved: 2 }), 20); },
        restore: (m, reply) => reply({ folder: m.folder, moved: 2 }),
      } },
    });
    await dod.start();
    assert.deepEqual((await dod.knownFolders()).folders.map((f) => f.key), ['documents', 'music']);
    await assert.rejects(dod.relocate('music'), (e) => e.code === 'w2_active');
    assert.ok(!prog.received.some((m) => m.cmd === 'relocate'), 'nicht gesendet');
    await assert.rejects(dod.relocate('windows'), (e) => e.code === 'invalid');
    const r = await dod.relocate('documents', 'Dokumente');
    assert.equal(r.moved, 2);
    assert.deepEqual(prog.received.find((m) => m.cmd === 'relocate'), { id: prog.received.find((m) => m.cmd === 'relocate').id, cmd: 'relocate', folder: 'documents', name: 'Dokumente' });
    assert.ok(statuses.some((s) => s.busy && s.busy.kind === 'relocate' && s.progress && s.progress.done === 1));
    assert.equal(dod.status().busy, null);
    await dod.restore('documents');
    assert.ok(prog.received.some((m) => m.cmd === 'restore' && m.folder === 'documents'));
    await dod.stop();
  });

  it('Massenlöschung im Status, Antwort, Kontextmenü-Ereignis, belegter Platz', async () => {
    const actions = [];
    const { dod, prog } = make({
      opts: { onAction: (a) => actions.push(a) },
      program: { handlers: {
        usage: (m, reply) => reply({ localBytes: 10, totalBytes: 100 }),
        deletes: (m, reply, fail, ev) => { reply({ decided: 1 }); ev({ event: 'status', state: 'idle', massDelete: null }); },
        'sync-now': (m, reply, fail, ev) => {
          reply({ queued: true });
          ev({ event: 'status', state: 'idle', massDelete: { files: 30, items: 1, offline: false, sample: ['C:\\x\\Fotos'] } });
          ev({ event: 'action', action: 'share', path: 'C:\\x\\a.pdf', node: 7, area: 'mine:1', isDir: false });
          ev({ event: 'action', action: 'rm', path: 'C:\\x' });
        },
      } },
    });
    await dod.start();
    await dod.syncNow();
    await waitFor(() => dod.status().massDelete && actions.length === 1);
    assert.equal(dod.status().massDelete.files, 30);
    assert.deepEqual(actions[0], { action: 'share', path: 'C:\\x\\a.pdf', node: 7, area: 'mine:1', isDir: false });
    await assert.rejects(dod.deletes('maybe'), (e) => e.code === 'invalid');
    await dod.deletes('restore');
    await waitFor(() => dod.status().massDelete === null);
    assert.ok(prog.received.some((m) => m.cmd === 'deletes' && m.decision === 'restore'));
    assert.deepEqual(await dod.usage(), { localBytes: 10, totalBytes: 100 });
    await dod.stop();
  });

  it('Start mit Administratorrechten wird angezeigt; falsches Konto ist ein Fehler', async () => {
    let t = make({ program: { readyExtra: { launch: 'inprocess', elevated: true } } });
    await t.dod.start();
    assert.equal(t.dod.status().elevated, true);
    assert.ok(t.logs.some((l) => l.includes('Administratorrechten')));
    await t.dod.stop();
    t = make({ program: { ready: false }, opts: { timers: { setTimeout: () => 0, clearTimeout() {} } } });
    assert.equal(await t.dod.start(), false);
    assert.equal(t.dod.status().state, 'error');
  });

  it('Kontextmenü über Argumente, gesperrte Pfade für „Ordner sichern“, Ordner öffnen', async () => {
    const opened = [];
    const { dod, prog } = make({ opts: { openPath: async (p) => { opened.push(p); return ''; } }, program: { handlers: {
      start: (m, reply, fail, ev) => { reply({ state: 'idle', syncRoot: 'C:\\Users\\Max\\GateControl Drive', registered: true }); ev({ event: 'status', state: 'idle', syncRoot: 'C:\\Users\\Max\\GateControl Drive', registered: true }); },
      action: (m, reply) => reply({ queued: true }),
    } } });
    await dod.start();
    await waitFor(() => dod.syncRoot());
    assert.deepEqual(dod.blockedPaths(), ['C:\\Users\\Max\\GateControl Drive']);
    await dod.openRoot();
    assert.deepEqual(opened, ['C:\\Users\\Max\\GateControl Drive']);
    await dod.action({ action: 'versions', path: 'C:\\Users\\Max\\GateControl Drive\\a.txt' });
    assert.ok(prog.received.some((m) => m.cmd === 'action' && m.action === 'versions'));
    await assert.rejects(dod.action({ action: 'format', path: 'C:\\' }), (e) => e.code === 'invalid');
    await dod.stop();
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
    assert.deepEqual(parseActionArgv(['x.exe', '--drive-action', 'share', '--drive-path', 'C:\\a b\\c.txt']), { action: 'share', path: 'C:\\a b\\c.txt' });
    assert.equal(parseActionArgv(['x.exe', '--drive-action', 'delete', '--drive-path', 'C:\\a']), null);
    assert.equal(parseActionArgv(['x.exe', '--drive-action', 'share']), null);
    assert.ok(overlaps('C:\\Users\\Max\\Documents', 'c:\\users\\max\\documents\\'));
    assert.ok(overlaps('C:\\Users\\Max', 'C:\\Users\\Max\\Documents'));
    assert.ok(!overlaps('C:\\Users\\Max\\Documents2', 'C:\\Users\\Max\\Documents'));
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
      disable: async (o) => { calls.push(['disable', o.force]); if (!o.force) throw Object.assign(new Error('x'), { code: 'unsynced', data: { count: 1, paths: ['a'] } }); return { unregistered: true }; },
      relocate: async (f, n) => { calls.push(['relocate', f, n]); return { moved: 1 }; },
    };
    const ch = driveOnDemandChannels(dod, log);
    assert.equal(ch['drive-ondemand:status']().state, 'idle');
    assert.deepEqual(await ch['drive-ondemand:set-enabled']({}, 'yes'), { ok: true, result: false });
    assert.deepEqual(calls, [['enabled', false]]);
    assert.deepEqual(await ch['drive-ondemand:sync-now'](), { ok: false, code: 'not_running' });
    assert.deepEqual(await ch['drive-ondemand:pause'](), { ok: true, result: { paused: true } });
    assert.deepEqual(await ch['drive-ondemand:disable']({}, { force: 'yes' }), { ok: false, code: 'unsynced', data: { count: 1, paths: ['a'] } });
    assert.deepEqual(await ch['drive-ondemand:disable']({}, { force: true }), { ok: true, result: { unregistered: true } });
    assert.deepEqual(await ch['drive-ondemand:relocate']({}, 'music', { evil: 1 }), { ok: true, result: { moved: 1 } });
    assert.deepEqual(calls.slice(1), [['disable', false], ['disable', true], ['relocate', 'music', null]]);
  });
});
