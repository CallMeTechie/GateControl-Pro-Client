'use strict';

/**
 * Fake gc-drive-sync.exe for the e2e runs (loaded by app-hooks.js into the
 * Electron main process, never packaged): `spawn` returns a child-process
 * double whose first stdout line is the ready line, and the "pipe" is a real
 * named pipe (Windows) / unix socket served in this process with the JSON line
 * protocol of drive-sync/PROTOCOL.md. No sync root, no registry, no Known
 * Folder is touched.
 *
 * Tests steer it through globalThis.__gcE2E.driveSyncFake (electronApp.evaluate):
 *   received            commands seen ({ cmd, … }, never the token)
 *   massDelete(files)   status event with a held mass delete
 *   action(a, node)     Explorer menu event (share | versions | portal)
 *   unsynced = n        `unregister` without force fails with n paths
 */

const net = require('net');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { PassThrough } = require('stream');

const KNOWN = ['desktop', 'documents', 'pictures', 'videos', 'music'];
const LEAF = { desktop: 'Desktop', documents: 'Documents', pictures: 'Pictures', videos: 'Videos', music: 'Music' };

function createDriveSyncFake({ dir }) {
  const sep = process.platform === 'win32' ? '\\' : '/';
  const root = [dir, 'GateControl Drive'].join(sep);
  const profile = [dir, 'profile'].join(sep);
  const fake = {
    received: [],
    unsynced: 0,
    // Map: folder names come over the pipe, never used as object keys
    known: new Map(KNOWN.map((k) => [k, { path: [profile, LEAF[k]].join(sep), inDrive: false, from: null }])),
    status: { state: 'stopped', pending: 0, transferring: 0, errors: [], lastSync: null, syncRoot: root, registered: false, massDelete: null, elevated: false },
    conn: null,
    send(obj) { if (fake.conn) fake.conn.write(`${JSON.stringify(obj)}\n`); },
    pushStatus(patch) { Object.assign(fake.status, patch || {}); fake.send({ event: 'status', ...fake.status }); },
    massDelete(files) { fake.pushStatus({ massDelete: { files, items: 1, offline: false, sample: [`${root}${sep}Meine Dateien${sep}Fotos`] }, errors: [{ code: 'mass_delete', message: `${files} Dateien`, at: new Date().toISOString() }] }); return true; },
    action(action, node) { fake.send({ event: 'action', action, path: `${root}${sep}Meine Dateien${sep}Brief.pdf`, node, area: 'mine:1', isDir: false }); return true; },
  };

  function handle(msg, reply, fail) {
    const { token, ...seen } = msg; // eslint-disable-line no-unused-vars
    fake.received.push(seen);
    switch (msg.cmd) {
      case 'hello': return reply({ protocol: 2, version: '0.1.0', pid: 4242, syncRoot: root, state: fake.status.state, elevated: false, knownFolders: true });
      case 'configure': return reply({ configured: true });
      case 'start':
        reply({ ...fake.status, state: 'starting', registered: true });
        return fake.pushStatus({ state: 'idle', registered: true, lastSync: new Date().toISOString() });
      case 'status': return reply(fake.status);
      case 'sync-now': return reply({ queued: true });
      case 'pause': reply({ paused: true }); return fake.pushStatus({ state: 'paused' });
      case 'resume': reply({ paused: false }); return fake.pushStatus({ state: 'idle' });
      case 'usage': return reply({ localBytes: 3435973837, totalBytes: 197568495616, files: 4210, localFiles: 312, pinnedFiles: 40 });
      case 'known-folders':
        return reply({ syncRoot: root, folders: KNOWN.map((k) => ({ key: k, ...fake.known.get(k) })) });
      case 'relocate': {
        const key = KNOWN.find((x) => x === msg.folder);
        const k = key ? fake.known.get(key) : null;
        if (!k || k.inDrive) return fail('already_relocated', 'x');
        const to = [root, 'Meine Dateien', typeof msg.name === 'string' ? msg.name : key].join(sep);
        fake.send({ event: 'progress', op: 'relocate', folder: msg.folder, phase: 'move', done: 1, total: 3 });
        setTimeout(() => {
          fake.known.set(key, { path: to, inDrive: true, from: k.path });
          reply({ folder: msg.folder, from: k.path, to, moved: 3 });
        }, 300);
        return undefined;
      }
      case 'restore': {
        const key = KNOWN.find((x) => x === msg.folder);
        const k = key ? fake.known.get(key) : null;
        if (!k || !k.inDrive) return fail('not_relocated', 'x');
        fake.send({ event: 'progress', op: 'restore', folder: msg.folder, phase: 'load', done: 2, total: 5 });
        setTimeout(() => {
          fake.known.set(key, { path: k.from, inDrive: false, from: null });
          reply({ folder: msg.folder, from: k.path, to: k.from, moved: 3 });
        }, 300);
        return undefined;
      }
      case 'deletes':
        reply({ decided: 1, apply: msg.decision === 'apply' });
        return fake.pushStatus({ massDelete: null, errors: [] });
      case 'action':
        reply({ queued: true });
        return fake.action(msg.action, 11);
      case 'unregister': {
        const rel = KNOWN.filter((k) => fake.known.get(k).inDrive);
        if (rel.length) return fail('relocated', 'Windows-Ordner liegen im Drive', { folders: rel });
        if (fake.unsynced > 0 && !msg.force) {
          return fail('unsynced', `${fake.unsynced} Änderungen`, { count: fake.unsynced, paths: [`${root}${sep}Meine Dateien${sep}Notiz.txt`] });
        }
        fake.status.registered = false;
        return reply({ unregistered: true });
      }
      case 'shutdown': return reply({ shutdown: true });
      default: return fail('unknown_command', 'x');
    }
  }

  function spawn(_exe, args) {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => { setImmediate(() => child.emit('exit', 1)); return true; };
    if (args[0] === 'unregister') {
      setImmediate(() => { child.stdout.end('{"unregistered":true}\n'); child.emit('exit', 0); });
      return child;
    }
    const id = crypto.randomBytes(8).toString('hex');
    const name = process.platform === 'win32'
      ? `\\\\.\\pipe\\gatecontrol-drive-sync-S-1-5-21-0-0-0-1001-${id}`
      : path.join(os.tmpdir(), `gcds-e2e-${process.pid}-${id}.sock`);
    const server = net.createServer((c) => {
      fake.conn = c;
      let buf = '';
      c.setEncoding('utf8');
      c.on('data', (d) => {
        buf += d;
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          let msg;
          try { msg = JSON.parse(buf.slice(0, i)); } catch { msg = null; }
          buf = buf.slice(i + 1);
          if (!msg) continue;
          const reply = (result) => c.write(`${JSON.stringify({ id: msg.id, ok: true, result })}\n`);
          const fail = (code, message, data) => c.write(`${JSON.stringify({ id: msg.id, ok: false, error: { code, message, ...(data ? { data } : {}) } })}\n`);
          handle(msg, reply, fail);
          if (msg.cmd === 'shutdown') setTimeout(() => { c.end(); server.close(); child.emit('exit', 0); }, 20);
        }
      });
    });
    server.listen(name, () => {
      child.stdout.write(`${JSON.stringify({ event: 'ready', pipe: name, pid: 4242, version: '0.1.0', protocol: 2, launch: 'token', elevated: false })}\n`);
    });
    return child;
  }

  return { fake, spawn };
}

module.exports = { createDriveSyncFake };
