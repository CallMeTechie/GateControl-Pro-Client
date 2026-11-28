'use strict';

/**
 * Fake gc-rdp-host.exe (Remotedesktop im GateControl-Fenster) for the unit tests of RdpManager and the e2e runs
 * (loaded by app-hooks.js into the Electron main process, never packaged). `spawn` returns a child-process
 * double that speaks the line protocol of rdp-host/Program.cs on its stdin / stdout: a ready line, and for a
 * connect the states connecting → connected → loggedin. No window, no RDP control, no connection.
 *
 * Steered through `fake` (in e2e: globalThis.__gcE2E.rdpHostFake via electronApp.evaluate):
 *   spawns              [{ file, args }] — the command lines (never credentials)
 *   received            the messages the app sent, in order ({ type, … }, the connect with its password)
 *   failStart           null | 'error' (spawn fails) | 'exit' (exits before ready) | 'silent' (no ready line)
 *   autoLogin           false: a connect stays at "connecting"
 *   disconnect(r, e, u) the session ends (reason, ext, byUser); byUser closes the window like the real host
 *   action(a)           a button of the error view: 'reconnect' | 'mstsc'
 *   setting(k, v)       the bar changed a setting ('drives', true)
 *   mstsc               [{ args }] — launches of Windows-Remotedesktop (the recorded mstsc of app-hooks)
 */

const { EventEmitter } = require('events');
const { PassThrough, Writable } = require('stream');

function createRdpHostFake() {
  const fake = {
    spawns: [],
    received: [],
    failStart: null,
    autoLogin: true,
    children: [],
    mstsc: [],
    stored: [],
    get child() { return fake.children[fake.children.length - 1] || null; },
    disconnect(reason = 3, ext = 5, byUser = false) { const c = fake.child; if (c) c.disconnect(reason, ext, byUser); return true; },
    action(action) { const c = fake.child; if (c) c.out({ type: 'action', action }); return true; },
    setting(key, value) { const c = fake.child; if (c) c.out({ type: 'setting', key, value }); return true; },
    messages(type) { return fake.received.filter((m) => m.type === type); },
  };

  let nextPid = 7100;

  function spawn(file, args) {
    fake.spawns.push({ file, args: [...(args || [])] });
    const child = new EventEmitter();
    child.pid = nextPid++;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.exited = false;
    child.connected = false;
    let buf = '';
    child.stdin = new Writable({
      write(chunk, enc, cb) {
        buf += chunk.toString('utf8');
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i);
          buf = buf.slice(i + 1);
          let msg = null;
          try { msg = JSON.parse(line); } catch { msg = { type: 'invalid' }; }
          fake.received.push(msg);
          setImmediate(() => onMessage(msg));
        }
        cb();
      },
      final(cb) { setImmediate(() => child.shutdown()); cb(); },
    });
    child.out = (msg) => { if (!child.exited) child.stdout.write(`${JSON.stringify(msg)}\n`); };
    child.exit = (code = 0) => {
      if (child.exited) return;
      child.exited = true;
      child.emit('exit', code, null);
    };
    child.kill = () => { child.exit(1); return true; };
    child.disconnect = (reason, ext, byUser) => {
      if (!child.connected) return;
      child.connected = false;
      child.out({ type: 'disconnected', reason, ext, text: 'Die Remotesitzung wurde getrennt.', byUser });
      if (byUser) child.close();
    };
    child.close = () => {
      if (child.connected) { child.disconnect(1, 0, true); return; }
      child.out({ type: 'closed' });
      setImmediate(() => child.exit(0));
    };
    child.shutdown = () => child.close();

    function onMessage(msg) {
      switch (msg.type) {
        case 'connect':
          child.out({ type: 'state', state: 'connecting' });
          if (!fake.autoLogin) return;
          setTimeout(() => {
            child.connected = true;
            child.out({ type: 'state', state: 'connected' });
            child.out({ type: 'state', state: 'loggedin' });
            child.out({ type: 'network', quality: 4, rttMs: 14, bandwidthKbps: 100000 });
          }, 20);
          return;
        case 'disconnect':
        case 'close':
          child.close();
          return;
        default:
      }
    }

    fake.children.push(child);
    if (fake.failStart === 'error') {
      setImmediate(() => child.emit('error', Object.assign(new Error('spawn gc-rdp-host.exe ENOENT'), { code: 'ENOENT' })));
      return child;
    }
    if (fake.failStart === 'exit') {
      setImmediate(() => child.exit(3));
      return child;
    }
    if (fake.failStart !== 'silent') setImmediate(() => child.out({ type: 'ready', pid: child.pid, version: '1.0.0', mstscax: '10.0.26100.1' }));
    return child;
  }

  /** The recorded Windows-Remotedesktop way (no .rdp launch, no cmdkey). */
  const mstsc = {
    launch(args, done) {
      fake.mstsc.push({ args: [...args] });
      const proc = { pid: 8100 + fake.mstsc.length };
      fake.endMstsc = () => done(null);
      return proc;
    },
    store(target, username) { fake.stored.push({ target, username }); },
    clear() {},
  };

  return { fake, spawn, mstsc };
}

module.exports = { createRdpHostFake };
