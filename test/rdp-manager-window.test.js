'use strict';

// RdpManager with the GateControl window (gc-rdp-host.exe, here the fake of test/e2e/support/rdp-host-fake.js):
//   - "Verbinden" opens the window by default; credentials only over the host's stdin, never on its command
//     line, no .rdp file launch and no cmdkey;
//   - the app setting, the host's local choice and the click's choice decide; RemoteApp, a missing host and a
//     host that does not start fall back to Windows-Remotedesktop (with a notice);
//   - audit start / end from the window's disconnect, plain text for the error view, its buttons, the bar's
//     drives setting (only within the server's permission), "Fenster anzeigen", disconnect, app exit.

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const RdpManager = require('../src/services/rdp/rdp-manager');
const { createRdpHostFake } = require('./e2e/support/rdp-host-fake');

const log = { info() {}, warn() {}, error() {}, debug() {} };

function memStore(init = {}) {
  const data = JSON.parse(JSON.stringify(init));
  const walk = (key, create) => {
    const parts = key.split('.');
    let o = data;
    for (const p of parts.slice(0, -1)) {
      if (!o[p] || typeof o[p] !== 'object') { if (!create) return [null, null]; o[p] = {}; }
      o = o[p];
    }
    return [o, parts.at(-1)];
  };
  return {
    data,
    get(key, d) { const [o, k] = walk(key, false); return o && o[k] !== undefined ? o[k] : d; },
    set(key, v) { const [o, k] = walk(key, true); o[k] = v; },
  };
}

const ROUTE = {
  id: 7, name: 'Buchhaltung-PC', host: '10.0.0.21', port: 3389, access_mode: 'internal', credential_mode: 'full',
  username: 'anna', password: 'test-pass-1', domain: 'BUERO', resolution_mode: 'dynamic', redirect_clipboard: 1, redirect_drives: 1,
  audio_mode: 'local', nla_enabled: 1,
};

const managers = [];
function setup({ route = ROUTE, store = {}, hostAvailable = true, failStart = null } = {}) {
  const { fake, spawn, mstsc } = createRdpHostFake();
  fake.failStart = failStart;
  const calls = [];
  const api = {
    getRdpConnect: async () => ({ ...route }),
    startRdpSession: async (id) => { calls.push(['start', id]); return { session: { id: 501 } }; },
    endRdpSession: async (id, d) => { calls.push(['end', id, d]); },
    updateRdpSession: async () => {},
    getRdpServices: async () => [{ ...route }],
  };
  const m = new RdpManager({
    apiClient: api, log, store: memStore(store), getTunnelState: () => ({ connected: true }), getPeerInfo: async () => ({}),
    hostExePath: 'C:\\gc\\resources\\rdp-host\\gc-rdp-host.exe', spawnHost: spawn, hostExists: () => hostAvailable, platform: 'win32',
    mstsc, getTheme: () => 'dark', t: (k) => `T:${k}`,
  });
  m._tcpCheck = async () => true;
  m.rdpServices = [{ ...route }];
  const events = [];
  for (const e of ['session-start', 'session-end', 'notice', 'host-action', 'progress']) m.on(e, (d) => events.push([e, d]));
  managers.push(m);
  return { m, fake, calls, events };
}

const tick = (ms = 60) => new Promise((r) => setTimeout(r, ms));

afterEach(() => {
  for (const m of managers.splice(0)) { m.monitor.stopAll(); m.activeSessions.clear(); }
});

describe('RdpManager: GateControl window', () => {
  it('opens the window by default, credentials only over stdin', async () => {
    const { m, fake, calls, events } = setup();
    const r = await m.connect(7);
    assert.deepEqual(r, { success: true, via: 'window' });
    assert.equal(fake.spawns.length, 1);
    assert.deepEqual(fake.spawns[0].args, [], 'no arguments: nothing on the command line');
    assert.ok(!JSON.stringify(fake.spawns).includes('test-pass-1'));
    const connect = fake.messages('connect')[0];
    assert.equal(connect.password, 'test-pass-1');
    assert.equal(connect.username, 'anna');
    assert.equal(connect.domain, 'BUERO');
    assert.equal(connect.texts.retry, 'T:rdpWindow.host.retry');
    assert.equal(fake.mstsc.length, 0, 'no mstsc');
    assert.equal(fake.stored.length, 0, 'no cmdkey');
    assert.deepEqual(calls[0], ['start', 7]);
    assert.ok(events.some(([e, d]) => e === 'progress' && d.step === 'mode' && d.status === 'window'));
    assert.ok(events.some(([e, d]) => e === 'session-start' && d.via === 'window'));
    assert.equal(m.getActiveSessions()[0].via, 'window');

    // the person disconnects: audit end "normal", the window closes
    await tick();
    fake.disconnect(1, 0, true);
    await tick();
    const end = calls.find((c) => c[0] === 'end');
    assert.equal(end[2].endReason, 'normal');
    assert.equal(end[2].sessionId, 501);
    assert.equal(m.isSessionActive(7), false);
    assert.ok(events.some(([e, d]) => e === 'session-end' && d.via === 'window'));
    assert.equal(fake.child.exited, true);
  });

  it('the app setting "Windows-Remotedesktop" keeps the previous way', async () => {
    const { m, fake } = setup({ store: { rdp: { openIn: 'mstsc' } } });
    const r = await m.connect(7);
    assert.deepEqual(r, { success: true, via: 'mstsc' });
    assert.equal(fake.spawns.length, 0);
    assert.equal(fake.mstsc.length, 1);
    assert.match(fake.mstsc[0].args[0], /gatecontrol_rdp_[0-9a-f]+\.rdp$/);
    assert.equal(fake.stored.length >= 1, true, 'cmdkey as before');
    fake.endMstsc();
  });

  it('per host and per click: the choice wins', async () => {
    const a = setup({ store: { rdp: { openIn: 'mstsc', hosts: { 7: { open: 'window' } } } } });
    assert.equal((await a.m.connect(7)).via, 'window');
    const b = setup();
    assert.equal((await b.m.connect(7, { via: 'mstsc' })).via, 'mstsc');
    b.fake.endMstsc();
    const c = setup({ store: { rdp: { openIn: 'mstsc' } } });
    assert.equal((await c.m.connect(7, { via: 'window' })).via, 'window');
  });

  it('RemoteApp routes and a missing host open with Windows-Remotedesktop, with a notice', async () => {
    const a = setup({ route: { ...ROUTE, remote_app: '||notepad' } });
    assert.equal((await a.m.connect(7)).via, 'mstsc');
    assert.ok(a.events.some(([e, d]) => e === 'notice' && d.kind === 'remoteapp'));
    a.fake.endMstsc();
    const b = setup({ hostAvailable: false });
    assert.equal((await b.m.connect(7)).via, 'mstsc');
    assert.ok(b.events.some(([e, d]) => e === 'notice' && d.kind === 'host-missing'));
    b.fake.endMstsc();
  });

  for (const failStart of ['error', 'exit']) {
    it(`a host that does not start (${failStart}) falls back to Windows-Remotedesktop`, async () => {
      const { m, fake, events, calls } = setup({ failStart });
      const r = await m.connect(7);
      assert.equal(r.via, 'mstsc');
      assert.equal(fake.mstsc.length, 1);
      assert.ok(events.some(([e, d]) => e === 'notice' && d.kind === 'host-failed'));
      assert.equal(calls.filter((c) => c[0] === 'start').length, 1, 'one audit start (mstsc), none for the window');
      fake.endMstsc();
    });
  }

  it('a disconnect by the server: plain text for the error view, "Erneut verbinden" reuses the window', async () => {
    const { m, fake, calls, events } = setup();
    await m.connect(7);
    await tick();
    fake.disconnect(3, 5, false);
    await tick();
    const explain = fake.messages('explain')[0];
    assert.deepEqual(explain, { type: 'explain', title: 'T:rdpWindow.err.replaced.title', text: 'T:rdpWindow.err.replaced.text' });
    assert.equal(calls.find((c) => c[0] === 'end')[2].endReason, 'replaced');
    assert.equal(fake.child.exited, false, 'the window stays with its error view');

    fake.action('reconnect');
    await tick();
    assert.ok(events.some(([e, d]) => e === 'host-action' && d.action === 'reconnect'));
    await m.connect(7, { via: 'window' });
    assert.equal(fake.spawns.length, 1, 'same window');
    assert.equal(fake.messages('connect').length, 2);
    assert.equal(m.isSessionActive(7), true);
  });

  it('"Mit Windows-Remotedesktop öffnen" in the error view closes the window and asks for mstsc', async () => {
    const { m, fake, events } = setup();
    await m.connect(7);
    await tick();
    fake.disconnect(3, 0, false);
    await tick();
    fake.action('mstsc');
    await tick();
    assert.ok(fake.messages('close').length >= 1);
    assert.ok(events.some(([e, d]) => e === 'host-action' && d.action === 'mstsc'));
    assert.equal(fake.child.exited, true);
    assert.equal(m.hostSessions.size, 0);
  });

  it('a running window session: "Verbinden" brings it to the front', async () => {
    const { m, fake } = setup();
    await m.connect(7);
    const r = await m.connect(7);
    assert.deepEqual(r, { success: true, via: 'window', focused: true });
    assert.equal(fake.spawns.length, 1);
    assert.equal(fake.messages('focus').length, 1);
    assert.equal(m.focusWindow(7), true);
    await tick();
    assert.equal(fake.messages('focus').length, 2);
  });

  it('the bar\'s drives setting is kept per host, only within what the server permits', async () => {
    const { m, fake } = setup({ route: { ...ROUTE, redirect_drives: 0 } });
    await m.connect(7);
    await tick();
    fake.setting('drives', true);
    await tick();
    assert.deepEqual(m.getLocalSettings(7), {}, 'not permitted: not stored');
    fake.setting('drives', false);
    await tick();
    assert.deepEqual(m.getLocalSettings(7), { drives: false }, 'switching off is always allowed');

    const b = setup();
    await b.m.connect(7);
    await tick();
    b.fake.setting('drives', false);
    await tick();
    assert.deepEqual(b.m.getLocalSettings(7), { drives: false });
    b.fake.setting('drives', true);
    await tick();
    assert.deepEqual(b.m.getLocalSettings(7), { drives: true });
    assert.equal(b.m.getLocalSettings(7).drives && true, true);
  });

  it('local settings: only known keys, never beyond the route; null resets', () => {
    const { m } = setup({ route: { ...ROUTE, redirect_drives: 0, multi_monitor: 0 } });
    assert.deepEqual(m.setLocalSettings(7, { drives: true, display: 'multimon', clipboard: false, evil: 'x', open: 'mstsc' }), { clipboard: false, open: 'mstsc' });
    assert.deepEqual(m.setLocalSettings(7, { clipboard: null }), { open: 'mstsc' });
    assert.deepEqual(m.setLocalSettings('../x', { open: 'mstsc' }), {});
    assert.equal(m.setOpenIn('mstsc'), 'mstsc');
    assert.equal(m.getOpenIn(), 'mstsc');
    assert.equal(m.setOpenIn('bogus'), 'window');
  });

  it('disconnect asks the window; app exit ends its stdin and audits app_exit', async () => {
    const { m, fake, calls } = setup();
    await m.connect(7);
    await tick();
    m.disconnect(7);
    await tick();
    assert.ok(fake.messages('close').length >= 1);
    assert.equal(m.isSessionActive(7), false);

    const b = setup();
    await b.m.connect(7);
    await tick();
    b.m.cleanupAll();
    await tick();
    assert.equal(b.fake.child.exited, true);
    assert.ok(b.calls.some((c) => c[0] === 'end' && c[2].endReason === 'app_exit'));
    assert.ok(calls.some((c) => c[0] === 'end'));
  });

  it('the host crashes: the session ends with its audit', async () => {
    const { m, fake, calls } = setup();
    await m.connect(7);
    await tick();
    fake.child.exit(255);
    await tick();
    assert.equal(m.isSessionActive(7), false);
    assert.equal(calls.find((c) => c[0] === 'end')[2].endReason, 'error');
  });

  it('the theme follows the app', async () => {
    const { m, fake } = setup();
    await m.connect(7);
    m.setTheme('light');
    await tick();
    assert.deepEqual(fake.messages('theme')[0], { type: 'theme', theme: 'light' });
  });
});
