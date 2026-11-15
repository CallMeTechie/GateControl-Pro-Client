'use strict';

// Fernzugriff stage 2: the switch "Remote Desktop erlauben" registers the PC (core RemoteHost); a server
// without the plugin 1.1 keeps the old rule for the whole VPN.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { setupRemoteHost } = require('../src/main/remote-host');

function fakes(status = 'ready') {
  const host = new EventEmitter();
  host.st = { enabled: false, status: 'off', code: null, request: null };
  host.status = () => ({ ...host.st });
  host.enable = async () => { host.st = { ...host.st, enabled: true, status, code: '482-913-075' }; host.emit('state', host.status()); return host.status(); };
  host.disable = async () => { host.st = { enabled: false, status: 'off', code: null, request: null }; return host.status(); };
  host.start = async (w) => (w ? host.enable() : host.status());
  host.decide = async (...a) => { host.decided = a; };
  host.setShareMode = async (m) => { host.mode = m; };
  host.newCode = async () => {};
  host.enableRdpInWindows = async () => {};
  host.stop = () => {};
  const rdp = { calls: [], enable: async () => rdp.calls.push('enable'), disable: async () => rdp.calls.push('disable'), reconcile: async (o) => { rdp.calls.push(['reconcile', o.wanted]); return o.wanted; } };
  const data = new Map();
  const store = { get: (k, d) => (data.has(k) ? data.get(k) : d), set: (k, v) => data.set(k, v) };
  const sent = [];
  const win = { webContents: { send: (c, p) => sent.push([c, p]) }, isDestroyed: () => false, flashFrame: () => {} };
  let shown = 0;
  const rh = setupRemoteHost({ core: {}, host, apiClient: {}, log: { warn() {}, info() {} }, store, rdpAllow: rdp, configPath: 'wg.conf', getMainWindow: () => win, showWindow: () => { shown++; } });
  return { host, rdp, store, sent, rh, shown: () => shown };
}

test('switch on: the PC registers, no rule for the whole VPN; off: signed off', async () => {
  const { rh, rdp, store, sent } = fakes('ready');
  const s = await rh.toggle(true);
  assert.equal(s.status, 'ready');
  assert.equal(s.legacy, false);
  assert.equal(store.get('tunnel.rdpAllow'), true);
  assert.ok(!rdp.calls.includes('enable'));
  assert.ok(sent.some(([c]) => c === 'remote-host:state'));
  await rh.toggle(false);
  assert.equal(store.get('tunnel.rdpAllow'), false);
  assert.equal(rdp.calls[rdp.calls.length - 1], 'disable');
});

test('a server without the plugin 1.1: the old way (3389 for the whole VPN)', async () => {
  const { rh, rdp } = fakes('unavailable');
  const s = await rh.toggle(true);
  assert.equal(s.legacy, true);
  assert.ok(rdp.calls.includes('enable'));
});

test('start: the old rule only without the plugin; the request opens the window; channels', async () => {
  const a = fakes('ready');
  a.store.set('tunnel.rdpAllow', true);
  await a.rh.start();
  assert.deepEqual(a.rdp.calls.find((c) => Array.isArray(c)), ['reconcile', false]);
  const b = fakes('unavailable');
  b.store.set('tunnel.rdpAllow', true);
  await b.rh.start();
  assert.deepEqual(b.rdp.calls.find((c) => Array.isArray(c)), ['reconcile', true]);
  a.host.emit('request', { requestId: 'rq_abcdefghij', from: { name: 'Sabine' }, mode: 'control', via: 'browser' });
  assert.equal(a.shown(), 1);
  assert.ok(a.sent.some(([c, p]) => c === 'remote-host:request' && p && p.from.name === 'Sabine'));
  await a.rh.channels['remote-host:decide'](null, 'rq_abcdefghij', 'allow', 'view');
  assert.deepEqual(a.host.decided, ['rq_abcdefghij', 'allow', 'view']);
  await a.rh.channels['remote-host:share'](null, 'open');
  assert.equal(a.host.mode, 'open');
});
