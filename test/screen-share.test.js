'use strict';

// Fernzugriff stage 7 ("Bildschirm teilen"): the switch and its channels (main/remote-host.js) and the bar at the
// top while a session runs (main/screen-bar.js) — with fakes, no Electron.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { setupRemoteHost } = require('../src/main/remote-host');
const { setupScreenBar } = require('../src/main/screen-bar');

function fakeHost() {
  const host = new EventEmitter();
  host.calls = [];
  host.st = { enabled: false, status: 'off', code: null, request: null, screen: { supported: true, enabled: false, status: 'off', session: null } };
  host.status = () => ({ ...host.st });
  host.start = async (a, b) => { host.calls.push(['start', a, b]); return host.status(); };
  host.setScreen = async (on) => { host.calls.push(['setScreen', on]); host.st.screen = { ...host.st.screen, enabled: on }; return host.status(); };
  host.decide = async (...a) => { host.calls.push(['decide', ...a]); };
  host.screenStop = () => host.calls.push(['screenStop']);
  host.screenViewOnly = () => host.calls.push(['screenViewOnly']);
  host.stop = () => {};
  return host;
}

function fakeBar() {
  const b = { updates: [], stop: [], viewOnly: [], destroyed: false };
  b.update = (s) => b.updates.push(s);
  b.onStop = (fn) => b.stop.push(fn);
  b.onViewOnly = (fn) => b.viewOnly.push(fn);
  b.destroy = () => { b.destroyed = true; };
  return b;
}

function make() {
  const host = fakeHost();
  const bar = fakeBar();
  const data = new Map();
  const store = { get: (k, d) => (data.has(k) ? data.get(k) : d), set: (k, v) => data.set(k, v) };
  const rdp = { enable: async () => {}, disable: async () => {}, reconcile: async () => false };
  const win = { webContents: { send: () => {} }, isDestroyed: () => false, flashFrame: () => {} };
  const rh = setupRemoteHost({ core: {}, host, apiClient: {}, log: { warn() {}, info() {} }, store, rdpAllow: rdp, configPath: 'wg.conf', getMainWindow: () => win, bar });
  return { host, bar, store, rh };
}

test('the switch is kept and given to the core at the next start', async () => {
  const { host, store, rh } = make();
  await rh.channels['remote-host:screen'](null, true);
  assert.equal(store.get('remote.screenShare'), true);
  assert.deepEqual(host.calls.pop(), ['setScreen', true]);
  await rh.start();
  assert.deepEqual(host.calls.pop(), ['start', false, true]);
  await rh.channels['remote-host:screen'](null, 'yes');
  assert.deepEqual(host.calls.pop(), ['setScreen', false], 'only true switches it on');
});

test('control only when "Ansehen und steuern" was chosen; anything else is view', async () => {
  const { host, rh } = make();
  await rh.channels['remote-host:decide'](null, 'rq_abcdefghij', 'allow', 'control');
  await rh.channels['remote-host:decide'](null, 'rq_abcdefghij', 'allow', undefined);
  await rh.channels['remote-host:decide'](null, 'rq_abcdefghij', 'allow', 'CONTROL');
  assert.deepEqual(host.calls.map((c) => c[3]), ['control', 'view', 'view']);
});

test('the bar follows the session; its buttons and the page\'s act on the core at once', async () => {
  const { host, bar, rh } = make();
  host.emit('state', { ...host.status(), screen: { enabled: true, session: { state: 'live', viewer: 'Lena Vogt', mode: 'control', since: 1 } } });
  assert.equal(bar.updates.pop().viewer, 'Lena Vogt');
  bar.viewOnly[0]();
  bar.stop[0]();
  rh.channels['remote-host:screen-view-only']();
  rh.channels['remote-host:screen-stop']();
  assert.deepEqual(host.calls.map((c) => c[0]), ['screenViewOnly', 'screenStop', 'screenViewOnly', 'screenStop']);
  rh.stop();
  assert.equal(bar.destroyed, true);
});

function fakeElectron() {
  const ipc = new EventEmitter();
  const wins = [];
  class BrowserWindow extends EventEmitter {
    constructor(o) {
      super();
      this.opts = o;
      this.sent = [];
      this.visible = false;
      this.destroyedFlag = false;
      this.webContents = { send: (c, p) => this.sent.push([c, p]) };
      wins.push(this);
    }
    setAlwaysOnTop(on, level) { this.level = level; }
    loadFile(f) { this.file = f; return Promise.resolve(); }
    isDestroyed() { return this.destroyedFlag; }
    isVisible() { return this.visible; }
    showInactive() { this.visible = true; this.inactive = true; }
    hide() { this.visible = false; }
    setBounds(b) { this.bounds = b; }
    setClosable() {}
    destroy() { this.destroyedFlag = true; }
  }
  const screen = { getPrimaryDisplay: () => ({ workArea: { x: 0, y: 0, width: 1920, height: 1040 } }) };
  return { BrowserWindow, screen, ipcMain: ipc, wins };
}

test('the bar: on top, not focusable, sandboxed; shows while the session runs, hides at the end; only its own buttons count', () => {
  const e = fakeElectron();
  const t = (k) => ({ 'screenShare.barControl': '{{ name }} steuert deinen Bildschirm', 'screenShare.stop': 'Beenden' }[k] || k);
  const bar = setupScreenBar({ BrowserWindow: e.BrowserWindow, screen: e.screen, ipcMain: e.ipcMain, preload: 'p.js', html: 'b.html', t });
  bar.update({ state: 'connecting' });
  const w = e.wins[0];
  assert.deepEqual([w.opts.alwaysOnTop, w.opts.focusable, w.opts.frame, w.opts.closable, w.opts.skipTaskbar], [true, false, false, false, true]);
  assert.deepEqual([w.opts.webPreferences.contextIsolation, w.opts.webPreferences.sandbox, w.opts.webPreferences.nodeIntegration], [true, true, false]);
  assert.equal(w.level, 'screen-saver');
  assert.equal(w.opts.x, Math.round((1920 - w.opts.width) / 2), 'centred at the top');
  assert.equal(w.inactive, true, 'never takes the focus');
  bar.update({ state: 'live', viewer: 'Lena Vogt', mode: 'control', since: 5 });
  const last = w.sent.pop()[1];
  assert.deepEqual([last.viewer, last.mode, last.texts.control, last.texts.stop], ['Lena Vogt', 'control', '{{ name }} steuert deinen Bildschirm', 'Beenden']);
  let stopped = 0;
  bar.onStop(() => stopped++);
  e.ipcMain.emit('screen-bar:stop', { sender: { other: true } });
  assert.equal(stopped, 0, 'not from another window');
  e.ipcMain.emit('screen-bar:stop', { sender: w.webContents });
  assert.equal(stopped, 1);
  bar.update({ state: 'ended', reason: 'sender' });
  assert.equal(w.visible, false);
  bar.update(null);
  assert.equal(e.wins.length, 1, 'one window, reused');
});
