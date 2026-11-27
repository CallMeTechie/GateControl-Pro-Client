'use strict';

// The screen stays on while a video plays — not only in the Medien player: Drive's viewer, the vault's viewer (also in
// full screen) and the clips of the cameras (src/renderer/video-awake.js), as on Android only while the video really
// plays. One blocker for all in the main process (src/main/media-awake.js, the same as the player's), counted per
// video so one that stops never frees another; the channel video:awake (preload, ipc-pro) and how the views use it.
// The live picture of the cameras is left out on purpose.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const VA = require('../src/renderer/video-awake');
const { createMediaAwake, PAUSE_GRACE_MS, WATCHDOG_MS } = require('../src/main/media-awake');
const { registerProIpc } = require('../src/main/ipc-pro');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

function blockerFake() {
  return { started: new Set(), n: 0, start(type) { assert.equal(type, 'prevent-display-sleep'); this.n += 1; this.started.add(this.n); return this.n; }, stop(id) { this.started.delete(id); }, isStarted(id) { return this.started.has(id); } };
}
function timeoutFake() {
  return { list: [], setTimeout(fn, ms) { const x = { fn, ms, off: false }; this.list.push(x); return x; }, clearTimeout(x) { if (x) x.off = true; }, fire(ms) { for (const x of this.list.filter((y) => !y.off && y.ms === ms)) { x.off = true; x.fn(); } } };
}

describe('one blocker, counted per video (main/media-awake.js)', () => {
  it('two videos: the one that stops does not free the other, the last one does', () => {
    const blocker = blockerFake();
    const a = createMediaAwake({ powerSaveBlocker: blocker, timers: timeoutFake() });
    assert.equal(a.set('playing', 'video:v1', 0), true);
    assert.equal(a.set('playing', 'video:v2', 0), true);
    assert.equal(blocker.started.size, 1, 'one blocker for both');
    assert.equal(a.holders, 2);
    assert.equal(a.set('stopped', 'video:v1', 0), true, 'v2 still plays');
    assert.equal(blocker.started.size, 1);
    assert.equal(a.set('stopped', 'video:v1', 0), true, 'twice is no harm');
    assert.equal(a.set('stopped', 'video:v2', 0), false);
    assert.equal(blocker.started.size, 0);
  });

  it('a video\'s pause frees at once (no minute), the player\'s after the minute; together they count', () => {
    const blocker = blockerFake();
    const timers = timeoutFake();
    const a = createMediaAwake({ powerSaveBlocker: blocker, timers });
    a.set('playing');
    a.set('playing', 'video:v1', 0);
    assert.equal(a.set('paused', 'video:v1', 0), true, 'the player still plays');
    assert.equal(a.holders, 1);
    a.set('paused');
    assert.equal(a.active, true, 'the player\'s minute');
    timers.fire(PAUSE_GRACE_MS);
    assert.equal(a.active, false);
    assert.equal(blocker.started.size, 0);
  });

  it('the player\'s stop does not free a video that plays', () => {
    const blocker = blockerFake();
    const a = createMediaAwake({ powerSaveBlocker: blocker, timers: timeoutFake() });
    a.set('playing', 'video:v1', 0);
    a.set('playing');
    assert.equal(a.set('stopped'), true);
    assert.equal(blocker.started.size, 1);
  });

  it('a video that stops saying "playing" is dropped by the watchdog; stop() frees all', () => {
    const blocker = blockerFake();
    const timers = timeoutFake();
    const a = createMediaAwake({ powerSaveBlocker: blocker, timers });
    a.set('playing', 'video:v1', 0);
    timers.fire(WATCHDOG_MS);
    assert.equal(a.active, false);
    a.set('playing', 'video:v1', 0);
    a.set('playing', 'video:v2', 0);
    a.stop();
    assert.equal(a.holders, 0);
    assert.equal(blocker.started.size, 0);
  });

  it('unknown states and keys change nothing', () => {
    const a = createMediaAwake({ powerSaveBlocker: blockerFake(), timers: timeoutFake() });
    assert.equal(a.set('nonsense', 'video:v1', 0), false);
    assert.equal(a.set('playing', '', 0), false);
    assert.equal(a.set('playing', 42, 0), false);
    assert.equal(a.holders, 0);
  });
});

describe('the channel video:awake (ipc-pro)', () => {
  function register(mediaAwake) {
    const handlers = new Map();
    const ipcMain = { handle: (c, fn) => handlers.set(c, fn), on() {}, removeHandler() {} };
    registerProIpc(ipcMain, {
      store: { get: () => undefined, set() {} }, log: { info() {}, warn() {}, error() {} },
      setLocale() {}, getLocale: () => 'de', onLocaleChanged() {}, checkSystemDns: async () => ({}), setAutostart: async () => {},
      rdpManager: {}, rdpWolClient: {}, setRdpPanelOpen() {}, getMachineFingerprint: () => 'a'.repeat(64), mediaAwake,
    });
    return handlers;
  }

  it('hands the video\'s own key to the shared blocker, without the minute; rejects other keys', () => {
    const calls = [];
    const h = register({ set: (...a) => { calls.push(a); return true; } });
    const fn = h.get('video:awake');
    assert.equal(typeof fn, 'function');
    assert.equal(fn({}, 'v3', 'playing'), true);
    assert.deepEqual(calls, [['playing', 'video:v3', 0]]);
    assert.equal(fn({}, 'player', 'stopped'), false, 'never the player\'s key');
    assert.equal(fn({}, '../x', 'playing'), false);
    assert.equal(fn({}, { k: 1 }, 'playing'), false);
    assert.equal(calls.length, 1);
  });
});

describe('a video in the page (renderer/video-awake.js)', () => {
  function videoFake() {
    const v = new EventEmitter();
    v.paused = true; v.ended = false; v.isConnected = true; v.readyState = 0;
    v.addEventListener = (e, f) => v.on(e, f);
    v.removeEventListener = (e, f) => v.off(e, f);
    v.fire = (e) => {
      if (e === 'play' || e === 'playing') v.paused = false;
      if (e === 'pause' || e === 'ended') v.paused = true;
      v.emit(e);
    };
    return v;
  }
  function make() {
    const sent = [];
    const timers = { list: [], setInterval(fn, ms) { const x = { fn, ms, off: false }; this.list.push(x); return x; }, clearInterval(x) { if (x) x.off = true; }, tick() { for (const x of this.list.filter((y) => !y.off)) x.fn(); } };
    const a = VA.create({ send: (k, s) => { sent.push(`${k}:${s}`); }, timers });
    return { a, sent, timers };
  }

  it('on only while it really plays: play/playing on; pause, ended, error, waiting, emptied, abort off', () => {
    const { a, sent } = make();
    const v = videoFake();
    const h = a.watch(v);
    assert.equal(h.holding, false, 'not before it plays');
    for (const off of ['pause', 'ended', 'error', 'waiting', 'emptied', 'abort']) {
      v.fire('playing');
      assert.equal(h.holding, true, `playing before ${off}`);
      v.fire(off);
      assert.equal(h.holding, false, off);
    }
    v.fire('play');
    v.fire('playing');
    assert.equal(h.holding, true);
    assert.equal(sent.filter((s) => s === 'v1:playing').length, 7, 'one "playing" per start, not per event');
    assert.equal(sent.filter((s) => s === 'v1:stopped').length, 6);
  });

  it('says so again while it plays; a video taken out of the page or paused unnoticed counts as stopped', () => {
    const { a, sent, timers } = make();
    const v = videoFake();
    a.watch(v);
    v.fire('playing');
    timers.tick();
    assert.deepEqual(sent, ['v1:playing', 'v1:playing']);
    v.isConnected = false;
    timers.tick();
    assert.deepEqual(sent, ['v1:playing', 'v1:playing', 'v1:stopped']);
    assert.equal(VA.REFRESH_MS < WATCHDOG_MS, true, 'refreshed before the main process drops it');
  });

  it('release(): off, and no event turns it on again (the viewer closed)', () => {
    const { a, sent } = make();
    const v = videoFake();
    const h = a.watch(v);
    v.fire('playing');
    h.release();
    assert.equal(h.holding, false);
    v.fire('playing');
    assert.equal(h.holding, false);
    assert.deepEqual(sent, ['v1:playing', 'v1:stopped']);
    h.release();
  });

  it('two videos have two keys: one stopping does not stop the other', () => {
    const { a, sent } = make();
    const v1 = videoFake();
    const v2 = videoFake();
    const h1 = a.watch(v1);
    const h2 = a.watch(v2);
    v1.fire('playing');
    v2.fire('playing');
    v1.fire('pause');
    assert.equal(h1.holding, false);
    assert.equal(h2.holding, true);
    assert.deepEqual(sent, ['v1:playing', 'v2:playing', 'v1:stopped']);
  });

  it('`when`: the camera\'s live picture is left out, its clips count', () => {
    const { a, sent, timers } = make();
    const v = videoFake();
    let clip = null;
    const h = a.watch(v, { when: () => !!clip });
    v.fire('playing');
    assert.equal(h.holding, false, 'live');
    clip = { id: 1 };
    v.fire('playing');
    assert.equal(h.holding, true, 'a clip');
    clip = null;
    timers.tick();
    assert.equal(h.holding, false, 'back to live');
    assert.deepEqual(sent, ['v1:playing', 'v1:stopped']);
  });

  it('a video already playing when watched is on at once; nothing without a bridge or element', () => {
    const { a } = make();
    const v = videoFake();
    v.paused = false; v.readyState = 4;
    assert.equal(a.watch(v).holding, true);
    assert.equal(a.watch(null).holding, false);
    assert.doesNotThrow(() => VA.create({ send: () => { throw new Error('no bridge'); } }).watch(videoFake()).release());
  });
});

describe('wired into the app', () => {
  it('preload and main: video:awake to the same blocker, made also without the Medien plugin', () => {
    assert.match(read('src', 'main', 'preload.js'), /api\.videoAwake = \(key, state\) => ipcRenderer\.invoke\('video:awake', key, state\)/);
    const main = read('src', 'main', 'main.js');
    assert.match(main, /mediaAwake = powerSaveBlocker \? createMediaAwake\(\{ powerSaveBlocker, log \}\) : null;/);
  });

  it('index.html loads video-awake.js before the viewers and the cameras', () => {
    const html = read('src', 'renderer', 'index.html');
    const at = (s) => html.indexOf(`src="${s}"`);
    assert.ok(at('video-awake.js') > 0);
    for (const f of ['drive-viewer.js', 'drive-vault-viewer.js', 'camera-view.js']) assert.ok(at('video-awake.js') < at(f), f);
  });

  it('Drive\'s viewer, the vault\'s viewer (videos, not sound) and the camera clips watch their <video>', () => {
    const dv = read('src', 'renderer', 'drive-viewer.js');
    assert.match(dv, /awake = root\.GCVideoAwake\.watch\(v\)/);
    assert.match(dv, /if \(awake\) \{ awake\.release\(\); awake = null; \}/, 'released when it closes / another one is shown');
    const vv = read('src', 'renderer', 'drive-vault-viewer.js');
    assert.match(vv, /r\.kind === 'video' && root\.GCVideoAwake \? root\.GCVideoAwake\.watch\(m\)/);
    assert.match(vv, /if \(awake\) awake\.release\(\);/);
    const cam = read('src', 'renderer', 'camera-view.js');
    assert.match(cam, /GCVideoAwake\.watch\(refs\.video, \{ when: \(\) => !!S\.clip \}\)/, 'only while a clip plays');
    assert.doesNotMatch(read('src', 'renderer', 'home-view.js'), /GCVideoAwake/, 'the live preview on the start page stays out');
  });
});
