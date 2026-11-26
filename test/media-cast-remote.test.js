'use strict';

// "Auf TV/PC abspielen" — this PC as the receiver (src/renderer/media-cast-remote.js): a start of the phone opens
// Medien and the player at the place with its sound and subtitle, the phone's keys go to the player, every change goes
// back as a state (the tracks with Jellyfin's index, "Aus" as off), the end tells the phone why; and how it is wired
// (index.html, renderer, main with the core's MediaCastReceiver, the status line's texts).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const CR = require('../src/renderer/media-cast-remote');
const MS = require('../src/renderer/media-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);
const SESSION = 'a1b2c3d4e5f6a7b8c9d0e1f2';

const VERSION = {
  audio: [{ index: 1, language: 'ger', languageName: 'Deutsch', label: 'AC3 5.1', codec: 'ac3', channels: 6 }, { index: 2, language: 'eng', languageName: 'English', label: 'AAC 2.0', codec: 'aac', channels: 2 }],
  subtitles: [{ index: 5, language: 'ger', languageName: 'Deutsch', codecLabel: 'SRT' }],
};

function fakeCast() {
  const h = {};
  const calls = [];
  const sub = (name) => (cb) => { h[name] = cb; return () => { delete h[name]; }; };
  return {
    h, calls,
    status: async () => ({ ok: true, session: null }),
    opened: (session) => { calls.push(['opened', session]); return Promise.resolve({ ok: true }); },
    state: (session, st) => { calls.push(['state', session, st]); return Promise.resolve({ ok: true }); },
    closed: (session, o) => { calls.push(['closed', session, o]); return Promise.resolve({ ok: true }); },
    onPlay: sub('play'), onCommand: sub('command'), onSession: sub('session'),
  };
}

function fakePlayer() {
  const p = {
    open: false,
    state: { req: null },
    snap: { phase: 'loading', positionMs: 0, durationMs: 0, title: 'Kobaltnacht', version: VERSION, play: null, share: false, volume: 80, muted: false },
    calls: [],
    async play(req) { p.calls.push(['play', req]); p.open = true; p.state.req = req; },
    async close(why = 'user') {
      if (!p.open) return;
      const req = p.state.req;
      p.open = false;
      p.calls.push(['close', why]);
      if (req && req.onEnd) req.onEnd({ why, positionMs: p.snap.positionMs, durationMs: p.snap.durationMs });
    },
  };
  const rec = (name) => (...a) => { p.calls.push([name, ...a]); };
  p.remote = { snapshot: () => ({ ...p.snap }), play: rec('r.play'), pause: rec('r.pause'), seekTo: rec('r.seekTo'), seekBy: rec('r.seekBy'),
    audio: rec('r.audio'), subtitle: rec('r.subtitle'), volume: rec('r.volume'), stop: () => p.close('remote') };
  return p;
}

const playEvent = (over = {}) => ({
  session: SESSION, sourceId: 'jf-1', itemId: 'm1', item: { sourceId: 'jf-1', id: 'm1', name: 'Kobaltnacht', kind: 'movie' },
  detail: { ok: true, versions: [VERSION] }, startMs: 754_000, audioIndex: 2, subtitleIndex: -1, controllerName: 'Pixel 8', ...over,
});

function setup() {
  let now = 1_000_000;
  const cast = fakeCast();
  const player = fakePlayer();
  const pages = [];
  const r = CR.mount({ cast, player, MS, t, openPage: () => pages.push('medien'), now: () => now });
  return { cast, player, r, pages, advance: (ms) => { now += ms; } };
}

describe('media-cast-remote: the pure parts', () => {
  it('tracks: the labels of the player\'s panel, Jellyfin\'s index as id, "Aus" as off; a share has none', () => {
    const tr = CR.tracksOf({ version: VERSION, play: { audioIndex: 2, subtitleIndex: -1 } }, MS, t, {});
    assert.deepEqual(tr.audio.map((a) => [a.id, a.selected]), [['a1', false], ['a2', true]]);
    assert.ok(tr.audio[0].label.startsWith('Deutsch'));
    assert.deepEqual(tr.subtitles.map((s) => [s.id, s.selected]), [['off', true], ['s5', false]]);
    assert.deepEqual(CR.tracksOf({ version: VERSION, share: true }, MS, t, {}), { audio: [], subtitles: [] });
    assert.deepEqual(CR.tracksOf({ version: { audio: [], subtitles: [] }, play: {} }, MS, t, {}).subtitles, [], 'only "Aus": no subtitles to offer');
  });

  it('the end: the phone\'s "Stopp", the end of the film, closed here, an error', () => {
    assert.deepEqual(CR.closedOf({ why: 'remote', positionMs: 5, durationMs: 9 }, null), { positionMs: 5, durationMs: 9, byRemote: true, ended: false, failed: false });
    assert.equal(CR.closedOf({ why: 'ended' }, null).ended, true);
    assert.deepEqual(CR.closedOf({ why: 'user' }, { phase: 'playing' }), { positionMs: 0, durationMs: 0, byRemote: false, ended: false, failed: false });
    assert.equal(CR.closedOf({ why: 'error' }, { phase: 'failed' }).failed, true);
  });
});

describe('media-cast-remote: the phone sends a title', () => {
  it('Medien and the player open at the place with the phone\'s sound and subtitle; the core hears it is shown', async () => {
    const x = setup();
    await x.cast.h.play(playEvent());
    assert.deepEqual(x.pages, ['medien']);
    const req = x.player.calls[0][1];
    assert.deepEqual([req.item.id, req.startMs, req.audioIndex, req.subtitleIndex, req.cast.session, req.cast.controllerName], ['m1', 754_000, 2, -1, SESSION, 'Pixel 8']);
    assert.deepEqual(x.cast.calls[0], ['opened', SESSION]);
    assert.equal(x.r.session, SESSION);
  });

  it('the phone\'s keys go to the player; another session\'s not', async () => {
    const x = setup();
    await x.cast.h.play(playEvent());
    const cmds = [
      { cmd: 'pause' }, { cmd: 'play' }, { cmd: 'seek', positionMs: 60_000 }, { cmd: 'seekBy', deltaMs: -10_000 },
      { cmd: 'audio', audioIndex: 1 }, { cmd: 'subtitle', subtitleIndex: 5 }, { cmd: 'volume', volume: 30 },
    ];
    for (const c of cmds) x.cast.h.command({ session: SESSION, ...c });
    x.cast.h.command({ session: 'other-session-1', cmd: 'pause' });
    assert.deepEqual(x.player.calls.slice(1), [['r.pause'], ['r.play'], ['r.seekTo', 60_000], ['r.seekBy', -10_000], ['r.audio', 1], ['r.subtitle', 5], ['r.volume', 30, undefined]]);
  });

  it('changes go to the core as states (at once on events, while playing every 2 s); "Stand" now', async () => {
    const x = setup();
    await x.cast.h.play(playEvent());
    x.player.snap = { ...x.player.snap, phase: 'playing', positionMs: 754_000, durationMs: 7_200_000, play: { audioIndex: 2, subtitleIndex: -1 } };
    x.r.onChange('playing');
    x.advance(500);
    x.r.onChange('time');
    x.advance(2000);
    x.r.onChange('time');
    x.cast.h.command({ session: SESSION, cmd: 'status' });
    const states = x.cast.calls.filter((c) => c[0] === 'state');
    assert.equal(states.length, 3);
    const st = states[0][2];
    assert.deepEqual([st.phase, st.positionMs, st.durationMs, st.title, st.volume, st.force], ['playing', 754_000, 7_200_000, 'Kobaltnacht', 80, false]);
    assert.deepEqual(st.audio.find((a) => a.selected).id, 'a2');
    assert.equal(states[2][2].force, true);
  });

  it('"Stopp" of the phone closes the player: stopped by the remote; closed on this PC: closed', async () => {
    const x = setup();
    await x.cast.h.play(playEvent());
    x.cast.h.command({ session: SESSION, cmd: 'stop' });
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(x.cast.calls.pop(), ['closed', SESSION, { positionMs: 0, durationMs: 0, byRemote: true, ended: false, failed: false }]);
    assert.equal(x.r.session, null);
    await x.cast.h.play(playEvent());
    await x.player.close();
    assert.equal(x.cast.calls.pop()[2].byRemote, false);
  });

  it('an error of the player ends the session for the phone (the player keeps "Erneut versuchen")', async () => {
    const x = setup();
    await x.cast.h.play(playEvent());
    x.player.snap = { ...x.player.snap, phase: 'failed', positionMs: 1000 };
    x.r.onChange('error');
    assert.deepEqual(x.cast.calls.pop(), ['closed', SESSION, { positionMs: 1000, durationMs: 0, byRemote: false, ended: false, failed: true }]);
    assert.equal(x.player.open, true);
  });

  it('nothing for a player that shows another title', async () => {
    const x = setup();
    await x.cast.h.play(playEvent());
    x.player.state.req = { item: { id: 'x' } };
    x.r.onChange('playing');
    x.cast.h.command({ session: SESSION, cmd: 'pause' });
    assert.equal(x.cast.calls.filter((c) => c[0] === 'state').length, 0);
    assert.equal(x.player.calls.filter((c) => c[0] === 'r.pause').length, 0);
  });
});

describe('media-cast-remote: wired', () => {
  it('index.html loads it after the player; renderer mounts it with the player and media.cast', () => {
    const html = read('src', 'renderer', 'index.html');
    assert.ok(html.indexOf('media-cast-remote.js') > html.indexOf('media-player.js'));
    assert.ok(html.indexOf('media-cast-remote.js') < html.indexOf('renderer.js'));
    const r = read('src', 'renderer', 'renderer.js');
    assert.match(r, /GCMediaCastRemote\.mount\(\{[\s\S]*cast: mediaApi\.cast,[\s\S]*player: mediaPlayer/);
    assert.match(r, /onChange: \(why\) => mediaCastRemote\?\.onChange\(why\)/);
  });

  it('main makes the core\'s receiver with the push stream and the signal, passes it to the IPC, starts and stops it', () => {
    const m = read('src', 'main', 'main.js');
    assert.match(m, /new MediaCastReceiver\(\{[\s\S]*pushClient: notifications\?\.pushClient,[\s\S]*notificationCenter: notifications\?\.notificationCenter/);
    assert.match(m, /\n {4}mediaCast,\n/);
    assert.match(m, /mediaCast\?\.start\(\)/);
    assert.match(m, /mediaCast\?\.stop\(\)/);
    assert.match(m, /mediaCast\?\.on\('play'/);
  });

  it('the status line "Vom Handy gesteuert" in both languages; the player shows it for a cast', () => {
    const de = JSON.parse(read('src', 'i18n', 'de.json'));
    const en = JSON.parse(read('src', 'i18n', 'en.json'));
    assert.equal(de.media.player.castBy, 'Vom Handy gesteuert · {{name}}');
    assert.ok(en.media.player.cast && en.media.player.castBy.includes('{{name}}'));
    const p = read('src', 'renderer', 'media-player.js');
    assert.match(p, /t\('media\.player\.castBy'/);
    assert.match(p, /remote,/);
  });

  it('the core has the receiver this client asks for', () => {
    let core = null;
    for (const d of [path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) if (fs.existsSync(path.join(d, 'src', 'services', 'media-cast.js'))) { core = d; break; }
    if (!core) return;
    const bridge = fs.readFileSync(path.join(core, 'src', 'preload', 'bridge.js'), 'utf8');
    for (const fn of ['opened:', 'state:', 'closed:', 'onPlay:', 'onCommand:']) assert.ok(bridge.includes(fn), fn);
  });
});
