'use strict';

// The player of "Medien" (Stufe 4g): its pure logic (src/renderer/media-player-state.js: the caps for
// media.setCaps, the info line, the keys, T / U, the progress reports, the jumps, the missing picture of HEVC, the
// volume, the title, the countdown), "no sleep while it plays" (src/main/media-awake.js) and how it is wired
// (index.html with hls.js from vendor/ and its licence, renderer, preload, the Pro channel, main).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const PS = require('../src/renderer/media-player-state');
const { createMediaAwake, PAUSE_GRACE_MS, WATCHDOG_MS } = require('../src/main/media-awake');

const ROOT = path.join(__dirname, '..');
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

describe('what Chromium plays (media.setCaps)', () => {
  it('HEVC and AV1 by MediaCapabilities (hardware decoder), else canPlayType "probably"; the rest by canPlayType', () => {
    const c = PS.capsFrom({
      canPlay: { hevc: 'probably', av1: 'probably', vp9: 'probably', mkv: '', ac3: '', eac3: 'maybe' },
      decoding: { hevc: { supported: false }, av1: { supported: true } },
      hdr: true,
    });
    assert.deepEqual(c, { hevc: false, av1: true, vp9: true, mkv: false, hdr: true, ac3: false, eac3: true, maxAudioChannels: 6 });
    assert.equal(PS.capsFrom({ canPlay: { hevc: 'probably' } }).hevc, true, 'no MediaCapabilities answer');
    assert.equal(PS.capsFrom({ canPlay: { hevc: 'maybe' } }).hevc, false);
    assert.equal(PS.capsFrom({}).maxAudioChannels, 6);
    assert.equal(PS.capsFrom({ channels: 8 }).maxAudioChannels, 8);
    assert.ok(PS.PROBES.hevc.type.includes('hvc1') && PS.PROBES.hevc.config.video.contentType.includes('hvc1'));
  });
});

describe('the info line', () => {
  it('at home directly: "Zuhause · direkt von der NAS"', () => {
    const i = PS.infoLine({ link: { atHome: true }, method: 'DirectPlay', converted: false }, null, t, 'de');
    assert.deepEqual(i, { way: 'home', converted: false, text: 'media.player.homeDirect' });
  });

  it('away: the measurement and Original, or what the NAS converts (picture step and sound, only the sound)', () => {
    assert.equal(PS.infoLine({ link: { atHome: false, bps: 18000000 }, method: 'DirectPlay' }, null, t, 'de').text, 'media.player.away(18 Mbit/s) · media.player.original');
    const conv = PS.infoLine({ link: { atHome: false, bps: 18000000 }, method: 'Transcode', converted: true, bitrate: 8000000, transcodeReasons: ['ContainerBitrateExceedsLimit', 'AudioCodecNotSupported'] }, 'AAC 5.1', t, 'de');
    assert.equal(conv.text, 'media.player.away(18 Mbit/s) · media.player.converts(1080p · 8 Mbit/s) · media.player.sound(AAC 5.1)');
    assert.equal(conv.converted, true);
    const sound = PS.infoLine({ link: { atHome: true }, method: 'Transcode', converted: true, bitrate: null, transcodeReasons: ['AudioCodecNotSupported'] }, 'AAC 5.1', t, 'de');
    assert.equal(sound.text, 'media.player.home · media.player.convertsSound(AAC 5.1)');
    const pic = PS.infoLine({ link: { atHome: false }, converted: true, transcodeReasons: ['VideoCodecNotSupported'] }, null, t, 'de');
    assert.equal(pic.text, 'media.player.awayNoBw · media.player.converts(media.player.picture)');
    assert.equal(PS.infoLine({ link: { atHome: true }, method: 'DirectStream' }, null, t).text, 'media.player.home · media.player.remux');
  });
});

describe('times, keys, choices', () => {
  it('the time of the bar', () => {
    assert.equal(PS.clock(2530), '42:10');
    assert.equal(PS.clock(6480), '1:48:00');
    assert.equal(PS.timeLabel(2530, 6480), '42:10 / 1:48:00');
    assert.equal(PS.timeLabel(30, NaN, 52 * 60000), '0:30 / 52:00', 'the title\'s length while the stream does not know it');
    assert.equal(PS.timeLabel(30, 0, null), '0:30');
  });

  it('the keys of mockup 9 (and nothing with Strg / Alt or in a field)', () => {
    const k = (key, o = {}) => PS.keyAction({ key, ...o });
    assert.equal(k(' '), 'toggle');
    assert.equal(k('ArrowLeft'), 'back');
    assert.equal(k('ArrowRight'), 'forward');
    assert.equal(k('f'), 'fullscreen');
    assert.equal(k('F'), 'fullscreen');
    assert.equal(k('u'), 'subtitles');
    assert.equal(k('T'), 'audio');
    assert.equal(k('m'), 'mute');
    assert.equal(k('Escape'), 'escape');
    assert.equal(k('ArrowUp'), 'volumeUp');
    assert.equal(k('x'), null);
    assert.equal(k('f', { ctrlKey: true }), null);
    assert.equal(k('n', { ctrlKey: true }), null);
    assert.equal(k(' ', { targetTag: 'INPUT' }), null);
  });

  it('T / U: the next sound or subtitle, round, "Aus" included', () => {
    assert.equal(PS.nextOption([1, 2, 3], 1), 2);
    assert.equal(PS.nextOption([1, 2, 3], 3), 1);
    assert.equal(PS.nextOption([-1, 4, 5], -1), 4);
    assert.equal(PS.nextOption([-1, 4, 5], 9), -1);
    assert.equal(PS.nextOption([], 1), null);
  });

  it('a progress report every 10 s while playing', () => {
    assert.equal(PS.progressDue(NaN, 1000, false), true);
    assert.equal(PS.progressDue(1000, 5000, false), false);
    assert.equal(PS.progressDue(1000, 11000, false), true);
    assert.equal(PS.progressDue(1000, 50000, true), false);
  });

  it('the jumps stay inside the film', () => {
    assert.equal(PS.seekTarget(5, -10, 100), 0);
    assert.equal(PS.seekTarget(50, 10, 100), 60);
    assert.equal(PS.seekTarget(95, 10, 100), 99.5);
    assert.equal(PS.seekTarget(5, 10, NaN), 15);
  });

  it('a missing picture (HEVC without the decoder): asked again once, only with a video track, after a moment', () => {
    const base = { videoWidth: 0, videoHeight: 0, currentTime: 3, hasVideo: true, retried: false };
    assert.equal(PS.missingPicture(base), true);
    assert.equal(PS.missingPicture({ ...base, currentTime: 1 }), false, 'not at once');
    assert.equal(PS.missingPicture({ ...base, retried: true }), false);
    assert.equal(PS.missingPicture({ ...base, hasVideo: false }), false, 'music has no picture');
    assert.equal(PS.missingPicture({ ...base, videoWidth: 1920, videoHeight: 1080 }), false);
  });

  it('the volume of this PC, the title, the countdown', () => {
    assert.deepEqual(PS.volumeOf('{"volume":0.4,"muted":true}'), { volume: 0.4, muted: true });
    assert.deepEqual(PS.volumeOf('{"volume":7}'), { volume: 1, muted: false });
    assert.deepEqual(PS.volumeOf(null), { volume: 1, muted: false });
    assert.deepEqual(PS.titleOf({ kind: 'episode', seriesName: 'Station Eisvogel', season: 2, episode: 4, name: 'Polarnacht' }, t), { title: 'Station Eisvogel', sub: 'media.player.se(2,4) · Polarnacht' });
    assert.deepEqual(PS.titleOf({ kind: 'movie', name: 'Kobaltnacht', year: 2025 }, t), { title: 'Kobaltnacht', sub: '2025' });
    assert.equal(PS.countdown(1000, 1000), 10);
    assert.equal(PS.countdown(1000, 4500), 7);
    assert.equal(PS.countdown(1000, 20000), 0);
  });
});

describe('no sleep while a film plays (main/media-awake.js)', () => {
  function fakes() {
    const blocker = { started: new Set(), n: 0, start(type) { assert.equal(type, 'prevent-display-sleep'); this.n += 1; this.started.add(this.n); return this.n; }, stop(id) { this.started.delete(id); }, isStarted(id) { return this.started.has(id); } };
    const timers = { list: [], setTimeout(fn, ms) { const x = { fn, ms, off: false }; this.list.push(x); return x; }, clearTimeout(x) { if (x) x.off = true; }, fire(ms) { for (const x of this.list.filter((y) => !y.off && y.ms === ms)) { x.off = true; x.fn(); } } };
    return { blocker, timers };
  }

  it('playing holds the PC awake; one minute after a pause it may sleep; playing again before keeps it', () => {
    const { blocker, timers } = fakes();
    const a = createMediaAwake({ powerSaveBlocker: blocker, timers });
    assert.equal(a.set('playing'), true);
    assert.equal(blocker.started.size, 1);
    a.set('playing');
    assert.equal(blocker.n, 1, 'one blocker');
    a.set('paused');
    assert.equal(a.active, true, 'still awake right after the pause');
    a.set('playing');
    timers.fire(PAUSE_GRACE_MS);
    assert.equal(a.active, true, 'the grace was cancelled');
    a.set('paused');
    timers.fire(PAUSE_GRACE_MS);
    assert.equal(a.active, false);
    assert.equal(blocker.started.size, 0);
  });

  it('closing the player frees it at once; a page that stops saying "playing" frees it after two minutes; nonsense changes nothing', () => {
    const { blocker, timers } = fakes();
    const a = createMediaAwake({ powerSaveBlocker: blocker, timers });
    a.set('playing');
    assert.equal(a.set('stopped'), false);
    assert.equal(blocker.started.size, 0);
    a.set('playing');
    timers.fire(WATCHDOG_MS);
    assert.equal(a.active, false);
    assert.equal(a.set('whatever'), false);
    a.set('paused');
    assert.equal(a.active, false, 'a pause without playing holds nothing');
    a.set('playing');
    a.stop();
    assert.equal(blocker.started.size, 0);
  });
});

describe('player wiring', () => {
  const html = read('src', 'renderer', 'index.html');
  const renderer = read('src', 'renderer', 'renderer.js');
  const main = read('src', 'main', 'main.js');
  const preload = read('src', 'main', 'preload.js');
  const ipc = read('src', 'main', 'ipc-pro.js');

  it('hls.js from vendor/ with its licence, before the player, the player before renderer', () => {
    const at = (s) => html.indexOf(s);
    assert.ok(at('src="vendor/hls/hls.min.js"') > at('src="media-view.js"'));
    assert.ok(at('src="vendor/hls/hls.min.js"') < at('src="media-player-state.js"') && at('src="media-player-state.js"') < at('src="media-player.js"'));
    assert.ok(at('src="media-player.js"') < at('src="renderer.js"'));
    const lic = read('src', 'renderer', 'vendor', 'hls', 'LICENSE');
    assert.match(lic, /Apache License, Version 2\.0/);
    assert.match(read('src', 'renderer', 'vendor', 'hls', 'README.md'), /hls\.js@1\.7\.4/);
    const js = read('src', 'renderer', 'vendor', 'hls', 'hls.min.js');
    assert.doesNotMatch(js, /sourceMappingURL/);
    assert.match(read('src', 'renderer', 'media-player.js'), /enableWorker: false/, 'no blob: worker under the CSP');
  });

  it('the player never puts server text into innerHTML', () => {
    for (const f of ['media-player.js', 'media-player-state.js']) assert.doesNotMatch(read('src', 'renderer', f), /\.innerHTML\s*=|insertAdjacentHTML\(|\.outerHTML\s*=/, f);
  });

  it('renderer: the player is made with the awake channel and handed to the page; it closes for another page', () => {
    assert.match(renderer, /GCMediaPlayer\.mount\(\{/);
    assert.match(renderer, /window\.gatecontrol\.mediaAwake\(state\)/);
    assert.match(renderer, /player: mediaPlayer,/);
    assert.match(renderer, /page !== 'medien' && mediaPlayer\?\.open\) mediaPlayer\.close\(\)/);
  });

  it('preload, the Pro channel, main: media-player:awake to powerSaveBlocker, released on quit', () => {
    assert.match(preload, /api\.mediaAwake = \(state\) => ipcRenderer\.invoke\('media-player:awake', state\)/);
    assert.match(ipc, /'media-player:awake': \(_, state\) => \(ctx\.mediaAwake \? ctx\.mediaAwake\.set/);
    assert.match(main, /createMediaAwake\(\{ powerSaveBlocker, log \}\)/);
    assert.match(main, /\n\s+mediaAwake,\n/);
    assert.match(main, /mediaAwake\?\.stop\(\)/);
  });

  it('every media.player.* key exists in de and en', () => {
    const de = JSON.parse(read('src', 'i18n', 'de.json'));
    const en = JSON.parse(read('src', 'i18n', 'en.json'));
    const get = (o, k) => k.split('.').reduce((x, p) => (x && typeof x === 'object' ? x[p] : undefined), o);
    const src = ['media-player.js', 'media-player-state.js'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set([...src.matchAll(/['`](media\.[a-zA-Z.]+[a-zA-Z])['`]/g)].map((m) => m[1]));
    assert.ok(keys.size > 40);
    for (const k of keys) {
      assert.equal(typeof get(de, k), 'string', `de: ${k}`);
      assert.equal(typeof get(en, k), 'string', `en: ${k}`);
    }
  });
});
