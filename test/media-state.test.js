'use strict';

// View logic of the page "Medien" (src/renderer/media-state.js, no DOM): the sources and the way to them, the times,
// the cards of the rows, merging several Jellyfin servers and the search over all sources, the grid's keys and pages,
// the detail column (chips, sound, subtitles, quality), seasons and episodes, error texts; and how the page is wired (index.html with the CSP for
// gcmedia:, renderer, preload, main: the scheme, the service, the network changes) and that every media.* key exists
// in both Pro locales.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const MS = require('../src/renderer/media-state');

const ROOT = path.join(__dirname, '..');
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const NOW = new Date(2026, 10, 24, 20, 0, 0).getTime();
const DAY = 24 * 3600 * 1000;
const MIN = 60 * 1000;

const jelly = (o = {}) => ({ id: 'j1', kind: 'jellyfin', name: 'DS918+', address: 'http://192.168.1.20:8096', userName: 'Mila', ready: true, signedIn: true, alwaysOriginal: false, link: { atHome: true, via: 'lan', bps: null }, ...o });
const share = (o = {}) => ({ id: 's1', kind: 'smb', name: '192.168.1.20', address: 'smb://192.168.1.20/filme', unc: '\\\\192.168.1.20\\filme', userName: 'medien-lesen', ready: true, pairWith: 'w1', link: {}, ...o });
const title = (o = {}) => ({
  id: 'a1', sourceId: 'j1', kind: 'movie', name: 'Kobaltnacht', year: 2025, runtimeMs: 108 * MIN, positionMs: 42 * MIN + 10000, played: false,
  genres: ['Drama'], rating: '12', poster: 'gcmedia://image/tok/Items/a1/Images/Primary', backdrop: null, resumable: true,
  leftMs: 108 * MIN - (42 * MIN + 10000), progress: (42 * MIN + 10000) / (108 * MIN), addedAt: NOW - 20 * DAY, playedAt: NOW - 3600000, ...o,
});
const version = (o = {}) => ({
  id: 'v1', container: 'mkv', bitrate: 40000000, video: { codec: 'hevc', width: 3840, height: 2160, videoRangeType: 'HDR10' }, videoLabel: '4K HDR10', hdr: 'HDR10',
  audio: [
    { index: 1, codec: 'dts', channels: 6, language: 'ger', languageName: 'Deutsch', label: 'DTS 5.1', fate: 'converted' },
    { index: 2, codec: 'truehd', channels: 8, language: 'eng', languageName: 'Englisch', label: 'TrueHD 7.1', fate: 'converted' },
    { index: 3, codec: 'aac', channels: 2, language: 'ger', languageName: 'Deutsch', label: 'AAC Stereo', title: 'Hörfilm-Fassung', fate: 'decoded' },
  ],
  subtitles: [
    { index: 4, codec: 'subrip', codecLabel: 'SRT', language: 'ger', languageName: 'Deutsch', burnIn: false },
    { index: 5, codec: 'pgssub', codecLabel: 'PGS', language: 'eng', languageName: 'Englisch', burnIn: true, forced: false },
  ],
  pick: { audioIndex: 1, subtitleIndex: null },
  quality: { originalBps: 40000000, originalFits: true, adaptedBps: null, suggestAdapted: false },
  ...o,
});

describe('sources and the way', () => {
  it('sources: Jellyfin, the ready ones, the shares; the grid\'s source', () => {
    const st = { sources: [jelly(), share(), jelly({ id: 'j2', ready: false, signedIn: false })] };
    const s = MS.sourcesOf(st);
    assert.deepEqual(s.jellyfin.map((x) => x.id), ['j1', 'j2']);
    assert.deepEqual(s.ready.map((x) => x.id), ['j1']);
    assert.deepEqual(s.shares.map((x) => x.id), ['s1']);
    assert.equal(MS.pickSource(st, 'j2').id, 'j1', 'a signed out one is not picked');
    assert.equal(MS.pickSource(st, 'gone').id, 'j1');
    assert.equal(MS.pickSource({ sources: [share()] }, null), null);
    assert.deepEqual(MS.sourcesOf(null).all, []);
  });

  it('bandwidth and the picture of a step, as the core labels them', () => {
    assert.equal(MS.bandwidth(18000000, 'de'), '18 Mbit/s');
    assert.equal(MS.bandwidth(2500000, 'de'), '2,5 Mbit/s');
    assert.equal(MS.bandwidth(2500000, 'en'), '2.5 Mbit/s');
    assert.equal(MS.bandwidth(3000000, 'de'), '3 Mbit/s');
    assert.equal(MS.bandwidth(800000, 'de'), '800 kbit/s');
    assert.equal(MS.bandwidth(null), null);
    assert.equal(MS.resolution(8000000), '1080p');
    assert.equal(MS.resolution(4000000), '720p');
    assert.equal(MS.resolution(2000000), '480p');
  });

  it('the pill and the status bar: Zuhause · direkt, Unterwegs · 18 Mbit/s, not checked yet', () => {
    assert.deepEqual(MS.linkLabel({ atHome: true }, t, 'de'), { cls: 'is-home', text: 'media.link.home' });
    assert.deepEqual(MS.linkLabel({ atHome: false, bps: 18000000 }, t, 'de'), { cls: 'is-away', text: 'media.link.away(18 Mbit/s)' });
    assert.deepEqual(MS.linkLabel({ atHome: false, bps: null }, t, 'de'), { cls: 'is-away', text: 'media.link.awayNoBw' });
    assert.deepEqual(MS.linkLabel({ atHome: null }, t, 'de'), { cls: 'is-unknown', text: 'media.link.checking' });
    assert.equal(MS.statusLine({ atHome: true }, t), 'media.status.home');
    assert.equal(MS.statusLine({ atHome: false, bps: 18000000 }, t, 'de'), 'media.status.away(18 Mbit/s)');
    assert.equal(MS.statusLine(null, t), null);
  });

  it('chips and lines of the sources (no secret is ever there to show)', () => {
    assert.equal(MS.sourceChip(jelly(), t), 'media.src.jellyfin(DS918+)');
    assert.equal(MS.sourceChip(share(), t), 'media.src.share(\\\\192.168.1.20\\filme)');
    assert.equal(MS.sourceSub(jelly(), t, 'BUERO-PC'), 'media.src.signedInAs(Mila) · 192.168.1.20:8096 · media.src.device(BUERO-PC)');
    assert.equal(MS.sourceSub(share(), t), 'media.src.smbHomeWebdav · medien-lesen');
    assert.equal(MS.sourceSub(share({ pairWith: null, useExisting: true, userName: null }), t), 'media.src.smb · media.src.explorer');
    assert.equal(MS.sourceSub(share({ kind: 'webdav', pairWith: null }), t), 'media.src.webdav · medien-lesen');
  });

  it('"Immer Original" is on when every Jellyfin source has it', () => {
    assert.equal(MS.alwaysOriginal({ sources: [jelly({ alwaysOriginal: true }), share()] }), true);
    assert.equal(MS.alwaysOriginal({ sources: [jelly({ alwaysOriginal: true }), jelly({ id: 'j2' })] }), false);
    assert.equal(MS.alwaysOriginal({ sources: [share()] }), false);
  });
});

describe('times and cards', () => {
  it('clock, running time, what is left', () => {
    assert.equal(MS.clock(42 * MIN + 10000), '42:10');
    assert.equal(MS.clock(108 * MIN), '1:48:00');
    assert.equal(MS.clock(5000), '0:05');
    assert.equal(MS.clock(null), '0:00');
    assert.equal(MS.runtime(108 * MIN, t), 'media.runtime.hm(1,48)');
    assert.equal(MS.runtime(52 * MIN, t), 'media.runtime.m(52)');
    assert.equal(MS.runtime(120 * MIN, t), 'media.runtime.h(2)');
    assert.equal(MS.runtime(0, t), null);
    assert.equal(MS.shortRuntime(112 * MIN), '1:52');
    assert.equal(MS.leftLabel({ leftMs: 18 * MIN }, t), 'media.left.min(18)');
    assert.equal(MS.leftLabel({ leftMs: 66 * MIN }, t), 'media.left.hm(1:06)');
    assert.equal(MS.leftLabel({ leftMs: null }, t), null);
  });

  it('a card of Weiterschauen: a film "ab 42:10", an episode its series with "Staffel 2 · Folge 4"', () => {
    const c = MS.resumeCard(title(), t);
    assert.equal(c.title, 'Kobaltnacht');
    assert.equal(c.sub, 'media.at(42:10)');
    assert.equal(c.left, 'media.left.hm(1:06)');
    assert.equal(c.progress, 39);
    assert.equal(c.picture, title().poster, 'no backdrop: the poster');
    const e = MS.resumeCard(title({ kind: 'episode', name: 'Polarnacht', seriesName: 'Station Eisvogel', season: 2, episode: 4, backdrop: 'gcmedia://image/x' }), t);
    assert.equal(e.title, 'Station Eisvogel');
    assert.equal(e.sub, 'media.episode(2,4)');
    assert.equal(e.picture, 'gcmedia://image/x');
  });

  it('a poster: year (and length), a series its seasons, NEU in the first week, the bar only when started', () => {
    const p = MS.posterCard(title({ addedAt: NOW - 2 * DAY }), t, NOW, { full: true });
    assert.equal(p.sub, '2025 · 1:48');
    assert.equal(p.isNew, true);
    assert.equal(p.progress, 39);
    assert.equal(MS.posterCard(title(), t, NOW).sub, '2025');
    assert.equal(MS.posterCard(title(), t, NOW).isNew, false);
    assert.equal(MS.posterCard(title({ resumable: false, positionMs: 0 }), t, NOW).progress, 0);
    const s = MS.posterCard(title({ kind: 'series', childCount: 3, year: 2021 }), t, NOW, { full: true });
    assert.equal(s.sub, 'media.seasons(3)');
    assert.equal(MS.posterCard(title({ kind: 'series', childCount: 1 }), t, NOW, { full: true }).sub, 'media.seasons1');
    assert.equal(MS.posterCard(title({ played: true }), t, NOW).played, true);
  });

  it('"diese Woche" only when every new title is of this week', () => {
    assert.equal(MS.latestSub([title({ addedAt: NOW - DAY }), title({ addedAt: NOW - 3 * DAY })], t, NOW), 'media.row.thisWeek');
    assert.equal(MS.latestSub([title({ addedAt: NOW - DAY }), title({ addedAt: NOW - 30 * DAY })], t, NOW), 'media.row.count(2)');
    assert.equal(MS.latestSub([], t, NOW), '');
  });
});

describe('several servers and the search', () => {
  it('Weiterschauen of all of them, the one played last first, each title once', () => {
    const a = { ok: true, items: [title({ id: 'a', playedAt: NOW - 5000 }), title({ id: 'b', playedAt: NOW - 100 })] };
    const b = { ok: true, items: [title({ id: 'c', sourceId: 'j2', playedAt: NOW - 50 }), title({ id: 'a', playedAt: NOW })] };
    const merged = MS.mergeResume([a, { ok: false, code: 'offline' }, b]);
    assert.deepEqual(merged.map((x) => `${x.sourceId}|${x.id}`), ['j2|c', 'j1|b', 'j1|a']);
    assert.equal(MS.mergeResume([a, b], 1).length, 1);
  });

  it('Zuletzt hinzugefügt of all of them, the newest first', () => {
    const merged = MS.mergeLatest([{ ok: true, items: [title({ id: 'a', addedAt: 1 }), title({ id: 'b', addedAt: 3 })] }, { ok: true, items: [title({ id: 'c', sourceId: 'j2', addedAt: 2 })] }]);
    assert.deepEqual(merged.map((x) => x.id), ['b', 'c', 'a']);
  });

  it('the search: a title of two sources once (the first, Jellyfin), films and series before episodes, the start of the name first', () => {
    const a = { ok: true, items: [title({ id: 'e1', kind: 'episode', name: 'Eisdrift', seriesId: 's', season: 1, episode: 2 }), title({ id: 'm1', name: 'Der Eisvogel', year: 2020 }), title({ id: 's1', kind: 'series', name: 'Station Eisvogel', year: 2024 })] };
    const b = { ok: true, items: [title({ id: 'x9', sourceId: 'j2', name: 'Station Eisvogel', kind: 'series', year: 2024 }), title({ id: 'm2', sourceId: 'j2', name: 'Eiszeit', year: 2019 })] };
    const r = MS.mergeSearch([a, b], 'Eis');
    assert.deepEqual(r.map((x) => x.id), ['m2', 'm1', 's1', 'e1']);
  });

  it('genres of the loaded titles, A–Z, with the chosen one', () => {
    assert.deepEqual(MS.genresOf([title({ genres: ['Krimi', 'Drama'] }), title({ genres: ['drama', 'Komödie'] })], 'Western'), ['Drama', 'drama', 'Komödie', 'Krimi', 'Western'].sort((x, y) => x.localeCompare(y, 'de', { sensitivity: 'base' })));
  });

  it('pages of the grid: appended, each title once, the next start', () => {
    let g = MS.appendPage(null, { items: [title({ id: 'a' }), title({ id: 'b' })], total: 3, next: 2 });
    assert.deepEqual([g.items.length, g.total, g.next], [2, 3, 2]);
    g = MS.appendPage(g, { items: [title({ id: 'b' }), title({ id: 'c' })], total: 3, next: null });
    assert.deepEqual(g.items.map((x) => x.id), ['a', 'b', 'c']);
    assert.equal(g.next, null);
  });

  it('the arrow keys in the grid', () => {
    assert.equal(MS.gridMove(3, 'ArrowRight', 5, 12), 4);
    assert.equal(MS.gridMove(11, 'ArrowRight', 5, 12), 11);
    assert.equal(MS.gridMove(0, 'ArrowLeft', 5, 12), 0);
    assert.equal(MS.gridMove(3, 'ArrowDown', 5, 12), 8);
    assert.equal(MS.gridMove(8, 'ArrowDown', 5, 12), 8, 'no cell below: stays');
    assert.equal(MS.gridMove(8, 'ArrowUp', 5, 12), 3);
    assert.equal(MS.gridMove(2, 'ArrowUp', 5, 12), 2);
    assert.equal(MS.gridMove(7, 'Home', 5, 12), 0);
    assert.equal(MS.gridMove(2, 'End', 5, 12), 11);
    assert.equal(MS.gridMove(0, 'ArrowDown', 5, 0), -1);
  });
});

describe('the detail column', () => {
  const caps = { hevc: false, hdr: false, ac3: false, eac3: false, maxAudioChannels: 6 };

  it('the chips: 4K · HDR10, HEVC · mkv and what the PC has converted', () => {
    assert.deepEqual(MS.detailChips(version(), 1, { ...caps, hevc: true, hdr: true }, t), [
      { cls: '', text: '4K · HDR10' }, { cls: '', text: 'HEVC · mkv' }, { cls: 'is-warn', text: 'media.chip.audioConverted' },
    ]);
    assert.equal(MS.detailChips(version(), 1, caps, t).at(-1).text, 'media.chip.bothConverted', 'no HEVC decoder, DTS');
    assert.equal(MS.detailChips(version(), 3, caps, t).at(-1).text, 'media.chip.videoConverted');
    assert.equal(MS.detailChips(version({ video: { codec: 'h264', height: 1080 }, videoLabel: '1080p', hdr: null, container: 'mp4' }), 3, caps, t).length, 2);
    assert.deepEqual(MS.detailChips(null, 1, caps, t), []);
  });

  it('sound: "Deutsch · DTS 5.1" — Chromium kann kein DTS: NAS rechnet in AAC 5.1 um; a stereo track stays stereo', () => {
    const a = MS.audioOptions(version(), caps, t);
    assert.deepEqual(a.map((x) => x.label), ['Deutsch · DTS 5.1', 'Englisch · TrueHD 7.1', 'Deutsch · AAC Stereo – Hörfilm-Fassung']);
    assert.equal(a[0].why, 'media.audio.cannot(DTS,AAC 5.1)');
    assert.equal(a[0].note, 'media.audio.converts(AAC 5.1)');
    assert.equal(a[2].why, 'media.audio.direct');
    assert.equal(MS.targetAudio({ channels: 6 }, { maxAudioChannels: 2 }), 'AAC Stereo');
    assert.equal(MS.audioFate({ codec: 'ac3' }, { ac3: true }), 'decoded');
    assert.equal(MS.audioFate({ codec: 'ac3' }, {}), 'converted');
    assert.equal(MS.pickedAudio(version()), 1);
    assert.equal(MS.pickedAudio(version({ pick: null })), 1);
  });

  it('subtitles: Aus first, text as WebVTT, a picture burnt in', () => {
    const s = MS.subtitleOptions(version(), t);
    assert.deepEqual(s.map((x) => x.value), [-1, 4, 5]);
    assert.equal(s[1].label, 'Deutsch · media.sub.text(SRT)');
    assert.equal(s[1].note, 'media.sub.vtt');
    assert.equal(s[2].note, 'media.sub.burnIn');
    assert.equal(s[2].burnIn, true);
    assert.equal(MS.pickedSubtitle(version()), -1);
    assert.equal(MS.pickedSubtitle(version({ pick: { audioIndex: 1, subtitleIndex: 4 } })), 4);
  });

  it('quality: Automatisch · zu Hause Original, away the step of the line, fixed steps, Immer Original', () => {
    assert.equal(MS.qualityOptions(t, 'de').length, MS.QUALITIES.length);
    assert.equal(MS.qualityOptions(t, 'de')[2].label, '1080p · 20 Mbit/s');
    assert.equal(MS.qualityNote('auto', version().quality, { atHome: true }, t, 'de'), 'media.quality.autoHome');
    assert.equal(MS.qualityNote('auto', { suggestAdapted: true, adaptedBps: 8000000 }, { atHome: false, bps: 18000000 }, t, 'de'), 'media.quality.autoAway(1080p,8 Mbit/s)');
    assert.equal(MS.qualityNote('auto', { suggestAdapted: false }, { atHome: false, bps: 90000000 }, t, 'de'), 'media.quality.autoAwayOriginal');
    assert.equal(MS.qualityNote('8', null, { atHome: true }, t), 'media.quality.fixedNote');
    assert.equal(MS.qualityNote('original', null, { atHome: false }, t), 'media.quality.originalNote');
    assert.equal(MS.qualityNote('auto', null, { atHome: false }, t, 'de', true), 'media.quality.alwaysOriginal');
  });

  it('the meta line and the play button', () => {
    assert.equal(MS.metaLine(title(), t), '2025 · media.runtime.hm(1,48) · Drama · FSK 12');
    assert.equal(MS.metaLine(title({ kind: 'series', childCount: 2, rating: 'TV-14', genres: [] }), t), '2025 · media.seasons(2) · TV-14');
    assert.equal(MS.playLabel(title(), t), 'media.detail.resume(42:10)');
    assert.equal(MS.playLabel(title({ positionMs: 0 }), t), 'media.detail.play');
    assert.equal(MS.playLabel(title({ played: true }), t), 'media.detail.play');
  });

  it('seasons, the season to open, the next episode, its row, the one after', () => {
    const seasons = [
      { id: 's0', kind: 'season', name: 'Specials', episode: 0, unplayed: 2 },
      { id: 's1', kind: 'season', name: 'Staffel 1', episode: 1, unplayed: 0 },
      { id: 's2', kind: 'season', name: 'Staffel 2', episode: 2, unplayed: 3 },
    ];
    assert.deepEqual(MS.seasonChips(seasons, t).map((c) => c.label), ['media.series.specials', 'media.series.season(1)', 'media.series.season(2)']);
    assert.equal(MS.firstSeason(seasons, null), 's2', 'the first with something unwatched, not the specials');
    assert.equal(MS.firstSeason(seasons, { seasonId: 's1' }), 's1');
    assert.equal(MS.firstSeason([], null), null);
    const eps = [
      title({ id: 'e1', kind: 'episode', episode: 1, played: true, positionMs: 0 }),
      title({ id: 'e2', kind: 'episode', episode: 2, played: false, positionMs: 0 }),
      title({ id: 'e3', kind: 'episode', episode: 3, played: false, positionMs: 600000, runtimeMs: 52 * MIN, leftMs: 42 * MIN, progress: 10 / 52 }),
    ];
    assert.equal(MS.nextEpisode(eps).id, 'e3', 'the one started first');
    assert.equal(MS.nextEpisode(eps.slice(0, 2)).id, 'e2');
    assert.equal(MS.nextEpisode([eps[0]]), null);
    const r = MS.episodeRow(eps[2], t);
    assert.deepEqual([r.num, r.sub, r.progress], ['3', 'media.runtime.m(52) · media.left.min(42)', 19]);
    assert.equal(MS.episodeAfter(eps, 'e2').id, 'e3');
    assert.equal(MS.episodeAfter(eps, 'e3'), null);
  });
});

describe('error texts', () => {
  it('error texts; an unknown code is "failed"', () => {
    assert.equal(MS.errorText('smb_conflict', t), 'media.error.smb_conflict');
    assert.equal(MS.errorText('timeout', t), 'media.error.offline');
    assert.equal(MS.errorText('weird', t), 'media.error.failed');
  });

  it('the card on the overview is on unless switched off', () => {
    assert.equal(MS.homeCardOn(null), true);
    assert.equal(MS.homeCardOn('on'), true);
    assert.equal(MS.homeCardOn('off'), false);
  });
});

describe('page wiring', () => {
  const html = read('src', 'renderer', 'index.html');
  const renderer = read('src', 'renderer', 'renderer.js');
  const main = read('src', 'main', 'main.js');
  const preload = read('src', 'main', 'preload.js');

  it('index.html: state before the views before renderer, nav entry, page, card, styles, CSP for gcmedia: (pictures, video, hls.js)', () => {
    const at = (s) => html.indexOf(s);
    assert.ok(at('src="media-state.js"') > 0 && at('src="media-state.js"') < at('src="media-sources-view.js"'));
    assert.ok(at('src="media-sources-view.js"') < at('src="media-view.js"') && at('src="media-view.js"') < at('src="renderer.js"'));
    assert.match(html, /id="nav-medien"[^>]*data-page="medien"[^>]*hidden/);
    assert.match(html, /<section class="page" id="page-medien"/);
    assert.match(html, /id="media-home"[^>]*hidden/);
    assert.match(html, /href="styles\/media\.css"/);
    const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
    for (const d of ['img-src', 'media-src', 'connect-src']) assert.match(csp, new RegExp(`${d} [^;]*gcmedia:`), d);
    assert.doesNotMatch(csp, /script-src[^;]*(unsafe|gcmedia)/);
  });

  it('the views never put server text into innerHTML', () => {
    for (const f of ['media-view.js', 'media-sources-view.js', 'media-state.js']) assert.doesNotMatch(read('src', 'renderer', f), /\.innerHTML\s*=|insertAdjacentHTML\(|\.outerHTML\s*=/, f);
  });

  it('renderer: the page, the entry, show / hide, the card on the start page', () => {
    assert.match(renderer, /const PAGES = \[[^\]]*'medien'/);
    assert.ok(html.indexOf('id="nav-vault"') < html.indexOf('id="nav-medien"') && html.indexOf('id="nav-medien"') < html.indexOf('id="nav-kameras"'), 'before Kameras');
    assert.match(renderer, /GCMediaView\.mount\(\{/);
    assert.match(renderer, /homeHost: \$\('#media-home'\)/);
    assert.match(renderer, /page === 'medien' && prev !== 'medien'\) mediaView\?\.show\(\)/);
    assert.match(renderer, /mediaView\?\.homeShow\(\)/);
    assert.match(renderer, /mediaView\?\.relabel\(\)/);
  });

  it('preload: the core\'s media bridge', () => {
    assert.match(preload, /createMediaBridge/);
    assert.match(preload, /api\.media = createMediaBridge\(ipcRenderer\)/);
  });

  it('main: gcmedia: privileged before ready (in the one call), served by MediaService, the service to the IPC, closed on quit, network changes', () => {
    const priv = main.indexOf('MediaStreamService.SCHEME, privileges');
    assert.ok(priv > 0 && priv < main.indexOf('protocol.registerSchemesAsPrivileged(schemes)'));
    assert.equal((main.match(/registerSchemesAsPrivileged\(/g) || []).length, 1, 'one call for all schemes');
    assert.match(main, /protocol\.handle\(MediaStreamService\.SCHEME, \(req\) => media\.stream\.handleProtocol\(req\)\)/);
    assert.match(main, /new MediaStore\(\{ store, protect: DriveService\.safeStorageProtect\(safeStorage\) \}\)/);
    assert.match(main, /\n\s+media,\n/);
    assert.match(main, /media\?\.close\(\)/);
    assert.match(main, /media\.networkChanged\(\)/);
    assert.match(main, /mediaTunnelUp !== tunnelState\.connected/);
  });

  it('every media.* key the page uses exists in de and en', () => {
    const de = JSON.parse(read('src', 'i18n', 'de.json'));
    const en = JSON.parse(read('src', 'i18n', 'en.json'));
    const get = (o, k) => k.split('.').reduce((x, p) => (x && typeof x === 'object' ? x[p] : undefined), o);
    const src = ['media-view.js', 'media-sources-view.js', 'media-state.js'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set([...src.matchAll(/['`](media\.[a-zA-Z.]+[a-zA-Z])['`]/g)].map((m) => m[1]));
    for (const tab of MS.TABS.concat('search')) keys.add(`media.tabs.${tab}`);
    for (const s of MS.SORTS) keys.add(`media.sort.${s}`);
    for (const c of ['invalid', 'offline', 'unauthorized', 'not_found', 'unsupported', 'unsupported_version', 'quick_connect_off', 'expired', 'signed_out', 'no_protect', 'too_many', 'smb_conflict', 'cert_untrusted', 'cert_changed', 'no_lan_route', 'failed']) keys.add(`media.error.${c}`);
    assert.ok(keys.size > 100);
    for (const k of keys) {
      assert.equal(typeof get(de, k), 'string', `de: ${k}`);
      assert.equal(typeof get(en, k), 'string', `en: ${k}`);
    }
  });
});

describe('NAS shares beside Jellyfin (4h, the cases of Android\'s MediaLogic)', () => {
  const movie = (id, name, o = {}) => title({ id, name, sourceId: o.share ? 's1' : 'j1', fromShare: !!o.share, year: o.year ?? null, playedAt: o.playedAt ?? null, addedAt: o.addedAt ?? null, positionMs: 0, resumable: false, ...o });

  it('the library: ready Jellyfin servers and the shares', () => {
    const s = MS.sourcesOf({ sources: [jelly(), share(), jelly({ id: 'j2', ready: false })] });
    assert.deepEqual(s.library.map((x) => x.id), ['j1', 's1']);
    assert.deepEqual(MS.sourcesOf({ sources: [share()] }).library.map((x) => x.id), ['s1'], 'shares alone are a library');
  });

  it('keys: the same title written differently, A–Z as Jellyfin', () => {
    assert.equal(MS.keyOf('Die letzte Fähre nach Mirow'), MS.keyOf('die.letzte.fähre.nach.mirow'));
    assert.equal(MS.sortKeyOf('The Pegelwart'), 'pegelwart');
    assert.equal(MS.sortKeyOf('Letzte Fähre'), 'letzte fahre');
  });

  it('a title in Jellyfin and on a share shows once, Jellyfin\'s', () => {
    const jf = [movie('j-k', 'Kupferstadt', { year: 2025 }), title({ id: 'j-g', kind: 'series', name: 'Graufeld', year: null })];
    const shares = [
      movie('f:Kupferstadt.2025.mkv', 'kupferstadt', { share: true, year: 2025 }),
      movie('f:Kupferstadt.1961.mkv', 'Kupferstadt', { share: true, year: 1961 }),
      movie('f:Graufeld.mkv', 'Graufeld', { share: true }),
      title({ id: 's:graufeld', sourceId: 's1', kind: 'series', name: 'Graufeld', year: null, fromShare: true }),
      movie('f:Moorlicht.mkv', 'Moorlicht', { share: true }),
    ];
    assert.deepEqual(MS.withoutDuplicates(shares, jf).map((x) => x.id), ['f:Kupferstadt.1961.mkv', 'f:Graufeld.mkv', 'f:Moorlicht.mkv']);
    const ep = title({ id: 'e', kind: 'episode', name: 'Ebbe', seriesName: 'Graufeld', season: 1, episode: 2 });
    assert.equal(MS.same(ep, { ...ep, id: 'f:x', name: 'Graufeld', fromShare: true }), true);
    assert.equal(MS.same(ep, { ...ep, id: 'f:y', episode: 3 }), false);
    assert.deepEqual(MS.withoutDuplicates(shares, []), shares);
    // the core's keys win over the page's own
    assert.equal(MS.same({ kind: 'movie', name: 'A', key: 'x' }, { kind: 'movie', name: 'B', key: 'x' }), true);
  });

  it('Filme A–Z: the shares\' titles in their places, later ones wait for the next page', () => {
    const jf = [movie('a', 'Achterwasser'), movie('b', 'Blaue Stunde in Tarnow'), movie('k', 'Kobaltnacht')];
    const shares = [movie('f:z', 'Zwielicht', { share: true }), movie('f:d', 'Der Pegelwart', { share: true }), movie('f:aa', 'Ankerplatz', { share: true }), movie('f:k', 'Kobaltnacht', { share: true })];
    const f = { sort: 'name', unplayed: false, genre: null };
    assert.deepEqual(MS.mergeGrid(jf, false, shares, f).map((x) => x.id), ['a', 'f:aa', 'b', 'f:d', 'k']);
    assert.deepEqual(MS.mergeGrid(jf, true, shares, f).map((x) => x.id), ['a', 'f:aa', 'b', 'f:d', 'k', 'f:z']);
    assert.deepEqual(MS.mergeGrid([], true, shares, f).map((x) => x.id), ['f:aa', 'f:d', 'f:k', 'f:z'], 'only shares');
    assert.deepEqual(MS.mergeGrid([], false, shares, f), [], 'Jellyfin not loaded yet');
    assert.deepEqual(MS.mergeGrid(jf, true, shares, { ...f, genre: 'Drama' }).map((x) => x.id), ['a', 'b', 'k'], 'a genre: the shares have none');
    const played = [movie('f:p', 'Paulas Werkstatt', { share: true, played: true })];
    assert.deepEqual(MS.mergeGrid([], true, played, { ...f, unplayed: true }), []);
    const byYear = MS.mergeGrid([movie('j', 'Jahr 2020', { year: 2020 })], true, [movie('f:n', 'Neu', { share: true, year: 2026 }), movie('f:o', 'Alt', { share: true, year: 1999 })], { ...f, sort: 'year' });
    assert.deepEqual(byYear.map((x) => x.id), ['f:n', 'j', 'f:o']);
  });

  it('Weiterschauen of all sources: watched last first, a share\'s twin of a Jellyfin title goes', () => {
    const jf = { ok: true, items: [movie('k', 'Kobaltnacht', { playedAt: 300 }), movie('p', 'Paulas Werkstatt', { playedAt: 100 })] };
    const sh = { ok: true, items: [movie('f:l', 'Die Lindqvist-Akten', { share: true, playedAt: 200 }), movie('f:k', 'Kobaltnacht', { share: true, playedAt: 400 })] };
    assert.deepEqual(MS.mergeResume([jf, sh], 12).map((x) => x.id), ['k', 'f:l', 'p']);
    assert.deepEqual(MS.mergeResume([jf, sh], 2).map((x) => x.id), ['k', 'f:l']);
    // a share's title Jellyfin has (known from the rows), even when Jellyfin has not started it
    assert.deepEqual(MS.mergeResume([sh], 12, [movie('j-l', 'Die Lindqvist-Akten')]).map((x) => x.id), ['f:k']);
    const latest = MS.mergeLatest([{ ok: true, items: [movie('s', 'Sternwarte 9', { addedAt: 50 })] }, { ok: true, items: [movie('f:g', 'Graufeld', { share: true, addedAt: 70 })] }], 16);
    assert.deepEqual(latest.map((x) => x.id), ['f:g', 's']);
  });

  it('the search: Jellyfin first, a share\'s twin goes', () => {
    const r = MS.mergeSearch([{ ok: true, items: [movie('j', 'Kobaltnacht', { year: 2025 })] }, { ok: true, items: [movie('f:k', 'Kobaltnacht', { share: true, year: 2025 }), movie('f:m', 'Kobaltmond', { share: true })] }], 'Kobalt');
    assert.deepEqual(r.map((x) => x.id), ['j', 'f:m']);
  });
});

describe('Ordner (4h)', () => {
  const entry = (o) => ({ name: 'x', path: 'x', directory: false, size: 0, kind: 'video', progress: null, ...o });

  it('folders, videos and sound; a line with size, length and "noch … Min."', () => {
    const items = [entry({ name: 'Urlaub 2025', directory: true, kind: 'folder' }), entry({ name: 'poster.jpg', kind: 'image' }), entry({ name: 'a.srt', kind: 'subtitle' }), entry({ name: 'Hörspiel.mp3', kind: 'audio' }), entry({ name: 'Notizen.txt', kind: null })];
    assert.deepEqual(MS.folderItems(items).map((e) => e.name), ['Urlaub 2025', 'Hörspiel.mp3']);
    const r = MS.folderRow(entry({ name: 'Geburtstag Oma.mkv', title: 'Geburtstag Oma', size: 1.8e9, poster: 'gcmedia://image/t/p.jpg', progress: { positionMs: 23 * MIN, durationMs: 42 * MIN, played: false } }), t, 'de');
    assert.deepEqual(r, { kind: 'video', title: 'Geburtstag Oma', sub: '1,8 GB · media.runtime.m(42) · media.left.min(19)', picture: 'gcmedia://image/t/p.jpg', progress: 55, played: false, file: 'Geburtstag Oma.mkv' });
    const ep = MS.folderRow(entry({ name: 'Graufeld.S01E02.Ebbe.mkv', title: 'Ebbe', season: 1, episode: 2, size: 920e6, progress: { positionMs: 0, durationMs: 0, played: true } }), t, 'en');
    assert.equal(ep.sub, 'media.episode(1,2) · 920 MB');
    assert.equal(ep.played, true);
    assert.equal(MS.folderRow(entry({ name: 'Ohne Titel.mp4' }), t, 'de').title, 'Ohne Titel');
    assert.equal(MS.folderRow(entry({ name: 'Urlaub', directory: true }), t, 'de').kind, 'folder');
    assert.equal(MS.sizeLabel(3.4e9, 'de'), '3,4 GB');
    assert.equal(MS.sizeLabel(34e9, 'de'), '34 GB');
    assert.equal(MS.sizeLabel(0, 'de'), null);
  });

  it('the path as buttons, the folder above, the way of the share', () => {
    assert.deepEqual(MS.crumbs('Filme/Familie', '\\\\nas\\filme'), [{ label: '\\\\nas\\filme', dir: '' }, { label: 'Filme', dir: 'Filme' }, { label: 'Familie', dir: 'Filme/Familie' }]);
    assert.equal(MS.parentDir('Filme/Familie'), 'Filme');
    assert.equal(MS.parentDir('Filme'), '');
    assert.equal(MS.parentDir(''), null);
    assert.deepEqual(MS.shareWay(share(), 'smb', { atHome: true }, t), { label: 'SMB · media.folders.home', hint: 'media.folders.pairHint' });
    assert.deepEqual(MS.shareWay(share({ pairWith: null, kind: 'webdav' }), 'webdav', { atHome: false }, t), { label: 'WebDAV · media.folders.away', hint: 'media.folders.originalHint' });
    assert.equal(MS.shareWay(share(), null, {}, t).label, 'SMB');
  });

  it('Ordner with Jellyfin (as Android #301): the libraries beside the shares, one server read is enough', () => {
    assert.equal(MS.folderStart({ sources: [jelly()] }), 'roots', 'Jellyfin alone: its libraries, no empty card');
    assert.equal(MS.folderStart({ sources: [jelly(), share()] }), 'roots', 'beside libraries a share is not opened by itself');
    assert.equal(MS.folderStart({ sources: [jelly({ ready: false }), share()] }), 'share');
    assert.equal(MS.folderStart({ sources: [share()] }), 'share');
    assert.equal(MS.folderStart({ sources: [jelly({ ready: false })] }), 'empty');
    assert.equal(MS.folderStart(null), 'empty');
    const ok = { ok: true, folders: [{ id: 'v1', name: 'Filme' }, { id: 'v2', name: 'Serien' }, { id: 7 }], items: [] };
    assert.deepEqual(MS.libraryRoots([{ sourceId: 'j1', r: ok }, { sourceId: 'j2', r: { ok: false, code: 'offline' } }]), {
      rows: [{ sourceId: 'j1', id: 'v1', name: 'Filme' }, { sourceId: 'j1', id: 'v2', name: 'Serien' }], error: null,
    });
    assert.deepEqual(MS.libraryRoots([{ sourceId: 'j2', r: { ok: false, code: 'offline' } }]), { rows: [], error: 'offline' });
    assert.deepEqual(MS.libraryRoots([{ sourceId: 'j1', r: { ok: true, folders: [], items: [] } }]), { rows: [], error: null });
    assert.deepEqual(MS.libraryRoots([]), { rows: [], error: null });
  });

  it('the overview "Ergänzt" (as Android #309): head without names, Als Nächstes, marks, genres', () => {
    assert.equal(MS.headLabel(jelly(), t, false), 'media.src.jellyfinOnly', 'one server: only the kind');
    assert.equal(MS.headLabel(jelly(), t, true), 'media.src.jellyfin(DS918+)', 'several: the name only in the choice');
    assert.deepEqual(MS.nextUpWithout([title({ id: 'e5' }), title({ id: 'e4' })], [title({ id: 'e4' })]).map((x) => x.id), ['e5']);
    assert.equal(MS.newEpisodes([title({ kind: 'series', newCount: 3 }), title({ kind: 'episode' })]), 4);
    assert.equal(MS.posterMark(title({ kind: 'series', newCount: 3 }), t), 'media.mark.newCount(3)');
    assert.equal(MS.posterMark(title({ kind: 'episode', season: 2, episode: 5 }), t), 'media.mark.seasonEpisode(2,5)');
    assert.equal(MS.posterMark(title(), t), null);
    const c = MS.nextCard(title({ kind: 'episode', name: 'Tauwetter', seriesName: 'Station Eisvogel', season: 2, episode: 5, runtimeMs: 52 * MIN, backdrop: 'gcmedia://image/tok/b' }), t);
    assert.deepEqual(c, { id: 'a1', title: 'Station Eisvogel', sub: 'Tauwetter · media.runtime.m(52)', mark: 'media.mark.seasonEpisode(2,5)', picture: 'gcmedia://image/tok/b' });
    assert.equal(MS.genreTone('Krimi'), MS.genreTone('krimi'));
    assert.ok(MS.genreTone('Drama') >= 0 && MS.genreTone('Drama') < 5);
    assert.deepEqual(MS.mergeGenres(['Krimi', 'drama'], ['Drama', ' ', 'Äpfel']), ['Äpfel', 'drama', 'Krimi']);
    // "Favoriten" leaves the shares out of the grid (they have none)
    const nas = title({ id: 'f:x', sourceId: 's1', name: 'Leuchtfeuer', fromShare: true, played: false });
    assert.equal(MS.mergeGrid([], true, [nas], { sort: 'name' }).length, 1);
    assert.equal(MS.mergeGrid([], true, [nas], { sort: 'name', favorite: true }).length, 0);
  });

  it('a title in a Jellyfin folder: its line, picture, bar and whether it plays', () => {
    const m = MS.libraryTitle(title(), t);
    assert.equal(m.title, 'Kobaltnacht');
    assert.equal(m.sub, `2025 · media.runtime.hm(1,48) · ${MS.leftLabel(title(), t)}`);
    assert.equal(m.picture, title().poster);
    assert.equal(m.progress, 39);
    assert.equal(m.playable, true);
    const s = MS.libraryTitle(title({ kind: 'series', childCount: 3, resumable: false, backdrop: 'gcmedia://image/tok/b' }), t);
    assert.equal(s.sub, '2025 · media.seasons(3)');
    assert.equal(s.picture, 'gcmedia://image/tok/b');
    assert.equal(s.playable, false);
    assert.equal(s.progress, 0);
    assert.equal(MS.libraryTitle(title({ kind: 'season', seriesName: 'Graufeld', year: null, resumable: false }), t).sub, 'Graufeld');
    assert.equal(MS.libraryTitle(title({ kind: 'video', year: null, resumable: false, played: true }), t).played, true);
  });

  it('the check before the start: what the PC cannot, VLC or another app', () => {
    const dts = { verdict: 'partial', container: 'mkv', video: 'ok', audio: 'no', reasons: ['audio_codec'], external: true, streams: { video: ['h264'], audio: ['dts'], subtitles: [] } };
    assert.deepEqual(MS.checkNote(dts, t), { level: 'warn', text: 'media.check.audio(DTS)', external: true });
    assert.deepEqual(MS.checkNote({ verdict: 'no', container: 'avi', reasons: ['container'], external: true }, t), { level: 'bad', text: 'media.check.container(AVI)', external: true });
    assert.deepEqual(MS.checkNote({ verdict: 'yes', reasons: [], external: false }, t), { level: 'ok', text: 'media.check.ok', external: false });
    assert.equal(MS.checkNote({ verdict: 'yes', reasons: ['picture_subtitles'], streams: { audio: ['aac'] } }, t).level, 'warn');
    assert.equal(MS.checkNote({ verdict: 'unknown', reasons: ['unknown'] }, t).level, 'unknown');
    assert.equal(MS.checkNote({ verdict: 'partial', reasons: ['hevc_no_hw'], external: true, streams: { video: ['hevc'], audio: ['aac'] } }, t).text, 'media.check.hevc');
    assert.equal(MS.checkNote(null, t), null);
    assert.equal(MS.externalApp({ vlc: true }, 'webdav'), 'vlc');
    assert.equal(MS.externalApp({ vlc: false, openPath: true }, 'smb'), 'default');
    assert.equal(MS.externalApp({ vlc: false, openPath: true }, 'webdav'), null, 'WebDAV has no path for Windows\' app');
    assert.equal(MS.errorText('no_vlc', t), 'media.error.no_vlc');
  });

  it('the page and the main process are wired for the folders', () => {
    const view = read('src', 'renderer', 'media-view.js');
    assert.match(view, /api\.shareList\(/);
    assert.match(view, /api\.shareCheck\(/);
    assert.match(view, /api\.shareExternal\(/);
    assert.match(read('src', 'renderer', 'media-player.js'), /media\.check\.anyway/);
    assert.match(read('src', 'main', 'main.js'), /openPath: \(target\) => shell\.openPath\(target\)/);
  });
});

describe('„Im Ordner suchen“ and the menu of a title (as Android)', () => {
  it('every word, any case and accents, without the extension (ShareFolders.matches)', () => {
    assert.equal(MS.nameMatches('Geburtstag.Oma.mkv', 'oma'), true);
    assert.equal(MS.nameMatches('Fußball WM 2014.mp4', 'fussball 2014'), true);
    assert.equal(MS.nameMatches('Fußball WM 2014.mp4', 'fussball 2018'), false, 'every word');
    assert.equal(MS.nameMatches('Kupferstadt.2025.1080p.mkv', 'mkv'), false, 'not the extension');
    assert.equal(MS.nameMatches('Strand.Urlaub', 'urlaub', true), true, 'a folder or title keeps its whole name');
    assert.equal(MS.nameMatches('Strände_2019.mkv', 'STRANDE'), true);
    assert.equal(MS.nameMatches('x.mkv', '   '), false, 'no words: no hit');
  });

  it('a share\'s folder: its folders and files by name, then the hits below, each once', () => {
    const items = [
      { name: 'Strand 2019', path: 'Urlaub/Strand 2019', directory: true, kind: 'folder' },
      { name: 'Berge', path: 'Urlaub/Berge', directory: true, kind: 'folder' },
      { name: 'Strand.Tag1.mkv', path: 'Urlaub/Strand.Tag1.mkv', directory: false, kind: 'video', itemId: 'f:Urlaub/Strand.Tag1.mkv' },
      { name: 'Strand.jpg', path: 'Urlaub/Strand.jpg', directory: false, kind: 'image' },
    ];
    const below = [
      { name: 'Strand.Tag1.mkv', path: 'Urlaub/Strand.Tag1.mkv', directory: false, kind: 'video', folder: 'Urlaub' },
      { name: 'Strand.Abend.mkv', path: 'Urlaub/Strand 2019/Strand.Abend.mkv', directory: false, kind: 'video', folder: 'Urlaub/Strand 2019' },
    ];
    assert.deepEqual(MS.folderHits(items, below, 'strand').map((e) => e.path), ['Urlaub/Strand 2019', 'Urlaub/Strand.Tag1.mkv', 'Urlaub/Strand 2019/Strand.Abend.mkv']);
    assert.deepEqual(MS.folderHits(items, [], 'berge').map((e) => e.path), ['Urlaub/Berge']);
    assert.equal(MS.hitFolder('Urlaub/Strand 2019', 'Urlaub'), 'Strand 2019');
    assert.equal(MS.hitFolder('Urlaub', 'Urlaub'), '', 'the folder itself: no line');
    assert.equal(MS.hitFolder('Serien/Graufeld', ''), 'Serien/Graufeld');
  });

  it('a Jellyfin folder: its folders and titles by name, then Jellyfin\'s hits below', () => {
    const r = MS.libraryHits([{ id: 'f1', name: 'Klassiker' }, { id: 'f2', name: 'Kobalt-Reihe' }], [title({ id: 'a1' }), title({ id: 'a2', name: 'Moorlicht' })], [title({ id: 'a1' }), title({ id: 'a3', name: 'Kobaltnacht II' })], 'kobalt');
    assert.deepEqual(r.folders.map((f) => f.id), ['f2']);
    assert.deepEqual(r.items.map((x) => x.id), ['a1', 'a3']);
  });

  it('the menu: Weiter ab / Abspielen, Von vorn when begun, Gesehen either way; no player: only Gesehen', () => {
    assert.deepEqual(MS.titleMenu(title(), t, true), [
      { id: 'play', label: 'media.detail.resume(42:10)' },
      { id: 'restart', label: 'media.detail.restart' },
      { id: 'played', label: 'media.detail.markPlayed' },
    ]);
    assert.deepEqual(MS.titleMenu(title({ positionMs: 0, played: true }), t, true).map((a) => [a.id, a.label]), [['play', 'media.detail.play'], ['played', 'media.detail.markUnplayed']]);
    assert.deepEqual(MS.titleMenu(title({ kind: 'series', positionMs: 0 }), t, true).map((a) => a.id), ['play', 'played']);
    assert.deepEqual(MS.titleMenu(title({ kind: 'season' }), t, true).map((a) => a.id), ['played']);
    assert.deepEqual(MS.titleMenu(title(), t, false).map((a) => a.id), ['played']);
    assert.deepEqual(MS.titleMenu(title({ kind: 'collection' }), t, true), []);
    assert.deepEqual(MS.titleMenu(null, t, true), []);
  });

  it('the menu\'s key: the context-menu key or Umschalt+F10', () => {
    assert.equal(MS.isMenuKey({ key: 'ContextMenu' }), true);
    assert.equal(MS.isMenuKey({ key: 'F10', shiftKey: true }), true);
    assert.equal(MS.isMenuKey({ key: 'F10', shiftKey: false }), false);
    assert.equal(MS.isMenuKey({ key: 'Enter' }), false);
  });

  it('the page is wired: the searches of the core, the menu on the rows, grids and lists', () => {
    const view = read('src', 'renderer', 'media-view.js');
    assert.match(view, /api\.shareSearch\(/);
    assert.match(view, /api\.librarySearch\(/);
    assert.match(view, /return withMenu\(b, it, runFor\(it\)/, 'the posters of the grid and the rows');
    assert.match(view, /withMenu\(card, it, runFor\(it\)\)/, 'Weiterschauen');
    assert.match(view, /withMenu\(rowEl, folderTitle\(share, e\)/, 'a share\'s file');
  });
});

describe('Medien-Plugin (W2): the sources from the server, the network rule', () => {
  const managed = (o = {}) => jelly({ managed: true, sid: 'jf-1', awayMode: 'vpn', deviceName: 'GateControl · Büro-PC', problem: null, ...o });

  it('the entry "Medien" only with the plugin\'s tab', () => {
    assert.equal(MS.visible({ server: { visible: true } }), true);
    assert.equal(MS.visible({ server: { visible: false } }), false);
    assert.equal(MS.visible({ sources: [jelly()] }), false, 'a source set up on this PC is no reason any more');
  });

  it('the way: home, away through the VPN, direct, blocked (only through the VPN)', () => {
    assert.equal(MS.wayOf({ atHome: false, blocked: true }), 'blocked');
    assert.equal(MS.linkLabel({ atHome: false, blocked: true }, t, 'de').text, 'media.link.blocked');
    assert.equal(MS.linkLabel({ atHome: false, via: 'direct', bps: null }, t, 'de').text, 'media.link.directNoBw');
    assert.equal(MS.statusLine({ atHome: false, blocked: true }, t, 'de'), 'media.status.blocked');
    assert.equal(MS.sourcePill(managed(), t).text, 'media.way.home');
    assert.equal(MS.sourcePill(managed({ link: { atHome: false, via: 'tunnel' } }), t).text, 'media.way.vpn');
    assert.equal(MS.sourcePill(managed({ link: { atHome: false, via: 'direct' } }), t).text, 'media.way.direct');
    assert.equal(MS.sourcePill(managed({ link: { atHome: false, blocked: true } }), t).text, 'media.way.blocked');
    assert.deepEqual(MS.sourcePill(managed({ problem: 'no_mapping' }), t), { cls: 'is-warn', text: 'media.problem.no_mapping' });
    assert.equal(MS.sourcePill(managed({ ready: false, userName: null }), t).text, 'media.src.signingInPill', 'signs in by itself');
    assert.equal(MS.awayRule(managed(), t), 'media.src.awayVpn');
    assert.equal(MS.awayRule(managed({ awayMode: 'direct', awayAddress: 'https://jellyfin.example.test' }), t), 'media.src.awayDirect(jellyfin.example.test)');
    assert.equal(MS.awayRule(jelly(), t), null);
  });

  it('what a source says: the plugin\'s device name, "wird angemeldet", "SMB geprüft", WebDAV after 1219', () => {
    assert.match(MS.sourceSub(managed(), t, 'PC'), /media\.src\.device\(GateControl · Büro-PC\)/);
    assert.match(MS.sourceSub(managed({ userName: null, ready: false }), t), /media\.src\.signingIn/);
    assert.match(MS.sourceSub(share({ managed: true, smbChecked: true }), t), /media\.src\.smbChecked/);
    assert.match(MS.sourceSub(share({ managed: true, link: { smbConflict: true } }), t), /media\.src\.smbConflict/);
  });

  it('the notes of the server: off, licence, long offline, taken over; the age of the list', () => {
    assert.deepEqual(MS.serverNotes({ state: 'unavailable', reason: 'plugin_unavailable' }, t).map((n) => n.text), ['media.server.off']);
    assert.deepEqual(MS.serverNotes({ state: 'unavailable', reason: 'license_required' }, t).map((n) => n.text), ['media.server.license']);
    assert.deepEqual(MS.serverNotes({ offline: { days: 31, hint: true, expired: false } }, t).map((n) => n.text), ['media.server.offline(31)']);
    const n = MS.serverNotes({ notice: { adopted: [{ name: 'DS918+' }], dropped: [{ name: 'Alt' }], at: 5 } }, t);
    assert.equal(n[0].key, 'notice:5');
    assert.match(n[0].text, /media\.server\.adopted\(DS918\+\).*media\.server\.dropped\(Alt\)/);
    assert.equal(MS.fetchedLabel({ fetchedAt: NOW - 3 * MIN }, t, NOW), 'media.server.fetchedMin(3)');
    assert.equal(MS.fetchedLabel({}, t, NOW), null);
    assert.equal(MS.errorText('vpn_required', t), 'media.error.vpn_required');
    assert.equal(MS.errorText('no_mapping', t), 'media.error.no_mapping');
  });

  it('wiring: Quellen without a dialog, the entry by the tab, the tunnel for the network rule, the server\'s sources', () => {
    const view = read('src', 'renderer', 'media-sources-view.js');
    for (const gone of ['addShare', 'quickConnect', 'signIn(', 'authorize(', 'removeSource', 'md-dlg', 'discover(']) assert.ok(!view.includes(gone), gone);
    const renderer = read('src', 'renderer', 'renderer.js');
    assert.ok(!/if \(mediaView\) \$\('#nav-medien'\)\.hidden = false;/.test(renderer), 'not shown just because the core has Medien');
    assert.match(renderer, /onVisible: \(show\) => \{\s*\$\('#nav-medien'\)\.hidden = !show;/);
    const main = read('src', 'main', 'main.js');
    assert.match(main, /tunnel: \{\s*up: \(\) => !!tunnelState\.connected,/);
    assert.match(main, /new MediaServerSources\(\{/);
    assert.match(main, /mediaSources\?\.start\(\)/);
    const mediaView = read('src', 'renderer', 'media-view.js');
    assert.match(mediaView, /media\.vpn\.connecting/);
    assert.match(mediaView, /api\.sources\.refresh\(\)/);
  });
});

describe('media-state: „Videos umwandeln“ (gatecontrol-medien 1.6.0)', () => {
  it('what this PC does not play itself, for the text', () => {
    assert.equal(MS.convertWhat({ code: 'hevc', codec: 'hevc' }), 'HEVC');
    assert.equal(MS.convertWhat({ code: 'video_codec', codec: 'mpeg2video' }), 'MPEG-2');
    assert.equal(MS.convertWhat({ code: 'dovi', codec: 'hevc' }), 'Dolby Vision');
    assert.equal(MS.convertWhat({ code: 'hdr', codec: 'hevc' }), 'HEVC HDR');
    assert.equal(MS.convertWhat(null), null);
  });

  it('the clock of the start: German 24 hours, past or unknown none', () => {
    const at = new Date(2026, 10, 25, 1, 8).getTime();
    assert.equal(MS.convertClock(at, 'de', NOW), '01:08');
    assert.match(MS.convertClock(at, 'en', NOW), /^01:08/);
    assert.equal(MS.convertClock(NOW - 1000, 'de', NOW), null);
    assert.equal(MS.convertClock(null, 'de', NOW), null);
  });

  it('the card per state: offer with the button, requested, queued with place and time, running with the bar; else none', () => {
    const problem = { code: 'hevc', codec: 'hevc' };
    const offer = MS.convertCard({ kind: 'offer', problem }, t, 'de', NOW);
    assert.deepEqual(offer, { kind: 'offer', title: 'media.convert.offerTitle', text: 'media.convert.offerText(HEVC)', button: 'media.convert.request', percent: null });
    assert.equal(MS.convertCard({ kind: 'offer' }, t, 'de', NOW).text, 'media.convert.offerTextPlain');
    assert.deepEqual(MS.convertCard({ kind: 'requested', problem }, t, 'de', NOW), { kind: 'requested', title: 'media.convert.requestedTitle', text: 'media.convert.requestedText', button: null, percent: null });
    const q = MS.convertCard({ kind: 'queued', position: 2, startsAt: new Date(2026, 10, 25, 1, 0).getTime(), problem }, t, 'de', NOW);
    assert.equal(q.title, 'media.convert.queuedTitle · media.convert.queuedPlace(2) · media.convert.queuedFrom(01:00)');
    assert.equal(q.button, null, 'nothing to press: playing stays');
    assert.equal(MS.convertCard({ kind: 'queued', position: null, startsAt: null }, t, 'de', NOW).title, 'media.convert.queuedTitle');
    const r = MS.convertCard({ kind: 'running', percent: 47.4, problem }, t, 'de', NOW);
    assert.deepEqual([r.title, r.percent], ['media.convert.runningPercent(47)', 47]);
    assert.deepEqual([MS.convertCard({ kind: 'running', percent: null }, t, 'de', NOW).title], ['media.convert.runningTitle']);
    assert.equal(MS.convertCard(null, t, 'de', NOW), null);
    assert.equal(MS.convertCard({ kind: 'done' }, t, 'de', NOW), null);
  });

  it('the page asks the core and keeps playing possible', () => {
    const mediaView = read('src', 'renderer', 'media-view.js');
    assert.match(mediaView, /api\.convertHint\(/);
    assert.match(mediaView, /api\.convertRequest\(/);
    assert.match(mediaView, /api\.convertPrefetch\(/);
  });
});
