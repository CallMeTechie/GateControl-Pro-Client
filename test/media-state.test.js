'use strict';

// View logic of the page "Medien" (src/renderer/media-state.js, no DOM): the sources and the way to them, the times,
// the cards of the rows, merging several Jellyfin servers and the search over all sources, the grid's keys and pages,
// the detail column (chips, sound, subtitles, quality), seasons and episodes, the dialog "Quelle hinzufügen" (address
// hints, the Quick Connect code, the certificate), error texts; and how the page is wired (index.html with the CSP for
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

describe('the dialog "Quelle hinzufügen"', () => {
  it('a share by name gets the hint to take the IP address', () => {
    assert.equal(MS.smbHost('\\\\nas\\filme'), 'nas');
    assert.equal(MS.smbHost('smb://192.168.1.20/filme'), '192.168.1.20');
    assert.equal(MS.smbHost('filme'), null);
    assert.equal(MS.smbNameHint('\\\\nas\\filme'), true);
    assert.equal(MS.smbNameHint('\\\\192.168.1.20\\filme'), false);
    assert.equal(MS.smbNameHint(''), false);
  });

  it('the form: an address, a user to a password, the WebDAV address when asked', () => {
    assert.equal(MS.formProblem('smb', { address: '' }), 'address');
    assert.equal(MS.formProblem('smb', { address: 'filme' }), 'address');
    assert.equal(MS.formProblem('webdav', { address: '\\\\nas\\filme' }), 'address');
    assert.equal(MS.formProblem('smb', { address: '\\\\nas\\filme', user: '', password: 'x' }), 'user');
    assert.equal(MS.formProblem('smb', { address: '\\\\nas\\filme', user: 'u', password: 'x', alsoWebdav: true, webdavAddress: '' }), 'webdav');
    assert.equal(MS.formProblem('smb', { address: '\\\\nas\\filme', user: 'u', password: 'x' }), null);
    assert.equal(MS.formProblem('webdav', { address: 'https://192.168.1.20:5006/filme' }), null);
    assert.equal(MS.formProblem('ftp', { address: 'x' }), 'invalid');
  });

  it('the WebDAV address suggested for an SMB share (Synology\'s port)', () => {
    assert.equal(MS.webdavFor('\\\\192.168.1.20\\filme'), 'https://192.168.1.20:5006/filme');
    assert.equal(MS.webdavFor('smb://nas/serien/alt'), 'https://nas:5006/serien');
    assert.equal(MS.webdavFor('nas'), '');
  });

  it('the Quick Connect codes: shown "482 913", typed "731 205" / "731-205"', () => {
    assert.equal(MS.codeLabel('482913'), '482 913');
    assert.equal(MS.codeOf('731 205'), '731205');
    assert.equal(MS.codeOf('731-205'), '731205');
    assert.equal(MS.codeOf('12345'), null);
    assert.equal(MS.codeOf('abcdef'), null);
  });

  it('the certificate: the fingerprint in pairs, the date', () => {
    const fp = 'ab'.repeat(32);
    assert.equal(MS.fingerprintLabel(fp), Array(32).fill('AB').join(':'));
    assert.equal(MS.fingerprintLabel('short'), 'short');
    assert.match(MS.dateLabel('2027-03-01T00:00:00Z', 'de-DE'), /0?1\.0?3\.2027/);
  });

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
    for (const k of MS.KINDS) keys.add(`media.dlg.kind.${k}`);
    for (const p of ['address', 'user', 'webdav', 'invalid']) keys.add(`media.dlg.problem.${p}`);
    for (const c of ['invalid', 'offline', 'unauthorized', 'not_found', 'unsupported', 'unsupported_version', 'quick_connect_off', 'expired', 'signed_out', 'no_protect', 'too_many', 'smb_conflict', 'cert_untrusted', 'cert_changed', 'no_lan_route', 'failed']) keys.add(`media.error.${c}`);
    assert.ok(keys.size > 100);
    for (const k of keys) {
      assert.equal(typeof get(de, k), 'string', `de: ${k}`);
      assert.equal(typeof get(en, k), 'string', `en: ${k}`);
    }
  });
});
