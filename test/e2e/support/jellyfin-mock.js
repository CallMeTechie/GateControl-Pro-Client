'use strict';

/**
 * A small Jellyfin (10.10) for the e2e suite of "Medien": the REST paths the core's JellyfinClient asks
 * (core services/media-jellyfin.js), on 127.0.0.1 with a random port. The app reaches it at
 * http://localhost:<port> ("localhost" is a home host for plain HTTP, core utils/media-address.js); it is not in a
 * subnet of a LAN adapter, so the core takes it as "away" and measures the bandwidth (Playback/BitrateTest).
 *
 *   const jf = await startJellyfin({ password: 'geheim' });
 *   jf.address            'localhost:<port>' (what the person types)
 *   jf.state.qcConfirmed  true: the Quick Connect code counts as confirmed
 *   jf.log                [{ method, path, query, body }] of every request
 *   jf.reports            the progress reports (Sessions/Playing…)
 *   await jf.close()
 *
 * Titles, names and addresses are made up (as the mockups of Stufe 4).
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const FIXTURES = path.join(__dirname, '..', 'fixtures');
const POSTER = fs.readFileSync(path.join(FIXTURES, 'camera-still.jpg'));
/** The bytes of the bandwidth measurement (Playback/BitrateTest): at most this much, made once. */
const MEASURE = Buffer.alloc(3000000);
const TICKS = 10000;
const MIN = 60 * 1000;
const DAY = 24 * 60 * MIN;
const SERVER_ID = 'f00dfeed0000000000000000000000aa';
const USER_ID = 'a11ce0000000000000000000000000b1';
const TOKEN = 'e2e-jellyfin-token-0001';

const hex = (n) => n.toString(16).padStart(32, '0');
let nextId = 0x1000;
const id = () => hex(nextId++);

function streams({ video = 'hevc', width = 3840, height = 2160, range = 'HDR10', audio = [], subs = [] } = {}) {
  const s = [{ Index: 0, Type: 'Video', Codec: video, Width: width, Height: height, VideoRange: range === 'SDR' ? 'SDR' : 'HDR', VideoRangeType: range, IsDefault: true }];
  let i = 1;
  for (const a of audio) s.push({ Index: i++, Type: 'Audio', Codec: a.codec, Language: a.lang, Channels: a.ch, Title: a.title || null, DisplayTitle: a.display || null, IsDefault: !!a.def });
  for (const x of subs) s.push({ Index: i++, Type: 'Subtitle', Codec: x.codec, Language: x.lang, IsTextSubtitleStream: x.text !== false, IsExternal: false, DeliveryMethod: x.text !== false ? 'External' : 'Encode', DeliveryUrl: x.text !== false ? `/Videos/x/x/Subtitles/${i - 1}/0/Stream.vtt` : null });
  return s;
}

function movie(name, year, o = {}) {
  return {
    Id: o.id || id(), Type: 'Movie', Name: name, ProductionYear: year, RunTimeTicks: (o.min || 100) * MIN * TICKS,
    Genres: o.genres || ['Drama'], OfficialRating: o.rating || null, Overview: o.overview || null,
    DateCreated: new Date(Date.now() - (o.addedDaysAgo ?? 40) * DAY).toISOString(),
    ImageTags: o.poster ? { Primary: 'tag1' } : {}, BackdropImageTags: o.poster ? ['bd1'] : [],
    UserData: { PlaybackPositionTicks: (o.posMin || 0) * MIN * TICKS, Played: !!o.played, LastPlayedDate: o.posMin ? new Date(Date.now() - (o.playedHoursAgo || 1) * 3600000).toISOString() : null },
    MediaSources: [{
      Id: o.sourceId || id(), Container: o.container || 'mkv', Bitrate: o.bitrate || 40000000, RunTimeTicks: (o.min || 100) * MIN * TICKS,
      SupportsDirectPlay: true, SupportsDirectStream: true, SupportsTranscoding: true,
      DefaultAudioStreamIndex: 1, MediaStreams: o.streams || streams({ video: 'h264', width: 1920, height: 1080, range: 'SDR', audio: [{ codec: 'aac', lang: 'ger', ch: 2, def: true }] }),
    }],
  };
}

function createLibrary() {
  const kobalt = movie('Kobaltnacht', 2025, {
    min: 108, posMin: 42.1667, genres: ['Drama', 'Mystery'], rating: '12', addedDaysAgo: 20, poster: true, playedHoursAgo: 2,
    overview: 'Eine Funkerin auf einer abgelegenen Wetterstation fängt in einer Winternacht Signale auf, die es nicht geben dürfte.',
    streams: streams({
      audio: [{ codec: 'dts', lang: 'ger', ch: 6, def: true }, { codec: 'truehd', lang: 'eng', ch: 8 }, { codec: 'aac', lang: 'ger', ch: 2, title: 'Hörfilm-Fassung' }],
      subs: [{ codec: 'subrip', lang: 'ger' }, { codec: 'PGSSUB', lang: 'eng', text: false }],
    }),
  });
  const movies = [
    kobalt,
    movie('Achterwasser', 2019, { genres: ['Krimi'] }),
    movie('Blaue Stunde in Tarnow', 2020, { genres: ['Drama'] }),
    movie('Der Pegelwart', 2018, { genres: ['Komödie'], played: true }),
    movie('Kupferstadt', 2025, { min: 124, addedDaysAgo: 3, genres: ['Krimi'] }),
    movie('Moorlicht', 2017, { genres: ['Mystery'] }),
    movie('Nordkap, einfach', 2021, { genres: ['Komödie'] }),
    movie('Sternwarte 9', 2026, { min: 112, addedDaysAgo: 1, genres: ['Science-Fiction'] }),
    movie('Wolkenbruch & Söhne', 2023, { min: 104, genres: ['Komödie'] }),
    movie('Zugvogelzeit', 2016, { genres: ['Drama'] }),
    movie('Hinterm Salzberg', 2024, { min: 97, addedDaysAgo: 5, genres: ['Drama'] }),
    movie('Paulas Werkstatt', 2022, { min: 96, posMin: 72.5, playedHoursAgo: 30, genres: ['Komödie'] }),
  ];
  const series = [];
  const seasons = new Map();
  const episodes = new Map();
  const mkSeries = (name, year, plan, o = {}) => {
    const sid = id();
    const s = {
      Id: sid, Type: 'Series', Name: name, ProductionYear: year, ChildCount: plan.length, Genres: o.genres || ['Drama'],
      Overview: o.overview || null, DateCreated: new Date(Date.now() - (o.addedDaysAgo ?? 60) * DAY).toISOString(), ImageTags: {},
      UserData: { UnplayedItemCount: 0, Played: false },
    };
    series.push(s);
    const list = [];
    plan.forEach((count, si) => {
      const seasonId = id();
      const season = { Id: seasonId, Type: 'Season', Name: `Staffel ${si + 1}`, IndexNumber: si + 1, SeriesId: sid, SeriesName: name, UserData: { UnplayedItemCount: 0 } };
      list.push(season);
      const eps = [];
      for (let e = 1; e <= count; e++) {
        const pos = o.progress && o.progress[0] === si + 1 && o.progress[1] === e ? o.progress[2] : 0;
        const played = o.watched ? (si + 1 < o.watched[0] || (si + 1 === o.watched[0] && e <= o.watched[1])) : false;
        const ep = movie(`Folge ${e}: ${o.titles && o.titles[e - 1] ? o.titles[e - 1] : 'Ohne Titel'}`, year, { min: 52, posMin: pos, playedHoursAgo: pos ? 1 : 0, played, genres: s.Genres });
        Object.assign(ep, { Type: 'Episode', SeriesId: sid, SeriesName: name, SeasonId: seasonId, ParentIndexNumber: si + 1, IndexNumber: e });
        eps.push(ep);
        if (!played) season.UserData.UnplayedItemCount++;
      }
      episodes.set(seasonId, eps);
    });
    seasons.set(sid, list);
    return s;
  };
  mkSeries('Station Eisvogel', 2024, [6, 6], {
    progress: [2, 4, 34], watched: [2, 3], addedDaysAgo: 12,
    titles: ['Ankunft', 'Eisdrift', 'Funkstille', 'Polarnacht', 'Tauwetter', 'Abflug'],
    overview: 'Eine Forschungsstation im Eis, sechs Menschen und ein Winter, der nicht enden will.',
  });
  mkSeries('Graufeld', 2021, [8, 8, 6], { addedDaysAgo: 4, genres: ['Krimi'] });
  mkSeries('Ankerplatz 12', 2023, [10], { addedDaysAgo: 90, genres: ['Komödie'] });
  const all = () => [...movies, ...series, ...[...episodes.values()].flat()];
  return { movies, series, seasons, episodes, all, kobalt };
}

const pick = (it) => {
  const { MediaSources, ...rest } = it;
  return rest;
};

async function startJellyfin({ password = 'geheim', quickConnect = true, authorizeCode = '731205' } = {}) {
  const lib = createLibrary();
  const state = { qcConfirmed: false, quickConnect, authorized: [], loggedOut: 0 };
  const log = [];
  const reports = [];

  const send = (res, status, body, type = 'application/json') => {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    res.writeHead(status, { 'Content-Type': type, 'Content-Length': buf.length });
    res.end(buf);
  };
  const authed = (req) => /Token="e2e-jellyfin-token-0001"/.test(String(req.headers.authorization || ''));
  const auth = { AccessToken: TOKEN, ServerId: SERVER_ID, User: { Id: USER_ID, Name: 'Mila' } };

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const u = new URL(req.url, 'http://x');
      const p = u.pathname;
      const q = u.searchParams;
      const raw = Buffer.concat(chunks).toString('utf8');
      let body = null;
      try { body = raw ? JSON.parse(raw) : null; } catch { body = null; }
      log.push({ method: req.method, path: p, query: Object.fromEntries(q), body });

      if (p === '/System/Info/Public') return send(res, 200, { Id: SERVER_ID, ServerName: 'DS918+', Version: '10.10.3', LocalAddress: 'http://192.168.1.20:8096' });
      if (p === '/QuickConnect/Enabled') return send(res, 200, state.quickConnect);
      if (p === '/QuickConnect/Initiate' && req.method === 'POST') return state.quickConnect ? send(res, 200, { Code: '482913', Secret: 'qc-secret-1', Authenticated: false }) : send(res, 401, '');
      if (p === '/QuickConnect/Connect') return send(res, 200, { Code: '482913', Secret: q.get('secret'), Authenticated: state.qcConfirmed });
      if (p === '/Users/AuthenticateWithQuickConnect' && req.method === 'POST') return state.qcConfirmed ? send(res, 200, auth) : send(res, 401, '');
      if (p === '/Users/AuthenticateByName' && req.method === 'POST') return body && body.Pw === password && body.Username === 'mila' ? send(res, 200, auth) : send(res, 401, '');

      if (!authed(req)) return send(res, 401, '');

      if (p === '/Playback/BitrateTest') {
        // the size asked for, as a whole number within the fixed buffer (never a buffer of the size asked for)
        const asked = Number.parseInt(String(q.get('size') || ''), 10);
        const size = Number.isInteger(asked) && asked > 0 ? Math.min(MEASURE.length, asked) : MEASURE.length;
        res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': size });
        return res.end(MEASURE.subarray(0, size));
      }
      if (p === '/Sessions/Logout') { state.loggedOut++; res.writeHead(204); return res.end(); }
      if (p === '/QuickConnect/Authorize' && req.method === 'POST') {
        if (q.get('code') !== authorizeCode) return send(res, 404, '');
        state.authorized.push(q.get('code'));
        return send(res, 200, true);
      }
      if (/^\/Sessions\/Playing/.test(p)) { reports.push({ path: p, body }); res.writeHead(204); return res.end(); }

      let m = /^\/UserPlayedItems\/([0-9a-f]{32})$/.exec(p);
      if (m) {
        const it = lib.all().find((x) => x.Id === m[1]);
        if (!it) return send(res, 404, '');
        it.UserData.Played = req.method === 'POST';
        if (it.UserData.Played) it.UserData.PlaybackPositionTicks = 0;
        return send(res, 200, { Played: it.UserData.Played });
      }
      m = /^\/Items\/([0-9a-f]{32})\/Images\/(Primary|Backdrop)$/.exec(p);
      if (m) return send(res, 200, POSTER, 'image/jpeg');

      if (p === '/UserItems/Resume') {
        const items = lib.all().filter((x) => (x.Type === 'Movie' || x.Type === 'Episode') && x.UserData.PlaybackPositionTicks > 0 && !x.UserData.Played)
          .sort((a, b) => String(b.UserData.LastPlayedDate).localeCompare(String(a.UserData.LastPlayedDate)));
        return send(res, 200, { Items: items.map(pick), TotalRecordCount: items.length });
      }
      if (p === '/Items/Latest') {
        const items = [...lib.movies, ...lib.series].sort((a, b) => b.DateCreated.localeCompare(a.DateCreated)).slice(0, Number(q.get('limit')) || 16);
        return send(res, 200, items.map(pick));
      }
      if (p === '/Items') {
        const types = String(q.get('includeItemTypes') || '').split(',');
        let items = lib.all().filter((x) => types.includes(x.Type));
        const term = q.get('searchTerm');
        if (term) items = items.filter((x) => x.Name.toLowerCase().includes(term.toLowerCase()));
        if (q.get('filters') === 'IsUnplayed') items = items.filter((x) => !x.UserData.Played);
        if (q.get('genres')) items = items.filter((x) => (x.Genres || []).includes(q.get('genres')));
        const by = String(q.get('sortBy') || 'SortName');
        if (by.startsWith('DateCreated')) items.sort((a, b) => b.DateCreated.localeCompare(a.DateCreated));
        else if (by.startsWith('ProductionYear')) items.sort((a, b) => (b.ProductionYear - a.ProductionYear) || a.Name.localeCompare(b.Name, 'de'));
        else items.sort((a, b) => a.Name.localeCompare(b.Name, 'de'));
        const start = Number(q.get('startIndex')) || 0;
        const limit = Number(q.get('limit')) || 100;
        return send(res, 200, { Items: items.slice(start, start + limit).map(pick), TotalRecordCount: items.length, StartIndex: start });
      }
      m = /^\/Shows\/([0-9a-f]{32})\/Seasons$/.exec(p);
      if (m) return send(res, 200, { Items: (lib.seasons.get(m[1]) || []).map(pick) });
      m = /^\/Shows\/([0-9a-f]{32})\/Episodes$/.exec(p);
      if (m) return send(res, 200, { Items: (lib.episodes.get(q.get('seasonId')) || []).map(pick) });
      m = /^\/Items\/([0-9a-f]{32})$/.exec(p);
      if (m) {
        const it = lib.all().find((x) => x.Id === m[1]);
        return it ? send(res, 200, it) : send(res, 404, '');
      }
      return send(res, 404, '');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return {
    port,
    address: `localhost:${port}`,
    state,
    log,
    reports,
    lib,
    count: (re) => log.filter((x) => re.test(x.path)).length,
    close: () => new Promise((r) => { if (server.closeAllConnections) server.closeAllConnections(); server.close(() => r()); }),
  };
}

module.exports = { startJellyfin, SERVER_ID, USER_ID };
