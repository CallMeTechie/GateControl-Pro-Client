'use strict';

/**
 * A small WebDAV share for the e2e suite of "Medien › Ordner" (Stufe 4h): PROPFIND (Depth 1) and GET with Range, as
 * the core's WebDavShare asks them (core services/media-share.js), with Basic access, on 127.0.0.1 with a random port.
 * The app reaches it at http://localhost:<port>/filme ("localhost" is a home host for plain HTTP); it is not in a
 * subnet of a LAN adapter, so the core takes the share as "away" — WebDAV is what a pair takes away anyway.
 *
 *   const dav = await startWebDav();
 *   dav.address   'http://localhost:<port>/filme' (what the person types)
 *   dav.user / dav.password
 *   dav.log       [{ method, path, range }] of every request
 *   await dav.close()
 *
 * The tree: a film that Jellyfin has too (Kobaltnacht: shown once, Jellyfin's), a film only on the NAS that plays
 * (Leuchtfeuer: VP8 + Opus, with its poster beside it), one Chromium has no sound for (Silvester am See: H.264 + DTS in
 * Matroska → "In VLC öffnen" / "Trotzdem abspielen"), series in season folders (Graufeld, which Jellyfin has too;
 * Hafenlichter only here). Titles are made up.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const FIXTURES = path.join(__dirname, '..', 'fixtures');
const MOVIE = fs.readFileSync(path.join(FIXTURES, 'media-movie.webm'));
const POSTER = fs.readFileSync(path.join(FIXTURES, 'camera-still.jpg'));

// ── a Matroska head with its tracks (as core test/media-playable.test.js builds it) ──
function idBytes(id) {
  const out = [];
  for (let v = id; v > 0; v = Math.floor(v / 256)) out.unshift(v % 256);
  return Buffer.from(out);
}
function size(n) {
  if (n < 0x7f) return Buffer.from([0x80 | n]);
  return Buffer.from([0x40 | (n >> 8), n & 0xff]);
}
const ebml = (id, ...content) => {
  const body = Buffer.concat(content.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(c, 'ascii'))));
  return Buffer.concat([idBytes(id), size(body.length), body]);
};
function mkv(tracks) {
  const header = ebml(0x1a45dfa3, ebml(0x4286, Buffer.from([1])), ebml(0x4282, 'matroska'));
  const entries = tracks.map(([type, codec]) => ebml(0xae, ebml(0xd7, Buffer.from([1])), ebml(0x83, Buffer.from([type])), ebml(0x86, codec)));
  const seg = Buffer.concat([ebml(0x1549a966, ebml(0x2ad7b1, Buffer.from([0x0f, 0x42, 0x40]))), ebml(0x1654ae6b, ...entries), ebml(0x1f43b675, Buffer.alloc(64))]);
  return Buffer.concat([header, idBytes(0x18538067), Buffer.from([0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), seg]);
}

const FILES = {
  'Kobaltnacht (2025)/Kobaltnacht (2025).webm': MOVIE,
  'Leuchtfeuer (2024)/Leuchtfeuer (2024).webm': MOVIE,
  'Leuchtfeuer (2024)/poster.jpg': POSTER,
  'Familie/Silvester am See.mkv': mkv([[1, 'V_MPEG4/ISO/AVC'], [2, 'A_DTS']]),
  'Familie/Notizen.txt': Buffer.from('nichts'),
  'Serien/Graufeld/Staffel 1/Graufeld.S01E01.Flut.webm': MOVIE,
  'Serien/Graufeld/Staffel 1/Graufeld.S01E02.Ebbe.webm': MOVIE,
  'Serien/Hafenlichter/Staffel 1/Hafenlichter.S01E01.Flut.webm': MOVIE,
  'Serien/Hafenlichter/Staffel 1/Hafenlichter.S01E02.Ebbe.webm': MOVIE,
  '@eaDir/x.jpg': POSTER,
};
const MODIFIED = new Date(Date.UTC(2026, 10, 20, 12, 0, 0)).toUTCString();

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const enc = (p) => p.split('/').map((x) => encodeURIComponent(x)).join('/');

function entriesOf(dir) {
  const prefix = dir ? `${dir}/` : '';
  const out = new Map();
  for (const [p, buf] of Object.entries(FILES)) {
    if (!p.startsWith(prefix)) continue;
    const rest = p.slice(prefix.length).split('/');
    if (out.has(rest[0])) continue;
    out.set(rest[0], rest.length > 1 ? { dir: true } : { dir: false, size: buf.length });
  }
  return out;
}

function multistatus(root, dir, entries, only = false) {
  const resp = (href, isDir, len) => `<d:response><d:href>${esc(href)}</d:href><d:propstat><d:prop>`
    + `<d:resourcetype>${isDir ? '<d:collection/>' : ''}</d:resourcetype>${isDir ? '' : `<d:getcontentlength>${len}</d:getcontentlength>`}`
    + `<d:getlastmodified>${MODIFIED}</d:getlastmodified></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`;
  const base = `${root}/${dir ? `${enc(dir)}/` : ''}`;
  const parts = only ? [] : [resp(base, true, 0)];
  for (const [name, e] of entries) parts.push(resp(`${base}${encodeURIComponent(name)}${e.dir ? '/' : ''}`, e.dir, e.size));
  return `<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">${parts.join('')}</d:multistatus>`;
}

async function startWebDav({ user = 'kino', password = 'e2e-dav-pw' } = {}) {
  const log = [];
  const root = '/filme';
  const expected = `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    log.push({ method: req.method, path: decodeURIComponent(url.pathname), range: req.headers.range || null });
    if (req.headers.authorization !== expected) {
      res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="filme"' });
      res.end();
      return;
    }
    let rel = decodeURIComponent(url.pathname);
    if (!rel.startsWith(root)) { res.writeHead(404); res.end(); return; }
    rel = rel.slice(root.length).replace(/^\/+|\/+$/g, '');
    if (rel.split('/').some((x) => x === '..')) { res.writeHead(404); res.end(); return; }
    if (req.method === 'PROPFIND' && FILES[rel]) {
      // a file (Depth 0): its own entry
      const i = rel.lastIndexOf('/');
      const body = Buffer.from(multistatus(root, i > 0 ? rel.slice(0, i) : '', new Map([[rel.slice(i + 1), { dir: false, size: FILES[rel].length }]]), true), 'utf8');
      res.writeHead(207, { 'Content-Type': 'application/xml; charset=utf-8', 'Content-Length': body.length });
      res.end(body);
      return;
    }
    if (req.method === 'PROPFIND') {
      const entries = entriesOf(rel);
      if (rel && !entries.size) { res.writeHead(404); res.end(); return; }
      const body = Buffer.from(multistatus(root, rel, entries), 'utf8');
      res.writeHead(207, { 'Content-Type': 'application/xml; charset=utf-8', 'Content-Length': body.length });
      res.end(body);
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); res.end(); return; }
    const buf = FILES[rel];
    if (!buf) { res.writeHead(404); res.end(); return; }
    const type = rel.endsWith('.jpg') ? 'image/jpeg' : rel.endsWith('.webm') ? 'video/webm' : rel.endsWith('.mkv') ? 'video/x-matroska' : 'application/octet-stream';
    const m = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
    if (m) {
      const start = m[1] === '' ? Math.max(0, buf.length - Number(m[2])) : Number(m[1]);
      const end = m[1] !== '' && m[2] !== '' ? Math.min(Number(m[2]), buf.length - 1) : buf.length - 1;
      if (start >= buf.length) { res.writeHead(416, { 'Content-Range': `bytes */${buf.length}` }); res.end(); return; }
      res.writeHead(206, { 'Content-Type': type, 'Content-Length': end - start + 1, 'Content-Range': `bytes ${start}-${end}/${buf.length}`, 'Accept-Ranges': 'bytes' });
      res.end(req.method === 'HEAD' ? undefined : buf.subarray(start, end + 1));
      return;
    }
    res.writeHead(200, { 'Content-Type': type, 'Content-Length': buf.length, 'Accept-Ranges': 'bytes' });
    res.end(req.method === 'HEAD' ? undefined : buf);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  return {
    address: `http://localhost:${port}/filme`,
    user,
    password,
    log,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

module.exports = { startWebDav };
