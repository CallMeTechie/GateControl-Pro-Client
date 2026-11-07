'use strict';

/**
 * The home cameras of the plugin gatecontrol-door 1.6.0 ("Tür & Kamera") for
 * the e2e mock server (contract: the plugin's README "Kameras im Heimnetz",
 * the gateway's docs/cameras.md §7/§8):
 *
 *   GET plugins/gatecontrol-door/api/cameras/home               → { supported, minGatecontrol, every, cameras }
 *   GET plugins/gatecontrol-door/api/cameras/home/<id>/live     → live (mode 'live') or a still every 10 s (mode 'snapshot')
 *   GET plugins/gatecontrol-door/api/cameras/home/<id>/still    → { still: { data, mime, at } }
 *   GET plugins/gatecontrol-door/api/cameras/home/<id>/clips    → { day, clips }
 *   GET /camera-media/<token>/<file>                            → the media (no login; Range for clip.mp4)
 *   GET /notify-media/<file>.jpg                                → the picture of a push
 *
 * Cameras the person does not see answer 404 not_found like the plugin.
 *
 *   const door = mock.setDoor({
 *     cameras: [{ id: 'c0123456789abcde', name: 'Einfahrt', … }],
 *     mode: 'snapshot' | 'live',       // what GET …/live answers (no VPN / VPN)
 *     clips: { '<cameraId>': [ … ] },  // startedAt etc. as ISO
 *     supported: true,                 // false: GateControl before 1.240.0
 *   });
 *   door.log → [{ route, query }], door.media → ['<file>', …]
 */

const fs = require('fs');
const path = require('path');

const BASE = 'plugins/gatecontrol-door/api/';
const FIXTURES = path.join(__dirname, '..', 'fixtures');
const STILL = fs.readFileSync(path.join(FIXTURES, 'camera-still.jpg'));
const VIDEO = fs.readFileSync(path.join(FIXTURES, 'camera-live.mp4'));
const MEDIA_RE = /^\/camera-media\/([A-Za-z0-9_-]{16,400}\.[A-Za-z0-9_-]{43})\/(snapshot\.jpg|live\.mp4|clip\.mp4|thumb\.jpg|index\.m3u8)$/;

/** A token of the media addresses (the server's are HMAC-signed; here a name per camera / event and kind). */
const token = (subject, kind) => `${`${kind}-${subject}`.padEnd(24, 'x')}.${'S'.repeat(43)}`;
const media = (subject, kind, file) => `/camera-media/${token(subject, kind)}/${file}`;

function createDoor({ version = '1.6.0', supported = true, cameras = [], mode = 'snapshot', clips = {}, audio = true } = {}) {
  const state = { version, supported, cameras, mode, clips, audio, log: [], media: [], tokens: new Map() };
  const remember = (subject, kind) => { state.tokens.set(token(subject, kind), { subject, kind }); return subject; };

  state.entry = () => ({ id: 'gatecontrol-door', name: 'Tür & Kamera', version: state.version, tab: null });

  const view = (c) => {
    remember(c.id, 'snap');
    return {
      kind: 'home', gateway: 'DS918 Gateway', model: null, source: 'onvif', state: 'ok', online: true, codec: 'h264',
      events: { supported: true, state: 'pullpoint', kinds: ['person', 'vehicle', 'animal'] },
      settings: { record: 'motion', events: ['person', 'vehicle'], retentionDays: 14, stream: 'main', audio: state.audio },
      push: true, snapshotUrl: media(c.id, 'snap', 'snapshot.jpg'), snapshotAt: new Date(Date.now() - 4000).toISOString(), lastEventAt: null, ...c,
    };
  };

  /** → true when the request was ours (answered). */
  state.handle = ({ method, route, query }, json) => {
    if (!route.startsWith(BASE)) return false;
    const p = route.slice(BASE.length);
    state.log.push({ route: p, query });
    if (method !== 'GET') return json(404, { ok: false, code: 'not_found' }), true;
    if (p === 'cameras/home') {
      if (!state.supported) return json(200, { ok: true, supported: false, minGatecontrol: '1.240.0', cameras: [] }), true;
      return json(200, { ok: true, supported: true, minGatecontrol: '1.240.0', every: 10, cameras: state.cameras.map(view) }), true;
    }
    const m = /^cameras\/home\/(c[0-9a-f]{15})\/(live|still|clips)$/.exec(p);
    const cam = m && state.cameras.find((c) => c.id === m[1]);
    if (!cam) return json(404, { ok: false, code: 'not_found', error: 'Nicht gefunden' }), true;
    if (m[2] === 'live') {
      const snap = media(remember(cam.id, 'snap'), 'snap', 'snapshot.jpg');
      if (state.mode !== 'live') return json(200, { ok: true, live: { mode: 'snapshot', snapshot: snap, every: 10, reason: 'vpn_required', via: 'internet' } }), true;
      remember(cam.id, 'live');
      return json(200, {
        ok: true,
        live: {
          mode: 'live', via: 'vpn', ready: true, hls: media(cam.id, 'live', 'index.m3u8'), mp4: media(cam.id, 'live', 'live.mp4'), snapshot: media(cam.id, 'live', 'snapshot.jpg'),
          codec: 'avc1.42C00D, mp4a.40.2', audio: state.audio, every: 10, expiresAt: new Date(Date.now() + 600000).toISOString(),
        },
      }), true;
    }
    if (m[2] === 'still') return json(200, { ok: true, still: { data: STILL.toString('base64'), mime: 'image/jpeg', at: new Date().toISOString() } }), true;
    const list = (state.clips[cam.id] || []).map((e) => {
      remember(e.id, 'clip');
      return {
        cameraId: cam.id, camera: cam.name, kinds: [e.kind], endedAt: null, nobodyHome: null, ms: 4000,
        thumbUrl: media(e.id, 'clip', 'thumb.jpg'), clipUrl: e.noClip ? null : media(e.id, 'clip', 'clip.mp4'), ...e,
      };
    });
    return json(200, { ok: true, day: new Date().toISOString().slice(0, 10), clips: list }), true;
  };

  /** /camera-media/… and /notify-media/… → true when answered. */
  state.serveMedia = (req, url, res) => {
    if (/^\/notify-media\/[A-Za-z0-9_-]{8,128}\.jpg$/.test(url.pathname)) {
      state.media.push('notify.jpg');
      res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Content-Length': STILL.length });
      res.end(STILL);
      return true;
    }
    const m = MEDIA_RE.exec(url.pathname);
    if (!m) return false;
    const tok = state.tokens.get(m[1]);
    const file = m[2];
    if (!tok || (file === 'clip.mp4' || file === 'thumb.jpg') !== (tok.kind === 'clip')) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found');
      return true;
    }
    state.media.push(file);
    if (file === 'snapshot.jpg' || file === 'thumb.jpg') {
      res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Content-Length': STILL.length, 'Cache-Control': 'no-store' });
      res.end(STILL);
      return true;
    }
    if (file === 'live.mp4') {
      // a continuous fragmented MP4 (here: the 4 s fixture, then the answer ends like a token running out)
      res.writeHead(200, { 'Content-Type': 'video/mp4', 'Cache-Control': 'no-store' });
      res.end(VIDEO);
      return true;
    }
    if (file === 'clip.mp4') {
      const r = /^bytes=(\d+)-(\d*)$/.exec(req.headers.range || '');
      if (r) {
        const start = Number(r[1]);
        const end = r[2] ? Math.min(Number(r[2]), VIDEO.length - 1) : VIDEO.length - 1;
        res.writeHead(206, { 'Content-Type': 'video/mp4', 'Content-Range': `bytes ${start}-${end}/${VIDEO.length}`, 'Content-Length': end - start + 1, 'Accept-Ranges': 'bytes' });
        res.end(VIDEO.subarray(start, end + 1));
      } else {
        res.writeHead(200, { 'Content-Type': 'video/mp4', 'Content-Length': VIDEO.length, 'Accept-Ranges': 'bytes' });
        res.end(VIDEO);
      }
      return true;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('not found');
    return true;
  };

  return state;
}

module.exports = { createDoor };
