'use strict';

// View logic of the page "Kameras" (src/renderer/camera-state.js, no DOM):
// camera cards and chips, which camera to show, the player's overlay, when
// the live answer is asked for again, the rows of "Clips heute", error texts
// and push targets; where a camera toast leads (notify-state.js); how the
// page is wired (index.html, CSP for gccam:, renderer, main: the scheme and
// the service) and that every cameras.* key exists in the core locales.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const CS = require('../src/renderer/camera-state');
const NS = require('../src/renderer/notify-state');

const ROOT = path.join(__dirname, '..');
const CORE_PKG = '@gatecontrol/client-core';
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const NOW = new Date(2026, 10, 7, 14, 2, 31).getTime();
const CAM1 = 'c0123456789abcde';
const CAM2 = 'cfedcba987654321';
const TOK = `${'a'.repeat(40)}.${'B'.repeat(43)}`;

const camera = (o = {}) => ({
  id: CAM1, kind: 'home', name: 'Einfahrt', gateway: 'DS918 Gateway', model: 'Reolink RLC-510A', source: 'onvif', state: 'ok', online: true,
  codec: 'h264', events: { supported: true, state: 'pullpoint', kinds: ['person', 'vehicle'] },
  settings: { record: 'motion', events: ['person', 'vehicle'], retentionDays: 14, stream: 'main', audio: true },
  push: true, snapshotUrl: `gccam://media/${TOK}/snapshot.jpg`, snapshotAt: NOW - 4000, lastEventAt: NOW - 3600000, ...o,
});

describe('camera cards and chips', () => {
  it('a card: Heimnetz · live, model · motion · clips, picture stamp', () => {
    const v = CS.cardView(camera(), t, NOW, 'de-DE');
    assert.deepEqual(v.pills, [{ label: 'cameras.card.home', cls: 'is-info' }, { label: 'cameras.card.live', cls: 'is-ok' }]);
    assert.equal(v.desc, 'Reolink RLC-510A · cameras.card.motion(cameras.kinds.person, cameras.kinds.vehicle) · cameras.card.retention(14)');
    assert.equal(v.stamp, 'Einfahrt · cameras.ago.s(4)');
    assert.equal(v.picture, `gccam://media/${TOK}/snapshot.jpg`);
    const away = CS.cardView(camera({ settings: { record: 'away', events: [], retentionDays: 7 } }), t, NOW, 'de-DE');
    assert.equal(away.desc, 'Reolink RLC-510A · cameras.card.away · cameras.card.retention(7)');
    const never = CS.cardView(camera({ model: null, settings: { record: 'never', retentionDays: 14 } }), t, NOW, 'de-DE');
    assert.equal(never.desc, 'cameras.card.never');
    const off = CS.cardView(camera({ online: false, snapshotUrl: null, snapshotAt: null }), t, NOW, 'de-DE');
    assert.deepEqual(off.pills.map((p) => p.cls), ['is-info', 'is-err']);
    assert.equal(off.stamp, 'Einfahrt');
    assert.equal(off.offline, true);
    const bad = CS.cardView(camera({ state: 'auth_failed' }), t, NOW, 'de-DE');
    assert.equal(bad.pills.at(-1).label, 'cameras.state.auth_failed');
  });

  it('ago and durations', () => {
    assert.equal(CS.ago(NOW - 1000, NOW, t), 'cameras.ago.now');
    assert.equal(CS.ago(NOW - 120000, NOW, t), 'cameras.ago.min(2)');
    assert.equal(CS.ago(NOW - 3 * 3600000, NOW, t), 'cameras.ago.h(3)');
    assert.equal(CS.ago(null, NOW, t), '');
    assert.equal(CS.duration(24000), '0:24');
    assert.equal(CS.duration(65000), '1:05');
    assert.equal(CS.duration(0), '');
  });

  it('which camera: the one asked for while it is still seen, else the first online one', () => {
    const list = [camera({ id: CAM2, online: false }), camera()];
    assert.equal(CS.pickCamera(list, CAM2), CAM2);
    assert.equal(CS.pickCamera(list, 'c1111111111111111'), CAM1, 'gone (rights) → the first online');
    assert.equal(CS.pickCamera([camera({ online: false })], null), CAM1);
    assert.equal(CS.pickCamera([], CAM1), null);
    assert.equal(CS.onlineCount(list), 1);
  });
});

describe('player', () => {
  const live = { mode: 'live', via: 'vpn', mp4: `gccam://media/${TOK}/live.mp4`, hls: `gccam://media/${TOK}/index.m3u8`, snapshot: `gccam://media/${TOK}/snapshot.jpg`, audio: true, every: 10, expiresAt: NOW + 600000, codec: 'avc1.640028' };
  const still = { mode: 'snapshot', snapshot: `gccam://media/${TOK}/snapshot.jpg`, every: 10, reason: 'vpn_required' };

  it('overlay: ● LIVE · HD über VPN, Standbild alle 10 s, a clip', () => {
    const a = CS.overlay({ live, camera: camera() }, t, 'de-DE', NOW);
    assert.deepEqual(a.badge, { text: '● cameras.live', cls: 'is-live' });
    assert.equal(a.quality, 'cameras.hd · cameras.viaVpn');
    assert.match(a.stamp, /^cameras\.stamp\(Einfahrt,14:02:31\)$/);
    const sd = CS.overlay({ live: { ...live, via: 'lan' }, camera: camera({ settings: { stream: 'sub' } }) }, t, 'de-DE', NOW);
    assert.equal(sd.quality, 'cameras.sd · cameras.viaLan');
    const b = CS.overlay({ live: still, camera: camera(), pictureAt: NOW - 60000 }, t, 'de-DE', NOW);
    assert.deepEqual(b.badge, { text: 'cameras.stillEvery(10)', cls: 'is-still' });
    assert.equal(b.quality, null);
    assert.match(b.stamp, /14:01:31/);
    const c = CS.overlay({ live, camera: camera(), clip: { kind: 'person', startedAt: new Date(2026, 10, 7, 14, 2, 0).getTime() } }, t, 'de-DE', NOW);
    assert.equal(c.badge.cls, 'is-clip');
    assert.match(c.badge.text, /^cameras\.clips\.playing\(cameras\.kind\.person,14:02\)$/);
  });

  it('what plays: the continuous fMP4, HLS only where it can; stills get a counter', () => {
    assert.equal(CS.videoSrc(live, false), live.mp4);
    assert.equal(CS.videoSrc({ ...live, mp4: null }, false), null);
    assert.equal(CS.videoSrc({ ...live, mp4: null }, true), live.hls);
    assert.equal(CS.videoSrc(still, true), null);
    assert.equal(CS.stillSrc(still.snapshot, 3), `${still.snapshot}?t=3`);
    assert.equal(CS.stillSrc(`${still.snapshot}?t=2`, 4), `${still.snapshot}?t=4`);
    assert.equal(CS.codecParam('h265'), 'hvc1.1.6.L93.B0');
    assert.equal(CS.codecParam('avc1.640028'), 'avc1.640028');
    assert.equal(CS.codecParam('"><script>'), null);
    assert.match(CS.codecHint({ codec: 'hvc1.1.6.L120' }, t), /H\.265/);
  });

  it('asks for the live answer again before its tokens run out (10 min)', () => {
    assert.equal(CS.refreshIn(live, NOW), 570000);
    assert.equal(CS.refreshIn({ ...live, expiresAt: NOW + 1000 }, NOW), 20000, 'never below 20 s');
    assert.equal(CS.refreshIn(still, NOW), CS.SNAPSHOT_REFRESH_MS);
    assert.ok(CS.SNAPSHOT_REFRESH_MS < 10 * 60 * 1000);
  });
});

describe('Clips heute, errors, pushes', () => {
  it('a clip row: Person · 0:24, time · Niemand zu Hause, pill; without a clip only the preview', () => {
    const at = new Date(2026, 10, 7, 14, 2, 0).getTime();
    const v = CS.clipView({ id: 'e000000000000002', kind: 'person', kinds: ['motion', 'person', 'vehicle'], startedAt: at, ms: 24000, nobodyHome: true, thumbUrl: 'gccam://media/x/thumb.jpg', clipUrl: 'gccam://media/x/clip.mp4' }, t, 'de-DE');
    assert.equal(v.title, 'cameras.clips.row(cameras.kind.person,0:24)');
    assert.equal(v.sub, '14:02 · cameras.clips.nobodyHome');
    assert.deepEqual(v.pill, { label: 'cameras.kind.person', cls: 'is-warn' });
    assert.deepEqual(v.extra, [{ label: 'cameras.kind.vehicle', cls: 'is-info' }]);
    assert.equal(v.playable, true);
    const w = CS.clipView({ id: 'e000000000000003', kind: 'animal', kinds: ['animal'], startedAt: at, ms: null, nobodyHome: false, thumbUrl: null, clipUrl: null }, t, 'de-DE');
    assert.equal(w.title, 'cameras.kind.animal');
    assert.equal(w.sub, '14:02 · cameras.clips.noClip');
    assert.equal(w.pill.cls, 'is-neu');
    assert.equal(w.playable, false);
  });

  it('error texts', () => {
    assert.equal(CS.errorText({ code: 'cam_offline' }, t), 'cameras.error.cam_offline');
    assert.equal(CS.errorText({ code: 'not_found' }, t), 'cameras.error.not_found');
    assert.equal(CS.errorText({ code: 'http_502' }, t), 'cameras.error.network');
    assert.equal(CS.errorText({ code: 'weird' }, t), 'cameras.error.failed');
    assert.equal(CS.unavailableText({ reason: 'needs_gatecontrol', minGatecontrol: '1.240.0' }, t), 'cameras.unavailable.needs_gatecontrol(1.240.0)');
    assert.equal(CS.unavailableText({ reason: 'no_cameras' }, t), 'cameras.empty');
  });

  it('a camera push opens the page on its camera; Ring and the locks keep the inbox', () => {
    const entry = { id: 702, topic: 'plugin:gatecontrol-door:kamera', data: { route: 'plg-gatecontrol-door', door: { type: 'home_camera_event', cameraId: CAM1, eventId: 'e000000000000002' } } };
    assert.deepEqual(CS.entryContext(entry), { cameraId: CAM1, eventId: 'e000000000000002' });
    assert.equal(CS.entryContext({ ...entry, topic: 'plugin:gatecontrol-door:doorbell' }), null);
    assert.equal(CS.entryContext({ topic: 'plugin:gatecontrol-door:doorbell', data: { door: { type: 'ding', cameraId: 4 } } }), null);
    assert.deepEqual(CS.pushTarget({ cameraId: CAM1 }), { cameraId: CAM1, eventId: null });
    assert.equal(CS.pushTarget({ cameraId: '../x' }), null);

    const pages = ['status', 'inbox', 'kameras'];
    const ctx = { cameraId: CAM1, eventId: 'e000000000000002' };
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-door', id: 702, context: ctx }, pages), { page: 'kameras', id: null, context: ctx });
    // the page is not there: the inbox
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-door', id: 702, context: ctx }, ['status', 'inbox']), { page: 'inbox', id: 702 });
    // Ring "Ansehen" (open_app_route plg-gatecontrol-door without a camera context): as before
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-door', id: 701 }, pages), { page: 'inbox', id: 701 });
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-door', id: 701, context: { lockId: 1 } }, pages), { page: 'inbox', id: 701 });
    // a chat card link "Live-Bild" (Ring) still goes to the portal (no own page for plg-gatecontrol-door)
    assert.equal(NS.routeTarget('plg-gatecontrol-door', pages), null);
  });
});

describe('page wiring', () => {
  const html = read('src', 'renderer', 'index.html');
  const view = read('src', 'renderer', 'camera-view.js');
  const state = read('src', 'renderer', 'camera-state.js');
  const renderer = read('src', 'renderer', 'renderer.js');
  const main = read('src', 'main', 'main.js');

  it('index.html: state before view before renderer, hidden nav entry, page, styles, CSP for gccam: pictures and video', () => {
    const i = (s) => html.indexOf(s);
    assert.ok(i('<script src="camera-state.js">') > 0);
    assert.ok(i('<script src="camera-state.js">') < i('<script src="camera-view.js">'));
    assert.ok(i('<script src="camera-view.js">') < i('<script src="renderer.js">'));
    assert.match(html, /id="nav-kameras"[^>]*data-page="kameras"[^>]*hidden/);
    assert.match(html, /id="page-kameras"/);
    assert.match(html, /href="styles\/cameras\.css"/);
    assert.ok(fs.existsSync(path.join(ROOT, 'src', 'renderer', 'styles', 'cameras.css')));
    const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
    assert.match(csp, /img-src [^;]*gccam:/);
    assert.match(csp, /media-src [^;]*gccam:/);
    assert.doesNotMatch(csp, /script-src[^;]*gccam/);
    assert.doesNotMatch(csp, /default-src[^;]*gccam/);
  });

  it('server text never goes through innerHTML', () => {
    const code = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.doesNotMatch(code(view), /innerHTML|insertAdjacentHTML|outerHTML|document\.write|\beval\(|new Function\(/);
    assert.doesNotMatch(code(state), /innerHTML|document\./);
  });

  it('renderer: page, nav, toast click / inbox → the camera, VPN changes reach the view', () => {
    assert.match(renderer, /'vault', 'kameras', 'inbox'/);
    assert.match(renderer, /camerasView = camerasApi && window\.GCCameraView/);
    assert.match(renderer, /target\.page === 'kameras'\) \{\n\t\t\topenCameras\(target\.context\)/);
    assert.match(renderer, /GCCameraState\.entryContext\(entry\)/);
    assert.match(renderer, /camerasView\?\.networkChanged\(\)/);
    assert.match(renderer, /camerasView\?\.relabel\(\)/);
  });

  it('main: gccam: privileged before ready (one call with gcmail:), served by CamerasService, service to the IPC', () => {
    const reg = main.indexOf('protocol.registerSchemesAsPrivileged(schemes)');
    assert.ok(reg > 0 && reg < main.indexOf("app.on('ready'"));
    assert.ok(main.indexOf('schemes.push({ scheme: CamerasService.SCHEME') > 0 && main.indexOf('schemes.push({ scheme: CamerasService.SCHEME') < reg);
    assert.match(main, /protocol\.handle\(CamerasService\.SCHEME, \(req\) => cameras\.handleProtocol\(req\)\)/);
    assert.match(main, /\n {4}cameras,\n/, 'cameras goes to registerBaseHandlers');
    assert.match(main, /cameras\?\.start\(\)/);
    assert.match(main, /cameras\?\.stop\(\)/);
  });

  it('every cameras.* key of the view exists in the core locales (de and en)', (t2) => {
    let dir = null;
    try { dir = path.dirname(require.resolve(`${CORE_PKG}/package.json`, { paths: [ROOT] })); } catch {
      for (const d of [path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) if (fs.existsSync(path.join(d, 'src', 'i18n', 'locales', 'de.json'))) { dir = d; break; }
    }
    const loc = (l) => (dir ? JSON.parse(fs.readFileSync(path.join(dir, 'src', 'i18n', 'locales', `${l}.json`), 'utf8')) : null);
    const de = loc('de');
    if (!de || !de.cameras) { t2.skip('core without cameras.* (core.ref before Kameras)'); return; }
    const en = loc('en');
    const get = (o, k) => k.split('.').reduce((x, p) => (x && typeof x === 'object' ? x[p] : undefined), o);
    const src = `${view}\n${state}\n${renderer}\n${html}`;
    const keys = new Set([...src.matchAll(/['`"](cameras\.[a-zA-Z_.]+[a-zA-Z])['`"]/g)].map((m) => m[1]));
    for (const k of CS.KINDS) { keys.add(`cameras.kind.${k}`); keys.add(`cameras.kinds.${k}`); }
    for (const s of ['unreachable', 'auth_failed', 'not_allowed', 'no_stream', 'error']) keys.add(`cameras.state.${s}`);
    for (const e of ['not_found', 'cam_offline', 'cam_unreachable', 'cam_not_ready', 'cam_needs_gc', 'cam_auth', 'cam_unsupported', 'cam_service', 'cam_not_allowed', 'no_image', 'rate_limited', 'too_soon', 'network', 'timeout', 'failed']) keys.add(`cameras.error.${e}`);
    assert.ok(keys.size > 50, `found ${keys.size} keys`);
    for (const k of keys) {
      assert.equal(typeof get(de, k), 'string', `${k} missing in core de.json`);
      assert.equal(typeof get(en, k), 'string', `${k} missing in core en.json`);
    }
  });
});
