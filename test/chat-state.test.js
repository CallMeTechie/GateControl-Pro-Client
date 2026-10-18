'use strict';

// View logic of the page "Chats" (src/renderer/chat-state.js, no DOM), how
// the page loads the chat scripts, the CSP for pictures / voice messages,
// and that every chat.* key the view uses exists in the core locales.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const CS = require('../src/renderer/chat-state');

const ROOT = path.join(__dirname, '..');
// Minimal t(): the key with its parameters; the disappearing labels exist (like the real locales).
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : (/^chat\.dis\.(off|86400|604800|2592000)$/.test(key) ? `[${key}]` : key));
const NOW = new Date(2026, 9, 17, 18, 0, 0).getTime();
const at = (h, m, dayOffset = 0) => new Date(2026, 9, 17 + dayOffset, h, m).toISOString();
const ME = { user: { id: 7, name: 'Marc' }, limits: { editWindowS: 900, types: ['image/webp', 'audio/ogg', 'audio/webm', 'application/pdf'], maxBytes: 1000 }, features: { edit: true, reactions: true } };
const ctx = { t, locale: 'de', me: ME, people: [{ id: 9, name: 'Lena' }] };

const member = (userId, name, extra = {}) => ({ userId, name, colorHex: '#2FBF71', initials: name ? name.slice(0, 2).toUpperCase() : null, avatarUrl: null, gone: !name, role: 'member', ...extra });
const direct = (extra = {}) => ({
  id: 12, kind: 'direct', title: 'Anna', peer: member(8, 'Anna'), members: [member(7, 'Marc'), member(8, 'Anna')],
  me: { lastReadId: 100, notify: 'all', mutedUntil: null }, unread: 0, typing: [], can: { send: true }, readUpTo: 101, deliveredUpTo: 103,
  lastMessage: null, createdAt: at(9, 0, -3), updatedAt: at(9, 0, -3), ...extra,
});
const group = (extra = {}) => ({
  id: 13, kind: 'group', title: 'Familie', peer: null, members: [member(7, 'Marc', { role: 'admin' }), member(8, 'Anna'), member(9, 'Lena')],
  me: { lastReadId: 0, notify: 'all' }, unread: 2, typing: [], can: { send: true, editInfo: true }, lastMessage: null, createdAt: at(9, 0, -3), ...extra,
});
const msg = (id, extra = {}) => ({ id, conversationId: 12, senderId: 8, mine: false, kind: 'text', text: `m${id}`, createdAt: at(17, 0), reactions: [], ...extra });

describe('chat-state: names, titles, previews', () => {
  it('names: me as "Du", members, people, deleted accounts, GateControl', () => {
    const c = group();
    assert.equal(CS.nameOf(c, 7, ctx), 'chat.you');
    assert.equal(CS.nameOf(c, 7, ctx, { you: false }), 'Marc');
    assert.equal(CS.nameOf(c, 8, ctx), 'Anna');
    assert.equal(CS.nameOf({ members: [] }, 9, ctx), 'Lena');
    assert.equal(CS.nameOf(c, 99, ctx), 'chat.gone');
    assert.equal(CS.nameOf(c, null, ctx), 'GateControl');
    assert.equal(CS.title({ kind: 'direct', title: null }, t), 'chat.gone');
    assert.equal(CS.title({ kind: 'group', title: null }, t), 'chat.group');
  });

  it('list preview: typing first, own messages, group sender, media summaries', () => {
    assert.deepEqual(CS.preview(direct({ typing: [8] }), ctx), { text: 'chat.typing', typing: true });
    assert.deepEqual(CS.preview(group({ typing: [8] }), ctx), { text: 'chat.typingOne(Anna)', typing: true });
    assert.deepEqual(CS.preview(group({ typing: [8, 9] }), ctx), { text: 'chat.typingMany(2)', typing: true });
    assert.equal(CS.preview(direct({ lastMessage: msg(1, { mine: true, senderId: 7, text: 'Hi' }) }), ctx).text, 'chat.you: Hi');
    assert.equal(CS.preview(group({ lastMessage: msg(1, { text: 'Hallo' }) }), ctx).text, 'Anna: Hallo');
    assert.equal(CS.preview(direct({ lastMessage: msg(1, { kind: 'voice', text: null, meta: { durationMs: 14200 } }) }), ctx).text, 'chat.kind.voice · 0:14');
    assert.equal(CS.preview(direct({ lastMessage: msg(1, { kind: 'file', text: null, meta: { fileName: 'Brief.pdf' } }) }), ctx).text, 'Brief.pdf');
    assert.equal(CS.preview(direct({ lastMessage: msg(1, { kind: 'image', text: 'Urlaub' }) }), ctx).text, 'chat.kind.image: Urlaub');
    assert.equal(CS.preview(direct({ lastMessage: msg(1, { deleted: true }) }), ctx).text, 'chat.msg.deleted');
    assert.equal(CS.preview(direct(), ctx).text, 'chat.chatNew');
    assert.equal(CS.preview(group(), ctx).text, 'chat.groupNew');
  });

  it('system messages', () => {
    const c = group();
    const sys = (system) => ({ kind: 'system', system });
    assert.equal(CS.systemText(sys({ event: 'created', by: 7, title: 'Familie' }), c, ctx), 'chat.sys.created(chat.you,Familie)');
    assert.equal(CS.systemText(sys({ event: 'member_added', by: 8, userIds: [9, 7] }), c, ctx), 'chat.sys.added(Anna,Lena, chat.you)');
    assert.equal(CS.systemText(sys({ event: 'member_left', userId: 9 }), c, ctx), 'chat.sys.left(Lena)');
    assert.equal(CS.systemText(sys({ event: 'title', by: null, title: 'Neu' }), c, ctx), 'chat.sys.title(GateControl,Neu)');
    assert.equal(CS.systemText(sys({ event: 'disappearing', by: 8, seconds: 86400 }), c, ctx), 'chat.sys.disOn(Anna,[chat.dis.86400])');
    assert.equal(CS.systemText(sys({ event: 'disappearing', by: 8, seconds: 0 }), c, ctx), 'chat.sys.disOff(Anna)');
    assert.equal(CS.systemText({ kind: 'system', system: { event: 'notice' }, text: 'Tim ist zu Hause' }, c, ctx), 'Tim ist zu Hause');
    // Messenger 1.1.0: the managed group was handed over
    assert.equal(CS.systemText(sys({ event: 'released', by: null }), c, ctx), 'chat.sys.released');
  });

  it('header sub line and closed composer', () => {
    assert.equal(CS.headSub(group(), ctx).text, 'chat.you, Anna, Lena');
    assert.equal(CS.headSub(direct(), ctx).text, 'chat.directSub');
    assert.equal(CS.headSub(direct({ peer: member(8, null) }), ctx).text, 'chat.peerGone');
    assert.equal(CS.headSub(group({ readonly: true }), ctx).text, 'chat.channelSub');
    assert.equal(CS.composerBlock(direct()), null);
    assert.equal(CS.composerBlock(group({ readonly: true })), 'readonly');
    assert.equal(CS.composerBlock(direct({ peer: member(8, null) })), 'peerGone');
    assert.equal(CS.composerBlock(direct({ can: { send: false } })), 'readonly');
  });

  it('filters the list by title, preview and member names', () => {
    const list = [direct({ lastMessage: msg(1, { text: 'Milch kaufen' }) }), group()];
    assert.deepEqual(CS.filterConversations(list, 'fam', ctx).map((c) => c.id), [13]);
    assert.deepEqual(CS.filterConversations(list, 'MILCH', ctx).map((c) => c.id), [12]);
    assert.deepEqual(CS.filterConversations(list, 'lena', ctx).map((c) => c.id), [13]);
    assert.equal(CS.filterConversations(list, '  ', ctx).length, 2);
  });

  it('avatars: person, group, deleted account', () => {
    assert.deepEqual(CS.avatarOf(direct()), { kind: 'person', name: 'Anna', initials: 'AN', color: '#2FBF71', avatarUrl: null });
    assert.deepEqual(CS.avatarOf(group({ avatarMediaId: 'abc' })), { kind: 'icon', icon: 'group', mediaId: 'abc' });
    assert.equal(CS.avatarOf(direct({ peer: member(8, null) })).icon, 'gone');
    assert.equal(CS.personAvatar({ name: 'X', colorHex: 'red' }).color, '#64748B', 'only #rrggbb colours');
    assert.equal(CS.initials('Anna Maria Schmidt'), 'AS');
  });
});

describe('chat-state: times, ticks, timeline', () => {
  it('list and day labels', () => {
    assert.equal(CS.listTime(at(17, 44), ctx, NOW), '17:44');
    assert.equal(CS.listTime(at(17, 44, -1), ctx, NOW), 'chat.rel.yesterday');
    assert.match(CS.listTime(at(17, 44, -3), ctx, NOW), /^\S+$/);
    assert.equal(CS.listTime(at(17, 44, -30), ctx, NOW), '17.09.');
    assert.equal(CS.dayLabel(at(8, 0), ctx, NOW), 'chat.rel.today');
    assert.equal(CS.dayLabel(at(8, 0, -1), ctx, NOW), 'chat.rel.yesterday');
    assert.match(CS.dayLabel(at(8, 0, -4), ctx, NOW), /Oktober/);
    assert.equal(CS.duration(61000), '1:01');
    assert.equal(CS.bytes(248 * 1024, 'de'), '248 KB');
  });

  it('ticks from the receipts', () => {
    const c = direct();
    assert.equal(CS.status(msg(101, { mine: true }), c), 'read');
    assert.equal(CS.status(msg(102, { mine: true }), c), 'delivered');
    assert.equal(CS.status(msg(104, { mine: true }), c), 'sent');
    assert.equal(CS.status(msg(104), c), null);
    assert.equal(CS.status({ pending: true }, c), 'pending');
    assert.equal(CS.status({ pending: true, failed: true }, c), 'failed');
  });

  it('message actions: edit / delete for everyone only within the window', () => {
    const c = direct();
    const fresh = msg(5, { mine: true, senderId: 7, createdAt: new Date(NOW - 60000).toISOString() });
    const old = msg(6, { mine: true, senderId: 7, createdAt: new Date(NOW - 3600000).toISOString() });
    assert.deepEqual(CS.messageActions(fresh, c, ctx, NOW), { reply: true, react: true, copy: true, edit: true, deleteMe: true, deleteAll: true });
    assert.deepEqual(CS.messageActions(old, c, ctx, NOW), { reply: true, react: true, copy: true, edit: false, deleteMe: true, deleteAll: false });
    assert.equal(CS.messageActions(msg(7, { kind: 'voice', mine: true, createdAt: new Date(NOW).toISOString() }), c, ctx, NOW).edit, false);
    assert.equal(CS.messageActions(msg(8, { deleted: true }), c, ctx, NOW).reply, false);
    assert.equal(CS.messageActions(msg(9), group({ readonly: true, can: { send: false } }), ctx, NOW).reply, false);
    assert.equal(CS.messageActions({ pending: true }, c, ctx, NOW).deleteMe, false);
  });

  it('timeline: day separators, unread line, grouping, pending at the end', () => {
    const list = [
      msg(1, { createdAt: at(10, 0, -1) }),
      msg(2, { createdAt: at(10, 1, -1) }),
      msg(3, { createdAt: at(9, 0), senderId: 7, mine: true }),
      msg(4, { createdAt: at(9, 1) }),
      msg(5, { createdAt: at(9, 2) }),
    ];
    const pending = [{ pending: true, clientId: 'c1', mine: true, senderId: 7, kind: 'text', createdAt: at(9, 3) }];
    const items = CS.timeline(list, pending, direct(), ctx, { unreadFrom: 3, now: NOW });
    assert.deepEqual(items.map((i) => (i.type === 'msg' ? `${i.m.id || i.m.clientId}${i.cont ? '+' : ''}` : i.type)), ['day', '1', '2+', 'day', '3', 'unread', '4', '5+', 'c1']);
    assert.equal(items.at(-1).status, 'pending');
  });

  it('mute and disappearing options', () => {
    assert.equal(CS.muteValue(direct()), 'off');
    assert.equal(CS.muteValue(direct({ me: { notify: 'none' } })), 'always');
    assert.equal(CS.muteValue(direct({ me: { notify: 'all', mutedUntil: new Date(NOW + 3600000).toISOString() } }), NOW), 'until');
    assert.deepEqual(CS.mutePatch('off'), { notify: 'all', mutedUntil: null });
    assert.deepEqual(CS.mutePatch('always'), { notify: 'none', mutedUntil: null });
    assert.equal(CS.mutePatch('8h', NOW).mutedUntil, new Date(NOW + 8 * 3600000).toISOString());
    assert.equal(CS.mutePatch('until'), null);
    assert.equal(CS.disLabel(0, t), '[chat.dis.off]');
    assert.equal(CS.disLabel(604800, t), '[chat.dis.604800]');
    assert.equal(CS.disLabel(3600, t), 'chat.dis.seconds(3600)');
  });
});

describe('chat-state: files, recording, errors', () => {
  it('what can be attached', () => {
    assert.deepEqual(CS.attachKind({ type: 'image/png', size: 5e6 }, ME.limits), { kind: 'image' });
    assert.deepEqual(CS.attachKind({ type: 'application/pdf', size: 10 }, ME.limits), { kind: 'file' });
    assert.deepEqual(CS.attachKind({ type: 'application/pdf', size: 5000 }, ME.limits), { kind: null, reason: 'too_large' });
    assert.deepEqual(CS.attachKind({ type: 'application/x-msdownload', size: 10 }, ME.limits), { kind: null, reason: 'unsupported_type' });
    assert.deepEqual(CS.attachKind({ type: '', size: 10 }, ME.limits), { kind: null, reason: 'unsupported_type' });
  });

  it('scaling, bubble sizes, badges, map links', () => {
    assert.deepEqual(CS.scaledSize(4000, 3000, 2048), { w: 2048, h: 1536 });
    assert.deepEqual(CS.scaledSize(100, 50, 2048), { w: 100, h: 50 });
    assert.deepEqual(CS.bubbleSize({ w: 2048, h: 1024 }), { w: 320, h: 160 });
    assert.deepEqual(CS.bubbleSize(null), { w: 240, h: 180 });
    assert.equal(CS.fileBadge('Elternbrief.pdf', 'application/pdf'), 'PDF');
    assert.equal(CS.fileBadge('ohne', 'application/zip'), 'ZIP');
    assert.equal(CS.mapUrl({ lat: 48.1, lon: 11.5 }), 'https://www.openstreetmap.org/?mlat=48.100000&mlon=11.500000#map=17/48.100000/11.500000');
    assert.equal(CS.mapUrl({ lat: 'x' }), null);
  });

  it('voice recording: accepted type and waveform', () => {
    assert.equal(CS.recordingMime((m) => m.startsWith('audio/webm'), ME.limits.types), 'audio/webm;codecs=opus');
    assert.equal(CS.recordingMime((m) => m === 'audio/mp4', ME.limits.types), null, 'mp4 is not allowed by the server here');
    assert.equal(CS.recordingMime(() => { throw new Error('old'); }, []), null);
    assert.deepEqual(CS.waveform([0, 10, 300, 20, 5, 7], 3), [10, 255, 7]);
    assert.deepEqual(CS.waveform([], 3), []);
  });

  it('error and unavailable texts fall back sensibly', () => {
    const tt = (k) => ({ 'chat.error.readonly': 'Lesen nur', 'chat.error.failed': 'Fehler', 'chat.unavailable.unsupported': 'Zu alt', 'chat.unavailable.not_installed': 'Fehlt' }[k] || k);
    assert.equal(CS.errorText({ code: 'readonly' }, tt), 'Lesen nur');
    assert.equal(CS.errorText({ code: 'weird' }, tt), 'Fehler');
    assert.equal(CS.errorText('readonly', tt), 'Lesen nur');
    assert.equal(CS.errorText(null, tt), 'Fehler');
    assert.equal(CS.unavailableText({ reason: 'unsupported' }, tt), 'Zu alt');
    assert.equal(CS.unavailableText({ reason: 'x' }, tt), 'Fehlt');
  });

  it('pinned GateControl row from the inbox', () => {
    assert.deepEqual(CS.inboxRow({ items: [{ title: 'Klingel: Haustür', created_at: at(17, 52) }], unread: 1 }, ctx, NOW), { title: 'chat.inbox.title', text: 'Klingel: Haustür', time: '17:52', unread: 1 });
    assert.equal(CS.inboxRow(null, ctx, NOW).text, 'chat.inbox.empty');
  });
});

describe('chat-state: map and location', () => {
  it('Web Mercator: world pixels and back', () => {
    assert.deepEqual(CS.worldPx(0, 0, 0), { x: 128, y: 128 });
    const p = CS.worldPx(48.137154, 11.576124, 15);
    const back = CS.lonLat(p.x, p.y, 15);
    assert.ok(Math.abs(back.lat - 48.137154) < 1e-9 && Math.abs(back.lon - 11.576124) < 1e-9);
    assert.ok(Math.abs(CS.worldPx(90, 0, 0).y) < 1e-6, 'clamped to the map');
    assert.ok(Math.abs(CS.lonLat(256 * 4 + 128, 128, 0).lon) < 1e-9, 'longitude wraps');
    assert.equal(CS.clampZoom(25), 19);
    assert.equal(CS.clampZoom(-3), 2);
    assert.equal(CS.clampZoom('x'), 2);
  });

  it('tile grid covers the view, wraps x, leaves out rows outside the map', () => {
    const g = CS.tileGrid(128, 128, 0, 256, 256);
    assert.deepEqual(g, [{ key: '0/0/0', z: 0, x: 0, y: 0, left: 0, top: 0 }]);
    const wide = CS.tileGrid(512, 512, 2, 600, 300);
    assert.equal(new Set(wide.map((x) => x.key)).size, wide.length);
    for (const tl of wide) {
      assert.ok(tl.left > -256 && tl.left < 600 && tl.top > -256 && tl.top < 300);
      assert.ok(tl.x >= 0 && tl.x < 4 && tl.y >= 0 && tl.y < 4);
    }
    const edge = CS.tileGrid(10, 10, 1, 256, 256);
    assert.ok(edge.some((tl) => tl.x === 1 && tl.left < 0), 'left of the date line: the last column');
    assert.ok(edge.every((tl) => tl.y >= 0));
  });

  it('accuracy: metres per pixel, zoom for a radius', () => {
    assert.ok(Math.abs(CS.metersPerPx(0, 0) - 156543.03392) < 1e-6);
    assert.ok(CS.metersPerPx(60, 10) < CS.metersPerPx(0, 10));
    assert.equal(CS.zoomForAccuracy(12), 17);
    assert.equal(CS.zoomForAccuracy(400), 15);
    assert.equal(CS.zoomForAccuracy(20000), 11);
    assert.equal(CS.zoomForAccuracy(null), 16);
  });

  it('location body: rounded, label trimmed, accuracy only when given', () => {
    assert.deepEqual(CS.locationBody({ lat: 48.1371549, lon: 11.5761249 }, '  Treff  punkt ', 23.4), { lat: 48.137155, lon: 11.576125, label: 'Treff punkt', accuracy: 23 });
    assert.deepEqual(CS.locationBody({ lat: 1, lon: 2 }, '', null), { lat: 1, lon: 2 });
    assert.equal(CS.locationBody(null, 'x'), null);
    assert.equal(CS.locationBody({ lat: 91, lon: 0 }), null);
    assert.equal(CS.locationBody({ lat: 1, lon: 2 }, 'x'.repeat(300)).label.length, 200);
    assert.equal(CS.coordText({ lat: 48.1371549, lon: 11.5 }), '48.13715, 11.50000');
    assert.equal(CS.coordText(null), '');
  });

  it('geolocation errors → denied / unavailable / timeout', () => {
    assert.equal(CS.geoError({ code: 1 }), 'denied');
    assert.equal(CS.geoError({ code: 2 }), 'unavailable');
    assert.equal(CS.geoError({ code: 3 }), 'timeout');
    assert.equal(CS.geoError(null), 'unavailable');
  });
});

describe('chat-state: pinned inbox', () => {
  const inbox = { unread: 2, items: [{ id: 5, state: 'delivered' }, { id: 4, state: 'delivered' }, { id: 3, state: 'read' }] };

  it('oldest first; the first unread entry is where the chat opens', () => {
    assert.deepEqual(CS.inboxTimeline(inbox).map((e) => e.id), [3, 4, 5]);
    assert.equal(CS.inboxFirstUnread(inbox), 4);
    assert.equal(CS.inboxFirstUnread({ items: [{ id: 1, state: 'read' }] }), null);
    assert.equal(CS.inboxFirstUnread(null), null);
  });

  it('seen: most of the entry in view, or a tall entry filling half the list', () => {
    assert.equal(CS.inboxSeen(0.6, 40, 500), true);
    assert.equal(CS.inboxSeen(0.3, 40, 500), false);
    assert.equal(CS.inboxSeen(0.3, 260, 500), true);
    assert.equal(CS.inboxSeen(0, 0, 0), false);
  });
});

describe('Chats page', () => {
  const html = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'index.html'), 'utf8');
  const view = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'chat-view.js'), 'utf8');

  it('loads chat-state.js and chat-view.js before renderer.js, and the stylesheet', () => {
    const a = html.indexOf('<script src="chat-state.js">');
    const b = html.indexOf('<script src="chat-view.js">');
    const c = html.indexOf('<script src="renderer.js">');
    assert.ok(a > 0 && a < b && b < c);
    assert.ok(html.includes('href="styles/chat.css"'));
    assert.ok(html.includes('id="page-chats"'));
    assert.match(html, /id="nav-chats"[^>]*hidden/);
  });

  it('CSP allows blob: pictures and voice messages, nothing from the network', () => {
    const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
    assert.match(csp, /img-src 'self' data: blob:/);
    assert.match(csp, /media-src 'self' blob: mediastream:/);
    assert.match(csp, /default-src 'self'/);
    assert.doesNotMatch(csp, /https?:/);
  });

  it('never writes user data as HTML', () => {
    assert.doesNotMatch(view, /\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write\(/);
  });

  it('every chat.* key of the view exists in the core locales (de + en)', (tctx) => {
    let dir = null;
    for (const d of [path.join(ROOT, 'node_modules', '@gatecontrol', 'client-core'), path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) {
      if (fs.existsSync(path.join(d, 'src', 'i18n', 'locales', 'de.json'))) { dir = d; break; }
    }
    if (!dir) { tctx.skip('core not available'); return; }
    const flat = (obj, p = '', out = {}) => { for (const [k, v] of Object.entries(obj)) { const key = p ? `${p}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(fs.readFileSync(path.join(dir, 'src', 'i18n', 'locales', 'de.json'), 'utf8')));
    const en = flat(JSON.parse(fs.readFileSync(path.join(dir, 'src', 'i18n', 'locales', 'en.json'), 'utf8')));
    const state = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'chat-state.js'), 'utf8');
    const renderer = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'renderer.js'), 'utf8');
    const main = fs.readFileSync(path.join(ROOT, 'src', 'main', 'messenger.js'), 'utf8');
    const keys = new Set();
    for (const src of [view, state, renderer, main, html]) for (const m of src.matchAll(/['"`](chat\.[A-Za-z0-9_.]+[A-Za-z0-9_])['"`]/g)) keys.add(m[1]);
    // built at runtime
    for (const k of ['text', 'image', 'voice', 'file', 'location', 'system']) keys.add(`chat.kind.${k}`);
    for (const k of ['pending', 'failed', 'sent', 'delivered', 'read']) keys.add(`chat.status.${k}`);
    for (const k of ['direct', 'group']) keys.add(`chat.new.${k}`);
    for (const k of ['not_installed', 'unsupported', 'hidden', 'forbidden']) keys.add(`chat.unavailable.${k}`);
    for (const k of ['off', '86400', '604800', '2592000']) keys.add(`chat.dis.${k}`);
    for (const k of ['denied', 'unavailable', 'timeout']) keys.add(`chat.loc.${k}`);
    keys.delete('chat.dis.');
    assert.ok(keys.size > 100, `only ${keys.size} keys found`);
    for (const key of keys) {
      assert.ok(key in de, `de: ${key}`);
      assert.ok(key in en, `en: ${key}`);
    }
  });
});

describe('chat-state: videos and file previews (Messenger 1.3.0)', () => {
  const file = (extra = {}) => msg(300, { kind: 'file', text: null, meta: { fileName: 'clip.mp4' }, media: { id: 'a'.repeat(32), mime: 'video/mp4', bytes: 2048, thumbId: 'b'.repeat(32) }, ...extra });

  it('a video is a file with `video` or a video/* type', () => {
    assert.deepEqual(CS.videoInfo(file({ video: { durationMs: 14200, width: 1280, height: 720 } })), { durationMs: 14200, width: 1280, height: 720 });
    assert.deepEqual(CS.videoInfo(file()), { durationMs: null, width: null, height: null });
    assert.equal(CS.videoInfo(file({ media: { id: 'a'.repeat(32), mime: 'application/pdf' } })), null);
    assert.equal(CS.videoInfo(file({ deleted: true })), null);
    assert.equal(CS.videoInfo(msg(1, { kind: 'image', media: { mime: 'image/webp' } })), null);
    // a pending video (outbox): `video` from the send body, the local type
    assert.deepEqual(CS.videoInfo({ pending: true, kind: 'file', video: { durationMs: 1000 }, media: { id: null, mime: 'video/webm', local: true } }), { durationMs: 1000, width: null, height: null });
  });

  it('summary: "Video · 0:14" instead of the file name', () => {
    assert.equal(CS.summary(file({ video: { durationMs: 14200 } }), direct(), ctx), 'chat.kind.video · 0:14');
    assert.equal(CS.summary(file({ text: 'Urlaub' }), direct(), ctx), 'chat.kind.video: Urlaub');
    assert.equal(CS.summary(file({ media: { mime: 'application/pdf' }, meta: { fileName: 'a.pdf' } }), direct(), ctx), 'a.pdf');
  });

  it('frame time, preview steps, features, filters, attach kind', () => {
    assert.equal(CS.videoFrameTime(30), 1);
    assert.equal(CS.videoFrameTime(1.2), 0.6);
    assert.equal(CS.videoFrameTime(Infinity), 0);
    assert.equal(CS.videoFrameTime(NaN), 0);
    assert.ok(CS.THUMB_STEPS.every(([side, q]) => side <= 640 && q > 0 && q < 1));
    assert.deepEqual(CS.thumbSteps(640), CS.THUMB_STEPS);
    assert.deepEqual(CS.thumbSteps(undefined), CS.THUMB_STEPS);
    assert.ok(CS.thumbSteps(320).every(([side]) => side <= 320));
    assert.equal(new Set(CS.thumbSteps(200).map((x) => x.join())).size, CS.thumbSteps(200).length);
    assert.equal(CS.hasFeature({ features: ['video_meta'] }, 'video_meta'), true);
    assert.equal(CS.hasFeature({ features: { file_thumbs: true } }, 'file_thumbs'), true);
    assert.equal(CS.hasFeature(ME, 'video_meta'), false);
    assert.deepEqual(CS.mediaFilters(ME, null), ['image', 'file']);
    assert.deepEqual(CS.mediaFilters({ features: ['video_meta'] }, null), ['image', 'video', 'file']);
    assert.deepEqual(CS.mediaFilters(ME, { image: 1, voice: 0, file: 2, video: 0 }), ['image', 'video', 'file']);
    assert.equal(CS.mediaTotal({ image: 1, voice: 2, file: 3, video: 4 }), 10);
    assert.equal(CS.mediaTotal(null), 0);
    const lim = { types: ['video/mp4', 'application/pdf'], maxBytes: 1000 };
    assert.deepEqual(CS.attachKind({ type: 'video/mp4', size: 10 }, lim), { kind: 'video' });
    assert.deepEqual(CS.attachKind({ type: 'video/webm', size: 10 }, lim), { kind: null, reason: 'unsupported_type' });
    assert.deepEqual(CS.attachKind({ type: 'video/mp4', size: 5000 }, lim), { kind: null, reason: 'too_large' });
  });
});

describe('chat-state: update hint', () => {
  it('only while available and with unknown features', () => {
    const h = { features: ['polls'], key: 'polls' };
    assert.deepEqual(CS.updateHint({ state: 'available', updateHint: h }), h);
    assert.equal(CS.updateHint({ state: 'available', updateHint: null }), null);
    assert.equal(CS.updateHint({ state: 'unavailable', updateHint: h }), null);
    assert.equal(CS.updateHint({ state: 'available', updateHint: { features: [] } }), null);
    assert.equal(CS.updateHint(null), null);
  });
});
