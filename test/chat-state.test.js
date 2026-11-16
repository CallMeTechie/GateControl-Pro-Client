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

  // second real test over WhatsApp: the chat „Schatzimausi 💕“ showed „S“ and a replacement mark (half the heart)
  it('initials: whole characters, letters and digits only — never half an emoji, never an emoji', () => {
    const LONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
    assert.equal(CS.initials('Schatzimausi 💕'), 'S');
    assert.equal(CS.initials('💕'), '?', 'only emoji: the single fallback character');
    assert.equal(CS.initials('💕 ❤️ 👨‍👩‍👧'), '?');
    assert.equal(CS.initials('Ä Ö'), 'ÄÖ');
    assert.equal(CS.initials('A\u0308rger'), 'ÄR', 'a letter with a combining mark stays whole');
    assert.equal(CS.initials('van der Berg'), 'VB');
    assert.equal(CS.initials('Kim'), 'KI');
    assert.equal(CS.initials('💕Mama'), 'MA');
    assert.equal(CS.initials('1️⃣'), '1');
    assert.equal(CS.initials(''), '?');
    assert.equal(CS.initials('\u{1D49C}lice \u{1D505}ob'), '\u{1D49C}\u{1D505}');
    for (const s of ['Schatzimausi 💕', '💕 x', 'a 💕', 'A😀']) assert.doesNotMatch(CS.initials(s), LONE, `no half character of ${s}`);
    // a bridged chat without a picture: its avatar
    assert.equal(CS.personAvatar({ name: 'Schatzimausi 💕' }).initials, 'S');
    assert.equal(CS.personAvatar({ name: 'Mama', initials: 'M💕' }).initials, 'M', 'the server’s initials: letters only');
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
    assert.deepEqual(CS.messageActions(fresh, c, ctx, NOW), { reply: true, react: true, copy: true, edit: true, deleteMe: true, deleteAll: true, pin: false, pinned: false, remind: false, suggest: false });
    assert.deepEqual(CS.messageActions(old, c, ctx, NOW), { reply: true, react: true, copy: true, edit: false, deleteMe: true, deleteAll: false, pin: false, pinned: false, remind: false, suggest: false });
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
    assert.equal(CS.disLabel(3600, t), 'chat.dis.hours(1)');
    // Messenger 1.23: a timer of Signal holds any number of seconds — the largest whole unit
    assert.equal(CS.disLabel(30, t), 'chat.dis.seconds(30)');
    assert.equal(CS.disLabel(300, t), 'chat.dis.minutes(5)');
    assert.equal(CS.disLabel(28800, t), 'chat.dis.hours(8)');
    assert.equal(CS.disLabel(1209600, t), 'chat.dis.weeks(2)');
    assert.equal(CS.disLabel(90, t), 'chat.dis.seconds(90)');
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
  // Messenger 1.4.0 modules of the view
  const modules = ['chat-rich.js', 'chat-status.js', 'chat-linked.js', 'chat-settings.js'].map((f) => fs.readFileSync(path.join(ROOT, 'src', 'renderer', f), 'utf8'));

  it('loads chat-state.js, the 1.4.0 modules and chat-view.js before renderer.js, and the stylesheet', () => {
    const a = html.indexOf('<script src="chat-state.js">');
    const b = html.indexOf('<script src="chat-view.js">');
    const c = html.indexOf('<script src="renderer.js">');
    assert.ok(a > 0 && a < b && b < c);
    for (const f of ['chat-rich.js', 'chat-status.js', 'chat-linked.js', 'chat-settings.js']) {
      const i = html.indexOf(`<script src="${f}">`);
      assert.ok(i > a && i < b, f);
    }
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
    for (const src of [view, ...modules]) assert.doesNotMatch(src, /\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write\(/);
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
    for (const src of [view, ...modules, state, renderer, main, html]) for (const m of src.matchAll(/['"`](chat\.[A-Za-z0-9_.]+[A-Za-z0-9_])['"`]/g)) keys.add(m[1]);
    // built at runtime
    // Messenger 1.13 / 1.14: linked services and chats over a bridge
    for (const k of ['state_unreachable', 'state_logged_out', 'state_unlinked', 'state_locked', 'state_off', 'closed', 'cannot_send', 'first_1', 'first_2', 'first_3']) keys.add(`chat.bc.${k}`);
    for (const k of ['image', 'video', 'audio', 'voice', 'file', 'sticker', 'location', 'unsupported', 'view_once']) keys.add(`chat.bc.ph.${k}`);
    for (const k of ['bridge_error', 'unreachable', 'not_running', 'timeout', 'network_error', 'no_permission', 'too_old', 'unsupported', 'not_handled', 'bridge_unavailable', 'chat_closed']) keys.add(`chat.bc.reason.${k}`);
    for (const k of ['bridge_off', 'consent_required', 'bridge_locked', 'bridge_unsupported', 'bridge_failed', 'bridge_unreachable', 'rate_limited', 'bridge_text_only', 'bridge_unlinked']) keys.add(`chat.error.${k}`);
    for (const [net, notes] of Object.entries(CS.LINK_NOTES)) {
      for (const k of notes) keys.add(`chat.br.note_${net}_${k}`);
      for (const k of ['sub_logged_out', 'qr_lead']) keys.add(`chat.br.${k}_${net}`);
      for (const k of CS.qrSteps(net)) keys.add(k);
      // Messenger 1.23: the pairing code only where the service offers it (Signal: the QR code only)
      if (net !== 'signal') for (const k of ['code_step1', 'code_step2']) keys.add(`chat.br.${k}_${net}`);
      else for (const k of ['qr_renews', 'linked']) keys.add(`chat.br.${k}_${net}`);
      if (net !== 'whatsapp') for (const k of ['recTitle', 'recText', 'recSavedYes', 'recSavedNo']) keys.add(`chat.person.${k}_${net}`);
    }
    for (const k of CS.LINK_FLOWS) keys.add(`chat.br.flow_${k}`);
    for (const k of ['text', 'image', 'voice', 'file', 'location', 'system']) keys.add(`chat.kind.${k}`);
    for (const k of ['pending', 'failed', 'sent', 'delivered', 'read']) keys.add(`chat.status.${k}`);
    for (const k of ['direct', 'group']) keys.add(`chat.new.${k}`);
    for (const k of ['not_installed', 'unsupported', 'hidden', 'forbidden']) keys.add(`chat.unavailable.${k}`);
    for (const k of ['off', '86400', '604800', '2592000', 'seconds', 'minutes', 'hours', 'days', 'weeks']) keys.add(`chat.dis.${k}`);
    for (const k of ['denied', 'unavailable', 'timeout']) keys.add(`chat.loc.${k}`);
    // Messenger 1.4.0
    for (const k of ['poll', 'event', 'arrival', 'action']) keys.add(`chat.kind.${k}`);
    for (const k of ['run', 'request', 'grant']) { keys.add(`chat.action.mode.${k}`); keys.add(`chat.action.hint.${k}`); }
    for (const k of ['done', 'denied', 'expired']) keys.add(`chat.action.state.${k}`);
    for (const k of ['live', 'arrived', 'stopped']) keys.add(`chat.arrival.state.${k}`);
    for (const k of ['all', 'family', 'nobody', 'custom']) keys.add(`chat.audience.${k}`);
    for (const k of ['yes', 'maybe', 'no']) keys.add(`chat.event.${k}`);
    for (const o of CS.remindOptions(NOW)) keys.add(`chat.remind.${o.key}`);
    for (const n of [0, 15, 60, 120, 1440]) keys.add(`chat.reminderMin.${n}`);
    for (const p of CS.PRESETS) { keys.add(`chat.st.preset.${p}`); keys.add(`chat.st.presetHint.${p}`); }
    for (const o of CS.untilOptions(NOW)) keys.add(`chat.st.untilOpt.${o.key}`);
    for (const k of ['text', 'image']) keys.add(`chat.story.kind.${k}`);
    for (const k of ['blocked', 'not_allowed', 'feature_off', 'closed', 'no_approver', 'unavailable', 'rate_limited', 'unsupported']) keys.add(`chat.error.${k}`);
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

describe('chat-state: Messenger 1.4.0', () => {
  const F14 = { status: true, stories: true, polls: true, events: true, arrival: true, actions: true, msg_tools: true, privacy2: true };
  const me14 = { ...ME, features: { ...ME.features, ...F14 }, integrations: { familie: { lists: true, calendar: false, places: true } } };
  const cx14 = { ...ctx, me: me14 };

  it('features, Familie integrations and kinds this version draws', () => {
    assert.deepEqual(CS.features14(me14), { status: true, stories: true, polls: true, events: true, arrival: true, actions: true, tools: true, privacy: true, storyDuration: false, notices: false, noticeRoutes: false, linked: false, bridgeChats: false, bridgeMedia: false, bridgeNewChat: false, bridgeHistory: false, bridgeContacts: false });
    assert.deepEqual(CS.features14(ME), { status: false, stories: false, polls: false, events: false, arrival: false, actions: false, tools: false, privacy: false, storyDuration: false, notices: false, noticeRoutes: false, linked: false, bridgeChats: false, bridgeMedia: false, bridgeNewChat: false, bridgeHistory: false, bridgeContacts: false });
    assert.deepEqual(CS.familie(me14), { lists: true, calendar: false, places: true });
    assert.deepEqual(CS.familie(ME), { lists: false, calendar: false, places: false });
    for (const k of ['poll', 'event', 'arrival', 'action', 'card', 'text']) assert.equal(CS.isShownKind({ kind: k }), true, k);
    assert.equal(CS.isShownKind({ kind: 'hologram' }), false);
    assert.equal(CS.summary({ kind: 'hologram', text: 'x' }, direct(), ctx), 'chat.msg.unsupported');
    assert.equal(CS.summary({ kind: 'poll', poll: { question: 'Pizza?' } }, direct(), ctx), '📊 chat.kind.poll: Pizza?');
    assert.equal(CS.summary({ kind: 'card', card: { title: 'Haustür', text: 'Es klingelt' } }, direct(), ctx), 'Haustür: Es klingelt');
  });

  it('story duration (Messenger 1.4.1): offered only with story_duration (and stories)', () => {
    const withDur = { ...me14, features: { ...me14.features, story_duration: true } };
    assert.equal(CS.features14(withDur).storyDuration, true);
    assert.deepEqual(CS.storyDurations(withDur), [1, 3, 6, 12, 24]);
    assert.deepEqual(CS.storyDurations({ ...withDur, limits: { storyDurationsH: [24, 3, 48] } }), [3, 24], 'limits, known hours only');
    assert.deepEqual(CS.storyDurations({ ...withDur, limits: { storyDurationsH: [] } }), [1, 3, 6, 12, 24]);
    assert.equal(CS.storyDurations(me14), null, 'no key → 24 h, no choice');
    assert.equal(CS.storyDurations({ ...ME, features: { story_duration: true } }), null, 'not without stories');
    assert.equal(CS.STORY_DURATION_DEFAULT_H, 24);
  });

  it('own active stories: stats, the "Meine Storys" line, a posted story added at once', () => {
    const later = new Date(NOW + 3600000).toISOString();
    const gone = new Date(NOW - 1000).toISOString();
    const own = { user: { id: 7 }, stories: [{ id: 1, viewerCount: 2, expiresAt: later }, { id: 2, viewerCount: 3, expiresAt: later }, { id: 3, viewerCount: 9, expiresAt: gone }] };
    assert.deepEqual(CS.ownStoryStats(own, NOW), { count: 2, viewers: 5 });
    assert.deepEqual(CS.ownStoryStats({ stories: [] }, NOW), { count: 0, viewers: 0 });
    assert.deepEqual(CS.ownStoryStats(null, NOW), { count: 0, viewers: 0 });
    assert.equal(CS.ownStoryLine({ count: 2, viewers: 5 }, t), 'chat.st.storiesN(2) · chat.story.viewers(5)');
    assert.equal(CS.ownStoryLine({ count: 1, viewers: 0 }, t), 'chat.st.storiesOne · chat.story.viewers(0)');

    const story = { id: 301, kind: 'text', text: 'Grillen', createdAt: new Date(NOW).toISOString(), expiresAt: later };
    const feed = { items: [{ user: { id: 8 }, stories: [] }], me: { user: { id: 7, name: 'Marc' }, status: { preset: 'dnd' }, stories: [{ id: 300, expiresAt: later }] } };
    const next = CS.addOwnStory(feed, story, { id: 7, name: 'Marc' });
    assert.deepEqual(next.me.stories.map((x) => x.id), [300, 301]);
    assert.equal(next.me.stories[1].viewerCount, 0);
    assert.equal(next.me.status.preset, 'dnd', 'status kept');
    assert.equal(next.items, feed.items);
    assert.equal(feed.me.stories.length, 1, 'the old feed is not changed');
    assert.deepEqual(CS.addOwnStory(next, story, null).me.stories.map((x) => x.id), [300, 301], 'not twice');
    const fresh = CS.addOwnStory(null, story, { id: 7, name: 'Marc', initials: 'MA' });
    assert.deepEqual(fresh.items, []);
    assert.equal(fresh.me.user.name, 'Marc');
    assert.deepEqual(fresh.me.stories.map((x) => x.id), [301]);
    assert.equal(CS.ownStoryStats(fresh.me, NOW).count, 1);
    assert.equal(CS.addOwnStory(feed, null, null).me, feed.me, 'no story: unchanged');
  });

  it('status lines, rings, ages and "Löschen nach"', () => {
    const tl = { ...ctx, t: (k, p) => (k === 'chat.st.preset.homeoffice' ? 'Im Homeoffice' : t(k, p)) };
    assert.equal(CS.statusLine({ preset: 'homeoffice', text: null, until: at(19, 0) }, tl, NOW), 'Im Homeoffice · chat.st.untilShort(19:00)');
    assert.equal(CS.presetLabel('homeoffice', tl.t), 'Im Homeoffice');
    assert.equal(CS.presetLabel('unknown', t), '');
    assert.equal(CS.statusLine({ preset: 'none', text: 'Im Garten' }, ctx, NOW), 'Im Garten');
    assert.equal(CS.statusLine({ preset: 'away', text: null, destLabel: 'Zuhause', eta: at(18, 40) }, ctx, NOW), 'chat.st.awayTo(Zuhause) · chat.st.eta(18:40)');
    assert.equal(CS.statusLine(null, ctx), '');
    assert.equal(CS.statusRing({ stories: [{ seen: true }, { seen: false }] }), 'unseen');
    assert.equal(CS.statusRing({ stories: [{ seen: true }] }), 'seen');
    assert.equal(CS.statusRing({ stories: [] }), 'none');
    assert.equal(CS.firstUnseen([{ seen: true }, { seen: false }]), 1);
    assert.equal(CS.firstUnseen([{ seen: true }]), 0);
    assert.equal(CS.relAge(new Date(NOW - 12 * 60000).toISOString(), ctx, NOW), 'chat.rel.minAgo(12)');
    assert.equal(CS.remaining(new Date(NOW + 23.5 * 3600000).toISOString(), ctx, NOW), 'chat.rel.hLeft(23)');
    const until = CS.untilOptions(NOW);
    assert.deepEqual(until.map((o) => o.key), ['30m', '1h', '4h', 'today', 'never']);
    assert.equal(Date.parse(until[1].at) - NOW, 3600000);
    assert.equal(until[4].at, null);
    const rem = CS.remindOptions(NOW);
    assert.equal(new Date(rem[1].at).getDate(), 18, '18:00 already passed → tomorrow evening');
    assert.equal(new Date(rem[2].at).getHours(), 9);
  });

  it('polls: shares, own votes, single / multi choice, head', () => {
    const poll = { question: 'Essen?', options: [{ id: 'o1', text: 'Grillen', count: 2, voters: [8, 9] }, { id: 'o2', text: 'Pasta', count: 1, voters: [7] }], multi: false, anonymous: false, allowAdd: true, closed: false, voterCount: 3, memberCount: 4, creatorId: 7, myVotes: ['o2'], closesAt: at(18, 30) };
    const v = CS.pollView(poll, cx14);
    assert.deepEqual(v.options.map((o) => [o.pct, o.mine, o.lead]), [[67, false, true], [33, true, false]]);
    assert.equal(v.mineCreator, true);
    assert.equal(v.allowAdd, true);
    assert.deepEqual(CS.nextVotes(poll, 'o1'), ['o1']);
    assert.deepEqual(CS.nextVotes(poll, 'o2'), [], 'again → withdrawn');
    assert.deepEqual(CS.nextVotes({ ...poll, multi: true }, 'o1'), ['o2', 'o1']);
    assert.deepEqual(CS.nextVotes({ ...poll, multi: true }, 'o2'), []);
    assert.equal(CS.pollHead(poll, ctx, NOW), 'chat.poll.head · chat.poll.ends(18:30)');
    assert.equal(CS.pollHead({ ...poll, closed: true }, ctx, NOW), 'chat.poll.head · chat.poll.closed');
    assert.equal(CS.pollView({ ...poll, closed: true }, cx14).allowAdd, false);
  });

  it('events: answers with guests, date badge, edit rights', () => {
    assert.deepEqual(CS.rsvpCounts({ yes: [{ userId: 8, guests: 2 }, { userId: 7, guests: 0 }], maybe: [{ userId: 9 }], no: [], mine: 'yes', myGuests: 0 }), { yes: 4, maybe: 1, no: 0, mine: 'yes', myGuests: 0 });
    const v = CS.eventView({ startsAt: at(12, 30, 9), endsAt: at(16, 0, 9) }, ctx, NOW);
    assert.equal(v.day, '26');
    assert.equal(v.time, '12:30 – 16:00');
    assert.equal(v.rel, 'chat.event.inDays(9)');
    assert.equal(v.past, false);
    assert.equal(CS.eventView({ startsAt: at(10, 0, -1) }, ctx, NOW).past, true);
    assert.equal(CS.eventView({ startsAt: at(0, 0, 1), allDay: true }, ctx, NOW).time, 'chat.event.allDay');
    assert.equal(CS.canEditEvent({ creatorId: 7 }, direct(), cx14), true);
    assert.equal(CS.canEditEvent({ creatorId: 8 }, group({ me: { role: 'admin' } }), cx14), true);
    assert.equal(CS.canEditEvent({ creatorId: 8 }, group({ me: { role: 'member' } }), cx14), false);
    assert.equal(CS.canEditEvent({ creatorId: 7, cancelled: true }, direct(), cx14), false);
  });

  it('live arrival: ETA, distance, progress', () => {
    const v = CS.arrivalView({ dest: { label: 'Zuhause', lat: 50, lon: 7 }, state: 'live', etaAt: new Date(NOW + 9 * 60000).toISOString(), distanceM: 3100, progress: 0.4, position: { lat: 50.1, lon: 7 } }, ctx, NOW);
    assert.deepEqual([v.live, v.minutes, v.distance, v.progress, v.label], [true, 9, '3,1 km', 0.4, 'Zuhause']);
    assert.equal(CS.arrivalView({ state: 'arrived', progress: 0.9 }, ctx, NOW).progress, 1);
    assert.equal(CS.distanceText(445, 'de'), '450 m');
    assert.equal(CS.distanceText(-1, 'de'), '');
  });

  it('home actions: buttons from `can`, done only after an approved request, grants, cards', () => {
    const c = group();
    const req = { senderId: 9, action: { mode: 'request', label: 'Garage öffnen', state: 'open', can: { run: false, approve: true, deny: true } } };
    const v = CS.actionView(req, c, cx14);
    assert.deepEqual([v.run, v.approve, v.deny, v.stateText], [false, true, true, 'chat.action.waiting']);
    assert.equal(v.head, 'chat.action.headRequest(Lena)');
    const done = CS.actionView({ ...req, action: { ...req.action, state: 'done', can: { approve: true } } }, c, cx14);
    assert.deepEqual([done.approve, done.stateText], [false, 'chat.action.state.done']);
    const run = CS.actionView({ senderId: 7, action: { mode: 'run', label: 'Licht', state: 'open', can: { run: true } } }, c, cx14);
    assert.equal(run.run, true);
    assert.equal(run.stateText, '');
    const grant = CS.actionView({ senderId: 7, action: { mode: 'grant', label: 'Licht', state: 'open', grant: { toUserId: 9, until: at(22, 0) }, can: { run: false } } }, c, cx14);
    assert.equal(grant.sub, 'chat.action.grantTo(Lena,22:00)');
    assert.equal(CS.cardHead({ createdAt: at(17, 52), card: { kind: 'doorbell', title: 'Haustür' } }, ctx), 'chat.card.doorbell · Haustür · 17:52');
    assert.equal(CS.cardRoute({ route: 'plg-gatecontrol-door', kind: 'live_view' }), 'plg-gatecontrol-door');
    assert.equal(CS.cardRoute({ route: 'javascript:alert(1)' }), null);
    assert.equal(CS.iconPath('M3 21V9l9-6 9 6v12H3z'), 'M3 21V9l9-6 9 6v12H3z');
    assert.equal(CS.iconPath('<script>'), null);
  });

  it('message menu: pin (can.pin), remind, suggestions only with Familie and text', () => {
    const c = direct({ can: { send: true, pin: true }, pinned: [5] });
    const a = CS.messageActions(msg(5), c, cx14, NOW);
    assert.deepEqual([a.pin, a.pinned, a.remind, a.suggest], [true, true, true, true]);
    const none = CS.messageActions(msg(5), direct({ can: { send: true } }), { ...cx14, me: { ...me14, integrations: {} } }, NOW);
    assert.deepEqual([none.pin, none.suggest], [false, false]);
    assert.equal(CS.messageActions(msg(5), c, ctx, NOW).remind, false, 'without msg_tools');
  });

  it('chat list: chips, own lists, archive; last seen; blocked peers', () => {
    const list = [direct({ id: 1, unread: 2 }), group({ id: 2, unread: 0 }), direct({ id: 3, archived: true, unread: 4 })];
    assert.deepEqual(CS.listFilter(list, {}).map((c) => c.id), [1, 2]);
    assert.deepEqual(CS.listFilter(list, { filter: 'unread' }).map((c) => c.id), [1]);
    assert.deepEqual(CS.listFilter(list, { filter: 'groups' }).map((c) => c.id), [2]);
    assert.deepEqual(CS.listFilter(list, { filter: 'list:w', lists: [{ id: 'w', conversationIds: [2, 3] }] }).map((c) => c.id), [2]);
    assert.deepEqual(CS.listFilter(list, { archived: true }).map((c) => c.id), [3]);
    assert.deepEqual(CS.archivedInfo(list), { count: 1, unread: 4 });
    assert.equal(CS.lastSeenText({ online: true }, ctx, NOW), 'chat.seen.online');
    assert.equal(CS.lastSeenText({ online: false, lastSeenAt: at(17, 44) }, ctx, NOW), 'chat.seen.today(17:44)');
    assert.equal(CS.lastSeenText({ online: false, lastSeenAt: null }, ctx, NOW), null);
    assert.equal(CS.headSub(direct({ peer: member(8, 'Anna', { online: true }) }), ctx).text, 'chat.seen.online');
    assert.equal(CS.composerBlock(direct({ peer: member(8, 'Anna', { blocked: true }) })), 'blocked');
    assert.equal(CS.listId('Arbeit & Verein', [{ id: 'arbeit-verein' }]), 'arbeit-verein-2');
    assert.deepEqual(CS.shownActions([{ id: 'a' }, { id: 'b' }], ['b']).map((a) => a.id), ['a']);
    assert.equal(CS.fontScale('large') > 1, true);
    assert.equal(CS.fromLocalInput(CS.localInput(at(15, 30))), at(15, 30));
    assert.equal(CS.fromLocalInput('nope'), null);
  });

  it('system messages of 1.4.0', () => {
    const c = group();
    assert.equal(CS.systemText({ kind: 'system', system: { event: 'poll_closed', by: null, question: 'Essen?', winner: 'Pizza' } }, c, ctx), 'chat.sys.pollClosedAuto(Essen?,chat.sys.pollWinner(Pizza))');
    assert.equal(CS.systemText({ kind: 'system', system: { event: 'arrived', userId: 8, label: 'Zuhause' } }, c, ctx), 'chat.sys.arrived(Anna,Zuhause)');
    assert.equal(CS.systemText({ kind: 'system', system: { event: 'action_run', userId: 9, asUserId: 8, label: 'Licht' } }, c, ctx), 'chat.sys.actionRunAs(Lena,Licht,Anna)');
    assert.equal(CS.systemText({ kind: 'system', system: { event: 'something_new' } }, c, ctx), 'chat.sys.unknown');
  });
});

describe('Messenger 1.6: notifications in chats', () => {
  const me16 = { ...ME, features: { ...ME.features, status: true, notices: true, notice_routes: true } };

  it('knows the 1.6 features', () => {
    const f = CS.features14(me16);
    assert.deepEqual([f.notices, f.noticeRoutes], [true, true]);
    assert.deepEqual([CS.features14(ME).notices, CS.features14(ME).noticeRoutes], [false, false]);
  });

  it('list sections: pinned chats (listPinned) apart, each in its order; none while searching', () => {
    const fam = group({ id: 20, title: 'Familie', listPinned: true, unread: 0 });
    const list = [direct({ id: 1 }), fam, group({ id: 2 })];
    const s = CS.listSections(list);
    assert.deepEqual(s.pinned.map((c) => c.id), [20]);
    assert.deepEqual(s.chats.map((c) => c.id), [1, 2]);
    const q = CS.listSections(list, { sectioned: false });
    assert.deepEqual([q.pinned.length, q.chats.map((c) => c.id)], [0, [1, 20, 2]]);
    assert.deepEqual(CS.listSections(null), { pinned: [], chats: [] });
    // filters apply to pinned chats as well (the list is split after filtering)
    assert.deepEqual(CS.listSections(CS.listFilter([fam, direct({ id: 1, unread: 1 })], { filter: 'unread' })).pinned, []);
  });

  it('notice channels: tag, header line, no "kept by a plugin"', () => {
    const ch = group({ id: 30, title: 'Schule', readonly: true, managedBy: 'gatecontrol-messenger', can: { send: false }, notice: { source: 'plugin:gatecontrol-schule', label: 'Schule' } });
    assert.equal(CS.isNotice(ch), true);
    assert.equal(CS.isNotice(group()), false);
    assert.equal(CS.noticeLabel(ch), 'Schule');
    assert.equal(CS.headSub(ch, ctx).text, 'chat.notice.infoSub(Schule)');
    assert.equal(CS.headSub({ ...ch, notice: {} }, ctx).text, 'chat.channelSub');
    assert.equal(CS.composerBlock(ch), 'readonly');
    // the list preview without "GateControl:" in front
    assert.equal(CS.preview({ ...ch, lastMessage: { kind: 'text', text: 'Neu', senderId: null } }, ctx).text, 'Neu');
  });

  it('notice cards: head "<source> · <topic>", checked notice, picture and link to the notification', () => {
    const card = {
      kind: 'notice', title: 'Elternbrief', text: 'Zeile 1\nZeile 2', image: null, imageUrl: '/notify-media/schule0001ab.jpg',
      link: { label: 'Ganze Nachricht lesen', route: 'plg-gatecontrol-schule/messages/4711', kind: null },
      actions: [], lastRun: null,
      notice: { source: 'plugin:gatecontrol-schule', sourceLabel: 'Schule', topic: 'plugin:gatecontrol-schule:messages', topicLabel: 'Nachrichten der Schule', priority: 'high', data: { schule: { studentId: 3, messageId: 4711 } } },
    };
    const m = { id: 5, kind: 'card', createdAt: at(17, 52), card };
    assert.equal(CS.cardHead(m, ctx), 'Schule · Nachrichten der Schule · 17:52');
    // without labels: the old head
    assert.equal(CS.cardHead({ ...m, card: { ...card, notice: { topic: 'devices' } } }, ctx), 'chat.card.notice · Elternbrief · 17:52');
    assert.equal(CS.noticeImage(card), '/notify-media/schule0001ab.jpg');
    assert.equal(CS.noticeImage({ imageUrl: 'https://evil.example/notify-media/schule0001ab.jpg' }), null);
    assert.equal(CS.noticeImage({ imageUrl: '/notify-media/../x.jpg' }), null);
    const n = CS.noticeOf(card);
    assert.deepEqual([n.source, n.topic, n.priority, n.data.schule.messageId], ['plugin:gatecontrol-schule', 'plugin:gatecontrol-schule:messages', 'high', 4711]);
    assert.deepEqual(CS.noticeOf({ notice: { source: 'evil', topic: '../x', sourceLabel: 'A\u0000B', priority: 'urgent', data: [1] } }), { source: null, sourceLabel: 'A B', topic: null, topicLabel: null, priority: 'normal', data: null });
    assert.equal(CS.noticeOf({}), null);
    const link = CS.cardLink(card, t);
    assert.deepEqual(link, {
      route: 'plg-gatecontrol-schule/messages/4711', label: 'Ganze Nachricht lesen', icon: 'external',
      target: { route: 'plg-gatecontrol-schule/messages/4711', topic: 'plugin:gatecontrol-schule:messages', data: { schule: { studentId: 3, messageId: 4711 } } },
    });
    // the doorbell's link keeps working; labels ≤ 40, default label
    assert.deepEqual(CS.cardLink({ link: { route: 'plg-gatecontrol-door', kind: 'live_view' } }, t), { route: 'plg-gatecontrol-door', label: 'chat.card.open', icon: 'video', target: { route: 'plg-gatecontrol-door', topic: null, data: null } });
    assert.equal(CS.cardLink({ link: { route: 'plg-x', label: 'x'.repeat(60) } }, t).label.length, 40);
    for (const bad of ['plg-x/../y', 'plg-x/..', 'plg-x/a/b/c/d', 'vpn', 'https://x']) assert.equal(CS.cardLink({ link: { route: bad } }, t), null, bad);
    // the whole text, line breaks kept (preview of the list: title and text)
    assert.equal(CS.summary(m, group(), ctx), 'Elternbrief: Zeile 1\nZeile 2');
  });
});

// ── Messenger 1.13 „Verknüpfte Dienste“ and 1.14 chats over a bridge ──

describe('chat-state: chats over a bridge (Messenger 1.14)', () => {
  const BRIDGE = { network: 'whatsapp', label: 'WhatsApp', state: 'ok', closed: false, supports: ['text', 'reply', 'reaction', 'edit', 'delete', 'read', 'typing'] };
  const bridged = (extra = {}) => ({
    id: 20, kind: 'direct', title: 'Kim Muster', peer: null, members: [member(7, 'Marc')], me: { lastReadId: 0, notify: 'all' }, unread: 0, typing: [], typingContacts: [],
    can: { send: true, pin: true, editInfo: false, manageMembers: false, leave: false, setDisappearing: false }, readUpTo: null, deliveredUpTo: null, bridge: { ...BRIDGE }, lastMessage: null, createdAt: at(9, 0, -3), ...extra,
  });
  const from = (id, name, extra = {}) => msg(id, { senderId: null, via: 'bridge:whatsapp', bridge: { sender: { contactId: id, name }, remote: false, state: null, reason: null, placeholder: null }, ...extra });
  const own = (id, state, extra = {}) => msg(id, { senderId: 7, mine: true, createdAt: new Date(NOW - 60000).toISOString(), status: state === 'pending' ? 'sending' : state, bridge: { sender: null, remote: false, state, reason: null, placeholder: null, ...extra } });

  it('features: the two words, and nothing without them', () => {
    assert.deepEqual([CS.features14({ features: { linked_services: true } }).linked, CS.features14({ features: { linked_services: true } }).bridgeChats], [true, false]);
    assert.equal(CS.features14({ features: { bridge_chats: true } }).bridgeChats, true);
    assert.deepEqual([CS.features14(ME).linked, CS.features14(ME).bridgeChats], [false, false]);
    assert.equal(CS.bridgeOf(direct()), null);
    assert.equal(CS.bridgeOf({ bridge: null }), null);
    assert.equal(CS.bridgeOf(bridged()).network, 'whatsapp');
  });

  it('title, picture, the line under the name, the service\'s sign and filters', () => {
    assert.equal(CS.title(bridged(), t), 'Kim Muster');
    assert.equal(CS.title(bridged({ title: null }), t), 'chat.bc.unknown_contact');
    assert.deepEqual([CS.avatarOf(bridged()).kind, CS.avatarOf(bridged()).initials], ['person', 'KM']);
    assert.deepEqual(CS.avatarOf(bridged({ title: null })), { kind: 'icon', icon: 'gone' });
    assert.equal(CS.avatarOf(bridged({ kind: 'group' })).icon, 'group');
    assert.deepEqual(CS.headSub(bridged(), ctx), { text: 'chat.bc.via(WhatsApp)', typing: false });
    assert.equal(CS.bridgeMark('whatsapp'), 'WA');
    assert.equal(CS.bridgeName('signal'), 'Signal');
    const list = [direct(), bridged(), bridged({ id: 21, kind: 'group' }), bridged({ id: 22, archived: true })];
    assert.deepEqual(CS.bridgeNetworks(list), [{ id: 'whatsapp', label: 'WhatsApp' }]);
    assert.deepEqual(CS.bridgeNetworks([direct(), group()]), []);
    assert.deepEqual(CS.listFilter(list, { filter: 'gc' }).map((c) => c.id), [12]);
    assert.deepEqual(CS.listFilter(list, { filter: 'net:whatsapp' }).map((c) => c.id), [20, 21]);
    assert.deepEqual(CS.listFilter(list, { filter: 'net:signal' }), []);
  });

  it('who wrote: the contact, an unknown contact, the own account; contacts are grouped apart', () => {
    const c = bridged({ kind: 'group', title: 'Elternrunde' });
    assert.equal(CS.senderName(from(1, 'Robin'), c, ctx), 'Robin');
    assert.equal(CS.senderName(from(2, null), c, ctx), 'chat.bc.unknown_contact');
    assert.equal(CS.senderName(own(3, 'sent'), c, ctx), 'chat.you');
    assert.equal(CS.senderName(msg(4), direct(), ctx), 'Anna');
    assert.equal(CS.quoteName({ id: 1, senderId: null, contactId: 12, senderName: 'Kim Muster' }, c, ctx), 'Kim Muster');
    assert.equal(CS.quoteName({ id: 1, senderId: null, contactId: 12, senderName: null }, c, ctx), 'chat.bc.unknown_contact');
    assert.equal(CS.quoteName({ id: 1, senderId: 8 }, direct(), ctx), 'Anna');
    const tl = CS.timeline([from(1, 'Robin'), from(1, 'Robin', { id: 5 }), from(2, 'Kai', { id: 6 })], [], c, ctx, { now: NOW }).filter((x) => x.type === 'msg');
    assert.deepEqual(tl.map((x) => x.cont), [false, true, false]);
    assert.equal(CS.preview({ ...c, lastMessage: from(1, 'Robin', { text: 'Wer bringt Kuchen?' }) }, ctx).text, 'Robin: Wer bringt Kuchen?');
    assert.equal(CS.preview({ ...bridged(), lastMessage: from(1, 'Kim', { text: 'Hi' }) }, ctx).text, 'Hi');
    assert.equal(CS.systemText({ kind: 'system', system: { event: 'bridge_notice', network: 'whatsapp' }, text: 'Getrennt.' }, c, ctx), 'chat.bc.notice(WhatsApp): Getrennt.');
  });

  it('typing: contacts of the other side', () => {
    assert.equal(CS.typingText(bridged(), ctx), null);
    assert.equal(CS.typingText(bridged({ typingContacts: [{ contactId: 1, name: 'Kim' }] }), ctx), 'chat.typing');
    assert.equal(CS.typingText(bridged({ kind: 'group', typingContacts: [{ contactId: 1, name: 'Kim' }] }), ctx), 'chat.typingOne(Kim)');
    assert.equal(CS.typingText(bridged({ kind: 'group', typingContacts: [{ contactId: 1, name: null }] }), ctx), 'chat.typingOne(chat.bc.unknown_contact)');
    assert.equal(CS.typingText(bridged({ kind: 'group', typingContacts: [{ contactId: 1 }, { contactId: 2 }] }), ctx), 'chat.typingMany(2)');
    assert.deepEqual(CS.headSub(bridged({ typingContacts: [{ contactId: 1, name: 'Kim' }] }), ctx), { text: 'chat.typing', typing: true });
  });

  it('placeholders are said, never swallowed', () => {
    const c = bridged();
    const ph = (kind, name, text = null) => from(1, 'Kim', { text, bridge: { sender: { contactId: 1, name: 'Kim' }, placeholder: { kind, name } } });
    assert.equal(CS.placeholderText(ph('image', 'grill.jpg'), c, t), 'chat.bc.ph.image · grill.jpg – chat.bc.ph_later(WhatsApp)');
    assert.equal(CS.placeholderText(ph('voice', null), c, t), 'chat.bc.ph.voice – chat.bc.ph_later(WhatsApp)');
    assert.equal(CS.placeholderText(ph('unsupported', null), c, t), 'chat.bc.ph.unsupported(WhatsApp)');
    assert.equal(CS.placeholderOf(ph('hologram', null)), null);
    assert.equal(CS.placeholderText(from(1, 'Kim'), c, t), null);
    assert.equal(CS.summary(ph('image', 'grill.jpg', 'So sah es aus'), c, ctx), 'chat.bc.ph.image · grill.jpg – chat.bc.ph_later(WhatsApp): So sah es aus');
    assert.equal(CS.summary(from(1, 'Kim', { text: 'Hi' }), c, ctx), 'Hi');
  });

  it('own messages: the bridge\'s word (sent, delivered, read, not sent with its reason)', () => {
    const c = bridged({ readUpTo: 3, deliveredUpTo: 4 });
    assert.equal(CS.status(own(3, 'read'), c), 'read');
    assert.equal(CS.status(own(4, 'delivered'), c), 'delivered');
    assert.equal(CS.status(own(5, 'sent'), c), 'sent');
    assert.equal(CS.status(own(2, 'failed'), c), 'failed', 'not sent, although older ones were read');
    assert.equal(CS.status(own(6, 'pending'), c), 'pending');
    assert.equal(CS.status(from(7, 'Kim'), c), null);
    assert.deepEqual(CS.bridgeFailure(own(2, 'failed', { reason: 'not_running' }), t), { text: 'chat.bc.failed chat.bc.reason.not_running', resend: true });
    assert.equal(CS.bridgeFailure(own(2, 'failed', { reason: 'm_forbidden' }), t).text, 'chat.bc.failed chat.bc.reason.bridge_error');
    assert.equal(CS.bridgeFailure(own(2, 'failed', { reason: null }), t).text, 'chat.bc.failed chat.bc.reason.bridge_error');
    assert.equal(CS.bridgeFailure(own(5, 'sent'), t), null);
    assert.equal(CS.bridgeFailure(msg(5, { mine: true }), t), null);
  });

  it('message menu: only what crosses; nothing on a message that was not sent; no edit of one written on the phone', () => {
    const c = bridged();
    const a = (m, conv = c) => CS.messageActions(m, conv, ctx, NOW);
    assert.deepEqual([a(from(1, 'Kim', { text: 'Hi' })).reply, a(from(1, 'Kim')).react, a(from(1, 'Kim')).edit, a(from(1, 'Kim')).deleteAll, a(from(1, 'Kim')).deleteMe], [true, true, false, false, true]);
    const sent = a(own(2, 'sent'));
    assert.deepEqual([sent.reply, sent.react, sent.edit, sent.deleteAll], [true, true, true, true]);
    const failed = a(own(3, 'failed'));
    assert.deepEqual([failed.reply, failed.react, failed.edit, failed.deleteMe, failed.copy], [false, false, false, true, true]);
    assert.equal(a(own(4, 'sent', { remote: true })).edit, false);
    assert.equal(a(own(4, 'sent', { remote: true })).reply, true);
    // a service that takes no reactions / edits
    const few = bridged({ bridge: { ...BRIDGE, supports: ['text', 'reply'] } });
    assert.deepEqual([a(own(2, 'sent'), few).react, a(own(2, 'sent'), few).edit, a(own(2, 'sent'), few).reply], [false, false, true]);
    // the link is gone: readable, nothing goes out
    const off = bridged({ can: { send: false }, bridge: { ...BRIDGE, state: 'logged_out' } });
    assert.deepEqual([a(own(2, 'sent'), off).reply, a(own(2, 'sent'), off).edit, a(own(2, 'sent'), off).deleteAll, a(own(2, 'sent'), off).deleteMe], [false, false, false, true]);
    // a normal chat is untouched
    assert.equal(CS.messageActions(msg(1, { mine: true, senderId: 7, createdAt: new Date(NOW - 60000).toISOString() }), direct(), ctx, NOW).edit, true);
  });

  it('why nothing goes out: the state of the link, with "Neu verknüpfen" where it helps', () => {
    assert.equal(CS.bridgeBlock(bridged()), null);
    assert.equal(CS.composerBlock(bridged()), null);
    assert.equal(CS.bridgeBlock(direct()), null);
    const st = (state, extra = {}) => bridged({ can: { send: false }, bridge: { ...BRIDGE, state, ...extra } });
    assert.deepEqual(CS.bridgeBlock(st('unreachable')), { key: 'state_unreachable', relink: false, warn: true });
    assert.deepEqual(CS.bridgeBlock(st('logged_out')), { key: 'state_logged_out', relink: true, warn: true });
    assert.deepEqual(CS.bridgeBlock(st('unlinked')), { key: 'state_unlinked', relink: true, warn: false });
    assert.deepEqual(CS.bridgeBlock(st('locked')), { key: 'state_locked', relink: false, warn: true });
    assert.deepEqual(CS.bridgeBlock(st('off')), { key: 'state_off', relink: false, warn: false });
    assert.deepEqual(CS.bridgeBlock(st('ok', { closed: true })), { key: 'closed', relink: false, warn: false });
    assert.deepEqual(CS.bridgeBlock(st('ok')), { key: 'cannot_send', relink: false, warn: false });
    for (const s of ['unreachable', 'logged_out', 'unlinked', 'locked', 'off']) assert.equal(CS.composerBlock(st(s)), 'bridge', s);
    // a normal chat keeps its own reasons
    assert.equal(CS.composerBlock(direct({ can: { send: false } })), 'readonly');
  });
});

describe('chat-state: „Verknüpfte Dienste“ (Messenger 1.13)', () => {
  const net = (extra = {}) => ({ id: 'whatsapp', state: 'running', allowed: true, lock: null, consent: false, outdated: false, logins: [], ...extra });
  const login = (state, extra = {}) => ({ id: 'l1', name: '+49 1512 0000000', state, since: '2026-11-02T10:00:00.000Z', ...extra });
  const row = (n) => CS.linkedRow(n, ctx);

  it('the overview: every state of a service', () => {
    assert.deepEqual([row(net()).state, row(net()).sub, row(net()).link, row(net()).unlink, row(net()).pill], ['none', 'chat.br.sub_none', true, false, null]);
    const linked = row(net({ logins: [login('connected')] }));
    assert.deepEqual([linked.state, linked.sub, linked.pill, linked.unlink, linked.link, linked.again], ['linked', 'chat.br.sub_linked_since(02.11.2026) · +49 1512 0000000', { text: 'chat.br.pill_linked', tone: 'ok' }, true, false, null]);
    assert.equal(row(net({ logins: [login('connecting', { since: null, name: '' })] })).sub, 'chat.br.sub_linked');
    assert.deepEqual(row(net({ outdated: true, logins: [login('connected')] })).pill, { text: 'chat.br.pill_outdated', tone: 'warn' });
    const out = row(net({ logins: [login('logged_out')] }));
    assert.deepEqual([out.state, out.pill.tone, out.unlink, out.link], ['logged_out', 'err', false, false]);
    assert.match(out.sub, /^chat\.br\.sub_logged_out_at\(02\.11\.2026\)/);
    assert.deepEqual(out.again, { hint: 'chat.br.relink_hint', link: true, forget: true });
    const err = row(net({ logins: [login('error')] }));
    assert.deepEqual([err.state, err.unlink, err.again.forget, err.again.link], ['error', true, false, true]);
    const locked = row(net({ allowed: false, lock: 'child' }));
    assert.deepEqual([locked.state, locked.link, locked.pill], ['locked', false, { text: 'chat.br.pill_locked', tone: 'off' }]);
    // a child whose link was signed out: no new link while it is locked
    assert.deepEqual(row(net({ allowed: false, logins: [login('logged_out')] })).again, { hint: 'chat.br.sub_locked', link: false, forget: true });
    assert.deepEqual([row(net({ state: 'starting' })).state, row(net({ state: 'starting' })).pill.text, row(net({ state: 'starting' })).link], ['starting', 'chat.br.pill_starting', false]);
    for (const s of ['unreachable', 'failed']) assert.deepEqual([row(net({ state: s, logins: [login('connected')] })).state, row(net({ state: s })).unlink, row(net({ state: s, logins: [login('logged_out')] })).again], ['unreachable', false, null]);
    assert.equal(CS.mainLogin(net({ logins: [login('logged_out'), login('connected', { id: 'l2' })] })).id, 'l2');
    assert.equal(CS.mainLogin(net()), null);
    assert.equal(CS.linkDate('nope', 'de'), '');
    assert.equal(CS.linkDate('2026-11-02T10:00:00.000Z', 'en'), '02/11/2026');
    assert.equal(CS.linkable('whatsapp'), true);
    // Messenger 1.23: Signal
    assert.equal(CS.linkable('signal'), true);
    assert.equal(CS.linkable('telegram'), false);
    assert.equal(CS.linkable('constructor'), false);
  });

  it('why a link ended: a code that ran out, no answer, a refusal', () => {
    assert.equal(CS.linkErrorText({ ok: false, code: 'bridge_failed', reason: 'timeout' }, t), 'chat.br.err_expired');
    assert.equal(CS.linkErrorText({ ok: false, code: 'bridge_failed', reason: 'login_expired' }, t), 'chat.br.err_expired');
    assert.equal(CS.linkErrorText({ ok: false, code: 'network' }, t), 'chat.br.err_no_answer');
    assert.equal(CS.linkErrorText({ ok: false, code: 'timeout' }, t), 'chat.br.err_no_answer');
    // other codes: chat.error.<code>
    const known = (k) => ({ 'chat.error.bridge_failed': 'Abgelehnt.', 'chat.error.bridge_unsupported': 'Anderer Weg.' }[k] || k);
    assert.equal(CS.linkErrorText({ ok: false, code: 'bridge_failed', reason: 'refused' }, known), 'Abgelehnt.');
    assert.equal(CS.linkErrorText('bridge_unsupported', known), 'Anderer Weg.');
    assert.equal(CS.linkErrorText({ ok: false, code: 'whatever' }, known), 'chat.error.failed');
  });

  it('the pairing code in boxes, the QR code from its modules', () => {
    assert.deepEqual(CS.codeChars('K7-M4').map((c) => (c.dash ? '–' : c.ch)), ['K', '7', '–', 'M', '4']);
    const rows = Array.from({ length: 21 }, (_, y) => (y === 0 ? '1'.repeat(21) : `1${'0'.repeat(19)}1`));
    const q = CS.qrPath({ size: 21, rows });
    assert.equal(q.size, 29, 'four modules of quiet zone on every side');
    assert.ok(q.d.startsWith('M4 4h21v1h-21z'), 'one rectangle per run of dark modules');
    assert.equal(q.d.split('M').length - 1, 1 + 20 * 2);
    assert.match(q.d, /^[Mhvz0-9 -]+$/);
    for (const bad of [null, {}, { rows: [] }, { rows: rows.slice(1) }, { rows: rows.map((r) => r.replace(/0/g, 'x')) }, { rows: rows.map((r) => r.slice(1)) }]) assert.equal(CS.qrPath(bad), null);
  });
});

describe('Chats page: linked services and chats over a bridge', () => {
  const read = (f) => fs.readFileSync(path.join(ROOT, 'src', 'renderer', f), 'utf8');

  it('chat-linked.js loads before chat-settings.js; the section needs the feature word', () => {
    const html = read('index.html');
    assert.ok(html.indexOf('<script src="chat-linked.js">') > 0 && html.indexOf('<script src="chat-linked.js">') < html.indexOf('<script src="chat-settings.js">'));
    assert.match(read('chat-settings.js'), /f\.linked && linked \? \{ id: 'linked'/);
    assert.match(read('chat-state.js'), /linked: f\('linked_services'\), bridgeChats: f\('bridge_chats'\)/);
  });

  it('neither the number nor the code is stored or logged; the QR code is drawn black on white', () => {
    const linked = read('chat-linked.js');
    assert.doesNotMatch(linked, /localStorage|sessionStorage|console\.|indexedDB/);
    assert.match(linked, /setAttribute\('fill', '#fff'\)/);
    assert.match(linked, /setAttribute\('fill', '#000'\)/);
    assert.match(read('styles/chat.css'), /\.cv-br-qrbox \{[^}]*background: #fff/);
    // no version checks anywhere in the chat modules
    for (const f of ['chat-linked.js', 'chat-settings.js', 'chat-view.js', 'chat-state.js']) assert.doesNotMatch(read(f), /st(atus)?\.version|\.version\s*[<>]=?/, f);
  });
});

describe('chat-state: files, pictures and a new chat by number over a bridge (Messenger 1.15 / 1.16)', () => {
  const MEDIA = { network: 'whatsapp', label: 'WhatsApp', state: 'ok', closed: false, supports: ['text', 'reply', 'image', 'video', 'voice', 'file'], mediaTypes: { image: ['image/jpeg', 'image/png', 'image/webp'], video: ['video/mp4'], voice: ['audio/ogg', 'audio/mp4', 'audio/aac', 'audio/mpeg'], file: null } };
  const conv = (bridge, extra = {}) => ({ id: 20, kind: 'direct', title: 'Kim Muster', peer: null, members: [], can: { send: true }, bridge, ...extra });
  const phMsg = (placeholder, text = null) => ({ id: 5, kind: 'text', text, senderId: null, via: 'bridge:whatsapp', bridge: { sender: { contactId: 1, name: 'Kim' }, placeholder } });

  it('features: bridge_media and bridge_new_chat only from the words', () => {
    const f = CS.features14({ features: { bridge_chats: true, bridge_media: true, bridge_new_chat: true } });
    assert.deepEqual([f.bridgeMedia, f.bridgeNewChat], [true, true]);
    assert.deepEqual([CS.features14(ME).bridgeMedia, CS.features14(ME).bridgeNewChat], [false, false]);
  });

  it('a chat takes files only when `supports` names them; the type from `mediaTypes`', () => {
    const old = conv({ ...MEDIA, supports: ['text', 'reply'], mediaTypes: undefined });
    assert.equal(CS.bridgeTakesFiles(old), false);
    assert.equal(CS.bridgeTakesFiles(conv(MEDIA)), true);
    assert.equal(CS.bridgeTakesFiles(direct()), false);
    assert.equal(CS.bridgeMediaRefusal(old, 'image', 'image/jpeg'), 'text_only');
    assert.equal(CS.bridgeMediaRefusal(conv(MEDIA), 'image', 'image/webp'), null);
    assert.equal(CS.bridgeMediaRefusal(conv(MEDIA), 'file', 'video/quicktime'), 'video');
    assert.equal(CS.bridgeMediaRefusal(conv(MEDIA), 'file', 'video/mp4'), null);
    assert.equal(CS.bridgeMediaRefusal(conv(MEDIA), 'file', 'application/zip'), null);
    assert.equal(CS.bridgeMediaRefusal(conv(MEDIA), 'voice', 'audio/webm'), 'voice');
    assert.equal(CS.bridgeMediaRefusal(direct(), 'image', 'image/gif'), null);
    assert.equal(CS.bridgeImageType(conv(MEDIA)), 'image/webp');
    assert.equal(CS.bridgeImageType(conv({ ...MEDIA, mediaTypes: { image: ['image/jpeg'] } })), 'image/jpeg');
    assert.equal(CS.mediaTypeText('video', conv(MEDIA), t), 'chat.bc.media_type.video(WhatsApp)');
  });

  it('the mic: only a recording type the service takes (Chromium mostly records WebM → no mic)', () => {
    const webmOnly = (m) => m.startsWith('audio/webm');
    const withMp4 = (m) => m.startsWith('audio/webm') || m === 'audio/mp4';
    assert.equal(CS.voiceMime(conv(MEDIA), webmOnly, []), null);
    assert.equal(CS.voiceMime(conv(MEDIA), withMp4, []), 'audio/mp4');
    assert.equal(CS.voiceMime(conv(MEDIA), withMp4, ['audio/webm']), null, 'the server must take it as well');
    assert.equal(CS.voiceMime(conv({ ...MEDIA, supports: ['text'] }), withMp4, []), null);
    assert.equal(CS.voiceMime(direct(), webmOnly, ['audio/webm']), 'audio/webm;codecs=opus', 'own chats as before');
  });

  it('placeholders: loading, failed with the reason, a location, and as in 1.14 without a state', () => {
    const c = conv(MEDIA);
    assert.equal(CS.placeholderText(phMsg({ kind: 'image', name: 'grill.jpg', state: 'loading' }), c, t), 'chat.bc.ph.image · grill.jpg – chat.bc.ph_loading');
    assert.equal(CS.placeholderText(phMsg({ kind: 'video', name: null, state: 'failed', reason: 'too_large' }), c, t), 'chat.bc.ph.video – chat.bc.ph_fail.too_large(WhatsApp)');
    assert.equal(CS.placeholderText(phMsg({ kind: 'file', name: 'x.exe', state: 'failed', reason: 'weird' }), c, t), 'chat.bc.ph.file · x.exe – chat.bc.ph_fail.other(WhatsApp)');
    assert.equal(CS.placeholderText(phMsg({ kind: 'image', name: null, state: null }), c, t), 'chat.bc.ph.image – chat.bc.ph_later(WhatsApp)');
    const loc = CS.placeholderOf(phMsg({ kind: 'location', name: null, state: null, geo: { lat: 50.1, lon: 7.2 } }, 'Grillplatz'));
    assert.deepEqual(loc.geo, { lat: 50.1, lon: 7.2 });
    assert.equal(CS.summary(phMsg({ kind: 'location', name: null, state: null, geo: { lat: 50.1, lon: 7.2 } }, 'Grillplatz'), c, ctx), 'chat.bc.ph.location: Grillplatz');
    assert.equal(CS.placeholderOf(phMsg({ kind: 'location', geo: { lat: 99, lon: 7 } })).geo, null);
    assert.equal(CS.placeholderOf(phMsg({ kind: 'file', state: 'failed', reason: 'infected' })).reason, 'infected');
  });

  it('a bridged contact’s picture: avatarMediaId (initials until it is there)', () => {
    assert.deepEqual(CS.avatarOf(conv(MEDIA, { avatarMediaId: 'a'.repeat(32) })).mediaId, 'a'.repeat(32));
    assert.ok(!CS.avatarOf(conv(MEDIA, { avatarMediaId: null })).mediaId);
    assert.equal(CS.avatarOf(conv(MEDIA, { avatarMediaId: null })).initials, 'KM');
    assert.equal(CS.avatarOf(conv(MEDIA, { title: null, avatarMediaId: 'b'.repeat(32) })).mediaId, 'b'.repeat(32));
  });

  it('the number of the dialog: +49 by default, checks, the way it is shown', () => {
    assert.deepEqual(CS.newChatNumber('0151 23456789'), { number: '+4915123456789', error: null });
    assert.deepEqual(CS.newChatNumber('151-2345 6789'), { number: '+4915123456789', error: null });
    assert.deepEqual(CS.newChatNumber('0664 1234567', '+43'), { number: '+436641234567', error: null });
    assert.deepEqual(CS.newChatNumber('+43 664 1234567'), { number: '+436641234567', error: null });
    assert.deepEqual(CS.newChatNumber('0043 664 1234567'), { number: '+436641234567', error: null });
    assert.equal(CS.newChatNumber('0151 234').error, 'invalid_mobile_de');
    assert.equal(CS.newChatNumber('030 12').error, 'invalid');
    assert.equal(CS.newChatNumber('0151 abc').error, 'invalid_chars');
    assert.equal(CS.newChatNumber('  ').error, 'empty');
    assert.equal(CS.formatNumber('+4915123456789'), '+49 151 23456789');
    assert.equal(CS.formatNumber('+12125550123'), '+1 212 5550123');
    assert.equal(CS.formatNumber('+4203601234567'), '+420 360 1234567');
  });

  it('which services offer „WhatsApp-Chat mit Nummer“ and the dialog’s first state', () => {
    const me = { features: { bridge_chats: true, bridge_new_chat: true } };
    const login = (state) => [{ id: 'l1', name: '+49', state, since: null }];
    const net = (extra) => ({ id: 'whatsapp', state: 'running', allowed: true, logins: login('connected'), newChat: null, ...extra });
    const list = (n) => CS.newChatServices({ available: true, networks: [n] }, me);
    assert.deepEqual(list(net()).map((x) => [x.id, x.name, x.mark, x.state]), [['whatsapp', 'WhatsApp', 'WA', 'input']]);
    assert.deepEqual(CS.newChatServices({ available: true, networks: [net()] }, { features: { bridge_chats: true } }), [], 'no word, no row');
    assert.deepEqual(list(net({ logins: [] })), [], 'never linked');
    assert.equal(list(net({ logins: login('logged_out') }))[0].state, 'loggedout');
    assert.equal(list(net({ state: 'unreachable' }))[0].state, 'unreach');
    assert.equal(list(net({ allowed: false }))[0].state, 'locked');
    assert.deepEqual(list(net({ newChat: { available: false, reason: 'child_new_chat_off', limit: null } })), [], 'the parents switched it off: no row');
    assert.equal(list(net({ newChat: { available: false, reason: 'child_locked', limit: null } }))[0].state, 'locked');
    assert.equal(list(net({ newChat: { available: true, reason: null, limit: { perHour: 10, left: 7, retryAfterS: 0 } } }))[0].limit.perHour, 10);
    assert.deepEqual(list({ ...net(), id: 'telegram' }), [], 'a service this version cannot link');
    assert.deepEqual(list({ ...net(), id: 'signal' }), [], 'Messenger 1.23: no chat by number over Signal');
    assert.deepEqual(CS.newChatServices({ available: false, networks: [net()] }, me), []);
  });

  it('refusals of resolve / chats → the dialog’s state', () => {
    const st = (r) => CS.newChatErrorState(r).state;
    assert.equal(st({ code: 'invalid_number' }), 'invalid');
    assert.deepEqual(CS.newChatErrorState({ code: 'rate_limited', retryAfterS: 840 }), { state: 'rate', retryAfterS: 840 });
    assert.equal(CS.newChatErrorState({ code: 'rate_limited' }).retryAfterS, 600);
    assert.equal(st({ code: 'bridge_unlinked', reason: 'logged_out' }), 'loggedout');
    assert.equal(st({ code: 'bridge_unlinked', reason: 'unlinked' }), 'unlinked');
    assert.equal(st({ code: 'bridge_locked' }), 'locked');
    assert.equal(st({ code: 'child_new_chat_off' }), 'locked');
    assert.equal(st({ code: 'bridge_unreachable' }), 'unreach');
    assert.equal(st({ code: 'feature_off' }), 'off');
    assert.equal(st({ code: 'not_found', reason: 'not_on_network' }), 'none');
    assert.equal(st(null), 'failed');
  });

  it('the dialog never stores or logs the number', () => {
    const view = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'chat-view.js'), 'utf8');
    const start = view.indexOf('function numberChatDialog(');
    const end = view.indexOf('async function addMembersDialog(');
    assert.ok(start > 0 && end > start);
    assert.doesNotMatch(view.slice(start, end), /localStorage|sessionStorage|console\.|indexedDB/);
  });
});

describe('chat-state: older history, the phone, „Brücke veraltet“ over a bridge (Messenger 1.17)', () => {
  const WA = { network: 'whatsapp', label: 'WhatsApp', state: 'ok', closed: false, supports: ['text', 'image'] };
  const conv = { id: 20, kind: 'direct', title: 'Kim Muster', peer: null, members: [], can: { send: true }, bridge: WA };
  const phMsg = (placeholder) => ({ id: 5, kind: 'text', text: null, senderId: null, via: 'bridge:whatsapp', bridge: { sender: { contactId: 1, name: 'Kim' }, placeholder } });
  const net = (extra = {}) => ({ id: 'whatsapp', state: 'running', allowed: true, lock: null, consent: true, outdated: false, clientOutdated: false, logins: [{ id: 'l1', name: '', state: 'connected', since: '2026-11-02T10:00:00.000Z' }], phone: { offline: false, days: null, leftDays: null }, ...extra });
  const NS = require('../src/renderer/notify-state');

  it('features: bridge_history only from the word', () => {
    assert.equal(CS.features14({ features: { bridge_chats: true, bridge_history: true } }).bridgeHistory, true);
    assert.equal(CS.features14(ME).bridgeHistory, false);
  });

  it('a file of the history: „… – älterer Verlauf“ (on_request); an older app reads the state as unknown', () => {
    assert.equal(CS.placeholderOf(phMsg({ kind: 'image', name: 'IMG-2041.jpg', state: 'on_request' })).state, 'on_request');
    assert.equal(CS.placeholderText(phMsg({ kind: 'image', name: 'IMG-2041.jpg', state: 'on_request' }), conv, t), 'chat.bc.ph.image · IMG-2041.jpg – chat.bc.ph_on_request');
    assert.equal(CS.placeholderText(phMsg({ kind: 'file', name: null, state: 'failed', reason: 'gone' }), conv, t), 'chat.bc.ph.file – chat.bc.ph_fail.gone(WhatsApp)');
    assert.equal(CS.placeholderOf(phMsg({ kind: 'image', state: 'later' })).state, null);
  });

  it('the phone warning under a linked service, not when signed out; leftDays 0 → „jederzeit“', () => {
    assert.equal(CS.linkedRow(net(), ctx).phone, null);
    assert.equal(CS.linkedRow(net({ phone: { offline: true, days: 12, leftDays: 2 } }), ctx).phone, 'chat.br.phone_offline(WhatsApp,12)');
    assert.equal(CS.linkedRow(net({ phone: { offline: true, days: 15, leftDays: 0 } }), ctx).phone, 'chat.br.phone_offline_now(WhatsApp,15)');
    assert.equal(CS.linkedRow(net({ phone: { offline: true, days: null, leftDays: null } }), ctx).phone, 'chat.br.phone_offline(WhatsApp,12)');
    const out = net({ phone: { offline: true, days: 14, leftDays: 0 }, logins: [{ id: 'l1', state: 'logged_out', since: null }] });
    assert.equal(CS.linkedRow(out, ctx).phone, null);
    assert.equal(CS.linkedRow(net({ phone: { offline: true, days: 13, leftDays: 1 } }), ctx).state, 'linked', 'the link still works');
  });

  it('„Brücke veraltet“ also when the service refuses the bridge (clientOutdated)', () => {
    assert.deepEqual(CS.linkedRow(net({ clientOutdated: true }), ctx).pill, { text: 'chat.br.pill_outdated', tone: 'warn' });
    assert.equal(CS.isOutdated(net({ clientOutdated: true })), true);
    assert.equal(CS.isOutdated(net({ outdated: true })), true);
    assert.equal(CS.isOutdated(net()), false);
  });

  it('the row „Älteren Verlauf laden“: choice, nights to come, switched off, none on an older server', () => {
    const h = CS.historyRow({ available: true, days: 30, default: 30, options: [0, 30, -1], pending: 0 }, t);
    assert.deepEqual(h, { title: 'chat.br.hist_title', sub: 'chat.br.hist_sub(chat.br.hist_days(30))', available: true, value: 30,
      options: [{ value: 0, label: 'chat.br.hist_off' }, { value: 30, label: 'chat.br.hist_days(30)' }, { value: -1, label: 'chat.br.hist_all' }] });
    assert.equal(CS.historyRow({ available: true, days: -1, options: [0, 30, -1], pending: 412 }, t).sub, 'chat.br.hist_sub(chat.br.hist_all) · chat.br.hist_pending(412)');
    const off = CS.historyRow({ available: false, days: 30, options: [0, 30, -1], pending: 9 }, t);
    assert.deepEqual([off.sub, off.options, off.available], ['chat.br.hist_admin_off', [], false]);
    assert.equal(CS.historyRow(null, t), null);
  });

  it('the push of „Verknüpfte Dienste“ opens them on the chats page', () => {
    assert.equal(CS.isBridgePush({ topic: 'plugin:gatecontrol-messenger:bridge', data: { deepLink: 'bridges', bridge: 'whatsapp' } }), true);
    assert.equal(CS.isBridgePush({ topic: 'plugin:gatecontrol-messenger:message', data: {} }), false);
    assert.equal(CS.isBridgePush(null), false);
    const context = { type: 'bridges', bridge: 'whatsapp' };
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-messenger', id: 40, context }, ['chats', 'inbox']), { page: 'chats', id: null, context });
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-messenger', id: 40, context }, ['inbox']), { page: 'inbox', id: 40 });
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-messenger', id: 41 }, ['chats', 'inbox']), { page: 'chats', id: null });
  });
});

describe('chat-state: „Neuer Chat“ with contacts (Messenger 1.18)', () => {
  const WA = { network: 'whatsapp', label: 'WhatsApp', state: 'ok', closed: false, supports: ['text'] };
  const conv = { id: 21, kind: 'direct', title: 'Sabine Wolf', peer: null, members: [], can: { send: true }, bridge: WA };

  it('features: bridge_contacts only from the word', () => {
    assert.equal(CS.features14({ features: { bridge_new_chat: true, bridge_contacts: true } }).bridgeContacts, true);
    assert.equal(CS.features14({ features: { bridge_new_chat: true } }).bridgeContacts, false);
  });

  it('the line under an address book contact, the kinds of numbers, the first name', () => {
    const one = { phones: [{ key: 'mobile', kind: 'mobile', number: '+49 151 23456780' }] };
    assert.equal(CS.contactPhonesSub(one, t), 'chat.ncc.kind_mobile · +49 151 23456780');
    assert.equal(CS.contactPhonesSub({ phones: [{}, {}, {}] }, t), 'chat.ncc.numbers(3)');
    assert.equal(CS.phoneKindText('work-2', t), 'chat.ncc.kind_work');
    assert.equal(CS.phoneKindText('fax', t), 'chat.ncc.kind_other');
    assert.equal(CS.firstName('  Sabine  Wolf'), 'Sabine');
    assert.equal(CS.firstName(null), '');
  });

  it('long sections: three rows, all while searching or opened', () => {
    const items = [1, 2, 3, 4, 5];
    assert.deepEqual(CS.contactsShown(items, '', false), [1, 2, 3]);
    assert.deepEqual(CS.contactsShown(items, ' ber ', false), items);
    assert.deepEqual(CS.contactsShown(items, '', true), items);
    assert.deepEqual(CS.contactsShown(null, '', false), []);
  });

  it('the number dialog of the footer takes its first state from the WhatsApp section', () => {
    const limit = { perHour: 10, left: 7, retryAfterS: 0 };
    assert.deepEqual(CS.contactsService({ whatsapp: { state: 'ok' }, limit }), { id: 'whatsapp', name: 'WhatsApp', mark: 'WA', state: 'input', limit });
    assert.equal(CS.contactsService({ whatsapp: { state: 'logged_out' } }).state, 'loggedout');
    assert.equal(CS.contactsService({ whatsapp: { state: 'unreachable' } }).state, 'unreach');
    assert.equal(CS.contactsService(null).limit, null);
  });

  it('refusals of a contact’s chat → its row (409 contact_expired: the list anew)', () => {
    const v = (r) => CS.contactChatError(r).view;
    for (const code of ['contact_expired', 'bridge_logged_out', 'bridge_unlinked']) assert.equal(v({ code }), 'reload', code);
    assert.equal(v({ code: 'not_found', reason: 'contact_gone' }), 'reload');
    assert.deepEqual(CS.contactChatError({ code: 'not_found', reason: 'not_on_network', remembered: true }), { view: 'none', remembered: true });
    assert.deepEqual(CS.contactChatError({ code: 'rate_limited', retryAfterS: 840, perHour: 10 }), { view: 'rate', retryAfterS: 840, perHour: 10 });
    assert.equal(CS.contactChatError({ code: 'rate_limited' }).retryAfterS, 3600);
    for (const code of ['bridge_unreachable', 'bridge_off', 'timeout', 'network']) assert.equal(v({ code }), 'unreach', code);
    assert.equal(v({ code: 'mail_missing' }), 'failed');
    assert.equal(v(null), 'failed');
  });

  it('the first line of a chat just started: by number, with a WhatsApp contact, from the address book', () => {
    assert.equal(CS.startedLine({ kind: 'contact', name: 'Lena Berger' }, conv, t), 'chat.nc.first_line_contact(WhatsApp,Lena Berger)');
    assert.equal(CS.startedLine({ kind: 'book', name: 'Sabine Wolf', number: '+49 151 23456780' }, conv, t), 'chat.nc.first_line_book(WhatsApp,Sabine Wolf,+49 151 23456780)');
    assert.equal(CS.startedLine({ kind: 'number', number: '+4915123456789', name: null }, conv, t), 'chat.nc.first_line(WhatsApp,+49 151 23456789,Sabine Wolf)');
    assert.equal(CS.startedLine(null, conv, t), '');
  });

  it('the contacts never go into storage or the log', () => {
    const view = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'chat-view.js'), 'utf8');
    const start = view.indexOf('function contactsPicker(');
    const end = view.indexOf('function numberChatDialog(');
    assert.ok(start > 0 && end > start);
    assert.doesNotMatch(view.slice(start, end), /localStorage|sessionStorage|console\.|indexedDB/);
  });
});

// Messenger 1.20 (Chats v2, Teil A): channels, groups where only admins write, format, links, link previews, the
// messengers' logos, the retry of a bridged file.
describe('chat-state – channels, format and links (Messenger 1.20)', () => {
  const chan = (extra = {}) => ({
    id: 40, kind: 'group', title: 'Sicherheit kompakt', members: [member(7, 'Marc')], muted: true, unread: 2,
    me: { lastReadId: 0, notify: 'none', mutedUntil: null },
    bridge: { network: 'whatsapp', label: 'WhatsApp', state: 'ok', closed: false, channel: true, readOnly: true, reactions: 'own', supports: ['text', 'reply', 'reaction'] },
    can: { send: false, sendReason: 'channel', react: true, pin: true },
    lastMessage: { id: 90, kind: 'text', text: 'Jetzt patchen', senderId: null, mine: false, createdAt: at(10, 0), bridge: { sender: null, channel: true } },
    ...extra,
  });
  const admins = () => ({ ...chan(), id: 41, title: 'Elternbeirat', muted: false, bridge: { ...chan().bridge, channel: false }, can: { send: false, sendReason: 'admins_only', react: true } });
  const post = (extra = {}) => ({ id: 91, kind: 'text', text: 'Hallo', senderId: null, mine: false, createdAt: new Date(NOW - 60000).toISOString(), bridge: { sender: null, channel: true, state: null }, reactions: [], ...extra });

  it('a channel: no „Name:“ in the list, „Kanal · WhatsApp“, read only, the entry’s line', () => {
    assert.equal(CS.isChannel(chan()), true);
    assert.equal(CS.isChannel(admins()), false);
    assert.equal(CS.isChannel(direct()), false);
    assert.equal(CS.preview(chan(), ctx).text, 'Jetzt patchen');
    assert.equal(CS.headSub(chan(), ctx).text, 'chat.ch.sub(WhatsApp)');
    assert.equal(CS.composerBlock(chan()), 'channel');
    assert.equal(CS.composerBlock(admins()), 'admins_only');
    // the bridge away: the bar says why, the composer the old way
    const down = { ...admins(), bridge: { ...admins().bridge, state: 'unreachable' } };
    assert.equal(CS.composerBlock(down), 'bridge');
    assert.equal(CS.bridgeBlock(chan()), null);
    assert.equal(CS.bridgeBlock(admins()), null);
    assert.equal(CS.bridgeBlock(down).key, 'state_unreachable');
    assert.equal(CS.channelEntryText({ count: 2, unread: 0 }, t), 'chat.ch.entryNone');
    assert.equal(CS.channelEntryText({ count: 2, unread: 1 }, t), 'chat.ch.entryOne');
    assert.equal(CS.channelEntryText({ count: 2, unread: 7 }, t), 'chat.ch.entryNew(7)');
    assert.equal(CS.channelEntryText({ count: 2, unread: 140 }, t), 'chat.ch.entryNew(99+)');
    assert.equal(CS.channelNetworks([chan(), chan({ id: 42 })]), 'WhatsApp');
    assert.deepEqual(CS.filterChannels([chan(), chan({ id: 42, title: 'Wetter', lastMessage: null })], 'wett', ctx).map((c) => c.id), [42]);
    assert.deepEqual(CS.filterChannels([chan()], 'patchen', ctx).map((c) => c.id), [40]);
    assert.equal(CS.senderName(post(), chan(), ctx), 'Sicherheit kompakt');
  });

  it('the menu: no answer, edit or delete for all in a channel / admins-only group — but a reaction while can.react', () => {
    const a = CS.messageActions(post(), chan(), ctx, NOW);
    assert.equal(a.reply, false);
    assert.equal(a.react, true);
    assert.equal(a.deleteAll, false);
    assert.equal(CS.messageActions(post(), admins(), ctx, NOW).react, true);
    // the bridge refused one: reacting in channels is off
    assert.equal(CS.messageActions(post(), chan({ can: { send: false, sendReason: 'channel', react: false } }), ctx, NOW).react, false);
    assert.equal(CS.messageActions(post({ mine: true }), chan(), ctx, NOW).react, false);
    // a GateControl chat as before
    assert.equal(CS.messageActions({ ...post(), bridge: null, senderId: 8 }, direct(), ctx, NOW).react, true);
    assert.equal(CS.hasOwnReaction(post({ reactions: [{ emoji: '👍', count: 1, userIds: [7] }] }), ctx), true);
    assert.equal(CS.hasOwnReaction(post({ reactions: [{ emoji: '👍', count: 3, userIds: [8] }] }), ctx), false);
    assert.equal(CS.errorText({ code: 'bridge_read_only', reason: 'reactions_off' }, t), 'chat.error.reactions_off');
  });

  it('linkify: http(s) and www. addresses, trailing punctuation is text, no other schemes', () => {
    assert.deepEqual(CS.linkify('Siehe https://ex.example/a?b=1. Und www.test.example/x), oder?'), [
      { text: 'Siehe ' }, { text: 'https://ex.example/a?b=1', href: 'https://ex.example/a?b=1' }, { text: '. Und ' },
      { text: 'www.test.example/x', href: 'https://www.test.example/x' }, { text: '), oder?' },
    ]);
    assert.deepEqual(CS.linkify('javascript:alert(1) file:///c:/x ftp://a.example'), [{ text: 'javascript:alert(1) file:///c:/x ftp://a.example' }]);
    assert.deepEqual(CS.linkify('„https://ex.example/“'), [{ text: '„' }, { text: 'https://ex.example/', href: 'https://ex.example/' }, { text: '“' }]);
    assert.equal(CS.safeHref('https://user:pw@ex.example/'), null);
    assert.equal(CS.safeHref('http://ex.example'), 'http://ex.example/');
    assert.equal(CS.safeHref('data:text/html,x'), null);
    assert.deepEqual(CS.linkify(''), []);
  });

  it('richText: marks (UTF-16, nested), link marks only http(s), unknown or outside marks ignored, linkify inside', () => {
    const text = 'Neu 👍 fett und kursiv – mehr: https://ex.example/n';
    const i = text.indexOf('fett');
    const segs = CS.richText(text, [
      { type: 'bold', start: i, end: i + 15 }, { type: 'italic', start: i + 9, end: i + 15 },
      { type: 'underline', start: 0, end: 3 }, { type: 'bold', start: 0, end: 999 }, { type: 'link', start: 0, end: 3, url: 'javascript:x' },
    ]);
    assert.equal(segs.map((x) => x.text).join(''), text);
    const by = (s) => segs.find((x) => x.text === s);
    assert.equal(by('fett und ').bold, true);
    assert.equal(by('fett und ').italic, false);
    assert.deepEqual([by('kursiv').bold, by('kursiv').italic], [true, true]);
    assert.equal(segs[0].href, null);
    assert.equal(by('https://ex.example/n').href, 'https://ex.example/n');
    const linked = CS.richText('Hier lesen', [{ type: 'link', start: 0, end: 4, url: 'https://ex.example/l' }, { type: 'code', start: 5, end: 10 }]);
    assert.deepEqual(linked.map((x) => [x.text, x.href, x.code]), [['Hier', 'https://ex.example/l', false], [' ', null, false], ['lesen', null, true]]);
    assert.deepEqual(CS.richText('<b>nicht fett</b>', null).map((x) => [x.text, x.bold]), [['<b>nicht fett</b>', false]]);
    assert.deepEqual(CS.richText('Zeile 1\n\nZeile 2', []).map((x) => x.text), ['Zeile 1\n\nZeile 2']);
  });

  it('the link preview: http(s) only, its picture loading / there / failed', () => {
    const m = post({ preview: { url: 'https://sk.example/news', title: 'Lücke', description: 'Text', site: null, image: { mediaId: '0123456789abcdef0123456789abcdef', url: null, mime: 'image/jpeg', w: 640, h: 360, state: null } } });
    assert.deepEqual(CS.linkPreview(m), { href: 'https://sk.example/news', title: 'Lücke', description: 'Text', site: 'sk.example', image: { mediaId: '0123456789abcdef0123456789abcdef', w: 640, h: 360, loading: false } });
    assert.equal(CS.linkPreview(post({ preview: { ...m.preview, image: { mediaId: null, w: 10, h: 5, state: 'loading' } } })).image.loading, true);
    assert.equal(CS.linkPreview(post({ preview: { ...m.preview, image: { mediaId: null, state: 'failed' } } })).image, null);
    assert.equal(CS.linkPreview(post({ preview: { ...m.preview, url: 'javascript:alert(1)' } })), null);
    assert.equal(CS.linkPreview(post({ kind: 'image', preview: m.preview })), null);
    assert.equal(CS.linkPreview(post()), null);
  });

  it('logos instead of „WA“: WhatsApp, GateControl, anything else a speech bubble', () => {
    assert.equal(CS.netGlyph('whatsapp').known, true);
    assert.equal(CS.netGlyph('gatecontrol').known, true);
    const o = CS.netGlyph('telegram');
    assert.equal(o.known, false);
    assert.equal(o.paths.length, 1);
    assert.equal(CS.netGlyph('__proto__').known, false);
  });

  it('a bridged file that failed with retry: „Erneut versuchen“', () => {
    const ph = (p) => CS.placeholderOf({ id: 1, bridge: { placeholder: p } });
    assert.equal(ph({ kind: 'image', state: 'failed', reason: 'unavailable', retry: true }).retry, true);
    assert.equal(ph({ kind: 'image', state: 'failed', reason: 'unavailable' }).retry, false);
    assert.equal(ph({ kind: 'image', state: 'loading', retry: true }).retry, false);
  });

  it('the view builds texts from elements only (no innerHTML) and opens links over the shell', () => {
    const view = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'chat-view.js'), 'utf8');
    assert.doesNotMatch(view, /\.innerHTML\s*=|insertAdjacentHTML|outerHTML\s*=/);
    const start = view.indexOf('function openLink(');
    assert.ok(start > 0);
    assert.match(view.slice(start, start + 400), /CS\.safeHref\(href\)[\s\S]*shell\.openExternal\(u\)/);
  });
});

describe('chat-state: persons (Messenger 1.21, Chats v2 Teil B)', () => {
  const WA_BRIDGE = { network: 'whatsapp', label: 'WhatsApp', state: 'ok', supports: ['text', 'reply', 'reaction', 'edit', 'delete'] };
  const person = (over = {}) => ({
    id: 12, kind: 'direct', title: 'Anna', avatarUrl: '/avatars/a.webp', avatarMediaId: null, unread: 2, readUpTo: 4701, deliveredUpTo: 4702, bridge: null,
    peer: { userId: 8, name: 'Anna', initials: 'AN', colorHex: '#F97316' }, can: { send: true, pin: true }, me: { lastReadId: 4700 },
    person: {
      id: 1, name: 'Anna', nameFrom: 'account', userId: 8, conversationId: 12, names: ['Anna', 'Schatzimausi 💕'],
      ways: [
        { way: 'gatecontrol', label: 'GateControl', conversationId: 12, title: 'Anna', bridge: null, can: { send: true, react: true } },
        { way: 'whatsapp', label: 'WhatsApp', conversationId: 13, title: 'Schatzimausi 💕', bridge: WA_BRIDGE, can: { send: true, react: true } },
      ],
      reply: { way: 'whatsapp', label: 'WhatsApp', conversationId: 13 },
    },
    ...over,
  });

  it('a person, its ways, the line under its name, the way of an answer', () => {
    const c = person();
    assert.equal(CS.isPerson(c), true);
    assert.equal(CS.isPerson({ id: 1, person: { id: 1, ways: [] } }), false);
    assert.deepEqual(CS.personWays(c), [{ way: 'gatecontrol', label: 'GateControl' }, { way: 'whatsapp', label: 'WhatsApp' }]);
    assert.equal(CS.personSub(c), 'GateControl · WhatsApp');
    assert.equal(CS.replyWay(c).conversationId, 13);
    assert.equal(CS.bridgeOf(c), null, 'no service sign at the picture');
    assert.deepEqual(CS.headSub(c, ctx), { text: 'GateControl · WhatsApp', typing: false, person: true });
    assert.equal(CS.wayOf({ way: 'whatsapp' }), 'whatsapp');
    assert.equal(CS.wayOf({ way: 'x y' }), null);
    assert.equal(CS.wayLabel('gatecontrol'), 'GateControl');
  });

  it('the composer is the way the server picks: WhatsApp — no location there; back to GateControl', () => {
    const c = person();
    const s = CS.sendConv(c);
    assert.equal(s.id, 12, 'the entry’s id (the core sends through persons/:id)');
    assert.equal(CS.bridgeOf(s).network, 'whatsapp');
    assert.equal(CS.composerBlock(c), null);
    const gc = CS.sendConv(person({ person: { ...person().person, reply: { way: 'gatecontrol', conversationId: 12 } } }));
    assert.equal(CS.bridgeOf(gc), null);
    const down = person();
    down.person.ways[1].can = { send: false };
    assert.equal(CS.composerBlock(down), 'bridge');
  });

  it('each message in its way: the ticks of GateControl, the state of the bridge; what may be done with it', () => {
    const c = person();
    const gcMsg = { id: 4701, conversationId: 12, way: 'gatecontrol', mine: true, kind: 'text', text: 'Hi', createdAt: at(10, 0) };
    const waMsg = { id: 4710, conversationId: 13, way: 'whatsapp', mine: true, kind: 'text', text: 'Hi', createdAt: at(10, 5), status: 'delivered', bridge: { state: 'sent' } };
    assert.equal(CS.status(gcMsg, c), 'read');
    assert.equal(CS.status(waMsg, c), 'delivered');
    assert.equal(CS.msgConv(c, waMsg).bridge.network, 'whatsapp');
    assert.equal(CS.msgConv(c, gcMsg).bridge, null);
    // a message written in WhatsApp's own app cannot be edited here
    const remote = { ...waMsg, bridge: { state: 'sent', remote: true }, createdAt: new Date(NOW - 60000).toISOString() };
    assert.equal(CS.messageActions(remote, c, ctx, NOW).edit, false);
    assert.equal(CS.messageActions({ ...gcMsg, createdAt: new Date(NOW - 60000).toISOString() }, c, ctx, NOW).edit, true);
    // no unread line by id in a person's history (its ways are mixed by time)
    const tl = CS.timeline([{ ...gcMsg, mine: false, senderId: 8 }], [], c, ctx, { unreadFrom: 0, now: NOW });
    assert.equal(tl.some((x) => x.type === 'unread'), false);
  });

  it('the list: found by every name, the chips „Nur GateControl“ / „WhatsApp“ count each way, a list with any way’s id', () => {
    const c = person();
    const plain = { id: 30, kind: 'direct', title: 'Kim', bridge: WA_BRIDGE, lastMessage: null };
    assert.deepEqual(CS.filterConversations([c, plain], 'schatz', ctx).map((x) => x.id), [12]);
    assert.deepEqual(CS.listFilter([c, plain], { filter: 'gc' }).map((x) => x.id), [12]);
    assert.deepEqual(CS.listFilter([c, plain], { filter: 'net:whatsapp' }).map((x) => x.id), [12, 30]);
    assert.deepEqual(CS.listFilter([c, plain], { filter: 'list:a', lists: [{ id: 'a', conversationIds: [13] }] }).map((x) => x.id), [12]);
    assert.deepEqual(CS.bridgeNetworks([c]), [{ id: 'whatsapp', label: 'WhatsApp' }]);
    assert.equal(CS.typingText({ ...c, typingContacts: [{ name: 'S' }] }, ctx), 'chat.typing');
    const a = CS.avatarOf(c);
    assert.equal(a.kind, 'person');
    assert.equal(a.initials, 'AN');
    assert.equal(a.avatarUrl, '/avatars/a.webp');
  });

  it('the source chips, the name choice, a merge by hand', () => {
    const c = person();
    assert.deepEqual(CS.sourceChips(c, t).map((x) => x.way), [null, 'gatecontrol', 'whatsapp']);
    assert.deepEqual(CS.sourceChips({ id: 1 }, t), []);
    assert.deepEqual(CS.personNameOptions(c), [{ value: 'account', label: 'Anna' }, { value: '13', label: 'Schatzimausi 💕' }]);
    assert.equal(CS.personNameValue(c), 'account');
    assert.equal(CS.personNameValue(person({ person: { ...person().person, nameFrom: 13 } })), '13');
    const wa = { id: 40, kind: 'direct', title: 'Schatz', bridge: WA_BRIDGE, peer: null };
    assert.deepEqual(CS.mergeNameOptions(wa, { account: { userId: 8, name: 'Anna' } }), [{ value: 'account', label: 'Anna' }, { value: 40, label: 'Schatz' }]);
    assert.deepEqual(CS.mergeRequest(wa, { account: { userId: 8 } }, 'account'), { conversationIds: [40], userId: 8, name: 'account' });
    assert.deepEqual(CS.mergeRequest(c, { chat: { conversationId: 50, title: 'Anna 2' } }, 50), { conversationIds: [12, 50], name: 50 });
    const me = { features: { chat_people: true } };
    assert.equal(CS.canMergeByHand(wa, me), true);
    assert.equal(CS.canMergeByHand({ ...wa, kind: 'group' }, me), false);
    assert.equal(CS.canMergeByHand({ ...wa, bridge: { ...WA_BRIDGE, channel: true } }, me), false);
    assert.equal(CS.canMergeByHand(c, me), false, 'a person merges in „Wege von …“');
    assert.equal(CS.canMergeByHand(wa, { features: {} }), false);
    const f = CS.filterCandidates({ accounts: [{ userId: 8, name: 'Anna' }, { userId: 9, name: 'Lena' }], chats: [{ conversationId: 3, title: 'Lenas Handy' }] }, 'len');
    assert.deepEqual([f.accounts.map((x) => x.userId), f.chats.map((x) => x.conversationId)], [[9], [3]]);
  });
});

describe('chat-state: Signal (Messenger 1.23, Brücken Stufe 7a)', () => {
  const sg = (extra = {}) => ({ id: 'signal', state: 'running', allowed: true, lock: null, consent: true, outdated: false, logins: [], flows: ['qr'], history: { maxDays: 30, phoneConfirms: true }, ...extra });
  const sgChat = (extra = {}) => ({ id: 31, kind: 'direct', title: 'Kim Muster', members: [{ userId: 7 }], bridge: { network: 'signal', label: 'Signal', state: null, closed: false }, ...extra });

  it('name, mark, logo with its ring; the ways in (QR code only), the steps beside the code', () => {
    assert.equal(CS.bridgeName('signal'), 'Signal');
    assert.equal(CS.bridgeMark('signal'), 'SG');
    const g = CS.netGlyph('signal');
    assert.equal(g.known, true);
    assert.equal(g.ring, true);
    assert.equal(CS.netGlyph('whatsapp').ring, false);
    assert.deepEqual(CS.linkFlows(sg()), ['qr']);
    assert.deepEqual(CS.linkFlows({ id: 'whatsapp' }), ['phone', 'qr'], 'an older plugin names no flows');
    assert.deepEqual(CS.linkFlows(sg({ flows: ['sms'] })), ['phone', 'qr']);
    assert.deepEqual(CS.qrSteps('signal'), ['chat.br.qr_step1_signal', 'chat.br.qr_step2_signal', 'chat.br.qr_step3_signal']);
    assert.deepEqual(CS.qrSteps('whatsapp'), ['chat.br.qr_step1_whatsapp', 'chat.br.qr_step2_whatsapp']);
    assert.deepEqual(CS.LINK_NOTES.signal, ['unofficial', 'phone', 'e2e', 'safety']);
  });

  it('the history: „Verlauf: 30 Tage“ behind the linked row, „nur beim Verknüpfen“ under „Älteren Verlauf laden“', () => {
    const linked = sg({ logins: [{ id: 'aci', name: '', state: 'connected', since: '2026-11-16T08:00:00.000Z' }] });
    const h = { available: true, days: 30, default: 30, options: [0, 30, -1], pending: 0 };
    assert.equal(CS.linkedRow(linked, { ...ctx, history: h }).sub, 'chat.br.sub_linked_since(16.11.2026) · chat.br.hist_line(30)');
    assert.equal(CS.linkedRow(linked, { ...ctx, history: { ...h, pending: 40 } }).sub, 'chat.br.sub_linked_since(16.11.2026) · chat.br.hist_line_pending(30)');
    assert.equal(CS.linkedRow(linked, { ...ctx, history: { ...h, days: 0 } }).sub, 'chat.br.sub_linked_since(16.11.2026)');
    assert.equal(CS.linkedRow(linked, ctx).sub, 'chat.br.sub_linked_since(16.11.2026)', 'no history row: nothing said');
    assert.match(CS.historyRow(h, t, [sg()]).sub, /chat\.br\.hist_once\(Signal,30\)$/);
    assert.doesNotMatch(CS.historyRow(h, t, [{ id: 'whatsapp' }]).sub, /hist_once/);
    assert.doesNotMatch(CS.historyRow({ ...h, available: false }, t, [sg()]).sub, /hist_once/);
  });

  it('chats: a view-once message, a timer changed in Signal', () => {
    const c = sgChat();
    const ph = { id: 5, kind: 'text', senderId: null, text: '', bridge: { placeholder: { kind: 'view_once' } } };
    assert.equal(CS.placeholderOf(ph).kind, 'view_once');
    assert.equal(CS.placeholderText(ph, c, t), 'chat.bc.ph.view_once(Signal)');
    const sys = (system) => ({ kind: 'system', system });
    assert.equal(CS.systemText(sys({ event: 'disappearing', by: null, seconds: 28800, network: 'signal' }), c, ctx), 'chat.sys.disOnNet(Signal,chat.dis.hours(8))');
    assert.equal(CS.systemText(sys({ event: 'disappearing', by: null, seconds: 0, network: 'signal' }), c, ctx), 'chat.sys.disOffNet(Signal)');
    assert.equal(CS.systemText(sys({ event: 'disappearing', by: null, seconds: 604800 }), c, ctx), 'chat.sys.disOn(GateControl,[chat.dis.604800])');
  });
});
