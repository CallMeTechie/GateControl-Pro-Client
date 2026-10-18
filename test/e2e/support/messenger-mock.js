'use strict';

/**
 * The Messenger plugin for the e2e mock server (gatecontrol-plugins
 * plugins/gatecontrol-messenger README "App-API"): GET /api/v1/client/plugins,
 * the chat API below …/plugins/gatecontrol-messenger/api/, raw media upload and
 * download, /avatars/…. In-memory, one account (Marc, id 7) talking to Anna (8)
 * and Lena (9). Events for the push stream go through `emit(type, data)`
 * (mock-server writes them as `event: plugin`). Messenger 1.1 API (around,
 * serverTime, readUpTo in `read`); `features` as `GET me` answers them (1.3.0:
 * video_meta / file_thumbs: true enable video meta and file previews).
 */

const crypto = require('crypto');

const PLUGIN = 'gatecontrol-messenger';
const ME = 7;
const iso = (ms) => new Date(ms).toISOString();

function createMessenger({ emit = () => {}, features = null } = {}) {
  const users = [
    { id: 7, name: 'Marc', initials: 'MA', colorHex: '#2FBF71', avatarUrl: null },
    { id: 8, name: 'Anna', initials: 'AN', colorHex: '#F97316', avatarUrl: null },
    { id: 9, name: 'Lena', initials: 'LE', colorHex: '#F2B91B', avatarUrl: null },
  ];
  const convs = new Map();
  const msgs = new Map();
  const media = new Map();
  const log = { sent: [], reads: [], actives: [], typings: [], uploads: [], reactions: [], around: [], mediaLists: [] };
  let nextConv = 12;
  let nextMsg = 4700;

  const person = (id) => {
    const u = users.find((x) => x.id === id);
    return u ? { userId: u.id, name: u.name, avatarUrl: u.avatarUrl, initials: u.initials, colorHex: u.colorHex, color: 'green', gone: false }
      : { userId: id, name: null, avatarUrl: null, initials: null, colorHex: null, color: null, gone: true };
  };

  function addConv({ kind = 'direct', members = [ME, 8], title = null } = {}) {
    const id = nextConv++;
    convs.set(id, { id, kind, title, managedBy: null, members: members.map((u) => ({ id: u, role: u === ME ? 'admin' : 'member', lastRead: 0, lastDelivered: 0 })), createdAt: Date.now(), updatedAt: Date.now() });
    msgs.set(id, []);
    return id;
  }

  function addMsg(convId, { senderId = 8, text = 'Hallo', kind = 'text', clientId = null, mediaId = null, meta = null, replyTo = null, location = null, thumbMediaId = null, video = null, system = null } = {}) {
    const m = { id: nextMsg++, conversationId: convId, senderId, clientId, kind, text, mediaId, meta, replyTo, location, thumbMediaId, video, system, createdAt: Date.now(), editedAt: null, deleted: false, reactions: [] };
    msgs.get(convId).push(m);
    const c = convs.get(convId);
    c.updatedAt = Date.now();
    if (senderId === ME) { const mb = c.members.find((x) => x.id === ME); mb.lastRead = m.id; mb.lastDelivered = m.id; }
    return m;
  }

  function receipts(c) {
    const others = c.members.filter((x) => x.id !== ME);
    return {
      readUpTo: others.length ? Math.min(...others.map((x) => x.lastRead)) : null,
      deliveredUpTo: others.length ? Math.min(...others.map((x) => x.lastDelivered)) : null,
      receipts: others.map((x) => ({ userId: x.id, lastReadId: x.lastRead, lastDeliveredId: x.lastDelivered })),
    };
  }

  function msgView(m) {
    const c = convs.get(m.conversationId);
    const r = receipts(c);
    const f = m.mediaId ? media.get(m.mediaId) : null;
    const q = m.replyTo ? msgs.get(m.conversationId).find((x) => x.id === m.replyTo) : null;
    return {
      id: m.id, conversationId: m.conversationId, senderId: m.senderId, clientId: m.clientId, kind: m.kind, via: null, mine: m.senderId === ME,
      createdAt: iso(m.createdAt), editedAt: m.editedAt ? iso(m.editedAt) : null, deletedAt: null, expiresAt: null, deleted: m.deleted, undecryptable: false,
      text: m.deleted ? null : m.text,
      replyTo: q ? { id: q.id, senderId: q.senderId, kind: q.kind, text: q.text, deleted: q.deleted, missing: false } : null,
      media: f && !m.deleted ? { id: m.mediaId, mime: f.mime, bytes: f.data.length, url: null, thumbId: m.thumbMediaId || null, thumbUrl: null } : null,
      ...(m.video && !m.deleted ? { video: m.video } : {}),
      meta: m.deleted ? null : m.meta, location: m.deleted ? null : (m.location || null), system: m.system || null, reactions: m.deleted ? [] : m.reactions,
      status: m.senderId === ME ? (m.id <= r.readUpTo ? 'read' : m.id <= r.deliveredUpTo ? 'delivered' : 'sent') : null,
    };
  }

  function convView(c) {
    const list = msgs.get(c.id).filter((m) => !m.hidden);
    const mine = c.members.find((x) => x.id === ME);
    const others = c.members.filter((x) => x.id !== ME);
    const last = list[list.length - 1] || null;
    const peer = c.kind === 'direct' ? person(others[0] && others[0].id) : null;
    return {
      id: c.id, kind: c.kind, title: c.kind === 'direct' ? (peer && peer.name) : c.title, peer, avatarUrl: null, avatarMediaId: null,
      managedBy: c.managedBy || null, readonly: false, disappearingS: 0, createdBy: ME, createdAt: iso(c.createdAt), updatedAt: iso(c.updatedAt),
      lastMessageId: last ? last.id : null,
      members: c.members.map((x) => ({ ...person(x.id), role: x.role, joinedAt: iso(c.createdAt) })),
      me: { role: mine.role, mutedUntil: null, notify: 'all', lastReadId: mine.lastRead, lastDeliveredId: mine.lastDelivered },
      muted: false,
      unread: list.filter((m) => m.senderId !== ME && m.id > mine.lastRead && !m.deleted).length,
      lastMessage: last ? msgView(last) : null,
      typing: [],
      ...receipts(c),
      can: { send: true, editInfo: c.kind === 'group' && !c.managedBy, manageMembers: c.kind === 'group' && !c.managedBy, leave: c.kind === 'group' && !c.managedBy, setDisappearing: true },
    };
  }

  /** Answers a request below /api/v1/client/ (route without that prefix) or /avatars/; false when not ours. */
  function handle({ method, route, query, raw, headers }, json, send) {
    if (route === 'plugins') return json(200, { ok: true, plugins: [{ id: PLUGIN, name: 'Messenger', version: '1.0.0', tab: { label: 'Chats', icon: 'M0 0' } }] }), true;
    const mediaBase = `plugins/${PLUGIN}/media`;
    if (route === mediaBase && method === 'PUT') {
      const mime = String(headers['content-type'] || '');
      if (!/^(image|audio|video)\/|^application\/pdf$/.test(mime)) return json(415, { ok: false, code: 'unsupported_type' }), true;
      const mediaId = crypto.randomBytes(16).toString('hex');
      media.set(mediaId, { mime, data: raw });
      log.uploads.push({ mediaId, mime, bytes: raw.length });
      return json(200, { ok: true, mediaId, mime, bytes: raw.length }), true;
    }
    if (route.startsWith(`${mediaBase}/`) && method === 'GET') {
      const f = media.get(route.slice(mediaBase.length + 1));
      if (!f) return json(404, { ok: false, code: 'not_found' }), true;
      return send(200, f.mime, f.data), true;
    }
    const apiBase = `plugins/${PLUGIN}/api/`;
    if (!route.startsWith(apiBase)) return false;
    let body = {};
    try { body = raw.length ? JSON.parse(raw.toString('utf8')) : {}; } catch { body = {}; }
    const [a, b, c] = route.slice(apiBase.length).split('/');

    if (a === 'me') {
      return json(200, {
        ok: true, user: { id: ME, name: 'Marc', avatarUrl: null, initials: 'MA', colorHex: '#2FBF71' }, prefs: { readReceipts: true, typing: true, preview: true },
        license: { licensed: true, state: 'active', expiresAt: null },
        features: api.features || { direct: true, groups: true, voice: true, files: true, location: true, reactions: true, edit: true, search: true, disappearing: true, bridges: false, e2e: false },
        limits: { maxBytes: 25 * 1024 * 1024, types: ['image/webp', 'image/jpeg', 'image/png', 'audio/ogg', 'audio/webm', 'audio/mp4', 'video/webm', 'video/mp4', 'application/pdf'], quotaFull: false, editWindowS: 900, maxVoiceS: 300, textMax: 4000, thumbMaxBytes: 65536, imageMaxSide: 2048, groupMax: 256, titleMax: 80, pageMax: 100, typingS: 6, typingEveryS: 3, activeS: 30, disappearingS: [0, 86400, 604800, 2592000], retentionDays: 0 },
        serverTime: iso(Date.now()),
      }), true;
    }
    if (a === 'prefs') return json(200, { ok: true, prefs: { readReceipts: true, typing: true, preview: true, ...body } }), true;
    if (a === 'people') return json(200, { ok: true, people: users.filter((x) => x.id !== ME).map((x) => ({ id: x.id, name: x.name, avatarUrl: null, initials: x.initials, colorHex: x.colorHex, color: 'green' })) }), true;
    if (a === 'conversations' && !b && method === 'GET') {
      const since = query.since ? Date.parse(query.since) : null;
      return json(200, { ok: true, conversations: [...convs.values()].filter((x) => !since || x.updatedAt >= since).map(convView), removed: [], serverTime: iso(Date.now()) }), true;
    }
    if (a === 'conversations' && !b && method === 'POST') {
      if (body.kind === 'direct') {
        const ex = [...convs.values()].find((x) => x.kind === 'direct' && x.members.some((y) => y.id === body.userIds[0]));
        if (ex) return json(200, { ok: true, conversation: convView(ex), created: false }), true;
      }
      const id = addConv({ kind: body.kind, members: [ME, ...body.userIds], title: body.title || null });
      return json(200, { ok: true, conversation: convView(convs.get(id)), created: true }), true;
    }
    if (a === 'conversations' && b) {
      const conv = convs.get(Number(b));
      if (!conv) return json(404, { ok: false, code: 'not_found' }), true;
      const list = msgs.get(conv.id);
      if (!c && method === 'GET') return json(200, { ok: true, conversation: convView(conv) }), true;
      if (!c && method === 'PATCH') {
        if (body.title) conv.title = body.title;
        conv.updatedAt = Date.now();
        return json(200, { ok: true, conversation: convView(conv), left: false }), true;
      }
      if (c === 'messages' && method === 'GET') {
        const vis = list.filter((x) => !x.hidden);
        const limit = Number(query.limit) || 50;
        let out;
        let hasMore = false;
        const extra = { serverTime: iso(Date.now()) };
        if (query.before) { const o = vis.filter((x) => x.id < Number(query.before)); out = o.slice(-limit); hasMore = o.length > limit; } else if (query.after) { const n = vis.filter((x) => x.id > Number(query.after)); out = n.slice(0, limit); hasMore = n.length > limit; } else if (query.around) {
          const at = Number(query.around);
          log.around.push({ conversationId: conv.id, around: at });
          const older = vis.filter((x) => x.id < at);
          const before = older.slice(-Math.floor(limit / 2));
          const rest = vis.filter((x) => x.id >= at);
          const after = rest.slice(0, limit - before.length);
          out = before.concat(after);
          extra.hasMoreBefore = older.length > before.length;
          extra.hasMoreAfter = rest.length > after.length;
          hasMore = extra.hasMoreBefore || extra.hasMoreAfter;
        } else if (query.changedSince) { out = []; } else { out = vis.slice(-limit); hasMore = vis.length > limit; }
        return json(200, { ok: true, messages: out.map(msgView), hasMore, ...receipts(conv), ...extra }), true;
      }
      if (c === 'messages' && method === 'POST') {
        const dup = list.find((x) => x.clientId === body.clientId && x.senderId === ME);
        if (dup) return json(200, { ok: true, message: msgView(dup), duplicate: true }), true;
        if ((body.mediaId && !media.has(body.mediaId)) || (body.thumbMediaId && !media.has(body.thumbMediaId))) return json(409, { ok: false, code: 'media_invalid' }), true;
        const m = addMsg(conv.id, { senderId: ME, text: body.text || null, kind: body.kind || 'text', clientId: body.clientId, mediaId: body.mediaId || null, meta: body.meta || null, replyTo: body.replyTo || null, location: body.location || null, thumbMediaId: body.thumbMediaId || null, video: body.video || null });
        log.sent.push(body);
        emit('message.new', { conversationId: conv.id, messageId: m.id, senderId: ME, clientId: m.clientId, kind: m.kind, createdAt: iso(m.createdAt) });
        return json(200, { ok: true, message: msgView(m), duplicate: false }), true;
      }
      if (c === 'read') {
        const mb = conv.members.find((x) => x.id === ME);
        mb.lastRead = Math.max(mb.lastRead, Number(body.upTo) || 0);
        log.reads.push({ conversationId: conv.id, upTo: body.upTo });
        return json(200, { ok: true, lastReadId: mb.lastRead, unread: convView(conv).unread }), true;
      }
      if (c === 'typing') { log.typings.push({ conversationId: conv.id, body }); return json(200, { ok: true, until: body.stop ? null : iso(Date.now() + 6000) }), true; }
      if (c === 'active') { log.actives.push({ conversationId: conv.id, body }); return json(200, { ok: true, until: iso(Date.now() + 30000) }), true; }
      if (c === 'search') return json(200, { ok: true, results: list.filter((x) => (x.text || '').toLowerCase().includes(String(query.q || '').toLowerCase())).reverse().map(msgView), scanned: list.length, truncated: false }), true;
      if (c === 'media') {
        log.mediaLists.push({ conversationId: conv.id, kind: query.kind });
        const isVideo = (x) => /^video\//.test((media.get(x.mediaId) || {}).mime || '');
        const all = list.filter((x) => x.mediaId && !x.deleted && !x.hidden);
        const kinds = { image: (x) => x.kind === 'image', voice: (x) => x.kind === 'voice', file: (x) => x.kind === 'file' && !isVideo(x), video: (x) => x.kind === 'file' && isVideo(x) };
        const counts = { image: all.filter(kinds.image).length, voice: all.filter(kinds.voice).length, file: all.filter(kinds.file).length };
        if (api.features) counts.video = all.filter(kinds.video).length;
        const items = all.filter(kinds[query.kind] || (() => true)).reverse().slice(0, Number(query.limit) || 30);
        return json(200, { ok: true, items: items.map(msgView), counts, hasMore: false }), true;
      }
    }
    if (a === 'messages' && b) {
      let m = null;
      for (const l of msgs.values()) m = l.find((x) => x.id === Number(b)) || m;
      if (!m) return json(404, { ok: false, code: 'not_found' }), true;
      if (c === 'reaction') {
        m.reactions = body.emoji ? [{ emoji: body.emoji, count: 1, userIds: [ME] }] : [];
        log.reactions.push({ id: m.id, emoji: body.emoji });
        return json(200, { ok: true, reactions: m.reactions }), true;
      }
      if (!c && method === 'PATCH') { m.text = body.text; m.editedAt = Date.now(); return json(200, { ok: true, message: msgView(m) }), true; }
      if (!c && method === 'DELETE') {
        if (query.for === 'all') { m.deleted = true; return json(200, { ok: true, forAll: true, message: msgView(m) }), true; }
        m.hidden = true;
        return json(200, { ok: true, forAll: false, message: null }), true;
      }
    }
    return json(404, { ok: false, code: 'not_found' }), true;
  }

  const api = {
    PLUGIN,
    ME,
    log,
    /** `GET me` features object (null: the 1.0 … 1.2 flags; 1.3.0 adds video_meta / file_thumbs: true). */
    features,
    addConv,
    addMsg,
    /** Upload a file into the mock's media store (e.g. a received video and its preview) → mediaId. */
    addMedia(mime, data) {
      const mediaId = crypto.randomBytes(16).toString('hex');
      media.set(mediaId, { mime, data: Buffer.from(data) });
      return mediaId;
    },
    /** A plugin hands its managed group over (release_group, Messenger 1.1.0). */
    release(convId) {
      const c = convs.get(convId);
      c.managedBy = null;
      c.updatedAt = Date.now();
      const m = addMsg(convId, { senderId: null, kind: 'system', text: null, system: { event: 'released', by: null } });
      emit('message.new', { conversationId: convId, messageId: m.id, senderId: null, clientId: null, kind: 'system', createdAt: iso(m.createdAt) });
      emit('conversation.update', { conversationId: convId, reason: 'released' });
      return m;
    },
    manage(convId, plugin) { convs.get(convId).managedBy = plugin; },
    /** A message from someone else, announced like the plugin does (message.new). */
    receive(convId, opts = {}) {
      const m = addMsg(convId, { senderId: 8, ...opts });
      emit('message.new', { conversationId: convId, messageId: m.id, senderId: m.senderId, clientId: null, kind: m.kind, createdAt: iso(m.createdAt) });
      return m;
    },
    /** The other member read up to `upTo` (ticks turn blue). */
    readBy(convId, userId, upTo) {
      const c = convs.get(convId);
      const mb = c.members.find((x) => x.id === userId);
      mb.lastRead = upTo;
      mb.lastDelivered = Math.max(mb.lastDelivered, upTo);
      // Messenger 1.1.0: the event carries what GET conversations/:id would give the recipient.
      const r = receipts(c);
      emit('read', { conversationId: convId, userId, lastReadId: upTo, lastDeliveredId: mb.lastDelivered, readUpTo: r.readUpTo, deliveredUpTo: r.deliveredUpTo });
    },
    typing(convId, userId, on = true) {
      emit('typing', { conversationId: convId, userId, until: on ? iso(Date.now() + 6000) : null });
    },
    messages: (convId) => msgs.get(convId).slice(),
    handle,
  };
  return api;
}

module.exports = { createMessenger, PLUGIN };
