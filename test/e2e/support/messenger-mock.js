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
 * Messenger 1.4.0 (FEATURES_14): status and stories, prefs privacy / notify /
 * chats, blocks, archive, pins, lists, export, reminders, suggestions (with
 * `familie: true` also to-list / to-calendar / places), polls, events, live
 * arrival, home actions and plugin cards (card pictures as base64).
 */

const crypto = require('crypto');

const PLUGIN = 'gatecontrol-messenger';
const ME = 7;
const iso = (ms) => new Date(ms).toISOString();

const FEATURES_14 = Object.freeze({
  direct: true, groups: true, voice: true, files: true, location: true, reactions: true, edit: true, search: true, disappearing: true, bridges: false, e2e: false,
  video_meta: true, file_thumbs: true, status: true, stories: true, polls: true, events: true, arrival: true, actions: true, msg_tools: true, privacy2: true,
});

function createMessenger({ emit = () => {}, features = null, familie = false } = {}) {
  const users = [
    { id: 7, name: 'Marc', initials: 'MA', colorHex: '#2FBF71', avatarUrl: null },
    { id: 8, name: 'Anna', initials: 'AN', colorHex: '#F97316', avatarUrl: null },
    { id: 9, name: 'Lena', initials: 'LE', colorHex: '#F2B91B', avatarUrl: null },
  ];
  const convs = new Map();
  const msgs = new Map();
  const media = new Map();
  const log = {
    sent: [], reads: [], actives: [], typings: [], uploads: [], reactions: [], around: [], mediaLists: [],
    // 1.4.0
    prefs: [], statusPuts: [], stories: [], seen: [], storyReacts: [], blocks: [], archives: [], pins: [], lists: [], exports: [], reminds: [],
    toList: [], toCalendar: [], votes: [], pollOps: [], rsvps: [], checks: [], eventEdits: [], actionOps: [], arrivalStops: [],
  };
  const st14 = {
    prefs: { readReceipts: true, typing: true, preview: true, privacy: { lastSeen: 'all', avatar: 'all', statusDefault: 'all', placeInStatus: 'family', groupAdd: 'all', defaultDisappearingS: 0 }, notify: { groupsMentionsOnly: false, reactions: true, statusDigest: false, eventReminderMin: 60 }, chats: { keepArchived: true } },
    statuses: new Map(), stories: [], nextStory: 300, blocks: new Set(), lists: [], reminders: [], nextReminder: 1,
    suggest: { items: [], dates: [] }, presence: new Map(),
    actions: [
      { id: 'garage.open', plugin: 'gatecontrol-garage', label: 'Garage öffnen', icon: 'M3 21V9l9-6 9 6v12H3z', kind: 'button', needsConfirm: false, state: null, subtitle: null, pluginName: 'Garage' },
      { id: 'light.living', plugin: 'gatecontrol-home', label: 'Wohnzimmerlicht', icon: null, kind: 'toggle', needsConfirm: false, state: 'off', subtitle: null, pluginName: 'Zuhause' },
    ],
    cardImages: new Map(),
  };
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

  function addMsg(convId, { senderId = 8, text = 'Hallo', kind = 'text', clientId = null, mediaId = null, meta = null, replyTo = null, location = null, thumbMediaId = null, video = null, system = null, poll = null, event = null, action = null, arrival = null, card = null, replyStory = null } = {}) {
    const m = { id: nextMsg++, conversationId: convId, senderId, clientId, kind, text, mediaId, meta, replyTo, location, thumbMediaId, video, system, poll, event, action, arrival, card, replyStory, createdAt: Date.now(), changedAt: Date.now(), editedAt: null, deleted: false, reactions: [] };
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
      ...(m.poll ? { poll: m.poll } : {}), ...(m.event ? { event: m.event } : {}), ...(m.action ? { action: actionView(m) } : {}),
      ...(m.arrival ? { arrival: m.arrival } : {}), ...(m.card ? { card: m.card } : {}), ...(m.replyStory ? { replyStory: m.replyStory } : {}),
      status: m.senderId === ME ? (m.id <= r.readUpTo ? 'read' : m.id <= r.deliveredUpTo ? 'delivered' : 'sent') : null,
    };
  }

  /** `can` of an action message for the caller (Marc): the sender cannot approve his own request. */
  function actionView(m) {
    const a = m.action;
    const open = a.state === 'open';
    const approver = a.mode === 'request' && m.senderId !== ME && (!a.approverIds || a.approverIds.includes(ME));
    return { ...a, can: { run: open && (a.mode === 'run' || (a.mode === 'grant' && !!a.grant && a.grant.toUserId === ME)), approve: open && approver, deny: open && approver } };
  }

  const presence = (id) => {
    const p = st14.presence.get(id);
    return p ? { online: !!p.online, lastSeenAt: p.lastSeenAt || null } : { online: false, lastSeenAt: null };
  };

  function nextEvent(c) {
    const now = Date.now();
    const ev = msgs.get(c.id).filter((m) => m.kind === 'event' && !m.deleted && !m.hidden && m.event && !m.event.cancelled && Date.parse(m.event.startsAt) > now)
      .sort((a, b) => Date.parse(a.event.startsAt) - Date.parse(b.event.startsAt))[0];
    return ev ? { messageId: ev.id, title: ev.event.title, startsAt: ev.event.startsAt, yesCount: ev.event.rsvp.yes.length } : null;
  }

  function convView(c) {
    const list = msgs.get(c.id).filter((m) => !m.hidden);
    const mine = c.members.find((x) => x.id === ME);
    const others = c.members.filter((x) => x.id !== ME);
    const last = list[list.length - 1] || null;
    const peer = c.kind === 'direct' ? person(others[0] && others[0].id) : null;
    return {
      id: c.id, kind: c.kind,
      title: c.kind === 'direct' ? (peer && peer.name) : c.title,
      peer: peer && api.features14 ? { ...peer, ...presence(peer.userId), blocked: st14.blocks.has(peer.userId) } : peer,
      avatarUrl: null, avatarMediaId: null,
      managedBy: c.managedBy || null, readonly: false, disappearingS: 0, createdBy: ME, createdAt: iso(c.createdAt), updatedAt: iso(c.updatedAt),
      lastMessageId: last ? last.id : null,
      members: c.members.map((x) => ({ ...person(x.id), role: x.role, joinedAt: iso(c.createdAt) })),
      me: { role: mine.role, mutedUntil: null, notify: 'all', lastReadId: mine.lastRead, lastDeliveredId: mine.lastDelivered },
      muted: false,
      unread: list.filter((m) => m.senderId !== ME && m.id > mine.lastRead && !m.deleted).length,
      lastMessage: last ? msgView(last) : null,
      typing: [],
      ...receipts(c),
      can: { send: !(peer && st14.blocks.has(peer.userId)), editInfo: c.kind === 'group' && !c.managedBy, manageMembers: c.kind === 'group' && !c.managedBy, leave: c.kind === 'group' && !c.managedBy, setDisappearing: true, ...(api.features14 ? { pin: true } : {}) },
      ...(api.features14 ? { archived: !!c.archived, pinned: c.pinned || [], nextEvent: nextEvent(c) } : {}),
    };
  }

  const userOut = (id) => { const u = users.find((x) => x.id === id) || {}; return { id, name: u.name || null, avatarUrl: null, initials: u.initials || null, colorHex: u.colorHex || null }; };
  const storyOut = (x, own) => ({
    id: x.id, kind: x.kind, text: x.text || null, bg: x.bg || null, font: x.font || null, mediaId: x.mediaId || null, thumbMediaId: x.thumbMediaId || null, video: x.video || null,
    url: null, thumbUrl: null, createdAt: iso(x.createdAt), expiresAt: iso(x.createdAt + 86400000), seen: own ? true : x.seen.has(ME), place: x.place || null, eventMessageId: x.eventMessageId || null,
    ...(own ? { viewerCount: x.seen.size, reactionCount: x.reactions.size, visibility: x.visibility || 'all' } : {}),
  });
  function feed() {
    const ids = new Set([...st14.statuses.keys(), ...st14.stories.map((x) => x.userId)]);
    ids.delete(ME);
    const items = [...ids].filter((id) => !st14.blocks.has(id)).map((id) => {
      const stories = st14.stories.filter((x) => x.userId === id).map((x) => storyOut(x, false));
      return { user: userOut(id), status: st14.statuses.get(id) || null, stories, unseen: stories.some((x) => !x.seen) };
    }).sort((a, b) => Number(b.unseen) - Number(a.unseen));
    return { items, me: { user: userOut(ME), status: st14.statuses.get(ME) || null, stories: st14.stories.filter((x) => x.userId === ME).map((x) => storyOut(x, true)), unseen: false }, serverTime: iso(Date.now()) };
  }
  const findMsg = (id) => { let m = null; for (const l of msgs.values()) m = l.find((x) => x.id === Number(id)) || m; return m; };
  const changed = (m, type) => {
    m.changedAt = Date.now();
    if (type) emit(type, { conversationId: m.conversationId, messageId: m.id, updatedAt: iso(m.changedAt), ...(type === 'arrival.update' ? { state: m.arrival.state } : {}) });
  };

  /** Messenger 1.4.0 routes (below …/api/) → true when answered. */
  function route14(method, seg, query, body, json) {
    const [a, b, c, d] = seg;
    if (!api.features14) return false;
    if (a === 'prefs' && method === 'PUT') {
      log.prefs.push(body);
      // only the known prefs (never a key taken over from the body, e.g. __proto__)
      for (const k of ['readReceipts', 'typing', 'preview']) if (typeof body[k] === 'boolean') st14.prefs[k] = body[k];
      for (const k of ['privacy', 'notify', 'chats']) {
        const v = body[k];
        if (!v || typeof v !== 'object') continue;
        const next = { ...st14.prefs[k] };
        for (const key of Object.keys(st14.prefs[k])) if (Object.prototype.hasOwnProperty.call(v, key)) next[key] = v[key];
        st14.prefs[k] = next;
      }
      return json(200, { ok: true, prefs: st14.prefs }), true;
    }
    if (a === 'status' && !b) {
      if (method === 'GET') return json(200, { ok: true, status: st14.statuses.get(ME) || null }), true;
      if (method === 'PUT') {
        log.statusPuts.push(body);
        const s = { preset: body.preset, text: body.text || null, place: null, until: body.until || null, eta: body.eta || null, destLabel: body.destLabel || null, updatedAt: iso(Date.now()), ownText: body.text || null, visibility: body.visibility || 'all', userIds: body.userIds || [] };
        st14.statuses.set(ME, s);
        emit('status.update', { userId: ME });
        return json(200, { ok: true, status: s }), true;
      }
      if (method === 'DELETE') { st14.statuses.delete(ME); emit('status.update', { userId: ME }); return json(200, { ok: true, status: null }), true; }
    }
    if (a === 'status' && b === 'feed') return json(200, { ok: true, ...feed() }), true;
    if (a === 'status' && b === 'stories') {
      if (!c && method === 'POST') {
        log.stories.push(body);
        const x = { id: st14.nextStory++, userId: ME, ...body, createdAt: Date.now(), seen: new Set(), reactions: new Map() };
        st14.stories.push(x);
        emit('story.new', { userId: ME, storyId: x.id });
        return json(200, { ok: true, story: storyOut(x, true) }), true;
      }
      const x = st14.stories.find((y) => y.id === Number(c));
      if (!x) return json(404, { ok: false, code: 'not_found' }), true;
      if (!d && method === 'DELETE') { st14.stories = st14.stories.filter((y) => y !== x); return json(200, { ok: true, deleted: true }), true; }
      if (d === 'seen') { x.seen.add(ME); log.seen.push(x.id); return json(200, { ok: true, seen: true }), true; }
      if (d === 'viewers') return json(200, { ok: true, viewers: [...x.seen].map((u) => ({ user: userOut(u), seenAt: iso(Date.now()), reaction: x.reactions.get(u) || null })) }), true;
      if (d === 'react') {
        log.storyReacts.push({ id: x.id, emoji: body.emoji });
        x.reactions.set(ME, body.emoji);
        const conv = [...convs.values()].find((y) => y.kind === 'direct' && y.members.some((z) => z.id === x.userId)) || convs.get(addConv({ members: [ME, x.userId] }));
        const m = addMsg(conv.id, { senderId: ME, text: body.emoji, replyStory: { storyId: x.id, ownerId: x.userId, preview: { kind: x.kind, text: x.text || null, thumbMediaId: null } } });
        emit('message.new', { conversationId: conv.id, messageId: m.id, senderId: ME, clientId: null, kind: 'text', createdAt: iso(m.createdAt) });
        return json(200, { ok: true, message: msgView(m) }), true;
      }
    }
    if (a === 'blocks') {
      const out = () => [...st14.blocks].map((id) => ({ userId: id, ...userOut(id), at: iso(Date.now()), gone: false }));
      if (!b && method === 'GET') return json(200, { ok: true, blocks: out() }), true;
      if (!b && method === 'POST') { st14.blocks.add(body.userId); log.blocks.push({ userId: body.userId, blocked: true }); return json(200, { ok: true, blocks: out() }), true; }
      if (b && method === 'DELETE') { st14.blocks.delete(Number(b)); log.blocks.push({ userId: Number(b), blocked: false }); return json(200, { ok: true, blocks: out() }), true; }
    }
    if (a === 'lists') {
      if (method === 'GET') return json(200, { ok: true, lists: st14.lists }), true;
      if (method === 'PUT') { st14.lists = Array.isArray(body) ? body : body.lists; log.lists.push(st14.lists); emit('lists.update', {}); return json(200, { ok: true, lists: st14.lists }), true; }
    }
    if (a === 'reminders') {
      if (!b && method === 'GET') return json(200, { ok: true, reminders: st14.reminders }), true;
      if (b && method === 'DELETE') { st14.reminders = st14.reminders.filter((x) => x.id !== Number(b)); return json(200, { ok: true, deleted: true }), true; }
    }
    if (a === 'actions' && !b) return json(200, { ok: true, actions: st14.actions }), true;
    if (a === 'familie' && b === 'places') return (familie ? json(200, { ok: true, places: [{ id: 'oma', name: 'Oma Gisela', lat: 50.2, lon: 7.2, radiusM: 150 }, { id: 'home', name: 'Zuhause', lat: 50.1, lon: 7.1, radiusM: 150 }] }) : json(409, { ok: false, code: 'unavailable' })), true;
    if (a === 'conversations' && b && ['archive', 'pins', 'export'].includes(c)) {
      const conv = convs.get(Number(b));
      if (!conv) return json(404, { ok: false, code: 'not_found' }), true;
      if (c === 'archive') { conv.archived = body.archived === true; log.archives.push({ id: conv.id, archived: conv.archived }); return json(200, { ok: true, conversation: convView(conv) }), true; }
      if (c === 'pins' && method === 'POST') { conv.pinned = [...(conv.pinned || []).filter((x) => x !== body.messageId), body.messageId].slice(-3); log.pins.push({ id: conv.id, messageId: body.messageId, pinned: true }); return json(200, { ok: true, conversation: convView(conv) }), true; }
      if (c === 'pins' && method === 'DELETE') { conv.pinned = (conv.pinned || []).filter((x) => x !== Number(d)); log.pins.push({ id: conv.id, messageId: Number(d), pinned: false }); return json(200, { ok: true, conversation: convView(conv) }), true; }
      if (c === 'export') {
        log.exports.push({ id: conv.id, before: query.before || null });
        const vis = msgs.get(conv.id).filter((x) => !x.hidden);
        const line = (x) => `18.10.26, 10:00 - ${(users.find((u) => u.id === x.senderId) || {}).name || 'GateControl'}: ${x.text || '<Medien>'}`;
        return json(200, { ok: true, format: 'txt', mime: 'text/plain', fileName: 'Chat mit Anna.txt', text: vis.map(line).join('\n') + '\n', count: vis.length, truncated: false, before: null }), true;
      }
    }
    if (a === 'messages' && b && c) {
      const m = findMsg(b);
      if (!m) return json(404, { ok: false, code: 'not_found' }), true;
      const out = (extra = {}) => json(200, { ok: true, ...extra, message: msgView(m) });
      if (c === 'remind') { const r = { id: st14.nextReminder++, messageId: m.id, conversationId: m.conversationId, at: body.at, createdAt: iso(Date.now()), preview: m.text }; st14.reminders.push(r); log.reminds.push(body); return json(200, { ok: true, reminder: r }), true; }
      if (c === 'suggest') return json(200, { ok: true, ...st14.suggest }), true;
      if (c === 'to-list') { if (!familie) return json(409, { ok: false, code: 'unavailable' }), true; log.toList.push({ id: m.id, ...body }); return json(200, { ok: true, listId: 'shopping', listName: 'Einkaufsliste', added: body.items.length, skipped: 0 }), true; }
      if (c === 'to-calendar') { if (!familie) return json(409, { ok: false, code: 'unavailable' }), true; log.toCalendar.push({ id: m.id, ...body }); return json(200, { ok: true, eventId: 77 }), true; }
      if (c === 'vote') {
        const p = m.poll;
        if (p.closed) return json(409, { ok: false, code: 'closed' }), true;
        log.votes.push({ id: m.id, optionIds: body.optionIds });
        for (const o of p.options) { o.voters = (o.voters || []).filter((u) => u !== ME); if (body.optionIds.includes(o.id)) o.voters.push(ME); o.count = o.voters.length; }
        p.myVotes = body.optionIds;
        p.voterCount = new Set(p.options.flatMap((o) => o.voters)).size;
        changed(m, 'poll.update');
        return out(), true;
      }
      if (c === 'options') { log.pollOps.push({ id: m.id, op: 'option', text: body.text }); m.poll.options.push({ id: `o${m.poll.options.length + 1}`, text: body.text, count: 0, voters: [], addedBy: ME }); changed(m, 'poll.update'); return out(), true; }
      if (c === 'close') { log.pollOps.push({ id: m.id, op: 'close' }); m.poll.closed = true; m.poll.closedAt = iso(Date.now()); changed(m, 'poll.update'); return out(), true; }
      if (c === 'nudge') { log.pollOps.push({ id: m.id, op: 'nudge' }); return out({ nudged: 1 }), true; }
      if (c === 'rsvp') {
        log.rsvps.push({ id: m.id, ...body });
        const r = m.event.rsvp;
        for (const k of ['yes', 'maybe', 'no']) r[k] = r[k].filter((x) => x.userId !== ME);
        if (['yes', 'maybe', 'no'].includes(body.answer)) r[body.answer].push({ userId: ME, guests: body.guests || 0 });
        r.mine = body.answer || null;
        r.myGuests = body.answer === 'yes' ? (body.guests || 0) : 0;
        changed(m, 'event.update');
        return out(), true;
      }
      if (c === 'checklist') { log.checks.push({ id: m.id, itemId: d, done: body.done }); const it = m.event.checklist.find((x) => x.id === d); it.doneBy = body.done ? ME : null; changed(m, 'event.update'); return out(), true; }
      if (c === 'event' && method === 'PATCH') {
        log.eventEdits.push({ id: m.id, ...body });
        for (const k of ['title', 'startsAt', 'endsAt', 'allDay', 'place', 'description', 'guests', 'reminderMin', 'familyCalendar', 'departureHint', 'cancelled']) {
          if (Object.prototype.hasOwnProperty.call(body, k)) m.event[k] = body[k];
        }
        changed(m, 'event.update');
        return out(), true;
      }
      if (c === 'arrival' && d === 'stop') { log.arrivalStops.push(m.id); m.arrival.state = 'stopped'; changed(m, 'arrival.update'); return out(), true; }
      if (c === 'action') {
        log.actionOps.push({ id: m.id, op: d, body });
        if (m.kind === 'card') { m.card.lastRun = { by: ME, at: iso(Date.now()), ok: true }; changed(m, 'action.update'); return out({ result: { ok: true, message: 'Tür geöffnet', state: null, error: null } }), true; }
        const ac = m.action;
        if (ac.state !== 'open') return json(409, { ok: false, code: 'closed' }), true;
        if (d === 'deny') { ac.state = 'denied'; changed(m, 'action.update'); return out({ result: null }), true; }
        if (d === 'approve') ac.state = 'done';
        ac.result = { ok: true, message: 'Garage geöffnet' };
        changed(m, 'action.update');
        return out({ result: { ok: true, message: 'Garage geöffnet', state: null, error: null } }), true;
      }
      if (c === 'card' && d === 'image') {
        const img = st14.cardImages.get(m.id);
        if (!img) return json(404, { ok: false, code: 'not_found' }), true;
        return json(200, { ok: true, mime: img.mime, bytes: img.data.length, data: img.data.toString('base64') }), true;
      }
    }
    return false;
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
        ok: true, user: { id: ME, name: 'Marc', avatarUrl: null, initials: 'MA', colorHex: '#2FBF71' }, prefs: api.features14 ? st14.prefs : { readReceipts: true, typing: true, preview: true },
        ...(api.features14 ? { integrations: { familie: { lists: !!familie, calendar: !!familie, places: !!familie } } } : {}),
        license: { licensed: true, state: 'active', expiresAt: null },
        features: api.features || { direct: true, groups: true, voice: true, files: true, location: true, reactions: true, edit: true, search: true, disappearing: true, bridges: false, e2e: false },
        limits: { maxBytes: 25 * 1024 * 1024, types: ['image/webp', 'image/jpeg', 'image/png', 'audio/ogg', 'audio/webm', 'audio/mp4', 'video/webm', 'video/mp4', 'application/pdf'], quotaFull: false, editWindowS: 900, maxVoiceS: 300, textMax: 4000, thumbMaxBytes: 65536, imageMaxSide: 2048, groupMax: 256, titleMax: 80, pageMax: 100, typingS: 6, typingEveryS: 3, activeS: 30, disappearingS: [0, 86400, 604800, 2592000], retentionDays: 0, ...(api.features14 ? { statusTextMax: 60, storyTextMax: 700, pollOptionsMax: 12, pollQuestionMax: 200, pollOptionMax: 80, eventTitleMax: 120, eventChecklistMax: 20, pinsMax: 3, listsMax: 20 } : {}) },
        serverTime: iso(Date.now()),
      }), true;
    }
    if (route14(method, route.slice(apiBase.length).split('/'), query, body, json)) return true;
    if (a === 'prefs') return json(200, { ok: true, prefs: { readReceipts: true, typing: true, preview: true, ...body } }), true;
    if (a === 'people') return json(200, { ok: true, people: users.filter((x) => x.id !== ME).map((x) => ({ id: x.id, name: x.name, avatarUrl: null, initials: x.initials, colorHex: x.colorHex, color: 'green', ...(api.features14 ? { ...presence(x.id), blocked: st14.blocks.has(x.id) } : {}) })) }), true;
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
        } else if (query.changedSince) { const since = Date.parse(query.changedSince); out = vis.filter((x) => x.changedAt > since); } else { out = vis.slice(-limit); hasMore = vis.length > limit; }
        return json(200, { ok: true, messages: out.map(msgView), hasMore, ...receipts(conv), ...extra }), true;
      }
      if (c === 'messages' && method === 'POST') {
        const dup = list.find((x) => x.clientId === body.clientId && x.senderId === ME);
        if (dup) return json(200, { ok: true, message: msgView(dup), duplicate: true }), true;
        if ((body.mediaId && !media.has(body.mediaId)) || (body.thumbMediaId && !media.has(body.thumbMediaId))) return json(409, { ok: false, code: 'media_invalid' }), true;
        const rich = {};
        if (body.kind === 'poll') rich.poll = { ...body.poll, options: body.poll.options.map((t, i) => ({ id: `o${i + 1}`, text: t, count: 0, voters: [], addedBy: null })), closed: false, closedAt: null, voterCount: 0, memberCount: conv.members.length, creatorId: ME, myVotes: [] };
        if (body.kind === 'event') {
          const { rsvp, checklist, ...ev } = body.event;
          rich.event = { endsAt: null, allDay: false, place: null, description: null, guests: false, reminderMin: 60, familyCalendar: false, departureHint: false, ...ev, checklist: (checklist || []).map((t, i) => ({ id: `c${i + 1}`, text: t, doneBy: null, doneAt: null })), rsvpEnabled: rsvp !== false, rsvp: { yes: [], maybe: [], no: [], mine: null, myGuests: 0 }, cancelled: false, creatorId: ME };
        }
        if (body.kind === 'action') rich.action = { plugin: null, icon: null, needsConfirm: false, approverIds: null, grant: null, ...body.action, state: 'open', result: null, by: null, at: null };
        if (body.replyStory) { const x = st14.stories.find((y) => y.id === body.replyStory.storyId); rich.replyStory = { storyId: body.replyStory.storyId, ownerId: x ? x.userId : null, preview: { kind: x ? x.kind : 'text', text: x ? x.text || null : null, thumbMediaId: null } }; }
        const m = addMsg(conv.id, { senderId: ME, text: body.text || null, kind: body.kind || 'text', clientId: body.clientId, mediaId: body.mediaId || null, meta: body.meta || null, replyTo: body.replyTo || null, location: body.location || null, thumbMediaId: body.thumbMediaId || null, video: body.video || null, ...rich });
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
    /** Messenger 1.4.0 routes and fields on (features with any 1.4.0 key). */
    features14: !!(features && ['status', 'polls', 'events', 'actions', 'msg_tools', 'privacy2'].some((k) => features[k] === true)),
    st14,
    /** A status of someone (Messenger 1.4.0). */
    setStatus(userId, status) { st14.statuses.set(userId, { preset: 'none', text: null, place: null, until: null, eta: null, destLabel: null, updatedAt: iso(Date.now()), ...status }); emit('status.update', { userId }); },
    /** A story of someone → its id (emits story.new). */
    addStory(userId, story = {}) {
      const x = { id: st14.nextStory++, userId, kind: 'text', text: 'Hallo', bg: '#1D4ED8', ...story, createdAt: Date.now(), seen: new Set(), reactions: new Map() };
      st14.stories.push(x);
      emit('story.new', { userId, storyId: x.id });
      return x.id;
    },
    /** Online / last seen of a person. */
    setPresence(userId, p) { st14.presence.set(userId, p); },
    /** A card picture (bytes) for a card message. */
    setCardImage(messageId, mime, data) { st14.cardImages.set(messageId, { mime, data: Buffer.from(data) }); },
    /** Change a 1.4.0 message from "outside" and send its update event. */
    update(messageId, fn) {
      const m = findMsg(messageId);
      fn(m);
      changed(m, m.kind === 'poll' ? 'poll.update' : m.kind === 'event' ? 'event.update' : m.kind === 'arrival' ? 'arrival.update' : 'action.update');
      return m;
    },
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

module.exports = { createMessenger, PLUGIN, FEATURES_14 };
