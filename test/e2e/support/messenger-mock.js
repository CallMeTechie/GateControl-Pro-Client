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
 * Messenger 1.4.1 (FEATURES_141): `story_duration` — POST status/stories
 * takes durationH (limits.storyDurationsH). failStory(code) makes the next
 * story post fail, `st14.feedFail` makes GET status/feed fail.
 * Messenger 1.13 / 1.14 (FEATURES_LINKED / FEATURES_BRIDGED): „Verknüpfte
 * Dienste“ (bridges/*: consent, login with a pairing code or a QR code,
 * waiting, cancel, unlink — `bridge` steers it) and chats over a bridge
 * (addBridgeConv / addBridgeMsg; they exist only for calls with ?bridged=1,
 * take text only, `bridge.sendFails` stores a message as not sent). Every API
 * call is noted in log.calls ({ method, route, query }).
 *
 * Messenger 1.21 (FEATURES_V2B, `chat_people`): persons — addPerson({ convIds, userId, nameFrom }); with ?people=1 the
 * list folds the ways (`person`, `folded`), persons/… routes (messages by time with `way`, send over the way of the
 * newest incoming message, read, search, patch, archive, merge, split), `suggestions`, `recognition` (GET bridges).
 *
 * Messenger 1.27 (FEATURES_V127, `placeMessages`): `person.replyPref`, PUT persons/:id { replyPref } (people21.replyPrefs),
 * `reply.fallback` when the chosen way cannot send; `bridge.location` names `location` in `supports`.
 */

const crypto = require('crypto');

const PLUGIN = 'gatecontrol-messenger';
const ME = 7;
const iso = (ms) => new Date(ms).toISOString();

const FEATURES_14 = Object.freeze({
  direct: true, groups: true, voice: true, files: true, location: true, reactions: true, edit: true, search: true, disappearing: true, bridges: false, e2e: false,
  video_meta: true, file_thumbs: true, status: true, stories: true, polls: true, events: true, arrival: true, actions: true, msg_tools: true, privacy2: true,
});
// Messenger 1.4.1: a story's duration (`durationH`)
const FEATURES_141 = Object.freeze({ ...FEATURES_14, story_duration: true });
const STORY_DURATIONS_H = [1, 3, 6, 12, 24];
// Messenger 1.13: the server offers a bridge; 1.14: this person has chats over one
const FEATURES_LINKED = Object.freeze({ ...FEATURES_141, linked_services: true });
const FEATURES_BRIDGED = Object.freeze({ ...FEATURES_LINKED, bridge_chats: true });
// Messenger 1.15: files and pictures over a bridge, a new chat by phone number
const FEATURES_STAGE4 = Object.freeze({ ...FEATURES_BRIDGED, bridge_media: true, bridge_new_chat: true });
// Messenger 1.17: older history at a new link, its files on request, the phone warning
const FEATURES_STAGE5 = Object.freeze({ ...FEATURES_STAGE4, bridge_history: true });
// Messenger 1.18: „Neuer Chat“ with contacts (GateControl, WhatsApp, the address book)
const FEATURES_STAGE4C = Object.freeze({ ...FEATURES_STAGE5, bridge_contacts: true });
// Messenger 1.20 (Chats v2, Teil A): channels on their own page, groups where only admins write, format, link previews
const FEATURES_V2A = Object.freeze({ ...FEATURES_STAGE4C, bridge_channels: true });
// Messenger 1.21 (Chats v2, Teil B): persons — one entry per human over several ways
const FEATURES_V2B = Object.freeze({ ...FEATURES_V2A, chat_people: true });
// Messenger 1.27: „Nachrichten senden über“ per person, the plus menu with everything, place messages
const FEATURES_V127 = Object.freeze({ ...FEATURES_V2B, placeMessages: true });
const WA_MEDIA_TYPES = Object.freeze({ image: ['image/jpeg', 'image/png', 'image/webp'], video: ['video/mp4'], voice: ['audio/ogg', 'audio/mp4', 'audio/aac', 'audio/mpeg'], file: null });

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
    // 1.13 / 1.14: every API call, what was asked of the bridge (never a number: only whether one came), resends
    calls: [], bridge: [], resends: [],
    // 1.17: PUT bridges/history bodies, messages whose file of the history was asked for
    history: [], fetches: [],
  };
  // 1.13 / 1.14: the bridges as GET bridges tells them, and the login in progress
  const bridge = {
    available: true,
    location: 'server',
    networks: [{ id: 'whatsapp', state: 'running', allowed: true, lock: null, consent: null, outdated: false, version: '0.12.1', wantVersion: '0.12.1', logins: [] }],
    process: null,
    confirmAfter: 2,          // so many waiting calls before the phone "confirmed" (Infinity: never)
    qrRenewAt: null,          // a waiting call number at which the QR code is renewed
    loginFails: null,         // { status, code, reason } for the next waiting call; { drop: n } = no answer n times
    phoneRefused: false,
    sendFails: null,          // a reason: the bridge does not take the next message (stored as not sent)
    // 1.15: files cross (supports + mediaTypes); the new chat by number (features.bridge_new_chat)
    media: false,
    location: false,          // 1.27 (gc.bridges 14): the bridge sends a location (`supports` names it)
    scanPending: 0,           // so many sends of a file are refused with 423 scan_pending first
    numbers: new Map(),       // '+49…' → name of the numbers "at WhatsApp"
    lookups: 0,
    lookupMax: 10,
    resolveDelayMs: 0,
    resolveFails: null,       // { status, code, reason?, retryAfterS? } for the next resolve / chats
    // 1.17 (features.bridge_history): older history at a new link; historyFails / fetchFails: { status, code } once
    history: { available: true, days: 30, default: 30, options: [0, 30, -1], pending: 0 },
    historyFails: null,
    fetchFails: null,
    // 1.18 (features.bridge_contacts): the WhatsApp contacts of the bridge ({ ref, name, conversationId, … }), the address
    // book of Mail ({ contactId, name, phones }; null = no Mail), the state of the list, refs that ran out, „nicht bei
    // WhatsApp“ remembered (`${contactId}|${key}`), a delay of the list, a delay of a check, a refusal of the next chat
    contacts: [],
    book: null,
    listState: 'ok',
    expired: new Set(),
    notOn: new Set(),
    contactsDelayMs: 0,
    chatDelayMs: 0,
    chatFails: null,
  };
  const st14 = {
    prefs: { readReceipts: true, typing: true, preview: true, privacy: { lastSeen: 'all', avatar: 'all', statusDefault: 'all', placeInStatus: 'family', groupAdd: 'all', defaultDisappearingS: 0 }, notify: { groupsMentionsOnly: false, reactions: true, statusDigest: false, eventReminderMin: 60 }, chats: { keepArchived: true } },
    statuses: new Map(), stories: [], nextStory: 300, storyFail: null, feedFail: false, blocks: new Set(), lists: [], reminders: [], nextReminder: 1,
    suggest: { items: [], dates: [] }, presence: new Map(),
    actions: [
      { id: 'garage.open', plugin: 'gatecontrol-garage', label: 'Garage öffnen', icon: 'M3 21V9l9-6 9 6v12H3z', kind: 'button', needsConfirm: false, state: null, subtitle: null, pluginName: 'Garage' },
      { id: 'light.living', plugin: 'gatecontrol-home', label: 'Wohnzimmerlicht', icon: null, kind: 'toggle', needsConfirm: false, state: 'off', subtitle: null, pluginName: 'Zuhause' },
    ],
    cardImages: new Map(),
  };
  let nextConv = 12;
  let nextMsg = 4700;
  // 1.21: persons of Marc (id → { id, ways, userId, nameFrom }), open suggestions, their answers, the consent to be
  // recognised by the own WhatsApp (null: GateControl has no such call); log.persons: what was asked of persons/…
  const persons = new Map();
  let nextPerson = 1;
  const people21 = { suggestions: [], answers: [], recognition: null, merges: [], splits: [], reads: [], names: [], replyPrefs: [] };

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

  /** A chat over a bridge: one member (Marc), no peer. */
  function addBridgeConv({ kind = 'direct', title = 'Kim Muster', network = 'whatsapp', state = 'ok', closed = false, channel = false, readOnly = false } = {}) {
    const id = addConv({ kind: channel ? 'group' : kind, members: [ME], title });
    // 1.20: a channel (muted from the start, read only), a group where only admins write
    Object.assign(convs.get(id), { bridge: { network, state, closed, readUpTo: null, deliveredUpTo: null, channel, readOnly: readOnly || channel, reactions: 'own' }, notify: channel ? 'none' : 'all' });
    return id;
  }

  /** A message in a chat over a bridge: of a contact, of Marc's phone (`remote`), a placeholder, a notice, an own one with a state. */
  function addBridgeMsg(convId, { contact = { contactId: 12, name: 'Kim Muster' }, text = 'Hallo', remote = false, placeholder = null, notice = false, state = null, reason = null, replyTo = null, kind = null, mediaId = null, meta = null, video = null, post = false, marks = null, preview = null } = {}) {
    const mine = remote || state != null;
    const m = addMsg(convId, { senderId: mine ? ME : null, text, kind: kind || (notice ? 'system' : 'text'), replyTo, mediaId, meta, video, system: notice ? { event: 'bridge_notice', network: convs.get(convId).bridge.network } : null });
    // 1.20: a post of a channel (`post`), the format of the text, a link preview
    m.bridge = { sender: mine || notice || post ? null : contact, remote, state: mine ? (state || 'sent') : null, reason, placeholder, ...(post ? { channel: true } : {}) };
    m.marks = marks;
    m.preview = preview;
    return m;
  }

  const qrRows = (seed) => Array.from({ length: 29 }, (_, y) => Array.from({ length: 29 }, (_, x) => {
    const finder = (cx, cy) => { const dx = Math.abs(x - cx); const dy = Math.abs(y - cy); const d = Math.max(dx, dy); return d <= 3 ? (d === 2 ? '0' : '1') : null; };
    return finder(3, 3) || finder(25, 3) || finder(3, 25) || (((x * 7 + y * 13 + seed * 5 + ((x * y) % 5)) % 3 === 0) ? '1' : '0');
  }).join(''));
  const waitStep = (pr) => (pr.flow === 'qr'
    ? { id: `qr${pr.n}`, type: 'display_and_wait', display: { type: 'qr', data: `2@mock${pr.n}`, matrix: { size: 29, rows: qrRows(pr.n) } } }
    : { id: 'code1', type: 'display_and_wait', display: { type: 'code', data: 'K7P2-M4X9' } });

  /** GET contacts/new-chat (the plugin's contactchat.js, 1.18) → the three sections, filtered by q. → true when answered. */
  function contactsRoute(method, seg, query, json) {
    if (seg[0] !== 'contacts' || seg[1] !== 'new-chat' || method !== 'GET') return false;
    if (!(features && features.bridge_contacts === true)) return json(404, { ok: false, code: 'not_found' }), true;
    const B = bridge;
    const net = B.networks[0];
    const q = String(query.q || '').trim().slice(0, 100);
    const has = (n) => !q || String(n || '').toLowerCase().includes(q.toLowerCase());
    log.bridge.push({ op: 'contacts', q: q ? 'set' : '' });
    const answer = () => {
      const gatecontrol = users.filter((x) => x.id !== ME && has(x.name)).map((x) => {
        const c = [...convs.values()].find((y) => y.kind === 'direct' && !y.bridge && y.members.some((mb) => mb.id === x.id));
        return { userId: x.id, name: x.name, avatarUrl: null, initials: x.initials, colorHex: x.colorHex, conversationId: c ? c.id : null };
      });
      const linked = net.logins.length > 0 && net.allowed;
      const st = !linked ? null : (net.logins.every((l) => l.state === 'logged_out') ? 'logged_out' : (net.state !== 'running' || B.listState === 'unreachable' ? 'unreachable' : B.listState));
      const items = B.contacts.filter((c) => has(c.name)).sort((x, y) => x.name.localeCompare(y.name, 'de'));
      const whatsapp = st ? { state: st, total: B.contacts.length, items: st === 'ok' ? items.map((c) => ({ ref: c.ref, name: c.name, avatarMediaId: c.avatarMediaId || null, avatarUrl: null, conversationId: c.conversationId || null, alsoInAddressBook: !!c.alsoInAddressBook, addressBookId: c.addressBookId || null })) : [] } : null;
      const book = whatsapp && B.book && B.book.length ? B.book : null;
      const addressBook = book ? { state: st, total: book.length, items: book.filter((x) => has(x.name)).map((x) => ({ contactId: x.contactId, name: x.name, conversationId: x.conversationId || null,
        phones: x.phones.map((p) => ({ ...p, notOnNetwork: B.notOn.has(`${x.contactId}|${p.key}`) })) })) } : null;
      const digits = /^[+0-9\s\-./()]{6,40}$/.test(q) ? q.replace(/[\s\-./()]/g, '').replace(/^0(?=[1-9])/, '+49') : '';
      const number = whatsapp && /^\+[1-9][0-9]{6,14}$/.test(digits) ? { e164: digits, show: digits.replace(/^\+49(\d{3})/, '+49 $1 '), conversationId: null } : null;
      json(200, { ok: true, network: 'whatsapp', query: q, gatecontrol, whatsapp, addressBook, addressBookReason: whatsapp && !book ? 'no_mail' : null,
        number, numberEntry: !!whatsapp, limit: { perHour: B.lookupMax, left: Math.max(0, B.lookupMax - B.lookups), retryAfterS: 0 } });
    };
    if (B.contactsDelayMs) setTimeout(answer, B.contactsDelayMs);
    else answer();
    return true;
  }

  /** bridges/* (the plugin's bridges.js). → true when answered. */
  function bridgeRoute(method, seg, body, json, drop) {
    if (seg[0] !== 'bridges') return false;
    if (!(features && features.linked_services === true)) return json(404, { ok: false, code: 'not_found' }), true;
    const B = bridge;
    const hist = features && features.bridge_history === true;
    if (seg.length === 1 && method === 'GET') return json(200, { ok: true, bridges: B.available ? { available: true, location: B.location, networks: B.networks, ...(hist ? { history: B.history } : {}), ...(people21.recognition ? { recognition: { available: true, network: 'whatsapp', ...people21.recognition } } : {}) } : { available: false, networks: [] } }), true;
    // 1.21 (gc.bridges version 9): „Dürfen andere auf diesem Server dich an deinem WhatsApp erkennen?“
    if (seg.length === 2 && seg[1] === 'recognition' && method === 'PUT') {
      if (!people21.recognition) return json(403, { ok: false, code: 'feature_off' }), true;
      people21.recognition = { asked: true, allowed: body.allowed === true };
      return json(200, { ok: true, recognition: { available: true, network: 'whatsapp', ...people21.recognition } }), true;
    }
    // 1.17: what of the older messages comes over
    if (seg.length === 2 && seg[1] === 'history' && method === 'PUT') {
      if (!hist || !B.history) return json(403, { ok: false, code: 'feature_off' }), true;
      log.history.push(body);
      if (B.historyFails) { const f = B.historyFails; B.historyFails = null; return json(f.status, { ok: false, code: f.code }), true; }
      if (![0, 30, -1].includes(body && body.days)) return json(400, { ok: false, code: 'invalid' }), true;
      B.history = { ...B.history, days: body.days, pending: body.days === 0 ? 0 : B.history.pending };
      return json(200, { ok: true, history: B.history }), true;
    }
    const net = B.networks.find((n) => n.id === seg[1]);
    if (!net || seg.length < 3) return json(404, { ok: false, code: 'not_found' }), true;
    if (!B.available) return json(409, { ok: false, code: 'bridge_off', reason: 'no_host' }), true;
    // 1.18: a WhatsApp contact ({ ref }: nothing checked or counted) or an address book number ({ contactId, phoneKind })
    if (seg.length === 3 && seg[2] === 'chats' && method === 'POST' && (body.ref != null || body.contactId != null)) {
      if (!(features && features.bridge_contacts === true)) return json(400, { ok: false, code: 'invalid_number' }), true;
      const answer = () => {
        if (B.chatFails) { const f = B.chatFails; B.chatFails = null; return json(f.status, { ok: false, code: f.code, ...(f.reason ? { reason: f.reason } : {}), ...(f.retryAfterS ? { retryAfterS: f.retryAfterS, perHour: f.perHour || 10 } : {}) }); }
        if (!net.allowed) return json(403, { ok: false, code: 'bridge_locked' });
        if (net.logins.every((l) => l.state === 'logged_out')) return json(409, { ok: false, code: 'bridge_logged_out', reason: 'logged_out' });
        if (net.state !== 'running') return json(503, { ok: false, code: 'bridge_unreachable', reason: 'not_running' });
        if (body.ref != null) {
          if (B.expired.has(body.ref)) return json(409, { ok: false, code: 'contact_expired' });
          const c = B.contacts.find((x) => x.ref === body.ref);
          if (!c) return json(400, { ok: false, code: 'invalid' });
          log.bridge.push({ op: 'chat_ref' });
          const existing = c.conversationId && convs.get(c.conversationId);
          const id = existing ? existing.id : addBridgeConv({ title: c.name });
          c.conversationId = id;
          return json(200, { ok: true, conversation: convView(convs.get(id)), created: !existing });
        }
        if (!B.book) return json(409, { ok: false, code: 'mail_missing' });
        const x = B.book.find((y) => y.contactId === body.contactId);
        const ph = x && x.phones.find((p) => p.key === body.phoneKind);
        if (!ph) return json(404, { ok: false, code: 'not_found', reason: 'contact_gone' });
        if (B.notOn.has(`${x.contactId}|${ph.key}`)) return json(404, { ok: false, code: 'not_found', reason: 'not_on_network', remembered: true });
        if (B.lookups >= B.lookupMax) return json(429, { ok: false, code: 'rate_limited', retryAfterS: 840, perHour: 10 });
        B.lookups += 1;
        log.bridge.push({ op: 'chat_book', key: ph.key });
        if (!B.numbers.has(ph.e164)) { B.notOn.add(`${x.contactId}|${ph.key}`); return json(404, { ok: false, code: 'not_found', reason: 'not_on_network' }); }
        const existing = [...convs.values()].find((c) => c.bridge && c.bridge.number === ph.e164);
        const id = existing ? existing.id : addBridgeConv({ title: x.name });
        convs.get(id).bridge.number = ph.e164;
        return json(200, { ok: true, conversation: convView(convs.get(id)), created: !existing });
      };
      if (B.chatDelayMs) setTimeout(answer, B.chatDelayMs);
      else answer();
      return true;
    }
    // 1.15: a new chat by number (never logged here: only that a lookup came)
    if (seg.length === 3 && (seg[2] === 'resolve' || seg[2] === 'chats') && method === 'POST') {
      if (!(features && features.bridge_new_chat === true)) return json(404, { ok: false, code: 'not_found' }), true;
      const answer = () => {
        if (B.resolveFails) { const f = B.resolveFails; B.resolveFails = null; return json(f.status, { ok: false, code: f.code, ...(f.reason ? { reason: f.reason } : {}), ...(f.retryAfterS ? { retryAfterS: f.retryAfterS } : {}) }); }
        if (!net.allowed) return json(403, { ok: false, code: 'bridge_locked' });
        if (!net.logins.length) return json(409, { ok: false, code: 'bridge_unlinked', reason: 'unlinked' });
        if (net.logins.every((l) => l.state === 'logged_out')) return json(409, { ok: false, code: 'bridge_logged_out', reason: 'logged_out' });
        if (net.state !== 'running') return json(503, { ok: false, code: 'bridge_unreachable', reason: 'not_running' });
        const num = String(body.number || '').replace(/[\s()-]/g, '');
        if (!/^\+[1-9][0-9]{6,14}$/.test(num)) return json(400, { ok: false, code: 'invalid_number' });
        if (B.lookups >= B.lookupMax) return json(429, { ok: false, code: 'rate_limited', retryAfterS: 840, perHour: 10 });
        B.lookups += 1;
        log.bridge.push({ op: seg[2], valid: true });
        const name = B.numbers.get(num);
        const existing = [...convs.values()].find((c) => c.bridge && c.bridge.number === num);
        if (seg[2] === 'resolve') return json(200, { ok: true, found: name != null, name: name || null, avatarUrl: null, existing: existing ? { conversationId: existing.id } : null });
        if (name == null) return json(404, { ok: false, code: 'not_found', reason: 'not_on_network' });
        const id = existing ? existing.id : addBridgeConv({ title: name });
        convs.get(id).bridge.number = num;
        return json(200, { ok: true, conversation: convView(convs.get(id)), created: !existing });
      };
      if (B.resolveDelayMs) setTimeout(answer, B.resolveDelayMs);
      else answer();
      return true;
    }
    const gate = (consent = true) => (!net.allowed ? [403, 'bridge_locked'] : (consent && !net.consent ? [409, 'consent_required'] : null));
    if (seg.length === 3 && seg[2] === 'consent' && method === 'POST') {
      const g = gate(false);
      if (g) return json(g[0], { ok: false, code: g[1] }), true;
      if (body.accept !== true) return json(400, { ok: false, code: 'invalid' }), true;
      net.consent = net.consent || iso(Date.now());
      log.bridge.push({ op: 'consent' });
      return json(200, { ok: true, consent: net.consent }), true;
    }
    if (seg.length === 3 && seg[2] === 'login' && method === 'POST') {
      const g = gate();
      if (g) return json(g[0], { ok: false, code: g[1] }), true;
      if (net.state !== 'running') return json(503, { ok: false, code: 'bridge_unreachable', reason: 'not_running' }), true;
      const pr = { id: `proc${log.bridge.length + 1}`, flow: body.flow, n: 1, polls: 0 };
      B.process = pr;
      log.bridge.push({ op: 'start', flow: pr.flow });
      return json(200, { ok: true, login: { processId: pr.id, step: pr.flow === 'phone' ? { id: 'phone1', type: 'user_input', fields: [{ id: 'phone_number', type: 'phone_number', optional: false }] } : waitStep(pr) } }), true;
    }
    if (seg.length === 5 && seg[2] === 'login' && method === 'POST') {
      const g = gate();
      if (g) return json(g[0], { ok: false, code: g[1] }), true;
      const pr = B.process;
      if (!pr || pr.id !== seg[3]) return json(404, { ok: false, code: 'not_found' }), true;
      if (body.input) {
        log.bridge.push({ op: 'input', step: seg[4], valid: /^\+[0-9]{6,15}$/.test(String(body.input.phone_number || '')) });
        if (B.phoneRefused) return json(502, { ok: false, code: 'bridge_failed', reason: 'bad_number' }), true;
        return json(200, { ok: true, login: { processId: pr.id, step: waitStep(pr) } }), true;
      }
      pr.polls += 1;
      log.bridge.push({ op: 'wait', step: seg[4] });
      if (B.loginFails) {
        const f = B.loginFails;
        if (f.drop) { f.drop -= 1; if (!f.drop) B.loginFails = null; drop(); return true; }
        B.loginFails = null;
        B.process = null;
        return json(f.status, { ok: false, code: f.code, ...(f.reason ? { reason: f.reason } : {}) }), true;
      }
      if (pr.flow === 'qr' && B.qrRenewAt === pr.polls) { pr.n += 1; return json(200, { ok: true, login: { processId: pr.id, step: waitStep(pr) } }), true; }
      if (pr.polls < B.confirmAfter) return json(200, { ok: true, login: { processId: pr.id, waiting: true } }), true;
      B.process = null;
      net.logins = [{ id: 'login1', name: '+49 1512 0000000', state: 'connected', since: iso(Date.now()) }];
      for (const c of convs.values()) if (c.bridge && c.bridge.network === net.id) { c.bridge.state = 'ok'; c.updatedAt = Date.now(); }
      return json(200, { ok: true, login: { processId: pr.id, step: { id: 'done', type: 'complete', loginId: 'login1' } } }), true;
    }
    if (seg.length === 4 && seg[2] === 'login' && method === 'DELETE') {
      log.bridge.push({ op: 'cancel', process: seg[3] });
      if (B.process && B.process.id === seg[3]) B.process = null;
      return json(200, { ok: true, cancelled: true }), true;
    }
    if (seg.length === 4 && seg[2] === 'logins' && method === 'DELETE') {
      if (!net.logins.some((l) => l.id === seg[3])) return json(404, { ok: false, code: 'not_found' }), true;
      log.bridge.push({ op: 'unlink', login: seg[3] });
      net.logins = net.logins.filter((l) => l.id !== seg[3]);
      for (const c of convs.values()) if (c.bridge && c.bridge.network === net.id) { c.bridge.state = 'unlinked'; c.updatedAt = Date.now(); }
      return json(200, { ok: true, unlinked: true }), true;
    }
    return json(404, { ok: false, code: 'not_found' }), true;
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
      replyTo: q ? { id: q.id, senderId: q.senderId, kind: q.kind, text: q.text, deleted: q.deleted, missing: false, ...(q.bridge && q.bridge.sender ? { contactId: q.bridge.sender.contactId, senderName: q.bridge.sender.name } : {}) } : null,
      media: f && !m.deleted ? { id: m.mediaId, mime: f.mime, bytes: f.data.length, url: null, thumbId: m.thumbMediaId || null, thumbUrl: null } : null,
      ...(m.video && !m.deleted ? { video: m.video } : {}),
      meta: m.deleted ? null : m.meta, location: m.deleted ? null : (m.location || null), system: m.system || null, reactions: m.deleted ? [] : m.reactions,
      ...(m.poll ? { poll: m.poll } : {}), ...(m.event ? { event: m.event } : {}), ...(m.action ? { action: actionView(m) } : {}),
      ...(m.arrival ? { arrival: m.arrival } : {}), ...(m.card ? { card: m.card } : {}), ...(m.replyStory ? { replyStory: m.replyStory } : {}),
      status: m.senderId === ME ? (m.id <= r.readUpTo ? 'read' : m.id <= r.deliveredUpTo ? 'delivered' : 'sent') : null,
      // 1.21: the way of every message
      ...(features && features.chat_people === true ? { way: c.bridge ? c.bridge.network : 'gatecontrol' } : {}),
      // 1.14: a message of a chat over a bridge
      ...(c.bridge ? {
        via: `bridge:${c.bridge.network}`,
        bridge: m.bridge || { sender: null, remote: false, state: m.senderId === ME ? 'sent' : null, reason: null, placeholder: null },
        marks: m.deleted ? null : (m.marks || null),
        preview: m.deleted ? null : (m.preview || null),
        ...(m.senderId === ME && m.bridge && m.bridge.state ? { status: m.bridge.state === 'pending' ? 'sending' : m.bridge.state } : {}),
        reactions: m.deleted ? [] : m.reactions.concat(m.contactReactions || []),
      } : {}),
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

  const chanWord = () => !!(features && features.bridge_channels === true);
  const isChan = (x) => !!(x.bridge && x.bridge.channel && chanWord());

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
      me: { role: mine.role, mutedUntil: null, notify: c.notify || 'all', lastReadId: mine.lastRead, lastDeliveredId: mine.lastDelivered },
      muted: c.notify === 'none',
      unread: list.filter((m) => m.senderId !== ME && m.id > mine.lastRead && !m.deleted).length,
      lastMessage: last ? msgView(last) : null,
      typing: [],
      ...receipts(c),
      can: { send: !(peer && st14.blocks.has(peer.userId)), editInfo: c.kind === 'group' && !c.managedBy, manageMembers: c.kind === 'group' && !c.managedBy, leave: c.kind === 'group' && !c.managedBy, setDisappearing: true, ...(api.features14 ? { pin: true } : {}) },
      ...(api.features14 ? { archived: !!c.archived, pinned: c.pinned || [], nextEvent: nextEvent(c) } : {}),
      // 1.14: `bridge` (null inside GateControl); a chat over a bridge has no peer and one member
      ...(features && (features.linked_services === true || features.bridge_chats === true) ? { bridge: null } : {}),
      ...(c.bridge ? {
        title: c.title, peer: null,
        bridge: {
          network: c.bridge.network, label: 'WhatsApp', state: c.bridge.state, closed: !!c.bridge.closed,
          ...(chanWord() ? { channel: !!c.bridge.channel, readOnly: !!c.bridge.readOnly, ...(c.bridge.channel ? { reactions: c.bridge.reactions } : {}) } : {}),
          supports: ['text', 'reply', 'reaction', 'edit', 'delete', 'read', 'typing', ...(bridge.media ? ['image', 'video', 'voice', 'file'] : []), ...(bridge.location ? ['location'] : [])],
          ...(bridge.media ? { mediaTypes: WA_MEDIA_TYPES } : {}),
        },
        avatarMediaId: c.avatarMediaId || null,
        readUpTo: c.bridge.readUpTo, deliveredUpTo: c.bridge.deliveredUpTo, receipts: [],
        can: {
          send: c.bridge.state === 'ok' && !c.bridge.closed && !(chanWord() && c.bridge.readOnly), pin: true, editInfo: false, manageMembers: false, leave: false, setDisappearing: false,
          ...(chanWord() ? { sendReason: c.bridge.channel ? 'channel' : (c.bridge.readOnly ? 'admins_only' : null), react: c.bridge.state === 'ok' && !c.bridge.closed && (!c.bridge.channel || c.bridge.reactions === 'own') } : {}),
        },
      } : {}),
    };
  }

  // ── 1.21: persons ──
  const personOf = (cid) => [...persons.values()].find((p) => p.ways.includes(cid)) || null;
  const wayName = (c) => (c.bridge ? c.bridge.network : 'gatecontrol');
  const keyLess = (x, y) => x.createdAt < y.createdAt || (x.createdAt === y.createdAt && x.id < y.id);
  const byKey = (x, y) => (keyLess(x, y) ? -1 : keyLess(y, x) ? 1 : 0);
  function addPerson({ convIds, userId = null, nameFrom = null }) {
    const id = nextPerson++;
    persons.set(id, { id, ways: convIds.slice(), userId, nameFrom: nameFrom || (userId ? 'account' : Math.min(...convIds)), createdAt: Date.now() });
    return id;
  }
  function personEntry(p) {
    const cs = p.ways.map((id) => convs.get(id)).filter(Boolean);
    const views = cs.map(convView);
    const gc = cs.find((c) => !c.bridge);
    const lead = gc || cs.slice().sort((x, y) => x.id - y.id)[0];
    const leadView = views.find((v) => v.id === lead.id);
    const acc = p.userId ? users.find((u) => u.id === p.userId) : null;
    const src = p.nameFrom !== 'account' ? views.find((v) => v.id === p.nameFrom) : null;
    const name = src ? src.title : (acc ? acc.name : leadView.title);
    let best = null;
    for (const c of cs) {
      const inc = msgs.get(c.id).filter((m) => !m.hidden && m.senderId !== ME && m.kind !== 'system');
      const li = inc[inc.length - 1];
      if (li && (!best || li.createdAt > best.li.createdAt || (li.createdAt === best.li.createdAt && !c.bridge))) best = { c, li };
    }
    let pick = best ? best.c : lead;
    if (pick.bridge && gc && !(pick.bridge.state === 'ok' && !pick.bridge.closed)) pick = gc;
    // 1.27: a fixed way while it can send, else GateControl with `fallback`
    let fallback = false;
    const pref = p.replyPref || 'auto';
    const want = pref !== 'auto' ? cs.find((c) => wayName(c) === pref) : null;
    if (want) {
      if (!want.bridge || (want.bridge.state === 'ok' && !want.bridge.closed)) pick = want;
      else if (gc && gc !== want) { pick = gc; fallback = true; }
    }
    const ways = views.slice().sort((x, y) => (x.bridge ? 1 : 0) - (y.bridge ? 1 : 0) || x.id - y.id).map((v) => ({
      way: v.bridge ? v.bridge.network : 'gatecontrol', label: v.bridge ? v.bridge.label : 'GateControl', conversationId: v.id, title: v.title,
      avatarUrl: v.avatarUrl || null, avatarMediaId: v.avatarMediaId || null, unread: v.unread, muted: v.muted, archived: !!v.archived,
      lastMessageAt: v.lastMessage ? v.lastMessage.createdAt : null, bridge: v.bridge || null,
      can: { send: !!v.can.send, sendReason: v.can.sendReason || null, react: v.can.react !== false },
    }));
    let last = null;
    for (const v of views) if (v.lastMessage && (!last || v.lastMessage.createdAt > last.createdAt || (v.lastMessage.createdAt === last.createdAt && v.lastMessage.id > last.id))) last = v.lastMessage;
    const names = [];
    for (const n of [name, acc && acc.name, ...views.map((v) => v.title)]) if (n && !names.includes(n)) names.push(n);
    return {
      ...leadView, title: name, unread: views.reduce((s, v) => s + v.unread, 0), lastMessage: last, archived: views.every((v) => !!v.archived),
      updatedAt: iso(Math.max(...cs.map((c) => c.updatedAt))),
      person: {
        id: p.id, name, nameFrom: src ? src.id : (acc ? 'account' : null), userId: p.userId, conversationId: lead.id, names, ways,
        reply: { way: wayName(pick), label: pick.bridge ? 'WhatsApp' : 'GateControl', conversationId: pick.id, ...(fallback ? { fallback: true } : {}) }, createdAt: iso(p.createdAt),
        ...(features && features.placeMessages === true ? { replyPref: pref } : {}),
      },
    };
  }
  /** persons/* → true when answered (POST …/messages goes on as the way's POST, see handle). */
  function personRoute(method, seg, query, body, json) {
    const [, b, c, d] = seg;
    const ok = (p) => { const e = personEntry(p); return json(200, { ok: true, conversation: e, person: e.person }), true; };
    if (seg.length === 2 && b === 'suggestions' && method === 'GET') return json(200, { ok: true, suggestions: people21.suggestions }), true;
    if (seg.length === 3 && b === 'suggestions' && method === 'POST') {
      if (!people21.suggestions.some((x) => x.id === c)) return json(404, { ok: false, code: 'not_found' }), true;
      people21.answers.push({ id: c, action: body.action });
      people21.suggestions = people21.suggestions.filter((x) => x.id !== c);
      return json(200, { ok: true, suggestion: { id: c, state: body.action, until: null } }), true;
    }
    if (seg.length === 2 && b === 'candidates' && method === 'GET') {
      const cid = Number(query.conversationId);
      const conv = convs.get(cid);
      if (!conv) return json(404, { ok: false, code: 'not_found' }), true;
      const own = personOf(cid);
      const hasAccount = (!conv.bridge && conv.kind === 'direct') || !!(own && own.userId);
      const accounts = hasAccount ? [] : users.filter((u) => u.id !== ME).map((u) => ({ userId: u.id, name: u.name, avatarUrl: null, initials: u.initials, colorHex: u.colorHex, personId: null }));
      const chats = [...convs.values()].filter((x) => x.bridge && x.kind === 'direct' && !x.bridge.channel && x.id !== cid && !(own && own.ways.includes(x.id)) && msgs.get(x.id).length)
        .map((x) => ({ conversationId: x.id, title: x.title, network: x.bridge.network, label: 'WhatsApp', avatarUrl: null, avatarMediaId: x.avatarMediaId || null, personId: (personOf(x.id) || {}).id || null }));
      return json(200, { ok: true, accounts, chats }), true;
    }
    if (seg.length === 1 && method === 'POST') {
      const ids = Array.isArray(body.conversationIds) ? body.conversationIds : [];
      people21.merges.push(body);
      for (const id of ids) {
        const x = convs.get(id);
        if (!x) return json(404, { ok: false, code: 'not_found' }), true;
        if (x.kind !== 'direct' || (x.bridge && x.bridge.channel)) return json(409, { ok: false, code: 'cannot_merge', reason: 'group' }), true;
      }
      let userId = body.userId || null;
      const all = new Set(ids);
      for (const id of ids) {
        const x = convs.get(id);
        if (!x.bridge) userId = x.members.find((y) => y.id !== ME).id;
        const pp = personOf(id);
        if (pp) { pp.ways.forEach((w) => all.add(w)); if (pp.userId) userId = pp.userId; persons.delete(pp.id); }
      }
      if (userId && ![...all].some((id) => !convs.get(id).bridge)) {
        const ex = [...convs.values()].find((x) => x.kind === 'direct' && !x.bridge && x.members.some((y) => y.id === userId));
        all.add(ex ? ex.id : addConv({ kind: 'direct', members: [ME, userId] }));
      }
      if (all.size < 2) return json(409, { ok: false, code: 'cannot_merge', reason: 'one_way' }), true;
      const pid = addPerson({ convIds: [...all], userId, nameFrom: body.name || (userId ? 'account' : null) });
      people21.suggestions = people21.suggestions.filter((s) => !all.has(s.conversationId));
      for (const id of all) { convs.get(id).updatedAt = Date.now(); emit('conversation.update', { conversationId: id, reason: 'person', personId: pid }); }
      return ok(persons.get(pid));
    }
    const p = persons.get(Number(b));
    if (!p) return json(404, { ok: false, code: 'not_found' }), true;
    const all = p.ways.map((id) => convs.get(id));
    const touch = () => { for (const x of all) x.updatedAt = Date.now(); };
    if (seg.length === 2 && method === 'GET') return ok(p);
    if (seg.length === 2 && (method === 'PATCH' || method === 'PUT')) {
      // 1.27: replyPref — auto | gatecontrol | a network the person has (else bad_request)
      if (body.replyPref !== undefined) {
        const v = body.replyPref === null ? 'auto' : body.replyPref;
        if (typeof v !== 'string' || !/^[a-z]{2,20}$/.test(v)) return json(400, { ok: false, code: 'invalid' }), true;
        if (v !== 'auto' && !all.some((x) => wayName(x) === v)) return json(400, { ok: false, code: 'bad_request' }), true;
        p.replyPref = v;
        people21.replyPrefs.push({ personId: p.id, method, replyPref: v });
      }
      if (body.name !== undefined) { p.nameFrom = body.name; people21.names.push(body.name); }
      for (const x of all) if (body.notify === 'all' || body.notify === 'none') x.notify = body.notify;
      touch();
      return ok(p);
    }
    if (seg.length === 3 && c === 'archive' && method === 'POST') { for (const x of all) x.archived = body.archived === true; touch(); return ok(p); }
    if ((seg.length === 4 && c === 'ways' && method === 'DELETE') || (seg.length === 2 && method === 'DELETE')) {
      if (d && !p.ways.includes(Number(d))) return json(404, { ok: false, code: 'not_found' }), true;
      const leave = d ? [Number(d)] : p.ways.slice();
      people21.splits.push({ personId: p.id, conversationId: d ? Number(d) : null });
      p.ways = p.ways.filter((id) => !leave.includes(id));
      let person = null;
      const out = [];
      if (p.ways.length < 2) { leave.push(...p.ways); persons.delete(p.id); } else { if (leave.includes(p.nameFrom)) p.nameFrom = p.userId ? 'account' : Math.min(...p.ways); const e = personEntry(p); person = e.person; out.push(e); }
      touch();
      for (const id of new Set(leave)) out.push(convView(convs.get(id)));
      for (const x of all) emit('conversation.update', { conversationId: x.id, reason: 'person', personId: person ? p.id : null });
      return json(200, { ok: true, person, conversations: out }), true;
    }
    const ways = query.way ? all.filter((x) => wayName(x) === query.way) : all;
    const rows = () => ways.flatMap((x) => msgs.get(x.id).filter((m) => !m.hidden)).sort(byKey);
    const marks = () => all.map((x) => { const v = convView(x); return { conversationId: x.id, way: wayName(x), lastReadId: v.me.lastReadId, readUpTo: v.readUpTo, deliveredUpTo: v.deliveredUpTo }; });
    if (seg.length === 3 && c === 'messages' && method === 'GET') {
      const limit = Number(query.limit) || 50;
      const list = rows();
      const cur = (id) => all.flatMap((x) => msgs.get(x.id)).find((m) => m.id === Number(id)) || null;
      let out;
      let hasMore = false;
      const extra = {};
      if (query.before) { const k = cur(query.before); const o = list.filter((x) => keyLess(x, k)); out = o.slice(-limit); hasMore = o.length > limit; } else if (query.after) { const k = cur(query.after); const n = list.filter((x) => keyLess(k, x)); out = n.slice(0, limit); hasMore = n.length > limit; } else if (query.around) {
        const k = cur(query.around);
        const half = Math.floor(limit / 2);
        const older = list.filter((x) => keyLess(x, k));
        const rest = list.filter((x) => !keyLess(x, k));
        const before = older.slice(-half);
        out = before.concat(rest.slice(0, limit - before.length));
        extra.hasMoreBefore = older.length > before.length;
        extra.hasMoreAfter = rest.length > limit - before.length;
        hasMore = extra.hasMoreBefore || extra.hasMoreAfter;
      } else if (query.changedSince) { const since = Date.parse(query.changedSince); out = list.filter((x) => x.changedAt > since); } else { out = list.slice(-limit); hasMore = list.length > limit; }
      return json(200, { ok: true, messages: out.map(msgView), hasMore, ...extra, ways: marks(), serverTime: iso(Date.now()) }), true;
    }
    if (seg.length === 3 && c === 'read' && method === 'POST') {
      people21.reads.push({ personId: p.id, upTo: body.upTo == null ? null : body.upTo });
      const k = body.upTo != null ? all.flatMap((x) => msgs.get(x.id)).find((m) => m.id === body.upTo) : null;
      const out = all.map((x) => {
        const mb = x.members.find((y) => y.id === ME);
        const upto = msgs.get(x.id).filter((m) => !k || !keyLess(k, m));
        mb.lastRead = Math.max(mb.lastRead, upto.length ? upto[upto.length - 1].id : 0);
        return { conversationId: x.id, way: wayName(x), lastReadId: mb.lastRead, unread: convView(x).unread };
      });
      return json(200, { ok: true, unread: out.reduce((s, x) => s + x.unread, 0), ways: out }), true;
    }
    if (seg.length === 3 && c === 'search' && method === 'GET') {
      const q = String(query.q || '').toLowerCase();
      return json(200, { ok: true, results: rows().filter((x) => (x.text || '').toLowerCase().includes(q)).reverse().map(msgView), scanned: rows().length, truncated: false }), true;
    }
    return json(404, { ok: false, code: 'not_found' }), true;
  }
  /** POST persons/:id/messages → the way it goes (the message it answers, else the way of the newest incoming). */
  function personSendWay(p, body) {
    const e = personEntry(p);
    const rq = body && body.replyTo ? p.ways.find((id) => msgs.get(id).some((m) => m.id === body.replyTo)) : null;
    const rw = rq && e.person.ways.find((x) => x.conversationId === rq && x.can.send);
    return rw || e.person.reply;
  }

  const userOut = (id) => { const u = users.find((x) => x.id === id) || {}; return { id, name: u.name || null, avatarUrl: null, initials: u.initials || null, colorHex: u.colorHex || null }; };
  const storyOut = (x, own) => ({
    id: x.id, kind: x.kind, text: x.text || null, bg: x.bg || null, font: x.font || null, mediaId: x.mediaId || null, thumbMediaId: x.thumbMediaId || null, video: x.video || null,
    url: null, thumbUrl: null, createdAt: iso(x.createdAt), expiresAt: iso(x.createdAt + (x.durationH || 24) * 3600000), seen: own ? true : x.seen.has(ME), place: x.place || null, eventMessageId: x.eventMessageId || null,
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
    if (a === 'status' && b === 'feed') {
      if (st14.feedFail) return json(503, { ok: false, code: 'unavailable' }), true;
      return json(200, { ok: true, ...feed() }), true;
    }
    if (a === 'status' && b === 'stories') {
      if (!c && method === 'POST') {
        log.stories.push(body);
        if (st14.storyFail) { const code = st14.storyFail; st14.storyFail = null; return json(code === 'too_many' ? 409 : 403, { ok: false, code, error: code }), true; }
        if (body.kind === 'text' && !body.text) return json(400, { ok: false, code: 'invalid' }), true;
        // 1.4.1: durationH only with story_duration, one of limits.storyDurationsH
        if (body.durationH !== undefined && !(features && features.story_duration === true && STORY_DURATIONS_H.includes(body.durationH))) return json(400, { ok: false, code: 'invalid' }), true;
        // the known fields only (no key of the request body is written into the stored story)
        const x = {
          id: st14.nextStory++, userId: ME, kind: body.kind, text: body.text, bg: body.bg, font: body.font, mediaId: body.mediaId, thumbMediaId: body.thumbMediaId,
          video: body.video, visibility: body.visibility, userIds: body.userIds, place: body.place, eventMessageId: body.eventMessageId, durationH: body.durationH || 24,
          createdAt: Date.now(), seen: new Set(), reactions: new Map(),
        };
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
  function handle({ method, route, query, raw, headers, drop }, json, send) {
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
    log.calls.push({ method, route: route.slice(apiBase.length), query: { ...query } });
    // 1.14: a chat over a bridge exists only for a client that says it knows them
    const bridged = query.bridged === '1' || body.bridged === true;
    // 1.21: persons — only for a client that knows them (?people=1 with ?bridged=1)
    const peopleOn = !!(features && features.chat_people === true) && bridged && (query.people === '1' || body.people === true);
    if (a === 'persons') {
      if (!peopleOn) return json(404, { ok: false, code: 'not_found' }), true;
      const seg = route.slice(apiBase.length).split('/');
      if (seg.length === 3 && c === 'messages' && method === 'POST') {
        const p = persons.get(Number(b));
        if (!p) return json(404, { ok: false, code: 'not_found' }), true;
        const w = personSendWay(p, body);
        const wrapped = (s, out, h) => json(s, s === 200 ? { ...out, way: w.way, conversationId: w.conversationId } : out, h);
        return handle({ method, route: `${apiBase}conversations/${w.conversationId}/messages`, query, raw, headers, drop }, wrapped, send);
      }
      return personRoute(method, seg, query, body, json);
    }
    if (contactsRoute(method, route.slice(apiBase.length).split('/'), query, json)) return true;
    if (bridgeRoute(method, route.slice(apiBase.length).split('/'), body, json, drop || (() => json(503, { ok: false, code: 'unavailable' })))) return true;

    if (a === 'me') {
      return json(200, {
        ok: true, user: { id: ME, name: 'Marc', avatarUrl: null, initials: 'MA', colorHex: '#2FBF71' },
        prefs: api.features14 ? (api.avatarProfile ? { ...st14.prefs, privacy: { ...st14.prefs.privacy, avatarProfile: api.avatarProfile } } : st14.prefs) : { readReceipts: true, typing: true, preview: true },
        // Messenger 1.22: „Wer sieht dein Bild?“ from the profile (ms.avatarProfile = 'contacts' …)
        ...(api.avatarProfile ? { avatarInProfile: true } : {}),
        ...(api.features14 ? { integrations: { familie: { lists: !!familie, calendar: !!familie, places: !!familie } } } : {}),
        license: { licensed: true, state: 'active', expiresAt: null },
        features: api.features || { direct: true, groups: true, voice: true, files: true, location: true, reactions: true, edit: true, search: true, disappearing: true, bridges: false, e2e: false },
        limits: { maxBytes: 25 * 1024 * 1024, types: ['image/webp', 'image/jpeg', 'image/png', 'audio/ogg', 'audio/webm', 'audio/mp4', 'video/webm', 'video/mp4', 'application/pdf'], quotaFull: false, editWindowS: 900, maxVoiceS: 300, textMax: 4000, thumbMaxBytes: 65536, imageMaxSide: 2048, groupMax: 256, titleMax: 80, pageMax: 100, typingS: 6, typingEveryS: 3, activeS: 30, disappearingS: [0, 86400, 604800, 2592000], retentionDays: 0, ...(api.features14 ? { statusTextMax: 60, storyTextMax: 700, ...(features && features.story_duration === true ? { storyDurationsH: STORY_DURATIONS_H } : {}), pollOptionsMax: 12, pollQuestionMax: 200, pollOptionMax: 80, eventTitleMax: 120, eventChecklistMax: 20, pinsMax: 3, listsMax: 20 } : {}) },
        serverTime: iso(Date.now()),
      }), true;
    }
    if (route14(method, route.slice(apiBase.length).split('/'), query, body, json)) return true;
    if (a === 'prefs') return json(200, { ok: true, prefs: { readReceipts: true, typing: true, preview: true, ...body } }), true;
    if (a === 'people') return json(200, { ok: true, people: users.filter((x) => x.id !== ME).map((x) => ({ id: x.id, name: x.name, avatarUrl: null, initials: x.initials, colorHex: x.colorHex, color: 'green', ...(api.features14 ? { ...presence(x.id), blocked: st14.blocks.has(x.id) } : {}) })) }), true;
    // 1.20: a client that knows channels (?channels=1) gets them on their own page
    const chans = chanWord() && (query.channels === '1' || body.channels === true);
    const chanList = () => [...convs.values()].filter((x) => isChan(x) && msgs.get(x.id).some((m) => !m.hidden)).map(convView);
    if (a === 'conversations' && !b && method === 'GET') {
      const since = query.since ? Date.parse(query.since) : null;
      const cl = chans && bridged ? chanList() : null;
      let list = [...convs.values()].filter((x) => (!since || x.updatedAt >= since) && (!x.bridge || (bridged && msgs.get(x.id).length)) && !(chans && isChan(x))).map(convView);
      // 1.21: one entry per person (the lead's id), the other ways `folded`
      let folded = null;
      if (peopleOn) {
        folded = [];
        const seen = new Set();
        list = list.flatMap((v) => {
          const pp = personOf(v.id);
          if (!pp) return [v];
          if (seen.has(pp.id)) { folded.push(v.id); return []; }
          seen.add(pp.id);
          const e = personEntry(pp);
          if (e.id !== v.id) folded.push(v.id);
          return [e];
        });
        for (const pp of persons.values()) { const lead = personEntry(pp).id; for (const id of pp.ways) if (id !== lead && !folded.includes(id)) folded.push(id); }
      }
      return json(200, { ok: true, conversations: list, removed: [], ...(folded ? { folded } : {}),
        ...(cl ? { channels: { count: cl.length, unread: cl.reduce((n, x) => n + x.unread, 0) } } : {}), serverTime: iso(Date.now()) }), true;
    }
    if (a === 'channels' && !b && method === 'GET') {
      if (!chans || !bridged) return json(404, { ok: false, code: 'not_found' }), true;
      const cl = chanList();
      return json(200, { ok: true, channels: cl, removed: [], unread: cl.reduce((n, x) => n + x.unread, 0), serverTime: iso(Date.now()) }), true;
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
      if (!conv || (conv.bridge && !bridged)) return json(404, { ok: false, code: 'not_found' }), true;
      const list = msgs.get(conv.id);
      // 1.21: a way of a person names it
      if (!c && method === 'GET') return json(200, { ok: true, conversation: { ...convView(conv), ...(peopleOn && personOf(conv.id) ? { person: personEntry(personOf(conv.id)).person } : {}) } }), true;
      if (!c && method === 'PATCH') {
        if (body.title) conv.title = body.title;
        if (body.notify === 'all' || body.notify === 'none') { conv.notify = body.notify; log.notifies = (log.notifies || []).concat({ id: conv.id, notify: body.notify }); }
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
        if (conv.bridge && conv.bridge.readOnly && chanWord()) return json(409, { ok: false, code: 'bridge_read_only', reason: conv.bridge.channel ? 'channel' : 'admins_only' }), true;
        if (conv.bridge) {
          const fileKind = bridge.media && ['image', 'voice', 'file'].includes(body.kind) && body.mediaId;
          if (!fileKind && ((body.kind != null && body.kind !== 'text') || ['mediaId', 'thumbMediaId', 'video', 'meta'].some((k) => body[k] != null))) return json(409, { ok: false, code: 'bridge_text_only', reason: 'kind' }), true;
          if (['location', 'poll', 'event', 'arrival', 'action', 'replyStory'].some((k) => body[k] != null)) return json(409, { ok: false, code: 'bridge_text_only', reason: 'kind' }), true;
          if (fileKind) {
            const fm = media.get(body.mediaId);
            if (!fm) return json(409, { ok: false, code: 'media_invalid' }), true;
            if (bridge.scanPending > 0) { bridge.scanPending -= 1; log.scanPending = (log.scanPending || 0) + 1; return json(423, { ok: false, code: 'scan_pending' }, { 'Retry-After': '1' }), true; }
            const k = body.kind === 'file' ? (/^video\//.test(fm.mime) ? 'video' : 'file') : body.kind;
            if (WA_MEDIA_TYPES[k] && !WA_MEDIA_TYPES[k].includes(fm.mime)) return json(409, { ok: false, code: 'bridge_media_type', reason: k }), true;
          }
          const st = conv.bridge.state;
          if (st === 'locked') return json(403, { ok: false, code: 'bridge_locked' }), true;
          if (st === 'off') return json(409, { ok: false, code: 'bridge_off', reason: 'off' }), true;
          if (st === 'unreachable') return json(503, { ok: false, code: 'bridge_unreachable', reason: 'not_running' }), true;
          if (st === 'logged_out' || st === 'unlinked') return json(409, { ok: false, code: 'bridge_unlinked', reason: st }), true;
          if (conv.bridge.closed) return json(502, { ok: false, code: 'bridge_failed', reason: 'chat_closed' }), true;
          const bm = addMsg(conv.id, { senderId: ME, text: body.text || null, clientId: body.clientId, replyTo: body.replyTo || null, ...(fileKind ? { kind: body.kind, mediaId: body.mediaId, meta: body.meta || null, video: body.video || null } : {}) });
          bm.bridge = { sender: null, remote: false, state: bridge.sendFails ? 'failed' : 'sent', reason: bridge.sendFails || null, placeholder: null };
          log.sent.push(body);
          emit('message.new', { conversationId: conv.id, messageId: bm.id, senderId: ME, clientId: bm.clientId, kind: bm.kind, createdAt: iso(bm.createdAt), bridge: conv.bridge.network });
          return json(200, { ok: true, message: msgView(bm), duplicate: false }), true;
        }
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
      if (!m || (convs.get(m.conversationId).bridge && !bridged)) return json(404, { ok: false, code: 'not_found' }), true;
      // 1.17: a file of the older history, fetched now
      if (c === 'fetch' && method === 'POST') {
        const ph = m.bridge && m.bridge.placeholder;
        // 1.19: a file that failed, once more (`retry: true`) — also without bridge_history
        const again = !!(ph && ph.state === 'failed' && ph.retry === true);
        if ((!again && !(features && features.bridge_history === true)) || !convs.get(m.conversationId).bridge) return json(404, { ok: false, code: 'not_found' }), true;
        log.fetches.push(m.id);
        if (bridge.fetchFails) { const f = bridge.fetchFails; bridge.fetchFails = null; return json(f.status, { ok: false, code: f.code }), true; }
        if (!ph || (ph.state !== 'on_request' && !again)) return json(400, { ok: false, code: 'invalid' }), true;
        m.bridge = { ...m.bridge, placeholder: { ...ph, state: 'loading' } };
        m.changedAt = Date.now();
        emit('message.update', { conversationId: m.conversationId, messageId: m.id, editedAt: iso(m.changedAt), media: true });
        return json(200, { ok: true, message: msgView(m) }), true;
      }
      if (c === 'resend' && method === 'POST') {
        if (!m.bridge || m.bridge.state !== 'failed') return json(400, { ok: false, code: 'invalid' }), true;
        log.resends.push(m.id);
        m.bridge = { ...m.bridge, state: bridge.sendFails ? 'failed' : 'sent', reason: bridge.sendFails || null };
        m.changedAt = Date.now();
        return json(200, { ok: true, message: msgView(m) }), true;
      }
      if (c === 'reaction') {
        const mc = convs.get(m.conversationId);
        if (mc.bridge && mc.bridge.channel && chanWord() && mc.bridge.reactions === 'off') return json(409, { ok: false, code: 'bridge_read_only', reason: 'reactions_off', error: 'Reagieren geht in Kanälen nicht: WhatsApp hat eine Reaktion abgelehnt.' }), true;
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
    /** Messenger 1.22: the level of „Wer sieht dein Bild?“ in the profile (null: an older messenger). */
    avatarProfile: null,
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
    /** The next story post fails with `code` (e.g. 'feature_off', 'too_many'). */
    failStory(code = 'feature_off') { st14.storyFail = code; },
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
    /** Messenger 1.13 / 1.14: the bridges' state (networks, the login in progress, sendFails, …). */
    bridge,
    addBridgeConv,
    addBridgeMsg,
    /** A contact's message arrives in a chat over a bridge (message.new with `bridge`). */
    receiveBridge(convId, opts = {}) {
      const m = addBridgeMsg(convId, opts);
      emit('message.new', { conversationId: convId, messageId: m.id, senderId: m.senderId, clientId: null, kind: m.kind, createdAt: iso(m.createdAt), bridge: convs.get(convId).bridge.network });
      return m;
    },
    /**
     * Messenger 1.15: the file of a placeholder arrived (message.update { media: true }): `kind`, `mediaId`, `meta`,
     * `video` of the message; the placeholder goes. `fail` instead: { reason } keeps it as failed.
     */
    bridgeFileArrived(messageId, { kind, mediaId, meta = null, video = null, fail = null } = {}) {
      const m = findMsg(messageId);
      if (fail) m.bridge.placeholder = { ...m.bridge.placeholder, state: 'failed', reason: fail.reason };
      else { Object.assign(m, { kind, mediaId, meta, video }); m.bridge.placeholder = null; }
      m.changedAt = Date.now();
      m.editedAt = null;
      emit('message.update', { conversationId: m.conversationId, messageId: m.id, editedAt: iso(m.changedAt), media: true });
      return m;
    },
    /**
     * Messenger 1.17: older messages of the history were filed into a chat at night (no message.new, no push, read):
     * `list` of addBridgeMsg options (+ `at`: its own time in the past); one conversation.update { reason: history }.
     */
    historyArrived(convId, list) {
      const added = list.map(({ at, ...o }) => { const m = addBridgeMsg(convId, o); if (at) m.createdAt = at; return m; });
      const c = convs.get(convId);
      const mb = c.members.find((x) => x.id === ME);
      if (mb) mb.lastRead = Math.max(mb.lastRead, ...added.map((m) => m.id));
      emit('conversation.update', { conversationId: convId, reason: 'history' });
      return added;
    },
    /** Messenger 1.15: the picture of a chat over a bridge (the contact's, the group's). */
    setBridgeAvatar(convId, mediaId) {
      const c = convs.get(convId);
      c.avatarMediaId = mediaId;
      c.updatedAt = Date.now();
      emit('conversation.update', { conversationId: convId, reason: 'avatar' });
    },
    /** The state of a chat's bridge changed (unreachable, logged_out, …; `closed`). */
    setBridgeState(convId, patch) {
      const c = convs.get(convId);
      Object.assign(c.bridge, patch);
      c.updatedAt = Date.now();
      emit('conversation.update', { conversationId: convId, reason: 'bridge' });
    },
    /** The other side got / read Marc's messages up to `upTo` (the bridge's word). */
    bridgeRead(convId, upTo, { read = true } = {}) {
      const c = convs.get(convId);
      c.bridge.deliveredUpTo = upTo;
      if (read) c.bridge.readUpTo = upTo;
      for (const m of msgs.get(convId)) if (m.senderId === ME && m.id <= upTo && m.bridge && m.bridge.state !== 'failed') { m.bridge.state = read ? 'read' : 'delivered'; m.changedAt = Date.now(); }
      c.updatedAt = Date.now();
      emit('read', { conversationId: convId, userId: null, lastReadId: read ? upTo : null, lastDeliveredId: upTo, readUpTo: c.bridge.readUpTo, deliveredUpTo: c.bridge.deliveredUpTo });
    },
    /** Contacts of a chat over a bridge are typing (userId null). */
    bridgeTyping(convId, contacts = [{ contactId: 12, name: 'Kim Muster' }]) {
      emit('typing', { conversationId: convId, userId: null, contacts, until: contacts.length ? iso(Date.now() + 6000) : null });
    },
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
    // 1.21: persons, suggestions, the consent of the own WhatsApp
    addPerson,
    persons,
    people21,
    /** A message of a contact at a moment (ms) — the order of a person's ways is by time. */
    at(m, ms) { m.createdAt = ms; m.changedAt = ms; return m; },
    handle,
  };
  return api;
}

module.exports = { createMessenger, PLUGIN, FEATURES_14, FEATURES_141, FEATURES_LINKED, FEATURES_BRIDGED, FEATURES_STAGE4, FEATURES_STAGE5, FEATURES_STAGE4C, FEATURES_V2A, FEATURES_V2B, FEATURES_V127 };
