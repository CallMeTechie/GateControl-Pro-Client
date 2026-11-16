/**
 * GateControl -- Chats view state (renderer, no DOM access)
 *
 * Pure helpers for the page "Chats" (GateControl Messenger): names, titles,
 * list previews, system message texts, "schreibt …", ticks, the timeline
 * with day separators and the unread line, edit/delete windows, mute and
 * disappearing options, error texts, voice-recording helpers, video files
 * (frame time, preview sizes, media filters), Messenger 1.4.0 (status and
 * stories, polls, events, live arrivals, home actions and plugin cards,
 * chat filters and archive, last seen). Loaded as a
 * plain script before chat-view.js (window.GCChatState) and required by the
 * node tests (test/chat-state.test.js).
 *
 * Messenger 1.21 (chat_people): persons — one entry for several ways of a
 * human (`person`): its ways, the way of an answer, a way's view of the entry
 * (wayConv / sendConv / msgConv) for the composer and the bubbles.
 *
 * Inputs are what window.gatecontrol.chat returns (core MessengerService:
 * conversations, messages, status().me); `t` is the i18n function (keys
 * chat.* of the core locales). The same file is used by Pro and Community.
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCChatState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const DAY = 86400000;
	const EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🙏'];
	const COLOR_RE = /^#[0-9a-fA-F]{6}$/;

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	// Messenger 1.11: the host's virus scan (scan-state.js; absent in an app without it: nothing shown)
	const SCAN = (typeof self !== 'undefined' && self.GCScanState) || (typeof require === 'function' ? (() => { try { return require('./scan-state'); } catch { return null; } })() : null);
	const localeTag = (locale) => (locale === 'en' ? 'en-GB' : 'de-DE');

	/** Person (member / peer / people entry) of a conversation by user id. */
	function member(c, uid) {
		if (!c || !Array.isArray(c.members)) return null;
		return c.members.find((m) => m && m.userId === uid) || null;
	}

	/**
	 * Display name of a user in a conversation. ctx: { me, people, t }.
	 * opts.you=false → own name instead of "Du".
	 */
	function nameOf(c, uid, ctx, opts = {}) {
		const t = ctx.t;
		if (uid === null || uid === undefined) return 'GateControl';
		const meId = ctx.me && ctx.me.user ? ctx.me.user.id : null;
		if (uid === meId) return opts.you === false ? (ctx.me.user.name || t('chat.you')) : t('chat.you');
		const m = member(c, uid);
		if (m && m.name) return m.name;
		const p = Array.isArray(ctx.people) ? ctx.people.find((x) => x && x.id === uid) : null;
		if (p && p.name) return p.name;
		return t('chat.gone');
	}

	function title(c, t) {
		if (!c) return '';
		if (c.title) return String(c.title);
		// Messenger 1.14: a contact of another messenger whose name is not known
		if (bridgeOf(c)) return t('chat.bc.unknown_contact');
		return c.kind === 'direct' ? t('chat.gone') : t('chat.group');
	}

	/** Avatar description for the view: { kind: 'icon'|'person', icon?, name, initials, color, avatarUrl, mediaId }. */
	function avatarOf(c) {
		if (!c) return { kind: 'icon', icon: 'group' };
		// Messenger 1.21: a person — the picture of the way its name comes from (else of another way), no service sign
		if (isPerson(c)) {
			const peer = c.peer && !c.peer.gone ? c.peer : null;
			const mediaId = typeof c.avatarMediaId === 'string' && c.avatarMediaId ? c.avatarMediaId : null;
			return { ...personAvatar({ name: c.title, avatarUrl: c.avatarUrl || null, initials: c.person.nameFrom === 'account' && peer ? peer.initials : null, colorHex: peer ? peer.colorHex : null }), ...(mediaId ? { mediaId } : {}) };
		}
		// Messenger 1.14: a chat over a bridge has no peer — the contact's initials, a group's sign; 1.15: the contact's
		// picture (`avatarMediaId`) once the server fetched it
		if (bridgeOf(c) && c.kind !== 'group') {
			const mediaId = typeof c.avatarMediaId === 'string' && c.avatarMediaId ? c.avatarMediaId : null;
			const pic = mediaId ? { mediaId } : {};
			return c.title ? { ...personAvatar({ name: c.title }), ...pic } : { kind: 'icon', icon: 'gone', ...pic };
		}
		if (c.kind === 'group') return { kind: 'icon', icon: c.readonly ? 'system' : 'group', mediaId: c.avatarMediaId || null };
		const p = c.peer;
		if (!p || p.gone) return { kind: 'icon', icon: 'gone' };
		return personAvatar(p);
	}

	function personAvatar(p) {
		return {
			kind: 'person',
			name: str(p.name),
			// the server's initials: letters and digits only, whole characters
			initials: letters(p.initials).slice(0, 3).join('') || initials(p.name),
			color: COLOR_RE.test(str(p.colorHex)) ? p.colorHex : '#64748B',
			avatarUrl: typeof p.avatarUrl === 'string' ? p.avatarUrl : null,
		};
	}

	// whole characters, letters and digits only: an emoji is never cut in half („Schatzimausi 💕“ showed „S“ and a
	// replacement mark) and never an initial
	const INI_RE = /[\p{L}\p{N}](?:(?![\uFE00-\uFE0F])\p{M})*/gu;
	function letters(w) { return String(w || '').normalize('NFC').match(INI_RE) || []; }
	/** „Schatzimausi 💕“ → „S“, „van der Berg“ → „VB“, „Kim“ → „KI“, only emoji / nothing → „?“. */
	function initials(name) {
		const parts = str(name).trim().split(/\s+/).filter(Boolean);
		const out = parts.length > 1 ? (letters(parts[0])[0] || '') + (letters(parts[parts.length - 1])[0] || '') : letters(parts[0]).slice(0, 2).join('');
		return out.toUpperCase() || '?';
	}

	// Messenger 1.23: a timer of another messenger (Signal) may hold any number of seconds — the largest whole unit
	const DIS_UNITS = [['weeks', 604800], ['days', 86400], ['hours', 3600], ['minutes', 60]];

	function disLabel(s, t) {
		if (!s) return t('chat.dis.off');
		const key = `chat.dis.${s}`;
		const v = t(key);
		if (v !== key) return v;
		const u = Number.isSafeInteger(s) && s > 0 ? DIS_UNITS.find(([, n]) => s % n === 0) : null;
		return u ? t(`chat.dis.${u[0]}`, { n: s / u[1] }) : t('chat.dis.seconds', { n: s });
	}

	/** Text of a system message (`kind: system`), like the portal. */
	function systemText(m, c, ctx) {
		const t = ctx.t;
		const s = (m && m.system) || {};
		const by = s.by === undefined ? null : s.by;
		const who = by === null ? 'GateControl' : nameOf(c, by, ctx);
		const names = (Array.isArray(s.userIds) ? s.userIds : []).map((u) => nameOf(c, u, ctx)).join(', ');
		switch (s.event) {
			case 'created': return t('chat.sys.created', { name: who, title: s.title || title(c, t) });
			case 'member_added': return t('chat.sys.added', { name: who, names });
			case 'member_removed': return t('chat.sys.removed', { name: who, names });
			case 'member_left': return t('chat.sys.left', { name: nameOf(c, s.userId, ctx) });
			case 'title': return t('chat.sys.title', { name: who, title: s.title || '' });
			case 'avatar': return t('chat.sys.avatar', { name: who });
			// Messenger 1.23: changed in the other messenger (Signal) — `network`, nobody of GateControl did it
			case 'disappearing':
				if (by === null && s.network) {
					const network = bridgeName(s.network);
					return s.seconds ? t('chat.sys.disOnNet', { network, time: disLabel(s.seconds, t) }) : t('chat.sys.disOffNet', { network });
				}
				return s.seconds ? t('chat.sys.disOn', { name: who, time: disLabel(s.seconds, t) }) : t('chat.sys.disOff', { name: who });
			// Messenger 1.1.0: the plugin handed its managed group over.
			case 'released': return t('chat.sys.released');
			// Messenger 1.4.0
			case 'poll_closed': {
				const q = str(s.question);
				const result = s.winner ? t('chat.sys.pollWinner', { winner: s.winner }) : t('chat.sys.pollTie');
				return by === null ? t('chat.sys.pollClosedAuto', { question: q, result }) : t('chat.sys.pollClosed', { name: who, question: q, result });
			}
			case 'event_cancelled': return t('chat.sys.eventCancelled', { name: who, title: str(s.title) });
			case 'arrived': return t('chat.sys.arrived', { name: nameOf(c, s.userId, ctx), label: str(s.label) });
			case 'action_run': return s.asUserId && s.asUserId !== s.userId
				? t('chat.sys.actionRunAs', { name: nameOf(c, s.userId, ctx), label: str(s.label), as: nameOf(c, s.asUserId, ctx) })
				: t('chat.sys.actionRun', { name: nameOf(c, s.userId, ctx), label: str(s.label) });
			case 'action_denied': return t('chat.sys.actionDenied', { name: who, label: str(s.label) });
			// Messenger 1.14: a note of the bridge itself — under the service's name, not GateControl's
			case 'bridge_notice': return [t('chat.bc.notice', { network: bridgeLabel(c) || bridgeName(s.network) }), str(m && m.text)].filter(Boolean).join(': ');
			default: return str(m && m.text) || t('chat.sys.unknown');
		}
	}

	function duration(ms) {
		const s = Math.max(0, Math.round((Number(ms) || 0) / 1000));
		return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
	}

	/** Does the server offer a feature (`GET me` features: flags or a list of names)? */
	function hasFeature(me, name) {
		const f = me && me.features;
		if (Array.isArray(f)) return f.includes(name);
		return !!f && typeof f === 'object' && f[name] === true;
	}

	const isVideoMime = (m) => /^video\//i.test(str(m));

	/**
	 * A video file (Messenger 1.3.0 `video`, or a `video/*` file of an older
	 * server): { durationMs, width, height } (null where unknown), or null.
	 */
	function videoInfo(m) {
		if (!m || m.kind !== 'file' || m.deleted) return null;
		const v = (m.video && typeof m.video === 'object' && m.video) || (m.meta && m.meta.video && typeof m.meta.video === 'object' && m.meta.video) || null;
		if (!v && !isVideoMime(m.media && m.media.mime)) return null;
		const num = (x) => (Number.isFinite(Number(x)) && Number(x) > 0 ? Number(x) : null);
		const src = v || {};
		return { durationMs: num(src.durationMs), width: num(src.width), height: num(src.height) };
	}

	/** Second of a video whose frame becomes the preview: ~1 s, the middle of shorter ones. */
	function videoFrameTime(durationS) {
		const d = Number(durationS);
		if (!Number.isFinite(d) || d <= 0) return 0;
		return d >= 2 ? 1 : d / 2;
	}

	/** Attempts for a preview ≤ 64 KB: [long side, WebP quality], smaller each time. */
	const THUMB_STEPS = [[640, 0.72], [640, 0.55], [480, 0.5], [360, 0.45], [240, 0.4]];

	/** THUMB_STEPS with the long side capped at the server's limits.thumbMaxSide (default 640). */
	function thumbSteps(maxSide) {
		const cap = Number(maxSide) > 0 ? Math.floor(Number(maxSide)) : 640;
		const out = [];
		for (const [side, q] of THUMB_STEPS) {
			const s = Math.min(side, cap);
			if (!out.some(([a, b]) => a === s && b === q)) out.push([s, q]);
		}
		return out;
	}

	/** The "newer version of GateControl" banner: status().updateHint while available, else null. */
	function updateHint(st) {
		const h = st && st.state === 'available' ? st.updateHint : null;
		return h && Array.isArray(h.features) && h.features.length ? h : null;
	}

	/** Filters of the media list in the chat info: Fotos, Videos (when the server has them), Dateien. */
	function mediaFilters(me, counts) {
		const video = hasFeature(me, 'video_meta') || !!(counts && Number.isFinite(counts.video));
		return video ? ['image', 'video', 'file'] : ['image', 'file'];
	}

	/** Shared media in all (counts of GET …/media). */
	function mediaTotal(counts) {
		const c = counts || {};
		return ['image', 'voice', 'file', 'video'].reduce((n, k) => n + (Number(c[k]) || 0), 0);
	}

	/** One line about a message (list preview, quotes, search results). */
	function summary(m, c, ctx) {
		const t = ctx.t;
		if (!m) return '';
		if (m.deleted) return m.mine ? t('chat.msg.deletedMine') : t('chat.msg.deleted');
		if (m.undecryptable) return t('chat.msg.undecryptable');
		// Messenger 1.14: a file or kind of message that does not cross the bridge yet
		const ph = placeholderText(m, c, t);
		if (ph) return ph + (m.text ? `: ${m.text}` : '');
		switch (m.kind) {
			case 'image': return t('chat.kind.image') + (m.text ? `: ${m.text}` : '');
			case 'voice': return t('chat.kind.voice') + (m.meta && m.meta.durationMs != null ? ` · ${duration(m.meta.durationMs)}` : '');
			case 'file': {
				const v = videoInfo(m);
				if (v) return t('chat.kind.video') + (v.durationMs ? ` · ${duration(v.durationMs)}` : '') + (m.text ? `: ${m.text}` : '');
				return (m.meta && m.meta.fileName) || t('chat.kind.file');
			}
			case 'location': return t('chat.kind.location') + (m.location && m.location.label ? `: ${m.location.label}` : '');
			case 'system': return systemText(m, c, ctx);
			// Messenger 1.4.0
			case 'poll': return `📊 ${t('chat.kind.poll')}: ${str(m.poll && m.poll.question)}`;
			case 'event': return `📅 ${t('chat.kind.event')}: ${str(m.event && m.event.title)}`;
			case 'arrival': return `📍 ${t('chat.kind.arrival')}: ${str(m.arrival && m.arrival.dest && m.arrival.dest.label)}`;
			case 'action': return `${t('chat.kind.action')}: ${str(m.action && m.action.label)}`;
			case 'card': return m.card ? [m.card.title, m.card.text || m.text].filter(Boolean).join(': ') : str(m.text);
			case 'text': return str(m.text);
			default: return SHOWN_KINDS.includes(m.kind) ? str(m.text) : t('chat.msg.unsupported');
		}
	}

	function typingText(c, ctx) {
		// Messenger 1.21: a person writes on one of its ways
		if (isPerson(c)) return (Array.isArray(c.typingContacts) && c.typingContacts.length) || (Array.isArray(c.typing) && c.typing.length) ? ctx.t('chat.typing') : null;
		// Messenger 1.14: contacts of a chat over a bridge (`typingContacts`)
		if (bridgeOf(c)) {
			const who = Array.isArray(c.typingContacts) ? c.typingContacts : [];
			if (!who.length) return null;
			if (c.kind !== 'group') return ctx.t('chat.typing');
			if (who.length === 1) return ctx.t('chat.typingOne', { name: who[0].name || ctx.t('chat.bc.unknown_contact') });
			return ctx.t('chat.typingMany', { n: who.length });
		}
		const ids = Array.isArray(c && c.typing) ? c.typing : [];
		if (!ids.length) return null;
		if (c.kind === 'direct') return ctx.t('chat.typing');
		if (ids.length === 1) return ctx.t('chat.typingOne', { name: nameOf(c, ids[0], ctx) });
		return ctx.t('chat.typingMany', { n: ids.length });
	}

	/** Second line of a chat in the list. */
	function preview(c, ctx) {
		const typing = typingText(c, ctx);
		if (typing) return { text: typing, typing: true };
		const m = c.lastMessage;
		if (!m) return { text: c.kind === 'group' ? ctx.t('chat.groupNew') : ctx.t('chat.chatNew'), typing: false };
		const s = summary(m, c, ctx);
		if (m.kind === 'system') return { text: s, typing: false };
		if (m.mine) return { text: `${ctx.t('chat.you')}: ${s}`, typing: false };
		// Messenger 1.6 notice channel: everything in it comes from GateControl
		if (isNotice(c)) return { text: s, typing: false };
		// Messenger 1.20: a channel writes everything itself
		if (isChannel(c)) return { text: s, typing: false };
		if (c.kind === 'group') return { text: `${senderName(m, c, ctx)}: ${s}`, typing: false };
		return { text: s, typing: false };
	}

	function dayStart(d) {
		return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
	}

	function hm(iso, locale) {
		const d = new Date(iso);
		return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString(localeTag(locale), { hour: '2-digit', minute: '2-digit' });
	}

	/** List time: "17:44" today, "Gestern", weekday within a week, else "12.10.". */
	function listTime(iso, ctx, now = Date.now()) {
		if (!iso) return '';
		const d = new Date(iso);
		if (Number.isNaN(d.getTime())) return '';
		const diff = Math.round((dayStart(new Date(now)) - dayStart(d)) / DAY);
		if (diff <= 0) return hm(iso, ctx.locale);
		if (diff === 1) return ctx.t('chat.rel.yesterday');
		if (diff < 7) return d.toLocaleDateString(localeTag(ctx.locale), { weekday: 'short' });
		return d.toLocaleDateString(localeTag(ctx.locale), { day: '2-digit', month: '2-digit' });
	}

	/** Day separator: "Heute", "Gestern", "Mittwoch, 14. Oktober". */
	function dayLabel(iso, ctx, now = Date.now()) {
		const d = new Date(iso);
		if (Number.isNaN(d.getTime())) return '';
		const n = new Date(now);
		const diff = Math.round((dayStart(n) - dayStart(d)) / DAY);
		if (diff <= 0) return ctx.t('chat.rel.today');
		if (diff === 1) return ctx.t('chat.rel.yesterday');
		return d.toLocaleDateString(localeTag(ctx.locale), {
			weekday: 'long', day: 'numeric', month: 'long', year: d.getFullYear() === n.getFullYear() ? undefined : 'numeric',
		});
	}

	function when(iso, locale) {
		const d = new Date(iso);
		if (!iso || Number.isNaN(d.getTime())) return '–';
		return `${d.toLocaleDateString(localeTag(locale), { day: '2-digit', month: '2-digit', year: 'numeric' })} ${hm(iso, locale)}`;
	}

	function bytes(n, locale) {
		let v = Number(n) || 0;
		const units = ['B', 'KB', 'MB', 'GB'];
		let i = 0;
		while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
		const s = i === 0 ? String(Math.round(v)) : v.toLocaleString(localeTag(locale), { maximumFractionDigits: v < 10 ? 1 : 0 });
		return `${s} ${units[i]}`;
	}

	/** Ticks of an own message: 'pending'|'failed'|'sent'|'delivered'|'read'|null. */
	function status(m, c) {
		if (!m) return null;
		// Messenger 1.21: a message of a person — the ticks of its way (GateControl's marks, a bridge's own state)
		if (isPerson(c)) return status(m, msgConv(c, m));
		if (m.pending) return m.failed ? 'failed' : 'pending';
		if (!m.mine || m.kind === 'system') return null;
		// Messenger 1.14, a chat over a bridge: what the other messenger said about this very message
		const bs = m.bridge && typeof m.bridge === 'object' ? m.bridge.state : null;
		if (bs === 'failed' || m.status === 'failed') return 'failed';
		if (bs === 'pending' || m.status === 'sending') return 'pending';
		const read = c && Number.isSafeInteger(c.readUpTo) ? c.readUpTo : null;
		const delivered = c && Number.isSafeInteger(c.deliveredUpTo) ? c.deliveredUpTo : null;
		if (read !== null && m.id <= read) return 'read';
		if (delivered !== null && m.id <= delivered) return 'delivered';
		if (m.status === 'read' || m.status === 'delivered') return m.status;
		return 'sent';
	}

	function withinWindow(m, limits, now = Date.now()) {
		const w = ((limits && limits.editWindowS) || 0) * 1000;
		return w > 0 && now - new Date(m.createdAt).getTime() <= w;
	}

	/** What the message menu offers. */
	function messageActions(m, c0, ctx, now = Date.now()) {
		// Messenger 1.21: what a message of a person allows is what its way allows
		const c = isPerson(c0) ? msgConv(c0, m) : c0;
		const limits = (ctx.me && ctx.me.limits) || {};
		const features = (ctx.me && ctx.me.features) || {};
		if (!m || m.pending) return { reply: false, react: false, edit: false, deleteMe: false, deleteAll: false, copy: false, pin: false, pinned: false, remind: false, suggest: false };
		const live = !m.deleted && m.kind !== 'system';
		const canSend = !!(c && c.can && c.can.send);
		// Messenger 1.14, a chat over a bridge: only what crosses (`bridge.supports`); nothing on a message that was not
		// sent (it offers „Erneut senden“), no edit of one written in the messenger's own app
		const b = bridgeOf(c);
		const mb = (m.bridge && typeof m.bridge === 'object' && m.bridge) || {};
		const notSent = !!b && m.mine && (mb.state === 'failed' || mb.state === 'pending');
		const crosses = (what) => !b || (!notSent && Array.isArray(b.supports) && b.supports.includes(what));
		return {
			reply: live && canSend && crosses('reply'),
			// Messenger 1.20: a channel or a group where only admins write — no answer, but a reaction (`can.react`; in a
			// channel the person's own, until the bridge refused one)
			react: live && features.reactions !== false && crosses('reaction')
				&& (b && c.can && c.can.react === false ? false : (canSend || (!!b && !!(c.can && c.can.react) && !m.mine && mb.state !== 'failed'))),
			copy: live && !!m.text,
			edit: live && m.mine && ['text', 'image', 'file'].includes(m.kind) && features.edit !== false && withinWindow(m, limits, now)
				&& (!b || (m.kind === 'text' && !mb.remote && !mb.placeholder && canSend && crosses('edit'))),
			deleteMe: true,
			deleteAll: live && m.mine && withinWindow(m, limits, now) && (!b || notSent || (canSend && crosses('delete'))),
			// Messenger 1.4.0 (msg_tools): pin (can.pin), "Erinnere mich", suggestions to Familie
			pin: live && hasFeature(ctx.me, 'msg_tools') && !!(c && c.can && c.can.pin),
			pinned: !!(c && Array.isArray(c.pinned) && c.pinned.includes(m.id)),
			remind: live && hasFeature(ctx.me, 'msg_tools'),
			suggest: live && hasFeature(ctx.me, 'msg_tools') && !!m.text && (familie(ctx.me).lists || familie(ctx.me).calendar),
		};
	}

	/**
	 * Timeline of a chat: day separators, the unread line (first message of
	 * others after me.lastReadId, when the chat had unread messages on
	 * opening), consecutive messages of the same sender grouped (`cont`).
	 * → [{ type: 'day', label } | { type: 'unread' } | { type: 'msg', m, cont, status }]
	 */
	function timeline(messages, pending, c, ctx, { unreadFrom = null, now = Date.now() } = {}) {
		const out = [];
		const all = (Array.isArray(messages) ? messages : []).concat(Array.isArray(pending) ? pending : []);
		let lastDay = null;
		let prev = null;
		let unreadShown = false;
		for (const m of all) {
			const d = new Date(m.createdAt || now);
			const dk = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
			if (dk !== lastDay) {
				out.push({ type: 'day', label: dayLabel(m.createdAt || new Date(now).toISOString(), ctx, now) });
				lastDay = dk;
				prev = null;
			}
			if (!unreadShown && unreadFrom !== null && !isPerson(c) && !m.pending && !m.mine && m.id > unreadFrom && m.kind !== 'system') {
				out.push({ type: 'unread' });
				unreadShown = true;
				prev = null;
			}
			const cont = !!prev && prev.kind !== 'system' && m.kind !== 'system' && senderKey(prev) === senderKey(m)
				&& !!prev.mine === !!m.mine && (new Date(m.createdAt) - new Date(prev.createdAt)) < 5 * 60000;
			out.push({ type: 'msg', m, cont, status: status(m, c) });
			prev = m;
		}
		return out;
	}

	/** Chat list filtered by the search field (title, preview, member names). */
	function filterConversations(list, q, ctx) {
		const items = Array.isArray(list) ? list : [];
		const s = str(q).trim().toLowerCase();
		if (!s) return items;
		return items.filter((c) => {
			if (title(c, ctx.t).toLowerCase().includes(s)) return true;
			if (preview(c, ctx).text.toLowerCase().includes(s)) return true;
			// Messenger 1.21: a person is found by every name it has („Schatz“ and „Jenny“)
			if (isPerson(c) && Array.isArray(c.person.names) && c.person.names.some((n) => str(n).toLowerCase().includes(s))) return true;
			return Array.isArray(c.members) && c.members.some((m) => m && str(m.name).toLowerCase().includes(s));
		});
	}

	/** Mute select value: 'off' | 'until' | 'always'. */
	function muteValue(c, now = Date.now()) {
		const me = (c && c.me) || {};
		if (me.notify === 'none') return 'always';
		if (me.mutedUntil && new Date(me.mutedUntil).getTime() > now) return 'until';
		return 'off';
	}

	/** PATCH body for a mute choice ('off' | '8h' | '1w' | 'always'), or null. */
	function mutePatch(value, now = Date.now()) {
		if (value === 'always') return { notify: 'none', mutedUntil: null };
		if (value === 'off') return { notify: 'all', mutedUntil: null };
		if (value === '8h') return { notify: 'all', mutedUntil: new Date(now + 8 * 3600000).toISOString() };
		if (value === '1w') return { notify: 'all', mutedUntil: new Date(now + 7 * DAY).toISOString() };
		return null;
	}

	/** Header sub line: typing, members, direct / channel. */
	function headSub(c, ctx) {
		const typing = typingText(c, ctx);
		if (typing) return { text: typing, typing: true };
		if (!c) return { text: '', typing: false };
		// Messenger 1.21: the ways of a person („GateControl · WhatsApp“, with their logos)
		if (isPerson(c)) return { text: personSub(c), typing: false, person: true };
		// Messenger 1.20: „Kanal · WhatsApp“
		if (isChannel(c)) return { text: ctx.t('chat.ch.sub', { network: bridgeLabel(c) }), typing: false };
		// Messenger 1.14: „über WhatsApp“
		if (bridgeOf(c)) return { text: ctx.t('chat.bc.via', { network: bridgeLabel(c) }), typing: false };
		// Messenger 1.6 notice channel: "Mitteilungen von Schule – nur für dich"
		if (isNotice(c) && noticeLabel(c)) return { text: ctx.t('chat.notice.infoSub', { source: noticeLabel(c) }), typing: false };
		if (c.readonly) return { text: ctx.t('chat.channelSub'), typing: false };
		if (c.kind === 'group') {
			const meId = ctx.me && ctx.me.user ? ctx.me.user.id : null;
			const names = (c.members || []).map((m) => (m.userId === meId ? ctx.t('chat.you') : (m.name || ctx.t('chat.gone'))));
			return { text: names.join(', '), typing: false };
		}
		if (c.peer && c.peer.gone) return { text: ctx.t('chat.peerGone'), typing: false };
		// Messenger 1.4.0 (privacy2): online / last seen as the person allows it
		const seen = lastSeenText(c.peer, ctx);
		if (seen) return { text: seen, typing: false, online: !!(c.peer && c.peer.online) };
		return { text: ctx.t('chat.directSub'), typing: false };
	}

	/** Why the composer is closed: null | 'readonly' | 'peerGone'. */
	function composerBlock(c0) {
		// Messenger 1.21: a person — the composer of the way the answer takes
		const c = isPerson(c0) ? sendConv(c0) : c0;
		if (!c) return 'readonly';
		// Messenger 1.14: a chat over a bridge that takes nothing right now (bridgeBlock says why)
		// Messenger 1.20: a channel (only the channel writes), a group where only admins write (while the bridge runs)
		if (bridgeOf(c) && c.can && c.can.send === false && c.can.sendReason === 'channel') return 'channel';
		if (bridgeOf(c) && c.can && c.can.send === false && c.can.sendReason === 'admins_only' && bridgeOf(c).state === 'ok' && !bridgeOf(c).closed) return 'admins_only';
		if (bridgeOf(c)) return c.can && c.can.send === false ? 'bridge' : null;
		if (c.readonly) return 'readonly';
		if (c.kind === 'direct' && c.peer && c.peer.gone) return 'peerGone';
		if (c.kind === 'direct' && c.peer && c.peer.blocked) return 'blocked';
		if (c.can && c.can.send === false) return 'readonly';
		return null;
	}

	/** Short label for a file card: "PDF", "ZIP", … */
	function fileBadge(name, mime) {
		const n = str(name);
		const i = n.lastIndexOf('.');
		if (i > 0 && n.length - i <= 6) return n.slice(i + 1).toUpperCase();
		const m = str(mime).split('/')[1];
		return m ? m.split(/[.+;-]/)[0].slice(0, 4).toUpperCase() : 'FILE';
	}

	/** Error text for a code of the core / plugin. */
	function errorText(res, t) {
		const code = res && typeof res === 'object' ? res.code : res;
		// Messenger 1.11: 423 quarantined | scan_pending | scan_blocked of a file, 422 infected, 503 scan_unavailable
		const scanText = SCAN ? SCAN.refusalText(res && typeof res === 'object' ? res : { code }, t) : null;
		if (scanText) return scanText;
		// Messenger 1.20: 409 bridge_read_only — reacting in channels went off (the bridge refused a reaction)
		if (code === 'bridge_read_only' && res && typeof res === 'object' && res.reason === 'reactions_off') return t('chat.error.reactions_off');
		if (code) {
			const key = `chat.error.${code}`;
			const v = t(key);
			if (v !== key) return v;
		}
		return t('chat.error.failed');
	}

	/**
	 * Messenger 1.11: the file of a message and the virus scan → null (nothing to show) or { kind, blocked, warn, title,
	 * text }. Blocked (the receiver's and the sender's view): „Wird auf Viren geprüft …“ / „Datei gesperrt“ with the
	 * reason instead of picture, player or file; marked: a warning line under the file.
	 */
	function mediaScan(m, t) {
		const scan = m && m.media && m.media.scan;
		const kind = SCAN ? SCAN.view(scan) : null;
		if (!kind) return null;
		const finding = scan.finding ? str(scan.finding).slice(0, 200) : '';
		const out = { kind, blocked: SCAN.isBlocked(scan), warn: kind === 'warning', title: '', text: '' };
		switch (kind) {
			case 'checking': out.title = t('scan.checking'); out.text = t('ui.scan.afterCheck'); break;
			case 'malware': out.title = t('scan.fileBlocked'); out.text = finding ? t('ui.scan.foundOf', { finding }) : t('ui.scan.found'); break;
			case 'unscannable': out.title = t('scan.scanBlocked'); break;
			case 'warning': out.text = SCAN.reason(scan, t); break;
			case 'notCheckable': out.text = t('scan.notCheckable'); break;
			default: out.title = t('scan.fileBlocked');
		}
		return out;
	}

	/**
	 * Messenger 1.11: a message the host refused because of its file (422 infected, 423 scan_blocked) → { text, retry: false }
	 * („Nicht gesendet – Schadsoftware gefunden“, never sent again); else null.
	 */
	function notSentText(m, t) {
		const code = m && m.error;
		if (code === 'infected') return m.finding ? t('scan.notSentOf', { finding: str(m.finding).slice(0, 200) }) : t('scan.notSent');
		if (code === 'scan_blocked') return t('scan.notSentUnscannable');
		return null;
	}

	/** Text for an unavailable messenger (status().reason). */
	function unavailableText(st, t) {
		const reason = st && st.reason;
		const key = `chat.unavailable.${reason}`;
		const v = t(key);
		return v !== key ? v : t('chat.unavailable.not_installed');
	}

	/** Peak levels of a recording reduced to n bars (0…255). */
	function waveform(levels, n) {
		const list = Array.isArray(levels) ? levels : [];
		if (!list.length || n <= 0) return [];
		const out = [];
		const step = list.length / n;
		for (let i = 0; i < n; i++) {
			const a = Math.floor(i * step);
			const b = Math.max(a + 1, Math.floor((i + 1) * step));
			let mx = 0;
			for (let k = a; k < b && k < list.length; k++) mx = Math.max(mx, list[k]);
			out.push(Math.max(0, Math.min(255, Math.round(mx))));
		}
		return out;
	}

	/** MediaRecorder type the server accepts (limits.types), or null. */
	function recordingMime(isTypeSupported, types) {
		const allowed = Array.isArray(types) ? types : [];
		for (const m of ['audio/ogg;codecs=opus', 'audio/webm;codecs=opus', 'audio/mp4', 'audio/webm', 'audio/ogg']) {
			try {
				if (isTypeSupported(m) && (!allowed.length || allowed.includes(m.split(';')[0]))) return m;
			} catch (_) { /* old engine */ }
		}
		return null;
	}

	/** Size of a picture scaled to a long side of `max` (never up). */
	function scaledSize(w, h, max) {
		const k = Math.min(1, max / Math.max(w, h, 1));
		return { w: Math.max(1, Math.round(w * k)), h: Math.max(1, Math.round(h * k)) };
	}

	/**
	 * What to do with a dropped / picked file: 'image' (scaled), 'video' (sent
	 * as a file with preview and length), 'file', or null (refused) + reason.
	 */
	function attachKind(file, limits) {
		const type = str(file && file.type).toLowerCase();
		const types = Array.isArray(limits && limits.types) ? limits.types : [];
		const max = Number(limits && limits.maxBytes) || Infinity;
		if (/^image\/(jpeg|png|webp|gif|bmp)$/.test(type)) return { kind: 'image' };
		if (!type || (types.length && !types.includes(type))) return { kind: null, reason: 'unsupported_type' };
		if (file.size > max) return { kind: null, reason: 'too_large' };
		return { kind: isVideoMime(type) ? 'video' : 'file' };
	}

	/** Dimensions for an image bubble (≤ 320 × 320, keeps the ratio). */
	function bubbleSize(meta) {
		const w = Number(meta && meta.w) || 0;
		const h = Number(meta && meta.h) || 0;
		if (!w || !h) return { w: 240, h: 180 };
		const k = Math.min(320 / w, 320 / h, 1);
		return { w: Math.max(80, Math.round(w * k)), h: Math.max(60, Math.round(h * k)) };
	}

	/** OpenStreetMap link of a location message. */
	function mapUrl(loc) {
		if (!loc || !Number.isFinite(loc.lat) || !Number.isFinite(loc.lon)) return null;
		const lat = loc.lat.toFixed(6);
		const lon = loc.lon.toFixed(6);
		return `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=17/${lat}/${lon}`;
	}

	// ── Map (location dialog and previews; Web Mercator, 256 px tiles) ──

	const TILE = 256;
	const MAP_MIN_ZOOM = 2;
	const MAP_MAX_ZOOM = 19;
	const MAX_LAT = 85.05112878;

	const clampZoom = (z) => Math.max(MAP_MIN_ZOOM, Math.min(MAP_MAX_ZOOM, Math.round(Number(z) || MAP_MIN_ZOOM)));

	/** lat/lon → world pixel at zoom z ({ x, y }, 0 … 256·2^z). */
	function worldPx(lat, lon, z) {
		const size = TILE * 2 ** z;
		const la = Math.max(-MAX_LAT, Math.min(MAX_LAT, Number(lat) || 0));
		const s = Math.sin((la * Math.PI) / 180);
		return {
			x: ((Number(lon) || 0) + 180) / 360 * size,
			y: (0.5 - Math.log((1 + s) / (1 - s)) / (4 * Math.PI)) * size,
		};
	}

	/** World pixel at zoom z → { lat, lon } (longitude wrapped to −180 … 180). */
	function lonLat(x, y, z) {
		const size = TILE * 2 ** z;
		let lon = (x / size) * 360 - 180;
		lon = ((((lon + 180) % 360) + 360) % 360) - 180;
		const n = Math.PI - (2 * Math.PI * Math.max(0, Math.min(size, y))) / size;
		const lat = (180 / Math.PI) * Math.atan(0.5 * (Math.exp(n) - Math.exp(-n)));
		return { lat, lon };
	}

	/**
	 * Tiles covering a w × h view whose centre is world pixel (cx, cy) at zoom z:
	 * [{ key, z, x, y, left, top }] (x wrapped around the date line, rows
	 * outside the map left out; left/top relative to the view).
	 */
	function tileGrid(cx, cy, z, w, h) {
		const n = 2 ** z;
		const x0 = cx - w / 2;
		const y0 = cy - h / 2;
		const out = [];
		for (let ty = Math.floor(y0 / TILE); ty <= Math.floor((y0 + h - 1) / TILE); ty++) {
			if (ty < 0 || ty >= n) continue;
			for (let tx = Math.floor(x0 / TILE); tx <= Math.floor((x0 + w - 1) / TILE); tx++) {
				const x = ((tx % n) + n) % n;
				out.push({ key: `${z}/${tx}/${ty}`, z, x, y: ty, left: Math.round(tx * TILE - x0), top: Math.round(ty * TILE - y0) });
			}
		}
		return out;
	}

	/** Metres per screen pixel at a latitude and zoom (accuracy circle). */
	function metersPerPx(lat, z) {
		return (156543.03392 * Math.cos(((Number(lat) || 0) * Math.PI) / 180)) / 2 ** z;
	}

	/** Zoom that shows an accuracy radius (m) comfortably: 18 for a few metres … 11 for kilometres. */
	function zoomForAccuracy(acc) {
		const a = Number(acc);
		if (!Number.isFinite(a) || a <= 0) return 16;
		if (a <= 30) return 17;
		if (a <= 150) return 16;
		if (a <= 600) return 15;
		if (a <= 2500) return 13;
		return 11;
	}

	/** Coordinates as sent: 6 decimals (~10 cm). */
	const roundCoord = (v) => Math.round(Number(v) * 1e6) / 1e6;

	/** "48.13743, 11.57549" */
	function coordText(loc) {
		if (!loc || !Number.isFinite(loc.lat) || !Number.isFinite(loc.lon)) return '';
		return `${loc.lat.toFixed(5)}, ${loc.lon.toFixed(5)}`;
	}

	/** GeolocationPositionError (or none) → 'denied' | 'unavailable' | 'timeout'. */
	function geoError(err) {
		const code = err && Number(err.code);
		if (code === 1) return 'denied';
		if (code === 3) return 'timeout';
		return 'unavailable';
	}

	/**
	 * Location message body from the dialog: { lat, lon, label?, accuracy? }
	 * or null without a valid point. Accuracy only for an own position
	 * that was not moved afterwards.
	 */
	function locationBody(point, label, accuracy) {
		if (!point || !Number.isFinite(point.lat) || !Number.isFinite(point.lon) || Math.abs(point.lat) > 90 || Math.abs(point.lon) > 180) return null;
		const body = { lat: roundCoord(point.lat), lon: roundCoord(point.lon) };
		const l = str(label).replace(/\s+/g, ' ').trim().slice(0, 200);
		if (l) body.label = l;
		const a = Number(accuracy);
		if (Number.isFinite(a) && a >= 0 && accuracy !== null && accuracy !== undefined) body.accuracy = Math.round(a);
		return body;
	}

	// ── Pinned "GateControl" (notification inbox) ──

	/** Inbox entries oldest first, as the chat shows them. */
	function inboxTimeline(inbox) {
		const items = inbox && Array.isArray(inbox.items) ? inbox.items : [];
		return items.slice().reverse();
	}

	/** Id of the oldest unread entry (where the chat opens), or null. */
	function inboxFirstUnread(inbox) {
		const first = inboxTimeline(inbox).find((e) => e && e.state === 'delivered');
		return first ? first.id : null;
	}

	/**
	 * Has an entry been seen? It counts once most of it is in view (60 %), or
	 * — for an entry taller than the list — once it fills half the list.
	 * ratio: IntersectionObserverEntry.intersectionRatio; shownPx: height of the
	 * visible part; viewPx: height of the list.
	 */
	function inboxSeen(ratio, shownPx, viewPx) {
		if (Number(ratio) >= 0.6) return true;
		return Number(viewPx) > 0 && Number(shownPx) >= Number(viewPx) * 0.5;
	}

	/** The pinned "GateControl" row from the inbox (core NotificationCenter list()). */
	function inboxRow(inbox, ctx, now = Date.now()) {
		const items = inbox && Array.isArray(inbox.items) ? inbox.items : [];
		const first = items[0] || null;
		return {
			title: ctx.t('chat.inbox.title'),
			text: first ? (first.title || first.body || '') : ctx.t('chat.inbox.empty'),
			time: first ? listTime(first.created_at || first.received_at, ctx, now) : '',
			unread: Number(inbox && inbox.unread) || 0,
		};
	}

	// ── Messenger 1.4.0 ──

	/** Message kinds this version draws; others → "needs a newer app version". */
	const SHOWN_KINDS = ['text', 'image', 'voice', 'file', 'location', 'system', 'poll', 'event', 'arrival', 'action', 'card'];
	const isShownKind = (m) => !!m && SHOWN_KINDS.includes(m.kind);
	const STORY_EMOJIS = ['👏', '😂', '💪', '❤️', '😮', '🙏'];
	const STORY_COLORS = ['#0F766E', '#1D4ED8', '#7C3AED', '#BE185D', '#B45309', '#334155'];
	const PRESETS = ['homeoffice', 'away', 'dnd', 'auto_place'];

	// Messenger 1.4.1: story durations in hours (`durationH`, `limits.storyDurationsH`); the server's default is 24.
	const STORY_DURATIONS_H = [1, 3, 6, 12, 24];
	const STORY_DURATION_DEFAULT_H = 24;

	/** Which 1.4.0 parts the server offers (`GET me` features: true keys only); storyDuration since 1.4.1. */
	function features14(me) {
		const f = (k) => hasFeature(me, k);
		return {
			status: f('status'), stories: f('stories'), polls: f('polls'), events: f('events'), arrival: f('arrival'), actions: f('actions'), tools: f('msg_tools'), privacy: f('privacy2'),
			storyDuration: f('stories') && f('story_duration'),
			// Messenger 1.6: notice channels / cards, the family chat pinned to the list, "Wo Mitteilungen erscheinen"
			notices: f('notices'), noticeRoutes: f('notice_routes'),
			// Messenger 1.13: „Verknüpfte Dienste“; 1.14: this person has chats over a bridge
			linked: f('linked_services'), bridgeChats: f('bridge_chats'),
			// Messenger 1.15: files and pictures over a bridge; a new chat by phone number
			bridgeMedia: f('bridge_media'), bridgeNewChat: f('bridge_new_chat'),
			// Messenger 1.17: „Älteren Verlauf laden“, files of the history on request, the phone warning
			bridgeHistory: f('bridge_history'),
			// Messenger 1.18: „Neuer Chat“ with contacts (GateControl, WhatsApp, the address book)
			bridgeContacts: f('bridge_contacts'),
			// Messenger 1.25: the contacts' WhatsApp status updates in the status row, the switch „WhatsApp mitteilen …“
			bridgeStatus: f('bridge_status'),
		};
	}

	/**
	 * Messenger 1.25: the status row's entries — the accounts (`items`) and the contacts' WhatsApp status updates
	 * (`bridged`) mixed: unseen first, then the newest story, else the server's order. A bridged entry stands for no
	 * account: `user` { id: null, name } and `bridged` { network, contactId, chatId, canReply, avatarMediaId }, its key
	 * `wa:<contactId>`.
	 */
	function mixFeed(items, bridged) {
		const newest = (it) => { const l = Array.isArray(it.stories) ? it.stories : []; return l.length ? String(l[l.length - 1].createdAt || '') : ''; };
		const all = (Array.isArray(items) ? items : []).map((it, k) => ({ it: { ...it, key: String(it.user && it.user.id) }, k }));
		(Array.isArray(bridged) ? bridged : []).forEach((b, k) => {
			if (!b || !b.contact || !Array.isArray(b.stories) || !b.stories.length) return;
			const prefix = { whatsapp: 'wa', signal: 'sg', telegram: 'tg' }[b.network] || b.network;
			all.push({
				k: 10000 + k,
				it: {
					key: `${prefix}:${b.contact.id}`,
					user: { id: null, name: b.contact.name || null },
					status: null,
					stories: b.stories,
					unseen: b.stories.some((s) => s && !s.seen),
					bridged: { network: b.network, contactId: b.contact.id, chatId: b.chatId || null, canReply: b.canReply === true, avatarMediaId: b.contact.avatarMediaId || null },
				},
			});
		});
		all.sort((a, b) => {
			const ua = !!a.it.unseen;
			const ub = !!b.it.unseen;
			if (ua !== ub) return ua ? -1 : 1;
			const na = newest(a.it);
			const nb = newest(b.it);
			if (na !== nb) return na < nb ? 1 : -1;
			return a.k - b.k;
		});
		return all.map((x) => x.it);
	}

	// ── Messenger 1.14: chats over a bridge (another messenger, today WhatsApp) ──

	// Messenger 1.23: Signal; 1.24: Telegram
	const BRIDGE_NAMES = { whatsapp: 'WhatsApp', signal: 'Signal', telegram: 'Telegram' };
	const BRIDGE_MARKS = { whatsapp: 'WA', signal: 'SG', telegram: 'TG' };
	const BRIDGE_STATES = ['unreachable', 'logged_out', 'unlinked', 'locked', 'off'];
	// Messenger 1.23: view_once — a picture or video of Signal to be seen once (opened only there)
	const PLACEHOLDER_KINDS = ['image', 'video', 'audio', 'voice', 'file', 'sticker', 'location', 'unsupported', 'view_once'];
	const FAIL_REASONS = ['bridge_error', 'unreachable', 'not_running', 'timeout', 'network_error', 'no_permission', 'too_old', 'unsupported', 'not_handled', 'bridge_unavailable', 'chat_closed'];

	/** `bridge` of a conversation ({ network, label, state, closed, supports }) or null inside GateControl. */
	function bridgeOf(c) {
		// Messenger 1.21: a person is no chat over a bridge itself — its ways are (wayConv)
		if (isPerson(c)) return null;
		const b = c && c.bridge;
		return b && typeof b === 'object' && typeof b.network === 'string' && b.network ? b : null;
	}

	/** The service's own name (never translated); an id this version does not know shows as it is. */
	function bridgeName(id) {
		const s = str(id);
		return BRIDGE_NAMES[s] || (s ? s.charAt(0).toUpperCase() + s.slice(1) : '');
	}

	/** Two letters for the sign at a picture ("WA"). */
	function bridgeMark(id) {
		const s = str(id);
		return BRIDGE_MARKS[s] || s.slice(0, 2).toUpperCase();
	}

	function bridgeLabel(c) {
		const b = bridgeOf(c);
		return b ? (str(b.label).slice(0, 40) || bridgeName(b.network)) : '';
	}

	/** The services the chat list has chats of: [{ id, label }] (the filter chips appear with the first one). */
	function bridgeNetworks(list) {
		const out = [];
		for (const c of Array.isArray(list) ? list : []) {
			// Messenger 1.21: the bridged ways of a person count as well
			for (const x of isPerson(c) ? c.person.ways.map((w) => wayConv(c, w)) : [c]) {
				const b = bridgeOf(x);
				if (b && !out.some((y) => y.id === b.network)) out.push({ id: b.network, label: bridgeLabel(x) });
			}
		}
		return out;
	}

	/**
	 * Why a chat over a bridge takes nothing right now → null (it does) or { key, relink, warn }:
	 * `key` is the text chat.bc.<key> ({{network}}), `relink` offers „Neu verknüpfen“ (Verknüpfte Dienste).
	 */
	function bridgeBlock(c) {
		const b = bridgeOf(c);
		if (!b) return null;
		if (BRIDGE_STATES.includes(b.state)) return { key: `state_${b.state}`, relink: b.state === 'logged_out' || b.state === 'unlinked', warn: b.state !== 'unlinked' && b.state !== 'off' };
		if (b.closed) return { key: 'closed', relink: false, warn: false };
		// Messenger 1.20: read only by design (a channel, a group where only admins write) — the composer says so
		if (c.can && c.can.send === false && (c.can.sendReason === 'channel' || c.can.sendReason === 'admins_only')) return null;
		if (c.can && c.can.send === false) return { key: 'cannot_send', relink: false, warn: false };
		return null;
	}

	/** Who wrote a message: the contact of a chat over a bridge, else the account (nameOf). */
	function senderName(m, c0, ctx, opts) {
		const c = isPerson(c0) ? msgConv(c0, m) : c0;
		const mb = m && m.bridge && typeof m.bridge === 'object' ? m.bridge : null;
		if (mb && mb.sender) return str(mb.sender.name) || ctx.t('chat.bc.unknown_contact');
		// Messenger 1.20: a post of a channel — the channel wrote it
		if (m && !m.mine && isChannel(c)) return title(c, ctx.t);
		if (m && !m.mine && bridgeOf(c) && (m.senderId === null || m.senderId === undefined)) return bridgeLabel(c);
		return nameOf(c, m ? m.senderId : null, ctx, opts);
	}

	/** The name over a quoted message (`replyTo` of a contact carries contactId / senderName). */
	function quoteName(q, c, ctx) {
		if (q && q.contactId != null) return str(q.senderName) || ctx.t('chat.bc.unknown_contact');
		return nameOf(c, q ? q.senderId : null, ctx);
	}

	/** Messages of the same sender are grouped: contacts of a bridge share `senderId: null`. */
	function senderKey(m) {
		const mb = m && m.bridge && typeof m.bridge === 'object' ? m.bridge : null;
		return mb && mb.sender && mb.sender.contactId != null ? `c${mb.sender.contactId}` : m.senderId;
	}

	const PH_FAIL = ['too_large', 'type', 'infected', 'quota', 'gone', 'unavailable'];

	/**
	 * `bridge.placeholder` of a message → { kind, name, state, reason, geo } or null. Messenger 1.15: `state` loading
	 * (the server fetches the file) | failed (+ `reason`) | null (nothing to fetch: a location with `geo`, an encrypted
	 * file, a server without the file route — and every placeholder of 1.14). 1.17: on_request — a file of the older
	 * history, fetched when the person asks for it („Laden“).
	 */
	function placeholderOf(m) {
		const p = m && !m.deleted && m.bridge && typeof m.bridge === 'object' ? m.bridge.placeholder : null;
		if (!p || typeof p !== 'object' || !PLACEHOLDER_KINDS.includes(p.kind)) return null;
		const g = p.geo && typeof p.geo === 'object' ? p.geo : null;
		const geo = g && Number.isFinite(g.lat) && Number.isFinite(g.lon) && Math.abs(g.lat) <= 90 && Math.abs(g.lon) <= 180 ? { lat: g.lat, lon: g.lon } : null;
		const state = p.state === 'loading' || p.state === 'failed' || p.state === 'on_request' ? p.state : null;
		// Messenger 1.19: `retry` — a file that failed may be asked for once more („Erneut versuchen“)
		return { kind: p.kind, name: str(p.name).slice(0, 200) || null, state, reason: state === 'failed' ? (PH_FAIL.includes(p.reason) ? p.reason : 'other') : null, geo, retry: state === 'failed' && p.retry === true };
	}

	/**
	 * „Bild · grill.jpg – folgt; in WhatsApp ansehen“, 1.15: „… – wird geladen …“ / „… – zu groß, öffne es in WhatsApp“
	 * (1.24) / „… – gesperrt – Schadsoftware gefunden“; „Nachricht dieser Art …“; null without placeholder.
	 */
	function placeholderText(m, c0, t) {
		const c = isPerson(c0) ? msgConv(c0, m) : c0;
		const p = placeholderOf(m);
		if (!p) return null;
		const network = bridgeLabel(c) || bridgeName(str(m.via).replace(/^bridge:/, ''));
		if (p.kind === 'unsupported') return t('chat.bc.ph.unsupported', { network });
		if (p.kind === 'view_once') return t('chat.bc.ph.view_once', { network });
		// a location of the bridge: shown on the map (its label is the message's text)
		if (p.geo) return t('chat.bc.ph.location');
		const what = [t(`chat.bc.ph.${p.kind}`), p.name].filter(Boolean).join(' · ');
		if (p.state === 'loading') return `${what} – ${t('chat.bc.ph_loading')}`;
		if (p.state === 'on_request') return `${what} – ${t('chat.bc.ph_on_request')}`;
		if (p.state === 'failed') return `${what} – ${t(`chat.bc.ph_fail.${p.reason}`, { network })}`;
		return `${what} – ${t('chat.bc.ph_later', { network })}`;
	}


	// ── Messenger 1.21: persons ──

	const GC_WAY = 'gatecontrol';
	const WAY_RE = /^[a-z]{2,20}$/;

	/** One entry for several ways of a human (`person` { id, ways, reply, names, … }; its id is the lead's). */
	function isPerson(c) {
		const p = c && c.person;
		return !!(p && typeof p === 'object' && Number.isSafeInteger(p.id) && Array.isArray(p.ways) && p.ways.length > 0);
	}

	/** The way of a message (`way`): 'gatecontrol' or a bridge's network, else null. */
	function wayOf(m) {
		return m && typeof m.way === 'string' && WAY_RE.test(m.way) ? m.way : null;
	}

	/** The name of a way (never translated): „GateControl“, „WhatsApp“, … */
	function wayLabel(way, label) {
		if (label) return str(label).slice(0, 40);
		return way === GC_WAY ? 'GateControl' : bridgeName(way);
	}

	/** The ways of a person, each kind once (GateControl first, as the server orders them) → [{ way, label }] */
	function personWays(c) {
		if (!isPerson(c)) return [];
		const out = [];
		for (const w of c.person.ways) {
			const way = w && WAY_RE.test(str(w.way)) ? w.way : null;
			if (way && !out.some((x) => x.way === way)) out.push({ way, label: wayLabel(way, w.label) });
		}
		return out;
	}

	/** „GateControl · WhatsApp“ under the name of a person. */
	function personSub(c) {
		return personWays(c).map((w) => w.label).join(' · ');
	}

	/** The way an answer takes now (`person.reply`, the server's pick) → that way of `person.ways`, or null. */
	function replyWay(c) {
		if (!isPerson(c) || !c.person.reply) return null;
		const id = c.person.reply.conversationId;
		return c.person.ways.find((w) => w && w.conversationId === id) || null;
	}

	/**
	 * The entry seen as one of its ways — a chat over a bridge (`bridge`, `can` of the way) or the GateControl chat (its
	 * read marks): what the composer and the bubbles of that way check, as in a chat of its own.
	 */
	function wayConv(c, w) {
		if (!isPerson(c) || !w) return c;
		const gc = !w.bridge;
		return {
			...c,
			person: null,
			bridge: w.bridge || null,
			can: { ...(c.can || {}), ...(w.can || {}) },
			title: w.title || c.title,
			peer: gc ? c.peer : null,
			readUpTo: gc ? c.readUpTo : null,
			deliveredUpTo: gc ? c.deliveredUpTo : null,
			receipts: gc ? c.receipts : [],
		};
	}

	/** The composer of a person: the way the answer takes (else the GateControl way, else the first). */
	function sendConv(c) {
		if (!isPerson(c)) return c;
		const ways = c.person.ways;
		return wayConv(c, replyWay(c) || ways.find((w) => w && !w.bridge) || ways[0]);
	}

	/** A message of a person seen in its way (its conversation, else its `way`). */
	function msgConv(c, m) {
		if (!isPerson(c)) return c;
		const ways = c.person.ways;
		const w = (m && ways.find((x) => x && x.conversationId === m.conversationId)) || (wayOf(m) && ways.find((x) => x && x.way === wayOf(m))) || null;
		return w ? wayConv(c, w) : sendConv(c);
	}

	/** The source chips of a person's history: Alle · GateControl · WhatsApp → [{ way: null | way, label }] */
	function sourceChips(c, t) {
		if (!isPerson(c)) return [];
		return [{ way: null, label: t('chat.person.srcAll') }, ...personWays(c)];
	}

	/** The options of „Name in deiner Liste“ of a person: the account's name, the name of each bridged way. */
	function personNameOptions(c) {
		if (!isPerson(c)) return [];
		const p = c.person;
		const out = [];
		if (p.userId != null) {
			const gw = p.ways.find((w) => w && !w.bridge);
			out.push({ value: 'account', label: str((gw && gw.title) || p.name) });
		}
		for (const w of p.ways) if (w && w.bridge && w.title) out.push({ value: String(w.conversationId), label: str(w.title) });
		const seen = new Set();
		return out.filter((o) => { if (!o.label || seen.has(o.label)) return false; seen.add(o.label); return true; });
	}

	/** The value of the name choice now: 'account' or the conversation id of a way (as a string). */
	function personNameValue(c) {
		if (!isPerson(c)) return null;
		const nf = c.person.nameFrom;
		return nf === 'account' || nf == null ? 'account' : String(nf);
	}

	/**
	 * The name dialog of a merge by hand: [{ value: 'account' | conversationId, label }] — the account's name first (the
	 * default), the chat's own name, the picked chat's. `pick`: { account } | { chat }.
	 */
	function mergeNameOptions(c, pick) {
		const out = [];
		const p = isPerson(c) ? c.person : null;
		const acc = pick && pick.account ? pick.account : null;
		if (acc) out.push({ value: 'account', label: str(acc.name) });
		else if (p && p.userId != null) out.push({ value: 'account', label: str(((p.ways.find((w) => w && !w.bridge)) || {}).title || p.name) });
		else if (!p && c && !bridgeOf(c) && c.peer) out.push({ value: 'account', label: str(c.peer.name || c.title) });
		if (p) for (const w of p.ways) { if (w && w.bridge) out.push({ value: w.conversationId, label: str(w.title) }); }
		else if (c && bridgeOf(c)) out.push({ value: c.id, label: str(c.title) });
		if (pick && pick.chat) out.push({ value: pick.chat.conversationId, label: str(pick.chat.title) });
		const seen = new Set();
		return out.filter((o) => { if (!o.label || seen.has(o.label)) return false; seen.add(o.label); return true; });
	}

	/** POST persons of a merge by hand: the chat (or the person's lead), the picked chat, the picked account, the name. */
	function mergeRequest(c, pick, name) {
		const ids = [isPerson(c) ? c.person.conversationId : c.id];
		if (pick && pick.chat) ids.push(pick.chat.conversationId);
		const req = { conversationIds: ids };
		if (pick && pick.account) req.userId = pick.account.userId;
		if (name != null) req.name = name;
		return req;
	}

	/** May the chat info offer „Mit Person zusammenführen …“? A chat with one person — never a group or a channel. */
	function canMergeByHand(c, me) {
		if (!c || !hasFeature(me, 'chat_people') || isPerson(c)) return false;
		if (c.kind !== 'direct' || isChannel(c) || isNotice(c) || c.readonly || c.managedBy) return false;
		return !!bridgeOf(c) || !!(c.peer && !c.peer.gone);
	}

	/** The candidates of „Mit Person zusammenführen“ filtered by the search field (accounts by name, chats by title). */
	function filterCandidates(r, q) {
		const s = str(q).trim().toLowerCase();
		const hit = (n) => !s || str(n).toLowerCase().includes(s);
		return {
			accounts: (r && Array.isArray(r.accounts) ? r.accounts : []).filter((a) => hit(a.name)),
			chats: (r && Array.isArray(r.chats) ? r.chats : []).filter((x) => hit(x.title)),
		};
	}

	// ── Messenger 1.20: channels, format, links, link previews, the messengers' logos ──

	/** A channel of another messenger (`bridge.channel`): read only, on the page „Kanäle“. */
	function isChannel(c) {
		const b = bridgeOf(c);
		return !!b && b.channel === true;
	}

	/** The second line of the entry „Kanäle“: „3 neue Beiträge“ / „1 neuer Beitrag“ / „Keine neuen Beiträge“. */
	function channelEntryText(sum, t) {
		const n = sum && Number.isSafeInteger(sum.unread) && sum.unread > 0 ? sum.unread : 0;
		if (!n) return t('chat.ch.entryNone');
		return n === 1 ? t('chat.ch.entryOne') : t('chat.ch.entryNew', { n: n > 99 ? '99+' : n });
	}

	/** The networks of the channels for the page's subtitle („WhatsApp“). */
	function channelNetworks(list) {
		return bridgeNetworks(list).map((n) => n.label).join(' · ');
	}

	/** The channels filtered by the page's search (name, newest post). */
	function filterChannels(list, q, ctx) {
		const s = str(q).trim().toLowerCase();
		const items = Array.isArray(list) ? list : [];
		if (!s) return items;
		return items.filter((c) => title(c, ctx.t).toLowerCase().includes(s) || preview(c, ctx).text.toLowerCase().includes(s));
	}

	/** Has the person an own reaction on this message (the note under it in a channel)? */
	function hasOwnReaction(m, ctx) {
		const meId = ctx && ctx.me && ctx.me.user ? ctx.me.user.id : null;
		return !!m && Array.isArray(m.reactions) && m.reactions.some((r) => r && Array.isArray(r.userIds) && r.userIds.includes(meId));
	}

	/** An http(s) address (a `www.` one as https) → its href, or null (no other scheme, no user / password). */
	function safeHref(raw) {
		const v = str(raw).trim();
		if (!v || v.length > 2048) return null;
		const s = /^www\./i.test(v) ? `https://${v}` : v;
		let u;
		try { u = new URL(s); } catch (_) { return null; }
		return (u.protocol === 'http:' || u.protocol === 'https:') && u.hostname && !u.username && !u.password ? u.href : null;
	}

	const URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"]{2,2000}/gi;
	const TRAIL_RE = /[.,;:!?)\]}'"»“”]+$/;

	/** Plain text → [{ text, href? }]: http(s) and www. addresses become links (trailing punctuation stays text). */
	function linkify(text) {
		const s = str(text);
		const out = [];
		let last = 0;
		URL_RE.lastIndex = 0;
		let m;
		while ((m = URL_RE.exec(s))) {
			const raw = m[0].replace(TRAIL_RE, '');
			const href = raw.length > 3 ? safeHref(raw) : null;
			if (!href) continue;
			if (m.index > last) out.push({ text: s.slice(last, m.index) });
			out.push({ text: raw, href });
			last = m.index + raw.length;
			URL_RE.lastIndex = last;
		}
		if (last < s.length) out.push({ text: s.slice(last) });
		return out;
	}

	const MARK_TYPES = ['bold', 'italic', 'strike', 'code'];

	/**
	 * A text with its `marks` (bold, italic, strike, code, link — UTF-16 offsets, `end` exclusive, may nest; unknown
	 * types and marks outside the text are left out) → [{ text, bold, italic, strike, code, href }] — the pieces the view
	 * builds as elements (never HTML). Addresses without a mark are linkified in every piece.
	 */
	function richText(text, marks) {
		const s = str(text);
		const list = (Array.isArray(marks) ? marks : []).filter((k) => k && typeof k === 'object' && (MARK_TYPES.includes(k.type) || k.type === 'link')
			&& Number.isSafeInteger(k.start) && Number.isSafeInteger(k.end) && k.start >= 0 && k.end <= s.length && k.end > k.start);
		const plain = (piece, extra) => linkify(piece).map((x) => ({ bold: false, italic: false, strike: false, code: false, href: null, ...extra, ...x, ...(extra.href ? { href: extra.href } : {}) }));
		if (!list.length) return s ? plain(s, {}) : [];
		const cuts = [...new Set([0, s.length, ...list.flatMap((k) => [k.start, k.end])])].sort((a, b) => a - b);
		const out = [];
		for (let i = 0; i < cuts.length - 1; i++) {
			const a = cuts[i];
			const b = cuts[i + 1];
			const on = list.filter((k) => k.start <= a && k.end >= b);
			const link = on.find((k) => k.type === 'link' && safeHref(k.url));
			const extra = { bold: on.some((k) => k.type === 'bold'), italic: on.some((k) => k.type === 'italic'), strike: on.some((k) => k.type === 'strike'), code: on.some((k) => k.type === 'code'), href: link ? safeHref(link.url) : null };
			const piece = s.slice(a, b);
			if (extra.href) out.push({ ...extra, text: piece });
			else out.push(...plain(piece, extra));
		}
		return out;
	}

	/**
	 * `preview` of a text message → { href, title, description, site, image: { mediaId, w, h, loading } | null } or
	 * null (no http(s) address). A picture that failed or has no file is left out.
	 */
	function linkPreview(m) {
		const p = m && m.kind === 'text' && !m.deleted && m.preview && typeof m.preview === 'object' ? m.preview : null;
		const href = p ? safeHref(p.url) : null;
		if (!href) return null;
		const im = p.image && typeof p.image === 'object' ? p.image : null;
		const dim = (v) => (Number.isSafeInteger(v) && v > 0 && v <= 100000 ? v : null);
		let image = null;
		if (im && im.state === 'loading') image = { mediaId: null, w: dim(im.w), h: dim(im.h), loading: true };
		else if (im && im.state !== 'failed' && typeof im.mediaId === 'string' && /^[0-9a-f]{32}$/.test(im.mediaId)) image = { mediaId: im.mediaId, w: dim(im.w), h: dim(im.h), loading: false };
		let host = '';
		try { host = new URL(href).hostname; } catch (_) { host = ''; }
		return { href, title: str(p.title).slice(0, 300) || null, description: str(p.description).slice(0, 1000) || null, site: str(p.site).slice(0, 100) || host, image };
	}

	// The messengers' logos (plain glyphs, only to say which service it is; 24×24, filled, evenodd) — like the portal's
	// MS.netLogo; a network this version does not know gets a speech bubble.
	const NET_GLYPHS = {
		whatsapp: ['M12 2.6a9.3 9.3 0 0 0-8 14l-1.3 4.8 4.9-1.3A9.3 9.3 0 1 0 12 2.6zm0 1.7a7.6 7.6 0 1 1-3.9 14.1l-.3-.2-2.9.8.8-2.8-.2-.3A7.6 7.6 0 0 1 12 4.3z', 'M9.2 7.6c.2-.4.4-.4.7-.4h.5c.2 0 .4 0 .6.5l.8 1.9c.1.2.1.4 0 .6l-.5.7c-.1.2-.2.3 0 .6.6 1 1.4 1.8 2.5 2.4.3.1.4.1.6-.1l.7-.8c.2-.2.4-.2.6-.1l1.8.9c.2.1.4.2.4.4.1.3 0 1-.3 1.4-.4.5-1.3 1-2 1-1 .1-2.3-.4-4-1.6-1.5-1.2-2.5-2.6-2.9-3.6-.4-1-.2-2 .5-2.8z'],
		gatecontrol: ['M12 2.5l7.5 2.8v5.9c0 4.8-3.2 8.6-7.5 10.3-4.3-1.7-7.5-5.5-7.5-10.3V5.3z'],
		// Messenger 1.23: Signal — a speech bubble in a dashed ring (NET_RINGS), like the portal's
		signal: ['M12 5.6a6.4 6.4 0 0 0-5.5 9.7l-.8 3 3.1-.7A6.4 6.4 0 1 0 12 5.6z'],
		// Messenger 1.24: Telegram — the paper plane, like the portal's
		telegram: ['M3.4 11.3l15.9-6.2c.8-.3 1.4.2 1.2 1.3l-2.7 12.7c-.2.9-.7 1.1-1.5.7l-4.1-3-2 1.9c-.2.2-.4.4-.8.4l.3-4.2 7.7-7c.3-.3-.1-.4-.5-.2l-9.5 6-4.1-1.3c-.9-.3-.9-.9.2-1.3z'],
	};
	const NET_RINGS = new Set(['signal']);
	const NET_OTHER = ['M4 5h16v11H9l-5 4z'];

	/** The logo of a network → { known, paths, ring } (paths of a 24×24 glyph; ring: a dashed circle around it). */
	function netGlyph(network) {
		const known = Object.prototype.hasOwnProperty.call(NET_GLYPHS, str(network));
		return { known, paths: known ? NET_GLYPHS[str(network)] : NET_OTHER, ring: known && NET_RINGS.has(str(network)) };
	}

	// ── Messenger 1.15: files over a bridge ──

	/** The kind a file goes out as over a bridge (like the plugin): image | voice | video (a file of video/*) | file. */
	function bridgeOutKind(kind, mime) {
		if (kind === 'image' || kind === 'voice') return kind;
		return /^video\//.test(str(mime).toLowerCase()) ? 'video' : 'file';
	}

	/** Does a chat over a bridge take files at all (`bridge.supports` names one of the kinds)? */
	function bridgeTakesFiles(c) {
		const b = bridgeOf(c);
		return !!b && Array.isArray(b.supports) && ['image', 'video', 'voice', 'file'].some((k) => b.supports.includes(k));
	}

	/**
	 * May this file go into the chat over a bridge? → null (yes), 'text_only' (no files of this kind) or the kind whose
	 * types it misses ('image' | 'voice' | 'video'); `mediaTypes[kind]` null = any type.
	 */
	function bridgeMediaRefusal(c, kind, mime) {
		const b = bridgeOf(c);
		if (!b) return null;
		const k = bridgeOutKind(kind, mime);
		if (!Array.isArray(b.supports) || !b.supports.includes(k)) return 'text_only';
		const types = b.mediaTypes && typeof b.mediaTypes === 'object' ? b.mediaTypes[k] : null;
		if (!Array.isArray(types)) return null;
		return types.includes(str(mime).split(';')[0].trim().toLowerCase()) ? null : k;
	}

	/** The picture type to send into a chat over a bridge: WebP when it takes it, else JPEG. */
	function bridgeImageType(c) {
		const b = bridgeOf(c);
		const types = b && b.mediaTypes && Array.isArray(b.mediaTypes.image) ? b.mediaTypes.image : null;
		return !types || types.includes('image/webp') ? 'image/webp' : 'image/jpeg';
	}

	/**
	 * A recording type for a voice message: in a chat over a bridge only one the service takes (`mediaTypes.voice` —
	 * WhatsApp takes no WebM, which is mostly all Chromium records), else as recordingMime. → mime or null (no mic).
	 */
	function voiceMime(c, isTypeSupported, types) {
		const b = bridgeOf(c);
		if (!b) return recordingMime(isTypeSupported, types);
		if (!Array.isArray(b.supports) || !b.supports.includes('voice')) return null;
		const want = b.mediaTypes && Array.isArray(b.mediaTypes.voice) ? b.mediaTypes.voice : null;
		const allowed = Array.isArray(types) ? types : [];
		for (const m of ['audio/ogg;codecs=opus', 'audio/mp4;codecs=opus', 'audio/mp4;codecs=mp4a.40.2', 'audio/mp4', 'audio/aac', 'audio/mpeg', 'audio/webm;codecs=opus', 'audio/webm']) {
			const base = m.split(';')[0];
			if (want && !want.includes(base)) continue;
			if (allowed.length && !allowed.includes(base)) continue;
			try { if (isTypeSupported(m)) return m; } catch (_) { /* old engine */ }
		}
		return null;
	}

	/** „WhatsApp nimmt Videos nur als MP4 an.“ for a refusal 409 bridge_media_type / a check before sending. */
	function mediaTypeText(reason, c, t) {
		const k = ['image', 'video', 'voice', 'file'].includes(reason) ? reason : 'file';
		return t(`chat.bc.media_type.${k}`, { network: bridgeLabel(c) || 'WhatsApp' });
	}

	// ── Messenger 1.15 / 1.16: a new chat by phone number ──

	// The country codes of the dialog's list (others: paste the number with +).
	const NEW_CHAT_CC = [
		['DE', '+49'], ['AT', '+43'], ['CH', '+41'], ['NL', '+31'], ['BE', '+32'], ['LU', '+352'], ['FR', '+33'], ['IT', '+39'], ['ES', '+34'],
		['PL', '+48'], ['CZ', '+420'], ['DK', '+45'], ['GB', '+44'], ['TR', '+90'], ['US', '+1'],
	];

	/**
	 * A number as typed in the dialog → { number: '+49…' | null, error: null | 'empty' | 'invalid' | 'invalid_mobile_de' |
	 * 'invalid_chars' }. Like the core's bridgeNumber (which checks it again): spaces, brackets, dots, dashes and slashes
	 * go, 00 → +, a + keeps its country, any other number gets `cc` and loses its leading 0.
	 */
	function newChatNumber(raw, cc = '+49') {
		const code = /^\+[1-9][0-9]{0,3}$/.test(str(cc)) ? cc : '+49';
		let v = str(raw).trim().replace(/[\s()/.\u2010-\u2015-]/g, '');
		if (!v) return { number: null, error: 'empty' };
		if (!/^\+?[0-9]+$/.test(v) || v.length > 24) return { number: null, error: 'invalid_chars' };
		if (v.startsWith('00')) v = `+${v.slice(2)}`;
		else if (!v.startsWith('+')) v = code + v.replace(/^0+/, '');
		if (v.startsWith('+49')) {
			const nat = v.slice(3);
			if (/^1[5-7]/.test(nat) && nat.length < 10) return { number: null, error: 'invalid_mobile_de' };
			if (nat.length < 6) return { number: null, error: 'invalid' };
		}
		if (!/^\+[1-9][0-9]{7,14}$/.test(v)) return { number: null, error: 'invalid' };
		return { number: v, error: null };
	}

	/** '+4915123456789' → '+49 151 23456789' (the country code of the list, then three digits, then the rest). */
	function formatNumber(n) {
		const v = str(n);
		if (!/^\+[0-9]{4,16}$/.test(v)) return v;
		const cc = NEW_CHAT_CC.map((x) => x[1]).sort((a, b) => b.length - a.length).find((x) => v.startsWith(x));
		const code = cc || v.slice(0, 3);
		const rest = v.slice(code.length);
		return rest.length > 6 ? `${code} ${rest.slice(0, 3)} ${rest.slice(3)}` : `${code} ${rest}`;
	}

	/**
	 * The services offered for a new chat by number (GET bridges; only with the feature `bridge_new_chat`): linked for
	 * this person — also signed out, not reachable or locked by the parents (the dialog then says why) —, never when the
	 * parents switched new chats off for the child (`newChat.reason: child_new_chat_off`). → [{ id, name, mark, state }]
	 * with `state` the dialog's first state: input | loggedout | unlinked | unreach | locked | off.
	 */
	const NEW_CHAT_NETS = ['whatsapp'];

	function newChatServices(bridges, me) {
		if (!hasFeature(me, 'bridge_new_chat')) return [];
		const b = bridges && typeof bridges === 'object' ? bridges : {};
		if (b.available === false) return [];
		const out = [];
		for (const n of Array.isArray(b.networks) ? b.networks : []) {
			// Messenger 1.23: a chat by number only where this version has the dialog for it (WhatsApp; not Signal)
			if (!n || !linkable(n.id) || !NEW_CHAT_NETS.includes(n.id)) continue;
			const nc = n.newChat && typeof n.newChat === 'object' ? n.newChat : null;
			if (nc && nc.reason === 'child_new_chat_off') continue;
			const logins = Array.isArray(n.logins) ? n.logins : [];
			if (!logins.length && !(nc && nc.reason && nc.reason !== 'unlinked')) continue;
			out.push({ id: n.id, name: bridgeName(n.id), mark: bridgeMark(n.id), state: newChatState(n), limit: nc && nc.limit ? nc.limit : null });
		}
		return out;
	}

	/** The dialog's first state for a service of GET bridges (newChat.reason of 1.16, else the link's state). */
	function newChatState(n) {
		const nc = n && n.newChat && typeof n.newChat === 'object' ? n.newChat : null;
		const byReason = { unlinked: 'unlinked', logged_out: 'loggedout', unreachable: 'unreach', child_locked: 'locked', off: 'off' };
		if (nc && !nc.available && byReason[nc.reason]) return byReason[nc.reason];
		if (nc && nc.available) return 'input';
		if (n && n.allowed === false) return 'locked';
		if (n && (n.state === 'unreachable' || n.state === 'failed' || n.state === 'starting')) return 'unreach';
		const l = mainLogin(n);
		if (!l) return 'unlinked';
		if (l.state === 'logged_out') return 'loggedout';
		return 'input';
	}

	/**
	 * A refusal of resolve / chats → the dialog's state: invalid | rate (+ retryAfterS) | loggedout | unlinked | locked |
	 * unreach | off | none | failed.
	 */
	function newChatErrorState(res) {
		const r = res && typeof res === 'object' ? res : { code: res };
		switch (r.code) {
			case 'invalid_number': return { state: 'invalid' };
			case 'rate_limited': return {
				state: 'rate',
				retryAfterS: Number.isSafeInteger(r.retryAfterS) && r.retryAfterS > 0 ? r.retryAfterS : 600,
				// Messenger 1.16: the brake per hour comes with the refusal
				...(Number.isSafeInteger(r.perHour) && r.perHour > 0 ? { perHour: r.perHour } : {}),
			};
			case 'bridge_unlinked': return { state: r.reason === 'logged_out' ? 'loggedout' : 'unlinked' };
			case 'bridge_logged_out': return { state: 'loggedout' };
			case 'bridge_locked': case 'child_new_chat_off': return { state: 'locked' };
			case 'bridge_unreachable': case 'bridge_failed': case 'timeout': case 'network': return { state: 'unreach' };
			case 'bridge_off': case 'feature_off': case 'unsupported': return { state: 'off' };
			case 'not_found': return { state: 'none' };
			default: return { state: 'failed' };
		}
	}

	// ── Messenger 1.18: „Neuer Chat“ with contacts ──

	// The service the contacts are of (GET contacts/new-chat?network=), rows of a long section before „Alle …“.
	const CONTACTS_NET = 'whatsapp';
	const CONTACTS_FIRST = 3;
	const PHONE_KINDS = ['mobile', 'work', 'home', 'other'];

	/** „Mobil“ / „Geschäftlich“ / „Privat“ / „Weitere“ of a number's kind (or key: mobile-2 → mobile). */
	function phoneKindText(kind, t) {
		const k = str(kind).replace(/-.*/, '');
		return t(`chat.ncc.kind_${PHONE_KINDS.includes(k) ? k : 'other'}`);
	}

	/** The line under an address book contact: „Mobil · +49 …“ for one number, „3 Nummern“ for several. */
	function contactPhonesSub(x, t) {
		const phones = x && Array.isArray(x.phones) ? x.phones : [];
		if (phones.length === 1) return `${phoneKindText(phones[0].kind, t)} · ${str(phones[0].number)}`;
		return t('chat.ncc.numbers', { n: phones.length });
	}

	/** The first word of a name („Hat {name} eine andere Nummer …“). */
	const firstName = (name) => str(name).trim().split(/\s+/)[0] || '';

	/** The rows of a long section shown: all while searching or opened („Alle …“), else the first three. */
	function contactsShown(items, q, open) {
		const list = Array.isArray(items) ? items : [];
		return str(q).trim() || open ? list : list.slice(0, CONTACTS_FIRST);
	}

	/**
	 * The number dialog of 1.15 / 1.16 („Nicht dabei? Nummer eingeben“) for the list's service → { id, name, mark, state,
	 * limit } like newChatServices — its first state from the WhatsApp section (signed out, not reachable).
	 */
	function contactsService(data) {
		const d = data && typeof data === 'object' ? data : {};
		const wa = d.whatsapp && typeof d.whatsapp === 'object' ? d.whatsapp : null;
		const state = wa && wa.state === 'logged_out' ? 'loggedout' : (wa && wa.state === 'unreachable' ? 'unreach' : 'input');
		return { id: CONTACTS_NET, name: bridgeName(CONTACTS_NET), mark: bridgeMark(CONTACTS_NET), state, limit: d.limit || null };
	}

	/**
	 * A refusal of POST …/chats for a contact → what its row shows: { view: 'reload' } (load the list again:
	 * contact_expired, signed out, the contact gone), 'none' (not at WhatsApp; remembered), 'rate' (+ retryAfterS,
	 * perHour), 'unreach' or 'failed'.
	 */
	function contactChatError(res) {
		const r = res && typeof res === 'object' ? res : { code: res };
		switch (r.code) {
			case 'contact_expired': case 'bridge_logged_out': return { view: 'reload' };
			case 'bridge_unlinked': return { view: 'reload' };
			case 'not_found': return r.reason === 'not_on_network' ? { view: 'none', remembered: r.remembered === true } : { view: 'reload' };
			case 'rate_limited': return {
				view: 'rate',
				retryAfterS: Number.isSafeInteger(r.retryAfterS) && r.retryAfterS > 0 ? r.retryAfterS : 3600,
				...(Number.isSafeInteger(r.perHour) && r.perHour > 0 ? { perHour: r.perHour } : {}),
			};
			case 'bridge_unreachable': case 'bridge_off': case 'timeout': case 'network': return { view: 'unreach' };
			default: return { view: 'failed' };
		}
	}

	/** The first line of a chat just started (by number, a WhatsApp contact or the address book) → text, or ''. */
	function startedLine(st, c, t) {
		if (!st || !c) return '';
		const network = bridgeLabel(c) || bridgeName(CONTACTS_NET);
		const name = st.name || title(c, t);
		if (st.kind === 'contact') return t('chat.nc.first_line_contact', { network, name });
		if (st.kind === 'book') return t('chat.nc.first_line_book', { network, name, number: str(st.number) });
		return t('chat.nc.first_line', { network, number: formatNumber(st.number), name });
	}

	/** An own message of a chat over a bridge that was not sent → { text, resend } (the reason in words), or null. */
	function bridgeFailure(m, t) {
		const mb = m && !m.pending && m.mine && !m.deleted && m.bridge && typeof m.bridge === 'object' ? m.bridge : null;
		if (!mb || mb.state !== 'failed') return null;
		const reason = FAIL_REASONS.includes(mb.reason) ? mb.reason : 'bridge_error';
		return { text: `${t('chat.bc.failed')} ${t(`chat.bc.reason.${reason}`)}`, resend: true };
	}

	// ── Messenger 1.13: „Verknüpfte Dienste“ ──

	// Messenger 1.23: Signal — a linked device, by QR code only (`networks[].flows`), three steps beside the code
	// Messenger 1.24: Telegram — the QR code preselected on a computer, the number (code, password) the second way
	const LINK_NOTES = { whatsapp: ['unofficial', 'ban', 'phone', 'e2e'], signal: ['unofficial', 'phone', 'e2e', 'safety'], telegram: ['unofficial', 'e2e'] };
	const LINK_FLOWS = ['phone', 'qr'];
	const LINK_FLOWS_OF = { telegram: ['qr', 'phone'] };
	const LINK_QR_STEPS = { whatsapp: 2, signal: 3, telegram: 3 };

	/** The ways in a service offers (GET bridges → networks[].flows; an older plugin names none: both), the first preselected. */
	function linkFlows(n) {
		const order = (n && LINK_FLOWS_OF[str(n.id)]) || LINK_FLOWS;
		const f = n && Array.isArray(n.flows) ? order.filter((x) => n.flows.includes(x)) : [];
		return f.length ? f : order.slice();
	}

	/** Messenger 1.24: the name of a way of a service („Mit Telefonnummer“ for Telegram, else „Mit Code“ / „QR-Code“). */
	function flowLabel(id, flow, t) {
		const own = `chat.br.flow_${flow}_${str(id)}`;
		return t(own) !== own ? t(own) : t(`chat.br.flow_${flow}`);
	}

	/** Messenger 1.24: the tag „Bot“ and the members of a large group („340 Mitglieder“) of a chat over a bridge. */
	function bridgeExtras(c, t) {
		const b = bridgeOf(c);
		if (!b) return { bot: false, members: '' };
		const n = Number.isSafeInteger(b.members) && b.members >= 200 ? b.members : 0;
		return { bot: b.bot === true && c.kind === 'direct', members: n ? t('chat.bc.members', { n }) : '' };
	}

	/** Messenger 1.24: the channels of one service (`net` null: all) — the chips of the channels page. */
	function channelsOf(list, net) {
		const items = Array.isArray(list) ? list : [];
		return net ? items.filter((c) => { const b = bridgeOf(c); return !!b && b.network === net; }) : items;
	}

	/** The steps beside the QR code of a service: chat.br.qr_step1_<net> … */
	function qrSteps(id) {
		const n = LINK_QR_STEPS[str(id)] || 2;
		return Array.from({ length: n }, (_, i) => `chat.br.qr_step${i + 1}_${str(id)}`);
	}

	/**
	 * Messenger 1.23: the history of a service that brings it only at the link (Signal, `history.phoneConfirms`):
	 * „· Verlauf: 30 Tage, wird nachts geladen“ behind a linked row (only when the person wants history).
	 */
	function historyLine(n, h, t) {
		const max = n && n.history && Number.isSafeInteger(n.history.maxDays) ? n.history.maxDays : null;
		if (!max || !h || h.available !== true || h.days === 0) return '';
		return t(Number.isSafeInteger(h.pending) && h.pending > 0 ? 'chat.br.hist_line_pending' : 'chat.br.hist_line', { n: max });
	}
	const LOGIN_ORDER = ['connected', 'connecting', 'error', 'logged_out', 'unknown'];

	/** The services this version can link (it has their notes and steps); others are not offered. */
	const linkable = (id) => Object.prototype.hasOwnProperty.call(LINK_NOTES, str(id));

	/** The login of a service that matters most: a linked one, else one that was signed out or failed. */
	function mainLogin(n) {
		let best = null;
		for (const l of (n && Array.isArray(n.logins) ? n.logins : [])) if (!best || LOGIN_ORDER.indexOf(l.state) < LOGIN_ORDER.indexOf(best.state)) best = l;
		return best;
	}

	function linkDate(iso, locale) {
		const d = iso ? new Date(iso) : null;
		if (!d || Number.isNaN(d.getTime())) return '';
		return d.toLocaleDateString(localeTag(locale), { day: '2-digit', month: '2-digit', year: 'numeric' });
	}

	/**
	 * A service in the overview → { state, sub, pill: { text, tone }, link, unlink, again: null | { hint, link, forget } }.
	 * state: unreachable | starting | linked | logged_out | error | locked | none | noapp (1.24: Telegram not set up yet).
	 */
	function linkedRow(n, ctx) {
		const t = ctx.t;
		const l = mainLogin(n);
		const name = bridgeName(n.id);
		const out = { id: n.id, name, mark: bridgeMark(n.id), login: l, state: 'none', sub: '', pill: null, link: false, unlink: false, again: null, phone: null };
		// Messenger 1.24: Telegram is not set up on the server yet — an administrator enters the application id first
		if (n.needs === 'app') {
			out.state = 'noapp';
			out.sub = t('chat.br.sub_noapp');
			out.pill = { text: t('chat.br.pill_noapp'), tone: 'off' };
			return out;
		}
		if (n.state === 'unreachable' || n.state === 'starting' || n.state === 'failed') {
			out.state = n.state === 'starting' ? 'starting' : 'unreachable';
			out.sub = t(n.state === 'starting' ? 'chat.br.sub_starting' : 'chat.br.sub_unreachable');
			out.pill = { text: t(n.state === 'starting' ? 'chat.br.pill_starting' : 'chat.br.pill_unreachable'), tone: 'warn' };
		} else if (l && (l.state === 'connected' || l.state === 'connecting')) {
			out.state = 'linked';
			const date = linkDate(l.since, ctx.locale);
			out.sub = [date ? t('chat.br.sub_linked_since', { date }) : t('chat.br.sub_linked'), l.name, historyLine(n, ctx.history, t)].filter(Boolean).join(' · ');
			out.pill = isOutdated(n) ? { text: t('chat.br.pill_outdated'), tone: 'warn' } : { text: t('chat.br.pill_linked'), tone: 'ok' };
			out.unlink = true;
		} else if (l && l.state === 'logged_out') {
			out.state = 'logged_out';
			const date = linkDate(l.since, ctx.locale);
			const why = t(`chat.br.sub_logged_out_${n.id}`);
			out.sub = [date ? t('chat.br.sub_logged_out_at', { date }) : t('chat.br.sub_logged_out'), why !== `chat.br.sub_logged_out_${n.id}` ? why : ''].filter(Boolean).join(' ');
			out.pill = { text: t('chat.br.pill_logged_out'), tone: 'err' };
		} else if (l) {
			out.state = 'error';
			out.sub = t('chat.br.sub_error');
			out.pill = { text: t('chat.br.pill_error'), tone: 'err' };
			out.unlink = true;
		} else if (!n.allowed) {
			out.state = 'locked';
			out.sub = t('chat.br.sub_locked');
			out.pill = { text: t('chat.br.pill_locked'), tone: 'off' };
		} else {
			out.sub = t('chat.br.sub_none');
			out.link = true;
		}
		// signed out or failed: a new code is enough (the notes were confirmed before)
		if (l && ['logged_out', 'error', 'unknown'].includes(l.state) && n.state === 'running') {
			out.again = { hint: t(n.allowed ? 'chat.br.relink_hint' : 'chat.br.sub_locked'), link: !!n.allowed, forget: l.state === 'logged_out' };
		}
		// Messenger 1.17: the bridge's warning — the phone was not seen for 12 days and more (the link still works)
		out.phone = phoneWarning(n, l, t);
		return out;
	}

	/** „Brücke veraltet“: older than intended (`outdated`) or, Messenger 1.17, refused by the service (`clientOutdated`). */
	function isOutdated(n) {
		return !!n && (n.outdated === true || n.clientOutdated === true);
	}

	/**
	 * Messenger 1.17: „Handy seit {days} Tagen nicht gesehen. Öffne WhatsApp …“ under a service whose phone the bridge
	 * did not see for days (`phone.offline`), not for a login that is signed out; `leftDays: 0` → „… jederzeit trennen“.
	 * → the text or null.
	 */
	function phoneWarning(n, l, t) {
		const p = n && n.phone && typeof n.phone === 'object' ? n.phone : null;
		if (!p || p.offline !== true || !l || l.state === 'logged_out') return null;
		const days = Number.isSafeInteger(p.days) && p.days > 0 ? p.days : 12;
		const name = bridgeName(n.id);
		return t(p.leftDays === 0 ? 'chat.br.phone_offline_now' : 'chat.br.phone_offline', { name, days });
	}

	// Messenger 1.17: what of the older messages comes over at a new link
	const HISTORY_DAYS = [0, 30, -1];

	/** „Aus“ / „Letzte 30 Tage“ / „Alles“. */
	function historyLabel(d, t) {
		if (d === 0) return t('chat.br.hist_off');
		if (d < 0) return t('chat.br.hist_all');
		return t('chat.br.hist_days', { n: d });
	}

	/**
	 * The row „Älteren Verlauf laden“ (GET bridges → history) → null (a server without it: no row) or { title, sub,
	 * available, value, options: [{ value, label }] }. Switched off by the administrator: no choice, „Auf diesem Server
	 * abgeschaltet“; `pending` adds „· N kommen heute Nacht“.
	 */
	function historyRow(h, t, nets) {
		if (!h || typeof h !== 'object') return null;
		const days = HISTORY_DAYS.includes(h.days) ? h.days : 30;
		const opts = (Array.isArray(h.options) ? h.options : HISTORY_DAYS).filter((d) => HISTORY_DAYS.includes(d));
		const list = opts.length ? opts : HISTORY_DAYS;
		const available = h.available === true;
		let sub = available ? t('chat.br.hist_sub', { choice: historyLabel(days, t) }) : t('chat.br.hist_admin_off');
		if (available && Number.isSafeInteger(h.pending) && h.pending > 0) sub += ` · ${t('chat.br.hist_pending', { n: h.pending })}`;
		// Messenger 1.23: a service that brings its history only at the link (Signal) — later there is nothing more
		const once = (Array.isArray(nets) ? nets : []).find((n) => n && n.history && n.history.phoneConfirms === true);
		if (once && available) sub += ` ${t('chat.br.hist_once', { name: bridgeName(once.id), n: once.history.maxDays || 30 })}`;
		return { title: t('chat.br.hist_title'), sub, available, value: days, options: available ? list.map((d) => ({ value: d, label: historyLabel(d, t) })) : [] };
	}

	/** Messenger 1.17: an inbox entry / push of „Verknüpfte Dienste“ (topic `bridge`, deepLink bridges)? */
	function isBridgePush(entry) {
		if (!entry || typeof entry !== 'object') return false;
		const topic = str(entry.topic);
		const data = entry.data && typeof entry.data === 'object' ? entry.data : {};
		return topic === 'plugin:gatecontrol-messenger:bridge' || (topic.startsWith('plugin:gatecontrol-messenger:') && data.deepLink === 'bridges');
	}

	/** Why an attempt to link ended, in words (a code that ran out reads differently from a refusal). */
	function linkErrorText(res, t) {
		const r = res && typeof res === 'object' ? res : { code: res };
		if (r.code === 'bridge_failed' && /timeout|expired/.test(str(r.reason))) return t('chat.br.err_expired');
		if (r.code === 'network' || r.code === 'timeout') return t('chat.br.err_no_answer');
		return errorText(r, t);
	}

	/** The pairing code in pieces for the big boxes: [{ ch, dash }]. */
	function codeChars(code) {
		return str(code).split('').map((ch) => ({ ch, dash: ch === '-' || ch === ' ' }));
	}

	/** A QR code's modules ({ size, rows }) → { size (with a quiet zone of 4), d (SVG path of the dark modules) }, or null. */
	function qrPath(matrix, quiet = 4) {
		const m = matrix && typeof matrix === 'object' ? matrix : null;
		if (!m || !Array.isArray(m.rows) || m.rows.length < 21 || m.rows.length > 177) return null;
		const n = m.rows.length;
		let d = '';
		for (let y = 0; y < n; y += 1) {
			const row = str(m.rows[y]);
			if (row.length !== n || /[^01]/.test(row)) return null;
			// one rectangle per run of dark modules
			for (let x = 0; x < n; x += 1) {
				if (row.charAt(x) !== '1') continue;
				let w = 1;
				while (x + w < n && row.charAt(x + w) === '1') w += 1;
				d += `M${x + quiet} ${y + quiet}h${w}v1h-${w}z`;
				x += w - 1;
			}
		}
		return { size: n + 2 * quiet, d };
	}

	/**
	 * The story durations to offer (Messenger 1.4.1 `story_duration`):
	 * `limits.storyDurationsH` limited to the known hours, all known hours
	 * when it sends none — null when the server takes no duration (24 h).
	 */
	function storyDurations(me) {
		if (!features14(me).storyDuration) return null;
		const src = me && me.limits && Array.isArray(me.limits.storyDurationsH) ? me.limits.storyDurationsH : null;
		const list = src ? STORY_DURATIONS_H.filter((h) => src.includes(h)) : [];
		return list.length ? list : STORY_DURATIONS_H.slice();
	}

	/** The own feed item's active stories → { count, viewers } (viewers: the views of all of them). */
	function ownStoryStats(item, now = Date.now()) {
		const list = (item && Array.isArray(item.stories) ? item.stories : []).filter((s) => s && !(s.expiresAt && new Date(s.expiresAt).getTime() <= now));
		return { count: list.length, viewers: list.reduce((n, s) => n + (Number(s.viewerCount) > 0 ? Number(s.viewerCount) : 0), 0) };
	}

	/** "2 Storys aktiv · Gesehen von 5" (card "Meine Storys"). */
	function ownStoryLine(stats, t) {
		const n = stats && stats.count ? stats.count : 0;
		return [n === 1 ? t('chat.st.storiesOne') : t('chat.st.storiesN', { n }), t('chat.story.viewers', { n: stats && stats.viewers ? stats.viewers : 0 })].join(' · ');
	}

	/**
	 * A story just posted, added to the feed before it is fetched again
	 * (shown at once in "Mein Status") → a new feed; a story already there is
	 * not added twice.
	 */
	function addOwnStory(feed, story, meUser) {
		const f = feed && typeof feed === 'object' ? feed : {};
		const items = Array.isArray(f.items) ? f.items : [];
		if (!story || typeof story !== 'object' || story.id == null) return { ...f, items };
		const u = meUser || {};
		const mine = f.me && typeof f.me === 'object' ? f.me : { user: { id: u.id, name: u.name, avatarUrl: u.avatarUrl, initials: u.initials, colorHex: u.colorHex }, status: null, stories: [], unseen: false };
		const stories = Array.isArray(mine.stories) ? mine.stories.filter((s) => s && s.id !== story.id) : [];
		stories.push({ viewerCount: 0, reactionCount: 0, ...story, seen: true });
		return { ...f, items, me: { ...mine, stories } };
	}

	/** integrations.familie of `GET me` → { lists, calendar, places }. */
	function familie(me) {
		const x = me && me.integrations && me.integrations.familie ? me.integrations.familie : {};
		return { lists: x.lists === true, calendar: x.calendar === true, places: x.places === true };
	}

	function presetLabel(preset, t) {
		const key = `chat.st.preset.${preset}`;
		const v = t(key);
		return v !== key ? v : '';
	}

	/** One line of a status: "Im Homeoffice · bis 17:00", "Unterwegs nach Zuhause · ca. 17:40". */
	function statusLine(st, ctx, now = Date.now()) {
		if (!st || typeof st !== 'object') return '';
		const t = ctx.t;
		let text = str(st.text) || presetLabel(st.preset, t);
		if (st.preset === 'away' && st.destLabel && !st.text) text = t('chat.st.awayTo', { place: st.destLabel });
		const parts = [text];
		if (st.preset === 'away' && st.eta) parts.push(t('chat.st.eta', { time: hm(st.eta, ctx.locale) }));
		else if (st.until && new Date(st.until).getTime() > now) parts.push(t('chat.st.untilShort', { time: shortWhen(st.until, ctx, now) }));
		return parts.filter(Boolean).join(' · ');
	}

	/** "17:00" today, "Sa. 17:00" within a week, else "24.10. 17:00". */
	function shortWhen(iso, ctx, now = Date.now()) {
		const d = new Date(iso);
		if (Number.isNaN(d.getTime())) return '';
		const diff = Math.round((dayStart(d) - dayStart(new Date(now))) / DAY);
		if (diff === 0) return hm(iso, ctx.locale);
		if (diff > 0 && diff < 7) return `${d.toLocaleDateString(localeTag(ctx.locale), { weekday: 'short' })} ${hm(iso, ctx.locale)}`;
		return `${d.toLocaleDateString(localeTag(ctx.locale), { day: '2-digit', month: '2-digit' })} ${hm(iso, ctx.locale)}`;
	}

	/** Ring of a person in the status strip: 'unseen' (glow), 'seen', 'none' (status only). */
	function statusRing(item) {
		const stories = item && Array.isArray(item.stories) ? item.stories : [];
		if (!stories.length) return 'none';
		return stories.some((s) => s && !s.seen) ? 'unseen' : 'seen';
	}

	/** Index of the first unseen story of a person (0 when all are seen). */
	function firstUnseen(stories) {
		const list = Array.isArray(stories) ? stories : [];
		const i = list.findIndex((s) => s && !s.seen);
		return i < 0 ? 0 : i;
	}

	/** "gerade eben", "vor 12 Min.", "vor 3 Std." */
	function relAge(iso, ctx, now = Date.now()) {
		const ms = now - new Date(iso).getTime();
		if (!Number.isFinite(ms)) return '';
		const min = Math.floor(ms / 60000);
		if (min < 1) return ctx.t('chat.rel.now');
		if (min < 60) return ctx.t('chat.rel.minAgo', { n: min });
		return ctx.t('chat.rel.hAgo', { n: Math.floor(min / 60) });
	}

	/** "noch 23 Std." / "noch 12 Min." until a story expires. */
	function remaining(iso, ctx, now = Date.now()) {
		const ms = new Date(iso).getTime() - now;
		if (!Number.isFinite(ms) || ms <= 0) return '';
		const min = Math.ceil(ms / 60000);
		return min < 60 ? ctx.t('chat.rel.minLeft', { n: min }) : ctx.t('chat.rel.hLeft', { n: Math.floor(min / 60) });
	}

	/** "Löschen nach" of the status dialog → [{ key, at (ISO|null) }]. */
	function untilOptions(now = Date.now()) {
		const end = new Date(now);
		end.setHours(23, 59, 0, 0);
		return [
			{ key: '30m', at: new Date(now + 30 * 60000).toISOString() },
			{ key: '1h', at: new Date(now + 3600000).toISOString() },
			{ key: '4h', at: new Date(now + 4 * 3600000).toISOString() },
			{ key: 'today', at: end.toISOString() },
			{ key: 'never', at: null },
		];
	}

	/** "Erinnere mich" choices → [{ key, at }]: in 1 h, this evening 18:00 (else tomorrow), tomorrow 09:00, next week. */
	function remindOptions(now = Date.now()) {
		const d = new Date(now);
		const evening = new Date(d.getFullYear(), d.getMonth(), d.getDate(), 18, 0, 0, 0);
		if (evening.getTime() <= now + 15 * 60000) evening.setDate(evening.getDate() + 1);
		const tomorrow = new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1, 9, 0, 0, 0);
		const week = new Date(d.getFullYear(), d.getMonth(), d.getDate() + 7, 9, 0, 0, 0);
		return [
			{ key: '1h', at: new Date(now + 3600000).toISOString() },
			{ key: 'evening', at: evening.toISOString() },
			{ key: 'tomorrow', at: tomorrow.toISOString() },
			{ key: 'week', at: week.toISOString() },
		];
	}

	/**
	 * A poll for the bubble: options with share of the votes (0…100), own
	 * choice, voters (when not anonymous), the leading options once votes exist.
	 */
	function pollView(poll, ctx) {
		const p = poll && typeof poll === 'object' ? poll : {};
		const opts = Array.isArray(p.options) ? p.options : [];
		const mine = new Set(Array.isArray(p.myVotes) ? p.myVotes : []);
		const max = opts.reduce((n, o) => Math.max(n, Number(o.count) || 0), 0);
		const sum = opts.reduce((n, o) => n + (Number(o.count) || 0), 0);
		const meId = ctx && ctx.me && ctx.me.user ? ctx.me.user.id : null;
		return {
			question: str(p.question),
			closed: !!p.closed,
			multi: !!p.multi,
			anonymous: !!p.anonymous,
			allowAdd: !!p.allowAdd && !p.closed,
			voterCount: Number(p.voterCount) || 0,
			memberCount: Number(p.memberCount) || 0,
			mineCreator: meId !== null && p.creatorId === meId,
			voted: mine.size > 0,
			options: opts.map((o) => {
				const count = Number(o.count) || 0;
				return {
					id: o.id, text: str(o.text), count, mine: mine.has(o.id),
					pct: sum > 0 ? Math.round((count / sum) * 100) : 0,
					lead: max > 0 && count === max,
					voters: Array.isArray(o.voters) ? o.voters : null,
				};
			}),
		};
	}

	/** Option ids after a click: single choice → [id] (again → []), multi → toggled. */
	function nextVotes(poll, optionId) {
		const mine = Array.isArray(poll && poll.myVotes) ? poll.myVotes.slice() : [];
		if (!(poll && poll.multi)) return mine.length === 1 && mine[0] === optionId ? [] : [optionId];
		return mine.includes(optionId) ? mine.filter((x) => x !== optionId) : mine.concat(optionId);
	}

	/** Bubble head of a poll: "ABSTIMMUNG · endet Sa. 18:00" / "· beendet". */
	function pollHead(poll, ctx, now = Date.now()) {
		const t = ctx.t;
		if (poll && poll.closed) return `${t('chat.poll.head')} · ${t('chat.poll.closed')}`;
		if (poll && poll.closesAt) return `${t('chat.poll.head')} · ${t('chat.poll.ends', { time: shortWhen(poll.closesAt, ctx, now) })}`;
		return t('chat.poll.head');
	}

	/** Answers of an event: { yes (people + guests), maybe, no, mine, myGuests }. */
	function rsvpCounts(rsvp) {
		const r = rsvp && typeof rsvp === 'object' ? rsvp : {};
		const list = (k) => (Array.isArray(r[k]) ? r[k] : []);
		return {
			yes: list('yes').reduce((n, x) => n + 1 + (Number(x && x.guests) || 0), 0),
			maybe: list('maybe').length,
			no: list('no').length,
			mine: ['yes', 'maybe', 'no'].includes(r.mine) ? r.mine : null,
			myGuests: Number(r.myGuests) || 0,
		};
	}

	/** Date badge and times of an event: { month 'OKT', day '26', weekday 'SO', time '12:30 – 16:00', rel 'in 8 Tagen', past }. */
	function eventView(ev, ctx, now = Date.now()) {
		const e = ev && typeof ev === 'object' ? ev : {};
		const d = new Date(e.startsAt);
		if (Number.isNaN(d.getTime())) return { month: '', day: '', weekday: '', time: '', rel: '', past: false };
		const tag = localeTag(ctx.locale);
		const end = e.endsAt ? new Date(e.endsAt) : null;
		let time;
		if (e.allDay) time = ctx.t('chat.event.allDay');
		else time = hm(e.startsAt, ctx.locale) + (end && !Number.isNaN(end.getTime()) ? ` – ${hm(e.endsAt, ctx.locale)}` : '');
		const days = Math.round((dayStart(d) - dayStart(new Date(now))) / DAY);
		let rel = '';
		if (days === 0) rel = ctx.t('chat.rel.today');
		else if (days === 1) rel = ctx.t('chat.event.tomorrow');
		else if (days > 1) rel = ctx.t('chat.event.inDays', { n: days });
		const over = (end && !Number.isNaN(end.getTime()) ? end.getTime() : d.getTime() + (e.allDay ? DAY : 0)) < now;
		return {
			month: d.toLocaleDateString(tag, { month: 'short' }).replace('.', '').toUpperCase(),
			day: String(d.getDate()),
			weekday: d.toLocaleDateString(tag, { weekday: 'short' }).replace('.', '').toUpperCase(),
			date: d.toLocaleDateString(tag, { weekday: 'short', day: '2-digit', month: '2-digit' }),
			time,
			rel,
			past: over,
		};
	}

	/** May the viewer edit / cancel an event (creator, or a group admin)? */
	function canEditEvent(ev, c, ctx) {
		const meId = ctx && ctx.me && ctx.me.user ? ctx.me.user.id : null;
		if (!ev || ev.cancelled || meId === null) return false;
		if (ev.creatorId === meId) return true;
		return !!(c && c.kind === 'group' && c.me && c.me.role === 'admin');
	}

	/** "3,1 km" / "450 m" */
	function distanceText(m, locale) {
		const v = Number(m);
		if (!Number.isFinite(v) || v < 0) return '';
		if (v < 1000) return `${Math.round(v / 10) * 10} m`;
		return `${(v / 1000).toLocaleString(localeTag(locale), { maximumFractionDigits: 1 })} km`;
	}

	/** A live arrival for the bubble: { state, label, eta '17:40', minutes, distance, progress 0…1, live }. */
	function arrivalView(a, ctx, now = Date.now()) {
		const x = a && typeof a === 'object' ? a : {};
		const state = ['live', 'arrived', 'stopped'].includes(x.state) ? x.state : 'stopped';
		const eta = x.etaAt && !Number.isNaN(new Date(x.etaAt).getTime()) ? x.etaAt : null;
		const minutes = eta ? Math.max(0, Math.round((new Date(eta).getTime() - now) / 60000)) : null;
		const p = Number(x.progress);
		return {
			state,
			live: state === 'live',
			label: str(x.dest && x.dest.label) || ctx.t('chat.arrival.dest'),
			eta: eta ? hm(eta, ctx.locale) : '',
			minutes,
			distance: distanceText(x.distanceM, ctx.locale),
			progress: state === 'arrived' ? 1 : (Number.isFinite(p) ? Math.max(0, Math.min(1, p)) : 0),
			position: x.position && Number.isFinite(x.position.lat) && Number.isFinite(x.position.lon) ? x.position : null,
			dest: x.dest && Number.isFinite(x.dest.lat) && Number.isFinite(x.dest.lon) ? x.dest : null,
		};
	}

	/**
	 * A home action message: head text, state line and the buttons the viewer
	 * gets (`can` of the server). A request counts as done only once approved.
	 */
	function actionView(m, c, ctx) {
		const t = ctx.t;
		const a = (m && m.action) || {};
		const can = a.can || {};
		const state = ['open', 'done', 'denied', 'expired'].includes(a.state) ? a.state : 'open';
		const label = str(a.label) || t('chat.kind.action');
		let head;
		if (a.mode === 'request') head = t('chat.action.headRequest', { name: nameOf(c, m.senderId, ctx, { you: false }) });
		else if (a.mode === 'grant') head = t('chat.action.headGrant');
		else head = t('chat.action.headRun');
		let sub = '';
		if (a.mode === 'grant' && a.grant) {
			sub = t('chat.action.grantTo', { name: nameOf(c, a.grant.toUserId, ctx), time: hm(a.grant.until, ctx.locale) });
		}
		const stateText = state === 'open' ? (a.mode === 'request' ? t('chat.action.waiting') : '') : t(`chat.action.state.${state}`);
		const open = state === 'open';
		return {
			head, label, sub, state, stateText,
			run: open && can.run === true && a.mode !== 'request',
			approve: open && can.approve === true && a.mode === 'request',
			deny: open && can.deny === true && a.mode === 'request',
			needsConfirm: a.needsConfirm === true,
			result: a.result && typeof a.result === 'object' ? a.result : null,
			icon: typeof a.icon === 'string' ? a.icon : null,
		};
	}

	/**
	 * Head of a plugin card: "KLINGEL · Haustür · 17:52"; a notice card of
	 * Messenger 1.6 names its notification: "Schule · Nachrichten der Schule · 17:52".
	 */
	function cardHead(m, ctx) {
		const card = (m && m.card) || {};
		const n = noticeOf(card);
		if (n && (n.sourceLabel || n.topicLabel)) return [n.sourceLabel, n.topicLabel, hm(m && m.createdAt, ctx.locale)].filter(Boolean).join(' · ');
		const kind = card.kind === 'doorbell' ? ctx.t('chat.card.doorbell') : ctx.t('chat.card.notice');
		return [kind, str(card.title), hm(m && m.createdAt, ctx.locale)].filter(Boolean).join(' · ');
	}

	/**
	 * A card link the app can open: another plugin's app route plg-<id>; since
	 * Messenger 1.6 it may name a screen of the plugin after a `/`
	 * (plg-gatecontrol-schule/messages/4711, at most three segments, no `.` / `..`).
	 */
	function cardRoute(link) {
		const r = link && typeof link.route === 'string' ? link.route : '';
		return r.length <= 200 && /^plg-[a-z0-9]+(?:-[a-z0-9]+)*(?:\/(?!\.{1,2}(?:\/|$))[A-Za-z0-9_.:-]{1,80}){0,3}$/.test(r) ? r : null;
	}

	const NOTICE_SOURCE_RE = /^(?:core|plugin:[a-z0-9]+(?:-[a-z0-9]+)*)$/;
	const NOTICE_TOPIC_RE = /^(?:[a-z][a-z0-9_]{0,31}|plugin:[a-z0-9]+(?:-[a-z0-9]+)*:[a-z][a-z0-9_-]{0,31})$/;
	const NOTIFY_MEDIA_RE = /^\/notify-media\/[A-Za-z0-9_-]{8,128}\.(?:jpg|jpeg|png|webp)$/;
	const line = (v, max) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max) : '');

	/**
	 * The notification a notice card carries (Messenger 1.6 `card.notice`):
	 * { source, sourceLabel, topic, topicLabel, priority, data } with checked
	 * ids and plain labels, or null. `data` is untrusted (like a push's data).
	 */
	function noticeOf(card) {
		const n = card && card.notice && typeof card.notice === 'object' && !Array.isArray(card.notice) ? card.notice : null;
		if (!n) return null;
		const data = n.data && typeof n.data === 'object' && !Array.isArray(n.data) ? n.data : null;
		return {
			source: typeof n.source === 'string' && NOTICE_SOURCE_RE.test(n.source) ? n.source : null,
			sourceLabel: line(n.sourceLabel, 60) || null,
			topic: typeof n.topic === 'string' && NOTICE_TOPIC_RE.test(n.topic) ? n.topic : null,
			topicLabel: line(n.topicLabel, 80) || null,
			priority: ['info', 'normal', 'high', 'critical'].includes(n.priority) ? n.priority : 'normal',
			data,
		};
	}

	/** The picture of a notice card on the own server (`imageUrl`: /notify-media/…), or null. */
	function noticeImage(card) {
		const u = card && typeof card.imageUrl === 'string' ? card.imageUrl.trim() : '';
		return NOTIFY_MEDIA_RE.test(u) ? u : null;
	}

	/**
	 * A card's link → { route, label, icon, target } or null: `target` is what
	 * notify.open() gets ({ route, topic, data } of the card's notification),
	 * so the link opens what a click on that notification would.
	 */
	function cardLink(card, t) {
		const l = card && card.link && typeof card.link === 'object' ? card.link : null;
		const route = cardRoute(l);
		if (!route) return null;
		const n = noticeOf(card);
		return {
			route,
			label: line(l.label, 40) || t('chat.card.open'),
			icon: l.kind === 'live_view' ? 'video' : 'external',
			target: { route, topic: n ? n.topic : null, data: n ? n.data : null },
		};
	}

	/** A notice channel of Messenger 1.6 (`notice { source, label }`): GateControl's notifications of one source. */
	function isNotice(c) {
		return !!(c && c.notice && typeof c.notice === 'object' && !Array.isArray(c.notice));
	}

	/** The source name of a notice channel ("Schule"), or ''. */
	function noticeLabel(c) {
		return isNotice(c) ? line(c.notice.label, 60) : '';
	}

	/**
	 * The chat list's sections (Messenger 1.6): under "Angeheftet" the chats
	 * the server pins to the list (`listPinned`, the family group) after the
	 * GateControl entry, under "Chats" the rest — each in its order. Without
	 * sections (search) pinned chats simply appear among the results.
	 */
	function listSections(list, { sectioned = true } = {}) {
		const items = Array.isArray(list) ? list : [];
		if (!sectioned) return { pinned: [], chats: items };
		return { pinned: items.filter((c) => c && c.listPinned === true), chats: items.filter((c) => !(c && c.listPinned === true)) };
	}

	/** SVG path data of an action icon (24 × 24) when it looks like one, else null. */
	function iconPath(d) {
		return typeof d === 'string' && d.length <= 2000 && /^[MmLlHhVvCcSsQqTtAaZz0-9.,\s-]+$/.test(d) ? d : null;
	}

	/** "online" / "zuletzt online heute um 17:44" / null (hidden or unknown). */
	function lastSeenText(p, ctx, now = Date.now()) {
		if (!p || p.gone) return null;
		if (p.online === true) return ctx.t('chat.seen.online');
		if (!p.lastSeenAt) return null;
		const d = new Date(p.lastSeenAt);
		if (Number.isNaN(d.getTime())) return null;
		const diff = Math.round((dayStart(new Date(now)) - dayStart(d)) / DAY);
		const time = hm(p.lastSeenAt, ctx.locale);
		if (diff <= 0) return ctx.t('chat.seen.today', { time });
		if (diff === 1) return ctx.t('chat.seen.yesterday', { time });
		return ctx.t('chat.seen.date', { date: d.toLocaleDateString(localeTag(ctx.locale), { day: '2-digit', month: '2-digit' }), time });
	}

	/**
	 * The chat list for a filter chip: 'all' | 'unread' | 'groups' | 'list:<id>',
	 * archived chats apart (archived: true shows only those).
	 */
	function listFilter(list, { filter = 'all', archived = false, lists = [] } = {}) {
		const items = (Array.isArray(list) ? list : []).filter((c) => !!c.archived === !!archived);
		if (archived || filter === 'all') return items;
		// Messenger 1.14: „Nur GateControl“ and one chip per linked service
		// Messenger 1.21: a person counts for every way it has
		if (filter === 'gc') return items.filter((c) => (isPerson(c) ? personWays(c).some((w) => w.way === GC_WAY) : !bridgeOf(c)));
		if (str(filter).startsWith('net:')) return items.filter((c) => (isPerson(c) ? personWays(c).some((w) => `net:${w.way}` === filter) : bridgeOf(c) && `net:${bridgeOf(c).network}` === filter));
		if (filter === 'unread') return items.filter((c) => (c.unread || 0) > 0);
		if (filter === 'groups') return items.filter((c) => c.kind === 'group');
		if (str(filter).startsWith('list:')) {
			const l = (Array.isArray(lists) ? lists : []).find((x) => x && `list:${x.id}` === filter);
			const ids = new Set(l && Array.isArray(l.conversationIds) ? l.conversationIds : []);
			// Messenger 1.21: an entry with the id of any way of a person counts for it
			return items.filter((c) => ids.has(c.id) || (isPerson(c) && c.person.ways.some((w) => ids.has(w.conversationId))));
		}
		return items;
	}

	/** Archived chats and their unread messages (the "Archiviert" row). */
	function archivedInfo(list) {
		const a = (Array.isArray(list) ? list : []).filter((c) => c.archived);
		return { count: a.length, unread: a.reduce((n, c) => n + (c.muted ? 0 : (c.unread || 0)), 0) };
	}

	/** Home actions for the attach menu without the ones switched off in "Haus-Aktionen" (ids). */
	function shownActions(actions, hidden) {
		const off = new Set(Array.isArray(hidden) ? hidden : []);
		return (Array.isArray(actions) ? actions : []).filter((a) => a && typeof a.id === 'string' && !off.has(a.id));
	}

	/** A new id for a custom chat list ([A-Za-z0-9_-]{1,40}). */
	function listId(name, existing) {
		const base = str(name).toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 30) || 'liste';
		const taken = new Set((Array.isArray(existing) ? existing : []).map((l) => l && l.id));
		let id = base;
		for (let i = 2; taken.has(id); i++) id = `${base}-${i}`;
		return id;
	}

	/** Font size choice → scale of the chat text. */
	function fontScale(size) {
		return size === 'small' ? 0.92 : size === 'large' ? 1.14 : 1;
	}

	/** <input type="datetime-local"> value of a time (local), and back to ISO. */
	function localInput(iso) {
		const d = new Date(iso);
		if (Number.isNaN(d.getTime())) return '';
		const p = (n) => String(n).padStart(2, '0');
		return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
	}
	function fromLocalInput(v) {
		if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(v)) return null;
		const d = new Date(v);
		return Number.isNaN(d.getTime()) ? null : d.toISOString();
	}

	return {
		SHOWN_KINDS,
		isShownKind,
		STORY_EMOJIS,
		STORY_COLORS,
		STORY_DURATIONS_H,
		STORY_DURATION_DEFAULT_H,
		PRESETS,
		features14,
		GC_WAY, isPerson, wayOf, wayLabel, personWays, personSub, replyWay, wayConv, sendConv, msgConv, sourceChips, personNameOptions, personNameValue,
		mergeNameOptions, mergeRequest, canMergeByHand, filterCandidates,
		isChannel, channelEntryText, channelNetworks, filterChannels, hasOwnReaction, safeHref, linkify, richText, linkPreview, netGlyph,
		bridgeOf, bridgeName, bridgeMark, bridgeLabel, bridgeNetworks, bridgeBlock, senderName, quoteName, senderKey, placeholderOf, placeholderText, bridgeFailure,
		bridgeOutKind, bridgeTakesFiles, bridgeMediaRefusal, bridgeImageType, voiceMime, mediaTypeText,
		NEW_CHAT_CC, newChatNumber, formatNumber, newChatServices, newChatState, newChatErrorState,
		CONTACTS_NET, CONTACTS_FIRST, phoneKindText, contactPhonesSub, firstName, contactsShown, contactsService, contactChatError, startedLine,
		LINK_NOTES, LINK_FLOWS, LINK_QR_STEPS, linkFlows, flowLabel, bridgeExtras, channelsOf, qrSteps, historyLine, linkable, mainLogin, linkDate, linkedRow, isOutdated, phoneWarning, historyRow, historyLabel, isBridgePush, HISTORY_DAYS, linkErrorText, codeChars, qrPath,
		storyDurations,
		ownStoryStats,
		ownStoryLine,
		addOwnStory,
		familie,
		presetLabel,
		statusLine,
		shortWhen,
		statusRing,
		mixFeed,
		firstUnseen,
		relAge,
		remaining,
		untilOptions,
		remindOptions,
		pollView,
		nextVotes,
		pollHead,
		rsvpCounts,
		eventView,
		canEditEvent,
		distanceText,
		arrivalView,
		actionView,
		cardHead,
		cardRoute,
		noticeOf,
		noticeImage,
		cardLink,
		isNotice,
		noticeLabel,
		listSections,
		iconPath,
		lastSeenText,
		listFilter,
		archivedInfo,
		shownActions,
		listId,
		fontScale,
		localInput,
		fromLocalInput,
		EMOJIS,
		member,
		nameOf,
		title,
		avatarOf,
		personAvatar,
		initials,
		disLabel,
		systemText,
		duration,
		hasFeature,
		videoInfo,
		videoFrameTime,
		THUMB_STEPS,
		thumbSteps,
		updateHint,
		mediaFilters,
		mediaTotal,
		summary,
		typingText,
		preview,
		hm,
		listTime,
		dayLabel,
		when,
		bytes,
		status,
		withinWindow,
		messageActions,
		timeline,
		filterConversations,
		muteValue,
		mutePatch,
		headSub,
		composerBlock,
		fileBadge,
		errorText,
		mediaScan,
		notSentText,
		unavailableText,
		waveform,
		recordingMime,
		scaledSize,
		attachKind,
		bubbleSize,
		mapUrl,
		inboxRow,
		TILE,
		MAP_MIN_ZOOM,
		MAP_MAX_ZOOM,
		clampZoom,
		worldPx,
		lonLat,
		tileGrid,
		metersPerPx,
		zoomForAccuracy,
		roundCoord,
		coordText,
		geoError,
		locationBody,
		inboxTimeline,
		inboxFirstUnread,
		inboxSeen,
	};
});
