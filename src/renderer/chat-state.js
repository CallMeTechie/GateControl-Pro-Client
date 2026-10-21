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
		return c.kind === 'direct' ? t('chat.gone') : t('chat.group');
	}

	/** Avatar description for the view: { kind: 'icon'|'person', icon?, name, initials, color, avatarUrl, mediaId }. */
	function avatarOf(c) {
		if (!c) return { kind: 'icon', icon: 'group' };
		if (c.kind === 'group') return { kind: 'icon', icon: c.readonly ? 'system' : 'group', mediaId: c.avatarMediaId || null };
		const p = c.peer;
		if (!p || p.gone) return { kind: 'icon', icon: 'gone' };
		return personAvatar(p);
	}

	function personAvatar(p) {
		return {
			kind: 'person',
			name: str(p.name),
			initials: str(p.initials) || initials(p.name),
			color: COLOR_RE.test(str(p.colorHex)) ? p.colorHex : '#64748B',
			avatarUrl: typeof p.avatarUrl === 'string' ? p.avatarUrl : null,
		};
	}

	function initials(name) {
		const parts = str(name || '?').trim().split(/\s+/);
		const a = (parts[0] || '?').charAt(0);
		const b = parts.length > 1 ? parts[parts.length - 1].charAt(0) : (parts[0] || '').charAt(1);
		return (a + (b || '')).toUpperCase();
	}

	function disLabel(s, t) {
		if (!s) return t('chat.dis.off');
		const key = `chat.dis.${s}`;
		const v = t(key);
		return v !== key ? v : t('chat.dis.seconds', { n: s });
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
			case 'disappearing': return s.seconds ? t('chat.sys.disOn', { name: who, time: disLabel(s.seconds, t) }) : t('chat.sys.disOff', { name: who });
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
		if (c.kind === 'group') return { text: `${nameOf(c, m.senderId, ctx)}: ${s}`, typing: false };
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
		if (m.pending) return m.failed ? 'failed' : 'pending';
		if (!m.mine || m.kind === 'system') return null;
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
	function messageActions(m, c, ctx, now = Date.now()) {
		const limits = (ctx.me && ctx.me.limits) || {};
		const features = (ctx.me && ctx.me.features) || {};
		if (!m || m.pending) return { reply: false, react: false, edit: false, deleteMe: false, deleteAll: false, copy: false, pin: false, pinned: false, remind: false, suggest: false };
		const live = !m.deleted && m.kind !== 'system';
		const canSend = !!(c && c.can && c.can.send);
		return {
			reply: live && canSend,
			react: live && features.reactions !== false && canSend,
			copy: live && !!m.text,
			edit: live && m.mine && ['text', 'image', 'file'].includes(m.kind) && features.edit !== false && withinWindow(m, limits, now),
			deleteMe: true,
			deleteAll: live && m.mine && withinWindow(m, limits, now),
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
			if (!unreadShown && unreadFrom !== null && !m.pending && !m.mine && m.id > unreadFrom && m.kind !== 'system') {
				out.push({ type: 'unread' });
				unreadShown = true;
				prev = null;
			}
			const cont = !!prev && prev.kind !== 'system' && m.kind !== 'system' && prev.senderId === m.senderId
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
	function composerBlock(c) {
		if (!c) return 'readonly';
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
		if (code) {
			const key = `chat.error.${code}`;
			const v = t(key);
			if (v !== key) return v;
		}
		return t('chat.error.failed');
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
		};
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
		if (filter === 'unread') return items.filter((c) => (c.unread || 0) > 0);
		if (filter === 'groups') return items.filter((c) => c.kind === 'group');
		if (str(filter).startsWith('list:')) {
			const l = (Array.isArray(lists) ? lists : []).find((x) => x && `list:${x.id}` === filter);
			const ids = new Set(l && Array.isArray(l.conversationIds) ? l.conversationIds : []);
			return items.filter((c) => ids.has(c.id));
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
		storyDurations,
		ownStoryStats,
		ownStoryLine,
		addOwnStory,
		familie,
		presetLabel,
		statusLine,
		shortWhen,
		statusRing,
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
