/**
 * GateControl -- Chats view state (renderer, no DOM access)
 *
 * Pure helpers for the page "Chats" (GateControl Messenger): names, titles,
 * list previews, system message texts, "schreibt …", ticks, the timeline
 * with day separators and the unread line, edit/delete windows, mute and
 * disappearing options, error texts, voice-recording helpers. Loaded as a
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
			default: return str(m && m.text);
		}
	}

	function duration(ms) {
		const s = Math.max(0, Math.round((Number(ms) || 0) / 1000));
		return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
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
			case 'file': return (m.meta && m.meta.fileName) || t('chat.kind.file');
			case 'location': return t('chat.kind.location') + (m.location && m.location.label ? `: ${m.location.label}` : '');
			case 'system': return systemText(m, c, ctx);
			default: return str(m.text);
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
		if (!m || m.pending) return { reply: false, react: false, edit: false, deleteMe: false, deleteAll: false, copy: false };
		const live = !m.deleted && m.kind !== 'system';
		const canSend = !!(c && c.can && c.can.send);
		return {
			reply: live && canSend,
			react: live && features.reactions !== false && canSend,
			copy: live && !!m.text,
			edit: live && m.mine && ['text', 'image', 'file'].includes(m.kind) && features.edit !== false && withinWindow(m, limits, now),
			deleteMe: true,
			deleteAll: live && m.mine && withinWindow(m, limits, now),
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
		if (c.readonly) return { text: ctx.t('chat.channelSub'), typing: false };
		if (c.kind === 'group') {
			const meId = ctx.me && ctx.me.user ? ctx.me.user.id : null;
			const names = (c.members || []).map((m) => (m.userId === meId ? ctx.t('chat.you') : (m.name || ctx.t('chat.gone'))));
			return { text: names.join(', '), typing: false };
		}
		if (c.peer && c.peer.gone) return { text: ctx.t('chat.peerGone'), typing: false };
		return { text: ctx.t('chat.directSub'), typing: false };
	}

	/** Why the composer is closed: null | 'readonly' | 'peerGone'. */
	function composerBlock(c) {
		if (!c) return 'readonly';
		if (c.readonly) return 'readonly';
		if (c.kind === 'direct' && c.peer && c.peer.gone) return 'peerGone';
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

	/** What to do with a dropped / picked file: 'image' (scaled), 'file', or null (refused) + reason. */
	function attachKind(file, limits) {
		const type = str(file && file.type).toLowerCase();
		const types = Array.isArray(limits && limits.types) ? limits.types : [];
		const max = Number(limits && limits.maxBytes) || Infinity;
		if (/^image\/(jpeg|png|webp|gif|bmp)$/.test(type)) return { kind: 'image' };
		if (!type || (types.length && !types.includes(type))) return { kind: null, reason: 'unsupported_type' };
		if (file.size > max) return { kind: null, reason: 'too_large' };
		return { kind: 'file' };
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

	return {
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
	};
});
