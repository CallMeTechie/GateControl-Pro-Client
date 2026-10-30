/**
 * GateControl -- Mail view state (renderer, no DOM access)
 *
 * Pure helpers for the page "Mail" (plugin gatecontrol-mail, Phase 1): times
 * and dates of the list, initials and colours of the accounts, the title of
 * what is shown (Alle Posteingänge, an account's inbox or folder, search,
 * Zum Ablegen, Postausgang), the folder tree of an account, the quick actions
 * of a row (the swipe actions of the settings), the AI chips, Drive
 * suggestions, recipients as typed, "Senden planen" presets, the undo
 * countdown, the provider list of "Konto hinzufügen" and the error texts of
 * Mail's codes. Loaded as a plain script before mail-view.js
 * (window.GCMailState) and required by the node tests
 * (test/mail-state.test.js).
 *
 * Inputs are what window.gatecontrol.mail returns (core MailService, answers
 * cleaned by core utils/mail.js); `t` is the i18n function (keys mail.* of
 * the app locales).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCMailState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const DAY = 24 * 60 * 60 * 1000;
	const ROLE_ORDER = ['inbox', 'drafts', 'sent', 'archive', 'junk', 'trash'];
	const SWIPES = ['archive', 'delete', 'read', 'none'];
	const COLORS = ['#F5B544', '#79B8FF', '#FF8080', '#46E0A0', '#B79CFF', '#F28CC2', '#5FD3E0', '#C7CDD6'];
	const PROVIDER_LOOK = {
		m365: ['MS', '#1F4FA0', '#FFFFFF'],
		outlook: ['MS', '#1F4FA0', '#FFFFFF'],
		gmx: ['GMX', '#1C449B', '#FFFFFF'],
		webde: ['WEB', '#FFD800', '#1A1D22'],
		tonline: ['T', '#E20074', '#FFFFFF'],
		gmail: ['G', '#FFFFFF', '#D93025'],
		imap: ['@', '#262D38', '#E6EAF0'],
	};
	const EMAIL_RE = /^[^\s@<>()",;:\\[\]]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z0-9-]{2,63}$/;

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const pad = (n) => String(n).padStart(2, '0');
	const localeTag = (l) => (l === 'en' ? 'en-GB' : 'de-DE');
	const startOfDay = (ms) => { const d = new Date(ms); d.setHours(0, 0, 0, 0); return d.getTime(); };

	// ── Times, sizes, names ──────────────────────────────

	/** The time of a list row: 09:42 today, "Gestern", a weekday this week, 03.11., 03.11.25 in another year. */
	function timeLabel(ms, now, locale, t) {
		if (!Number.isFinite(ms) || ms <= 0) return '';
		const d = new Date(ms);
		const today = startOfDay(now);
		if (ms >= today) return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
		if (ms >= today - DAY) return t('mail.time.yesterday');
		if (ms >= today - 6 * DAY) return d.toLocaleDateString(localeTag(locale), { weekday: 'short' }).replace(/\.$/, '');
		const n = new Date(now);
		if (d.getFullYear() === n.getFullYear()) return locale === 'en' ? `${pad(d.getDate())}/${pad(d.getMonth() + 1)}` : `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.`;
		return locale === 'en' ? `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${String(d.getFullYear()).slice(2)}` : `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${String(d.getFullYear()).slice(2)}`;
	}

	/** The full date of a mail ("Di., 3. Nov. 2026, 08:15"). */
	function fullDate(ms, locale) {
		if (!Number.isFinite(ms) || ms <= 0) return '';
		return new Date(ms).toLocaleString(localeTag(locale), { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
	}

	function bytes(n, locale) {
		const v = Number(n) || 0;
		const fmt = (x, d) => x.toLocaleString(localeTag(locale), { maximumFractionDigits: d });
		if (v < 1024) return `${v} B`;
		if (v < 1024 * 1024) return `${fmt(v / 1024, 0)} KB`;
		if (v < 1024 ** 3) return `${fmt(v / 1024 ** 2, 1)} MB`;
		return `${fmt(v / 1024 ** 3, 1)} GB`;
	}

	/** Name of an address ({ name, email }), else its address, else "Unbekannt". */
	function senderName(a, t) {
		return str(a && a.name).trim() || str(a && a.email).trim() || t('mail.unknownSender');
	}

	/** Two letters for the round picture of a row. */
	function initials(a) {
		const name = str(a && a.name).trim();
		if (name) {
			const words = name.replace(/[^\p{L}\p{N}\s]/gu, ' ').split(/\s+/).filter(Boolean);
			const ini = words.slice(0, 2).map((w) => w[0]).join('');
			if (ini) return ini.toUpperCase();
		}
		const mail = str(a && a.email);
		return (mail[0] || '?').toUpperCase();
	}

	/** Extension tag of an attachment (PDF, DOC, XLS …) and its tone. */
	function fileTag(name, mime) {
		const n = str(name).toLowerCase();
		const i = n.lastIndexOf('.');
		const ext = i > 0 ? n.slice(i + 1) : '';
		const m = str(mime).toLowerCase();
		if (ext === 'pdf' || m === 'application/pdf') return { tag: 'PDF', tone: 'err' };
		if (['doc', 'docx', 'odt', 'rtf'].includes(ext) || m.includes('wordprocessing')) return { tag: 'DOC', tone: 'info' };
		if (['xls', 'xlsx', 'ods', 'csv'].includes(ext) || m.includes('spreadsheet')) return { tag: 'XLS', tone: 'acc' };
		if (['ppt', 'pptx', 'odp'].includes(ext) || m.includes('presentation')) return { tag: 'PPT', tone: 'warn' };
		if (m.startsWith('image/') || ['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic'].includes(ext)) return { tag: 'IMG', tone: 'pro' };
		if (['zip', '7z', 'rar', 'gz'].includes(ext)) return { tag: 'ZIP', tone: 'warn' };
		if (['ics'].includes(ext) || m === 'text/calendar') return { tag: 'ICS', tone: 'info' };
		if (/^[a-z0-9]{1,4}$/.test(ext)) return { tag: ext.toUpperCase(), tone: 'muted' };
		return { tag: 'FILE', tone: 'muted' };
	}

	// ── Accounts, folders, what is shown ─────────────────

	function accountOf(me, id) {
		return ((me && me.accounts) || []).find((a) => a.id === id) || null;
	}

	function folderOf(folders, id) {
		for (const a of (folders && folders.accounts) || []) {
			const f = a.folders.find((x) => x.id === id);
			if (f) return { ...f, accountId: a.accountId };
		}
		return null;
	}

	/** The localized name of a folder with a role (Posteingang, Gesendet …), else its own name. */
	function folderName(f, t) {
		if (!f) return '';
		return f.role ? t(`mail.role.${f.role}`) : str(f.name);
	}

	/**
	 * An account's folders as a tree: the folders with a role first (Posteingang, Entwürfe, Gesendet, Archiv,
	 * Spam, Papierkorb), then the others by name; children below their parent → [{ folder, depth }].
	 */
	function folderTree(list) {
		const all = Array.isArray(list) ? list : [];
		const ids = new Set(all.map((f) => f.id));
		const kids = new Map();
		for (const f of all) {
			const p = f.parentId && ids.has(f.parentId) && f.parentId !== f.id ? f.parentId : 0;
			if (!kids.has(p)) kids.set(p, []);
			kids.get(p).push(f);
		}
		const rank = (f) => (f.role ? ROLE_ORDER.indexOf(f.role) : ROLE_ORDER.length);
		const sort = (a, b) => rank(a) - rank(b) || str(a.name).localeCompare(str(b.name), 'de', { sensitivity: 'base' });
		const out = [];
		const seen = new Set();
		const walk = (p, depth) => {
			for (const f of (kids.get(p) || []).sort(sort)) {
				if (seen.has(f.id)) continue;
				seen.add(f.id);
				out.push({ folder: f, depth });
				if (depth < 6) walk(f.id, depth + 1);
			}
		};
		walk(0, 0);
		return out;
	}

	/** The folder with this role of an account (folders answer), or null. */
	function roleFolder(folders, accountId, role) {
		const a = ((folders && folders.accounts) || []).find((x) => x.accountId === accountId);
		return a ? a.folders.find((f) => f.role === role) || null : null;
	}

	/** Does the view show an inbox (Relevant / Sonstige)? */
	function isInbox(view, folders) {
		if (!view || view.kind !== 'box') return false;
		if (!view.folderId) return true;
		const f = folderOf(folders, view.folderId);
		return !!(f && f.role === 'inbox');
	}

	/** Title and subtitle of the middle column. */
	function viewTitle(view, me, folders, t) {
		const accounts = (me && me.accounts) || [];
		const unread = (me && me.unread) || { all: 0, byAccount: {} };
		if (!view || view.kind === 'box') {
			const v = view || { box: 'all' };
			if (v.box === 'all') {
				return { title: t('mail.allInboxes'), sub: `${t(accounts.length === 1 ? 'mail.accounts.one' : 'mail.accounts.other', { count: accounts.length })} · ${t('mail.unreadCount', { count: unread.all || 0 })}` };
			}
			const acc = accountOf(me, v.box);
			const f = v.folderId ? folderOf(folders, v.folderId) : null;
			const n = f ? f.unread : (unread.byAccount && unread.byAccount[String(v.box)]) || 0;
			return { title: f ? folderName(f, t) : t('mail.role.inbox'), sub: `${acc ? acc.name : ''} · ${t('mail.unreadCount', { count: n })}` };
		}
		if (view.kind === 'search') return { title: t('mail.search.title'), sub: `„${str(view.q)}“` };
		if (view.kind === 'filing') return { title: t('mail.filing.title'), sub: t('mail.filing.sub') };
		if (view.kind === 'outbox') return { title: t('mail.outbox.title'), sub: '' };
		return { title: t('mail.title'), sub: '' };
	}

	/** List query of a box view (the tab only for an inbox). */
	function listQuery(view, folders, tab, filter) {
		const q = { box: view.box === 'all' ? 'all' : view.box, limit: 50 };
		if (view.folderId && view.box !== 'all') q.folder = view.folderId;
		if (isInbox(view, folders)) q.tab = tab === 'other' ? 'other' : 'relevant';
		const f = filter || {};
		if (f.unread) q.unread = true;
		if (f.flagged) q.flagged = true;
		if (f.attachments) q.attachments = true;
		return q;
	}

	/** Items of a list page after the ones shown (no doubles). */
	function mergeItems(old, items) {
		const seen = new Set((old || []).map((m) => m.id));
		return (old || []).concat((items || []).filter((m) => !seen.has(m.id)));
	}

	// ── Quick actions of a row (the swipe actions of the settings) ───

	/** The settings' swipe actions as buttons of a row: [{ action, icon, key }] (right first, no "none", no doubles). */
	function rowActions(settings, item) {
		const s = settings || {};
		const out = [];
		for (const a of [s.swipeRight, s.swipeLeft]) {
			if (!SWIPES.includes(a) || a === 'none' || out.some((x) => x.action === a)) continue;
			if (a === 'read') out.push({ action: 'read', icon: item && item.unread ? 'mailOpen' : 'mail', key: item && item.unread ? 'mail.act.markRead' : 'mail.act.markUnread' });
			else out.push({ action: a, icon: a === 'archive' ? 'archive' : 'trash', key: `mail.act.${a}` });
		}
		return out;
	}

	/** What an action does to a mail: { flags: { unread } } | { act: 'archive' | 'delete' | 'junk' }. */
	function actionCall(action, item) {
		if (action === 'read') return { flags: { unread: !(item && item.unread) } };
		if (action === 'flag') return { flags: { flagged: !(item && item.flagged) } };
		if (['archive', 'delete', 'junk'].includes(action)) return { act: action };
		return null;
	}

	// ── AI, Drive ─────────────────────────────────────────

	/**
	 * The to-dos of the AI as chips: deadlines and events with a date → "In den Familienkalender" when the family
	 * calendar is there ({ kind, text, index, calendar: true }); the others only show.
	 */
	function todoChips(ai, features) {
		if (!ai || ai.status !== 'done') return [];
		const cal = Array.isArray(features) && features.includes('familyCalendar');
		return (ai.todos || []).map((td, index) => ({
			index,
			kind: td.kind,
			text: td.text,
			calendar: cal && (td.kind === 'deadline' || td.kind === 'event') && !!td.date,
		}));
	}

	/** "95 % sicher" of a suggestion (or null). */
	function confidence(s) {
		return s && Number.isFinite(s.confidence) ? Math.round(s.confidence * 100) : null;
	}

	/** The line under a Drive suggestion: "in Finanzen › Strom · gelernt" / "· 72 % sicher". */
	function suggestionLine(s, t) {
		if (!s) return '';
		const where = str(s.path || s.where);
		const pct = confidence(s);
		const why = s.reason === 'rule' || s.reason === 'learned' ? t(`mail.drive.reason.${s.reason}`) : (pct !== null ? t('mail.drive.sure', { pct }) : '');
		return why ? t('mail.drive.inWhere', { where }) + ` · ${why}` : t('mail.drive.inWhere', { where });
	}

	// ── Writing ──────────────────────────────────────────

	function escapeHtml(s) {
		return str(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
	}

	/** Plain text (an AI reply, a signature) → paragraphs of HTML. */
	function textToHtml(text) {
		return str(text).replace(/\r\n?/g, '\n').split(/\n{2,}/).map((p) => `<p>${escapeHtml(p).replace(/\n/g, '<br>')}</p>`).join('');
	}

	/** The signature block put under a new mail ("-- " line, then the text). */
	function signatureHtml(sig) {
		const s = str(sig).trim();
		return s ? `<p><br></p><p class="gc-sig">-- <br>${escapeHtml(s).replace(/\r?\n/g, '<br>')}</p>` : '';
	}

	function isEmail(v) {
		return EMAIL_RE.test(str(v).trim());
	}

	/** "Name <a@b>" | "a@b" → { name, email } | null. */
	function parseAddress(raw) {
		const s = str(raw).trim();
		const m = /^(?:"?([^"<]*?)"?\s*)?<([^<>\s]+)>$/.exec(s);
		if (m) return isEmail(m[2]) ? { name: m[1].trim() || null, email: m[2] } : null;
		return isEmail(s) ? { name: null, email: s } : null;
	}

	/** Text of a recipient field → { list: [{ name, email }], bad: ['tim@'] } (split at , ; outside quotes). */
	function parseRecipients(text) {
		const parts = [];
		let cur = '';
		let quoted = false;
		for (const ch of str(text)) {
			if (ch === '"') quoted = !quoted;
			if (!quoted && (ch === ',' || ch === ';' || ch === '\n')) { if (cur.trim()) parts.push(cur.trim()); cur = ''; } else cur += ch;
		}
		if (cur.trim()) parts.push(cur.trim());
		const list = [];
		const bad = [];
		for (const p of parts) {
			const a = parseAddress(p);
			if (!a) bad.push(p);
			else if (!list.some((x) => x.email.toLowerCase() === a.email.toLowerCase())) list.push(a);
		}
		return { list, bad };
	}

	/** A recipient as a chip text: its name, else the address. */
	function recipientLabel(r) {
		return str(r && r.name).trim() || str(r && r.email);
	}

	/** "Senden planen": tonight 18:00 (before 17:00), tomorrow 08:00, Monday 08:00 → [{ key, at }]. */
	function sendPresets(now) {
		const at = (days, h) => { const d = new Date(now); d.setDate(d.getDate() + days); d.setHours(h, 0, 0, 0); return d.getTime(); };
		const out = [];
		if (new Date(now).getHours() < 17) out.push({ key: 'mail.schedule.tonight', at: at(0, 18) });
		out.push({ key: 'mail.schedule.tomorrow', at: at(1, 8) });
		const dow = new Date(now).getDay();
		const toMonday = ((8 - dow) % 7) || 7;
		if (toMonday > 1) out.push({ key: 'mail.schedule.monday', at: at(toMonday, 8) });
		return out;
	}

	/** <input type="datetime-local"> value → ms (local time), or null when not in the future. */
	function localInputMs(v, now) {
		const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(str(v));
		if (!m) return null;
		const ms = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5])).getTime();
		return Number.isFinite(ms) && ms > now + 60 * 1000 ? ms : null;
	}

	/** ms → value of <input type="datetime-local">. */
	function localInputValue(ms) {
		const d = new Date(ms);
		return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
	}

	/** Seconds left to undo a send (0 when over). */
	function undoLeft(undoUntil, now) {
		return Math.max(0, Math.ceil(((Number(undoUntil) || 0) - now) / 1000));
	}

	/** Recipients of "Allen antworten" besides the person's own address: is it more than one? */
	function canReplyAll(message, me) {
		if (!message) return false;
		const own = new Set(((me && me.accounts) || []).map((a) => str(a.email).toLowerCase()));
		const all = [message.from, ...(message.to || []), ...(message.cc || [])].filter((a) => a && a.email && !own.has(str(a.email).toLowerCase()));
		return new Set(all.map((a) => a.email.toLowerCase())).size > 1;
	}

	/** Size of the attachments sent as copies (bytes). */
	function attachmentBytes(list) {
		return (list || []).reduce((s, a) => s + (a && a.as !== 'link' ? Number(a.size) || 0 : 0), 0);
	}

	// ── Konto hinzufügen, settings ───────────────────────

	/**
	 * Rows of "Konto hinzufügen": Microsoft first, then as the server lists them; Microsoft without a client id on
	 * the server stays in the list, greyed, with "noch nicht eingerichtet" → [{ id, label, auth, hint, help, look, disabled }].
	 */
	function providerRows(providers, features, lang) {
		const ms = Array.isArray(features) && features.includes('microsoft');
		const rows = (providers || []).map((p) => ({
			id: p.id,
			label: p.label,
			auth: p.auth,
			hint: p.hint ? (lang === 'en' ? p.hint.en : p.hint.de) : null,
			help: p.help || null,
			look: PROVIDER_LOOK[p.id] || PROVIDER_LOOK.imap,
			disabled: p.auth === 'microsoft' && !ms,
		}));
		return rows.sort((a, b) => (b.auth === 'microsoft') - (a.auth === 'microsoft'));
	}

	/** A colour not yet taken by an account (the palette in order). */
	function freeColor(me) {
		const used = new Set(((me && me.accounts) || []).map((a) => str(a.color).toUpperCase()));
		return COLORS.find((c) => !used.has(c)) || COLORS[0];
	}

	/** Storage of the person: { used, total, pct, text } or null. */
	function quotaView(limits, locale, t) {
		const l = limits || {};
		if (!Number.isFinite(l.quotaBytes) || l.quotaBytes <= 0) return null;
		const used = Number(l.usedBytes) || 0;
		const pct = Math.min(100, Math.round((used / l.quotaBytes) * 100));
		return { used, total: l.quotaBytes, pct, text: t('mail.settings.storage', { used: bytes(used, locale), total: bytes(l.quotaBytes, locale) }) };
	}

	// ── Errors ───────────────────────────────────────────

	const ERR_KEYS = {
		network: 'offline', timeout: 'offline', not_configured: 'offline', http_502: 'offline', http_503: 'offline', http_504: 'offline',
		auth_failed: 'auth_failed', imap_disabled: 'imap_disabled', unreachable: 'unreachable', tls: 'tls', limit: 'limit',
		not_allowed: 'not_allowed', invalid: 'invalid', too_large: 'too_large', ai_off: 'ai_off', ai_unavailable: 'ai_unavailable',
		rate_limited: 'rate_limited', familie_unavailable: 'familie_unavailable', ms_unavailable: 'ms_unavailable', access_denied: 'access_denied',
		consent_required: 'consent_required', ms_not_configured: 'ms_not_configured', timeout_signin: 'timeout_signin', browser_failed: 'browser_failed',
		busy: 'busy', state_mismatch: 'signin_failed', invalid_response: 'signin_failed', drive_unavailable: 'drive_unavailable',
		mail_unavailable: 'mail_unavailable', unsafe: 'unsafe', not_found: 'not_found', open_failed: 'open_failed', missing: 'missing', empty: 'empty',
		encrypted: 'encrypted', forbidden: 'forbidden',
		microsoft_off: 'microsoft_off', attachments_unsupported: 'attachments_unsupported', images_blocked: 'images_blocked',
		images_off: 'images_off', no_folder: 'no_folder', not_waiting: 'not_waiting', login_required: 'login_required',
		exists: 'exists', links_disabled: 'links_disabled',
	};

	/** The text of a failed answer ({ code, detail }); the server's hint for a refused login. */
	function errorText(r, t, lang) {
		const code = str(r && r.code);
		const hint = r && r.detail && r.detail.hint ? (lang === 'en' ? r.detail.hint.en || r.detail.hint.de : r.detail.hint.de || r.detail.hint.en) : null;
		const key = ERR_KEYS[code] || (/^http_5/.test(code) ? 'offline' : 'failed');
		const base = t(`mail.err.${key}`);
		return hint ? `${base} ${hint}` : base;
	}

	return {
		COLORS,
		PROVIDER_LOOK,
		timeLabel,
		fullDate,
		bytes,
		senderName,
		initials,
		fileTag,
		accountOf,
		folderOf,
		folderName,
		folderTree,
		roleFolder,
		isInbox,
		viewTitle,
		listQuery,
		mergeItems,
		rowActions,
		actionCall,
		todoChips,
		confidence,
		suggestionLine,
		escapeHtml,
		textToHtml,
		signatureHtml,
		isEmail,
		parseAddress,
		parseRecipients,
		recipientLabel,
		sendPresets,
		localInputMs,
		localInputValue,
		undoLeft,
		canReplyAll,
		attachmentBytes,
		providerRows,
		freeColor,
		quotaView,
		errorText,
	};
});
