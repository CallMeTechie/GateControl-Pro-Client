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
 * Mail's codes. Phase 2: the calendar (ranges of the views, the day grid with
 * overlapping events, times, recurrence and reminder texts, the event form,
 * invitation states) and the contacts (letter sections, birthdays, the edit
 * form, merge choices, suggestions). Loaded as a plain script before mail-view.js
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

	/** From this depth on the folders in the menu are not indented any further. */
	const FOLDER_MAX_INDENT = 4;

	/**
	 * An account's folders as a tree: the folders with a role always on top (Posteingang, Entwürfe, Gesendet, Archiv,
	 * Spam, Papierkorb), then the others by name; children below their parent (parentId), by name. A parent the list
	 * does not hold (not synced) leaves its children on top, so does a loop → [{ folder, depth, parent, kids (ids),
	 * hasKids, unreadBelow (all unread below it) }], each parent before its children.
	 */
	function folderTree(list) {
		const all = (Array.isArray(list) ? list : []).filter((f) => f && f.id != null);
		const ids = new Set(all.map((f) => f.id));
		const parentOf = (f) => (!f.role && f.parentId && ids.has(f.parentId) && f.parentId !== f.id ? f.parentId : 0);
		const kids = new Map();
		for (const f of all) {
			const p = parentOf(f);
			if (!kids.has(p)) kids.set(p, []);
			kids.get(p).push(f);
		}
		const rank = (f) => (f.role && ROLE_ORDER.includes(f.role) ? ROLE_ORDER.indexOf(f.role) : ROLE_ORDER.length);
		const sort = (a, b) => rank(a) - rank(b) || str(a.name).localeCompare(str(b.name), 'de', { sensitivity: 'base' }) || a.id - b.id;
		const out = [];
		const seen = new Set();
		// → the unread mail of f and everything below it
		const walk = (f, depth, parent) => {
			seen.add(f.id);
			const node = { folder: f, depth, parent, kids: [], hasKids: false, unreadBelow: 0 };
			out.push(node);
			for (const c of (kids.get(f.id) || []).slice().sort(sort)) {
				if (seen.has(c.id)) continue;
				node.kids.push(c.id);
				node.unreadBelow += walk(c, depth + 1, f.id);
			}
			node.hasKids = node.kids.length > 0;
			return (Number(f.unread) || 0) + node.unreadBelow;
		};
		for (const f of (kids.get(0) || []).slice().sort(sort)) if (!seen.has(f.id)) walk(f, 0, null);
		for (const f of all.slice().sort(sort)) if (!seen.has(f.id)) walk(f, 0, null);
		return out;
	}

	/** The ids above folder `id` in a folderTree, its parent first. */
	function folderAncestors(tree, id) {
		const byId = new Map((tree || []).map((n) => [n.folder.id, n]));
		const out = [];
		let n = byId.get(id);
		while (n && n.parent != null && !out.includes(n.parent)) { out.push(n.parent); n = byId.get(n.parent); }
		return out;
	}

	/**
	 * Whether a folder shows its children in the menu: as folded by the person (ffolds: Map id → bool, kept on this
	 * PC), else closed — open when the folder shown (`current`) lies below it.
	 */
	function folderOpen(tree, ffolds, id, current) {
		if (ffolds && ffolds.has(id)) return !!ffolds.get(id);
		return current != null && folderAncestors(tree, current).includes(id);
	}

	/** A tap on a folder's arrow: its children open or close (ffolds is changed and returned). */
	function toggleFolder(tree, ffolds, id, current) {
		ffolds.set(id, !folderOpen(tree, ffolds, id, current));
		return ffolds;
	}

	/** A folder picked or pointed at: the folders above it open (ffolds is changed; → whether anything changed). */
	function revealFolder(tree, ffolds, id) {
		let changed = false;
		for (const a of folderAncestors(tree, id)) if (ffolds.get(a) !== true) { ffolds.set(a, true); changed = true; }
		return changed;
	}

	/**
	 * The rows the menu shows of a folderTree: the children of a closed folder are left out → [{ folder, depth, indent
	 * (the depth up to FOLDER_MAX_INDENT), hasKids, open, unreadBelow (only for a closed parent, else 0) }].
	 */
	function folderRows(tree, ffolds, current) {
		const out = [];
		let hiddenBelow = -1;
		for (const n of tree || []) {
			if (hiddenBelow >= 0) {
				if (n.depth > hiddenBelow) continue;
				hiddenBelow = -1;
			}
			const open = n.hasKids && folderOpen(tree, ffolds, n.folder.id, current);
			out.push({ folder: n.folder, depth: n.depth, indent: Math.min(n.depth, FOLDER_MAX_INDENT), hasKids: n.hasKids, open, unreadBelow: n.hasKids && !open ? n.unreadBelow : 0 });
			if (n.hasKids && !open) hiddenBelow = n.depth;
		}
		return out;
	}

	/** The folds of the folders as kept on this PC (JSON { id: bool }) → Map; anything else → an empty Map. */
	function folderFoldsOf(raw) {
		const m = new Map();
		try {
			const o = JSON.parse(raw || '{}');
			if (o && typeof o === 'object' && !Array.isArray(o)) for (const [k, v] of Object.entries(o)) if (/^\d+$/.test(k) && typeof v === 'boolean') m.set(Number(k), v);
		} catch { /* none */ }
		return m;
	}

	/** The folds of the folders → JSON to keep (at most the last 500). */
	function folderFoldsJson(ffolds) {
		const o = {};
		for (const [k, v] of [...(ffolds || new Map())].slice(-500)) o[k] = !!v;
		return JSON.stringify(o);
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
		// Phase 2: calendar and contacts
		conflict: 'conflict', read_only: 'read_only', feature_off: 'feature_off', not_supported: 'not_supported', send_failed: 'send_failed',
		invitation_outdated: 'invitation_outdated', invalid_vcard: 'invalid_vcard', invalid_ics: 'invalid_ics', dav_unavailable: 'dav_unavailable',
	};

	/** The text of a failed answer ({ code, detail }); the server's hint for a refused login. */
	// ── Accounts as the Outlook app shows them (Mail 1.1.2) ─────

	/** Microsoft's four squares, drawn by the page (no logo file). */
	const MS_TILES = ['#F25022', '#7FBA00', '#00A4EF', '#FFB900'];
	const ACCOUNT_MARKS = {
		outlook: { text: 'O', bg: '#0F6CBD', fg: '#FFFFFF' },
		m365: { text: '', bg: '#F3F4F6', fg: '#1A1D22', tiles: MS_TILES },
		gmail: { text: 'G', bg: '#FFFFFF', fg: '#EA4335' },
		gmx: { text: 'GMX', bg: '#1C449B', fg: '#FFFFFF', small: true },
		webde: { text: 'W', bg: '#FFD800', fg: '#1A1D22' },
		tonline: { text: 'T', bg: '#E20074', fg: '#FFFFFF' },
	};

	/**
	 * The round mark of an account without a picture: own simple signs in the provider's colour ("O", four squares,
	 * "G", "GMX", "W", "T"), else "@" in the account's colour → { text, bg, fg, tiles?, small? }.
	 */
	function accountMark(account) {
		const m = account && ACCOUNT_MARKS[account.provider];
		if (m) return { ...m };
		return { text: '@', bg: (account && account.color) || '#79B8FF', fg: '#0D1015' };
	}

	/** The address below the name (none when the name is the address). */
	function accountSub(account) {
		if (!account || !account.email) return null;
		return str(account.name).trim().toLowerCase() === account.email.toLowerCase() ? null : account.email;
	}

	// ── Loading later (Mail 1.1.2) ───────────────────────────

	/** How often an attachment or embedded picture still on its way is asked for again by itself. */
	const BUSY_RETRIES = 3;

	/**
	 * A failure `{ ok: false, code: 'busy', detail: { reason, retryAfter } }` → { loading, waitMs } (retryAfter 1…60 s,
	 * 5 without one); null for anything else.
	 */
	function busyRetry(r) {
		if (!r || r.ok !== false || r.code !== 'busy') return null;
		const d = r.detail && typeof r.detail === 'object' ? r.detail : {};
		const s = Number.isFinite(d.retryAfter) ? Math.round(d.retryAfter) : 5;
		return { loading: d.reason === 'loading', waitMs: Math.min(60, Math.max(1, s)) * 1000 };
	}

	/** Whether a live event (mail:changed) brings the body of the open mail (its id, or its conversation's). */
	function bringsBody(changed, message) {
		if (!changed || !message) return false;
		return (!!changed.messageId && changed.messageId === message.id) || (!!changed.threadId && changed.threadId === message.threadId);
	}

	// ── The reader (wide mails, the menu's folds, the conversation, a sender) ──

	/** Below this a wide mail is not made any smaller to fit. */
	const FIT_MIN = 0.25;

	/**
	 * The zoom of the frame's #gc-fit so a wide mail (a newsletter's table of a fixed 600 px) fits without scrolling
	 * sideways: `avail` its width and `content` the width of what it holds (scrollWidth), both measured at zoom 1.
	 * 1 when it fits (1 px of rounding allowed); never below FIT_MIN.
	 */
	function fitZoom(avail, content) {
		const a = Number(avail);
		const c = Number(content);
		if (!(a > 0) || !(c > a + 1)) return 1;
		return Math.max(FIT_MIN, Math.floor((a / c) * 1000) / 1000);
	}

	/** Where "Mails dunkel darstellen" is kept on this PC (on unless switched off). */
	const DARK_KEY = 'gc.mail.darkMails';
	/** The menu's folded folders (folderFoldsJson), kept on this PC. */
	const FOLDER_FOLDS_KEY = 'gc.mail.folderFolds';

	/** The stored "Mails dunkel darstellen" (localStorage value) → on / off; on by default. */
	function darkSetting(raw) {
		return raw !== '0' && raw !== 'false';
	}

	/**
	 * Whether a mail is shown dark (as the Outlook app shows mails while it is dark): the app is dark, "Mails dunkel
	 * darstellen" is on and the mail was not switched to light ("Hell anzeigen").
	 */
	function showDark(appDark, setting, shownLight) {
		return !!appDark && !!setting && !shownLight;
	}

	/** The frame document of a mail (core: doc as sent, docDark with its colours for the dark app). */
	function frameDoc(x, dark) {
		if (!x) return '';
		return dark && typeof x.docDark === 'string' && x.docDark ? x.docDark : (x.doc || '');
	}

	/** Whether the menu shows an account's folders: as folded this session (folds: Map id → bool), else open for the account shown. */
	function foldOpen(folds, accountId, view) {
		if (folds && folds.has(accountId)) return !!folds.get(accountId);
		return !!view && view.kind === 'box' && view.box === accountId;
	}

	/** A tap on an account in the menu: its folders open or close (folds is changed and returned). */
	function toggleFold(folds, accountId, view) {
		folds.set(accountId, !foldOpen(folds, accountId, view));
		return folds;
	}

	/** A conversation (GET threads/<id>) around the open mail: { older, newer }, each oldest first (the newest at the bottom). */
	function conversation(items, currentId) {
		const seen = new Set();
		const list = (Array.isArray(items) ? items : []).filter((m) => m && !seen.has(m.id) && seen.add(m.id))
			.sort((a, b) => (a.date - b.date) || (a.id - b.id));
		const at = list.findIndex((m) => m.id === currentId);
		if (at < 0) return { older: list, newer: [] };
		return { older: list.slice(0, at), newer: list.slice(at + 1) };
	}

	/** The senders of a conversation for its line, each once, at most `max`. */
	function participants(items, t, max = 3) {
		const seen = new Set();
		const out = [];
		for (const m of Array.isArray(items) ? items : []) {
			const key = str(m && m.from && m.from.email).toLowerCase() || str(m && m.from && m.from.name);
			if (!key || seen.has(key)) continue;
			seen.add(key);
			out.push(senderName(m.from, t));
		}
		return out.slice(0, max);
	}

	/** The plugin's `from` matches a part of the address: only the mails of exactly `email` stay. */
	function fromSender(items, email) {
		const e = str(email).trim().toLowerCase();
		return (Array.isArray(items) ? items : []).filter((m) => m && m.from && str(m.from.email).trim().toLowerCase() === e);
	}

	/** The sender in the person's contacts (contacts?q=, a `person` hit with a name), null without one. */
	function contactOf(items, email) {
		const e = str(email).trim().toLowerCase();
		return (Array.isArray(items) ? items : []).find((c) => c && c.source === 'person' && str(c.email).trim().toLowerCase() === e && str(c.name).trim()) || null;
	}

	// ── Calendar (Phase 2) ───────────────────────────────

	const MINUTE = 60 * 1000;
	const WEEKDAYS = ['MO', 'TU', 'WE', 'TH', 'FR', 'SA', 'SU'];
	/** The reminders offered (minutes before; 0: at the start). */
	const REMINDERS = [0, 5, 10, 15, 30, 60, 120, 1440, 2880, 10080];
	const VIEWS = ['day', 'week', 'month', 'list'];

	const dayStart = startOfDay;
	/** `n` days after the day of `ms` (local midnight; DST days are 23 / 25 hours). */
	function addDays(ms, n) { const d = new Date(ms); d.setDate(d.getDate() + n); return d.getTime(); }
	/** ms → 'YYYY-MM-DD' (local). */
	function ymd(ms) { const d = new Date(ms); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; }
	/** 'YYYY-MM-DD' → local midnight (ms), or null. */
	function fromYmd(s) {
		const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(str(s));
		if (!m) return null;
		const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
		return d.getMonth() === Number(m[2]) - 1 ? d.getTime() : null;
	}
	/** 'HH:MM' of ms (local). */
	function hhmm(ms) { const d = new Date(ms); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; }
	/** A date ('YYYY-MM-DD') and a time ('HH:MM') of the form → ms (local), or null. */
	function localMs(date, time) {
		const d = fromYmd(date);
		const m = /^(\d{1,2}):(\d{2})$/.exec(str(time));
		if (d === null || !m || Number(m[1]) > 23 || Number(m[2]) > 59) return null;
		const x = new Date(d);
		x.setHours(Number(m[1]), Number(m[2]), 0, 0);
		return x.getTime();
	}

	/**
	 * The days of a calendar view around `anchor` → { from, to, days: [local midnights] } (the range for GET events,
	 * ≤ 62 days): a day, a week from `weekStart` (Mon 1 / Sun 0; workWeek: Mon–Fri), the month as six weeks, a list of
	 * `listDays` from the anchor on.
	 */
	function viewRange(view, anchor, { weekStart = 1, workWeek = false, listDays = 30 } = {}) {
		const a = dayStart(anchor);
		if (view === 'day') return { from: a, to: addDays(a, 1), days: [a] };
		if (view === 'month') {
			const first = new Date(a);
			first.setDate(1);
			const back = (first.getDay() - weekStart + 7) % 7;
			const start = addDays(first.getTime(), -back);
			const days = Array.from({ length: 42 }, (_, i) => addDays(start, i));
			return { from: start, to: addDays(start, 42), days, month: first.getMonth() };
		}
		if (view === 'list') return { from: a, to: addDays(a, Math.min(60, Math.max(1, listDays))), days: [] };
		const back = (new Date(a).getDay() - weekStart + 7) % 7;
		const start = addDays(a, -back);
		let days = Array.from({ length: 7 }, (_, i) => addDays(start, i));
		if (workWeek) days = days.filter((d) => { const w = new Date(d).getDay(); return w !== 0 && w !== 6; });
		return { from: days[0], to: addDays(days[days.length - 1], 1), days };
	}

	/** ‹ › of a view: a day, a week, a month (the 1st), 30 days of the list. */
	function shiftAnchor(view, anchor, dir) {
		const s = dir < 0 ? -1 : 1;
		if (view === 'day') return addDays(anchor, s);
		if (view === 'month') { const d = new Date(dayStart(anchor)); d.setDate(1); d.setMonth(d.getMonth() + s); return d.getTime(); }
		if (view === 'list') return addDays(anchor, 30 * s);
		return addDays(anchor, 7 * s);
	}

	/** The head of a view: "November 2026", "3.–9. Nov. 2026" (a week), "Di., 3. November 2026" (a day). */
	function rangeTitle(view, range, anchor, locale) {
		const tag = localeTag(locale);
		if (view === 'month') return new Date(dayStart(anchor)).toLocaleDateString(tag, { month: 'long', year: 'numeric' });
		if (view === 'day') return new Date(range.from).toLocaleDateString(tag, { weekday: 'short', day: 'numeric', month: 'long', year: 'numeric' });
		if (view === 'list') return new Date(range.from).toLocaleDateString(tag, { month: 'long', year: 'numeric' });
		const a = new Date(range.from);
		const b = new Date(addDays(range.to, -1));
		const sameMonth = a.getMonth() === b.getMonth() && a.getFullYear() === b.getFullYear();
		const left = sameMonth ? (locale === 'en' ? String(a.getDate()) : `${a.getDate()}.`) : a.toLocaleDateString(tag, { day: 'numeric', month: 'short' });
		return `${left} – ${b.toLocaleDateString(tag, { day: 'numeric', month: 'short', year: 'numeric' })}`;
	}

	/** Does an item (occurrence / overlay item) lie on the day starting at `day`? All-day ones by their dates. */
	function onDay(x, day) {
		if (x.allDay && x.startDate) { const d = ymd(day); return x.startDate <= d && d <= (x.endDate || x.startDate); }
		const end = addDays(day, 1);
		return x.start < end && (x.end > day || (x.end === x.start && x.start >= day));
	}

	/**
	 * The timed items of a day as blocks of the grid: [{ item, top, height (minutes), col, cols }]; overlapping ones
	 * side by side (columns of a cluster), at least 20 minutes high.
	 */
	function layoutDay(items, day) {
		const end = addDays(day, 1);
		const list = (items || []).filter((x) => !x.allDay && x.start < end && x.end > day - (x.end === x.start ? 1 : 0))
			.map((x) => {
				const top = Math.max(0, Math.round((x.start - day) / MINUTE));
				const bottom = Math.min(Math.round((end - day) / MINUTE), Math.round((Math.max(x.end, x.start) - day) / MINUTE));
				return { item: x, top, height: Math.max(20, bottom - top), col: 0, cols: 1 };
			})
			.sort((a, b) => a.top - b.top || b.height - a.height);
		let cluster = [];
		let clusterEnd = -1;
		const close = () => { const n = Math.max(1, ...cluster.map((b) => b.col + 1)); for (const b of cluster) b.cols = n; cluster = []; };
		for (const b of list) {
			if (cluster.length && b.top >= clusterEnd) close();
			const used = new Set(cluster.filter((c) => c.top + c.height > b.top).map((c) => c.col));
			let col = 0;
			while (used.has(col)) col += 1;
			b.col = col;
			cluster.push(b);
			clusterEnd = Math.max(clusterEnd, b.top + b.height);
		}
		if (cluster.length) close();
		return list;
	}

	/** The all-day items of a day (occurrences and overlay items), by title. */
	function allDayOn(items, day) {
		return (items || []).filter((x) => x.allDay && onDay(x, day)).sort((a, b) => str(a.title).localeCompare(str(b.title)));
	}

	/** Everything of a day for the month grid / the list: all-day first, then by start. */
	function dayItems(items, day) {
		return (items || []).filter((x) => onDay(x, day)).sort((a, b) => (b.allDay ? 1 : 0) - (a.allDay ? 1 : 0) || a.start - b.start || str(a.title).localeCompare(str(b.title)));
	}

	/** The list view: [{ day, items }] of the days in [from, to) that have something. */
	function agenda(items, from, to) {
		const out = [];
		for (let d = dayStart(from); d < to; d = addDays(d, 1)) {
			const list = dayItems(items, d);
			if (list.length) out.push({ day: d, items: list });
		}
		return out;
	}

	/** Where the "now" line is on the day's grid (minutes), or null when `now` is not on that day. */
	function nowMinutes(now, day) {
		return now >= day && now < addDays(day, 1) ? Math.round((now - day) / MINUTE) : null;
	}

	/** "10:00–11:00", "ganztägig", "4.–5. Nov." (several days), "3.11. 22:00 – 4.11. 01:00". */
	function eventTimeText(x, locale, t) {
		if (!x) return '';
		const tag = localeTag(locale);
		if (x.allDay) {
			const a = fromYmd(x.startDate);
			const b = fromYmd(x.endDate || x.startDate);
			if (a === null || b === null || a === b) return t('mail.cal.allDay');
			return `${new Date(a).toLocaleDateString(tag, { day: 'numeric', month: 'short' })} – ${new Date(b).toLocaleDateString(tag, { day: 'numeric', month: 'short' })}`;
		}
		if (dayStart(x.start) === dayStart(Math.max(x.start, x.end - 1))) return `${hhmm(x.start)}–${hhmm(x.end)}`;
		const d = (ms) => new Date(ms).toLocaleDateString(tag, { day: 'numeric', month: 'numeric' });
		return `${d(x.start)} ${hhmm(x.start)} – ${d(x.end)} ${hhmm(x.end)}`;
	}

	/** The date of an event for the sheet: "Di., 3. Nov. 2026". */
	function eventDate(x, locale) {
		if (!x) return '';
		const ms = x.allDay && x.startDate ? fromYmd(x.startDate) : x.start;
		return new Date(ms).toLocaleDateString(localeTag(locale), { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' });
	}

	/** Short weekday names of MO … SU in the language. */
	function weekdayName(code, locale, long = false) {
		const i = WEEKDAYS.indexOf(String(code).replace(/^[+-]?\d/, ''));
		if (i < 0) return '';
		return new Date(2024, 0, 1 + i).toLocaleDateString(localeTag(locale), { weekday: long ? 'long' : 'short' }).replace(/\.$/, '');
	}

	/** The recurrence as text: "Wöchentlich am Di, Do", "Alle 2 Wochen", "Monatlich am 4.", "… bis 31.12.2026" / "· 5 Mal". */
	function recurrenceText(rec, t, locale) {
		if (!rec) return '';
		if (!rec.freq) return t('mail.cal.rec.custom');
		const n = rec.interval || 1;
		const days = (rec.byDay || []).map((d) => weekdayName(d, locale)).filter(Boolean).join(', ');
		let s;
		if (rec.freq === 'daily') s = n > 1 ? t('mail.cal.rec.dailyN', { n }) : t('mail.cal.rec.daily');
		else if (rec.freq === 'weekly') {
			if (days) s = n > 1 ? t('mail.cal.rec.weeklyNOn', { n, days }) : t('mail.cal.rec.weeklyOn', { days });
			else s = n > 1 ? t('mail.cal.rec.weeklyN', { n }) : t('mail.cal.rec.weekly');
		} else if (rec.freq === 'monthly') {
			const base = n > 1 ? t('mail.cal.rec.monthlyN', { n }) : t('mail.cal.rec.monthly');
			if (rec.byMonthDay && rec.byMonthDay.length) s = `${base} ${t('mail.cal.rec.onDay', { day: rec.byMonthDay.join(', ') })}`;
			else if (rec.bySetPos && rec.byDay && rec.byDay.length) s = `${base} ${t('mail.cal.rec.onPos', { pos: t(`mail.cal.rec.pos.${rec.bySetPos}`), day: weekdayName(rec.byDay[0], locale, true) })}`;
			else s = base;
		} else s = n > 1 ? t('mail.cal.rec.yearlyN', { n }) : t('mail.cal.rec.yearly');
		if (rec.until) { const u = fromYmd(rec.until); if (u !== null) s += ` ${t('mail.cal.rec.until', { date: new Date(u).toLocaleDateString(localeTag(locale)) })}`; }
		else if (rec.count) s += ` · ${t('mail.cal.rec.count', { count: rec.count })}`;
		return s;
	}

	/** A reminder as text: "Zur Startzeit", "15 Minuten vorher", "2 Stunden vorher", "1 Tag vorher", "1 Woche vorher". */
	function reminderText(min, t) {
		const m = Number(min);
		if (!Number.isFinite(m) || m < 0) return '';
		if (m === 0) return t('mail.cal.rem.atStart');
		if (m % 10080 === 0) return t(m === 10080 ? 'mail.cal.rem.week' : 'mail.cal.rem.weeks', { count: m / 10080 });
		if (m % 1440 === 0) return t(m === 1440 ? 'mail.cal.rem.day' : 'mail.cal.rem.days', { count: m / 1440 });
		if (m % 60 === 0) return t(m === 60 ? 'mail.cal.rem.hour' : 'mail.cal.rem.hours', { count: m / 60 });
		return t('mail.cal.rem.minutes', { count: m });
	}

	/**
	 * The choices of one reminder's menu: REMINDERS and the reminder itself when it is not one of them (an all-day event's
	 * default 360 = 18:00 the day before, a value from another app) — else the menu would show the first choice instead.
	 */
	function reminderChoices(min) {
		const m = Number(min);
		return Number.isInteger(m) && m >= 0 && !REMINDERS.includes(m) ? [...REMINDERS, m].sort((a, b) => a - b) : REMINDERS.slice();
	}

	/** The answers of attendees → { accepted, tentative, declined, needs_action, total }. */
	function responseCounts(attendees) {
		const c = { accepted: 0, tentative: 0, declined: 0, needs_action: 0, total: 0 };
		for (const a of attendees || []) {
			if (a.role === 'resource') continue;
			c.total += 1;
			if (c[a.response] !== undefined) c[a.response] += 1;
		}
		return c;
	}

	/**
	 * The calendar list of the menu: [{ key, label, items: [{ kind: 'calendar' | 'overlay', id, name, color, visible, … }] }]
	 * — "GateControl" (own calendars and subscriptions without an account), per account (its name), "Eingeblendet".
	 */
	function calendarGroups(calendars, overlays, me, t) {
		const groups = [];
		const own = (calendars || []).filter((c) => !c.accountId);
		if (own.length) groups.push({ key: 'gc', label: t('mail.cal.groupOwn'), items: own.map((c) => ({ kind: 'calendar', ...c })) });
		for (const a of (me && me.accounts) || []) {
			const list = (calendars || []).filter((c) => c.accountId === a.id);
			if (list.length) groups.push({ key: `acc:${a.id}`, label: a.name, account: a, items: list.map((c) => ({ kind: 'calendar', ...c })) });
		}
		const orphans = (calendars || []).filter((c) => c.accountId && !((me && me.accounts) || []).some((a) => a.id === c.accountId));
		if (orphans.length) groups.push({ key: 'other', label: t('mail.cal.groupOther'), items: orphans.map((c) => ({ kind: 'calendar', ...c })) });
		if ((overlays || []).length) groups.push({ key: 'overlays', label: t('mail.cal.groupOverlays'), items: overlays.map((o) => ({ kind: 'overlay', ...o })) });
		return groups;
	}

	/** The ids for GET events: the visible calendars and overlays. */
	function visibleIds(calendars, overlays) {
		return [...(calendars || []).filter((c) => c.visible).map((c) => c.id), ...(overlays || []).filter((o) => o.visible).map((o) => o.id)];
	}

	/** The colour of an item: its calendar's / overlay's. */
	function itemColor(x, calendars, overlays) {
		if (x && x.overlayId) { const o = (overlays || []).find((y) => y.id === x.overlayId); return o ? o.color : '#8C96A5'; }
		const c = (calendars || []).find((y) => y.id === (x && x.calendarId));
		return c ? c.color : '#8C96A5';
	}

	/** The monthly position of a day: { pos: 1 … 4 | -1 (the last), day: 'TU' }. */
	function monthPos(ms) {
		const d = new Date(ms);
		const day = WEEKDAYS[(d.getDay() + 6) % 7];
		const last = new Date(d.getFullYear(), d.getMonth() + 1, 0).getDate();
		const pos = d.getDate() + 7 > last ? -1 : Math.ceil(d.getDate() / 7);
		return { pos, day };
	}

	/** The form's recurrence from an event's: { kind: none | daily | weekly | monthlyDay | monthlyPos | yearly | custom, interval, days, end, until, count }. */
	function recurrenceForm(rec, startMs) {
		const base = { kind: 'none', interval: 1, days: [WEEKDAYS[(new Date(startMs).getDay() + 6) % 7]], end: 'never', until: '', count: 10 };
		if (!rec) return base;
		if (!rec.freq || rec.editable === false) return { ...base, kind: 'custom', rrule: rec.rrule || null };
		const out = { ...base, interval: rec.interval || 1 };
		if (rec.until) { out.end = 'until'; out.until = rec.until; } else if (rec.count) { out.end = 'count'; out.count = rec.count; }
		if (rec.freq === 'daily') out.kind = 'daily';
		else if (rec.freq === 'weekly') { out.kind = 'weekly'; if (rec.byDay && rec.byDay.length) out.days = rec.byDay.slice(); }
		else if (rec.freq === 'monthly') out.kind = rec.bySetPos ? 'monthlyPos' : 'monthlyDay';
		else out.kind = 'yearly';
		return out;
	}

	/** The form's recurrence → the body's (`undefined`: unchanged, a custom rule kept; null: none). */
	function recurrenceBody(f, startMs) {
		if (!f || f.kind === 'none') return null;
		if (f.kind === 'custom') return undefined;
		const interval = Math.max(1, Math.min(999, Number(f.interval) || 1));
		const b = { freq: f.kind === 'monthlyDay' || f.kind === 'monthlyPos' ? 'monthly' : f.kind, interval };
		if (f.kind === 'weekly') b.byDay = WEEKDAYS.filter((d) => (f.days || []).includes(d));
		if (f.kind === 'weekly' && !b.byDay.length) b.byDay = [WEEKDAYS[(new Date(startMs).getDay() + 6) % 7]];
		if (f.kind === 'monthlyDay') b.byMonthDay = [new Date(startMs).getDate()];
		if (f.kind === 'monthlyPos') { const p = monthPos(startMs); b.byDay = [p.day]; b.bySetPos = p.pos; }
		if (f.end === 'until' && fromYmd(f.until) !== null) b.until = f.until;
		if (f.end === 'count') b.count = Math.max(1, Math.min(999, Number(f.count) || 1));
		return b;
	}

	/**
	 * The form of the event dialog from an event (or a new one: { start, end, allDay, calendarId }): dates and times
	 * as the inputs want them, the reminders, the attendees, the recurrence.
	 */
	function eventForm(ev, prefs, calendars) {
		const x = ev || {};
		const writable = (calendars || []).filter((c) => c.writable);
		const calId = writable.some((c) => c.id === x.calendarId) ? x.calendarId
			: ((prefs && writable.some((c) => c.id === prefs.defaultCalendarId)) ? prefs.defaultCalendarId : (writable[0] ? writable[0].id : null));
		const start = Number.isFinite(x.start) ? x.start : Date.now();
		const end = Number.isFinite(x.end) && x.end > start ? x.end : start + 60 * MINUTE;
		const allDay = !!x.allDay;
		const sd = allDay && x.startDate ? x.startDate : ymd(start);
		const ed = allDay && x.endDate ? x.endDate : ymd(allDay ? start : end);
		const def = prefs ? (allDay ? prefs.allDayReminder : prefs.defaultReminder) : 15;
		return {
			eventId: x.eventId || null, calendarId: calId, title: str(x.title), allDay,
			startDate: sd, startTime: hhmm(start), endDate: ed, endTime: hhmm(end),
			location: str(x.location), onlineUrl: x.online && x.online.provider !== 'teams' ? x.online.url : '', teams: !!(x.online && x.online.provider === 'teams'),
			reminders: Array.isArray(x.reminders) ? x.reminders.slice(0, 3) : (Number.isFinite(x.reminder) ? [x.reminder] : (def === null || def === undefined ? [] : [def])),
			attendees: (x.attendees && Array.isArray(x.attendees) ? x.attendees : []).filter((a) => !a.self && a.role !== 'resource').map((a) => ({ name: a.name || null, email: a.email })),
			busy: x.busy || 'busy', private: !!x.private, description: str(x.description),
			recurrence: recurrenceForm(x.recurrence || null, start), etag: x.etag || null, occurrence: x.occurrence || null, recurring: !!x.recurring,
		};
	}

	/** The form → the body of POST / PATCH events, or { error: field } (title, start, end). */
	function eventBody(f, { hadOnline = false } = {}) {
		const title = str(f.title).trim();
		if (!title) return { error: 'title' };
		const b = { calendarId: f.calendarId, title, allDay: !!f.allDay };
		let startMs;
		if (f.allDay) {
			const a = fromYmd(f.startDate);
			const z = fromYmd(f.endDate || f.startDate);
			if (a === null) return { error: 'start' };
			if (z === null || z < a) return { error: 'end' };
			b.startDate = f.startDate;
			b.endDate = f.endDate || f.startDate;
			startMs = a;
		} else {
			const s = localMs(f.startDate, f.startTime);
			const e = localMs(f.endDate || f.startDate, f.endTime);
			if (s === null) return { error: 'start' };
			if (e === null || e <= s) return { error: 'end' };
			b.start = s;
			b.end = e;
			startMs = s;
		}
		b.location = str(f.location).trim() || null;
		b.description = str(f.description);
		if (f.teams) b.online = { create: 'teams' };
		else if (str(f.onlineUrl).trim()) b.online = { url: str(f.onlineUrl).trim() };
		else if (hadOnline) b.online = null;
		b.reminders = [...new Set((f.reminders || []).filter((m) => Number.isInteger(m) && m >= 0))].slice(0, 3);
		const rec = recurrenceBody(f.recurrence, startMs);
		if (rec !== undefined) b.recurrence = rec;
		b.attendees = (f.attendees || []).filter((a) => a && isEmail(a.email)).map((a) => (a.name ? { email: a.email, name: a.name } : { email: a.email }));
		b.busy = ['busy', 'free', 'tentative', 'oof'].includes(f.busy) ? f.busy : 'busy';
		b.private = !!f.private;
		return b;
	}

	/** `ms` moved by `days` and `min` minutes of wall clock (local; a DST change in between keeps the clock time). */
	function wallMove(ms, days, min) { const d = new Date(ms); d.setDate(d.getDate() + days); d.setMinutes(d.getMinutes() + min); return d.getTime(); }
	const dayMin = (ms) => { const d = new Date(ms); return d.getHours() * 60 + d.getMinutes(); };

	/**
	 * "Alle Termine der Serie" with changed times (PATCH scope 'series'): the shift the person made at the shown
	 * occurrence `ev` — in days and minutes of wall clock, not in ms — put on the series' own start (`ev.series` of
	 * Mail 1.3.0: DTSTART / DTEND of the master) → { start, end } | { startDate, endDate }. The occurrence's times sent
	 * back unchanged give the series' times unchanged. null without `series` (Mail 1.2.0): then only "Nur dieser Termin"
	 * may change the time. (As L.shiftSeries of the portal, gatecontrol-mail ui/pimlogic.js.)
	 */
	function seriesTimes(body, ev) {
		const s = ev && ev.series;
		if (!s || !body) return null;
		const occDay = ev.allDay && ev.startDate ? ev.startDate : ymd(ev.start);
		const seriesDay = s.allDay && s.startDate ? s.startDate : ymd(s.start);
		const days = (a, b) => Math.round((fromYmd(a) - fromYmd(b)) / 86400000);
		if (body.allDay) {
			if (fromYmd(body.startDate) === null) return null;
			const len = Math.max(0, days(body.endDate || body.startDate, body.startDate));
			const startDate = ymd(addDays(fromYmd(seriesDay), days(body.startDate, occDay)));
			return { startDate, endDate: ymd(addDays(fromYmd(startDate), len)) };
		}
		const d = days(ymd(body.start), occDay);
		const base = s.allDay ? fromYmd(seriesDay) : s.start;
		const min = dayMin(body.start) - (ev.allDay || s.allDay ? 0 : dayMin(ev.start));
		const start = wallMove(base, d, min);
		return { start, end: start + Math.max(0, body.end - body.start) };
	}

	/** What a new event of a tap on the grid gets: half an hour snapped, one hour long. */
	function slotAt(day, minutes) {
		const m = Math.max(0, Math.min(23 * 60 + 30, Math.floor(minutes / 30) * 30));
		const d = new Date(day);
		d.setHours(Math.floor(m / 60), m % 60, 0, 0);
		return { start: d.getTime(), end: d.getTime() + 60 * MINUTE };
	}

	/** The state line of an invitation card: { key, tone } — the texts (mail.cal.inv.*) take { name, response }. */
	function inviteStatus(inv) {
		if (!inv) return null;
		if (inv.state === 'outdated') return { key: 'outdated', tone: 'muted' };
		if (inv.method === 'cancel') return { key: inv.state === 'applied' ? 'cancelledRemoved' : 'cancelled', tone: 'err' };
		if (inv.method === 'reply') {
			const who = (inv.attendees || []).find((a) => a.email && inv.from && a.email.toLowerCase() === str(inv.from.email).toLowerCase());
			return { key: `reply.${who && who.response !== 'needs_action' ? who.response : 'accepted'}`, tone: 'info' };
		}
		if (inv.method === 'counter') return { key: inv.state === 'open' ? 'counter' : 'counterDone', tone: 'info' };
		if (inv.state === 'answered' || inv.state === 'applied' || (inv.myResponse && inv.myResponse !== 'needs_action' && inv.myResponse !== 'organizer')) {
			return { key: `answered.${['accepted', 'tentative', 'declined'].includes(inv.myResponse) ? inv.myResponse : 'accepted'}`, tone: inv.myResponse === 'declined' ? 'err' : 'acc' };
		}
		return { key: 'open', tone: 'info' };
	}

	/** Microsoft accounts that still lack the rights of calendar / contacts ("Neu anmelden"). */
	function consentAccounts(me) {
		return ((me && me.accounts) || []).filter((a) => Array.isArray(a.missingScopes) && a.missingScopes.length);
	}

	// ── Contacts (Phase 2) ───────────────────────────────

	/** The list's sections by letter (the order of the list kept): [{ letter, items }]. */
	function cardSections(items) {
		const out = [];
		for (const c of items || []) {
			const l = c.letter || '#';
			if (!out.length || out[out.length - 1].letter !== l) out.push({ letter: l, items: [] });
			out[out.length - 1].items.push(c);
		}
		return out;
	}

	/** The second line of a contact's row: the company, else the first address, else the number. */
	function cardSub(c) {
		return str(c && (c.company || (c.emails && c.emails[0]) || c.phone)).trim();
	}

	/** "14. März 1981 · wird 46" / "14. März" (without the year). */
	function birthdayText(b, now, locale, t) {
		const m = /^(\d{4}|-)-(\d{2})-(\d{2})$/.exec(str(b));
		if (!m) return '';
		const month = Number(m[2]) - 1;
		const day = Number(m[3]);
		const ref = new Date(2000, month, day);
		const tag = localeTag(locale);
		if (m[1] === '-') return ref.toLocaleDateString(tag, { day: 'numeric', month: 'long' });
		const year = Number(m[1]);
		const text = new Date(year, month, day).toLocaleDateString(tag, { day: 'numeric', month: 'long', year: 'numeric' });
		const n = new Date(now);
		const passed = n.getMonth() > month || (n.getMonth() === month && n.getDate() > day);
		const age = n.getFullYear() - year + (passed ? 1 : 0);
		return age > 0 && age < 150 ? `${text} · ${t('mail.con.turns', { age })}` : text;
	}

	/** A birthday as the form shows it: { day: '14.03.', year: '1981' } (DE) / '14/03' (EN). */
	function birthdayInput(b, locale) {
		const m = /^(\d{4}|-)-(\d{2})-(\d{2})$/.exec(str(b));
		if (!m) return { day: '', year: '' };
		return { day: locale === 'en' ? `${m[3]}/${m[2]}` : `${m[3]}.${m[2]}.`, year: m[1] === '-' ? '' : m[1] };
	}

	/** The form's day ("14.03.", "14.3", "14/03") and year → 'YYYY-MM-DD' | '--MM-DD' | null (empty); undefined when invalid. */
	function birthdayValue(day, year) {
		const d = str(day).trim();
		const y = str(year).trim();
		if (!d && !y) return null;
		const m = /^(\d{1,2})[./-](\d{1,2})\.?$/.exec(d);
		if (!m) return undefined;
		const dd = Number(m[1]);
		const mm = Number(m[2]);
		if (mm < 1 || mm > 12 || dd < 1 || dd > 31) return undefined;
		if (y && !/^\d{4}$/.test(y)) return undefined;
		const yr = y ? Number(y) : 2000;
		const check = new Date(yr, mm - 1, dd);
		if (check.getMonth() !== mm - 1 || (y && (yr < 1850 || yr > new Date().getFullYear()))) return undefined;
		return `${y || '-'}-${pad(mm)}-${pad(dd)}`;
	}

	/** The edit form of a contact (or a draft of "Als Kontakt speichern"). */
	function cardForm(card, locale) {
		const c = card || {};
		const n = c.name || {};
		const b = birthdayInput(c.birthday, locale);
		return {
			id: c.id || null, etag: c.etag || null, addressbookId: c.addressbookId || null,
			given: str(n.given), family: str(n.family), display: str(n.display),
			company: str(c.company), title: str(c.title),
			emails: (c.emails || []).map((e) => ({ value: e.value, type: e.type || 'work' })),
			phones: (c.phones || []).map((p) => ({ value: p.value, type: p.type || 'mobile' })),
			addresses: (c.addresses || []).map((a) => ({ type: a.type || 'home', street: str(a.street), postalCode: str(a.postalCode), city: str(a.city), region: str(a.region), country: str(a.country) })),
			bdayDay: b.day, bdayYear: b.year, note: str(c.note), groups: (c.groups || []).slice(),
		};
	}

	/** The form → the body of POST / PATCH cards, or { error: field }. */
	function cardBody(f) {
		const birthday = birthdayValue(f.bdayDay, f.bdayYear);
		if (birthday === undefined) return { error: 'birthday' };
		const emails = [];
		for (const e of f.emails || []) {
			const v = str(e.value).trim();
			if (!v) continue;
			if (!isEmail(v)) return { error: 'email' };
			emails.push({ value: v, type: e.type || 'other', primary: !emails.length });
		}
		const phones = (f.phones || []).map((p) => ({ value: str(p.value).trim(), type: p.type || 'other' })).filter((p) => p.value);
		if (phones.some((p) => !/\d/.test(p.value))) return { error: 'phone' };
		const given = str(f.given).trim();
		const family = str(f.family).trim();
		const company = str(f.company).trim();
		if (!given && !family && !company && !emails.length && !phones.length) return { error: 'name' };
		const name = { given, family };
		if (!given && !family && str(f.display).trim()) name.display = str(f.display).trim();
		const b = {
			name, emails, phones, company: company || null, title: str(f.title).trim() || null,
			addresses: (f.addresses || []).map((a) => ({ type: a.type || 'home', street: str(a.street).trim(), postalCode: str(a.postalCode).trim(), city: str(a.city).trim(), region: str(a.region).trim(), country: str(a.country).trim() }))
				.filter((a) => a.street || a.postalCode || a.city || a.region || a.country),
			birthday, note: str(f.note), groups: (f.groups || []).slice(),
		};
		if (!f.id && f.addressbookId) b.addressbookId = f.addressbookId;
		if (f.id && f.etag) b.etag = f.etag;
		return b;
	}

	/** An address as lines: "Hansaring 12" / "50670 Köln" / region, country. */
	function addressLines(a) {
		if (!a) return [];
		return [str(a.street), [a.postalCode, a.city].map(str).filter(Boolean).join(' '), [a.region, a.country].map(str).filter(Boolean).join(', ')].filter(Boolean);
	}

	/** A map search of an address (https, OpenStreetMap). */
	function mapUrl(a) {
		const q = addressLines(a).join(', ');
		return q ? `https://www.openstreetmap.org/search?query=${encodeURIComponent(q)}` : null;
	}

	/** The source line of a contact: "Firma · M365", "Meine Kontakte" (+ ", nur lesend"). */
	function bookLabel(book, me) {
		if (!book) return '';
		const acc = book.accountId ? accountOf(me, book.accountId) : null;
		return acc && !str(book.name).includes(acc.name) ? `${acc.name} · ${book.name}` : str(book.name);
	}

	/** The colour dot of a contact's source (its account's colour; own address books none). */
	function bookColor(book, me) {
		if (!book || !book.accountId) return null;
		const acc = accountOf(me, book.accountId);
		return acc ? acc.color : null;
	}

	/** A suggestion while writing → the recipients it gives: one address, or a group's members. */
	function suggestionRecipients(s) {
		if (!s) return [];
		if (s.source === 'group') return (s.members || []).filter((m) => m && isEmail(m.email)).map((m) => ({ name: m.name || null, email: m.email }));
		return isEmail(s.email) ? [{ name: s.name || null, email: s.email }] : [];
	}

	/** The fields a merge can pick among the cards (where they differ) → [{ field, options: [{ id, value }] }]. */
	function mergeChoices(cards) {
		const fields = ['name', 'company', 'title', 'birthday'];
		const out = [];
		for (const field of fields) {
			const seen = new Map();
			for (const c of cards || []) {
				const v = field === 'name' ? str(c.name && (c.name.display || [c.name.given, c.name.family].filter(Boolean).join(' '))) : str(c[field]);
				if (v && !seen.has(v)) seen.set(v, c.id);
			}
			if (seen.size > 1) out.push({ field, options: [...seen.entries()].map(([value, id]) => ({ id, value })) });
		}
		return out;
	}


	// ── Contacts with the GC contact as the master (Mail 1.4.0) ──

	/** The server knows the GC contact as the master (Mail 1.4.0): its summaries carry `favorite` (null before). */
	function hasMaster(items) {
		return (items || []).some((c) => c && typeof c.favorite === 'boolean');
	}

	/** A source of a contact: "Firma · M365 (max@firma.de)" — its address book and, with an account, the account's address. */
	function sourceLabel(src, books, me) {
		if (!src) return '';
		const book = (books || []).find((b) => b.id === src.addressbookId) || null;
		const name = book ? bookLabel(book, me) : str(src.addressbook);
		const acc = str(src.account);
		return acc && !name.includes(acc) ? `${name} (${acc})` : name;
	}

	/** The colour dots of a row: one per source (the account's colour; own address books none), without doubles. */
	function sourceColors(c, books, me) {
		const list = c && Array.isArray(c.sources) && c.sources.length ? c.sources : [{ addressbookId: c && c.addressbookId }];
		const out = [];
		for (const s of list) {
			const book = (books || []).find((b) => b.id === s.addressbookId) || null;
			const color = bookColor(book, me);
			if (color && !out.some((x) => x.color === color)) out.push({ color, label: book ? bookLabel(book, me) : '' });
		}
		return out;
	}

	/** A value of a conflict as text: a number, an address on one line, a birthday, a text. */
	function conflictValueText(field, v, locale) {
		if (v === null || v === undefined) return '';
		if (field === 'phones') return str(v.value);
		if (field === 'addresses') return addressLines(v).join(', ');
		if (field === 'birthday') {
			const m = /^(\d{4}|-)-(\d{2})-(\d{2})$/.exec(str(v));
			if (!m) return '';
			const d = new Date(m[1] === '-' ? 2000 : Number(m[1]), Number(m[2]) - 1, Number(m[3]));
			return d.toLocaleDateString(localeTag(locale), m[1] === '-' ? { day: 'numeric', month: 'long' } : { day: 'numeric', month: 'long', year: 'numeric' });
		}
		return str(v);
	}

	/**
	 * The band of a conflict: "Outlook (ma.backes@outlook.com) hat eine andere Mobilnummer: 0171 … (bisher 0170 …)" →
	 * { text, canAdd } — "Zusätzlich" only where a second value fits (numbers, addresses).
	 */
	function conflictText(c, books, me, locale, t) {
		if (!c) return { text: '', canAdd: false };
		const PHONE = ['mobile', 'home', 'work', 'fax'];
		const ADDR = ['home', 'work'];
		const field = c.field === 'phones' ? `phone_${PHONE.includes(c.type) ? c.type : 'other'}` : (c.field === 'addresses' ? `address_${ADDR.includes(c.type) ? c.type : 'other'}` : c.field);
		const what = t(`mail.con.cf.${field}`);
		const value = conflictValueText(c.field, c.value, locale);
		const before = conflictValueText(c.field, c.replaces, locale);
		const source = sourceLabel(c.source, books, me) || t('mail.con.cf.other');
		const text = before ? t('mail.con.cf.textWas', { source, what, value, before }) : t('mail.con.cf.text', { source, what, value });
		return { text, canAdd: (c.field === 'phones' || c.field === 'addresses') && !!c.replaces };
	}

	/** The accounts a change did not reach (writeBack ok: false) → their labels, without doubles. */
	function writeBackFailed(writeBack, books, me) {
		const out = [];
		for (const w of writeBack || []) {
			if (!w || w.ok) continue;
			const book = (books || []).find((b) => b.id === w.addressbookId) || null;
			const label = book ? bookLabel(book, me) : '';
			if (label && !out.includes(label)) out.push(label);
		}
		return out;
	}

	/** The accounts a change went to as well (writeBack ok) → their labels. */
	function writeBackDone(writeBack, books, me) {
		const out = [];
		for (const w of writeBack || []) {
			if (!w || !w.ok) continue;
			const book = (books || []).find((b) => b.id === w.addressbookId) || null;
			const label = book ? bookLabel(book, me) : '';
			if (label && !out.includes(label)) out.push(label);
		}
		return out;
	}

	/** The fields of a card in the duplicates view: numbers, addresses, the first postal address. */
	function dupFields(card) {
		const c = card || {};
		return {
			phones: (c.phones || []).map((p) => str(p.value)).filter(Boolean),
			emails: (c.emails || []).map((e) => str(e.value)).filter(Boolean),
			address: c.addresses && c.addresses[0] ? addressLines(c.addresses[0]).join(', ') : '',
		};
	}

	/** The name of a card / preview as shown ("Schatzimausi 💞" as written). */
	function cardName(c) {
		const n = (c && c.name) || {};
		return str(n.display).trim() || [n.given, n.family].map(str).filter(Boolean).join(' ') || str(c && c.emails && c.emails[0] && c.emails[0].value);
	}

	/** The duplicates of 1.4.0 split: the uncertain ones to confirm (with their details), and whether the view is the new one. */
	function dupCases(items) {
		const list = items || [];
		const fresh = list.some((d) => d && typeof d.certain === 'boolean');
		return { fresh, open: fresh ? list.filter((d) => d.certain === false || d.certain === null) : list };
	}

	/** "Automatisch zusammengeführt": the protocol's automatic merges not undone, newest first. */
	function autoMerges(items) {
		return (items || []).filter((m) => m && (m.mode === 'auto' || m.mode === 'migrated') && !m.undoneAt);
	}

	/** A merge of the protocol as a line: "Sabine Keller · Meine Kontakte + Firma · M365". */
	function mergeLine(m) {
		if (!m) return '';
		const names = [...new Set((m.cards || []).map((c) => str(c.name)).filter(Boolean))];
		const books = [...new Set((m.cards || []).map((c) => str(c.addressbook)).filter(Boolean))];
		return [names.join(' / '), books.join(' + ')].filter(Boolean).join(' · ');
	}

	// ── The start page: pinned favourites and the calendar widget ──

	const PINS_MAX = 12;

	/** The pins of the start page as kept on this PC → { calendar: bool, contacts: [ids ≤ 12] }. */
	function homePins(raw) {
		const o = raw && typeof raw === 'object' ? raw : {};
		const ids = Array.isArray(o.contacts) ? o.contacts.filter((x) => Number.isSafeInteger(x) && x > 0) : [];
		return { calendar: o.calendar === true, contacts: [...new Set(ids)].slice(0, PINS_MAX) };
	}

	/** A favourite pinned or loosened → the new pins (a copy; at most 12). */
	function pinContact(pins, id, on) {
		const p = homePins(pins);
		const rest = p.contacts.filter((x) => x !== id);
		return { ...p, contacts: on && Number.isSafeInteger(id) && id > 0 ? rest.concat(id).slice(0, PINS_MAX) : rest };
	}

	/** The tiles: the favourites pinned, in the favourites' order → [{ id, name, initials, phone, email, photo, photoEtag }]. */
	function favoriteTiles(favorites, pins) {
		const p = homePins(pins);
		return (favorites || []).filter((f) => f && p.contacts.includes(f.id)).map((f) => ({
			id: f.id, name: str(f.name), initials: initials({ name: f.name, email: f.email }), phone: f.phone ? str(f.phone.value) || null : null,
			email: f.email || null, photo: !!f.photo, photoEtag: f.photoEtag || null,
		}));
	}

	/** The widget's days: [{ day, label ('Heute' / 'Morgen' / a date), items: [{ …item, time }] }] in the server's order. */
	function upcomingDays(res, now, locale, t) {
		const today = (res && res.today) || ymd(now);
		const tomorrow = ymd(addDays(fromYmd(today) || now, 1));
		const out = [];
		for (const x of (res && res.items) || []) {
			const day = x.day || today;
			if (!out.length || out[out.length - 1].day !== day) {
				const label = day === today ? t('home.cal.today') : (day === tomorrow ? t('home.cal.tomorrow') : new Date(fromYmd(day) || now).toLocaleDateString(localeTag(locale), { weekday: 'long', day: 'numeric', month: 'short' }));
				out.push({ day, label, items: [] });
			}
			const time = x.allDay ? t('mail.cal.allDay') : (x.start < now && x.end > now ? t('home.cal.now') : hhmm(x.start));
			out[out.length - 1].items.push({ ...x, time });
		}
		return out;
	}

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
		folderAncestors,
		folderOpen,
		toggleFolder,
		revealFolder,
		folderRows,
		folderFoldsOf,
		folderFoldsJson,
		FOLDER_MAX_INDENT,
		FOLDER_FOLDS_KEY,
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
		accountMark,
		accountSub,
		BUSY_RETRIES,
		busyRetry,
		bringsBody,
		FIT_MIN,
		fitZoom,
		DARK_KEY,
		darkSetting,
		showDark,
		frameDoc,
		foldOpen,
		toggleFold,
		conversation,
		participants,
		fromSender,
		contactOf,
		errorText,
		// Phase 2: calendar
		WEEKDAYS,
		REMINDERS,
		VIEWS,
		addDays,
		ymd,
		fromYmd,
		hhmm,
		localMs,
		viewRange,
		shiftAnchor,
		rangeTitle,
		onDay,
		layoutDay,
		allDayOn,
		dayItems,
		agenda,
		nowMinutes,
		eventTimeText,
		eventDate,
		weekdayName,
		recurrenceText,
		reminderText,
		reminderChoices,
		responseCounts,
		calendarGroups,
		visibleIds,
		itemColor,
		monthPos,
		recurrenceForm,
		recurrenceBody,
		eventForm,
		eventBody,
		slotAt,
		seriesTimes,
		inviteStatus,
		consentAccounts,
		// Phase 2: contacts
		cardSections,
		cardSub,
		birthdayText,
		birthdayInput,
		birthdayValue,
		cardForm,
		cardBody,
		addressLines,
		mapUrl,
		bookLabel,
		bookColor,
		suggestionRecipients,
		mergeChoices,
		// Mail 1.4.0: the GC contact as the master, favourites, the start page
		hasMaster,
		sourceLabel,
		sourceColors,
		conflictValueText,
		conflictText,
		writeBackFailed,
		writeBackDone,
		dupFields,
		cardName,
		dupCases,
		autoMerges,
		mergeLine,
		homePins,
		pinContact,
		favoriteTiles,
		upcomingDays,
	};
});
