/**
 * GateControl -- Mail: several mails at once (renderer, no DOM access)
 *
 * Mail 1.13 "Mehrfachauswahl + Wischaktionen" on the page "Mail", as a mail program on the desktop does it: a click
 * opens a mail, Strg+click ticks mails (the open one with them), Umschalt+click a range, Strg+A every mail loaded
 * ("Alle N auswählen" asks the server for the whole folder, Mail 1.13 `bulkAll`), Esc ends the selection. The bar of
 * the selection (Archivieren, Löschen, Verschieben, Kopieren, Gelesen / Ungelesen, Markieren, Spam, Nach Sonstige /
 * Relevant, Auswahl aufheben), what the selection is (one account or several, mails in the trash, unread ones),
 * the questions before deleting, the folder picker (search, "Zuletzt"), dragging onto a folder of the menu, the
 * note after an action ("12 Mails nach „2026“ verschoben · Rückgängig") and the quick actions of the settings (the
 * swipe sides of the app: seven actions with `swipeV2`, else the old four).
 *
 * Pure helpers for mail-view.js, loaded as a plain script (window.GCMailBulk) and required by the node tests
 * (test/mail-bulk-state.test.js). Inputs are what window.gatecontrol.mail returns (core MailService); `t` is the
 * i18n function (keys mail.bulk.*).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCMailBulk = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const SWIPES_OLD = ['archive', 'delete', 'read', 'none'];
	const SWIPES_V2 = ['archive', 'delete', 'read', 'flag', 'move', 'junk', 'none'];
	const RECENT_KEY = 'gc.mail.recentFolders';
	const RECENT_MAX = 5;
	const DRAG_TYPE = 'application/x-gc-mail-ids';
	const UNDO_SHOW_MS = 8000;     // the note with "Rückgängig" (the server keeps the token 2 minutes)
	const MAX = 2000;              // GET messages/ids and one selection

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const isId = (v) => Number.isSafeInteger(v) && v > 0;
	const has = (me, f) => !!(me && Array.isArray(me.features) && me.features.includes(f));

	function plural(t, key, n, params) {
		const count = Number(n) || 0;
		return t(`${key}.${count === 1 ? 'one' : 'other'}`, { ...(params || {}), count });
	}

	// ── the selection ────────────────────────────────────

	/**
	 * A click on a row (ids: the rows in the order shown) → { ids, anchor } of the selection, or null for a plain click
	 * (it opens the mail and ends the selection). Strg: this one in or out — the mail open (`current`) is ticked too
	 * when the selection starts; Umschalt: the range from the anchor (the open mail when there is none; Strg+Umschalt:
	 * the range added).
	 */
	function click(sel, ids, id, { ctrl = false, shift = false, current = null } = {}) {
		const list = Array.isArray(ids) ? ids : [];
		const cur = sel && sel.ids instanceof Set ? sel.ids : new Set();
		const anchor = sel && sel.anchor !== null && sel.anchor !== undefined && list.includes(sel.anchor) ? sel.anchor : (list.includes(current) ? current : null);
		if (shift && anchor !== null && list.includes(id)) {
			const a = list.indexOf(anchor);
			const b = list.indexOf(id);
			const out = ctrl ? new Set(cur) : new Set();
			for (const x of list.slice(Math.min(a, b), Math.max(a, b) + 1)) out.add(x);
			return { ids: out, anchor, all: null };
		}
		if (ctrl || shift) {
			const out = new Set(cur);
			if (!out.size && current !== null && current !== id && list.includes(current)) out.add(current);
			if (out.has(id)) out.delete(id); else out.add(id);
			return { ids: out, anchor: id, all: null };
		}
		return null;
	}

	/** The tick of a row (its check box): in or out. */
	function toggle(sel, id, { current = null, ids = [] } = {}) {
		return click(sel, ids, id, { ctrl: true, current });
	}

	/** Strg+A: every mail loaded. */
	function selectLoaded(items) {
		const ids = (Array.isArray(items) ? items : []).map((m) => m && m.id).filter(isId);
		return { ids: new Set(ids), anchor: ids[0] || null, all: null };
	}

	/** "Alle N auswählen": the ids of GET messages/ids (the loaded ones first in their order). */
	function selectAll(r, items) {
		const ids = (r && Array.isArray(r.ids) ? r.ids : []).filter(isId).slice(0, MAX);
		const loaded = (Array.isArray(items) ? items : []).map((m) => m.id).filter((id) => ids.includes(id));
		const set = new Set([...loaded, ...ids]);
		return { ids: set, anchor: loaded[0] || ids[0] || null, all: { total: Math.max(Number(r && r.total) || 0, set.size), truncated: !!(r && r.truncated) } };
	}

	/** After a reload: the mails still in the list stay ticked; a selection from "Alle" keeps its ids. */
	function prune(sel, items) {
		if (!sel || !(sel.ids instanceof Set)) return null;
		if (sel.all) return sel;
		const keep = new Set((Array.isArray(items) ? items : []).map((m) => m.id));
		const ids = new Set([...sel.ids].filter((x) => keep.has(x)));
		return ids.size ? { ids, anchor: keep.has(sel.anchor) ? sel.anchor : null, all: null } : null;
	}

	/** Mails gone (moved, deleted) leave the selection; null when none is left. */
	function without(sel, gone) {
		if (!sel || !(sel.ids instanceof Set)) return null;
		const g = new Set(gone || []);
		const ids = new Set([...sel.ids].filter((x) => !g.has(x)));
		return ids.size ? { ids, anchor: g.has(sel.anchor) ? null : sel.anchor, all: sel.all && ids.size === sel.ids.size ? sel.all : null } : null;
	}

	/**
	 * What the selection is: { count, items (the loaded ones), unknown (ids not loaded), accounts, accountId (one
	 * account, else null), mixed, inTrash (any in a trash folder), allTrash, anyUnread, anyUnflagged }. Mails not
	 * loaded ("Alle") belong to the list's account (view.box), else to any account of the person.
	 */
	function facts(ids, items, { view = null, folders = null, me = null } = {}) {
		const list = [...(ids instanceof Set ? ids : new Set(ids || []))];
		const byId = new Map((Array.isArray(items) ? items : []).map((m) => [m.id, m]));
		const loaded = list.map((id) => byId.get(id)).filter(Boolean);
		const unknown = list.length - loaded.length;
		const accounts = new Set(loaded.map((m) => m.accountId).filter(isId));
		const v = view || {};
		if (unknown) {
			if (isId(v.box)) accounts.add(v.box);
			else for (const a of (me && me.accounts) || []) accounts.add(a.id);
		}
		const trashIds = new Set();
		for (const acc of (folders && folders.accounts) || []) for (const f of acc.folders || []) if (f.role === 'trash') trashIds.add(f.id);
		const viewTrash = isId(v.folderId) && trashIds.has(v.folderId);
		const inTrash = (m) => trashIds.has(m.folderId) || (viewTrash && !isId(m.folderId));
		const trashed = loaded.filter(inTrash).length + (viewTrash ? unknown : 0);
		const acc = [...accounts];
		return {
			count: list.length,
			ids: list,
			items: loaded,
			unknown,
			accounts: acc,
			accountId: acc.length === 1 ? acc[0] : null,
			mixed: acc.length > 1,
			inTrash: trashed > 0,
			allTrash: list.length > 0 && trashed === list.length,
			// mails not loaded: "Gelesen" / "Markieren" first (they may be unread)
			anyUnread: loaded.some((m) => m.unread) || unknown > 0,
			anyUnflagged: loaded.some((m) => !m.flagged) || unknown > 0,
		};
	}

	/**
	 * The buttons of the selection's bar → [{ id, icon, label, disabled, why }]: Archivieren, Löschen, Verschieben,
	 * Kopieren (Mail 1.13 `copy`), Gelesen / Ungelesen, Markieren / Markierung entfernen, Spam, Nach Sonstige /
	 * Nach Relevant (inboxes only). Moving and copying stay in one account.
	 */
	function barActions(f, { me = null, inbox = false, tab = 'relevant' } = {}) {
		const x = f || {};
		const why = x.mixed ? 'mail.bulk.oneAccount' : null;
		const out = [
			{ id: 'archive', icon: 'archive', label: 'mail.bulk.archive' },
			{ id: 'delete', icon: 'trash', label: x.allTrash ? 'mail.bulk.purge' : 'mail.bulk.delete' },
			{ id: 'move', icon: 'move', label: 'mail.bulk.move', disabled: !!why, why },
		];
		if (has(me, 'copy')) out.push({ id: 'copy', icon: 'copy', label: 'mail.bulk.copy', disabled: !!why, why });
		out.push(
			x.anyUnread ? { id: 'read', icon: 'mailOpen', label: 'mail.bulk.read' } : { id: 'unread', icon: 'mail', label: 'mail.bulk.unread' },
			x.anyUnflagged ? { id: 'flag', icon: 'flag', label: 'mail.bulk.flag' } : { id: 'unflag', icon: 'flag', label: 'mail.bulk.unflag' },
			{ id: 'junk', icon: 'junk', label: 'mail.bulk.junk' },
		);
		if (inbox) out.push(tab === 'other' ? { id: 'toRelevant', icon: 'tab', label: 'mail.act.toRelevant' } : { id: 'toOther', icon: 'tab', label: 'mail.act.toOther' });
		return out.map((a) => ({ disabled: false, why: null, ...a }));
	}

	/** A bar's button (or a menu entry) → the call: { flags } | { act } | { act: 'tab', tab } | { pick: 'move' | 'copy' }. */
	function barCall(id) {
		switch (id) {
			case 'read': return { flags: { unread: false } };
			case 'unread': return { flags: { unread: true } };
			case 'flag': return { flags: { flagged: true } };
			case 'unflag': return { flags: { flagged: false } };
			case 'archive': case 'delete': case 'junk': return { act: id };
			case 'move': case 'copy': return { pick: id };
			case 'toOther': return { act: 'tab', tab: 'other' };
			case 'toRelevant': return { act: 'tab', tab: 'relevant' };
			default: return null;
		}
	}

	/**
	 * Ask before deleting? 'purge' when a mail is in the trash already (always: it is gone for good), 'delete' with
	 * the setting "Vor dem Löschen fragen" (Mail 1.13 `confirmDelete`), else null (deleted at once, "Rückgängig").
	 */
	function confirmKind(f, settings) {
		if (f && f.inTrash) return 'purge';
		return settings && settings.confirmDelete === true ? 'delete' : null;
	}

	/** Whole conversations with the actions on the list's rows: the conversation view is on (the core sends it with `threadScope` only). */
	function threadsFor(view, me) {
		return !!(view && view.kind === 'box' && me && me.settings && me.settings.threads);
	}

	/** A key in the list → 'all' | 'clear' | 'delete' | 'extendUp' | 'extendDown' | null. */
	function keyAction(e) {
		const k = e || {};
		const mod = !!(k.ctrlKey || k.metaKey);
		if (mod && !k.altKey && !k.shiftKey && str(k.key).toLowerCase() === 'a') return 'all';
		if (k.altKey || mod) return null;
		if (k.key === 'Escape') return 'clear';
		if (k.key === 'Delete') return 'delete';
		if (k.shiftKey && k.key === 'ArrowUp') return 'extendUp';
		if (k.shiftKey && k.key === 'ArrowDown') return 'extendDown';
		return null;
	}

	/** Umschalt+↑/↓: the range from the anchor to the next row up or down (`focus`: the row the range ends on). */
	function extend(sel, ids, dir, { current = null, focus = null } = {}) {
		const list = Array.isArray(ids) ? ids : [];
		if (!list.length) return null;
		const anchor = sel && list.includes(sel.anchor) ? sel.anchor : (list.includes(current) ? current : list[0]);
		const from = list.includes(focus) ? focus : anchor;
		const to = list[Math.max(0, Math.min(list.length - 1, list.indexOf(from) + (dir === 'up' ? -1 : 1)))];
		const a = list.indexOf(anchor);
		const b = list.indexOf(to);
		return { ids: new Set(list.slice(Math.min(a, b), Math.max(a, b) + 1)), anchor, all: null, focus: to };
	}

	// ── after an action ──────────────────────────────────

	/**
	 * The note after an action → { text, undo }: "12 Mails nach „2026“ verschoben" etc.; `undo` when it can be taken
	 * back — by the server's tokens (move, copy, archive, delete, junk; Mail 1.13 `undo`) or by the app itself
	 * (read / unread, flag, Relevant / Sonstige: the opposite call).
	 */
	function doneView(kind, { count = 0, folder = '', purged = 0, undo = null, back = null, t }) {
		const n = Number(count) || 0;
		const keys = {
			move: 'mail.bulk.done.move', copy: 'mail.bulk.done.copy', archive: 'mail.bulk.done.archive', delete: 'mail.bulk.done.delete', junk: 'mail.bulk.done.junk',
			read: 'mail.bulk.done.read', unread: 'mail.bulk.done.unread', flag: 'mail.bulk.done.flag', unflag: 'mail.bulk.done.unflag',
			toOther: 'mail.bulk.done.toOther', toRelevant: 'mail.bulk.done.toRelevant',
		};
		const p = Number(purged) || 0;
		if (kind === 'delete' && p && p >= n) return { text: plural(t, 'mail.bulk.done.purged', p), undo: false };
		const parts = [plural(t, keys[kind] || 'mail.bulk.done.archive', n - (kind === 'delete' ? p : 0), { folder: str(folder) })];
		if (kind === 'delete' && p) parts.push(plural(t, 'mail.bulk.done.purged', p));
		const tokens = !!(undo && Array.isArray(undo.tokens) && undo.tokens.length);
		return { text: parts.join(' · '), undo: tokens || !!(back && back.length) };
	}

	/**
	 * The opposite calls of read / unread / flag for the mails as they were (`before`: the loaded summaries) →
	 * [{ ids, flags }], or null when a mail was not loaded (its old state is unknown).
	 */
	function flagsBack(before, flags, ids) {
		const list = Array.isArray(before) ? before : [];
		const want = Array.isArray(ids) ? ids : list.map((m) => m.id);
		if (!flags || list.length < want.length) return null;
		const key = typeof flags.unread === 'boolean' ? 'unread' : 'flagged';
		const groups = new Map();
		for (const m of list) {
			const was = !!m[key];
			if (was === flags[key]) continue;
			if (!groups.has(was)) groups.set(was, []);
			groups.get(was).push(m.id);
		}
		return [...groups.entries()].map(([was, g]) => ({ ids: g, flags: { [key]: was } }));
	}

	/** Relevant / Sonstige back: [{ ids, tab }] by the tab each mail had. */
	function tabBack(before, tab) {
		const groups = new Map();
		for (const m of Array.isArray(before) ? before : []) {
			const was = m.tab === 'other' ? 'other' : 'relevant';
			if (was === tab) continue;
			if (!groups.has(was)) groups.set(was, []);
			groups.get(was).push(m.id);
		}
		return [...groups.entries()].map(([was, g]) => ({ ids: g, tab: was }));
	}

	// ── the folder picker ────────────────────────────────

	/** The folders used last (kept on this PC) → [{ id, accountId }]. */
	function parseRecent(raw) {
		let v = null;
		try { v = JSON.parse(str(raw) || '[]'); } catch { v = []; }
		return (Array.isArray(v) ? v : []).filter((x) => x && isId(x.id) && isId(x.accountId)).slice(0, RECENT_MAX * 4).map((x) => ({ id: x.id, accountId: x.accountId }));
	}

	/** The list with this folder first (≤ RECENT_MAX per account) → JSON. */
	function pushRecent(list, id, accountId) {
		const rest = (Array.isArray(list) ? list : []).filter((x) => x.id !== id);
		const out = [{ id, accountId }, ...rest];
		const per = new Map();
		const kept = out.filter((x) => { const n = (per.get(x.accountId) || 0) + 1; per.set(x.accountId, n); return n <= RECENT_MAX; });
		return JSON.stringify(kept.slice(0, RECENT_MAX * 4));
	}

	/** The account's folders used last that still exist (not `here` when moving). */
	function recentFolders(recent, folders, accountId, { here = null, mode = 'move' } = {}) {
		const acc = ((folders && folders.accounts) || []).find((a) => a.accountId === accountId);
		const byId = new Map(((acc && acc.folders) || []).map((f) => [f.id, f]));
		return (recent || []).filter((x) => x.accountId === accountId && byId.has(x.id) && !(mode === 'move' && x.id === here)).map((x) => byId.get(x.id)).slice(0, RECENT_MAX);
	}

	/** The folders of the search in the picker: name or path contains the words (case ignored). */
	function searchFolders(list, q) {
		const words = str(q).toLowerCase().split(/\s+/).filter(Boolean);
		if (!words.length) return [];
		return (Array.isArray(list) ? list : []).filter((f) => {
			const hay = `${str(f.name)} ${str(f.path)}`.toLowerCase();
			return words.every((w) => hay.includes(w));
		});
	}

	/** The picker's main button: "Nach „2026“ verschieben" / "… kopieren", "Ordner wählen" without one. */
	function pickGo(mode, folderName, t) {
		if (!folderName) return t('mail.bulk.pick.choose');
		return t(mode === 'copy' ? 'mail.bulk.pick.goCopy' : 'mail.bulk.pick.goMove', { folder: str(folderName) });
	}

	// ── dragging onto a folder of the menu ───────────────

	/**
	 * May the dragged mails go into this folder? One account only (the folder's), not where they all are already
	 * (a move; a copy may: a duplicate as IMAP COPY does), copying only with Mail 1.13 `copy`.
	 */
	function canDrop(drag, folder, { copy = false, me = null } = {}) {
		if (!drag || !Array.isArray(drag.ids) || !drag.ids.length || !folder || !isId(folder.id)) return false;
		if (drag.mixed || !isId(drag.accountId) || drag.accountId !== folder.accountId) return false;
		if (copy) return has(me, 'copy');
		return !(Array.isArray(drag.folderIds) && drag.folderIds.length && drag.folderIds.every((x) => x === folder.id));
	}

	/** "3 Mails hierher verschieben" / "… kopieren" */
	function dropText(count, copy, t) {
		return plural(t, copy ? 'mail.bulk.drop.copy' : 'mail.bulk.drop.move', count);
	}

	// ── the quick actions (the swipe sides of the app) ───

	/** The actions to choose: all seven with Mail 1.13 `swipeV2`, else the old four. */
	function swipeChoices(me) {
		return has(me, 'swipeV2') ? SWIPES_V2.slice() : SWIPES_OLD.slice();
	}

	return {
		SWIPES_OLD,
		SWIPES_V2,
		RECENT_KEY,
		RECENT_MAX,
		DRAG_TYPE,
		UNDO_SHOW_MS,
		MAX,
		plural,
		click,
		toggle,
		selectLoaded,
		selectAll,
		prune,
		without,
		facts,
		barActions,
		barCall,
		confirmKind,
		threadsFor,
		keyAction,
		extend,
		doneView,
		flagsBack,
		tabBack,
		parseRecent,
		pushRecent,
		recentFolders,
		searchFolders,
		pickGo,
		canDrop,
		dropText,
		swipeChoices,
	};
});
