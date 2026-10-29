/**
 * GateControl -- Drive: the selection of many files and folders (renderer, no DOM access)
 *
 * Drive 1.12 on the page "Drive" (and in "Fotos"): the selection like in the Explorer — a click on a row selects it,
 * Strg+click one more, Umschalt+click a range, Strg+A all, Esc none; the check box of each row and the tri-state one of
 * the head —, what the selection can do (Herunterladen als ZIP, Verschieben / Kopieren nach …, Link teilen, In den
 * Papierkorb, Umbenennen — with the reason when not: read only, a vault, "Braucht Drive 1.12"), the shortcuts
 * (Strg+X / C / V inside Drive, Entf, F2), dragging onto a folder ("N Elemente hierher verschieben", Strg: kopieren),
 * the texts of "Ziel wählen", of the question for names the target has already, of a job's progress and of the note
 * after it ("3 Elemente nach „Rechnungen“ verschoben · Rückgängig"), the folders used last as targets and "neu hier".
 * Pure helpers for drive-view.js, drive-bulk-view.js and drive-photos-view.js, loaded as a plain script
 * (window.GCDriveBulkState) and required by the node tests (test/drive-bulk-state.test.js).
 *
 * Inputs are what window.gatecontrol.drive returns (core DriveService, Drive 1.12 'bulk' / 'zip' / 'multiLink'); `t` is
 * the i18n function (keys drive.bulk.*).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDriveBulkState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const RECENT_KEY = 'gc.drive.recentTargets';
	const RECENT_MAX = 5;
	const DRAG_TYPE = 'application/x-gc-drive-nodes';
	const NEW_HERE_MS = 2 * 60 * 1000;
	const FILES_MAX = 20;          // ZIP / one link for several without 'zipMixed': at most 20 files (or one folder for a ZIP)
	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const isId = (v) => Number.isSafeInteger(v) && v > 0;
	const has = (me, f) => !!(me && Array.isArray(me.features) && me.features.includes(f));
	const localeTag = (l) => (l === 'en' ? 'en-GB' : 'de-DE');

	function plural(t, key, n, params) {
		const count = Number(n) || 0;
		return t(`${key}.${count === 1 ? 'one' : 'other'}`, { ...(params || {}), count });
	}

	function bytes(n, locale) {
		const v = Number(n);
		if (!Number.isFinite(v) || v < 0) return '';
		if (v < 1024) return `${v} B`;
		const units = ['KB', 'MB', 'GB', 'TB'];
		let x = v / 1024;
		let i = 0;
		while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
		const digits = x >= 100 || i === 0 ? 0 : 1;
		return `${x.toLocaleString(localeTag(locale), { minimumFractionDigits: digits, maximumFractionDigits: digits })} ${units[i]}`;
	}

	// ── the selection ────────────────────────────────────

	/**
	 * A click on a row (ids: the rows in the order shown) → { sel, anchor }. Plain: only this one; Strg: this one in or
	 * out; Umschalt: the range from the anchor (Strg+Umschalt: the range added).
	 */
	function click(sel, ids, id, { ctrl = false, shift = false, anchor = null } = {}) {
		const list = Array.isArray(ids) ? ids : [];
		const cur = sel instanceof Set ? sel : new Set();
		if (shift && anchor !== null && list.includes(anchor) && list.includes(id)) {
			const a = list.indexOf(anchor);
			const b = list.indexOf(id);
			const range = list.slice(Math.min(a, b), Math.max(a, b) + 1);
			const out = ctrl ? new Set(cur) : new Set();
			for (const x of range) out.add(x);
			return { sel: out, anchor };
		}
		if (ctrl) return { sel: toggle(cur, id), anchor: id };
		return { sel: new Set([id]), anchor: id };
	}

	/** The check box of a row: in / out (Umschalt with an anchor: the range, like a click). */
	function toggle(sel, id) {
		const out = new Set(sel instanceof Set ? sel : []);
		if (out.has(id)) out.delete(id); else out.add(id);
		return out;
	}

	/** The head's check box → 'none' | 'some' | 'all' of the rows shown. */
	function headState(sel, ids) {
		const list = Array.isArray(ids) ? ids : [];
		const n = list.filter((x) => sel && sel.has(x)).length;
		return !n ? 'none' : n === list.length ? 'all' : 'some';
	}

	/** Only what is still shown stays selected (after a reload). */
	function prune(sel, ids) {
		const keep = new Set(Array.isArray(ids) ? ids : []);
		return new Set([...(sel || [])].filter((x) => keep.has(x)));
	}

	/** "3 ausgewählt" and "2 Dateien, 1 Ordner" (+ the size of the files) of the selected nodes. */
	function summary(items, t, locale) {
		const list = Array.isArray(items) ? items : [];
		const folders = list.filter((n) => n && n.isDir).length;
		const files = list.length - folders;
		const size = list.reduce((s, n) => s + (n && !n.isDir ? Number(n.size) || 0 : 0), 0);
		const parts = [];
		if (files) parts.push(plural(t, 'drive.bulk.files', files));
		if (folders) parts.push(plural(t, 'drive.bulk.folders', folders));
		return {
			count: list.length,
			files,
			folders,
			title: t('drive.bulk.selected', { count: list.length }),
			detail: parts.join(', '),
			size: files ? bytes(size, locale) : '',
		};
	}

	// ── what the selection can do ────────────────────────

	/**
	 * The actions of a selection → { zip, move, copy, link, trash, rename, cut, copyClip } each { on, why } (why: an i18n
	 * key of drive.bulk.why.* when not), and `undo`. `writable`: the folder shown may be written (search: every node's
	 * area); `vault`: the nodes lie in a vault folder (Drive 1.9). Drive 1.12: copying needs 'copyServer' (GateControl
	 * 1.215); ZIP / one link for several need GateControl's public links ('zip' / 'multiLink') and — without 'zipMixed' —
	 * one folder or at most 20 files (a link: files only).
	 */
	function actions(items, { me, writable = true, vault = false } = {}) {
		const list = Array.isArray(items) ? items : [];
		const n = list.length;
		const bulk = has(me, 'bulk');
		const mixedOk = has(me, 'zipMixed');
		const dirs = list.filter((x) => x && x.isDir).length;
		const locked = list.some((x) => x && x.encrypted && x.locked);
		const off = (why) => ({ on: false, why });
		const on = { on: true, why: null };
		// a Drive 1.12 without the feature: GateControl's links are switched off
		const linksFeature = (feature) => (has(me, feature) ? on : off(bulk ? 'drive.bulk.why.linksOff' : 'drive.bulk.why.needs112'));
		const write = writable ? on : off('drive.bulk.why.readOnly');
		const out = {};
		if (!n) out.zip = off(null);
		else if (vault) out.zip = off('drive.bulk.why.vault');
		else if (!has(me, 'zip')) out.zip = linksFeature('zip');
		else if (!mixedOk && !(dirs === 1 && n === 1) && (dirs > 0 || n > FILES_MAX)) out.zip = off('drive.bulk.why.zipLimit');
		else out.zip = on;
		// moving: the loop of single calls on an older Drive, inside the same vault too
		out.move = !n ? off(null) : locked ? off('drive.bulk.why.locked') : write;
		// copying needs only the right to read the nodes
		if (!n) out.copy = off(null);
		else if (vault) out.copy = off('drive.bulk.why.vault');
		else if (!bulk) out.copy = off('drive.bulk.why.needs112');
		else if (!has(me, 'copyServer')) out.copy = off('drive.bulk.why.needsGc');
		else out.copy = on;
		if (!n) out.link = off(null);
		else if (vault) out.link = off('drive.bulk.why.vault');
		else if (!writable) out.link = off('drive.bulk.why.readOnly');
		else if (n === 1) out.link = on;
		else if (!has(me, 'multiLink')) out.link = linksFeature('multiLink');
		else if (!mixedOk && dirs) out.link = off('drive.bulk.why.mixed');
		else if (!mixedOk && n > FILES_MAX) out.link = off('drive.bulk.why.linkLimit');
		else out.link = on;
		out.trash = !n ? off(null) : write;
		out.rename = n !== 1 ? off('drive.bulk.why.one') : locked ? off('drive.bulk.why.locked') : write;
		out.cut = out.move;
		out.copyClip = out.copy;
		// "Rückgängig" only with Drive 1.12
		out.undo = bulk;
		return out;
	}

	/** Strg+V into the folder shown: what is in the clipboard and whether it may go there → { on, why, op, count }. */
	function pasteState(clip, folder, me) {
		if (!clip || !Array.isArray(clip.items) || !clip.items.length) return { on: false, why: 'drive.bulk.clip.nothing', op: null, count: 0 };
		const op = clip.mode === 'copy' ? 'copy' : 'move';
		const count = clip.items.length;
		if (!folder || !folder.writable) return { on: false, why: 'drive.bulk.why.readOnly', op, count };
		if (op === 'copy' && !has(me, 'bulk')) return { on: false, why: 'drive.bulk.why.needs112', op, count };
		if (op === 'copy' && !has(me, 'copyServer')) return { on: false, why: 'drive.bulk.why.needsGc', op, count };
		const vault = !!(folder.node && folder.node.encrypted);
		const from = !!clip.vault;
		if (vault !== from || (vault && op === 'copy')) return { on: false, why: 'drive.bulk.why.vault', op, count };
		const id = folder.node && folder.node.id;
		if (op === 'move' && clip.items.every((x) => x.parentId === id)) return { on: false, why: 'drive.bulk.why.here', op, count };
		return { on: true, why: null, op, count };
	}

	// ── keys ─────────────────────────────────────────────

	/**
	 * A key on the page → 'all' | 'clear' | 'trash' | 'rename' | 'cut' | 'copy' | 'paste' | null. Never while typing in a
	 * field (`target`: { tag, editable }).
	 */
	function keyAction(e, { target = null } = {}) {
		const k = e || {};
		const tg = target || {};
		if (tg.editable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(str(tg.tag).toUpperCase())) return null;
		const mod = !!(k.ctrlKey || k.metaKey);
		const key = str(k.key);
		if (mod && !k.altKey) {
			const c = key.toLowerCase();
			if (c === 'a') return 'all';
			if (c === 'x') return 'cut';
			if (c === 'c') return 'copy';
			if (c === 'v') return 'paste';
			return null;
		}
		if (k.altKey || mod) return null;
		if (key === 'Escape') return 'clear';
		if (key === 'Delete') return 'trash';
		if (key === 'F2') return 'rename';
		return null;
	}

	// ── dragging onto a folder ───────────────────────────

	/**
	 * May the dragged nodes go into folder `targetId`? Not into one of them, not where they all are already (a move);
	 * `crumbs`: the ids above the target when known (a dragged folder must not be one of them).
	 */
	function canDrop(drag, targetId, { copy = false, crumbs = [] } = {}) {
		if (!drag || !Array.isArray(drag.items) || !drag.items.length || !isId(targetId)) return false;
		const ids = new Set(drag.items.map((x) => x.id));
		if (ids.has(targetId)) return false;
		if ((crumbs || []).some((c) => ids.has(c))) return false;
		if (!copy && drag.items.every((x) => x.parentId === targetId)) return false;
		return true;
	}

	/** "3 Elemente hierher verschieben" / "… kopieren" */
	function dropText(count, copy, t) {
		return plural(t, copy ? 'drive.bulk.drop.copy' : 'drive.bulk.drop.move', count);
	}

	// ── "Ziel wählen" ────────────────────────────────────

	/**
	 * A folder of the target dialog → { disabled, sub } — one of the selected folders (or below one) cannot take them:
	 * "Wird verschoben – nicht in sich selbst". `crumbIds`: the ids of the folder shown and above it.
	 */
	function targetRow(node, items, { mode = 'move', crumbIds = [] } = {}) {
		const ids = new Set((Array.isArray(items) ? items : []).filter((x) => x && x.isDir).map((x) => x.id));
		const inside = ids.has(node && node.id) || (crumbIds || []).some((c) => ids.has(c));
		return inside ? { disabled: true, sub: mode === 'copy' ? 'drive.bulk.target.itselfCopy' : 'drive.bulk.target.itself' } : { disabled: false, sub: null };
	}

	/**
	 * May the folder shown be the target → { ok, why } — written to, not one of the selected folders (or inside one),
	 * not where everything is already (a move), never a vault from outside (and out of one).
	 */
	function targetOk(folder, items, { mode = 'move', vault = null } = {}) {
		if (!folder || !folder.node) return { ok: false, why: null };
		if (!folder.writable) return { ok: false, why: 'drive.bulk.target.readOnly' };
		const enc = !!folder.node.encrypted;
		if (enc !== !!vault || (enc && folder.node.vaultId !== vault)) return { ok: false, why: 'drive.bulk.why.vault' };
		const crumbIds = (folder.crumbs || []).map((c) => c.id).concat(folder.node.id);
		const list = Array.isArray(items) ? items : [];
		if (targetRow(folder.node, list, { mode, crumbIds }).disabled) return { ok: false, why: mode === 'copy' ? 'drive.bulk.target.itselfCopy' : 'drive.bulk.target.itself' };
		if (mode === 'move' && list.length && list.every((x) => x.parentId === folder.node.id)) return { ok: false, why: 'drive.bulk.why.here' };
		return { ok: true, why: null };
	}

	/** The folders used last as targets (kept on this PC) → [{ id, path }] */
	function parseRecent(raw) {
		let v = null;
		try { v = JSON.parse(str(raw) || '[]'); } catch { v = []; }
		return (Array.isArray(v) ? v : []).filter((x) => x && isId(x.id) && typeof x.path === 'string' && x.path).slice(0, RECENT_MAX).map((x) => ({ id: x.id, path: x.path.slice(0, 500) }));
	}

	/** The list with `id` first (at most RECENT_MAX) → JSON */
	function pushRecent(list, id, path) {
		const out = [{ id, path: str(path).slice(0, 500) }, ...(Array.isArray(list) ? list : []).filter((x) => x.id !== id)].slice(0, RECENT_MAX);
		return JSON.stringify(out);
	}

	/** "Meine Dateien › Steuern › 2025" → "Steuern › 2025" for a chip (the last two parts). */
	function shortPath(path) {
		const parts = str(path).split(' › ').filter(Boolean);
		return parts.length > 2 ? parts.slice(-2).join(' › ') : parts.join(' › ');
	}

	// ── names the target has already ─────────────────────

	/**
	 * The question once for all names → { title, intro, rows: [{ name, text }], more, sameNames, sameText, ask,
	 * renameExample, skipText } — `ask` false when every one has the same content there (nothing to decide).
	 */
	function conflictView(check, { t, locale, now = Date.now(), mode = 'move', target = '', when = null } = {}) {
		const list = check && Array.isArray(check.conflicts) ? check.conflicts : [];
		const day = (ms) => (Number.isFinite(ms) ? (typeof when === 'function' ? when(ms, now, locale, t) : new Date(ms).toLocaleDateString(localeTag(locale))) : '');
		const what = (size, mtime, dir) => (dir ? t('drive.bulk.conflict.folder') : [bytes(size, locale), day(mtime)].filter(Boolean).join(', '));
		const rows = list.slice(0, 8).map((c) => ({
			name: c.path || c.name,
			text: c.isDir && c.existing && c.existing.isDir
				? t('drive.bulk.conflict.merge')
				: `${t('drive.bulk.conflict.there', { what: what(c.existing && c.existing.size, c.existing && c.existing.mtime, c.existing && c.existing.isDir) })} · ${t('drive.bulk.conflict.new', { what: c.same ? t('drive.bulk.conflict.same') : what(c.size, c.mtime, c.isDir) })}`,
		}));
		const same = list.filter((c) => c.same).map((c) => c.name);
		const first = list.find((c) => !c.isDir) || list[0];
		const ext = first ? str(first.name).lastIndexOf('.') : -1;
		return {
			title: plural(t, 'drive.bulk.conflict.title', list.length),
			intro: t('drive.bulk.conflict.intro', { folder: target }),
			rows,
			more: list.length + (Number(check && check.conflictsMore) || 0) > rows.length ? t('drive.bulk.conflict.more', { count: list.length + (Number(check && check.conflictsMore) || 0) - rows.length }) : '',
			merges: check && check.merges ? plural(t, 'drive.bulk.conflict.merges', check.merges) : '',
			sameNames: same,
			sameText: same.length ? t('drive.bulk.conflict.sameHint', { names: same.slice(0, 3).join('“, „') }) : t('drive.bulk.conflict.sameHintAny'),
			ask: list.some((c) => !c.same),
			renameExample: first && ext > 0 && !first.isDir ? `… (2)${str(first.name).slice(ext)}` : '… (2)',
			skipText: plural(t, mode === 'copy' ? 'drive.bulk.conflict.skipSubCopy' : 'drive.bulk.conflict.skipSub', list.filter((c) => !c.same).length),
		};
	}

	const REASONS = ['forbidden', 'into_itself', 'encrypted', 'locked', 'same_folder', 'root', 'not_found'];

	/** "2 Elemente können nicht mit: liegen schon dort" (grouped by reason) or '' */
	function blockedText(blocked, t) {
		const list = Array.isArray(blocked) ? blocked : [];
		if (!list.length) return '';
		const by = new Map();
		for (const b of list) by.set(b.reason, (by.get(b.reason) || 0) + 1);
		const why = [...by.keys()].map((r) => t(`drive.bulk.reason.${REASONS.includes(r) ? r : 'failed'}`)).join(', ');
		return plural(t, 'drive.bulk.blocked', list.length, { why });
	}

	// ── a job ────────────────────────────────────────────

	const OP_KINDS = ['move', 'copy', 'trash', 'restore', 'purge', 'undo'];
	const failedOf = (res) => Math.max(Number(res && res.failedCount) || 0, res && Array.isArray(res.failed) ? res.failed.length : 0);

	/** "Kopiere „Urlaub 2026“ nach Familie" / "Verschiebe 3 Elemente nach Rechnungen" / "Lösche 2 Elemente" */
	function opTitle(row, t) {
		const r = row || {};
		const kind = r.undo ? 'undo' : OP_KINDS.includes(r.kind) ? r.kind : 'move';
		const target = str(r.targetName).split(' › ').pop() || '…';
		const count = Number(r.count) || 0;
		if (kind === 'undo') return t('drive.bulk.op.undo');
		if (r.name && count <= 1) return t(`drive.bulk.op.${kind}One`, { name: r.name, target });
		return plural(t, `drive.bulk.op.${kind}`, count || Number(r.total) || 0, { target });
	}

	/**
	 * A job's row of the transfer list → { title, text, pct, active, cls, cancel, undo, server }: "58 von 128 Dateien ·
	 * 1,4 von 3,1 GB", the end (with what was skipped / failed), "Abbrechen" while it runs, "Rückgängig" until undoUntil.
	 */
	function opView(row, { t, locale, now = Date.now(), errorText = null } = {}) {
		const r = row || {};
		const total = Number(r.total) || 0;
		const done = Math.min(total || Number(r.done) || 0, Number(r.done) || 0);
		const running = r.state === 'running';
		let text;
		let cls = '';
		if (running) {
			const files = total ? t('drive.bulk.op.files', { done, total }) : t('drive.bulk.op.starting');
			text = Number(r.bytesTotal) > 0 ? `${files} · ${t('drive.bulk.op.bytes', { done: bytes(r.bytesDone || 0, locale), total: bytes(r.bytesTotal, locale) })}` : files;
		} else if (r.state === 'done') {
			const res = r.results || {};
			const extra = [];
			if (res.skipped) extra.push(t('drive.bulk.op.skipped', { count: res.skipped }));
			if (failedOf(res)) extra.push(t('drive.bulk.op.failedSome', { count: failedOf(res) }));
			text = [r.undone ? t('drive.bulk.snack.undone') : t('drive.bulk.op.done'), ...extra].join(' · ');
			cls = failedOf(res) ? 'is-warn' : 'is-ok';
		} else if (r.state === 'cancelled') {
			text = t('drive.bulk.op.cancelled');
			cls = 'is-warn';
		} else {
			const reason = typeof errorText === 'function' ? errorText({ code: r.code || 'failed' }, t) : str(r.code);
			text = t('drive.bulk.op.failed', { reason });
			cls = 'is-err';
		}
		const pct = total > 0 ? Math.round((done / total) * 100) : (running ? 0 : 100);
		return {
			title: opTitle(r, t),
			text,
			pct,
			cls,
			active: running,
			cancel: running,
			// the jobs of the server go on without the app
			server: running && !r.local,
			undo: !running && !!r.undoable && !r.undone && Number.isFinite(r.undoUntil) && r.undoUntil > now,
		};
	}

	/** The note when a job ended → { text, undo } ("3 Elemente nach „Rechnungen“ verschoben" · "Rückgängig") or null */
	function snackView(row, { t, now = Date.now() } = {}) {
		const r = row || {};
		if (r.state === 'running') return null;
		const count = Number(r.count) || (r.results ? (r.results.done || 0) + (r.results.skipped || 0) + failedOf(r.results) : 0) || Number(r.total) || 0;
		const target = str(r.targetName).split(' › ').pop() || '…';
		let text;
		if (r.undo) text = t('drive.bulk.snack.undone');
		else if (r.state === 'cancelled') text = t('drive.bulk.op.cancelled');
		else if (r.state === 'failed') return null;
		else if (r.kind === 'trash') text = plural(t, 'drive.bulk.snack.trash', count);
		else if (r.kind === 'copy') text = plural(t, 'drive.bulk.snack.copy', count, { target });
		else if (r.kind === 'move') text = plural(t, 'drive.bulk.snack.move', count, { target });
		else if (r.kind === 'restore') text = plural(t, 'drive.bulk.snack.restore', count);
		else text = t('drive.bulk.op.done');
		const res = r.results || {};
		const extra = [];
		if (res.skipped) extra.push(t('drive.bulk.op.skipped', { count: res.skipped }));
		if (failedOf(res)) extra.push(t('drive.bulk.op.failedSome', { count: failedOf(res) }));
		return { text: [text, ...extra].join(' · '), undo: !!r.undoable && !r.undo && Number.isFinite(r.undoUntil) && r.undoUntil > now, warn: !!failedOf(res) };
	}

	/** How long the note stays (ms): until "Rückgängig" ends, at most 12 s, at least 6 s. */
	function snackMs(row, now = Date.now()) {
		const until = row && Number.isFinite(row.undoUntil) ? row.undoUntil - now : 12000;
		return Math.max(6000, Math.min(12000, until));
	}

	// ── "neu hier" ───────────────────────────────────────

	/**
	 * After a move / copy: what is new in the target → { folderId, ids, names, until } (ids of a move stay the same;
	 * copies are known by their names).
	 */
	function freshOf(job, row, now = Date.now()) {
		if (!job || !row || row.state !== 'done' || row.undo || !(row.kind === 'move' || row.kind === 'copy') || !isId(job.targetId)) return null;
		// Drive 1.12 names the top nodes at the target (results.resultIds); else moved ones keep their ids, copies their names
		const made = row.results && Array.isArray(row.results.resultIds) ? row.results.resultIds.filter(isId) : [];
		return {
			folderId: job.targetId,
			ids: new Set(made.length ? made : row.kind === 'move' ? job.ids || [] : []),
			names: !made.length && row.kind === 'copy' ? new Set((job.names || []).map((x) => str(x).toLowerCase())) : new Set(),
			until: now + NEW_HERE_MS,
		};
	}

	/** Is node `n` in folder `folderId` "neu hier"? */
	function isFresh(fresh, n, folderId, now = Date.now()) {
		if (!fresh || fresh.folderId !== folderId || now > fresh.until || !n) return false;
		return fresh.ids.has(n.id) || fresh.names.has(str(n.name).toLowerCase());
	}

	// ── "Fotos": Alle / Keine per month ─────────────────

	/** A month's photos in the selection → 'none' | 'some' | 'all' */
	function monthState(sel, items) {
		return headState(sel, (Array.isArray(items) ? items : []).map((p) => p.id));
	}

	/** All of a month in (on) or out of the selection. */
	function selectMonth(sel, items, on) {
		const out = new Set(sel instanceof Set ? sel : []);
		for (const p of Array.isArray(items) ? items : []) { if (on) out.add(p.id); else out.delete(p.id); }
		return out;
	}

	return {
		RECENT_KEY, RECENT_MAX, DRAG_TYPE, NEW_HERE_MS, FILES_MAX, REASONS,
		click, toggle, headState, prune, summary,
		actions, pasteState, keyAction,
		canDrop, dropText,
		targetRow, targetOk, parseRecent, pushRecent, shortPath,
		conflictView, blockedText,
		opTitle, opView, snackView, snackMs,
		freshOf, isFresh,
		monthState, selectMonth,
	};
});
