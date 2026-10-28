/**
 * GateControl -- Drive: the menu, the vault lock and the Drive settings (renderer, no DOM access)
 *
 * Drive 1.11 on the page "Drive": the left column (the person's name and seat, "Persönlich" / "Gemeinsam" with the
 * areas as an unfoldable folder tree — loaded only when unfolded, the unfolded nodes kept on this PC —, "Tresore"
 * and the bar of icons), the keyboard steps of the tree (arrows, Home / End, Enter), the vault rows, the choices of
 * "Neuer Tresor" ("Wer darf ihn öffnen?"), and the texts of the vault lock (Windows Hello) and of the Drive settings
 * (auto-lock choices, the cache, AI per area, the notification topics of Drive). Pure helpers for drive-view.js,
 * drive-vault-view.js and drive-settings-view.js, loaded as a plain script (window.GCDriveMenuState) and required by
 * the node tests (test/drive-menu-state.test.js).
 *
 * Inputs are what window.gatecontrol.drive returns (core DriveService); `t` is the i18n function (keys drive.*).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDriveMenuState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const OPEN_KEY = 'gc.drive.tree.open';
	const OPEN_MAX = 500;
	const AUTO_LOCK = [1, 3, 5, 15, 0];
	const DRIVE_TOPIC = 'plugin:gatecontrol-drive:';
	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const has = (me, f) => !!(me && Array.isArray(me.features) && me.features.includes(f));
	const isId = (v) => Number.isSafeInteger(v) && v > 0;

	// ── who ──────────────────────────────────────────────

	/** The head of the menu → { name, initial, seat } ("Familien-Platz" / "Business-Platz"). */
	function meView(me, t) {
		const m = (me && me.me) || {};
		const name = str(m.name).trim();
		return {
			name,
			initial: name ? name.charAt(0).toUpperCase() : '?',
			seat: m.seat === 'family' ? t('drive.menu.seat.family') : m.seat === 'business' ? t('drive.menu.seat.business') : '',
		};
	}

	/** "Persönlich" (Meine Dateien) and "Gemeinsam" (Familie, Kinder, Team-Ordner) in the areas' order. */
	function areaGroups(areas) {
		const list = Array.isArray(areas) ? areas.filter(Boolean) : [];
		return { personal: list.filter((a) => a.kind === 'mine'), shared: list.filter((a) => a.kind !== 'mine') };
	}

	// ── the unfolded nodes (kept on this PC) ─────────────

	function parseOpen(text) {
		let v = null;
		try { v = JSON.parse(str(text) || '[]'); } catch { v = null; }
		return new Set((Array.isArray(v) ? v : []).filter(isId).slice(-OPEN_MAX));
	}

	function serializeOpen(set) {
		return JSON.stringify([...(set || [])].filter(isId).slice(-OPEN_MAX));
	}

	/** The folders above the one shown (unfolded so it is visible in the tree): its crumbs without itself. */
	function ancestorsOf(folder) {
		const cr = folder && Array.isArray(folder.crumbs) ? folder.crumbs : [];
		return cr.slice(0, -1).map((c) => c.id).filter(isId);
	}

	// ── the tree ─────────────────────────────────────────

	/**
	 * Can a node be unfolded? hasDirs true / false from Drive 1.11; unknown (older Drive) until loaded: then by what
	 * came back.
	 */
	function expandable(hasDirs, loaded) {
		if (loaded) return loaded.items.length > 0;
		return hasDirs !== false;
	}

	/**
	 * The visible rows of one group's tree → { rows, needs } — rows: { key, id, level, area, label, sub, kind,
	 * expandable, expanded, loading, current, posinset, setsize }; needs: the unfolded nodes not loaded yet.
	 * @param {object[]} areas - the group's areas
	 * @param {object} o - { nodes: Map id → { items: [{ id, name, hasDirs }], loading, error } | undefined, open: Set,
	 *   current: the folder shown (id) or null, t, locale, usage(a) → text, areaLabel(a), areaHint(a) }
	 */
	function treeRows(areas, o) {
		const rows = [];
		const needs = [];
		const nodes = o.nodes || new Map();
		const open = o.open || new Set();
		const list = Array.isArray(areas) ? areas : [];
		const walk = (items, level, parentKey) => {
			items.forEach((n, i) => {
				const loaded = nodes.get(n.id);
				const done = loaded && Array.isArray(loaded.items) ? loaded : null;
				const can = expandable(n.hasDirs, done);
				const expanded = can && open.has(n.id);
				const key = `n:${n.id}`;
				rows.push({
					key, id: n.id, level, area: null, label: str(n.name), sub: null, kind: 'folder', parentKey,
					expandable: can, expanded, loading: expanded && !done, current: o.current === n.id, posinset: i + 1, setsize: items.length,
				});
				if (expanded && !done && !(loaded && loaded.loading) && !(loaded && loaded.error)) needs.push(n.id);
				if (expanded && done) walk(done.items, level + 1, key);
			});
		};
		list.forEach((a, i) => {
			const loaded = nodes.get(a.rootId);
			const done = loaded && Array.isArray(loaded.items) ? loaded : null;
			const can = expandable(null, done);
			const expanded = can && open.has(a.rootId);
			const key = `n:${a.rootId}`;
			const use = typeof o.usage === 'function' ? o.usage(a) : null;
			const hint = typeof o.areaHint === 'function' ? o.areaHint(a) : '';
			rows.push({
				key, id: a.rootId, level: 1, area: a.id, label: typeof o.areaLabel === 'function' ? o.areaLabel(a) : str(a.label),
				sub: [use, hint].filter(Boolean).join(' · ') || null, kind: a.kind, parentKey: null,
				expandable: can, expanded, loading: expanded && !done, current: o.current === a.rootId, posinset: i + 1, setsize: list.length,
			});
			if (expanded && !done && !(loaded && loaded.loading) && !(loaded && loaded.error)) needs.push(a.rootId);
			if (expanded && done) walk(done.items, 2, key);
		});
		return { rows, needs };
	}

	/**
	 * A key on a tree row (WAI-ARIA tree) → { focus: index } | { expand: id } | { collapse: id } | { open: id } | null.
	 * ArrowDown / ArrowUp: next / previous row; Home / End; ArrowRight: unfold, or to the first child; ArrowLeft:
	 * fold, or to the parent; Enter / Space: open the folder.
	 */
	function treeKey(key, rows, index) {
		const r = rows[index];
		if (!r) return null;
		switch (key) {
			case 'ArrowDown': return index + 1 < rows.length ? { focus: index + 1 } : null;
			case 'ArrowUp': return index > 0 ? { focus: index - 1 } : null;
			case 'Home': return rows.length ? { focus: 0 } : null;
			case 'End': return rows.length ? { focus: rows.length - 1 } : null;
			case 'ArrowRight':
				if (r.expandable && !r.expanded) return { expand: r.id };
				if (r.expanded && rows[index + 1] && rows[index + 1].level > r.level) return { focus: index + 1 };
				return null;
			case 'ArrowLeft': {
				if (r.expanded) return { collapse: r.id };
				const p = rows.findIndex((x) => x.key === r.parentKey);
				return p >= 0 ? { focus: p } : null;
			}
			case 'Enter':
			case ' ':
				return { open: r.id };
			default: return null;
		}
	}

	// ── vaults ───────────────────────────────────────────

	/** Who a vault is for: "Privat" / "Mit Familie geteilt" / "Kinder · Lena" / "Team · Büro". */
	function vaultScope(area, t) {
		if (!area) return '';
		if (area.kind === 'mine') return t('drive.menu.vault.private');
		if (area.kind === 'family') return t('drive.menu.vault.family');
		if (area.kind === 'child') return t('drive.area.child', { name: str(area.label) });
		return t('drive.area.team', { name: str(area.label) });
	}

	function shortDate(ms, locale) {
		if (!Number.isFinite(ms)) return '';
		try { return new Date(ms).toLocaleDateString(locale === 'en' ? 'en-GB' : 'de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' }); } catch { return ''; }
	}

	/**
	 * The rows under "Tresore" → [{ vaultId, nodeId, name, sub, state, locked, current }] — the name only while open
	 * (locked: "Tresor vom 12.03.2026"); state text: entsperrt / gesperrt / wartet auf Freigabe / kein Zugriff.
	 */
	function vaultRows(vaults, areas, { t, locale, currentVault = null } = {}) {
		const list = Array.isArray(vaults) ? vaults : [];
		const byArea = new Map((Array.isArray(areas) ? areas : []).map((a) => [a.id, a]));
		return list.map((v) => {
			const st = v.state === 'open' ? 'open' : v.state === 'pending' ? 'pending' : v.state === 'none' || v.state === 'revoked' ? 'none' : v.state === 'unsupported' ? 'unsupported' : 'locked';
			const date = shortDate(v.createdAt, locale);
			const name = v.name ? str(v.name) : (date ? t('drive.menu.vault.lockedName', { date }) : t('drive.menu.vault.lockedNameNoDate'));
			return {
				vaultId: v.id, nodeId: v.nodeId, name, state: st, locked: st !== 'open',
				sub: [vaultScope(byArea.get(v.areaId), t), t(`drive.menu.vault.state.${st}`)].filter(Boolean).join(' · '),
				current: currentVault === v.id,
			};
		}).sort((a, b) => Number(a.locked) - Number(b.locked) || a.name.localeCompare(b.name));
	}

	/**
	 * "Wer darf ihn öffnen?" of "Neuer Tresor" → [{ areaId, label, hint }]: "Nur ich" (Meine Dateien), "Mit der
	 * Familie teilen" (only with a family seat), for a business seat each team folder one may write to.
	 */
	function vaultChoices(me, areas, t) {
		const list = (Array.isArray(areas) ? areas : []).filter((a) => a && a.writable && !a.archived);
		const seat = me && me.me ? me.me.seat : null;
		const out = [];
		for (const a of list.filter((x) => x.kind === 'mine')) out.push({ areaId: a.id, label: t('drive.vault.create.onlyMe'), hint: t('drive.vault.create.onlyMeHint') });
		if (seat !== 'business') for (const a of list.filter((x) => x.kind === 'family')) out.push({ areaId: a.id, label: t('drive.vault.create.family'), hint: t('drive.vault.create.familyHint') });
		if (seat === 'business') for (const a of list.filter((x) => x.kind === 'team')) out.push({ areaId: a.id, label: t('drive.area.team', { name: str(a.label) }), hint: t('drive.vault.create.teamHint') });
		return out;
	}

	// ── the bar of icons ─────────────────────────────────

	/**
	 * The icons at the bottom of the menu (only what this Drive / this build has) → [{ key, icon, label }] — key is
	 * the view it opens ('import' opens the portal).
	 */
	function toolItems({ me, photos = false, storage = false, sync = false, deadlines = false, importer = false, settings = true }, t) {
		const out = [];
		if (photos && has(me, 'photos')) out.push({ key: 'photos', icon: 'image', label: t('drive.photos.title') });
		out.push({ key: 'links', icon: 'link', label: t('drive.menu.links') });
		out.push({ key: 'trash', icon: 'trash', label: t('drive.trash.title') });
		if (storage && has(me, 'storage')) out.push({ key: 'storage', icon: 'disk', label: t('drive.storage.title') });
		if (sync) out.push({ key: 'sync', icon: 'sync', label: t('drive.sync.title') });
		if (deadlines && has(me, 'docAi')) out.push({ key: 'deadlines', icon: 'calendar', label: t('drive.deadline.title') });
		if (importer && has(me, 'cloudImport')) out.push({ key: 'import', icon: 'import', label: t('drive.import.menu') });
		if (settings) out.push({ key: 'settings', icon: 'gear', label: t('drive.settings.title') });
		return out;
	}

	// ── the vault lock ───────────────────────────────────

	/** What Windows Hello answered → the hint of the vault card / the settings (null: nothing to say). */
	function helloHint(hello, t) {
		if (!hello || hello.available) return null;
		const r = hello.reason;
		if (r === 'not_set_up' || r === 'device_not_present') return { text: t('drive.lock.hello.notSetUp'), setup: true };
		if (r === 'disabled_by_policy') return { text: t('drive.lock.hello.policy'), setup: false };
		if (r === 'device_busy') return { text: t('drive.lock.hello.busy'), setup: false };
		return { text: t('drive.lock.hello.unavailable'), setup: false };
	}

	/** May the card offer "Entsperren"? (Hello available, or the switch off) */
	function canUnlock(lock) {
		if (!lock || !lock.enforced) return true;
		return !(lock.settings && lock.settings.hello) || !!(lock.hello && lock.hello.available);
	}

	function autoLockOptions(t) {
		return AUTO_LOCK.map((m) => ({ value: m, label: m ? t(m === 1 ? 'drive.lock.after.one' : 'drive.lock.after.other', { count: m }) : t('drive.lock.after.never') }));
	}

	/** The vaults this PC has keys for ("Freigegeben für") → names (locked ones by date). */
	function approvedVaults(rows) {
		return (Array.isArray(rows) ? rows : []).filter((r) => r.state === 'open' || r.state === 'locked').map((r) => r.name);
	}

	// ── the settings ─────────────────────────────────────

	/** "KI für Dokumente": the areas with a switch (one may write; the Drive says docAi) → [{ areaId, on }] */
	function docAiAreas(areas, me) {
		if (!has(me, 'docAi')) return [];
		return (Array.isArray(areas) ? areas : []).filter((a) => a && typeof a.docAi === 'boolean' && a.writable && !a.archived).map((a) => ({ area: a, areaId: a.id, on: a.docAi }));
	}

	/** Drive's notification topics on this PC (the app's mute list) → [{ id, label, on }] */
	function notifyRows(topics, muted, t) {
		const off = new Set(Array.isArray(muted) ? muted : []);
		return (Array.isArray(topics) ? topics : []).filter((tp) => tp && typeof tp.id === 'string' && tp.id.startsWith(DRIVE_TOPIC)).map((tp) => {
			const ev = tp.id.slice(DRIVE_TOPIC.length);
			const label = ev === 'deadline' ? t('drive.settings.notify.deadline') : ev === 'vault' ? t('drive.settings.notify.vault') : (str(tp.label) || ev);
			return { id: tp.id, label, on: !off.has(tp.id) };
		});
	}

	/** The mute list after switching topic `id` on / off. */
	function toggleMuted(muted, id, on) {
		const s = new Set(Array.isArray(muted) ? muted : []);
		if (on) s.delete(id); else s.add(id);
		return [...s];
	}

	return {
		OPEN_KEY, AUTO_LOCK,
		meView, areaGroups, parseOpen, serializeOpen, ancestorsOf, expandable, treeRows, treeKey,
		vaultScope, vaultRows, vaultChoices, toolItems,
		helloHint, canUnlock, autoLockOptions, approvedVaults,
		docAiAreas, notifyRows, toggleMuted,
	};
});
