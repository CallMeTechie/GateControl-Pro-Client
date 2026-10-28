/**
 * GateControl -- Drive "Speicher" view state (renderer, no DOM access)
 *
 * Pure helpers of the view "Speicher" of the page Drive (Drive 1.7
 * 'storage'): the total with its parts (files, older versions, trash) and
 * the limit, the areas and people as bars, the largest files and the
 * duplicates with the choice what goes into the trash (at least one copy of
 * each group always stays). Loaded as a plain script before
 * drive-storage-view.js (window.GCDriveStorageState) and required by the
 * node tests (test/drive-storage-state.test.js).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDriveStorageState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const num = (v) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : 0);

	function plural(t, key, n, params) {
		const count = Number(n) || 0;
		return t(`${key}.${count === 1 ? 'one' : 'other'}`, { ...(params || {}), count });
	}

	/** Percent 0 … 100 (one decimal below 10 %), 0 without a whole. */
	function pct(part, whole) {
		const w = num(whole);
		if (!w) return 0;
		const p = Math.min(100, (num(part) / w) * 100);
		return p < 10 ? Math.round(p * 10) / 10 : Math.round(p);
	}

	/**
	 * The head: { used, of, pct, parts: [{ key, label, bytes, text }], files }
	 * (`of`: the limit of the storage, or null).
	 */
	function totalView(st, { t, fmt } = {}) {
		const tot = (st && st.total) || {};
		const max = st && st.limit ? num(st.limit.maxBytes) : 0;
		const all = num(tot.bytes) + num(tot.versionsBytes) + num(tot.trashBytes);
		const parts = [
			{ key: 'files', bytes: num(tot.bytes) },
			{ key: 'versions', bytes: num(tot.versionsBytes) },
			{ key: 'trash', bytes: num(tot.trashBytes) },
		].map((p) => ({ ...p, label: t(`drive.storage.part.${p.key}`), text: fmt(p.bytes), pct: pct(p.bytes, max || all) }));
		return {
			used: fmt(all),
			of: max ? fmt(max) : null,
			pct: max ? pct(all, max) : null,
			parts,
			files: plural(t, 'drive.storage.files', num(tot.files)),
		};
	}

	/** The areas (or people) as bars against the largest one → [{ id, label, text, sub, pct }] */
	function barsView(list, { t, fmt, areaLabel } = {}) {
		const rows = Array.isArray(list) ? list : [];
		const top = rows.reduce((m, r) => Math.max(m, num(r.bytes) + num(r.versionsBytes) + num(r.trashBytes)), 0);
		return rows.map((r) => {
			const sum = num(r.bytes) + num(r.versionsBytes) + num(r.trashBytes);
			const sub = [plural(t, 'drive.storage.files', num(r.files))];
			if (num(r.versionsBytes)) sub.push(t('drive.storage.versionsOf', { size: fmt(r.versionsBytes) }));
			if (num(r.trashBytes)) sub.push(t('drive.storage.trashOf', { size: fmt(r.trashBytes) }));
			const label = r.user ? str(r.name) || `#${r.user}` : (areaLabel ? areaLabel({ ...r, label: r.label }, t) : str(r.label));
			return {
				id: r.id || `u${r.user}`,
				label,
				text: r.quota ? t('drive.storage.ofQuota', { used: fmt(sum), quota: fmt(r.quota) }) : fmt(sum),
				sub: sub.join(' · '),
				pct: r.quota ? pct(sum, r.quota) : pct(sum, top),
			};
		});
	}

	/** Where a file lies: "Meine Dateien › Fotos" (its path without the name, the area's label first). */
	function placeOf(item, areas, areaLabel, t) {
		const a = (Array.isArray(areas) ? areas : []).find((x) => x.id === item.areaId);
		const parts = str(item.path).split('/').filter(Boolean);
		if (parts.length && parts[parts.length - 1] === item.name) parts.pop();
		return [a && areaLabel ? areaLabel(a, t) : '', ...parts].filter(Boolean).join(' › ');
	}

	/** A duplicate group → { key, title, sub, items } */
	function dupView(g, { t, fmt } = {}) {
		const x = g || {};
		return {
			key: str(x.sha256) || x.items.map((i) => i.id).join('-'),
			title: str((x.items[0] || {}).name),
			sub: [plural(t, 'drive.storage.copies', num(x.count) || x.items.length), t('drive.storage.size', { size: fmt(x.size) }), t('drive.storage.wasted', { size: fmt(x.wasted) })].join(' · '),
			items: x.items,
		};
	}

	/**
	 * The suggestion for a group: every copy but the oldest goes (only those one may delete)
	 * → Set of ids. The copy kept is the one changed first.
	 */
	function suggest(group) {
		const items = (group && Array.isArray(group.items) ? group.items : []).slice();
		if (items.length < 2) return new Set();
		items.sort((a, b) => (num(a.updatedAt) || Infinity) - (num(b.updatedAt) || Infinity) || a.id - b.id);
		const keep = items.find((i) => !i.canDelete) || items[0];
		return new Set(items.filter((i) => i !== keep && i.canDelete).map((i) => i.id));
	}

	/** Can `id` be ticked in its group: one may delete it, and it is not the last copy left unticked. */
	function canTick(group, selected, id) {
		const items = group && Array.isArray(group.items) ? group.items : [];
		const it = items.find((i) => i.id === id);
		if (!it || !it.canDelete) return false;
		if (selected.has(id)) return true;
		const left = items.filter((i) => !selected.has(i.id) && i.id !== id);
		return left.length >= 1;
	}

	/** The ids ticked over all groups, with every group keeping at least one copy → [id] */
	function toTrash(groups, selected) {
		const out = [];
		for (const g of Array.isArray(groups) ? groups : []) {
			const items = Array.isArray(g.items) ? g.items : [];
			const ticked = items.filter((i) => selected.has(i.id) && i.canDelete);
			if (ticked.length >= items.length) ticked.pop(); // never every copy
			out.push(...ticked.map((i) => i.id));
		}
		return out;
	}

	/** Bytes the ticked copies take → number */
	function freed(groups, ids) {
		const set = new Set(ids);
		let n = 0;
		for (const g of Array.isArray(groups) ? groups : []) for (const i of g.items || []) if (set.has(i.id)) n += num(i.size || g.size);
		return n;
	}

	return { pct, totalView, barsView, placeOf, dupView, suggest, canTick, toTrash, freed };
});
