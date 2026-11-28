/**
 * GateControl -- layout of the pages on this PC (renderer, no DOM access)
 *
 * The widths (and the list's height) the person dragged with the dividers
 * (gc-split.js, window.GCSplit) in Mail, Mitteilungen and Notizen & Aufgaben.
 * Kept per device in localStorage, one entry per page:
 *
 *   gc.layout.mail  = { …, w: { folders, list }, h: { list } }   (h: share of the height)
 *   gc.layout.inbox = { w: { list } }
 *   gc.layout.notes = { w: { side, detail } }
 *
 * A divider is named by its page and path ("notes.w.detail"); LIMITS holds
 * its minimum, maximum and standard size (px, for h: a share 0…1). A stored
 * size is only ever limited by the window (the room left for the other side),
 * never overwritten by it. Loaded as a plain script before gc-split.js
 * (window.GCLayoutState) and required by the node tests
 * (test/layout-state.test.js).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCLayoutState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const PREFIX = 'gc.layout.';
	const PAGES = ['mail', 'inbox', 'notes'];

	// min, max, standard; `keep`: what the other side keeps at least (px)
	const LIMITS = {
		'mail.w.folders': { min: 180, max: 320, def: 224 },
		'mail.w.list': { min: 300, max: 640, def: 360, keep: 420 },
		'mail.h.list': { min: 0.3, max: 0.7, def: 0.42, keep: 220 },
		'inbox.w.list': { min: 320, max: 640, def: 0.4, defMin: 380, defMax: 520, keep: 420 },
		'notes.w.side': { min: 190, max: 320, def: 232 },
		'notes.w.detail': { min: 340, max: 760, def: 460, defNote: 520, keep: 360 },
	};
	// the arrow keys move a divider by 16 px, with Umschalt by 64 px
	const STEP = 16;
	const STEP_BIG = 64;

	const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
	const num = (v) => typeof v === 'number' && Number.isFinite(v);

	/** "notes.w.detail" → { page: 'notes', path: ['w', 'detail'] } (null for anything else). */
	function parseKey(key) {
		const parts = String(key || '').split('.');
		if (parts.length !== 3 || !PAGES.includes(parts[0]) || (parts[1] !== 'w' && parts[1] !== 'h') || !/^[a-z]+$/.test(parts[2])) return null;
		return { page: parts[0], path: [parts[1], parts[2]] };
	}

	/** The storage key of a page ("gc.layout.mail"). */
	const storageKey = (page) => PREFIX + page;

	/** What the storage holds for a page (a JSON text or null) → a plain object (never throws). */
	function readPage(raw) {
		if (!raw) return {};
		try {
			const v = typeof raw === 'string' ? JSON.parse(raw) : raw;
			return isObj(v) ? v : {};
		} catch {
			return {};
		}
	}

	/** The stored size of a divider (a number within its limits) or null. */
	function sizeOf(page, key) {
		const k = parseKey(key);
		const lim = LIMITS[key];
		if (!k || !lim) return null;
		const box = isObj(page) ? page[k.path[0]] : null;
		const v = isObj(box) ? box[k.path[1]] : null;
		return num(v) ? clamp(v, lim.min, lim.max) : null;
	}

	/** The page with a divider's size set (null: removed) → a copy. */
	function withSize(page, key, v) {
		const k = parseKey(key);
		const out = { ...(isObj(page) ? page : {}) };
		if (!k) return out;
		const box = { ...(isObj(out[k.path[0]]) ? out[k.path[0]] : {}) };
		if (v === null || v === undefined || !num(v)) delete box[k.path[1]];
		else box[k.path[1]] = k.path[0] === 'h' ? Math.round(v * 1000) / 1000 : Math.round(v);
		if (Object.keys(box).length) out[k.path[0]] = box;
		else delete out[k.path[0]];
		return out;
	}

	/** The page without any widths and heights ("Spaltenbreiten zurücksetzen"); the rest stays. */
	function withoutSizes(page) {
		const out = { ...(isObj(page) ? page : {}) };
		delete out.w;
		delete out.h;
		return out;
	}

	function clamp(v, lo, hi) {
		if (!num(v)) return lo;
		return Math.min(Math.max(v, lo), Math.max(lo, hi));
	}

	/**
	 * The standard size of a divider in px: Mitteilungen 40 % of the room (380–520 px), the details of Notizen
	 * 520 px while a note is open, else 460; the others their fixed one. `room`: the space the pane and the other
	 * side share (px), for h the height of both.
	 */
	function standard(key, { room = 0, note = false } = {}) {
		const lim = LIMITS[key];
		if (!lim) return 0;
		if (key === 'inbox.w.list') return clamp(Math.round(room * lim.def), lim.defMin, lim.defMax);
		if (key === 'notes.w.detail' && note) return lim.defNote;
		if (parseKey(key).path[0] === 'h') return Math.round(room * lim.def);
		return lim.def;
	}

	/**
	 * What the pane may be now (px): { min, max } of its limits, the maximum lowered so the other side keeps its
	 * least (`room`: the space both share, px). For h the limits are shares of `room`.
	 */
	function bounds(key, room) {
		const lim = LIMITS[key];
		if (!lim) return { min: 0, max: 0 };
		const h = parseKey(key).path[0] === 'h';
		const min = h ? Math.round(lim.min * room) : lim.min;
		let max = h ? Math.round(lim.max * room) : lim.max;
		if (lim.keep && num(room) && room > 0) max = Math.min(max, room - lim.keep);
		return { min, max: Math.max(min, max) };
	}

	/**
	 * The size shown (px): the stored one (h: its share of `room`) or the standard, within the bounds — the window
	 * limits it, the stored value stays as it is. → { px, limited } (limited: the window took something away).
	 */
	function shown(key, stored, room, opts) {
		const b = bounds(key, room);
		const h = parseKey(key) && parseKey(key).path[0] === 'h';
		const want = stored === null || stored === undefined ? standard(key, { ...(opts || {}), room }) : (h ? stored * room : stored);
		const px = Math.round(clamp(want, b.min, b.max));
		return { px, limited: px !== Math.round(want) };
	}

	/** The value to store for a size in px (h: the share of `room`). */
	function toStored(key, px, room) {
		const k = parseKey(key);
		if (!k) return null;
		if (k.path[0] !== 'h') return Math.round(px);
		return room > 0 ? clamp(px / room, LIMITS[key].min, LIMITS[key].max) : null;
	}

	/**
	 * A key on a focused divider → the new size (px) or null (not a key of the divider). `end`: the pane is on the
	 * far side (details on the right): → makes it narrower. `h`: the divider lies across (↑ ↓).
	 * 'reset' for Eingabe (the standard size).
	 */
	function keyStep(e, cur, b, { end = false, h = false } = {}) {
		const key = e && e.key;
		const step = e && e.shiftKey ? STEP_BIG : STEP;
		const grow = h ? 'ArrowDown' : (end ? 'ArrowLeft' : 'ArrowRight');
		const shrink = h ? 'ArrowUp' : (end ? 'ArrowRight' : 'ArrowLeft');
		if (key === grow) return clamp(cur + step, b.min, b.max);
		if (key === shrink) return clamp(cur - step, b.min, b.max);
		if (key === 'Home') return b.min;
		if (key === 'End') return b.max;
		if (key === 'Enter') return 'reset';
		return null;
	}

	/** Where a drag would put the pane (px): its size at the start plus the way of the pointer (end: the other way). */
	function dragSize(start, delta, { end = false } = {}) {
		return start + (end ? -delta : delta);
	}

	/** The badge while dragging: "412 px" / "42 %", at a limit "Mindestbreite 300 px" (t: the app's texts). */
	function badgeText(key, px, b, room, t, atLimit) {
		const h = parseKey(key) && parseKey(key).path[0] === 'h';
		const value = h ? `${Math.round((px / (room || 1)) * 100)} %` : `${Math.round(px)} px`;
		if (!atLimit) return value;
		const which = px <= b.min ? 'min' : 'max';
		return t(`layout.split.${h ? 'h' : 'w'}.${which}`, { value });
	}

	return {
		PREFIX, PAGES, LIMITS, STEP, STEP_BIG,
		parseKey, storageKey, readPage, sizeOf, withSize, withoutSizes,
		clamp, standard, bounds, shown, toStored, keyStep, dragSize, badgeText,
	};
});
