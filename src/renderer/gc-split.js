/**
 * GateControl -- the dividers between the columns (renderer, GCSplit)
 *
 * One building block for Mail, Mitteilungen and Notizen & Aufgaben: a 1 px
 * line as before; on hover (after 150 ms) a green line with a grip and a tip
 * ("Ziehen: Breite ändern"), while dragging a thicker line with the size in
 * px (the height of Mail's list in %), at its least / most the line turns
 * yellow and stops. A double click puts the standard size back (animated),
 * the keyboard moves it too (Tab onto the divider, ←/→ 16 px, with Umschalt
 * 64 px, Pos1 / Ende the least / most, Eingabe the standard). Role separator
 * with aria-valuenow/min/max.
 *
 * What was dragged is kept on this PC (gc.layout.<page>, layout-state.js:
 * GCLayoutState). A narrower window limits the size shown (the other side
 * keeps its least), the stored one stays. Without a stored size the standard
 * is shown, limited the same way.
 *
 *   const s = GCSplit.create({ key: 'notes.w.detail', pane, other, end: true, t, label: () => t('…') });
 *   parent.insertBefore(s.el, pane);   // then s.apply() (again when the standard changes)
 *
 * Texts only through textContent / attributes, no markup built from text.
 */
(function (root) {
	'use strict';

	const LS = root.GCLayoutState;
	const groups = new Map();       // parent element → Set of the dividers in it
	const observers = new Map();    // parent element → its ResizeObserver
	let cache = null;               // page → its stored object (read once, written through)

	function store() {
		try { return root.localStorage || null; } catch { return null; }
	}

	function page(name) {
		if (!cache) cache = new Map();
		if (!cache.has(name)) {
			let raw = null;
			try { const s = store(); raw = s ? s.getItem(LS.storageKey(name)) : null; } catch { raw = null; }
			cache.set(name, LS.readPage(raw));
		}
		return cache.get(name);
	}

	function savePage(name, value) {
		if (!cache) cache = new Map();
		cache.set(name, value);
		try {
			const s = store();
			if (!s) return;
			if (Object.keys(value).length) s.setItem(LS.storageKey(name), JSON.stringify(value));
			else s.removeItem(LS.storageKey(name));
		} catch { /* storage unavailable: the size holds for this run */ }
	}

	const reduced = () => { try { return !!(root.matchMedia && root.matchMedia('(prefers-reduced-motion: reduce)').matches); } catch { return false; } };
	const shownEl = (n) => !!n && n.isConnected && !n.hidden && n.getClientRects().length > 0;

	function mk(tag, cls, text) {
		const n = document.createElement(tag);
		if (cls) n.className = cls;
		if (text) n.textContent = text;
		return n;
	}

	/**
	 * @param {object} o
	 * @param {string} o.key - 'mail.w.list' | 'mail.w.folders' | 'mail.h.list' | 'inbox.w.list' | 'notes.w.side' | 'notes.w.detail'
	 * @param {HTMLElement} o.pane - the column that gets wider / narrower (its width, for h its height)
	 * @param {HTMLElement|(() => HTMLElement|null)} [o.other] - the side that gives the room (kept at its least)
	 * @param {boolean} [o.end] - the pane is after the divider (details on the right)
	 * @param {Function} o.t - the app's texts
	 * @param {() => string} o.label - the name for screen readers ("Breite der Details")
	 * @param {() => object} [o.opts] - for the standard size ({ note: true } while a note is open)
	 * @param {(px: number) => void} [o.onChange] - the size changed (dragged, reset, the window)
	 */
	function create(o) {
		const key = o.key;
		const k = LS.parseKey(key);
		if (!k) throw new Error(`GCSplit: unknown key ${key}`);
		const h = k.path[0] === 'h';
		const end = !!o.end;
		const t = o.t || ((x) => x);
		const prop = h ? 'height' : 'width';

		const line = mk('span', 'gc-line');
		const grip = mk('span', 'gc-grip');
		grip.append(mk('i'));
		const tip = mk('span', 'gc-tip');
		const tipMain = mk('span', 'gc-tip-main');
		const tipSub = mk('span', 'gc-tip-sub');
		tip.append(tipMain, tipSub);
		tip.setAttribute('aria-hidden', 'true');
		const handle = mk('div', `gc-split${h ? ' is-h' : ''}${end ? ' is-end' : ''}`);
		handle.append(line, grip, tip);
		handle.setAttribute('role', 'separator');
		handle.setAttribute('tabindex', '0');
		handle.setAttribute('aria-orientation', h ? 'horizontal' : 'vertical');
		handle.setAttribute('data-split', key);
		let badge = null;
		let badgeTimer = null;
		let drag = null;
		let px = null;

		const other = () => (typeof o.other === 'function' ? o.other() : o.other) || null;
		const size = (n) => { const r = n.getBoundingClientRect(); return h ? r.height : r.width; };

		/** The space the pane and the other side share (px); 0 while the page is not shown. */
		function room() {
			const parent = handle.parentElement;
			if (!parent || !shownEl(parent)) return 0;
			const ot = other();
			let total = h ? parent.clientHeight : parent.clientWidth;
			for (const c of parent.children) {
				if (c === o.pane || c === ot || !shownEl(c)) continue;
				const pos = root.getComputedStyle ? root.getComputedStyle(c).position : '';
				if (pos === 'absolute' || pos === 'fixed') continue;
				total -= size(c);
			}
			return Math.max(0, total);
		}

		function labels() {
			handle.setAttribute('aria-label', o.label ? o.label() : '');
			tipMain.textContent = t(`layout.split.${h ? 'h' : 'w'}.drag`);
			tipSub.textContent = t(`layout.split.${h ? 'h' : 'w'}.hint`);
		}

		function setSize(v, r, b) {
			px = Math.round(v);
			o.pane.style[prop] = `${px}px`;
			const bb = b || LS.bounds(key, r);
			handle.setAttribute('aria-valuenow', String(px));
			handle.setAttribute('aria-valuemin', String(bb.min));
			handle.setAttribute('aria-valuemax', String(bb.max));
			handle.setAttribute('aria-valuetext', LS.badgeText(key, px, bb, r, t, false));
			if (o.onChange) o.onChange(px);
		}

		function showBadge(text, ms) {
			if (!badge) { badge = mk('span', 'gc-badge'); handle.append(badge); }
			badge.textContent = text;
			clearTimeout(badgeTimer);
			if (ms) badgeTimer = setTimeout(hideBadge, ms);
		}
		function hideBadge() {
			clearTimeout(badgeTimer);
			if (badge) { badge.remove(); badge = null; }
		}

		/** Shows the stored size (or the standard) within what the window allows; stores nothing. */
		function apply() {
			if (drag || !shownEl(handle) || !shownEl(o.pane)) return;
			const r = room();
			if (!r) return;
			const stored = LS.sizeOf(page(k.page), key);
			const s = LS.shown(key, stored, r, o.opts ? o.opts() : {});
			if (s.px !== px || o.pane.style[prop] !== `${s.px}px`) setSize(s.px, r);
		}

		function save(v, r) {
			savePage(k.page, LS.withSize(page(k.page), key, v === null ? null : LS.toStored(key, v, r)));
		}

		function siblings() {
			const set = groups.get(handle.parentElement);
			if (set) for (const s of set) if (s !== api) s.apply();
		}

		/** The reset's animation ends at once: a key or a drag right after it sets the size without easing. */
		let animTimer = null;
		function stopAnim() {
			if (animTimer === null) return;
			clearTimeout(animTimer);
			animTimer = null;
			o.pane.style.transition = '';
		}

		/** Back to the standard size (double click, Eingabe, "Spaltenbreiten zurücksetzen"); animated. */
		function reset({ animate = true } = {}) {
			save(null, 0);
			const r = room();
			if (!r || !shownEl(o.pane)) return;
			const s = LS.shown(key, null, r, o.opts ? o.opts() : {});
			stopAnim();
			if (animate && !reduced()) {
				o.pane.style.transition = `${prop} .18s ease`;
				animTimer = setTimeout(() => { animTimer = null; o.pane.style.transition = ''; siblings(); }, 220);
			}
			setSize(s.px, r);
			if (!animate || reduced()) siblings();
		}

		handle.addEventListener('pointerenter', labels);
		handle.addEventListener('focus', labels);

		handle.addEventListener('pointerdown', (e) => {
			if (e.button !== 0) return;
			e.preventDefault();
			const r = room();
			if (!r) return;
			stopAnim();
			try { handle.setPointerCapture(e.pointerId); } catch { /* not capturable */ }
			drag = { pos: h ? e.clientY : e.clientX, px: size(o.pane), room: r, id: e.pointerId };
			handle.classList.add('is-drag');
			document.documentElement.classList.add('gc-resizing', h ? 'gc-resizing-h' : 'gc-resizing-w');
			showBadge(LS.badgeText(key, drag.px, LS.bounds(key, r), r, t, false));
		});
		handle.addEventListener('pointermove', (e) => {
			if (!drag) return;
			const want = LS.dragSize(drag.px, (h ? e.clientY : e.clientX) - drag.pos, { end });
			const b = LS.bounds(key, drag.room);
			const v = LS.clamp(want, b.min, b.max);
			const limit = want < b.min || want > b.max;
			handle.classList.toggle('is-limit', limit);
			setSize(v, drag.room, b);
			showBadge(LS.badgeText(key, v, b, drag.room, t, limit));
			siblings();
		});
		const stop = () => {
			if (!drag) return;
			const r = drag.room;
			drag = null;
			handle.classList.remove('is-drag', 'is-limit');
			document.documentElement.classList.remove('gc-resizing', 'gc-resizing-h', 'gc-resizing-w');
			hideBadge();
			if (px !== null) save(px, r);
			siblings();
		};
		handle.addEventListener('pointerup', stop);
		handle.addEventListener('pointercancel', stop);
		handle.addEventListener('lostpointercapture', stop);
		handle.addEventListener('dblclick', (e) => { e.preventDefault(); reset(); });
		handle.addEventListener('keydown', (e) => {
			const r = room();
			if (!r) return;
			const b = LS.bounds(key, r);
			const cur = px === null ? size(o.pane) : px;
			const v = LS.keyStep(e, cur, b, { end, h });
			if (v === null) return;
			e.preventDefault();
			e.stopPropagation();
			if (v !== 'reset') stopAnim();
			if (v === 'reset') { reset(); showBadge(LS.badgeText(key, px, b, r, t, false), 1400); return; }
			setSize(v, r, b);
			save(v, r);
			siblings();
			showBadge(LS.badgeText(key, v, b, r, t, v <= b.min || v >= b.max), 1400);
		});
		handle.addEventListener('blur', hideBadge);

		const api = {
			el: handle,
			key,
			apply,
			reset,
			relabel: labels,
			/** The size shown now (px) or null. */
			get size() { return px; },
			/** Put into the page (after the pane, or before it for `end`) and watched with its parent. */
			attach() {
				const parent = handle.parentElement;
				if (!parent) return api;
				if (!groups.has(parent)) groups.set(parent, new Set());
				groups.get(parent).add(api);
				if (!observers.has(parent) && typeof ResizeObserver === 'function') {
					const ro = new ResizeObserver(() => { for (const s of groups.get(parent) || []) s.apply(); });
					ro.observe(parent);
					observers.set(parent, ro);
				}
				labels();
				apply();
				return api;
			},
		};
		return api;
	}

	/** Forgets what was read (the tests; another window changed the storage). */
	function forget() { cache = null; }

	/** The sizes of a page removed and its dividers back to the standard (Mail: "Spaltenbreiten zurücksetzen"). */
	function resetPage(name) {
		savePage(name, LS.withoutSizes(page(name)));
		for (const set of groups.values()) for (const s of set) if (s.key.startsWith(`${name}.`)) s.reset({ animate: false });
	}

	/** The stored layout of a page (Mail's settings beside the sizes) and to change it. */
	function getPage(name) { return { ...page(name) }; }
	function setPage(name, value) { savePage(name, value || {}); }

	if (typeof root.addEventListener === 'function') {
		// another window of the app changed the layout: read again
		root.addEventListener('storage', (e) => { if (e && typeof e.key === 'string' && e.key.startsWith(LS.PREFIX)) forget(); });
	}

	root.GCSplit = { create, forget, resetPage, getPage, setPage };
})(typeof self !== 'undefined' ? self : this);
