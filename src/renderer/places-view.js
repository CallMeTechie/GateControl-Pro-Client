/**
 * GateControl -- Meine Orte (renderer view of „Mein Profil › Meine Orte“, GateControl ≥ 1.299)
 *
 * - The page: the list on the left — the own places with „Genutzt von“ and „kein Standort“, below them Familie's
 *   places only to look at (from chat.pickPlaces(), source 'familie') —, the map on the right (OpenStreetMap tiles over
 *   places.mapTile, every place with its radius as a circle). A place opens the editor in place of the map: name, the
 *   seven symbols, the radius (50–2000 m in steps of 50), who sees it („Familie“ only in a family), the address search
 *   („Suchen“ / Enter, with the attribution; while the server's search is off this PC's answers), a click on the map
 *   sets the point and asks its address (places.mapReverse). A change sends only what differs (diffBody). Deleting a
 *   place in use shows who uses it and deletes it only on „Trotzdem löschen“ (force).
 * - picker(): the one place choice of the forms (Chats: the place of an event) — three chips plus „Alle Orte…“, the
 *   sheet with „Zuletzt genutzt“, „In der Nähe“ (from the chosen place or „Zuhause“: this PC has no position), A–Z, the
 *   local search and address hits („Als Ort speichern?“). Familie's places have the blue symbol.
 *
 * Windows watches no place (the phone does): the push event `places` and a reconnect only load the page again
 * (places.onChanged).
 *
 * Data: window.gatecontrol.places (core PlacesService over IPC); logic without DOM: places-state.js
 * (window.GCPlacesState); the map's arithmetic: chat-state.js (window.GCChatState: worldPx, tileGrid, …).
 * Server text only goes into textContent / attributes; icons are built from static path data (no innerHTML).
 */
(function (root) {
	'use strict';

	const PS = root.GCPlacesState;
	const NS = 'http://www.w3.org/2000/svg';
	const ICONS = {
		home: 'M3 11l9-7 9 7v9H3z|M9 20v-6h6v6',
		work: 'M3 8h18v12H3z|M8 8V5h8v3|M3 13h18',
		school: 'M2 9l10-5 10 5-10 5z|M6 11v5c3 2 9 2 12 0v-5',
		gym: 'M6 7v10|M18 7v10|M3 10v4|M21 10v4|M6 12h12',
		shop: 'M3 4h2l2.4 11h10.2L20 8H6.2|M9 20h.01|M17 20h.01',
		family: 'M9 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z|M2.5 20a6.5 6.5 0 0 1 13 0|M16 4.3a3.5 3.5 0 0 1 0 6.4|M18 14.2a6.5 6.5 0 0 1 3.5 5.8',
		pin: 'M12 21s7-6.2 7-11a7 7 0 0 0-14 0c0 4.8 7 11 7 11z|M12 12a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z',
		refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8|M21 3v5h-5',
		plus: 'M12 5v14|M5 12h14',
		minus: 'M5 12h14',
		trash: 'M3 6h18|M8 6V4h8v2|M6 6l1 14h10l1-14',
		search: 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z|M21 21l-4.3-4.3',
		x: 'M18 6 6 18|M6 6l12 12',
		alert: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 8v5M12 16h.01',
		list: 'M4 6h16|M4 12h16|M4 18h10',
		back: 'M15 6l-6 6 6 6',
		chevron: 'M9 6l6 6-6 6',
	};

	function icon(name, size = 16, stroke = '2') {
		const s = document.createElementNS(NS, 'svg');
		s.setAttribute('viewBox', '0 0 24 24');
		s.setAttribute('width', String(size));
		s.setAttribute('height', String(size));
		s.setAttribute('fill', 'none');
		s.setAttribute('stroke', 'currentColor');
		s.setAttribute('stroke-width', stroke);
		s.setAttribute('stroke-linecap', 'round');
		s.setAttribute('stroke-linejoin', 'round');
		s.setAttribute('aria-hidden', 'true');
		for (const d of String(ICONS[name] || ICONS.pin).split('|')) {
			const p = document.createElementNS(NS, 'path');
			p.setAttribute('d', d);
			s.appendChild(p);
		}
		return s;
	}

	/** el('div', { class, text, on: { click }, attrs… }, [children]) — text only via textContent. */
	function el(tag, attrs, kids) {
		const n = document.createElement(tag);
		for (const [k, v] of Object.entries(attrs || {})) {
			if (v === null || v === undefined || v === false) continue;
			if (k === 'text') n.textContent = String(v);
			else if (k === 'class') n.className = v;
			else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
			else n.setAttribute(k, v === true ? '' : String(v));
		}
		for (const c of kids || []) if (c !== null && c !== undefined && c !== false && c !== '') n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
		return n;
	}
	const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };
	const ok = (r) => !!r && r.ok !== false;
	const iconBtn = (name, label, onClick, extra = {}) => el('button', { type: 'button', class: `mo-ib${extra.cls ? ` ${extra.cls}` : ''}`, title: label, 'aria-label': label, ...extra.attrs, on: { click: onClick } }, [icon(name, extra.size || 16)]);

	/** The symbol of a place in its round badge (Familie's blue). */
	function badge(o, size = 30) {
		return el('span', { class: `mo-badge${o && o.familie ? ' is-familie' : ''}${o && o.hasPoint === false ? ' is-nopoint' : ''}`, style: `width:${size}px;height:${size}px`, 'aria-hidden': 'true' }, [icon(PS.iconOf(o && o.icon), Math.round(size * 0.55))]);
	}

	// ── Map (OpenStreetMap tiles of the main process; Web Mercator of chat-state.js) ──

	const tileCaches = new WeakMap(); // tile function → Map('z/x/y' → Promise<objectURL|null>)
	const TILE_CACHE_MAX = 384;

	function tileUrl(tile, z, x, y) {
		let cache = tileCaches.get(tile);
		if (!cache) { cache = new Map(); tileCaches.set(tile, cache); }
		const key = `${z}/${x}/${y}`;
		let p = cache.get(key);
		if (p) { cache.delete(key); cache.set(key, p); return p; }
		p = Promise.resolve(tile(z, x, y))
			.then((r) => (r && r.ok !== false && r.data ? URL.createObjectURL(new Blob([r.data], { type: r.mime || 'image/png' })) : null))
			.catch(() => null);
		cache.set(key, p);
		p.then((u) => { if (!u && cache.get(key) === p) cache.delete(key); });
		while (cache.size > TILE_CACHE_MAX) {
			const [k, old] = cache.entries().next().value;
			cache.delete(k);
			old.then((u) => { if (u) setTimeout(() => URL.revokeObjectURL(u), 5000); });
		}
		return p;
	}

	/**
	 * A slippy map with places and their radius as circles.
	 * mo: { tile(z, x, y), t, lat, lon, zoom, height, interactive?, onPick?(lat, lon), onMark?(key), label? }
	 * → { el, center(lat, lon, zoom?), fit(points), marks([{ key, lat, lon, radiusM, icon, familie, active, title }]) }
	 */
	function placeMap(mo) {
		const CS = root.GCChatState;
		const t = mo.t;
		let z = CS.clampZoom(mo.zoom || 5);
		let c = CS.worldPx(mo.lat, mo.lon, z);
		let marks = [];
		const imgs = new Map();
		const layer = el('div', { class: 'cv-map-tiles' });
		const over = el('div', { class: 'mo-map-over' });
		const box = el('div', { class: `cv-map mo-map${mo.interactive ? ' is-live' : ''}`, style: `height:${mo.height}px`, 'data-map': mo.interactive ? 'pick' : 'overview' }, [layer, over]);
		const size = () => ({ w: box.clientWidth || 0, h: box.clientHeight || mo.height || 0 });
		let raf = 0;
		const schedule = () => { if (!raf) raf = requestAnimationFrame(draw); };
		const resetTiles = () => { for (const img of imgs.values()) img.remove(); imgs.clear(); };
		const clampY = () => { const n = CS.TILE * 2 ** z; c = { x: c.x, y: Math.max(0, Math.min(n, c.y)) }; };
		let pendingFit = null;

		function draw() {
			raf = 0;
			const { w, h } = size();
			if (!w || !h) return;
			if (pendingFit) { const f = pendingFit; pendingFit = null; doFit(f, w, h); }
			const want = new Set();
			for (const tl of CS.tileGrid(c.x, c.y, z, w, h)) {
				want.add(tl.key);
				let img = imgs.get(tl.key);
				if (!img) {
					img = el('img', { class: 'cv-map-tile', alt: '', draggable: 'false' });
					imgs.set(tl.key, img);
					layer.appendChild(img);
					const mine = img;
					tileUrl(mo.tile, tl.z, tl.x, tl.y).then((u) => { if (u && imgs.get(tl.key) === mine) mine.src = u; });
				}
				img.style.transform = `translate(${tl.left}px, ${tl.top}px)`;
			}
			for (const [k, img] of imgs) if (!want.has(k)) { img.remove(); imgs.delete(k); }
			clear(over);
			for (const m of marks) {
				const p = CS.worldPx(m.lat, m.lon, z);
				const x = Math.round(p.x - c.x + w / 2);
				const y = Math.round(p.y - c.y + h / 2);
				const r = Number.isFinite(m.radiusM) ? m.radiusM / CS.metersPerPx(m.lat, z) : 0;
				const cls = `${m.familie ? ' is-familie' : ''}${m.active ? ' is-active' : ''}`;
				if (r >= 4) over.appendChild(el('div', { class: `mo-map-circle${cls}`, style: `width:${Math.round(r * 2)}px;height:${Math.round(r * 2)}px;transform:translate(${Math.round(x - r)}px, ${Math.round(y - r)}px)` }));
				const pin = el(mo.onMark ? 'button' : 'div', {
					class: `mo-map-pin${cls}`, style: `transform:translate(${x}px, ${y}px)`, 'data-mark': m.key,
					...(mo.onMark ? { type: 'button', title: m.title || '', 'aria-label': m.title || '', on: { click: (e) => { e.stopPropagation(); mo.onMark(m.key); } } } : { 'aria-hidden': 'true' }),
				}, [icon(PS.iconOf(m.icon), 14, '2.2')]);
				over.appendChild(pin);
			}
		}

		function zoomAt(dz, px, py) {
			const nz = CS.clampZoom(z + dz);
			if (nz === z) return;
			const { w, h } = size();
			const ox = px === undefined ? 0 : px - w / 2;
			const oy = py === undefined ? 0 : py - h / 2;
			const k = 2 ** (nz - z);
			c = { x: (c.x + ox) * k - ox, y: (c.y + oy) * k - oy };
			z = nz;
			clampY();
			resetTiles();
			schedule();
		}

		function doFit(points, w, h) {
			const pts = points.filter((p) => PS.hasPoint(p.lat, p.lon));
			if (!pts.length) return;
			let best = CS.clampZoom(pts.length === 1 ? 15 : 17);
			for (let zz = best; zz >= 2; zz--) {
				const px = pts.map((p) => CS.worldPx(p.lat, p.lon, zz));
				const xs = px.map((p) => p.x);
				const ys = px.map((p) => p.y);
				best = zz;
				if (Math.max(...xs) - Math.min(...xs) <= w - 80 && Math.max(...ys) - Math.min(...ys) <= h - 80) break;
			}
			if (best !== z) { z = best; resetTiles(); }
			const px = pts.map((p) => CS.worldPx(p.lat, p.lon, z));
			c = { x: (Math.min(...px.map((p) => p.x)) + Math.max(...px.map((p) => p.x))) / 2, y: (Math.min(...px.map((p) => p.y)) + Math.max(...px.map((p) => p.y))) / 2 };
		}

		const pickAt = (px, py) => {
			if (!mo.onPick) return;
			const { w, h } = size();
			const p = CS.lonLat(c.x - w / 2 + px, c.y - h / 2 + py, z);
			mo.onPick(p.lat, p.lon);
		};

		box.setAttribute('tabindex', '0');
		box.setAttribute('role', 'application');
		box.setAttribute('aria-label', mo.label || t('places.map'));
		box.appendChild(el('div', { class: 'cv-map-zoom' }, [
			iconBtn('plus', t('places.zoomIn'), (e) => { e.stopPropagation(); zoomAt(1); }, { cls: 'mo-ib-sm' }),
			iconBtn('minus', t('places.zoomOut'), (e) => { e.stopPropagation(); zoomAt(-1); }, { cls: 'mo-ib-sm' }),
		]));
		let drag = null;
		box.addEventListener('pointerdown', (e) => {
			if (e.button !== 0 || (e.target.closest && e.target.closest('button'))) return;
			drag = { id: e.pointerId, x: e.clientX, y: e.clientY, moved: false };
			try { box.setPointerCapture(e.pointerId); } catch { /* pointer gone */ }
		});
		box.addEventListener('pointermove', (e) => {
			if (!drag || e.pointerId !== drag.id) return;
			const dx = e.clientX - drag.x;
			const dy = e.clientY - drag.y;
			if (!drag.moved && Math.abs(dx) + Math.abs(dy) < 5) return;
			drag.moved = true;
			box.classList.add('is-drag');
			c = { x: c.x - dx, y: c.y - dy };
			clampY();
			drag.x = e.clientX;
			drag.y = e.clientY;
			schedule();
		});
		const end = (e) => {
			if (!drag || e.pointerId !== drag.id) return;
			const click = !drag.moved && e.type === 'pointerup';
			drag = null;
			box.classList.remove('is-drag');
			if (click && mo.interactive) { const r = box.getBoundingClientRect(); pickAt(e.clientX - r.left, e.clientY - r.top); }
		};
		box.addEventListener('pointerup', end);
		box.addEventListener('pointercancel', end);
		box.addEventListener('wheel', (e) => {
			e.preventDefault();
			const r = box.getBoundingClientRect();
			zoomAt(e.deltaY < 0 ? 1 : -1, e.clientX - r.left, e.clientY - r.top);
		}, { passive: false });
		box.addEventListener('keydown', (e) => {
			if (e.target !== box) return;
			const step = 96;
			const moves = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] };
			if (moves[e.key]) { e.preventDefault(); c = { x: c.x + moves[e.key][0], y: c.y + moves[e.key][1] }; clampY(); schedule(); }
			else if (e.key === '+' || e.key === '=') { e.preventDefault(); zoomAt(1); }
			else if (e.key === '-') { e.preventDefault(); zoomAt(-1); }
			else if (mo.interactive && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); const { w, h } = size(); pickAt(w / 2, h / 2); }
		});
		box.appendChild(el('span', { class: 'cv-map-attr', text: t('places.osm') }));
		if (typeof ResizeObserver === 'function') new ResizeObserver(() => schedule()).observe(box);
		schedule();

		return {
			el: box,
			center(lat, lon, zoom) {
				if (zoom !== undefined && CS.clampZoom(zoom) !== z) { z = CS.clampZoom(zoom); resetTiles(); }
				c = CS.worldPx(lat, lon, z);
				schedule();
			},
			fit(points) { pendingFit = points; schedule(); },
			marks(list) { marks = (list || []).filter((m) => PS.hasPoint(m.lat, m.lon)); schedule(); },
		};
	}

	const DEFAULT_VIEW = { lat: 51.1657, lon: 10.4515, zoom: 5 };

	// ── A small modal (above the chats' dialogs) ─────────

	/**
	 * modal({ title, body: [nodes], actions: [{ label, cls, act, value, onClick }], dialog, cls, ref }) → Promise<value | null>.
	 * `ref.close(value)` closes it from outside.
	 */
	function modal(o) {
		return new Promise((resolve) => {
			const prev = document.activeElement;
			const titleId = `mo-dlg-${Math.random().toString(36).slice(2, 8)}`;
			const box = el('div', { class: `mo-dlg${o.cls ? ` ${o.cls}` : ''}`, role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId, tabindex: '-1', 'data-dialog': o.dialog || null });
			const scrim = el('div', { class: 'mo-scrim' }, [box]);
			let done = false;
			const close = (v) => {
				if (done) return;
				done = true;
				scrim.remove();
				if (prev && prev.isConnected && prev.focus) { try { prev.focus(); } catch { /* gone */ } }
				resolve(v === undefined ? null : v);
			};
			if (o.ref) o.ref.close = close;
			scrim.addEventListener('mousedown', (e) => { if (e.target === scrim) close(null); });
			scrim.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(null); } });
			const err = el('div', { class: 'mo-dlg-err', role: 'alert', hidden: true });
			box.append(
				el('h2', { id: titleId, class: 'mo-dlg-h', text: o.title }),
				...(o.body || []),
				err,
				el('div', { class: 'mo-dlg-acts' }, (o.actions || []).map((a) => el('button', {
					type: 'button', class: `btn btn-sm ${a.cls || 'btn-ghost'}`, 'data-act': a.act || null, text: a.label,
					on: { click: async (e) => {
						if (!a.onClick) { close(a.value); return; }
						const btn = e.currentTarget;
						btn.disabled = true;
						const r = await a.onClick();
						btn.disabled = false;
						if (typeof r === 'string') { err.textContent = r; err.hidden = false; return; }
						if (r !== false) close(r === true || r === undefined ? a.value : r);
					} },
				}))),
			);
			document.body.appendChild(scrim);
			setTimeout(() => { const f = box.querySelector('input, .btn-pri') || box; f.focus(); }, 0);
		});
	}

	/** The list „Genutzt von“ as rows. */
	function usedByList(usedBy, t) {
		const lines = PS.usedByLines(usedBy, t);
		return el('ul', { class: 'mo-used', 'data-list': 'used-by' }, lines.map((l) => el('li', { 'data-plugin': l.plugin, text: l.text })));
	}

	/**
	 * Delete a place: the question, then — in use — who uses it and „Trotzdem löschen“ (force).
	 * `remove(id, { force })` → the answer of places.remove / notes.deletePlace. → true when it is gone.
	 */
	async function deleteFlow({ place, remove, t, errorText }) {
		const yes = await modal({
			title: t('places.deleteQ', { name: place.name }), dialog: 'place-delete',
			body: [el('p', { class: 'mo-dlg-p', text: t('places.deleteText') })],
			actions: [{ label: t('places.cancel'), value: false }, { label: t('places.delete'), cls: 'btn-danger', act: 'delete-yes', value: true }],
		});
		if (yes !== true) return false;
		let r = await Promise.resolve(remove(place.id, { force: false })).catch((e) => ({ ok: false, error: e && e.message }));
		if (r && r.ok === false && r.code === 'in_use') {
			const force = await modal({
				title: t('places.inUseTitle'), dialog: 'place-in-use',
				body: [
					el('p', { class: 'mo-dlg-p', text: t('places.inUseText', { name: place.name }) }),
					usedByList(r.usedBy, t),
					el('p', { class: 'mo-dlg-p hint', text: t('places.inUseAfter') }),
				],
				actions: [{ label: t('places.cancel'), value: false }, { label: t('places.deleteForce'), cls: 'btn-danger', act: 'delete-force', value: true }],
			});
			if (force !== true) return false;
			r = await Promise.resolve(remove(place.id, { force: true })).catch((e) => ({ ok: false, error: e && e.message }));
		}
		if (!ok(r)) return errorText(r);
		return true;
	}

	// ── The page ─────────────────────────────────────────

	/**
	 * @param {object} o
	 * @param {HTMLElement} o.root - the page section (empty)
	 * @param {object} o.api - window.gatecontrol.places
	 * @param {object} [o.chat] - window.gatecontrol.chat (Familie's places of the choice's source)
	 * @param {Function} o.t
	 * @param {() => string} o.getLocale
	 * @param {Function} [o.toast]
	 * @param {Function} [o.onStatus] - ({ state: 'available' | 'unsupported' | 'unknown' }) — the nav entry
	 * @param {Function} [o.openExternal] - the attribution's link
	 * @returns {{ show(), hide(), refresh(), relabel(), status(), open(ctx) }}
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const lang = () => (o.getLocale() === 'en' ? 'en' : 'de');
		const toast = (msg, type) => { if (typeof o.toast === 'function') o.toast(msg, type || 'info'); };

		const S = {
			shown: false,
			list: null,     // answer of api.list()
			pick: null,     // answer of chat.pickPlaces() (Familie's places)
			error: null,    // the last refusal of list()
			loading: false,
			state: 'unknown',
			sel: null,      // null | { kind: 'own', id } | { kind: 'new' } | { kind: 'familie', key }
			retry: null,
			seq: 0,
		};

		// ── Skeleton ─────────────────────────────────────
		const refs = {};
		const rootEl = el('div', { class: 'pv' });
		o.root.appendChild(rootEl);
		refs.h = el('h1', { class: 'mo-h', text: t('places.title') });
		refs.sub = el('span', { class: 'mo-sub' });
		refs.refresh = iconBtn('refresh', t('places.refresh'), () => load(true), { attrs: { 'data-act': 'refresh' } });
		refs.add = el('button', { type: 'button', class: 'btn btn-pri btn-sm mo-add', 'data-act': 'new', on: { click: () => select({ kind: 'new' }) } }, [icon('plus', 15), el('span', { text: t('places.new') })]);
		refs.banner = el('div', { class: 'mo-banner', role: 'status', hidden: true });
		refs.list = el('div', { class: 'mo-list scroll', 'data-pane': 'list' });
		refs.side = el('div', { class: 'mo-side', 'data-pane': 'side' });
		refs.body = el('div', { class: 'mo-body' }, [refs.list, refs.side]);
		refs.state = el('div', { class: 'mo-state', hidden: true });
		rootEl.append(
			el('div', { class: 'mo-head' }, [el('div', { class: 'mo-head-tx' }, [refs.h, refs.sub]), refs.refresh, refs.add]),
			refs.banner, refs.state, refs.body,
		);

		let overview = null; // the map of all places
		let editor = null;   // the open editor: { place, draft, map, … }

		function setState(state) {
			if (state === S.state) return;
			S.state = state;
			if (typeof o.onStatus === 'function') o.onStatus({ state });
		}

		// ── Loading ──────────────────────────────────────

		async function load(refresh = false) {
			const seq = ++S.seq;
			S.loading = true;
			clearTimeout(S.retry);
			if (S.shown) renderHead();
			const [r, pick] = await Promise.all([
				Promise.resolve(api.list({ refresh })).catch((e) => ({ ok: false, code: 'failed', error: e && e.message })),
				S.shown && o.chat && typeof o.chat.pickPlaces === 'function' ? Promise.resolve(o.chat.pickPlaces()).catch(() => null) : Promise.resolve(S.pick),
			]);
			if (seq !== S.seq) return;
			S.loading = false;
			if (ok(r)) {
				S.list = r;
				S.error = null;
				setState('available');
			} else {
				S.error = r;
				if (r && r.code === 'unsupported') { S.list = null; setState('unsupported'); } else {
					setState(S.list ? 'available' : 'unknown');
					// not set up yet, or the server is away: ask again later
					S.retry = setTimeout(() => load(false), 60000);
				}
			}
			S.pick = ok(pick) ? pick : null;
			if (S.sel && S.sel.kind === 'own' && !ownById(S.sel.id)) { closeEditor(); S.sel = null; }
			if (S.shown) render();
		}

		const ownById = (id) => (S.list ? S.list.places.find((p) => p.id === id) || null : null);
		const lists = () => PS.pageLists(S.list, S.pick);

		// ── Rendering ────────────────────────────────────

		function renderHead() {
			const l = S.list ? lists() : null;
			refs.sub.textContent = l ? [PS.plural(t, 'places.count', l.mine.length), l.missing ? PS.plural(t, 'places.missing', l.missing) : null].filter(Boolean).join(' · ') : t('places.sub');
			refs.sub.title = t('places.sub');
			refs.refresh.disabled = S.loading;
			refs.refresh.classList.toggle('is-busy', S.loading);
			refs.add.hidden = !S.list;
			refs.add.disabled = !!(S.list && S.list.places.length >= ((S.list.limits && S.list.limits.places) || 100));
			const banner = S.list && S.list.stale ? t('places.offline') : (l && l.missing ? PS.plural(t, 'places.missingHint', l.missing) : '');
			refs.banner.hidden = !banner;
			refs.banner.textContent = banner;
		}

		function render() {
			renderHead();
			const nothing = !S.list;
			refs.body.hidden = nothing;
			refs.state.hidden = !nothing;
			if (nothing) {
				clear(refs.state);
				if (S.loading || (!S.error && S.state === 'unknown')) refs.state.appendChild(el('p', { class: 'mo-loading', text: t('places.loading') }));
				else if (S.state === 'unsupported') refs.state.append(icon('alert', 28), el('strong', { text: t('places.title') }), el('span', { 'data-state': 'unsupported', text: t('places.unsupported') }));
				else refs.state.append(icon('alert', 28), el('strong', { text: t('places.failed') }), el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('places.retry'), on: { click: () => load(true) } }));
				return;
			}
			renderList();
			if (!editor) renderOverview();
		}

		function row(p, familie) {
			const key = familie ? `f:${p.ref}` : `p:${p.id}`;
			const on = S.sel && ((S.sel.kind === 'own' && !familie && S.sel.id === p.id) || (S.sel.kind === 'familie' && familie && S.sel.key === p.ref));
			const users = familie ? 0 : PS.pluginsUsing(p);
			const sub = familie ? t('places.familieKept') : PS.placeLine(p, t);
			return el('button', { type: 'button', class: `mo-row${on ? ' on' : ''}${familie ? ' is-familie' : ''}`, 'data-place': key, 'aria-current': on ? 'true' : null,
				on: { click: () => select(familie ? { kind: 'familie', key: p.ref } : { kind: 'own', id: p.id }) } }, [
				badge({ icon: p.icon, familie, hasPoint: familie ? true : p.hasPoint }, 32),
				el('span', { class: 'mo-row-tx' }, [el('b', { text: p.name }), el('span', { class: 'mo-row-sub', text: sub })]),
				!familie && !p.hasPoint ? el('span', { class: 'mo-chip is-warn', 'data-mark': 'no-point', text: t('places.noPoint') }) : null,
				users ? el('span', { class: 'mo-chip', 'data-mark': 'used', title: PS.usedByLines(p.usedBy, t).map((x) => x.text).join('\n'), text: PS.plural(t, 'places.usesPlugins', users) }) : null,
			]);
		}

		function renderList() {
			const l = lists();
			clear(refs.list);
			refs.list.appendChild(el('div', { class: 'lbl mo-lbl', 'data-section': 'mine', text: t('places.sectionMine', { n: l.mine.length }) }));
			if (!l.mine.length) refs.list.appendChild(el('p', { class: 'hint mo-empty', 'data-state': 'empty', text: t('places.empty') }));
			for (const p of l.mine) refs.list.appendChild(row(p, false));
			if (l.familie.length) {
				refs.list.appendChild(el('div', { class: 'lbl mo-lbl', 'data-section': 'familie', text: t('places.sectionFamilie') }));
				for (const p of l.familie) refs.list.appendChild(row(p, true));
				refs.list.appendChild(el('p', { class: 'hint mo-foot', text: t('places.familieOnly') }));
			}
		}

		function markList() {
			const l = lists();
			return [
				...l.mine.filter((p) => p.hasPoint).map((p) => ({ key: `p:${p.id}`, lat: p.lat, lon: p.lon, radiusM: p.radiusM, icon: p.icon, title: p.name, active: !!(S.sel && S.sel.kind === 'own' && S.sel.id === p.id) })),
				...l.familie.filter((p) => PS.hasPoint(p.lat, p.lon)).map((p) => ({ key: `f:${p.ref}`, lat: p.lat, lon: p.lon, radiusM: p.radiusM, icon: p.icon, familie: true, title: p.name, active: !!(S.sel && S.sel.kind === 'familie' && S.sel.key === p.ref) })),
			];
		}

		function renderOverview() {
			const marks = markList();
			if (!overview) {
				overview = placeMap({ tile: api.mapTile, t, ...DEFAULT_VIEW, height: 420, label: t('places.mapOverview'), onMark: (key) => {
					if (key.startsWith('p:')) select({ kind: 'own', id: Number(key.slice(2)) });
					else select({ kind: 'familie', key: key.slice(2) });
				} });
			}
			// the first time there is something to show: all of it in view
			if (!overview.fitted && marks.length) { overview.fit(marks); overview.fitted = true; }
			overview.marks(marks);
			clear(refs.side);
			const f = S.sel && S.sel.kind === 'familie' ? lists().familie.find((p) => p.ref === S.sel.key) : null;
			refs.side.append(
				overview.el,
				f ? el('div', { class: 'mo-card', 'data-card': 'familie' }, [
					el('div', { class: 'mo-card-h' }, [badge({ icon: f.icon, familie: true }, 30), el('b', { text: f.name }), el('span', { class: 'mo-grow' }), iconBtn('x', t('places.close'), () => select(null))]),
					el('p', { class: 'hint', text: [t('places.familieKept'), Number.isFinite(f.radiusM) ? t('places.radiusShort', { m: f.radiusM }) : null].filter(Boolean).join(' · ') }),
					el('p', { class: 'hint', text: t('places.familieOnly') }),
				]) : el('p', { class: 'hint mo-foot', text: t('places.sub') }),
			);
		}

		function select(sel) {
			S.sel = sel;
			closeEditor();
			if (sel && (sel.kind === 'own' || sel.kind === 'new')) openEditor(sel.kind === 'new' ? null : ownById(sel.id));
			else {
				renderList();
				renderOverview();
				if (sel && sel.kind === 'familie') {
					const f = lists().familie.find((p) => p.ref === sel.key);
					if (f && PS.hasPoint(f.lat, f.lon)) overview.center(f.lat, f.lon, 15);
				}
			}
		}

		// ── The editor ───────────────────────────────────

		function closeEditor() {
			if (!editor) return;
			clearTimeout(editor.revTimer);
			editor.open = false;
			editor = null;
		}

		function openEditor(place) {
			const limits = (S.list && S.list.limits) || null;
			const ed = { place, draft: PS.draftOf(place, limits), open: true, revSeq: 0, revTimer: null, autoAddr: place ? place.address || '' : '', busy: false };
			editor = ed;
			renderList();
			const d = ed.draft;

			const name = el('input', { class: 'inp', type: 'text', maxlength: String(PS.NAME_MAX), value: d.name, placeholder: t('places.namePh'), 'aria-label': t('places.name'), 'data-f': 'name' });
			name.addEventListener('input', () => { d.name = name.value; });

			const icons = el('div', { class: 'mo-icons', role: 'radiogroup', 'aria-label': t('places.icon') });
			const drawIcons = () => {
				clear(icons);
				for (const ic of PS.ICONS) {
					const on = d.icon === ic;
					icons.appendChild(el('button', { type: 'button', class: `mo-ic${on ? ' on' : ''}`, role: 'radio', 'aria-checked': on ? 'true' : 'false', 'data-icon': ic, title: t(`places.icons.${ic}`), 'aria-label': t(`places.icons.${ic}`),
						on: { click: () => { d.icon = ic; drawIcons(); drawMarks(); } } }, [icon(ic, 18)]));
				}
			};
			drawIcons();

			const radiusLabel = el('span', { class: 'mo-f-l', text: t('places.radius', { m: d.radiusM }) });
			const radius = el('input', { type: 'range', class: 'mo-range', min: String(PS.RADIUS.min), max: String(PS.RADIUS.max), step: String(PS.RADIUS.step), value: String(d.radiusM), 'aria-label': t('places.radius', { m: d.radiusM }), 'data-f': 'radius' });
			radius.addEventListener('input', () => {
				d.radiusM = PS.snapRadius(radius.value, limits);
				radiusLabel.textContent = t('places.radius', { m: d.radiusM });
				radius.setAttribute('aria-label', radiusLabel.textContent);
				drawMarks();
			});

			const vis = el('div', { class: 'seg mo-vis', role: 'radiogroup', 'aria-label': t('places.visibility') });
			const drawVis = () => {
				clear(vis);
				for (const v of PS.visibilityChoices(S.list && S.list.family, place && place.visibility)) {
					const on = d.visibility === v;
					vis.appendChild(el('button', { type: 'button', class: on ? 'on' : '', role: 'radio', 'aria-checked': on ? 'true' : 'false', 'data-vis': v, text: t(`places.vis.${v}`), on: { click: () => { d.visibility = v; drawVis(); } } }));
				}
			};
			drawVis();

			// address search: only on „Suchen“ / Enter
			const q = el('input', { class: 'inp', type: 'search', maxlength: String(PS.SEARCH_MAX), placeholder: t('places.searchPh'), 'aria-label': t('places.searchPh'), 'data-f': 'q', spellcheck: 'false' });
			const searchBtn = el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-act': 'search', on: { click: () => search() } }, [icon('search', 14), el('span', { text: t('places.search') })]);
			const hits = el('div', { class: 'mo-hits', 'data-list': 'hits', hidden: true });
			q.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); search(); } });

			const address = el('input', { class: 'inp', type: 'text', maxlength: String(PS.ADDRESS_MAX), value: d.address, placeholder: t('places.addressPh'), 'aria-label': t('places.address'), 'data-f': 'address' });
			address.addEventListener('input', () => { d.address = address.value; });
			const setAddress = (v, auto) => {
				if (auto && address.value.trim() && address.value !== ed.autoAddr) return;
				address.value = v || '';
				d.address = address.value;
				if (auto) ed.autoAddr = address.value;
			};

			const pointLine = el('p', { class: 'hint mo-point', 'data-state': 'point', role: 'status' });
			const anchor = PS.anchorOf(PS.mergeOptions([], S.list ? S.list.places : []), null);
			const start = PS.hasPoint(d.lat, d.lon) ? { lat: d.lat, lon: d.lon, zoom: 16 } : (anchor ? { ...anchor, zoom: 13 } : DEFAULT_VIEW);
			const map = placeMap({ tile: api.mapTile, t, lat: start.lat, lon: start.lon, zoom: start.zoom, height: 300, interactive: true, label: t('places.mapPick'), onPick: (lat, lon) => setPoint(lat, lon, 'map') });
			ed.map = map;
			function drawMarks() {
				map.marks(PS.hasPoint(d.lat, d.lon) ? [{ key: 'draft', lat: d.lat, lon: d.lon, radiusM: d.radiusM, icon: d.icon, active: true }] : []);
				pointLine.textContent = PS.hasPoint(d.lat, d.lon) ? `${t('places.pointSet')}: ${d.lat.toFixed(5)}, ${d.lon.toFixed(5)}` : t('places.mapHint');
			}
			function setPoint(lat, lon, source, label) {
				d.lat = Math.round(lat * 1e6) / 1e6;
				d.lon = Math.round(lon * 1e6) / 1e6;
				err.hidden = true;
				drawMarks();
				if (source === 'search') { ed.revSeq++; if (label) setAddress(label, true); return; }
				// the address of the point (core: Nominatim, one request per second)
				const seq = ++ed.revSeq;
				clearTimeout(ed.revTimer);
				ed.revTimer = setTimeout(() => {
					if (typeof api.mapReverse !== 'function') return;
					Promise.resolve(api.mapReverse(d.lat, d.lon, lang()))
						.then((r) => { if (ed.open && seq === ed.revSeq && ok(r) && r.label) setAddress(r.label, true); })
						.catch(() => {});
				}, 500);
			}
			drawMarks();

			async function search() {
				const text = q.value.trim();
				hits.hidden = false;
				clear(hits);
				if (!PS.searchable(text)) { hits.appendChild(el('p', { class: 'hint', 'data-state': 'search-min', text: t('places.searchMin') })); return; }
				if (ed.busy) return;
				ed.busy = true;
				searchBtn.disabled = true;
				hits.appendChild(el('p', { class: 'hint', role: 'status', 'data-state': 'searching', text: t('places.searching') }));
				const near = PS.hasPoint(d.lat, d.lon) ? { lat: d.lat, lon: d.lon } : (anchor || undefined);
				const r = await Promise.resolve(api.search(text, near, lang())).catch((e) => ({ ok: false, error: e && e.message }));
				ed.busy = false;
				searchBtn.disabled = false;
				if (!ed.open) return;
				clear(hits);
				if (!ok(r)) { hits.appendChild(el('p', { class: 'mo-err', role: 'alert', 'data-state': 'search-error', text: PS.searchErrorText(r, t) })); return; }
				if (r.via === 'device') hits.appendChild(el('p', { class: 'hint', 'data-state': 'search-device', text: t('places.searchDevice') }));
				if (!r.results.length) hits.appendChild(el('p', { class: 'hint', 'data-state': 'search-none', text: t('places.searchNone') }));
				for (const h of r.results) {
					hits.appendChild(el('button', { type: 'button', class: 'mo-hit', 'data-hit': h.name, on: { click: () => {
						hits.hidden = true;
						if (!name.value.trim()) { name.value = h.name; d.name = h.name; }
						map.center(h.lat, h.lon, 16);
						setPoint(h.lat, h.lon, 'search', h.address || h.name);
					} } }, [icon('pin', 15), el('span', { class: 'mo-hit-tx' }, [el('b', { text: h.name }), h.address ? el('span', { text: h.address }) : null]),
						Number.isFinite(h.distanceM) ? el('span', { class: 'mo-dist', text: PS.distanceText(h.distanceM, lang()) }) : null]));
				}
				hits.appendChild(attribution(r.attribution));
			}

			const err = el('p', { class: 'mo-err', role: 'alert', 'data-state': 'error', hidden: true });
			const fail = (text) => { err.textContent = text; err.hidden = false; };

			async function save() {
				const problem = PS.draftProblem(d);
				if (problem) { fail(t(problem === 'name' ? 'places.nameNeed' : 'places.pointNeed')); return; }
				let r;
				if (!place) r = await Promise.resolve(api.create(PS.createBody(d))).catch((e) => ({ ok: false, error: e && e.message }));
				else {
					const patch = PS.diffBody(place, d);
					if (!Object.keys(patch).length) { toast(t('places.unchanged')); select(null); return; }
					r = await Promise.resolve(api.update(place.id, patch)).catch((e) => ({ ok: false, error: e && e.message }));
				}
				if (!ok(r)) { fail(PS.errorText(r, t, limits)); return; }
				toast(t('places.saved'), 'success');
				S.sel = null;
				closeEditor();
				await load(false);
			}

			async function remove() {
				const r = await deleteFlow({ place, t, remove: (id, opts) => api.remove(id, opts), errorText: (x) => PS.errorText(x, t, limits) });
				if (r === true) { toast(t('places.deleted'), 'success'); S.sel = null; closeEditor(); await load(false); } else if (typeof r === 'string') fail(r);
			}

			const field = (label, node, attrs) => el('div', { class: 'mo-f', ...(attrs || {}) }, [typeof label === 'string' ? el('span', { class: 'mo-f-l', text: label }) : label, node]);
			clear(refs.side);
			refs.side.appendChild(el('div', { class: 'mo-ed', 'data-editor': place ? String(place.id) : 'new' }, [
				el('div', { class: 'mo-ed-h' }, [
					iconBtn('back', t('places.close'), () => select(null), { attrs: { 'data-act': 'close' } }),
					el('h2', { class: 'mo-ed-title', text: place ? t('places.edit') : t('places.new') }),
					el('span', { class: 'mo-grow' }),
					place ? iconBtn('trash', t('places.delete'), () => remove(), { cls: 'is-danger', attrs: { 'data-act': 'delete' } }) : null,
				]),
				field(t('places.name'), name),
				field(t('places.icon'), icons),
				field(t('places.searchPh'), el('div', { class: 'mo-search' }, [q, searchBtn])),
				hits,
				map.el,
				pointLine,
				field(t('places.address'), address),
				field(radiusLabel, radius),
				field(t('places.visibility'), vis),
				place ? el('div', { class: 'mo-f', 'data-box': 'used-by' }, [el('span', { class: 'mo-f-l', text: t('places.usedBy') }),
					PS.usedByLines(place.usedBy, t).length ? usedByList(place.usedBy, t) : el('p', { class: 'hint', text: t('places.usedNone') })]) : null,
				place && !place.hasPoint ? el('p', { class: 'mo-note is-warn', 'data-state': 'no-point', text: t('places.noPointDetail') }) : null,
				place ? el('p', { class: 'hint', text: t('places.detailHint') }) : null,
				err,
				el('div', { class: 'mo-acts' }, [
					el('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'data-act': 'cancel', text: t('places.cancel'), on: { click: () => select(null) } }),
					el('button', { type: 'button', class: 'btn btn-pri btn-sm', 'data-act': 'save', text: t('places.save'), on: { click: () => save() } }),
				]),
			]));
			setTimeout(() => { if (ed.open) name.focus(); }, 0);
		}

		function attribution(a) {
			const at = a || { text: t('places.osm'), url: null };
			return el('p', { class: 'hint mo-attr', 'data-state': 'attribution' }, [
				at.url && typeof o.openExternal === 'function'
					? el('button', { type: 'button', class: 'mo-link', text: at.text, on: { click: () => o.openExternal(at.url) } })
					: el('span', { text: at.text }),
			]);
		}

		// ── Events ───────────────────────────────────────

		if (typeof api.onChanged === 'function') api.onChanged(() => load(false));
		load(false);

		return {
			show() { S.shown = true; render(); load(false); },
			hide() { S.shown = false; },
			refresh() { return load(true); },
			status() { return { state: S.state }; },
			relabel() {
				refs.h.textContent = t('places.title');
				refs.refresh.title = t('places.refresh');
				refs.refresh.setAttribute('aria-label', t('places.refresh'));
				refs.add.lastChild.textContent = t('places.new');
				if (S.shown && !editor) { overview = null; render(); }
			},
			/** { id } opens that place, { new: true } a new one. */
			open(ctx) {
				if (ctx && ctx.new) select({ kind: 'new' });
				else if (ctx && Number.isSafeInteger(ctx.id) && ownById(ctx.id)) select({ kind: 'own', id: ctx.id });
			},
		};
	}

	// ── The place choice of the forms ────────────────────

	/**
	 * Three chips plus „Alle Orte…“ and the sheet.
	 * @param {object} o
	 * @param {Function} o.t
	 * @param {() => string} o.getLocale
	 * @param {Array} o.options - PS.mergeOptions(…)
	 * @param {object} [o.selected] - the choice that stands
	 * @param {object} [o.api] - window.gatecontrol.places (address search, „Als Ort speichern?“); null: local only
	 * @param {Function} o.onChange - (option | null)
	 * @param {Function} [o.openExternal]
	 * @returns {{ el, selected(), set(option | null) }}
	 */
	function picker(o) {
		const t = o.t;
		const lang = () => (o.getLocale() === 'en' ? 'en' : 'de');
		let options = (o.options || []).slice();
		let selected = o.selected || null;
		const box = el('div', { class: 'mo-pick', 'data-picker': 'places' });

		function set(opt, notify = true) {
			selected = opt || null;
			draw();
			if (notify && typeof o.onChange === 'function') o.onChange(selected);
		}

		function draw() {
			clear(box);
			const here = PS.anchorOf(options, selected);
			for (const c of PS.chips(options, selected, here)) {
				const on = !!selected && selected.key === c.key;
				box.appendChild(el('button', { type: 'button', class: `mo-pchip${on ? ' on' : ''}${c.familie ? ' is-familie' : ''}`, 'aria-pressed': on ? 'true' : 'false', 'data-ref': c.ref || c.key, title: PS.sourceLine(c, t),
					on: { click: () => set(on ? null : c) } }, [icon(c.icon, 14), el('span', { text: c.name })]));
			}
			box.appendChild(el('button', { type: 'button', class: 'mo-pchip is-all', 'data-act': 'all', on: { click: () => sheet() } }, [icon('list', 14), el('span', { text: t('places.all') })]));
		}

		/** The sheet „Alle Orte…“: groups, the local search, addresses on „Suchen“. → the choice (or null). */
		function sheet() {
			const q = el('input', { class: 'inp', type: 'search', maxlength: String(PS.SEARCH_MAX), placeholder: t('places.pickSearch'), 'aria-label': t('places.pickSearch'), 'data-f': 'pick-q', spellcheck: 'false' });
			const go = el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-act': 'pick-search', disabled: !o.api }, [icon('search', 14), el('span', { text: t('places.search') })]);
			const list = el('div', { class: 'mo-sheet-list scroll', 'data-list': 'pick' });
			const st = { hits: null, attribution: null, via: null, error: null, busy: false };
			let close = null;

			const optRow = (x, here) => {
				const on = !!selected && selected.key === x.key;
				const d = PS.distanceOf(x, here);
				return el('button', { type: 'button', class: `mo-opt${on ? ' on' : ''}${x.familie ? ' is-familie' : ''}`, 'data-ref': x.ref || x.key, on: { click: () => choose(x) } }, [
					badge(x, 28),
					el('span', { class: 'mo-opt-tx' }, [el('b', { text: x.name }), el('span', { text: PS.sourceLine(x, t) })]),
					on ? el('span', { class: 'mo-chip', text: t('places.pickSelected') }) : null,
					d !== null && d > 0 ? el('span', { class: 'mo-dist', text: PS.distanceText(d, lang()) }) : null,
				]);
			};
			const head = (text, kind) => el('div', { class: 'lbl mo-lbl', 'data-group': kind, text });

			function drawList() {
				clear(list);
				const here = PS.anchorOf(options, selected);
				const text = q.value.trim();
				if (!text) {
					if (!options.length) list.appendChild(el('p', { class: 'hint', text: t('places.pickNone') }));
					for (const g of PS.groups(options, here)) {
						list.appendChild(head(g.kind === 'letter' ? g.letter : (g.kind === 'near' && here ? `${t('places.group.near')} · ${here.name}` : t(`places.group.${g.kind}`)), g.kind === 'letter' ? `letter:${g.letter}` : g.kind));
						for (const x of g.items) list.appendChild(optRow(x, here));
					}
					return;
				}
				const local = PS.search(options, text, here);
				list.appendChild(head(t('places.group.mine'), 'mine'));
				if (!local.length) list.appendChild(el('p', { class: 'hint', 'data-state': 'local-none', text: t('places.pickLocalNone') }));
				for (const x of local) list.appendChild(optRow(x, here));
				if (st.busy) list.appendChild(el('p', { class: 'hint', role: 'status', text: t('places.searching') }));
				else if (st.error) list.appendChild(el('p', { class: 'mo-err', role: 'alert', text: st.error }));
				else if (st.hits) {
					list.appendChild(head(t('places.group.addresses'), 'addresses'));
					if (st.via === 'device') list.appendChild(el('p', { class: 'hint', 'data-state': 'search-device', text: t('places.searchDevice') }));
					const fresh = PS.newHits(st.hits, options);
					if (!fresh.length) list.appendChild(el('p', { class: 'hint', text: t('places.searchNone') }));
					for (const h of fresh) {
						const x = PS.hitOption(h);
						if (!x) continue;
						list.appendChild(el('button', { type: 'button', class: 'mo-opt is-hit', 'data-hit': h.name, on: { click: () => askSave(x) } }, [
							badge(x, 28), el('span', { class: 'mo-opt-tx' }, [el('b', { text: x.name }), el('span', { text: PS.sourceLine(x, t) })]),
							Number.isFinite(h.distanceM) ? el('span', { class: 'mo-dist', text: PS.distanceText(h.distanceM, lang()) }) : null,
						]));
					}
					list.appendChild(el('p', { class: 'hint mo-attr', 'data-state': 'attribution' }, [
						st.attribution && st.attribution.url && typeof o.openExternal === 'function'
							? el('button', { type: 'button', class: 'mo-link', text: st.attribution.text, on: { click: () => o.openExternal(st.attribution.url) } })
							: el('span', { text: (st.attribution && st.attribution.text) || t('places.osm') }),
					]));
				} else if (o.api) list.appendChild(el('p', { class: 'hint', 'data-state': 'press', text: PS.searchable(text) ? t('places.pickPress') : t('places.searchMin') }));
			}

			async function addressSearch() {
				const text = q.value.trim();
				if (!o.api || st.busy || !PS.searchable(text)) { drawList(); return; }
				st.busy = true;
				st.error = null;
				drawList();
				const here = PS.anchorOf(options, selected);
				const r = await Promise.resolve(o.api.search(text, here ? { lat: here.lat, lon: here.lon } : undefined, lang())).catch((e) => ({ ok: false, error: e && e.message }));
				st.busy = false;
				if (ok(r)) { st.hits = r.results; st.attribution = r.attribution; st.via = r.via; } else { st.hits = null; st.error = PS.searchErrorText(r, t); }
				drawList();
			}

			function choose(x) {
				set(x);
				if (close) close();
			}

			/** „Als Ort speichern?“ — Speichern: a new place of „Meine Orte“; Nur hier: the point only in this form. */
			async function askSave(x) {
				const ans = await modal({
					title: t('places.saveQTitle'), dialog: 'place-save-q',
					body: [el('p', { class: 'mo-dlg-p', text: t('places.saveQText', { name: x.name }) })],
					actions: [
						{ label: t('places.cancel'), value: null },
						{ label: t('places.onlyHere'), cls: 'btn-sec', act: 'only-here', value: 'here' },
						{ label: t('places.saveQYes'), cls: 'btn-pri', act: 'save-place', onClick: async () => {
							const r = await Promise.resolve(o.api.create({ name: x.name, lat: x.lat, lon: x.lon, ...(x.address ? { address: x.address } : {}), radiusM: PS.RADIUS.default, icon: 'pin', visibility: 'self' }))
								.catch((e) => ({ ok: false, error: e && e.message }));
							if (!ok(r) || !r.place) return PS.errorText(r, t);
							return { place: r.place };
						} },
					],
				});
				if (ans === 'here') choose(x);
				else if (ans && ans.place) {
					const opt = PS.option({ ...ans.place, ref: ans.place.ref || `profile:${ans.place.id}`, source: 'profile' });
					if (opt) { options = [opt, ...options.filter((y) => y.key !== opt.key)]; choose(opt); }
				}
			}

			let timer = null;
			q.addEventListener('input', () => { st.hits = null; st.error = null; clearTimeout(timer); timer = setTimeout(drawList, 120); });
			q.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); addressSearch(); } });
			go.addEventListener('click', () => addressSearch());
			drawList();
			const ref = {};
			close = () => { if (ref.close) ref.close(null); };
			return modal({
				title: t('places.pickTitle'), dialog: 'place-pick', cls: 'mo-sheet', ref,
				body: [el('div', { class: 'mo-search' }, [q, go]), list],
				actions: [
					selected ? { label: t('places.pickClear'), cls: 'btn-ghost', act: 'pick-clear', onClick: () => { set(null); return true; } } : null,
					{ label: t('places.close'), value: null },
				].filter(Boolean),
			});
		}

		draw();
		return {
			el: box,
			selected: () => selected,
			set: (opt) => set(opt, false),
			options: () => options.slice(),
		};
	}

	root.GCPlacesView = { mount, picker, placeMap, deleteFlow, usedByList, badge };
})(typeof self !== 'undefined' ? self : this);
