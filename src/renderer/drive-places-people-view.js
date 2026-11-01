/**
 * GateControl -- Drive "Orte und Personen" (renderer view, part of "Fotos" on the page Drive)
 *
 * Drive 1.16 'photoPlaces' / 'photoPeople' (Mockup 8), only with the features `me` reports:
 * - "Karte": an OpenStreetMap map (tiles from the main process, core map-service.js, like the chats' maps; the
 *   attribution always shows) with the clusters of photos/map for the box in view (drag, wheel, +/−, arrow keys), on
 *   the right "Orte im Bild" — a cluster and its row pick the same place; a row (or the picked cluster again) opens it,
 *   a cluster of several places zooms in.
 * - A place: a small map, "214 Fotos · 12 Tage · St. Pauli, Altona", the people on these photos (a click shows the
 *   photos with them), the photos by day with the district.
 * - "Personen": the progress of the recognition (the phones find the faces; this PC finds none), "Benannt",
 *   "Wer ist das?" (naming), "Ausgeblendet"; the gear opens the settings "Orte und Personen".
 * - A person: the face, photos and years, the link to a family member or contact, "Ist das auch …?" (uncertain faces:
 *   "Ja, alle", "Einzeln prüfen"), "Zusammen mit" (photos with both), the person's places, the photos by year;
 *   rename, merge with another person, hide.
 * - "Wer ist das?": a name (typed or from the family / the contacts / the people Drive knows), "Sieht aus wie …"
 *   (merge), "Ausblenden"; afterwards a short confirmation with "Rückgängig".
 * - The search field: suggestions while typing (people, places, what is on the photos); the marks of a search.
 *
 * Created by drive-photos-view.js (it hands over its helpers: picture / previewUrl / grid, render, the search).
 * Data: window.gatecontrol.drive; names to offer: window.gatecontrol.chat.people (family) and
 * window.gatecontrol.mail.contacts (contacts) when there; texts: drive.pp.*; logic without DOM:
 * drive-places-people-state.js. Server text only ever goes into textContent / attributes.
 */
(function (root) {
	'use strict';

	const PPS = root.GCDrivePlacesPeopleState;
	const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed', error: err && err.message });
	const PAGE = 120;
	let uid = 0;
	const nextId = (p) => `${p}-${++uid}`;

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive
	 * @param {Function} o.t
	 * @param {Function} o.getLocale
	 * @param {Function} o.toast
	 * @param {HTMLElement} o.host - dialogs
	 * @param {object} o.ui - { el, icon, clear, openDialog }
	 * @param {Function} o.getMe
	 * @param {Function} o.errorText - (r) → text
	 * @param {Function} o.previewUrl - (photo, large) → Promise<objectURL | null>
	 * @param {Function} o.picture - (box, photo, large) a preview into box
	 * @param {Function} o.grid - (photos) → the grid of tiles (open the lightbox)
	 * @param {Function} o.render - draws "Fotos" again
	 * @param {Function} o.search - (q) a search of the timeline
	 * @param {Function} [o.resetInput] - the search field shows the search of the timeline again
	 * @param {Function} [o.openSettings] - (section) the Drive settings
	 * @param {Function} [o.onOpen] - the view opened a place / person (the photos view leaves its selection)
	 */
	function create(o) {
		const api = o.api;
		const t = o.t;
		const { el, icon, clear, openDialog } = o.ui;
		const locale = () => o.getLocale();
		const toast = o.toast || (() => {});
		const err = (r) => o.errorText(r);
		const feats = () => PPS.features(o.getMe());
		const S = {
			places: null, placesErr: null, placesLoading: false,
			view: null, fitted: false, clusters: [], pick: null, clusterErr: null,
			people: null, progress: null, peopleErr: null, peopleLoading: false, allUnnamed: false, showHidden: false,
			settings: null,
			open: null,
			seq: 0,
		};

		// ── Faces ────────────────────────────────────────
		/** A round face of `person` (its cover cut out of the photo; the initials until it is there). */
		function face(cover, { size = 96, name = null, id = null, unknown = false } = {}) {
			const ini = el('span', { class: 'dpp-ini', 'aria-hidden': 'true' }, unknown && !name ? [icon('user', Math.round(size * 0.4), '1.6')] : [PPS.initials(name)]);
			const f = el('span', { class: `dpp-face dpp-tone-${unknown && !name ? 'none' : PPS.toneOf(id === null ? name : id)}`, style: `width:${size}px;height:${size}px;font-size:${Math.round(size * 0.3)}px` }, [ini]);
			if (cover && cover.item && cover.box) {
				Promise.resolve(o.previewUrl(cover.item, true)).then((u) => {
					if (!u || !f.isConnected) return;
					const img = el('img', { alt: '', draggable: 'false' });
					img.addEventListener('load', () => {
						const c = PPS.faceCrop(cover.box, img.naturalWidth, img.naturalHeight, size);
						if (!c) return;
						img.style.width = `${c.width}px`;
						img.style.height = `${c.height}px`;
						img.style.left = `${c.left}px`;
						img.style.top = `${c.top}px`;
						f.classList.add('has-img');
					});
					img.src = u;
					f.appendChild(img);
				}).catch(() => {});
			}
			return f;
		}

		// ── Loading ──────────────────────────────────────
		async function loadPlaces() {
			if (!feats().places || S.placesLoading) return;
			S.placesLoading = true;
			const r = await Promise.resolve(api.photoPlaces({})).catch(fail);
			S.placesLoading = false;
			if (r && r.ok) { S.places = r.places; S.placesErr = null; } else S.placesErr = r;
			if (map.box.isConnected) { fitOnce(); renderAside(); }
		}

		async function loadPeople({ quiet = false } = {}) {
			if (!feats().people) return;
			S.peopleLoading = !quiet;
			if (!quiet) o.render();
			const [r, st] = await Promise.all([Promise.resolve(api.people()).catch(fail), Promise.resolve(api.photoSettings()).catch(() => null)]);
			S.peopleLoading = false;
			if (st && st.ok) S.settings = st;
			if (r && r.ok) { S.people = r.people; S.progress = r.progress; S.peopleErr = null; } else S.peopleErr = r;
			o.render();
		}

		const peopleNow = () => S.people || [];

		// ── Map ──────────────────────────────────────────
		const tileCache = new Map();
		function tileUrl(z, x, y) {
			const key = `${z}/${x}/${y}`;
			let p = tileCache.get(key);
			if (p) { tileCache.delete(key); tileCache.set(key, p); return p; }
			p = Promise.resolve(typeof api.mapTile === 'function' ? api.mapTile(z, x, y) : null)
				.then((r) => (r && r.ok !== false && r.data ? URL.createObjectURL(new Blob([r.data], { type: r.mime || 'image/png' })) : null))
				.catch(() => null);
			tileCache.set(key, p);
			p.then((u) => { if (!u && tileCache.get(key) === p) tileCache.delete(key); });
			while (tileCache.size > 384) {
				const [k, old] = tileCache.entries().next().value;
				tileCache.delete(k);
				old.then((u) => { if (u) setTimeout(() => URL.revokeObjectURL(u), 5000); });
			}
			return p;
		}

		/**
		 * A slippy map: mapView({ interactive, height?, label }) → { box, center(lat, lon, zoom), view(), size(),
		 * setMarks(list of { lat, lon, … } → element), onMove(fn) }.
		 */
		function mapView({ interactive = true, label = '' } = {}) {
			let z = 5;
			let c = PPS.worldPx(51.1657, 10.4515, z);
			let marks = [];
			let makeMark = null;
			let moved = null;
			const imgs = new Map();
			const layer = el('div', { class: 'dpp-map-tiles' });
			const pins = el('div', { class: 'dpp-map-pins' });
			const box = el('div', { class: `dpp-map${interactive ? ' is-live' : ''}` }, [layer, pins]);
			const size = () => ({ w: box.clientWidth || 0, h: box.clientHeight || 0 });
			let raf = 0;
			const schedule = () => { if (!raf) raf = requestAnimationFrame(draw); };
			const resetTiles = () => { for (const img of imgs.values()) img.remove(); imgs.clear(); };
			const clampY = () => { const n = PPS.TILE * 2 ** z; c = { x: c.x, y: Math.max(0, Math.min(n, c.y)) }; };
			let moveTimer = null;
			const changed = () => { schedule(); clearTimeout(moveTimer); moveTimer = setTimeout(() => { if (moved) moved(); }, 320); };

			function draw() {
				raf = 0;
				const { w, h } = size();
				if (!w || !h) return;
				const want = new Set();
				for (const tl of PPS.tileGrid(c.x, c.y, z, w, h)) {
					want.add(tl.key);
					let img = imgs.get(tl.key);
					if (!img) {
						img = el('img', { class: 'dpp-map-tile', alt: '', draggable: 'false' });
						imgs.set(tl.key, img);
						layer.appendChild(img);
						const mine = img;
						tileUrl(tl.z, tl.x, tl.y).then((u) => { if (u && imgs.get(tl.key) === mine) mine.src = u; });
					}
					img.style.transform = `translate(${tl.left}px, ${tl.top}px)`;
				}
				for (const [k, img] of imgs) if (!want.has(k)) { img.remove(); imgs.delete(k); }
				clear(pins);
				for (const m of marks) {
					const p = PPS.screenPos(m.lat, m.lon, c.x, c.y, z, w, h);
					if (p.x < -40 || p.y < -40 || p.x > w + 40 || p.y > h + 40) continue;
					const e = makeMark ? makeMark(m) : el('span', { class: 'dpp-dot' });
					e.style.left = `${p.x}px`;
					e.style.top = `${p.y}px`;
					pins.appendChild(e);
				}
			}

			function zoomAt(dz, px, py) {
				const nz = PPS.clampZoom(z + dz);
				if (nz === z) return;
				const { w, h } = size();
				const ox = px === undefined ? 0 : px - w / 2;
				const oy = py === undefined ? 0 : py - h / 2;
				const k = 2 ** (nz - z);
				c = { x: (c.x + ox) * k - ox, y: (c.y + oy) * k - oy };
				z = nz;
				clampY();
				resetTiles();
				changed();
			}

			const zoomBtns = [];
			if (interactive) {
				box.setAttribute('tabindex', '0');
				box.setAttribute('role', 'application');
				box.setAttribute('aria-label', label);
				const zb = (ic, key, dz) => { const b = el('button', { type: 'button', class: 'dv-ib dpp-zoom-b', 'data-label': key, on: { click: (e) => { e.stopPropagation(); zoomAt(dz); } } }, [icon(ic, 16)]); zoomBtns.push(b); return b; };
				box.appendChild(el('div', { class: 'dpp-map-zoom' }, [zb('plus', 'drive.pp.map.zoomIn', 1), zb('minus', 'drive.pp.map.zoomOut', -1)]));
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
					if (!drag.moved && Math.abs(dx) + Math.abs(dy) < 4) return;
					drag.moved = true;
					box.classList.add('is-drag');
					c = { x: c.x - dx, y: c.y - dy };
					clampY();
					drag.x = e.clientX;
					drag.y = e.clientY;
					changed();
				});
				const end = (e) => { if (drag && e.pointerId === drag.id) { drag = null; box.classList.remove('is-drag'); } };
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
					const mv = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] };
					if (mv[e.key]) { e.preventDefault(); c = { x: c.x + mv[e.key][0], y: c.y + mv[e.key][1] }; clampY(); changed(); }
					else if (e.key === '+' || e.key === '=') { e.preventDefault(); zoomAt(1); }
					else if (e.key === '-') { e.preventDefault(); zoomAt(-1); }
				});
			}
			const attr = el('span', { class: 'dpp-map-attr' });
			box.appendChild(attr);
			// the texts in the language now (the map of the tab is made once and kept)
			const relabel = () => {
				attr.textContent = t('drive.pp.map.attribution');
				for (const b of zoomBtns) { const l = t(b.getAttribute('data-label')); b.setAttribute('aria-label', l); b.title = l; }
				if (interactive) box.setAttribute('aria-label', t('drive.pp.map.label'));
			};
			relabel();
			if (typeof ResizeObserver === 'function') new ResizeObserver(() => changed()).observe(box);

			return {
				box,
				size,
				center(lat, lon, zoom) {
					if (zoom !== undefined && PPS.clampZoom(zoom) !== z) { z = PPS.clampZoom(zoom); resetTiles(); }
					c = PPS.worldPx(lat, lon, z);
					changed();
				},
				zoomOn(lat, lon, dz) { c = PPS.worldPx(lat, lon, z); zoomAt(dz); },
				view() { const { w, h } = size(); return { bbox: PPS.viewBbox(c.x, c.y, z, w, h), zoom: z, w, h }; },
				setMarks(list, make) { marks = Array.isArray(list) ? list : []; makeMark = make || null; schedule(); },
				onMove(fn) { moved = fn; },
				redraw: schedule,
				relabel,
			};
		}

		const map = mapView({ interactive: true, label: t('drive.pp.map.label') });
		const aside = el('aside', { class: 'dpp-aside', 'aria-label': t('drive.pp.map.inView') });
		const mapSplit = el('div', { class: 'dpp-split' }, [map.box, aside]);
		map.onMove(() => loadClusters());

		function fitOnce() {
			if (S.fitted || !S.places) return;
			const { w, h } = map.size();
			if (!w || !h) return;
			S.fitted = true;
			const v = PPS.fitView(S.places.map((p) => ({ lat: p.lat, lon: p.lon })), w, h, { maxZoom: 12 });
			map.center(v.lat, v.lon, v.zoom);
		}

		let clusterSeq = 0;
		async function loadClusters() {
			if (!map.box.isConnected) return;
			const v = map.view();
			if (!v.w || !v.h) return;
			const seq = ++clusterSeq;
			const r = await Promise.resolve(api.photoMap(v.bbox, v.zoom, {})).catch(fail);
			if (seq !== clusterSeq) return;
			if (r && r.ok) { S.clusters = r.clusters; S.clusterErr = null; } else S.clusterErr = r;
			drawClusters();
			renderAside();
		}

		function drawClusters() {
			map.setMarks(S.clusters, (cl) => {
				const name = cl.key ? placeName(cl.key) : '';
				const on = !!cl.key && cl.key === S.pick;
				const b = el('button', {
					type: 'button', class: `dpp-cl${on ? ' is-on' : ''}`, 'data-key': cl.key || '', 'aria-pressed': on ? 'true' : 'false',
					'aria-label': [name || t('drive.pp.map.several'), PPS.fmt(cl.count, locale())].join(' · '), title: name || t('drive.pp.map.several'),
					text: PPS.fmt(cl.count, locale()),
					on: {
						click: (e) => {
							e.stopPropagation();
							if (!cl.key) { map.zoomOn(cl.lat, cl.lon, 2); return; }
							if (S.pick === cl.key) { openPlace(cl.key); return; }
							pick(cl.key);
						},
						dblclick: (e) => { e.stopPropagation(); if (cl.key) openPlace(cl.key); },
					},
				});
				return b;
			});
		}

		function placeName(key) {
			const p = (S.places || []).find((x) => x.key === key);
			return p ? p.name : '';
		}

		function pick(key) {
			S.pick = key;
			drawClusters();
			renderAside();
			const row = aside.querySelector(`[data-key="${CSS.escape(key)}"]`);
			if (row && typeof row.scrollIntoView === 'function') row.scrollIntoView({ block: 'nearest' });
		}

		function renderAside() {
			clear(aside);
			aside.appendChild(el('div', { class: 'dpp-aside-h', text: t('drive.pp.map.inView') }));
			if (S.placesErr || S.clusterErr) { aside.appendChild(el('p', { class: 'dv-p dpp-aside-note', text: err(S.placesErr || S.clusterErr) })); return; }
			const rows = PPS.placeRows(S.clusters, S.places, { locale: locale() });
			if (!rows.length) {
				aside.appendChild(el('p', { class: 'dv-p dpp-aside-note', text: S.places && !S.places.length ? t('drive.pp.map.none') : t('drive.pp.map.noneHere') }));
				return;
			}
			for (const r of rows) {
				const th = el('span', { class: 'dpp-th dv-k-image' }, [icon('image', 18, '1.6')]);
				if (r.cover) o.picture(th, r.cover);
				aside.appendChild(el('button', {
					type: 'button', class: `dpp-pl${r.key === S.pick ? ' is-on' : ''}`, 'data-key': r.key, 'aria-pressed': r.key === S.pick ? 'true' : 'false',
					on: { click: () => openPlace(r.key), focus: () => { if (S.pick !== r.key) { S.pick = r.key; drawClusters(); for (const x of aside.querySelectorAll('.dpp-pl')) { const onx = x.getAttribute('data-key') === r.key; x.classList.toggle('is-on', onx); x.setAttribute('aria-pressed', onx ? 'true' : 'false'); } } } },
				}, [
					th,
					el('span', { class: 'dpp-pl-tx' }, [el('span', { class: 'dpp-pl-name', text: r.name }), r.sub ? el('span', { class: 'dpp-sub', text: r.sub }) : null]),
					el('span', { class: 'dpp-n', text: PPS.fmt(r.count, locale()) }),
				]));
			}
		}

		function renderMap(body) {
			body.classList.add('is-map');
			map.relabel();
			aside.setAttribute('aria-label', t('drive.pp.map.inView'));
			body.appendChild(mapSplit);
			if (!S.places && !S.placesLoading) loadPlaces();
			renderAside();
			drawClusters();
			// the size is known once it is in the page
			requestAnimationFrame(() => { fitOnce(); map.redraw(); loadClusters(); });
		}

		// ── A place ──────────────────────────────────────
		/** Opens a place (from the map, a suggestion, a person): its photos (with `person`: only those with that person). */
		function openPlace(key, { name = null, person = null } = {}) {
			S.open = { kind: 'place', key, name: name || placeName(key), person, items: [], next: null, districts: [], total: null, loading: true, error: null };
			if (typeof o.onOpen === 'function') o.onOpen();
			if (feats().people && !S.people) loadPeople({ quiet: true });
			loadOpen();
		}

		function openPerson(id) {
			S.open = { kind: 'person', id, detail: null, items: [], next: null, with: null, faces: null, loading: true, error: null };
			if (typeof o.onOpen === 'function') o.onOpen();
			if (!S.people) loadPeople({ quiet: true });
			loadOpen();
		}

		async function loadOpen({ more = false } = {}) {
			const x = S.open;
			if (!x) return;
			const seq = ++S.seq;
			if (!more) { x.loading = true; x.error = null; o.render(); }
			const before = more ? x.next : null;
			if (x.kind === 'place') {
				const r = await Promise.resolve(api.photos({ place: x.key, districts: !more, withPeople: feats().people, limit: PAGE, ...(before ? { before } : {}), ...(x.person ? { person: x.person } : {}) })).catch(fail);
				if (seq !== S.seq || S.open !== x) return;
				x.loading = false;
				if (!r || !r.ok) { if (more) toast(err(r), 'error'); else x.error = r; o.render(); return; }
				x.items = more ? x.items.concat(r.items.filter((p) => !x.items.some((q) => q.id === p.id))) : r.items;
				x.next = r.next;
				if (!more) {
					x.districts = r.districts || [];
					const pl = (S.places || []).find((p) => p.key === x.key);
					x.total = pl && !x.person ? pl.count : null;
					if (!x.name) x.name = (r.items.find((p) => p.geo && p.geo.place && p.geo.place.key === x.key) || { geo: { place: { name: '' } } }).geo.place.name;
					if (!x.center) {
						const g = r.items.find((p) => p.geo);
						x.center = pl && Number.isFinite(pl.lat) ? { lat: pl.lat, lon: pl.lon } : g ? { lat: g.geo.lat, lon: g.geo.lon } : null;
					}
				}
				o.render();
				return;
			}
			const who = x.with ? [x.id, x.with] : x.id;
			const [d, r, u] = await Promise.all([
				more ? Promise.resolve({ ok: true, ...x.detail }) : Promise.resolve(api.person(x.id)).catch(fail),
				Promise.resolve(api.photos({ person: who, limit: PAGE, ...(before ? { before } : {}) })).catch(fail),
				more || x.with ? Promise.resolve(null) : Promise.resolve(api.uncertainFaces(x.id, 50)).catch(() => null),
			]);
			if (seq !== S.seq || S.open !== x) return;
			x.loading = false;
			if (!d || !d.ok) { x.error = d; o.render(); return; }
			x.detail = { person: d.person, together: d.together, places: d.places, uncertain: d.uncertain, years: d.years };
			if (u && u.ok) x.faces = u.faces;
			if (!r || !r.ok) { if (more) toast(err(r), 'error'); else x.error = r; o.render(); return; }
			x.items = more ? x.items.concat(r.items.filter((p) => !x.items.some((q) => q.id === p.id))) : r.items;
			x.next = r.next;
			o.render();
		}

		function back() {
			S.open = null;
			o.render();
		}

		const backBtn = (label) => el('button', { type: 'button', class: 'btn btn-ghost btn-sm dpp-back', on: { click: () => back() } }, [icon('back', 14), el('span', { text: label })]);
		const moreBtn = (next) => (next ? el('div', { class: 'dpv-more' }, [el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.photos.more'), on: { click: () => loadOpen({ more: true }) } })]) : null);
		const loadingEl = () => el('div', { class: 'dv-empty', text: t('drive.loading') });
		const errorEl = (r, retry) => el('div', { class: 'dv-empty' }, [icon('alert', 26, '1.6'), el('span', { text: err(r) }), el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.retry'), on: { click: retry } })]);

		function renderPlace(body, x) {
			body.appendChild(el('div', { class: 'dpp-top' }, [backBtn(t('drive.pp.backMap'))]));
			if (x.loading && !x.items.length) { body.appendChild(loadingEl()); return; }
			if (x.error) { body.appendChild(errorEl(x.error, () => loadOpen())); return; }
			// one small map per place shown (kept while it is open)
			if (!x.mini) { x.mini = mapView({ interactive: false }); x.mini.box.classList.add('dpp-mini'); }
			const mini = x.mini;
			mini.relabel();
			const pts = x.items.filter((p) => p.geo).map((p) => ({ lat: p.geo.lat, lon: p.geo.lon }));
			const head = el('div', { class: 'dpp-place-head card' }, [mini.box, el('div', { class: 'dpp-place-tx' }, [
				el('h2', { class: 'dpp-title', text: x.name || t('drive.pp.place.unknown') }),
				el('span', { class: 'dpp-sub', text: PPS.placeSub({ count: x.total !== null ? x.total : x.items.length, items: x.items, districts: x.districts }, { t, locale: locale() }) }),
			])]);
			body.appendChild(head);
			requestAnimationFrame(() => {
				const { w, h } = mini.size();
				const v = pts.length ? PPS.fitView(pts, w, h, { maxZoom: 14, pad: 24 }) : (x.center ? { lat: x.center.lat, lon: x.center.lon, zoom: 11 } : null);
				if (v) mini.center(v.lat, v.lon, v.zoom);
				mini.setMarks(pts);
			});
			// the people on these photos: a click shows the photos with them
			const ppl = feats().people ? PPS.peopleOn(x.items, peopleNow()) : [];
			if (ppl.length || x.person) {
				const chips = el('div', { class: 'dpp-chips', role: 'group', 'aria-label': t('drive.pp.place.people') });
				for (const p of ppl.slice(0, 12)) {
					const on = x.person !== null && String(x.person) === String(p.id);
					const per = peopleNow().find((q) => String(q.id) === String(p.id));
					chips.appendChild(el('button', {
						type: 'button', class: `dpp-pchip${on ? ' is-on' : ''}`, 'aria-pressed': on ? 'true' : 'false', 'data-person': String(p.id),
						on: { click: () => { x.person = on ? null : p.id; loadOpen(); } },
					}, [face(per && per.cover, { size: 26, name: p.name, id: p.id }), el('span', { text: `${p.name} · ${PPS.fmt(p.count, locale())}` })]));
				}
				body.appendChild(chips);
			}
			if (!x.items.length) { body.appendChild(el('div', { class: 'dv-empty' }, [icon('image', 28, '1.6'), el('span', { text: t('drive.pp.place.empty') })])); return; }
			for (const g of PPS.byDay(x.items, { locale: locale(), t })) {
				body.appendChild(el('section', { class: 'dpv-month', 'data-day': g.key }, [
					el('div', { class: 'dpv-month-h' }, [el('span', { class: 'dpv-month-name', text: g.label }), el('span', { class: 'dpv-month-n', text: g.sub })]),
					o.grid(g.items),
				]));
			}
			const m = moreBtn(x.next);
			if (m) body.appendChild(m);
		}

		// ── People ───────────────────────────────────────
		function personTile(p, { unnamed = false } = {}) {
			return el('button', { type: 'button', role: 'listitem', class: 'dpp-p', 'data-person': String(p.id), on: { click: () => (unnamed ? nameDialog(p) : openPerson(p.id)) } }, [
				face(p.cover, { size: 88, name: p.name, id: p.id, unknown: unnamed }),
				el('span', { class: `dpp-p-name${unnamed ? ' is-ask' : ''}`, text: unnamed ? t('drive.pp.people.name') : p.name }),
				el('span', { class: 'dpp-sub', text: PPS.fmt(p.count, locale()) }),
			]);
		}

		function renderPeople(body) {
			if (S.peopleLoading && !S.people) { body.appendChild(loadingEl()); return; }
			if (S.peopleErr && !S.people) { body.appendChild(errorEl(S.peopleErr, () => loadPeople())); return; }
			const g = PPS.groupPeople(S.people);
			const gear = typeof o.openSettings === 'function'
				? el('button', { type: 'button', class: 'dv-ib dpp-gear', 'aria-label': t('drive.pp.people.settings'), title: t('drive.pp.people.settings'), on: { click: () => o.openSettings('places') } }, [icon('gear', 16)])
				: null;
			body.appendChild(el('div', { class: 'dpp-people-head' }, [el('span', { class: 'dpp-sub', text: PPS.peopleSub(g, t, locale()) }), el('span', { class: 'dv-grow' }), gear]));
			const off = S.settings && S.settings.people === false;
			if (off && !(S.people || []).length) {
				body.appendChild(el('div', { class: 'card dpp-off' }, [
					el('b', { text: t('drive.pp.people.offTitle') }),
					el('p', { class: 'dv-p', text: t('drive.pp.people.offText') }),
					typeof o.openSettings === 'function' ? el('button', { type: 'button', class: 'btn btn-pri btn-sm', text: t('drive.pp.people.offOpen'), on: { click: () => o.openSettings('places') } }) : null,
				]));
				return;
			}
			const pr = PPS.progressOf(S.progress, { t, locale: locale() });
			if (pr && !pr.done) {
				body.appendChild(el('div', { class: 'dpp-progress card' }, [
					el('div', { class: 'dpp-progress-h' }, [icon('refresh', 15), el('span', { text: t('drive.pp.progress.title', { count: pr.text }) })]),
					el('div', { class: 'dpp-bar', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(pr.pct) }, [el('span', { style: `width:${pr.pct}%` })]),
					el('span', { class: 'dpp-sub', text: t('drive.pp.progress.phones') }),
				]));
			}
			if (!g.named.length && !g.unnamed.length && !g.hidden.length) {
				body.appendChild(el('div', { class: 'dv-empty' }, [icon('users', 28, '1.6'), el('span', { text: t('drive.pp.people.none') })]));
			}
			if (g.named.length) {
				body.appendChild(el('div', { class: 'dpp-sec' }, [el('span', { class: 'dpp-h', text: t('drive.pp.people.namedTitle') })]));
				body.appendChild(el('div', { class: 'dpp-pgrid', role: 'list', 'aria-label': t('drive.pp.people.namedTitle') }, g.named.map((p) => personTile(p))));
			}
			if (g.unnamed.length) {
				const shown = S.allUnnamed ? g.unnamed : g.unnamed.slice(0, 14);
				body.appendChild(el('div', { class: 'dpp-sec' }, [el('span', { class: 'dpp-h', text: t('drive.pp.people.whoTitle') }), el('span', { class: 'dpp-sub', text: t('drive.pp.people.whoHint') })]));
				body.appendChild(el('div', { class: 'dpp-pgrid', role: 'list', 'aria-label': t('drive.pp.people.whoTitle') }, shown.map((p) => personTile(p, { unnamed: true }))));
				if (g.unnamed.length > shown.length) {
					body.appendChild(el('button', { type: 'button', class: 'btn btn-sec btn-sm dpp-more-people', text: t('drive.pp.people.moreUnnamed', { count: PPS.fmt(g.unnamed.length - shown.length, locale()) }), on: { click: () => { S.allUnnamed = true; o.render(); } } }));
				}
			}
			if (g.hidden.length) {
				body.appendChild(el('div', { class: 'dpp-sec' }, [
					el('span', { class: 'dpp-h', text: t('drive.pp.people.hiddenTitle') }),
					el('span', { class: 'dpp-sub', text: PPS.fmt(g.hidden.length, locale()) }),
					el('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'aria-expanded': S.showHidden ? 'true' : 'false', text: t(S.showHidden ? 'drive.pp.people.hiddenHide' : 'drive.pp.people.hiddenShow'), on: { click: () => { S.showHidden = !S.showHidden; o.render(); } } }),
				]));
				body.appendChild(el('p', { class: 'dv-p dpp-note', text: t('drive.pp.people.hiddenText') }));
				if (S.showHidden) {
					body.appendChild(el('div', { class: 'dpp-pgrid', role: 'list' }, g.hidden.map((p) => el('div', { role: 'listitem', class: 'dpp-p is-hidden', 'data-person': String(p.id) }, [
						face(p.cover, { size: 64, name: p.name, id: p.id, unknown: !p.name }),
						el('span', { class: 'dpp-p-name', text: p.name || t('drive.pp.people.noName') }),
						el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('drive.pp.people.unhide'), on: { click: () => setHidden(p, false) } }),
					]))));
				}
			}
			body.appendChild(el('p', { class: 'dv-p dpp-note', text: t('drive.pp.people.phonesNote') }));
		}

		async function setHidden(p, hidden) {
			const r = await Promise.resolve(api.updatePerson(p.id, { hidden })).catch(fail);
			if (!r || !r.ok) { toast(err(r), 'error'); return null; }
			toast(t(hidden ? 'drive.pp.person.hiddenDone' : 'drive.pp.person.shownDone'), 'success');
			await loadPeople({ quiet: true });
			return r;
		}

		// ── A person ─────────────────────────────────────
		function renderPerson(body, x) {
			body.appendChild(el('div', { class: 'dpp-top' }, [backBtn(t('drive.pp.backPeople'))]));
			if (x.loading && !x.detail) { body.appendChild(loadingEl()); return; }
			if (x.error) { body.appendChild(errorEl(x.error, () => loadOpen())); return; }
			const d = x.detail;
			const p = d.person;
			const actions = el('div', { class: 'dpp-actions' }, [
				el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => nameDialog(p, { rename: !!p.name }) } }, [icon('pen', 14), el('span', { text: t(p.name ? 'drive.pp.person.rename' : 'drive.pp.people.name') })]),
				el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => mergeDialog(p) } }, [icon('users', 14), el('span', { text: t('drive.pp.person.merge') })]),
				el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: async () => { const r = await setHidden(p, !p.hidden); if (r) { if (r.person) x.detail.person = r.person; o.render(); } } } }, [icon('eye', 14), el('span', { text: t(p.hidden ? 'drive.pp.people.unhide' : 'drive.pp.person.hide') })]),
			]);
			const link = PPS.contactText(p.contact, t);
			body.appendChild(el('div', { class: 'dpp-person-head' }, [
				face(p.cover, { size: 88, name: p.name, id: p.id, unknown: !p.name }),
				el('div', { class: 'dpp-person-tx' }, [
					el('h2', { class: 'dpp-title', text: p.name || t('drive.pp.people.noName') }),
					el('span', { class: 'dpp-sub', text: PPS.personSub(d, { t, locale: locale() }) }),
					link ? el('span', { class: 'dpp-sub dpp-link' }, [icon('user', 13), el('span', { text: link })]) : null,
				]),
				el('span', { class: 'dv-grow' }),
				actions,
			]));
			// "Ist das auch …?"
			if (p.name && !x.with && d.uncertain > 0 && x.faces && x.faces.length) {
				const prev = PPS.uncertainPreview(x.faces);
				body.appendChild(el('div', { class: 'dpp-ask card' }, [
					el('b', { text: t('drive.pp.person.askTitle', { name: p.name }) }),
					el('div', { class: 'dpp-ask-faces' }, [
						...prev.shown.map((f) => face({ box: f.box, item: f.item }, { size: 52, name: p.name, id: p.id })),
						prev.more ? el('span', { class: 'dpp-face dpp-more-n', style: 'width:52px;height:52px', text: `+${prev.more}` }) : null,
					]),
					el('span', { class: 'dpp-sub', text: t(`drive.pp.person.askText.${d.uncertain === 1 ? 'one' : 'other'}`, { count: PPS.fmt(d.uncertain, locale()) }) }),
					el('div', { class: 'dpp-row' }, [
						el('button', { type: 'button', class: 'btn btn-pri btn-sm', text: t('drive.pp.person.askAll'), on: { click: () => confirmAll(x) } }),
						el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.pp.person.askEach'), on: { click: () => reviewDialog(x) } }),
					]),
				]));
			}
			if (d.together.length) {
				body.appendChild(el('div', { class: 'dpp-sec' }, [el('span', { class: 'dpp-h', text: t('drive.pp.person.together') }), el('span', { class: 'dpp-sub', text: t('drive.pp.person.togetherHint') })]));
				const chips = el('div', { class: 'dpp-chips', role: 'group', 'aria-label': t('drive.pp.person.together') });
				for (const w of d.together.slice(0, 12)) {
					const on = x.with !== null && String(x.with) === String(w.id);
					const per = peopleNow().find((q) => String(q.id) === String(w.id));
					chips.appendChild(el('button', { type: 'button', class: `dpp-pchip${on ? ' is-on' : ''}`, 'aria-pressed': on ? 'true' : 'false', 'data-person': String(w.id), on: { click: () => { x.with = on ? null : w.id; loadOpen(); } } }, [
						face(per && per.cover, { size: 26, name: w.name, id: w.id }), el('span', { text: `${w.name || t('drive.pp.people.noName')} · ${PPS.fmt(w.count, locale())}` }),
					]));
				}
				body.appendChild(chips);
			}
			if (d.places.length && feats().places) {
				body.appendChild(el('div', { class: 'dpp-sec' }, [el('span', { class: 'dpp-h', text: t('drive.pp.person.places') })]));
				body.appendChild(el('div', { class: 'dpp-chips' }, d.places.slice(0, 12).map((pl) => el('button', {
					type: 'button', class: 'dv-chip', 'data-key': pl.key, text: `${pl.name} · ${PPS.fmt(pl.count, locale())}`, on: { click: () => openPlace(pl.key, { name: pl.name, person: p.id }) },
				}))));
			}
			if (x.loading) { body.appendChild(loadingEl()); return; }
			if (!x.items.length) { body.appendChild(el('div', { class: 'dv-empty' }, [icon('image', 28, '1.6'), el('span', { text: t('drive.pp.person.empty') })])); return; }
			for (const g of PPS.byYear(x.items, t)) {
				body.appendChild(el('section', { class: 'dpv-month', 'data-year': g.key }, [
					el('div', { class: 'dpv-month-h' }, [el('span', { class: 'dpv-month-name', text: g.label }), el('span', { class: 'dpv-month-n', text: t(`drive.pp.photos.${g.items.length === 1 ? 'one' : 'other'}`, { count: PPS.fmt(g.items.length, locale()) }) })]),
					o.grid(g.items),
				]));
			}
			const m = moreBtn(x.next);
			if (m) body.appendChild(m);
		}

		async function confirmAll(x) {
			const ids = (x.faces || []).map((f) => f.faceId);
			if (!ids.length) return;
			const r = await Promise.resolve(api.confirmFaces(x.id, ids, true)).catch(fail);
			if (!r || !r.ok) { toast(err(r), 'error'); return; }
			toast(t(`drive.pp.person.confirmed.${ids.length === 1 ? 'one' : 'other'}`, { count: PPS.fmt(ids.length, locale()) }), 'success');
			loadOpen();
			loadPeople({ quiet: true });
		}

		/** "Einzeln prüfen": each uncertain face with "Ja" / "Nein". */
		function reviewDialog(x) {
			const p = x.detail.person;
			let changed = false;
			const dlg = openDialog({ title: t('drive.pp.person.askTitle', { name: p.name }), host: o.host, closeLabel: t('drive.close'), onClose: () => { if (changed) { loadOpen(); loadPeople({ quiet: true }); } } });
			dlg.box.classList.add('dpp-dlg');
			const list = el('div', { class: 'dpp-review', role: 'list' });
			const draw = () => {
				clear(list);
				const faces = x.faces || [];
				if (!faces.length) { list.appendChild(el('p', { class: 'dv-p', text: t('drive.pp.person.askDone') })); return; }
				for (const f of faces) {
					const answer = async (yes) => {
						const r = await Promise.resolve(api.confirmFaces(x.id, [f.faceId], yes)).catch(fail);
						if (!r || !r.ok) { toast(err(r), 'error'); return; }
						changed = true;
						x.faces = x.faces.filter((y) => y.faceId !== f.faceId);
						draw();
					};
					list.appendChild(el('div', { class: 'dpp-review-row', role: 'listitem', 'data-face': String(f.faceId) }, [
						face({ box: f.box, item: f.item }, { size: 56, name: p.name, id: p.id }),
						el('span', { class: 'dpp-pl-tx' }, [el('span', { class: 'dpp-pl-name', text: f.item.name }), el('span', { class: 'dpp-sub', text: Number.isFinite(f.item.takenAt) ? new Date(f.item.takenAt).toLocaleDateString(locale() === 'en' ? 'en-GB' : 'de-DE', { day: 'numeric', month: 'long', year: 'numeric' }) : '' })]),
						el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.pp.person.no'), on: { click: () => answer(false) } }),
						el('button', { type: 'button', class: 'btn btn-pri btn-sm', text: t('drive.pp.person.yes'), on: { click: () => answer(true) } }),
					]));
				}
			};
			draw();
			dlg.body.appendChild(list);
			dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.close'), on: { click: () => dlg.close(null) } }));
		}

		/** "Mit anderer Person zusammenführen": the named people to pick. */
		function mergeDialog(p) {
			const dlg = openDialog({ title: t('drive.pp.person.mergeTitle', { name: p.name || t('drive.pp.people.noName') }), host: o.host, closeLabel: t('drive.close') });
			dlg.box.classList.add('dpp-dlg');
			const errEl = el('span', { class: 'dv-dlg-err', role: 'alert' });
			const list = el('div', { class: 'dv-pick-list', role: 'list' });
			const others = PPS.groupPeople(peopleNow()).named.filter((q) => String(q.id) !== String(p.id));
			if (!others.length) list.appendChild(el('div', { class: 'dv-pick-note', text: t('drive.pp.person.mergeNone') }));
			for (const q of others) {
				list.appendChild(el('button', { type: 'button', role: 'listitem', class: 'dv-pick-row', 'data-person': String(q.id), on: { click: async () => {
					const r = await Promise.resolve(api.mergePerson(p.id, q.id)).catch(fail);
					if (!r || !r.ok) { errEl.textContent = err(r); return; }
					dlg.close(r);
					toast(t('drive.pp.name.mergedTitle', { name: q.name }), 'success');
					await loadPeople({ quiet: true });
					openPerson(r.person.id);
				} } }, [face(q.cover, { size: 32, name: q.name, id: q.id }), el('span', { class: 'dv-pick-tx' }, [el('span', { class: 'dv-pick-name', text: q.name }), el('span', { class: 'dv-pick-sub', text: t(`drive.pp.photos.${q.count === 1 ? 'one' : 'other'}`, { count: PPS.fmt(q.count, locale()) }) })])]));
			}
			dlg.body.append(el('p', { class: 'dv-p', text: t('drive.pp.person.mergeText') }), list);
			dlg.foot.append(errEl, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }));
		}

		// ── "Wer ist das?" ───────────────────────────────
		let familyCache = null;
		async function family() {
			if (familyCache) return familyCache;
			const chat = root.gatecontrol && root.gatecontrol.chat;
			if (!chat || typeof chat.people !== 'function') { familyCache = []; return familyCache; }
			const r = await Promise.resolve(chat.people()).catch(() => null);
			familyCache = r && r.ok && Array.isArray(r.people) ? r.people.filter((x) => x && x.name).map((x) => ({ id: x.id, name: x.name })) : [];
			return familyCache;
		}

		async function contacts(q) {
			const mail = root.gatecontrol && root.gatecontrol.mail;
			if (!mail || typeof mail.contacts !== 'function' || String(q || '').trim().length < 2) return [];
			const r = await Promise.resolve(mail.contacts(String(q).trim())).catch(() => null);
			return r && r.ok && Array.isArray(r.items) ? r.items.filter((c) => c && c.name && c.source !== 'group') : [];
		}

		/** Names a person ("Wer ist das?" / "Umbenennen"), with "Sieht aus wie …" and "Ausblenden"; `then` after it is done. */
		function nameDialog(p, { rename = false } = {}) {
			const dlg = openDialog({ title: t(rename ? 'drive.pp.person.rename' : 'drive.pp.name.title'), host: o.host, closeLabel: t('drive.close'), onClose: () => { if (done) loadPeople({ quiet: true }).then(() => { if (S.open && S.open.kind === 'person') loadOpen(); }); } });
			dlg.box.classList.add('dpp-dlg', 'dpp-name-dlg');
			let done = null;
			let contact = p.contact || null;
			let detail = null;
			const sub = el('span', { class: 'dpp-sub' });
			const headTx = el('div', { class: 'dpp-name-tx' }, [rename && p.name ? el('span', { class: 'dpp-name-h', text: p.name }) : null, sub]);
			const inputId = nextId('dpp-name');
			const input = el('input', { id: inputId, type: 'text', class: 'dv-input dpp-name-in', maxlength: '200', spellcheck: 'false', value: p.name || '', placeholder: t('drive.pp.name.placeholder'), autocomplete: 'off' });
			const errEl = el('span', { class: 'dv-field-err', role: 'alert' });
			const sugs = el('div', { class: 'dpp-name-sugs', role: 'list', 'aria-label': t('drive.pp.name.fromFamily') });
			const alike = el('div', { class: 'dpp-alike' });
			const save = el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.pp.name.save') });
			const hide = el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.pp.person.hide') });
			const edit = el('div', { class: 'dpp-name-edit' }, [
				el('div', { class: 'dpp-name-head' }, [face(p.cover, { size: 56, name: p.name, id: p.id, unknown: !p.name }), headTx]),
				el('label', { class: 'lbl', for: inputId, text: t('drive.pp.name.label') }), input, errEl,
				el('div', { class: 'dpp-aside-h', text: t('drive.pp.name.fromFamily') }), sugs,
				alike,
			]);
			dlg.body.appendChild(edit);
			const fam = { list: [] };
			let mail = [];
			let mailTimer = null;
			const drawSugs = () => {
				clear(sugs);
				const list = PPS.nameChoices({ q: input.value, people: peopleNow(), family: fam.list, contacts: mail, self: p.id }, t);
				if (!list.length) { sugs.appendChild(el('p', { class: 'dv-p dpp-note', text: t('drive.pp.name.noSuggestions') })); }
				for (const s of list) {
					sugs.appendChild(el('button', { type: 'button', role: 'listitem', class: 'dpp-name-sug', on: { click: () => { input.value = s.name; contact = s.contact; drawSugs(); input.focus(); updateSave(); } } }, [
						el('span', { class: `dpp-face dpp-tone-${PPS.toneOf(s.name)}`, style: 'width:36px;height:36px;font-size:13px' }, [el('span', { class: 'dpp-ini', text: PPS.initials(s.name) })]),
						el('span', { class: 'dpp-pl-tx' }, [el('span', { class: 'dpp-pl-name', text: s.name }), el('span', { class: 'dpp-sub', text: s.sub })]),
					]));
				}
			};
			const updateSave = () => { save.disabled = !input.value.trim(); };
			input.addEventListener('input', () => {
				errEl.textContent = '';
				if (contact && contact.name !== input.value.trim()) contact = null;
				updateSave();
				drawSugs();
				clearTimeout(mailTimer);
				mailTimer = setTimeout(async () => { mail = await contacts(input.value); if (edit.isConnected) drawSugs(); }, 300);
			});
			input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
			updateSave();
			drawSugs();
			family().then((f) => { fam.list = f; if (edit.isConnected) drawSugs(); });
			Promise.resolve(api.person(p.id)).then((r) => { if (r && r.ok) { detail = r; sub.textContent = PPS.nameSub(r, { t, locale: locale() }); } }).catch(() => {});
			// "Sieht aus wie …"
			Promise.resolve(api.similarPeople(p.id)).then((r) => {
				const s = r && r.ok ? (r.people || []).find((x) => x.name) : null;
				if (!s || !alike.isConnected) return;
				const per = peopleNow().find((q) => String(q.id) === String(s.id));
				alike.append(el('div', { class: 'dpp-alike-card' }, [
					face(per && per.cover, { size: 44, name: s.name, id: s.id }),
					el('span', { class: 'dpp-pl-tx' }, [el('span', { class: 'dpp-pl-name', text: t('drive.pp.name.alike', { name: s.name }) }), el('span', { class: 'dpp-sub', text: t('drive.pp.name.alikeText') })]),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.pp.name.merge'), on: { click: () => merge(s) } }),
				]));
			}).catch(() => {});

			async function submit() {
				const e = PPS.nameError(input.value, t);
				if (e) { errEl.textContent = e; return; }
				save.disabled = true;
				const name = input.value.trim();
				const patch = { name };
				if (contact && contact.name === name) patch.contact = contact;
				const before = { name: p.name || '', contact: p.contact || null };
				const r = await Promise.resolve(api.updatePerson(p.id, patch)).catch(fail);
				save.disabled = false;
				if (!r || !r.ok) { errEl.textContent = err(r); return; }
				const count = (detail && detail.person && detail.person.count) || p.count || 0;
				if (r.mergedInto !== null && r.mergedInto !== undefined) finish({ kind: 'merge', title: t('drive.pp.name.mergedTitle', { name: r.person.name || name }), text: t('drive.pp.name.mergedText', { name: r.person.name || name, count: PPS.fmt(r.person.count, locale()) }) });
				else finish({ kind: 'save', title: t('drive.pp.name.savedTitle', { name }), text: t('drive.pp.name.savedText', { name, count: PPS.fmt(count, locale()) }), undo: () => api.updatePerson(p.id, before) });
			}

			async function merge(s) {
				const r = await Promise.resolve(api.mergePerson(p.id, s.id)).catch(fail);
				if (!r || !r.ok) { errEl.textContent = err(r); return; }
				finish({ kind: 'merge', title: t('drive.pp.name.mergedTitle', { name: s.name }), text: t('drive.pp.name.mergedText', { name: s.name, count: PPS.fmt(r.person.count, locale()) }) });
			}

			hide.addEventListener('click', async () => {
				const r = await Promise.resolve(api.updatePerson(p.id, { hidden: true })).catch(fail);
				if (!r || !r.ok) { errEl.textContent = err(r); return; }
				finish({ kind: 'hide', title: t('drive.pp.name.hiddenTitle'), text: t(`drive.pp.name.hiddenText.${p.count === 1 ? 'one' : 'other'}`, { count: PPS.fmt(p.count, locale()) }), undo: () => api.updatePerson(p.id, { hidden: false }) });
			});
			save.addEventListener('click', submit);

			/** The short confirmation: what happened, "Rückgängig" (not after merging), the next person without a name. */
			function finish(d) {
				done = d;
				clear(dlg.body);
				clear(dlg.foot);
				dlg.setTitle(d.title);
				dlg.body.appendChild(el('div', { class: 'dpp-done', role: 'status' }, [
					el('span', { class: 'dpp-done-ic' }, [icon('check', 26, '2.4')]),
					el('b', { class: 'dpp-name-h', text: d.title }),
					el('span', { class: 'dpp-sub', text: d.text }),
				]));
				const nextOne = () => PPS.groupPeople(peopleNow()).unnamed.find((q) => String(q.id) !== String(p.id));
				const undo = d.undo ? el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.pp.name.undo'), on: { click: async () => {
					const r = await Promise.resolve(d.undo()).catch(fail);
					if (!r || !r.ok) { toast(err(r), 'error'); return; }
					done = { kind: 'undo' };
					dlg.close(null);
				} } }) : null;
				const nx = rename ? null : nextOne();
				dlg.foot.append(el('span', { class: 'dv-grow' }), undo,
					nx ? el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.pp.name.next'), on: { click: async () => { dlg.close(null); await loadPeople({ quiet: true }); const n2 = nextOne(); if (n2) nameDialog(n2); } } })
						: el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.pp.name.finish'), on: { click: () => dlg.close(null) } }));
				if (S.open && S.open.kind === 'person' && d.kind === 'merge') S.open = null;
			}

			dlg.foot.append(el('span', { class: 'dv-grow' }), hide, save);
			setTimeout(() => { input.focus(); input.select(); }, 0);
		}

		// ── Search: suggestions while typing, marks ──────
		/** Suggestions under the search field `input` (inside `wrap`); onPick of a label / Enter → o.search(q). */
		function attachSuggest(input, wrap) {
			const list = el('div', { class: 'dpp-sug', role: 'listbox', id: nextId('dpp-sug'), hidden: true, 'aria-label': t('drive.pp.sug.title') });
			wrap.classList.add('dpp-sug-wrap');
			wrap.appendChild(list);
			input.setAttribute('aria-controls', list.id);
			input.setAttribute('aria-autocomplete', 'list');
			let rows = [];
			let active = -1;
			let timer = null;
			let seq = 0;
			const close = () => { list.hidden = true; active = -1; input.setAttribute('aria-expanded', 'false'); input.removeAttribute('aria-activedescendant'); };
			const choose = (r) => {
				close();
				if (r.kind === 'person') { if (o.resetInput) o.resetInput(); openPerson(r.id); }
				else if (r.kind === 'place') { if (o.resetInput) o.resetInput(); openPlace(r.key, { name: r.name }); }
				else { const q = PPS.withLabel(input.value, r.label); input.value = q; o.search(q); }
			};
			const draw = (q) => {
				clear(list);
				list.appendChild(el('div', { class: 'dpp-aside-h', text: t('drive.pp.sug.title') }));
				rows.forEach((r, i) => {
					const ic = r.kind === 'person'
						? face((peopleNow().find((x) => String(x.id) === String(r.id)) || {}).cover, { size: 36, name: r.name, id: r.id })
						: el('span', { class: `dpp-sug-ic is-${r.kind}` }, [icon(r.kind === 'place' ? 'pin' : 'image', 18)]);
					list.appendChild(el('div', { role: 'option', id: `${list.id}-${i}`, class: `dpp-sug-row${i === active ? ' is-on' : ''}`, 'aria-selected': i === active ? 'true' : 'false', 'data-kind': r.kind,
						on: { mousedown: (e) => { e.preventDefault(); choose(r); } } }, [
						ic, el('span', { class: 'dpp-pl-tx' }, [el('span', { class: 'dpp-pl-name', text: r.name }), el('span', { class: 'dpp-sub', text: r.sub })]), el('span', { class: 'dpp-n', text: r.count }),
					]));
				});
				if (!rows.length) list.appendChild(el('div', { class: 'dpp-sug-none', text: t('drive.pp.sug.none', { q }) }));
				list.appendChild(el('div', { class: 'dpp-sug-tip', text: t('drive.pp.sug.tip') }));
				list.hidden = false;
				input.setAttribute('aria-expanded', 'true');
				if (active >= 0) input.setAttribute('aria-activedescendant', `${list.id}-${active}`); else input.removeAttribute('aria-activedescendant');
			};
			const ask = async () => {
				const q = input.value.trim();
				const f = feats();
				if (!q || document.activeElement !== input || (!f.places && !f.people)) { close(); return; }
				const my = ++seq;
				const r = await Promise.resolve(api.photoSuggest(q)).catch(() => null);
				if (my !== seq || document.activeElement !== input) return;
				rows = r && r.ok ? PPS.suggestionRows(r, { t, locale: locale() }) : [];
				active = -1;
				draw(q);
			};
			input.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(ask, 220); });
			input.addEventListener('blur', () => setTimeout(close, 120));
			// capture: before the field's own Enter / Escape
			input.addEventListener('keydown', (e) => {
				if (list.hidden) return;
				if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
					e.preventDefault();
					if (!rows.length) return;
					active = e.key === 'ArrowDown' ? (active + 1) % rows.length : (active <= 0 ? rows.length - 1 : active - 1);
					draw(input.value.trim());
				} else if (e.key === 'Enter' && active >= 0) {
					e.preventDefault();
					e.stopImmediatePropagation();
					choose(rows[active]);
				} else if (e.key === 'Escape') {
					e.preventDefault();
					e.stopImmediatePropagation();
					close();
				} else if (e.key === 'Enter') close();
			}, true);
			return { close };
		}

		/** The people and places a search recognised: chips that open them. */
		function marksEl(marks) {
			const m = marks || {};
			const people = Array.isArray(m.people) ? m.people : [];
			const places = Array.isArray(m.places) ? m.places : [];
			if (!people.length && !places.length) return null;
			return el('div', { class: 'dpp-marks', role: 'group', 'aria-label': t('drive.pp.sug.marks') }, [
				el('span', { class: 'dpp-sub', text: t('drive.pp.sug.marks') }),
				...people.map((p) => el('button', { type: 'button', class: 'dpp-pchip', 'data-person': String(p.id), on: { click: () => openPerson(p.id) } }, [
					face((peopleNow().find((x) => String(x.id) === String(p.id)) || {}).cover, { size: 22, name: p.name, id: p.id }), el('span', { text: p.name }),
				])),
				...places.map((p) => el('button', { type: 'button', class: 'dpp-pchip is-place', 'data-key': p.key, on: { click: () => openPlace(p.key, { name: p.name }) } }, [
					el('span', { class: 'dpp-sug-ic is-place' }, [icon('pin', 13)]), el('span', { text: p.name }),
				])),
			]);
		}

		/** "Hamburg · Altona" of a photo (the lightbox) or '' */
		function placeText(p) {
			const pl = p && p.geo && p.geo.place;
			return pl ? [pl.name, pl.district].filter(Boolean).join(' · ') : '';
		}

		return {
			/** Draws the open place / person, else the tab ('map' | 'people') into `body`; false when there is nothing to draw. */
			render(tab, body) {
				body.classList.remove('is-map');
				if (S.open && S.open.kind === 'place') { renderPlace(body, S.open); return true; }
				if (S.open && S.open.kind === 'person') { renderPerson(body, S.open); return true; }
				if (tab === 'map' && feats().places) { renderMap(body); return true; }
				if (tab === 'people' && feats().people) { renderPeople(body); return true; }
				return false;
			},
			/** A tab was opened: load what it shows. */
			show(tab) {
				S.open = null;
				if (tab === 'people') loadPeople();
				if (tab === 'map') loadPlaces();
			},
			hasOpen: () => !!S.open,
			close() { S.open = null; },
			refresh(tab) {
				if (S.open) { loadOpen(); return; }
				if (tab === 'people') loadPeople({ quiet: true });
				if (tab === 'map') loadPlaces().then(() => loadClusters());
			},
			openPlace, openPerson, attachSuggest, marksEl, placeText, nameDialog,
		};
	}

	root.GCDrivePlacesPeopleView = { create };
})(typeof self !== 'undefined' ? self : this);
