/**
 * GateControl -- Drive "Orte und Personen" view state (renderer, no DOM access)
 *
 * Pure helpers of the places and people of the view "Fotos" (Drive 1.16 'photoPlaces' / 'photoPeople'): which
 * switches the view has (Zeitachse | Karte | Personen | Alben), the map (Web Mercator, 256 px OpenStreetMap tiles,
 * the box of the view, a view that fits the places), the list "Orte im Bild" of the clusters in view, the texts of a
 * place (time span, districts, photos by day), the people (named / "Wer ist das?" / hidden, the progress of the
 * recognition, initials and a colour per person, the face cut out of a photo), a person (photos, years, the link to a
 * family member or contact), the suggestions while typing, the names offered when naming, and the settings rows.
 * Loaded as a plain script before drive-places-people-view.js (window.GCDrivePlacesPeopleState) and required by the
 * node tests (test/drive-116-state.test.js).
 *
 * Inputs are what window.gatecontrol.drive returns (core DriveService, answers cleaned by core utils/drive.js); `t`
 * is the i18n function (keys drive.pp.* of the app locales).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDrivePlacesPeopleState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const localeTag = (l) => (l === 'en' ? 'en-GB' : 'de-DE');
	const arr = (v) => (Array.isArray(v) ? v : []);

	function plural(t, key, n, locale = 'de') {
		const count = Number(n) || 0;
		return t(`${key}.${count === 1 ? 'one' : 'other'}`, { count: fmt(count, locale) });
	}

	/** 1204 → "1.204" (de) / "1,204" (en) */
	function fmt(n, locale = 'de') {
		const v = Number(n) || 0;
		try { return v.toLocaleString(localeTag(locale)); } catch { return String(v); }
	}

	/** Which of the new parts this Drive offers: { places, people } (me.features). */
	function features(me) {
		const f = me && Array.isArray(me.features) ? me.features : [];
		return { places: f.includes('photoPlaces'), people: f.includes('photoPeople') };
	}

	/** The switch of the view: Zeitachse | Karte | Personen (| Alben) → [{ key, label }] */
	function segments(me, t) {
		const f = features(me);
		const all = me && Array.isArray(me.features) ? me.features : [];
		return [
			{ key: 'timeline', label: t('drive.pp.seg.timeline') },
			f.places ? { key: 'map', label: t('drive.pp.seg.map') } : null,
			f.people ? { key: 'people', label: t('drive.pp.seg.people') } : null,
			all.includes('albums') ? { key: 'albums', label: t('drive.photos.albums') } : null,
		].filter(Boolean);
	}

	// ── Map (Web Mercator, 256 px tiles) ─────────────────

	const TILE = 256;
	const MIN_ZOOM = 2;
	const MAX_ZOOM = 18;
	const MAX_LAT = 85.05112878;

	const clampZoom = (z) => Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, Math.round(Number(z) || MIN_ZOOM)));

	/** lat/lon → world pixel at zoom z ({ x, y }, 0 … 256·2^z). */
	function worldPx(lat, lon, z) {
		const size = TILE * 2 ** z;
		const la = Math.max(-MAX_LAT, Math.min(MAX_LAT, Number(lat) || 0));
		const s = Math.sin((la * Math.PI) / 180);
		return { x: ((Number(lon) || 0) + 180) / 360 * size, y: (0.5 - Math.log((1 + s) / (1 - s)) / (4 * Math.PI)) * size };
	}

	/** World pixel at zoom z → { lat, lon } (longitude wrapped to −180 … 180). */
	function lonLat(x, y, z) {
		const size = TILE * 2 ** z;
		let lon = (x / size) * 360 - 180;
		lon = ((((lon + 180) % 360) + 360) % 360) - 180;
		const n = Math.PI - (2 * Math.PI * Math.max(0, Math.min(size, y))) / size;
		return { lat: (180 / Math.PI) * Math.atan(0.5 * (Math.exp(n) - Math.exp(-n))), lon };
	}

	/** Tiles covering a w × h view whose centre is world pixel (cx, cy) at zoom z → [{ key, z, x, y, left, top }] */
	function tileGrid(cx, cy, z, w, h) {
		const n = 2 ** z;
		const x0 = cx - w / 2;
		const y0 = cy - h / 2;
		const out = [];
		for (let ty = Math.floor(y0 / TILE); ty <= Math.floor((y0 + h - 1) / TILE); ty++) {
			if (ty < 0 || ty >= n) continue;
			for (let tx = Math.floor(x0 / TILE); tx <= Math.floor((x0 + w - 1) / TILE); tx++) {
				out.push({ key: `${z}/${tx}/${ty}`, z, x: ((tx % n) + n) % n, y: ty, left: Math.round(tx * TILE - x0), top: Math.round(ty * TILE - y0) });
			}
		}
		return out;
	}

	const round6 = (v) => Math.round(v * 1e6) / 1e6;

	/** The box [w, s, e, n] of a view (centre world pixel, zoom, size); the whole width when it spans the world. */
	function viewBbox(cx, cy, z, w, h) {
		const size = TILE * 2 ** z;
		const a = lonLat(cx - w / 2, cy - h / 2, z);
		const b = lonLat(cx + w / 2, cy + h / 2, z);
		if (w >= size) return [-180, round6(b.lat), 180, round6(a.lat)];
		return [round6(a.lon), round6(b.lat), round6(b.lon), round6(a.lat)];
	}

	/** A view showing every point ({ lat, lon }) in w × h with some margin → { lat, lon, zoom } (Germany without points). */
	function fitView(points, w, h, { maxZoom = 13, pad = 60 } = {}) {
		const pts = arr(points).filter((p) => p && Number.isFinite(p.lat) && Number.isFinite(p.lon));
		if (!pts.length) return { lat: 51.1657, lon: 10.4515, zoom: 5 };
		const la = pts.map((p) => p.lat);
		const lo = pts.map((p) => p.lon);
		const box = { n: Math.max(...la), s: Math.min(...la), e: Math.max(...lo), w: Math.min(...lo) };
		const lat = (box.n + box.s) / 2;
		const lon = (box.e + box.w) / 2;
		const ww = Math.max(64, (Number(w) || 0) - pad * 2);
		const hh = Math.max(64, (Number(h) || 0) - pad * 2);
		for (let z = maxZoom; z > MIN_ZOOM; z--) {
			const a = worldPx(box.n, box.w, z);
			const b = worldPx(box.s, box.e, z);
			if (b.x - a.x <= ww && b.y - a.y <= hh) return { lat, lon, zoom: z };
		}
		return { lat, lon, zoom: MIN_ZOOM };
	}

	/** Where a cluster sits in the view (px from its top left), its position at the date line taken nearest the centre. */
	function screenPos(lat, lon, cx, cy, z, w, h) {
		const size = TILE * 2 ** z;
		const p = worldPx(lat, lon, z);
		let dx = p.x - cx;
		if (dx > size / 2) dx -= size;
		if (dx < -size / 2) dx += size;
		return { x: Math.round(w / 2 + dx), y: Math.round(h / 2 + p.y - cy) };
	}

	// ── Places ───────────────────────────────────────────

	/** A month of a time → "Juli 2025" / "July 2025" */
	function monthText(ms, locale) {
		return new Date(ms).toLocaleDateString(localeTag(locale), { month: 'long', year: 'numeric' });
	}

	/** When the photos of a place were taken: "August 2023" / "März – Juli 2026" / "2014 – 2026" or '' */
	function spanText(from, to, locale) {
		if (!Number.isFinite(from) || !Number.isFinite(to)) return Number.isFinite(from || to) ? monthText(from || to, locale) : '';
		const a = new Date(Math.min(from, to));
		const b = new Date(Math.max(from, to));
		if (a.getFullYear() !== b.getFullYear()) return `${a.getFullYear()} – ${b.getFullYear()}`;
		if (a.getMonth() === b.getMonth()) return monthText(a.getTime(), locale);
		return `${a.toLocaleDateString(localeTag(locale), { month: 'long' })} – ${monthText(b.getTime(), locale)}`;
	}

	/** "DE" → "Deutschland" / "Germany" (Intl), else the code */
	function countryName(code, locale) {
		if (!/^[A-Z]{2}$/.test(str(code))) return '';
		try { return new Intl.DisplayNames([localeTag(locale)], { type: 'region' }).of(code) || code; } catch { return code; }
	}

	/** Region and country of a place ("Hamburg · Deutschland"), the region left out when it is the place's name. */
	function placeWhere(place, locale) {
		const p = place || {};
		return [p.region && p.region !== p.name ? p.region : '', countryName(p.country, locale)].filter(Boolean).join(' · ');
	}

	/** Is a point inside a box [w, s, e, n] (w > e: across the date line)? */
	function inBox(lat, lon, box) {
		if (!Array.isArray(box) || box.length !== 4 || !Number.isFinite(lat) || !Number.isFinite(lon)) return false;
		const [w, s, e, n] = box;
		return lat >= s && lat <= n && (w <= e ? lon >= w && lon <= e : lon >= w || lon <= e);
	}

	/**
	 * "Orte im Bild": the places in the box of the view (photos/places, with all their photos) and the places of the
	 * clusters there that are one place, most photos first, with the time span → [{ key, name, sub, count, cover }].
	 * A cluster of several places only shows on the map; its places are in the list by their position.
	 */
	function placeRows(clusters, places, { locale, bbox = null } = {}) {
		const byKey = new Map(arr(places).map((p) => [p.key, p]));
		const rows = new Map();
		for (const p of arr(places)) {
			if (bbox && inBox(p.lat, p.lon, bbox)) rows.set(p.key, { key: p.key, count: Number(p.count) || 0, cover: p.cover || null, whole: true });
		}
		for (const c of arr(clusters)) {
			if (!c || !c.key) continue;
			const r = rows.get(c.key) || { key: c.key, count: 0, cover: c.cover || null, whole: false };
			if (!r.whole) r.count += Number(c.count) || 0;
			if (!r.cover && c.cover) r.cover = c.cover;
			rows.set(c.key, r);
		}
		return [...rows.values()].map((r) => {
			const p = byKey.get(r.key);
			return { key: r.key, name: p ? p.name : '', sub: p ? (spanText(p.from, p.to, locale) || placeWhere(p, locale)) : '', count: r.count, cover: r.cover || (p && p.cover) || null };
		}).filter((r) => r.name).sort((a, b) => b.count - a.count);
	}

	const dayKey = (ms) => { const d = new Date(ms); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };

	/**
	 * The photos of a place by day (newest first) → [{ key, label: "Sa., 14. März 2026", sub: "Altona · 22", items }];
	 * the district most photos of that day were taken in.
	 */
	function byDay(items, { locale, t } = {}) {
		const out = [];
		const map = new Map();
		for (const p of arr(items)) {
			const key = Number.isFinite(p.takenAt) ? dayKey(p.takenAt) : 'none';
			let g = map.get(key);
			if (!g) { g = { key, at: p.takenAt, items: [] }; map.set(key, g); out.push(g); }
			g.items.push(p);
		}
		out.sort((a, b) => (a.key === 'none') - (b.key === 'none') || (a.key < b.key ? 1 : a.key > b.key ? -1 : 0));
		return out.map((g) => {
			const d = new Map();
			for (const p of g.items) { const x = p.geo && p.geo.place && p.geo.place.district; if (x) d.set(x, (d.get(x) || 0) + 1); }
			const top = [...d].sort((a, b) => b[1] - a[1])[0];
			const label = g.key === 'none' ? t('drive.photos.noDate') : new Date(g.at).toLocaleDateString(localeTag(locale), { weekday: 'short', day: 'numeric', month: 'long', year: 'numeric' });
			return { key: g.key, label, sub: [top ? top[0] : '', fmt(g.items.length, locale)].filter(Boolean).join(' · '), items: g.items };
		});
	}

	/** The line under a place's name: "214 Fotos · 12 Tage · St. Pauli, Altona, HafenCity" */
	function placeSub({ count = 0, items = [], districts = [] } = {}, { t, locale } = {}) {
		const days = new Set(arr(items).filter((p) => Number.isFinite(p.takenAt)).map((p) => dayKey(p.takenAt))).size;
		return [
			plural(t, 'drive.pp.photos', count, locale),
			days ? plural(t, 'drive.pp.days', days, locale) : '',
			arr(districts).slice(0, 3).map((d) => d.name).join(', '),
		].filter(Boolean).join(' · ');
	}

	/** The people on photos (items with `people`), most first, by their names (people of GET people) → [{ id, name, count }] */
	function peopleOn(items, people) {
		const names = new Map(arr(people).filter((p) => p && p.name && !p.hidden).map((p) => [String(p.id), p]));
		const n = new Map();
		for (const it of arr(items)) for (const id of arr(it.people)) if (names.has(String(id))) n.set(String(id), (n.get(String(id)) || 0) + 1);
		return [...n].map(([id, count]) => ({ id: names.get(id).id, name: names.get(id).name, count })).sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
	}

	// ── People ───────────────────────────────────────────

	/** "Oma Gerda" → "OG", "lea" → "L" */
	function initials(name) {
		const w = str(name).trim().split(/\s+/).filter(Boolean);
		return w.slice(0, 2).map((x) => x.charAt(0).toUpperCase()).join('') || '?';
	}

	const TONES = 5;
	/** A colour (0 … 4: the app's error / warn / info / accent / pro tones) per person, the same on every redraw. */
	function toneOf(id) {
		let h = 0;
		for (const c of str(id)) h = (h * 31 + c.charCodeAt(0)) >>> 0;
		return h % TONES;
	}

	/** GET people → { named (most photos first), unnamed, hidden } */
	function groupPeople(people) {
		const list = arr(people).filter(Boolean);
		const byCount = (a, b) => b.count - a.count || str(a.name).localeCompare(str(b.name));
		return {
			named: list.filter((p) => !p.hidden && p.name).sort(byCount),
			unnamed: list.filter((p) => !p.hidden && !p.name).sort(byCount),
			hidden: list.filter((p) => p.hidden).sort(byCount),
		};
	}

	/**
	 * "Wer ist das?" one after the other: the next person without a name (most photos first) that this round has not
	 * shown yet. `seen` holds the ids the round has shown (named, hidden, merged or skipped); null ends the round
	 * ("Alle durchgesehen"). Works on an old list too (GET people failed): nobody comes back.
	 */
	function nextToName(people, seen) {
		const s = new Set([...(seen instanceof Set ? seen : arr(seen))].map(str));
		return groupPeople(people).unnamed.find((p) => !s.has(str(p.id))) || null;
	}

	/** The head line of "Personen": "5 benannt · 9 noch ohne Namen" */
	function peopleSub(groups, t, locale) {
		const g = groups || { named: [], unnamed: [] };
		return [plural(t, 'drive.pp.people.named', g.named.length, locale), g.unnamed.length ? plural(t, 'drive.pp.people.unnamedN', g.unnamed.length, locale) : ''].filter(Boolean).join(' · ');
	}

	/** The recognition's progress → { text: "4.120 von 6.212 Fotos", pct: 66, done } or null (nothing to recognise). */
	function progressOf(progress, { t, locale } = {}) {
		if (!progress || !Number.isFinite(progress.total) || progress.total <= 0) return null;
		const done = Math.min(progress.done || 0, progress.total);
		return { text: t('drive.pp.progress.count', { done: fmt(done, locale), total: fmt(progress.total, locale) }), pct: Math.round((done / progress.total) * 100), done: done >= progress.total };
	}

	/**
	 * The face of `box` ([x, y, w, h], 0 … 1) cut out of a picture of W × H into a round frame of `size` px: the image's
	 * width, height and offset → { width, height, left, top } (the face in the middle with some room around it).
	 */
	function faceCrop(box, W, H, size, room = 1.7) {
		if (!Array.isArray(box) || box.length !== 4 || !(W > 0) || !(H > 0) || !(size > 0)) return null;
		const [x, y, w, h] = box;
		const side = Math.max(w * W, h * H) * room;
		const c = Math.min(Math.max(side, 8), Math.min(W, H) * 1.0 || side);
		const cx = (x + w / 2) * W;
		const cy = (y + h / 2) * H;
		const k = size / c;
		let left = -(cx - c / 2) * k;
		let top = -(cy - c / 2) * k;
		// keep the picture covering the frame
		left = Math.min(0, Math.max(size - W * k, left));
		top = Math.min(0, Math.max(size - H * k, top));
		return { width: Math.round(W * k), height: Math.round(H * k), left: Math.round(left), top: Math.round(top) };
	}

	/** "2016 – 2026" / "2026" / '' */
	function yearsText(years) {
		if (!years || !Number.isFinite(years.from) || !Number.isFinite(years.to)) return '';
		return years.from === years.to ? String(years.from) : `${years.from} – ${years.to}`;
	}

	/** The line under a person's name: "812 Fotos · 2016 – 2026" */
	function personSub(detail, { t, locale } = {}) {
		const d = detail || {};
		const p = d.person || {};
		return [plural(t, 'drive.pp.photos', p.count || 0, locale), yearsText(d.years)].filter(Boolean).join(' · ');
	}

	/** "Verknüpft mit Familie › Lea" / "Verknüpft mit Kontakt › Klaus Kramer" or '' */
	function contactText(contact, t) {
		if (!contact || !contact.name) return '';
		return t(contact.kind === 'family' ? 'drive.pp.person.linkedFamily' : 'drive.pp.person.linkedContact', { name: contact.name });
	}

	/** The photos of a person by year (newest first) → [{ key, label, items }] */
	function byYear(items, t) {
		const out = [];
		const map = new Map();
		for (const p of arr(items)) {
			const key = Number.isFinite(p.takenAt) ? String(new Date(p.takenAt).getFullYear()) : 'none';
			let g = map.get(key);
			if (!g) { g = { key, label: key === 'none' ? t('drive.photos.noDate') : key, items: [] }; map.set(key, g); out.push(g); }
			g.items.push(p);
		}
		return out.sort((a, b) => (a.key === 'none') - (b.key === 'none') || (a.key < b.key ? 1 : a.key > b.key ? -1 : 0));
	}

	/** "Ist das auch …?": the first faces and how many more → { shown, more } */
	function uncertainPreview(faces, n = 4) {
		const list = arr(faces);
		return { shown: list.slice(0, n), more: Math.max(0, list.length - n) };
	}

	/** The headline of the naming dialog's sub line: "64 Fotos · 2019 – 2026 · oft mit Mama" */
	function nameSub(detail, { t, locale } = {}) {
		const d = detail || {};
		const p = d.person || {};
		const with1 = arr(d.together)[0];
		return [plural(t, 'drive.pp.photos', p.count || 0, locale), yearsText(d.years), with1 && with1.name ? t('drive.pp.name.oftenWith', { name: with1.name }) : ''].filter(Boolean).join(' · ');
	}

	/**
	 * Names offered when naming ("Aus Familie und Kontakten"): the people Drive knows already (named), the family
	 * (GateControl's people of the household) and contacts (Mail) that match what was typed (word starts, any case) →
	 * [{ name, sub, contact, personId }] (at most `max`, no name twice).
	 */
	function nameChoices({ q = '', people = [], family = [], contacts = [], self = null, max = 3 } = {}, t) {
		const query = str(q).trim().toLowerCase();
		const hit = (name) => {
			if (!query) return true;
			const n = str(name).toLowerCase();
			return n.startsWith(query) || n.split(/\s+/).some((w) => w.startsWith(query));
		};
		const out = [];
		const seen = new Set();
		const add = (x) => {
			const k = x.name.toLowerCase();
			if (!x.name || seen.has(k) || out.length >= max) return;
			seen.add(k);
			out.push(x);
		};
		for (const p of arr(people)) {
			if (!p || !p.name || p.hidden || (self !== null && String(p.id) === String(self)) || !hit(p.name)) continue;
			add({ name: p.name, sub: p.contact && p.contact.kind === 'family' ? t('drive.pp.name.familyNamed', { count: fmt(p.count) }) : t('drive.pp.name.named', { count: fmt(p.count) }), contact: p.contact || null, personId: p.id });
		}
		for (const f of arr(family)) {
			if (!f || !f.name || !hit(f.name)) continue;
			add({ name: f.name, sub: t('drive.pp.name.family'), contact: { kind: 'family', id: f.id, name: f.name }, personId: null });
		}
		for (const c of arr(contacts)) {
			if (!c || !c.name || !hit(c.name)) continue;
			add({ name: c.name, sub: c.email ? t('drive.pp.name.contactMail', { email: c.email }) : t('drive.pp.name.contact'), contact: { kind: 'contact', id: c.contactId || c.email, name: c.name }, personId: null });
		}
		return out;
	}

	/** null when a name is fine, else the text */
	function nameError(raw, t) {
		const s = str(raw).trim();
		if (!s) return t('drive.pp.name.empty');
		if (s.length > 200) return t('drive.pp.name.long');
		return null;
	}

	// ── Search ───────────────────────────────────────────

	/**
	 * The suggestions while typing (photos/suggest) → [{ kind: 'person' | 'place' | 'label', id, key, label, name, sub,
	 * count }] (people, then places, then what is on the photos).
	 */
	function suggestionRows(sug, { t, locale } = {}) {
		const s = sug || {};
		return [
			...arr(s.people).map((p) => ({ kind: 'person', id: p.id, name: p.name, sub: t('drive.pp.sug.person'), count: fmt(p.count, locale) })),
			...arr(s.places).map((p) => ({ kind: 'place', key: p.key, name: p.name, sub: p.sub ? t('drive.pp.sug.placeIn', { sub: p.sub }) : t('drive.pp.sug.place'), count: fmt(p.count, locale) })),
			...arr(s.labels).map((l) => ({ kind: 'label', label: l.label, name: l.text || l.label, sub: t('drive.pp.sug.label'), count: fmt(l.count, locale) })),
		];
	}

	/** The query after a label was picked: its last (unfinished) word becomes the label. */
	function withLabel(q, label) {
		const words = str(q).trim().split(/\s+/).filter(Boolean);
		if (words.length) words.pop();
		words.push(str(label));
		return words.join(' ');
	}

	// ── Settings ─────────────────────────────────────────

	/**
	 * The rows of "Orte und Personen" in the settings (Mockup 7) → { places: [{ key, on }], people: { on, rows } } —
	 * stripGeoOnShare only when Drive reports it; the people's rows only while it is on.
	 */
	function settingsRows(s, me) {
		const f = features(me);
		const x = s || {};
		return {
			places: f.places ? [{ key: 'keepGeo', on: x.keepGeo !== false }, typeof x.stripGeoOnShare === 'boolean' ? { key: 'stripGeoOnShare', on: x.stripGeoOnShare } : null].filter(Boolean) : null,
			people: f.people ? { on: !!x.people, rows: x.people ? [{ key: 'peopleKids', on: !!x.peopleKids }] : [] } : null,
		};
	}

	return {
		fmt, features, segments,
		TILE, MIN_ZOOM, MAX_ZOOM, clampZoom, worldPx, lonLat, tileGrid, viewBbox, fitView, screenPos,
		spanText, countryName, placeWhere, inBox, placeRows, byDay, placeSub, peopleOn,
		initials, toneOf, groupPeople, nextToName, peopleSub, progressOf, faceCrop, yearsText, personSub, contactText, byYear, uncertainPreview, nameSub, nameChoices, nameError,
		suggestionRows, withLabel, settingsRows,
	};
});
