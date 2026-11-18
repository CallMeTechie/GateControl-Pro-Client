/**
 * GateControl -- Meine Orte, view state (renderer, no DOM access)
 *
 * Pure helpers of the page „Meine Orte“ (Mein Profil › Meine Orte, GateControl ≥ 1.299) and of the one place choice
 * of the forms (Chats: the place of an event). Loaded as a plain script before places-view.js
 * (window.GCPlacesState) and required by the node tests (test/places-state.test.js).
 *
 * - The page: the list (own places with „Genutzt von“ and „kein Standort“, Familie places only to look at), the
 *   editor's draft and what a change sends — only what differs (diffBody, the same rules as the core's
 *   utils/places.js: lat and lon together, an emptied address null), the radius in steps of 50 m, the texts of
 *   refusals.
 * - The choice (ported from the Android app's PlacePicking.kt): at most three chips plus „Alle Orte…“ (1. the chosen
 *   one, 2. the most used, 3. filled with the nearest), the sheet with „Zuletzt genutzt“, „In der Nähe“ and A–Z, the
 *   local search, address hits that are no place yet. This PC has no position: „In der Nähe“ is measured from the
 *   chosen place, else from „Zuhause“, else the group is left out.
 *
 * Inputs are what window.gatecontrol.places (core PlacesService, answers cleaned by core utils/places.js) and
 * chat.pickPlaces() (Messenger 1.28 `profilePlaces`, core utils/messenger.js normalizePickPlace) return; `t` is the
 * i18n function (keys places.* of the Pro locales).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCPlacesState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const ICONS = Object.freeze(['home', 'work', 'school', 'gym', 'shop', 'family', 'pin']);
	const VISIBILITY = Object.freeze(['self', 'family', 'all']);
	const RADIUS = Object.freeze({ min: 50, max: 2000, step: 50, default: 150 });
	const NAME_MAX = 60;
	const ADDRESS_MAX = 200;
	const SEARCH_MIN = 3;
	const SEARCH_MAX = 120;
	const CHIPS_MAX = 3;
	const RECENT_MAX = 3;
	const NEAR_M = 5000;
	const SAME_POINT_M = 30;
	const KINDS = Object.freeze(['task', 'location_message', 'reminder', 'rule']);

	const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : (typeof v === 'string' && /^\s*-?\d+(?:\.\d+)?\s*$/.test(v) ? Number(v) : null));
	const round6 = (v) => Math.round(v * 1e6) / 1e6;
	// eslint-disable-next-line no-control-regex
	const CTRL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g;

	/** One line: control characters → spaces, spaces folded, trimmed, at most `max`. */
	function line(v, max) {
		if (typeof v !== 'string') return '';
		return v.replace(CTRL_RE, ' ').replace(/\s+/g, ' ').trim().slice(0, max).trim();
	}

	/** A real point: within range and never 0/0. */
	function hasPoint(lat, lon) {
		return Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180 && !(lat === 0 && lon === 0);
	}

	const iconOf = (v) => (ICONS.includes(v) ? v : 'pin');
	const visibilityOf = (v) => (VISIBILITY.includes(v) ? v : 'self');

	/** The radius of the slider: 50 … 2000 in steps of 50 (a server value in between is rounded to the next step). */
	function snapRadius(v, limits) {
		const r = (limits && limits.radius) || RADIUS;
		const n = num(v);
		if (n === null) return r.default || RADIUS.default;
		const s = Math.round(n / RADIUS.step) * RADIUS.step;
		return Math.min(r.max || RADIUS.max, Math.max(r.min || RADIUS.min, s));
	}

	/** „{{n}} Orte“: the `_one` / `_other` key by the count. */
	function plural(t, key, n, params) {
		return t(`${key}_${n === 1 ? 'one' : 'other'}`, { n, ...(params || {}) });
	}

	// ── The page ─────────────────────────────────────────

	/** Lower case, without accents and „ß“: „Bäckerei“ matches „backerei“. */
	function normalize(s) {
		return String(s || '').toLowerCase().replace(/ß/g, 'ss').normalize('NFD').replace(/[̀-ͯ]/g, '').trim();
	}

	const byName = (a, b) => {
		const c = normalize(a.name).localeCompare(normalize(b.name), 'de');
		return c || String(a.key || a.id || '').localeCompare(String(b.key || b.id || ''));
	};

	/**
	 * The page's lists: { mine (own places, by name), familie (Familie places of the choice's source, by name),
	 * missing (own places without a point) }. `pick`: the answer of chat.pickPlaces() or null.
	 */
	function pageLists(list, pick) {
		const mine = ((list && list.places) || []).filter((p) => p && p.own !== false).slice().sort(byName);
		const familie = ((pick && pick.places) || []).filter((p) => p && p.source === 'familie').map((p) => ({ ...p, key: p.ref })).sort(byName);
		return { mine, familie, missing: mine.filter((p) => !p.hasPoint).length };
	}

	/** „Lindenweg 12 · 150 m · Familie“ — the grey line of an own place in the list. */
	function placeLine(p, t) {
		if (!p) return '';
		if (!p.hasPoint) return [t('places.noPoint'), p.address].filter(Boolean).join(' · ');
		return [p.address, t('places.radiusShort', { m: p.radiusM }), t(`places.visShort.${visibilityOf(p.visibility)}`)].filter(Boolean).join(' · ');
	}

	/** „Genutzt von“ in words: [{ plugin, text: 'Notizen · 2 Aufgaben' }]. */
	function usedByLines(usedBy, t) {
		return (Array.isArray(usedBy) ? usedBy : []).filter((u) => u && u.count > 0).map((u) => {
			const what = KINDS.includes(u.kind) ? plural(t, `places.use.${u.kind}`, u.count) : t('places.use.other', { n: u.count });
			return { plugin: u.plugin, text: t('places.useLine', { plugin: u.pluginName || u.plugin, what }) };
		});
	}

	/** How many plugins use the place (the short mark of the list), 0 for none. */
	const pluginsUsing = (p) => new Set(((p && p.usedBy) || []).filter((u) => u && u.count > 0).map((u) => u.plugin)).size;

	/** The editor's draft of a place (null: a new one) — the radius snapped to the slider's steps. */
	function draftOf(p, limits) {
		if (!p) return { name: '', icon: 'pin', lat: null, lon: null, radiusM: snapRadius(null, limits), address: '', visibility: 'self' };
		return {
			name: p.name || '', icon: iconOf(p.icon), lat: p.hasPoint ? p.lat : null, lon: p.hasPoint ? p.lon : null,
			radiusM: snapRadius(p.radiusM, limits), address: p.address || '', visibility: visibilityOf(p.visibility),
		};
	}

	/** What keeps the draft from being saved: 'name' | 'point' | null. */
	function draftProblem(d) {
		if (!d || !line(d.name, NAME_MAX)) return 'name';
		if (!hasPoint(d.lat, d.lon)) return 'point';
		return null;
	}

	/** POST body of a new place from the draft (only the keys the server knows; no empty address). */
	function createBody(d) {
		const b = { name: line(d.name, NAME_MAX), lat: round6(d.lat), lon: round6(d.lon), icon: iconOf(d.icon), radiusM: snapRadius(d.radiusM), visibility: visibilityOf(d.visibility) };
		const a = line(d.address, ADDRESS_MAX);
		if (a) b.address = a;
		return b;
	}

	/**
	 * The draft against the place it changes → only what differs (core utils/places.js diffBody): lat and lon together,
	 * an emptied address as null. `{}`: nothing changed.
	 */
	function diffBody(old, d) {
		const o = old || {};
		const n = createBody(d);
		const b = {};
		if (n.name !== o.name) b.name = n.name;
		if (n.icon !== iconOf(o.icon)) b.icon = n.icon;
		if (!hasPoint(o.lat, o.lon) || round6(o.lat) !== n.lat || round6(o.lon) !== n.lon) { b.lat = n.lat; b.lon = n.lon; }
		if (n.radiusM !== o.radiusM) b.radiusM = n.radiusM;
		const addr = n.address || null;
		if (addr !== (o.address || null)) b.address = addr;
		if (n.visibility !== visibilityOf(o.visibility)) b.visibility = n.visibility;
		return b;
	}

	/** The visibilities to offer: „Familie“ only to a person in a family. */
	function visibilityChoices(family, current) {
		return VISIBILITY.filter((v) => v !== 'family' || family === true || current === 'family');
	}

	/** A refusal of places:* in words. */
	function errorText(r, t, limits) {
		const code = (r && r.code) || 'other';
		if (code === 'limit') return t('places.err.limit', { n: (limits && limits.places) || 100 });
		if (code === 'duplicate' || code === 'invalid' || code === 'not_found' || code === 'rate_limited' || code === 'unsupported') return t(`places.err.${code}`);
		if (r && (r.status === 0 || code === 'network' || code === 'offline' || code === 'timeout' || code === 'unreachable')) return t('places.err.offline');
		return t('places.err.other');
	}

	/** A refusal of the address search in words. */
	function searchErrorText(r, t) {
		const code = r && r.code;
		if (code === 'rate_limited') return r.retryAfter ? plural(t, 'places.searchBusyMin', Math.max(1, Math.ceil(r.retryAfter / 60))) : t('places.searchBusy');
		if (code === 'search_off') return t('places.searchOff');
		if (code === 'invalid' && r.field === 'q') return t('places.searchMin');
		return t('places.searchDown');
	}

	// ── The place choice (PlacePicking.kt) ───────────────

	/** Great-circle distance in metres (haversine). */
	function distanceM(lat1, lon1, lat2, lon2) {
		const R = 6371000;
		const rad = (d) => (d * Math.PI) / 180;
		const dLat = rad(lat2 - lat1);
		const dLon = rad(lon2 - lon1);
		const a = Math.sin(dLat / 2) ** 2 + Math.cos(rad(lat1)) * Math.cos(rad(lat2)) * Math.sin(dLon / 2) ** 2;
		return Math.round(2 * R * Math.asin(Math.sqrt(Math.min(1, Math.max(0, a)))));
	}

	/** How far `o` is from `here` ({ lat, lon }), or null (no anchor, or the place has no point). */
	function distanceOf(o, here) {
		if (!here || !o || !hasPoint(o.lat, o.lon)) return null;
		return distanceM(here.lat, here.lon, o.lat, o.lon);
	}

	/** „850 m“, „3,4 km“, „12 km“ — the decimal sign of the locale. */
	function distanceText(m, locale) {
		if (m < 1000) return `${Math.round(m / 10) * 10} m`;
		if (m < 10000) return `${(m / 1000).toLocaleString(locale === 'en' ? 'en' : 'de', { minimumFractionDigits: 1, maximumFractionDigits: 1 })} km`;
		return `${Math.round(m / 1000)} km`;
	}

	/** The letter of the A–Z group: the first letter without accent, „#“ for anything else. */
	function letterOf(name) {
		const c = normalize(name).charAt(0);
		return c >= 'a' && c <= 'z' ? c.toUpperCase() : '#';
	}

	const timeMs = (v) => { const ms = typeof v === 'string' ? Date.parse(v) : NaN; return Number.isFinite(ms) ? ms : null; };

	/**
	 * A choice: { key, ref, id, name, icon, lat, lon, radiusM, address, familie, usage, lastUsedMs, rank }. `ref` null:
	 * a point used only in this form (a hit of the address search).
	 */
	function option(p, rank) {
		if (!p || typeof p !== 'object') return null;
		const name = line(p.name, 80);
		if (!name) return null;
		const lat = num(p.lat);
		const lon = num(p.lon);
		const point = hasPoint(lat, lon);
		const ref = typeof p.ref === 'string' && p.ref ? p.ref : null;
		const familie = p.source === 'familie' || (!!ref && !ref.startsWith('profile:'));
		const profileId = ref && /^profile:[1-9]\d{0,15}$/.test(ref) ? Number(ref.slice(8)) : null;
		return {
			key: ref || `point:${point ? lat : '-'},${point ? lon : '-'}`,
			ref, id: p.id !== undefined ? p.id : profileId, profileId, name, icon: iconOf(p.icon),
			lat: point ? lat : null, lon: point ? lon : null, hasPoint: point,
			radiusM: Number.isFinite(p.radiusM) ? p.radiusM : null,
			address: line(p.address, ADDRESS_MAX) || null,
			familie: ref ? familie : false,
			usage: Number.isSafeInteger(p.usageCount) && p.usageCount > 0 ? p.usageCount : 0,
			lastUsedMs: timeMs(p.lastUsedAt),
			rank: Number.isSafeInteger(rank) ? rank : (Number.isSafeInteger(p.rank) ? p.rank : Number.MAX_SAFE_INTEGER),
		};
	}

	/** A hit of the address search as a choice used only here. */
	function hitOption(h) {
		const o = option({ name: h && h.name, lat: h && h.lat, lon: h && h.lon, address: h && h.address, radiusM: RADIUS.default });
		return o ? { ...o, hit: true } : null;
	}

	/**
	 * The choices of a form: the plugin's list (chat.pickPlaces(): its order and use win) and the profile's own places
	 * (places.list()) filling in what the plugin does not know.
	 */
	function mergeOptions(pluginPlaces, mine) {
		const out = [];
		const seen = new Set();
		(Array.isArray(pluginPlaces) ? pluginPlaces : []).forEach((p, i) => {
			const o = option(p, i);
			if (o && !seen.has(o.key)) { seen.add(o.key); out.push(o); }
		});
		(Array.isArray(mine) ? mine : []).forEach((p) => {
			if (!p || p.own === false) return;
			const o = option({ ...p, ref: p.ref || `profile:${p.id}`, source: 'profile' });
			if (o && !seen.has(o.key)) { seen.add(o.key); out.push(o); }
		});
		return out.slice(0, 200);
	}

	/** Most used first, then the latest use, then the plugin's order, then the name. */
	function byUse(a, b) {
		return (b.usage - a.usage) || ((b.lastUsedMs || -Infinity) - (a.lastUsedMs || -Infinity)) || (a.rank - b.rank) || byName(a, b);
	}

	/**
	 * Where „In der Nähe“ is measured from — this PC has no position: the chosen place, else „Zuhause“ (an own place with
	 * the symbol home, else Familie's home, else one named so), else null (no such group).
	 */
	function anchorOf(options, selected) {
		if (selected && hasPoint(selected.lat, selected.lon)) return { lat: selected.lat, lon: selected.lon, name: selected.name };
		const list = (options || []).filter((o) => o && hasPoint(o.lat, o.lon));
		const home = list.find((o) => !o.familie && o.icon === 'home') || list.find((o) => o.ref === 'home')
			|| list.find((o) => ['zuhause', 'home', 'daheim'].includes(normalize(o.name)));
		return home ? { lat: home.lat, lon: home.lon, name: home.name } : null;
	}

	/**
	 * The chips in the form, at most `max`: 1. the chosen one, 2. the most used, 3. filled with the nearest to `here`,
	 * then the plugin's order. Each once; a place without a point is no chip.
	 */
	function chips(options, selected, here, max = CHIPS_MAX) {
		const out = new Map();
		const add = (o) => { if (o && out.size < max && !out.has(o.key)) out.set(o.key, o); };
		add(selected);
		const usable = (options || []).filter((o) => o && o.hasPoint);
		usable.filter((o) => o.usage > 0).sort(byUse).forEach(add);
		if (here) usable.slice().sort((a, b) => (distanceOf(a, here) ?? Infinity) - (distanceOf(b, here) ?? Infinity)).forEach(add);
		usable.slice().sort(byUse).forEach(add);
		return [...out.values()];
	}

	/**
	 * The sheet without a search: [{ kind: 'recent' | 'near' | 'letter', letter?, items }] — „Zuletzt genutzt“ (at most
	 * 3, by the latest use), „In der Nähe“ (up to 5 km from `here`, by distance; none without `here`), then the rest A–Z.
	 * Each place once, in the first group it belongs to.
	 */
	function groups(options, here) {
		const seen = new Set();
		const all = (options || []).filter((o) => o && !seen.has(o.key) && seen.add(o.key));
		const recent = all.filter((o) => o.lastUsedMs !== null).sort((a, b) => b.lastUsedMs - a.lastUsedMs).slice(0, RECENT_MAX);
		const taken = new Set(recent.map((o) => o.key));
		const near = !here ? [] : all.filter((o) => !taken.has(o.key))
			.map((o) => ({ o, d: distanceOf(o, here) })).filter((x) => x.d !== null && x.d <= NEAR_M)
			.sort((a, b) => a.d - b.d).map((x) => x.o);
		for (const o of near) taken.add(o.key);
		const rest = all.filter((o) => !taken.has(o.key)).sort(byName);
		const out = [];
		if (recent.length) out.push({ kind: 'recent', items: recent });
		if (near.length) out.push({ kind: 'near', items: near });
		const letters = new Map();
		for (const o of rest) {
			const l = letterOf(o.name);
			if (!letters.has(l)) letters.set(l, []);
			letters.get(l).push(o);
		}
		for (const l of [...letters.keys()].sort((a, b) => (a === '#') - (b === '#') || a.localeCompare(b))) out.push({ kind: 'letter', letter: l, items: letters.get(l) });
		return out;
	}

	/**
	 * The local search of the sheet: own and Familie places whose name or address holds `query` — a name that starts with
	 * it first, then the nearest (with an anchor), then by name.
	 */
	function search(options, query, here) {
		const q = normalize(query);
		if (!q) return [];
		const seen = new Set();
		return (options || []).filter((o) => o && !seen.has(o.key) && seen.add(o.key))
			.filter((o) => normalize(o.name).includes(q) || (o.address && normalize(o.address).includes(q)))
			.sort((a, b) => (!normalize(a.name).startsWith(q) - !normalize(b.name).startsWith(q))
				|| ((distanceOf(a, here) ?? Infinity) - (distanceOf(b, here) ?? Infinity)) || byName(a, b));
	}

	/** May the address search be asked: 3 … 120 characters (only on „Suchen“ / Enter). */
	const searchable = (query) => { const n = String(query || '').trim().length; return n >= SEARCH_MIN && n <= SEARCH_MAX; };

	/** The address hits that are none of the places listed already (the same point within 30 m). */
	function newHits(hits, options) {
		return (hits || []).filter((h) => h && hasPoint(h.lat, h.lon)
			&& !(options || []).some((o) => o && o.hasPoint && distanceM(h.lat, h.lon, o.lat, o.lon) <= SAME_POINT_M));
	}

	/** The choice that stands for a stored reference (e.g. `place:3` of Familie, `profile:12`), else null. */
	function find(options, ref) {
		return ref ? (options || []).find((o) => o && o.ref === ref) || null : null;
	}

	/**
	 * The place of a Messenger event for a choice: a Familie place as before ({ label, familiePlaceId, lat, lon }), a
	 * profile place or a hit as a copy ({ label, lat, lon }); `label` the text of the field.
	 */
	function eventPlace(o, label) {
		if (!o) return null;
		const l = line(label || o.name, 120);
		if (!l) return null;
		const out = { label: l };
		if (o.familie && o.id != null) out.familiePlaceId = o.id;
		if (o.hasPoint) { out.lat = o.lat; out.lon = o.lon; }
		return out;
	}

	/** The source line of a choice in the sheet: „Meine Orte · 200 m“ / „Familie · 150 m“ / „OpenStreetMap“. */
	function sourceLine(o, t) {
		if (!o) return '';
		if (o.hit) return [o.address, t('places.srcOsm')].filter(Boolean).join(' · ');
		const src = t(o.familie ? 'places.srcFamilie' : 'places.srcMine');
		return [src, Number.isFinite(o.radiusM) ? t('places.radiusShort', { m: o.radiusM }) : null, o.hasPoint ? null : t('places.noPoint')].filter(Boolean).join(' · ');
	}

	return {
		ICONS, VISIBILITY, RADIUS, NAME_MAX, ADDRESS_MAX, SEARCH_MIN, SEARCH_MAX, CHIPS_MAX, RECENT_MAX, NEAR_M, KINDS,
		line, hasPoint, iconOf, visibilityOf, snapRadius, plural, normalize,
		pageLists, placeLine, usedByLines, pluginsUsing, draftOf, draftProblem, createBody, diffBody, visibilityChoices, errorText, searchErrorText,
		distanceM, distanceOf, distanceText, letterOf, option, hitOption, mergeOptions, byUse, anchorOf, chips, groups, search, searchable, newHits, find,
		eventPlace, sourceLine,
	};
});
