/**
 * GateControl -- Drive "Erinnerungen" view state (renderer, no DOM access)
 *
 * Pure helpers of the page "Erinnerungen" (Drive plugin 1.26, feature `memoryCollections`): the overview's "Alle"
 * opens it. The core cleans GET memories (utils/drive.js normalizeMemoryCollections); this file groups the
 * collections by kind in the order of the page ("Heute in früheren Jahren", "Ausflüge und Reisen", "Mit deinen
 * Leuten", "Diesen Monat in früheren Jahren", "Jahresrückblick", "Orte") and puts a card into words ("Heute vor 2
 * Jahren" · "8. November 2024 · 14 Fotos", "Hamburg, Lübeck" · "5 Tage · Juli 2025 · 87 Fotos", "Mit Noah", "2025 im
 * Rückblick", "Langenlonsheim" · "12 Fotos").
 * Loaded as a plain script before drive-memories-view.js (window.GCDriveMemoriesState) and required by the node tests
 * (test/drive-126-state.test.js). `t` is the i18n function (keys drive.mem.* of the app locales).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDriveMemoriesState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const KINDS = Object.freeze(['day', 'trip', 'person', 'month', 'year', 'place']);
	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const arr = (v) => (Array.isArray(v) ? v : []);
	const localeTag = (l) => (l === 'en' ? 'en-GB' : 'de-DE');

	function fmt(n, locale = 'de') {
		const v = Number(n) || 0;
		try { return v.toLocaleString(localeTag(locale)); } catch { return String(v); }
	}

	function plural(t, key, n, locale = 'de', params = {}) {
		const count = Number(n) || 0;
		return t(`${key}.${count === 1 ? 'one' : 'other'}`, { ...params, count: fmt(count, locale) });
	}

	/** May the overview open the page? (the feature of this Drive, and the API of the core) */
	function available(me, api) {
		return !!(me && Array.isArray(me.features) && me.features.includes('memoryCollections') && api && typeof api.memoryCollections === 'function');
	}

	/** The collections by kind in the order of the page → [{ kind, items }] (empty kinds left out). */
	function sections(list) {
		const all = arr(list);
		return KINDS.map((kind) => ({ kind, items: all.filter((c) => c && c.kind === kind) })).filter((s) => s.items.length);
	}

	/** 'YYYY-MM-DD' (or 'YYYY-MM') → a local date, or null. */
	function dateOf(s) {
		const m = /^(\d{4})-(\d{2})(?:-(\d{2}))?$/.exec(str(s));
		if (!m) return null;
		const d = new Date(Number(m[1]), Number(m[2]) - 1, m[3] ? Number(m[3]) : 1);
		return Number.isNaN(d.getTime()) ? null : d;
	}

	function monthYear(s, locale = 'de') {
		const d = dateOf(s);
		if (!d) return '';
		try { return d.toLocaleDateString(localeTag(locale), { month: 'long', year: 'numeric' }); } catch { return str(s); }
	}

	function fullDate(s, locale = 'de') {
		const d = dateOf(s);
		if (!d) return '';
		try { return d.toLocaleDateString(localeTag(locale), { day: 'numeric', month: 'long', year: 'numeric' }); } catch { return str(s); }
	}

	/** A card: { title, sub } — the photo count always in the line below. */
	function cardText(c, { t, locale = 'de' } = {}) {
		const n = plural(t, 'drive.photos.count', c ? c.count : 0, locale);
		const line = (...parts) => parts.filter(Boolean).join(' · ');
		if (!c) return { title: '', sub: n };
		if (c.kind === 'day') return { title: plural(t, 'drive.ov.mem.today', c.yearsAgo || 1, locale), sub: line(fullDate(c.date, locale), n) };
		if (c.kind === 'trip') {
			const names = arr(c.places).length ? arr(c.places) : [c.place && c.place.name].filter(Boolean);
			return { title: names.join(', ') || t('drive.mem.trip'), sub: line(c.days ? plural(t, 'drive.mem.days', c.days, locale) : '', monthYear(c.firstDay, locale), n) };
		}
		if (c.kind === 'person') return { title: t('drive.mem.with', { name: str(c.person && c.person.name) }), sub: n };
		if (c.kind === 'month') return { title: plural(t, 'drive.mem.monthAgo', c.yearsAgo || 1, locale), sub: line(monthYear(c.month, locale), n) };
		if (c.kind === 'year') return { title: t('drive.mem.year', { year: str(c.year) }), sub: n };
		return { title: str(c.place && c.place.name), sub: n };
	}

	/** The heading of a section. */
	function sectionTitle(kind, t) {
		return t(`drive.mem.sec.${KINDS.includes(kind) ? kind : 'place'}`);
	}

	return { KINDS, available, sections, cardText, sectionTitle, monthYear, fullDate };
});
