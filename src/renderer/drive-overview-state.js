/**
 * GateControl -- Drive "Übersicht" view state (renderer, no DOM access)
 *
 * Pure helpers of the page "Übersicht" (Drive 1.18, mockup WinStart): the switch Übersicht | Dateien | Fotos and
 * which of it is on for a view of the page, and the words of the tiles — a deadline ("in 3 Tagen · Familie"), the
 * photos to review, the attachments to file, a file opened lately ("gestern · Familie"), a memory ("Heute vor 2
 * Jahren", "30 Fotos · Mallorca"), the people, the places, a row of "Neu in …" ("Mama hat 14 Fotos hinzugefügt",
 * "Urlaub 2026 · vor 2 Std.") and the storage ("212 GB von 1 TB"). Which tiles show and their numbers come from the
 * core (utils/drive-overview.js, `view` of drive.overview()); this file only puts them into words.
 * Loaded as a plain script before drive-overview-view.js (window.GCDriveOverviewState) and required by the node
 * tests (test/drive-118-state.test.js). `t` is the i18n function (keys drive.ov.* of the app locales).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDriveOverviewState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

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

	// ── The switch ───────────────────────────────────────

	/** Übersicht | Dateien | Fotos (Fotos only with the feature) → [{ key, label }] */
	function pages({ overview = true, photos = false } = {}, t) {
		return [
			overview ? { key: 'overview', label: t('drive.ov.page.overview') } : null,
			{ key: 'files', label: t('drive.ov.page.files') },
			photos ? { key: 'photos', label: t('drive.ov.page.photos') } : null,
		].filter(Boolean);
	}

	/** Which page a view of Drive belongs to: the overview, the photos, the files (folder, search, trash …) or none. */
	function pageOf(view) {
		if (view === 'overview') return 'overview';
		if (view === 'photos' || view === 'memories') return 'photos';
		if (['folder', 'search', 'trash', 'links', 'deadlines', 'ask'].includes(view)) return 'files';
		return null;
	}

	// ── Times ────────────────────────────────────────────

	/** "vor 4 Min.", "vor 2 Std.", "gestern", "vor 3 Tagen", else the date. */
	function ago(ms, now, locale = 'de', t) {
		if (!Number.isFinite(ms)) return '';
		const s = Math.max(0, Math.round((now - ms) / 1000));
		if (s < 60) return t('drive.ov.time.now');
		if (s < 3600) return t('drive.ov.time.min', { n: Math.floor(s / 60) });
		if (s < 86400) return t('drive.ov.time.hours', { n: Math.floor(s / 3600) });
		const d = new Date(ms);
		const y = new Date(now - 86400000);
		if (d.getFullYear() === y.getFullYear() && d.getMonth() === y.getMonth() && d.getDate() === y.getDate()) return t('drive.ov.time.yesterday');
		const days = Math.floor(s / 86400);
		if (days < 7) return t('drive.ov.time.days', { n: days });
		return d.toLocaleDateString(localeTag(locale), { day: '2-digit', month: '2-digit', year: 'numeric' });
	}

	// ── The tiles ────────────────────────────────────────

	/** A deadline: its title, "in 3 Tagen · Familie" and the number on its square (when: { key, days } of the core). */
	function deadlineRow(d, when, { t, areaLabel = () => '' } = {}) {
		const title = str(d && d.label) || str(d && d.node && d.node.name) || t(`drive.deadline.kind.${d && d.kind}`);
		const day = !when ? '' : when.key === 'past' ? t('drive.ov.due.past') : when.key === 'today' ? t('drive.ov.due.today') : plural(t, 'drive.ov.due.in', when.days);
		const area = d && d.node ? str(areaLabel(d.node.areaId)) : '';
		// the square shows the days (up to 99), "!" for today or over, else (null) the calendar
		const badge = !when ? null : when.key === 'in' ? (when.days <= 99 ? String(when.days) : null) : '!';
		return { title, sub: [day, area].filter(Boolean).join(' · '), badge };
	}

	/** The short type of a file on its symbol (PDF, DOC, XLS, PPT, TXT, ZIP or the extension). */
	function fileBadge(name) {
		const ext = str(name).toLowerCase().split('.').pop();
		if (!ext || ext === str(name).toLowerCase()) return { text: '', tone: 'muted' };
		if (ext === 'pdf') return { text: 'PDF', tone: 'red' };
		if (['doc', 'docx', 'odt', 'rtf'].includes(ext)) return { text: 'DOC', tone: 'blue' };
		if (['xls', 'xlsx', 'ods', 'csv'].includes(ext)) return { text: 'XLS', tone: 'green' };
		if (['ppt', 'pptx', 'odp'].includes(ext)) return { text: 'PPT', tone: 'amber' };
		if (['zip', '7z', 'rar', 'tar', 'gz'].includes(ext)) return { text: 'ZIP', tone: 'muted' };
		return { text: ext.slice(0, 4).toUpperCase(), tone: 'muted' };
	}

	/** A file of "Zuletzt geöffnet": "gestern · Familie". */
	function recentSub(r, { t, locale = 'de', now = Date.now() } = {}) {
		const at = r && (r.openedAt || r.changedAt || (r.node && r.node.mtime));
		return [at ? ago(at, now, locale, t) : '', str(r && r.areaLabel)].filter(Boolean).join(' · ');
	}

	/** A memory: "Heute vor 2 Jahren" / "Vor einem Jahr" / "An diesem Tag" and "30 Fotos · Mallorca". */
	function memoryText(m, label, { t, locale = 'de' } = {}) {
		const years = label ? label.years : 0;
		const title = years <= 0 ? t('drive.ov.mem.day') : plural(t, label.today ? 'drive.ov.mem.today' : 'drive.ov.mem.ago', years, locale);
		const place = m && m.cover && m.cover.geo && m.cover.geo.place ? m.cover.geo.place.name : '';
		return { title, sub: [plural(t, 'drive.photos.count', m ? m.count : 0, locale), place].filter(Boolean).join(' · ') };
	}

	/** A row of "Neu in …": { name, rest } ("Mama" bold, "hat 14 Fotos hinzugefügt") and "Urlaub 2026 · vor 2 Std." */
	function activityText(a, line, { t, locale = 'de', now = Date.now() } = {}) {
		const name = str(line && line.name) || t('drive.ov.act.someone');
		const k = line ? line.key : 'changed';
		const rest = k === 'file' || k === 'changedOne' ? t(`drive.ov.act.${k}`, { file: str(line.file) })
			: plural(t, `drive.ov.act.${k}`, line ? line.n : 1, locale);
		const where = str(line && line.folder) || str(a && a.area && a.area.label);
		return { name, rest, sub: [where, a && a.at ? ago(a.at, now, locale, t) : ''].filter(Boolean).join(' · ') };
	}

	/** The heading of "Neu in …": "Neu in Familie", else "Neu in geteilten Bereichen". */
	function activityTitle(area, t) {
		return area ? t('drive.ov.act.title', { area }) : t('drive.ov.act.titleShared');
	}

	/** "212 GB von 1 TB" / "212 GB belegt" (and the target, "NAS"). */
	function storageText(s, { t, locale = 'de', formatBytes = (n) => String(n) } = {}) {
		if (!s) return '';
		const used = formatBytes(s.used, locale);
		const main = s.total ? t('drive.ov.storage.of', { used, total: formatBytes(s.total, locale) }) : t('drive.ov.storage.used', { used });
		return s.target ? `${main} · ${s.target}` : main;
	}

	/** "Köln · Hamburg · Mallorca" under the map. */
	function placesLine(places) {
		return arr(places && places.top).map((p) => p.name).join(' · ');
	}

	/** Initials of a person ("Oma Gerda" → "OG", no name → "?"). */
	function initials(name) {
		const w = str(name).trim().split(/\s+/).filter(Boolean);
		return w.slice(0, 2).map((x) => Array.from(x)[0].toUpperCase()).join('') || '?';
	}

	return { fmt, plural, pages, pageOf, ago, deadlineRow, fileBadge, recentSub, memoryText, activityText, activityTitle, storageText, placesLine, initials };
});
