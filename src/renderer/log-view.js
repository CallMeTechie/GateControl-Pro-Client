/**
 * GateControl -- Log page helpers (renderer, no DOM access)
 *
 * The main process parses the log file (core utils/log-parse.js, logs:get
 * with { format: 'entries' }) into entries { ts, date, time, ms, level, msg }
 * — newest first, a stack trace stays with its entry. This file turns them
 * into what the table shows: a compact time ("24.10. 20:58:32"), the level
 * group for the filter buttons (debug counts as info) and the search.
 *
 * Loaded as a plain script before renderer.js (window.GCLogView) and
 * required by the node tests. Identical in Pro and Community.
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCLogView = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const GROUPS = { error: 'error', warn: 'warn', info: 'info', debug: 'info' };
	const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
	const TIME_RE = /^\d{2}:\d{2}:\d{2}$/;

	/** 'error' | 'warn' | 'info' (debug → info) | null */
	function levelGroup(level) {
		return GROUPS[level] || null;
	}

	/** Compact time for the table: "24.10. 20:58:32" (en: "10/24 20:58:32"); '' without time. */
	function formatLogTime(entry, locale) {
		const m = entry && typeof entry.date === 'string' ? DATE_RE.exec(entry.date) : null;
		if (!m || !TIME_RE.test(entry.time || '')) return '';
		const day = String(locale || '').toLowerCase().startsWith('en') ? `${m[2]}/${m[3]}` : `${m[3]}.${m[2]}.`;
		return `${day} ${entry.time}`;
	}

	/** Full timestamp for the tooltip: "2026-10-24 20:58:32.553". */
	function fullLogTime(entry) {
		if (!entry || !entry.date || !entry.time) return '';
		return `${entry.date} ${entry.time}${entry.ms ? `.${entry.ms}` : ''}`;
	}

	/**
	 * Result of logs.get({ format: 'entries' }) → entries. A string (an older
	 * main process) becomes one entry per line without time and level.
	 */
	function toEntries(result) {
		if (Array.isArray(result)) {
			return result.filter((e) => e && typeof e.msg === 'string').map((e) => ({
				ts: Number.isFinite(e.ts) ? e.ts : null,
				date: typeof e.date === 'string' ? e.date : '',
				time: typeof e.time === 'string' ? e.time : '',
				ms: typeof e.ms === 'string' ? e.ms : '',
				level: GROUPS[e.level] ? e.level : null,
				msg: e.msg,
			}));
		}
		if (typeof result === 'string') {
			return result.split(/\r?\n/).filter((l) => l.trim()).map((msg) => ({ ts: null, date: '', time: '', ms: '', level: null, msg }));
		}
		return [];
	}

	/**
	 * Level filter ('all' | 'info' | 'warn' | 'error') and search (message,
	 * time in both forms, level).
	 */
	function filterLogEntries(entries, { level = 'all', query = '', locale = '' } = {}) {
		const q = String(query || '').trim().toLowerCase();
		return (entries || []).filter((e) => {
			if (level !== 'all' && levelGroup(e.level) !== level) return false;
			if (!q) return true;
			const hay = `${e.msg}\n${fullLogTime(e)}\n${formatLogTime(e, locale)}\n${e.level || ''}`.toLowerCase();
			return hay.includes(q);
		});
	}

	return { levelGroup, formatLogTime, fullLogTime, toEntries, filterLogEntries };
});
