/**
 * GateControl -- the host's virus scan in the plugin pages (renderer, no DOM access)
 *
 * Drive 1.19, GateDrop 1.4, Mail 1.8 and Messenger 1.11 (GateControl 1.223.0) put `scan { state, blocked, finding }`
 * on files, attachments and chat media (the core passes it on, core utils/scan.js); Mail adds `removed`. Only
 * `blocked` decides: a blocked file is not opened, downloaded, previewed, shared or handed on. Without `scan`
 * (older host or plugin) nothing is shown and nothing changes.
 *
 * What a page shows (chip):
 *   checking     pending + blocked      „Wird geprüft …“
 *   malware      infected + blocked     „Gesperrt – Schadsoftware“ (the finding as tooltip)
 *   unscannable  unscannable + blocked  „Gesperrt – nicht prüfbar“
 *   blocked      blocked, other state   „Gesperrt“
 *   removed      Mail: deleted at once  „Anhang entfernt (Schadsoftware)“
 *   warning      infected, not blocked  „Warnung – Schadsoftware“ (ask before opening)
 *   notCheckable unscannable, not blocked  quiet „Nicht prüfbar“
 *
 * The refusals of the core / plugins ({ ok: false, code, scan?, finding?, name?, retryAfter? }) → refusalText.
 * The texts are the core's i18n `scan.*` (DE / EN). Loaded as a plain script before the plugin pages
 * (window.GCScanState) and required by the node tests (test/scan-state.test.js).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCScanState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const KINDS = ['checking', 'malware', 'unscannable', 'blocked', 'removed', 'warning', 'notCheckable'];
	const REFUSALS = ['scan_pending', 'quarantined', 'scan_blocked'];
	const CODES = [...REFUSALS, 'infected', 'scan_unavailable', 'attachment_removed', 'attachment_blocked'];
	const TONE = { checking: 'checking', malware: 'blocked', unscannable: 'blocked', blocked: 'blocked', removed: 'blocked', warning: 'warning', notCheckable: 'quiet' };
	const RETRY_DEFAULT_S = 5;

	const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
	const line = (v) => (typeof v === 'string' ? v.replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 200) : '');

	/** The kind of `scan` a page shows (see above), or null: nothing. */
	function view(scan) {
		const s = obj(scan);
		if (!s) return null;
		if (s.removed === true) return 'removed';
		if (s.blocked === true) {
			if (s.state === 'pending') return 'checking';
			if (s.state === 'infected') return 'malware';
			if (s.state === 'unscannable') return 'unscannable';
			return 'blocked';
		}
		if (s.state === 'infected') return 'warning';
		if (s.state === 'unscannable') return 'notCheckable';
		return null;
	}

	/** Not opened, downloaded, previewed, shared or handed on. */
	function isBlocked(scan) {
		const s = obj(scan);
		return !!(s && (s.blocked === true || s.removed === true));
	}

	/** Marked only (infected, not blocked): opening asks first. */
	const isWarning = (scan) => view(scan) === 'warning';

	/**
	 * The chip of a file → { kind, tone: 'checking' | 'blocked' | 'warning' | 'quiet', text, title } or null.
	 * `title`: the long text (with the finding) for the tooltip.
	 */
	function chip(scan, t) {
		const kind = view(scan);
		if (!kind) return null;
		const text = {
			checking: 'scan.checkingShort', malware: 'scan.malware', unscannable: 'scan.unscannableShort', blocked: 'scan.blocked',
			removed: 'scan.removed', warning: 'scan.warning', notCheckable: 'scan.notCheckable',
		}[kind];
		return { kind, tone: TONE[kind], text: t(text), title: reason(scan, t) || t(text) };
	}

	/** The reason a file cannot be opened (shown instead of open / download), or the warning of a marked one. */
	function reason(scan, t) {
		const kind = view(scan);
		const finding = line(scan && scan.finding);
		switch (kind) {
			case 'checking': return t('scan.checkingOpen');
			case 'malware': return finding ? t('scan.quarantinedOf', { finding }) : t('scan.quarantined');
			case 'unscannable': return t('scan.scanBlocked');
			case 'blocked': return t('scan.blockedHint');
			case 'removed': return t('scan.attachmentRemoved');
			case 'warning': return finding ? t('scan.warningOf', { finding }) : t('scan.warning');
			case 'notCheckable': return t('scan.notCheckable');
			default: return null;
		}
	}

	/** The question before a marked file opens: { title, text, confirm }. */
	function warnAsk(scan, name, t) {
		return { title: reason(scan, t) || t('scan.warning'), text: t('scan.warningAsk', { name: line(name) || '?' }), confirm: t('scan.openAnyway') };
	}

	const isScanCode = (code) => CODES.includes(code);

	/** A scan refusal of the core ({ ok: false, code, finding?, name?, scan? }) → its text, else null. */
	function refusalText(res, t) {
		const r = obj(res);
		if (!r || !isScanCode(r.code)) return null;
		const finding = line(r.finding || (obj(r.scan) && r.scan.finding));
		const name = line(r.name || (obj(r.detail) && r.detail.name));
		switch (r.code) {
			case 'scan_pending': return t('scan.checkingOpen');
			case 'quarantined': return finding ? t('scan.quarantinedOf', { finding }) : t('scan.quarantined');
			case 'scan_blocked': return name ? t('scan.scanBlockedOf', { name }) : t('scan.scanBlocked');
			case 'infected': return name ? t('scan.rejectedOf', { name }) : t('scan.rejected');
			case 'scan_unavailable': return t('scan.unavailable');
			case 'attachment_removed': return t('scan.attachmentRemoved');
			case 'attachment_blocked': return name ? t('scan.attachmentBlockedOf', { name }) : t('scan.attachmentBlocked');
			default: return null;
		}
	}

	/**
	 * A 423 scan_pending worth another try → the wait in ms (its Retry-After, 1 … 60 s), else null.
	 * `tries`: the tries made so far; at most `max` (default 2) more.
	 */
	function retryDelay(res, tries = 0, max = 2) {
		const r = obj(res);
		if (!r || r.code !== 'scan_pending' || tries >= max) return null;
		const s = Number.isFinite(r.retryAfter) && r.retryAfter > 0 ? r.retryAfter : RETRY_DEFAULT_S;
		return Math.min(60, Math.max(1, Math.round(s))) * 1000;
	}

	/** „1 gesperrte Datei fehlt.“ / „3 gesperrte Dateien fehlen.“ (ZIP, links of several), or null. */
	function skippedText(n, t) {
		const c = Number(n) || 0;
		if (c <= 0) return null;
		return c === 1 ? t('scan.skippedOne') : t('scan.skippedMany', { count: c });
	}

	/** Folder sync: „1 Datei wegen des Virenscans nicht geladen“ …, or null. */
	function syncBlockedText(n, t) {
		const c = Number(n) || 0;
		if (c <= 0) return null;
		return c === 1 ? t('scan.syncBlockedOne') : t('scan.syncBlockedMany', { count: c });
	}

	return {
		KINDS, CODES, REFUSALS,
		view, isBlocked, isWarning, chip, reason, warnAsk, isScanCode, refusalText, retryDelay, skippedText, syncBlockedText,
	};
});
