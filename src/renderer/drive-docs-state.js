/**
 * GateControl -- Drive: AI for documents and deadlines (renderer, no DOM access)
 *
 * Drive 1.8 'docAi': what Drive recognised in a document (kind, title, date,
 * sender, amount), its suggestion (a name, a folder) and its deadlines
 * (payment, cancellation, objection) with the person's reminder "Erinnern N
 * Tage vorher"; the overview "Fristen". Pure helpers for drive-docs-view.js,
 * loaded as a plain script (window.GCDriveDocsState) and required by the node
 * tests (test/drive-18-state.test.js).
 *
 * Inputs are what window.gatecontrol.drive returns (core utils/drive.js
 * normalizeInsight / normalizeDeadline); `t` is the i18n function (drive.*).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDriveDocsState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const DOC_KINDS = ['invoice', 'contract', 'notice', 'medical', 'certificate', 'statement', 'insurance', 'warranty', 'other'];
	const DEADLINE_KINDS = ['payment', 'cancellation', 'objection'];
	// "Erinnern N Tage vorher": the choices of the select (null: no reminder)
	const REMIND_DAYS = [null, 0, 1, 3, 7, 14, 30];
	// the icon of a kind of document (drive-view.js ICONS)
	const DOC_ICON = { invoice: 'receipt', contract: 'contract', notice: 'stamp', medical: 'medical', certificate: 'award', statement: 'bank', insurance: 'shield', warranty: 'shield', other: 'file' };
	const DAY = 86400000;

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const localeTag = (l) => (l === 'en' ? 'en-GB' : 'de-DE');

	/** "Rechnung", "Vertrag", … ('' for an unknown kind) */
	function docKindLabel(kind, t) {
		return DOC_KINDS.includes(kind) ? t(`drive.doc.kind.${kind}`) : '';
	}

	function docIcon(kind) {
		return DOC_ICON[kind] || 'file';
	}

	/** 'YYYY-MM-DD' → '14.03.2026' / '14 Mar 2026' ('' when not a day) */
	function dayText(day, locale) {
		const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(str(day));
		if (!m) return '';
		const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
		return locale === 'en'
			? d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
			: d.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' });
	}

	/** 89.5 EUR → "89,50 €" (de) / "€89.50" (en); without a currency the number only. */
	function amountText(amount, currency, locale) {
		if (typeof amount !== 'number' || !Number.isFinite(amount)) return '';
		try {
			if (currency) return amount.toLocaleString(localeTag(locale), { style: 'currency', currency });
		} catch { /* an unknown currency code */ }
		return amount.toLocaleString(localeTag(locale), { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + (currency ? ` ${currency}` : '');
	}

	/**
	 * "Erkannt" of a file → { status, statusText, fields: [{ key, label, value }], canRun } — fields only while ready:
	 * kind, title, date, sender, amount (empty ones left out).
	 */
	function insightView(ins, { t, locale } = {}) {
		const x = ins || {};
		const status = ['none', 'pending', 'ready', 'failed', 'off'].includes(x.status) ? x.status : 'none';
		const fields = [];
		if (status === 'ready') {
			const add = (key, value) => { if (value) fields.push({ key, label: t(`drive.doc.field.${key}`), value }); };
			add('kind', docKindLabel(x.kind, t));
			add('title', str(x.title));
			add('date', dayText(x.date, locale));
			add('sender', str(x.sender));
			add('amount', amountText(x.amount, x.currency, locale));
		}
		let statusText = '';
		if (status === 'pending') statusText = t('drive.doc.pending');
		else if (status === 'none') statusText = t('drive.doc.none');
		else if (status === 'off') statusText = t('drive.doc.off');
		else if (status === 'failed') statusText = t('drive.doc.failed', { reason: errorReason(x.error, t) });
		else if (!fields.length) statusText = t('drive.doc.nothing');
		return { status, statusText, fields };
	}

	/** Why a recognition failed (the plugin's error codes) */
	function errorReason(code, t) {
		const known = ['no_text', 'media_disabled', 'ai_budget', 'ai_capability', 'ai_invalid', 'ai_timeout', 'ai_provider'];
		return t(`drive.doc.reason.${known.includes(code) ? code : 'other'}`);
	}

	/**
	 * The suggestion → null or { name, folder, folderText } — name: the suggested file name, folder: true when a folder
	 * is suggested ("Meine Dateien › Rechnungen"; folderPath '' is the area's top folder).
	 */
	function suggestionView(ins, areaLabel, t) {
		const s = ins && ins.status === 'ready' ? ins.suggestion : null;
		if (!s || (!s.name && !s.folderId)) return null;
		const parts = [str(areaLabel) || t('drive.area.mine')];
		if (s.folderId && s.folderPath) parts.push(...str(s.folderPath).split('/').filter(Boolean));
		return { name: s.name ? str(s.name) : null, folder: !!s.folderId, folderText: s.folderId ? parts.join(' › ') : null };
	}

	/** "Zahlungsfrist" / "Kündigungsfrist" / "Widerspruchsfrist" */
	function deadlineKind(kind, t) {
		return DEADLINE_KINDS.includes(kind) ? t(`drive.deadline.kind.${kind}`) : t('drive.deadline.kind.other');
	}

	/** Days from today (local) to 'YYYY-MM-DD' (negative: past), or null. */
	function daysUntil(day, now) {
		const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(str(day));
		if (!m) return null;
		const n = new Date(now);
		const today = new Date(n.getFullYear(), n.getMonth(), n.getDate()).getTime();
		const at = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])).getTime();
		return Math.round((at - today) / DAY);
	}

	/** "heute" / "morgen" / "in 5 Tagen" / "vor 2 Tagen" */
	function relativeDay(days, t) {
		if (days === null) return '';
		if (days === 0) return t('drive.deadline.today');
		if (days === 1) return t('drive.deadline.tomorrow');
		if (days > 1) return t('drive.deadline.inDays', { count: days });
		return t(days === -1 ? 'drive.deadline.ago.one' : 'drive.deadline.ago.other', { count: -days });
	}

	/**
	 * A deadline → { id, title, date, when, label, reminder, urgent, past, value } — value: the select's value of the
	 * reminder ('' none, else the days).
	 */
	function deadlineView(d, { t, locale, now = Date.now() } = {}) {
		const x = d || {};
		const days = daysUntil(x.date, now);
		const r = x.reminder;
		return {
			id: x.id,
			title: deadlineKind(x.kind, t),
			date: dayText(x.date, locale),
			when: relativeDay(days, t),
			label: str(x.label),
			past: days !== null && days < 0,
			urgent: days !== null && days >= 0 && days <= 7,
			reminder: r ? (r.sent ? t('drive.deadline.reminded') : reminderText(r.daysBefore, t)) : '',
			value: r && Number.isInteger(r.daysBefore) ? String(r.daysBefore) : '',
		};
	}

	/** "Erinnern am Tag selbst" / "Erinnern 3 Tage vorher" */
	function reminderText(days, t) {
		if (days === null || days === undefined) return t('drive.deadline.remind.none');
		if (days === 0) return t('drive.deadline.remind.day');
		return t(days === 1 ? 'drive.deadline.remind.one' : 'drive.deadline.remind.other', { count: days });
	}

	/** The options of "Erinnern N Tage vorher" → [{ value, label }] ('' = none) */
	function reminderOptions(t) {
		return REMIND_DAYS.map((d) => ({ value: d === null ? '' : String(d), label: reminderText(d, t) }));
	}

	/** The select's value → daysBefore (null: no reminder) */
	function reminderDays(value) {
		if (value === '' || value === null || value === undefined) return null;
		const n = Number(value);
		return Number.isInteger(n) && n >= 0 && n <= 90 ? n : null;
	}

	/**
	 * The overview "Fristen" → [{ key, title, items }] — overdue (still in the answer: the past days of `from`), the
	 * next 30 days, later. Each item: deadlineView + { file, nodeId, parentId, node }.
	 */
	function deadlineGroups(list, { t, locale, now = Date.now() } = {}) {
		const groups = { soon: [], later: [], past: [] };
		for (const d of Array.isArray(list) ? list : []) {
			if (!d || !d.node) continue;
			const v = deadlineView(d, { t, locale, now });
			const days = daysUntil(d.date, now);
			const item = { ...v, file: str(d.node.name), nodeId: d.node.id, parentId: d.node.parentId || null, node: d.node };
			if (days !== null && days < 0) groups.past.push(item);
			else if (days !== null && days <= 30) groups.soon.push(item);
			else groups.later.push(item);
		}
		return [
			{ key: 'soon', title: t('drive.deadline.group.soon'), items: groups.soon },
			{ key: 'later', title: t('drive.deadline.group.later'), items: groups.later },
			{ key: 'past', title: t('drive.deadline.group.past'), items: groups.past },
		].filter((g) => g.items.length);
	}

	/** The text after "Erneut erkennen" was refused with 422 unsupported (reason no_text | media_disabled). */
	function recognizeError(res, t) {
		const reason = res && res.code === 'unsupported' && res.reason ? res.reason : null;
		return reason ? t(`drive.doc.reason.${reason === 'media_disabled' ? 'media_disabled' : 'no_text'}`) : null;
	}

	return {
		DOC_KINDS, DEADLINE_KINDS, REMIND_DAYS,
		docKindLabel, docIcon, dayText, amountText, insightView, errorReason, suggestionView,
		deadlineKind, daysUntil, relativeDay, deadlineView, reminderText, reminderOptions, reminderDays, deadlineGroups, recognizeError,
	};
});
