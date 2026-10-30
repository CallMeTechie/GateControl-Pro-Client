/**
 * GateControl -- Drive: AI in Drive, Drive 1.14 (renderer, no DOM access)
 *
 * Pure helpers for drive-ki-view.js (and drive-view.js / drive-photos-view.js), loaded as a plain script
 * (window.GCDriveKiState) and required by the node tests (test/drive-114-state.test.js):
 * - "Fristen" by month, each with its kind, the day and "in N Tagen", the file, "In den Familienkalender" /
 *   "Im Familienkalender ✓" ('deadlineCalendar') and the reminder.
 * - "Ablegen" after an upload (D4): which upload is watched, the suggestion bar (name, folder, "An die Zahlung am …
 *   erinnern").
 * - "In Dokument umwandeln" (D5, 'scanDocs'): the formats per kind (PDF · Word · Excel · Nur Bild), the one picked
 *   first, the texts of the preview, the cost line and the button, the name with its extension.
 * - Questions in the search (D1, 'docAsk'): when the search field asks, the answer card, the deadline of a source.
 * - Photos by content (D3, 'photoSearch'): the words of the search and the chips.
 *
 * Inputs are what window.gatecontrol.drive returns (core utils/drive.js); `t` is the i18n function (drive.*).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDriveKiState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const DAY = 86400000;
	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const localeTag = (l) => (l === 'en' ? 'en-GB' : 'de-DE');
	const has = (me, f) => !!(me && Array.isArray(me.features) && me.features.includes(f));

	/** What of Drive 1.14 this Drive can → { calendar, ask, scan, photoSearch, docAi } */
	function features(me) {
		return { calendar: has(me, 'deadlineCalendar'), ask: has(me, 'docAsk'), scan: has(me, 'scanDocs'), photoSearch: has(me, 'photoSearch'), docAi: has(me, 'docAi') };
	}

	function dayOf(day) {
		const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(str(day));
		return m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])) : null;
	}

	function daysUntil(day, now) {
		const d = dayOf(day);
		if (!d) return null;
		const n = new Date(now);
		return Math.round((d.getTime() - new Date(n.getFullYear(), n.getMonth(), n.getDate()).getTime()) / DAY);
	}

	/** 'YYYY-MM-DD' → "Mo 30.11." / "Mon 30 Nov" */
	function shortDay(day, locale) {
		const d = dayOf(day);
		if (!d) return '';
		const wd = d.toLocaleDateString(localeTag(locale), { weekday: 'short' }).replace(/\.$/, '');
		return locale === 'en'
			? `${wd} ${d.getDate()} ${d.toLocaleDateString('en-GB', { month: 'short' })}`
			: `${wd} ${String(d.getDate()).padStart(2, '0')}.${String(d.getMonth() + 1).padStart(2, '0')}.`;
	}

	/** "heute" / "morgen" / "in 27 Tagen" / "vor 2 Tagen" */
	function relative(days, t) {
		if (days === null) return '';
		if (days === 0) return t('drive.deadline.today');
		if (days === 1) return t('drive.deadline.tomorrow');
		if (days > 1) return t('drive.deadline.inDays', { count: days });
		return t(days === -1 ? 'drive.deadline.ago.one' : 'drive.deadline.ago.other', { count: -days });
	}

	// ── D2: "Fristen" ──────────────────────────────────────

	const DEADLINE_KINDS = ['payment', 'cancellation', 'objection', 'warranty', 'renewal'];

	/** The tag of a deadline: "Zahlung", "Kündigung", "Widerspruch", "Garantieende", "Vertragsverlängerung" */
	function deadlineTag(kind, t) {
		return t(`drive.ki.dl.tag.${DEADLINE_KINDS.includes(kind) ? kind : 'other'}`);
	}

	/**
	 * A card of "Fristen" → { id, tag, day, when, title, file, nodeId, node, past, urgent, calendar, canCalendar }.
	 * renewal: "kündigen bis So 31.01." (its date is the last day to cancel).
	 */
	function deadlineCard(d, { t, locale, now = Date.now(), calendar = false } = {}) {
		const x = d || {};
		const days = daysUntil(x.date, now);
		const past = days !== null && days < 0;
		const day = shortDay(x.date, locale);
		const rel = relative(days, t);
		const dayText = x.kind === 'renewal' ? t('drive.ki.dl.cancelBy', { day }) : day;
		return {
			id: x.id,
			tag: deadlineTag(x.kind, t),
			day: dayText,
			when: past || (days !== null && days <= 60) ? rel : '',
			title: str(x.label) || deadlineTag(x.kind, t),
			file: x.node ? str(x.node.name) : '',
			nodeId: x.node ? x.node.id : null,
			node: x.node || null,
			past,
			urgent: days !== null && days >= 0 && days <= 7,
			calendar: !!x.calendar,
			canCalendar: !!calendar && !past,
		};
	}

	/** "November 2026" */
	function monthTitle(day, locale) {
		const d = dayOf(day);
		return d ? d.toLocaleDateString(localeTag(locale), { month: 'long', year: 'numeric' }) : '';
	}

	/**
	 * "Fristen" → [{ key, title, items: [card] }]: overdue first ("Abgelaufen"), then by month (from the answer's order:
	 * by date).
	 */
	function deadlineMonths(list, { t, locale, now = Date.now(), calendar = false } = {}) {
		const past = [];
		const months = new Map();
		for (const d of Array.isArray(list) ? list : []) {
			if (!d || !d.node || !dayOf(d.date)) continue;
			const card = deadlineCard(d, { t, locale, now, calendar });
			if (card.past) { past.push({ ...card, date: d.date }); continue; }
			const key = d.date.slice(0, 7);
			if (!months.has(key)) months.set(key, { key, title: monthTitle(d.date, locale), items: [] });
			months.get(key).items.push({ ...card, date: d.date });
		}
		const byDate = (a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : a.id - b.id);
		for (const g of months.values()) g.items.sort(byDate);
		const out = [...months.values()].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
		if (past.length) out.unshift({ key: 'past', title: t('drive.deadline.group.past'), items: past.sort(byDate) });
		return out;
	}

	/** The button of the family calendar → { label, done } */
	function calendarButton(card, t) {
		return card.calendar ? { label: t('drive.ki.dl.inCalendar'), done: true } : { label: t('drive.ki.dl.toCalendar'), done: false };
	}

	// ── D4: "Ablegen" after an upload ──────────────────────

	const DOC_EXT_RE = /\.(pdf|jpe?g|png|heic|heif|webp|tiff?|docx?|odt|txt)$/i;
	const WATCH_MS = 60000;

	/**
	 * The transfer rows that ended since the last look → the upload to watch (the newest file that ended now) or null.
	 * `seen`: the ids already looked at (changed in place). Folders, vaults and anything but documents are left out.
	 */
	function newUpload(rows, seen, { me = null } = {}) {
		let pick = null;
		for (const r of Array.isArray(rows) ? rows : []) {
			if (!r || r.dir !== 'up' || r.state !== 'done' || seen.has(r.id)) continue;
			seen.add(r.id);
			if (!r.nodeId || r.folder || r.files !== undefined || !DOC_EXT_RE.test(str(r.name))) continue;
			pick = r;
		}
		if (!pick || !has(me, 'docAi')) return null;
		return { nodeId: pick.nodeId, name: str(pick.name), folderId: pick.folderId || null };
	}

	/**
	 * The bar "Vorschlag · Ablegen als … in …" of a recognised file → null (nothing to suggest) or { name, path,
	 * folder, payment: { id, day } | null }. `areaLabel(areaId)`; the node: where the file lies now.
	 */
	function fileBar(ins, node, { areaLabel, t, locale } = {}) {
		if (!ins || ins.status !== 'ready' || !ins.suggestion) return null;
		const s = ins.suggestion;
		const name = s.name && s.name !== str(node && node.name) ? str(s.name) : null;
		const folder = !!s.folderId && s.folderId !== (node && node.parentId);
		if (!name && !folder) return null;
		const parts = [str(typeof areaLabel === 'function' ? areaLabel(node && node.areaId) : '') || t('drive.area.mine')];
		if (folder && s.folderPath) parts.push(...str(s.folderPath).split('/').filter(Boolean));
		const pay = (Array.isArray(ins.deadlines) ? ins.deadlines : []).find((d) => d && d.kind === 'payment' && !d.reminder && daysUntil(d.date, Date.now()) >= 0);
		return {
			name: name || str(node && node.name),
			renamed: !!name,
			folder,
			path: folder ? parts.join(' › ') : null,
			payment: pay ? { id: pay.id, day: shortDayPlain(pay.date, locale) } : null,
		};
	}

	/** 'YYYY-MM-DD' → "28.11." / "28 Nov" */
	function shortDayPlain(day, locale) {
		const d = dayOf(day);
		if (!d) return '';
		return locale === 'en' ? `${d.getDate()} ${d.toLocaleDateString('en-GB', { month: 'short' })}` : `${String(d.getDate()).padStart(2, '0')}.${String(d.getMonth() + 1).padStart(2, '0')}.`;
	}

	// ── D5: "In Dokument umwandeln" ────────────────────────

	const SCAN_KINDS = ['printed', 'handwriting', 'table', 'whiteboard', 'other'];
	const SCAN_EXT = { pdf: 'pdf', docx: 'docx', xlsx: 'xlsx' };
	const SCAN_MIME_RE = /^image\/(jpeg|png|webp|heic|heif|tiff|bmp)$/i;
	const SCAN_NAME_RE = /\.(jpe?g|png|webp|hei[cf]|tiff?|bmp)$/i;

	/** Can this file (or these files) become a document? Pictures, not in a vault, ≤ 20, where one may write. */
	function scanAvailable(items, { me, writable } = {}) {
		const list = Array.isArray(items) ? items : [];
		return has(me, 'scanDocs') && !!writable && list.length > 0 && list.length <= 20
			&& list.every((n) => n && !n.isDir && !n.encrypted && (SCAN_MIME_RE.test(str(n.mime)) || SCAN_NAME_RE.test(str(n.name))));
	}

	/** The formats offered: PDF · Word (not for "nothing recognised") · Excel (tables only) · Nur Bild (one page) */
	function scanFormats(kind, pages = 1) {
		const k = SCAN_KINDS.includes(kind) ? kind : 'other';
		const out = ['pdf'];
		if (k !== 'other') out.push('docx');
		if (k === 'table') out.push('xlsx');
		if (pages === 1) out.push('image');
		return out;
	}

	/** The format picked first: table → Excel, handwriting / whiteboard → Word, printed → PDF, nothing → the picture. */
	function scanDefault(kind, pages = 1) {
		if (kind === 'table') return 'xlsx';
		if (kind === 'handwriting' || kind === 'whiteboard') return 'docx';
		if (kind === 'printed' || pages > 1) return 'pdf';
		return 'image';
	}

	/**
	 * The card "Erkannt: …" and the rest of "Scan prüfen" for the format `fmt` → { kind, summary, ask, preview, cost,
	 * save, chips: [{ key, label, on }] }.
	 */
	function scanView(scan, fmt, t) {
		const s = scan || {};
		const kind = SCAN_KINDS.includes(s.kind) ? s.kind : 'other';
		const pages = s.pages || 1;
		const formats = scanFormats(kind, pages);
		const f = formats.includes(fmt) ? fmt : scanDefault(kind, pages);
		let preview;
		if (f === 'pdf') preview = t(s.local ? 'drive.ki.scan.preview.pdfLocal' : 'drive.ki.scan.preview.pdf');
		else if (f === 'xlsx') preview = t('drive.ki.scan.preview.xlsx');
		else if (f === 'docx') preview = t(`drive.ki.scan.preview.docx.${kind === 'other' ? 'printed' : kind}`);
		else preview = t('drive.ki.scan.preview.image');
		const cost = f === 'image' ? t('drive.ki.scan.cost.none') : f === 'pdf' && s.local ? t('drive.ki.scan.cost.local') : t('drive.ki.scan.cost.ai');
		return {
			kind,
			format: f,
			title: s.classified === false && kind === 'other' ? t('drive.ki.scan.unknown') : t('drive.ki.scan.recognised', { kind: t(`drive.ki.scan.kind.${kind}`) }),
			summary: str(s.summary) || (s.local && s.words ? t('drive.ki.scan.words', { count: s.words }) : ''),
			ask: t(`drive.ki.scan.ask.${scanDefault(kind, pages)}`),
			preview,
			cost,
			save: t(`drive.ki.scan.save.${f}`),
			chips: formats.map((k) => ({ key: k, label: t(`drive.ki.scan.format.${k}`), on: k === f })),
		};
	}

	/** The name shown without an extension (a picture's or document's one is dropped). */
	function baseName(name) {
		return str(name).trim().replace(/\.(jpe?g|png|webp|hei[cf]|tiff?|bmp|pdf|docx|xlsx)$/i, '');
	}

	/** The extension the file will get for `fmt` ('.xlsx'; 'image': the picture's own). */
	function scanExt(fmt, pictureName) {
		if (SCAN_EXT[fmt]) return `.${SCAN_EXT[fmt]}`;
		const m = /\.[A-Za-z0-9]{1,5}$/.exec(str(pictureName));
		return m ? m[0] : '';
	}

	/** The name and folder suggested first: Drive's suggestion (docAi), else the picture's name and folder. */
	function scanStart(scan) {
		const s = scan || {};
		const sug = s.suggestion || null;
		return {
			name: baseName(sug && sug.name ? sug.name : s.name),
			folderId: sug && sug.folderId ? sug.folderId : s.folderId || null,
			folderPath: sug && sug.folderId ? str(sug.folderPath) : null,
		};
	}

	// ── D1: questions in the search ────────────────────────

	/**
	 * Does the search field ask? The chip "Fragen" ('ask'), else ('auto') a text that ends with "?" — the chip "Dateien"
	 * ('files') always searches files. Only where Drive answers.
	 */
	function asks(q, mode, me) {
		if (!has(me, 'docAsk') || mode === 'files') return false;
		return mode === 'ask' || /\?\s*$/.test(str(q));
	}

	/**
	 * The answer card → { found, text, sources: [{ nodeId, name, where, quote }], count, searched } — where: "Ordner ·
	 * Seite 1"; searched: "Gesucht nach: …" for nothing found.
	 */
	function answerView(a, { t, areas = [], areaLabel } = {}) {
		const x = a || {};
		const found = x.status === 'answered' && !!x.answer;
		const sources = (found && Array.isArray(x.sources) ? x.sources : []).map((s) => ({
			nodeId: s.nodeId,
			name: str(s.name),
			where: [str(s.path).split('/').filter(Boolean).join(' › '), s.page ? t('drive.ki.ask.page', { page: s.page }) : ''].filter(Boolean).join(' · '),
			quote: s.quote ? `„${str(s.quote).replace(/^[„"“]+|[“"”]+$/g, '')}“` : '',
		}));
		const where = (Array.isArray(areas) ? areas : []).map((ar) => (typeof areaLabel === 'function' ? areaLabel(ar) : str(ar && ar.label))).filter(Boolean);
		const terms = Array.isArray(x.terms) ? x.terms.filter(Boolean) : [];
		return {
			found,
			text: found ? str(x.answer) : t('drive.ki.ask.nothing'),
			sources,
			count: sources.length === 1 ? t('drive.ki.ask.sources.one') : t('drive.ki.ask.sources.other', { count: sources.length }),
			searched: !found && terms.length ? t('drive.ki.ask.searched', { terms: terms.join(', '), where: where.length ? where.join(t('drive.ki.ask.and')) : t('drive.ki.ask.yourFiles') }) : '',
		};
	}

	/**
	 * "Frist in den Familienkalender" of an answer: the next deadline of a source file that is not in the calendar yet
	 * (null: no button).
	 */
	function answerDeadline(answer, deadlines, now = Date.now()) {
		if (!answer || answer.status !== 'answered') return null;
		const ids = new Set((answer.sources || []).map((s) => s.nodeId));
		const list = (Array.isArray(deadlines) ? deadlines : []).filter((d) => d && d.node && ids.has(d.node.id) && !d.calendar && daysUntil(d.date, now) >= 0);
		list.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));
		return list[0] || null;
	}

	// ── D3: photos by content ──────────────────────────────

	/** The words of a photo search: "Strand  Meer" → ['Strand', 'Meer'] (≤ 5, no doubles). */
	function photoWords(q) {
		const out = [];
		for (const w of str(q).split(/\s+/)) {
			const x = w.trim().slice(0, 40);
			if (x && !out.some((y) => y.toLowerCase() === x.toLowerCase())) out.push(x);
		}
		return out.slice(0, 5);
	}

	/**
	 * The chips of a photo search → [{ term, on, label }]: the words searched (on; a click takes one out), then the
	 * most frequent labels of the hits ("+ Meer"; a click adds it).
	 */
	function photoChips(q, terms) {
		const words = photoWords(q);
		const out = words.map((w) => ({ term: w, on: true, label: w }));
		for (const x of Array.isArray(terms) ? terms : []) {
			const term = x && typeof x === 'object' ? str(x.term) : str(x);
			if (!term || words.some((w) => w.toLowerCase() === term.toLowerCase())) continue;
			out.push({ term, on: false, label: `+ ${term}` });
			if (out.length >= words.length + 6) break;
		}
		return out;
	}

	/** A chip clicked → the new search text. */
	function photoToggle(q, term) {
		const words = photoWords(q);
		const i = words.findIndex((w) => w.toLowerCase() === str(term).toLowerCase());
		if (i >= 0) words.splice(i, 1);
		else words.push(str(term));
		return words.join(' ');
	}

	return {
		DEADLINE_KINDS, SCAN_KINDS, WATCH_MS,
		features, daysUntil, shortDay, relative,
		deadlineTag, deadlineCard, monthTitle, deadlineMonths, calendarButton,
		newUpload, fileBar, shortDayPlain,
		scanAvailable, scanFormats, scanDefault, scanView, baseName, scanExt, scanStart,
		asks, answerView, answerDeadline,
		photoWords, photoChips, photoToggle,
	};
});
