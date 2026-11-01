/**
 * GateControl -- Drive: AI in Drive, Drive 1.14 (renderer, no DOM access)
 *
 * Pure helpers for drive-ki-view.js (and drive-view.js / drive-photos-view.js), loaded as a plain script
 * (window.GCDriveKiState) and required by the node tests (test/drive-114-state.test.js):
 * - "Fristen" by month, each with its kind, the day and "in N Tagen", the file, "In den Familienkalender" /
 *   "Im Familienkalender ✓" ('deadlineCalendar') and the reminder; Drive 1.17 ('deadlineMailCalendar') "In Kalender
 *   eintragen" into the family calendar or a mail calendar, and the target per area ("Fristen aus …").
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

	/** What of Drive 1.14 this Drive can → { calendar, ask, scan, photoSearch, docAi, mailCalendar (Drive 1.17) } */
	function features(me) {
		return { calendar: has(me, 'deadlineCalendar'), ask: has(me, 'docAsk'), scan: has(me, 'scanDocs'), photoSearch: has(me, 'photoSearch'), docAi: has(me, 'docAi'), mailCalendar: has(me, 'deadlineMailCalendar') };
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
	 * A card of "Fristen" → { id, tag, day, when, title, file, nodeId, node, areaId, past, urgent, calendar, entry,
	 * canCalendar }. renewal: "kündigen bis So 31.01." (its date is the last day to cancel). entry (Drive 1.17): the
	 * target of the calendar entry ({ kind, label }; null: the family calendar).
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
			areaId: x.node ? x.node.areaId || null : null,
			past,
			urgent: days !== null && days >= 0 && days <= 7,
			calendar: !!x.calendar,
			entry: x.calendar && x.calendar.target ? x.calendar.target : null,
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

	/**
	 * The button of the calendar → { label, done }: "In den Familienkalender" / "Im Familienkalender"; Drive 1.17 with a
	 * mail calendar to choose (`any`) "In Kalender eintragen", an entry in a mail calendar "Im Kalender · Outlook".
	 */
	function calendarButton(card, t, { any = false } = {}) {
		if (!card.calendar) return { label: t(any ? 'drive.ki.dl.toCalendarAny' : 'drive.ki.dl.toCalendar'), done: false };
		const e = card.entry;
		if (!e || e.kind !== 'mail') return { label: t('drive.ki.dl.inCalendar'), done: true };
		const where = str(e.label).split(' · ')[0].trim();
		return { label: where ? t('drive.ki.dl.inCalendarAt', { where }) : t('drive.ki.dl.inCalendarAny'), done: true };
	}

	// ── Drive 1.17: the family calendar or a calendar of the mail plugin ('deadlineMailCalendar') ──

	/** A mail calendar → "Outlook · Kalender" */
	function mailLabel(c) {
		const parts = [str(c && c.account ? c.account.label : '').trim(), str(c && c.name).trim()].filter(Boolean);
		return [...new Set(parts)].join(' · ');
	}

	/** A target as the value of a choice: 'off' | 'family' | 'mail:<calendarId>' */
	function targetValue(target) {
		if (!target) return 'off';
		if (target.kind === 'mail' && target.calendarId) return `mail:${target.calendarId}`;
		return target.kind === 'family' ? 'family' : 'off';
	}

	/** The value of a choice → the target (null: off, or a mail calendar that is not there any more). */
	function targetFromValue(value, calendars) {
		if (value === 'family') return { kind: 'family' };
		const m = /^mail:(.+)$/.exec(str(value));
		const c = m && calendars && Array.isArray(calendars.mail) ? calendars.mail.find((x) => x.id === m[1]) : null;
		return c ? { kind: 'mail', calendarId: c.id, label: mailLabel(c) } : null;
	}

	/**
	 * The choice of an area's target → [{ account, options: [{ value, label, target }] }]: "Nicht eintragen" (`off`),
	 * the family calendar (when Familie takes entries), then the mail calendars by account (only with `mail`).
	 */
	function targetChoices(calendars, { t, mail = false, off = true } = {}) {
		const c = calendars || {};
		const first = [];
		if (off) first.push({ value: 'off', label: t('drive.ki.dl.target.off'), target: null });
		if (c.family) first.push({ value: 'family', label: t('drive.ki.dl.target.family'), target: { kind: 'family' } });
		const out = first.length ? [{ account: null, options: first }] : [];
		if (!mail) return out;
		const groups = new Map();
		for (const x of Array.isArray(c.mail) ? c.mail : []) {
			if (!x || !x.id) continue;
			const key = x.account ? str(x.account.id) : '';
			if (!groups.has(key)) groups.set(key, { account: str(x.account ? x.account.label : '') || t('drive.ki.dl.target.mail'), options: [] });
			groups.get(key).options.push({ value: `mail:${x.id}`, label: mailLabel(x), name: str(x.name), color: x.color || null, target: { kind: 'mail', calendarId: x.id, label: mailLabel(x) } });
		}
		return out.concat([...groups.values()]);
	}

	/** The targets a single deadline can go to (no "off"). */
	function deadlineTargets(calendars, mail) {
		return targetChoices(calendars, { t: (k) => k, mail, off: false }).flatMap((g) => g.options.map((o) => o.target));
	}

	/** "In Kalender eintragen" asks only when more than one target is possible. */
	function asksTarget(targets) {
		return Array.isArray(targets) && targets.length > 1;
	}

	/** The target picked first for a deadline of `areaId`: my target of the area when still possible, else the family calendar, else the first. */
	function preselect(rows, areaId, targets) {
		const list = Array.isArray(targets) ? targets : [];
		const row = (Array.isArray(rows) ? rows : []).find((r) => r && r.areaId === areaId);
		const v = row ? targetValue(row.target) : 'off';
		return list.find((x) => v !== 'off' && targetValue(x) === v) || list.find((x) => x.kind === 'family') || list[0] || null;
	}

	/** The value of an area's target: "Nicht eintragen", "Familienkalender" or "Outlook · Kalender". */
	function targetText(target, calendars, t) {
		if (!target) return t('drive.ki.dl.target.off');
		if (target.kind !== 'mail') return t('drive.ki.dl.target.family');
		const c = calendars && Array.isArray(calendars.mail) ? calendars.mail.find((x) => x.id === target.calendarId) : null;
		return (c && mailLabel(c)) || str(target.label) || t('drive.ki.dl.target.mail');
	}

	/**
	 * The deadline rows of the settings under "KI für Dokumente", one per area with AI on: with Drive 1.17 my target
	 * (`targets` from deadlines/targets) → { areaId, kind: 'target', target }, else the switch into the family calendar
	 * ('deadlineCalendar') → { areaId, kind: 'switch', on }; null: none.
	 */
	function deadlineRow(area, me, targets) {
		if (!area || area.docAi !== true) return null;
		const row = has(me, 'deadlineMailCalendar') && Array.isArray(targets) ? targets.find((r) => r && r.areaId === area.id) : null;
		if (row) return { areaId: area.id, kind: 'target', target: row.target || null };
		if (has(me, 'deadlineCalendar') && typeof area.deadlinesToCalendar === 'boolean') return { areaId: area.id, kind: 'switch', on: area.deadlinesToCalendar };
		return null;
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

	const SCAN_PAGES_MAX = 8;

	/** Can this file (or these files) become a document? Pictures, not in a vault, ≤ 8, where one may write. */
	function scanAvailable(items, { me, writable } = {}) {
		const list = Array.isArray(items) ? items : [];
		return has(me, 'scanDocs') && !!writable && list.length > 0 && list.length <= SCAN_PAGES_MAX
			&& list.every((n) => n && !n.isDir && !n.encrypted && (SCAN_MIME_RE.test(str(n.mime)) || SCAN_NAME_RE.test(str(n.name))));
	}

	/**
	 * The formats offered: PDF (only when this PC reads the text or its pictures can go to Drive) · Word (not for
	 * "nothing recognised") · Excel (tables only) · Nur Bild (one page)
	 */
	function scanFormats(kind, pages = 1, pdf = true) {
		const k = SCAN_KINDS.includes(kind) ? kind : 'other';
		const out = pdf ? ['pdf'] : [];
		if (k !== 'other') out.push('docx');
		if (k === 'table') out.push('xlsx');
		if (pages === 1) out.push('image');
		return out;
	}

	/** The format picked first: table → Excel, handwriting / whiteboard → Word, printed → PDF, nothing → the picture. */
	function scanDefault(kind, pages = 1, pdf = true) {
		if (kind === 'table') return 'xlsx';
		if (kind === 'handwriting' || kind === 'whiteboard') return 'docx';
		if (kind === 'printed' || pages > 1) return pdf ? 'pdf' : (kind === 'printed' ? 'docx' : 'image');
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
		const pdf = s.pdf !== false;
		const formats = scanFormats(kind, pages, pdf);
		const def = scanDefault(kind, pages, pdf);
		const f = formats.includes(fmt) ? fmt : formats.includes(def) ? def : formats[0];
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
			ask: t(`drive.ki.scan.ask.${formats.includes(def) ? def : f}`),
			// no PDF without this PC's text or pictures for Drive
			noPdf: pdf ? '' : t('drive.ki.scan.noPdf'),
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

	/** "Original-Scan behalten" at first: the choice kept on this PC ('1' / '0'), else Drive's setting, else on. */
	function scanKeep(stored, me) {
		if (stored === '0') return false;
		if (stored === '1') return true;
		const s = me && me.settings ? me.settings.scanKeepOriginal : null;
		return s !== false;
	}

	/** The areas whose new deadlines may go into the family calendar on their own (write, 'deadlineCalendar'). */
	function calendarAreas(areas, me) {
		if (!has(me, 'deadlineCalendar')) return [];
		return (Array.isArray(areas) ? areas : []).filter((a) => a && typeof a.deadlinesToCalendar === 'boolean' && a.writable && !a.archived).map((a) => ({ area: a, areaId: a.id, on: a.deadlinesToCalendar }));
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
		// where Drive searched (its answer), else the person's areas
		const where = Array.isArray(x.areas) && x.areas.length ? x.areas.map(str).filter(Boolean)
			: (Array.isArray(areas) ? areas : []).map((ar) => (typeof areaLabel === 'function' ? areaLabel(ar) : str(ar && ar.label))).filter(Boolean);
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
	 * "Frist in den Familienkalender" of an answer: the deadline Drive names with it (a source's whose date the answer
	 * names), else the next deadline of a source file not in the calendar yet (null: no button).
	 */
	function answerDeadline(answer, deadlines, now = Date.now()) {
		if (!answer || answer.status !== 'answered') return null;
		if (answer.deadline && answer.deadline.id) return answer.deadline.calendar || daysUntil(answer.deadline.date, now) < 0 ? null : answer.deadline;
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
			const label = (x && typeof x === 'object' && str(x.label)) || term;
			if (!term || words.some((w) => w.toLowerCase() === term.toLowerCase() || w.toLowerCase() === label.toLowerCase())) continue;
			out.push({ term, on: false, label: `+ ${label}` });
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
		DEADLINE_KINDS, SCAN_KINDS, SCAN_PAGES_MAX, WATCH_MS,
		features, daysUntil, shortDay, relative,
		deadlineTag, deadlineCard, monthTitle, deadlineMonths, calendarButton,
		mailLabel, targetValue, targetFromValue, targetChoices, deadlineTargets, asksTarget, preselect, targetText, deadlineRow,
		newUpload, fileBar, shortDayPlain,
		scanAvailable, scanFormats, scanDefault, scanView, baseName, scanExt, scanStart, scanKeep, calendarAreas,
		asks, answerView, answerDeadline,
		photoWords, photoChips, photoToggle,
	};
});
