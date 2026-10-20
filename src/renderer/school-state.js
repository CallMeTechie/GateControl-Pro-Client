/**
 * GateControl -- Schule view state (renderer, no DOM access)
 *
 * Pure helpers for the page "Schule" (plugin gatecontrol-schule, WebUntis):
 * weeks (this / next week, Monday … Sunday, Saturday and Sunday only when
 * something happens), lessons with their states (Entfällt, Vertretung,
 * Zusatz), exams and homework of a day, the change log, school messages and
 * absences (plugin 1.4.0), the child selector (colour, initials), the tabs
 * the plugin supports and where a push message leads. Loaded as a plain
 * script before school-view.js (window.GCSchoolState) and required by the
 * node tests (test/school-state.test.js).
 *
 * Inputs are what window.gatecontrol.school returns (core SchoolService,
 * answers already cleaned by core utils/school.js); `t` is the i18n
 * function (keys school.* of the core locales). The same file is used by
 * Pro and Community.
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCSchoolState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
	const COLOR_RE = /^#[0-9a-fA-F]{6}$/;
	const APP_ROUTE = 'plg-gatecontrol-schule';
	const TOPIC_PREFIX = 'plugin:gatecontrol-schule:';
	const PUSH_KINDS = ['changes', 'exams', 'homework', 'messages', 'absences'];
	const TABS = ['week', 'changes', 'messages', 'absences'];
	const ERRORS = ['network', 'timeout', 'forbidden', 'invalid', 'unsupported', 'not_configured', 'auth'];
	// Colours for children without one (older plugins): calm, readable on both themes.
	const PALETTE = ['#2FBF71', '#3B82F6', '#F97316', '#A855F7', '#EAB308', '#EC4899', '#14B8A6', '#EF4444'];
	// Days asked for each list (the plugin's defaults).
	const DAYS = { changes: 7, messages: 30, absences: 60 };

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const localeTag = (locale) => (locale === 'en' ? 'en-GB' : 'de-DE');
	const pad = (n) => String(n).padStart(2, '0');

	// ── Dates (local calendar days as 'YYYY-MM-DD') ──────────

	function isDate(v) {
		const m = DATE_RE.exec(str(v));
		if (!m) return false;
		const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
		return d.getFullYear() === Number(m[1]) && d.getMonth() === Number(m[2]) - 1 && d.getDate() === Number(m[3]);
	}

	/** Date → 'YYYY-MM-DD' (local). */
	function isoOf(d) {
		return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
	}

	/** 'YYYY-MM-DD' → Date at local noon (safe across DST changes). */
	function dateOf(iso) {
		const m = DATE_RE.exec(str(iso));
		return m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 12) : null;
	}

	function addDays(iso, n) {
		const d = dateOf(iso);
		d.setDate(d.getDate() + n);
		return isoOf(d);
	}

	/** Monday of the week of `iso`. */
	function mondayOf(iso) {
		const d = dateOf(iso);
		const wd = (d.getDay() + 6) % 7; // Monday = 0
		d.setDate(d.getDate() - wd);
		return isoOf(d);
	}

	/** Week `offset` (0 = this week) from today → { from, to, dates } (Monday … Sunday). */
	function weekRange(today, offset = 0) {
		const from = addDays(mondayOf(today), 7 * (Number(offset) || 0));
		const dates = [];
		for (let i = 0; i < 7; i++) dates.push(addDays(from, i));
		return { from, to: dates[6], dates };
	}

	/** Weeks between the week of `today` and the week of `date` (next week = 1). */
	function weekOffsetOf(today, date) {
		if (!isDate(today) || !isDate(date)) return 0;
		const a = dateOf(mondayOf(today));
		const b = dateOf(mondayOf(date));
		return Math.round((b - a) / (7 * 86400000));
	}

	function weekdayShort(iso, locale) {
		const d = dateOf(iso);
		if (!d) return '';
		return d.toLocaleDateString(localeTag(locale), { weekday: 'short' }).replace(/\.$/, '');
	}

	function weekdayLong(iso, locale) {
		const d = dateOf(iso);
		return d ? d.toLocaleDateString(localeTag(locale), { weekday: 'long' }) : '';
	}

	/** '20.10.' (de) / '20/10' (en). */
	function dateShort(iso, locale) {
		const d = dateOf(iso);
		if (!d) return '';
		if (locale === 'en') return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}`;
		return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.`;
	}

	/** 'Mo 20.10.' */
	function dayText(iso, locale) {
		return `${weekdayShort(iso, locale)} ${dateShort(iso, locale)}`.trim();
	}

	/** Timestamp (ms) → 'heute 07:15' / '20.10. 07:15'. */
	function stamp(ms, t, locale, now = Date.now()) {
		if (!Number.isFinite(ms)) return '';
		const d = new Date(ms);
		const time = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
		if (isoOf(d) === isoOf(new Date(now))) return t('school.todayAt', { time });
		return `${dateShort(isoOf(d), locale)} ${time}`;
	}

	/** Line under the title: "Stand heute 07:15" / "Noch nicht abgerufen". */
	function updatedText(updatedAt, t, locale, now = Date.now()) {
		if (!Number.isFinite(updatedAt)) return t('school.updatedNever');
		return t('school.updated', { time: stamp(updatedAt, t, locale, now) });
	}

	// ── Children ────────────────────────────────────────────

	function initials(name) {
		const parts = str(name).trim().split(/\s+/).filter(Boolean);
		if (!parts.length) return '?';
		if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
		return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
	}

	function studentColor(s) {
		if (s && COLOR_RE.test(str(s.color))) return s.color;
		const id = s && Number.isSafeInteger(s.id) ? s.id : 0;
		return PALETTE[Math.abs(id) % PALETTE.length];
	}

	/** Chip of a child: { id, name, sub, color, initials, avatarUrl } */
	function studentChip(s, t) {
		return {
			id: s.id,
			name: str(s.name) || '?',
			sub: s.klasse ? t('school.klasse', { name: s.klasse }) : '',
			color: studentColor(s),
			initials: initials(s.name),
			avatarUrl: s.avatarUrl || null,
		};
	}

	/** The selected child: the wanted one if it exists, else the first. */
	function pickStudent(students, wanted) {
		const list = Array.isArray(students) ? students : [];
		if (wanted != null && list.some((s) => s.id === wanted)) return wanted;
		return list.length ? list[0].id : null;
	}

	// ── Week ────────────────────────────────────────────────

	const hasContent = (day) => !!day && ((day.lessons && day.lessons.length) || (day.exams && day.exams.length) || (day.homework && day.homework.length));

	/**
	 * Columns of the week: Monday … Friday always, Saturday / Sunday only
	 * when the child has lessons, exams or homework there.
	 * → [{ date, day|null, weekend }]
	 */
	function weekColumns(dates, student) {
		const byDate = new Map(((student && student.days) || []).map((d) => [d.date, d]));
		return (dates || []).map((date, i) => ({ date, day: byDate.get(date) || null, weekend: i >= 5 }))
			.filter((c) => !c.weekend || hasContent(c.day));
	}

	function periodLabel(x, t) {
		if (!x || !Number.isSafeInteger(x.period)) return '';
		if (Number.isSafeInteger(x.periodEnd) && x.periodEnd > x.period) return t('school.periods', { from: x.period, to: x.periodEnd });
		return t('school.period', { n: x.period });
	}

	const differs = (oldV, newV) => !!oldV && oldV !== newV;
	const uniq = (list) => [...new Set(list.filter(Boolean))];

	/**
	 * A lesson as shown: { state, cls, badge, time, period, subject, title,
	 * subjectOld, teacher, teacherOld, room, roomOld, note } — the *Old values
	 * only when they differ (struck through next to the new one).
	 */
	function lessonView(l, t) {
		const state = ['cancelled', 'changed', 'extra'].includes(l && l.state) ? l.state : 'normal';
		return {
			state,
			cls: `is-${state}`,
			badge: state === 'normal' ? null : t(`school.state.${state}`),
			time: l.start && l.end ? `${l.start}–${l.end}` : '',
			period: periodLabel(l, t),
			subject: str(l.subjectLong || l.subject) || '—',
			title: uniq([l.subjectLong, l.subject]).join(' · '),
			subjectOld: differs(l.subjectOld, l.subject) ? l.subjectOld : null,
			teacher: l.teacher || null,
			teacherOld: differs(l.teacherOld, l.teacher) ? l.teacherOld : null,
			room: l.room || null,
			roomOld: differs(l.roomOld, l.room) ? l.roomOld : null,
			note: uniq([l.substText, l.info, l.text]).join(' · ') || null,
		};
	}

	function examView(x, t) {
		return {
			title: str(x.name || x.type) || t('school.exam'),
			subject: str(x.subjectLong || x.subject),
			type: x.type && x.type !== x.name ? x.type : null,
			time: x.start ? (x.end ? `${x.start}–${x.end}` : x.start) : '',
			text: x.text || null,
		};
	}

	function homeworkView(h, t, locale) {
		return {
			subject: str(h.subjectLong || h.subject),
			text: str(h.text),
			done: h.completed === true,
			given: isDate(h.givenDate) ? t('school.homeworkGiven', { date: dateShort(h.givenDate, locale) }) : null,
		};
	}

	/** Counts of a week for a child (title of the week: "2 Ausfälle · 1 Arbeit"). */
	function weekSummary(columns) {
		const out = { cancelled: 0, changed: 0, extra: 0, exams: 0, homework: 0 };
		for (const c of columns || []) {
			const d = c.day;
			if (!d) continue;
			for (const l of d.lessons || []) if (out[l.state] !== undefined) out[l.state] += 1;
			out.exams += (d.exams || []).length;
			out.homework += (d.homework || []).filter((h) => !h.completed).length;
		}
		return out;
	}

	// ── Lists ───────────────────────────────────────────────

	/** Items of one child (messages: studentIds lists it, or names no child). */
	function forStudent(list, studentId, kind) {
		const items = Array.isArray(list) ? list : [];
		if (studentId == null) return items;
		if (kind === 'messages') return items.filter((m) => !Array.isArray(m.studentIds) || !m.studentIds.length || m.studentIds.includes(studentId));
		return items.filter((x) => x.studentId == null || x.studentId === studentId);
	}

	/** [{ date, items }] in the order of the list. */
	function groupByDate(list) {
		const out = [];
		const idx = new Map();
		for (const x of Array.isArray(list) ? list : []) {
			if (!idx.has(x.date)) { idx.set(x.date, out.length); out.push({ date: x.date, items: [] }); }
			out[idx.get(x.date)].items.push(x);
		}
		return out;
	}

	/** Changes sorted by lesson (date desc, then start) for the list. */
	function sortChanges(list) {
		return (Array.isArray(list) ? list.slice() : []).sort((a, b) => {
			if (a.date !== b.date) return a.date < b.date ? 1 : -1;
			return str(a.start) < str(b.start) ? -1 : str(a.start) > str(b.start) ? 1 : 0;
		});
	}

	function changeView(c, t, locale, now = Date.now()) {
		const kind = ['cancelled', 'changed', 'extra', 'restored'].includes(c.kind) ? c.kind : 'changed';
		return {
			kind,
			cls: `is-${kind === 'restored' ? 'normal' : kind}`,
			label: t(`school.change.${kind}`),
			day: dayText(c.date, locale),
			time: c.start ? (c.end ? `${c.start}–${c.end}` : c.start) : '',
			period: periodLabel(c, t),
			subject: str(c.subjectLong || c.subject) || '—',
			subjectOld: differs(c.subjectOld, c.subject) ? c.subjectOld : null,
			teacher: c.teacher || null,
			teacherOld: differs(c.teacherOld, c.teacher) ? c.teacherOld : null,
			room: c.room || null,
			roomOld: differs(c.roomOld, c.room) ? c.roomOld : null,
			note: uniq([c.substText, c.info]).join(' · ') || null,
			student: c.student || null,
			detected: Number.isFinite(c.detectedAt) ? t('school.change.detected', { time: stamp(c.detectedAt, t, locale, now) }) : '',
		};
	}

	function messageView(m, t, locale, now = Date.now()) {
		return {
			id: m.id,
			subject: str(m.subject) || t('school.messages.noSubject'),
			sender: m.sender || '',
			when: Number.isFinite(m.sentAt) ? stamp(m.sentAt, t, locale, now) : '',
			preview: m.preview || '',
			body: m.body || null,
			isNew: m.isNew === true,
			attachments: m.hasAttachments === true,
		};
	}

	function absenceView(a, t, locale) {
		const status = a.excused === true ? { key: 'school.abs.excused', cls: 'is-ok' }
			: a.excused === false ? { key: 'school.abs.unexcused', cls: 'is-err' }
				: { key: 'school.abs.open', cls: 'is-warn' };
		const days = a.endDate ? t('school.abs.range', { from: dayText(a.date, locale), to: dayText(a.endDate, locale) }) : dayText(a.date, locale);
		return {
			days,
			time: a.start && a.end ? `${a.start}–${a.end}` : a.start ? t('school.abs.from', { time: a.start }) : t('school.abs.allDay'),
			reason: a.reason || null,
			text: a.text || null,
			status: { label: t(status.key), cls: status.cls },
		};
	}

	// ── Tabs, errors, pushes ────────────────────────────────

	/** Tabs of the page: messages / absences unless the plugin lacks them (false). */
	function tabsFor(features) {
		const f = features || {};
		return TABS.filter((tab) => (tab === 'messages' ? f.messages !== false : tab === 'absences' ? f.absences !== false : true));
	}

	function errorText(res, t) {
		const code = res && typeof res.code === 'string' ? res.code : 'failed';
		if (ERRORS.includes(code)) return t(`school.err.${code}`);
		if (/^http_5\d\d$/.test(code)) return t('school.err.server');
		return t('school.err.failed', { code });
	}

	/**
	 * Schule context of an inbox entry ({ topic, data }) — the same rule as
	 * the core (utils/school.js pushContext) — or null.
	 */
	function entryContext(entry) {
		if (!entry || typeof entry !== 'object') return null;
		const topic = str(entry.topic);
		const data = entry.data && typeof entry.data === 'object' && !Array.isArray(entry.data) ? entry.data : {};
		if (!topic.startsWith(TOPIC_PREFIX) && data.route !== APP_ROUTE) return null;
		const s = data.schule && typeof data.schule === 'object' ? data.schule : {};
		const fromTopic = topic.startsWith(TOPIC_PREFIX) ? topic.slice(TOPIC_PREFIX.length) : '';
		const kind = PUSH_KINDS.includes(fromTopic) ? fromTopic : PUSH_KINDS.includes(s.kind) ? s.kind : null;
		const sid = Number(s.studentId);
		const mid = s.messageId;
		return {
			kind,
			studentId: Number.isSafeInteger(sid) && sid > 0 ? sid : null,
			date: isDate(s.date) ? s.date : null,
			messageId: (Number.isSafeInteger(mid) && mid > 0) || (typeof mid === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(mid)) ? mid : null,
		};
	}

	/**
	 * Where a Schule push leads (context from core: { kind, studentId, date,
	 * messageId }): { tab, studentId, weekOffset, date, messageId }. Changes,
	 * exams and homework open the week of that day (this or next week),
	 * messages / absences their tab (week when the plugin lacks it).
	 */
	function pushTarget(ctx, today, features) {
		const c = ctx && typeof ctx === 'object' ? ctx : {};
		const tabs = tabsFor(features);
		const studentId = Number.isSafeInteger(c.studentId) ? c.studentId : null;
		const date = isDate(c.date) ? c.date : null;
		if ((c.kind === 'messages' || c.kind === 'absences') && tabs.includes(c.kind)) {
			return { tab: c.kind, studentId, weekOffset: 0, date: null, messageId: c.kind === 'messages' && c.messageId != null ? c.messageId : null };
		}
		if (c.kind === 'changes' && !date) return { tab: 'changes', studentId, weekOffset: 0, date: null, messageId: null };
		const off = date ? weekOffsetOf(today, date) : 0;
		return { tab: 'week', studentId, weekOffset: Math.max(0, Math.min(1, off)), date: off >= 0 && off <= 1 ? date : null, messageId: null };
	}

	return {
		APP_ROUTE,
		TABS,
		DAYS,
		PALETTE,
		isDate,
		isoOf,
		addDays,
		mondayOf,
		weekRange,
		weekOffsetOf,
		weekdayShort,
		weekdayLong,
		dateShort,
		dayText,
		stamp,
		updatedText,
		initials,
		studentColor,
		studentChip,
		pickStudent,
		weekColumns,
		periodLabel,
		lessonView,
		examView,
		homeworkView,
		weekSummary,
		forStudent,
		groupByDate,
		sortChanges,
		changeView,
		messageView,
		absenceView,
		tabsFor,
		errorText,
		entryContext,
		pushTarget,
	};
});
