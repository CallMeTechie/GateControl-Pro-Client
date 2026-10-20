/**
 * GateControl -- Schule (renderer view of the plugin gatecontrol-schule)
 *
 * The children's WebUntis timetable: a child selector (colour, picture or
 * initials), the week as day columns (this / next week) with the lessons
 * and their states — Entfällt (red, struck through), Vertretung (orange,
 * the old teacher / room / subject struck through), Zusatz —, holidays,
 * exams and homework of each day; the change log ("Änderungen"); with
 * plugin 1.4.0 the school's messages ("Nachrichten") and the absences
 * ("Fehlzeiten"). Schule pushes reload the page; a click on their toast
 * opens it on the child and day (or the message).
 *
 * Data: window.gatecontrol.school (core SchoolService over IPC); texts:
 * school.* of the core locales; view logic without DOM: school-state.js
 * (window.GCSchoolState). The same file is used by Pro and Community.
 *
 * Note: server text only ever goes into textContent / attributes; icons are
 * built from static path data with createElementNS (no innerHTML).
 */
(function (root) {
	'use strict';

	const SS = root.GCSchoolState;
	const NS = 'http://www.w3.org/2000/svg';
	const ICONS = {
		school: 'M2 9l10-5 10 5-10 5z|M6 11v5c3 2 9 2 12 0v-5M22 9v6',
		refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8|M21 3v5h-5',
		alert: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 8v5M12 16h.01',
		exam: 'M9 4h6v3H9z|M7 5H5v16h14V5h-2|M9 12h6M9 16h4',
		book: 'M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z|M4 19V5',
		check: 'M4 12l5 5L20 6',
		sun: 'M12 8a4 4 0 1 0 0 8a4 4 0 1 0 0-8|M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
		mail: 'M3 6h18v12H3z|M3 7l9 6 9-6',
		clip: 'M21 11.5l-8.5 8.5a5 5 0 0 1-7-7l9-9a3.5 3.5 0 0 1 5 5l-9 9a2 2 0 0 1-3-3l8-8',
		chevron: 'M9 6l6 6-6 6',
		cloudOff: 'M3 3l18 18|M8 8a5 5 0 0 0-2 9h11|M10 5a7 7 0 0 1 9 6 4 4 0 0 1 1 7',
	};

	function icon(name, size = 16, stroke = '2') {
		const s = document.createElementNS(NS, 'svg');
		s.setAttribute('viewBox', '0 0 24 24');
		s.setAttribute('width', String(size));
		s.setAttribute('height', String(size));
		s.setAttribute('fill', 'none');
		s.setAttribute('stroke', 'currentColor');
		s.setAttribute('stroke-width', stroke);
		s.setAttribute('stroke-linecap', 'round');
		s.setAttribute('stroke-linejoin', 'round');
		s.setAttribute('aria-hidden', 'true');
		for (const d of String(ICONS[name] || ICONS.alert).split('|')) {
			const p = document.createElementNS(NS, 'path');
			p.setAttribute('d', d);
			s.appendChild(p);
		}
		return s;
	}

	/** el('div', { class, text, on: { click }, attrs… }, [children]) — text only via textContent. */
	function el(tag, attrs, kids) {
		const n = document.createElement(tag);
		for (const [k, v] of Object.entries(attrs || {})) {
			if (v === null || v === undefined || v === false) continue;
			if (k === 'text') n.textContent = String(v);
			else if (k === 'class') n.className = v;
			else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
			else n.setAttribute(k, v === true ? '' : String(v));
		}
		for (const c of kids || []) if (c !== null && c !== undefined && c !== false && c !== '') n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
		return n;
	}
	const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };

	/** "new (old struck through)" for teacher / room / subject. */
	function withOld(value, old, cls) {
		const box = el('span', { class: cls });
		if (old) box.appendChild(el('s', { class: 'sv-old', text: old }));
		if (value) box.appendChild(el('span', { text: value }));
		return box;
	}

	/**
	 * @param {object} o
	 * @param {HTMLElement} o.root - the page section (empty)
	 * @param {object} o.api - window.gatecontrol.school
	 * @param {Function} o.t - i18n
	 * @param {() => string} o.getLocale
	 * @param {(st: object) => void} [o.onStatus] - availability (nav entry)
	 * @param {() => number} [o.now]
	 * @returns {{ show(), hide(), open(ctx), refresh(), status(), relabel() }}
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const now = typeof o.now === 'function' ? o.now : () => Date.now();
		const locale = () => o.getLocale();
		const today = () => SS.isoOf(new Date(now()));

		const S = {
			status: null,
			shown: false,
			tab: 'week',
			weekOffset: 0,
			studentId: null,
			focusDate: null,     // day to highlight / scroll to (push target)
			openMessage: null,   // expanded message id
			students: [],        // from the last timetable answer
			week: new Map(),     // offset → answer
			lists: { changes: null, messages: null, absences: null },
			errors: new Map(),   // what → result with ok:false
			loading: new Set(),
			dirty: true,
			avatars: new Map(),  // url → Promise<objectURL|null>
		};

		// ── Skeleton ─────────────────────────────────────────
		const refs = {};
		const rootEl = el('div', { class: 'sv' });
		o.root.appendChild(rootEl);
		refs.sub = el('span', { class: 'sv-sub' });
		refs.refresh = el('button', { type: 'button', class: 'sv-ib', title: t('school.refresh'), 'aria-label': t('school.refresh'), on: { click: () => reload(true) } }, [icon('refresh', 16)]);
		refs.kids = el('div', { class: 'sv-kids', role: 'group', 'aria-label': t('school.children') });
		refs.tabs = el('div', { class: 'seg sv-tabs', role: 'tablist', 'aria-label': t('school.title') });
		refs.weeks = el('div', { class: 'seg sv-weeks', role: 'group', 'aria-label': t('school.week.label') });
		refs.range = el('span', { class: 'sv-range' });
		refs.banner = el('div', { class: 'sv-banner', role: 'status', hidden: true });
		refs.body = el('div', { class: 'sv-body scroll', 'aria-live': 'polite' });
		refs.h = el('h1', { class: 'sv-h', text: t('school.title') });
		rootEl.append(
			el('div', { class: 'sv-head' }, [
				el('div', { class: 'sv-head-tx' }, [refs.h, refs.sub]),
				el('span', { class: 'sv-grow' }),
				refs.refresh,
			]),
			refs.kids,
			el('div', { class: 'sv-bar' }, [refs.tabs, el('span', { class: 'sv-grow' }), refs.range, refs.weeks]),
			refs.banner,
			refs.body,
		);

		// ── Avatars ──────────────────────────────────────────
		function avatarUrl(url) {
			if (!S.avatars.has(url)) {
				S.avatars.set(url, Promise.resolve(api.avatar(url)).then((r) => {
					if (!r || !r.ok || !r.data) return null;
					return URL.createObjectURL(new Blob([r.data], { type: r.mime || 'image/webp' }));
				}).catch(() => null));
			}
			return S.avatars.get(url);
		}

		function avatar(chip, size) {
			const box = el('span', { class: 'sv-av', 'aria-hidden': 'true', style: `width:${size}px;height:${size}px;font-size:${Math.max(10, Math.round(size * 0.36))}px` });
			box.style.setProperty('--c', chip.color);
			box.appendChild(el('span', { text: chip.initials }));
			if (chip.avatarUrl) {
				avatarUrl(chip.avatarUrl).then((u) => {
					if (u) box.appendChild(el('img', { class: 'sv-av-img', src: u, alt: '', draggable: 'false' }));
				});
			}
			return box;
		}

		// ── Data ─────────────────────────────────────────────
		const student = () => S.students.find((s) => s.id === S.studentId) || null;

		async function loadWeek(offset, refresh) {
			const key = `week:${offset}`;
			const r = SS.weekRange(today(), offset);
			S.loading.add(key);
			render();
			const res = await Promise.resolve(api.timetable(r.from, r.to, { refresh })).catch((err) => ({ ok: false, code: 'failed', error: err && err.message }));
			S.loading.delete(key);
			if (res && res.ok) {
				S.week.set(offset, res);
				S.errors.delete(key);
				S.students = Array.isArray(res.students) ? res.students : [];
				S.studentId = SS.pickStudent(S.students, S.studentId);
			} else {
				S.errors.set(key, res || { ok: false, code: 'failed' });
			}
			render();
		}

		async function loadList(what, refresh) {
			const fn = api[what];
			if (typeof fn !== 'function') return;
			S.loading.add(what);
			render();
			const res = await Promise.resolve(fn(SS.DAYS[what], { refresh })).catch((err) => ({ ok: false, code: 'failed', error: err && err.message }));
			S.loading.delete(what);
			if (res && res.ok) {
				S.lists[what] = res;
				S.errors.delete(what);
			} else if (res && res.code === 'unsupported') {
				S.lists[what] = null;
				if (S.tab === what) S.tab = 'week';
				refreshStatus();
			} else {
				S.errors.set(what, res || { ok: false, code: 'failed' });
			}
			render();
		}

		/** Load what the current tab needs (the week always: it names the children). */
		function reload(refresh = false) {
			S.dirty = false;
			const jobs = [loadWeek(S.weekOffset, refresh)];
			if (S.tab !== 'week') jobs.push(loadList(S.tab, refresh));
			if (S.tab === 'week' && S.lists.changes === null) jobs.push(loadList('changes', false)); // count on the tab
			return Promise.all(jobs);
		}

		function ensure() {
			if (S.dirty) return reload(false);
			if (!S.week.has(S.weekOffset) && !S.loading.has(`week:${S.weekOffset}`)) loadWeek(S.weekOffset, false);
			if (S.tab !== 'week' && !S.lists[S.tab] && !S.loading.has(S.tab)) loadList(S.tab, false);
			return Promise.resolve();
		}

		async function refreshStatus() {
			const st = await Promise.resolve(api.status()).catch(() => null);
			if (st) setStatus(st);
		}

		function setStatus(st) {
			const was = S.status && S.status.state;
			S.status = st;
			if (typeof o.onStatus === 'function') { try { o.onStatus(st); } catch { /* app */ } }
			if (!SS.tabsFor(st && st.features).includes(S.tab)) S.tab = 'week';
			// Plugin back (or new server): forget the old answers.
			if (st && st.state === 'available' && was !== 'available') { S.week.clear(); S.lists = { changes: null, messages: null, absences: null }; S.dirty = true; if (S.shown) reload(false); }
			render();
		}

		// ── Render ───────────────────────────────────────────
		function render() {
			renderHead();
			renderKids();
			renderTabs();
			renderBody();
		}

		function renderHead() {
			const res = S.week.get(S.weekOffset) || S.week.get(0);
			refs.sub.textContent = res ? SS.updatedText(res.updatedAt, t, locale(), now()) : '';
			const stale = [...S.week.values()].some((r) => r.stale) || Object.values(S.lists).some((r) => r && r.stale);
			refs.banner.hidden = !stale;
			clear(refs.banner);
			if (stale) refs.banner.append(icon('cloudOff', 15), el('span', { text: t('school.stale') }));
			refs.refresh.disabled = S.loading.size > 0;
			refs.refresh.classList.toggle('is-busy', S.loading.size > 0);
		}

		function renderKids() {
			clear(refs.kids);
			refs.kids.hidden = S.students.length === 0;
			for (const s of S.students) {
				const chip = SS.studentChip(s, t);
				const on = s.id === S.studentId;
				const b = el('button', { type: 'button', class: `sv-kid${on ? ' is-on' : ''}`, 'aria-pressed': on ? 'true' : 'false', on: { click: () => { S.studentId = s.id; S.openMessage = null; render(); } } }, [
					avatar(chip, 30),
					el('span', { class: 'sv-kid-tx' }, [el('b', { text: chip.name }), chip.sub ? el('span', { text: chip.sub }) : null]),
				]);
				b.style.setProperty('--c', chip.color);
				refs.kids.appendChild(b);
			}
		}

		function renderTabs() {
			clear(refs.tabs);
			const tabs = SS.tabsFor(S.status && S.status.features);
			const changes = S.lists.changes ? SS.forStudent(S.lists.changes.changes, S.studentId, 'changes').length : 0;
			const fresh = S.lists.messages ? SS.forStudent(S.lists.messages.messages, S.studentId, 'messages').filter((m) => m.isNew).length : 0;
			for (const tab of tabs) {
				const count = tab === 'changes' ? changes : tab === 'messages' ? fresh : 0;
				const b = el('button', { type: 'button', role: 'tab', class: S.tab === tab ? 'on' : '', 'aria-selected': S.tab === tab ? 'true' : 'false', on: { click: () => setTab(tab) } }, [
					t(`school.tab.${tab}`),
					count ? el('span', { class: 'sv-count', text: count > 99 ? '99+' : String(count) }) : null,
				]);
				refs.tabs.appendChild(b);
			}
			clear(refs.weeks);
			refs.weeks.hidden = S.tab !== 'week';
			refs.range.hidden = S.tab !== 'week';
			if (S.tab === 'week') {
				for (const [off, key] of [[0, 'school.week.this'], [1, 'school.week.next']]) {
					refs.weeks.appendChild(el('button', { type: 'button', class: S.weekOffset === off ? 'on' : '', 'aria-pressed': S.weekOffset === off ? 'true' : 'false', text: t(key), on: { click: () => setWeek(off) } }));
				}
				const r = SS.weekRange(today(), S.weekOffset);
				refs.range.textContent = t('school.week.range', { from: SS.dateShort(r.from, locale()), to: SS.dateShort(r.to, locale()) });
			}
		}

		function setTab(tab) {
			if (S.tab === tab) return;
			S.tab = tab;
			S.openMessage = null;
			render();
			ensure();
		}

		function setWeek(off) {
			if (S.weekOffset === off) return;
			S.weekOffset = off;
			S.focusDate = null;
			render();
			ensure();
		}

		function stateBox(kind, title, hint, action) {
			return el('div', { class: `sv-state${kind === 'error' ? ' is-error' : ''}` }, [
				icon(kind === 'error' ? 'alert' : 'school', 34, '1.6'),
				el('strong', { text: title }),
				hint ? el('span', { text: hint }) : null,
				action ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: action.label, on: { click: action.run } }) : null,
			]);
		}

		function renderBody() {
			clear(refs.body);
			const st = S.status;
			if (st && st.state === 'unavailable') {
				refs.body.appendChild(stateBox('info', t('school.unavailable.title'), t('school.unavailable.hint')));
				return;
			}
			const weekKey = `week:${S.weekOffset}`;
			const weekRes = S.week.get(S.weekOffset);
			if (!weekRes) {
				const err = S.errors.get(weekKey);
				if (err) refs.body.appendChild(stateBox('error', t('school.err.title'), SS.errorText(err, t), { label: t('school.retry'), run: () => reload(true) }));
				else refs.body.appendChild(el('div', { class: 'sv-loading', text: t('school.loading') }));
				return;
			}
			if (!S.students.length) {
				refs.body.appendChild(stateBox('info', t('school.noStudents.title'), t('school.noStudents.hint')));
				return;
			}
			if (S.tab === 'week') renderWeek(weekRes);
			else renderList(S.tab);
		}

		// ── Week ─────────────────────────────────────────────
		function renderWeek(res) {
			const s = (res.students || []).find((x) => x.id === S.studentId) || null;
			const r = SS.weekRange(today(), S.weekOffset);
			const cols = SS.weekColumns(r.dates, s);
			const grid = el('div', { class: 'sv-week', style: `--cols:${cols.length}` });
			const tday = today();
			const color = s ? SS.studentColor(s) : null;
			if (color) grid.style.setProperty('--c', color);
			for (const c of cols) {
				const isToday = c.date === tday;
				const col = el('section', { class: `sv-day${isToday ? ' is-today' : ''}${c.date === S.focusDate ? ' is-focus' : ''}${c.day && c.day.holiday ? ' is-holiday' : ''}`, 'aria-label': `${SS.weekdayLong(c.date, locale())} ${SS.dateShort(c.date, locale())}`, 'data-date': c.date });
				col.appendChild(el('header', { class: 'sv-day-head' }, [
					el('b', { text: SS.weekdayShort(c.date, locale()) }),
					el('span', { text: SS.dateShort(c.date, locale()) }),
					isToday ? el('span', { class: 'sv-today', text: t('school.today') }) : null,
				]));
				const d = c.day;
				if (d && d.holiday) col.appendChild(el('div', { class: 'sv-holiday' }, [icon('sun', 14), el('span', { text: d.holiday })]));
				for (const x of (d && d.exams) || []) {
					const v = SS.examView(x, t);
					col.appendChild(el('div', { class: 'sv-exam' }, [
						el('div', { class: 'sv-exam-top' }, [icon('exam', 14), el('b', { text: v.title })]),
						el('div', { class: 'sv-exam-meta', text: [v.subject, v.time, v.type].filter(Boolean).join(' · ') }),
						v.text ? el('div', { class: 'sv-note', text: v.text }) : null,
					]));
				}
				const lessons = (d && d.lessons) || [];
				for (const l of lessons) col.appendChild(lessonCard(SS.lessonView(l, t)));
				if (!lessons.length && !(d && d.holiday)) col.appendChild(el('div', { class: 'sv-free', text: t('school.noLessons') }));
				const hw = (d && d.homework) || [];
				if (hw.length) {
					const box = el('div', { class: 'sv-hw' }, [el('div', { class: 'sv-hw-h' }, [icon('book', 14), el('span', { text: t('school.homework') })])]);
					for (const h of hw) {
						const v = SS.homeworkView(h, t, locale());
						box.appendChild(el('div', { class: `sv-hw-item${v.done ? ' is-done' : ''}` }, [
							el('div', { class: 'sv-hw-subj' }, [v.done ? el('span', { class: 'sv-done', title: t('school.homeworkDone') }, [icon('check', 12, '3')]) : null, el('b', { text: v.subject })]),
							el('div', { class: 'sv-hw-text', text: v.text }),
							v.given ? el('div', { class: 'sv-hw-given', text: v.given }) : null,
						]));
					}
					col.appendChild(box);
				}
				grid.appendChild(col);
			}
			refs.body.appendChild(grid);
			if (S.focusDate) {
				const target = grid.querySelector(`[data-date="${S.focusDate}"]`);
				if (target && typeof target.scrollIntoView === 'function') target.scrollIntoView({ block: 'nearest', inline: 'center' });
			}
		}

		function lessonCard(v) {
			const card = el('div', { class: `sv-lesson ${v.cls}`, title: v.title || null }, [
				el('div', { class: 'sv-l-top' }, [
					el('span', { class: 'sv-l-time', text: v.time }),
					v.period ? el('span', { class: 'sv-l-per', text: v.period }) : null,
					v.badge ? el('span', { class: 'sv-badge', text: v.badge }) : null,
				]),
				withOld(v.subject, v.subjectOld, 'sv-l-subj'),
			]);
			if (v.teacher || v.teacherOld || v.room || v.roomOld) {
				card.appendChild(el('div', { class: 'sv-l-meta' }, [
					v.teacher || v.teacherOld ? withOld(v.teacher, v.teacherOld, 'sv-l-teacher') : null,
					v.room || v.roomOld ? withOld(v.room, v.roomOld, 'sv-l-room') : null,
				]));
			}
			if (v.note) card.appendChild(el('div', { class: 'sv-note', text: v.note }));
			return card;
		}

		// ── Lists ────────────────────────────────────────────
		function renderList(what) {
			const res = S.lists[what];
			if (!res) {
				const err = S.errors.get(what);
				if (err) refs.body.appendChild(stateBox('error', t('school.err.title'), SS.errorText(err, t), { label: t('school.retry'), run: () => loadList(what, true) }));
				else refs.body.appendChild(el('div', { class: 'sv-loading', text: t('school.loading') }));
				return;
			}
			const items = SS.forStudent(res[what], S.studentId, what);
			if (!items.length) {
				refs.body.appendChild(stateBox('info', t(`school.${what}.empty`, { days: SS.DAYS[what] }), null));
				return;
			}
			if (what === 'changes') renderChanges(items);
			else if (what === 'messages') renderMessages(items);
			else renderAbsences(items);
		}

		function renderChanges(items) {
			const box = el('div', { class: 'sv-list' });
			for (const g of SS.groupByDate(SS.sortChanges(items))) {
				box.appendChild(el('h2', { class: 'sv-list-h', text: SS.dayText(g.date, locale()) }));
				for (const c of g.items) {
					const v = SS.changeView(c, t, locale(), now());
					box.appendChild(el('div', { class: `sv-row sv-change ${v.cls}` }, [
						el('span', { class: 'sv-badge', text: v.label }),
						el('div', { class: 'sv-row-tx' }, [
							el('div', { class: 'sv-row-top' }, [withOld(v.subject, v.subjectOld, 'sv-l-subj'), el('span', { class: 'sv-row-when', text: [v.period, v.time].filter(Boolean).join(' · ') })]),
							v.teacher || v.teacherOld || v.room || v.roomOld ? el('div', { class: 'sv-l-meta' }, [
								v.teacher || v.teacherOld ? withOld(v.teacher, v.teacherOld, 'sv-l-teacher') : null,
								v.room || v.roomOld ? withOld(v.room, v.roomOld, 'sv-l-room') : null,
							]) : null,
							v.note ? el('div', { class: 'sv-note', text: v.note }) : null,
							v.detected ? el('div', { class: 'sv-row-foot', text: v.detected }) : null,
						]),
					]));
				}
			}
			refs.body.appendChild(box);
		}

		function renderMessages(items) {
			const box = el('div', { class: 'sv-list' });
			for (const m of items) {
				const v = SS.messageView(m, t, locale(), now());
				const open = S.openMessage === v.id;
				const head = el('button', { type: 'button', class: 'sv-msg-head', 'aria-expanded': open ? 'true' : 'false', on: { click: () => { S.openMessage = open ? null : v.id; render(); } } }, [
					v.isNew ? el('span', { class: 'sv-dot', title: t('school.messages.new') }) : null,
					el('span', { class: 'sv-row-tx' }, [
						el('span', { class: 'sv-row-top' }, [
							el('b', { class: 'sv-msg-subj', text: v.subject }),
							v.attachments ? el('span', { class: 'sv-clip', title: t('school.messages.attachments') }, [icon('clip', 13)]) : null,
							el('span', { class: 'sv-row-when', text: v.when }),
						]),
						el('span', { class: 'sv-msg-from', text: v.sender }),
						!open && v.preview ? el('span', { class: 'sv-msg-pv', text: v.preview }) : null,
					]),
					icon('chevron', 14),
				]);
				const row = el('div', { class: `sv-row sv-msg${open ? ' is-open' : ''}${v.isNew ? ' is-new' : ''}`, 'data-id': String(v.id) }, [head]);
				if (open) {
					row.appendChild(el('div', { class: 'sv-msg-body', text: v.body || v.preview || t('school.messages.noBody') }));
					if (v.attachments) row.appendChild(el('div', { class: 'sv-row-foot', text: t('school.messages.attachmentsHint') }));
				}
				box.appendChild(row);
			}
			refs.body.appendChild(box);
			if (S.openMessage != null) {
				const target = box.querySelector('.sv-msg.is-open');
				if (target && typeof target.scrollIntoView === 'function') target.scrollIntoView({ block: 'nearest' });
			}
		}

		function renderAbsences(items) {
			const box = el('div', { class: 'sv-list' });
			for (const a of items) {
				const v = SS.absenceView(a, t, locale());
				box.appendChild(el('div', { class: 'sv-row sv-abs' }, [
					el('div', { class: 'sv-row-tx' }, [
						el('div', { class: 'sv-row-top' }, [el('b', { text: v.days }), el('span', { class: 'sv-row-when', text: v.time }), el('span', { class: 'sv-grow' }), el('span', { class: `sv-pill ${v.status.cls}`, text: v.status.label })]),
						v.reason ? el('div', { class: 'sv-abs-reason', text: v.reason }) : null,
						v.text ? el('div', { class: 'sv-note', text: v.text }) : null,
					]),
				]));
			}
			refs.body.appendChild(box);
		}

		// ── Events ───────────────────────────────────────────
		if (typeof api.onState === 'function') api.onState((st) => setStatus(st));
		if (typeof api.onPush === 'function') {
			api.onPush(() => {
				// New changes / reminders / messages: the core dropped its cache.
				S.dirty = true;
				if (S.shown) reload(false);
			});
		}
		refreshStatus();
		render();

		return {
			show() {
				S.shown = true;
				render();
				ensure();
			},
			hide() {
				S.shown = false;
				S.focusDate = null;
			},
			/** Open on a push target (context from notify:navigate / an inbox entry). */
			open(ctx) {
				const target = SS.pushTarget(ctx, today(), S.status && S.status.features);
				S.tab = target.tab;
				S.weekOffset = target.weekOffset;
				S.focusDate = target.date;
				S.openMessage = target.messageId;
				if (target.studentId != null) S.studentId = target.studentId;
				S.dirty = true;
				render();
				if (S.shown) ensure();
			},
			refresh: () => reload(true),
			status: () => S.status,
			/** Language changed: static labels, then everything else. */
			relabel() {
				refs.h.textContent = t('school.title');
				refs.refresh.title = t('school.refresh');
				refs.refresh.setAttribute('aria-label', t('school.refresh'));
				refs.kids.setAttribute('aria-label', t('school.children'));
				refs.tabs.setAttribute('aria-label', t('school.title'));
				refs.weeks.setAttribute('aria-label', t('school.week.label'));
				render();
			},
		};
	}

	root.GCSchoolView = { mount };
})(typeof self !== 'undefined' ? self : this);
