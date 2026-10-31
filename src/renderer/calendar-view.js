/**
 * GateControl -- Mail › Kalender (renderer, plugin gatecontrol-mail Phase 2)
 *
 * The area "Kalender" of the Mail page (mockups "Kalender", "Einladung",
 * "MenueNeu"), two columns: the menu shows the calendars with a tick and their
 * colour, grouped "GateControl", per account and "Eingeblendet" (Familie,
 * Alltag, birthdays) with their state ("wird abgeglichen", a failure, "Neu
 * anmelden"); a right click: colour, reminders on / off, rename, delete; at
 * the bottom "Kalender hinzufügen" and "iCal-Abo". The view on the right:
 * Tag / Woche (Arbeitswoche) / Monat / Liste, "Heute", ‹ ›, the chips of the
 * visible calendars, the grid (all-day row, hours 0–24 scrolled to 7:00,
 * overlapping events side by side, an open invitation dashed, a cancelled one
 * struck through, overlays "nur ansehen", the now line); a click into free
 * time makes a new event there. An event opens as a sheet on the right (Esc
 * closes): time, recurrence, calendar, place (map), "Teilnehmen", reminders,
 * attendees with their answers, the description (HTML in a sandboxed frame
 * like a mail), Bearbeiten / Löschen or Zusagen / Mit Vorbehalt / Absagen
 * with a comment. Editing in a dialog: all-day, recurrence, "nur dieser /
 * Serie", reminders, attendees with suggestions (groups go in as their
 * members), place, online link (Teams in Microsoft 365 calendars), busy /
 * free, private; a conflict offers "Neu laden" and "Meine Änderung erneut
 * anwenden". The invitation card of the reading pane comes from here too.
 *
 * Offline (the core's cache) the calendar shows what it has and greys out
 * every change ("Offline – geht wieder mit Verbindung").
 *
 * Built by mail-view.js through GCCalendarView.create(ctx) with the Mail
 * page's helpers (ctx); pure logic in mail-state.js (GCMailState). Server
 * text only goes into textContent / attributes; an event's HTML description
 * only into a sandboxed frame (the core's document).
 */
(function (root) {
	'use strict';

	const MS = root.GCMailState;
	const HOUR_PX = 48;
	const START_HOUR = 7;

	function create(ctx) {
		const { api, t } = ctx;
		const { el, icon, clear, dot, openDialog, mailFrame, sw } = root.GCMailUI;
		const lang = () => ctx.lang();
		const toast = (m, type) => ctx.toast(m, type);
		const errText = (r) => ctx.errText(r);
		const call = (p) => Promise.resolve(p).catch((err) => ({ ok: false, code: (err && err.code) || 'failed' }));

		const C = {
			cals: null,           // GET calendars: { calendars, overlays, prefs, consent }
			calsOffline: false,
			view: 'week',
			anchor: Date.now(),
			workWeek: false,
			range: null,
			items: [],
			overlays: [],
			listTo: null,
			loading: false,
			error: null,
			offline: false,
			seq: 0,
			sheet: null,          // { item, event, doc, docDark, loading, error, offline }
			sheetSeq: 0,
			main: null,
			shown: false,
			scrollTop: null,
			invites: [],
		};

		const cals = () => (C.cals && C.cals.calendars) || [];
		const overlays = () => (C.cals && C.cals.overlays) || [];
		const calOf = (id) => cals().find((c) => c.id === id) || null;
		const offlineNote = () => t('mail.cal.offlineHint');

		// ── Loading ──────────────────────────────────────

		async function loadCalendars() {
			const r = await call(api.calendars());
			if (r && r.ok) {
				const first = !C.cals;
				C.cals = r;
				C.calsOffline = !!r.offline;
				if (first && r.prefs) {
					C.view = r.prefs.view === 'day' || r.prefs.view === 'month' || r.prefs.view === 'list' ? r.prefs.view : 'week';
					C.workWeek = !!r.prefs.workWeek;
				}
			} else if (!C.cals) C.error = errText(r);
			return r;
		}

		async function loadInvites() {
			const r = await call(api.invitations('open'));
			if (r && r.ok) C.invites = r.items.filter((i) => i.method === 'request' || i.method === 'counter' || i.method === 'cancel');
			ctx.renderMenu();
		}

		function rangeNow() {
			const p = (C.cals && C.cals.prefs) || {};
			return MS.viewRange(C.view, C.anchor, { weekStart: p.weekStart === 0 ? 0 : 1, workWeek: C.view === 'week' && C.workWeek, listDays: 30 });
		}

		async function loadRange({ keep = false } = {}) {
			if (!C.cals) await loadCalendars();
			const seq = ++C.seq;
			C.range = rangeNow();
			if (!keep) { C.items = []; C.overlays = []; }
			C.loading = true;
			renderMain();
			const r = await call(api.events({ from: C.range.from, to: C.range.to, calendars: MS.visibleIds(cals(), overlays()) }));
			if (seq !== C.seq) return;
			C.loading = false;
			if (r && r.ok) {
				C.items = r.items;
				C.overlays = r.overlays;
				C.offline = !!r.offline;
				C.error = null;
				C.listTo = C.range.to;
			} else C.error = errText(r);
			renderMain();
		}

		/** The list goes on below: the next 30 days. */
		async function loadMore() {
			if (C.loading || !C.listTo) return;
			const from = C.listTo;
			const to = MS.addDays(from, 30);
			C.loading = true;
			renderMain();
			const r = await call(api.events({ from, to, calendars: MS.visibleIds(cals(), overlays()) }));
			C.loading = false;
			if (r && r.ok) {
				const seen = new Set([...C.items, ...C.overlays].map((x) => x.key));
				C.items = C.items.concat(r.items.filter((x) => !seen.has(x.key)));
				C.overlays = C.overlays.concat(r.overlays.filter((x) => !seen.has(x.key)));
				C.listTo = to;
			} else toast(errText(r), 'error');
			renderMain();
		}

		let reloadTimer = null;
		function reloadSoon(withCalendars) {
			clearTimeout(reloadTimer);
			reloadTimer = setTimeout(async () => {
				if (!C.shown) return;
				if (withCalendars) { await loadCalendars(); ctx.renderMenu(); }
				await loadRange({ keep: true });
				if (C.sheet && C.sheet.item && !C.sheet.item.overlayId) openSheet(C.sheet.item, { quiet: true });
			}, 400);
		}

		// ── The menu (left) ──────────────────────────────

		function stateNote(c) {
			if (c.state === 'syncing') return el('span', { class: 'cal-it-state', text: t('mail.cal.state.syncing') });
			if (c.state === 'consent_required') return el('span', { class: 'cal-it-state is-warn', text: t('mail.cal.state.consent') });
			if (c.state === 'auth_failed' || c.state === 'unreachable') return el('span', { class: 'cal-it-state is-err', title: t(`mail.cal.state.${c.state}`) }, [icon('alert', 13)]);
			return null;
		}

		function tick(color, on) {
			const b = el('span', { class: `cal-ck${on ? ' on' : ''}`, 'aria-hidden': 'true' }, [on ? icon('check', 12, '3') : null]);
			b.style.setProperty('--c', color);
			return b;
		}

		function renderSide(side) {
			if (!C.cals) {
				side.append(el('p', { class: 'ml-note cal-side-note', text: C.error || t('mail.loading') }));
				if (!C.error) loadCalendars().then(() => ctx.renderMenu());
				return;
			}
			if (C.invites.length) {
				side.append(el('button', { type: 'button', class: 'ml-it', on: { click: () => showInvites() } }, [icon('mail', 16), el('span', { class: 'ml-it-tx', text: t('mail.cal.invitations') }), el('span', { class: 'ml-n', text: String(C.invites.length) })]));
			}
			for (const g of MS.calendarGroups(cals(), overlays(), ctx.me(), t)) {
				side.append(el('div', { class: 'ml-lab', text: g.key === 'overlays' ? t('mail.cal.groupOverlaysLong') : g.label }));
				for (const x of g.items) {
					if (x.kind === 'overlay' && ((x.source === 'familie' && !ctx.has('familyOverlay')) || (x.source === 'alltag' && !ctx.has('alltagOverlay')))) continue;
					const b = el('button', {
						type: 'button', class: 'ml-it cal-it', role: 'switch', 'aria-checked': x.visible ? 'true' : 'false', title: x.name,
						on: { click: () => toggleVisible(x), contextmenu: (e) => { e.preventDefault(); calMenu(e, x); } },
					}, [
						tick(x.color, x.visible),
						el('span', { class: 'ml-it-tx', text: x.name }),
						x.kind === 'calendar' && x.isDefault ? el('span', { class: 'cal-it-def', text: t('mail.cal.default') }) : null,
						x.kind === 'calendar' ? stateNote(x) : null,
					]);
					side.append(b);
				}
			}
			side.append(el('div', { class: 'cal-side-acts' }, [
				el('button', { type: 'button', class: 'ml-it cal-add', disabled: C.calsOffline || null, on: { click: () => addCalendar() } }, [icon('plus', 16), el('span', { class: 'ml-it-tx', text: t('mail.cal.add') })]),
				el('button', { type: 'button', class: 'ml-it cal-add', disabled: C.calsOffline || null, on: { click: () => addSubscription() } }, [icon('link', 16), el('span', { class: 'ml-it-tx', text: t('mail.cal.subscribe') })]),
			]));
		}

		async function toggleVisible(x) {
			const visible = !x.visible;
			const r = await call(x.kind === 'overlay' ? api.updateOverlay(x.id, { visible }) : api.updateCalendar(x.id, { visible }));
			if (!r || !r.ok) { toast(errText(r), 'error'); return; }
			const list = x.kind === 'overlay' ? overlays() : cals();
			const it = list.find((y) => y.id === x.id);
			if (it) it.visible = visible;
			ctx.renderMenu();
			loadRange({ keep: true });
		}

		function calMenu(e, x) {
			const items = [['mail.cal.menu.color', 'image', () => pickColor(x)]];
			if (x.kind === 'calendar') {
				items.push([x.notify ? 'mail.cal.menu.notifyOff' : 'mail.cal.menu.notifyOn', 'clock', async () => {
					const r = await call(api.updateCalendar(x.id, { notify: !x.notify }));
					if (r && r.ok) { Object.assign(calOf(x.id) || {}, { notify: r.calendar.notify }); toast(t(r.calendar.notify ? 'mail.cal.notifyOn' : 'mail.cal.notifyOff', { name: x.name }), 'success'); ctx.renderMenu(); } else toast(errText(r), 'error');
				}]);
				items.push(['mail.cal.menu.rename', 'pen', () => renameCalendar(x)]);
				if (x.writable && !x.isDefault) items.push(['mail.cal.menu.default', 'check', async () => {
					const r = await call(api.calSettings({ defaultCalendarId: x.id }));
					if (r && r.ok) { C.cals.prefs = r.prefs; for (const c of cals()) c.isDefault = c.id === x.id; ctx.renderMenu(); } else toast(errText(r), 'error');
				}]);
				if (x.source === 'local' || x.source === 'ics') items.push(['mail.cal.menu.delete', 'trash', () => deleteCalendar(x)]);
			}
			ctx.popMenu(e.clientX, e.clientY, items);
		}

		function pickColor(x) {
			const dlg = openDialog({ title: t('mail.cal.menu.color'), closeLabel: t('mail.close') });
			const box = el('div', { class: 'ml-colors', role: 'radiogroup', 'aria-label': t('mail.cal.menu.color') });
			for (const c of MS.COLORS) {
				const b = el('button', { type: 'button', role: 'radio', class: `ml-color${c === x.color ? ' on' : ''}`, 'aria-checked': c === x.color ? 'true' : 'false', 'aria-label': c, on: { click: async () => {
					dlg.close();
					const r = await call(x.kind === 'overlay' ? api.updateOverlay(x.id, { color: c }) : api.updateCalendar(x.id, { color: c }));
					if (!r || !r.ok) { toast(errText(r), 'error'); return; }
					await loadCalendars();
					ctx.renderMenu();
					renderMain();
				} } });
				b.style.background = c;
				box.append(b);
			}
			dlg.body.append(box);
		}

		function nameDialog(title, value, onSave) {
			const dlg = openDialog({ title, closeLabel: t('mail.close') });
			const input = el('input', { type: 'text', class: 'ml-input', maxlength: '80', value: value || '', 'aria-label': t('mail.cal.name') });
			const err = el('span', { class: 'ml-dlg-err', role: 'alert' });
			const save = el('button', { type: 'button', class: 'btn btn-pri', text: t('mail.save'), on: { click: async () => {
				if (!input.value.trim()) { err.textContent = t('mail.cal.needName'); return; }
				save.disabled = true;
				const r = await onSave(input.value.trim());
				save.disabled = false;
				if (r && r.ok) dlg.close(); else err.textContent = errText(r);
			} } });
			input.addEventListener('keydown', (e) => { if (e.key === 'Enter') save.click(); });
			dlg.body.append(el('label', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: t('mail.cal.name') }), input]));
			dlg.foot.append(err, el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), save);
			return dlg;
		}

		function addCalendar() {
			nameDialog(t('mail.cal.add'), '', async (name) => {
				const r = await call(api.createCalendar({ name }));
				if (r && r.ok) { await loadCalendars(); ctx.renderMenu(); loadRange({ keep: true }); }
				return r;
			});
		}

		function renameCalendar(x) {
			nameDialog(t('mail.cal.menu.rename'), x.name, async (name) => {
				const r = await call(api.updateCalendar(x.id, { name }));
				if (r && r.ok) { await loadCalendars(); ctx.renderMenu(); renderMain(); }
				return r;
			});
		}

		function deleteCalendar(x) {
			const dlg = openDialog({ title: t('mail.cal.deleteTitle', { name: x.name }), closeLabel: t('mail.close') });
			dlg.body.append(el('p', { class: 'ml-p', text: t(x.source === 'ics' ? 'mail.cal.deleteSubText' : 'mail.cal.deleteText') }));
			dlg.foot.append(el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), el('button', { type: 'button', class: 'btn btn-danger', text: t('mail.cal.menu.delete'), on: { click: async () => {
				const r = await call(api.deleteCalendar(x.id));
				if (!r || !r.ok) { toast(r && r.code === 'not_supported' ? t('mail.cal.lastCalendar') : errText(r), 'error'); return; }
				dlg.close();
				await loadCalendars();
				ctx.renderMenu();
				loadRange({ keep: true });
			} } }));
		}

		function addSubscription() {
			const dlg = openDialog({ title: t('mail.cal.subscribe'), closeLabel: t('mail.close'), wide: true });
			const url = el('input', { type: 'url', class: 'ml-input', maxlength: '2048', placeholder: 'webcal:// … / https:// …', spellcheck: 'false', 'aria-label': t('mail.cal.subUrl') });
			const name = el('input', { type: 'text', class: 'ml-input', maxlength: '80', 'aria-label': t('mail.cal.name') });
			const acc = el('select', { class: 'ml-input', 'aria-label': t('mail.cal.subAccount') }, [el('option', { value: '', text: t('mail.cal.subNoAccount') })]);
			for (const a of (ctx.me() && ctx.me().accounts) || []) acc.append(el('option', { value: String(a.id), text: a.name }));
			const err = el('span', { class: 'ml-dlg-err', role: 'alert' });
			dlg.body.append(
				el('p', { class: 'ml-note', text: t('mail.cal.subHint') }),
				el('label', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: t('mail.cal.subUrl') }), url]),
				el('label', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: t('mail.cal.nameOptional') }), name]),
				el('label', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: t('mail.cal.subAccount') }), acc]),
			);
			const save = el('button', { type: 'button', class: 'btn btn-pri', text: t('mail.cal.subAdd'), on: { click: async () => {
				err.textContent = '';
				if (!/^(webcal|https):\/\//i.test(url.value.trim())) { err.textContent = t('mail.cal.subBadUrl'); return; }
				save.disabled = true;
				const r = await call(api.subscribe({ url: url.value.trim(), name: name.value.trim() || undefined, accountId: acc.value ? Number(acc.value) : undefined }));
				save.disabled = false;
				if (!r || !r.ok) { err.textContent = errText(r); return; }
				dlg.close();
				toast(t('mail.cal.subDone', { name: r.calendar.name }), 'success');
				await loadCalendars();
				ctx.renderMenu();
				loadRange({ keep: true });
			} } });
			dlg.foot.append(err, el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), save);
		}

		function showInvites() {
			const dlg = openDialog({ title: t('mail.cal.invitations'), closeLabel: t('mail.close'), wide: true });
			if (!C.invites.length) dlg.body.append(el('p', { class: 'ml-p', text: t('mail.cal.noInvitations') }));
			for (const inv of C.invites) dlg.body.append(inviteCardOf(inv, { onDone: () => loadInvites() }));
			dlg.foot.append(el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.close'), on: { click: () => dlg.close() } }));
		}

		// ── The view (right) ─────────────────────────────

		function go(view, anchor) {
			if (view) C.view = view;
			if (anchor !== undefined) C.anchor = anchor;
			C.scrollTop = null;
			loadRange();
			if (view && api.calSettings && C.cals && C.cals.prefs && C.cals.prefs.view !== view && !C.offline) {
				C.cals.prefs.view = view;
				call(api.calSettings({ view }));
			}
		}

		function renderMain() {
			const main = C.main;
			if (!main || !C.shown) return;
			const oldScroll = main.querySelector('.cal-scroll');
			if (oldScroll && C.scrollTop === null) C.scrollTop = oldScroll.scrollTop;
			else if (oldScroll) C.scrollTop = oldScroll.scrollTop;
			clear(main);
			const range = C.range || rangeNow();
			const head = el('div', { class: 'cal-head' }, [
				el('h1', { class: 'ml-h cal-title', text: MS.rangeTitle(C.view, range, C.anchor, lang()) }),
				el('div', { class: 'cal-nav' }, [
					el('button', { type: 'button', class: 'ml-ib', title: t('mail.cal.prev'), 'aria-label': t('mail.cal.prev'), on: { click: () => go(null, MS.shiftAnchor(C.view, C.anchor, -1)) } }, [icon('back', 16)]),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('mail.cal.today'), on: { click: () => go(null, Date.now()) } }),
					el('button', { type: 'button', class: 'ml-ib', title: t('mail.cal.next'), 'aria-label': t('mail.cal.next'), on: { click: () => go(null, MS.shiftAnchor(C.view, C.anchor, 1)) } }, [icon('chevron', 16)]),
				]),
				el('span', { class: 'ml-grow' }),
				root.GCMailUI.seg(MS.VIEWS.map((v) => [v, t(`mail.cal.view.${v}`)]), C.view, (v) => go(v), t('mail.cal.viewLabel')),
				C.view === 'week' ? el('label', { class: 'cal-ww' }, [sw(C.workWeek, t('mail.cal.workWeek'), (on) => { C.workWeek = on; call(api.calSettings({ workWeek: on })); go(); }), el('span', { text: t('mail.cal.workWeek') })]) : null,
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.refresh'), 'aria-label': t('mail.refresh'), on: { click: () => reloadSoon(true) } }, [icon('refresh', 16)]),
				el('button', { type: 'button', class: 'btn btn-pri btn-sm cal-new', disabled: C.offline || C.calsOffline || null, title: C.offline ? offlineNote() : null, on: { click: () => openEditor(null) } }, [icon('plus', 15), el('span', { text: t('mail.cal.newEvent') })]),
			]);
			main.append(head);
			// chips of the visible calendars: a click hides / shows
			const chips = el('div', { class: 'ml-chips cal-chips', role: 'group', 'aria-label': t('mail.cal.visible') });
			for (const x of [...cals().map((c) => ({ ...c, kind: 'calendar' })), ...overlays().map((o) => ({ ...o, kind: 'overlay' }))]) {
				if (!x.visible) continue;
				chips.append(el('button', { type: 'button', class: 'ml-chip cal-chip', 'aria-pressed': 'true', title: t('mail.cal.hide', { name: x.name }), on: { click: () => toggleVisible(x) } }, [tick(x.color, true), el('span', { text: x.name })]));
			}
			if (chips.childNodes.length) main.append(chips);
			for (const b of ctx.consentBands()) main.append(b);
			if (C.offline || C.calsOffline) main.append(el('div', { class: 'ml-banner' }, [icon('offline', 15), el('span', { text: t('mail.cal.offline') })]));
			if (C.error) main.append(el('div', { class: 'ml-banner is-err' }, [icon('alert', 15), el('span', { class: 'ml-grow', text: C.error }), el('button', { type: 'button', class: 'btn btn-sec btn-xs', text: t('mail.retry'), on: { click: () => { C.error = null; loadCalendars().then(() => { ctx.renderMenu(); loadRange(); }); } } })]));
			const body = el('div', { class: 'cal-body' });
			const viewEl = el('div', { class: `cal-view cal-v-${C.view}` });
			const all = [...C.items, ...C.overlays];
			if (C.view === 'month') renderMonth(viewEl, range, all);
			else if (C.view === 'list') renderList(viewEl, range, all);
			else renderGrid(viewEl, range, all);
			body.append(viewEl);
			if (C.sheet) body.append(renderSheet());
			main.append(body);
			const sc = main.querySelector('.cal-scroll');
			if (sc) sc.scrollTop = C.scrollTop !== null ? C.scrollTop : START_HOUR * HOUR_PX - 12;
		}

		function blockTitle(x) {
			const parts = [x.title || t('mail.cal.noTitle'), MS.eventTimeText(x, lang(), t)];
			if (x.location) parts.push(x.location);
			if (x.overlayId) parts.push(t('mail.cal.readOnly'));
			else if (x.myResponse === 'needs_action') parts.push(t('mail.cal.openInvite'));
			if (x.status === 'cancelled') parts.push(t('mail.cal.cancelled'));
			return parts.join(' · ');
		}

		function itemClasses(x) {
			return [x.overlayId ? 'is-overlay' : '', x.myResponse === 'needs_action' ? 'is-open' : '', x.status === 'cancelled' ? 'is-cancelled' : '', x.busy === 'free' ? 'is-free' : '',
				C.sheet && C.sheet.item && C.sheet.item.key === x.key ? 'on' : ''].filter(Boolean).join(' ');
		}

		function renderGrid(box, range, all) {
			const days = range.days;
			const now = Date.now();
			const today = new Date(now).setHours(0, 0, 0, 0);
			const cols = `56px repeat(${days.length}, minmax(0, 1fr))`;
			const headRow = el('div', { class: 'cal-dhead' });
			headRow.style.gridTemplateColumns = cols;
			headRow.append(el('span'));
			for (const d of days) {
				const dt = new Date(d);
				headRow.append(el('button', { type: 'button', class: `cal-dh${d === today ? ' is-today' : ''}`, title: t('mail.cal.openDay'), on: { click: () => go('day', d) } }, [
					el('span', { class: 'cal-dh-w', text: dt.toLocaleDateString(lang() === 'en' ? 'en-GB' : 'de-DE', { weekday: 'short' }).replace(/\.$/, '') }),
					el('span', { class: 'cal-dh-d', text: String(dt.getDate()) }),
				]));
			}
			box.append(headRow);
			const allRow = el('div', { class: 'cal-allday' });
			allRow.style.gridTemplateColumns = cols;
			allRow.append(el('span', { class: 'cal-gutter-lab', text: t('mail.cal.allDayShort') }));
			let anyAllDay = false;
			for (const d of days) {
				const cell = el('div', { class: 'cal-ad-cell' });
				for (const x of MS.allDayOn(all, d)) {
					anyAllDay = true;
					const b = el('button', { type: 'button', class: `cal-ad ${itemClasses(x)}`, title: blockTitle(x), on: { click: () => openSheet(x) } }, [el('span', { text: x.title || t('mail.cal.noTitle') })]);
					b.style.setProperty('--c', MS.itemColor(x, cals(), overlays()));
					cell.append(b);
				}
				allRow.append(cell);
			}
			allRow.classList.toggle('is-empty', !anyAllDay);
			box.append(allRow);
			const scroll = el('div', { class: 'cal-scroll' });
			const grid = el('div', { class: 'cal-grid' });
			grid.style.gridTemplateColumns = cols;
			grid.style.height = `${24 * HOUR_PX}px`;
			const gutter = el('div', { class: 'cal-gutter' });
			for (let h = 1; h < 24; h += 1) {
				const lab = el('span', { class: 'cal-hr', text: `${String(h).padStart(2, '0')}:00` });
				lab.style.top = `${h * HOUR_PX}px`;
				gutter.append(lab);
			}
			grid.append(gutter);
			for (const d of days) {
				const col = el('div', { class: `cal-col${d === today ? ' is-today' : ''}`, role: 'group', 'aria-label': new Date(d).toLocaleDateString(lang() === 'en' ? 'en-GB' : 'de-DE', { weekday: 'long', day: 'numeric', month: 'long' }) });
				col.addEventListener('click', (e) => {
					if (e.target !== col || C.offline || C.calsOffline) return;
					const slot = MS.slotAt(d, (e.offsetY / HOUR_PX) * 60);
					openEditor(null, { start: slot.start, end: slot.end });
				});
				for (const b of MS.layoutDay(all, d)) {
					const x = b.item;
					const ev = el('button', { type: 'button', class: `cal-ev ${itemClasses(x)}`, title: blockTitle(x), on: { click: (e) => { e.stopPropagation(); openSheet(x); } } }, [
						el('span', { class: 'cal-ev-t', text: x.title || t('mail.cal.noTitle') }),
						b.height >= 40 ? el('span', { class: 'cal-ev-s', text: [MS.eventTimeText(x, lang(), t), x.location, x.overlayId ? t('mail.cal.readOnly') : (x.myResponse === 'needs_action' ? t('mail.cal.openInvite') : null)].filter(Boolean).join(' · ') }) : null,
					]);
					ev.style.setProperty('--c', MS.itemColor(x, cals(), overlays()));
					ev.style.top = `${(b.top / 60) * HOUR_PX}px`;
					ev.style.height = `${Math.max(18, (b.height / 60) * HOUR_PX - 2)}px`;
					ev.style.left = `calc(${(b.col / b.cols) * 100}% + 2px)`;
					ev.style.width = `calc(${100 / b.cols}% - 4px)`;
					col.append(ev);
				}
				const nm = MS.nowMinutes(now, d);
				if (nm !== null) { const line = el('span', { class: 'cal-now', 'aria-hidden': 'true' }); line.style.top = `${(nm / 60) * HOUR_PX}px`; col.append(line); }
				grid.append(col);
			}
			scroll.append(grid);
			box.append(scroll);
			if (C.loading) box.append(el('div', { class: 'cal-loading', text: t('mail.loading') }));
		}

		function renderMonth(box, range, all) {
			const tag = lang() === 'en' ? 'en-GB' : 'de-DE';
			const today = new Date(Date.now()).setHours(0, 0, 0, 0);
			const head = el('div', { class: 'cal-mhead' });
			for (let i = 0; i < 7; i += 1) head.append(el('span', { text: new Date(range.days[i]).toLocaleDateString(tag, { weekday: 'short' }).replace(/\.$/, '') }));
			box.append(head);
			const grid = el('div', { class: 'cal-month' });
			for (const d of range.days) {
				const list = MS.dayItems(all, d);
				const cell = el('div', { class: `cal-mcell${new Date(d).getMonth() !== range.month ? ' is-other' : ''}${d === today ? ' is-today' : ''}` });
				cell.append(el('button', { type: 'button', class: 'cal-mday', title: t('mail.cal.openDay'), text: String(new Date(d).getDate()), on: { click: () => go('day', d) } }));
				for (const x of list.slice(0, 3)) {
					const b = el('button', { type: 'button', class: `cal-mitem ${itemClasses(x)}`, title: blockTitle(x), on: { click: () => openSheet(x) } }, [
						el('span', { class: 'cal-mdot' }),
						!x.allDay ? el('span', { class: 'cal-mtime', text: MS.hhmm(x.start) }) : null,
						el('span', { class: 'cal-mtitle', text: x.title || t('mail.cal.noTitle') }),
					]);
					b.style.setProperty('--c', MS.itemColor(x, cals(), overlays()));
					cell.append(b);
				}
				if (list.length > 3) cell.append(el('button', { type: 'button', class: 'cal-mmore', text: t('mail.cal.more', { count: list.length - 3 }), on: { click: () => go('day', d) } }));
				grid.append(cell);
			}
			box.append(grid);
		}

		function renderList(box, range, all) {
			const tag = lang() === 'en' ? 'en-GB' : 'de-DE';
			const today = new Date(Date.now()).setHours(0, 0, 0, 0);
			const scroll = el('div', { class: 'cal-agenda' });
			const days = MS.agenda(all, range.from, C.listTo || range.to);
			if (!days.length && !C.loading) scroll.append(el('div', { class: 'ml-empty' }, [icon('calendar', 28), el('p', { class: 'ml-p', text: t('mail.cal.nothing') })]));
			for (const g of days) {
				scroll.append(el('h3', { class: `cal-ag-day${g.day === today ? ' is-today' : ''}`, text: `${new Date(g.day).toLocaleDateString(tag, { weekday: 'long', day: 'numeric', month: 'long' })}${g.day === today ? ` · ${t('mail.cal.today')}` : ''}` }));
				for (const x of g.items) {
					const row = el('button', { type: 'button', class: `cal-ag-row ${itemClasses(x)}`, on: { click: () => openSheet(x) } }, [
						el('span', { class: 'cal-ag-bar' }),
						el('span', { class: 'cal-ag-time', text: MS.eventTimeText(x, lang(), t) }),
						el('span', { class: 'cal-ag-tx' }, [el('span', { class: 'cal-ag-title', text: x.title || t('mail.cal.noTitle') }), x.location || x.overlayId ? el('span', { class: 'ml-sub', text: [x.location, x.overlayId ? t('mail.cal.readOnly') : null].filter(Boolean).join(' · ') }) : null]),
					]);
					row.style.setProperty('--c', MS.itemColor(x, cals(), overlays()));
					scroll.append(row);
				}
			}
			scroll.append(el('button', { type: 'button', class: 'btn btn-ghost btn-sm ml-more', disabled: C.loading || null, text: C.loading ? t('mail.loading') : t('mail.cal.loadMore'), on: { click: () => loadMore() } }));
			scroll.addEventListener('scroll', () => { if (!C.loading && scroll.scrollTop + scroll.clientHeight > scroll.scrollHeight - 120) loadMore(); });
			box.append(scroll);
		}

		// ── An event (the sheet on the right) ────────────

		async function openSheet(item, { quiet = false } = {}) {
			const seq = ++C.sheetSeq;
			if (!quiet || !C.sheet) C.sheet = { item, event: null, loading: !item.overlayId, error: null };
			renderMain();
			if (item.overlayId) return;
			const r = await call(api.event(item.eventId, item.occurrence));
			if (seq !== C.sheetSeq || !C.sheet) return;
			if (r && r.ok) C.sheet = { item, event: r.event, doc: r.doc, docDark: r.docDark, offline: !!r.offline, loading: false };
			else C.sheet = { item, error: r && r.code === 'not_found' ? t('mail.cal.gone') : errText(r), loading: false };
			renderMain();
		}

		function closeSheet() {
			C.sheet = null;
			C.sheetSeq += 1;
			renderMain();
		}

		function sheetRow(ic, kids, cls) {
			return el('div', { class: `cal-sh-row${cls ? ` ${cls}` : ''}` }, [el('span', { class: 'cal-sh-ic' }, [icon(ic, 16)]), el('div', { class: 'cal-sh-tx' }, kids)]);
		}

		function renderSheet() {
			const S = C.sheet;
			const x = S.event || S.item;
			const box = el('aside', { class: 'cal-sheet', role: 'dialog', 'aria-label': x.title || t('mail.cal.event') });
			const color = MS.itemColor(x, cals(), overlays());
			box.style.setProperty('--c', color);
			box.append(el('div', { class: 'cal-sh-head' }, [
				el('span', { class: 'cal-sh-bar' }),
				el('h2', { class: `cal-sh-title${x.status === 'cancelled' ? ' is-cancelled' : ''}`, text: x.title || t('mail.cal.noTitle') }),
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.close'), 'aria-label': t('mail.close'), on: { click: closeSheet } }, [icon('close', 16)]),
			]));
			const scroll = el('div', { class: 'cal-sh-body' });
			box.append(scroll);
			const zone = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch { return null; } })();
			scroll.append(sheetRow('clock', [
				el('span', { class: 'cal-sh-main', text: MS.eventDate(x, lang()) }),
				el('span', { class: 'ml-sub', text: MS.eventTimeText(x, lang(), t) + (x.timeZone && zone && x.timeZone !== zone && !x.allDay ? ` (${x.timeZone})` : '') }),
				S.event && S.event.recurrence ? el('span', { class: 'ml-sub', text: MS.recurrenceText(S.event.recurrence, t, lang()) }) : null,
			]));
			if (x.status === 'cancelled') scroll.append(el('div', { class: 'ml-banner is-err' }, [icon('alert', 14), el('span', { text: t('mail.cal.cancelled') })]));
			const cal = x.calendarId ? calOf(x.calendarId) : null;
			const ov = x.overlayId ? overlays().find((o) => o.id === x.overlayId) : null;
			if (cal || ov) scroll.append(sheetRow('calendar', [el('span', { class: 'cal-sh-cal' }, [dot(color), el('span', { text: (cal || ov).name })]), ov ? el('span', { class: 'ml-sub', text: t('mail.cal.readOnlyLong') }) : null]));
			if (x.location) {
				scroll.append(sheetRow('folder', [el('button', { type: 'button', class: 'cal-link', title: t('mail.cal.openMap'), text: x.location, on: { click: () => openUrl(`https://www.openstreetmap.org/search?query=${encodeURIComponent(x.location)}`) } })]));
			}
			if (x.online && x.online.url) {
				scroll.append(sheetRow('link', [el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => openUrl(x.online.url) } }, [el('span', { text: t(x.online.provider === 'teams' ? 'mail.cal.joinTeams' : 'mail.cal.join') })])]));
			}
			if (S.loading) scroll.append(el('p', { class: 'ml-p', text: t('mail.loading') }));
			if (S.error) scroll.append(el('p', { class: 'ml-p', text: S.error }));
			const ev = S.event;
			if (ev) {
				if (ev.reminders.length) scroll.append(sheetRow('clock', ev.reminders.map((m) => el('span', { class: 'ml-sub', text: MS.reminderText(m, t) }))));
				if (ev.organizer || ev.attendees.length) {
					const c = MS.responseCounts(ev.attendees);
					const list = el('div', { class: 'cal-att-list' });
					if (ev.organizer) list.append(personRow({ name: ev.organizer.name, email: ev.organizer.email, contactId: null }, t('mail.cal.organizer')));
					for (const a of ev.attendees) list.append(personRow(a, t(`mail.cal.resp.${a.response}`), a.response));
					scroll.append(sheetRow('mail', [el('span', { class: 'cal-sh-main', text: t('mail.cal.attendeesCount', { yes: c.accepted, total: c.total }) }), list]));
				}
				if (S.doc) {
					const dark = ctx.mailDark();
					scroll.append(el('div', { class: `ml-frame-wrap cal-desc${dark ? ' is-dark' : ''}` }, [mailFrame(dark ? S.docDark || S.doc : S.doc, { title: t('mail.cal.description'), dark })]));
				} else if (ev.description) scroll.append(el('p', { class: 'cal-desc-tx', text: ev.description }));
				const off = S.offline || C.offline;
				const acts = el('div', { class: 'cal-sh-acts' });
				if (ev.canRespond) {
					const comment = el('input', { type: 'text', class: 'ml-input', maxlength: '500', placeholder: t('mail.cal.commentPh'), 'aria-label': t('mail.cal.comment') });
					const answer = (response) => respondEvent(ev, response, comment.value.trim());
					acts.append(
						el('div', { class: 'cal-answer' }, [
							el('button', { type: 'button', class: `btn btn-sm ${ev.myResponse === 'accepted' ? 'btn-pri' : 'btn-sec'}`, disabled: off || null, text: t('mail.cal.accept'), on: { click: () => answer('accepted') } }),
							el('button', { type: 'button', class: `btn btn-sm ${ev.myResponse === 'tentative' ? 'btn-pri' : 'btn-sec'}`, disabled: off || null, text: t('mail.cal.tentative'), on: { click: () => answer('tentative') } }),
							el('button', { type: 'button', class: `btn btn-sm ${ev.myResponse === 'declined' ? 'btn-danger is-on' : 'btn-sec cal-decline'}`, disabled: off || null, text: t('mail.cal.decline'), on: { click: () => answer('declined') } }),
						]),
						comment,
					);
				}
				if (ev.canEdit || ev.canDelete) {
					acts.append(el('div', { class: 'cal-answer' }, [
						ev.canEdit ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', disabled: off || null, on: { click: () => openEditor(ev) } }, [icon('pen', 14), el('span', { text: t('mail.cal.edit') })]) : null,
						ev.canDelete ? el('button', { type: 'button', class: 'btn btn-ghost btn-sm cal-del', disabled: off || null, on: { click: () => deleteEvent(ev) } }, [icon('trash', 14), el('span', { text: t('mail.cal.delete') })]) : null,
					]));
				}
				if (ev.readOnly) acts.append(el('p', { class: 'ml-note', text: t('mail.cal.readOnlyCal') }));
				if (off && (ev.canEdit || ev.canRespond)) acts.append(el('p', { class: 'ml-note', text: offlineNote() }));
				if (acts.childNodes.length) scroll.append(acts);
			}
			return box;
		}

		function personRow(a, label, response) {
			const name = a.name || a.email;
			const av = el('span', { class: 'ml-av ml-av-sm', text: MS.initials({ name: a.name, email: a.email }) });
			av.style.background = 'var(--panel2)';
			av.style.color = 'var(--text)';
			const go2 = () => {
				if (a.contactId && ctx.has('contacts')) ctx.openContact(a.contactId);
				else if (a.email && ctx.has('contacts')) ctx.saveContact({ email: a.email, name: a.name });
			};
			return el('button', { type: 'button', class: 'cal-person', title: a.email || '', on: { click: go2 } }, [
				av, el('span', { class: 'cal-person-n', text: name }), el('span', { class: `cal-resp${response ? ` is-${response}` : ''}`, text: label || '' }),
			]);
		}

		function openUrl(url) {
			if (window.gatecontrol && window.gatecontrol.shell) window.gatecontrol.shell.openExternal(url);
		}

		async function respondEvent(ev, response, comment) {
			const r = await call(api.respondEvent(ev.eventId, { response, comment: comment || undefined, occurrence: ev.occurrence || undefined }));
			if (!r || !r.ok) { toast(errText(r), 'error'); return; }
			toast(t(`mail.cal.answered.${response}`), 'success');
			C.sheet.event = r.event;
			reloadSoon(false);
		}

		/**
		 * Series: "Nur dieser Termin" / "Alle Termine der Serie" → 'occurrence' | 'series' | null. `seriesOk: false`
		 * (a changed time without the master's times of Mail 1.3.0): only "Nur dieser Termin", with a note.
		 */
		function askScope(title, { seriesOk = true } = {}) {
			return new Promise((resolve) => {
				const dlg = openDialog({ title, closeLabel: t('mail.close'), onClose: (v) => resolve(v || null) });
				dlg.body.append(el('p', { class: 'ml-p', text: t('mail.cal.scopeText') }));
				if (!seriesOk) dlg.body.append(el('p', { class: 'ml-note cal-scope-note', text: t('mail.cal.scopeOnlyOne') }));
				dlg.foot.append(
					el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close(null) } }),
					el('button', { type: 'button', class: `btn ${seriesOk ? 'btn-sec' : 'btn-pri'} cal-scope-one`, text: t('mail.cal.scopeOne'), on: { click: () => dlg.close('occurrence') } }),
					seriesOk ? el('button', { type: 'button', class: 'btn btn-pri cal-scope-all', text: t('mail.cal.scopeAll'), on: { click: () => dlg.close('series') } }) : null,
				);
			});
		}

		async function deleteEvent(ev) {
			let scope = 'series';
			if (ev.recurring && ev.occurrence) { scope = await askScope(t('mail.cal.deleteTitleEv')); if (!scope) return; }
			const withOthers = ev.attendees.some((a) => !a.self);
			const organizer = ev.myResponse === 'organizer' || (ev.organizer && ev.organizer.self);
			const dlg = openDialog({ title: t('mail.cal.deleteTitleEv'), closeLabel: t('mail.close') });
			dlg.body.append(el('p', { class: 'ml-p', text: t('mail.cal.deleteEvText', { title: ev.title }) }));
			const notify = el('input', { type: 'checkbox', class: 'ml-check', checked: withOthers || null });
			const comment = el('input', { type: 'text', class: 'ml-input', maxlength: '500', placeholder: t('mail.cal.commentPh') });
			if (withOthers) dlg.body.append(el('label', { class: 'ml-check-row' }, [notify, el('span', { text: t(organizer ? 'mail.cal.notifyCancel' : 'mail.cal.notifyDecline') })]), comment);
			dlg.foot.append(el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), el('button', { type: 'button', class: 'btn btn-danger', text: t('mail.cal.delete'), on: { click: async () => {
				const r = await call(api.deleteEvent(ev.eventId, { scope, occurrence: scope === 'occurrence' ? ev.occurrence : undefined, notify: withOthers && notify.checked, comment: comment.value.trim() || undefined }));
				if (!r || !r.ok) { toast(errText(r), 'error'); return; }
				dlg.close();
				toast(t('mail.cal.deleted'), 'success');
				closeSheet();
				reloadSoon(false);
			} } }));
		}

		// ── Editing (dialog) ─────────────────────────────

		function deviceZone() {
			try { return Intl.DateTimeFormat().resolvedOptions().timeZone || null; } catch { return null; }
		}

		/** The dialog of a new (ev null, at { start, end }) or an existing event. */
		async function openEditor(ev, at = null) {
			if (!C.cals) await loadCalendars();
			const writable = cals().filter((c) => c.writable);
			if (!writable.length) { toast(t('mail.cal.noWritable'), 'error'); return; }
			const prefs = (C.cals && C.cals.prefs) || {};
			let F;
			if (ev) F = MS.eventForm(ev, prefs, cals());
			else {
				const base = at || (() => { const s = MS.slotAt(new Date(C.anchor).setHours(0, 0, 0, 0), Math.max(9 * 60, (new Date().getHours() + 1) * 60)); return s; })();
				F = MS.eventForm({ start: base.start, end: base.end, allDay: false, calendarId: prefs.defaultCalendarId }, prefs, cals());
			}
			const zone = (ev && ev.timeZone) || deviceZone() || '';
			// a change sends only what changed (a series keeps its own times when they were not touched)
			const before = ev ? MS.eventBody(MS.eventForm(ev, prefs, cals()), { hadOnline: !!ev.online }) : null;
			const dlg = openDialog({ title: ev ? t('mail.cal.editTitle') : t('mail.cal.newEvent'), wide: true, closeLabel: t('mail.close'), cls: 'cal-edit' });
			const field = (label, input, cls) => el('label', { class: `ml-field${cls ? ` ${cls}` : ''}` }, [el('span', { class: 'ml-sub', text: label }), input]);
			const title = el('input', { type: 'text', class: 'ml-input cal-in-title', maxlength: '255', value: F.title, placeholder: t('mail.cal.titlePh'), 'aria-label': t('mail.cal.titleLabel') });
			title.addEventListener('input', () => { F.title = title.value; });
			const calSel = el('select', { class: 'ml-input', 'aria-label': t('mail.cal.calendar') });
			for (const c of writable) calSel.append(el('option', { value: String(c.id), text: c.name, selected: c.id === F.calendarId || null }));
			calSel.disabled = !!ev;
			const allDaySw = sw(F.allDay, t('mail.cal.allDay'), (on) => { F.allDay = on; drawTimes(); });
			const times = el('div', { class: 'cal-times' });
			const drawTimes = () => {
				clear(times);
				const sd = el('input', { type: 'date', class: 'ml-input', value: F.startDate, 'aria-label': t('mail.cal.startDate') });
				const ed = el('input', { type: 'date', class: 'ml-input', value: F.endDate, 'aria-label': t('mail.cal.endDate') });
				sd.addEventListener('change', () => {
					const before = MS.fromYmd(F.startDate);
					const end = MS.fromYmd(F.endDate);
					F.startDate = sd.value;
					const now = MS.fromYmd(sd.value);
					if (before !== null && end !== null && now !== null) { F.endDate = MS.ymd(MS.addDays(now, Math.round((end - before) / 86400000))); ed.value = F.endDate; }
				});
				ed.addEventListener('change', () => { F.endDate = ed.value; });
				if (F.allDay) {
					times.append(field(t('mail.cal.from'), sd), field(t('mail.cal.to'), ed));
				} else {
					const st = el('input', { type: 'time', class: 'ml-input', value: F.startTime, step: '300', 'aria-label': t('mail.cal.startTime') });
					const et = el('input', { type: 'time', class: 'ml-input', value: F.endTime, step: '300', 'aria-label': t('mail.cal.endTime') });
					st.addEventListener('change', () => {
						const s0 = MS.localMs(F.startDate, F.startTime);
						const e0 = MS.localMs(F.endDate, F.endTime);
						F.startTime = st.value;
						const s1 = MS.localMs(F.startDate, st.value);
						if (s0 !== null && e0 !== null && s1 !== null) { const e1 = s1 + (e0 - s0); F.endDate = MS.ymd(e1); F.endTime = MS.hhmm(e1); et.value = F.endTime; ed.value = F.endDate; }
					});
					et.addEventListener('change', () => { F.endTime = et.value; });
					times.append(el('div', { class: 'cal-pair' }, [field(t('mail.cal.from'), sd), field(t('mail.cal.time'), st)]), el('div', { class: 'cal-pair' }, [field(t('mail.cal.to'), ed), field(t('mail.cal.time'), et)]));
				}
			};
			drawTimes();
			const tzIn = el('input', { type: 'text', class: 'ml-input', value: zone, maxlength: '64', spellcheck: 'false', 'aria-label': t('mail.cal.timeZone') });
			const tz = el('details', { class: 'cal-tz' }, [el('summary', { class: 'ml-sub', text: t('mail.cal.timeZoneIs', { zone: zone || '—' }) }), field(t('mail.cal.timeZone'), tzIn)]);
			// recurrence
			const R = F.recurrence;
			const recSel = el('select', { class: 'ml-input', 'aria-label': t('mail.cal.repeat') });
			const startMs = () => MS.localMs(F.startDate, F.startTime) || MS.fromYmd(F.startDate) || Date.now();
			const recOpts = () => {
				clear(recSel);
				const p = MS.monthPos(startMs());
				const kinds = [['none', t('mail.cal.recNone')], ['daily', t('mail.cal.rec.daily')], ['weekly', t('mail.cal.rec.weekly')],
					['monthlyDay', t('mail.cal.recMonthlyDay', { day: new Date(startMs()).getDate() })],
					['monthlyPos', t('mail.cal.recMonthlyPos', { pos: t(`mail.cal.rec.pos.${p.pos}`), day: MS.weekdayName(p.day, lang(), true) })],
					['yearly', t('mail.cal.rec.yearly')]];
				if (R.kind === 'custom') kinds.push(['custom', t('mail.cal.rec.custom')]);
				for (const [v, label] of kinds) recSel.append(el('option', { value: v, text: label, selected: v === R.kind || null }));
			};
			recOpts();
			const recMore = el('div', { class: 'cal-rec-more' });
			const drawRec = () => {
				clear(recMore);
				recMore.hidden = R.kind === 'none' || R.kind === 'custom';
				if (recMore.hidden) return;
				const iv = el('input', { type: 'number', class: 'ml-input ml-input-port', min: '1', max: '99', value: String(R.interval || 1), 'aria-label': t('mail.cal.every') });
				iv.addEventListener('input', () => { R.interval = Number(iv.value) || 1; });
				recMore.append(field(t('mail.cal.every'), iv, 'cal-every'));
				if (R.kind === 'weekly') {
					const days = el('div', { class: 'cal-wdays', role: 'group', 'aria-label': t('mail.cal.onDays') });
					for (const d of MS.WEEKDAYS) {
						const on = R.days.includes(d);
						days.append(el('button', { type: 'button', class: `cal-wd${on ? ' on' : ''}`, 'aria-pressed': on ? 'true' : 'false', text: MS.weekdayName(d, lang()), on: { click: (e) => {
							R.days = R.days.includes(d) ? R.days.filter((x) => x !== d) : R.days.concat(d);
							e.currentTarget.classList.toggle('on');
							e.currentTarget.setAttribute('aria-pressed', R.days.includes(d) ? 'true' : 'false');
						} } }));
					}
					recMore.append(days);
				}
				const endSel = el('select', { class: 'ml-input', 'aria-label': t('mail.cal.ends') }, [['never', t('mail.cal.endNever')], ['until', t('mail.cal.endUntil')], ['count', t('mail.cal.endCount')]].map(([v, l]) => el('option', { value: v, text: l, selected: v === R.end || null })));
				const until = el('input', { type: 'date', class: 'ml-input', value: R.until || '', 'aria-label': t('mail.cal.endUntil'), hidden: R.end !== 'until' || null });
				const cnt = el('input', { type: 'number', class: 'ml-input ml-input-port', min: '1', max: '999', value: String(R.count || 10), 'aria-label': t('mail.cal.endCount'), hidden: R.end !== 'count' || null });
				endSel.addEventListener('change', () => { R.end = endSel.value; until.hidden = R.end !== 'until'; cnt.hidden = R.end !== 'count'; });
				until.addEventListener('change', () => { R.until = until.value; });
				cnt.addEventListener('input', () => { R.count = Number(cnt.value) || 1; });
				recMore.append(el('div', { class: 'cal-pair' }, [field(t('mail.cal.ends'), endSel), until, cnt]));
			};
			recSel.addEventListener('change', () => { R.kind = recSel.value; drawRec(); });
			recSel.addEventListener('focus', recOpts);
			drawRec();
			const place = el('input', { type: 'text', class: 'ml-input', maxlength: '500', value: F.location, 'aria-label': t('mail.cal.location') });
			place.addEventListener('input', () => { F.location = place.value; });
			// online
			const online = el('div', { class: 'cal-online' });
			const drawOnline = () => {
				clear(online);
				const c = calOf(F.calendarId);
				if (c && c.canOnline) online.append(el('label', { class: 'ml-check-row' }, [sw(F.teams, t('mail.cal.teams'), (on) => { F.teams = on; drawOnline(); }), el('span', { text: t('mail.cal.teams') })]));
				else F.teams = false;
				if (!F.teams) {
					const url = el('input', { type: 'url', class: 'ml-input', maxlength: '2048', value: F.onlineUrl, placeholder: 'https://', 'aria-label': t('mail.cal.onlineLink') });
					url.addEventListener('input', () => { F.onlineUrl = url.value; });
					online.append(field(t('mail.cal.onlineLink'), url));
				}
			};
			// reminders
			const rem = el('div', { class: 'cal-rems' });
			const drawRem = () => {
				clear(rem);
				const c = calOf(F.calendarId);
				const max = c ? c.maxReminders : 3;
				F.reminders = F.reminders.slice(0, max);
				F.reminders.forEach((m, i) => {
					const s = el('select', { class: 'ml-input ml-input-sm', 'aria-label': t('mail.cal.reminder') });
					for (const x of MS.REMINDERS) s.append(el('option', { value: String(x), text: MS.reminderText(x, t), selected: x === m || null }));
					s.addEventListener('change', () => { F.reminders[i] = Number(s.value); });
					rem.append(el('span', { class: 'cal-rem' }, [s, el('button', { type: 'button', class: 'ml-rcpt-x', 'aria-label': t('mail.cal.removeReminder'), on: { click: () => { F.reminders.splice(i, 1); drawRem(); } } }, [icon('close', 11)])]));
				});
				if (F.reminders.length < max) rem.append(el('button', { type: 'button', class: 'btn btn-ghost btn-xs', on: { click: () => { F.reminders.push(prefs.defaultReminder ?? 15); drawRem(); } } }, [icon('plus', 13), el('span', { text: t('mail.cal.addReminder') })]));
				if (!F.reminders.length && max === 0) rem.append(el('span', { class: 'ml-note', text: t('mail.cal.noReminders') }));
			};
			// attendees
			const attBox = el('div', { class: 'cal-atts' });
			const via = el('p', { class: 'ml-note cal-via' });
			const drawVia = () => {
				const c = calOf(F.calendarId);
				let acc = c && c.accountId ? MS.accountOf(ctx.me(), c.accountId) : null;
				if (!acc && c) {
					const accs = (ctx.me() && ctx.me().accounts) || [];
					acc = accs.find((a) => a.kind === (c.kind === 'business' ? 'business' : 'personal')) || accs[0] || null;
				}
				via.textContent = F.attendees.length && acc ? t('mail.cal.sentVia', { name: acc.name }) : '';
				via.hidden = !via.textContent;
			};
			const attInput = ctx.recipientInput({
				label: t('mail.cal.attendees'),
				list: () => F.attendees,
				onChange: (list) => { F.attendees = list; drawVia(); },
			});
			attBox.append(attInput, via);
			calSel.addEventListener('change', () => { F.calendarId = Number(calSel.value); drawOnline(); drawRem(); drawVia(); });
			drawOnline();
			drawRem();
			drawVia();
			const busy = el('select', { class: 'ml-input ml-input-sm', 'aria-label': t('mail.cal.showAs') }, ['busy', 'tentative', 'free', 'oof'].map((v) => el('option', { value: v, text: t(`mail.cal.busy.${v}`), selected: v === F.busy || null })));
			busy.addEventListener('change', () => { F.busy = busy.value; });
			const priv = sw(F.private, t('mail.cal.private'), (on) => { F.private = on; });
			const desc = el('textarea', { class: 'ml-input cal-desc-in', rows: '4', maxlength: '32000', 'aria-label': t('mail.cal.description') });
			desc.value = F.description;
			desc.addEventListener('input', () => { F.description = desc.value; });
			dlg.body.append(
				title,
				el('div', { class: 'cal-pair' }, [field(t('mail.cal.calendar'), calSel), el('label', { class: 'ml-check-row cal-allday-sw' }, [allDaySw, el('span', { text: t('mail.cal.allDay') })])]),
				times, tz,
				field(t('mail.cal.repeat'), recSel), recMore,
				field(t('mail.cal.location'), place), online,
				el('div', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: t('mail.cal.reminders') }), rem]),
				attBox,
				el('div', { class: 'cal-pair' }, [field(t('mail.cal.showAs'), busy), el('label', { class: 'ml-check-row' }, [priv, el('span', { text: t('mail.cal.private') })])]),
				field(t('mail.cal.description'), desc),
			);
			const err = el('span', { class: 'ml-dlg-err', role: 'alert' });
			const save = el('button', { type: 'button', class: 'btn btn-pri cal-save', text: t('mail.save'), on: { click: () => doSave() } });
			dlg.foot.append(err, el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), save);
			setTimeout(() => title.focus(), 0);

			async function doSave(again = null) {
				err.textContent = '';
				attInput.flush();
				const body = MS.eventBody(F, { hadOnline: !!(ev && ev.online) });
				if (body.error) { err.textContent = t(`mail.cal.bad.${body.error}`); return; }
				if (tzIn.value.trim() && tzIn.value.trim() !== zone) body.timeZone = tzIn.value.trim();
				else if (!ev && zone) body.timeZone = zone;
				save.disabled = true;
				let r;
				if (ev) {
					delete body.calendarId;
					const same = (k) => JSON.stringify(body[k]) === JSON.stringify(before[k]);
					const timesSame = ['allDay', 'start', 'end', 'startDate', 'endDate'].every(same);
					for (const k of Object.keys(body)) {
						if (k === 'title' || k === 'timeZone') continue;
						if (['allDay', 'start', 'end', 'startDate', 'endDate'].includes(k) ? timesSame : same(k)) delete body[k];
					}
					if (body.title === before.title && Object.keys(body).length > 1) delete body.title;
					if (again) body.etag = again;
					else if (ev.etag) body.etag = ev.etag;
					if (ev.recurring && ev.occurrence) {
						// a changed time of the whole series is made against the master's times (Mail 1.3.0 `series`);
						// without them (Mail 1.2.0) only this occurrence may move
						const moved = 'start' in body || 'startDate' in body || 'allDay' in body;
						const scope = await askScope(t('mail.cal.editTitle'), { seriesOk: !moved || !!ev.series });
						if (!scope) { save.disabled = false; return; }
						body.scope = scope;
						if (scope === 'occurrence') { body.occurrence = ev.occurrence; delete body.recurrence; }
						else if (moved) Object.assign(body, MS.seriesTimes(body, ev) || {});
					}
					r = await call(api.updateEvent(ev.eventId, body));
				} else {
					r = await call(api.createEvent(body));
				}
				save.disabled = false;
				if (r && r.code === 'conflict' && r.current) { conflictDialog(r.current, (choice) => { if (choice === 'mine') doSave(r.current.etag); else { dlg.close(); C.sheet = { item: r.current, event: r.current }; renderMain(); } }); return; }
				if (!r || !r.ok) { err.textContent = errText(r); return; }
				dlg.close();
				const sent = r.sent ? r.sent.mail + r.sent.internal : 0;
				toast(sent ? t('mail.cal.savedSent', { count: sent }) : t('mail.saved'), 'success');
				if (r.event) {
					if (!ev) { C.anchor = r.event.start; }
					C.sheet = { item: r.event, event: r.event };
				}
				await loadRange({ keep: true });
				if (r.event) openSheet(r.event, { quiet: true });
			}
		}

		/** 409 conflict: "Der Termin wurde inzwischen geändert" → 'reload' | 'mine'. */
		function conflictDialog(current, then) {
			const dlg = openDialog({ title: t('mail.cal.conflictTitle'), closeLabel: t('mail.close') });
			dlg.body.append(el('p', { class: 'ml-p', text: t('mail.cal.conflictText', { title: current.title }) }));
			dlg.foot.append(
				el('button', { type: 'button', class: 'btn btn-sec cal-reload', text: t('mail.cal.conflictReload'), on: { click: () => { dlg.close(); then('reload'); } } }),
				el('button', { type: 'button', class: 'btn btn-pri cal-mine', text: t('mail.cal.conflictMine'), on: { click: () => { dlg.close(); then('mine'); } } }),
			);
		}

		// ── Invitation card (the reading pane, the invitations) ─

		/** The small grid of the invitation's day: its time dashed, what else is on (conflicts red). */
		function miniGrid(inv) {
			const wrap = el('div', { class: 'cal-mini' });
			if (inv.allDay) return wrap;
			const from = new Date(inv.start); from.setMinutes(0, 0, 0); from.setHours(from.getHours() - 1);
			const to = new Date(inv.end); to.setMinutes(0, 0, 0); to.setHours(to.getHours() + (new Date(inv.end).getMinutes() ? 2 : 1));
			const px = 28;
			const hours = Math.max(2, Math.min(8, Math.round((to - from) / 3600000)));
			wrap.style.height = `${hours * px}px`;
			for (let i = 0; i < hours; i += 1) {
				const h = el('span', { class: 'cal-mini-h', text: String((from.getHours() + i) % 24).padStart(2, '0') });
				h.style.top = `${i * px}px`;
				wrap.append(h);
			}
			const place = (s, e, node) => {
				const top = Math.max(0, ((s - from.getTime()) / 3600000) * px);
				const bottom = Math.min(hours * px, ((e - from.getTime()) / 3600000) * px);
				if (bottom <= 0 || top >= hours * px) return;
				node.style.top = `${top}px`;
				node.style.height = `${Math.max(14, bottom - top - 2)}px`;
				wrap.append(node);
			};
			for (const o of inv.day || []) {
				const clash = (inv.conflicts || []).some((c) => c.start === o.start && c.title === o.title);
				const b = el('span', { class: `cal-mini-b${clash ? ' is-clash' : ''}`, text: o.title || '' });
				b.style.setProperty('--c', MS.itemColor(o, cals(), overlays()));
				place(o.start, o.end, b);
			}
			place(inv.start, inv.end, el('span', { class: 'cal-mini-b is-new', text: `${inv.title} (${t('mail.cal.new')})` }));
			return wrap;
		}

		/** The card of an invitation (mockup "Einladung"); onDone after an answer (the mail reloads). */
		function inviteCardOf(inv, { onDone = null, messageId = null } = {}) {
			const card = el('div', { class: 'ml-card cal-inv', 'data-invitation': String(inv.id) });
			const st = MS.inviteStatus(inv);
			const who = inv.from && (inv.from.name || inv.from.email) ? (inv.from.name || inv.from.email) : '';
			card.append(el('div', { class: 'cal-inv-head' }, [
				el('span', { class: 'cal-inv-ic' }, [icon('calendar', 18)]),
				el('span', { class: 'cal-inv-tx' }, [
					el('span', { class: 'cal-inv-title', text: inv.title || t('mail.cal.noTitle') }),
					el('span', { class: 'cal-inv-time', text: `${MS.eventDate(inv, lang())} · ${MS.eventTimeText(inv, lang(), t)}` }),
					inv.location ? el('span', { class: 'ml-sub', text: inv.location }) : null,
					inv.recurrence && inv.recurrence.summary ? el('span', { class: 'ml-sub', text: lang() === 'en' ? inv.recurrence.summary.en : inv.recurrence.summary.de }) : null,
				]),
			]));
			if (st) card.append(el('div', { class: `cal-inv-state is-${st.tone}`, text: t(`mail.cal.inv.${st.key}`, { name: who }) }));
			if (inv.comment) card.append(el('blockquote', { class: 'cal-inv-comment', text: inv.comment }));
			if (inv.method === 'counter' && inv.proposed) card.append(el('div', { class: 'ml-sub', text: t('mail.cal.inv.proposed', { time: `${MS.eventDate({ start: inv.proposed.start }, lang())} · ${MS.eventTimeText({ start: inv.proposed.start, end: inv.proposed.end }, lang(), t)}` }) }));
			if (inv.method === 'request' && inv.state !== 'outdated') {
				card.append(miniGrid(inv));
				if (inv.conflicts && inv.conflicts.length) card.append(el('div', { class: 'cal-inv-clash' }, [icon('alert', 14), el('span', { text: t('mail.cal.inv.clash', { list: inv.conflicts.map((c) => c.title).join(', ') }) })]));
				else if (!inv.allDay) card.append(el('div', { class: 'ml-sub', text: t('mail.cal.inv.noClash') }));
			}
			const busy = (b, on) => { for (const x of card.querySelectorAll('button')) x.disabled = on; if (b) b.classList.toggle('is-busy', on); };
			const done = async (r, okKey) => {
				if (!r || !r.ok) { toast(r && r.code === 'invitation_outdated' ? t('mail.cal.inv.outdated') : errText(r), 'error'); busy(null, false); return; }
				if (okKey) toast(t(okKey), 'success');
				C.invites = C.invites.filter((x) => x.id !== inv.id);
				reloadSoon(true);
				if (onDone) onDone(r);
			};
			if (inv.method === 'request' && (inv.state === 'open' || inv.state === 'answered')) {
				const answered = inv.state === 'answered' || (inv.myResponse && !['needs_action', 'organizer'].includes(inv.myResponse));
				const area = el('div', { class: 'cal-inv-answer', hidden: answered || null });
				const comment = el('textarea', { class: 'ml-input cal-inv-cmt', rows: '2', maxlength: '2000', placeholder: t('mail.cal.commentPh'), 'aria-label': t('mail.cal.comment'), hidden: true });
				const target = el('select', { class: 'ml-input ml-input-sm', 'aria-label': t('mail.cal.inv.target') });
				const fillTarget = () => {
					clear(target);
					for (const id of inv.calendarChoices) { const c = calOf(id); target.append(el('option', { value: String(id), text: c ? c.name : `#${id}`, selected: id === inv.calendarId || null })); }
				};
				fillTarget();
				if (!C.cals) loadCalendars().then(fillTarget);
				const answer = async (response, extra = {}) => {
					busy(null, true);
					const r = await call(api.respondInvitation(inv.id, { response, comment: comment.value.trim() || undefined, calendarId: target.value ? Number(target.value) : undefined, ...extra }));
					done(r, `mail.cal.answered.${response}`);
				};
				area.append(
					el('div', { class: 'cal-answer' }, [
						el('button', { type: 'button', class: 'btn btn-pri btn-sm cal-inv-yes', text: t('mail.cal.accept'), on: { click: () => answer('accepted') } }),
						el('button', { type: 'button', class: 'btn btn-sec btn-sm cal-inv-maybe', text: t('mail.cal.tentative'), on: { click: () => answer('tentative') } }),
						el('button', { type: 'button', class: 'btn btn-sec btn-sm cal-decline cal-inv-no', text: t('mail.cal.decline'), on: { click: () => answer('declined') } }),
					]),
					el('div', { class: 'cal-inv-more' }, [
						el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('mail.cal.inv.addComment'), on: { click: (e) => { comment.hidden = !comment.hidden; if (!comment.hidden) comment.focus(); e.currentTarget.hidden = true; } } }),
						el('button', { type: 'button', class: 'btn btn-ghost btn-xs cal-inv-propose', text: t('mail.cal.inv.propose'), on: { click: () => proposeTime(inv, (s, e2) => answer('tentative', { proposeStart: s, proposeEnd: e2 })) } }),
					]),
					comment,
					inv.calendarChoices.length ? el('label', { class: 'cal-inv-target' }, [el('span', { class: 'ml-sub', text: t('mail.cal.inv.target') }), target]) : null,
				);
				if (answered) card.append(el('button', { type: 'button', class: 'btn btn-ghost btn-xs cal-inv-change', text: t('mail.cal.inv.change'), on: { click: (e) => { area.hidden = false; e.currentTarget.remove(); } } }));
				card.append(area);
			} else if (inv.method === 'cancel' && inv.state === 'open') {
				card.append(el('div', { class: 'cal-answer' }, [el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('mail.cal.inv.remove'), on: { click: async () => { busy(null, true); done(await call(api.applyInvitation(inv.id)), 'mail.cal.inv.removed'); } } })]));
			} else if (inv.method === 'counter' && inv.state === 'open') {
				card.append(el('div', { class: 'cal-answer' }, [
					el('button', { type: 'button', class: 'btn btn-pri btn-sm', text: t('mail.cal.inv.applyCounter'), on: { click: async () => { busy(null, true); done(await call(api.applyInvitation(inv.id)), 'mail.cal.inv.applied'); } } }),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('mail.cal.inv.declineCounter'), on: { click: async () => { busy(null, true); done(await call(api.dismissInvitation(inv.id, true)), null); } } }),
				]));
			}
			if (inv.attendees.length) {
				const people = el('details', { class: 'cal-inv-people' }, [el('summary', { class: 'ml-sub', text: t('mail.cal.attendeesCount', { yes: inv.counts.accepted, total: inv.attendees.filter((a) => a.role !== 'resource').length }) })]);
				if (inv.organizer && inv.organizer.email) people.append(personRow({ name: inv.organizer.name, email: inv.organizer.email, contactId: inv.organizer.contactId }, t('mail.cal.organizer')));
				for (const a of inv.attendees) people.append(personRow(a, t(`mail.cal.resp.${a.response}`), a.response));
				card.append(people);
			}
			if (inv.eventId && messageId) card.append(el('button', { type: 'button', class: 'btn btn-ghost btn-xs cal-inv-open', text: t('mail.cal.inv.openInCalendar'), on: { click: () => ctx.openEvent(inv.eventId, null) } }));
			return card;
		}

		function proposeTime(inv, then) {
			const dlg = openDialog({ title: t('mail.cal.inv.propose'), closeLabel: t('mail.close') });
			const s = el('input', { type: 'datetime-local', class: 'ml-input', value: MS.localInputValue(inv.start), 'aria-label': t('mail.cal.from') });
			const e = el('input', { type: 'datetime-local', class: 'ml-input', value: MS.localInputValue(inv.end), 'aria-label': t('mail.cal.to') });
			const err = el('span', { class: 'ml-dlg-err', role: 'alert' });
			dlg.body.append(el('label', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: t('mail.cal.from') }), s]), el('label', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: t('mail.cal.to') }), e]));
			dlg.foot.append(err, el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), el('button', { type: 'button', class: 'btn btn-pri', text: t('mail.cal.inv.send'), on: { click: () => {
				const a = MS.localInputMs(s.value, 0);
				const b = MS.localInputMs(e.value, 0);
				if (!a || !b || b <= a) { err.textContent = t('mail.cal.bad.end'); return; }
				dlg.close();
				then(a, b);
			} } }));
		}

		/** The card in the reading pane of a mail with `invite`. */
		function inviteCard(message, { onDone } = {}) {
			return inviteCardOf(message.invite, { onDone, messageId: message.id });
		}

		async function openInvitation(id) {
			const r = await call(api.invitation(id));
			if (!r || !r.ok) { toast(errText(r), 'error'); return; }
			const dlg = openDialog({ title: t('mail.cal.invitation'), wide: true, closeLabel: t('mail.close') });
			dlg.body.append(inviteCardOf(r.invitation, { onDone: () => { dlg.close(); loadInvites(); } }));
			dlg.foot.append(el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.close'), on: { click: () => dlg.close() } }));
		}

		/** A reminder push / a shared event: the calendar on its day, the event's sheet. */
		async function openEvent(eventId, occurrence) {
			const r = await call(api.event(eventId, occurrence || null));
			if (!r || !r.ok) { toast(r && r.code === 'not_found' ? t('mail.cal.gone') : errText(r), 'error'); return; }
			C.anchor = r.event.start;
			if (C.view === 'list') C.view = 'week';
			C.sheet = { item: r.event, event: r.event, doc: r.doc, docDark: r.docDark, offline: !!r.offline };
			await loadRange();
		}

		// ── Lifecycle ────────────────────────────────────

		function onKey(e) {
			if (!C.shown || e.key !== 'Escape' || !C.sheet || document.querySelector('.ml-scrim')) return;
			e.preventDefault();
			closeSheet();
		}
		document.addEventListener('keydown', onKey);

		return {
			renderSide,
			/** The area is shown in `main` (the Mail page's right column). */
			async show(main) {
				C.main = main;
				C.shown = true;
				if (!C.cals) { await loadCalendars(); ctx.renderMenu(); }
				loadInvites();
				await loadRange({ keep: !!C.range });
			},
			hide() { C.shown = false; },
			relabel() { renderMain(); },
			/** mail:calendar live events. */
			onLive(c) {
				if (!c) return;
				if (c.kind === 'calendars') { C.cals = null; if (C.shown) reloadSoon(true); return; }
				if (c.kind === 'invitation') { loadInvites(); if (C.shown) reloadSoon(false); return; }
				if (C.shown) reloadSoon(false);
			},
			openEvent,
			openInvitation,
			inviteCard,
			newEvent: (at) => openEditor(null, at || null),
			calendars: () => C.cals,
		};
	}

	root.GCCalendarView = { create };
})(typeof self !== 'undefined' ? self : this);
