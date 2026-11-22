/**
 * GateControl -- Start: pinned favourites, the calendar widget (renderer,
 * plugin gatecontrol-mail 1.4.0) and the plugins' quick actions
 *
 * The section "Angeheftet" of the start page ("Übersicht") below the services:
 *  - the calendar widget: the next events of today and tomorrow (GET
 *    events/upcoming through the core's MailService; offline the last answer
 *    with a note). A click on an event opens it in the calendar, the head opens
 *    the calendar; it reloads on the live events of the calendar, at the change
 *    of the day and every few minutes (past ones go); × removes it.
 *  - tiles of the favourites pinned (GET cards/favorites): the picture or the
 *    initials, the name and the main number. A click calls the main number
 *    (tel:, like "Anrufen" of a contact); without a number, on the name or with
 *    a right click the contact opens. × loosens the tile.
 *  - cards of the plugins' quick actions pinned (one per device: values,
 *    controls, buttons — quick-actions-view.js); "Schnellaktionen" in the head
 *    pins them. They do not need Mail: without the Mail plugin the section
 *    shows only them.
 *
 * What is pinned is kept on this PC (localStorage gc.home.pins) by
 * window.GCHomePins, which the contacts ("Auf Start anheften" of a favourite)
 * and the calendar ("Termine auf Start anheften") use as well, and the quick
 * actions' dialog ("Schnellaktionen anheften"). Servers before Mail 1.4.0
 * answer without these paths: the section stays hidden and the calendar offers
 * no pin; a server without quick actions shows no button for them.
 *
 * Built by renderer.js through GCHomeView.mount(…); pure logic in mail-state.js
 * (GCMailState: homePins, pinContact, favoriteTiles, upcomingDays). Server text
 * only into textContent / attributes.
 */
(function (root) {
	'use strict';

	const MS = root.GCMailState;
	const QS = root.GCQuickActionsState;
	const KEY = 'gc.home.pins';
	const RELOAD_MS = 5 * 60 * 1000;

	// ── The pins of this PC ─────────────────────────────

	const listeners = new Set();
	const support = { calendar: null, favorites: null };   // null: not known yet; false: the server has no such path

	function load() {
		try { return MS.homePins(JSON.parse(root.localStorage.getItem(KEY) || 'null')); } catch { return MS.homePins(null); }
	}

	function notify(v) {
		for (const fn of [...listeners]) { try { fn(v); } catch { /* a listener's problem */ } }
	}

	function save(p) {
		const v = MS.homePins(p);
		try { root.localStorage.setItem(KEY, JSON.stringify(v)); } catch { /* storage unavailable */ }
		notify(v);
	}

	/** What the server has (the calendar widget, favourites); a change tells the listeners (the calendar's "anheften"). */
	function supports(what, yes) {
		if (support[what] === yes) return;
		support[what] = yes;
		notify(load());
	}

	const pins = {
		get: load,
		hasContact: (id) => load().contacts.includes(id),
		pinContact: (id, on) => save(MS.pinContact(load(), id, on)),
		hasCalendar: () => load().calendar,
		setCalendar: (on) => save({ ...load(), calendar: on === true }),
		/** The server has the calendar widget (unknown until it was asked: offered). */
		calendarSupported: () => support.calendar !== false,
		/** The quick actions pinned: [{ device, anchor, title, hidden }] (GCMailState.homeActionPins). */
		actions: () => load().actions,
		setActions: (list) => save({ ...load(), actions: list }),
		/** A device pinned (`device`: its group of GCQuickActionsState.group) or loosened (by its key). */
		pinDevice: (key, device, on) => {
			const p = load();
			save({ ...p, actions: on && device && QS ? QS.pinDevice(p.actions, device, true) : p.actions.filter((x) => x.device !== key) });
		},
		/** A part of a pinned device's card hidden or shown again. */
		setHidden: (key, partId, hide) => { if (QS) { const p = load(); save({ ...p, actions: QS.setHidden(p.actions, key, partId, hide) }); } },
		onChange(fn) { listeners.add(fn); return () => listeners.delete(fn); },
	};
	root.GCHomePins = pins;

	// ── The section ─────────────────────────────────────

	/**
	 * @param {object} o
	 * @param {HTMLElement} o.host - the section on the start page
	 * @param {object|null} o.api - window.gatecontrol.mail (null: no Mail, only the quick actions)
	 * @param {object|null} [o.quickActions] - window.gatecontrol.quickActions (core QuickActionsService)
	 * @param {Function} o.t
	 * @param {() => string} o.getLocale
	 * @param {(msg: string, type?: string) => void} o.toast
	 * @param {(context: object) => void} o.openMail - the Mail page on a target ({ kind: 'calendar' | 'event' | 'contact' })
	 */
	function mount(o) {
		const { api, t } = o;
		const { el, icon, clear } = root.GCMailUI;
		const lang = () => (o.getLocale && o.getLocale() === 'en' ? 'en' : 'de');
		const call = (p) => Promise.resolve(p).catch((err) => ({ ok: false, code: (err && err.code) || 'failed' }));
		const H = {
			available: false,
			features: [],
			favorites: null,      // { items, offline }
			upcoming: null,       // { …answer, offline }
			upError: false,
			day: null,
			loadedAt: 0,
		};
		const photos = new Map();   // `${id}:${etag}` → data: URL | null (none) | Promise (asked, on its way)
		const qa = o.quickActions && root.GCQuickActionsView && QS ? root.GCQuickActionsView.create({
			api: o.quickActions, pins, t, getLocale: o.getLocale, toast: o.toast, onChange: () => render(),
		}) : null;

		const has = (f) => H.features.includes(f);
		const showCal = () => H.available && has('calendar') && pins.hasCalendar() && support.calendar !== false;
		const tiles = () => (H.available && has('contacts') && H.favorites ? MS.favoriteTiles(H.favorites.items, load()) : []);

		async function loadFavorites() {
			if (!H.available || !has('contacts') || !load().contacts.length) { render(); return; }
			const r = await call(api.favorites());
			if (r && r.ok) {
				supports('favorites', !r.unsupported);
				H.favorites = r.unsupported ? null : { items: r.items, offline: !!r.offline };
			}
			render();
		}

		async function loadUpcoming() {
			if (!H.available || !has('calendar') || !pins.hasCalendar()) { render(); return; }
			const r = await call(api.upcoming({ days: 2, limit: 8 }));
			H.loadedAt = Date.now();
			H.day = new Date().toDateString();
			if (r && r.ok) {
				supports('calendar', !r.unsupported);
				H.upcoming = r.unsupported ? null : r;
				H.upError = false;
			} else H.upError = !H.upcoming;
			render();
		}

		async function refresh() {
			if (!api) { render(); return; }
			const st = await call(api.status());
			H.available = !!(st && st.state === 'available');
			if (H.available) {
				const me = await call(api.me());
				H.features = me && me.ok && Array.isArray(me.features) ? me.features : [];
				// once: whether the server has the widget (the calendar's "anheften" hides otherwise)
				if (support.calendar === null && has('calendar') && !pins.hasCalendar()) {
					const r = await call(api.upcoming({ days: 2, limit: 1 }));
					if (r && r.ok) supports('calendar', !r.unsupported);
				}
			}
			await Promise.all([loadUpcoming(), loadFavorites()]);
		}

		// ── Drawing ──────────────────────────────────────

		function avatar(f) {
			const box = el('span', { class: 'home-fav-av', 'aria-hidden': 'true', text: f.initials });
			if (f.photo) {
				const key = `${f.id}:${f.photoEtag || ''}`;
				const show = (url) => { if (url) { clear(box); box.append(el('img', { src: url, alt: '', draggable: 'false' })); } };
				// still on its way: the tile drawn again meanwhile waits for the same answer (else it kept the initials)
				if (!photos.has(key) && api.cardPhoto) {
					photos.set(key, call(api.cardPhoto(f.id, f.photoEtag)).then((r) => {
						const url = r && r.ok && /^data:image\/(jpeg|png);base64,/.test(r.url) ? r.url : null;
						photos.set(key, url);
						return url;
					}));
				}
				const p = photos.get(key);
				if (typeof p === 'string') show(p);
				else if (p) p.then(show);
			}
			return box;
		}

		async function dial(f) {
			if (!f.phone) { o.openMail({ kind: 'contact', contactId: f.id }); return; }
			const r = await call(api.call(f.phone));
			if (!r || !r.ok) o.toast(t('mail.con.noPhoneApp'), 'error');
		}

		function tile(f) {
			const open = () => o.openMail({ kind: 'contact', contactId: f.id });
			const box = el('div', { class: 'card home-fav', 'data-id': String(f.id), title: f.phone ? t('home.fav.call', { name: f.name }) : t('home.fav.noPhone'), on: {
				click: (e) => { if (!e.target.closest('.home-fav-name, .home-x')) dial(f); },
				contextmenu: (e) => { e.preventDefault(); open(); },
			} }, [
				el('button', { type: 'button', class: 'home-fav-call', 'aria-label': f.phone ? t('home.fav.call', { name: f.name }) : t('home.fav.open', { name: f.name }) }, [
					avatar(f),
					f.phone ? el('span', { class: 'home-fav-tel', 'aria-hidden': 'true' }, [icon('phone', 11, '2.4')]) : null,
				]),
				el('button', { type: 'button', class: 'home-fav-name', 'aria-label': t('home.fav.open', { name: f.name }), on: { click: open } }, [
					el('span', { class: 'svc-name', text: f.name }),
					el('span', { class: 'svc-host', text: f.phone || f.email || '' }),
				]),
				el('button', { type: 'button', class: 'btn btn-ghost home-x', title: t('home.fav.unpin', { name: f.name }), 'aria-label': t('home.fav.unpin', { name: f.name }), on: { click: () => pins.pinContact(f.id, false) } }, [icon('close', 13)]),
			]);
			return box;
		}

		function calendarCard() {
			const U = H.upcoming;
			const card = el('section', { class: 'card home-cal', 'aria-label': t('home.cal.title') });
			card.append(el('div', { class: 'home-cal-head' }, [
				el('button', { type: 'button', class: 'home-cal-open', title: t('home.cal.open'), on: { click: () => o.openMail({ kind: 'calendar' }) } }, [
					el('span', { class: 'home-cal-ic' }, [icon('calendar', 17)]),
					el('span', { class: 'svc-meta' }, [el('span', { class: 'h-card', text: t('home.cal.title') }), el('span', { class: 'desc', text: t('home.cal.sub') })]),
				]),
				el('button', { type: 'button', class: 'btn btn-ghost home-x', title: t('home.remove'), 'aria-label': t('home.remove'), on: { click: () => pins.setCalendar(false) } }, [icon('close', 14)]),
			]));
			if (U && U.offline) card.append(el('p', { class: 'home-cal-note', text: t('home.cal.offline') }));
			if (!U) {
				card.append(el('p', { class: 'home-cal-empty', text: H.upError ? t('home.cal.error') : t('mail.loading') }));
				return card;
			}
			const days = MS.upcomingDays(U, Date.now(), lang(), t);
			if (!days.length) card.append(el('p', { class: 'home-cal-empty', text: t('home.cal.empty') }));
			for (const d of days) {
				card.append(el('div', { class: 'home-cal-day', text: d.label }));
				for (const x of d.items) {
					const bar = el('span', { class: 'home-ev-bar' });
					if (x.color) bar.style.background = x.color;
					card.append(el('button', { type: 'button', class: `home-ev${x.tentative ? ' is-tentative' : ''}`, 'data-key': x.key, on: {
						click: () => o.openMail(x.eventId ? { kind: 'event', eventId: x.eventId, occurrence: x.occurrence || null } : { kind: 'calendar' }),
					} }, [
						el('span', { class: 'home-ev-time', text: x.time }),
						bar,
						el('span', { class: 'home-ev-tx' }, [
							el('span', { class: 'home-ev-title', text: x.title }),
							x.location || x.tentative ? el('span', { class: 'home-ev-sub', text: [x.tentative ? t('home.cal.tentative') : null, x.location].filter(Boolean).join(' · ') }) : null,
						]),
					]));
				}
			}
			if (U.more) card.append(el('span', { class: 'home-cal-more', text: t('home.cal.more', { count: U.more }) }));
			return card;
		}

		function render() {
			const host = o.host;
			if (!host) return;
			// drawn again: the focus stays on the same control of the same card
			const act = document.activeElement && host.contains(document.activeElement) ? document.activeElement : null;
			const focus = act && act.closest('[data-device]') ? [act.closest('[data-device]').getAttribute('data-device'), act.getAttribute('data-fk')] : null;
			clear(host);
			const list = tiles();
			const cal = showCal();
			const actions = !!qa && qa.available();
			host.hidden = !cal && !list.length && !actions;
			if (host.hidden) return;
			host.append(el('div', { class: 'home-pins-head' }, [el('h2', { class: 'h-card grow', text: t('home.title') }), qa ? qa.button() : null]));
			if (qa && qa.hasCards()) host.append(el('p', { class: 'home-pins-sub', text: t('home.qa.sub') }));
			host.append(el('div', { class: 'home-pins-grid' }, [cal ? calendarCard() : null, ...list.map(tile), ...(qa ? qa.cards() : [])]));
			if (focus && focus[1]) {
				const card = [...host.querySelectorAll('[data-device]')].find((n) => n.getAttribute('data-device') === focus[0]);
				const f = card && [...card.querySelectorAll('[data-fk]')].find((n) => n.getAttribute('data-fk') === focus[1]);
				if (f && !f.disabled) f.focus();
			}
		}

		// ── Keeping it current ───────────────────────────

		let calTimer = null;
		let favTimer = null;
		const soon = (which) => {
			if (which === 'cal') { clearTimeout(calTimer); calTimer = setTimeout(loadUpcoming, 400); } else { clearTimeout(favTimer); favTimer = setTimeout(loadFavorites, 400); }
		};
		if (api && api.onCalendar) api.onCalendar(() => soon('cal'));
		if (api && api.onContacts) api.onContacts((c) => { if (c && c.kind !== 'groups') soon('fav'); });
		if (api && api.onState) api.onState(() => refresh());
		pins.onChange(() => {
			if (qa) qa.pinsChanged();
			if (!H.favorites && load().contacts.length) loadFavorites();
			if (!H.upcoming && pins.hasCalendar()) loadUpcoming();
			render();
		});
		// the change of the day, past events: asked again
		setInterval(() => {
			if (!showCal()) return;
			if (H.day !== new Date().toDateString() || Date.now() - H.loadedAt > RELOAD_MS) loadUpcoming();
			else render();
		}, 60 * 1000);

		refresh();
		if (qa) qa.refresh();

		return {
			/** The language changed. */
			relabel() { if (qa) qa.relabel(); render(); },
			/** The start page is shown again: what may have changed meanwhile. */
			show() {
				if (H.available && Date.now() - H.loadedAt > 30 * 1000) { loadUpcoming(); loadFavorites(); }
				if (qa) qa.show();
			},
			refresh() { if (qa) qa.refresh(); return refresh(); },
			/** "Schnellaktionen anheften" (null without quick actions). */
			openQuickActions: qa ? () => qa.openPicker() : null,
		};
	}

	root.GCHomeView = { mount };
})(typeof self !== 'undefined' ? self : this);
