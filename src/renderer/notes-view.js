/**
 * GateControl -- Notizen & Aufgaben (renderer view of the plugin gatecontrol-notizen)
 *
 * The PC layout of the mockup "Windows": the menu (Privat | Arbeit, Mein Tag, Wichtig, Geplant, Mir zugewiesen, the
 * other plugins, my lists, notebooks, tags, Quellen, Umziehen), the list in the middle with the quick entry (Strg+N;
 * read on this PC with the plugin's own ui/quickparse.js for the chips, created by the server with the same parser)
 * and the details on the right — a task (sub tasks, due, reminder, repeat, list, attachments, note), an item of
 * another plugin (ticked off there, opened there: Mail's mail, Drive's deadline, Schule; else its portal tab) or a note
 * (Markdown with a toolbar; shown with notes-md.js as a tree of nodes — never an HTML string; check boxes, a line → a
 * task, pictures and files). Tresor notebooks: end-to-end encrypted in the main process; locked / unlocked with Windows
 * Hello, a new device asks, the recovery key, a new key. "Quellen" (the person's choices per source) and "Umziehen"
 * (Microsoft To Do by device code through Mail; DS Note's .nsx read on this PC with a password for protected notes).
 * Plugin 1.3.0 (the words of me.features): the card „Gestern offen geblieben“ above „Heute“ in Mein Tag (a row: Erledigt,
 * Heute, Verschieben; „Alle heute“), a task's marks (Erinnerung, Später: …, im Kalender), the calendar chip of the quick
 * entry, and the buttons of the morning hint that open the page (open({ kind: 'yesterday', action })).
 * Plugin 1.4.0 (`shoppingLists`, `taskList`): the shopping lists in the menu and a list's page (tick off, add, change,
 * delete items; shown at once, sent by the main process in order — also later when the server is away), the mark
 * „Einkauf 0/8“ of a task (opens the list), „Angehängte Liste“ in a task's details, the list chip of the quick entry
 * (the server's suggestion — the parser on this PC is untouched), „Alles abgehakt“ with „Rückgängig“, and the button
 * „Liste öffnen“ of a reminder (open({ kind: 'shopping', uid })).
 * Plugin 1.5.0 (`places`, `placeSearch`): a task hangs on a place — the mark and the line „Ort“ of a task, the dialog
 * „Welcher …?“ (the places near one of the person's places with estimated minutes and kilometres, „Jeder …“, „Meine
 * Orte“, on arriving / on leaving, remembering — a list, no map: this app loads no map tiles), the place chip of the
 * quick entry (the server's suggestion), „Orte“ on the page „Quellen“ (the person's switches, „Meine Orte“) and the
 * consent for a place someone else set. The phone watches the places and reminds; this PC shows and changes them. A
 * search goes out only when the person asks for it (the chip, „Suchen“, Enter) — never while typing.
 * Plugin 1.6.0 (`taskTurns`, `taskStars`, `familyTasks`, `doneFeedback`, `placeMine`): „Wer ist dran?“ (Eine Person ·
 * Reihum · Wer zuerst) in the quick entry (from two people on; read on this PC with the plugin's own ui/turnwords.js
 * after the parser) and in a task's details with „Wer macht mit“, the marks of a row (whose turn, the stars, „Erledigt
 * von …“), the stars of a task of the family's list (given by parents only), a parent ticks off for a child („Abhaken
 * für“) and hands a task back („Noch nicht fertig“ — also a button of the message „… hat ‚…‘ erledigt“), the family's
 * list (managed by the Familie plugin: no sharing, leaving or deleting here; a child changes only what no parent made),
 * the note „Umzug abgeschlossen“ once, „Meldung, wenn ein Kind abhakt“ on the page „Quellen“, and the consent for a
 * place only for who may give it. The stars are counted in the Familie plugin; this page only shows the number.
 * Plugin 1.7.0 (`driveDeadlines`): „Notizen & Aufgaben“ rings the reminders of Drive's deadlines — such a task shows
 * the deadline at its row („Frist 30. Nov. · Versicherungsschein.pdf · 3 Tage vorher“) and in its details („Aus Drive“
 * with „Datei öffnen“: the file on the Drive page; where the deadline and the days are set), and says what deleting it
 * means. A list the person only reads has no quick entry, its tasks are shown but not changed.
 *
 * Data: window.gatecontrol.notes (core NotesService over IPC); texts: notes.* of the Pro locales; logic without DOM:
 * notes-state.js (window.GCNotesState), notes-md.js (window.GCNotesMd). Server text only ever goes into textContent
 * or attributes that are not URLs; icons are static path data (createElementNS).
 */
(function (root) {
	'use strict';

	const NS = root.GCNotesState;
	const MD = root.GCNotesMd;
	const SVG = 'http://www.w3.org/2000/svg';
	const ICONS = {
		sun: 'M12 4V2M12 22v-2M4 12H2M22 12h-2M5.6 5.6 4.2 4.2M19.8 19.8l-1.4-1.4M5.6 18.4l-1.4 1.4M19.8 4.2l-1.4 1.4|M12 7a5 5 0 1 0 0 10a5 5 0 1 0 0-10',
		star: 'M12 3l2.8 5.7 6.2.9-4.5 4.4 1 6.2L12 17.3 6.5 20.2l1-6.2L3 9.6l6.2-.9z',
		cal: 'M4 6h16v14H4zM4 10h16M8 3v4M16 3v4',
		bell: 'M6 16v-5a6 6 0 0 1 12 0v5l2 2H4z|M10 21h4',
		flag: 'M5 21V4M5 4h12l-2 4 2 4H5',
		user: 'M12 4a4 4 0 1 0 0 8a4 4 0 1 0 0-8|M4 21a8 8 0 0 1 16 0',
		list: 'M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01',
		plus: 'M12 5v14M5 12h14',
		check: 'M5 12l5 5L20 7',
		note: 'M6 3h9l4 4v14H6zM14 3v5h5',
		lock: 'M6 11h12v10H6zM8 11V8a4 4 0 0 1 8 0v3',
		unlock: 'M6 11h12v10H6zM8 11V8a4 4 0 0 1 7.5-2',
		tag: 'M3 12V4h8l10 10-8 8z|M7.5 8.5h.01',
		pin: 'M9 3h6l-1 6 4 4H6l4-4zM12 13v8',
		trash: 'M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3',
		back: 'M15 18l-6-6 6-6',
		open: 'M14 4h6v6M20 4l-9 9M18 14v6H4V6h6',
		gear: 'M12 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6|M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
		move: 'M4 12h16M14 6l6 6-6 6',
		search: 'M11 4a7 7 0 1 0 0 14a7 7 0 1 0 0-14|M21 21l-5-5',
		clip: 'M21 12l-8.5 8.5a5 5 0 0 1-7-7L14 5a3.5 3.5 0 0 1 5 5l-8.5 8.5a2 2 0 0 1-3-3L15 8',
		edit: 'M4 20h4L20 8l-4-4L4 16zM14 6l4 4',
		x: 'M6 6l12 12M18 6L6 18',
		refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8|M21 3v5h-5',
		image: 'M4 5h16v14H4z|M4 16l5-5 4 4 3-3 4 4|M15 9h.01',
		table: 'M4 5h16v14H4zM4 10h16M4 15h16M10 5v14',
		link: 'M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1|M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1',
		devices: 'M3 5h13v10H3z|M8 19h3|M18 9h3v11h-3z',
		key: 'M15 4a5 5 0 1 0 0 10a5 5 0 1 0 0-10|M11 12l-8 8M5 18l2 2M7 16l2 2',
		cloud: 'M7 18h10a4 4 0 0 0 .5-8A6 6 0 0 0 6 9.5 4.3 4.3 0 0 0 7 18z',
		cart: 'M3 4h2.5l2.3 10.5h9.6L19.5 7H6.6|M9.5 19.5h.01|M16.5 19.5h.01',
		home: 'M4 11l8-7 8 7|M6 10v10h12V10|M10 20v-5h4v5',
		place: 'M12 21s-7-6.3-7-11.2a7 7 0 0 1 14 0C19 14.7 12 21 12 21z|M12 7.3a2.6 2.6 0 1 0 0 5.2a2.6 2.6 0 1 0 0-5.2',
		turn: 'M17 2l4 4-4 4|M3 11V9a3 3 0 0 1 3-3h15|M7 22l-4-4 4-4|M21 13v2a3 3 0 0 1-3 3H3',
		clock: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 7v5l3 2',
		people: 'M9 11a3.5 3.5 0 1 0 0-7a3.5 3.5 0 0 0 0 7z|M2.5 20a6.5 6.5 0 0 1 13 0|M16 4.3a3.5 3.5 0 0 1 0 6.4|M18 14.2a6.5 6.5 0 0 1 3.5 5.8',
	};

	function icon(name, size = 18) {
		const s = document.createElementNS(SVG, 'svg');
		s.setAttribute('viewBox', '0 0 24 24');
		s.setAttribute('width', String(size));
		s.setAttribute('height', String(size));
		s.setAttribute('fill', 'none');
		s.setAttribute('stroke', 'currentColor');
		s.setAttribute('stroke-width', '2');
		s.setAttribute('stroke-linecap', 'round');
		s.setAttribute('stroke-linejoin', 'round');
		s.setAttribute('aria-hidden', 'true');
		for (const d of String(ICONS[name] || ICONS.list).split('|')) {
			const p = document.createElementNS(SVG, 'path');
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
			else if (k === 'value') n.value = String(v);
			else if (k === 'checked') n.checked = !!v;
			else if (k === 'disabled') n.disabled = !!v;
			else n.setAttribute(k, v === true ? '' : String(v));
		}
		for (const c of kids || []) if (c !== null && c !== undefined && c !== false && c !== '') n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
		return n;
	}
	const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };

	/**
	 * @param {object} o
	 * @param {HTMLElement} o.root - the page section (empty)
	 * @param {object} o.api - window.gatecontrol.notes
	 * @param {Function} o.t - i18n
	 * @param {() => string} o.getLocale
	 * @param {(msg: string, type?: string) => void} o.toast
	 * @param {(target: object) => void} o.openTarget - a page of the app ({ page, context }) or the portal ({ portal })
	 * @param {() => string[]} o.pages - the pages that exist right now
	 * @param {(url: string) => void} o.openExternal - a link of a note in the browser (core checks it)
	 * @param {(st: object) => void} [o.onStatus] - availability (nav entry)
	 * @param {(n: number) => void} [o.onCount] - what "Mein Tag" counts (the nav badge)
	 * @param {object} [o.places] - window.gatecontrol.places: plugin 1.8.0 (`profilePlaces`) loads „Meine Orte“ again on a change
	 * @param {() => void} [o.openPlaces] - the page „Meine Orte“ of this app; [o.placesShown] whether it is there
	 * @returns {{ show(), hide(), open(ctx), focusQuick(), refresh(), status(), available(), relabel() }}
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const lang = () => (String(o.getLocale() || 'de').startsWith('en') ? 'en' : 'de');
		const toast = (msg, type, action) => o.toast(msg, type || 'info', action || null);
		const fail = (r) => toast(NS.errText(r, t), 'error');
		const ok = (r) => !!r && r.ok !== false;

		const S = {
			status: null, shown: false, me: null, area: 'private', nav: null, people: [], view: { kind: 'smart', id: 'myday' }, data: null,
			detail: null, detailData: null, editing: false, folded: {}, seq: 0, dseq: 0, dirty: true, quickText: '',
			ds: null, dsEvent: null, images: new Map(),
			shop: null,   // plugin 1.4.0: { lists, items, pending, stale } — the shopping lists as the main process holds them
			places: null, // plugin 1.5.0: { places, family, favs } — „Meine Orte“ as the page „Quellen“ shows them
			quickPlace: null, // … and what the person chose for the quick entry's line: { text, choice }
			quickTurn: null,  // plugin 1.6.0: „Wer ist dran?“ chosen for the people of the quick entry's line: { key, value }
			movedTold: false, // … and the note „Umzug abgeschlossen“ was shown in this run
			// plugin 1.9.0: „Aufgabe | Termin | Notiz“, the choices of the chips of an event ({ text, date, time, endTime,
			// allDay, location, calendarId, reminder }), „Aufgabe lassen“ until the line is emptied or saved, the calendars
			quickMode: 'task', quickEv: null, quickKeepTask: false, cals: null, calsAt: 0,
		};

		// ── skeleton ─────────────────────────────────────────
		const rootEl = el('div', { class: 'nz', 'data-pane': 'list' });
		o.root.appendChild(rootEl);
		const refs = {};
		refs.side = el('nav', { class: 'nz-side scroll', 'aria-label': t('notes.title') });
		refs.main = el('section', { class: 'nz-main scroll', 'aria-live': 'polite' });
		refs.detail = el('aside', { class: 'nz-detail scroll', 'aria-label': t('notes.details') });
		refs.gate = el('div', { class: 'nz-gate', hidden: true });
		rootEl.append(refs.side, refs.main, refs.detail, refs.gate);

		// ── loading ──────────────────────────────────────────
		async function loadMe() {
			const r = await Promise.resolve(api.me({ refresh: true })).catch(() => null);
			if (!ok(r)) return false;
			S.me = r.me;
			S.vaultSupported = r.vaultSupported !== false;
			// the area the person chose last (prefs) — once; later the switch decides
			if (!S.areaSet) { S.area = (r.me.prefs && r.me.prefs.area) === 'work' ? 'work' : 'private'; S.areaSet = true; }
			return true;
		}

		async function reloadNav() {
			const r = await Promise.resolve(api.nav(S.area)).catch(() => null);
			if (ok(r)) {
				S.nav = r.nav;
				if (o.onCount) o.onCount(r.nav.smart.myday);
			}
			renderSide();
		}

		// ── „Termin“ (plugin 1.9.0) ─────────────────────────
		const eventsOn = () => NS.eventsOn(S.me);

		/** The person's calendars in Mail (asked at most once a minute here; offline the last answer). */
		async function loadCals(force = false) {
			if (!eventsOn()) { S.cals = null; return null; }
			if (!force && S.cals && Date.now() - S.calsAt < 60000) return S.cals;
			const r = await Promise.resolve(api.eventCalendars()).catch(() => null);
			if (ok(r)) { S.cals = r.calendars; S.calsAt = Date.now(); }
			return S.cals;
		}

		// ── shopping lists (plugin 1.4.0) ───────────────────
		const shopOn = () => NS.offers(S.me, 'shoppingLists');

		/** An answer of shopping() / shoppingOps() → what the page holds; tasks a list completed are told once. */
		function takeShop(r) {
			if (!ok(r)) return false;
			S.shop = { lists: r.lists || [], items: r.items || [], pending: r.pending || 0, stale: r.stale === true || r.offline === true };
			if (r.completed && r.completed.length) allTicked(r.completed);
			return true;
		}

		async function reloadShop() {
			if (!shopOn()) { S.shop = null; return; }
			takeShop(await Promise.resolve(api.shopping()).catch(() => null));
			renderSide();
			if (S.view.kind !== 'shopping') return;
			// the list is gone (deleted, left, no longer shared)
			if (S.shop && !NS.shopList(S.shop, S.view.id)) { go({ kind: 'smart', id: 'myday' }); return; }
			renderMainKeepingFocus();
		}

		/** The list's page again without losing what is being typed into „Punkt hinzufügen“. */
		function renderMainKeepingFocus() {
			const a = document.activeElement;
			const id = a && refs.main.contains(a) && a.id ? a.id : null;
			const pos = id && typeof a.selectionStart === 'number' ? [a.selectionStart, a.selectionEnd] : null;
			renderMain();
			const again = id ? refs.main.querySelector(`#${id}`) : null;
			if (again) { again.focus(); if (pos) { try { again.setSelectionRange(pos[0], pos[1]); } catch { /* not a text field */ } } }
		}

		/** „Alles abgehakt. ‚Bei Lidl einkaufen‘ ist erledigt.“ — with the way back (the items stay ticked). */
		function allTicked(completed) {
			const text = NS.allTickedText(completed, t);
			if (!text) return;
			toast(text, 'success', { label: t('notes.shop.undo'), run: async () => {
				for (const c of completed) { const r = await api.completeTask(c.taskId, false); if (!ok(r)) { fail(r); break; } }
				soon(0);
			} });
			soon(150);
		}

		/** Operations on the shopping lists: shown at once (the main process queues and sends them). */
		async function shopOps(ops) {
			const r = await Promise.resolve(api.shoppingOps(ops)).catch(() => null);
			if (!takeShop(r)) { if (r) fail(r); return null; }
			if (r.rejected && r.rejected.length) toast(NS.errText({ code: r.rejected[0].code }, t), 'error');
			renderSide();
			if (S.view.kind === 'shopping') { if (NS.shopList(S.shop, S.view.id)) renderMainKeepingFocus(); else go({ kind: 'smart', id: 'myday' }); }
			return r;
		}

		function openShopList(uid) {
			const l = NS.shopList(S.shop, uid);
			if (!l) return false;
			if (l.area !== S.area) { S.area = l.area; reloadNav(); }
			go({ kind: 'shopping', id: uid });
			return true;
		}

		function notebookOf(id) {
			return ((S.nav && S.nav.notes && S.nav.notes.notebooks) || []).find((b) => b.id === id) || null;
		}

		async function loadView() {
			const v = S.view;
			if (v.kind === 'smart') return api.view(v.id, S.area);
			if (v.kind === 'list') return api.view(`list:${v.id}`, S.area);
			if (v.kind === 'source') return api.view(`source:${v.plugin}`, S.area);
			if (v.kind === 'search') return api.search(v.q, S.area);
			if (v.kind === 'sources') {
				// plugin 1.5.0: „Orte“ shows what holds now (the administrator may have switched the search on or off meanwhile)
				if (placesOn()) { await loadMe(); reloadPlaces(); }
				// plugin 1.9.0: „Termine aus dem Kalender“ (the switches as the server holds them now)
				if (eventsOn()) await loadCals(true);
				return api.sources();
			}
			if (v.kind === 'import') return { ok: true };
			if (v.kind === 'shopping') return { ok: true };   // shown from S.shop (reloadShop)
			// notes
			const nb = v.notebook ? notebookOf(v.notebook) : null;
			if (nb && nb.vault) {
				const st = await api.vaultOpen(nb.vault.id);
				if (!ok(st)) return st;
				if (st.state !== 'open') return { ok: true, locked: st.state, notebook: nb, notes: [] };
				const r = await api.notes({ notebook: nb.id, limit: 200 });
				const info = await Promise.resolve(api.vaultInfo(nb.vault.id)).catch(() => null);
				return ok(r) ? { ok: true, notebook: nb, notes: r.notes, next: r.next, vault: ok(info) ? info.vault : null } : r;
			}
			const q = { area: S.area, notebook: v.notebook || null, tag: v.tag || null };
			const [p, all] = await Promise.all([api.notes({ ...q, pinned: true, limit: 50 }), api.notes({ ...q, limit: 60 })]);
			if (!ok(p)) return p;
			if (!ok(all)) return all;
			return { ok: true, notebook: nb, pinned: p.notes, notes: all.notes.filter((n) => !n.pinned), next: all.next };
		}

		async function reloadView() {
			if (S.view.kind === 'shopping') { ++S.seq; S.data = { ok: true }; renderMainKeepingFocus(); return; }
			const seq = ++S.seq;
			const r = await Promise.resolve(loadView()).catch((err) => ({ ok: false, code: 'failed', error: err && err.message }));
			if (seq !== S.seq) return;
			if (!ok(r)) {
				if (r && r.code === 'not_found' && S.view.kind !== 'smart') { go({ kind: 'smart', id: 'myday' }); return; }
				S.data = { error: r };
			} else S.data = r;
			renderMain();
		}

		async function reloadDetail() {
			const d = S.detail;
			if (!d) { renderDetail(); return; }
			const seq = ++S.dseq;
			const r = await Promise.resolve(d.type === 'task' ? api.task(d.id) : d.type === 'source' ? api.item(d.id) : api.note(d.id)).catch(() => null);
			if (seq !== S.dseq) return;
			if (!ok(r)) {
				if (r && r.code === 'not_found') { S.detail = null; S.detailData = null; }
				else if (r) fail(r);
			} else S.detailData = r;
			renderDetail();
		}

		async function reloadAll() {
			if (!S.me) { if (!(await loadMe())) { renderGate('error'); return; } }
			renderGate(null);
			const pp = Promise.resolve(api.people()).then((r) => { if (ok(r)) S.people = r.people; }).catch(() => {});
			await Promise.all([reloadNav(), reloadView(), pp, reloadShop(), loadCals()]);
			if (S.detail && !S.editing) reloadDetail();
			movedNote();
		}

		/**
		 * „Umzug abgeschlossen“ (plugin 1.6.0) — once per person: the tasks and place reminders of the family live in this
		 * page now. „OK“ and „Ansehen“ tell the server it was read; „Ansehen“ opens the family's list.
		 */
		function movedNote() {
			const f = NS.familyInfo(S.me);
			if (!f.moved || f.moved.seen || S.movedTold || !S.shown) return;
			S.movedTold = true;
			let d = null;
			const seen = async (look) => {
				d.close();
				const r = await Promise.resolve(api.familySeen()).catch(() => null);
				if (ok(r) && S.me && S.me.familyTasks && S.me.familyTasks.moved) S.me.familyTasks.moved.seen = true;
				if (look) go({ kind: 'list', id: f.listId });
			};
			d = dialog(t('notes.moved.title'), [
				el('p', { class: 'nz-p', text: t('notes.moved.what', { tasks: f.moved.tasks, places: f.moved.places }) }),
				el('ul', { class: 'nz-moved' }, ['keep', 'places', 'stars', 'copy'].map((k) => el('li', { text: t(`notes.moved.${k}`) }))),
			], [btn(t('notes.moved.look'), () => seen(true), 'btn-sec', null, { 'data-act': 'moved-look' }), btn(t('notes.moved.ok'), () => seen(false), 'btn-pri', null, { 'data-act': 'moved-ok' })], { wide: true });
			d.box.setAttribute('data-dlg', 'moved');
		}

		let soonTimer = null;
		function soon(ms = 350) {
			clearTimeout(soonTimer);
			soonTimer = setTimeout(() => {
				if (!S.shown) { S.dirty = true; return; }
				reloadNav();
				reloadView();
				reloadShop();
				if (S.detail && !S.editing) reloadDetail();
			}, ms);
		}

		function go(view) {
			S.view = view;
			S.detail = null;
			S.detailData = null;
			S.editing = false;
			rootEl.setAttribute('data-pane', 'list');
			renderSide();
			renderDetail();
			S.data = null;
			renderMain();
			return reloadView();
		}

		function renderGate(kind) {
			refs.gate.hidden = !kind;
			for (const n of [refs.side, refs.main, refs.detail]) n.hidden = !!kind;
			if (!kind) return;
			clear(refs.gate).append(icon('note', 40), el('b', { text: t('notes.unavailable') }),
				el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('notes.retry'), on: { click: () => { S.me = null; reloadAll(); } } }));
		}

		// ── dialogs ──────────────────────────────────────────
		function dialog(title, body, actions, opts = {}) {
			const scrim = el('div', { class: 'scrim nz-scrim' });
			const box = el('div', { class: `card dialog nz-dlg${opts.wide ? ' is-wide' : ''}`, role: 'dialog', 'aria-modal': 'true', 'aria-label': title });
			const close = () => { scrim.remove(); document.removeEventListener('keydown', onKey, true); if (opts.onClose) opts.onClose(); };
			const onKey = (e) => { if (e.key === 'Escape' && !opts.sticky) { e.stopPropagation(); close(); } };
			box.append(el('div', { class: 'nz-dlg-head' }, [el('h3', { class: 'nz-dlg-title', text: title }), opts.sticky ? null : el('button', { type: 'button', class: 'nz-ib', 'aria-label': t('notes.close'), title: t('notes.close'), on: { click: close } }, [icon('x', 16)])]));
			for (const n of body) if (n) box.appendChild(n);
			if (actions && actions.length) box.appendChild(el('div', { class: 'dlg-actions' }, actions));
			scrim.appendChild(box);
			scrim.addEventListener('mousedown', (e) => { if (e.target === scrim && !opts.sticky) close(); });
			document.addEventListener('keydown', onKey, true);
			rootEl.appendChild(scrim);
			const first = box.querySelector('input, textarea, select');
			if (first) setTimeout(() => first.focus(), 0);
			return { close, box };
		}

		const btn = (label, fn, cls = 'btn-sec', ic = null, attrs = {}) => el('button', { type: 'button', class: `btn btn-sm ${cls}`, on: { click: fn }, ...attrs }, [ic ? icon(ic, 15) : null, el('span', { text: label })]);
		const ib = (name, label, fn, on = false, attrs = {}) => el('button', { type: 'button', class: `nz-ib${on ? ' on' : ''}`, title: label, 'aria-label': label, 'aria-pressed': on ? 'true' : null, on: { click: fn }, ...attrs }, [icon(name, 17)]);
		const field = (label, control, hint) => el('label', { class: 'nz-f' }, [el('span', { class: 'nz-f-l', text: label }), control, hint ? el('span', { class: 'hint', text: hint }) : null]);
		const sw = (on, onChange, label, disabled = false) => {
			const b = el('button', { type: 'button', class: `sw${on ? ' on' : ''}`, role: 'switch', 'aria-checked': on ? 'true' : 'false', 'aria-label': label, disabled }, [el('span')]);
			b.addEventListener('click', () => { const v = b.getAttribute('aria-checked') !== 'true'; b.classList.toggle('on', v); b.setAttribute('aria-checked', v ? 'true' : 'false'); onChange(v); });
			return b;
		};

		function prompt(title, value, onSave, extra = []) {
			const input = el('input', { class: 'inp', type: 'text', value: value || '', maxlength: '80', 'aria-label': t('notes.name') });
			const err = el('p', { class: 'nz-err', role: 'alert' });
			let d = null;
			const save = async () => {
				const v = input.value.trim();
				if (!v) return;
				const r = await onSave(v);
				if (r && r.ok === false) { err.textContent = NS.errText(r, t); return; }
				d.close();
			};
			input.addEventListener('keydown', (e) => { if (e.key === 'Enter') save(); });
			d = dialog(title, [field(t('notes.name'), input), ...extra, err], [btn(t('notes.cancel'), () => d.close(), 'btn-ghost'), btn(t('notes.save'), save, 'btn-pri')]);
			return d;
		}

		/** The recovery key, shown once: kept? Then it closes. */
		function showRecovery(key, name) {
			return new Promise((resolve) => {
				const kept = el('input', { type: 'checkbox', id: 'nz-rec-kept' });
				const done = btn(t('notes.vault.recoveryDone'), () => { d.close(); resolve(); }, 'btn-pri', null, { disabled: true });
				kept.addEventListener('change', () => { done.disabled = !kept.checked; });
				const copy = btn(t('notes.vault.copy'), () => { navigator.clipboard.writeText(key).then(() => toast(t('notes.vault.copied'), 'success'), () => {}); }, 'btn-sec', 'key');
				const d = dialog(t('notes.vault.recoveryTitle'), [
					el('p', { class: 'nz-p', text: t('notes.vault.recoveryText', { name: name || '' }) }),
					el('p', { class: 'nz-recovery mono', text: key, 'data-recovery': 'true' }),
					el('div', { class: 'nz-row-acts' }, [copy]),
					el('label', { class: 'nz-check' }, [kept, el('span', { text: t('notes.vault.recoveryKept') })]),
				], [done], { sticky: true, wide: true });
			});
		}

		// ── the menu ─────────────────────────────────────────
		function navRow(label, count, current, fn, opts = {}) {
			return el('button', {
				type: 'button', class: `nz-it${current ? ' on' : ''}${opts.sub ? ' sub' : ''}${opts.quiet ? ' quiet' : ''}`, 'aria-current': current ? 'page' : null,
				'data-view': opts.key || null, on: { click: () => { fn(); } },
			}, [opts.icon ? icon(opts.icon, 17) : null, opts.dot ? el('span', { class: 'nz-dot', 'data-color': opts.dot }) : null,
				el('span', { class: 'nz-it-tx', text: label }), opts.mark ? el('span', { class: 'nz-it-mark', title: opts.markTitle || null }, [icon(opts.mark, 14)]) : null,
				count ? el('span', { class: 'nz-n', text: String(count) }) : null]);
		}
		const isView = (kind, id) => {
			const v = S.view;
			return v.kind === kind && (id === undefined || v.id === id || v.plugin === id || (kind === 'notes' && v.notebook === id));
		};

		function renderSide() {
			const s = clear(refs.side);
			s.appendChild(el('h2', { class: 'nz-side-h', text: t('notes.title') }));
			const seg = el('div', { class: 'seg nz-area', role: 'group', 'aria-label': t('notes.areaLabel') });
			for (const a of ['private', 'work']) {
				seg.appendChild(el('button', { type: 'button', class: S.area === a ? 'on' : '', 'aria-pressed': S.area === a ? 'true' : 'false', 'data-area': a, text: t(`notes.area.${a}`), on: { click: () => setArea(a) } }));
			}
			s.appendChild(seg);
			const search = el('input', { id: 'nz-search', class: 'inp', type: 'search', placeholder: t('notes.searchPh'), 'aria-label': t('notes.search'), maxlength: '200' });
			search.value = S.view.kind === 'search' ? S.view.q : '';
			search.addEventListener('keydown', (e) => { if (e.key === 'Enter' && search.value.trim().length >= 2) go({ kind: 'search', q: search.value.trim() }); });
			s.appendChild(el('label', { class: 'search nz-search' }, [icon('search', 16), search]));
			const n = S.nav;
			const sm = (n && n.smart) || {};
			s.appendChild(navRow(t('notes.v.myday'), sm.myday, isView('smart', 'myday'), () => go({ kind: 'smart', id: 'myday' }), { icon: 'sun', key: 'myday' }));
			s.appendChild(navRow(t('notes.v.important'), sm.important, isView('smart', 'important'), () => go({ kind: 'smart', id: 'important' }), { icon: 'star', key: 'important' }));
			s.appendChild(navRow(t('notes.v.planned'), sm.planned, isView('smart', 'planned'), () => go({ kind: 'smart', id: 'planned' }), { icon: 'cal', key: 'planned' }));
			s.appendChild(navRow(t('notes.v.assigned'), sm.assigned, isView('smart', 'assigned'), () => go({ kind: 'smart', id: 'assigned' }), { icon: 'user', key: 'assigned' }));
			if (n && n.sources.length) {
				s.appendChild(el('div', { class: 'nz-lab', text: t('notes.fromPlugins') }));
				for (const x of n.sources) s.appendChild(navRow(x.label, x.open, isView('source', x.plugin), () => go({ kind: 'source', plugin: x.plugin }), { icon: 'open', key: `source:${x.plugin}` }));
			}
			s.appendChild(el('div', { class: 'nz-lab', text: t('notes.myLists') }));
			const groups = new Map(((n && n.groups) || []).map((g) => [g.id, g]));
			const lists = (n && n.lists) || [];
			for (const l of lists.filter((x) => !x.groupId || !groups.has(x.groupId))) s.appendChild(listRow(l));
			for (const g of groups.values()) {
				s.appendChild(el('div', { class: 'nz-it quiet nz-group', text: g.name }));
				for (const l of lists.filter((x) => x.groupId === g.id)) s.appendChild(listRow(l, true));
			}
			s.appendChild(navRow(t('notes.newList'), null, false, newList, { icon: 'plus', quiet: true, key: 'new-list' }));
			// plugin 1.4.0: the shopping lists of the area (they hold items, no tasks)
			if (shopOn()) {
				s.appendChild(el('div', { class: 'nz-lab', text: t('notes.shop.lists') }));
				for (const l of NS.shopNav(S.shop, n, S.area)) {
					s.appendChild(navRow(l.name, l.open, isView('shopping', l.id), () => go({ kind: 'shopping', id: l.id }), { icon: 'cart', key: `shopping:${l.id}`, mark: l.family ? 'home' : null, markTitle: t('notes.shop.family') }));
				}
				if (canWrite()) s.appendChild(navRow(t('notes.shop.newList'), null, false, newShopList, { icon: 'plus', quiet: true, key: 'new-shopping' }));
			}
			const notes = (n && n.notes) || { total: 0, notebooks: [], tags: [] };
			s.appendChild(el('div', { class: 'nz-lab', text: t('notes.notes') }));
			s.appendChild(navRow(t('notes.allNotes'), notes.total, S.view.kind === 'notes' && !S.view.notebook && !S.view.tag, () => go({ kind: 'notes' }), { icon: 'note', key: 'notes' }));
			for (const b of notes.notebooks) {
				s.appendChild(navRow(NS.notebookName(b, t), b.count, isView('notes', b.id), () => go({ kind: 'notes', notebook: b.id }), { sub: true, icon: b.vault ? (b.locked ? 'lock' : 'unlock') : null, key: `notebook:${b.id}` }));
			}
			s.appendChild(navRow(t('notes.newNotebook'), null, false, newNotebook, { icon: 'plus', quiet: true, key: 'new-notebook' }));
			if (notes.tags.length) {
				s.appendChild(el('div', { class: 'nz-lab', text: t('notes.tags') }));
				for (const g of notes.tags.slice(0, 12)) s.appendChild(navRow(`#${g.tag}`, g.count, S.view.kind === 'notes' && S.view.tag === g.tag, () => go({ kind: 'notes', tag: g.tag }), { sub: true, key: `tag:${g.tag}` }));
			}
			s.appendChild(el('div', { class: 'nz-lab', text: t('notes.more') }));
			s.appendChild(navRow(t('notes.sources'), null, isView('sources'), () => go({ kind: 'sources' }), { icon: 'gear', key: 'sources' }));
			if (S.me && (S.me.imports.mstodo || S.me.imports.dsnote) && (has('mstodo') || has('dsnote'))) {
				s.appendChild(navRow(t('notes.import.title'), null, isView('import'), () => go({ kind: 'import' }), { icon: 'move', key: 'import' }));
			}
		}
		const has = (f) => !S.me || S.me.features.includes(f);

		function listRow(l, sub) {
			// plugin 1.6.0: the family's list carries the house (as the family's shopping lists do)
			const fam = isFamily(l);
			return navRow(l.name + (l.shared && !fam ? ` · ${t('notes.shared')}` : ''), l.open, isView('list', l.id), () => go({ kind: 'list', id: l.id }), { sub: !!sub, icon: 'list', dot: l.color || null, key: `list:${l.id}`, mark: fam ? 'home' : null, markTitle: t('notes.shop.family') });
		}

		const isFamily = (l) => !!l && l.family === true && NS.isFamilyList(S.me, l.id);

		function setArea(a) {
			if (S.area === a) return;
			S.area = a;
			api.setPrefs({ area: a }).catch(() => {});
			if (S.view.kind === 'list' || S.view.kind === 'shopping' || (S.view.kind === 'notes' && S.view.notebook)) S.view = { kind: 'smart', id: 'myday' };
			S.detail = null;
			S.detailData = null;
			renderDetail();
			reloadNav();
			reloadView();
		}

		// ── the list in the middle ───────────────────────────
		function header(title, sub, extra) {
			return el('div', { class: 'nz-head' }, [el('div', { class: 'nz-head-tx' }, [el('h1', { class: 'nz-h', text: title }), sub ? el('span', { class: 'nz-sub', text: sub }) : null]), el('span', { class: 'grow' }), ...(extra || [])]);
		}

		function renderMain() {
			const m = clear(refs.main);
			const v = S.view;
			if (v.kind === 'notes') return renderNotes(m);
			if (v.kind === 'sources') return renderSources(m);
			if (v.kind === 'import') return renderImport(m);
			if (v.kind === 'search') return renderSearch(m);
			if (v.kind === 'shopping') return renderShopping(m);
			const d = S.data;
			let title = v.kind === 'smart' ? t(`notes.v.${v.id}`) : (d && d.view && d.view.title) || '';
			if (v.kind === 'list') { const l = ((S.nav && S.nav.lists) || []).find((x) => x.id === v.id); if (l) title = l.name; }
			const list = d && d.view && d.view.list;
			const sub = v.kind === 'smart' && v.id === 'myday' && S.me ? NS.longDate(S.me.today, t)
				: list && list.shared ? t('notes.sharedWith', { names: list.members.map((x) => x.name).join(', ') }) : null;
			const extra = [];
			if (v.kind === 'list' && list) extra.push(ib('gear', t('notes.listSettings'), () => listSettings(list)));
			if (v.kind === 'source') extra.push(ib('refresh', t('notes.syncNow'), async () => { const r = await api.syncSource(v.plugin); toast(ok(r) && r.scheduled ? t('notes.syncScheduled') : t('notes.syncRecent')); }));
			m.appendChild(header(title, sub, extra));
			// a member who only reads a list adds nothing to it (the server would refuse it)
			const ro = v.kind === 'list' && !NS.listWritable(list || ((S.nav && S.nav.lists) || []).find((x) => x.id === v.id), null);
			if (ro) m.appendChild(el('p', { class: 'hint nz-readonly', 'data-hint': 'read-only', text: t('notes.readOnlyList') }));
			else if (has('tasks')) m.appendChild(quickBox());
			if (!d) { m.appendChild(el('p', { class: 'nz-muted', text: t('notes.loading') })); return; }
			if (d.error) { m.appendChild(el('div', { class: 'note note-err', text: NS.errText(d.error, t) })); return; }
			let any = false;
			// „Gestern offen geblieben“ above „Heute“; its rows are not shown a second time under „Überfällig“
			const card = NS.yesterdayCard(d.view, S.me);
			if (card) { any = true; m.appendChild(yesterdayCard(card)); }
			for (const s of NS.sectionsWithout(d.view.sections, card)) {
				if (!s.items.length && !(v.kind === 'list' && s.id === 'open')) continue;
				any = true;
				m.appendChild(sectionCard(s, v.kind === 'smart' ? v.id : v.kind));
			}
			if (!any) m.appendChild(el('div', { class: 'card nz-card nz-empty', text: t(v.kind === 'source' ? 'notes.emptySource' : 'notes.empty') }));
		}

		function sectionCard(s, viewId) {
			const key = `${S.view.kind}:${S.view.id || S.view.plugin || ''}:${s.id}`;
			const closed = S.folded[key] !== undefined ? S.folded[key] : s.collapsed;
			const card = el('div', { class: 'card nz-card nz-sec', 'data-id': s.id });
			const title = NS.sectionTitle(s, viewId, t);
			if (s.collapsed) {
				card.appendChild(el('button', { type: 'button', class: 'nz-sec-h nz-fold', 'aria-expanded': closed ? 'false' : 'true', on: { click: () => { S.folded[key] = !closed; renderMain(); } } }, [el('span', { text: `${closed ? '▸' : '▾'} ${title} (${s.count})` })]));
			} else {
				card.appendChild(el('div', { class: `nz-sec-h${s.id === 'overdue' ? ' is-over' : ''}` }, [el('span', { text: title }), s.items.length ? el('span', { class: 'nz-n', text: String(s.items.length) }) : null]));
			}
			if (!closed) for (const x of s.items) card.appendChild(itemRow(x));
			return card;
		}

		function itemRow(x) {
			const openNow = S.detail && S.detail.uid === x.uid;
			const row = el('div', { class: `nz-row${openNow ? ' on' : ''}${x.done ? ' is-done' : ''}`, role: 'button', tabindex: '0', 'data-uid': x.uid, on: {
				click: () => openDetail(x),
				keydown: (e) => { if (e.key === 'Enter' && e.target === row) openDetail(x); },
			} });
			// plugin 1.9.0: an event of the calendar — the calendar's colour instead of a tick box, it opens Mail's event
			if (NS.isEvent(x)) return eventRow(x, openNow);
			if (x.canComplete && !(S.me && S.me.readOnly)) {
				row.appendChild(el('button', { type: 'button', class: `nz-ck${x.done ? ' on' : ''}`, 'aria-label': x.done ? t('notes.undo') : t('notes.complete'), 'aria-pressed': x.done ? 'true' : 'false',
					on: { click: (e) => { e.stopPropagation(); complete(x, !x.done); } } }, [icon('check', 13)]));
			} else row.appendChild(el('span', { class: 'nz-ck-none' }));
			const meta = NS.metaLine(x, { userId: S.me && S.me.user.id, me: S.me, lists: S.nav ? S.nav.lists : [], inList: S.view.kind === 'list' }, t);
			const marks = NS.taskMarks(x, S.me, t);
			row.appendChild(el('div', { class: 'nz-row-tx' }, [el('span', { class: 'nz-row-title', text: x.title }), meta.length || marks.length ? el('span', { class: 'nz-row-meta' }, [
				meta.length ? el('span', { class: 'nz-row-meta-tx', text: meta.join(' · ') }) : null, ...marks.map(markEl)]) : null]));
			const chip = NS.sourceChip(x, t);
			if (chip) row.appendChild(el('span', { class: 'chip chip-sm nz-src', 'data-tone': chip.tone, text: chip.text }));
			if (x.important) row.appendChild(el('span', { class: 'chip chip-sm nz-src', 'data-tone': 'warn', text: t('notes.important') }));
			const w = NS.whenText(x, S.me && S.me.today, t);
			if (w) row.appendChild(el('span', { class: `nz-when${x.overdue ? ' is-over' : ''}`, text: w }));
			if (x.type === 'task') {
				row.appendChild(el('button', { type: 'button', class: `nz-star${x.important ? ' on' : ''}`, 'aria-label': t('notes.important'), 'aria-pressed': x.important ? 'true' : 'false',
					on: { click: async (e) => { e.stopPropagation(); const r = await api.updateTask(x.id, { important: !x.important }); if (ok(r)) soon(0); else fail(r); } } }, [icon('star', 16)]));
			}
			return row;
		}

		/** An event's row (Bild 7): the calendar sign in its colour, „Ort · Kalender“, the time on the right, no tick box. */
		function eventRow(x, openNow) {
			const open = () => {
				if (x.pending) { toast(t('notes.ev.pendingHint')); return; }
				const target = NS.openTarget(x.source.open, o.pages ? o.pages() : null);
				if (target) o.openTarget(target);
			};
			const row = el('div', { class: `nz-row nz-ev${openNow ? ' on' : ''}${x.pending ? ' is-pending' : ''}`, role: 'button', tabindex: '0', 'data-uid': x.uid, 'data-kind': 'event', on: {
				click: open,
				keydown: (e) => { if (e.key === 'Enter' && e.target === row) open(); },
			} });
			const color = x.event.calendar && x.event.calendar.color;
			const sign = el('span', { class: 'nz-evcal', title: x.event.calendar ? x.event.calendar.name : null }, [icon('cal', 16)]);
			if (color) sign.style.color = color;
			row.appendChild(sign);
			const meta = NS.eventMeta(x, S.me && S.me.today, t);
			row.appendChild(el('div', { class: 'nz-row-tx' }, [el('span', { class: 'nz-row-title', text: x.title }), meta.length ? el('span', { class: 'nz-row-meta' }, [el('span', { class: 'nz-row-meta-tx', text: meta.join(' · ') })]) : null]));
			const w = NS.eventWhen(x);
			if (w) row.appendChild(el('span', { class: 'nz-when', text: w }));
			if (x.pending) {
				row.appendChild(el('button', { type: 'button', class: 'nz-ib', 'data-act': 'unqueue', title: t('notes.ev.unqueue'), 'aria-label': t('notes.ev.unqueue'), on: { click: async (e) => {
					e.stopPropagation();
					const r = await api.unqueueEvent(x.clientId);
					if (!ok(r)) { fail(r); return; }
					soon(0);
				} } }, [icon('x', 15)]));
			}
			return row;
		}

		/**
		 * A small mark of a task (plugin 1.3.0): the bell „Erinnerung“ / „Später: …“, the calendar „im Kalender“; plugin
		 * 1.4.0: the shopping list it carries („Einkauf 0/8“) — a button that opens the list; plugin 1.5.0: the place it
		 * hangs on („Baumarkt Nord“ — the phone reminds there).
		 */
		function markEl(k) {
			if (k.kind === 'list') {
				return el('button', { type: 'button', class: 'nz-mark nz-mark-list', 'data-kind': 'list', title: k.title || null, 'aria-label': `${k.title}: ${k.text}`,
					on: { click: (e) => { e.stopPropagation(); if (!openShopList(k.uid)) toast(t('notes.shop.gone')); }, keydown: (e) => e.stopPropagation() } }, [icon('cart', 12), el('span', { text: k.text })]);
			}
			// plugin 1.6.0: whose turn („Reihum · Lena ist dran“, „Wer zuerst“), the stars, „Erledigt von …“
			const ic = { calendar: 'cal', place: 'place', turn: k.first ? 'people' : 'turn', stars: 'star', doneby: 'check' }[k.kind] || 'bell';
			return el('span', { class: 'nz-mark', 'data-kind': k.kind, title: k.title || null }, [icon(ic, 12), el('span', { text: k.text })]);
		}

		// ── „Gestern offen geblieben“ (plugin 1.3.0) ─────────
		const canWrite = () => !(S.me && S.me.readOnly);

		function yesterdayCard(card) {
			const box = el('div', { class: 'card nz-card nz-sec nz-yd', 'data-id': 'yesterday' });
			const title = t('notes.y.title');
			box.appendChild(el('div', { class: 'nz-sec-h nz-yd-h' }, [icon('flag', 15), el('span', { text: title }), el('span', { class: 'nz-n', text: String(card.items.length) }), el('span', { class: 'grow' }),
				canWrite() && card.items.some((x) => x.canEdit) ? btn(t('notes.y.allToday'), () => decideAll({ action: 'today', area: S.area }), 'btn-ghost nz-yd-all') : null]));
			for (const x of card.items) {
				const openNow = S.detail && S.detail.uid === x.uid;
				const row = el('div', { class: `nz-row nz-yd-row${openNow ? ' on' : ''}`, role: 'button', tabindex: '0', 'data-uid': x.uid, on: {
					click: () => openDetail(x),
					keydown: (e) => { if (e.key === 'Enter' && e.target === row) openDetail(x); },
				} });
				const l = ((S.nav && S.nav.lists) || []).find((y) => y.id === x.listId);
				const meta = [NS.whenText(x, S.me && S.me.today, t), l ? `${t(`notes.area.${l.area}`)} › ${l.name}` : ''].filter(Boolean);
				row.appendChild(el('div', { class: 'nz-row-tx' }, [el('span', { class: 'nz-row-title', text: x.title }), meta.length ? el('span', { class: 'nz-row-meta', text: meta.join(' · ') }) : null]));
				if (canWrite() && (x.canComplete || x.canEdit)) {
					const act = (key, fn) => el('button', { type: 'button', class: 'btn btn-sm nz-yd-btn', 'data-act': key, 'aria-label': `${t(`notes.y.${key}`)}: ${x.title}`, text: t(`notes.y.${key}`), on: { click: (e) => { e.stopPropagation(); fn(); } } });
					row.appendChild(el('div', { class: 'nz-yd-acts' }, [
						x.canComplete ? act('done', () => complete(x, true)) : null,
						x.canEdit ? act('today', () => moveRow(x, 'today')) : null,
						x.canEdit ? act('move', () => askMove(card.moveOptions, (to) => moveRow(x, to))) : null,
					]));
				}
				box.appendChild(row);
			}
			return box;
		}

		async function moveRow(x, to) {
			const r = await api.moveTask(x.id, to);
			if (!ok(r)) { fail(r); if (r && r.code === 'not_found') soon(0); return; }
			soon(0);
		}

		/** Every task of the card — or the tasks a message named — at once („Alle heute“, „Alle N abhaken?“, „Verschieben auf“). */
		async function decideAll(body) {
			const r = await api.decideYesterday(body);
			if (!ok(r)) { fail(r); return; }
			if (r.failed && r.failed.length) toast(t('notes.y.someFailed', { n: r.failed.length }), 'error');
			soon(0);
		}

		/** „Verschieben auf“: Morgen · Am Wochenende · Anderes Datum → pick(to). */
		function askMove(options, pick) {
			let d = null;
			const choose = (to) => { d.close(); pick(to); };
			const date = el('input', { class: 'inp nz-inp-sm', type: 'date', min: (S.me && S.me.today) || null, 'aria-label': t('notes.y.otherDate') });
			const set = btn(t('notes.y.move'), () => { if (date.value) choose(date.value); }, 'btn-sec', null, { disabled: true, 'data-act': 'date' });
			date.addEventListener('input', () => { set.disabled = !date.value || !!(S.me && S.me.today && date.value < S.me.today); });
			d = dialog(t('notes.y.askMove'), [
				el('div', { class: 'nz-yd-choices' }, NS.moveChoices(options, t).map((o) => btn(o.label, () => choose(o.to), 'btn-sec', null, { 'data-to': o.to }))),
				field(t('notes.y.otherDate'), el('span', { class: 'nz-pair' }, [date, set])),
			], [btn(t('notes.cancel'), () => d.close(), 'btn-ghost')]);
		}

		/**
		 * A button of the morning hint opened the page: „Erledigt“ of several tasks asks once („Alle N abhaken?“),
		 * „Verschieben“ offers the days. Asked about what is still open of the tasks the message named (both areas).
		 */
		async function askYesterday(c) {
			if (!NS.offers(S.me, 'yesterdayOpen')) return;
			const here = () => NS.yesterdayCard(S.data && S.data.view, S.me);
			// the card of the other area when this one has none
			if (!here()) {
				const other = S.area === 'work' ? 'private' : 'work';
				const there = await Promise.resolve(api.view('myday', other)).catch(() => null);
				if (ok(there) && NS.yesterdayCard(there.view, S.me)) { S.area = other; renderSide(); await Promise.all([reloadNav(), reloadView()]); }
			}
			if (c.action !== 'done_ask' && c.action !== 'move') return;
			if (!canWrite()) return;
			const r = await Promise.resolve(api.yesterday()).catch(() => null);
			const open = ok(r) && r.yesterday ? r.yesterday.items.map((x) => x.id) : null;
			const ids = NS.askedIds(c.taskIds, open);
			if (!ids.length) { toast(t('notes.y.none')); return; }
			if (c.action === 'move') { askMove(ok(r) && r.yesterday ? r.yesterday.moveOptions : [], (to) => decideAll({ action: 'move', to, ids })); return; }
			let d = null;
			d = dialog(t('notes.y.askDone', { n: ids.length }), [el('p', { class: 'nz-p', text: t('notes.y.askDoneText') })],
				[btn(t('notes.cancel'), () => d.close(), 'btn-ghost'), btn(t('notes.y.askDoneConfirm'), () => { d.close(); decideAll({ action: 'done', ids }); }, 'btn-pri', null, { 'data-act': 'confirm' })]);
		}

		// ── a shopping list (plugin 1.4.0) ───────────────────
		function renderShopping(m) {
			const l = NS.shopList(S.shop, S.view.id);
			if (!l) { m.appendChild(header(t('notes.shop.lists'), null)); m.appendChild(el('p', { class: 'nz-muted', text: t('notes.loading') })); return; }
			const meId = S.me && S.me.user.id;
			const edit = l.canEdit && canWrite();
			m.appendChild(header(l.name, NS.shopWith(l, meId, t), [l.pending ? null : ib('gear', t('notes.shop.settings'), () => shopSettings(l))]));
			m.firstChild.querySelector('.nz-h').prepend(icon('cart', 22));
			const b = NS.shopBelongs(l, t);
			if (b) m.appendChild(el('button', { type: 'button', class: 'nz-shop-task', 'data-task': String(b.taskId), on: { click: () => openDetail({ uid: `t:${b.taskId}`, type: 'task', id: b.taskId }) } }, [icon('check', 14), el('span', { text: b.text })]));
			if (S.shop.stale || S.shop.pending) m.appendChild(el('div', { class: 'note nz-shop-wait', role: 'status', text: t('notes.shop.waiting', { n: S.shop.pending }) }));
			if (!edit) m.appendChild(el('p', { class: 'hint', text: t('notes.shop.readOnly') }));
			if (edit) {
				const text = el('input', { id: 'nz-shop-add', class: 'nz-quick-inp', type: 'text', autocomplete: 'off', maxlength: '120', placeholder: t('notes.shop.addPh'), 'aria-label': t('notes.shop.addPh') });
				const qty = el('input', { id: 'nz-shop-qty', class: 'nz-quick-inp nz-shop-qty', type: 'text', autocomplete: 'off', maxlength: '40', placeholder: t('notes.shop.qty'), 'aria-label': t('notes.shop.qty') });
				const draft = S.shopDraft && S.shopDraft.id === l.id ? S.shopDraft : { id: l.id, text: '', qty: '' };
				S.shopDraft = draft;
				text.value = draft.text;
				qty.value = draft.qty;
				text.addEventListener('input', () => { draft.text = text.value; });
				qty.addEventListener('input', () => { draft.qty = qty.value; });
				const add = async () => {
					const v = text.value.trim();
					if (!v) { text.focus(); return; }
					const op = { op: 'item_add', listId: l.id, text: v };
					if (qty.value.trim()) op.qty = qty.value.trim();
					draft.text = '';
					draft.qty = '';
					await shopOps([op]);
					const again = refs.main.querySelector('#nz-shop-add');
					if (again) again.focus();
				};
				for (const n of [text, qty]) n.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); add(); } });
				m.appendChild(el('div', { class: 'nz-quick' }, [el('div', { class: 'nz-quick-box nz-shop-addbox' }, [icon('plus', 18), text, qty, ib('plus', t('notes.shop.add'), add, false, { 'data-act': 'shop-add' })])]));
			}
			const items = NS.shopItems(S.shop, l.id);
			if (!items.length) { m.appendChild(el('div', { class: 'card nz-card nz-empty', text: t(edit ? 'notes.shop.empty' : 'notes.shop.emptyRead') })); return; }
			const card = el('div', { class: 'card nz-card nz-sec nz-shop', 'data-id': 'shopping' });
			card.appendChild(el('div', { class: 'nz-sec-h' }, [el('span', { text: t('notes.shop.progress', { done: l.total - l.open, total: l.total }) }), el('span', { class: 'grow' }),
				edit && l.total > l.open ? btn(t('notes.shop.clear'), () => shopOps([{ op: 'clear_checked', listId: l.id }]), 'btn-ghost nz-shop-clear', null, { 'data-act': 'shop-clear' }) : null]));
			for (const i of items) {
				const row = el('div', { class: `nz-row nz-shop-row${i.checked ? ' is-done' : ''}`, 'data-item': i.id });
				const tick = () => shopOps([{ op: 'item_check', id: i.id, checked: !i.checked }]);
				if (edit) {
					row.appendChild(el('button', { type: 'button', class: `nz-ck${i.checked ? ' on' : ''}`, 'aria-label': `${i.checked ? t('notes.shop.untick') : t('notes.shop.tick')}: ${i.text}`, 'aria-pressed': i.checked ? 'true' : 'false', on: { click: tick } }, [icon('check', 13)]));
				} else row.appendChild(el('span', { class: `nz-ck nz-ck-ro${i.checked ? ' on' : ''}`, 'aria-hidden': 'true' }, [icon('check', 13)]));
				row.appendChild(el('div', { class: 'nz-row-tx', on: edit ? { click: tick } : {} }, [el('span', { class: 'nz-row-title', text: i.text })]));
				if (i.qty) row.appendChild(el('span', { class: 'nz-shop-q', text: i.qty }));
				if (edit) {
					row.appendChild(ib('edit', `${t('notes.shop.edit')}: ${i.text}`, () => editShopItem(i), false, { 'data-act': 'shop-edit' }));
					row.appendChild(ib('trash', `${t('notes.delete')}: ${i.text}`, () => shopOps([{ op: 'item_delete', id: i.id }]), false, { 'data-act': 'shop-delete' }));
				}
				card.appendChild(row);
			}
			m.appendChild(card);
		}

		function editShopItem(i) {
			const text = el('input', { class: 'inp', type: 'text', value: i.text, maxlength: '120', 'aria-label': t('notes.shop.item') });
			const qty = el('input', { class: 'inp', type: 'text', value: i.qty || '', maxlength: '40', 'aria-label': t('notes.shop.qty') });
			let d = null;
			const save = async () => {
				const v = text.value.trim();
				if (!v) return;
				const op = { op: 'item_edit', id: i.id };
				if (v !== i.text) op.text = v;
				if (qty.value.trim() !== (i.qty || '')) op.qty = qty.value.trim() || null;
				d.close();
				if (op.text !== undefined || op.qty !== undefined) await shopOps([op]);
			};
			for (const n of [text, qty]) n.addEventListener('keydown', (e) => { if (e.key === 'Enter') save(); });
			d = dialog(t('notes.shop.edit'), [field(t('notes.shop.item'), text), field(t('notes.shop.qty'), qty)], [btn(t('notes.cancel'), () => d.close(), 'btn-ghost'), btn(t('notes.save'), save, 'btn-pri', null, { 'data-act': 'save' })]);
		}

		/** „Neue Einkaufsliste“ → the list's text id (made by the main process) or null. */
		function newShopList(then) {
			const d = prompt(t('notes.shop.newList'), '', async (name) => {
				const r = await Promise.resolve(api.shoppingOps([{ op: 'list_add', name, icon: 'cart', area: S.area }])).catch(() => null);
				if (!takeShop(r)) return r || { ok: false, code: 'failed' };
				if (r.rejected && r.rejected.length) return { ok: false, code: r.rejected[0].code };
				renderSide();
				const uid = r.ids && r.ids[0];
				if (typeof then === 'function') then(uid);
				else if (uid) go({ kind: 'shopping', id: uid });
				return r;
			});
			const input = d.box.querySelector('input');
			if (input) input.maxLength = 40;
		}

		/** A shopping list's name, who it is shared with, deleting (who may manage it) or leaving it. */
		function shopSettings(l) {
			const fam = S.me && S.me.shopping && S.me.shopping.family;
			const famOk = NS.offers(S.me, 'familyShopping') && !!fam && fam.available && fam.bound && fam.parent && l.canManage;
			const share = l.role === 'owner' && !l.family && l.listId ? sharePicker(l.members) : null;
			let family = l.family;
			const extra = [];
			if (famOk) extra.push(field(t('notes.shop.shareFamily'), sw(l.family, (v) => { family = v; }, t('notes.shop.shareFamily')), t('notes.shop.shareFamilyHint')));
			if (share) extra.push(field(t('notes.shareWith'), share.box));
			if (!l.canManage) extra.push(el('p', { class: 'hint', text: t('notes.shop.notYours') }));
			const d = prompt(t('notes.shop.settings'), l.name, async (name) => {
				let r = { ok: true };
				if (l.canManage && name !== l.name) {
					r = await Promise.resolve(api.shoppingOps([{ op: 'list_rename', id: l.id, name }])).catch(() => null);
					if (!takeShop(r)) return r || { ok: false, code: 'failed' };
					if (r.rejected && r.rejected.length) return { ok: false, code: r.rejected[0].code };
				}
				if (famOk && family !== l.family) r = await api.shoppingFamily(l.id, family);
				if (ok(r) && share && !family) r = await api.listMembers(l.listId, share.value());
				if (ok(r)) { reloadNav(); reloadShop(); }
				return r;
			}, [...extra, el('div', { class: 'nz-row-acts' }, [btn(l.canManage ? t('notes.shop.deleteList') : t('notes.leaveList'), async () => {
				if (l.canManage) { const r = await shopOps([{ op: 'list_delete', id: l.id }]); if (!r) return; }
				else { const r = await api.deleteList(l.listId); if (!ok(r)) { fail(r); return; } await reloadShop(); }
				d.close();
				if (S.view.kind === 'shopping') go({ kind: 'smart', id: 'myday' });
				reloadNav();
				if (!l.canManage) return;
				toast(t('notes.shop.deleted', { name: l.name }), 'success', l.role === 'owner' && l.listId ? { label: t('notes.shop.undo'), run: async () => {
					const r = await api.shoppingRestore(l.listId);
					if (!ok(r)) { fail(r); return; }
					await reloadShop();
					reloadNav();
					openShopList(l.id);
				} } : null);
			}, 'btn-danger', 'trash', { 'data-act': 'shop-remove' })])]);
			const input = d.box.querySelector('input');
			if (input) { input.maxLength = 40; input.disabled = !l.canManage; }
		}

		async function complete(x, done) {
			x.done = done;
			renderMain();
			const r = x.type === 'task' ? await api.completeTask(x.id, done) : await api.completeItem(x.id, done);
			if (!ok(r)) { x.done = !done; renderMain(); fail(r); return; }
			// plugin 1.6.0: „reihum“ — who is on next time
			const nextUp = r.next && r.next.turn === 'rotate' ? NS.turnText(r.next, S.me, t) : '';
			if (r.next && r.next.due) toast(t('notes.nextRepeat', { when: NS.dayText(r.next.due.date, S.me.today, t) }) + (nextUp ? ` · ${nextUp}` : ''), 'success');
			else if (x.type === 'source' && done) toast(t('notes.doneThere', { source: x.source.label }), 'success');
			soon(150);
		}

		// ── the quick entry (Strg+N) ─────────────────────────
		function quickBox() {
			// plugin 1.9.0: „Aufgabe | Termin | Notiz“ — the switch is always clear; the app never switches by itself
			const evOn = eventsOn();
			if (!evOn) S.quickMode = 'task';
			const mode = () => S.quickMode;
			const input = el('input', { id: 'nz-quick', class: 'nz-quick-inp', type: 'text', autocomplete: 'off', maxlength: '500', placeholder: t(mode() === 'event' ? 'notes.ev.ph' : mode() === 'note' ? 'notes.ev.notePh' : 'notes.quick.ph'), 'aria-label': t('notes.quick.label') });
			input.value = S.quickText;
			const chips = el('div', { class: 'nz-chips', 'aria-live': 'polite' });
			// the question „Als Termin anlegen?“ and the card „Kein Kalender“
			const ask = el('div', { class: 'nz-evask', hidden: true });
			let draft = null;
			const evCh = () => {
				const text = input.value.trim();
				if (!S.quickEv || S.quickEv.text !== text) {
					// what came from the line goes with it; the calendar and the reminder the person chose stay
					const keep = S.quickEv ? { calendarId: S.quickEv.calendarId, reminder: S.quickEv.reminder } : {};
					S.quickEv = { text, ...keep };
				}
				return S.quickEv;
			};
			const setEv = (patch) => { Object.assign(evCh(), patch); show(); input.focus(); };
			// plugin 1.6.0: „Wer ist dran?“ — shown from two people on, read on this PC (the plugin's ui/turnwords.js)
			const turnBox = el('div', { class: 'nz-qturn', hidden: true });
			let parsed = null;
			let words = null;
			const turnKey = () => (words ? words.people.map((x) => x.id).join(',') : '');
			const turnNow = () => NS.quickTurn(words, S.quickTurn && S.quickTurn.key === turnKey() ? S.quickTurn.value : undefined);
			// plugin 1.4.0: the shopping list the line names — the server's suggestion (POST parse), asked a moment after typing
			const lists = NS.offers(S.me, 'taskList') && shopOn();
			// plugin 1.5.0: the place the line names („beim Baumarkt“) — likewise the server's suggestion, never the parser's
			const placesOn = NS.offers(S.me, 'places');
			const sug = { text: null, attach: null, choice: undefined, place: null, pchoice: undefined, timer: null, seq: 0 };
			const attachNow = () => (sug.text === input.value.trim() ? NS.quickAttach(sug.attach, sug.choice) : null);
			const placeNow = () => (placesOn && sug.text === input.value.trim() ? NS.quickPlace(sug.place, sug.pchoice, t) : null);
			const show = () => {
				S.quickText = input.value;
				clear(chips);
				clear(ask).hidden = true;
				if (!input.value.trim()) S.quickKeepTask = false;
				if (mode() === 'event') { clear(turnBox).hidden = true; showEvent(); return; }
				if (mode() === 'note') { clear(turnBox).hidden = true; parsed = null; return; }
				const ctx = NS.quickCtx(S.me, S.nav, S.people);
				parsed = NS.quickParse(input.value, ctx);
				// plugin 1.9.0: a date and a time — „Das sieht wie ein Termin aus“ (asked, never switched)
				if (NS.eventAsk(parsed, S.me, mode(), S.quickKeepTask)) {
					ask.hidden = false;
					ask.setAttribute('data-card', 'ask');
					ask.append(icon('cal', 16), el('span', { class: 'nz-evask-tx', text: t('notes.ev.askText') }),
						btn(t('notes.ev.askYes'), () => setMode('event'), 'btn-pri', null, { 'data-act': 'as-event' }),
						btn(t('notes.ev.askNo'), () => { S.quickKeepTask = true; show(); input.focus(); }, 'btn-ghost', null, { 'data-act': 'keep-task' }));
				}
				words = NS.quickWords(parsed, ctx, S.me, S.view);
				const qt = turnNow();
				clear(turnBox).hidden = !qt;
				if (qt) turnBox.append(el('span', { class: 'nz-qturn-l', id: 'nz-qturn-l', text: t('notes.turn.label') }), turnSeg(qt.value, (v) => { S.quickTurn = { key: turnKey(), value: v }; show(); input.focus(); }, false, 'nz-qturn-l'), el('span', { class: 'hint', text: t('notes.turn.hint') }));
				if (!parsed) return;
				const qa = attachNow();
				chips.appendChild(el('span', { class: 'nz-chips-l', text: t('notes.quick.found') }));
				for (const c of NS.quickChips(parsed, ctx, S.area, t, lang(), S.me, qa, words, qt)) chips.appendChild(el('span', { class: `chip nz-qchip${c.plain ? ' plain' : ''}`, 'data-kind': c.kind, title: c.title || null, text: c.text }));
				if (qa) chips.appendChild(attachChip(qa));
				const qp = placeNow();
				if (qp) chips.appendChild(placeChip(qp));
			};
			/**
			 * „Ort: Baumarkt …“ / „Ort: Baumarkt Nord · beim Ankommen“ — a click opens the choice (the search goes out then,
			 * not while typing); × saves without a place.
			 */
			const placeChip = (qp) => {
				// kept with the line: the list may be drawn anew (a live event) while the choice is open
				const set = (v) => {
					S.quickPlace = v === undefined ? null : { text: sug.text, choice: v };
					if (!input.isConnected) { renderMain(); const again = refs.main.querySelector('#nz-quick'); if (again) again.focus(); return; }
					sug.pchoice = v;
					show();
					input.focus();
				};
				const chip = el('span', { class: `chip nz-qchip nz-qchip-place${qp.plain ? ' plain' : ''}`, 'data-kind': 'place', 'data-state': qp.state });
				chip.appendChild(el('button', { type: 'button', class: 'nz-qbtn', title: qp.title, on: { click: () => {
					if (qp.state === 'off') { set(undefined); return; }
					const p0 = sug.place;
					placeDialog({ hint: qp.hint, decided: p0 && p0.place, options: p0 ? p0.options : [], searchNow: qp.state === 'ask', none: false, onSave: (arg, text) => set(arg ? { arg, text } : null) });
				} } }, [icon('place', 13), el('span', { text: qp.text })]));
				if (qp.state !== 'off') chip.appendChild(el('button', { type: 'button', class: 'nz-qx', 'aria-label': t('notes.place.chipRemove'), title: t('notes.place.chipRemove'), on: { click: () => set(null) } }, [icon('x', 12)]));
				return chip;
			};
			/** „Liste: Einkauf · 8 offen“ — taken away with ×, or another list chosen when several fit. */
			const attachChip = (qa) => {
				const set = (v) => { sug.choice = v; show(); input.focus(); };
				const chip = el('span', { class: `chip nz-qchip nz-qchip-shop${qa.list ? '' : ' plain'}`, 'data-kind': 'shopping', title: t('notes.shop.chipHint') }, [icon('cart', 13)]);
				if (qa.lists.length > 1) {
					const sel = el('select', { class: 'nz-qsel', 'aria-label': t('notes.shop.attached') }, [el('option', { value: '', text: t('notes.shop.chooseList') }), ...qa.lists.map((l) => el('option', { value: String(l.id), text: t('notes.shop.chip', { name: l.name, n: l.open }) }))]);
					sel.value = qa.list ? String(qa.list.id) : '';
					sel.addEventListener('change', () => set(sel.value ? Number(sel.value) : null));
					chip.appendChild(sel);
				} else chip.appendChild(el('span', { text: qa.list ? t('notes.shop.chip', { name: qa.list.name, n: qa.list.open }) : t('notes.shop.chipOff', { name: qa.lists[0].name }) }));
				if (qa.list) chip.appendChild(el('button', { type: 'button', class: 'nz-qx', 'aria-label': t('notes.shop.chipRemove'), title: t('notes.shop.chipRemove'), on: { click: () => set(null) } }, [icon('x', 12)]));
				else if (qa.lists.length === 1) chip.appendChild(el('button', { type: 'button', class: 'nz-qx', 'aria-label': t('notes.shop.chipAdd'), title: t('notes.shop.chipAdd'), on: { click: () => set(qa.lists[0].id) } }, [icon('plus', 12)]));
				return chip;
			};
			const suggest = () => {
				if ((!lists && !placesOn) || mode() !== 'task') return;
				clearTimeout(sug.timer);
				const text = input.value.trim();
				if (text === sug.text) return;
				sug.text = null;
				sug.attach = null;
				sug.choice = undefined;
				sug.place = null;
				sug.pchoice = S.quickPlace && S.quickPlace.text === text ? S.quickPlace.choice : undefined;
				const seq = ++sug.seq;
				if (!text) return;
				sug.timer = setTimeout(async () => {
					const r = await Promise.resolve(api.parse(text, S.area)).catch(() => null);
					if (seq !== sug.seq || !input.isConnected) return;
					sug.text = text;
					sug.attach = ok(r) && lists ? r.attach || null : null;
					sug.place = ok(r) && placesOn ? r.place || null : null;
					if (input.value.trim() === text) show();
				}, 250);
			};
			/** Event mode: the line read as an event, its chips (each one changes what it shows), or „Kein Kalender“. */
			const showEvent = () => {
				const text = input.value.trim();
				const ctx = NS.quickCtx(S.me, S.nav, S.people);
				const p = text && ctx.today ? NS.quickParse(text, { ...ctx, mode: 'event' }) : null;
				draft = p ? NS.eventDraft(p, evCh(), S.cals, S.me.today) : null;
				const why = NS.eventBlocked(S.me, S.cals);
				if (why) { noCalendar(why); return; }
				if (!draft) return;
				chips.appendChild(el('span', { class: 'nz-chips-l', text: t('notes.ev.found') }));
				for (const c of NS.eventChips(draft, S.cals, t, S.me.today, lang())) chips.appendChild(eventChip(c));
				if (o.pages && o.pages().includes('mail')) {
					chips.appendChild(el('button', { type: 'button', class: 'chip nz-qchip nz-qmore', 'data-kind': 'more', on: { click: moreDetails } }, [el('span', { text: t('notes.ev.more') })]));
				}
				if (!draft.location && draft.placeSuggest) chips.appendChild(el('span', { class: 'hint nz-evhint', text: t('notes.ev.placeHint', { title: draft.title }) }));
			};
			/** Bild 9: the switch stays, the reason, and the line saved as a task with its day instead. */
			const noCalendar = (why) => {
				ask.hidden = false;
				ask.setAttribute('data-card', 'no-calendar');
				ask.setAttribute('data-why', NS.eventWhy(why));
				ask.append(el('div', { class: 'nz-evask-body' }, [el('b', { text: t('notes.ev.noCalTitle') }), el('span', { class: 'nz-evask-tx', text: t(`notes.ev.noCal.${NS.eventWhy(why)}`) })]),
					input.value.trim() ? btn(t('notes.ev.asTask'), () => saveTask(), 'btn-sec', 'check', { 'data-act': 'as-task' }) : null);
			};
			const eventChip = (c) => {
				const attrs = { class: `chip nz-qchip nz-qchip-ev${c.plain ? ' plain' : ''}${c.suggest ? ' is-suggest' : ''}`, 'data-kind': c.kind };
				if (c.kind === 'calendar' || c.kind === 'reminder') {
					const opts = c.kind === 'calendar'
						? S.cals.calendars.filter((x) => x.target).map((x) => ({ value: String(x.id), label: t('notes.ev.calendar', { name: x.name }) }))
						: NS.reminderChoices(draft.allDay, draft.reminder, t).map((x) => ({ value: String(x.value), label: x.label }));
					const sel = el('select', { class: 'nz-qsel', 'aria-label': t(c.kind === 'calendar' ? 'notes.ev.calendarLabel' : 'notes.ev.reminderLabel'), 'data-act': c.kind }, opts.map((x) => el('option', { value: x.value, text: x.label })));
					sel.value = c.kind === 'calendar' ? String(draft.calendarId) : String(draft.reminder === null ? false : draft.reminder);
					sel.addEventListener('change', () => setEv(c.kind === 'calendar' ? { calendarId: Number(sel.value) } : { reminder: sel.value === 'false' ? false : Number(sel.value) }));
					const chip = el('span', attrs, [icon(c.kind === 'calendar' ? 'cal' : 'bell', 13), sel]);
					if (c.color) chip.style.setProperty('--ev-color', c.color);
					return chip;
				}
				const ic = { date: 'cal', time: 'clock', place: 'place', repeat: 'refresh' }[c.kind] || 'cal';
				const click = () => {
					if (c.kind === 'date') dateDialog();
					else if (c.kind === 'time') timeDialog();
					else if (c.kind === 'place') { if (c.suggest) setEv({ location: draft.placeSuggest }); else placeTextDialog(); }
				};
				if (c.kind === 'repeat') return el('span', attrs, [el('span', { text: c.text })]);
				return el('span', attrs, [el('button', { type: 'button', class: 'nz-qbtn', 'data-act': c.kind, on: { click } }, [icon(ic, 13), el('span', { text: c.text })])]);
			};
			const dateDialog = () => {
				const inp = el('input', { class: 'inp', type: 'date', value: draft.date || '', 'aria-label': t('notes.ev.day') });
				let d = null;
				const save = () => { if (!inp.value) return; d.close(); setEv({ date: inp.value }); };
				inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') save(); });
				d = dialog(t('notes.ev.day'), [field(t('notes.ev.day'), inp)], [btn(t('notes.cancel'), () => d.close(), 'btn-ghost'), btn(t('notes.ev.apply'), save, 'btn-pri', null, { 'data-act': 'apply' })]);
				d.box.setAttribute('data-dlg', 'ev-date');
			};
			const timeDialog = () => {
				let allDay = draft.allDay;
				const from = el('input', { class: 'inp nz-inp-sm', type: 'time', value: draft.time || '09:00', 'aria-label': t('notes.ev.from') });
				const to = el('input', { class: 'inp nz-inp-sm', type: 'time', value: draft.endTime || '10:00', 'aria-label': t('notes.ev.to') });
				const times = el('div', { class: 'nz-evtimes' }, [field(t('notes.ev.from'), from), field(t('notes.ev.to'), to)]);
				times.hidden = allDay;
				let d = null;
				const save = () => { d.close(); setEv(allDay ? { allDay: true } : { allDay: false, time: from.value || '09:00', endTime: to.value || null }); };
				d = dialog(t('notes.ev.time'), [field(t('notes.ev.allDay'), sw(allDay, (v) => { allDay = v; times.hidden = v; }, t('notes.ev.allDay'))), times], [btn(t('notes.cancel'), () => d.close(), 'btn-ghost'), btn(t('notes.ev.apply'), save, 'btn-pri', null, { 'data-act': 'apply' })]);
				d.box.setAttribute('data-dlg', 'ev-time');
			};
			/** Bild 4: only a text — it stands in the calendar's entry; no reminder on arriving, no position. */
			const placeTextDialog = () => {
				const inp = el('input', { class: 'inp', type: 'text', maxlength: '255', value: draft.location || draft.placeSuggest || '', placeholder: t('notes.ev.placePh'), 'aria-label': t('notes.ev.placePh') });
				let d = null;
				const save = () => { d.close(); setEv({ location: inp.value.trim() || null }); };
				inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') save(); });
				d = dialog(t('notes.ev.placeTitle'), [field(t('notes.ev.placePh'), inp, t('notes.ev.placeOnlyText'))],
					[draft.location ? btn(t('notes.ev.placeRemove'), () => { d.close(); setEv({ location: null }); }, 'btn-ghost', null, { 'data-act': 'place-remove' }) : null, btn(t('notes.ev.apply'), save, 'btn-pri', null, { 'data-act': 'apply' })].filter(Boolean));
				d.box.setAttribute('data-dlg', 'ev-place');
			};
			/** „Mehr Angaben …“: Mail's own form of a new event, filled in with what the chips show — saved there. */
			const moreDetails = () => {
				if (!draft || !draft.title) return;
				o.openTarget({ page: 'mail', context: { kind: 'newEvent', prefill: NS.eventPrefill(draft) } });
			};
			const setMode = (m) => {
				S.quickMode = m;
				// no calendar last time: asked again at once (it may be there now)
				if (m === 'event') loadCals(!!S.cals && S.cals.state !== 'ok').then(() => { const q = refs.main.querySelector('#nz-quick'); if (q && mode() === 'event') q.dispatchEvent(new Event('input')); });
				renderMain();
				const again = refs.main.querySelector('#nz-quick');
				if (again) again.focus();
			};
			const clearLine = () => {
				input.value = '';
				S.quickText = '';
				S.quickPlace = null;
				S.quickTurn = null;
				S.quickEv = null;
				S.quickKeepTask = false;
				suggest();
				show();
				input.focus();
			};
			/** „Als Aufgabe mit Datum speichern“ (no calendar): the line unchanged as a task — its day, time and reminder from it. */
			const saveTask = async () => {
				const ctx = NS.quickCtx(S.me, S.nav, S.people);
				const p = NS.quickParse(input.value, ctx);
				const body = NS.quickBody(input.value, p, S.view, S.area, null, null, null, null);
				input.disabled = true;
				const r = await api.createTask(body);
				input.disabled = false;
				if (!ok(r)) { fail(r); input.focus(); return; }
				clearLine();
				toast(t('notes.quick.added', { title: r.task.title }), 'success');
				soon(0);
			};
			const saveEvent = async () => {
				if (!draft || !draft.title || !draft.date) return;
				if (NS.eventBlocked(S.me, S.cals)) return;
				input.disabled = true;
				const r = await api.createEvent(NS.eventBody(draft));
				input.disabled = false;
				if (!ok(r)) {
					// refused for good (Mail gone, the calendar off): the card with „Als Aufgabe mit Datum speichern“
					if (r && r.code === 'unavailable' && r.reason) { S.cals = { ...(S.cals || {}), state: 'none', reason: r.reason, calendars: (S.cals && S.cals.calendars) || [], targets: [] }; show(); }
					else fail(r);
					input.focus();
					return;
				}
				const title = draft.title;
				clearLine();
				const undo = { label: t('notes.ev.undo'), run: async () => {
					const u = r.queued ? await api.unqueueEvent(r.clientId) : await api.deleteEvent(r.event.id);
					if (!ok(u)) fail(u);
					soon(0);
				} };
				toast(r.queued ? t('notes.ev.queued', { title }) : t('notes.ev.added', { title }), 'success', undo);
				soon(0);
			};
			const saveNote = async () => {
				const text = input.value.trim();
				input.disabled = true;
				const r = await api.createNote({ title: text.slice(0, 300), body: '', area: S.area });
				input.disabled = false;
				if (!ok(r)) { fail(r); input.focus(); return; }
				clearLine();
				toast(t('notes.ev.noteAdded', { title: text }), 'success', { label: t('notes.ev.noteOpen'), run: () => { go({ kind: 'notes' }).then(() => openNote(r.note.id)); } });
				reloadNav();
			};
			input.addEventListener('input', () => { suggest(); show(); });
			input.addEventListener('keydown', async (e) => {
				if (e.key === 'Escape') { input.value = ''; S.quickEv = null; S.quickKeepTask = false; suggest(); show(); return; }
				if (e.key !== 'Enter' || !input.value.trim() || input.disabled) return;
				if (mode() === 'event') { await saveEvent(); return; }
				if (mode() === 'note') { await saveNote(); return; }
				// the suggestion for this very line has not come yet: the server decides (it attaches when exactly one list fits)
				// … and likewise the place: it sets the one that is decided and surely meant, never another
				const here = sug.text === input.value.trim();
				const body = NS.quickBody(input.value, parsed, S.view, S.area, !lists ? null : here ? attachNow() : 'auto', !placesOn ? null : here ? placeNow() : 'auto', words, turnNow());
				input.disabled = true;
				const r = await api.createTask(body);
				input.disabled = false;
				if (!ok(r)) { fail(r); input.focus(); return; }
				clearLine();
				toast(r.task.attachedList ? t('notes.shop.addedWith', { title: r.task.title, name: r.task.attachedList.name })
					: r.task.place ? t('notes.place.added', { title: r.task.title, name: r.task.place.name }) : t('notes.quick.added', { title: r.task.title }), 'success');
				soon(0);
			});
			setTimeout(() => { suggest(); show(); }, 0);
			const seg = evOn ? el('div', { class: 'seg nz-qmode', role: 'group', 'aria-label': t('notes.ev.kind') }, ['task', 'event', 'note'].map((k) => el('button', {
				type: 'button', class: mode() === k ? 'on' : '', 'aria-pressed': mode() === k ? 'true' : 'false', 'data-mode': k, text: t(`notes.ev.mode.${k}`),
				on: { click: () => { if (mode() !== k) setMode(k); } },
			}))) : null;
			return el('div', { class: 'nz-quick', 'data-mode': mode() }, [seg, el('label', { class: 'nz-quick-box' }, [icon(mode() === 'event' ? 'cal' : mode() === 'note' ? 'note' : 'plus', 18), input, el('span', { class: 'nz-kbd', text: t('notes.quick.kbd') })]), ask, chips, turnBox]);
		}

		/** „Eine Person · Reihum · Wer zuerst“ — the choice of the quick entry and of a task's details. */
		function turnSeg(value, pick, disabled, labelledBy) {
			const seg = el('div', { class: 'seg nz-turn-seg', role: 'group', 'aria-labelledby': labelledBy || null });
			for (const k of ['one', 'rotate', 'first']) {
				seg.appendChild(el('button', { type: 'button', class: value === k ? 'on' : '', 'aria-pressed': value === k ? 'true' : 'false', 'data-turn': k, disabled, text: t(`notes.turn.${k}`),
					on: { click: () => { if (value !== k) pick(k); } } }));
			}
			return seg;
		}

		function focusQuick() {
			if (!['smart', 'list', 'source'].includes(S.view.kind) || !has('tasks')) {
				go({ kind: 'smart', id: 'myday' }).then(() => { const q = refs.main.querySelector('#nz-quick'); if (q) q.focus(); });
				return;
			}
			const q = refs.main.querySelector('#nz-quick');
			if (q) { q.focus(); q.select(); }
		}

		// ── details ──────────────────────────────────────────
		function openDetail(x) {
			S.detail = { uid: x.uid, type: x.type, id: x.id };
			S.detailData = null;
			S.editing = false;
			rootEl.setAttribute('data-pane', 'detail');
			for (const r of refs.main.querySelectorAll('.nz-row')) r.classList.toggle('on', r.dataset.uid === x.uid);
			renderDetail();
			return reloadDetail();
		}

		function openNote(id, edit = false) {
			S.detail = { uid: `n:${id}`, type: 'note', id };
			S.detailData = null;
			S.editing = !!edit;
			rootEl.setAttribute('data-pane', 'detail');
			for (const c of refs.main.querySelectorAll('.nz-nc')) c.classList.toggle('on', Number(c.dataset.id) === id);
			renderDetail();
			return reloadDetail();
		}

		function closeDetail() {
			S.detail = null;
			S.detailData = null;
			S.editing = false;
			rootEl.setAttribute('data-pane', 'list');
			renderDetail();
			for (const r of refs.main.querySelectorAll('.nz-row.on, .nz-nc.on')) r.classList.remove('on');
		}

		function renderDetail() {
			const d = clear(refs.detail);
			const wide = S.view.kind === 'sources' || S.view.kind === 'import';
			rootEl.classList.toggle('no-detail', wide);
			if (wide) return;
			if (!S.detail) { d.appendChild(el('div', { class: 'nz-pick', text: S.view.kind === 'notes' ? t('notes.pickNote') : t('notes.pick') })); return; }
			if (!S.detailData) { d.appendChild(el('p', { class: 'nz-muted', text: t('notes.loading') })); return; }
			if (S.detail.type === 'task') d.appendChild(taskDetail(S.detailData.task));
			else if (S.detail.type === 'source') d.appendChild(itemDetail(S.detailData.item, S.detailData.taskId));
			else d.appendChild(noteDetail(S.detailData.note));
		}

		function closeRow() {
			return el('div', { class: 'nz-d-top' }, [el('span', { class: 'grow' }), ib('x', t('notes.close'), closeDetail)]);
		}

		function openOriginal(open) {
			const target = NS.openTarget(open, o.pages ? o.pages() : null);
			if (!target) return;
			if (target.page === 'notizen') { if (target.note) openNote(target.note); return; }
			o.openTarget(target);
		}

		async function patchTask(task, body) {
			const r = await api.updateTask(task.id, body);
			if (!ok(r)) { fail(r); return; }
			S.detailData = { ok: true, task: r.task };
			renderDetail();
			soon();
		}

		function taskDetail(task) {
			const box = el('div', { class: 'nz-d', 'data-task': String(task.id) });
			box.appendChild(closeRow());
			const title = el('textarea', { class: 'nz-d-title', rows: '2', maxlength: '300', 'aria-label': t('notes.titleField') });
			title.value = task.title;
			title.addEventListener('change', () => { const v = title.value.trim(); if (v && v !== task.title) patchTask(task, { title: v }); });
			// plugin 1.6.0: a task of the family's list a parent made — a child changes only „Mein Tag“ and ticks off what is theirs
			const fam = NS.familyInfo(S.me);
			const inFamily = task.family === true && NS.isFamilyList(S.me, task.listId);
			// … and a task of a list the person only reads stays readable too
			const locked = !task.canEdit;
			// plugin 1.7.0: this task reminds of a deadline of a file in Drive
			const dl = NS.deadlineInfo(task, S.me, t);
			box.appendChild(el('div', { class: 'nz-d-headrow' }, [
				el('button', { type: 'button', class: `nz-ck nz-ck-lg${task.done ? ' on' : ''}`, 'data-free': '', disabled: !task.canComplete, 'aria-label': task.done ? t('notes.undo') : t('notes.complete'), on: { click: async () => { const r = await api.completeTask(task.id, !task.done); if (!ok(r)) fail(r); else { reloadDetail(); soon(0); } } } }, [icon('check', 14)]),
				title,
				el('button', { type: 'button', class: `nz-star${task.important ? ' on' : ''}`, 'aria-label': t('notes.important'), 'aria-pressed': task.important ? 'true' : 'false', on: { click: () => patchTask(task, { important: !task.important }) } }, [icon('star', 20)]),
			]));
			const list = task.list || ((S.nav && S.nav.lists) || []).find((l) => l.id === task.listId);
			if (list) box.appendChild(el('div', { class: 'nz-crumb', text: `${t(`notes.area.${list.area}`)} › ${list.name}` }));
			if (locked) box.appendChild(inFamily ? el('p', { class: 'hint nz-locked', 'data-hint': 'parents-only', text: t('notes.err.parents_only') }) : el('p', { class: 'hint nz-locked', 'data-hint': 'read-only', text: t('notes.readOnlyTask') }));
			// „Erledigt von Lena“ — and for a parent the way back: „Noch nicht fertig“ (the task is open again, the stars are taken back)
			const by = NS.doneByText(task, S.me, t);
			const handBack = inFamily && fam.parent && task.done && task.doneBy && task.doneBy.id !== S.me.user.id && canWrite();
			if (by || handBack) {
				box.appendChild(el('div', { class: 'nz-doneby', 'data-free': '' }, [
					by ? el('span', { class: 'nz-mark nz-mark-lg', 'data-kind': 'doneby' }, [icon('check', 14), el('span', { text: by })]) : null,
					el('span', { class: 'grow' }),
					handBack ? btn(t('notes.turn.notDone'), async () => {
						const r = await api.completeTask(task.id, false);
						if (!ok(r)) { fail(r); return; }
						toast(t('notes.turn.handedBack', { title: task.title }), 'success');
						reloadDetail();
						soon(0);
					}, 'btn-sec', null, { 'data-act': 'not-done', title: t('notes.turn.notDoneHint') }) : null,
				]));
			}
			if (dl) box.appendChild(deadlineBox(task, dl));
			else if (task.sourceItem) box.appendChild(fromButton(task.sourceItem));
			// sub tasks
			box.appendChild(el('div', { class: 'nz-lb', text: t('notes.subtasks') }));
			const subs = el('div', { class: 'card nz-group-card' });
			for (const s of task.subtasks || []) {
				subs.appendChild(el('div', { class: `nz-subt${s.done ? ' is-done' : ''}`, 'data-id': String(s.id) }, [
					el('button', { type: 'button', class: `nz-ck${s.done ? ' on' : ''}`, 'aria-label': s.done ? t('notes.undo') : t('notes.complete'), on: { click: async () => { const r = await api.completeTask(s.id, !s.done); if (!ok(r)) fail(r); else { reloadDetail(); soon(); } } } }, [icon('check', 12)]),
					el('span', { class: 'grow', text: s.title }),
					ib('trash', t('notes.delete'), async () => { const r = await api.deleteTask(s.id); if (!ok(r)) fail(r); else { reloadDetail(); soon(); } }),
				]));
			}
			const add = el('input', { class: 'nz-add-inp', type: 'text', maxlength: '300', placeholder: t('notes.addSubtask'), 'aria-label': t('notes.addSubtask') });
			add.addEventListener('keydown', async (e) => {
				if (e.key !== 'Enter' || !add.value.trim()) return;
				const r = await api.createTask({ parentId: task.id, title: add.value.trim() });
				if (!ok(r)) { fail(r); return; }
				reloadDetail();
				soon();
			});
			subs.appendChild(el('label', { class: 'nz-subt nz-subt-add' }, [icon('plus', 15), add]));
			box.appendChild(subs);
			// details
			box.appendChild(el('div', { class: 'nz-lb', text: t('notes.details') }));
			const det = el('div', { class: 'card nz-group-card' });
			const myDay = field(t('notes.inMyDay'), sw(task.myDay, (v) => patchTask(task, { myDay: v }), t('notes.inMyDay')));
			myDay.setAttribute('data-free', '');
			det.appendChild(myDay);
			const dd = el('input', { class: 'inp nz-inp-sm', type: 'date', value: task.due ? task.due.date : '', 'aria-label': t('notes.due') });
			const dt = el('input', { class: 'inp nz-inp-sm', type: 'time', value: task.due && task.due.time ? task.due.time : '', 'aria-label': t('notes.dueTime') });
			const setDue = () => patchTask(task, { due: dd.value ? { date: dd.value, time: dt.value || null } : null });
			dd.addEventListener('change', setDue);
			dt.addEventListener('change', setDue);
			det.appendChild(field(t('notes.due'), el('span', { class: 'nz-pair' }, [dd, dt])));
			const rm = el('input', { class: 'inp nz-inp-sm', type: 'datetime-local', value: NS.localInput(task.remindAt), 'aria-label': t('notes.reminder') });
			rm.addEventListener('change', () => patchTask(task, { remindAt: rm.value ? { date: rm.value.slice(0, 10), time: rm.value.slice(11, 16) } : null }));
			// plugin 1.3.0: put off with „Später“; the event in the person's calendar in Mail
			const marks = NS.taskMarks(task, S.me, t);
			const later = marks.find((k) => k.kind === 'reminder' && task.snoozed);
			det.appendChild(field(t('notes.reminder'), rm, later ? later.text : null));
			const inCal = marks.find((k) => k.kind === 'calendar');
			if (inCal) det.appendChild(field(t('notes.calendar'), el('span', { class: 'nz-mark nz-mark-lg', 'data-kind': 'calendar' }, [icon('cal', 14), el('span', { text: inCal.long })])));
			const ro = NS.repeatOptions(task, S.me.today, t, lang());
			const rs = el('select', { class: 'inp nz-inp-sm', 'aria-label': t('notes.repeat') }, ro.options.map((x) => el('option', { value: x.value, text: x.label })));
			rs.value = ro.value;
			rs.addEventListener('change', () => {
				const opt = ro.options.find((x) => x.value === rs.value);
				if (!opt || rs.value === 'custom') return;
				if (opt.rule === 'after') {
					const n = el('input', { class: 'inp nz-inp-sm', type: 'number', min: '1', max: '365', value: '7', 'aria-label': t('notes.r.days') });
					const d = dialog(t('notes.r.after'), [field(t('notes.r.days'), n)], [btn(t('notes.cancel'), () => { d.close(); rs.value = ro.value; }, 'btn-ghost'),
						btn(t('notes.save'), () => { d.close(); patchTask(task, { repeat: { type: 'after', interval: Math.max(1, Math.min(365, Number(n.value) || 1)) } }); }, 'btn-pri')]);
					return;
				}
				patchTask(task, { repeat: opt.rule });
			});
			det.appendChild(field(t('notes.repeat'), rs));
			const members = list ? [list.owner, ...(list.members || [])].filter(Boolean) : [];
			// plugin 1.6.0: „wer zuerst“ has nobody assigned; with „reihum“ the choice is who is on now (somebody who takes part)
			const turnsOn = NS.offers(S.me, 'taskTurns') && !task.parentId;
			const turn = turnsOn ? task.turn : null;
			if (turn !== 'first') {
				const who = turn === 'rotate' ? task.people : members;
				const as = el('select', { class: 'inp nz-inp-sm', 'aria-label': t('notes.assigned'), 'data-act': 'assignee' }, [turn === 'rotate' ? null : el('option', { value: '', text: t('notes.nobody') }), ...who.map((m) => el('option', { value: String(m.id), text: S.me && m.id === S.me.user.id ? t('notes.me') : m.name || '' }))]);
				as.value = task.assignee ? String(task.assignee.id) : '';
				as.addEventListener('change', () => patchTask(task, { assigneeId: as.value ? Number(as.value) : null }));
				det.appendChild(field(t('notes.assigned'), as));
			}
			if (turnsOn && (members.length >= 2 || turn)) det.appendChild(turnField(task, members));
			if (NS.starsShown(S.me, task.listId) && !task.parentId) det.appendChild(starsField(task));
			// … and a parent ticks a task of the family's list off for a member of the family (the stars are theirs)
			if (inFamily && fam.parent && !task.done && !task.parentId && canWrite()) {
				const tf = el('select', { class: 'inp nz-inp-sm', 'aria-label': t('notes.turn.tickFor'), 'data-act': 'tick-for' }, [el('option', { value: '', text: t('notes.turn.tickForPick') }), ...members.map((m) => el('option', { value: String(m.id), text: m.id === S.me.user.id ? t('notes.me') : m.name || '' }))]);
				tf.addEventListener('change', async () => {
					const uid = Number(tf.value);
					if (!uid) return;
					const r = await api.completeTask(task.id, true, uid);
					if (!ok(r)) { tf.value = ''; fail(r); return; }
					const nm = members.find((m) => m.id === uid);
					toast(t('notes.turn.doneBy', { name: uid === S.me.user.id ? t('notes.turn.byMe') : (nm && nm.name) || '' }), 'success');
					reloadDetail();
					soon(0);
				});
				det.appendChild(field(t('notes.turn.tickFor'), tf, t('notes.turn.tickForHint')));
			}
			const ls = el('select', { class: 'inp nz-inp-sm', 'aria-label': t('notes.list') }, ((S.nav && S.nav.lists) || []).map((l) => el('option', { value: String(l.id), text: `${t(`notes.area.${l.area}`)} › ${l.name}` })));
			if (!((S.nav && S.nav.lists) || []).some((l) => l.id === task.listId) && list) ls.appendChild(el('option', { value: String(task.listId), text: list.name }));
			ls.value = String(task.listId);
			ls.addEventListener('change', () => patchTask(task, { listId: Number(ls.value) }));
			det.appendChild(field(t('notes.list'), ls));
			// plugin 1.4.0: the shopping list the task carries (the list stays what it is and can hang at several tasks)
			if (NS.offers(S.me, 'taskList') && shopOn() && !task.parentId) det.appendChild(attachedField(task));
			// plugin 1.5.0: the place the task hangs on — shown and changed here, watched by the phone
			if (placesOn() && !task.parentId) det.appendChild(placeField(task));
			box.appendChild(det);
			// attachments
			box.appendChild(el('div', { class: 'nz-lb', text: t('notes.attachments') }));
			box.appendChild(attachmentList('task', task.id, task.attachmentList || [], null));
			// note
			box.appendChild(el('div', { class: 'nz-lb', text: t('notes.note') }));
			const note = el('textarea', { class: 'inp nz-note-plain', rows: '4', 'aria-label': t('notes.note'), placeholder: t('notes.notePh') });
			note.value = task.note || '';
			note.addEventListener('change', () => patchTask(task, { note: note.value }));
			box.appendChild(note);
			if (task.sourceItem && !dl) box.appendChild(el('p', { class: 'hint', text: t('notes.doneHereThere', { source: task.sourceItem.source.label }) }));
			// deleting such a task means „no reminder of this deadline“ — said where it is deleted, and once more after
			if (dl && !locked) box.appendChild(el('p', { class: 'hint nz-dl-del', 'data-hint': 'deadline-delete', text: t('notes.dl.deleteHint') }));
			box.appendChild(el('div', { class: 'nz-d-foot' }, [
				el('span', { class: 'hint', text: task.updatedAt ? t('notes.changed', { when: new Date(task.updatedAt).toLocaleString(lang()) }) : '' }),
				locked ? null : btn(t('notes.delete'), async () => { const r = await api.deleteTask(task.id); if (!ok(r)) { fail(r); return; } closeDetail(); soon(0); toast(dl ? t('notes.dl.deleted') : t('notes.deleted'), 'success'); }, 'btn-danger', 'trash'),
			]));
			// what only the parents change stays readable (the server would refuse it anyway)
			if (locked) for (const c of box.querySelectorAll('input, select, textarea, button')) if (!c.closest('[data-free], .nz-d-top')) c.disabled = true;
			return box;
		}

		/**
		 * „Wer ist dran?“ in a task's details (plugin 1.6.0): Eine Person · Reihum · Wer zuerst, and under it who takes
		 * part. Changing needs two people at least; the server decides who is on.
		 */
		function turnField(task, members) {
			const may = task.canEdit && canWrite();
			const cur = task.turn || 'one';
			const send = (to, people) => {
				const body = NS.turnPatch(task, to, people);
				if (!body) { toast(t('notes.turn.two'), 'error'); renderDetail(); return; }
				patchTask(task, body);
			};
			const f = el('div', { class: 'nz-f nz-turn', 'data-field': 'turn' }, [el('span', { class: 'nz-f-l', id: 'nz-turn-l', text: t('notes.turn.label') }),
				turnSeg(cur, (to) => send(to, NS.turnPeople(task, members)), !may, 'nz-turn-l'), el('span', { class: 'hint', text: t('notes.turn.hint') })]);
			if (task.turn) {
				const chosen = new Set(task.people.map((x) => x.id));
				const who = el('div', { class: 'nz-share nz-turn-who', role: 'group', 'aria-label': t('notes.turn.people') });
				// who takes part keeps its order; a new one joins at the end
				const order = [...task.people, ...members.filter((m) => !chosen.has(m.id))];
				for (const m of order) {
					const cb = el('input', { type: 'checkbox', checked: chosen.has(m.id), disabled: !may, 'data-person': String(m.id) });
					cb.addEventListener('change', () => { if (cb.checked) chosen.add(m.id); else chosen.delete(m.id); send(task.turn, order.filter((x) => chosen.has(x.id)).map((x) => x.id)); });
					who.appendChild(el('label', { class: 'nz-check' }, [cb, el('span', { text: S.me && m.id === S.me.user.id ? t('notes.me') : m.name || '' })]));
				}
				f.append(el('span', { class: 'nz-f-l nz-turn-who-l', text: t('notes.turn.people') }), who);
			}
			return f;
		}

		/** „Sterne“ of a task of the family's list: parents choose (keine, 1 … 10), everybody else reads the number. */
		function starsField(task) {
			const may = NS.mayStar(S.me, task.listId) && task.canEdit && canWrite();
			let control;
			if (may) {
				control = el('select', { class: 'inp nz-inp-sm', 'aria-label': t('notes.turn.stars'), 'data-act': 'stars' }, NS.starChoices(S.me, t).map((c) => el('option', { value: String(c.value), text: c.label })));
				control.value = String(task.stars || 0);
				control.addEventListener('change', () => patchTask(task, { stars: Number(control.value) }));
			} else control = el('span', { class: 'nz-mark nz-mark-lg', 'data-kind': 'stars' }, [icon('star', 14), el('span', { text: task.stars ? NS.starsText(task.stars, t) : t('notes.turn.starsNone') })]);
			const f = field(t('notes.turn.stars'), control, t('notes.turn.starsHint'));
			f.setAttribute('data-field', 'stars');
			return f;
		}

		/** „Angehängte Liste“: none, one of the person's shopping lists, or a new one; the arrow opens the list. */
		function attachedField(task) {
			const cur = task.attachedList;
			const meId = S.me && S.me.user.id;
			const all = ((S.shop && S.shop.lists) || []).filter((l) => l.listId);
			const sel = el('select', { class: 'inp nz-inp-sm', 'aria-label': t('notes.shop.attached') }, [el('option', { value: '', text: t('notes.shop.none') }),
				...all.map((l) => el('option', { value: String(l.listId), text: NS.shopChoice(l, meId, t) }))]);
			if (cur && !all.some((l) => l.listId === cur.id)) sel.appendChild(el('option', { value: String(cur.id), text: cur.name }));
			if (canWrite()) sel.appendChild(el('option', { value: 'new', text: t('notes.shop.newListChoice') }));
			sel.value = cur ? String(cur.id) : '';
			sel.disabled = !task.canEdit || !canWrite();
			sel.addEventListener('change', () => {
				if (sel.value === 'new') {
					sel.value = cur ? String(cur.id) : '';
					newShopList((uid) => { if (uid) patchTask(task, { attachedListUid: uid }).then(() => reloadShop()); });
					return;
				}
				patchTask(task, { attachedListId: sel.value ? Number(sel.value) : null }).then(() => reloadShop());
			});
			return field(t('notes.shop.attached'), el('span', { class: 'nz-pair nz-attached' }, [sel,
				cur ? ib('open', t('notes.shop.openList'), () => { if (!openShopList(cur.uid)) toast(t('notes.shop.gone')); }, false, { 'data-act': 'open-list' }) : null]));
		}

		// ── a task at a place (plugin 1.5.0) ─────────────────
		const placesOn = () => NS.offers(S.me, 'places');

		/**
		 * „Ort“ in a task's details: „Baumarkt Nord · beim Ankommen“ — a click opens the choice. Under it what the person
		 * should know: someone else set the place (accept / decline), it waits for consent, it was declined, „Jeder …“
		 * needs the search, or the hint „in der Nähe“.
		 */
		function placeField(task) {
			const p = task.place;
			const may = task.canEdit && canWrite();
			const open = el('button', { type: 'button', class: 'btn btn-sec btn-sm nz-place-btn', 'data-act': 'place', disabled: !may, title: p ? NS.placeSummary(p, t) : null, 'aria-label': p ? t('notes.place.change', { name: p.name }) : t('notes.place.choose'),
				on: { click: () => placeDialog({ place: p, onSave: (arg) => patchTask(task, { place: arg }) }) } }, [icon('place', 15), el('span', { text: p ? NS.placeSummary(p, t) : t('notes.place.choose') })]);
			// no <label>: the hint under it carries buttons of its own
			const f = el('div', { class: 'nz-f nz-place' }, [el('span', { class: 'nz-f-l', text: t('notes.place.field') }), open]);
			const h = NS.placeHint(task, S.me, t);
			if (h) {
				const answer = async (accept) => {
					const r = await Promise.resolve(api.placeConsent(task.id, accept)).catch(() => null);
					if (!ok(r)) { fail(r); return; }
					toast(t(r.consent === 'accepted' ? 'notes.place.accepted' : 'notes.place.declined'), 'success');
					reloadDetail();
					soon();
				};
				f.appendChild(el('span', { class: `hint nz-place-hint${h.ask ? ' is-ask' : ''}`, 'data-kind': h.kind, role: h.ask ? 'group' : null, 'aria-label': h.ask ? h.text : null }, [
					el('span', { text: h.text }),
					h.ask ? el('span', { class: 'nz-row-acts' }, [btn(t('notes.place.accept'), () => answer(true), 'btn-pri', null, { 'data-act': 'place-accept' }), btn(t('notes.place.decline'), () => answer(false), 'btn-sec', null, { 'data-act': 'place-decline' })]) : null,
				]));
			}
			return f;
		}

		/** A row to choose in the dialog „Welcher …?“: the name, the grey line, on the right the minutes and the distance. */
		function placeRow(o) {
			return el('button', { type: 'button', class: `nz-pl-row${o.on ? ' on' : ''}${o.dashed ? ' is-any' : ''}`, role: 'radio', 'aria-checked': o.on ? 'true' : 'false', 'data-ref': o.ref || null, on: { click: o.pick } }, [
				el('span', { class: 'nz-pl-dot', 'aria-hidden': 'true' }),
				el('span', { class: 'nz-pl-tx' }, [el('b', { text: o.name }), o.sub ? el('span', { text: o.sub }) : null]),
				o.right ? el('span', { class: 'nz-pl-r' }, [el('b', { text: o.right[0] }), el('span', { text: o.right[1] })]) : null,
			]);
		}

		/** What a failed search says. */
		function searchError(r) {
			const code = r && r.code;
			if (code === 'module_off') return t('notes.place.searchOff');
			if (code === 'busy') return r.retryAfter ? t('notes.place.searchBusyIn', { n: r.retryAfter }) : t('notes.place.searchBusy');
			if ((code === 'invalid' || code === 'not_found') && r.field === 'near') return t('notes.place.searchNear');
			return t('notes.place.searchDown');
		}

		/** „Fahrzeit geschätzt aus der Entfernung. Kartendaten: © OpenStreetMap“ — the link opens in the browser. */
		function attributionLine(a, withApprox) {
			const url = a && a.url;
			return el('p', { class: 'hint nz-pl-attr' }, [withApprox ? el('span', { text: `${t('notes.place.approx')} ` }) : null,
				url ? el('button', { type: 'button', class: 'nz-linkbtn', 'data-act': 'osm', text: a.text, on: { click: () => o.openExternal(url) } }) : el('span', { text: a.text })]);
		}

		/**
		 * The dialog „Welcher Baumarkt?“ / „Ort“ (the plugin's portal dialog as a list, without a map): the search near one
		 * of the person's places (only on „Suchen“, Enter, or when the chip „Ort: Baumarkt …“ opened it — never while
		 * typing), the hits with estimated minutes and kilometres, „Jeder …“, „Meine Orte“, on arriving / on leaving, „als
		 * meinen Ort merken“. `c`: { place (a task's place), hint ({ key, label, query, trigger } of the quick entry),
		 * decided (its place that stands), options, searchNow, none (false: no „Ohne Ort“), onSave(arg | null, text) }.
		 */
		function placeDialog(c) {
			const cur = c.place || null;
			const hint = c.hint || null;
			const st = {
				sel: null, trigger: (cur ? cur.trigger : hint && hint.trigger) === 'exit' ? 'exit' : 'enter', key: (hint && hint.key) || (cur && cur.key) || null,
				label: (hint && hint.label && hint.key ? hint.label : null) || (cur && cur.key ? cur.label : null), remember: false, results: null, any: false, radius: 15,
				all: null, busy: false, error: null, attribution: null, seq: 0,
			};
			const dec = c.decided || null;
			if (dec) st.sel = dec.familyId ? { type: 'family', familyId: dec.familyId } : { type: 'own', placeId: dec.id };
			const head = () => (st.label ? t('notes.place.which', { label: st.label }) : t('notes.place.title'));
			const q = el('input', { class: 'inp', type: 'search', value: (hint && hint.query) || '', placeholder: t('notes.place.searchPh'), 'aria-label': t('notes.place.searchPh'), maxlength: '80', 'data-act': 'place-q' });
			const near = el('select', { class: 'inp', 'aria-label': t('notes.place.near'), 'data-act': 'place-near' });
			const go2 = btn(t('notes.place.search'), () => search(), 'btn-sec', 'search', { 'data-act': 'place-search' });
			const searchRow = el('div', { class: 'nz-pl-search' }, [q, near, go2]);
			const dyn = el('div', { class: 'nz-pl-body' });
			const d = dialog(head(), [el('div', { class: 'nz-pl' }, [searchRow, dyn])], [], { wide: true });
			d.box.classList.add('nz-pl-dlg');
			d.box.setAttribute('data-dialog', 'place');
			const titleEl = d.box.querySelector('.nz-dlg-title');
			const isSel = (type, test) => !!st.sel && st.sel.type === type && (!test || test(st.sel));
			const pick = (sel) => { st.sel = sel; draw(); };

			async function search() {
				const text = q.value.trim();
				if (st.busy || (text.length < 2 && !st.key)) return;
				// the line's own kind or name is asked by its key; anything typed is for the server to read (a kind, an address, a name)
				const b = text.length >= 2 && !(hint && text === hint.query && st.key && st.key === hint.key) ? { q: text } : { key: st.key, ...(st.label ? { label: st.label } : {}) };
				Object.assign(b, NS.nearArg(near.value));
				if (!b.nearPlaceId && !b.nearFamilyId) b.address = true;
				const seq = ++st.seq;
				st.busy = true;
				st.error = null;
				draw();
				const r = await Promise.resolve(api.searchPlaces(b)).catch(() => null);
				if (seq !== st.seq || !d.box.isConnected) return;
				st.busy = false;
				if (!ok(r)) {
					st.results = null;
					st.error = searchError(r);
					// switched off meanwhile: the page learns it
					if (r && (r.code === 'module_off' || r.code === 'unavailable')) await loadMe();
					draw();
					return;
				}
				Object.assign(st, { results: r.results, any: r.any, attribution: r.attribution, radius: r.radiusKm, key: r.key || null, label: r.key ? r.label : null, none: r.label || text });
				// a hit of an earlier search is no choice any more
				if (isSel('hit') || isSel('any')) st.sel = null;
				if (!st.sel && r.results.length) st.sel = { type: 'hit', hit: r.results.find((x) => x.fav) || r.results[0] };
				draw();
			}
			q.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); search(); } });

			function draw() {
				titleEl.textContent = head();
				d.box.setAttribute('aria-label', head());
				clear(dyn);
				const state = NS.searchState(S.me);
				const opts = NS.nearOptions(st.all);
				searchRow.hidden = state !== 'on';
				go2.disabled = st.busy;
				if (state === 'on' && st.all && !opts.length) dyn.appendChild(el('p', { class: 'hint', text: t('notes.place.nearHint') }));
				if (st.busy) dyn.appendChild(el('p', { class: 'hint', role: 'status', 'data-state': 'searching', text: t('notes.place.searching') }));
				if (st.error) dyn.appendChild(el('div', { class: 'note note-err', role: 'alert', text: st.error }));
				if (st.results) {
					if (!st.results.length) dyn.appendChild(el('p', { class: 'nz-pl-none', text: t('notes.place.none', { label: st.none || '', km: st.radius || 15 }) }));
					const list = el('div', { class: 'nz-pl-list', role: 'radiogroup', 'aria-label': head(), 'data-list': 'hits' });
					for (const x of st.results) {
						const sub = [x.address, x.fav && st.label ? t('notes.place.favFor', { label: st.label }) : x.uses > 1 ? t('notes.place.used', { n: x.uses }) : null].filter(Boolean).join(' · ');
						list.appendChild(placeRow({ name: x.name, sub, ref: x.ref, right: x.distanceM === null ? null : [t('notes.place.min', { n: x.minutes }), NS.distText(x.distanceM, lang())], on: isSel('hit', (z) => z.hit === x), pick: () => pick({ type: 'hit', hit: x }) }));
					}
					if (st.any && st.key && st.label) list.appendChild(placeRow({ name: t('notes.place.any', { label: st.label }), sub: t('notes.place.anyHint'), ref: 'any', dashed: true, on: isSel('any'), pick: () => pick({ type: 'any' }) }));
					if (list.childNodes.length) dyn.appendChild(list);
					// „© OpenStreetMap“ stands wherever hits stand
					if (st.attribution) dyn.appendChild(attributionLine(st.attribution, st.results.some((x) => x.distanceM !== null)));
					dyn.appendChild(el('p', { class: 'hint', text: t('notes.place.privacy') }));
				}
				// „Meine Orte“: the family's, the own ones, and what was chosen for this kind before
				dyn.appendChild(el('div', { class: 'nz-lb', text: t('notes.place.mine') }));
				if (!st.all) dyn.appendChild(el('p', { class: 'hint', text: t('notes.place.loading') }));
				else {
					const ml = el('div', { class: 'nz-pl-list', role: 'radiogroup', 'aria-label': t('notes.place.mine'), 'data-list': 'mine' });
					for (const f of st.all.family) ml.appendChild(placeRow({ name: f.name, sub: t('notes.place.family'), ref: `f:${f.familyId}`, on: isSel('family', (z) => z.familyId === f.familyId), pick: () => pick({ type: 'family', familyId: f.familyId }) }));
					const own = [...st.all.places, ...(c.options || []).filter((x) => !st.all.places.some((y) => y.id === x.id))];
					for (const x of own) {
						const sub = NS.placeSub(x, t) || (x.named ? t('notes.place.saved') : x.uses > 1 ? t('notes.place.used', { n: x.uses }) : '');
						ml.appendChild(placeRow({ name: x.name, sub, ref: `p:${x.id}`, on: isSel('own', (z) => z.placeId === x.id), pick: () => pick({ type: 'own', placeId: x.id }) }));
					}
					dyn.appendChild(ml.childNodes.length ? ml : el('p', { class: 'hint', text: t('notes.place.mineNone') }));
				}
				if (state !== 'on') dyn.appendChild(el('p', { class: 'hint', 'data-state': 'search-off', text: t(state === 'unavailable' ? 'notes.place.searchDown' : 'notes.place.searchOff') }));
				// on arriving / on leaving, remember
				const seg = el('div', { class: 'seg nz-pl-when', role: 'group', 'aria-label': t('notes.place.when') });
				for (const tr of ['enter', 'exit']) {
					seg.appendChild(el('button', { type: 'button', class: st.trigger === tr ? 'on' : '', 'aria-pressed': st.trigger === tr ? 'true' : 'false', 'data-trigger': tr, text: t(`notes.place.${tr}`), on: { click: () => { st.trigger = tr; draw(); } } }));
				}
				dyn.appendChild(seg);
				if (st.key && st.label && (isSel('hit') || isSel('own'))) {
					const ck = el('input', { type: 'checkbox', checked: st.remember, 'data-act': 'place-remember' });
					ck.addEventListener('change', () => { st.remember = ck.checked; });
					dyn.appendChild(el('label', { class: 'nz-check' }, [ck, el('span', { text: t('notes.place.remember', { label: st.label }) })]));
				}
				dyn.appendChild(el('p', { class: 'hint nz-pl-phone', text: t('notes.place.phoneHint') }));
				dyn.appendChild(el('div', { class: 'dlg-actions' }, [
					c.none !== false && cur ? btn(t('notes.place.remove'), () => { d.close(); c.onSave(null, ''); }, 'btn-danger', null, { 'data-act': 'place-none' }) : null,
					btn(t('notes.cancel'), () => d.close(), 'btn-ghost'),
					btn(t('notes.save'), () => {
						// plugin 1.8.0: a place of „Meine Orte“ by its reference (profile:<id>)
						const arg = st.all && st.all.profile ? NS.profileArg(NS.placeChoiceArg(st.sel, st), st.all.places) : NS.placeChoiceArg(st.sel, st);
						const text = NS.placeChoiceText(st.sel, st, { places: [...(st.all ? st.all.places : []), ...(c.options || [])], family: st.all ? st.all.family : [] }, t) || (cur ? cur.name : '');
						d.close();
						c.onSave(arg, text);
					}, 'btn-pri', null, { 'data-act': 'place-save', disabled: !st.sel && !cur }),
				]));
			}

			draw();
			// „Meine Orte“ and whether the search is on right now (`me.places` — it may have been switched meanwhile)
			Promise.all([Promise.resolve(api.places()).catch(() => null), loadMe()]).then(([r]) => {
				if (!d.box.isConnected) return;
				if (!ok(r)) { if (r) fail(r); st.all = { places: [], family: [], favs: [] }; draw(); return; }
				st.all = { places: r.places || [], family: r.family || [], favs: r.favs || [], profile: r.profile === true };
				clear(near);
				const opts = NS.nearOptions(st.all);
				for (const x of opts) near.appendChild(el('option', { value: x.value, text: t('notes.place.nearOf', { name: x.label }) }));
				if (!opts.length) near.appendChild(el('option', { value: '', text: t('notes.place.nearNone') }));
				if (cur && cur.id && !st.sel && st.all.places.some((x) => x.id === cur.id)) st.sel = { type: 'own', placeId: cur.id };
				draw();
				// the chip „Ort: Baumarkt …“ asked for the places near: one search, because the dialog was opened for it
				if (c.searchNow && st.key && NS.searchState(S.me) === 'on' && opts.length) search();
			});
			return d;
		}

		/**
		 * One of „Meine Orte“, new or changed: name, address (looked up through the server when the search is on), latitude
		 * and longitude, the radius. No map — this app loads no map tiles.
		 */
		function placeEditor(pl, all, done) {
			const info = (S.me && S.me.places) || null;
			const searchOn = NS.searchState(S.me) === 'on';
			const name = el('input', { class: 'inp', type: 'text', value: pl ? pl.name : '', maxlength: '80', 'aria-label': t('notes.place.name'), 'data-f': 'name' });
			const addr = el('input', { class: 'inp', type: 'text', value: pl ? pl.address : '', maxlength: '160', placeholder: t('notes.place.addressPh'), 'aria-label': t('notes.place.address'), 'data-f': 'address' });
			const lat = el('input', { class: 'inp', type: 'number', step: 'any', min: '-90', max: '90', value: pl ? String(pl.lat) : '', placeholder: t('notes.place.lat'), 'aria-label': t('notes.place.lat'), 'data-f': 'lat' });
			const lon = el('input', { class: 'inp', type: 'number', step: 'any', min: '-180', max: '180', value: pl ? String(pl.lon) : '', placeholder: t('notes.place.lon'), 'aria-label': t('notes.place.lon'), 'data-f': 'lon' });
			const radius = el('input', { class: 'inp', type: 'number', min: '50', max: '2000', step: '10', value: String(pl ? pl.radius : info ? info.radius.default : 150), 'aria-label': t('notes.place.radius'), 'data-f': 'radius' });
			const hits = el('div', { class: 'nz-pl-list', 'data-list': 'addresses' });
			const err = el('p', { class: 'nz-err', role: 'alert' });
			let ref = null;
			let busy = false;
			const find = async () => {
				const text = addr.value.trim();
				if (busy || text.length < 3) return;
				busy = true;
				clear(hits).appendChild(el('p', { class: 'hint', role: 'status', text: t('notes.place.searching') }));
				const r = await Promise.resolve(api.searchPlaces({ q: text, address: true, ...NS.nearArg((NS.nearOptions(all)[0] || {}).value) })).catch(() => null);
				busy = false;
				clear(hits);
				if (!ok(r)) { hits.appendChild(el('p', { class: 'hint', role: 'alert', text: searchError(r) })); return; }
				if (!r.results.length) hits.appendChild(el('p', { class: 'nz-pl-none', text: t('notes.place.addrNone') }));
				for (const x of r.results) {
					hits.appendChild(placeRow({ name: x.name, sub: x.address, ref: x.ref, on: false, pick: () => {
						lat.value = String(x.lat);
						lon.value = String(x.lon);
						if (x.address) addr.value = x.address;
						ref = x.ref || null;
						clear(hits);
					} }));
				}
				if (r.attribution && r.results.length) hits.appendChild(attributionLine(r.attribution, false));
			};
			addr.addEventListener('keydown', (e) => { if (e.key === 'Enter' && searchOn) { e.preventDefault(); find(); } });
			// a point typed by hand is no hit of the search any more
			for (const n of [lat, lon]) n.addEventListener('input', () => { ref = null; });
			const save = async () => {
				const a = Number(lat.value);
				const b = Number(lon.value);
				if (!name.value.trim()) { err.textContent = t('notes.place.nameNeed'); return; }
				if (lat.value === '' || lon.value === '' || !Number.isFinite(a) || !Number.isFinite(b) || Math.abs(a) > 90 || Math.abs(b) > 180) { err.textContent = t('notes.place.pointNeed'); return; }
				const rad = Math.max(50, Math.min(2000, Math.round(Number(radius.value)) || 150));
				const body = { name: name.value.trim(), address: addr.value.trim(), lat: a, lon: b, radius: rad };
				const r = await Promise.resolve(pl ? api.updatePlace(pl.id, { ...body, named: true }) : api.createPlace(ref ? { ...body, ref } : body)).catch(() => null);
				if (!ok(r)) { err.textContent = NS.errText(r, t); return; }
				d.close();
				done();
			};
			const d = dialog(pl ? t('notes.place.edit') : t('notes.place.new'), [
				field(t('notes.place.name'), name),
				field(t('notes.place.address'), el('span', { class: 'nz-pair nz-pl-addr' }, [addr, searchOn ? btn(t('notes.place.addrFind'), find, 'btn-sec', 'search', { 'data-act': 'addr-find' }) : null])),
				hits,
				el('div', { class: 'nz-pair nz-pl-coords' }, [lat, lon]),
				field(t('notes.place.radius'), radius),
				el('p', { class: 'hint', text: t(searchOn ? 'notes.place.editHint' : 'notes.place.editHintOff') }),
				err,
			], [btn(t('notes.cancel'), () => d.close(), 'btn-ghost'), btn(t('notes.save'), save, 'btn-pri', null, { 'data-act': 'place-save' })], { wide: true });
			d.box.setAttribute('data-dialog', 'place-edit');
			return d;
		}

		/** „Meine Orte“ for the page „Quellen“ (asked when it is shown and after a change). */
		async function reloadPlaces() {
			if (!placesOn()) { S.places = null; return; }
			const r = await Promise.resolve(api.places()).catch(() => null);
			if (ok(r)) S.places = { places: r.places || [], family: r.family || [], favs: r.favs || [], profile: r.profile === true, notMoved: r.notMoved || [] };
			if (S.view.kind === 'sources') renderMain();
		}

		/**
		 * „Orte“ on the page „Quellen“: the person's switches (the search on the internet, the hint „in der Nähe“ and its
		 * quiet hours — they steer the phone) and „Meine Orte“.
		 */
		function placesSettings(wrap, save) {
			const info = S.me.places;
			const prefs = (S.me.prefs && S.me.prefs.places) || { search: true, nearby: true, quiet: null };
			const set = async (places) => { await save({ places }); await loadMe(); if (S.view.kind === 'sources') renderMain(); };
			wrap.appendChild(el('h2', { class: 'nz-set-title', 'data-set': 'places', text: t('notes.place.setTitle') }));
			const card = el('div', { class: 'card nz-card nz-places-set', 'data-card': 'place-switches' });
			const adminOff = !info || !info.search.enabled || !NS.offers(S.me, 'placeSearch');
			card.appendChild(field(t('notes.place.setSearch'), sw(!adminOff && prefs.search !== false, (v) => set({ search: v }), t('notes.place.setSearch'), adminOff), adminOff ? t('notes.place.setSearchAdmin') : t('notes.place.setSearchHint')));
			card.appendChild(field(t('notes.place.setNearby'), sw(prefs.nearby !== false, (v) => set({ nearby: v }), t('notes.place.setNearby')), t('notes.place.setNearbyHint')));
			const quiet = prefs.quiet || null;
			const from = el('input', { class: 'inp nz-inp-sm', type: 'time', value: quiet ? quiet.from : '21:00', 'aria-label': t('notes.place.setQuietFrom') });
			const to = el('input', { class: 'inp nz-inp-sm', type: 'time', value: quiet ? quiet.to : '07:00', 'aria-label': t('notes.place.setQuietTo') });
			const saveQuiet = () => { if (from.value && to.value && from.value !== to.value) set({ quiet: { from: from.value, to: to.value } }); };
			from.addEventListener('change', saveQuiet);
			to.addEventListener('change', saveQuiet);
			card.appendChild(field(t('notes.place.setQuiet'), sw(!!quiet, (v) => set({ quiet: v ? { from: from.value || '21:00', to: to.value || '07:00' } : null }), t('notes.place.setQuiet')), t('notes.place.setQuietHint')));
			if (quiet) card.appendChild(field(t('notes.place.setQuietTimes'), el('span', { class: 'nz-pair' }, [from, to])));
			card.appendChild(el('p', { class: 'hint nz-places-phone', text: t('notes.place.setHint') }));
			card.appendChild(el('p', { class: 'hint', text: t('notes.place.privacy') }));
			wrap.appendChild(card);
			// „Meine Orte“
			const mine = el('div', { class: 'card nz-card nz-places-mine', 'data-card': 'places' });
			const all = S.places;
			const again = () => reloadPlaces();
			mine.appendChild(el('div', { class: 'nz-set-h' }, [el('b', { class: 'grow', text: t('notes.place.mine') }), all && canWrite() ? btn(t('notes.place.new'), () => placeEditor(null, all, again), 'btn-sec', 'plus', { 'data-act': 'place-new' }) : null]));
			// plugin 1.8.0 (`profilePlaces`): the places are those of „Meine Orte“ in the profile — the page of this app,
			// what the move could not take
			if (all && all.profile) {
				const page = typeof o.openPlaces === 'function' && (typeof o.placesShown !== 'function' || o.placesShown());
				mine.appendChild(el('div', { class: 'nz-place-profile', 'data-box': 'profile' }, [
					el('span', { class: 'hint grow', text: t('notes.place.profileHint') }),
					page ? btn(t('notes.place.openMine'), () => o.openPlaces(), 'btn-sec', 'place', { 'data-act': 'open-places' }) : null,
				]));
				if (all.notMoved && all.notMoved.length) {
					const n = all.notMoved.length;
					mine.appendChild(el('div', { class: 'note note-warn', 'data-box': 'not-moved', text: t(`notes.place.notMoved_${n === 1 ? 'one' : 'other'}`, { n, names: all.notMoved.map((x) => x.name).join(', ') }) }));
				}
			}
			if (!all) mine.appendChild(el('p', { class: 'hint', text: t('notes.place.loading') }));
			else {
				for (const f of all.family) {
					mine.appendChild(el('div', { class: 'nz-place-row', 'data-place': `f:${f.familyId}` }, [el('div', { class: 'grow' }, [el('b', { text: f.name }), el('span', { class: 'hint nz-block', text: t('notes.place.family') })]), el('span', { class: 'nz-place-ic', title: t('notes.place.family') }, [icon('home', 16)])]));
				}
				const PV = root.GCPlacesView;
				for (const x of all.places) {
					const favs = x.favFor || [];
					// plugin 1.8.0: the symbol and who sees the place (fields of the profile)
					const vis = all.profile && x.visibility ? t(`places.visShort.${x.visibility}`) : null;
					const sub = [NS.placeSub(x, t), vis].filter(Boolean).join(' · ');
					mine.appendChild(el('div', { class: 'nz-place-row', 'data-place': `p:${x.id}`, 'data-icon': all.profile && x.icon ? x.icon : null }, [
						all.profile && PV ? PV.badge({ icon: x.icon }, 28) : null,
						el('div', { class: 'grow' }, [el('b', { text: x.name }), sub ? el('span', { class: 'hint nz-block', text: sub }) : null]),
						favs.length && canWrite() ? ib('x', t('notes.place.forget', { label: favs.map((f) => f.label).join(', ') }), async () => {
							for (const f of favs) { const r = await api.setPlaceFav(f.key, null); if (!ok(r)) { fail(r); break; } }
							again();
						}, false, { 'data-act': 'place-forget' }) : null,
						canWrite() ? ib('edit', t('notes.place.edit'), () => placeEditor(x, all, again), false, { 'data-act': 'place-edit' }) : null,
						canWrite() ? ib('trash', t('notes.delete'), async () => {
							// plugin 1.8.0: a place another plugin uses asks first who uses it, then deletes it all the same (force)
							if (all.profile && PV) {
								const r = await PV.deleteFlow({ place: x, t, remove: (id, opts) => api.deletePlace(id, opts), errorText: (res) => NS.errText(res, t) });
								if (typeof r === 'string') toast(r, 'error');
								if (r === true) again();
								return;
							}
							const r = await api.deletePlace(x.id);
							if (!ok(r)) fail(r);
							again();
						}, false, { 'data-act': 'place-delete' }) : null,
					]));
				}
				if (!all.family.length && !all.places.length) mine.appendChild(el('p', { class: 'hint', text: t('notes.place.mineNone') }));
			}
			wrap.appendChild(mine);
		}

		/**
		 * A task that reminds of a deadline of a file in Drive (plugin 1.7.0): „Aus Drive · <Datei> · Datei öffnen“ — the
		 * file on the Drive page of this app —, the day with how many days before, and where both are set.
		 */
		function deadlineBox(task, dl) {
			const open = dl.open || (task.sourceItem && task.sourceItem.source.open) || null;
			const from = t('notes.from', { source: task.sourceItem ? task.sourceItem.source.label : t(`notes.src.${task.source ? task.source.plugin : 'gatecontrol-drive'}`) });
			return el('div', { class: 'nz-dl', 'data-box': 'deadline', 'data-free': '' }, [
				open ? el('button', { type: 'button', class: 'nz-from', 'data-act': 'open-file', on: { click: () => openOriginal(open) } }, [
					el('b', { text: from }), el('span', { class: 'nz-from-tx', text: [dl.file, t('notes.dl.open')].filter(Boolean).join(' · ') }), icon('open', 15)])
					: el('div', { class: 'nz-from is-plain' }, [el('b', { text: from }), el('span', { class: 'nz-from-tx', text: dl.file })]),
				el('span', { class: 'nz-mark nz-mark-lg', 'data-kind': 'deadline' }, [icon('bell', 14), el('span', { text: [dl.line, dl.before].filter(Boolean).join(' · ') })]),
				el('p', { class: 'hint', 'data-hint': 'deadline', text: t('notes.dl.hint') }),
			]);
		}

		function fromButton(item) {
			return el('button', { type: 'button', class: 'nz-from', on: { click: () => openOriginal(item.source.open) } }, [
				el('b', { text: t('notes.from', { source: item.source.label }) }), el('span', { class: 'nz-from-tx', text: `${item.subtitle || item.title} · ${t('notes.openThere')}` }), icon('open', 15)]);
		}

		function itemDetail(x, taskId) {
			const box = el('div', { class: 'nz-d', 'data-item': String(x.id) });
			box.appendChild(closeRow());
			box.appendChild(el('h2', { class: 'nz-d-h', text: x.title }));
			box.appendChild(fromButton(x));
			box.appendChild(el('div', { class: 'nz-lb', text: t('notes.details') }));
			const det = el('div', { class: 'card nz-group-card' });
			const row = (label, value) => det.appendChild(el('div', { class: 'nz-f' }, [el('span', { class: 'nz-f-l', text: label }), el('span', { class: 'nz-f-v', text: value })]));
			if (x.due) row(t('notes.due'), NS.dayText(x.due.date, S.me.today, t) + (x.due.time ? ` ${x.due.time}` : ''));
			if (x.show && x.lead === 'evening') row(t('notes.shownAt'), `${NS.dayText(x.show.date, S.me.today, t)} ${x.show.time || ''}`.trim());
			if (x.assignee && x.assignee.name) row(t('notes.assigned'), x.assignee.name);
			if (x.group) row(t('notes.group'), x.group.label);
			if (x.progress) row(t('notes.progress'), `${x.progress.done}/${x.progress.total}`);
			for (const [k, v] of Object.entries(x.meta || {})) if (k !== 'type' && typeof v !== 'boolean') row(t(`notes.m.${k}`) === `notes.m.${k}` ? k : t(`notes.m.${k}`), String(v));
			if (det.childNodes.length) box.appendChild(det);
			if (x.canComplete) {
				box.appendChild(el('div', { class: 'nz-row-acts' }, [btn(x.done ? t('notes.undo') : t('notes.completeThere', { source: x.source.label }), () => complete(x, !x.done).then(() => setTimeout(reloadDetail, 300)), x.done ? 'btn-sec' : 'btn-pri', 'check')]));
				box.appendChild(el('p', { class: 'hint', text: t('notes.carryHint') }));
				box.appendChild(el('div', { class: 'nz-row-acts' }, [btn(taskId ? t('notes.carryOpen') : t('notes.carry'), async () => {
					const r = await api.carryItem(x.id);
					if (!ok(r)) { fail(r); return; }
					S.detail = { uid: `t:${r.task.id}`, type: 'task', id: r.task.id };
					S.detailData = { ok: true, task: r.task };
					renderDetail();
					soon();
				}, 'btn-sec', 'plus')]));
			}
			return box;
		}

		// ── attachments ──────────────────────────────────────
		function attachmentList(kind, refId, list, vaultId) {
			const box = el('div', { class: 'nz-atts' });
			for (const a of list) {
				box.appendChild(el('div', { class: 'nz-att', 'data-att': String(a.id) }, [
					icon('clip', 15),
					el('button', { type: 'button', class: 'nz-att-name', text: a.name || t('notes.file'), title: t('notes.openFile'), on: { click: async () => { const r = await api.openAttachment(a.id, vaultId); if (!ok(r)) fail(r); } } }),
					ib('move', t('notes.saveAs'), async () => { const r = await api.saveAttachment(a.id, vaultId); if (!ok(r) && r.code !== 'cancelled') fail(r); }),
					ib('trash', t('notes.delete'), async () => { const r = await api.deleteAttachment(a.id); if (!ok(r)) fail(r); else { reloadDetail(); soon(); } }),
				]));
			}
			box.appendChild(btn(t('notes.addFile'), async () => {
				const r = await api.attach(kind, refId);
				if (!ok(r)) { if (r && r.code !== 'cancelled') fail(r); return; }
				for (const x of r.rejected || []) toast(`${x.name}: ${NS.errText({ code: x.code }, t)}`, 'error');
				reloadDetail();
				soon();
			}, 'btn-sec', 'clip'));
			return box;
		}

		/** A picture of a note: its bytes from the main process (a Tresor's decrypted there) as a blob: URL. */
		function imageUrl(id, vaultId) {
			const key = `${id}|${vaultId || ''}`;
			if (!S.images.has(key)) {
				S.images.set(key, Promise.resolve(api.attachmentImage(id, vaultId)).then((r) => (ok(r) && r.data ? URL.createObjectURL(new Blob([r.data], { type: r.mime })) : null)).catch(() => null));
			}
			return S.images.get(key);
		}

		function forgetImages() {
			for (const p of S.images.values()) p.then((u) => { if (u) URL.revokeObjectURL(u); }).catch(() => {});
			S.images.clear();
		}

		// ── a note ───────────────────────────────────────────
		/** The Markdown tree (notes-md.js) → DOM: text nodes only, links open in the browser through the main process. */
		function inlineNodes(list, ctx) {
			const out = [];
			for (const n of list) {
				if (n.t === 'text') out.push(document.createTextNode(n.v));
				else if (n.t === 'code') out.push(el('code', { text: n.v }));
				else if (n.t === 'b') out.push(el('strong', null, inlineNodes(n.c, ctx)));
				else if (n.t === 'i') out.push(el('em', null, inlineNodes(n.c, ctx)));
				else if (n.t === 's') out.push(el('del', null, inlineNodes(n.c, ctx)));
				else if (n.t === 'span') out.push(...inlineNodes(n.c, ctx));
				else if (n.t === 'tag') out.push(el('button', { type: 'button', class: 'nm-tag', text: n.v, on: { click: () => go({ kind: 'notes', tag: n.v.slice(1).toLowerCase() }) } }));
				else if (n.t === 'link') {
					const href = MD.safeUrl(n.href);
					out.push(el('a', { class: 'nm-link', role: 'link', tabindex: '0', title: href || '', on: {
						click: (e) => { e.preventDefault(); if (href) o.openExternal(href); },
						keydown: (e) => { if (e.key === 'Enter' && href) o.openExternal(href); },
					} }, inlineNodes(n.c, ctx)));
				} else if (n.t === 'img' || n.t === 'file') {
					const a = ctx.atts.get(n.att);
					const label = (n.t === 'img' ? n.alt : n.label) || (a && a.name) || t('notes.file');
					if (!a) { out.push(el('span', { class: 'nm-missing', text: label })); continue; }
					if (n.t === 'img' && /^image\//.test(a.mime || '')) {
						const img = el('img', { class: 'nm-img', alt: label, 'data-att': String(a.id), draggable: 'false' });
						imageUrl(a.id, ctx.vaultId).then((u) => { if (u) img.src = u; else img.replaceWith(el('span', { class: 'nm-missing', text: label })); });
						out.push(img);
					} else {
						out.push(el('button', { type: 'button', class: 'nm-file', 'data-att': String(a.id), on: { click: async () => { const r = await api.openAttachment(a.id, ctx.vaultId); if (!ok(r)) fail(r); } } }, [icon('clip', 13), el('span', { text: label })]));
					}
				} else if (n.t === 'task') {
					const tk = ctx.tasks.get(n.task);
					const label = tk ? t('notes.taskChip') + (tk.due ? ` · ${NS.dayText(tk.due.date, S.me.today, t)}` : '') : (n.label || t('notes.taskChip'));
					out.push(el('button', { type: 'button', class: `nm-task${tk && tk.done ? ' is-done' : ''}`, 'data-task': String(n.task), text: label, on: { click: () => openDetail({ uid: `t:${n.task}`, type: 'task', id: n.task }) } }));
				}
			}
			return out;
		}

		function renderMarkdown(md, ctx) {
			const body = el('div', { class: 'nz-md' });
			for (const b of MD.parse(md)) {
				if (b.t === 'p') {
					const p = el('p');
					b.lines.forEach((l, i) => { if (i) p.appendChild(el('br')); for (const n of inlineNodes(l, ctx)) p.appendChild(n); });
					body.appendChild(p);
				} else if (b.t === 'h') body.appendChild(el(`h${b.level}`, null, inlineNodes(b.c, ctx)));
				else if (b.t === 'hr') body.appendChild(el('hr'));
				else if (b.t === 'code') body.appendChild(el('pre', null, [el('code', { text: b.text })]));
				else if (b.t === 'quote') {
					const q = el('blockquote');
					b.lines.forEach((l, i) => { if (i) q.appendChild(el('br')); for (const n of inlineNodes(l, ctx)) q.appendChild(n); });
					body.appendChild(q);
				} else if (b.t === 'table') {
					body.appendChild(el('div', { class: 'nm-table' }, [el('table', null, [
						el('thead', null, [el('tr', null, b.head.map((c) => el('th', null, inlineNodes(c, ctx))))]),
						el('tbody', null, b.rows.map((r) => el('tr', null, r.map((c) => el('td', null, inlineNodes(c, ctx)))))),
					])]));
				} else if (b.t === 'list') {
					const list = el(b.ordered ? 'ol' : 'ul', { class: b.check ? 'nm-checks' : null });
					for (const it of b.items) {
						if (!b.check) { list.appendChild(el('li', { class: it.depth ? `nm-d${it.depth}` : null }, inlineNodes(it.c, ctx))); continue; }
						const box = el('input', { type: 'checkbox', class: 'nm-box', 'data-line': String(it.line), checked: it.done, disabled: !ctx.checkable, 'aria-label': it.label });
						box.addEventListener('change', () => ctx.onCheck(it.line, box.checked));
						const hasTask = it.c.some((n) => n.t === 'task');
						list.appendChild(el('li', { class: `nm-check${it.done ? ' is-done' : ''}${it.depth ? ` nm-d${it.depth}` : ''}`, 'data-line': String(it.line) }, [
							box, el('span', { class: 'nm-ct' }, inlineNodes(it.c, ctx)),
							ctx.toTask && !hasTask && !it.done ? el('button', { type: 'button', class: 'nm-totask', text: t('notes.toTask'), on: { click: () => ctx.toTask(it.line) } }) : null,
						]));
					}
					body.appendChild(list);
				}
			}
			return body;
		}

		function noteDetail(n) {
			const box = el('div', { class: 'nz-d nz-note', 'data-note': String(n.id), 'data-color': n.color || null });
			box.appendChild(closeRow());
			const nb = notebookOf(n.notebookId);
			const vaultId = n.encrypted ? n.vaultId : null;
			if (n.encrypted && n.locked) {
				box.appendChild(lockedCard(nb, 'locked'));
				return box;
			}
			box.appendChild(el('div', { class: 'nz-crumb', text: `${n.encrypted ? '🔒 ' : ''}${nb ? NS.notebookName(nb, t) : ''} · ${t('notes.saved')}` }));
			if (S.editing) { box.appendChild(noteEditor(n, vaultId)); return box; }
			box.appendChild(el('h2', { class: 'nz-note-h', text: n.title || t('notes.untitled') }));
			const ctx = {
				atts: new Map((n.attachments || []).map((a) => [a.id, a])), tasks: new Map((n.tasks || []).map((x) => [x.id, x])), vaultId, checkable: !(S.me && S.me.readOnly),
				onCheck: async (line, done) => {
					const r = await api.checkNote(n.id, line, done);
					if (!ok(r)) { fail(r); reloadDetail(); return; }
					S.detailData = { ok: true, note: r.note };
					renderDetail();
					soon();
				},
				toTask: n.encrypted || (S.me && S.me.readOnly) ? null : async (line) => {
					const r = await api.noteToTask(n.id, line, {});
					if (!ok(r)) { fail(r); return; }
					toast(t('notes.taskMade'), 'success');
					reloadDetail();
					soon();
				},
			};
			box.appendChild(renderMarkdown(n.body || '', ctx));
			const rest = (n.attachments || []).filter((a) => !(n.body || '').includes(`(att:${a.id})`));
			if (rest.length) {
				box.appendChild(el('div', { class: 'nz-lb', text: t('notes.attachments') }));
				box.appendChild(attachmentList('note', n.id, rest, vaultId));
			}
			const tools = el('div', { class: 'nz-row-acts' }, [
				btn(t('notes.edit'), () => { S.editing = true; renderDetail(); }, 'btn-sec', 'edit', { 'data-act': 'edit' }),
				ib('pin', n.pinned ? t('notes.unpin') : t('notes.pin'), async () => { const r = await api.updateNote(n.id, { pinned: !n.pinned }); if (!ok(r)) fail(r); else { S.detailData = { ok: true, note: r.note }; renderDetail(); soon(); } }, n.pinned),
				ib('clip', t('notes.addFile'), async () => { const r = await api.attach('note', n.id); if (!ok(r)) { if (r && r.code !== 'cancelled') fail(r); return; } reloadDetail(); soon(); }),
			]);
			box.appendChild(tools);
			const colors = el('div', { class: 'nz-colors', role: 'group', 'aria-label': t('notes.color') });
			for (const c of NS.COLORS) {
				colors.appendChild(el('button', { type: 'button', class: 'nz-color', 'data-color': c, 'aria-label': t(`notes.c.${c}`), title: t(`notes.c.${c}`), 'aria-pressed': (n.color || 'none') === c ? 'true' : 'false',
					on: { click: async () => { const r = await api.updateNote(n.id, { color: c }); if (!ok(r)) fail(r); else { S.detailData = { ok: true, note: r.note }; renderDetail(); soon(); } } } }));
			}
			box.appendChild(colors);
			if (!n.encrypted) {
				const move = el('select', { class: 'inp nz-inp-sm', 'aria-label': t('notes.moveTo') }, ((S.nav && S.nav.notes.notebooks) || []).filter((b) => !b.vault).map((b) => el('option', { value: String(b.id), text: b.name })));
				move.value = String(n.notebookId);
				move.addEventListener('change', async () => { const r = await api.updateNote(n.id, { notebookId: Number(move.value) }); if (!ok(r)) fail(r); else { soon(0); reloadDetail(); } });
				box.appendChild(field(t('notes.moveTo'), move));
			}
			box.appendChild(el('div', { class: 'nz-d-foot' }, [
				el('span', { class: 'hint', text: n.updatedAt ? t('notes.changed', { when: new Date(n.updatedAt).toLocaleString(lang()) }) : '' }),
				btn(t('notes.delete'), async () => { const r = await api.deleteNote(n.id); if (!ok(r)) { fail(r); return; } closeDetail(); soon(0); toast(t('notes.deleted'), 'success'); }, 'btn-danger', 'trash'),
			]));
			return box;
		}

		/** The editor: title, the toolbar (Markdown), the text; saved after a pause, "Fertig" or Strg+S. */
		function noteEditor(n, vaultId) {
			const wrap = el('div', { class: 'nz-editor-wrap' });
			const title = el('input', { class: 'inp nz-ed-title', type: 'text', maxlength: '300', value: n.title || '', placeholder: t('notes.titleField'), 'aria-label': t('notes.titleField') });
			const ta = el('textarea', { class: 'inp nz-editor', spellcheck: 'true', placeholder: t('notes.textPh'), 'aria-label': t('notes.text') });
			ta.value = n.body || '';
			const err = el('p', { class: 'nz-err', role: 'alert' });
			let rev = n.rev;
			let timer = null;
			let dirty = false;
			const apply = (st) => {
				ta.value = st.value;
				ta.focus();
				ta.setSelectionRange(st.start, st.end);
				ta.dispatchEvent(new Event('input'));
			};
			const cur = () => ({ value: ta.value, start: ta.selectionStart, end: ta.selectionEnd });
			const tool = (key, label, fn, content) => el('button', { type: 'button', class: 'nz-tool', 'data-tool': key, title: label, 'aria-label': label, on: { mousedown: (e) => e.preventDefault(), click: fn } }, [content]);
			const txt = (s, cls) => el('span', { class: cls || null, text: s });
			const tools = el('div', { class: 'nz-tools', role: 'toolbar', 'aria-label': t('notes.f.toolbar') }, [
				tool('heading', t('notes.f.heading'), () => apply(MD.prefix(cur(), '## ')), txt('H', 'nz-tool-h')),
				tool('bold', t('notes.f.bold'), () => apply(MD.wrap(cur(), '**', '**', t('notes.f.bold'))), txt('B', 'nz-tool-b')),
				tool('italic', t('notes.f.italic'), () => apply(MD.wrap(cur(), '*', '*', t('notes.f.italic'))), txt('I', 'nz-tool-i')),
				tool('strike', t('notes.f.strike'), () => apply(MD.wrap(cur(), '~~', '~~', t('notes.f.strike'))), txt('S', 'nz-tool-s')),
				tool('list', t('notes.f.list'), () => apply(MD.prefix(cur(), '- ')), icon('list', 16)),
				tool('numbered', t('notes.f.numbered'), () => apply(MD.prefix(cur(), '1. ')), txt('1.')),
				tool('check', t('notes.f.check'), () => apply(MD.prefix(cur(), '- [ ] ')), icon('check', 16)),
				tool('table', t('notes.f.table'), () => apply(MD.insert(cur(), MD.tableText(t('notes.f.col')))), icon('table', 16)),
				tool('link', t('notes.f.link'), () => apply(MD.wrap(cur(), '[', '](https://)', t('notes.f.linkText'))), icon('link', 16)),
				tool('image', t('notes.f.image'), async () => {
					const pos = cur();
					const r = await api.attach('note', n.id);
					if (!ok(r)) { if (r && r.code !== 'cancelled') fail(r); return; }
					for (const x of r.rejected || []) toast(`${x.name}: ${NS.errText({ code: x.code }, t)}`, 'error');
					let st = { value: ta.value, start: pos.start, end: pos.end };
					for (const a of r.attachments) st = MD.insert(st, MD.attachmentText(a.id, a.name, /^image\//.test(a.mime || '')));
					if (r.attachments.length) apply(st);
				}, icon('image', 16)),
			]);
			const save = async (close) => {
				clearTimeout(timer);
				const patch = { title: title.value, body: ta.value };
				if (!n.encrypted) patch.rev = rev;
				const r = await api.updateNote(n.id, patch);
				if (!ok(r)) { err.textContent = r && r.code === 'conflict' ? t('notes.err.noteConflict') : NS.errText(r, t); return false; }
				rev = r.note.rev;
				dirty = false;
				err.textContent = '';
				if (close) { S.editing = false; S.detailData = { ok: true, note: r.note }; renderDetail(); }
				soon();
				return true;
			};
			const later = () => { dirty = true; clearTimeout(timer); timer = setTimeout(() => save(false), 2500); };
			ta.addEventListener('input', later);
			title.addEventListener('input', later);
			const keys = (e) => { if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S')) { e.preventDefault(); save(true); } };
			ta.addEventListener('keydown', keys);
			title.addEventListener('keydown', keys);
			wrap.append(title, tools, ta, el('p', { class: 'hint', text: t('notes.mdHint') }), err,
				el('div', { class: 'dlg-actions' }, [
					btn(t('notes.cancel'), async () => { clearTimeout(timer); if (dirty) await save(false); S.editing = false; reloadDetail(); }, 'btn-ghost'),
					btn(t('notes.done'), () => save(true), 'btn-pri', 'check', { 'data-act': 'done' }),
				]));
			setTimeout(() => (n.title ? ta : title).focus(), 0);
			return wrap;
		}

		// ── notes in the middle ──────────────────────────────
		function noteCard(n) {
			const nb = notebookOf(n.notebookId);
			const meta = [];
			for (const g of (n.tags || []).slice(0, 3)) meta.push(`#${g}`);
			if (nb && S.view.kind === 'notes' && !S.view.notebook) meta.push(nb.vault ? t('notes.vault.name') : nb.name);
			if (n.check) meta.push(`${n.check.done}/${n.check.total}`);
			if (n.images) meta.push(t('notes.imagesN', { n: n.images }));
			if (n.updatedAt && S.me) meta.push(NS.dayText(NS.isoDay(n.updatedAt), S.me.today, t));
			const openNow = S.detail && S.detail.type === 'note' && S.detail.id === n.id;
			const card = el('button', { type: 'button', class: `nz-nc${openNow ? ' on' : ''}${n.encrypted && n.locked ? ' is-locked' : ''}`, 'data-id': String(n.id), 'data-color': n.color || null, on: { click: () => openNote(n.id) } }, [
				el('b', { class: 'nz-nc-t' }, [n.encrypted ? icon('lock', 13) : null, el('span', { text: NS.noteTitle(n, t) })]),
				n.snippet ? el('span', { class: 'nz-nc-s', text: n.snippet }) : null,
				el('span', { class: 'nz-nc-m', text: meta.join(' · ') }),
			]);
			if (n.hit) {
				const s = el('span', { class: 'nz-nc-s' });
				String(n.hit).split('\u0002').forEach((part, i) => {
					if (i === 0) { s.appendChild(document.createTextNode(part)); return; }
					const p = part.split('\u0003');
					s.appendChild(el('mark', { text: p[0] }));
					s.appendChild(document.createTextNode(p.slice(1).join('')));
				});
				const old = card.querySelector('.nz-nc-s');
				if (old) old.replaceWith(s); else card.insertBefore(s, card.lastChild);
			}
			return card;
		}

		async function newNote(nb) {
			const r = await api.createNote(nb ? { notebookId: nb.id, title: '', body: '' } : { area: S.area, title: '', body: '' });
			if (!ok(r)) { fail(r); return; }
			soon(0);
			openNote(r.note.id, true);
		}

		function renderNotes(m) {
			const d = S.data || {};
			const v = S.view;
			const nb = v.notebook ? notebookOf(v.notebook) : null;
			const title = v.tag ? `#${v.tag}` : nb ? NS.notebookName(nb, t) : t('notes.allNotes');
			const extra = [btn(t('notes.newNote'), () => newNote(nb), 'btn-pri', 'plus', { id: 'nz-new-note', disabled: !!(nb && nb.vault && d.locked) })];
			if (nb && nb.vault && !d.locked) {
				extra.push(ib('devices', t('notes.vault.devices'), () => devicesDialog(nb)));
				extra.push(ib('gear', t('notes.vault.lockSettings'), lockSettings));
				extra.push(ib('lock', t('notes.vault.lockNow'), async () => { await api.vaultLock(); }, false, { 'data-act': 'vault-lock' }));
			}
			if (nb && !nb.vault && !nb.isDefault && !nb.bound) extra.push(ib('gear', t('notes.nbSettings'), () => notebookSettings(nb)));
			const sub = nb && nb.bound ? t('notes.boundHint', { plugin: nb.bound.label }) : nb && nb.shared ? t('notes.sharedWith', { names: nb.members.map((x) => x.name).join(', ') }) : nb && nb.vault ? t('notes.vault.e2e') : null;
			m.appendChild(header(title, sub, extra));
			if (!S.data) { m.appendChild(el('p', { class: 'nz-muted', text: t('notes.loading') })); return; }
			if (d.error) { m.appendChild(el('div', { class: 'note note-err', text: NS.errText(d.error, t) })); return; }
			if (d.locked) { m.appendChild(lockedCard(nb, d.locked)); return; }
			if (nb && nb.vault && d.vault) {
				if (d.vault.pending > 0) m.appendChild(el('div', { class: 'banner banner-info nz-banner' }, [icon('devices', 16), el('span', { class: 'grow', text: t('notes.vault.requests', { n: d.vault.pending }) }), btn(t('notes.vault.review'), () => devicesDialog(nb), 'btn-sec')]));
				if (d.vault.needsRotation) m.appendChild(el('div', { class: 'banner banner-warn nz-banner' }, [icon('key', 16), el('span', { class: 'grow', text: t('notes.vault.rotate') }), btn(t('notes.vault.rotateNow'), () => rotate(nb), 'btn-sec')]));
			}
			if (!nb && !v.tag) {
				const chips = el('div', { class: 'nz-nbchips' });
				for (const b of (S.nav && S.nav.notes.notebooks) || []) chips.appendChild(el('button', { type: 'button', class: 'chip nz-nbchip', on: { click: () => go({ kind: 'notes', notebook: b.id }) } }, [b.vault ? icon('lock', 12) : null, el('span', { text: NS.notebookName(b, t) })]));
				m.appendChild(chips);
			}
			if ((d.pinned || []).length) {
				m.appendChild(el('div', { class: 'nz-lab', text: t('notes.pinned') }));
				m.appendChild(el('div', { class: 'nz-notes' }, d.pinned.map(noteCard)));
			}
			const list = d.notes || [];
			m.appendChild(el('div', { class: 'nz-lab', text: t('notes.recent') }));
			if (!list.length && !(d.pinned || []).length) m.appendChild(el('div', { class: 'card nz-card nz-empty', text: t('notes.noNotes') }));
			else m.appendChild(el('div', { class: 'nz-notes' }, list.map(noteCard)));
			if (d.next) {
				m.appendChild(btn(t('notes.moreNotes'), async () => {
					const r = await api.notes({ area: S.area, notebook: v.notebook || null, tag: v.tag || null, before: d.next, limit: 60 });
					if (!ok(r)) { fail(r); return; }
					d.notes = d.notes.concat(r.notes.filter((x) => !x.pinned || (nb && nb.vault)));
					d.next = r.next;
					renderMain();
				}, 'btn-ghost'));
			}
		}

		function renderSearch(m) {
			const d = S.data || {};
			m.appendChild(header(t('notes.searchFor', { q: S.view.q }), null, []));
			if (!S.data) { m.appendChild(el('p', { class: 'nz-muted', text: t('notes.loading') })); return; }
			if (d.error) { m.appendChild(el('div', { class: 'note note-err', text: NS.errText(d.error, t) })); return; }
			const items = [...(d.tasks || []), ...(d.items || [])];
			if (items.length) m.appendChild(sectionCard({ id: 'tasks', title: t('notes.tasks'), items, count: items.length }, 'search'));
			if ((d.notes || []).length) {
				m.appendChild(el('div', { class: 'nz-lab', text: t('notes.notes') }));
				m.appendChild(el('div', { class: 'nz-notes' }, d.notes.map(noteCard)));
			}
			if (!items.length && !(d.notes || []).length) m.appendChild(el('div', { class: 'card nz-card nz-empty', text: t('notes.nothingFound') }));
		}

		// ── lists and notebooks ──────────────────────────────
		function newList() {
			let kind = 'list';
			const seg = el('div', { class: 'seg' });
			for (const k of ['list', 'group']) {
				const b = el('button', { type: 'button', class: k === kind ? 'on' : '', text: t(`notes.kind.${k}`), on: { click: () => { kind = k; for (const c of seg.children) c.classList.toggle('on', c === b); } } });
				seg.appendChild(b);
			}
			prompt(t('notes.newList'), '', async (name) => {
				if (kind === 'group') { const r = await api.createGroup({ name, area: S.area }); if (ok(r)) reloadNav(); return r; }
				const r = await api.createList({ name, area: S.area });
				if (ok(r)) { reloadNav(); go({ kind: 'list', id: r.list.id }); }
				return r;
			}, [seg]);
		}

		function sharePicker(current) {
			const chosen = new Set((current || []).map((m) => m.id));
			const box = el('div', { class: 'nz-share' });
			for (const p of S.people.filter((x) => !x.me)) {
				const cb = el('input', { type: 'checkbox', checked: chosen.has(p.id) });
				cb.addEventListener('change', () => { if (cb.checked) chosen.add(p.id); else chosen.delete(p.id); });
				box.appendChild(el('label', { class: 'nz-check' }, [cb, el('span', { text: p.name })]));
			}
			if (!box.childNodes.length) box.appendChild(el('p', { class: 'hint', text: S.me && S.me.sharing === 'off' ? t('notes.sharingOff') : t('notes.nobodyToShare') }));
			return { box, value: () => [...chosen] };
		}

		function colorPicker(current) {
			let color = current || 'none';
			const box = el('div', { class: 'nz-colors', role: 'group', 'aria-label': t('notes.color') });
			for (const c of NS.COLORS) {
				const b = el('button', { type: 'button', class: 'nz-color', 'data-color': c, 'aria-label': t(`notes.c.${c}`), 'aria-pressed': color === c ? 'true' : 'false', on: { click: () => { color = c; for (const x of box.children) x.setAttribute('aria-pressed', x === b ? 'true' : 'false'); } } });
				box.appendChild(b);
			}
			return { box, value: () => color };
		}

		function listSettings(l) {
			const owner = l.role === 'owner';
			const share = sharePicker(l.members);
			const color = colorPicker(l.color);
			const groups = el('select', { class: 'inp', 'aria-label': t('notes.group') }, [el('option', { value: '', text: t('notes.noGroup') }), ...((S.nav && S.nav.groups) || []).map((g) => el('option', { value: String(g.id), text: g.name }))]);
			groups.value = l.groupId ? String(l.groupId) : '';
			const extra = [field(t('notes.group'), groups)];
			// plugin 1.6.0: who belongs to the family's list is decided by the Familie plugin — no sharing, leaving or deleting here
			const fam = isFamily(l);
			if (owner) extra.push(field(t('notes.color'), color.box));
			if (owner && !fam) extra.push(field(t('notes.shareWith'), share.box));
			if (fam) extra.push(el('p', { class: 'hint', 'data-hint': 'family-list', text: t('notes.err.family_list') }));
			const d = prompt(t('notes.listSettings'), l.name, async (name) => {
				const body = { groupId: groups.value ? Number(groups.value) : null };
				if (owner) { if (!l.isDefault || name !== l.name) body.name = name; body.color = color.value(); }
				let r = await api.updateList(l.id, body);
				if (ok(r) && owner && !fam) r = await api.listMembers(l.id, share.value());
				if (ok(r)) { reloadNav(); reloadView(); }
				return r;
			}, [...extra, fam ? null : el('div', { class: 'nz-row-acts' }, [btn(owner ? t('notes.deleteList') : t('notes.leaveList'), async () => {
				if (l.isDefault) { toast(t('notes.err.default'), 'error'); return; }
				const r = await api.deleteList(l.id);
				if (!ok(r)) { fail(r); return; }
				d.close();
				go({ kind: 'smart', id: 'myday' });
				reloadNav();
			}, 'btn-danger', 'trash')])]);
		}

		function newNotebook() {
			let vault = false;
			const hint = el('p', { class: 'hint' });
			const seg = el('div', { class: 'seg', role: 'group' });
			const canVault = has('vault') && S.me && S.me.vaults && S.vaultSupported;
			for (const k of ['plain', 'vault']) {
				const b = el('button', { type: 'button', class: k === 'plain' ? 'on' : '', 'data-kind': k, text: t(`notes.nb.${k}`), disabled: k === 'vault' && !canVault, on: { click: () => {
					vault = k === 'vault';
					hint.textContent = vault ? t('notes.vault.hint') : '';
					for (const c of seg.children) c.classList.toggle('on', c === b);
				} } });
				seg.appendChild(b);
			}
			if (!canVault) hint.textContent = !S.vaultSupported ? t('notes.vault.unsupported') : t('notes.err.vaults_off');
			prompt(t('notes.newNotebook'), '', async (name) => {
				const r = await api.createNotebook({ name, area: S.area, vault });
				if (!ok(r)) return r;
				if (r.recoveryKey) setTimeout(() => showRecovery(r.recoveryKey, name), 0);
				await reloadNav();
				go({ kind: 'notes', notebook: r.notebook.id });
				return r;
			}, [seg, hint]);
		}

		function notebookSettings(nb) {
			const owner = nb.role === 'owner';
			const share = sharePicker(nb.members);
			const extra = owner ? [field(t('notes.shareWith'), share.box)] : [];
			const d = prompt(t('notes.nbSettings'), nb.name, async (name) => {
				let r = owner ? await api.updateNotebook(nb.id, { name }) : { ok: true };
				if (ok(r) && owner) r = await api.notebookMembers(nb.id, share.value());
				if (ok(r)) { reloadNav(); reloadView(); }
				return r;
			}, [...extra, el('div', { class: 'nz-row-acts' }, [btn(owner ? t('notes.deleteNotebook') : t('notes.leaveNotebook'), async () => {
				const r = await api.deleteNotebook(nb.id);
				if (!ok(r)) { fail(r); return; }
				d.close();
				go({ kind: 'notes' });
				reloadNav();
			}, 'btn-danger', 'trash')])]);
		}

		// ── Tresor notebooks ─────────────────────────────────
		function lockedCard(nb, state) {
			const L = NS.vaultLocked(state, t);
			const card = el('div', { class: 'card nz-card nz-locked', 'data-state': state }, [icon('lock', 34), el('b', { text: t('notes.vault.locked') }), el('p', { class: 'nz-p', text: L.text })]);
			const acts = el('div', { class: 'nz-row-acts nz-center' });
			const vid = nb && nb.vault && nb.vault.id;
			if (L.actions.includes('unlock')) {
				acts.appendChild(btn(t('notes.vault.unlock'), async () => {
					const r = await api.vaultUnlock(vid);
					if (!ok(r)) { fail(r); return; }
					await reloadNav();
					reloadView();
					if (S.detail) reloadDetail();
				}, 'btn-pri', 'unlock', { 'data-act': 'vault-unlock' }));
			}
			if (L.actions.includes('ask')) {
				acts.appendChild(btn(t('notes.vault.ask'), async () => {
					const r = await api.vaultRequest(vid);
					if (!ok(r)) { fail(r); return; }
					const d = dialog(t('notes.vault.asked'), [el('p', { class: 'nz-p', text: t('notes.vault.askedText') }), el('p', { class: 'nz-safety mono', text: r.safetyNumber })], [btn(t('notes.close'), () => { d.close(); reloadView(); }, 'btn-pri')]);
				}, 'btn-pri'));
			}
			if (L.actions.includes('recover') && vid) acts.appendChild(btn(t('notes.vault.recover'), () => recover(nb), 'btn-sec', 'key'));
			card.appendChild(acts);
			return card;
		}

		function recover(nb) {
			const input = el('textarea', { class: 'inp nz-rec-inp mono', rows: '3', spellcheck: 'false', autocomplete: 'off', 'aria-label': t('notes.vault.recoveryKey') });
			const err = el('p', { class: 'nz-err', role: 'alert' });
			const d = dialog(t('notes.vault.recover'), [el('p', { class: 'nz-p', text: t('notes.vault.recoverText') }), input, err], [
				btn(t('notes.cancel'), () => d.close(), 'btn-ghost'),
				btn(t('notes.vault.unlock'), async () => {
					const r = await api.vaultRecover(nb.vault.id, input.value);
					if (!ok(r)) { err.textContent = r.code === 'recovery_key' ? t('notes.vault.recoveryWrong') : NS.errText(r, t); return; }
					d.close();
					toast(t('notes.vault.recovered'), 'success');
					await reloadNav();
					reloadView();
				}, 'btn-pri'),
			]);
		}

		async function devicesDialog(nb) {
			const r = await api.vaultDevices(nb.vault.id);
			if (!ok(r)) { fail(r); return; }
			const list = el('div', { class: 'nz-devs' });
			const pending = r.devices.filter((x) => x.state === 'pending');
			const who = (id) => (S.people.find((p) => p.id === id) || {}).name || '';
			for (const dv of r.devices.filter((x) => x.state !== 'revoked')) {
				const row = el('div', { class: 'card nz-dev', 'data-device': dv.deviceId }, [
					el('div', { class: 'nz-dev-tx' }, [el('b', { text: [who(dv.userId), dv.name].filter(Boolean).join(' · ') || dv.deviceId }), el('span', { class: 'hint', text: dv.mine ? t('notes.vault.thisPc') : t(`notes.vault.dev.${dv.state}`) })]),
					dv.state === 'pending' ? el('p', { class: 'nz-safety mono', text: dv.safetyNumber || '' }) : null,
				]);
				if (dv.state === 'pending') {
					row.appendChild(el('div', { class: 'nz-row-acts' }, [
						btn(t('notes.vault.decline'), async () => { const x = await api.vaultDecline(nb.vault.id, dv.deviceId); if (!ok(x)) fail(x); else row.remove(); }, 'btn-danger'),
						btn(t('notes.vault.approve'), async () => { const x = await api.vaultApprove(nb.vault.id, dv.deviceId, dv.safetyNumber); if (!ok(x)) fail(x); else { toast(t('notes.vault.approved'), 'success'); row.remove(); soon(); } }, 'btn-pri'),
					]));
				}
				list.appendChild(row);
			}
			dialog(t('notes.vault.devices'), [el('p', { class: 'nz-p', text: pending.length ? t('notes.vault.reviewText') : t('notes.vault.devicesText') }), list], [], { wide: true });
		}

		async function rotate(nb) {
			const r = await api.vaultRotate(nb.vault.id);
			if (!ok(r)) { fail(r); return; }
			toast(t('notes.vault.rotated'), 'success');
			if (r.recoveryKey) await showRecovery(r.recoveryKey, NS.notebookName(nb, t));
			reloadNav();
			reloadView();
		}

		async function lockSettings() {
			const r = await api.vaultStatus();
			if (!ok(r)) { fail(r); return; }
			const s = r.lock.settings;
			const mins = el('select', { class: 'inp', 'aria-label': t('notes.vault.autoLock') }, r.lock.choices.map((m) => el('option', { value: String(m), text: m ? t('notes.vault.minutes', { n: m }) : t('notes.vault.never') })));
			mins.value = String(s.autoLockMinutes);
			mins.addEventListener('change', async () => { const x = await api.vaultSettings({ autoLockMinutes: Number(mins.value) }); if (!ok(x)) fail(x); });
			const body = [
				el('p', { class: 'nz-p', text: t('notes.vault.lockText') }),
				field(t('notes.vault.autoLock'), mins),
				field(t('notes.vault.lockOnLeave'), sw(s.lockOnLeave, async (v) => { const x = await api.vaultSettings({ lockOnLeave: v }); if (!ok(x)) fail(x); }, t('notes.vault.lockOnLeave'))),
				field(t('notes.vault.hello'), sw(s.hello, async (v) => { const x = await api.vaultSettings({ hello: v }); if (!ok(x)) { fail(x); lockSettings(); } }, t('notes.vault.hello')), r.lock.hello.available ? null : t('notes.vault.helloMissing')),
			];
			if (r.device) body.push(el('p', { class: 'hint', text: t('notes.vault.safetyThis', { n: r.device.safetyNumber }) }));
			const d = dialog(t('notes.vault.lockSettings'), body, [btn(t('notes.close'), () => d.close(), 'btn-pri')]);
		}

		// ── "Quellen" ────────────────────────────────────────
		function renderSources(m) {
			m.appendChild(header(t('notes.sources'), null, []));
			m.appendChild(el('p', { class: 'nz-p', text: t('notes.sourcesIntro') }));
			const d = S.data;
			if (!d) { m.appendChild(el('p', { class: 'nz-muted', text: t('notes.loading') })); return; }
			if (d.error) { m.appendChild(el('div', { class: 'note note-err', text: NS.errText(d.error, t) })); return; }
			const prefs = (S.me && S.me.prefs) || { sources: {}, groups: {} };
			const save = async (body) => { const r = await api.setPrefs(body); if (!ok(r)) { fail(r); return; } S.me.prefs = r.prefs; reloadNav(); };
			const wrap = el('div', { class: 'nz-set' });
			for (const s of d.sources) {
				const sp = prefs.sources[s.plugin] || {};
				const card = el('div', { class: 'card nz-card nz-srccard', 'data-plugin': s.plugin });
				card.appendChild(el('div', { class: 'nz-set-h' }, [
					el('span', { class: 'nz-badge', 'data-tone': NS.SOURCE_TONE[s.plugin] || 'neutral', text: s.label.slice(0, 2) }),
					el('div', { class: 'grow' }, [el('b', { text: s.label }), el('span', { class: 'hint nz-block', text: !s.enabled ? t('notes.srcOffAdmin') : !s.available ? t('notes.srcMissing') : s.hint || '' })]),
					sw(sp.on !== false && s.enabled, (v) => save({ sources: { [s.plugin]: { on: v } } }), s.label, !s.enabled || !s.available),
				]));
				if (s.plugin === 'gatecontrol-familie') {
					const kids = el('select', { class: 'inp nz-inp-sm', 'aria-label': t('notes.srcKids') }, ['all', 'mine', 'none'].map((k) => el('option', { value: k, text: t(`notes.kids.${k}`) })));
					kids.value = sp.kids || 'all';
					kids.addEventListener('change', () => save({ sources: { [s.plugin]: { kids: kids.value } } }));
					card.appendChild(field(t('notes.srcKids'), kids));
					card.appendChild(field(t('notes.srcShopping'), sw(sp.shoppingInMyDay === true, (v) => save({ sources: { [s.plugin]: { shoppingInMyDay: v } } }), t('notes.srcShopping'))));
				}
				if (s.plugin === 'gatecontrol-mail') card.appendChild(field(t('notes.srcFlagged'), sw(sp.flagged !== false, (v) => save({ sources: { [s.plugin]: { flagged: v } } }), t('notes.srcFlagged'))));
				if (s.plugin === 'gatecontrol-alltag') {
					const ev = el('input', { class: 'inp nz-inp-sm', type: 'time', value: sp.evening || prefs.evening || '18:00', 'aria-label': t('notes.srcEvening') });
					ev.addEventListener('change', () => { if (ev.value) save({ sources: { [s.plugin]: { evening: ev.value } } }); });
					card.appendChild(field(t('notes.srcEvening'), ev));
				}
				for (const g of s.groups) {
					const key = NS.groupKey(s.plugin, g.id);
					const sel = el('select', { class: 'inp nz-inp-sm', 'aria-label': g.label }, ['private', 'work', 'hide'].map((k) => el('option', { value: k, text: t(`notes.groupTo.${k}`) })));
					sel.value = prefs.groups[key] || 'private';
					sel.addEventListener('change', () => save({ groups: { [key]: sel.value } }));
					card.appendChild(field(g.label, sel));
				}
				card.appendChild(el('div', { class: 'nz-row-acts' }, [
					el('span', { class: 'hint grow', text: s.lastSync ? t('notes.lastSync', { when: new Date(s.lastSync).toLocaleString(lang()) }) : '' }),
					btn(t('notes.syncNow'), async () => { const r = await api.syncSource(s.plugin); if (!ok(r)) fail(r); else toast(r.scheduled ? t('notes.syncScheduled') : t('notes.syncRecent')); }, 'btn-ghost', 'refresh'),
				]));
				wrap.appendChild(card);
			}
			const evening = el('input', { class: 'inp nz-inp-sm', type: 'time', value: prefs.evening || '18:00', 'aria-label': t('notes.remindAt') });
			evening.addEventListener('change', () => { if (evening.value) save({ evening: evening.value }); });
			wrap.appendChild(el('div', { class: 'card nz-card' }, [field(t('notes.remindAt'), evening, t('notes.remindAtHint'))]));
			wrap.appendChild(el('div', { class: 'card nz-card nz-soon' }, [el('b', { text: t('notes.srcLater') }), el('span', { class: 'hint', text: t('notes.srcLaterHint') })]));
			// plugin 1.6.0: the message to a parent when a child ticks a task of the family's list off
			const fam = NS.familyInfo(S.me);
			if (NS.offers(S.me, 'doneFeedback') && fam.bound && fam.parent) {
				const fb = el('select', { class: 'inp nz-inp-sm', 'aria-label': t('notes.turn.feedback'), 'data-act': 'feedback' }, ['all', 'stars', 'off'].map((k) => el('option', { value: k, text: t(`notes.turn.feedback_${k}`) })));
				fb.value = prefs.feedback || 'all';
				fb.addEventListener('change', () => save({ feedback: fb.value }));
				wrap.appendChild(el('h2', { class: 'nz-set-title', 'data-set': 'family', text: t('notes.turn.setTitle') }));
				wrap.appendChild(el('div', { class: 'card nz-card', 'data-card': 'feedback' }, [field(t('notes.turn.feedback'), fb, t('notes.turn.feedbackHint'))]));
			}
			// plugin 1.9.0: „Termine aus dem Kalender“ — which calendars show on „Mein Tag“ and „Geplant“ (Bild 8)
			if (eventsOn() && S.cals && S.cals.calendars.length) {
				const card = el('div', { class: 'card nz-card nz-srccard', 'data-card': 'calendars' });
				card.appendChild(el('div', { class: 'nz-set-h' }, [el('span', { class: 'nz-evcal' }, [icon('cal', 18)]), el('div', { class: 'grow' }, [el('b', { text: t('notes.ev.cal.title') }), el('span', { class: 'hint nz-block', text: t('notes.ev.cal.hint') })])]));
				for (const c of S.cals.calendars) {
					const name = el('span', { class: 'nz-evcal-name' }, [el('span', { class: 'nz-evcal' }, [icon('cal', 14)]), el('span', { text: c.name })]);
					if (c.color) name.firstChild.style.color = c.color;
					card.appendChild(el('div', { class: 'nz-f nz-evcal-row', 'data-cal': c.key }, [el('span', { class: 'nz-f-l' }, [name, el('span', { class: 'hint nz-block', text: NS.calendarSub(c, t) })]),
						sw(c.shown, async (v) => { await save({ groups: NS.calendarChoice(c, v) }); await loadCals(true); }, c.name)]));
				}
				card.appendChild(el('p', { class: 'hint', text: t('notes.ev.cal.tasksHint') }));
				wrap.appendChild(card);
			}
			// plugin 1.5.0: the person's switches of places and „Meine Orte“
			if (placesOn() && S.me.places) placesSettings(wrap, save);
			m.appendChild(wrap);
		}

		// ── "Umziehen" ───────────────────────────────────────
		function renderImport(m) {
			m.appendChild(header(t('notes.import.title'), null, []));
			m.appendChild(el('p', { class: 'nz-p', text: t('notes.import.intro') }));
			const wrap = el('div', { class: 'nz-set' });
			if (S.me.imports.mstodo && has('mstodo')) wrap.appendChild(mstodoCard());
			if (S.me.imports.dsnote && has('dsnote')) wrap.appendChild(dsnoteCard());
			m.appendChild(wrap);
		}

		function stats(list) {
			return el('div', { class: 'nz-stats' }, list.map(([n, label]) => el('div', { class: 'nz-stat' }, [el('b', { text: String(n) }), el('span', { text: label })])));
		}

		function mstodoCard() {
			const card = el('div', { class: 'card nz-card', 'data-import': 'mstodo' }, [el('div', { class: 'nz-set-h' }, [el('span', { class: 'nz-badge', 'data-tone': 'info', text: 'To Do' }),
				el('div', { class: 'grow' }, [el('b', { text: 'Microsoft To Do' }), el('span', { class: 'hint nz-block', text: t('notes.import.msHint') })])])]);
			const body = el('div', { class: 'nz-imp-body' }, [el('p', { class: 'nz-muted', text: t('notes.loading') })]);
			card.appendChild(body);
			(async () => {
				const r = await api.msAccounts();
				clear(body);
				if (!ok(r)) { body.appendChild(el('p', { class: 'nz-err', text: NS.errText(r, t) })); return; }
				if (!r.available) { body.appendChild(el('p', { class: 'hint', text: t(r.reason === 'mail_missing' ? 'notes.import.noMail' : r.reason === 'off' ? 'notes.import.msOff' : 'notes.import.msUnavailable') })); return; }
				if (!r.accounts.length) { body.appendChild(el('p', { class: 'hint', text: t('notes.import.noAccount') })); return; }
				const acc = el('select', { class: 'inp', 'aria-label': t('notes.import.account') }, r.accounts.map((a) => el('option', { value: String(a.id), text: a.email })));
				body.appendChild(field(t('notes.import.account'), acc));
				const area = el('div');
				body.appendChild(area);
				const step = async () => {
					clear(area);
					const a = r.accounts.find((x) => String(x.id) === acc.value);
					if (!a.tasks) {
						area.appendChild(el('p', { class: 'hint', text: t('notes.import.consentHint') }));
						area.appendChild(btn(t('notes.import.consent'), () => consent(a, step), 'btn-pri', null, { 'data-act': 'consent' }));
						return;
					}
					area.appendChild(el('p', { class: 'nz-muted', text: t('notes.loading') }));
					const pv = await api.msPreview(a.id);
					clear(area);
					if (!ok(pv)) {
						if (pv.code === 'consent_required') { a.tasks = false; step(); return; }
						area.appendChild(el('p', { class: 'nz-err', text: NS.errText(pv, t) }));
						return;
					}
					msPreview(area, a, pv);
				};
				acc.addEventListener('change', step);
				step();
				const l = await api.msLinks();
				if (ok(l) && l.links.some((x) => x.twoWay)) {
					card.appendChild(el('div', { class: 'nz-lb', text: t('notes.import.links') }));
					for (const x of l.links.filter((y) => y.twoWay)) {
						card.appendChild(el('div', { class: 'nz-f' }, [el('span', { class: 'nz-f-l', text: x.listName + (x.error ? ` · ${t('notes.import.syncError')}` : '') }),
							btn(t('notes.import.unlink'), async () => { const u = await api.msUnlink(x.id); if (!ok(u)) fail(u); else { toast(t('notes.import.unlinked'), 'success'); renderMain(); } }, 'btn-ghost')]));
					}
				}
			})();
			return card;
		}

		/** Microsoft's device code: the code is shown, Microsoft's page opens in the browser, then a poll until it is done. */
		async function consent(a, after) {
			const r = await api.msConsent(a.id);
			if (!ok(r)) { fail(r); return; }
			let stop = false;
			const status = el('p', { class: 'hint', text: t('notes.import.waiting') });
			const d = dialog(t('notes.import.consent'), [
				el('p', { class: 'nz-p', text: t('notes.import.codeText') }),
				el('p', { class: 'nz-safety mono', 'data-code': 'true', text: r.userCode }),
				el('div', { class: 'nz-row-acts' }, [
					btn(t('notes.import.copyCode'), () => { navigator.clipboard.writeText(r.userCode).then(() => toast(t('notes.vault.copied'), 'success'), () => {}); }, 'btn-sec'),
					btn(t('notes.import.openMs'), async () => { const x = await api.msOpen(r.verificationUri); if (!ok(x)) fail(x); }, 'btn-pri', 'open'),
				]),
				status,
			], [btn(t('notes.cancel'), () => { stop = true; d.close(); }, 'btn-ghost')], { onClose: () => { stop = true; } });
			const poll = async () => {
				if (stop) return;
				const p = await api.msPoll(a.id, r.deviceId);
				if (stop) return;
				if (!ok(p)) { d.close(); fail(p); return; }
				if (p.status === 'done') { stop = true; d.close(); a.tasks = true; toast(t('notes.import.consented'), 'success'); after(); return; }
				if (p.status === 'pending') { setTimeout(poll, Math.max(1, r.interval) * 1000); return; }
				d.close();
				toast(t('notes.import.consentFailed'), 'error');
			};
			setTimeout(poll, Math.max(1, r.interval) * 1000);
		}

		function msPreview(area, a, pv) {
			area.appendChild(stats([[pv.totals.lists, t('notes.import.lists')], [pv.totals.open, t('notes.import.openTasks')], [pv.totals.attachments, t('notes.import.withAttachment')]]));
			const rows = [];
			const tl = el('div', { class: 'nz-imp-lists' });
			for (const l of pv.lists) {
				const inc = el('input', { type: 'checkbox', checked: l.include, 'aria-label': l.name });
				const ar = el('select', { class: 'inp nz-inp-sm', 'aria-label': t('notes.areaLabel') }, ['private', 'work'].map((k) => el('option', { value: k, text: t(`notes.area.${k}`) })));
				ar.value = l.area;
				rows.push({ l, inc, ar });
				tl.appendChild(el('label', { class: 'nz-imp-row' }, [inc, el('span', { class: 'grow', text: `${l.name} (${l.open})` }), ar]));
			}
			area.appendChild(tl);
			const done = el('select', { class: 'inp nz-inp-sm', 'aria-label': t('notes.import.takeDone') }, [[0, 'none'], [30, 'd30'], [90, 'd90'], [365, 'd365'], [-1, 'all']].map(([v, k]) => el('option', { value: String(v), text: t(`notes.import.done.${k}`) })));
			done.value = '90';
			area.appendChild(field(t('notes.import.takeDone'), done));
			let twoWay = false;
			area.appendChild(field(t('notes.import.twoWay'), sw(false, (v) => { twoWay = v; }, t('notes.import.twoWay'), !S.me.imports.mstodoSync), t('notes.import.twoWayHint')));
			const bar = el('div', { class: 'nz-bar', hidden: true }, [el('i')]);
			const status = el('p', { class: 'hint' });
			const start = btn(t('notes.import.takeN', { n: pv.totals.open }), async () => {
				start.disabled = true;
				const r = await api.msStart({ accountId: a.id, lists: rows.map((x) => ({ id: x.l.id, name: x.l.name, area: x.ar.value, include: x.inc.checked })), doneDays: Number(done.value), twoWay });
				if (!ok(r)) { start.disabled = false; fail(r); return; }
				bar.hidden = false;
				const total = rows.filter((x) => x.inc.checked).reduce((n, x) => n + x.l.open, 0) || 1;
				const poll = async () => {
					const j = await api.job(r.job.id);
					if (!ok(j)) { fail(j); return; }
					const st = j.job.stats || {};
					bar.firstChild.style.width = `${Math.min(100, Math.round((100 * (st.tasks || 0)) / total))}%`;
					status.textContent = t('notes.import.jobStats', { tasks: st.tasks || 0, lists: st.lists || 0, attachments: st.attachments || 0 });
					if (j.job.state === 'running') setTimeout(poll, 3000);
					else if (j.job.state === 'done') { bar.firstChild.style.width = '100%'; toast(t('notes.import.msDone'), 'success'); reloadNav(); }
					else status.textContent = t('notes.import.failed', { code: j.job.error || j.job.state });
				};
				poll();
			}, 'btn-pri', null, { 'data-act': 'ms-start' });
			area.append(bar, status, start);
		}

		function dsnoteCard() {
			const card = el('div', { class: 'card nz-card', 'data-import': 'dsnote' }, [el('div', { class: 'nz-set-h' }, [el('span', { class: 'nz-badge', 'data-tone': 'warn', text: 'DS' }),
				el('div', { class: 'grow' }, [el('b', { text: 'Synology DS Note' }), el('span', { class: 'hint nz-block', text: t('notes.import.dsHint') })])])]);
			const area = el('div', { class: 'nz-imp-body' });
			card.appendChild(btn(t('notes.import.dsPick'), async () => {
				clear(area).appendChild(el('p', { class: 'nz-muted', text: t('notes.import.dsReading') }));
				const r = await api.dsPick();
				clear(area);
				if (!ok(r)) { if (r && r.code !== 'cancelled') area.appendChild(el('p', { class: 'nz-err', text: r.code === 'nsx_invalid' ? t('notes.import.dsBad') : NS.errText(r, t) })); return; }
				S.ds = r;
				S.dsEvent = null;
				dsSummary(area);
			}, 'btn-sec', 'open', { 'data-act': 'ds-pick' }));
			card.appendChild(el('p', { class: 'hint', text: t('notes.import.dsNas') }));
			card.appendChild(area);
			if (S.ds) dsSummary(area);
			return card;
		}

		function dsSummary(area) {
			const s = S.ds;
			area.appendChild(el('b', { text: t('notes.import.dsFound', { file: s.file }) }));
			area.appendChild(stats([[s.notebooks.length, t('notes.import.notebooks')], [s.notes, t('notes.notes')], [NS.formatBytes(s.bytes, lang()), t('notes.import.files')]]));
			const pw = el('input', { class: 'inp', type: 'password', autocomplete: 'off', 'aria-label': t('notes.import.dsPassword'), id: 'nz-ds-password' });
			if (s.protectedNotes) {
				area.appendChild(el('p', { class: 'hint', text: t('notes.import.dsProtected', { n: s.protectedNotes }) }));
				area.appendChild(field(t('notes.import.dsPassword'), pw));
			}
			area.appendChild(el('p', { class: 'hint', text: t('notes.import.dsWhere', { area: t(`notes.area.${S.area}`) }) }));
			const bar = el('div', { class: 'nz-bar', hidden: !S.dsEvent }, [el('i')]);
			const status = el('p', { class: 'hint', 'data-import-status': 'true', text: S.dsEvent ? NS.importText(S.dsEvent, t) : '' });
			const go2 = btn(t('notes.import.takeNotesN', { n: s.notes }), async () => {
				go2.disabled = true;
				bar.hidden = false;
				const r = await api.dsImport({ password: pw.value, area: S.area });
				pw.value = '';
				if (!ok(r)) { go2.disabled = false; fail(r); }
			}, 'btn-pri', null, { 'data-act': 'ds-start', disabled: !!(S.dsEvent && S.dsEvent.state === 'running') });
			S.dsUi = { bar, status, go2 };
			area.append(bar, status, go2);
		}

		function onImport(e) {
			if (!e) return;
			if (e.vault && e.vault.recoveryKey) { showRecovery(e.vault.recoveryKey, e.vault.name); reloadNav(); return; }
			S.dsEvent = e;
			const ui = S.dsUi;
			if (ui && ui.status.isConnected) {
				ui.bar.hidden = false;
				ui.bar.firstChild.style.width = `${e.state === 'running' && e.total ? Math.round((100 * (e.done || 0)) / e.total) : 100}%`;
				ui.status.textContent = NS.importText(e, t);
				ui.go2.disabled = e.state === 'running';
			}
			if (e.state !== 'running') { reloadNav(); if (e.state === 'done') toast(t('notes.import.dsFinished'), 'success'); }
		}

		// ── live ─────────────────────────────────────────────
		if (typeof api.onChanged === 'function') {
			api.onChanged((c) => {
				// plugin 1.5.0: the switches of places may have changed on another device — `me.places` says what holds now
				if (placesOn() && S.shown && c && Array.isArray(c.what) && c.what.includes('places')) loadMe().then(() => soon(0));
				else soon();
			});
		}
		// „Meine Orte“ changed (here, on another device, by a plugin): plugin 1.8.0 keeps its places in the profile — the
		// list on „Quellen“ and a task's place are read again
		if (o.places && typeof o.places.onChanged === 'function') {
			o.places.onChanged(() => {
				if (!placesOn() || !(S.me && S.me.places && S.me.places.profile)) return;
				reloadPlaces();
				if (S.shown) soon();
			});
		}
		if (typeof api.onVault === 'function') api.onVault((v) => { if (v && v.event === 'approved') soon(); });
		if (typeof api.onImport === 'function') api.onImport(onImport);
		if (typeof api.onVaultLock === 'function') {
			api.onVaultLock((e) => {
				if (!e || !e.locked) return;
				forgetImages();
				// a Tresor note leaves the screen with the lock
				if (S.detail && S.detail.type === 'note' && S.detailData && S.detailData.note && S.detailData.note.encrypted) closeDetail();
				if (!S.shown) { S.dirty = true; return; }
				reloadNav();
				if (S.view.kind === 'notes') reloadView();
			});
		}
		rootEl.addEventListener('keydown', (e) => {
			if (!S.shown || e.defaultPrevented) return;
			if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && (e.key === 'n' || e.key === 'N')) { e.preventDefault(); focusQuick(); }
		});

		function applyStatus(st) {
			S.status = st || null;
			const avail = !!st && st.state === 'available';
			if (o.onStatus) o.onStatus(st);
			if (avail && S.shown && (S.dirty || !S.me)) { S.dirty = false; reloadAll(); }
			if (!avail) { S.me = null; S.dirty = true; }
		}
		if (typeof api.onState === 'function') api.onState(applyStatus);
		Promise.resolve(api.status()).then(applyStatus).catch(() => {});

		renderSide();
		renderMain();
		renderDetail();

		return {
			show() {
				S.shown = true;
				if (S.dirty || !S.me) { S.dirty = false; reloadAll(); }
			},
			hide() { S.shown = false; },
			/**
			 * A push click / a link: { kind: 'task' | 'list' | 'notebook' | 'vault' | 'home', … } or { note }; the morning hint
			 * { kind: 'yesterday', taskIds, action: 'done_ask' | 'move' | null } → Mein Tag with the card (and the question);
			 * a reminder's button „Liste öffnen“ { kind: 'shopping', uid, taskId } → the shopping list to tick off.
			 */
			async open(ctx) {
				S.shown = true;
				if (!S.me) { S.dirty = false; await reloadAll(); }
				const c = ctx && typeof ctx === 'object' ? ctx : null;
				if (!c) return;
				if (c.quick) { focusQuick(); return; }
				if (c.kind === 'yesterday') { await go({ kind: 'smart', id: 'myday' }); await askYesterday(c); }
				else if (c.kind === 'shopping' && c.uid) {
					// „Liste öffnen“ of a reminder: the list to tick off; gone meanwhile (or an older plugin): the task, else Mein Tag
					if (shopOn()) await reloadShop();
					if (shopOn() && openShopList(c.uid)) return;
					if (c.taskId) { if (S.view.kind !== 'smart') await go({ kind: 'smart', id: 'myday' }); openDetail({ uid: `t:${c.taskId}`, type: 'task', id: c.taskId }); }
					else go({ kind: 'smart', id: 'myday' });
				}
				else if (c.kind === 'task' && c.taskId) { if (S.view.kind !== 'smart') await go({ kind: 'smart', id: 'myday' }); openDetail({ uid: `t:${c.taskId}`, type: 'task', id: c.taskId }); }
				else if (c.kind === 'list' && c.listId) go({ kind: 'list', id: c.listId });
				else if (c.kind === 'notebook' && c.notebookId) go({ kind: 'notes', notebook: c.notebookId });
				else if (c.kind === 'vault' && c.vaultId) {
					await reloadNav();
					const nb = ((S.nav && S.nav.notes.notebooks) || []).find((b) => b.vault && b.vault.id === c.vaultId);
					if (nb) { await go({ kind: 'notes', notebook: nb.id }); if (c.event === 'request' && S.data && !S.data.locked) devicesDialog(nb); }
				} else if (c.note) { await go({ kind: 'notes' }); openNote(c.note); }
				else go({ kind: 'smart', id: 'myday' });
			},
			focusQuick,
			refresh: () => reloadAll(),
			status: () => S.status,
			available: () => !!(S.status && S.status.state === 'available'),
			relabel() { renderSide(); renderMain(); renderDetail(); },
		};
	}

	root.GCNotesView = { mount };
})(typeof self !== 'undefined' ? self : this);
