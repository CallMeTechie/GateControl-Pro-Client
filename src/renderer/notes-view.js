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
	 * @returns {{ show(), hide(), open(ctx), focusQuick(), refresh(), status(), available(), relabel() }}
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const lang = () => (String(o.getLocale() || 'de').startsWith('en') ? 'en' : 'de');
		const toast = (msg, type) => o.toast(msg, type || 'info');
		const fail = (r) => toast(NS.errText(r, t), 'error');
		const ok = (r) => !!r && r.ok !== false;

		const S = {
			status: null, shown: false, me: null, area: 'private', nav: null, people: [], view: { kind: 'smart', id: 'myday' }, data: null,
			detail: null, detailData: null, editing: false, folded: {}, seq: 0, dseq: 0, dirty: true, quickText: '',
			ds: null, dsEvent: null, images: new Map(),
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

		function notebookOf(id) {
			return ((S.nav && S.nav.notes && S.nav.notes.notebooks) || []).find((b) => b.id === id) || null;
		}

		async function loadView() {
			const v = S.view;
			if (v.kind === 'smart') return api.view(v.id, S.area);
			if (v.kind === 'list') return api.view(`list:${v.id}`, S.area);
			if (v.kind === 'source') return api.view(`source:${v.plugin}`, S.area);
			if (v.kind === 'search') return api.search(v.q, S.area);
			if (v.kind === 'sources') return api.sources();
			if (v.kind === 'import') return { ok: true };
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
			await Promise.all([reloadNav(), reloadView(), pp]);
			if (S.detail && !S.editing) reloadDetail();
		}

		let soonTimer = null;
		function soon(ms = 350) {
			clearTimeout(soonTimer);
			soonTimer = setTimeout(() => {
				if (!S.shown) { S.dirty = true; return; }
				reloadNav();
				reloadView();
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
				el('span', { class: 'nz-it-tx', text: label }), count ? el('span', { class: 'nz-n', text: String(count) }) : null]);
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
			return navRow(l.name + (l.shared ? ` · ${t('notes.shared')}` : ''), l.open, isView('list', l.id), () => go({ kind: 'list', id: l.id }), { sub: !!sub, icon: 'list', dot: l.color || null, key: `list:${l.id}` });
		}

		function setArea(a) {
			if (S.area === a) return;
			S.area = a;
			api.setPrefs({ area: a }).catch(() => {});
			if (S.view.kind === 'list' || (S.view.kind === 'notes' && S.view.notebook)) S.view = { kind: 'smart', id: 'myday' };
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
			if (has('tasks')) m.appendChild(quickBox());
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
			if (x.canComplete && !(S.me && S.me.readOnly)) {
				row.appendChild(el('button', { type: 'button', class: `nz-ck${x.done ? ' on' : ''}`, 'aria-label': x.done ? t('notes.undo') : t('notes.complete'), 'aria-pressed': x.done ? 'true' : 'false',
					on: { click: (e) => { e.stopPropagation(); complete(x, !x.done); } } }, [icon('check', 13)]));
			} else row.appendChild(el('span', { class: 'nz-ck-none' }));
			const meta = NS.metaLine(x, { userId: S.me && S.me.user.id, lists: S.nav ? S.nav.lists : [], inList: S.view.kind === 'list' }, t);
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

		/** A small mark of a task (plugin 1.3.0): the bell „Erinnerung“ / „Später: …“, the calendar „im Kalender“. */
		function markEl(k) {
			return el('span', { class: 'nz-mark', 'data-kind': k.kind, title: k.title || null }, [icon(k.kind === 'calendar' ? 'cal' : 'bell', 12), el('span', { text: k.text })]);
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

		async function complete(x, done) {
			x.done = done;
			renderMain();
			const r = x.type === 'task' ? await api.completeTask(x.id, done) : await api.completeItem(x.id, done);
			if (!ok(r)) { x.done = !done; renderMain(); fail(r); return; }
			if (r.next && r.next.due) toast(t('notes.nextRepeat', { when: NS.dayText(r.next.due.date, S.me.today, t) }), 'success');
			else if (x.type === 'source' && done) toast(t('notes.doneThere', { source: x.source.label }), 'success');
			soon(150);
		}

		// ── the quick entry (Strg+N) ─────────────────────────
		function quickBox() {
			const input = el('input', { id: 'nz-quick', class: 'nz-quick-inp', type: 'text', autocomplete: 'off', maxlength: '500', placeholder: t('notes.quick.ph'), 'aria-label': t('notes.quick.label') });
			input.value = S.quickText;
			const chips = el('div', { class: 'nz-chips', 'aria-live': 'polite' });
			let parsed = null;
			const show = () => {
				S.quickText = input.value;
				clear(chips);
				const ctx = NS.quickCtx(S.me, S.nav, S.people);
				parsed = NS.quickParse(input.value, ctx);
				if (!parsed) return;
				chips.appendChild(el('span', { class: 'nz-chips-l', text: t('notes.quick.found') }));
				for (const c of NS.quickChips(parsed, ctx, S.area, t, lang(), S.me)) chips.appendChild(el('span', { class: `chip nz-qchip${c.plain ? ' plain' : ''}`, 'data-kind': c.kind, title: c.title || null, text: c.text }));
			};
			input.addEventListener('input', show);
			input.addEventListener('keydown', async (e) => {
				if (e.key === 'Escape') { input.value = ''; show(); return; }
				if (e.key !== 'Enter' || !input.value.trim() || input.disabled) return;
				const body = NS.quickBody(input.value, parsed, S.view, S.area);
				input.disabled = true;
				const r = await api.createTask(body);
				input.disabled = false;
				if (!ok(r)) { fail(r); input.focus(); return; }
				input.value = '';
				S.quickText = '';
				show();
				input.focus();
				toast(t('notes.quick.added', { title: r.task.title }), 'success');
				soon(0);
			});
			setTimeout(show, 0);
			return el('div', { class: 'nz-quick' }, [el('label', { class: 'nz-quick-box' }, [icon('plus', 18), input, el('span', { class: 'nz-kbd', text: t('notes.quick.kbd') })]), chips]);
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
			box.appendChild(el('div', { class: 'nz-d-headrow' }, [
				el('button', { type: 'button', class: `nz-ck nz-ck-lg${task.done ? ' on' : ''}`, 'aria-label': task.done ? t('notes.undo') : t('notes.complete'), on: { click: async () => { const r = await api.completeTask(task.id, !task.done); if (!ok(r)) fail(r); else { reloadDetail(); soon(0); } } } }, [icon('check', 14)]),
				title,
				el('button', { type: 'button', class: `nz-star${task.important ? ' on' : ''}`, 'aria-label': t('notes.important'), 'aria-pressed': task.important ? 'true' : 'false', on: { click: () => patchTask(task, { important: !task.important }) } }, [icon('star', 20)]),
			]));
			const list = task.list || ((S.nav && S.nav.lists) || []).find((l) => l.id === task.listId);
			if (list) box.appendChild(el('div', { class: 'nz-crumb', text: `${t(`notes.area.${list.area}`)} › ${list.name}` }));
			if (task.sourceItem) box.appendChild(fromButton(task.sourceItem));
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
			det.appendChild(field(t('notes.inMyDay'), sw(task.myDay, (v) => patchTask(task, { myDay: v }), t('notes.inMyDay'))));
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
			const as = el('select', { class: 'inp nz-inp-sm', 'aria-label': t('notes.assigned') }, [el('option', { value: '', text: t('notes.nobody') }), ...members.map((m) => el('option', { value: String(m.id), text: S.me && m.id === S.me.user.id ? t('notes.me') : m.name || '' }))]);
			as.value = task.assignee ? String(task.assignee.id) : '';
			as.addEventListener('change', () => patchTask(task, { assigneeId: as.value ? Number(as.value) : null }));
			det.appendChild(field(t('notes.assigned'), as));
			const ls = el('select', { class: 'inp nz-inp-sm', 'aria-label': t('notes.list') }, ((S.nav && S.nav.lists) || []).map((l) => el('option', { value: String(l.id), text: `${t(`notes.area.${l.area}`)} › ${l.name}` })));
			if (!((S.nav && S.nav.lists) || []).some((l) => l.id === task.listId) && list) ls.appendChild(el('option', { value: String(task.listId), text: list.name }));
			ls.value = String(task.listId);
			ls.addEventListener('change', () => patchTask(task, { listId: Number(ls.value) }));
			det.appendChild(field(t('notes.list'), ls));
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
			if (task.sourceItem) box.appendChild(el('p', { class: 'hint', text: t('notes.doneHereThere', { source: task.sourceItem.source.label }) }));
			box.appendChild(el('div', { class: 'nz-d-foot' }, [
				el('span', { class: 'hint', text: task.updatedAt ? t('notes.changed', { when: new Date(task.updatedAt).toLocaleString(lang()) }) : '' }),
				btn(t('notes.delete'), async () => { const r = await api.deleteTask(task.id); if (!ok(r)) { fail(r); return; } closeDetail(); soon(0); toast(t('notes.deleted'), 'success'); }, 'btn-danger', 'trash'),
			]));
			return box;
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
			if (owner) extra.push(field(t('notes.color'), color.box), field(t('notes.shareWith'), share.box));
			const d = prompt(t('notes.listSettings'), l.name, async (name) => {
				const body = { groupId: groups.value ? Number(groups.value) : null };
				if (owner) { if (!l.isDefault || name !== l.name) body.name = name; body.color = color.value(); }
				let r = await api.updateList(l.id, body);
				if (ok(r) && owner) r = await api.listMembers(l.id, share.value());
				if (ok(r)) { reloadNav(); reloadView(); }
				return r;
			}, [...extra, el('div', { class: 'nz-row-acts' }, [btn(owner ? t('notes.deleteList') : t('notes.leaveList'), async () => {
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
		if (typeof api.onChanged === 'function') api.onChanged(() => soon());
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
			 * { kind: 'yesterday', taskIds, action: 'done_ask' | 'move' | null } → Mein Tag with the card (and the question).
			 */
			async open(ctx) {
				S.shown = true;
				if (!S.me) { S.dirty = false; await reloadAll(); }
				const c = ctx && typeof ctx === 'object' ? ctx : null;
				if (!c) return;
				if (c.quick) { focusQuick(); return; }
				if (c.kind === 'yesterday') { await go({ kind: 'smart', id: 'myday' }); await askYesterday(c); }
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
