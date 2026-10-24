/**
 * GateControl -- Vault (renderer view of the plugin gatecontrol-vault)
 *
 * The end-to-end encrypted password manager (mockups W1 / W3, Android A2–A10):
 * intro and setup (master password with strength, recovery key shown — print,
 * copy, "gesichert" — before the account is sent), unlock (Windows Hello,
 * master password, "Angemeldet bleiben", recovery key → new password), the list of entries
 * with vault chips and search beside the detail (fields with Kopieren /
 * Öffnen, secrets masked until revealed, 2FA codes with countdown), edit of
 * all six types with custom fields and the password generator, history,
 * trash, vaults (create / rename / delete / members, W3 share dialog with
 * safety number), emergency access, import and settings. Vault pushes open
 * the right sub page.
 *
 * Data: window.gatecontrol.vault (core VaultService over IPC). Lists carry
 * no secrets; an entry's secrets come only with vault:entry (detail, edit)
 * and vault:history and reach the DOM only in a field the person revealed or
 * is editing. Copies go through vault:copy (main writes the clipboard and
 * clears it after 30 s). Texts: vault.* of the app locales; view logic
 * without DOM: vault-state.js (window.GCVaultState). The same file is used
 * by Pro and Community.
 *
 * Note: user / server text only ever goes into textContent / attributes;
 * icons are built from static path data with createElementNS (no innerHTML).
 */
(function (root) {
	'use strict';

	const VS = root.GCVaultState;
	const NS = 'http://www.w3.org/2000/svg';
	const ICONS = {
		lock: 'M5 11h14v10H5z|M8 11V8a4 4 0 0 1 8 0v3',
		unlock: 'M5 11h14v10H5z|M8 11V8a4 4 0 0 1 7.5-2',
		shield: 'M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z',
		search: 'M11 4a7 7 0 1 0 0 14a7 7 0 1 0 0-14|M20 20l-3.5-3.5',
		plus: 'M12 5v14M5 12h14',
		more: 'M5 12h.01M12 12h.01M19 12h.01',
		refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8|M21 3v5h-5',
		star: 'M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1-4.4-4.3 6.1-.9z',
		eye: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z|M12 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6',
		eyeOff: 'M3 3l18 18|M10.6 6.1A9.8 9.8 0 0 1 12 6c6.4 0 10 6 10 6a17 17 0 0 1-3.2 3.8|M6.6 6.6C3.8 8.4 2 12 2 12s3.6 7 10 7a9.6 9.6 0 0 0 4.4-1.1|M9.9 9.9a3 3 0 0 0 4.2 4.2',
		copy: 'M9 9h11v11H9z|M5 15H4V4h11v1',
		external: 'M14 4h6v6|M20 4l-9 9|M18 14v6H4V6h6',
		trash: 'M4 7h16|M10 11v6M14 11v6|M6 7l1 13h10l1-13|M9 7V4h6v3',
		history: 'M3 12a9 9 0 1 0 3-6.7L3 8|M3 3v5h5|M12 7v5l3 3',
		users: 'M9 11a4 4 0 1 0 0-8a4 4 0 1 0 0 8|M2 21a7 7 0 0 1 14 0|M17 3.5a4 4 0 0 1 0 7|M22 21a7 7 0 0 0-4-6.3',
		lifebuoy: 'M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20|M12 8a4 4 0 1 0 0 8a4 4 0 1 0 0-8|M4.9 4.9l4.3 4.3M14.8 14.8l4.3 4.3M19.1 4.9l-4.3 4.3M9.2 14.8l-4.3 4.3',
		upload: 'M12 15V3|M7 8l5-5 5 5|M4 15v4a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4',
		settings: 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6',
		back: 'M15 18l-6-6 6-6',
		close: 'M6 6l12 12M18 6L6 18',
		alert: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 8v5M12 16h.01',
		cloudOff: 'M3 3l18 18|M8 8a5 5 0 0 0-2 9h11|M10 5a7 7 0 0 1 9 6 4 4 0 0 1 1 7',
		key: 'M15 7a4 4 0 1 0 0 .01|M12 10l-9 9v2h3l1-1v-2h2v-2h2l2-2',
		print: 'M6 9V3h12v6|M6 18H4v-7h16v7h-2|M8 14h8v7H8z',
		check: 'M4 12l5 5L20 6',
		wand: 'M15 4V2M15 16v-2M8 9h2M20 9h2M17.8 11.8l1.4 1.4M17.8 6.2l1.4-1.4M12.2 6.2l-1.4-1.4|M3 21l9-9',
		login: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M3 12h18|M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18',
		totp: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 7v5l3 2',
		note: 'M6 3h9l4 4v14H6z|M9 12h7M9 16h5',
		card: 'M3 6h18v12H3z|M3 10h18|M7 15h4',
		wifi: 'M2 9a15 15 0 0 1 20 0|M5 12.5a10 10 0 0 1 14 0|M8.5 16a5 5 0 0 1 7 0|M12 19.5h.01',
		identity: 'M4 5h16v14H4z|M9 10a2 2 0 1 0 0 .01|M6.5 16a3 3 0 0 1 5 0|M14 10h4M14 14h3',
		qr: 'M3 3h6v6H3z|M15 3h6v6h-6z|M3 15h6v6H3z|M21 15h-3a2 2 0 0 0-2 2v4|M21 21v.01|M12 7v3a2 2 0 0 1-2 2H7|M3 12h.01|M12 3h.01|M12 16v.01|M16 12h1|M21 12v.01|M12 21v-1',
		monitor: 'M3 4h18v12H3z|M8 20h8|M12 16v4',
		clipboard: 'M9 3h6v3H9z|M9 4.5H6V21h12V4.5h-3',
		image: 'M3 5h18v14H3z|M8.5 9.5a1.5 1.5 0 1 0 0 .01|M21 15l-5-5L5 19',
		tablet: 'M6 3h12v18H6z|M11 18h2',
		globe: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M3 12h18|M12 3c2.5 2.5 3.8 5.5 3.8 9s-1.3 6.5-3.8 9c-2.5-2.5-3.8-5.5-3.8-9s1.3-6.5 3.8-9',
		hello: 'M4 8V6a2 2 0 0 1 2-2h2|M16 4h2a2 2 0 0 1 2 2v2|M20 16v2a2 2 0 0 1-2 2h-2|M8 20H6a2 2 0 0 1-2-2v-2|M9 9.5v1M15 9.5v1|M12 9.5v3.5h-1|M9.5 15.5a3.5 3.5 0 0 0 5 0',
	};

	function icon(name, size = 16, stroke = '1.8') {
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
			else if (k === 'value') n.value = String(v);
			else if (k === 'checked') n.checked = !!v;
			else n.setAttribute(k, v === true ? '' : String(v));
		}
		for (const c of kids || []) if (c !== null && c !== undefined && c !== false && c !== '') n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
		return n;
	}
	const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };
	const btn = (cls, label, run, extra) => el('button', { type: 'button', class: `btn ${cls}`, on: { click: run }, ...(extra || {}) }, Array.isArray(label) ? label : [label]);
	const iconBtn = (cls, name, label, run, extra) => el('button', { type: 'button', class: `btn ${cls} btn-icon vt-ib`, title: label, 'aria-label': label, on: { click: run }, ...(extra || {}) }, [icon(name, 17)]);

	/** '48213 90577 …' as a grid of groups (compare with the other device). */
	function safetyEl(number, id) {
		const groups = String(number || '').split(/\s+/).filter(Boolean);
		return el('div', { class: 'vt-safety', id: id || null, 'aria-label': String(number || '') }, groups.length ? groups.map((g) => el('span', { text: g })) : [el('span', { text: '—' })]);
	}

	function avatar(title, large) {
		return el('span', { class: `vt-av${large ? ' vt-av-lg' : ''} vt-t${VS.tone(title)}`, 'aria-hidden': 'true', text: VS.letter(title) });
	}

	/**
	 * @param {object} o
	 * @param {HTMLElement} o.root - the page section (empty)
	 * @param {object} o.api - window.gatecontrol.vault
	 * @param {Function} o.t - i18n
	 * @param {() => string} o.getLocale
	 * @param {(msg: string, type?: string) => void} [o.toast]
	 * @param {(url: string) => Promise} [o.openExternal]
	 * @param {HTMLElement} [o.statusHost] - the app's status bar (footer texts while shown)
	 * @param {(st: object) => void} [o.onStatus] - availability (nav entry)
	 * @param {() => number} [o.now]
	 * @returns {{ show(), hide(), open(ctx), status(), relabel() }}
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const now = typeof o.now === 'function' ? o.now : () => Date.now();
		const locale = () => o.getLocale();
		let toastTimer = null;
		/** In-page notice when the app has no toast helper of its own (Community). */
		function ownToast(msg, type) {
			let n = rootEl.querySelector(':scope > .vt-toast');
			if (!n) n = el('div', { class: 'vt-toast', role: 'status' });
			if (n.parentNode !== rootEl) rootEl.appendChild(n);
			n.className = `vt-toast${type === 'error' ? ' is-err' : type === 'success' ? ' is-ok' : ''}`;
			n.textContent = String(msg || '');
			n.hidden = false;
			clearTimeout(toastTimer);
			toastTimer = setTimeout(() => { n.hidden = true; }, 5000);
		}
		const toast = (msg, type) => { if (typeof o.toast === 'function') o.toast(msg, type || 'info'); else ownToast(msg, type); };

		const S = {
			status: null,
			shown: false,
			built: null,          // key of the screen on the page
			flow: null,           // 'setup' | 'setupDone' | 'recover' | 'recoverKey'
			setupKey: null,       // recovery key between vault:setup and vault:setup:confirm
			setupBusy: false,     // vault:setup running (its vault:state can come first)
			recoveryKey: null,    // new recovery key after completeRecovery
			sub: 'list',          // list | trash | vaults | vault | emergency | emView | import | settings
			filter: null,         // vault id of the chips
			query: '',
			entries: [],          // summaries (not trashed)
			vaults: [],           // views
			unreadable: 0,
			trash: [],
			dataRev: null,
			loaded: false,
			listErr: null,
			selId: null,
			detail: null,         // vault:entry answer (with secrets) of selId while shown
			detailErr: null,
			mode: 'view',         // view | edit | history
			revealed: new Set(),  // keys of revealed secret fields
			draft: null,
			draftBase: null,
			gen: null,            // generator panel { field, opts, value, res }
			history: null,
			vaultId: null,        // sub 'vault'
			people: null,
			em: null,
			emView: null,         // { id, grantor, vaults, entries, selId, detail }
			imp: null,            // { text, name, res, vaultId, busy }
			settings: null,
			totp: null,           // { key, code, left, period }
			shares: null,         // Wi-Fi shares of the shown entry: { id, rev, view, err, at } (plugin 1.4.0)
			pending: null,        // push target waiting for unlock
			lastActivity: null,
			lastTouch: 0,
			autoTried: false,     // "Angemeldet bleiben" tried once while shown
			helloTried: false,    // Windows Hello asked once while shown (not again after a lock on the page)
			helloBusy: false,     // a Windows Hello prompt of this page is open
			unlockErr: null,      // error line of the unlock screen (kept when the screen is built again)
		};

		// ── Calls ────────────────────────────────────────────
		// Calls the core does not count as activity (list refreshes, 2FA countdown, …): they do not restart the auto-lock.
		const PASSIVE = new Set(['check', 'sync', 'entries', 'vaults', 'totp', 'settings', 'emergency', 'people', 'status', 'helloCheck', 'wifiShares'].map((k) => api[k]).filter(Boolean));
		async function call(fn, ...args) {
			if (!PASSIVE.has(fn)) S.lastActivity = now();
			let r;
			try {
				r = await Promise.resolve(typeof fn === 'function' ? fn(...args) : null);
			} catch (err) {
				r = { ok: false, code: 'failed', error: err && err.message };
			}
			if (!r || typeof r !== 'object') r = { ok: false, code: 'failed' };
			if (r.ok === false && r.code === 'locked') refreshStatus();
			return r;
		}
		const fail = (r) => toast(VS.errorText(r, t), 'error');

		async function copy(arg, label) {
			const r = await call(api.copy, arg);
			if (r.ok) toast(t('vault.copiedSecret', { label, seconds: Math.round((r.clearsInMs || 30000) / 1000) }), 'success');
			else fail(r);
			return r;
		}

		function openUrl(url) {
			const u = VS.openableUrl(url);
			if (!u || typeof o.openExternal !== 'function') return;
			Promise.resolve(o.openExternal(u)).catch(() => {});
		}

		// ── Skeleton ─────────────────────────────────────────
		const rootEl = el('div', { class: 'vt' });
		o.root.appendChild(rootEl);
		const refs = {};
		refs.sbLock = el('span', { class: 'statusbar-item sb-item vt-sb' });
		refs.sbClip = el('span', { class: 'statusbar-item sb-item vt-sb vt-sb-right', text: t('vault.foot.clipboard') });
		if (o.statusHost) o.statusHost.append(refs.sbLock, refs.sbClip);

		// Activity on the page keeps the vault open (auto-lock counts from the last one).
		// Real input on the page keeps the vault open: vault:touch at most every 15 s.
		const activity = () => {
			if (!S.shown || !S.status || !S.status.unlocked) return;
			if (now() - S.lastTouch < 15000) return;
			S.lastTouch = now();
			S.lastActivity = S.lastTouch;
			Promise.resolve(api.touch && api.touch()).catch(() => {});
		};
		rootEl.addEventListener('pointerdown', activity, true);
		rootEl.addEventListener('keydown', activity, true);
		rootEl.addEventListener('wheel', activity, { capture: true, passive: true });

		// ── Menus and dialogs ────────────────────────────────
		let openMenu = null;
		function closeMenu() {
			if (!openMenu) return;
			openMenu.el.remove();
			document.removeEventListener('pointerdown', openMenu.outside, true);
			document.removeEventListener('keydown', openMenu.esc, true);
			const anchor = openMenu.anchor;
			openMenu = null;
			anchor.setAttribute('aria-expanded', 'false');
		}
		function menu(anchor, items) {
			const again = openMenu && openMenu.anchor === anchor;
			closeMenu();
			if (again) return;
			const m = el('div', { class: 'card vt-menu', role: 'menu' });
			for (const it of items) {
				m.appendChild(el('button', { type: 'button', role: 'menuitem', id: it.id || null, class: `vt-mi${it.danger ? ' is-danger' : ''}`, on: { click: () => { closeMenu(); it.run(); } } }, [it.icon ? icon(it.icon, 16) : null, el('span', { text: it.label })]));
			}
			rootEl.appendChild(m);
			const a = anchor.getBoundingClientRect();
			const r = rootEl.getBoundingClientRect();
			const w = m.offsetWidth || 220;
			m.style.top = `${a.bottom - r.top + 6}px`;
			m.style.left = `${Math.max(8, Math.min(a.right - r.left - w, r.width - w - 8))}px`;
			const outside = (e) => { if (!m.contains(e.target) && !anchor.contains(e.target)) closeMenu(); };
			const esc = (e) => { if (e.key === 'Escape') { e.stopPropagation(); closeMenu(); anchor.focus(); } };
			document.addEventListener('pointerdown', outside, true);
			document.addEventListener('keydown', esc, true);
			openMenu = { el: m, anchor, outside, esc };
			anchor.setAttribute('aria-expanded', 'true');
			const first = m.querySelector('button');
			if (first) first.focus();
		}

		let dlg = null;
		/** A modal dialog: { title, sub?, body: [nodes], actions: [{ label, cls, run, id? }] } → { close, el, buttons }. */
		function dialog({ title, sub, body, actions, onClose }) {
			closeDialog();
			const buttons = {};
			const box = el('div', { class: 'card vt-dialog', role: 'dialog', 'aria-modal': 'true', 'aria-label': title });
			const head = el('div', { class: 'vt-dialog-head' }, [
				el('div', null, [el('h2', { class: 'disp', text: title }), sub ? el('span', { class: 'vt-desc', text: sub }) : null]),
				iconBtn('btn-ghost', 'close', t('vault.close'), () => closeDialog()),
			]);
			box.appendChild(head);
			for (const n of body || []) if (n) box.appendChild(n);
			if (actions && actions.length) {
				const row = el('div', { class: 'vt-dlg-actions' });
				for (const a of actions) {
					const b = btn(a.cls || 'btn-sec', a.label, () => a.run());
					if (a.id) buttons[a.id] = b;
					row.appendChild(b);
				}
				box.appendChild(row);
			}
			const scrim = el('div', { class: 'vt-scrim', on: { pointerdown: (e) => { if (e.target === scrim) closeDialog(); } } }, [box]);
			const esc = (e) => { if (e.key === 'Escape') { e.stopPropagation(); closeDialog(); } };
			document.addEventListener('keydown', esc, true);
			rootEl.appendChild(scrim);
			dlg = { scrim, esc, onClose };
			const focus = box.querySelector('input, select, textarea, [role="option"]:not([disabled]), .vt-dlg-actions .btn-pri') || box.querySelector('button');
			if (focus) setTimeout(() => focus.focus(), 0);
			return { close: closeDialog, el: box, buttons };
		}
		function closeDialog() {
			if (!dlg) return;
			const d = dlg;
			dlg = null;
			document.removeEventListener('keydown', d.esc, true);
			d.scrim.remove();
			if (typeof d.onClose === 'function') d.onClose();
		}
		/** Yes / no question → Promise<boolean>. */
		function confirm(text, okLabel, danger) {
			return new Promise((resolve) => {
				let answered = false;
				const done = (v) => { if (answered) return; answered = true; closeDialog(); resolve(v); };
				dialog({
					title: text,
					body: [],
					actions: [
						{ label: t('vault.cancel'), cls: 'btn-ghost', run: () => done(false) },
						{ label: okLabel, cls: danger ? 'btn-danger' : 'btn-pri', run: () => done(true) },
					],
					onClose: () => { if (!answered) { answered = true; resolve(false); } },
				});
			});
		}

		// ── Status and data ──────────────────────────────────
		async function refreshStatus() {
			const st = await Promise.resolve(api.status && api.status()).catch(() => null);
			if (st && typeof st === 'object') setStatus(st);
		}

		function wipe() {
			S.entries = [];
			S.vaults = [];
			S.trash = [];
			S.unreadable = 0;
			S.detail = null;
			S.selId = null;
			S.mode = 'view';
			S.revealed.clear();
			S.draft = null;
			S.draftBase = null;
			S.gen = null;
			S.history = null;
			S.people = null;
			S.em = null;
			S.emView = null;
			S.imp = null;
			S.totp = null;
			S.shares = null;
			S.loaded = false;
			S.dataRev = null;
			if (S.sub === 'emView' || S.sub === 'import') S.sub = 'list';
			closeDialog();
			closeMenu();
			// the next build only detaches the page: empty what held revealed secrets / the edit form now
			for (const k of ['detail', 'emDetail', 'page']) if (refs[k]) clear(refs[k]);
			refs.detailKey = null;
			refs.totpCode = null;
			refs.genOut = null;
		}

		function setStatus(st) {
			const was = S.status;
			S.status = st;
			if (typeof o.onStatus === 'function') { try { o.onStatus(st); } catch { /* app */ } }
			if (was && was.unlocked && !st.unlocked) wipe();
			if (!st.unlocked) S.dataRev = null;
			if (st.state !== 'available') { S.flow = null; S.setupKey = null; }
			if (!st.setupPending && S.setupKey && st.account !== 'ready') {
				// a lock (or another device) discarded the unconfirmed setup: its recovery key is void
				S.setupKey = null;
				if (S.flow === 'setup') toast(t('vault.err.setupGone'), 'error');
			} else if (!st.setupPending && S.setupKey) S.setupKey = null;
			if (st.account === 'ready' && S.flow === 'setup' && !st.setupPending) S.flow = st.unlocked ? 'setupDone' : null;
			if (st.unlocked) { S.autoTried = true; S.helloTried = true; S.unlockErr = null; }
			if (st.unlocked && S.dataRev !== st.dataRev) {
				S.dataRev = st.dataRev;
				loadData();
			}
			render();
			maybeAutoUnlock();
			maybeAutoHello();
		}

		async function loadData() {
			const res = await call(api.entries, {});
			if (!S.status || !S.status.unlocked) return;
			if (res.ok) {
				S.entries = Array.isArray(res.entries) ? res.entries : [];
				S.vaults = Array.isArray(res.vaults) ? res.vaults : [];
				S.unreadable = Number(res.unreadable) || 0;
				S.listErr = null;
				if (S.filter && !S.vaults.some((v) => v.id === S.filter)) S.filter = null;
			} else {
				S.listErr = res;
			}
			S.loaded = true;
			if (S.sub === 'trash') await loadTrash();
			applyPending();
			// the selected entry changed meanwhile (sync, another device): read it again
			if (S.selId && S.mode !== 'edit') {
				const sum = S.entries.find((e) => e.id === S.selId);
				if (!sum) { S.selId = null; S.detail = null; S.mode = 'view'; } else if (!S.detail || S.detail.rev !== sum.rev || S.detail.pending !== sum.pending) loadDetail(S.selId, true);
			}
			update();
		}

		async function loadTrash() {
			const res = await call(api.entries, { trash: true });
			S.trash = res.ok && Array.isArray(res.entries) ? res.entries : [];
		}

		const vaultOf = (id) => S.vaults.find((v) => v.id === id) || null;
		const names = () => VS.vaultNames(S.vaults, t);
		const canWrite = (vaultId) => { const v = vaultOf(vaultId); return !!(v && v.canWrite); };

		// "Angemeldet bleiben": open with the kept key once when the page shows (not after a manual lock).
		function maybeAutoUnlock() {
			const st = S.status;
			if (!S.shown || S.autoTried || !st || VS.gate(st) !== 'unlock' || !st.remember || S.flow) return;
			if (st.lastLock && st.lastLock.reason === 'manual') return; // locked on purpose: the button stays
			S.autoTried = true;
			unlockRemembered(true);
		}

		// Windows Hello: asked once when the page shows while locked (not after a lock on the page, not while blocked).
		function maybeAutoHello() {
			const st = S.status;
			if (!S.shown || S.helloTried || S.helloBusy || !st || VS.gate(st) !== 'unlock' || S.flow || st.helloBusy) return;
			if (!VS.helloView(st, t).primary) return;
			S.helloTried = true;
			unlockHello(true);
		}

		function showUnlockErr(text) {
			S.unlockErr = text || null;
			if (refs.unlockErr && refs.unlockErr.isConnected) refs.unlockErr.textContent = text || '';
		}

		function paintHelloBusy() {
			const b = refs.helloBtn;
			if (!b || !b.isConnected) return;
			b.disabled = S.helloBusy;
			const label = b.querySelector('span');
			if (label) label.textContent = t(S.helloBusy ? 'vault.hello.busy' : 'vault.hello.button');
		}

		async function unlockHello(quiet) {
			if (S.helloBusy) return;
			S.helloBusy = true;
			showUnlockErr(null);
			paintHelloBusy();
			const r = await call(api.unlockHello);
			S.helloBusy = false;
			paintHelloBusy();
			if (r.ok) { if (r.status) setStatus(r.status); return; }
			// an automatic prompt the person closed: no error, the button stays
			if (!(quiet && r.code === 'hello_cancelled')) showUnlockErr(VS.errorText(r, t));
			refreshStatus();
		}

		async function unlockRemembered(quiet) {
			const r = await call(api.unlockRemembered);
			if (r.ok) { if (r.status) setStatus(r.status); return; }
			if (!quiet || r.code !== 'not_remembered') fail(r);
			refreshStatus();
		}

		// ── Screen ───────────────────────────────────────────
		function screen() {
			const g = VS.gate(S.status);
			if (g === 'intro' && S.flow === 'setup') return 'setup1';
			if (g === 'setup') return 'setup2';
			if (g === 'unlock' && S.flow === 'recover') return 'recover';
			if (g === 'home' && S.flow === 'setupDone') return 'setup3';
			if (g === 'home' && S.flow === 'recoverKey' && S.recoveryKey) return 'recoverKey';
			if ((g === 'home' || g === 'newpw') && S.flow === 'recoverBusy') return 'newpw';
			if (g === 'home') return `home:${S.sub}`;
			return g;
		}

		function render() {
			let key = screen();
			// the unlock screen changes with Windows Hello (on, blocked, not available here)
			if (key === 'unlock') key = `unlock|${VS.helloView(S.status, t).key}`;
			if (key !== S.built) {
				closeMenu();
				if (!key.startsWith('home')) closeDialog();
				S.built = key;
				build(key);
			} else {
				update();
			}
			renderFoot();
		}

		function build(key) {
			clear(rootEl);
			refs.body = null;
			if (key.startsWith('home:')) return buildHome(key.slice(5));
			const box = el('div', { class: 'vt-gate' });
			rootEl.appendChild(box);
			switch (key.split('|')[0]) {
				case 'loading': return box.appendChild(stateCard('lock', t('vault.loading'), null));
				case 'unavailable':
				case 'error': return box.appendChild(stateCard('cloudOff', t('vault.unavailable.title'), t('vault.unavailable.hint'), { label: t('vault.retry'), run: () => call(api.check).then((r) => { if (r.status) setStatus(r.status); else refreshStatus(); }) }));
				case 'intro': return box.appendChild(buildIntro());
				case 'setup1': return box.appendChild(buildSetupPassword());
				case 'setup2': return box.appendChild(buildSetupKey());
				case 'setup3': return box.appendChild(buildSetupDone());
				case 'unlock': return box.appendChild(buildUnlock());
				case 'recover': return box.appendChild(buildRecover());
				case 'newpw': return box.appendChild(buildNewPassword());
				case 'recoverKey': return box.appendChild(buildRecoveryKey(S.recoveryKey, { title: t('vault.recover.newKeyTitle'), step: null, done: () => { S.flow = null; S.recoveryKey = null; render(); } }));
				default: return box.appendChild(stateCard('lock', t('vault.loading'), null));
			}
		}

		function stateCard(name, title, hint, action) {
			return el('div', { class: 'card vt-gate-card', style: 'align-items:center;text-align:center' }, [
				el('div', { class: 'vt-gate-icon' }, [icon(name, 26)]),
				el('h2', { class: 'disp', text: title }),
				hint ? el('p', { class: 'vt-desc', text: hint }) : null,
				action ? btn('btn-sec', action.label, action.run) : null,
			]);
		}

		/** Light changes without rebuilding forms: head, lists, detail. */
		function update() {
			if (!S.built || !S.built.startsWith('home:')) return;
			renderHead();
			switch (S.sub) {
				case 'list': renderChips(); renderList(); if (S.mode === 'view') renderDetail(); break;
				case 'trash': renderTrash(); break;
				case 'vaults': renderVaults(); break;
				case 'vault': renderVault(); break;
				default: break;
			}
		}

		// ── Footer (status bar) and the 1-second tick ────────
		function renderFoot() {
			refs.sbLock.textContent = VS.lockText(t, S.status, S.lastActivity, now());
			refs.sbClip.hidden = !(S.status && S.status.unlocked);
		}
		let ticker = null;
		function tick() {
			renderFoot();
			tickShares();
			const tp = S.totp;
			if (tp && refs.totpCode && refs.totpCode.isConnected) {
				tp.left -= 1;
				if (tp.left <= 0) fetchTotp(tp.arg, tp.key);
				else paintTotp();
			}
		}

		// ── Intro, setup ─────────────────────────────────────
		function buildIntro() {
			return el('div', { class: 'card vt-gate-card' }, [
				el('div', { class: 'vt-gate-icon' }, [icon('shield', 26)]),
				el('h2', { class: 'disp', text: t('vault.intro.title') }),
				el('p', { class: 'vt-desc', text: t('vault.intro.text') }),
				el('div', { class: 'vt-form-acts', style: 'justify-content:flex-start' }, [
					btn('btn-pri', t('vault.intro.start'), () => { S.flow = 'setup'; render(); }, { id: 'vault-setup-start' }),
				]),
			]);
		}

		function steps(n, total = 3) {
			const bar = el('div', { class: 'vt-steps', 'aria-hidden': 'true' });
			for (let i = 1; i <= total; i++) bar.appendChild(el('span', { class: i <= n ? 'on' : '' }));
			return el('div', { class: 'vt-block' }, [el('span', { class: 'vt-step', text: t('vault.setup.step', { n, total }) }), bar]);
		}

		/** Password input with show / hide. */
		function pwInput(attrs) {
			const input = el('input', { class: 'inp', type: 'password', autocomplete: 'off', spellcheck: 'false', ...attrs });
			const toggle = el('button', { type: 'button', class: 'btn btn-sec btn-icon vt-ib', title: t('vault.reveal'), 'aria-label': t('vault.reveal'), 'aria-pressed': 'false' }, [icon('eye', 17)]);
			toggle.addEventListener('click', () => {
				const show = input.type === 'password';
				input.type = show ? 'text' : 'password';
				clear(toggle).appendChild(icon(show ? 'eyeOff' : 'eye', 17));
				const label = t(show ? 'vault.conceal' : 'vault.reveal');
				toggle.title = label;
				toggle.setAttribute('aria-label', label);
				toggle.setAttribute('aria-pressed', show ? 'true' : 'false');
			});
			return { input, box: el('div', { class: 'vt-pw' }, [input, toggle]) };
		}

		function meter() {
			const m = el('div', { class: 'vt-meter', 'aria-live': 'polite' });
			const bars = el('span', { class: 'vt-meter-bars', 'aria-hidden': 'true' }, [el('span'), el('span'), el('span'), el('span')]);
			const label = el('b');
			const detail = el('span');
			m.append(bars, label, detail);
			return {
				el: m,
				set(res, pw) {
					const v = VS.strengthView(res, pw, t);
					m.className = `vt-meter ${v.cls}`;
					label.textContent = v.label;
					detail.textContent = v.detail;
				},
			};
		}

		/** Master password + repeat with strength (setup, recovery, change) → { el, value(), ok(), focus() }. */
		function masterFields({ label, onChange, autofocus }) {
			const a = pwInput({ id: 'vault-pw-new', 'aria-label': label, autofocus: autofocus ? true : null });
			const b = pwInput({ id: 'vault-pw-repeat', 'aria-label': t('vault.setup.pwRepeat') });
			const m = meter();
			const hint = el('span', { class: 'vt-hint' });
			let res = null;
			let seq = 0;
			let timer = null;
			const state = () => VS.masterCheck(a.input.value, b.input.value, res);
			const paint = () => {
				const c = state();
				hint.textContent = c.hint ? t(c.hint) : t('vault.setup.pwRule');
				hint.className = c.ok ? 'vt-hint vt-hint-ok' : c.hint === 'vault.setup.pwMismatch' ? 'vt-hint vt-err' : 'vt-hint';
				m.set(res, a.input.value);
				if (onChange) onChange(c.ok);
			};
			a.input.addEventListener('input', () => {
				clearTimeout(timer);
				const pw = a.input.value;
				if (!pw) { res = null; paint(); return; }
				const my = ++seq;
				timer = setTimeout(async () => {
					const r = await call(api.strength, pw);
					if (my !== seq) return;
					res = r;
					paint();
				}, 120);
				paint();
			});
			b.input.addEventListener('input', paint);
			paint();
			return {
				el: el('div', { class: 'vt-form' }, [
					el('div', { class: 'field' }, [el('label', { for: 'vault-pw-new', text: label }), a.box, m.el]),
					el('div', { class: 'field' }, [el('label', { for: 'vault-pw-repeat', text: t('vault.setup.pwRepeat') }), b.box, hint]),
				]),
				value: () => a.input.value,
				ok: () => state().ok,
				clear: () => { a.input.value = ''; b.input.value = ''; res = null; paint(); },
				inputs: [a.input, b.input],
			};
		}

		function buildSetupPassword() {
			const err = el('div', { class: 'vt-err', role: 'alert' });
			const next = btn('btn-pri', t('vault.next'), () => submit(), { id: 'vault-setup-next', disabled: true });
			const f = masterFields({ label: t('vault.setup.pwLabel'), onChange: (ok) => { next.disabled = !ok; }, autofocus: true });
			const submit = async () => {
				if (!f.ok() || next.disabled) return;
				next.disabled = true;
				err.textContent = '';
				next.textContent = t('vault.setup.creating');
				S.setupBusy = true;
				const r = await call(api.setup, f.value());
				S.setupBusy = false;
				next.textContent = t('vault.next');
				next.disabled = false;
				if (!r.ok) { err.textContent = VS.errorText(r, t); return; }
				f.clear();
				S.setupKey = r.recoveryKey;
				// vault:state (setupPending) may have come before this answer: show the key now
				if (S.built === 'setup2') S.built = null;
				refreshStatus();
			};
			for (const i of f.inputs) i.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
			return el('div', { class: 'card vt-gate-card' }, [
				steps(1),
				el('h2', { class: 'disp', text: t('vault.setup.pwTitle') }),
				el('p', { class: 'vt-desc', text: t('vault.setup.pwText') }),
				f.el,
				el('div', { class: 'vt-note vt-note-warn' }, [el('b', { text: t('vault.setup.warnTitle') }), el('div', { text: t('vault.setup.warnText') })]),
				err,
				el('div', { class: 'vt-form-acts' }, [btn('btn-ghost', t('vault.cancel'), () => { S.flow = null; render(); }), next]),
			]);
		}

		function printKey(key) {
			const sheet = el('div', { class: 'vt-print' }, [
				el('h1', { text: t('vault.recovery.printTitle') }),
				el('div', { class: 'vt-rk' }, VS.recoveryGroups(key).map((g) => el('span', { text: g }))),
				el('p', { text: t('vault.recovery.printNote', { date: new Date(now()).toLocaleDateString(locale() === 'en' ? 'en-GB' : 'de-DE') }) }),
			]);
			document.body.appendChild(sheet);
			document.body.classList.add('vt-printing');
			let done = false;
			const cleanup = () => {
				if (done) return;
				done = true;
				document.body.classList.remove('vt-printing');
				sheet.remove();
				window.removeEventListener('afterprint', cleanup);
			};
			window.addEventListener('afterprint', cleanup);
			setTimeout(cleanup, 120000);
			try { window.print(); } catch { cleanup(); }
		}

		/** The recovery key with print / copy / tips and the "kept safe" check (setup step 2, after a recovery). */
		function buildRecoveryKey(key, { title, step, done, back, busyText }) {
			const err = el('div', { class: 'vt-err', role: 'alert' });
			const next = btn('btn-pri', t('vault.next'), () => go(), { id: 'vault-recovery-next', disabled: true });
			const check = el('input', { type: 'checkbox', id: 'vault-recovery-ok', on: { change: () => { next.disabled = !check.checked; } } });
			const go = async () => {
				if (!check.checked) return;
				next.disabled = true;
				err.textContent = '';
				if (busyText) next.textContent = busyText;
				const r = await done();
				next.textContent = t('vault.next');
				next.disabled = !check.checked;
				if (r && r.ok === false) err.textContent = VS.errorText(r, t);
			};
			const tips = el('ol', { class: 'vt-tips' }, ['vault.recovery.tip1', 'vault.recovery.tip2', 'vault.recovery.tip3'].map((k, i) => el('li', null, [el('b', { text: String(i + 1) }), el('span', { text: t(k) })])));
			return el('div', { class: 'card vt-gate-card' }, [
				step ? steps(step) : null,
				el('h2', { class: 'disp', text: title }),
				el('p', { class: 'vt-desc', text: t('vault.recovery.text') }),
				el('div', { class: 'vt-rk', id: 'vault-recovery-key', 'aria-label': t('vault.recovery.label') }, VS.recoveryGroups(key).map((g) => el('span', { text: g }))),
				el('div', { class: 'vt-form-acts', style: 'justify-content:flex-start' }, [
					btn('btn-sec btn-sm', [icon('print', 15), el('span', { text: t('vault.recovery.print') })], () => printKey(key)),
					btn('btn-sec btn-sm', [icon('copy', 15), el('span', { text: t('vault.copy') })], () => copy({ text: key }, t('vault.recovery.label'))),
				]),
				tips,
				el('label', { class: 'vt-check' }, [check, el('span', { text: t('vault.recovery.confirm') })]),
				err,
				el('div', { class: 'vt-form-acts' }, [back ? btn('btn-ghost', t('vault.cancel'), back) : null, next]),
			]);
		}

		function buildSetupKey() {
			if (!S.setupKey && S.setupBusy) return stateCard('key', t('vault.setup.creating'), null);
			if (!S.setupKey) {
				// the key is gone (page reloaded): start over
				call(api.cancelSetup).then(() => { S.flow = 'setup'; refreshStatus(); });
				return stateCard('key', t('vault.loading'), null);
			}
			return buildRecoveryKey(S.setupKey, {
				title: t('vault.recovery.title'),
				step: 2,
				busyText: t('vault.setup.saving'),
				back: async () => { await call(api.cancelSetup); S.setupKey = null; S.flow = 'setup'; refreshStatus(); },
				done: async () => {
					const r = await call(api.confirmSetup);
					if (!r.ok && r.code === 'no_setup') {
						// locked meanwhile (or refused): the keys are gone — start again with the password
						S.setupKey = null;
						S.flow = 'setup';
						toast(VS.errorText(r, t), 'error');
						refreshStatus();
						return r;
					}
					if (!r.ok) return r;
					S.setupKey = null;
					S.flow = 'setupDone';
					if (r.status) setStatus(r.status); else refreshStatus();
					return r;
				},
			});
		}

		function rememberRow() {
			const st = S.status || {};
			// Windows Hello asks for the person every time: "Angemeldet bleiben" would open without them
			const usable = st.rememberAvailable && !st.hello;
			const sw = el('button', { type: 'button', class: `sw${st.remember ? ' on' : ''}`, role: 'switch', 'aria-checked': st.remember ? 'true' : 'false', 'aria-label': t('vault.remember.title'), id: 'vault-remember', disabled: usable ? null : true }, [el('span')]);
			sw.addEventListener('click', async () => {
				const on = !sw.classList.contains('on');
				sw.disabled = true;
				const r = await call(api.setSettings, { remember: on });
				sw.disabled = false;
				if (!r.ok) { fail(r); return; }
				sw.classList.toggle('on', !!r.remember);
				sw.setAttribute('aria-checked', r.remember ? 'true' : 'false');
				refreshStatus();
			});
			return el('div', { class: 'vt-set-row' }, [
				el('div', null, [el('b', { text: t('vault.remember.title') }), el('span', { text: st.hello ? t('vault.hello.rememberOff') : st.rememberAvailable ? t('vault.remember.text') : t('vault.remember.unavailable') })]),
				sw,
			]);
		}

		/** "Mit Windows Hello entsperren": on → the master password (dialog), then Windows asks; off at once. */
		function helloRow() {
			const st = S.status || {};
			const v = VS.helloSetting(st, t);
			const sw = el('button', { type: 'button', class: `sw${v.on ? ' on' : ''}`, role: 'switch', 'aria-checked': v.on ? 'true' : 'false', 'aria-label': t('vault.hello.title'), id: 'vault-hello', disabled: v.disabled ? true : null }, [el('span')]);
			sw.addEventListener('click', async () => {
				if (!v.on) { helloDialog(); return; }
				sw.disabled = true;
				const r = await call(api.setHello, false);
				sw.disabled = false;
				if (!r.ok) { fail(r); return; }
				toast(t('vault.hello.turnedOff'), 'info');
				await refreshStatus();
				renderSettings();
			});
			const texts = [el('b', { text: t('vault.hello.title') }), el('span', { text: v.text })];
			if (!v.on && !v.disabled && st.remember) texts.push(el('span', { text: t('vault.hello.replaces') }));
			const kids = [el('div', null, texts)];
			if (v.setup && typeof o.openExternal === 'function') {
				kids.push(btn('btn-sec btn-sm', [icon('external', 14), el('span', { text: t('vault.hello.openSettings') })], () => {
					Promise.resolve(o.openExternal('ms-settings:signinoptions')).catch(() => {});
				}, { id: 'vault-hello-setup' }));
			}
			kids.push(sw);
			return el('div', { class: 'vt-set-row', id: 'vault-hello-row' }, kids);
		}

		function helloDialog() {
			const pw = pwInput({ id: 'vault-hello-pw', 'aria-label': t('vault.unlock.password') });
			const err = el('div', { class: 'vt-err', role: 'alert' });
			let busy = false;
			const go = async () => {
				const b = d.buttons.go;
				if (busy || !pw.input.value) return;
				busy = true;
				b.disabled = true;
				b.textContent = t('vault.hello.busy');
				err.textContent = '';
				const r = await call(api.setHello, true, pw.input.value);
				busy = false;
				b.disabled = false;
				b.textContent = t('vault.hello.confirmButton');
				if (!r.ok) {
					err.textContent = VS.errorText(r, t);
					if (r.code === 'wrong_password') pw.input.select();
					return;
				}
				pw.input.value = '';
				closeDialog();
				toast(t('vault.hello.turnedOn'), 'success');
				await refreshStatus();
				renderSettings();
			};
			const d = dialog({
				title: t('vault.hello.confirmTitle'),
				body: [
					el('p', { class: 'vt-desc', text: t('vault.hello.confirmText') }),
					el('div', { class: 'field' }, [el('label', { for: 'vault-hello-pw', text: t('vault.unlock.password') }), pw.box]),
					err,
				],
				actions: [
					{ label: t('vault.cancel'), cls: 'btn-ghost', run: () => { if (!busy) closeDialog(); } },
					{ id: 'go', label: t('vault.hello.confirmButton'), cls: 'btn-pri', run: () => go() },
				],
				onClose: () => { pw.input.value = ''; },
			});
			d.buttons.go.id = 'vault-hello-confirm';
			pw.input.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
		}

		function buildSetupDone() {
			return el('div', { class: 'card vt-gate-card' }, [
				steps(3),
				el('h2', { class: 'disp', text: t('vault.setup.doneTitle') }),
				el('p', { class: 'vt-desc', text: t('vault.setup.doneText') }),
				rememberRow(),
				el('div', { class: 'vt-set-row' }, [
					el('div', null, [el('b', { text: t('vault.quickInfo.title') }), el('span', { text: t('vault.quickInfo.text') })]),
					el('span', { class: 'vt-kbd', text: t('vault.shortcut') }),
				]),
				el('div', { class: 'vt-form-acts' }, [btn('btn-pri', t('vault.setup.finish'), () => { S.flow = null; render(); }, { id: 'vault-setup-finish' })]),
			]);
		}

		// ── Unlock, recovery ─────────────────────────────────
		function buildUnlock() {
			const st = S.status || {};
			const hv = VS.helloView(st, t);
			const err = el('div', { class: 'vt-err', role: 'alert', text: S.unlockErr || '' });
			refs.unlockErr = err;
			const pw = pwInput({ id: 'vault-unlock-pw', 'aria-label': t('vault.unlock.password'), autofocus: hv.primary ? null : true });
			const remember = el('input', { type: 'checkbox', id: 'vault-unlock-remember', checked: !!st.remember });
			const go = btn(hv.primary ? 'btn-sec' : 'btn-pri', t('vault.unlock.button'), () => submit(), { id: 'vault-unlock' });
			// Windows Hello first when it is on; the master password stays below
			refs.helloBtn = hv.primary
				? btn('btn-pri btn-lg', [icon('hello', 20), el('span', { text: t(S.helloBusy ? 'vault.hello.busy' : 'vault.hello.button') })], () => unlockHello(false), { id: 'vault-unlock-hello', disabled: S.helloBusy ? true : null })
				: null;
			const submit = async () => {
				const v = pw.input.value;
				if (!v || go.disabled) return;
				go.disabled = true;
				showUnlockErr(null);
				go.textContent = t('vault.unlock.busy');
				const r = await call(api.unlock, v);
				go.textContent = t('vault.unlock.button');
				go.disabled = false;
				if (!r.ok) {
					err.textContent = VS.errorText(r, t);
					pw.input.select();
					return;
				}
				pw.input.value = '';
				if (st.rememberAvailable && !st.hello && remember.checked !== !!st.remember) {
					const s = await call(api.setSettings, { remember: remember.checked });
					if (!s.ok) fail(s);
				}
				if (r.status) setStatus(r.status); else refreshStatus();
			};
			pw.input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
			const last = Number.isFinite(st.lastSyncAt) ? t('vault.locked.lastSync', { when: VS.when(st.lastSyncAt, t, locale(), now()) }) : '';
			return el('div', { class: 'card vt-gate-card' }, [
				el('div', { class: 'vt-gate-icon' }, [icon('lock', 26)]),
				el('h2', { class: 'disp', text: t('vault.locked.title') }),
				last ? el('p', { class: 'vt-desc', text: last }) : null,
				st.remember && st.rememberAvailable ? btn('btn-sec', [icon('unlock', 16), el('span', { text: t('vault.unlock.remembered') })], () => unlockRemembered(false), { id: 'vault-unlock-remembered' }) : null,
				refs.helloBtn,
				refs.helloBtn ? el('div', { class: 'vt-or', text: t('vault.hello.orPassword') }) : null,
				hv.hint ? el('div', { class: 'vt-hello-hint', id: 'vault-hello-hint' }, [icon('hello', 16), el('span', { text: hv.hint })]) : null,
				el('div', { class: 'field' }, [el('label', { for: 'vault-unlock-pw', text: t('vault.unlock.password') }), pw.box]),
				st.rememberAvailable && !st.hello ? el('label', { class: 'vt-check' }, [remember, el('span', { text: t('vault.remember.title') })]) : null,
				err,
				el('div', { class: 'vt-form-acts' }, [
					el('button', { type: 'button', class: 'vt-link', id: 'vault-forgot', text: t('vault.unlock.forgot'), on: { click: () => { S.flow = 'recover'; render(); } } }),
					el('span', { class: 'vt-grow' }),
					go,
				]),
			]);
		}

		function buildRecover() {
			const err = el('div', { class: 'vt-err', role: 'alert' });
			const input = el('input', { class: 'inp mono', id: 'vault-recover-key', autocomplete: 'off', spellcheck: 'false', placeholder: 'XXXX-XXXX-XXXX-…', 'aria-label': t('vault.recover.key') });
			const go = btn('btn-pri', t('vault.next'), () => submit(), { id: 'vault-recover-next' });
			const submit = async () => {
				const v = input.value.trim();
				if (!v || go.disabled) return;
				go.disabled = true;
				err.textContent = '';
				const r = await call(api.recover, v);
				go.disabled = false;
				if (!r.ok) {
					err.textContent = r.code === 'recovery_key' && !VS.recoveryComplete(v) ? `${VS.errorText(r, t)} ${t('vault.recover.typo')}` : VS.errorText(r, t);
					return;
				}
				input.value = '';
				S.flow = null;
				if (r.status) setStatus(r.status); else refreshStatus();
			};
			input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
			setTimeout(() => input.focus(), 0);
			return el('div', { class: 'card vt-gate-card' }, [
				el('div', { class: 'vt-gate-icon' }, [icon('key', 26)]),
				el('h2', { class: 'disp', text: t('vault.recover.title') }),
				el('p', { class: 'vt-desc', text: t('vault.recover.text') }),
				el('div', { class: 'field' }, [el('label', { for: 'vault-recover-key', text: t('vault.recover.key') }), input]),
				err,
				el('div', { class: 'vt-form-acts' }, [btn('btn-ghost', t('vault.back'), () => { S.flow = null; render(); }), go]),
			]);
		}

		function buildNewPassword() {
			const err = el('div', { class: 'vt-err', role: 'alert' });
			const go = btn('btn-pri', t('vault.next'), () => submit(), { id: 'vault-newpw-next', disabled: true });
			const f = masterFields({ label: t('vault.recover.newPw'), onChange: (ok) => { go.disabled = !ok; }, autofocus: true });
			const submit = async () => {
				if (!f.ok() || go.disabled) return;
				go.disabled = true;
				err.textContent = '';
				go.textContent = t('vault.setup.creating');
				S.flow = 'recoverBusy'; // its vault:state (recovering: false) can come before the answer
				const r = await call(api.completeRecovery, f.value());
				go.textContent = t('vault.next');
				go.disabled = false;
				if (!r.ok) { S.flow = null; err.textContent = VS.errorText(r, t); render(); return; }
				f.clear();
				S.recoveryKey = r.recoveryKey;
				S.flow = 'recoverKey';
				refreshStatus();
			};
			for (const i of f.inputs) i.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
			return el('div', { class: 'card vt-gate-card' }, [
				el('div', { class: 'vt-gate-icon' }, [icon('key', 26)]),
				el('h2', { class: 'disp', text: t('vault.recover.newPw') }),
				el('p', { class: 'vt-desc', text: t('vault.recover.newPwText') }),
				f.el,
				err,
				el('div', { class: 'vt-form-acts' }, [btn('btn-ghost', t('vault.lock'), () => call(api.lock).then(() => refreshStatus())), go]),
			]);
		}

		// ── Home: head, chips, list, detail ──────────────────
		function buildHome(sub) {
			refs.sub = el('span', { class: 'vt-sub', id: 'vault-sub' });
			refs.h = el('h1', { class: 'vt-h1', text: t('vault.title') });
			refs.search = el('input', {
				type: 'search', id: 'vault-search', 'aria-label': t('vault.search'), placeholder: t('vault.search'), value: S.query, autocomplete: 'off', spellcheck: 'false',
				on: {
					input: () => { S.query = refs.search.value; if (S.sub !== 'list') setSub('list'); else { renderList(); } },
					keydown: (e) => {
						if (e.key === 'Escape' && refs.search.value) { e.stopPropagation(); refs.search.value = ''; S.query = ''; renderList(); }
						if (e.key === 'ArrowDown') { const first = refs.list && refs.list.querySelector('.vt-row'); if (first) { e.preventDefault(); first.focus(); } }
						if (e.key === 'Enter') { const hits = visibleEntries(); if (hits.length) selectEntry(hits[0].id); }
					},
				},
			});
			const newBtn = btn('btn-pri', [icon('plus', 16, '2.4'), el('span', { text: t('vault.new') })], () => {
				menu(newBtn, VS.TYPES.map((tp) => ({ icon: tp, label: t(`vault.type.${tp}`), run: () => startNew(tp) })));
			}, { id: 'vault-new', 'aria-haspopup': 'menu', 'aria-expanded': 'false', disabled: VS.writableVaults(S.vaults).length || !S.loaded ? null : true });
			refs.newBtn = newBtn;
			const moreBtn = iconBtn('btn-sec', 'more', t('vault.more'), () => {
				menu(moreBtn, [
					{ icon: 'users', label: t('vault.menu.vaults'), run: () => setSub('vaults') },
					{ icon: 'lifebuoy', label: t('vault.menu.emergency'), run: () => setSub('emergency') },
					{ icon: 'upload', label: t('vault.menu.import'), run: () => setSub('import') },
					{ icon: 'trash', label: t('vault.menu.trash'), run: () => setSub('trash') },
					{ icon: 'settings', label: t('vault.menu.settings'), run: () => setSub('settings') },
					{ icon: 'refresh', label: t('vault.menu.sync'), run: () => syncNow() },
				]);
			}, { id: 'vault-more', 'aria-haspopup': 'menu', 'aria-expanded': 'false' });
			const lockBtn = iconBtn('btn-sec', 'lock', t('vault.lock'), () => lockNow(), { id: 'vault-lock' });
			rootEl.appendChild(el('div', { class: 'vt-head' }, [
				el('div', { class: 'vt-head-tx' }, [refs.h, refs.sub]),
				el('label', { class: 'vt-search' }, [icon('search', 16), refs.search, el('span', { class: 'vt-kbd', text: t('vault.shortcut'), title: t('vault.quickInfo.text') })]),
				newBtn,
				moreBtn,
				lockBtn,
			]));
			refs.banners = el('div', { class: 'vt-banners' });
			rootEl.appendChild(refs.banners);
			refs.chips = null;
			refs.list = null;
			refs.detail = null;
			refs.page = null;
			if (sub === 'list') {
				refs.chips = el('div', { class: 'seg vt-chips', role: 'group', 'aria-label': t('vault.filter.label') });
				refs.list = el('section', { class: 'card vt-list', id: 'vault-list', 'aria-label': t('vault.list') });
				refs.detail = el('section', { class: 'card vt-detail', id: 'vault-detail', 'aria-label': t('vault.entry') });
				rootEl.append(refs.chips, el('div', { class: 'vt-cols' }, [refs.list, refs.detail]));
				refs.detailKey = null;
				renderHead();
				renderChips();
				renderList();
				renderDetail(true);
				return;
			}
			refs.page = el('div', { class: 'vt-page', id: `vault-page-${sub}` });
			rootEl.appendChild(refs.page);
			renderHead();
			switch (sub) {
				case 'trash': return buildTrash();
				case 'vaults': return buildVaults();
				case 'vault': return buildVault();
				case 'emergency': return buildEmergency();
				case 'emView': return buildEmergencyView();
				case 'import': return buildImport();
				case 'settings': return buildSettings();
				default: return null;
			}
		}

		function setSub(sub) {
			if (S.sub === 'list' && S.mode === 'edit' && sub !== 'list') {
				leaveEdit().then((ok) => { if (ok) { S.sub = sub; render(); } });
				return;
			}
			if (sub !== 'import') S.imp = null;
			if (sub !== 'emView') S.emView = null;
			// settings chosen again: built again (asks Windows Hello's availability again)
			if (sub === 'settings' && S.sub === 'settings') S.built = null;
			S.sub = sub;
			render();
		}

		function pageHead(title, extra) {
			return el('div', { class: 'vt-page-head' }, [
				btn('btn-ghost btn-sm', [icon('back', 16), el('span', { text: t('vault.back') })], () => setSub(S.sub === 'vault' ? 'vaults' : S.sub === 'emView' ? 'emergency' : 'list'), { id: 'vault-back' }),
				el('h2', { class: 'disp', text: title }),
				...(extra || []),
			]);
		}

		async function syncNow() {
			const r = await call(api.sync);
			if (!r.ok) fail(r);
			refreshStatus();
		}

		async function lockNow() {
			if (S.mode === 'edit' && !(await leaveEdit())) return;
			const r = await call(api.lock);
			if (r.status) setStatus(r.status); else refreshStatus();
		}

		function renderHead() {
			if (!refs.sub) return;
			const count = S.entries.length;
			refs.sub.textContent = S.loaded ? VS.headerText(t, { entries: count, vaults: S.vaults.length, status: S.status }, locale(), now()) : t('vault.loading');
			if (refs.newBtn) refs.newBtn.disabled = !VS.writableVaults(S.vaults).length;
			clear(refs.banners);
			const st = S.status || {};
			for (const n of st.notices || []) {
				const key = `vault.notice.${['conflict', 'limit', 'refused'].includes(n.code) ? n.code : 'refused'}`;
				refs.banners.appendChild(el('div', { class: 'vt-banner vt-banner-warn', role: 'status' }, [
					icon('alert', 16), el('span', { text: t(key) }),
					btn('btn-ghost btn-sm', t('vault.notice.dismiss'), () => call(api.clearNotices).then(refreshStatus)),
				]));
			}
			if (S.unreadable > 0) refs.banners.appendChild(el('div', { class: 'vt-banner vt-banner-info', role: 'status' }, [icon('alert', 16), el('span', { text: VS.plural(t, 'vault.unreadable', S.unreadable) })]));
			if (S.listErr) refs.banners.appendChild(el('div', { class: 'vt-banner vt-banner-warn', role: 'status' }, [icon('cloudOff', 16), el('span', { text: VS.errorText(S.listErr, t) }), btn('btn-ghost btn-sm', t('vault.retry'), () => loadData())]));
		}

		function renderChips() {
			if (!refs.chips) return;
			clear(refs.chips);
			refs.chips.hidden = S.vaults.length < 2;
			for (const c of VS.filterChips(S.vaults, t)) {
				const on = c.id === S.filter;
				refs.chips.appendChild(el('button', { type: 'button', class: on ? 'on' : '', 'aria-pressed': on ? 'true' : 'false', text: c.label, on: { click: () => { S.filter = c.id; renderChips(); renderList(); } } }));
			}
		}

		const visibleEntries = () => VS.filterEntries(S.entries, { vaultId: S.filter, query: S.query });

		function entryRow(e, nm, { onClick, selected, acts, showVault = true } = {}) {
			const kids = [
				avatar(e.title),
				el('span', { class: 'vt-row-tx' }, [
					el('span', { class: 'vt-row-title' }, [el('span', { class: 'vt-ellipsis', text: e.title || '…' }), e.fav ? el('span', { class: 'vt-fav', title: t('vault.section.favorites') }, [icon('star', 12)]) : null, e.pending ? el('span', { class: 'chip vt-chip-sm c-warn', title: t('vault.pending'), text: '•' }) : null]),
					el('span', { class: 'vt-row-sub', text: VS.rowSub(e) || t(`vault.type.${VS.TYPES.includes(e.type) ? e.type : 'note'}`) }),
				]),
				showVault ? el('span', { class: 'vt-row-vault', text: nm.get(e.vaultId) || '' }) : null,
				acts || null,
			];
			if (!onClick) return el('div', { class: 'vt-row', 'data-id': e.id }, kids);
			return el('button', { type: 'button', class: `vt-row${selected ? ' is-sel' : ''}`, 'data-id': e.id, 'aria-current': selected ? 'true' : null, on: { click: onClick, keydown: rowKeys } }, kids);
		}

		function rowKeys(e) {
			if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
			const rows = [...e.currentTarget.parentElement.querySelectorAll('.vt-row')];
			const i = rows.indexOf(e.currentTarget);
			const next = rows[e.key === 'ArrowDown' ? i + 1 : i - 1];
			if (next) { e.preventDefault(); next.focus(); next.click(); } else if (e.key === 'ArrowUp' && refs.search) { e.preventDefault(); refs.search.focus(); }
		}

		function renderList() {
			if (!refs.list) return;
			const focused = document.activeElement && refs.list.contains(document.activeElement) ? document.activeElement.getAttribute('data-id') : null;
			clear(refs.list);
			if (!S.loaded) { refs.list.appendChild(el('div', { class: 'vt-empty', text: t('vault.loading') })); return; }
			const list = visibleEntries();
			if (!list.length) {
				refs.list.appendChild(el('div', { class: 'vt-empty', text: S.entries.length ? t('vault.noResults') : t('vault.empty') }));
				return;
			}
			const nm = names();
			const multi = S.vaults.length > 1 && !S.filter;
			for (const sec of VS.sections(list, { query: S.query })) {
				if (sec.key === 'favorites' || (sec.key === 'all' && list.some((e) => e.fav) && !S.query.trim())) refs.list.appendChild(el('div', { class: 'lbl vt-list-sec', text: t(`vault.section.${sec.key}`) }));
				for (const e of sec.items) refs.list.appendChild(entryRow(e, nm, { onClick: () => selectEntry(e.id), selected: e.id === S.selId, showVault: multi }));
			}
			if (focused) {
				const again = refs.list.querySelector(`.vt-row[data-id="${CSS.escape(focused)}"]`);
				if (again) again.focus();
			}
		}

		async function selectEntry(id) {
			if (S.selId === id && S.mode === 'view') return;
			if (S.mode === 'edit' && !(await leaveEdit())) return;
			S.selId = id;
			S.mode = 'view';
			S.history = null;
			S.revealed.clear();
			S.detail = null;
			S.detailErr = null;
			S.totp = null;
			S.shares = null;
			renderList();
			renderDetail(true);
			loadDetail(id, false);
		}

		async function loadDetail(id, quiet) {
			const r = await call(api.entry, id);
			if (S.selId !== id) return;
			if (r.ok && r.entry) {
				const changed = !S.detail || S.detail.rev !== r.entry.rev;
				S.detail = r.entry;
				S.detailErr = null;
				if (changed && quiet) S.revealed.clear();
			} else {
				S.detail = null;
				S.detailErr = r;
			}
			if (S.mode === 'view') renderDetail(true);
		}

		function detailKey() {
			const d = S.detail;
			return `${S.selId}|${d ? `${d.rev}|${d.pending}|${d.vaultId}` : S.detailErr ? 'err' : 'load'}|${[...S.revealed].join(',')}|${S.mode}|${S.vaults.map((v) => `${v.id}:${v.canWrite}:${v.name}`).join(',')}`;
		}

		function renderDetail(force) {
			if (!refs.detail) return;
			if (S.mode === 'edit') return;
			const key = detailKey();
			if (!force && key === refs.detailKey) return;
			refs.detailKey = key;
			clear(refs.detail);
			refs.totpCode = null;
			if (!S.selId) {
				refs.detail.appendChild(el('div', { class: 'vt-placeholder' }, [icon('shield', 34, '1.5'), el('span', { text: S.entries.length ? t('vault.noSelection') : t('vault.empty') })]));
				return;
			}
			if (!S.detail) {
				if (S.detailErr) refs.detail.appendChild(el('div', { class: 'vt-placeholder' }, [icon('alert', 30, '1.5'), el('span', { text: VS.errorText(S.detailErr, t) })]));
				else refs.detail.appendChild(el('div', { class: 'vt-placeholder', text: t('vault.loading') }));
				return;
			}
			if (S.mode === 'history') { renderHistory(); return; }
			const d = S.detail;
			const writable = canWrite(d.vaultId);
			refs.detail.append(...detailNodes(d, {
				vaultName: names().get(d.vaultId) || '',
				writable,
				onEdit: () => startEdit(),
				onFav: () => toggleFav(),
				foot: [
					btn('btn-ghost btn-sm', [icon('history', 15), el('span', { text: t('vault.history.link') })], () => openHistory(), { id: 'vault-history' }),
					writable ? btn('btn-ghost btn-sm', [icon('trash', 15), el('span', { text: t('vault.trash.action') })], () => trashEntry(d), { id: 'vault-trash' }) : null,
					writable ? null : el('span', { class: 'chip vt-chip-sm', text: t('vault.readOnly') }),
				],
			}));
			if (VS.wifiShareable(d.data) && !d.trashed) {
				if (!S.shares || S.shares.id !== d.id || S.shares.rev !== d.rev) loadShares(d.id, d.rev);
				refs.detail.appendChild(shareBlock(d, writable));
			}
		}

		// ── Wi-Fi shares (plugin 1.4.0): „Freigabe auf Wandtablet“ / „Freigabe auf Portalseite“ ──
		// Main builds the copy from the decrypted entry (core VaultService.wifiShare); this page never sees it.
		async function loadShares(id, rev) {
			S.shares = { id, rev, view: null, err: null, at: now() };
			const r = await call(api.wifiShares, id);
			if (!S.shares || S.shares.id !== id) return;
			if (r.ok) S.shares.view = VS.shareView(r);
			else S.shares.err = r;
			if (S.selId === id && S.mode === 'view') renderDetail(true);
		}

		function shareBlock(d, writable) {
			const sh = S.shares && S.shares.id === d.id ? S.shares : null;
			const rows = el('div', { class: 'vt-shares' });
			if (!sh || (!sh.view && !sh.err)) rows.appendChild(el('span', { class: 'vt-note-line', text: t('vault.wifiShare.loading') }));
			else if (sh.err) rows.appendChild(el('div', { class: 'vt-note vt-note-err', text: VS.shareErrorText(sh.err, t) }));
			else {
				for (const x of sh.view.shares) {
					rows.appendChild(el('div', { class: 'vt-share', 'data-share': x.target }, [
						icon(x.target === 'wall' ? 'tablet' : 'globe', 18),
						el('div', { class: 'vt-share-tx' }, [
							el('b', { text: t(x.target === 'wall' ? 'vault.wifiShare.onWall' : 'vault.wifiShare.onPortal') }),
							el('span', { class: 'vt-note-line vt-share-left', 'data-until': x.expiresAt || '', text: VS.shareLeftText(t, x.expiresAt, now()) }),
							x.createdBy ? el('span', { class: 'vt-note-line', text: t('vault.wifiShare.by', { name: x.createdBy }) }) : null,
							x.current ? null : el('span', { class: 'vt-note-line vt-share-stale', text: t('vault.wifiShare.stale') }),
						]),
						x.canEnd && !x.current ? btn('btn-sec btn-xs', t('vault.wifiShare.update'), () => runShare(d, x.target, 'keep', 'vault.wifiShare.updated')) : null,
						x.canEnd ? btn('btn-danger btn-xs', t('vault.wifiShare.end'), () => endShare(d, x)) : null,
					]));
				}
				if (!sh.view.shares.length) rows.appendChild(el('span', { class: 'vt-note-line', text: t('vault.wifiShare.none') }));
			}
			const starts = sh && sh.view ? VS.shareStarts(sh.view, writable) : [];
			const acts = starts.map((tg) => btn('btn-sec btn-sm', [icon(tg === 'wall' ? 'tablet' : 'globe', 15), el('span', { text: t(tg === 'wall' ? 'vault.wifiShare.toWall' : 'vault.wifiShare.toPortal') })], () => shareDialog2(d, tg), { 'data-share-start': tg }));
			return el('div', { class: 'vt-block vt-share-block', id: 'vault-shares' }, [
				el('div', { class: 'vt-page-head' }, [el('span', { class: 'lbl', style: 'flex-grow:1', text: t('vault.wifiShare.title') })]),
				rows,
				acts.length ? el('div', { class: 'vt-share-acts' }, acts) : null,
				writable && sh && sh.view && !sh.view.targets.wall && !sh.view.shares.some((x) => x.target === 'wall') ? el('span', { class: 'vt-note-line', text: t('vault.wifiShare.noWall') }) : null,
			]);
		}

		/** The dialog: how long, and that everyone there sees the password. */
		function shareDialog2(d, target) {
			let choice = '1h';
			const opts = el('div', { class: 'vt-share-durations', role: 'radiogroup', 'aria-label': t('vault.wifiShare.duration') }, VS.SHARE_DURATIONS.map((k) => el('label', { class: 'vt-share-dur' }, [
				el('input', { type: 'radio', name: 'vt-share-dur', value: k, checked: k === choice, on: { change: () => { choice = k; } } }),
				el('span', { text: t(`vault.wifiShare.d.${k}`) }),
			])));
			const ssid = String((d.data.fields || {}).ssid || '');
			dialog({
				title: t(target === 'wall' ? 'vault.wifiShare.toWall' : 'vault.wifiShare.toPortal'),
				sub: t('vault.wifiShare.ask', { name: ssid }),
				body: [
					opts,
					el('div', { class: 'vt-note vt-note-warn', text: t(target === 'wall' ? 'vault.wifiShare.warnWall' : 'vault.wifiShare.warnPortal') }),
					el('span', { class: 'vt-note-line', text: t('vault.wifiShare.copyHint') }),
				],
				actions: [
					{ label: t('vault.cancel'), cls: 'btn-ghost', run: () => closeDialog() },
					{ id: 'go', label: t('vault.wifiShare.start'), cls: 'btn-pri', run: () => { closeDialog(); runShare(d, target, choice, target === 'wall' ? 'vault.wifiShare.startedWall' : 'vault.wifiShare.startedPortal'); } },
				],
			});
		}

		async function runShare(d, target, duration, okKey) {
			const r = await call(api.wifiShare, d.id, target, duration);
			if (r.ok) toast(t(okKey), 'success');
			else toast(VS.shareErrorText(r, t), 'error');
			if (S.selId === d.id) loadShares(d.id, d.rev);
		}

		async function endShare(d, x) {
			const r = await call(api.wifiShareEnd, x.id);
			if (r.ok) toast(t('vault.wifiShare.ended'), 'success');
			else toast(VS.shareErrorText(r, t), 'error');
			if (S.selId === d.id) loadShares(d.id, d.rev);
		}

		/** Every second: the time left of the shares on screen; one that is over → the list again (at most every 15 s). */
		function tickShares() {
			if (!refs.detail || !refs.detail.isConnected) return;
			let over = false;
			for (const n of refs.detail.querySelectorAll('.vt-share-left')) {
				const until = n.getAttribute('data-until');
				if (!until) continue;
				if (!(Date.parse(until) > now())) over = true;
				n.textContent = VS.shareLeftText(t, until, now());
			}
			if (over && S.shares && S.shares.view && S.selId === S.shares.id && now() - S.shares.at > 15000) loadShares(S.shares.id, S.shares.rev);
		}

		/**
		 * The detail of an entry (also read-only for emergency access):
		 * head, field rows with copy / open / reveal, 2FA code, notes, custom fields.
		 */
		function detailNodes(d, { vaultName, writable, onEdit, onFav, foot, emergencyId = null }) {
			const data = d.data || {};
			const fields = data.fields || {};
			const copyArg = (field) => (emergencyId ? { id: d.id, field, emergencyId } : { id: d.id, field });
			const out = [];
			out.push(el('div', { class: 'vt-d-head' }, [
				avatar(data.title, true),
				el('div', { class: 'vt-d-tx' }, [
					el('span', { class: 'vt-d-title', id: 'vault-detail-title', text: data.title || '…' }),
					el('span', { class: 'vt-d-sub', text: VS.changedText(t, d, vaultName, locale(), now()) }),
				]),
				el('div', { class: 'vt-d-acts' }, [
					d.pending ? el('span', { class: 'chip vt-chip-sm c-warn', text: t('vault.pending') }) : null,
					onFav && writable ? el('button', { type: 'button', class: `btn btn-ghost btn-icon vt-ib vt-fav-btn${d.fav ? ' is-on' : ''}`, title: t(d.fav ? 'vault.fav.remove' : 'vault.fav.add'), 'aria-label': t(d.fav ? 'vault.fav.remove' : 'vault.fav.add'), 'aria-pressed': d.fav ? 'true' : 'false', on: { click: onFav } }, [icon('star', 17)]) : null,
					onEdit && writable ? btn('btn-sec btn-sm', t('vault.edit.title'), onEdit, { id: 'vault-edit' }) : null,
				]),
			]));
			const grid = el('div', { class: 'vt-grid' });
			const add = (label, value, acts) => grid.append(el('span', { class: 'vt-grid-l', text: label }), value, el('div', { class: 'vt-grid-a' }, acts));
			for (const row of VS.detailRows(d)) {
				const label = t(row.label);
				if (row.totp) {
					const box = el('span', { class: 'vt-totp' });
					refs.totpCode = el('span', { class: 'vt-totp-code', id: 'vault-totp-code', text: '··· ···' });
					refs.totpRing = el('span', { class: 'vt-ring', 'aria-hidden': 'true' });
					refs.totpLeft = el('span', { class: 'vt-totp-left' });
					box.append(refs.totpCode, refs.totpRing, refs.totpLeft);
					add(label, box, [btn('btn-pri btn-xs', t('vault.copy'), () => copy(copyArg('totp'), label))]);
					const arg = emergencyId ? { id: d.id, emergencyId } : { id: d.id };
					const key = `${emergencyId || ''}:${d.id}:${d.rev}`;
					if (!S.totp || S.totp.key !== key) fetchTotp(arg, key); else paintTotp();
					continue;
				}
				const value = String(fields[row.key] || '');
				if (row.secret) {
					const rk = `${emergencyId || ''}:${row.key}`;
					const shown = S.revealed.has(rk);
					const text = shown ? value : row.key === 'number' ? VS.maskedNumber(value) : VS.mask(value);
					add(label, el('span', { class: `vt-grid-v vt-secret${shown ? ' is-shown' : ''}`, 'data-field': row.key, text }), [
						el('button', { type: 'button', class: 'btn btn-ghost btn-xs btn-icon vt-ib', title: t(shown ? 'vault.conceal' : 'vault.reveal'), 'aria-label': t(shown ? 'vault.conceal' : 'vault.reveal'), 'aria-pressed': shown ? 'true' : 'false', on: { click: () => { if (shown) S.revealed.delete(rk); else S.revealed.add(rk); rerenderDetail(); } } }, [icon(shown ? 'eyeOff' : 'eye', 16)]),
						btn(row.key === 'password' ? 'btn-pri btn-xs' : 'btn-sec btn-xs', t('vault.copy'), () => copy(copyArg(row.key), label), { 'data-copy': row.key }),
					]);
				} else {
					add(label, el('span', { class: `vt-grid-v${row.multiline ? ' is-multi' : ''}`, text: value }), [btn('btn-sec btn-xs', t('vault.copy'), () => copy(copyArg(row.key), label), { 'data-copy': row.key })]);
				}
			}
			(data.urls || []).forEach((u, i) => {
				const openable = VS.openableUrl(u);
				add(t('vault.field.url'), el('span', { class: 'vt-grid-v', text: u }), [
					i === 0 ? btn('btn-sec btn-xs', t('vault.copy'), () => copy(copyArg('url'), t('vault.field.url'))) : null,
					openable ? btn('btn-sec btn-xs', t('vault.open'), () => openUrl(u), { title: t('vault.openWebsite') }) : null,
				]);
			});
			if ((data.apps || []).length) add(t('vault.field.apps'), el('span', { class: 'vt-grid-v', text: data.apps.join(', ') }), []);
			(data.custom || []).forEach((c, i) => {
				const label = c.name || t('vault.custom.unnamed');
				const rk = `${emergencyId || ''}:custom:${i}`;
				const shown = !c.secret || S.revealed.has(rk);
				add(label, el('span', { class: `vt-grid-v${c.secret ? ' vt-secret' : ''}${c.secret && shown ? ' is-shown' : ''}`, text: shown ? c.value : VS.mask(c.value) }), [
					c.secret ? el('button', { type: 'button', class: 'btn btn-ghost btn-xs btn-icon vt-ib', title: t(shown ? 'vault.conceal' : 'vault.reveal'), 'aria-label': t(shown ? 'vault.conceal' : 'vault.reveal'), on: { click: () => { if (shown) S.revealed.delete(rk); else S.revealed.add(rk); rerenderDetail(); } } }, [icon(shown ? 'eyeOff' : 'eye', 16)]) : null,
					btn('btn-sec btn-xs', t('vault.copy'), () => copy(copyArg(`custom:${i}`), label)),
				]);
			});
			if (grid.childNodes.length) out.push(grid);
			if (data.notes) {
				out.push(el('div', { class: 'vt-block' }, [
					el('div', { class: 'vt-page-head' }, [el('span', { class: 'lbl', style: 'flex-grow:1', text: t('vault.field.notes') }), btn('btn-ghost btn-xs', t('vault.copy'), () => copy(copyArg('notes'), t('vault.field.notes')))]),
					el('div', { class: 'vt-notes', text: data.notes }),
				]));
			}
			if (d.trashed) out.push(el('div', { class: 'vt-note vt-note-neutral', text: t('vault.trash.info') }));
			if (foot && foot.some(Boolean)) out.push(el('div', { class: 'vt-d-foot' }, foot));
			return out;
		}

		function rerenderDetail() {
			if (S.sub === 'emView') renderEmergencyDetail();
			else renderDetail(true);
		}

		async function fetchTotp(arg, key) {
			S.totp = { key, arg, code: null, left: 0, period: 30, error: null };
			const r = await call(api.totp, arg);
			if (!S.totp || S.totp.key !== key) return;
			if (r.ok) Object.assign(S.totp, { code: r.code, left: Number(r.secondsLeft) || 30, period: Number(r.period) || 30 });
			else S.totp.error = r;
			paintTotp();
		}

		function paintTotp() {
			const tp = S.totp;
			if (!tp || !refs.totpCode) return;
			if (tp.error) {
				refs.totpCode.textContent = '—';
				refs.totpLeft.textContent = t('vault.totp.invalid');
				return;
			}
			if (!tp.code) return;
			refs.totpCode.textContent = VS.prettyCode(tp.code);
			refs.totpLeft.textContent = t('vault.totp.left', { seconds: Math.max(0, tp.left) });
			refs.totpRing.style.setProperty('--p', String(Math.max(0, Math.min(1, tp.left / tp.period))));
			const box = refs.totpCode.parentElement;
			if (box) box.classList.toggle('is-low', tp.left <= 5);
		}

		async function toggleFav() {
			const d = S.detail;
			if (!d) return;
			const data = { ...d.data, fav: !d.fav };
			if (!data.fav) delete data.fav;
			const r = await call(api.save, { id: d.id, vaultId: d.vaultId, data });
			if (!r.ok) fail(r);
		}

		async function trashEntry(d) {
			const r = await call(api.trash, d.id);
			if (!r.ok) { fail(r); return; }
			toast(t('vault.trash.moved', { title: d.data.title }), 'info');
			S.selId = null;
			S.detail = null;
			renderDetail(true);
		}

		// ── History ──────────────────────────────────────────
		async function openHistory() {
			S.mode = 'history';
			S.history = null;
			S.revealed.clear();
			renderDetail(true);
			const id = S.selId;
			const r = await call(api.history, id);
			if (S.selId !== id || S.mode !== 'history') return;
			S.history = r.ok ? (Array.isArray(r.history) ? r.history : []) : r;
			renderDetail(true);
		}

		function renderHistory() {
			const d = S.detail;
			const writable = canWrite(d.vaultId);
			refs.detail.appendChild(el('div', { class: 'vt-page-head' }, [
				btn('btn-ghost btn-sm', [icon('back', 16), el('span', { text: t('vault.back') })], () => { S.mode = 'view'; S.history = null; S.revealed.clear(); renderDetail(true); }),
				el('h2', { class: 'disp', text: `${t('vault.history.title')} · ${d.data.title}` }),
			]));
			const h = S.history;
			if (!h) { refs.detail.appendChild(el('div', { class: 'vt-empty', text: t('vault.loading') })); return; }
			if (!Array.isArray(h)) { refs.detail.appendChild(el('div', { class: 'vt-empty', text: VS.errorText(h, t) })); return; }
			if (!h.length) { refs.detail.appendChild(el('div', { class: 'vt-empty', text: t('vault.history.empty') })); return; }
			const list = el('div', { class: 'card vt-rows', id: 'vault-history-list' });
			for (const v of [...h].sort((a, b) => b.rev - a.rev)) {
				const rk = `h:${v.rev}`;
				const shown = S.revealed.has(rk);
				const pw = v.data && v.data.fields ? v.data.fields.password || '' : '';
				const user = v.data && v.data.fields ? v.data.fields.username || v.data.fields.email || '' : '';
				const meta = [VS.when(v.updatedAt, t, locale(), now()), v.device ? `„${v.device}“` : ''].filter(Boolean).join(' · ');
				list.appendChild(el('div', { class: 'vt-row', style: 'align-items:flex-start;flex-direction:column;gap:8px' }, [
					el('div', { class: 'vt-row-title' }, [el('span', { text: t('vault.history.version', { rev: v.rev }) }), el('span', { class: 'vt-row-sub', text: meta })]),
					el('div', { class: 'vt-row-sub', text: [v.data && v.data.title, user].filter(Boolean).join(' · ') }),
					pw ? el('div', { class: 'vt-totp' }, [
						el('span', { class: `vt-secret${shown ? ' is-shown' : ''}`, text: shown ? pw : VS.mask(pw) }),
						el('button', { type: 'button', class: 'btn btn-ghost btn-xs btn-icon vt-ib', title: t(shown ? 'vault.conceal' : 'vault.reveal'), 'aria-label': t(shown ? 'vault.conceal' : 'vault.reveal'), on: { click: () => { if (shown) S.revealed.delete(rk); else S.revealed.add(rk); renderDetail(true); } } }, [icon(shown ? 'eyeOff' : 'eye', 16)]),
						btn('btn-sec btn-xs', t('vault.copy'), () => copy({ text: pw }, t('vault.field.password'))),
					]) : null,
					writable ? btn('btn-sec btn-xs', t('vault.history.restore'), async () => {
						const r = await call(api.save, { id: d.id, vaultId: d.vaultId, data: v.data });
						if (!r.ok) { fail(r); return; }
						toast(t('vault.history.restored'), 'success');
						S.mode = 'view';
						S.history = null;
						S.revealed.clear();
						loadDetail(d.id, true);
					}) : null,
				]));
			}
			refs.detail.appendChild(list);
		}

		// ── Edit ─────────────────────────────────────────────
		function defaultVault() {
			const w = VS.writableVaults(S.vaults);
			if (S.filter && w.some((v) => v.id === S.filter)) return S.filter;
			return (w.find((v) => v.personal) || w[0] || {}).id || null;
		}

		async function startNew(type) {
			if (S.mode === 'edit' && !(await leaveEdit())) return;
			if (S.sub !== 'list') { S.sub = 'list'; render(); }
			S.selId = null;
			S.detail = null;
			S.totp = null;
			S.draft = VS.emptyDraft(type, defaultVault());
			S.draftBase = JSON.parse(JSON.stringify(S.draft));
			S.gen = null;
			S.mode = 'edit';
			renderList();
			buildEdit();
		}

		function startEdit() {
			if (!S.detail) return;
			S.draft = VS.draftFrom(S.detail);
			S.draftBase = JSON.parse(JSON.stringify(S.draft));
			S.gen = null;
			S.mode = 'edit';
			buildEdit();
		}

		/** → true when the edit was left (saved nothing, or the person discarded the changes). */
		async function leaveEdit() {
			if (S.mode !== 'edit') return true;
			if (VS.draftChanged(S.draft, S.draftBase) && !(await confirm(t('vault.discard.title'), t('vault.discard.yes'), true))) return false;
			endEdit();
			return true;
		}

		function endEdit() {
			S.mode = 'view';
			S.draft = null;
			S.draftBase = null;
			S.gen = null;
			refs.detailKey = null;
			renderDetail(true);
		}

		function buildEdit() {
			if (!refs.detail) return;
			clear(refs.detail);
			refs.totpCode = null;
			const dr = S.draft;
			const isNew = !dr.id;
			const err = el('div', { class: 'vt-err', role: 'alert', id: 'vault-edit-error' });
			const field = (id, label, input, extra) => el('div', { class: 'field' }, [el('label', { for: id, text: label }), input, ...(extra || [])]);
			const text = (id, value, set, attrs) => el('input', { class: 'inp', id, value, autocomplete: 'off', spellcheck: 'false', on: { input: (e) => set(e.target.value) }, ...(attrs || {}) });
			const secret = (id, value, set, label) => {
				const p = pwInput({ id, 'aria-label': label });
				p.input.value = value;
				p.input.addEventListener('input', (e) => set(e.target.value));
				return p;
			};

			const form = el('form', { class: 'vt-form', id: 'vault-edit-form', on: { submit: (e) => { e.preventDefault(); save(); } } });
			form.appendChild(el('div', { class: 'vt-page-head' }, [el('h2', { class: 'disp', text: isNew ? t(`vault.newType.${dr.type}`) : t('vault.edit.title') })]));

			// type (new entries) and vault
			const types = el('select', { class: 'inp', id: 'vault-edit-type', on: { change: (e) => { dr.type = e.target.value; if (dr.type === 'login' && !dr.urls.length) dr.urls = ['']; buildEdit(); } } },
				VS.TYPES.map((tp) => el('option', { value: tp, text: t(`vault.type.${tp}`), selected: tp === dr.type ? true : null })));
			const vaults = el('select', { class: 'inp', id: 'vault-edit-vault', disabled: isNew ? null : true, on: { change: (e) => { dr.vaultId = e.target.value; } } },
				VS.writableVaults(S.vaults).map((v) => el('option', { value: v.id, text: names().get(v.id), selected: v.id === dr.vaultId ? true : null })));
			form.appendChild(el('div', { class: 'vt-form-row' }, [
				field('vault-edit-title', t('vault.field.title'), text('vault-edit-title', dr.title, (v) => { dr.title = v; }, { autofocus: true, required: true })),
				isNew ? field('vault-edit-type', t('vault.edit.type'), types) : null,
				field('vault-edit-vault', t('vault.field.vault'), vaults),
			]));

			for (const f of VS.FIELDS[dr.type]) {
				const id = `vault-edit-${f.key}`;
				const label = t(f.totp ? 'vault.field.totpSecret' : `vault.field.${f.key}`);
				const value = dr.fields[f.key] || '';
				const set = (v) => { dr.fields[f.key] = v; };
				if (f.secret) {
					const p = secret(id, value, set, label);
					const extra = [];
					if (f.key === 'password') {
						p.box.appendChild(btn('btn-sec btn-sm', [icon('wand', 15), el('span', { text: t('vault.gen.title') })], () => toggleGen(f.key, p.input), { id: 'vault-gen-toggle', 'aria-expanded': S.gen && S.gen.field === f.key ? 'true' : 'false' }));
						if (S.gen && S.gen.field === f.key) extra.push(genPanel(p.input));
					}
					if (f.totp && typeof api.totpQr === 'function') {
						// 2FA from a QR code (screen, clipboard, image file) instead of typing the key
						p.box.appendChild(btn('btn-sec btn-sm', [icon('qr', 15), el('span', { text: t('vault.qr.scan') })], (e) => qrMenu(e.currentTarget), { id: 'vault-qr-scan', 'aria-haspopup': 'menu', 'aria-expanded': 'false' }));
					}
					form.appendChild(field(id, label, p.box, extra));
				} else if (f.multiline) {
					form.appendChild(field(id, label, el('textarea', { class: 'inp', id, rows: '3', spellcheck: 'false', value, on: { input: (e) => set(e.target.value) } })));
				} else if (f.key === 'ssid' && typeof api.wifiScan === 'function') {
					// Wi-Fi networks nearby: pick one instead of typing its name
					form.appendChild(field(id, label, el('div', { class: 'vt-ssid' }, [
						text(id, value, set),
						btn('btn-sec btn-sm', [icon('wifi', 15), el('span', { text: t('vault.wifi.scan') })], () => wifiDialog(), { id: 'vault-wifi-scan', 'aria-haspopup': 'dialog' }),
					])));
				} else {
					form.appendChild(field(id, label, text(id, value, set)));
				}
			}

			// web addresses and programs (login)
			if (dr.type === 'login') {
				const box = el('div', { class: 'vt-list-edit' });
				dr.urls.forEach((u, i) => {
					box.appendChild(el('div', { class: 'field-row' }, [
						text(`vault-edit-url-${i}`, u, (v) => { dr.urls[i] = v; }, { placeholder: 'https://', 'aria-label': t('vault.field.url') }),
						dr.urls.length > 1 ? iconBtn('btn-ghost', 'close', t('vault.removeUrl'), () => { dr.urls.splice(i, 1); buildEdit(); }) : null,
					]));
				});
				box.appendChild(btn('btn-ghost btn-sm', [icon('plus', 14), el('span', { text: t('vault.addUrl') })], () => { dr.urls.push(''); buildEdit(); }));
				form.appendChild(el('div', { class: 'field' }, [el('label', { text: t('vault.field.urls') }), box]));
				if (dr.apps.length) {
					const apps = el('div', { class: 'vt-list-edit' });
					dr.apps.forEach((a, i) => apps.appendChild(el('div', { class: 'field-row' }, [
						text(`vault-edit-app-${i}`, a, (v) => { dr.apps[i] = v; }, { 'aria-label': t('vault.field.app') }),
						iconBtn('btn-ghost', 'close', t('vault.removeUrl'), () => { dr.apps.splice(i, 1); buildEdit(); }),
					])));
					form.appendChild(el('div', { class: 'field' }, [el('label', { text: t('vault.field.apps') }), apps]));
				}
			}

			form.appendChild(field('vault-edit-notes', t('vault.field.notes'), el('textarea', { class: 'inp', id: 'vault-edit-notes', rows: dr.type === 'note' ? '8' : '3', value: dr.notes, on: { input: (e) => { dr.notes = e.target.value; } } })));

			// custom fields
			const custom = el('div', { class: 'vt-list-edit' });
			dr.custom.forEach((c, i) => {
				const val = c.secret ? secret(`vault-edit-custom-${i}`, c.value, (v) => { c.value = v; }, t('vault.custom.value')).box
					: text(`vault-edit-custom-${i}`, c.value, (v) => { c.value = v; }, { 'aria-label': t('vault.custom.value'), placeholder: t('vault.custom.value') });
				custom.appendChild(el('div', { class: 'vt-custom' }, [
					text(`vault-edit-custom-name-${i}`, c.name, (v) => { c.name = v; }, { 'aria-label': t('vault.custom.name'), placeholder: t('vault.custom.name') }),
					val,
					el('label', { class: 'vt-check' }, [el('input', { type: 'checkbox', checked: c.secret, on: { change: (e) => { c.secret = e.target.checked; buildEdit(); } } }), el('span', { text: t('vault.custom.secret') })]),
					iconBtn('btn-ghost', 'close', t('vault.custom.remove'), () => { dr.custom.splice(i, 1); buildEdit(); }),
				]));
			});
			custom.appendChild(btn('btn-ghost btn-sm', [icon('plus', 14), el('span', { text: t('vault.custom.add') })], () => { dr.custom.push({ name: '', value: '', secret: false }); buildEdit(); }, { id: 'vault-custom-add' }));
			form.appendChild(el('div', { class: 'field' }, [el('label', { text: t('vault.custom.title') }), custom]));

			form.appendChild(err);
			const saveBtn = el('button', { type: 'submit', class: 'btn btn-pri', id: 'vault-edit-save', text: t('vault.save') });
			form.appendChild(el('div', { class: 'vt-form-acts' }, [btn('btn-ghost', t('vault.cancel'), () => leaveEdit(), { id: 'vault-edit-cancel' }), saveBtn]));
			refs.detail.appendChild(form);

			async function save() {
				const e = VS.draftError(dr);
				if (e) { err.textContent = t(e); return; }
				saveBtn.disabled = true;
				err.textContent = '';
				const r = await call(api.save, { id: dr.id, vaultId: dr.vaultId, data: VS.draftToData(dr) });
				saveBtn.disabled = false;
				if (!r.ok) { err.textContent = VS.errorText(r, t); return; }
				const id = r.id || dr.id;
				S.mode = 'view';
				S.draft = null;
				S.draftBase = null;
				S.gen = null;
				S.selId = id;
				S.detail = null;
				S.revealed.clear();
				toast(t('vault.edit.saved'), 'success');
				renderList();
				renderDetail(true);
				loadDetail(id, false);
			}
		}

		// ── Generator ────────────────────────────────────────
		function toggleGen(fieldKey) {
			if (S.gen && S.gen.field === fieldKey) S.gen = null;
			else S.gen = { field: fieldKey, opts: { words: false, length: 20, upper: true, digits: true, symbols: true, avoidAmbiguous: false, wordCount: 4 }, value: '', res: null };
			buildEdit();
			if (S.gen && !S.gen.value) generate();
		}

		async function generate() {
			const g = S.gen;
			if (!g) return;
			const r = await call(api.generate, g.opts);
			if (S.gen !== g) return;
			if (!r.ok) { fail(r); return; }
			g.value = r.password;
			g.res = { ok: true, strength: r.strength, words: g.opts.words ? g.opts.wordCount : 0 };
			if (refs.genOut) {
				refs.genOut.textContent = g.value;
				refs.genMeter.set(g.res, g.value);
			}
		}

		function genPanel(target) {
			const g = S.gen;
			const o2 = g.opts;
			refs.genOut = el('div', { class: 'vt-gen-out', id: 'vault-gen-out', 'aria-live': 'polite', text: g.value || '…' });
			refs.genMeter = meter();
			if (g.res) refs.genMeter.set(g.res, g.value);
			const mode = el('div', { class: 'seg', role: 'group', 'aria-label': t('vault.gen.title') });
			for (const [words, key] of [[false, 'vault.gen.random'], [true, 'vault.gen.words']]) {
				mode.appendChild(el('button', { type: 'button', class: o2.words === words ? 'on' : '', 'aria-pressed': o2.words === words ? 'true' : 'false', text: t(key), on: { click: () => { o2.words = words; buildEdit(); generate(); } } }));
			}
			const lenVal = el('b', { text: String(o2.words ? o2.wordCount : o2.length) });
			const range = el('input', {
				type: 'range', min: o2.words ? '3' : '8', max: o2.words ? '8' : '64', value: String(o2.words ? o2.wordCount : o2.length), 'aria-label': t(o2.words ? 'vault.gen.wordCount' : 'vault.gen.length'),
				on: { input: (e) => { const n = Number(e.target.value); if (o2.words) o2.wordCount = n; else o2.length = n; lenVal.textContent = String(n); generate(); } },
			});
			const opt = (key, label) => el('label', { class: 'vt-check' }, [el('input', { type: 'checkbox', checked: !!o2[key], on: { change: (e) => { o2[key] = e.target.checked; generate(); } } }), el('span', { text: t(label) })]);
			return el('div', { class: 'vt-gen', id: 'vault-gen' }, [
				mode,
				refs.genOut,
				refs.genMeter.el,
				el('div', { class: 'vt-gen-len' }, [el('span', { text: t(o2.words ? 'vault.gen.wordCount' : 'vault.gen.length') }), range, lenVal]),
				o2.words ? null : el('div', { class: 'vt-gen-opts' }, [opt('upper', 'vault.gen.upper'), opt('digits', 'vault.gen.digits'), opt('symbols', 'vault.gen.symbols'), opt('avoidAmbiguous', 'vault.gen.ambiguous')]),
				el('div', { class: 'vt-form-acts' }, [
					btn('btn-ghost btn-sm', [icon('refresh', 14), el('span', { text: t('vault.gen.again') })], () => generate()),
					btn('btn-pri btn-sm', t('vault.gen.use'), () => {
						if (!S.gen || !S.gen.value) return;
						S.draft.fields[S.gen.field] = S.gen.value;
						target.value = S.gen.value;
						S.gen = null;
						buildEdit();
					}, { id: 'vault-gen-use' }),
				]),
			]);
		}

		// ── Wi-Fi networks nearby (Wi-Fi entries) ───────────
		/** Wi-Fi icon whose arcs show the signal (0–3). */
		function wifiIcon(bars) {
			const s = icon('wifi', 18, '2');
			const arcs = s.querySelectorAll('path');   // large, middle, small arc, dot
			[3, 2, 1].forEach((need, i) => { if (bars < need && arcs[i]) arcs[i].setAttribute('opacity', '.3'); });
			s.setAttribute('data-bars', String(bars));
			return s;
		}

		/** "WLAN in der Nähe": scan (≈ 4 s), list, pick → name, security (and title) of the draft. SSIDs only via textContent. */
		function wifiDialog() {
			if (!S.draft || S.mode !== 'edit') return;
			const draft = S.draft;
			let seq = 0;
			const list = el('div', { class: 'vt-people vt-wifi-list', role: 'listbox', 'aria-label': t('vault.wifi.list'), id: 'vault-wifi-list' });
			const d = dialog({
				title: t('vault.wifi.title'),
				sub: t('vault.wifi.sub'),
				body: [list],
				actions: [
					{ id: 'again', label: [icon('refresh', 14), el('span', { text: t('vault.wifi.again') })], cls: 'btn-ghost', run: () => scan() },
					{ label: t('vault.cancel'), cls: 'btn-sec', run: () => closeDialog() },
				],
			});
			if (d.buttons.again) d.buttons.again.id = 'vault-wifi-again';

			const pick = (net) => {
				if (S.draft !== draft || S.mode !== 'edit') { closeDialog(); return; }
				VS.applyWifi(draft, net);
				closeDialog();
				buildEdit();
				const pw = refs.detail && refs.detail.querySelector('#vault-edit-password');
				if (pw) pw.focus();
			};

			const show = (v) => {
				clear(list);
				list.removeAttribute('aria-busy');
				if (v.kind === 'error') {
					const note = el('div', { class: 'vt-note vt-note-warn vt-wifi-msg', role: 'alert', id: 'vault-wifi-error', 'data-code': v.code }, [
						v.title ? el('b', { text: v.title }) : null,
						el('span', { text: v.text }),
					]);
					if (v.settings && typeof o.openExternal === 'function') {
						note.appendChild(el('div', { class: 'vt-wifi-acts' }, [
							btn('btn-sec btn-sm', [icon('external', 14), el('span', { text: t('vault.wifi.openSettings') })], () => {
								Promise.resolve(o.openExternal('ms-settings:privacy-location')).catch(() => {});
							}, { id: 'vault-wifi-settings' }),
						]));
					}
					list.appendChild(note);
					return;
				}
				if (v.kind === 'empty') {
					list.appendChild(el('div', { class: 'vt-empty', id: 'vault-wifi-empty', text: t('vault.wifi.empty') }));
					return;
				}
				for (const net of v.networks) {
					const bars = VS.wifiBars(net.signal);
					const row = el('button', { type: 'button', role: 'option', class: 'vt-person vt-wifi-row', 'aria-selected': 'false' }, [
						el('span', { class: `vt-av vt-av-round ${net.connected ? 'vt-t2' : 'vt-tn'}`, 'aria-hidden': 'true' }, [wifiIcon(bars)]),
						el('span', { class: 'vt-person-tx' }, [el('b', { class: 'vt-ellipsis', text: net.ssid }), el('span', { text: VS.wifiRowSub(net, t) })]),
						net.connected ? el('span', { class: 'vt-person-state is-ok', text: t('vault.wifi.connected') }) : null,
					]);
					row.addEventListener('click', () => pick(net));
					list.appendChild(row);
				}
			};

			async function scan() {
				const mine = ++seq;
				if (d.buttons.again) d.buttons.again.disabled = true;
				clear(list);
				list.setAttribute('aria-busy', 'true');
				const spin = icon('refresh', 16);
				spin.classList.add('vt-spin');
				list.appendChild(el('div', { class: 'vt-empty vt-wifi-wait', role: 'status', id: 'vault-wifi-wait' }, [spin, el('span', { text: t('vault.wifi.searching') })]));
				const r = await call(api.wifiScan);
				if (mine !== seq || !list.isConnected) return;
				if (d.buttons.again) d.buttons.again.disabled = false;
				show(VS.wifiScanView(r, t));
				const first = list.querySelector('.vt-wifi-row, #vault-wifi-settings');
				if (first) first.focus();
			}
			scan();
		}

		// ── 2FA key from a QR code ("QR-Code scannen") ──────
		function qrMenu(anchor) {
			menu(anchor, [
				{ id: 'vault-qr-screen', icon: 'monitor', label: t('vault.qr.screen'), run: () => qrDialog('screen') },
				{ id: 'vault-qr-clipboard', icon: 'clipboard', label: t('vault.qr.clipboard'), run: () => qrDialog('clipboard') },
				{ id: 'vault-qr-file', icon: 'image', label: t('vault.qr.file'), run: () => qrDialog('file') },
			]);
		}

		/** Scan (main process: screen / clipboard / image file), pick one of several codes → 2FA key, title, user name. Labels only via textContent. */
		function qrDialog(source) {
			if (!S.draft || S.mode !== 'edit' || !VS.QR_SOURCES.includes(source)) return;
			const draft = S.draft;
			let seq = 0;
			const list = el('div', { class: 'vt-people vt-qr-list', role: 'listbox', 'aria-label': t('vault.qr.list'), id: 'vault-qr-list' });
			const d = dialog({
				title: t('vault.qr.title'),
				sub: t('vault.qr.sub'),
				body: [list],
				actions: [
					{ id: 'again', label: [icon('refresh', 14), el('span', { text: t('vault.qr.again') })], cls: 'btn-ghost', run: () => scan() },
					{ label: t('vault.cancel'), cls: 'btn-sec', run: () => closeDialog() },
				],
			});
			if (d.buttons.again) d.buttons.again.id = 'vault-qr-again';

			const pick = (code) => {
				if (S.draft !== draft || S.mode !== 'edit') { closeDialog(); return; }
				VS.applyTotpQr(draft, code.uri);
				closeDialog();
				buildEdit();
				toast(t('vault.qr.applied'), 'success');
				const f = refs.detail && refs.detail.querySelector('#vault-edit-totp');
				if (f) f.focus();
			};

			const show = (v) => {
				clear(list);
				list.removeAttribute('aria-busy');
				if (v.kind === 'error') {
					list.appendChild(el('div', { class: 'vt-note vt-note-warn vt-qr-msg', role: 'alert', id: 'vault-qr-error', 'data-code': v.code }, [el('span', { text: v.text })]));
					return;
				}
				for (const c of v.codes) {
					const row = el('button', { type: 'button', role: 'option', class: 'vt-person vt-qr-row', 'aria-selected': 'false' }, [
						avatar(c.title),
						el('span', { class: 'vt-person-tx' }, [el('b', { class: 'vt-ellipsis', text: c.title }), c.sub ? el('span', { class: 'vt-ellipsis', text: c.sub }) : null]),
					]);
					row.addEventListener('click', () => pick(c));
					list.appendChild(row);
				}
			};

			async function scan() {
				const mine = ++seq;
				if (d.buttons.again) d.buttons.again.disabled = true;
				clear(list);
				list.setAttribute('aria-busy', 'true');
				const spin = icon('refresh', 16);
				spin.classList.add('vt-spin');
				list.appendChild(el('div', { class: 'vt-empty vt-qr-wait', role: 'status', id: 'vault-qr-wait' }, [spin, el('span', { text: VS.totpQrBusy(source, t) })]));
				const r = await call(api.totpQr, source);
				if (mine !== seq || !list.isConnected) return;
				if (d.buttons.again) d.buttons.again.disabled = false;
				const v = VS.totpQrView(r, source, t);
				if (v.kind === 'cancelled') { closeDialog(); return; }
				if (v.kind === 'list' && v.codes.length === 1) { pick(v.codes[0]); return; }
				show(v);
				const first = list.querySelector('.vt-qr-row') || d.buttons.again;
				if (first) first.focus();
			}
			scan();
		}

		// ── Trash ────────────────────────────────────────────
		function buildTrash() {
			refs.page.appendChild(pageHead(t('vault.trash.title')));
			refs.trashList = el('div', { class: 'card vt-rows', id: 'vault-trash-list' });
			refs.page.append(refs.trashList, el('p', { class: 'vt-hint', text: t('vault.trash.info') }));
			renderTrash();
			loadTrash().then(renderTrash);
		}

		function renderTrash() {
			if (!refs.trashList || !refs.trashList.isConnected) return;
			clear(refs.trashList);
			if (!S.trash.length) { refs.trashList.appendChild(el('div', { class: 'vt-empty', text: t('vault.trash.empty') })); return; }
			const nm = names();
			for (const e of S.trash) {
				const w = canWrite(e.vaultId);
				refs.trashList.appendChild(entryRow(e, nm, {
					acts: w ? el('div', { class: 'vt-row-acts' }, [
						btn('btn-sec btn-xs', t('vault.restore'), async () => { const r = await call(api.restore, e.id); if (!r.ok) fail(r); else { await loadTrash(); renderTrash(); } }),
						btn('btn-danger btn-xs', t('vault.purge'), async () => {
							if (!(await confirm(t('vault.purgeConfirm', { title: e.title }), t('vault.purge'), true))) return;
							const r = await call(api.purge, e.id);
							if (!r.ok) fail(r); else { await loadTrash(); renderTrash(); }
						}),
					]) : el('span', { class: 'chip vt-chip-sm', text: t('vault.readOnly') }),
				}));
			}
		}

		// ── Vaults and sharing ───────────────────────────────
		function buildVaults() {
			refs.page.appendChild(pageHead(t('vault.vaults.title'), [
				btn('btn-pri btn-sm', [icon('plus', 15, '2.2'), el('span', { text: t('vault.vaults.newVault') })], () => nameDialog(t('vault.vaults.newVault'), '', t('vault.create'), async (name) => {
					const r = await call(api.createVault, name);
					if (!r.ok) return r;
					S.vaultId = r.vault && r.vault.id;
					if (S.vaultId) setSub('vault');
					return r;
				}), { id: 'vault-new-vault' }),
			]));
			refs.vaultCards = el('div', { class: 'vt-cards', id: 'vault-cards' });
			refs.page.appendChild(refs.vaultCards);
			renderVaults();
		}

		function renderVaults() {
			if (!refs.vaultCards || !refs.vaultCards.isConnected) return;
			clear(refs.vaultCards);
			const nm = names();
			for (const v of S.vaults) {
				const name = nm.get(v.id);
				refs.vaultCards.appendChild(el('button', { type: 'button', class: 'card vt-vcard', 'data-id': v.id, on: { click: () => { S.vaultId = v.id; setSub('vault'); } } }, [
					el('div', { class: 'vt-vcard-top' }, [avatar(name), el('b', { text: name }), el('span', { class: `chip vt-chip-sm${v.personal ? '' : ' c-info'}`, text: t(v.personal ? 'vault.vaults.personal' : 'vault.vaults.shared') })]),
					el('span', { text: [VS.plural(t, 'vault.head.entries', v.count), v.personal ? null : VS.plural(t, 'vault.vaults.members', (v.members || []).length), t(VS.roleLabel(v.role))].filter(Boolean).join(' · ') }),
					v.needsRekey || v.rekeying ? el('span', { text: t('vault.vaults.rekeyNeeded') }) : null,
				]));
			}
		}

		function nameDialog(title, value, okLabel, run) {
			const input = el('input', { class: 'inp', id: 'vault-name-input', value, maxlength: '120', placeholder: t('vault.vaults.nameHint'), 'aria-label': t('vault.vaults.name') });
			const err = el('div', { class: 'vt-err', role: 'alert' });
			const go = async () => {
				const name = input.value.trim();
				if (!name) return;
				d.buttons.ok.disabled = true;
				const r = await run(name);
				if (d.buttons.ok) d.buttons.ok.disabled = false;
				if (r && r.ok === false) { err.textContent = VS.errorText(r, t); return; }
				closeDialog();
			};
			input.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
			const d = dialog({
				title,
				body: [el('div', { class: 'field' }, [el('label', { for: 'vault-name-input', text: t('vault.vaults.name') }), input]), err],
				actions: [{ label: t('vault.cancel'), cls: 'btn-ghost', run: () => closeDialog() }, { id: 'ok', label: okLabel, cls: 'btn-pri', run: go }],
			});
		}

		function buildVault() {
			refs.vaultBox = el('div', { class: 'vt-stack' });
			refs.page.appendChild(refs.vaultBox);
			renderVault();
		}

		function renderVault() {
			if (!refs.vaultBox || !refs.vaultBox.isConnected) return;
			const v = vaultOf(S.vaultId);
			clear(refs.vaultBox);
			if (!v) {
				refs.vaultBox.append(pageHead(t('vault.vaults.title')), el('div', { class: 'vt-empty', text: S.loaded ? t('vault.err.notFound') : t('vault.loading') }));
				return;
			}
			const name = names().get(v.id);
			const me = S.status && S.status.myUserId;
			const head = [];
			if (v.canManage) head.push(btn('btn-sec btn-sm', t('vault.rename'), () => nameDialog(t('vault.vaults.renameTitle'), name, t('vault.save'), (n) => call(api.renameVault, v.id, n))));
			if (!v.personal) head.push(btn('btn-ghost btn-sm', t('vault.share.leave'), async () => {
				if (!(await confirm(t('vault.share.leaveConfirm', { name }), t('vault.share.leave'), true))) return;
				const r = await call(api.removeMember, v.id, me);
				if (!r.ok) fail(r); else setSub('vaults');
			}));
			if (!v.personal && v.canManage) head.push(btn('btn-danger btn-sm', t('vault.share.deleteVault'), async () => {
				if (!(await confirm(t('vault.share.deleteConfirm', { name }), t('vault.share.deleteVault'), true))) return;
				const r = await call(api.deleteVault, v.id);
				if (!r.ok) fail(r); else setSub('vaults');
			}));
			refs.vaultBox.appendChild(pageHead(t('vault.share.title', { name }), head));
			refs.vaultBox.appendChild(el('span', { class: 'vt-sub', text: [VS.plural(t, 'vault.head.entries', v.count), t(VS.roleLabel(v.role))].join(' · ') }));
			if (v.needsRekey || v.rekeying) refs.vaultBox.appendChild(el('div', { class: 'vt-note vt-note-info', text: t('vault.vaults.rekeyNeeded') }));
			if (v.personal) {
				refs.vaultBox.appendChild(el('div', { class: 'vt-note vt-note-neutral', text: t('vault.share.personalHint') }));
				return;
			}
			const card = el('div', { class: 'card vt-card' }, [el('div', { class: 'vt-page-head' }, [
				el('h3', { style: 'flex-grow:1', text: t('vault.share.members', { count: (v.members || []).length }) }),
				v.canManage ? btn('btn-pri btn-sm', [icon('plus', 15, '2.2'), el('span', { text: t('vault.share.addPerson') })], () => shareDialog(v), { id: 'vault-add-person' }) : null,
			])]);
			const rows = el('div', { class: 'vt-rows', id: 'vault-members' });
			for (const m of v.members || []) {
				const self = m.userId === me;
				const acts = el('div', { class: 'vt-row-acts' });
				if (v.canManage && !self) {
					const sel = el('select', { class: 'inp', style: 'height:32px;width:auto', 'aria-label': t('vault.share.role'), on: { change: async (e) => { const r = await call(api.setRole, v.id, m.userId, e.target.value); if (!r.ok) { fail(r); renderVault(); } } } },
						VS.ROLES.map((role) => el('option', { value: role, text: t(VS.roleLabel(role)), selected: role === m.role ? true : null })));
					acts.append(sel, btn('btn-ghost btn-xs', t('vault.remove'), async () => {
						if (!(await confirm(t('vault.share.removeConfirm', { person: m.name, name }), t('vault.remove'), true))) return;
						const r = await call(api.removeMember, v.id, m.userId);
						if (!r.ok) fail(r);
					}));
				} else {
					acts.appendChild(el('span', { class: 'chip vt-chip-sm', text: t(VS.roleLabel(m.role)) }));
				}
				rows.appendChild(el('div', { class: 'vt-row' }, [
					el('span', { class: `vt-av vt-av-round vt-t${VS.tone(m.name)}`, 'aria-hidden': 'true', text: VS.initial(m.name) }),
					el('span', { class: 'vt-row-tx' }, [el('span', { class: 'vt-row-title', text: self ? t('vault.share.you', { name: m.name }) : m.name }), el('span', { class: 'vt-row-sub', text: t(VS.roleHint(m.role)) })]),
					acts,
				]));
			}
			card.appendChild(rows);
			refs.vaultBox.append(card, el('p', { class: 'vt-hint', text: t('vault.share.removeInfo') }));
		}

		/** W3: add a person to a vault (person, role, safety number compared). */
		async function shareDialog(v) {
			const name = names().get(v.id);
			const st = { person: null, role: 'read', compared: false };
			const list = el('div', { class: 'vt-people', role: 'listbox', 'aria-label': t('vault.share.people'), id: 'vault-people' }, [el('div', { class: 'vt-empty', text: t('vault.loading') })]);
			const roleSeg = el('div', { class: 'seg', role: 'radiogroup', 'aria-label': t('vault.share.role') });
			const roleHint = el('span', { class: 'vt-hint' });
			const safety = el('div', { class: 'vt-safety-box', hidden: true });
			const err = el('div', { class: 'vt-err', role: 'alert' });
			const d = dialog({
				title: t('vault.share.addTitle', { vault: name }),
				sub: t('vault.share.addSub'),
				body: [
					el('div', { class: 'field' }, [el('label', { text: t('vault.share.person') }), list]),
					el('div', { class: 'field' }, [el('label', { text: t('vault.share.role') }), roleSeg, roleHint]),
					safety,
					err,
				],
				actions: [
					{ label: t('vault.cancel'), cls: 'btn-ghost', run: () => closeDialog() },
					{ id: 'add', label: t('vault.share.add'), cls: 'btn-pri', run: async () => {
						if (!st.person || !st.compared) return;
						d.buttons.add.disabled = true;
						const r = await call(api.addMember, v.id, st.person.id, st.role);
						if (!r.ok) { err.textContent = VS.errorText(r, t); paint(); return; }
						closeDialog();
					} },
				],
			});
			const paint = () => {
				clear(roleSeg);
				for (const role of VS.ROLES) {
					roleSeg.appendChild(el('button', { type: 'button', role: 'radio', class: st.role === role ? 'on' : '', 'aria-checked': st.role === role ? 'true' : 'false', text: t(VS.roleLabel(role)), on: { click: () => { st.role = role; paint(); } } }));
				}
				roleHint.textContent = t(VS.roleHint(st.role));
				clear(safety);
				safety.hidden = !st.person;
				if (st.person) {
					safety.append(
						el('div', null, [icon('shield', 16, '2'), el('span', { text: t('vault.share.safetyOf', { name: st.person.name }) })]),
						safetyEl(st.person.safetyNumber),
						el('span', { class: 'vt-hint', text: t('vault.share.safetyText', { name: st.person.name }) }),
						el('label', { class: 'vt-check' }, [el('input', { type: 'checkbox', id: 'vault-safety-ok', checked: st.compared, on: { change: (e) => { st.compared = e.target.checked; paint(); } } }), el('span', { text: t('vault.share.compared', { name: st.person.name }) })]),
					);
				}
				if (d.buttons.add) d.buttons.add.disabled = !(st.person && st.compared);
			};
			paint();
			const r = await call(api.people);
			if (!list.isConnected) return;
			clear(list);
			if (!r.ok) { list.appendChild(el('div', { class: 'vt-empty', text: VS.errorText(r, t) })); return; }
			const people = VS.candidates((r.people || []).filter((p) => p.id !== (S.status && S.status.myUserId)), v.members);
			if (!people.length) { list.appendChild(el('div', { class: 'vt-empty', text: t('vault.share.noPeople') })); return; }
			for (const p of people) {
				const b = el('button', { type: 'button', role: 'option', class: 'vt-person', 'aria-selected': 'false', disabled: p.hasVault ? null : true, 'data-id': String(p.id) }, [
					el('span', { class: `vt-av vt-av-round ${p.hasVault ? `vt-t${VS.tone(p.name)}` : 'vt-tn'}`, 'aria-hidden': 'true', text: VS.initial(p.name) }),
					el('span', { class: 'vt-person-tx' }, [el('b', { text: p.name })]),
					el('span', { class: `vt-person-state${p.hasVault ? ' is-ok' : ''}`, text: t(p.hasVault ? 'vault.share.hasVault' : 'vault.share.noVault') }),
				]);
				b.addEventListener('click', () => {
					st.person = p;
					st.compared = false;
					for (const x of list.querySelectorAll('.vt-person')) x.setAttribute('aria-selected', x === b ? 'true' : 'false');
					paint();
				});
				list.appendChild(b);
			}
		}

		// ── Emergency access ─────────────────────────────────
		function buildEmergency() {
			refs.page.appendChild(pageHead(t('vault.em.title')));
			refs.emBox = el('div', { class: 'vt-stack', id: 'vault-emergency' }, [el('div', { class: 'vt-empty', text: t('vault.loading') })]);
			refs.page.append(refs.emBox, el('p', { class: 'vt-hint', text: t('vault.em.info') }));
			loadEmergency();
		}

		async function loadEmergency() {
			const r = await call(api.emergency);
			S.em = r.ok ? { granted: r.granted || [], received: r.received || [] } : r;
			renderEmergency();
		}

		function renderEmergency() {
			const box = refs.emBox;
			if (!box || !box.isConnected) return;
			clear(box);
			const em = S.em;
			if (!em) { box.appendChild(el('div', { class: 'vt-empty', text: t('vault.loading') })); return; }
			if (em.ok === false) { box.append(el('div', { class: 'vt-empty', text: VS.errorText(em, t) }), btn('btn-sec btn-sm', t('vault.retry'), () => loadEmergency())); return; }
			const step = async (id, s) => { const r = await call(api.emergencyStep, id, s); if (!r.ok) fail(r); loadEmergency(); };
			for (const e of em.granted.filter((x) => x.status === 'requested')) {
				box.appendChild(el('div', { class: 'vt-alert', role: 'alert' }, [
					el('b', { text: t('vault.em.requested', { name: e.grantee.name }) }),
					el('span', { text: t('vault.em.requestedText', { name: e.grantee.name, time: VS.remainingText(t, e.releaseAt, now()) }) }),
					el('div', { class: 'vt-form-acts' }, [btn('btn-sec btn-sm', t('vault.em.deny'), () => step(e.id, 'deny')), btn('btn-pri btn-sm', t('vault.em.approve'), () => step(e.id, 'approve'))]),
				]));
			}
			const mine = el('div', { class: 'card vt-card' }, [el('div', { class: 'vt-page-head' }, [
				el('h3', { style: 'flex-grow:1', text: t('vault.em.mine') }),
				btn('btn-sec btn-sm', [icon('plus', 15, '2.2'), el('span', { text: t('vault.em.add') })], () => emergencyDialog(), { id: 'vault-em-add' }),
			])]);
			const rows = el('div', { class: 'vt-rows' });
			if (!em.granted.length) rows.appendChild(el('div', { class: 'vt-empty', text: t('vault.em.none') }));
			for (const e of em.granted) {
				rows.appendChild(el('div', { class: 'vt-row vt-em-row' }, [
					el('span', { class: `vt-av vt-av-round vt-t${VS.tone(e.grantee.name)}`, 'aria-hidden': 'true', text: VS.initial(e.grantee.name) }),
					el('span', { class: 'vt-row-tx' }, [el('span', { class: 'vt-row-title', text: e.grantee.name }), el('span', { class: 'vt-row-sub', text: t('vault.em.wait', { time: VS.waitText(t, e.waitHours) }) })]),
					el('span', { class: `chip vt-chip-sm${e.status === 'requested' ? ' c-warn' : e.status === 'granted' ? ' c-ok' : ''}`, text: t(VS.emStatusKey(e.status)) }),
					el('div', { class: 'vt-row-acts' }, [
						e.status === 'granted' ? btn('btn-ghost btn-xs', t('vault.em.takeBack'), () => step(e.id, 'deny')) : null,
						btn('btn-ghost btn-xs', t('vault.em.remove'), async () => { const r = await call(api.emergencyRemove, e.id); if (!r.ok) fail(r); loadEmergency(); }),
					]),
				]));
			}
			mine.appendChild(rows);
			box.appendChild(mine);
			if (em.received.length) {
				const card = el('div', { class: 'card vt-card' }, [el('h3', { text: t('vault.em.for') })]);
				const list = el('div', { class: 'vt-rows' });
				for (const e of em.received) {
					const sub = e.status === 'requested'
						? t('vault.em.waitingUntil', { time: VS.remainingText(t, e.releaseAt, now()), name: e.grantor.name })
						: `${t('vault.em.waitLabel')} ${VS.waitText(t, e.waitHours)}`;
					let action;
					if (e.status === 'granted') action = btn('btn-pri btn-xs', t('vault.em.open'), () => openEmergency(e.id));
					else if (e.status === 'ready') {
						action = btn('btn-sec btn-xs', t('vault.em.request'), async () => {
							if (!(await confirm(t('vault.em.requestConfirm', { name: e.grantor.name, time: VS.waitText(t, e.waitHours) }), t('vault.em.request')))) return;
							step(e.id, 'request');
						});
					} else action = el('span', { class: 'chip vt-chip-sm c-warn', text: t(VS.emStatusKey(e.status)) });
					list.appendChild(el('div', { class: 'vt-row vt-em-row' }, [
						el('span', { class: `vt-av vt-av-round vt-t${VS.tone(e.grantor.name)}`, 'aria-hidden': 'true', text: VS.initial(e.grantor.name) }),
						el('span', { class: 'vt-row-tx' }, [el('span', { class: 'vt-row-title', text: e.grantor.name }), el('span', { class: 'vt-row-sub', text: sub })]),
						el('div', { class: 'vt-row-acts' }, [action, btn('btn-ghost btn-xs', t('vault.em.decline'), async () => { const r = await call(api.emergencyRemove, e.id); if (!r.ok) fail(r); loadEmergency(); })]),
					]));
				}
				card.appendChild(list);
				box.appendChild(card);
			}
		}

		async function emergencyDialog() {
			const st = { person: null, wait: 48, compared: false };
			const list = el('div', { class: 'vt-people', role: 'listbox', 'aria-label': t('vault.share.people') }, [el('div', { class: 'vt-empty', text: t('vault.loading') })]);
			const waitSeg = el('div', { class: 'seg', role: 'radiogroup', 'aria-label': t('vault.em.waitLabel'), style: 'flex-wrap:wrap' });
			const safety = el('div', { class: 'vt-safety-box', hidden: true });
			const err = el('div', { class: 'vt-err', role: 'alert' });
			const d = dialog({
				title: t('vault.em.add'),
				sub: t('vault.em.info'),
				body: [el('div', { class: 'field' }, [el('label', { text: t('vault.em.pick') }), list]), el('div', { class: 'field' }, [el('label', { text: t('vault.em.waitLabel') }), waitSeg]), safety, err],
				actions: [
					{ label: t('vault.cancel'), cls: 'btn-ghost', run: () => closeDialog() },
					{ id: 'add', label: t('vault.share.add'), cls: 'btn-pri', run: async () => {
						if (!st.person || !st.compared) return;
						d.buttons.add.disabled = true;
						const r = await call(api.emergencyAdd, st.person.id, st.wait);
						if (!r.ok) { err.textContent = VS.errorText(r, t); paint(); return; }
						closeDialog();
						loadEmergency();
					} },
				],
			});
			const paint = () => {
				clear(waitSeg);
				for (const h of VS.WAIT_CHOICES) waitSeg.appendChild(el('button', { type: 'button', role: 'radio', class: st.wait === h ? 'on' : '', 'aria-checked': st.wait === h ? 'true' : 'false', text: VS.waitText(t, h), on: { click: () => { st.wait = h; paint(); } } }));
				clear(safety);
				safety.hidden = !st.person;
				if (st.person) {
					safety.append(
						el('div', null, [icon('shield', 16, '2'), el('span', { text: t('vault.share.safetyOf', { name: st.person.name }) })]),
						safetyEl(st.person.safetyNumber),
						el('label', { class: 'vt-check' }, [el('input', { type: 'checkbox', checked: st.compared, on: { change: (e) => { st.compared = e.target.checked; paint(); } } }), el('span', { text: t('vault.share.compared', { name: st.person.name }) })]),
					);
				}
				if (d.buttons.add) d.buttons.add.disabled = !(st.person && st.compared);
			};
			paint();
			const r = await call(api.people);
			if (!list.isConnected) return;
			clear(list);
			if (!r.ok) { list.appendChild(el('div', { class: 'vt-empty', text: VS.errorText(r, t) })); return; }
			const taken = (S.em && S.em.granted ? S.em.granted : []).map((e) => ({ userId: e.grantee.id }));
			const people = VS.candidates((r.people || []).filter((p) => p.id !== (S.status && S.status.myUserId)), taken);
			if (!people.length) { list.appendChild(el('div', { class: 'vt-empty', text: t('vault.share.noPeople') })); return; }
			for (const p of people) {
				const b = el('button', { type: 'button', role: 'option', class: 'vt-person', 'aria-selected': 'false', disabled: p.hasVault ? null : true }, [
					el('span', { class: `vt-av vt-av-round ${p.hasVault ? `vt-t${VS.tone(p.name)}` : 'vt-tn'}`, 'aria-hidden': 'true', text: VS.initial(p.name) }),
					el('span', { class: 'vt-person-tx' }, [el('b', { text: p.name })]),
					el('span', { class: `vt-person-state${p.hasVault ? ' is-ok' : ''}`, text: t(p.hasVault ? 'vault.share.hasVault' : 'vault.share.noVault') }),
				]);
				b.addEventListener('click', () => {
					st.person = p;
					st.compared = false;
					for (const x of list.querySelectorAll('.vt-person')) x.setAttribute('aria-selected', x === b ? 'true' : 'false');
					paint();
				});
				list.appendChild(b);
			}
		}

		async function openEmergency(id) {
			const r = await call(api.emergencyOpen, id);
			if (!r.ok) { fail(r); return; }
			S.emView = { id, grantor: r.grantor, vaults: r.vaults || [], entries: (r.entries || []).filter((e) => !e.trashed), selId: null, detail: null, query: '' };
			setSub('emView');
		}

		function buildEmergencyView() {
			const v = S.emView;
			if (!v) { setSub('emergency'); return; }
			refs.page.appendChild(pageHead(t('vault.em.viewTitle', { name: v.grantor.name }), [el('span', { class: 'chip c-warn', text: t('vault.em.readOnly') })]));
			refs.emList = el('section', { class: 'card vt-list', 'aria-label': t('vault.list') });
			refs.emDetail = el('section', { class: 'card vt-detail', 'aria-label': t('vault.entry') });
			refs.page.appendChild(el('div', { class: 'vt-cols', style: 'padding-bottom:0' }, [refs.emList, refs.emDetail]));
			renderEmergencyList();
			renderEmergencyDetail();
		}

		function renderEmergencyList() {
			const v = S.emView;
			if (!v || !refs.emList) return;
			clear(refs.emList);
			if (!v.entries.length) { refs.emList.appendChild(el('div', { class: 'vt-empty', text: t('vault.trash.empty') })); return; }
			const nm = new Map(v.vaults.map((x) => [x.id, x.name || (x.kind === 'personal' ? t('vault.vaults.personal') : '…')]));
			for (const e of v.entries) refs.emList.appendChild(entryRow(e, nm, { onClick: () => selectEmergency(e.id), selected: e.id === v.selId, showVault: v.vaults.length > 1 }));
		}

		async function selectEmergency(id) {
			const v = S.emView;
			v.selId = id;
			v.detail = null;
			S.revealed.clear();
			S.totp = null;
			renderEmergencyList();
			renderEmergencyDetail();
			const r = await call(api.entry, id, { emergencyId: v.id });
			if (S.emView !== v || v.selId !== id) return;
			v.detail = r.ok ? r.entry : null;
			if (!r.ok) fail(r);
			renderEmergencyDetail();
		}

		function renderEmergencyDetail() {
			const v = S.emView;
			if (!v || !refs.emDetail) return;
			clear(refs.emDetail);
			refs.totpCode = null;
			if (!v.detail) {
				refs.emDetail.appendChild(el('div', { class: 'vt-placeholder' }, [icon('lifebuoy', 34, '1.5'), el('span', { text: v.selId ? t('vault.loading') : t('vault.noSelection') })]));
				return;
			}
			const vault = v.vaults.find((x) => x.id === v.detail.vaultId);
			refs.emDetail.append(...detailNodes(v.detail, { vaultName: vault ? vault.name || '' : '', writable: false, emergencyId: v.id }));
		}

		// ── Import ───────────────────────────────────────────
		function buildImport() {
			refs.page.appendChild(pageHead(t('vault.import.title')));
			refs.impBox = el('div', { class: 'vt-stack', id: 'vault-import' });
			refs.page.appendChild(refs.impBox);
			renderImport();
		}

		function renderImport() {
			const box = refs.impBox;
			if (!box || !box.isConnected) return;
			clear(box);
			const imp = S.imp;
			const file = el('input', { type: 'file', accept: '.json,.csv,text/csv,application/json', id: 'vault-import-file', hidden: true, on: { change: (e) => readFile(e.target.files && e.target.files[0]) } });
			const pick = btn(imp && imp.res ? 'btn-sec btn-sm' : 'btn-pri', [icon('upload', 15), el('span', { text: t(imp && imp.res ? 'vault.import.other' : 'vault.import.pick') })], () => file.click(), { id: 'vault-import-pick' });
			box.appendChild(el('div', { class: 'card vt-card' }, [
				el('h3', { text: t('vault.import.from') }),
				el('span', { class: 'vt-desc', text: t('vault.import.sources') }),
				el('div', { class: 'vt-form-acts', style: 'justify-content:flex-start' }, [pick, imp && imp.name ? el('span', { class: 'mono vt-hint', text: imp.name }) : null]),
				file,
			]));
			if (imp && imp.busy) box.appendChild(el('div', { class: 'vt-empty', text: t(imp.busy) }));
			if (imp && imp.error) box.appendChild(el('div', { class: 'vt-note vt-note-err', role: 'alert', text: imp.error }));
			if (imp && imp.res && !imp.busy) {
				const res = imp.res;
				const n = VS.importCount(res);
				const targets = VS.writableVaults(S.vaults);
				const sel = el('select', { class: 'inp vt-select', id: 'vault-import-vault', on: { change: (e) => { imp.vaultId = e.target.value; parse(); } } },
					targets.map((v) => el('option', { value: v.id, text: names().get(v.id), selected: v.id === imp.vaultId ? true : null })));
				const card = el('div', { class: 'card vt-card' }, [
					el('h3', { text: VS.plural(t, 'vault.import.found', res.counts.total) }),
					el('div', { class: 'vt-chiprow' }, VS.importChips(t, res.counts).map((c) => el('span', { class: 'chip', text: c }))),
					res.duplicates ? el('div', { class: 'vt-note vt-note-warn', text: VS.plural(t, 'vault.import.dupes', res.duplicates) }) : null,
					el('div', { class: 'field' }, [el('label', { for: 'vault-import-vault', text: t('vault.import.into') }), sel]),
					el('div', { class: 'vt-note vt-note-info', text: t('vault.import.info') }),
				]);
				const preview = (res.preview || []).slice(0, 50);
				if (preview.length) {
					const table = el('table', { class: 'vt-preview' }, [el('thead', null, [el('tr', null, [t('vault.field.title'), t('vault.field.username'), t('vault.field.url'), ''].map((h) => el('th', { text: h })))])]);
					const tb = el('tbody');
					for (const p of preview) {
						tb.appendChild(el('tr', { class: p.duplicate ? 'is-dup' : '' }, [
							el('td', { text: p.title || '…' }), el('td', { text: p.username || '' }), el('td', { text: p.host || '' }),
							el('td', { text: p.duplicate ? t('vault.import.duplicate') : [p.hasTotp ? '2FA' : '', t(`vault.type.${VS.TYPES.includes(p.type) ? p.type : 'login'}`)].filter(Boolean).join(' · ') }),
						]));
					}
					table.appendChild(tb);
					card.append(el('span', { class: 'lbl', text: t('vault.import.preview') }), el('div', { style: 'overflow:auto' }, [table]));
					if ((res.preview || []).length > preview.length) card.appendChild(el('span', { class: 'vt-hint', text: t('vault.import.more', { count: res.preview.length - preview.length }) }));
				}
				card.appendChild(el('div', { class: 'vt-form-acts' }, [
					btn('btn-ghost', t('vault.cancel'), () => { S.imp = null; renderImport(); }),
					btn('btn-pri', VS.plural(t, 'vault.import.button', n), () => saveImport(), { id: 'vault-import-save', disabled: n > 0 && imp.vaultId ? null : true }),
				]));
				box.appendChild(card);
			}
		}

		async function readFile(f) {
			if (!f) return;
			const vaultId = (S.imp && S.imp.vaultId) || defaultVault();
			if (f.size > VS.MAX_IMPORT_BYTES) { S.imp = { name: f.name, vaultId, error: t('vault.import.tooLarge') }; renderImport(); return; }
			S.imp = { name: f.name, vaultId, busy: 'vault.import.reading' };
			renderImport();
			let text = '';
			try { text = await f.text(); } catch { text = ''; }
			if (!S.imp || S.imp.name !== f.name) return;
			S.imp.text = text;
			parse();
		}

		async function parse() {
			const imp = S.imp;
			if (!imp || !imp.text) return;
			imp.busy = 'vault.import.reading';
			imp.error = null;
			renderImport();
			const r = await call(api.importParse, imp.text, { vaultId: imp.vaultId });
			if (S.imp !== imp) return;
			imp.busy = null;
			if (r.ok) imp.res = r;
			else { imp.res = null; imp.text = null; imp.error = VS.errorText(r, t); }
			renderImport();
		}

		async function saveImport() {
			const imp = S.imp;
			if (!imp || !imp.res || !imp.vaultId) return;
			imp.busy = 'vault.import.saving';
			renderImport();
			const r = await call(api.importSave, imp.vaultId, { skipDuplicates: true });
			if (S.imp !== imp) return;
			imp.busy = null;
			if (!r.ok) { imp.error = VS.errorText(r, t); renderImport(); return; }
			toast(VS.plural(t, 'vault.import.done', r.saved), 'success');
			S.imp = null;
			S.filter = imp.vaultId;
			setSub('list');
		}

		// ── Settings ─────────────────────────────────────────
		function buildSettings() {
			refs.page.appendChild(pageHead(t('vault.settings.title')));
			refs.setBox = el('div', { class: 'vt-stack', id: 'vault-settings' });
			refs.page.appendChild(refs.setBox);
			call(api.settings).then((r) => { S.settings = r.ok ? r : null; renderSettings(); });
			// Windows Hello set up / removed meanwhile: ask Windows again
			if (typeof api.helloCheck === 'function') call(api.helloCheck).then(() => refreshStatus()).then(() => renderSettings());
			renderSettings();
		}

		function renderSettings() {
			const box = refs.setBox;
			if (!box || !box.isConnected) return;
			clear(box);
			const st = S.status || {};
			const s = S.settings || { autoLockMinutes: st.autoLockMinutes, choices: VS.AUTO_LOCK };
			const seg = el('div', { class: 'seg', role: 'radiogroup', 'aria-label': t('vault.settings.autoLock'), id: 'vault-autolock', style: 'flex-wrap:wrap' });
			for (const c of VS.autoLockChoices(t, s.choices)) {
				const on = c.minutes === s.autoLockMinutes;
				seg.appendChild(el('button', { type: 'button', role: 'radio', class: on ? 'on' : '', 'aria-checked': on ? 'true' : 'false', 'data-minutes': String(c.minutes), text: c.label, on: { click: async () => {
					const r = await call(api.setSettings, { autoLockMinutes: c.minutes });
					if (!r.ok) { fail(r); return; }
					S.settings = r;
					renderSettings();
					refreshStatus();
				} } }));
			}
			box.appendChild(el('div', { class: 'card vt-card' }, [el('h3', { text: t('vault.settings.autoLock') }), seg, el('span', { class: 'vt-hint', text: t('vault.settings.autoLockHint') }), helloRow(), rememberRow()]));

			// change the master password
			const cur = pwInput({ id: 'vault-pw-current', 'aria-label': t('vault.settings.currentPw') });
			const err = el('div', { class: 'vt-err', role: 'alert' });
			const go = btn('btn-pri btn-sm', t('vault.settings.changePw'), async () => {
				if (!cur.input.value || !f.ok()) return;
				go.disabled = true;
				err.textContent = '';
				const r = await call(api.changePassword, cur.input.value, f.value());
				go.disabled = false;
				if (!r.ok) { err.textContent = VS.errorText(r, t); return; }
				cur.input.value = '';
				f.clear();
				toast(t('vault.settings.changePwDone'), 'success');
			}, { id: 'vault-change-pw', disabled: true });
			const f = masterFields({ label: t('vault.recover.newPw'), onChange: (ok) => { go.disabled = !ok; } });
			box.appendChild(el('div', { class: 'card vt-card' }, [
				el('h3', { text: t('vault.settings.changePw') }),
				el('div', { class: 'field' }, [el('label', { for: 'vault-pw-current', text: t('vault.settings.currentPw') }), cur.box]),
				f.el,
				err,
				el('div', { class: 'vt-form-acts', style: 'max-width:560px' }, [go]),
			]));

			box.appendChild(el('div', { class: 'card vt-card' }, [
				el('h3', { text: t('vault.settings.mySafety') }),
				safetyEl(st.safetyNumber, 'vault-my-safety'),
				el('span', { class: 'vt-hint', text: t('vault.settings.mySafetyText') }),
			]));
			box.appendChild(el('div', { class: 'card vt-card' }, [
				el('h3', { text: t('vault.quickInfo.title') }),
				el('div', { class: 'vt-form-acts', style: 'justify-content:flex-start' }, [el('span', { class: 'vt-kbd', text: t('vault.shortcut') }), el('span', { class: 'vt-desc', text: t('vault.quickInfo.text') })]),
			]));
			box.appendChild(el('div', { class: 'card vt-card' }, [
				el('h3', { text: t('vault.settings.deleteAccount') }),
				el('span', { class: 'vt-desc', text: t('vault.settings.deleteAccountConfirm') }),
				el('div', { class: 'vt-form-acts', style: 'justify-content:flex-start' }, [btn('btn-danger btn-sm', t('vault.settings.deleteAccount'), () => deleteAccountDialog(), { id: 'vault-delete-account' })]),
			]));
		}

		function deleteAccountDialog() {
			const check = el('input', { type: 'checkbox', on: { change: () => { d.buttons.del.disabled = !check.checked; } } });
			const err = el('div', { class: 'vt-err', role: 'alert' });
			const d = dialog({
				title: t('vault.settings.deleteAccount'),
				body: [el('p', { class: 'vt-desc', text: t('vault.settings.deleteAccountConfirm') }), el('label', { class: 'vt-check' }, [check, el('span', { text: t('vault.settings.deleteAccountCheck') })]), err],
				actions: [
					{ label: t('vault.cancel'), cls: 'btn-ghost', run: () => closeDialog() },
					{ id: 'del', label: t('vault.settings.deleteAccount'), cls: 'btn-danger', run: async () => {
						if (!check.checked) return;
						d.buttons.del.disabled = true;
						const r = await call(api.deleteAccount, 'DELETE');
						if (!r.ok) { err.textContent = VS.errorText(r, t); d.buttons.del.disabled = false; return; }
						closeDialog();
						toast(t('vault.settings.deleted'), 'info');
						S.sub = 'list';
						if (r.status) setStatus(r.status); else refreshStatus();
					} },
				],
			});
			d.buttons.del.disabled = true;
		}

		// ── Push targets ─────────────────────────────────────
		function applyPending() {
			const p = S.pending;
			if (!p || !S.status || !S.status.unlocked || !S.loaded) return;
			S.pending = null;
			if (p.page === 'emergency') { S.sub = 'emergency'; S.built = null; render(); return; }
			if (p.page === 'vault' && vaultOf(p.vaultId)) { S.vaultId = p.vaultId; S.sub = 'vault'; S.built = null; render(); return; }
			if (p.vaultId && vaultOf(p.vaultId)) S.filter = p.vaultId;
			if (S.sub !== 'list') { S.sub = 'list'; S.built = null; render(); }
		}

		// ── Events ───────────────────────────────────────────
		if (typeof api.onState === 'function') api.onState((st) => { if (st && typeof st === 'object') setStatus(st); });
		if (typeof api.onPush === 'function') {
			api.onPush((ctx) => {
				// a vault shared just now / an emergency request: open it when the page is in front
				if (!S.shown || S.mode === 'edit') return;
				S.pending = VS.pushTarget(ctx);
				if (S.status && S.status.unlocked && S.loaded) applyPending();
				if (S.sub === 'emergency') loadEmergency();
			});
		}
		refreshStatus();
		render();

		return {
			show() {
				S.shown = true;
				document.body.classList.add('vault-mode');
				clearInterval(ticker);
				ticker = setInterval(tick, 1000);
				render();
				maybeAutoUnlock();
				// Windows Hello set up / a remote session meanwhile: ask Windows again before offering it
				if (S.status && !S.status.unlocked && S.status.hello && typeof api.helloCheck === 'function') {
					call(api.helloCheck).then(() => refreshStatus());
				}
				maybeAutoHello();
				if (S.status && S.status.unlocked && !S.loaded) loadData();
			},
			hide() {
				S.shown = false;
				document.body.classList.remove('vault-mode');
				clearInterval(ticker);
				ticker = null;
				closeMenu();
				// secrets leave the screen with the page
				if (S.revealed.size) { S.revealed.clear(); if (S.mode !== 'edit') rerenderDetail(); }
				if (S.gen && refs.genOut) { S.gen = null; if (S.mode === 'edit') buildEdit(); }
				S.autoTried = false;
				S.helloTried = false;
			},
			/** Open on a push target (context of a toast click or vault:push). */
			open(ctx) {
				S.pending = VS.pushTarget(ctx);
				applyPending();
				render();
			},
			status: () => S.status,
			/** Language changed: build the screen again (a form in progress keeps its draft). */
			relabel() {
				refs.sbClip.textContent = t('vault.foot.clipboard');
				if (S.mode === 'edit' && S.built === 'home:list') {
					renderHead();
					renderChips();
					renderList();
					buildEdit();
				} else {
					S.built = null;
					render();
				}
			},
		};
	}

	root.GCVaultView = { mount };
})(typeof self !== 'undefined' ? self : this);
