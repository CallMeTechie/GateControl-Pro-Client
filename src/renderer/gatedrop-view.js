/**
 * GateControl -- GateDrop (renderer view of the plugin gatecontrol-gatedrop)
 *
 * The page "GateDrop": a drop zone ("Dateien hierher ziehen oder auswählen",
 * text or link), the state of this PC (direct receiving in the WLAN, the
 * folder Downloads\GateControl, "Senden an" in the Explorer), running
 * transfers and the lists Empfangen / Gesendet / Links (show / open / save
 * received files, copy texts, end links).
 *
 * The send dialog ("Teilen: …", opened from the page, by drag & drop on the
 * window, from "Senden an → GateDrop" in the Explorer or the tray): files,
 * text or link, Meine Geräte, Personen, Ablegen (NAS) & Link für Externe
 * (validity + PIN), note; after sending the link and its PIN.
 *
 * Data: window.gatecontrol.gatedrop (core GateDropService over IPC); texts:
 * gatedrop.* of the core locales; view logic without DOM: gatedrop-state.js
 * (window.GCGateDropState). The same file is used by Pro and Community.
 *
 * Note: server text only ever goes into textContent / attributes; icons are
 * built from static path data with createElementNS (no innerHTML).
 */
(function (root) {
	'use strict';

	const GS = root.GCGateDropState;
	const NS = 'http://www.w3.org/2000/svg';
	const ICONS = {
		share: 'M12 3v12|M7 8l5-5 5 5|M5 21h14',
		upload: 'M12 16V4|M7 9l5-5 5 5|M5 20h14',
		down: 'M12 4v11|M7 10l5 5 5-5|M5 20h14',
		up: 'M12 20V9|M7 14l5-5 5 5|M5 4h14',
		file: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z|M14 3v5h5',
		text: 'M4 6h16M4 12h16M4 18h10',
		link: 'M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1|M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1',
		folder: 'M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z',
		wifi: 'M5 12.5a10 10 0 0 1 14 0|M8.5 16a5 5 0 0 1 7 0|M12 19.5h.01|M2 9a15 15 0 0 1 20 0',
		refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8|M21 3v5h-5',
		close: 'M6 6l12 12M18 6L6 18',
		plus: 'M12 5v14M5 12h14',
		alert: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 8v5M12 16h.01',
		copy: 'M9 9h11v11H9z|M5 15H4V4h11v1',
		check: 'M4 12l5 5L20 6',
		phone: 'M8 2h8a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z|M11 18h2',
		pc: 'M3 4h18v12H3z|M8 20h8M12 16v4',
		nas: 'M4 4h16v6H4z|M4 14h16v6H4z|M8 7h.01M8 17h.01',
		lock: 'M6 11h12v10H6z|M8 11V7a4 4 0 0 1 8 0v4',
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
			else if (k === 'value') n.value = v;
			else n.setAttribute(k, v === true ? '' : String(v));
		}
		for (const c of kids || []) if (c !== null && c !== undefined && c !== false && c !== '') n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
		return n;
	}
	const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };
	let uid = 0;
	const nextId = (p) => `${p}-${++uid}`;

	/**
	 * @param {object} o
	 * @param {HTMLElement} o.root - the page section (empty)
	 * @param {object} o.api - window.gatecontrol.gatedrop
	 * @param {Function} o.t - i18n
	 * @param {() => string} o.getLocale
	 * @param {(msg: string, type?: string) => void} [o.toast]
	 * @param {(st: object) => void} [o.onStatus] - availability (nav entry)
	 * @param {() => void} [o.onOpen] - show the page (push / toast click)
	 * @param {HTMLElement} [o.dialogHost] - where the send dialog goes (default document.body)
	 * @param {() => number} [o.now]
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const now = typeof o.now === 'function' ? o.now : () => Date.now();
		const locale = () => o.getLocale();
		const host = o.dialogHost || document.body;
		let toastTimer = null;
		/** In-page notice when the app has no toast helper of its own. */
		function ownToast(msg, type) {
			let n = host.querySelector(':scope > .gd-toast');
			if (!n) { n = el('div', { class: 'gd-toast', role: 'status' }); host.appendChild(n); }
			n.className = `gd-toast${type === 'error' ? ' is-err' : ''}`;
			n.textContent = String(msg || '');
			n.hidden = false;
			clearTimeout(toastTimer);
			toastTimer = setTimeout(() => { n.hidden = true; }, 5000);
		}
		const toast = typeof o.toast === 'function' ? o.toast : ownToast;

		const S = {
			status: null,
			shown: false,
			tab: 'received',
			focusSend: null,
			lists: { received: null, sent: null, links: null },
			stale: { received: false, sent: false, links: false },
			errors: new Map(),
			loading: new Set(),
			dirty: new Set(GS.TABS),
			jobs: new Map(),      // progress id → event
			explorer: null,       // { enabled, supported }
		};

		// ── Page skeleton ────────────────────────────────────
		const refs = {};
		const rootEl = el('div', { class: 'gd' });
		o.root.appendChild(rootEl);

		function buildPage() {
			clear(rootEl);
			refs.h = el('h1', { class: 'gd-h', text: t('gatedrop.title') });
			refs.sub = el('span', { class: 'gd-sub', text: t('gatedrop.sub') });
			refs.refresh = el('button', { type: 'button', class: 'gd-ib', title: t('gatedrop.refresh'), 'aria-label': t('gatedrop.refresh'), on: { click: () => reload(true) } }, [icon('refresh', 16)]);
			refs.banner = el('div', { class: 'gd-banner', role: 'status', hidden: true });

			refs.dropZone = el('div', { class: 'gd-drop' }, [
				el('span', { class: 'gd-drop-ic' }, [icon('upload', 26, '1.8')]),
				el('b', { class: 'gd-drop-h', text: t('gatedrop.drop.title') }),
				el('span', { class: 'gd-drop-hint', text: t('gatedrop.drop.hint') }),
				el('div', { class: 'gd-drop-btns' }, [
					el('button', { type: 'button', class: 'btn btn-pri', on: { click: () => pickFiles() } }, [icon('plus', 16), el('span', { text: t('gatedrop.drop.pick') })]),
					el('button', { type: 'button', class: 'btn btn-sec', on: { click: () => openDialog({ files: [] }) } }, [icon('text', 16), el('span', { text: t('gatedrop.drop.text') })]),
				]),
			]);

			refs.listen = el('div', { class: 'gd-side-row' });
			refs.folderPath = el('span', { class: 'gd-side-sub' });
			refs.explorerRow = el('div', { class: 'gd-side-row', hidden: true });
			refs.side = el('div', { class: 'card gd-side' }, [
				refs.listen,
				el('div', { class: 'gd-side-row' }, [
					el('span', { class: 'gd-side-ic' }, [icon('folder', 16)]),
					el('div', { class: 'gd-side-tx' }, [el('b', { text: t('gatedrop.folderLabel') }), refs.folderPath]),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => call(api.openFolder()) } }, [el('span', { text: t('gatedrop.openFolder') })]),
				]),
				refs.explorerRow,
				el('span', { class: 'gd-side-note', text: t('gatedrop.retention') }),
			]);

			refs.jobs = el('div', { class: 'gd-jobs', 'aria-live': 'polite' });
			refs.tabs = el('div', { class: 'seg gd-tabs', role: 'tablist', 'aria-label': t('gatedrop.title') });
			for (const tab of GS.TABS) {
				const b = el('button', { type: 'button', role: 'tab', 'data-tab': tab, text: t(`gatedrop.tab.${tab}`), on: { click: () => setTab(tab) } });
				refs.tabs.appendChild(b);
			}
			refs.list = el('div', { class: 'gd-list', role: 'tabpanel', 'aria-live': 'polite' });

			rootEl.append(
				el('div', { class: 'gd-head' }, [el('div', { class: 'gd-head-tx' }, [refs.h, refs.sub]), el('span', { class: 'gd-grow' }), refs.refresh]),
				refs.banner,
				el('div', { class: 'gd-body scroll' }, [
					el('div', { class: 'gd-top' }, [refs.dropZone, refs.side]),
					refs.jobs,
					el('div', { class: 'gd-bar' }, [refs.tabs]),
					refs.list,
				]),
			);
			renderSide();
			renderTabs();
			renderJobs();
			renderList();
			renderBanner();
		}

		// ── Helpers ──────────────────────────────────────────

		async function call(p, okMsg) {
			try {
				const r = await p;
				if (r && r.ok === false) { toast(GS.errorText(r, t), 'error'); return null; }
				if (okMsg) toast(okMsg, 'success');
				return r;
			} catch (err) {
				toast(GS.errorText({ code: err && err.code }, t), 'error');
				return null;
			}
		}

		function available() {
			return !!S.status && S.status.state === 'available';
		}

		// ── Side card ────────────────────────────────────────

		function renderSide() {
			if (!refs.listen) return;
			clear(refs.listen);
			const on = !!(S.status && S.status.listening);
			refs.listen.append(
				el('span', { class: `gd-side-ic${on ? ' is-on' : ''}` }, [icon('wifi', 16)]),
				el('div', { class: 'gd-side-tx' }, [el('b', { text: on ? t('gatedrop.listening') : t('gatedrop.notListening') })]),
			);
			refs.folderPath.textContent = (S.status && S.status.folder) || '';
			const ex = S.explorer;
			refs.explorerRow.hidden = !ex || !ex.supported;
			clear(refs.explorerRow);
			if (ex && ex.supported) {
				const labelId = nextId('gd-ex');
				const sw = el('button', { type: 'button', class: `sw${ex.enabled ? ' on' : ''}`, role: 'switch', 'aria-checked': ex.enabled ? 'true' : 'false', 'aria-labelledby': labelId, on: { click: () => setExplorer(!ex.enabled) } }, [el('span')]);
				refs.explorerRow.append(
					el('span', { class: 'gd-side-ic' }, [icon('share', 16)]),
					el('div', { class: 'gd-side-tx' }, [el('b', { id: labelId, text: t('gatedrop.explorer') }), el('span', { class: 'gd-side-sub', text: t('gatedrop.explorerHint') })]),
					sw,
				);
			}
		}

		async function loadExplorer() {
			try { S.explorer = await api.explorer(); } catch { S.explorer = null; }
			renderSide();
		}

		async function setExplorer(enabled) {
			const r = await call(api.explorer(enabled));
			if (r) S.explorer = r;
			renderSide();
		}

		// ── Banner ───────────────────────────────────────────

		function renderBanner() {
			if (!refs.banner) return;
			clear(refs.banner);
			let text = null;
			let retry = false;
			if (S.status && S.status.state === 'unavailable') text = t('gatedrop.unavailable');
			else if (S.errors.has(S.tab)) { text = GS.errorText(S.errors.get(S.tab), t); retry = true; }
			else if (S.stale[S.tab]) text = t('gatedrop.stale');
			refs.banner.hidden = !text;
			if (!text) return;
			refs.banner.append(icon('alert', 16), el('span', { class: 'gd-grow', text }));
			if (retry) refs.banner.appendChild(el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('gatedrop.retry'), on: { click: () => reload(true) } }));
		}

		// ── Jobs (progress) ──────────────────────────────────

		function renderJobs() {
			if (!refs.jobs) return;
			clear(refs.jobs);
			for (const p of S.jobs.values()) {
				const text = GS.progressText(p, t);
				if (!text) continue;
				const bar = el('div', { class: 'gd-job-bar' }, [el('span', { style: `width:${GS.percent(p.sent, p.total)}%` })]);
				refs.jobs.appendChild(el('div', { class: `card gd-job${p.phase === 'failed' ? ' is-warn' : ''}` }, [
					el('span', { class: 'gd-job-ic' }, [icon(p.dir === 'in' ? 'down' : 'up', 16)]),
					el('div', { class: 'gd-job-tx' }, [el('span', { text: p.name ? `${p.name} · ${text}` : text }), p.phase === 'failed' ? null : bar]),
				]));
			}
		}

		function onProgress(p) {
			if (!p || !p.id) return;
			if (p.phase === 'done' || p.phase === 'sent') {
				S.jobs.delete(p.id);
			} else {
				S.jobs.set(p.id, p);
				if (p.phase === 'failed') setTimeout(() => { if (S.jobs.get(p.id) === p) { S.jobs.delete(p.id); renderJobs(); } }, 8000);
			}
			renderJobs();
		}

		// ── Tabs / lists ─────────────────────────────────────

		function renderTabs() {
			if (!refs.tabs) return;
			for (const b of refs.tabs.querySelectorAll('button')) {
				const on = b.dataset.tab === S.tab;
				b.classList.toggle('on', on);
				b.setAttribute('aria-selected', on ? 'true' : 'false');
			}
		}

		function setTab(tab) {
			if (!GS.TABS.includes(tab)) return;
			S.tab = tab;
			renderTabs();
			renderBanner();
			if (S.dirty.has(tab) || !S.lists[tab]) load(tab);
			else renderList();
		}

		async function load(kind, refresh = false) {
			if (!available()) { renderList(); return; }
			S.loading.add(kind);
			S.dirty.delete(kind);
			if (kind === S.tab) renderList();
			let r;
			try { r = await api.inbox(kind, { refresh }); } catch (err) { r = { ok: false, code: err && err.code }; }
			S.loading.delete(kind);
			if (r && r.ok) {
				S.lists[kind] = r.items || [];
				S.stale[kind] = !!r.stale;
				S.errors.delete(kind);
			} else {
				S.errors.set(kind, r || { code: 'failed' });
			}
			if (kind === S.tab) { renderList(); renderBanner(); }
		}

		function reload(refresh) {
			if (refresh) api.check().catch(() => {});
			for (const k of GS.TABS) S.dirty.add(k);
			load(S.tab, refresh === true);
		}

		function rowIcon(kind) {
			return el('span', { class: `gd-row-ic gd-ic-${kind}` }, [icon(kind === 'files' ? 'file' : kind === 'link' ? 'link' : kind === 'text' ? 'text' : kind, 18)]);
		}

		function receivedRow(s) {
			const v = GS.receivedView(s, { t, locale: locale(), now: now() });
			const actions = [];
			if (v.canShow) {
				actions.push(el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('gatedrop.list.show'), on: { click: () => call(api.showItem(s.local[0].path)) } }));
				if (s.local.length === 1) actions.push(el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('gatedrop.list.open'), on: { click: () => call(api.openItem(s.local[0].path)) } }));
			} else if (v.canSave) {
				actions.push(el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('gatedrop.list.save'), on: { click: (e) => saveSend(s, e.currentTarget) } }));
			}
			if (s.link) actions.push(el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('gatedrop.list.openLink'), on: { click: () => call(api.openLink(s.link)) } }));
			if (s.text || s.link) actions.push(el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('gatedrop.list.copyText'), on: { click: () => call(api.copy(s.text || s.link), t('gatedrop.result.copied')) } }));
			const body = [el('b', { class: 'gd-row-title', text: v.title }), el('span', { class: 'gd-row-meta', text: [v.meta, v.size].filter(Boolean).join(' · ') })];
			if (s.text) body.push(el('span', { class: 'gd-row-text', text: s.text.length > 400 ? `${s.text.slice(0, 400)}…` : s.text }));
			if (s.link && !s.text) body.push(el('span', { class: 'gd-row-text mono', text: s.link }));
			if (v.note) body.push(el('span', { class: 'gd-row-note', text: v.note }));
			return el('div', { class: `gd-row${S.focusSend && S.focusSend === s.id ? ' is-focus' : ''}`, 'data-id': s.id }, [
				rowIcon(v.kind), el('div', { class: 'gd-row-tx' }, body), el('div', { class: 'gd-row-act' }, actions),
			]);
		}

		async function saveSend(s, btn) {
			if (btn) btn.disabled = true;
			const r = await call(api.saveSend(s.id));
			if (btn) btn.disabled = false;
			if (r) load('received', true);
		}

		function sentRow(s) {
			const v = GS.sentView(s, { t, locale: locale(), now: now() });
			const chips = el('div', { class: 'gd-chips' }, v.deliveries.map((d) => el('span', { class: `gd-st gd-st-${d.tone}`, text: `${d.label}: ${d.text}` })));
			return el('div', { class: 'gd-row' }, [
				rowIcon('up'),
				el('div', { class: 'gd-row-tx' }, [el('b', { class: 'gd-row-title', text: v.title }), el('span', { class: 'gd-row-meta', text: v.meta }), v.deliveries.length ? chips : null]),
			]);
		}

		function linkRow(l) {
			const v = GS.linkView(l, { t, locale: locale(), now: now() });
			const actions = [];
			if (v.active && l.url) actions.push(el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('gatedrop.list.copyLink'), on: { click: () => call(api.copy(l.url), t('gatedrop.result.copied')) } }));
			if (v.active) {
				actions.push(el('button', {
					type: 'button', class: 'btn btn-sec btn-sm', text: t('gatedrop.list.endLink'),
					on: { click: async (e) => {
						if (!root.confirm || root.confirm(t('gatedrop.list.endConfirm'))) {
							e.currentTarget.disabled = true;
							const r = await call(api.endLink(l.token));
							if (r) load('links', true);
						}
					} },
				}));
			}
			return el('div', { class: `gd-row${v.active ? '' : ' is-old'}` }, [
				rowIcon('link'),
				el('div', { class: 'gd-row-tx' }, [el('b', { class: 'gd-row-title', text: v.title }), el('span', { class: 'gd-row-meta', text: v.meta })]),
				el('div', { class: 'gd-row-act' }, actions),
			]);
		}

		function renderList() {
			if (!refs.list) return;
			clear(refs.list);
			const kind = S.tab;
			const items = S.lists[kind];
			if (!items) {
				if (S.loading.has(kind) || !S.errors.has(kind)) refs.list.appendChild(el('div', { class: 'gd-empty', text: t('gatedrop.loading') }));
				return;
			}
			const list = kind === 'links' ? GS.sortLinks(items, now()) : items;
			if (!list.length) {
				const key = kind === 'received' ? 'emptyReceived' : kind === 'sent' ? 'emptySent' : 'emptyLinks';
				refs.list.appendChild(el('div', { class: 'gd-empty' }, [icon(kind === 'links' ? 'link' : kind === 'sent' ? 'up' : 'down', 28, '1.6'), el('span', { text: t(`gatedrop.list.${key}`) })]));
				return;
			}
			const card = el('div', { class: 'card gd-card' });
			for (const s of list) card.appendChild(kind === 'received' ? receivedRow(s) : kind === 'sent' ? sentRow(s) : linkRow(s));
			refs.list.appendChild(card);
			if (S.focusSend) {
				const hit = card.querySelector('.gd-row.is-focus');
				if (hit && hit.scrollIntoView) hit.scrollIntoView({ block: 'nearest' });
			}
		}

		// ── Send dialog ──────────────────────────────────────

		const D = { open: false, files: [], text: '', note: '', sel: GS.emptySelection(), targets: null, loadError: null, busy: false, error: null, result: null, prevFocus: null };
		const dlg = {};

		function buildDialog() {
			dlg.scrim = el('div', { class: 'gd-scrim', hidden: true, on: { mousedown: (e) => { if (e.target === dlg.scrim && !D.busy) closeDialog(); } } });
			dlg.titleId = nextId('gd-dlg-h');
			dlg.box = el('div', { class: 'gd-dlg', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': dlg.titleId });
			dlg.scrim.appendChild(dlg.box);
			dlg.scrim.addEventListener('keydown', (e) => {
				if (e.key === 'Escape' && !D.busy) { e.preventDefault(); closeDialog(); }
				if (e.key === 'Tab') trapFocus(e);
			});
			host.appendChild(dlg.scrim);
		}

		function trapFocus(e) {
			const items = [...dlg.box.querySelectorAll('button:not([disabled]), input:not([disabled]), textarea:not([disabled])')].filter((n) => n.offsetParent !== null);
			if (!items.length) return;
			const first = items[0];
			const last = items[items.length - 1];
			if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); } else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
		}

		function openDialog({ files = [], rejected = [] } = {}) {
			if (!available()) { toast(t('gatedrop.unavailable'), 'error'); return; }
			if (D.open && !D.result) {
				addFiles(files, rejected);
				return;
			}
			Object.assign(D, { open: true, files: [], text: '', note: '', sel: GS.emptySelection(), error: null, result: null, busy: false });
			D.prevFocus = document.activeElement;
			addFiles(files, rejected, { render: false });
			dlg.scrim.hidden = false;
			renderDialog();
			loadTargets(false);
			const first = dlg.box.querySelector('.gd-dlg-body textarea, .gd-dlg-body input, .gd-dlg-foot .btn-pri');
			setTimeout(() => (first || dlg.box).focus(), 0);
		}

		function closeDialog() {
			D.open = false;
			dlg.scrim.hidden = true;
			clear(dlg.box);
			if (D.prevFocus && D.prevFocus.focus) { try { D.prevFocus.focus(); } catch { /* gone */ } }
		}

		function addFiles(files, rejected, { render = true } = {}) {
			const m = GS.mergeFiles(D.files, files);
			D.files = m.files;
			const msgs = GS.rejectedTexts(rejected, t);
			if (m.dropped) msgs.push(t('gatedrop.dialog.tooMany'));
			if (msgs.length) toast(msgs.join(' '), 'error');
			if (render && D.open) renderDialog();
		}

		async function loadTargets(refresh) {
			D.loadError = null;
			let r;
			try { r = await api.targets({ refresh }); } catch (err) { r = { ok: false, code: err && err.code }; }
			if (!D.open) return;
			if (r && r.ok) D.targets = r;
			else D.loadError = r || { code: 'failed' };
			renderDialog();
		}

		async function dialogPick() {
			const r = await api.pick().catch(() => null);
			if (r && r.ok) addFiles(r.files, r.rejected);
		}

		function sectionLabel(text) {
			return el('span', { class: 'lbl gd-lbl', text });
		}

		function targetChip({ label, on, onClick, iconName }) {
			return el('button', { type: 'button', class: `gd-tchip${on ? ' is-on' : ''}`, 'aria-pressed': on ? 'true' : 'false', on: { click: onClick } }, [iconName ? icon(iconName, 14) : null, el('span', { text: label })]);
		}

		function renderDialog() {
			if (!D.open) return;
			const keepScroll = dlg.body ? dlg.body.scrollTop : 0;
			clear(dlg.box);
			if (D.result) { renderResult(); return; }

			const head = el('div', { class: 'gd-dlg-head' }, [
				el('h2', { id: dlg.titleId, class: 'gd-dlg-h', text: GS.dialogTitle(D.files, t) }),
				el('button', { type: 'button', class: 'gd-ib', 'aria-label': t('gatedrop.dialog.close'), title: t('gatedrop.dialog.close'), disabled: D.busy, on: { click: () => closeDialog() } }, [icon('close', 16)]),
			]);

			const body = el('div', { class: 'gd-dlg-body' });
			dlg.body = body;

			// Files
			if (D.files.length) {
				const list = el('div', { class: 'gd-files' });
				for (const f of D.files) {
					list.appendChild(el('div', { class: 'gd-file' }, [
						icon('file', 14),
						el('span', { class: 'gd-file-name', text: f.name, title: f.name }),
						el('span', { class: 'gd-file-size', text: GS.formatBytes(f.size, locale()) }),
						el('button', { type: 'button', class: 'gd-file-x', 'aria-label': t('gatedrop.dialog.remove', { name: f.name }), disabled: D.busy, on: { click: () => { D.files = D.files.filter((x) => x.id !== f.id); renderDialog(); } } }, [icon('close', 12)]),
					]));
				}
				body.appendChild(list);
			}
			body.appendChild(el('button', { type: 'button', class: 'btn btn-ghost btn-sm gd-add', disabled: D.busy, on: { click: () => dialogPick() } }, [icon('plus', 14), el('span', { text: t('gatedrop.dialog.add') })]));

			const textId = nextId('gd-text');
			const ta = el('textarea', { id: textId, class: 'gd-input gd-textarea', rows: '2', maxlength: '20000', placeholder: t('gatedrop.dialog.textPlaceholder'), disabled: D.busy, value: D.text, on: { input: (e) => { D.text = e.target.value; updateFoot(); } } });
			body.appendChild(el('label', { class: 'gd-sr', for: textId, text: t('gatedrop.dialog.text') }));
			body.appendChild(ta);

			// Targets
			if (!D.targets && !D.loadError) {
				body.appendChild(el('div', { class: 'gd-dlg-load', text: t('gatedrop.loading') }));
			} else if (!D.targets && D.loadError) {
				body.appendChild(el('div', { class: 'gd-dlg-load' }, [
					el('span', { text: t('gatedrop.dialog.loadFailed') }),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('gatedrop.retry'), on: { click: () => loadTargets(true) } }),
				]));
			} else {
				const tg = GS.dialogTargets(D.targets);
				body.appendChild(sectionLabel(t('gatedrop.dialog.devices')));
				if (!tg.devices.length) body.appendChild(el('span', { class: 'gd-none', text: t('gatedrop.dialog.noDevices') }));
				for (const d of tg.devices) {
					const id = nextId('gd-dev');
					const checked = D.sel.devices.includes(d.id);
					body.appendChild(el('label', { class: 'gd-dev', for: id }, [
						el('input', { id, type: 'checkbox', checked, disabled: D.busy, on: { change: () => { D.sel.devices = GS.toggle(D.sel.devices, d.id); updateFoot(); } } }),
						icon(d.platform === 'windows' ? 'pc' : 'phone', 16),
						el('b', { text: d.name }),
						el('span', { class: `gd-dev-meta${d.online ? ' is-on' : ''}`, text: GS.deviceMeta(d, t) }),
					]));
				}
				body.appendChild(sectionLabel(t('gatedrop.dialog.people')));
				if (!tg.people.length) body.appendChild(el('span', { class: 'gd-none', text: t('gatedrop.dialog.noPeople') }));
				else {
					const row = el('div', { class: 'gd-tchips' });
					for (const p of tg.people) {
						row.appendChild(targetChip({
							label: p.kind === 'family' ? (p.name || t('gatedrop.dialog.family')) : p.name,
							on: D.sel.people.includes(p.id),
							onClick: () => { D.sel.people = GS.toggle(D.sel.people, p.id); renderDialog(); },
						}));
					}
					body.appendChild(row);
				}
				if (tg.nas.length || tg.link) {
					body.appendChild(sectionLabel(t('gatedrop.dialog.nasLink')));
					const row = el('div', { class: 'gd-tchips' });
					for (const n of tg.nas) {
						row.appendChild(targetChip({ label: t('gatedrop.dialog.nas', { path: n.path || n.label }), iconName: 'nas', on: D.sel.nas.includes(n.id), onClick: () => { D.sel.nas = GS.toggle(D.sel.nas, n.id); renderDialog(); } }));
					}
					if (tg.link) {
						row.appendChild(targetChip({ label: D.sel.link ? t('gatedrop.dialog.linkOn') : t('gatedrop.dialog.link'), iconName: 'link', on: D.sel.link, onClick: () => { D.sel.link = !D.sel.link; renderDialog(); } }));
					}
					body.appendChild(row);
					if (tg.link && D.sel.link) {
						const seg = el('div', { class: 'seg gd-exp', role: 'radiogroup', 'aria-label': t('gatedrop.dialog.expires') });
						if (!tg.expires.includes(D.sel.expires)) D.sel.expires = tg.expires.includes('1d') ? '1d' : tg.expires[0];
						for (const x of tg.expires) {
							seg.appendChild(el('button', { type: 'button', role: 'radio', 'aria-checked': D.sel.expires === x ? 'true' : 'false', class: D.sel.expires === x ? 'on' : '', text: t(`gatedrop.expires.${x}`), on: { click: () => { D.sel.expires = x; renderDialog(); } } }));
						}
						const pinLabel = nextId('gd-pin');
						body.appendChild(el('div', { class: 'gd-linkopts' }, [
							el('div', { class: 'gd-linkopt' }, [el('span', { class: 'gd-linkopt-l', text: t('gatedrop.dialog.expires') }), seg]),
							el('div', { class: 'gd-linkopt' }, [
								icon('lock', 14),
								el('span', { id: pinLabel, class: 'gd-linkopt-l gd-grow', text: t('gatedrop.dialog.pin') }),
								el('button', { type: 'button', class: `sw${D.sel.pin ? ' on' : ''}`, role: 'switch', 'aria-checked': D.sel.pin ? 'true' : 'false', 'aria-labelledby': pinLabel, on: { click: () => { D.sel.pin = !D.sel.pin; renderDialog(); } } }, [el('span')]),
							]),
							el('span', { class: 'gd-none', text: t('gatedrop.dialog.linkHint') }),
						]));
					}
				}
			}

			const noteId = nextId('gd-note');
			body.appendChild(el('label', { class: 'lbl gd-lbl', for: noteId, text: t('gatedrop.dialog.note') }));
			body.appendChild(el('input', { id: noteId, type: 'text', class: 'gd-input', maxlength: '500', placeholder: t('gatedrop.dialog.notePlaceholder'), disabled: D.busy, value: D.note, on: { input: (e) => { D.note = e.target.value; } } }));

			dlg.err = el('span', { class: 'gd-dlg-err', role: 'alert' });
			dlg.send = el('button', { type: 'button', class: 'btn btn-pri', on: { click: () => doSend() } }, [el('span', { text: D.busy ? t('gatedrop.dialog.sending') : t('gatedrop.dialog.send') })]);
			const foot = el('div', { class: 'gd-dlg-foot' }, [
				dlg.err,
				el('button', { type: 'button', class: 'btn btn-sec', text: t('gatedrop.dialog.cancel'), disabled: D.busy, on: { click: () => closeDialog() } }),
				dlg.send,
			]);
			dlg.box.append(head, body, foot);
			body.scrollTop = keepScroll;
			updateFoot();
		}

		function updateFoot() {
			if (!dlg.send) return;
			const c = GS.canSend({ files: D.files, text: D.text, selection: D.sel, targets: D.targets });
			dlg.send.disabled = D.busy || !c.ok;
			dlg.err.textContent = D.error ? D.error : (!c.ok && (D.files.length || D.text) && c.key !== 'gatedrop.dialog.empty' ? t(c.key) : '');
		}

		async function doSend() {
			const c = GS.canSend({ files: D.files, text: D.text, selection: D.sel, targets: D.targets });
			if (!c.ok || D.busy) return;
			const tl = GS.splitTextLink(D.text);
			D.busy = true;
			D.error = null;
			renderDialog();
			let r;
			try {
				r = await api.send({ files: D.files.map((f) => f.id), text: tl.text, link: tl.link, note: D.note.trim() || null, to: GS.buildTo(D.sel, D.targets) });
			} catch (err) {
				r = { ok: false, code: err && err.code };
			}
			D.busy = false;
			if (!D.open) return;
			if (!r || r.ok === false) {
				D.error = GS.errorText(r, t);
				renderDialog();
				return;
			}
			S.dirty.add('sent');
			S.dirty.add('links');
			if (S.shown && (S.tab === 'sent' || S.tab === 'links')) load(S.tab);
			if (r.link || (r.direct && r.direct.length)) {
				D.result = r;
				renderDialog();
			} else {
				closeDialog();
				toast(t('gatedrop.result.title'), 'success');
			}
		}

		function renderResult() {
			const r = D.result;
			const kids = [
				el('div', { class: 'gd-dlg-head' }, [
					el('span', { class: 'gd-ok-ic' }, [icon('check', 18)]),
					el('h2', { id: dlg.titleId, class: 'gd-dlg-h', text: t('gatedrop.result.title') }),
				]),
			];
			const body = el('div', { class: 'gd-dlg-body' });
			if (r.direct && r.direct.length) body.appendChild(el('span', { class: 'gd-none', text: t('gatedrop.result.direct') }));
			if (r.link && r.link.url) {
				const copyBtn = el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: async () => {
					const ok = await call(api.copy(r.link.pin ? `${r.link.url}\nPIN: ${r.link.pin}` : r.link.url));
					if (ok) { copyBtn.lastChild.textContent = t('gatedrop.result.copied'); }
				} } }, [icon('copy', 14), el('span', { text: t('gatedrop.result.copy') })]);
				body.append(
					el('span', { class: 'lbl gd-lbl', text: t('gatedrop.result.link') }),
					el('div', { class: 'gd-linkbox' }, [el('span', { class: 'gd-linkurl mono', text: r.link.url }), copyBtn]),
				);
				if (r.link.pin) body.appendChild(el('b', { class: 'gd-pin mono', text: t('gatedrop.result.pin', { pin: r.link.pin }) }));
			}
			kids.push(body);
			kids.push(el('div', { class: 'gd-dlg-foot' }, [el('span', { class: 'gd-grow' }), el('button', { type: 'button', class: 'btn btn-pri', text: t('gatedrop.result.done'), on: { click: () => closeDialog() } })]));
			dlg.box.append(...kids);
			const done = dlg.box.querySelector('.gd-dlg-foot .btn-pri');
			if (done) setTimeout(() => done.focus(), 0);
		}

		async function pickFiles() {
			if (!available()) return;
			const r = await api.pick().catch(() => null);
			if (r && r.ok) openDialog({ files: r.files, rejected: r.rejected });
		}

		// ── Status ───────────────────────────────────────────

		function applyStatus(st) {
			const was = available();
			S.status = st || null;
			renderSide();
			renderBanner();
			if (typeof o.onStatus === 'function') { try { o.onStatus(S.status); } catch { /* app */ } }
			if (!was && available()) {
				loadExplorer();
				if (S.shown) reload(false);
			}
			if (!available() && D.open && S.status && S.status.state === 'unavailable') closeDialog();
		}

		// ── Events ───────────────────────────────────────────

		const unsub = [];
		const on = (fn, cb) => { if (typeof fn === 'function') { const off = fn(cb); if (typeof off === 'function') unsub.push(off); } };
		on(api.onState, (st) => applyStatus(st));
		on(api.onProgress, (p) => onProgress(p));
		on(api.onChanged, (c) => {
			const kind = c && GS.TABS.includes(c.kind) ? c.kind : null;
			if (kind) S.dirty.add(kind);
			if (S.shown && kind === S.tab) load(kind);
		});
		on(api.onReceived, () => {
			S.dirty.add('received');
			if (S.shown && S.tab === 'received') load('received', true);
		});
		on(api.onCompose, (c) => openDialog(c || {}));
		on(api.onNavigate, (ctx) => { open(ctx); if (typeof o.onOpen === 'function') o.onOpen(); });

		// ── Public ───────────────────────────────────────────

		function show() {
			S.shown = true;
			if (!S.explorer) loadExplorer();
			if (S.dirty.has(S.tab) || !S.lists[S.tab]) load(S.tab);
		}

		function hide() {
			S.shown = false;
		}

		function open(ctx) {
			const c = GS.navContext(ctx);
			S.focusSend = c.sendId;
			S.dirty.add(c.tab);
			S.tab = c.tab;
			renderTabs();
			if (S.shown) load(c.tab, true);
		}

		function relabel() {
			buildPage();
			if (D.open) renderDialog();
		}

		buildDialog();
		buildPage();
		api.status().then((st) => applyStatus(st)).catch(() => applyStatus({ state: 'unknown' }));
		// "Senden an" while the window was still loading: the files wait in main.
		if (typeof api.takeCompose === 'function') {
			api.takeCompose().then((c) => {
				if (c && c.ok && ((c.files && c.files.length) || (c.rejected && c.rejected.length))) {
					const tryOpen = (n) => { if (available()) openDialog(c); else if (n > 0) setTimeout(() => tryOpen(n - 1), 500); };
					tryOpen(20);
				}
			}).catch(() => {});
		}

		return {
			show,
			hide,
			open,
			relabel,
			compose: (c) => openDialog(c || {}),
			openDialog: (c) => openDialog(c || {}),
			pick: () => pickFiles(),
			status: () => S.status,
			available,
			destroy: () => { for (const off of unsub.splice(0)) { try { off(); } catch { /* gone */ } } },
		};
	}

	/**
	 * Files dragged onto the window → the send dialog. Drops a page handles
	 * itself (the chat composer calls preventDefault) are left alone; a drop
	 * that nobody takes never navigates the window to the file.
	 * @param {object} o
	 * @param {object} o.view - mount() result
	 * @param {object} o.api - window.gatecontrol.gatedrop (prepareDropped)
	 * @param {Function} o.t
	 * @param {HTMLElement} [o.host] - overlay parent (default document.body)
	 * @param {(target: Element) => boolean} [o.skip] - areas with their own drop (chat)
	 * @param {(msg: string, type?: string) => void} [o.toast]
	 * @returns {() => void} detach
	 */
	function attachWindowDrop({ view, api, t, host = document.body, skip = () => false, toast = () => {} }) {
		const overlay = el('div', { class: 'gd-drop-overlay', hidden: true }, [el('div', null, [icon('share', 32, '1.8'), el('span', { text: t('gatedrop.drop.overlay') })])]);
		host.appendChild(overlay);
		let depth = 0;
		const hasFiles = (e) => !!e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
		const ours = (e) => hasFiles(e) && view.available() && !(e.target && e.target.nodeType === 1 && skip(e.target));
		const hide = () => { depth = 0; overlay.hidden = true; };
		const onEnter = (e) => {
			if (!ours(e)) return;
			depth++;
			overlay.firstChild.lastChild.textContent = t('gatedrop.drop.overlay');
			overlay.hidden = false;
		};
		const onOver = (e) => {
			if (!hasFiles(e)) return;
			// Always: no navigation to a dropped file; copy only where GateDrop takes it.
			e.preventDefault();
			if (e.dataTransfer) e.dataTransfer.dropEffect = ours(e) ? 'copy' : 'none';
		};
		const onLeave = () => { depth = Math.max(0, depth - 1); if (!depth) overlay.hidden = true; };
		const onDrop = async (e) => {
			if (!hasFiles(e)) return;
			const take = !e.defaultPrevented && ours(e);
			e.preventDefault();
			hide();
			if (!take) return;
			const r = await api.prepareDropped(e.dataTransfer.files).catch(() => null);
			if (r && r.ok) view.compose({ files: r.files, rejected: r.rejected });
			else toast(GS.errorText(r, t), 'error');
		};
		window.addEventListener('dragenter', onEnter);
		window.addEventListener('dragover', onOver);
		window.addEventListener('dragleave', onLeave);
		window.addEventListener('drop', onDrop);
		window.addEventListener('dragend', hide);
		return () => {
			window.removeEventListener('dragenter', onEnter);
			window.removeEventListener('dragover', onOver);
			window.removeEventListener('dragleave', onLeave);
			window.removeEventListener('drop', onDrop);
			window.removeEventListener('dragend', hide);
			overlay.remove();
		};
	}

	root.GCGateDropView = { mount, attachWindowDrop };
})(typeof self !== 'undefined' ? self : this);
