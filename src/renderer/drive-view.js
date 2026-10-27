/**
 * GateControl -- Drive (renderer view of the plugin gatecontrol-drive)
 *
 * The page "Drive": the areas on the left (Meine Dateien, Familie, Kinder ·
 * Name, Team · Name with their storage), "Geteilt" (the person's links) and
 * "Papierkorb"; on the right the folder with breadcrumbs, sorting, "Neuer
 * Ordner" and "Hochladen" (button or files dropped on the page), the list
 * (preview pictures, name, date, size) and a menu per row: Öffnen, Speichern
 * unter …, Link teilen (rights, validity, PIN), Umbenennen, Verschieben,
 * Ältere Versionen, In den Papierkorb. Search covers names and the
 * recognised text of scans (with the words around the hit). Uploads and
 * downloads show in a list at the bottom; a taken name asks "Neue Version" /
 * "Beide behalten" / "Überspringen".
 *
 * "Ordner sichern" (folders of this PC backed up / synced, core DriveSync)
 * is a view of the page too: drive-sync-view.js, shown by the last entry on
 * the left.
 *
 * pickFolder() is the dialog "In Drive speichern" of Chats, GateDrop and
 * Schule: writable areas and folders only, it starts in the folder picked
 * last and remembers the new one.
 *
 * Data: window.gatecontrol.drive (core DriveService over IPC); texts: drive.*
 * of the app locales; view logic without DOM: drive-state.js
 * (window.GCDriveState).
 *
 * Note: server text only ever goes into textContent / attributes; icons are
 * built from static path data with createElementNS (no innerHTML).
 */
(function (root) {
	'use strict';

	const DS = root.GCDriveState;
	const NS = 'http://www.w3.org/2000/svg';
	const ICONS = {
		cloud: 'M7 18h10a4 4 0 0 0 .5-8A6 6 0 0 0 6 9.5 4.3 4.3 0 0 0 7 18z',
		folder: 'M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z',
		file: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z|M14 3v5h5',
		image: 'M4 5h16v14H4z|M4 16l5-5 4 4 3-3 4 4|M15 9h.01',
		video: 'M4 6h12v12H4z|M16 10l5-3v10l-5-3',
		audio: 'M9 18V6l10-2v12|M9 18a3 3 0 1 1-6 0a3 3 0 1 1 6 0|M19 16a3 3 0 1 1-6 0a3 3 0 1 1 6 0',
		pdf: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z|M14 3v5h5|M8 13h8M8 17h5',
		archive: 'M4 4h16v4H4z|M5 8v12h14V8|M10 12h4',
		user: 'M12 4a4 4 0 1 0 0 8a4 4 0 1 0 0-8|M4 20a8 8 0 0 1 16 0',
		users: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2|M9 3a4 4 0 1 0 0 8a4 4 0 1 0 0-8|M22 21v-2a4 4 0 0 0-3-3.87|M16 3.13a4 4 0 0 1 0 7.75',
		child: 'M12 3a3 3 0 1 0 0 6a3 3 0 1 0 0-6|M7 21v-6l-2-3 4-2h6l4 2-2 3v6',
		team: 'M3 21h18|M5 21V7l7-4 7 4v14|M9 21v-6h6v6',
		link: 'M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1|M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1',
		trash: 'M4 7h16|M10 11v6M14 11v6|M6 7l1 13h10l1-13|M9 7V4h6v3',
		search: 'M11 4a7 7 0 1 0 0 14a7 7 0 1 0 0-14|M21 21l-4.3-4.3',
		refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8|M21 3v5h-5',
		upload: 'M12 16V4|M7 9l5-5 5 5|M5 20h14',
		down: 'M12 4v11|M7 10l5 5 5-5|M5 20h14',
		plus: 'M12 5v14M5 12h14',
		more: 'M5 12h.01M12 12h.01M19 12h.01',
		close: 'M6 6l12 12M18 6L6 18',
		back: 'M15 6l-6 6 6 6',
		chevron: 'M9 6l6 6-6 6',
		pen: 'M4 20h4L19 9l-4-4L4 16z',
		move: 'M5 12h14|M13 6l6 6-6 6',
		history: 'M3 12a9 9 0 1 0 3-6.7L3 8|M3 3v5h5|M12 7v5l3 3',
		restore: 'M3 12a9 9 0 1 0 3-6.7L3 8|M3 3v5h5',
		copy: 'M9 9h11v11H9z|M5 15H4V4h11v1',
		open: 'M14 4h6v6|M20 4l-9 9|M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5',
		eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z|M12 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6',
		alert: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 8v5M12 16h.01',
		check: 'M4 12l5 5L20 6',
		lock: 'M6 11h12v10H6z|M8 11V7a4 4 0 0 1 8 0v4',
		pause: 'M8 5v14M16 5v14',
		play: 'M7 5l12 7-12 7z',
		sync: 'M4 12a8 8 0 0 1 14-5.3L20 9|M20 4v5h-5|M20 12a8 8 0 0 1-14 5.3L4 15|M4 20v-5h5',
	};
	const KIND_ICON = { folder: 'folder', image: 'image', video: 'video', audio: 'audio', pdf: 'pdf', archive: 'archive' };
	const AREA_ICON = { mine: 'user', family: 'users', child: 'child', team: 'team' };

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
		for (const d of String(ICONS[name] || ICONS.file).split('|')) {
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
	const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed', error: err && err.message });

	// ── Dialog (modal) ───────────────────────────────────

	/**
	 * A modal dialog: openDialog({ title, host, onClose }) → { box, body, foot, setTitle, close }.
	 * Esc and a click on the backdrop close it; focus returns to where it was.
	 */
	function openDialog({ title, host = document.body, onClose = null, wide = false, closeLabel = 'Close' }) {
		const before = document.activeElement;
		const titleId = nextId('dv-dlg-t');
		const h = el('h2', { id: titleId, class: 'dv-dlg-h', text: title });
		const body = el('div', { class: 'dv-dlg-body' });
		const foot = el('div', { class: 'dv-dlg-foot' });
		let closed = false;
		const close = (value) => {
			if (closed) return;
			closed = true;
			document.removeEventListener('keydown', onKey, true);
			scrim.remove();
			if (before && typeof before.focus === 'function' && before.isConnected) before.focus();
			if (onClose) onClose(value);
		};
		const box = el('div', { class: `dv-dlg${wide ? ' is-wide' : ''}`, role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId, tabindex: '-1' }, [
			el('div', { class: 'dv-dlg-head' }, [h, el('button', { type: 'button', class: 'dv-ib', 'aria-label': closeLabel, title: closeLabel, on: { click: () => close(null) } }, [icon('close', 16)])]),
			body,
			foot,
		]);
		const scrim = el('div', { class: 'dv-scrim', on: { mousedown: (e) => { if (e.target === scrim) close(null); } } }, [box]);
		function onKey(e) {
			if (e.key === 'Escape') { e.stopPropagation(); close(null); }
		}
		document.addEventListener('keydown', onKey, true);
		host.appendChild(scrim);
		setTimeout(() => {
			const first = body.querySelector('input, button, [tabindex="0"]');
			(first || box).focus();
		}, 0);
		return { box, body, foot, close, setTitle: (s) => { h.textContent = s; }, get closed() { return closed; } };
	}

	// ── Folder picker ────────────────────────────────────

	/**
	 * "In Drive speichern" / "Verschieben": a folder the person may write to.
	 * Writable areas first, then their folders; starts in the folder picked
	 * last (when it still loads and is writable).
	 *
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive
	 * @param {Function} o.t
	 * @param {string} [o.title]
	 * @param {string} [o.confirm] - text of the confirm button
	 * @param {number} [o.exclude] - a folder that must not be picked or entered (the node being moved)
	 * @param {boolean} [o.remember=true] - remember the folder picked (drive.setLastFolder)
	 * @param {number} [o.startId] - start here instead of the folder picked last
	 * @param {string} [o.fallback] - the plugin's own place without a pick ("Meine Dateien › Messenger"):
	 *   a button "Standardort" that resolves { folderId: null, path: fallback }
	 * @returns {Promise<{ folderId: number|null, path: string } | null>}
	 */
	function pickFolder(o) {
		const api = o.api;
		const t = o.t;
		const remember = o.remember !== false;
		return new Promise((resolve) => {
			const P = { areas: null, folder: null, area: null, loading: true, error: null };
			const dlg = openDialog({ title: o.title || t('drive.picker.title'), host: o.host, closeLabel: t('drive.close'), onClose: (v) => resolve(v || null) });
			const path = el('div', { class: 'dv-pick-path' });
			const list = el('div', { class: 'dv-pick-list', role: 'list' });
			const err = el('span', { class: 'dv-dlg-err', role: 'alert' });
			const ok = el('button', { type: 'button', class: 'btn btn-pri', text: o.confirm || t('drive.picker.here'), on: { click: () => pick() } });
			dlg.body.append(path, list);
			const std = o.fallback ? el('button', { type: 'button', class: 'btn btn-ghost', title: o.fallback, text: t('drive.picker.default'), on: { click: () => dlg.close({ folderId: null, path: o.fallback }) } }) : null;
			dlg.foot.append(err, std, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), ok);

			async function pick() {
				if (!DS.canPick(P.folder) || P.folder.node.id === o.exclude) return;
				const id = P.folder.node.id;
				if (remember && typeof api.setLastFolder === 'function') await Promise.resolve(api.setLastFolder(id)).catch(() => {});
				dlg.close({ folderId: id, path: DS.pickerPath(P.folder, P.area, t) });
			}

			async function browse(id, initial = false) {
				if (!id) { P.folder = null; P.area = null; render(); return; }
				P.loading = true;
				render();
				const r = await Promise.resolve(api.folder(id, { limit: 1000 })).catch(fail);
				P.loading = false;
				if (r && r.ok) {
					if (initial && !DS.canPick(r)) { P.folder = null; render(); return; }
					P.folder = r;
					P.area = (P.areas || []).find((a) => a.id === r.node.areaId) || null;
					P.error = null;
				} else if (initial) {
					P.folder = null;
				} else {
					P.error = DS.errorText(r, t);
				}
				render();
			}

			function row(label, sub, ic, onClick, disabled) {
				return el('button', { type: 'button', role: 'listitem', class: 'dv-pick-row', disabled: disabled || null, on: { click: onClick } }, [
					el('span', { class: 'dv-pick-ic' }, [icon(ic, 16)]),
					el('span', { class: 'dv-pick-tx' }, [el('span', { class: 'dv-pick-name', text: label }), sub ? el('span', { class: 'dv-pick-sub', text: sub }) : null]),
					icon('chevron', 14),
				]);
			}

			function render() {
				clear(list);
				err.textContent = P.error || '';
				if (P.loading && !P.areas) {
					list.appendChild(el('div', { class: 'dv-pick-note', text: t('drive.loading') }));
				} else if (!P.folder) {
					path.textContent = t('drive.picker.areas');
					const areas = DS.writableAreas(P.areas);
					if (!areas.length) list.appendChild(el('div', { class: 'dv-pick-note', text: P.error || t('drive.picker.none') }));
					for (const a of areas) list.appendChild(row(DS.areaLabel(a, t), DS.areaHint(a, t), AREA_ICON[a.kind] || 'folder', () => browse(a.rootId)));
				} else {
					path.textContent = DS.pickerPath(P.folder, P.area, t);
					const cr = P.folder.crumbs || [];
					const parent = cr.length > 1 ? cr[cr.length - 2].id : null;
					list.appendChild(el('button', { type: 'button', class: 'dv-pick-row is-back', on: { click: () => browse(parent) } }, [
						el('span', { class: 'dv-pick-ic' }, [icon('back', 16)]),
						el('span', { class: 'dv-pick-name', text: parent ? t('drive.picker.up') : t('drive.picker.areas') }),
					]));
					const subs = DS.pickerFolders(P.folder, o.exclude);
					if (!subs.length) list.appendChild(el('div', { class: 'dv-pick-note', text: t('drive.picker.noFolders') }));
					for (const n of subs) list.appendChild(row(n.name, null, 'folder', () => browse(n.id)));
				}
				ok.disabled = !P.folder || !DS.canPick(P.folder) || P.folder.node.id === o.exclude || P.loading;
			}

			(async () => {
				const [areas, last] = await Promise.all([
					Promise.resolve(api.areas()).catch(fail),
					o.startId ? Promise.resolve({ ok: true, folderId: o.startId }) : Promise.resolve(typeof api.lastFolder === 'function' ? api.lastFolder() : null).catch(() => null),
				]);
				P.loading = false;
				if (areas && areas.ok) P.areas = areas.areas;
				else { P.areas = []; P.error = DS.errorText(areas, t); }
				const start = DS.pickerStart(last && last.folderId);
				if (start && start !== o.exclude && P.areas.length) await browse(start, true);
				else render();
			})();
		});
	}

	// ── The page ─────────────────────────────────────────

	/**
	 * @param {object} o
	 * @param {HTMLElement} o.root - the page section (empty)
	 * @param {object} o.api - window.gatecontrol.drive
	 * @param {Function} o.t - i18n
	 * @param {() => string} o.getLocale
	 * @param {(msg: string, type?: string) => void} [o.toast]
	 * @param {(st: object) => void} [o.onStatus] - availability (nav entry)
	 * @param {HTMLElement} [o.dialogHost]
	 * @param {() => number} [o.now]
	 * @returns {{ show(), hide(), refresh(), status(), available(), relabel(), pickFolder(opts) }}
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const now = typeof o.now === 'function' ? o.now : () => Date.now();
		const locale = () => o.getLocale();
		const toast = typeof o.toast === 'function' ? o.toast : () => {};
		const host = o.dialogHost || document.body;
		const store = (() => { try { return root.localStorage || null; } catch { return null; } })();
		const remembered = (k) => { try { return store ? store.getItem(k) : null; } catch { return null; } };
		const keep = (k, v) => { try { if (store) store.setItem(k, v); } catch { /* private */ } };

		const S = {
			status: null,
			shown: false,
			dirty: true,
			me: null,
			access: null,
			areas: [],
			areaId: remembered('gc.drive.area'),
			view: 'folder',     // folder | search | trash | links | sync
			folderId: null,
			folder: null,
			sort: DS.SORTS.includes(remembered('gc.drive.sort')) ? remembered('gc.drive.sort') : 'name',
			query: '',
			results: null,
			trash: null,
			links: null,
			loading: false,
			error: null,
			transfers: [],
			conflictOpen: false,
			menu: null,
			previews: new Map(),
			syncSummary: '',
		};

		// ── Skeleton ─────────────────────────────────────
		const refs = {};
		const rootEl = el('div', { class: 'dv' });
		o.root.appendChild(rootEl);
		refs.h = el('h1', { class: 'dv-h', text: t('drive.title') });
		refs.sub = el('span', { class: 'dv-sub' });
		refs.searchLabel = el('label', { class: 'dv-sr', for: nextId('dv-q') });
		refs.search = el('input', { id: refs.searchLabel.getAttribute('for'), type: 'search', class: 'dv-search-in', maxlength: '100', on: { input: onSearchInput, keydown: onSearchKey } });
		refs.refresh = el('button', { type: 'button', class: 'dv-ib', on: { click: () => reload() } }, [icon('refresh', 16)]);
		refs.banner = el('div', { class: 'dv-banner', role: 'status', hidden: true });
		refs.side = el('nav', { class: 'dv-side scroll' });
		refs.bar = el('div', { class: 'dv-bar' });
		refs.note = el('div', { class: 'dv-note', hidden: true });
		refs.list = el('div', { class: 'dv-list card', role: 'list' });
		refs.listWrap = el('div', { class: 'dv-list-wrap scroll' }, [refs.list]);
		refs.transfers = el('div', { class: 'dv-transfers card', hidden: true });
		// "Ordner sichern" (drive-sync-view.js): only with the core's DriveSync
		const syncView = root.GCDriveSyncView && api.sync ? root.GCDriveSyncView.mount({
			api: api.sync, t, getLocale: o.getLocale, now, toast, host, onDemandApi: o.onDemandApi || null,
			ui: { el, icon, clear, openDialog },
			pickDriveFolder: (opts) => pickFolder({ api, t, host, ...(opts || {}) }),
			onSummary: (sum) => {
				const tx = sum ? sum.text : '';
				if (tx === S.syncSummary) return;
				S.syncSummary = tx;
				if (S.shown && !refs.main.hidden) renderSide();
			},
		}) : null;
		refs.pane = el('section', { class: 'dv-pane' }, [refs.bar, refs.note, refs.listWrap, refs.transfers, syncView ? syncView.el : null]);
		refs.empty = el('div', { class: 'dv-gate', hidden: true });
		refs.main = el('div', { class: 'dv-main' }, [refs.side, refs.pane]);
		rootEl.append(
			el('div', { class: 'dv-head' }, [
				el('div', { class: 'dv-head-tx' }, [refs.h, refs.sub]),
				el('span', { class: 'dv-grow' }),
				el('div', { class: 'dv-search' }, [icon('search', 15), refs.searchLabel, refs.search]),
				refs.refresh,
			]),
			refs.banner,
			refs.empty,
			refs.main,
		);

		// Files dropped on the page go into the folder shown.
		let dragDepth = 0;
		const hasFiles = (e) => !!e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
		rootEl.addEventListener('dragenter', (e) => { if (!hasFiles(e)) return; dragDepth++; rootEl.classList.toggle('is-drop', canUpload()); });
		rootEl.addEventListener('dragleave', () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) rootEl.classList.remove('is-drop'); });
		rootEl.addEventListener('dragover', (e) => {
			if (!hasFiles(e)) return;
			e.preventDefault();
			if (e.dataTransfer) e.dataTransfer.dropEffect = canUpload() ? 'copy' : 'none';
		});
		rootEl.addEventListener('drop', async (e) => {
			if (!hasFiles(e)) return;
			e.preventDefault();
			dragDepth = 0;
			rootEl.classList.remove('is-drop');
			if (!canUpload()) { toast(t('drive.upload.notHere'), 'error'); return; }
			const r = await Promise.resolve(api.uploadDropped(S.folder.node.id, e.dataTransfer.files)).catch(fail);
			afterQueue(r);
		});

		// ── Status ───────────────────────────────────────
		function setStatus(st) {
			S.status = st || null;
			if (typeof o.onStatus === 'function') o.onStatus(S.status);
			if (S.shown && S.status && S.status.state === 'available' && S.dirty) reload();
		}
		Promise.resolve(api.status()).then(setStatus).catch(() => {});
		api.onState((st) => { S.dirty = true; setStatus(st); });
		api.onTransfers((rows) => { S.transfers = Array.isArray(rows) ? rows : []; renderTransfers(); maybeAskConflict(); });
		api.onChanged((c) => {
			if (S.shown && S.view === 'folder' && S.folder && c && c.folderId === S.folder.node.id) loadFolder(S.folder.node.id, { quiet: true });
			else S.dirty = true;
		});
		Promise.resolve(api.transfers()).then((r) => { if (r && r.ok) { S.transfers = r.transfers; renderTransfers(); } }).catch(() => {});

		// ── Loading ──────────────────────────────────────
		const area = () => S.areas.find((a) => a.id === (S.folder ? S.folder.node.areaId : S.areaId)) || null;
		const canUpload = () => S.view === 'folder' && !!S.folder && S.folder.writable;

		async function reload() {
			S.dirty = false;
			S.loading = true;
			S.error = null;
			render();
			const me = await Promise.resolve(api.me()).catch(fail);
			S.me = me && me.ok ? me : null;
			S.access = DS.accessOf(S.me);
			if (!me || !me.ok) {
				S.loading = false;
				S.error = me;
				render();
				return;
			}
			if (S.access.usable) {
				const ar = await Promise.resolve(api.areas()).catch(fail);
				S.areas = DS.sortAreas(ar && ar.ok ? ar.areas : me.areas);
			} else {
				S.areas = [];
			}
			S.loading = false;
			if (!S.access.usable || !S.areas.length) { render(); return; }
			if (S.view === 'folder') {
				const a = DS.currentArea(S.areas, S.areaId);
				await loadFolder(S.folderId || (a && a.rootId), { quiet: true, fallback: a && a.rootId });
			} else if (S.view === 'sync') openSync();
			else if (S.view === 'trash') await loadTrash();
			else if (S.view === 'links') await loadLinks();
			else if (S.view === 'search') await runSearch();
			else render();
		}

		async function loadFolder(id, { quiet = false, fallback = null } = {}) {
			S.view = 'folder';
			S.folderId = id;
			if (!quiet) { S.loading = true; render(); }
			const r = await Promise.resolve(api.folder(id, DS.sortQuery(S.sort))).catch(fail);
			if (S.folderId !== id) return;
			S.loading = false;
			if (r && r.ok) {
				S.folder = r;
				S.error = null;
				S.areaId = r.node.areaId;
				keep('gc.drive.area', S.areaId);
			} else if (fallback && fallback !== id && r && (r.code === 'not_found' || r.code === 'forbidden')) {
				await loadFolder(fallback);
				return;
			} else {
				S.error = r;
			}
			render();
		}

		function openSync() {
			if (!syncView) return;
			S.view = 'sync';
			S.loading = false;
			S.error = null;
			refs.search.value = '';
			S.query = '';
			render();
			syncView.show();
		}

		async function loadTrash() {
			S.view = 'trash';
			S.loading = true;
			render();
			const r = await Promise.resolve(api.trash()).catch(fail);
			S.loading = false;
			if (S.view !== 'trash') return;
			S.trash = r && r.ok ? r.items : null;
			S.error = r && r.ok ? null : r;
			render();
		}

		async function loadLinks() {
			S.view = 'links';
			S.loading = true;
			render();
			const r = await Promise.resolve(api.links()).catch(fail);
			S.loading = false;
			if (S.view !== 'links') return;
			S.links = r && r.ok ? r : null;
			S.error = r && r.ok ? null : r;
			render();
		}

		let searchTimer = null;
		function onSearchInput() {
			clearTimeout(searchTimer);
			const q = refs.search.value.trim();
			if (!q) { if (S.view === 'search') backToFolder(); return; }
			if (q.length < 2) return;
			searchTimer = setTimeout(() => { S.query = q; runSearch(); }, 350);
		}
		function onSearchKey(e) {
			if (e.key === 'Enter') {
				clearTimeout(searchTimer);
				const q = refs.search.value.trim();
				if (q.length >= 2) { S.query = q; runSearch(); }
			} else if (e.key === 'Escape' && refs.search.value) {
				e.preventDefault();
				refs.search.value = '';
				backToFolder();
			}
		}
		async function runSearch() {
			const q = S.query;
			S.view = 'search';
			S.loading = true;
			render();
			const r = await Promise.resolve(api.search(q)).catch(fail);
			if (S.view !== 'search' || S.query !== q) return;
			S.loading = false;
			S.results = r && r.ok ? r.items : null;
			S.error = r && r.ok ? null : r;
			render();
		}
		function backToFolder() {
			S.query = '';
			const a = DS.currentArea(S.areas, S.areaId);
			loadFolder(S.folder ? S.folder.node.id : (a && a.rootId));
		}

		// ── Actions ──────────────────────────────────────
		function done(r, okKey) {
			if (r && r.ok) { if (okKey) toast(t(okKey), 'success'); return true; }
			if (r && r.cancelled) return false;
			toast(DS.errorText(r, t), 'error');
			return false;
		}
		const refreshView = () => (S.view === 'folder' && S.folder ? loadFolder(S.folder.node.id, { quiet: true }) : S.view === 'trash' ? loadTrash() : S.view === 'search' ? runSearch() : S.view === 'links' ? loadLinks() : S.view === 'sync' ? openSync() : null);

		async function openNode(n) {
			if (n.isDir) { refs.search.value = ''; S.query = ''; loadFolder(n.id); return; }
			const r = await Promise.resolve(api.open(n.id)).catch(fail);
			if (r && r.ok) return;
			if (r && r.code === 'unsafe') {
				toast(t('drive.err.unsafe'), 'error');
				return;
			}
			done(r);
		}

		async function saveAs(n, versionId) {
			const r = await Promise.resolve(api.saveAs(n.id, versionId || null)).catch(fail);
			if (r && r.ok) toast(t('drive.saved', { path: r.path }), 'success');
			else done(r);
		}

		async function pickAndUpload() {
			if (!canUpload()) return;
			const p = await Promise.resolve(api.pick()).catch(fail);
			if (!p || !p.ok) { if (p && p.code !== 'cancelled') done(p); return; }
			const r = await Promise.resolve(api.upload(S.folder.node.id, p.paths)).catch(fail);
			afterQueue(r);
		}

		function afterQueue(r) {
			if (!r || !r.ok) { done(r); return; }
			if (r.rejected && r.rejected.length) toast(DS.plural(t, 'drive.upload.rejected', r.rejected.length, { names: r.rejected.map((x) => x.name).slice(0, 3).join(', ') }), 'error');
		}

		function nameDialog({ title, value = '', confirm, run }) {
			const dlg = openDialog({ title, host, closeLabel: t('drive.close') });
			const id = nextId('dv-name');
			const input = el('input', { id, type: 'text', class: 'dv-input', maxlength: '255', value, spellcheck: 'false' });
			const errEl = el('span', { class: 'dv-field-err', role: 'alert' });
			const ok = el('button', { type: 'button', class: 'btn btn-pri', text: confirm });
			const check = () => { const e = DS.nameError(input.value, t); errEl.textContent = input.value ? (e || '') : ''; ok.disabled = !!e; return !e; };
			const submit = async () => {
				if (!check()) return;
				ok.disabled = true;
				const r = await Promise.resolve(run(input.value.trim())).catch(fail);
				if (r && r.ok) { dlg.close(r); refreshView(); return; }
				ok.disabled = false;
				errEl.textContent = DS.errorText(r, t);
			};
			input.addEventListener('input', check);
			input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
			ok.addEventListener('click', submit);
			dlg.body.append(el('label', { class: 'lbl', for: id, text: t('drive.name.label') }), input, errEl);
			dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), ok);
			check();
			setTimeout(() => {
				input.focus();
				const dot = value.lastIndexOf('.');
				input.setSelectionRange(0, dot > 0 ? dot : value.length);
			}, 0);
		}

		function confirmDialog({ title, text, confirm, danger, run }) {
			const dlg = openDialog({ title, host, closeLabel: t('drive.close') });
			const errEl = el('span', { class: 'dv-dlg-err', role: 'alert' });
			const ok = el('button', { type: 'button', class: `btn ${danger ? 'btn-danger' : 'btn-pri'}`, text: confirm });
			ok.addEventListener('click', async () => {
				ok.disabled = true;
				const r = await Promise.resolve(run()).catch(fail);
				if (r && r.ok) { dlg.close(r); return; }
				ok.disabled = false;
				errEl.textContent = DS.errorText(r, t);
			});
			dlg.body.append(el('p', { class: 'dv-p', text }));
			dlg.foot.append(errEl, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), ok);
		}

		function newFolder() {
			if (!canUpload()) return;
			const parentId = S.folder.node.id;
			nameDialog({ title: t('drive.newFolder'), confirm: t('drive.create'), run: (name) => api.mkdir(parentId, name) });
		}

		function renameNode(n) {
			nameDialog({ title: t('drive.renameTitle', { name: n.name }), value: n.name, confirm: t('drive.rename'), run: (name) => api.rename(n.id, name) });
		}

		function trashNode(n) {
			confirmDialog({
				title: t('drive.removeTitle', { name: n.name }), text: t(n.isDir ? 'drive.removeFolderText' : 'drive.removeText'), confirm: t('drive.remove'), danger: true,
				run: async () => { const r = await api.remove(n.id); if (r && r.ok) { toast(t('drive.done.trash'), 'success'); refreshView(); } return r; },
			});
		}

		async function moveNode(n) {
			const to = await pickFolder({ api, t, host, title: t('drive.moveTitle', { name: n.name }), confirm: t('drive.moveHere'), exclude: n.isDir ? n.id : null, remember: false, startId: S.folder ? S.folder.node.id : null });
			if (!to) return;
			if (S.folder && to.folderId === n.parentId) return;
			const r = await Promise.resolve(api.move(n.id, to.folderId)).catch(fail);
			if (done(r, 'drive.done.move')) refreshView();
		}

		async function versionsDialog(n) {
			const dlg = openDialog({ title: t('drive.versions.title', { name: n.name }), host, closeLabel: t('drive.close') });
			const box = el('div', { class: 'dv-vers' }, [el('div', { class: 'dv-pick-note', text: t('drive.loading') })]);
			dlg.body.appendChild(box);
			dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.close'), on: { click: () => dlg.close(null) } }));
			const load = async () => {
				const r = await Promise.resolve(api.versions(n.id)).catch(fail);
				clear(box);
				if (!r || !r.ok) { box.appendChild(el('div', { class: 'dv-dlg-err', text: DS.errorText(r, t) })); return; }
				const line = (label, meta, kids) => el('div', { class: 'dv-ver' }, [el('div', { class: 'dv-ver-tx' }, [el('b', { text: label }), el('span', { class: 'dv-ver-meta', text: meta })]), ...kids]);
				box.appendChild(line(t('drive.versions.current'), [DS.when(r.current.mtime || r.current.updatedAt, now(), locale(), t), DS.formatBytes(r.current.size, locale())].filter(Boolean).join(' · '), []));
				if (!r.versions.length) box.appendChild(el('div', { class: 'dv-pick-note', text: t('drive.versions.none') }));
				const writable = !!(S.areas.find((a) => a.id === n.areaId) || {}).writable;
				for (const v of r.versions) {
					box.appendChild(line(t('drive.versions.rev', { rev: v.rev }), [DS.when(v.at, now(), locale(), t), DS.formatBytes(v.size, locale())].filter(Boolean).join(' · '), [
						el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('drive.saveAs'), on: { click: () => saveAs(n, v.id) } }),
						writable ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.versions.restore'), on: { click: async (e) => {
							e.currentTarget.disabled = true;
							const x = await Promise.resolve(api.restoreVersion(n.id, v.id)).catch(fail);
							if (done(x, 'drive.done.version')) { refreshView(); load(); }
						} } }) : null,
					]));
				}
			};
			load();
		}

		function shareDialog(n) {
			const dlg = openDialog({ title: t('drive.share.title', { name: n.name }), host, wide: true, closeLabel: t('drive.close') });
			const draft = { mode: 'view', expires: '7d', pin: '' };
			const modes = DS.linkModes(n);
			const form = el('div', { class: 'dv-share' });
			const result = el('div', { class: 'dv-share-result', hidden: true });
			const existing = el('div', { class: 'dv-share-links' });
			const errEl = el('span', { class: 'dv-dlg-err', role: 'alert' });
			const create = el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.share.create') });
			const seg = (label, values, key, textOf) => {
				const s = el('div', { class: 'seg dv-seg', role: 'radiogroup', 'aria-label': label });
				const draw = () => {
					clear(s);
					for (const v of values) {
						s.appendChild(el('button', { type: 'button', role: 'radio', 'aria-checked': draft[key] === v ? 'true' : 'false', class: draft[key] === v ? 'on' : '', text: textOf(v), on: { click: () => { draft[key] = v; draw(); } } }));
					}
				};
				draw();
				return el('div', { class: 'dv-share-row' }, [el('span', { class: 'lbl', text: label }), s]);
			};
			const pinId = nextId('dv-pin');
			const pin = el('input', { id: pinId, type: 'text', inputmode: 'numeric', class: 'dv-input dv-pin', maxlength: '12', placeholder: t('drive.share.pinPlaceholder'), autocomplete: 'off', on: { input: () => { draft.pin = pin.value; errEl.textContent = DS.pinOk(pin.value) ? '' : t('drive.share.pinInvalid'); create.disabled = !DS.pinOk(pin.value); } } });
			form.append(
				seg(t('drive.share.who'), modes, 'mode', (m) => t(`drive.link.mode.${m}`)),
				seg(t('drive.share.valid'), DS.LINK_EXPIRES, 'expires', (x) => t(`drive.share.expires.${x}`)),
				el('div', { class: 'dv-share-row' }, [el('label', { class: 'lbl', for: pinId, text: t('drive.share.pin') }), pin]),
			);
			create.addEventListener('click', async () => {
				const body = DS.linkRequest(n, draft);
				if (!body) { errEl.textContent = t('drive.share.pinInvalid'); return; }
				create.disabled = true;
				const r = await Promise.resolve(api.createLink(body)).catch(fail);
				create.disabled = false;
				if (!r || !r.ok) { errEl.textContent = DS.errorText(r, t); return; }
				errEl.textContent = '';
				showResult(r.link);
				loadExisting();
			});
			function showResult(link) {
				clear(result);
				result.hidden = false;
				const url = el('input', { type: 'text', class: 'dv-input dv-url', readonly: true, value: link.url || '', 'aria-label': t('drive.share.url') });
				result.append(
					el('div', { class: 'dv-share-ok' }, [icon('check', 16), el('span', { text: t('drive.share.created') })]),
					el('div', { class: 'dv-share-urlrow' }, [url, el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => copy(link.url) } }, [icon('copy', 14), el('span', { text: t('drive.share.copy') })])]),
					draft.pin ? el('span', { class: 'dv-pick-note', text: t('drive.share.pinNote') }) : null,
				);
				url.addEventListener('focus', () => url.select());
			}
			async function loadExisting() {
				const r = await Promise.resolve(api.links(n.id)).catch(fail);
				clear(existing);
				const active = r && r.ok ? r.links.filter((l) => l.active) : [];
				if (!active.length) return;
				existing.appendChild(el('span', { class: 'lbl', text: t('drive.share.active') }));
				for (const l of active) existing.appendChild(linkRow(l, () => loadExisting()));
			}
			dlg.body.append(form, result, existing);
			dlg.foot.append(errEl, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.close'), on: { click: () => dlg.close(null) } }), create);
			loadExisting();
		}

		function copy(text) {
			const okMsg = () => toast(t('drive.share.copied'), 'success');
			if (root.navigator && navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(String(text || '')).then(okMsg).catch(() => toast(t('drive.err.copy'), 'error'));
		}

		function linkRow(l, after) {
			const v = DS.linkView(l, { t, locale: locale(), now: now() });
			return el('div', { class: `dv-link${v.active ? '' : ' is-ended'}`, role: 'listitem' }, [
				el('span', { class: 'dv-row-ic' }, [icon('link', 16)]),
				el('div', { class: 'dv-link-tx' }, [el('span', { class: 'dv-link-name', text: v.title }), el('span', { class: 'dv-row-sub', text: v.meta })]),
				v.active && v.url ? el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => copy(v.url) } }, [icon('copy', 14), el('span', { text: t('drive.share.copy') })]) : null,
				v.active ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.share.end'), on: { click: async (e) => {
					e.currentTarget.disabled = true;
					const r = await Promise.resolve(api.endLink(v.token)).catch(fail);
					if (done(r, 'drive.done.linkEnded')) after();
					else e.currentTarget.disabled = false;
				} } }) : null,
			]);
		}

		// ── Conflicts of uploads ─────────────────────────
		function maybeAskConflict() {
			if (S.conflictOpen || !S.shown) return;
			const row = S.transfers.find((r) => r.state === 'conflict');
			if (row) askConflict(row);
		}

		function askConflict(row) {
			if (S.conflictOpen) return;
			S.conflictOpen = true;
			const dlg = openDialog({ title: t('drive.conflict.title', { name: row.name }), host, closeLabel: t('drive.close'), onClose: () => { S.conflictOpen = false; setTimeout(maybeAskConflict, 0); } });
			const choose = async (choice) => {
				await Promise.resolve(api.resolve(row.id, choice)).catch(() => {});
				dlg.close(true);
			};
			dlg.body.append(el('p', { class: 'dv-p', text: t('drive.conflict.text') }));
			dlg.foot.append(
				el('span', { class: 'dv-grow' }),
				el('button', { type: 'button', class: 'btn btn-ghost', text: t('drive.conflict.skip'), on: { click: () => choose(null) } }),
				el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.conflict.keep'), on: { click: () => choose('rename') } }),
				el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.conflict.version'), on: { click: () => choose('version') } }),
			);
		}

		// ── Row menu ─────────────────────────────────────
		function closeMenu() {
			if (S.menu) { S.menu.remove(); S.menu = null; }
		}

		function openMenu(n, anchor, at) {
			closeMenu();
			const writable = S.view === 'folder' ? !!(S.folder && S.folder.writable) : !!(S.areas.find((a) => a.id === n.areaId) || {}).writable;
			const acts = DS.actionsFor(n, writable);
			const items = [];
			const item = (ic, label, fn, danger) => items.push(el('button', { type: 'button', role: 'menuitem', class: `dv-menu-item${danger ? ' is-danger' : ''}`, on: { click: () => { closeMenu(); fn(); } } }, [icon(ic, 15), el('span', { text: label })]));
			item(n.isDir ? 'folder' : 'open', t('drive.open'), () => openNode(n));
			if (acts.saveAs) item('down', t('drive.saveAs'), () => saveAs(n));
			if (S.view === 'search' && n.parentId) item('folder', t('drive.search.showFolder'), () => { refs.search.value = ''; S.query = ''; loadFolder(n.parentId); });
			if (acts.share) item('link', t('drive.share.menu'), () => shareDialog(n));
			if (acts.rename) item('pen', t('drive.rename'), () => renameNode(n));
			if (acts.move) item('move', t('drive.move'), () => moveNode(n));
			if (acts.versions) item('history', t('drive.versions.menu'), () => versionsDialog(n));
			if (acts.remove) item('trash', t('drive.remove'), () => trashNode(n), true);
			const menu = el('div', { class: 'dv-menu', role: 'menu' }, items);
			const layer = el('div', { class: 'dv-menu-layer', on: { mousedown: (e) => { if (e.target === layer) closeMenu(); }, contextmenu: (e) => { e.preventDefault(); closeMenu(); } } }, [menu]);
			layer.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.stopPropagation(); closeMenu(); if (anchor && anchor.focus) anchor.focus(); } });
			host.appendChild(layer);
			S.menu = layer;
			// at a right click: the pointer; else below (or above) the "⋯" button
			const r = anchor.getBoundingClientRect();
			const mr = menu.getBoundingClientRect();
			const x = at ? at.left : r.right - mr.width;
			const y = at ? at.top : r.bottom + 4;
			const left = Math.max(8, Math.min(window.innerWidth - mr.width - 8, x));
			const top = y + mr.height + 8 < window.innerHeight ? y : Math.max(8, (at ? at.top : r.top - 4) - mr.height);
			menu.style.left = `${left}px`;
			menu.style.top = `${top}px`;
			const first = menu.querySelector('button');
			if (first) first.focus();
		}

		// ── Previews ─────────────────────────────────────
		function previewUrl(mediaId, tries = 0) {
			if (S.previews.has(mediaId)) return S.previews.get(mediaId);
			const p = Promise.resolve(api.preview(mediaId)).then((r) => {
				if (r && r.ok && r.data) return URL.createObjectURL(new Blob([r.data], { type: r.mime || 'image/jpeg' }));
				S.previews.delete(mediaId);
				if (r && r.code === 'preview_pending' && tries < 3) return new Promise((res) => setTimeout(() => res(previewUrl(mediaId, tries + 1)), 4000));
				return null;
			}).catch(() => { S.previews.delete(mediaId); return null; });
			S.previews.set(mediaId, p);
			return p;
		}

		function thumb(v) {
			const box = el('span', { class: `dv-thumb dv-k-${v.kind}` }, [icon(KIND_ICON[v.kind] || 'file', 18), v.badge && !v.isDir && !KIND_ICON[v.kind] ? el('span', { class: 'dv-badge', text: v.badge }) : null]);
			if (v.preview && v.mediaId) {
				previewUrl(v.mediaId).then((u) => {
					if (u && box.isConnected !== false) {
						box.classList.add('has-img');
						box.appendChild(el('img', { src: u, alt: '', draggable: 'false', loading: 'lazy' }));
					}
				});
			}
			return box;
		}

		// ── Render ───────────────────────────────────────
		function relabel() {
			refs.h.textContent = t('drive.title');
			refs.searchLabel.textContent = t('drive.search.label');
			refs.search.placeholder = t('drive.search.placeholder');
			refs.refresh.title = t('drive.refresh');
			refs.refresh.setAttribute('aria-label', t('drive.refresh'));
			render();
			if (syncView) syncView.relabel();
		}

		function render() {
			closeMenu();
			const st = S.status;
			const offline = st && st.state === 'error';
			refs.banner.hidden = !offline && !(S.error && ['offline', 'network', 'timeout'].includes(S.error.code));
			clear(refs.banner);
			if (!refs.banner.hidden) refs.banner.append(icon('alert', 15), el('span', { text: t('drive.err.offline') }));

			const gate = S.access && !S.access.usable ? S.access.key : (S.access && S.access.key === 'drive.access.noAreas' ? S.access.key : null);
			refs.empty.hidden = !gate && !(S.error && !S.me);
			refs.main.hidden = !refs.empty.hidden;
			clear(refs.empty);
			if (!refs.empty.hidden) {
				refs.empty.append(
					el('span', { class: 'dv-gate-ic' }, [icon('cloud', 30, '1.8')]),
					el('p', { class: 'dv-p', text: gate ? t(gate) : DS.errorText(S.error, t) }),
					!gate ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.retry'), on: { click: () => reload() } }) : null,
				);
				refs.sub.textContent = '';
				return;
			}
			const inSync = S.view === 'sync' && !!syncView;
			refs.bar.hidden = inSync;
			refs.listWrap.hidden = inSync;
			if (syncView && !inSync) syncView.hide();
			renderSide();
			renderBar();
			if (!inSync) renderList();
			renderTransfers();
		}

		function sideButton({ label, sub, ic, on, onClick }) {
			return el('button', { type: 'button', class: `dv-area${on ? ' is-on' : ''}`, 'aria-current': on ? 'page' : null, on: { click: onClick } }, [
				el('span', { class: 'dv-area-ic' }, [icon(ic, 16)]),
				el('span', { class: 'dv-area-tx' }, [el('span', { class: 'dv-area-name', text: label }), sub ? el('span', { class: 'dv-area-sub', text: sub }) : null]),
			]);
		}

		function renderSide() {
			clear(refs.side);
			refs.side.setAttribute('aria-label', t('drive.areas'));
			refs.side.appendChild(el('span', { class: 'lbl dv-side-lbl', text: t('drive.areas') }));
			const cur = S.view === 'folder' ? (S.folder ? S.folder.node.areaId : S.areaId) : null;
			for (const a of S.areas) {
				const use = DS.usage(a, t, locale());
				refs.side.appendChild(sideButton({
					label: DS.areaLabel(a, t), sub: [DS.areaHint(a, t), use].filter(Boolean).join(' · '), ic: AREA_ICON[a.kind] || 'folder', on: cur === a.id,
					onClick: () => { refs.search.value = ''; S.query = ''; S.areaId = a.id; keep('gc.drive.area', a.id); loadFolder(a.rootId); },
				}));
			}
			refs.side.appendChild(el('span', { class: 'dv-side-sep' }));
			refs.side.appendChild(sideButton({ label: t('drive.links.title'), sub: t('drive.links.sub'), ic: 'link', on: S.view === 'links', onClick: () => { refs.search.value = ''; loadLinks(); } }));
			refs.side.appendChild(sideButton({ label: t('drive.trash.title'), sub: null, ic: 'trash', on: S.view === 'trash', onClick: () => { refs.search.value = ''; loadTrash(); } }));
			if (syncView) {
				refs.side.appendChild(el('span', { class: 'dv-side-sep' }));
				refs.side.appendChild(sideButton({ label: t('drive.sync.title'), sub: S.syncSummary || null, ic: 'sync', on: S.view === 'sync', onClick: () => openSync() }));
			}
		}

		function renderBar() {
			clear(refs.bar);
			refs.note.hidden = true;
			const a = area();
			if (S.view === 'folder') {
				const cr = DS.crumbs(S.folder, a, t);
				const nav = el('nav', { class: 'dv-crumbs', 'aria-label': t('drive.crumbs') });
				cr.forEach((c, i) => {
					if (i) nav.appendChild(el('span', { class: 'dv-crumb-sep', 'aria-hidden': 'true', text: '›' }));
					nav.appendChild(c.current ? el('span', { class: 'dv-crumb is-current', 'aria-current': 'page', text: c.name }) : el('button', { type: 'button', class: 'dv-crumb', text: c.name, on: { click: () => loadFolder(c.id) } }));
				});
				const sort = el('div', { class: 'seg dv-seg', role: 'radiogroup', 'aria-label': t('drive.sort.label') });
				for (const s of DS.SORTS) {
					sort.appendChild(el('button', { type: 'button', role: 'radio', 'aria-checked': S.sort === s ? 'true' : 'false', class: S.sort === s ? 'on' : '', text: t(`drive.sort.${s}`), on: { click: () => { S.sort = s; keep('gc.drive.sort', s); if (S.folder) loadFolder(S.folder.node.id, { quiet: true }); } } }));
				}
				const w = !!(S.folder && S.folder.writable);
				refs.bar.append(nav, el('span', { class: 'dv-grow' }), sort,
					w ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: newFolder } }, [icon('plus', 14), el('span', { text: t('drive.newFolder') })]) : null,
					w ? el('button', { type: 'button', class: 'btn btn-pri btn-sm', on: { click: pickAndUpload } }, [icon('upload', 14), el('span', { text: t('drive.upload.button') })]) : null);
				if (a && a.kind === 'child' && a.via === 'parent') { refs.note.hidden = false; refs.note.textContent = t('drive.childNote'); }
				else if (S.folder && !w) { refs.note.hidden = false; refs.note.textContent = t('drive.readOnly'); }
				refs.sub.textContent = a ? [DS.areaLabel(a, t), DS.usage(a, t, locale())].filter(Boolean).join(' · ') : '';
			} else if (S.view === 'search') {
				refs.bar.append(el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => { refs.search.value = ''; backToFolder(); } } }, [icon('back', 14), el('span', { text: t('drive.back') })]),
					el('span', { class: 'dv-bar-h', text: t('drive.search.title', { q: S.query }) }));
				refs.sub.textContent = t('drive.search.hint');
			} else if (S.view === 'trash') {
				refs.bar.append(el('span', { class: 'dv-bar-h', text: t('drive.trash.title') }));
				const days = S.me && S.me.settings && S.me.settings.trashDays;
				refs.note.hidden = !days;
				if (days) refs.note.textContent = t('drive.trash.info', { n: days });
				refs.sub.textContent = '';
			} else if (S.view === 'sync') {
				refs.sub.textContent = '';
			} else if (S.view === 'links') {
				refs.bar.append(el('span', { class: 'dv-bar-h', text: t('drive.links.title') }));
				if (S.links && S.links.enabled === false) { refs.note.hidden = false; refs.note.textContent = t('drive.err.linksDisabled'); }
				refs.sub.textContent = '';
			}
		}

		function emptyState(text) {
			return el('div', { class: 'dv-empty' }, [icon(S.view === 'trash' ? 'trash' : S.view === 'links' ? 'link' : S.view === 'search' ? 'search' : 'folder', 28, '1.6'), el('span', { text })]);
		}

		function renderList() {
			clear(refs.list);
			if (S.loading && !(S.view === 'folder' && S.folder)) { refs.list.appendChild(el('div', { class: 'dv-empty', text: t('drive.loading') })); return; }
			if (S.error && S.me) {
				refs.list.appendChild(el('div', { class: 'dv-empty' }, [icon('alert', 26, '1.6'), el('span', { text: DS.errorText(S.error, t) }), el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.retry'), on: { click: () => refreshView() } })]));
				return;
			}
			if (S.view === 'links') { renderLinks(); return; }
			const items = S.view === 'folder' ? (S.folder ? S.folder.items : []) : S.view === 'search' ? (S.results || []) : (S.trash || []);
			const mode = S.view;
			refs.list.appendChild(el('div', { class: 'dv-row dv-row-head', 'aria-hidden': 'true' }, [
				el('span', { class: 'dv-c-name', text: t('drive.col.name') }),
				el('span', { class: 'dv-c-date', text: t(mode === 'trash' ? 'drive.col.deleted' : 'drive.col.date') }),
				el('span', { class: 'dv-c-size', text: t('drive.col.size') }),
				el('span', { class: 'dv-c-act' }),
			]));
			if (!items.length) {
				refs.list.appendChild(emptyState(mode === 'search' ? t('drive.search.empty') : mode === 'trash' ? t('drive.trash.empty') : (S.folder && S.folder.writable ? t('drive.emptyWritable') : t('drive.empty'))));
				return;
			}
			for (const n of items) refs.list.appendChild(mode === 'trash' ? trashRow(n) : nodeRow(n, mode));
			if (S.view === 'folder' && S.folder && S.folder.next) refs.list.appendChild(el('div', { class: 'dv-more', text: t('drive.more', { n: S.folder.total }) }));
		}

		function nodeRow(n, mode) {
			const v = DS.rowView(n, { t, locale: locale(), now: now(), mode });
			const more = el('button', { type: 'button', class: 'dv-ib dv-more-btn', title: t('drive.actions'), 'aria-label': t('drive.actionsFor', { name: v.name }), 'aria-haspopup': 'menu', on: { click: (e) => { e.stopPropagation(); openMenu(n, more); } } }, [icon('more', 16)]);
			const main = el('button', { type: 'button', class: 'dv-c-name dv-open', title: v.isDir ? t('drive.openFolder') : t('drive.openFile'), on: { click: () => openNode(n) } }, [
				thumb(v),
				el('span', { class: 'dv-name-tx' }, [el('span', { class: 'dv-name', text: v.name }), v.sub ? el('span', { class: 'dv-row-sub', text: v.sub }) : null]),
			]);
			const row = el('div', { class: 'dv-row', role: 'listitem', 'data-id': String(v.id) }, [
				main,
				el('span', { class: 'dv-c-date', text: v.date }),
				el('span', { class: 'dv-c-size', text: v.size }),
				el('span', { class: 'dv-c-act' }, [more]),
			]);
			row.addEventListener('contextmenu', (e) => { e.preventDefault(); openMenu(n, more, { left: e.clientX, top: e.clientY }); });
			return row;
		}

		function trashRow(n) {
			const v = DS.rowView(n, { t, locale: locale(), now: now(), mode: 'trash' });
			return el('div', { class: 'dv-row is-trash', role: 'listitem', 'data-id': String(v.id) }, [
				el('span', { class: 'dv-c-name' }, [thumb(v), el('span', { class: 'dv-name-tx' }, [el('span', { class: 'dv-name', text: v.name }), v.sub ? el('span', { class: 'dv-row-sub', text: v.sub }) : null])]),
				el('span', { class: 'dv-c-date', text: v.date }),
				el('span', { class: 'dv-c-size', text: v.size }),
				el('span', { class: 'dv-c-act dv-trash-act' }, [
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: async (e) => {
						e.currentTarget.disabled = true;
						const r = await Promise.resolve(api.restore(n.id)).catch(fail);
						if (done(r, 'drive.done.restore')) loadTrash();
						else e.currentTarget.disabled = false;
					} } }, [icon('restore', 14), el('span', { text: t('drive.trash.restore') })]),
					el('button', { type: 'button', class: 'btn btn-ghost btn-sm dv-danger', text: t('drive.trash.purge'), on: { click: () => confirmDialog({
						title: t('drive.trash.purgeTitle', { name: n.name }), text: t('drive.trash.purgeText'), confirm: t('drive.trash.purge'), danger: true,
						run: async () => { const r = await api.purge(n.id); if (r && r.ok) { toast(t('drive.done.purge'), 'success'); loadTrash(); } return r; },
					}) } }),
				]),
			]);
		}

		function renderLinks() {
			const list = S.links ? S.links.links : [];
			if (!list.length) { refs.list.appendChild(emptyState(t('drive.links.empty'))); return; }
			for (const l of list) refs.list.appendChild(linkRow(l, () => loadLinks()));
		}

		function renderTransfers() {
			const rows = S.transfers || [];
			refs.transfers.hidden = !rows.length || refs.main.hidden || S.view === 'sync';
			clear(refs.transfers);
			if (refs.transfers.hidden) return;
			const summary = DS.transfersSummary(rows, t);
			refs.transfers.appendChild(el('div', { class: 'dv-tr-head' }, [
				el('span', { class: 'lbl', text: t('drive.transfer.title') }),
				summary ? el('span', { class: 'dv-tr-sum', text: summary }) : null,
				el('span', { class: 'dv-grow' }),
				rows.some((r) => !['queued', 'running', 'conflict'].includes(r.state)) ? el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('drive.transfer.clear'), on: { click: () => Promise.resolve(api.clearTransfers()).then((r) => { if (r && r.ok) { S.transfers = r.transfers; renderTransfers(); } }).catch(() => {}) } }) : null,
			]));
			const list = el('div', { class: 'dv-tr-list scroll' });
			for (const r of rows.slice().reverse()) {
				const v = DS.transferView(r, t, locale());
				list.appendChild(el('div', { class: `dv-tr ${v.cls}` }, [
					el('span', { class: 'dv-tr-ic' }, [icon(v.dir === 'down' ? 'down' : 'upload', 14)]),
					el('div', { class: 'dv-tr-tx' }, [
						el('div', { class: 'dv-tr-top' }, [el('span', { class: 'dv-tr-name', text: v.name }), el('span', { class: 'dv-tr-state', text: v.text })]),
						v.active ? el('div', { class: 'dv-tr-bar' }, [el('span', { style: `width:${v.pct}%` })]) : null,
					]),
					v.conflict ? el('button', { type: 'button', class: 'btn btn-sec btn-xs', text: t('drive.transfer.choose'), on: { click: () => askConflict(r) } }) : null,
					v.path ? el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('drive.transfer.show'), on: { click: () => api.showItem(v.path) } }) : null,
				]));
			}
			refs.transfers.appendChild(list);
		}

		relabel();

		return {
			show() {
				S.shown = true;
				if (S.dirty || !S.me) reload();
				else refreshView();
				maybeAskConflict();
			},
			hide() {
				S.shown = false;
				closeMenu();
				if (syncView) syncView.hide();
			},
			/** Opens "Ordner sichern" (tray entry, links). */
			openSync: () => { if (syncView) { S.shown = true; openSync(); } },
			refresh: () => reload(),
			status: () => S.status,
			available: () => !!(S.status && S.status.state === 'available'),
			relabel,
			pickFolder: (opts) => pickFolder({ api, t, host, ...(opts || {}) }),
			/**
			 * Explorer-Kontextmenü (Dateien bei Bedarf): „Link teilen …“ / „Ältere
			 * Versionen“ für einen Knoten. `code`: der Knoten ist nicht abrufbar.
			 */
			openAction(action, node, code) {
				if (code || !node || !node.id) { toast(t(code === 'not_synced' ? 'drive.od.err.not_synced' : 'drive.od.err.node'), 'error'); return; }
				if (action === 'share') shareDialog(node);
				else if (action === 'versions' && !node.isDir) versionsDialog(node);
			},
		};
	}

	/**
	 * "In Drive speichern" from another page: pick a folder, then `save(folderId)`
	 * (the plugin of that page hands the file to Drive; null: its own default place)
	 * → toast "Gespeichert in …".
	 * @returns {Promise<boolean>} saved
	 */
	async function saveToDrive({ api, t, toast, title, save, host, fallback }) {
		const to = await pickFolder({ api, t, host, fallback, title: title || t('drive.save.title'), confirm: t('drive.save.here') });
		if (!to) return false;
		const tell = typeof toast === 'function' ? toast : () => {};
		tell(t('drive.save.saving'), 'info');
		let r;
		try { r = await save(to.folderId); } catch (err) { r = fail(err); }
		if (r && r.ok) {
			tell(DS.savedText(r.saved, t), 'success');
			return true;
		}
		tell(DS.errorText(r, t), 'error');
		return false;
	}

	root.GCDriveView = { mount, pickFolder, saveToDrive };
})(typeof self !== 'undefined' ? self : this);
