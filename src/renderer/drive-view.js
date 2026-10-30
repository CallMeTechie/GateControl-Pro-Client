/**
 * GateControl -- Drive (renderer view of the plugin gatecontrol-drive)
 *
 * The page "Drive": the menu on the left (Drive 1.11, drive-menu-state.js) —
 * the person's name and seat, "Persönlich" (Meine Dateien) and "Gemeinsam"
 * (Familie, Kinder · Name, Team · Name with their storage) as an unfoldable
 * folder tree (the arrow folds, the name opens; loaded only when unfolded;
 * unfolded nodes kept on this PC; arrows / Home / End / Enter on the keyboard),
 * "Tresore" (the vault folders — only here, never among the files) and a bar
 * of icons (Fotos, Geteilt, Papierkorb, Speicher, Ordner sichern, Fristen,
 * Importieren, Einstellungen — what this Drive has); on the right the folder
 * with breadcrumbs, sorting, "Neu" (Neuer Ordner, Dateien / Ordner hochladen,
 * Neuer Tresor) and "Hochladen" (button or files dropped on the page), the list
 * (preview pictures, name, date, size; sorted by name, date, size or type —
 * "Typ" here: folders, then documents, tables, … by extension and name) and a menu per row: Öffnen, Speichern
 * unter …, Link teilen (rights, validity, PIN), Umbenennen, Verschieben,
 * Ältere Versionen, Im Portal öffnen (Drive 1.6 'links'), In den Papierkorb.
 * Search covers names and the recognised text of scans (with the words
 * around the hit). Uploads and downloads show in a list at the bottom; a
 * taken name asks "Neue Version" / "Beide behalten" / "Überspringen". Whole
 * folders go up too ("Ordner hochladen" or dropped). What changes elsewhere
 * (push `changed`) and coming back to the window reload the folder, search,
 * trash or links shown (at most every 2 s, scroll position and focus kept).
 * Drive 1.6 'guard': while Drive keeps this device stopped, a banner on top
 * ("Von Drive gestoppt: ungewöhnliche Änderungen") offers "Rückgängig
 * machen", "War ich – freigeben" and "Im Portal prüfen".
 *
 * "Ordner sichern" (folders of this PC backed up / synced, core DriveSync)
 * is a view of the page too: drive-sync-view.js; so are the Drive settings
 * (drive-settings-view.js, the gear). Drive 1.11 vault lock: a vault opens
 * only after Windows Hello (the card "Tresor gesperrt"); when the core locks
 * the vaults (time without use, window hidden, Windows locked) an open vault
 * folder closes to its card; activity on a vault keeps it open.
 *
 * Drive 1.7 (only with the features `me` reports): "Auf früheren Stand
 * zurücksetzen …" of a folder (row menu, and the bar for the folder shown;
 * 'timeTravel'): a time → the preview (what comes back, gets its old
 * content, goes into the trash, is moved; a note when Drive does not know
 * older renames; what happens to the folders of this PC in "Ordner
 * sichern") → run → the result with "Rückgängig" (a time travel to
 * `before`). "Fotos" ('photos' / 'albums' / 'frame', drive-photos-view.js)
 * and "Speicher" ('storage', drive-storage-view.js) are views of the page
 * like "Ordner sichern".
 *
 * pickFolder() is the dialog "In Drive speichern" of Chats, GateDrop and
 * Schule: writable areas and folders only, it starts in the folder picked
 * last and remembers the new one.
 *
 * Drive 1.8 / 1.9 (only with the features `me` reports): "Details" of a
 * file — what Drive recognised, its suggestion and deadlines ('docAi',
 * drive-docs-view.js) — and "Fristen" on the left; a symbol of the kind of
 * document in the list; the switch "KI für Dokumente" per area in the Drive
 * settings (write right; Drive 1.11); "Aus Google Drive / OneDrive importieren (im
 * Portal)" ('cloudImport'); "Im Browser bearbeiten / ansehen" for office
 * documents ('office'); vault folders ('vault', drive-vault-view.js): "Neuer
 * Tresor-Ordner", names decrypted on this PC, the card to ask for access or
 * open with the recovery key, "Geräte" (requests with safety numbers). A
 * click on a deadline push opens the file's details (open(context)).
 *
 * Drive 1.12 (several at once, drive-bulk-view.js / drive-bulk-state.js): a check box per row and the tri-state
 * one of the head; a click on a row selects it (the name still opens, a double click on the row opens), Strg+click
 * one more, Umschalt+click a range, Strg+A all, Esc none; the green bar of the selection (Herunterladen (ZIP),
 * Verschieben nach …, Kopieren nach …, Link teilen, Löschen — greyed with the reason when not possible), the menu of
 * a selection on a right click, Strg+X / Strg+C / Strg+V inside Drive, Entf, F2, dragging rows onto a folder of the
 * list, the menu's tree or the breadcrumbs (Strg: copy; files from the Explorer still go up as before), the shortcuts
 * below the list; jobs show in the transfer list (progress, "Abbrechen", "Rückgängig"), new ones "neu hier".
 *
 * Drive 1.14 (only with the features `me` reports, drive-ki-view.js / drive-ki-state.js): "Fristen" by month with
 * "In den Familienkalender" ('deadlineCalendar'); after a document went up the bar "Vorschlag · Ablegen als … in …"
 * ('docAi'); "In Dokument umwandeln" of pictures (row menu, the menu of a selection: "Scan prüfen", 'scanDocs');
 * the chips "Dateien | Fragen" at the search field — a question (the chip, or "?" at the end, Enter) is answered from
 * the person's files with its sources ('docAsk').
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
	const MS = root.GCDriveMenuState;
	const BS = root.GCDriveBulkState;
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
		disk: 'M4 6a8 3 0 1 0 16 0a8 3 0 1 0-16 0|M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6|M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3',
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
		// Drive 1.8 / 1.9
		vault: 'M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z|M10 13h4v3h-4z|M10.5 13v-1a1.5 1.5 0 0 1 3 0v1',
		calendar: 'M4 6h16v14H4z|M4 10h16|M8 3v4M16 3v4',
		receipt: 'M6 3h12v18l-3-2-3 2-3-2-3 2z|M9 8h6M9 12h6',
		contract: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z|M14 3v5h5|M8 17c1-2 2-2 3 0s2 2 3 0',
		stamp: 'M9 4h6l-1 7h-4z|M5 14h14v3H5z|M7 20h10',
		medical: 'M10 4h4v6h6v4h-6v6h-4v-6H4v-4h6z',
		award: 'M12 3a5 5 0 1 0 0 10a5 5 0 1 0 0-10|M9 12l-2 9 5-3 5 3-2-9',
		bank: 'M3 10l9-6 9 6|M5 10v8M9 10v8M15 10v8M19 10v8|M3 20h18',
		shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
		device: 'M3 5h18v11H3z|M8 20h8|M12 16v4',
		globe: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M3 12h18|M12 3c3 3 3 15 0 18|M12 3c-3 3-3 15 0 18',
		import: 'M12 3v12|M7 10l5 5 5-5|M5 21h14|M17 3h3v3',
		// Drive 1.11
		table: 'M3 4h18v16H3z|M3 10h18|M9 4v16|M15 4v16',
		gear: 'M12.2 2h-.4a2 2 0 0 0-2 2v.2a2 2 0 0 1-1 1.7l-.4.3a2 2 0 0 1-2 0l-.2-.1a2 2 0 0 0-2.7.7l-.2.4a2 2 0 0 0 .7 2.7l.2.1a2 2 0 0 1 1 1.7v.5a2 2 0 0 1-1 1.8l-.2.1a2 2 0 0 0-.7 2.7l.2.4a2 2 0 0 0 2.7.7l.2-.1a2 2 0 0 1 2 0l.4.3a2 2 0 0 1 1 1.7v.2a2 2 0 0 0 2 2h.4a2 2 0 0 0 2-2v-.2a2 2 0 0 1 1-1.7l.4-.3a2 2 0 0 1 2 0l.2.1a2 2 0 0 0 2.7-.7l.2-.4a2 2 0 0 0-.7-2.7l-.2-.1a2 2 0 0 1-1-1.8v-.5a2 2 0 0 1 1-1.7l.2-.1a2 2 0 0 0 .7-2.7l-.2-.4a2 2 0 0 0-2.7-.7l-.2.1a2 2 0 0 1-2 0l-.4-.3a2 2 0 0 1-1-1.7V4a2 2 0 0 0-2-2z|M12 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6',
		chevDown: 'M6 9l6 6 6-6',
		folderPlus: 'M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z|M12 10v6M9 13h6',
	};
	const KIND_ICON = { folder: 'folder', image: 'image', video: 'video', audio: 'audio', pdf: 'pdf', archive: 'archive', vault: 'vault' };
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
			// "Neuer Ordner" in the folder shown: made, then entered (it can be picked right away)
			const nfId = nextId('dv-pick-nf');
			const nfInput = el('input', { id: nfId, type: 'text', class: 'dv-input', maxlength: '255', spellcheck: 'false', 'aria-label': t('drive.name.label'), placeholder: t('drive.picker.newName') });
			const nfErr = el('span', { class: 'dv-field-err', role: 'alert' });
			const nfOk = el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.create'), on: { click: () => makeFolder() } });
			const nfRow = el('div', { class: 'dv-pick-new', hidden: true }, [nfInput, nfOk, nfErr]);
			const nfBtn = el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => { nfRow.hidden = !nfRow.hidden; if (!nfRow.hidden) { nfInput.value = ''; nfErr.textContent = ''; nfInput.focus(); } } } }, [icon('plus', 14), el('span', { text: t('drive.newFolder') })]);
			nfInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); makeFolder(); } else if (e.key === 'Escape') { e.stopPropagation(); nfRow.hidden = true; } });
			nfInput.addEventListener('input', () => { nfErr.textContent = nfInput.value ? (DS.nameError(nfInput.value, t) || '') : ''; });
			async function makeFolder() {
				if (!P.folder || !DS.canPick(P.folder)) return;
				const e = DS.nameError(nfInput.value, t);
				if (e) { nfErr.textContent = e; return; }
				nfOk.disabled = true;
				const r = await Promise.resolve(api.mkdir(P.folder.node.id, nfInput.value.trim())).catch(fail);
				nfOk.disabled = false;
				if (!r || !r.ok) { nfErr.textContent = DS.errorText(r, t); return; }
				nfRow.hidden = true;
				await browse(r.node.id);
			}
			dlg.body.append(path, nfRow, list);
			const std = o.fallback ? el('button', { type: 'button', class: 'btn btn-ghost', title: o.fallback, text: t('drive.picker.default'), on: { click: () => dlg.close({ folderId: null, path: o.fallback }) } }) : null;
			dlg.foot.append(...[err, nfBtn, std, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), ok].filter(Boolean));

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
				nfBtn.hidden = !P.folder || !DS.canPick(P.folder) || typeof api.mkdir !== 'function';
				if (nfBtn.hidden) nfRow.hidden = true;
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
			view: 'folder',     // folder | search | trash | links | sync | photos | storage
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
			guard: null,       // Drive 1.6: { locked, incident, portal }
			livePending: false,
			vaultStatus: null, // Drive 1.9: { supported, device } of this PC
			vaults: [],        // Drive 1.9: the vaults (pending requests, needsRotation)
			// Drive 1.11: the menu's tree (node id → { items, loading, error }), the unfolded nodes (kept on this PC),
			// the vault lock's status, the last activity sent to the core
			tree: new Map(),
			open: MS.parseOpen(remembered(MS.OPEN_KEY)),
			treeFocus: null,
			lock: null,
			lastTouch: 0,
			// Drive 1.12: the selection (node ids of the list shown; `selKey` the list it belongs to), its anchor for
			// Umschalt+click, Strg+X / Strg+C inside Drive, the nodes being dragged, what a job brought ("neu hier")
			sel: new Set(),
			anchor: null,
			selKey: null,
			clip: null,
			drag: null,
			fresh: null,
			// Drive 1.14: the search field asks ('ask') or searches files; the question shown and its answer
			searchMode: 'auto',
			ask: null,
		};
		const keepOpen = () => keep(MS.OPEN_KEY, MS.serializeOpen(S.open));

		// ── Skeleton ─────────────────────────────────────
		const refs = {};
		const rootEl = el('div', { class: 'dv' });
		o.root.appendChild(rootEl);
		refs.h = el('h1', { class: 'dv-h', text: t('drive.title') });
		refs.sub = el('span', { class: 'dv-sub' });
		refs.searchLabel = el('label', { class: 'dv-sr', for: nextId('dv-q') });
		refs.search = el('input', { id: refs.searchLabel.getAttribute('for'), type: 'search', class: 'dv-search-in', maxlength: '100', on: { input: onSearchInput, keydown: onSearchKey } });
		refs.refresh = el('button', { type: 'button', class: 'dv-ib', on: { click: () => reload() } }, [icon('refresh', 16)]);
		// Drive 1.14 'docAsk': "Dateien | Fragen" at the search field
		refs.modes = el('div', { class: 'seg dv-seg dv-ki-modes', role: 'radiogroup', hidden: true });
		refs.banner = el('div', { class: 'dv-banner', role: 'status', hidden: true });
		refs.guard = el('div', { class: 'dv-guard', role: 'alert', hidden: true });
		refs.side = el('nav', { class: 'dv-side scroll' });
		refs.bar = el('div', { class: 'dv-bar' });
		refs.note = el('div', { class: 'dv-note', hidden: true });
		refs.list = el('div', { class: 'dv-list card', role: 'list' });
		refs.listWrap = el('div', { class: 'dv-list-wrap scroll' }, [refs.list]);
		// Drive 1.12: the green bar of the selection, the shortcuts below the list, the hint while dragging
		refs.selBar = el('div', { class: 'dv-selbar', role: 'toolbar', hidden: true });
		refs.keys = el('div', { class: 'dv-keys', role: 'group', hidden: true });
		refs.dropHint = el('div', { class: 'dv-drop-hint', 'aria-hidden': 'true', hidden: true });
		refs.transfers = el('div', { class: 'dv-transfers card', hidden: true });
		// "Ordner sichern" (drive-sync-view.js): only with the core's DriveSync
		const syncView = root.GCDriveSyncView && api.sync ? root.GCDriveSyncView.mount({
			api: api.sync, t, getLocale: o.getLocale, now, toast, host, onDemandApi: o.onDemandApi || null,
			ui: { el, icon, clear, openDialog },
			pickDriveFolder: (opts) => pickFolder({ api, t, host, ...(opts || {}) }),
			// Drive 1.11: its settings card is shown in the Drive settings
			openSettings: (section) => openSettingsView(section),
			onSummary: (sum) => {
				const tx = sum ? sum.text : '';
				if (tx === S.syncSummary) return;
				S.syncSummary = tx;
				if (S.shown && !refs.main.hidden) renderSide();
			},
		}) : null;
		// Drive 1.12: jobs for the selection (drive-bulk-view.js) — "Ziel wählen", the question for names there already,
		// the note "… verschoben · Rückgängig" when a job ended
		const bulkUi = root.GCDriveBulkView && BS && api.ops ? root.GCDriveBulkView.create({
			api, t, getLocale: o.getLocale, ui: { el, icon, clear, openDialog }, host, toast, now, DS,
			getMe: () => S.me, getAreas: () => S.areas, copyText: (text) => copy(text),
			onFresh: (f) => { S.fresh = f; },
			onDone: () => {
				if (!S.shown) { S.dirty = true; return; }
				// "Fotos" draws again itself; the folder, the search and the menu's tree load again
				if (VIEWS[S.view] && S.view === 'photos') VIEWS[S.view].refresh();
				else live.request();
			},
		}) : null;
		// Drive 1.7: "Fotos" (drive-photos-view.js) and "Speicher" (drive-storage-view.js)
		const extra = {
			api, t, getLocale: o.getLocale, toast, host, ui: { el, icon, clear, openDialog },
			getMe: () => S.me, getAreas: () => S.areas, areaLabel: DS.areaLabel, errorText: DS.errorText, formatBytes: DS.formatBytes,
			openFolder: (id) => { refs.search.value = ''; S.query = ''; loadFolder(id); },
			// Drive 1.12: the selection of photos (ZIP, Verschieben / Kopieren nach …, Link, Löschen)
			bulk: bulkUi ? {
				actions: (items) => BS.actions(items, { me: S.me, writable: items.every((n) => !!(S.areas.find((a) => a.id === n.areaId) || {}).writable), vault: false }),
				zip: (items) => bulkUi.zip(items, null),
				move: (items, mode) => {
					const a = BS.actions(items, { me: S.me, writable: items.every((n) => !!(S.areas.find((x) => x.id === n.areaId) || {}).writable), vault: false });
					return bulkUi.run({ op: mode, items, canMove: a.move.on, canCopy: a.copy.on });
				},
				trash: (items) => bulkUi.run({ op: 'trash', items, confirm: !DS.hasFeature(S.me, 'bulk') }),
				link: (items) => (items.length === 1 ? shareDialog(items[0]) : bulkUi.linkDialog(items)),
			} : null,
		};
		const photosView = root.GCDrivePhotosView && typeof api.photos === 'function' ? root.GCDrivePhotosView.mount(extra) : null;
		const storageView = root.GCDriveStorageView && typeof api.storage === 'function' ? root.GCDriveStorageView.mount(extra) : null;
		// Drive 1.11: the Drive settings (the gear)
		const settingsView = root.GCDriveSettingsView ? root.GCDriveSettingsView.mount({
			api, t, getLocale: o.getLocale, toast, ui: { el, icon, clear, openDialog }, syncView, onDemand: !!o.onDemandApi, notifyApi: o.notifyApi || null,
			page: () => ({ me: S.me, areas: S.areas, vaults: S.vaults, vaultStatus: S.vaultStatus, lock: S.lock, sort: S.sort, syncSummary: S.syncSummary }),
			openSync: () => openSync(),
			// kept for the lists; the folder loads in that order when it is shown next
			setSort: (sort) => { if (DS.SORTS.includes(sort)) { S.sort = sort; keep('gc.drive.sort', sort); } },
			docAiChanged: (areaId, on) => {
				S.areas = DS.withDocAi(S.areas, areaId, on);
				if (S.me && Array.isArray(S.me.areas)) S.me = { ...S.me, areas: DS.withDocAi(S.me.areas, areaId, on) };
				S.dirty = true;
			},
			lockChanged: (st) => { S.lock = st && st.ok !== false ? st : S.lock; },
			cacheCleared: () => {
				for (const p of S.previews.values()) Promise.resolve(p).then((u) => { if (u) URL.revokeObjectURL(u); }).catch(() => {});
				S.previews.clear();
			},
		}) : null;
		const VIEWS = { sync: syncView, photos: photosView, storage: storageView, settings: settingsView };
		// Drive 1.8 'docAi' (drive-docs-view.js) and 1.9 'vault' (drive-vault-view.js)
		const docs = root.GCDriveDocsView && typeof api.insight === 'function' ? root.GCDriveDocsView.create({
			api, t, getLocale: o.getLocale, ui: { el, icon, clear, openDialog }, host, toast, now, errorText: DS.errorText,
			areaLabel: (areaId) => DS.areaLabel(S.areas.find((a) => a.id === areaId), t),
			writable: (n) => !!(S.areas.find((a) => a.id === n.areaId) || {}).writable,
			openFile: (n) => openNode(n),
			changed: () => refreshView(),
		}) : null;
		// Drive 1.14: deadlines by month and into the family calendar, "Ablegen" after an upload, "In Dokument umwandeln",
		// the answer to a question (drive-ki-view.js)
		const KS = root.GCDriveKiState;
		const ki = root.GCDriveKiView && KS && typeof api.ask === 'function' ? root.GCDriveKiView.create({
			api, t, getLocale: o.getLocale, ui: { el, icon, clear, openDialog }, host, toast, now, errorText: DS.errorText,
			getMe: () => S.me, getAreas: () => S.areas,
			areaLabel: (areaId) => DS.areaLabel(S.areas.find((a) => a.id === areaId), t),
			areaOfFolder: (folderId) => (S.folder && S.folder.node.id === folderId ? S.folder.node.areaId : S.areaId),
			pickFolder: (opts) => pickFolder({ api, t, host, ...(opts || {}) }),
			folderPath: async (id) => {
				const r = await Promise.resolve(api.folder(id, { limit: 1 })).catch(fail);
				return r && r.ok ? DS.pickerPath(r, S.areas.find((a) => a.id === r.node.areaId) || null, t) : '';
			},
			openFile: (id) => { Promise.resolve(api.open(id)).then((r) => { if (r && !r.ok) done(r); }).catch(() => {}); },
			details: docs ? (n) => docs.details(n) : null,
			changed: () => refreshView(),
		}) : null;
		const vaultUi = root.GCDriveVaultView && api.vault ? root.GCDriveVaultView.create({
			api, t, ui: { el, icon, clear, openDialog }, host, toast, errorText: DS.errorText,
			changed: () => { loadVaults().then(() => refreshView()); },
			// Drive 1.11: the vault lock
			getLock: () => S.lock,
			unlocked: () => { loadVaults().then(() => refreshView()); },
			openSettings: () => openSettingsView('vaults'),
		}) : null;
		const vaultOn = () => !!vaultUi && root.GCDriveVaultState.vaultAvailable(S.me, S.vaultStatus);
		refs.pane = el('section', { class: 'dv-pane' }, [refs.bar, refs.note, refs.selBar, refs.listWrap, refs.keys, ki ? ki.bar : null, refs.transfers, syncView ? syncView.el : null, photosView ? photosView.el : null, storageView ? storageView.el : null, settingsView ? settingsView.el : null]);
		refs.empty = el('div', { class: 'dv-gate', hidden: true });
		refs.main = el('div', { class: 'dv-main' }, [refs.side, refs.pane]);
		rootEl.append(
			el('div', { class: 'dv-head' }, [
				el('div', { class: 'dv-head-tx' }, [refs.h, refs.sub]),
				el('span', { class: 'dv-grow' }),
				el('div', { class: 'dv-search' }, [icon('search', 15), refs.searchLabel, refs.search]),
				refs.modes,
				refs.refresh,
			]),
			refs.banner,
			refs.guard,
			refs.empty,
			refs.main,
			...[refs.dropHint, bulkUi ? bulkUi.el : null].filter(Boolean),
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
		api.onTransfers((rows) => { S.transfers = Array.isArray(rows) ? rows : []; renderTransfers(); maybeAskConflict(); if (ki) ki.onTransfers(S.transfers); });
		api.onChanged((c) => {
			if (S.shown && S.view === 'folder' && S.folder && c && c.folderId === S.folder.node.id) loadFolder(S.folder.node.id, { quiet: true });
			else S.dirty = true;
		});
		// Drive changed elsewhere (push `changed`) / back in the window: what is shown loads again
		const live = DS.throttle(() => liveRefresh(), 2000);
		if (typeof api.onRemote === 'function') {
			api.onRemote((ev) => {
				if (ki) ki.onRemote();
				if (S.shown && DS.liveRelevant(ev, { view: S.view, areaId: S.folder ? S.folder.node.areaId : S.areaId })) live.request();
				else if (!S.shown) S.dirty = true;
			});
		}
		if (typeof root.addEventListener === 'function') {
			root.addEventListener('focus', () => { if (S.shown && S.me) live.request(); });
		}
		// Drive 1.6 'guard'
		if (typeof api.onGuard === 'function') api.onGuard((g) => { S.guard = g || null; renderGuard(); });
		// Drive 1.9: a request, an approval, a new key of a vault folder
		if (api.vault && typeof api.vault.onEvent === 'function') {
			api.vault.onEvent(() => { if (S.shown && vaultOn()) loadVaults().then(() => { if (S.view === 'folder') live.request(); }); });
		}
		// Drive 1.11: the vaults locked (time without use, window hidden, Windows locked, by hand) / unlocked
		if (api.vault && typeof api.vault.onLock === 'function') {
			api.vault.onLock((e) => {
				if (S.lock) S.lock = { ...S.lock, unlocked: !(e && e.locked) };
				if (!e || !e.locked) return;
				// an open vault folder closes to its card; the menu shows the vaults locked again
				const fv = S.folder && S.folder.vault;
				if (fv) {
					// the vault's "Geräte" closes too (approving needs its key); a recovery key being shown stays
					for (const d of host.querySelectorAll('.dv-scrim')) { if (d.querySelector('.dv-vdev') && !d.querySelector('.dv-rk')) d.dispatchEvent(new MouseEvent('mousedown', { bubbles: true })); }
					const v = vaultOf(fv.id);
					S.folder = null;
					S.dirty = true;
					if (S.shown) loadVaults().then(() => loadFolder(v ? v.nodeId : S.folderId));
				} else if (S.shown && vaultOn()) {
					loadVaults().then(() => { if (!VIEWS[S.view] || S.view === 'settings') render(); });
				}
			});
		}
		// Drive 1.11: real input on a vault keeps it open (vault:touch at most every 15 s)
		const vaultActivity = () => {
			if (!S.shown || !api.vault || typeof api.vault.touch !== 'function') return;
			if (!(S.folder && S.folder.vault && S.folder.vault.state === 'open')) return;
			if (now() - S.lastTouch < 15000) return;
			S.lastTouch = now();
			Promise.resolve(api.vault.touch()).catch(() => {});
		};
		rootEl.addEventListener('pointerdown', vaultActivity, true);
		rootEl.addEventListener('keydown', vaultActivity, true);
		rootEl.addEventListener('wheel', vaultActivity, { capture: true, passive: true });
		Promise.resolve(api.transfers()).then((r) => { if (r && r.ok) { S.transfers = r.transfers; renderTransfers(); if (ki) ki.onTransfers(S.transfers); } }).catch(() => {});

		// ── Loading ──────────────────────────────────────
		const area = () => S.areas.find((a) => a.id === (S.folder ? S.folder.node.areaId : S.areaId)) || null;
		// a vault folder only while this PC has its key
		const canUpload = () => S.view === 'folder' && !!S.folder && S.folder.writable && !(S.folder.vault && S.folder.vault.state !== 'open');

		/** Drive 1.9: this PC's vault state and the vaults (requests waiting, a new key needed). */
		async function loadVaults() {
			if (!vaultUi || !DS.hasFeature(S.me, 'vault')) { S.vaultStatus = null; S.vaults = []; return; }
			const [st, lock] = await Promise.all([
				Promise.resolve(api.vault.status()).catch(() => null),
				typeof api.vault.lockStatus === 'function' ? Promise.resolve(api.vault.lockStatus()).catch(() => null) : null,
			]);
			S.vaultStatus = st && st.ok ? st : null;
			S.lock = lock && lock.ok ? lock : null;
			if (!vaultOn()) { S.vaults = []; return; }
			const r = await Promise.resolve(api.vault.list()).catch(() => null);
			S.vaults = r && r.ok ? r.vaults : [];
		}
		const vaultOf = (id) => S.vaults.find((v) => v.id === id) || null;

		async function reload() {
			S.dirty = false;
			S.loading = true;
			S.error = null;
			render();
			const me = await Promise.resolve(api.me()).catch(fail);
			S.me = me && me.ok ? me : null;
			S.access = DS.accessOf(S.me);
			if (S.me && S.me.guard) S.guard = { locked: !!S.me.guard.locked, incident: S.me.guard.incident || null, portal: !!(S.me.links && S.me.links.drive) };
			if (!me || !me.ok) {
				S.loading = false;
				S.error = me;
				render();
				return;
			}
			if (S.access.usable) {
				const ar = await Promise.resolve(api.areas()).catch(fail);
				S.areas = DS.sortAreas(ar && ar.ok ? ar.areas : me.areas);
				// the menu's tree loads again (only what is unfolded); the first time "Meine Dateien" is unfolded
				S.tree.clear();
				if (remembered(MS.OPEN_KEY) === null) {
					const mine = S.areas.find((x) => x.kind === 'mine');
					if (mine) { S.open.add(mine.rootId); keepOpen(); }
				}
				await loadVaults();
			} else {
				S.areas = [];
			}
			S.loading = false;
			if (!S.access.usable || !S.areas.length) { render(); return; }
			if (S.view === 'folder') {
				const a = DS.currentArea(S.areas, S.areaId);
				await loadFolder(S.folderId || (a && a.rootId), { quiet: true, fallback: a && a.rootId });
			} else if (S.view === 'sync') openSync();
			else if (S.view === 'photos' || S.view === 'storage') openExtra(S.view);
			else if (S.view === 'trash') await loadTrash();
			else if (S.view === 'links') await loadLinks();
			else if (S.view === 'search') await runSearch();
			else if (S.view === 'deadlines') openDeadlines();
			else if (S.view === 'settings') openSettingsView();
			else if (S.view === 'ask' && S.ask) { if (!DS.hasFeature(S.me, 'docAsk')) backToFolder(); else render(); }
			else render();
		}

		/** The Drive settings (Drive 1.11, the gear); `section` scrolls to one ('backup', 'vaults', …). */
		function openSettingsView(section = null) {
			if (!settingsView) return;
			S.view = 'settings';
			S.loading = false;
			S.error = null;
			refs.search.value = '';
			S.query = '';
			render();
			settingsView.show();
			if (section) setTimeout(() => settingsView.focus(section), 0);
		}

		// ── The menu's tree (Drive 1.11) ─────────────────
		/** Loads the subfolders of `id` (once; again with `fresh`) and draws the menu. */
		async function loadTree(id, { fresh = false } = {}) {
			const cur = S.tree.get(id);
			if (cur && cur.loading) return;
			if (cur && cur.items && !fresh) return;
			S.tree.set(id, { ...(cur || {}), loading: true, error: null });
			const r = typeof api.tree === 'function' ? await Promise.resolve(api.tree(id)).catch(fail) : null;
			if (r && r.ok) S.tree.set(id, { items: r.items, loading: false, error: null });
			else S.tree.set(id, { items: cur && cur.items ? cur.items : null, loading: false, error: DS.errorText(r || { code: 'unsupported' }, t) });
			if (S.shown && !refs.main.hidden) renderSide();
		}

		/** What is unfolded and loaded loads again (after a change: new / renamed / moved folders). */
		function refreshTree() {
			for (const [id, x] of S.tree) {
				if (x && x.items && S.open.has(id)) loadTree(id, { fresh: true });
				else if (!S.open.has(id)) S.tree.delete(id);
			}
		}

		function setOpen(id, on) {
			if (on) S.open.add(id); else S.open.delete(id);
			keepOpen();
			renderSide();
		}

		/** "Fristen" (Drive 1.8 'docAi'): the deadlines of every file the person reads. */
		function openDeadlines() {
			if (!docs || !DS.hasFeature(S.me, 'docAi')) { S.view = 'folder'; const a = DS.currentArea(S.areas, S.areaId); loadFolder(S.folderId || (a && a.rootId)); return; }
			S.view = 'deadlines';
			S.loading = false;
			S.error = null;
			refs.search.value = '';
			S.query = '';
			render();
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
				// the folder shown is visible in the menu: the folders above it unfold (not inside a vault)
				if (!r.vault) {
					const up = MS.ancestorsOf(r).filter((x) => !S.open.has(x));
					if (up.length) { for (const x of up) S.open.add(x); keepOpen(); }
				}
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

		/** "Fotos" / "Speicher" (Drive 1.7): only while this Drive reports the feature. */
		function extraAvailable(view) {
			if (view === 'photos') return !!photosView && DS.hasFeature(S.me, 'photos');
			if (view === 'storage') return !!storageView && DS.hasFeature(S.me, 'storage');
			return false;
		}

		function openExtra(view) {
			if (!extraAvailable(view)) { S.view = 'folder'; const a = DS.currentArea(S.areas, S.areaId); loadFolder(S.folderId || (a && a.rootId)); return; }
			S.view = view;
			S.loading = false;
			S.error = null;
			refs.search.value = '';
			S.query = '';
			render();
			VIEWS[view].show();
		}

		async function loadTrash({ quiet = false } = {}) {
			S.view = 'trash';
			if (!quiet || !S.trash) { S.loading = true; render(); }
			const r = await Promise.resolve(api.trash()).catch(fail);
			S.loading = false;
			if (S.view !== 'trash') return;
			S.trash = r && r.ok ? r.items : null;
			S.error = r && r.ok ? null : r;
			render();
		}

		async function loadLinks({ quiet = false } = {}) {
			S.view = 'links';
			if (!quiet || !S.links) { S.loading = true; render(); }
			const r = await Promise.resolve(api.links()).catch(fail);
			S.loading = false;
			if (S.view !== 'links') return;
			S.links = r && r.ok ? r : null;
			S.error = r && r.ok ? null : r;
			render();
		}

		let searchTimer = null;
		/** Drive 1.14: does the search field ask (the chip "Fragen", or "?" at the end)? */
		const asking = (q) => !!ki && KS.asks(q, S.searchMode, S.me);
		function onSearchInput() {
			clearTimeout(searchTimer);
			const q = refs.search.value.trim();
			renderModes();
			if (!q) { S.searchMode = 'auto'; renderModes(); if (S.view === 'search' || S.view === 'ask') backToFolder(); return; }
			// a question waits for Enter (Drive answers a limited number per hour)
			if (asking(q) || q.length < 2) return;
			searchTimer = setTimeout(() => { S.query = q; runSearch(); }, 350);
		}
		function onSearchKey(e) {
			if (e.key === 'Enter') {
				clearTimeout(searchTimer);
				const q = refs.search.value.trim();
				if (q.length >= 2 && asking(q)) runAsk(q);
				else if (q.length >= 2) { S.query = q; runSearch(); }
			} else if (e.key === 'Escape' && refs.search.value) {
				e.preventDefault();
				refs.search.value = '';
				S.searchMode = 'auto';
				renderModes();
				backToFolder();
			}
		}
		/** "Dateien | Fragen" (only where Drive answers questions). */
		function renderModes() {
			clear(refs.modes);
			refs.modes.hidden = !ki || !DS.hasFeature(S.me, 'docAsk');
			if (refs.modes.hidden) return;
			refs.modes.setAttribute('aria-label', t('drive.ki.ask.modes'));
			const on = asking(refs.search.value) ? 'ask' : 'files';
			for (const m of ['files', 'ask']) {
				refs.modes.appendChild(el('button', { type: 'button', role: 'radio', 'aria-checked': on === m ? 'true' : 'false', class: on === m ? 'on' : '', 'data-mode': m, text: t(`drive.ki.ask.mode.${m}`), on: { click: () => {
					S.searchMode = m;
					refs.search.placeholder = t(m === 'ask' ? 'drive.ki.ask.placeholder' : 'drive.search.placeholder');
					renderModes();
					refs.search.focus();
					const q = refs.search.value.trim();
					if (m === 'files' && q.length >= 2 && !asking(q)) { S.query = q; runSearch(); }
				} } }));
			}
		}
		/** Drive 1.14 'docAsk': the question `q` to the person's files → the answer card in the list. */
		async function runAsk(q) {
			S.view = 'ask';
			S.query = '';
			S.ask = { q, loading: true, answer: null, error: null };
			S.loading = false;
			S.error = null;
			render();
			const r = await Promise.resolve(api.ask(q)).catch(fail);
			if (S.view !== 'ask' || !S.ask || S.ask.q !== q) return;
			S.ask = { q, loading: false, answer: r && r.ok ? r : null, error: r && r.ok ? null : r };
			render();
		}
		async function runSearch({ quiet = false } = {}) {
			const q = S.query;
			S.view = 'search';
			if (!quiet || !S.results) { S.loading = true; render(); }
			const r = await Promise.resolve(api.search(q)).catch(fail);
			if (S.view !== 'search' || S.query !== q) return;
			S.loading = false;
			S.results = r && r.ok ? r.items : null;
			S.error = r && r.ok ? null : r;
			render();
		}
		function backToFolder() {
			S.query = '';
			S.ask = null;
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
		const refreshView = () => {
			refreshTree();
			return S.view === 'folder' && S.folder ? loadFolder(S.folder.node.id, { quiet: true }) : S.view === 'trash' ? loadTrash() : S.view === 'search' ? runSearch() : S.view === 'links' ? loadLinks() : S.view === 'deadlines' ? openDeadlines() : S.view === 'sync' ? openSync() : VIEWS[S.view] ? VIEWS[S.view].refresh() : null;
		};

		/**
		 * Live reload (push `changed`, back in the window): without "loading", scroll position and
		 * the focused row kept; waits while a menu or dialog is open.
		 */
		async function liveRefresh() {
			if (!S.shown || S.loading || VIEWS[S.view] !== undefined) return;
			if (S.menu || host.querySelector('.dv-scrim')) { S.livePending = true; return; }
			S.livePending = false;
			const top = refs.listWrap.scrollTop;
			const a = document.activeElement;
			const row = a && refs.list.contains(a) ? a.closest('[data-id]') : null;
			const focusId = row ? row.getAttribute('data-id') : null;
			const focusMore = !!(a && a.classList && a.classList.contains('dv-more-btn'));
			refreshTree();
			if (S.view === 'folder' && S.folder) await loadFolder(S.folder.node.id, { quiet: true });
			else if (S.view === 'trash') await loadTrash({ quiet: true });
			else if (S.view === 'search' && S.query) await runSearch({ quiet: true });
			else if (S.view === 'links') await loadLinks({ quiet: true });
			refs.listWrap.scrollTop = top;
			if (focusId) {
				const back = refs.list.querySelector(`[data-id="${CSS.escape(focusId)}"] ${focusMore ? '.dv-more-btn' : '.dv-open'}`);
				if (back) back.focus();
			}
		}

		async function openNode(n) {
			// Drive 1.9: a vault this PC has no key for opens on its card ("Zugriff anfragen")
			if (n.isDir) { refs.search.value = ''; S.query = ''; loadFolder(n.id); return; }
			if (n.encrypted && n.locked) { toast(t('drive.err.vaultLocked'), 'error'); return; }
			const r = await Promise.resolve(api.open(n.id)).catch(fail);
			if (r && r.ok) return;
			if (r && r.code === 'unsafe') {
				toast(t('drive.err.unsafe'), 'error');
				return;
			}
			done(r);
		}

		/** "Im Browser bearbeiten / ansehen" (Drive 1.9 'office'): the office address in the default browser. */
		async function openOffice(n) {
			const r = await Promise.resolve(api.office(n.id)).catch(fail);
			if (r && r.ok) toast(t(r.mode === 'edit' ? 'drive.office.openedEdit' : 'drive.office.openedView'), 'info');
			else done(r);
		}

		/** "Aus Google Drive / OneDrive importieren (im Portal)" (Drive 1.8 'cloudImport') */
		async function openImport() {
			const r = await Promise.resolve(api.openImport()).catch(fail);
			if (r && r.ok) toast(t('drive.import.opened'), 'info');
			else done(r);
		}

		async function openInPortal(n) {
			const r = await Promise.resolve(api.openInPortal(n ? n.id : null)).catch(fail);
			if (!r || !r.ok) done(r);
		}

		// ── Guard (Drive 1.6) ────────────────────────────
		function renderGuard() {
			clear(refs.guard);
			const v = DS.guardView(S.guard, { t, locale: locale(), now: now() });
			refs.guard.hidden = !v;
			if (!v) return;
			const list = v.sample.length ? el('ul', { class: 'dv-guard-list' }, v.sample.map((x) => el('li', { text: x }))) : null;
			const more = v.more ? el('span', { class: 'dv-guard-more', text: DS.plural(t, 'drive.guard.more', v.more) }) : null;
			refs.guard.append(
				el('span', { class: 'dv-guard-ic' }, [icon('lock', 18)]),
				el('div', { class: 'dv-guard-tx' }, [el('b', { text: v.title }), el('p', { class: 'dv-p', text: v.text }), list, more]),
				el('div', { class: 'dv-guard-acts' }, [
					v.id !== null ? el('button', { type: 'button', class: 'btn btn-pri btn-sm', text: t('drive.guard.undo'), on: { click: () => decideGuard(v.id, 'undo') } }) : null,
					v.id !== null ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.guard.release'), on: { click: () => decideGuard(v.id, 'release') } }) : null,
					v.portal ? el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('drive.guard.portal'), on: { click: () => openInPortal(null) } }) : null,
				]),
			);
		}

		function decideGuard(id, decision) {
			confirmDialog({
				title: t(decision === 'undo' ? 'drive.guard.undoTitle' : 'drive.guard.releaseTitle'),
				text: t(decision === 'undo' ? 'drive.guard.undoText' : 'drive.guard.releaseText'),
				confirm: t(decision === 'undo' ? 'drive.guard.undo' : 'drive.guard.release'),
				danger: decision === 'release',
				run: async () => {
					const r = await api.guardDecide(id, decision);
					if (r && r.ok) {
						S.guard = r.guard || null;
						renderGuard();
						toast(decision === 'undo' ? t('drive.guard.undone', { restored: r.restored || 0, trashed: r.trashed || 0 }) : t('drive.guard.released'), 'success');
						refreshView();
					}
					return r;
				},
			});
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

		async function pickFolderAndUpload() {
			if (!canUpload() || typeof api.pickFolders !== 'function') return;
			const p = await Promise.resolve(api.pickFolders()).catch(fail);
			if (!p || !p.ok) { if (p && p.code !== 'cancelled') done(p); return; }
			const r = await Promise.resolve(api.upload(S.folder.node.id, p.paths)).catch(fail);
			afterQueue(r);
		}

		function afterQueue(r) {
			if (!r || !r.ok) { done(r); return; }
			const ft = DS.folderQueuedText(r, t);
			if (ft) toast(ft, 'info');
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

		/**
		 * "Neu" (Drive 1.11, like the app's plus menu): Neuer Ordner, Dateien hochladen, Ordner hochladen and — not in
		 * a vault — "Neuer Tresor" (it goes into the top folder of the area picked and shows in the menu).
		 */
		function newMenu(anchor) {
			const fv = S.folder && S.folder.vault;
			const items = [
				{ icon: 'folderPlus', label: t('drive.newFolder'), run: newFolder, key: 'folder' },
				{ icon: 'upload', label: t('drive.new.files'), run: pickAndUpload, key: 'files' },
				typeof api.pickFolders === 'function' ? { icon: 'folder', label: t('drive.upload.folderButton'), run: pickFolderAndUpload, key: 'dir' } : null,
			];
			if (!fv && vaultOn() && vaultUi) {
				items.push('sep', { icon: 'lock', label: t('drive.vault.create.button'), sub: t('drive.vault.create.menuHint'), key: 'vault', run: () => {
					const lock = S.lock && S.lock.settings ? S.lock.settings : null;
					vaultUi.createDialog(MS.vaultChoices(S.me, S.areas, t), { autoLock: lock ? lock.autoLockMinutes : 3, hello: !lock || !S.lock.enforced ? true : lock.hello });
				} });
			}
			popupMenu(anchor, items.filter(Boolean));
		}

		/** A small menu below a button (the row menu's look): items { icon, label, sub?, run, key } or 'sep'. */
		function popupMenu(anchor, items) {
			closeMenu();
			const els = items.map((x) => (x === 'sep' ? el('div', { class: 'dv-menu-sep', role: 'separator' }) : el('button', { type: 'button', role: 'menuitem', class: `dv-menu-item${x.sub ? ' has-sub' : ''}`, 'data-item': x.key, on: { click: () => { closeMenu(); x.run(); } } }, [
				icon(x.icon, 15),
				x.sub ? el('span', { class: 'dv-menu-tx' }, [el('span', { text: x.label }), el('span', { class: 'dv-menu-sub', text: x.sub })]) : el('span', { text: x.label }),
			])));
			const menu = el('div', { class: 'dv-menu', role: 'menu' }, els);
			const layer = el('div', { class: 'dv-menu-layer', on: { mousedown: (e) => { if (e.target === layer) closeMenu(); } } }, [menu]);
			const buttons = els.filter((x) => x.tagName === 'BUTTON');
			layer.addEventListener('keydown', (e) => {
				if (e.key === 'Escape') { e.stopPropagation(); closeMenu(); if (anchor && anchor.focus) anchor.focus(); return; }
				const i = buttons.indexOf(document.activeElement);
				if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
					e.preventDefault();
					const n = buttons.length;
					buttons[(i + (e.key === 'ArrowDown' ? 1 : n - 1) + n) % n].focus();
				}
			});
			host.appendChild(layer);
			S.menu = layer;
			const r = anchor.getBoundingClientRect();
			const mr = menu.getBoundingClientRect();
			menu.style.left = `${Math.max(8, Math.min(window.innerWidth - mr.width - 8, r.right - mr.width))}px`;
			menu.style.top = `${r.bottom + 4 + mr.height + 8 < window.innerHeight ? r.bottom + 4 : Math.max(8, r.top - 4 - mr.height)}px`;
			if (buttons[0]) buttons[0].focus();
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
			// Drive 1.12: "Ziel wählen" with the question for a name there already (and "Rückgängig")
			if (bulkUi) { doMove([n], 'move'); return; }
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

		// ── Time travel (Drive 1.7) ──────────────────────
		/**
		 * "Auf früheren Stand zurücksetzen …": a time (quick choices or date and time) → the preview
		 * → run → the result with "Rückgängig" (a time travel to `before`).
		 */
		function timeTravelDialog(n) {
			const name = n.parentId ? n.name : DS.areaLabel(S.areas.find((a) => a.id === n.areaId), t) || n.name;
			const dlg = openDialog({ title: t('drive.tt.title', { name }), host, wide: true, closeLabel: t('drive.close') });
			dlg.box.classList.add('dv-tt');
			const errEl = el('span', { class: 'dv-dlg-err', role: 'alert' });
			let at = null;
			const back = () => pickStep();

			function pickStep() {
				clear(dlg.body);
				clear(dlg.foot);
				errEl.textContent = '';
				const nowMs = now();
				const id = nextId('dv-tt-at');
				const input = el('input', { id, type: 'datetime-local', class: 'dv-input dv-tt-at', max: DS.localInputValue(nowMs), value: DS.localInputValue(at || nowMs - 86400000) });
				const presets = el('div', { class: 'dv-tt-presets' });
				for (const p of DS.timeTravelPresets(nowMs, t)) presets.appendChild(el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: p.label, on: { click: () => { input.value = DS.localInputValue(p.at); at = p.at; preview(); } } }));
				const go = el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.tt.preview') });
				const submit = () => {
					const v = DS.parseLocalInput(input.value);
					const e = DS.timeTravelError(v, now(), t);
					if (e) { errEl.textContent = e; return; }
					at = v;
					preview();
				};
				go.addEventListener('click', submit);
				input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
				dlg.body.append(
					el('p', { class: 'dv-p', text: t('drive.tt.intro') }),
					el('span', { class: 'lbl', text: t('drive.tt.quick') }),
					presets,
					el('label', { class: 'lbl', for: id, text: t('drive.tt.when') }),
					input,
				);
				dlg.foot.append(errEl, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), go);
				setTimeout(() => input.focus(), 0);
			}

			async function preview() {
				clear(dlg.body);
				clear(dlg.foot);
				errEl.textContent = '';
				dlg.body.appendChild(el('div', { class: 'dv-pick-note', text: t('drive.tt.checking') }));
				const r = await Promise.resolve(api.timeTravelPreview(n.id, new Date(at).toISOString())).catch(fail);
				if (dlg.closed) return;
				clear(dlg.body);
				if (!r || !r.ok) {
					dlg.body.appendChild(el('div', { class: 'dv-dlg-err', text: DS.errorText(r, t) }));
					dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.back'), on: { click: back } }));
					return;
				}
				const v = DS.timeTravelView(r, { t, locale: locale() });
				dlg.body.appendChild(el('p', { class: 'dv-p dv-tt-when', text: t('drive.tt.backTo', { when: DS.longWhen(at, locale()) }) }));
				if (v.empty) {
					dlg.body.appendChild(el('div', { class: 'dv-note', text: t('drive.tt.nothingToDo') }));
					dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.back'), on: { click: back } }), el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.close'), on: { click: () => dlg.close(null) } }));
					return;
				}
				dlg.body.appendChild(el('ul', { class: 'dv-tt-sum' }, v.lines.map((l) => el('li', { text: l }))));
				if (v.sample.length) {
					dlg.body.appendChild(el('span', { class: 'lbl', text: t('drive.tt.examples') }));
					dlg.body.appendChild(el('div', { class: 'dv-tt-sample' }, v.sample.map((x) => el('div', { class: 'dv-tt-row' }, [
						el('span', { class: 'dv-tt-op', text: x.op }),
						el('span', { class: 'dv-tt-name', text: x.path || x.name }),
					]))));
					if (v.more) dlg.body.appendChild(el('span', { class: 'dv-pick-note', text: t('drive.tt.more', { count: v.more }) }));
				}
				if (v.limited) dlg.body.appendChild(el('div', { class: 'dv-note is-warn', text: v.limited }));
				if (v.lost) dlg.body.appendChild(el('div', { class: 'dv-note is-warn', text: v.lost }));
				if (v.tooMany) {
					dlg.body.appendChild(el('div', { class: 'dv-dlg-err dv-tt-many', role: 'alert', text: v.tooMany }));
					dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.back'), on: { click: back } }));
					return;
				}
				for (const l of DS.timeTravelLinked(r.linked, t)) dlg.body.appendChild(el('div', { class: `dv-note${l.mode === 'sync' ? '' : ' is-muted'}` }, [el('b', { text: t(l.mode === 'sync' ? 'drive.tt.linkedSyncH' : 'drive.tt.linkedBackupH') }), ' ', l.text]));
				dlg.body.appendChild(el('p', { class: 'dv-p', text: t('drive.tt.safe') }));
				const ok = el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.tt.run') });
				ok.addEventListener('click', () => run(at, ok));
				dlg.foot.append(errEl, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.back'), on: { click: back } }), ok);
			}

			async function run(when, btn, { undo = false } = {}) {
				if (btn) btn.disabled = true;
				errEl.textContent = '';
				const r = await Promise.resolve(api.timeTravel(n.id, new Date(when).toISOString())).catch(fail);
				if (btn) btn.disabled = false;
				if (!r || !r.ok) { errEl.textContent = DS.errorText(r, t); if (dlg.closed) toast(DS.errorText(r, t), 'error'); return; }
				refreshView();
				const text = DS.timeTravelResultText(r, t, { undo });
				toast(text, 'success');
				if (dlg.closed) return;
				clear(dlg.body);
				clear(dlg.foot);
				dlg.body.append(el('div', { class: 'dv-share-ok' }, [icon('check', 16), el('span', { text })]));
				if (!undo) dlg.body.appendChild(el('p', { class: 'dv-p', text: t('drive.tt.undoHint') }));
				const undoBtn = !undo && Number.isFinite(r.before) ? el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.tt.undo') }) : null;
				if (undoBtn) undoBtn.addEventListener('click', () => run(r.before, undoBtn, { undo: true }));
				dlg.foot.append(...[errEl, undoBtn, el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.close'), on: { click: () => dlg.close(null) } })].filter(Boolean));
			}

			pickStep();
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
			if (S.livePending) setTimeout(() => { if (S.livePending) live.request(); }, 0);
		}

		function openMenu(n, anchor, at) {
			closeMenu();
			const writable = S.view === 'folder' ? !!(S.folder && S.folder.writable) : !!(S.areas.find((a) => a.id === n.areaId) || {}).writable;
			const acts = DS.actionsFor(n, writable, S.me);
			const items = [];
			const item = (ic, label, fn, danger) => items.push(el('button', { type: 'button', role: 'menuitem', class: `dv-menu-item${danger ? ' is-danger' : ''}`, on: { click: () => { closeMenu(); fn(); } } }, [icon(ic, 15), el('span', { text: label })]));
			item(n.isDir ? 'folder' : 'open', t('drive.open'), () => openNode(n));
			if (acts.saveAs) item('down', t('drive.saveAs'), () => saveAs(n));
			if (S.view === 'search' && n.parentId) item('folder', t('drive.search.showFolder'), () => { refs.search.value = ''; S.query = ''; loadFolder(n.parentId); });
			if (acts.share) item('link', t('drive.share.menu'), () => shareDialog(n));
			if (acts.rename) item('pen', t('drive.rename'), () => renameNode(n));
			if (acts.move) item('move', t('drive.move'), () => moveNode(n));
			// Drive 1.12: "Kopieren nach …" and the ZIP of a folder
			if (bulkUi && !n.encrypted && BS.actions([n], { me: S.me }).copy.on) item('copy', t('drive.bulk.copyTo'), () => doMove([n], 'copy'));
			if (bulkUi && n.isDir && !n.encrypted && BS.actions([n], { me: S.me }).zip.on) item('down', t('drive.bulk.zipMenu'), () => bulkUi.zip([n], n.name));
			if (acts.versions) item('history', t('drive.versions.menu'), () => versionsDialog(n));
			if (acts.timeTravel) item('restore', t('drive.tt.menu'), () => timeTravelDialog(n));
			// Drive 1.8 'docAi' / 1.9 'office'
			if (acts.details && docs) item('calendar', t('drive.doc.details'), () => docs.details(n));
			// Drive 1.14 'scanDocs': a picture becomes a document
			if (ki && ki.available([n], writable)) item('file', t('drive.ki.scan.menu'), () => ki.scanDialog([n]));
			if (acts.office) item('globe', t(acts.office === 'edit' ? 'drive.office.edit' : 'drive.office.view'), () => openOffice(n));
			if (acts.portal) item('cloud', t('drive.portal.open'), () => openInPortal(n));
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

		// ── The selection (Drive 1.12) ───────────────────
		/** The list shown can be selected in: a folder (an open vault too) or the search. */
		const selectable = () => !!bulkUi && ((S.view === 'folder' && !!S.folder && !(S.folder.vault && S.folder.vault.state !== 'open')) || S.view === 'search');
		const selKeyNow = () => (S.view === 'folder' ? `f:${S.folder ? S.folder.node.id : S.folderId}` : S.view === 'search' ? `s:${S.query}` : S.view);
		/** The rows shown, in their order. */
		function shownItems() {
			if (S.view === 'folder') return S.folder ? DS.sortRows(S.folder.items, S.sort, { locale: locale() }) : [];
			if (S.view === 'search') return S.results || [];
			return [];
		}
		const selItems = () => shownItems().filter((n) => S.sel.has(n.id));
		const currentVault = () => (S.view === 'folder' && S.folder && S.folder.vault ? S.folder.vault.id : null);
		/** Where the selection may be written: the folder shown, or (search) every node's area. */
		function selWritable(items) {
			if (S.view === 'folder') return !!(S.folder && S.folder.writable);
			return items.every((n) => !!(S.areas.find((a) => a.id === n.areaId) || {}).writable);
		}
		const selActions = (items) => BS.actions(items, { me: S.me, writable: selWritable(items), vault: !!currentVault() });
		/** The name of the folder shown ("Dokumente", the area's for its top folder). */
		const folderName = () => (S.view === 'folder' && S.folder ? (S.folder.node.parentId ? S.folder.node.name : DS.areaLabel(area(), t) || S.folder.node.name) : '');

		function setSel(sel, anchor) {
			S.sel = sel;
			if (anchor !== undefined) S.anchor = anchor;
			paintSel();
		}
		function clearSel() {
			if (!S.sel.size) return;
			setSel(new Set(), null);
		}

		/** A click on a row (not its name, ⋯ or check box) / Strg / Umschalt on it. */
		function selectClick(n, e) {
			const ids = shownItems().map((x) => x.id);
			const r = BS.click(S.sel, ids, n.id, { ctrl: e.ctrlKey || e.metaKey, shift: e.shiftKey, anchor: S.anchor });
			setSel(r.sel, r.anchor);
		}

		/** The check box of a row (Umschalt: the range). */
		function checkClick(n, e) {
			if (e.shiftKey && S.anchor !== null) {
				const r = BS.click(S.sel, shownItems().map((x) => x.id), n.id, { ctrl: true, shift: true, anchor: S.anchor });
				setSel(r.sel, r.anchor);
			} else setSel(BS.toggle(S.sel, n.id), n.id);
		}

		/** Classes and check boxes of the rows, the head's tri-state, the bar — without drawing the list again. */
		function paintSel() {
			for (const row of refs.list.querySelectorAll('.dv-row[data-id]')) {
				const on = S.sel.has(Number(row.getAttribute('data-id')));
				row.classList.toggle('is-sel', on);
				const cb = row.querySelector('.dv-cb');
				if (cb) cb.checked = on;
			}
			const head = refs.list.querySelector('.dv-cb-all');
			if (head) {
				const st = BS.headState(S.sel, shownItems().map((n) => n.id));
				head.checked = st === 'all';
				head.indeterminate = st === 'some';
			}
			paintClip();
			renderSelBar();
		}

		/** Strg+X: the rows cut are shown faded until they are pasted. */
		function paintClip() {
			const cut = S.clip && S.clip.mode === 'cut' ? new Set(S.clip.items.map((x) => x.id)) : null;
			for (const row of refs.list.querySelectorAll('.dv-row[data-id]')) row.classList.toggle('is-cut', !!cut && cut.has(Number(row.getAttribute('data-id'))));
		}

		/** The green bar: ✕, "3 ausgewählt · 2 Dateien, 1 Ordner", ZIP, Verschieben nach …, Kopieren nach …, Link, Löschen. */
		function renderSelBar() {
			clear(refs.selBar);
			const items = selectable() ? selItems() : [];
			refs.selBar.hidden = !items.length;
			if (!items.length) return;
			const sum = BS.summary(items, t, locale());
			const acts = selActions(items);
			refs.selBar.setAttribute('aria-label', t('drive.bulk.bar'));
			const btn = (key, ic, label, fn, danger) => {
				const a = acts[key];
				return el('button', {
					type: 'button', class: `dv-tb${danger ? ' is-danger' : ''}${a.on ? '' : ' is-off'}`, 'data-act': key, 'aria-disabled': a.on ? null : 'true',
					title: a.on ? label : `${label} – ${t(a.why)}`, on: { click: () => (a.on ? fn() : toast(t(a.why), 'info')) },
				}, [icon(ic, 15), el('span', { text: label })]);
			};
			refs.selBar.append(
				el('button', { type: 'button', class: 'dv-tb is-icon dv-sel-clear', 'aria-label': t('drive.bulk.clear'), title: t('drive.bulk.clearKey'), on: { click: () => clearSel() } }, [icon('close', 15)]),
				el('span', { class: 'dv-sel-n' }, [el('b', { text: sum.title }), sum.detail ? el('span', { class: 'dv-sel-d', text: ` · ${sum.detail}` }) : null]),
				btn('zip', 'down', t('drive.bulk.zip'), () => doZip(selItems())),
				btn('move', 'move', t('drive.bulk.moveTo'), () => doMove(selItems(), 'move')),
				btn('copy', 'copy', t('drive.bulk.copyTo'), () => doMove(selItems(), 'copy')),
				btn('link', 'link', t('drive.bulk.link'), () => doLink(selItems())),
				btn('trash', 'trash', t('drive.bulk.trash'), () => doTrash(selItems()), true),
			);
		}

		/** The shortcuts below the list (folder / search). */
		function renderKeys() {
			clear(refs.keys);
			refs.keys.hidden = !selectable();
			if (refs.keys.hidden) return;
			const k = (x) => el('kbd', { class: 'dv-key', text: x });
			const ctrl = t('drive.bulk.key.ctrl');
			const click = t('drive.bulk.keys.click');
			const item = (parts, text) => el('span', { class: 'dv-keys-i' }, [...parts, ` ${text}`]);
			refs.keys.setAttribute('aria-label', t('drive.bulk.keys.label'));
			refs.keys.append(
				item([k(ctrl), '+', k('A')], t('drive.bulk.keys.all')),
				item([k(t('drive.bulk.key.shift')), `+${click}`], t('drive.bulk.keys.range')),
				item([k(ctrl), `+${click}`], t('drive.bulk.keys.single')),
				item([k(ctrl), '+', k('X'), ' / ', k('V')], t('drive.bulk.keys.cutPaste')),
				item([k(ctrl), '+', k('C'), ' / ', k('V')], t('drive.bulk.keys.copyPaste')),
				item([k(t('drive.bulk.key.del'))], t('drive.bulk.keys.trash')),
				item([k('Esc')], t('drive.bulk.keys.clear')),
				el('span', { class: 'dv-keys-i is-drag', text: t('drive.bulk.dropHint') }),
			);
		}

		// ── What the selection does ──────────────────────
		async function doMove(items, mode) {
			if (!bulkUi || !items.length) return;
			const fv = currentVault();
			const a = selActions(items);
			const v = fv ? vaultOf(fv) : null;
			const row = await bulkUi.run({
				op: mode, items, from: folderName() || null, startId: S.view === 'folder' && S.folder ? S.folder.node.id : null,
				vault: fv, vaultRoot: v ? v.nodeId : null, canMove: a.move.on, canCopy: a.copy.on,
			});
			if (row && row.kind !== 'copy') clearSel();
		}

		async function doTrash(items) {
			if (!bulkUi || !items.length) return;
			const row = await bulkUi.run({ op: 'trash', items, confirm: !DS.hasFeature(S.me, 'bulk') });
			if (row) clearSel();
		}

		function doZip(items) {
			if (bulkUi && items.length) bulkUi.zip(items, items.length > 1 ? folderName() || null : null);
		}

		function doLink(items) {
			if (!items.length) return;
			if (items.length === 1) shareDialog(items[0]);
			else if (bulkUi) bulkUi.linkDialog(items);
		}

		/** Strg+X / Strg+C: kept inside Drive (never the files themselves on the Windows clipboard). */
		function clipSet(mode, items) {
			if (!items.length) return;
			const a = selActions(items);
			const ok = mode === 'cut' ? a.cut : a.copyClip;
			if (!ok.on) { toast(t(ok.why), 'info'); return; }
			S.clip = { mode, items: items.map((n) => ({ id: n.id, name: n.name, isDir: n.isDir, parentId: n.parentId, size: n.size })), vault: currentVault() };
			paintClip();
			toast(DS.plural(t, mode === 'cut' ? 'drive.bulk.clip.cut' : 'drive.bulk.clip.copied', items.length), 'info');
		}

		/** Strg+V into the folder shown. */
		async function paste() {
			if (!bulkUi || S.view !== 'folder' || !S.folder) return;
			const st = BS.pasteState(S.clip, S.folder, S.me);
			if (!st.on) { toast(t(st.why), 'info'); return; }
			const target = { folderId: S.folder.node.id, path: DS.pickerPath(S.folder, area(), t), name: folderName() };
			const row = await bulkUi.run({ op: st.op, items: S.clip.items, target });
			if (row && st.op === 'move') { S.clip = null; paintClip(); }
		}

		/** The keys of the selection (not while typing, a menu or a dialog is open, nor in the menu's tree). */
		function onSelKey(e) {
			if (!S.shown || refs.main.hidden || !selectable() || S.menu || host.querySelector('.dv-scrim')) return;
			const tg = e.target;
			if (tg && tg !== document.body && tg !== document.documentElement && !rootEl.contains(tg)) return;
			if (tg && refs.side.contains(tg)) return;
			const tag = tg && tg.tagName ? tg.tagName.toUpperCase() : '';
			const editable = !!(tg && tg.isContentEditable) || tag === 'TEXTAREA' || tag === 'SELECT' || (tag === 'INPUT' && !['checkbox', 'radio', 'button'].includes(String(tg.type || '').toLowerCase()));
			const act = BS.keyAction(e, { target: { editable } });
			if (!act) return;
			const items = selItems();
			if (act === 'all') { e.preventDefault(); setSel(new Set(shownItems().map((n) => n.id)), null); return; }
			if (act === 'clear') {
				if (S.sel.size) { e.preventDefault(); clearSel(); } else if (S.clip) { S.clip = null; paintClip(); }
				return;
			}
			if (act === 'paste') { e.preventDefault(); paste(); return; }
			if (!items.length) return;
			if (act === 'copy' && root.getSelection && String(root.getSelection() || '')) return;
			e.preventDefault();
			if (act === 'trash') { const a = selActions(items); if (a.trash.on) doTrash(items); else toast(t(a.trash.why), 'info'); }
			else if (act === 'rename') { const a = selActions(items); if (a.rename.on) renameNode(items[0]); else toast(t(a.rename.why), 'info'); }
			else if (act === 'cut') clipSet('cut', items);
			else if (act === 'copy') clipSet('copy', items);
		}
		document.addEventListener('keydown', onSelKey);

		/** Right click into a selection of several: its menu (the mockup's) at the pointer. */
		function openSelMenu(at, anchor) {
			const items = selItems();
			const a = selActions(items);
			const entries = [
				{ key: 'zip', icon: 'down', label: t('drive.bulk.zipMenu'), act: a.zip, run: () => doZip(items) },
				{ key: 'cut', icon: 'move', label: t('drive.bulk.cut'), kbd: `${t('drive.bulk.key.ctrl')}+X`, act: a.cut, run: () => clipSet('cut', items) },
				{ key: 'copy', icon: 'copy', label: t('drive.bulk.copy'), kbd: `${t('drive.bulk.key.ctrl')}+C`, act: a.copyClip, run: () => clipSet('copy', items) },
				{ key: 'moveTo', icon: 'folder', label: t('drive.bulk.moveTo'), act: a.move, run: () => doMove(items, 'move') },
				{ key: 'copyTo', icon: 'copy', label: t('drive.bulk.copyTo'), act: a.copy, run: () => doMove(items, 'copy') },
				// Drive 1.14 'scanDocs': several pictures become one document (the pages in the order shown)
				...(ki && items.length > 1 && ki.available(items, selWritable(items)) ? [{ key: 'scan', icon: 'file', label: t('drive.ki.scan.menuMany', { count: items.length }), act: { on: true }, run: () => ki.scanDialog(items) }] : []),
				'sep',
				{ key: 'rename', icon: 'pen', label: t('drive.rename'), kbd: 'F2', act: a.rename, run: () => renameNode(items[0]) },
				{ key: 'link', icon: 'link', label: t('drive.bulk.link'), act: a.link, run: () => doLink(items) },
				'sep',
				{ key: 'trash', icon: 'trash', label: t('drive.bulk.trashMenu'), kbd: t('drive.bulk.key.del'), act: a.trash, run: () => doTrash(items), danger: true },
			];
			closeMenu();
			const els = entries.map((x) => (x === 'sep' ? el('div', { class: 'dv-menu-sep', role: 'separator' }) : el('button', {
				type: 'button', role: 'menuitem', class: `dv-menu-item${x.danger ? ' is-danger' : ''}${x.act.on ? '' : ' is-off'}`, 'data-item': x.key,
				'aria-disabled': x.act.on ? null : 'true', title: x.act.on ? null : t(x.act.why),
				on: { click: () => { if (!x.act.on) return; closeMenu(); x.run(); } },
			}, [icon(x.icon, 15), el('span', { text: x.label }), x.kbd ? el('span', { class: 'dv-menu-kbd', text: x.kbd }) : null])));
			const menu = el('div', { class: 'dv-menu dv-sel-menu', role: 'menu', 'aria-label': DS.plural(t, 'drive.bulk.menuLabel', items.length) }, [
				el('div', { class: 'dv-menu-h', text: DS.plural(t, 'drive.bulk.menuTitle', items.length) }), ...els,
			]);
			const layer = el('div', { class: 'dv-menu-layer', on: { mousedown: (e) => { if (e.target === layer) closeMenu(); }, contextmenu: (e) => { e.preventDefault(); closeMenu(); } } }, [menu]);
			const buttons = els.filter((x) => x.tagName === 'BUTTON');
			layer.addEventListener('keydown', (e) => {
				if (e.key === 'Escape') { e.stopPropagation(); closeMenu(); if (anchor && anchor.focus) anchor.focus(); return; }
				if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
					e.preventDefault();
					const i = buttons.indexOf(document.activeElement);
					const n = buttons.length;
					buttons[(i + (e.key === 'ArrowDown' ? 1 : n - 1) + n) % n].focus();
				}
			});
			host.appendChild(layer);
			S.menu = layer;
			const mr = menu.getBoundingClientRect();
			menu.style.left = `${Math.max(8, Math.min(window.innerWidth - mr.width - 8, at.left))}px`;
			menu.style.top = `${at.top + mr.height + 8 < window.innerHeight ? at.top : Math.max(8, at.top - mr.height)}px`;
			const first = buttons.find((b) => !b.classList.contains('is-off')) || buttons[0];
			if (first) first.focus();
		}

		// ── Dragging onto a folder (Drive 1.12) ──────────
		function endDrag() {
			S.drag = null;
			rootEl.classList.remove('is-dragging');
			refs.dropHint.hidden = true;
			for (const x of rootEl.querySelectorAll('.is-drop-target')) x.classList.remove('is-drop-target');
		}

		/** `node` takes dragged rows: tg() → { id, crumbs, vault, name, path } of the folder or null. */
		function dropTarget(node, tg) {
			const allowed = (e) => {
				if (!S.drag) return null;
				const x = tg();
				if (!x || (x.vault || null) !== (S.drag.vault || null)) return null;
				return BS.canDrop(S.drag, x.id, { copy: e.ctrlKey, crumbs: x.crumbs || [] }) ? x : null;
			};
			node.addEventListener('dragover', (e) => {
				const x = allowed(e);
				if (!x) return;
				e.preventDefault();
				e.stopPropagation();
				if (e.dataTransfer) e.dataTransfer.dropEffect = e.ctrlKey ? 'copy' : 'move';
				node.classList.add('is-drop-target');
				refs.dropHint.textContent = BS.dropText(S.drag.items.length, e.ctrlKey, t);
				refs.dropHint.hidden = false;
				refs.dropHint.style.left = `${e.clientX + 16}px`;
				refs.dropHint.style.top = `${e.clientY + 12}px`;
			});
			node.addEventListener('dragleave', (e) => {
				if (e.relatedTarget && node.contains(e.relatedTarget)) return;
				node.classList.remove('is-drop-target');
				refs.dropHint.hidden = true;
			});
			node.addEventListener('drop', (e) => {
				const x = allowed(e);
				if (!x) return;
				e.preventDefault();
				e.stopPropagation();
				const copyIt = e.ctrlKey;
				const items = S.drag.items;
				endDrag();
				const cp = BS.actions(items, { me: S.me }).copy;
				if (copyIt && !cp.on) { toast(t(cp.why), 'error'); return; }
				bulkUi.run({ op: copyIt ? 'copy' : 'move', items, target: { folderId: x.id, path: x.path || x.name, name: x.name } }).then((row) => { if (row && !copyIt) clearSel(); });
			});
		}

		function dragStart(n, e) {
			if (!selectable()) { e.preventDefault(); return; }
			if (!S.sel.has(n.id)) setSel(new Set([n.id]), n.id);
			const items = selItems();
			S.drag = { items: items.map((x) => ({ id: x.id, name: x.name, isDir: x.isDir, parentId: x.parentId })), vault: currentVault() };
			if (e.dataTransfer) {
				e.dataTransfer.setData(BS.DRAG_TYPE, JSON.stringify(items.map((x) => x.id)));
				e.dataTransfer.effectAllowed = 'copyMove';
			}
			rootEl.classList.add('is-dragging');
		}
		document.addEventListener('dragend', () => { if (S.drag) endDrag(); });

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
			const ic = v.locked && !v.isDir ? 'lock' : (KIND_ICON[v.kind] || 'file');
			const box = el('span', { class: `dv-thumb dv-k-${v.kind}${v.encrypted ? ' is-enc' : ''}` }, [icon(ic, 18), v.badge && !v.isDir && !KIND_ICON[v.kind] && !v.locked ? el('span', { class: 'dv-badge', text: v.badge }) : null]);
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
			refs.search.placeholder = t(ki && S.searchMode === 'ask' && DS.hasFeature(S.me, 'docAsk') ? 'drive.ki.ask.placeholder' : 'drive.search.placeholder');
			refs.refresh.title = t('drive.refresh');
			refs.refresh.setAttribute('aria-label', t('drive.refresh'));
			render();
			for (const v of Object.values(VIEWS)) if (v) v.relabel();
		}

		function render() {
			closeMenu();
			renderGuard();
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
			const inSync = !!VIEWS[S.view];
			refs.bar.hidden = inSync;
			refs.listWrap.hidden = inSync;
			for (const [k, v] of Object.entries(VIEWS)) if (v && k !== S.view) v.hide();
			renderSide();
			renderBar();
			renderModes();
			if (!inSync) renderList();
			if (inSync || !selectable()) { refs.selBar.hidden = true; clear(refs.selBar); }
			renderKeys();
			renderTransfers();
		}

		function sideButton({ label, sub, ic, on, onClick, cls = '' }) {
			return el('button', { type: 'button', class: `dv-area${cls}${on ? ' is-on' : ''}`, 'aria-current': on ? 'page' : null, on: { click: onClick } }, [
				el('span', { class: 'dv-area-ic' }, [icon(ic, 16)]),
				el('span', { class: 'dv-area-tx' }, [el('span', { class: 'dv-area-name', text: label }), sub ? el('span', { class: 'dv-area-sub', text: sub }) : null]),
			]);
		}

		/** Drive 1.11: the menu — who, "Persönlich" / "Gemeinsam" as trees, "Tresore", the bar of icons. */
		function renderSide() {
			const before = document.activeElement;
			const focusKey = before && refs.side.contains(before) ? before.getAttribute('data-key') : null;
			const scrollTop = refs.sideScroll ? refs.sideScroll.scrollTop : 0;
			clear(refs.side);
			refs.side.setAttribute('aria-label', t('drive.menu.label'));
			const mv = MS.meView(S.me, t);
			refs.side.appendChild(el('div', { class: 'dv-me' }, [
				el('span', { class: 'dv-me-av', 'aria-hidden': 'true', text: mv.initial }),
				el('span', { class: 'dv-me-tx' }, [el('span', { class: 'dv-me-name', text: mv.name || t('drive.title') }), mv.seat ? el('span', { class: 'dv-me-seat', text: mv.seat }) : null]),
			]));
			const scroll = el('div', { class: 'dv-side-scroll scroll' });
			refs.sideScroll = scroll;
			const inFolder = S.view === 'folder';
			const shownVault = inFolder && S.folder && S.folder.vault ? S.folder.vault.id : null;
			const current = inFolder && !shownVault ? (S.folder ? S.folder.node.id : S.folderId) : null;
			const groups = MS.areaGroups(S.areas);
			const opts = { nodes: S.tree, open: S.open, current, usage: (a) => DS.usage(a, t, locale()), areaLabel: (a) => DS.areaLabel(a, t), areaHint: (a) => DS.areaHint(a, t) };
			const needs = [];
			for (const [key, list] of [['personal', groups.personal], ['shared', groups.shared]]) {
				if (!list.length) continue;
				const labelId = nextId('dv-grp');
				scroll.appendChild(el('span', { class: 'lbl dv-side-lbl', id: labelId, text: t(`drive.menu.${key}`) }));
				const tr = MS.treeRows(list, opts);
				needs.push(...tr.needs);
				scroll.appendChild(treeEl(tr.rows, labelId));
			}
			// "Tresore": only here (Drive 1.11), never among the files
			if (vaultOn() && S.vaults.length) {
				const labelId = nextId('dv-grp');
				scroll.appendChild(el('span', { class: 'lbl dv-side-lbl', id: labelId, text: t('drive.menu.vaults') }));
				const box = el('div', { class: 'dv-vaults', role: 'group', 'aria-labelledby': labelId });
				for (const v of MS.vaultRows(S.vaults, S.areas, { t, locale: locale(), currentVault: shownVault })) {
					const b = sideButton({ label: v.name, sub: v.sub, ic: v.locked ? 'lock' : 'vault', on: v.current, cls: ` dv-vault-item${v.locked ? ' is-locked' : ''}`, onClick: () => { refs.search.value = ''; S.query = ''; loadFolder(v.nodeId); } });
					b.setAttribute('data-vault', v.vaultId);
					b.setAttribute('data-key', `v:${v.vaultId}`);
					box.appendChild(b);
				}
				scroll.appendChild(box);
			}
			refs.side.appendChild(scroll);
			// the bar of icons (each with its tooltip)
			const tools = el('div', { class: 'dv-tools', role: 'group', 'aria-label': t('drive.menu.tools') });
			const items = MS.toolItems({ me: S.me, photos: extraAvailable('photos'), storage: extraAvailable('storage'), sync: !!syncView, deadlines: !!docs, importer: typeof api.openImport === 'function', settings: !!settingsView }, t);
			for (const it of items) {
				const on = S.view === it.key;
				tools.appendChild(el('button', {
					type: 'button', class: `dv-ib dv-tool${on ? ' is-on' : ''}`, title: it.key === 'sync' && S.syncSummary ? `${it.label} · ${S.syncSummary}` : it.label, 'aria-label': it.label,
					'aria-current': on ? 'page' : null, 'data-view': it.key, 'data-key': `tool:${it.key}`, on: { click: () => openTool(it.key) },
				}, [icon(it.icon, 17)]));
			}
			refs.side.appendChild(tools);
			scroll.scrollTop = scrollTop;
			for (const id of needs) loadTree(id);
			if (focusKey) {
				const back = refs.side.querySelector(`[data-key="${CSS.escape(focusKey)}"]`);
				if (back) back.focus();
			}
		}

		function openTool(key) {
			refs.search.value = '';
			S.query = '';
			if (key === 'photos' || key === 'storage') openExtra(key);
			else if (key === 'links') loadLinks();
			else if (key === 'trash') loadTrash();
			else if (key === 'sync') openSync();
			else if (key === 'deadlines') openDeadlines();
			else if (key === 'import') openImport();
			else if (key === 'settings') openSettingsView();
		}

		/**
		 * One group's tree (WAI-ARIA tree, flat rows with aria-level): the arrow folds / unfolds, the name opens;
		 * keys: arrows, Home / End, Enter / Space (GCDriveMenuState.treeKey). One row is in the tab order.
		 */
		function treeEl(rows, labelId) {
			const tree = el('div', { class: 'dv-tree', role: 'tree', 'aria-labelledby': labelId });
			/** The ids above row `i` of the flat tree (by aria-level). */
			const ancestorsAt = (i) => {
				const out = [];
				let lvl = rows[i].level;
				for (let j = i - 1; j >= 0 && lvl > 1; j--) if (rows[j].level < lvl) { out.push(rows[j].id); lvl = rows[j].level; }
				return out;
			};
			let tab = rows.findIndex((r) => r.key === S.treeFocus);
			if (tab < 0) tab = rows.findIndex((r) => r.current);
			if (tab < 0) tab = 0;
			const els = rows.map((r, i) => {
				const tw = r.expandable
					? el('span', { class: `dv-tw${r.expanded ? ' is-open' : ''}`, 'aria-hidden': 'true', title: t(r.expanded ? 'drive.menu.fold' : 'drive.menu.unfold', { name: r.label }) }, [icon('chevron', 14, '2.4')])
					: el('span', { class: 'dv-tw is-leaf', 'aria-hidden': 'true' });
				tw.addEventListener('click', (e) => { if (!r.expandable) return; e.stopPropagation(); S.treeFocus = r.key; setOpen(r.id, !r.expanded); });
				const ic = r.area ? el('span', { class: 'dv-area-ic' }, [icon(AREA_ICON[r.kind] || 'folder', 16)]) : el('span', { class: 'dv-tree-ic' }, [icon('folder', 15)]);
				const item = el('div', {
					class: `dv-tree-row${r.area ? ' is-area' : ''}${r.current ? ' is-on' : ''}${r.loading ? ' is-loading' : ''}`, role: 'treeitem',
					'aria-level': String(r.level), 'aria-setsize': String(r.setsize), 'aria-posinset': String(r.posinset),
					'aria-selected': r.current ? 'true' : 'false', 'aria-expanded': r.expandable ? (r.expanded ? 'true' : 'false') : null,
					'aria-busy': r.loading ? 'true' : null, tabindex: i === tab ? '0' : '-1', 'data-key': r.key, 'data-node': String(r.id),
					style: `--lvl:${r.level - 1}`, title: r.sub ? `${r.label} · ${r.sub}` : r.label,
				}, [tw, ic, el('span', { class: 'dv-area-tx' }, [el('span', { class: 'dv-area-name', text: r.label }), r.sub ? el('span', { class: 'dv-area-sub', text: r.sub }) : null])]);
				item.addEventListener('click', () => { S.treeFocus = r.key; openTreeNode(r); });
				// Drive 1.12: dragged rows go into this folder (with Strg: copied)
				if (bulkUi) {
					const ar = r.area ? S.areas.find((a) => a.id === r.area) : null;
					if (!ar || (ar.writable && !ar.archived)) dropTarget(item, () => ({ id: r.id, name: r.label, crumbs: ancestorsAt(i), vault: null, path: r.label }));
				}
				return item;
			});
			tree.append(...els);
			tree.addEventListener('keydown', (e) => {
				const idx = els.indexOf(document.activeElement);
				if (idx < 0) return;
				const act = MS.treeKey(e.key, rows, idx);
				if (!act) return;
				e.preventDefault();
				e.stopPropagation();
				if (act.focus !== undefined) {
					els[idx].setAttribute('tabindex', '-1');
					els[act.focus].setAttribute('tabindex', '0');
					els[act.focus].focus();
					S.treeFocus = rows[act.focus].key;
				} else if (act.expand !== undefined) { S.treeFocus = rows[idx].key; setOpen(act.expand, true); }
				else if (act.collapse !== undefined) { S.treeFocus = rows[idx].key; setOpen(act.collapse, false); }
				else if (act.open !== undefined) { S.treeFocus = rows[idx].key; openTreeNode(rows[idx]); }
			});
			return tree;
		}

		function openTreeNode(r) {
			refs.search.value = '';
			S.query = '';
			if (r.area) { S.areaId = r.area; keep('gc.drive.area', r.area); }
			loadFolder(r.id);
		}

		/** The vault a breadcrumb lies in (from the vault's own folder on), else null. */
		function crumbVault(cr, i) {
			const fv = S.folder && S.folder.vault ? S.folder.vault.id : null;
			const v = fv ? vaultOf(fv) : null;
			const at = v ? cr.findIndex((x) => x.id === v.nodeId) : -1;
			return fv && at >= 0 && i >= at ? fv : null;
		}

		function renderBar() {
			clear(refs.bar);
			refs.note.hidden = true;
			refs.note.classList.remove('is-warn');
			const a = area();
			if (S.view === 'folder') {
				const cr = DS.crumbs(S.folder, a, t);
				const nav = el('nav', { class: 'dv-crumbs', 'aria-label': t('drive.crumbs') });
				cr.forEach((c, i) => {
					if (i) nav.appendChild(el('span', { class: 'dv-crumb-sep', 'aria-hidden': 'true', text: '›' }));
					const b = c.current ? el('span', { class: 'dv-crumb is-current', 'aria-current': 'page', text: c.name }) : el('button', { type: 'button', class: 'dv-crumb', text: c.name, on: { click: () => loadFolder(c.id) } });
					// Drive 1.12: dragged rows go up into a folder above
					if (!c.current && bulkUi) dropTarget(b, () => ({ id: c.id, name: c.name, crumbs: cr.slice(0, i).map((x) => x.id), vault: crumbVault(cr, i), path: c.name }));
					nav.appendChild(b);
				});
				const sort = el('div', { class: 'seg dv-seg', role: 'radiogroup', 'aria-label': t('drive.sort.label') });
				for (const s of DS.SORTS) {
					sort.appendChild(el('button', { type: 'button', role: 'radio', 'aria-checked': S.sort === s ? 'true' : 'false', class: S.sort === s ? 'on' : '', 'data-sort': s, text: t(`drive.sort.${s}`), on: { click: () => setSort(s) } }));
				}
				const fv = S.folder && S.folder.vault;   // Drive 1.9: the vault this folder lies in
				const w = canUpload();
				const tt = S.folder && DS.actionsFor(S.folder.node, w, S.me).timeTravel;
				const vInfo = fv ? vaultOf(fv.id) : null;
				const plus = w ? el('button', { type: 'button', class: 'btn btn-sec btn-sm dv-new', 'aria-haspopup': 'menu', on: { click: (e) => newMenu(e.currentTarget) } }, [icon('plus', 14), el('span', { text: t('drive.new.button') }), icon('chevDown', 13)]) : null;
				refs.bar.append(...[nav, el('span', { class: 'dv-grow' }), sort,
					tt ? el('button', { type: 'button', class: 'dv-ib dv-tt-btn', title: t('drive.tt.menu'), 'aria-label': t('drive.tt.menu'), on: { click: () => timeTravelDialog(S.folder.node) } }, [icon('restore', 16)]) : null,
					fv && fv.state === 'open' && vaultUi ? el('button', { type: 'button', class: 'btn btn-ghost btn-sm dv-vault-devices', on: { click: () => vaultUi.devicesDialog(fv.id, { onRotate: () => vaultUi.rotateDialog(fv.id) }) } }, [icon('device', 14), el('span', { text: t('drive.vault.devices.button') }), vInfo && vInfo.pending ? el('span', { class: 'dv-count', text: String(vInfo.pending) }) : null]) : null,
					fv && fv.state === 'open' && S.lock && S.lock.enforced && api.vault && typeof api.vault.lock === 'function' ? el('button', { type: 'button', class: 'dv-ib dv-vault-lock', title: t('drive.lock.now'), 'aria-label': t('drive.lock.now'), on: { click: () => Promise.resolve(api.vault.lock()).catch(() => {}) } }, [icon('lock', 16)]) : null,
					plus,
					w ? el('button', { type: 'button', class: 'btn btn-pri btn-sm dv-upload', on: { click: pickAndUpload } }, [icon('upload', 14), el('span', { text: t('drive.upload.button') })]) : null].filter(Boolean));
				if (fv && fv.state === 'open') { refs.note.hidden = false; refs.note.textContent = root.GCDriveVaultState.folderNote(vInfo, { t }); refs.note.classList.toggle('is-warn', !!(vInfo && vInfo.needsRotation)); }
				else if (a && a.kind === 'child' && a.via === 'parent') { refs.note.hidden = false; refs.note.textContent = t('drive.childNote'); }
				else if (S.folder && !S.folder.writable) { refs.note.hidden = false; refs.note.textContent = t('drive.readOnly'); }
				refs.sub.textContent = a ? [DS.areaLabel(a, t), DS.usage(a, t, locale())].filter(Boolean).join(' · ') : '';
			} else if (S.view === 'search') {
				refs.bar.append(el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => { refs.search.value = ''; backToFolder(); } } }, [icon('back', 14), el('span', { text: t('drive.back') })]),
					el('span', { class: 'dv-bar-h', text: t('drive.search.title', { q: S.query }) }));
				refs.sub.textContent = t('drive.search.hint');
			} else if (S.view === 'ask' && S.ask) {
				refs.bar.append(el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => { refs.search.value = ''; renderModes(); backToFolder(); } } }, [icon('back', 14), el('span', { text: t('drive.back') })]),
					el('span', { class: 'dv-bar-h', text: t('drive.ki.ask.title', { q: S.ask.q }) }));
				refs.sub.textContent = t('drive.ki.ask.sub');
			} else if (S.view === 'trash') {
				refs.bar.append(el('span', { class: 'dv-bar-h', text: t('drive.trash.title') }));
				const days = S.me && S.me.settings && S.me.settings.trashDays;
				refs.note.hidden = !days;
				if (days) refs.note.textContent = t('drive.trash.info', { n: days });
				refs.sub.textContent = '';
			} else if (VIEWS[S.view]) {
				refs.sub.textContent = '';
			} else if (S.view === 'deadlines') {
				refs.bar.append(el('span', { class: 'dv-bar-h', text: t('drive.deadline.title') }));
				refs.sub.textContent = t('drive.deadline.sub');
			} else if (S.view === 'links') {
				refs.bar.append(el('span', { class: 'dv-bar-h', text: t('drive.links.title') }));
				if (S.links && S.links.enabled === false) { refs.note.hidden = false; refs.note.textContent = t('drive.err.linksDisabled'); }
				refs.sub.textContent = '';
			}
		}

		/** "Name" / "Datum" / "Größe" / "Typ": Drive is asked again only when its order changes ("Typ" is sorted here). */
		function setSort(s) {
			const before = DS.sortQuery(S.sort);
			S.sort = s;
			keep('gc.drive.sort', s);
			if (!S.folder) return;
			const q = DS.sortQuery(s);
			if (q.sort === before.sort && q.order === before.order) render();
			else loadFolder(S.folder.node.id, { quiet: true });
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
			if (S.view === 'deadlines') { if (ki) ki.renderDeadlines(refs.list, { onOpen: docs ? (n) => docs.details(n) : null }); else if (docs) docs.renderDeadlines(refs.list); return; }
			if (S.view === 'ask') { if (ki && S.ask) ki.renderAnswer(refs.list, S.ask); return; }
			// Drive 1.9: a vault folder this PC cannot open yet → its card instead of the (unreadable) list
			const fv = S.view === 'folder' && S.folder && S.folder.vault;
			if (fv && fv.state !== 'open' && vaultUi) {
				refs.list.appendChild(vaultUi.gate(fv.id, fv.state || 'none', { safetyNumber: fv.state === 'pending' && S.vaultStatus && S.vaultStatus.device ? S.vaultStatus.device.safetyNumber : null }));
				return;
			}
			const items = S.view === 'folder' || S.view === 'search' ? shownItems() : (S.trash || []);
			const mode = S.view;
			// Drive 1.12: the selection belongs to the list shown (another folder / search: none); after a reload only
			// what is still there stays selected
			const cbs = selectable();
			if (S.selKey !== selKeyNow()) { S.selKey = selKeyNow(); S.sel = new Set(); S.anchor = null; } else S.sel = BS ? BS.prune(S.sel, items.map((n) => n.id)) : new Set();
			renderSelBar();
			const headCb = cbs && items.length ? el('input', { type: 'checkbox', class: 'dv-cb dv-cb-all', 'aria-label': t('drive.bulk.selectAll'), title: t('drive.bulk.selectAll'), on: { click: (e) => {
				e.stopPropagation();
				const ids = shownItems().map((n) => n.id);
				setSel(BS.headState(S.sel, ids) === 'all' ? new Set() : new Set(ids), null);
			} } }) : null;
			refs.list.appendChild(el('div', { class: `dv-row dv-row-head${cbs ? ' has-cb' : ''}` }, [
				cbs ? el('span', { class: 'dv-c-cb' }, [headCb]) : null,
				el('span', { class: 'dv-c-name', 'aria-hidden': 'true', text: t('drive.col.name') }),
				el('span', { class: 'dv-c-date', 'aria-hidden': 'true', text: t(mode === 'trash' ? 'drive.col.deleted' : 'drive.col.date') }),
				el('span', { class: 'dv-c-size', 'aria-hidden': 'true', text: t('drive.col.size') }),
				el('span', { class: 'dv-c-act' }),
			]));
			if (!items.length) {
				refs.list.appendChild(emptyState(mode === 'search' ? t('drive.search.empty') : mode === 'trash' ? t('drive.trash.empty') : (S.folder && S.folder.writable ? t('drive.emptyWritable') : t('drive.empty'))));
				return;
			}
			for (const n of items) refs.list.appendChild(mode === 'trash' ? trashRow(n) : nodeRow(n, mode, cbs));
			if (S.view === 'folder' && S.folder && S.folder.next) refs.list.appendChild(el('div', { class: 'dv-more', text: t('drive.more', { n: S.folder.total }) }));
			if (cbs) paintSel();
		}

		function nodeRow(n, mode, cbs = false) {
			const v = DS.rowView(n, { t, locale: locale(), now: now(), mode });
			const more = el('button', { type: 'button', class: 'dv-ib dv-more-btn', title: t('drive.actions'), 'aria-label': t('drive.actionsFor', { name: v.name }), 'aria-haspopup': 'menu', on: { click: (e) => { e.stopPropagation(); openMenu(n, more); } } }, [icon('more', 16)]);
			// Drive 1.12: "neu hier" after a move / copy into this folder
			const fresh = BS && S.view === 'folder' && S.folder && BS.isFresh(S.fresh, n, S.folder.node.id, now());
			// the name opens (as before); with Strg / Umschalt it selects
			const main = el('button', { type: 'button', class: 'dv-c-name dv-open', title: v.isDir ? t('drive.openFolder') : t('drive.openFile'), on: { click: (e) => { if (cbs && (e.ctrlKey || e.metaKey || e.shiftKey)) return; openNode(n); } } }, [
				thumb(v),
				el('span', { class: 'dv-name-tx' }, [
					el('span', { class: `dv-name${v.locked ? ' is-locked' : ''}`, text: v.name }),
					v.sub ? el('span', { class: 'dv-row-sub', text: v.sub }) : null,
					// Drive 1.8: the kind of document Drive recognised
					v.doc && root.GCDriveDocsState ? el('span', { class: 'dv-doc', 'data-doc': v.doc }, [icon(root.GCDriveDocsState.docIcon(v.doc), 12), el('span', { text: root.GCDriveDocsState.docKindLabel(v.doc, t) })]) : null,
					v.vault ? el('span', { class: 'dv-doc dv-enc' }, [icon('lock', 12), el('span', { text: t('drive.vault.badge') })]) : null,
					fresh ? el('span', { class: 'dv-new', text: t('drive.bulk.newHere') }) : null,
				]),
			]);
			const cb = cbs ? el('input', { type: 'checkbox', class: 'dv-cb', 'aria-label': t('drive.bulk.selectRow', { name: v.name }), on: { click: (e) => { e.stopPropagation(); checkClick(n, e); } } }) : null;
			const row = el('div', { class: `dv-row${cbs ? ' has-cb' : ''}${v.encrypted ? ' is-enc' : ''}${fresh ? ' is-new' : ''}`, role: 'listitem', 'data-id': String(v.id), draggable: cbs && !v.locked ? 'true' : null }, [
				cbs ? el('span', { class: 'dv-c-cb' }, [cb]) : null,
				main,
				el('span', { class: 'dv-c-date', text: v.date }),
				el('span', { class: 'dv-c-size', text: v.size }),
				el('span', { class: 'dv-c-act' }, [more]),
			]);
			row.addEventListener('contextmenu', (e) => {
				e.preventDefault();
				// in a selection of several: the menu of the selection; else this row is selected and gets its own menu
				if (cbs && S.sel.has(n.id) && S.sel.size > 1) { openSelMenu({ left: e.clientX, top: e.clientY }, more); return; }
				if (cbs) setSel(new Set([n.id]), n.id);
				openMenu(n, more, { left: e.clientX, top: e.clientY });
			});
			if (cbs) {
				// Drive 1.12: a click on the row selects (Strg: one more, Umschalt: a range), a double click opens
				row.addEventListener('click', (e) => {
					if (e.target.closest('.dv-more-btn, .dv-cb')) return;
					if (e.target.closest('.dv-open') && !(e.ctrlKey || e.metaKey || e.shiftKey)) return;
					if (e.shiftKey) e.preventDefault();
					selectClick(n, e);
					main.focus();
				});
				row.addEventListener('dblclick', (e) => { if (!e.target.closest('.dv-open, .dv-more-btn, .dv-cb')) openNode(n); });
				row.addEventListener('mousedown', (e) => { if (e.shiftKey) e.preventDefault(); });
				row.addEventListener('dragstart', (e) => dragStart(n, e));
				if (v.isDir && !v.locked) {
					const crumbIds = S.view === 'folder' && S.folder ? (S.folder.crumbs || []).map((c) => c.id).concat(S.folder.node.id) : [];
					dropTarget(row, () => ({ id: n.id, name: v.name, crumbs: crumbIds, vault: n.encrypted ? n.vaultId || currentVault() : null, path: v.name }));
				}
			}
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
			refs.transfers.hidden = !rows.length || refs.main.hidden || !!VIEWS[S.view];
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
				if (r.dir === 'op') { if (BS) list.appendChild(opRow(r)); continue; }
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

		/** Drive 1.12: a job of the selection in the transfer list (progress, "Abbrechen", "Rückgängig"). */
		function opRow(r) {
			const v = BS.opView(r, { t, locale: locale(), now: now(), errorText: DS.errorText });
			const ic = r.undo ? 'restore' : r.kind === 'copy' ? 'copy' : r.kind === 'trash' || r.kind === 'purge' ? 'trash' : r.kind === 'restore' ? 'restore' : 'move';
			return el('div', { class: `dv-tr is-op ${v.cls}`, 'data-op': String(r.opId) }, [
				el('span', { class: 'dv-tr-ic' }, [icon(ic, 14)]),
				el('div', { class: 'dv-tr-tx' }, [
					el('div', { class: 'dv-tr-top' }, [el('span', { class: 'dv-tr-name', text: v.title }), el('span', { class: 'dv-tr-state', text: v.text })]),
					v.active ? el('div', { class: 'dv-tr-bar', role: 'progressbar', 'aria-label': v.title, 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(v.pct) }, [el('span', { style: `width:${v.pct}%` })]) : null,
					v.server ? el('span', { class: 'dv-tr-note', text: t('drive.bulk.op.server') }) : null,
				]),
				v.cancel && bulkUi ? el('button', { type: 'button', class: 'btn btn-ghost btn-xs dv-op-cancel', text: t('drive.bulk.op.cancel'), on: { click: (e) => { e.currentTarget.disabled = true; bulkUi.cancel(r); } } }) : null,
				v.undo && bulkUi ? el('button', { type: 'button', class: 'btn btn-sec btn-xs dv-op-undo', text: t('drive.bulk.snack.undo'), on: { click: (e) => { e.currentTarget.disabled = true; bulkUi.undo(r); } } }) : null,
			]);
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
				if (S.drag) endDrag();
				if (bulkUi) bulkUi.hideSnack();
				for (const v of Object.values(VIEWS)) if (v) v.hide();
			},
			/** Opens "Ordner sichern" (tray entry, links). */
			openSync: () => { if (syncView) { S.shown = true; openSync(); } },
			refresh: () => reload(),
			status: () => S.status,
			available: () => !!(S.status && S.status.state === 'available'),
			relabel,
			pickFolder: (opts) => pickFolder({ api, t, host, ...(opts || {}) }),
			/**
			 * A push click (Drive 1.8 / 1.9): { kind: 'deadline', nodeId, deadlineId } opens the file's details in its
			 * folder; { kind: 'vault', vaultId, nodeId } the vault (its "Geräte" on a request).
			 */
			async open(context) {
				const c = context && typeof context === 'object' ? context : null;
				S.shown = true;
				if (!S.me) await reload();
				if (!c) return;
				if (c.kind === 'deadline' && docs) {
					const r = await Promise.resolve(api.deadlines()).catch(fail);
					const d = r && r.ok ? r.deadlines.find((x) => (c.deadlineId && x.id === c.deadlineId) || (x.node && x.node.id === c.nodeId)) : null;
					if (!d) { openDeadlines(); return; }
					if (d.node.parentId) await loadFolder(d.node.parentId);
					docs.details(d.node);
				} else if (c.kind === 'vault' && c.nodeId) {
					await loadVaults();
					await loadFolder(c.nodeId);
					if (c.event === 'request' && vaultUi && S.folder && S.folder.vault && S.folder.vault.state === 'open') vaultUi.devicesDialog(c.vaultId, { onRotate: () => vaultUi.rotateDialog(c.vaultId) });
				}
			},
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
