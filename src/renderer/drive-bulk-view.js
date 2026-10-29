/**
 * GateControl -- Drive: jobs for a selection of many files and folders (renderer view, Drive 1.12)
 *
 * The dialogs and notes of the selection on the page "Drive" (drive-view.js) and in "Fotos" (drive-photos-view.js):
 * - "Ziel wählen" (Verschieben nach … / Kopieren nach …): Verschieben | Kopieren, the areas as chips (read only ones
 *   greyed "(nur ansehen)"), the path, the folders (a selected folder and what lies in it greyed "Wird verschoben –
 *   nicht in sich selbst"), "Neuer Ordner hier", "Zuletzt benutzt" (kept on this PC), "Ziel: …" and "Hierher
 *   verschieben (N)". Inside a vault folder only the same vault (never a vault from outside).
 * - The question for names the target has already, once for all: "Als neue Version speichern" (default) / "Beide
 *   behalten" / "Überspringen" — the same content is never stored twice, folders of the same name are merged. On an
 *   older Drive (no 'bulk') a new version is not possible.
 * - The job itself (core DriveService.opsStart): its progress is a row of the transfer list; when it ends the note at
 *   the bottom "3 Elemente nach „Rechnungen“ verschoben · Rückgängig" (Drive 1.12), new ones get "neu hier".
 * - "Herunterladen (ZIP)" ("Speichern unter …"), "Link teilen" for several files (one link, with validity and PIN).
 *
 * Data: window.gatecontrol.drive (ops, zip, createLink, folder, areas, mkdir); logic: drive-bulk-state.js
 * (window.GCDriveBulkState); texts: drive.bulk.*. Server text only via textContent.
 */
(function (root) {
	'use strict';

	const BS = root.GCDriveBulkState;
	const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed', error: err && err.message });

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive
	 * @param {Function} o.t
	 * @param {() => string} o.getLocale
	 * @param {object} o.ui - { el, icon, clear, openDialog } of drive-view.js
	 * @param {HTMLElement} o.host - dialogs
	 * @param {Function} o.toast
	 * @param {object} o.DS - GCDriveState (errorText, areaLabel, pickerPath, nameError, writableAreas, sortAreas, linkView …)
	 * @param {() => object} o.getMe
	 * @param {() => object[]} o.getAreas
	 * @param {(fresh: object) => void} [o.onFresh] - what a move / copy brought into a folder ("neu hier")
	 * @param {(row: object) => void} [o.onDone] - a job ended (the page reloads what it shows)
	 * @param {(text: string) => void} [o.copyText] - into the clipboard
	 * @param {() => number} [o.now]
	 */
	function create(o) {
		const { el, icon, clear, openDialog } = o.ui;
		const api = o.api;
		const t = o.t;
		const DS = o.DS;
		const now = typeof o.now === 'function' ? o.now : () => Date.now();
		const locale = () => o.getLocale();
		const toast = typeof o.toast === 'function' ? o.toast : () => {};
		const host = o.host || document.body;
		const store = (() => { try { return root.localStorage || null; } catch { return null; } })();
		const jobs = new Map();   // job id → { ids, names, targetId } (for "neu hier")
		let uid = 0;
		const nextId = (p) => `${p}-${++uid}`;
		const has = (f) => DS.hasFeature(o.getMe(), f);

		// ── the note at the bottom ("… verschoben · Rückgängig") ─
		const snackText = el('span', { class: 'dv-snack-tx' });
		const snackBtn = el('button', { type: 'button', class: 'dv-snack-act', hidden: true });
		const snackClose = el('button', { type: 'button', class: 'dv-snack-x', 'aria-label': t('drive.close'), title: t('drive.close') }, [icon('close', 14)]);
		const snack = el('div', { class: 'dv-snack', role: 'status', 'aria-live': 'polite', hidden: true }, [snackText, snackBtn, snackClose]);
		let snackTimer = null;
		let snackRow = null;
		snackClose.addEventListener('click', () => hideSnack());
		snackBtn.addEventListener('click', async () => {
			const row = snackRow;
			hideSnack();
			if (!row) return;
			const r = await Promise.resolve(api.ops.undo(row.opId)).catch(fail);
			if (!r || !r.ok) toast(undoError(r), 'error');
		});

		/** "Rückgängig" refused: 409 conflict { reason: expired | undone | running | nothing } */
		function undoError(r) {
			if (r && (r.reason === 'expired' || r.reason === 'undone')) return t('drive.bulk.snack.undoExpired');
			if (r && r.reason === 'running') return t('drive.bulk.snack.undoRunning');
			if (r && r.reason === 'nothing') return t('drive.bulk.snack.undoNothing');
			return DS.errorText(r, t);
		}

		/** A job refused: the limits of Drive 1.12 (413 too_large: too many nodes) */
		const jobError = (r) => (r && r.code === 'too_large' ? t('drive.err.tooMany') : DS.errorText(r, t));

		function showSnack(row) {
			const v = BS.snackView(row, { t, now: now() });
			if (!v) return;
			clearTimeout(snackTimer);
			snackRow = v.undo ? row : null;
			snackText.textContent = v.text;
			snackBtn.textContent = t('drive.bulk.snack.undo');
			snackBtn.hidden = !v.undo;
			snack.classList.toggle('is-warn', v.warn);
			snack.hidden = false;
			snackTimer = setTimeout(hideSnack, BS.snackMs(row, now()));
		}

		function hideSnack() {
			clearTimeout(snackTimer);
			snackTimer = null;
			snackRow = null;
			snack.hidden = true;
		}

		if (typeof api.onOp === 'function') {
			api.onOp((row) => {
				if (!row || typeof row !== 'object') return;
				const job = jobs.get(row.opId);
				const fresh = BS.freshOf(job, row, now());
				if (fresh && typeof o.onFresh === 'function') o.onFresh(fresh);
				if (row.state === 'failed') toast(t('drive.bulk.op.failed', { reason: DS.errorText({ code: row.code || 'failed' }, t) }), 'error');
				else showSnack(row);
				if (typeof o.onDone === 'function') o.onDone(row);
			});
		}

		// ── "Ziel wählen" ─────────────────────────────────

		/**
		 * @param {object} p
		 * @param {object[]} p.items - the nodes
		 * @param {'move'|'copy'} p.mode
		 * @param {string} [p.from] - the name of the folder they come from
		 * @param {number} [p.startId] - the folder to start in
		 * @param {string|null} [p.vault] - the vault they lie in (only that vault can be the target)
		 * @param {boolean} [p.canMove] / [p.canCopy] / [p.lockMode]
		 * @returns {Promise<{ folderId, path, name, mode } | null>}
		 */
		function targetDialog(p) {
			const items = p.items || [];
			const n = items.length;
			const vault = p.vault || null;
			return new Promise((resolve) => {
				const T = { mode: p.mode === 'copy' ? 'copy' : 'move', areas: [], folder: null, area: null, loading: true, error: null };
				const dlg = openDialog({ title: t('drive.bulk.target.title'), host, wide: true, closeLabel: t('drive.close'), onClose: (v) => resolve(v || null) });
				dlg.box.classList.add('dv-target');
				const subText = n === 1 && items[0]
					? (p.from ? t('drive.bulk.target.fromOne', { name: items[0].name, folder: p.from }) : t('drive.bulk.target.one', { name: items[0].name }))
					: (p.from ? DS.plural(t, 'drive.bulk.target.from', n, { folder: p.from }) : DS.plural(t, 'drive.bulk.target.count', n));
				const sub = el('span', { class: 'dv-target-sub', text: subText });
				const head = dlg.box.querySelector('.dv-dlg-head .dv-dlg-h');
				if (head) head.after(sub);
				const seg = el('div', { class: 'seg dv-seg dv-target-mode', role: 'radiogroup', 'aria-label': t('drive.bulk.target.mode') });
				const chips = el('div', { class: 'dv-target-chips', role: 'group', 'aria-label': t('drive.areas') });
				const path = el('nav', { class: 'dv-pick-path dv-target-path', 'aria-label': t('drive.crumbs') });
				const list = el('div', { class: 'dv-pick-list', role: 'list' });
				const recentBox = el('div', { class: 'dv-target-recent' });
				const err = el('span', { class: 'dv-dlg-err', role: 'alert' });
				const where = el('span', { class: 'dv-target-to' });
				const ok = el('button', { type: 'button', class: 'btn btn-pri dv-target-ok', on: { click: () => pick() } });
				// "Neuer Ordner hier"
				const nfInput = el('input', { type: 'text', class: 'dv-input', maxlength: '255', spellcheck: 'false', 'aria-label': t('drive.name.label'), placeholder: t('drive.picker.newName') });
				const nfErr = el('span', { class: 'dv-field-err', role: 'alert' });
				const nfOk = el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.create'), on: { click: () => makeFolder() } });
				const nfRow = el('div', { class: 'dv-pick-new', hidden: true }, [nfInput, nfOk, nfErr]);
				nfInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); makeFolder(); } else if (e.key === 'Escape') { e.stopPropagation(); nfRow.hidden = true; } });
				nfInput.addEventListener('input', () => { nfErr.textContent = nfInput.value ? (DS.nameError(nfInput.value, t) || '') : ''; });
				dlg.body.append(seg, chips, path, nfRow, list, recentBox);
				dlg.foot.append(where, el('span', { class: 'dv-grow' }), err, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), ok);

				const crumbIds = () => (T.folder ? (T.folder.crumbs || []).map((c) => c.id).concat(T.folder.node.id) : []);
				const pathText = () => (T.folder ? DS.pickerPath(T.folder, T.area, t) : '');

				async function makeFolder() {
					if (!T.folder || !T.folder.writable) return;
					const e = DS.nameError(nfInput.value, t);
					if (e) { nfErr.textContent = e; return; }
					nfOk.disabled = true;
					const r = await Promise.resolve(api.mkdir(T.folder.node.id, nfInput.value.trim())).catch(fail);
					nfOk.disabled = false;
					if (!r || !r.ok) { nfErr.textContent = DS.errorText(r, t); return; }
					nfRow.hidden = true;
					await browse(r.node.id);
				}

				function pick() {
					const v = BS.targetOk(T.folder, items, { mode: T.mode, vault });
					if (!v.ok) return;
					const pth = pathText();
					try { if (store && !vault) store.setItem(BS.RECENT_KEY, BS.pushRecent(BS.parseRecent(store.getItem(BS.RECENT_KEY)), T.folder.node.id, pth)); } catch { /* private */ }
					const name = T.folder.node.parentId ? T.folder.node.name : DS.areaLabel(T.area, t) || T.folder.node.name;
					dlg.close({ folderId: T.folder.node.id, path: pth, name, mode: T.mode });
				}

				async function browse(id) {
					T.loading = true;
					render();
					const r = await Promise.resolve(api.folder(id, { limit: 1000 })).catch(fail);
					T.loading = false;
					if (r && r.ok) {
						T.folder = r;
						T.area = T.areas.find((a) => a.id === r.node.areaId) || null;
						T.error = null;
					} else {
						T.error = DS.errorText(r, t);
					}
					render();
				}

				function render() {
					// Verschieben | Kopieren
					clear(seg);
					for (const m of ['move', 'copy']) {
						const allowed = m === 'move' ? p.canMove !== false : p.canCopy !== false;
						seg.appendChild(el('button', {
							type: 'button', role: 'radio', 'aria-checked': T.mode === m ? 'true' : 'false', class: T.mode === m ? 'on' : '', 'data-mode': m,
							disabled: !allowed || null, title: !allowed ? t(m === 'copy' ? (vault ? 'drive.bulk.why.vault' : 'drive.bulk.why.needs112') : 'drive.bulk.why.readOnly') : null,
							text: t(`drive.bulk.target.${m}`), on: { click: () => { T.mode = m; render(); } },
						}));
					}
					// the areas (not inside a vault: the vault's folders only)
					clear(chips);
					chips.hidden = !!vault;
					if (!vault) {
						for (const a of DS.sortAreas(T.areas)) {
							const w = !!(a.writable && !a.archived);
							const on = T.area && T.area.id === a.id;
							chips.appendChild(el('button', {
								type: 'button', class: `dv-chip${on ? ' is-on' : ''}`, disabled: !w || null, 'aria-pressed': on ? 'true' : 'false', 'data-area': a.id,
								text: w ? DS.areaLabel(a, t) : t('drive.bulk.target.readOnlyArea', { name: DS.areaLabel(a, t) }),
								on: { click: () => browse(a.rootId) },
							}));
						}
					}
					// the path: every part above opens that folder
					clear(path);
					const cr = T.folder ? DS.crumbs(T.folder, T.area, t) : [];
					const vaultTop = vault ? cr.findIndex((c) => c.id === p.vaultRoot) : -1;
					cr.forEach((c, i) => {
						if (vault && vaultTop >= 0 && i < vaultTop) return;
						if (path.firstChild) path.appendChild(el('span', { class: 'dv-crumb-sep', 'aria-hidden': 'true', text: '›' }));
						path.appendChild(c.current ? el('span', { class: 'dv-crumb is-current', text: c.name }) : el('button', { type: 'button', class: 'dv-crumb', text: c.name, on: { click: () => browse(c.id) } }));
					});
					// the folders
					clear(list);
					err.textContent = T.error || '';
					if (T.loading && !T.folder) {
						list.appendChild(el('div', { class: 'dv-pick-note', text: t('drive.loading') }));
					} else if (T.folder) {
						const parent = cr.length > 1 && !(vault && T.folder.node.id === p.vaultRoot) ? cr[cr.length - 2].id : null;
						if (parent) {
							list.appendChild(el('button', { type: 'button', class: 'dv-pick-row is-back', on: { click: () => browse(parent) } }, [
								el('span', { class: 'dv-pick-ic' }, [icon('back', 16)]),
								el('span', { class: 'dv-pick-name', text: t('drive.picker.up') }),
							]));
						}
						const ids = crumbIds();
						const subs = (T.folder.items || []).filter((x) => x && x.isDir && (vault ? x.encrypted && !x.locked : !x.encrypted));
						if (!subs.length) list.appendChild(el('div', { class: 'dv-pick-note', text: t('drive.picker.noFolders') }));
						for (const x of subs) {
							const r = BS.targetRow(x, items, { mode: T.mode, crumbIds: ids });
							list.appendChild(el('button', { type: 'button', role: 'listitem', class: 'dv-pick-row', 'data-node': String(x.id), disabled: r.disabled || null, on: { click: () => browse(x.id) } }, [
								el('span', { class: 'dv-pick-ic' }, [icon('folder', 16)]),
								el('span', { class: 'dv-pick-tx' }, [el('span', { class: 'dv-pick-name', text: x.name }), r.sub ? el('span', { class: 'dv-pick-sub', text: t(r.sub) }) : null]),
								icon('chevron', 14),
							]));
						}
						if (T.folder.writable) {
							list.appendChild(el('button', { type: 'button', class: 'dv-pick-row dv-target-new', on: { click: () => { nfRow.hidden = !nfRow.hidden; if (!nfRow.hidden) { nfInput.value = ''; nfErr.textContent = ''; nfInput.focus(); } } } }, [
								el('span', { class: 'dv-pick-ic' }, [icon('plus', 16)]),
								el('span', { class: 'dv-pick-name', text: t('drive.bulk.target.newFolder') }),
							]));
						}
					}
					// "Zuletzt benutzt"
					clear(recentBox);
					let recent = [];
					try { recent = vault || !store ? [] : BS.parseRecent(store.getItem(BS.RECENT_KEY)); } catch { recent = []; }
					if (recent.length) {
						recentBox.append(el('span', { class: 'lbl', text: t('drive.bulk.target.recent') }), el('div', { class: 'dv-target-chips' }, recent.map((x) => el('button', { type: 'button', class: 'dv-chip', title: x.path, text: BS.shortPath(x.path), on: { click: () => browse(x.id) } }))));
					}
					// "Ziel: …" and "Hierher verschieben (N)"
					const v = BS.targetOk(T.folder, items, { mode: T.mode, vault });
					where.textContent = T.folder ? t('drive.bulk.target.to', { path: pathText() }) : '';
					if (!v.ok && v.why && T.folder) where.textContent = `${where.textContent} · ${t(v.why)}`;
					ok.textContent = t(T.mode === 'copy' ? 'drive.bulk.target.copyHere' : 'drive.bulk.target.moveHere', { count: n });
					ok.disabled = !v.ok || T.loading;
				}

				(async () => {
					const areas = await Promise.resolve(api.areas()).catch(fail);
					T.areas = areas && areas.ok ? areas.areas : (o.getAreas() || []);
					if (!(areas && areas.ok)) T.error = DS.errorText(areas, t);
					let start = p.startId || null;
					if (!start) {
						const w = DS.writableAreas(T.areas);
						start = w.length ? w[0].rootId : null;
					}
					if (start) await browse(start);
					else { T.loading = false; render(); }
				})();
			});
		}

		// ── names the target has already ─────────────────

		/** → 'version' | 'rename' | 'skip' | null (cancelled) */
		function conflictDialog(check, { mode, target, local = false }) {
			return new Promise((resolve) => {
				const v = BS.conflictView(check, { t, locale: locale(), now: now(), mode, target, when: DS.when });
				const dlg = openDialog({ title: v.title, host, closeLabel: t('drive.close'), onClose: (x) => resolve(x || null) });
				dlg.box.classList.add('dv-conflict');
				let choice = local ? 'rename' : 'version';
				const name = nextId('dv-cf');
				const opt = (value, label, subText, disabled) => {
					const input = el('input', { type: 'radio', name, value, disabled: disabled || null });
					input.checked = choice === value;
					input.addEventListener('change', () => { if (input.checked) { choice = value; paint(); } });
					return el('label', { class: 'dv-choice', 'data-choice': value }, [input, el('span', { class: 'dv-choice-tx' }, [el('span', { class: 'dv-choice-h', text: label }), el('span', { class: 'dv-choice-sub', text: subText })])]);
				};
				const opts = [
					opt('version', t('drive.bulk.conflict.version'), local ? t('drive.bulk.why.needs112') : t('drive.bulk.conflict.versionSub'), local),
					opt('rename', t('drive.bulk.conflict.rename'), t('drive.bulk.conflict.renameSub', { example: v.renameExample })),
					opt('skip', t('drive.bulk.conflict.skip'), v.skipText),
				];
				const paint = () => { for (const l of opts) l.classList.toggle('is-on', l.getAttribute('data-choice') === choice); };
				paint();
				dlg.body.append(...[
					el('p', { class: 'dv-p', text: v.intro }),
					el('ul', { class: 'dv-cf-list' }, v.rows.map((r) => el('li', {}, [el('span', { class: 'dv-cf-name', text: r.name }), el('span', { class: 'dv-cf-sub', text: r.text })]))),
					v.more ? el('span', { class: 'dv-pick-note', text: v.more }) : null,
					v.merges ? el('span', { class: 'dv-pick-note', text: v.merges }) : null,
					el('fieldset', { class: 'dv-choices' }, [el('legend', { class: 'lbl', text: t('drive.bulk.conflict.question') }), ...opts]),
					el('div', { class: 'dv-cf-hint' }, [icon('check', 14), el('span', { text: v.sameText })]),
					check.blocked && check.blocked.length ? el('div', { class: 'dv-note is-warn', text: BS.blockedText(check.blocked, t) }) : null,
				].filter(Boolean));
				dlg.foot.append(
					el('span', { class: 'dv-grow' }),
					el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }),
					el('button', { type: 'button', class: 'btn btn-pri dv-cf-ok', text: t(mode === 'copy' ? 'drive.bulk.target.copy' : 'drive.bulk.target.move'), on: { click: () => dlg.close(choice) } }),
				);
			});
		}

		// ── a job ─────────────────────────────────────────

		/**
		 * Verschieben / Kopieren / In den Papierkorb for `items`: (target dialog) → check → (the question) → the job.
		 * @param {object} p - { op: 'move'|'copy'|'trash', items, target?: { folderId, path, name }, from?, startId?, vault?,
		 *   vaultRoot?, canMove?, canCopy?, confirm?: boolean (trash: ask first — an older Drive has no "Rückgängig") }
		 * @returns {Promise<object|null>} the job's row once started
		 */
		async function run(p) {
			const items = (p.items || []).filter(Boolean);
			if (!items.length) return null;
			let op = p.op;
			let target = p.target || null;
			if ((op === 'move' || op === 'copy') && !target) {
				target = await targetDialog({ items, mode: op, from: p.from, startId: p.startId, vault: p.vault || null, vaultRoot: p.vaultRoot || null, canMove: p.canMove, canCopy: p.canCopy });
				if (!target) return null;
				op = target.mode;
			}
			if (op === 'copy' && !(has('bulk') && has('copyServer'))) { toast(t(has('bulk') ? 'drive.bulk.why.needsGc' : 'drive.bulk.why.needs112'), 'error'); return null; }
			if (op === 'trash' && p.confirm) {
				const yes = await confirmTrash(items);
				if (!yes) return null;
			}
			const ids = items.map((x) => x.id);
			const check = await Promise.resolve(api.ops.check(op, ids, target ? target.folderId : null)).catch(fail);
			if (!check || !check.ok) { toast(jobError(check), 'error'); return null; }
			if (check.tooMany) { toast(t('drive.err.tooMany'), 'error'); return null; }
			if (check.quota && check.quota.free !== null && check.quota.free !== undefined && check.quota.needed > check.quota.free) { toast(t('drive.err.quota'), 'error'); return null; }
			const blocked = new Set((check.blocked || []).map((b) => b.id));
			const go = items.filter((x) => !blocked.has(x.id));
			if (!go.length) { toast(BS.blockedText(check.blocked, t), 'error'); return null; }
			let onConflict = null;
			const conflicts = (check.conflicts || []).filter((c) => !blocked.has(c.id));
			if (conflicts.length) {
				const asked = { ...check, conflicts };
				if (BS.conflictView(asked, { t, locale: locale(), mode: op, target: target ? target.name : '' }).ask) {
					onConflict = await conflictDialog(asked, { mode: op, target: target ? target.name : '', local: !!check.local });
					if (!onConflict) return null;
				} else {
					onConflict = check.local ? 'skip' : 'version';
				}
			} else if (blocked.size) {
				toast(BS.blockedText(check.blocked, t), 'info');
			}
			const parents = [...new Set(go.map((x) => x.parentId).filter(Boolean))];
			const meta = { name: go[0].name, count: go.length, target: target ? target.name : null, parents };
			const r = await Promise.resolve(api.ops.start(op, go.map((x) => x.id), { target: target ? target.folderId : null, onConflict, meta })).catch(fail);
			if (!r || !r.ok) { toast(jobError(r), 'error'); return null; }
			jobs.set(r.op.opId, { ids: go.map((x) => x.id), names: go.map((x) => x.name), targetId: target ? target.folderId : null });
			while (jobs.size > 50) jobs.delete(jobs.keys().next().value);
			return r.op;
		}

		function confirmTrash(items) {
			return new Promise((resolve) => {
				const dlg = openDialog({ title: DS.plural(t, 'drive.bulk.trashConfirm', items.length), host, closeLabel: t('drive.close'), onClose: (v) => resolve(!!v) });
				dlg.body.append(el('p', { class: 'dv-p', text: t(items.some((x) => x.isDir) ? 'drive.removeFolderText' : 'drive.removeText') }));
				dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(false) } }), el('button', { type: 'button', class: 'btn btn-danger', text: t('drive.remove'), on: { click: () => dlg.close(true) } }));
			});
		}

		/** "Herunterladen (ZIP)": "Speichern unter …" (name: the folder of one, else of the folder shown) → toast */
		async function zip(items, name) {
			if (!has('zip')) { toast(t('drive.bulk.why.needs112'), 'error'); return; }
			const r = await Promise.resolve(api.zip(items.map((x) => x.id), name || (items.length === 1 ? items[0].name.replace(/\.[^.]+$/, '') : null))).catch(fail);
			if (r && r.ok) toast(t('drive.saved', { path: r.path }), 'success');
			else if (r && (r.reason === 'mixed' || r.reason === 'too_many')) toast(t('drive.bulk.why.zipLimit'), 'error');
			else if (!r || !r.cancelled) toast(DS.errorText(r, t), 'error');
		}

		/** "Link teilen" for several files: one link with validity and PIN (Drive 1.12 'multiLink'). */
		function linkDialog(items) {
			const dlg = openDialog({ title: DS.plural(t, 'drive.bulk.linkTitle', items.length), host, wide: true, closeLabel: t('drive.close') });
			const draft = { mode: 'view', expires: '7d', pin: '' };
			const form = el('div', { class: 'dv-share' });
			const result = el('div', { class: 'dv-share-result', hidden: true });
			const errEl = el('span', { class: 'dv-dlg-err', role: 'alert' });
			const create = el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.share.create') });
			const seg = (label, values, key, textOf) => {
				const s = el('div', { class: 'seg dv-seg', role: 'radiogroup', 'aria-label': label });
				const draw = () => {
					clear(s);
					for (const v of values) s.appendChild(el('button', { type: 'button', role: 'radio', 'aria-checked': draft[key] === v ? 'true' : 'false', class: draft[key] === v ? 'on' : '', text: textOf(v), on: { click: () => { draft[key] = v; draw(); } } }));
				};
				draw();
				return el('div', { class: 'dv-share-row' }, [el('span', { class: 'lbl', text: label }), s]);
			};
			const pinId = nextId('dv-pin');
			const pin = el('input', { id: pinId, type: 'text', inputmode: 'numeric', class: 'dv-input dv-pin', maxlength: '12', placeholder: t('drive.share.pinPlaceholder'), autocomplete: 'off', on: { input: () => { draft.pin = pin.value; errEl.textContent = DS.pinOk(pin.value) ? '' : t('drive.share.pinInvalid'); create.disabled = !DS.pinOk(pin.value); } } });
			form.append(...[
				el('ul', { class: 'dv-cf-list dv-link-names' }, items.slice(0, 6).map((x) => el('li', {}, [el('span', { class: 'dv-cf-name', text: x.name })]))),
				items.length > 6 ? el('span', { class: 'dv-pick-note', text: t('drive.bulk.conflict.more', { count: items.length - 6 }) }) : null,
				seg(t('drive.share.who'), ['view', 'download'], 'mode', (m) => t(`drive.link.mode.${m}`)),
				seg(t('drive.share.valid'), DS.LINK_EXPIRES, 'expires', (x) => t(`drive.share.expires.${x}`)),
				el('div', { class: 'dv-share-row' }, [el('label', { class: 'lbl', for: pinId, text: t('drive.share.pin') }), pin]),
			].filter(Boolean));
			create.addEventListener('click', async () => {
				if (!DS.pinOk(draft.pin)) { errEl.textContent = t('drive.share.pinInvalid'); return; }
				create.disabled = true;
				const r = await Promise.resolve(api.createLink({ ids: items.map((x) => x.id), mode: draft.mode, expires: draft.expires, pin: draft.pin || null })).catch(fail);
				create.disabled = false;
				if (!r || !r.ok) { errEl.textContent = r && r.reason === 'mixed' ? t('drive.bulk.why.mixed') : r && r.reason === 'too_many' ? t('drive.bulk.why.linkLimit') : DS.errorText(r, t); return; }
				errEl.textContent = '';
				clear(result);
				result.hidden = false;
				const url = el('input', { type: 'text', class: 'dv-input dv-url', readonly: true, value: r.link.url || '', 'aria-label': t('drive.share.url') });
				url.addEventListener('focus', () => url.select());
				result.append(...[
					el('div', { class: 'dv-share-ok' }, [icon('check', 16), el('span', { text: t('drive.share.created') })]),
					el('div', { class: 'dv-share-urlrow' }, [url, el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => { if (typeof o.copyText === 'function') o.copyText(r.link.url); } } }, [icon('copy', 14), el('span', { text: t('drive.share.copy') })])]),
					draft.pin ? el('span', { class: 'dv-pick-note', text: t('drive.share.pinNote') }) : null,
				].filter(Boolean));
			});
			dlg.body.append(form, result);
			dlg.foot.append(errEl, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.close'), on: { click: () => dlg.close(null) } }), create);
		}

		/** "Abbrechen" of a running job (transfer list). */
		async function cancel(row) {
			const r = await Promise.resolve(api.ops.cancel(row.opId)).catch(fail);
			if (!r || !r.ok) toast(DS.errorText(r, t), 'error');
		}

		/** "Rückgängig" of a job that ended (transfer list). */
		async function undo(row) {
			hideSnack();
			const r = await Promise.resolve(api.ops.undo(row.opId)).catch(fail);
			if (!r || !r.ok) toast(undoError(r), 'error');
		}

		return { el: snack, run, targetDialog, conflictDialog, zip, linkDialog, cancel, undo, hideSnack, showSnack };
	}

	root.GCDriveBulkView = { create };
})(typeof self !== 'undefined' ? self : this);
