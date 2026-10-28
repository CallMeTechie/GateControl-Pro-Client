/**
 * GateControl -- Drive: AI for documents and deadlines (renderer view)
 *
 * Drive 1.8 'docAi' on the page "Drive" (only while `me` reports the feature):
 * - "Details" of a file: "Erkannt" (Art, Titel, Datum, Absender, Betrag), the
 *   suggestion (a name / a folder) with "Übernehmen", "Erneut erkennen"
 *   (write right), and the file's deadlines, each with "Erinnern N Tage
 *   vorher" (the reminder is the person's own; reading is enough).
 * - "Fristen": the deadlines of every file the person reads (next 30 days,
 *   later, overdue), each opening the file's details.
 *
 * Data: window.gatecontrol.drive (insight, recognize, applyInsight, deadlines,
 * remind); logic: drive-docs-state.js (window.GCDriveDocsState); texts:
 * drive.doc.* / drive.deadline.*. Server text only via textContent.
 */
(function (root) {
	'use strict';

	const DD = root.GCDriveDocsState;

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive
	 * @param {Function} o.t
	 * @param {() => string} o.getLocale
	 * @param {object} o.ui - { el, icon, clear, openDialog } of drive-view.js
	 * @param {HTMLElement} o.host
	 * @param {Function} o.toast
	 * @param {Function} o.errorText - (res, t) → text
	 * @param {(areaId: string) => string} o.areaLabel - the label of an area ("Meine Dateien")
	 * @param {(node) => boolean} o.writable - may the person write where the node lies?
	 * @param {(node) => void} o.openFile - "Öffnen"
	 * @param {() => void} o.changed - something moved / was renamed: the page reloads what it shows
	 * @param {() => number} [o.now]
	 */
	function create(o) {
		const { el, icon, clear, openDialog } = o.ui;
		const t = o.t;
		const now = typeof o.now === 'function' ? o.now : () => Date.now();
		const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed' });

		/** The select "Erinnern N Tage vorher" of a deadline. */
		function reminderSelect(d, onDone) {
			const v = DD.deadlineView(d, { t, locale: o.getLocale(), now: now() });
			const sel = el('select', { class: 'dv-input dv-dl-remind', 'aria-label': t('drive.deadline.remind.label', { what: v.title }) });
			for (const opt of DD.reminderOptions(t)) sel.appendChild(el('option', { value: opt.value, text: opt.label }));
			sel.value = v.value;
			sel.disabled = v.past;
			sel.addEventListener('change', async () => {
				sel.disabled = true;
				const r = await Promise.resolve(o.api.remind(d.id, DD.reminderDays(sel.value))).catch(fail);
				sel.disabled = false;
				if (r && r.ok) {
					Object.assign(d, r.deadline);
					o.toast(DD.reminderDays(sel.value) === null ? t('drive.deadline.remind.off') : t('drive.deadline.remind.set'), 'success');
					if (onDone) onDone(r.deadline);
				} else {
					sel.value = v.value;
					o.toast(o.errorText(r, t), 'error');
				}
			});
			return sel;
		}

		function deadlineRow(d, extra) {
			const v = DD.deadlineView(d, { t, locale: o.getLocale(), now: now() });
			return el('div', { class: `dv-dl${v.urgent ? ' is-urgent' : ''}${v.past ? ' is-past' : ''}`, 'data-deadline': String(d.id) }, [
				el('span', { class: 'dv-row-ic dv-dl-ic' }, [icon('calendar', 16)]),
				el('div', { class: 'dv-dl-tx' }, [
					el('span', { class: 'dv-dl-h' }, [el('b', { text: v.title }), ' ', el('span', { class: 'dv-dl-date', text: `${v.date} · ${v.when}` })]),
					v.label ? el('span', { class: 'dv-row-sub', text: v.label }) : null,
					extra || null,
				]),
				reminderSelect(d, null),
			]);
		}

		/**
		 * "Details" of file `node`: what Drive recognised, its suggestion, its deadlines.
		 */
		function details(node) {
			const dlg = openDialog({ title: t('drive.doc.title', { name: node.name }), host: o.host, wide: true, closeLabel: t('drive.close') });
			dlg.box.classList.add('dv-docs');
			const body = el('div', { class: 'dv-ins' }, [el('div', { class: 'dv-pick-note', text: t('drive.loading') })]);
			const errEl = el('span', { class: 'dv-dlg-err', role: 'alert' });
			dlg.body.appendChild(body);
			const writable = o.writable(node);
			const run = el('button', { type: 'button', class: 'btn btn-sec', hidden: !writable }, [icon('refresh', 14), el('span', { text: t('drive.doc.run') })]);
			const openBtn = el('button', { type: 'button', class: 'btn btn-ghost', text: t('drive.open'), on: { click: () => { dlg.close(null); o.openFile(node); } } });
			dlg.foot.append(errEl, openBtn, run, el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.close'), on: { click: () => dlg.close(null) } }));
			let cur = node;

			function show(ins) {
				clear(body);
				const v = DD.insightView(ins, { t, locale: o.getLocale() });
				body.appendChild(el('h3', { class: 'dv-ins-h', text: t('drive.doc.recognised') }));
				if (v.fields.length) {
					body.appendChild(el('dl', { class: 'dv-ins-grid' }, v.fields.flatMap((f) => [
						el('dt', { text: f.label }),
						el('dd', { 'data-field': f.key }, f.key === 'kind' ? [icon(DD.docIcon(ins.kind), 14), el('span', { text: f.value })] : [el('span', { text: f.value })]),
					])));
				}
				if (v.statusText) body.appendChild(el('p', { class: 'dv-p dv-ins-status', text: v.statusText }));
				const sug = DD.suggestionView(ins, o.areaLabel(cur.areaId), t);
				if (sug && writable) {
					const box = el('div', { class: 'dv-ins-sug' }, [el('span', { class: 'lbl', text: t('drive.doc.suggestion') })]);
					const take = async (what, btn) => {
						btn.disabled = true;
						errEl.textContent = '';
						const r = await Promise.resolve(o.api.applyInsight(cur.id, what)).catch(fail);
						btn.disabled = false;
						if (!r || !r.ok) { errEl.textContent = o.errorText(r, t); return; }
						cur = { ...cur, ...r.node };
						dlg.setTitle(t('drive.doc.title', { name: cur.name }));
						o.toast(t('drive.doc.applied'), 'success');
						o.changed();
						show(r.insight || ins);
					};
					if (sug.name) {
						const b = el('button', { type: 'button', class: 'btn btn-sec btn-sm dv-ins-take', 'data-take': 'name' }, [icon('pen', 14), el('span', { text: t('drive.doc.takeName') })]);
						b.addEventListener('click', () => take({ name: true }, b));
						box.appendChild(el('div', { class: 'dv-ins-row' }, [el('span', { class: 'dv-ins-val', text: sug.name }), b]));
					}
					if (sug.folder) {
						const b = el('button', { type: 'button', class: 'btn btn-sec btn-sm dv-ins-take', 'data-take': 'folder' }, [icon('move', 14), el('span', { text: t('drive.doc.takeFolder') })]);
						b.addEventListener('click', () => take({ folder: true }, b));
						box.appendChild(el('div', { class: 'dv-ins-row' }, [el('span', { class: 'dv-ins-val', text: sug.folderText }), b]));
					}
					if (sug.name && sug.folder) {
						const b = el('button', { type: 'button', class: 'btn btn-pri btn-sm dv-ins-take', 'data-take': 'both', text: t('drive.doc.takeBoth') });
						b.addEventListener('click', () => take({ name: true, folder: true }, b));
						box.appendChild(el('div', { class: 'dv-ins-row is-end' }, [b]));
					}
					body.appendChild(box);
				}
				body.appendChild(el('h3', { class: 'dv-ins-h', text: t('drive.deadline.title') }));
				const dls = Array.isArray(ins && ins.deadlines) ? ins.deadlines : [];
				if (!dls.length) body.appendChild(el('p', { class: 'dv-p', text: t('drive.deadline.none') }));
				for (const d of dls) body.appendChild(deadlineRow(d));
			}

			async function load() {
				const r = await Promise.resolve(o.api.insight(cur.id)).catch(fail);
				if (dlg.closed) return;
				if (!r || !r.ok) { clear(body); body.appendChild(el('div', { class: 'dv-dlg-err', text: o.errorText(r, t) })); return; }
				show(r.insight);
			}
			run.addEventListener('click', async () => {
				run.disabled = true;
				errEl.textContent = '';
				const r = await Promise.resolve(o.api.recognize(cur.id)).catch(fail);
				run.disabled = false;
				if (!r || !r.ok) { errEl.textContent = DD.recognizeError(r, t) || o.errorText(r, t); return; }
				o.toast(t('drive.doc.queued'), 'info');
				show(r.insight);
			});
			load();
			return dlg;
		}

		/**
		 * "Fristen" into `list` (the page's list) → loads GET deadlines and renders the groups; a row opens the file's details.
		 */
		async function renderDeadlines(list, { onOpen } = {}) {
			clear(list);
			list.appendChild(el('div', { class: 'dv-empty', text: t('drive.loading') }));
			const r = await Promise.resolve(o.api.deadlines()).catch(fail);
			clear(list);
			if (!r || !r.ok) {
				list.appendChild(el('div', { class: 'dv-empty' }, [icon('alert', 26, '1.6'), el('span', { text: o.errorText(r, t) })]));
				return r;
			}
			const groups = DD.deadlineGroups(r.deadlines, { t, locale: o.getLocale(), now: now() });
			if (!groups.length) {
				list.appendChild(el('div', { class: 'dv-empty' }, [icon('calendar', 28, '1.6'), el('span', { text: t('drive.deadline.empty') })]));
				return r;
			}
			const byId = new Map(r.deadlines.map((d) => [d.id, d]));
			for (const g of groups) {
				list.appendChild(el('div', { class: 'dv-dl-group lbl', text: g.title }));
				for (const item of g.items) {
					const file = el('button', { type: 'button', class: 'dv-dl-file', title: t('drive.doc.details'), on: { click: () => (onOpen ? onOpen(item.node) : details(item.node)) } }, [icon('file', 13), el('span', { text: item.file })]);
					list.appendChild(deadlineRow(byId.get(item.id), file));
				}
			}
			return r;
		}

		return { details, renderDeadlines };
	}

	root.GCDriveDocsView = { create };
})(typeof self !== 'undefined' ? self : this);
