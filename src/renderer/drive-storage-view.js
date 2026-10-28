/**
 * GateControl -- Drive "Speicher" (renderer view, part of the page Drive)
 *
 * Drive 1.7 'storage': how much Drive takes – in all and per area (files,
 * older versions, trash; the limit of the storage and of an area), per
 * person for administrators ("Alle": every area of the server), the 20
 * largest files ("Im Ordner zeigen", "In den Papierkorb") and the
 * duplicates (same content and size): the copies to remove are ticked
 * ("Vorschlag": all but the oldest one; one copy of each group always
 * stays) and go into the trash after a question.
 *
 * Mounted by drive-view.js (el / icon / clear / openDialog, me, the areas,
 * opening a folder). Data: window.gatecontrol.drive; texts:
 * drive.storage.*; view logic without DOM: drive-storage-state.js
 * (window.GCDriveStorageState). Server text only ever goes into
 * textContent / attributes.
 */
(function (root) {
	'use strict';

	const SS = root.GCDriveStorageState;
	const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed', error: err && err.message });

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive
	 * @param {Function} o.t
	 * @param {Function} o.getLocale
	 * @param {Function} [o.toast]
	 * @param {HTMLElement} [o.host]
	 * @param {object} o.ui - { el, icon, clear, openDialog }
	 * @param {() => object} o.getMe
	 * @param {() => object[]} o.getAreas
	 * @param {Function} o.areaLabel - GCDriveState.areaLabel
	 * @param {Function} o.errorText - GCDriveState.errorText
	 * @param {Function} o.formatBytes - GCDriveState.formatBytes
	 * @param {(folderId: number) => void} o.openFolder
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const { el, icon, clear, openDialog } = o.ui;
		const locale = () => o.getLocale();
		const toast = typeof o.toast === 'function' ? o.toast : () => {};
		const host = o.host || document.body;
		const fmt = (n) => o.formatBytes(n || 0, locale());
		const err = (r) => o.errorText(r, t);
		const pl = (key, n, params) => t(`${key}.${Number(n) === 1 ? 'one' : 'other'}`, { ...(params || {}), count: Number(n) || 0 });
		const S = { shown: false, all: false, data: null, loading: false, error: null, sel: new Set(), seq: 0 };

		const wrap = el('div', { class: 'dsg', hidden: true });
		const head = el('div', { class: 'dsv-head' });
		const body = el('div', { class: 'dsg-body' });
		wrap.append(head, body);

		const isAdmin = () => { const me = o.getMe(); return !!(me && me.me && me.me.admin); };

		async function load() {
			const seq = ++S.seq;
			S.loading = !S.data;
			S.error = null;
			render();
			const r = await Promise.resolve(api.storage(S.all && isAdmin())).catch(fail);
			if (seq !== S.seq) return;
			S.loading = false;
			if (r && r.ok) {
				S.data = r;
				const ids = new Set(r.duplicates.flatMap((g) => g.items.map((i) => i.id)));
				S.sel = new Set([...S.sel].filter((id) => ids.has(id)));
			} else {
				S.error = r;
				// "Alle" refused (no administrator any more): back to one's own areas
				if (S.all && r && r.code === 'forbidden') S.all = false;
			}
			render();
		}

		function renderHead() {
			clear(head);
			head.append(el('div', { class: 'dsv-head-tx' }, [
				el('h2', { class: 'dsv-h', text: t('drive.storage.title') }),
				el('p', { class: 'dv-p', text: t(S.all ? 'drive.storage.introAll' : 'drive.storage.intro') }),
			]));
			if (isAdmin()) {
				const seg = el('div', { class: 'seg dv-seg', role: 'radiogroup', 'aria-label': t('drive.storage.scope') });
				for (const v of [false, true]) {
					seg.appendChild(el('button', { type: 'button', role: 'radio', 'aria-checked': S.all === v ? 'true' : 'false', class: S.all === v ? 'on' : '', text: t(v ? 'drive.storage.all' : 'drive.storage.mine'), on: { click: () => { if (S.all === v) return; S.all = v; S.data = null; S.sel = new Set(); load(); } } }));
				}
				head.appendChild(seg);
			}
			head.appendChild(el('button', { type: 'button', class: 'dv-ib', title: t('drive.refresh'), 'aria-label': t('drive.refresh'), on: { click: () => load() } }, [icon('refresh', 16)]));
		}

		function bar(pct, cls = '') {
			return el('div', { class: `dsg-bar ${cls}`, role: 'presentation' }, [el('span', { style: `width:${Math.max(0, Math.min(100, Number(pct) || 0))}%` })]);
		}

		function card(title, kids, extra) {
			return el('section', { class: 'card dsv-card' }, [
				el('div', { class: 'dsv-card-head' }, [el('div', { class: 'dsv-card-tx' }, [el('h3', { class: 'dsv-card-h', text: title }), extra ? el('span', { class: 'dv-p', text: extra }) : null])]),
				...kids,
			]);
		}

		function render() {
			if (!S.shown) return;
			renderHead();
			clear(body);
			if (S.loading) { body.appendChild(el('div', { class: 'dv-empty', text: t('drive.loading') })); return; }
			if (S.error && !S.data) {
				body.appendChild(el('div', { class: 'dv-empty' }, [icon('alert', 26, '1.6'), el('span', { text: err(S.error) }), el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.retry'), on: { click: () => load() } })]));
				return;
			}
			if (!S.data) return;
			const d = S.data;
			const tv = SS.totalView(d, { t, fmt });
			body.appendChild(card(t('drive.storage.total'), [
				el('div', { class: 'dsg-total' }, [
					el('span', { class: 'dsg-big', text: tv.used }),
					el('span', { class: 'dv-p', text: tv.of ? t('drive.storage.ofLimit', { limit: tv.of, pct: tv.pct }) : tv.files }),
				]),
				tv.pct !== null ? bar(tv.pct, tv.pct >= 90 ? 'is-err' : tv.pct >= 75 ? 'is-warn' : '') : null,
				el('div', { class: 'dsg-parts' }, tv.parts.map((p) => el('div', { class: `dsg-part is-${p.key}` }, [el('span', { class: 'dsg-dot' }), el('span', { class: 'dsg-part-l', text: p.label }), el('b', { text: p.text })]))),
				tv.of ? el('div', { class: 'dsg-foot dv-p', text: tv.files }) : null,
			]));

			const areaRows = SS.barsView(d.areas, { t, fmt, areaLabel: o.areaLabel });
			body.appendChild(card(t('drive.storage.areas'), areaRows.length ? areaRows.map((r, i) => {
				const a = d.areas[i];
				return el('div', { class: 'dsg-row', 'data-area': a.id }, [
					el('div', { class: 'dsg-row-tx' }, [el('span', { class: 'dsg-name', text: r.label }), el('span', { class: 'dsg-sub', text: r.sub })]),
					el('div', { class: 'dsg-row-end' }, [
						SS.canPrune(a) ? el('button', { type: 'button', class: 'btn btn-ghost btn-xs dsg-prune', text: t('drive.storage.prune'), on: { click: () => pruneDialog(a, r.label) } }) : null,
						el('span', { class: 'dsg-val', text: r.text }),
					]),
					bar(r.pct),
				]);
			}) : [el('div', { class: 'dsv-empty', text: t('drive.storage.none') })]));

			if (d.people && d.people.length) {
				body.appendChild(card(t('drive.storage.people'), SS.barsView(d.people, { t, fmt }).map((r) => el('div', { class: 'dsg-row' }, [
					el('div', { class: 'dsg-row-tx' }, [el('span', { class: 'dsg-name', text: r.label }), el('span', { class: 'dsg-sub', text: r.sub })]),
					el('span', { class: 'dsg-val', text: r.text }),
					bar(r.pct),
				]))));
			}

			const areas = o.getAreas();
			body.appendChild(card(t('drive.storage.largest'), d.largest.length ? d.largest.map((f) => el('div', { class: 'dsg-file', 'data-id': String(f.id) }, [
				el('div', { class: 'dsg-row-tx' }, [el('span', { class: 'dsg-name', text: f.name }), el('span', { class: 'dsg-sub', text: SS.placeOf(f, areas, o.areaLabel, t) })]),
				el('span', { class: 'dsg-val', text: fmt(f.size) }),
				el('div', { class: 'dsv-acts' }, [
					f.parentId ? el('button', { type: 'button', class: 'dv-ib dsv-act', title: t('drive.search.showFolder'), 'aria-label': t('drive.search.showFolder'), on: { click: () => o.openFolder(f.parentId) } }, [icon('folder', 15)]) : null,
					canTrash(f) ? el('button', { type: 'button', class: 'dv-ib dsv-act dv-danger', title: t('drive.remove'), 'aria-label': t('drive.remove'), on: { click: () => trash([f]) } }, [icon('trash', 15)]) : null,
				]),
			])) : [el('div', { class: 'dsv-empty', text: t('drive.storage.none') })]));

			renderDuplicates(d);
		}

		/** May the largest file go into the trash (Drive 1.7.0 `canDelete`, else a writable area)? */
		function canTrash(f) {
			if (f.canDelete === true) return true;
			const a = o.getAreas().find((x) => x.id === f.areaId);
			return !!(a && a.writable);
		}

		/** "Ältere Versionen aufräumen" of an area (administrators and managers of the area: `canPrune`). */
		function pruneDialog(area, label) {
			const dlg = openDialog({ title: t('drive.storage.pruneTitle', { name: label }), host, closeLabel: t('drive.close') });
			const errEl = el('span', { class: 'dv-dlg-err', role: 'alert' });
			const sel = el('select', { class: 'dv-input dsg-keep', 'aria-label': t('drive.storage.pruneKeep') });
			for (const k of SS.KEEP) sel.appendChild(el('option', { value: String(k), text: pl('drive.storage.keep', k) }));
			sel.value = '3';
			const ok = el('button', { type: 'button', class: 'btn btn-danger', text: t('drive.storage.prune') });
			ok.addEventListener('click', async () => {
				ok.disabled = true;
				const r = await Promise.resolve(api.pruneVersions(area.id, Number(sel.value))).catch(fail);
				if (!r || !r.ok) { ok.disabled = false; errEl.textContent = err(r); return; }
				dlg.close(r);
				toast([pl('drive.storage.pruned', r.removed, { size: fmt(r.freedBytes) }), r.more ? t('drive.storage.prunedMore') : ''].filter(Boolean).join(' '), 'success');
				load();
			});
			dlg.body.append(el('p', { class: 'dv-p', text: t('drive.storage.pruneText', { size: fmt(area.versionsBytes) }) }), el('span', { class: 'lbl', text: t('drive.storage.pruneKeep') }), sel);
			dlg.foot.append(errEl, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), ok);
		}

		function renderDuplicates(d) {
			const groups = d.duplicates;
			const ids = SS.toTrash(groups, S.sel);
			const wasted = groups.reduce((n, g) => n + (g.wasted || 0), 0);
			const kids = [];
			if (!groups.length) kids.push(el('div', { class: 'dsv-empty', text: t('drive.storage.noDuplicates') }));
			else {
				kids.push(el('div', { class: 'dsg-dup-bar' }, [
					el('span', { class: 'dv-p', text: ids.length ? pl('drive.storage.dupSelected', ids.length, { size: fmt(SS.freed(groups, ids)) }) : t('drive.storage.dupHint') }),
					el('span', { class: 'dv-grow' }),
					el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('drive.storage.suggest'), on: { click: () => { S.sel = new Set(groups.flatMap((g) => [...SS.suggest(g)])); render(); } } }),
					ids.length ? el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('drive.storage.clearSel'), on: { click: () => { S.sel = new Set(); render(); } } }) : null,
					el('button', { type: 'button', class: 'btn btn-sec btn-sm dv-danger', disabled: !ids.length, on: { click: () => trash(groups.flatMap((g) => g.items).filter((i) => ids.includes(i.id))) } }, [icon('trash', 14), el('span', { text: t('drive.storage.dupTrash') })]),
				]));
				const areas = o.getAreas();
				for (const g of groups) {
					const v = SS.dupView(g, { t, fmt });
					const box = el('div', { class: 'dsg-dup', 'data-sha': v.key }, [el('div', { class: 'dsg-dup-h' }, [el('span', { class: 'dsg-name', text: v.title }), el('span', { class: 'dsg-sub', text: v.sub })])]);
					for (const it of g.items) {
						const on = S.sel.has(it.id);
						const can = SS.canTick(g, S.sel, it.id);
						const cb = el('input', { type: 'checkbox', checked: on, disabled: !can && !on, 'aria-label': t('drive.storage.dupTick', { name: it.name }) });
						cb.addEventListener('change', () => {
							if (cb.checked && !SS.canTick(g, S.sel, it.id)) { cb.checked = false; return; }
							const next = new Set(S.sel);
							if (cb.checked) next.add(it.id); else next.delete(it.id);
							S.sel = next;
							render();
						});
						box.appendChild(el('label', { class: `dsg-dup-row${on ? ' is-on' : ''}`, 'data-id': String(it.id) }, [
							cb,
							el('div', { class: 'dsg-row-tx' }, [el('span', { class: 'dsg-name', text: SS.placeOf(it, areas, o.areaLabel, t) || it.name }), el('span', { class: 'dsg-sub', text: [it.name, it.canDelete ? '' : t('drive.storage.readOnly')].filter(Boolean).join(' · ') })]),
							it.parentId ? el('button', { type: 'button', class: 'dv-ib dsv-act', title: t('drive.search.showFolder'), 'aria-label': t('drive.search.showFolder'), on: { click: (e) => { e.preventDefault(); o.openFolder(it.parentId); } } }, [icon('folder', 15)]) : null,
						]));
					}
					kids.push(box);
				}
			}
			body.appendChild(card(t('drive.storage.duplicates'), kids, groups.length ? t('drive.storage.wastedAll', { size: fmt(wasted) }) : null));
		}

		/** Files into the trash after a question (nothing is gone for good). */
		function trash(files) {
			if (!files.length) return;
			const days = (o.getMe() && o.getMe().settings && o.getMe().settings.trashDays) || null;
			const dlg = openDialog({ title: files.length === 1 ? t('drive.removeTitle', { name: files[0].name }) : pl('drive.storage.trashTitle', files.length), host, closeLabel: t('drive.close') });
			const errEl = el('span', { class: 'dv-dlg-err', role: 'alert' });
			const ok = el('button', { type: 'button', class: 'btn btn-danger', text: t('drive.remove') });
			const list = el('ul', { class: 'dsg-trash-list' }, files.slice(0, 8).map((f) => el('li', { text: f.path || f.name })));
			dlg.body.append(
				el('p', { class: 'dv-p', text: [t('drive.storage.trashText', { size: fmt(files.reduce((n, f) => n + (f.size || 0), 0)) }), days ? t('drive.trash.info', { n: days }) : ''].filter(Boolean).join(' ') }),
				list,
				files.length > 8 ? el('span', { class: 'dv-pick-note', text: pl('drive.storage.andMore', files.length - 8) }) : null,
			);
			ok.addEventListener('click', async () => {
				ok.disabled = true;
				let failed = 0;
				let last = null;
				for (const f of files) {
					const r = await Promise.resolve(api.remove(f.id)).catch(fail);
					if (!r || !r.ok) { failed++; last = r; }
				}
				dlg.close(true);
				if (failed) toast(pl('drive.storage.trashFailed', failed, { reason: err(last) }), 'error');
				else toast(t('drive.done.trash'), 'success');
				S.sel = new Set();
				load();
			});
			dlg.foot.append(errEl, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), ok);
		}

		return {
			el: wrap,
			show() { S.shown = true; wrap.hidden = false; load(); },
			hide() { S.shown = false; wrap.hidden = true; },
			refresh: () => load(),
			relabel: () => render(),
		};
	}

	root.GCDriveStorageView = { mount };
})(typeof self !== 'undefined' ? self : this);
