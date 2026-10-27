/**
 * GateControl -- "Ordner sichern" (renderer view, part of the page Drive)
 *
 * Folders of this PC in Drive (core DriveSync in the main process, also while
 * the window is closed): the Windows folders (Desktop, Dokumente, Bilder,
 * Videos, Musik) with a switch each ("Nur sichern" into Meine Dateien ›
 * Geräte › <PC>), "Weitere Ordner" — any folder, "Nur sichern" or
 * "Abgleichen" with a Drive folder picked in Drive's folder picker — with
 * their state (aktuell / läuft n von m Dateien / pausiert / wartet / Fehler
 * mit Grund, zuletzt gesichert), pause, "Jetzt abgleichen", "Im Explorer
 * öffnen" and "Entfernen" (stops, deletes nothing), the question after a
 * mass delete ("Löschen übertragen" / "Wiederherstellen") and the settings
 * (node_modules / .git, size, upload / download limit, home network, VPN).
 *
 * Mounted by drive-view.js (it hands over its helpers el / icon / clear /
 * openDialog and its folder picker). Data: window.gatecontrol.drive.sync;
 * texts: drive.sync.*; view logic without DOM: drive-sync-state.js
 * (window.GCDriveSyncState). Server and path text only ever goes into
 * textContent / attributes.
 */
(function (root) {
	'use strict';

	const SS = root.GCDriveSyncState;
	const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed', error: err && err.message });
	let uid = 0;
	const nextId = (p) => `${p}-${++uid}`;

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive.sync
	 * @param {Function} o.t
	 * @param {Function} o.getLocale
	 * @param {Function} [o.now]
	 * @param {Function} [o.toast]
	 * @param {HTMLElement} [o.host] - dialogs
	 * @param {object} o.ui - { el, icon, clear, openDialog } of drive-view.js
	 * @param {Function} o.pickDriveFolder - (opts) → Promise<{ folderId, path } | null>
	 * @param {Function} [o.onSummary] - (summary) after every status
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const { el, icon, clear, openDialog } = o.ui;
		const now = typeof o.now === 'function' ? o.now : () => Date.now();
		const locale = () => o.getLocale();
		const toast = typeof o.toast === 'function' ? o.toast : () => {};
		const host = o.host || document.body;
		let st = null;
		let shown = false;
		let settingsKey = '';

		const wrap = el('div', { class: 'dsv', hidden: true });
		const head = el('div', { class: 'dsv-head' });
		const asks = el('div', { class: 'dsv-asks' });
		const knownCard = el('section', { class: 'card dsv-card' });
		const moreCard = el('section', { class: 'card dsv-card' });
		const setCard = el('section', { class: 'card dsv-card dsv-set' });
		wrap.append(head, asks, knownCard, moreCard, setCard);

		function apply(s) {
			if (!s || !s.ok) return;
			st = s;
			if (typeof o.onSummary === 'function') o.onSummary(SS.summary(st, ctx()));
			if (shown) render();
		}
		api.onChange(apply);
		Promise.resolve(api.status()).then(apply).catch(() => {});

		const ctx = () => ({ t, locale: locale(), now: now() });

		async function call(fn, okKey) {
			let r;
			try { r = await fn(); } catch (err) { r = fail(err); }
			if (r && r.ok === false) { if (r.code !== 'cancelled') toast(SS.errorText(r, t), 'error'); return null; }
			if (okKey) toast(t(okKey), 'success');
			if (r && r.folders) apply(r);
			return r;
		}

		// ── Rendering ────────────────────────────────────

		/** Re-renders a part and puts the focus back on the control it was on. */
		function keepFocus(fn) {
			const a = document.activeElement;
			const key = a && wrap.contains(a) ? a.getAttribute('data-key') : null;
			fn();
			if (key) {
				const back = wrap.querySelector(`[data-key="${CSS.escape(key)}"]`);
				if (back) back.focus();
			}
		}

		function render() {
			if (!st) { clear(head); head.appendChild(el('p', { class: 'dv-p', text: t('drive.loading') })); return; }
			keepFocus(() => {
				renderHead();
				renderAsks();
				renderKnown();
				renderMore();
			});
			const key = JSON.stringify([st.settings, st.network, st.device, locale()]);
			if (key !== settingsKey) { settingsKey = key; keepFocus(renderSettings); }
		}

		function renderHead() {
			clear(head);
			const sum = SS.summary(st, ctx());
			const anyFolder = st.folders.length > 0;
			head.append(
				el('div', { class: 'dsv-head-tx' }, [
					el('h2', { class: 'dsv-h', text: t('drive.sync.title') }),
					el('p', { class: 'dv-p', text: t('drive.sync.intro') }),
				]),
				el('span', { class: `dsv-pill is-${sum.cls}`, role: 'status' }, [icon(sum.cls === 'ok' ? 'check' : sum.cls === 'run' ? 'refresh' : sum.cls === 'pause' ? 'pause' : 'alert', 14, '2.4'), el('span', { text: sum.text })]),
				anyFolder ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-key': 'pause-all', on: { click: () => call(() => api.pause(null, !st.paused)) } }, [icon(st.paused ? 'play' : 'pause', 14), el('span', { text: t(st.paused ? 'drive.sync.resumeAll' : 'drive.sync.pauseAll') })]) : null,
				anyFolder ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-key': 'run-all', disabled: st.paused ? true : null, on: { click: () => call(() => api.run(null), 'drive.sync.done.run') } }, [icon('refresh', 14), el('span', { text: t('drive.sync.runAll') })]) : null,
			);
		}

		function renderAsks() {
			clear(asks);
			for (const c of SS.confirms(st)) {
				asks.appendChild(el('div', { class: 'dsv-ask', role: 'alert' }, [
					el('span', { class: 'dsv-ask-ic' }, [icon('alert', 18)]),
					el('div', { class: 'dsv-ask-tx' }, [
						el('div', { class: 'dsv-ask-h', text: t('drive.sync.ask.title', { name: c.name, count: c.count, total: c.total }) }),
						el('div', { class: 'dv-p', text: t(c.mode === 'backup' ? 'drive.sync.ask.textBackup' : 'drive.sync.ask.textSync') }),
					]),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-key': `ask-restore-${c.id}`, text: t('drive.sync.ask.restore'), on: { click: () => call(() => api.deletes(c.id, 'restore')) } }),
					el('button', { type: 'button', class: 'btn btn-ghost btn-sm dv-danger', 'data-key': `ask-apply-${c.id}`, text: t('drive.sync.ask.apply'), on: { click: () => call(() => api.deletes(c.id, 'apply')) } }),
				]));
			}
		}

		function stateLine(f) {
			const v = SS.folderView(f, ctx());
			const box = el('div', { class: `dsv-state is-${v.cls}` }, [
				el('span', { class: 'dsv-dot', 'aria-hidden': 'true' }),
				el('span', { class: 'dsv-state-tx', text: v.text }),
			]);
			const out = [box];
			if (v.pct !== null) out.push(el('div', { class: 'dv-tr-bar dsv-bar', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(v.pct), 'aria-label': v.text }, [el('span', { style: `width:${v.pct}%` })]));
			if (v.detail.length) out.push(el('div', { class: 'dsv-detail', text: v.detail.join(' · ') }));
			return { v, nodes: out };
		}

		function folderActions(f, v) {
			const b = (ic, label, key, fn, cls = '') => el('button', { type: 'button', class: `dv-ib dsv-act ${cls}`, title: label, 'aria-label': `${label}: ${v.name}`, 'data-key': `${key}-${f.id}`, on: { click: fn } }, [icon(ic, 15)]);
			return el('div', { class: 'dsv-acts' }, [
				b(f.paused ? 'play' : 'pause', t(f.paused ? 'drive.sync.resume' : 'drive.sync.pause'), 'pause', () => call(() => api.pause(f.id, !f.paused))),
				b('refresh', t('drive.sync.run'), 'run', () => call(() => api.run(f.id), 'drive.sync.done.run')),
				b('open', t('drive.sync.openLocal'), 'open', () => call(() => api.open(f.id))),
				b('trash', t('drive.sync.remove'), 'remove', () => removeFolder(f, v), 'dv-danger'),
			]);
		}

		function renderKnown() {
			clear(knownCard);
			const rows = SS.knownRows(st, t);
			knownCard.hidden = !rows.length;
			if (!rows.length) return;
			knownCard.append(
				el('div', { class: 'dsv-card-head' }, [
					el('div', { class: 'dsv-card-tx' }, [el('h3', { class: 'dsv-card-h', text: t('drive.sync.known.title') }), el('p', { class: 'dv-p', text: t('drive.sync.known.text', { device: st.device.name }) })]),
				]),
			);
			for (const k of rows) {
				const f = k.folder;
				const on = !!f;
				const sw = el('button', {
					type: 'button', class: `sw${on ? ' on' : ''}`, role: 'switch', 'aria-checked': on ? 'true' : 'false', 'aria-label': t('drive.sync.known.switch', { name: k.label }), 'data-key': `known-${k.key}`,
					on: { click: () => (on ? removeFolder(f, SS.folderView(f, ctx())) : call(() => api.add({ path: k.path, mode: 'backup' }), 'drive.sync.done.add')) },
				}, [el('span')]);
				const info = f ? stateLine(f) : null;
				knownCard.appendChild(el('div', { class: 'dsv-row', 'data-folder': f ? f.id : null }, [
					el('span', { class: 'dsv-ic' }, [icon('folder', 17)]),
					el('div', { class: 'dsv-main' }, [
						el('div', { class: 'dsv-name', text: k.label }),
						el('div', { class: 'dsv-path', text: k.path }),
						...(info ? info.nodes : [el('div', { class: 'dsv-detail', text: t('drive.sync.known.off') })]),
					]),
					f ? el('div', { class: 'dsv-target' }, [el('span', { class: 'dsv-mode', text: info.v.modeText }), el('span', { class: 'dsv-target-tx', text: info.v.target })]) : el('div', { class: 'dsv-target' }),
					f ? folderActions(f, info.v) : el('div', { class: 'dsv-acts' }),
					sw,
				]));
			}
		}

		function renderMore() {
			clear(moreCard);
			const list = SS.otherFolders(st);
			moreCard.append(el('div', { class: 'dsv-card-head' }, [
				el('div', { class: 'dsv-card-tx' }, [el('h3', { class: 'dsv-card-h', text: t('drive.sync.more.title') }), el('p', { class: 'dv-p', text: t('drive.sync.more.text') })]),
				el('button', { type: 'button', class: 'btn btn-pri btn-sm', 'data-key': 'add', on: { click: () => addDialog() } }, [icon('plus', 14), el('span', { text: t('drive.sync.add.button') })]),
			]));
			if (!list.length) {
				moreCard.appendChild(el('div', { class: 'dsv-empty', text: t('drive.sync.more.empty') }));
				return;
			}
			for (const f of list) {
				const info = stateLine(f);
				moreCard.appendChild(el('div', { class: 'dsv-row', 'data-folder': f.id }, [
					el('span', { class: 'dsv-ic' }, [icon(f.mode === 'sync' ? 'sync' : 'upload', 17)]),
					el('div', { class: 'dsv-main' }, [
						el('div', { class: 'dsv-name', text: info.v.name }),
						el('div', { class: 'dsv-path', text: info.v.path }),
						...info.nodes,
					]),
					el('div', { class: 'dsv-target' }, [el('span', { class: `dsv-mode is-${f.mode}`, text: info.v.modeText }), el('span', { class: 'dsv-target-tx', text: info.v.target })]),
					folderActions(f, info.v),
				]));
			}
		}

		function setRow(title, desc, control, id) {
			return el('div', { class: 'set-row dsv-set-row' }, [
				el('div', { class: 'grow' }, [el('div', { class: 'set-row-title', id, text: title }), desc ? el('div', { class: 'set-row-desc', text: desc }) : null]),
				control,
			]);
		}

		function switchFor(key, on, labelId, disabled = false) {
			return el('button', {
				type: 'button', class: `sw${on ? ' on' : ''}`, role: 'switch', 'aria-checked': on ? 'true' : 'false', 'aria-labelledby': labelId, 'data-key': `set-${key}`, disabled: disabled ? true : null,
				on: { click: () => call(() => api.settings({ [key]: !on })) },
			}, [el('span')]);
		}

		function selectFor(key, values, current, label, labelId) {
			const s = el('select', { class: 'inp dsv-select', 'aria-labelledby': labelId, 'data-key': `set-${key}`, on: { change: () => call(() => api.settings({ [key]: Number(s.value) })) } });
			for (const v of SS.options(values, current)) {
				const opt = el('option', { value: String(v), text: label(v) });
				if (v === Number(current)) opt.selected = true;
				s.appendChild(opt);
			}
			return s;
		}

		function renderSettings() {
			clear(setCard);
			const s = st.settings || {};
			const ids = {};
			for (const k of ['skipDev', 'maxFileBytes', 'upKBs', 'downKBs', 'homeOnly', 'vpnOnly']) ids[k] = nextId(`dsv-${k}`);
			const net = st.network || {};
			const homeTx = net.known ? t(net.home ? 'drive.sync.set.atHome' : 'drive.sync.set.notHome', { n: net.known }) : t('drive.sync.set.noHome');
			setCard.append(
				el('div', { class: 'dsv-card-head' }, [el('div', { class: 'dsv-card-tx' }, [el('h3', { class: 'dsv-card-h', text: t('drive.sync.set.title') }), el('p', { class: 'dv-p', text: [t('drive.sync.set.device', { device: st.device.name }), st.device.key ? t('drive.sync.set.deviceKey', { key: st.device.key }) : ''].filter(Boolean).join(' ') })])]),
				setRow(t('drive.sync.set.skipDev'), t('drive.sync.set.skipDevDesc'), switchFor('skipDev', !!s.skipDev, ids.skipDev), ids.skipDev),
				setRow(t('drive.sync.set.maxSize'), t('drive.sync.set.maxSizeDesc'), selectFor('maxFileBytes', SS.SIZES, s.maxFileBytes, (v) => SS.sizeLabel(v, locale(), t), ids.maxFileBytes), ids.maxFileBytes),
				setRow(t('drive.sync.set.up'), null, selectFor('upKBs', SS.RATES, s.upKBs, (v) => SS.rateLabel(v, locale(), t), ids.upKBs), ids.upKBs),
				setRow(t('drive.sync.set.down'), null, selectFor('downKBs', SS.RATES, s.downKBs, (v) => SS.rateLabel(v, locale(), t), ids.downKBs), ids.downKBs),
				setRow(t('drive.sync.set.homeOnly'), homeTx, el('div', { class: 'dsv-home' }, [
					el('button', { type: 'button', class: 'btn btn-sec btn-xs', 'data-key': 'home-set', text: t('drive.sync.set.markHome'), on: { click: () => call(() => api.home(true), 'drive.sync.done.home') } }),
					net.known ? el('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'data-key': 'home-clear', text: t('drive.sync.set.forgetHome'), on: { click: () => call(() => api.home(false)) } }) : null,
					switchFor('homeOnly', !!s.homeOnly, ids.homeOnly, !net.known),
				]), ids.homeOnly),
				setRow(t('drive.sync.set.vpnOnly'), t('drive.sync.set.vpnOnlyDesc'), switchFor('vpnOnly', !!s.vpnOnly, ids.vpnOnly), ids.vpnOnly),
				el('p', { class: 'dsv-foot dv-p', text: t('drive.sync.set.always') }),
			);
		}

		// ── Actions ──────────────────────────────────────

		function removeFolder(f, v) {
			const dlg = openDialog({ title: t('drive.sync.removeTitle', { name: v.name }), host, closeLabel: t('drive.close') });
			const err = el('span', { class: 'dv-dlg-err', role: 'alert' });
			dlg.body.appendChild(el('p', { class: 'dv-p', text: t(f.mode === 'sync' ? 'drive.sync.removeTextSync' : 'drive.sync.removeText', { target: v.target }) }));
			const go = el('button', { type: 'button', class: 'btn btn-sec btn-danger', text: t('drive.sync.remove'), on: { click: async () => {
				go.disabled = true;
				const r = await call(() => api.remove(f.id), 'drive.sync.done.remove');
				if (r) { dlg.close(); Promise.resolve(api.status()).then(apply).catch(() => {}); } else go.disabled = false;
			} } });
			dlg.foot.append(err, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close() } }), go);
		}

		function addDialog(preset = {}) {
			const draft = { path: preset.path || '', mode: preset.mode || 'backup', targetId: null, targetLabel: '' };
			const dlg = openDialog({ title: t('drive.sync.add.title'), host, closeLabel: t('drive.close'), wide: true });
			const err = el('span', { class: 'dv-dlg-err', role: 'alert' });
			const add = el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.sync.add.confirm'), on: { click: () => submit() } });
			const pathId = nextId('dsv-path');
			const modeId = nextId('dsv-mode');
			const targetId = nextId('dsv-target');
			const pathTx = el('div', { class: 'dsv-pick-val dsv-mono', id: pathId });
			const targetTx = el('div', { class: 'dsv-pick-val', id: targetId });
			const modeDesc = el('p', { class: 'dv-p dsv-mode-desc' });
			const seg = el('div', { class: 'seg dv-seg', role: 'radiogroup', 'aria-labelledby': modeId });
			const targetRow = el('div', { class: 'dsv-field' }, [
				el('div', { class: 'lbl', text: t('drive.sync.add.target') }),
				el('div', { class: 'dsv-pick' }, [targetTx, el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'aria-describedby': targetId, text: t('drive.sync.add.pickTarget'), on: { click: pickTarget } })]),
			]);
			dlg.body.append(
				el('div', { class: 'dsv-field' }, [
					el('div', { class: 'lbl', text: t('drive.sync.add.local') }),
					el('div', { class: 'dsv-pick' }, [pathTx, el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'aria-describedby': pathId, text: t('drive.sync.add.pickLocal'), on: { click: pickLocal } })]),
				]),
				el('div', { class: 'dsv-field' }, [el('div', { class: 'lbl', id: modeId, text: t('drive.sync.add.mode') }), seg, modeDesc]),
				targetRow,
			);
			dlg.foot.append(err, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close() } }), add);

			function paint() {
				pathTx.textContent = draft.path || t('drive.sync.add.noLocal');
				pathTx.classList.toggle('is-empty', !draft.path);
				targetTx.textContent = draft.targetLabel || t('drive.sync.add.noTarget');
				targetTx.classList.toggle('is-empty', !draft.targetLabel);
				clear(seg);
				for (const m of SS.MODES) {
					seg.appendChild(el('button', { type: 'button', role: 'radio', 'aria-checked': draft.mode === m ? 'true' : 'false', class: draft.mode === m ? 'on' : '', text: t(`drive.sync.mode.${m}`), on: { click: () => { draft.mode = m; paint(); } } }));
				}
				modeDesc.textContent = t(`drive.sync.mode.${draft.mode}Desc`, { device: st && st.device ? st.device.name : 'PC' });
				targetRow.hidden = draft.mode !== 'sync';
				add.disabled = !SS.addCheck(draft).ok;
			}
			async function pickLocal() {
				const r = await Promise.resolve(api.pick()).catch(fail);
				if (r && r.ok && r.path) { draft.path = r.path; err.textContent = ''; paint(); }
			}
			async function pickTarget() {
				const to = await o.pickDriveFolder({ title: t('drive.sync.add.pickTargetTitle'), confirm: t('drive.sync.add.pickTargetHere'), remember: false, host });
				if (to && to.folderId) { draft.targetId = to.folderId; draft.targetLabel = to.path; err.textContent = ''; paint(); }
			}
			async function submit() {
				if (!SS.addCheck(draft).ok) return;
				add.disabled = true;
				let r;
				try { r = await api.add({ path: draft.path, mode: draft.mode, targetId: draft.mode === 'sync' ? draft.targetId : null }); } catch (e) { r = fail(e); }
				if (r && r.ok) {
					toast(t('drive.sync.done.add'), 'success');
					dlg.close();
					Promise.resolve(api.status()).then(apply).catch(() => {});
					return;
				}
				err.textContent = SS.errorText(r, t);
				add.disabled = false;
			}
			paint();
		}

		return {
			el: wrap,
			show() {
				shown = true;
				wrap.hidden = false;
				settingsKey = '';
				Promise.resolve(api.status()).then(apply).catch(() => {});
				render();
			},
			hide() {
				shown = false;
				wrap.hidden = true;
			},
			relabel() { settingsKey = ''; if (shown) render(); },
			summary: () => (st ? SS.summary(st, ctx()) : null),
			addDialog,
		};
	}

	root.GCDriveSyncView = { mount };
})(typeof self !== 'undefined' ? self : this);
