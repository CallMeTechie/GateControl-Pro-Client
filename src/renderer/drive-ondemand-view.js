/**
 * GateControl -- "Dateien bei Bedarf" (renderer view, part of "Ordner sichern")
 *
 * The card "GateControl Drive im Explorer" on top of "Ordner sichern": switch
 * on (registers the folder "GateControl Drive" in the Explorer) and off (asks
 * first: only files kept on this PC stay; changes not uploaded yet are
 * uploaded first, otherwise switching off stops and lists them), the state
 * (aktuell / lädt n / pausiert / Fehler mit Grund), "Im Explorer öffnen",
 * pause, the space used on this PC, the question after a mass delete
 * ("Löschen übertragen" / "Wiederherstellen"), and the Windows folders
 * (Desktop, Dokumente, Bilder, Videos, Musik) that can be moved into
 * Meine Dateien and put back — each only after an explicit "yes", locked
 * while "Ordner sichern" backs the same folder up (and the other way round).
 *
 * Mounted by drive-sync-view.js with its helpers el / icon / clear /
 * openDialog. Data: window.gatecontrol.driveOnDemand; texts: drive.od.*;
 * logic without DOM: drive-ondemand-state.js (window.GCDriveOnDemandState).
 * Paths and server texts only ever go into textContent / attributes.
 */
(function (root) {
	'use strict';

	const OS = root.GCDriveOnDemandState;
	const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed' });

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.driveOnDemand
	 * @param {Function} o.t
	 * @param {Function} o.getLocale
	 * @param {Function} [o.toast]
	 * @param {HTMLElement} [o.host] - dialogs
	 * @param {object} o.ui - { el, icon, clear, openDialog }
	 * @param {Function} [o.onKnown] - (known) after every Windows-folder list (W2 locks)
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const { el, icon, clear, openDialog } = o.ui;
		const toast = typeof o.toast === 'function' ? o.toast : () => {};
		const host = o.host || document.body;
		const locale = () => o.getLocale();
		let st = null;
		let known = null;
		let sync = null;
		let usage = null;
		let shown = false;
		let lastRunning = null;

		const card = el('section', { class: 'card dsv-card dod', 'aria-labelledby': 'dod-h' });
		const knownCard = el('section', { class: 'card dsv-card dod-known', hidden: true, 'aria-labelledby': 'dod-known-h' });
		const wrap = el('div', { class: 'dod-wrap' }, [card, knownCard]);

		async function call(fn, okKey) {
			let r;
			try { r = await fn(); } catch (err) { r = fail(err); }
			if (r && r.ok === false) {
				if (r.code !== 'cancelled') toast(OS.errorText(r, t), 'error');
				return null;
			}
			if (okKey) toast(t(okKey), 'success');
			return r || { ok: true };
		}

		function apply(s) {
			if (!s) return;
			st = s;
			const running = !!(st.enabled && st.running);
			if (running !== lastRunning) {
				lastRunning = running;
				if (running) { loadKnown(); loadUsage(); } else { known = null; usage = null; if (typeof o.onKnown === 'function') o.onKnown(null); }
			}
			if (shown) render();
		}
		api.onStatus(apply);
		Promise.resolve(api.status()).then(apply).catch(() => {});

		async function loadKnown() {
			const r = await Promise.resolve(api.knownFolders()).catch(fail);
			known = r && r.ok ? r.result : null;
			if (typeof o.onKnown === 'function') o.onKnown(known);
			if (shown) render();
		}

		async function loadUsage() {
			const r = await Promise.resolve(api.usage()).catch(fail);
			usage = r && r.ok ? r.result : null;
			if (shown) render();
		}

		// ── Rendering ────────────────────────────────────

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
			keepFocus(() => { renderCard(); renderKnown(); });
		}

		function renderCard() {
			clear(card);
			const s = st || { state: 'disabled', enabled: false, supported: true };
			const sum = OS.summary(s, { t });
			const on = sum.on;
			const sw = el('button', {
				type: 'button', class: `sw${on ? ' on' : ''}`, role: 'switch', 'aria-checked': on ? 'true' : 'false', 'aria-labelledby': 'dod-h', 'data-key': 'od-switch',
				disabled: s.supported === false || s.busy ? true : null,
				on: { click: () => (on ? disableDialog() : enable()) },
			}, [el('span')]);
			card.appendChild(el('div', { class: 'dsv-card-head' }, [
				el('div', { class: 'dsv-card-tx' }, [
					el('h3', { class: 'dsv-card-h', id: 'dod-h', text: t('drive.od.title') }),
					el('p', { class: 'dv-p', text: t(on ? 'drive.od.introOn' : 'drive.od.intro') }),
				]),
				on ? el('span', { class: `dsv-pill is-${sum.cls}`, role: 'status' }, [icon(sum.cls === 'ok' ? 'check' : sum.cls === 'run' ? 'refresh' : sum.cls === 'pause' ? 'pause' : 'alert', 14, '2.4'), el('span', { text: sum.text })]) : null,
				sw,
			]));
			if (!on) {
				if (s.supported === false) card.appendChild(el('p', { class: 'dv-p dod-note', text: sum.text }));
				return;
			}
			const pct = OS.progressPct(s);
			if (pct !== null) card.appendChild(el('div', { class: 'dv-tr-bar dsv-bar', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(pct), 'aria-label': sum.text }, [el('span', { style: `width:${pct}%` })]));
			if (sum.detail.length) card.appendChild(el('div', { class: 'dsv-detail dod-detail', text: sum.detail.join(' · ') }));

			const sus = OS.suspect(s);
			if (sus && typeof api.suspect === 'function') {
				card.appendChild(el('div', { class: 'dsv-ask dod-ask is-guard', role: 'alert' }, [
					el('span', { class: 'dsv-ask-ic' }, [icon('lock', 18)]),
					el('div', { class: 'dsv-ask-tx' }, [
						el('div', { class: 'dsv-ask-h', text: t('drive.od.suspect.title', { count: sus.count }) }),
						el('div', { class: 'dv-p', text: [t(sus.why === 'extension' ? 'drive.sync.suspect.textExtension' : 'drive.sync.suspect.textEntropy'), sus.sample.join(', ')].filter(Boolean).join(' ') }),
					]),
					el('button', { type: 'button', class: 'btn btn-pri btn-sm', 'data-key': 'od-sus-keep', text: t('drive.sync.suspect.keep'), on: { click: () => call(() => api.suspect('keep')) } }),
					el('button', { type: 'button', class: 'btn btn-ghost btn-sm dv-danger', 'data-key': 'od-sus-upload', text: t('drive.sync.suspect.upload'), on: { click: () => call(() => api.suspect('upload')) } }),
				]));
			}

			const md = OS.massDelete(s);
			if (md) {
				card.appendChild(el('div', { class: 'dsv-ask dod-ask', role: 'alert' }, [
					el('span', { class: 'dsv-ask-ic' }, [icon('alert', 18)]),
					el('div', { class: 'dsv-ask-tx' }, [
						el('div', { class: 'dsv-ask-h', text: t(md.offline ? 'drive.od.ask.titleOffline' : 'drive.od.ask.title', { count: md.files }) }),
						el('div', { class: 'dv-p', text: [t('drive.od.ask.text'), md.sample.join(', ')].filter(Boolean).join(' ') }),
					]),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-key': 'od-ask-restore', text: t('drive.od.ask.restore'), on: { click: () => call(() => api.deletes('restore'), 'drive.od.done.restored') } }),
					el('button', { type: 'button', class: 'btn btn-ghost btn-sm dv-danger', 'data-key': 'od-ask-apply', text: t('drive.od.ask.apply'), on: { click: () => call(() => api.deletes('apply'), 'drive.od.done.applied') } }),
				]));
			}

			const u = OS.usageText(usage, { t, locale: locale() });
			const paused = s.state === 'paused';
			const running = !!s.running;
			card.appendChild(el('div', { class: 'dod-row' }, [
				el('div', { class: 'dod-usage' }, u ? [
					el('div', { class: 'dod-usage-item' }, [el('span', { class: 'dod-usage-l', text: t('drive.od.usage.local') }), el('b', { class: 'dod-usage-v', text: u.local })]),
					el('div', { class: 'dod-usage-item' }, [el('span', { class: 'dod-usage-l', text: t('drive.od.usage.total') }), el('b', { class: 'dod-usage-v', text: u.total })]),
				] : [el('span', { class: 'dv-p', text: t('drive.od.usage.none') })]),
				el('span', { class: 'dv-grow' }),
				el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-key': 'od-open', disabled: running ? null : true, on: { click: () => call(() => api.openRoot()) } }, [icon('open', 14), el('span', { text: t('drive.od.open') })]),
				el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-key': 'od-pause', disabled: running && !s.busy ? null : true, on: { click: () => call(() => (paused ? api.resume() : api.pause())) } }, [icon(paused ? 'play' : 'pause', 14), el('span', { text: t(paused ? 'drive.od.resume' : 'drive.od.pause') })]),
				el('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'data-key': 'od-usage', 'aria-label': t('drive.od.usage.refresh'), title: t('drive.od.usage.refresh'), disabled: running ? null : true, on: { click: () => loadUsage() } }, [icon('refresh', 14)]),
			]));
		}

		function renderKnown() {
			clear(knownCard);
			const s = st || {};
			const rows = s.enabled ? OS.knownRows(known, sync, s, t) : [];
			knownCard.hidden = !rows.length;
			if (!rows.length) return;
			knownCard.appendChild(el('div', { class: 'dsv-card-head' }, [
				el('div', { class: 'dsv-card-tx' }, [el('h3', { class: 'dsv-card-h', id: 'dod-known-h', text: t('drive.od.known.title') }), el('p', { class: 'dv-p', text: t('drive.od.known.text') })]),
			]));
			for (const k of rows) {
				const stateTx = k.working ? OS.summary(s, { t }).text
					: k.inDrive ? t('drive.od.known.inDrive') : t('drive.od.known.local');
				const note = k.lock === 'w2' && !k.inDrive ? t('drive.od.known.lockedByW2') : null;
				const btn = k.inDrive
					? el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-key': `od-restore-${k.key}`, disabled: k.canRestore ? null : true, on: { click: () => restoreDialog(k) } }, [icon('down', 14), el('span', { text: t('drive.od.known.restore') })])
					: el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-key': `od-move-${k.key}`, disabled: k.canMove ? null : true, title: note || null, on: { click: () => relocateDialog(k) } }, [icon('upload', 14), el('span', { text: t('drive.od.known.move') })]);
				knownCard.appendChild(el('div', { class: `dsv-row dod-krow${k.inDrive ? ' is-in' : ''}`, 'data-known': k.key }, [
					el('span', { class: 'dsv-ic' }, [icon(k.inDrive ? 'cloud' : 'folder', 17)]),
					el('div', { class: 'dsv-main' }, [
						el('div', { class: 'dsv-name', text: k.label }),
						el('div', { class: 'dsv-path', text: k.path }),
						el('div', { class: `dsv-state is-${k.working ? 'run' : k.inDrive ? 'ok' : 'none'}` }, [el('span', { class: 'dsv-dot', 'aria-hidden': 'true' }), el('span', { class: 'dsv-state-tx', text: stateTx })]),
						note ? el('div', { class: 'dsv-detail dod-lock', text: note }) : null,
					]),
					btn,
				]));
			}
		}

		// ── Actions ──────────────────────────────────────

		async function enable() {
			const r = await call(() => api.enable());
			if (r) { toast(t('drive.od.done.on'), 'success'); Promise.resolve(api.status()).then(apply).catch(() => {}); }
		}

		function disableDialog() {
			const dlg = openDialog({ title: t('drive.od.off.title'), host, closeLabel: t('drive.close') });
			const errBox = el('div', { class: 'dod-off-err', role: 'alert' });
			dlg.body.append(
				el('p', { class: 'dv-p', text: t('drive.od.off.text') }),
				el('ul', { class: 'dod-list' }, [
					el('li', { text: t('drive.od.off.keep') }),
					el('li', { text: t('drive.od.off.online') }),
					el('li', { text: t('drive.od.off.upload') }),
				]),
				errBox,
			);
			const cancel = el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close() } });
			const go = el('button', { type: 'button', class: 'btn btn-sec btn-danger', 'data-key': 'od-off-go', text: t('drive.od.off.confirm') });
			const force = el('button', { type: 'button', class: 'btn btn-ghost dv-danger', hidden: true, text: t('drive.od.off.force') });
			const run = async (withForce) => {
				go.disabled = true; force.disabled = true;
				clear(errBox);
				errBox.appendChild(el('p', { class: 'dv-p', text: t('drive.od.off.working') }));
				let r;
				try { r = await api.disable(withForce); } catch (e) { r = fail(e); }
				clear(errBox);
				go.disabled = false; force.disabled = false;
				if (r && r.ok) { dlg.close(); toast(t('drive.od.done.off'), 'success'); Promise.resolve(api.status()).then(apply).catch(() => {}); return; }
				errBox.appendChild(el('p', { class: 'dv-dlg-err', text: OS.errorText(r, t) }));
				if (r && r.code === 'unsynced') {
					errBox.appendChild(el('ul', { class: 'dod-list dod-paths' }, OS.unsyncedList(r).map((p) => el('li', { text: p }))));
					errBox.appendChild(el('p', { class: 'dv-p', text: t('drive.od.off.forceText') }));
					force.hidden = false;
					go.textContent = t('drive.od.off.retry');
				} else if (r && r.code === 'not_running') {
					force.hidden = false;
				} else if (r && r.code === 'relocated') {
					const folders = r.data && Array.isArray(r.data.folders) ? r.data.folders : [];
					errBox.appendChild(el('p', { class: 'dv-p', text: folders.map((f) => t(`drive.sync.known.${f}`)).join(', ') }));
				}
			};
			go.addEventListener('click', () => run(false));
			force.addEventListener('click', () => run(true));
			dlg.foot.append(force, el('span', { class: 'dv-grow' }), cancel, go);
		}

		function relocateDialog(k) {
			const target = t('drive.od.known.target', { name: k.label });
			const dlg = openDialog({ title: t('drive.od.move.title', { name: k.label }), host, closeLabel: t('drive.close') });
			const check = el('input', { type: 'checkbox', id: `dod-agree-${k.key}`, 'data-key': 'od-move-agree' });
			const go = el('button', { type: 'button', class: 'btn btn-pri', 'data-key': 'od-move-go', disabled: true, text: t('drive.od.move.confirm') });
			check.addEventListener('change', () => { go.disabled = !check.checked; });
			dlg.body.append(
				el('p', { class: 'dv-p', text: t('drive.od.move.text', { from: k.path, to: target }) }),
				el('ul', { class: 'dod-list' }, [
					el('li', { text: t('drive.od.move.point1') }),
					el('li', { text: t('drive.od.move.point2') }),
					el('li', { text: t('drive.od.move.point3') }),
				]),
				el('label', { class: 'dod-agree', for: check.id }, [check, el('span', { text: t('drive.od.move.agree') })]),
			);
			go.addEventListener('click', async () => {
				dlg.close();
				const r = await call(() => api.relocate(k.key, k.label), 'drive.od.done.moved');
				if (r) loadKnown();
				loadUsage();
			});
			dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close() } }), go);
		}

		function restoreDialog(k) {
			const dlg = openDialog({ title: t('drive.od.restore.title', { name: k.label }), host, closeLabel: t('drive.close') });
			const to = k.from || t('drive.od.restore.defaultPlace');
			dlg.body.append(
				el('p', { class: 'dv-p', text: t('drive.od.restore.text', { to }) }),
				el('ul', { class: 'dod-list' }, [
					el('li', { text: t('drive.od.restore.point1') }),
					el('li', { text: t('drive.od.restore.point2') }),
				]),
			);
			const go = el('button', { type: 'button', class: 'btn btn-pri', 'data-key': 'od-restore-go', text: t('drive.od.restore.confirm') });
			go.addEventListener('click', async () => {
				dlg.close();
				const r = await call(() => api.restore(k.key), 'drive.od.done.restoredFolder');
				if (r) loadKnown();
				loadUsage();
			});
			dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close() } }), go);
		}

		return {
			el: wrap,
			show() {
				shown = true;
				Promise.resolve(api.status()).then(apply).catch(() => {});
				if (st && st.enabled && st.running) { loadKnown(); loadUsage(); }
				render();
			},
			hide() { shown = false; },
			relabel() { if (shown) render(); },
			/** W2 status (folders) for the locks. */
			setSync(s) { sync = s; if (shown) renderKnown(); },
			/** For W2: text why a Windows folder cannot be backed up (it lies in the Drive) or null. */
			w2Lock(path) { const key = OS.w2Lock(path, known); return key ? t(key) : null; },
		};
	}

	root.GCDriveOnDemandView = { mount };
})(typeof self !== 'undefined' ? self : this);
