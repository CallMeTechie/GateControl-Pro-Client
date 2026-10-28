/**
 * GateControl -- Drive settings (renderer view, part of the page Drive)
 *
 * Drive 1.11: the gear at the bottom of the menu opens the settings as a view of the page (like "Ordner sichern"):
 *   1. Sicherung — "Ordner sichern" and "GateControl Drive im Explorer" (a line each, they open "Ordner sichern")
 *      and its settings card (node_modules / .git, size, upload / download limit, home network, VPN — moved here
 *      from "Ordner sichern", drive-sync-view.js settingsCard, so nothing is there twice).
 *   2. Tresore — "Mit Windows Hello öffnen" (on by default; off only after Windows Hello, with a warning), "Automatisch
 *      sperren nach …" (1 / 3 / 5 / 15 minutes, never), "Beim Verlassen sperren" (window minimized or closed into the
 *      tray), "Jetzt sperren", this PC's safety number, "Freigegeben für" (the vaults this PC has keys for).
 *   3. KI für Dokumente — a switch per area one may write to (PATCH areas/<id> { docAi }); "Tresore werden nie von
 *      der KI gelesen."
 *   4. Ansicht — the sorting of the lists (the same as the bar's).
 *   5. Daten auf diesem Gerät — the cache (opened files, previews) with its size and "Leeren".
 *   6. Benachrichtigungen — Drive's topics of the app's notifications (deadline reminders, vault requests), switched
 *      on this PC (the app's mute list; no new server API).
 * Everything is kept on this PC except the AI switches (Drive).
 *
 * Mounted by drive-view.js (helpers el / icon / clear / openDialog). Logic: drive-menu-state.js; texts:
 * drive.settings.*, drive.lock.*. Server text only via textContent.
 */
(function (root) {
	'use strict';

	const MS = root.GCDriveMenuState;
	const DS = root.GCDriveState;
	const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed' });
	let uid = 0;
	const nextId = (p) => `${p}-${++uid}`;

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive
	 * @param {Function} o.t
	 * @param {Function} o.getLocale
	 * @param {Function} [o.toast]
	 * @param {object} o.ui - { el, icon, clear, openDialog }
	 * @param {object} [o.syncView] - drive-sync-view.js instance (its settings card)
	 * @param {Function} o.page - () → { me, areas, vaults, vaultStatus, lock, sort, syncSummary }
	 * @param {Function} o.openSync - opens "Ordner sichern"
	 * @param {Function} o.setSort - (sort) the page's sorting
	 * @param {Function} o.docAiChanged - (areaId, on) the page's areas follow
	 * @param {Function} o.lockChanged - (status) the page's lock status follows
	 * @param {Function} [o.cacheCleared] - the page drops its previews
	 * @param {object} [o.notifyApi] - window.gatecontrol.notify (getPrefs / setPrefs)
	 */
	function mount(o) {
		const api = o.api;
		const vapi = api.vault || null;
		const t = o.t;
		const { el, icon, clear } = o.ui;
		const toast = typeof o.toast === 'function' ? o.toast : () => {};
		const locale = () => o.getLocale();
		let shown = false;
		let cache = null;
		let notify = null;
		let focusKey = null;

		const wrap = el('div', { class: 'dset', hidden: true });
		const head = el('div', { class: 'dsv-head' });
		const body = el('div', { class: 'dset-body' });
		wrap.append(head, body);

		async function call(fn, okKey) {
			let r;
			try { r = await fn(); } catch (err) { r = fail(err); }
			if (!r || r.ok === false) { if (!r || r.code !== 'hello_cancelled') toast(DS.errorText(r, t), 'error'); return null; }
			if (okKey) toast(t(okKey), 'success');
			return r;
		}

		const card = (key, title, desc, kids) => el('section', { class: 'card dsv-card dset-card', 'data-section': key }, [
			el('div', { class: 'dsv-card-head' }, [el('div', { class: 'dsv-card-tx' }, [el('h3', { class: 'dsv-card-h', text: title }), desc ? el('p', { class: 'dv-p', text: desc }) : null])]),
			...kids,
		]);
		const row = (title, desc, control, id = nextId('dset-r'), extra = null) => el('div', { class: 'set-row dsv-set-row' }, [
			el('div', { class: 'grow' }, [el('div', { class: 'set-row-title', id, text: title }), desc ? el('div', { class: 'set-row-desc', text: desc }) : null, extra]),
			control,
		]);
		const sw = (key, on, labelId, onClick, disabled = false) => el('button', {
			type: 'button', class: `sw${on ? ' on' : ''}`, role: 'switch', 'aria-checked': on ? 'true' : 'false', 'aria-labelledby': labelId, 'data-key': key,
			disabled: disabled ? true : null, on: { click: onClick },
		}, [el('span')]);

		function render() {
			const a = document.activeElement;
			focusKey = a && wrap.contains(a) ? a.getAttribute('data-key') : focusKey;
			const p = o.page();
			clear(head);
			head.append(el('div', { class: 'dsv-head-tx' }, [el('h2', { class: 'dsv-h', text: t('drive.settings.title') }), el('p', { class: 'dv-p', text: t('drive.settings.intro') })]));
			clear(body);
			body.append(backup(p));
			const v = vaults(p);
			if (v) body.append(v);
			const ai = docAi(p);
			if (ai) body.append(ai);
			body.append(view(p), data(), notifications());
			if (focusKey) {
				const back = wrap.querySelector(`[data-key="${CSS.escape(focusKey)}"]`);
				if (back) back.focus();
			}
		}

		// 1. Sicherung
		function backup(p) {
			const kids = [];
			if (typeof o.openSync === 'function' && o.syncView) {
				kids.push(row(t('drive.sync.title'), p.syncSummary || t('drive.settings.backup.syncDesc'),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-key': 'open-sync', on: { click: () => o.openSync() } }, [icon('sync', 14), el('span', { text: t('drive.settings.backup.open') })])));
				if (o.onDemand) {
					kids.push(row(t('drive.settings.backup.explorer'), t('drive.settings.backup.explorerDesc'),
						el('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'data-key': 'open-od', on: { click: () => o.openSync() } }, [el('span', { text: t('drive.settings.backup.open') })])));
				}
			}
			const c = card('backup', t('drive.settings.backup.title'), null, kids);
			if (o.syncView && o.syncView.settingsCard) c.appendChild(o.syncView.settingsCard);
			return c;
		}

		// 2. Tresore
		function vaults(p) {
			if (!vapi || !DS.hasFeature(p.me, 'vault')) return null;
			const supported = !!(p.vaultStatus && p.vaultStatus.supported);
			const lock = p.lock;
			if (!supported || !lock) {
				return card('vaults', t('drive.settings.vaults.title'), t(supported ? 'drive.loading' : 'drive.vault.gate.unsupported'), []);
			}
			const s = lock.settings || {};
			const ids = { hello: nextId('dset-h'), auto: nextId('dset-a'), leave: nextId('dset-l') };
			const hint = lock.enforced && s.hello ? MS.helloHint(lock.hello, t) : null;
			const helloDesc = el('div', { class: 'dset-extra' }, [
				!s.hello ? el('div', { class: 'dv-note is-warn dset-warn', text: t('drive.lock.hello.offWarn') }) : null,
				hint ? el('div', { class: 'dv-note is-warn dv-hello-hint' }, [el('span', { text: hint.text }), ' ',
					hint.setup ? el('button', { type: 'button', class: 'btn btn-ghost btn-xs dv-hello-setup', 'data-key': 'hello-setup', text: t('drive.lock.hello.setup'), on: { click: () => Promise.resolve(vapi.helloSettings()).catch(() => {}) } }) : null]) : null,
			]);
			const auto = el('select', { class: 'inp dsv-select', 'aria-labelledby': ids.auto, 'data-key': 'lock-auto', on: { change: () => setLock({ autoLockMinutes: Number(auto.value) }) } });
			for (const opt of MS.autoLockOptions(t)) {
				const x = el('option', { value: String(opt.value), text: opt.label });
				if (opt.value === s.autoLockMinutes) x.selected = true;
				auto.appendChild(x);
			}
			const rows = MS.vaultRows(p.vaults, p.areas, { t, locale: locale() });
			const approved = MS.approvedVaults(rows);
			const dev = p.vaultStatus.device;
			const kids = [
				lock.enforced ? row(t('drive.lock.hello.label'), t('drive.lock.hello.desc'), sw('lock-hello', !!s.hello, ids.hello, () => setLock({ hello: !s.hello })), ids.hello, helloDesc) : null,
				row(t('drive.lock.auto.label'), t('drive.lock.auto.desc'), auto, ids.auto),
				row(t('drive.lock.leave.label'), t('drive.lock.leave.desc'), sw('lock-leave', !!s.lockOnLeave, ids.leave, () => setLock({ lockOnLeave: !s.lockOnLeave })), ids.leave),
				row(t('drive.lock.state.label'), t(lock.unlocked && lock.enforced ? 'drive.lock.state.open' : 'drive.lock.state.locked'),
					lock.unlocked && lock.enforced ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-key': 'lock-now', on: { click: lockNow } }, [icon('lock', 14), el('span', { text: t('drive.lock.now') })]) : el('span')),
				row(t('drive.settings.vaults.safety'), t('drive.settings.vaults.safetyDesc'), el('code', { class: 'dv-safety-n dset-safety', text: dev ? dev.safetyNumber : t('drive.settings.vaults.noDevice') })),
				row(t('drive.settings.vaults.approved'), approved.length ? approved.join(', ') : t('drive.settings.vaults.none'), el('span', { class: 'dset-count', text: String(approved.length) })),
			];
			return card('vaults', t('drive.settings.vaults.title'), null, kids.filter(Boolean));
		}

		async function setLock(patch) {
			if (!vapi) return;
			const r = await call(() => vapi.lockSettings(patch));
			if (r && typeof o.lockChanged === 'function') o.lockChanged(r);
			render();
		}

		async function lockNow() {
			const r = await call(() => vapi.lock(), 'drive.lock.locked');
			if (r) refreshLock();
		}

		async function refreshLock() {
			if (!vapi || typeof vapi.lockStatus !== 'function') return;
			const r = await Promise.resolve(vapi.lockStatus()).catch(() => null);
			if (r && r.ok && typeof o.lockChanged === 'function') o.lockChanged(r);
			if (shown) render();
		}

		// 3. KI für Dokumente
		function docAi(p) {
			if (typeof api.setDocAi !== 'function') return null;
			const list = MS.docAiAreas(p.areas, p.me);
			if (!list.length) return null;
			const kids = list.map((x) => {
				const id = nextId('dset-ai');
				return row(DS.areaLabel(x.area, t), t('drive.docAi.hint'), sw(`ai-${x.areaId}`, x.on, id, async () => {
					const r = await call(() => api.setDocAi(x.areaId, !x.on));
					if (!r) return;
					const on = r.area && typeof r.area.docAi === 'boolean' ? r.area.docAi : !x.on;
					o.docAiChanged(x.areaId, on);
					toast(t(on ? 'drive.docAi.onDone' : 'drive.docAi.offDone', { area: DS.areaLabel(x.area, t) }), 'success');
					render();
				}), id);
			});
			kids.push(el('p', { class: 'dsv-foot dv-p', text: t('drive.settings.ai.vaults') }));
			return card('ai', t('drive.docAi.label'), null, kids);
		}

		// 4. Ansicht
		function view(p) {
			const id = nextId('dset-sort');
			const s = el('select', { class: 'inp dsv-select', 'aria-labelledby': id, 'data-key': 'view-sort', on: { change: () => { o.setSort(s.value); render(); } } });
			for (const k of DS.SORTS) {
				const x = el('option', { value: k, text: t(`drive.sort.${k}`) });
				if (k === p.sort) x.selected = true;
				s.appendChild(x);
			}
			return card('view', t('drive.settings.view.title'), null, [row(t('drive.settings.view.sort'), t('drive.settings.view.sortDesc'), s, id)]);
		}

		// 5. Daten auf diesem Gerät
		function data() {
			const desc = cache ? t('drive.settings.cache.size', { size: DS.formatBytes(cache.bytes, locale()) || '0 B' }) : t('drive.loading');
			const btn = el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-key': 'cache-clear', disabled: !cache || typeof api.clearCache !== 'function' ? true : null, text: t('drive.settings.cache.clear'), on: { click: clearCache } });
			return card('data', t('drive.settings.data.title'), null, [
				row(t('drive.settings.cache.label'), desc, btn),
				el('p', { class: 'dsv-foot dv-p', text: t('drive.settings.cache.never') }),
			]);
		}

		async function loadCache() {
			if (typeof api.cache !== 'function') return;
			const r = await Promise.resolve(api.cache()).catch(() => null);
			cache = r && r.ok ? r : null;
			if (shown) render();
		}

		async function clearCache() {
			const r = await call(() => api.clearCache());
			if (!r) return;
			if (typeof o.cacheCleared === 'function') o.cacheCleared();
			toast(r.kept ? t('drive.settings.cache.clearedKept', { count: r.kept }) : t('drive.settings.cache.cleared'), 'success');
			loadCache();
		}

		// 6. Benachrichtigungen
		function notifications() {
			const n = notify;
			const rows = n ? MS.notifyRows(n.topics, n.muted, t) : [];
			const kids = rows.map((x) => {
				const id = nextId('dset-n');
				return row(x.label, null, sw(`notify-${x.id}`, x.on, id, () => setTopic(x.id, !x.on)), id);
			});
			if (!kids.length) kids.push(el('p', { class: 'dv-p dset-empty', text: t(n ? 'drive.settings.notify.none' : 'drive.loading') }));
			return card('notify', t('drive.settings.notify.title'), t('drive.settings.notify.desc'), kids);
		}

		async function loadNotify() {
			const na = o.notifyApi;
			if (!na || typeof na.getPrefs !== 'function') { notify = { topics: [], muted: [] }; if (shown) render(); return; }
			const p = await Promise.resolve(na.getPrefs()).catch(() => null);
			notify = { topics: (p && Array.isArray(p.topics)) ? p.topics : [], muted: (p && Array.isArray(p.mutedTopics)) ? p.mutedTopics : [] };
			if (shown) render();
		}

		async function setTopic(id, on) {
			const na = o.notifyApi;
			if (!na || !notify) return;
			const mutedTopics = MS.toggleMuted(notify.muted, id, on);
			const r = await Promise.resolve(na.setPrefs({ mutedTopics })).catch(fail);
			if (r && r.ok) notify.muted = (r.prefs && Array.isArray(r.prefs.mutedTopics)) ? r.prefs.mutedTopics : mutedTopics;
			else toast(DS.errorText(r, t), 'error');
			render();
		}

		return {
			el: wrap,
			show() {
				shown = true;
				wrap.hidden = false;
				focusKey = null;
				if (o.syncView && o.syncView.showSettings) o.syncView.showSettings();
				render();
				loadCache();
				loadNotify();
				refreshLock();
			},
			hide() {
				shown = false;
				wrap.hidden = true;
				if (o.syncView && o.syncView.hideSettings) o.syncView.hideSettings();
			},
			refresh() { if (shown) { render(); loadCache(); refreshLock(); } },
			relabel() { if (shown) render(); },
			/** Scrolls to a section ('backup', 'vaults', 'ai', 'view', 'data', 'notify'). */
			focus(section) {
				const c = wrap.querySelector(`[data-section="${CSS.escape(String(section || ''))}"]`);
				if (c && typeof c.scrollIntoView === 'function') c.scrollIntoView({ block: 'start' });
			},
		};
	}

	root.GCDriveSettingsView = { mount };
})(typeof self !== 'undefined' ? self : this);
