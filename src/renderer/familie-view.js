/**
 * GateControl -- Familie (renderer view of the plugin gatecontrol-familie)
 *
 * "Internet zu Hause" for parents and children:
 * - "Internet zu Hause": a card per child — Internet an, pausiert bis …,
 *   heute länger bis …, nicht gefiltert, not readable —, where the child is
 *   (zu Hause · WLAN / App, unterwegs), the number of its devices, the note
 *   "Pausiert von der Regel …", and for parents the buttons with the dialogs
 *   "Pausieren" and "Heute länger". A child sees its own card, read only.
 * - "Regeln": the rules as a list (on / off) and a dialog for the action
 *   "Internet zu Hause" only; every other action of a rule is written back
 *   unchanged. Triggers and other actions are edited in the portal.
 * - "Meine Anwesenheit": "Anwesenheit teilen", "WLAN-Erkennung verwenden",
 *   the source of the current state and one's own devices in the home Wi-Fi.
 * "Internet zu Hause" pushes reload the page; a click on their toast opens it.
 *
 * Data: window.gatecontrol.familie (core FamilieService over IPC); texts:
 * familie.* of the core locales; view logic without DOM: familie-state.js
 * (window.GCFamilieState).
 *
 * Note: server text only ever goes into textContent / attributes; icons are
 * built from static path data with createElementNS (no innerHTML).
 */
(function (root) {
	'use strict';

	const FS = root.GCFamilieState;
	const NS = 'http://www.w3.org/2000/svg';
	const ICONS = {
		family: 'M9 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z|M2.5 20a6.5 6.5 0 0 1 13 0|M16 4.3a3.5 3.5 0 0 1 0 6.4|M18 14.2a6.5 6.5 0 0 1 3.5 5.8',
		refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8|M21 3v5h-5',
		alert: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 8v5M12 16h.01',
		wifi: 'M2 8.5a15 15 0 0 1 20 0|M5.5 12.5a10 10 0 0 1 13 0|M9 16.2a5 5 0 0 1 6 0|M12 20h.01',
		home: 'M3 11l9-7 9 7v9H3z|M9 20v-6h6v6',
		phone: 'M7 3h10v18H7z|M11 18h2',
		pin: 'M12 21s7-6.2 7-11a7 7 0 0 0-14 0c0 4.8 7 11 7 11z|M12 12a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z',
		pause: 'M9 5v14M15 5v14',
		play: 'M7 5l12 7-12 7z',
		clock: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z|M12 7v5l3 2',
		zap: 'M13 2L4 14h7l-1 8 9-12h-7z',
		cloudOff: 'M3 3l18 18|M8 8a5 5 0 0 0-2 9h11|M10 5a7 7 0 0 1 9 6 4 4 0 0 1 1 7',
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
			else n.setAttribute(k, v === true ? '' : String(v));
		}
		for (const c of kids || []) if (c !== null && c !== undefined && c !== false && c !== '') n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
		return n;
	}
	const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };

	let seq = 0;
	const nextId = (p) => `${p}-${++seq}`;

	/**
	 * @param {object} o
	 * @param {HTMLElement} o.root - the page section (empty)
	 * @param {object} o.api - window.gatecontrol.familie
	 * @param {Function} o.t - i18n
	 * @param {() => string} o.getLocale
	 * @param {(msg: string, type?: string) => void} [o.toast]
	 * @param {(st: object) => void} [o.onStatus] - availability (nav entry)
	 * @param {() => number} [o.now]
	 * @returns {{ show(), hide(), open(ctx), refresh(), status(), relabel() }}
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const now = typeof o.now === 'function' ? o.now : () => Date.now();
		const locale = () => o.getLocale();
		const toast = (msg, type) => { if (typeof o.toast === 'function') o.toast(msg, type || 'info'); };

		const S = {
			status: null,
			shown: false,
			tab: 'internet',
			internet: null,      // answer of api.internet()
			rules: null,         // answer of api.rules()
			options: null,       // answer of api.ruleOptions()
			presence: null,      // answer of api.presence()
			wifi: null,          // answer of api.wifi()
			errors: new Map(),   // what → result with ok:false
			loading: new Set(),
			busy: new Set(),     // 'child:<id>', 'rule:<id>', 'share', 'wifi', 'dev:<id>'
			dirty: true,
			focusChild: null,    // card to highlight (push target)
			focusRule: null,     // rule to highlight ("Regel öffnen")
			avatars: new Map(),  // url → Promise<objectURL|null>
			tick: null,          // timer: the next moment a card changes by itself
			poll: null,          // timer: while shown, the cards are asked again
		};

		// ── Skeleton ─────────────────────────────────────────
		const refs = {};
		const rootEl = el('div', { class: 'fv' });
		o.root.appendChild(rootEl);
		refs.h = el('h1', { class: 'fv-h', text: t('familie.title') });
		refs.sub = el('span', { class: 'fv-sub' });
		refs.tabs = el('div', { class: 'seg fv-tabs', role: 'tablist', 'aria-label': t('familie.tabs') });
		refs.refresh = el('button', { type: 'button', class: 'fv-ib', title: t('familie.refresh'), 'aria-label': t('familie.refresh'), on: { click: () => reload(true) } }, [icon('refresh', 16)]);
		refs.banner = el('div', { class: 'fv-banner', role: 'status', hidden: true });
		refs.body = el('div', { class: 'fv-body scroll' });
		rootEl.append(
			el('div', { class: 'fv-head' }, [
				el('div', { class: 'fv-head-tx' }, [refs.h, refs.sub]),
				refs.tabs,
				refs.refresh,
			]),
			refs.banner,
			refs.body,
		);

		// ── Time ─────────────────────────────────────────────
		/** { now (the server's), tz, locale } for the texts. */
		function ctx() {
			const i = S.internet && S.internet.internet;
			return { now: FS.serverNow(S.internet, now()), tz: (i && i.timezone) || null, locale: locale() };
		}

		// ── Avatars ──────────────────────────────────────────
		function avatarUrl(url) {
			if (!S.avatars.has(url)) {
				S.avatars.set(url, Promise.resolve(api.avatar(url)).then((r) => {
					if (!r || !r.ok || !r.data) return null;
					return URL.createObjectURL(new Blob([r.data], { type: r.mime || 'image/webp' }));
				}).catch(() => null));
			}
			return S.avatars.get(url);
		}

		function avatar(face, size) {
			const box = el('span', { class: 'fv-av', 'aria-hidden': 'true', style: `width:${size}px;height:${size}px;font-size:${Math.max(10, Math.round(size * 0.36))}px` });
			box.style.setProperty('--c', face.color);
			box.appendChild(el('span', { text: face.initials }));
			if (face.avatarUrl) {
				avatarUrl(face.avatarUrl).then((u) => {
					if (u) box.appendChild(el('img', { class: 'fv-av-img', src: u, alt: '', draggable: 'false' }));
				});
			}
			return box;
		}

		// ── Data ─────────────────────────────────────────────
		const tabs = () => FS.tabsFor(S.status, S.internet);
		const call = (fn, ...args) => Promise.resolve().then(() => fn(...args)).catch((err) => ({ ok: false, code: 'failed', error: err && err.message }));

		async function load(what, fn, refresh) {
			if (typeof fn !== 'function') return;
			S.loading.add(what);
			render();
			const res = await call(fn, { refresh });
			S.loading.delete(what);
			if (res && res.ok) {
				S[what] = res;
				S.errors.delete(what);
			} else {
				S.errors.set(what, res || { ok: false, code: 'failed' });
			}
			if (what === 'internet') fixTab();
			render();
			if (what === 'internet') schedule();
		}

		/** The tab may be gone with a new answer (role, modules, an adult child without a card). */
		function fixTab() {
			const have = tabs();
			if (have.length && !have.includes(S.tab)) { S.tab = have[0]; ensure(); }
		}

		function loadTab(tab, refresh) {
			if (tab === 'rules') return Promise.all([load('rules', api.rules, refresh), load('options', api.ruleOptions, refresh)]);
			if (tab === 'presence') return Promise.all([load('presence', api.presence, refresh), load('wifi', api.wifi, refresh)]);
			return Promise.resolve();
		}

		/** Load what the current tab needs (the cards always: they carry the time zone and decide the tabs). */
		function reload(refresh = false) {
			S.dirty = false;
			return Promise.all([load('internet', api.internet, refresh), loadTab(S.tab, refresh)]);
		}

		function ensure() {
			if (S.dirty) return reload(false);
			if (!S.internet && !S.loading.has('internet')) load('internet', api.internet, false);
			if (S.tab === 'rules' && !S.rules && !S.loading.has('rules')) loadTab('rules', false);
			if (S.tab === 'presence' && !S.presence && !S.loading.has('presence')) loadTab('presence', false);
			return Promise.resolve();
		}

		/** A pause / extra time ends, a blocked time starts: render then, and ask the server shortly after. */
		function schedule() {
			clearTimeout(S.tick);
			S.tick = null;
			if (!S.shown || !S.internet) return;
			const c = ctx();
			const at = FS.nextChange(S.internet.internet.children, c.now);
			if (at === null) return;
			S.tick = setTimeout(() => {
				render();
				setTimeout(() => { if (S.shown) load('internet', api.internet, true); }, 1500);
			}, Math.min(Math.max(at - c.now, 0) + 500, 2147000000));
		}

		async function refreshStatus() {
			const st = await Promise.resolve(api.status()).catch(() => null);
			if (st) setStatus(st);
		}

		function setStatus(st) {
			const was = S.status && S.status.state;
			const who = S.status && S.status.me ? `${S.status.me.userId}:${S.status.me.role}` : '';
			S.status = st;
			if (typeof o.onStatus === 'function') { try { o.onStatus(st); } catch { /* app */ } }
			const is = st && st.me ? `${st.me.userId}:${st.me.role}` : '';
			// The plugin back, a new server or another person: forget the old answers.
			if (st && st.state === 'available' && (was !== 'available' || who !== is)) {
				Object.assign(S, { internet: null, rules: null, options: null, presence: null, wifi: null, dirty: true });
				S.errors.clear();
				if (dlg.open) closeDialog();
				if (S.shown) reload(false);
			}
			fixTab();
			render();
		}

		// ── Changes ──────────────────────────────────────────

		/** The answer of a change replaces the child's card; `done(child)` is the text of the toast. */
		function applyChild(res, done) {
			if (!S.internet || !res.child) return;
			const list = S.internet.internet.children;
			const i = list.findIndex((c) => c.userId === res.child.userId);
			if (i >= 0) list[i] = res.child;
			render();
			schedule();
			if (done) toast(done(res.child), 'success');
			// the server's clock and the other cards
			load('internet', api.internet, true);
		}

		/** A change of a child's internet from a button of its card. */
		async function act(child, fn, done) {
			const key = `child:${child.userId}`;
			if (S.busy.has(key)) return;
			S.busy.add(key);
			render();
			const res = await call(fn);
			S.busy.delete(key);
			if (res && res.ok) { applyChild(res, done); return; }
			render();
			toast(FS.errorText(res, t), 'error');
		}

		function runButton(id, child) {
			const c = ctx();
			const name = child.name;
			if (id === 'pause') return openPause(child);
			if (id === 'extend') return openExtend(child);
			if (id === 'reload') return reload(true);
			if (id === 'resume') return act(child, () => api.resume(child.userId), () => t('familie.toast.resumed', { name }));
			if (id === 'add30') return act(child, () => api.pause(child.userId, { add: 30 }), (k) => t('familie.toast.paused', { name, time: FS.whenText(k.paused, c, t) }));
			if (id === 'extend30') return act(child, () => api.extend(child.userId, 30), (k) => t('familie.toast.extended', { name, time: FS.whenText(k.extended, c, t) }));
			if (id === 'endExtra') return act(child, () => api.extend(child.userId, 0), () => t('familie.toast.extraEnded', { name }));
			return null;
		}

		// ── Dialogs ──────────────────────────────────────────
		const dlg = { open: false, busy: false, error: '', prevFocus: null, render: null, submit: null };

		function buildDialog() {
			dlg.titleId = nextId('fv-dlg-h');
			dlg.box = el('div', { class: 'fv-dlg', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': dlg.titleId, tabindex: '-1' });
			dlg.scrim = el('div', { class: 'fv-scrim', hidden: true, on: { mousedown: (e) => { if (e.target === dlg.scrim && !dlg.busy) closeDialog(); } } }, [dlg.box]);
			dlg.scrim.addEventListener('keydown', (e) => {
				if (e.key === 'Escape' && !dlg.busy) { e.preventDefault(); e.stopPropagation(); closeDialog(); }
				if (e.key === 'Tab') trapFocus(e);
			});
			o.root.appendChild(dlg.scrim);
		}

		function trapFocus(e) {
			const items = [...dlg.box.querySelectorAll('button:not([disabled]), input:not([disabled])')].filter((n) => n.offsetParent !== null);
			if (!items.length) return;
			const first = items[0];
			const last = items[items.length - 1];
			if (e.shiftKey && (document.activeElement === first || document.activeElement === dlg.box)) { e.preventDefault(); last.focus(); }
			else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
		}

		/**
		 * A dialog: `build()` → { title, body: [nodes], submitLabel, canSubmit, extra: [nodes] };
		 * `submit()` → a result of the API (ok closes it, else its error is shown).
		 */
		function openDialog(build, submit) {
			const from = document.activeElement;
			const anchor = from && from.closest ? from.closest('[data-child], [data-rule]') : null;
			Object.assign(dlg, {
				open: true, busy: false, error: '', render: build, submit, prevFocus: from,
				prevKey: from && from.getAttribute ? from.getAttribute('data-k') : null,
				prevAnchor: anchor ? (anchor.hasAttribute('data-child') ? `[data-child="${anchor.getAttribute('data-child')}"]` : `[data-rule="${anchor.getAttribute('data-rule')}"]`) : null,
			});
			dlg.scrim.hidden = false;
			renderDialog();
			const first = dlg.box.querySelector('.fv-opt[aria-pressed="true"], .fv-opt, input');
			setTimeout(() => (first || dlg.box).focus(), 0);
		}

		function closeDialog() {
			dlg.open = false;
			dlg.scrim.hidden = true;
			clear(dlg.box);
			// back to the button the dialog came from — rebuilt meanwhile: the same one, else the first of its card / row
			const find = (sel) => (sel ? refs.body.querySelector(sel) : null);
			const back = (dlg.prevFocus && dlg.prevFocus.isConnected ? dlg.prevFocus : null)
				|| find(dlg.prevKey ? `[data-k="${dlg.prevKey}"]:not([disabled])` : null)
				|| find(dlg.prevAnchor ? `${dlg.prevAnchor} button:not([disabled])` : null);
			dlg.prevFocus = null;
			if (back && back.focus) { try { back.focus(); } catch { /* gone */ } }
		}

		/** Run the dialog's action (`run`: another one of the same dialog, e.g. "Aktion entfernen"). */
		async function submitDialog(run = dlg.submit) {
			if (!dlg.open || dlg.busy) return;
			dlg.busy = true;
			dlg.error = '';
			renderDialog();
			const res = await call(run);
			dlg.busy = false;
			if (!dlg.open) return;
			if (res && res.ok) { closeDialog(); return; }
			dlg.error = FS.errorText(res, t);
			renderDialog();
		}

		function renderDialog() {
			if (!dlg.open) return;
			// keep the focus on the same control across a re-render
			const act = document.activeElement;
			const keep = act && dlg.box.contains(act) ? act.getAttribute('data-k') : null;
			const d = dlg.render();
			clear(dlg.box);
			dlg.box.append(...[
				el('h2', { id: dlg.titleId, class: 'fv-dlg-h', text: d.title }),
				...d.body,
				dlg.error ? el('div', { class: 'fv-dlg-err', role: 'alert', text: dlg.error }) : null,
				el('div', { class: 'fv-dlg-acts' }, [
					...(d.extra || []),
					el('span', { class: 'fv-grow' }),
					el('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'data-k': 'cancel', text: t('familie.cancel'), disabled: dlg.busy, on: { click: () => closeDialog() } }),
					el('button', { type: 'button', class: 'btn btn-pri btn-sm', 'data-k': 'submit', text: d.submitLabel, disabled: dlg.busy || !d.canSubmit, on: { click: () => submitDialog() } }),
				]),
			].filter(Boolean));
			if (keep) {
				const again = dlg.box.querySelector(`[data-k="${keep}"]`);
				if (again && !again.disabled) again.focus();
				else dlg.box.focus();
			}
		}

		/** A row of choices: buttons with aria-pressed inside a labelled group. */
		function options(label, items, group) {
			const id = nextId('fv-lab');
			return [
				label ? el('div', { id, class: 'fv-lab', text: label }) : null,
				el('div', { class: 'fv-opts', role: 'group', 'aria-labelledby': label ? id : null, 'aria-label': label ? null : group }, items.map((it) => el('button', {
					type: 'button', class: `fv-opt${it.on ? ' is-on' : ''}`, 'aria-pressed': it.on ? 'true' : 'false', 'data-k': it.key, disabled: dlg.busy || it.disabled === true,
					title: it.title || null, on: { click: () => { it.pick(); renderDialog(); } },
				}, [it.face ? avatar(it.face, 22) : null, el('span', { text: it.label })]))),
			].filter(Boolean);
		}

		function timeField(label, value, onInput) {
			const id = nextId('fv-time');
			const input = el('input', { id, type: 'time', class: 'fv-in', value, 'data-k': 'time', disabled: dlg.busy, step: '300' });
			input.addEventListener('input', () => { onInput(input.value); refreshHint(); });
			input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); submitDialog(); } });
			return el('div', { class: 'fv-time' }, [el('label', { class: 'fv-sub', for: id, text: label }), input]);
		}

		/** The hint and the submit button follow the time field without rebuilding it (the field keeps its caret). */
		function refreshHint() {
			const d = dlg.render();
			const hint = dlg.box.querySelector('.fv-dlg-hint');
			if (hint && d.hint !== undefined) hint.textContent = d.hint;
			const ok = dlg.box.querySelector('[data-k="submit"]');
			if (ok) ok.disabled = dlg.busy || !d.canSubmit;
		}

		const hintLine = (text) => el('div', { class: 'fv-sub fv-dlg-hint', text });
		const durLabel = (c) => (c === 'until' ? t('familie.pause.until') : FS.durationText(c, t));

		function openPause(child) {
			const f = { choice: 30, time: FS.defaultUntil(ctx().now, ctx().tz) };
			openDialog(() => {
				const c = ctx();
				const hint = FS.pauseHint(f.choice, f.time, child.name, c, t);
				return {
					title: t('familie.pause.title', { name: child.name }),
					hint,
					body: [
						...options(null, FS.PAUSE_CHOICES.map((x) => ({ key: `d${x}`, label: durLabel(x), on: f.choice === x, pick: () => { f.choice = x; } })), t('familie.pause.howLong')),
						f.choice === 'until' ? timeField(t('familie.pause.untilLabel'), f.time, (v) => { f.time = v; }) : null,
						hintLine(hint),
					].filter(Boolean),
					submitLabel: t('familie.btn.pause'),
					canSubmit: !!FS.pauseArgs(f.choice, f.time),
				};
			}, async () => {
				const res = await call(api.pause, child.userId, FS.pauseArgs(f.choice, f.time));
				if (res && res.ok) applyChild(res, (k) => t('familie.toast.paused', { name: child.name, time: FS.whenText(k.paused, ctx(), t) }));
				return res;
			});
		}

		function openExtend(child) {
			const f = { minutes: 30, fromNow: false };
			openDialog(() => {
				const c = ctx();
				const plan = FS.extendPlan(child, c.now, c.tz);
				const hint = FS.extendHint(child, f.minutes, f.fromNow, child.name, c, t);
				return {
					title: t('familie.extend.title', { name: child.name }),
					hint,
					body: [
						...options(null, FS.EXTEND_CHOICES.map((x) => ({ key: `d${x}`, label: FS.durationText(x, t), on: f.minutes === x, pick: () => { f.minutes = x; } })), t('familie.extend.howLong')),
						...(plan.choose ? options(t('familie.extend.from'), [
							{ key: 'sched', label: t('familie.extend.fromSchedule', { time: FS.hm(plan.from, c.tz) }), on: !f.fromNow, pick: () => { f.fromNow = false; } },
							{ key: 'now', label: t('familie.extend.fromNow'), on: f.fromNow, pick: () => { f.fromNow = true; } },
						]) : []),
						hintLine(hint),
					],
					submitLabel: t('familie.extend.submit'),
					canSubmit: true,
				};
			}, async () => {
				const res = await call(api.extend, child.userId, f.minutes, { fromNow: f.fromNow });
				if (res && res.ok) applyChild(res, (k) => t('familie.toast.extended', { name: child.name, time: FS.whenText(k.extended, ctx(), t) }));
				return res;
			});
		}

		/** The dialog of a rule's action "Internet zu Hause" (one action at a time; "Neue Aktion" adds one). */
		function openRule(rule) {
			const net = (S.options && S.options.internet) || { available: false, children: [] };
			const mine = FS.internetActions(rule);
			const f = { index: mine.length ? mine[0].index : null, form: FS.formOf(mine.length ? mine[0].action : null, net.children) };
			const pick = (index) => {
				f.index = index;
				const a = index === null ? null : rule.actions[index];
				f.form = FS.formOf(a, net.children);
			};
			const canAdd = rule.actions.length < FS.MAX_ACTIONS;
			const save = async (list) => {
				if (!list) return { ok: false, code: 'invalid' };
				const res = await call(api.setRuleActions, rule.id, list);
				if (res && res.ok) {
					putRule(res.rule);
					toast(t('familie.rules.saved'), 'success');
				}
				return res;
			};
			openDialog(() => {
				const people = S.options && S.options.people;
				const kids = net.children.map((k) => ({ userId: k.userId, face: FS.faceOf(k), name: k.name }));
				// a child the action names but that is no longer offered (grown up, left the family)
				const cur = f.index === null ? null : rule.actions[f.index];
				if (cur && cur.userId && !kids.some((k) => k.userId === cur.userId)) kids.push({ userId: cur.userId, face: FS.faceOf({ userId: cur.userId, name: cur.name }), name: t('familie.rules.dialog.gone', { name: cur.name || '?' }), gone: true });
				const body = FS.actionBody(f.form);
				const gone = kids.some((k) => k.gone && k.userId === f.form.userId);
				const me = S.status && S.status.me ? S.status.me.name : '';
				const hint = f.form.op === 'pause' && f.form.choice === 'until'
					? t('familie.rules.dialog.untilHint')
					: t(f.form.op === 'resume' ? 'familie.rules.dialog.onBehalfResume' : 'familie.rules.dialog.onBehalf', { name: me });
				const only = rule.actions.length <= 1;
				return {
					title: t('familie.rules.dialog.title'),
					hint,
					body: [
						...(mine.length ? options(t('familie.rules.dialog.which'), [
							...mine.map((m) => ({ key: `a${m.index}`, label: FS.actionText(m.action, people, t), on: f.index === m.index, pick: () => pick(m.index) })),
							{ key: 'anew', label: t('familie.rules.dialog.new'), on: f.index === null, disabled: !canAdd, title: canAdd ? null : t('familie.rules.dialog.full'), pick: () => pick(null) },
						]) : []),
						...options(t('familie.rules.dialog.who'), kids.map((k) => ({ key: `u${k.userId}`, label: k.name, face: k.face, on: f.form.userId === k.userId, disabled: k.gone === true, pick: () => { f.form.userId = k.userId; } }))),
						...options(t('familie.rules.dialog.what'), ['pause', 'resume'].map((op) => ({ key: op, label: t(`familie.rules.dialog.op.${op}`), on: f.form.op === op, pick: () => { f.form.op = op; } }))),
						...(f.form.op === 'pause' ? options(t('familie.rules.dialog.howLong'), FS.ruleChoices(f.form).map((x) => ({ key: `d${x}`, label: durLabel(x), on: f.form.choice === x, pick: () => { f.form.choice = x; if (x === 'until' && !f.form.until) f.form.until = '18:00'; } }))) : []),
						f.form.op === 'pause' && f.form.choice === 'until' ? timeField(t('familie.rules.dialog.untilLabel'), f.form.until, (v) => { f.form.until = v; }) : null,
						hintLine(hint),
					].filter(Boolean),
					extra: f.index !== null ? [el('button', {
						type: 'button', class: 'btn btn-danger btn-sm', 'data-k': 'remove', text: t('familie.rules.dialog.remove'), disabled: dlg.busy || only,
						title: only ? t('familie.rules.dialog.onlyAction') : null,
						on: { click: () => submitDialog(() => save(FS.withAction(rule, f.index, null))) },
					})] : [],
					submitLabel: t('familie.rules.dialog.save'),
					canSubmit: !!body && !gone,
				};
			}, () => save(FS.withAction(rule, f.index, FS.actionBody(f.form))));
		}

		function putRule(rule) {
			if (!S.rules || !rule) return;
			const i = S.rules.rules.findIndex((r) => r.id === rule.id);
			if (i >= 0) S.rules.rules[i] = rule;
			render();
		}

		async function toggleRule(rule) {
			const key = `rule:${rule.id}`;
			if (S.busy.has(key)) return;
			S.busy.add(key);
			render();
			const res = await call(api.setRuleActive, rule.id, !rule.active);
			S.busy.delete(key);
			if (res && res.ok) {
				putRule(res.rule);
				toast(t(res.rule.active ? 'familie.rules.on' : 'familie.rules.off'), 'success');
			} else {
				render();
				toast(FS.errorText(res, t), 'error');
			}
			const sw = refs.body.querySelector(`.fv-li[data-rule="${rule.id}"] .sw`);
			if (sw) sw.focus();
		}

		/** A switch of "Meine Anwesenheit": `fn()` → answer, `apply(res)` puts it into the state. */
		async function flip(key, fn, apply) {
			if (S.busy.has(key)) return;
			S.busy.add(key);
			render();
			const res = await call(fn);
			S.busy.delete(key);
			if (res && res.ok) apply(res);
			else toast(FS.errorText(res, t), 'error');
			render();
			const sw = refs.body.querySelector(`[data-sw="${key}"]`);
			if (sw) sw.focus();
			// the state ("zu Hause seit …", its source) follows the switches
			if (res && res.ok) load('presence', api.presence, true);
		}

		// ── Render ───────────────────────────────────────────
		function render() {
			renderHead();
			renderBody();
		}

		function renderHead() {
			const st = S.status;
			const c = ctx();
			refs.sub.textContent = [FS.dateLong(c.now, c), st && st.me ? st.me.name : ''].filter(Boolean).join(' · ');
			const have = tabs();
			clear(refs.tabs);
			refs.tabs.hidden = have.length < 2;
			for (const tab of have) {
				refs.tabs.appendChild(el('button', {
					type: 'button', role: 'tab', id: `fv-tab-${tab}`, class: S.tab === tab ? 'on' : '', 'aria-selected': S.tab === tab ? 'true' : 'false', text: t(`familie.tab.${tab}`),
					on: { click: () => setTab(tab) },
				}));
			}
			const stale = [S.internet, S.rules, S.presence, S.wifi].some((r) => r && r.stale);
			refs.banner.hidden = !stale;
			clear(refs.banner);
			if (stale) refs.banner.append(icon('cloudOff', 15), el('span', { text: t('familie.stale') }));
			refs.refresh.disabled = S.loading.size > 0;
			refs.refresh.classList.toggle('is-busy', S.loading.size > 0);
		}

		function setTab(tab) {
			if (S.tab === tab) return;
			S.tab = tab;
			S.focusChild = null;
			if (tab !== 'rules') S.focusRule = null;
			render();
			ensure();
			const b = refs.tabs.querySelector('button.on');
			if (b && document.activeElement && refs.tabs.contains(document.activeElement)) b.focus();
		}

		function stateBox(kind, title, hint, action) {
			return el('div', { class: `fv-state${kind === 'error' ? ' is-error' : ''}` }, [
				icon(kind === 'error' ? 'alert' : 'family', 34, '1.6'),
				el('strong', { text: title }),
				hint ? el('span', { text: hint }) : null,
				action ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: action.label, on: { click: action.run } }) : null,
			]);
		}

		/** Loading / error of `what`, or null when its answer is there. */
		function pending(what) {
			if (S[what]) return null;
			const err = S.errors.get(what);
			if (err && err.code === 'module_off') return stateBox('info', t('familie.off.title'), t('familie.off.hint'));
			if (err) return stateBox('error', FS.errorText(err, t), null, { label: t('familie.retry'), run: () => reload(true) });
			return el('div', { class: 'fv-loading', role: 'status', text: t('familie.loading') });
		}

		function renderBody() {
			// a re-render must not take the keyboard focus away
			const act = document.activeElement;
			const keep = act && refs.body.contains(act) ? act.getAttribute('data-k') : null;
			const top = refs.body.scrollTop;
			clear(refs.body);
			const st = S.status;
			if (st && st.state === 'unavailable') {
				refs.body.appendChild(stateBox('info', t('familie.unavailable.title'), t('familie.unavailable.hint')));
				return;
			}
			if (S.tab === 'rules') renderRules();
			else if (S.tab === 'presence') renderPresence();
			else renderInternet();
			refs.body.scrollTop = top;
			if (keep) {
				const again = refs.body.querySelector(`[data-k="${keep}"]`);
				if (again && !again.disabled) again.focus();
			}
		}

		// ── Tab: Internet zu Hause ───────────────────────────
		function renderInternet() {
			const wait = pending('internet');
			if (wait) { refs.body.appendChild(wait); return; }
			const i = S.internet.internet;
			if (!i.available) {
				refs.body.appendChild(stateBox('info', t('familie.internet.none.title'), i.supported === false ? t('familie.internet.none.old') : t('familie.internet.none.hint')));
				return;
			}
			if (!i.children.length) {
				refs.body.appendChild(stateBox('info', t('familie.internet.empty.title'), t(i.manage ? 'familie.internet.empty.parent' : 'familie.internet.empty.child')));
				return;
			}
			const c = { ...ctx(), manage: i.manage };
			const canOpenRule = tabs().includes('rules');
			const grid = el('div', { class: 'fv-grid' });
			for (const child of i.children) {
				const v = FS.cardView(child, c, t);
				const busy = S.busy.has(`child:${child.userId}`);
				const card = el('div', { class: `fv-card is-${v.state}${S.focusChild === child.userId ? ' is-focus' : ''}`, 'data-child': child.userId, role: 'group', 'aria-label': v.face.name }, [
					el('div', { class: 'fv-kid' }, [
						avatar(v.face, 38),
						el('div', { class: 'fv-kid-tx' }, [
							el('div', { class: 'fv-kid-n' }, [
								el('b', { text: v.face.name }),
								el('span', { class: `fv-chip ${v.chip.cls}`, text: v.chip.text }),
								v.presence ? el('span', { class: 'fv-chip is-mute' }, [icon(v.presence.icon, 13), el('span', { text: v.presence.text })]) : null,
							]),
							el('div', { class: 'fv-sub', text: v.sub }),
						]),
					]),
					v.note ? el('div', { class: `fv-note ${v.state === 'extended' ? 'is-info' : 'is-warn'}` }, [
						icon('zap', 16),
						el('div', {}, [
							el('span', { text: v.note.text }),
							v.note.title ? ' ' : null,
							v.note.title ? el('b', { text: v.note.title }) : null,
							v.note.tail ? el('span', { text: `\u00A0· ${v.note.tail}` }) : null,
							canOpenRule ? el('br') : null,
							canOpenRule ? el('button', { type: 'button', class: 'fv-link', 'data-k': `rule-${child.userId}`, text: t('familie.internet.openRule'), on: { click: () => showRule(v.note.ruleId) } }) : null,
						]),
					]) : null,
					v.buttons.length ? el('div', { class: 'fv-btns' }, v.buttons.map((id) => el('button', {
						type: 'button', class: `btn btn-sm ${id === 'resume' ? 'btn-pri' : 'btn-sec'}`, 'data-k': `${id}-${child.userId}`, disabled: busy,
						on: { click: () => runButton(id, child) },
					}, [
						id === 'pause' ? icon('pause', 14) : id === 'extend' ? icon('clock', 14) : id === 'resume' ? icon('play', 14) : id === 'reload' ? icon('refresh', 14) : null,
						el('span', { text: t(`familie.btn.${id}`) }),
					]))) : null,
				]);
				card.style.setProperty('--c', v.face.color);
				grid.appendChild(card);
			}
			refs.body.append(grid, el('div', { class: 'fv-foot', text: t(i.manage ? 'familie.internet.foot.parent' : 'familie.internet.foot.child') }));
			if (S.focusChild != null) {
				const target = grid.querySelector('.fv-card.is-focus');
				if (target && typeof target.scrollIntoView === 'function') target.scrollIntoView({ block: 'nearest' });
			}
		}

		/** "Regel öffnen": the rule list on that rule. */
		function showRule(ruleId) {
			S.focusRule = ruleId;
			S.tab = 'rules';
			render();
			ensure().then(() => focusRule());
			focusRule();
		}

		function focusRule() {
			if (S.focusRule == null) return;
			const row = refs.body.querySelector(`.fv-li[data-rule="${S.focusRule}"]`);
			if (!row) return;
			if (typeof row.scrollIntoView === 'function') row.scrollIntoView({ block: 'nearest' });
			const b = row.querySelector('.btn:not([disabled]), .sw:not([disabled])');
			if (b) b.focus();
		}

		// ── Tab: Regeln ──────────────────────────────────────
		function renderRules() {
			const wait = pending('rules');
			if (wait) { refs.body.appendChild(wait); return; }
			const rules = S.rules.rules;
			if (!rules.length) {
				refs.body.appendChild(stateBox('info', t('familie.rules.empty.title'), t('familie.rules.empty.hint')));
				return;
			}
			const opts = S.options || null;
			const list = el('div', { class: 'fv-list', role: 'list' });
			for (const rule of rules) {
				const v = FS.ruleRow(rule, opts, locale(), t);
				const busy = S.busy.has(`rule:${rule.id}`);
				list.appendChild(el('div', { class: `fv-li${S.focusRule === rule.id ? ' is-focus' : ''}${v.active ? '' : ' is-off'}`, role: 'listitem', 'data-rule': rule.id }, [
					icon('zap', 18),
					el('div', { class: 'fv-li-tx' }, [
						el('b', { text: v.title }),
						el('span', { text: v.summary }),
						v.problems.length ? el('span', { class: 'fv-chip is-warn', title: v.problems.join(' · '), text: t('familie.rules.unavailable') }) : null,
						v.problems.length ? el('span', { class: 'sr-only', text: v.problems.join('. ') }) : null,
					]),
					el('button', {
						type: 'button', class: `sw${v.active ? ' on' : ''}`, role: 'switch', 'aria-checked': v.active ? 'true' : 'false', 'data-k': `sw-${rule.id}`,
						'aria-label': t('familie.rules.active', { title: v.title }), disabled: busy || !v.canToggle, on: { click: () => toggleRule(rule) },
					}, [el('span')]),
					el('button', {
						type: 'button', class: 'btn btn-sec btn-sm', 'data-k': `edit-${rule.id}`, text: t('familie.rules.edit'), disabled: busy || !v.canEdit || !opts,
						title: v.editOff ? t(`familie.rules.editOff.${v.editOff}`) : null, 'aria-label': t('familie.rules.editNamed', { title: v.title }),
						on: { click: () => openRule(rule) },
					}),
				]));
			}
			refs.body.append(list, el('div', { class: 'fv-foot', text: t('familie.rules.foot') }));
		}

		// ── Tab: Meine Anwesenheit ───────────────────────────
		function switchRow(o2) {
			return el('div', { class: 'fv-li' }, [
				o2.icon ? icon(o2.icon, 18) : null,
				el('div', { class: 'fv-li-tx' }, [el('b', { id: o2.id, text: o2.title }), o2.hint ? el('span', { text: o2.hint }) : null]),
				o2.side ? el('span', { class: 'fv-sub', text: o2.side }) : null,
				el('button', {
					type: 'button', class: `sw${o2.on ? ' on' : ''}`, role: 'switch', 'aria-checked': o2.on ? 'true' : 'false', 'aria-labelledby': o2.id, 'data-sw': o2.key, 'data-k': o2.key,
					disabled: S.busy.has(o2.key), on: { click: o2.flip },
				}, [el('span')]),
			]);
		}

		function renderPresence() {
			const wait = pending('presence');
			if (wait) { refs.body.appendChild(wait); return; }
			const p = S.presence;
			const w = (S.wifi && S.wifi.wifi) || { available: false, consent: false, devices: [] };
			const c = ctx();
			const list = el('div', { class: 'fv-list' });
			list.appendChild(switchRow({
				key: 'share', id: nextId('fv-sw'), icon: 'home', title: t('familie.presence.share.title'), hint: t('familie.presence.share.hint'), on: p.me.share,
				flip: () => flip('share', () => api.setShare(!p.me.share), (res) => { p.me.share = res.share === true; if (res.self) p.self = res.self; }),
			}));
			// the server knows no Wi-Fi detection: no switch
			if (p.me.wifi !== null) {
				list.appendChild(switchRow({
					key: 'wifi', id: nextId('fv-sw'), icon: 'wifi', title: t('familie.presence.wifi.title'), hint: t('familie.presence.wifi.hint'), on: p.me.wifi,
					flip: () => flip('wifi', () => api.setWifi(!p.me.wifi), (res) => { p.me.wifi = res.wifi.consent; S.wifi = { ...(S.wifi || {}), ok: true, wifi: res.wifi }; }),
				}));
			}
			const src = FS.sourceChip(p.self, t);
			list.appendChild(el('div', { class: 'fv-li' }, [
				el('div', { class: 'fv-li-tx' }, [el('span', { text: t('familie.presence.now') }), el('b', { text: FS.ownStateText(p.self, c, t) })]),
				src ? el('span', { class: `fv-chip ${src.cls}` }, [icon(src.icon, 13), el('span', { text: src.text })]) : null,
			]));
			refs.body.appendChild(list);

			if (p.me.wifi === null) return;
			if (!p.me.wifi || !w.available) {
				refs.body.appendChild(el('div', { class: 'fv-foot', text: t('familie.presence.wifi.off') }));
				return;
			}
			const card = el('div', { class: 'fv-card fv-devs' }, [el('h2', { class: 'fv-card-h', text: t('familie.presence.devices.title') })]);
			if (!w.devices.length) {
				card.appendChild(el('div', { class: 'fv-sub', text: t('familie.presence.devices.empty') }));
			} else {
				const rows = el('div', { class: 'fv-list' });
				for (const d of w.devices) {
					const v = FS.deviceRow(d, c, t);
					const key = `dev:${d.id}`;
					rows.appendChild(switchRow({
						key, id: nextId('fv-sw'), icon: 'phone', title: v.name, hint: v.meta, side: v.countsText, on: v.counts,
						flip: () => flip(key, () => api.setWifiDevice(d.id, !d.counts), (res) => { S.wifi = { ...(S.wifi || {}), ok: true, wifi: res.wifi }; }),
					}));
				}
				card.appendChild(rows);
			}
			card.appendChild(el('div', { class: 'fv-foot', text: t('familie.presence.devices.foot') }));
			refs.body.appendChild(card);
		}

		// ── Events ───────────────────────────────────────────
		buildDialog();
		if (typeof api.onState === 'function') api.onState((st) => setStatus(st));
		if (typeof api.onPush === 'function') {
			api.onPush(() => {
				// A pause set, ended or run out: the core dropped its copy.
				S.dirty = true;
				if (S.shown) load('internet', api.internet, true).then(() => { S.dirty = false; });
			});
		}
		refreshStatus();
		render();

		return {
			show() {
				S.shown = true;
				render();
				// back on the page: the cards may have changed meanwhile (the core keeps answers for a few seconds)
				if (!S.dirty && S.internet && !S.loading.has('internet')) load('internet', api.internet, false);
				ensure();
				schedule();
				clearInterval(S.poll);
				// Parents get no push about what the other parent or a rule did: ask now and then.
				S.poll = setInterval(() => { if (S.shown && !dlg.open && !S.loading.has('internet')) load('internet', api.internet, true); }, 60000);
			},
			hide() {
				S.shown = false;
				S.focusChild = null;
				S.focusRule = null;
				clearInterval(S.poll);
				clearTimeout(S.tick);
				S.poll = null;
				S.tick = null;
				if (dlg.open && !dlg.busy) closeDialog();
			},
			/** Open on a target (context of a push from notify:navigate / an inbox entry). */
			open(c) {
				const target = FS.openTarget(c, tabs());
				S.tab = target.tab;
				S.focusChild = target.childId;
				S.focusRule = target.ruleId;
				S.dirty = true;
				render();
				if (S.shown) ensure();
			},
			refresh: () => reload(true),
			status: () => S.status,
			/** Language changed: static labels, then everything else. */
			relabel() {
				refs.h.textContent = t('familie.title');
				refs.refresh.title = t('familie.refresh');
				refs.refresh.setAttribute('aria-label', t('familie.refresh'));
				refs.tabs.setAttribute('aria-label', t('familie.tabs'));
				render();
				renderDialog();
			},
		};
	}

	root.GCFamilieView = { mount };
})(typeof self !== 'undefined' ? self : this);
