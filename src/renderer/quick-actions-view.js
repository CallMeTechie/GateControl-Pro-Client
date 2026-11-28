/**
 * GateControl -- Start: the plugins' quick actions pinned as cards (renderer)
 *
 * Part of the section "Angeheftet" on the start page (home-view.js draws the
 * section, this file the cards and the dialog "Schnellaktionen anheften").
 * One card per device, like the Android app's widget card: icon, name, the
 * badge (a battery, a valve) and the power switch in the head; then the main
 * value (a temperature with the house and the outdoor reading beside it),
 * the small readings, the status line, the day bar (widget.timeline: the
 * segments, a mark for now, the axis 0 6 12 18 24), the controls (stepper,
 * slider, choice — greyed out and sending nothing while the plugin lists them
 * disabled; a choice without a selection shows none) and the device's other
 * actions as a row of buttons (logic chains too; not the plain button carrying
 * the widget — a toggle carrying it that is not the power switch stays one). × loosens the card; the
 * dialog pins devices and hides the parts a card should not show.
 *
 * Data: window.gatecontrol.quickActions (core QuickActionsService in main:
 * list(), run(plugin, id, how)). A stepper is sent 600 ms after the last
 * click (one request for "+ + +"), a slider when it is let go, a choice at
 * once; the plugin's answer (its new widget) replaces the card. A refusal
 * "control_disabled" (409) says so and asks the list again. A server without
 * quick actions (before they existed) shows neither the cards nor the button.
 *
 * What is pinned is kept on this PC (gc.home.pins → actions, window.GCHomePins).
 * Pure logic in quick-actions-state.js (GCQuickActionsState). Server text only
 * into textContent / attributes; icons are SVG path data the core checked.
 */
(function (root) {
	'use strict';

	const QS = root.GCQuickActionsState;
	const NS = 'http://www.w3.org/2000/svg';
	const DEBOUNCE_MS = 600;
	const RELOAD_MS = 60 * 1000;
	const AFTER_RUN_MS = 1500;
	const RETRY_MS = 15 * 1000;
	// house with thermometer (the temperature inside), sun and cloud (outside) — like the Android card
	const HOUSE_THERMO = 'M3 11l9-7 9 7|M5 10v10h8|M18 13v5.5|M16 18.5a2 2 0 1 0 4 0a2 2 0 1 0-4 0|M18 13a1 1 0 0 1 1 1v4.5';
	const CLOUD_SUN = 'M12 4V2|M5.6 6.6 4.2 5.2|M18.4 6.6l1.4-1.4|M8 11a4 4 0 0 1 7.5-2|M7 20h10a3.5 3.5 0 0 0 0-7h-.5A5 5 0 0 0 7 14a3 3 0 0 0 0 6z';

	/** An SVG of path data ('|' separates several paths; 24×24, stroke). */
	function glyph(d, size = 18) {
		const s = document.createElementNS(NS, 'svg');
		for (const [k, v] of [['viewBox', '0 0 24 24'], ['width', String(size)], ['height', String(size)], ['fill', 'none'], ['stroke', 'currentColor'],
			['stroke-width', '2'], ['stroke-linecap', 'round'], ['stroke-linejoin', 'round'], ['aria-hidden', 'true']]) s.setAttribute(k, v);
		for (const part of String(d || QS.BOLT).split('|')) {
			const p = document.createElementNS(NS, 'path');
			p.setAttribute('d', part);
			s.appendChild(p);
		}
		return s;
	}

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.quickActions
	 * @param {object} o.pins - window.GCHomePins
	 * @param {Function} o.t
	 * @param {() => string} o.getLocale
	 * @param {(msg: string, type?: string) => void} o.toast
	 * @param {() => void} o.onChange - the section draws again (cards() / available() changed)
	 */
	function create(o) {
		const { api, pins, t } = o;
		const { el, icon, clear, openDialog, sw } = root.GCMailUI;
		const lang = () => (o.getLocale && o.getLocale() === 'en' ? 'en' : 'de');
		const call = (p) => Promise.resolve(p).catch(() => ({ ok: false, reason: 'failed' }));

		const S = {
			load: 'idle',        // idle | loading | ok | unsupported | error
			actions: [],
			devices: [],
			offline: false,
			loadedAt: 0,
			running: new Set(),  // action keys on their way
			local: new Map(),    // `${actionKey}/${controlId}` → the value shown until the answer
			timers: new Map(),   // the same key → debounce timer
		};
		const cards = new Map();   // device key → card element (drawn again when its data changes)
		let dialog = null;
		let loading = null;

		// ── Loading ──────────────────────────────────────

		function setActions(list) {
			S.actions = list;
			S.devices = QS.group(list);
			const now = pins.actions();
			const synced = QS.syncPins(now, S.devices);
			if (synced !== now) pins.setActions(synced);
		}

		function refresh() {
			if (loading) return loading;
			if (S.load === 'idle') S.load = 'loading';
			loading = call(api.list()).then((r) => {
				loading = null;
				S.loadedAt = Date.now();
				if (r && r.ok && r.supported === false) {
					S.load = 'unsupported';
					setActions([]);
				} else if (r && r.ok) {
					S.load = 'ok';
					S.offline = !!r.offline;
					setActions(Array.isArray(r.actions) ? r.actions : []);
				} else {
					S.load = 'error';
					S.offline = true;
				}
				cards.clear();
				o.onChange();
				if (dialog && !dialog.closed) syncPicker();
			});
			return loading;
		}

		// ── Running ──────────────────────────────────────

		const findAction = (key) => S.actions.find((a) => QS.actionKey(a) === key) || null;

		/** The answer of a run into the list: a toggle's new state, the carrier's new widget. */
		function apply(a, res) {
			const cur = findAction(QS.actionKey(a));
			if (!cur) return;
			if (res.state && QS.isToggle(cur)) cur.state = res.state;
			if (res.widget) cur.widget = res.widget;
			S.devices = QS.group(S.actions);
		}

		let afterRun = null;
		function settle(a, res, title) {
			if (res && res.ok) {
				apply(a, res);
				if (res.message) o.toast(t('home.qa.error.message', { name: title, message: res.message }), 'info');
				else if (!QS.isToggle(a)) o.toast(t('home.qa.done', { name: title }), 'success');
			} else {
				o.toast(QS.failureText(res, title, t), 'error');
			}
			redraw(QS.deviceKey(a));
			clearTimeout(afterRun);
			afterRun = setTimeout(refresh, res && QS.reloadAfter(res) ? 0 : AFTER_RUN_MS);
		}

		async function run(a) {
			const key = QS.actionKey(a);
			if (S.running.has(key)) return;
			if (QS.needsConfirm(a) && !(await confirmRun(a))) { redraw(QS.deviceKey(a)); return; }
			S.running.add(key);
			redraw(QS.deviceKey(a));
			const res = await call(api.run(a.plugin, a.id, QS.isToggle(a) ? { state: QS.target(a) } : {}));
			S.running.delete(key);
			settle(a, res, a.title);
		}

		function confirmRun(a) {
			return new Promise((resolve) => {
				const dlg = openDialog({ title: t('home.qa.confirm.title', { name: a.title }), closeLabel: t('home.qa.confirm.cancel'), onClose: (v) => resolve(v === true) });
				dlg.box.classList.add('qa-confirm');
				if (a.subtitle) dlg.body.append(el('p', { class: 'qa-confirm-sub', text: a.subtitle }));
				dlg.foot.append(
					el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('home.qa.confirm.cancel'), on: { click: () => dlg.close(false) } }),
					el('button', { type: 'button', class: 'btn btn-pri btn-sm', 'data-qa-confirm': '', text: t('home.qa.confirm.run'), on: { click: () => dlg.close(true) } }),
				);
			});
		}

		/** A control moved: shown at once, sent after `delay` (stepper: the last of several clicks). */
		function control(d, c, value, delay) {
			if (c.disabled || !d.carrier) return;
			const carrier = d.carrier;
			const k = `${QS.actionKey(carrier)}/${c.id}`;
			S.local.set(k, value);
			clearTimeout(S.timers.get(k));
			S.timers.set(k, setTimeout(async () => {
				S.timers.delete(k);
				const res = await call(api.run(carrier.plugin, carrier.id, { control: c.id, value }));
				// a newer value is on its way: that one's answer counts
				if (S.timers.has(k)) return;
				S.local.delete(k);
				if (res && res.ok) {
					apply(carrier, res);
					redraw(d.key);
					if (res.message) o.toast(t('home.qa.error.message', { name: d.title, message: res.message }), 'info');
				} else {
					o.toast(QS.failureText(res, d.title, t), 'error');
					redraw(d.key);
					if (QS.reloadAfter(res)) refresh();
				}
			}, delay));
		}

		// ── Drawing a card ───────────────────────────────

		const pinned = () => pins.actions();

		/** Draws one card again in place (the focus stays on the same control). */
		function redraw(key) {
			const old = cards.get(key);
			cards.delete(key);
			if (!old || !old.isConnected) { o.onChange(); return; }
			const pin = pinned().find((p) => p.device === key || QS.resolve(p, S.devices)?.key === key);
			if (!pin) { o.onChange(); return; }
			const focus = document.activeElement && old.contains(document.activeElement) ? document.activeElement.getAttribute('data-fk') : null;
			const card = cardFor(pin);
			old.replaceWith(card);
			if (focus) {
				const f = card.querySelector(`[data-fk="${CSS.escape(focus)}"]`);
				if (f && !f.disabled) f.focus();
			}
		}

		function cardFor(pin) {
			const d = QS.resolve(pin, S.devices);
			const key = d ? d.key : pin.device;
			if (cards.has(key)) return cards.get(key);
			const card = d ? deviceCard(d, pin) : missingCard(pin);
			cards.set(key, card);
			return card;
		}

		function unpinButton(key, name) {
			return el('button', { type: 'button', class: 'btn btn-ghost home-x', 'data-fk': 'unpin', title: t('home.qa.unpin', { name }), 'aria-label': t('home.qa.unpin', { name }),
				on: { click: () => pins.pinDevice(key, null, false) } }, [icon('close', 13)]);
		}

		function missingCard(pin) {
			const name = pin.title || pin.device;
			let text = t('home.qa.loading');
			if (S.load === 'ok' && !S.offline) text = t('home.qa.gone');
			else if (S.load === 'error' || S.offline) text = t('home.qa.unreachable');
			return el('section', { class: 'card qa-card is-missing', 'data-device': pin.device, 'aria-label': name }, [
				el('div', { class: 'qa-head' }, [
					el('span', { class: 'qa-ic' }, [glyph(QS.BOLT, 18)]),
					el('span', { class: 'qa-name', text: name }),
					unpinButton(pin.device, name),
				]),
				el('p', { class: 'qa-status', text }),
			]);
		}

		function deviceCard(d, pin) {
			const shown = QS.shownParts(d, pin);
			const w = d.widget;
			const power = d.power && shown.has(`action:${d.power.id}`) ? d.power : null;
			const tone = QS.tone((w && w.state) || (d.power && d.power.state) || (d.actions.length === 1 && QS.isToggle(d.actions[0]) ? d.actions[0].state : null));
			const single = !w && d.actions.length === 1 && QS.isToggle(d.actions[0]) ? d.actions[0] : null;   // a plain switch: in the head
			const head = el('div', { class: 'qa-head' }, [
				el('span', { class: `qa-ic${tone ? ` is-${tone}` : ''}` }, [glyph(d.icon || (single ? QS.displayIcon(single) : null), 18)]),
				el('span', { class: 'qa-name', title: d.subtitle || null }, [el('span', { class: 'qa-title', text: d.title }), d.subtitle && !w ? el('span', { class: 'qa-sub', text: d.subtitle }) : null]),
				w && w.badge ? badge(w.badge) : null,
				power ? switchFor(power, d) : null,
				single ? switchFor(single, d) : null,
				unpinButton(d.key, d.title),
			]);
			const card = el('section', { class: `card qa-card${S.offline ? ' is-offline' : ''}`, 'data-device': d.key, 'aria-label': d.title }, [head]);
			if (S.offline) card.append(el('p', { class: 'qa-note', text: t('home.qa.offline') }));
			if (w) {
				const outdoor = w.readings.find((r) => r.id === QS.OUTDOOR && r.value != null && shown.has(`reading:${r.id}`)) || null;
				const valueShown = (w.value != null || w.label != null) && shown.has(QS.PART.VALUE);
				const temperature = w.value != null && QS.isTemperature(w.unit);
				const climate = (valueShown && temperature) || (outdoor && (!valueShown || temperature));
				if (climate) card.append(climateLine(valueShown && temperature ? w : null, outdoor));
				else if (valueShown) card.append(mainValue(w));
				const readings = w.readings.filter((r) => shown.has(`reading:${r.id}`) && !(climate && r === outdoor));
				if (readings.length) card.append(el('div', { class: 'qa-readings' }, readings.map(reading)));
				if (w.status && shown.has(QS.PART.STATUS)) card.append(el('p', { class: 'qa-status', text: w.status }));
				if (w.timeline && shown.has(QS.PART.TIMELINE)) card.append(timeline(w.timeline));
				for (const c of w.controls) if (shown.has(`control:${c.id}`)) card.append(controlFor(d, c));
			}
			// the plain button carrying the widget is no button of its own (a hidden entry of it in an old pin does nothing)
			const buttons = d.actions.filter((a) => QS.asButton(d, a) && a !== single && shown.has(`action:${a.id}`));
			if (buttons.length) {
				const row = el('div', { class: 'qa-acts' }, buttons.map((a) => actionButton(a)));
				row.style.gridTemplateColumns = `repeat(${QS.buttonsPerRow(buttons.length)}, minmax(0, 1fr))`;
				card.append(row);
			}
			return card;
		}

		function switchFor(a, d) {
			const busy = S.running.has(QS.actionKey(a));
			const b = sw(QS.isOn(a), a.title || d.title, () => run(a));
			b.setAttribute('data-fk', `sw:${a.id}`);
			b.classList.add('qa-sw');
			if (busy) { b.disabled = true; b.classList.add('is-busy'); }
			return b;
		}

		function badge(b) {
			const text = QS.readingText(b, lang());
			const label = [b.label, text].filter(Boolean).join(': ');
			const tone = QS.tone(b.state);
			return el('span', { class: `qa-badge${tone ? ` is-${tone}` : ''}`, title: label || null, 'aria-label': label || null, role: 'img' }, [glyph(b.icon, 16), text ? el('span', { text, 'aria-hidden': 'true' }) : null]);
		}

		function climateLine(main, outdoor) {
			const line = el('div', { class: 'qa-climate' });
			if (main) {
				const v = `${QS.valueText(main.value, lang())} ${main.unit}`;
				line.append(el('span', { class: 'qa-temp', role: 'img', 'aria-label': t('home.qa.inside', { value: v }) }, [el('span', { class: 'qa-temp-ic is-in' }, [glyph(HOUSE_THERMO, 22)]), el('span', { class: 'qa-temp-v', text: v, 'aria-hidden': 'true' })]));
			}
			if (outdoor) {
				const v = QS.readingText(outdoor, lang());
				line.append(el('span', { class: 'qa-temp is-out', role: 'img', 'aria-label': t('home.qa.outside', { value: v }) }, [el('span', { class: 'qa-temp-ic is-out' }, [glyph(CLOUD_SUN, 22)]), el('span', { class: 'qa-temp-v', text: v, 'aria-hidden': 'true' })]));
			}
			return line;
		}

		function mainValue(w) {
			const v = QS.valueText(w.value, lang());
			return el('div', { class: 'qa-value' }, [
				el('div', { class: 'qa-value-row' }, [
					w.icon ? el('span', { class: 'qa-value-ic', title: w.label || null }, [glyph(w.icon, 18)]) : null,
					el('span', { class: 'qa-value-v', text: v === null ? '–' : v }),
					w.unit && v !== null ? el('span', { class: 'qa-value-u', text: w.unit }) : null,
				]),
				w.label && !w.icon ? el('span', { class: 'qa-value-l', text: w.label }) : null,
			]);
		}

		function reading(r) {
			const text = QS.readingText(r, lang());
			const tone = QS.tone(r.state);
			const label = [r.label, text].filter(Boolean).join(': ');
			if (!text && r.icon) return el('span', { class: `qa-reading is-icon${tone ? ` is-${tone}` : ''}`, role: 'img', 'aria-label': label, title: label }, [glyph(r.icon, 16)]);
			return el('span', { class: `qa-reading${tone ? ` is-${tone}` : ''}`, title: label, 'data-reading': r.id }, [r.icon ? glyph(r.icon, 15) : null, el('span', { class: 'qa-reading-v', text: text || r.label })]);
		}

		function timeline(tl) {
			const v = QS.timelineView(tl, lang());
			const label = [t('home.qa.timeline', { segments: v.spoken }), v.nowText ? t('home.qa.timelineNow', { time: v.nowText }) : null].filter(Boolean).join('; ');
			const bar = el('div', { class: 'qa-tl-bar', 'aria-hidden': 'true' });
			for (const s of v.segments) {
				const seg = el('span', { class: `qa-tl-seg${s.tone ? ` is-${s.tone}` : ''}`, title: s.label || null });
				seg.style.left = `${s.left}%`;
				seg.style.width = `${s.width}%`;
				if (s.color) seg.style.background = s.color;
				bar.append(seg);
			}
			if (v.now !== null) {
				const now = el('span', { class: 'qa-tl-now' });
				now.style.left = `${v.now}%`;
				bar.append(now);
			}
			return el('div', { class: 'qa-tl', role: 'img', 'aria-label': label }, [
				bar,
				el('div', { class: 'qa-tl-axis', 'aria-hidden': 'true' }, v.ticks.map((x) => el('span', { text: x }))),
			]);
		}

		function controlFor(d, c) {
			const k = `${d.carrier ? QS.actionKey(d.carrier) : ''}/${c.id}`;
			const pending = S.local.has(k);
			const cls = `qa-ctl qa-${c.kind}${c.disabled ? ' is-disabled' : ''}${pending ? ' is-pending' : ''}`;
			const box = el('div', { class: cls, 'data-control': c.id, title: c.disabled ? t('home.qa.disabled') : null, 'aria-disabled': c.disabled ? 'true' : null });
			if (c.kind === 'choice') {
				const value = pending ? S.local.get(k) : c.value;
				const group = el('div', { class: 'qa-choice-row', role: 'radiogroup', 'aria-label': c.label || d.title });
				group.style.gridTemplateColumns = `repeat(${QS.choicePerRow(c.options.length)}, minmax(0, 1fr))`;
				for (const opt of c.options) {
					const on = opt.id === value;
					const g = QS.optionGlyph(opt);
					group.append(el('button', { type: 'button', class: `qa-opt${on ? ' on' : ''}`, role: 'radio', 'aria-checked': on ? 'true' : 'false', 'aria-label': opt.label,
						title: opt.label, 'data-fk': `opt:${c.id}:${opt.id}`, 'data-option': opt.id, disabled: c.disabled ? true : null,
						on: { click: (e) => {
							if (c.disabled || opt.id === (S.local.has(k) ? S.local.get(k) : c.value)) return;
							for (const b of group.children) { const sel = b === e.currentTarget; b.classList.toggle('on', sel); b.setAttribute('aria-checked', sel ? 'true' : 'false'); }
							box.classList.add('is-pending');
							control(d, c, opt.id, 0);
						} } }, [g ? glyph(g, 18) : el('span', { class: 'qa-opt-l', text: opt.label }), g ? el('span', { class: 'qa-opt-l', text: opt.label }) : null]));
				}
				if (c.label) box.append(el('span', { class: 'qa-ctl-l', text: c.label }));
				box.append(group);
				return box;
			}
			let value = pending ? S.local.get(k) : c.value;
			const out = el('span', { class: 'qa-ctl-v', text: QS.controlText(value, c, lang()) });
			const name = c.label || d.title;
			if (c.kind === 'stepper') {
				const minus = el('button', { type: 'button', class: 'qa-ib', 'data-fk': `dec:${c.id}`, 'aria-label': t('home.qa.decrease', { name }), title: t('home.qa.decrease', { name }) }, [icon('minus', 16)]);
				const plus = el('button', { type: 'button', class: 'qa-ib', 'data-fk': `inc:${c.id}`, 'aria-label': t('home.qa.increase', { name }), title: t('home.qa.increase', { name }) }, [icon('plus', 16)]);
				const sync = () => { minus.disabled = c.disabled || value <= c.min; plus.disabled = c.disabled || value >= c.max; };
				const step = (dir) => {
					if (c.disabled) return;
					const next = QS.snap(value + dir * c.step, c);
					if (next === value) return;
					value = next;
					out.textContent = QS.controlText(value, c, lang());
					box.classList.add('is-pending');
					sync();
					control(d, c, value, DEBOUNCE_MS);
				};
				minus.addEventListener('click', () => step(-1));
				plus.addEventListener('click', () => step(1));
				sync();
				box.append(el('span', { class: 'qa-ctl-l', text: c.label || '' }), minus, out, plus);
				return box;
			}
			// slider: the value while it moves, sent when let go
			const input = el('input', { type: 'range', class: 'qa-range', min: String(c.min), max: String(c.max), step: String(c.step), 'aria-label': name, 'data-fk': `range:${c.id}`, disabled: c.disabled ? true : null });
			input.value = String(value);
			input.addEventListener('input', () => { value = QS.snap(Number(input.value), c); out.textContent = QS.controlText(value, c, lang()); });
			input.addEventListener('change', () => { if (c.disabled) return; box.classList.add('is-pending'); control(d, c, value, 0); });
			box.append(el('div', { class: 'qa-slider-head' }, [el('span', { class: 'qa-ctl-l', text: c.label || '' }), out]), input);
			return box;
		}

		function actionButton(a) {
			const busy = S.running.has(QS.actionKey(a));
			const look = QS.currentLook(a);
			const tone = look && look.tone ? look.tone : null;
			const toggle = QS.isToggle(a);
			const on = QS.isOn(a);
			return el('button', {
				type: 'button',
				class: `qa-act${tone ? ` is-${tone}` : ''}${!tone && on ? ' on' : ''}${busy ? ' is-busy' : ''}`,
				role: toggle ? 'switch' : null,
				'aria-checked': toggle ? (on ? 'true' : 'false') : null,
				'data-action': a.id,
				'data-fk': `act:${a.id}`,
				title: a.subtitle || a.title,
				disabled: busy ? true : null,
				on: { click: () => run(a) },
			}, [busy ? el('span', { class: 'qa-spin', 'aria-hidden': 'true' }) : glyph(QS.displayIcon(a), 17), el('span', { class: 'qa-act-l', text: a.title })]);
		}

		// ── The dialog "Schnellaktionen anheften" ────────
		//
		// Fixed at the top: the search (name, room, plugin) and "5 von 12 angeheftet" with its bar. Then "Angeheftet" in
		// the order of the cards (dragged by the grip or Alt+↑/↓; "Teile" opens what the card shows) and the devices by
		// plugin (a group folds; its head stays while scrolling; "2 von 7"). A pinned device is in both places.
		// A switch changes only its rows (never the whole dialog): the row stays where it is, the focus on the switch;
		// a list that comes in the background only updates names and lines while the devices are the same.

		const GRIP = 'M9 6h.01M9 12h.01M9 18h.01M15 6h.01M15 12h.01M15 18h.01';
		let P = null;   // the open dialog's parts and what the person did in it (search, folded groups, open "Teile")

		function openPicker() {
			if (dialog && !dialog.closed) return;
			dialog = openDialog({ title: t('home.qa.pick.title'), wide: true, closeLabel: t('home.qa.pick.done'), cls: 'qa-pick qp' });
			const search = el('input', { type: 'search', class: 'ml-search-in', placeholder: t('home.qa.pick.search'), 'aria-label': t('home.qa.pick.search'), maxlength: '100', spellcheck: 'false', 'data-qp-q': '' });
			const countTx = el('span', { class: 'qp-count-tx', 'data-qp-n': '' });
			const bar = el('span', { class: 'qp-bar', 'aria-hidden': 'true' }, [el('i')]);
			const count = el('div', { class: 'qp-count', role: 'status', 'aria-live': 'polite' }, [countTx, bar]);
			const full = el('div', { class: 'qp-hint-full', hidden: true }, [icon('alert', 15), el('span', { text: t('home.qa.pick.fullHint', { max: QS.MAX_PINS }) })]);
			const top = el('div', { class: 'qp-top' }, [el('div', { class: 'qp-tools' }, [el('label', { class: 'ml-search' }, [icon('search', 15), search]), count]), full]);
			dialog.box.insertBefore(top, dialog.body);
			dialog.body.classList.add('qp-body');
			dialog.foot.append(
				el('p', { class: 'qp-foot-note', text: t('home.qa.pick.note') }),
				el('button', { type: 'button', class: 'btn btn-pri btn-sm', text: t('home.qa.pick.done'), on: { click: () => dialog.close() } }),
			);
			P = { search, count, countTx, bar: bar.firstChild, full, q: '', folded: new Set(), parts: new Set(), shape: null, dragKey: null };
			search.addEventListener('input', () => { P.q = search.value; filter(); });
			search.addEventListener('keydown', (e) => { if (e.key === 'Escape' && search.value) { e.stopPropagation(); search.value = ''; P.q = ''; filter(); } });
			fillPicker();
			// what the plugins offer now (a device added, one taken away)
			refresh();
		}

		/** After a list came in: the same devices → only names and lines; else built again (scroll and focus kept). */
		function syncPicker() {
			if (!dialog || dialog.closed || !P) return;
			if (P.shape === QS.pickShape(S.load, S.devices)) { updateRows(); return; }
			const body = dialog.body;
			const anchor = firstRowInView(body);
			const focusKey = document.activeElement && body.contains(document.activeElement) ? focusId(document.activeElement) : null;
			fillPicker();
			if (anchor) {
				const r = body.querySelector(anchor.sel);
				if (r) body.scrollTop += r.getBoundingClientRect().top - body.getBoundingClientRect().top - anchor.off;
			}
			if (focusKey) {
				const f = body.querySelector(focusKey);
				if (f && !f.disabled) f.focus({ preventScroll: true });
			}
		}

		const zone = (n) => (n.closest('.qp-pins') ? '.qp-pins' : '.qp-groups');
		function rowSel(r) { return `${zone(r)} .qa-pick-row[data-device="${CSS.escape(r.dataset.device)}"]`; }
		function focusId(a) {
			const r = a.closest('.qa-pick-row');
			if (r && a.dataset.qpFk) return `${rowSel(r)} [data-qp-fk="${a.dataset.qpFk}"]`;
			if (a.dataset.qpG) return `[data-qp-g="${CSS.escape(a.dataset.qpG)}"]`;
			return null;
		}
		function firstRowInView(body) {
			const top = body.getBoundingClientRect().top;
			for (const r of body.querySelectorAll('.qa-pick-row')) {
				const b = r.getBoundingClientRect();
				if (b.height && b.bottom > top + 1) return { sel: rowSel(r), off: b.top - top };
			}
			return null;
		}

		function fillPicker() {
			const body = clear(dialog.body);
			P.shape = QS.pickShape(S.load, S.devices);
			const ready = S.load === 'ok' && S.devices.length > 0;
			P.search.disabled = !ready;
			counter();
			if (S.load === 'idle' || S.load === 'loading') { body.append(el('p', { class: 'qa-pick-empty', text: t('home.qa.loading') })); return; }
			if (S.load === 'unsupported') { body.append(el('p', { class: 'qa-pick-empty', text: t('home.qa.pick.unsupported') })); return; }
			if (S.load === 'error') {
				body.append(el('p', { class: 'qa-pick-empty', text: t('home.qa.pick.failed') }),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm qa-pick-retry', text: t('home.qa.pick.retry'), on: { click: () => refresh() } }));
				return;
			}
			if (!S.devices.length) { body.append(el('p', { class: 'qa-pick-empty', text: t('home.qa.pick.none') })); return; }
			const list = pinned();
			// "Angeheftet": the cards' order
			const pinRows = el('div', { class: 'qp-rows qp-pins', 'data-qp-pins': '' });
			list.forEach((p, i) => pinRows.append(...pinnedRow(p, i)));
			if (!list.length) pinRows.append(el('p', { class: 'qp-empty', text: t('home.qa.pick.nonePinned') }));
			wirePinDrag(pinRows);
			body.append(groupBox({ id: '_pins', name: t('home.qa.pick.pinned'), sub: t('home.qa.pick.order'), rows: pinRows, pins: true }));
			// the devices by plugin
			const groups = el('div', { class: 'qp-groups' });
			for (const g of QS.pickGroups(S.devices, list)) {
				const rows = el('div', { class: 'qp-rows' });
				for (const d of g.devices) rows.append(groupRow(d));
				groups.append(groupBox({ id: g.plugin, name: g.name, rows, count: g }));
			}
			body.append(groups, el('p', { class: 'qp-empty qp-none', hidden: true }));
			filter();
		}

		function groupBox({ id, name, sub, rows, pins = false, count = null }) {
			const open = !P.folded.has(id);
			const gc = el('span', { class: 'qp-gc' });
			if (count) gc.append(el('b', { text: String(count.pinned) }), ` ${t('home.qa.pick.of', { total: count.total })}`);
			else gc.textContent = sub || '';
			const head = el('button', { type: 'button', class: `qp-gh${pins ? ' is-pins' : ''}`, 'aria-expanded': open ? 'true' : 'false', 'data-qp-g': id }, [
				el('span', { class: 'qp-chev' }, [icon('chevDown', 15)]),
				el('span', { class: 'qp-gn qa-pick-h', text: name }),
				gc,
			]);
			const box = el('section', { class: `qp-group${pins ? ' is-pins' : ''}`, 'data-g': id, 'data-open': open ? 'true' : 'false' }, [head, rows]);
			head.addEventListener('click', () => {
				const now = box.getAttribute('data-open') !== 'true';
				if (now) P.folded.delete(id); else P.folded.add(id);
				box.setAttribute('data-open', now ? 'true' : 'false');
				head.setAttribute('aria-expanded', now ? 'true' : 'false');
			});
			return box;
		}

		/** The title and the line below with the search's hit marked (text only). */
		function titleBox(title, sub) {
			const mark = (s) => QS.highlight(s, P.q).map((x) => (x.hit ? el('mark', { text: x.text }) : document.createTextNode(x.text)));
			return el('span', { class: 'qa-pick-t' }, [el('span', { class: 'qa-title' }, mark(title)), sub ? el('span', { class: 'qa-sub' }, mark(sub)) : null]);
		}

		const deviceIcon = (d) => glyph(d.icon || (d.actions[0] && QS.displayIcon(d.actions[0])), 17);

		/** A device in its plugin's group: the switch, "angeheftet" while it is. */
		function groupRow(d) {
			const list = pinned();
			const on = QS.isPinned(list, d.key);
			const toggle = sw(on, t('home.qa.pick.pin', { name: d.title }), (next) => togglePin(d, next, toggle));
			toggle.setAttribute('data-qp-fk', 'sw');
			const row = el('div', { class: `qa-pick-row qp-row${on ? ' is-on' : ''}`, 'data-device': d.key }, [
				el('span', { class: 'qa-ic' }, [deviceIcon(d)]),
				titleBox(d.title, d.subtitle),
				el('span', { class: 'qp-tag', hidden: !on || null }, [icon('pin', 12), el('span', { text: t('home.qa.pick.isPinned') })]),
				toggle,
			]);
			return row;
		}

		function partLabel(p) {
			if (p.kind === 'value') return p.label || t('home.qa.part.value');
			if (p.kind === 'status') return t('home.qa.part.status');
			if (p.kind === 'timeline') return t('home.qa.part.timeline');
			if (p.kind === 'power') return t('home.qa.part.power', { name: p.label });
			return p.label;
		}

		/** A pinned device in "Angeheftet": grip, place, name, "Teile", the switch; its parts below while open. */
		function pinnedRow(pin, i) {
			const d = QS.resolve(pin, S.devices);
			const key = d ? d.key : pin.device;
			const name = d ? d.title : (pin.title || pin.device);
			const sub = d ? [d.pluginName, d.subtitle].filter(Boolean).join(' · ') : t('home.qa.gone');
			const all = d ? QS.parts(d) : [];
			const grip = el('button', { type: 'button', class: 'qp-grip', 'data-qp-fk': 'grip', title: t('home.qa.pick.move'), 'aria-label': t('home.qa.pick.moveName', { name }) }, [glyph(GRIP, 16)]);
			const toggle = sw(true, t('home.qa.pick.pin', { name }), (next) => { if (!next) unpinFrom(key, toggle); });
			toggle.setAttribute('data-qp-fk', 'sw');
			const open = P.parts.has(key) && all.length > 1;
			const partsBtn = all.length > 1 ? el('button', { type: 'button', class: 'qp-parts-btn', 'data-qp-fk': 'parts', 'aria-expanded': open ? 'true' : 'false', title: t('home.qa.pick.parts') }, [
				el('span', { text: t('home.qa.pick.partsShort') }), icon('chevDown', 13),
			]) : null;
			const row = el('div', { class: `qa-pick-row qp-row is-on${d ? '' : ' is-gone'}`, 'data-device': key }, [
				grip,
				el('span', { class: 'qp-pos', text: String(i + 1) }),
				el('span', { class: 'qa-ic' }, [d ? deviceIcon(d) : glyph(QS.BOLT, 17)]),
				titleBox(name, sub),
				partsBtn,
				toggle,
			]);
			grip.addEventListener('pointerdown', () => { row.draggable = true; });
			grip.addEventListener('keydown', (e) => moveKey(e, key));
			row.addEventListener('keydown', (e) => { if (e.target !== grip) moveKey(e, key); });
			const box = open ? partsBox(d, pin) : null;
			if (partsBtn) {
				partsBtn.addEventListener('click', () => {
					const now = !P.parts.has(key);
					if (now) P.parts.add(key); else P.parts.delete(key);
					partsBtn.setAttribute('aria-expanded', now ? 'true' : 'false');
					const old = row.nextElementSibling && row.nextElementSibling.classList.contains('qa-parts') ? row.nextElementSibling : null;
					if (old) old.remove();
					if (now) row.after(partsBox(d, pinned().find((p) => p.device === key) || pin));
				});
			}
			return box ? [row, box] : [row];
		}

		function partsBox(d, pin) {
			const hidden = new Set(pin.hidden || []);
			const box = el('fieldset', { class: 'qa-parts qp-parts', 'data-device': d.key }, [el('legend', { text: t('home.qa.pick.parts') })]);
			for (const p of QS.parts(d)) {
				const cb = el('input', { type: 'checkbox', 'data-part': p.id });
				cb.checked = !hidden.has(p.id);
				cb.addEventListener('change', () => pins.setHidden(d.key, p.id, !cb.checked));
				box.append(el('label', { class: 'qa-part' }, [cb, el('span', { text: partLabel(p) })]));
			}
			return box;
		}

		/** Keeps `row` where it is on the screen while `change` adds or removes rows above it. */
		function keepPlace(row, change) {
			const body = dialog.body;
			const before = row && row.isConnected ? row.getBoundingClientRect().top : null;
			change();
			if (before !== null && row.isConnected) body.scrollTop += row.getBoundingClientRect().top - before;
		}

		/** The switch in a group: pinned at the end of "Angeheftet" or loosened; only these rows change. */
		function togglePin(d, on, toggle) {
			const row = toggle.closest('.qa-pick-row');
			keepPlace(row, () => {
				pins.pinDevice(d.key, d, on);
				const box = dialog.body.querySelector('[data-qp-pins]');
				const old = box.querySelector(`.qa-pick-row[data-device="${CSS.escape(d.key)}"]`);
				if (on && !old) {
					const list = pinned();
					const i = list.findIndex((p) => p.device === d.key);
					if (i >= 0) {
						const empty = box.querySelector('.qp-empty');
						if (empty) empty.remove();
						const made = pinnedRow(list[i], i);
						box.append(...made);
						flash(made[0]);
					}
				} else if (!on && old) {
					removePinned(box, old);
				}
				markGroupRow(d.key, on);
				flash(row);
			});
			counter();
		}

		/** The switch of a row in "Angeheftet": loosened; the focus goes to the next row's switch (or the group's). */
		function unpinFrom(key, toggle) {
			const box = dialog.body.querySelector('[data-qp-pins]');
			const row = toggle.closest('.qa-pick-row');
			let next = row.nextElementSibling;
			while (next && !next.classList.contains('qa-pick-row')) next = next.nextElementSibling;
			let prev = row.previousElementSibling;
			while (prev && !prev.classList.contains('qa-pick-row')) prev = prev.previousElementSibling;
			const stay = next || prev || dialog.body.querySelector(`.qp-groups .qa-pick-row[data-device="${CSS.escape(key)}"]`);
			keepPlace(stay, () => {
				pins.pinDevice(key, null, false);
				removePinned(box, row);
				markGroupRow(key, false);
			});
			counter();
			const f = stay && stay.querySelector('[data-qp-fk="sw"]');
			if (f) f.focus({ preventScroll: true });
		}

		function removePinned(box, row) {
			const parts = row.nextElementSibling && row.nextElementSibling.classList.contains('qa-parts') ? row.nextElementSibling : null;
			if (parts) parts.remove();
			row.remove();
			if (!box.querySelector('.qa-pick-row')) box.append(el('p', { class: 'qp-empty', text: t('home.qa.pick.nonePinned') }));
			numberPins();
		}

		function markGroupRow(key, on) {
			const r = dialog.body.querySelector(`.qp-groups .qa-pick-row[data-device="${CSS.escape(key)}"]`);
			if (!r) return;
			r.classList.toggle('is-on', on);
			const s = r.querySelector('.sw');
			s.classList.toggle('on', on);
			s.setAttribute('aria-checked', on ? 'true' : 'false');
			const tag = r.querySelector('.qp-tag');
			if (tag) tag.hidden = !on;
		}

		function flash(row) {
			if (!row) return;
			row.classList.remove('is-flash');
			void row.offsetWidth;
			row.classList.add('is-flash');
		}

		function numberPins() {
			const box = dialog.body.querySelector('[data-qp-pins]');
			if (box) box.querySelectorAll('.qa-pick-row .qp-pos').forEach((p, i) => { p.textContent = String(i + 1); });
		}

		/** "5 von 12 angeheftet", the bar, the hint when full; the switches of the groups greyed out then; the groups' counts. */
		function counter() {
			if (!P) return;
			const list = pinned();
			const n = list.length;
			const isFull = n >= QS.MAX_PINS;
			clear(P.countTx).append(el('b', { text: String(n) }), ` ${t('home.qa.pick.countOf', { max: QS.MAX_PINS })}`);
			P.bar.style.width = `${Math.min(100, (n / QS.MAX_PINS) * 100)}%`;
			P.count.classList.toggle('is-full', isFull);
			P.full.hidden = !isFull || S.load !== 'ok';
			const body = dialog.body;
			for (const r of body.querySelectorAll('.qp-groups .qa-pick-row')) {
				const s = r.querySelector('.sw');
				const off = isFull && !QS.isPinned(list, r.dataset.device);
				s.disabled = off;
				s.title = off ? t('home.qa.pick.full', { max: QS.MAX_PINS }) : '';
				r.classList.toggle('qp-dim', off);
			}
			for (const g of QS.pickGroups(S.devices, list)) {
				const gc = body.querySelector(`.qp-group[data-g="${CSS.escape(g.plugin)}"] .qp-gc`);
				if (gc) clear(gc).append(el('b', { text: String(g.pinned) }), ` ${t('home.qa.pick.of', { total: g.total })}`);
			}
		}

		/** The search: rows that do not fit hidden, groups without a hit too; while searching all groups are open. */
		function filter() {
			if (!P || !dialog) return;
			const body = dialog.body;
			const q = P.q.trim();
			let any = false;
			for (const r of body.querySelectorAll('.qa-pick-row')) {
				const d = S.devices.find((x) => x.key === r.dataset.device);
				const pin = pinned().find((p) => p.device === r.dataset.device);
				const fits = d ? QS.matches(d, q) : QS.matches({ title: pin ? pin.title : r.dataset.device }, q);
				r.hidden = !fits;
				const parts = r.nextElementSibling && r.nextElementSibling.classList.contains('qa-parts') ? r.nextElementSibling : null;
				if (parts) parts.hidden = !fits;
				const tb = r.querySelector('.qa-pick-t');
				if (tb) tb.replaceWith(titleBox(tb.querySelector('.qa-title').textContent, tb.querySelector('.qa-sub') ? tb.querySelector('.qa-sub').textContent : null));
				if (fits && r.closest('.qp-groups')) any = true;
			}
			for (const g of body.querySelectorAll('.qp-groups .qp-group')) {
				g.hidden = !g.querySelector('.qa-pick-row:not([hidden])');
				g.classList.toggle('is-search', !!q);
			}
			const pinsGroup = body.querySelector('.qp-group.is-pins');
			if (pinsGroup) pinsGroup.classList.toggle('is-search', !!q);
			const none = body.querySelector('.qp-none');
			if (none) {
				none.hidden = !q || any;
				none.textContent = q && !any ? t('home.qa.pick.nothing', { q }) : '';
			}
		}

		/** Names and lines from a newer list (the same devices): in place. */
		function updateRows() {
			const body = dialog.body;
			for (const r of body.querySelectorAll('.qa-pick-row')) {
				const d = S.devices.find((x) => x.key === r.dataset.device);
				if (!d) continue;
				const tb = r.querySelector('.qa-pick-t');
				const sub = r.closest('.qp-pins') ? [d.pluginName, d.subtitle].filter(Boolean).join(' · ') : d.subtitle;
				if (tb) tb.replaceWith(titleBox(d.title, sub));
			}
			counter();
		}

		// ── Order of "Angeheftet": the grip dragged, Alt+↑/↓ ──

		function moveKey(e, key) {
			if (!e.altKey || (e.key !== 'ArrowUp' && e.key !== 'ArrowDown')) return;
			e.preventDefault();
			e.stopPropagation();
			const now = pinned();
			const next = QS.movePin(now, key, e.key === 'ArrowUp' ? -1 : 1);
			if (next === now) return;
			pins.setActions(next);
			const box = dialog.body.querySelector('[data-qp-pins]');
			const row = box.querySelector(`.qa-pick-row[data-device="${CSS.escape(key)}"]`);
			const parts = row.nextElementSibling && row.nextElementSibling.classList.contains('qa-parts') ? row.nextElementSibling : null;
			const rows = [...box.querySelectorAll('.qa-pick-row')];
			const i = rows.indexOf(row);
			if (e.key === 'ArrowUp' && i > 0) box.insertBefore(row, rows[i - 1]);
			else if (e.key === 'ArrowDown' && i < rows.length - 1) {
				const after = rows[i + 1];
				const afterParts = after.nextElementSibling && after.nextElementSibling.classList.contains('qa-parts') ? after.nextElementSibling : null;
				(afterParts || after).after(row);
			}
			if (parts) row.after(parts);
			numberPins();
			const g = row.querySelector('.qp-grip');
			if (g) { g.focus({ preventScroll: true }); g.scrollIntoView({ block: 'nearest' }); }
		}

		function wirePinDrag(box) {
			const drop = () => box.querySelector('.qp-drop');
			box.addEventListener('dragstart', (e) => {
				const r = e.target.closest && e.target.closest('.qa-pick-row');
				if (!r || !r.draggable) { e.preventDefault(); return; }
				P.dragKey = r.dataset.device;
				r.classList.add('is-ghost');
				try { e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', r.dataset.device); } catch { /* no data */ }
			});
			box.addEventListener('dragover', (e) => {
				if (!P.dragKey) return;
				e.preventDefault();
				const rows = [...box.querySelectorAll('.qa-pick-row')];
				const before = rows.find((r) => e.clientY < r.getBoundingClientRect().top + r.offsetHeight / 2) || null;
				let d = drop();
				if (!d) d = el('div', { class: 'qp-drop', 'aria-hidden': 'true' });
				if (before) box.insertBefore(d, before); else box.append(d);
			});
			box.addEventListener('drop', (e) => {
				if (!P.dragKey) return;
				e.preventDefault();
				const d = drop();
				const row = box.querySelector(`.qa-pick-row[data-device="${CSS.escape(P.dragKey)}"]`);
				if (d && row) {
					const parts = row.nextElementSibling && row.nextElementSibling.classList.contains('qa-parts') ? row.nextElementSibling : null;
					box.insertBefore(row, d);
					if (parts) row.after(parts);
					pins.setActions(QS.orderPins(pinned(), [...box.querySelectorAll('.qa-pick-row')].map((r) => r.dataset.device)));
					numberPins();
					flash(row);
				}
				if (d) d.remove();
			});
			box.addEventListener('dragend', () => {
				for (const r of box.querySelectorAll('.qa-pick-row')) { r.classList.remove('is-ghost'); r.draggable = false; }
				const d = drop();
				if (d) d.remove();
				P.dragKey = null;
			});
		}

		// ── Keeping it current ───────────────────────────

		// pinned cards: asked again every minute while the window is shown; not asked yet (no server set up, no
		// network): every 15 s until an answer comes
		setInterval(() => {
			if (typeof document.visibilityState === 'string' && document.visibilityState !== 'visible') return;
			if (S.load === 'error' || (pinned().length && Date.now() - S.loadedAt >= RELOAD_MS)) refresh();
		}, RETRY_MS);

		return {
			/** The section has something of this part: a server with quick actions, or cards pinned. */
			available: () => S.load === 'ok' || pinned().length > 0,
			/** The cards of the pinned devices, in the pins' order. */
			cards: () => pinned().map(cardFor),
			/** The button "Schnellaktionen" of the section's head (null while the server has none). */
			button: () => (S.load === 'ok' ? el('button', { type: 'button', class: 'btn btn-ghost btn-xs qa-open', id: 'home-qa-open', title: t('home.qa.openHint'), on: { click: openPicker } }, [icon('pin', 14), el('span', { text: t('home.qa.open') })]) : null),
			/** Whether a card is drawn now (the sub line of the head). */
			hasCards: () => pinned().length > 0,
			openPicker,
			refresh,
			/** The start page is shown again. */
			show() { if (S.load === 'error' || Date.now() - S.loadedAt > 30 * 1000) refresh(); },
			/** The language changed: titles come in the new one. */
			relabel() { cards.clear(); refresh(); },
			/** The pins changed: cards are taken from the cache or drawn. */
			pinsChanged() { cards.clear(); },
		};
	}

	root.GCQuickActionsView = { create };
})(typeof self !== 'undefined' ? self : this);
