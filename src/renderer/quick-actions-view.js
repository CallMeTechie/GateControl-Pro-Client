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
				if (dialog && !dialog.closed) fillPicker();
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

		function openPicker() {
			if (dialog && !dialog.closed) return;
			dialog = openDialog({ title: t('home.qa.pick.title'), wide: true, closeLabel: t('home.qa.pick.done'), cls: 'qa-pick' });
			dialog.foot.append(el('button', { type: 'button', class: 'btn btn-pri btn-sm', text: t('home.qa.pick.done'), on: { click: () => dialog.close() } }));
			fillPicker();
			// what the plugins offer now (a device added, one taken away)
			refresh();
		}

		function fillPicker() {
			const body = clear(dialog.body);
			body.append(el('p', { class: 'qa-pick-hint', text: t('home.qa.pick.hint', { max: QS.MAX_PINS }) }));
			if (S.load === 'idle' || S.load === 'loading') { body.append(el('p', { class: 'qa-pick-empty', text: t('home.qa.loading') })); return; }
			if (S.load === 'unsupported') { body.append(el('p', { class: 'qa-pick-empty', text: t('home.qa.pick.unsupported') })); return; }
			if (S.load === 'error') {
				body.append(el('p', { class: 'qa-pick-empty', text: t('home.qa.pick.failed') }),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm qa-pick-retry', text: t('home.qa.pick.retry'), on: { click: () => refresh() } }));
				return;
			}
			if (!S.devices.length) { body.append(el('p', { class: 'qa-pick-empty', text: t('home.qa.pick.none') })); return; }
			const byPlugin = new Map();
			for (const d of S.devices) {
				if (!byPlugin.has(d.plugin)) byPlugin.set(d.plugin, { name: d.pluginName, list: [] });
				byPlugin.get(d.plugin).list.push(d);
			}
			for (const g of byPlugin.values()) {
				body.append(el('h3', { class: 'qa-pick-h', text: g.name }));
				for (const d of g.list) body.append(pickRow(d));
			}
		}

		function partLabel(p) {
			if (p.kind === 'value') return p.label || t('home.qa.part.value');
			if (p.kind === 'status') return t('home.qa.part.status');
			if (p.kind === 'timeline') return t('home.qa.part.timeline');
			if (p.kind === 'power') return t('home.qa.part.power', { name: p.label });
			return p.label;
		}

		function pickRow(d) {
			const list = pinned();
			const on = QS.isPinned(list, d.key);
			const full = !on && list.length >= QS.MAX_PINS;
			const toggle = sw(on, t('home.qa.pick.pin', { name: d.title }), (next) => { pins.pinDevice(d.key, d, next); fillPicker(); });
			if (full) { toggle.disabled = true; toggle.title = t('home.qa.pick.full', { max: QS.MAX_PINS }); }
			const row = el('div', { class: `qa-pick-row${on ? ' is-on' : ''}`, 'data-device': d.key }, [
				el('div', { class: 'qa-pick-main' }, [
					el('span', { class: 'qa-ic' }, [glyph(d.icon || (d.actions[0] && QS.displayIcon(d.actions[0])), 17)]),
					el('span', { class: 'qa-pick-t' }, [el('span', { class: 'qa-title', text: d.title }), d.subtitle ? el('span', { class: 'qa-sub', text: d.subtitle }) : null]),
					toggle,
				]),
			]);
			const all = QS.parts(d);
			if (on && all.length > 1) {
				const pin = list.find((p) => p.device === d.key);
				const hidden = new Set(pin.hidden || []);
				const box = el('fieldset', { class: 'qa-parts' }, [el('legend', { text: t('home.qa.pick.parts') })]);
				for (const p of all) {
					const cb = el('input', { type: 'checkbox', 'data-part': p.id });
					cb.checked = !hidden.has(p.id);
					cb.addEventListener('change', () => pins.setHidden(d.key, p.id, !cb.checked));
					box.append(el('label', { class: 'qa-part' }, [cb, el('span', { text: partLabel(p) })]));
				}
				row.append(box);
			}
			return row;
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
