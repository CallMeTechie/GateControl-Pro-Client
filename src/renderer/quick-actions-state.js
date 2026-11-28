/**
 * GateControl -- Schnellaktionen view state (renderer, no DOM access)
 *
 * Pure helpers for the plugins' quick actions pinned to the start page
 * ("Angeheftet", quick-actions-view.js): the actions of one device grouped
 * into a card (like the Android app: the action that brings the widget — no
 * button of its own unless it is a toggle that is not the power switch —, its
 * power switch, the other actions as buttons), the parts of a card the person
 * can hide, the pins of this PC (gc.home.pins → actions, kept by home-view.js
 * through GCMailState.homePins), numbers as the card shows them, a stepper's
 * grid, the day bar (widget.timeline: segments, the mark for now, the axis
 * 0 6 12 18 24) and the texts of a failed run. Loaded as a plain script before
 * quick-actions-view.js (window.GCQuickActionsState) and required by the node
 * tests (test/quick-actions-state.test.js).
 *
 * Input are the actions of window.gatecontrol.quickActions.list() — already
 * checked by the core (utils/quick-actions.js) as strictly as the server.
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCQuickActionsState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	// the bolt of an action without an icon of its own (like the Android app)
	const BOLT = 'M13 2 3 14h9l-1 8 10-12h-9l1-8z';
	// stroke paths for the option ids plugins use for modes (Klima: auto, cool, heat, dry, fan; on / off), as on Android
	const OPTION_GLYPHS = {
		auto: 'M20 12a8 8 0 0 1-14 5.3M4 12a8 8 0 0 1 14-5.3M18 3v4h-4M6 21v-4h4',
		cool: 'M12 2v20M3.3 7l17.4 10M3.3 17L20.7 7M9 4l3 2 3-2M9 20l3-2 3 2',
		heat: 'M12 8a4 4 0 1 0 0 8a4 4 0 0 0 0-8M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
		dry: 'M12 3c3.5 4.5 6 7.7 6 11a6 6 0 0 1-12 0c0-3.3 2.5-6.5 6-11z',
		fan: 'M3 8h11a3 3 0 1 0-3-3M3 12h16a3 3 0 1 1-3 3M3 16h8',
		off: 'M12 3v9M6.3 6.3a8 8 0 1 0 11.4 0',
		on: 'M12 3v9M6.3 6.3a8 8 0 1 0 11.4 0',
	};
	const PART = { VALUE: 'value', STATUS: 'status', TIMELINE: 'timeline' };
	const OUTDOOR = 'outdoor';
	const MAX_PINS = 12;

	const actionKey = (a) => `${a.plugin}/${a.id}`;
	/** Actions without a device are a device of their own. */
	const deviceKey = (a) => `${a.plugin}/${a.device && a.device.id ? a.device.id : `@${a.id}`}`;
	const isToggle = (a) => !!a && a.kind === 'toggle';
	const isOn = (a) => isToggle(a) && a.state === 'on';

	// ── Devices ─────────────────────────────────────────

	/**
	 * The actions as devices, in the order their first action comes → [{ key, plugin, pluginName, title, subtitle,
	 * icon, actions, carrier, widget, power }]: carrier the first action with a widget, power its switch when the
	 * widget says it is the device's power switch (a toggle with widget.power true).
	 */
	function group(actions) {
		const map = new Map();
		for (const a of actions || []) {
			if (!a || !a.plugin || !a.id) continue;
			const k = deviceKey(a);
			if (!map.has(k)) map.set(k, []);
			map.get(k).push(a);
		}
		return [...map.entries()].map(([key, list]) => device(key, list));
	}

	function device(key, list) {
		const first = list[0];
		const own = !first.device;
		const carrier = list.find((a) => a.widget) || null;
		const widget = carrier ? carrier.widget : null;
		return {
			key,
			plugin: first.plugin,
			pluginName: first.pluginName || first.plugin,
			title: own ? first.title : first.device.title || first.title,
			subtitle: own ? first.subtitle || null : first.device.subtitle || null,
			icon: own ? first.icon || null : first.device.icon || first.icon || null,
			actions: list,
			carrier,
			widget,
			power: carrier && isToggle(carrier) && widget && widget.power !== false ? carrier : null,
		};
	}

	/**
	 * Everything a card of the device can show, in display order → [{ id, kind, label }]; kind power | value |
	 * reading | status | timeline | control | action (the actions shown as buttons, see asButton). label: the plugin's name for it (null for status, timeline and
	 * a nameless value — the app names those).
	 */
	function parts(d) {
		const out = [];
		const w = d.widget;
		if (d.power) out.push({ id: `action:${d.power.id}`, kind: 'power', label: d.power.title });
		if (w && (w.value != null || w.label != null)) out.push({ id: PART.VALUE, kind: 'value', label: w.label || null });
		for (const r of (w && w.readings) || []) out.push({ id: `reading:${r.id}`, kind: 'reading', label: r.label });
		if (w && w.status) out.push({ id: PART.STATUS, kind: 'status', label: null });
		if (w && w.timeline) out.push({ id: PART.TIMELINE, kind: 'timeline', label: null });
		for (const c of (w && w.controls) || []) out.push({ id: `control:${c.id}`, kind: 'control', label: c.label || c.id });
		for (const a of d.actions) if (asButton(d, a)) out.push({ id: `action:${a.id}`, kind: 'action', label: a.title });
		return out;
	}

	/**
	 * Whether an action of the device is a button of its card: not its power switch (that is in the head) and not
	 * the plain button carrying the widget (that is the card itself). A toggle carrying the widget without being the
	 * power switch (widget.power false) stays a button, else nothing could switch it.
	 */
	function asButton(d, a) {
		if (!a || a === d.power) return false;
		return a !== d.carrier || isToggle(a);
	}

	/** The ids of the parts a pin shows (everything the device has but what the person hid). */
	function shownParts(d, pin) {
		const hidden = new Set((pin && pin.hidden) || []);
		return new Set(parts(d).map((p) => p.id).filter((id) => !hidden.has(id)));
	}

	// ── Pins of this PC (gc.home.pins → actions) ────────

	/** The device a pin names now: by its key, else by its anchor action (the plugin changed the device id). */
	function resolve(pin, devices) {
		if (!pin) return null;
		return (devices || []).find((d) => d.key === pin.device)
			|| (pin.anchor ? (devices || []).find((d) => d.actions.some((a) => actionKey(a) === pin.anchor)) : null)
			|| null;
	}

	const isPinned = (pins, key) => (pins || []).some((p) => p.device === key);

	/** The device pinned (at the end, at most 12) or loosened → the new list (a copy). */
	function pinDevice(pins, d, on) {
		const list = (pins || []).filter((p) => p.device !== d.key);
		if (!on) return list;
		const old = (pins || []).find((p) => p.device === d.key);
		const pin = { device: d.key, anchor: d.actions[0] ? actionKey(d.actions[0]) : null, title: d.title, hidden: old ? old.hidden : [] };
		return old ? (pins || []).map((p) => (p.device === d.key ? pin : p)) : list.concat(pin).slice(0, MAX_PINS);
	}

	/** A part of a pinned device shown or hidden → the new list (a copy). */
	function setHidden(pins, key, partId, hide) {
		return (pins || []).map((p) => {
			if (p.device !== key) return p;
			const rest = (p.hidden || []).filter((x) => x !== partId);
			return { ...p, hidden: hide ? rest.concat(partId) : rest };
		});
	}

	/**
	 * The pins following the devices now: a device found by its anchor gets its current key, its title is kept
	 * current (shown while the server cannot be asked); unchanged when nothing changed (same array).
	 */
	function syncPins(pins, devices) {
		let changed = false;
		const out = (pins || []).map((p) => {
			const d = resolve(p, devices);
			if (!d) return p;
			const anchor = p.anchor && d.actions.some((a) => actionKey(a) === p.anchor) ? p.anchor : (d.actions[0] ? actionKey(d.actions[0]) : null);
			if (d.key === p.device && d.title === p.title && anchor === p.anchor) return p;
			changed = true;
			return { ...p, device: d.key, title: d.title, anchor };
		});
		return changed ? out : pins;
	}

	// ── The dialog "Schnellaktionen anheften" ───────────

	/** The devices by plugin, in the order the plugins list them: [{ plugin, name, devices, pinned, total }]. */
	function pickGroups(devices, pins) {
		const map = new Map();
		for (const d of devices || []) {
			if (!map.has(d.plugin)) map.set(d.plugin, { plugin: d.plugin, name: d.pluginName || d.plugin, devices: [], pinned: 0, total: 0 });
			const g = map.get(d.plugin);
			g.devices.push(d);
			g.total += 1;
			if (isPinned(pins, d.key)) g.pinned += 1;
		}
		return [...map.values()];
	}

	const norm = (s) => String(s || '').toLocaleLowerCase('de-DE');

	/** Whether a device fits the search (its name, its line below — the room —, the plugin); an empty search: all. */
	function matches(d, q) {
		const n = norm(q).trim();
		if (!n) return true;
		return norm([d.title, d.subtitle, d.pluginName].filter(Boolean).join(' ')).includes(n);
	}

	/** A text cut at the first hit of the search: [{ text, hit }] (for the highlight; no markup). */
	function highlight(text, q) {
		const s = String(text || '');
		const n = norm(q).trim();
		const at = n ? norm(s).indexOf(n) : -1;
		if (at < 0) return [{ text: s, hit: false }];
		return [{ text: s.slice(0, at), hit: false }, { text: s.slice(at, at + n.length), hit: true }, { text: s.slice(at + n.length), hit: false }].filter((x) => x.text);
	}

	/** A pinned device one place up (dir -1) or down (+1) → the new list (a copy; the same array when it cannot move). */
	function movePin(pins, key, dir) {
		const list = (pins || []).slice();
		const i = list.findIndex((p) => p.device === key);
		const j = i + (dir < 0 ? -1 : 1);
		if (i < 0 || j < 0 || j >= list.length) return pins;
		[list[i], list[j]] = [list[j], list[i]];
		return list;
	}

	/** The pins in the order of `keys` (the rows after a drag); pins not named keep their place at the end. */
	function orderPins(pins, keys) {
		const list = pins || [];
		const out = [];
		for (const k of keys || []) { const p = list.find((x) => x.device === k); if (p && !out.includes(p)) out.push(p); }
		for (const p of list) if (!out.includes(p)) out.push(p);
		return out;
	}

	/** What the dialog is built from: the state of the list and the devices by plugin (the rows stay while it is the same). */
	function pickShape(load, devices) {
		return `${load}|${(devices || []).map((d) => `${d.plugin}/${d.key}`).join(',')}`;
	}

	// ── Numbers ─────────────────────────────────────────

	const tag = (locale) => (locale === 'en' ? 'en-US' : 'de-DE');

	/** 22 → "22", 21.5 → "21,5" (locale), at most one decimal; decimals 1 keeps it: 21 → "21,0". No grouping. */
	function formatNumber(v, locale, decimals = 0) {
		if (typeof v !== 'number' || !Number.isFinite(v)) return '';
		return new Intl.NumberFormat(tag(locale), { maximumFractionDigits: 1, minimumFractionDigits: Math.min(1, Math.max(0, decimals)), useGrouping: false }).format(v);
	}

	/** A value of the server (text or number) as text; null for none. */
	function valueText(v, locale) {
		if (typeof v === 'number') return formatNumber(v, locale);
		return typeof v === 'string' && v ? v : null;
	}

	/** The decimals a control's step needs (0.5 → 1). */
	const decimals = (c) => (c && c.step % 1 !== 0 ? 1 : 0);

	/** A control's value as it shows it: as many decimals as its step needs, then its unit ("21,0 °C"). */
	function controlText(v, c, locale) {
		const n = formatNumber(v, locale, decimals(c));
		return c && c.unit ? `${n} ${c.unit}` : n;
	}

	/** Onto the control's grid (min + n × step) and into its range. */
	function snap(v, c) {
		const stepped = c.min + Math.round((v - c.min) / c.step) * c.step;
		const rounded = decimals(c) === 0 ? Math.round(stepped) : Math.round(stepped * 10) / 10;
		return Math.min(c.max, Math.max(c.min, rounded));
	}

	/** Whether a unit is a temperature's (°C, °F, °): the value then gets the house with the thermometer. */
	const isTemperature = (unit) => typeof unit === 'string' && (unit.startsWith('°') || unit === '℃' || unit === '℉');

	/** A reading / badge as text: "48 %" (value and unit), "" without a value. */
	function readingText(r, locale) {
		const v = valueText(r && r.value, locale);
		return v === null ? '' : (r.unit ? `${v} ${r.unit}` : v);
	}

	// ── Running ─────────────────────────────────────────

	/** The state a run switches a toggle to: off when on, else on (an unknown state too). */
	const target = (a) => (isToggle(a) ? (a.state === 'on' ? 'off' : 'on') : null);

	/** Whether to ask first: only towards confirmWhen when the plugin gives it, else `confirm`. */
	const needsConfirm = (a) => (isToggle(a) && a.confirmWhen ? target(a) === a.confirmWhen : a.confirm === true);

	/**
	 * What the confirmation names: for a toggle the command of the state a run switches to (verbs, e.g. „Aufsperren“
	 * of a lock showing „Zugesperrt“), else the title.
	 */
	function confirmLabel(a) {
		const want = target(a);
		const v = want && a.verbs && typeof a.verbs[want] === 'string' ? a.verbs[want].trim() : '';
		return v || (a && a.title) || '';
	}

	/** The look of a toggle's current state ({ icon, tone }) or null. */
	function currentLook(a) {
		if (!isToggle(a) || !a.look) return null;
		if (a.state === 'on') return a.look.on || null;
		if (a.state === 'off') return a.look.off || null;
		return null;
	}

	/** The icon to draw now: the current state's own one, else the action's, else the bolt. */
	const displayIcon = (a) => (currentLook(a) && currentLook(a).icon) || (a && a.icon) || BOLT;

	/** An option's glyph: its own icon, else a built-in one for a common id, else null (then its label shows). */
	const optionGlyph = (o) => (o && o.icon) || (o && Object.prototype.hasOwnProperty.call(OPTION_GLYPHS, o.id) ? OPTION_GLYPHS[o.id] : null);

	/** The tone of a state for icons / chips: good | warn | crit | null. */
	function tone(state) {
		if (state === 'on' || state === 'good') return 'good';
		if (state === 'warn' || state === 'crit') return state;
		return null;
	}

	/**
	 * The text of a failed run → i18n key + parameter: the plugin's own sentence when it sent one, else one of
	 * home.qa.error.* (control_disabled, gone, no_user, busy, timeout, network, state_unknown, not_configured, failed).
	 */
	const REASONS = new Set(['control_disabled', 'gone', 'no_user', 'busy', 'timeout', 'network', 'state_unknown', 'not_configured', 'invalid']);
	function failureText(res, title, t) {
		const r = res || {};
		if (r.message && r.reason !== 'control_disabled') return t('home.qa.error.message', { name: title, message: r.message });
		const reason = REASONS.has(r.reason) ? (r.reason === 'invalid' ? 'failed' : r.reason) : 'failed';
		return t(`home.qa.error.${reason}`, { name: title });
	}

	/** After a refusal the list is asked again (the plugin's state changed under us). */
	const reloadAfter = (res) => !!res && (res.reason === 'control_disabled' || res.reason === 'gone' || res.reason === 'state_unknown');

	// ── Layout ──────────────────────────────────────────

	/** Options of a choice per row: up to 5 in one row, more as two even rows (6 → 3 + 3, 7 → 4 + 3). */
	const choicePerRow = (n) => (n <= 5 ? Math.max(1, n) : Math.ceil(n / 2));

	/** Buttons per row: up to 3, 4 as 2 + 2. */
	const buttonsPerRow = (n) => (n === 4 ? 2 : Math.min(3, Math.max(1, n)));

	// ── The day bar (widget.timeline) ───────────────────

	/** A position as text: "6:52" / "24:00" for a day (0…24), else the number. */
	function positionText(x, tl, locale) {
		const day = tl.from >= 0 && tl.to <= 24;
		if (!day) return formatNumber(x, locale);
		const m = Math.round(x * 60);
		return `${Math.floor(m / 60)}:${String(m % 60).padStart(2, '0')}`;
	}

	/**
	 * The bar as drawn → { segments: [{ left, width, tone, color, label }] (percent of the bar), now: percent | null,
	 * ticks: five evenly spaced marks (for 0…24 "0 6 12 18 24"), spoken: "0:00–6:00 Nacht, …", nowText: "6:52" | null }.
	 */
	function timelineView(tl, locale) {
		const span = tl.to - tl.from;
		const pct = (x) => Math.min(100, Math.max(0, ((x - tl.from) / span) * 100));
		return {
			segments: tl.segments.map((s) => ({ left: pct(s.from), width: pct(s.to) - pct(s.from), tone: s.tone || null, color: s.color || null, label: s.label || null })),
			now: tl.now == null ? null : pct(tl.now),
			ticks: [0, 1, 2, 3, 4].map((i) => formatNumber(tl.from + (span * i) / 4, locale)),
			spoken: tl.segments.map((s) => [`${positionText(s.from, tl, locale)}–${positionText(s.to, tl, locale)}`, s.label].filter(Boolean).join(' ')).join(', '),
			nowText: tl.now == null ? null : positionText(tl.now, tl, locale),
		};
	}

	return {
		BOLT, OUTDOOR, MAX_PINS, PART,
		actionKey, deviceKey, isToggle, isOn,
		group, parts, asButton, shownParts,
		resolve, isPinned, pinDevice, setHidden, syncPins,
		pickGroups, matches, highlight, movePin, orderPins, pickShape,
		formatNumber, valueText, decimals, controlText, snap, isTemperature, readingText,
		target, needsConfirm, confirmLabel, currentLook, displayIcon, optionGlyph, tone, failureText, reloadAfter,
		choicePerRow, buttonsPerRow,
		positionText, timelineView,
	};
});
