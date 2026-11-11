/**
 * GateControl -- Familie view state (renderer, no DOM access)
 *
 * Pure helpers for the page "Familie" (plugin gatecontrol-familie, "Internet
 * zu Hause"): which tabs a person sees, the card of a child in its states
 * (pause, "Heute länger", error, normal, not filtered — checked in this
 * order, like the portal card), the choices of the dialogs "Pausieren" and
 * "Heute länger", the note "Pausiert von der Regel …", the rule list with
 * its trigger and actions in words, the rule action "Internet zu Hause"
 * (the other actions of a rule stay as they are when it is saved), "Meine
 * Anwesenheit" (state, source, own devices) and where a push leads. Loaded
 * as a plain script before familie-view.js (window.GCFamilieState) and
 * required by the node tests (test/familie-state.test.js).
 *
 * Inputs are what window.gatecontrol.familie returns (core FamilieService,
 * answers already cleaned by core utils/familie.js: times are ms
 * timestamps); `t` is the i18n function (keys familie.* of the core
 * locales). Times are shown in the family's time zone (`internet.timezone`).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCFamilieState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const APP_ROUTE = 'plg-gatecontrol-familie';
	const TOPIC_PREFIX = 'plugin:gatecontrol-familie:';
	const INTERNET_TOPIC = `${TOPIC_PREFIX}internet`;
	const PUSH_KINDS = ['pause', 'resume', 'extend', 'extend_end', 'pause_over', 'extend_over'];
	const TABS = ['internet', 'rules', 'presence'];
	const ERRORS = ['network', 'timeout', 'forbidden', 'invalid', 'parents_only', 'not_found', 'unavailable', 'not_person', 'module_off', 'not_member', 'not_configured', 'auth', 'too_many', 'state_required'];
	const COLOR_RE = /^#[0-9a-fA-F]{6}$/;
	const TIME_RE = /^([01]\d|2[0-3]):([0-5]\d)$/;
	// Colours for members without one: calm, readable on both themes.
	const PALETTE = ['#2FBF71', '#3B82F6', '#F97316', '#A855F7', '#EAB308', '#EC4899', '#14B8A6', '#EF4444'];
	const PAUSE_CHOICES = [30, 60, 120, 'until'];
	const EXTEND_CHOICES = [15, 30, 60];
	const RULE_CHOICES = [30, 60, 120, 'until'];
	const MAX_ACTIONS = 10;
	const MAX_RULE_MIN = 1440;
	const MIN = 60000;

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const localeTag = (locale) => (locale === 'en' ? 'en-GB' : 'de-DE');
	const pad = (n) => String(n).padStart(2, '0');
	const isMs = (v) => typeof v === 'number' && Number.isFinite(v) && v > 0;

	// ── Time (in the family's time zone) ─────────────────────

	const fmtCache = new Map();
	/** Intl formatter in `tz` (the device's zone when the name is unknown here). */
	function fmt(tag, tz, opts) {
		const key = `${tag}|${tz || ''}|${JSON.stringify(opts)}`;
		if (!fmtCache.has(key)) {
			let f;
			try { f = new Intl.DateTimeFormat(tag, tz ? { ...opts, timeZone: tz } : opts); } catch { f = new Intl.DateTimeFormat(tag, opts); }
			fmtCache.set(key, f);
		}
		return fmtCache.get(key);
	}

	/** { y, m, d, hh, mm } of a moment in `tz`. */
	function parts(ms, tz) {
		const out = {};
		for (const p of fmt('en-GB', tz, { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(new Date(ms))) out[p.type] = p.value;
		return { y: Number(out.year), m: Number(out.month), d: Number(out.day), hh: Number(out.hour) % 24, mm: Number(out.minute) };
	}

	/** 'YYYY-MM-DD' of a moment in `tz`. */
	function dayOf(ms, tz) {
		const p = parts(ms, tz);
		return `${p.y}-${pad(p.m)}-${pad(p.d)}`;
	}

	/** 'HH:MM' of a moment in `tz`. */
	function hm(ms, tz) {
		if (!isMs(ms)) return '';
		const p = parts(ms, tz);
		return `${pad(p.hh)}:${pad(p.mm)}`;
	}

	/** Calendar days from `a` to `b` in `tz`. */
	function dayDiff(a, b, tz) {
		return Math.round((Date.parse(`${dayOf(b, tz)}T00:00:00Z`) - Date.parse(`${dayOf(a, tz)}T00:00:00Z`)) / 86400000);
	}

	/**
	 * A moment in words, seen from `ctx.now`: "21:00" today, "morgen 06:00",
	 * "gestern 22:10", else "Fr., 13.11., 21:00". ctx = { now, tz, locale }.
	 */
	function whenText(ms, ctx, t) {
		if (!isMs(ms)) return '';
		const time = hm(ms, ctx.tz);
		const d = dayDiff(ctx.now, ms, ctx.tz);
		if (d === 0) return time;
		if (d === 1) return t('familie.when.tomorrow', { time });
		if (d === -1) return t('familie.when.yesterday', { time });
		const day = fmt(localeTag(ctx.locale), ctx.tz, { weekday: 'short', day: '2-digit', month: '2-digit' }).format(new Date(ms));
		return t('familie.when.day', { day, time });
	}

	/** "Mittwoch, 11. November" */
	function dateLong(ms, ctx) {
		return fmt(localeTag(ctx.locale), ctx.tz, { weekday: 'long', day: 'numeric', month: 'long' }).format(new Date(ms));
	}

	/**
	 * The server's "now" for an answer of `internet`: its serverTime plus the
	 * time since it was fetched (a wrong PC clock does not end a pause early).
	 */
	function serverNow(res, localNow) {
		const i = res && res.internet;
		if (!i || !isMs(i.serverTime) || !isMs(res.fetchedAt)) return localNow;
		return i.serverTime + Math.max(0, localNow - res.fetchedAt);
	}

	/** 30 → "30 Min.", 60 → "1 Std.", 90 → "1 Std. 30 Min." */
	function durationText(minutes, t) {
		const n = Number(minutes);
		if (!Number.isSafeInteger(n) || n <= 0) return '';
		const h = Math.floor(n / 60);
		const m = n % 60;
		if (!h) return t('familie.dur.min', { n: m });
		if (!m) return t('familie.dur.h', { n: h });
		return t('familie.dur.hm', { h, m });
	}

	/** ["Tim", "Lea", "Mia"] → "Tim, Lea und Mia" */
	function joinNames(names, t) {
		const a = names.filter(Boolean);
		if (a.length <= 1) return a[0] || '';
		return `${a.slice(0, -1).join(', ')} ${t('familie.and')} ${a[a.length - 1]}`;
	}

	// ── Members ──────────────────────────────────────────────

	function initialsOf(name) {
		const words = str(name).trim().split(/\s+/).filter(Boolean);
		if (!words.length) return '?';
		if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
		return (words[0][0] + words[words.length - 1][0]).toUpperCase();
	}

	/** { userId, name, initials, color, avatarUrl } for the avatar of a member. */
	function faceOf(m) {
		const o = m && typeof m === 'object' ? m : {};
		const id = Number(o.userId) || 0;
		return {
			userId: id,
			name: str(o.name),
			initials: str(o.initials) || initialsOf(o.name),
			color: COLOR_RE.test(str(o.color)) ? o.color : PALETTE[Math.abs(id) % PALETTE.length],
			avatarUrl: typeof o.avatarUrl === 'string' && o.avatarUrl ? o.avatarUrl : null,
		};
	}

	// ── Tabs ─────────────────────────────────────────────────

	/**
	 * The tabs of a person (status of the core service: { me: { role },
	 * modules }): parents "Internet zu Hause", "Regeln" (module rules) and
	 * "Meine Anwesenheit" (module presence). A child sees its own card and
	 * nothing else; one without a card (an adult child, `internet` answered
	 * without children) "Meine Anwesenheit" instead.
	 */
	function tabsFor(status, internet) {
		const st = status && typeof status === 'object' ? status : {};
		const role = st.me && st.me.role;
		const mod = st.modules || {};
		if (role === 'parent') return ['internet', mod.rules ? 'rules' : null, mod.presence ? 'presence' : null].filter(Boolean);
		if (role !== 'child') return [];
		const i = internet && internet.internet;
		const noCard = !!i && i.available && i.manage === false && Array.isArray(i.children) && !i.children.length;
		if (noCard && mod.presence) return ['presence'];
		return ['internet'];
	}

	// ── Internet zu Hause: the card of a child ───────────────

	/** 'paused' | 'extended' | 'error' | 'normal' | 'unfiltered' — in this order. */
	function cardState(child, now) {
		const c = child || {};
		if (isMs(c.paused) && c.paused > now) return 'paused';
		if (isMs(c.extended) && c.extended > now) return 'extended';
		if (c.error) return 'error';
		if (c.filtered) return 'normal';
		return 'unfiltered';
	}

	/** The buttons of a card: ids in the order shown. Without `manage` (a child) none. */
	function buttonsFor(state, manage) {
		if (!manage) return [];
		if (state === 'paused') return ['resume', 'add30'];
		if (state === 'extended') return ['pause', 'extend30', 'endExtra'];
		if (state === 'normal') return ['pause', 'extend'];
		if (state === 'error') return ['reload'];
		return [];
	}

	/** { icon, text } of where the child is — null when it does not share (or the function is off). */
	function presenceChip(p, t) {
		if (!p || typeof p !== 'object') return null;
		if (p.state === 'home') {
			if (p.source === 'wifi') return { icon: 'wifi', text: t('familie.internet.presence.homeWifi') };
			if (p.source === 'app') return { icon: 'phone', text: t('familie.internet.presence.homeApp') };
			return { icon: 'home', text: t('familie.internet.presence.home') };
		}
		if (p.state === 'away') return { icon: 'pin', text: t('familie.internet.presence.away') };
		return null;
	}

	function devicesText(n, t) {
		if (!Number.isSafeInteger(n) || n <= 0) return '';
		return n === 1 ? t('familie.internet.devices.one') : t('familie.internet.devices.other', { count: n });
	}

	/** "Soziale Netzwerke, Spiele und Videos" / "Internet aus" */
	function blockText(s, t) {
		if (!s || s.block !== 'categories' || !Array.isArray(s.categories) || !s.categories.length) return t('familie.internet.block.all');
		return joinNames(s.categories.map((c) => t(`familie.internet.cat.${c}`)), t);
	}

	/** "Pausiert von der Regel „Abendessen“ · Anna · 17:30" in pieces (the title is shown bold). */
	function ruleNote(by, kind, ctx, t) {
		if (!by || !by.rule) return null;
		const key = kind === 'extended' ? 'familie.internet.extRule' : 'familie.internet.byRule';
		const title = str(by.rule.title).trim();
		return {
			ruleId: by.rule.id,
			text: title ? t(key) : t(`${key}Unnamed`),
			title: title ? t('familie.quoted', { text: title }) : null,
			tail: [by.name, isMs(by.at) ? whenText(by.at, ctx, t) : ''].filter(Boolean).join(' · '),
		};
	}

	/** "Von Marc um 17:30." — who set it by hand; '' when unknown or set by a rule. */
	function byText(by, ctx, t) {
		if (!by || by.rule || !by.name) return '';
		return isMs(by.at) ? t('familie.internet.by', { name: by.name, time: whenText(by.at, ctx, t) }) : t('familie.internet.byName', { name: by.name });
	}

	/**
	 * The card of a child: { state, face, chip: { cls, text }, presence,
	 * sub (lines joined with " · " or sentences), note (rule) | null,
	 * buttons, until }. ctx = { now (server time), tz, locale, manage }.
	 */
	function cardView(child, ctx, t) {
		const c = child || {};
		const state = cardState(c, ctx.now);
		const away = !!c.presence && c.presence.state === 'away';
		const devices = devicesText(c.devices, t);
		const next = c.nextSchedule || null;
		const out = { state, face: faceOf(c), chip: null, presence: state === 'error' ? null : presenceChip(c.presence, t), sub: '', note: null, buttons: buttonsFor(state, ctx.manage === true), until: null };
		const dots = (a) => a.filter(Boolean).join(' · ');
		const says = (a) => a.filter(Boolean).join(' ');

		if (state === 'paused') {
			out.until = c.paused;
			out.chip = { cls: 'is-warn', text: t('familie.internet.chip.paused', { time: whenText(c.paused, ctx, t) }) };
			out.note = ruleNote(c.pausedBy, 'paused', ctx, t);
			const off = c.devices === 1 ? t('familie.internet.pausedOn.one') : c.devices > 1 ? t('familie.internet.pausedOn.other', { count: c.devices }) : t('familie.internet.pausedOn.none');
			out.sub = says([off, byText(c.pausedBy, ctx, t), away ? t('familie.internet.awayPause', { name: out.face.name }) : '']);
		} else if (state === 'extended') {
			out.until = c.extended;
			out.chip = { cls: 'is-info', text: t('familie.internet.chip.extended', { time: whenText(c.extended, ctx, t) }) };
			out.note = ruleNote(c.extendedBy, 'extended', ctx, t);
			const by = c.extendedBy && !c.extendedBy.rule && c.extendedBy.name
				? (isMs(c.extendedBy.at) ? t('familie.internet.extBy', { name: c.extendedBy.name, time: whenText(c.extendedBy.at, ctx, t) }) : c.extendedBy.name) : '';
			out.sub = dots([
				next ? t('familie.internet.sub.suspended', { time: whenText(next.from, ctx, t) }) : t('familie.internet.sub.suspendedAll'),
				by, devices, away ? t('familie.internet.awayExtra', { name: out.face.name }) : '',
			]);
		} else if (state === 'error') {
			out.chip = { cls: 'is-mute', text: t('familie.internet.chip.error') };
			out.sub = t('familie.internet.sub.error');
		} else if (state === 'normal') {
			if (next && next.active) {
				out.until = next.to;
				out.chip = { cls: 'is-mute', text: isMs(next.to) ? t('familie.internet.chip.blocked', { time: whenText(next.to, ctx, t) }) : t('familie.internet.chip.blockedNow') };
				out.sub = dots([t('familie.internet.sub.active', { what: blockText(next, t) }), devices]);
			} else {
				out.until = next ? next.from : null;
				out.chip = { cls: 'is-ok', text: t('familie.internet.chip.on') };
				out.sub = dots([next ? t('familie.internet.sub.next', { time: whenText(next.from, ctx, t), what: blockText(next, t) }) : t('familie.internet.sub.noSchedule'), devices]);
			}
		} else {
			out.chip = { cls: 'is-mute', text: t('familie.internet.chip.unfiltered') };
			out.sub = c.devices > 0 ? t('familie.internet.sub.noFilter', { name: out.face.name }) : t('familie.internet.sub.noDevices');
		}
		return out;
	}

	/** The next moment a card changes by itself (a pause / extra time ends, a blocked time starts or ends) or null. */
	function nextChange(children, now) {
		let best = null;
		for (const c of Array.isArray(children) ? children : []) {
			const s = c.nextSchedule || {};
			for (const v of [c.paused, c.extended, s.from, s.to]) if (isMs(v) && v > now && (best === null || v < best)) best = v;
		}
		return best;
	}

	// ── Dialog "Pausieren" ───────────────────────────────────

	const isTime = (v) => typeof v === 'string' && TIME_RE.test(v);

	/** The next full or half hour at least 30 min ahead, as 'HH:MM' in `tz` (the default of "bis Uhrzeit"). */
	function defaultUntil(now, tz) {
		const p = parts(now + 30 * MIN, tz);
		const mins = p.hh * 60 + p.mm;
		const up = (Math.ceil(mins / 30) * 30) % 1440;
		return `${pad(Math.floor(up / 60))}:${pad(up % 60)}`;
	}

	/** Is 'HH:MM' already over today in `tz` (then it means tomorrow)? */
	function untilTomorrow(time, now, tz) {
		if (!isTime(time)) return false;
		const p = parts(now, tz);
		const [h, m] = time.split(':').map(Number);
		return h * 60 + m <= p.hh * 60 + p.mm;
	}

	/** What `api.pause` gets for a choice of the dialog: { minutes } | { until } | null (no valid time). */
	function pauseArgs(choice, time) {
		if (choice === 'until') return isTime(time) ? { until: time } : null;
		return Number.isSafeInteger(choice) && choice > 0 ? { minutes: choice } : null;
	}

	/** The line under the choices of "Pausieren": until when, and that the child is told. */
	function pauseHint(choice, time, name, ctx, t) {
		const told = t('familie.dialog.told', { name });
		if (choice === 'until') {
			if (!isTime(time)) return t('familie.pause.untilMissing');
			return `${untilTomorrow(time, ctx.now, ctx.tz) ? t('familie.pause.untilTomorrow', { time }) : t('familie.pause.untilToday', { time })} ${told}`;
		}
		return `${t('familie.pause.durHint', { time: whenText(ctx.now + choice * MIN, ctx, t) })} ${told}`;
	}

	// ── Dialog "Heute länger" ────────────────────────────────

	/**
	 * How "Heute länger" counts for a child: { choose, from } — `choose`: the
	 * blocked time starts later today and no extra time runs, so the minutes
	 * may count from its start (`from`) or from now. Otherwise they count
	 * from the end of a running extra time, else from now.
	 */
	function extendPlan(child, now, tz) {
		const c = child || {};
		const running = isMs(c.extended) && c.extended > now;
		const s = c.nextSchedule;
		const ahead = !!s && !s.active && isMs(s.from) && s.from > now && dayDiff(now, s.from, tz) === 0;
		return { choose: ahead && !running, from: ahead ? s.from : null, running: running ? c.extended : null };
	}

	/** When the extra time would end (as the plugin counts it). */
	function extendEnd(child, minutes, fromNow, now, tz) {
		const plan = extendPlan(child, now, tz);
		const base = plan.running || (plan.choose && !fromNow ? plan.from : now);
		return base + minutes * MIN;
	}

	function extendHint(child, minutes, fromNow, name, ctx, t) {
		const plan = extendPlan(child, ctx.now, ctx.tz);
		const end = whenText(extendEnd(child, minutes, fromNow, ctx.now, ctx.tz), ctx, t);
		const first = plan.choose && !fromNow ? t('familie.extend.hintSchedule', { time: end }) : t('familie.extend.hintNow', { time: end });
		return `${first} ${t('familie.dialog.told', { name })}`;
	}

	// ── Rules ────────────────────────────────────────────────

	const nameIn = (people, id) => {
		const p = (Array.isArray(people) ? people : []).find((x) => x && x.userId === id);
		return p ? str(p.name) : '';
	};

	/** "Täglich um 18:00", "Mo–Fr um 07:00", "Mo, Mi um 15:00" */
	function scheduleText(tr, locale, t) {
		const days = Array.isArray(tr.weekdays) ? tr.weekdays : [];
		const time = tr.time || '';
		if (!time) return t('familie.rules.trig.other');
		if (days.length === 7 || !days.length) return t('familie.rules.trig.daily', { time });
		// 2024-01-01 is a Monday
		const short = (d) => fmt(localeTag(locale), 'UTC', { weekday: 'short' }).format(new Date(Date.UTC(2024, 0, d))).replace(/\.$/, '');
		const run = days.length >= 3 && days.every((d, i) => i === 0 || d === days[i - 1] + 1);
		const label = run ? `${short(days[0])}–${short(days[days.length - 1])}` : days.map(short).join(', ');
		return t('familie.rules.trig.days', { days: label, time });
	}

	/** The trigger of a rule in words. */
	function triggerText(trigger, people, locale, t) {
		const tr = trigger || {};
		const who = (id) => nameIn(people, id);
		switch (tr.type) {
			case 'schedule': return scheduleText(tr, locale, t);
			case 'all_away': return t('familie.rules.trig.all_away');
			case 'first_home': return t('familie.rules.trig.first_home');
			case 'child_home_alone': return t('familie.rules.trig.child_home_alone');
			case 'person_home':
			case 'person_away': return t(`familie.rules.trig.${tr.type}`, { name: who(tr.userId) || t('familie.rules.someone') });
			case 'place_enter':
			case 'place_exit': return t(`familie.rules.trig.${tr.type}`, { name: who(tr.userId) || t('familie.rules.someone'), place: tr.placeName || '–' });
			case 'school_change': return tr.userId && who(tr.userId) ? t('familie.rules.trig.school', { name: who(tr.userId) }) : t('familie.rules.trig.schoolAny');
			default: return t('familie.rules.trig.other');
		}
	}

	/** An action of a rule in words ("Internet von Tim pausieren (30 Min.)"). */
	function actionText(action, people, t) {
		const a = action || {};
		if (a.type === 'internet') {
			const name = a.name || nameIn(people, a.userId) || t('familie.rules.someone');
			if (a.op === 'resume') return t('familie.rules.act.resume', { name });
			if (a.until) return t('familie.rules.act.pauseUntil', { name, time: a.until });
			if (a.minutes) return t('familie.rules.act.pauseFor', { name, dur: durationText(a.minutes, t) });
			return t('familie.rules.act.pause', { name });
		}
		if (a.type === 'notify') {
			if (a.to === 'parents') return t('familie.rules.act.notifyParents');
			if (a.to === 'all') return t('familie.rules.act.notifyAll');
			const names = joinNames((Array.isArray(a.to) ? a.to : []).map((id) => nameIn(people, id)), t);
			return names ? t('familie.rules.act.notifyTo', { names }) : t('familie.rules.act.notify');
		}
		if (a.type === 'messenger') {
			if (a.to === 'family') return t('familie.rules.act.chatFamily');
			const names = joinNames((Array.isArray(a.to) ? a.to : []).map((id) => nameIn(people, id)), t);
			return names ? t('familie.rules.act.chatTo', { names }) : t('familie.rules.act.chat');
		}
		if (a.type === 'quick_action') {
			if (!a.title) return t('familie.rules.act.quick');
			return a.verb ? t('familie.rules.act.quickVerb', { title: a.title, verb: a.verb }) : a.title;
		}
		return t('familie.rules.act.other');
	}

	/** The "Internet zu Hause" actions of a rule: [{ index, action }]. */
	function internetActions(rule) {
		const out = [];
		((rule && rule.actions) || []).forEach((action, index) => { if (action && action.type === 'internet') out.push({ index, action }); });
		return out;
	}

	/** Why an "Internet zu Hause" action does not run ("Jonas ist kein minderjähriges Kind der Familie mehr") or ''. */
	function problemText(action, people, t) {
		const a = action || {};
		if (a.type !== 'internet' || (a.available !== false && !a.problem)) return '';
		const name = a.name || nameIn(people, a.userId) || t('familie.rules.someone');
		const code = ['not_found', 'not_allowed', 'unavailable'].includes(a.problem) ? a.problem : 'unavailable';
		return t(`familie.rules.problem.${code}`, { name });
	}

	/**
	 * A row of the rule list: { id, title, summary, problems: [text],
	 * active, canToggle, canEdit, editOff (why "Bearbeiten" is off) }.
	 * "Bearbeiten" changes only the action "Internet zu Hause": it needs a
	 * rule the person may edit and the action on this server (rules/options).
	 */
	function ruleRow(rule, options, locale, t) {
		const r = rule || {};
		const people = options && options.people;
		const net = options && options.internet;
		const acts = Array.isArray(r.actions) ? r.actions : [];
		const offered = !!net && net.available === true;
		const full = acts.length >= MAX_ACTIONS && !internetActions(r).length;
		const editOff = !r.editable ? 'readonly' : !offered ? ((net && net.reason) === 'parents_only' ? 'parents_only' : 'unavailable') : full ? 'full' : null;
		return {
			id: r.id,
			title: str(r.title).trim() || t('familie.rules.untitled'),
			summary: [triggerText(r.trigger, people, locale, t), acts.map((a) => actionText(a, people, t)).join(', ')].filter(Boolean).join(' · '),
			problems: acts.map((a) => problemText(a, people, t)).filter(Boolean),
			active: r.active === true,
			canToggle: r.pausable === true,
			canEdit: !editOff,
			editOff,
		};
	}

	/** The form of the action dialog for an action (or a new one for the first child). */
	function formOf(action, children) {
		const kids = Array.isArray(children) ? children : [];
		if (!action) return { userId: kids.length ? kids[0].userId : null, op: 'pause', choice: 30, until: '' };
		const until = isTime(action.until) ? action.until : '';
		const minutes = Number.isSafeInteger(action.minutes) && action.minutes > 0 ? action.minutes : 30;
		return { userId: action.userId || null, op: action.op === 'resume' ? 'resume' : 'pause', choice: until ? 'until' : minutes, until };
	}

	/** The durations offered for a form: 30 / 60 / 120 min, the stored one when it is another, "bis Uhrzeit". */
	function ruleChoices(form) {
		const c = form && form.choice;
		if (Number.isSafeInteger(c) && !RULE_CHOICES.includes(c)) return [...RULE_CHOICES.filter((x) => x !== 'until'), c].sort((a, b) => a - b).concat('until');
		return RULE_CHOICES.slice();
	}

	/** The form → the action of the rule API, or null while it is incomplete. */
	function actionBody(form) {
		const f = form || {};
		if (!Number.isSafeInteger(f.userId) || f.userId <= 0) return null;
		if (f.op === 'resume') return { type: 'internet', op: 'resume', userId: f.userId };
		if (f.op !== 'pause') return null;
		if (f.choice === 'until') return isTime(f.until) ? { type: 'internet', op: 'pause', userId: f.userId, until: f.until } : null;
		return Number.isSafeInteger(f.choice) && f.choice >= 1 && f.choice <= MAX_RULE_MIN ? { type: 'internet', op: 'pause', userId: f.userId, minutes: f.choice } : null;
	}

	/**
	 * All actions of `rule` for `PATCH rules/<id>` with one change: `index`
	 * null adds `body` at the end, otherwise the action there is replaced
	 * (`body`) or removed (`body` null). Every other action goes back as the
	 * server sent it (`input`). → the list, or null when it would be empty,
	 * too long, or the index is no "Internet zu Hause" action.
	 */
	function withAction(rule, index, body) {
		const acts = (rule && Array.isArray(rule.actions)) ? rule.actions : [];
		if (acts.some((a) => !a || !a.input)) return null;
		const out = acts.map((a) => a.input);
		if (index === null || index === undefined) {
			if (!body) return null;
			out.push(body);
		} else {
			if (!Number.isSafeInteger(index) || !acts[index] || acts[index].type !== 'internet') return null;
			if (body) out[index] = body;
			else out.splice(index, 1);
		}
		return out.length && out.length <= MAX_ACTIONS ? out : null;
	}

	// ── Meine Anwesenheit ────────────────────────────────────

	/** "zu Hause seit 16:40" — one's own state in words. */
	function ownStateText(self, ctx, t) {
		const s = self || {};
		if (s.state === 'home' || s.state === 'away') {
			return isMs(s.since) ? t(`familie.presence.state.${s.state}Since`, { time: whenText(s.since, ctx, t) }) : t(`familie.presence.state.${s.state}`);
		}
		return t(s.state === 'unknown' ? 'familie.presence.state.unknown' : 'familie.presence.state.not_shared');
	}

	/** { icon, text, cls } "Quelle: WLAN" / "Quelle: App", or null without a state. */
	function sourceChip(self, t) {
		const s = self || {};
		if ((s.state !== 'home' && s.state !== 'away') || !s.source) return null;
		return s.source === 'wifi' ? { icon: 'wifi', text: t('familie.presence.source.wifi'), cls: 'is-ok' } : { icon: 'phone', text: t('familie.presence.source.app'), cls: 'is-ok' };
	}

	/** A row of "Meine Geräte im Heim-WLAN": { id, name, meta, counts, countsText }. */
	function deviceRow(d, ctx, t) {
		const o = d || {};
		const seen = isMs(o.lastSeen) ? t('familie.presence.devices.lastSeen', { time: whenText(o.lastSeen, ctx, t) }) : t('familie.presence.devices.never');
		return {
			id: o.id,
			name: str(o.name) || t('familie.presence.devices.unnamed'),
			meta: [seen, o.gateway].filter(Boolean).join(' · '),
			counts: o.counts === true,
			countsText: o.counts === true ? t('familie.presence.devices.counts') : t('familie.presence.devices.countsNot'),
		};
	}

	// ── Errors and push ──────────────────────────────────────

	function errorText(res, t) {
		const code = res && typeof res.code === 'string' ? res.code : 'failed';
		if (ERRORS.includes(code)) return t(`familie.err.${code}`);
		if (/^http_5\d\d$/.test(code)) return t('familie.err.server');
		return t('familie.err.failed', { code });
	}

	/**
	 * "Internet zu Hause" context of an inbox entry ({ topic, data }) — the
	 * same rule as the core (utils/familie.js pushContext) — or null.
	 */
	function entryContext(entry) {
		if (!entry || typeof entry !== 'object') return null;
		const topic = str(entry.topic);
		const data = entry.data && typeof entry.data === 'object' && !Array.isArray(entry.data) ? entry.data : {};
		const f = data.familie && typeof data.familie === 'object' && !Array.isArray(data.familie) ? data.familie : {};
		const ours = topic === INTERNET_TOPIC || ((topic.startsWith(TOPIC_PREFIX) || data.route === APP_ROUTE) && f.type === 'internet');
		if (!ours) return null;
		const id = (v) => (Number.isSafeInteger(v) && v > 0 ? v : null);
		return { type: 'internet', kind: PUSH_KINDS.includes(f.kind) ? f.kind : null, userId: id(f.userId), ruleId: id(f.ruleId) };
	}

	/**
	 * Where a context leads: { tab, childId, ruleId } — a push of "Internet
	 * zu Hause" the cards (on the child), `{ tab: 'rules', ruleId }` the
	 * rule ("Regel öffnen"). A tab the person does not have falls back to the first.
	 */
	function openTarget(ctx, tabs) {
		const c = ctx && typeof ctx === 'object' ? ctx : {};
		const have = Array.isArray(tabs) && tabs.length ? tabs : ['internet'];
		const want = TABS.includes(c.tab) ? c.tab : 'internet';
		const tab = have.includes(want) ? want : have[0];
		const id = (v) => (Number.isSafeInteger(v) && v > 0 ? v : null);
		return { tab, childId: tab === 'internet' ? id(c.userId) : null, ruleId: tab === 'rules' ? id(c.ruleId) : null };
	}

	return {
		APP_ROUTE,
		TOPIC_PREFIX,
		INTERNET_TOPIC,
		PUSH_KINDS,
		TABS,
		PAUSE_CHOICES,
		EXTEND_CHOICES,
		MAX_ACTIONS,
		hm,
		dayOf,
		whenText,
		dateLong,
		serverNow,
		durationText,
		joinNames,
		faceOf,
		tabsFor,
		cardState,
		buttonsFor,
		presenceChip,
		blockText,
		cardView,
		nextChange,
		defaultUntil,
		untilTomorrow,
		pauseArgs,
		pauseHint,
		extendPlan,
		extendEnd,
		extendHint,
		triggerText,
		actionText,
		internetActions,
		problemText,
		ruleRow,
		formOf,
		ruleChoices,
		actionBody,
		withAction,
		ownStateText,
		sourceChip,
		deviceRow,
		errorText,
		entryContext,
		openTarget,
	};
});
