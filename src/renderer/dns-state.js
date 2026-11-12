/**
 * GateControl -- DNS-Schutz view state (renderer, no DOM access)
 *
 * Pure helpers for the card "DNS-Schutz" on the start page ("Übersicht"):
 * the DNS filter of the VPN devices (plugin gatecontrol-dns). What the card
 * shows in its states — active, paused with the time left, filter down
 * ("fallback"), not filtered, starting, not reachable —, the counters, the
 * durations the server allows, the note of a pause, the top blocked domains
 * and the text of a failure. The card draws what the server says (`may`) and
 * decides nothing itself. Loaded as a plain script before dns-view.js
 * (window.GCDnsState) and required by the node tests (test/dns-state.test.js).
 *
 * Input is the snapshot of window.gatecontrol.dnsProtect (core
 * DnsProtectService: { state, data, fetchedAt, stale, error }, `data`
 * cleaned by core utils/dns-protect.js, times as ms); `t` is the i18n
 * function (keys dnsProtect.* of the core locales).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDnsState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	// The chips always shown; 240 only when the server offers it.
	const CHIPS = [5, 30, 60];
	const LONG = 240;
	const EXTEND = 30;
	const BANNER_REASONS = ['profile', 'admins_only'];
	// trouble the app words itself (the answer, if any, is not from the plugin)
	const OWN_ERRORS = ['network', 'timeout', 'rate_limited'];
	const MIN = 60000;

	const localeTag = (locale) => (locale === 'en' ? 'en-GB' : 'de-DE');
	const pad = (n) => String(n).padStart(2, '0');
	const isMs = (v) => typeof v === 'number' && Number.isFinite(v) && v > 0;

	// ── Time ─────────────────────────────────────────────────

	/** The server's clock now: its time plus what passed here since the answer. */
	function serverNow(snap, now) {
		const d = snap && snap.data;
		if (!d || !isMs(d.serverTime) || !isMs(snap.fetchedAt)) return now;
		return d.serverTime + Math.max(0, now - snap.fetchedAt);
	}

	/** A server time on this PC's clock (only a clock off by a minute or more is corrected). */
	function onLocalClock(ms, snap) {
		const d = snap && snap.data;
		if (!isMs(ms) || !d || !isMs(d.serverTime) || !isMs(snap.fetchedAt)) return ms;
		const skew = snap.fetchedAt - d.serverTime;
		return Math.abs(skew) >= MIN ? ms + skew : ms;
	}

	/** "15:12" on this PC's clock. */
	function hm(ms, locale) {
		if (!isMs(ms)) return '';
		return new Intl.DateTimeFormat(localeTag(locale), { hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(ms));
	}

	/** Milliseconds a pause still runs (0 when over; null: no end). */
	function remainingMs(snap, now) {
		const p = snap && snap.data && snap.data.pause;
		if (!p || !isMs(p.until)) return null;
		return Math.max(0, p.until - serverNow(snap, now));
	}

	/** "24:08", from an hour on "1:05:00". */
	function countdown(ms) {
		if (ms === null || ms === undefined) return '';
		const s = Math.max(0, Math.ceil(ms / 1000));
		const h = Math.floor(s / 3600);
		const m = Math.floor((s % 3600) / 60);
		return h > 0 ? `${h}:${pad(m)}:${pad(s % 60)}` : `${pad(m)}:${pad(s % 60)}`;
	}

	/** "30 Minuten", "1 Stunde", "1 Std. 30 Min." */
	function durationText(minutes, t) {
		const n = Math.max(1, Math.round(minutes));
		if (n < 60) return n === 1 ? t('dnsProtect.duration.minute') : t('dnsProtect.duration.minutes', { n });
		const h = Math.floor(n / 60);
		const m = n % 60;
		if (m) return t('dnsProtect.duration.hm', { h, m });
		return h === 1 ? t('dnsProtect.duration.hour') : t('dnsProtect.duration.hours', { n: h });
	}

	// ── Numbers ──────────────────────────────────────────────

	function num(n, locale) {
		return new Intl.NumberFormat(localeTag(locale)).format(n || 0);
	}

	/** "15,1 %" */
	function percent(p, locale) {
		return new Intl.NumberFormat(localeTag(locale), { style: 'percent', maximumFractionDigits: 1 }).format((p || 0) / 100);
	}

	// ── The card ─────────────────────────────────────────────

	const shown = (snap) => !!snap && snap.state === 'available';

	function counters(d, locale, t) {
		const c = d.counters;
		return {
			items: [
				{ key: 'queries', label: t('dnsProtect.kv.queries'), value: num(c.queries, locale) },
				{ key: 'blocked', label: t('dnsProtect.kv.blocked'), value: num(c.blocked, locale) },
				{ key: 'percent', label: t('dnsProtect.kv.percent'), value: percent(c.percent, locale) },
			],
			// whose numbers, unless they are this device's
			note: c.scope === 'device' ? '' : t(`dnsProtect.scope.${c.scope === 'person' ? 'person' : 'server'}`),
		};
	}

	/** The duration chips: 5 / 30 / 60 always (greyed when not offered), 4 h only when offered, "Bis ich wieder einschalte". */
	function pauseChoices(may, t) {
		const offered = may.durations || [];
		const list = [...CHIPS, ...(offered.includes(LONG) ? [LONG] : [])].map((m) => ({
			key: String(m),
			label: t(`dnsProtect.dur.${m}`),
			how: { minutes: m },
			disabled: !offered.includes(m),
			title: offered.includes(m) ? '' : t('dnsProtect.hint.notOffered'),
			clock: true,
		}));
		list.push({ key: 'forever', label: t('dnsProtect.forever'), how: { forever: true }, disabled: !may.forever, title: '', clock: false });
		return list;
	}

	function unfilteredText(d, t) {
		const dev = d.device;
		if (!dev) return t('dnsProtect.sub.noDevice');
		if (dev.state === 'ownDns') return dev.ownDns ? t('dnsProtect.sub.ownDns', { dns: dev.ownDns }) : t('dnsProtect.sub.ownDnsPlain');
		if (dev.state === 'excluded') return t('dnsProtect.sub.excluded');
		if (dev.state === 'disabled') return t('dnsProtect.sub.disabled');
		return t('dnsProtect.sub.unfiltered');
	}

	function pausedSub(snap, locale, t) {
		const p = snap.data.pause;
		if (p && isMs(p.until)) return t('dnsProtect.sub.pausedUntil', { time: hm(onLocalClock(p.until, snap), locale) });
		if (p && p.byMe) return t('dnsProtect.sub.pausedOpenMe');
		if (p && p.by) return t('dnsProtect.sub.pausedOpenBy', { name: p.by.name });
		return t('dnsProtect.sub.pausedOpen');
	}

	/** "Unterbrochen von dir um 14:42 für 30 Minuten. Solange wird auf diesem Gerät nichts gesperrt." */
	function pauseNote(snap, locale, t) {
		const d = snap.data;
		const p = d.pause;
		if (!p) return '';
		// for all devices, by an admin: only an admin ends it
		if (p.scope === 'all' && !d.may.resume) return t('dnsProtect.note.all');
		const where = t(`dnsProtect.note.${d.device ? 'device' : 'devices'}`);
		if (!isMs(p.since)) return where;
		const time = hm(onLocalClock(p.since, snap), locale);
		const duration = isMs(p.until) && p.until > p.since ? durationText((p.until - p.since) / MIN, t) : null;
		const who = p.byMe ? 'byMe' : p.by ? 'byOther' : 'plain';
		const params = { time, ...(p.by && !p.byMe ? { name: p.by.name } : {}), ...(duration ? { duration } : {}) };
		return `${t(`dnsProtect.note.${who}${duration ? '' : 'Open'}`, params)} ${where}`;
	}

	/**
	 * What the card shows, or null (no card: the server reports no DNS
	 * protection, it is off, or nothing is known yet).
	 *
	 * @param {object} snap - snapshot of the service
	 * @param {{ now: number, locale: string, connected?: boolean, busy?: boolean }} ctx
	 * @returns {null | { state, tone, icon, sub, chip: { text, tone, countdown }, banner, counters, pause, paused, notes, retry }}
	 */
	function cardView(snap, ctx, t) {
		if (!shown(snap)) return null;
		const { now, locale } = ctx;
		const d = snap.data;
		const notes = [];
		if (!d) {
			// asked, and the plugin or the network is in trouble; before the first answer: nothing yet
			if (!snap.error) return null;
			return { state: 'error', tone: 'neutral', icon: 'shieldOff', sub: t('dnsProtect.unreachable'), chip: { text: t('dnsProtect.chip.error'), tone: 'neutral', countdown: null }, banner: null, counters: null, pause: null, paused: null, notes, retry: true };
		}
		if (d.state === 'off') return null;
		if (snap.stale) notes.push(t('dnsProtect.stale'));
		const v = { state: d.state, tone: 'neutral', icon: 'shield', sub: '', chip: { text: '', tone: 'neutral', countdown: null }, banner: null, counters: counters(d, locale, t), pause: null, paused: null, notes, retry: false };

		if (d.state === 'fallback') {
			const since = d.outage && isMs(d.outage.since) ? hm(onLocalClock(d.outage.since, snap), locale) : '';
			Object.assign(v, { tone: 'err', icon: 'shieldX', sub: since ? t('dnsProtect.sub.fallbackSince', { time: since }) : t('dnsProtect.sub.fallback') });
			v.chip = { text: t('dnsProtect.chip.fallback'), tone: 'err', countdown: null };
			v.banner = { tone: 'err', icon: 'warn', title: t('dnsProtect.banner.fallbackTitle'), text: t('dnsProtect.banner.fallbackText') };
			return v;
		}
		if (d.state === 'starting') {
			Object.assign(v, { icon: 'shieldOff', sub: t('dnsProtect.sub.starting'), counters: null });
			v.chip.text = t('dnsProtect.chip.starting');
			return v;
		}
		if (d.state === 'unfiltered') {
			Object.assign(v, { icon: 'shieldOff', sub: unfilteredText(d, t), counters: null });
			v.chip.text = t('dnsProtect.chip.unfiltered');
			return v;
		}
		if (ctx.connected === false) notes.push(t('dnsProtect.disconnected'));
		if (d.state === 'paused') {
			const left = remainingMs(snap, now);
			Object.assign(v, { tone: 'warn', icon: 'shieldPause', sub: pausedSub(snap, locale, t) });
			v.chip = { text: t('dnsProtect.chip.paused'), tone: 'warn', countdown: left === null ? null : countdown(left) };
			v.paused = { resume: d.may.resume, extend: d.may.extend, countdown: left === null ? null : countdown(left), note: pauseNote(snap, locale, t) };
			return v;
		}
		// active
		Object.assign(v, { tone: 'ok', sub: t('dnsProtect.sub.active') });
		v.chip = { text: t('dnsProtect.chip.active'), tone: 'ok', countdown: null };
		if (d.may.pause) {
			v.pause = {
				label: t(`dnsProtect.pauseFor.${d.device ? 'device' : 'devices'}`),
				choices: pauseChoices(d.may, t),
				hint: t(d.may.forever ? 'dnsProtect.hint.endsSelf' : 'dnsProtect.hint.foreverOff'),
			};
		} else if (BANNER_REASONS.includes(d.may.reason)) {
			v.banner = { tone: 'info', icon: 'lock', title: t('dnsProtect.banner.notAllowedTitle'), text: t(`dnsProtect.banner.${d.may.reason}`) };
		}
		return v;
	}

	/** The card "Top gesperrte Domains": null (no card), else the rows (maybe none yet). */
	function topView(snap, locale) {
		if (!shown(snap) || !snap.data || !Array.isArray(snap.data.top)) return null;
		if (['off', 'starting', 'unfiltered'].includes(snap.data.state)) return null;
		return snap.data.top.map((x) => ({ domain: x.domain, count: num(x.count, locale) }));
	}

	/** The text of a failed change: the plugin's sentence for a refusal, an own one for network trouble. */
	function errorText(res, t) {
		const r = res || {};
		const sentence = typeof r.error === 'string' && r.error !== r.code && !/^HTTP \d+$/.test(r.error) && /\s/.test(r.error) ? r.error.slice(0, 300) : '';
		if (OWN_ERRORS.includes(r.code)) return t(`dnsProtect.error.${r.code}`);
		if (sentence && ((r.status >= 400 && r.status < 500) || (r.status === 503 && r.code === 'unavailable'))) return sentence;
		if (r.status >= 500 || r.code === 'unavailable') return t('dnsProtect.error.unavailable');
		return t('dnsProtect.error.failed');
	}

	return {
		CHIPS,
		EXTEND,
		serverNow,
		onLocalClock,
		hm,
		remainingMs,
		countdown,
		durationText,
		num,
		percent,
		shown,
		pauseChoices,
		pauseNote,
		cardView,
		topView,
		errorText,
	};
});
