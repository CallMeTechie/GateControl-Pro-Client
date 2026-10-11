/**
 * GateControl -- Notification center view state (renderer, no DOM access)
 *
 * Pure helpers for the "Mitteilungen" page and the settings tab
 * "Benachrichtigungen": filters, list/detail texts, facts, empty states,
 * the push status card, topic switches and the kill-switch note. Loaded as a
 * plain script before renderer.js (window.GCNotifyState) and required by the
 * node tests (test/notify-state.test.js).
 *
 * Inputs are what window.gatecontrol.notify returns (core NotificationCenter:
 * list() items, status(), getPrefs()); `t` is the i18n function.
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCNotifyState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const PRIORITY_CHIP = { critical: 'c-err', high: 'c-warn', normal: 'c-info', info: '' };
	const MAX_FACTS = 6;

	const str = (v) => (v === null || v === undefined ? '' : String(v));

	/** Label of a topic id (server hello), with a readable fallback. */
	function topicLabel(topics, id) {
		if (!id) return '';
		const hit = Array.isArray(topics) ? topics.find((tp) => tp && tp.id === id) : null;
		if (hit && hit.label) return String(hit.label);
		// plugin:<plugin>:<event> → "<plugin> · <event>"
		const m = /^plugin:([^:]+):(.+)$/.exec(id);
		return m ? `${m[1]} · ${m[2]}` : String(id);
	}

	/** Entries of one filter: 'all', 'unread' or a topic id. */
	function filterItems(items, filter) {
		const list = Array.isArray(items) ? items : [];
		if (!filter || filter === 'all') return list;
		if (filter === 'unread') return list.filter((e) => e.state === 'delivered');
		return list.filter((e) => e.topic === filter);
	}

	/**
	 * Filter chips: Alle, Ungelesen, then the topics that have entries (in
	 * the order of the server's topic list), plus the active one.
	 * @returns {{ id: string, label: string, count: number }[]}
	 */
	function filterOptions(items, topics, active, t) {
		const list = Array.isArray(items) ? items : [];
		const out = [
			{ id: 'all', label: t('ui.inbox.filterAll'), count: list.length },
			{ id: 'unread', label: t('ui.inbox.filterUnread'), count: list.filter((e) => e.state === 'delivered').length },
		];
		const used = new Set(list.map((e) => e.topic).filter(Boolean));
		if (active && active !== 'all' && active !== 'unread') used.add(active);
		const order = (Array.isArray(topics) ? topics : []).map((tp) => tp.id);
		const ids = [...used].sort((a, b) => {
			const ia = order.indexOf(a);
			const ib = order.indexOf(b);
			return (ia < 0 ? 1e6 : ia) - (ib < 0 ? 1e6 : ib) || a.localeCompare(b);
		});
		for (const id of ids) {
			out.push({ id, label: topicLabel(topics, id), count: list.filter((e) => e.topic === id).length });
		}
		return out;
	}

	function pad2(n) { return String(n).padStart(2, '0'); }

	/**
	 * Short time of an entry: "21:42" today, "gestern" / weekday within a
	 * week, otherwise the date.
	 */
	function formatTime(iso, t, { now = Date.now(), locale } = {}) {
		const ts = Date.parse(iso);
		if (!Number.isFinite(ts)) return '';
		const d = new Date(ts);
		const today = new Date(now);
		const startOfDay = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
		const days = Math.round((startOfDay(today) - startOfDay(d)) / 86400000);
		if (days <= 0) return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
		if (days === 1) return t('ui.inbox.yesterday');
		try {
			if (days < 7) return d.toLocaleDateString(locale, { weekday: 'long' });
			return d.toLocaleDateString(locale, { day: '2-digit', month: '2-digit', year: 'numeric' });
		} catch {
			return `${pad2(d.getDate())}.${pad2(d.getMonth() + 1)}.${d.getFullYear()}`;
		}
	}

	/** Clock time (HH:MM) of an ISO date or epoch ms, '' when invalid. */
	function clock(value) {
		const ts = typeof value === 'number' ? value : Date.parse(value);
		if (!Number.isFinite(ts)) return '';
		const d = new Date(ts);
		return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
	}

	/** Priority as a pill (null for normal / info in list rows). */
	function priorityPill(priority, t) {
		if (priority !== 'critical' && priority !== 'high') return null;
		return { label: t(`push.priority.${priority}`), cls: PRIORITY_CHIP[priority] };
	}

	/**
	 * Second line of a list row: "Kritisch" (coloured) + "Gateways · 21:42".
	 * @returns {{ priority: ?{label, cls}, text: string }}
	 */
	function rowMeta(entry, topics, t, opts) {
		const parts = [];
		const topic = topicLabel(topics, entry.topic);
		if (topic) parts.push(topic);
		const time = formatTime(entry.created_at || entry.received_at, t, opts);
		if (time) parts.push(time);
		return { priority: priorityPill(entry.priority, t), text: parts.join(' · ') };
	}

	/** Pill above the detail title: "Kritisch · Gateways". */
	function detailPill(entry, topics, t) {
		const p = entry.priority || 'normal';
		const parts = [t(`push.priority.${p}`)];
		const topic = topicLabel(topics, entry.topic);
		if (topic) parts.push(topic);
		return { label: parts.join(' · '), cls: PRIORITY_CHIP[p] || '' };
	}

	/**
	 * Fact cards of the detail view: data.facts ([{ label, value }], from the
	 * server event, at most 6) plus when and how it arrived.
	 */
	function entryFacts(entry, t, opts) {
		const out = [];
		const facts = entry && entry.data && Array.isArray(entry.data.facts) ? entry.data.facts : [];
		for (const f of facts) {
			if (out.length >= MAX_FACTS) break;
			if (!f || typeof f !== 'object') continue;
			const label = str(f.label).slice(0, 60);
			const value = str(f.value).slice(0, 120);
			if (label && value) out.push({ label, value });
		}
		const when = entry.received_at || entry.created_at;
		const time = formatTime(when, t, opts);
		if (time) {
			const at = time.includes(':') ? time : `${time} ${clock(when)}`;
			const via = entry.via === 'tunnel' || entry.via === 'direct' ? t(`push.via.${entry.via}`) : '';
			out.push({ label: t('ui.inbox.received'), value: via ? `${at} · ${via}` : at });
		}
		return out;
	}

	/**
	 * Which empty state the list shows (null = the list has entries).
	 * Order: switched off → server cannot push yet → not set up → load error
	 * → nothing in this filter → nothing at all.
	 */
	function emptyState({ status, prefs, total, shown, filter, error }) {
		if (shown > 0) return null;
		if ((prefs && prefs.enabled === false) || (status && status.enabled === false)) return 'off';
		const reason = status && status.reason;
		if (total === 0 && (reason === 'unsupported' || reason === 'push_disabled')) return 'unsupported';
		if (total === 0 && reason === 'not_configured') return 'notConfigured';
		if (error) return 'error';
		if (total > 0 && filter && filter !== 'all') return 'filtered';
		return 'empty';
	}

	/**
	 * Calm one-line hint above a non-empty list when push is not receiving
	 * (server too old, push off at the server, error …), or null.
	 */
	function listHint(status) {
		if (!status || status.enabled === false) return null;
		if (status.state === 'connected' || status.state === 'connecting') return null;
		if (!status.reason || status.reason === 'off') return null;
		return `push.reason.${status.reason}`;
	}

	/**
	 * Status card of the settings tab.
	 * @returns {{ tone: 'ok'|'warn'|'err'|'off', stateKey: string, reasonKey: ?string,
	 *   server: string, viaKey: ?string, since: string, dnd: ?string }}
	 */
	function statusView(status) {
		const s = status || {};
		const state = ['connected', 'connecting', 'disabled', 'error', 'stopped'].includes(s.state) ? s.state : 'stopped';
		const tone = state === 'connected' ? 'ok' : state === 'connecting' ? 'warn' : state === 'error' ? 'err' : 'off';
		const reasonKey = s.reason && state !== 'connected' ? `push.reason.${s.reason}` : null;
		return {
			tone,
			stateKey: `push.state.${state}`,
			reasonKey,
			server: s.serverHost ? String(s.serverHost) : '',
			viaKey: state === 'connected' && (s.via === 'tunnel' || s.via === 'direct') ? `push.via.${s.via}` : null,
			since: state === 'connected' && s.since ? clock(s.since) : '',
			dnd: s.dnd && s.dnd.active && s.dnd.until ? clock(s.dnd.until) : null,
		};
	}

	/** Topic switches: one per server topic, on = not muted on this PC. */
	function topicRows(topics, mutedTopics) {
		const muted = new Set(Array.isArray(mutedTopics) ? mutedTopics : []);
		return (Array.isArray(topics) ? topics : [])
			.filter((tp) => tp && typeof tp.id === 'string')
			.map((tp) => ({ id: tp.id, label: tp.label ? String(tp.label) : topicLabel([], tp.id), on: !muted.has(tp.id) }));
	}

	/** mutedTopics after switching one topic on/off. */
	function toggleTopic(mutedTopics, id, on) {
		const set = new Set(Array.isArray(mutedTopics) ? mutedTopics : []);
		if (on) set.delete(id); else set.add(id);
		return [...set];
	}

	/**
	 * Kill-switch note: warning when push only works through the tunnel,
	 * reassurance when the kill switch is on and the path is covered, else null.
	 */
	function killSwitchNote(status) {
		const ks = status && status.killSwitch;
		if (!ks || !ks.active) return null;
		if (ks.tunnelOnly) return { tone: 'warn', key: 'push.tunnelOnly' };
		return { tone: 'ok', key: 'push.killSwitchOk' };
	}

	/** Nav badge text ('' = hidden). */
	function badgeText(unread) {
		const n = Number(unread) || 0;
		if (n <= 0) return '';
		return n > 99 ? '99+' : String(n);
	}

	/**
	 * Where a notify:navigate event leads: { page, id } (app routes of the
	 * contract; the rest opens the entry in the inbox).
	 */
	function navigateTarget(evt, pages) {
		const route = evt && evt.route;
		const id = evt && Number.isSafeInteger(evt.id) ? evt.id : null;
		const map = { vpn: 'status', services: 'services', inbox: 'inbox' };
		const page = map[route];
		if (page && (!pages || pages.includes(page))) return { page, id: page === 'inbox' ? id : null };
		return { page: 'inbox', id };
	}

	return {
		PRIORITY_CHIP,
		topicLabel,
		filterItems,
		filterOptions,
		formatTime,
		clock,
		priorityPill,
		rowMeta,
		detailPill,
		entryFacts,
		emptyState,
		listHint,
		statusView,
		topicRows,
		toggleTopic,
		killSwitchNote,
		badgeText,
		navigateTarget,
	};
});
