/**
 * GateControl -- Notification center view state (renderer, no DOM access)
 *
 * Pure helpers for the "Mitteilungen" page and the settings tab
 * "Benachrichtigungen": filters (read state × source), day groups, list rows,
 * detail texts, facts, answer buttons, keyboard steps, empty states,
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

	// ── Sources: "System" (core topics) and one per plugin ──

	const SYSTEM = 'system';

	/** Source of a topic: 'system' (core topics, none) or 'plugin:<id>'. */
	function sourceKey(topic) {
		const m = /^plugin:([^:]+):/.exec(str(topic));
		return m ? `plugin:${m[1]}` : SYSTEM;
	}

	/**
	 * A topic label split into its source and its own part. The server names
	 * plugin topics "<plugin> · <topic>" ("Fahrzeuge · Fahrt erfasst
	 * (Fahrtenbuch)"), a plugin's default topic just "<plugin>"; core topics
	 * belong to "System".
	 * @returns {{ source: string, topic: string }}
	 */
	function topicParts(topics, id, t) {
		const label = topicLabel(topics, id);
		if (sourceKey(id) === SYSTEM) return { source: t('ui.inbox.system'), topic: label };
		const i = label.indexOf(' · ');
		if (i < 0) return { source: label, topic: '' };
		return { source: label.slice(0, i), topic: label.slice(i + 3) };
	}

	// Line icons (24×24, stroke) of the sources this app knows; others get their initial.
	const ICONS = {
		system: ['M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z'],
		'gatecontrol-messenger': ['M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12z'],
		'gatecontrol-schule': ['M2 9l10-5 10 5-10 5z', 'M6 11v5c3 2 9 2 12 0v-5M22 9v6'],
		'gatecontrol-gatedrop': ['M12 3v12', 'm7 8 5-5 5 5', 'M5 21h14'],
		'gatecontrol-vault': ['M7 11h10a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2z', 'M8 11V8a4 4 0 0 1 8 0v3'],
		'gatecontrol-skoda': ['M5 17H3v-4.5L5.2 8a2 2 0 0 1 1.8-1h10a2 2 0 0 1 1.8 1l2.2 4.5V17h-2', 'M9 17h6', 'M5 17a2 2 0 1 0 4 0a2 2 0 1 0-4 0', 'M15 17a2 2 0 1 0 4 0a2 2 0 1 0-4 0', 'M3 12.5h18'],
		'gatecontrol-door': ['M18 20V6a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v14', 'M2 20h20', 'M14 12v.01'],
		'gatecontrol-synology': ['M22 12H2', 'M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z', 'M6 16h.01', 'M10 16h.01'],
		'gatecontrol-proxmox': ['M4 4h16v6H4z', 'M4 14h16v6H4z', 'M8 7h.01', 'M8 17h.01'],
		'gatecontrol-familie': ['M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2', 'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z', 'M22 21v-2a4 4 0 0 0-3-3.87', 'M16 3.13a4 4 0 0 1 0 7.75'],
		'gatecontrol-alltag': ['M8 2v4', 'M16 2v4', 'M3 10h18', 'M5 4h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z'],
		'gatecontrol-raumklima': ['M14 4v10.54a4 4 0 1 1-4 0V4a2 2 0 0 1 4 0Z'],
		'gatecontrol-smarthome': ['M3 10l9-7 9 7v10a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z'],
	};

	/**
	 * Badge of a source: { paths } (a known icon) or { initial } (first
	 * letter or digit of its name, '?' without one).
	 */
	function sourceBadge(topic, sourceLabel) {
		const key = sourceKey(topic);
		const paths = ICONS[key === SYSTEM ? SYSTEM : key.slice(7)];
		if (paths) return { paths, initial: '' };
		const m = /[\p{L}\p{N}]/u.exec(str(sourceLabel));
		return { paths: null, initial: m ? m[0].toUpperCase() : '?' };
	}

	// ── Filters: read state × source ────────────────────────

	const SOURCE_VALUE_RE = /^(?:src:(?:system|plugin:[^:\s]{1,80})|topic:\S{1,120})$/;

	/**
	 * A filter as the page keeps it: { read: 'all'|'unread', source } —
	 * source '' (all), 'src:system', 'src:plugin:<id>' or 'topic:<topic id>'.
	 * Anything else (an old or broken saved value) becomes the default.
	 */
	function normalizeFilter(f) {
		const o = f && typeof f === 'object' ? f : {};
		return {
			read: o.read === 'unread' ? 'unread' : 'all',
			source: typeof o.source === 'string' && SOURCE_VALUE_RE.test(o.source) ? o.source : '',
		};
	}

	function isDefaultFilter(f) {
		const n = normalizeFilter(f);
		return n.read === 'all' && !n.source;
	}

	function matchesSource(entry, source) {
		if (!source) return true;
		if (source.startsWith('src:')) return sourceKey(entry.topic) === source.slice(4);
		if (source.startsWith('topic:')) return entry.topic === source.slice(6);
		return true;
	}

	/**
	 * Entries of a filter: { read, source } (see normalizeFilter), or the
	 * older single value 'all' / 'unread' / a topic id.
	 */
	function filterItems(items, filter) {
		const list = Array.isArray(items) ? items : [];
		let f;
		if (!filter || filter === 'all') f = normalizeFilter(null);
		else if (filter === 'unread') f = { read: 'unread', source: '' };
		else if (typeof filter === 'string') f = { read: 'all', source: `topic:${filter}` };
		else f = normalizeFilter(filter);
		return list.filter((e) => (f.read !== 'unread' || e.state === 'delivered') && matchesSource(e, f.source));
	}

	/**
	 * Choices of the "Quelle" select: all sources, then System and each
	 * plugin that has entries (in the order of the server's topic list), each
	 * followed by its topics (depth 1) when it has more than one. The active
	 * choice is always offered. `unread` counts the unread entries.
	 * @returns {{ value: string, label: string, depth: number, unread: number }[]}
	 */
	function sourceOptions(items, topics, active, t) {
		const list = Array.isArray(items) ? items : [];
		const order = (Array.isArray(topics) ? topics : []).map((tp) => tp && tp.id);
		const rank = (id) => { const i = order.indexOf(id); return i < 0 ? 1e6 : i; };
		const unread = (pred) => list.filter((e) => e.state === 'delivered' && pred(e)).length;

		const ids = new Set(list.map((e) => e.topic || ''));
		const act = normalizeFilter({ source: active }).source;
		if (act.startsWith('topic:')) ids.add(act.slice(6));
		const groups = new Map(); // source key → { topics: Set, rank }
		const addSource = (key) => { if (!groups.has(key)) groups.set(key, { topics: new Set(), rank: 1e6 }); return groups.get(key); };
		for (const id of ids) {
			const g = addSource(sourceKey(id));
			if (id) g.topics.add(id);
			g.rank = Math.min(g.rank, id ? rank(id) : 1e6);
		}
		if (act.startsWith('src:')) addSource(act.slice(4));

		const label = (key) => {
			if (key === SYSTEM) return t('ui.inbox.system');
			// the plugin's name as the server writes it in one of its topic labels
			const pid = key.slice(7);
			const known = (Array.isArray(topics) ? topics : []).find((tp) => tp && sourceKey(tp.id) === key && tp.label);
			return known ? topicParts(topics, known.id, t).source : topicParts([], `plugin:${pid}:x`, t).source;
		};
		const keys = [...groups.keys()].sort((a, b) => {
			if (a === SYSTEM || b === SYSTEM) return a === SYSTEM ? -1 : 1;
			return groups.get(a).rank - groups.get(b).rank || label(a).localeCompare(label(b));
		});

		const out = [{ value: '', label: t('ui.inbox.sourceAll'), depth: 0, unread: unread(() => true) }];
		for (const key of keys) {
			out.push({ value: `src:${key}`, label: label(key), depth: 0, unread: unread((e) => sourceKey(e.topic) === key) });
			const tps = [...groups.get(key).topics].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
			if (tps.length < 2 && !(act.startsWith('topic:') && tps.includes(act.slice(6)))) continue;
			for (const id of tps) {
				const parts = topicParts(topics, id, t);
				out.push({ value: `topic:${id}`, label: parts.topic || parts.source, depth: 1, unread: unread((e) => e.topic === id) });
			}
		}
		return out;
	}

	/** Text of a select choice: indented topics, "· 2 neu" when unread. */
	function optionText(opt, t) {
		const pad = opt.depth > 0 ? '    ' : '';
		return `${pad}${opt.label}${opt.unread > 0 ? ` · ${t('ui.inbox.newCount', { count: opt.unread })}` : ''}`;
	}

	function pad2(n) { return String(n).padStart(2, '0'); }

	const startOfDay = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();

	/**
	 * Short time of an entry: "21:42" today, "gestern" / weekday within a
	 * week, otherwise the date.
	 */
	function formatTime(iso, t, { now = Date.now(), locale } = {}) {
		const ts = Date.parse(iso);
		if (!Number.isFinite(ts)) return '';
		const d = new Date(ts);
		const days = Math.round((startOfDay(new Date(now)) - startOfDay(d)) / 86400000);
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

	/** When an entry happened (server time, else when it arrived). */
	function entryTime(entry) {
		return (entry && (entry.created_at || entry.received_at)) || '';
	}

	/**
	 * Heading of a day: "Heute", "Gestern", the weekday within a week, else
	 * "10. Oktober" (with the year when it is not this year).
	 */
	function dayLabel(iso, t, { now = Date.now(), locale } = {}) {
		const ts = Date.parse(iso);
		if (!Number.isFinite(ts)) return t('ui.inbox.earlier');
		const d = new Date(ts);
		const today = new Date(now);
		const days = Math.round((startOfDay(today) - startOfDay(d)) / 86400000);
		if (days <= 0) return t('ui.inbox.today');
		if (days === 1) return t('ui.inbox.yesterdayDay');
		try {
			if (days < 7) return d.toLocaleDateString(locale, { weekday: 'long' });
			const opts = d.getFullYear() === today.getFullYear() ? { day: 'numeric', month: 'long' } : { day: 'numeric', month: 'long', year: 'numeric' };
			return d.toLocaleDateString(locale, opts);
		} catch {
			return `${pad2(d.getDate())}.${pad2(d.getMonth() + 1)}.${d.getFullYear()}`;
		}
	}

	/**
	 * Entries (newest first) in groups of one day each, in list order.
	 * @returns {{ key: string, label: string, items: object[] }[]}
	 */
	function groupByDay(items, t, opts) {
		const out = [];
		for (const e of Array.isArray(items) ? items : []) {
			const ts = Date.parse(entryTime(e));
			const key = Number.isFinite(ts) ? String(startOfDay(new Date(ts))) : 'none';
			const last = out[out.length - 1];
			if (last && last.key === key) last.items.push(e);
			else out.push({ key, label: dayLabel(entryTime(e), t, opts), items: [e] });
		}
		return out;
	}

	/** Priority as a pill (null for normal / info in list rows). */
	function priorityPill(priority, t) {
		if (priority !== 'critical' && priority !== 'high') return null;
		return { label: t(`push.priority.${priority}`), cls: PRIORITY_CHIP[priority] };
	}

	/** Body text on one line (for the preview; the row ellipsizes it). */
	function oneLine(text) {
		return str(text).replace(/\s+/g, ' ').trim();
	}

	/**
	 * What a list row shows: the source badge, a small label (the plugin's
	 * name, or the topic for System), the time, the title and one line of
	 * the message itself (the topic only when there is no text).
	 */
	function rowView(entry, topics, t) {
		const parts = topicParts(topics, entry.topic, t);
		const system = sourceKey(entry.topic) === SYSTEM;
		const label = system ? (parts.topic || parts.source) : parts.source;
		return {
			label,
			labelTitle: [parts.source, parts.topic].filter(Boolean).join(' › '),
			badge: sourceBadge(entry.topic, parts.source),
			time: clock(entryTime(entry)),
			title: str(entry.title) || '—',
			preview: oneLine(entry.body) || parts.topic || '',
			unread: entry.state === 'delivered',
			priority: priorityPill(entry.priority, t),
		};
	}

	/** Breadcrumb of the detail view: source › topic (topic '' when none). */
	function breadcrumb(entry, topics, t) {
		const parts = topicParts(topics, entry.topic, t);
		return { source: parts.source, topic: parts.topic, badge: sourceBadge(entry.topic, parts.source) };
	}

	/** "Heute, 09:27 · direkt über HTTPS" — when (and how) the entry arrived. */
	function receivedLine(entry, t, opts) {
		const when = (entry && (entry.received_at || entry.created_at)) || '';
		const time = clock(when);
		if (!time) return '';
		const via = entry.via === 'tunnel' || entry.via === 'direct' ? t(`push.via.${entry.via}`) : '';
		const at = `${dayLabel(when, t, opts)}, ${time}`;
		return t('ui.inbox.receivedAt', { when: via ? `${at} · ${via}` : at });
	}

	/** Fact cards of the detail view: data.facts ([{ label, value }], from the server event, at most 6). */
	function entryFacts(entry) {
		const out = [];
		const facts = entry && entry.data && Array.isArray(entry.data.facts) ? entry.data.facts : [];
		for (const f of facts) {
			if (out.length >= MAX_FACTS) break;
			if (!f || typeof f !== 'object') continue;
			const label = str(f.label).slice(0, 60);
			const value = str(f.value).slice(0, 120);
			if (label && value) out.push({ label, value });
		}
		return out;
	}

	/**
	 * Buttons of the detail view: the actions the entry carries (core list).
	 * Answer buttons (callback, e.g. "Privat" / "Geschäftlich") are all equal
	 * and the given answer (`acted`) is marked; otherwise the first is primary.
	 * @returns {{ buttons: { id, label, cls, chosen }[], answered: string }}
	 */
	function actionButtons(entry) {
		const list = (entry && Array.isArray(entry.actions) ? entry.actions : []).filter((a) => a && a.id);
		const answers = list.some((a) => a.type === 'callback');
		const acted = entry && entry.acted ? String(entry.acted) : '';
		const buttons = list.map((a, i) => {
			const chosen = !!acted && a.id === acted && (a.type === 'callback' || a.type === 'ack');
			const pri = answers ? chosen : i === 0;
			return { id: String(a.id), label: str(a.label) || String(a.id), cls: pri ? 'btn-pri' : 'btn-sec', chosen };
		});
		const hit = buttons.find((b) => b.chosen);
		return { buttons, answered: hit ? hit.label : '' };
	}

	/**
	 * The entry selected after a key in the list: ArrowDown / ArrowUp one
	 * step, Home / End the first / last (null: the key does nothing).
	 */
	function stepSelection(ids, current, key) {
		const list = Array.isArray(ids) ? ids : [];
		if (!list.length) return null;
		const i = list.indexOf(current);
		if (key === 'Home') return list[0];
		if (key === 'End') return list[list.length - 1];
		if (key === 'ArrowDown') return i < 0 ? list[0] : list[Math.min(list.length - 1, i + 1)];
		if (key === 'ArrowUp') return i < 0 ? list[0] : list[Math.max(0, i - 1)];
		return null;
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
		const filtered = filter && typeof filter === 'object' ? !isDefaultFilter(filter) : !!filter && filter !== 'all';
		if (total > 0 && filtered) return 'filtered';
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
	 * contract; the rest opens the entry in the inbox). Schule (a toast the
	 * core's SchoolService claimed) also passes its `context` (child, day,
	 * message) on: { page: 'schule', id: null, context }; GateDrop likewise
	 * ({ tab, sendId }): { page: 'gatedrop', id: null, context }; Vault
	 * ({ topic, event, vaultId, emergencyId, page }): { page: 'vault', id: null, context }.
	 */
	function navigateTarget(evt, pages) {
		const route = evt && evt.route;
		const id = evt && Number.isSafeInteger(evt.id) ? evt.id : null;
		const map = { vpn: 'status', services: 'services', inbox: 'inbox', 'plg-gatecontrol-messenger': 'chats', 'plg-gatecontrol-schule': 'schule', 'plg-gatecontrol-gatedrop': 'gatedrop', 'plg-gatecontrol-vault': 'vault', 'plg-gatecontrol-drive': 'drive' };
		const page = map[route];
		if (page && (!pages || pages.includes(page))) {
			// Drive 1.8 / 1.9: a deadline reminder opens its file, a vault request the vault (core DriveService.clickContext)
			if (page === 'schule' || page === 'gatedrop' || page === 'vault' || page === 'drive') return { page, id: null, context: evt.context && typeof evt.context === 'object' ? evt.context : null };
			return { page, id: page === 'inbox' ? id : null };
		}
		return { page: 'inbox', id };
	}

	/**
	 * A card link in a chat (plg-<id>, Messenger 1.6 also plg-<id>/<screen>)
	 * → this app's page for it: { page, context } — Schule on its tab or
	 * message (`plg-gatecontrol-schule/messages/<id>`) — or null when the app
	 * has no page for it (then the plugin's portal tab opens).
	 */
	function routeTarget(route, pages) {
		const parts = str(route).split('/');
		const map = { 'plg-gatecontrol-messenger': 'chats', 'plg-gatecontrol-schule': 'schule', 'plg-gatecontrol-gatedrop': 'gatedrop', 'plg-gatecontrol-vault': 'vault' };
		const page = map[parts[0]];
		if (!page || (pages && !pages.includes(page))) return null;
		// GateDrop: plg-gatecontrol-gatedrop[/received|sent|links]
		if (page === 'gatedrop') return { page, context: ['received', 'sent', 'links'].includes(parts[1]) ? { tab: parts[1], sendId: null } : null };
		// Vault: plg-gatecontrol-vault[/emergency]
		if (page === 'vault') return { page, context: parts[1] === 'emergency' ? { topic: 'emergency', event: null, vaultId: null, emergencyId: null, page: 'emergency' } : null };
		if (page !== 'schule') return { page, context: null };
		const kind = ['messages', 'absences', 'changes'].includes(parts[1]) ? parts[1] : null;
		const raw = kind === 'messages' && /^[A-Za-z0-9_.:-]{1,80}$/.test(str(parts[2])) ? parts[2] : null;
		// ids as the Schule service has them: numbers stay numbers
		const messageId = raw && /^[1-9]\d{0,14}$/.test(raw) ? Number(raw) : raw;
		return { page, context: kind ? { kind, studentId: null, date: null, messageId } : null };
	}

	/**
	 * Quiet hours card (read-only; set in the portal). Input: notify status()
	 * (quiet, quietKnown) or notify.quiet() ({ known, quiet }).
	 * → null while unknown (server without quiet hours / not connected yet),
	 *   otherwise { key, params, detailKey } for t().
	 */
	function quietView(status) {
		if (!status || typeof status !== 'object') return null;
		const known = status.quietKnown === true || status.known === true;
		if (!known) return null;
		const q = status.quiet;
		const hhmm = /^\d{2}:\d{2}$/;
		if (!q || !hhmm.test(str(q.from)) || !hhmm.test(str(q.to))) return { key: 'ui.notify.quietNone', params: null, detailKey: null };
		const tz = q.tz ? str(q.tz) : '';
		return {
			key: tz ? 'ui.notify.quietRangeTz' : 'ui.notify.quietRange',
			params: tz ? { from: q.from, to: q.to, tz } : { from: q.from, to: q.to },
			detailKey: q.criticalBypass ? 'ui.notify.quietCriticalBypass' : 'ui.notify.quietCriticalSilent',
		};
	}

	return {
		quietView,
		PRIORITY_CHIP,
		topicLabel,
		sourceKey,
		topicParts,
		sourceBadge,
		normalizeFilter,
		isDefaultFilter,
		filterItems,
		sourceOptions,
		optionText,
		formatTime,
		clock,
		dayLabel,
		groupByDay,
		priorityPill,
		rowView,
		breadcrumb,
		receivedLine,
		entryFacts,
		actionButtons,
		stepSelection,
		emptyState,
		listHint,
		statusView,
		topicRows,
		toggleTopic,
		killSwitchNote,
		badgeText,
		navigateTarget,
		routeTarget,
	};
});
