/**
 * GateControl -- GateDrop view state (renderer, no DOM access)
 *
 * Pure helpers for the page "GateDrop" and its send dialog (plugin
 * gatecontrol-gatedrop): sizes, the dialog title, the targets the person
 * picked → `to` of the send (own devices and other people's open ones),
 * what is missing before "Senden", text vs. link, the lines of the lists
 * (Empfangen / Gesendet / Links), link state, progress, error texts, where a
 * push leads and the setting "Wer darf an diesen PC senden?". Loaded as a plain script
 * before gatedrop-view.js (window.GCGateDropState) and required by the node
 * tests (test/gatedrop-state.test.js).
 *
 * Inputs are what window.gatecontrol.gatedrop returns (core GateDropService,
 * answers already cleaned by core utils/gatedrop.js); `t` is the i18n
 * function (keys gatedrop.* of the core locales). The same file is used by
 * Pro and Community.
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCGateDropState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const APP_ROUTE = 'plg-gatecontrol-gatedrop';
	const TABS = ['received', 'sent', 'links'];
	const EXPIRES = ['1h', '1d', '7d', 'once'];
	const MAX_ITEMS = 20;
	const MAX_TEXT = 20000;
	const ERRORS = ['unavailable', 'target_unavailable', 'network', 'timeout', 'too_large', 'quota_exceeded', 'no_target', 'missing', 'changed', 'forbidden', 'invalid'];
	// Who may send to this PC (GateDrop 1.2.0): only its owner, or everyone of the GateControl.
	const ACCESS = ['self', 'everyone'];
	// waiting (GateDrop 1.1.0): the own device was offline, the send waits until it is online again.
	const STATUS = ['pending', 'waiting', 'direct', 'delivered', 'opened', 'failed', 'expired'];

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const localeTag = (locale) => (locale === 'en' ? 'en-GB' : 'de-DE');
	const pad = (n) => String(n).padStart(2, '0');

	/** 1536 → '1,5 KB' (de) / '1.5 KB' (en). */
	function formatBytes(n, locale) {
		const v = Number(n);
		if (!Number.isFinite(v) || v < 0) return '';
		if (v < 1024) return `${v} B`;
		const units = ['KB', 'MB', 'GB'];
		let x = v / 1024;
		let i = 0;
		while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
		const digits = x >= 100 ? 0 : 1;
		return `${x.toLocaleString(localeTag(locale), { maximumFractionDigits: digits, minimumFractionDigits: 0 })} ${units[i]}`;
	}

	function percent(sent, total) {
		const s = Number(sent);
		const tt = Number(total);
		if (!Number.isFinite(s) || !Number.isFinite(tt) || tt <= 0) return 0;
		return Math.max(0, Math.min(100, Math.floor((s / tt) * 100)));
	}

	/** "Teilen: angebot.pdf" / "Teilen: 3 Dateien" / "Teilen" */
	function dialogTitle(files, t) {
		const list = Array.isArray(files) ? files : [];
		if (list.length === 1) return t('gatedrop.dialog.title', { name: list[0].name });
		if (list.length > 1) return t('gatedrop.dialog.titleMany', { count: list.length });
		return t('gatedrop.dialog.titleText');
	}

	/** One http(s) URL alone → link, everything else → text. */
	function splitTextLink(value) {
		const s = str(value).trim();
		if (!s) return { text: null, link: null };
		if (!/\s/.test(s) && s.length <= 2048 && /^https?:\/\/[^\s]+$/i.test(s)) {
			try {
				const u = new URL(s);
				if (u.protocol === 'http:' || u.protocol === 'https:') return { text: null, link: s };
			} catch { /* text */ }
		}
		return { text: str(value).slice(0, MAX_TEXT), link: null };
	}

	/** Empty selection of the dialog. */
	function emptySelection() {
		return { devices: [], people: [], nas: [], link: false, expires: '1d', pin: true };
	}

	function toggle(list, id) {
		const s = str(id);
		return list.includes(s) ? list.filter((x) => x !== s) : [...list, s];
	}

	/**
	 * Ids of the devices one may send to: own ones and other people's open for
	 * everyone (peopleDevices) — null while the targets are not known.
	 */
	function deviceIds(targets) {
		if (!targets || (!Array.isArray(targets.devices) && !Array.isArray(targets.peopleDevices))) return null;
		return new Set([...(targets.devices || []), ...(targets.peopleDevices || [])].map((d) => str(d.id)));
	}

	/** Dialog selection → `to` of POST sends (null when nothing is picked). */
	function buildTo(sel, targets) {
		const s = sel || emptySelection();
		const nasById = new Map(((targets && targets.nas) || []).map((n) => [n.id, n]));
		// A device that is no longer offered (closed for others meanwhile) drops out.
		const known = deviceIds(targets);
		const to = {
			people: [...new Set(s.people || [])],
			devices: [...new Set(s.devices || [])].filter((id) => !known || known.has(id)),
			nas: (s.nas || []).filter((id) => nasById.has(id)).map((id) => ({ id, path: nasById.get(id).path || undefined })),
		};
		if (s.link) to.link = { expires: EXPIRES.includes(s.expires) ? s.expires : '1d', pin: s.pin === true };
		const any = to.people.length || to.devices.length || to.nas.length || to.link;
		return any ? to : null;
	}

	/**
	 * Can the dialog send? → { ok, key } (key: gatedrop.dialog.* text of what is missing).
	 */
	function canSend({ files, text, selection, targets }) {
		const list = Array.isArray(files) ? files : [];
		const tl = splitTextLink(text);
		if (!list.length && !tl.text && !tl.link) return { ok: false, key: 'gatedrop.dialog.empty' };
		if (list.length > MAX_ITEMS) return { ok: false, key: 'gatedrop.dialog.tooMany' };
		const to = buildTo(selection, targets);
		if (!to) return { ok: false, key: 'gatedrop.dialog.pickTarget' };
		if (to.link && !list.length) return { ok: false, key: 'gatedrop.dialog.linkNeedsFiles' };
		return { ok: true, key: null };
	}

	/**
	 * Targets → what the dialog shows (own devices first online, Familie first
	 * among people; other people's open devices by owner, then online first).
	 */
	function dialogTargets(targets) {
		const tg = targets || {};
		const byOnline = (a, b) => (Number(b.online) - Number(a.online)) || str(a.name).localeCompare(str(b.name));
		const devices = (tg.devices || []).filter((d) => !d.self).slice().sort(byOnline);
		const ownerOf = (d) => str(d.owner && d.owner.name);
		const peopleDevices = (tg.peopleDevices || []).filter((d) => d && d.owner).slice().sort((a, b) => ownerOf(a).localeCompare(ownerOf(b)) || byOnline(a, b));
		const people = (tg.people || []).slice().sort((a, b) => (Number(b.kind === 'family') - Number(a.kind === 'family')) || str(a.name).localeCompare(str(b.name)));
		const me = tg.me || {};
		// Validities the plugin offers (limits.linkExpires), in the known order.
		const offered = tg.limits && Array.isArray(tg.limits.linkExpires) ? EXPIRES.filter((x) => tg.limits.linkExpires.includes(x)) : [];
		return {
			devices,
			peopleDevices,
			people,
			nas: me.canNas ? (tg.nas || []) : [],
			link: !!(me.canLink && tg.links && tg.links.enabled),
			expires: offered.length ? offered : EXPIRES.slice(),
		};
	}

	/**
	 * Device line: "online · im selben WLAN". Offline devices stay selectable
	 * (GateDrop 1.1.0 keeps the send for them): "offline · kommt an, sobald es online ist".
	 */
	function deviceMeta(d, t) {
		const parts = [d && d.online ? t('gatedrop.dialog.online') : t('gatedrop.dialog.offlineLater')];
		if (d && d.direct) parts.push(t('gatedrop.dialog.direct'));
		return parts.join(' · ');
	}

	/** Another person's device: "Surface · Marc". */
	function peopleDeviceLabel(d, t) {
		const owner = d && d.owner && d.owner.name;
		return owner ? t('gatedrop.dialog.deviceOf', { device: str(d.name), owner: str(owner) }) : str(d && d.name);
	}

	/**
	 * "Wer darf an diesen PC senden?" (GET device) → null when the server does
	 * not offer it (hidden), else { value, options: [{ value, label, on }], hint }.
	 */
	function accessView(a, t) {
		if (!a || a.ok === false || !a.supported) return null;
		const value = ACCESS.includes(a.receiveFrom) ? a.receiveFrom : 'self';
		return {
			value,
			options: ACCESS.map((x) => ({ value: x, label: t(`gatedrop.access.${x}`), on: x === value })),
			hint: t(value === 'everyone' ? 'gatedrop.access.everyoneHint' : 'gatedrop.access.selfHint'),
		};
	}

	// ── Time ─────────────────────────────────────────────

	function sameDay(a, b) {
		return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
	}

	/** 'heute 10:12' / 'gestern 18:01' / '18.10. 09:30' */
	function when(ms, now, locale, t) {
		if (!Number.isFinite(ms)) return '';
		const d = new Date(ms);
		const n = new Date(now);
		const time = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
		if (sameDay(d, n)) return t('gatedrop.list.today', { time });
		const y = new Date(now - 86400000);
		if (sameDay(d, y)) return t('gatedrop.list.yesterday', { time });
		const date = d.toLocaleDateString(localeTag(locale), { day: '2-digit', month: '2-digit' });
		return `${date} ${time}`;
	}

	/** Time left: 'in 23 Std.' style through Intl.RelativeTimeFormat. */
	function relativeFuture(ms, now, locale) {
		const diff = ms - now;
		const rtf = new Intl.RelativeTimeFormat(localeTag(locale), { numeric: 'auto' });
		const min = Math.round(diff / 60000);
		if (Math.abs(min) < 60) return rtf.format(min, 'minute');
		const h = Math.round(diff / 3600000);
		if (Math.abs(h) < 48) return rtf.format(h, 'hour');
		return rtf.format(Math.round(diff / 86400000), 'day');
	}

	// ── Lists ────────────────────────────────────────────

	/** Title of a send: the file name, "3 Dateien", "Text" or "Link". */
	function sendTitle(s, t) {
		const items = (s && s.items) || [];
		if (items.length === 1) return items[0].name;
		if (items.length > 1) return t('gatedrop.list.files', { count: items.length });
		if (s && s.link) return t('gatedrop.list.link');
		return t('gatedrop.list.text');
	}

	/** Received send → { title, meta, size, kind } */
	function receivedView(s, { t, locale, now }) {
		const items = s.items || [];
		const bytes = items.reduce((sum, it) => sum + (Number(it.bytes) || 0), 0);
		const meta = [];
		const fromName = s.from && (s.from.name || s.from.deviceName);
		if (fromName) meta.push(t('gatedrop.list.from', { name: s.from.name && s.from.deviceName ? `${s.from.name} (${s.from.deviceName})` : fromName }));
		if (s.at) meta.push(when(s.at, now, locale, t));
		if (s.via === 'direct') meta.push(t('gatedrop.via.direct'));
		return {
			title: sendTitle(s, t),
			meta: meta.join(' · '),
			size: bytes ? formatBytes(bytes, locale) : '',
			kind: items.length ? 'files' : s.link ? 'link' : 'text',
			note: s.note || null,
			canShow: Array.isArray(s.local) && s.local.length > 0,
			canSave: !s.localOnly && items.some((it) => it.mediaId) && !(Array.isArray(s.local) && s.local.length),
		};
	}

	/**
	 * Sent send → { title, meta, deliveries: [{ label, kind, status, text, full, tone }] }.
	 * full: `text` names the target itself ("Wartet, bis „Pixel“ online ist"), shown without the label.
	 */
	function sentView(s, { t, locale, now }) {
		const deliveries = (s.deliveries || []).map((d) => {
			const status = STATUS.includes(d.status) ? d.status : 'pending';
			const label = d.targetName || d.target || t(`gatedrop.kind.${d.kind}`);
			const full = status === 'waiting';
			return {
				label,
				kind: d.kind,
				status,
				text: full ? t('gatedrop.status.waiting', { device: label })
					: t(`gatedrop.status.${status}`) + (d.via && (status === 'delivered' || status === 'opened') ? ` · ${t(`gatedrop.via.${d.via}`)}` : ''),
				full,
				tone: status === 'failed' || status === 'expired' ? 'err' : status === 'pending' || status === 'waiting' ? 'muted' : 'ok',
			};
		});
		const meta = [];
		if (s.to) meta.push(t('gatedrop.list.to', { name: s.to }));
		else if (deliveries.length) meta.push(t('gatedrop.list.to', { name: deliveries.map((d) => d.label).join(', ') }));
		if (s.at) meta.push(when(s.at, now, locale, t));
		return { title: sendTitle(s, t), meta: meta.join(' · '), deliveries };
	}

	/** Link state: active | expired | locked | ended */
	function linkState(l, now) {
		if (!l) return 'ended';
		if (l.revoked) return 'ended';
		if (l.locked) return 'locked';
		if (l.expired || (Number.isFinite(l.expiresAt) && l.expiresAt <= now)) return 'expired';
		if (l.once && l.downloads >= 1) return 'expired';
		if (Number.isFinite(l.maxDownloads) && l.maxDownloads > 0 && l.downloads >= l.maxDownloads) return 'expired';
		return 'active';
	}

	/** Link line → { title, meta, state, active } */
	function linkView(l, { t, locale, now }) {
		const state = linkState(l, now);
		const parts = [];
		if (state === 'active' && Number.isFinite(l.expiresAt)) parts.push(t('gatedrop.list.linkExpires', { when: relativeFuture(l.expiresAt, now, locale) }));
		else if (state === 'expired') parts.push(t('gatedrop.list.linkExpired'));
		else if (state === 'locked') parts.push(t('gatedrop.list.linkLocked'));
		else if (state === 'ended') parts.push(t('gatedrop.list.linkEnded'));
		if (l.once) parts.push(t('gatedrop.list.linkOnce'));
		parts.push(l.downloads > 0 ? t('gatedrop.list.linkDownloads', { count: l.downloads }) : t('gatedrop.list.linkNone'));
		const items = l.items || [];
		let title = l.title || (items.length === 1 ? items[0].name : items.length ? t('gatedrop.list.files', { count: items.length }) : t('gatedrop.list.link'));
		if (l.pin) title = `${title} · ${t('gatedrop.list.linkPin')}`;
		return { title, meta: parts.join(' · '), state, active: state === 'active' };
	}

	/** Links: active first, then the rest by date. */
	function sortLinks(list, now) {
		return (list || []).slice().sort((a, b) => {
			const aa = linkState(a, now) === 'active' ? 1 : 0;
			const bb = linkState(b, now) === 'active' ? 1 : 0;
			return (bb - aa) || ((b.at || b.expiresAt || 0) - (a.at || a.expiresAt || 0));
		});
	}

	/** Progress event → text, or null when it is over. */
	function progressText(p, t) {
		if (!p) return null;
		if (p.phase === 'failed') return t('gatedrop.progress.failed');
		const pc = percent(p.sent, p.total);
		if (p.phase === 'upload') return t('gatedrop.progress.upload', { percent: pc });
		if (p.phase === 'direct') return t('gatedrop.progress.direct', { percent: pc });
		if (p.phase === 'download') return t('gatedrop.progress.download', { percent: pc });
		return null;
	}

	/** First line of the send toast: "angebot.pdf" / "3 Dateien" / "Text". */
	function sendLabel(files, t) {
		const list = Array.isArray(files) ? files : [];
		if (list.length === 1) return str(list[0].name);
		if (list.length > 1) return t('gatedrop.sendToast.files', { count: list.length });
		return t('gatedrop.sendToast.text');
	}

	/**
	 * Send toast of one job ({ phase, sent, total, via } from 'progress', error text)
	 * → { tone: 'busy' | 'ok' | 'err', text, percent } (percent null: no known share yet).
	 */
	function sendToastView(job, t) {
		const j = job || {};
		if (j.error) return { tone: 'err', text: `${t('gatedrop.sendToast.failed')}: ${str(j.error)}`, percent: null };
		if (j.phase === 'done') return { tone: 'ok', text: t(j.via === 'direct' ? 'gatedrop.sendToast.doneDirect' : 'gatedrop.sendToast.done'), percent: 100 };
		if (j.phase === 'failed') return { tone: 'busy', text: t('gatedrop.progress.failed'), percent: null };
		if (j.phase === 'upload' || j.phase === 'direct') return { tone: 'busy', text: progressText(j, t), percent: percent(j.sent, j.total) };
		if (j.phase === 'sent') return { tone: 'busy', text: t('gatedrop.sendToast.transferring'), percent: null };
		return { tone: 'busy', text: t('gatedrop.sendToast.preparing'), percent: null };
	}

	/** Rejected files of a prepare → texts. */
	function rejectedTexts(rejected, t) {
		return (rejected || []).slice(0, 5).map((r) => {
			const reason = ['directory', 'too_large', 'empty', 'missing', 'too_many'].includes(r.reason) ? r.reason : 'invalid';
			return t(`gatedrop.rejected.${reason}`, { name: r.name || '?' });
		});
	}

	/** A failed answer ({ ok: false, code }) → text. */
	function errorText(res, t) {
		const code = res && res.code;
		if (ERRORS.includes(code)) return t(`gatedrop.error.${code}`);
		if (code === 'auth') return t('gatedrop.error.forbidden');
		if (code === 'too_many') return t('gatedrop.dialog.tooMany');
		if (code === 'empty') return t('gatedrop.dialog.empty');
		return t('gatedrop.error.failed', { code: str(code || (res && res.status) || '?').slice(0, 40) });
	}

	/** Add files to a dialog list without doubles (same id) and at most 20. */
	function mergeFiles(list, add) {
		const out = (list || []).slice();
		const ids = new Set(out.map((f) => f.id));
		let dropped = 0;
		for (const f of add || []) {
			if (ids.has(f.id)) continue;
			if (out.length >= MAX_ITEMS) { dropped++; continue; }
			out.push(f);
			ids.add(f.id);
		}
		return { files: out, dropped };
	}

	/** notify:navigate / gatedrop:navigate context → { tab, sendId } */
	function navContext(ctx) {
		const c = ctx && typeof ctx === 'object' ? ctx : {};
		return { tab: TABS.includes(c.tab) ? c.tab : 'received', sendId: c.sendId === null || c.sendId === undefined ? null : str(c.sendId) };
	}

	return {
		APP_ROUTE,
		TABS,
		EXPIRES,
		ACCESS,
		MAX_ITEMS,
		formatBytes,
		percent,
		dialogTitle,
		splitTextLink,
		emptySelection,
		toggle,
		deviceIds,
		buildTo,
		canSend,
		dialogTargets,
		deviceMeta,
		peopleDeviceLabel,
		accessView,
		when,
		relativeFuture,
		sendTitle,
		receivedView,
		sentView,
		linkState,
		linkView,
		sortLinks,
		progressText,
		sendLabel,
		sendToastView,
		rejectedTexts,
		errorText,
		mergeFiles,
		navContext,
	};
});
