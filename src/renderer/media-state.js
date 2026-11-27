/**
 * GateControl -- Medien view state (renderer, no DOM access)
 *
 * Pure helpers for the page "Medien" (Stufe 4f, Windows: films and series from the NAS — Jellyfin first, SMB and
 * WebDAV shares beside it): the sources and the way to them ("Zuhause · direkt von der NAS", "Unterwegs · 18 Mbit/s",
 * the status bar), the cards of the rows (Weiterschauen, Zuletzt hinzugefügt, Filme, Serien), the posters of the
 * grid, the times ("noch 18 Min.", "ab 42:10", "1 Std. 48 Min."), the detail column (chips, sound, subtitles and
 * quality with what the PC does with them), seasons and episodes, the search over all sources, the keys of the grid
 * and the error texts. Sources come from the server (Medien-Plugin), there is no setup on this PC.
 * Loaded as a plain script before media-view.js (window.GCMediaState) and required by the node tests
 * (test/media-state.test.js).
 *
 * Inputs are what window.gatecontrol.media answers (core MediaService over IPC, docs/media.md: titles with gcmedia://
 * posters, sources without any secret); `t` is the i18n function (keys media.* of the Pro locales).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCMediaState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const TABS = ['overview', 'movies', 'series', 'folders'];
	const SORTS = ['name', 'added', 'year'];
	const QUALITIES = ['auto', 'original', '20', '12', '8', '4', '2'];
	const NEW_MS = 7 * 24 * 60 * 60 * 1000;
	const PAGE_SIZE = 60;
	const ROW_LIMIT = 16;
	const HOME_CARD_KEY = 'gc.media.homeCard';
	const ERROR_CODES = ['invalid', 'offline', 'timeout', 'unauthorized', 'not_found', 'unsupported', 'unsupported_version', 'quick_connect_off',
		'expired', 'signed_out', 'no_protect', 'too_many', 'smb_conflict', 'cert_untrusted', 'cert_changed', 'no_lan_route', 'no_vlc', 'failed',
		// Medien-Plugin (W2): the sources from the server, the network rule
		'vpn_required', 'no_mapping', 'admin_user', 'user_disabled', 'not_configured', 'no_access', 'rate_limited', 'code_invalid', 'device_mismatch',
		'plugin_unavailable', 'license_required', 'jellyfin_unreachable'];
	// Chromium (Electron on Windows) decodes these sounds itself; everything else Jellyfin converts (core utils/media-jellyfin.js)
	const DECODED_AUDIO = ['aac', 'mp3', 'opus', 'flac', 'vorbis'];
	const CODEC_LABELS = {
		dts: 'DTS', dca: 'DTS', truehd: 'TrueHD', mlp: 'TrueHD', ac3: 'Dolby Digital', eac3: 'Dolby Digital Plus', aac: 'AAC', mp3: 'MP3',
		flac: 'FLAC', opus: 'Opus', vorbis: 'Vorbis', subrip: 'SRT', srt: 'SRT', ass: 'ASS', ssa: 'ASS', webvtt: 'VTT', vtt: 'VTT',
		pgssub: 'PGS', pgs: 'PGS', dvdsub: 'DVD', dvbsub: 'DVB', mov_text: 'Text', hevc: 'HEVC', h265: 'HEVC', h264: 'H.264', avc: 'H.264',
		av1: 'AV1', vp9: 'VP9', vp8: 'VP8', mpeg2video: 'MPEG-2', mpeg4: 'MPEG-4', vc1: 'VC-1',
	};

	const PROBLEMS = ['no_mapping', 'quick_connect_off', 'admin_user', 'user_disabled', 'not_configured'];

	const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
	const list = (v) => (Array.isArray(v) ? v.filter(isObj) : []);
	const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
	const pad2 = (n) => String(n).padStart(2, '0');

	// ── sources and the way to them ─────────────────────────

	/**
	 * The sources of media:status that can be asked now, Jellyfin first (in the order they were set up); `library`: the
	 * ready Jellyfin servers and the shares (a pair once, as the core lists it) — the rows, grids and the search (4h).
	 */
	function sourcesOf(status) {
		const all = list(status && status.sources);
		const ready = all.filter((s) => s.kind === 'jellyfin' && s.ready);
		const shares = all.filter((s) => s.kind === 'smb' || s.kind === 'webdav');
		return { all, jellyfin: all.filter((s) => s.kind === 'jellyfin'), ready, shares, library: ready.concat(shares.filter((s) => s.ready !== false)) };
	}

	/** The Jellyfin source the grid shows: the one chosen when it is still there and signed in, else the first ready one. */
	function pickSource(status, chosen) {
		const { ready } = sourcesOf(status);
		return ready.find((s) => s.id === chosen) || ready[0] || null;
	}

	/** "18 Mbit/s" / "2,5 Mbit/s" / "800 kbit/s" (as core utils/media-quality.js label). */
	function bandwidth(bps, lang) {
		const b = num(bps);
		if (b === null || b <= 0) return null;
		if (b >= 10000000) return `${Math.floor(b / 1000000)} Mbit/s`;
		if (b >= 1000000) {
			const tenths = Math.floor(b / 100000);
			if (tenths % 10 === 0) return `${tenths / 10} Mbit/s`;
			const s = (tenths / 10).toFixed(1);
			return `${lang === 'en' ? s : s.replace('.', ',')} Mbit/s`;
		}
		return `${Math.floor(b / 1000)} kbit/s`;
	}

	/** The picture a converting step gives: "1080p" from 6 Mbit/s, "720p" from 3 (as the server scales by bit rate). */
	function resolution(bps) {
		if (bps >= 6000000) return '1080p';
		if (bps >= 3000000) return '720p';
		return '480p';
	}

	/**
	 * The way to a source now: 'home' (direct in the LAN), 'away' (through the tunnel or, with the admin's exception,
	 * over its HTTPS address), 'blocked' (away, only through the VPN, none up), 'unknown' (not checked yet).
	 */
	function wayOf(link) {
		if (!isObj(link) || link.atHome === null || link.atHome === undefined) return 'unknown';
		if (link.blocked === true) return 'blocked';
		return link.atHome ? 'home' : 'away';
	}

	/** The pill beside the source chips: "Zuhause · direkt von der NAS" / "Unterwegs · 18 Mbit/s". */
	function linkLabel(link, t, lang) {
		const way = wayOf(link);
		if (way === 'home') return { cls: 'is-home', text: t('media.link.home') };
		if (way === 'blocked') return { cls: 'is-away is-blocked', text: t('media.link.blocked') };
		if (way === 'away') {
			const bw = bandwidth(link.bps, lang);
			if (link.via === 'direct') return { cls: 'is-away', text: bw ? t('media.link.direct', { bw }) : t('media.link.directNoBw') };
			return { cls: 'is-away', text: bw ? t('media.link.away', { bw }) : t('media.link.awayNoBw') };
		}
		return { cls: 'is-unknown', text: t('media.link.checking') };
	}

	/** The status bar: "Medien: Zuhause, direkt im LAN" / "Medien: Unterwegs, über den Tunnel · 18 Mbit/s"; null when unknown. */
	function statusLine(link, t, lang) {
		const way = wayOf(link);
		if (way === 'home') return t('media.status.home');
		if (way === 'blocked') return t('media.status.blocked');
		if (way === 'away') {
			const bw = bandwidth(link.bps, lang);
			if (link.via === 'direct') return bw ? t('media.status.direct', { bw }) : t('media.status.directNoBw');
			return bw ? t('media.status.away', { bw }) : t('media.status.awayNoBw');
		}
		return null;
	}

	/** `\\192.168.1.20\filme` of a share (its UNC), else its address. */
	function sharePath(s) {
		return (s && (s.unc || s.address)) || '';
	}

	/** The chip of a source on the overview: "Jellyfin · DS918+" / "NAS-Freigabe · \\nas\filme". */
	function sourceChip(s, t) {
		if (!s) return '';
		return s.kind === 'jellyfin' ? t('media.src.jellyfin', { name: s.name || 'Jellyfin' }) : t('media.src.share', { path: sharePath(s) });
	}

	/** The line under a source in Quellen. */
	function sourceSub(s, t, deviceName) {
		if (!s) return '';
		if (s.kind === 'jellyfin') {
			const parts = [];
			if (s.managed && !s.userName && !s.problem) parts.push(t('media.src.signingIn'));
			if (s.userName) parts.push(t('media.src.signedInAs', { user: s.userName }));
			if (s.managed && s.deviceName) deviceName = s.deviceName;
			if (s.address) parts.push(String(s.address).replace(/^https?:\/\//, ''));
			if (deviceName) parts.push(t('media.src.device', { device: deviceName }));
			return parts.join(' · ');
		}
		const way = s.pairWith ? t('media.src.smbHomeWebdav') : s.kind === 'smb' ? t('media.src.smb') : t('media.src.webdav');
		const extra = s.kind === 'smb' && s.useExisting ? ` · ${t('media.src.explorer')}` : s.userName ? ` · ${s.userName}` : '';
		const checked = s.managed && s.smbChecked === true ? ` · ${t('media.src.smbChecked')}` : '';
		const conflict = isObj(s.link) && s.link.smbConflict ? ` · ${t('media.src.smbConflict')}` : '';
		return `${way}${extra}${checked}${conflict}`;
	}

	/**
	 * The pill of a source in Quellen (Medien-Plugin): its state now — a problem of the admin ("Zuordnung fehlt"), not
	 * signed in yet, at home / away through the VPN / away direct / blocked (only through the VPN). → { cls, text }.
	 */
	function sourcePill(s, t) {
		if (!s) return { cls: 'is-warn', text: '' };
		if (s.problem) return { cls: 'is-warn', text: t(`media.problem.${PROBLEMS.includes(s.problem) ? s.problem : 'other'}`) };
		if (s.kind === 'jellyfin' && !s.ready) return { cls: 'is-warn', text: s.managed ? t('media.src.signingInPill') : t('media.src.signedOutPill') };
		if (s.kind !== 'jellyfin' && s.managed && s.hasPassword === false && s.userName) return { cls: 'is-warn', text: t('media.src.noPassword') };
		const way = wayOf(s.link);
		if (way === 'blocked') return { cls: 'is-warn', text: t('media.way.blocked') };
		if (way === 'home') return { cls: 'is-acc', text: t('media.way.home') };
		if (way === 'away') return { cls: 'is-acc', text: s.link.via === 'direct' ? t('media.way.direct') : t('media.way.vpn') };
		return { cls: 'is-acc', text: t('media.src.connected') };
	}

	/** "unterwegs nur über VPN" / "unterwegs auch ohne VPN (https://…)": the rule of a server source. */
	function awayRule(s, t) {
		if (!s || !s.managed) return null;
		return s.awayMode === 'direct' && s.awayAddress ? t('media.src.awayDirect', { address: String(s.awayAddress).replace(/^https:\/\//, '') }) : t('media.src.awayVpn');
	}

	/** "vom Server, vor 3 Min." of the list; null when it never came. */
	function fetchedLabel(server, t, now = Date.now()) {
		const at = isObj(server) ? num(server.fetchedAt) : null;
		if (!at) return null;
		const min = Math.max(0, Math.floor((now - at) / 60000));
		if (min < 1) return t('media.server.fetchedNow');
		if (min < 120) return t('media.server.fetchedMin', { min });
		const h = Math.floor(min / 60);
		if (h < 48) return t('media.server.fetchedH', { h });
		return t('media.server.fetchedD', { d: Math.floor(h / 24) });
	}

	/**
	 * The notes of the server's list (Medien-Plugin): the plugin off or without licence, long without the server, the
	 * sources taken over. → [{ cls, text, key? }] (key: a note that can be put away on this PC).
	 */
	function serverNotes(server, t) {
		const out = [];
		if (!isObj(server)) return out;
		if (server.state === 'unavailable') out.push({ cls: 'note-warn', text: t(server.reason === 'license_required' ? 'media.server.license' : 'media.server.off') });
		if (isObj(server.offline) && server.offline.hint) out.push({ cls: 'note-warn', text: t(server.offline.expired ? 'media.server.offlineExpired' : 'media.server.offline', { days: server.offline.days }) });
		const n = server.notice;
		if (isObj(n) && (list(n.adopted).length || list(n.dropped).length)) {
			const names = (xs) => xs.map((x) => String(x.name || '')).filter(Boolean).join(', ');
			const parts = [t('media.server.notice')];
			if (list(n.adopted).length) parts.push(t('media.server.adopted', { names: names(list(n.adopted)) }));
			if (list(n.dropped).length) parts.push(t('media.server.dropped', { names: names(list(n.dropped)) }));
			out.push({ cls: 'note-info', text: parts.join(' '), key: `notice:${n.at || 0}` });
		}
		return out;
	}

	/** The entry "Medien" in the sidebar: only while the plugin gives its tab (media:status → server.visible). */
	function visible(status) {
		return !!(isObj(status) && isObj(status.server) && status.server.visible === true);
	}

	/** "Immer Original" on the page: on when every Jellyfin source has it (the switch sets all of them). */
	function alwaysOriginal(status) {
		const j = sourcesOf(status).jellyfin;
		return j.length > 0 && j.every((s) => s.alwaysOriginal === true);
	}

	// ── times ───────────────────────────────────────────────

	/** "42:10" / "1:48:00" of a position or length. */
	function clock(ms) {
		const total = Math.max(0, Math.floor((num(ms) || 0) / 1000));
		const h = Math.floor(total / 3600);
		const m = Math.floor((total % 3600) / 60);
		const s = total % 60;
		return h > 0 ? `${h}:${pad2(m)}:${pad2(s)}` : `${m}:${pad2(s)}`;
	}

	/** "1 Std. 48 Min." / "52 Min." of a running time; null without one. */
	function runtime(ms, t) {
		const n = num(ms);
		if (n === null || n <= 0) return null;
		const min = Math.max(1, Math.round(n / 60000));
		const h = Math.floor(min / 60);
		const m = min % 60;
		if (!h) return t('media.runtime.m', { m });
		return m ? t('media.runtime.hm', { h, m }) : t('media.runtime.h', { h });
	}

	/** "1:52" of a running time (a poster's line); null without one. */
	function shortRuntime(ms) {
		const n = num(ms);
		if (n === null || n <= 0) return null;
		const min = Math.round(n / 60000);
		return `${Math.floor(min / 60)}:${pad2(min % 60)}`;
	}

	/** What is left: "noch 18 Min." under an hour, "noch 1:06" above; null without a length or position. */
	function leftLabel(item, t) {
		const left = num(item && item.leftMs);
		if (left === null) return null;
		const min = Math.max(1, Math.round(left / 60000));
		if (min < 60) return t('media.left.min', { min });
		return t('media.left.hm', { time: `${Math.floor(min / 60)}:${pad2(min % 60)}` });
	}

	// ── titles ──────────────────────────────────────────────

	/** "Staffel 2 · Folge 4" of an episode; null for anything else. */
	function episodeLabel(item, t) {
		if (!item || item.kind !== 'episode') return null;
		if (Number.isInteger(item.season) && Number.isInteger(item.episode)) return t('media.episode', { season: item.season, episode: item.episode });
		if (Number.isInteger(item.episode)) return t('media.episodeOnly', { episode: item.episode });
		return null;
	}

	/** "3 Staffeln" / "1 Staffel" of a series (Jellyfin's ChildCount); null when not known. */
	function seasonsLabel(item, t) {
		const n = item && Number.isInteger(item.childCount) ? item.childCount : null;
		if (!n) return null;
		return n === 1 ? t('media.seasons1') : t('media.seasons', { count: n });
	}

	/** Added in the last 7 days: the "NEU" mark. */
	function isNew(item, now) {
		const at = num(item && item.addedAt);
		return at !== null && now - at >= 0 && now - at < NEW_MS;
	}

	/**
	 * A card of "Weiterschauen" (16:9, mockup 8): { title, sub ("ab 42:10" / "Staffel 2 · Folge 4"), left ("noch 18 Min."),
	 * progress 0..100, picture (backdrop, else poster), nas }.
	 */
	function resumeCard(item, t) {
		const ep = episodeLabel(item, t);
		return {
			id: item.id,
			title: item.kind === 'episode' && item.seriesName ? item.seriesName : item.name,
			sub: ep || (item.positionMs > 0 ? t('media.at', { time: clock(item.positionMs) }) : ''),
			left: leftLabel(item, t),
			progress: Math.round(Math.min(1, Math.max(0, num(item.progress) || 0)) * 100),
			picture: item.backdrop || item.poster || null,
			nas: item.fromShare === true,
		};
	}

	/** A poster (2:3): { title, sub ("2026 · 1:52" / "3 Staffeln" / "2025"), picture, progress, isNew, nas, played }. */
	function posterCard(item, t, now, { full = false } = {}) {
		let sub;
		if (item.kind === 'series') sub = full ? seasonsLabel(item, t) || (item.year ? String(item.year) : '') : (item.year ? String(item.year) : seasonsLabel(item, t) || '');
		else if (item.kind === 'episode') sub = episodeLabel(item, t) || '';
		else sub = [item.year ? String(item.year) : null, full ? shortRuntime(item.runtimeMs) : null].filter(Boolean).join(' · ');
		return {
			id: item.id,
			title: item.kind === 'episode' && item.seriesName ? item.seriesName : item.name,
			sub,
			picture: item.poster || null,
			progress: item.resumable ? Math.round(Math.min(1, Math.max(0, num(item.progress) || 0)) * 100) : 0,
			isNew: isNew(item, now),
			nas: item.fromShare === true,
			played: item.played === true,
		};
	}

	/** The rows of the overview: "Zuletzt hinzugefügt" says "diese Woche" when all of it is new. */
	function latestSub(items, t, now) {
		const l = list(items);
		if (!l.length) return '';
		return l.every((x) => isNew(x, now)) ? t('media.row.thisWeek') : t('media.row.count', { count: l.length });
	}

	// ── titles of several sources (4h, as Android's MediaLogic) ─

	/** The key two titles are the same by (letters and digits, no case) — the core sends it as `key`. */
	function keyOf(name) {
		return String(name || '').toLowerCase().replace(/[^\p{L}\p{Nd}]/gu, '');
	}

	/** A–Z as Jellyfin sorts (an English article in front does not count) — the core sends it as `sortKey`. */
	function sortKeyOf(name) {
		const n = String(name || '').toLowerCase().trim();
		const article = ['the ', 'a ', 'an '].find((x) => n.startsWith(x) && n.length > x.length);
		const plain = (article ? n.slice(article.length) : n).replace(/ß/g, 'ss').normalize('NFD').replace(/\p{M}+/gu, '');
		return plain.replace(/[^\p{L}\p{Nd} ]/gu, '').replace(/ +/g, ' ').trim();
	}

	const titleKey = (it) => (typeof it.key === 'string' ? it.key : keyOf(it.kind === 'episode' ? it.seriesName || it.name : it.name));
	const sortOf = (it) => (typeof it.sortKey === 'string' ? it.sortKey : sortKeyOf(it.name));

	/** Two titles are the same film, series or episode (the name, and the year when both have one). */
	function same(a, b) {
		if (!a || !b) return false;
		if (a.kind === 'episode' || b.kind === 'episode') {
			return a.kind === b.kind && Number.isInteger(a.season) && a.season === b.season && a.episode === b.episode
				&& !!a.seriesName && !!b.seriesName && keyOf(a.seriesName) === keyOf(b.seriesName);
		}
		if ((a.kind === 'series') !== (b.kind === 'series')) return false;
		const k = titleKey(a);
		if (!k || k !== titleKey(b)) return false;
		return !a.year || !b.year || a.year === b.year;
	}

	/** `shares`' titles without those `jellyfin` has too: a title in both shows once, Jellyfin's. */
	function withoutDuplicates(shares, jellyfin) {
		const j = list(jellyfin);
		if (!j.length) return list(shares);
		const byKey = new Map();
		for (const it of j) {
			const k = titleKey(it);
			if (!byKey.has(k)) byKey.set(k, []);
			byKey.get(k).push(it);
		}
		return list(shares).filter((s) => !(byKey.get(titleKey(s)) || []).some((x) => same(s, x)));
	}

	/** The titles of several answers, each once (Jellyfin's first: a share's twin goes), in the order they came. */
	function flatten(answers, known) {
		const seen = new Set();
		const out = [];
		for (const a of answers) for (const it of list(a && a.ok ? a.items : [])) {
			const key = `${it.sourceId}|${it.id}`;
			if (seen.has(key)) continue;
			seen.add(key);
			out.push(it);
		}
		const jf = out.filter((x) => x.fromShare !== true).concat(list(known));
		const shares = withoutDuplicates(out.filter((x) => x.fromShare === true), jf);
		return out.filter((x) => x.fromShare !== true || shares.includes(x));
	}

	const stable = (items, cmp) => items.map((it, i) => ({ it, i })).sort((a, b) => cmp(a.it, b.it) || a.i - b.i).map((x) => x.it);

	/** "Weiterschauen" of all sources (Jellyfin servers and shares): the one played last first, each title once. */
	function mergeResume(answers, limit = ROW_LIMIT, known = []) {
		return stable(flatten(answers, known), (a, b) => (num(b.playedAt) || 0) - (num(a.playedAt) || 0)).slice(0, limit);
	}

	/** "Zuletzt hinzugefügt" of all sources, the newest first, a title of Jellyfin and a share once (Jellyfin's). */
	function mergeLatest(answers, limit = ROW_LIMIT, known = []) {
		return stable(flatten(answers, known), (a, b) => (num(b.addedAt) || 0) - (num(a.addedAt) || 0)).slice(0, limit);
	}

	/** The order of a grid: A–Z, newest first, or the latest year first; then A–Z. */
	function comparator(sort) {
		const byName = (a, b) => { const x = sortOf(a); const y = sortOf(b); return x < y ? -1 : x > y ? 1 : 0; };
		if (sort === 'added') return (a, b) => (num(b.addedAt) || 0) - (num(a.addedAt) || 0) || byName(a, b);
		if (sort === 'year') return (a, b) => (num(b.year) || 0) - (num(a.year) || 0) || byName(a, b);
		return byName;
	}

	/** Not watched yet: a film or episode not played, a series with episodes left. */
	function unwatched(t) {
		if (t.kind === 'series' || t.kind === 'season') return Number.isInteger(t.unplayed) ? t.unplayed > 0 : !t.played;
		return !t.played;
	}

	/**
	 * A grid of Jellyfin (its pages in the server's order) with the shares' titles in their places — a title Jellyfin
	 * has too once, Jellyfin's. While Jellyfin has more pages (`complete` false) a share's title after the last one
	 * loaded waits for the next page. Filters: only unwatched ones; a genre leaves the shares out (they have none).
	 */
	function mergeGrid(jellyfin, complete, shares, f) {
		const o = f || {};
		const j = list(jellyfin);
		if (!complete && !j.length) return [];
		const cmp = comparator(o.sort);
		const last = j.length ? j[j.length - 1] : null;
		const waiting = stable(withoutDuplicates(shares, j).filter((t) => (!o.unplayed || unwatched(t)) && !o.genre), cmp)
			.filter((t) => complete || !last || cmp(t, last) <= 0);
		const out = [];
		let i = 0;
		for (const x of j) {
			while (i < waiting.length && cmp(waiting[i], x) < 0) out.push(waiting[i++]);
			out.push(x);
		}
		while (i < waiting.length) out.push(waiting[i++]);
		return out;
	}

	const norm = (s) => String(s || '').toLocaleLowerCase('de').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, ' ').trim();

	/**
	 * "In allen Quellen suchen": the hits of every source, films and series first, then episodes; a title that two
	 * sources have (the same name and year) appears once — the Jellyfin one, as on the TV.
	 */
	function mergeSearch(answers, q) {
		const term = norm(q);
		const out = [];
		for (const a of answers) for (const it of list(a && a.ok ? a.items : [])) {
			if (out.some((x) => (x.sourceId === it.sourceId && x.id === it.id) || same(x, it))) continue;
			out.push(it);
		}
		const rank = (it) => (it.kind === 'episode' ? 2 : 0) + (norm(it.name).startsWith(term) ? 0 : 1);
		return out.map((it, i) => ({ it, i })).sort((a, b) => rank(a.it) - rank(b.it) || a.i - b.i).map((x) => x.it);
	}

	/** The genres the grid's filter offers: those of the titles loaded so far, A–Z, plus the chosen one. */
	function genresOf(items, chosen) {
		const set = new Set();
		for (const it of list(items)) for (const g of Array.isArray(it.genres) ? it.genres : []) if (typeof g === 'string' && g.trim()) set.add(g.trim());
		if (chosen) set.add(chosen);
		return [...set].sort((a, b) => a.localeCompare(b, 'de', { sensitivity: 'base' }));
	}

	/** A page of the grid appended to what is there (an item once), with the next start. */
	function appendPage(prev, answer) {
		const items = list(prev && prev.items).slice();
		const ids = new Set(items.map((x) => x.id));
		for (const it of list(answer && answer.items)) if (!ids.has(it.id)) { ids.add(it.id); items.push(it); }
		const next = answer && Number.isInteger(answer.next) ? answer.next : null;
		return { items, total: num(answer && answer.total) ?? items.length, next };
	}

	/** Arrow keys in the grid: the index after `key` with `cols` columns (stays inside 0..count-1). */
	function gridMove(index, key, cols, count) {
		if (!count) return -1;
		const c = Math.max(1, cols | 0);
		const i = Math.min(count - 1, Math.max(0, index | 0));
		switch (key) {
			case 'ArrowRight': return Math.min(count - 1, i + 1);
			case 'ArrowLeft': return Math.max(0, i - 1);
			case 'ArrowDown': return i + c < count ? i + c : i;
			case 'ArrowUp': return i - c >= 0 ? i - c : i;
			case 'Home': return 0;
			case 'End': return count - 1;
			case 'PageDown': return Math.min(count - 1, i + c * 3);
			case 'PageUp': return Math.max(0, i - c * 3);
			default: return i;
		}
	}

	// ── the detail column ───────────────────────────────────

	function codecLabel(codec) {
		const c = codec ? String(codec).toLowerCase() : '';
		if (!c) return null;
		return Object.prototype.hasOwnProperty.call(CODEC_LABELS, c) ? CODEC_LABELS[c] : c.toUpperCase();
	}

	function channelsLabel(ch) {
		if (ch === 1) return 'Mono';
		if (ch === 2) return 'Stereo';
		if (ch === 6) return '5.1';
		if (ch === 8) return '7.1';
		return ch ? `${ch} ch` : null;
	}

	/** The sound Jellyfin converts to for this PC: AAC 5.1 when the track has more than two channels, else AAC Stereo. */
	function targetAudio(stream, caps) {
		const max = caps && Number.isInteger(caps.maxAudioChannels) ? caps.maxAudioChannels : 6;
		return (stream && stream.channels > 2 && max >= 6) ? 'AAC 5.1' : 'AAC Stereo';
	}

	/** Whether Chromium plays the sound itself (core MT.fate): 'decoded' | 'converted'. */
	function audioFate(stream, caps) {
		if (stream && (stream.fate === 'decoded' || stream.fate === 'converted')) return stream.fate;
		const c = stream && stream.codec ? String(stream.codec).toLowerCase() : '';
		if (DECODED_AUDIO.includes(c) || (c === 'ac3' && caps && caps.ac3) || (c === 'eac3' && caps && caps.eac3)) return 'decoded';
		return 'converted';
	}

	/** The options of "Ton": { value (stream index), label "Deutsch · DTS 5.1", note "NAS rechnet in AAC 5.1 um" | "direkt" }. */
	function audioOptions(version, caps, t) {
		return list(version && version.audio).map((s) => {
			const lang = s.languageName || (s.language ? String(s.language).toUpperCase() : t('media.lang.unknown'));
			const label = s.label || [codecLabel(s.codec), channelsLabel(s.channels)].filter(Boolean).join(' ') || 'Audio';
			const extra = s.title && !String(s.title).toLowerCase().includes(String(lang).toLowerCase()) ? ` – ${s.title}` : '';
			const fate = audioFate(s, caps);
			return {
				value: s.index,
				label: `${lang} · ${label}${extra}`,
				fate,
				note: fate === 'converted' ? t('media.audio.converts', { target: targetAudio(s, caps) }) : t('media.audio.direct'),
				why: fate === 'converted' ? t('media.audio.cannot', { codec: codecLabel(s.codec) || 'Audio', target: targetAudio(s, caps) }) : t('media.audio.direct'),
			};
		});
	}

	/** The options of "Untertitel": "Aus" (-1) first, then { label "Deutsch · Text (SRT)", note }. */
	function subtitleOptions(version, t) {
		const out = [{ value: -1, label: t('media.sub.off'), note: '', burnIn: false }];
		for (const s of list(version && version.subtitles)) {
			const lang = s.languageName || (s.language ? String(s.language).toUpperCase() : t('media.lang.unknown'));
			const codec = s.codecLabel || codecLabel(s.codec) || '';
			const burnIn = s.burnIn === true || s.picture === true;
			const kind = burnIn ? t('media.sub.picture', { codec }) : t('media.sub.text', { codec });
			const forced = s.forced ? ` · ${t('media.sub.forced')}` : '';
			out.push({ value: s.index, label: `${lang} · ${kind}${forced}`, note: burnIn ? t('media.sub.burnIn') : t('media.sub.vtt'), burnIn });
		}
		return out;
	}

	/** The subtitle chosen at the start: the series' choice (pick), else off. */
	function pickedSubtitle(version) {
		const p = version && version.pick;
		return p && Number.isInteger(p.subtitleIndex) ? p.subtitleIndex : -1;
	}

	function pickedAudio(version) {
		const p = version && version.pick;
		if (p && Number.isInteger(p.audioIndex)) return p.audioIndex;
		const a = list(version && version.audio);
		return a.length ? a[0].index : null;
	}

	/** Whether Chromium shows the picture itself (HEVC only with the hardware decoder, HDR only with Windows' HDR on). */
	function videoConverted(version, caps) {
		const v = version && version.video;
		if (!v) return false;
		const c = String(v.codec || '').toLowerCase();
		if ((c === 'hevc' || c === 'h265') && !(caps && caps.hevc)) return true;
		if (c && !['h264', 'avc', 'hevc', 'h265', 'vp9', 'vp8', 'av1'].includes(c)) return true;
		if (version.hdr && !(caps && caps.hdr)) return true;
		return false;
	}

	/** The chips of the detail: "4K · HDR10", "HEVC · mkv", "am PC: Ton umgerechnet" (warn). */
	function detailChips(version, audioIndex, caps, t) {
		if (!version) return [];
		const out = [];
		const res = version.videoLabel ? String(version.videoLabel).split(' ')[0] : null;
		const pic = [res, version.hdr].filter(Boolean).join(' · ');
		if (pic) out.push({ cls: '', text: pic });
		const fmt = [codecLabel(version.video && version.video.codec), version.container].filter(Boolean).join(' · ');
		if (fmt) out.push({ cls: '', text: fmt });
		const a = list(version.audio).find((s) => s.index === audioIndex);
		const vConv = videoConverted(version, caps);
		const aConv = a ? audioFate(a, caps) === 'converted' : false;
		if (vConv && aConv) out.push({ cls: 'is-warn', text: t('media.chip.bothConverted') });
		else if (vConv) out.push({ cls: 'is-warn', text: t('media.chip.videoConverted') });
		else if (aConv) out.push({ cls: 'is-warn', text: t('media.chip.audioConverted') });
		return out;
	}

	// ── „Videos umwandeln“ (gatecontrol-medien 1.6.0) ───────

	/** What this PC does not play itself, for the hint: „HEVC“, „Dolby Vision“, „HDR“, „MPEG-2“ (core MC.videoProblem). */
	function convertWhat(problem) {
		if (!isObj(problem)) return null;
		if (problem.code === 'dovi') return 'Dolby Vision';
		if (problem.code === 'hdr') return [codecLabel(problem.codec), 'HDR'].filter(Boolean).join(' ');
		return codecLabel(problem.codec);
	}

	/** The clock time of `startsAt` (ms) — German 24 hours „01:08“, English the locale's short time; null when past or unknown. */
	function convertClock(startsAt, lang, now = Date.now()) {
		const ms = num(startsAt);
		if (ms === null || ms <= now) return null;
		const d = new Date(ms);
		if (lang !== 'en') return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
		try { return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }); } catch { return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`; }
	}

	/**
	 * The card before playing (core media:convert:hint) → null | { kind, title, text, button (label) | null, percent }:
	 *   offer      „Wird beim Abspielen umgewandelt“ · „Für heute Nacht vormerken“
	 *   requested  „Zum Umwandeln vorgemerkt“
	 *   queued     „Wird heute Nacht umgewandelt · Platz 2 · ab 01:08 Uhr“
	 *   running    „Wird gerade umgewandelt – 47 %“ (with the bar)
	 * Playing stays possible always: the card never replaces a button.
	 */
	function convertCard(hint, t, lang, now = Date.now()) {
		if (!isObj(hint)) return null;
		const what = convertWhat(hint.problem);
		if (hint.kind === 'offer') {
			return { kind: 'offer', title: t('media.convert.offerTitle'), text: what ? t('media.convert.offerText', { what }) : t('media.convert.offerTextPlain'), button: t('media.convert.request'), percent: null };
		}
		if (hint.kind === 'requested') return { kind: 'requested', title: t('media.convert.requestedTitle'), text: t('media.convert.requestedText'), button: null, percent: null };
		if (hint.kind === 'queued') {
			const parts = [t('media.convert.queuedTitle')];
			const pos = num(hint.position);
			if (pos !== null && pos > 0) parts.push(t('media.convert.queuedPlace', { n: pos }));
			const clock = convertClock(hint.startsAt, lang, now);
			if (clock) parts.push(t('media.convert.queuedFrom', { time: clock }));
			return { kind: 'queued', title: parts.join(' · '), text: t('media.convert.after'), button: null, percent: null };
		}
		if (hint.kind === 'running') {
			const pc = num(hint.percent);
			const p = pc === null ? null : Math.round(Math.min(100, Math.max(0, pc)));
			return { kind: 'running', title: p === null ? t('media.convert.runningTitle') : t('media.convert.runningPercent', { n: p }), text: t('media.convert.after'), button: null, percent: p };
		}
		return null;
	}

	/** The meta line: "2025 · 1 Std. 48 Min. · Drama · FSK 12". */
	function metaLine(title, t) {
		if (!title) return '';
		const parts = [];
		if (title.kind === 'episode') parts.push(episodeLabel(title, t));
		if (title.year) parts.push(String(title.year));
		if (title.kind === 'series') parts.push(seasonsLabel(title, t));
		else parts.push(runtime(title.runtimeMs, t));
		if (Array.isArray(title.genres) && title.genres.length) parts.push(title.genres.slice(0, 2).join(', '));
		if (title.rating) parts.push(/^\d+$/.test(String(title.rating)) ? `FSK ${title.rating}` : String(title.rating));
		return parts.filter(Boolean).join(' · ');
	}

	/** The options of "Qualität" with the line of the detail ("Automatisch · zu Hause Original"). */
	function qualityOptions(t, lang) {
		return QUALITIES.map((q) => ({
			value: q,
			label: q === 'auto' ? t('media.quality.auto') : q === 'original' ? t('media.quality.original') : `${resolution(Number(q) * 1000000)} · ${bandwidth(Number(q) * 1000000, lang)}`,
		}));
	}

	/** What "Automatisch" means for this title now: at home the original, away the step the line carries. */
	function qualityNote(setting, offer, link, t, lang, alwaysOrig) {
		const q = QUALITIES.includes(String(setting)) ? String(setting) : 'auto';
		if (alwaysOrig) return t('media.quality.alwaysOriginal');
		if (q !== 'auto') return q === 'original' ? t('media.quality.originalNote') : t('media.quality.fixedNote');
		const way = wayOf(link);
		if (way === 'home') return t('media.quality.autoHome');
		if (offer && offer.suggestAdapted && num(offer.adaptedBps)) {
			return t('media.quality.autoAway', { res: resolution(offer.adaptedBps), bw: bandwidth(offer.adaptedBps, lang) });
		}
		return way === 'away' ? t('media.quality.autoAwayOriginal') : t('media.quality.autoUnknown');
	}

	/** The button of a title: "Weiter ab 42:10" when started, else "Abspielen". */
	function playLabel(title, t) {
		return title && title.positionMs > 0 && !title.played ? t('media.detail.resume', { time: clock(title.positionMs) }) : t('media.detail.play');
	}

	/** The seasons of a series as the column's chips: { id, label "Staffel 1" / "Extras" }. */
	function seasonChips(seasons, t) {
		return list(seasons).map((s) => ({
			id: s.id,
			label: Number.isInteger(s.episode) && s.episode === 0 ? t('media.series.specials') : Number.isInteger(s.episode) ? t('media.series.season', { n: s.episode }) : s.name,
			unplayed: Number.isInteger(s.unplayed) ? s.unplayed : null,
		}));
	}

	/** The season to open first: the one of the episode to watch next, else the first with something unwatched, else the first. */
	function firstSeason(seasons, nextEpisode) {
		const l = list(seasons);
		if (!l.length) return null;
		if (nextEpisode && nextEpisode.seasonId && l.some((s) => s.id === nextEpisode.seasonId)) return nextEpisode.seasonId;
		const open = l.find((s) => s.episode !== 0 && (s.unplayed === null || s.unplayed === undefined || s.unplayed > 0));
		return (open || l.find((s) => s.episode !== 0) || l[0]).id;
	}

	/** The episode to watch next: the one started, else the first not watched (in order), else none. */
	function nextEpisode(episodes) {
		const l = list(episodes);
		return l.find((e) => e.positionMs > 0 && !e.played) || l.find((e) => !e.played) || null;
	}

	/** A row of the episode list: { id, num "4", title, sub "52 Min. · noch 18 Min.", progress, played }. */
	function episodeRow(e, t) {
		return {
			id: e.id,
			num: Number.isInteger(e.episode) ? String(e.episode) : '·',
			title: e.name,
			sub: [runtime(e.runtimeMs, t), e.positionMs > 0 && !e.played ? leftLabel(e, t) : null].filter(Boolean).join(' · '),
			progress: e.positionMs > 0 && !e.played ? Math.round(Math.min(1, Math.max(0, num(e.progress) || 0)) * 100) : 0,
			played: e.played === true,
		};
	}

	/** The episode after `id` in the list (the next one of the season), else null. */
	function episodeAfter(episodes, id) {
		const l = list(episodes);
		const i = l.findIndex((e) => e.id === id);
		return i >= 0 && i + 1 < l.length ? l[i + 1] : null;
	}

	// ── Ordner: the folders of a share (4h) ─────────────────

	/** What the folder view shows: folders, videos and sound (no pictures, subtitles or other files). */
	function folderItems(items) {
		return list(items).filter((e) => e.directory === true || e.kind === 'video' || e.kind === 'audio');
	}

	/** "1,4 GB" / "700 MB" / "12 kB". */
	function sizeLabel(bytes, lang) {
		const n = num(bytes);
		if (n === null || n <= 0) return null;
		const dec = (v) => (lang === 'en' ? v : v.replace('.', ','));
		if (n >= 1e9) return `${dec((n / 1e9).toFixed(n >= 1e10 ? 0 : 1))} GB`;
		if (n >= 1e6) return `${Math.round(n / 1e6)} MB`;
		return `${Math.max(1, Math.round(n / 1e3))} kB`;
	}

	/** The name of a file without its extension ("Moorlicht.mp4" → "Moorlicht"). */
	function baseName(name) {
		const n = String(name || '');
		const i = n.lastIndexOf('.');
		return i > 0 ? n.slice(0, i) : n;
	}

	/**
	 * A line of the folder view: { kind 'folder' | 'video' | 'audio', title (from the name: "Kobaltnacht", an episode's
	 * name), sub ("2025 · 1,4 GB · 1 Std. 48 Min. · noch 19 Min." / "Staffel 1 · Folge 2 · …"), picture, progress 0..100,
	 * played, file (the name as it is) }.
	 */
	function folderRow(e, t, lang) {
		if (e.directory) return { kind: 'folder', title: e.name, sub: '', picture: null, progress: 0, played: false, file: e.name };
		const p = isObj(e.progress) ? e.progress : null;
		const dur = p && p.durationMs > 0 ? p.durationMs : null;
		const pos = p && !p.played ? p.positionMs || 0 : 0;
		const parts = [];
		if (Number.isInteger(e.season) && Number.isInteger(e.episode)) parts.push(t('media.episode', { season: e.season, episode: e.episode }));
		if (e.year) parts.push(String(e.year));
		parts.push(sizeLabel(e.size, lang));
		if (dur) parts.push(runtime(dur, t));
		if (pos > 0 && dur) parts.push(leftLabel({ leftMs: Math.max(0, dur - pos) }, t));
		return {
			kind: e.kind === 'audio' ? 'audio' : 'video',
			title: e.title || baseName(e.name),
			sub: parts.filter(Boolean).join(' · '),
			picture: e.poster || null,
			progress: pos > 0 && dur ? Math.round(Math.min(1, pos / dur) * 100) : 0,
			played: !!(p && p.played),
			file: e.name,
		};
	}

	/** The path above a folder as buttons: [{ label, dir }] from the share's root ("\\nas\filme") down. */
	function crumbs(dir, rootLabel) {
		const parts = String(dir || '').split('/').filter(Boolean);
		const out = [{ label: rootLabel, dir: '' }];
		parts.forEach((p, i) => out.push({ label: p, dir: parts.slice(0, i + 1).join('/') }));
		return out;
	}

	/** The folder above `dir` ("" at the root: none). */
	function parentDir(dir) {
		const parts = String(dir || '').split('/').filter(Boolean);
		return parts.length ? parts.slice(0, -1).join('/') : null;
	}

	// ── Ordner: Jellyfin's libraries beside the shares (as Android #301) ──

	/**
	 * What "Ordner" shows first: 'roots' (a Jellyfin server is ready: its libraries and the shares as a list),
	 * 'share' (no Jellyfin: the share as before, several as chips), 'empty' (neither).
	 */
	function folderStart(status) {
		const { ready, shares } = sourcesOf(status);
		if (ready.length) return 'roots';
		return shares.length ? 'share' : 'empty';
	}

	/**
	 * The libraries of the servers asked ([{ sourceId, r }], r the answer of media:libraries) → { rows, error }: rows
	 * [{ sourceId, id, name }] in the servers' order; error only when no server could be read (one is enough).
	 */
	function libraryRoots(answers) {
		const rows = [];
		let read = false;
		let error = null;
		for (const a of list(answers)) {
			const r = a && a.r;
			if (r && r.ok) {
				read = true;
				for (const f of list(r.folders)) if (isObj(f) && typeof f.id === 'string' && typeof f.name === 'string') rows.push({ sourceId: a.sourceId, id: f.id, name: f.name });
			} else if (!error) error = (r && r.code) || 'failed';
		}
		return { rows, error: read ? null : error };
	}

	/** A film, series or video in a Jellyfin folder: picture, name, "2024 · 1 Std. 48 Min. · noch 18 Min.". */
	function libraryTitle(item, t) {
		const parts = [];
		if (item.kind === 'episode') parts.push(episodeLabel(item, t));
		if (item.kind === 'season' && item.seriesName) parts.push(item.seriesName);
		if (item.year) parts.push(String(item.year));
		if (item.kind === 'series') parts.push(seasonsLabel(item, t));
		else if (item.kind !== 'season') parts.push(runtime(item.runtimeMs, t));
		if (item.resumable) parts.push(leftLabel(item, t));
		const playable = item.kind === 'movie' || item.kind === 'episode' || item.kind === 'video';
		return {
			title: item.name,
			sub: parts.filter(Boolean).join(' · '),
			picture: item.backdrop || item.poster || null,
			progress: item.resumable ? Math.round(Math.min(1, Math.max(0, num(item.progress) || 0)) * 100) : 0,
			played: item.played === true,
			playable,
		};
	}

	/** The line under a share's head: "SMB · Zuhause" / "WebDAV · unterwegs", with the hint of a pair. */
	function shareWay(source, via, link, t) {
		const way = wayOf(link);
		const kind = via === 'webdav' ? 'WebDAV' : via === 'smb' ? 'SMB' : source && source.kind === 'webdav' ? 'WebDAV' : 'SMB';
		const where = way === 'home' ? t('media.folders.home') : way === 'away' ? t('media.folders.away') : null;
		return {
			label: where ? `${kind} · ${where}` : kind,
			hint: source && source.pairWith ? t('media.folders.pairHint') : t('media.folders.originalHint'),
		};
	}

	/**
	 * The check before the start (core check: utils/media-playable.js) as the page says it: { level 'ok' | 'warn' |
	 * 'bad' | 'unknown', text ("Ton DTS: am PC kein Ton"), external (VLC is the better way) }; null without a check.
	 */
	function checkNote(check, t) {
		if (!isObj(check)) return null;
		const reasons = Array.isArray(check.reasons) ? check.reasons : [];
		const st = isObj(check.streams) ? check.streams : {};
		const audio = Array.isArray(st.audio) && st.audio.length ? codecLabel(st.audio[0]) : null;
		const video = Array.isArray(st.video) && st.video.length ? codecLabel(st.video[0]) : null;
		const container = check.container ? String(check.container).toUpperCase() : '';
		const texts = [];
		if (reasons.includes('container')) texts.push(t('media.check.container', { format: container || '?' }));
		if (reasons.includes('hevc_no_hw')) texts.push(t('media.check.hevc'));
		if (reasons.includes('video_codec')) texts.push(t('media.check.video', { codec: video || '?' }));
		if (reasons.includes('audio_codec')) texts.push(t('media.check.audio', { codec: audio || '?' }));
		if (reasons.includes('some_audio')) texts.push(t('media.check.someAudio', { codec: audio || '?' }));
		if (reasons.includes('picture_subtitles')) texts.push(t('media.check.pictureSubs'));
		const verdict = check.verdict;
		const level = verdict === 'yes' ? (texts.length ? 'warn' : 'ok') : verdict === 'partial' ? 'warn' : verdict === 'no' ? 'bad' : 'unknown';
		if (!texts.length) texts.push(level === 'ok' ? t('media.check.ok') : t('media.check.unknown'));
		return { level, text: texts.join(' · '), external: check.external === true && (verdict === 'no' || verdict === 'partial') };
	}

	/** Which other app: VLC when it is there, else Windows' app for the file (SMB only: WebDAV has no path), else none. */
	function externalApp(info, via) {
		if (isObj(info) && info.vlc) return 'vlc';
		if (isObj(info) && info.openPath !== false && via === 'smb') return 'default';
		return null;
	}

	// ── Quellen: the dialog ─────────────────────────────────

	/** The sentence of an error code (media.error.*); an unknown one is "failed". */
	function errorText(code, t) {
		const c = ERROR_CODES.includes(code) ? code : 'failed';
		return t(`media.error.${c === 'timeout' ? 'offline' : c}`);
	}

	/** "Weiterschauen" on the overview: on unless switched off on this PC (localStorage value). */
	function homeCardOn(stored) {
		return stored !== 'off' && stored !== false && stored !== 'false';
	}

	return {
		TABS,
		SORTS,
		QUALITIES,
		PAGE_SIZE,
		ROW_LIMIT,
		HOME_CARD_KEY,
		NEW_MS,
		sourcesOf,
		pickSource,
		bandwidth,
		resolution,
		wayOf,
		linkLabel,
		statusLine,
		sourcePill,
		awayRule,
		fetchedLabel,
		serverNotes,
		visible,
		sharePath,
		sourceChip,
		sourceSub,
		alwaysOriginal,
		clock,
		runtime,
		shortRuntime,
		leftLabel,
		episodeLabel,
		seasonsLabel,
		isNew,
		resumeCard,
		posterCard,
		latestSub,
		mergeResume,
		mergeLatest,
		mergeSearch,
		keyOf,
		sortKeyOf,
		same,
		withoutDuplicates,
		comparator,
		unwatched,
		mergeGrid,
		folderItems,
		sizeLabel,
		baseName,
		folderRow,
		crumbs,
		parentDir,
		folderStart,
		libraryRoots,
		libraryTitle,
		shareWay,
		checkNote,
		externalApp,
		genresOf,
		appendPage,
		gridMove,
		codecLabel,
		channelsLabel,
		targetAudio,
		audioFate,
		audioOptions,
		subtitleOptions,
		pickedSubtitle,
		pickedAudio,
		videoConverted,
		detailChips,
		convertWhat,
		convertClock,
		convertCard,
		metaLine,
		qualityOptions,
		qualityNote,
		playLabel,
		seasonChips,
		firstSeason,
		nextEpisode,
		episodeRow,
		episodeAfter,
		errorText,
		homeCardOn,
	};
});
