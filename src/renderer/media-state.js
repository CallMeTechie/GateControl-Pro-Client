/**
 * GateControl -- Medien view state (renderer, no DOM access)
 *
 * Pure helpers for the page "Medien" (Stufe 4f, Windows: films and series from the NAS — Jellyfin first, SMB and
 * WebDAV shares beside it): the sources and the way to them ("Zuhause · direkt von der NAS", "Unterwegs · 18 Mbit/s",
 * the status bar), the cards of the rows (Weiterschauen, Zuletzt hinzugefügt, Filme, Serien), the posters of the
 * grid, the times ("noch 18 Min.", "ab 42:10", "1 Std. 48 Min."), the detail column (chips, sound, subtitles and
 * quality with what the PC does with them), seasons and episodes, the search over all sources, the keys of the grid,
 * the dialog "Quelle hinzufügen" (address hints, the Quick Connect code, the certificate) and the error texts.
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
	const KINDS = ['jellyfin', 'smb', 'webdav'];
	const NEW_MS = 7 * 24 * 60 * 60 * 1000;
	const PAGE_SIZE = 60;
	const ROW_LIMIT = 16;
	const HOME_CARD_KEY = 'gc.media.homeCard';
	const ERROR_CODES = ['invalid', 'offline', 'timeout', 'unauthorized', 'not_found', 'unsupported', 'unsupported_version', 'quick_connect_off',
		'expired', 'signed_out', 'no_protect', 'too_many', 'smb_conflict', 'cert_untrusted', 'cert_changed', 'no_lan_route', 'failed'];
	// Chromium (Electron on Windows) decodes these sounds itself; everything else Jellyfin converts (core utils/media-jellyfin.js)
	const DECODED_AUDIO = ['aac', 'mp3', 'opus', 'flac', 'vorbis'];
	const CODEC_LABELS = {
		dts: 'DTS', dca: 'DTS', truehd: 'TrueHD', mlp: 'TrueHD', ac3: 'Dolby Digital', eac3: 'Dolby Digital Plus', aac: 'AAC', mp3: 'MP3',
		flac: 'FLAC', opus: 'Opus', vorbis: 'Vorbis', subrip: 'SRT', srt: 'SRT', ass: 'ASS', ssa: 'ASS', webvtt: 'VTT', vtt: 'VTT',
		pgssub: 'PGS', pgs: 'PGS', dvdsub: 'DVD', dvbsub: 'DVB', mov_text: 'Text', hevc: 'HEVC', h265: 'HEVC', h264: 'H.264', avc: 'H.264',
		av1: 'AV1', vp9: 'VP9', vp8: 'VP8', mpeg2video: 'MPEG-2', mpeg4: 'MPEG-4', vc1: 'VC-1',
	};

	const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
	const list = (v) => (Array.isArray(v) ? v.filter(isObj) : []);
	const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
	const pad2 = (n) => String(n).padStart(2, '0');

	// ── sources and the way to them ─────────────────────────

	/** The sources of media:status that can be asked now, Jellyfin first (in the order they were set up). */
	function sourcesOf(status) {
		const all = list(status && status.sources);
		return {
			all,
			jellyfin: all.filter((s) => s.kind === 'jellyfin'),
			ready: all.filter((s) => s.kind === 'jellyfin' && s.ready),
			shares: all.filter((s) => s.kind === 'smb' || s.kind === 'webdav'),
		};
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

	/** The way to a source now: 'home' (direct in the LAN), 'away' (through the tunnel), 'unknown' (not checked yet). */
	function wayOf(link) {
		if (!isObj(link) || link.atHome === null || link.atHome === undefined) return 'unknown';
		return link.atHome ? 'home' : 'away';
	}

	/** The pill beside the source chips: "Zuhause · direkt von der NAS" / "Unterwegs · 18 Mbit/s". */
	function linkLabel(link, t, lang) {
		const way = wayOf(link);
		if (way === 'home') return { cls: 'is-home', text: t('media.link.home') };
		if (way === 'away') {
			const bw = bandwidth(link.bps, lang);
			return { cls: 'is-away', text: bw ? t('media.link.away', { bw }) : t('media.link.awayNoBw') };
		}
		return { cls: 'is-unknown', text: t('media.link.checking') };
	}

	/** The status bar: "Medien: Zuhause, direkt im LAN" / "Medien: Unterwegs, über den Tunnel · 18 Mbit/s"; null when unknown. */
	function statusLine(link, t, lang) {
		const way = wayOf(link);
		if (way === 'home') return t('media.status.home');
		if (way === 'away') {
			const bw = bandwidth(link.bps, lang);
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
			if (s.userName) parts.push(t('media.src.signedInAs', { user: s.userName }));
			if (s.address) parts.push(String(s.address).replace(/^https?:\/\//, ''));
			if (deviceName) parts.push(t('media.src.device', { device: deviceName }));
			return parts.join(' · ');
		}
		const way = s.pairWith ? t('media.src.smbHomeWebdav') : s.kind === 'smb' ? t('media.src.smb') : t('media.src.webdav');
		const extra = s.kind === 'smb' && s.useExisting ? ` · ${t('media.src.explorer')}` : s.userName ? ` · ${s.userName}` : '';
		return `${way}${extra}`;
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

	/** Several Jellyfin servers: "Weiterschauen" of all of them, the one played last first, each title once. */
	function mergeResume(answers, limit = ROW_LIMIT) {
		const seen = new Set();
		const out = [];
		for (const a of answers) for (const it of list(a && a.ok ? a.items : [])) {
			const key = `${it.sourceId}|${it.id}`;
			if (seen.has(key)) continue;
			seen.add(key);
			out.push(it);
		}
		out.sort((a, b) => (num(b.playedAt) || 0) - (num(a.playedAt) || 0));
		return out.slice(0, limit);
	}

	/** Several Jellyfin servers: "Zuletzt hinzugefügt" of all of them, the newest first. */
	function mergeLatest(answers, limit = ROW_LIMIT) {
		const out = [];
		const seen = new Set();
		for (const a of answers) for (const it of list(a && a.ok ? a.items : [])) {
			const key = `${it.sourceId}|${it.id}`;
			if (!seen.has(key)) { seen.add(key); out.push(it); }
		}
		out.sort((a, b) => (num(b.addedAt) || 0) - (num(a.addedAt) || 0));
		return out.slice(0, limit);
	}

	const norm = (s) => String(s || '').toLocaleLowerCase('de').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, ' ').trim();

	/**
	 * "In allen Quellen suchen": the hits of every source, films and series first, then episodes; a title that two
	 * sources have (the same name and year) appears once — the Jellyfin one, as on the TV.
	 */
	function mergeSearch(answers, q) {
		const term = norm(q);
		const seen = new Set();
		const out = [];
		for (const a of answers) for (const it of list(a && a.ok ? a.items : [])) {
			const key = `${it.kind === 'episode' ? `${it.seriesId}|${it.season}|${it.episode}` : it.kind}|${norm(it.name)}|${it.year || ''}`;
			if (seen.has(key)) continue;
			seen.add(key);
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

	// ── Quellen: the dialog ─────────────────────────────────

	const ipv4 = (h) => /^(?:\d{1,3}\.){3}\d{1,3}$/.test(h) && h.split('.').every((p) => Number(p) <= 255);

	/** The host of `\\nas\filme` / `smb://nas/filme`; null when it is none. */
	function smbHost(address) {
		const a = String(address || '').trim();
		const m = /^(?:\\\\|\/\/|smb:\/\/)([^\\/]+)/i.exec(a);
		return m ? m[1].replace(/:\d+$/, '') : null;
	}

	/** "Am PC lieber die IP-Adresse statt \\nas": a share given by name (unterwegs the tunnel does not resolve it). */
	function smbNameHint(address) {
		const h = smbHost(address);
		return !!h && !ipv4(h) && !h.includes(':');
	}

	/** What the form needs before "Verbinden": an address; a user only with a password field filled or the reverse. */
	function formProblem(kind, f) {
		const address = String((f && f.address) || '').trim();
		if (!KINDS.includes(kind)) return 'invalid';
		if (!address) return 'address';
		if (kind === 'smb' && !smbHost(address)) return 'address';
		if (kind === 'webdav' && /^(?:\\\\|smb:)/i.test(address)) return 'address';
		if (kind !== 'jellyfin' && !String(f.user || '').trim() && String(f.password || '')) return 'user';
		if (kind === 'smb' && f.alsoWebdav && !String(f.webdavAddress || '').trim()) return 'webdav';
		return null;
	}

	/** A WebDAV address to suggest for `\\192.168.1.20\filme`: https://192.168.1.20:5006/filme (Synology's port). */
	function webdavFor(smbAddress) {
		const a = String(smbAddress || '').trim();
		const m = /^(?:\\\\|\/\/|smb:\/\/)([^\\/]+)[\\/]+([^\\/]+)/i.exec(a);
		if (!m) return '';
		return `https://${m[1].replace(/:\d+$/, '')}:5006/${m[2]}`;
	}

	/** The Quick Connect code as shown: "482 913". */
	function codeLabel(code) {
		const s = String(code || '').replace(/\s+/g, '');
		return /^\d{6}$/.test(s) ? `${s.slice(0, 3)} ${s.slice(3)}` : s;
	}

	/** The code of another device as typed ("731 205", "731-205") → "731205", else null. */
	function codeOf(input) {
		const s = String(input == null ? '' : input).replace(/[\s-]/g, '');
		return /^\d{6}$/.test(s) ? s : null;
	}

	/** "AB:CD:…" of a SHA-256 fingerprint in groups (the dialog "Zertifikat bestätigen"). */
	function fingerprintLabel(fp) {
		const hex = String(fp || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
		if (hex.length !== 64) return String(fp || '');
		return hex.match(/.{2}/g).join(':');
	}

	/** A date of the certificate ("validTo") as the person reads it. */
	function dateLabel(v, locale) {
		const d = new Date(v);
		if (Number.isNaN(d.getTime())) return String(v || '');
		try { return d.toLocaleDateString(locale || undefined, { year: 'numeric', month: '2-digit', day: '2-digit' }); } catch { return d.toISOString().slice(0, 10); }
	}

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
		KINDS,
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
		metaLine,
		qualityOptions,
		qualityNote,
		playLabel,
		seasonChips,
		firstSeason,
		nextEpisode,
		episodeRow,
		episodeAfter,
		smbHost,
		smbNameHint,
		formProblem,
		webdavFor,
		codeLabel,
		codeOf,
		fingerprintLabel,
		dateLabel,
		errorText,
		homeCardOn,
	};
});
