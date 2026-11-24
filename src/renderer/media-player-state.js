/**
 * GateControl -- Medien player state (renderer, no DOM access, Stufe 4g)
 *
 * Pure helpers for the player of "Medien" (mockup 9): what Chromium in this app plays (the caps from canPlayType /
 * MediaCapabilities / matchMedia for media.setCaps), the info line ("Unterwegs · 18 Mbit/s · NAS rechnet um: 1080p ·
 * 8 Mbit/s · Ton AAC 5.1" / "Zuhause · direkt von der NAS"), the keys (Leertaste, ← →, F, U, T, Esc, M), the next
 * sound or subtitle for T / U, when a progress report is due, the "picture missing" check (HEVC without a decoder:
 * videoWidth 0 → ask again with H.264), the times of the control bar and the volume kept on this PC. Loaded as a plain
 * script before media-player.js (window.GCMediaPlayerState) and required by the node tests
 * (test/media-player-state.test.js).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCMediaPlayerState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const SEEK_S = 10;
	const PROGRESS_MS = 10000;
	const AWAKE_MS = 30000;
	const HIDE_MS = 3000;
	const VOLUME_KEY = 'gc.media.volume';
	const NO_PICTURE_MS = 2500;

	/** The questions put to Chromium for the caps (MIME types and the MediaCapabilities configurations). */
	const PROBES = Object.freeze({
		hevc: { type: 'video/mp4; codecs="hvc1.1.6.L120.90"', config: { type: 'file', video: { contentType: 'video/mp4; codecs="hvc1.1.6.L120.90"', width: 1920, height: 1080, bitrate: 10000000, framerate: 24 } } },
		av1: { type: 'video/mp4; codecs="av01.0.08M.08"', config: { type: 'file', video: { contentType: 'video/mp4; codecs="av01.0.08M.08"', width: 1920, height: 1080, bitrate: 10000000, framerate: 24 } } },
		vp9: { type: 'video/webm; codecs="vp9"' },
		mkv: { type: 'video/x-matroska; codecs="avc1.640028"' },
		ac3: { type: 'audio/mp4; codecs="ac-3"' },
		eac3: { type: 'audio/mp4; codecs="ec-3"' },
	});

	/**
	 * The caps for media.setCaps from what Chromium answered: { canPlay: { hevc: '' | 'maybe' | 'probably', … },
	 * decoding: { hevc: { supported }, av1: … }, hdr: matchMedia('(dynamic-range: high)').matches, channels }.
	 * HEVC and AV1 count when MediaCapabilities says "supported" (it knows whether a hardware decoder is there) or,
	 * without an answer, canPlayType says "probably".
	 */
	function capsFrom({ canPlay = {}, decoding = {}, hdr = false, channels = null } = {}) {
		const yes = (k) => canPlay[k] === 'probably' || canPlay[k] === 'maybe';
		const dec = (k) => (decoding[k] && typeof decoding[k].supported === 'boolean' ? decoding[k].supported : canPlay[k] === 'probably');
		const ch = Number.isInteger(channels) && channels >= 6 ? Math.min(8, channels) : 6;
		return {
			hevc: dec('hevc'),
			av1: dec('av1'),
			vp9: yes('vp9'),
			mkv: yes('mkv'),
			hdr: hdr === true,
			ac3: yes('ac3'),
			eac3: yes('eac3'),
			maxAudioChannels: ch,
		};
	}

	function bandwidth(bps, lang) {
		const b = Number(bps);
		if (!Number.isFinite(b) || b <= 0) return null;
		if (b >= 10000000) return `${Math.floor(b / 1000000)} Mbit/s`;
		if (b >= 1000000) {
			const tenths = Math.floor(b / 100000);
			if (tenths % 10 === 0) return `${tenths / 10} Mbit/s`;
			const s = (tenths / 10).toFixed(1);
			return `${lang === 'en' ? s : s.replace('.', ',')} Mbit/s`;
		}
		return `${Math.floor(b / 1000)} kbit/s`;
	}

	function resolution(bps) {
		if (bps >= 6000000) return '1080p';
		if (bps >= 3000000) return '720p';
		return '480p';
	}

	const REASONS_VIDEO = /^(?:VideoCodecNotSupported|VideoProfileNotSupported|VideoLevelNotSupported|VideoRangeTypeNotSupported|VideoBitDepthNotSupported|VideoResolutionNotSupported|VideoBitrateNotSupported|ContainerBitrateExceedsLimit|SubtitleCodecNotSupported|VideoFramerateNotSupported)$/;
	const REASONS_AUDIO = /^Audio/;

	/**
	 * The info line of the player (mockup 9): the way, the measurement away, and what the NAS does —
	 * { way: 'home' | 'away' | 'unknown', text, converted }.
	 *   home, direct:  "Zuhause · direkt von der NAS"
	 *   away, direct:  "Unterwegs · 18 Mbit/s · Original"
	 *   converted:     "… · NAS rechnet um: 1080p · 8 Mbit/s · Ton AAC 5.1" (only the sound: "NAS rechnet den Ton um: AAC 5.1")
	 */
	function infoLine(play, audioTarget, t, lang) {
		const link = (play && play.link) || {};
		const way = link.atHome === true ? 'home' : link.atHome === false ? 'away' : 'unknown';
		const parts = [];
		if (way === 'home') parts.push(t('media.player.home'));
		else if (way === 'away') {
			const bw = bandwidth(link.bps, lang);
			parts.push(bw ? t('media.player.away', { bw }) : t('media.player.awayNoBw'));
		}
		const converted = !!(play && play.converted);
		if (converted) {
			const reasons = Array.isArray(play.transcodeReasons) ? play.transcodeReasons : [];
			const video = !!play.bitrate || reasons.some((r) => REASONS_VIDEO.test(r)) || !reasons.length;
			const audio = reasons.some((r) => REASONS_AUDIO.test(r));
			if (video) {
				const step = play.bitrate ? `${resolution(play.bitrate)} · ${bandwidth(play.bitrate, lang)}` : t('media.player.picture');
				parts.push(t('media.player.converts', { what: step }));
				if (audio && audioTarget) parts.push(t('media.player.sound', { codec: audioTarget }));
			} else if (audio) {
				parts.push(t('media.player.convertsSound', { codec: audioTarget || 'AAC' }));
			}
		} else if (play && play.method === 'DirectStream') {
			parts.push(t('media.player.remux'));
		} else if (way !== 'home') {
			parts.push(t('media.player.original'));
		}
		if (way === 'home' && !converted && !(play && play.method === 'DirectStream')) parts[0] = t('media.player.homeDirect');
		return { way, converted, text: parts.filter(Boolean).join(' · ') };
	}

	/** "42:10" / "1:48:00" of seconds. */
	function clock(sec) {
		const s0 = Math.max(0, Math.floor(Number(sec) || 0));
		const h = Math.floor(s0 / 3600);
		const m = Math.floor((s0 % 3600) / 60);
		const s = s0 % 60;
		const p = (n) => String(n).padStart(2, '0');
		return h > 0 ? `${h}:${p(m)}:${p(s)}` : `${m}:${p(s)}`;
	}

	/** "42:10 / 1:48:00": the position and the length (the title's, when the stream does not know it). */
	function timeLabel(pos, duration, runtimeMs) {
		const d = Number.isFinite(duration) && duration > 0 ? duration : (Number(runtimeMs) > 0 ? runtimeMs / 1000 : 0);
		return d > 0 ? `${clock(pos)} / ${clock(d)}` : clock(pos);
	}

	/**
	 * A key of the player → an action: 'toggle' (Leertaste, K), 'back' / 'forward' (← →, J / L: 10 s), 'fullscreen' (F),
	 * 'subtitles' (U), 'audio' (T), 'mute' (M), 'escape' (Esc), 'volumeUp' / 'volumeDown' (↑ ↓); null for anything
	 * else or with Strg / Alt / Meta (the app's own shortcuts), and in a text field.
	 */
	function keyAction(e) {
		if (!e || e.ctrlKey || e.altKey || e.metaKey) return null;
		const tag = e.targetTag ? String(e.targetTag).toLowerCase() : '';
		if (tag === 'input' || tag === 'textarea' || tag === 'select') return null;
		switch (e.key) {
			case ' ': case 'Spacebar': case 'k': case 'K': return 'toggle';
			case 'ArrowLeft': case 'j': case 'J': return 'back';
			case 'ArrowRight': case 'l': case 'L': return 'forward';
			case 'ArrowUp': return 'volumeUp';
			case 'ArrowDown': return 'volumeDown';
			case 'f': case 'F': return 'fullscreen';
			case 'u': case 'U': return 'subtitles';
			case 't': case 'T': return 'audio';
			case 'm': case 'M': return 'mute';
			case 'Escape': return 'escape';
			default: return null;
		}
	}

	/** The next option after `current` (T: the next sound, U: the next subtitle — "Aus" included), round. */
	function nextOption(values, current) {
		const l = Array.isArray(values) ? values : [];
		if (!l.length) return null;
		const i = l.indexOf(current);
		return l[(i + 1) % l.length];
	}

	/** A position report is due: every 10 s while playing (Jellyfin's "Weiterschauen" on every device). */
	function progressDue(lastAt, now, paused) {
		if (paused) return false;
		return !Number.isFinite(lastAt) || now - lastAt >= PROGRESS_MS;
	}

	/** The new position of a jump (10 s back / forward), inside 0 … the length (a little before the end). */
	function seekTarget(pos, delta, duration) {
		const p = Math.max(0, (Number(pos) || 0) + delta);
		return Number.isFinite(duration) && duration > 0 ? Math.min(p, Math.max(0, duration - 0.5)) : p;
	}

	/**
	 * "Only sound, no picture" (HEVC without the Windows decoder, Risiko 4): the stream has a video track, it plays
	 * for a moment and Chromium shows no picture → ask Jellyfin again with H.264 — once per title.
	 */
	function missingPicture({ videoWidth, videoHeight, currentTime, hasVideo, retried }) {
		if (!hasVideo || retried) return false;
		return (videoWidth === 0 || videoHeight === 0) && Number(currentTime) >= NO_PICTURE_MS / 1000;
	}

	/** The volume kept on this PC (0..1, default 1) and whether it is muted. */
	function volumeOf(stored) {
		try {
			const v = JSON.parse(stored);
			if (!v || typeof v !== 'object' || typeof v.volume !== 'number' || !Number.isFinite(v.volume)) return { volume: 1, muted: !!(v && v.muted) };
			return { volume: Math.min(1, Math.max(0, v.volume)), muted: !!v.muted };
		} catch {
			return { volume: 1, muted: false };
		}
	}

	/** The episode's line in the player's title: "Station Eisvogel · S2 F4 · Polarnacht". */
	function titleOf(item, t) {
		if (!item) return { title: '', sub: '' };
		if (item.kind === 'episode' && item.seriesName) {
			const se = Number.isInteger(item.season) && Number.isInteger(item.episode) ? t('media.player.se', { s: item.season, e: item.episode }) : null;
			return { title: item.seriesName, sub: [se, item.name].filter(Boolean).join(' · ') };
		}
		return { title: item.name || '', sub: item.year ? String(item.year) : '' };
	}

	/** Seconds left before "Nächste Folge" starts on its own after the end (a countdown of 10 s). */
	function countdown(endedAt, now, total = 10) {
		return Math.max(0, total - Math.floor((now - endedAt) / 1000));
	}

	return {
		SEEK_S,
		PROGRESS_MS,
		AWAKE_MS,
		HIDE_MS,
		VOLUME_KEY,
		PROBES,
		capsFrom,
		bandwidth,
		resolution,
		infoLine,
		clock,
		timeLabel,
		keyAction,
		nextOption,
		progressDue,
		seekTarget,
		missingPicture,
		volumeOf,
		titleOf,
		countdown,
	};
});
