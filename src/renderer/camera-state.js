/**
 * GateControl -- Kameras view state (renderer, no DOM access)
 *
 * Pure helpers for the page "Kameras" (home cameras of the plugin
 * gatecontrol-door 1.6.0 "Tür & Kamera"): the camera cards (picture, name,
 * "Heimnetz" / "live" / "offline", model · motion · how long clips stay),
 * the chips, which camera to show, the player's overlay ("● LIVE",
 * "HD · über VPN" or "Standbild · alle 10 s", "Einfahrt · 16:52:31"), when
 * the live answer must be asked for again (tokens last 10 minutes), the
 * rows of "Clips heute" with their type pills, error texts and where a
 * camera push leads. Loaded as a plain script before camera-view.js
 * (window.GCCameraState) and required by the node tests
 * (test/camera-state.test.js).
 *
 * Inputs are what window.gatecontrol.cameras returns (core CamerasService,
 * answers already cleaned by core utils/cameras.js: times in ms, media as
 * gccam:// addresses); `t` is the i18n function (keys cameras.* of the core
 * locales).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCCameraState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const APP_ROUTE = 'plg-gatecontrol-door';
	const TOPIC = 'plugin:gatecontrol-door:kamera';
	const PUSH_TYPE = 'home_camera_event';
	const CAM_ID_RE = /^c[0-9a-f]{15}$/;
	const EVENT_ID_RE = /^e[0-9a-f]{15}$/;
	const KINDS = ['person', 'vehicle', 'animal', 'motion'];
	// Pills of the mockup: Person (warn), Auto (info), Tier / Bewegung (neutral)
	const KIND_CLASS = { person: 'is-warn', vehicle: 'is-info', animal: 'is-neu', motion: 'is-neu' };
	const ERROR_CODES = ['not_found', 'cam_offline', 'cam_unreachable', 'cam_not_ready', 'cam_needs_gc', 'cam_auth', 'cam_unsupported', 'cam_service', 'cam_not_allowed', 'cam_tls', 'no_image', 'rate_limited', 'too_soon', 'network', 'timeout'];
	const MIN_REFRESH_MS = 20 * 1000;
	const SNAPSHOT_REFRESH_MS = 9 * 60 * 1000; // the still's token lasts 10 min
	const CARD_EVERY_MS = 30 * 1000;           // pictures of the cards

	const isCameraId = (v) => typeof v === 'string' && CAM_ID_RE.test(v);
	const pad = (n) => String(n).padStart(2, '0');

	function timeOf(ms, locale, seconds = false) {
		if (!Number.isFinite(ms)) return '';
		try {
			return new Intl.DateTimeFormat(locale || undefined, { hour: '2-digit', minute: '2-digit', ...(seconds ? { second: '2-digit' } : {}) }).format(new Date(ms));
		} catch {
			const d = new Date(ms);
			return `${pad(d.getHours())}:${pad(d.getMinutes())}${seconds ? `:${pad(d.getSeconds())}` : ''}`;
		}
	}

	/** "vor 4 s" / "vor 2 min" / "vor 3 h" / a time — of a picture or an event. */
	function ago(ms, now, t, locale) {
		if (!Number.isFinite(ms)) return '';
		const s = Math.max(0, Math.round((now - ms) / 1000));
		if (s < 3) return t('cameras.ago.now');
		if (s < 60) return t('cameras.ago.s', { n: s });
		if (s < 3600) return t('cameras.ago.min', { n: Math.floor(s / 60) });
		if (s < 12 * 3600) return t('cameras.ago.h', { n: Math.floor(s / 3600) });
		return timeOf(ms, locale);
	}

	/** 24000 → "0:24", 65000 → "1:05". */
	function duration(ms) {
		if (!Number.isFinite(ms) || ms <= 0) return '';
		const s = Math.max(1, Math.round(ms / 1000));
		return `${Math.floor(s / 60)}:${pad(s % 60)}`;
	}

	function kindPill(kind, t) {
		const k = KINDS.includes(kind) ? kind : 'motion';
		return { label: t(`cameras.kind.${k}`), cls: KIND_CLASS[k] };
	}

	/** "Bewegung: Personen, Autos" / "… nur wenn niemand zu Hause" / "keine Clips". */
	function recordText(settings, t) {
		const s = settings || {};
		if (s.record === 'never') return t('cameras.card.never');
		if (s.record === 'away') return t('cameras.card.away');
		const kinds = (Array.isArray(s.events) ? s.events : []).filter((k) => KINDS.includes(k));
		if (!kinds.length) return '';
		return t('cameras.card.motion', { kinds: kinds.map((k) => t(`cameras.kinds.${k}`)).join(', ') });
	}

	/** A camera card (Kameras.dc "cam"): picture stamp, name, pills, description. */
	function cardView(c, t, now, locale) {
		const pills = [{ label: t('cameras.card.home'), cls: 'is-info' }];
		if (c.online) pills.push({ label: t('cameras.card.live'), cls: 'is-ok' });
		else pills.push({ label: t('cameras.card.offline'), cls: 'is-err' });
		if (c.online && c.state && c.state !== 'ok') pills.push({ label: t(`cameras.state.${c.state}`), cls: 'is-warn' });
		// plugin 1.7.0: resolution and sound ("2560×1440 · mit Ton")
		const res = Number.isSafeInteger(c.width) && Number.isSafeInteger(c.height) ? t('cameras.card.res', { w: c.width, h: c.height }) : null;
		const desc = [c.model, res, c.audio ? t('cameras.card.withSound') : null, recordText(c.settings, t), c.settings && c.settings.record !== 'never' && c.settings.retentionDays ? t('cameras.card.retention', { days: c.settings.retentionDays }) : null]
			.filter(Boolean).join(' · ');
		const when = ago(c.snapshotAt, now, t, locale);
		return {
			id: c.id,
			name: c.name,
			pills,
			desc,
			stamp: when ? `${c.name} · ${when}` : c.name,
			picture: c.snapshotUrl || null,
			offline: !c.online,
		};
	}

	/**
	 * The switch "Push bei Personen" (plugin 1.7.0) for camera c: { show, on } — only when the plugin knows the
	 * own push (myPush true/false) and the administrator lets the camera push at all.
	 */
	function myPushView(c) {
		const known = !!c && typeof c.myPush === 'boolean';
		return { show: known && c.push !== false, on: known ? c.myPush : true };
	}

	function onlineCount(cameras) {
		return (Array.isArray(cameras) ? cameras : []).filter((c) => c && c.online).length;
	}

	/** Which camera to show: the one asked for while the person still sees it, else the first online one. */
	function pickCamera(cameras, wanted) {
		const list = Array.isArray(cameras) ? cameras : [];
		if (wanted && list.some((c) => c.id === wanted)) return wanted;
		const on = list.find((c) => c.online);
		return on ? on.id : (list[0] ? list[0].id : null);
	}

	/**
	 * Overlay of the player: badge (● LIVE / Standbild · alle 10 s / Clip), quality
	 * (HD · über VPN, SD · im Heimnetz) and the stamp "Einfahrt · 16:52:31".
	 */
	function overlay({ live, camera, clip = null, pictureAt = null }, t, locale, now) {
		const name = camera ? camera.name : '';
		if (clip) {
			return {
				badge: { text: t('cameras.clips.playing', { kind: t(`cameras.kind.${KINDS.includes(clip.kind) ? clip.kind : 'motion'}`), time: timeOf(clip.startedAt, locale) }), cls: 'is-clip' },
				quality: null,
				stamp: t('cameras.stamp', { name, time: timeOf(clip.startedAt, locale, true) }),
			};
		}
		if (live && live.mode === 'live') {
			const q = camera && camera.settings && camera.settings.stream === 'sub' ? t('cameras.sd') : t('cameras.hd');
			const via = live.via === 'lan' ? t('cameras.viaLan') : t('cameras.viaVpn');
			return { badge: { text: `● ${t('cameras.live')}`, cls: 'is-live' }, quality: `${q} · ${via}`, stamp: t('cameras.stamp', { name, time: timeOf(now, locale, true) }) };
		}
		if (live && live.mode === 'snapshot') {
			return {
				badge: { text: t('cameras.stillEvery', { s: live.every || 10 }), cls: 'is-still' },
				quality: null,
				stamp: t('cameras.stamp', { name, time: timeOf(Number.isFinite(pictureAt) ? pictureAt : now, locale, true) }),
			};
		}
		return { badge: null, quality: null, stamp: name };
	}

	/** ms until the live answer must be asked for again (new tokens; the VPN may have come up). */
	function refreshIn(live, now) {
		if (!live) return SNAPSHOT_REFRESH_MS;
		if (live.mode === 'live') {
			if (!Number.isFinite(live.expiresAt)) return 4 * 60 * 1000;
			return Math.max(MIN_REFRESH_MS, live.expiresAt - now - 30 * 1000);
		}
		return SNAPSHOT_REFRESH_MS;
	}

	/** The still with a counter against caching (gccam://…/snapshot.jpg?t=<n>). */
	function stillSrc(url, n) {
		if (typeof url !== 'string' || !url) return '';
		return `${url.split('?')[0]}?t=${Math.max(0, Math.floor(n) || 0)}`;
	}

	/** Which address the <video> plays: the continuous fMP4 (Chromium has no HLS), else HLS when it can. */
	function videoSrc(live, canHls) {
		if (!live || live.mode !== 'live') return null;
		if (live.mp4) return live.mp4;
		return live.hls && canHls ? live.hls : null;
	}

	/** H.265 that Chromium cannot play → the hint of the mockup ("Unterstrom (H.264) wählen"). */
	function codecHint(live, t) {
		const c = live && typeof live.codec === 'string' ? live.codec : '';
		return /^(hev1|hvc1|h265|hevc)/i.test(c) ? t('cameras.codec', { codec: 'H.265' }) : t('cameras.codec', { codec: c || '?' });
	}

	/**
	 * The codecs parameter of a MIME type for canPlayType: RFC 6381 strings as the gateway reports them
	 * ("avc1.640028, mp4a.40.2"), the short names of the camera list (h264 / h265), else null (unknown).
	 */
	function codecParam(codec) {
		const c = typeof codec === 'string' ? codec.trim() : '';
		if (/^h\.?264$|^avc$/i.test(c)) return 'avc1.42E01E';
		if (/^h\.?265$|^hevc$/i.test(c)) return 'hvc1.1.6.L93.B0';
		return /^[a-z0-9]{4}(?:\.[A-Za-z0-9]+)*(?:, ?[a-z0-9]{4}(?:\.[A-Za-z0-9]+)*)*$/.test(c) ? c : null;
	}

	/** A row of "Clips heute": "Person · 0:24", "14:02 · Niemand zu Hause", pill. */
	function clipView(c, t, locale) {
		const pill = kindPill(c.kind, t);
		const dur = duration(c.ms);
		const title = dur ? t('cameras.clips.row', { kind: pill.label, duration: dur }) : pill.label;
		const sub = [timeOf(c.startedAt, locale), c.nobodyHome === true ? t('cameras.clips.nobodyHome') : null, c.clipUrl ? null : t('cameras.clips.noClip')].filter(Boolean).join(' · ');
		const extra = (Array.isArray(c.kinds) ? c.kinds : []).filter((k) => k !== c.kind && k !== 'motion' && KINDS.includes(k)).map((k) => kindPill(k, t));
		return {
			id: c.id,
			title,
			sub,
			pill,
			extra,
			thumb: c.thumbUrl || null,
			playable: !!c.clipUrl,
			label: t('cameras.clips.play', { time: timeOf(c.startedAt, locale) }),
		};
	}

	/** Text of a failed answer ({ ok: false, code }). */
	function errorText(res, t) {
		const code = res && typeof res.code === 'string' ? res.code : 'failed';
		if (ERROR_CODES.includes(code)) return t(`cameras.error.${code}`);
		if (/^http_5\d\d$/.test(code)) return t('cameras.error.network');
		return t('cameras.error.failed');
	}

	/** Why the page is empty (status of the core service). */
	function unavailableText(status, t) {
		const s = status || {};
		if (s.reason === 'needs_gatecontrol') return t('cameras.unavailable.needs_gatecontrol', { version: s.minGatecontrol || '1.240.0' });
		if (s.reason === 'unsupported') return t('cameras.unavailable.unsupported');
		return t('cameras.empty');
	}

	/**
	 * A camera push in the inbox (topic `kamera`, data.door.type `home_camera_event`)
	 * → { cameraId, eventId } or null (Ring, locks: the inbox as before).
	 */
	function entryContext(entry) {
		if (!entry || typeof entry !== 'object') return null;
		const data = entry.data && typeof entry.data === 'object' ? entry.data : {};
		const door = data.door && typeof data.door === 'object' ? data.door : {};
		if (door.type !== PUSH_TYPE || (entry.topic && entry.topic !== TOPIC) || !isCameraId(door.cameraId)) return null;
		return { cameraId: door.cameraId, eventId: typeof door.eventId === 'string' && EVENT_ID_RE.test(door.eventId) ? door.eventId : null };
	}

	/** A push context (toast click, inbox) → { cameraId, eventId } for the page, else null. */
	function pushTarget(ctx) {
		if (!ctx || typeof ctx !== 'object' || !isCameraId(ctx.cameraId)) return null;
		return { cameraId: ctx.cameraId, eventId: typeof ctx.eventId === 'string' && EVENT_ID_RE.test(ctx.eventId) ? ctx.eventId : null };
	}

	return {
		APP_ROUTE,
		TOPIC,
		KINDS,
		CARD_EVERY_MS,
		SNAPSHOT_REFRESH_MS,
		isCameraId,
		timeOf,
		ago,
		duration,
		kindPill,
		recordText,
		cardView,
		myPushView,
		onlineCount,
		pickCamera,
		overlay,
		refreshIn,
		stillSrc,
		videoSrc,
		codecHint,
		codecParam,
		clipView,
		errorText,
		unavailableText,
		entryContext,
		pushTarget,
	};
});
