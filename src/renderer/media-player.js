/**
 * GateControl -- Medien player (renderer, Stufe 4g, mockup 9)
 *
 * Plays a film or an episode in the app's window with its own controls in the GateControl style (not Chromium's bar):
 * the HTML5 video of the page, hls.js (vendor/hls) for Jellyfin's converted streams (HLS in fMP4; Chromium has no HLS),
 * all bytes through gcmedia:// (no access in the page). On top the title and the info line ("Unterwegs · 18 Mbit/s ·
 * NAS rechnet um: 1080p · 8 Mbit/s · Ton AAC 5.1"); on the right the panel with sound, subtitles (text as WebVTT,
 * a picture is burnt in by the NAS) and quality; below the seek bar, ±10 s, play / pause, the time, the volume,
 * subtitles, picture-in-picture and full screen, "Nächste Folge". Keys: Leertaste, ← →, F, U, T, M, Esc (full screen
 * first, then back). The sidebar is covered while it plays.
 *
 * What it tells the core: media.setCaps once (canPlayType / MediaCapabilities / matchMedia), the progress (start,
 * every 10 s, on pause and seek, stop — Jellyfin's "Weiterschauen" on every device), and Windows stays awake while it
 * plays (media-player:awake; free one minute after a pause, main/media-awake.js). HEVC without the Windows decoder
 * gives sound without picture (videoWidth 0): the player asks Jellyfin again with H.264, once per title.
 *
 * A file of a NAS share (Stufe 4h) plays as it is (no converting, no tracks to choose): before it starts the core's
 * check says what Chromium cannot (DTS / AC3 sound, HEVC without the decoder, avi …) — then the player says so and
 * offers "In VLC öffnen" (VLC installed) or "In anderer App öffnen" (Windows' app, SMB), and "Trotzdem abspielen".
 *
 * "Auf TV/PC abspielen": a title the phone sent (req.cast, media-cast-remote.js) plays here the same way; the top line
 * says "Vom Handy gesteuert · <Handy>", every change goes to `o.onChange` and the phone's keys come in through `remote`.
 *
 * Built by renderer.js (GCMediaPlayer.mount); pure logic in media-player-state.js and media-state.js; texts
 * media.player.* of the Pro locales. Server text only into textContent; icons from static path data.
 */
(function (root) {
	'use strict';

	const PS = root.GCMediaPlayerState;
	const MS = root.GCMediaState;
	const NS = 'http://www.w3.org/2000/svg';
	const ICONS = {
		back: 'M15 6l-6 6 6 6',
		play: 'M8 5v14l11-7z',
		pause: 'M7 5h3.5v14H7z|M13.5 5H17v14h-3.5z',
		rew: 'M3 12a9 9 0 1 0 3-6.7|M3 4v5h5',
		ffw: 'M21 12a9 9 0 1 1-3-6.7|M21 4v5h-5',
		cc: 'M5 5h14a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2z|M10.5 10.2a2.2 2.2 0 1 0 0 3.6M17 10.2a2.2 2.2 0 1 0 0 3.6',
		audio: 'M4 10v4h4l5 4V6l-5 4z|M16 9a4 4 0 0 1 0 6M18.5 6.5a8 8 0 0 1 0 11',
		mute: 'M4 10v4h4l5 4V6l-5 4z|M17 9l5 6M22 9l-5 6',
		pip: 'M5 5h14a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2z|M13 12h6v5h-6z',
		full: 'M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5',
		shrink: 'M9 4v5H4M15 4v5h5M9 20v-5H4M15 20v-5h5',
		next: 'M6 5l9 7-9 7z|M18 5v14',
		sliders: 'M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1|M15 4a2 2 0 1 0 0 4a2 2 0 1 0 0-4|M9 10a2 2 0 1 0 0 4a2 2 0 1 0 0-4|M17 16a2 2 0 1 0 0 4a2 2 0 1 0 0-4',
		check: 'M5 12l5 5 9-10',
		alert: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 8v5M12 16h.01',
		x: 'M18 6L6 18M6 6l12 12',
		phone: 'M8 3h8a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z|M11 18h2',
	};

	function icon(name, size = 18, fill = false) {
		const s = document.createElementNS(NS, 'svg');
		s.setAttribute('viewBox', '0 0 24 24');
		s.setAttribute('width', String(size));
		s.setAttribute('height', String(size));
		s.setAttribute('fill', fill ? 'currentColor' : 'none');
		s.setAttribute('stroke', 'currentColor');
		s.setAttribute('stroke-width', '2');
		s.setAttribute('stroke-linecap', 'round');
		s.setAttribute('stroke-linejoin', 'round');
		s.setAttribute('aria-hidden', 'true');
		for (const d of String(ICONS[name] || ICONS.alert).split('|')) {
			const p = document.createElementNS(NS, 'path');
			p.setAttribute('d', d);
			s.appendChild(p);
		}
		return s;
	}

	function el(tag, attrs, kids) {
		const n = document.createElement(tag);
		for (const [k, v] of Object.entries(attrs || {})) {
			if (v === null || v === undefined || v === false) continue;
			if (k === 'text') n.textContent = String(v);
			else if (k === 'class') n.className = v;
			else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
			else n.setAttribute(k, v === true ? '' : String(v));
		}
		for (const c of kids || []) if (c !== null && c !== undefined && c !== false && c !== '') n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
		return n;
	}
	const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };
	const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed', error: err && err.message });

	/** What Chromium plays here (asked once per app run) → media.setCaps. */
	async function probeCaps(video) {
		const canPlay = {};
		for (const [k, p] of Object.entries(PS.PROBES)) {
			try { canPlay[k] = video.canPlayType(p.type) || ''; } catch { canPlay[k] = ''; }
		}
		const decoding = {};
		const mc = root.navigator && root.navigator.mediaCapabilities;
		if (mc && typeof mc.decodingInfo === 'function') {
			for (const k of ['hevc', 'av1']) {
				try { decoding[k] = await mc.decodingInfo(PS.PROBES[k].config); } catch { /* no answer: canPlayType */ }
			}
		}
		let hdr = false;
		try { hdr = !!(root.matchMedia && root.matchMedia('(dynamic-range: high)').matches); } catch { hdr = false; }
		return PS.capsFrom({ canPlay, decoding, hdr });
	}

	function mount(o) {
		const api = o.api;
		const t = o.t;
		const lang = () => (typeof o.getLocale === 'function' ? o.getLocale() : 'de');
		const toast = typeof o.toast === 'function' ? o.toast : () => {};
		const awake = (state) => { if (typeof o.awake === 'function') Promise.resolve(o.awake(state)).catch(() => {}); };
		// "Auf TV/PC abspielen": every change of the playback (media-cast-remote.js decides what goes to the phone)
		const changed = (why) => { if (typeof o.onChange === 'function') { try { o.onChange(why); } catch { /* the remote is gone */ } } };
		const now = () => Date.now();
		const storage = (() => { try { return root.localStorage || null; } catch { return null; } })();

		const P = {
			open: false,
			req: null,          // what was asked: { item, detail, startMs, audioIndex, subtitleIndex, next, onEnd }
			detail: null,       // media:detail of the title (the tracks)
			play: null,         // media:play's answer now
			hls: null,
			started: false,     // 'start' reported for this play
			lastReport: NaN,
			seq: 0,
			retried: new Set(), // titles asked again with H.264
			caps: null,
			panel: false,
			ended: null,        // { at, next } while "Nächste Folge" counts down
			error: null,
			loading: false,
			awakeAt: 0,
			ext: null,          // media:external:info (VLC there?), asked once per app run
			hint: null,         // a share's file waits for "Trotzdem abspielen": { r, startMs }
			waiting: false,     // the video waits for data ('waiting' until 'playing' / 'canplay')
		};
		let hideTimer = null;
		let countdownTimer = null;

		// ── Skeleton ─────────────────────────────────────────
		const R = {};
		R.video = el('video', { class: 'mp-video', playsinline: true, preload: 'auto' });
		R.shade = el('div', { class: 'mp-shade' });
		R.title = el('b', { class: 'mp-title' });
		R.sub = el('span', { class: 'mp-sub' });
		R.info = el('span', { class: 'mp-info' });
		R.cast = el('span', { class: 'mp-cast', hidden: true }, [icon('phone', 14), el('span')]);
		R.back = el('button', { type: 'button', class: 'mp-ib mp-back', on: { click: () => close() } }, [icon('back', 20)]);
		R.panelBtn = el('button', { type: 'button', class: 'mp-ib mp-panel-btn', on: { click: () => togglePanel() } }, [icon('sliders', 18)]);
		R.top = el('div', { class: 'mp-top' }, [R.back, el('div', { class: 'mp-tt' }, [R.title, el('div', { class: 'mp-line' }, [R.sub, R.info, R.cast])]), el('span', { class: 'mp-grow' }), R.panelBtn]);
		R.panel = el('div', { class: 'mp-panel', role: 'dialog', hidden: true });
		R.keys = el('div', { class: 'mp-keys' });
		R.center = el('div', { class: 'mp-center', role: 'status', 'aria-live': 'polite', hidden: true });
		R.nextBox = el('div', { class: 'mp-nextbox', hidden: true });
		R.buffered = el('i');
		R.played = el('span');
		R.thumb = el('b');
		R.hoverTime = el('em', { hidden: true });
		R.bar = el('div', { class: 'mp-bar', role: 'slider', tabindex: '0', 'aria-valuemin': '0' }, [R.buffered, R.played, R.thumb, R.hoverTime]);
		R.playBtn = el('button', { type: 'button', class: 'mp-rb mp-main', on: { click: () => toggle() } });
		R.rew = el('button', { type: 'button', class: 'mp-rb mp-rew', on: { click: () => seekBy(-PS.SEEK_S) } }, [icon('rew', 20)]);
		R.ffw = el('button', { type: 'button', class: 'mp-rb mp-ffw', on: { click: () => seekBy(PS.SEEK_S) } }, [icon('ffw', 20)]);
		R.time = el('span', { class: 'mp-time' });
		R.muteBtn = el('button', { type: 'button', class: 'mp-rb mp-mute', on: { click: () => mute() } });
		R.vol = el('input', { type: 'range', class: 'mp-vol', min: '0', max: '1', step: '0.05' });
		R.vol.addEventListener('input', () => { R.video.volume = Number(R.vol.value); R.video.muted = Number(R.vol.value) === 0; saveVolume(); renderControls(); });
		R.ccBtn = el('button', { type: 'button', class: 'mp-rb mp-cc', on: { click: () => togglePanel() } }, [icon('cc', 20)]);
		R.pipBtn = el('button', { type: 'button', class: 'mp-rb mp-pip', on: { click: () => pip() } }, [icon('pip', 20)]);
		R.fullBtn = el('button', { type: 'button', class: 'mp-rb mp-full', on: { click: () => fullscreen() } });
		R.nextBtn = el('button', { type: 'button', class: 'mp-rb mp-next', hidden: true, on: { click: () => playNext() } }, [icon('next', 18, true), el('span')]);
		R.ctl = el('div', { class: 'mp-ctl' }, [
			R.bar,
			el('div', { class: 'mp-row' }, [R.rew, R.playBtn, R.ffw, R.time, el('span', { class: 'mp-grow' }), R.nextBtn, R.muteBtn, R.vol, R.ccBtn, R.pipBtn, R.fullBtn]),
		]);
		R.root = el('div', { class: 'mp', hidden: true, role: 'region', tabindex: '-1' }, [R.video, R.shade, R.center, R.top, R.panel, R.nextBox, R.keys, R.ctl]);
		(o.host || document.body).appendChild(R.root);

		// ── Volume ───────────────────────────────────────────
		const vol = PS.volumeOf(storage ? (() => { try { return storage.getItem(PS.VOLUME_KEY); } catch { return null; } })() : null);
		R.video.volume = vol.volume;
		R.video.muted = vol.muted;
		function saveVolume() {
			try { if (storage) storage.setItem(PS.VOLUME_KEY, JSON.stringify({ volume: R.video.volume, muted: R.video.muted })); } catch { /* storage unavailable */ }
		}

		// ── Labels ───────────────────────────────────────────
		function relabel() {
			R.back.title = t('media.player.close');
			R.back.setAttribute('aria-label', t('media.player.close'));
			R.panelBtn.title = t('media.player.panel');
			R.panelBtn.setAttribute('aria-label', t('media.player.panel'));
			R.root.setAttribute('aria-label', t('media.player.label'));
			R.panel.setAttribute('aria-label', t('media.player.panel'));
			R.bar.setAttribute('aria-label', t('media.player.seek'));
			R.rew.title = t('media.player.rew'); R.rew.setAttribute('aria-label', t('media.player.rew'));
			R.ffw.title = t('media.player.ffw'); R.ffw.setAttribute('aria-label', t('media.player.ffw'));
			R.ccBtn.title = t('media.player.subtitlesKey'); R.ccBtn.setAttribute('aria-label', t('media.player.panel'));
			R.pipBtn.title = t('media.player.pip'); R.pipBtn.setAttribute('aria-label', t('media.player.pip'));
			R.vol.setAttribute('aria-label', t('media.player.volume'));
			R.nextBtn.lastChild.textContent = t('media.player.next');
			clear(R.keys);
			const k = (keys, label) => el('span', {}, [...keys.map((x) => el('kbd', { text: x })), label]);
			R.keys.append(k([t('media.player.key.space')], t('media.player.key.pause')), k(['←', '→'], t('media.player.key.seek')),
				k(['F'], t('media.player.key.full')), k(['U'], t('media.player.key.sub')), k(['T'], t('media.player.key.audio')), k(['Esc'], t('media.player.key.back')));
			renderControls();
			renderPanel();
			renderInfo();
		}

		function renderControls() {
			const v = R.video;
			const playing = !v.paused && !v.ended;
			clear(R.playBtn).appendChild(icon(playing ? 'pause' : 'play', 22, true));
			R.playBtn.setAttribute('aria-label', playing ? t('media.player.pause') : t('media.player.play'));
			R.playBtn.title = `${playing ? t('media.player.pause') : t('media.player.play')} (${t('media.player.key.space')})`;
			clear(R.muteBtn).appendChild(icon(v.muted || v.volume === 0 ? 'mute' : 'audio', 20));
			R.muteBtn.setAttribute('aria-label', v.muted ? t('media.player.unmute') : t('media.player.mute'));
			R.muteBtn.title = R.muteBtn.getAttribute('aria-label');
			R.vol.value = String(v.muted ? 0 : v.volume);
			const fs = document.fullscreenElement === R.root;
			clear(R.fullBtn).appendChild(icon(fs ? 'shrink' : 'full', 20));
			R.fullBtn.title = `${fs ? t('media.player.exitFull') : t('media.player.full')} (F)`;
			R.fullBtn.setAttribute('aria-label', fs ? t('media.player.exitFull') : t('media.player.full'));
			R.pipBtn.hidden = !document.pictureInPictureEnabled;
			const next = nextOf();
			R.nextBtn.hidden = !next;
			renderTime();
		}

		function duration() {
			const d = R.video.duration;
			if (Number.isFinite(d) && d > 0) return d;
			const rt = P.req && P.req.item && P.req.item.runtimeMs;
			return rt > 0 ? rt / 1000 : 0;
		}

		function renderTime() {
			const v = R.video;
			const d = duration();
			R.time.textContent = PS.timeLabel(v.currentTime, d, null);
			const pct = d > 0 ? Math.min(100, (v.currentTime / d) * 100) : 0;
			R.played.style.width = `${pct}%`;
			R.thumb.style.left = `${pct}%`;
			let buf = 0;
			try { if (v.buffered.length) buf = v.buffered.end(v.buffered.length - 1); } catch { buf = 0; }
			R.buffered.style.width = d > 0 ? `${Math.min(100, (buf / d) * 100)}%` : '0%';
			R.bar.setAttribute('aria-valuemax', String(Math.round(d)));
			R.bar.setAttribute('aria-valuenow', String(Math.round(v.currentTime)));
			R.bar.setAttribute('aria-valuetext', PS.timeLabel(v.currentTime, d, null));
		}

		// ── Info line, panel ─────────────────────────────────

		function version() { return P.detail && P.detail.versions ? P.detail.versions[0] : null; }

		function audioTarget() {
			const v = version();
			const a = v && v.audio ? v.audio.find((x) => P.play && x.index === P.play.audioIndex) : null;
			return a && MS.audioFate(a, P.caps || {}) === 'converted' ? MS.targetAudio(a, P.caps || {}) : null;
		}

		function renderInfo() {
			const it = P.req && P.req.item;
			const tt = PS.titleOf(it, t);
			R.title.textContent = tt.title;
			const srcName = it && typeof o.sourceName === 'function' ? o.sourceName(it.sourceId) : '';
			R.sub.textContent = [tt.sub, srcName].filter(Boolean).join(' · ');
			const info = P.play ? PS.infoLine(P.play, audioTarget(), t, lang()) : null;
			if (info && P.play.via) info.text = [info.text, P.play.via === 'webdav' ? 'WebDAV' : 'SMB'].filter(Boolean).join(' · ');
			R.info.hidden = !info || !info.text;
			R.info.textContent = info ? info.text : '';
			R.info.className = `mp-info${info && info.converted ? ' is-conv' : ''}${info && info.way === 'home' ? ' is-home' : ''}`;
			const cast = P.req && P.req.cast;
			R.cast.hidden = !cast;
			R.cast.lastChild.textContent = cast ? (cast.controllerName ? t('media.player.castBy', { name: cast.controllerName }) : t('media.player.cast')) : '';
		}

		function renderPanel() {
			clear(R.panel);
			R.panel.hidden = !P.panel;
			R.root.classList.toggle('has-panel', P.panel);
			const v = version();
			const caps = P.caps || {};
			const opt = (label, note, on, click, cls) => el('button', { type: 'button', class: `mp-opt${on ? ' is-on' : ''} ${cls || ''}`, 'aria-pressed': on ? 'true' : 'false', on: { click } }, [
				el('span', { class: 'mp-opt-tx' }, [el('span', { class: 'mp-opt-t', text: label }), note ? el('span', { class: 'mp-opt-v', text: note }) : null]),
				on ? icon('check', 16) : null,
			]);
			if (isShare()) {
				const note = P.play ? MS.checkNote(P.play.check, t) : null;
				R.panel.appendChild(el('h3', { class: 'mp-h', text: t('media.folders.fileTitle') }));
				R.panel.appendChild(el('div', { class: 'mp-none', text: t('media.folders.originalHint') }));
				if (note) R.panel.appendChild(el('div', { class: `mp-none mp-check is-${note.level}`, text: note.text }));
				return;
			}
			R.panel.appendChild(el('h3', { class: 'mp-h', text: t('media.detail.audio') }));
			const aOpts = v ? MS.audioOptions(v, caps, t) : [];
			if (!aOpts.length) R.panel.appendChild(el('div', { class: 'mp-none', text: t('media.player.noTracks') }));
			for (const a of aOpts) R.panel.appendChild(opt(a.label, a.note, P.play && P.play.audioIndex === a.value, () => switchTo({ audioIndex: a.value }), 'mp-opt-audio'));
			R.panel.appendChild(el('h3', { class: 'mp-h', text: t('media.detail.subtitles') }));
			const cur = P.play && Number.isInteger(P.play.subtitleIndex) ? P.play.subtitleIndex : -1;
			for (const s of v ? MS.subtitleOptions(v, t) : [{ value: -1, label: t('media.sub.off'), note: '' }]) {
				R.panel.appendChild(opt(s.label, s.note, cur === s.value, () => switchTo({ subtitleIndex: s.value }), 'mp-opt-sub'));
			}
			R.panel.appendChild(el('h3', { class: 'mp-h', text: t('media.detail.quality') }));
			const q = o.quality ? o.quality() : 'auto';
			for (const x of MS.qualityOptions(t, lang())) {
				let note = '';
				if (x.value === 'auto' && q === 'auto' && P.play) note = P.play.converted && P.play.bitrate ? t('media.player.autoNow', { what: `${PS.resolution(P.play.bitrate)} · ${PS.bandwidth(P.play.bitrate, lang())}` }) : t('media.player.autoOriginal');
				R.panel.appendChild(opt(x.label, note, q === x.value, () => switchQuality(x.value), 'mp-opt-quality'));
			}
		}

		function togglePanel(force) {
			P.panel = typeof force === 'boolean' ? force : !P.panel;
			renderPanel();
			showControls();
		}

		// ── Controls show / hide ─────────────────────────────

		function showControls() {
			R.root.classList.remove('is-idle');
			clearTimeout(hideTimer);
			hideTimer = setTimeout(() => {
				if (P.open && !R.video.paused && !P.panel && !P.ended && !R.ctl.matches(':hover')) R.root.classList.add('is-idle');
			}, PS.HIDE_MS);
		}

		// ── Playing ──────────────────────────────────────────

		/** Opens the player for `req`: { item, detail?, startMs, audioIndex?, subtitleIndex?, next?, onEnd? }. */
		async function play(req) {
			if (!req || !req.item) return;
			if (P.open) {
				const before = P.req;
				const end = ending();
				await stop('switch');
				// another title instead of the phone's: its remote ends
				if (before && before.cast && before.cast !== req.cast && typeof before.onEnd === 'function') before.onEnd({ ...end, why: 'switch' });
			}
			P.open = true;
			P.req = req;
			P.detail = req.detail || null;
			P.play = null;
			P.ended = null;
			P.error = null;
			P.waiting = false;
			clearInterval(countdownTimer);
			R.nextBox.hidden = true;
			R.root.hidden = false;
			document.body.classList.add('mp-open');
			document.addEventListener('keydown', onKey, true);
			relabel();
			R.root.focus();
			showControls();
			if (!P.caps) {
				P.caps = await probeCaps(R.video).catch(() => null);
				if (P.caps) {
					try { const r = await api.setCaps(P.caps); if (r && r.caps) P.caps = r.caps; } catch { /* the core keeps its default */ }
				}
			}
			if (!P.detail) {
				try { const d = await api.detail(req.item.sourceId, req.item.id); if (d && d.ok) P.detail = d; } catch { /* the panel stays short */ }
			}
			await start({ startMs: req.startMs || 0, audioIndex: req.audioIndex, subtitleIndex: req.subtitleIndex });
		}

		async function start({ startMs, audioIndex, subtitleIndex, quality }) {
			const seq = ++P.seq;
			const it = P.req.item;
			P.loading = true;
			P.error = null;
			setCenter(t('media.player.loading'), 'loading');
			let r;
			try {
				r = await api.play(it.sourceId, it.id, {
					startMs: Math.max(0, Math.floor(startMs || 0)),
					audioIndex: Number.isInteger(audioIndex) ? audioIndex : undefined,
					subtitleIndex: Number.isInteger(subtitleIndex) ? subtitleIndex : undefined,
					seriesId: it.seriesId || undefined,
					quality: quality || undefined,
					originalBps: version() && version().bitrate ? version().bitrate : undefined,
				});
			} catch (err) { r = fail(err); }
			if (seq !== P.seq || !P.open) { if (r && r.ok) api.report(r.playId, 'stop', { positionMs: 0 }).catch(() => {}); return; }
			P.loading = false;
			if (!r || !r.ok) { showError(r && r.code); return; }
			P.play = r;
			P.started = false;
			P.lastReport = NaN;
			const note = isShare() ? MS.checkNote(r.check, t) : null;
			if (note && note.external && !P.req.anyway && !P.req.cast) {
				P.hint = { r, startMs: startMs || 0 };
				renderInfo();
				renderPanel();
				await showHint(note);
				return;
			}
			attach(r, startMs || 0);
			renderInfo();
			renderPanel();
			renderControls();
			changed('start');
		}

		function isShare() { return !!(P.req && P.req.item && P.req.item.fromShare === true); }

		async function externalInfo() {
			if (P.ext) return P.ext;
			try { const r = await api.externalInfo(); P.ext = r && r.ok ? r : { vlc: false, openPath: false }; } catch { P.ext = { vlc: false, openPath: false }; }
			return P.ext;
		}

		/** Another app for this file: VLC (loopback, SMB and WebDAV) or Windows' app (SMB) — the player closes. */
		async function openExternal(app) {
			const it = P.req && P.req.item;
			if (!it) return;
			let r;
			try { r = await api.shareExternal(it.sourceId, it.id, app, PS.titleOf(it, t).title); } catch (err) { r = fail(err); }
			if (r && r.ok) {
				toast(app === 'vlc' ? t('media.check.openedVlc') : t('media.check.openedOther'), 'info');
				close();
			} else toast(MS.errorText(r && r.code, t), 'error');
		}

		/** The buttons of another app, as far as there is one for this file. */
		async function externalButtons() {
			const info = await externalInfo();
			const via = P.play ? P.play.via : null;
			const app = MS.externalApp(info, via);
			if (!app) return [el('div', { class: 'mp-hint-no', text: t('media.check.noApp') })];
			return [el('button', { type: 'button', class: 'btn btn-pri btn-sm mp-ext', 'data-app': app, on: { click: () => openExternal(app) } }, [
				el('span', { text: app === 'vlc' ? t('media.check.vlc') : t('media.check.other') }),
			])];
		}

		/** "Ton DTS: am PC kein Ton" with "In VLC öffnen" / "In anderer App öffnen" and "Trotzdem abspielen". */
		async function showHint(note) {
			setCenter(note.text, 'hint');
			const seq = P.seq;
			const btns = await externalButtons();
			if (seq !== P.seq || !P.hint) return;
			R.center.appendChild(el('div', { class: 'mp-hint-b' }, [
				...btns,
				el('button', { type: 'button', class: 'btn btn-sec btn-sm mp-anyway', text: t('media.check.anyway'), on: { click: () => playAnyway() } }),
				el('button', { type: 'button', class: 'btn btn-ghost btn-sm mp-hint-back', text: t('media.check.back'), on: { click: () => close() } }),
			]));
			const first = R.center.querySelector('button');
			if (first) first.focus();
		}

		function playAnyway() {
			const h = P.hint;
			if (!h) return;
			P.hint = null;
			P.req.anyway = true;
			setCenter(t('media.player.loading'), 'loading');
			attach(h.r, h.startMs);
			renderControls();
		}

		function attach(r, startMs) {
			const v = R.video;
			detachSource();
			for (const tr of [...v.querySelectorAll('track')]) tr.remove();
			for (const s of r.subtitles || []) {
				if (s.mime && s.mime !== 'text/vtt') continue;
				const track = el('track', { kind: 'subtitles', src: s.url, srclang: s.language || 'und', label: s.label || s.language || 'Untertitel', default: true });
				v.appendChild(track);
				track.addEventListener('load', () => { try { track.track.mode = 'showing'; } catch { /* gone */ } });
			}
			const startSec = Math.max(0, startMs / 1000);
			if (r.hls) {
				const Hls = root.Hls;
				if (Hls && Hls.isSupported()) {
					const h = new Hls({ enableWorker: false, startPosition: startSec > 0 ? startSec : -1, maxBufferLength: 30, backBufferLength: 60 });
					P.hls = h;
					h.on(Hls.Events.ERROR, (_e, data) => {
						if (!data || !data.fatal || P.hls !== h) return;
						if (data.type === Hls.ErrorTypes.MEDIA_ERROR) { try { h.recoverMediaError(); return; } catch { /* below */ } }
						showError('stream');
					});
					h.loadSource(r.url);
					h.attachMedia(v);
				} else {
					v.src = r.url;
				}
			} else {
				v.src = r.url;
				if (startSec > 0) v.addEventListener('loadedmetadata', () => { try { v.currentTime = startSec; } catch { /* stays at 0 */ } }, { once: true });
			}
			const p = v.play();
			if (p && typeof p.catch === 'function') p.catch(() => {});
		}

		function detachSource() {
			const v = R.video;
			if (P.hls) { try { P.hls.destroy(); } catch { /* gone */ } P.hls = null; }
			v.removeAttribute('src');
			try { v.load(); } catch { /* nothing loaded */ }
		}

		function setCenter(text, kind) {
			clear(R.center);
			R.center.hidden = !text;
			R.center.className = `mp-center${kind ? ` is-${kind}` : ''}`;
			if (!text) return;
			if (kind === 'loading') R.center.appendChild(el('span', { class: 'mp-spin' }));
			if (kind === 'error' || kind === 'hint') R.center.appendChild(icon('alert', 28));
			R.center.appendChild(el('span', { class: 'mp-center-tx', text }));
		}

		function showError(code) {
			P.error = code || 'failed';
			const msg = code === 'stream' || code === 'media' ? t('media.player.streamError') : MS.errorText(code, t);
			setCenter(msg, 'error');
			R.center.appendChild(el('button', { type: 'button', class: 'btn btn-sec btn-sm mp-retry', text: t('media.player.retry'), on: { click: () => restartHere() } }));
			changed('error');
			if (isShare() && P.play) {
				const seq = P.seq;
				externalButtons().then((btns) => { if (seq === P.seq && P.error) R.center.appendChild(el('div', { class: 'mp-hint-b' }, btns)); });
			}
			awake('paused');
		}

		function position() {
			const v = R.video;
			return Number.isFinite(v.currentTime) ? v.currentTime * 1000 : 0;
		}

		function report(event) {
			if (!P.play) return Promise.resolve();
			P.lastReport = now();
			const d = duration();
			return api.report(P.play.playId, event, { positionMs: Math.floor(position()), paused: R.video.paused, durationMs: d > 0 ? Math.floor(d * 1000) : undefined }).catch(() => {});
		}

		/** Another sound / subtitle / quality, or H.264 after a missing picture: ask again at the same place. */
		async function switchTo(change) {
			if (!P.play) return;
			const pos = position();
			const audioIndex = change.audioIndex !== undefined ? change.audioIndex : P.play.audioIndex;
			const subtitleIndex = change.subtitleIndex !== undefined ? change.subtitleIndex : (Number.isInteger(P.play.subtitleIndex) ? P.play.subtitleIndex : -1);
			if (audioIndex === P.play.audioIndex && subtitleIndex === (Number.isInteger(P.play.subtitleIndex) ? P.play.subtitleIndex : -1) && !change.force) return;
			await report('stop');
			P.play = null;
			await start({ startMs: pos, audioIndex, subtitleIndex });
		}

		async function switchQuality(q) {
			if (typeof o.setQuality === 'function') await o.setQuality(q);
			await switchTo({ force: true });
		}

		function restartHere() {
			const pos = P.play ? position() : (P.req ? P.req.startMs || 0 : 0);
			const a = P.play ? P.play.audioIndex : P.req.audioIndex;
			const s = P.play ? P.play.subtitleIndex : P.req.subtitleIndex;
			if (P.play) report('stop');
			P.play = null;
			start({ startMs: pos, audioIndex: a, subtitleIndex: s });
		}

		function toggle() {
			const v = R.video;
			if (P.ended) return;
			if (v.paused) { const p = v.play(); if (p && p.catch) p.catch(() => {}); } else v.pause();
		}

		function seekBy(sec) {
			const v = R.video;
			v.currentTime = PS.seekTarget(v.currentTime, sec, duration());
			showControls();
		}

		function mute() {
			R.video.muted = !R.video.muted;
			if (!R.video.muted && R.video.volume === 0) R.video.volume = 0.5;
			saveVolume();
			renderControls();
		}

		function fullscreen() {
			if (document.fullscreenElement) { document.exitFullscreen().catch(() => {}); return; }
			if (R.root.requestFullscreen) R.root.requestFullscreen().catch(() => {});
		}

		function pip() {
			if (document.pictureInPictureElement) { document.exitPictureInPicture().catch(() => {}); return; }
			if (R.video.requestPictureInPicture) R.video.requestPictureInPicture().catch(() => toast(t('media.player.pipFailed'), 'info'));
		}

		function cycle(kind) {
			const v = version();
			if (!v || !P.play) return;
			if (kind === 'audio') {
				const vals = MS.audioOptions(v, P.caps || {}, t).map((x) => x.value);
				const n = PS.nextOption(vals, P.play.audioIndex);
				if (n !== null && n !== P.play.audioIndex) { toast(t('media.player.audioTo', { label: MS.audioOptions(v, P.caps || {}, t).find((x) => x.value === n).label }), 'info'); switchTo({ audioIndex: n }); }
			} else {
				const opts = MS.subtitleOptions(v, t);
				const cur = Number.isInteger(P.play.subtitleIndex) ? P.play.subtitleIndex : -1;
				const n = PS.nextOption(opts.map((x) => x.value), cur);
				if (n !== null && n !== cur) { toast(t('media.player.subtitleTo', { label: opts.find((x) => x.value === n).label }), 'info'); switchTo({ subtitleIndex: n }); }
			}
		}

		function onKey(e) {
			if (!P.open) return;
			if (document.querySelector('.md-scrim')) return;
			const a = PS.keyAction({ key: e.key, ctrlKey: e.ctrlKey, altKey: e.altKey, metaKey: e.metaKey, targetTag: e.target && e.target.tagName });
			if (!a) return;
			// a focused button takes Space / Enter itself
			if (a === 'toggle' && e.key === ' ' && e.target && e.target.tagName === 'BUTTON' && e.target !== R.playBtn) return;
			e.preventDefault();
			e.stopPropagation();
			showControls();
			switch (a) {
				case 'toggle': toggle(); break;
				case 'back': seekBy(-PS.SEEK_S); break;
				case 'forward': seekBy(PS.SEEK_S); break;
				case 'volumeUp': R.video.muted = false; R.video.volume = Math.min(1, R.video.volume + 0.05); saveVolume(); renderControls(); break;
				case 'volumeDown': R.video.volume = Math.max(0, R.video.volume - 0.05); saveVolume(); renderControls(); break;
				case 'fullscreen': fullscreen(); break;
				case 'subtitles': cycle('subtitle'); break;
				case 'audio': cycle('audio'); break;
				case 'mute': mute(); break;
				case 'escape':
					if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
					else if (P.panel) togglePanel(false);
					else close();
					break;
				default: break;
			}
		}

		// ── The next episode ─────────────────────────────────

		function nextOf() { return P.req && typeof P.req.next === 'function' ? P.req.next(P.req.item) : null; }

		function playNext() {
			const n = nextOf();
			if (!n) return;
			clearInterval(countdownTimer);
			const req = { ...P.req, item: n, detail: null, startMs: n.played ? 0 : n.positionMs || 0, audioIndex: undefined, subtitleIndex: undefined, anyway: false };
			play(req);
		}

		function onEnded() {
			report('stop');
			const played = P.play;
			P.play = null;
			if (played) api.endStream(played.playId).catch(() => {});
			awake('paused');
			const n = nextOf();
			if (!n) { close('ended'); return; }
			P.ended = { at: now(), next: n };
			const draw = () => {
				const left = PS.countdown(P.ended.at, now());
				clear(R.nextBox);
				R.nextBox.hidden = false;
				const tt = PS.titleOf(n, t);
				R.nextBox.append(
					el('div', { class: 'mp-next-k', text: t('media.player.nextIn', { s: left }) }),
					el('div', { class: 'mp-next-t', text: [tt.sub].filter(Boolean).join('') || tt.title }),
					el('div', { class: 'mp-next-b' }, [
						el('button', { type: 'button', class: 'btn btn-pri btn-sm mp-next-now', on: { click: () => playNext() } }, [icon('play', 14, true), el('span', { text: t('media.player.nextNow') })]),
						el('button', { type: 'button', class: 'btn btn-sec btn-sm mp-next-cancel', text: t('media.player.nextCancel'), on: { click: () => { clearInterval(countdownTimer); close(); } } }),
					]),
				);
				if (left <= 0) playNext();
			};
			draw();
			countdownTimer = setInterval(() => { if (P.ended) draw(); }, 1000);
		}

		// ── Video events ─────────────────────────────────────

		const v = R.video;
		v.addEventListener('playing', () => {
			P.waiting = false;
			setCenter(null);
			if (!P.started && P.play) { P.started = true; report('start'); }
			awake('playing');
			P.awakeAt = now();
			renderControls();
			showControls();
			changed('playing');
		});
		v.addEventListener('pause', () => {
			if (!P.open) return;
			if (P.play && !v.ended) report('progress');
			awake('paused');
			renderControls();
			showControls();
			changed('pause');
		});
		v.addEventListener('seeked', () => { if (P.play && P.started) report('progress'); renderTime(); changed('seeked'); });
		v.addEventListener('waiting', () => { if (P.open && !P.error) { P.waiting = true; setCenter(t('media.player.buffering'), 'loading'); changed('waiting'); } });
		v.addEventListener('canplay', () => { P.waiting = false; if (!P.error && !P.loading) setCenter(null); });
		v.addEventListener('timeupdate', () => {
			renderTime();
			changed('time');
			if (!P.play) return;
			if (P.started && PS.progressDue(P.lastReport, now(), v.paused)) report('progress');
			if (!v.paused && now() - P.awakeAt >= PS.AWAKE_MS) { P.awakeAt = now(); awake('playing'); }
			const it = P.req && P.req.item;
			const hasVideo = !!(version() && version().video);
			const key = it ? `${it.sourceId}|${it.id}` : '';
			if (PS.missingPicture({ videoWidth: v.videoWidth, videoHeight: v.videoHeight, currentTime: v.currentTime - (P.startSec || 0), hasVideo, retried: P.retried.has(key) })) {
				P.retried.add(key);
				noPicture();
			}
		});
		v.addEventListener('loadedmetadata', () => { P.startSec = v.currentTime || 0; renderTime(); changed('metadata'); });
		v.addEventListener('progress', () => renderTime());
		v.addEventListener('volumechange', () => { renderControls(); changed('volume'); });
		v.addEventListener('ended', () => onEnded());
		v.addEventListener('error', () => { if (P.open && P.play && !P.hls) showError('media'); });
		v.addEventListener('dblclick', () => fullscreen());
		v.addEventListener('click', () => { if (P.panel) togglePanel(false); else toggle(); });
		document.addEventListener('fullscreenchange', () => { if (P.open) renderControls(); });
		R.root.addEventListener('mousemove', () => showControls());

		/** HEVC without the decoder (only sound): the core is told and Jellyfin asked again with H.264. */
		async function noPicture() {
			toast(t('media.player.noPicture'), 'info');
			P.caps = { ...(P.caps || {}), hevc: false };
			try { await api.setCaps(P.caps); } catch { /* the next PlaybackInfo still asks */ }
			await switchTo({ force: true });
		}

		// seek bar: click, drag, keys, the time under the mouse
		function fraction(e) {
			const r = R.bar.getBoundingClientRect();
			return r.width > 0 ? Math.min(1, Math.max(0, (e.clientX - r.left) / r.width)) : 0;
		}
		let dragging = false;
		R.bar.addEventListener('pointerdown', (e) => { dragging = true; R.bar.setPointerCapture(e.pointerId); const d = duration(); if (d > 0) v.currentTime = fraction(e) * d; });
		R.bar.addEventListener('pointermove', (e) => {
			const d = duration();
			const f = fraction(e);
			R.hoverTime.hidden = !(d > 0);
			R.hoverTime.textContent = PS.clock(f * d);
			R.hoverTime.style.left = `${f * 100}%`;
			if (dragging && d > 0) v.currentTime = f * d;
		});
		R.bar.addEventListener('pointerup', () => { dragging = false; });
		R.bar.addEventListener('pointerleave', () => { R.hoverTime.hidden = true; });
		R.bar.addEventListener('keydown', (e) => {
			if (e.key === 'Home') { e.preventDefault(); v.currentTime = 0; } else if (e.key === 'End') { e.preventDefault(); v.currentTime = PS.seekTarget(duration(), 0, duration()); }
		});

		// ── The end ──────────────────────────────────────────

		async function stop(why) {
			clearInterval(countdownTimer);
			const played = P.play;
			if (played) {
				await report('stop');
				api.endStream(played.playId).catch(() => {});
			}
			P.play = null;
			P.hint = null;
			P.seq++;
			detachSource();
			if (why !== 'switch') awake('stopped');
		}

		/** What the end tells the one who opened it: why ('user', 'ended', 'remote', 'switch'), the place and the length. */
		function ending(why = 'user') {
			const d = duration();
			return { why, positionMs: Math.floor(position()), durationMs: d > 0 ? Math.floor(d * 1000) : 0 };
		}

		async function close(why = 'user') {
			if (!P.open) return;
			const req = P.req;
			const end = ending(typeof why === 'string' ? why : 'user');
			await stop('close');
			P.open = false;
			P.ended = null;
			P.panel = false;
			document.removeEventListener('keydown', onKey, true);
			if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
			if (document.pictureInPictureElement) document.exitPictureInPicture().catch(() => {});
			R.root.hidden = true;
			R.nextBox.hidden = true;
			setCenter(null);
			document.body.classList.remove('mp-open');
			if (req && typeof req.onEnd === 'function') req.onEnd(end);
		}

		// ── The phone's keys ("Auf TV/PC abspielen", media-cast-remote.js) ──

		/** How it plays now, for the phone: { phase, positionMs, durationMs, title, version, play, volume, muted }. */
		function snapshot() {
			const v = R.video;
			let phase = 'loading';
			if (P.error) phase = 'failed';
			else if (P.ended || v.ended) phase = 'ended';
			else if (P.loading || !P.play || P.hint) phase = 'loading';
			else if (P.waiting) phase = 'buffering';
			else if (v.paused) phase = 'paused';
			else phase = 'playing';
			const d = duration();
			return {
				phase,
				positionMs: Math.floor(P.play ? position() : (P.req && P.req.startMs) || 0),
				durationMs: d > 0 ? Math.floor(d * 1000) : 0,
				title: P.req && P.req.item ? PS.titleOf(P.req.item, t).title : null,
				version: version(),
				play: P.play ? { audioIndex: P.play.audioIndex, subtitleIndex: Number.isInteger(P.play.subtitleIndex) ? P.play.subtitleIndex : -1 } : null,
				share: isShare(),
				volume: Math.round((v.muted ? 0 : v.volume) * 100),
				muted: v.muted === true,
			};
		}

		const remote = {
			snapshot,
			play() { const v = R.video; if (P.open && v.paused && !P.ended) { const p = v.play(); if (p && p.catch) p.catch(() => {}); } },
			pause() { if (P.open && !R.video.paused) R.video.pause(); },
			seekTo(ms) { if (P.open && P.play) { R.video.currentTime = PS.seekTarget(Math.max(0, ms) / 1000, 0, duration()); showControls(); } },
			seekBy(ms) { if (P.open && P.play) seekBy(ms / 1000); },
			audio(index) { if (P.open && P.play && !isShare() && Number.isInteger(index)) switchTo({ audioIndex: index }); },
			subtitle(index) { if (P.open && P.play && !isShare() && Number.isInteger(index)) switchTo({ subtitleIndex: index }); },
			volume(level, muted) {
				if (!P.open) return;
				if (Number.isFinite(level)) { R.video.volume = Math.min(1, Math.max(0, level / 100)); R.video.muted = level === 0; }
				if (typeof muted === 'boolean') R.video.muted = muted;
				saveVolume();
				renderControls();
			},
			stop() { return close('remote'); },
		};

		relabel();

		return {
			play,
			close,
			relabel,
			remote,
			get open() { return P.open; },
			get state() { return P; },
		};
	}

	root.GCMediaPlayer = { mount, probeCaps };
})(typeof window !== 'undefined' ? window : globalThis);
