/**
 * GateControl -- Kameras (renderer view of the home cameras of gatecontrol-door)
 *
 * "Tür & Kamera" 1.6.0, Kameras im Heimnetz (mockups KameraHandy / Kameras,
 * laid out for the desktop): the cameras as chips, the player — live video
 * through the VPN (the continuous fMP4 `live.mp4` in a <video>; Chromium has
 * no HLS) or, without VPN, a new still every 10 s with the hint —, the
 * buttons "Standbild speichern", "Vollbild" and "Ton", "Clips heute" with
 * their type pills (a click plays the clip in the player) and all cameras as
 * cards with their pictures. Only the cameras the person may see come from
 * the server (rights per camera); a camera push reloads its clips, a click on
 * its toast opens the page on that camera. Ring and the locks stay in the
 * portal ("Schlösser und Ring im Portal").
 *
 * Data: window.gatecontrol.cameras (core CamerasService over IPC; pictures
 * and video as gccam:// addresses served by the main process); texts:
 * cameras.* of the core locales; view logic without DOM: camera-state.js
 * (window.GCCameraState).
 *
 * Note: server text only ever goes into textContent / attributes; icons are
 * built from static path data with createElementNS (no innerHTML).
 */
(function (root) {
	'use strict';

	const CS = root.GCCameraState;
	const NS = 'http://www.w3.org/2000/svg';
	const ICONS = {
		camera: 'M3 7h3l2-3h8l2 3h3v13H3z|M12 10a3.5 3.5 0 1 0 0 7a3.5 3.5 0 1 0 0-7',
		refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8|M21 3v5h-5',
		alert: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 8v5M12 16h.01',
		save: 'M12 3v12|M7 10l5 5 5-5|M5 21h14',
		expand: 'M4 9V4h5|M20 9V4h-5|M4 15v5h5|M20 15v5h-5',
		shrink: 'M9 4v5H4|M15 4v5h5|M9 20v-5H4|M15 20v-5h5',
		sound: 'M4 9h4l5-4v14l-5-4H4z|M16 9a4 4 0 0 1 0 6|M19 6a8 8 0 0 1 0 12',
		mute: 'M4 9h4l5-4v14l-5-4H4z|M17 9l5 6M22 9l-5 6',
		play: 'M8 5v14l11-7z',
		back: 'M15 6l-6 6 6 6',
		portal: 'M14 4h6v6|M20 4l-9 9|M18 14v6H4V6h6',
	};

	function icon(name, size = 16, stroke = '2') {
		const s = document.createElementNS(NS, 'svg');
		s.setAttribute('viewBox', '0 0 24 24');
		s.setAttribute('width', String(size));
		s.setAttribute('height', String(size));
		s.setAttribute('fill', 'none');
		s.setAttribute('stroke', 'currentColor');
		s.setAttribute('stroke-width', stroke);
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

	/** el('div', { class, text, on: { click }, attrs… }, [children]) — text only via textContent. */
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
	const pill = (p) => el('span', { class: `cm-pill ${p.cls}`, text: p.label });

	function mount(o) {
		const api = o.api;
		const t = o.t;
		const now = typeof o.now === 'function' ? o.now : () => Date.now();
		const locale = () => (typeof o.getLocale === 'function' ? o.getLocale() : undefined);

		const S = {
			status: null,
			shown: false,
			list: null,          // last answer of cameras.list
			listError: null,
			selected: null,      // camera id
			focusEvent: null,    // event id of a push to highlight
			live: null,          // answer of cameras.live for the selected camera
			liveError: null,
			liveSeq: 0,          // guards against answers of an earlier selection
			phase: 'idle',       // idle | loading | playing | still | error
			pictureAt: null,     // when the last still arrived
			stillN: 0,
			failures: 0,
			muted: true,
			clip: null,          // the clip being played
			clips: new Map(),    // camera id → answer of cameras.clips
			clipsError: new Map(),
			cardN: 0,
			saving: false,
			codecProblem: false,
		};
		const timers = { still: null, refresh: null, retry: null, cards: null, clock: null };
		const stopTimer = (k) => { clearTimeout(timers[k]); clearInterval(timers[k]); timers[k] = null; };

		// ── Skeleton ─────────────────────────────────────────
		const refs = {};
		const rootEl = el('div', { class: 'cm scroll' });
		o.root.appendChild(rootEl);
		refs.h = el('h1', { class: 'cm-h', text: t('cameras.title') });
		refs.sub = el('span', { class: 'cm-sub', text: t('cameras.sub') });
		refs.online = el('span', { class: 'cm-pill is-ok', hidden: true });
		refs.portal = el('button', { type: 'button', class: 'btn btn-ghost cm-portal', on: { click: () => { if (typeof o.openPortal === 'function') o.openPortal(); } } }, [icon('portal', 15), el('span', { text: t('cameras.portal') })]);
		refs.refresh = el('button', { type: 'button', class: 'cm-ib', title: t('cameras.refresh'), 'aria-label': t('cameras.refresh'), on: { click: () => reload(true) } }, [icon('refresh', 16)]);
		refs.banner = el('div', { class: 'cm-banner', role: 'status', hidden: true });
		refs.chips = el('div', { class: 'cm-chips', role: 'group', 'aria-label': t('cameras.chooser') });
		refs.empty = el('div', { class: 'cm-state', hidden: true });

		// player
		refs.video = el('video', { class: 'cm-media', playsinline: true, muted: true, autoplay: true, hidden: true, disablepictureinpicture: true });
		refs.video.muted = true;
		refs.img = el('img', { class: 'cm-media', alt: '', draggable: 'false', hidden: true });
		refs.badge = el('span', { class: 'cm-ov-pill', hidden: true });
		refs.quality = el('span', { class: 'cm-ov-pill is-dark', hidden: true });
		refs.stamp = el('span', { class: 'cm-ov-stamp' });
		refs.msg = el('div', { class: 'cm-msg', hidden: true });
		refs.player = el('div', { class: 'cm-player', role: 'img', tabindex: '-1' }, [
			refs.video, refs.img,
			el('div', { class: 'cm-ov-top' }, [refs.badge, el('span', { class: 'cm-grow' }), refs.quality]),
			refs.msg,
			el('div', { class: 'cm-ov-bottom' }, [refs.stamp]),
		]);
		refs.save = el('button', { type: 'button', class: 'btn btn-sec cm-act', on: { click: () => saveStill() } }, [icon('save', 16), el('span', { text: t('cameras.saveStill') })]);
		refs.fullLabel = el('span', { text: t('cameras.fullscreen') });
		refs.fullIcon = icon('expand', 16);
		refs.full = el('button', { type: 'button', class: 'btn btn-sec cm-act', on: { click: () => toggleFullscreen() } }, [refs.fullIcon, refs.fullLabel]);
		refs.soundLabel = el('span', { text: t('cameras.sound') });
		refs.soundIcon = icon('mute', 16);
		refs.sound = el('button', { type: 'button', class: 'btn btn-sec cm-act', 'aria-pressed': 'false', on: { click: () => toggleSound() } }, [refs.soundIcon, refs.soundLabel]);
		refs.back = el('button', { type: 'button', class: 'btn btn-ghost cm-back', hidden: true, on: { click: () => backToLive() } }, [icon('back', 15), el('span', { text: t('cameras.clips.back') })]);
		refs.hint = el('p', { class: 'cm-hint' });

		// clips
		refs.clipsH = el('h2', { class: 'cm-h2', text: t('cameras.clips.title') });
		refs.clipsCam = el('span', { class: 'cm-sub' });
		refs.clipList = el('div', { class: 'cm-clips', 'aria-live': 'polite' });

		// all cameras
		refs.allH = el('h2', { class: 'cm-h2', text: t('cameras.all') });
		refs.allSub = el('span', { class: 'cm-sub', text: t('cameras.allSub') });
		refs.cards = el('div', { class: 'cm-cards' });

		refs.main = el('div', { class: 'cm-main' }, [
			el('div', { class: 'cm-stage' }, [
				refs.player,
				el('div', { class: 'cm-acts' }, [refs.save, refs.full, refs.sound]),
				el('div', { class: 'cm-under' }, [refs.back, refs.hint]),
			]),
			el('section', { class: 'cm-card cm-clipcard', 'aria-label': t('cameras.clips.title') }, [
				el('div', { class: 'cm-card-head' }, [refs.clipsH, el('span', { class: 'cm-grow' }), refs.clipsCam]),
				refs.clipList,
			]),
		]);
		refs.all = el('section', { class: 'cm-card' }, [
			el('div', { class: 'cm-card-head' }, [refs.allH, el('span', { class: 'cm-grow' }), refs.allSub]),
			refs.cards,
		]);

		rootEl.append(
			el('div', { class: 'cm-head' }, [
				el('div', { class: 'cm-head-tx' }, [el('div', { class: 'cm-title' }, [refs.h, refs.online]), refs.sub]),
				el('span', { class: 'cm-grow' }),
				refs.portal,
				refs.refresh,
			]),
			refs.banner,
			refs.chips,
			refs.empty,
			refs.main,
			refs.all,
		);

		const cameras = () => (S.list && Array.isArray(S.list.cameras) ? S.list.cameras : []);
		const camera = () => cameras().find((c) => c.id === S.selected) || null;

		// ── Data ─────────────────────────────────────────────
		async function loadList(refresh) {
			const res = await Promise.resolve(api.list({ refresh })).catch((err) => ({ ok: false, code: 'failed', error: err && err.message }));
			if (res && res.ok) {
				S.list = res;
				S.listError = null;
			} else {
				S.listError = res || { ok: false, code: 'failed' };
			}
			const before = S.selected;
			S.selected = CS.pickCamera(cameras(), S.selected);
			// the camera shown is no longer there (rights changed): the next one starts afresh
			if (S.selected !== before) resetPlayer();
			render();
			return res;
		}

		async function loadClips(id, refresh) {
			if (!id) return;
			const res = await Promise.resolve(api.clips(id, null, { refresh })).catch((err) => ({ ok: false, code: 'failed', error: err && err.message }));
			if (res && res.ok) { S.clips.set(id, res); S.clipsError.delete(id); } else S.clipsError.set(id, res || { ok: false, code: 'failed' });
			if (id === S.selected) renderClips();
		}

		/** The list, then the live picture (when none runs or on refresh) and the clips of the camera shown. */
		function reload(refresh = false) {
			return loadList(refresh).then(() => {
				if (!S.selected || !S.shown) return undefined;
				if (!S.clip && (refresh || S.phase === 'idle' || S.phase === 'error')) startLive();
				return loadClips(S.selected, refresh);
			});
		}

		// ── Player ───────────────────────────────────────────
		function stopMedia() {
			stopTimer('still');
			stopTimer('retry');
			stopTimer('refresh');
			stopTimer('clock');
			const v = refs.video;
			if (v.getAttribute('src')) {
				try { v.pause(); } catch { /* not playing */ }
				v.removeAttribute('src');
				try { v.load(); } catch { /* jsdom */ }
			}
			v.hidden = true;
			v.controls = false;
			refs.img.hidden = true;
		}

		function resetPlayer() {
			S.liveSeq += 1; // answers in flight are no longer wanted
			S.clip = null;
			S.live = null;
			S.phase = 'idle';
			S.failures = 0;
			S.codecProblem = false;
			refs.video.onerror = null;
			stopMedia();
		}

		/** A chip / card: that camera's live picture and clips. */
		function select(id) {
			if (!id) return;
			if (id === S.selected && !S.clip && S.phase !== 'idle' && S.phase !== 'error') return;
			S.selected = id;
			S.focusEvent = null;
			resetPlayer();
			render();
			if (S.shown) {
				startLive();
				loadClips(id, false);
			}
		}

		/**
		 * Ask for the live answer and play it. quiet: a refresh of the tokens while stills are shown —
		 * the last still stays until the next one arrives.
		 */
		async function startLive({ quiet = false } = {}) {
			const id = S.selected;
			if (!id || !S.shown) return;
			const keep = quiet && S.phase === 'still';
			if (keep) { stopTimer('still'); stopTimer('retry'); stopTimer('refresh'); } else stopMedia();
			const seq = ++S.liveSeq;
			if (!keep) S.phase = 'loading';
			S.liveError = null;
			renderPlayer();
			const res = await Promise.resolve(api.live(id)).catch((err) => ({ ok: false, code: 'failed', error: err && err.message }));
			if (seq !== S.liveSeq || !S.shown || S.clip) return;
			if (!res || !res.ok || !res.live) {
				S.live = null;
				S.liveError = res || { ok: false, code: 'failed' };
				S.phase = 'error';
				renderPlayer();
				// no right on this camera any more: the list says what is left
				if (res && res.code === 'not_found') loadList(true);
				else scheduleRetry();
				return;
			}
			S.live = res.live;
			const src = S.codecProblem ? null : CS.videoSrc(res.live, canHls());
			if (src) playVideo(src, seq);
			else showStills(seq);
			stopTimer('refresh');
			timers.refresh = setTimeout(() => { if (seq === S.liveSeq) startLive({ quiet: true }); }, CS.refreshIn(S.live, now()));
		}

		function canHls() {
			try { return !!refs.video.canPlayType && refs.video.canPlayType('application/vnd.apple.mpegurl') !== ''; } catch { return false; }
		}

		function playVideo(src, seq) {
			const v = refs.video;
			v.controls = false;
			v.muted = S.muted || !(S.live && S.live.audio);
			v.hidden = false;
			refs.img.hidden = true;
			const onPlaying = () => {
				if (seq !== S.liveSeq) return;
				S.phase = 'playing';
				S.failures = 0;
				renderPlayer();
			};
			const onEnd = (ev) => {
				if (seq !== S.liveSeq || S.clip) return;
				v.removeEventListener('playing', onPlaying);
				v.removeEventListener('ended', onEnd);
				v.removeEventListener('error', onEnd);
				const err = v.error;
				// MEDIA_ERR_SRC_NOT_SUPPORTED (4) / DECODE (3) with a codec this PC cannot play (H.265): stills instead
				const codec = CS.codecParam(S.live && S.live.codec);
				const unplayable = !!codec && typeof v.canPlayType === 'function' && v.canPlayType(`video/mp4; codecs="${codec}"`) === '';
				if (ev && ev.type === 'error' && err && (err.code === 4 || err.code === 3) && S.phase !== 'playing' && unplayable) {
					S.codecProblem = true;
					showStills(seq);
					return;
				}
				// live.mp4 ends with its token (≤ 5 min) or the stream broke: a new answer
				S.failures += ev && ev.type === 'error' ? 1 : 0;
				scheduleRetry(ev && ev.type === 'ended' ? 300 : null);
			};
			v.addEventListener('playing', onPlaying);
			v.addEventListener('ended', onEnd);
			v.addEventListener('error', onEnd);
			v.src = src;
			const p = v.play && v.play();
			if (p && typeof p.catch === 'function') p.catch(() => { /* autoplay muted: the browser decides */ });
			stopTimer('clock');
			timers.clock = setInterval(() => { if (S.phase === 'playing') renderOverlay(); }, 1000);
			renderPlayer();
		}

		function showStills(seq) {
			const live = S.live;
			const url = live && live.snapshot;
			refs.video.hidden = true;
			if (!url) { S.phase = 'error'; S.liveError = { code: 'no_image' }; renderPlayer(); return; }
			const every = Math.max(5, (live.every || 10)) * 1000;
			const next = () => {
				if (seq !== S.liveSeq || !S.shown || S.clip) return;
				S.stillN += 1;
				const src = CS.stillSrc(url, S.stillN);
				const pic = new Image();
				pic.onload = () => {
					if (seq !== S.liveSeq || S.clip) return;
					refs.img.src = src;
					refs.img.hidden = false;
					S.pictureAt = now();
					S.phase = 'still';
					S.failures = 0;
					renderPlayer();
				};
				pic.onerror = () => {
					if (seq !== S.liveSeq) return;
					S.failures += 1;
					// the token may have run out: ask again after a few failures
					if (S.failures >= 3) startLive();
					else if (S.phase !== 'still') { S.phase = 'error'; S.liveError = { code: 'cam_unreachable' }; renderPlayer(); }
				};
				pic.src = src;
			};
			S.phase = S.phase === 'still' ? 'still' : 'loading';
			renderPlayer();
			next();
			stopTimer('still');
			timers.still = setInterval(next, every);
		}

		function scheduleRetry(fixedMs = null) {
			stopTimer('retry');
			if (!S.shown || S.clip) return;
			const ms = fixedMs !== null ? fixedMs : Math.min(30000, 2000 * (2 ** Math.min(S.failures, 4)));
			const seq = S.liveSeq;
			timers.retry = setTimeout(() => { if (seq === S.liveSeq) startLive(); }, ms);
		}

		function playClip(clip) {
			if (!clip || !clip.clipUrl) return;
			S.liveSeq += 1; // the live answer in flight is no longer wanted
			stopMedia();
			S.clip = clip;
			const v = refs.video;
			v.hidden = false;
			v.controls = true;
			v.muted = S.muted;
			v.src = clip.clipUrl;
			const p = v.play && v.play();
			if (p && typeof p.catch === 'function') p.catch(() => {});
			v.onerror = () => { if (S.clip === clip && o.toast) o.toast(t('cameras.clips.gone'), 'info'); };
			S.phase = 'playing';
			render();
		}

		function backToLive() {
			resetPlayer();
			render();
			startLive();
		}

		// ── Buttons ──────────────────────────────────────────
		async function saveStill() {
			if (!S.selected || S.saving) return;
			S.saving = true;
			renderActions();
			const res = await Promise.resolve(api.saveStill(S.selected)).catch((err) => ({ ok: false, code: 'failed', error: err && err.message }));
			S.saving = false;
			renderActions();
			if (res && res.ok) { if (o.toast) o.toast(t('cameras.saved'), 'success'); } else if (res && !res.cancelled && o.toast) o.toast(`${t('cameras.saveFailed')} ${CS.errorText(res, t)}`, 'error');
		}

		function toggleFullscreen() {
			const d = refs.player.ownerDocument;
			if (d.fullscreenElement) { if (d.exitFullscreen) d.exitFullscreen().catch(() => {}); return; }
			if (refs.player.requestFullscreen) refs.player.requestFullscreen().catch(() => {});
		}
		refs.player.ownerDocument.addEventListener('fullscreenchange', () => renderActions());
		refs.player.addEventListener('dblclick', () => toggleFullscreen());

		function toggleSound() {
			S.muted = !S.muted;
			refs.video.muted = S.muted || (!S.clip && !(S.live && S.live.audio));
			renderActions();
		}

		// ── Render ───────────────────────────────────────────
		function render() {
			const st = S.status;
			const list = cameras();
			const n = CS.onlineCount(list);
			refs.online.hidden = !list.length;
			refs.online.textContent = t('cameras.online', { count: n });
			refs.refresh.disabled = !S.shown;

			// banner: an old copy or a failed list
			const stale = S.list && S.list.stale;
			refs.banner.hidden = !(stale || (S.listError && S.list));
			refs.banner.textContent = stale || S.list ? t('cameras.stale') : '';

			const empty = !list.length;
			refs.main.hidden = empty;
			refs.all.hidden = empty;
			refs.chips.hidden = empty;
			refs.empty.hidden = !empty;
			if (empty) {
				clear(refs.empty);
				if (!S.list && !S.listError) {
					refs.empty.appendChild(el('div', { class: 'cm-loading', text: t('cameras.loading') }));
				} else if (S.listError && !S.list) {
					refs.empty.append(icon('alert', 28, '1.6'), el('strong', { text: CS.errorText(S.listError, t) }), el('button', { type: 'button', class: 'btn btn-sec', text: t('cameras.retry'), on: { click: () => reload(true) } }));
					refs.empty.classList.add('is-error');
				} else {
					refs.empty.classList.remove('is-error');
					refs.empty.append(icon('camera', 28, '1.6'), el('strong', { text: CS.unavailableText(st, t) }), el('span', { text: t('cameras.emptySub') }));
				}
				stopMedia();
				return;
			}
			renderChips();
			renderPlayer();
			renderClips();
			renderCards();
		}

		function renderChips() {
			clear(refs.chips);
			for (const c of cameras()) {
				const on = c.id === S.selected;
				refs.chips.appendChild(el('button', {
					type: 'button', class: `cm-chip${on ? ' is-on' : ''}${c.online ? '' : ' is-off'}`, 'aria-pressed': on ? 'true' : 'false', 'data-id': c.id,
					on: { click: () => select(c.id) },
				}, [el('span', { class: 'cm-dot', 'aria-hidden': 'true' }), el('span', { text: c.name })]));
			}
		}

		function renderOverlay() {
			const ov = CS.overlay({ live: S.live, camera: camera(), clip: S.clip, pictureAt: S.pictureAt }, t, locale(), now());
			const show = S.phase === 'playing' || S.phase === 'still' || !!S.clip;
			refs.badge.hidden = !(show && ov.badge);
			if (ov.badge) { refs.badge.textContent = ov.badge.text; refs.badge.className = `cm-ov-pill ${ov.badge.cls}`; }
			refs.quality.hidden = !(show && ov.quality);
			refs.quality.textContent = ov.quality || '';
			refs.stamp.textContent = ov.stamp || '';
		}

		function renderPlayer() {
			const c = camera();
			refs.player.setAttribute('aria-label', t('cameras.player', { name: c ? c.name : '' }));
			renderOverlay();
			// message in the middle: loading / offline / error
			clear(refs.msg);
			let msg = null;
			if (S.clip) msg = null;
			else if (S.phase === 'loading') msg = [el('span', { class: 'cm-spin', 'aria-hidden': 'true' }), el('span', { text: t('cameras.connecting') })];
			else if (S.phase === 'error') {
				const offline = c && !c.online;
				msg = [icon('alert', 22, '1.8'), el('strong', { text: offline ? t('cameras.offline') : CS.errorText(S.liveError, t) }),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('cameras.reconnect'), on: { click: () => { S.failures = 0; startLive(); } } })];
			}
			refs.msg.hidden = !msg;
			if (msg) refs.msg.append(...msg);
			if (S.phase === 'error') refs.img.hidden = true;
			// hint under the player
			const live = S.live;
			if (S.codecProblem) refs.hint.textContent = CS.codecHint(live, t);
			else if (live && live.mode === 'live') refs.hint.textContent = t('cameras.hintLive');
			else refs.hint.textContent = t('cameras.hint', { s: (live && live.every) || (S.list && S.list.every) || 10 });
			refs.back.hidden = !S.clip;
			renderActions();
		}

		function renderActions() {
			const c = camera();
			refs.save.disabled = !c || S.saving;
			refs.save.classList.toggle('is-busy', S.saving);
			const full = !!refs.player.ownerDocument.fullscreenElement;
			refs.fullLabel.textContent = full ? t('cameras.fullscreenExit') : t('cameras.fullscreen');
			refs.fullIcon.replaceWith(refs.fullIcon = icon(full ? 'shrink' : 'expand', 16));
			refs.full.disabled = !c;
			// Ton: live video with sound, or a clip
			const liveAudio = !!(S.live && S.live.mode === 'live' && S.live.audio && S.phase === 'playing');
			const canSound = !!S.clip || liveAudio;
			refs.sound.disabled = !canSound;
			const on = canSound && !S.muted;
			refs.sound.setAttribute('aria-pressed', on ? 'true' : 'false');
			refs.sound.classList.toggle('is-on', on);
			refs.soundIcon.replaceWith(refs.soundIcon = icon(on ? 'sound' : 'mute', 16));
			refs.sound.title = !canSound ? (S.live && S.live.mode === 'live' ? t('cameras.noSound') : t('cameras.soundLive')) : (on ? t('cameras.soundOff') : t('cameras.soundOn'));
		}

		function renderClips() {
			const c = camera();
			refs.clipsCam.textContent = c ? c.name : '';
			clear(refs.clipList);
			if (!c) return;
			const res = S.clips.get(c.id);
			const err = S.clipsError.get(c.id);
			if (!res && !err) { refs.clipList.appendChild(el('div', { class: 'cm-loading', text: t('cameras.loading') })); return; }
			if (!res && err) {
				refs.clipList.appendChild(el('div', { class: 'cm-note is-error' }, [el('span', { text: CS.errorText(err, t) }), el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('cameras.retry'), on: { click: () => loadClips(c.id, true) } })]));
				return;
			}
			if (!res.clips.length) { refs.clipList.appendChild(el('div', { class: 'cm-note', text: t('cameras.clips.empty') })); return; }
			for (const clip of res.clips) {
				const v = CS.clipView(clip, t, locale());
				const thumb = el('span', { class: 'cm-th', 'aria-hidden': 'true' }, [
					v.thumb ? el('img', { src: v.thumb, alt: '', draggable: 'false', loading: 'lazy' }) : null,
					v.playable ? el('span', { class: 'cm-th-play' }, [icon('play', 14)]) : null,
				]);
				const playing = S.clip && S.clip.id === clip.id;
				const row = el(v.playable ? 'button' : 'div', {
					class: `cm-clip${playing ? ' is-on' : ''}${S.focusEvent === clip.id ? ' is-focus' : ''}`, 'data-id': clip.id,
					...(v.playable ? { type: 'button', 'aria-label': v.label, on: { click: () => playClip(clip) } } : {}),
				}, [
					thumb,
					el('span', { class: 'cm-clip-tx' }, [el('strong', { text: v.title }), el('span', { class: 'cm-sub', text: v.sub })]),
					el('span', { class: 'cm-clip-pills' }, [pill(v.pill), ...v.extra.map(pill)]),
				]);
				refs.clipList.appendChild(row);
			}
			if (S.focusEvent) {
				const f = refs.clipList.querySelector('.cm-clip.is-focus');
				if (f && typeof f.scrollIntoView === 'function') f.scrollIntoView({ block: 'nearest' });
			}
		}

		function renderCards() {
			clear(refs.cards);
			for (const c of cameras()) {
				const v = CS.cardView(c, t, now(), locale());
				const shot = el('span', { class: `cm-shot${v.offline ? ' is-off' : ''}`, 'aria-hidden': 'true' }, [
					v.picture ? el('img', { src: CS.stillSrc(v.picture, S.cardN), alt: '', draggable: 'false', loading: 'lazy' }) : el('span', { class: 'cm-shot-none', text: t('cameras.card.noPicture') }),
					el('span', { class: 'cm-shot-stamp', text: v.stamp }),
				]);
				refs.cards.appendChild(el('button', {
					type: 'button', class: `cm-cam${c.id === S.selected ? ' is-on' : ''}`, 'aria-pressed': c.id === S.selected ? 'true' : 'false', 'data-id': c.id,
					on: { click: () => { select(c.id); if (typeof refs.player.scrollIntoView === 'function') refs.player.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); } },
				}, [
					shot,
					el('span', { class: 'cm-cam-row' }, [el('strong', { text: v.name }), el('span', { class: 'cm-grow' }), ...v.pills.map(pill)]),
					v.desc ? el('span', { class: 'cm-sub', text: v.desc }) : null,
				]));
			}
		}

		// ── Events ───────────────────────────────────────────
		function setStatus(st) {
			S.status = st || null;
			if (typeof o.onStatus === 'function') o.onStatus(S.status);
			if (S.shown) render();
		}
		function refreshStatus() {
			Promise.resolve(api.status()).then((st) => setStatus(st)).catch(() => {});
		}
		if (typeof api.onState === 'function') api.onState((st) => setStatus(st));
		if (typeof api.onPush === 'function') {
			api.onPush(() => {
				// a new clip: the core dropped its cache — the list (last event) and the clips again
				if (S.shown) reload(false);
			});
		}
		refreshStatus();

		return {
			show() {
				S.shown = true;
				render();
				reload(false);
				stopTimer('cards');
				timers.cards = setInterval(() => { S.cardN += 1; if (S.shown) renderCards(); }, CS.CARD_EVERY_MS);
			},
			hide() {
				S.shown = false;
				S.focusEvent = null;
				resetPlayer();
				stopTimer('cards');
				const d = refs.player.ownerDocument;
				if (d.fullscreenElement && d.exitFullscreen) d.exitFullscreen().catch(() => {});
			},
			/** Open on a push target ({ cameraId, eventId } from notify:navigate / an inbox entry). */
			open(ctx) {
				const target = CS.pushTarget(ctx);
				if (!target) return;
				S.focusEvent = target.eventId;
				S.clips.delete(target.cameraId);
				if (cameras().some((c) => c.id === target.cameraId) || !S.list) S.selected = target.cameraId;
				resetPlayer();
				render();
				if (S.shown) reload(true);
			},
			/** The VPN came up / went down: the server decides anew between live video and stills. */
			networkChanged() {
				if (S.shown && S.selected && !S.clip) { S.failures = 0; S.codecProblem = false; startLive({ quiet: true }); }
			},
			refresh: () => reload(true),
			status: () => S.status,
			relabel() {
				refs.h.textContent = t('cameras.title');
				refs.sub.textContent = t('cameras.sub');
				refs.portal.lastChild.textContent = t('cameras.portal');
				refs.refresh.title = t('cameras.refresh');
				refs.refresh.setAttribute('aria-label', t('cameras.refresh'));
				refs.chips.setAttribute('aria-label', t('cameras.chooser'));
				refs.save.lastChild.textContent = t('cameras.saveStill');
				refs.soundLabel.textContent = t('cameras.sound');
				refs.back.lastChild.textContent = t('cameras.clips.back');
				refs.clipsH.textContent = t('cameras.clips.title');
				refs.allH.textContent = t('cameras.all');
				refs.allSub.textContent = t('cameras.allSub');
				render();
			},
		};
	}

	root.GCCameraView = { mount };
})(typeof self !== 'undefined' ? self : this);
