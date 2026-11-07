/**
 * GateControl -- Drive viewer of pictures and videos (renderer)
 *
 * The stage of the large view (Drive 1.21; used by the lightbox of drive-photos-view.js, opened from "Fotos", the
 * overview and — new — "Dateien"):
 *   - picture(stage, p, o): the large preview at once, the original over it (gcdrive:, streamed by the main process)
 *     once zoomed or when there is no preview; zoom with the mouse wheel, + / − / 0, a double click, two fingers;
 *     moved by dragging while zoomed.
 *   - video(stage, p, o): a <video controls> from `drive.stream(id)` — the main process serves gcdrive://media/<token>
 *     from the own server with the Range of the request, so nothing is loaded whole first; play / pause, seek, sound,
 *     full screen; the place it was left (while the app runs); a type the PC cannot play says so ("In anderer App
 *     öffnen"). A file the virus scan holds back never gets an address (the core refuses it too).
 *   - fullscreen(el): the stage in full screen and back.
 * Every handle has destroy(): the video stops, its address ends (drive.endStream).
 * Loaded as a plain script after drive-viewer-state.js (window.GCDriveViewer).
 */
(function (root) {
	'use strict';

	const VS = root.GCDriveViewerState;
	const placesOfApp = VS ? VS.places() : null;

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive (stream, endStream)
	 * @param {Function} o.t - i18n
	 * @param {object} o.ui - { el, icon, clear }
	 * @param {Function} [o.previewUrl] - (p, large) → Promise<object URL | null> (the lightbox's previews)
	 */
	function create(o) {
		const { api, t } = o;
		const { el, icon } = o.ui;
		const places = placesOfApp || (VS ? VS.places() : null);
		const canStream = !!(api && typeof api.stream === 'function');

		async function streamOf(p) {
			if (!canStream) return null;
			const r = await Promise.resolve(api.stream(p.id)).catch(() => null);
			return r && r.ok && typeof r.url === 'string' && r.url.startsWith('gcdrive:') ? r : null;
		}
		function endStream(url) {
			if (url && api && typeof api.endStream === 'function') Promise.resolve(api.endStream(url)).catch(() => {});
		}

		function busy() {
			return el('div', { class: 'dvw-busy', role: 'status' }, [el('span', { class: 'dvw-spin', 'aria-hidden': 'true' }), el('span', { text: t('drive.viewer.loading') })]);
		}

		// ── a picture ───────────────────────────────────────

		function picture(stage, p, opts = {}) {
			let z = { s: 1, x: 0, y: 0 };
			let gone = false;
			let url = null;            // the original's gcdrive: address
			let originalAsked = false;
			const img = el('img', { class: 'dvw-img', alt: p.name || '', draggable: 'false' });
			const box = el('div', { class: 'dpv-big dvw-pic' }, [img]);
			stage.appendChild(box);
			const wait = busy();
			const apply = () => {
				img.style.transform = VS.transform(z);
				box.classList.toggle('is-zoomed', z.s > 1);
				if (z.s > 1) original();
				if (opts.onZoom) opts.onZoom(z.s);
			};
			const size = () => ({ w: box.clientWidth, h: box.clientHeight });
			const fromMiddle = (e) => {
				const r = box.getBoundingClientRect();
				return [e.clientX - (r.left + r.width / 2), e.clientY - (r.top + r.height / 2)];
			};
			async function original() {
				if (originalAsked || gone) return;
				originalAsked = true;
				const s = await streamOf(p);
				if (!s || gone) { if (s) endStream(s.url); return; }
				url = s.url;
				const big = new Image();
				big.onload = () => { if (!gone) { img.src = url; wait.remove(); } };
				big.onerror = () => { if (!gone && !img.getAttribute('src')) { wait.remove(); box.appendChild(el('p', { class: 'dvw-hint', text: t('drive.viewer.noPicture') })); } };
				big.src = url;
			}
			// the large preview first; without one the original at once
			const pre = p.preview && opts.previewUrl ? Promise.resolve(opts.previewUrl(p, true)).catch(() => null) : Promise.resolve(null);
			box.appendChild(wait);
			pre.then((u) => {
				if (gone) return;
				if (u) { img.src = u; wait.remove(); } else original();
			});
			box.addEventListener('wheel', (e) => {
				e.preventDefault();
				const [cx, cy] = fromMiddle(e);
				z = VS.zoomBy(z, e.deltaY < 0 ? 1.2 : 1 / 1.2, cx, cy, size());
				apply();
			}, { passive: false });
			box.addEventListener('dblclick', (e) => {
				const [cx, cy] = fromMiddle(e);
				z = z.s > 1 ? { s: 1, x: 0, y: 0 } : VS.zoomBy(z, 2.5, cx, cy, size());
				apply();
			});
			const ptr = new Map();
			let g = null;
			box.addEventListener('pointerdown', (e) => {
				ptr.set(e.pointerId, { x: e.clientX, y: e.clientY });
				if (ptr.size === 2) {
					const [a, b] = [...ptr.values()];
					g = { pinch: Math.hypot(a.x - b.x, a.y - b.y) || 1, s: z.s };
				} else g = { x: e.clientX, y: e.clientY, zx: z.x, zy: z.y };
				try { box.setPointerCapture(e.pointerId); } catch { /* gone */ }
			});
			box.addEventListener('pointermove', (e) => {
				const q = ptr.get(e.pointerId);
				if (!q || !g) return;
				q.x = e.clientX; q.y = e.clientY;
				if (g.pinch && ptr.size === 2) {
					const [a, b] = [...ptr.values()];
					z = VS.clamp({ ...z, s: Math.max(1, Math.min(VS.ZOOM_MAX, g.s * ((Math.hypot(a.x - b.x, a.y - b.y) || 1) / g.pinch))) }, size());
					apply();
				} else if (!g.pinch && z.s > 1) {
					z = VS.clamp({ s: z.s, x: g.zx + (e.clientX - g.x), y: g.zy + (e.clientY - g.y) }, size());
					apply();
				}
			});
			const up = (e) => {
				const g0 = g;
				ptr.delete(e.pointerId);
				if (ptr.size) return;
				g = null;
				// a swipe at 1×: the next or the one before
				if (g0 && !g0.pinch && z.s <= 1 && opts.onSwipe) {
					const dx = e.clientX - g0.x;
					const dy = e.clientY - g0.y;
					if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy) * 1.5) opts.onSwipe(dx < 0 ? 1 : -1);
				}
			};
			box.addEventListener('pointerup', up);
			box.addEventListener('pointercancel', up);
			return {
				kind: 'image',
				by(f) { z = VS.zoomBy(z, f, 0, 0, size()); apply(); },
				reset() { z = { s: 1, x: 0, y: 0 }; apply(); },
				get zoom() { return z.s; },
				destroy() { gone = true; endStream(url); url = null; },
			};
		}

		// ── a video ─────────────────────────────────────────

		function video(stage, p, opts = {}) {
			let gone = false;
			let url = null;
			let v = null;
			let tried = false;
			const holder = el('div', { class: 'dvw-video' });
			stage.appendChild(holder);

			const hint = (text, actions = []) => {
				holder.querySelectorAll('.dvw-note').forEach((x) => x.remove());
				holder.appendChild(el('div', { class: 'dvw-note', role: 'note' }, [el('p', { class: 'dvw-hint', text }), actions.length ? el('div', { class: 'dvw-acts' }, actions) : null]));
			};
			const otherApp = () => (opts.openExternal ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => opts.openExternal(p) } }, [icon('open', 14), el('span', { text: t('drive.viewer.openOther') })]) : null);
			const stop = () => {
				if (!v) return;
				if (places) places.keep(p, v.currentTime, v.duration);
				try { v.pause(); } catch { /* not playing */ }
				v.removeAttribute('src');
				try { v.load(); } catch { /* nothing */ }
			};
			const cannot = () => {
				stop();
				if (v) v.remove();
				v = null;
				hint(t('drive.viewer.cannotPlay', { type: VS.typeName(p) }), [otherApp()].filter(Boolean));
			};

			async function start() {
				const probe = document.createElement('video');
				if (!tried && VS.rareType(p.mime, (m) => probe.canPlayType(m))) {
					hint(t('drive.viewer.cannotPlay', { type: VS.typeName(p) }), [
						otherApp(),
						el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => { tried = true; holder.querySelectorAll('.dvw-note').forEach((x) => x.remove()); start(); } } }, [el('span', { text: t('drive.viewer.tryAnyway') })]),
					].filter(Boolean));
					return;
				}
				const wait = busy();
				holder.appendChild(wait);
				const s = await streamOf(p);
				wait.remove();
				if (gone) { if (s) endStream(s.url); return; }
				if (!s) { hint(t('drive.viewer.failed'), [otherApp()].filter(Boolean)); return; }
				url = s.url;
				v = el('video', { class: 'dvw-player', controls: '', preload: 'metadata', playsinline: '' });
				v.addEventListener('loadedmetadata', () => {
					const at = places && places.get(p);
					if (at && Number.isFinite(v.duration) && at < v.duration - VS.KEEP_MS / 1000) { try { v.currentTime = at; } catch { /* not seekable */ } }
				});
				v.addEventListener('loadeddata', () => {
					// a picture the PC cannot decode (often HEVC without the Windows extension): only the sound plays
					if (v && v.videoWidth === 0 && v.videoHeight === 0) hint(t('drive.viewer.noPictureVideo'), [otherApp()].filter(Boolean));
				});
				v.addEventListener('timeupdate', () => { if (places && v) places.keep(p, v.currentTime, v.duration); });
				v.addEventListener('ended', () => { if (places) places.forget(p); });
				v.addEventListener('error', () => {
					if (!v || gone) return;
					const kind = VS.trouble(v.error ? v.error.code : 0);
					if (kind === 'network') hint(t('drive.viewer.network'), [el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => { const at = v ? v.currentTime : 0; const src = url; v.src = src; try { v.currentTime = at; } catch { /* later */ } v.play().catch(() => {}); holder.querySelectorAll('.dvw-note').forEach((x) => x.remove()); } } }, [el('span', { text: t('drive.viewer.retry') })])]);
					else cannot();
				});
				holder.appendChild(v);
				v.src = url;
				v.play().catch(() => { /* the person presses play */ });
			}

			// the virus scan: blocked — nothing (the lightbox shows the reason); marked — the play button asks first
			if (opts.blocked) {
				holder.appendChild(el('span', { class: 'dpv-big' }, [icon('video', 40, '1.4')]));
			} else if (opts.ask) {
				const btn = el('button', { type: 'button', class: 'dvw-playbtn', 'aria-label': t('drive.viewer.play'), title: t('drive.viewer.play'), on: { click: () => opts.ask(() => { btn.remove(); start(); }) } }, [icon('play', 28)]);
				holder.appendChild(btn);
			} else {
				start();
			}
			return {
				kind: 'video',
				get element() { return v; },
				destroy() { gone = true; stop(); endStream(url); url = null; },
			};
		}

		function fullscreen(target) {
			const d = target.ownerDocument;
			if (d.fullscreenElement) { if (d.exitFullscreen) d.exitFullscreen().catch(() => {}); return; }
			if (target.requestFullscreen) target.requestFullscreen().catch(() => {});
		}

		return { picture, video, fullscreen, canStream };
	}

	root.GCDriveViewer = { create };
})(typeof self !== 'undefined' ? self : this);
