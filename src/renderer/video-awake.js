/**
 * GateControl -- the screen stays on while a video plays (Drive's viewer, the vault's viewer also in full screen, the
 * clips of the cameras) — as on Android (KeepScreenOnWhilePlaying): only while the video really plays. 'play' /
 * 'playing' on; 'pause', 'ended', 'error', 'waiting' (buffering), 'emptied' / 'abort' (another one shown, closed) and
 * release() (the viewer closes) off. While it plays it says so again every 30 s, a video taken out of the page counts
 * as stopped.
 *
 * The main process holds one blocker for all (main/media-awake.js, the same as the Medien player): each video its own
 * key, so one that stops never frees the screen of another that still plays. The live picture of the cameras is not
 * watched (`when`: the camera page only while a clip plays) — like the live preview on the start page.
 *
 *   const h = GCVideoAwake.watch(videoEl, { when: () => !!S.clip });   …   h.release();
 *
 * Without DOM access at load time so it can be unit-tested (test/video-awake.test.js).
 */
(function (root) {
	'use strict';

	const REFRESH_MS = 30000;
	const ON = ['play', 'playing'];
	const OFF = ['pause', 'ended', 'error', 'waiting', 'emptied', 'abort'];

	/**
	 * @param {object} o
	 * @param {(key: string, state: 'playing' | 'stopped') => any} o.send - window.gatecontrol.videoAwake
	 * @param {object} [o.timers] - { setInterval, clearInterval } (tests)
	 * @param {number} [o.refreshMs]
	 */
	function create({ send, timers = { setInterval: (f, ms) => setInterval(f, ms), clearInterval: (t) => clearInterval(t) }, refreshMs = REFRESH_MS } = {}) {
		let n = 0;
		const tell = (key, state) => {
			try { Promise.resolve(send && send(key, state)).catch(() => {}); } catch { /* no bridge */ }
		};

		/** Watches `v` (an HTMLVideoElement); → { release(), get holding } */
		function watch(v, { when = null } = {}) {
			if (!v || typeof v.addEventListener !== 'function') return { release() {}, get holding() { return false; } };
			n += 1;
			const key = `v${n}`;
			let holding = false;
			let tick = null;
			let released = false;
			const plays = () => !v.paused && !v.ended && v.isConnected !== false;

			function off() {
				if (tick) { timers.clearInterval(tick); tick = null; }
				if (!holding) return;
				holding = false;
				tell(key, 'stopped');
			}

			function on() {
				if (released) return;
				if (when && !when()) { off(); return; }
				if (holding) return;
				holding = true;
				tell(key, 'playing');
				tick = timers.setInterval(() => {
					if (!plays() || (when && !when())) off();
					else tell(key, 'playing');
				}, refreshMs);
			}

			for (const ev of ON) v.addEventListener(ev, on);
			for (const ev of OFF) v.addEventListener(ev, off);
			// already playing when watched (autoplay that started before)
			if (plays() && v.readyState > 2) on();

			return {
				release() {
					if (released) return;
					released = true;
					for (const ev of ON) v.removeEventListener(ev, on);
					for (const ev of OFF) v.removeEventListener(ev, off);
					off();
				},
				get holding() { return holding; },
			};
		}

		return { watch };
	}

	// the app's instance: window.gatecontrol.videoAwake (preload) when the page has it
	const app = create({ send: (key, state) => (root.gatecontrol && typeof root.gatecontrol.videoAwake === 'function' ? root.gatecontrol.videoAwake(key, state) : null) });

	root.GCVideoAwake = { create, watch: app.watch, REFRESH_MS, ON, OFF };
	if (typeof module !== 'undefined' && module.exports) module.exports = root.GCVideoAwake;
})(typeof self !== 'undefined' ? self : this);
