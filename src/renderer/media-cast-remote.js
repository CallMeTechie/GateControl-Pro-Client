/**
 * GateControl -- "Auf TV/PC abspielen": this PC as the receiver (renderer, no DOM access)
 *
 * The phone sends a title to this PC (plugin "Medien", cast contract v1; the core's MediaCastReceiver checks, finds the
 * own source and asks the detail by the network rule): `cast.onPlay` opens Medien and the player at the place, with the
 * phone's sound and subtitle; the player's top line says "Vom Handy gesteuert · <Handy>". The phone stays the remote:
 * `cast.onCommand` (Pause, Abspielen, Spulen, Springen, Ton, Untertitel, Lautstärke, Stopp, Stand) goes to the
 * player's `remote`, and every change of the player goes back as a state (`cast.state`: the core tells the phone what
 * is worth a message — a change, a jump, a heartbeat). When the player closes the phone hears why (its "Stopp", the
 * end, closed on this PC, another title, an error).
 *
 * Loaded as a plain script after media-player.js (window.GCMediaCastRemote) and required by the node tests
 * (test/media-cast-remote.test.js).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCMediaCastRemote = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	/** A state of a playing player goes to the core at most this often (the core decides what reaches the phone). */
	const TICK_MS = 2000;

	/**
	 * Sound and subtitles of the player's version as the phone shows them (the labels of the player's panel): ids are
	 * Jellyfin's stream index (`a3`, `s5`), the subtitle "Aus" is `off` — the core maps them back. A share's file has none.
	 */
	function tracksOf(snap, MS, t, caps) {
		const v = snap && snap.version;
		if (!v || snap.share || !MS) return { audio: [], subtitles: [] };
		const play = snap.play || {};
		const audio = MS.audioOptions(v, caps || {}, t)
			.filter((a) => Number.isInteger(a.value) && a.value >= 0)
			.map((a) => ({ id: `a${a.value}`, label: String(a.label).slice(0, 120), selected: a.value === play.audioIndex }));
		const subs = MS.subtitleOptions(v, t).filter((s) => Number.isInteger(s.value));
		const cur = Number.isInteger(play.subtitleIndex) ? play.subtitleIndex : -1;
		const subtitles = subs.length > 1
			? subs.map((s) => ({ id: s.value < 0 ? 'off' : `s${s.value}`, label: String(s.label).slice(0, 120), selected: s.value < 0 ? cur < 0 : s.value === cur }))
			: [];
		return { audio, subtitles };
	}

	/** The player's snapshot → media:cast:state's argument. */
	function stateOf(snap, MS, t, caps) {
		const tr = tracksOf(snap, MS, t, caps);
		return {
			phase: snap.phase,
			positionMs: Math.max(0, Math.floor(snap.positionMs || 0)),
			durationMs: Math.max(0, Math.floor(snap.durationMs || 0)),
			title: snap.title || null,
			audio: tr.audio,
			subtitles: tr.subtitles,
			volume: Number.isFinite(snap.volume) ? snap.volume : undefined,
			muted: typeof snap.muted === 'boolean' ? snap.muted : undefined,
		};
	}

	/** Why the player closed → media:cast:closed's flags. */
	function closedOf(end, snap) {
		const e = end || {};
		return {
			positionMs: Math.max(0, Math.floor(e.positionMs || 0)),
			durationMs: Math.max(0, Math.floor(e.durationMs || 0)),
			byRemote: e.why === 'remote',
			ended: e.why === 'ended',
			failed: e.why !== 'remote' && !!snap && snap.phase === 'failed',
		};
	}

	/**
	 * Wires the core's receiver to the player.
	 * @param {object} o
	 * @param {object} o.cast - window.gatecontrol.media.cast (status, opened, state, closed, onPlay, onCommand, onSession)
	 * @param {object} o.player - the mounted player (play, close, remote, state)
	 * @param {Function} [o.openPage] - shows the page Medien (the player belongs to it)
	 * @param {object} [o.MS] - GCMediaState (track labels)
	 * @param {Function} [o.t]
	 * @param {Function} [o.caps] - what Chromium plays (the player's caps), for the sound labels
	 * @param {Function} [o.now]
	 */
	function mount(o) {
		const cast = o.cast;
		const player = o.player;
		const t = o.t || ((k) => k);
		const now = o.now || (() => Date.now());
		let cur = null;     // { session, controllerName, req }
		let lastAt = 0;
		let lastPhase = null;
		const unsub = [];

		const mine = () => !!cur && !!player.state && player.state.req === cur.req && player.open;

		function report(force) {
			if (!mine()) return;
			const snap = player.remote.snapshot();
			if (snap.phase === 'failed') {
				// the player shows its error ("Erneut versuchen" works here): for the phone the session is over
				cur.lastSnap = snap;
				ended(cur.session, { why: 'error', positionMs: snap.positionMs, durationMs: snap.durationMs });
				return;
			}
			lastAt = now();
			lastPhase = snap.phase;
			Promise.resolve(cast.state(cur.session, { ...stateOf(snap, o.MS, t, o.caps ? o.caps() : null), force: force === true })).catch(() => {});
		}

		/** A change of the player: at once on events, while it plays at most every TICK_MS. */
		function onChange(why) {
			if (!mine()) return;
			if (why === 'time') {
				const snap = player.remote.snapshot();
				if (snap.phase === lastPhase && now() - lastAt < TICK_MS) return;
			}
			report(false);
		}

		function ended(session, end) {
			if (!cur || cur.session !== session) return;
			const snap = cur.lastSnap;
			cur = null;
			Promise.resolve(cast.closed(session, closedOf(end, snap))).catch(() => {});
		}

		async function onPlay(p) {
			if (!p || !p.session || !p.item) return;
			if (typeof o.openPage === 'function') o.openPage();
			const session = p.session;
			const req = {
				item: p.item,
				detail: p.detail || null,
				startMs: p.startMs || 0,
				audioIndex: Number.isInteger(p.audioIndex) ? p.audioIndex : undefined,
				subtitleIndex: Number.isInteger(p.subtitleIndex) ? p.subtitleIndex : undefined,
				cast: { session, controllerName: p.controllerName || null },
				onEnd: (end) => ended(session, end),
			};
			cur = { session, controllerName: p.controllerName || null, req, lastSnap: null };
			lastAt = 0;
			lastPhase = null;
			const started = player.play(req);
			Promise.resolve(cast.opened(session)).catch(() => {});
			await started;
		}

		function onCommand(c) {
			if (!c || !cur || c.session !== cur.session) return;
			const r = player.remote;
			if (!mine()) {
				// not shown (yet): only the end matters
				if (c.cmd === 'stop') cur = null;
				return;
			}
			switch (c.cmd) {
				case 'play': r.play(); break;
				case 'pause': r.pause(); break;
				case 'seek': r.seekTo(c.positionMs); break;
				case 'seekBy': r.seekBy(c.deltaMs); break;
				case 'audio': r.audio(c.audioIndex); break;
				case 'subtitle': r.subtitle(c.subtitleIndex); break;
				case 'volume': r.volume(c.volume, c.muted); break;
				case 'status': report(true); break;
				case 'stop': r.stop(); break;
				default: break;
			}
		}

		unsub.push(cast.onPlay((p) => { onPlay(p).catch(() => {}); }));
		unsub.push(cast.onCommand(onCommand));

		return {
			/** The player's o.onChange. */
			onChange(why) {
				if (cur && mine()) cur.lastSnap = player.remote.snapshot();
				onChange(why);
			},
			get session() { return cur ? cur.session : null; },
			stop() { for (const off of unsub.splice(0)) { try { if (typeof off === 'function') off(); } catch { /* gone */ } } },
		};
	}

	return { TICK_MS, tracksOf, stateOf, closedOf, mount };
});
