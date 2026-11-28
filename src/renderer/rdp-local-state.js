/**
 * GateControl -- Remotedesktop "Auf diesem PC" (no DOM, no Electron)
 *
 * What a host of Fernzugriff may do on this PC, and what the person chose for it here:
 *
 *   allowed(route)          what the server's route permits (the ceiling)
 *   sanitizeLocal(x)        a stored / sent choice reduced to known keys and values
 *   effective(route, local) the settings of a connect: the server's route, only ever RESTRICTED by the
 *                           local choice — a local choice can switch something off or pick less, never
 *                           switch on what the server does not permit
 *   openMode(...)           GateControl-Fenster or Windows-Remotedesktop for "Verbinden", with the reason
 *
 * The open mode: the setting "Remotedesktop öffnen in" of the app (rdp.openIn, standard the window),
 * per host overridable ("open" in the local choice), per click from the menu at "Verbinden" (via).
 * RemoteApp routes always open with Windows-Remotedesktop (phase 1).
 *
 * Loaded as a plain script by the renderer (window.GCRdpLocal), required by the main process
 * (src/services/rdp/rdp-manager.js) and by the node tests (test/rdp-local-state.test.js).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCRdpLocal = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const OPEN = ['window', 'mstsc'];
	const DISPLAY = ['window', 'fullscreen', 'multimon'];
	const RESOLUTION = ['server', 'dynamic', 'fixed'];
	const KEYBOARD = ['fullscreen', 'always', 'never'];
	// audio: "local" redirects the most (the sound comes to this PC), "off" the least
	const AUDIO = ['local', 'remote', 'off'];

	/** 1 / true / '1' → true, 0 / false → false, null / undefined → the server's standard. */
	function flag(v, dflt) {
		if (v === null || v === undefined || v === '') return dflt;
		if (typeof v === 'string') return v === '1' || v.toLowerCase() === 'true';
		return !!v;
	}

	/** What the route of the server permits. */
	function allowed(route) {
		const r = route || {};
		const audio = AUDIO.includes(r.audio_mode) ? r.audio_mode : 'local';
		return {
			clipboard: flag(r.redirect_clipboard, true),
			drives: flag(r.redirect_drives, false),
			printers: flag(r.redirect_printers, false),
			smartcards: flag(r.redirect_smartcard, false),
			multimon: flag(r.multi_monitor, false),
			// the server's audio mode and everything that redirects less
			audio: AUDIO.slice(AUDIO.indexOf(audio)),
			remoteApp: typeof r.remote_app === 'string' && r.remote_app.trim() !== '',
		};
	}

	/** The server's own display as a choice of this card. */
	function serverDisplay(route) {
		const r = route || {};
		if (flag(r.multi_monitor, false)) return 'multimon';
		if (r.resolution_mode === 'fullscreen' || !r.resolution_mode) return 'fullscreen';
		return 'window';
	}

	/** Only known keys and values survive; anything else is "as the server says" (absent). */
	function sanitizeLocal(x) {
		const out = {};
		if (!x || typeof x !== 'object') return out;
		if (OPEN.includes(x.open)) out.open = x.open;
		if (DISPLAY.includes(x.display)) out.display = x.display;
		if (RESOLUTION.includes(x.resolution)) out.resolution = x.resolution;
		if (KEYBOARD.includes(x.keyboard)) out.keyboard = x.keyboard;
		if (typeof x.clipboard === 'boolean') out.clipboard = x.clipboard;
		if (typeof x.drives === 'boolean') out.drives = x.drives;
		if (AUDIO.includes(x.audio)) out.audio = x.audio;
		return out;
	}

	/**
	 * A choice the server does not permit is dropped (so a later "permitted" by the admin does not
	 * switch it on by itself, and nothing stored can widen the route).
	 */
	function restrictLocal(route, local) {
		const a = allowed(route);
		const l = sanitizeLocal(local);
		if (l.display === 'multimon' && !a.multimon) delete l.display;
		if (l.clipboard === true && !a.clipboard) delete l.clipboard;
		if (l.drives === true && !a.drives) delete l.drives;
		if (l.audio && !a.audio.includes(l.audio)) delete l.audio;
		return l;
	}

	/** The settings of one connect: the route, restricted by the local choice. */
	function effective(route, local) {
		const r = route || {};
		const a = allowed(r);
		const l = restrictLocal(r, local);
		const display = l.display || serverDisplay(r);
		const fixedByServer = r.resolution_mode === 'fixed';
		let resolution = l.resolution && l.resolution !== 'server' ? l.resolution : (fixedByServer ? 'fixed' : 'dynamic');
		const width = Number.isInteger(r.resolution_width) && r.resolution_width >= 200 ? r.resolution_width : 1920;
		const height = Number.isInteger(r.resolution_height) && r.resolution_height >= 200 ? r.resolution_height : 1080;
		const depth = [15, 16, 24, 32].includes(Number(r.color_depth)) ? Number(r.color_depth) : 32;
		if (display === 'multimon') resolution = 'dynamic';
		return {
			display: { mode: display, resolution, width, height, colorDepth: depth },
			keyboard: l.keyboard || 'fullscreen',
			redirect: {
				clipboard: a.clipboard && l.clipboard !== false,
				drives: a.drives && l.drives !== false,
				printers: a.printers,
				smartcards: a.smartcards,
				audio: l.audio || a.audio[0],
			},
			allow: { clipboard: a.clipboard, drives: a.drives },
		};
	}

	/**
	 * GateControl-Fenster or Windows-Remotedesktop.
	 * @param {object} o
	 * @param {string} [o.via]      the click's choice (menu at "Verbinden", the error view)
	 * @param {object} [o.local]    the host's local choice (open)
	 * @param {string} [o.global]   the app setting rdp.openIn
	 * @param {object} [o.route]    the route (RemoteApp → mstsc)
	 * @param {boolean} [o.hostAvailable=true] gc-rdp-host.exe is there and may start
	 * @returns {{ mode: 'window'|'mstsc', reason: string }}
	 */
	function openMode({ via, local, global, route, hostAvailable = true } = {}) {
		let mode = 'window';
		let reason = 'standard';
		if (OPEN.includes(global)) { mode = global; reason = 'setting'; }
		const l = sanitizeLocal(local);
		if (l.open) { mode = l.open; reason = 'host'; }
		if (OPEN.includes(via)) { mode = via; reason = 'choice'; }
		if (mode === 'window' && allowed(route).remoteApp) return { mode: 'mstsc', reason: 'remoteapp' };
		if (mode === 'window' && !hostAvailable) return { mode: 'mstsc', reason: 'host-missing' };
		return { mode, reason };
	}

	return { OPEN, DISPLAY, RESOLUTION, KEYBOARD, AUDIO, flag, allowed, serverDisplay, sanitizeLocal, restrictLocal, effective, openMode };
});
