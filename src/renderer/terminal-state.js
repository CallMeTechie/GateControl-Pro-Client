/**
 * GateControl -- SSH terminal window state (renderer, no DOM access)
 *
 * What the tab, the bar, the status line and the card over the terminal show for a session of core's RemoteTerm
 * (states connecting | hostkey | ready | reconnecting | offline | exited | failed), the text of an error code (design
 * „Fehlertexte“), pasting (more than one line asks first, design question 6), the font steps, the fingerprint in
 * groups. Loaded as a plain script before terminal.js (window.GCTermState) and required by the node tests.
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCTermState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const fill = (s, vars) => {
		const m = new Map(Object.entries(vars || {}));
		return String(s || '').replace(/\{\{\s*(\w+)\s*\}\}/g, (_x, k) => (m.get(k) != null ? String(m.get(k)) : ''));
	};

	/** The key of an error code in texts.errors. */
	function errorKey(code) {
		switch (code) {
			case 'host_key_mismatch': case 'host_key_rejected': case 'host_key_unpinned':
			case 'recording_unavailable': case 'plugin_unavailable': case 'shell_refused': case 'maintenance': case 'no_right':
				return code;
			case 'auth_failed': case 'key_unreadable': case 'credential_required': case 'credential_unreadable': case 'credential_missing': return 'auth';
			case 'http_503': case 'offline': return 'plugin_unavailable';
			case 'unreachable': case 'timeout': case 'listener_required': case 'hello_timeout': case 'connection_lost': case 'network': return 'unreachable';
			case 'limit': case 'limit_reached': case 'rate_limited': case 'http_429': return 'limit';
			case 'not_found': case 'http_404': return 'expired';
			case 'forbidden': return 'no_right';
			default: return 'other';
		}
	}

	function errorText(code, texts) {
		const e = (texts && texts.errors) || {};
		return fill(e[errorKey(code)] || e.other || code, { code });
	}

	/** Tab dot: live (green), working (amber), ended (grey), locked/failed (red). */
	function tone(s) {
		if (!s) return 'off';
		if (s.state === 'ready') return 'ok';
		if (s.state === 'connecting' || s.state === 'reconnecting' || s.state === 'hostkey') return 'warn';
		if (s.state === 'failed' && (s.verdict === 'locked' || s.verdict === 'final')) return 'err';
		return 'off';
	}

	function tabLabel(s) {
		return s.tmux ? `${s.deviceName} · ${s.tmux}` : s.deviceName;
	}

	/** The meta line next to the name: tmux, size. */
	function meta(s) {
		const out = [];
		if (s.tmux && !s.tmuxMissing) out.push(`tmux: ${s.tmux}`);
		if (s.cols && s.rows) out.push(`${s.cols}×${s.rows}`);
		return out.join(' · ');
	}

	function stateText(s, texts) {
		if (!s) return '';
		switch (s.state) {
			case 'ready': return s.view ? texts.viewOnly : texts.connected;
			case 'connecting': case 'hostkey': return s.attempt > 0 ? texts.reconnecting : texts.connecting;
			case 'reconnecting': return texts.reconnecting;
			case 'offline': return texts.offline;
			default: return texts.ended;
		}
	}

	/**
	 * The card over the dimmed terminal, or null. Actions: try (now), reconnect, close (the tab), disconnect.
	 * @param {object} s - status of RemoteTerm
	 * @param {number} now
	 */
	function overlay(s, texts, now = Date.now()) {
		if (!s) return null;
		const keeps = s.tmux && !s.tmuxMissing;
		switch (s.state) {
			case 'connecting':
				return s.attempt > 0 ? null : { kind: 'hint', text: fill(texts.connectingTo, { name: s.deviceName }) };
			case 'reconnecting': {
				const secs = Math.max(0, Math.ceil(((s.at || now) - now) / 1000));
				return { kind: 'card', title: texts.lostTitle,
					text: [fill(texts.lostText, { s: secs, n: s.attempt }), keeps ? fill(texts.tmuxKeeps, { tmux: s.tmux }) : ''].filter(Boolean).join(' '),
					actions: [{ act: 'disconnect', label: texts.disconnect }, { act: 'try', label: texts.tryNow, primary: true }] };
			}
			case 'offline':
				return { kind: 'card', title: fill(texts.offlineTitle, { name: s.deviceName }),
					text: [texts.offlineText, keeps ? fill(texts.offlineTmux, { tmux: s.tmux }) : ''].filter(Boolean).join(' '),
					actions: [{ act: 'reconnect', label: texts.reconnect, primary: true }] };
			case 'exited': {
				const admin = s.reason === 'ended_by_plugin';
				const text = admin ? texts.exitAdmin : s.reason === 'connection_lost' ? texts.exitLost : keeps ? texts.exitTmux : texts.exitShell;
				const actions = [{ act: 'close', label: texts.closeTab }];
				if (!admin) actions.push({ act: 'reconnect', label: texts.reconnect, primary: true });
				return { kind: 'card', title: texts.exitTitle, text, actions };
			}
			case 'failed': {
				if (s.verdict === 'locked') return { kind: 'locked' };
				const actions = [{ act: 'close', label: texts.closeTab }];
				if (s.code === 'host_key_rejected' || s.verdict === 'limit') actions.push({ act: 'reconnect', label: texts.reconnect, primary: true });
				return { kind: 'card', title: texts.ended, text: errorText(s.code, texts), actions };
			}
			default: return null;
		}
	}

	/** Input only while ready and allowed. */
	const canType = (s) => !!(s && s.state === 'ready' && !s.view);

	/** Lines of a paste; a trailing line break does not count. */
	function pasteLines(text) {
		const x = String(text || '').replace(/\r\n?/g, '\n').replace(/\n+$/, '');
		return x ? x.split('\n').length : 0;
	}

	/** What a paste sends: CR line ends, no ESC or other control characters (a paste cannot end a bracketed paste). */
	function pasteText(text) {
		// eslint-disable-next-line no-control-regex
		return String(text || '').replace(/\r\n?|\n/g, '\r').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '');
	}

	function clampFont(px, min = 9, max = 28) {
		const v = Math.round(Number(px));
		return Number.isFinite(v) ? Math.max(min, Math.min(max, v)) : 14;
	}

	return { fill, errorKey, errorText, tone, tabLabel, meta, stateText, overlay, canType, pasteLines, pasteText, clampFont };
});
