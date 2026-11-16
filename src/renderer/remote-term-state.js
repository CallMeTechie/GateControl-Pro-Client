/**
 * GateControl -- SSH devices on the page „Fernzugriff“ (renderer, no DOM access)
 *
 * The details of an SSH device of core's RemoteTerm (design section 1): which tmux choices exist (resume a session,
 * the default session, a new one with a checked name, or only the shell), which one is preselected (the most
 * recently active), the button's label, what goes to remote-term:open, whether the recording hint comes first.
 * Loaded as a plain script before renderer.js (window.GCRemoteTermState) and required by the node tests.
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCRemoteTermState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const TMUX_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;

	const validName = (n) => TMUX_RE.test(String(n || ''));

	/** „Neue Sitzung“: tmux, taken → tmux-2 … */
	function suggestName(taken, base) {
		const b = validName(base) && String(base).length <= 28 ? base : 'tmux';
		const set = new Set(taken || []);
		if (!set.has(b)) return b;
		let i = 2;
		while (set.has(`${b}-${i}`) && i < 999) i++;
		return `${b}-${i}`;
	}

	/**
	 * The choices of a device. tmuxState: { loading } | { list: { sessions, hidden, tmux, hostKey } } | { error: code }
	 * → { kind: 'locked' | 'loading' | 'choices', notice: null | 'first' | 'missing' | 'error', options: [...], hidden }
	 */
	function choices(device, tmuxState, locked) {
		if (locked) return { kind: 'locked', options: [], notice: null, hidden: 0 };
		if (!device.tmux) return { kind: 'choices', notice: null, hidden: 0, options: [{ key: 'plain' }] };
		const st = tmuxState || { loading: true };
		if (st.loading) return { kind: 'loading', options: [], notice: null, hidden: 0 };
		if (st.error === 'host_key_mismatch') return { kind: 'locked', options: [], notice: null, hidden: 0 };
		if (st.error === 'tmux_unavailable') return { kind: 'choices', notice: 'missing', hidden: 0, options: [{ key: 'plain' }] };
		const list = st.list || { sessions: [], hidden: 0, tmux: device.tmux, hostKey: null };
		const notice = list.hostKey === 'unpinned' || st.error === 'host_key_unpinned' ? 'first' : st.error ? 'error' : null;
		const sessions = (list.sessions || []).filter((s) => validName(s.name));
		const options = sessions.map((s) => ({ key: 'resume:' + s.name, name: s.name, windows: s.windows, attached: s.attached, activity: s.activity }));
		options.push({ key: 'default', tmux: device.tmux });
		options.push({ key: 'new', suggestion: suggestName(sessions.map((s) => s.name), device.tmux) });
		return { kind: 'choices', notice, hidden: list.hidden || 0, options };
	}

	/** The preselected choice: the most recently active session (the list comes sorted), else the default. */
	function initialPick(c) {
		if (!c || !c.options.length) return null;
		return c.options[0].key;
	}

	function buttonKey(c, pick) {
		if (c.notice === 'missing') return 'remoteTerm.anyway';
		return String(pick || '').startsWith('resume:') ? 'remoteTerm.resumeBtn' : 'remoteTerm.connect';
	}

	/** What remote-term:open gets; null when the new name is not valid. */
	function openParams(device, pick, newName, record) {
		let tmux = null;
		if (String(pick).startsWith('resume:')) tmux = { attach: String(pick).slice(7) };
		else if (pick === 'new') {
			if (!validName(newName)) return null;
			tmux = { create: newName };
		}
		return { deviceId: device.id, deviceName: device.name, tmux, recording: device.recording, record: device.recording === 'optional' && record === true };
	}

	/** „zuletzt aktiv vor 2 Min.“ */
	function minutesAgo(ms, now = Date.now()) {
		return ms ? Math.max(0, Math.round((now - ms) / 60000)) : null;
	}

	return { validName, suggestName, choices, initialPick, buttonKey, openParams, minutesAgo };
});
