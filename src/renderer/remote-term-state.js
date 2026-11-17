/**
 * GateControl -- SSH devices on the page „Fernzugriff“ (renderer, no DOM access)
 *
 * The details of an SSH device of core's RemoteTerm (design section 1): which tmux choices exist (resume a session,
 * the default session, a new one with a checked name, or only the shell), which one is preselected (the most
 * recently active), the button's label, what goes to remote-term:open, whether the recording hint comes first; and
 * (Fernzugriff 1.8) what can be ended there: sessions, windows, all detached ones, the questions before it.
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

	// ── Fernzugriff 1.8: tmux-Sitzungen und Fenster beenden (design section 8, T1–T4) ──

	/**
	 * What can be ended in a list: nothing with an older plugin (kill false, the dialog as before). With kill: the
	 * sessions in the order of the choices, then those that cannot be resumed (`others`), each with id and windows;
	 * the detached ones for „Alle getrennten Sitzungen beenden“, which shows from two on.
	 */
	function killable(list) {
		if (!list || list.kill !== true) return { kill: false, sessions: [], others: [], detached: [], showAll: false };
		const withId = (x) => x && typeof x.id === 'string' && /^\$\d{1,6}$/.test(x.id);
		const sessions = (list.sessions || []).filter((x) => withId(x) && validName(x.name));
		const others = (list.others || []).filter(withId);
		const detached = [...sessions, ...others].filter((x) => !(x.attached > 0));
		return { kill: true, sessions, others, detached, showAll: detached.length >= 2 };
	}

	/** A session of the list by its id (sessions and others). */
	function findSession(list, id) {
		return [...((list && list.sessions) || []), ...((list && list.others) || [])].find((x) => x.id === id) || null;
	}

	const winList = (x) => (Array.isArray(x && x.windowList) ? x.windowList : []);

	/**
	 * The question before ending. kind 'session' (T2), 'window' (T3), 'detached' (T4).
	 * → { title: [key, vars], sub: [key, vars] | null, lines: [[key, vars]], warn: { title, text } | null, ok: [key, vars],
	 *     danger, items (T4: the detached sessions to tick), request }
	 */
	function killDialog(kind, list, ref) {
		if (kind === 'session') {
			const x = findSession(list, ref && ref.session);
			if (!x) return null;
			const n = x.attached > 0 ? x.attached : 0;
			const wl = winList(x);
			return {
				kind, title: ['remoteTerm.killSessionTitle', { name: x.name }],
				sub: wl.length ? ['remoteTerm.killSessionSub', { n: x.windows || wl.length, cmds: wl.map((w) => w.command || w.name).filter(Boolean).join(', ') }] : null,
				lines: [['remoteTerm.killSessionText', {}]],
				warn: n ? { title: ['remoteTerm.killAttachedTitle', {}], text: ['remoteTerm.killAttachedText', { n }] } : null,
				ok: [n ? 'remoteTerm.killAnyway' : 'remoteTerm.killSessionOk', {}], danger: true, items: null,
				request: { session: x.id },
			};
		}
		if (kind === 'window') {
			const x = findSession(list, ref && ref.session);
			const wl = winList(x);
			const w = wl.find((y) => y.id === (ref && ref.window));
			if (!x || !w) return null;
			const last = wl.length <= 1;
			const lines = [w.command ? ['remoteTerm.killWindowText', { cmd: w.command }] : ['remoteTerm.killWindowTextPlain', {}]];
			lines.push(last ? ['remoteTerm.killLastWindow', {}] : ['remoteTerm.killWindowOthers', { n: wl.length - 1 }]);
			return {
				kind, title: ['remoteTerm.killWindowTitle', { name: w.name || String(w.index) }], sub: ['remoteTerm.killWindowSub', { session: x.name, index: w.index }],
				lines, warn: last && x.attached > 0 ? { title: ['remoteTerm.killAttachedTitle', {}], text: ['remoteTerm.killAttachedText', { n: x.attached }] } : null,
				ok: ['remoteTerm.closeWindowOk', {}], danger: true, items: null, last,
				request: { session: x.id, window: w.id },
			};
		}
		if (kind === 'detached') {
			const k = killable(list);
			if (!k.showAll) return null;
			const keeps = [...k.sessions, ...k.others].filter((x) => x.attached > 0).map((x) => x.name);
			const lines = [['remoteTerm.killSessionText', {}]];
			if (keeps.length) lines.push(['remoteTerm.killDetachedKeeps', { names: keeps.map((nm) => `„${nm}“`).join(', ') }]);
			return {
				kind, title: ['remoteTerm.killDetachedTitle', { n: k.detached.length }], sub: null, lines, warn: null,
				ok: detachedOk(k.detached.length), danger: true,
				items: k.detached.map((x) => ({ id: x.id, name: x.name, windows: x.windows, cmds: winList(x).map((w) => w.command || w.name).filter(Boolean).join(', '), activity: x.activity })),
				request: { sessions: k.detached.map((x) => x.id) },
			};
		}
		return null;
	}

	/** The button of T4 for the sessions still ticked. */
	function detachedOk(n) {
		return n === 1 ? ['remoteTerm.killDetachedOkOne', {}] : ['remoteTerm.killDetachedOk', { n }];
	}

	/**
	 * After a kill: the new list, or a quiet reload (tmux_gone, tmux_changed: nothing in red), or an error.
	 * → { list } | { reload: true } | { error }; plus skippedAttached (T4: attached by now, GateControl kept it).
	 */
	function killOutcome(r) {
		if (!r || typeof r !== 'object') return { error: 'failed' };
		if (r.error === 'tmux_gone' || r.error === 'tmux_changed') return { reload: true };
		if (r.error) return { error: String(r.error) };
		const skippedAttached = (Array.isArray(r.skipped) ? r.skipped : []).filter((x) => x && x.reason === 'attached').length;
		const { killed, skipped, ...list } = r;
		return { list, skippedAttached };
	}

	return { validName, suggestName, choices, initialPick, buttonKey, openParams, minutesAgo, killable, findSession, killDialog, detachedOk, killOutcome };
});
