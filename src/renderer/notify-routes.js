/**
 * GateControl -- "Wo Mitteilungen erscheinen" (renderer)
 *
 * Per kind of notification (push topic, core 1.191) the chat it appears in:
 * the pinned chat "GateControl" (default), the family chat (Familie group,
 * for everyone in the household — only adults may choose it: `canFamily`)
 * or an own chat of its source ("Schule", only for the person). Locked kinds
 * (security, admin notices) always stay in GateControl; without a sink
 * (the Messenger plugin) everything does.
 *
 * Shown in Einstellungen › Benachrichtigungen (skin 'settings') and in the
 * chat settings (skin 'chat'); the same file is used by Pro and Community.
 * Data: window.gatecontrol.notify.routes() / setRoute(topic, dest) (core
 * NotificationCenter → GET/PUT /api/v1/client/push/routes; on "own" the
 * answer names the source's own chat, GateControl 1.192: a toast says
 * whether it was created or is the existing one, and the page's onChat
 * reloads the chat list); texts:
 * push.routes.* of the core locales. The view logic is pure and exported for
 * the node tests (test/notify-routes.test.js); mount() needs a DOM.
 *
 * Note: server text only ever goes into textContent / attributes.
 */
(function (root, factory) {
	const api = factory(root);
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCNotifyRoutes = api;
})(typeof self !== 'undefined' ? self : this, function (root) {
	'use strict';

	const DESTS = ['inbox', 'family', 'own'];
	const LOCK_PATH = ['M6 11h12v10H6z', 'M8 11V8a4 4 0 0 1 8 0v3'];
	const NETWORK = ['network', 'timeout', 'ECONNREFUSED', 'ECONNRESET', 'ENOTFOUND', 'ETIMEDOUT', 'ECONNABORTED', 'EAI_AGAIN', 'not_configured'];

	const str = (v) => (v === null || v === undefined ? '' : String(v));

	/** Where `topic` really ends up: without a sink, or locked, always GateControl. */
	function effective(routes, topic) {
		if (!routes || !routes.sink || !topic || topic.locked) return 'inbox';
		return DESTS.includes(topic.dest) ? topic.dest : 'inbox';
	}

	/**
	 * The choices for `topic`: GateControl always; the family chat for those
	 * who may set it (or while it is set, shown but not changeable); the own
	 * chat with a sink.
	 */
	function options(routes, topic) {
		if (!routes || !routes.sink || !topic || topic.locked) return ['inbox'];
		return ['inbox', routes.canFamily || topic.dest === 'family' ? 'family' : null, 'own'].filter(Boolean);
	}

	/** This person can change `topic` (not locked, a sink, and no family choice they may not lift). */
	function editable(routes, topic) {
		return !!routes && !!routes.sink && !!topic && !topic.locked && (topic.dest !== 'family' || routes.canFamily === true);
	}

	/** `routes` with `topicId` going to `dest` (shown before the server answered). */
	function withDest(routes, topicId, dest) {
		if (!routes || !Array.isArray(routes.groups)) return routes;
		return {
			...routes,
			groups: routes.groups.map((g) => ({
				...g,
				topics: (g.topics || []).map((tp) => (tp.id === topicId ? { ...tp, dest, familySetBy: dest === 'family' ? tp.familySetBy : null } : tp)),
			})),
		};
	}

	/** Text of a destination for `group` (the own chat is named after its source). */
	function destLabel(dest, group, t) {
		if (dest === 'family') return t('push.routes.dest.family');
		if (dest === 'own') return t('push.routes.dest.own', { label: str(group && group.label) });
		return t('push.routes.dest.inbox');
	}

	/** Text of a choice in the picker ("Familien-Chat – für alle in Familie sichtbar"). */
	function optionLabel(dest, group, t) {
		if (dest === 'family') return t('push.routes.option.family');
		if (dest === 'own') return t('push.routes.option.own', { label: str(group && group.label) });
		return t('push.routes.option.inbox');
	}

	/** The line under a kind: what its current choice means. */
	function hint(routes, topic, group, t) {
		// locked kinds: the lock and "immer GateControl" are the control already
		if (!topic || topic.locked) return '';
		const dest = effective(routes, topic);
		if (dest === 'family') {
			const by = topic.familySetBy ? t('push.routes.familySetBy', { name: topic.familySetBy }) : t('push.routes.familySet');
			return routes && routes.canFamily ? `${t('push.routes.hint.family')} · ${by}` : `${by} · ${t('push.routes.familyOnlyAdults')}`;
		}
		if (dest === 'own') return t('push.routes.hint.own', { label: str(group && group.label) });
		return t('push.routes.hint.inbox');
	}

	/** i18n key of a refusal (setRoute / routes error code). */
	function errorKey(code) {
		const c = str(code);
		if (c === 'family_not_allowed') return 'push.routes.err.family';
		if (c === 'locked') return 'push.routes.err.locked';
		if (c === 'no_sink') return 'push.routes.err.noSink';
		if (c === 'no_user' || c === 'forbidden' || c === 'http_403') return 'push.routes.err.forbidden';
		if (c === 'unknown_topic') return 'push.routes.err.unknownTopic';
		if (c === 'push_disabled') return 'push.routes.err.pushDisabled';
		if (NETWORK.includes(c)) return 'push.routes.err.network';
		return 'push.routes.err.failed';
	}

	/**
	 * The confirmation after a choice of the own chat: "Chat „Schule“ angelegt"
	 * (created) or "Erscheint im vorhandenen Chat „Schule“" — '' when the answer
	 * names no chat (inbox / family, older servers or cores, failures).
	 */
	function chatNotice(res, dest, t) {
		const chat = res && res.ok && dest === 'own' ? res.chat : null;
		if (!chat || typeof chat !== 'object' || !str(chat.label)) return '';
		return t(chat.created === true ? 'push.routes.chatCreated' : 'push.routes.chatExisting', { label: str(chat.label) });
	}

	/**
	 * State of the page from a routes() answer: 'unsupported' (older server or
	 * an app core without the API — the entries are hidden), 'error', 'empty'
	 * or 'ready' (+ routes).
	 */
	function viewState(res) {
		if (!res || typeof res !== 'object') return { state: 'error', routes: null };
		if (res.ok === false) {
			if (res.error === 'unsupported' || res.error === 'not_attached') return { state: 'unsupported', routes: null, error: res.error };
			return { state: 'error', routes: null, error: str(res.error) || 'failed' };
		}
		const r = res.routes;
		if (!r || !Array.isArray(r.groups)) return { state: 'error', routes: null, error: 'bad_response' };
		const any = r.groups.some((g) => g && Array.isArray(g.topics) && g.topics.length);
		return { state: any ? 'ready' : 'empty', routes: r };
	}

	/** Whether the app's core offers the routes API at all (older cores: no entry). */
	function supported(api) {
		return !!api && typeof api.routes === 'function' && typeof api.setRoute === 'function';
	}

	// ── DOM (renderer only) ─────────────────────────────────

	const SKINS = {
		// Einstellungen › Benachrichtigungen: rows like "Themen auf diesem PC"
		settings: {
			group: 'nr-group', head: 'nr-src', card: 'nr-card', row: 'set-row compact nr-row', tx: 'grow', title: 'set-row-title', desc: 'set-row-desc', note: 'set-row-desc nr-note', select: 'inp select nr-select',
		},
		// chat settings page: groups and rows like its other sections
		chat: {
			group: 'cv-set-group', head: 'cv-sec', card: 'cv-set-card', row: 'cv-pref nr-row', tx: 'cv-pref-tx', title: null, desc: null, note: 'cv-note nr-note', select: 'inp cv-select nr-select',
		},
	};

	function el(tag, attrs, kids) {
		const n = root.document.createElement(tag);
		for (const [k, v] of Object.entries(attrs || {})) {
			if (v === null || v === undefined || v === false) continue;
			if (k === 'text') n.textContent = String(v);
			else if (k === 'class') n.className = v;
			else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
			else n.setAttribute(k, v === true ? '' : String(v));
		}
		for (const c of kids || []) if (c !== null && c !== undefined && c !== false) n.appendChild(typeof c === 'string' ? root.document.createTextNode(c) : c);
		return n;
	}

	function lockIcon() {
		const NS = 'http://www.w3.org/2000/svg';
		const s = root.document.createElementNS(NS, 'svg');
		for (const [k, v] of [['viewBox', '0 0 24 24'], ['width', '14'], ['height', '14'], ['fill', 'none'], ['stroke', 'currentColor'], ['stroke-width', '2'], ['stroke-linecap', 'round'], ['stroke-linejoin', 'round'], ['aria-hidden', 'true']]) s.setAttribute(k, v);
		for (const d of LOCK_PATH) {
			const p = root.document.createElementNS(NS, 'path');
			p.setAttribute('d', d);
			s.appendChild(p);
		}
		return s;
	}

	/**
	 * Draw the page into `host` and load it.
	 * @param {HTMLElement} host - emptied and filled
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.notify (routes, setRoute)
	 * @param {Function} o.t - i18n
	 * @param {(msg: string, type?: string) => void} [o.toast]
	 * @param {'settings'|'chat'} [o.skin='settings']
	 * @param {(state: string) => void} [o.onState] - 'unsupported' | 'error' | 'empty' | 'ready' after each load
	 * @param {(chat: object) => void} [o.onChat] - after "own" named the source's own chat (reload the chat list)
	 * @returns {{ load(): Promise<string>, render(): void }}
	 */
	function mount(host, o) {
		const t = o.t;
		const skin = SKINS[o.skin] || SKINS.settings;
		const toast = typeof o.toast === 'function' ? o.toast : () => {};
		let view = { state: 'loading', routes: null };
		let busy = null; // topic id being saved
		let seq = 0;

		const clear = () => { while (host.firstChild) host.removeChild(host.firstChild); };
		const note = (text, extra) => el('p', { class: `${skin.note}${extra ? ` ${extra}` : ''}`, text });
		const tx = (title, desc) => el('span', { class: skin.tx }, [
			skin.title ? el('div', { class: skin.title, text: title }) : el('b', { text: title }),
			desc ? (skin.desc ? el('div', { class: skin.desc, text: desc }) : el('small', { text: desc })) : null,
		]);

		function render() {
			clear();
			host.setAttribute('data-state', view.state);
			if (view.state === 'loading') { host.appendChild(note(t('push.routes.loading'))); return; }
			if (view.state === 'unsupported') { host.appendChild(note(t('push.routes.unsupported'))); return; }
			if (view.state === 'error') {
				host.appendChild(note(t('push.routes.loadFailed')));
				host.appendChild(el('button', { type: 'button', class: 'btn btn-sec btn-sm nr-retry', text: t('push.routes.retry'), on: { click: () => load() } }));
				return;
			}
			const r = view.routes;
			host.appendChild(note(t('push.routes.intro')));
			if (!r.sink) host.appendChild(note(t('push.routes.noSink'), 'nr-nosink'));
			else host.appendChild(note(t('push.routes.introFamily')));
			if (view.state === 'empty') { host.appendChild(note(t('push.routes.empty'))); return; }
			for (const g of r.groups) {
				const card = el('div', { class: skin.card, role: 'list' });
				for (const tp of g.topics) card.appendChild(row(r, g, tp));
				host.appendChild(el('div', { class: skin.group, 'data-source': g.source }, [el('div', { class: skin.head, text: g.label }), card]));
			}
			host.appendChild(note(t('push.routes.footer')));
		}

		function row(r, g, tp) {
			let control;
			if (tp.locked) {
				control = el('span', { class: 'nr-locked', title: t('push.routes.lockedA11y'), 'aria-label': t('push.routes.lockedA11y') }, [lockIcon(), el('span', { text: t('push.routes.locked') })]);
			} else if (!editable(r, tp)) {
				control = el('span', { class: 'nr-fixed', text: destLabel(effective(r, tp), g, t) });
			} else {
				const sel = el('select', { class: skin.select, 'aria-label': `${tp.label}: ${t('push.routes.title')}`, disabled: busy === tp.id ? true : null, 'data-topic': tp.id });
				for (const d of options(r, tp)) sel.appendChild(el('option', { value: d, text: optionLabel(d, g, t) }));
				sel.value = effective(r, tp);
				sel.addEventListener('change', () => save(tp, g, sel.value));
				control = sel;
			}
			return el('div', { class: skin.row, role: 'listitem', 'data-topic': tp.id, 'data-dest': effective(r, tp) }, [tx(tp.label, hint(r, tp, g, t)), control]);
		}

		async function save(tp, g, dest) {
			if (busy || !view.routes || dest === effective(view.routes, tp)) { render(); return; }
			const before = view.routes;
			busy = tp.id;
			view = { ...view, routes: withDest(before, tp.id, dest) };
			render();
			const res = await Promise.resolve(o.api.setRoute(tp.id, dest)).catch((e) => ({ ok: false, error: e && e.message }));
			busy = null;
			if (res && res.ok && res.routes) {
				view = viewState(res);
				const msg = chatNotice(res, dest, t);
				if (msg) {
					toast(msg, 'success');
					if (typeof o.onChat === 'function') Promise.resolve().then(() => o.onChat(res.chat)).catch(() => {});
				}
			} else {
				view = { ...view, routes: before };
				if (res && res.error === 'unsupported') view = { state: 'unsupported', routes: null };
				toast(t(errorKey(res && res.error)), 'error');
			}
			render();
			if (typeof o.onState === 'function') o.onState(view.state);
		}

		async function load() {
			const mine = ++seq;
			if (!supported(o.api)) {
				view = { state: 'unsupported', routes: null };
			} else {
				if (view.state !== 'ready') { view = { state: 'loading', routes: null }; render(); }
				const res = await Promise.resolve(o.api.routes()).catch((e) => ({ ok: false, error: e && e.message }));
				if (mine !== seq) return view.state;
				view = viewState(res);
			}
			render();
			if (typeof o.onState === 'function') o.onState(view.state);
			return view.state;
		}

		render();
		return { load, render };
	}

	return {
		DESTS,
		effective,
		options,
		editable,
		withDest,
		destLabel,
		optionLabel,
		hint,
		errorKey,
		chatNotice,
		viewState,
		supported,
		mount,
	};
});
