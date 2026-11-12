/**
 * GateControl -- DNS-Schutz (renderer view of the card on the start page)
 *
 * The card "DNS-Schutz" and, next to it, "Top gesperrte Domains" on
 * "Übersicht": the DNS filter of the VPN devices (plugin gatecontrol-dns).
 * - active: the counters of today and the chips to pause for this device
 *   (only the durations the server allows; "Bis ich wieder einschalte" greyed
 *   unless the admin enabled it), or the note why pausing is not allowed;
 * - paused: until when, the time left counting down, "Wieder einschalten"
 *   and "+30 Min." when the server allows them, who paused;
 * - filter down ("fallback"): the warning, no buttons;
 * - not filtered / starting / not reachable: one line.
 * Both cards are hidden while the server reports no DNS protection (older
 * server, no plugin, switched off) — the start page then looks as before.
 *
 * Data: window.gatecontrol.dnsProtect (core DnsProtectService over IPC: one
 * snapshot, pushed on every change); texts: dnsProtect.* of the core locales;
 * view logic without DOM: dns-state.js (window.GCDnsState).
 *
 * Note: server text only ever goes into textContent / attributes; icons are
 * built from static path data with createElementNS (no innerHTML).
 */
(function (root) {
	'use strict';

	const DS = root.GCDnsState;
	const NS = 'http://www.w3.org/2000/svg';
	const SHIELD = 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z';
	const ICONS = {
		shield: `${SHIELD}|m9 12 2 2 4-4`,
		shieldPause: `${SHIELD}|M10 9.5v5M14 9.5v5`,
		shieldX: `${SHIELD}|m9.5 9.5 5 5M14.5 9.5l-5 5`,
		shieldOff: `${SHIELD}|m4 4 16 16`,
		clock: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z|M12 7v5l3 2',
		lock: 'M5 11h14v10H5z|M8 11V7a4 4 0 0 1 8 0v4',
		warn: 'M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z|M12 9v4M12 17h.01',
		refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8|M21 3v5h-5',
	};
	const TONES = { ok: 'c-ok', warn: 'c-warn', err: 'c-err', info: 'c-info', neutral: '' };

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
		for (const d of String(ICONS[name] || ICONS.shield).split('|')) {
			const p = document.createElementNS(NS, 'path');
			p.setAttribute('d', d);
			s.appendChild(p);
		}
		return s;
	}

	function el(tag, attrs, kids) {
		const n = document.createElement(tag);
		for (const [k, v] of Object.entries(attrs || {})) {
			if (v === null || v === undefined || v === false || v === '') continue;
			if (k === 'text') n.textContent = String(v);
			else if (k === 'class') n.className = v;
			else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
			else n.setAttribute(k, v === true ? '' : String(v));
		}
		for (const c of kids || []) if (c !== null && c !== undefined && c !== false && c !== '') n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
		return n;
	}
	const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };

	/**
	 * @param {object} o
	 * @param {HTMLElement} o.host - the card on the start page
	 * @param {HTMLElement} o.topHost - the card "Top gesperrte Domains"
	 * @param {object} o.api - window.gatecontrol.dnsProtect
	 * @param {Function} o.t
	 * @param {() => string} o.getLocale
	 * @param {(msg: string, type?: string) => void} o.toast
	 * @param {() => boolean} [o.isConnected] - the tunnel is up
	 */
	function mount(o) {
		const { host, topHost, api, t } = o;
		const locale = () => (o.getLocale && o.getLocale() === 'en' ? 'en' : 'de');
		const call = (p) => Promise.resolve(p).catch((err) => ({ ok: false, code: (err && err.code) || 'failed' }));
		const S = { snap: null, busy: false, focus: null, pageShown: true, watched: null, askedFor: null };
		let ticker = null;

		const ctx = () => ({ now: Date.now(), locale: locale(), connected: o.isConnected ? o.isConnected() : undefined });

		// ── Actions ──────────────────────────────────────

		/** The button that has the focus: it is given back after the redraw (a busy button is disabled and loses it). */
		const focusedAct = () => (host.contains(document.activeElement) ? document.activeElement.getAttribute('data-act') : null);

		async function act(run, done) {
			if (S.busy) return;
			S.busy = true;
			S.focus = focusedAct();
			render();
			const r = await call(run());
			S.busy = false;
			if (r && r.ok) {
				if (r.snapshot) S.snap = r.snapshot;
				o.toast(done(r), 'success');
			} else {
				o.toast(DS.errorText(r, t), 'error');
			}
			render();
		}

		const pause = (how) => act(() => api.pause(how), () => t(how.extend ? 'dnsProtect.done.extended' : 'dnsProtect.done.paused'));
		const resume = () => act(() => api.resume(), (r) => t(r.resumed === false ? 'dnsProtect.done.notPaused' : 'dnsProtect.done.resumed'));
		async function retry() {
			if (S.busy) return;
			S.busy = true;
			S.focus = focusedAct();
			render();
			const r = await call(api.refresh());
			S.busy = false;
			if (r && r.state) S.snap = r;
			render();
		}

		// ── Drawing ──────────────────────────────────────

		const btn = (cls, act_, label, onClick, extra = {}, kids = []) => el('button', {
			type: 'button', class: `btn btn-sm ${cls}`, 'data-act': act_, disabled: S.busy || extra.disabled, title: extra.title, on: { click: onClick },
		}, [...kids, el('span', { text: label })]);

		function banner(b) {
			return el('div', { class: `banner banner-${b.tone} dnsp-ban`, role: b.tone === 'err' ? 'alert' : 'note' }, [
				el('span', { class: `dnsp-ban-ic t-${b.tone}` }, [icon(b.icon, 18)]),
				el('div', { class: 'grow' }, [el('strong', { text: b.title }), ' ', el('span', { text: b.text })]),
			]);
		}

		function card(v) {
			const kids = [];
			kids.push(el('div', { class: 'dnsp-head' }, [
				el('span', { class: `dnsp-ic ${TONES[v.tone]}` }, [icon(v.icon, 18)]),
				el('div', { class: 'dnsp-t', 'aria-live': 'polite' }, [
					el('h2', { class: 'h-card', text: t('dnsProtect.title') }),
					el('span', { class: 'desc', text: v.sub }),
				]),
				el('span', { class: `chip ${TONES[v.chip.tone]}`, 'data-chip': v.state }, [
					el('span', { text: v.chip.text }),
					v.chip.countdown ? el('span', { 'aria-hidden': 'true', text: '·' }) : null,
					v.chip.countdown ? el('span', { class: 'mono', 'data-cd': true, 'aria-hidden': 'true', text: v.chip.countdown }) : null,
				]),
			]));
			if (v.banner) kids.push(banner(v.banner));
			if (v.counters) {
				kids.push(el('dl', { class: 'dnsp-kv' }, v.counters.items.map((c) => el('div', { 'data-kv': c.key }, [
					el('dt', { class: 'desc', text: c.label }),
					el('dd', { class: 'disp', text: c.value }),
				]))));
				if (v.counters.note) kids.push(el('p', { class: 'desc dnsp-note', text: v.counters.note }));
			}
			if (v.pause) {
				kids.push(el('div', { class: 'dnsp-btns', role: 'group', 'aria-label': v.pause.label }, [
					el('span', { class: 'desc dnsp-lead', text: v.pause.label }),
					...v.pause.choices.map((c) => btn('btn-sec', `pause-${c.key}`, c.label, () => pause(c.how), { disabled: c.disabled, title: c.title }, c.clock ? [icon('clock', 14)] : [])),
				]));
				kids.push(el('p', { class: 'desc dnsp-note', text: v.pause.hint }));
			}
			if (v.paused) {
				const p = v.paused;
				if (p.resume || p.countdown || p.extend) {
					kids.push(el('div', { class: 'dnsp-btns' }, [
						p.resume ? btn('btn-pri', 'resume', t('dnsProtect.resume'), resume, {}, [icon('shield', 14, '2.2')]) : null,
						p.countdown ? el('span', { class: 'dnsp-cd mono', role: 'timer', 'aria-label': t('dnsProtect.remaining', { time: p.countdown }) }, [el('span', { 'data-cd': true, 'aria-hidden': 'true', text: p.countdown })]) : null,
						p.extend ? btn('btn-sec', 'extend', t('dnsProtect.extend'), () => pause({ extend: DS.EXTEND })) : null,
					]));
				}
				if (p.note) kids.push(el('p', { class: 'desc dnsp-note', 'data-note': 'pause', text: p.note }));
			}
			for (const n of v.notes) kids.push(el('p', { class: 'desc dnsp-note', text: n }));
			if (v.retry) kids.push(el('div', { class: 'dnsp-btns' }, [btn('btn-sec', 'retry', t('dnsProtect.retry'), retry, {}, [icon('refresh', 14)])]));
			return kids;
		}

		function renderTop() {
			const rows = DS.topView(S.snap, locale());
			clear(topHost);
			topHost.hidden = !rows || host.hidden;
			if (topHost.hidden) return;
			topHost.append(el('h2', { class: 'h-card', text: t('dnsProtect.top.title') }));
			if (!rows.length) { topHost.append(el('p', { class: 'desc', text: t('dnsProtect.top.empty') })); return; }
			topHost.append(el('ol', { class: 'dnsp-top-list' }, rows.map((r) => el('li', null, [
				el('span', { class: 'mono dnsp-dom', title: r.domain, text: r.domain }),
				el('span', { class: 'mono dnsp-cnt', text: r.count }),
			]))));
		}

		function render() {
			const v = DS.cardView(S.snap, ctx(), t);
			// a button that had the focus keeps it across the redraw
			const focused = focusedAct() || (S.busy ? null : S.focus);
			if (!S.busy) S.focus = null;
			clear(host);
			host.hidden = !v;
			if (v) {
				host.dataset.state = v.state;
				host.dataset.tone = v.tone;
				host.append(...card(v));
				if (focused) {
					const again = host.querySelector(`[data-act="${focused}"]:not(:disabled)`) || host.querySelector('button:not(:disabled)');
					if (again) again.focus();
				}
			}
			renderTop();
			host.classList.toggle('is-wide', topHost.hidden);
			tick(!!(v && v.paused && v.paused.countdown));
			watch();
		}

		/** The time left of a pause, every second; at its end the server is asked once. */
		function tick(on) {
			if (!on) { clearInterval(ticker); ticker = null; return; }
			if (ticker) return;
			ticker = setInterval(() => {
				const left = DS.remainingMs(S.snap, Date.now());
				if (left === null) return;
				const text = DS.countdown(left);
				for (const n of host.querySelectorAll('[data-cd]')) n.textContent = text;
				const timer = host.querySelector('.dnsp-cd');
				// the spoken time only changes by the minute
				if (timer && left % 60000 < 1000) timer.setAttribute('aria-label', t('dnsProtect.remaining', { time: text }));
				// once per pause: the service asks as well, and a server that still says "paused" is not asked every second
				const until = S.snap.data.pause.until;
				if (left <= 0 && S.askedFor !== until) { S.askedFor = until; call(api.refresh()); }
			}, 1000);
		}

		/** Tell the service whether the card is on screen (it then asks the status more often). */
		function watch() {
			const on = S.pageShown && !host.hidden && document.visibilityState === 'visible';
			if (on === S.watched) return;
			S.watched = on;
			call(api.watch(on));
		}

		function apply(snap) {
			if (!snap || typeof snap !== 'object') return;
			S.snap = snap;
			render();
		}

		if (api.onChange) api.onChange(apply);
		document.addEventListener('visibilitychange', watch);
		call(api.status()).then(apply);

		return {
			/** The language changed. */
			relabel: render,
			/** The start page is shown again. */
			show() { S.pageShown = true; watch(); },
			hide() { S.pageShown = false; watch(); },
			/** The tunnel went up or down. */
			connection: render,
		};
	}

	root.GCDnsView = { mount };
})(typeof self !== 'undefined' ? self : this);
