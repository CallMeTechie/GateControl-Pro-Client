/**
 * GateControl -- the SSH terminal window (Fernzugriff stage 3)
 *
 * One tab per session of core's RemoteTerm (main process); xterm.js 5.5.0 + addon-fit from the app package draws
 * it. Copy and paste like Windows Terminal: selecting does not copy by itself, Strg+C stays the shell's interrupt,
 * Strg+Umschalt+C / V / A copy, paste and select all; the font with Strg+wheel, Strg+Plus/Minus/0 or the buttons
 * (9…28 px, one size for all devices). Pasting more than one line asks first. The context menu (right click) holds
 * the same. Only window.gcTerm (terminal-preload.js) talks to the main process; nothing here is logged.
 */
'use strict';

(function () {
	const S = window.GCTermState;
	const api = window.gcTerm;
	const $ = (id) => document.getElementById(id);

	// ── CSP: default-src 'self' blocks the two <style> elements of xterm's DOM renderer; their text goes into
	// constructed style sheets instead (not covered by the policy, nothing inline is allowed).
	(function adoptXtermStyles() {
		const create = Document.prototype.createElement;
		document.createElement = function (tag, opts) {
			if (String(tag).toLowerCase() !== 'style' || typeof CSSStyleSheet !== 'function') return create.call(this, tag, opts);
			// an inert stand-in (an empty <style> alone would already count as inline style)
			const el = create.call(this, 'span');
			el.hidden = true;
			const sheet = new CSSStyleSheet();
			let text = '';
			document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
			Object.defineProperty(el, 'textContent', {
				get: () => text,
				set: (v) => { text = String(v == null ? '' : v); sheet.replaceSync(text); },
			});
			const remove = el.remove.bind(el);
			el.remove = () => { document.adoptedStyleSheets = document.adoptedStyleSheets.filter((x) => x !== sheet); remove(); };
			return el;
		};
	})();

	// The terminal's surface stays dark in both themes (design question 5).
	const THEME = {
		background: '#0b0e13', foreground: '#e6eaf0', cursor: '#3ddc97', cursorAccent: '#0b0e13', selectionBackground: 'rgba(121,184,255,.35)',
		black: '#1c222b', red: '#ff7b72', green: '#3ddc97', yellow: '#f5b544', blue: '#79b8ff', magenta: '#d2a8ff', cyan: '#56d4dd', white: '#c9d1d9',
		brightBlack: '#6e7681', brightRed: '#ffa198', brightGreen: '#56e3a6', brightYellow: '#f8cf6a', brightBlue: '#a5d6ff', brightMagenta: '#e2c5ff',
		brightCyan: '#8ce8ee', brightWhite: '#ffffff',
	};

	let T = { errors: {} };
	let font = 14;
	let fontMin = 9;
	let fontMax = 28;
	let askPaste = true;
	/** id → { status?, pending?, term?, fit?, el } */
	const tabs = new Map();
	let active = null;
	let dialogFor = null; // what the open dialog is about
	let hintTimer = null;
	let tick = null;

	// ── Tabs ──

	function ensureTerminal(tab) {
		if (tab.term) return;
		const el = document.createElement('div');
		el.className = 'term';
		el.hidden = true;
		$('stage').appendChild(el);
		const term = new window.Terminal({
			fontFamily: "'JetBrains Mono', Consolas, monospace", fontSize: font, theme: THEME, cursorBlink: true, scrollback: 5000,
			allowProposedApi: false, rightClickSelectsWord: false, macOptionIsMeta: false, convertEol: false,
		});
		const fit = new window.FitAddon.FitAddon();
		term.loadAddon(fit);
		term.open(el);
		term.onData((d) => { if (S.canType(tab.status)) api.input(tab.id, d); });
		term.onResize(({ cols, rows }) => api.resize(tab.id, cols, rows));
		term.attachCustomKeyEventHandler((ev) => keys(ev, tab));
		// a paste of the browser (Umschalt+Einfg, middle click) goes the same way as ours: asked first
		el.addEventListener('paste', (ev) => {
			ev.preventDefault();
			ev.stopPropagation();
			const text = ev.clipboardData ? ev.clipboardData.getData('text/plain') : '';
			if (text) pasteText(tab, text);
		}, true);
		el.addEventListener('wheel', (ev) => {
			if (!ev.ctrlKey) return;
			ev.preventDefault();
			setFont(font + (ev.deltaY < 0 ? 1 : -1));
		}, { passive: false });
		el.addEventListener('contextmenu', (ev) => { ev.preventDefault(); openMenu(ev.clientX, ev.clientY); });
		tab.el = el;
		tab.term = term;
		tab.fit = fit;
	}

	function upsert(status) {
		if (status.closed) { drop(status.id); return; }
		let tab = tabs.get(status.id);
		if (!tab) {
			tab = { id: status.id };
			tabs.set(status.id, tab);
			if (!active) active = status.id;
		}
		tab.status = status;
		ensureTerminal(tab);
		render();
	}

	function drop(id) {
		const tab = tabs.get(id);
		if (!tab) return;
		if (tab.term) tab.term.dispose();
		if (tab.el) tab.el.remove();
		tabs.delete(id);
		if (active === id) active = tabs.size ? [...tabs.keys()][tabs.size - 1] : null;
		if (dialogFor && dialogFor.id === id) closeDialog();
		if (!tabs.size) { window.close(); return; }
		render();
	}

	function select(id) {
		if (!tabs.has(id)) return;
		active = id;
		api.select(id);
		render();
	}

	function current() { return active ? tabs.get(active) : null; }

	// ── Render ──

	function render() {
		const list = $('tab-list');
		list.textContent = '';
		for (const tab of tabs.values()) {
			const b = document.createElement('button');
			b.type = 'button';
			b.className = 'tab' + (tab.id === active ? ' on' : '');
			b.setAttribute('role', 'tab');
			b.setAttribute('aria-selected', String(tab.id === active));
			const dot = document.createElement('span');
			dot.className = 'tdot t-' + (tab.pending ? 'warn' : S.tone(tab.status));
			b.appendChild(dot);
			if (tab.status && tab.status.recording && tab.status.state === 'ready') {
				const r = document.createElement('span');
				r.className = 'rec-dot';
				r.title = T.recording;
				b.appendChild(r);
			}
			const name = document.createElement('span');
			name.className = 'tname';
			name.textContent = tab.pending ? tab.pending.deviceName : S.tabLabel(tab.status);
			b.appendChild(name);
			const x = document.createElement('span');
			x.className = 'tclose';
			x.textContent = '×';
			x.title = T.closeTab;
			x.addEventListener('click', (ev) => { ev.stopPropagation(); askDisconnect(tab); });
			b.appendChild(x);
			b.addEventListener('click', () => select(tab.id));
			list.appendChild(b);
		}
		for (const tab of tabs.values()) if (tab.el) tab.el.hidden = tab.id !== active;
		const tab = current();
		const s = tab && tab.status;
		$('bar-name').textContent = tab ? (tab.pending ? tab.pending.deviceName : s.deviceName) : '';
		$('bar-meta').textContent = s ? S.meta(s) : '';
		const rec = !!(s && s.recording && s.state === 'ready');
		$('bar-rec').hidden = !rec;
		$('bar-rec-text').textContent = T.recording;
		$('font-val').textContent = `${font} px`;
		$('st-state').textContent = s ? S.stateText(s, T) : '';
		$('st-dot').className = 'st-dot t-' + (s ? S.tone(s) : 'off');
		$('st-count').textContent = S.fill(T.sessions, { n: tabs.size });
		$('tmux-banner').hidden = !(s && s.state === 'ready' && s.tmuxMissing);
		$('tmux-banner').textContent = T.tmuxMissing;
		renderOverlay(tab);
		if (tab && tab.fit && !tab.el.hidden) {
			requestAnimationFrame(() => { try { tab.fit.fit(); } catch { /* not visible */ } });
			if (S.canType(s)) tab.term.focus();
		}
		renderDialogFor(tab);
	}

	function renderOverlay(tab) {
		const old = document.querySelector('.ov');
		if (old) old.remove();
		if (!tab || !tab.status) return;
		const o = S.overlay(tab.status, T);
		if (!o || o.kind === 'locked') return;
		const ov = document.createElement('div');
		ov.className = 'ov' + (o.kind === 'hint' ? ' ov-hint' : '');
		if (o.kind === 'hint') {
			ov.textContent = o.text;
		} else {
			const card = document.createElement('div');
			card.className = 'ov-card';
			const h = document.createElement('strong');
			h.textContent = o.title;
			const p = document.createElement('p');
			p.textContent = o.text;
			card.append(h, p);
			const row = document.createElement('div');
			row.className = 'ov-actions';
			for (const a of o.actions) {
				const b = document.createElement('button');
				b.type = 'button';
				b.className = 'btn' + (a.primary ? ' btn-pri' : '');
				b.textContent = a.label;
				b.addEventListener('click', () => act(a.act, tab));
				row.appendChild(b);
			}
			card.appendChild(row);
			ov.appendChild(card);
		}
		$('stage').appendChild(ov);
	}

	function act(what, tab) {
		if (!tab) return;
		if (what === 'try' || what === 'reconnect') api.reconnect(tab.id);
		else if (what === 'close') { api.close(tab.id); drop(tab.id); }
		else if (what === 'disconnect') askDisconnect(tab);
	}

	// ── Dialogs ──

	function dialog({ label = '', title, body, actions, about }) {
		$('dlg-label').textContent = label;
		$('dlg-label').hidden = !label;
		$('dlg-title').textContent = title;
		const b = $('dlg-body');
		b.textContent = '';
		for (const node of body) b.appendChild(node);
		const row = $('dlg-actions');
		row.textContent = '';
		for (const a of actions) {
			const btn = document.createElement('button');
			btn.type = 'button';
			btn.className = 'btn' + (a.primary ? ' btn-pri' : '') + (a.danger ? ' btn-danger' : '');
			btn.textContent = a.label;
			if (a.id) btn.id = a.id;
			btn.addEventListener('click', a.run);
			row.appendChild(btn);
		}
		dialogFor = about || null;
		$('dlg').hidden = false;
		const first = row.querySelector('.btn-pri') || row.querySelector('.btn');
		if (first) first.focus();
	}

	function closeDialog() {
		$('dlg').hidden = true;
		dialogFor = null;
		clearInterval(tick);
		tick = null;
		const tab = current();
		if (tab && tab.term && S.canType(tab.status)) tab.term.focus();
	}

	const p = (text, cls) => { const e = document.createElement('p'); e.textContent = text; if (cls) e.className = cls; return e; };

	/** The dialogs a state of the active tab needs: the host key, a changed key, the recording hint. */
	function renderDialogFor(tab) {
		if (!tab) return;
		const s = tab.status;
		if (tab.pending) {
			if (tab.pending.failed || tab.pending.busy || (dialogFor && dialogFor.kind === 'rec' && dialogFor.id === tab.id)) return;
			dialog({
				label: tab.pending.deviceName, title: T.recTitle, about: { kind: 'rec', id: tab.id },
				body: [p(tab.pending.always ? T.recAlways : T.recOptional)],
				actions: [
					{ label: T.cancel, run: () => { api.confirm(tab.id, false); closeDialog(); drop(tab.id); } },
					{ label: T.recOk, primary: true, id: 'rec-ok', run: () => confirmPending(tab) },
				],
			});
			return;
		}
		if (s && s.state === 'hostkey' && s.hostKey) {
			if (dialogFor && dialogFor.kind === 'hk' && dialogFor.id === tab.id) return;
			const fp = document.createElement('div');
			fp.className = 'fp';
			const alg = document.createElement('div');
			alg.className = 'fp-alg';
			alg.textContent = `${s.hostKey.alg} · SHA256`;
			const val = document.createElement('div');
			val.className = 'fp-val';
			val.id = 'hk-fingerprint';
			val.textContent = s.hostKey.groups;
			fp.append(alg, val);
			const cmd = document.createElement('div');
			cmd.className = 'cmd';
			const code = document.createElement('code');
			code.textContent = 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub';
			const copy = document.createElement('button');
			copy.type = 'button';
			copy.className = 'btn btn-xs';
			copy.textContent = T.hkCopy;
			copy.addEventListener('click', () => api.clipWrite(code.textContent));
			cmd.append(code, copy);
			const left = p('', 'muted');
			const upd = () => { left.textContent = S.fill(T.hkLeft, { s: Math.max(0, Math.ceil(((s.hostKey.until || Date.now()) - Date.now()) / 1000)) }); };
			upd();
			dialog({
				label: T.hkLabel, title: T.hkTitle, about: { kind: 'hk', id: tab.id },
				body: [p(S.fill(T.hkText, { name: s.deviceName })), fp, cmd, left],
				actions: [
					{ label: T.cancel, run: () => { api.trust(tab.id, false); closeDialog(); } },
					{ label: T.hkTrust, primary: true, id: 'hk-trust', run: () => { api.trust(tab.id, true); closeDialog(); } },
				],
			});
			tick = setInterval(upd, 500);
			return;
		}
		if (s && s.state === 'failed' && s.verdict === 'locked') {
			if (dialogFor && dialogFor.kind === 'locked' && dialogFor.id === tab.id) return;
			dialog({
				label: T.mismatchLabel, title: T.mismatchTitle, about: { kind: 'locked', id: tab.id },
				body: [p(S.fill(T.mismatchText, { name: s.deviceName }))],
				actions: [{ label: T.closeTab, primary: true, id: 'locked-close', run: () => { closeDialog(); api.close(tab.id); drop(tab.id); } }],
			});
			return;
		}
		if (dialogFor && (dialogFor.kind === 'hk' || dialogFor.kind === 'locked') && dialogFor.id === tab.id) closeDialog();
	}

	async function confirmPending(tab) {
		tab.pending.busy = true;
		closeDialog();
		const r = await api.confirm(tab.id, true);
		if (r && r.session) { upsert(r.session); select(r.session.id); drop(tab.id); return; }
		// the plugin refused the ticket (recording not possible, no right …): say so, then the tab goes
		tab.pending.failed = true;
		dialog({
			label: tab.pending.deviceName, title: T.ended, about: { kind: 'close' },
			body: [p(S.errorText((r && r.error) || 'failed', T))],
			actions: [{ label: T.closeTab, primary: true, run: () => { closeDialog(); drop(tab.id); } }],
		});
	}

	function askDisconnect(tab) {
		if (tab.pending) { api.close(tab.id); drop(tab.id); return; }
		const s = tab.status;
		if (!s || !['connecting', 'hostkey', 'ready', 'reconnecting'].includes(s.state)) { api.close(tab.id); drop(tab.id); return; }
		const keeps = s.tmux && !s.tmuxMissing;
		dialog({
			title: T.disconnectTitle, about: { kind: 'leave', id: tab.id },
			body: [p(keeps ? S.fill(T.disconnectTmux, { tmux: s.tmux, name: s.deviceName }) : T.disconnectShell)],
			actions: [
				{ label: T.cancel, run: closeDialog },
				{ label: T.disconnect, primary: !!keeps, danger: !keeps, id: 'leave-ok', run: () => { closeDialog(); api.close(tab.id); drop(tab.id); } },
			],
		});
	}

	// ── Keys, copy, paste, font ──

	function keys(ev, tab) {
		if (ev.type !== 'keydown') return true;
		const k = ev.key.toLowerCase();
		if (ev.ctrlKey && ev.shiftKey && (k === 'c' || k === 'v' || k === 'a')) {
			ev.preventDefault();
			if (k === 'c') copySel(tab);
			if (k === 'v') paste(tab);
			if (k === 'a') tab.term.selectAll();
			return false;
		}
		if (ev.ctrlKey && !ev.shiftKey && !ev.altKey && (ev.key === '+' || ev.key === '=' || ev.key === '-' || ev.key === '0')) {
			ev.preventDefault();
			setFont(ev.key === '0' ? 14 : font + (ev.key === '-' ? -1 : 1));
			return false;
		}
		return true;
	}

	function copySel(tab) {
		const sel = tab && tab.term ? tab.term.getSelection() : '';
		if (sel) api.clipWrite(sel);
	}

	async function paste(tab) {
		const text = await api.clipRead();
		if (text) pasteText(tab, text);
	}

	function pasteText(tab, text) {
		if (!tab || !S.canType(tab.status)) return;
		const lines = S.pasteLines(text);
		const go = () => tab.term.paste(S.pasteText(text));
		if (!askPaste || lines <= 1) { go(); return; }
		const never = document.createElement('label');
		never.className = 'chk';
		const box = document.createElement('input');
		box.type = 'checkbox';
		never.append(box, document.createTextNode(' ' + T.pasteNever));
		const pre = document.createElement('pre');
		pre.className = 'paste-pre';
		pre.textContent = text.split(/\r?\n/).slice(0, 4).map((l) => l.slice(0, 100)).join('\n');
		dialog({
			title: S.fill(T.pasteTitle, { n: lines }), about: { kind: 'paste', id: tab.id },
			body: [p(T.pasteText), pre, never],
			actions: [
				{ label: T.cancel, run: closeDialog },
				{ label: T.pasteOk, primary: true, id: 'paste-ok', run: () => {
					if (box.checked) { askPaste = false; api.askPaste(false); }
					closeDialog();
					go();
				} },
			],
		});
	}

	async function setFont(px) {
		const next = S.clampFont(px, fontMin, fontMax);
		if (next === font) return;
		font = await api.font(next);
		for (const tab of tabs.values()) if (tab.term) tab.term.options.fontSize = font;
		render();
		const tab = current();
		if (tab && tab.term) {
			requestAnimationFrame(() => {
				try { tab.fit.fit(); } catch { /* hidden */ }
				const h = $('font-hint');
				h.textContent = S.fill(T.font, { px: font, cols: tab.term.cols, rows: tab.term.rows });
				h.hidden = false;
				clearTimeout(hintTimer);
				hintTimer = setTimeout(() => { h.hidden = true; }, 1500);
			});
		}
	}

	// ── Context menu ──

	function openMenu(x, y) {
		const m = $('ctx-menu');
		m.hidden = false;
		const r = m.getBoundingClientRect();
		m.style.left = `${Math.min(x, window.innerWidth - r.width - 4)}px`;
		m.style.top = `${Math.min(y, window.innerHeight - r.height - 4)}px`;
	}

	$('ctx-menu').addEventListener('click', (ev) => {
		const b = ev.target.closest('button[data-act]');
		if (!b) return;
		$('ctx-menu').hidden = true;
		const tab = current();
		switch (b.dataset.act) {
			case 'copy': copySel(tab); break;
			case 'paste': paste(tab); break;
			case 'selectAll': if (tab && tab.term) tab.term.selectAll(); break;
			case 'bigger': setFont(font + 1); break;
			case 'smaller': setFont(font - 1); break;
			case 'reconnect': if (tab) api.reconnect(tab.id); break;
			case 'disconnect': if (tab) askDisconnect(tab); break;
			default:
		}
	});
	document.addEventListener('mousedown', (ev) => { if (!ev.target.closest('#ctx-menu')) $('ctx-menu').hidden = true; });
	document.addEventListener('keydown', (ev) => {
		if (ev.key !== 'Escape') return;
		$('ctx-menu').hidden = true;
		if (dialogFor && (dialogFor.kind === 'paste' || dialogFor.kind === 'leave' || dialogFor.kind === 'close')) closeDialog();
	});

	$('font-minus').addEventListener('click', () => setFont(font - 1));
	$('font-plus').addEventListener('click', () => setFont(font + 1));
	$('btn-copy').addEventListener('click', () => copySel(current()));
	$('btn-paste').addEventListener('click', () => paste(current()));
	$('btn-disconnect').addEventListener('click', () => { const tab = current(); if (tab) askDisconnect(tab); });
	$('tab-add').addEventListener('click', () => api.add());

	new ResizeObserver(() => {
		const tab = current();
		if (tab && tab.fit && !tab.el.hidden) { try { tab.fit.fit(); } catch { /* hidden */ } }
	}).observe($('stage'));

	// ── Main process ──

	function addPending(pd) {
		if (tabs.has(pd.pendingId)) return;
		tabs.set(pd.pendingId, { id: pd.pendingId, pending: { deviceName: pd.deviceName, always: pd.always } });
		active = pd.pendingId;
		render();
	}

	function applyTexts() {
		document.title = T.title;
		document.querySelectorAll('[data-t]').forEach((e) => { e.textContent = T[e.dataset.t] || ''; });
		document.querySelectorAll('kbd').forEach((e) => { e.textContent = e.textContent.replace('Strg+Umschalt', T.keyCtrlShift || 'Strg+Umschalt').replace(/^Strg\+(?!Umschalt)/, (T.keyCtrl || 'Strg') + '+'); });
		$('btn-copy').textContent = T.copy;
		$('btn-paste').textContent = T.paste;
		$('btn-disconnect').textContent = T.disconnect;
		$('tab-add').setAttribute('aria-label', T.add);
		$('tab-add').title = T.add;
		$('font-minus').title = T.fontSmaller;
		$('font-plus').title = T.fontBigger;
	}

	api.onStatus(upsert);
	api.onData(({ id, data }) => { const tab = tabs.get(id); if (tab && tab.term) tab.term.write(data); });
	api.onPending(addPending);
	api.onFocus(({ id }) => select(id));
	api.onClosing(({ count }) => {
		dialog({
			title: S.fill(T.closeAllTitle, { n: count }), about: { kind: 'close' },
			body: [p(T.closeAllText)],
			actions: [{ label: T.cancel, run: closeDialog }, { label: T.disconnect, primary: true, id: 'close-all', run: () => { closeDialog(); api.closeAll(); } }],
		});
	});

	api.ready().then((init) => {
		T = init.texts || T;
		font = init.fontPx || font;
		fontMin = init.fontMin || fontMin;
		fontMax = init.fontMax || fontMax;
		askPaste = init.askPaste !== false;
		if (init.theme === 'light') document.documentElement.setAttribute('data-theme', 'light');
		applyTexts();
		for (const s of init.sessions || []) upsert(s);
		for (const pd of init.pending || []) addPending(pd);
		if (init.focus && tabs.has(init.focus)) select(init.focus);
		render();
	});
})();
