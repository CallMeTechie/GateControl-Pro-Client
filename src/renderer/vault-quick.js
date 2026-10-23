/**
 * GateControl -- Vault quick search window (Strg+Alt+P, mockup W2)
 *
 * Type to search; Enter copies the password (a 2FA-only entry: its code),
 * Strg+B the user name, Strg+T the 2FA code, Strg+O opens the website,
 * ↑ / ↓ move, Esc closes. While Vault is locked the field takes the master
 * password (or the kept sign-in opens it right away). Copies go through main
 * (vault:copy, cleared after 30 s); the list carries no secrets — only the
 * current 2FA codes of the hits are shown, as in the mockup.
 *
 * Data: window.gcQuick (vault-quick-preload.js); logic: vault-state.js
 * (window.GCVaultState: quickSearch, quickKey, quickCommand). The same file
 * is used by Pro and Community.
 */
(function () {
	'use strict';

	const VS = window.GCVaultState;
	const Q = window.gcQuick;
	const t = (k, p) => Q.t(k, p);
	const $ = (id) => document.getElementById(id);

	const input = $('vq-input');
	const hitsEl = $('vq-hits');
	const statusEl = $('vq-status');
	const foot = $('vq-foot');

	const S = { status: null, entries: [], names: new Map(), hits: [], sel: 0, codes: new Map(), busy: false, lastTouch: 0, hideTimer: null, gen: 0 };

	function el(tag, cls, text) {
		const n = document.createElement(tag);
		if (cls) n.className = cls;
		if (text !== undefined && text !== null) n.textContent = text;
		return n;
	}
	const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };

	const mode = () => {
		const st = S.status;
		if (!st || st.state !== 'available') return 'unavailable';
		if (st.account !== 'ready') return 'noAccount';
		return st.unlocked ? 'search' : 'locked';
	};

	function say(text, err) {
		statusEl.hidden = !text;
		statusEl.textContent = text || '';
		statusEl.classList.toggle('is-err', !!err);
	}

	function labels() {
		$('vq').setAttribute('aria-label', t('vault.quick.title'));
		hitsEl.setAttribute('aria-label', t('vault.quick.hits'));
		$('vq-esc').textContent = t('vault.quick.kbdEsc');
		clear(foot);
		if (mode() !== 'search') return;
		for (const [k, label] of [['kbdEnter', 'password'], ['kbdB', 'username'], ['kbdT', 'totp'], ['kbdO', 'url']]) {
			const s = el('span');
			s.append(el('kbd', 'vt-kbd', t(`vault.quick.${k}`)), document.createTextNode(t(`vault.quick.${label}`)));
			foot.appendChild(s);
		}
	}

	function setupInput() {
		const m = mode();
		if (m === 'locked') {
			input.type = 'password';
			input.placeholder = t('vault.unlock.password');
			input.setAttribute('aria-label', t('vault.unlock.password'));
		} else {
			input.type = 'search';
			input.placeholder = t('vault.quick.search');
			input.setAttribute('aria-label', t('vault.quick.search'));
		}
		input.disabled = m === 'unavailable' || m === 'noAccount';
	}

	function render() {
		labels();
		setupInput();
		clear(hitsEl);
		const m = mode();
		if (m === 'unavailable' || m === 'noAccount') {
			hitsEl.appendChild(el('div', 'vq-msg', t(m === 'unavailable' ? 'vault.quick.unavailable' : 'vault.quick.noAccount')));
			return;
		}
		if (m === 'locked') {
			hitsEl.appendChild(el('div', 'vq-msg', S.busy ? t('vault.unlock.busy') : t('vault.quick.lockedHint')));
			return;
		}
		if (!input.value.trim()) { hitsEl.appendChild(el('div', 'vq-msg', t('vault.quick.hint'))); return; }
		if (!S.hits.length) { hitsEl.appendChild(el('div', 'vq-msg', t('vault.noResults'))); return; }
		S.hits.forEach((h, i) => {
			const row = el('div', 'vq-hit');
			row.id = `vq-hit-${i}`;
			row.setAttribute('role', 'option');
			row.setAttribute('aria-selected', i === S.sel ? 'true' : 'false');
			const av = el('span', `vt-av vt-t${VS.tone(h.title)}`, VS.letter(h.title));
			av.setAttribute('aria-hidden', 'true');
			const tx = el('span', 'vt-row-tx');
			tx.append(el('span', 'vt-row-title', h.title || '…'), el('span', 'vt-row-sub', [VS.rowSub(h), S.names.get(h.vaultId)].filter(Boolean).join(' · ')));
			row.append(av, tx);
			const code = S.codes.get(h.id);
			if (h.hasTotp && code && code.code) row.appendChild(el('span', 'vq-code', VS.prettyCode(code.code)));
			row.addEventListener('click', () => { S.sel = i; render(); input.focus(); });
			row.addEventListener('dblclick', () => run('password'));
			hitsEl.appendChild(row);
		});
		input.setAttribute('aria-activedescendant', `vq-hit-${S.sel}`);
		const selRow = $(`vq-hit-${S.sel}`);
		if (selRow && typeof selRow.scrollIntoView === 'function') selRow.scrollIntoView({ block: 'nearest' });
	}

	async function refresh() {
		S.status = await Promise.resolve(Q.status()).catch(() => null);
		if (mode() === 'search') {
			const r = await Promise.resolve(Q.entries()).catch(() => null);
			if (r && r.ok) {
				S.entries = Array.isArray(r.entries) ? r.entries : [];
				S.names = VS.vaultNames(r.vaults || [], t);
			} else if (r && r.code === 'locked') {
				S.status = await Promise.resolve(Q.status()).catch(() => S.status);
			}
		} else {
			S.entries = [];
		}
		search();
	}

	function search() {
		S.hits = mode() === 'search' ? VS.quickSearch(S.entries, input.value, 8) : [];
		S.sel = VS.moveSelection(S.sel, null, S.hits.length);
		render();
		loadCodes();
	}

	async function loadCodes() {
		const gen = ++S.gen;
		for (const h of S.hits) {
			if (!h.hasTotp) continue;
			const c = S.codes.get(h.id);
			if (c && c.until > Date.now()) continue;
			const r = await Promise.resolve(Q.totp(h.id)).catch(() => null);
			if (gen !== S.gen) return;
			if (r && r.ok) S.codes.set(h.id, { code: r.code, until: Date.now() + (Number(r.secondsLeft) || 1) * 1000 });
		}
		render();
	}

	function touch() {
		if (mode() !== 'search' || Date.now() - S.lastTouch < 15000) return;
		S.lastTouch = Date.now();
		Promise.resolve(Q.touch()).catch(() => {});
	}

	async function unlock() {
		const pw = input.value;
		if (!pw || S.busy) return;
		S.busy = true;
		say('');
		render();
		const r = await Promise.resolve(Q.unlock(pw)).catch(() => ({ ok: false, code: 'failed' }));
		S.busy = false;
		if (!r.ok) {
			say(VS.errorText(r, t), true);
			input.select();
			render();
			return;
		}
		input.value = '';
		await refresh();
		input.focus();
	}

	function hideSoon(ms) {
		clearTimeout(S.hideTimer);
		S.hideTimer = setTimeout(() => Q.hide(), ms);
	}

	async function run(action) {
		const hit = S.hits[S.sel];
		const cmd = VS.quickCommand(action, hit);
		if (!cmd) { if (hit) say(t('vault.quick.nothing'), true); return; }
		if (cmd.kind === 'open') {
			Promise.resolve(Q.openUrl(cmd.url)).catch(() => {});
			Q.hide();
			return;
		}
		const label = t(cmd.field === 'totp' ? 'vault.field.totp' : `vault.field.${cmd.field}`);
		const r = await Promise.resolve(Q.copy(hit.id, cmd.field)).catch(() => ({ ok: false, code: 'failed' }));
		if (!r.ok) { say(VS.errorText(r, t), true); return; }
		say(t('vault.copiedSecret', { label, seconds: Math.round((r.clearsInMs || 30000) / 1000) }));
		hideSoon(700);
	}

	document.addEventListener('keydown', (e) => {
		touch();
		const m = mode();
		if (m !== 'search') {
			if (e.key === 'Escape') { e.preventDefault(); Q.hide(); } else if (e.key === 'Enter' && m === 'locked') { e.preventDefault(); unlock(); }
			return;
		}
		const action = VS.quickKey(e);
		if (!action) return;
		e.preventDefault();
		if (action === 'close') { Q.hide(); return; }
		if (action === 'up' || action === 'down') { S.sel = VS.moveSelection(S.sel, action, S.hits.length); render(); return; }
		run(action);
	});
	document.addEventListener('pointerdown', touch, true);
	document.addEventListener('wheel', touch, { capture: true, passive: true });
	input.addEventListener('input', () => { say(''); if (mode() === 'search') { S.sel = 0; search(); } });

	// codes run out: fetch again
	setInterval(() => {
		if (mode() !== 'search' || !S.hits.some((h) => h.hasTotp)) return;
		if (S.hits.some((h) => h.hasTotp && (!S.codes.has(h.id) || S.codes.get(h.id).until <= Date.now()))) loadCodes();
	}, 1000);

	Q.onShow(async (p) => {
		clearTimeout(S.hideTimer);
		document.documentElement.setAttribute('data-theme', p.theme);
		document.documentElement.lang = p.locale === 'en' ? 'en' : 'de';
		say('');
		input.value = '';
		S.hits = [];
		S.sel = 0;
		S.codes.clear();
		await refresh();
		const st = S.status;
		if (mode() === 'locked' && st.remember && st.rememberAvailable && !(st.lastLock && st.lastLock.reason === 'manual')) {
			S.busy = true;
			render();
			const r = await Promise.resolve(Q.unlockRemembered()).catch(() => null);
			S.busy = false;
			if (r && r.ok) await refresh(); else render();
		}
		input.focus();
	});
	// hidden: nothing stays on screen for next time
	Q.onHide(() => {
		input.value = '';
		S.hits = [];
		S.codes.clear();
		say('');
		render();
	});

	render();
})();
