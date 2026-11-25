/**
 * GateControl -- Medien › Quellen (renderer view, Stufe 4f, mockup 10)
 *
 * The sources of this PC as a list (Jellyfin · DS918+ "angemeldet als …, dieses Gerät heißt …" with "Abmelden", a
 * share \\nas\filme "SMB zu Hause, WebDAV unterwegs" with "Bearbeiten"), the switches "Immer Original" and
 * "Weiterschauen auf der Übersicht", "Gerät anmelden" (the Quick Connect code of a TV or another PC confirmed with
 * this PC's access) and the dialog "Quelle hinzufügen":
 *   - Jellyfin: the search in the LAN (never over the VPN), or the address typed; a self-signed certificate is shown
 *     once to confirm; then Quick Connect (the code to confirm in Jellyfin or on another GateControl device) or name
 *     and password (sent once to Jellyfin, never kept).
 *   - SMB: \\192.168.1.20\filme with name and password; Windows signs the share in for GateControl (no drive letter);
 *     Windows' error 1219 (the Explorer is connected to that server with another user) → "Mit dem Explorer-Zugang
 *     verwenden"; "Auch als WebDAV einrichten, für unterwegs".
 *   - WebDAV: https://192.168.1.20:5006/filme with name and password, the certificate confirmed once.
 *
 * Built by media-view.js (window.GCMediaSources.mount); data: window.gatecontrol.media; pure logic in media-state.js.
 * No password ever stays in the page longer than the dialog; server text only into textContent.
 */
(function (root) {
	'use strict';

	const MS = root.GCMediaState;
	const POLL_MS = 2500;

	function mount(o) {
		const api = o.api;
		const t = o.t;
		const el = o.el;
		const icon = o.icon;
		const toast = typeof o.toast === 'function' ? o.toast : () => {};
		const locale = () => (typeof o.getLocale === 'function' ? o.getLocale() : undefined);
		const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed', error: err && err.message });
		const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };
		const storage = o.storage || null;

		const S = { shown: false, busy: new Set(), authorize: { source: null, code: '', busy: false, note: null } };
		let dlg = null; // the open dialog (one at a time)

		const rootEl = el('div', { class: 'md md-sources' });
		o.root.appendChild(rootEl);

		function status() { return o.getStatus ? o.getStatus() : null; }

		// ── The page ─────────────────────────────────────────

		function render() {
			clear(rootEl);
			const st = status();
			const { all, jellyfin } = MS.sourcesOf(st);
			rootEl.appendChild(el('div', { class: 'md-head' }, [
				el('button', { type: 'button', class: 'btn btn-ghost btn-sm btn-icon md-back', title: t('media.sources.back'), 'aria-label': t('media.sources.back'), on: { click: () => o.onBack() } }, [icon('left', 18)]),
				el('h1', { class: 'md-h', text: t('media.sources.title') }),
				el('span', { class: 'md-grow' }),
				el('button', { type: 'button', class: 'btn btn-pri btn-sm md-add', disabled: st && st.supported === false ? true : null, on: { click: () => add() } }, [icon('plus', 15), el('span', { text: t('media.sources.add') })]),
			]));
			const body = el('div', { class: 'md-srcbody scroll' });
			rootEl.appendChild(body);
			if (st && st.supported === false) body.appendChild(el('div', { class: 'note note-warn', text: t('media.unsupported.text') }));

			const listEl = el('div', { class: 'md-srclist' });
			if (!all.length) listEl.appendChild(el('div', { class: 'md-card md-card-empty' }, [el('div', { class: 'md-card-tx' }, [el('b', { text: t('media.sources.none') }), el('small', { text: t('media.empty.text') })])]));
			for (const s of all) listEl.appendChild(sourceCard(s, st));
			body.appendChild(listEl);

			// "Immer Original" (all Jellyfin sources)
			if (jellyfin.length) {
				const on = MS.alwaysOriginal(st);
				body.appendChild(switchCard(t('media.original.title'), t('media.original.text'), on, 'md-sw-original', async () => {
					for (const s of jellyfin) {
						let r;
						try { r = await api.setAlwaysOriginal(s.id, !on); } catch (err) { r = fail(err); }
						if (!r || !r.ok) { toast(MS.errorText(r && r.code, t), 'error'); break; }
					}
					await o.reloadStatus();
				}));
			}
			// "Weiterschauen" on the app's overview (this PC)
			const homeOn = (() => { try { return MS.homeCardOn(storage ? storage.getItem(MS.HOME_CARD_KEY) : null); } catch { return true; } })();
			body.appendChild(switchCard(t('media.homeCard.title'), t('media.homeCard.text'), homeOn, 'md-sw-home', () => {
				try { if (storage) storage.setItem(MS.HOME_CARD_KEY, homeOn ? 'off' : 'on'); } catch { /* storage unavailable */ }
				if (o.onHomeCard) o.onHomeCard();
				render();
			}));
			// "Gerät anmelden"
			const ready = MS.sourcesOf(st).ready;
			if (ready.length) body.appendChild(authorizeCard(ready));
		}

		function switchCard(title, text, on, cls, onToggle) {
			const sw = el('button', { type: 'button', class: `sw${on ? ' on' : ''}`, role: 'switch', 'aria-checked': on ? 'true' : 'false', 'aria-label': title, on: { click: () => onToggle() } }, [el('span')]);
			return el('div', { class: `md-card ${cls}` }, [el('div', { class: 'md-card-tx' }, [el('b', { text: title }), el('small', { text })]), sw]);
		}

		function sourceCard(s, st) {
			const jelly = s.kind === 'jellyfin';
			const ok = s.ready;
			const busy = S.busy.has(s.id);
			const actions = [];
			if (jelly) {
				if (!ok) actions.push(el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('media.src.signIn'), on: { click: () => signInAgain(s) } }));
				actions.push(el('button', { type: 'button', class: 'btn btn-sec btn-sm md-signout', disabled: busy ? true : null, text: ok ? t('media.src.signOut') : t('media.src.remove'), on: { click: () => remove(s) } }));
			} else {
				actions.push(el('button', { type: 'button', class: 'btn btn-sec btn-sm md-edit', text: t('media.src.edit'), on: { click: () => add({ kind: s.kind, address: s.unc || s.address, user: s.userName || '' }) } }));
				actions.push(el('button', { type: 'button', class: 'btn btn-ghost btn-sm md-remove', disabled: busy ? true : null, text: t('media.src.remove'), on: { click: () => remove(s) } }));
			}
			return el('div', { class: 'md-card md-srccard', 'data-id': s.id, 'data-kind': s.kind }, [
				el('span', { class: `md-card-ic${jelly ? '' : ' is-info'}` }, [icon(jelly ? 'film' : 'folder', 18, '1.9')]),
				el('div', { class: 'md-card-tx' }, [el('b', { text: MS.sourceChip(s, t) }), el('small', { text: MS.sourceSub(s, t, jelly ? st && st.deviceName : null) })]),
				el('span', { class: `md-pill ${ok ? 'is-acc' : 'is-warn'}`, text: ok ? t('media.src.connected') : t('media.src.signedOutPill') }),
				...actions,
			]);
		}

		async function remove(s) {
			S.busy.add(s.id);
			render();
			let r;
			try { r = await api.removeSource(s.id); } catch (err) { r = fail(err); }
			S.busy.delete(s.id);
			if (!r || !r.ok) toast(MS.errorText(r && r.code, t), 'error');
			await o.reloadStatus();
		}

		function authorizeCard(ready) {
			const A = S.authorize;
			if (!A.source || !ready.some((s) => s.id === A.source)) A.source = ready[0].id;
			const inp = el('input', { class: 'inp md-code-inp', inputmode: 'numeric', maxlength: '7', placeholder: '000 000', autocomplete: 'off', 'aria-label': t('media.authorize.code'), value: A.code });
			inp.addEventListener('input', () => { A.code = inp.value; A.note = null; });
			inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); confirm(); } });
			const btn = el('button', { type: 'button', class: 'btn btn-pri btn-sm md-code-btn', disabled: A.busy ? true : null, text: t('media.authorize.confirm'), on: { click: () => confirm() } });
			let pick = null;
			if (ready.length > 1) {
				pick = el('select', { class: 'inp md-code-src', 'aria-label': t('media.authorize.server') });
				for (const s of ready) pick.appendChild(el('option', { value: s.id, text: MS.sourceChip(s, t), selected: s.id === A.source }));
				pick.addEventListener('change', () => { A.source = pick.value; });
			}
			async function confirm() {
				const code = MS.codeOf(inp.value);
				if (!code) { A.note = { cls: 'note-err', text: t('media.authorize.invalid') }; render(); return; }
				A.busy = true;
				A.code = inp.value;
				render();
				let r;
				try { r = await api.authorize(A.source, code); } catch (err) { r = fail(err); }
				A.busy = false;
				if (r && r.ok) { A.code = ''; A.note = { cls: 'note-ok', text: t('media.authorize.done') }; } else A.note = { cls: 'note-err', text: r && r.code === 'not_found' ? t('media.authorize.notFound') : r && r.code === 'invalid' ? t('media.authorize.invalid') : MS.errorText(r && r.code, t) };
				render();
			}
			return el('div', { class: 'md-card md-authorize' }, [
				el('div', { class: 'md-card-tx' }, [
					el('b', { text: t('media.authorize.title') }),
					el('small', { text: t('media.authorize.text') }),
					el('div', { class: 'md-code-row' }, [pick, inp, btn]),
					A.note ? el('div', { class: `note ${A.note.cls} md-code-note`, role: 'status', text: A.note.text }) : null,
				]),
			]);
		}

		// ── The dialog ───────────────────────────────────────

		/**
		 * "Quelle hinzufügen" (kind and fields given: "Bearbeiten" / "Neu anmelden"). One dialog at a time; Esc and
		 * the backdrop close it (a running Quick Connect is cancelled, the password fields forgotten).
		 */
		function add(pre = {}) {
			if (dlg) dlg.close();
			const D = {
				kind: MS.KINDS.includes(pre.kind) ? pre.kind : 'jellyfin',
				step: 'start',          // jellyfin: start | server | qc ; shares: form
				address: pre.address || '',
				user: pre.user || '',
				password: '',
				alsoWebdav: false,
				webdavAddress: '',
				found: null,            // the servers of the LAN search (null: searching)
				server: null,           // answer of media:server
				method: 'qc',           // qc | password
				qc: null,               // { flow, code } | { expired: true }
				cert: null,             // { address, certificate, then }
				conflict: false,
				error: null,
				busy: false,
				edit: !!pre.address && pre.kind !== 'jellyfin',
			};
			let pollTimer = null;
			const before = document.activeElement;
			const titleId = `md-dlg-t-${Date.now().toString(36)}`;
			const h = el('h2', { id: titleId, class: 'md-dlg-h' });
			const body = el('div', { class: 'md-dlg-body' });
			const foot = el('div', { class: 'md-dlg-foot' });
			const box = el('div', { class: 'md-dlg', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId, tabindex: '-1' }, [
				el('div', { class: 'md-dlg-head' }, [h, el('button', { type: 'button', class: 'btn btn-ghost btn-sm btn-icon', 'aria-label': t('media.dlg.close'), title: t('media.dlg.close'), on: { click: () => close() } }, [icon('x', 16)])]),
				body, foot,
			]);
			const scrim = el('div', { class: 'md-scrim', on: { mousedown: (e) => { if (e.target === scrim && !D.busy) close(); } } }, [box]);
			const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); e.preventDefault(); if (!D.busy) close(); } };
			document.addEventListener('keydown', onKey, true);
			document.body.appendChild(scrim);

			function close() {
				if (!dlg || dlg.box !== box) return;
				dlg = null;
				clearTimeout(pollTimer);
				if (D.qc && D.qc.flow) api.quickConnect.cancel(D.qc.flow).catch(() => {});
				D.password = '';
				document.removeEventListener('keydown', onKey, true);
				scrim.remove();
				if (before && typeof before.focus === 'function' && before.isConnected) before.focus();
			}
			dlg = { box, close };

			const field = (label, attrs, key, opts = {}) => {
				const id = `md-f-${key}-${Math.random().toString(36).slice(2, 7)}`;
				const inp = el('input', { id, class: `inp md-f-${key}`, ...attrs, value: D[key] || '' });
				inp.addEventListener('input', () => { D[key] = inp.value; if (opts.onInput) opts.onInput(inp.value); });
				inp.addEventListener('keydown', (e) => { if (e.key === 'Enter' && opts.enter) { e.preventDefault(); opts.enter(); } });
				return el('div', { class: 'field md-field' }, [el('label', { for: id, text: label }), inp, opts.hint ? el('span', { class: 'hint', text: opts.hint }) : null]);
			};
			const errorNote = () => (D.error ? el('div', { class: 'note note-err md-dlg-err', role: 'alert', text: D.error }) : null);
			const btn = (label, cls, fn, disabled) => el('button', { type: 'button', class: `btn ${cls} btn-sm`, disabled: disabled ? true : null, text: label, on: { click: fn } });

			function draw() {
				h.textContent = D.cert ? t('media.dlg.cert.title') : D.edit ? t('media.dlg.editTitle') : t('media.dlg.title');
				clear(body);
				clear(foot);
				if (D.cert) { drawCert(); return; }
				if (!D.edit && D.step !== 'qc' && D.step !== 'server') {
					const seg = el('div', { class: 'seg md-kinds', role: 'tablist' });
					for (const k of MS.KINDS) {
						seg.appendChild(el('button', {
							type: 'button', role: 'tab', class: D.kind === k ? 'on' : '', 'aria-selected': D.kind === k ? 'true' : 'false', 'data-kind': k,
							text: t(`media.dlg.kind.${k}`), on: { click: () => { if (D.busy) return; D.kind = k; D.step = 'start'; D.error = null; D.conflict = false; D.address = ''; draw(); if (k === 'jellyfin') discover(); } },
						}));
					}
					body.appendChild(seg);
				}
				if (D.kind === 'jellyfin') drawJellyfin(); else drawShare();
			}

			// Jellyfin ------------------------------------------------------

			async function discover() {
				D.found = null;
				draw();
				let r;
				try { r = await api.discover(); } catch (err) { r = fail(err); }
				if (!dlg || dlg.box !== box) return;
				D.found = r && r.ok ? r.servers || [] : [];
				if (D.step === 'start') draw();
			}

			function drawJellyfin() {
				if (D.step === 'start') {
					const lan = el('div', { class: 'md-found' }, [el('div', { class: 'md-found-h', text: t('media.dlg.found') })]);
					if (D.found === null) lan.appendChild(el('div', { class: 'md-found-none', text: t('media.dlg.searching') }));
					else if (!D.found.length) lan.appendChild(el('div', { class: 'md-found-none' }, [el('span', { text: t('media.dlg.noneFound') }), ' ', el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('media.dlg.searchAgain'), on: { click: () => discover() } })]));
					else for (const s of D.found) {
						const on = MS.smbHost(D.address) === null && D.address === s.address;
						lan.appendChild(el('button', { type: 'button', class: `md-server${on ? ' is-on' : ''}`, on: { click: () => { D.address = s.address; serverStep(); } } }, [
							el('span', { class: 'md-card-ic' }, [icon('film', 16, '1.9')]),
							el('span', { class: 'md-card-tx' }, [el('b', { text: s.name || 'Jellyfin' }), el('small', { text: String(s.address).replace(/^https?:\/\//, '') })]),
							icon('right', 16),
						]));
					}
					body.appendChild(lan);
					body.appendChild(field(t('media.dlg.address'), { type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: '192.168.1.20' }, 'address', { hint: t('media.dlg.hint.jellyfin'), enter: () => serverStep() }));
					const e = errorNote();
					if (e) body.appendChild(e);
					foot.append(btn(t('media.dlg.cancel'), 'btn-ghost', () => close()), btn(t('media.dlg.next'), 'btn-pri md-next', () => serverStep(), D.busy));
					return;
				}
				// a server: its name, then Quick Connect or name and password
				const sv = D.server && D.server.server;
				body.appendChild(el('div', { class: 'md-server is-static' }, [
					el('span', { class: 'md-card-ic' }, [icon('film', 16, '1.9')]),
					el('span', { class: 'md-card-tx' }, [el('b', { text: (sv && sv.name) || 'Jellyfin' }), el('small', { text: `${String(D.server.address).replace(/^https?:\/\//, '')}${sv && sv.version ? ` · Jellyfin ${sv.version}` : ''}` })]),
					el('span', { class: 'md-pill is-acc' }, [icon('check', 12, '3'), el('span', { text: t('media.dlg.reached') })]),
				]));
				const qcOn = D.server.quickConnect === true;
				if (!qcOn) D.method = 'password';
				const seg = el('div', { class: 'seg md-methods', role: 'tablist' });
				for (const m of ['qc', 'password']) {
					seg.appendChild(el('button', {
						type: 'button', role: 'tab', class: D.method === m ? 'on' : '', 'aria-selected': D.method === m ? 'true' : 'false', disabled: m === 'qc' && !qcOn ? true : null,
						text: m === 'qc' ? t('media.dlg.qc') : t('media.dlg.userPass'), on: { click: () => { D.method = m; D.error = null; draw(); if (m === 'qc' && !D.qc) startQc(); } },
					}));
				}
				body.appendChild(seg);
				if (!qcOn) body.appendChild(el('div', { class: 'note note-neutral', text: t('media.error.quick_connect_off') }));
				if (D.method === 'qc') {
					if (!D.qc) body.appendChild(el('div', { class: 'md-state is-small', text: t('media.loading') }));
					else if (D.qc.expired) {
						body.appendChild(el('div', { class: 'note note-warn', text: t('media.error.expired') }));
						foot.append(btn(t('media.dlg.cancel'), 'btn-ghost', () => close()), btn(t('media.dlg.qcNew'), 'btn-pri', () => startQc()));
					} else {
						body.appendChild(el('div', { class: 'md-qc' }, [
							el('div', { class: 'md-qc-k', text: t('media.dlg.qcCode') }),
							el('div', { class: 'md-qc-code mono', text: MS.codeLabel(D.qc.code) }),
							el('div', { class: 'md-qc-hint', text: t('media.dlg.qcHint') }),
							el('div', { class: 'md-qc-wait' }, [el('span', { class: 'dot pulse' }), el('span', { text: t('media.dlg.qcWaiting') })]),
						]));
					}
				} else {
					body.appendChild(field(t('media.dlg.user'), { type: 'text', autocomplete: 'username', spellcheck: 'false' }, 'user'));
					body.appendChild(field(t('media.dlg.password'), { type: 'password', autocomplete: 'current-password' }, 'password', { enter: () => signIn() }));
					body.appendChild(el('div', { class: 'md-chk' }, [icon('check', 14, '2.4'), el('span', { text: t('media.dlg.passwordOnce') })]));
				}
				const e = errorNote();
				if (e) body.appendChild(e);
				if (!foot.childNodes.length) {
					foot.append(btn(t('media.dlg.back'), 'btn-ghost', () => { stopQc(); D.step = 'start'; D.server = null; D.error = null; draw(); }));
					if (D.method === 'password') foot.append(btn(t('media.dlg.signIn'), 'btn-pri md-signin', () => signIn(), D.busy));
				}
			}

			async function serverStep() {
				if (D.busy || !D.address.trim()) return;
				D.busy = true; D.error = null; draw();
				let r;
				try { r = await api.server(D.address.trim()); } catch (err) { r = fail(err); }
				D.busy = false;
				if (!dlg || dlg.box !== box) return;
				if (r && !r.ok && (r.code === 'cert_untrusted' || r.code === 'cert_changed') && r.certificate) {
					D.cert = { address: r.address, certificate: r.certificate, changed: r.code === 'cert_changed', then: () => serverStep() };
					draw();
					return;
				}
				if (!r || !r.ok) { D.error = MS.errorText(r && r.code, t); draw(); return; }
				D.server = r;
				D.step = 'server';
				D.method = r.quickConnect ? 'qc' : 'password';
				draw();
				if (D.method === 'qc') startQc();
			}

			function stopQc() {
				clearTimeout(pollTimer);
				if (D.qc && D.qc.flow) api.quickConnect.cancel(D.qc.flow).catch(() => {});
				D.qc = null;
			}

			async function startQc() {
				stopQc();
				D.error = null;
				draw();
				let r;
				try { r = await api.quickConnect.start(D.server.address); } catch (err) { r = fail(err); }
				if (!dlg || dlg.box !== box || D.method !== 'qc') { if (r && r.ok) api.quickConnect.cancel(r.flow).catch(() => {}); return; }
				if (!r || !r.ok) {
					if (r && r.code === 'quick_connect_off') { D.server.quickConnect = false; D.method = 'password'; }
					else D.error = MS.errorText(r && r.code, t);
					draw();
					return;
				}
				D.qc = { flow: r.flow, code: r.code };
				draw();
				poll();
			}

			function poll() {
				clearTimeout(pollTimer);
				pollTimer = setTimeout(async () => {
					if (!dlg || dlg.box !== box || !D.qc || !D.qc.flow) return;
					const flow = D.qc.flow;
					let r;
					try { r = await api.quickConnect.poll(flow); } catch (err) { r = fail(err); }
					if (!dlg || dlg.box !== box || !D.qc || D.qc.flow !== flow) return;
					if (r && r.ok && r.state === 'done') { D.qc = null; done(r.source); return; }
					if (r && !r.ok && r.code === 'expired') { D.qc = { expired: true }; draw(); return; }
					if (r && !r.ok && r.code !== 'offline') { D.error = MS.errorText(r.code, t); draw(); }
					poll();
				}, POLL_MS);
			}

			async function signIn() {
				if (D.busy || !D.user.trim()) return;
				D.busy = true; D.error = null; draw();
				let r;
				try { r = await api.signIn({ address: D.server.address, user: D.user.trim(), password: D.password }); } catch (err) { r = fail(err); }
				D.busy = false;
				if (!dlg || dlg.box !== box) return;
				if (!r || !r.ok) { D.error = MS.errorText(r && r.code, t); draw(); return; }
				D.password = '';
				done(r.source);
			}

			// The certificate -------------------------------------------

			function drawCert() {
				const c = D.cert.certificate || {};
				body.appendChild(el('p', { class: 'desc', text: D.cert.changed ? t('media.dlg.cert.changed') : t('media.dlg.cert.text') }));
				const dl = el('dl', { class: 'md-cert' });
				const row = (k, v, mono) => { if (v) dl.append(el('dt', { text: k }), el('dd', { class: mono ? 'mono' : '', text: v })); };
				row(t('media.dlg.cert.address'), D.cert.address);
				row(t('media.dlg.cert.subject'), c.subject);
				row(t('media.dlg.cert.issuer'), c.issuer);
				row(t('media.dlg.cert.validTo'), c.validTo ? MS.dateLabel(c.validTo, locale()) : null);
				row(t('media.dlg.cert.fingerprint'), MS.fingerprintLabel(c.fingerprint), true);
				body.appendChild(dl);
				const e = errorNote();
				if (e) body.appendChild(e);
				foot.append(btn(t('media.dlg.cancel'), 'btn-ghost', () => { D.cert = null; draw(); }), btn(t('media.dlg.cert.trust'), 'btn-pri md-trust', () => trust(), D.busy));
			}

			async function trust() {
				const c = D.cert;
				D.busy = true; draw();
				let r;
				try { r = await api.trust(c.address, c.certificate.fingerprint); } catch (err) { r = fail(err); }
				D.busy = false;
				if (!dlg || dlg.box !== box) return;
				if (!r || !r.ok) { D.error = MS.errorText(r && r.code, t); draw(); return; }
				D.cert = null;
				D.error = null;
				c.then();
			}

			// Shares ----------------------------------------------------

			function drawShare() {
				const smb = D.kind === 'smb';
				body.appendChild(field(t('media.dlg.address'), { type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: smb ? '\\\\192.168.1.20\\filme' : 'https://192.168.1.20:5006/filme' }, 'address', {
					hint: smb ? t('media.dlg.hint.smb') : t('media.dlg.hint.webdav'),
					onInput: () => { if (smb) { nameHint.hidden = !MS.smbNameHint(D.address); if (D.alsoWebdav && !D.webdavTouched) { D.webdavAddress = MS.webdavFor(D.address); if (webdavInp) webdavInp.value = D.webdavAddress; } } },
					enter: () => submitShare(),
				}));
				const nameHint = el('div', { class: 'note note-info md-ip-hint', hidden: !(smb && MS.smbNameHint(D.address)), text: t('media.dlg.smbIp', { host: MS.smbHost(D.address) || 'nas' }) });
				if (smb) body.appendChild(nameHint);
				body.appendChild(el('div', { class: 'md-two' }, [
					field(t('media.dlg.user'), { type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: t('media.dlg.userHint') }, 'user'),
					field(t('media.dlg.password'), { type: 'password', autocomplete: 'off' }, 'password', { enter: () => submitShare() }),
				]));
				if (smb) {
					body.appendChild(el('div', { class: 'md-note' }, [el('b', { text: t('media.dlg.smbNoteStrong') }), ' ', el('span', { text: t('media.dlg.smbNote') })]));
				}
				if (D.conflict) {
					body.appendChild(el('div', { class: 'note note-warn md-conflict', role: 'alert' }, [
						el('div', { text: t('media.dlg.conflict', { host: MS.smbHost(D.address) || '' }) }),
						el('button', { type: 'button', class: 'btn btn-sec btn-sm md-use-existing', disabled: D.busy ? true : null, text: t('media.dlg.useExisting'), on: { click: () => submitShare({ useExisting: true }) } }),
					]));
				}
				body.appendChild(el('div', { class: 'md-chk' }, [icon('check', 14, '2.4'), el('span', { text: t('media.dlg.encrypted') })]));
				let webdavInp = null;
				if (smb && !D.edit) {
					const cb = el('input', { type: 'checkbox', class: 'md-also-webdav', checked: D.alsoWebdav ? true : null });
					cb.addEventListener('change', () => { D.alsoWebdav = cb.checked; if (D.alsoWebdav && !D.webdavAddress) D.webdavAddress = MS.webdavFor(D.address); draw(); });
					body.appendChild(el('label', { class: 'md-chk is-box' }, [cb, el('span', { text: t('media.dlg.alsoWebdav') })]));
					if (D.alsoWebdav) {
						const f = field(t('media.dlg.webdavAddress'), { type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'https://192.168.1.20:5006/filme' }, 'webdavAddress', { hint: t('media.dlg.hint.webdav'), onInput: () => { D.webdavTouched = true; } });
						webdavInp = f.querySelector('input');
						body.appendChild(f);
					}
				}
				const e = errorNote();
				if (e) body.appendChild(e);
				foot.append(btn(t('media.dlg.cancel'), 'btn-ghost', () => close(), D.busy), btn(D.busy ? t('media.dlg.connecting') : t('media.dlg.connect'), 'btn-pri md-connect', () => submitShare(), D.busy));
			}

			async function submitShare(opts = {}) {
				if (D.busy) return;
				const problem = MS.formProblem(D.kind, D);
				if (problem) { D.error = t(`media.dlg.problem.${problem}`); draw(); return; }
				D.busy = true; D.error = null; draw();
				const useExisting = opts.useExisting === true;
				let r;
				try {
					r = await api.addShare({ kind: D.kind, address: D.address.trim(), user: useExisting ? null : (D.user.trim() || null), password: useExisting ? null : (D.user.trim() ? D.password : null), useExisting });
				} catch (err) { r = fail(err); }
				D.busy = false;
				if (!dlg || dlg.box !== box) return;
				if (r && !r.ok && (r.code === 'cert_untrusted' || r.code === 'cert_changed') && r.certificate) {
					D.cert = { address: r.address, certificate: r.certificate, changed: r.code === 'cert_changed', then: () => submitShare(opts) };
					draw();
					return;
				}
				if (r && !r.ok && r.code === 'smb_conflict') { D.conflict = true; D.error = null; draw(); return; }
				if (!r || !r.ok) { D.error = MS.errorText(r && r.code, t); draw(); return; }
				if (D.kind === 'smb' && D.alsoWebdav && D.webdavAddress.trim()) {
					const w = await addWebdav();
					if (!w) return;
				}
				D.password = '';
				done(r.source);
			}

			/** "Auch als WebDAV einrichten": the same folder over HTTPS (the same name and password). */
			async function addWebdav() {
				D.busy = true; draw();
				let r;
				try { r = await api.addShare({ kind: 'webdav', address: D.webdavAddress.trim(), user: D.user.trim() || null, password: D.user.trim() ? D.password : null }); } catch (err) { r = fail(err); }
				D.busy = false;
				if (!dlg || dlg.box !== box) return false;
				if (r && !r.ok && (r.code === 'cert_untrusted' || r.code === 'cert_changed') && r.certificate) {
					D.cert = { address: r.address, certificate: r.certificate, changed: r.code === 'cert_changed', then: async () => { const ok = await addWebdav(); if (ok) { D.password = ''; done(null); } } };
					draw();
					return false;
				}
				if (!r || !r.ok) {
					toast(t('media.dlg.webdavFailed', { error: MS.errorText(r && r.code, t) }), 'warning');
					D.alsoWebdav = false;
					return true;
				}
				return true;
			}

			function done(src) {
				close();
				toast(t('media.dlg.done', { name: src ? MS.sourceChip(src, t) : t('media.dlg.kind.webdav') }), 'success');
				o.reloadStatus();
			}

			draw();
			if (D.kind === 'jellyfin') {
				if (pre.address) serverStep(); else discover();
			}
			setTimeout(() => { const f = body.querySelector('input:not([type=checkbox]), button'); (f || box).focus(); }, 0);
		}

		/** A Jellyfin source signed out (401): the dialog on its address. */
		function signInAgain(s) {
			add({ kind: 'jellyfin', address: s.address });
		}

		return {
			show() { S.shown = true; render(); },
			hide() { S.shown = false; if (dlg) dlg.close(); },
			render() { if (S.shown) render(); },
			add: (pre) => add(pre || {}),
			signInAgain,
		};
	}

	root.GCMediaSources = { mount };
})(typeof window !== 'undefined' ? window : globalThis);
