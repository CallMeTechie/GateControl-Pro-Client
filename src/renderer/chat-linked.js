/**
 * GateControl -- Chats: "Verknüpfte Dienste" (renderer, Messenger 1.13.0)
 *
 * A section of the chat settings page (chat-settings.js), shown only while
 * `GET me` features has `linked_services`: a person links their OWN account
 * at another messenger (first WhatsApp) with the bridge that runs next to
 * GateControl. Like the portal's page of the same name:
 *
 *   overview  per service: not linked / linked since, own number / signed
 *             out / error / locked for a child / starting / not reachable /
 *             outdated; where the bridges run
 *   notes     before the first link, confirmed once per service
 *   link      a pairing code (the number is asked for first) or a QR code,
 *             drawn from its modules, black on white; the page asks the
 *             server for the next step until the phone confirmed (the
 *             server waits up to 15 s per call). A code that ran out or was
 *             refused offers "Neuen Code anfordern".
 *
 * Messenger 1.17 (feature `bridge_history`, GET bridges → history): the row
 * „Älteren Verlauf laden“ (Aus / Letzte 30 Tage / Alles, PUT bridges/history)
 * under the services, the warning „Handy seit N Tagen nicht gesehen“ under a
 * service (networks[].phone) and „Brücke veraltet“ also by `clientOutdated`.
 *
 * Different from the phone apps: no "open WhatsApp" button (the phone is
 * another device), "Code kopieren" instead. Leaving the section or the
 * settings page drops a login that was not finished; up to three waiting
 * calls in a row may stay without an answer before a code is given up.
 * The number, the pairing code and the QR content exist only for as long as
 * they show: never stored on this PC, never written to a log.
 *
 * Mounted by chat-settings.js: window.GCChatLinked.create(kit).
 * Note: user data only ever goes into textContent / attributes.
 */
(function (root) {
	'use strict';

	const CS = root.GCChatState;
	const POLL_MS = 1500;
	const MAX_MISSES = 3;
	const CLIPBOARD_MS = 60000;
	const NS = 'http://www.w3.org/2000/svg';

	function create(kit) {
		const { api, t, el, icon, iconBtn, clear, confirmDialog, toast } = kit;
		let host = null;          // where the section is drawn right now (the page redraws it at will)
		let info = null;          // GET bridges
		let loading = false;
		let loadError = null;
		// what shows: { name: 'overview' } | { name: 'notes', net, saving } |
		// { name: 'link', net, flow, phase: 'starting' | 'phone' | 'code' | 'qr' | 'failed', … }
		let view = { name: 'overview' };
		let run = null;           // the link in progress: { net, process, stopped, timer }
		let copied = null;        // the code put on the clipboard (cleared again when it is still there)
		let copyTimer = null;
		let histSaving = false;   // PUT bridges/history in flight

		const name = (id) => CS.bridgeName(id);
		const network = (id) => (info && Array.isArray(info.networks) ? info.networks.find((n) => n.id === id) : null) || null;
		const call = (p) => p.catch((e) => ({ ok: false, code: 'failed', error: e && e.message }));
		const pill = (p) => (p ? el('span', { class: `cv-chip cv-br-pill is-${p.tone}`, text: p.text }) : null);
		const note = (ic, text, cls = '') => el('p', { class: `cv-note cv-note-lock ${cls}`.trim() }, [icon(ic, 14), el('span', { text })]);

		// ── Data ────────────────────────────────────────────

		async function load() {
			loading = true;
			paint();
			const r = await call(api.bridges());
			loading = false;
			if (r && r.ok !== false && r.bridges) { info = r.bridges; loadError = null; } else loadError = r || { code: 'failed' };
			paint();
		}

		// ── The link itself ─────────────────────────────────

		/** End what is in progress; with tell: ask the bridge to drop the login as well. */
		function stopRun(tell) {
			const r = run;
			if (!r) return;
			run = null;
			r.stopped = true;
			clearTimeout(r.timer);
			if (tell && r.process) api.bridgeCancel(r.net, r.process).catch(() => {});
		}

		function begin(id) {
			const n = network(id);
			if (!n || !n.allowed) return;
			if (n.consent) link(id, 'phone');
			else { view = { name: 'notes', net: id, saving: false }; paint(); }
		}

		async function confirmNotes() {
			const v = view;
			if (v.name !== 'notes' || v.saving) return;
			v.saving = true;
			paint();
			const r = await call(api.bridgeConsent(v.net));
			if (view !== v) return;
			if (!r || r.ok === false) { v.saving = false; refused(r); return; }
			const n = network(v.net);
			if (n) n.consent = true;
			link(v.net, 'phone');
		}

		async function link(id, flow) {
			stopRun(true);
			const mine = { net: id, process: null, stopped: false, timer: null, misses: 0 };
			run = mine;
			view = { name: 'link', net: id, flow, phase: 'starting' };
			paint();
			const r = await call(api.bridgeLogin(id, flow));
			if (mine.stopped) {
				// left while the bridge was still answering: drop what it started
				const pid = r && r.login && r.login.processId;
				if (pid) api.bridgeCancel(id, pid).catch(() => {});
				return;
			}
			if (!r || r.ok === false) { failed(mine, r); return; }
			onStep(mine, r.login);
		}

		function onStep(mine, login) {
			if (mine.stopped || view.name !== 'link') return;
			const lg = login || {};
			mine.process = lg.processId || mine.process;
			mine.misses = 0;
			const step = lg.step || {};
			if (lg.waiting) {
				// only a step that shows something is waited for
				if (!mine.waitingOn) { failed(mine, { code: 'bridge_unsupported' }, true); return; }
				mine.timer = setTimeout(() => poll(mine), POLL_MS);
			} else if (step.type === 'complete') {
				run = null;
				mine.stopped = true;
				toast(t('chat.br.linked', { name: name(mine.net) }), 'success');
				view = { name: 'overview' };
				load();
				// the chats of this service may arrive now
				if (typeof kit.refreshList === 'function') kit.refreshList({ server: true });
			} else if (step.type === 'phone') {
				mine.waitingOn = null;
				view = { ...view, phase: 'phone', stepId: step.id, fieldId: step.fieldId, sending: false, error: null, draft: '' };
				paint();
			} else if (step.type === 'code' || step.type === 'qr') {
				// WhatsApp renews the QR code a few times: each one is a new step
				mine.waitingOn = step.id;
				view = step.type === 'code' ? { ...view, phase: 'code', code: step.code } : { ...view, phase: 'qr', matrix: step.matrix };
				paint();
				poll(mine);
			} else {
				failed(mine, { code: 'bridge_unsupported' }, true);
			}
		}

		async function poll(mine) {
			if (mine.stopped || !mine.waitingOn) return;
			const r = await call(api.bridgeStep(mine.net, mine.process, mine.waitingOn));
			if (mine.stopped) return;
			if (!r || r.ok === false) {
				// a gap in the connection while waiting is no reason to throw a valid code away
				const gap = r && (r.code === 'network' || r.code === 'timeout');
				if (gap && (mine.misses += 1) <= MAX_MISSES) { mine.timer = setTimeout(() => poll(mine), POLL_MS); return; }
				failed(mine, r, gap);
				return;
			}
			onStep(mine, r.login);
		}

		async function submitPhone(raw) {
			const v = view;
			const mine = run;
			if (v.name !== 'link' || v.phase !== 'phone' || v.sending || !mine) return;
			v.sending = true;
			v.error = null;
			paint();
			const r = await call(api.bridgeStep(mine.net, mine.process, v.stepId, { phone: String(raw || ''), fieldId: v.fieldId }));
			if (mine.stopped || view !== v) return;
			if (r && r.ok === false && (r.code === 'phone_invalid' || r.code === 'bridge_failed')) {
				// not a number with its country code / one the service does not take: stay here
				v.sending = false;
				v.error = r.code === 'phone_invalid' ? 'invalid' : 'refused';
				paint();
				return;
			}
			v.draft = '';
			if (!r || r.ok === false) { failed(mine, r); return; }
			onStep(mine, r.login);
		}

		/** This attempt ended; `tell`: the bridge may still hold the login — drop it. */
		function failed(mine, r, tell = false) {
			if (run === mine) run = null;
			mine.stopped = true;
			clearTimeout(mine.timer);
			if (tell && mine.process) api.bridgeCancel(mine.net, mine.process).catch(() => {});
			const code = r && r.code;
			if (code === 'consent_required') {
				// the notes were not confirmed after all: show them
				const n = network(mine.net);
				if (n) n.consent = false;
				view = { name: 'notes', net: mine.net, saving: false };
				paint();
			} else if (code === 'bridge_locked' || code === 'bridge_off') {
				refused(r);
			} else if (view.name === 'link') {
				view = { name: 'link', net: mine.net, flow: view.flow, phase: 'failed', error: r || { code: 'failed' } };
				paint();
			}
		}

		/** Messenger 1.17: „Älteren Verlauf laden“ — 0, 30 or -1; holds at the next link. */
		async function setHistory(days) {
			if (histSaving || !info || !info.history) return;
			histSaving = true;
			paint();
			const r = await call(api.bridgeHistory(days));
			histSaving = false;
			if (r && r.ok !== false && r.history) {
				info.history = r.history;
				toast(t('chat.br.hist_saved'), 'success');
			} else {
				toast(CS.errorText(r, t), 'error');
			}
			paint();
		}

		/** A refusal outside a running link: said in a toast; locked / switched off → the overview says so. */
		function refused(r) {
			toast(CS.errorText(r, t), 'error');
			if (r && (r.code === 'bridge_locked' || r.code === 'bridge_off')) { view = { name: 'overview' }; load(); } else paint();
		}

		async function unlink(id, quiet) {
			const n = network(id);
			const l = n ? CS.mainLogin(n) : null;
			if (!l) return;
			if (!quiet && !(await confirmDialog(t('chat.br.unlink_confirm', { name: name(id) }), t('chat.br.unlink'), true))) return;
			const r = await call(api.bridgeUnlink(id, l.id));
			if (!r || r.ok === false) toast(CS.errorText(r, t), 'error');
			else if (!quiet) toast(t('chat.br.unlinked', { name: name(id) }), 'success');
			load();
			if (typeof kit.refreshList === 'function') kit.refreshList({ server: true });
		}

		function back() {
			const wasLink = view.name === 'link';
			stopRun(true);
			view = { name: 'overview' };
			if (wasLink) load(); else paint();
		}

		// ── Clipboard ───────────────────────────────────────

		function copyCode(code) {
			const cb = root.navigator && root.navigator.clipboard;
			if (!cb || typeof cb.writeText !== 'function') return;
			cb.writeText(String(code)).then(() => {
				toast(t('chat.br.code_copied'), 'success');
				copied = String(code);
				clearTimeout(copyTimer);
				copyTimer = setTimeout(clearCopied, CLIPBOARD_MS);
			}).catch(() => {});
		}

		/** The code leaves the clipboard again when it is still there (best effort: Windows may refuse the read). */
		function clearCopied() {
			const code = copied;
			copied = null;
			clearTimeout(copyTimer);
			const cb = root.navigator && root.navigator.clipboard;
			if (!code || !cb || typeof cb.readText !== 'function') return;
			cb.readText().then((now) => { if (now === code) return cb.writeText(''); return null; }).catch(() => {});
		}

		// ── Drawing ─────────────────────────────────────────

		function paint() {
			if (!host || !host.isConnected) return;
			clear(host);
			const nodes = view.name === 'notes' ? notesView() : (view.name === 'link' ? linkView() : overview());
			for (const n of nodes) if (n) host.appendChild(n);
		}

		function overview() {
			const out = [el('p', { class: 'cv-br-lead', text: t('chat.br.lead') })];
			if (!info) {
				if (loadError && !loading) {
					out.push(el('div', { class: 'cv-set-card' }, [el('div', { class: 'cv-pref' }, [
						el('span', { class: 'cv-pref-tx' }, [el('b', { text: t('chat.br.load_failed') }), el('small', { text: CS.errorText(loadError, t) })]),
						el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('chat.retry'), on: { click: () => load() } }),
					])]));
				} else {
					out.push(el('div', { class: 'cv-set-card' }, [el('p', { class: 'cv-dim cv-set-pad', text: t('chat.loading') })]));
				}
				return out;
			}
			const nets = info.available ? info.networks.filter((n) => CS.linkable(n.id)) : [];
			if (!nets.length) {
				out.push(el('div', { class: 'cv-set-card' }, [el('p', { class: 'cv-dim cv-set-pad', text: t('chat.br.none_offered') })]));
				return out;
			}
			const cx = kit.ctx();
			const outdated = nets.filter((n) => CS.isOutdated(n));
			if (outdated.length) out.push(note('info', t('chat.br.outdated_banner', { name: name(outdated[0].id) }), 'cv-br-warn'));
			const card = el('div', { class: 'cv-set-card cv-br-list' });
			for (const n of nets) {
				const r = CS.linkedRow(n, cx);
				card.appendChild(el('div', { class: 'cv-pref cv-br-row', 'data-net': n.id, 'data-state': r.state }, [
					el('span', { class: 'cv-br-mark', 'aria-hidden': 'true', text: r.mark }),
					el('span', { class: 'cv-pref-tx' }, [el('b', { text: r.name }), el('small', { text: r.sub })]),
					el('span', { class: 'cv-br-act' }, [
						pill(r.pill),
						r.unlink ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-act': 'unlink', text: t('chat.br.unlink'), on: { click: () => unlink(n.id, false) } }) : null,
						r.link ? el('button', { type: 'button', class: 'btn btn-pri btn-sm', 'data-act': 'link', text: t('chat.br.link'), on: { click: () => begin(n.id) } }) : null,
					]),
				]));
				if (r.again) {
					card.appendChild(el('div', { class: 'cv-pref cv-br-again', 'data-net': n.id }, [
						el('span', { class: 'cv-pref-tx' }, [el('b', { text: t('chat.br.relink') }), el('small', { text: r.again.hint })]),
						el('span', { class: 'cv-br-act' }, [
							r.again.link ? el('button', { type: 'button', class: 'btn btn-pri btn-sm', 'data-act': 'relink', text: t('chat.br.relink_btn', { name: r.name }), on: { click: () => begin(n.id) } }) : null,
							r.again.forget ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-act': 'forget', text: t('chat.br.forget'), on: { click: () => unlink(n.id, true) } }) : null,
						]),
					]));
				}
				// Messenger 1.17: the phone was not seen for days — the link still works, but not for long
				if (r.phone) card.appendChild(el('div', { class: 'cv-br-phone-row', 'data-net': n.id }, [note('info', r.phone, 'cv-br-warn')]));
			}
			out.push(el('div', { class: 'cv-set-group' }, [card]));
			// Messenger 1.17: older messages — what comes over at the next link
			const h = CS.historyRow(info.history, t);
			if (h) {
				let pick = null;
				if (h.available) {
					pick = el('select', { class: 'inp cv-select', id: 'cv-br-hist', 'data-act': 'history', 'aria-label': h.title, disabled: histSaving ? true : null }, h.options.map((o) => el('option', { value: String(o.value), text: o.label })));
					pick.value = String(h.value);
					pick.addEventListener('change', () => setHistory(Number(pick.value)));
				}
				out.push(el('div', { class: 'cv-set-group' }, [el('div', { class: 'cv-set-card' }, [el('div', { class: 'cv-pref', 'data-pref': 'history', 'data-available': h.available ? 'true' : 'false' }, [
					el('span', { class: 'cv-pref-tx' }, [el('b', { text: h.title }), el('small', { text: h.sub })]),
					pick,
				])])]));
			}
			out.push(el('div', { class: 'cv-set-group' }, [el('div', { class: 'cv-set-card' }, [el('div', { class: 'cv-pref', 'data-pref': 'runsOn' }, [
				el('span', { class: 'cv-pref-tx' }, [el('b', { text: t('chat.br.runs_on') }), el('small', { text: `${t(info.location === 'gateway' ? 'chat.br.runs_on_gateway' : 'chat.br.runs_on_server')} · ${t(outdated.length ? 'chat.br.runs_outdated' : 'chat.br.runs_current')}` })]),
				pill(outdated.length ? { text: t('chat.br.pill_outdated'), tone: 'warn' } : { text: t('chat.br.pill_ok'), tone: 'ok' }),
			])])]));
			if (outdated.length) out.push(el('p', { class: 'cv-note', text: t('chat.br.outdated_hint') }));
			out.push(el('p', { class: 'cv-note', text: t('chat.br.foot_unlink') }));
			// what the chat list does with a linked service — said only where the server has such chats for this person
			if (info.history) out.push(note('lock', t('chat.br.foot_preview_hist')));
			else if (CS.features14(kit.me()).bridgeChats) out.push(note('lock', t('chat.br.foot_preview')));
			return out;
		}

		function head(titleText) {
			return el('div', { class: 'cv-br-head' }, [iconBtn('back', t('chat.br.back'), () => back(), 'cv-ib-flat cv-br-back'), el('b', { text: titleText })]);
		}

		function notesView() {
			const v = view;
			const box = el('input', { type: 'checkbox', id: 'cv-br-ok' });
			const next = el('button', { type: 'button', class: 'btn btn-pri', 'data-act': 'next', text: t('chat.br.next'), disabled: true });
			box.addEventListener('change', () => { next.disabled = !box.checked || v.saving; });
			next.addEventListener('click', () => confirmNotes());
			if (v.saving) { box.checked = true; box.disabled = true; }
			return [
				head(t('chat.br.notes_title', { name: name(v.net) })),
				el('ul', { class: 'cv-br-notes' }, (CS.LINK_NOTES[v.net] || []).map((k) => el('li', { text: t(`chat.br.note_${v.net}_${k}`) }))),
				el('label', { class: 'cv-br-check', for: 'cv-br-ok' }, [box, el('span', { text: t('chat.br.notes_confirm') })]),
				el('div', { class: 'cv-br-bar' }, [el('span', { class: 'cv-dim', text: t('chat.br.notes_free') }), next]),
			];
		}

		function tabs(v) {
			return el('div', { class: 'cv-chips cv-br-tabs', role: 'tablist', 'aria-label': t('chat.br.flows') }, CS.LINK_FLOWS.map((f) => el('button', {
				type: 'button', role: 'tab', class: 'cv-chip-btn', 'data-flow': f, 'aria-pressed': f === v.flow ? 'true' : 'false', 'aria-selected': f === v.flow ? 'true' : 'false', text: t(`chat.br.flow_${f}`),
				on: { click: () => { if (f !== v.flow) link(v.net, f); } },
			})));
		}

		const steps = (keys) => el('ol', { class: 'cv-br-steps' }, keys.map((k) => el('li', { text: t(k) })));
		const waiting = () => el('p', { class: 'cv-br-wait', role: 'status' }, [el('span', { class: 'cv-br-dot', 'aria-hidden': 'true' }), el('span', { text: t('chat.br.waiting') })]);

		function qrSvg(matrix) {
			const q = CS.qrPath(matrix);
			if (!q) return null;
			// always black on white, whatever the theme: phones scan it
			const s = document.createElementNS(NS, 'svg');
			s.setAttribute('viewBox', `0 0 ${q.size} ${q.size}`);
			s.setAttribute('class', 'cv-br-qr');
			s.setAttribute('role', 'img');
			s.setAttribute('aria-label', t('chat.br.qr_alt'));
			s.setAttribute('shape-rendering', 'crispEdges');
			const bg = document.createElementNS(NS, 'rect');
			bg.setAttribute('width', String(q.size));
			bg.setAttribute('height', String(q.size));
			bg.setAttribute('fill', '#fff');
			const p = document.createElementNS(NS, 'path');
			p.setAttribute('d', q.d);
			p.setAttribute('fill', '#000');
			s.append(bg, p);
			return s;
		}

		function linkView() {
			const v = view;
			const out = [head(t('chat.br.link_title', { name: name(v.net) })), tabs(v)];
			if (v.phase === 'starting') {
				out.push(el('p', { class: 'cv-dim', text: t('chat.loading') }));
			} else if (v.phase === 'phone') {
				const input = el('input', { type: 'tel', class: 'inp cv-br-phone', id: 'cv-br-phone', inputmode: 'tel', autocomplete: 'off', spellcheck: 'false', maxlength: '40', placeholder: t('chat.br.phone_placeholder') });
				input.value = v.draft || '';
				input.disabled = !!v.sending;
				// kept for a redraw of the page only — never stored, gone once it was sent or the page left
				input.addEventListener('input', () => { v.draft = input.value; });
				const go = el('button', { type: 'button', class: 'btn btn-pri', 'data-act': 'code', text: t('chat.br.get_code'), disabled: v.sending ? true : null, on: { click: () => submitPhone(input.value) } });
				input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); submitPhone(input.value); } });
				out.push(
					el('label', { class: 'cv-field cv-br-field', for: 'cv-br-phone' }, [el('span', { text: t('chat.br.phone_label', { name: name(v.net) }) }), input]),
					v.error ? el('p', { class: 'cv-br-err', role: 'alert', text: t(v.error === 'invalid' ? 'chat.br.phone_invalid' : 'chat.br.phone_refused') }) : null,
					el('p', { class: 'cv-note', text: t('chat.br.phone_hint') }),
					el('div', { class: 'cv-br-bar' }, [el('span'), go]),
				);
				setTimeout(() => { if (input.isConnected && !input.disabled) input.focus(); }, 30);
			} else if (v.phase === 'code') {
				const boxes = el('div', { class: 'cv-br-code', role: 'group', 'aria-label': `${t('chat.br.code_label')} ${v.code}` }, CS.codeChars(v.code).map((c) => el('span', { class: c.dash ? 'cv-br-dash' : 'cv-br-digit', 'aria-hidden': 'true', text: c.dash ? '–' : c.ch })));
				out.push(
					el('p', { class: 'cv-br-lead', text: t('chat.br.code_lead', { name: name(v.net) }) }),
					boxes,
					el('div', { class: 'cv-br-copy' }, [el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-act': 'copy', on: { click: () => copyCode(v.code) } }, [icon('copy', 13), t('chat.br.copy_code')])]),
					steps([`chat.br.code_step1_${v.net}`, `chat.br.code_step2_${v.net}`, 'chat.br.code_step3']),
					el('p', { class: 'cv-note', text: t('chat.br.code_note') }),
					waiting(),
				);
			} else if (v.phase === 'qr') {
				out.push(
					el('p', { class: 'cv-br-lead', text: t(`chat.br.qr_lead_${v.net}`) }),
					el('div', { class: 'cv-br-qrbox' }, [qrSvg(v.matrix)]),
					steps([`chat.br.qr_step1_${v.net}`, `chat.br.qr_step2_${v.net}`]),
					waiting(),
				);
			} else {
				out.push(
					note('info', CS.linkErrorText(v.error, t), 'cv-br-warn'),
					el('div', { class: 'cv-br-bar' }, [el('span'), el('button', { type: 'button', class: 'btn btn-pri', 'data-act': 'again', text: t(v.flow === 'phone' ? 'chat.br.new_code' : 'chat.br.new_qr'), on: { click: () => link(v.net, v.flow) } })]),
				);
			}
			return out;
		}

		// ── Public ──────────────────────────────────────────

		return {
			/** Draw the section into `body` (a redraw of the page keeps what is in progress). */
			draw(body) {
				const first = !host || !host.isConnected;
				host = el('div', { class: 'cv-br' });
				body.appendChild(host);
				if (first && view.name === 'overview') load(); else paint();
			},
			/** The section or the page was left: a login that was not finished is dropped, number and code forgotten. */
			leave() {
				stopRun(true);
				clearCopied();
				host = null;
				view = { name: 'overview' };
			},
			/** Messenger 1.17: a push of „Verknüpfte Dienste“ came — the overview asks again (nothing else is touched). */
			reload() {
				if (host && host.isConnected && view.name === 'overview') load();
			},
			/** Is something in progress or shown (tests)? */
			state: () => ({ view: view.name, phase: view.phase || null, running: !!run }),
		};
	}

	root.GCChatLinked = { create };
})(typeof self !== 'undefined' ? self : this);
