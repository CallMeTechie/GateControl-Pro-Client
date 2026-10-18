/**
 * GateControl -- Chats: message kinds of Messenger 1.4.0 (renderer)
 *
 * Bubbles for polls, events, live arrivals, home actions and plugin cards
 * (doorbell with picture, buttons and the "Live-Bild" link), the bubble for
 * kinds this version does not know, and the dialogs that create them:
 * "Abstimmung erstellen", "Ereignis erstellen / bearbeiten", "Haus-Aktion
 * senden", plus the suggestion dialogs of the message menu ("Auf
 * Einkaufsliste", "Termin anlegen") and "Erinnere mich".
 *
 * Mounted by chat-view.js with its kit (el, icon, dialog, api, …):
 * window.GCChatRich.create(kit). Windows sends no live arrival; it shows them
 * and stops an own one. Each part is offered only when `GET me` features
 * has its key (kit decides before calling in).
 *
 * Note: user data only ever goes into textContent / attributes; pictures of
 * cards arrive as bytes and are shown as blob: URLs; action icons are SVG
 * path data set as the `d` attribute (checked by GCChatState.iconPath).
 */
(function (root) {
	'use strict';

	const CS = root.GCChatState;
	const NS = 'http://www.w3.org/2000/svg';

	function create(kit) {
		const { api, t, el, icon, clear, dialog, confirmDialog, toast } = kit;
		const fail = (r) => toast(CS.errorText(r, t), 'error');
		const call = async (p) => {
			const r = await p.catch((e) => ({ ok: false, error: e && e.message }));
			if (!r || r.ok === false) { fail(r); return null; }
			return r;
		};
		const blocked = (m, c) => !!m.pending || !!CS.composerBlock(c);

		function head(text, extra) {
			return el('div', { class: 'cv-rich-head' }, [el('span', { text }), extra || null]);
		}

		function serverIcon(d, size = 20) {
			const path = CS.iconPath(d);
			if (!path) return icon('bolt', size);
			const s = document.createElementNS(NS, 'svg');
			s.setAttribute('viewBox', '0 0 24 24');
			s.setAttribute('width', String(size));
			s.setAttribute('height', String(size));
			s.setAttribute('fill', 'currentColor');
			s.setAttribute('aria-hidden', 'true');
			const p = document.createElementNS(NS, 'path');
			p.setAttribute('d', path);
			s.appendChild(p);
			return s;
		}

		function miniAvatars(c, ids, cx) {
			const box = el('span', { class: 'cv-mini-avs' });
			for (const uid of (ids || []).slice(0, 3)) {
				const p = CS.member(c, uid);
				box.appendChild(kit.avatar(p && !p.gone ? CS.personAvatar(p) : { kind: 'person', initials: CS.initials(CS.nameOf(c, uid, cx)), color: '#64748B' }, 20));
			}
			return box;
		}

		// ── Bubble bodies ───────────────────────────────────

		/** The body of a 1.4.0 message inside its bubble, or null for other kinds. */
		function body(m, c, cx) {
			if (!CS.isShownKind(m)) return el('div', { class: 'cv-text cv-dim cv-unsupported' }, [icon('info', 14), el('span', { text: t('chat.msg.unsupported') })]);
			switch (m.kind) {
				case 'poll': return m.poll ? pollEl(m, c, cx) : null;
				case 'event': return m.event ? eventEl(m, c, cx) : null;
				case 'arrival': return m.arrival ? arrivalEl(m, c, cx) : null;
				case 'action': return m.action ? actionEl(m, c, cx) : null;
				case 'card': return m.card ? cardEl(m, c, cx) : null;
				default: return null;
			}
		}

		// ── Poll ──
		function pollEl(m, c, cx) {
			const v = CS.pollView(m.poll, cx);
			const off = blocked(m, c) || v.closed;
			const box = el('div', { class: `cv-poll${v.closed ? ' is-closed' : ''}` });
			box.append(
				head(CS.pollHead(m.poll, cx)),
				el('b', { class: 'cv-poll-q', text: v.question }),
				el('div', { class: 'cv-poll-sub', text: [v.multi ? t('chat.poll.multi') : t('chat.poll.single'), v.memberCount ? t('chat.poll.voted', { n: v.voterCount, of: v.memberCount }) : t('chat.poll.votes', { n: v.voterCount })].join(' · ') }),
			);
			for (const o of v.options) {
				const btn = el('button', {
					type: 'button', class: `cv-poll-opt${o.mine ? ' is-mine' : ''}${v.closed && o.lead ? ' is-lead' : ''}`, 'aria-pressed': o.mine ? 'true' : 'false', disabled: off ? true : null, 'data-option': o.id,
					on: { click: (e) => { e.stopPropagation(); call(api.poll(m.id, 'vote', { optionIds: CS.nextVotes(m.poll, o.id) })); } },
				}, [
					el('span', { class: `cv-poll-check${v.multi ? ' is-multi' : ''}` }, [o.mine ? icon('check', 12, '3') : null]),
					el('span', { class: 'cv-poll-tx', text: o.text }),
					o.voters && o.voters.length ? miniAvatars(c, o.voters, cx) : null,
					el('span', { class: 'cv-poll-n', text: String(o.count) }),
					el('span', { class: 'cv-poll-bar', style: `width:${o.pct}%`, 'aria-hidden': 'true' }),
				]);
				box.appendChild(btn);
			}
			const tools = el('div', { class: 'cv-rich-tools' });
			if (v.allowAdd && !blocked(m, c)) tools.appendChild(el('button', { type: 'button', class: 'cv-link', text: t('chat.poll.addOption'), on: { click: (e) => { e.stopPropagation(); addOptionDialog(m); } } }));
			if (!v.anonymous && v.voterCount) tools.appendChild(el('button', { type: 'button', class: 'cv-link', text: t('chat.poll.showVotes'), on: { click: (e) => { e.stopPropagation(); votesDialog(m, c, cx); } } }));
			const admin = c && c.kind === 'group' && c.me && c.me.role === 'admin';
			if (!v.closed && !m.pending && v.mineCreator && v.voterCount < v.memberCount) {
				tools.appendChild(el('button', { type: 'button', class: 'cv-link', text: t('chat.poll.nudge'), on: { click: async (e) => { e.stopPropagation(); const r = await call(api.poll(m.id, 'nudge')); if (r) toast(t('chat.poll.nudged', { n: r.nudged || 0 }), 'success'); } } }));
			}
			if (!v.closed && !m.pending && (v.mineCreator || admin)) {
				tools.appendChild(el('button', { type: 'button', class: 'cv-link', text: t('chat.poll.close'), on: { click: async (e) => { e.stopPropagation(); if (await confirmDialog(t('chat.poll.closeQ'), t('chat.poll.close'))) call(api.poll(m.id, 'close')); } } }));
			}
			if (tools.childNodes.length) box.appendChild(tools);
			return box;
		}

		function addOptionDialog(m) {
			const input = el('input', { class: 'inp', maxlength: '80', 'aria-label': t('chat.poll.option') });
			dialog(t('chat.poll.addOption'), el('label', { class: 'cv-field' }, [el('span', { text: t('chat.poll.option') }), input]), [
				{ label: t('chat.common.cancel'), value: null },
				{ label: t('chat.poll.add'), primary: true, onClick: async () => { const v = input.value.trim(); if (!v) return false; return !!(await call(api.poll(m.id, 'option', { text: v }))); } },
			]);
		}

		function votesDialog(m, c, cx) {
			const v = CS.pollView(m.poll, cx);
			const list = el('div', { class: 'cv-stack' });
			for (const o of v.options) {
				list.appendChild(el('div', { class: 'cv-sec', text: `${o.text} · ${o.count}` }));
				for (const uid of o.voters || []) list.appendChild(el('div', { class: 'cv-member' }, [kit.avatar(CS.member(c, uid) ? CS.personAvatar(CS.member(c, uid)) : { kind: 'icon', icon: 'gone' }, 28), el('span', { class: 'cv-member-tx', text: CS.nameOf(c, uid, cx) })]));
			}
			dialog(t('chat.poll.showVotes'), list, [{ label: t('chat.common.close'), value: null }]);
		}

		// ── Event ──
		function eventEl(m, c, cx) {
			const ev = m.event;
			const v = CS.eventView(ev, cx);
			const r = CS.rsvpCounts(ev.rsvp);
			const off = blocked(m, c) || ev.cancelled;
			const box = el('div', { class: `cv-event${ev.cancelled ? ' is-cancelled' : ''}${v.past ? ' is-past' : ''}` });
			const place = ev.place && ev.place.label ? ev.place.label : null;
			box.appendChild(el('div', { class: 'cv-event-top' }, [
				el('span', { class: 'cv-event-date', 'aria-hidden': 'true' }, [el('small', { text: v.month }), el('b', { text: v.day }), el('small', { text: v.weekday })]),
				el('span', { class: 'cv-event-tx' }, [
					el('b', { class: 'cv-event-title', text: ev.title || '' }),
					el('span', { class: 'cv-event-when', text: [v.date, v.time, v.rel].filter(Boolean).join(' · ') }),
					place ? el('span', { class: 'cv-event-place' }, [icon('pin', 12), el('span', { text: place })]) : null,
				]),
				ev.cancelled ? el('span', { class: 'cv-chip is-err', text: t('chat.event.cancelled') }) : null,
			]));
			if (ev.description) box.appendChild(el('div', { class: 'cv-text cv-event-desc', text: ev.description }));
			const items = Array.isArray(ev.checklist) ? ev.checklist : [];
			if (items.length) {
				const cl = el('div', { class: 'cv-event-list' }, [el('div', { class: 'cv-rich-head', text: t('chat.event.checklist') })]);
				for (const it of items) {
					const cb = el('input', { type: 'checkbox', checked: !!it.doneBy, disabled: off ? true : null, 'aria-label': it.text || '' });
					cb.addEventListener('change', (e) => { e.stopPropagation(); call(api.event(m.id, 'check', { itemId: it.id, done: cb.checked })); });
					cl.appendChild(el('label', { class: `cv-event-item${it.doneBy ? ' is-done' : ''}` }, [cb, el('span', { text: it.text || '' }), it.doneBy ? el('small', { text: `– ${CS.nameOf(c, it.doneBy, cx)}` }) : null]));
				}
				box.appendChild(cl);
			}
			if (ev.rsvpEnabled !== false && !ev.cancelled) {
				const row = el('div', { class: 'cv-rsvp', role: 'group', 'aria-label': t('chat.event.rsvp') });
				for (const k of ['yes', 'maybe', 'no']) {
					row.appendChild(el('button', {
						type: 'button', class: `cv-rsvp-btn is-${k}`, 'aria-pressed': r.mine === k ? 'true' : 'false', disabled: off ? true : null, 'data-answer': k,
						on: { click: (e) => { e.stopPropagation(); call(api.event(m.id, 'rsvp', { answer: r.mine === k ? null : k, guests: k === 'yes' ? r.myGuests : undefined })); } },
					}, [el('b', { text: t(`chat.event.${k}`) }), el('span', { text: String(r[k]) })]));
				}
				box.appendChild(row);
				if (ev.guests && r.mine === 'yes' && !off) {
					const set = (n) => call(api.event(m.id, 'rsvp', { answer: 'yes', guests: Math.max(0, Math.min(20, n)) }));
					box.appendChild(el('div', { class: 'cv-guests' }, [
						el('span', { text: t('chat.event.guests') }),
						kit.iconBtn('minus', t('chat.event.guestsLess'), (e) => { e.stopPropagation(); set(r.myGuests - 1); }, 'cv-ib-sm'),
						el('b', { class: 'cv-guests-n', text: String(r.myGuests) }),
						kit.iconBtn('plus', t('chat.event.guestsMore'), (e) => { e.stopPropagation(); set(r.myGuests + 1); }, 'cv-ib-sm'),
					]));
				}
			}
			const tools = el('div', { class: 'cv-rich-tools' });
			if (ev.rsvpEnabled !== false && (r.yes || r.maybe || r.no)) tools.appendChild(el('button', { type: 'button', class: 'cv-link', text: t('chat.event.who'), on: { click: (e) => { e.stopPropagation(); rsvpDialog(m, c, cx); } } }));
			if (!m.pending && CS.canEditEvent(ev, c, cx)) {
				tools.appendChild(el('button', { type: 'button', class: 'cv-link', text: t('chat.event.edit'), on: { click: (e) => { e.stopPropagation(); eventDialog(c, m); } } }));
				tools.appendChild(el('button', { type: 'button', class: 'cv-link is-danger', text: t('chat.event.cancel'), on: { click: async (e) => { e.stopPropagation(); if (await confirmDialog(t('chat.event.cancelQ'), t('chat.event.cancel'), true)) call(api.event(m.id, 'edit', { patch: { cancelled: true } })); } } }));
			}
			if (ev.familyCalendar) tools.appendChild(el('span', { class: 'cv-chip', text: t('chat.event.inCalendar') }));
			if (tools.childNodes.length) box.appendChild(tools);
			return box;
		}

		function rsvpDialog(m, c, cx) {
			const rs = m.event.rsvp || {};
			const list = el('div', { class: 'cv-stack' });
			for (const k of ['yes', 'maybe', 'no']) {
				const people = Array.isArray(rs[k]) ? rs[k] : [];
				if (!people.length) continue;
				list.appendChild(el('div', { class: 'cv-sec', text: `${t(`chat.event.${k}`)} · ${people.length}` }));
				for (const p of people) {
					const mb = CS.member(c, p.userId);
					list.appendChild(el('div', { class: 'cv-member' }, [
						kit.avatar(mb ? CS.personAvatar(mb) : { kind: 'icon', icon: 'gone' }, 28),
						el('span', { class: 'cv-member-tx', text: CS.nameOf(c, p.userId, cx) + (p.guests ? ` (+${p.guests})` : '') }),
					]));
				}
			}
			dialog(t('chat.event.who'), list, [{ label: t('chat.common.close'), value: null }]);
		}

		// ── Live arrival ──
		function arrivalEl(m, c, cx) {
			const v = CS.arrivalView(m.arrival, cx);
			const box = el('div', { class: `cv-arrival is-${v.state}` });
			const where = v.position || v.dest;
			if (where && typeof api.mapTile === 'function') {
				const mv = kit.mapView({ lat: where.lat, lon: where.lon, zoom: 13, width: 280, height: 120 });
				mv.marker(where.lat, where.lon, v.position && v.position.accuracy);
				box.appendChild(el('div', { class: 'cv-arrival-map' }, [mv.el]));
			}
			let title;
			if (v.state === 'arrived') title = t('chat.arrival.arrived', { place: v.label });
			else if (v.state === 'stopped') title = t('chat.arrival.stopped', { place: v.label });
			else title = v.eta ? t('chat.arrival.eta', { place: v.label, time: v.eta }) : t('chat.arrival.live', { place: v.label });
			box.appendChild(el('div', { class: 'cv-arrival-row' }, [
				icon('pin', 16),
				el('b', { class: 'cv-arrival-title', text: title }),
				el('span', { class: `cv-chip is-${v.state}`, text: t(`chat.arrival.state.${v.state}`) }),
			]));
			if (v.live) {
				const sub = [v.minutes !== null ? t('chat.arrival.minutes', { n: v.minutes }) : null, v.distance].filter(Boolean).join(' · ');
				if (sub) box.appendChild(el('div', { class: 'cv-arrival-sub', text: sub }));
			}
			box.appendChild(el('div', { class: 'cv-progress', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(Math.round(v.progress * 100)) }, [el('span', { style: `width:${Math.round(v.progress * 100)}%` })]));
			const tools = el('div', { class: 'cv-rich-tools' });
			if (where && typeof api.mapTile === 'function') tools.appendChild(el('button', { type: 'button', class: 'cv-link', text: t('chat.arrival.onMap'), on: { click: (e) => { e.stopPropagation(); mapOverlay(v); } } }));
			if (v.live && m.mine && !m.pending) {
				tools.appendChild(el('button', { type: 'button', class: 'cv-link is-danger', text: t('chat.arrival.stop'), on: { click: async (e) => { e.stopPropagation(); if (await confirmDialog(t('chat.arrival.stopQ'), t('chat.arrival.stop'))) call(api.stopArrival(m.id)); } } }));
			}
			if (tools.childNodes.length) box.appendChild(tools);
			return box;
		}

		function mapOverlay(v) {
			const where = v.position || v.dest;
			const mv = kit.mapView({ lat: where.lat, lon: where.lon, zoom: 14, height: 420, interactive: true, label: v.label });
			mv.marker(where.lat, where.lon, v.position && v.position.accuracy);
			const tx = [v.label, v.live && v.eta ? t('chat.arrival.etaShort', { time: v.eta }) : null, v.live ? v.distance : null].filter(Boolean).join(' · ');
			dialog(t('chat.arrival.onMap'), el('div', { class: 'cv-loc-dlg' }, [mv.el, el('p', { class: 'cv-loc-src', text: tx })]), [{ label: t('chat.common.close'), value: null }], { wide: true });
		}

		// ── Home action ──
		function actionEl(m, c, cx) {
			const v = CS.actionView(m, c, cx);
			const box = el('div', { class: `cv-action is-${v.state}` });
			box.append(
				head(`${v.head} · ${CS.hm(m.createdAt, cx.locale)}`),
				el('div', { class: 'cv-action-row' }, [
					el('span', { class: 'cv-action-ic' }, [serverIcon(v.icon, 20)]),
					el('span', { class: 'cv-action-tx' }, [el('b', { text: v.label }), v.sub ? el('span', { text: v.sub }) : null]),
				]),
			);
			if (v.stateText) box.appendChild(el('div', { class: `cv-action-state is-${v.state}`, text: v.stateText }));
			if (v.result && v.result.message) box.appendChild(el('div', { class: `cv-action-result${v.result.ok === false ? ' is-err' : ''}`, text: v.result.message }));
			const btns = el('div', { class: 'cv-rich-btns' });
			const run = async (op) => {
				if (v.needsConfirm && op !== 'deny' && !(await confirmDialog(t('chat.action.confirm', { label: v.label }), op === 'approve' ? t('chat.action.approve') : t('chat.action.run')))) return;
				const r = await call(api.action(m.id, op));
				if (r) resultToast(r.result);
			};
			if (!m.pending) {
				if (v.run) btns.appendChild(el('button', { type: 'button', class: 'btn btn-pri btn-sm', 'data-op': 'run', text: t('chat.action.run'), on: { click: (e) => { e.stopPropagation(); run('run'); } } }));
				if (v.approve) btns.appendChild(el('button', { type: 'button', class: 'btn btn-pri btn-sm', 'data-op': 'approve', text: t('chat.action.approve'), on: { click: (e) => { e.stopPropagation(); run('approve'); } } }));
				if (v.deny) btns.appendChild(el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-op': 'deny', text: t('chat.action.deny'), on: { click: (e) => { e.stopPropagation(); run('deny'); } } }));
			}
			if (btns.childNodes.length) box.appendChild(btns);
			return box;
		}

		function resultToast(res) {
			if (!res) return;
			if (res.ok) toast(res.message || t('chat.action.doneToast'), 'success');
			else toast(res.message || t('chat.action.failedToast'), 'error');
		}

		// ── Plugin card (doorbell, notice) ──
		function cardEl(m, c, cx) {
			const card = m.card;
			const box = el('div', { class: `cv-card is-${card.kind === 'doorbell' ? 'doorbell' : 'notice'}` });
			box.appendChild(head(CS.cardHead(m, cx)));
			if (card.image) {
				const img = el('button', { type: 'button', class: 'cv-card-img is-loading', 'aria-label': t('chat.card.picture') });
				box.appendChild(img);
				kit.cardImageUrl(m.id).then((u) => {
					img.classList.remove('is-loading');
					if (!u) { img.classList.add('is-missing'); img.appendChild(icon('image', 26, '1.6')); return; }
					img.appendChild(el('img', { src: u, alt: '', draggable: 'false' }));
					img.addEventListener('click', (e) => { e.stopPropagation(); kit.lightboxUrl(u); });
				});
			}
			const text = card.text || m.text;
			if (text) box.appendChild(el('div', { class: 'cv-text', text }));
			const btns = el('div', { class: 'cv-rich-btns' });
			for (const a of Array.isArray(card.actions) ? card.actions : []) {
				if (!a || a.canRun === false) continue;
				btns.appendChild(el('button', { type: 'button', class: 'btn btn-pri btn-sm', 'data-action': a.actionId, on: { click: async (e) => {
					e.stopPropagation();
					if (a.needsConfirm && !(await confirmDialog(t('chat.action.confirm', { label: a.label || '' }), t('chat.action.run')))) return;
					const r = await call(api.action(m.id, 'run', { actionId: a.actionId, plugin: a.plugin }));
					if (r) resultToast(r.result);
				} } }, [serverIcon(a.icon, 15), el('span', { text: a.label || t('chat.action.run') })]));
			}
			const route = CS.cardRoute(card.link);
			if (route && typeof kit.openRoute === 'function') {
				btns.appendChild(el('button', { type: 'button', class: 'btn btn-sec btn-sm cv-card-link', 'data-route': route, on: { click: (e) => { e.stopPropagation(); kit.openRoute(route); } } }, [icon(card.link.kind === 'live_view' ? 'video' : 'external', 15), el('span', { text: card.link.label || t('chat.card.open') })]));
			}
			if (btns.childNodes.length) box.appendChild(btns);
			if (card.lastRun && card.lastRun.at) {
				const who = card.lastRun.by != null ? CS.nameOf(c, card.lastRun.by, cx, { you: false }) : 'GateControl';
				box.appendChild(el('div', { class: `cv-card-last${card.lastRun.ok === false ? ' is-err' : ''}`, text: t(card.lastRun.ok === false ? 'chat.card.lastFailed' : 'chat.card.last', { name: who, time: CS.hm(card.lastRun.at, cx.locale) }) }));
			}
			return box;
		}

		// ── Dialogs: create ─────────────────────────────────

		function sw(label, on, hint) {
			const b = el('button', { type: 'button', class: `sw${on ? ' on' : ''}`, role: 'switch', 'aria-checked': on ? 'true' : 'false', 'aria-label': label }, [el('span')]);
			b.addEventListener('click', () => { const v = b.getAttribute('aria-checked') !== 'true'; b.setAttribute('aria-checked', v ? 'true' : 'false'); b.classList.toggle('on', v); });
			const row = el('div', { class: 'cv-pref' }, [el('span', { class: 'cv-pref-tx' }, [el('b', { text: label }), hint ? el('small', { text: hint }) : null]), b]);
			return { row, get: () => b.getAttribute('aria-checked') === 'true', btn: b };
		}

		async function send(c, req) {
			const r = await api.send({ conversationId: c.id, ...req }).catch((e) => ({ ok: false, error: e && e.message }));
			if (!r || r.ok === false) return CS.errorText(r, t);
			kit.afterSend();
			return null;
		}

		/** "Abstimmung erstellen" (Messenger 1.4.0, feature polls). */
		function pollDialog(c) {
			const lim = kit.limits();
			const max = lim.pollOptionsMax || 12;
			const q = el('input', { class: 'inp', maxlength: String(lim.pollQuestionMax || 200), placeholder: t('chat.poll.questionPh'), 'aria-label': t('chat.poll.question') });
			const opts = el('div', { class: 'cv-stack cv-poll-opts' });
			const addBtn = el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => addOpt('') } }, [icon('plus', 13), t('chat.poll.addAnswer', { max })]);
			const addOpt = (v) => {
				if (opts.children.length >= max) return;
				const input = el('input', { class: 'inp', maxlength: String(lim.pollOptionMax || 80), value: v, placeholder: t('chat.poll.answerPh', { n: opts.children.length + 1 }), 'aria-label': t('chat.poll.option') });
				const row = el('div', { class: 'cv-poll-optrow' }, [input, kit.iconBtn('close', t('chat.common.remove'), () => { if (opts.children.length > 2) { row.remove(); addBtn.disabled = false; } }, 'cv-ib-flat cv-ib-sm')]);
				opts.appendChild(row);
				addBtn.disabled = opts.children.length >= max;
				return input;
			};
			addOpt('');
			addOpt('');
			const multi = sw(t('chat.poll.optMulti'), false);
			const anon = sw(t('chat.poll.optAnon'), false, t('chat.poll.optAnonHint'));
			const allowAdd = sw(t('chat.poll.optAdd'), true);
			const ends = el('select', { class: 'inp cv-select', 'aria-label': t('chat.poll.ends') }, [
				el('option', { value: '', text: t('chat.poll.endsNever') }),
				...CS.remindOptions().map((o) => el('option', { value: o.at, text: t(`chat.remind.${o.key}`) })),
				el('option', { value: 'custom', text: t('chat.common.custom') }),
			]);
			const custom = el('input', { class: 'inp', type: 'datetime-local', hidden: true, 'aria-label': t('chat.poll.ends') });
			ends.addEventListener('change', () => { custom.hidden = ends.value !== 'custom'; });
			const msg = el('p', { class: 'cv-dlg-err', role: 'status' });
			const bodyEl = el('div', { class: 'cv-stack cv-create' }, [
				el('label', { class: 'cv-field' }, [el('span', { text: t('chat.poll.question') }), q]),
				el('div', { class: 'cv-field' }, [el('span', { text: t('chat.poll.answers') }), opts, addBtn]),
				el('div', { class: 'cv-prefs' }, [multi.row, anon.row, allowAdd.row]),
				el('div', { class: 'cv-field' }, [el('span', { text: t('chat.poll.ends') }), el('div', { class: 'cv-row-inline' }, [ends, custom])]),
				msg,
			]);
			return dialog(t('chat.poll.create'), bodyEl, [
				{ label: t('chat.common.cancel'), value: null },
				{ label: t('chat.poll.send'), primary: true, onClick: async () => {
					const options = Array.from(opts.querySelectorAll('input')).map((i) => i.value.trim()).filter(Boolean);
					if (!q.value.trim()) { msg.textContent = t('chat.poll.needQuestion'); return false; }
					if (new Set(options.map((o) => o.toLowerCase())).size < 2) { msg.textContent = t('chat.poll.needOptions'); return false; }
					const poll = { question: q.value.trim(), options, multi: multi.get(), anonymous: anon.get(), allowAdd: allowAdd.get() };
					const at = ends.value === 'custom' ? CS.fromLocalInput(custom.value) : ends.value;
					if (ends.value === 'custom' && (!at || new Date(at).getTime() <= Date.now())) { msg.textContent = t('chat.poll.needEnd'); return false; }
					if (at) poll.closesAt = at;
					const err = await send(c, { kind: 'poll', poll });
					if (err) { msg.textContent = err; return false; }
					return true;
				} },
			]);
		}

		/** "Ereignis erstellen" / edit an own event (PATCH, only the changed fields). */
		async function eventDialog(c, m = null) {
			const me = kit.me();
			const fam = CS.familie(me);
			const f14 = CS.features14(me);
			const ev = m ? m.event : null;
			const lim = kit.limits();
			const startDefault = new Date(Date.now() + 86400000);
			startDefault.setMinutes(0, 0, 0);
			const title = el('input', { class: 'inp', maxlength: String(lim.eventTitleMax || 120), value: ev ? ev.title : '', placeholder: t('chat.event.titlePh'), 'aria-label': t('chat.event.title') });
			const starts = el('input', { class: 'inp', type: 'datetime-local', value: CS.localInput(ev ? ev.startsAt : startDefault.toISOString()), 'aria-label': t('chat.event.starts') });
			const ends = el('input', { class: 'inp', type: 'datetime-local', value: ev && ev.endsAt ? CS.localInput(ev.endsAt) : '', 'aria-label': t('chat.event.ends') });
			const allDay = sw(t('chat.event.allDay'), !!(ev && ev.allDay));
			const place = el('input', { class: 'inp', maxlength: '120', value: ev && ev.place ? ev.place.label : '', placeholder: t('chat.event.placePh'), 'aria-label': t('chat.event.place') });
			let familiePlace = ev && ev.place && ev.place.familiePlaceId != null ? ev.place : null;
			const placeSel = el('select', { class: 'inp cv-select', hidden: true, 'aria-label': t('chat.event.familiePlace') }, [el('option', { value: '', text: t('chat.event.familiePlace') })]);
			let places = [];
			if (fam.places) {
				const r = await api.places().catch(() => null);
				places = r && r.ok !== false && Array.isArray(r.places) ? r.places : [];
				for (const p of places) placeSel.appendChild(el('option', { value: String(p.id), text: p.name || '' }));
				placeSel.hidden = !places.length;
				if (familiePlace) placeSel.value = String(familiePlace.familiePlaceId);
			}
			placeSel.addEventListener('change', () => {
				const p = places.find((x) => String(x.id) === placeSel.value);
				familiePlace = p ? { label: p.name, familiePlaceId: p.id, lat: p.lat, lon: p.lon } : null;
				if (p) place.value = p.name || '';
			});
			place.addEventListener('input', () => { if (familiePlace && place.value !== familiePlace.label) { familiePlace = null; placeSel.value = ''; } });
			const desc = el('textarea', { class: 'inp cv-textarea', rows: '2', maxlength: '1000', placeholder: t('chat.event.descPh'), 'aria-label': t('chat.event.desc') });
			desc.value = ev && ev.description ? ev.description : '';
			const list = el('textarea', { class: 'inp cv-textarea', rows: '3', placeholder: t('chat.event.checklistPh'), 'aria-label': t('chat.event.checklist') });
			list.value = ev && Array.isArray(ev.checklist) ? ev.checklist.map((x) => x.text).join('\n') : '';
			const rsvp = sw(t('chat.event.optRsvp'), ev ? ev.rsvpEnabled !== false : true, t('chat.event.optRsvpHint'));
			const guests = sw(t('chat.event.optGuests'), ev ? !!ev.guests : false);
			const cal = fam.calendar ? sw(t('chat.event.optCalendar'), ev ? !!ev.familyCalendar : false, t('chat.event.optCalendarHint')) : null;
			const dep = f14.arrival ? sw(t('chat.event.optDeparture'), ev ? !!ev.departureHint : false, t('chat.event.optDepartureHint')) : null;
			const prefMin = me && me.prefs && me.prefs.notify && Number.isFinite(me.prefs.notify.eventReminderMin) ? me.prefs.notify.eventReminderMin : 60;
			const rem = el('select', { class: 'inp cv-select', 'aria-label': t('chat.event.reminder') }, [0, 15, 60, 120, 1440].map((n) => el('option', { value: String(n), text: t(`chat.reminderMin.${n}`) })));
			rem.value = String(ev && Number.isFinite(ev.reminderMin) ? ev.reminderMin : prefMin);
			const msg = el('p', { class: 'cv-dlg-err', role: 'status' });
			const bodyEl = el('div', { class: 'cv-stack cv-create' }, [
				el('label', { class: 'cv-field' }, [el('span', { text: t('chat.event.title') }), title]),
				el('div', { class: 'cv-row-inline' }, [
					el('label', { class: 'cv-field' }, [el('span', { text: t('chat.event.starts') }), starts]),
					el('label', { class: 'cv-field' }, [el('span', { text: t('chat.event.ends') }), ends]),
				]),
				el('div', { class: 'cv-prefs' }, [allDay.row]),
				el('div', { class: 'cv-field' }, [el('span', { text: t('chat.event.place') }), el('div', { class: 'cv-row-inline' }, [place, placeSel])]),
				el('label', { class: 'cv-field' }, [el('span', { text: t('chat.event.desc') }), desc]),
				el('label', { class: 'cv-field' }, [el('span', { text: t('chat.event.checklist') }), list]),
				el('div', { class: 'cv-prefs' }, [rsvp.row, guests.row, cal && cal.row, dep && dep.row].filter(Boolean)),
				el('div', { class: 'cv-kv' }, [el('span', { class: 'cv-kv-l', text: t('chat.event.reminder') }), rem]),
				msg,
			]);
			const build = () => {
				const s = CS.fromLocalInput(starts.value);
				if (!title.value.trim()) { msg.textContent = t('chat.event.needTitle'); return null; }
				if (!s) { msg.textContent = t('chat.event.needStart'); return null; }
				const e = CS.fromLocalInput(ends.value);
				if (e && new Date(e) < new Date(s)) { msg.textContent = t('chat.event.endBeforeStart'); return null; }
				const out = {
					title: title.value.trim(), startsAt: s, endsAt: e || null, allDay: allDay.get(),
					place: place.value.trim() ? (familiePlace && familiePlace.label === place.value.trim() ? familiePlace : { label: place.value.trim() }) : null,
					description: desc.value.trim() || null,
					checklist: list.value.split('\n').map((x) => x.trim()).filter(Boolean).slice(0, lim.eventChecklistMax || 20),
					rsvp: rsvp.get(), guests: guests.get(), reminderMin: Number(rem.value),
				};
				if (cal) out.familyCalendar = cal.get();
				if (dep) out.departureHint = dep.get();
				return out;
			};
			return dialog(m ? t('chat.event.editTitle') : t('chat.event.create'), bodyEl, [
				{ label: t('chat.common.cancel'), value: null },
				{ label: m ? t('chat.common.save') : t('chat.event.send'), primary: true, onClick: async () => {
					const e = build();
					if (!e) return false;
					if (!m) {
						if (!e.endsAt) delete e.endsAt;
						if (!e.place) delete e.place;
						if (!e.description) delete e.description;
						const err = await send(c, { kind: 'event', event: e });
						if (err) { msg.textContent = err; return false; }
						return true;
					}
					const r = await api.event(m.id, 'edit', { patch: e }).catch((x) => ({ ok: false, error: x && x.message }));
					if (!r || r.ok === false) { msg.textContent = CS.errorText(r, t); return false; }
					return true;
				} },
			], { wide: true });
		}

		/** "Haus-Aktion senden": a button to run, a request for approval, or a grant for a time. */
		async function actionDialog(c, action) {
			const cx = kit.ctx();
			const meId = cx.me && cx.me.user ? cx.me.user.id : null;
			const others = (c.members || []).filter((mb) => mb.userId !== meId && !mb.gone);
			let mode = 'run';
			const tabs = el('div', { class: 'cv-tabs', role: 'group' });
			const label = el('input', { class: 'inp', maxlength: '80', value: action.label || '', 'aria-label': t('chat.action.label') });
			const approvers = el('div', { class: 'cv-people scroll' }, others.map((mb) => el('label', { class: 'cv-person' }, [kit.avatar(CS.personAvatar(mb), 30), el('span', { class: 'cv-person-name', text: mb.name || '' }), el('input', { type: 'checkbox', value: String(mb.userId), 'aria-label': mb.name || '' })])));
			const grantTo = el('select', { class: 'inp cv-select', 'aria-label': t('chat.action.grantWho') }, others.map((mb) => el('option', { value: String(mb.userId), text: mb.name || '' })));
			const until = el('input', { class: 'inp', type: 'datetime-local', value: CS.localInput(new Date(Date.now() + 2 * 3600000).toISOString()), 'aria-label': t('chat.action.grantUntil') });
			const reqBox = el('div', { class: 'cv-field', hidden: true }, [el('span', { text: t('chat.action.approvers') }), el('small', { class: 'cv-dim', text: t('chat.action.approversHint') }), approvers]);
			const grantBox = el('div', { class: 'cv-stack', hidden: true }, [
				action.needsConfirm ? el('p', { class: 'cv-note', text: t('chat.action.noGrant') }) : null,
				el('label', { class: 'cv-field' }, [el('span', { text: t('chat.action.grantWho') }), grantTo]),
				el('label', { class: 'cv-field' }, [el('span', { text: t('chat.action.grantUntil') }), until]),
			].filter(Boolean));
			const hint = el('p', { class: 'cv-note' });
			const draw = () => {
				for (const b of tabs.querySelectorAll('button')) b.setAttribute('aria-pressed', b.dataset.mode === mode ? 'true' : 'false');
				reqBox.hidden = mode !== 'request';
				grantBox.hidden = mode !== 'grant';
				hint.textContent = t(`chat.action.hint.${mode}`);
			};
			for (const k of ['run', 'request', 'grant']) {
				if (k !== 'run' && c.kind === 'direct' && !others.length) continue;
				tabs.appendChild(el('button', { type: 'button', 'data-mode': k, text: t(`chat.action.mode.${k}`), on: { click: () => { mode = k; draw(); } } }));
			}
			const msg = el('p', { class: 'cv-dlg-err', role: 'status' });
			draw();
			const top = el('div', { class: 'cv-action-row' }, [el('span', { class: 'cv-action-ic' }, [serverIcon(action.icon, 22)]), el('span', { class: 'cv-action-tx' }, [el('b', { text: action.label || '' }), el('span', { text: action.pluginName || action.plugin || '' })])]);
			return dialog(t('chat.action.sendTitle'), el('div', { class: 'cv-stack cv-create' }, [top, tabs, hint, el('label', { class: 'cv-field' }, [el('span', { text: t('chat.action.label') }), label]), reqBox, grantBox, msg]), [
				{ label: t('chat.common.cancel'), value: null },
				{ label: t('chat.action.send'), primary: true, onClick: async () => {
					const a = { mode, actionId: action.id, plugin: action.plugin, label: label.value.trim() || action.label };
					if (mode === 'request') {
						const ids = Array.from(approvers.querySelectorAll('input:checked')).map((x) => Number(x.value));
						if (ids.length) a.approverIds = ids;
					}
					if (mode === 'grant') {
						if (action.needsConfirm) { msg.textContent = t('chat.action.noGrant'); return false; }
						const at = CS.fromLocalInput(until.value);
						if (!grantTo.value || !at || new Date(at).getTime() <= Date.now() || new Date(at).getTime() > Date.now() + 7 * 86400000) { msg.textContent = t('chat.action.needUntil'); return false; }
						a.grant = { toUserId: Number(grantTo.value), until: at };
					}
					const err = await send(c, { kind: 'action', action: a });
					if (err) { msg.textContent = err; return false; }
					return true;
				} },
			]);
		}

		// ── Dialogs: message menu tools ─────────────────────

		/** "Erinnere mich": presets or a time of one's own. */
		function remindDialog(m) {
			const custom = el('input', { class: 'inp', type: 'datetime-local', 'aria-label': t('chat.remind.custom') });
			let closeFn = null;
			const go = async (at) => {
				const r = await call(api.remind(m.id, at));
				if (r) { toast(t('chat.remind.set', { time: CS.when(at, kit.ctx().locale) }), 'success'); if (closeFn) closeFn(null); }
			};
			const bodyEl = el('div', { class: 'cv-stack' }, [
				...CS.remindOptions().map((o) => el('button', { type: 'button', class: 'btn btn-sec cv-remind-opt', on: { click: () => go(o.at) } }, [el('span', { text: t(`chat.remind.${o.key}`) }), el('small', { class: 'cv-dim', text: CS.when(o.at, kit.ctx().locale) })])),
				el('div', { class: 'cv-row-inline' }, [custom, el('button', { type: 'button', class: 'btn btn-pri', text: t('chat.remind.setBtn'), on: { click: () => { const at = CS.fromLocalInput(custom.value); if (at && new Date(at).getTime() > Date.now()) go(at); else toast(t('chat.remind.needFuture'), 'warning'); } } })]),
			]);
			dialog(t('chat.remind.title'), bodyEl, [], { onOpen: (done) => { closeFn = done; } });
		}

		/** "Auf Einkaufsliste": the suggested items, editable, to Familie's list. */
		function toListDialog(m, items) {
			const list = el('div', { class: 'cv-stack' });
			const addRow = (text, on = true) => list.appendChild(el('label', { class: 'cv-check' }, [el('input', { type: 'checkbox', checked: on, value: text }), el('span', { text })]));
			for (const it of items) addRow(it);
			const more = el('input', { class: 'inp', maxlength: '120', placeholder: t('chat.suggest.addItem'), 'aria-label': t('chat.suggest.addItem') });
			more.addEventListener('keydown', (e) => { if (e.key === 'Enter' && more.value.trim()) { e.preventDefault(); addRow(more.value.trim()); more.value = ''; } });
			return dialog(t('chat.suggest.toList'), el('div', { class: 'cv-stack' }, [list, more, el('p', { class: 'cv-note', text: t('chat.suggest.hint') })]), [
				{ label: t('chat.common.cancel'), value: null },
				{ label: t('chat.suggest.add'), primary: true, onClick: async () => {
					const chosen = Array.from(list.querySelectorAll('input:checked')).map((x) => x.value).concat(more.value.trim() ? [more.value.trim()] : []);
					if (!chosen.length) return false;
					const r = await call(api.toList(m.id, chosen));
					if (!r) return false;
					toast(t('chat.suggest.added', { n: r.added, list: r.listName || t('chat.suggest.shopping') }), 'success');
					return true;
				} },
			]);
		}

		/** "Termin anlegen": a found date (title, time) to Familie's calendar. */
		function toCalendarDialog(m, dates) {
			const d = dates[0] || {};
			const title = el('input', { class: 'inp', maxlength: '80', value: d.title || '', 'aria-label': t('chat.event.title') });
			const starts = el('input', { class: 'inp', type: 'datetime-local', value: CS.localInput(d.startsAt), 'aria-label': t('chat.event.starts') });
			const allDay = sw(t('chat.event.allDay'), !!d.allDay);
			const pick = dates.length > 1 ? el('select', { class: 'inp cv-select', 'aria-label': t('chat.suggest.date') }, dates.map((x, i) => el('option', { value: String(i), text: x.label || CS.when(x.startsAt, kit.ctx().locale) }))) : null;
			if (pick) pick.addEventListener('change', () => { const x = dates[Number(pick.value)]; title.value = x.title || title.value; starts.value = CS.localInput(x.startsAt); });
			return dialog(t('chat.suggest.toCalendar'), el('div', { class: 'cv-stack' }, [pick, el('label', { class: 'cv-field' }, [el('span', { text: t('chat.event.title') }), title]), el('label', { class: 'cv-field' }, [el('span', { text: t('chat.event.starts') }), starts]), el('div', { class: 'cv-prefs' }, [allDay.row]), el('p', { class: 'cv-note', text: t('chat.suggest.hint') })].filter(Boolean)), [
				{ label: t('chat.common.cancel'), value: null },
				{ label: t('chat.suggest.create'), primary: true, onClick: async () => {
					const s = CS.fromLocalInput(starts.value);
					if (!title.value.trim() || !s) return false;
					const r = await call(api.toCalendar(m.id, { title: title.value.trim(), startsAt: s, allDay: allDay.get() }));
					if (!r) return false;
					toast(t('chat.suggest.created'), 'success');
					return true;
				} },
			]);
		}

		return { body, pollDialog, eventDialog, actionDialog, remindDialog, toListDialog, toCalendarDialog, serverIcon };
	}

	root.GCChatRich = { create };
})(typeof self !== 'undefined' ? self : this);
