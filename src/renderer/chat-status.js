/**
 * GateControl -- Chats: status and stories of Messenger 1.4.0 (renderer)
 *
 * The status strip under "Angeheftet" (own avatar "Mein Status" first, then
 * the people of `GET status/feed`; a glowing ring while they have stories
 * not seen yet), the dialog "Dein Status" (text, presets, "Löschen nach",
 * "Sichtbar für"), the story viewer (text, picture and video stories with
 * progress, previous / next, reply and reaction, viewers of one's own) and
 * "Status erstellen" (text and picture stories).
 *
 * Own active stories: the glowing ring around "Mein Status" (and the own
 * avatar in the list head), a click on the avatar shows them with their
 * viewers, "+" adds a new one, the card "Meine Storys" in "Dein Status". A
 * posted story is added to the feed at once (before it is fetched again).
 * Messenger 1.4.1 (`story_duration`): the duration 1 / 3 / 6 / 12 / 24 Std.;
 * without it "24 Std." is plain text. A failed post stays as an error in
 * the composer.
 *
 * Mounted by chat-view.js with its kit: window.GCChatStatus.create(kit).
 * Shown only when `GET me` features has `status` (stories: `stories`).
 *
 * Note: user data only ever goes into textContent / attributes; story
 * pictures and videos come as bytes (chat.media) and are shown as blob: URLs.
 */
(function (root) {
	'use strict';

	const CS = root.GCChatState;

	function create(kit) {
		const { api, t, el, icon, iconBtn, clear, dialog, confirmDialog, toast } = kit;
		const S = { feed: null, loading: null };
		const listeners = new Set();
		const meId = () => { const me = kit.me(); return me && me.user ? me.user.id : null; };
		const f14 = () => CS.features14(kit.me());

		// ── Feed ────────────────────────────────────────────

		async function load(refresh = false) {
			if (!f14().status) { S.feed = null; return null; }
			const r = await api.statusFeed(refresh ? { refresh: true } : undefined).catch(() => null);
			if (r && r.ok !== false) set(r);
			return S.feed;
		}
		function set(feed) {
			S.feed = { items: Array.isArray(feed.items) ? feed.items : [], me: feed.me || null };
			for (const fn of listeners) { try { fn(S.feed); } catch (_) { /* view */ } }
		}
		/** The own feed item (status, stories) or a stub. */
		function mine() {
			const me = kit.me();
			const u = me && me.user ? me.user : { id: null, name: null };
			return (S.feed && S.feed.me) || { user: { id: u.id, name: u.name, avatarUrl: u.avatarUrl, initials: u.initials, colorHex: u.colorHex }, status: null, stories: [] };
		}
		/** Has the own user active stories? (ring around "Mein Status" and the own avatar) */
		const hasOwnStories = () => CS.ownStoryStats(mine()).count > 0;
		/** The own stories in the viewer (with "Gesehen von" and the viewers list). */
		function viewOwn() {
			const own = mine();
			if (!own.stories || !own.stories.length) return;
			viewer([own], 0, 0);
		}
		/** A story just posted: shown at once in "Mein Status", before the feed is fetched again. */
		function addOwn(story) {
			const me = kit.me();
			set(CS.addOwnStory(S.feed || { items: [] }, story, me && me.user));
		}

		// ── Strip ───────────────────────────────────────────

		function ringAvatar(item, size, ring) {
			const wrap = el('span', { class: `cv-ring is-${ring}` });
			wrap.appendChild(kit.avatar(CS.personAvatar({ ...item.user, initials: item.user.initials }), size));
			return wrap;
		}

		/** The strip element (null when the server has no status). */
		function strip() {
			if (!f14().status) return null;
			const box = el('div', { class: 'cv-strip', role: 'list', 'aria-label': t('chat.st.strip') });
			const own = mine();
			const active = hasOwnStories();
			const ownLine = CS.statusLine(own.status, kit.ctx());
			const avLabel = active ? t('chat.st.viewMine') : t('chat.st.yours');
			// avatar: the own stories (or "Dein Status" without any); "+": a new status / story
			const ownEl = el('div', { class: `cv-st is-me${active ? ' has-stories' : ''}`, role: 'listitem' }, [
				el('button', {
					type: 'button', class: 'cv-st-av', title: ownLine ? `${avLabel} · ${ownLine}` : avLabel, 'aria-label': ownLine ? `${avLabel}: ${ownLine}` : avLabel,
					on: { click: () => (active ? viewOwn() : statusDialog()) },
				}, [ringAvatar(own, 50, active ? 'own' : 'none')]),
				el('button', {
					type: 'button', class: 'cv-st-plus', title: t('chat.st.addStory'), 'aria-label': t('chat.st.addStory'),
					on: { click: () => (f14().stories ? composeStory() : statusDialog()) },
				}, [icon('plus', 12, '3')]),
				el('span', { class: 'cv-st-cap', text: t('chat.st.mine') }),
			]);
			box.appendChild(ownEl);
			const items = S.feed ? S.feed.items : [];
			items.forEach((it, i) => {
				const ring = CS.statusRing(it);
				const line = CS.statusLine(it.status, kit.ctx());
				const name = it.user && it.user.name ? it.user.name : t('chat.gone');
				box.appendChild(el('button', {
					type: 'button', class: `cv-st${ring === 'unseen' ? ' is-unseen' : ''}`, role: 'listitem', 'data-user': String(it.user && it.user.id),
					title: line ? `${name}: ${line}` : name, 'aria-label': `${name}${ring === 'unseen' ? `, ${t('chat.st.new')}` : ''}${line ? `: ${line}` : ''}`,
					on: { click: () => (it.stories && it.stories.length ? viewer(items, i, CS.firstUnseen(it.stories)) : statusCard(it)) },
				}, [ringAvatar(it, 50, ring), el('span', { class: 'cv-st-cap', text: name.split(' ')[0] })]));
			});
			return box;
		}

		/** A person with only a status: a small card with "Nachricht schreiben". */
		function statusCard(it) {
			const cx = kit.ctx();
			const st = it.status || {};
			let closeFn = null;
			const bodyEl = el('div', { class: 'cv-stcard' }, [
				kit.avatar(CS.personAvatar(it.user), 64),
				el('b', { text: it.user.name || t('chat.gone') }),
				el('span', { class: 'cv-stcard-line', text: CS.statusLine(st, cx) || t('chat.st.none') }),
				st.updatedAt ? el('small', { class: 'cv-dim', text: CS.relAge(st.updatedAt, cx) }) : null,
				el('button', { type: 'button', class: 'btn btn-pri btn-sm', text: t('chat.st.write'), on: { click: () => { if (closeFn) closeFn(null); kit.openDirect(it.user.id); } } }),
			]);
			dialog(t('chat.st.title'), bodyEl, [], { onOpen: (done) => { closeFn = done; } });
		}

		// ── "Dein Status" ───────────────────────────────────

		function statusDialog() {
			const cx = kit.ctx();
			const own = mine();
			const cur = own.status || null;
			const lim = kit.limits();
			const max = lim.statusTextMax || 60;
			const fam = CS.familie(kit.me());
			let preset = cur ? cur.preset : 'none';
			const text = el('input', { class: 'inp', maxlength: String(max), value: cur ? (cur.ownText || (cur.preset === 'none' ? cur.text : '') || '') : '', placeholder: t('chat.st.textPh'), 'aria-label': t('chat.st.text') });
			const count = el('span', { class: 'cv-count-tx' });
			const upd = () => { count.textContent = `${text.value.length}/${max}`; };
			text.addEventListener('input', upd);
			upd();
			const presets = el('div', { class: 'cv-presets', role: 'radiogroup', 'aria-label': t('chat.st.preset.label') });
			const away = el('div', { class: 'cv-row-inline', hidden: true });
			const eta = el('input', { class: 'inp', type: 'datetime-local', value: cur && cur.eta ? CS.localInput(cur.eta) : '', 'aria-label': t('chat.st.etaLabel') });
			const dest = el('input', { class: 'inp', maxlength: '80', value: cur && cur.destLabel ? cur.destLabel : '', placeholder: t('chat.st.destPh'), 'aria-label': t('chat.st.dest') });
			away.append(el('label', { class: 'cv-field' }, [el('span', { text: t('chat.st.dest') }), dest]), el('label', { class: 'cv-field' }, [el('span', { text: t('chat.st.etaLabel') }), eta]));
			const drawPresets = () => {
				for (const b of presets.querySelectorAll('button')) b.setAttribute('aria-checked', b.dataset.preset === preset ? 'true' : 'false');
				away.hidden = preset !== 'away';
			};
			for (const p of CS.PRESETS) {
				if (p === 'auto_place' && !fam.places) continue;
				presets.appendChild(el('button', { type: 'button', role: 'radio', class: 'cv-preset', 'data-preset': p, on: { click: () => { preset = preset === p ? 'none' : p; drawPresets(); } } }, [
					el('b', { text: CS.presetLabel(p, t) }), el('small', { text: t(`chat.st.presetHint.${p}`) }),
				]));
			}
			drawPresets();
			const untilSel = el('div', { class: 'cv-chips', role: 'radiogroup', 'aria-label': t('chat.st.untilLabel') });
			let untilKey = cur && cur.until ? 'keep' : 'never';
			const untilOpts = CS.untilOptions();
			const drawUntil = () => { for (const b of untilSel.querySelectorAll('button')) b.setAttribute('aria-checked', b.dataset.key === untilKey ? 'true' : 'false'); };
			if (cur && cur.until) untilSel.appendChild(el('button', { type: 'button', role: 'radio', class: 'cv-chip-btn', 'data-key': 'keep', text: t('chat.st.untilTime', { time: CS.shortWhen(cur.until, cx) }), on: { click: () => { untilKey = 'keep'; drawUntil(); } } }));
			for (const o of untilOpts) untilSel.appendChild(el('button', { type: 'button', role: 'radio', class: 'cv-chip-btn', 'data-key': o.key, text: t(`chat.st.untilOpt.${o.key}`), on: { click: () => { untilKey = o.key; drawUntil(); } } }));
			drawUntil();
			const vis = audiencePicker(cur ? cur.visibility : null, cur ? cur.userIds : null);
			const msg = el('p', { class: 'cv-dlg-err', role: 'status' });
			const bodyEl = el('div', { class: 'cv-stack cv-create' }, [
				el('label', { class: 'cv-field' }, [el('span', { class: 'cv-field-top' }, [el('span', { text: t('chat.st.text') }), count]), text]),
				el('div', { class: 'cv-field' }, [el('span', { text: t('chat.st.preset.label') }), presets, away]),
				el('div', { class: 'cv-field' }, [el('span', { text: t('chat.st.untilLabel') }), untilSel]),
				el('div', { class: 'cv-field' }, [el('span', { text: t('chat.st.visible') }), vis.el]),
				msg,
			]);
			const buttons = [];
			if (cur) buttons.push({ label: t('chat.st.clear'), danger: true, onClick: async () => { const r = await api.clearStatus().catch((e) => ({ ok: false, error: e && e.message })); if (!r || r.ok === false) { msg.textContent = CS.errorText(r, t); return false; } toast(t('chat.st.cleared'), 'success'); return true; } });
			buttons.push({ label: t('chat.common.cancel'), value: null });
			buttons.push({ label: t('chat.common.save'), primary: true, onClick: async () => {
				const body = { preset, text: text.value.trim() || undefined };
				if (preset === 'none' && !body.text) { msg.textContent = t('chat.st.needText'); return false; }
				if (untilKey === 'keep') body.until = cur.until;
				else { const o = untilOpts.find((x) => x.key === untilKey); if (o && o.at) body.until = o.at; }
				Object.assign(body, vis.value());
				if (body.visibility === 'custom' && !(body.userIds || []).length) { msg.textContent = t('chat.st.needPeople'); return false; }
				if (preset === 'away') {
					const at = CS.fromLocalInput(eta.value);
					if (at) body.eta = at;
					if (dest.value.trim()) body.destLabel = dest.value.trim();
				}
				const r = await api.setStatus(body).catch((e) => ({ ok: false, error: e && e.message }));
				if (!r || r.ok === false) { msg.textContent = CS.errorText(r, t); return false; }
				toast(t('chat.st.saved'), 'success');
				load(true);
				return true;
			} });
			let closeFn = null;
			if (f14().stories) bodyEl.insertBefore(el('button', { type: 'button', class: 'btn btn-sec btn-sm cv-st-story', on: { click: () => { composeStory(); } } }, [icon('image', 14), t('chat.st.newStory')]), bodyEl.firstChild);
			// "Meine Storys": the own active stories, prominent on top
			const stats = CS.ownStoryStats(own);
			if (stats.count) {
				bodyEl.insertBefore(el('div', { class: 'cv-mystories' }, [
					ringAvatar(own, 44, 'own'),
					el('span', { class: 'cv-mystories-tx' }, [el('b', { text: t('chat.st.myStoriesTitle') }), el('small', { text: CS.ownStoryLine(stats, t) })]),
					el('button', { type: 'button', class: 'btn btn-pri btn-sm', 'aria-label': t('chat.st.viewMine'), text: t('chat.st.open'), on: { click: () => { if (closeFn) closeFn(null); viewOwn(); } } }),
				]), bodyEl.firstChild);
			}
			return dialog(t('chat.st.yours'), bodyEl, buttons, { onOpen: (done) => { closeFn = done; } });
		}

		/** "Sichtbar für": Alle / Familie / Ausgewählte … (people) → { el, value() }. */
		function audiencePicker(current, userIds) {
			const me = kit.me();
			const def = me && me.prefs && me.prefs.privacy ? me.prefs.privacy.statusDefault : 'all';
			let v = current || def || 'all';
			const chosen = new Set(Array.isArray(userIds) ? userIds : []);
			const chips = el('div', { class: 'cv-chips', role: 'radiogroup', 'aria-label': t('chat.st.visible') });
			const people = el('div', { class: 'cv-people scroll', hidden: true });
			const draw = () => {
				for (const b of chips.querySelectorAll('button')) b.setAttribute('aria-checked', b.dataset.v === v ? 'true' : 'false');
				people.hidden = v !== 'custom';
			};
			for (const k of ['all', 'family', 'custom']) chips.appendChild(el('button', { type: 'button', role: 'radio', class: 'cv-chip-btn', 'data-v': k, text: t(`chat.audience.${k}`), on: { click: () => { v = k; draw(); if (k === 'custom') fill(); } } }));
			let filled = false;
			const fill = async () => {
				if (filled) return;
				filled = true;
				const list = await kit.loadPeople();
				for (const p of list) {
					const cb = el('input', { type: 'checkbox', value: String(p.id), checked: chosen.has(p.id), 'aria-label': p.name || '' });
					cb.addEventListener('change', () => { if (cb.checked) chosen.add(p.id); else chosen.delete(p.id); });
					people.appendChild(el('label', { class: 'cv-person' }, [kit.avatar(CS.personAvatar(p), 30), el('span', { class: 'cv-person-name', text: p.name || '' }), cb]));
				}
			};
			if (v === 'custom') fill();
			draw();
			return { el: el('div', { class: 'cv-stack' }, [chips, people]), value: () => (v === 'custom' ? { visibility: 'custom', userIds: [...chosen] } : { visibility: v }) };
		}

		// ── "Status erstellen" (stories) ─────────────────────

		function composeStory() {
			if (!f14().stories) return null;
			const lim = kit.limits();
			let kind = 'text';
			let bg = CS.STORY_COLORS[0];
			let font = 'sans';
			let file = null;
			let fileUrl = null;
			const text = el('textarea', { class: 'cv-story-input', maxlength: String(lim.storyTextMax || 700), placeholder: t('chat.story.textPh'), 'aria-label': t('chat.story.text') });
			const preview = el('div', { class: 'cv-story-prev' });
			const count = el('span', { class: 'cv-count-tx' });
			const fileIn = el('input', { type: 'file', accept: 'image/png,image/jpeg,image/webp,video/mp4,video/webm', hidden: true });
			const tabs = el('div', { class: 'cv-tabs', role: 'group' });
			const colors = el('div', { class: 'cv-story-colors', role: 'radiogroup', 'aria-label': t('chat.story.bg') }, CS.STORY_COLORS.map((c) => el('button', { type: 'button', role: 'radio', class: 'cv-story-color', style: `background:${c}`, 'data-c': c, 'aria-label': c, on: { click: () => { bg = c; draw(); } } })));
			const fontBtn = el('button', { type: 'button', class: 'btn btn-sec btn-sm', title: t('chat.story.font'), 'aria-label': t('chat.story.font'), text: 'Aa', on: { click: () => { font = font === 'sans' ? 'serif' : font === 'serif' ? 'mono' : 'sans'; draw(); } } });
			const pickBtn = el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => { fileIn.value = ''; fileIn.click(); } } }, [icon('image', 14), t('chat.story.pick')]);
			const vis = audiencePicker(null, null);
			// Messenger 1.4.1: the duration when the server takes one, else "24 Std." as plain text
			const durations = CS.storyDurations(kit.me());
			let durationH = CS.STORY_DURATION_DEFAULT_H;
			if (durations && !durations.includes(durationH)) durationH = durations[durations.length - 1];
			const hours = (h) => t('chat.story.hours', { n: h });
			const hint = el('p', { class: 'cv-note' });
			const durEl = durations
				? el('div', { class: 'cv-chips cv-story-dur', role: 'radiogroup', 'aria-label': t('chat.story.duration') }, durations.map((h) => el('button', {
					type: 'button', role: 'radio', class: 'cv-chip-btn', 'data-h': String(h), text: hours(h), on: { click: () => { durationH = h; drawDur(); } },
				})))
				: el('span', { class: 'cv-story-dur-fixed', 'data-h': String(CS.STORY_DURATION_DEFAULT_H), text: hours(CS.STORY_DURATION_DEFAULT_H) });
			const drawDur = () => {
				if (durations) for (const b of durEl.querySelectorAll('button')) b.setAttribute('aria-checked', b.dataset.h === String(durationH) ? 'true' : 'false');
				hint.textContent = t('chat.story.hintTime', { time: hours(durations ? durationH : CS.STORY_DURATION_DEFAULT_H) });
			};
			drawDur();
			// A failed post stays here as an error (not only a toast), until the next try.
			const msg = el('p', { class: 'cv-story-msg', role: 'alert', hidden: true });
			const showMsg = (text, type = 'error') => {
				msg.textContent = text;
				msg.dataset.type = type;
				msg.hidden = !text;
				if (text && typeof msg.scrollIntoView === 'function') msg.scrollIntoView({ block: 'nearest' });
			};
			const draw = () => {
				for (const b of tabs.querySelectorAll('button')) b.setAttribute('aria-pressed', b.dataset.kind === kind ? 'true' : 'false');
				for (const b of colors.querySelectorAll('button')) b.setAttribute('aria-checked', b.dataset.c === bg ? 'true' : 'false');
				colors.hidden = kind !== 'text';
				fontBtn.hidden = kind !== 'text';
				pickBtn.hidden = kind === 'text';
				count.textContent = `${text.value.length}/${lim.storyTextMax || 700}`;
				clear(preview);
				preview.className = `cv-story-prev is-${kind} font-${font}`;
				if (kind === 'text') {
					preview.style.background = bg;
					preview.appendChild(text);
				} else {
					preview.style.background = '#0b0f14';
					if (fileUrl && file && /^video\//.test(file.type)) preview.appendChild(el('video', { src: fileUrl, muted: true, autoplay: true, loop: true, playsinline: true }));
					else if (fileUrl) preview.appendChild(el('img', { src: fileUrl, alt: '' }));
					else preview.appendChild(el('span', { class: 'cv-story-empty', text: t('chat.story.noFile') }));
					text.setAttribute('placeholder', t('chat.story.captionPh'));
					preview.appendChild(el('div', { class: 'cv-story-cap' }, [text]));
				}
			};
			text.addEventListener('input', () => { count.textContent = `${text.value.length}/${lim.storyTextMax || 700}`; });
			for (const k of ['text', 'image']) tabs.appendChild(el('button', { type: 'button', 'data-kind': k, text: t(`chat.story.kind.${k}`), on: { click: () => { kind = k; if (k !== 'text' && !file) { fileIn.value = ''; fileIn.click(); } draw(); } } }));
			fileIn.addEventListener('change', () => {
				const f = fileIn.files && fileIn.files[0];
				if (!f) return;
				if (!/^image\//.test(f.type) && !/^video\//.test(f.type)) { toast(t('chat.error.unsupported_type'), 'error'); return; }
				file = f;
				if (fileUrl) URL.revokeObjectURL(fileUrl);
				fileUrl = URL.createObjectURL(f);
				kind = /^video\//.test(f.type) ? 'video' : 'image';
				draw();
			});
			draw();
			const bodyEl = el('div', { class: 'cv-stack cv-create' }, [
				el('div', { class: 'cv-row-inline' }, [tabs, el('span', { class: 'cv-grow' }), colors, fontBtn, pickBtn, count]),
				preview,
				fileIn,
				el('div', { class: 'cv-field' }, [el('span', { text: t('chat.st.visible') }), vis.el]),
				el('div', { class: 'cv-field' }, [el('span', { text: t('chat.story.duration') }), durEl]),
				hint,
				msg,
			]);
			const share = async () => {
				const req = { kind, ...vis.value() };
				if (text.value.trim()) req.text = text.value.trim();
				if (req.visibility === 'custom' && !req.userIds.length) { showMsg(t('chat.st.needPeople')); return false; }
				if (kind === 'text') {
					if (!req.text) { showMsg(t('chat.story.needText')); return false; }
					req.bg = bg;
					req.font = font;
				} else if (!file) { showMsg(t('chat.story.needFile')); return false; }
				if (durations) req.durationH = durationH;
				showMsg(t('chat.story.sharing'), 'busy');
				if (kind !== 'text') {
					try { Object.assign(req, await kit.storyFile(file, kind)); } catch (_) { showMsg(t('chat.story.failed', { error: t('chat.error.media_invalid') })); return false; }
				}
				const r = await api.createStory(req).catch((e) => ({ ok: false, error: e && e.message }));
				if (!r || r.ok === false) { showMsg(t('chat.story.failed', { error: CS.errorText(r, t) })); return false; }
				showMsg('');
				if (r.story) addOwn(r.story);
				toast(t('chat.story.shared'), 'success');
				load(true);
				return true;
			};
			let busy = false;
			return dialog(t('chat.story.create'), bodyEl, [
				{ label: t('chat.common.cancel'), value: null },
				{ label: t('chat.story.share'), primary: true, onClick: async () => {
					if (busy) return false;
					busy = true;
					const dlg = msg.closest('.cv-dlg');
					const btn = dlg ? dlg.querySelector('.cv-dlg-foot .btn-pri') : null;
					if (btn) btn.disabled = true;
					try {
						return await share();
					} catch (e) {
						showMsg(t('chat.story.failed', { error: CS.errorText({ ok: false, error: e && e.message }, t) }));
						return false;
					} finally {
						busy = false;
						if (btn) btn.disabled = false;
					}
				} },
			], { wide: true }).then((v) => { if (fileUrl) URL.revokeObjectURL(fileUrl); return v; });
		}

		// ── Story viewer ────────────────────────────────────

		/**
		 * Full-size viewer over the chat page: people[pi].stories[si] on, a
		 * progress bar per story, click left / right or ←/→, Esc closes.
		 */
		function viewer(people, pi, si) {
			const cx = kit.ctx();
			let p = pi;
			let s = si;
			let timer = null;
			let started = 0;
			let paused = false;
			let left = 0;
			let video = null;
			const ov = el('div', { class: 'cv-overlay cv-story', role: 'dialog', 'aria-modal': 'true', 'aria-label': t('chat.story.view') });
			const bars = el('div', { class: 'cv-story-bars' });
			const headEl = el('div', { class: 'cv-story-head' });
			const stage = el('div', { class: 'cv-story-stage' });
			const foot = el('div', { class: 'cv-story-foot' });
			const card = el('div', { class: 'cv-story-card' }, [bars, headEl, stage, foot]);
			const prevBtn = el('button', { type: 'button', class: 'cv-story-nav is-prev', 'aria-label': t('chat.story.prev'), on: { click: (e) => { e.stopPropagation(); step(-1); } } }, [icon('back', 22)]);
			const nextBtn = el('button', { type: 'button', class: 'cv-story-nav is-next', 'aria-label': t('chat.story.next'), on: { click: (e) => { e.stopPropagation(); step(1); } } }, [icon('chevron', 22)]);
			ov.append(prevBtn, card, nextBtn);
			const close = () => { clearTimeout(timer); if (video) { try { video.pause(); } catch (_) { /* gone */ } } ov.remove(); document.removeEventListener('keydown', onKey, true); load(); };
			const onKey = (e) => {
				if (e.target && e.target.tagName === 'INPUT') { if (e.key === 'Escape') { e.stopPropagation(); close(); } return; }
				if (e.key === 'Escape') { e.stopPropagation(); close(); } else if (e.key === 'ArrowRight') { e.preventDefault(); step(1); } else if (e.key === 'ArrowLeft') { e.preventDefault(); step(-1); }
			};
			ov.addEventListener('click', (e) => { if (e.target === ov) close(); });
			document.addEventListener('keydown', onKey, true);

			function step(d) {
				const list = people[p].stories || [];
				if (s + d >= 0 && s + d < list.length) { s += d; show(); return; }
				if (d > 0 && p + 1 < people.length) { p += 1; s = CS.firstUnseen(people[p].stories); show(); return; }
				if (d < 0 && p > 0) { p -= 1; s = Math.max(0, (people[p].stories || []).length - 1); show(); return; }
				if (d > 0) close();
			}
			function schedule(ms) {
				clearTimeout(timer);
				started = Date.now();
				left = ms;
				const bar = bars.children[s] && bars.children[s].firstChild;
				if (bar) { bar.style.transition = 'none'; bar.style.width = '0%'; requestAnimationFrame(() => { bar.style.transition = `width ${ms}ms linear`; bar.style.width = '100%'; }); }
				timer = setTimeout(() => step(1), ms);
			}
			function pause(on) {
				if (paused === on) return;
				paused = on;
				const bar = bars.children[s] && bars.children[s].firstChild;
				if (on) {
					clearTimeout(timer);
					left = Math.max(0, left - (Date.now() - started));
					if (bar) { const w = getComputedStyle(bar).width; bar.style.transition = 'none'; bar.style.width = w; }
					if (video) video.pause();
				} else {
					if (video) { video.play().catch(() => {}); return; }
					started = Date.now();
					if (bar) { requestAnimationFrame(() => { bar.style.transition = `width ${left}ms linear`; bar.style.width = '100%'; }); }
					timer = setTimeout(() => step(1), left);
				}
			}
			function show() {
				clearTimeout(timer);
				paused = false;
				if (video) { try { video.pause(); } catch (_) { /* gone */ } video = null; }
				const person = people[p];
				const list = person.stories || [];
				const st = list[s];
				if (!st) { close(); return; }
				const own = person.user && person.user.id === meId();
				prevBtn.disabled = p === 0 && s === 0;
				clear(bars);
				list.forEach((_, i) => bars.appendChild(el('span', { class: 'cv-story-bar' }, [el('i', { style: `width:${i < s ? 100 : 0}%` })])));
				clear(headEl).append(...[
					kit.avatar(CS.personAvatar(person.user), 36),
					el('span', { class: 'cv-story-who' }, [
						el('b', { text: own ? t('chat.st.mine') : (person.user.name || t('chat.gone')) }),
						el('small', { text: [CS.relAge(st.createdAt, cx), CS.remaining(st.expiresAt, cx)].filter(Boolean).join(' · ') }),
					]),
					el('span', { class: 'cv-grow' }),
					own ? iconBtn('trash', t('chat.story.delete'), async () => {
						pause(true);
						if (!(await confirmDialog(t('chat.story.deleteQ'), t('chat.common.delete'), true))) { pause(false); return; }
						const r = await api.deleteStory(st.id).catch((e) => ({ ok: false, error: e && e.message }));
						if (!r || r.ok === false) { toast(CS.errorText(r, t), 'error'); pause(false); return; }
						list.splice(s, 1);
						if (!list.length) { close(); return; }
						s = Math.min(s, list.length - 1);
						show();
					}, 'cv-ib-flat') : null,
					iconBtn('close', t('chat.common.close'), close, 'cv-ib-flat'),
				].filter(Boolean));
				clear(stage);
				stage.className = `cv-story-stage is-${st.kind} font-${st.font || 'sans'}`;
				stage.style.background = st.kind === 'text' ? (/^#[0-9a-fA-F]{6}$/.test(st.bg || '') ? st.bg : CS.STORY_COLORS[0]) : '#000';
				const extra = [st.place ? t('chat.story.place', { place: st.place }) : null].filter(Boolean).join(' · ');
				if (st.kind === 'text') {
					stage.appendChild(el('div', { class: 'cv-story-text', text: st.text || '' }));
					schedule(Math.min(15000, 5000 + (st.text || '').length * 40));
				} else {
					const media = el('div', { class: 'cv-story-media' });
					stage.appendChild(media);
					if (st.text) stage.appendChild(el('div', { class: 'cv-story-caption', text: st.text }));
					kit.mediaUrl(st.mediaId).then((u) => {
						if (people[p] !== person || person.stories[s] !== st) return;
						if (!u) { media.appendChild(el('span', { class: 'cv-dim', text: t('chat.msg.mediaUnavailable') })); schedule(4000); return; }
						if (st.kind === 'video') {
							video = el('video', { src: u, autoplay: true, playsinline: true });
							video.addEventListener('loadedmetadata', () => { const d = Number.isFinite(video.duration) ? video.duration * 1000 : 10000; schedule(Math.min(60000, Math.max(3000, d))); });
							video.addEventListener('error', () => schedule(4000));
							media.appendChild(video);
						} else {
							media.appendChild(el('img', { src: u, alt: '' }));
							schedule(6000);
						}
					});
				}
				if (extra) stage.appendChild(el('div', { class: 'cv-story-extra', text: extra }));
				stage.addEventListener('pointerdown', () => pause(true));
				stage.addEventListener('pointerup', () => pause(false));
				stage.addEventListener('pointerleave', () => pause(false));
				clear(foot);
				if (own) {
					const n = Number(st.viewerCount) || 0;
					foot.appendChild(el('button', { type: 'button', class: 'btn btn-sec btn-sm cv-story-viewers', on: { click: () => { pause(true); viewersDialog(st).then(() => pause(false)); } } }, [icon('eye', 14), t('chat.story.viewers', { n })]));
				} else {
					if (!st.seen) {
						st.seen = true;
						api.storySeen(st.id).catch(() => {});
					}
					const reply = el('input', { class: 'inp cv-story-reply', maxlength: '4000', placeholder: t('chat.story.replyPh', { name: person.user.name || '' }), 'aria-label': t('chat.story.reply') });
					reply.addEventListener('focus', () => pause(true));
					reply.addEventListener('blur', () => { if (!reply.value) pause(false); });
					const sendReply = async () => {
						const v = reply.value.trim();
						if (!v) return;
						const ok = await kit.replyToStory(person.user.id, st.id, v);
						if (ok) { reply.value = ''; toast(t('chat.story.replied', { name: person.user.name || '' }), 'success'); reply.blur(); }
					};
					reply.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); sendReply(); } });
					foot.append(
						el('div', { class: 'cv-story-emojis', role: 'group', 'aria-label': t('chat.story.react') }, CS.STORY_EMOJIS.map((em) => el('button', { type: 'button', text: em, 'aria-label': em, on: { click: async () => {
							const r = await api.storyReact(st.id, em).catch((e) => ({ ok: false, error: e && e.message }));
							if (!r || r.ok === false) toast(CS.errorText(r, t), 'error');
							else toast(t('chat.story.reacted', { emoji: em }), 'success');
						} } }))),
						el('div', { class: 'cv-row-inline' }, [reply, iconBtn('send', t('chat.send'), sendReply, 'cv-ib-pri')]),
						el('small', { class: 'cv-story-hint', text: t('chat.story.replyHint', { name: person.user.name || '' }) }),
					);
				}
			}
			kit.mount(ov);
			show();
		}

		async function viewersDialog(st) {
			const r = await api.storyViewers(st.id).catch(() => null);
			const list = el('div', { class: 'cv-stack' });
			const vs = r && r.ok !== false ? r.viewers : [];
			if (!vs.length) list.appendChild(el('p', { class: 'cv-empty', text: t('chat.story.noViewers') }));
			for (const v of vs) {
				list.appendChild(el('div', { class: 'cv-member' }, [
					kit.avatar(CS.personAvatar(v.user || {}), 30),
					el('span', { class: 'cv-member-tx' }, [el('b', { text: (v.user && v.user.name) || t('chat.gone') }), el('small', { class: 'cv-dim', text: CS.hm(v.seenAt, kit.ctx().locale) })]),
					v.reaction ? el('span', { class: 'cv-story-vr', text: v.reaction }) : null,
				]));
			}
			return dialog(t('chat.story.viewersTitle'), list, [{ label: t('chat.common.close'), value: null }]);
		}

		return {
			load,
			set,
			strip,
			statusDialog,
			composeStory,
			viewer,
			viewOwn,
			hasOwnStories,
			mine,
			feed: () => S.feed,
			onChange: (fn) => { listeners.add(fn); return () => listeners.delete(fn); },
		};
	}

	root.GCChatStatus = { create };
})(typeof self !== 'undefined' ? self : this);
