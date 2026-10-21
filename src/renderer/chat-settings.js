/**
 * GateControl -- Chats: "Chat-Einstellungen" as a page (renderer)
 *
 * A full page over the chat view (not a dialog), WhatsApp-like sections on
 * the left and their settings on the right:
 *   Konto / Profil · Datenschutz (last seen, picture, status default, place
 *   in status, groups, default disappearing timer, read receipts, "schreibt
 *   …", blocked people) · Benachrichtigungen (server notify.* prefs, preview,
 *   the sound of this PC) · Chats (Enter sends, font size, archive, export)
 *   · Listen (own chat filters) · Erinnerungen · Speicher · Haus-Aktionen
 *   (which actions the attach menu shows, a setting of this PC) · Wo
 *   Mitteilungen erscheinen (Messenger 1.6, core push routes:
 *   notify-routes.js, the same view as in Einstellungen › Benachrichtigungen).
 * The 1.0 settings (read receipts, typing, preview) work with every server;
 * the rest appears only when `GET me` features has privacy2 / msg_tools /
 * actions.
 *
 * Mounted by chat-view.js with its kit: window.GCChatSettings.create(kit).
 * Local settings (this PC) live in localStorage under gc.chat.*.
 *
 * Note: user data only ever goes into textContent / attributes.
 */
(function (root) {
	'use strict';

	const CS = root.GCChatState;
	const LOCAL = {
		enter: 'gc.chat.enterSends',
		font: 'gc.chat.fontSize',
		sound: 'gc.chat.sound',
		hidden: 'gc.chat.hiddenActions',
	};

	/** Local settings of this PC (localStorage; defaults when unavailable). */
	const local = {
		get(key, fallback) {
			try { const v = root.localStorage.getItem(key); return v === null ? fallback : JSON.parse(v); } catch (_) { return fallback; }
		},
		set(key, value) {
			try { root.localStorage.setItem(key, JSON.stringify(value)); } catch (_) { /* storage unavailable */ }
		},
	};

	function create(kit) {
		const { api, t, el, icon, iconBtn, clear, dialog, confirmDialog, toast } = kit;
		let page = null;
		let section = 'account';
		const fail = (r) => toast(CS.errorText(r, t), 'error');
		const me = () => kit.me() || {};
		const prefs = () => me().prefs || {};
		const f14 = () => CS.features14(kit.me());

		function sections() {
			const f = f14();
			return [
				{ id: 'account', icon: 'user', label: t('chat.set.account'), sub: t('chat.set.accountSub') },
				{ id: 'privacy', icon: 'lock', label: t('chat.set.privacy'), sub: t(f.privacy ? 'chat.set.privacySub' : 'chat.set.privacySubOld') },
				{ id: 'notify', icon: 'bell', label: t('chat.set.notify'), sub: t('chat.set.notifySub') },
				{ id: 'chats', icon: 'chat', label: t('chat.set.chats'), sub: t('chat.set.chatsSub') },
				f.tools ? { id: 'lists', icon: 'list', label: t('chat.set.lists'), sub: t('chat.set.listsSub') } : null,
				f.tools ? { id: 'reminders', icon: 'clock', label: t('chat.set.reminders'), sub: t('chat.set.remindersSub') } : null,
				{ id: 'storage', icon: 'disk', label: t('chat.set.storage'), sub: t('chat.set.storageSub') },
				f.actions ? { id: 'actions', icon: 'home', label: t('chat.set.actions'), sub: t('chat.set.actionsSub') } : null,
				routesShown() ? { id: 'routes', icon: 'bell', label: t('chat.set.routes'), sub: t('chat.set.routesSub') } : null,
			].filter(Boolean);
		}

		/** "Wo Mitteilungen erscheinen": Messenger 1.6 (`notices` / `notice_routes`) and a core with the routes API. */
		function routesShown() {
			const f = f14();
			return (f.notices || f.noticeRoutes) && !!root.GCNotifyRoutes && root.GCNotifyRoutes.supported(kit.notify);
		}

		// ── Page ────────────────────────────────────────────

		function open(which) {
			if (which) section = which;
			if (!page) {
				page = el('section', { class: 'cv-settings', 'aria-label': t('chat.set.title') });
				kit.rootEl.appendChild(page);
				document.addEventListener('keydown', onKey, true);
			}
			render();
		}
		function close() {
			if (!page) return;
			page.remove();
			page = null;
			document.removeEventListener('keydown', onKey, true);
			kit.onSettingsClosed();
		}
		function onKey(e) {
			if (e.key !== 'Escape' || !page || document.querySelector('.cv-overlay')) return;
			e.stopPropagation();
			close();
		}
		const isOpen = () => !!page;

		function render() {
			if (!page) return;
			const list = sections();
			if (!list.some((s) => s.id === section)) section = 'account';
			clear(page);
			const nav = el('nav', { class: 'cv-set-nav scroll', 'aria-label': t('chat.set.title') });
			for (const s of list) {
				nav.appendChild(el('button', { type: 'button', class: `cv-set-item${s.id === section ? ' is-on' : ''}`, 'data-section': s.id, 'aria-current': s.id === section ? 'page' : 'false', on: { click: () => { section = s.id; render(); } } }, [
					el('span', { class: 'cv-set-ic' }, [icon(s.icon, 18)]),
					el('span', { class: 'cv-set-tx' }, [el('b', { text: s.label }), el('small', { text: s.sub })]),
				]));
			}
			const body = el('div', { class: 'cv-set-body scroll' });
			page.append(
				el('header', { class: 'cv-set-head' }, [
					iconBtn('back', t('chat.set.back'), () => close(), 'cv-ib-flat cv-set-back'),
					el('h1', { class: 'cv-h', text: t('chat.set.title') }),
				]),
				el('div', { class: 'cv-set-main' }, [nav, body]),
			);
			const draw = {
				account: drawAccount, privacy: drawPrivacy, notify: drawNotify, chats: drawChats, lists: drawLists, reminders: drawReminders, storage: drawStorage, actions: drawActions, routes: drawRoutes,
			}[section];
			const cur = list.find((s) => s.id === section);
			body.appendChild(el('h2', { class: 'cv-set-title', text: cur ? cur.label : '' }));
			draw(body);
		}

		// ── Building blocks ─────────────────────────────────

		function group(title, kids, note) {
			return el('div', { class: 'cv-set-group' }, [title ? el('div', { class: 'cv-sec', text: title }) : null, el('div', { class: 'cv-set-card' }, kids.filter(Boolean)), note ? el('p', { class: 'cv-note', text: note }) : null]);
		}

		function row(label, hint, control, id) {
			return el('div', { class: 'cv-pref', 'data-pref': id || null }, [el('span', { class: 'cv-pref-tx' }, [el('b', { text: label }), hint ? el('small', { text: hint }) : null]), control]);
		}

		/** A switch that saves itself (async save → true when stored). */
		function toggle(label, value, save) {
			const b = el('button', { type: 'button', class: `sw${value ? ' on' : ''}`, role: 'switch', 'aria-checked': value ? 'true' : 'false', 'aria-label': label }, [el('span')]);
			b.addEventListener('click', async () => {
				const next = b.getAttribute('aria-checked') !== 'true';
				b.setAttribute('aria-checked', next ? 'true' : 'false');
				b.classList.toggle('on', next);
				const ok = await save(next);
				if (!ok) { b.setAttribute('aria-checked', next ? 'false' : 'true'); b.classList.toggle('on', !next); }
			});
			return b;
		}

		function select(label, value, options, save) {
			const s = el('select', { class: 'inp cv-select', 'aria-label': label }, options.map(([v, text]) => el('option', { value: String(v), text })));
			s.value = String(value);
			let last = s.value;
			s.addEventListener('change', async () => {
				const opt = options.find(([v]) => String(v) === s.value);
				const ok = await save(opt ? opt[0] : s.value);
				if (!ok) s.value = last; else last = s.value;
			});
			return s;
		}

		/** PUT prefs (partial) → true when stored. */
		async function savePrefs(patch) {
			const r = await api.prefs(patch).catch((e) => ({ ok: false, error: e && e.message }));
			if (!r || r.ok === false) { fail(r); return false; }
			kit.reloadStatus();
			return true;
		}
		const audience = (keys) => keys.map((k) => [k, t(`chat.audience.${k}`)]);

		// ── Sections ────────────────────────────────────────

		function drawAccount(body) {
			const u = me().user || {};
			const own = kit.ownStatus();
			const line = own && own.status ? CS.statusLine(own.status, kit.ctx()) : '';
			body.append(
				el('div', { class: 'cv-set-profile' }, [
					kit.avatar(CS.personAvatar({ name: u.name, initials: u.initials, colorHex: u.colorHex, avatarUrl: u.avatarUrl }), 72),
					el('span', { class: 'cv-set-profile-tx' }, [el('b', { text: u.name || '' }), el('span', { class: 'cv-dim', text: line || t('chat.st.none') })]),
				]),
				group(null, [
					f14().status ? row(t('chat.st.yours'), line || t('chat.st.none'), el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('chat.set.changeStatus'), on: { click: () => kit.statusDialog() } })) : null,
					row(t('chat.set.profile'), t('chat.set.profileHint'), typeof kit.openPortal === 'function' ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => kit.openPortal() } }, [icon('external', 13), t('chat.set.inPortal')]) : el('span')),
				], t('chat.info.encrypted')),
			);
		}

		function drawPrivacy(body) {
			const p = prefs();
			const pv = p.privacy || {};
			const f = f14();
			if (f.privacy) {
				const lim = me().limits || {};
				const dis = (Array.isArray(lim.disappearingS) && lim.disappearingS.length ? lim.disappearingS : [0, 86400, 604800, 2592000]).map((s) => [s, CS.disLabel(s, t)]);
				body.appendChild(group(t('chat.set.whoSees'), [
					row(t('chat.set.lastSeen'), t('chat.set.lastSeenHint'), select(t('chat.set.lastSeen'), pv.lastSeen || 'all', audience(['all', 'family', 'nobody']), (v) => savePrefs({ privacy: { lastSeen: v } })), 'lastSeen'),
					row(t('chat.set.avatar'), null, select(t('chat.set.avatar'), pv.avatar || 'all', audience(['all', 'family', 'nobody']), (v) => savePrefs({ privacy: { avatar: v } })), 'avatar'),
					row(t('chat.set.statusDefault'), t('chat.set.statusDefaultHint'), select(t('chat.set.statusDefault'), pv.statusDefault || 'all', audience(['all', 'family', 'custom']), (v) => savePrefs({ privacy: { statusDefault: v } })), 'statusDefault'),
					row(t('chat.set.placeInStatus'), t('chat.set.placeInStatusHint'), select(t('chat.set.placeInStatus'), pv.placeInStatus || 'family', audience(['nobody', 'family', 'all']), (v) => savePrefs({ privacy: { placeInStatus: v } })), 'placeInStatus'),
				], t('chat.set.familyHint')));
			}
			body.appendChild(group(t('chat.set.messages'), [
				row(t('chat.prefs.readReceipts'), t('chat.prefs.readReceiptsHint'), toggle(t('chat.prefs.readReceipts'), p.readReceipts !== false, (v) => savePrefs({ readReceipts: v })), 'readReceipts'),
				row(t('chat.prefs.typing'), t('chat.prefs.typingHint'), toggle(t('chat.prefs.typing'), p.typing !== false, (v) => savePrefs({ typing: v })), 'typing'),
				f.privacy ? row(t('chat.set.defaultDis'), t('chat.set.defaultDisHint'), select(t('chat.set.defaultDis'), pv.defaultDisappearingS || 0, (me().limits && Array.isArray(me().limits.disappearingS) && me().limits.disappearingS.length ? me().limits.disappearingS : [0, 86400, 604800, 2592000]).map((s) => [s, CS.disLabel(s, t)]), (v) => savePrefs({ privacy: { defaultDisappearingS: Number(v) } })), 'defaultDisappearingS') : null,
			]));
			if (f.privacy) {
				body.appendChild(group(t('chat.set.groups'), [
					row(t('chat.set.groupAdd'), t('chat.set.groupAddHint'), select(t('chat.set.groupAdd'), pv.groupAdd || 'all', audience(['all', 'family', 'nobody']), (v) => savePrefs({ privacy: { groupAdd: v } })), 'groupAdd'),
				]));
			}
			if (f.tools) {
				const blocks = el('div', { class: 'cv-set-card' }, [el('p', { class: 'cv-dim cv-set-pad', text: t('chat.loading') })]);
				body.appendChild(el('div', { class: 'cv-set-group' }, [el('div', { class: 'cv-sec', text: t('chat.set.blocked') }), blocks, el('p', { class: 'cv-note', text: t('chat.set.blockedHint') })]));
				drawBlocks(blocks);
			}
			body.appendChild(el('p', { class: 'cv-note cv-note-lock' }, [icon('lock', 14), el('span', { text: t('chat.set.privacyNote') })]));
		}

		async function drawBlocks(box) {
			const r = await api.blocks().catch(() => null);
			if (!page || !box.isConnected) return;
			clear(box);
			const list = r && r.ok !== false ? r.blocks : [];
			if (!list.length) box.appendChild(el('p', { class: 'cv-dim cv-set-pad', text: t('chat.set.noneBlocked') }));
			for (const b of list) {
				box.appendChild(el('div', { class: 'cv-member cv-set-pad' }, [
					kit.avatar(b.gone ? { kind: 'icon', icon: 'gone' } : CS.personAvatar(b), 32),
					el('span', { class: 'cv-member-tx' }, [el('b', { text: b.name || t('chat.gone') })]),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('chat.block.unblock'), on: { click: async () => {
						const x = await api.block(b.userId, false).catch((e) => ({ ok: false, error: e && e.message }));
						if (!x || x.ok === false) fail(x); else drawBlocks(box);
					} } }),
				]));
			}
			box.appendChild(el('div', { class: 'cv-set-pad' }, [el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => blockSomeone(box, list) } }, [icon('plus', 13), t('chat.block.add')])]));
		}

		async function blockSomeone(box, blocked) {
			const people = await kit.loadPeople(true);
			const taken = new Set(blocked.map((b) => b.userId));
			let closeFn = null;
			const list = el('div', { class: 'cv-people scroll' });
			for (const p of people.filter((x) => !taken.has(x.id))) {
				list.appendChild(kit.personRow(p, { onClick: async () => {
					if (!(await confirmDialog(t('chat.block.q', { name: p.name || '' }), t('chat.block.block'), true))) return;
					const x = await api.block(p.id, true).catch((e) => ({ ok: false, error: e && e.message }));
					if (!x || x.ok === false) { fail(x); return; }
					if (closeFn) closeFn(null);
					drawBlocks(box);
				} }));
			}
			if (!list.childNodes.length) list.appendChild(el('p', { class: 'cv-empty', text: t('chat.new.noPeople') }));
			dialog(t('chat.block.add'), list, [], { onOpen: (done) => { closeFn = done; } });
		}

		function drawNotify(body) {
			const p = prefs();
			const n = p.notify || {};
			const f = f14();
			body.appendChild(group(t('chat.set.onThisPc'), [
				row(t('chat.set.sound'), t('chat.set.soundHint'), toggle(t('chat.set.sound'), local.get(LOCAL.sound, true) !== false, async (v) => { local.set(LOCAL.sound, v); if (v) kit.playSound('in'); return true; }), 'sound'),
				row(t('chat.prefs.preview'), t('chat.prefs.previewHint'), toggle(t('chat.prefs.preview'), p.preview !== false, (v) => savePrefs({ preview: v })), 'preview'),
			], t('chat.prefs.toastHint')));
			if (routesShown()) {
				body.appendChild(group(t('push.routes.title'), [
					row(t('push.routes.title'), t('push.routes.entryDesc'), el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('push.routes.open'), on: { click: () => { section = 'routes'; render(); } } }), 'routes'),
				]));
			}
			if (f.privacy) {
				body.appendChild(group(t('chat.set.groupsAndMore'), [
					row(t('chat.set.mentionsOnly'), t('chat.set.mentionsOnlyHint', { name: (me().user && me().user.name ? me().user.name.split(' ')[0] : '') }), toggle(t('chat.set.mentionsOnly'), n.groupsMentionsOnly === true, (v) => savePrefs({ notify: { groupsMentionsOnly: v } })), 'groupsMentionsOnly'),
					row(t('chat.set.reactions'), t('chat.set.reactionsHint'), toggle(t('chat.set.reactions'), n.reactions !== false, (v) => savePrefs({ notify: { reactions: v } })), 'reactions'),
					f.status ? row(t('chat.set.statusDigest'), t('chat.set.statusDigestHint'), toggle(t('chat.set.statusDigest'), n.statusDigest === true, (v) => savePrefs({ notify: { statusDigest: v } })), 'statusDigest') : null,
					f.events ? row(t('chat.set.eventReminder'), t('chat.set.eventReminderHint'), select(t('chat.set.eventReminder'), Number.isFinite(n.eventReminderMin) ? n.eventReminderMin : 60, [0, 15, 60, 120, 1440].map((x) => [x, t(`chat.reminderMin.${x}`)]), (v) => savePrefs({ notify: { eventReminderMin: Number(v) } })), 'eventReminderMin') : null,
				], f.status ? t('chat.set.dndHint') : null));
			}
		}

		function drawChats(body) {
			const p = prefs();
			const f = f14();
			body.appendChild(group(t('chat.set.display'), [
				row(t('chat.set.fontSize'), null, select(t('chat.set.fontSize'), local.get(LOCAL.font, 'medium'), [['small', t('chat.set.font.small')], ['medium', t('chat.set.font.medium')], ['large', t('chat.set.font.large')]], async (v) => { local.set(LOCAL.font, v); kit.applyLocal(); return true; }), 'fontSize'),
			]));
			body.appendChild(group(t('chat.set.chats'), [
				row(t('chat.set.enterSends'), t('chat.set.enterSendsHint'), toggle(t('chat.set.enterSends'), local.get(LOCAL.enter, true) !== false, async (v) => { local.set(LOCAL.enter, v); kit.applyLocal(); return true; }), 'enterSends'),
				f.privacy ? row(t('chat.set.keepArchived'), t('chat.set.keepArchivedHint'), toggle(t('chat.set.keepArchived'), !(p.chats && p.chats.keepArchived === false), (v) => savePrefs({ chats: { keepArchived: v } })), 'keepArchived') : null,
				f.tools ? row(t('chat.set.export'), t('chat.set.exportHint'), el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('chat.set.exportBtn'), on: { click: () => exportPick() } }), 'export') : null,
			]));
		}

		function exportPick() {
			let closeFn = null;
			const list = el('div', { class: 'cv-people scroll' });
			for (const c of kit.conversations()) {
				list.appendChild(el('button', { type: 'button', class: 'cv-person', on: { click: () => { if (closeFn) closeFn(null); kit.exportChat(c); } } }, [kit.avatar(CS.avatarOf(c), 32), el('span', { class: 'cv-person-name', text: CS.title(c, t) })]));
			}
			dialog(t('chat.set.exportPick'), list, [], { onOpen: (done) => { closeFn = done; } });
		}

		async function drawLists(body) {
			const box = el('div', { class: 'cv-set-card' }, [el('p', { class: 'cv-dim cv-set-pad', text: t('chat.loading') })]);
			body.appendChild(el('div', { class: 'cv-set-group' }, [box, el('p', { class: 'cv-note', text: t('chat.lists.hint') })]));
			const r = await api.lists().catch(() => null);
			if (!page || !box.isConnected) return;
			const lists = r && r.ok !== false ? r.lists : [];
			const save = async (next) => {
				const x = await api.saveLists(next).catch((e) => ({ ok: false, error: e && e.message }));
				if (!x || x.ok === false) { fail(x); return false; }
				kit.listsChanged(x.lists);
				render();
				return true;
			};
			clear(box);
			if (!lists.length) box.appendChild(el('p', { class: 'cv-dim cv-set-pad', text: t('chat.lists.none') }));
			for (const l of lists) {
				box.appendChild(el('div', { class: 'cv-member cv-set-pad', 'data-list': l.id }, [
					el('span', { class: 'cv-set-ic' }, [icon('list', 16)]),
					el('span', { class: 'cv-member-tx' }, [el('b', { text: l.name }), el('small', { class: 'cv-dim', text: t('chat.lists.count', { n: (l.conversationIds || []).length }) })]),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('chat.lists.edit'), on: { click: () => listDialog(lists, l, save) } }),
					iconBtn('trash', t('chat.common.delete'), async () => { if (await confirmDialog(t('chat.lists.deleteQ', { name: l.name }), t('chat.common.delete'), true)) save(lists.filter((x) => x.id !== l.id)); }, 'cv-ib-flat'),
				]));
			}
			const max = (me().limits && me().limits.listsMax) || 20;
			box.appendChild(el('div', { class: 'cv-set-pad' }, [el('button', { type: 'button', class: 'btn btn-ghost btn-sm', disabled: lists.length >= max ? true : null, on: { click: () => listDialog(lists, null, save) } }, [icon('plus', 13), t('chat.lists.add')])]));
		}

		/** Create / edit a chat list: name and its chats. */
		function listDialog(lists, l, save) {
			const name = el('input', { class: 'inp', maxlength: '40', value: l ? l.name : '', placeholder: t('chat.lists.namePh'), 'aria-label': t('chat.lists.name') });
			const ids = new Set(l ? l.conversationIds : []);
			const chats = el('div', { class: 'cv-people scroll' });
			for (const c of kit.conversations()) {
				const cb = el('input', { type: 'checkbox', value: String(c.id), checked: ids.has(c.id), 'aria-label': CS.title(c, t) });
				chats.appendChild(el('label', { class: 'cv-person' }, [kit.avatar(CS.avatarOf(c), 30), el('span', { class: 'cv-person-name', text: CS.title(c, t) }), cb]));
			}
			dialog(l ? t('chat.lists.edit') : t('chat.lists.add'), el('div', { class: 'cv-stack' }, [el('label', { class: 'cv-field' }, [el('span', { text: t('chat.lists.name') }), name]), el('div', { class: 'cv-field' }, [el('span', { text: t('chat.lists.chats') }), chats])]), [
				{ label: t('chat.common.cancel'), value: null },
				{ label: t('chat.common.save'), primary: true, onClick: async () => {
					const n = name.value.trim();
					if (!n) return false;
					const conversationIds = Array.from(chats.querySelectorAll('input:checked')).map((x) => Number(x.value));
					const next = l ? lists.map((x) => (x.id === l.id ? { ...x, name: n, conversationIds } : x)) : lists.concat({ id: CS.listId(n, lists), name: n, conversationIds });
					return save(next);
				} },
			]);
		}

		async function drawReminders(body) {
			const box = el('div', { class: 'cv-set-card' }, [el('p', { class: 'cv-dim cv-set-pad', text: t('chat.loading') })]);
			body.appendChild(el('div', { class: 'cv-set-group' }, [box, el('p', { class: 'cv-note', text: t('chat.remind.hint') })]));
			const r = await api.reminders().catch(() => null);
			if (!page || !box.isConnected) return;
			clear(box);
			const list = r && r.ok !== false ? r.reminders : [];
			if (!list.length) box.appendChild(el('p', { class: 'cv-dim cv-set-pad', text: t('chat.remind.none') }));
			const cx = kit.ctx();
			for (const x of list) {
				const c = kit.conversations().find((cv) => cv.id === x.conversationId);
				box.appendChild(el('div', { class: 'cv-member cv-set-pad', 'data-reminder': String(x.id) }, [
					el('span', { class: 'cv-set-ic' }, [icon('clock', 16)]),
					el('button', { type: 'button', class: 'cv-member-tx cv-set-link', on: { click: () => { close(); kit.openMessage(x.conversationId, x.messageId); } } }, [
						el('b', { text: CS.when(x.at, cx.locale) }),
						el('small', { class: 'cv-dim', text: [c ? CS.title(c, t) : null, x.preview].filter(Boolean).join(' · ') }),
					]),
					iconBtn('trash', t('chat.common.delete'), async () => {
						const d = await api.deleteReminder(x.id).catch((e) => ({ ok: false, error: e && e.message }));
						if (!d || d.ok === false) fail(d); else render();
					}, 'cv-ib-flat'),
				]));
			}
		}

		async function drawStorage(body) {
			const box = el('div', { class: 'cv-set-card' }, [el('p', { class: 'cv-dim cv-set-pad', text: t('chat.loading') })]);
			body.appendChild(el('div', { class: 'cv-set-group' }, [box]));
			const r = await api.storage().catch(() => null);
			if (!page || !box.isConnected) return;
			clear(box);
			if (!r || r.ok === false) { box.appendChild(el('p', { class: 'cv-dim cv-set-pad', text: CS.errorText(r, t) })); return; }
			const loc = kit.ctx().locale;
			const s = r.server || {};
			box.append(
				row(t('chat.set.serverQuota'), s.quotaFull ? t('chat.set.quotaFull') : t('chat.set.quotaOk'), el('span', { class: `cv-chip${s.quotaFull ? ' is-err' : ''}`, text: s.quotaFull ? t('chat.set.full') : t('chat.set.ok') }), 'quota'),
				row(t('chat.set.maxFile'), null, el('span', { class: 'cv-dim', text: s.maxBytes ? CS.bytes(s.maxBytes, loc) : '–' }), 'maxBytes'),
				row(t('chat.set.retention'), null, el('span', { class: 'cv-dim', text: s.retentionDays ? t('chat.set.retentionDays', { n: s.retentionDays }) : t('chat.set.retentionNone') }), 'retention'),
				row(t('chat.set.cache'), t('chat.set.cacheHint', { chats: r.cachedChats, messages: r.cachedMessages }), el('span', { class: 'cv-dim', text: CS.bytes((r.mediaCacheBytes || 0) + (r.avatarCacheBytes || 0), loc) }), 'cache'),
				row(t('chat.set.outbox'), null, el('span', { class: 'cv-dim', text: String(r.outbox || 0) }), 'outbox'),
				el('div', { class: 'cv-set-pad' }, [el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('chat.set.clearCache'), on: { click: async () => { await api.clearCache().catch(() => null); kit.clearMediaUrls(); toast(t('chat.set.cacheCleared'), 'success'); render(); } } })]),
			);
		}

		/** GateControl, family chat or an own chat per kind of notification (shared view, skin of this page). */
		function drawRoutes(body) {
			const host = el('div', { class: 'nr-host' });
			body.appendChild(host);
			root.GCNotifyRoutes.mount(host, { api: kit.notify, t, toast, skin: 'chat' }).load();
		}

		async function drawActions(body) {
			body.appendChild(el('p', { class: 'cv-note', text: t('chat.set.actionsInfo') }));
			const box = el('div', { class: 'cv-set-card' }, [el('p', { class: 'cv-dim cv-set-pad', text: t('chat.loading') })]);
			body.appendChild(el('div', { class: 'cv-set-group' }, [el('div', { class: 'cv-sec', text: t('chat.set.actionsShown') }), box, el('p', { class: 'cv-note', text: t('chat.set.actionsLocal') })]));
			const r = await api.actions({ refresh: true }).catch(() => null);
			if (!page || !box.isConnected) return;
			clear(box);
			const list = r && r.ok !== false ? r.actions : [];
			if (!r || r.ok === false) box.appendChild(el('p', { class: 'cv-dim cv-set-pad', text: CS.errorText(r, t) }));
			else if (!list.length) box.appendChild(el('p', { class: 'cv-dim cv-set-pad', text: t('chat.set.noActions') }));
			const hidden = new Set(local.get(LOCAL.hidden, []));
			for (const a of list) {
				box.appendChild(row(a.label || a.id, [a.pluginName || a.plugin, a.needsConfirm ? t('chat.set.needsConfirm') : null].filter(Boolean).join(' · '), toggle(a.label || a.id, !hidden.has(a.id), async (v) => {
					const h = new Set(local.get(LOCAL.hidden, []));
					if (v) h.delete(a.id); else h.add(a.id);
					local.set(LOCAL.hidden, [...h]);
					return true;
				}), `action:${a.id}`));
			}
		}

		return { open, close, isOpen, render, local, LOCAL };
	}

	root.GCChatSettings = { create, LOCAL, local: {
		get(key, fallback) { try { const v = root.localStorage.getItem(key); return v === null ? fallback : JSON.parse(v); } catch (_) { return fallback; } },
	} };
})(typeof self !== 'undefined' ? self : this);
