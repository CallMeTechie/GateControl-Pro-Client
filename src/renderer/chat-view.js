/**
 * GateControl -- Chats (renderer view of the GateControl Messenger)
 *
 * List | chat | info, like the portal tab of the plugin: the pinned
 * "GateControl" entry (the notification inbox), direct and group chats with
 * unread counts and "schreibt …"; the chat with text, pictures, files
 * (open / save as), voice messages (record + play), replies, reactions,
 * edit / delete, ticks, day separators and the unread line; new chat / group,
 * chat info (members, mute, disappearing, media), search (list: Strg+K, in a
 * chat: server search), "Meine Chat-Einstellungen"; drag & drop and paste of
 * files; offline outbox entries with "Erneut senden" / "Verwerfen";
 * "Standort senden" (map dialog: own position, a point on the map or an
 * address) and map previews of locations; the pinned inbox marks each entry
 * read once it has been in view; videos (a frame at ~1 s as preview, length,
 * played in an overlay) and file previews (Messenger 1.3.0); jumps to search
 * hits and quotes that are not loaded (`around`, Messenger 1.1.0) with a
 * window of its own until it meets the newest messages.
 *
 * Map tiles and addresses come from the main process (chat.mapTile /
 * mapSearch / mapReverse → core MapService, OpenStreetMap) as bytes / data;
 * the page shows them as blob: URLs, it never loads anything from the
 * network itself.
 *
 * Data: window.gatecontrol.chat (core MessengerService over IPC); texts:
 * chat.* of the core locales; view logic without DOM: chat-state.js
 * (window.GCChatState). The same file is used by Pro and Community.
 *
 * Note: user data only ever goes into textContent / attributes; icons are
 * built from static path data with createElementNS (no innerHTML).
 */
(function (root) {
	'use strict';

	const CS = root.GCChatState;
	const NS = 'http://www.w3.org/2000/svg';
	const ICONS = {
		search: 'M11 4a7 7 0 1 0 0 14a7 7 0 1 0 0-14|M20 20l-3.5-3.5',
		pen: 'M4 20h4L19 9l-4-4L4 16v4z',
		gear: 'M12 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6|M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
		attach: 'M21 11.5l-8.5 8.5a5 5 0 0 1-7-7l9-9a3.5 3.5 0 0 1 5 5l-9 9a2 2 0 0 1-3-3l8-8',
		mic: 'M9 6a3 3 0 0 1 6 0v5a3 3 0 0 1-6 0z|M5 11a7 7 0 0 0 14 0M12 18v3',
		send: 'M4 12l16-8-6 16-3-7z',
		back: 'M15 18l-6-6 6-6',
		info: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 11v5M12 8h.01',
		close: 'M6 6l12 12M18 6L6 18',
		reply: 'M9 14L4 9l5-5|M4 9h10a6 6 0 0 1 6 6v4',
		smile: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M8 14s1.5 2 4 2 4-2 4-2M9 9h.01M15 9h.01',
		trash: 'M4 7h16M10 11v6M14 11v6|M6 7l1 13h10l1-13M9 7V4h6v3',
		more: 'M12 5h.01M12 12h.01M12 19h.01',
		file: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z|M14 3v5h5',
		pin: 'M12 21s-7-6.2-7-11a7 7 0 1 1 14 0c0 4.8-7 11-7 11z|M12 7.5a2.5 2.5 0 1 0 0 5a2.5 2.5 0 1 0 0-5',
		group: 'M9 4.5a3.5 3.5 0 1 0 0 7a3.5 3.5 0 1 0 0-7|M2.5 20a6.5 6.5 0 0 1 13 0M16 4.5a3.5 3.5 0 0 1 0 7M18 14a5.5 5.5 0 0 1 3.5 6',
		shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
		lock: 'M6 11h12v10H6z|M8 11V8a4 4 0 0 1 8 0v3',
		bell: 'M6 8a6 6 0 0 1 12 0c0 7 3 8 3 8H3s3-1 3-8|M10 20a2 2 0 0 0 4 0',
		bellOff: 'M6 8a6 6 0 0 1 9.3-5M18 8c0 7 3 8 3 8H8|M10 20a2 2 0 0 0 4 0M3 3l18 18',
		timer: 'M12 7v5l3 2|M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18',
		plus: 'M12 5v14M5 12h14',
		check: 'M4 12l5 5L20 6',
		checks: 'M2 13l4 4 8-9M10 16l1 1 9-10',
		clock: 'M12 7v5l3 2|M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18',
		alert: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 8v5M12 16h.01',
		play: 'M8 5v14l11-7z',
		pause: 'M7 5h4v14H7zM13 5h4v14h-4z',
		image: 'M4 5h16v14H4z|M4 16l5-5 4 4 3-3 4 4|M15 8.5h.01',
		down: 'M12 5v14M6 13l6 6 6-6',
		external: 'M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6',
		copy: 'M9 9h11v11H9z|M5 15H4V4h11v1',
		retry: 'M21 12a9 9 0 1 1-3-6.7L21 8|M21 3v5h-5',
		minus: 'M5 12h14',
		target: 'M12 5a7 7 0 1 0 0 14a7 7 0 1 0 0-14|M12 10a2 2 0 1 0 0 4a2 2 0 1 0 0-4|M12 2v3M12 19v3M2 12h3M19 12h3',
		video: 'M3 6h12v12H3z|M15 10l6-3v10l-6-3z',
	};
	const FILLED = new Set(['play', 'pause']);

	function icon(name, size = 16, stroke = '2') {
		const s = document.createElementNS(NS, 'svg');
		s.setAttribute('viewBox', '0 0 24 24');
		s.setAttribute('width', String(size));
		s.setAttribute('height', String(size));
		const filled = FILLED.has(name);
		s.setAttribute('fill', filled ? 'currentColor' : 'none');
		s.setAttribute('stroke', filled ? 'none' : 'currentColor');
		s.setAttribute('stroke-width', stroke);
		s.setAttribute('stroke-linecap', 'round');
		s.setAttribute('stroke-linejoin', 'round');
		s.setAttribute('aria-hidden', 'true');
		for (const d of String(ICONS[name] || ICONS.info).split('|')) {
			const p = document.createElementNS(NS, 'path');
			p.setAttribute('d', d);
			s.appendChild(p);
		}
		return s;
	}

	/** el('div', { class, text, on: { click }, attrs… }, [children]) — text only via textContent. */
	function el(tag, attrs, kids) {
		const n = document.createElement(tag);
		for (const [k, v] of Object.entries(attrs || {})) {
			if (v === null || v === undefined || v === false) continue;
			if (k === 'text') n.textContent = String(v);
			else if (k === 'class') n.className = v;
			else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
			else if (k === 'value') n.value = v;
			else if (k === 'checked') n.checked = !!v;
			else if (k === 'style') n.setAttribute('style', v);
			else n.setAttribute(k, v === true ? '' : String(v));
		}
		for (const c of kids || []) if (c !== null && c !== undefined && c !== false) n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
		return n;
	}
	const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };

	function iconBtn(name, label, onClick, cls = '') {
		return el('button', { type: 'button', class: `cv-ib ${cls}`.trim(), 'aria-label': label, title: label, on: { click: onClick } }, [icon(name, 16)]);
	}

	/**
	 * @param {object} o
	 * @param {HTMLElement} o.root - the page section (empty)
	 * @param {object} o.api - window.gatecontrol.chat
	 * @param {object} [o.notify] - window.gatecontrol.notify (pinned "GateControl")
	 * @param {Function} o.t - i18n
	 * @param {() => string} o.getLocale
	 * @param {(msg: string, type?: string) => void} [o.toast]
	 * @param {(id: ?number) => void} [o.openInbox] - "In Mitteilungen öffnen"
	 * @param {(st: object) => void} [o.onStatus] - availability (nav entry)
	 * @param {(n: number) => void} [o.onUnread] - nav badge
	 * @param {() => void} [o.checkUpdate] - the app's update check (button of the "newer version" banner)
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		let toastTimer = null;
		/** In-page notice when the app has no toast helper of its own. */
		const ownToast = (msg, type = 'info') => {
			let n = rootEl.querySelector('.cv-toast');
			if (!n) { n = el('div', { class: 'cv-toast', role: 'status' }); rootEl.appendChild(n); }
			n.textContent = String(msg || '');
			n.setAttribute('data-type', type);
			n.hidden = false;
			clearTimeout(toastTimer);
			toastTimer = setTimeout(() => { n.hidden = true; }, 5000);
		};
		const toast = typeof o.toast === 'function' ? o.toast : (msg, type) => ownToast(msg, type);
		const S = {
			status: null,
			convs: [],
			cur: null,              // conversation id, 'inbox' or null
			view: null,             // messages view of the current chat
			q: '',
			people: null,
			reply: null,
			edit: null,
			rec: null,
			infoOpen: false,
			unreadFrom: new Map(),
			inbox: { items: [], unread: 0 },
			media: new Map(),       // mediaId → Promise<objectURL|null>
			avatars: new Map(),     // url → Promise<objectURL|null>
			local: new Map(),       // clientId → objectURL (pending pictures, video / file previews)
			localVideo: new Map(),  // clientId → objectURL of a video just sent from here
			mediaFilter: 'image',   // chat info: 'image' | 'video' | 'file'
			shown: false,
			loadingOlder: false,
			menu: null,
			search: null,
			inboxFrom: null,        // first unread inbox entry when the inbox chat was opened
		};
		const ctx = () => ({ t, locale: o.getLocale(), me: S.status && S.status.me, people: S.people });
		const conv = (id) => S.convs.find((c) => c.id === id) || null;
		const curConv = () => (typeof S.cur === 'number' ? conv(S.cur) : null);

		// ── Skeleton ─────────────────────────────────────────
		const refs = {};
		const rootEl = el('div', { class: 'cv', 'data-info': '0', 'data-pane': 'list' });
		o.root.appendChild(rootEl);

		refs.list = el('aside', { class: 'cv-list', 'aria-label': t('chat.title') });
		refs.count = el('span', { class: 'cv-count' });
		refs.q = el('input', { class: 'inp cv-q', type: 'search', placeholder: t('chat.searchChats'), 'aria-label': t('chat.searchChats'), spellcheck: 'false' });
		refs.banner = el('div', { class: 'cv-banner', role: 'status', hidden: true });
		refs.rows = el('div', { class: 'cv-rows scroll', role: 'list' });
		refs.listEmpty = el('div', { class: 'cv-empty', hidden: true });
		refs.h = el('h1', { class: 'cv-h', text: t('chat.title') });
		refs.prefsBtn = iconBtn('gear', t('chat.prefsOpen'), () => prefsDialog(), 'cv-ib-flat');
		refs.newBtn = el('button', { type: 'button', class: 'cv-ib cv-ib-pri', 'aria-label': t('chat.newChat'), title: t('chat.newChat'), on: { click: () => newChatDialog() } }, [icon('pen', 16, '2.4')]);
		refs.list.append(
			el('div', { class: 'cv-list-head' }, [
				el('div', { class: 'cv-list-title' }, [refs.h, refs.count, el('span', { class: 'cv-grow' }), refs.prefsBtn, refs.newBtn]),
				el('label', { class: 'cv-search' }, [icon('search', 15), refs.q]),
				refs.banner,
			]),
			refs.rows,
			refs.listEmpty,
		);

		refs.chat = el('section', { class: 'cv-chat', 'aria-live': 'off' });
		refs.pickTitle = el('strong', { text: t('chat.pickTitle') });
		refs.pickText = el('span', { text: t('chat.pickText') });
		refs.pick = el('div', { class: 'cv-pick' }, [icon('pen', 34, '1.6'), refs.pickTitle, refs.pickText]);
		refs.head = el('header', { class: 'cv-head', hidden: true });
		refs.searchBar = el('div', { class: 'cv-searchbar', hidden: true });
		refs.msgs = el('div', { class: 'cv-msgs scroll', role: 'log', 'aria-live': 'polite', tabindex: '-1' });
		refs.toLatest = el('button', { type: 'button', class: 'cv-tolatest', hidden: true, 'aria-label': t('chat.toLatest'), title: t('chat.toLatest'), on: { click: () => scrollBottom(true) } }, [icon('down', 18)]);
		refs.composer = el('div', { class: 'cv-composer', hidden: true });
		refs.drop = el('div', { class: 'cv-drop', hidden: true }, [icon('attach', 28, '1.8'), el('span', { text: t('chat.dropNow') })]);
		refs.file = el('input', { type: 'file', multiple: true, hidden: true, tabindex: '-1' });
		refs.avatarFile = el('input', { type: 'file', accept: 'image/png,image/jpeg,image/webp', hidden: true, tabindex: '-1' });
		refs.chat.append(refs.pick, refs.head, refs.searchBar, refs.msgs, refs.toLatest, refs.composer, refs.drop, refs.file, refs.avatarFile);

		refs.info = el('aside', { class: 'cv-info scroll', hidden: true, 'aria-label': t('chat.info.title') });
		refs.state = el('div', { class: 'cv-state', hidden: true });
		refs.hint = el('div', { class: 'cv-hint', role: 'status', hidden: true });
		rootEl.append(refs.list, refs.chat, refs.info, refs.state, refs.hint);

		// ── Avatars and media ────────────────────────────────

		function blobUrl(res) {
			if (!res || !res.ok || !res.data) return null;
			try { return URL.createObjectURL(new Blob([res.data], { type: res.mime || 'application/octet-stream' })); } catch (_) { return null; }
		}
		function mediaUrl(mediaId) {
			if (!mediaId) return Promise.resolve(null);
			if (!S.media.has(mediaId)) S.media.set(mediaId, api.media(mediaId).then(blobUrl).catch(() => null));
			return S.media.get(mediaId);
		}
		function avatarUrl(url) {
			if (!url) return Promise.resolve(null);
			if (!S.avatars.has(url)) S.avatars.set(url, api.avatar(url).then(blobUrl).catch(() => null));
			return S.avatars.get(url);
		}
		/** a: CS.avatarOf / personAvatar result */
		function avatar(a, size) {
			const box = el('span', { class: `cv-av${a.kind === 'icon' ? ` cv-av-icon cv-av-${a.icon}` : ''}`, 'aria-hidden': 'true', style: `width:${size}px;height:${size}px;font-size:${Math.max(10, Math.round(size * 0.34))}px` });
			if (a.kind === 'icon') box.appendChild(icon(a.icon === 'system' ? 'shield' : a.icon === 'gone' ? 'lock' : 'group', Math.round(size * 0.46)));
			else { box.style.setProperty('--c', a.color); box.appendChild(el('span', { text: a.initials || '?' })); }
			const load = a.kind === 'person' && a.avatarUrl ? avatarUrl(a.avatarUrl) : (a.mediaId ? mediaUrl(a.mediaId) : null);
			if (load) {
				load.then((u) => {
					if (!u) return;
					const img = el('img', { class: 'cv-av-img', src: u, alt: '', draggable: 'false' });
					box.appendChild(img);
					box.classList.add('has-img');
				});
			}
			return box;
		}

		// ── State / availability ─────────────────────────────

		async function loadStatus() {
			try { S.status = await api.status(); } catch (_) { S.status = null; }
			applyStatus();
		}

		function applyStatus() {
			const st = S.status || { state: 'unknown' };
			if (typeof o.onStatus === 'function') o.onStatus(st);
			const available = st.state === 'available';
			refs.list.hidden = !available;
			refs.chat.hidden = !available;
			if (!available) refs.info.hidden = true;
			refs.state.hidden = available;
			if (!available) renderState(st);
			renderBanner();
			renderHint();
			if (typeof o.onUnread === 'function') o.onUnread(available ? (st.unread || 0) : 0);
		}

		/**
		 * The server has chat functions this version does not know: a small
		 * banner on top, never blocking; closed → hidden for this set of features.
		 */
		function renderHint() {
			const h = CS.updateHint(S.status);
			clear(refs.hint);
			refs.hint.hidden = !h;
			if (!h) return;
			refs.hint.append(...[
				icon('info', 16),
				el('span', { class: 'cv-hint-tx', text: t('chat.updateHint.text') }),
				typeof o.checkUpdate === 'function' ? el('button', { type: 'button', class: 'btn btn-sec btn-sm cv-hint-check', text: t('chat.updateHint.check'), on: { click: () => o.checkUpdate() } }) : null,
				iconBtn('close', t('chat.updateHint.dismiss'), () => {
					refs.hint.hidden = true;
					if (S.status) S.status.updateHint = null;
					if (typeof api.dismissUpdateHint === 'function') api.dismissUpdateHint().catch(() => {});
				}, 'cv-ib-flat cv-ib-sm cv-hint-close'),
			].filter(Boolean));
		}

		function renderState(st) {
			clear(refs.state);
			if (st.state === 'checking' || st.state === 'unknown') {
				refs.state.append(el('strong', { text: t('chat.loading') }));
				return;
			}
			const err = st.state === 'error';
			refs.state.append(
				icon(err ? 'alert' : 'lock', 34, '1.6'),
				el('strong', { text: err ? t('chat.loadFailed') : t('chat.unavailable.title') }),
				el('span', { text: err ? CS.errorText(st.reason, t) : CS.unavailableText(st, t) }),
				el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('chat.retry'), on: { click: () => { api.check().then((s) => { S.status = s; applyStatus(); refreshList(); }); } } }),
			);
		}

		function renderBanner() {
			const st = S.status || {};
			let text = null;
			if (st.state === 'available' && st.stale) text = t('chat.offline');
			else if (st.state === 'available' && !st.live) text = t('chat.polling');
			refs.banner.hidden = !text;
			refs.banner.textContent = text || '';
			refs.banner.classList.toggle('is-warn', !!(st.stale));
		}

		// ── Chat list ────────────────────────────────────────

		let listTimer = null;
		function refreshListSoon() {
			clearTimeout(listTimer);
			listTimer = setTimeout(refreshList, 40);
		}
		async function refreshList({ server = false } = {}) {
			const r = await api.conversations(server ? { refresh: true } : undefined).catch(() => null);
			if (!r || r.ok === false) return;
			const before = curConv();
			const ticks = (c) => (c ? `${c.readUpTo}|${c.deliveredUpTo}` : '');
			S.convs = Array.isArray(r.conversations) ? r.conversations : [];
			if (typeof S.cur === 'number' && !conv(S.cur)) closeChat();
			renderList();
			if (typeof S.cur === 'number') {
				renderHead();
				renderComposer(false);
				if (S.infoOpen) renderInfo();
				// Read / delivered marks of the others changed → the ticks.
				if (S.view && ticks(before) !== ticks(curConv())) renderMessages('keep');
			}
		}

		function renderList() {
			const c = ctx();
			const list = CS.filterConversations(S.convs, S.q, c);
			clear(refs.rows);
			if (o.notify && !S.q) refs.rows.appendChild(inboxRowEl());
			for (const cv of list) refs.rows.appendChild(rowEl(cv, c));
			const unread = S.convs.reduce((n, x) => n + (x.muted ? 0 : (x.unread || 0)), 0);
			refs.count.textContent = unread > 0 ? String(unread) : '';
			refs.count.hidden = unread <= 0;
			refs.listEmpty.hidden = list.length > 0;
			refs.listEmpty.textContent = S.q ? t('chat.noMatch') : t('chat.noChats');
		}

		function inboxRowEl() {
			const r = CS.inboxRow(S.inbox, ctx());
			const on = S.cur === 'inbox';
			return el('button', { type: 'button', class: `cv-row is-pinned${on ? ' is-on' : ''}${r.unread ? ' is-unread' : ''}`, role: 'listitem', 'aria-current': on ? 'true' : 'false', on: { click: () => openInboxChat() } }, [
				avatar({ kind: 'icon', icon: 'system' }, 42),
				el('span', { class: 'cv-row-tx' }, [
					el('span', { class: 'cv-row-top' }, [el('b', { class: 'cv-row-name', text: r.title }), el('span', { class: 'cv-row-pin' }, [icon('pin', 12)]), el('span', { class: 'cv-row-time', text: r.time })]),
					el('span', { class: 'cv-row-bottom' }, [el('span', { class: 'cv-row-pv', text: r.text }), r.unread ? el('span', { class: 'cv-badge', text: String(r.unread) }) : null]),
				]),
			]);
		}

		function rowEl(c, cx) {
			const pv = CS.preview(c, cx);
			const on = S.cur === c.id;
			const time = CS.listTime(c.lastMessage ? c.lastMessage.createdAt : (c.updatedAt || c.createdAt), cx);
			const name = CS.title(c, t);
			const b = el('button', { type: 'button', class: `cv-row${on ? ' is-on' : ''}${c.unread ? ' is-unread' : ''}`, role: 'listitem', 'aria-current': on ? 'true' : 'false', 'data-id': String(c.id), on: { click: () => openChat(c.id) } }, [
				avatar(CS.avatarOf(c), 42),
				el('span', { class: 'cv-row-tx' }, [
					el('span', { class: 'cv-row-top' }, [
						el('b', { class: 'cv-row-name', text: name }),
						c.muted ? el('span', { class: 'cv-row-muted', title: t('chat.mute.always') }, [icon('bellOff', 12)]) : null,
						el('span', { class: 'cv-row-time', text: time }),
					]),
					el('span', { class: 'cv-row-bottom' }, [
						el('span', { class: `cv-row-pv${pv.typing ? ' is-typing' : ''}`, text: pv.text }),
						c.outbox ? el('span', { class: 'cv-row-out', title: t('chat.outbox.waiting') }, [icon('clock', 12)]) : null,
						c.unread ? el('span', { class: `cv-badge${c.muted ? ' is-muted' : ''}`, text: String(c.unread) }) : null,
					]),
				]),
			]);
			b.setAttribute('aria-label', `${name}${c.unread ? `, ${c.unread}` : ''}: ${pv.text}`);
			return b;
		}

		// ── Open / close ─────────────────────────────────────

		function reportOpen() {
			const visible = S.shown && document.visibilityState === 'visible' && document.hasFocus();
			api.open(typeof S.cur === 'number' ? S.cur : null, visible).catch(() => {});
			if (S.cur === 'inbox' && visible) markInboxSeen();
		}

		async function openChat(id) {
			const c = conv(id);
			if (!c) {
				// From a toast before the list knew it.
				const r = await api.conversation(id).catch(() => null);
				if (!r || !r.conversation) return;
				await refreshList();
			}
			const cc = conv(id);
			if (!cc) return;
			if (S.cur === 'inbox') stopInboxObs();
			if (S.cur !== id) {
				stopRec(false);
				S.reply = null;
				S.edit = null;
				closeSearch();
				S.view = null;
				S.unreadFrom.set(id, cc.unread > 0 && cc.me ? cc.me.lastReadId || 0 : null);
			}
			S.cur = id;
			rootEl.setAttribute('data-pane', 'chat');
			refs.pick.hidden = true;
			refs.head.hidden = false;
			renderList();
			renderHead();
			renderComposer(true);
			renderInfo();
			const cached = await api.messages(id, { cached: true }).catch(() => null);
			if (S.cur === id && cached && cached.ok !== false && (cached.messages.length || cached.pending.length)) { S.view = cached; renderMessages('bottom'); }
			reportOpen();
			const fresh = await api.messages(id).catch(() => null);
			if (S.cur !== id) return;
			if (fresh && fresh.ok !== false) {
				const first = !S.view;
				S.view = fresh;
				renderMessages(first ? 'bottom' : 'keep');
			} else if (!S.view) {
				clear(refs.msgs).appendChild(el('div', { class: 'cv-empty', text: CS.errorText(fresh, t) }));
			}
			if (refs.input && document.activeElement !== refs.q) refs.input.focus();
		}

		function closeChat() {
			stopRec(false);
			stopInboxObs();
			S.cur = null;
			S.view = null;
			S.infoOpen = false;
			rootEl.setAttribute('data-pane', 'list');
			refs.pick.hidden = false;
			refs.head.hidden = true;
			refs.composer.hidden = true;
			refs.toLatest.hidden = true;
			closeSearch();
			clear(refs.msgs);
			renderInfo();
			renderList();
			reportOpen();
		}

		// ── Pinned "GateControl" (notification inbox) ────────
		// Entries are marked read one by one once they have been in view while
		// the window is shown (notify.read(ids) → core ack of their seqs with
		// state "read"), not all at once when the chat is opened.

		let inboxObs = null;
		const inboxInView = new Set();   // unread entries in view right now
		const inboxSeenQ = new Set();    // seen, waiting for the next read call
		const inboxSent = new Map();     // id → time read was asked (no second call)
		let inboxReadTimer = null;

		async function loadInbox() {
			if (!o.notify) return;
			const r = await o.notify.list({ limit: 100 }).catch(() => null);
			if (!r) return;
			S.inbox = { items: Array.isArray(r.items) ? r.items : [], unread: Number(r.unread) || 0 };
			// A read that did not arrive may be asked again after a while.
			const now = Date.now();
			for (const e of S.inbox.items) if (e.state === 'delivered' && inboxSent.has(e.id) && now - inboxSent.get(e.id) > 10000) inboxSent.delete(e.id);
			renderList();
			if (S.cur === 'inbox') renderInbox('keep');
		}

		function openInboxChat() {
			stopRec(false);
			S.cur = 'inbox';
			S.view = null;
			S.infoOpen = false;
			S.inboxFrom = CS.inboxFirstUnread(S.inbox);
			closeSearch();
			rootEl.setAttribute('data-pane', 'chat');
			refs.pick.hidden = true;
			refs.head.hidden = false;
			refs.composer.hidden = true;
			renderInfo();
			renderList();
			renderInbox('open');
			reportOpen();
		}

		function inboxShown() {
			return S.cur === 'inbox' && S.shown && document.visibilityState === 'visible' && document.hasFocus();
		}

		/** The entries in view count as seen (only while the window is shown). */
		function markInboxSeen() {
			if (!o.notify || !inboxShown()) return;
			for (const id of inboxInView) if (!inboxSent.has(id)) inboxSeenQ.add(id);
			if (!inboxSeenQ.size) return;
			clearTimeout(inboxReadTimer);
			inboxReadTimer = setTimeout(flushInboxRead, 250);
		}

		function flushInboxRead() {
			const ids = [...inboxSeenQ].filter((id) => !inboxSent.has(id));
			inboxSeenQ.clear();
			if (!ids.length || !o.notify) return;
			const now = Date.now();
			for (const id of ids) {
				inboxSent.set(id, now);
				const b = refs.msgs.querySelector(`[data-nid="${id}"]`);
				if (b) b.classList.remove('is-unread');
			}
			o.notify.read(ids).catch(() => {});
		}

		function stopInboxObs() {
			if (inboxObs) inboxObs.disconnect();
			inboxObs = null;
			inboxInView.clear();
		}

		function onInboxIntersect(entries) {
			const viewPx = refs.msgs.clientHeight;
			for (const en of entries) {
				const id = Number(en.target.getAttribute('data-nid'));
				if (en.isIntersecting && CS.inboxSeen(en.intersectionRatio, en.intersectionRect.height, viewPx)) inboxInView.add(id);
				else inboxInView.delete(id);
			}
			markInboxSeen();
		}

		/** mode: 'open' (first unread entry, else the newest) | 'keep' (stay at the bottom, else keep the position) */
		function renderInbox(mode = 'keep') {
			const unread = Number(S.inbox.unread) || 0;
			clear(refs.head).append(...[
				iconBtn('back', t('chat.common.back'), () => closeChat(), 'cv-ib-flat cv-only-narrow'),
				avatar({ kind: 'icon', icon: 'system' }, 38),
				el('span', { class: 'cv-head-tx' }, [el('b', { text: t('chat.inbox.title') }), el('span', { class: 'cv-head-sub', text: t('chat.inbox.sub') })]),
				el('span', { class: 'cv-grow' }),
				unread > 0 && o.notify ? el('button', { type: 'button', class: 'btn btn-ghost btn-sm cv-inbox-readall', text: t('chat.inbox.readAll'), on: { click: () => { o.notify.read('all').catch(() => {}).then(() => loadInbox()); } } }) : null,
				o.openInbox ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => o.openInbox(null) } }, [icon('external', 14), t('chat.inbox.openAll')]) : null,
			].filter(Boolean));
			const wasBottom = atBottom();
			const prevTop = refs.msgs.scrollTop;
			if (inboxObs) inboxObs.disconnect();
			inboxInView.clear();
			clear(refs.msgs);
			const items = CS.inboxTimeline(S.inbox);
			if (!items.length) { refs.msgs.appendChild(el('div', { class: 'cv-empty', text: t('chat.inbox.empty') })); return; }
			inboxObs = typeof IntersectionObserver === 'function'
				? new IntersectionObserver(onInboxIntersect, { root: refs.msgs, threshold: [0, 0.25, 0.5, 0.6, 0.75, 1] })
				: null;
			const c = ctx();
			let lastDay = null;
			let anchor = null;
			for (const e of items) {
				const iso = e.created_at || e.received_at;
				const day = CS.dayLabel(iso, c);
				if (day !== lastDay) { refs.msgs.appendChild(el('div', { class: 'cv-day' }, [el('span', { text: day })])); lastDay = day; }
				if (S.inboxFrom !== null && e.id === S.inboxFrom) {
					anchor = el('div', { class: 'cv-unread-line' }, [el('span', { text: t('chat.unreadLine') })]);
					refs.msgs.appendChild(anchor);
				}
				const isUnread = e.state === 'delivered' && !inboxSent.has(e.id);
				const bubble = el('div', { class: `cv-bub cv-in cv-sysbub${isUnread ? ' is-unread' : ''}`, 'data-nid': String(e.id) }, [
					el('b', { class: 'cv-sys-title', text: e.title || '—' }),
					e.body ? el('div', { class: 'cv-text', text: e.body }) : null,
				]);
				const actions = Array.isArray(e.actions) ? e.actions : [];
				if (actions.length) {
					bubble.appendChild(el('div', { class: 'cv-sys-actions' }, actions.map((a) => el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: a.label, on: { click: async () => {
						const r = await o.notify.action(e.id, a.id).catch((err) => ({ ok: false, error: err && err.message }));
						if (r && r.ok === false) toast(CS.errorText(r, t), 'error');
						loadInbox();
					} } }))));
				}
				bubble.appendChild(el('div', { class: 'cv-meta' }, [el('span', { text: CS.hm(iso, c.locale) })]));
				refs.msgs.appendChild(bubble);
				if (isUnread) {
					if (inboxObs) inboxObs.observe(bubble);
					else inboxInView.add(e.id); // no observer: everything shown counts as seen
				}
			}
			if (mode === 'open') {
				if (anchor) refs.msgs.scrollTop += anchor.getBoundingClientRect().top - refs.msgs.getBoundingClientRect().top - 8;
				else scrollBottom(false);
			} else if (wasBottom) scrollBottom(false);
			else refs.msgs.scrollTop = prevTop;
			if (!inboxObs) markInboxSeen();
		}

		// ── Header ───────────────────────────────────────────

		function renderHead() {
			const c = curConv();
			if (!c) return;
			const cx = ctx();
			const sub = CS.headSub(c, cx);
			clear(refs.head).append(
				iconBtn('back', t('chat.common.back'), () => closeChat(), 'cv-ib-flat cv-only-narrow'),
				el('button', { type: 'button', class: 'cv-head-who', 'aria-label': t('chat.info.open'), on: { click: () => toggleInfo() } }, [
					avatar(CS.avatarOf(c), 38),
					el('span', { class: 'cv-head-tx' }, [el('b', { text: CS.title(c, t) }), el('span', { class: `cv-head-sub${sub.typing ? ' is-typing' : ''}`, text: sub.text })]),
				]),
				el('span', { class: 'cv-grow' }),
				iconBtn('search', t('chat.search.inChat'), () => toggleSearch(), 'cv-ib-flat'),
				iconBtn('info', t('chat.info.open'), () => toggleInfo(), `cv-ib-flat${S.infoOpen ? ' is-on' : ''}`),
			);
		}

		// ── Messages ─────────────────────────────────────────

		function atBottom() {
			return refs.msgs.scrollHeight - refs.msgs.scrollTop - refs.msgs.clientHeight < 80;
		}
		function scrollEnd(smooth) {
			refs.msgs.scrollTo({ top: refs.msgs.scrollHeight, behavior: smooth ? 'smooth' : 'auto' });
			refs.toLatest.hidden = !(S.view && S.view.detached);
		}
		/** To the newest message — out of a jump window first (reload the newest page). */
		function scrollBottom(smooth) {
			if (S.view && S.view.detached) { goLatest(); return; }
			scrollEnd(smooth);
		}
		async function goLatest() {
			const id = S.cur;
			if (typeof id !== 'number') return;
			const r = await api.messages(id).catch(() => null);
			if (S.cur !== id || !r || r.ok === false) return;
			S.view = r;
			renderMessages('bottom');
		}

		/** mode: 'bottom' | 'keep' (stay at the bottom, else keep the position) | 'prepend' | 'stay' (keep the position) */
		function renderMessages(mode = 'keep') {
			const c = curConv();
			const v = S.view;
			if (!c || !v) return;
			// A jump window does not follow new messages: no auto-scroll to its end.
			if (v.detached && mode === 'keep') mode = 'stay';
			const wasBottom = atBottom();
			const prevHeight = refs.msgs.scrollHeight;
			const prevTop = refs.msgs.scrollTop;
			const cx = ctx();
			clear(refs.msgs);
			if (v.hasMore && v.messages.length) {
				refs.msgs.appendChild(el('button', { type: 'button', class: 'cv-older btn btn-ghost btn-sm', text: t('chat.loadOlder'), on: { click: () => loadOlder() } }));
			}
			if (!v.messages.length && !v.pending.length) {
				refs.msgs.appendChild(el('div', { class: 'cv-empty', text: t('chat.empty') }));
			}
			const items = CS.timeline(v.messages, v.pending, c, cx, { unreadFrom: S.unreadFrom.has(c.id) ? S.unreadFrom.get(c.id) : null });
			for (const it of items) {
				if (it.type === 'day') refs.msgs.appendChild(el('div', { class: 'cv-day' }, [el('span', { text: it.label })]));
				else if (it.type === 'unread') refs.msgs.appendChild(el('div', { class: 'cv-unread-line' }, [el('span', { text: t('chat.unreadLine') })]));
				else refs.msgs.appendChild(it.m.kind === 'system' ? systemEl(it.m, c, cx) : bubbleEl(it, c, cx));
			}
			if (v.detached && v.hasMoreAfter) {
				refs.msgs.appendChild(el('button', { type: 'button', class: 'cv-newer btn btn-ghost btn-sm', text: t('chat.toLatest'), on: { click: () => goLatest() } }));
			}
			if (v.offline) refs.msgs.appendChild(el('div', { class: 'cv-note', text: t('chat.offline') }));
			if (v.detached) refs.toLatest.hidden = false;
			if (mode === 'bottom' || (mode === 'keep' && wasBottom)) scrollEnd(false);
			else if (mode === 'prepend') refs.msgs.scrollTop = refs.msgs.scrollHeight - prevHeight + prevTop;
			else refs.msgs.scrollTop = prevTop;
		}

		function systemEl(m, c, cx) {
			return el('div', { class: 'cv-sys', 'data-id': String(m.id) }, [el('span', { text: CS.systemText(m, c, cx) })]);
		}

		function ticks(status) {
			if (!status) return null;
			const map = { pending: 'clock', failed: 'alert', sent: 'check', delivered: 'checks', read: 'checks' };
			const s = el('span', { class: `cv-tick is-${status}`, title: t(`chat.status.${status}`), 'aria-label': t(`chat.status.${status}`) }, [icon(map[status], 14, '2.2')]);
			return s;
		}

		function quoteEl(q, c, cx) {
			if (!q) return null;
			const name = q.missing ? '' : CS.nameOf(c, q.senderId, cx);
			const text = q.missing ? t('chat.msg.quoteMissing') : (q.deleted ? t('chat.msg.deleted') : (q.text || t(`chat.kind.${q.kind || 'text'}`)));
			return el('button', { type: 'button', class: 'cv-quote', on: { click: (e) => { e.stopPropagation(); if (q.id && !q.missing) jumpTo(q.id); } } }, [
				name ? el('b', { text: name }) : null,
				el('span', { text }),
			]);
		}

		function bubbleEl(it, c, cx) {
			const m = it.m;
			const mine = !!m.mine;
			const wrap = el('div', { class: `cv-msg${mine ? ' is-out' : ' is-in'}${it.cont ? ' is-cont' : ''}`, 'data-id': m.id ? String(m.id) : '', 'data-client': m.clientId || '' });
			if (!mine && c.kind === 'group' && !it.cont) {
				const p = CS.member(c, m.senderId);
				wrap.appendChild(el('span', { class: 'cv-msg-av' }, [avatar(p && !p.gone ? CS.personAvatar(p) : { kind: 'icon', icon: m.senderId === null ? 'system' : 'gone' }, 28)]));
			} else if (!mine && c.kind === 'group') {
				wrap.appendChild(el('span', { class: 'cv-msg-av' }));
			}
			const b = el('div', { class: `cv-bub${mine ? ' cv-out' : ' cv-in'}${m.deleted ? ' is-deleted' : ''}${m.pending ? ' is-pending' : ''}${m.failed ? ' is-failed' : ''}` });
			if (!mine && c.kind === 'group' && !it.cont) {
				const p = CS.member(c, m.senderId);
				const name = el('b', { class: 'cv-sender', text: CS.nameOf(c, m.senderId, cx) });
				if (p && p.colorHex) name.style.color = p.colorHex;
				b.appendChild(name);
			}
			if (m.deleted) {
				b.appendChild(el('div', { class: 'cv-text cv-dim', text: mine ? t('chat.msg.deletedMine') : t('chat.msg.deleted') }));
			} else {
				if (m.replyTo) b.appendChild(quoteEl(m.replyTo, c, cx));
				if (m.kind === 'image') b.appendChild(imageEl(m));
				else if (m.kind === 'voice') b.appendChild(voiceEl(m));
				else if (m.kind === 'file') b.appendChild(CS.videoInfo(m) ? videoEl(m, cx) : fileEl(m, cx));
				else if (m.kind === 'location') b.appendChild(locationEl(m));
				if (m.undecryptable) b.appendChild(el('div', { class: 'cv-text cv-dim', text: t('chat.msg.undecryptable') }));
				else if (m.text && m.kind !== 'location') b.appendChild(el('div', { class: 'cv-text', text: m.text }));
			}
			const meta = el('div', { class: 'cv-meta' }, [
				m.expiresAt ? el('span', { class: 'cv-exp', title: t('chat.msg.expires', { time: CS.when(m.expiresAt, cx.locale) }) }, [icon('timer', 11)]) : null,
				m.editedAt && !m.deleted ? el('span', { text: t('chat.msg.edited') }) : null,
				el('span', { text: CS.hm(m.createdAt, cx.locale) }),
				mine ? ticks(it.status) : null,
			]);
			b.appendChild(meta);
			if (m.pending && m.failed) {
				b.appendChild(el('div', { class: 'cv-failed' }, [
					el('span', { text: t('chat.outbox.failed', { error: CS.errorText(m.error, t) }) }),
					el('button', { type: 'button', class: 'btn btn-sec btn-xs', on: { click: () => api.retry(m.clientId) } }, [icon('retry', 13), t('chat.outbox.retry')]),
					el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('chat.outbox.discard'), on: { click: () => { for (const map of [S.local, S.localVideo]) { const u = map.get(m.clientId); if (u) { URL.revokeObjectURL(u); map.delete(m.clientId); } } api.discard(m.clientId); } } }),
				]));
			} else if (m.pending && m.error) {
				b.appendChild(el('div', { class: 'cv-waiting', text: t('chat.outbox.waiting') }));
			}
			if (!m.deleted && Array.isArray(m.reactions) && m.reactions.length) b.appendChild(reactionsEl(m, c, cx));
			const body = el('div', { class: 'cv-msg-body' }, [b]);
			if (!m.pending) {
				const acts = CS.messageActions(m, c, cx);
				const tools = el('div', { class: 'cv-tools' }, [
					acts.reply ? iconBtn('reply', t('chat.msg.reply'), (e) => { e.stopPropagation(); startReply(m); }, 'cv-ib-sm') : null,
					iconBtn('more', t('chat.msg.more'), (e) => { e.stopPropagation(); openMenu(m, wrap, e.currentTarget); }, 'cv-ib-sm'),
				]);
				body.appendChild(tools);
				b.addEventListener('contextmenu', (e) => { e.preventDefault(); openMenu(m, wrap, b); });
				b.addEventListener('dblclick', (e) => { if (acts.reply && !(e.target.closest && e.target.closest('button,audio,a'))) startReply(m); });
			}
			wrap.appendChild(body);
			return wrap;
		}

		function imageEl(m) {
			const size = CS.bubbleSize(m.meta);
			const box = el('button', { type: 'button', class: 'cv-img', style: `width:${size.w}px;aspect-ratio:${size.w} / ${size.h}`, 'aria-label': t('chat.msg.openImage') });
			// The picture just sent from here: no need to download it again.
			const local = m.clientId ? S.local.get(m.clientId) || null : null;
			const show = (u) => { if (!u) { box.classList.add('is-missing'); box.appendChild(icon('image', 28, '1.6')); return; } box.appendChild(el('img', { src: u, alt: '', draggable: 'false' })); };
			if (local) show(local);
			else if (m.media) (m.media.thumbId ? mediaUrl(m.media.thumbId).then((u) => u || mediaUrl(m.media.id)) : mediaUrl(m.media.id)).then(show);
			else show(null);
			box.addEventListener('click', (e) => { e.stopPropagation(); if (m.media && m.media.id) lightbox(m); else if (local) lightboxUrl(local); });
			return box;
		}

		function lightbox(m) {
			mediaUrl(m.media.id).then((u) => { if (u) lightboxUrl(u, m); else toast(t('chat.msg.mediaUnavailable'), 'error'); });
		}
		function lightboxUrl(u, m) {
			const ov = el('div', { class: 'cv-overlay cv-lightbox', role: 'dialog', 'aria-modal': 'true', 'aria-label': t('chat.msg.openImage') });
			const close = () => { ov.remove(); document.removeEventListener('keydown', onKey, true); };
			const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); close(); } };
			ov.append(
				el('div', { class: 'cv-lightbox-bar' }, [
					m && m.media ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => saveMedia(m) } }, [icon('down', 14), t('chat.msg.saveAs')]) : null,
					iconBtn('close', t('chat.common.close'), close),
				]),
				el('img', { src: u, alt: '' }),
			);
			ov.addEventListener('click', (e) => { if (e.target === ov) close(); });
			document.addEventListener('keydown', onKey, true);
			rootEl.appendChild(ov);
		}

		function voiceEl(m) {
			const dur = (m.meta && m.meta.durationMs) || 0;
			const wf = m.meta && Array.isArray(m.meta.waveform) && m.meta.waveform.length ? m.meta.waveform : new Array(32).fill(40);
			const btn = el('button', { type: 'button', class: 'cv-play', 'aria-label': t('chat.msg.play') }, [icon('play', 14)]);
			const wave = el('div', { class: 'cv-wave', 'aria-hidden': 'true' }, wf.map((v) => el('i', { style: `height:${Math.max(3, Math.round((v / 255) * 26))}px` })));
			const time = el('span', { class: 'cv-voice-time', text: CS.duration(dur) });
			let audio = null;
			const paint = () => {
				const k = audio && audio.duration ? audio.currentTime / audio.duration : 0;
				const on = Math.round(k * wave.children.length);
				Array.prototype.forEach.call(wave.children, (bar, i) => bar.classList.toggle('is-on', i < on));
				time.textContent = CS.duration(audio && audio.currentTime ? audio.currentTime * 1000 : dur);
			};
			const setIcon = (playing) => { clear(btn).appendChild(icon(playing ? 'pause' : 'play', 14)); btn.setAttribute('aria-label', playing ? t('chat.msg.pause') : t('chat.msg.play')); };
			const ensure = async () => {
				if (audio) return audio;
				const u = (m.clientId && S.local.get(m.clientId)) || (m.media ? await mediaUrl(m.media.id) : null);
				if (!u) { toast(t('chat.msg.mediaUnavailable'), 'error'); return null; }
				audio = new Audio(u);
				audio.addEventListener('timeupdate', paint);
				audio.addEventListener('ended', () => { setIcon(false); audio.currentTime = 0; paint(); });
				audio.addEventListener('pause', () => setIcon(false));
				audio.addEventListener('play', () => setIcon(true));
				audio.addEventListener('error', () => { toast(t('chat.msg.mediaUnavailable'), 'error'); setIcon(false); });
				return audio;
			};
			btn.addEventListener('click', async (e) => {
				e.stopPropagation();
				const a = await ensure();
				if (!a) return;
				if (a.paused) a.play().catch(() => toast(t('chat.msg.mediaUnavailable'), 'error')); else a.pause();
			});
			wave.addEventListener('click', async (e) => {
				const a = await ensure();
				if (!a || !a.duration) return;
				const r = wave.getBoundingClientRect();
				a.currentTime = Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)) * a.duration;
				paint();
			});
			return el('div', { class: 'cv-voice' }, [btn, wave, time]);
		}

		/** Preview picture of a file / video message: the one sent from here, else media.thumbId. */
		function previewUrl(m) {
			const local = m.clientId ? S.local.get(m.clientId) || null : null;
			if (local) return Promise.resolve(local);
			return m.media && m.media.thumbId ? mediaUrl(m.media.thumbId) : Promise.resolve(null);
		}

		function fileEl(m, cx) {
			const card = fileCard(m, cx);
			if (!(m.media && m.media.thumbId) && !(m.clientId && S.local.has(m.clientId))) return card;
			// Messenger 1.3.0: a preview of the file (e.g. the first page) above the card.
			const thumb = el('button', { type: 'button', class: 'cv-file-thumb', 'aria-label': t('chat.msg.open'), hidden: true, on: { click: (e) => { e.stopPropagation(); if (!m.pending && m.media) openMedia(m); } } });
			previewUrl(m).then((u) => { if (u) { thumb.appendChild(el('img', { src: u, alt: '', draggable: 'false' })); thumb.hidden = false; } });
			return el('div', { class: 'cv-file-wrap' }, [thumb, card]);
		}

		/** Video bubble: preview with play button and length; plays in an overlay. */
		function videoEl(m, cx) {
			const v = CS.videoInfo(m) || {};
			const size = CS.bubbleSize({ w: v.width, h: v.height });
			const box = el('button', { type: 'button', class: 'cv-video', style: `width:${size.w}px;aspect-ratio:${size.w} / ${size.h}`, 'aria-label': t('chat.msg.openVideo'), title: t('chat.msg.openVideo') });
			previewUrl(m).then((u) => {
				if (u) box.insertBefore(el('img', { src: u, alt: '', draggable: 'false' }), box.firstChild);
				else box.classList.add('is-missing');
			});
			box.append(...[
				el('span', { class: 'cv-video-play', 'aria-hidden': 'true' }, [icon('play', 22)]),
				v.durationMs ? el('span', { class: 'cv-video-dur' }, [icon('video', 12), CS.duration(v.durationMs)]) : null,
			].filter(Boolean));
			box.addEventListener('click', (e) => { e.stopPropagation(); playVideo(m); });
			const name = (m.meta && m.meta.fileName) || t('chat.kind.video');
			return el('div', { class: 'cv-video-wrap' }, [
				box,
				el('div', { class: 'cv-file-sub cv-video-sub' }, [
					el('span', { class: 'cv-video-name', text: name, title: name }),
					el('span', { text: m.media ? CS.bytes(m.media.bytes, cx.locale) : '' }),
					!m.pending && m.media ? el('button', { type: 'button', class: 'cv-link', text: t('chat.msg.saveAs'), on: { click: (e) => { e.stopPropagation(); saveMedia(m); } } }) : null,
				]),
			]);
		}

		async function playVideo(m) {
			const local = m.clientId ? S.localVideo.get(m.clientId) || null : null;
			const u = local || (m.media && m.media.id ? await mediaUrl(m.media.id) : null);
			if (!u) { toast(t('chat.msg.mediaUnavailable'), 'error'); return; }
			const ov = el('div', { class: 'cv-overlay cv-lightbox cv-player', role: 'dialog', 'aria-modal': 'true', 'aria-label': t('chat.msg.openVideo') });
			const video = el('video', { src: u, controls: true, autoplay: true, playsinline: true, preload: 'auto' });
			const close = () => { try { video.pause(); } catch (_) { /* gone */ } ov.remove(); document.removeEventListener('keydown', onKey, true); };
			const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); close(); } };
			video.addEventListener('error', () => toast(t('chat.msg.videoUnsupported'), 'warning'));
			ov.append(
				el('div', { class: 'cv-lightbox-bar' }, [
					m.media && m.media.id && !m.pending ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => saveMedia(m) } }, [icon('down', 14), t('chat.msg.saveAs')]) : null,
					iconBtn('close', t('chat.common.close'), close),
				]),
				video,
			);
			ov.addEventListener('click', (e) => { if (e.target === ov) close(); });
			document.addEventListener('keydown', onKey, true);
			rootEl.appendChild(ov);
		}

		function fileCard(m, cx) {
			const name = (m.meta && m.meta.fileName) || t('chat.kind.file');
			const mime = m.media && m.media.mime;
			return el('div', { class: 'cv-file' }, [
				el('span', { class: 'cv-file-badge', text: CS.fileBadge(name, mime) }),
				el('span', { class: 'cv-file-tx' }, [
					el('b', { text: name }),
					el('span', { class: 'cv-file-sub' }, [
						el('span', { text: m.media ? CS.bytes(m.media.bytes, cx.locale) : '' }),
						!m.pending && m.media ? el('button', { type: 'button', class: 'cv-link', text: t('chat.msg.open'), on: { click: (e) => { e.stopPropagation(); openMedia(m); } } }) : null,
						!m.pending && m.media ? el('button', { type: 'button', class: 'cv-link', text: t('chat.msg.saveAs'), on: { click: (e) => { e.stopPropagation(); saveMedia(m); } } }) : null,
					]),
				]),
			]);
		}

		function locationEl(m) {
			const loc = m.location;
			const url = CS.mapUrl(loc);
			const label = (loc && loc.label) || t('chat.kind.location');
			const open = (e) => { e.stopPropagation(); if (url && root.gatecontrol && root.gatecontrol.shell) root.gatecontrol.shell.openExternal(url); };
			let preview = null;
			if (url && typeof api.mapTile === 'function') {
				const mv = mapView({ lat: loc.lat, lon: loc.lon, zoom: 15, width: 260, height: 140 });
				mv.marker(loc.lat, loc.lon, loc.accuracy);
				preview = el('button', { type: 'button', class: 'cv-loc-map', 'aria-label': t('chat.msg.mapOpen'), title: t('chat.msg.mapOpen'), on: { click: open } }, [mv.el]);
			}
			const sub = [CS.coordText(loc), loc && Number.isFinite(loc.accuracy) ? t('chat.loc.accuracyShort', { m: Math.round(loc.accuracy) }) : null].filter(Boolean).join(' · ');
			return el('div', { class: 'cv-loc' }, [
				preview,
				el('div', { class: 'cv-loc-row' }, [
					icon('pin', 18),
					el('span', { class: 'cv-loc-tx' }, [
						el('b', { text: label }),
						sub ? el('span', { class: 'cv-loc-sub', text: sub }) : null,
						url ? el('button', { type: 'button', class: 'cv-link', text: t('chat.msg.mapOpen'), on: { click: open } }) : null,
					]),
				]),
			]);
		}

		// ── Map (OpenStreetMap tiles from the main process) ──

		const tileCache = new Map(); // 'z/x/y' → Promise<objectURL|null> (insertion order = LRU)
		const TILE_CACHE_MAX = 384;

		function tileUrl(z, x, y) {
			const key = `${z}/${x}/${y}`;
			let p = tileCache.get(key);
			if (p) { tileCache.delete(key); tileCache.set(key, p); return p; }
			p = api.mapTile(z, x, y)
				.then((r) => (r && r.ok !== false && r.data ? URL.createObjectURL(new Blob([r.data], { type: r.mime || 'image/png' })) : null))
				.catch(() => null);
			tileCache.set(key, p);
			// A tile that failed is asked again next time.
			p.then((u) => { if (!u && tileCache.get(key) === p) tileCache.delete(key); });
			while (tileCache.size > TILE_CACHE_MAX) {
				const [k, old] = tileCache.entries().next().value;
				tileCache.delete(k);
				old.then((u) => { if (u) setTimeout(() => URL.revokeObjectURL(u), 5000); });
			}
			return p;
		}

		/**
		 * Slippy map with a pin and an optional accuracy circle.
		 * mo: { lat, lon, zoom, height, width?, interactive?, onPick?(lat, lon), label? }
		 * → { el, center(lat, lon, zoom?), marker(lat, lon, accuracy?) (null = none) }
		 * Interactive: drag to move, wheel / buttons / +/- to zoom, click or
		 * Enter to pick (the centre with the keyboard), arrow keys to move.
		 */
		function mapView(mo) {
			let z = CS.clampZoom(mo.zoom);
			let c = CS.worldPx(mo.lat, mo.lon, z);
			let mark = null;
			const imgs = new Map(); // tile key → <img>
			const layer = el('div', { class: 'cv-map-tiles' });
			const acc = el('div', { class: 'cv-map-acc', hidden: true });
			const pin = el('div', { class: 'cv-map-pin', hidden: true }, [icon('pin', 30, '2')]);
			const box = el('div', { class: `cv-map${mo.interactive ? ' is-live' : ''}`, style: `${mo.width ? `width:${mo.width}px;` : ''}height:${mo.height}px` }, [layer, acc, pin]);
			const size = () => ({ w: box.clientWidth || mo.width || 0, h: box.clientHeight || mo.height || 0 });
			let raf = 0;
			const schedule = () => { if (!raf) raf = requestAnimationFrame(draw); };
			const resetTiles = () => { for (const img of imgs.values()) img.remove(); imgs.clear(); };
			const clampY = () => { const n = CS.TILE * 2 ** z; c = { x: c.x, y: Math.max(0, Math.min(n, c.y)) }; };

			function draw() {
				raf = 0;
				const { w, h } = size();
				if (!w || !h) return;
				const want = new Set();
				for (const tl of CS.tileGrid(c.x, c.y, z, w, h)) {
					want.add(tl.key);
					let img = imgs.get(tl.key);
					if (!img) {
						img = el('img', { class: 'cv-map-tile', alt: '', draggable: 'false' });
						imgs.set(tl.key, img);
						layer.appendChild(img);
						const mine = img;
						tileUrl(tl.z, tl.x, tl.y).then((u) => { if (u && imgs.get(tl.key) === mine) mine.src = u; });
					}
					img.style.transform = `translate(${tl.left}px, ${tl.top}px)`;
				}
				for (const [k, img] of imgs) if (!want.has(k)) { img.remove(); imgs.delete(k); }
				if (mark) {
					const p = CS.worldPx(mark.lat, mark.lon, z);
					const x = Math.round(p.x - c.x + w / 2);
					const y = Math.round(p.y - c.y + h / 2);
					pin.hidden = false;
					pin.style.transform = `translate(${x}px, ${y}px)`;
					const r = mark.accuracy ? mark.accuracy / CS.metersPerPx(mark.lat, z) : 0;
					acc.hidden = !(r >= 6);
					if (!acc.hidden) {
						acc.style.width = `${Math.round(r * 2)}px`;
						acc.style.height = `${Math.round(r * 2)}px`;
						acc.style.transform = `translate(${Math.round(x - r)}px, ${Math.round(y - r)}px)`;
					}
				} else {
					pin.hidden = true;
					acc.hidden = true;
				}
			}

			function zoomAt(dz, px, py) {
				const nz = CS.clampZoom(z + dz);
				if (nz === z) return;
				const { w, h } = size();
				const ox = px === undefined ? 0 : px - w / 2;
				const oy = py === undefined ? 0 : py - h / 2;
				const k = 2 ** (nz - z);
				c = { x: (c.x + ox) * k - ox, y: (c.y + oy) * k - oy };
				z = nz;
				clampY();
				resetTiles();
				schedule();
			}

			const pickAt = (px, py) => {
				if (!mo.onPick) return;
				const { w, h } = size();
				const p = CS.lonLat(c.x - w / 2 + px, c.y - h / 2 + py, z);
				mo.onPick(p.lat, p.lon);
			};

			if (mo.interactive) {
				box.setAttribute('tabindex', '0');
				box.setAttribute('role', 'application');
				box.setAttribute('aria-label', mo.label || t('chat.loc.map'));
				box.appendChild(el('div', { class: 'cv-map-zoom' }, [
					iconBtn('plus', t('chat.loc.zoomIn'), (e) => { e.stopPropagation(); zoomAt(1); }, 'cv-ib-sm'),
					iconBtn('minus', t('chat.loc.zoomOut'), (e) => { e.stopPropagation(); zoomAt(-1); }, 'cv-ib-sm'),
				]));
				let drag = null;
				box.addEventListener('pointerdown', (e) => {
					if (e.button !== 0 || (e.target.closest && e.target.closest('button'))) return;
					drag = { id: e.pointerId, x: e.clientX, y: e.clientY, moved: false };
					try { box.setPointerCapture(e.pointerId); } catch { /* pointer gone */ }
				});
				box.addEventListener('pointermove', (e) => {
					if (!drag || e.pointerId !== drag.id) return;
					const dx = e.clientX - drag.x;
					const dy = e.clientY - drag.y;
					if (!drag.moved && Math.abs(dx) + Math.abs(dy) < 5) return;
					drag.moved = true;
					box.classList.add('is-drag');
					c = { x: c.x - dx, y: c.y - dy };
					clampY();
					drag.x = e.clientX;
					drag.y = e.clientY;
					schedule();
				});
				const end = (e) => {
					if (!drag || e.pointerId !== drag.id) return;
					const click = !drag.moved && e.type === 'pointerup';
					drag = null;
					box.classList.remove('is-drag');
					if (click) { const r = box.getBoundingClientRect(); pickAt(e.clientX - r.left, e.clientY - r.top); }
				};
				box.addEventListener('pointerup', end);
				box.addEventListener('pointercancel', end);
				box.addEventListener('wheel', (e) => {
					e.preventDefault();
					const r = box.getBoundingClientRect();
					zoomAt(e.deltaY < 0 ? 1 : -1, e.clientX - r.left, e.clientY - r.top);
				}, { passive: false });
				box.addEventListener('keydown', (e) => {
					if (e.target !== box) return;
					const step = 96;
					const moves = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] };
					if (moves[e.key]) { e.preventDefault(); c = { x: c.x + moves[e.key][0], y: c.y + moves[e.key][1] }; clampY(); schedule(); }
					else if (e.key === '+' || e.key === '=') { e.preventDefault(); zoomAt(1); }
					else if (e.key === '-') { e.preventDefault(); zoomAt(-1); }
					else if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); const { w, h } = size(); pickAt(w / 2, h / 2); }
				});
			}
			box.appendChild(el('span', { class: 'cv-map-attr', text: t('chat.loc.attribution') }));
			if (typeof ResizeObserver === 'function') new ResizeObserver(() => schedule()).observe(box);
			schedule();

			return {
				el: box,
				center(lat, lon, zoom) {
					if (zoom !== undefined && CS.clampZoom(zoom) !== z) { z = CS.clampZoom(zoom); resetTiles(); }
					c = CS.worldPx(lat, lon, z);
					schedule();
				},
				marker(lat, lon, accuracy) {
					mark = lat === null || lat === undefined ? null : { lat, lon, accuracy: Number.isFinite(accuracy) ? accuracy : null };
					schedule();
				},
			};
		}

		// ── "Standort senden" ────────────────────────────────

		const DEFAULT_VIEW = { lat: 51.1657, lon: 10.4515, zoom: 5 };
		const VIEW_KEY = 'gc.chat.locView';

		/** Where the dialog opens: around the last sent location (~1 km), else Germany. */
		function lastView() {
			try {
				const v = JSON.parse(root.localStorage.getItem(VIEW_KEY) || 'null');
				if (v && Number.isFinite(v.lat) && Number.isFinite(v.lon)) return { lat: v.lat, lon: v.lon, zoom: CS.clampZoom(v.zoom) };
			} catch { /* storage unavailable */ }
			return DEFAULT_VIEW;
		}
		function saveView(loc) {
			try { root.localStorage.setItem(VIEW_KEY, JSON.stringify({ lat: Math.round(loc.lat * 100) / 100, lon: Math.round(loc.lon * 100) / 100, zoom: 12 })); } catch { /* storage unavailable */ }
		}

		function locationDialog() {
			const c = curConv();
			if (!c || CS.composerBlock(c)) return;
			const lang = o.getLocale() === 'en' ? 'en' : 'de';
			const st = { open: true, point: null, accuracy: null, manual: false, autoLabel: '', revSeq: 0, revTimer: null };
			const status = el('p', { class: 'cv-loc-status', role: 'status', text: t('chat.loc.hint') });
			const setStatus = (text, type = 'info') => { status.textContent = text; status.setAttribute('data-type', type); };
			const label = el('input', { class: 'inp', maxlength: '200', placeholder: t('chat.loc.labelPh'), 'aria-label': t('chat.loc.label') });
			const q = el('input', { class: 'inp cv-q', type: 'search', placeholder: t('chat.loc.searchPh'), 'aria-label': t('chat.loc.search'), spellcheck: 'false' });
			const results = el('div', { class: 'cv-loc-results', role: 'list', hidden: true });
			const map = mapView({ ...lastView(), height: 300, interactive: true, onPick: (lat, lon) => setPoint({ lat, lon }, null, 'map') });
			const mineBtn = el('button', { type: 'button', class: 'btn btn-sec btn-sm cv-loc-mine', on: { click: () => locate() } }, [icon('target', 14), t('chat.loc.mine')]);

			const setLabel = (v) => {
				if (!v) return;
				if (!label.value.trim() || label.value === st.autoLabel) { label.value = v; st.autoLabel = v; }
			};

			function setPoint(p, accuracy, source, text) {
				st.point = { lat: p.lat, lon: p.lon };
				st.accuracy = Number.isFinite(accuracy) ? accuracy : null;
				if (source !== 'gps') st.manual = true;
				map.marker(p.lat, p.lon, st.accuracy);
				if (source !== 'gps') setStatus(`${t('chat.loc.picked')}: ${CS.coordText(p)}`);
				if (source === 'search') { st.revSeq++; setLabel(text); return; }
				// Address of the point (core: Nominatim, one request per second).
				const seq = ++st.revSeq;
				clearTimeout(st.revTimer);
				st.revTimer = setTimeout(() => {
					api.mapReverse(p.lat, p.lon, lang)
						.then((r) => { if (st.open && seq === st.revSeq && r && r.ok !== false && r.label) setLabel(r.label); })
						.catch(() => {});
				}, source === 'gps' ? 0 : 600);
			}

			function locate() {
				const geo = root.navigator && root.navigator.geolocation;
				if (!geo) { setStatus(t('chat.loc.unavailable'), 'warn'); return; }
				st.manual = false;
				mineBtn.disabled = true;
				setStatus(t('chat.loc.locating'));
				geo.getCurrentPosition((pos) => {
					mineBtn.disabled = false;
					if (!st.open) return;
					const a = Number.isFinite(pos.coords.accuracy) ? pos.coords.accuracy : null;
					const msg = a !== null ? t('chat.loc.accuracy', { m: Math.round(a) }) : t('chat.loc.picked');
					// A point picked meanwhile stays.
					if (st.manual) return;
					const p = { lat: pos.coords.latitude, lon: pos.coords.longitude };
					map.center(p.lat, p.lon, CS.zoomForAccuracy(a));
					setPoint(p, a, 'gps');
					setStatus(msg, 'ok');
				}, (err) => {
					mineBtn.disabled = false;
					if (!st.open || st.manual) return;
					setStatus(t(`chat.loc.${CS.geoError(err)}`), 'warn');
				}, { enableHighAccuracy: true, timeout: 15000, maximumAge: 60000 });
			}

			async function search() {
				const text = q.value.trim();
				if (text.length < 2) return;
				clear(results).hidden = false;
				results.appendChild(el('div', { class: 'cv-loc-note', text: t('chat.loc.searching') }));
				const r = await api.mapSearch(text, lang).catch(() => null);
				if (!st.open) return;
				clear(results);
				if (!r || r.ok === false) { results.appendChild(el('div', { class: 'cv-loc-note', text: t('chat.loc.searchFailed') })); return; }
				if (!r.results.length) { results.appendChild(el('div', { class: 'cv-loc-note', text: t('chat.loc.noResults') })); return; }
				for (const hit of r.results) {
					results.appendChild(el('button', { type: 'button', class: 'cv-loc-hit', role: 'listitem', on: { click: () => {
						results.hidden = true;
						map.center(hit.lat, hit.lon, 17);
						setPoint(hit, null, 'search', hit.label);
					} } }, [icon('pin', 14), el('span', { text: hit.label })]));
				}
			}
			q.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); search(); } });

			const body = el('div', { class: 'cv-loc-dlg' }, [
				el('div', { class: 'cv-loc-tools' }, [
					el('label', { class: 'cv-search cv-loc-q' }, [icon('search', 15), q]),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('chat.loc.searchBtn'), on: { click: () => search() } }),
					mineBtn,
				]),
				results,
				map.el,
				status,
				el('label', { class: 'cv-field' }, [el('span', { text: t('chat.loc.label') }), label]),
				el('p', { class: 'cv-loc-src', text: t('chat.loc.source') }),
			]);

			dialog(t('chat.loc.title'), body, [
				{ label: t('chat.common.cancel'), value: null },
				{ label: t('chat.loc.send'), primary: true, onClick: async () => {
					const loc = CS.locationBody(st.point, label.value, st.accuracy);
					if (!loc) { setStatus(t('chat.loc.needPoint'), 'warn'); return false; }
					const req = { conversationId: c.id, kind: 'location', location: loc };
					if (S.reply) req.replyTo = S.reply.id;
					const r = await api.send(req).catch((e) => ({ ok: false, error: e && e.message }));
					if (r && r.ok === false) { setStatus(CS.errorText(r, t), 'warn'); return false; }
					saveView(loc);
					if (S.reply) { S.reply = null; renderComposer(false); }
					scrollBottom(true);
					return true;
				} },
			], { wide: true, onOpen: () => locate() }).then(() => { st.open = false; clearTimeout(st.revTimer); });
		}

		async function openMedia(m) {
			const r = await api.openMedia(m.media.id, (m.meta && m.meta.fileName) || null).catch((e) => ({ ok: false, error: e && e.message }));
			if (r && r.ok) return;
			if (r && r.code === 'unsafe') toast(t('chat.msg.unsafe'), 'warning');
			else toast(CS.errorText(r, t), 'error');
		}
		async function saveMedia(m) {
			const r = await api.saveMedia(m.media.id, (m.meta && m.meta.fileName) || null).catch((e) => ({ ok: false, error: e && e.message }));
			if (r && r.ok) toast(t('chat.msg.saved', { path: r.path }), 'success');
			else if (!(r && r.cancelled)) toast(CS.errorText(r, t), 'error');
		}

		function reactionsEl(m, c, cx) {
			const meId = cx.me && cx.me.user ? cx.me.user.id : null;
			return el('div', { class: 'cv-reacts' }, m.reactions.map((r) => {
				const mineR = Array.isArray(r.userIds) && r.userIds.includes(meId);
				return el('button', {
					type: 'button', class: `cv-react${mineR ? ' is-mine' : ''}`,
					title: (r.userIds || []).map((u) => CS.nameOf(c, u, cx)).join(', '),
					on: { click: (e) => { e.stopPropagation(); react(m, mineR ? null : r.emoji); } },
				}, [r.emoji, r.count > 1 ? el('small', { text: String(r.count) }) : null]);
			}));
		}

		async function loadOlder() {
			const c = curConv();
			const v = S.view;
			if (!c || !v || S.loadingOlder || !v.messages.length) return;
			S.loadingOlder = true;
			const r = await api.messages(c.id, { before: v.messages[0].id }).catch(() => null);
			S.loadingOlder = false;
			if (S.cur !== c.id || !r || r.ok === false) return;
			S.view = r;
			renderMessages('prepend');
		}

		/** The newer page of a jump window (it joins the newest messages at the end). */
		async function loadNewer() {
			const c = curConv();
			const v = S.view;
			if (!c || !v || !v.detached || !v.hasMoreAfter || S.loadingNewer || !v.messages.length) return;
			S.loadingNewer = true;
			const r = await api.messages(c.id, { after: v.messages[v.messages.length - 1].id }).catch(() => null);
			S.loadingNewer = false;
			if (S.cur !== c.id || !r || r.ok === false) return;
			S.view = r;
			renderMessages('stay');
		}

		async function jumpTo(id) {
			const find = () => refs.msgs.querySelector(`[data-id="${Number(id)}"]`);
			let node = find();
			const cid = S.cur;
			if (!node && typeof cid === 'number' && S.view) {
				// Messenger ≥ 1.1.0: the page around the message, however old it is.
				const r = await api.messages(cid, { around: Number(id) }).catch(() => null);
				if (S.cur !== cid) return;
				if (r && r.ok !== false) {
					S.view = r;
					renderMessages('stay');
					node = find();
				} else if (r && r.code === 'unsupported') {
					for (let i = 0; !node && i < 10 && S.view && S.view.hasMore; i++) {
						await loadOlder();
						node = find();
					}
				}
			}
			if (!node) { toast(t('chat.msg.quoteMissing'), 'info'); return; }
			node.scrollIntoView({ block: 'center', behavior: 'smooth' });
			node.classList.add('is-hl');
			setTimeout(() => node.classList.remove('is-hl'), 1800);
		}

		refs.msgs.addEventListener('scroll', () => {
			const detached = !!(S.view && S.view.detached);
			refs.toLatest.hidden = atBottom() && !detached;
			if (refs.msgs.scrollTop < 40 && S.view && S.view.hasMore) loadOlder();
			if (detached && S.view.hasMoreAfter && refs.msgs.scrollHeight - refs.msgs.scrollTop - refs.msgs.clientHeight < 40) loadNewer();
		});

		// ── Message menu ─────────────────────────────────────

		function closeMenu() {
			if (S.menu) { S.menu.remove(); S.menu = null; }
		}
		function openMenu(m, wrap, anchor) {
			closeMenu();
			const c = curConv();
			if (!c) return;
			const cx = ctx();
			const acts = CS.messageActions(m, c, cx);
			const meId = cx.me && cx.me.user ? cx.me.user.id : null;
			const mineR = (m.reactions || []).find((r) => Array.isArray(r.userIds) && r.userIds.includes(meId));
			const items = [];
			if (acts.react) {
				items.push(el('div', { class: 'cv-menu-emojis', role: 'group', 'aria-label': t('chat.msg.react') }, CS.EMOJIS.map((e) => el('button', {
					type: 'button', 'aria-pressed': mineR && mineR.emoji === e ? 'true' : 'false', 'aria-label': e, text: e,
					on: { click: () => { closeMenu(); react(m, mineR && mineR.emoji === e ? null : e); } },
				}))));
			}
			const item = (ic, label, fn, danger) => items.push(el('button', { type: 'button', role: 'menuitem', class: `cv-menu-item${danger ? ' is-danger' : ''}`, on: { click: () => { closeMenu(); fn(); } } }, [icon(ic, 15), label]));
			if (acts.reply) item('reply', t('chat.msg.reply'), () => startReply(m));
			if (acts.copy) item('copy', t('chat.msg.copy'), () => copyText(m.text));
			if (acts.edit) item('pen', t('chat.msg.edit'), () => startEdit(m));
			if (m.kind === 'file' && m.media) item('down', t('chat.msg.saveAs'), () => saveMedia(m));
			if (m.kind === 'image' && m.media) item('down', t('chat.msg.saveAs'), () => saveMedia(m));
			if (acts.deleteMe) item('trash', t('chat.msg.deleteMe'), () => removeMsg(m, 'me'), true);
			if (acts.deleteAll) item('trash', t('chat.msg.deleteAll'), () => removeMsg(m, 'all'), true);
			const menu = el('div', { class: 'cv-menu', role: 'menu' }, items);
			const layer = el('div', { class: 'cv-menu-layer', on: { click: (e) => { if (e.target === layer) closeMenu(); }, contextmenu: (e) => { e.preventDefault(); closeMenu(); } } }, [menu]);
			rootEl.appendChild(layer);
			S.menu = layer;
			const r = (anchor || wrap).getBoundingClientRect();
			const mr = menu.getBoundingClientRect();
			const left = Math.max(8, Math.min(window.innerWidth - mr.width - 8, m.mine ? r.right - mr.width : r.left));
			const top = r.bottom + mr.height + 8 < window.innerHeight ? r.bottom + 4 : Math.max(8, r.top - mr.height - 4);
			menu.style.left = `${left}px`;
			menu.style.top = `${top}px`;
			const first = menu.querySelector('button');
			if (first) first.focus();
		}

		function copyText(text) {
			const done = () => toast(t('chat.msg.copied'), 'success');
			if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(String(text || '')).then(done).catch(() => {});
		}

		async function react(m, emoji) {
			const r = await api.react(m.id, emoji).catch((e) => ({ ok: false, error: e && e.message }));
			if (r && r.ok === false) toast(CS.errorText(r, t), 'error');
		}

		async function removeMsg(m, scope) {
			const ok = await confirmDialog(scope === 'all' ? t('chat.msg.deleteAllQ') : t('chat.msg.deleteMeQ'), t('chat.common.delete'), true);
			if (!ok) return;
			const r = await api.remove(m.id, scope).catch((e) => ({ ok: false, error: e && e.message }));
			if (r && r.ok === false) toast(CS.errorText(r, t), 'error');
		}

		function startReply(m) {
			S.reply = m;
			S.edit = null;
			renderComposer(false);
			if (refs.input) refs.input.focus();
		}
		function startEdit(m) {
			S.edit = m;
			S.reply = null;
			renderComposer(false);
			if (refs.input) {
				refs.input.value = m.text || '';
				grow();
				refs.input.focus();
				refs.input.setSelectionRange(refs.input.value.length, refs.input.value.length);
			}
		}

		// ── Composer ─────────────────────────────────────────

		function grow() {
			const i = refs.input;
			if (!i) return;
			i.style.height = 'auto';
			i.style.height = `${Math.min(180, Math.max(42, i.scrollHeight + 2))}px`;
		}

		function recordingSupported() {
			const types = S.status && S.status.me && S.status.me.limits ? S.status.me.limits.types : [];
			return !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia && root.MediaRecorder
				&& CS.recordingMime((m) => root.MediaRecorder.isTypeSupported(m), types));
		}

		/** keepText: rebuild without losing what is typed. */
		function renderComposer(reset) {
			const c = curConv();
			if (!c) { refs.composer.hidden = true; return; }
			refs.composer.hidden = false;
			const text = !reset && refs.input ? refs.input.value : '';
			clear(refs.composer);
			const block = CS.composerBlock(c);
			if (block) {
				refs.input = null;
				refs.composer.appendChild(el('div', { class: 'cv-blocked' }, [icon(block === 'readonly' ? 'shield' : 'lock', 15), el('span', { text: t(block === 'readonly' ? 'chat.readonly' : 'chat.peerGone') })]));
				return;
			}
			const cx = ctx();
			if (S.reply || S.edit) {
				const m = S.reply || S.edit;
				refs.composer.appendChild(el('div', { class: 'cv-replybar' }, [
					icon(S.edit ? 'pen' : 'reply', 15),
					el('span', { class: 'cv-replybar-tx' }, [
						el('b', { text: S.edit ? t('chat.msg.editing') : t('chat.msg.replyTo', { name: CS.nameOf(c, m.senderId, cx) }) }),
						el('span', { text: CS.summary(m, c, cx) }),
					]),
					iconBtn('close', t('chat.common.cancel'), () => { const wasEdit = !!S.edit; S.reply = null; S.edit = null; renderComposer(false); if (wasEdit && refs.input) { refs.input.value = ''; grow(); } }, 'cv-ib-flat'),
				]));
			}
			if (S.rec) {
				S.rec.timeEl = el('span', { class: 'cv-rec-time', text: CS.duration(Date.now() - S.rec.started) });
				refs.composer.appendChild(el('div', { class: 'cv-row-compose' }, [
					iconBtn('trash', t('chat.recCancel'), () => stopRec(false)),
					el('div', { class: 'cv-rec' }, [el('span', { class: 'cv-rec-dot' }), el('span', { text: t('chat.recording') }), S.rec.timeEl]),
					el('button', { type: 'button', class: 'cv-ib cv-ib-pri', 'aria-label': t('chat.recSend'), title: t('chat.recSend'), on: { click: () => stopRec(true) } }, [icon('send', 16, '2.2')]),
				]));
				refs.input = null;
				return;
			}
			refs.input = el('textarea', { class: 'cv-input', rows: '1', placeholder: t('chat.placeholder'), 'aria-label': t('chat.placeholder'), maxlength: String((cx.me && cx.me.limits && cx.me.limits.textMax) || 4000) });
			refs.input.value = text;
			refs.input.addEventListener('input', () => { grow(); if (refs.input.value.trim() && !S.edit) api.typing(c.id).catch(() => {}); });
			refs.input.addEventListener('keydown', (e) => {
				if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); submit(); }
				else if (e.key === 'Escape' && (S.reply || S.edit)) { e.preventDefault(); const wasEdit = !!S.edit; S.reply = null; S.edit = null; renderComposer(false); if (wasEdit && refs.input) refs.input.value = ''; }
				else if (e.key === 'ArrowUp' && !refs.input.value && S.view) {
					const last = S.view.messages.slice().reverse().find((x) => x.mine && CS.messageActions(x, c, ctx()).edit);
					if (last) { e.preventDefault(); startEdit(last); }
				}
			});
			refs.input.addEventListener('paste', (e) => {
				const files = e.clipboardData && e.clipboardData.files ? Array.from(e.clipboardData.files) : [];
				if (files.length) { e.preventDefault(); files.forEach((f) => attach(f)); }
			});
			const features = (cx.me && cx.me.features) || {};
			refs.composer.appendChild(el('div', { class: 'cv-row-compose' }, [
				features.files !== false ? iconBtn('attach', t('chat.attach'), () => { refs.file.value = ''; refs.file.click(); }) : null,
				features.location !== false && typeof api.mapTile === 'function' ? iconBtn('pin', t('chat.loc.button'), () => locationDialog(), 'cv-loc-btn') : null,
				refs.input,
				features.voice !== false && recordingSupported() ? iconBtn('mic', t('chat.recStart'), () => startRec()) : null,
				el('button', { type: 'button', class: 'cv-ib cv-ib-pri', 'aria-label': t('chat.send'), title: t('chat.send'), on: { click: () => submit() } }, [icon('send', 16, '2.2')]),
			]));
			refs.composer.appendChild(el('div', { class: 'cv-compose-hint', text: `${t('chat.enterHint')} · ${t('chat.dropHint')}` }));
			grow();
		}

		async function submit() {
			const c = curConv();
			if (!c || !refs.input) return;
			const text = refs.input.value.trim();
			if (!text) return;
			if (S.edit) {
				const m = S.edit;
				const r = await api.edit(m.id, text).catch((e) => ({ ok: false, error: e && e.message }));
				if (r && r.ok === false) { toast(CS.errorText(r, t), 'error'); return; }
				S.edit = null;
				refs.input.value = '';
				renderComposer(false);
				return;
			}
			const req = { conversationId: c.id, kind: 'text', text };
			if (S.reply) req.replyTo = S.reply.id;
			refs.input.value = '';
			grow();
			S.reply = null;
			renderComposer(false);
			api.typing(c.id, true).catch(() => {});
			const r = await api.send(req).catch((e) => ({ ok: false, error: e && e.message }));
			if (r && r.ok === false) { toast(CS.errorText(r, t), 'error'); if (refs.input && !refs.input.value) refs.input.value = text; return; }
			scrollBottom(true);
		}

		// ── Attachments ──────────────────────────────────────

		const limits = () => (S.status && S.status.me && S.status.me.limits) || {};

		async function blobBytes(blob) {
			return new Uint8Array(await blob.arrayBuffer());
		}

		/** src: ImageBitmap / <img> / <video>; w, h: its pixel size (default src.width / src.height). */
		function canvasBlob(img, max, type, quality, w = img.width, h = img.height) {
			const size = CS.scaledSize(w, h, max);
			const cv = document.createElement('canvas');
			cv.width = size.w;
			cv.height = size.h;
			cv.getContext('2d').drawImage(img, 0, 0, size.w, size.h);
			return new Promise((resolve) => {
				cv.toBlob((b) => {
					if (b && b.type === type) resolve({ blob: b, w: size.w, h: size.h });
					else cv.toBlob((j) => resolve({ blob: j, w: size.w, h: size.h }), 'image/jpeg', quality);
				}, type, quality);
			});
		}

		/** Preview ≤ maxBytes from a picture source: WebP (JPEG without a WebP encoder), smaller until it fits. */
		async function smallPreview(src, w, h, maxBytes, maxSide) {
			for (const [side, q] of CS.thumbSteps(maxSide)) {
				const out = await canvasBlob(src, side, 'image/webp', q, w, h);
				if (out.blob && out.blob.size <= maxBytes) return out.blob;
			}
			return null;
		}

		/**
		 * A video (Blob of the bytes read from the picked file — never the
		 * file object or its name) → { video: { durationMs, width, height },
		 * blob } (frame at ~1 s as preview, null when it cannot be drawn) or null
		 * when the engine cannot read it (no codec): sent as a plain file then.
		 */
		function videoPreview(bytes, maxBytes, maxSide) {
			return new Promise((resolve) => {
				const url = URL.createObjectURL(bytes);
				const v = document.createElement('video');
				let done = false;
				let timer = null;
				const finish = (res) => {
					if (done) return;
					done = true;
					clearTimeout(timer);
					v.removeAttribute('src');
					try { v.load(); } catch (_) { /* detached */ }
					URL.revokeObjectURL(url);
					resolve(res);
				};
				timer = setTimeout(() => finish(null), 10000);
				const grab = async () => {
					const d = Number.isFinite(v.duration) ? v.duration : 0;
					const video = {};
					if (d > 0) video.durationMs = Math.round(d * 1000);
					if (v.videoWidth > 0 && v.videoHeight > 0) { video.width = v.videoWidth; video.height = v.videoHeight; }
					let blob = null;
					try { if (video.width) blob = await smallPreview(v, v.videoWidth, v.videoHeight, maxBytes, maxSide); } catch (_) { blob = null; }
					finish({ video, blob });
				};
				v.muted = true;
				v.preload = 'auto';
				v.playsInline = true;
				v.addEventListener('error', () => finish(null));
				v.addEventListener('loadedmetadata', () => {
					const at = CS.videoFrameTime(v.duration);
					if (at > 0) { v.addEventListener('seeked', grab, { once: true }); v.currentTime = at; }
					else if (v.readyState >= 2) grab();
					else v.addEventListener('loadeddata', grab, { once: true });
				}, { once: true });
				v.src = url;
			});
		}

		async function attach(file) {
			const c = curConv();
			if (!c || CS.composerBlock(c)) return;
			const lim = limits();
			const k = CS.attachKind(file, lim);
			if (!k.kind) { toast(CS.errorText(k.reason, t), 'error'); return; }
			const caption = refs.input && refs.input.value.trim() ? refs.input.value.trim() : null;
			const req = { conversationId: c.id };
			if (caption) req.text = caption;
			if (S.reply) req.replyTo = S.reply.id;
			try {
				if (k.kind === 'image') {
					const img = await createImageBitmap(file);
					const main = await canvasBlob(img, lim.imageMaxSide || 2048, 'image/webp', 0.82);
					const thumb = await canvasBlob(img, 320, 'image/webp', 0.6);
					if (img.close) img.close();
					if (!main.blob || (lim.maxBytes && main.blob.size > lim.maxBytes)) { toast(t('chat.error.too_large'), 'error'); return; }
					req.kind = 'image';
					req.meta = { w: main.w, h: main.h };
					req.file = { name: file.name || 'foto.webp', mime: main.blob.type, data: await blobBytes(main.blob) };
					if (thumb.blob && thumb.blob.size <= (lim.thumbMaxBytes || 65536)) req.thumb = { mime: thumb.blob.type, data: await blobBytes(thumb.blob) };
					const r = await api.send(req);
					if (r && r.ok === false) { toast(CS.errorText(r, t), 'error'); return; }
					if (r && r.message && r.message.clientId) S.local.set(r.message.clientId, URL.createObjectURL(main.blob));
				} else {
					req.kind = 'file';
					req.meta = { fileName: (file.name || t('chat.kind.file')).slice(0, 200) };
					req.file = { name: file.name || null, mime: file.type, data: await blobBytes(file) };
					// Messenger 1.3.0: length and size of a video, a frame as preview.
					const me = S.status && S.status.me;
					const wantMeta = CS.hasFeature(me, 'video_meta');
					const wantThumb = CS.hasFeature(me, 'file_thumbs');
					let thumbBlob = null;
					// The video as a Blob of its bytes (preview and local playback).
					const videoBlob = k.kind === 'video' ? new Blob([req.file.data]) : null;
					if (videoBlob && (wantMeta || wantThumb)) {
						const pv = await videoPreview(videoBlob, lim.thumbMaxBytes || 65536, lim.thumbMaxSide || 640);
						if (pv && wantMeta && Object.keys(pv.video).length) req.video = pv.video;
						if (pv && wantThumb && pv.blob) { thumbBlob = pv.blob; req.thumb = { mime: pv.blob.type, data: await blobBytes(pv.blob) }; }
					}
					const r = await api.send(req);
					if (r && r.ok === false) { toast(CS.errorText(r, t), 'error'); return; }
					const cid = r && r.message && r.message.clientId;
					if (cid && thumbBlob) S.local.set(cid, URL.createObjectURL(thumbBlob));
					if (cid && videoBlob) S.localVideo.set(cid, URL.createObjectURL(videoBlob));
				}
			} catch (err) {
				toast(CS.errorText(null, t), 'error');
				return;
			}
			if (caption && refs.input) { refs.input.value = ''; grow(); }
			if (S.reply) { S.reply = null; renderComposer(false); }
			scrollBottom(true);
		}

		refs.file.addEventListener('change', () => { Array.from(refs.file.files || []).forEach((f) => attach(f)); });

		let dragDepth = 0;
		const hasFiles = (e) => e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
		refs.chat.addEventListener('dragenter', (e) => {
			if (!hasFiles(e) || !curConv() || CS.composerBlock(curConv())) return;
			e.preventDefault();
			dragDepth++;
			refs.drop.hidden = false;
		});
		refs.chat.addEventListener('dragover', (e) => { if (hasFiles(e) && curConv()) { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; } });
		refs.chat.addEventListener('dragleave', () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) refs.drop.hidden = true; });
		refs.chat.addEventListener('drop', (e) => {
			if (!hasFiles(e)) return;
			e.preventDefault();
			dragDepth = 0;
			refs.drop.hidden = true;
			Array.from(e.dataTransfer.files || []).forEach((f) => attach(f));
		});

		// ── Voice recording (MediaRecorder) ──────────────────

		async function startRec() {
			const c = curConv();
			if (!c || S.rec) return;
			const lim = limits();
			const mime = CS.recordingMime((m) => root.MediaRecorder.isTypeSupported(m), lim.types);
			if (!mime) return;
			let stream;
			try {
				stream = await navigator.mediaDevices.getUserMedia({ audio: true });
			} catch (_) {
				toast(t('chat.micDenied'), 'error');
				return;
			}
			const rec = { stream, chunks: [], levels: [], started: Date.now(), mime, timer: null, analyser: null, ac: null, conversationId: c.id, replyTo: S.reply ? S.reply.id : null };
			try {
				rec.recorder = new root.MediaRecorder(stream, { mimeType: mime });
			} catch (_) {
				stream.getTracks().forEach((tr) => tr.stop());
				toast(t('chat.micDenied'), 'error');
				return;
			}
			rec.recorder.ondataavailable = (e) => { if (e.data && e.data.size) rec.chunks.push(e.data); };
			try {
				rec.ac = new AudioContext();
				const src = rec.ac.createMediaStreamSource(stream);
				rec.analyser = rec.ac.createAnalyser();
				rec.analyser.fftSize = 512;
				src.connect(rec.analyser);
			} catch (_) { rec.analyser = null; }
			const buf = rec.analyser ? new Uint8Array(rec.analyser.fftSize) : null;
			rec.timer = setInterval(() => {
				if (rec.analyser) {
					rec.analyser.getByteTimeDomainData(buf);
					let sum = 0;
					for (let i = 0; i < buf.length; i++) { const v = (buf[i] - 128) / 128; sum += v * v; }
					rec.levels.push(Math.min(255, Math.round(Math.sqrt(sum / buf.length) * 255 * 3)));
				}
				if (rec.timeEl) rec.timeEl.textContent = CS.duration(Date.now() - rec.started);
				if (Date.now() - rec.started >= (lim.maxVoiceS || 300) * 1000) stopRec(true);
			}, 100);
			rec.recorder.start(250);
			S.rec = rec;
			renderComposer(false);
		}

		function stopRec(send) {
			const rec = S.rec;
			if (!rec) return;
			S.rec = null;
			clearInterval(rec.timer);
			const durationMs = Date.now() - rec.started;
			rec.recorder.onstop = async () => {
				rec.stream.getTracks().forEach((tr) => tr.stop());
				if (rec.ac && rec.ac.close) rec.ac.close().catch(() => {});
				if (curConv()) renderComposer(false);
				if (!send) return;
				if (durationMs < 800) { toast(t('chat.recShort'), 'info'); return; }
				const type = rec.mime.split(';')[0];
				const blob = new Blob(rec.chunks, { type });
				const lim = limits();
				const req = {
					conversationId: rec.conversationId,
					kind: 'voice',
					meta: { durationMs: Math.min(durationMs, (lim.maxVoiceS || 300) * 1000) },
					file: { name: 'sprachnachricht', mime: type, data: await blobBytes(blob) },
				};
				const wf = CS.waveform(rec.levels, Math.min(48, Math.max(8, rec.levels.length)));
				if (wf.length) req.meta.waveform = wf;
				if (rec.replyTo) { req.replyTo = rec.replyTo; S.reply = null; }
				const r = await api.send(req).catch((e) => ({ ok: false, error: e && e.message }));
				if (r && r.ok === false) { toast(CS.errorText(r, t), 'error'); return; }
				if (r && r.message && r.message.clientId) S.local.set(r.message.clientId, URL.createObjectURL(blob));
				if (curConv()) renderComposer(false);
				scrollBottom(true);
			};
			try { rec.recorder.stop(); } catch (_) { rec.recorder.onstop(); }
		}

		// ── Search in a chat ─────────────────────────────────

		function closeSearch() {
			S.search = null;
			refs.searchBar.hidden = true;
			clear(refs.searchBar);
		}
		function toggleSearch() {
			if (S.search) { closeSearch(); return; }
			const c = curConv();
			if (!c) return;
			const input = el('input', { class: 'inp', type: 'search', placeholder: t('chat.search.placeholder'), 'aria-label': t('chat.search.inChat') });
			const results = el('div', { class: 'cv-results scroll', hidden: true });
			let timer = null;
			input.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => run(input.value), 300); });
			input.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.stopPropagation(); closeSearch(); } });
			async function run(q) {
				const s = q.trim();
				if (s.length < 2) { results.hidden = true; return; }
				const r = await api.search(c.id, s).catch(() => null);
				if (S.cur !== c.id || !S.search) return;
				clear(results);
				results.hidden = false;
				if (!r || r.ok === false) { results.appendChild(el('div', { class: 'cv-empty', text: CS.errorText(r, t) })); return; }
				if (!r.results.length) results.appendChild(el('div', { class: 'cv-empty', text: t('chat.search.none') }));
				const cx = ctx();
				for (const m of r.results) {
					results.appendChild(el('button', { type: 'button', class: 'cv-result', on: { click: () => { results.hidden = true; jumpTo(m.id); } } }, [
						el('span', { class: 'cv-result-top' }, [el('b', { text: CS.nameOf(c, m.senderId, cx) }), el('span', { text: CS.when(m.createdAt, cx.locale) })]),
						el('span', { class: 'cv-result-tx', text: CS.summary(m, c, cx) }),
					]));
				}
				if (r.truncated) results.appendChild(el('div', { class: 'cv-note', text: t('chat.search.truncated') }));
			}
			S.search = { input, results };
			clear(refs.searchBar).append(el('div', { class: 'cv-searchbar-row' }, [icon('search', 15), input, iconBtn('close', t('chat.common.close'), () => closeSearch(), 'cv-ib-flat')]), results);
			refs.searchBar.hidden = false;
			input.focus();
		}

		// ── Info pane ────────────────────────────────────────

		function toggleInfo() {
			S.infoOpen = !S.infoOpen;
			renderInfo();
			renderHead();
		}

		async function patchConv(c, patch, avatarFile) {
			const r = await api.update(c.id, patch, avatarFile).catch((e) => ({ ok: false, error: e && e.message }));
			if (r && r.ok === false) { toast(CS.errorText(r, t), 'error'); renderInfo(); return null; }
			await refreshList();
			return r;
		}

		function kv(label, ic, value) {
			return el('div', { class: 'cv-kv' }, [el('span', { class: 'cv-kv-l' }, [icon(ic, 15), label]), value]);
		}

		function renderInfo() {
			const c = curConv();
			const open = !!(c && S.infoOpen);
			refs.info.hidden = !open;
			rootEl.setAttribute('data-info', open ? '1' : '0');
			if (!open) return;
			const cx = ctx();
			clear(refs.info);
			refs.info.appendChild(el('div', { class: 'cv-info-head' }, [el('b', { text: t('chat.info.title') }), iconBtn('close', t('chat.common.close'), () => toggleInfo(), 'cv-ib-flat')]));
			const sub = c.kind === 'group'
				? (c.managedBy ? t('chat.info.managed', { plugin: pluginName(c.managedBy) }) : t('chat.membersN', { n: (c.members || []).length }))
				: (c.peer && c.peer.gone ? t('chat.peerGone') : t('chat.directSub'));
			const top = el('div', { class: 'cv-info-top' }, [avatar(CS.avatarOf(c), 76), el('b', { text: CS.title(c, t) }), el('span', { class: 'cv-dim', text: sub })]);
			if (c.can && c.can.editInfo) {
				top.appendChild(el('div', { class: 'cv-info-btns' }, [
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => renameDialog(c) } }, [icon('pen', 13), t('chat.info.rename')]),
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => pickAvatar(c) } }, [icon('image', 13), t('chat.info.picture')]),
					c.avatarMediaId ? el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('chat.info.removePicture'), on: { click: () => patchConv(c, { avatarMediaId: null }) } }) : null,
				]));
			}
			refs.info.appendChild(top);

			const sec = el('div', { class: 'cv-info-sec' }, [el('div', { class: 'cv-sec', text: t('chat.info.chat') })]);
			const mute = el('select', { class: 'inp cv-select', 'aria-label': t('chat.info.notifications') }, [
				el('option', { value: 'off', text: t('chat.mute.off') }),
				el('option', { value: '8h', text: t('chat.mute.8h') }),
				el('option', { value: '1w', text: t('chat.mute.1w') }),
				el('option', { value: 'always', text: t('chat.mute.always') }),
			]);
			const mv = CS.muteValue(c);
			if (mv === 'until') mute.insertBefore(el('option', { value: 'until', text: t('chat.mute.until', { time: CS.when(c.me.mutedUntil, cx.locale) }) }), mute.firstChild);
			mute.value = mv;
			mute.addEventListener('change', () => { const p = CS.mutePatch(mute.value); if (p) patchConv(c, p); });
			sec.appendChild(kv(t('chat.info.notifications'), c.muted ? 'bellOff' : 'bell', mute));
			if (!c.readonly) {
				const opts = (cx.me && cx.me.limits && cx.me.limits.disappearingS) || [0, 86400, 604800, 2592000];
				if (c.can && c.can.setDisappearing && (!cx.me || !cx.me.features || cx.me.features.disappearing !== false)) {
					const dis = el('select', { class: 'inp cv-select', 'aria-label': t('chat.info.disappearing') }, opts.map((s) => el('option', { value: String(s), text: CS.disLabel(s, t) })));
					dis.value = String(c.disappearingS || 0);
					dis.addEventListener('change', () => patchConv(c, { disappearingS: Number(dis.value) }));
					sec.appendChild(kv(t('chat.info.disappearing'), 'timer', dis));
				} else {
					sec.appendChild(kv(t('chat.info.disappearing'), 'timer', el('span', { class: 'cv-dim', text: c.disappearingS ? CS.disLabel(c.disappearingS, t) : t('chat.info.disappearingOff') })));
				}
			}
			const mediaCount = el('span', { class: 'cv-dim', text: '…' });
			sec.appendChild(kv(t('chat.info.media'), 'image', mediaCount));
			refs.info.appendChild(sec);

			const mediaSec = el('div', { class: 'cv-info-sec cv-media-sec', hidden: true }, [el('div', { class: 'cv-sec', text: t('chat.info.recentMedia') })]);
			refs.info.appendChild(mediaSec);
			mediaPane(c, cx, mediaSec, mediaCount);

			if (c.kind === 'group' && !c.readonly) {
				const ms = el('div', { class: 'cv-info-sec' }, [el('div', { class: 'cv-sec', text: `${t('chat.info.members')} · ${(c.members || []).length}` })]);
				if (c.can && c.can.manageMembers) ms.appendChild(el('button', { type: 'button', class: 'btn btn-sec btn-sm cv-add', on: { click: () => addMembersDialog(c) } }, [icon('plus', 13), t('chat.info.addMembers')]));
				const meId = cx.me && cx.me.user ? cx.me.user.id : null;
				for (const mb of c.members || []) {
					const me = mb.userId === meId;
					const row = el('div', { class: 'cv-member' }, [
						avatar(mb.gone ? { kind: 'icon', icon: 'gone' } : CS.personAvatar(mb), 34),
						el('span', { class: 'cv-member-tx' }, [el('b', { text: me ? t('chat.you') : (mb.name || t('chat.gone')) }), mb.role === 'admin' ? el('small', { text: t('chat.info.admin') }) : null]),
					]);
					if (c.can && c.can.manageMembers && !me) row.appendChild(iconBtn('more', t('chat.info.memberActions', { name: mb.name || '' }), () => memberDialog(c, mb), 'cv-ib-flat'));
					ms.appendChild(row);
				}
				if (c.managedBy) ms.appendChild(el('p', { class: 'cv-note', text: t('chat.info.managedHint', { plugin: pluginName(c.managedBy) }) }));
				refs.info.appendChild(ms);
			}
			const foot = el('div', { class: 'cv-info-sec' }, [el('p', { class: 'cv-note cv-note-lock' }, [icon('lock', 14), el('span', { text: t('chat.info.encrypted') })])]);
			if (c.can && c.can.leave) foot.appendChild(el('button', { type: 'button', class: 'btn btn-danger cv-danger btn-sm', text: t('chat.info.leave'), on: { click: () => leave(c) } }));
			refs.info.appendChild(foot);
		}

		/**
		 * "Zuletzt geteilt" with the filters Fotos / Videos / Dateien (Videos:
		 * kind=video of Messenger 1.3.0, shown when the server has it).
		 */
		function mediaPane(c, cx, sec, countEl) {
			let filters = CS.mediaFilters(cx.me, null);
			if (!filters.includes(S.mediaFilter)) S.mediaFilter = 'image';
			const tabs = el('div', { class: 'cv-tabs cv-media-tabs', role: 'group', 'aria-label': t('chat.info.recentMedia') });
			const body = el('div', { class: 'cv-media-body' });
			sec.append(tabs, body);
			const labels = { image: 'chat.info.filterImages', video: 'chat.info.filterVideos', file: 'chat.info.filterFiles' };
			let seq = 0;
			const drawTabs = () => {
				clear(tabs);
				for (const k of filters) {
					tabs.appendChild(el('button', { type: 'button', 'data-kind': k, 'aria-pressed': S.mediaFilter === k ? 'true' : 'false', text: t(labels[k]), on: { click: () => { if (S.mediaFilter === k) return; S.mediaFilter = k; drawTabs(); load(); } } }));
				}
			};
			async function load() {
				const mine = ++seq;
				const kind = S.mediaFilter;
				const r = await api.mediaList(c.id, { kind, limit: kind === 'file' ? 20 : 9 }).catch(() => null);
				if (mine !== seq || !sec.isConnected) return;
				if (!r || r.ok === false) { countEl.textContent = '–'; return; }
				const n = CS.mediaTotal(r.counts);
				countEl.textContent = String(n);
				sec.hidden = n <= 0;
				const next = CS.mediaFilters(cx.me, r.counts);
				if (next.length !== filters.length) { filters = next; drawTabs(); }
				clear(body);
				const items = r.items.filter((m) => m && m.media && (kind !== 'file' || !CS.videoInfo(m)));
				if (!items.length) { body.appendChild(el('p', { class: 'cv-dim cv-media-none', text: t('chat.info.noMedia') })); return; }
				if (kind === 'file') {
					const list = el('div', { class: 'cv-media-files' });
					for (const m of items) {
						const name = (m.meta && m.meta.fileName) || t('chat.kind.file');
						list.appendChild(el('button', { type: 'button', class: 'cv-media-file', title: name, on: { click: () => openMedia(m) } }, [
							el('span', { class: 'cv-file-badge', text: CS.fileBadge(name, m.media.mime) }),
							el('span', { class: 'cv-file-tx' }, [el('b', { text: name }), el('span', { class: 'cv-file-sub', text: `${CS.bytes(m.media.bytes, cx.locale)} · ${CS.when(m.createdAt, cx.locale)}` })]),
						]));
					}
					body.appendChild(list);
					return;
				}
				const grid = el('div', { class: 'cv-grid' });
				for (const m of items) {
					const video = kind === 'video' ? (CS.videoInfo(m) || {}) : null;
					const cell = el('button', { type: 'button', class: `cv-grid-cell${video ? ' is-video' : ''}`, 'aria-label': t(video ? 'chat.msg.openVideo' : 'chat.msg.openImage'), on: { click: () => (video ? playVideo(m) : lightbox(m)) } });
					const src = video ? m.media.thumbId : (m.media.thumbId || m.media.id);
					if (src) mediaUrl(src).then((u) => { if (u) cell.insertBefore(el('img', { src: u, alt: '' }), cell.firstChild); });
					if (video) {
						cell.appendChild(el('span', { class: 'cv-video-play is-small', 'aria-hidden': 'true' }, [icon('play', 14)]));
						if (video.durationMs) cell.appendChild(el('span', { class: 'cv-video-dur', text: CS.duration(video.durationMs) }));
					}
					grid.appendChild(cell);
				}
				body.appendChild(grid);
			}
			drawTabs();
			load();
		}

		const pluginName = (id) => (id === 'gatecontrol-familie' ? t('chat.info.pluginFamilie') : id);

		function pickAvatar(c) {
			refs.avatarFile.value = '';
			refs.avatarFile.onchange = async () => {
				const file = refs.avatarFile.files && refs.avatarFile.files[0];
				if (!file) return;
				try {
					const img = await createImageBitmap(file);
					const out = await canvasBlob(img, 512, 'image/webp', 0.85);
					await patchConv(c, {}, { mime: out.blob.type, data: await blobBytes(out.blob) });
				} catch (_) {
					toast(t('chat.error.media_invalid'), 'error');
				}
			};
			refs.avatarFile.click();
		}

		async function leave(c) {
			const meId = S.status && S.status.me && S.status.me.user ? S.status.me.user.id : null;
			if (!meId || !(await confirmDialog(t('chat.info.leaveQ'), t('chat.info.leave'), true))) return;
			const r = await patchConv(c, { remove: [meId] });
			if (r && r.left) closeChat();
		}

		// ── Dialogs ──────────────────────────────────────────

		function dialog(titleText, body, buttons = [], { onOpen, wide = false } = {}) {
			return new Promise((resolve) => {
				let ov = null;
				const done = (v) => { if (!ov || !ov.parentNode) return; ov.remove(); document.removeEventListener('keydown', onKey, true); resolve(v); };
				const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); done(null); } };
				const foot = buttons.length ? el('div', { class: 'cv-dlg-foot' }, buttons.map((b) => el('button', {
					type: 'button', class: `btn ${b.primary ? 'btn-pri' : b.danger ? 'btn-danger cv-danger' : 'btn-sec'}`, text: b.label,
					on: { click: async () => { if (b.onClick) { const r = await b.onClick(); if (r === false) return; done(b.value !== undefined ? b.value : r); } else done(b.value); } },
				}))) : null;
				ov = el('div', { class: 'cv-overlay', role: 'dialog', 'aria-modal': 'true', 'aria-label': titleText }, [
					el('div', { class: `cv-dlg card${wide ? ' is-wide' : ''}` }, [
						el('div', { class: 'cv-dlg-head' }, [el('b', { text: titleText }), iconBtn('close', t('chat.common.close'), () => done(null), 'cv-ib-flat')]),
						el('div', { class: 'cv-dlg-body' }, [body]),
						foot,
					]),
				]);
				ov.addEventListener('mousedown', (e) => { if (e.target === ov) done(null); });
				document.addEventListener('keydown', onKey, true);
				rootEl.appendChild(ov);
				const f = ov.querySelector('input:not([type=checkbox]),textarea,select');
				if (f) setTimeout(() => f.focus(), 30);
				if (onOpen) onOpen(done);
			});
		}

		function confirmDialog(message, okLabel, danger) {
			return dialog(t('chat.common.confirm'), el('p', { class: 'cv-dlg-msg', text: message }), [
				{ label: t('chat.common.cancel'), value: false },
				{ label: okLabel, primary: !danger, danger: !!danger, value: true },
			]).then((v) => v === true);
		}

		async function loadPeople() {
			if (S.people) return S.people;
			const r = await api.people().catch(() => null);
			S.people = r && r.ok !== false ? r.people : [];
			return S.people;
		}

		function personRow(p, { check = false, onClick = null } = {}) {
			const kids = [avatar(CS.personAvatar(p), 36), el('span', { class: 'cv-person-name', text: p.name || t('chat.gone') })];
			if (check) return el('label', { class: 'cv-person' }, [...kids, el('input', { type: 'checkbox', value: String(p.id), 'aria-label': p.name || '' })]);
			return el('button', { type: 'button', class: 'cv-person', on: { click: onClick } }, kids);
		}

		async function newChatDialog() {
			const people = await loadPeople();
			let mode = 'direct';
			let closeFn = null;
			const tabs = el('div', { class: 'cv-tabs', role: 'group' });
			const filter = el('input', { class: 'inp', type: 'search', placeholder: t('chat.new.searchPeople'), 'aria-label': t('chat.new.searchPeople') });
			const titleInput = el('input', { class: 'inp', maxlength: String(limits().titleMax || 80), placeholder: t('chat.new.groupTitlePh'), 'aria-label': t('chat.new.groupTitle') });
			const titleGroup = el('label', { class: 'cv-field', hidden: true }, [el('span', { text: t('chat.new.groupTitle') }), titleInput]);
			const list = el('div', { class: 'cv-people scroll' });
			const msg = el('p', { class: 'cv-dlg-err', role: 'status' });
			const createBtn = el('button', { type: 'button', class: 'btn btn-pri', text: t('chat.new.create'), hidden: true, on: { click: async () => {
				const ids = Array.from(list.querySelectorAll('input[type=checkbox]:checked')).map((x) => Number(x.value));
				const tt = titleInput.value.trim();
				if (!tt) { msg.textContent = t('chat.new.needTitle'); return; }
				if (!ids.length) { msg.textContent = t('chat.new.needPeople'); return; }
				const r = await api.create({ kind: 'group', userIds: ids, title: tt }).catch((e) => ({ ok: false, error: e && e.message }));
				if (!r || r.ok === false) { msg.textContent = CS.errorText(r, t); return; }
				if (closeFn) closeFn(null);
				await refreshList();
				if (r.conversation) openChat(r.conversation.id);
			} } });
			const draw = () => {
				clear(list);
				const q = filter.value.trim().toLowerCase();
				const ps = people.filter((p) => !q || String(p.name || '').toLowerCase().includes(q));
				if (!ps.length) list.appendChild(el('p', { class: 'cv-empty', text: t('chat.new.noPeople') }));
				for (const p of ps) {
					list.appendChild(personRow(p, mode === 'group' ? { check: true } : { onClick: async () => {
						const r = await api.create({ kind: 'direct', userIds: [p.id] }).catch((e) => ({ ok: false, error: e && e.message }));
						if (!r || r.ok === false) { msg.textContent = CS.errorText(r, t); return; }
						if (closeFn) closeFn(null);
						await refreshList();
						if (r.conversation) openChat(r.conversation.id);
					} }));
				}
				titleGroup.hidden = mode !== 'group';
				createBtn.hidden = mode !== 'group';
				for (const b of tabs.querySelectorAll('button')) b.setAttribute('aria-pressed', b.dataset.mode === mode ? 'true' : 'false');
			};
			for (const k of ['direct', 'group']) tabs.appendChild(el('button', { type: 'button', 'data-mode': k, text: t(`chat.new.${k}`), on: { click: () => { mode = k; draw(); } } }));
			filter.addEventListener('input', draw);
			draw();
			dialog(t('chat.newChat'), el('div', { class: 'cv-new' }, [tabs, titleGroup, filter, list, msg, createBtn]), [], { onOpen: (done) => { closeFn = done; } });
		}

		async function addMembersDialog(c) {
			const people = await loadPeople();
			const list = el('div', { class: 'cv-people scroll' });
			const avail = people.filter((p) => !CS.member(c, p.id));
			if (!avail.length) list.appendChild(el('p', { class: 'cv-empty', text: t('chat.new.noPeople') }));
			for (const p of avail) list.appendChild(personRow(p, { check: true }));
			dialog(t('chat.info.addMembers'), list, [
				{ label: t('chat.common.cancel'), value: null },
				{ label: t('chat.info.add'), primary: true, onClick: async () => {
					const ids = Array.from(list.querySelectorAll('input[type=checkbox]:checked')).map((x) => Number(x.value));
					if (!ids.length) return false;
					await patchConv(c, { add: ids });
					return true;
				} },
			]);
		}

		function memberDialog(c, mb) {
			const admin = mb.role === 'admin';
			let closeFn = null;
			const body = el('div', { class: 'cv-stack' }, [
				el('button', { type: 'button', class: 'btn btn-sec', text: admin ? t('chat.info.unmakeAdmin') : t('chat.info.makeAdmin'), on: { click: () => { if (closeFn) closeFn(null); patchConv(c, { role: { userId: mb.userId, role: admin ? 'member' : 'admin' } }); } } }),
				el('button', { type: 'button', class: 'btn btn-danger cv-danger', text: t('chat.info.removeMember'), on: { click: () => { if (closeFn) closeFn(null); patchConv(c, { remove: [mb.userId] }); } } }),
			]);
			dialog(mb.name || t('chat.gone'), body, [], { onOpen: (done) => { closeFn = done; } });
		}

		function renameDialog(c) {
			const input = el('input', { class: 'inp', value: c.title || '', maxlength: String(limits().titleMax || 80), 'aria-label': t('chat.new.groupTitle') });
			dialog(t('chat.info.rename'), el('label', { class: 'cv-field' }, [el('span', { text: t('chat.new.groupTitle') }), input]), [
				{ label: t('chat.common.cancel'), value: null },
				{ label: t('chat.common.save'), primary: true, onClick: async () => { const v = input.value.trim(); if (!v) return false; await patchConv(c, { title: v }); return true; } },
			]);
		}

		async function prefsDialog() {
			const st = await api.status().catch(() => null);
			const prefs = (st && st.me && st.me.prefs) || {};
			const body = el('div', { class: 'cv-prefs' });
			for (const [k, label, hint] of [['readReceipts', 'chat.prefs.readReceipts', 'chat.prefs.readReceiptsHint'], ['typing', 'chat.prefs.typing', 'chat.prefs.typingHint'], ['preview', 'chat.prefs.preview', 'chat.prefs.previewHint']]) {
				const sw = el('button', { type: 'button', class: `sw${prefs[k] !== false ? ' on' : ''}`, role: 'switch', 'aria-checked': prefs[k] !== false ? 'true' : 'false', 'aria-label': t(label) }, [el('span')]);
				sw.addEventListener('click', async () => {
					const next = sw.getAttribute('aria-checked') !== 'true';
					sw.setAttribute('aria-checked', next ? 'true' : 'false');
					sw.classList.toggle('on', next);
					const r = await api.prefs({ [k]: next }).catch((e) => ({ ok: false, error: e && e.message }));
					if (!r || r.ok === false) {
						sw.setAttribute('aria-checked', next ? 'false' : 'true');
						sw.classList.toggle('on', !next);
						toast(CS.errorText(r, t), 'error');
					} else {
						loadStatus();
					}
				});
				body.appendChild(el('div', { class: 'cv-pref' }, [el('span', { class: 'cv-pref-tx' }, [el('b', { text: t(label) }), el('small', { text: t(hint) })]), sw]));
			}
			body.appendChild(el('p', { class: 'cv-note', text: t('chat.prefs.toastHint') }));
			body.appendChild(el('p', { class: 'cv-note cv-note-lock' }, [icon('lock', 14), el('span', { text: t('chat.info.encrypted') })]));
			dialog(t('chat.prefs.title'), body, [{ label: t('chat.common.close'), value: null }]);
		}

		// ── Live updates ─────────────────────────────────────

		let msgTimer = null;
		async function refreshMessages() {
			const id = S.cur;
			if (typeof id !== 'number') return;
			const r = await api.messages(id, { cached: true }).catch(() => null);
			if (S.cur !== id || !r || r.ok === false) return;
			const offline = S.view ? S.view.offline : false;
			S.view = { ...r, offline };
			renderMessages('keep');
		}

		api.onConversations(() => refreshListSoon());
		api.onTyping(() => refreshListSoon());
		api.onMessages((e) => {
			if (!e || e.conversationId !== S.cur) return;
			clearTimeout(msgTimer);
			msgTimer = setTimeout(refreshMessages, 30);
		});
		api.onState((st) => { S.status = st; applyStatus(); if (st && st.state === 'available') refreshListSoon(); });
		api.onUnread((n) => { if (S.status) S.status.unread = n; if (typeof o.onUnread === 'function' && S.status && S.status.state === 'available') o.onUnread(n); });
		api.onNavigate((e) => { if (e && Number.isSafeInteger(e.conversationId)) openChat(e.conversationId); });
		if (o.notify) {
			o.notify.onNew(() => loadInbox());
			o.notify.onUpdate(() => loadInbox());
		}

		document.addEventListener('visibilitychange', () => reportOpen());
		window.addEventListener('focus', () => reportOpen());
		window.addEventListener('blur', () => reportOpen());
		refs.q.addEventListener('input', () => { S.q = refs.q.value; renderList(); });
		refs.q.addEventListener('keydown', (e) => {
			if (e.key === 'Escape') { refs.q.value = ''; S.q = ''; renderList(); }
			if (e.key === 'Enter') { const first = refs.rows.querySelector('.cv-row:not(.is-pinned)'); if (first) first.click(); }
		});
		document.addEventListener('keydown', (e) => {
			if (!S.shown) return;
			if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); refs.q.focus(); refs.q.select(); }
			else if (e.key === 'Escape' && S.menu) closeMenu();
		});

		// ── Public ───────────────────────────────────────────

		loadStatus().then(() => refreshList());
		loadInbox();

		return {
			/** The page became visible. */
			show() {
				S.shown = true;
				api.view(true).catch(() => {});
				refreshList();
				loadInbox();
				reportOpen();
				if (typeof S.cur === 'number') refreshMessages();
			},
			/** The page was left. */
			hide() {
				S.shown = false;
				closeMenu();
				api.view(false).catch(() => {});
				reportOpen();
			},
			isShown: () => S.shown,
			open: (id) => openChat(id),
			openInbox: () => openInboxChat(),
			status: () => S.status,
			/** Locale changed: rebuild the texts. */
			relabel() {
				refs.q.placeholder = t('chat.searchChats');
				refs.q.setAttribute('aria-label', t('chat.searchChats'));
				refs.h.textContent = t('chat.title');
				for (const [b, key] of [[refs.prefsBtn, 'chat.prefsOpen'], [refs.newBtn, 'chat.newChat'], [refs.toLatest, 'chat.toLatest']]) { b.title = t(key); b.setAttribute('aria-label', t(key)); }
				refs.pickTitle.textContent = t('chat.pickTitle');
				refs.pickText.textContent = t('chat.pickText');
				refs.drop.lastChild.textContent = t('chat.dropNow');
				refs.list.setAttribute('aria-label', t('chat.title'));
				renderList();
				if (typeof S.cur === 'number') { renderHead(); renderComposer(false); renderMessages('keep'); renderInfo(); } else if (S.cur === 'inbox') renderInbox();
				applyStatus();
			},
		};
	}

	root.GCChatView = { mount, icon };
})(typeof self !== 'undefined' ? self : this);
