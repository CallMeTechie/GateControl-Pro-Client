/**
 * GateControl -- Mail (renderer view of the plugin gatecontrol-mail, Phase 1)
 *
 * The page "Mail" like a mail program on the desktop, three columns:
 *
 * - Menu (left, mockup "Menue"): "Alle Posteingänge", "Zum Ablegen" (with
 *   Drive), "Postausgang" (while something waits or failed), the accounts
 *   with their colour and unread count — the account shown unfolds its
 *   folders (Posteingang, Entwürfe, Gesendet, Archiv, Spam, Papierkorb, own
 *   folders as a tree) — and at the bottom "Konto hinzufügen",
 *   "Mail-Einstellungen" and the storage used.
 * - List (middle, mockup "Main"): title and unread count, search, "Neue
 *   Mail", the account chips (Alle / per account, colour dot), Relevant /
 *   Sonstige · n for inboxes, filters (Ungelesen, Markiert, Mit Anhang), the
 *   rows (picture with initials in the account's colour, sender, time,
 *   subject, preview, the AI's one-liner, symbols) with the swipe actions of
 *   the settings as quick buttons on hover, more on scrolling; offline the
 *   last lists of the cache with a note.
 * - Reading pane (right, mockup "Lesen"): Antworten / Allen antworten /
 *   Weiterleiten, Archivieren, Löschen, Spam, ungelesen, markieren,
 *   verschieben, Relevant ↔ Sonstige; subject, sender, account and time; the
 *   AI bar (Kurz gesagt, Zu tun as chips — deadlines into the family
 *   calendar —, reply suggestions); attachments with "In Drive speichern"
 *   and the suggestion ("Anderer Ordner", "künftig automatisch ablegen"),
 *   open / save as; "Bilder laden" (once / always for the sender); the mail
 *   in a sandboxed frame (no scripts, own CSP, links in the browser, pictures
 *   only through gcmail: with the client's sign-in); trackers removed; the
 *   older mails of the conversation. While the app is dark the mail is shown
 *   dark as the Outlook app does (the core's docDark: light backgrounds dark,
 *   dark text light, pictures untouched; "Mails dunkel darstellen" in the
 *   settings), the sun in the bar shows this one mail light ("Hell anzeigen").
 *
 * Writing (mockup "Schreiben") opens in the reading pane: Von (an account),
 * An / Cc / Bcc with suggestions, Betreff, the text in an editable sandboxed
 * frame (bold, italic, underline, list), attachments from this PC (button or
 * dropped files) or "Aus Drive" (search, copy or link with validity and
 * password), the server's warnings, the draft saved as it changes; "Senden"
 * leaves a bar with "Rückgängig" for 10 s, "Senden planen" picks a time.
 * "Zum Ablegen" (mockup "Ablegen") lists the attachments Drive was not sure
 * about; "Konto hinzufügen" (mockup "Konto") the providers (Microsoft with
 * the sign-in in the browser; without a client id on the server "noch nicht
 * eingerichtet"), the form with the provider's hint; the settings the
 * conversation view, the quick actions and per account name, colour, kind,
 * notifications, AI, attachments to Drive, signature, password, sign in
 * again, remove.
 *
 * Feature flags of `me`: without `ai` no AI bar, without `drive` no Drive
 * buttons, without `microsoft` Microsoft greyed.
 *
 * Data: window.gatecontrol.mail (core MailService over IPC); texts: mail.*
 * of the app locales; view logic without DOM: mail-state.js
 * (window.GCMailState). Drive's folder picker and search come from
 * drive-view.js / window.gatecontrol.drive when Drive is there.
 *
 * Note: server text only ever goes into textContent / attributes; the mail's
 * HTML only into the sandboxed frames (srcdoc made by the core); icons are
 * built from static path data with createElementNS (no innerHTML).
 */
(function (root) {
	'use strict';

	const MS = root.GCMailState;
	const NS = 'http://www.w3.org/2000/svg';
	const ICONS = {
		mail: 'M3 5h18v14H3z|M3 7l9 6 9-6',
		mailOpen: 'M3 10l9-6 9 6v9H3z|M3 10l9 6 9-6',
		inbox: 'M3 13h5l1 3h6l1-3h5|M5 5h14l2 8v6H3v-6z',
		send: 'M4 12l16-8-6 16-3-7z|M11 13l9-9',
		draft: 'M4 20h4L19 9l-4-4L4 16z',
		archive: 'M3 4h18v4H3z|M5 8v12h14V8|M10 12h4',
		trash: 'M4 7h16|M10 11v6M14 11v6|M6 7l1 13h10l1-13|M9 7V4h6v3',
		junk: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M5.6 5.6l12.8 12.8',
		folder: 'M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z',
		file: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z|M14 3v5h5',
		search: 'M11 4a7 7 0 1 0 0 14a7 7 0 1 0 0-14|M21 21l-4.3-4.3',
		refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8|M21 3v5h-5',
		pen: 'M4 20h4L19 9l-4-4L4 16z',
		reply: 'M10 9V5l-7 7 7 7v-4c5 0 8 1.5 11 5-1-5-4-10-11-11z',
		replyAll: 'M7 9V5l-6 7 6 7v-4|M13 9V5l-6 7 6 7v-4c5 0 7 1.5 10 5-1-5-3.5-10-10-11z',
		forward: 'M14 9V5l7 7-7 7v-4c-5 0-8 1.5-11 5 1-5 4-10 11-11z',
		flag: 'M5 21V4|M5 4h11l-2 4 2 4H5',
		move: 'M5 12h14|M13 6l6 6-6 6',
		tab: 'M4 6h16M4 12h10M4 18h6',
		clip: 'M21 12l-8.5 8.5a5 5 0 0 1-7-7L14 5a3.3 3.3 0 0 1 4.7 4.7l-8.5 8.5a1.7 1.7 0 0 1-2.4-2.4L15.5 8',
		cloud: 'M7 18h10a4 4 0 0 0 .5-8A6 6 0 0 0 6 9.5 4.3 4.3 0 0 0 7 18z',
		plus: 'M12 5v14M5 12h14',
		gear: 'M12.2 2h-.4a2 2 0 0 0-2 2v.2a2 2 0 0 1-1 1.7l-.4.3a2 2 0 0 1-2 0l-.2-.1a2 2 0 0 0-2.7.7l-.2.4a2 2 0 0 0 .7 2.7l.2.1a2 2 0 0 1 1 1.7v.5a2 2 0 0 1-1 1.8l-.2.1a2 2 0 0 0-.7 2.7l.2.4a2 2 0 0 0 2.7.7l.2-.1a2 2 0 0 1 2 0l.4.3a2 2 0 0 1 1 1.7v.2a2 2 0 0 0 2 2h.4a2 2 0 0 0 2-2v-.2a2 2 0 0 1 1-1.7l.4-.3a2 2 0 0 1 2 0l.2.1a2 2 0 0 0 2.7-.7l.2-.4a2 2 0 0 0-.7-2.7l-.2-.1a2 2 0 0 1-1-1.8v-.5a2 2 0 0 1 1-1.7l.2-.1a2 2 0 0 0 .7-2.7l-.2-.4a2 2 0 0 0-2.7-.7l-.2.1a2 2 0 0 1-2 0l-.4-.3a2 2 0 0 1-1-1.7V4a2 2 0 0 0-2-2z|M12 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6',
		close: 'M6 6l12 12M18 6L6 18',
		chevron: 'M9 6l6 6-6 6',
		chevDown: 'M6 9l6 6 6-6',
		back: 'M15 6l-6 6 6 6',
		copy: 'M9 9h11v11H9z|M5 15H4V4h11v1',
		more: 'M5 12h.01M12 12h.01M19 12h.01',
		spark: 'M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z|M19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8z',
		calendar: 'M4 6h16v14H4z|M4 10h16|M8 3v4M16 3v4',
		image: 'M4 5h16v14H4z|M4 16l5-5 4 4 3-3 4 4|M15 9h.01',
		shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
		alert: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 8v5M12 16h.01',
		check: 'M4 12l5 5L20 6',
		clock: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 7v5l3 3',
		open: 'M14 4h6v6|M20 4l-9 9|M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5',
		down: 'M12 4v11|M7 10l5 5 5-5|M5 20h14',
		link: 'M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1|M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1',
		bold: 'M7 5h6a3.5 3.5 0 0 1 0 7H7z|M7 12h7a3.5 3.5 0 0 1 0 7H7z',
		italic: 'M10 5h8M6 19h8M14 5l-4 14',
		underline: 'M7 4v7a5 5 0 0 0 10 0V4|M5 20h14',
		list: 'M9 6h11M9 12h11M9 18h11|M4.5 6h.01M4.5 12h.01M4.5 18h.01',
		sun: 'M12 8a4 4 0 1 0 0 8a4 4 0 1 0 0-8|M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
		moon: 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z',
		offline: 'M2 8.8a15 15 0 0 1 4.2-2.6|M10.7 5.1A15 15 0 0 1 22 8.8|M5 12.9a10 10 0 0 1 5.2-2.8|M16.8 11.5A10 10 0 0 1 19 12.9|M8.5 16.4a5 5 0 0 1 7 0|M12 20h.01|M3 3l18 18',
	};
	const TONE = { err: ['var(--err-bg)', 'var(--err)'], info: ['var(--info-bg)', 'var(--info)'], acc: ['var(--acc-bg)', 'var(--acc-t)'], warn: ['var(--warn-bg)', 'var(--warn)'], pro: ['var(--pro-bg)', 'var(--pro)'], muted: ['var(--panel2)', 'var(--muted)'] };
	const SAVE_DELAY_MS = 2500;
	const LIST_RELOAD_MS = 800;

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
		for (const d of String(ICONS[name] || ICONS.file).split('|')) {
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
			else if (k === 'style') n.setAttribute('style', v);
			else n.setAttribute(k, v === true ? '' : String(v));
		}
		for (const c of kids || []) if (c !== null && c !== undefined && c !== false && c !== '') n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
		return n;
	}
	const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };
	const dot = (color) => { const d = el('span', { class: 'ml-dot' }); d.style.background = color || 'var(--faint)'; return d; };
	let uid = 0;
	const nextId = (p) => `${p}-${++uid}`;
	const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed', error: err && err.message });
	const call = (p) => Promise.resolve(p).catch(fail);

	function sw(on, label, onChange) {
		const b = el('button', { type: 'button', class: `sw${on ? ' on' : ''}`, role: 'switch', 'aria-checked': on ? 'true' : 'false', 'aria-label': label }, [el('span')]);
		b.addEventListener('click', () => {
			const next = !b.classList.contains('on');
			b.classList.toggle('on', next);
			b.setAttribute('aria-checked', next ? 'true' : 'false');
			onChange(next);
		});
		return b;
	}

	function seg(options, value, onChange, label) {
		const box = el('div', { class: 'seg', role: 'radiogroup', 'aria-label': label || null });
		for (const [v, text] of options) {
			const b = el('button', { type: 'button', role: 'radio', class: v === value ? 'on' : '', 'aria-checked': v === value ? 'true' : 'false', text });
			b.addEventListener('click', () => {
				for (const x of box.children) { x.classList.remove('on'); x.setAttribute('aria-checked', 'false'); }
				b.classList.add('on');
				b.setAttribute('aria-checked', 'true');
				onChange(v);
			});
			box.appendChild(b);
		}
		return box;
	}

	// ── Dialog (modal) ───────────────────────────────────

	function openDialog({ title, onClose = null, wide = false, closeLabel = 'Close', cls = '' }) {
		const before = document.activeElement;
		const titleId = nextId('ml-dlg-t');
		const h = el('h2', { id: titleId, class: 'ml-dlg-h', text: title });
		const body = el('div', { class: 'ml-dlg-body' });
		const foot = el('div', { class: 'ml-dlg-foot' });
		let closed = false;
		const close = (value) => {
			if (closed) return;
			closed = true;
			document.removeEventListener('keydown', onKey, true);
			scrim.remove();
			if (before && typeof before.focus === 'function' && before.isConnected) before.focus();
			if (onClose) onClose(value);
		};
		const box = el('div', { class: `ml-dlg${wide ? ' is-wide' : ''}${cls ? ` ${cls}` : ''}`, role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId, tabindex: '-1' }, [
			el('div', { class: 'ml-dlg-head' }, [h, el('button', { type: 'button', class: 'ml-ib', 'aria-label': closeLabel, title: closeLabel, on: { click: () => close(null) } }, [icon('close', 16)])]),
			body,
			foot,
		]);
		const scrim = el('div', { class: 'ml-scrim', on: { mousedown: (e) => { if (e.target === scrim) close(null); } } }, [box]);
		function onKey(e) {
			if (e.key === 'Escape') { e.stopPropagation(); close(null); }
		}
		document.addEventListener('keydown', onKey, true);
		document.body.appendChild(scrim);
		setTimeout(() => {
			const first = body.querySelector('input, select, textarea, button, [tabindex="0"]');
			(first || box).focus();
		}, 0);
		return { box, body, foot, close, setTitle: (s) => { h.textContent = s; }, get closed() { return closed; } };
	}

	/**
	 * A sandboxed frame for a mail's document (no scripts; same origin only so the page can size it / read the editor).
	 * A mail wider than the pane (a newsletter's table of a fixed width) is set smaller as a whole: the window
	 * measures the frame's #gc-fit (core mailDocument) at zoom 1 and gives it CSS zoom (MS.fitZoom) — the frame
	 * itself never runs a script.
	 */
	function mailFrame(doc, { title, editable = false, dark = false } = {}) {
		const f = el('iframe', {
			class: editable ? 'ml-editor' : `ml-frame${dark ? ' is-dark' : ''}`,
			title: title || null,
			sandbox: editable ? 'allow-same-origin' : 'allow-same-origin allow-popups allow-popups-to-escape-sandbox',
			referrerpolicy: 'no-referrer',
		});
		f.srcdoc = doc;
		if (!editable) {
			const fit = () => {
				try {
					const d = f.contentDocument;
					if (!d || !d.documentElement) return;
					const root = d.documentElement;
					const box = d.getElementById('gc-fit');
					if (box) {
						box.style.zoom = '';
						const z = MS.fitZoom(box.clientWidth, box.scrollWidth);
						if (z < 1) box.style.zoom = String(z);
					}
					const h = Math.max(root.scrollHeight, d.body ? d.body.scrollHeight : 0);
					// the frame is as tall as the mail: no scrollbar of its own (a Windows scrollbar, shown for a
					// rounded half pixel, would take width from the mail that was just made to fit)
					root.style.overflowY = h < 30000 ? 'hidden' : '';
					f.style.height = `${Math.min(Math.max(h + 1, 60), 30000)}px`;
				} catch { /* not there yet */ }
			};
			f.addEventListener('load', () => {
				fit();
				for (const ms of [120, 400, 1000, 2500, 6000]) setTimeout(fit, ms);
				// pictures that come later change the width; so does the pane
				try { f.contentDocument.addEventListener('load', fit, true); } catch { /* gone */ }
			});
			if (typeof ResizeObserver === 'function') {
				let w = 0;
				new ResizeObserver(() => { if (f.clientWidth !== w) { w = f.clientWidth; fit(); } }).observe(f);
			}
		}
		return f;
	}

	/**
	 * @param {object} o
	 * @param {HTMLElement} o.root - #page-mail
	 * @param {object} o.api - window.gatecontrol.mail
	 * @param {Function} o.t
	 * @param {() => string} o.getLocale
	 * @param {(msg: string, type?: string) => void} o.toast
	 * @param {object} [o.driveApi] - window.gatecontrol.drive (search for "Aus Drive", the folder picker)
	 * @param {object} [o.driveView] - window.GCDriveView (pickFolder)
	 * @param {(st: object) => void} [o.onStatus] - availability (the nav entry)
	 * @param {(n: number) => void} [o.onUnread] - unread mails of all inboxes (the nav badge)
	 */
	function mount(o) {
		const { api, t } = o;
		const lang = () => (o.getLocale && o.getLocale() === 'en' ? 'en' : 'de');
		const toast = (msg, type) => { if (o.toast) o.toast(msg, type); };
		const errText = (r) => MS.errorText(r, t, lang());
		/** An attachment's failure: "still on its way from the provider" for busy (loading), else the code's text. */
		const attErr = (r) => { const b = MS.busyRetry(r); return b && b.loading ? t('mail.att.stillLoading') : errText(r); };

		// ── Account pictures (Mail 1.1.2) ────────────────

		const avatarUrls = new Map();     // media id → data: URL
		const avatarWaiting = new Map();  // media id → Promise<url | null>
		const avatarFailed = new Map();   // media id → when it last failed (asked again after a minute)

		function avatarUrl(mediaId) {
			if (avatarUrls.has(mediaId)) return Promise.resolve(avatarUrls.get(mediaId));
			if (avatarWaiting.has(mediaId)) return avatarWaiting.get(mediaId);
			if (!api.avatar || Date.now() - (avatarFailed.get(mediaId) || 0) < 60000) return Promise.resolve(null);
			const p = call(api.avatar(mediaId)).then((r) => {
				avatarWaiting.delete(mediaId);
				const url = r && r.ok && typeof r.url === 'string' && /^data:image\/(png|jpe?g|gif|webp|bmp|avif);base64,/.test(r.url) ? r.url : null;
				if (url) avatarUrls.set(mediaId, url);
				else avatarFailed.set(mediaId, Date.now());
				return url;
			});
			avatarWaiting.set(mediaId, p);
			return p;
		}

		/**
		 * An account as the Outlook app shows it: round, its picture (Microsoft) or the provider's mark (own simple
		 * signs, MS.accountMark), with a small dot in the account's colour.
		 */
		function avatarEl(a, size = 30, { dotted = true } = {}) {
			const box = el('span', { class: 'ml-av', 'aria-hidden': 'true' });
			box.style.width = `${size}px`;
			box.style.height = `${size}px`;
			const face = el('span', { class: 'ml-av-face' });
			const mark = MS.accountMark(a);
			face.style.background = mark.bg;
			face.style.color = mark.fg;
			if (mark.tiles) {
				const g = el('span', { class: 'ml-av-tiles' });
				for (const c of mark.tiles) { const q = el('span'); q.style.background = c; g.append(q); }
				face.append(g);
			} else {
				face.textContent = mark.text;
				face.style.fontSize = `${Math.round(size * (mark.small ? 0.3 : 0.46))}px`;
			}
			const picture = (url) => {
				clear(face);
				face.style.background = 'transparent';
				face.append(el('img', { src: url, alt: '', draggable: 'false' }));
			};
			const media = a && a.avatar && a.avatar.mediaId;
			if (media && avatarUrls.has(media)) picture(avatarUrls.get(media));
			else if (media) avatarUrl(media).then((url) => { if (url) picture(url); });
			box.append(face);
			if (dotted) {
				const d = el('span', { class: 'ml-av-dot' });
				d.style.background = (a && a.color) || 'var(--faint)';
				box.append(d);
			}
			return box;
		}

		const S = {
			status: null,
			shown: false,
			loaded: false,
			me: null,
			folders: null,
			view: { kind: 'box', box: 'all', folderId: null },
			lastBox: { kind: 'box', box: 'all', folderId: null },
			tab: 'relevant',
			filter: { unread: false, flagged: false, attachments: false },
			items: [],
			next: null,
			counts: null,
			offline: false,
			loading: false,
			listError: null,
			listSeq: 0,
			selectedId: null,
			pane: 'empty',          // 'empty' | 'read' | 'compose' | 'sender'
			read: null,             // { message, doc, docDark, light, ai, thread, aiError, suggest: Map(aid → { suggestion, duplicate }) }
			readSeq: 0,
			senderSeq: 0,
			folds: new Map(),       // account id → its folders shown in the menu (this session)
			sender: null,           // the sender's page: { email, name, accountId, contact, items, next, loading, error }
			outbox: [],
			filing: [],
			undo: null,             // { outboxId, draftId, until, sendAt, timer }
			compose: null,
		};

		// ── Mails in the dark ────────────────────────────

		const store = (() => { try { return root.localStorage || null; } catch { return null; } })();
		/** "Mails dunkel darstellen" (kept on this PC, on by default). */
		function darkMails() {
			try { return MS.darkSetting(store ? store.getItem(MS.DARK_KEY) : null); } catch { return true; }
		}
		function setDarkMails(on) {
			try { if (store) store.setItem(MS.DARK_KEY, on ? '1' : '0'); } catch { /* private */ }
			if (S.pane === 'read') renderPane();
		}
		/** Whether the app is dark right now (the window's theme: no data-theme="light"). */
		const appDark = () => document.documentElement.getAttribute('data-theme') !== 'light';
		/** Whether the open mail is shown dark (the app dark, the setting on, not switched to light). */
		const readDark = () => MS.showDark(appDark(), darkMails(), !!(S.read && S.read.light));
		// the app's theme changed: the open mail follows
		if (typeof MutationObserver === 'function') {
			new MutationObserver(() => { if (S.pane === 'read' && S.read && S.read.message) renderPane(); })
				.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
		}

		const page = el('div', { class: 'ml' });
		const side = el('aside', { class: 'ml-side', 'aria-label': t('mail.menu') });
		const listCol = el('section', { class: 'ml-list', 'aria-label': t('mail.list') });
		const pane = el('section', { class: 'ml-pane', 'aria-live': 'polite' });
		const gate = el('div', { class: 'ml-gate', hidden: true });
		const undoBar = el('div', { class: 'ml-undo', role: 'status', hidden: true });
		page.append(side, listCol, pane);
		o.root.append(gate, page, undoBar);

		// ── Availability ─────────────────────────────────

		function setStatus(st) {
			S.status = st || null;
			if (o.onStatus) o.onStatus(st);
			const avail = st && st.state === 'available';
			gate.hidden = avail;
			page.hidden = !avail;
			if (!avail) {
				clear(gate);
				const key = !st || st.state === 'unknown' ? 'mail.gate.loading' : st.state === 'error' ? 'mail.gate.offline' : 'mail.gate.unavailable';
				gate.append(el('div', { class: 'ml-gate-ic' }, [icon(st && st.state === 'error' ? 'offline' : 'mail', 28)]), el('p', { class: 'ml-p', text: t(key) }));
				if (st && st.state === 'error') gate.append(el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.retry'), on: { click: () => call(api.check()).then(setStatus) } }));
			} else if (S.shown && !S.loaded) {
				loadAll();
			}
		}

		api.onState && api.onState((st) => setStatus(st));
		call(api.status()).then((st) => setStatus(st && st.state ? st : null));

		// ── Loading ──────────────────────────────────────

		const features = () => (S.me && S.me.features) || ['mail'];
		const has = (f) => features().includes(f);

		async function loadMe() {
			const r = await call(api.me());
			if (r && r.ok) {
				S.me = r;
				if (o.onUnread) o.onUnread(r.unread ? r.unread.all : 0);
			}
			return r;
		}

		async function loadFolders() {
			const r = await call(api.folders());
			if (r && r.ok) S.folders = r;
		}

		async function loadOutbox() {
			const r = await call(api.outbox());
			if (r && r.ok) S.outbox = r.items;
			renderMenu();
			if (S.view.kind === 'outbox') renderOutbox();
		}

		async function loadFiling() {
			if (!has('drive')) { S.filing = []; return; }
			const r = await call(api.filing());
			if (r && r.ok) S.filing = r.items;
			renderMenu();
			if (S.view.kind === 'filing') renderFiling();
		}

		async function loadAll() {
			S.loaded = true;
			await loadMe();
			await loadFolders();
			renderMenu();
			await loadList();
			loadOutbox();
			loadFiling();
		}

		async function loadList({ more = false, keep = false } = {}) {
			const seq = ++S.listSeq;
			const v = S.view;
			if (v.kind === 'filing') { renderFiling(); return; }
			if (v.kind === 'outbox') { renderOutbox(); return; }
			S.loading = true;
			if (!more && !keep) { S.items = []; S.next = null; S.listError = null; S.resetScroll = true; }
			renderList();
			let r;
			if (v.kind === 'search') {
				r = await call(api.search({ q: v.q, box: v.box && v.box !== 'all' ? v.box : undefined, cursor: more ? S.next : undefined }));
			} else {
				const q = MS.listQuery(v, S.folders, S.tab, S.filter);
				if (more && S.next) q.before = S.next;
				r = await call(api.list(q));
			}
			if (seq !== S.listSeq) return;
			S.loading = false;
			if (r && r.ok) {
				S.items = more ? MS.mergeItems(S.items, r.items) : r.items;
				S.next = r.next || null;
				if (r.counts) S.counts = r.counts;
				S.offline = !!r.offline;
				S.remote = !!r.remote;
				S.listError = null;
			} else {
				S.listError = errText(r);
			}
			renderList();
		}

		let reloadTimer = null;
		function reloadSoon() {
			clearTimeout(reloadTimer);
			reloadTimer = setTimeout(async () => {
				if (!S.shown) return;
				await loadMe();
				await loadFolders();
				renderMenu();
				if (S.view.kind === 'box' || S.view.kind === 'search') loadList({ keep: true });
			}, LIST_RELOAD_MS);
		}

		api.onChanged && api.onChanged((c) => {
			if (!S.loaded) return;
			// Mail 1.1.2: the body, an attachment or an embedded picture of the open mail has come
			const R = S.read;
			if (c && R && R.message && !R.loading) {
				if (R.message.bodyMissing && MS.bringsBody(c, R.message)) refreshBody(R.message.id);
				if (c.messageId === R.message.id && c.attachmentId) {
					const w = R.atts && R.atts.get(c.attachmentId);
					if (w && !w.inFlight) w.run();
					if (R.pics && R.pics.waiting.has(c.attachmentId)) reloadPictures(R);
				}
			}
			const v = S.view;
			if (!c || !c.accountId || v.kind !== 'box' || v.box === 'all' || v.box === c.accountId) reloadSoon();
			else loadMe().then(renderMenu);
		});
		api.onOutbox && api.onOutbox(() => { if (S.loaded) loadOutbox(); });

		// ── Menu (left) ──────────────────────────────────

		function menuItem({ label, ic, color, count, on, onClick, sub = false, depth = 0, warn = false, title = null }) {
			const b = el('button', { type: 'button', class: `ml-it${on ? ' on' : ''}${sub ? ' sub' : ''}`, 'aria-current': on ? 'page' : null, title: title || label, on: { click: onClick } }, [
				color ? dot(color) : (ic ? icon(ic, 16) : null),
				el('span', { class: 'ml-it-tx', text: label }),
				warn ? el('span', { class: 'ml-it-warn', title: t('mail.accountProblem') }, [icon('alert', 14)]) : null,
				count ? el('span', { class: `ml-n${on ? ' on' : ''}`, text: count > 999 ? '999+' : String(count) }) : null,
			]);
			if (depth) b.style.paddingLeft = `${50 + depth * 14}px`;
			return b;
		}

		/** An account in the menu: its picture or mark, the name and below the address (like the Outlook app). */
		function accountItem(a, { count, on, onClick }) {
			const warn = a.state === 'auth_failed' || a.state === 'unreachable';
			const sub = MS.accountSub(a);
			return el('button', { type: 'button', class: `ml-it ml-it-acc${on ? ' on' : ''}`, 'aria-current': on ? 'page' : null, title: `${a.name} · ${a.email}`, on: { click: onClick } }, [
				avatarEl(a, 30),
				el('span', { class: 'ml-it-tx' }, [el('span', { class: 'ml-it-name', text: a.name }), sub ? el('span', { class: 'ml-it-mail', text: sub }) : null]),
				warn ? el('span', { class: 'ml-it-warn', title: t('mail.accountProblem') }, [icon('alert', 14)]) : null,
				count ? el('span', { class: `ml-n${on ? ' on' : ''}`, text: count > 999 ? '999+' : String(count) }) : null,
			]);
		}

		function renderMenu() {
			clear(side);
			const v = S.view;
			const me = S.me || { accounts: [], unread: { all: 0, byAccount: {} } };
			side.append(el('h2', { class: 'ml-side-h', text: t('mail.title') }));
			side.append(menuItem({ label: t('mail.allInboxes'), ic: 'inbox', count: me.unread.all, on: v.kind === 'box' && v.box === 'all', onClick: () => go({ kind: 'box', box: 'all', folderId: null }) }));
			if (has('drive')) side.append(menuItem({ label: t('mail.filing.title'), ic: 'cloud', count: S.filing.length, on: v.kind === 'filing', onClick: () => go({ kind: 'filing' }) }));
			if (S.outbox.length) side.append(menuItem({ label: t('mail.outbox.title'), ic: 'send', count: S.outbox.length, on: v.kind === 'outbox', onClick: () => go({ kind: 'outbox' }) }));
			if (me.accounts.length) side.append(el('div', { class: 'ml-lab', text: t('mail.accountsLabel') }));
			for (const a of me.accounts) {
				// a tap on the account (or its arrow) opens or closes its folders; its inbox is the tree's first entry
				const open = MS.foldOpen(S.folds, a.id, v);
				const fold = () => { MS.toggleFold(S.folds, a.id, S.view); renderMenu(); };
				const item = accountItem(a, { count: (me.unread.byAccount || {})[String(a.id)] || 0, on: !open && v.kind === 'box' && v.box === a.id, onClick: fold });
				item.setAttribute('aria-expanded', open ? 'true' : 'false');
				const row = el('div', { class: 'ml-acc' }, [
					item,
					el('button', { type: 'button', class: `ml-fold${open ? ' open' : ''}`, tabindex: '-1', 'aria-hidden': 'true', title: t('mail.folders', { name: a.name }), on: { click: fold } }, [icon('chevDown', 14)]),
				]);
				side.append(row);
				if (open) {
					const acc = ((S.folders && S.folders.accounts) || []).find((x) => x.accountId === a.id);
					const tree = MS.folderTree(acc ? acc.folders : []);
					const inboxOn = v.kind === 'box' && v.box === a.id && !v.folderId;
					if (!tree.some(({ folder }) => folder.role === 'inbox')) {
						side.append(menuItem({ label: t('mail.role.inbox'), sub: true, depth: 0, on: inboxOn, onClick: () => go({ kind: 'box', box: a.id, folderId: null }) }));
					}
					for (const { folder, depth } of tree) {
						const inbox = folder.role === 'inbox';
						side.append(menuItem({
							label: MS.folderName(folder, t), sub: true, depth, count: folder.role === 'sent' || folder.role === 'trash' ? 0 : folder.unread,
							on: inbox ? inboxOn : v.kind === 'box' && v.folderId === folder.id,
							onClick: () => go({ kind: 'box', box: a.id, folderId: inbox ? null : folder.id }),
						}));
					}
				}
			}
			const foot = el('div', { class: 'ml-side-foot' }, [
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.addAccount'), 'aria-label': t('mail.addAccount'), on: { click: () => openAddAccount() } }, [icon('plus', 18)]),
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.settings.title'), 'aria-label': t('mail.settings.title'), on: { click: () => openSettings() } }, [icon('gear', 18)]),
			]);
			const q = S.me ? MS.quotaView(S.me.limits, lang(), t) : null;
			if (q) {
				const bar = el('div', { class: 'ml-quota-bar' }, [el('span')]);
				bar.firstChild.style.width = `${q.pct}%`;
				if (q.pct >= 90) bar.classList.add('is-full');
				foot.append(el('div', { class: 'ml-quota', title: q.text }, [bar, el('span', { class: 'ml-quota-tx', text: q.text })]));
			}
			side.append(foot);
		}

		function go(view) {
			S.view = view;
			if (view.kind === 'box') { S.lastBox = view; S.tab = 'relevant'; }
			if (view.kind === 'filing' || view.kind === 'outbox') { S.selectedId = null; if (S.pane === 'read') S.pane = 'empty'; }
			page.classList.toggle('is-wide', view.kind === 'filing' || view.kind === 'outbox');
			renderMenu();
			if (view.kind === 'filing') { loadFiling(); renderFiling(); renderPane(); return; }
			if (view.kind === 'outbox') { loadOutbox(); renderOutbox(); renderPane(); return; }
			loadList();
			renderPane();
		}

		// ── List (middle) ────────────────────────────────

		const searchIn = el('input', { type: 'search', class: 'ml-search-in', placeholder: t('mail.search.placeholder'), 'aria-label': t('mail.search.placeholder'), maxlength: '200', spellcheck: 'false' });
		searchIn.addEventListener('keydown', (e) => {
			if (e.key === 'Enter') {
				const q = searchIn.value.trim();
				if (q.length >= 2) go({ kind: 'search', q, box: S.lastBox.box });
				else if (!q && S.view.kind === 'search') go(S.lastBox);
			} else if (e.key === 'Escape' && S.view.kind === 'search') {
				searchIn.value = '';
				go(S.lastBox);
			}
		});

		function renderList() {
			if (S.view.kind === 'filing') return renderFiling();
			if (S.view.kind === 'outbox') return renderOutbox();
			const oldRows = listCol.querySelector('.ml-rows');
			const keepScroll = oldRows && !S.resetScroll ? oldRows.scrollTop : 0;
			S.resetScroll = false;
			clear(listCol);
			const v = S.view;
			const head = MS.viewTitle(v, S.me, S.folders, t);
			listCol.append(el('div', { class: 'ml-head' }, [
				el('div', { class: 'ml-head-tx' }, [el('h1', { class: 'ml-h', text: head.title }), el('span', { class: 'ml-sub', text: head.sub })]),
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.refresh'), 'aria-label': t('mail.refresh'), on: { click: () => reloadSoon() } }, [icon('refresh', 16)]),
				el('button', { type: 'button', class: 'btn btn-pri btn-sm ml-new', on: { click: () => openCompose({}) } }, [icon('pen', 15), el('span', { text: t('mail.newMail') })]),
			]));
			searchIn.placeholder = t('mail.search.placeholder');
			searchIn.setAttribute('aria-label', t('mail.search.placeholder'));
			listCol.append(el('label', { class: 'ml-search' }, [icon('search', 15), searchIn]));
			const accounts = (S.me && S.me.accounts) || [];
			if (v.kind === 'box' && !v.folderId && accounts.length > 1) {
				const chips = el('div', { class: 'ml-chips', role: 'group', 'aria-label': t('mail.boxes') });
				const chip = (label, color, on, box) => el('button', { type: 'button', class: `ml-chip${on ? ' on' : ''}`, 'aria-pressed': on ? 'true' : 'false', on: { click: () => go({ kind: 'box', box, folderId: null }) } }, [dot(color), el('span', { text: label })]);
				chips.append(chip(t('mail.all'), 'var(--text)', v.box === 'all', 'all'));
				for (const a of accounts) chips.append(chip(a.name, a.color, v.box === a.id, a.id));
				listCol.append(chips);
			}
			if (MS.isInbox(v, S.folders)) {
				const tabs = el('div', { class: 'ml-tabs', role: 'tablist' });
				const tabBtn = (id, label) => el('button', { type: 'button', role: 'tab', class: `ml-tab${S.tab === id ? ' on' : ''}`, 'aria-selected': S.tab === id ? 'true' : 'false', text: label, on: { click: () => { if (S.tab !== id) { S.tab = id; loadList(); } } } });
				tabs.append(tabBtn('relevant', t('mail.tab.relevant')), tabBtn('other', S.counts ? t('mail.tab.otherCount', { count: S.counts.other }) : t('mail.tab.other')));
				listCol.append(tabs);
			}
			if (v.kind === 'box') {
				const f = el('div', { class: 'ml-filters', role: 'group', 'aria-label': t('mail.filter.label') });
				for (const k of ['unread', 'flagged', 'attachments']) {
					f.append(el('button', { type: 'button', class: `ml-filter${S.filter[k] ? ' on' : ''}`, 'aria-pressed': S.filter[k] ? 'true' : 'false', text: t(`mail.filter.${k}`), on: { click: () => { S.filter[k] = !S.filter[k]; loadList(); } } }));
				}
				listCol.append(f);
			}
			const problem = accounts.find((a) => a.state === 'auth_failed');
			if (problem) {
				listCol.append(el('div', { class: 'ml-banner is-err' }, [icon('alert', 15), el('span', { class: 'ml-grow', text: t('mail.authFailed', { name: problem.name }) }), el('button', { type: 'button', class: 'btn btn-sec btn-xs', text: t('mail.check'), on: { click: () => openAccount(problem) } })]));
			}
			if (S.offline) listCol.append(el('div', { class: 'ml-banner' }, [icon('offline', 15), el('span', { text: t('mail.offline') })]));
			if (v.kind === 'search' && S.remote) listCol.append(el('div', { class: 'ml-note', text: t('mail.search.remote') }));
			const rows = el('div', { class: 'ml-rows', role: 'listbox', 'aria-label': head.title, tabindex: '0' });
			rows.addEventListener('keydown', onListKey);
			if (!accounts.length && S.me && v.kind === 'box') {
				rows.append(el('div', { class: 'ml-empty' }, [icon('mail', 28), el('p', { class: 'ml-p', text: t('mail.noAccounts') }), el('button', { type: 'button', class: 'btn btn-pri', text: t('mail.addAccount'), on: { click: () => openAddAccount() } })]));
			} else if (S.listError && !S.items.length) {
				rows.append(el('div', { class: 'ml-empty' }, [el('p', { class: 'ml-p', text: S.listError }), el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.retry'), on: { click: () => loadList() } })]));
			} else if (!S.items.length) {
				rows.append(el('div', { class: 'ml-empty' }, [el('p', { class: 'ml-p', text: S.loading ? t('mail.loading') : (v.kind === 'search' ? t('mail.search.none') : t('mail.empty')) })]));
			}
			for (const m of S.items) rows.append(rowEl(m));
			if (S.next) {
				const more = el('button', { type: 'button', class: 'btn btn-ghost btn-sm ml-more', text: S.loading ? t('mail.loading') : t('mail.more'), disabled: S.loading || null, on: { click: () => loadList({ more: true }) } });
				rows.append(more);
				rows.addEventListener('scroll', () => { if (!S.loading && S.next && rows.scrollTop + rows.clientHeight > rows.scrollHeight - 200) loadList({ more: true }); });
			}
			listCol.append(rows);
			if (keepScroll) rows.scrollTop = keepScroll;
			const sel = S.selectedId && rows.querySelector(`[data-id="${S.selectedId}"]`);
			if (sel) sel.scrollIntoView({ block: 'nearest' });
		}

		function rowEl(m) {
			const acc = MS.accountOf(S.me, m.accountId);
			const color = acc ? acc.color : 'var(--faint)';
			const now = Date.now();
			const on = S.selectedId === m.id;
			const av = el('span', { class: 'ml-av', text: MS.initials(m.from) });
			av.style.background = color;
			const acts = el('span', { class: 'ml-row-acts' });
			for (const a of MS.rowActions(S.me && S.me.settings, m)) {
				acts.append(el('button', { type: 'button', class: 'ml-ib ml-ib-sm', title: t(a.key), 'aria-label': t(a.key), tabindex: '-1', on: { click: (e) => { e.stopPropagation(); runAction(a.action, [m]); } } }, [icon(a.icon, 15)]));
			}
			const row = el('div', { class: `ml-row${on ? ' on' : ''}${m.unread ? ' is-unread' : ''}`, role: 'option', 'aria-selected': on ? 'true' : 'false', 'data-id': String(m.id), tabindex: on ? '0' : '-1', on: { click: () => openMessage(m.id), contextmenu: (e) => { e.preventDefault(); rowMenu(e, m); } } }, [
				av,
				el('span', { class: 'ml-row-main' }, [
					el('span', { class: 'ml-row-l1' }, [dot(color), el('span', { class: 'ml-row-from', text: MS.senderName(m.from, t) }), m.threadCount > 1 && S.me && S.me.settings.threads ? el('span', { class: 'ml-row-n', text: String(m.threadCount) }) : null, el('span', { class: 'ml-row-time', text: MS.timeLabel(m.date, now, lang(), t) })]),
					el('span', { class: 'ml-row-subj', text: m.subject || t('mail.noSubject') }),
					el('span', { class: 'ml-row-snip', text: m.snippet || '' }),
					m.ai && m.ai.summary && has('ai') ? el('span', { class: 'ml-row-ai' }, [icon('spark', 12), el('span', { text: m.ai.summary })]) : null,
				]),
				el('span', { class: 'ml-row-side' }, [
					m.flagged ? el('span', { class: 'ml-row-flag', title: t('mail.act.flagged') }, [icon('flag', 13)]) : null,
					m.hasAttachments ? el('span', { class: 'ml-row-ic', title: t('mail.hasAttachments') }, [icon('clip', 13)]) : null,
					m.savedToDrive ? el('span', { class: 'ml-row-ic', title: t('mail.drive.saved') }, [icon('cloud', 13)]) : null,
					acts,
				]),
			]);
			return row;
		}

		function onListKey(e) {
			if (!S.items.length) return;
			const i = S.items.findIndex((m) => m.id === S.selectedId);
			if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
				e.preventDefault();
				const next = S.items[Math.max(0, Math.min(S.items.length - 1, i + (e.key === 'ArrowDown' ? 1 : -1)))];
				if (next) openMessage(next.id);
			} else if (e.key === 'Delete' && i >= 0) {
				e.preventDefault();
				runAction('delete', [S.items[i]]);
			}
		}

		function rowMenu(e, m) {
			const items = [
				[m.unread ? 'mail.act.markRead' : 'mail.act.markUnread', m.unread ? 'mailOpen' : 'mail', () => runAction('read', [m])],
				[m.flagged ? 'mail.act.unflag' : 'mail.act.flag', 'flag', () => runAction('flag', [m])],
				['mail.act.archive', 'archive', () => runAction('archive', [m])],
				['mail.act.delete', 'trash', () => runAction('delete', [m])],
				['mail.act.junk', 'junk', () => runAction('junk', [m])],
				[m.tab === 'other' ? 'mail.act.toRelevant' : 'mail.act.toOther', 'tab', () => setTab([m], m.tab === 'other' ? 'relevant' : 'other')],
				['mail.act.move', 'move', () => moveTo([m])],
			];
			popMenu(e.clientX, e.clientY, items);
		}

		function popMenu(x, y, items) {
			const layer = el('div', { class: 'ml-menu-layer', on: { mousedown: (ev) => { if (ev.target === layer) layer.remove(); } } });
			const menu = el('div', { class: 'ml-menu', role: 'menu' });
			for (const [key, ic, fn] of items) {
				menu.append(el('button', { type: 'button', role: 'menuitem', class: 'ml-menu-item', on: { click: () => { layer.remove(); fn(); } } }, [icon(ic, 15), el('span', { text: t(key) })]));
			}
			layer.append(menu);
			document.body.append(layer);
			const r = menu.getBoundingClientRect();
			menu.style.left = `${Math.min(x, window.innerWidth - r.width - 8)}px`;
			menu.style.top = `${Math.min(y, window.innerHeight - r.height - 8)}px`;
			const onKey = (ev) => { if (ev.key === 'Escape') { layer.remove(); document.removeEventListener('keydown', onKey, true); } };
			document.addEventListener('keydown', onKey, true);
			const first = menu.querySelector('button');
			if (first) first.focus();
		}

		// ── Acting on mails ──────────────────────────────

		function dropFromList(ids) {
			const set = new Set(ids);
			const i = S.items.findIndex((m) => set.has(m.id));
			S.items = S.items.filter((m) => !set.has(m.id));
			if (set.has(S.selectedId)) {
				const next = S.items[Math.min(i, S.items.length - 1)];
				S.selectedId = null;
				if (next) openMessage(next.id);
				else { S.pane = 'empty'; S.read = null; renderPane(); }
			}
		}

		async function runAction(action, list) {
			const ids = list.map((m) => m.id);
			const c = MS.actionCall(action, list[0]);
			if (!c) return;
			if (c.flags) {
				const r = await call(api.flags(ids, c.flags));
				if (!r || !r.ok) { toast(errText(r), 'error'); return; }
				for (const m of S.items) if (ids.includes(m.id)) Object.assign(m, c.flags);
				if (S.read && ids.includes(S.read.message.id)) Object.assign(S.read.message, c.flags);
				renderList();
				if (S.pane === 'read') renderPane();
				loadMe().then(renderMenu);
				return;
			}
			const r = await call(api.act(c.act, ids));
			if (!r || !r.ok) { toast(errText(r), 'error'); return; }
			toast(t(`mail.done.${c.act}`, { count: ids.length }), 'success');
			dropFromList(ids);
			renderList();
			loadMe().then(renderMenu);
		}

		async function setTab(list, tab) {
			const ids = list.map((m) => m.id);
			const r = await call(api.act('tab', ids, { tab }));
			if (!r || !r.ok) { toast(errText(r), 'error'); return; }
			toast(t(tab === 'relevant' ? 'mail.done.toRelevant' : 'mail.done.toOther'), 'success');
			if (MS.isInbox(S.view, S.folders)) { dropFromList(ids); renderList(); }
		}

		function moveTo(list) {
			const accountId = list[0].accountId;
			const acc = ((S.folders && S.folders.accounts) || []).find((a) => a.accountId === accountId);
			const dlg = openDialog({ title: t('mail.act.moveTitle'), closeLabel: t('mail.close') });
			const rows = el('div', { class: 'ml-pick-list', role: 'list' });
			for (const { folder, depth } of MS.folderTree(acc ? acc.folders : [])) {
				if (folder.id === list[0].folderId) continue;
				const b = el('button', { type: 'button', role: 'listitem', class: 'ml-pick-row', on: { click: async () => {
					dlg.close();
					const r = await call(api.act('move', list.map((m) => m.id), { folderId: folder.id }));
					if (!r || !r.ok) { toast(errText(r), 'error'); return; }
					toast(t('mail.done.move', { folder: MS.folderName(folder, t) }), 'success');
					dropFromList(list.map((m) => m.id));
					renderList();
				} } }, [icon('folder', 15), el('span', { text: MS.folderName(folder, t) })]);
				b.style.paddingLeft = `${12 + depth * 16}px`;
				rows.append(b);
			}
			dlg.body.append(rows);
			dlg.foot.append(el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }));
		}

		// ── Reading pane (right) ─────────────────────────

		async function openMessage(id, { fromPush = false } = {}) {
			if (S.compose && S.pane === 'compose' && !(await leaveCompose())) return;
			const seq = ++S.readSeq;
			S.selectedId = id;
			S.pane = 'read';
			S.read = { loading: true, message: S.items.find((m) => m.id === id) || null };
			renderList();
			renderPane();
			const r = await call(api.message(id));
			if (seq !== S.readSeq) return;
			if (!r || !r.ok) {
				S.read = { error: errText(r), message: S.read.message };
				renderPane();
				if (fromPush) toast(errText(r), 'error');
				return;
			}
			S.read = { message: r.message, doc: r.doc, docDark: r.docDark, light: false, offline: !!r.offline, ai: null, thread: null, suggest: new Map(), atts: new Map(), attEls: new Map(), pics: null };
			const row = S.items.find((m) => m.id === id);
			if (row && row.unread) { row.unread = false; renderList(); loadMe().then(renderMenu); }
			renderPane();
			if (r.offline) return;
			// a body the provider has not sent yet: AI, conversation and Drive once it is there (refreshBody)
			if (r.message.bodyMissing) { S.read.later = true; return; }
			loadExtras(seq, r.message);
		}

		function loadExtras(seq, m) {
			const acc = MS.accountOf(S.me, m.accountId);
			if (has('ai') && (!acc || acc.ai)) loadAi(seq, m.id);
			if (S.me && S.me.settings.threads && m.threadCount > 1 && m.threadId) loadThread(seq, m.threadId);
			if (has('drive')) loadSuggestions(seq, m);
		}

		/** The open mail again (its body has come: the live event, or "Erneut versuchen"); not marked read again. */
		async function refreshBody(id) {
			const R = S.read;
			if (!R || !R.message || R.message.id !== id || R.bodyBusy) return;
			const seq = S.readSeq;
			R.bodyBusy = true;
			renderPane();
			const r = await call(api.message(id, { markRead: false }));
			if (seq !== S.readSeq || S.read !== R) return;
			R.bodyBusy = false;
			if (r && r.ok) {
				R.message = r.message;
				R.doc = r.doc;
				R.docDark = r.docDark;
				R.offline = !!r.offline;
			}
			renderPane();
			if (r && r.ok && R.later && !r.message.bodyMissing && !r.offline) {
				R.later = false;
				loadExtras(seq, r.message);
			}
		}

		// ── Embedded pictures the provider still sends (cid, 409 busy) ──

		function setPicsNote(R, on) {
			R.pics.show = on;
			if (R.picsNote) R.picsNote.hidden = !on;
		}

		/** The frame asks for its pictures again (those it has are kept by the core). */
		function reloadPictures(R) {
			if (!R || !R.pics) return;
			clearTimeout(R.pics.timer);
			R.pics.timer = null;
			R.pics.waiting.clear();
			setPicsNote(R, false);
			if (R.frame && R.frame.isConnected) R.frame.srcdoc = MS.frameDoc(R, R.frameDark);
		}

		/** mail:loading { messageId, attachmentId, retryAfter }: asked again after retryAfter (a few times) or with the live event. */
		function onPictureLoading(x) {
			const R = S.read;
			if (!R || !R.message || !x || x.messageId !== R.message.id) return;
			if (!R.pics) R.pics = { waiting: new Set(), tries: 0, timer: null, show: false };
			const P = R.pics;
			if (x.attachmentId) P.waiting.add(x.attachmentId);
			if (P.tries >= MS.BUSY_RETRIES) { setPicsNote(R, false); return; }
			setPicsNote(R, true);
			if (P.timer) return;
			const wait = Math.min(60, Math.max(1, Number(x.retryAfter) || 5)) * 1000;
			P.timer = setTimeout(() => {
				P.timer = null;
				if (S.read !== R) return;
				P.tries++;
				reloadPictures(R);
			}, wait);
		}
		api.onLoading && api.onLoading(onPictureLoading);

		async function loadAi(seq, id) {
			let r = await call(api.ai(id));
			if (seq !== S.readSeq) return;
			if (r && r.ok && r.ai.status === 'none') {
				S.read.aiBusy = true;
				renderPane();
				r = await call(api.runAi(id));
				if (seq !== S.readSeq) return;
				S.read.aiBusy = false;
			}
			if (r && r.ok) S.read.ai = r.ai;
			else if (r && r.code !== 'ai_off') S.read.aiError = errText(r);
			renderPane();
		}

		/** The conversation's mails (GET threads/<id>, oldest first, the open one among them). */
		async function loadThread(seq, threadId) {
			const R = S.read;
			if (!R || R.threadBusy) return;
			R.threadBusy = true;
			const r = await call(api.thread(threadId));
			if (seq !== S.readSeq || S.read !== R) return;
			R.threadBusy = false;
			if (r && r.ok) R.thread = r.items;
			else if (R.threadOpen) toast(errText(r), 'error');
			renderPane();
		}

		/** "Unterhaltung · n Mails": all its mails show (loaded now when not yet) or fold again. */
		function toggleThread() {
			const R = S.read;
			if (!R || !R.message) return;
			R.threadOpen = !R.threadOpen;
			if (R.threadOpen && !R.thread && R.message.threadId) loadThread(S.readSeq, R.message.threadId);
			renderPane();
		}

		async function loadSuggestions(seq, message) {
			const list = message.attachments.filter((a) => !a.inline && !a.savedTo && !a.suggestion).slice(0, 3);
			for (const a of list) {
				const r = await call(api.suggest(message.id, a.id));
				if (seq !== S.readSeq) return;
				if (r && r.ok) S.read.suggest.set(a.id, { suggestion: r.suggestion, duplicate: r.duplicate });
			}
			if (list.length) renderPane();
		}

		function renderPane() {
			if (S.compose && S.compose.frame && S.compose.frame.isConnected) editorHtml();
			clear(pane);
			if (S.view.kind === 'filing' || S.view.kind === 'outbox') { pane.hidden = S.pane !== 'compose'; if (S.pane === 'compose') renderCompose(); return; }
			pane.hidden = false;
			if (S.pane === 'compose' && S.compose) { renderCompose(); return; }
			if (S.pane === 'sender' && S.sender) { renderSender(); return; }
			if (S.pane !== 'read' || !S.read) {
				pane.append(el('div', { class: 'ml-empty ml-pane-empty' }, [icon('mail', 34, '1.6'), el('p', { class: 'ml-p', text: t('mail.pickOne') })]));
				return;
			}
			const R = S.read;
			const m = R.message;
			if (R.loading || R.error) {
				pane.append(el('div', { class: 'ml-empty ml-pane-empty' }, [el('p', { class: 'ml-p', text: R.error || t('mail.loading') })]));
				return;
			}
			const acc = MS.accountOf(S.me, m.accountId);
			const bar = el('div', { class: 'ml-read-bar', role: 'toolbar', 'aria-label': t('mail.actions') });
			const tb = (ic, key, fn, primary) => el('button', { type: 'button', class: primary ? 'btn btn-sec btn-sm ml-read-btn' : 'ml-ib', title: t(key), 'aria-label': t(key), on: { click: fn } }, primary ? [icon(ic, 15), el('span', { text: t(key) })] : [icon(ic, 16)]);
			bar.append(...[
				tb('reply', 'mail.reply', () => openCompose({ mode: 'reply', message: m }), true),
				MS.canReplyAll(m, S.me) ? tb('replyAll', 'mail.replyAll', () => openCompose({ mode: 'replyAll', message: m }), true) : null,
				tb('forward', 'mail.forward', () => openCompose({ mode: 'forward', message: m }), true),
				el('span', { class: 'ml-grow' }),
				tb('archive', 'mail.act.archive', () => runAction('archive', [m])),
				tb('trash', 'mail.act.delete', () => runAction('delete', [m])),
				tb('junk', 'mail.act.junk', () => runAction('junk', [m])),
				tb(m.unread ? 'mailOpen' : 'mail', m.unread ? 'mail.act.markRead' : 'mail.act.markUnread', () => runAction('read', [m])),
				tb('flag', m.flagged ? 'mail.act.unflag' : 'mail.act.flag', () => runAction('flag', [m])),
				// "Hell anzeigen": this mail light as it was made (while the app is dark and mails are shown dark)
				appDark() && darkMails() && (R.docDark || (R.thread || []).some((x) => x.docDark))
					? tb(R.light ? 'moon' : 'sun', R.light ? 'mail.read.showDark' : 'mail.read.showLight', () => { R.light = !R.light; renderPane(); })
					: null,
				tb('more', 'mail.more', (e) => {
					const r = e.currentTarget.getBoundingClientRect();
					popMenu(r.left, r.bottom + 4, [
						['mail.act.move', 'move', () => moveTo([m])],
						[m.tab === 'other' ? 'mail.act.toRelevant' : 'mail.act.toOther', 'tab', () => setTab([m], m.tab === 'other' ? 'relevant' : 'other')],
					]);
				}),
			].filter(Boolean));
			const scroll = el('div', { class: 'ml-read' });
			if (R.offline) scroll.append(el('div', { class: 'ml-banner' }, [icon('offline', 15), el('span', { text: t('mail.offlineMail') })]));
			scroll.append(el('h2', { class: 'ml-read-subj', text: m.subject || t('mail.noSubject') }));
			// the conversation: its line (a tap shows all its mails), the mails before this one above, those after it below
			const conv = S.me && S.me.settings.threads && m.threadCount > 1 && m.threadId ? MS.conversation(R.thread || [], m.id) : null;
			if (conv) {
				const count = Math.max(m.threadCount, (R.thread || []).length);
				const names = MS.participants(R.thread && R.thread.length ? R.thread : [m], t);
				scroll.append(el('button', { type: 'button', class: `ml-conv${R.threadOpen ? ' open' : ''}`, 'aria-expanded': R.threadOpen ? 'true' : 'false', title: t(R.threadOpen ? 'mail.thread.hide' : 'mail.thread.show'), on: { click: toggleThread } }, [
					el('span', { class: 'ml-conv-tx' }, [el('span', { class: 'ml-sub', text: t('mail.thread.count', { count }) }), el('span', { class: 'ml-conv-names', text: names.join(', ') })]),
					R.threadOpen && R.threadBusy ? el('span', { class: 'ml-sub', text: t('mail.loading') }) : null,
					el('span', { class: 'ml-conv-ic' }, [icon('chevDown', 14)]),
				]));
				if (R.threadOpen) for (const x of conv.older) scroll.append(threadCard(x));
			}
			const toLine = [...m.to, ...m.cc].map((a) => MS.senderName(a, t)).slice(0, 6).join(', ');
			scroll.append(el('div', { class: 'ml-read-from' }, [
				dot(acc ? acc.color : null),
				m.from.email
					? el('button', { type: 'button', class: 'ml-read-name ml-read-sender', title: t('mail.sender.show'), on: { click: () => openSender(m) } }, [el('span', { text: MS.senderName(m.from, t) })])
					: el('span', { class: 'ml-read-name', text: MS.senderName(m.from, t) }),
				m.from.email && m.from.name ? el('span', { class: 'ml-read-addr', text: `<${m.from.email}>` }) : null,
				el('span', { class: 'ml-grow' }),
				el('span', { class: 'ml-read-date', text: MS.fullDate(m.date, lang()) }),
			]));
			scroll.append(el('div', { class: 'ml-read-to', text: `${t('mail.to', { name: acc ? acc.name : '' })}${toLine ? ` · ${toLine}` : ''}` }));
			// AI bar
			if (has('ai') && (R.ai || R.aiBusy || R.aiError)) scroll.append(aiCard(m, R));
			// attachments
			const atts = m.attachments.filter((a) => !a.inline);
			if (atts.length) {
				const box = el('div', { class: 'ml-atts' });
				for (const a of atts) box.append(attCard(m, a, R));
				if (atts.length > 1 && has('drive') && atts.some((a) => !a.savedTo)) {
					box.append(el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => saveAll(m) } }, [icon('cloud', 14), el('span', { text: t('mail.drive.saveAll') })]));
				}
				scroll.append(box);
			}
			if (m.imagesBlocked) {
				scroll.append(el('div', { class: 'ml-banner is-info' }, [
					icon('image', 15),
					el('span', { class: 'ml-grow', text: t('mail.images.blocked') }),
					el('button', { type: 'button', class: 'btn btn-sec btn-xs', text: t('mail.images.once'), on: { click: () => allowImages(m, 'once') } }),
					m.from.email ? el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('mail.images.sender'), on: { click: () => allowImages(m, 'sender') } }) : null,
				]));
			}
			if (m.bodyMissing) {
				// the provider has not sent the body yet (the snippet below): it comes with the live event
				scroll.append(el('div', { class: 'ml-banner is-info' }, [
					icon('clock', 15),
					el('span', { class: 'ml-grow', text: t('mail.bodyMissing') }),
					el('button', { type: 'button', class: 'btn btn-sec btn-xs', text: R.bodyBusy ? t('mail.loading') : t('mail.retry'), disabled: R.bodyBusy || null, on: { click: () => refreshBody(m.id) } }),
				]));
			}
			R.picsNote = el('div', { class: 'ml-read-note', hidden: !(R.pics && R.pics.show) }, [icon('image', 13), el('span', { text: t('mail.picturesLoading') })]);
			scroll.append(R.picsNote);
			R.frame = null;
			if (!m.bodyMissing || m.html || m.text) {
				R.frameDark = readDark();
				R.frame = mailFrame(MS.frameDoc(R, R.frameDark), { title: m.subject || t('mail.noSubject'), dark: R.frameDark });
				scroll.append(el('div', { class: `ml-frame-wrap${R.frameDark ? ' is-dark' : ''}` }, [R.frame]));
			}
			const notes = [];
			if (m.trackers > 0) notes.push(t('mail.trackers', { count: m.trackers }));
			if (!m.imagesBlocked && /gcmail:\/\/img\//.test(R.doc || '')) notes.push(t('mail.images.proxied'));
			const foot = el('div', { class: 'ml-read-foot' });
			if (notes.length) foot.append(el('span', { class: 'ml-read-note' }, [icon('shield', 13), el('span', { text: notes.join(' · ') })]));
			if (m.listUnsubscribe && m.listUnsubscribe.url) {
				foot.append(el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('mail.unsubscribe'), title: m.listUnsubscribe.url, on: { click: () => { if (window.gatecontrol && window.gatecontrol.shell) window.gatecontrol.shell.openExternal(m.listUnsubscribe.url); } } }));
			} else if (m.listUnsubscribe && m.listUnsubscribe.mail) {
				foot.append(el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('mail.unsubscribe'), title: m.listUnsubscribe.mail, on: { click: () => openCompose({ to: [{ name: null, email: m.listUnsubscribe.mail }], subject: 'unsubscribe', accountId: m.accountId }) } }));
			}
			if (foot.childNodes.length) scroll.append(foot);
			if (conv && R.threadOpen) for (const x of conv.newer) scroll.append(threadCard(x));
			// reply suggestions
			const replies = R.ai && R.ai.status === 'done' ? R.ai.replies : [];
			const bottom = el('div', { class: 'ml-read-bottom' });
			if (replies.length) {
				bottom.append(el('span', { class: 'ml-sub', text: t('mail.ai.replies') }));
				const row = el('div', { class: 'ml-sugs' });
				for (const r of replies) row.append(el('button', { type: 'button', class: 'ml-sug', title: r.text, text: r.label, on: { click: () => openCompose({ mode: 'reply', message: m, text: r.text }) } }));
				bottom.append(row);
				scroll.append(bottom);
			}
			pane.append(bar, scroll);
		}

		function aiCard(m, R) {
			const card = el('div', { class: 'ml-card ml-ai' });
			card.append(el('span', { class: 'ml-ai-h' }, [icon('spark', 14), el('span', { text: t('mail.ai.short') })]));
			if (R.aiBusy) { card.append(el('span', { class: 'ml-sub', text: t('mail.ai.working') })); return card; }
			if (R.aiError) { card.append(el('span', { class: 'ml-sub', text: R.aiError })); return card; }
			const ai = R.ai;
			card.firstChild.append(el('button', { type: 'button', class: 'btn btn-ghost btn-xs ml-ai-again', text: t('mail.ai.again'), on: { click: async () => {
				const id = m.id;
				R.aiBusy = true;
				renderPane();
				const r = await call(api.runAi(id, true));
				if (!S.read || S.read.message.id !== id) return;
				S.read.aiBusy = false;
				if (r && r.ok) S.read.ai = r.ai;
				else toast(errText(r), 'error');
				renderPane();
			} } }));
			if (ai.summary) card.append(el('p', { class: 'ml-ai-sum', text: ai.summary }));
			else if (!ai.todos.length) card.append(el('span', { class: 'ml-sub', text: t('mail.ai.nothing') }));
			const chips = MS.todoChips(ai, features());
			if (chips.length) {
				const row = el('div', { class: 'ml-ai-todos' });
				for (const c of chips) {
					if (c.calendar) {
						row.append(el('button', { type: 'button', class: 'ml-chip ml-todo', title: t('mail.ai.toCalendar'), on: { click: async (e) => {
							const b = e.currentTarget;
							b.disabled = true;
							const r = await call(api.todo(m.id, c.index));
							b.disabled = false;
							if (r && r.ok) { toast(t('mail.ai.inCalendar', { where: r.where || '' }), 'success'); b.classList.add('on'); }
							else toast(errText(r), 'error');
						} } }, [icon('calendar', 14), el('span', { text: c.text })]));
					} else {
						row.append(el('span', { class: 'ml-chip ml-todo is-static' }, [icon(c.kind === 'question' ? 'reply' : c.kind === 'amount' ? 'file' : 'check', 14), el('span', { text: c.text })]));
					}
				}
				card.append(row);
			}
			return card;
		}

		function attCard(m, a, R) {
			const attSub = el('span', { class: 'ml-sub' });
			if (R.attEls) R.attEls.set(a.id, attSub);
			attLabel(R, a);
			const ft = MS.fileTag(a.name, a.mime);
			const tag = el('span', { class: 'ml-ftag', text: ft.tag });
			const [bg, fg] = TONE[ft.tone] || TONE.muted;
			tag.style.background = bg;
			tag.style.color = fg;
			const card = el('div', { class: 'ml-card ml-att' });
			card.append(el('div', { class: 'ml-att-top' }, [
				tag,
				el('span', { class: 'ml-att-tx' }, [el('span', { class: 'ml-att-name', text: a.name, title: a.name }), attSub]),
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.att.open'), 'aria-label': t('mail.att.open'), on: { click: () => openAtt(m, a) } }, [icon('open', 15)]),
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.att.save'), 'aria-label': t('mail.att.save'), on: { click: () => saveAtt(m, a) } }, [icon('down', 15)]),
			]));
			if (!has('drive')) return card;
			if (a.savedTo) {
				card.append(el('div', { class: 'ml-att-saved' }, [icon('check', 14), el('span', { text: t('mail.drive.savedIn', { where: a.savedTo.where || '' }) })]));
				return card;
			}
			const extra = R.suggest.get(a.id);
			const s = a.suggestion || (extra && extra.suggestion) || null;
			if (extra && extra.duplicate) card.append(el('span', { class: 'ml-sub', text: t('mail.drive.duplicate') }));
			if (s) {
				card.append(el('div', { class: 'ml-att-sug' }, [
					el('span', { class: 'ml-sub', text: t('mail.drive.saveAs') }),
					el('span', { class: 'ml-att-sugname', text: s.name || a.name }),
					el('span', { class: 'ml-sub', text: MS.suggestionLine(s, t) }),
				]));
			}
			const remember = el('input', { type: 'checkbox', class: 'ml-check' });
			const sender = MS.senderName(m.from, t);
			card.append(el('div', { class: 'ml-att-acts' }, [
				el('button', { type: 'button', class: 'btn btn-pri btn-sm ml-grow', text: t('mail.drive.save'), on: { click: () => saveToDrive(m, a, { folderId: s ? null : undefined, remember: remember.checked }, !s) } }),
				el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('mail.drive.other'), on: { click: () => saveToDrive(m, a, { remember: remember.checked }, true) } }),
			]));
			if (m.from.email) card.append(el('label', { class: 'ml-check-row' }, [remember, el('span', { text: t('mail.drive.remember', { sender }) })]));
			return card;
		}

		/** Another mail of the conversation: sender, date and preview; unfolds to its body and "Mail öffnen". */
		function threadCard(x) {
			const card = el('details', { class: 'ml-card ml-thread', 'data-id': String(x.id) });
			const acc = MS.accountOf(S.me, x.accountId);
			const av = el('span', { class: 'ml-av ml-av-sm', text: MS.initials(x.from) });
			av.style.background = acc ? acc.color : 'var(--faint)';
			card.append(el('summary', { class: 'ml-thread-h' }, [
				av,
				el('span', { class: 'ml-read-name', text: MS.senderName(x.from, t) }),
				el('span', { class: 'ml-row-snip ml-grow', text: x.snippet || '' }),
				el('span', { class: 'ml-read-date', text: MS.timeLabel(x.date, Date.now(), lang(), t) }),
			]));
			card.addEventListener('toggle', () => {
				if (card.open && !card.querySelector('iframe')) {
					const dark = readDark();
					card.append(mailFrame(MS.frameDoc(x, dark), { title: x.subject || '', dark }));
					card.append(el('div', { class: 'ml-thread-foot' }, [el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('mail.thread.open'), on: { click: () => openMessage(x.id) } })]));
				}
			}, { once: false });
			return card;
		}

		// ── A sender (a tap on the sender of a mail) ─────

		/** The sender's page: who it is (the contacts' name when there is one), "Mail schreiben", "Adresse kopieren", their mails in the account. */
		async function openSender(m) {
			const email = m.from && m.from.email;
			if (!email) return;
			const seq = ++S.senderSeq;
			S.sender = { email, name: m.from.name || null, accountId: m.accountId, contact: null, items: [], next: null, loading: true, error: null, back: S.read };
			S.pane = 'sender';
			renderPane();
			call(api.contacts(email)).then((r) => {
				if (seq !== S.senderSeq || !S.sender || !r || !r.ok) return;
				S.sender.contact = MS.contactOf(r.items, email);
				if (S.pane === 'sender') renderPane();
			});
			await loadSender(seq);
		}

		async function loadSender(seq, more = false) {
			const P = S.sender;
			if (!P) return;
			P.loading = true;
			const r = await call(api.search({ from: P.email, box: P.accountId || undefined, cursor: more ? P.next : undefined }));
			if (seq !== S.senderSeq || S.sender !== P) return;
			P.loading = false;
			if (r && r.ok) {
				const got = MS.fromSender(r.items, P.email);
				P.items = more ? MS.mergeItems(P.items, got) : got;
				P.next = r.next || null;
				P.error = null;
			} else P.error = errText(r);
			if (S.pane === 'sender') renderPane();
		}

		function renderSender() {
			const P = S.sender;
			const acc = MS.accountOf(S.me, P.accountId);
			const name = (P.contact && P.contact.name) || P.name || P.email;
			const bar = el('div', { class: 'ml-read-bar', role: 'toolbar', 'aria-label': t('mail.actions') }, [
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.sender.back'), 'aria-label': t('mail.sender.back'), on: { click: () => { S.pane = S.read ? 'read' : 'empty'; renderPane(); } } }, [icon('back', 16)]),
				el('span', { class: 'ml-sub', text: t('mail.sender.title') }),
			]);
			const scroll = el('div', { class: 'ml-read ml-sender' });
			const av = el('span', { class: 'ml-av ml-av-lg', text: MS.initials({ name: name === P.email ? null : name, email: P.email }) });
			av.style.background = acc ? acc.color : 'var(--faint)';
			scroll.append(el('div', { class: 'ml-sender-head' }, [
				av,
				el('span', { class: 'ml-sender-tx' }, [
					el('h2', { class: 'ml-read-subj ml-sender-name', text: name }),
					name !== P.email ? el('span', { class: 'ml-read-addr ml-sender-mail', text: P.email }) : null,
					// the place for what the person's contacts know (the coming contacts plugin); for now that they are one
					P.contact ? el('span', { class: 'ml-sub ml-sender-contact', text: t('mail.sender.inContacts') }) : null,
				]),
			]));
			scroll.append(el('div', { class: 'ml-sender-acts' }, [
				el('button', { type: 'button', class: 'btn btn-pri btn-sm', on: { click: () => openCompose({ to: [{ name: P.name, email: P.email }], accountId: P.accountId }) } }, [icon('pen', 15), el('span', { text: t('mail.sender.write') })]),
				el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => {
					const done = () => toast(t('mail.sender.copied'), 'success');
					if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(P.email).then(done).catch(() => toast(t('mail.err.failed'), 'error'));
				} } }, [icon('copy', 15), el('span', { text: t('mail.sender.copy') })]),
			]));
			scroll.append(el('h3', { class: 'ml-lab ml-sender-lab', text: acc ? t('mail.sender.mailsIn', { name: acc.name }) : t('mail.sender.mails') }));
			const rows = el('div', { class: 'ml-rows ml-sender-rows', role: 'listbox', 'aria-label': t('mail.sender.mails') });
			for (const x of P.items) rows.append(rowEl(x));
			if (P.loading) rows.append(el('div', { class: 'ml-empty' }, [el('p', { class: 'ml-p', text: t('mail.loading') })]));
			else if (P.error && !P.items.length) rows.append(el('div', { class: 'ml-empty' }, [el('p', { class: 'ml-p', text: P.error }), el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.retry'), on: { click: () => loadSender(S.senderSeq) } })]));
			else if (!P.items.length) rows.append(el('div', { class: 'ml-empty' }, [el('p', { class: 'ml-p', text: t('mail.sender.none') })]));
			else if (P.next) rows.append(el('button', { type: 'button', class: 'btn btn-ghost btn-sm ml-more', text: t('mail.more'), on: { click: () => loadSender(S.senderSeq, true) } }));
			scroll.append(rows);
			pane.append(bar, scroll);
		}

		async function allowImages(m, allow) {
			const r = await call(api.allowImages(m.id, allow));
			if (!r || !r.ok) { toast(errText(r), 'error'); return; }
			if (S.read && S.read.message.id === m.id) {
				S.read.message = r.message;
				S.read.doc = r.doc;
				S.read.docDark = r.docDark;
				renderPane();
			}
			if (allow === 'sender') toast(t('mail.images.senderDone', { sender: MS.senderName(m.from, t) }), 'success');
		}

		/** The size below an attachment's name, "Wird gerade geladen …" while it is fetched or still on its way. */
		function attLabel(R, a) {
			const e = R && R.attEls && R.attEls.get(a.id);
			if (e) e.textContent = R.atts && R.atts.has(a.id) ? t('mail.att.loading') : MS.bytes(a.size, lang());
		}

		/**
		 * Opens an attachment. While the provider still sends it (409 busy, reason 'loading') it shows "Wird gerade
		 * geladen …" and asks again after retryAfter (MS.BUSY_RETRIES times) or at once with the live event.
		 */
		async function openAtt(m, a) {
			const R = S.read;
			if (!R || !R.atts || R.atts.has(a.id)) return;
			const w = { tries: 0, timer: null, inFlight: false, run: null };
			w.run = async () => {
				clearTimeout(w.timer);
				w.timer = null;
				w.inFlight = true;
				const r = await call(api.openAttachment(m.id, a.id, { name: a.name, mime: a.mime }));
				w.inFlight = false;
				if (S.read !== R) return;
				const b = MS.busyRetry(r);
				if (b && b.loading && w.tries < MS.BUSY_RETRIES) {
					w.tries++;
					w.timer = setTimeout(w.run, b.waitMs);
					return;
				}
				R.atts.delete(a.id);
				attLabel(R, a);
				if (r && r.ok) return;
				if (r && r.code === 'unsafe') { toast(t('mail.att.unsafe'), 'error'); return; }
				toast(attErr(r), 'error');
			};
			R.atts.set(a.id, w);
			attLabel(R, a);
			w.run();
		}

		async function saveAtt(m, a) {
			const r = await call(api.saveAttachment(m.id, a.id, { name: a.name }));
			if (r && r.ok) toast(t('mail.att.saved'), 'success');
			else if (r && r.code !== 'cancelled') toast(attErr(r), 'error');
		}

		async function pickDriveFolder(title) {
			if (!o.driveView || !o.driveApi) return null;
			return o.driveView.pickFolder({ api: o.driveApi, t, title, confirm: t('mail.drive.pickHere') });
		}

		async function saveToDrive(m, a, opts, pick) {
			let folderId = null;
			if (pick) {
				const p = await pickDriveFolder(t('mail.drive.pickTitle'));
				if (!p || !p.folderId) return;
				folderId = p.folderId;
			}
			const r = await call(api.saveToDrive(m.id, a.id, { folderId, remember: opts.remember === true }));
			if (!r || !r.ok) { toast(attErr(r), 'error'); return; }
			a.savedTo = r.savedTo;
			toast(t('mail.drive.savedIn', { where: r.savedTo.where || '' }), 'success');
			const row = S.items.find((x) => x.id === m.id);
			if (row) row.savedToDrive = true;
			if (S.read && S.read.message.id === m.id) renderPane();
		}

		async function saveAll(m) {
			const r = await call(api.saveAll(m.id));
			if (!r || !r.ok) { toast(errText(r), 'error'); return; }
			for (const s of r.saved) { const a = m.attachments.find((x) => x.id === s.attachmentId); if (a) a.savedTo = s.savedTo; }
			toast(r.failed.length ? t('mail.drive.savedSome', { saved: r.saved.length, failed: r.failed.length }) : t('mail.drive.savedAll', { count: r.saved.length }), r.failed.length ? 'info' : 'success');
			if (S.read && S.read.message.id === m.id) renderPane();
		}

		// ── Zum Ablegen ──────────────────────────────────

		function renderFiling() {
			clear(listCol);
			const head = MS.viewTitle(S.view, S.me, S.folders, t);
			const allBtn = S.filing.some((f) => f.suggestion) ? el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('mail.filing.all'), on: { click: () => fileAll() } }) : null;
			listCol.append(el('div', { class: 'ml-head' }, [el('div', { class: 'ml-head-tx' }, [el('h1', { class: 'ml-h', text: head.title })]), allBtn]));
			listCol.append(el('p', { class: 'ml-p ml-filing-intro', text: t('mail.filing.intro') }));
			const rows = el('div', { class: 'ml-rows ml-filing' });
			if (!S.filing.length) rows.append(el('div', { class: 'ml-empty' }, [icon('check', 26), el('p', { class: 'ml-p', text: t('mail.filing.empty') })]));
			for (const f of S.filing) {
				const acc = MS.accountOf(S.me, f.accountId);
				const ft = MS.fileTag(f.name, null);
				const tag = el('span', { class: 'ml-ftag', text: ft.tag });
				const [bg, fg] = TONE[ft.tone] || TONE.muted;
				tag.style.background = bg;
				tag.style.color = fg;
				const pct = MS.confidence(f.suggestion);
				rows.append(el('div', { class: 'ml-card ml-file' }, [
					el('div', { class: 'ml-att-top' }, [tag, el('span', { class: 'ml-att-tx' }, [
						el('span', { class: 'ml-att-name', text: f.name }),
						el('span', { class: 'ml-sub ml-file-from' }, [dot(acc ? acc.color : null), el('span', { text: [MS.senderName(f.from, t), acc ? acc.name : null].filter(Boolean).join(' · ') })]),
					])]),
					f.suggestion ? el('span', { class: 'ml-sub' }, [t('mail.filing.suggestion'), ' ', el('b', { text: f.suggestion.path || f.suggestion.where || '' }), pct !== null ? ` · ${t('mail.drive.sure', { pct })}` : '']) : el('span', { class: 'ml-sub', text: t('mail.filing.noSuggestion') }),
					el('div', { class: 'ml-att-acts' }, [
						f.suggestion ? el('button', { type: 'button', class: 'btn btn-pri btn-sm', text: t('mail.filing.file'), on: { click: () => fileOne(f, null) } }) : null,
						el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('mail.drive.other'), on: { click: async () => { const p = await pickDriveFolder(t('mail.drive.pickTitle')); if (p && p.folderId) fileOne(f, p.folderId); } } }),
						el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('mail.filing.dismiss'), on: { click: () => dismissOne(f) } }),
					]),
				]));
			}
			const auto = ((S.me && S.me.accounts) || []).map((a) => `${a.name}: ${t(`mail.settings.attachments.${a.attachments}`)}`).join(' · ');
			if (auto) rows.append(el('p', { class: 'ml-note', text: t('mail.filing.perAccount', { list: auto }) }));
			listCol.append(rows);
		}

		async function fileOne(f, folderId) {
			const r = await call(api.confirmFiling(f.id, folderId ? { folderId } : {}));
			if (!r || !r.ok) { toast(errText(r), 'error'); return false; }
			S.filing = S.filing.filter((x) => x.id !== f.id);
			toast(t('mail.drive.savedIn', { where: r.savedTo.where || '' }), 'success');
			renderFiling();
			renderMenu();
			return true;
		}

		async function fileAll() {
			for (const f of S.filing.filter((x) => x.suggestion)) {
				const r = await call(api.confirmFiling(f.id, {}));
				if (!r || !r.ok) { toast(errText(r), 'error'); break; }
				S.filing = S.filing.filter((x) => x.id !== f.id);
			}
			renderFiling();
			renderMenu();
		}

		async function dismissOne(f) {
			const r = await call(api.dismissFiling(f.id));
			if (!r || !r.ok) { toast(errText(r), 'error'); return; }
			S.filing = S.filing.filter((x) => x.id !== f.id);
			renderFiling();
			renderMenu();
		}

		// ── Postausgang ──────────────────────────────────

		function renderOutbox() {
			clear(listCol);
			listCol.append(el('div', { class: 'ml-head' }, [el('div', { class: 'ml-head-tx' }, [el('h1', { class: 'ml-h', text: t('mail.outbox.title') })])]));
			const rows = el('div', { class: 'ml-rows ml-filing' });
			if (!S.outbox.length) rows.append(el('div', { class: 'ml-empty' }, [icon('check', 26), el('p', { class: 'ml-p', text: t('mail.outbox.empty') })]));
			for (const x of S.outbox) {
				const acc = MS.accountOf(S.me, x.accountId);
				const st = x.state === 'failed' ? t('mail.outbox.failed', { error: x.error || '' }) : x.state === 'sending' ? t('mail.outbox.sending') : t('mail.outbox.waiting', { at: MS.fullDate(x.sendAt, lang()) });
				rows.append(el('div', { class: `ml-card ml-file${x.state === 'failed' ? ' is-failed' : ''}` }, [
					el('div', { class: 'ml-att-top' }, [icon(x.state === 'failed' ? 'alert' : 'clock', 18), el('span', { class: 'ml-att-tx' }, [
						el('span', { class: 'ml-att-name', text: x.subject || t('mail.noSubject') }),
						el('span', { class: 'ml-sub ml-file-from' }, [dot(acc ? acc.color : null), el('span', { text: [acc ? acc.name : null, st].filter(Boolean).join(' · ') })]),
					])]),
					x.state !== 'sending' ? el('div', { class: 'ml-att-acts' }, [el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('mail.outbox.edit'), on: { click: () => takeBack(x.id) } })]) : null,
				]));
			}
			listCol.append(rows);
		}

		async function takeBack(outboxId) {
			const r = await call(api.cancelSend(outboxId));
			if (!r || !r.ok) { toast(errText(r), 'error'); return; }
			if (S.undo && S.undo.outboxId === outboxId) endUndo();
			loadOutbox();
			if (r.draft) openCompose({ draft: r.draft });
			else toast(t('mail.outbox.back'), 'success');
		}

		// ── Undo bar ─────────────────────────────────────

		function endUndo() {
			if (!S.undo) return;
			clearInterval(S.undo.timer);
			S.undo = null;
			undoBar.hidden = true;
			clear(undoBar);
		}

		function startUndo(r) {
			endUndo();
			const scheduled = r.sendAt && r.sendAt > r.undoUntil + 1000;
			S.undo = { outboxId: r.outboxId, until: scheduled ? Date.now() + 10000 : r.undoUntil, sendAt: r.sendAt, scheduled, timer: null };
			const text = el('span', { class: 'ml-grow' });
			const btn = el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('mail.undo'), on: { click: () => takeBack(r.outboxId) } });
			clear(undoBar);
			undoBar.append(icon(scheduled ? 'clock' : 'send', 16), text, btn);
			undoBar.hidden = false;
			const tick = () => {
				const left = MS.undoLeft(S.undo.until, Date.now());
				if (left <= 0) { endUndo(); if (!scheduled) loadOutbox(); return; }
				text.textContent = scheduled ? t('mail.scheduled', { at: MS.fullDate(r.sendAt, lang()) }) : t('mail.sending', { s: left });
			};
			tick();
			S.undo.timer = setInterval(tick, 250);
		}

		// ── Writing ──────────────────────────────────────

		function defaultAccountId() {
			const accs = (S.me && S.me.accounts) || [];
			const v = S.lastBox;
			if (v.box !== 'all' && accs.some((a) => a.id === v.box)) return v.box;
			return accs.length ? accs[0].id : null;
		}

		/**
		 * Opens the editor: { mode, message, text } (reply / reply all / forward, prefilled by the server), { draft }
		 * (a draft again), { to, subject, accountId } (new).
		 */
		async function openCompose(x) {
			if (S.compose && !(await leaveCompose())) return;
			const accs = (S.me && S.me.accounts) || [];
			if (!accs.length) { openAddAccount(); return; }
			const C = {
				draftId: null, accountId: x.accountId || defaultAccountId(), to: x.to || [], cc: [], bcc: [], subject: x.subject || '',
				atts: [], warnings: [], mode: x.mode || null, html: '', dirty: false, saving: null, uploading: 0, frame: null, showCc: false, title: t('mail.compose.new'),
			};
			const acc = () => MS.accountOf(S.me, C.accountId);
			if (x.draft) {
				Object.assign(C, { draftId: x.draft.id, accountId: x.draft.accountId || C.accountId, to: x.draft.to, cc: x.draft.cc, bcc: x.draft.bcc, subject: x.draft.subject, atts: x.draft.attachments, warnings: x.draft.warnings, html: x.draft.html, title: t('mail.compose.draft') });
			} else if (x.mode && x.message) {
				const body = { replyTo: x.message.id, mode: x.mode };
				if (x.mode === 'forward') body.attachments = x.message.attachments.filter((a) => !a.inline).map((a) => ({ messageId: x.message.id, attachmentId: a.id }));
				S.compose = { busy: true, title: t(`mail.compose.${x.mode}`) };
				S.pane = 'compose';
				renderPane();
				const r = await call(api.createDraft(body));
				if (!r || !r.ok) { S.compose = null; S.pane = S.read ? 'read' : 'empty'; renderPane(); toast(errText(r), 'error'); return; }
				const d = r.draft;
				Object.assign(C, { draftId: d.id, accountId: d.accountId || x.message.accountId, to: d.to, cc: d.cc, bcc: d.bcc, subject: d.subject, atts: d.attachments, warnings: d.warnings, title: t(`mail.compose.${x.mode}`) });
				const a = acc();
				C.html = (x.text ? MS.textToHtml(x.text) : '<p><br></p>') + MS.signatureHtml(a && a.signature) + d.html;
				C.dirty = !!x.text;
			} else {
				const a = acc();
				C.html = `<p><br></p>${MS.signatureHtml(a && a.signature)}`;
			}
			C.showCc = C.cc.length > 0 || C.bcc.length > 0;
			S.compose = C;
			S.pane = 'compose';
			const doc = await call(api.editor(C.html));
			C.doc = doc && doc.ok ? doc.doc : '';
			C.docHtml = C.html;
			renderPane();
			if (C.dirty) scheduleSave();
		}

		function editorHtml() {
			const C = S.compose;
			try {
				const d = C && C.frame && C.frame.contentDocument;
				if (d && d.body && d.body.isContentEditable !== undefined && C.frameReady) { C.html = d.body.innerHTML; C.captured = true; }
			} catch { /* frame gone */ }
			return C ? C.html : '';
		}

		let saveTimer = null;
		let watchTimer = null;
		function scheduleSave() {
			const C = S.compose;
			if (!C) return;
			C.dirty = true;
			clearTimeout(saveTimer);
			saveTimer = setTimeout(() => { saveDraft().catch(() => {}); }, SAVE_DELAY_MS);
		}

		/** Saves the draft now (made on the first save) → the draft, or null on failure (toast). */
		async function saveDraft({ quiet = false } = {}) {
			const C = S.compose;
			if (!C) return null;
			clearTimeout(saveTimer);
			if (C.saving) await C.saving.catch(() => {});
			if (S.compose !== C) return null;
			editorHtml();
			const body = {
				accountId: C.accountId, to: C.to, cc: C.cc, bcc: C.bcc, subject: C.subject, html: C.html,
				attachments: C.atts.map((a) => (a.pending ? a.pending : { id: a.id })),
			};
			C.dirty = false;
			const p = call(C.draftId ? api.updateDraft(C.draftId, body) : api.createDraft(body));
			C.saving = p;
			const r = await p;
			C.saving = null;
			if (S.compose !== C) return r && r.ok ? r.draft : null;
			if (!r || !r.ok) {
				C.dirty = true;
				if (!quiet) toast(errText(r), 'error');
				return null;
			}
			C.draftId = r.draft.id;
			// what changed meanwhile stays (pending attachments added during the save)
			const sent = new Set(body.attachments.map((a) => JSON.stringify(a)));
			const later = C.atts.filter((a) => a.pending && !sent.has(JSON.stringify(a.pending)));
			// files of this PC stay marked (a Microsoft account cannot send them)
			const known = new Map(C.atts.filter((a) => a.id).map((a) => [a.id, !!a.foreign]));
			const fromPc = body.attachments.filter((a) => a.mediaId).map((a) => a.name);
			C.atts = r.draft.attachments.map((a) => ({ ...a, foreign: known.has(a.id) ? known.get(a.id) : fromPc.includes(a.name) })).concat(later);
			C.warnings = r.draft.warnings;
			if (later.length) scheduleSave();
			renderComposeParts();
			return r.draft;
		}

		/** Leaving the editor: saved as a draft (nothing typed: nothing kept) → true when it may close. */
		async function leaveCompose() {
			const C = S.compose;
			if (!C) return true;
			if (C.busy) return false;
			editorHtml();
			if (C.dirty || C.saving) {
				const d = await saveDraft({ quiet: true });
				if (!d && C.dirty) {
					toast(t('mail.compose.notSaved'), 'error');
					return false;
				}
				toast(t('mail.compose.savedDraft'), 'info');
			}
			closeCompose();
			return true;
		}

		function closeCompose() {
			clearTimeout(saveTimer);
			clearInterval(watchTimer);
			S.compose = null;
			S.pane = S.read ? 'read' : 'empty';
			renderPane();
		}

		async function discard() {
			const C = S.compose;
			if (!C) return;
			if (C.draftId) {
				const r = await call(api.deleteDraft(C.draftId));
				if (!r || !r.ok) { toast(errText(r), 'error'); return; }
			}
			closeCompose();
			toast(t('mail.compose.discarded'), 'info');
		}

		async function send(sendAt = null) {
			const C = S.compose;
			if (!C || C.busy) return;
			flushRecipients();
			if (!C.to.length && !C.cc.length && !C.bcc.length) { toast(t('mail.compose.noRecipients'), 'error'); return; }
			if (C.badRecipients) { toast(t('mail.compose.badRecipients'), 'error'); return; }
			if (C.uploading) { toast(t('mail.compose.uploading'), 'error'); return; }
			if (msBlocked(C)) { C.unsupported = true; renderComposeParts(); toast(t('mail.compose.msUnsupported'), 'error'); return; }
			C.busy = true;
			renderComposeParts();
			const d = await saveDraft();
			if (!d) { C.busy = false; renderComposeParts(); return; }
			const r = await call(api.send(d.id, sendAt));
			C.busy = false;
			if (r && r.code === 'attachments_unsupported') { C.unsupported = true; renderComposeParts(); toast(t('mail.compose.msUnsupported'), 'error'); return; }
			if (!r || !r.ok) { toast(errText(r), 'error'); renderComposeParts(); return; }
			closeCompose();
			startUndo(r);
			loadOutbox();
		}

		function schedule() {
			const now = Date.now();
			const dlg = openDialog({ title: t('mail.schedule.title'), closeLabel: t('mail.close') });
			for (const p of MS.sendPresets(now)) {
				dlg.body.append(el('button', { type: 'button', class: 'ml-pick-row', on: { click: () => { dlg.close(); send(p.at); } } }, [icon('clock', 15), el('span', { class: 'ml-grow', text: t(p.key) }), el('span', { class: 'ml-sub', text: MS.fullDate(p.at, lang()) })]));
			}
			const inId = nextId('ml-at');
			const input = el('input', { id: inId, type: 'datetime-local', class: 'ml-input', value: MS.localInputValue(now + 60 * 60 * 1000) });
			const err = el('span', { class: 'ml-dlg-err', role: 'alert' });
			dlg.body.append(el('label', { class: 'ml-field', for: inId }, [el('span', { class: 'ml-sub', text: t('mail.schedule.own') }), input]));
			dlg.foot.append(err, el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), el('button', { type: 'button', class: 'btn btn-pri', text: t('mail.schedule.send'), on: { click: () => {
				const at = MS.localInputMs(input.value, Date.now());
				if (!at) { err.textContent = t('mail.schedule.past'); return; }
				dlg.close();
				send(at);
			} } }));
		}

		// recipients
		const recipientInputs = new Map();   // 'to' | 'cc' | 'bcc' → input

		function flushRecipients() {
			const C = S.compose;
			if (!C) return;
			C.badRecipients = false;
			for (const [field, input] of recipientInputs) {
				if (!input.value.trim()) continue;
				const p = MS.parseRecipients(input.value);
				for (const a of p.list) if (!C[field].some((x) => x.email.toLowerCase() === a.email.toLowerCase())) C[field].push(a);
				input.value = p.bad.join(', ');
				input.classList.toggle('is-bad', p.bad.length > 0);
				if (p.bad.length) C.badRecipients = true;
				if (p.list.length) scheduleSave();
			}
		}

		function recipientField(field, label) {
			const C = S.compose;
			const wrap = el('div', { class: 'ml-f' });
			const chips = el('span', { class: 'ml-rcpts' });
			const input = el('input', { type: 'text', class: 'ml-rcpt-in', 'aria-label': label, spellcheck: 'false', autocomplete: 'off' });
			recipientInputs.set(field, input);
			const sug = el('div', { class: 'ml-sug-list', role: 'listbox', hidden: true });
			const drawChips = () => {
				clear(chips);
				for (const r of C[field]) {
					chips.append(el('span', { class: 'ml-rcpt', title: r.email }, [
						el('span', { text: MS.recipientLabel(r) }),
						el('button', { type: 'button', class: 'ml-rcpt-x', 'aria-label': t('mail.compose.removeRecipient', { name: MS.recipientLabel(r) }), on: { click: () => { C[field] = C[field].filter((x) => x !== r); drawChips(); scheduleSave(); } } }, [icon('close', 11)]),
					]));
				}
			};
			drawChips();
			let q = 0;
			let sugTimer = null;
			const add = (a) => { if (!C[field].some((x) => x.email.toLowerCase() === a.email.toLowerCase())) C[field].push(a); input.value = ''; sug.hidden = true; drawChips(); scheduleSave(); input.focus(); };
			input.addEventListener('input', () => {
				input.classList.remove('is-bad');
				clearTimeout(sugTimer);
				const v = input.value.trim();
				if (/[,;]$/.test(input.value)) { flushRecipients(); drawChips(); return; }
				if (v.length < 2) { sug.hidden = true; return; }
				sugTimer = setTimeout(async () => {
					const my = ++q;
					const r = await call(api.contacts(v));
					if (my !== q || !r || !r.ok) return;
					clear(sug);
					for (const c of r.items) sug.append(el('button', { type: 'button', role: 'option', class: 'ml-sug-row', on: { mousedown: (e) => { e.preventDefault(); add({ name: c.name, email: c.email }); } } }, [el('span', { class: 'ml-sug-name', text: c.name || c.email }), c.name ? el('span', { class: 'ml-sub', text: c.email }) : null]));
					sug.hidden = !r.items.length;
				}, 220);
			});
			input.addEventListener('keydown', (e) => {
				if (e.key === 'Enter' || e.key === 'Tab') {
					if (!sug.hidden && sug.firstChild && e.key === 'Enter') { e.preventDefault(); sug.firstChild.dispatchEvent(new MouseEvent('mousedown')); return; }
					if (input.value.trim()) { if (e.key === 'Enter') e.preventDefault(); flushRecipients(); drawChips(); }
				} else if (e.key === 'Backspace' && !input.value && C[field].length) {
					C[field].pop();
					drawChips();
					scheduleSave();
				} else if (e.key === 'Escape') {
					sug.hidden = true;
				}
			});
			input.addEventListener('blur', () => { setTimeout(() => { sug.hidden = true; }, 150); if (input.value.trim()) { flushRecipients(); drawChips(); } });
			wrap.append(el('span', { class: 'ml-f-k', text: label }), el('span', { class: 'ml-rcpt-box' }, [chips, input, sug]));
			return wrap;
		}

		const composeParts = { atts: null, warn: null, sendBtn: null };

		const isMsAccount = (id) => { const a = MS.accountOf(S.me, id); return !!a && (a.provider === 'm365' || a.provider === 'outlook'); };
		/** A Microsoft account sends through Graph: files of this PC (or another account's mail) cannot go along. */
		function msBlocked(C) {
			return isMsAccount(C.accountId) && C.atts.some((a) => a.as !== 'link' && (a.foreign || (a.pending && a.pending.mediaId)));
		}

		function renderComposeParts() {
			const C = S.compose;
			if (!C || !composeParts.atts) return;
			clear(composeParts.atts);
			for (const a of C.atts) {
				const ft = MS.fileTag(a.name, a.mime);
				composeParts.atts.append(el('span', { class: 'ml-catt', title: a.url || a.name }, [
					el('span', { class: 'ml-ftag ml-ftag-sm', text: a.as === 'link' ? t('mail.att.link') : ft.tag }),
					el('span', { class: 'ml-catt-name', text: a.name }),
					a.size ? el('span', { class: 'ml-sub', text: MS.bytes(a.size, lang()) }) : null,
					el('button', { type: 'button', class: 'ml-rcpt-x', 'aria-label': t('mail.att.remove', { name: a.name }), on: { click: () => { C.atts = C.atts.filter((x) => x !== a); renderComposeParts(); scheduleSave(); } } }, [icon('close', 11)]),
				]));
			}
			if (C.uploading) composeParts.atts.append(el('span', { class: 'ml-catt is-busy', text: t('mail.compose.uploadingN', { count: C.uploading }) }));
			composeParts.atts.hidden = !C.atts.length && !C.uploading;
			clear(composeParts.warn);
			for (const w of C.warnings) composeParts.warn.append(el('div', { class: `ml-banner${w.kind === 'too_large' ? ' is-info' : ''}` }, [icon('alert', 14), el('span', { text: w.text || t(`mail.warn.${w.kind}`) })]));
			if (C.unsupported && !msBlocked(C)) C.unsupported = false;
			if (msBlocked(C)) {
				composeParts.warn.append(el('div', { class: 'ml-banner is-err' }, [
					icon('alert', 14),
					el('span', { class: 'ml-grow', text: t('mail.compose.msUnsupported') }),
					has('drive') && o.driveApi ? el('button', { type: 'button', class: 'btn btn-sec btn-xs', text: t('mail.compose.driveLink'), on: { click: () => attachFromDrive('link') } }) : null,
				]));
			}
			composeParts.warn.hidden = !composeParts.warn.childNodes.length;
			if (composeParts.sendBtn) composeParts.sendBtn.disabled = !!C.busy;
		}

		async function addFiles(paths, dropped) {
			const C = S.compose;
			if (!C) return;
			C.uploading += dropped ? dropped.length : paths.length;
			renderComposeParts();
			const r = await call(dropped ? api.uploadDropped(dropped) : api.upload(paths));
			C.uploading = 0;
			if (S.compose !== C) return;
			if (!r || !r.ok) { toast(errText(r), 'error'); renderComposeParts(); return; }
			for (const it of r.items) C.atts.push({ id: null, name: it.name, size: it.size, mime: it.mime, as: 'copy', foreign: true, pending: { mediaId: it.mediaId, name: it.name } });
			for (const x of r.rejected) toast(`${x.name}: ${errText({ code: x.code })}`, 'error');
			renderComposeParts();
			if (r.items.length) scheduleSave();
		}

		async function attachFromPc() {
			const p = await call(api.pick());
			if (p && p.ok) addFiles(p.paths);
		}

		function attachFromDrive(prefer) {
			const C = S.compose;
			if (!C || !o.driveApi) return;
			const dlg = openDialog({ title: t('mail.fromDrive.title'), wide: true, closeLabel: t('mail.close') });
			const picked = new Map();   // nodeId → { node, as }
			const q = el('input', { type: 'search', class: 'ml-input', placeholder: t('mail.fromDrive.search'), 'aria-label': t('mail.fromDrive.search'), maxlength: '100' });
			const list = el('div', { class: 'ml-pick-list', role: 'list' });
			const days = el('select', { class: 'ml-input ml-input-sm', 'aria-label': t('mail.fromDrive.days') });
			for (const d of [1, 7, 14, 30, 90]) days.append(el('option', { value: String(d), text: t(d === 1 ? 'mail.fromDrive.day' : 'mail.fromDrive.daysN', { count: d }), selected: d === 14 || null }));
			const pw = el('input', { type: 'password', class: 'ml-input ml-input-sm', placeholder: t('mail.fromDrive.password'), 'aria-label': t('mail.fromDrive.password'), maxlength: '200', autocomplete: 'new-password' });
			const linkOpts = el('div', { class: 'ml-linkopts', hidden: true }, [el('span', { class: 'ml-sub', text: t('mail.fromDrive.linkOpts') }), days, pw]);
			const addBtn = el('button', { type: 'button', class: 'btn btn-pri', disabled: true, on: { click: () => {
				const exp = Number(days.value) || 14;
				for (const { node, as } of picked.values()) {
					const pending = { driveNodeId: node.id, as };
					if (as === 'link') { pending.expiresDays = exp; if (pw.value) pending.password = pw.value; }
					C.atts.push({ id: null, name: node.name, size: node.size, mime: node.mime, as, pending });
				}
				dlg.close();
				renderComposeParts();
				scheduleSave();
			} } });
			const sync = () => {
				addBtn.textContent = t(picked.size === 1 ? 'mail.fromDrive.addOne' : 'mail.fromDrive.add', { count: picked.size });
				addBtn.disabled = !picked.size;
				linkOpts.hidden = ![...picked.values()].some((p) => p.as === 'link');
			};
			sync();
			let seq = 0;
			let timer = null;
			const search = async () => {
				const v = q.value.trim();
				clear(list);
				if (v.length < 2) { list.append(el('p', { class: 'ml-note', text: t('mail.fromDrive.hint') })); return; }
				const my = ++seq;
				list.append(el('p', { class: 'ml-note', text: t('mail.loading') }));
				const r = await call(o.driveApi.search(v));
				if (my !== seq) return;
				clear(list);
				const files = r && r.ok ? r.items.filter((n) => !n.isDir) : [];
				if (!files.length) { list.append(el('p', { class: 'ml-note', text: r && r.ok ? t('mail.fromDrive.none') : errText(r) })); return; }
				list.append(el('div', { class: 'ml-sub', text: t('mail.fromDrive.hits') }));
				for (const n of files.slice(0, 50)) {
					const big = n.size > 20 * 1024 * 1024;
					const state = picked.get(n.id);
					const cb = el('input', { type: 'checkbox', class: 'ml-check', checked: !!state || null, 'aria-label': n.name });
					// Microsoft accounts: Drive files go as links anyway
					let as = state ? state.as : (big || prefer === 'link' || isMsAccount(C.accountId) ? 'link' : 'copy');
					const segBox = seg([['copy', t('mail.fromDrive.copy')], ['link', t('mail.fromDrive.link')]], as, (v2) => { as = v2; if (picked.has(n.id)) picked.set(n.id, { node: n, as }); sync(); }, n.name);
					cb.addEventListener('change', () => { if (cb.checked) picked.set(n.id, { node: n, as }); else picked.delete(n.id); sync(); });
					const ft = MS.fileTag(n.name, n.mime);
					const tag = el('span', { class: 'ml-ftag', text: ft.tag });
					const [bg, fg] = TONE[ft.tone] || TONE.muted;
					tag.style.background = bg;
					tag.style.color = fg;
					list.append(el('label', { class: 'ml-drive-row', role: 'listitem' }, [cb, tag, el('span', { class: 'ml-att-tx' }, [
						el('span', { class: 'ml-att-name', text: n.name }),
						el('span', { class: 'ml-sub', text: [n.path, MS.bytes(n.size, lang()), big ? t('mail.fromDrive.tooBig') : null].filter(Boolean).join(' · ') }),
					]), segBox]));
				}
			};
			q.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(search, 300); });
			search();
			dlg.body.append(q, list, linkOpts);
			dlg.foot.append(el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), addBtn);
		}

		function renderCompose() {
			const C = S.compose;
			if (!C) return;
			if (C.busy && !C.doc) { pane.append(el('div', { class: 'ml-empty ml-pane-empty' }, [el('p', { class: 'ml-p', text: t('mail.loading') })])); return; }
			recipientInputs.clear();
			const accs = (S.me && S.me.accounts) || [];
			const from = el('select', { class: 'ml-from', 'aria-label': t('mail.compose.from') });
			for (const a of accs) from.append(el('option', { value: String(a.id), text: `${a.email} · ${a.name}`, selected: a.id === C.accountId || null }));
			let fromAv = avatarEl(MS.accountOf(S.me, C.accountId), 22, { dotted: false });
			from.addEventListener('change', () => {
				C.accountId = Number(from.value);
				const next = avatarEl(MS.accountOf(S.me, C.accountId), 22, { dotted: false });
				fromAv.replaceWith(next);
				fromAv = next;
				renderComposeParts();
				scheduleSave();
			});
			const subj = el('input', { type: 'text', class: 'ml-subj-in', value: C.subject, 'aria-label': t('mail.compose.subject'), maxlength: '998' });
			subj.addEventListener('input', () => { C.subject = subj.value; scheduleSave(); });
			const sendBtn = el('button', { type: 'button', class: 'btn btn-pri btn-sm', on: { click: () => send(null) } }, [icon('send', 15), el('span', { text: t('mail.compose.send') })]);
			composeParts.sendBtn = sendBtn;
			const attachBtn = el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: (e) => {
				const r = e.currentTarget.getBoundingClientRect();
				const items = [['mail.compose.fromPc', 'file', attachFromPc]];
				if (has('drive') && o.driveApi) items.push(['mail.compose.fromDrive', 'cloud', attachFromDrive]);
				if (items.length === 1) attachFromPc();
				else popMenu(r.left, r.bottom + 4, items);
			} } }, [icon('clip', 15), el('span', { text: t('mail.compose.attach') })]);
			const head = el('div', { class: 'ml-read-bar' }, [
				el('h2', { class: 'ml-compose-h', text: C.title }),
				el('span', { class: 'ml-grow' }),
				attachBtn,
				el('span', { class: 'ml-split' }, [
					sendBtn,
					el('button', { type: 'button', class: 'btn btn-pri btn-sm ml-split-more', title: t('mail.schedule.title'), 'aria-label': t('mail.schedule.title'), on: { click: () => schedule() } }, [icon('clock', 15)]),
				]),
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.compose.discard'), 'aria-label': t('mail.compose.discard'), on: { click: () => discard() } }, [icon('trash', 16)]),
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.compose.close'), 'aria-label': t('mail.compose.close'), on: { click: () => leaveCompose() } }, [icon('close', 16)]),
			]);
			const fields = el('div', { class: 'ml-fields' });
			fields.append(el('div', { class: 'ml-f' }, [el('span', { class: 'ml-f-k', text: t('mail.compose.from') }), fromAv, from]));
			const toRow = recipientField('to', t('mail.compose.to'));
			if (!C.showCc) toRow.append(el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('mail.compose.ccBcc'), on: { click: () => { flushRecipients(); C.showCc = true; renderPane(); } } }));
			fields.append(toRow);
			if (C.showCc) fields.append(recipientField('cc', t('mail.compose.cc')), recipientField('bcc', t('mail.compose.bcc')));
			fields.append(el('div', { class: 'ml-f' }, [el('span', { class: 'ml-f-k', text: t('mail.compose.subject') }), subj]));
			composeParts.warn = el('div', { class: 'ml-cwarn' });
			composeParts.atts = el('div', { class: 'ml-catts' });
			const fmt = el('div', { class: 'ml-fmt', role: 'toolbar', 'aria-label': t('mail.compose.format') });
			for (const [cmd, ic, key] of [['bold', 'bold', 'mail.compose.bold'], ['italic', 'italic', 'mail.compose.italic'], ['underline', 'underline', 'mail.compose.underline'], ['insertUnorderedList', 'list', 'mail.compose.list']]) {
				fmt.append(el('button', { type: 'button', class: 'ml-ib ml-ib-sm', title: t(key), 'aria-label': t(key), on: { mousedown: (e) => e.preventDefault(), click: () => {
					try { const d = C.frame.contentDocument; d.body.focus(); d.execCommand(cmd, false, null); scheduleSave(); } catch { /* frame not ready */ }
				} } }, [icon(ic, 15)]));
			}
			// built again (Cc / Bcc shown, another view): the frame gets a new document with what was typed
			const fresh = !C.captured || C.docHtml === C.html;
			const frame = mailFrame(fresh ? (C.doc || '') : '', { title: t('mail.compose.body'), editable: true });
			C.frame = frame;
			C.frameReady = false;
			if (fresh) {
				frame.dataset.ok = '1';
			} else {
				const want = C.html;
				call(api.editor(want)).then((r) => {
					if (!r || !r.ok || C.frame !== frame) return;
					C.doc = r.doc;
					C.docHtml = want;
					frame.dataset.ok = '1';
					frame.srcdoc = r.doc;
				});
			}
			frame.addEventListener('load', () => {
				if (frame.dataset.ok !== '1') return;
				try {
					const d = frame.contentDocument;
					if (!C.captured && d.body && d.body.firstChild) {
						// the caret above the signature / the quote
						const range = d.createRange();
						range.setStart(d.body.firstChild, 0);
						range.collapse(true);
						const sel = d.getSelection();
						sel.removeAllRanges();
						sel.addRange(range);
					}
					C.frameReady = true;
					d.addEventListener('input', () => scheduleSave());
					d.addEventListener('drop', (e) => { if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) { e.preventDefault(); addFiles(null, e.dataTransfer.files); } });
				} catch { /* no access */ }
			});
			// typing in the frame is also noticed without its events (a changed text is saved)
			clearInterval(watchTimer);
			let last = C.html;
			watchTimer = setInterval(() => {
				if (S.compose !== C) { clearInterval(watchTimer); return; }
				const now = editorHtml();
				if (now !== last) { last = now; scheduleSave(); }
			}, 3000);
			const box = el('div', { class: 'ml-compose' }, [head, fields, composeParts.warn, composeParts.atts, fmt, el('div', { class: 'ml-editor-wrap' }, [frame])]);
			box.addEventListener('dragover', (e) => { if (e.dataTransfer && [...e.dataTransfer.types].includes('Files')) { e.preventDefault(); box.classList.add('is-drop'); } });
			box.addEventListener('dragleave', () => box.classList.remove('is-drop'));
			box.addEventListener('drop', (e) => { box.classList.remove('is-drop'); if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) { e.preventDefault(); addFiles(null, e.dataTransfer.files); } });
			pane.append(box);
			renderComposeParts();
		}

		// ── Konto hinzufügen ─────────────────────────────

		async function openAddAccount() {
			const dlg = openDialog({ title: t('mail.add.title'), wide: true, closeLabel: t('mail.close'), cls: 'ml-add' });
			const r = await call(api.providers());
			if (dlg.closed) return;
			if (!r || !r.ok) { dlg.body.append(el('p', { class: 'ml-p', text: errText(r) })); return; }
			const rows = MS.providerRows(r.providers, features(), lang());
			const list = el('div', { class: 'ml-provs', role: 'list' });
			const form = el('div', { class: 'ml-add-form', hidden: true });
			for (const p of rows) {
				const logo = el('span', { class: 'ml-logo', text: p.look[0] });
				logo.style.background = p.look[1];
				logo.style.color = p.look[2];
				const tagKey = `mail.add.auth.${p.auth}`;
				const b = el('button', { type: 'button', role: 'listitem', class: 'ml-prov', 'aria-disabled': p.disabled ? 'true' : null, on: { click: () => { for (const x of list.children) x.classList.remove('on'); b.classList.add('on'); showForm(p); } } }, [
					logo,
					el('span', { class: 'ml-att-tx' }, [el('span', { class: 'ml-att-name', text: p.label }), p.disabled ? el('span', { class: 'ml-sub', text: t('mail.add.msNotSetUp') }) : null]),
					el('span', { class: 'ml-ptag', text: t(tagKey) }),
				]);
				list.append(b);
			}
			dlg.body.append(list, form);
			dlg.foot.append(el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }));

			function field(label, input) {
				const id = nextId('ml-in');
				input.id = id;
				return el('label', { class: 'ml-field', for: id }, [el('span', { class: 'ml-sub', text: label }), input]);
			}

			function colorPicker(value, onPick) {
				const box = el('div', { class: 'ml-colors', role: 'radiogroup', 'aria-label': t('mail.add.color') });
				for (const c of MS.COLORS) {
					const b = el('button', { type: 'button', role: 'radio', class: `ml-color${c === value ? ' on' : ''}`, 'aria-checked': c === value ? 'true' : 'false', 'aria-label': c, on: { click: () => { for (const x of box.children) { x.classList.remove('on'); x.setAttribute('aria-checked', 'false'); } b.classList.add('on'); b.setAttribute('aria-checked', 'true'); onPick(c); } } });
					b.style.background = c;
					box.append(b);
				}
				return box;
			}

			function showForm(p) {
				clear(form);
				form.hidden = false;
				form.append(el('h3', { class: 'ml-add-h', text: t('mail.add.setUp', { name: p.label }) }));
				let color = MS.freeColor(S.me);
				let kind = p.id === 'm365' ? 'business' : 'personal';
				const name = el('input', { type: 'text', class: 'ml-input', maxlength: '120', placeholder: p.label, spellcheck: 'false' });
				const err = el('div', { class: 'ml-dlg-err', role: 'alert' });
				const kindSeg = seg([['personal', t('mail.kind.personal')], ['business', t('mail.kind.business')]], kind, (v) => { kind = v; }, t('mail.add.kind'));
				if (p.auth === 'microsoft') {
					if (p.disabled) {
						form.append(el('div', { class: 'ml-banner is-warn' }, [icon('alert', 15), el('span', { text: t('mail.add.msNotSetUpLong') })]));
						return;
					}
					form.append(field(t('mail.add.name'), name), colorPicker(color, (c) => { color = c; }), kindSeg);
					form.append(el('p', { class: 'ml-note', text: t('mail.add.msNote') }));
					const waiting = el('div', { class: 'ml-banner is-info', hidden: true }, [icon('clock', 15), el('span', { class: 'ml-grow', text: t('mail.add.msWaiting') }), el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('mail.cancel'), on: { click: () => api.cancelSignIn() } })]);
					const go2 = el('button', { type: 'button', class: 'btn btn-pri', text: t('mail.add.msSignIn'), on: { click: async () => {
						go2.disabled = true;
						waiting.hidden = false;
						err.textContent = '';
						const r2 = await call(api.microsoft({ name: name.value.trim() || undefined, color, kind }));
						go2.disabled = false;
						waiting.hidden = true;
						if (r2 && r2.ok) { dlg.close(); added(r2.account); return; }
						if (r2 && r2.code === 'cancelled') return;
						err.textContent = errText(r2 && r2.code === 'timeout' ? { code: 'timeout_signin' } : r2);
					} } });
					form.append(waiting, err, go2);
					return;
				}
				const email = el('input', { type: 'email', class: 'ml-input', maxlength: '320', spellcheck: 'false', autocomplete: 'off' });
				const pass = el('input', { type: 'password', class: 'ml-input', maxlength: '1024', autocomplete: 'new-password' });
				form.append(field(t('mail.add.email'), email), field(p.auth === 'app_password' ? t('mail.add.appPassword') : t('mail.add.password'), pass));
				form.append(field(t('mail.add.name'), name), colorPicker(color, (c) => { color = c; }), kindSeg);
				const srv = { imapHost: null, imapPort: null, imapSec: null, smtpHost: null, smtpPort: null, smtpSec: null, user: null };
				let servers = null;
				if (p.auth === 'imap' || p.id === 'imap') {
					servers = el('div', { class: 'ml-servers' });
					const host = () => el('input', { type: 'text', class: 'ml-input', maxlength: '253', spellcheck: 'false' });
					const port = (v) => el('input', { type: 'number', class: 'ml-input ml-input-port', min: '1', max: '65535', value: String(v) });
					const sec = (v) => { const s = el('select', { class: 'ml-input ml-input-sec' }); for (const x of ['tls', 'starttls']) s.append(el('option', { value: x, text: t(`mail.add.sec.${x}`), selected: x === v || null })); return s; };
					srv.imapHost = host(); srv.imapPort = port(993); srv.imapSec = sec('tls');
					srv.smtpHost = host(); srv.smtpPort = port(587); srv.smtpSec = sec('starttls');
					srv.user = el('input', { type: 'text', class: 'ml-input', maxlength: '320', spellcheck: 'false', placeholder: t('mail.add.userSame') });
					servers.append(
						el('div', { class: 'ml-server-row' }, [field(t('mail.add.imap'), srv.imapHost), field(t('mail.add.port'), srv.imapPort), field(t('mail.add.security'), srv.imapSec)]),
						el('div', { class: 'ml-server-row' }, [field(t('mail.add.smtp'), srv.smtpHost), field(t('mail.add.port'), srv.smtpPort), field(t('mail.add.security'), srv.smtpSec)]),
						field(t('mail.add.user'), srv.user),
					);
					form.append(servers);
					email.addEventListener('change', async () => {
						if (!MS.isEmail(email.value) || srv.imapHost.value) return;
						const d = await call(api.discover(email.value.trim()));
						if (!d || !d.ok) return;
						if (d.imap && !srv.imapHost.value) { srv.imapHost.value = d.imap.host; if (d.imap.port) srv.imapPort.value = String(d.imap.port); srv.imapSec.value = d.imap.security; }
						if (d.smtp && !srv.smtpHost.value) { srv.smtpHost.value = d.smtp.host; if (d.smtp.port) srv.smtpPort.value = String(d.smtp.port); srv.smtpSec.value = d.smtp.security; }
						const h = d.hint ? (lang() === 'en' ? d.hint.en : d.hint.de) : null;
						if (h) hintBox.querySelector('span').textContent = h;
						hintBox.hidden = !h;
					});
				}
				const hintBox = el('div', { class: 'ml-banner is-warn', hidden: !p.hint }, [icon('alert', 15), el('span', { text: p.hint || '' })]);
				form.append(hintBox);
				if (p.help) form.append(el('button', { type: 'button', class: 'btn btn-ghost btn-xs ml-help', text: t('mail.add.help'), on: { click: () => { if (window.gatecontrol && window.gatecontrol.shell) window.gatecontrol.shell.openExternal(p.help); } } }));
				form.append(el('p', { class: 'ml-note', text: t('mail.add.passwordNote') }));
				const connect = el('button', { type: 'button', class: 'btn btn-pri', text: t('mail.add.connect'), on: { click: async () => {
					err.textContent = '';
					if (!MS.isEmail(email.value)) { err.textContent = t('mail.add.badEmail'); return; }
					if (!pass.value) { err.textContent = t('mail.add.noPassword'); return; }
					const body = { provider: p.id, email: email.value.trim(), password: pass.value, name: name.value.trim() || undefined, color, kind };
					if (servers) {
						const portOf = (x) => Number(x.value);
						if (!srv.imapHost.value.trim() || !srv.smtpHost.value.trim()) { err.textContent = t('mail.add.noServer'); return; }
						body.imap = { host: srv.imapHost.value.trim(), port: portOf(srv.imapPort), security: srv.imapSec.value };
						body.smtp = { host: srv.smtpHost.value.trim(), port: portOf(srv.smtpPort), security: srv.smtpSec.value };
						if (srv.user.value.trim()) body.username = srv.user.value.trim();
					}
					connect.disabled = true;
					connect.textContent = t('mail.add.checking');
					const r2 = await call(api.addAccount(body));
					connect.disabled = false;
					connect.textContent = t('mail.add.connect');
					pass.value = '';
					if (r2 && r2.ok) { dlg.close(); added(r2.account); return; }
					err.textContent = errText(r2);
				} } });
				form.append(err, connect);
				email.focus();
			}

			async function added(account) {
				toast(t('mail.add.done', { name: account.name }), 'success');
				await loadMe();
				await loadFolders();
				go({ kind: 'box', box: account.id, folderId: null });
			}
		}

		// ── Settings ─────────────────────────────────────

		function openSettings() {
			const me = S.me;
			if (!me) return;
			const dlg = openDialog({ title: t('mail.settings.title'), wide: true, closeLabel: t('mail.close') });
			const put = async (patch) => {
				const r = await call(api.settings(patch));
				if (!r || !r.ok) { toast(errText(r), 'error'); return; }
				me.settings = r.settings;
				renderList();
			};
			const swOpts = ['archive', 'delete', 'read', 'none'];
			const sel = (value, onChange, label) => {
				const s = el('select', { class: 'ml-input ml-input-sm', 'aria-label': label });
				for (const x of swOpts) s.append(el('option', { value: x, text: t(`mail.swipe.${x}`), selected: x === value || null }));
				s.addEventListener('change', () => onChange(s.value));
				return s;
			};
			dlg.body.append(
				el('div', { class: 'lbl', text: t('mail.settings.general') }),
				el('div', { class: 'ml-set-row' }, [el('span', { class: 'ml-grow', text: t('mail.settings.threads') }), sw(me.settings.threads, t('mail.settings.threads'), (v) => put({ threads: v }))]),
				el('div', { class: 'ml-set-row' }, [el('span', { class: 'ml-grow' }, [t('mail.settings.quick1'), el('span', { class: 'ml-sub ml-block', text: t('mail.settings.quickHint') })]), sel(me.settings.swipeRight, (v) => put({ swipeRight: v }), t('mail.settings.quick1'))]),
				el('div', { class: 'ml-set-row' }, [el('span', { class: 'ml-grow', text: t('mail.settings.quick2') }), sel(me.settings.swipeLeft, (v) => put({ swipeLeft: v }), t('mail.settings.quick2'))]),
				el('div', { class: 'lbl', text: t('mail.settings.display') }),
				el('div', { class: 'ml-set-row' }, [el('span', { class: 'ml-grow' }, [t('mail.settings.darkMails'), el('span', { class: 'ml-sub ml-block', text: t('mail.settings.darkMailsHint') })]), sw(darkMails(), t('mail.settings.darkMails'), (v) => setDarkMails(v))]),
			);
			const q = MS.quotaView(me.limits, lang(), t);
			if (q) {
				const bar = el('div', { class: 'ml-quota-bar' }, [el('span')]);
				bar.firstChild.style.width = `${q.pct}%`;
				dlg.body.append(el('div', { class: 'lbl', text: t('mail.settings.storageTitle') }), el('div', { class: 'ml-quota is-wide' }, [bar, el('span', { class: 'ml-quota-tx', text: q.text })]));
			}
			dlg.body.append(el('div', { class: 'lbl', text: t('mail.accountsLabel') }));
			for (const a of me.accounts) {
				dlg.body.append(el('button', { type: 'button', class: 'ml-pick-row', on: { click: () => { dlg.close(); openAccount(a); } } }, [avatarEl(a, 32), el('span', { class: 'ml-att-tx' }, [el('span', { class: 'ml-att-name', text: a.name }), el('span', { class: 'ml-sub', text: `${a.email} · ${t(`mail.state.${a.state}`)}` })]), icon('chevron', 14)]));
			}
			dlg.body.append(el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => { dlg.close(); openAddAccount(); } } }, [icon('plus', 14), el('span', { text: t('mail.addAccount') })]));
			dlg.foot.append(el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.close'), on: { click: () => dlg.close() } }));
		}

		function openAccount(a) {
			const dlg = openDialog({ title: a.name, wide: true, closeLabel: t('mail.close') });
			const patch = {};
			const name = el('input', { type: 'text', class: 'ml-input', value: a.name, maxlength: '120' });
			name.addEventListener('input', () => { patch.name = name.value.trim(); });
			const field = (label, input) => { const id = nextId('ml-in'); input.id = id; return el('label', { class: 'ml-field', for: id }, [el('span', { class: 'ml-sub', text: label }), input]); };
			const colors = el('div', { class: 'ml-colors', role: 'radiogroup', 'aria-label': t('mail.add.color') });
			for (const c of MS.COLORS) {
				const b = el('button', { type: 'button', role: 'radio', class: `ml-color${c === a.color ? ' on' : ''}`, 'aria-checked': c === a.color ? 'true' : 'false', 'aria-label': c, on: { click: () => { for (const x of colors.children) x.classList.remove('on'); b.classList.add('on'); patch.color = c; } } });
				b.style.background = c;
				colors.append(b);
			}
			const sig = el('textarea', { class: 'ml-input ml-sig', rows: '4', maxlength: '10000' });
			sig.value = a.signature || '';
			sig.addEventListener('input', () => { patch.signature = sig.value; });
			dlg.body.append(
				el('div', { class: 'ml-acc-head' }, [
					avatarEl(a, 48),
					el('span', { class: 'ml-att-tx' }, [el('span', { class: 'ml-att-name', text: a.name }), el('span', { class: 'ml-sub', text: `${a.email} · ${t(`mail.state.${a.state}`)}` })]),
				]),
				field(t('mail.add.name'), name),
				colors,
				el('div', { class: 'ml-set-row' }, [el('span', { class: 'ml-grow', text: t('mail.add.kind') }), seg([['personal', t('mail.kind.personal')], ['business', t('mail.kind.business')]], a.kind, (v) => { patch.kind = v; }, t('mail.add.kind'))]),
				el('div', { class: 'ml-set-row' }, [el('span', { class: 'ml-grow', text: t('mail.settings.push') }), seg([['off', t('mail.push.off')], ['relevant', t('mail.push.relevant')], ['all', t('mail.push.all')]], a.push, (v) => { patch.push = v; }, t('mail.settings.push'))]),
			);
			if (has('ai')) dlg.body.append(el('div', { class: 'ml-set-row' }, [el('span', { class: 'ml-grow' }, [t('mail.settings.ai'), el('span', { class: 'ml-sub ml-block', text: t('mail.settings.aiHint') })]), sw(a.ai, t('mail.settings.ai'), (v) => { patch.ai = v; })]));
			if (has('drive')) dlg.body.append(el('div', { class: 'ml-set-row' }, [el('span', { class: 'ml-grow' }, [t('mail.settings.attachmentsTitle'), el('span', { class: 'ml-sub ml-block', text: t('mail.settings.attachmentsHint') })]), seg([['off', t('mail.settings.attachments.off')], ['suggest', t('mail.settings.attachments.suggest')], ['auto', t('mail.settings.attachments.auto')]], a.attachments, (v) => { patch.attachments = v; }, t('mail.settings.attachmentsTitle'))]));
			dlg.body.append(field(t('mail.settings.signature'), sig));
			const isMs = a.provider === 'm365' || a.provider === 'outlook';
			const err = el('span', { class: 'ml-dlg-err', role: 'alert' });
			if (isMs) {
				dlg.body.append(el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: async (e) => {
					const b = e.currentTarget;
					b.disabled = true;
					err.textContent = t('mail.add.msWaiting');
					const r = await call(api.microsoft({ accountId: a.id }));
					b.disabled = false;
					err.textContent = r && r.ok ? '' : (r && r.code === 'cancelled' ? '' : errText(r && r.code === 'timeout' ? { code: 'timeout_signin' } : r));
					if (r && r.ok) { toast(t('mail.settings.reloggedIn'), 'success'); loadMe().then(() => { renderMenu(); renderList(); }); }
				} } }, [icon('refresh', 14), el('span', { text: t('mail.settings.relogin') })]));
			} else {
				const pw = el('input', { type: 'password', class: 'ml-input', maxlength: '1024', autocomplete: 'new-password', placeholder: t('mail.settings.passwordKeep') });
				pw.addEventListener('input', () => { if (pw.value) patch.password = pw.value; else delete patch.password; });
				dlg.body.append(field(t('mail.settings.password'), pw));
			}
			dlg.body.append(el('button', { type: 'button', class: 'btn btn-danger btn-sm ml-remove', on: { click: () => removeAccount(a, dlg) } }, [icon('trash', 14), el('span', { text: t('mail.settings.remove') })]));
			const save = el('button', { type: 'button', class: 'btn btn-pri', text: t('mail.save'), on: { click: async () => {
				if (!Object.keys(patch).length) { dlg.close(); return; }
				save.disabled = true;
				const r = await call(api.updateAccount(a.id, patch));
				save.disabled = false;
				if (!r || !r.ok) { err.textContent = errText(r); return; }
				dlg.close();
				toast(t('mail.saved'), 'success');
				await loadMe();
				renderMenu();
				renderList();
			} } });
			dlg.foot.append(err, el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), save);
		}

		function removeAccount(a, parent) {
			const dlg = openDialog({ title: t('mail.settings.removeTitle', { name: a.name }), closeLabel: t('mail.close') });
			dlg.body.append(el('p', { class: 'ml-p', text: t('mail.settings.removeText') }));
			dlg.foot.append(el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), el('button', { type: 'button', class: 'btn btn-danger', text: t('mail.settings.remove'), on: { click: async () => {
				const r = await call(api.deleteAccount(a.id));
				if (!r || !r.ok) { toast(errText(r), 'error'); return; }
				dlg.close();
				parent.close();
				toast(t('mail.settings.removed', { name: a.name }), 'success');
				await loadMe();
				await loadFolders();
				go({ kind: 'box', box: 'all', folderId: null });
			} } }));
		}

		// ── Page ─────────────────────────────────────────

		o.root.addEventListener('keydown', (e) => {
			if (!S.shown || e.defaultPrevented) return;
			if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'n' && !e.shiftKey) { e.preventDefault(); openCompose({}); }
			else if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && S.pane === 'compose') { e.preventDefault(); send(null); }
		});

		function render() {
			renderMenu();
			renderList();
			renderPane();
		}

		renderMenu();
		renderList();
		renderPane();

		return {
			show() {
				S.shown = true;
				if (S.status && S.status.state === 'available') {
					if (!S.loaded) loadAll();
					else reloadSoon();
				}
			},
			hide() {
				S.shown = false;
				if (S.compose && S.compose.dirty) saveDraft({ quiet: true }).catch(() => {});
			},
			relabel() {
				render();
				setStatus(S.status);
			},
			/** A push target: { kind: 'message', messageId, accountId } | { kind: 'outbox', outboxId }. */
			async open(context) {
				S.shown = true;
				if (!S.loaded && S.status && S.status.state === 'available') await loadAll();
				if (!context) return;
				if (context.kind === 'outbox') { go({ kind: 'outbox' }); return; }
				if (context.kind === 'message' && context.messageId) {
					if (S.view.kind !== 'box') go(S.lastBox);
					openMessage(context.messageId, { fromPush: true });
				}
			},
			/** Unread mails of all inboxes (for the nav badge). */
			unread: () => (S.me && S.me.unread ? S.me.unread.all : 0),
		};
	}

	root.GCMailView = { mount };
})(typeof self !== 'undefined' ? self : this);
