/**
 * GateControl -- Mail › Kontakte (renderer, plugin gatecontrol-mail Phase 2)
 *
 * The area "Kontakte" of the Mail page (mockups "Kontakte", "Kontakt",
 * "KontaktBearbeiten", "MenueNeu"), three columns: the menu ("Alle Kontakte",
 * the address books with a tick for shown / hidden, the groups with their
 * count, "Dubletten"), the list (search at once — on this PC in the core's
 * summaries —, "Kontakte | Gruppen", letter sections, a row with the photo or
 * initials, the name, the company or first address and the source's colour
 * dot; "Neuer Kontakt"; import / export of vCard files through the core's file
 * dialogs) and the contact: photo, name, position · company, Mail / Anrufen
 * (tel:) / Bearbeiten, the fields (addresses → compose, numbers → call, an
 * address → map, birthday, note, groups, sources), "Letzte Mails" and
 * "Gemeinsame Termine". Editing in the right column: photo (a picture of this
 * PC, made 512 px JPEG by the core), names, company, position, several
 * addresses and numbers with their kind, postal addresses, birthday (year
 * optional), note, groups, the address book of a new one; a conflict offers
 * "Neu laden" and "Meine Änderung erneut anwenden". Duplicates: the pairs
 * with their reason, "Zusammenführen" (different sources are linked, the
 * providers keep both) and "Keine Dublette". A group: its members, "Mail an
 * alle", add and remove members.
 *
 * Read only sources (CardDAV without write right, Gmail's import) show "nur
 * lesend"; offline everything that changes is greyed out.
 *
 * Built by mail-view.js through GCContactsView.create(ctx); pure logic in
 * mail-state.js (GCMailState). Server text only into textContent / attributes.
 */
(function (root) {
	'use strict';

	const MS = root.GCMailState;
	const PHOTO_MAX = 80;

	function create(ctx) {
		const { api, t } = ctx;
		const { el, icon, clear, dot, openDialog } = root.GCMailUI;
		const lang = () => ctx.lang();
		const toast = (m, type) => ctx.toast(m, type);
		const errText = (r) => ctx.errText(r);
		const call = (p) => Promise.resolve(p).catch((err) => ({ ok: false, code: (err && err.code) || 'failed' }));

		const K = {
			books: null,          // GET addressbooks: { items, groups, prefs }
			booksOffline: false,
			book: 'all',
			group: null,
			q: '',
			tab: 'contacts',
			items: [],
			total: 0,
			loading: false,
			error: null,
			offline: false,
			seq: 0,
			pane: null,           // { kind: 'card' | 'edit' | 'group' | 'dups', … }
			paneSeq: 0,
			dups: null,
			main: null,
			shown: false,
			listScroll: 0,
		};
		const photos = new Map();      // card id → data: URL (or null while loading / failed)

		const books = () => (K.books && K.books.items) || [];
		const groups = () => (K.books && K.books.groups) || [];
		const bookOf = (id) => books().find((b) => b.id === id) || null;
		const groupOf = (id) => groups().find((g) => g.id === id) || null;
		const offline = () => K.offline || K.booksOffline;
		const offlineNote = () => t('mail.con.offlineHint');

		// ── Loading ──────────────────────────────────────

		async function loadBooks() {
			const r = await call(api.addressbooks());
			if (r && r.ok) { K.books = r; K.booksOffline = !!r.offline; } else if (!K.books) K.error = errText(r);
			return r;
		}

		async function loadDups() {
			if (offline()) return;
			const r = await call(api.duplicates());
			if (r && r.ok) K.dups = r.items;
			ctx.renderMenu();
			renderList();
		}

		async function loadList({ keep = true } = {}) {
			const seq = ++K.seq;
			K.loading = true;
			if (!keep) K.items = [];
			renderList();
			const r = await call(api.cards({ q: K.q, book: K.book, group: K.group }));
			if (seq !== K.seq) return;
			K.loading = false;
			if (r && r.ok) {
				K.items = r.items;
				K.offline = !!r.offline;
				K.error = null;
				if (!K.q && K.book === 'all' && !K.group) K.total = r.items.length;
			} else K.error = errText(r);
			renderList();
			ctx.renderMenu();
		}

		let reloadTimer = null;
		function reloadSoon({ books: withBooks = false, card = false } = {}) {
			clearTimeout(reloadTimer);
			reloadTimer = setTimeout(async () => {
				if (!K.shown) return;
				if (withBooks) await loadBooks();
				await loadList();
				if (card && K.pane && K.pane.kind === 'card') openCard(K.pane.id, { quiet: true });
				if (K.pane && K.pane.kind === 'group') openGroup(K.pane.id, { quiet: true });
				loadDups();
			}, 300);
		}

		// ── Photos ───────────────────────────────────────

		function avatar(c, size, cls = '') {
			const name = c && (c.name && typeof c.name === 'object' ? c.name.display : c.name);
			const box = el('span', { class: `ml-av con-av${cls ? ` ${cls}` : ''}`, 'aria-hidden': 'true', text: MS.initials({ name: name || null, email: (c && c.emails && c.emails[0] && (c.emails[0].value || c.emails[0])) || '' }) });
			box.style.width = `${size}px`;
			box.style.height = `${size}px`;
			box.style.fontSize = `${Math.round(size * 0.36)}px`;
			const has = c && (c.photo === true || (c.photo && c.photo.etag));
			if (has && c.id) {
				const etag = c.photoEtag || (c.photo && c.photo.etag) || null;
				const show = (url) => { clear(box); box.append(el('img', { src: url, alt: '', draggable: 'false' })); };
				const key = `${c.id}:${etag || ''}`;
				if (photos.get(key)) show(photos.get(key));
				else if (!photos.has(key) && photos.size < 1000) {
					photos.set(key, null);
					call(api.cardPhoto(c.id, etag)).then((r) => {
						if (r && r.ok && /^data:image\/(jpeg|png);base64,/.test(r.url)) { photos.set(key, r.url); show(r.url); }
					});
				}
			}
			return box;
		}

		// ── Menu (left) ──────────────────────────────────

		function renderSide(side) {
			if (!K.books) {
				side.append(el('p', { class: 'ml-note cal-side-note', text: K.error || t('mail.loading') }));
				if (!K.error) loadBooks().then(() => ctx.renderMenu());
				return;
			}
			const allOn = K.book === 'all' && !K.group && !(K.pane && K.pane.kind === 'dups');
			side.append(el('button', { type: 'button', class: `ml-it${allOn ? ' on' : ''}`, 'aria-current': allOn ? 'page' : null, on: { click: () => { K.book = 'all'; K.group = null; K.tab = 'contacts'; loadList(); ctx.renderMenu(); } } }, [
				icon('users', 16), el('span', { class: 'ml-it-tx', text: t('mail.con.all') }), el('span', { class: `ml-n${allOn ? ' on' : ''}`, text: String(K.total || books().reduce((s, b) => s + (b.visible ? b.count : 0), 0)) }),
			]));
			side.append(el('div', { class: 'ml-lab', text: t('mail.con.books') }));
			for (const b of books()) {
				const on = K.book === b.id;
				const color = MS.bookColor(b, ctx.me()) || 'var(--acc)';
				const ck = el('button', { type: 'button', class: `cal-ck con-book-ck${b.visible ? ' on' : ''}`, role: 'switch', 'aria-checked': b.visible ? 'true' : 'false', title: t(b.visible ? 'mail.con.hideBook' : 'mail.con.showBook', { name: b.name }), disabled: offline() || null, on: { click: (e) => { e.stopPropagation(); toggleBook(b); } } }, [b.visible ? icon('check', 12, '3') : null]);
				ck.style.setProperty('--c', color);
				side.append(el('div', { class: `ml-it con-book${on ? ' on' : ''}`, role: 'button', tabindex: '0', title: MS.bookLabel(b, ctx.me()), on: { click: () => { K.book = b.id; K.group = null; K.tab = 'contacts'; loadList(); ctx.renderMenu(); }, keydown: (e) => { if (e.key === 'Enter') e.currentTarget.click(); } } }, [
					ck,
					el('span', { class: 'ml-it-tx', text: MS.bookLabel(b, ctx.me()) }),
					!b.writable ? el('span', { class: 'cal-it-state', title: t('mail.con.readOnly'), text: t('mail.con.readOnlyShort') }) : null,
					b.state === 'consent_required' ? el('span', { class: 'cal-it-state is-warn', text: t('mail.cal.state.consent') }) : null,
					b.state === 'auth_failed' || b.state === 'unreachable' ? el('span', { class: 'cal-it-state is-err', title: t(`mail.cal.state.${b.state}`) }, [icon('alert', 13)]) : null,
					el('span', { class: `ml-n${on ? ' on' : ''}`, text: String(b.count) }),
				]));
			}
			if (groups().length) {
				side.append(el('div', { class: 'ml-lab', text: t('mail.con.groups') }));
				for (const g of groups()) {
					const on = K.group === g.id;
					side.append(el('button', { type: 'button', class: `ml-it${on ? ' on' : ''}`, on: { click: () => openGroup(g.id) } }, [
						g.color ? dot(g.color) : icon('users', 16), el('span', { class: 'ml-it-tx', text: g.name }), el('span', { class: `ml-n${on ? ' on' : ''}`, text: String(g.count) }),
					]));
				}
			}
			const dupsOn = !!(K.pane && K.pane.kind === 'dups');
			side.append(el('button', { type: 'button', class: `ml-it con-dups-it${dupsOn ? ' on' : ''}`, on: { click: () => openDups() } }, [
				icon('copy', 16), el('span', { class: 'ml-it-tx', text: t('mail.con.dups') }), K.dups && K.dups.length ? el('span', { class: 'ml-n con-n-warn', text: String(K.dups.length) }) : null,
			]));
		}

		async function toggleBook(b) {
			const r = await call(api.updateAddressbook(b.id, { visible: !b.visible }));
			if (!r || !r.ok) { toast(errText(r), 'error'); return; }
			b.visible = !b.visible;
			ctx.renderMenu();
			loadList();
		}

		// ── The list (middle) ────────────────────────────

		const searchIn = el('input', { type: 'search', class: 'ml-search-in', maxlength: '100', spellcheck: 'false' });
		let searchTimer = null;
		searchIn.addEventListener('input', () => {
			clearTimeout(searchTimer);
			searchTimer = setTimeout(() => { K.q = searchIn.value.trim(); loadList(); }, 120);
		});
		searchIn.addEventListener('keydown', (e) => { if (e.key === 'Escape' && searchIn.value) { e.stopPropagation(); searchIn.value = ''; K.q = ''; loadList(); } });

		let listCol = null;
		let paneCol = null;

		function renderMain() {
			const main = K.main;
			if (!main || !K.shown) return;
			clear(main);
			listCol = el('section', { class: 'con-list', 'aria-label': t('mail.con.title') });
			paneCol = el('section', { class: 'con-pane', 'aria-live': 'polite' });
			main.append(el('div', { class: 'con' }, [listCol, paneCol]));
			renderList();
			renderPane();
		}

		function renderList() {
			if (!listCol || !K.shown) return;
			const old = listCol.querySelector('.ml-rows');
			if (old) K.listScroll = old.scrollTop;
			clear(listCol);
			const g = K.group ? groupOf(K.group) : null;
			const b = K.book !== 'all' ? bookOf(K.book) : null;
			const title = g ? g.name : (b ? MS.bookLabel(b, ctx.me()) : t('mail.con.title'));
			const sub = t('mail.con.sub', { count: K.items.length, books: books().length });
			listCol.append(el('div', { class: 'ml-head' }, [
				el('div', { class: 'ml-head-tx' }, [el('h1', { class: 'ml-h', text: title }), el('span', { class: 'ml-sub', text: sub })]),
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.more'), 'aria-label': t('mail.more'), on: { click: (e) => moreMenu(e) } }, [icon('more', 16)]),
				el('button', { type: 'button', class: 'btn btn-pri btn-sm con-new', disabled: offline() || null, title: offline() ? offlineNote() : null, on: { click: () => openEdit(null) } }, [icon('plus', 15), el('span', { text: t('mail.con.new') })]),
			]));
			searchIn.placeholder = t('mail.con.searchPh');
			searchIn.setAttribute('aria-label', t('mail.con.search'));
			listCol.append(el('label', { class: 'ml-search' }, [icon('search', 15), searchIn]));
			const tabs = el('div', { class: 'ml-tabs', role: 'tablist' });
			const tab = (id, label) => el('button', { type: 'button', role: 'tab', class: `ml-tab${K.tab === id ? ' on' : ''}`, 'aria-selected': K.tab === id ? 'true' : 'false', text: label, on: { click: () => { K.tab = id; renderList(); } } });
			tabs.append(tab('contacts', t('mail.con.tabContacts')), tab('groups', t('mail.con.tabGroups', { count: groups().length })));
			listCol.append(tabs);
			for (const band of ctx.consentBands()) listCol.append(band);
			if (offline()) listCol.append(el('div', { class: 'ml-banner' }, [icon('offline', 15), el('span', { text: t('mail.con.offline') })]));
			const rows = el('div', { class: 'ml-rows con-rows', role: 'listbox', 'aria-label': title, tabindex: '0' });
			if (K.tab === 'groups') {
				for (const x of groups()) {
					rows.append(el('button', { type: 'button', class: `con-grp${K.pane && K.pane.kind === 'group' && K.pane.id === x.id ? ' on' : ''}`, on: { click: () => openGroup(x.id) } }, [
						el('span', { class: 'con-gic' }, [icon('users', 18)]),
						el('span', { class: 'con-row-tx' }, [el('span', { class: 'con-row-name', text: x.name }), el('span', { class: 'ml-sub', text: t('mail.con.members', { count: x.count }) })]),
					]));
				}
				if (!groups().length) rows.append(el('div', { class: 'ml-empty' }, [el('p', { class: 'ml-p', text: t('mail.con.noGroups') })]));
				rows.append(el('button', { type: 'button', class: 'btn btn-ghost btn-sm con-new-group', disabled: offline() || null, on: { click: () => newGroup() } }, [icon('plus', 14), el('span', { text: t('mail.con.newGroup') })]));
				listCol.append(rows);
				return;
			}
			if (K.dups && K.dups.length && !K.q) {
				rows.append(el('button', { type: 'button', class: 'ml-banner is-warn con-dup-band', on: { click: () => openDups() } }, [icon('copy', 15), el('span', { class: 'ml-grow', text: t('mail.con.dupsFound', { count: K.dups.length }) }), el('span', { class: 'con-link', text: t('mail.con.dupsShow') })]));
			}
			if (K.error && !K.items.length) rows.append(el('div', { class: 'ml-empty' }, [el('p', { class: 'ml-p', text: K.error }), el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.retry'), on: { click: () => { K.error = null; loadBooks().then(() => loadList()); } } })]));
			else if (!K.items.length) rows.append(el('div', { class: 'ml-empty' }, [icon('users', 28), el('p', { class: 'ml-p', text: K.loading ? t('mail.loading') : (K.q ? t('mail.con.none') : t('mail.con.empty')) })]));
			let shown = 0;
			for (const sec of MS.cardSections(K.items)) {
				rows.append(el('div', { class: 'con-letter', text: sec.letter }));
				for (const c of sec.items) {
					const book = bookOf(c.addressbookId);
					const color = MS.bookColor(book, ctx.me());
					const on = K.pane && (K.pane.kind === 'card' || K.pane.kind === 'edit') && K.pane.id === c.id;
					const row = el('button', { type: 'button', role: 'option', class: `con-row${on ? ' on' : ''}`, 'aria-selected': on ? 'true' : 'false', 'data-id': String(c.id), on: { click: () => openCard(c.id) } }, [
						shown < PHOTO_MAX ? avatar(c, 36) : avatar({ ...c, photo: false }, 36),
						el('span', { class: 'con-row-tx' }, [el('span', { class: 'con-row-name', text: c.name || t('mail.con.noName') }), MS.cardSub(c) ? el('span', { class: 'ml-sub con-row-sub', text: MS.cardSub(c) }) : null]),
						color ? el('span', { class: 'ml-dot con-src', title: book ? MS.bookLabel(book, ctx.me()) : '' }) : null,
					]);
					if (color) row.lastChild.style.background = color;
					rows.append(row);
					shown += 1;
				}
			}
			listCol.append(rows);
			if (K.listScroll) rows.scrollTop = K.listScroll;
		}

		function moreMenu(e) {
			const r = e.currentTarget.getBoundingClientRect();
			const prefs = (K.books && K.books.prefs) || {};
			const items = [];
			if (!offline()) items.push(['mail.con.import', 'down', () => importVcf()]);
			items.push(['mail.con.export', 'send', () => exportVcf()]);
			if (!offline()) items.push([prefs.sort === 'given' ? 'mail.con.sortFamily' : 'mail.con.sortGiven', 'list', async () => {
				const x = await call(api.cardSettings({ sort: prefs.sort === 'given' ? 'family' : 'given' }));
				if (x && x.ok) { K.books.prefs = x.prefs; loadList(); } else toast(errText(x), 'error');
			}]);
			ctx.popMenu(r.left, r.bottom + 4, items);
		}

		function importVcf() {
			const writable = books().filter((b) => b.writable);
			if (!writable.length) { toast(t('mail.con.noWritable'), 'error'); return; }
			const dlg = openDialog({ title: t('mail.con.import'), closeLabel: t('mail.close') });
			const sel = el('select', { class: 'ml-input', 'aria-label': t('mail.con.intoBook') }, writable.map((b) => el('option', { value: String(b.id), text: MS.bookLabel(b, ctx.me()), selected: b.isDefault || null })));
			dlg.body.append(el('p', { class: 'ml-p', text: t('mail.con.importText') }), el('label', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: t('mail.con.intoBook') }), sel]));
			const err = el('span', { class: 'ml-dlg-err', role: 'alert' });
			const go = el('button', { type: 'button', class: 'btn btn-pri', text: t('mail.con.pickFile'), on: { click: async () => {
				go.disabled = true;
				const r = await call(api.importVcf(Number(sel.value)));
				go.disabled = false;
				if (r && r.code === 'cancelled') return;
				if (!r || !r.ok) { err.textContent = errText(r); return; }
				dlg.close();
				toast(t('mail.con.imported', { imported: r.imported, updated: r.updated, skipped: r.skipped }), 'success');
				reloadSoon({ books: true });
			} } });
			dlg.foot.append(err, el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), go);
		}

		async function exportVcf() {
			const r = await call(api.exportVcf({ book: K.book, group: K.group || undefined }));
			if (r && r.code === 'cancelled') return;
			if (!r || !r.ok) { toast(errText(r), 'error'); return; }
			toast(t('mail.con.exported'), 'success');
		}

		// ── The right column ─────────────────────────────

		function renderPane() {
			if (!paneCol || !K.shown) return;
			clear(paneCol);
			const P = K.pane;
			if (!P) { paneCol.append(el('div', { class: 'ml-empty ml-pane-empty' }, [icon('users', 34, '1.6'), el('p', { class: 'ml-p', text: t('mail.con.pickOne') })])); return; }
			if (P.loading) { paneCol.append(el('div', { class: 'ml-empty ml-pane-empty' }, [el('p', { class: 'ml-p', text: t('mail.loading') })])); return; }
			if (P.error) { paneCol.append(el('div', { class: 'ml-empty ml-pane-empty' }, [el('p', { class: 'ml-p', text: P.error })])); return; }
			if (P.kind === 'card') renderCard(P);
			else if (P.kind === 'edit') renderEdit(P);
			else if (P.kind === 'group') renderGroup(P);
			else if (P.kind === 'dups') renderDups(P);
		}

		async function openCard(id, { quiet = false } = {}) {
			const seq = ++K.paneSeq;
			if (!quiet) { K.pane = { kind: 'card', id, loading: true }; renderList(); renderPane(); }
			const r = await call(api.card(id));
			if (seq !== K.paneSeq) return;
			if (!r || !r.ok) { K.pane = { kind: 'card', id, error: r && r.code === 'not_found' ? t('mail.con.gone') : errText(r) }; renderPane(); return; }
			K.pane = { kind: 'card', id, card: r.card, offline: !!r.offline, activity: null };
			renderPane();
			if (!r.offline) {
				const a = await call(api.activity(id));
				if (seq !== K.paneSeq || !K.pane || K.pane.id !== id) return;
				if (a && a.ok) { K.pane.activity = a; renderPane(); }
			}
		}

		function typeLabel(kind, type) { return t(`mail.con.type.${kind}.${type}`); }

		function renderCard(P) {
			const c = P.card;
			const book = bookOf(c.addressbookId);
			const ro = c.readOnly || (book && !book.writable);
			const off = P.offline || offline();
			const name = c.name.display || [c.name.given, c.name.family].filter(Boolean).join(' ') || (c.emails[0] && c.emails[0].value) || t('mail.con.noName');
			const bar = el('div', { class: 'ml-read-bar', role: 'toolbar', 'aria-label': t('mail.actions') }, [
				el('span', { class: 'ml-grow' }),
				!ro ? el('button', { type: 'button', class: 'ml-ib', title: t('mail.con.photoChange'), 'aria-label': t('mail.con.photoChange'), disabled: off || null, on: { click: () => changePhoto(c) } }, [icon('image', 16)]) : null,
				!ro ? el('button', { type: 'button', class: 'ml-ib', title: t('mail.con.delete'), 'aria-label': t('mail.con.delete'), disabled: off || null, on: { click: () => deleteCard(c) } }, [icon('trash', 16)]) : null,
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.close'), 'aria-label': t('mail.close'), on: { click: () => { K.pane = null; renderList(); renderPane(); } } }, [icon('close', 16)]),
			]);
			const scroll = el('div', { class: 'ml-read con-card' });
			const srcs = [MS.bookLabel(book, ctx.me())];
			for (const l of c.linked || []) { const lb = bookOf(l.addressbookId); if (lb) srcs.push(t('mail.con.linkedWith', { name: MS.bookLabel(lb, ctx.me()) })); }
			const color = MS.bookColor(book, ctx.me());
			scroll.append(el('div', { class: 'con-hero' }, [
				avatar({ ...c, name: { display: name } }, 88, 'con-av-lg'),
				el('h2', { class: 'ml-read-subj con-name', text: name }),
				c.title || c.company ? el('span', { class: 'con-job', text: [c.title, c.company].filter(Boolean).join(' · ') }) : null,
				el('span', { class: 'ml-sub con-srcline' }, [color ? dot(color) : null, el('span', { text: srcs.filter(Boolean).join(' · ') + (ro ? ` · ${t('mail.con.readOnly')}` : '') })]),
			]));
			const mailTo = (e) => {
				if (c.emails.length === 1) { ctx.openCompose({ to: [{ name, email: c.emails[0].value }] }); return; }
				const r = e.currentTarget.getBoundingClientRect();
				ctx.popMenu(r.left, r.bottom + 4, c.emails.map((x) => [null, 'mail', () => ctx.openCompose({ to: [{ name, email: x.value }] }), x.value]));
			};
			const callTo = (e) => {
				if (c.phones.length === 1) { dial(c.phones[0].value); return; }
				const r = e.currentTarget.getBoundingClientRect();
				ctx.popMenu(r.left, r.bottom + 4, c.phones.map((x) => [null, 'phone', () => dial(x.value), `${typeLabel('phone', x.type)} · ${x.value}`]));
			};
			scroll.append(el('div', { class: 'con-acts' }, [
				el('button', { type: 'button', class: 'con-act', disabled: !c.emails.length || null, on: { click: mailTo } }, [icon('mail', 18), el('span', { text: t('mail.con.mail') })]),
				el('button', { type: 'button', class: 'con-act', disabled: !c.phones.length || null, on: { click: callTo } }, [icon('phone', 18), el('span', { text: t('mail.con.call') })]),
				el('button', { type: 'button', class: 'con-act con-edit', disabled: ro || off || null, title: ro ? t('mail.con.readOnlyFrom', { name: MS.bookLabel(book, ctx.me()) }) : (off ? offlineNote() : null), on: { click: () => openEdit(c) } }, [icon('pen', 18), el('span', { text: t('mail.con.edit') })]),
			]));
			if (ro) scroll.append(el('p', { class: 'ml-note', text: t('mail.con.readOnlyFrom', { name: MS.bookLabel(book, ctx.me()) }) }));
			const fields = el('div', { class: 'ml-card con-fields' });
			const fld = (label, value, extra) => el('div', { class: 'con-fld' }, [el('span', { class: 'con-fld-tx' }, [el('span', { class: 'ml-sub', text: label }), value]), extra || null]);
			for (const e of c.emails) fields.append(fld(`${t('mail.con.email')} · ${typeLabel('email', e.type)}`, el('button', { type: 'button', class: 'con-link', text: e.value, on: { click: () => ctx.openCompose({ to: [{ name, email: e.value }] }) } })));
			for (const p of c.phones) fields.append(fld(typeLabel('phone', p.type), el('button', { type: 'button', class: 'con-link', text: p.value, on: { click: () => dial(p.value) } })));
			for (const a of c.addresses) {
				const url = MS.mapUrl(a);
				fields.append(fld(`${typeLabel('address', a.type)} · ${t('mail.con.address')}`, el('span', { class: 'con-addr', text: MS.addressLines(a).join('\n') }),
					url ? el('button', { type: 'button', class: 'ml-ib', title: t('mail.con.map'), 'aria-label': t('mail.con.map'), on: { click: () => openUrl(url) } }, [icon('open', 15)]) : null));
			}
			if (c.birthday) fields.append(fld(t('mail.con.birthday'), el('span', { text: MS.birthdayText(c.birthday, Date.now(), lang(), t) })));
			for (const u of c.urls) fields.append(fld(t('mail.con.web'), el('button', { type: 'button', class: 'con-link', text: u, on: { click: () => openUrl(u) } })));
			if (c.note) fields.append(fld(t('mail.con.note'), el('span', { class: 'con-note', text: c.note })));
			if (c.groups.length) fields.append(el('div', { class: 'con-fld' }, [el('span', { class: 'con-fld-tx' }, [el('span', { class: 'ml-sub', text: t('mail.con.groups') }), el('span', { class: 'con-chips' }, c.groups.map((g) => { const gg = groupOf(g); return gg ? el('button', { type: 'button', class: 'ml-chip', text: gg.name, on: { click: () => openGroup(gg.id) } }) : null; }))])]));
			if (fields.childNodes.length) scroll.append(fields);
			const A = P.activity;
			if (A && A.mails.length) {
				const list = el('div', { class: 'ml-card con-list-card' });
				for (const m of A.mails) {
					const acc = MS.accountOf(ctx.me(), m.accountId);
					list.append(el('button', { type: 'button', class: 'con-mail', on: { click: () => ctx.openMessage(m.id) } }, [
						dot(acc ? acc.color : null),
						el('span', { class: 'con-row-tx' }, [el('span', { class: 'con-row-name', text: m.subject || t('mail.noSubject') }), el('span', { class: 'ml-sub con-row-sub', text: m.snippet || '' })]),
						el('span', { class: 'ml-sub', text: MS.timeLabel(m.date, Date.now(), lang(), t) }),
					]));
				}
				if (c.emails[0]) list.append(el('button', { type: 'button', class: 'con-mail con-all', text: t('mail.con.allMails', { name: c.name.given || name }), on: { click: () => ctx.openSender({ email: c.emails[0].value, name }) } }));
				scroll.append(el('h3', { class: 'ml-lab con-lab', text: t('mail.con.lastMails') }), list);
			}
			if (A && A.events.length) {
				const list = el('div', { class: 'ml-card con-list-card' });
				for (const x of A.events) {
					const d = new Date(x.allDay && x.startDate ? MS.fromYmd(x.startDate) : x.start);
					list.append(el('button', { type: 'button', class: 'con-mail', on: { click: () => ctx.openEvent(x.eventId, x.occurrence) } }, [
						el('span', { class: 'con-evday' }, [el('span', { class: 'ml-sub', text: d.toLocaleDateString(lang() === 'en' ? 'en-GB' : 'de-DE', { weekday: 'short' }).replace(/\.$/, '') }), el('b', { text: String(d.getDate()) })]),
						el('span', { class: 'con-row-tx' }, [el('span', { class: 'con-row-name', text: x.title }), el('span', { class: 'ml-sub', text: [x.myResponse === 'needs_action' ? t('mail.cal.openInvite') : null, MS.eventTimeText(x, lang(), t), x.location].filter(Boolean).join(' · ') })]),
					]));
				}
				scroll.append(el('h3', { class: 'ml-lab con-lab', text: t('mail.con.events') }), list);
			}
			paneCol.append(bar, scroll);
		}

		function openUrl(url) { if (window.gatecontrol && window.gatecontrol.shell) window.gatecontrol.shell.openExternal(url); }

		async function dial(number) {
			const r = await call(api.call(number));
			if (!r || !r.ok) toast(t('mail.con.noPhoneApp'), 'error');
		}

		async function changePhoto(c) {
			const r = await call(api.setCardPhoto(c.id));
			if (r && r.code === 'cancelled') return;
			if (!r || !r.ok) { toast(errText(r), 'error'); return; }
			toast(t('mail.con.photoDone'), 'success');
			openCard(c.id, { quiet: true });
			loadList();
		}

		function deleteCard(c) {
			const dlg = openDialog({ title: t('mail.con.deleteTitle', { name: c.name.display || '' }), closeLabel: t('mail.close') });
			const book = bookOf(c.addressbookId);
			dlg.body.append(el('p', { class: 'ml-p', text: book && book.accountId ? t('mail.con.deleteRemote', { name: MS.bookLabel(book, ctx.me()) }) : t('mail.con.deleteText') }));
			dlg.foot.append(el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), el('button', { type: 'button', class: 'btn btn-danger con-del-ok', text: t('mail.con.delete'), on: { click: async () => {
				const r = await call(api.deleteCard(c.id));
				if (!r || !r.ok) { toast(errText(r), 'error'); return; }
				dlg.close();
				toast(t('mail.con.deleted'), 'success');
				K.pane = null;
				reloadSoon({ books: true });
				renderPane();
			} } }));
		}

		// ── Editing ──────────────────────────────────────

		/** The edit form in the right column: an existing card, a new one (null), or a draft ({ draft, existing }). */
		function openEdit(card, { draft = null } = {}) {
			const F = MS.cardForm(card || draft || null, lang());
			if (!card) {
				const writable = books().filter((b) => b.writable);
				const prefs = (K.books && K.books.prefs) || {};
				F.addressbookId = (writable.find((b) => b.id === prefs.defaultAddressbookId) || writable.find((b) => b.isDefault) || writable[0] || {}).id || null;
				F.id = null;
				F.etag = null;
				if (K.group && !F.groups.includes(K.group)) F.groups.push(K.group);
			}
			K.pane = { kind: 'edit', id: card ? card.id : null, form: F, card: card || null };
			renderList();
			renderPane();
		}

		function renderEdit(P) {
			const F = P.form;
			const isNew = !F.id;
			const book = bookOf(isNew ? F.addressbookId : P.card.addressbookId);
			const err = el('span', { class: 'ml-dlg-err', role: 'alert' });
			const save = el('button', { type: 'button', class: 'btn btn-pri btn-sm con-save', disabled: offline() || null, text: t('mail.save'), on: { click: () => doSave() } });
			const bar = el('div', { class: 'ml-read-bar' }, [
				el('h2', { class: 'ml-compose-h', text: isNew ? t('mail.con.new') : t('mail.con.editTitle') }),
				el('span', { class: 'ml-grow' }),
				err,
				save,
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.close'), 'aria-label': t('mail.close'), on: { click: () => { if (P.card) openCard(P.card.id); else { K.pane = null; renderPane(); } } } }, [icon('close', 16)]),
			]);
			const scroll = el('div', { class: 'ml-read con-edit-form' });
			const input = (key, label, opts = {}) => {
				const i = el('input', { type: opts.type || 'text', class: 'ml-input', value: F[key] || '', maxlength: String(opts.max || 200), 'aria-label': label, placeholder: opts.ph || null, spellcheck: 'false' });
				i.addEventListener('input', () => { F[key] = i.value; });
				return el('label', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: label }), i]);
			};
			const head = el('div', { class: 'con-edit-head' }, [
				avatar(P.card || { name: { display: [F.given, F.family].join(' ') } }, 64, 'con-av-lg'),
				el('span', { class: 'con-edit-src' }, [
					el('span', { class: 'ml-sub', text: book ? `${MS.bookLabel(book, ctx.me())}${book.accountId ? ` · ${t('mail.con.goesThere')}` : ''}` : '' }),
					!isNew ? el('button', { type: 'button', class: 'btn btn-ghost btn-xs', disabled: offline() || null, text: t('mail.con.photoChange'), on: { click: () => changePhoto(P.card) } }) : el('span', { class: 'ml-note', text: t('mail.con.photoLater') }),
					!isNew && P.card.photo ? el('button', { type: 'button', class: 'btn btn-ghost btn-xs', disabled: offline() || null, text: t('mail.con.photoRemove'), on: { click: async () => { const r = await call(api.deleteCardPhoto(P.card.id)); if (r && r.ok) { P.card = r.card; F.etag = r.card.etag; renderPane(); loadList(); } else toast(errText(r), 'error'); } } }) : null,
				]),
			]);
			scroll.append(head);
			if (isNew) {
				const writable = books().filter((b) => b.writable);
				const sel = el('select', { class: 'ml-input', 'aria-label': t('mail.con.book') }, writable.map((b) => el('option', { value: String(b.id), text: MS.bookLabel(b, ctx.me()), selected: b.id === F.addressbookId || null })));
				sel.addEventListener('change', () => { F.addressbookId = Number(sel.value); });
				scroll.append(el('label', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: t('mail.con.book') }), sel]));
			}
			scroll.append(el('div', { class: 'ml-card con-ecard' }, [
				el('div', { class: 'cal-pair' }, [input('given', t('mail.con.given')), input('family', t('mail.con.family'))]),
				input('company', t('mail.con.company')),
				input('title', t('mail.con.position')),
			]));
			const multi = (listKey, kind, types, label, addLabel, inputType) => {
				const box = el('div', { class: 'ml-card con-ecard' }, [el('span', { class: 'ml-lab con-elab', text: label })]);
				const rows = el('div', { class: 'con-multi-rows' });
				const draw = () => {
					clear(rows);
					F[listKey].forEach((x, i) => {
						const typeSel = el('select', { class: 'ml-input ml-input-sm con-type', 'aria-label': t('mail.con.kind') }, types.map((ty) => el('option', { value: ty, text: typeLabel(kind, ty), selected: ty === x.type || null })));
						typeSel.addEventListener('change', () => { x.type = typeSel.value; });
						const v = el('input', { type: inputType, class: 'ml-input', value: x.value, maxlength: kind === 'email' ? '320' : '60', 'aria-label': label, spellcheck: 'false' });
						v.addEventListener('input', () => { x.value = v.value; });
						rows.append(el('div', { class: 'con-multi' }, [typeSel, v, el('button', { type: 'button', class: 'ml-rcpt-x', 'aria-label': t('mail.con.remove'), on: { click: () => { F[listKey].splice(i, 1); draw(); } } }, [icon('close', 11)])]));
					});
				};
				draw();
				box.append(rows, el('button', { type: 'button', class: 'btn btn-ghost btn-xs con-add', on: { click: () => { F[listKey].push({ value: '', type: types[0] }); draw(); const last = rows.querySelector('.con-multi:last-child input'); if (last) last.focus(); } } }, [icon('plus', 13), el('span', { text: addLabel })]));
				return box;
			};
			scroll.append(multi('emails', 'email', ['work', 'home', 'other'], t('mail.con.email'), t('mail.con.addEmail'), 'email'));
			scroll.append(multi('phones', 'phone', ['mobile', 'work', 'home', 'fax', 'other'], t('mail.con.phone'), t('mail.con.addPhone'), 'tel'));
			const addrBox = el('div', { class: 'ml-card con-ecard' });
			const drawAddr = () => {
				clear(addrBox);
				addrBox.append(el('span', { class: 'ml-lab con-elab', text: t('mail.con.address') }));
				F.addresses.forEach((a, i) => {
					const f = (key, label, max = 200) => { const x = el('input', { type: 'text', class: 'ml-input', value: a[key] || '', maxlength: String(max), 'aria-label': label }); x.addEventListener('input', () => { a[key] = x.value; }); return el('label', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: label }), x]); };
					const typeSel = el('select', { class: 'ml-input ml-input-sm con-type', 'aria-label': t('mail.con.kind') }, ['home', 'work', 'other'].map((ty) => el('option', { value: ty, text: typeLabel('address', ty), selected: ty === a.type || null })));
					typeSel.addEventListener('change', () => { a.type = typeSel.value; });
					addrBox.append(el('div', { class: 'con-addr-edit' }, [
						el('div', { class: 'con-multi' }, [typeSel, el('span', { class: 'ml-grow' }), el('button', { type: 'button', class: 'ml-rcpt-x', 'aria-label': t('mail.con.remove'), on: { click: () => { F.addresses.splice(i, 1); drawAddr(); } } }, [icon('close', 11)])]),
						f('street', t('mail.con.street'), 300),
						el('div', { class: 'cal-pair' }, [f('postalCode', t('mail.con.zip'), 20), f('city', t('mail.con.city'))]),
						el('div', { class: 'cal-pair' }, [f('region', t('mail.con.region')), f('country', t('mail.con.country'))]),
					]));
				});
				addrBox.append(el('button', { type: 'button', class: 'btn btn-ghost btn-xs con-add', on: { click: () => { F.addresses.push({ type: 'home', street: '', postalCode: '', city: '', region: '', country: '' }); drawAddr(); } } }, [icon('plus', 13), el('span', { text: t('mail.con.addAddress') })]));
			};
			drawAddr();
			scroll.append(addrBox);
			const note = el('textarea', { class: 'ml-input con-note-in', rows: '3', maxlength: '8000', 'aria-label': t('mail.con.note') });
			note.value = F.note;
			note.addEventListener('input', () => { F.note = note.value; });
			scroll.append(el('div', { class: 'ml-card con-ecard' }, [
				el('div', { class: 'cal-pair' }, [input('bdayDay', t('mail.con.bdayDay'), { ph: lang() === 'en' ? '14/03' : '14.03.', max: 10 }), input('bdayYear', t('mail.con.bdayYear'), { ph: '1981', max: 4 })]),
				el('label', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: t('mail.con.note') }), note]),
			]));
			if (groups().length) {
				const chips = el('div', { class: 'con-chips', role: 'group', 'aria-label': t('mail.con.groups') });
				for (const g of groups()) {
					const on = F.groups.includes(g.id);
					chips.append(el('button', { type: 'button', class: `ml-chip${on ? ' on' : ''}`, 'aria-pressed': on ? 'true' : 'false', text: g.name, on: { click: (e) => {
						F.groups = F.groups.includes(g.id) ? F.groups.filter((x) => x !== g.id) : F.groups.concat(g.id);
						e.currentTarget.classList.toggle('on');
						e.currentTarget.setAttribute('aria-pressed', F.groups.includes(g.id) ? 'true' : 'false');
					} } }));
				}
				scroll.append(el('div', { class: 'ml-card con-ecard' }, [el('span', { class: 'ml-lab con-elab', text: t('mail.con.groups') }), chips]));
			}
			if (!isNew) scroll.append(el('button', { type: 'button', class: 'btn btn-danger btn-sm ml-remove', disabled: offline() || null, on: { click: () => deleteCard(P.card) } }, [icon('trash', 14), el('span', { text: t('mail.con.delete') })]));
			if (offline()) scroll.append(el('p', { class: 'ml-note', text: offlineNote() }));
			paneCol.append(bar, scroll);

			async function doSave(etag = null) {
				err.textContent = '';
				const body = MS.cardBody(F);
				if (body.error) { err.textContent = t(`mail.con.bad.${body.error}`); return; }
				if (etag) body.etag = etag;
				save.disabled = true;
				const r = await call(isNew ? api.createCard(body) : api.updateCard(F.id, body));
				save.disabled = false;
				if (r && r.code === 'conflict' && r.current) {
					const dlg = openDialog({ title: t('mail.con.conflictTitle'), closeLabel: t('mail.close') });
					dlg.body.append(el('p', { class: 'ml-p', text: t('mail.con.conflictText') }));
					dlg.foot.append(
						el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cal.conflictReload'), on: { click: () => { dlg.close(); openEdit(r.current); } } }),
						el('button', { type: 'button', class: 'btn btn-pri', text: t('mail.cal.conflictMine'), on: { click: () => { dlg.close(); doSave(r.current.etag); } } }),
					);
					return;
				}
				if (!r || !r.ok) { err.textContent = r && r.code === 'read_only' ? t('mail.con.readOnly') : errText(r); return; }
				toast(t('mail.saved'), 'success');
				openCard(r.card.id);
				reloadSoon({ books: true });
			}
		}

		/** "Als Kontakt speichern" ({ email, name?, messageId? }): the draft of the server (name, signature), or "Zu <Name> hinzufügen". */
		async function saveFrom({ email, name = null, messageId = null }) {
			const r = await call(api.cardDraft(email, messageId));
			const draft = r && r.ok ? r.draft : { name: { given: '', family: '', display: name || '' }, emails: [{ value: email, type: 'work', primary: true }], phones: [], addresses: [], groups: [] };
			if (r && r.ok && r.existing) {
				const ex = r.existing;
				const dlg = openDialog({ title: t('mail.con.saveTitle'), closeLabel: t('mail.close') });
				dlg.body.append(el('p', { class: 'ml-p', text: t('mail.con.existsText', { name: ex.name.display || email }) }));
				dlg.foot.append(
					el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.con.saveNew'), on: { click: () => { dlg.close(); openEdit(null, { draft }); } } }),
					el('button', { type: 'button', class: 'btn btn-pri con-add-to', text: t('mail.con.addTo', { name: ex.name.display || email }), on: { click: () => {
						dlg.close();
						const merged = { ...ex, emails: ex.emails.slice(), phones: ex.phones.slice() };
						for (const e of draft.emails || []) if (!merged.emails.some((x) => x.value.toLowerCase() === e.value.toLowerCase())) merged.emails.push(e);
						for (const p of draft.phones || []) if (!merged.phones.some((x) => x.value.replace(/\D/g, '') === p.value.replace(/\D/g, ''))) merged.phones.push(p);
						if (!merged.company && draft.company) merged.company = draft.company;
						if (!merged.title && draft.title) merged.title = draft.title;
						openEdit(ex);
						K.pane.form = MS.cardForm(merged, lang());
						renderPane();
					} } }),
				);
				return;
			}
			openEdit(null, { draft });
		}

		// ── Groups ───────────────────────────────────────

		async function openGroup(id, { quiet = false } = {}) {
			const seq = ++K.paneSeq;
			K.group = id;
			K.book = 'all';
			if (!quiet) { K.pane = { kind: 'group', id, loading: true }; renderPane(); loadList(); ctx.renderMenu(); }
			const r = await call(api.group(id));
			if (seq !== K.paneSeq) return;
			K.pane = r && r.ok ? { kind: 'group', id, group: r.group, members: r.members } : { kind: 'group', id, error: errText(r) };
			renderPane();
		}

		function renderGroup(P) {
			const g = P.group || groupOf(P.id) || { name: '', count: 0 };
			const off = offline();
			const bar = el('div', { class: 'ml-read-bar', role: 'toolbar', 'aria-label': t('mail.actions') }, [
				el('button', { type: 'button', class: 'btn btn-pri btn-sm', disabled: !P.members.some((m) => m.email) || null, on: { click: () => ctx.openCompose({ to: P.members.filter((m) => m.email).map((m) => ({ name: m.name || null, email: m.email })) }) } }, [icon('mail', 15), el('span', { text: t('mail.con.mailAll') })]),
				el('span', { class: 'ml-grow' }),
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.cal.menu.rename'), 'aria-label': t('mail.cal.menu.rename'), disabled: off || null, on: { click: () => renameGroup(g) } }, [icon('pen', 16)]),
				el('button', { type: 'button', class: 'ml-ib', title: t('mail.con.deleteGroup'), 'aria-label': t('mail.con.deleteGroup'), disabled: off || null, on: { click: () => deleteGroup(g) } }, [icon('trash', 16)]),
			]);
			const scroll = el('div', { class: 'ml-read' });
			scroll.append(el('div', { class: 'con-hero con-hero-sm' }, [el('span', { class: 'con-gic con-gic-lg' }, [icon('users', 26)]), el('h2', { class: 'ml-read-subj', text: g.name }), el('span', { class: 'ml-sub', text: t('mail.con.members', { count: P.members.length }) })]));
			const list = el('div', { class: 'ml-card con-list-card' });
			for (const m of P.members) {
				list.append(el('div', { class: 'con-member' }, [
					avatar({ name: m.name || m.email, emails: [m.email || ''] }, 30),
					el('button', { type: 'button', class: 'con-row-tx con-member-tx', on: { click: () => { if (m.contactId) openCard(m.contactId); } } }, [el('span', { class: 'con-row-name', text: m.name || m.email || '' }), m.email && m.name ? el('span', { class: 'ml-sub', text: m.email }) : null]),
					el('button', { type: 'button', class: 'ml-rcpt-x', disabled: off || null, 'aria-label': t('mail.con.removeMember', { name: m.name || m.email || '' }), on: { click: async () => {
						const r = await call(api.groupMembers(P.id, { remove: [m.id] }));
						if (!r || !r.ok) { toast(errText(r), 'error'); return; }
						P.members = r.members;
						renderPane();
						reloadSoon({ books: true });
					} } }, [icon('close', 11)]),
				]));
			}
			if (!P.members.length) list.append(el('p', { class: 'ml-p', text: t('mail.con.noMembers') }));
			scroll.append(list);
			// add members: contacts (searched on this PC) or an address
			const add = el('input', { type: 'text', class: 'ml-input', maxlength: '200', placeholder: t('mail.con.addMemberPh'), 'aria-label': t('mail.con.addMember'), disabled: off || null, spellcheck: 'false' });
			const hits = el('div', { class: 'ml-pick-list con-hits' });
			let timer = null;
			const addMember = async (entry) => {
				const r = await call(api.groupMembers(P.id, { add: [entry] }));
				if (!r || !r.ok) { toast(errText(r), 'error'); return; }
				P.members = r.members;
				add.value = '';
				renderPane();
				reloadSoon({ books: true });
			};
			add.addEventListener('input', () => {
				clearTimeout(timer);
				timer = setTimeout(async () => {
					clear(hits);
					const q = add.value.trim();
					if (q.length < 2) return;
					const r = await call(api.cards({ q }));
					for (const c of (r && r.ok ? r.items : []).slice(0, 8)) {
						if (P.members.some((m) => m.contactId === c.id)) continue;
						hits.append(el('button', { type: 'button', class: 'ml-pick-row', on: { click: () => addMember({ contactId: c.id }) } }, [avatar(c, 26), el('span', { class: 'ml-grow', text: c.name }), el('span', { class: 'ml-sub', text: c.emails[0] || '' })]));
					}
					if (MS.isEmail(q)) hits.append(el('button', { type: 'button', class: 'ml-pick-row', on: { click: () => addMember({ email: q }) } }, [icon('plus', 15), el('span', { text: t('mail.con.addAddressMember', { email: q }) })]));
				}, 150);
			});
			scroll.append(el('label', { class: 'ml-field con-add-member' }, [el('span', { class: 'ml-sub', text: t('mail.con.addMember') }), add]), hits);
			paneCol.append(bar, scroll);
		}

		function groupDialog(title, value, onSave) {
			const dlg = openDialog({ title, closeLabel: t('mail.close') });
			const input = el('input', { type: 'text', class: 'ml-input', maxlength: '80', value: value || '', 'aria-label': t('mail.con.groupName') });
			const err = el('span', { class: 'ml-dlg-err', role: 'alert' });
			const ok = el('button', { type: 'button', class: 'btn btn-pri', text: t('mail.save'), on: { click: async () => {
				if (!input.value.trim()) { err.textContent = t('mail.cal.needName'); return; }
				const r = await onSave(input.value.trim());
				if (r && r.ok) dlg.close(); else err.textContent = errText(r);
			} } });
			input.addEventListener('keydown', (e) => { if (e.key === 'Enter') ok.click(); });
			dlg.body.append(el('label', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: t('mail.con.groupName') }), input]));
			dlg.foot.append(err, el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), ok);
		}

		function newGroup() {
			groupDialog(t('mail.con.newGroup'), '', async (name) => {
				const r = await call(api.createGroup({ name }));
				if (r && r.ok) { await loadBooks(); ctx.renderMenu(); openGroup(r.group.id); }
				return r;
			});
		}

		function renameGroup(g) {
			groupDialog(t('mail.cal.menu.rename'), g.name, async (name) => {
				const r = await call(api.updateGroup(g.id, { name }));
				if (r && r.ok) { await loadBooks(); ctx.renderMenu(); openGroup(g.id, { quiet: true }); renderList(); }
				return r;
			});
		}

		function deleteGroup(g) {
			const dlg = openDialog({ title: t('mail.con.deleteGroupTitle', { name: g.name }), closeLabel: t('mail.close') });
			dlg.body.append(el('p', { class: 'ml-p', text: t('mail.con.deleteGroupText') }));
			dlg.foot.append(el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), el('button', { type: 'button', class: 'btn btn-danger', text: t('mail.con.deleteGroup'), on: { click: async () => {
				const r = await call(api.deleteGroup(g.id));
				if (!r || !r.ok) { toast(errText(r), 'error'); return; }
				dlg.close();
				K.pane = null;
				K.group = null;
				await loadBooks();
				ctx.renderMenu();
				loadList();
				renderPane();
			} } }));
		}

		// ── Duplicates ───────────────────────────────────

		async function openDups() {
			K.pane = { kind: 'dups', loading: true };
			K.group = null;
			ctx.renderMenu();
			renderPane();
			const r = await call(api.duplicates());
			if (!K.pane || K.pane.kind !== 'dups') return;
			if (r && r.ok) { K.dups = r.items; K.pane = { kind: 'dups', items: r.items }; } else K.pane = { kind: 'dups', error: errText(r) };
			ctx.renderMenu();
			renderPane();
		}

		function renderDups(P) {
			const scroll = el('div', { class: 'ml-read' });
			scroll.append(el('h2', { class: 'ml-read-subj', text: t('mail.con.dups') }), el('p', { class: 'ml-note', text: t('mail.con.dupsIntro') }));
			if (!P.items.length) scroll.append(el('div', { class: 'ml-empty' }, [icon('check', 26), el('p', { class: 'ml-p', text: t('mail.con.noDups') })]));
			for (const d of P.items) {
				const card = el('div', { class: 'ml-card con-dup' });
				card.append(el('span', { class: 'ml-sub', text: t(`mail.con.reason.${d.reason}`) }));
				for (const c of d.cards) {
					const b = bookOf(c.addressbookId);
					card.append(el('button', { type: 'button', class: 'con-dup-row', on: { click: () => openCard(c.id) } }, [avatar(c, 30), el('span', { class: 'con-row-tx' }, [el('span', { class: 'con-row-name', text: c.name }), el('span', { class: 'ml-sub', text: [c.emails[0], b ? MS.bookLabel(b, ctx.me()) : null].filter(Boolean).join(' · ') })])]));
				}
				card.append(el('div', { class: 'ml-att-acts' }, [
					el('button', { type: 'button', class: 'btn btn-pri btn-sm con-merge', disabled: offline() || null, text: t('mail.con.merge'), on: { click: () => mergeDialog(d) } }),
					el('button', { type: 'button', class: 'btn btn-ghost btn-sm', disabled: offline() || null, text: t('mail.con.notDup'), on: { click: async () => {
						const r = await call(api.ignoreDuplicates(d.cards.map((c) => c.id)));
						if (!r || !r.ok) { toast(errText(r), 'error'); return; }
						openDups();
					} } }),
				]));
				scroll.append(card);
			}
			paneCol.append(scroll);
		}

		async function mergeDialog(d) {
			const full = [];
			for (const c of d.cards) { const r = await call(api.card(c.id)); if (r && r.ok) full.push(r.card); }
			if (full.length < 2) { toast(t('mail.err.failed'), 'error'); return; }
			const dlg = openDialog({ title: t('mail.con.merge'), wide: true, closeLabel: t('mail.close') });
			const sameBook = full.every((c) => c.addressbookId === full[0].addressbookId);
			let primary = (full.find((c) => !c.readOnly) || full[0]).id;
			const pick = {};
			const primaries = el('div', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: t('mail.con.mergeKeep') })]);
			const nameOf = (c) => c.name.display || [c.name.given, c.name.family].filter(Boolean).join(' ');
			for (const c of full) {
				const b = bookOf(c.addressbookId);
				const r = el('input', { type: 'radio', name: 'con-primary', value: String(c.id), checked: c.id === primary || null });
				r.addEventListener('change', () => { primary = c.id; });
				primaries.append(el('label', { class: 'ml-check-row' }, [r, el('span', { text: `${nameOf(c)} · ${b ? MS.bookLabel(b, ctx.me()) : ''}` })]));
			}
			dlg.body.append(primaries);
			for (const ch of MS.mergeChoices(full)) {
				const sel = el('select', { class: 'ml-input ml-input-sm', 'aria-label': t(`mail.con.field.${ch.field}`) }, [el('option', { value: '', text: t('mail.con.mergeFromKept') }), ...ch.options.map((o) => el('option', { value: String(o.id), text: o.value }))]);
				sel.addEventListener('change', () => { if (sel.value) pick[ch.field] = Number(sel.value); else delete pick[ch.field]; });
				dlg.body.append(el('label', { class: 'ml-field' }, [el('span', { class: 'ml-sub', text: t(`mail.con.field.${ch.field}`) }), sel]));
			}
			const join = el('input', { type: 'checkbox', class: 'ml-check', checked: true });
			dlg.body.append(el('label', { class: 'ml-check-row' }, [join, el('span', { text: t('mail.con.mergeNotes') })]));
			dlg.body.append(el('p', { class: `ml-note${sameBook ? '' : ' con-linkhint'}`, text: t(sameBook ? 'mail.con.mergeSame' : 'mail.con.mergeLink') }));
			const err = el('span', { class: 'ml-dlg-err', role: 'alert' });
			dlg.foot.append(err, el('button', { type: 'button', class: 'btn btn-sec', text: t('mail.cancel'), on: { click: () => dlg.close() } }), el('button', { type: 'button', class: 'btn btn-pri', text: t('mail.con.merge'), on: { click: async () => {
				const body = { ids: full.map((c) => c.id), primaryId: primary };
				const p = { ...pick };
				if (join.checked) p.note = 'join';
				if (Object.keys(p).length) body.pick = p;
				const r = await call(api.merge(body));
				if (!r || !r.ok) { err.textContent = errText(r); return; }
				dlg.close();
				toast(t(sameBook ? 'mail.con.merged' : 'mail.con.linked'), 'success');
				reloadSoon({ books: true });
				openCard(r.card.id);
			} } }));
		}

		return {
			renderSide,
			async show(main) {
				K.main = main;
				K.shown = true;
				if (!K.books) { await loadBooks(); ctx.renderMenu(); }
				renderMain();
				await loadList({ keep: true });
				loadDups();
			},
			hide() { K.shown = false; },
			relabel() { renderMain(); },
			/** mail:contacts live events. */
			onLive(c) {
				if (!c || !K.shown) return;
				const mine = c.kind === 'changed' && K.pane && K.pane.kind === 'card' && c.contactIds.includes(K.pane.id);
				reloadSoon({ books: true, card: mine });
			},
			openCard,
			saveFrom,
			/** Esc in the right column: back to the contact / nothing. */
			escape() {
				if (!K.pane || document.querySelector('.ml-scrim')) return false;
				if (K.pane.kind === 'edit' && K.pane.card) openCard(K.pane.card.id); else { K.pane = null; renderList(); renderPane(); }
				return true;
			},
		};
	}

	root.GCContactsView = { create };
})(typeof self !== 'undefined' ? self : this);
