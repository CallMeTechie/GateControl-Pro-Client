/**
 * GateControl -- Medien (renderer view: films and series from the NAS, Stufe 4f)
 *
 * The page "Medien" of the Pro client (mockups 8 and 10 of Stufe 4): the head with the tabs Übersicht · Filme ·
 * Serien · Ordner, "In allen Quellen suchen" and "Quellen"; the overview with the source chips and the way
 * ("Zuhause · direkt von der NAS"), the rows Weiterschauen, Zuletzt hinzugefügt, Filme and Serien (Umschalt + Mausrad
 * or the arrows at the edge); Filme and Serien as a grid with sorting and filters and the detail column on the right
 * (a click selects, a double click or Enter plays, the arrow keys move through the grid; a series shows its seasons
 * and episodes there); the search over all sources. NAS shares (Stufe 4h): their films and series (from the file names)
 * sit in the rows and grids with the mark "NAS" — a title Jellyfin has too shows once, Jellyfin's —, "Weiterschauen"
 * runs over all sources, and "Ordner" shows a share's folders and files (picture and title from the name or a picture
 * beside it, size, length, "noch 19 Min.", at home SMB, away WebDAV; at home the files Chromium cannot play are marked
 * before, "In VLC öffnen" / "In anderer App öffnen" in the detail and the player). The page
 * "Quellen" is media-sources-view.js (window.GCMediaSources), the card "Weiterschauen" of the
 * app's overview is built here as well (homeCard()).
 *
 * Medien-Plugin (W2): the sources come from the server — nothing is set up here. The entry "Medien" shows only while
 * the plugin gives its tab (o.onVisible(status.server.visible)); opening the page asks the server's list again. The
 * network rule of the core: away only through the VPN — while the core starts the tunnel the banner says "VPN wird
 * verbunden …"; does it not come up, "Unterwegs nur über VPN" with "VPN einschalten" (o.connectVpn).
 *
 * Data: window.gatecontrol.media (core MediaService over IPC; posters as gcmedia:// addresses, no access in the
 * page); texts: media.* of the Pro locales; view logic without DOM: media-state.js (window.GCMediaState). Playing is
 * the player's (o.play, Stufe 4g); without it the page has no play buttons.
 *
 * Note: server text only ever goes into textContent / attributes; icons are built from static path data with
 * createElementNS (no innerHTML).
 */
(function (root) {
	'use strict';

	const MS = root.GCMediaState;
	const NS = 'http://www.w3.org/2000/svg';
	const ICONS = {
		film: 'M5 4h14a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z|M7 4v16M17 4v16M3 9h4M3 15h4M17 9h4M17 15h4',
		search: 'M11 4a7 7 0 1 0 0 14a7 7 0 1 0 0-14|M20 20l-3.5-3.5',
		sliders: 'M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1|M15 4a2 2 0 1 0 0 4a2 2 0 1 0 0-4|M9 10a2 2 0 1 0 0 4a2 2 0 1 0 0-4|M17 16a2 2 0 1 0 0 4a2 2 0 1 0 0-4',
		play: 'M8 5v14l11-7z',
		check: 'M5 12l5 5 9-10',
		down: 'M6 9l6 6 6-6',
		left: 'M15 6l-6 6 6 6',
		right: 'M9 6l6 6-6 6',
		wifi: 'M2 8.5a15 15 0 0 1 20 0M5 12a10 10 0 0 1 14 0M8.5 15.5a5 5 0 0 1 7 0|M12 19h.01',
		globe: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18',
		folder: 'M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z',
		alert: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 8v5M12 16h.01',
		x: 'M18 6L6 18M6 6l12 12',
		restart: 'M3 12a9 9 0 1 0 3-6.7|M3 4v5h5',
		plus: 'M12 5v14M5 12h14',
		music: 'M9 18V5l11-2v13|M6 15a3 3 0 1 0 0 6a3 3 0 1 0 0-6|M17 13a3 3 0 1 0 0 6a3 3 0 1 0 0-6',
		up: 'M12 19V5M5 12l7-7 7 7',
		external: 'M14 4h6v6M20 4l-9 9|M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5',
	};

	function icon(name, size = 16, stroke = '2', fill = false) {
		const s = document.createElementNS(NS, 'svg');
		s.setAttribute('viewBox', '0 0 24 24');
		s.setAttribute('width', String(size));
		s.setAttribute('height', String(size));
		s.setAttribute('fill', fill ? 'currentColor' : 'none');
		s.setAttribute('stroke', 'currentColor');
		s.setAttribute('stroke-width', stroke);
		s.setAttribute('stroke-linecap', 'round');
		s.setAttribute('stroke-linejoin', 'round');
		s.setAttribute('aria-hidden', 'true');
		for (const d of String(ICONS[name] || ICONS.alert).split('|')) {
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
			else n.setAttribute(k, v === true ? '' : String(v));
		}
		for (const c of kids || []) if (c !== null && c !== undefined && c !== false && c !== '') n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
		return n;
	}
	const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };
	const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed', error: err && err.message });

	/** A picture of a gcmedia:// address with the placeholder underneath (a poster that does not load stays the placeholder). */
	function picture(src, cls, seed) {
		let h = 0;
		for (const ch of String(seed || '')) h = (h * 31 + ch.charCodeAt(0)) % 8;
		const box = el('span', { class: `md-pic ${cls || ''}`, 'data-pg': String(h) }, [el('span', { class: 'md-glyph' }, [icon('film', 22, '1.6')])]);
		if (src && /^gcmedia:\/\//.test(src)) {
			const img = el('img', { alt: '', draggable: 'false', loading: 'lazy', decoding: 'async' });
			img.addEventListener('load', () => box.classList.add('has-img'));
			img.addEventListener('error', () => img.remove());
			img.src = src;
			box.appendChild(img);
		}
		return box;
	}

	function mount(o) {
		const api = o.api;
		const t = o.t;
		const lang = () => (typeof o.getLocale === 'function' ? o.getLocale() : 'de');
		const now = typeof o.now === 'function' ? o.now : () => Date.now();
		const toast = typeof o.toast === 'function' ? o.toast : () => {};
		const canPlay = () => !!(o.player && typeof o.player.play === 'function');

		const S = {
			status: null,
			statusError: null,
			shown: false,
			view: 'library',        // library | sources
			tab: 'overview',
			sourceId: null,         // the Jellyfin source of the grid
			rows: { resume: [], latest: [], movies: [], series: [], loading: false, error: null, key: null },
			grids: new Map(),       // `${tab}|${source}|${sort}|${unplayed}|${genre}` → { items, total, next, loading, error }
			filters: { movies: { sort: 'name', unplayed: false, genre: null }, series: { sort: 'name', unplayed: false, genre: null } },
			selected: { movies: null, series: null, search: null },
			details: new Map(),     // `${source}|${item}` → answer of media:detail
			choice: new Map(),      // `${source}|${item}` → { audio, subtitle }
			seasons: new Map(),     // `${source}|${series}` → answer
			episodes: new Map(),    // `${source}|${series}|${season}` → answer
			season: new Map(),      // `${source}|${series}` → the season shown
			search: { q: '', items: [], loading: false, seq: 0, error: null },
			home: { items: [], loaded: false },
			signedOut: new Set(),
			vpn: null,              // the tunnel started for Medien: 'connecting' | 'failed' | null
			shareTitles: new Map(), // `${tab}|${share ids}` → { items, loading, loaded, error }: all films / series of the shares
			folder: { sourceId: null, dir: '', items: [], via: null, link: null, loading: false, error: null, seq: 0, loaded: false },
			checks: new Map(),      // `${source}|${item}` → the core's check of a share's file (or { loading })
			ext: null,              // media:external:info
		};
		let rowsSeq = 0;
		let searchTimer = null;
		const homeOnKey = MS.HOME_CARD_KEY;
		const storage = (() => { try { return root.localStorage || null; } catch { return null; } })();
		const homeCardOn = () => { try { return MS.homeCardOn(storage ? storage.getItem(homeOnKey) : null); } catch { return true; } };

		// ── Skeleton ─────────────────────────────────────────
		const refs = {};
		const rootEl = el('div', { class: 'md' });
		o.root.appendChild(rootEl);

		refs.lib = el('div', { class: 'md-libview' });
		refs.srcHost = el('div', { class: 'md-srcview', hidden: true });
		rootEl.append(refs.lib, refs.srcHost);

		refs.h = el('h1', { class: 'md-h' });
		refs.tabs = el('div', { class: 'seg md-tabs', role: 'tablist' });
		refs.searchInp = el('input', { class: 'md-search-inp', type: 'search', spellcheck: 'false', autocomplete: 'off' });
		refs.searchInp.addEventListener('input', () => onSearchInput());
		refs.searchInp.addEventListener('keydown', (e) => { if (e.key === 'Escape' && refs.searchInp.value) { e.stopPropagation(); refs.searchInp.value = ''; onSearchInput(); } });
		refs.search = el('label', { class: 'md-search' }, [icon('search', 15), refs.searchInp]);
		refs.srcBtnLabel = el('span');
		refs.srcBtn = el('button', { type: 'button', class: 'btn btn-sec btn-sm md-srcbtn', on: { click: () => openSources() } }, [icon('sliders', 15), refs.srcBtnLabel]);
		refs.filters = el('div', { class: 'md-filters', hidden: true });
		refs.head = el('div', { class: 'md-head' }, [refs.h, refs.tabs, el('span', { class: 'md-grow' }), refs.filters, refs.search, refs.srcBtn]);
		refs.banner = el('div', { class: 'md-banner', role: 'status', hidden: true });
		refs.body = el('div', { class: 'md-body' });
		refs.lib.append(refs.head, refs.banner, refs.body);

		// the status bar item while the page is shown ("Medien: Zuhause, direkt im LAN")
		refs.sb = el('span', { class: 'statusbar-item md-sb', hidden: true });
		if (o.statusHost) {
			const grow = o.statusHost.querySelector('.grow');
			if (grow) o.statusHost.insertBefore(refs.sb, grow); else o.statusHost.appendChild(refs.sb);
		}

		// Quellen (media-sources-view.js)
		const sources = root.GCMediaSources ? root.GCMediaSources.mount({
			root: refs.srcHost,
			api,
			t,
			getLocale: o.getLocale,
			toast,
			icon,
			el,
			storage,
			onBack: () => showLibrary(),
			onHomeCard: () => renderHome(),
			getStatus: () => S.status,
			reloadStatus: () => loadStatus(),
		}) : null;

		// ── Status, the way ──────────────────────────────────

		async function loadStatus() {
			let st;
			try { st = await api.status(); } catch (err) { st = fail(err); }
			if (st && st.ok) { S.status = st; S.statusError = null; } else S.statusError = st;
			afterStatus();
			return st;
		}

		/** Opening Medien: the server's list asked again (the core merges it), then the status. */
		async function refreshServer() {
			if (api.sources && typeof api.sources.refresh === 'function') {
				try { await api.sources.refresh(); } catch { /* the last list counts */ }
			}
			return loadStatus();
		}

		let lastVisible = null;
		function tellVisible() {
			const v = MS.visible(S.status);
			if (v === lastVisible || !S.status) return;
			lastVisible = v;
			if (typeof o.onVisible === 'function') o.onVisible(v, S.status.server || null);
		}

		function onVpn(ev) {
			const st = ev && ev.state;
			S.vpn = st === 'connecting' ? 'connecting' : st === 'failed' ? 'failed' : null;
			renderBanner();
			if (st === 'up') loadStatus().then(() => { if (S.shown && S.view === 'library') loadRows(true); }).catch(() => {});
		}

		async function connectVpn() {
			if (typeof o.connectVpn !== 'function') return;
			S.vpn = 'connecting';
			renderBanner();
			try { await o.connectVpn(); } catch { /* the tunnel's own message */ }
			S.vpn = null;
			await loadStatus();
			if (S.view === 'library') loadRows(true);
		}

		function afterStatus() {
			const src = MS.pickSource(S.status, S.sourceId);
			S.sourceId = src ? src.id : null;
			for (const id of [...S.signedOut]) {
				const s = MS.sourcesOf(S.status).jellyfin.find((x) => x.id === id);
				if (!s || s.ready) S.signedOut.delete(id);
			}
			render();
			renderHome();
			if (sources) sources.render();
			tellVisible();
		}

		function source(id) { return MS.sourcesOf(S.status).all.find((s) => s.id === id) || null; }

		function onLink(ev) {
			if (!ev || !S.status) return;
			const s = (S.status.sources || []).find((x) => x.id === ev.sourceId);
			if (s) s.link = ev.link;
			renderWay();
			if (sources) sources.render();
		}

		function currentLink() {
			const s = source(S.sourceId) || MS.sourcesOf(S.status).shares[0] || null;
			return s ? s.link : null;
		}

		function renderWay() {
			const line = MS.statusLine(currentLink(), t, lang());
			refs.sb.hidden = !S.shown || !line;
			clear(refs.sb);
			if (line) refs.sb.append(icon('film', 13, '1.8'), el('span', { text: line }));
			if (refs.way) {
				const w = MS.linkLabel(currentLink(), t, lang());
				refs.way.className = `md-pill md-way ${w.cls}`;
				clear(refs.way).append(icon(w.cls === 'is-away' ? 'globe' : 'wifi', 13), el('span', { text: w.text }));
			}
		}

		function handle(r, sourceId) {
			if (r && !r.ok && r.code === 'signed_out' && sourceId) {
				S.signedOut.add(sourceId);
				renderBanner();
			}
			if (r && !r.ok && r.code === 'vpn_required' && S.vpn !== 'connecting') {
				S.vpn = 'failed';
				renderBanner();
			}
			return r;
		}

		function renderBanner() {
			clear(refs.banner);
			// the network rule: "VPN wird verbunden …" / "Unterwegs nur über VPN – VPN einschalten"
			if (S.vpn) {
				refs.banner.hidden = false;
				refs.banner.className = `md-banner md-vpn is-${S.vpn}`;
				if (S.vpn === 'connecting') refs.banner.append(el('span', { class: 'dot pulse' }), el('span', { class: 'md-grow', text: t('media.vpn.connecting') }));
				else {
					refs.banner.append(icon('alert', 15), el('span', { class: 'md-grow', text: t('media.vpn.required') }));
					if (typeof o.connectVpn === 'function') refs.banner.append(el('button', { type: 'button', class: 'btn btn-pri btn-xs md-vpn-on', text: t('media.vpn.connect'), on: { click: () => connectVpn() } }));
				}
				return;
			}
			refs.banner.className = 'md-banner';
			const out = [...S.signedOut].map((id) => source(id)).filter(Boolean);
			refs.banner.hidden = !out.length;
			if (!out.length) return;
			const s = out[0];
			// a source of the server signs in again by itself (the plugin confirms): no button, nothing to type
			refs.banner.append(icon('alert', 15), el('span', { class: 'md-grow', text: s.managed ? t('media.signedOutAuto', { name: MS.sourceChip(s, t) }) : t('media.signedOut', { name: MS.sourceChip(s, t) }) }));
		}

		// ── Head ─────────────────────────────────────────────

		function renderHead() {
			refs.h.textContent = t('media.title');
			refs.searchInp.placeholder = t('media.search');
			refs.searchInp.setAttribute('aria-label', t('media.search'));
			refs.srcBtnLabel.textContent = t('media.sources.button');
			clear(refs.tabs);
			refs.tabs.setAttribute('aria-label', t('media.title'));
			for (const tab of MS.TABS) {
				const on = S.tab === tab && !S.search.q;
				refs.tabs.appendChild(el('button', {
					type: 'button', role: 'tab', class: on ? 'on' : '', 'aria-selected': on ? 'true' : 'false', 'data-tab': tab,
					text: t(`media.tabs.${tab}`), on: { click: () => setTab(tab) },
				}));
			}
			const grid = (S.tab === 'movies' || S.tab === 'series') && !S.search.q;
			refs.filters.hidden = !grid;
			refs.search.hidden = grid;
			refs.srcBtn.hidden = grid;
			if (grid) renderFilters();
		}

		function renderFilters() {
			const tab = S.tab;
			const f = S.filters[tab];
			clear(refs.filters);
			const sort = el('select', { class: 'md-select md-sort', 'aria-label': t('media.sort.label') });
			for (const k of MS.SORTS) sort.appendChild(el('option', { value: k, text: t(`media.sort.${k}`), selected: f.sort === k }));
			sort.addEventListener('change', () => { f.sort = sort.value; renderBody(); });
			const unplayed = el('button', { type: 'button', class: `md-pill md-toggle${f.unplayed ? ' is-on' : ''}`, 'aria-pressed': f.unplayed ? 'true' : 'false', text: t('media.filter.unplayed'), on: { click: () => { f.unplayed = !f.unplayed; render(); } } });
			const genre = el('select', { class: 'md-select md-genre', 'aria-label': t('media.filter.genre') });
			genre.appendChild(el('option', { value: '', text: t('media.filter.allGenres') }));
			const g = grid(tab);
			for (const name of MS.genresOf(g ? g.items : [], f.genre)) genre.appendChild(el('option', { value: name, text: name, selected: f.genre === name }));
			genre.addEventListener('change', () => { f.genre = genre.value || null; render(); });
			refs.filters.append(sort, unplayed, genre);
		}

		function setTab(tab) {
			if (!MS.TABS.includes(tab)) return;
			if (S.search.q) { refs.searchInp.value = ''; S.search.q = ''; S.search.items = []; }
			S.tab = tab;
			if (S.view !== 'library') showLibrary(); else render();
		}

		// ── Body ─────────────────────────────────────────────

		function render() {
			renderHead();
			renderBanner();
			renderWay();
			renderBody();
		}

		function renderBody() {
			clear(refs.body);
			refs.grid = null;
			if (!S.status) {
				refs.body.appendChild(el('div', { class: 'md-state', text: S.statusError ? MS.errorText(S.statusError.code, t) : t('media.loading') }));
				return;
			}
			if (S.status.supported === false) {
				refs.body.appendChild(emptyCard(t('media.unsupported.title'), t('media.unsupported.text'), null));
				return;
			}
			const { all, library } = MS.sourcesOf(S.status);
			if (S.search.q) { renderSearch(); return; }
			if (S.tab === 'folders') { renderFolders(); return; }
			if (!all.length) {
				const server = S.status.server;
				const off = server && server.state === 'unavailable';
				refs.body.appendChild(emptyCard(off ? t(server.reason === 'license_required' ? 'media.server.license' : 'media.server.off') : t('media.empty.title'), t('media.empty.managed'), null));
				return;
			}
			if (!library.length) {
				refs.body.appendChild(emptyCard(t('media.noJellyfin.title'), t('media.noJellyfin.text'), { label: t('media.sources.button'), click: () => openSources() }));
				return;
			}
			if (S.tab === 'overview') renderOverview();
			else renderGrid(S.tab);
		}

		function emptyCard(title, text, action) {
			return el('div', { class: 'md-empty' }, [
				el('span', { class: 'md-empty-ic' }, [icon('film', 26, '1.6')]),
				el('h2', { class: 'md-empty-h', text: title }),
				el('p', { class: 'md-empty-tx', text }),
				action ? el('button', { type: 'button', class: 'btn btn-pri', on: { click: action.click } }, [el('span', { text: action.label })]) : null,
			]);
		}

		// ── Ordner: the folders of a share (4h) ─────────────

		function folderShare() {
			const { shares } = MS.sourcesOf(S.status);
			return shares.find((x) => x.id === S.folder.sourceId) || shares[0] || null;
		}

		async function loadFolder(sourceId, dir) {
			const seq = ++S.folder.seq;
			const same = S.folder.sourceId === sourceId && S.folder.dir === dir;
			S.folder = { ...S.folder, sourceId, dir, items: same ? S.folder.items : [], loading: true, error: null, seq };
			let r;
			try { r = await api.shareList(sourceId, dir); } catch (err) { r = fail(err); }
			if (seq !== S.folder.seq) return;
			if (r && r.ok) {
				S.folder = { ...S.folder, items: MS.folderItems(r.items), via: r.via || null, link: r.link || null, loading: false, loaded: true, error: null, dir: r.dir || '' };
				checkFolder(sourceId);
			} else S.folder = { ...S.folder, items: [], loading: false, loaded: true, error: (r && r.code) || 'failed' };
			if (S.shown && S.view === 'library' && S.tab === 'folders' && !S.search.q) renderBody();
		}

		/** At home the files of the folder are checked before (Chromium's formats); away only when one starts (the tunnel). */
		async function checkFolder(sourceId) {
			if (!S.folder.link || S.folder.link.atHome !== true || typeof api.shareCheck !== 'function') return;
			const seq = S.folder.seq;
			const todo = S.folder.items.filter((e) => e.kind === 'video' && e.itemId && !S.checks.has(`${sourceId}|${e.itemId}`)).slice(0, 40);
			let at = 0;
			const worker = async () => {
				while (at < todo.length && seq === S.folder.seq) {
					const e = todo[at++];
					const k = `${sourceId}|${e.itemId}`;
					S.checks.set(k, { loading: true });
					let r;
					try { r = await api.shareCheck(sourceId, e.itemId); } catch (err) { r = fail(err); }
					S.checks.set(k, r && r.ok ? r.check : { error: (r && r.code) || 'failed' });
					if (seq === S.folder.seq) renderFolderNote(e);
				}
			};
			await Promise.all([worker(), worker()]);
		}

		function renderFolderNote(e) {
			if (!refs.folderList) return;
			const row = [...refs.folderList.querySelectorAll('.md-fr')].find((x) => x.getAttribute('data-path') === e.path);
			const box = row ? row.querySelector('.md-fr-note') : null;
			if (!box) return;
			const note = MS.checkNote(S.checks.get(`${S.folder.sourceId}|${e.itemId}`), t);
			box.hidden = !note || note.level === 'ok' || note.level === 'unknown';
			box.textContent = note ? note.text : '';
			box.className = `md-fr-note is-${note ? note.level : 'unknown'}`;
		}

		function openFolder(dir) {
			const share = folderShare();
			if (!share) return;
			loadFolder(share.id, dir);
			renderBody();
		}

		/** A file of the folder as a title for the detail and the player (its id f:<path>, the progress of this PC). */
		function folderTitle(share, e) {
			const p = e.progress || null;
			const ep = Number.isInteger(e.season) && Number.isInteger(e.episode);
			return {
				id: e.itemId, sourceId: share.id, kind: ep ? 'episode' : 'movie', name: e.title || MS.baseName(e.name), seriesName: ep ? e.seriesName : null,
				season: e.season ?? null, episode: e.episode ?? null, year: e.year || null, runtimeMs: p && p.durationMs > 0 ? p.durationMs : null,
				positionMs: p && !p.played ? p.positionMs || 0 : 0, played: !!(p && p.played), fromShare: true, poster: e.poster || null, backdrop: null,
			};
		}

		function renderFolders() {
			const { shares } = MS.sourcesOf(S.status);
			if (!shares.length) {
				refs.body.appendChild(el('div', { class: 'md-empty md-folders' }, [
					el('span', { class: 'md-empty-ic' }, [icon('folder', 26, '1.6')]),
					el('h2', { class: 'md-empty-h', text: t('media.folders.title') }),
					el('p', { class: 'md-empty-tx', text: t('media.folders.text') }),
					el('button', { type: 'button', class: 'btn btn-sec', text: t('media.folders.sources'), on: { click: () => openSources() } }),
				]));
				return;
			}
			const share = folderShare();
			if (S.folder.sourceId !== share.id || (!S.folder.loaded && !S.folder.loading)) { loadFolder(share.id, S.folder.sourceId === share.id ? S.folder.dir : ''); }
			const f = S.folder;
			const wrap = el('div', { class: 'md-fv' });
			// the shares (more than one: chips), the path, the way
			if (shares.length > 1) {
				const chips = el('div', { class: 'md-chips md-fv-shares' });
				for (const x of shares) {
					const on = x.id === share.id;
					chips.appendChild(el('button', {
						type: 'button', class: `md-pill md-src${on ? ' is-on' : ''}`, 'aria-pressed': on ? 'true' : 'false', 'data-id': x.id,
						on: { click: () => { if (x.id !== S.folder.sourceId) { S.folder = { ...S.folder, sourceId: x.id, dir: '', items: [], loaded: false }; renderBody(); } } },
					}, [icon('folder', 13), el('span', { text: MS.sharePath(x) })]));
				}
				wrap.appendChild(chips);
			}
			const crumbs = el('nav', { class: 'md-crumbs', 'aria-label': t('media.folders.path') });
			const list = MS.crumbs(f.dir, MS.sharePath(share));
			list.forEach((c, i) => {
				if (i) crumbs.appendChild(el('span', { class: 'md-crumb-sep', 'aria-hidden': 'true', text: '›' }));
				const last = i === list.length - 1;
				crumbs.appendChild(el('button', { type: 'button', class: `md-crumb${last ? ' is-cur' : ''}`, 'aria-current': last ? 'location' : null, text: c.label, on: { click: () => { if (!last) openFolder(c.dir); } } }));
			});
			const way = MS.shareWay(share, f.via, f.link || share.link, t);
			const up = MS.parentDir(f.dir);
			wrap.appendChild(el('div', { class: 'md-fv-head' }, [
				up !== null ? el('button', { type: 'button', class: 'btn btn-sec btn-sm btn-icon md-fv-up', title: t('media.folders.up'), 'aria-label': t('media.folders.up'), on: { click: () => openFolder(up) } }, [icon('up', 15)]) : null,
				crumbs,
				el('span', { class: `md-pill md-fv-way ${MS.wayOf(f.link || share.link) === 'away' ? 'is-away' : 'is-home'}` }, [icon(MS.wayOf(f.link || share.link) === 'away' ? 'globe' : 'wifi', 13), el('span', { text: way.label })]),
			]));
			const box = el('div', { class: 'md-fl scroll', role: 'list', 'aria-label': t('media.tabs.folders') });
			refs.folderList = box;
			if (f.loading && !f.items.length) box.appendChild(el('div', { class: 'md-state', text: t('media.loading') }));
			else if (f.error) box.appendChild(el('div', { class: 'md-state is-err', text: MS.errorText(f.error, t) }));
			else if (!f.items.length) box.appendChild(el('div', { class: 'md-state', text: t('media.folders.emptyDir') }));
			const videos = f.items.filter((e) => !e.directory && e.itemId);
			for (const e of f.items) box.appendChild(folderRow(share, e, videos));
			wrap.appendChild(box);
			wrap.appendChild(el('div', { class: 'md-fv-hint', text: way.hint }));
			refs.body.appendChild(wrap);
		}

		function folderRow(share, e, videos) {
			const r = MS.folderRow(e, t, lang());
			if (r.kind === 'folder') {
				return el('button', { type: 'button', class: 'md-fr is-dir', role: 'listitem', 'data-path': e.path, on: { click: () => openFolder(e.path) } }, [
					el('span', { class: 'md-fr-ic' }, [icon('folder', 20, '1.8')]),
					el('span', { class: 'md-fr-tx' }, [el('b', { text: r.title })]),
					icon('right', 16),
				]);
			}
			const playable = !!e.itemId || r.kind === 'audio';
			const note = e.itemId ? MS.checkNote(S.checks.get(`${share.id}|${e.itemId}`), t) : null;
			const play = () => { if (e.itemId) playFile(share, e, videos); };
			const thumb = r.kind === 'audio'
				? el('span', { class: 'md-fr-th is-audio' }, [icon('music', 18, '1.8')])
				: el('span', { class: 'md-fr-th' }, [picture(r.picture, 'is-wide', e.path), r.progress ? el('span', { class: 'md-bar' }, [el('span', { style: `width:${r.progress}%` })]) : null]);
			return el('div', { class: `md-fr${r.played ? ' is-played' : ''}`, role: 'listitem', 'data-path': e.path, title: r.file }, [
				el('button', { type: 'button', class: 'md-fr-open', 'aria-label': `${r.title}${r.sub ? ` · ${r.sub}` : ''}`, disabled: !playable || !canPlay() || !e.itemId, on: { click: play } }),
				thumb,
				el('span', { class: 'md-fr-tx' }, [
					el('b', { text: r.title }),
					el('small', { text: r.sub }),
					el('span', { class: `md-fr-note is-${note ? note.level : 'unknown'}`, hidden: !note || note.level === 'ok' || note.level === 'unknown', text: note ? note.text : '' }),
				]),
				r.played ? el('span', { class: 'md-seen is-inline', title: t('media.detail.played') }, [icon('check', 12, '3')]) : null,
				canPlay() && e.itemId ? el('button', { type: 'button', class: 'md-ep-play md-fr-play', 'aria-label': `${t('media.detail.play')}: ${r.title}`, title: t('media.detail.play'), on: { click: play } }, [icon('play', 13, '2', true)]) : null,
			]);
		}

		function playFile(share, e, videos) {
			if (!canPlay()) return;
			const it = folderTitle(share, e);
			const list = videos.map((x) => folderTitle(share, x));
			o.player.play({
				item: it,
				detail: null,
				startMs: it.played ? 0 : it.positionMs || 0,
				next: (cur) => { const i = list.findIndex((x) => x.id === (cur || it).id); return i >= 0 && i + 1 < list.length ? list[i + 1] : null; },
				onEnd: () => refreshAfterPlay(),
			});
		}

		// ── Overview: chips, the way, the rows ───────────────

		function rowsKey() {
			return MS.sourcesOf(S.status).library.map((s) => s.id).join(',');
		}

		/** The Jellyfin titles the page knows so far: a share's twin of one of them is not shown (Jellyfin wins). */
		function knownJellyfin() {
			const out = [];
			for (const k of ['latest', 'movies', 'series']) for (const x of S.rows[k] || []) if (!x.fromShare) out.push(x);
			for (const g of S.grids.values()) for (const x of g.items || []) if (!x.fromShare) out.push(x);
			return out;
		}

		async function loadRows(force = false) {
			const key = rowsKey();
			if (!force && S.rows.key === key && (S.rows.loading || S.rows.loaded)) return;
			const seq = ++rowsSeq;
			S.rows = { ...S.rows, key, loading: true, error: null };
			const { library, shares } = MS.sourcesOf(S.status);
			const main = MS.pickSource(S.status, S.sourceId);
			const call = (list, fn) => Promise.all(list.map((s) => fn(s).then((r) => handle(r, s.id)).catch(fail)));
			// Jellyfin's rows of the chosen server, the shares' newest films and series beside them
			const rowOf = (fn) => call((main ? [main] : []).concat(shares), (s) => fn(s.id, { start: 0, limit: MS.ROW_LIMIT, sort: 'added' }));
			const [resume, latest, movies, series] = await Promise.all([
				call(library, (s) => api.resume(s.id, MS.ROW_LIMIT)),
				call(library, (s) => api.latest(s.id, MS.ROW_LIMIT)),
				rowOf(api.movies),
				rowOf(api.series),
			]);
			if (seq !== rowsSeq) return;
			const failed = [...resume, ...latest].every((r) => !r || !r.ok);
			const jf = [...latest, ...movies, ...series].flatMap((r) => (r && r.ok ? r.items : [])).filter((x) => !x.fromShare);
			S.rows = {
				key, loading: false, loaded: true,
				error: failed ? (resume.concat(latest).find((r) => r && r.code) || {}).code || 'failed' : null,
				resume: MS.mergeResume(resume, MS.ROW_LIMIT, jf),
				latest: MS.mergeLatest(latest, MS.ROW_LIMIT, jf).filter((x) => x.kind !== 'episode'),
				movies: MS.mergeLatest(movies, MS.ROW_LIMIT, jf),
				series: MS.mergeLatest(series, MS.ROW_LIMIT, jf),
			};
			S.home = { items: S.rows.resume, loaded: true };
			renderHome();
			if (S.shown && S.view === 'library' && S.tab === 'overview' && !S.search.q) renderBody();
			renderWay();
		}

		function renderOverview() {
			const { jellyfin, shares } = MS.sourcesOf(S.status);
			const chips = el('div', { class: 'md-chips' });
			for (const s of jellyfin) {
				const on = s.id === S.sourceId;
				chips.appendChild(el('button', {
					type: 'button', class: `md-pill md-src${on ? ' is-on' : ''}${s.ready ? '' : ' is-off'}`, 'aria-pressed': on ? 'true' : 'false',
					on: { click: () => { if (!s.ready) { openSources(); return; } S.sourceId = s.id; S.grids.clear(); loadRows(true); render(); } },
				}, [el('span', { class: 'md-dot' }), el('span', { text: MS.sourceChip(s, t) })]));
			}
			for (const s of shares) {
				chips.appendChild(el('button', {
					type: 'button', class: 'md-pill md-src is-share', 'data-id': s.id, title: t('media.folders.open'),
					on: { click: () => { S.folder = { ...S.folder, sourceId: s.id, dir: '', items: [], loaded: false }; setTab('folders'); } },
				}, [icon('folder', 13), el('span', { text: MS.sourceChip(s, t) })]));
			}
			refs.way = el('span', { class: 'md-pill md-way' });
			chips.appendChild(refs.way);
			const wrap = el('div', { class: 'md-ov scroll' }, [chips]);
			refs.body.appendChild(wrap);
			renderWay();

			if (S.rows.key !== rowsKey() || (!S.rows.loaded && !S.rows.loading)) loadRows();
			if (S.rows.loading && !S.rows.loaded) { wrap.appendChild(el('div', { class: 'md-state', text: t('media.loading') })); return; }
			if (S.rows.error) wrap.appendChild(el('div', { class: 'md-state is-err', text: MS.errorText(S.rows.error, t) }));
			const n = now();
			if (S.rows.resume.length) {
				wrap.appendChild(row(t('media.row.resume'), t('media.row.count', { count: S.rows.resume.length }), S.rows.resume.map((it) => thumb(it)), null, 'is-wide'));
			}
			if (S.rows.latest.length) {
				wrap.appendChild(row(t('media.row.latest'), MS.latestSub(S.rows.latest, t, n), S.rows.latest.map((it) => poster(it, { full: true })), null));
			}
			if (S.rows.movies.length) wrap.appendChild(row(t('media.row.movies'), '', S.rows.movies.map((it) => poster(it, { full: true })), () => setTab('movies')));
			if (S.rows.series.length) wrap.appendChild(row(t('media.row.series'), '', S.rows.series.map((it) => poster(it, { full: true })), () => setTab('series')));
			if (!S.rows.resume.length && !S.rows.latest.length && !S.rows.movies.length && !S.rows.series.length && !S.rows.error) {
				wrap.appendChild(el('div', { class: 'md-state', text: t('media.empty.nothing') }));
			}
		}

		/** A row with its head and the arrows at the edges (shown while it can scroll that way). */
		function row(label, sub, cards, all, cls) {
			const track = el('div', { class: `md-row ${cls || ''}`, role: 'list' }, cards.map((c) => { c.setAttribute('role', 'listitem'); return c; }));
			const prev = el('button', { type: 'button', class: 'md-edge is-prev', tabindex: '-1', 'aria-label': t('media.row.back'), on: { click: () => track.scrollBy({ left: -track.clientWidth * 0.8, behavior: 'smooth' }) } }, [icon('left', 18)]);
			const next = el('button', { type: 'button', class: 'md-edge is-next', tabindex: '-1', 'aria-label': t('media.row.more'), on: { click: () => track.scrollBy({ left: track.clientWidth * 0.8, behavior: 'smooth' }) } }, [icon('right', 18)]);
			const edges = () => {
				prev.hidden = track.scrollLeft <= 2;
				next.hidden = track.scrollLeft + track.clientWidth >= track.scrollWidth - 2;
			};
			track.addEventListener('scroll', edges, { passive: true });
			setTimeout(edges, 0);
			if (typeof ResizeObserver === 'function') new ResizeObserver(edges).observe(track);
			const head = el('div', { class: 'md-lbl' }, [
				el('span', { class: 'md-lbl-t', text: label }),
				sub ? el('span', { class: 'md-lbl-s', text: sub }) : null,
				el('span', { class: 'md-grow' }),
				all ? el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('media.row.all'), on: { click: all } }) : null,
			]);
			return el('section', { class: 'md-sec' }, [head, el('div', { class: 'md-rowwrap' }, [track, prev, next])]);
		}

		/** A card of "Weiterschauen" (16:9). A click opens the title, the ▶ on it plays (with the player). */
		function thumb(it) {
			const c = MS.resumeCard(it, t);
			const pic = picture(c.picture, 'is-wide', it.seriesId || it.id);
			const card = el('div', { class: 'md-th', 'data-id': it.id }, [
				pic,
				c.nas ? el('span', { class: 'md-mk', text: t('media.mark.nas') }) : null,
				c.left ? el('span', { class: 'md-dur', text: c.left }) : null,
				el('button', { type: 'button', class: 'md-th-open', 'aria-label': `${c.title}${c.sub ? ` · ${c.sub}` : ''}`, on: { click: () => openItem(it), dblclick: () => playItem(it) } }),
				canPlay() ? el('button', { type: 'button', class: 'md-th-play', 'aria-label': t('media.detail.resume', { time: MS.clock(it.positionMs) }), title: t('media.detail.resume', { time: MS.clock(it.positionMs) }), on: { click: (e) => { e.stopPropagation(); playItem(it); } } }, [icon('play', 18, '2', true)]) : null,
				el('div', { class: 'md-cap' }, [el('b', { text: c.title }), c.sub ? el('small', { text: c.sub }) : null]),
				el('div', { class: 'md-bar' }, [el('span', { style: `width:${c.progress}%` })]),
			]);
			return card;
		}

		/** A poster (2:3) of a row or the grid. */
		function poster(it, { full = false, grid: inGrid = false, selected = false } = {}) {
			const c = MS.posterCard(it, t, now(), { full });
			const b = el('button', {
				type: 'button', class: `md-pst${selected ? ' is-cur' : ''}${c.played ? ' is-played' : ''}`, 'data-id': it.id,
				'aria-label': `${c.title}${c.sub ? ` · ${c.sub}` : ''}`, 'aria-pressed': inGrid ? (selected ? 'true' : 'false') : null,
			}, [
				picture(c.picture, '', it.id),
				// "NAS" on the left (a share's title), "NEU" on the right — both can be
				c.nas ? el('span', { class: 'md-mk', text: t('media.mark.nas') }) : null,
				c.isNew ? el('span', { class: 'md-mk is-new', text: t('media.mark.new') }) : null,
				c.played ? el('span', { class: 'md-seen', title: t('media.detail.played') }, [icon('check', 12, '3')]) : null,
				c.progress ? el('div', { class: 'md-bar' }, [el('span', { style: `width:${c.progress}%` })]) : null,
				el('span', { class: 'md-pt' }, [el('b', { text: c.title }), c.sub ? el('small', { text: c.sub }) : null]),
			]);
			if (inGrid) {
				b.addEventListener('click', () => select(it));
				b.addEventListener('dblclick', () => playItem(it));
				b.addEventListener('keydown', (e) => onGridKey(e, it));
			} else {
				b.addEventListener('click', () => openItem(it));
				b.addEventListener('dblclick', () => playItem(it));
			}
			return b;
		}

		/** A title of a row: its tab with the title selected (an episode: its series). */
		function openItem(it) {
			if (it.kind === 'episode' && it.seriesId) {
				S.selected.series = { id: it.seriesId, sourceId: it.sourceId, kind: 'series', name: it.seriesName || it.name, posterId: null, episodeHint: it };
				S.season.set(`${it.sourceId}|${it.seriesId}`, it.seasonId || null);
				S.tab = 'series';
			} else if (it.kind === 'series') {
				S.selected.series = it;
				S.tab = 'series';
			} else {
				S.selected.movies = it;
				S.tab = 'movies';
			}
			if (it.sourceId && it.sourceId !== S.sourceId && MS.sourcesOf(S.status).ready.some((s) => s.id === it.sourceId)) S.sourceId = it.sourceId;
			if (S.search.q) { refs.searchInp.value = ''; S.search = { ...S.search, q: '', items: [], seq: S.search.seq + 1 }; }
			if (S.view !== 'library') showLibrary(); else render();
		}

		// ── Grid with the detail column ──────────────────────

		function gridKey(tab) {
			const f = S.filters[tab];
			return `${tab}|${S.sourceId}|${f.sort}|${f.unplayed}|${f.genre || ''}`;
		}

		function grid(tab) { return S.grids.get(gridKey(tab)) || null; }

		/** All films (or series) of the shares, for their places in the grid (a share's index is small: pages of 200). */
		function shareTitlesKey(tab) { return `${tab}|${MS.sourcesOf(S.status).shares.map((x) => x.id).join(',')}`; }

		async function loadShareTitles(tab) {
			const key = shareTitlesKey(tab);
			const cur = S.shareTitles.get(key);
			if (cur && (cur.loading || cur.loaded)) return;
			const st = { items: [], loading: true, loaded: false, error: null };
			S.shareTitles.set(key, st);
			const fn = tab === 'series' ? api.series : api.movies;
			for (const sh of MS.sourcesOf(S.status).shares) {
				let start = 0;
				for (let n = 0; n < 50 && start !== null; n++) {
					let r;
					try { r = await fn(sh.id, { start, limit: 200, sort: 'name' }); } catch (err) { r = fail(err); }
					if (!r || !r.ok) { st.error = (r && r.code) || 'failed'; break; }
					st.items.push(...r.items);
					start = Number.isInteger(r.next) ? r.next : null;
				}
			}
			st.loading = false;
			st.loaded = true;
			if (S.shown && S.view === 'library' && S.tab === tab && !S.search.q) {
				const top = refs.gridWrap ? refs.gridWrap.scrollTop : 0;
				renderBody();
				if (refs.gridWrap) refs.gridWrap.scrollTop = top;
			}
		}

		async function loadPage(tab) {
			const key = gridKey(tab);
			const g = S.grids.get(key) || { items: [], total: null, next: 0, loading: false, error: null };
			if (g.loading || g.next === null) return;
			if (!S.sourceId) { S.grids.set(key, { ...g, next: null }); return; }
			g.loading = true;
			S.grids.set(key, g);
			const f = S.filters[tab];
			const id = S.sourceId;
			const fn = tab === 'series' ? api.series : api.movies;
			let r;
			try { r = await fn(id, { start: g.next, limit: MS.PAGE_SIZE, sort: f.sort, unplayed: f.unplayed, genre: f.genre }); } catch (err) { r = fail(err); }
			handle(r, id);
			g.loading = false;
			if (r && r.ok) Object.assign(g, MS.appendPage(g, r), { error: null });
			else { g.error = (r && r.code) || 'failed'; g.next = null; }
			if (S.shown && S.view === 'library' && S.tab === tab && !S.search.q && gridKey(tab) === key) {
				const st = refs.gridWrap ? refs.gridWrap.scrollTop : 0;
				renderBody();
				if (refs.gridWrap) refs.gridWrap.scrollTop = st;
				renderFilters();
			}
		}

		function renderGrid(tab) {
			const g = grid(tab);
			if (!g) loadPage(tab);
			const hasShares = MS.sourcesOf(S.status).shares.length > 0;
			const sh = hasShares ? S.shareTitles.get(shareTitlesKey(tab)) : null;
			if (hasShares && !sh) loadShareTitles(tab);
			const jfItems = g ? g.items : [];
			const complete = !S.sourceId || (!!g && g.next === null);
			const items = hasShares ? MS.mergeGrid(jfItems, complete, sh ? sh.items : [], S.filters[tab]) : jfItems;
			const sel = S.selected[tab];
			if (!sel && items.length) S.selected[tab] = items[0];
			const loading = (S.sourceId ? (g ? g.loading || (!g.items.length && g.next !== null) : true) : false) || (!!sh && sh.loading && !items.length) || (hasShares && !sh && !items.length);
			renderLib(tab, items, loading, (g && g.error) || (!items.length && sh && sh.error) || null, () => { const x = grid(tab); if (x && x.next !== null && !x.loading) loadPage(tab); });
		}

		function renderLib(tab, items, loading, error, more) {
			const sel = S.selected[tab];
			refs.gridItems = items;
			const gridEl = el('div', { class: 'md-grid', role: 'group', 'aria-label': t(`media.tabs.${tab === 'search' ? 'search' : tab}`) });
			for (const it of items) gridEl.appendChild(poster(it, { grid: true, selected: !!sel && sel.id === it.id }));
			refs.grid = gridEl;
			const wrap = el('div', { class: 'md-gridwrap scroll' }, [gridEl]);
			if (loading) wrap.appendChild(el('div', { class: 'md-state', text: t('media.loading') }));
			else if (error) wrap.appendChild(el('div', { class: 'md-state is-err', text: MS.errorText(error, t) }));
			else if (!items.length) wrap.appendChild(el('div', { class: 'md-state', text: tab === 'search' ? t('media.empty.noResults') : t('media.empty.nothing') }));
			if (more) wrap.addEventListener('scroll', () => { if (wrap.scrollTop + wrap.clientHeight >= wrap.scrollHeight - 400) more(); }, { passive: true });
			refs.gridWrap = wrap;
			refs.det = el('aside', { class: 'md-det scroll', 'aria-live': 'polite' });
			refs.body.appendChild(el('div', { class: 'md-lib' }, [wrap, refs.det]));
			renderDetail(tab);
			// a grid that does not fill its space yet: the next page
			if (more) setTimeout(() => { if (wrap.isConnected && wrap.scrollHeight <= wrap.clientHeight + 40) more(); }, 0);
		}

		function select(it) {
			const tab = S.search.q ? 'search' : S.tab;
			S.selected[tab] = it;
			if (refs.grid) for (const b of refs.grid.querySelectorAll('.md-pst')) {
				const on = b.getAttribute('data-id') === it.id;
				b.classList.toggle('is-cur', on);
				b.setAttribute('aria-pressed', on ? 'true' : 'false');
			}
			renderDetail(tab);
		}

		function columns() {
			const cells = refs.grid ? [...refs.grid.children] : [];
			if (!cells.length) return 1;
			const top = cells[0].offsetTop;
			let n = 0;
			for (const c of cells) { if (c.offsetTop !== top) break; n += 1; }
			return Math.max(1, n);
		}

		function onGridKey(e, it) {
			if (e.key === 'Enter') { e.preventDefault(); playItem(it); return; }
			if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End', 'PageUp', 'PageDown'].includes(e.key)) return;
			e.preventDefault();
			const cells = refs.grid ? [...refs.grid.querySelectorAll('.md-pst')] : [];
			const i = cells.indexOf(e.currentTarget);
			const j = MS.gridMove(i, e.key, columns(), cells.length);
			if (j < 0 || !cells[j]) return;
			cells[j].focus();
			const items = currentItems();
			if (items[j]) select(items[j]);
			cells[j].scrollIntoView({ block: 'nearest' });
		}

		function currentItems() {
			if (S.search.q) return S.search.items;
			return refs.gridItems || [];
		}

		// ── Detail column ────────────────────────────────────

		const dkey = (it) => `${it.sourceId}|${it.id}`;

		async function loadDetail(it) {
			const k = dkey(it);
			if (S.details.has(k)) return S.details.get(k);
			S.details.set(k, { loading: true });
			let r;
			try { r = await api.detail(it.sourceId, it.id); } catch (err) { r = fail(err); }
			handle(r, it.sourceId);
			S.details.set(k, r && r.ok ? r : { error: (r && r.code) || 'failed' });
			if (S.details.size > 80) S.details.delete(S.details.keys().next().value);
			return S.details.get(k);
		}

		function stillSelected(tab, it) {
			const cur = S.selected[tab];
			return S.shown && S.view === 'library' && cur && cur.id === it.id && refs.det && refs.det.isConnected;
		}

		function renderDetail(tab) {
			const det = refs.det;
			if (!det) return;
			clear(det);
			const it = S.selected[tab];
			if (!it) { det.appendChild(el('div', { class: 'md-det-none', text: t('media.detail.none') })); return; }
			const d = S.details.get(dkey(it));
			if (!d) loadDetail(it).then(() => { if (stillSelected(tab, it)) renderDetail(tab); });
			const title = d && d.title ? d.title : it;
			det.appendChild(picture(title.backdrop || it.backdrop || null, 'is-bd', it.id));
			const inner = el('div', { class: 'md-det-in' });
			det.appendChild(inner);
			inner.appendChild(el('h2', { class: 'md-det-h', text: title.kind === 'episode' && title.seriesName ? title.seriesName : title.name }));
			if (title.kind === 'episode') inner.appendChild(el('div', { class: 'md-det-ep', text: title.name }));
			const meta = MS.metaLine(title, t);
			if (meta) inner.appendChild(el('div', { class: 'md-det-meta', text: meta }));
			if (title.kind === 'series') { renderSeries(inner, tab, title); return; }
			if (d && d.loading) inner.appendChild(el('div', { class: 'md-state is-small', text: t('media.loading') }));
			if (d && d.error) inner.appendChild(el('div', { class: 'md-state is-small is-err', text: MS.errorText(d.error, t) }));
			if (title.fromShare === true || it.fromShare === true) renderShareFile(inner, tab, title, d);
			else renderPlayable(inner, tab, title, d && d.versions ? d.versions[0] : null, d && d.link);
			if (title.overview) inner.appendChild(el('p', { class: 'md-det-tx', text: title.overview }));
		}

		/** Film / episode: chips, progress, the buttons, sound / subtitles / quality. */
		function renderPlayable(inner, tab, title, version, link) {
			const caps = (S.status && S.status.caps) || {};
			const k = dkey(title);
			const ch = S.choice.get(k) || {};
			const audio = ch.audio !== undefined ? ch.audio : MS.pickedAudio(version);
			const sub = ch.subtitle !== undefined ? ch.subtitle : MS.pickedSubtitle(version);
			const chips = MS.detailChips(version, audio, caps, t);
			if (chips.length) inner.appendChild(el('div', { class: 'md-det-chips' }, chips.map((c) => el('span', { class: `md-pill ${c.cls}`, text: c.text }))));
			if (title.positionMs > 0 && !title.played && title.runtimeMs > 0) {
				inner.appendChild(el('div', { class: 'md-prog', title: `${MS.clock(title.positionMs)} / ${MS.clock(title.runtimeMs)}` }, [el('span', { style: `width:${Math.round(Math.min(1, title.positionMs / title.runtimeMs) * 100)}%` })]));
			}
			const btns = el('div', { class: 'md-det-btns' });
			if (canPlay()) {
				btns.appendChild(el('button', { type: 'button', class: 'btn btn-pri btn-sm md-play', on: { click: () => playItem(title) } }, [icon('play', 14, '2', true), el('span', { text: MS.playLabel(title, t) })]));
				if (title.positionMs > 0 && !title.played) btns.appendChild(el('button', { type: 'button', class: 'btn btn-sec btn-sm md-restart', text: t('media.detail.restart'), on: { click: () => playItem(title, { fromStart: true }) } }));
			}
			btns.appendChild(el('button', {
				type: 'button', class: `btn btn-sec btn-sm btn-icon md-played${title.played ? ' is-on' : ''}`, 'aria-pressed': title.played ? 'true' : 'false',
				title: title.played ? t('media.detail.markUnplayed') : t('media.detail.markPlayed'), 'aria-label': title.played ? t('media.detail.markUnplayed') : t('media.detail.markPlayed'),
				on: { click: () => togglePlayed(tab, title) },
			}, [icon('check', 15, '2.4')]));
			inner.appendChild(btns);
			if (!version) return;

			const aOpts = MS.audioOptions(version, caps, t);
			if (aOpts.length) {
				const cur = aOpts.find((x) => x.value === audio) || aOpts[0];
				inner.appendChild(selBox(t('media.detail.audio'), aOpts, cur.value, cur.why, (v) => { S.choice.set(k, { ...(S.choice.get(k) || {}), audio: Number(v) }); renderDetail(tab); }, 'md-sel-audio'));
			}
			const sOpts = MS.subtitleOptions(version, t);
			const sCur = sOpts.find((x) => x.value === sub) || sOpts[0];
			inner.appendChild(selBox(t('media.detail.subtitles'), sOpts, sCur.value, sCur.note, (v) => { S.choice.set(k, { ...(S.choice.get(k) || {}), subtitle: Number(v) }); renderDetail(tab); }, 'md-sel-sub'));
			const q = (S.status && S.status.quality) || 'auto';
			const srcObj = source(title.sourceId);
			const qNote = MS.qualityNote(q, version.quality, link || (srcObj && srcObj.link), t, lang(), srcObj && srcObj.alwaysOriginal);
			inner.appendChild(selBox(t('media.detail.quality'), MS.qualityOptions(t, lang()), q, qNote, (v) => setQuality(v, tab), 'md-sel-quality'));
		}

		/** A share's film or episode: the file as it is (always the original), the check, another app. */
		function renderShareFile(inner, tab, title, d) {
			const k = dkey(title);
			const share = d && d.share ? d.share : null;
			let check = S.checks.get(k);
			if (share && share.check && !check) { check = share.check; S.checks.set(k, check); }
			if (share && !check && typeof api.shareCheck === 'function') {
				S.checks.set(k, { loading: true });
				api.shareCheck(title.sourceId, title.id).catch(fail).then((r) => {
					S.checks.set(k, r && r.ok ? r.check : { error: (r && r.code) || 'failed' });
					if (stillSelected(tab, title)) renderDetail(tab);
				});
			}
			const note = check && check.verdict ? MS.checkNote(check, t) : null;
			const chips = [el('span', { class: 'md-pill', text: t('media.mark.nas') })];
			const v = d && d.versions ? d.versions[0] : null;
			if (v && v.container) chips.push(el('span', { class: 'md-pill', text: String(v.container) }));
			if (share && share.size) chips.push(el('span', { class: 'md-pill', text: MS.sizeLabel(share.size, lang()) }));
			if (share && share.via) chips.push(el('span', { class: 'md-pill', text: share.via === 'webdav' ? 'WebDAV' : 'SMB' }));
			if (note && note.level !== 'ok' && note.level !== 'unknown') chips.push(el('span', { class: 'md-pill is-warn md-check', text: note.text }));
			inner.appendChild(el('div', { class: 'md-det-chips' }, chips));
			if (title.positionMs > 0 && !title.played && title.runtimeMs > 0) {
				inner.appendChild(el('div', { class: 'md-prog', title: `${MS.clock(title.positionMs)} / ${MS.clock(title.runtimeMs)}` }, [el('span', { style: `width:${Math.round(Math.min(1, title.positionMs / title.runtimeMs) * 100)}%` })]));
			}
			const btns = el('div', { class: 'md-det-btns' });
			if (canPlay()) {
				btns.appendChild(el('button', { type: 'button', class: 'btn btn-pri btn-sm md-play', on: { click: () => playItem(title) } }, [icon('play', 14, '2', true), el('span', { text: MS.playLabel(title, t) })]));
				if (title.positionMs > 0 && !title.played) btns.appendChild(el('button', { type: 'button', class: 'btn btn-sec btn-sm md-restart', text: t('media.detail.restart'), on: { click: () => playItem(title, { fromStart: true }) } }));
			}
			btns.appendChild(el('button', {
				type: 'button', class: `btn btn-sec btn-sm btn-icon md-played${title.played ? ' is-on' : ''}`, 'aria-pressed': title.played ? 'true' : 'false',
				title: title.played ? t('media.detail.markUnplayed') : t('media.detail.markPlayed'), 'aria-label': title.played ? t('media.detail.markUnplayed') : t('media.detail.markPlayed'),
				on: { click: () => togglePlayed(tab, title) },
			}, [icon('check', 15, '2.4')]));
			inner.appendChild(btns);
			if (note && note.external) {
				const host = el('div', { class: 'md-det-btns md-ext' });
				inner.appendChild(host);
				externalInfo().then((info) => {
					const app = MS.externalApp(info, share && share.via);
					if (!host.isConnected) return;
					if (!app) { host.appendChild(el('div', { class: 'md-sel-n', text: t('media.check.noApp') })); return; }
					host.appendChild(el('button', { type: 'button', class: 'btn btn-sec btn-sm md-ext-btn', 'data-app': app, on: { click: () => openExternal(title, app) } }, [
						icon('external', 14), el('span', { text: app === 'vlc' ? t('media.check.vlc') : t('media.check.other') }),
					]));
				});
			}
			inner.appendChild(el('div', { class: 'md-sel-n md-orig', text: t('media.folders.originalHint') }));
		}

		async function externalInfo() {
			if (S.ext) return S.ext;
			let r;
			try { r = typeof api.externalInfo === 'function' ? await api.externalInfo() : null; } catch { r = null; }
			S.ext = r && r.ok ? r : { vlc: false, openPath: false };
			return S.ext;
		}

		async function openExternal(title, app) {
			let r;
			try { r = await api.shareExternal(title.sourceId, title.id, app, title.kind === 'episode' && title.seriesName ? `${title.seriesName} · ${title.name}` : title.name); } catch (err) { r = fail(err); }
			if (r && r.ok) toast(app === 'vlc' ? t('media.check.openedVlc') : t('media.check.openedOther'), 'info');
			else toast(MS.errorText(r && r.code, t), 'error');
		}

		function selBox(label, options, value, note, onChange, cls) {
			const id = `md-sel-${Math.random().toString(36).slice(2, 9)}`;
			const sel = el('select', { id, class: 'md-sel-native' });
			for (const op of options) sel.appendChild(el('option', { value: String(op.value), text: op.label, selected: String(op.value) === String(value) }));
			sel.addEventListener('change', () => onChange(sel.value));
			const cur = options.find((op) => String(op.value) === String(value)) || options[0];
			return el('div', { class: `md-sel ${cls || ''}` }, [
				el('label', { class: 'md-sel-k', for: id, text: label }),
				el('div', { class: 'md-sel-v' }, [el('span', { text: cur ? cur.label : '' }), icon('down', 15)]),
				note ? el('div', { class: 'md-sel-n', text: note }) : null,
				sel,
			]);
		}

		async function setQuality(v, tab) {
			let r;
			try { r = await api.setQuality(v); } catch (err) { r = fail(err); }
			if (r && r.ok) { if (S.status) S.status.quality = r.quality; } else toast(MS.errorText(r && r.code, t), 'error');
			renderDetail(tab);
		}

		async function togglePlayed(tab, title) {
			const want = !title.played;
			let r;
			try { r = await api.setPlayed(title.sourceId, title.id, want); } catch (err) { r = fail(err); }
			handle(r, title.sourceId);
			if (!r || !r.ok) { toast(MS.errorText(r && r.code, t), 'error'); return; }
			const fix = (x) => { if (x && x.id === title.id && x.sourceId === title.sourceId) { x.played = want; if (want) { x.positionMs = 0; x.resumable = false; x.progress = 0; } } };
			for (const g of S.grids.values()) g.items.forEach(fix);
			for (const k of ['resume', 'latest', 'movies', 'series']) S.rows[k].forEach(fix);
			for (const v of S.episodes.values()) if (v && v.items) v.items.forEach(fix);
			S.search.items.forEach(fix);
			for (const v of S.shareTitles.values()) v.items.forEach(fix);
			Object.values(S.selected).forEach(fix);
			const d = S.details.get(dkey(title));
			if (d && d.title) fix(d.title);
			if (want) S.rows.resume = S.rows.resume.filter((x) => !(x.id === title.id && x.sourceId === title.sourceId));
			S.home.items = S.rows.resume;
			renderHome();
			if (S.view === 'library') renderBody();
		}

		// ── Series: seasons and episodes ─────────────────────

		async function loadSeasons(sourceId, seriesId) {
			const k = `${sourceId}|${seriesId}`;
			if (S.seasons.has(k)) return S.seasons.get(k);
			S.seasons.set(k, { loading: true });
			let r;
			try { r = await api.seasons(sourceId, seriesId); } catch (err) { r = fail(err); }
			handle(r, sourceId);
			S.seasons.set(k, r && r.ok ? r : { error: (r && r.code) || 'failed' });
			return S.seasons.get(k);
		}

		async function loadEpisodes(sourceId, seriesId, seasonId) {
			const k = `${sourceId}|${seriesId}|${seasonId || ''}`;
			if (S.episodes.has(k)) return S.episodes.get(k);
			S.episodes.set(k, { loading: true });
			let r;
			try { r = await api.episodes(sourceId, seriesId, seasonId); } catch (err) { r = fail(err); }
			handle(r, sourceId);
			S.episodes.set(k, r && r.ok ? r : { error: (r && r.code) || 'failed' });
			return S.episodes.get(k);
		}

		function renderSeries(inner, tab, title) {
			const sk = `${title.sourceId}|${title.id}`;
			const se = S.seasons.get(sk);
			if (!se) loadSeasons(title.sourceId, title.id).then(() => { if (stillSelected(tab, title)) renderDetail(tab); });
			const seasons = se && se.items ? se.items : [];
			let seasonId = S.season.get(sk);
			if (!seasonId && seasons.length) {
				seasonId = MS.firstSeason(seasons, title.episodeHint || null);
				S.season.set(sk, seasonId);
			}
			const ek = `${title.sourceId}|${title.id}|${seasonId || ''}`;
			const ep = seasonId ? S.episodes.get(ek) : null;
			if (seasonId && !ep) loadEpisodes(title.sourceId, title.id, seasonId).then(() => { if (stillSelected(tab, title)) renderDetail(tab); });
			const episodes = ep && ep.items ? ep.items : [];
			const next = title.episodeHint && episodes.some((e) => e.id === title.episodeHint.id) ? episodes.find((e) => e.id === title.episodeHint.id) : MS.nextEpisode(episodes);

			const btns = el('div', { class: 'md-det-btns' });
			if (canPlay() && next) {
				const label = next.positionMs > 0 && !next.played
					? t('media.series.resume', { s: next.season ?? '', e: next.episode ?? '', time: MS.clock(next.positionMs) })
					: t('media.series.play', { s: next.season ?? '', e: next.episode ?? '' });
				btns.appendChild(el('button', { type: 'button', class: 'btn btn-pri btn-sm md-play', on: { click: () => playItem(next, { list: episodes }) } }, [icon('play', 14, '2', true), el('span', { text: label })]));
			}
			if (btns.childNodes.length) inner.appendChild(btns);
			if (title.overview) inner.appendChild(el('p', { class: 'md-det-tx', text: title.overview }));

			if (se && se.loading) { inner.appendChild(el('div', { class: 'md-state is-small', text: t('media.loading') })); return; }
			if (se && se.error) { inner.appendChild(el('div', { class: 'md-state is-small is-err', text: MS.errorText(se.error, t) })); return; }
			if (!seasons.length) return;
			const chips = el('div', { class: 'md-seasons', role: 'tablist', 'aria-label': t('media.series.seasons') });
			for (const c of MS.seasonChips(seasons, t)) {
				const on = c.id === seasonId;
				chips.appendChild(el('button', {
					type: 'button', role: 'tab', class: `md-pill md-toggle${on ? ' is-on' : ''}`, 'aria-selected': on ? 'true' : 'false', text: c.label,
					on: { click: () => { S.season.set(sk, c.id); if (title.episodeHint) title.episodeHint = null; renderDetail(tab); } },
				}));
			}
			inner.appendChild(chips);
			if (ep && ep.loading) { inner.appendChild(el('div', { class: 'md-state is-small', text: t('media.loading') })); return; }
			if (ep && ep.error) { inner.appendChild(el('div', { class: 'md-state is-small is-err', text: MS.errorText(ep.error, t) })); return; }
			const listEl = el('div', { class: 'md-eps', role: 'list', 'aria-label': t('media.series.episodes') });
			for (const e of episodes) {
				const r = MS.episodeRow(e, t);
				const isNext = next && next.id === e.id;
				const rowEl = el('div', { class: `md-ep${r.played ? ' is-played' : ''}${isNext ? ' is-next' : ''}`, role: 'listitem', 'data-id': e.id }, [
					el('span', { class: 'md-ep-n', text: r.num }),
					el('span', { class: 'md-ep-tx' }, [el('b', { text: r.title }), r.sub ? el('small', { text: r.sub }) : null,
						r.progress ? el('span', { class: 'md-bar is-inline' }, [el('span', { style: `width:${r.progress}%` })]) : null]),
					r.played ? el('span', { class: 'md-seen is-inline', title: t('media.detail.played') }, [icon('check', 12, '3')]) : null,
					canPlay() ? el('button', { type: 'button', class: 'md-ep-play', 'aria-label': `${t('media.detail.play')}: ${r.title}`, title: t('media.detail.play'), on: { click: () => playItem(e, { list: episodes }) } }, [icon('play', 13, '2', true)]) : null,
				]);
				rowEl.addEventListener('dblclick', () => playItem(e, { list: episodes }));
				listEl.appendChild(rowEl);
			}
			inner.appendChild(listEl);
		}

		// ── Playing (the player of 4g) ───────────────────────

		async function playItem(it, opts = {}) {
			if (!canPlay() || !it) return;
			if (it.kind === 'series') {
				const se = await loadSeasons(it.sourceId, it.id);
				const seasonId = se && se.items ? MS.firstSeason(se.items, null) : null;
				if (!seasonId) return;
				const ep = await loadEpisodes(it.sourceId, it.id, seasonId);
				const next = MS.nextEpisode(ep && ep.items);
				if (next) playItem(next, { list: ep.items });
				return;
			}
			const k = dkey(it);
			const ch = S.choice.get(k) || {};
			let list = opts.list || null;
			if (!list && it.kind === 'episode' && it.seriesId && it.seasonId) {
				const ep = await loadEpisodes(it.sourceId, it.seriesId, it.seasonId);
				list = ep && ep.items ? ep.items : null;
			}
			const d = S.details.get(k);
			o.player.play({
				item: it,
				detail: d && d.versions ? d : null,
				startMs: opts.fromStart ? 0 : (it.played ? 0 : it.positionMs || 0),
				audioIndex: ch.audio,
				subtitleIndex: ch.subtitle,
				next: it.kind === 'episode' && list ? (cur) => MS.episodeAfter(list, (cur || it).id) : null,
				onEnd: () => refreshAfterPlay(),
			});
		}

		/** After the player: the progress changed in Jellyfin — the rows, the grids' bars and the details again. */
		function refreshAfterPlay() {
			S.details.clear();
			S.episodes.clear();
			S.seasons.clear();
			S.grids.clear();
			S.shareTitles.clear();
			loadRows(true);
			if (S.tab === 'folders' && S.folder.sourceId) loadFolder(S.folder.sourceId, S.folder.dir);
			if (S.shown) render();
		}

		// ── Search over all sources ──────────────────────────

		function onSearchInput() {
			clearTimeout(searchTimer);
			const q = refs.searchInp.value.trim();
			if (!q) {
				S.search = { q: '', items: [], loading: false, seq: S.search.seq + 1, error: null };
				render();
				return;
			}
			searchTimer = setTimeout(() => runSearch(q), 280);
		}

		async function runSearch(q) {
			const seq = S.search.seq + 1;
			const first = !S.search.q;
			S.search = { q, items: first ? [] : S.search.items, loading: true, seq, error: null };
			if (first) S.selected.search = null;
			render();
			const library = MS.sourcesOf(S.status).library;
			const answers = await Promise.all(library.map((s) => api.search(s.id, q).then((r) => handle(r, s.id)).catch(fail)));
			if (S.search.seq !== seq) return;
			const items = MS.mergeSearch(answers, q);
			const err = answers.length && answers.every((r) => !r || !r.ok) ? (answers[0] && answers[0].code) || 'failed' : null;
			S.search = { q, items, loading: false, seq, error: err };
			if (!S.selected.search || !items.some((x) => x.id === S.selected.search.id)) S.selected.search = items[0] || null;
			if (S.shown && S.view === 'library') { renderHead(); renderBody(); }
		}

		function renderSearch() {
			refs.body.appendChild(el('div', { class: 'md-searchhead' }, [el('span', { text: t('media.searchFor', { q: S.search.q }) }), el('span', { class: 'md-grow' }),
				el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('media.searchClear'), on: { click: () => { refs.searchInp.value = ''; onSearchInput(); refs.searchInp.focus(); } } })]));
			renderLib('search', S.search.items, S.search.loading && !S.search.items.length, S.search.error, null);
		}

		// ── Quellen ──────────────────────────────────────────

		function openSources() {
			S.view = 'sources';
			refs.lib.hidden = true;
			refs.srcHost.hidden = false;
			if (sources) sources.show();
		}

		function showLibrary() {
			S.view = 'library';
			refs.srcHost.hidden = true;
			refs.lib.hidden = false;
			if (sources) sources.hide();
			render();
		}

		// ── The card "Weiterschauen" on the app's overview ───

		function renderHome() {
			const host = o.homeHost;
			if (!host) return;
			const library = S.status ? MS.sourcesOf(S.status).library : [];
			const items = S.home.items || [];
			const show = homeCardOn() && library.length > 0 && items.length > 0;
			host.hidden = !show;
			clear(host);
			if (!show) return;
			const list = el('div', { class: 'md-home-row' });
			for (const it of items.slice(0, 4)) {
				const c = MS.resumeCard(it, t);
				list.appendChild(el('button', {
					type: 'button', class: 'md-home-th', 'aria-label': `${c.title}${c.sub ? ` · ${c.sub}` : ''}`,
					on: { click: () => { if (typeof o.openPage === 'function') o.openPage(); if (canPlay()) playItem(it); else openItem(it); } },
				}, [
					picture(c.picture, 'is-wide', it.seriesId || it.id),
					c.left ? el('span', { class: 'md-dur', text: c.left }) : null,
					canPlay() ? el('span', { class: 'md-home-play' }, [icon('play', 16, '2', true)]) : null,
					el('div', { class: 'md-cap' }, [el('b', { text: c.title }), c.sub ? el('small', { text: c.sub }) : null]),
					el('div', { class: 'md-bar' }, [el('span', { style: `width:${c.progress}%` })]),
				]));
			}
			host.append(
				el('div', { class: 'md-home-head' }, [
					el('span', { class: 'md-home-ic' }, [icon('film', 16, '1.9')]),
					el('h2', { class: 'h-card grow', text: t('media.home.title') }),
					el('button', { type: 'button', class: 'btn btn-ghost btn-xs', text: t('media.home.all'), on: { click: () => { if (typeof o.openPage === 'function') o.openPage(); setTab('overview'); } } }),
				]),
				list,
			);
		}

		async function loadHome() {
			if (!o.homeHost || !homeCardOn()) { renderHome(); return; }
			if (!S.status) await loadStatus();
			const library = S.status ? MS.sourcesOf(S.status).library : [];
			if (!library.length) { S.home = { items: [], loaded: true }; renderHome(); return; }
			const answers = await Promise.all(library.map((s) => api.resume(s.id, 8).then((r) => handle(r, s.id)).catch(fail)));
			S.home = { items: MS.mergeResume(answers, 8, knownJellyfin()), loaded: true };
			renderHome();
		}

		// ── Events ───────────────────────────────────────────

		if (typeof api.onState === 'function') api.onState((st) => { if (st && st.ok) { S.status = st; S.statusError = null; afterStatus(); } });
		if (typeof api.onLink === 'function') api.onLink((ev) => onLink(ev));
		if (typeof api.onVpn === 'function') api.onVpn((ev) => onVpn(ev));
		if (api.sources && typeof api.sources.onState === 'function') {
			api.sources.onState((server) => { if (S.status && server) { S.status.server = server; afterStatus(); } });
		}

		loadStatus().then(() => loadHome()).catch(() => {});

		return {
			show() {
				S.shown = true;
				refs.sb.hidden = false;
				refreshServer().then(() => {
					if (S.view === 'library' && S.tab === 'overview') loadRows(true);
				});
				if (S.view === 'sources' && sources) sources.show();
				render();
			},
			hide() {
				S.shown = false;
				refs.sb.hidden = true;
				if (sources) sources.hide();
			},
			/** The app's overview is shown: the card "Weiterschauen" again (at most every 30 s). */
			homeShow() {
				if (!S.home.loadedAt || now() - S.home.loadedAt > 30000) {
					S.home.loadedAt = now();
					loadHome().catch(() => {});
				} else renderHome();
			},
			relabel() {
				render();
				renderHome();
				if (sources) sources.render();
			},
			openSources,
			/** For the player (4g): the quality setting, its change, a source's name, what happened after playing. */
			quality: () => (S.status && S.status.quality) || 'auto',
			async setQuality(q) {
				let r;
				try { r = await api.setQuality(q); } catch (err) { r = fail(err); }
				if (r && r.ok && S.status) S.status.quality = r.quality;
				return r;
			},
			sourceName(id) {
				const s = source(id);
				return s ? MS.sourceChip(s, t) : '';
			},
			refreshAfterPlay,
			setTab,
			get state() { return S; },
		};
	}

	root.GCMediaView = { mount, icon, el, picture };
})(typeof window !== 'undefined' ? window : globalThis);
