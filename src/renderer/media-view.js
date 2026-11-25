/**
 * GateControl -- Medien (renderer view: films and series from the NAS, Stufe 4f)
 *
 * The page "Medien" of the Pro client (mockups 8 and 10 of Stufe 4): the head with the tabs Übersicht · Filme ·
 * Serien · Ordner, "In allen Quellen suchen" and "Quellen"; the overview with the source chips and the way
 * ("Zuhause · direkt von der NAS"), the rows Weiterschauen, Zuletzt hinzugefügt, Filme and Serien (Umschalt + Mausrad
 * or the arrows at the edge); Filme and Serien as a grid with sorting and filters and the detail column on the right
 * (a click selects, a double click or Enter plays, the arrow keys move through the grid; a series shows its seasons
 * and episodes there); the search over all sources; "Ordner" waits for the folders of the shares (4h). The page
 * "Quellen" with its dialog is media-sources-view.js (window.GCMediaSources), the card "Weiterschauen" of the
 * app's overview is built here as well (homeCard()).
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
			return r;
		}

		function renderBanner() {
			const out = [...S.signedOut].map((id) => source(id)).filter(Boolean);
			refs.banner.hidden = !out.length;
			clear(refs.banner);
			if (!out.length) return;
			const s = out[0];
			refs.banner.append(icon('alert', 15), el('span', { class: 'md-grow', text: t('media.signedOut', { name: MS.sourceChip(s, t) }) }),
				el('button', { type: 'button', class: 'btn btn-sec btn-xs', text: t('media.src.signIn'), on: { click: () => { openSources(); if (sources) sources.signInAgain(s); } } }));
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
			const { all, ready } = MS.sourcesOf(S.status);
			if (S.search.q) { renderSearch(); return; }
			if (S.tab === 'folders') { renderFolders(); return; }
			if (!all.length) {
				refs.body.appendChild(emptyCard(t('media.empty.title'), t('media.empty.text'), { label: t('media.empty.add'), click: () => { openSources(); if (sources) sources.add(); } }));
				return;
			}
			if (!ready.length) {
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
				action ? el('button', { type: 'button', class: 'btn btn-pri', on: { click: action.click } }, [icon('plus', 15), el('span', { text: action.label })]) : null,
			]);
		}

		function renderFolders() {
			refs.body.appendChild(el('div', { class: 'md-empty md-folders' }, [
				el('span', { class: 'md-empty-ic' }, [icon('folder', 26, '1.6')]),
				el('h2', { class: 'md-empty-h', text: t('media.folders.title') }),
				el('p', { class: 'md-empty-tx', text: t('media.folders.text') }),
				el('button', { type: 'button', class: 'btn btn-sec', text: t('media.folders.sources'), on: { click: () => openSources() } }),
			]));
		}

		// ── Overview: chips, the way, the rows ───────────────

		function rowsKey() {
			return MS.sourcesOf(S.status).ready.map((s) => s.id).join(',');
		}

		async function loadRows(force = false) {
			const key = rowsKey();
			if (!force && S.rows.key === key && (S.rows.loading || S.rows.loaded)) return;
			const seq = ++rowsSeq;
			S.rows = { ...S.rows, key, loading: true, error: null };
			const ready = MS.sourcesOf(S.status).ready;
			const main = MS.pickSource(S.status, S.sourceId);
			const call = (fn) => Promise.all(ready.map((s) => fn(s).then((r) => handle(r, s.id)).catch(fail)));
			const [resume, latest, movies, series] = await Promise.all([
				call((s) => api.resume(s.id, MS.ROW_LIMIT)),
				call((s) => api.latest(s.id, MS.ROW_LIMIT)),
				main ? api.movies(main.id, { start: 0, limit: MS.ROW_LIMIT, sort: 'added' }).then((r) => handle(r, main.id)).catch(fail) : null,
				main ? api.series(main.id, { start: 0, limit: MS.ROW_LIMIT, sort: 'added' }).then((r) => handle(r, main.id)).catch(fail) : null,
			]);
			if (seq !== rowsSeq) return;
			const failed = [...resume, ...latest].every((r) => !r || !r.ok);
			S.rows = {
				key, loading: false, loaded: true,
				error: failed ? (resume.concat(latest).find((r) => r && r.code) || {}).code || 'failed' : null,
				resume: MS.mergeResume(resume),
				latest: MS.mergeLatest(latest).filter((x) => x.kind !== 'episode'),
				movies: movies && movies.ok ? movies.items : [],
				series: series && series.ok ? series.items : [],
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
			for (const s of shares) chips.appendChild(el('span', { class: 'md-pill md-src is-share' }, [el('span', { text: MS.sourceChip(s, t) })]));
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
				c.isNew ? el('span', { class: 'md-mk is-new', text: t('media.mark.new') }) : c.nas ? el('span', { class: 'md-mk', text: t('media.mark.nas') }) : null,
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

		async function loadPage(tab) {
			const key = gridKey(tab);
			const g = S.grids.get(key) || { items: [], total: null, next: 0, loading: false, error: null };
			if (g.loading || g.next === null) return;
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
			const items = g ? g.items : [];
			const sel = S.selected[tab];
			if (!sel && items.length) S.selected[tab] = items[0];
			renderLib(tab, items, g ? g.loading || (!g.items.length && g.next !== null) : true, g && g.error, () => { const x = grid(tab); if (x && x.next !== null && !x.loading) loadPage(tab); });
		}

		function renderLib(tab, items, loading, error, more) {
			const sel = S.selected[tab];
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
			const g = grid(S.tab);
			return g ? g.items : [];
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
			renderPlayable(inner, tab, title, d && d.versions ? d.versions[0] : null, d && d.link);
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
				next: it.kind === 'episode' && list ? () => MS.episodeAfter(list, it.id) : null,
				onEnd: () => refreshAfterPlay(),
			});
		}

		/** After the player: the progress changed in Jellyfin — the rows, the grids' bars and the details again. */
		function refreshAfterPlay() {
			S.details.clear();
			S.episodes.clear();
			S.grids.clear();
			loadRows(true);
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
			const ready = MS.sourcesOf(S.status).ready;
			const answers = await Promise.all(ready.map((s) => api.search(s.id, q).then((r) => handle(r, s.id)).catch(fail)));
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
			const ready = S.status ? MS.sourcesOf(S.status).ready : [];
			const items = S.home.items || [];
			const show = homeCardOn() && ready.length > 0 && items.length > 0;
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
			const ready = S.status ? MS.sourcesOf(S.status).ready : [];
			if (!ready.length) { S.home = { items: [], loaded: true }; renderHome(); return; }
			const answers = await Promise.all(ready.map((s) => api.resume(s.id, 8).then((r) => handle(r, s.id)).catch(fail)));
			S.home = { items: MS.mergeResume(answers, 8), loaded: true };
			renderHome();
		}

		// ── Events ───────────────────────────────────────────

		if (typeof api.onState === 'function') api.onState((st) => { if (st && st.ok) { S.status = st; S.statusError = null; afterStatus(); } });
		if (typeof api.onLink === 'function') api.onLink((ev) => onLink(ev));

		loadStatus().then(() => loadHome()).catch(() => {});

		return {
			show() {
				S.shown = true;
				refs.sb.hidden = false;
				loadStatus().then(() => {
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
			/** For the player (4g): the title's choices and what happened after playing. */
			refreshAfterPlay,
			setTab,
			get state() { return S; },
		};
	}

	root.GCMediaView = { mount, icon, el, picture };
})(typeof window !== 'undefined' ? window : globalThis);
