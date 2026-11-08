/**
 * GateControl -- Drive "Erinnerungen" (renderer view, part of the page Drive)
 *
 * Drive plugin 1.26 'memoryCollections': the overview's "Alle" (and one of its memory cards) opens it. The collections
 * of the person's private photos (drive.memoryCollections()) as cards with their cover, by section; a card shows its
 * photos (drive.memoryPhotos(id), page by page) as the tiles of "Fotos", a click the large view of "Fotos" (it goes
 * through the photos of the collection). "Erinnerungen › …" leads back.
 *
 * Mounted by drive-view.js like "Fotos" (el / icon / clear and showPhotos — the lightbox of "Fotos"). Words: drive-
 * memories-state.js (window.GCDriveMemoriesState); texts drive.mem.*. Server text only ever goes into textContent /
 * attributes; no innerHTML.
 */
(function (root) {
	'use strict';

	const MS = root.GCDriveMemoriesState;
	const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed', error: err && err.message });
	const PAGE = 120;

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive
	 * @param {Function} o.t - i18n
	 * @param {Function} o.getLocale
	 * @param {{ el, icon, clear }} o.ui
	 * @param {Function} o.errorText - (result, t) → text
	 * @param {Function} o.showPhotos - (items, start) the photos large (the lightbox of "Fotos")
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const { el, icon, clear } = o.ui;
		const locale = () => o.getLocale();
		const M = { shown: false, loading: false, data: null, error: null, open: null, items: [], next: null, more: false, seq: 0 };
		const wrap = el('div', { class: 'dmm scroll', hidden: true });
		const previews = new Map();

		function preview(p) {
			if (!p || (!p.preview && !p.mediaId)) return Promise.resolve(null);
			const key = `${p.id}`;
			if (!previews.has(key)) {
				const ask = () => (p.mediaId ? api.preview(p.mediaId, { large: true }) : api.previewOf(p.id, { large: true }));
				previews.set(key, Promise.resolve(ask()).then((r) => (r && r.ok && r.data ? URL.createObjectURL(new Blob([r.data], { type: r.mime || 'image/jpeg' })) : null)).catch(() => null));
			}
			return previews.get(key);
		}

		async function load() {
			const seq = ++M.seq;
			M.loading = !M.data;
			render();
			const r = await Promise.resolve(api.memoryCollections()).catch(fail);
			if (seq !== M.seq) return;
			M.loading = false;
			if (r && r.ok) { M.data = r; M.error = null; } else if (!M.data) M.error = r;
			if (M.shown) render();
		}

		async function loadPhotos(before) {
			const seq = ++M.seq;
			M.more = true;
			if (!before) render();
			const r = await Promise.resolve(api.memoryPhotos(M.open.id, { limit: PAGE, ...(before ? { before } : {}) })).catch(fail);
			if (seq !== M.seq) return;
			M.more = false;
			if (r && r.ok) {
				const seen = new Set(M.items.map((p) => p.id));
				M.items = M.items.concat((r.items || []).filter((p) => p && !seen.has(p.id)));
				M.next = r.next || null;
				M.error = null;
			} else if (!M.items.length) M.error = r;
			if (M.shown) render();
		}

		function card(c) {
			const tx = MS.cardText(c, { t, locale: locale() });
			const img = el('img', { class: 'dov-mem-img', alt: '' });
			const b = el('button', { type: 'button', role: 'listitem', class: 'dov-mem dmm-card', 'data-memory': c.id, 'aria-label': `${tx.title}, ${tx.sub}`, on: { click: () => openCollection(c) } }, [
				img,
				el('span', { class: 'dov-mem-tx' }, [el('b', { text: tx.title }), el('span', { text: tx.sub })]),
			]);
			preview(c.cover).then((u) => { if (u) { img.src = u; b.classList.add('has-img'); } });
			return b;
		}

		function crumbs() {
			const box = el('nav', { class: 'dmm-crumbs', 'aria-label': t('drive.mem.title') });
			if (!M.open) {
				box.appendChild(el('h2', { class: 'dsv-h', text: t('drive.mem.title') }));
				return box;
			}
			box.append(
				el('button', { type: 'button', class: 'btn btn-ghost btn-sm dmm-back', on: { click: () => { closeCollection(); } } }, [icon('back', 14), el('span', { text: t('drive.mem.title') })]),
				el('span', { class: 'dmm-sep', 'aria-hidden': 'true', text: '›' }),
				el('h2', { class: 'dsv-h', text: MS.cardText(M.open, { t, locale: locale() }).title }),
			);
			return box;
		}

		function renderList() {
			if (M.loading) { wrap.appendChild(el('p', { class: 'dv-hint', text: t('drive.loading') })); return; }
			if (M.error && !M.data) { wrap.appendChild(el('p', { class: 'dv-hint', role: 'alert', text: o.errorText(M.error, t) })); return; }
			const secs = MS.sections(M.data && M.data.collections);
			if (!secs.length) { wrap.appendChild(el('p', { class: 'dv-hint dmm-none', text: t('drive.mem.none') })); return; }
			wrap.appendChild(el('p', { class: 'dv-hint dmm-note', text: t('drive.mem.private') }));
			for (const s of secs) {
				wrap.appendChild(el('section', { class: 'dmm-sec', 'data-kind': s.kind, 'aria-label': MS.sectionTitle(s.kind, t) }, [
					el('h3', { class: 'dmm-h', text: MS.sectionTitle(s.kind, t) }),
					el('div', { class: 'dmm-cards', role: 'list' }, s.items.map(card)),
				]));
			}
		}

		function tile(p, i) {
			const box = el('span', { class: `dpv-img dv-k-${p.kind === 'video' ? 'video' : 'image'}` }, [icon(p.kind === 'video' ? 'video' : 'image', 22, '1.6')]);
			const img = el('img', { alt: '' });
			preview(p).then((u) => { if (u) { img.src = u; box.appendChild(img); box.classList.add('has-img'); } });
			const b = el('button', { type: 'button', role: 'listitem', class: 'dpv-tile', 'data-id': String(p.id), title: p.name, on: { click: () => o.showPhotos(M.items, i) } }, [
				box,
				p.kind === 'video' ? el('span', { class: 'dpv-play', 'aria-hidden': 'true' }, [icon('play', 12)]) : null,
			]);
			b.setAttribute('aria-label', p.name);
			return b;
		}

		function renderPhotos() {
			wrap.appendChild(el('p', { class: 'dv-hint dmm-sub', text: MS.cardText(M.open, { t, locale: locale() }).sub }));
			if (M.error && !M.items.length) { wrap.appendChild(el('p', { class: 'dv-hint', role: 'alert', text: o.errorText(M.error, t) })); return; }
			if (!M.items.length) { wrap.appendChild(el('p', { class: 'dv-hint', text: M.more ? t('drive.loading') : t('drive.mem.empty') })); return; }
			wrap.appendChild(el('div', { class: 'dpv-grid dmm-grid', role: 'list' }, M.items.map((p, i) => tile(p, i))));
			if (M.next) {
				wrap.appendChild(el('div', { class: 'dmm-more' }, [el('button', { type: 'button', class: 'btn btn-sec btn-sm', disabled: M.more || null, text: t('drive.mem.more'), on: { click: () => loadPhotos(M.next) } })]));
			}
		}

		function render() {
			if (!M.shown) return;
			clear(wrap);
			wrap.appendChild(crumbs());
			if (M.open) renderPhotos(); else renderList();
		}

		/** One collection (of the page, or a card of the overview: { id, kind, … }). */
		function openCollection(c) {
			M.open = c;
			M.items = [];
			M.next = null;
			M.error = null;
			loadPhotos(null);
		}

		function closeCollection() {
			M.open = null;
			M.error = null;
			render();
			if (!M.data) load();
		}

		return {
			el: wrap,
			show() { M.shown = true; wrap.hidden = false; if (M.open && !M.items.length) loadPhotos(null); else if (M.open) render(); else load(); },
			hide() { M.shown = false; wrap.hidden = true; },
			refresh: () => (M.open ? render() : load()),
			relabel: () => render(),
			/** Before show(): the page itself (null) or one collection. */
			prepare(c) { M.open = null; M.items = []; M.next = null; if (c && c.id) M.open = c; },
			openCollection: (c) => openCollection(c),
		};
	}

	root.GCDriveMemoriesView = { mount };
})(typeof self !== 'undefined' ? self : this);
