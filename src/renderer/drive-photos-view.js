/**
 * GateControl -- Drive "Fotos" (renderer view, part of the page Drive)
 *
 * Drive 1.7 'photos' / 'albums' / 'frame': the pictures and videos of every
 * area one can read (or of one area) as a timeline by month, newest first,
 * with "Vor einem Jahr" on top (photos of this day of earlier years); a
 * month can be jumped to. A photo opens large (arrows for the next one) with
 * "Öffnen", "Speichern unter …", "Im Ordner zeigen" and "Im Portal öffnen".
 * "Auswählen" picks several photos (Shift for a range) to add them to an
 * album. "Alben": the albums one can see (cover, count, area, photo frame),
 * new album, rename, delete (the photos stay), photos out of an album, the
 * cover, and the switch "Im Fotorahmen zeigen" for those one may change.
 *
 * Mounted by drive-view.js (it hands over el / icon / clear / openDialog and
 * what it knows: me, the areas, opening a folder or a file). Data:
 * window.gatecontrol.drive; texts: drive.photos.*; view logic without DOM:
 * drive-photos-state.js (window.GCDrivePhotosState). Server text only ever
 * goes into textContent / attributes.
 */
(function (root) {
	'use strict';

	const PS = root.GCDrivePhotosState;
	const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed', error: err && err.message });
	let uid = 0;
	const nextId = (p) => `${p}-${++uid}`;

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive
	 * @param {Function} o.t
	 * @param {Function} o.getLocale
	 * @param {Function} [o.toast]
	 * @param {HTMLElement} [o.host] - dialogs
	 * @param {object} o.ui - { el, icon, clear, openDialog } of drive-view.js
	 * @param {() => object} o.getMe - GET me of the page
	 * @param {() => object[]} o.getAreas
	 * @param {Function} o.areaLabel - GCDriveState.areaLabel
	 * @param {Function} o.errorText - GCDriveState.errorText
	 * @param {(folderId: number) => void} o.openFolder - "Im Ordner zeigen"
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const { el, icon, clear, openDialog } = o.ui;
		const locale = () => o.getLocale();
		const toast = typeof o.toast === 'function' ? o.toast : () => {};
		const host = o.host || document.body;
		const err = (r) => o.errorText(r, t);
		const P = {
			shown: false,
			tab: 'timeline',     // timeline | albums
			area: '',
			items: [],
			next: null,
			months: [],
			memories: [],
			albums: null,
			album: null,         // { album, items, next } while an album is open
			loading: false,
			error: null,
			selecting: false,
			sel: new Set(),
			last: null,
			seq: 0,
		};
		const previews = new Map();
		const limit = PS.limiter(6);
		const seen = typeof root.IntersectionObserver === 'function'
			? new root.IntersectionObserver((entries) => {
				for (const e of entries) {
					if (!e.isIntersecting) continue;
					seen.unobserve(e.target);
					if (typeof e.target._load === 'function') e.target._load();
				}
			}, { rootMargin: '300px' })
			: null;

		const wrap = el('div', { class: 'dpv', hidden: true });
		const head = el('div', { class: 'dpv-head' });
		const selBar = el('div', { class: 'dpv-selbar', hidden: true });
		const body = el('div', { class: 'dpv-body scroll' });
		wrap.append(head, selBar, body);
		const sentinel = el('div', { class: 'dpv-sentinel' });
		const moreObs = typeof root.IntersectionObserver === 'function'
			? new root.IntersectionObserver((entries) => { if (entries.some((e) => e.isIntersecting)) loadMore(); }, { root: body, rootMargin: '400px' })
			: null;
		if (moreObs) moreObs.observe(sentinel);

		const feats = () => PS.features(o.getMe());

		// ── Loading ──────────────────────────────────────
		async function loadTimeline({ before = null } = {}) {
			const seq = ++P.seq;
			P.loading = true;
			P.error = null;
			P.items = [];
			P.next = null;
			render();
			const area = P.area || null;
			const [page, months, mem] = await Promise.all([
				Promise.resolve(api.photos({ area, before, limit: PS.PAGE })).catch(fail),
				Promise.resolve(api.photoMonths(area)).catch(fail),
				before || area ? Promise.resolve({ ok: true, groups: [] }) : Promise.resolve(api.memories()).catch(fail),
			]);
			if (seq !== P.seq) return;
			P.loading = false;
			if (!page || !page.ok) { P.error = page; render(); return; }
			P.items = page.items;
			P.next = page.next;
			P.months = months && months.ok ? months.months : [];
			P.memories = mem && mem.ok ? mem.groups : [];
			render();
		}

		let loadingMore = false;
		async function loadMore() {
			if (loadingMore || P.loading || !P.shown) return;
			const inAlbum = P.tab === 'albums' && P.album;
			const cursor = inAlbum ? P.album.next : P.tab === 'timeline' ? P.next : null;
			if (!cursor) return;
			loadingMore = true;
			const seq = P.seq;
			const r = inAlbum
				? await Promise.resolve(api.album(P.album.album.id, { before: cursor, limit: PS.PAGE })).catch(fail)
				: await Promise.resolve(api.photos({ area: P.area || null, before: cursor, limit: PS.PAGE })).catch(fail);
			loadingMore = false;
			if (seq !== P.seq) return;
			if (!r || !r.ok) { toast(err(r), 'error'); return; }
			if (inAlbum) { P.album.items = PS.mergePage(P.album.items, r); P.album.next = r.next; } else { P.items = PS.mergePage(P.items, r); P.next = r.next; }
			keepScroll(render);
		}

		async function loadAlbums() {
			const seq = ++P.seq;
			P.loading = true;
			P.error = null;
			P.album = null;
			render();
			const r = await Promise.resolve(api.albums()).catch(fail);
			if (seq !== P.seq) return;
			P.loading = false;
			if (r && r.ok) P.albums = r.albums;
			else P.error = r;
			render();
		}

		async function openAlbum(id) {
			const seq = ++P.seq;
			P.loading = true;
			P.error = null;
			clearSel();
			render();
			const r = await Promise.resolve(api.album(id, { limit: PS.PAGE })).catch(fail);
			if (seq !== P.seq) return;
			P.loading = false;
			if (r && r.ok) P.album = { album: r.album, items: r.items, next: r.next };
			else P.error = r;
			render();
		}

		function reload() {
			if (P.tab === 'albums') return P.album ? openAlbum(P.album.album.id) : loadAlbums();
			return loadTimeline();
		}

		function keepScroll(fn) {
			const top = body.scrollTop;
			fn();
			body.scrollTop = top;
		}

		// ── Previews ─────────────────────────────────────
		function previewUrl(p, large = false, tries = 0) {
			const key = `${p.id}|${large ? 'l' : 's'}`;
			if (previews.has(key)) return previews.get(key);
			const ask = () => (p.mediaId ? api.preview(p.mediaId, { large }) : api.previewOf(p.id, { large }));
			const run = limit.run(() => Promise.resolve(ask())).then((r) => {
				if (r && r.ok && r.data) return URL.createObjectURL(new Blob([r.data], { type: r.mime || 'image/jpeg' }));
				previews.delete(key);
				if (r && r.code === 'preview_pending' && tries < 3) return new Promise((res) => setTimeout(() => res(previewUrl(p, large, tries + 1)), 4000));
				return null;
			}).catch(() => { previews.delete(key); return null; });
			previews.set(key, run);
			while (previews.size > 1500) {
				const [k, v] = previews.entries().next().value;
				previews.delete(k);
				Promise.resolve(v).then((u) => { if (u) URL.revokeObjectURL(u); }).catch(() => {});
			}
			return run;
		}

		function picture(box, p, large = false) {
			if (!p.preview && !p.mediaId) return;
			const load = () => previewUrl(p, large).then((u) => {
				if (!u || !box.isConnected) return;
				box.classList.add('has-img');
				box.appendChild(el('img', { src: u, alt: '', draggable: 'false' }));
			});
			if (seen && !large) { box._load = load; seen.observe(box); } else load();
		}

		// ── Selection ────────────────────────────────────
		function clearSel() {
			P.sel = new Set();
			P.last = null;
			P.selecting = false;
		}

		function currentList() {
			return P.tab === 'albums' && P.album ? P.album.items : P.items;
		}

		function renderSel() {
			clear(selBar);
			selBar.hidden = !P.selecting;
			if (!P.selecting) return;
			const n = P.sel.size;
			const inAlbum = P.tab === 'albums' && P.album;
			const f = feats();
			selBar.append(
				el('span', { class: 'dpv-sel-n', text: n ? t('drive.photos.selected', { count: n }) : t('drive.photos.selectHint') }),
				el('span', { class: 'dv-grow' }),
				!inAlbum && f.albums ? el('button', { type: 'button', class: 'btn btn-pri btn-sm', disabled: !n, on: { click: () => addDialog(Array.from(P.sel)) } }, [icon('plus', 14), el('span', { text: t('drive.photos.addTo') })]) : null,
				inAlbum && P.album.album.canEdit ? el('button', { type: 'button', class: 'btn btn-sec btn-sm', disabled: n !== 1, on: { click: () => setCover(Array.from(P.sel)[0]) } }, [el('span', { text: t('drive.photos.album.cover') })]) : null,
				inAlbum && P.album.album.canEdit ? el('button', { type: 'button', class: 'btn btn-sec btn-sm dv-danger', disabled: !n, on: { click: () => removeFromAlbum(Array.from(P.sel)) } }, [el('span', { text: t('drive.photos.album.removeItems') })]) : null,
				el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('drive.cancel'), on: { click: () => { clearSel(); render(); } } }),
			);
		}

		function onTile(e, p, list, i) {
			if (P.selecting || e.ctrlKey || e.metaKey || e.shiftKey) {
				P.selecting = true;
				P.sel = e.shiftKey && P.last !== null ? PS.selectRange(P.sel, list, P.last, p.id) : PS.toggle(P.sel, p.id);
				P.last = p.id;
				keepScroll(render);
				return;
			}
			lightbox(list, i);
		}

		// ── Render ───────────────────────────────────────
		function tile(p, list, i) {
			const on = P.sel.has(p.id);
			const box = el('span', { class: `dpv-img dv-k-${p.kind === 'video' ? 'video' : 'image'}` }, [icon(p.kind === 'video' ? 'video' : 'image', 22, '1.6')]);
			picture(box, p);
			const b = el('button', {
				type: 'button', role: 'listitem', class: `dpv-tile${on ? ' is-sel' : ''}${P.selecting ? ' is-selecting' : ''}`, 'data-id': String(p.id),
				'aria-pressed': P.selecting ? (on ? 'true' : 'false') : null, title: [p.name, PS.photoWhen(p, locale())].filter(Boolean).join(' · '),
				on: { click: (e) => onTile(e, p, list, i) },
			}, [
				box,
				p.kind === 'video' ? el('span', { class: 'dpv-play', 'aria-hidden': 'true' }, [icon('play', 12)]) : null,
				P.selecting ? el('span', { class: 'dpv-check', 'aria-hidden': 'true' }, on ? [icon('check', 12, '3')] : []) : null,
			]);
			b.setAttribute('aria-label', p.name);
			return b;
		}

		function grid(list) {
			const g = el('div', { class: 'dpv-grid', role: 'list' });
			list.forEach((p) => g.appendChild(tile(p, list, list.indexOf(p))));
			return g;
		}

		function renderHead() {
			clear(head);
			const f = feats();
			const tabs = el('div', { class: 'seg dv-seg', role: 'tablist', 'aria-label': t('drive.photos.title') });
			const tab = (key, label) => tabs.appendChild(el('button', { type: 'button', role: 'tab', 'aria-selected': P.tab === key ? 'true' : 'false', class: P.tab === key ? 'on' : '', text: label, on: { click: () => { if (P.tab === key && !P.album) return; P.tab = key; clearSel(); if (key === 'albums') loadAlbums(); else loadTimeline(); } } }));
			tab('timeline', t('drive.photos.timeline'));
			if (f.albums) tab('albums', t('drive.photos.albums'));
			head.append(el('h2', { class: 'dsv-h', text: t('drive.photos.title') }), tabs, el('span', { class: 'dv-grow' }));
			if (P.tab === 'timeline') {
				const areaId = nextId('dpv-area');
				const sel = el('select', { id: areaId, class: 'dv-input dpv-select', 'aria-label': t('drive.photos.area') });
				for (const c of PS.areaChoices(o.getAreas(), o.areaLabel, t)) sel.appendChild(el('option', { value: c.id, text: c.label }));
				sel.value = P.area;
				sel.addEventListener('change', () => { P.area = sel.value; clearSel(); loadTimeline(); });
				head.appendChild(sel);
				if (P.months.length > 1) {
					const jump = el('select', { class: 'dv-input dpv-select', 'aria-label': t('drive.photos.jump') });
					jump.appendChild(el('option', { value: '', text: t('drive.photos.jump') }));
					for (const m of P.months) jump.appendChild(el('option', { value: m.month, text: `${PS.monthLabel(m.month, locale())} (${m.count})` }));
					jump.addEventListener('change', () => { if (jump.value) loadTimeline({ before: PS.monthStart(jump.value) }); });
					head.appendChild(jump);
				}
			}
			if (P.tab === 'timeline' || (P.album && P.album.album.canEdit)) {
				head.appendChild(el('button', { type: 'button', class: `btn btn-sm ${P.selecting ? 'btn-sec' : 'btn-ghost'}`, 'aria-pressed': P.selecting ? 'true' : 'false', on: { click: () => { if (P.selecting) clearSel(); else P.selecting = true; keepScroll(render); } } }, [icon('check', 14), el('span', { text: t('drive.photos.select') })]));
			}
			if (P.tab === 'albums' && !P.album) {
				head.appendChild(el('button', { type: 'button', class: 'btn btn-pri btn-sm', on: { click: () => newAlbumDialog() } }, [icon('plus', 14), el('span', { text: t('drive.photos.album.new') })]));
			}
			const me = o.getMe();
			if (me && me.links && me.links.drive) {
				head.appendChild(el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => portal(null) } }, [icon('cloud', 14), el('span', { text: t('drive.portal.open') })]));
			}
		}

		function render() {
			if (!P.shown) return;
			renderHead();
			renderSel();
			clear(body);
			if (P.loading) { body.appendChild(el('div', { class: 'dv-empty', text: t('drive.loading') })); return; }
			if (P.error) {
				body.appendChild(el('div', { class: 'dv-empty' }, [icon('alert', 26, '1.6'), el('span', { text: err(P.error) }), el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.retry'), on: { click: () => reload() } })]));
				return;
			}
			if (P.tab === 'albums') { if (P.album) renderAlbum(); else renderAlbums(); return; }
			renderTimeline();
		}

		function renderTimeline() {
			const mem = PS.memoriesView(P.memories, { t, locale: locale() });
			if (mem.length) {
				const strip = el('section', { class: 'dpv-mem card' }, [el('div', { class: 'dpv-mem-h' }, [icon('history', 16), el('b', { text: t('drive.photos.memories') })])]);
				for (const m of mem) {
					strip.appendChild(el('div', { class: 'dpv-mem-g' }, [
						el('div', { class: 'dpv-month-h' }, [el('span', { class: 'dpv-month-name', text: m.title }), el('span', { class: 'dpv-month-n', text: m.sub })]),
						grid(m.items),
					]));
				}
				body.appendChild(strip);
			}
			if (!P.items.length) {
				body.appendChild(el('div', { class: 'dv-empty' }, [icon('image', 28, '1.6'), el('span', { text: t('drive.photos.empty') })]));
				return;
			}
			for (const g of PS.groupByMonth(P.items, P.months, locale(), t)) {
				body.appendChild(el('section', { class: 'dpv-month', 'data-month': g.key }, [
					el('div', { class: 'dpv-month-h' }, [el('span', { class: 'dpv-month-name', text: g.label }), el('span', { class: 'dpv-month-n', text: DSPlural('drive.photos.count', g.count) })]),
					grid(g.items),
				]));
			}
			moreFoot(P.next);
		}

		function DSPlural(key, n, params) {
			return t(`${key}.${Number(n) === 1 ? 'one' : 'other'}`, { ...(params || {}), count: Number(n) || 0 });
		}

		function moreFoot(next) {
			if (!next) return;
			body.appendChild(el('div', { class: 'dpv-more' }, [el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.photos.more'), on: { click: () => loadMore() } })]));
			body.appendChild(sentinel);
		}

		function renderAlbums() {
			const list = P.albums || [];
			if (!list.length) {
				body.appendChild(el('div', { class: 'dv-empty' }, [icon('folder', 28, '1.6'), el('span', { text: t('drive.photos.album.none') })]));
				return;
			}
			const g = el('div', { class: 'dpv-albums', role: 'list' });
			for (const a of list) {
				const v = PS.albumView(a, { areas: o.getAreas(), areaLabel: o.areaLabel, t });
				const cover = el('span', { class: 'dpv-cover dv-k-image' }, [icon('image', 26, '1.6')]);
				if (v.coverId) picture(cover, { id: v.coverId, preview: true, mediaId: null });
				g.appendChild(el('button', { type: 'button', role: 'listitem', class: 'dpv-album', 'data-id': String(v.id), on: { click: () => openAlbum(v.id) } }, [
					cover,
					el('span', { class: 'dpv-album-tx' }, [
						el('span', { class: 'dpv-album-name', text: v.name }),
						el('span', { class: 'dpv-album-sub', text: v.sub }),
					]),
					v.frame ? el('span', { class: 'dpv-frame-badge', title: t('drive.photos.album.frameOn'), text: t('drive.photos.album.frameBadge') }) : null,
				]));
			}
			body.appendChild(g);
		}

		function renderAlbum() {
			const a = P.album.album;
			const v = PS.albumView(a, { areas: o.getAreas(), areaLabel: o.areaLabel, t });
			const top = el('div', { class: 'dpv-album-head' }, [
				el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => { clearSel(); loadAlbums(); } } }, [icon('back', 14), el('span', { text: t('drive.photos.albums') })]),
				el('div', { class: 'dpv-album-tx' }, [el('span', { class: 'dpv-album-title', text: v.name }), el('span', { class: 'dpv-album-sub', text: v.sub })]),
				el('span', { class: 'dv-grow' }),
			]);
			if (PS.frameSwitch(a, o.getMe())) {
				const sw = el('button', { type: 'button', class: `sw${a.frame ? ' on' : ''}`, role: 'switch', 'aria-checked': a.frame ? 'true' : 'false', 'aria-label': t('drive.photos.album.frame') }, [el('span')]);
				sw.addEventListener('click', async () => {
					sw.disabled = true;
					const r = await Promise.resolve(api.updateAlbum(a.id, { frame: !a.frame })).catch(fail);
					sw.disabled = false;
					if (!r || !r.ok) { toast(err(r), 'error'); return; }
					P.album.album = r.album;
					toast(t(r.album.frame ? 'drive.photos.album.frameOnDone' : 'drive.photos.album.frameOffDone'), 'success');
					keepScroll(render);
				});
				top.appendChild(el('label', { class: 'dpv-frame' }, [el('span', { text: t('drive.photos.album.frame') }), sw]));
			}
			if (a.canEdit) {
				top.append(
					el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => renameAlbum(a) } }, [icon('pen', 14), el('span', { text: t('drive.rename') })]),
					el('button', { type: 'button', class: 'btn btn-ghost btn-sm dv-danger', on: { click: () => deleteAlbum(a) } }, [icon('trash', 14), el('span', { text: t('drive.photos.album.delete') })]),
				);
			}
			body.appendChild(top);
			if (a.canEdit && P.album.items.length === 0) body.appendChild(el('p', { class: 'dv-note', text: t('drive.photos.album.howToAdd') }));
			if (!P.album.items.length) {
				body.appendChild(el('div', { class: 'dv-empty' }, [icon('image', 28, '1.6'), el('span', { text: t('drive.photos.album.empty') })]));
				return;
			}
			body.appendChild(grid(P.album.items));
			moreFoot(P.album.next);
		}

		// ── Lightbox ─────────────────────────────────────
		function lightbox(list, start) {
			let i = start;
			const onKey = (e) => {
				if (e.key === 'ArrowLeft') { e.preventDefault(); go(-1); } else if (e.key === 'ArrowRight') { e.preventDefault(); go(1); }
			};
			const dlg = openDialog({ title: '', host, wide: true, closeLabel: t('drive.close'), onClose: () => document.removeEventListener('keydown', onKey) });
			dlg.box.classList.add('dpv-light');
			const stage = el('div', { class: 'dpv-stage' });
			const meta = el('div', { class: 'dpv-meta' });
			const prev = el('button', { type: 'button', class: 'dv-ib dpv-nav is-prev', 'aria-label': t('drive.photos.prev'), title: t('drive.photos.prev'), on: { click: () => go(-1) } }, [icon('back', 18)]);
			const next = el('button', { type: 'button', class: 'dv-ib dpv-nav is-next', 'aria-label': t('drive.photos.next'), title: t('drive.photos.next'), on: { click: () => go(1) } }, [icon('chevron', 18)]);
			dlg.body.append(el('div', { class: 'dpv-stage-wrap' }, [prev, stage, next]), meta);
			document.addEventListener('keydown', onKey);
			function go(d) {
				const j = i + d;
				if (j < 0 || j >= list.length) return;
				i = j;
				show();
			}
			function show() {
				const p = list[i];
				dlg.setTitle(p.name);
				clear(stage);
				const box = el('span', { class: 'dpv-big' }, [icon(p.kind === 'video' ? 'video' : 'image', 40, '1.4')]);
				stage.appendChild(box);
				picture(box, p, true);
				meta.textContent = [PS.photoWhen(p, locale()), p.kind === 'video' ? t('drive.photos.video') : ''].filter(Boolean).join(' · ');
				prev.disabled = i === 0;
				next.disabled = i >= list.length - 1;
				clear(dlg.foot);
				const me = o.getMe();
				dlg.foot.append(
					el('span', { class: 'dv-grow' }),
					p.parentId ? el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => { dlg.close(null); o.openFolder(p.parentId); } } }, [icon('folder', 14), el('span', { text: t('drive.search.showFolder') })]) : null,
					me && me.links && me.links.node ? el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => portal(p.id) } }, [icon('cloud', 14), el('span', { text: t('drive.portal.open') })]) : null,
					feats().albums ? el('button', { type: 'button', class: 'btn btn-ghost btn-sm', on: { click: () => addDialog([p.id]) } }, [icon('plus', 14), el('span', { text: t('drive.photos.addTo') })]) : null,
					el('button', { type: 'button', class: 'btn btn-sec btn-sm', on: { click: () => saveAs(p) } }, [icon('down', 14), el('span', { text: t('drive.saveAs') })]),
					el('button', { type: 'button', class: 'btn btn-pri btn-sm', on: { click: () => openFile(p) } }, [icon('open', 14), el('span', { text: t('drive.open') })]),
				);
			}
			show();
		}

		async function openFile(p) {
			const r = await Promise.resolve(api.open(p.id)).catch(fail);
			if (!r || !r.ok) toast(err(r), 'error');
		}

		async function saveAs(p) {
			const r = await Promise.resolve(api.saveAs(p.id)).catch(fail);
			if (r && r.ok) toast(t('drive.saved', { path: r.path }), 'success');
			else if (!(r && r.cancelled)) toast(err(r), 'error');
		}

		async function portal(id) {
			const r = await Promise.resolve(api.openInPortal(id)).catch(fail);
			if (!r || !r.ok) toast(err(r), 'error');
		}

		// ── Albums: dialogs ──────────────────────────────
		function nameField(label, value) {
			const id = nextId('dpv-name');
			const input = el('input', { id, type: 'text', class: 'dv-input', maxlength: '200', value: value || '', spellcheck: 'false' });
			const errEl = el('span', { class: 'dv-field-err', role: 'alert' });
			return { input, errEl, nodes: [el('label', { class: 'lbl', for: id, text: label }), input, errEl] };
		}

		function areaField(selected) {
			const areas = PS.albumAreas(o.getAreas());
			if (areas.length < 2) return { value: () => (areas[0] ? areas[0].id : null), nodes: [] };
			const id = nextId('dpv-aarea');
			const sel = el('select', { id, class: 'dv-input' });
			for (const a of areas) sel.appendChild(el('option', { value: a.id, text: o.areaLabel(a, t) }));
			if (selected) sel.value = selected;
			return { value: () => sel.value || null, nodes: [el('label', { class: 'lbl', for: id, text: t('drive.photos.album.area') }), sel, el('span', { class: 'dv-pick-note', text: t('drive.photos.album.areaHint') })] };
		}

		function newAlbumDialog({ then = null } = {}) {
			const dlg = openDialog({ title: t('drive.photos.album.new'), host, closeLabel: t('drive.close') });
			const nf = nameField(t('drive.photos.album.name'), '');
			const af = areaField(null);
			const ok = el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.create') });
			const submit = async () => {
				const e = PS.albumNameError(nf.input.value, t);
				if (e) { nf.errEl.textContent = e; return; }
				ok.disabled = true;
				const r = await Promise.resolve(api.createAlbum(nf.input.value.trim(), af.value())).catch(fail);
				ok.disabled = false;
				if (!r || !r.ok) { nf.errEl.textContent = err(r); return; }
				dlg.close(r);
				toast(t('drive.photos.album.created', { name: r.album.name }), 'success');
				if (then) then(r.album);
				else if (P.tab === 'albums') loadAlbums();
			};
			nf.input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
			ok.addEventListener('click', submit);
			dlg.body.append(...nf.nodes, ...af.nodes);
			dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), ok);
			setTimeout(() => nf.input.focus(), 0);
		}

		async function addTo(albumId, ids) {
			let last = null;
			for (const part of PS.chunks(ids)) {
				last = await Promise.resolve(api.addToAlbum(albumId, part)).catch(fail);
				if (!last || !last.ok) return last;
			}
			return last;
		}

		/** "Zu Album hinzufügen": the albums one may change, or a new one. */
		async function addDialog(ids) {
			if (!ids.length) return;
			const dlg = openDialog({ title: DSPlural('drive.photos.addTitle', ids.length), host, closeLabel: t('drive.close') });
			const list = el('div', { class: 'dv-pick-list', role: 'list' }, [el('div', { class: 'dv-pick-note', text: t('drive.loading') })]);
			const errEl = el('span', { class: 'dv-dlg-err', role: 'alert' });
			dlg.body.appendChild(list);
			const added = (r) => {
				toast(DSPlural('drive.photos.added', ids.length, { name: r.album.name }), 'success');
				clearSel();
				if (P.tab === 'albums' && !P.album) loadAlbums();
				else keepScroll(render);
			};
			const done = async (album) => {
				const r = await addTo(album.id, ids);
				if (!r || !r.ok) { errEl.textContent = err(r); return; }
				dlg.close(r);
				added(r);
			};
			// a new album: made, then the photos go into it
			const fresh = async (album) => {
				const r = await addTo(album.id, ids);
				if (!r || !r.ok) { toast(err(r), 'error'); return; }
				added(r);
			};
			dlg.foot.append(errEl,
				el('button', { type: 'button', class: 'btn btn-ghost', on: { click: () => { dlg.close(null); newAlbumDialog({ then: (a) => { fresh(a); } }); } } }, [icon('plus', 14), el('span', { text: t('drive.photos.album.new') })]),
				el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }));
			const r = await Promise.resolve(api.albums()).catch(fail);
			clear(list);
			if (!r || !r.ok) { errEl.textContent = err(r); return; }
			P.albums = r.albums;
			const mine = PS.editableAlbums(r.albums);
			if (!mine.length) list.appendChild(el('div', { class: 'dv-pick-note', text: t('drive.photos.album.noneEditable') }));
			for (const a of mine) {
				const v = PS.albumView(a, { areas: o.getAreas(), areaLabel: o.areaLabel, t });
				list.appendChild(el('button', { type: 'button', role: 'listitem', class: 'dv-pick-row', on: { click: () => done(a) } }, [
					el('span', { class: 'dv-pick-ic' }, [icon('image', 16)]),
					el('span', { class: 'dv-pick-tx' }, [el('span', { class: 'dv-pick-name', text: v.name }), el('span', { class: 'dv-pick-sub', text: v.sub })]),
					icon('plus', 14),
				]));
			}
		}

		async function removeFromAlbum(ids) {
			const a = P.album && P.album.album;
			if (!a || !ids.length) return;
			for (const part of PS.chunks(ids)) {
				const r = await Promise.resolve(api.removeFromAlbum(a.id, part)).catch(fail);
				if (!r || !r.ok) { toast(err(r), 'error'); return; }
			}
			toast(DSPlural('drive.photos.album.removed', ids.length), 'success');
			clearSel();
			openAlbum(a.id);
		}

		async function setCover(id) {
			const a = P.album && P.album.album;
			if (!a || !id) return;
			const r = await Promise.resolve(api.updateAlbum(a.id, { coverId: id })).catch(fail);
			if (!r || !r.ok) { toast(err(r), 'error'); return; }
			P.album.album = r.album;
			toast(t('drive.photos.album.coverDone'), 'success');
			clearSel();
			keepScroll(render);
		}

		function renameAlbum(a) {
			const dlg = openDialog({ title: t('drive.photos.album.renameTitle', { name: a.name }), host, closeLabel: t('drive.close') });
			const nf = nameField(t('drive.photos.album.name'), a.name);
			const ok = el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.rename') });
			const submit = async () => {
				const e = PS.albumNameError(nf.input.value, t);
				if (e) { nf.errEl.textContent = e; return; }
				ok.disabled = true;
				const r = await Promise.resolve(api.updateAlbum(a.id, { name: nf.input.value.trim() })).catch(fail);
				ok.disabled = false;
				if (!r || !r.ok) { nf.errEl.textContent = err(r); return; }
				dlg.close(r);
				if (P.album) P.album.album = r.album;
				render();
			};
			nf.input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
			ok.addEventListener('click', submit);
			dlg.body.append(...nf.nodes);
			dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), ok);
			setTimeout(() => { nf.input.focus(); nf.input.select(); }, 0);
		}

		function deleteAlbum(a) {
			const dlg = openDialog({ title: t('drive.photos.album.deleteTitle', { name: a.name }), host, closeLabel: t('drive.close') });
			const errEl = el('span', { class: 'dv-dlg-err', role: 'alert' });
			const ok = el('button', { type: 'button', class: 'btn btn-danger', text: t('drive.photos.album.delete') });
			ok.addEventListener('click', async () => {
				ok.disabled = true;
				const r = await Promise.resolve(api.deleteAlbum(a.id)).catch(fail);
				if (!r || !r.ok) { ok.disabled = false; errEl.textContent = err(r); return; }
				dlg.close(r);
				toast(t('drive.photos.album.deleted'), 'success');
				clearSel();
				loadAlbums();
			});
			dlg.body.append(el('p', { class: 'dv-p', text: t('drive.photos.album.deleteText') }));
			dlg.foot.append(errEl, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), ok);
		}

		return {
			el: wrap,
			show() {
				P.shown = true;
				wrap.hidden = false;
				if (P.tab === 'albums' && !feats().albums) P.tab = 'timeline';
				reload();
			},
			hide() {
				P.shown = false;
				wrap.hidden = true;
			},
			refresh: () => reload(),
			relabel: () => render(),
		};
	}

	root.GCDrivePhotosView = { mount };
})(typeof self !== 'undefined' ? self : this);
