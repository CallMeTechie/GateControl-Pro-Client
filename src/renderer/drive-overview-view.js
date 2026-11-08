/**
 * GateControl -- Drive "Übersicht" (renderer view, part of the page Drive)
 *
 * Drive 1.18 (mockup WinStart): the page Drive opens on the overview — tiles in two rows: "Zu erledigen" (the next
 * deadlines, photos to review, mail attachments to file), "Zuletzt geöffnet", "Neu in Familie" with the storage
 * (and the state of "Ordner sichern") below; "Erinnerungen" (wide), "Personen" (with "Wer ist das?") and "Orte" (a
 * small map: the tiles of the main process's map service as pictures, no map to move; at 0 × 0 nothing is placed).
 * A tile shows only when it has something (the core decides: drive.overview() → { overview, view }; a Drive without
 * `overview` gets one the core built from what it has). What changes elsewhere reloads it, at most every 15 s.
 *
 * Mounted by drive-view.js like "Fotos" and "Speicher" (it hands over el / icon / clear / openDialog and where the
 * tiles lead). Server text only ever goes into textContent / attributes; no innerHTML.
 */
(function (root) {
	'use strict';

	const OS = root.GCDriveOverviewState;
	const PPS = root.GCDrivePlacesPeopleState;
	const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed', error: err && err.message });

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive
	 * @param {Function} o.t - i18n
	 * @param {Function} o.getLocale
	 * @param {{ el, icon, clear }} o.ui
	 * @param {Function} o.errorText - (result, t) → text
	 * @param {Function} o.formatBytes - (bytes, locale) → "212 GB"
	 * @param {Function} o.areaLabel - (areaId) → "Familie"
	 * @param {Function} o.openFile - (node) open the file
	 * @param {Function} o.openFolder - (folderId)
	 * @param {Function} o.openDeadlines - "Fristen"
	 * @param {Function} o.openPhotos - ({ tab?, person?, place?, name? }) the page "Fotos", there
	 * @param {Function} [o.openMemories] - (collection | null) the page "Erinnerungen" (Drive plugin 1.26) → false without it
	 * @param {Function} o.showPhotos - (items, start) the photos large (the lightbox of "Fotos")
	 * @param {Function} [o.nameDialog] - (person) "Wer ist das?"
	 * @param {Function} [o.openToFile] - Mail › "Zum Ablegen"
	 * @param {Function} [o.openStorage] - "Speicher"
	 * @param {Function} [o.syncSummary] - () → the state of "Ordner sichern" (text) or ''
	 * @param {Function} [o.openSync] - "Ordner sichern"
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const { el, icon, clear } = o.ui;
		const locale = () => o.getLocale();
		const now = typeof o.now === 'function' ? o.now : () => Date.now();
		const V = { shown: false, loading: false, data: null, view: null, error: null, seq: 0 };
		const wrap = el('div', { class: 'dov scroll', hidden: true });
		const previews = new Map();
		const tiles = new Map();

		async function load({ quiet = false } = {}) {
			const seq = ++V.seq;
			if (!quiet || !V.data) { V.loading = true; render(); }
			const r = await Promise.resolve(api.overview()).catch(fail);
			if (seq !== V.seq) return;
			V.loading = false;
			if (r && r.ok) { V.data = r.overview; V.view = r.view; V.error = null; } else if (!V.data) V.error = r;
			if (V.shown) render();
		}

		// ── Pictures ─────────────────────────────────────
		function preview(p) {
			if (!p || (!p.preview && !p.mediaId)) return Promise.resolve(null);
			const key = `${p.id}`;
			if (!previews.has(key)) {
				const ask = () => (p.mediaId ? api.preview(p.mediaId, { large: true }) : api.previewOf(p.id, { large: true }));
				previews.set(key, Promise.resolve(ask()).then((r) => (r && r.ok && r.data ? URL.createObjectURL(new Blob([r.data], { type: r.mime || 'image/jpeg' })) : null)).catch(() => null));
			}
			return previews.get(key);
		}
		function tile(z, x, y) {
			const key = `${z}/${x}/${y}`;
			if (!tiles.has(key)) {
				tiles.set(key, Promise.resolve(typeof api.mapTile === 'function' ? api.mapTile(z, x, y) : null)
					.then((r) => (r && r.ok !== false && r.data ? URL.createObjectURL(new Blob([r.data], { type: r.mime || 'image/png' })) : null))
					.catch(() => null));
			}
			return tiles.get(key);
		}

		// ── Building blocks ──────────────────────────────
		const panel = (key, title, { count = null, link = null, onLink = null, cls = '' } = {}, body = []) => el('section', { class: `dov-panel card${cls}`, 'data-tile': key }, [
			el('div', { class: 'dov-ph' }, [
				el('h3', { class: 'dov-h', text: title }),
				count !== null ? el('span', { class: 'dov-n', text: String(count) }) : null,
				link && onLink ? el('button', { type: 'button', class: 'dov-link', text: link, on: { click: onLink } }) : null,
			]),
			...body,
		]);
		const row = ({ lead, title, sub, onClick, cls = '' }) => el(onClick ? 'button' : 'div', { ...(onClick ? { type: 'button', on: { click: onClick } } : {}), class: `dov-row${cls}` }, [
			lead,
			el('span', { class: 'dov-row-tx' }, [typeof title === 'string' ? el('span', { class: 'dov-row-t', text: title }) : title, sub ? el('span', { class: 'dov-row-s', text: sub }) : null]),
		]);
		const sized = (n, st) => { Object.assign(n.style, st); return n; };
		const square = (text, tone) => el('span', { class: `dov-sq is-${tone}`, 'aria-hidden': 'true' }, [typeof text === 'string' ? document.createTextNode(text) : text]);

		// ── The tiles ────────────────────────────────────
		function todoPanel(d, v) {
			const td = d.todo;
			const rows = [];
			td.deadlines.forEach((x, i) => {
				const r = OS.deadlineRow(x, v.deadlines[i] && v.deadlines[i].when, { t, areaLabel: o.areaLabel });
				rows.push(row({ lead: square(r.badge || icon('calendar', 15), 'warn'), title: r.title, sub: r.sub, onClick: () => (x.node ? o.openFile(x.node) : o.openDeadlines()), cls: ' is-deadline' }));
			});
			const more = td.deadlinesTotal - td.deadlines.length;
			if (more > 0) rows.push(row({ lead: square(icon('calendar', 15), 'muted'), title: OS.plural(t, 'drive.ov.todo.more', more, locale()), onClick: () => o.openDeadlines() }));
			if (td.review > 0) rows.push(row({ lead: square('?', 'warn'), title: OS.plural(t, 'drive.ov.todo.review', td.review, locale()), sub: t('drive.ov.todo.reviewSub'), onClick: () => o.openPhotos({}) }));
			if ((td.toFile || 0) > 0) {
				rows.push(row({
					lead: square(String(td.toFile), 'blue'), title: OS.plural(t, 'drive.ov.todo.toFile', td.toFile, locale()),
					sub: td.toFileHint ? t('drive.ov.todo.toFileHint', { where: td.toFileHint }) : '', onClick: o.openToFile || null,
				}));
			}
			return panel('todo', t('drive.ov.todo.title'), { count: v.todoCount }, rows);
		}

		function recentPanel(d) {
			return panel('recent', t('drive.ov.recent.title'), { link: t('drive.ov.all'), onLink: () => o.openFiles() }, d.recent.slice(0, 5).map((r) => {
				const b = OS.fileBadge(r.node.name);
				return row({ lead: el('span', { class: `dov-fi is-${b.tone}`, 'aria-hidden': 'true', text: b.text }), title: r.node.name, sub: OS.recentSub(r, { t, locale: locale(), now: now() }), onClick: () => o.openFile(r.node) });
			}));
		}

		function storageFoot(d, v) {
			const parts = [];
			if (d.storage) {
				const fill = v.storageFill;
				const label = t('drive.ov.storage.label', { text: OS.storageText(d.storage, { t, locale: locale(), formatBytes: o.formatBytes }) });
				parts.push(el(o.openStorage ? 'button' : 'div', { ...(o.openStorage ? { type: 'button', on: { click: () => o.openStorage() } } : {}), class: 'dov-store' }, [
					el('span', { class: 'dov-row-s', text: label }),
					fill !== null ? el('span', { class: 'dov-bar', role: 'progressbar', 'aria-label': label, 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(Math.round(fill * 100)) }, [sized(el('span', { class: 'dov-bar-in' }), { width: `${Math.round(fill * 1000) / 10}%` })]) : null,
				]));
			}
			const sync = typeof o.syncSummary === 'function' ? o.syncSummary() : '';
			if (sync) parts.push(el('button', { type: 'button', class: 'dov-sync', on: { click: () => o.openSync && o.openSync() } }, [icon('sync', 14), el('span', { text: t('drive.ov.sync', { text: sync }) })]));
			return parts.length ? el('div', { class: 'dov-foot' }, parts) : null;
		}

		function activityPanel(d, v) {
			const rows = d.activity.map((a, i) => {
				const x = OS.activityText(a, v.activity[i], { t, locale: locale(), now: now() });
				const open = a.folder ? () => o.openFolder(a.folder.id) : a.sample ? () => o.openFile(a.sample) : null;
				return row({
					lead: el('span', { class: `dov-av is-t${a.user.id ? a.user.id % 6 : 0}`, 'aria-hidden': 'true', text: OS.initials(x.name) }),
					title: el('span', { class: 'dov-row-t is-plain' }, [el('b', { text: x.name }), ` ${x.rest}`]),
					sub: x.sub, onClick: open,
				});
			});
			return panel('activity', OS.activityTitle(v.activityArea, t), {}, [...rows, storageFoot(d, v)]);
		}

		function storagePanel(d, v) {
			return panel('storage', t('drive.ov.storage.title'), {}, [storageFoot(d, v)]);
		}

		function memoriesPanel(d, v) {
			const box = el('div', { class: 'dov-mems' });
			d.memories.forEach((m, i) => {
				const tx = OS.memoryText(m, v.memories[i], { t, locale: locale() });
				const img = el('img', { class: 'dov-mem-img', alt: '' });
				const card = el('button', { type: 'button', class: 'dov-mem', 'aria-label': `${tx.title}, ${tx.sub}`, on: { click: () => openMemory(m) } }, [
					img,
					el('span', { class: 'dov-mem-tx' }, [el('b', { text: tx.title }), el('span', { text: tx.sub })]),
				]);
				preview(m.cover).then((u) => { if (u) { img.src = u; card.classList.add('has-img'); } });
				box.appendChild(card);
			});
			// "Alle": the page "Erinnerungen" (Drive plugin 1.26), with an older Drive "Fotos"
			const all = () => { if (!(typeof o.openMemories === 'function' && o.openMemories(null))) o.openPhotos({}); };
			return panel('memories', t('drive.ov.mem.title'), { link: t('drive.ov.all'), onLink: all, cls: ' is-wide' }, [box]);
		}

		async function openMemory(m) {
			// Drive plugin 1.26: the collection "Heute vor X Jahren" on the page "Erinnerungen" (every photo of it)
			if (m.id && typeof o.openMemories === 'function' && o.openMemories({ id: m.id, kind: 'day', yearsAgo: m.yearsAgo, date: m.date, count: m.count, cover: m.cover })) return;
			let items = m.items && m.items.length >= m.count ? m.items : null;
			if (!items) {
				const r = await Promise.resolve(api.memories()).catch(fail);
				const g = r && r.ok ? r.groups.find((x) => x.yearsAgo === m.yearsAgo) : null;
				items = g && g.items.length ? g.items : (m.items && m.items.length ? m.items : [m.cover]);
			}
			o.showPhotos(items, 0);
		}

		function peoplePanel(d) {
			const p = d.people;
			const box = el('div', { class: 'dov-faces', role: 'list' });
			for (const x of p.people.slice(0, p.unnamed > 0 ? 5 : 6)) {
				box.appendChild(el('button', { type: 'button', role: 'listitem', class: 'dov-face', title: x.name, 'aria-label': x.name, 'data-person': String(x.id), on: { click: () => o.openPhotos({ person: x.id }) } }, [
					el('span', { class: `dov-fc is-t${typeof x.id === 'number' ? x.id % 6 : 0}`, 'aria-hidden': 'true', text: OS.initials(x.name) }),
					el('span', { class: 'dov-fn', text: x.name }),
				]));
			}
			if (p.unnamed > 0) {
				box.appendChild(el('button', { type: 'button', role: 'listitem', class: 'dov-face is-who', on: { click: () => who(p) } }, [
					el('span', { class: 'dov-fc is-who', 'aria-hidden': 'true', text: '?' }),
					el('span', { class: 'dov-fn', text: t('drive.ov.people.who') }),
				]));
			}
			return panel('people', t('drive.ov.people.title'), { link: t('drive.ov.all'), onLink: () => o.openPhotos({ tab: 'people' }) }, [box]);
		}

		/** "Wer ist das?": the person without a name with most photos (from GET people), named in the dialog of "Fotos". */
		async function who(p) {
			if (typeof o.nameDialog !== 'function') { o.openPhotos({ tab: 'people' }); return; }
			const r = await Promise.resolve(api.people()).catch(fail);
			const list = r && r.ok ? r.people.filter((x) => !x.name && !x.hidden).sort((a, b) => b.count - a.count) : [];
			const first = (p.firstUnnamed && list.find((x) => x.id === p.firstUnnamed)) || list[0];
			if (!first) { o.openPhotos({ tab: 'people' }); return; }
			o.nameDialog(first, () => load({ quiet: true }));
		}

		function placesPanel(d, v) {
			const map = el('button', { type: 'button', class: 'dov-map', 'aria-label': t('drive.ov.places.open'), on: { click: () => o.openPhotos({ tab: 'map' }) } }, [
				el('span', { class: 'dov-map-tiles' }),
				el('span', { class: 'dov-map-attr', text: t('drive.pp.map.attribution') }),
			]);
			const names = el('div', { class: 'dov-places' });
			d.places.top.forEach((pl, i) => {
				if (i) names.appendChild(document.createTextNode(' · '));
				names.appendChild(el('button', { type: 'button', class: 'dov-place', 'data-key': pl.key, text: pl.name, title: `${pl.name} · ${OS.fmt(pl.count, locale())}`, on: { click: () => o.openPhotos({ place: pl.key, name: pl.name }) } }));
			});
			// the map once it has its size (never at 0 × 0)
			requestAnimationFrame(() => drawMap(map, v.map));
			return panel('places', t('drive.ov.places.title'), { link: t('drive.ov.places.map'), onLink: () => o.openPhotos({ tab: 'map' }) }, [map, names]);
		}

		function drawMap(box, m) {
			const layer = box.querySelector('.dov-map-tiles');
			if (!layer || !m || !PPS) return;
			const w = box.clientWidth || 0;
			const h = box.clientHeight || 0;
			if (!w || !h) return;
			const [west, south, east, north] = m.bbox;
			const fit = PPS.fitView([{ lat: south, lon: west }, { lat: north, lon: east }], w, h, { maxZoom: 12, pad: 8 });
			const c = PPS.worldPx(fit.lat, fit.lon, fit.zoom);
			clear(layer);
			for (const tl of PPS.tileGrid(c.x, c.y, fit.zoom, w, h)) {
				const img = sized(el('img', { class: 'dov-map-tile', alt: '', draggable: 'false' }), { transform: `translate(${tl.left}px, ${tl.top}px)` });
				layer.appendChild(img);
				tile(tl.z, tl.x, tl.y).then((u) => { if (u) img.src = u; });
			}
			if (m.bubble) {
				const p = PPS.screenPos(m.bubble.lat, m.bubble.lon, c.x, c.y, fit.zoom, w, h);
				layer.appendChild(sized(el('span', { class: 'dov-bubble', text: OS.fmt(m.bubble.count, locale()) }), { left: `${p.x}px`, top: `${p.y}px` }));
			}
		}

		// ── Drawing ──────────────────────────────────────
		function render() {
			clear(wrap);
			if (V.loading && !V.data) { wrap.appendChild(el('div', { class: 'dv-empty', text: t('drive.loading') })); return; }
			if (!V.data) {
				wrap.appendChild(el('div', { class: 'dv-empty' }, [icon('alert', 26, '1.6'), el('span', { text: o.errorText(V.error, t) }), el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.retry'), on: { click: () => load() } })]));
				return;
			}
			const d = V.data;
			const v = V.view || { tiles: [], deadlines: [], memories: [], activity: [] };
			const make = { todo: todoPanel, recent: recentPanel, activity: activityPanel, storage: storagePanel, memories: memoriesPanel, people: peoplePanel, places: placesPanel };
			const first = v.tiles.filter((k) => ['todo', 'recent', 'activity', 'storage'].includes(k));
			const second = v.tiles.filter((k) => ['memories', 'people', 'places'].includes(k));
			if (!v.tiles.length) {
				wrap.appendChild(el('div', { class: 'dv-empty' }, [icon('cloud', 28, '1.6'), el('span', { text: t('drive.ov.empty') })]));
				const foot = storageFoot(d, v);
				if (foot) wrap.appendChild(foot);
				return;
			}
			if (first.length) wrap.appendChild(el('div', { class: `dov-grid is-n${first.length}` }, first.map((k) => make[k](d, v))));
			if (second.length) wrap.appendChild(el('div', { class: `dov-grid is-second${second.includes('memories') ? ' has-wide' : ''} is-n${second.length}` }, second.map((k) => make[k](d, v))));
		}

		return {
			el: wrap,
			show() {
				V.shown = true;
				wrap.hidden = false;
				load({ quiet: !!V.data });
			},
			hide() {
				V.shown = false;
				wrap.hidden = true;
			},
			refresh: () => load({ quiet: true }),
			relabel: () => { if (V.shown) render(); },
		};
	}

	root.GCDriveOverviewView = { mount };
})(typeof self !== 'undefined' ? self : this);
