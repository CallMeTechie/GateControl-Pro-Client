/**
 * GateControl -- Drive "Fotos" view state (renderer, no DOM access)
 *
 * Pure helpers of the view "Fotos" of the page Drive (Drive 1.7 'photos',
 * 'albums', 'frame'): the timeline grouped by month (with the counts of
 * photos/months), "Vor einem Jahr" (photos/memories), the albums (cards,
 * who may change them, the photo frame switch), the selection of photos
 * and a small limiter for the preview pictures. Loaded as a plain script
 * before drive-photos-view.js (window.GCDrivePhotosState) and required by
 * the node tests (test/drive-photos-state.test.js).
 *
 * Inputs are what window.gatecontrol.drive returns (core DriveService,
 * answers cleaned by core utils/drive.js); `t` is the i18n function (keys
 * drive.photos.* of the app locales).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDrivePhotosState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const PAGE = 120;
	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const pad = (n) => String(n).padStart(2, '0');
	const localeTag = (l) => (l === 'en' ? 'en-GB' : 'de-DE');

	function plural(t, key, n, params) {
		const count = Number(n) || 0;
		return t(`${key}.${count === 1 ? 'one' : 'other'}`, { ...(params || {}), count });
	}

	/** Which views this Drive offers: { photos, albums, frame, media } (me.features; media: Drive 1.25 'mediaFilter'). */
	function features(me) {
		const f = me && Array.isArray(me.features) ? me.features : [];
		return { photos: f.includes('photos'), albums: f.includes('albums'), frame: f.includes('frame'), media: f.includes('mediaFilter') };
	}

	// ── Drive 1.25 'mediaFilter': only pictures or only videos ──

	/** "Alle · Fotos · Videos" → [{ key: '' | 'image' | 'video', label }] */
	function mediaChoices(t) {
		return [{ key: '', label: t('drive.photos.media.all') }, { key: 'image', label: t('drive.photos.media.images') }, { key: 'video', label: t('drive.photos.media.videos') }];
	}

	/** The filter as sent: 'image' | 'video' while Drive knows it, else null (both). */
	function mediaOf(v, me) {
		return (v === 'image' || v === 'video') && features(me).media ? v : null;
	}

	/** A video's length on its tile: "0:07", "1:23", "1:02:03"; '' when unknown. */
	function durationText(ms) {
		if (!Number.isFinite(ms) || ms <= 0) return '';
		const s = Math.round(ms / 1000);
		const h = Math.floor(s / 3600);
		const m = Math.floor((s % 3600) / 60);
		return h ? `${h}:${pad(m)}:${pad(s % 60)}` : `${m}:${pad(s % 60)}`;
	}

	// ── Timeline ─────────────────────────────────────────

	/** ms → "2026-10" (local time) or '' */
	function monthKey(ms) {
		if (!Number.isFinite(ms)) return '';
		const d = new Date(ms);
		return `${d.getFullYear()}-${pad(d.getMonth() + 1)}`;
	}

	/** "2026-10" → "Oktober 2026" / "October 2026" */
	function monthLabel(key, locale) {
		const m = /^(\d{4})-(\d{2})$/.exec(str(key));
		if (!m) return '';
		return new Date(Number(m[1]), Number(m[2]) - 1, 1).toLocaleDateString(localeTag(locale), { month: 'long', year: 'numeric' });
	}

	/** "2026-10" → the cursor that starts the timeline in this month: the start of the next month (ISO). */
	function monthStart(key) {
		const m = /^(\d{4})-(\d{2})$/.exec(str(key));
		if (!m) return null;
		return new Date(Number(m[1]), Number(m[2]), 1).toISOString();
	}

	/**
	 * The photos loaded so far grouped by month (newest first) → [{ key, label, count, items }].
	 * `months` (photos/months) gives the count of a whole month; photos without a time go last.
	 */
	function groupByMonth(items, months, locale, t) {
		const counts = new Map((Array.isArray(months) ? months : []).map((m) => [m.month, m.count]));
		const out = [];
		const byKey = new Map();
		for (const p of Array.isArray(items) ? items : []) {
			const key = monthKey(p.takenAt) || 'none';
			let g = byKey.get(key);
			if (!g) {
				g = { key, label: key === 'none' ? t('drive.photos.noDate') : monthLabel(key, locale), count: counts.get(key) || 0, items: [] };
				byKey.set(key, g);
				out.push(g);
			}
			g.items.push(p);
		}
		for (const g of out) g.count = Math.max(g.count, g.items.length);
		out.sort((a, b) => (a.key === 'none') - (b.key === 'none') || (a.key < b.key ? 1 : a.key > b.key ? -1 : 0));
		return out;
	}

	/** Adds a page to the photos loaded so far (no doubles, newest first stays as the server sent it). */
	function mergePage(have, page) {
		const seen = new Set((Array.isArray(have) ? have : []).map((p) => p.id));
		const add = (page && Array.isArray(page.items) ? page.items : []).filter((p) => !seen.has(p.id));
		return (Array.isArray(have) ? have : []).concat(add);
	}

	/** "Vor einem Jahr" → [{ key, title, sub, items }] (closest year first). */
	function memoriesView(groups, { t, locale } = {}) {
		return (Array.isArray(groups) ? groups : []).filter((g) => g && Array.isArray(g.items) && g.items.length).map((g) => {
			const date = /^\d{4}-\d{2}-\d{2}$/.test(str(g.date)) ? new Date(Number(g.date.slice(0, 4)), Number(g.date.slice(5, 7)) - 1, Number(g.date.slice(8, 10))) : null;
			return {
				key: `y${g.yearsAgo}`,
				title: plural(t, 'drive.photos.yearsAgo', g.yearsAgo),
				sub: [date ? date.toLocaleDateString(localeTag(locale), { day: 'numeric', month: 'long', year: 'numeric' }) : '', plural(t, 'drive.photos.count', g.items.length)].filter(Boolean).join(' · '),
				items: g.items,
			};
		});
	}

	/** "14. Juli 2026, 18:03" of a photo (its time taken) or ''. */
	function photoWhen(p, locale) {
		if (!p || !Number.isFinite(p.takenAt)) return '';
		const d = new Date(p.takenAt);
		return `${d.toLocaleDateString(localeTag(locale), { day: 'numeric', month: 'long', year: 'numeric' })}, ${pad(d.getHours())}:${pad(d.getMinutes())}`;
	}

	/** The area filter of the timeline: "Alle Bereiche" and the areas one can read. */
	function areaChoices(areas, areaLabel, t) {
		return [{ id: '', label: t('drive.photos.allAreas') }].concat((Array.isArray(areas) ? areas : []).map((a) => ({ id: a.id, label: areaLabel(a, t) })));
	}

	// ── Albums ───────────────────────────────────────────

	/** An album card → { id, name, sub, coverId, frame, canEdit } */
	function albumView(a, { areas, areaLabel, t } = {}) {
		const x = a || {};
		const area = (Array.isArray(areas) ? areas : []).find((r) => r.id === x.areaId);
		const sub = [plural(t, 'drive.photos.count', x.count || 0), area && areaLabel ? areaLabel(area, t) : ''].filter(Boolean);
		return { id: x.id, name: str(x.name), sub: sub.join(' · '), coverId: x.coverId || null, frame: !!x.frame, canEdit: !!x.canEdit };
	}

	/** Albums photos can be added to (one may change them). */
	function editableAlbums(albums) {
		return (Array.isArray(albums) ? albums : []).filter((a) => a && a.canEdit);
	}

	/** Areas a new album can belong to (writable, not archived): Meine Dateien first. */
	function albumAreas(areas) {
		return (Array.isArray(areas) ? areas : []).filter((a) => a && a.writable && !a.archived);
	}

	/** null when an album name is fine, else the text. */
	function albumNameError(raw, t) {
		const s = str(raw).trim();
		if (!s) return t('drive.photos.album.nameEmpty');
		if (s.length > 200) return t('drive.photos.album.nameLong');
		return null;
	}

	/** Shows the photo frame switch of an album: the Drive has 'frame' and lets this person switch it (`canFrame`; canEdit is not enough). */
	function frameSwitch(album, me) {
		return !!album && !!album.canFrame && features(me).frame;
	}

	// ── Drive 1.31 'framePhotos': photos for the photo frame (GateControl TV) ──

	/** Can the person share single photos with the photo frame (me.features 'framePhotos')? */
	function framePhotosOn(me) {
		return !!(me && Array.isArray(me.features) && me.features.includes('framePhotos'));
	}

	const isPicture = (p) => !!p && p.kind !== 'video' && !(p.mime && /^video\//.test(String(p.mime)));

	/**
	 * What the menu offers for the photos `items` (selected, or the one in the large view), `inFrame` the ids known to be
	 * in the frame: { pictures, add, remove } (ids). Nothing (no pictures) when only videos are selected — then the entries
	 * are left out. `add` sends every item without the frame (videos too: Drive names them as skipped, not_image).
	 */
	function frameChoice(items, inFrame) {
		const list = (Array.isArray(items) ? items : []).filter((p) => p && Number.isSafeInteger(p.id) && p.id > 0);
		const has = inFrame instanceof Set ? (id) => inFrame.has(id) : () => false;
		const pictures = list.filter(isPicture).map((p) => p.id);
		if (!pictures.length) return { pictures: [], add: [], remove: [] };
		return {
			pictures,
			add: list.filter((p) => !has(p.id)).map((p) => p.id),
			remove: pictures.filter((id) => has(id)),
		};
	}

	/** The ids in the frame after an answer: GET frame/photos?ids= sets those asked, POST / DELETE give all ids. */
	function frameMerge(inFrame, r, asked) {
		const out = new Set(inFrame instanceof Set ? inFrame : []);
		if (!r || !r.ok || !Array.isArray(r.ids)) return out;
		if (Array.isArray(asked)) {
			for (const id of asked) out.delete(id);
			for (const id of r.ids) out.add(id);
			return out;
		}
		return new Set(r.ids);
	}

	/** Why a photo was left out, as the toast says it (Drive's reasons; an unknown one: "nicht möglich"). */
	const FRAME_REASONS = ['not_image', 'vault', 'blocked', 'child', 'not_found'];

	/**
	 * The toast after „Für Fotorahmen freigeben“ / „Aus Fotorahmen entfernen“ → { text, tone }.
	 * r: the answer of addToFrame / removeFromFrame; the skipped photos with their reason ("2 übersprungen: 1 Video,
	 * 1 im Tresor"); 403 { field: 'frame' }: this account may not share photos; other errors: errorText.
	 */
	function frameToast(r, { remove = false, t, errorText = null } = {}) {
		if (!r || !r.ok) {
			if (r && r.status === 403 && (r.field === 'frame' || r.code === 'forbidden')) return { text: t('drive.photos.frame.forbidden'), tone: 'error' };
			return { text: errorText ? errorText(r) : t('drive.photos.frame.failed'), tone: 'error' };
		}
		if (remove) return { text: plural(t, 'drive.photos.frame.removed', r.removed || 0), tone: 'success' };
		const parts = [plural(t, 'drive.photos.frame.added', r.added || 0)];
		const skipped = Array.isArray(r.skipped) ? r.skipped : [];
		if (skipped.length) {
			const by = new Map();
			for (const x of skipped) {
				const k = FRAME_REASONS.includes(x && x.reason) ? x.reason : 'other';
				by.set(k, (by.get(k) || 0) + 1);
			}
			const why = [...FRAME_REASONS, 'other'].filter((k) => by.has(k)).map((k) => plural(t, `drive.photos.frame.why.${k}`, by.get(k)));
			parts.push(plural(t, 'drive.photos.frame.skipped', skipped.length, { why: why.join(', ') }));
		}
		return { text: parts.join(' '), tone: r.added ? 'success' : 'info' };
	}

	// ── Selection ────────────────────────────────────────

	/** A new selection with `id` added or removed. */
	function toggle(sel, id) {
		const out = new Set(sel || []);
		if (out.has(id)) out.delete(id);
		else out.add(id);
		return out;
	}

	/** The ids from `last` to `id` in the order of `items` (shift-click) added to the selection. */
	function selectRange(sel, items, last, id) {
		const ids = (Array.isArray(items) ? items : []).map((p) => p.id);
		const a = ids.indexOf(last);
		const b = ids.indexOf(id);
		const out = new Set(sel || []);
		if (a < 0 || b < 0) { out.add(id); return out; }
		for (let i = Math.min(a, b); i <= Math.max(a, b); i++) out.add(ids[i]);
		return out;
	}

	/** The selection in parts the API takes (≤ 500 ids per call). */
	function chunks(ids, size = 500) {
		const list = Array.from(ids || []);
		const out = [];
		for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
		return out;
	}

	// ── Previews ─────────────────────────────────────────

	/**
	 * At most `n` jobs at a time (preview pictures): limiter(n) → run(fn) → Promise.
	 * Jobs wait in order; a failed job does not stop the others.
	 */
	function limiter(n) {
		let active = 0;
		const queue = [];
		const next = () => {
			if (active >= n || !queue.length) return;
			const { fn, resolve, reject } = queue.shift();
			active++;
			Promise.resolve().then(fn).then(resolve, reject).finally(() => { active--; next(); });
		};
		return {
			run(fn) { return new Promise((resolve, reject) => { queue.push({ fn, resolve, reject }); next(); }); },
			get pending() { return queue.length + active; },
		};
	}

	return {
		PAGE, features, mediaChoices, mediaOf, durationText,
		monthKey, monthLabel, monthStart, groupByMonth, mergePage, memoriesView, photoWhen, areaChoices,
		albumView, editableAlbums, albumAreas, albumNameError, frameSwitch,
		framePhotosOn, frameChoice, frameMerge, frameToast, FRAME_REASONS,
		toggle, selectRange, chunks, limiter,
	};
});
