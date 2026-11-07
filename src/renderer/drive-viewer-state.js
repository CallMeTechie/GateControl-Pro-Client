/**
 * GateControl -- Drive viewer of pictures and videos, state (renderer, no DOM access)
 *
 * Pure helpers of the large view (Drive 1.21; drive-photos-view.js "lightbox", drive-viewer.js): which files of a
 * folder it goes through, a file node as an item of the view, the zoom (factor and shift, held inside the picture),
 * where a video was left, and what to say when a video does not play. Loaded as a plain script before
 * drive-viewer.js (window.GCDriveViewerState) and required by the node tests (test/drive-121-state.test.js).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDriveViewerState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const ZOOM_MAX = 8;
	const KEEP_MS = 5000;
	// containers and codecs a Chromium build rarely plays: the hint first, "Trotzdem abspielen" tries
	const RARE_VIDEO = /^video\/(x-matroska|x-msvideo|avi|msvideo|x-ms-wmv|x-ms-asf|x-flv|mpeg|x-mpeg|3gpp2?)$/i;
	const IMAGE_EXT = /\.(jpe?g|png|gif|webp|heic|heif|bmp|avif)$/i;
	const VIDEO_EXT = /\.(mp4|m4v|mov|webm|mkv|avi|3gp)$/i;

	/** 'image' | 'video' | null — a picture or a video the view shows (no folder, nothing of a vault). */
	function kindOf(n) {
		if (!n || n.isDir || n.encrypted) return null;
		const m = String(n.mime || '').toLowerCase();
		if (/^image\//.test(m) && m !== 'image/svg+xml') return 'image';
		if (/^video\//.test(m)) return 'video';
		if (!m || m === 'application/octet-stream') {
			if (IMAGE_EXT.test(n.name || '')) return 'image';
			if (VIDEO_EXT.test(n.name || '')) return 'video';
		}
		return null;
	}

	/** A file node of a folder as an item of the view (the photos' shape: kind, takenAt). */
	function itemOf(n) {
		return { ...n, kind: kindOf(n), takenAt: n.takenAt || n.mtime || null };
	}

	/**
	 * The pictures and videos of `items` (a folder, a search) to go through from `n`, and where it is among them;
	 * just `n` when it is not in the list → { list, start }.
	 */
	function viewerList(items, n) {
		const list = (Array.isArray(items) ? items : []).filter((x) => kindOf(x)).map(itemOf);
		const start = list.findIndex((x) => x.id === n.id);
		return start < 0 ? { list: [itemOf(n)], start: 0 } : { list, start };
	}

	/** The zoom after a step `f` about (cx, cy) from the middle; held between 1 and ZOOM_MAX, the picture in view. */
	function zoomBy(z, f, cx = 0, cy = 0, box = null) {
		const s = Math.max(1, Math.min(ZOOM_MAX, (z.s || 1) * f));
		const k = s / (z.s || 1);
		return clamp({ s, x: cx - (cx - (z.x || 0)) * k, y: cy - (cy - (z.y || 0)) * k }, box);
	}

	/** The shift held so that the picture still covers the middle (box = { w, h } of the stage). */
	function clamp(z, box) {
		if (z.s <= 1) return { s: 1, x: 0, y: 0 };
		if (!box || !box.w || !box.h) return z;
		const mx = (box.w * (z.s - 1)) / 2;
		const my = (box.h * (z.s - 1)) / 2;
		return { s: z.s, x: Math.max(-mx, Math.min(mx, z.x)), y: Math.max(-my, Math.min(my, z.y)) };
	}

	function transform(z) {
		return !z || z.s <= 1 ? '' : `translate(${Math.round(z.x)}px, ${Math.round(z.y)}px) scale(${Math.round(z.s * 100) / 100})`;
	}

	/** Where videos were left: per file and revision, the last `max`, not within the first or last 5 s. */
	function places(max = 50) {
		const m = new Map();
		const key = (n) => `${n.id}:${n.rev || 0}`;
		return {
			get: (n) => (m.has(key(n)) ? m.get(key(n)) : null),
			keep(n, sec, duration) {
				const k = key(n);
				const ms = Math.round((Number(sec) || 0) * 1000);
				const d = Math.round((Number(duration) || 0) * 1000);
				if (d > 0 && ms >= d - KEEP_MS) { m.delete(k); return; }
				if (ms <= KEEP_MS) return;
				m.delete(k);
				m.set(k, ms / 1000);
				while (m.size > max) m.delete(m.keys().next().value);
			},
			forget: (n) => { m.delete(key(n)); },
			get size() { return m.size; },
		};
	}

	/** Should the view say first that the type rarely plays? (`canPlay`: the video element's canPlayType). */
	function rareType(mime, canPlay) {
		const m = String(mime || '').toLowerCase();
		if (!RARE_VIDEO.test(m)) return false;
		return typeof canPlay !== 'function' || canPlay(m) === '';
	}

	/** The type of a file as the hint says it ("MKV"; else its MIME type). */
	function typeName(n) {
		const name = String((n && n.name) || '');
		const i = name.lastIndexOf('.');
		return i > 0 && name.length - i <= 6 ? name.slice(i + 1).toUpperCase() : String((n && n.mime) || '');
	}

	/** MediaError code → 'cannot' (the format / codec) | 'network' | 'other'. */
	function trouble(code) {
		if (code === 3 || code === 4) return 'cannot';
		if (code === 2) return 'network';
		return 'other';
	}

	return { ZOOM_MAX, KEEP_MS, kindOf, itemOf, viewerList, zoomBy, clamp, transform, places, rareType, typeName, trouble };
});
