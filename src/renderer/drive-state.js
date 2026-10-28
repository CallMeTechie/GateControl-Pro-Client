/**
 * GateControl -- Drive view state (renderer, no DOM access)
 *
 * Pure helpers for the page "Drive" (plugin gatecontrol-drive: the files of
 * the person, the family, the children and the team on the own storage) and
 * for "In Drive speichern" in Chats, GateDrop and Schule: file kinds and
 * sizes, dates, area labels and their storage, list rows (folder, search,
 * trash), breadcrumbs, names Drive takes, link options and texts, the
 * transfer list, the folder picker (writable areas / folders only, the folder
 * last picked) and the error texts of Drive's codes. Loaded as a plain
 * script before drive-view.js (window.GCDriveState) and required by the node
 * tests (test/drive-state.test.js).
 *
 * Inputs are what window.gatecontrol.drive returns (core DriveService,
 * answers cleaned by core utils/drive.js); `t` is the i18n function (keys
 * drive.* of the app locales).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDriveState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const APP_ROUTE = 'plg-gatecontrol-drive';
	const SORTS = ['name', 'mtime', 'size'];
	const LINK_EXPIRES = ['1d', '7d', '30d', 'never'];
	const CONFLICT_CHOICES = ['version', 'rename', null];
	const PIN_RE = /^\d{4,12}$/;
	const FORBIDDEN_RE = /[/\\:*?"<>|\u0000-\u001f]/;
	const NAME_MAX = 255;
	const AREA_RANK = { mine: 0, family: 1, child: 2, team: 3 };

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const pad = (n) => String(n).padStart(2, '0');
	const localeTag = (l) => (l === 'en' ? 'en-GB' : 'de-DE');

	/** "1 Datei" / "3 Dateien": `${key}.one` / `${key}.other` with {{count}}. */
	function plural(t, key, n, params) {
		const count = Number(n) || 0;
		return t(`${key}.${count === 1 ? 'one' : 'other'}`, { ...(params || {}), count });
	}

	// ── Files ────────────────────────────────────────────

	const EXT = {
		image: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic', 'heif', 'bmp', 'avif', 'tif', 'tiff'],
		video: ['mp4', 'mov', 'mkv', 'webm', 'avi', '3gp', 'm4v'],
		audio: ['mp3', 'm4a', 'aac', 'ogg', 'opus', 'wav', 'flac'],
		pdf: ['pdf'],
		doc: ['doc', 'docx', 'odt', 'rtf', 'pages'],
		sheet: ['xls', 'xlsx', 'ods', 'csv', 'numbers'],
		slides: ['ppt', 'pptx', 'odp', 'key'],
		archive: ['zip', '7z', 'rar', 'tar', 'gz', 'tgz'],
		text: ['txt', 'md', 'json', 'xml', 'log'],
	};

	function extOf(name) {
		const s = str(name).trim();
		const i = s.lastIndexOf('.');
		return i > 0 ? s.slice(i + 1).toLowerCase() : '';
	}

	/** What a file is (its icon): folder, image, video, audio, pdf, doc, sheet, slides, archive, text, other. */
	function kindOf(node) {
		if (!node) return 'other';
		if (node.isDir) return 'folder';
		const m = str(node.mime).toLowerCase();
		const e = extOf(node.name);
		if (m.startsWith('image/') || EXT.image.includes(e)) return 'image';
		if (m.startsWith('video/') || EXT.video.includes(e)) return 'video';
		if (m.startsWith('audio/') || EXT.audio.includes(e)) return 'audio';
		if (m === 'application/pdf' || EXT.pdf.includes(e)) return 'pdf';
		if (EXT.doc.includes(e) || m.includes('wordprocessing') || m === 'application/msword') return 'doc';
		if (EXT.sheet.includes(e) || m.includes('spreadsheet')) return 'sheet';
		if (EXT.slides.includes(e) || m.includes('presentation')) return 'slides';
		if (EXT.archive.includes(e) || m.includes('zip') || m.includes('compressed')) return 'archive';
		if (m.startsWith('text/') || EXT.text.includes(e)) return 'text';
		return 'other';
	}

	/** Short badge on a file icon ("PDF", "DOCX" …): the extension, else nothing. */
	function badgeOf(node) {
		if (!node || node.isDir) return '';
		return extOf(node.name).toUpperCase().slice(0, 4);
	}

	/** 1,2 MB (de) / 1.2 MB (en). */
	function formatBytes(bytes, locale) {
		const n = Number(bytes);
		if (!Number.isFinite(n) || n < 0) return '';
		if (n < 1024) return `${n} B`;
		const units = ['KB', 'MB', 'GB', 'TB'];
		let v = n / 1024;
		let i = 0;
		while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
		const digits = v >= 100 || i === 0 ? 0 : 1;
		return `${v.toLocaleString(localeTag(locale), { minimumFractionDigits: digits, maximumFractionDigits: digits })} ${units[i]}`;
	}

	function sameDay(a, b) {
		return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
	}

	/** 'heute 10:12' / 'gestern 18:01' / '18.10.2026' */
	function when(ms, now, locale, t) {
		if (!Number.isFinite(ms)) return '';
		const d = new Date(ms);
		const n = new Date(now);
		const time = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
		if (sameDay(d, n)) return t('drive.time.today', { time });
		if (sameDay(d, new Date(now - 86400000))) return t('drive.time.yesterday', { time });
		return d.toLocaleDateString(localeTag(locale), { day: '2-digit', month: '2-digit', year: 'numeric' });
	}

	// ── Names ────────────────────────────────────────────

	/** A name Drive takes as typed: not empty, no / \ : * ? " < > |, no dot or space at the end, ≤ 255, not .gcdrive. */
	function validName(raw) {
		const s = str(raw).trim();
		if (!s || s.length > NAME_MAX || FORBIDDEN_RE.test(s)) return false;
		if (/[. ]$/.test(s) || s === '.' || s === '..' || s.toLowerCase() === '.gcdrive') return false;
		return true;
	}

	/** null when fine, else the text to show under the field. */
	function nameError(raw, t) {
		if (!str(raw).trim()) return t('drive.name.empty');
		return validName(raw) ? null : t('drive.name.invalid');
	}

	// ── Areas ────────────────────────────────────────────

	function sortAreas(list) {
		return (Array.isArray(list) ? list : []).slice().sort((a, b) => ((AREA_RANK[a.kind] ?? 9) - (AREA_RANK[b.kind] ?? 9)) || str(a.label).localeCompare(str(b.label)));
	}

	/** The label in lists: "Meine Dateien", "Familie Muster", "Kinder · Lena", "Team · Büro". */
	function areaLabel(a, t) {
		if (!a) return '';
		if (a.kind === 'mine') return t('drive.area.mine');
		if (a.kind === 'child') return t('drive.area.child', { name: str(a.label) });
		if (a.kind === 'team') return t('drive.area.team', { name: str(a.label) });
		return str(a.label);
	}

	/** Who sees it / what one may: "nur für dich", "mit der Familie geteilt", … */
	function areaHint(a, t) {
		if (!a) return '';
		if (a.archived) return t('drive.area.archived');
		if (a.kind === 'mine') return t('drive.area.mineHint');
		if (a.kind === 'family') return t('drive.area.familyHint');
		if (a.kind === 'child') return t(a.via === 'parent' ? 'drive.area.childParentHint' : 'drive.area.childOwnHint');
		return t(a.writable ? 'drive.area.teamHint' : 'drive.area.teamReadHint');
	}

	/** "38 GB" or "38 GB von 50 GB" (null without a storage figure). */
	function usage(a, t, locale) {
		const s = a && a.storage;
		if (!s || !Number.isFinite(s.bytes)) return null;
		const used = formatBytes(s.bytes, locale);
		return Number.isFinite(s.quota) && s.quota > 0 ? t('drive.area.usageOf', { used, quota: formatBytes(s.quota, locale) }) : used;
	}

	/** The area to show: the chosen one while it exists, else Meine Dateien, else the first. */
	function currentArea(areas, chosenId) {
		const list = Array.isArray(areas) ? areas : [];
		return list.find((a) => a.id === chosenId) || list.find((a) => a.kind === 'mine') || list[0] || null;
	}

	/** The state of the page from GET me: { usable, key } (key: the text when not usable). */
	function accessOf(me) {
		if (!me || me.ok === false) return { usable: false, key: null };
		if (!me.licence || !me.licence.valid) return { usable: false, key: 'drive.access.notLicensed' };
		if (!me.me || !me.me.seat) return { usable: false, key: 'drive.access.noSeat' };
		if (!Array.isArray(me.areas) || !me.areas.length) return { usable: true, key: 'drive.access.noAreas' };
		return { usable: true, key: null };
	}

	// ── Folder / rows ────────────────────────────────────

	/** Breadcrumbs of a folder: the top one named like its area. */
	function crumbs(folder, area, t) {
		const list = folder && Array.isArray(folder.crumbs) ? folder.crumbs : [];
		// a vault folder this PC has no key for (Drive 1.9): no name
		return list.map((c, i) => ({ id: c.id, name: i === 0 && area ? areaLabel(area, t) : c.locked ? t('drive.vault.lockedFolder') : c.name, current: i === list.length - 1 }));
	}

	/**
	 * One row of a list: { id, name, kind, badge, sub, date, size, isDir, preview, mediaId, doc, encrypted, locked, vault }.
	 * doc (Drive 1.8 'docAi'): the kind of document Drive recognised ('invoice' …) while insight.status is ready;
	 * vault (Drive 1.9): the folder is a vault folder; locked: a vault node without a key on this PC (no name).
	 */
	function rowView(node, { t, locale, now = Date.now(), mode = 'folder' } = {}) {
		const n = node || {};
		const sub = [];
		const locked = !!(n.encrypted && n.locked);
		if (mode === 'search') {
			if (n.path) sub.push(t('drive.search.in', { path: n.path }));
			if (n.match === 'text' && n.snippet) sub.push(n.snippet);
		} else if (mode === 'trash') {
			if (n.from) sub.push(t('drive.trash.from', { path: n.from }));
			if (n.isDir && Number.isFinite(n.files) && n.files > 0) sub.push(plural(t, 'drive.trash.files', n.files));
		}
		const stamp = mode === 'trash' && Number.isFinite(n.deletedAt) ? n.deletedAt : (Number.isFinite(n.mtime) ? n.mtime : n.updatedAt);
		return {
			id: n.id,
			name: locked ? t(n.vaultRoot ? 'drive.vault.lockedVault' : n.isDir ? 'drive.vault.lockedFolder' : 'drive.vault.lockedFile') : str(n.name),
			kind: n.encrypted && n.vaultRoot ? 'vault' : kindOf(n),
			badge: locked ? '' : badgeOf(n),
			sub: sub.join(' · '),
			snippet: mode === 'search' && n.match === 'text' ? str(n.snippet) : '',
			date: when(stamp, now, locale, t),
			size: n.isDir ? '' : formatBytes(n.size || 0, locale),
			isDir: !!n.isDir,
			preview: !!n.preview && !!n.mediaId && !n.encrypted,
			mediaId: n.mediaId || null,
			doc: !n.isDir && !n.encrypted && n.insight && n.insight.status === 'ready' && n.insight.kind ? n.insight.kind : null,
			encrypted: !!n.encrypted,
			locked,
			vault: !!(n.encrypted && n.vaultRoot),
		};
	}

	// Drive 1.9 'office': the documents "Im Browser bearbeiten" offers (never a vault's)
	const OFFICE_EXTS = ['docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp', 'csv'];

	/** 'edit' | 'view' | null — "Im Browser bearbeiten" (write right) / "Im Browser ansehen" (read only). */
	function officeMode(node, writable, me) {
		const n = node || {};
		if (n.isDir || n.encrypted || !hasFeature(me, 'office') || !OFFICE_EXTS.includes(extOf(n.name))) return null;
		return writable ? 'edit' : 'view';
	}

	/** Sort keys of the list → { sort, order } for drive.folder(). */
	function sortQuery(sort) {
		const s = SORTS.includes(sort) ? sort : 'name';
		return { sort: s, order: s === 'name' ? 'asc' : 'desc' };
	}

	/**
	 * What a row's menu offers: { open, saveAs, share, rename, move, versions, remove, portal, timeTravel, details, office }.
	 * A vault's nodes (Drive 1.9): no links, no moves, no time travel, no AI, no office; without the key only "In den
	 * Papierkorb".
	 */
	function actionsFor(node, writable, me) {
		const n = node || {};
		const enc = !!n.encrypted;
		const locked = enc && !!n.locked;
		return {
			open: !locked,
			saveAs: !n.isDir && !locked,
			share: !!writable && !enc,
			rename: !!writable && !locked,
			move: !!writable && !enc,
			versions: !n.isDir && !locked,
			remove: !!writable,
			// Drive 1.6 'links': "Im Portal öffnen"
			portal: hasPortalLinks(me),
			// Drive 1.7 'timeTravel': "Auf früheren Stand zurücksetzen …" (folders one may write to)
			timeTravel: !!n.isDir && !!writable && !enc && hasFeature(me, 'timeTravel'),
			// Drive 1.8 'docAi': "Details" (what Drive recognised, its deadlines)
			details: !n.isDir && !enc && hasFeature(me, 'docAi'),
			// Drive 1.9 'office': 'edit' | 'view' | null
			office: officeMode(n, writable, me),
		};
	}

	/** Does this Drive report `name` in me.features (Drive 1.5+)? */
	function hasFeature(me, name) {
		return !!(me && Array.isArray(me.features) && me.features.includes(name));
	}

	// ── Time travel (Drive 1.7) ─────────────────────────

	const TT_PRESETS = [
		{ key: 'hour', ms: 3600000 },
		{ key: 'day', ms: 86400000 },
		{ key: 'week', ms: 7 * 86400000 },
		{ key: 'month', ms: 30 * 86400000 },
	];

	/** ms → the value of an <input type="datetime-local"> ("2026-10-27T14:05", local time). */
	function localInputValue(ms) {
		if (!Number.isFinite(ms)) return '';
		const d = new Date(ms);
		return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
	}

	/** The value of an <input type="datetime-local"> → ms (local time) or null. */
	function parseLocalInput(v) {
		const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(str(v).trim());
		if (!m) return null;
		const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] || 0));
		if (d.getMonth() !== Number(m[2]) - 1 || d.getDate() !== Number(m[3])) return null;
		return d.getTime();
	}

	/** The quick choices "vor 1 Stunde" … "vor einem Monat" → [{ key, at, label }] */
	function timeTravelPresets(now, t) {
		return TT_PRESETS.map((p) => ({ key: p.key, at: now - p.ms, label: t(`drive.tt.preset.${p.key}`) }));
	}

	/** null when `at` can be asked for, else the text: not a time, in the future. */
	function timeTravelError(at, now, t) {
		if (!Number.isFinite(at)) return t('drive.tt.err.when');
		if (at >= now) return t('drive.tt.err.future');
		return null;
	}

	/** "Montag, 27.10.2026, 14:05" */
	function longWhen(ms, locale) {
		if (!Number.isFinite(ms)) return '';
		const d = new Date(ms);
		return `${d.toLocaleDateString(localeTag(locale), { weekday: 'long', day: '2-digit', month: '2-digit', year: 'numeric' })}, ${pad(d.getHours())}:${pad(d.getMinutes())}`;
	}

	/**
	 * The preview → { empty, lines: [string], sample: [{ op, name, path }], limited: string|null }:
	 * what comes back, gets the old content, goes into the trash, is moved.
	 */
	function timeTravelView(p, { t, locale } = {}) {
		const x = p || {};
		const lines = [];
		if (x.restore) lines.push(plural(t, 'drive.tt.restore', x.restore));
		if (x.revert) lines.push(plural(t, 'drive.tt.revert', x.revert));
		if (x.trash) lines.push(plural(t, 'drive.tt.trash', x.trash));
		if (x.move) lines.push(plural(t, 'drive.tt.move', x.move));
		const sample = (Array.isArray(x.sample) ? x.sample : []).slice(0, 8).map((s) => ({
			op: ['restore', 'revert', 'trash', 'move'].includes(s.op) ? t(`drive.tt.op.${s.op}`) : '',
			name: str(s.name),
			path: str(s.path),
		}));
		const ops = Number(x.ops) || Number(x.total) || 0;
		return {
			empty: !lines.length,
			// more steps than Drive does at once (400 invalid { field: 'at' }): a later time or a subfolder
			tooMany: Number(x.max) > 0 && ops > Number(x.max) ? t('drive.tt.tooMany', { ops, max: x.max }) : null,
			// files whose content of then is gone already: they stay as they are
			lost: x.lost ? plural(t, 'drive.tt.lost', x.lost) : null,
			lines,
			sample,
			more: Math.max(0, (Number(x.total) || 0) - sample.length),
			limited: x.limited ? t('drive.tt.limited', { since: Number.isFinite(x.historySince) ? longWhen(x.historySince, locale) : '—' }) : null,
		};
	}

	/**
	 * The folders of this PC the time travel touches ("Ordner sichern") → [{ name, text, mode }]:
	 * "Abgleichen" gets Drive's old state (PC changes stay as conflict copies), "Nur sichern" keeps the PC as it is.
	 */
	function timeTravelLinked(linked, t) {
		return (Array.isArray(linked) ? linked : []).map((l) => ({
			mode: l.mode === 'sync' ? 'sync' : 'backup',
			name: str(l.name || l.path),
			text: t(l.mode === 'sync' ? 'drive.tt.linkedSync' : 'drive.tt.linkedBackup', { name: str(l.name || l.path) }),
		}));
	}

	/** The result → "Zurückgesetzt: 3 zurückgeholt, …" (undo: "Rückgängig gemacht: …"). */
	function timeTravelResultText(r, t, { undo = false } = {}) {
		const x = r || {};
		const parts = [];
		if (x.restored) parts.push(plural(t, 'drive.tt.restored', x.restored));
		if (x.reverted) parts.push(plural(t, 'drive.tt.reverted', x.reverted));
		if (x.trashed) parts.push(plural(t, 'drive.tt.trashed', x.trashed));
		if (x.moved) parts.push(plural(t, 'drive.tt.moved', x.moved));
		if (x.failed) parts.push(plural(t, 'drive.tt.failed', x.failed));
		if (x.lost) parts.push(plural(t, 'drive.tt.lostDone', x.lost));
		const what = parts.length ? parts.join(', ') : t('drive.tt.nothing');
		return t(undo ? 'drive.tt.undone' : 'drive.tt.done', { what });
	}

	/** Does this Drive give direct portal links (me.features 'links', me.links.node)? */
	function hasPortalLinks(me) {
		return !!(me && Array.isArray(me.features) && me.features.includes('links') && me.links && me.links.node);
	}

	// ── Live (push `changed`) ───────────────────────────

	/** Does a change elsewhere ({ areas, seq }) touch what the page shows? */
	function liveRelevant(ev, { view, areaId } = {}) {
		if (!['folder', 'search', 'trash', 'links'].includes(view)) return false;
		const areas = ev && Array.isArray(ev.areas) ? ev.areas : null;
		if (!areas || !areas.length || view !== 'folder') return true;
		return areas.includes(areaId);
	}

	/**
	 * At most one call of `fn` per `ms` (the last request wins, nothing is lost):
	 * throttle(fn, 2000) → { request(), cancel() }.
	 */
	function throttle(fn, ms, { now = () => Date.now(), setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
		let last = -Infinity;
		let timer = null;
		const fire = () => { timer = null; last = now(); fn(); };
		return {
			request() {
				if (timer) return;
				const wait = Math.max(0, last + ms - now());
				if (!wait) fire();
				else timer = setTimer(fire, wait);
			},
			cancel() { if (timer) clearTimer(timer); timer = null; },
		};
	}

	// ── Guard (Drive 1.6) ───────────────────────────────

	/**
	 * The banner "Von Drive gestoppt" → { id, title, text, sample: [string], more } | null
	 * (only while Drive keeps this device stopped).
	 */
	function guardView(g, { t, locale, now = Date.now() } = {}) {
		if (!g || !g.locked) return null;
		const inc = g.incident || {};
		const sample = (Array.isArray(inc.sample) ? inc.sample : []).map(str).filter(Boolean).slice(0, 5);
		const files = Number(inc.files) || 0;
		const parts = [];
		if (files) parts.push(plural(t, 'drive.guard.files', files));
		if (Number.isFinite(inc.at)) parts.push(t('drive.guard.at', { when: when(inc.at, now, locale, t) }));
		if (inc.deviceName) parts.push(t('drive.guard.device', { name: str(inc.deviceName) }));
		return {
			id: inc.id === undefined || inc.id === null ? null : inc.id,
			title: t('drive.guard.title'),
			text: [t('drive.guard.text'), parts.join(' · ')].filter(Boolean).join(' '),
			sample,
			more: Math.max(0, files - sample.length),
			portal: !!g.portal,
		};
	}

	/** The toast after queueing uploads with folders: "2 Ordner, 37 Dateien …" (null without folders). */
	function folderQueuedText(r, t) {
		if (!r || !r.ok || !r.folders) return null;
		const parts = [plural(t, 'drive.upload.folders', r.folders), plural(t, 'drive.upload.files', (r.queued || []).length)];
		if (r.skipped) parts.push(plural(t, 'drive.upload.skipped', r.skipped));
		return t('drive.upload.folderQueued', { what: parts.join(', ') });
	}

	// ── Links ────────────────────────────────────────────

	/** Modes a node can be shared with: files view / download, folders also upload. */
	function linkModes(node) {
		return node && node.isDir ? ['view', 'download', 'upload'] : ['view', 'download'];
	}

	function pinOk(pin) {
		const s = str(pin).trim();
		return s === '' || PIN_RE.test(s);
	}

	/** The link dialog's draft → the body for drive.createLink(), or null when not valid. */
	function linkRequest(node, draft) {
		const d = draft || {};
		if (!node || !Number.isSafeInteger(node.id)) return null;
		if (!linkModes(node).includes(d.mode) || !LINK_EXPIRES.includes(d.expires) || !pinOk(d.pin)) return null;
		const pin = str(d.pin).trim();
		return { nodeId: node.id, mode: d.mode, expires: d.expires, ...(pin ? { pin } : {}) };
	}

	/** A link in a list: { token, url, title, meta, active, state } */
	function linkView(l, { t, locale, now = Date.now() } = {}) {
		const x = l || {};
		const meta = [t(`drive.link.mode.${['view', 'download', 'upload'].includes(x.mode) ? x.mode : 'view'}`)];
		if (x.active) meta.push(Number.isFinite(x.expiresAt) ? t('drive.link.until', { date: when(x.expiresAt, now, locale, t) }) : t('drive.link.endless'));
		else meta.push(t(x.endedWhy === 'moved' ? 'drive.link.endedMoved' : x.endedWhy === 'trashed' ? 'drive.link.endedTrashed' : 'drive.link.ended'));
		if (x.pin) meta.push(t('drive.link.withPin'));
		meta.push(t('drive.link.stats', { opens: x.opens || 0, downloads: x.downloads || 0 }));
		return { token: x.token, url: x.url || '', title: str(x.name) || str(x.path) || '—', meta: meta.join(' · '), active: !!x.active };
	}

	// ── Transfers ────────────────────────────────────────

	/** A row of the transfer list → { id, name, pct, text, cls, conflict, done, path } */
	function transferView(r, t, locale) {
		const x = r || {};
		const total = Number(x.total) || 0;
		const sent = Math.min(total, Number(x.sent) || 0);
		const pct = total > 0 ? Math.round((sent / total) * 100) : (x.state === 'done' || x.state === 'same' ? 100 : 0);
		let text;
		let cls = '';
		switch (x.state) {
			case 'queued': text = t('drive.transfer.queued'); break;
			case 'running': text = x.folder ? t('drive.transfer.folderMaking') : total ? t('drive.transfer.progress', { sent: formatBytes(sent, locale), total: formatBytes(total, locale) }) : t('drive.transfer.running'); break;
			case 'conflict': text = t('drive.transfer.conflict'); cls = 'is-warn'; break;
			case 'done': text = x.folder ? plural(t, 'drive.transfer.folderDone', x.files || 0) : t(x.dir === 'down' ? 'drive.transfer.loaded' : 'drive.transfer.done'); cls = 'is-ok'; break;
			case 'same': text = t('drive.transfer.same'); cls = 'is-ok'; break;
			case 'skipped': text = t('drive.transfer.skipped'); break;
			case 'failed': text = t('drive.transfer.failed', { reason: errorText({ code: x.code }, t) }); cls = 'is-err'; break;
			default: text = '';
		}
		return {
			id: x.id, name: str(x.name), dir: x.dir === 'down' ? 'down' : 'up', pct, text, cls,
			conflict: x.state === 'conflict', active: x.state === 'queued' || x.state === 'running', path: x.path || null,
		};
	}

	/** "2 von 5 hochgeladen" while uploads run, else null. */
	function transfersSummary(rows, t) {
		const ups = (Array.isArray(rows) ? rows : []).filter((r) => r.dir === 'up');
		if (!ups.some((r) => r.state === 'queued' || r.state === 'running')) return null;
		const done = ups.filter((r) => ['done', 'same', 'skipped', 'failed'].includes(r.state)).length;
		return t('drive.transfer.summary', { done, total: ups.length });
	}

	// ── Folder picker ("In Drive speichern", "Verschieben") ──

	/** Writable areas only (archived team folders and read-only child folders drop out). */
	function writableAreas(areas) {
		return sortAreas((Array.isArray(areas) ? areas : []).filter((a) => a && a.writable && !a.archived));
	}

	/**
	 * Where the picker starts: the folder last picked (checked by the caller:
	 * it must still load and be writable) or the list of areas (null).
	 */
	function pickerStart(lastFolderId) {
		return Number.isSafeInteger(lastFolderId) && lastFolderId > 0 ? lastFolderId : null;
	}

	/** May the picker take this folder (its own root for "Verschieben" excluded by the caller; never a vault folder)? */
	function canPick(folder) {
		return !!(folder && folder.writable && !(folder.node && folder.node.encrypted));
	}

	/** Subfolders of a folder the picker shows (not `exclude`, e.g. the node being moved). */
	function pickerFolders(folder, exclude) {
		// vault folders (Drive 1.9) take nothing from outside: not offered
		return (folder && Array.isArray(folder.items) ? folder.items : []).filter((n) => n && n.isDir && n.id !== exclude && !n.encrypted);
	}

	/** "Meine Dateien › Belege" of a folder in the picker. */
	function pickerPath(folder, area, t) {
		return crumbs(folder, area, t).map((c) => c.name).join(' › ');
	}

	// ── "In Drive speichern" in the other pages ──────────

	/** A chat message whose file can go into Drive (Messenger 1.10, `integrations.drive`). */
	function chatCanSave(m, me) {
		if (!m || m.pending || !m.media || !['image', 'voice', 'file'].includes(m.kind)) return false;
		return !!(me && me.integrations && me.integrations.drive === true);
	}

	/** "Gespeichert in Meine Dateien › Messenger › Foto.jpg" */
	function savedText(saved, t) {
		const s = saved || {};
		if (s.where) return t('drive.save.done', { where: s.where });
		return s.name ? t('drive.save.doneName', { name: s.name }) : t('drive.save.doneShort');
	}

	// ── Errors ───────────────────────────────────────────

	const CODES = {
		offline: 'offline', network: 'offline', timeout: 'offline', not_configured: 'offline',
		no_seat: 'noSeat', not_licensed: 'notLicensed', quota: 'quota', forbidden: 'forbidden',
		drive_unavailable: 'unavailable', unavailable: 'unavailable', rate_limited: 'rateLimited', http_429: 'rateLimited',
		exists: 'exists', invalid_name: 'name', invalid: 'invalid', not_found: 'notFound', conflict: 'exists',
		links_disabled: 'linksDisabled', no_unlimited: 'noUnlimited', no_public_url: 'noPublicUrl',
		unsafe: 'unsafe', open_failed: 'openFailed', upload_invalid: 'uploadInvalid', too_large: 'tooLarge',
		missing: 'missing', folder: 'folder', login_required: 'forbidden', drive_needs_files: 'needsFiles',
		http_404: 'notFound', http_403: 'forbidden', http_507: 'quota', SCHULE_ATTACHMENT_NOT_FOUND: 'notFound',
		SCHULE_MESSAGE_NOT_FOUND: 'notFound', SCHULE_ATTACHMENT_TOO_LARGE: 'tooLarge', SCHULE_UNTIS_UNAVAILABLE: 'schoolOffline',
		SCHULE_ATTACHMENT_FAILED: 'schoolOffline', empty_file: 'emptyFile', in_drive: 'inDrive',
		device_locked: 'locked', guard_locked: 'locked', unsupported: 'unsupported',
		// Drive 1.8 / 1.9
		feature_off: 'featureOff', encrypted: 'encrypted', office_unavailable: 'officeUnavailable',
		vault_locked: 'vaultLocked', vault_unsupported: 'vaultUnsupported', recovery_key: 'recoveryKey', safety: 'safety',
		stale_key: 'staleKey', vault_decrypt: 'vaultDecrypt', vault_invalid: 'vaultDecrypt', recovery_required: 'recoveryRequired',
	};

	/** The text of a failed answer ({ ok: false, code }) — Drive's codes and those of the plugins passing them on. */
	function errorText(res, t) {
		const code = res && typeof res.code === 'string' ? res.code : 'failed';
		const key = CODES[code];
		return key ? t(`drive.err.${key}`) : t('drive.err.generic', { code });
	}

	return {
		APP_ROUTE, SORTS, LINK_EXPIRES, CONFLICT_CHOICES,
		plural, extOf, kindOf, badgeOf, formatBytes, when,
		validName, nameError,
		sortAreas, areaLabel, areaHint, usage, currentArea, accessOf,
		crumbs, rowView, sortQuery, actionsFor, officeMode, OFFICE_EXTS, hasPortalLinks, hasFeature,
		localInputValue, parseLocalInput, timeTravelPresets, timeTravelError, longWhen, timeTravelView, timeTravelLinked, timeTravelResultText,
		liveRelevant, throttle, guardView, folderQueuedText,
		linkModes, pinOk, linkRequest, linkView,
		transferView, transfersSummary,
		writableAreas, pickerStart, canPick, pickerFolders, pickerPath,
		chatCanSave, savedText,
		ERROR_CODES: CODES, errorText,
	};
});
