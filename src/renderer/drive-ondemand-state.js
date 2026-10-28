/**
 * GateControl -- "Dateien bei Bedarf" view state (renderer, no DOM access)
 *
 * Pure helpers for the card "GateControl Drive im Explorer" on top of
 * "Ordner sichern" (gc-drive-sync over window.gatecontrol.driveOnDemand):
 * the state in words ("Aktuell", "Lädt 2 Dateien", "Pausiert", "Fehler: …"),
 * the space on this PC, the question after a mass delete, the Windows folders
 * that can be moved into the Drive and the lock between moving a folder and
 * backing it up with "Ordner sichern" (W2), progress of moving / putting back,
 * and the texts of failed calls. Loaded as a plain script before
 * drive-ondemand-view.js (window.GCDriveOnDemandState) and required by the
 * node tests (test/drive-ondemand-state.test.js).
 *
 * `t` is the i18n function (keys drive.od.* of the app locales).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDriveOnDemandState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const KNOWN = ['desktop', 'documents', 'pictures', 'videos', 'music'];
	const ERRORS = ['relocated', 'unsynced', 'not_running', 'w2_active', 'already_relocated', 'not_relocated', 'move_failed', 'set_failed',
		'hydrate_failed', 'revert_failed', 'target_taken', 'folder_missing', 'read_only', 'no_area', 'offline', 'busy', 'disabled', 'unsupported',
		'known_folder', 'contains_root', 'timeout', 'not_synced', 'launch', 'wrong_user'];
	const REASONS = ['network', 'timeout', 'forbidden', 'quota', 'read_only', 'outside_area', 'name_unsupported', 'empty_file', 'mass_delete',
		'local_io', 'hydrate', 'dehydrate', 'register_failed', 'connect_failed', 'watch_failed', 'exited', 'launch', 'wrong_user', 'unauthorized'];

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
	const localeTag = (l) => (l === 'en' ? 'en-GB' : 'de-DE');

	function plural(t, key, n, params) {
		const count = Number(n) || 0;
		return t(`${key}.${count === 1 ? 'one' : 'other'}`, { ...(params || {}), count });
	}

	/** 1,2 GB */
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

	function reasonText(code, t) {
		const c = str(code);
		if (/^http_\d+$/.test(c)) return t('drive.od.reason.http', { code: c.slice(5) });
		if (REASONS.includes(c)) return t(`drive.od.reason.${c}`);
		return t('drive.od.reason.generic', { code: c || '?' });
	}

	/**
	 * The state of the whole → { cls, text, detail, on, busy }
	 * cls: 'off' | 'ok' | 'run' | 'pause' | 'warn' | 'err' | 'ask'
	 */
	function summary(s, { t }) {
		const st = s || {};
		const out = { cls: 'off', text: '', detail: [], on: st.enabled === true, busy: !!st.busy };
		if (st.supported === false && st.state !== 'disabled') {
			out.text = t(st.state === 'missing' ? 'drive.od.state.missing' : 'drive.od.state.unsupported');
			return out;
		}
		if (!out.on) {
			out.text = t('drive.od.state.off');
			return out;
		}
		const errs = Array.isArray(st.errors) ? st.errors : [];
		if (st.busy) {
			out.cls = 'run';
			out.text = busyText(st, t);
		} else if (st.locked || st.state === 'locked') {
			// Drive 1.6 guard: Drive hat das Gerät gestoppt
			out.cls = 'err';
			out.text = t('drive.od.state.locked');
		} else if (st.suspect || st.state === 'suspect') {
			out.cls = 'ask';
			out.text = t('drive.od.state.suspect');
		} else if (st.massDelete) {
			out.cls = 'ask';
			out.text = t('drive.od.state.ask');
		} else {
			switch (st.state) {
				case 'starting': out.cls = 'run'; out.text = t('drive.od.state.starting'); break;
				case 'syncing': out.cls = 'run'; out.text = t('drive.od.state.syncing'); break;
				case 'paused': out.cls = 'pause'; out.text = t('drive.od.state.paused'); break;
				case 'offline': out.cls = 'warn'; out.text = t('drive.od.state.offline'); break;
				case 'error':
				case 'unconfigured':
				case 'launch': {
					out.cls = 'err';
					const e = errs[errs.length - 1];
					out.text = st.state === 'unconfigured' ? t('drive.od.state.unconfigured') : t('drive.od.state.error', { reason: reasonText(e && e.code, t) });
					break;
				}
				case 'idle': out.cls = 'ok'; out.text = t('drive.od.state.idle'); break;
				case 'disabled': out.cls = 'run'; out.text = t('drive.od.state.starting'); break;
				default: out.cls = 'run'; out.text = t('drive.od.state.starting');
			}
		}
		const n = num(st.transferring);
		if (n > 0 && out.cls !== 'err') {
			out.cls = out.cls === 'ok' ? 'run' : out.cls;
			if (st.state === 'idle' && !st.busy && !st.massDelete) out.text = plural(t, 'drive.od.state.loading', n);
			else out.detail.push(plural(t, 'drive.od.state.loading', n));
		}
		if (num(st.pending) > 0) out.detail.push(plural(t, 'drive.od.pending', st.pending));
		if (num(st.held) > 0) out.detail.push(plural(t, 'drive.sync.held', st.held));
		// Fehler einzelner Dateien (mit Pfad) – die ersten zwei
		for (const e of errs.filter((x) => x && x.path && x.code !== 'mass_delete').slice(-2)) {
			out.detail.push(t('drive.od.fileError', { name: baseName(e.path), reason: reasonText(e.code, t) }));
		}
		if (st.elevated) out.detail.push(t('drive.od.elevated'));
		return out;
	}

	function baseName(p) {
		const s = str(p).replace(/[\\/]+$/, '');
		const i = Math.max(s.lastIndexOf('\\'), s.lastIndexOf('/'));
		return i >= 0 ? s.slice(i + 1) : s;
	}

	function busyText(st, t) {
		const b = st.busy || {};
		const p = st.progress;
		const folder = b.folder ? t(`drive.sync.known.${b.folder}`) : '';
		if (b.kind === 'disable') return t('drive.od.busy.disable');
		const key = b.kind === 'restore' ? (p && p.phase === 'load' ? 'drive.od.busy.restoreLoad' : 'drive.od.busy.restore') : 'drive.od.busy.relocate';
		const base = t(key, { name: folder });
		return p && num(p.total) > 0 ? `${base} · ${t('drive.od.busy.progress', { done: Math.min(num(p.done), num(p.total)), total: num(p.total) })}` : base;
	}

	/** Progress 0…100 or null */
	function progressPct(st) {
		const p = st && st.progress;
		if (!st || !st.busy || !p || num(p.total) <= 0) return null;
		return Math.round((Math.min(num(p.done), num(p.total)) / num(p.total)) * 100);
	}

	/** "Auf diesem PC 3,2 GB · Im Drive 184 GB" → { local, total, text } */
	function usageText(u, { t, locale }) {
		if (!u || typeof u !== 'object') return null;
		return {
			local: formatBytes(u.localBytes, locale),
			total: formatBytes(u.totalBytes, locale),
			text: t('drive.od.usage.text', { local: formatBytes(u.localBytes, locale), total: formatBytes(u.totalBytes, locale), files: num(u.localFiles) }),
		};
	}

	/** The question after a mass delete → { files, offline, sample } | null */
	function massDelete(st) {
		const m = st && st.massDelete;
		if (!m) return null;
		return { files: num(m.files), items: num(m.items), offline: m.offline === true, sample: (Array.isArray(m.sample) ? m.sample : []).map(baseName).slice(0, 3) };
	}

	/** The question after the local ransomware check → { count, sample, why } | null */
	function suspect(st) {
		const m = st && st.suspect;
		if (!m) return null;
		return { count: num(m.count), sample: (Array.isArray(m.sample) ? m.sample : []).map(baseName).filter(Boolean).slice(0, 5), why: m.why === 'extension' ? 'extension' : 'entropy' };
	}

	/** Paths overlap (one in the other, Windows paths, case-insensitive)? */
	function overlaps(a, b) {
		const norm = (x) => str(x).replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();
		const x = norm(a);
		const y = norm(b);
		if (!x || !y) return false;
		return x === y || x.startsWith(`${y}\\`) || y.startsWith(`${x}\\`);
	}

	/**
	 * The Windows folders with what can be done:
	 * → [{ key, label, path, inDrive, from, canMove, canRestore, lock: 'w2' | 'busy' | 'off' | null }]
	 * `known`: answer of knownFolders(); `sync`: DriveSync.status() of W2 (folders with path).
	 */
	function knownRows(known, sync, st, t) {
		const list = known && Array.isArray(known.folders) ? known.folders : [];
		const w2 = sync && Array.isArray(sync.folders) ? sync.folders : [];
		const running = !!(st && st.enabled && st.running !== false && st.state !== 'error' && st.state !== 'unconfigured');
		return KNOWN.map((key) => {
			const k = list.find((x) => x && x.key === key);
			if (!k || !k.path) return null;
			const inDrive = k.inDrive === true;
			const backedUp = !inDrive && w2.some((f) => f && f.path && overlaps(f.path, k.path));
			let lock = null;
			if (st && st.busy) lock = 'busy';
			else if (!running) lock = 'off';
			else if (backedUp) lock = 'w2';
			return {
				key,
				label: t(`drive.sync.known.${key}`),
				path: str(k.path),
				from: str(k.from),
				inDrive,
				lock,
				canMove: !inDrive && !lock,
				canRestore: inDrive && (!lock || lock === 'w2'),
				working: !!(st && st.busy && st.busy.folder === key),
			};
		}).filter(Boolean);
	}

	/**
	 * For "Ordner sichern" (W2): is this Windows folder locked because it lies in
	 * the Drive (moved)? → reason key or null
	 */
	function w2Lock(knownPath, known) {
		const list = known && Array.isArray(known.folders) ? known.folders : [];
		const k = list.find((x) => x && x.inDrive && overlaps(x.path, knownPath));
		if (k) return 'drive.od.known.lockedForW2';
		const root = known && known.syncRoot;
		if (root && overlaps(knownPath, root)) return 'drive.od.known.lockedForW2';
		return null;
	}

	/** Text of a failed call (drive.od.err.*). */
	function errorText(r, t) {
		const code = str(r && r.code);
		if (code === 'unsynced') {
			const n = num(r && r.data && r.data.count);
			return plural(t, 'drive.od.err.unsynced', n || 1);
		}
		if (code === 'network') return t('drive.od.err.offline');
		if (ERRORS.includes(code)) return t(`drive.od.err.${code}`);
		return t('drive.od.err.generic', { code: code || '?' });
	}

	/** Paths of an `unsynced` answer (file names, at most `max`). */
	function unsyncedList(r, max = 5) {
		const paths = r && r.data && Array.isArray(r.data.paths) ? r.data.paths : [];
		return paths.slice(0, max).map(str);
	}

	return {
		KNOWN,
		formatBytes,
		reasonText,
		summary,
		progressPct,
		usageText,
		massDelete,
		suspect,
		overlaps,
		knownRows,
		w2Lock,
		errorText,
		unsyncedList,
		baseName,
	};
});
