/**
 * GateControl -- "Ordner sichern" view state (renderer, no DOM access)
 *
 * Pure helpers for the part "Ordner sichern" of the page Drive (core
 * DriveSync over window.gatecontrol.drive.sync): the state of the whole and
 * of each folder in words ("Aktuell", "Läuft · 3 von 10 Dateien",
 * "Pausiert", "Wartet: nicht im Heimnetz", "Fehler: …"), the time of the
 * last run, the Windows folders (Desktop, Dokumente, Bilder, Videos, Musik),
 * the "more folders" list, the options of the size and bandwidth selects and
 * the question of a mass delete. Loaded as a plain script before
 * drive-sync-view.js (window.GCDriveSyncState) and required by the node
 * tests (test/drive-sync-state.test.js).
 *
 * `t` is the i18n function (keys drive.sync.* of the app locales).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDriveSyncState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const GB = 1024 * 1024 * 1024;
	const KNOWN = ['desktop', 'documents', 'pictures', 'videos', 'music'];
	const MODES = ['backup', 'sync'];
	// "Upload / Download begrenzen": KB/s, 0 = unbegrenzt
	const RATES = [0, 128, 256, 512, 1024, 2048, 5120, 10240, 25600];
	// "Dateien größer als … auslassen": bytes, 0 = keine Grenze
	const SIZES = [1 * GB, 2 * GB, 5 * GB, 10 * GB, 20 * GB, 50 * GB, 0];
	const REASONS = ['all', 'folder', 'offline', 'unavailable', 'not_home', 'no_vpn', 'other_server', 'folder_missing', 'target_gone',
		'no_seat', 'not_licensed', 'forbidden', 'quota', 'some_failed', 'no_area', 'exists', 'too_many_files', 'mass_delete', 'guard_locked', 'suspect'];

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
	const localeTag = (l) => (l === 'en' ? 'en-GB' : 'de-DE');

	function plural(t, key, n, params) {
		const count = Number(n) || 0;
		return t(`${key}.${count === 1 ? 'one' : 'other'}`, { ...(params || {}), count });
	}

	/** "gerade eben" / "vor 5 Min." / "vor 3 Std." / "am 18.10.2026" */
	function ago(ms, now, locale, t) {
		if (!Number.isFinite(ms) || ms <= 0) return '';
		const s = Math.max(0, Math.round((now - ms) / 1000));
		if (s < 60) return t('drive.sync.ago.now');
		if (s < 3600) return t('drive.sync.ago.min', { n: Math.floor(s / 60) });
		if (s < 86400) return t('drive.sync.ago.hour', { n: Math.floor(s / 3600) });
		return t('drive.sync.ago.date', { date: new Date(ms).toLocaleDateString(localeTag(locale), { day: '2-digit', month: '2-digit', year: 'numeric' }) });
	}

	/** 1,2 GB / 512 KB/s */
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

	function rateLabel(kbs, locale, t) {
		const n = num(kbs);
		if (!n) return t('drive.sync.unlimited');
		if (n >= 1024) return `${(n / 1024).toLocaleString(localeTag(locale), { maximumFractionDigits: 1 })} MB/s`;
		return `${n} KB/s`;
	}

	function sizeLabel(bytes, locale, t) {
		const n = num(bytes);
		if (!n) return t('drive.sync.noLimit');
		return formatBytes(n, locale);
	}

	/** Select options with the current value in it (also when it is not one of the presets). */
	function options(list, current) {
		const out = list.slice();
		const c = num(current);
		if (!out.includes(c)) out.push(c);
		return out.sort((a, b) => (a === 0 ? 1 : b === 0 ? -1 : a - b));
	}

	function reasonText(reason, t) {
		const r = str(reason);
		if (REASONS.includes(r)) return t(`drive.sync.reason.${r}`);
		return t('drive.sync.reason.generic', { code: r || '?' });
	}

	/**
	 * A folder of DriveSync.status() in words → { name, path, mode, modeText, target, cls, text, detail, pct, busy }
	 * cls: 'ok' | 'run' | 'pause' | 'warn' | 'err' | 'ask'
	 */
	function folderView(f, { t, locale, now }) {
		const v = {
			id: f.id,
			name: str(f.name) || str(f.path),
			path: str(f.path),
			mode: MODES.includes(f.mode) ? f.mode : 'backup',
			target: str(f.target && f.target.label),
			cls: 'ok',
			text: '',
			detail: [],
			pct: null,
			busy: false,
		};
		v.modeText = t(`drive.sync.mode.${v.mode}`);
		const last = ago(f.lastSyncAt, now, locale, t);
		switch (f.state) {
			case 'syncing': {
				v.cls = 'run';
				v.busy = true;
				const total = num(f.total);
				if (total > 0) {
					v.text = t('drive.sync.state.running', { done: Math.min(num(f.done), total), total });
					const cur = f.current;
					const part = cur && num(cur.total) > 0 ? Math.min(1, num(cur.sent) / num(cur.total)) : 0;
					v.pct = Math.round(((Math.min(num(f.done), total) + part) / total) * 100);
				} else {
					v.text = t('drive.sync.state.checking');
				}
				if (f.current && f.current.name) v.detail.push(str(f.current.name));
				break;
			}
			case 'paused':
				v.cls = 'pause';
				v.text = t(f.reason === 'all' ? 'drive.sync.state.pausedAll' : 'drive.sync.state.paused');
				break;
			case 'waiting':
				v.cls = 'warn';
				v.text = t('drive.sync.state.waiting', { reason: reasonText(f.reason, t) });
				break;
			case 'confirm':
				v.cls = 'ask';
				v.text = t(f.reason === 'suspect' ? 'drive.sync.state.suspect' : 'drive.sync.state.confirm');
				break;
			case 'locked':
				v.cls = 'err';
				v.text = t('drive.sync.state.locked');
				break;
			case 'error':
				v.cls = 'err';
				if (f.reason === 'some_failed') {
					v.text = plural(t, 'drive.sync.state.failed', f.failed);
					if (f.failure && f.failure.name) v.detail.push(t('drive.sync.failure', { name: str(f.failure.name), code: str(f.failure.code) }));
				} else {
					v.text = t('drive.sync.state.error', { reason: reasonText(f.reason, t) });
				}
				break;
			default:
				v.text = last ? t('drive.sync.state.idleSince', { when: last }) : t('drive.sync.state.idle');
		}
		if (f.state !== 'idle' && last) v.detail.push(t('drive.sync.last', { when: last }));
		if (num(f.files) > 0 && f.state !== 'syncing') v.detail.push([plural(t, 'drive.sync.files', f.files), formatBytes(f.bytes, locale)].filter(Boolean).join(' · '));
		if (num(f.pendingDeletes) > 0) {
			// Drive 1.5: Drive deletes them at a known time
			const at = Number.isFinite(f.pendingUntil) && f.pendingUntil > 0 ? new Date(f.pendingUntil).toLocaleDateString(localeTag(locale), { day: '2-digit', month: '2-digit', year: 'numeric' }) : null;
			v.detail.push(at ? plural(t, 'drive.sync.pendingDeletesAt', f.pendingDeletes, { date: at }) : plural(t, 'drive.sync.pendingDeletes', f.pendingDeletes));
		}
		if (num(f.held) > 0) v.detail.push(plural(t, 'drive.sync.held', f.held));
		if (num(f.conflicts) > 0) v.detail.push(plural(t, 'drive.sync.conflicts', f.conflicts));
		if (num(f.skipped) > 0) v.detail.push(plural(t, 'drive.sync.skipped', f.skipped));
		return v;
	}

	/** The pill at the top: { cls, text } */
	function summary(st, { t, locale, now }) {
		if (!st || !Array.isArray(st.folders) || !st.folders.length) return { cls: 'none', text: t('drive.sync.sum.none') };
		const folders = st.folders;
		if (st.state === 'locked' || (st.guard && st.guard.locked)) return { cls: 'err', text: t('drive.sync.sum.locked') };
		if (st.paused) return { cls: 'pause', text: t('drive.sync.sum.paused') };
		const ask = folders.filter((f) => f.state === 'confirm').length;
		if (ask) return { cls: 'ask', text: t('drive.sync.sum.confirm') };
		const run = folders.filter((f) => f.state === 'syncing');
		if (run.length) {
			const total = run.reduce((n, f) => n + num(f.total), 0);
			const done = run.reduce((n, f) => n + Math.min(num(f.done), num(f.total)), 0);
			return { cls: 'run', text: total ? t('drive.sync.sum.running', { done, total }) : t('drive.sync.sum.checking') };
		}
		if (folders.some((f) => f.state === 'error')) return { cls: 'err', text: t('drive.sync.sum.error') };
		const wait = folders.find((f) => f.state === 'waiting');
		if (wait) return { cls: 'warn', text: t('drive.sync.sum.waiting', { reason: reasonText(wait.reason, t) }) };
		if (folders.every((f) => f.state === 'paused')) return { cls: 'pause', text: t('drive.sync.sum.paused') };
		const last = ago(st.lastSyncAt, now, locale, t);
		return { cls: 'ok', text: last ? t('drive.sync.sum.okSince', { when: last }) : t('drive.sync.sum.ok') };
	}

	/**
	 * The Windows folders (Desktop, Dokumente, Bilder, Videos, Musik) with their folder of the list
	 * → [{ key, label, path, folder }]
	 */
	function knownRows(st, t) {
		const list = st && Array.isArray(st.known) ? st.known : [];
		const folders = st && Array.isArray(st.folders) ? st.folders : [];
		return KNOWN.map((key) => {
			const k = list.find((x) => x && x.key === key);
			if (!k || !k.path) return null;
			const folder = k.folderId ? folders.find((f) => f.id === k.folderId) || null : null;
			return { key, label: t(`drive.sync.known.${key}`), path: str(k.path), folder };
		}).filter(Boolean);
	}

	/** The folders that are not one of the Windows folders above ("Weitere Ordner"). */
	function otherFolders(st) {
		const folders = st && Array.isArray(st.folders) ? st.folders : [];
		const known = new Set((st && Array.isArray(st.known) ? st.known : []).map((k) => k && k.folderId).filter(Boolean));
		return folders.filter((f) => !known.has(f.id));
	}

	/** The folders waiting for an answer about a mass delete → [{ id, name, count, total }] */
	function confirms(st) {
		const folders = st && Array.isArray(st.folders) ? st.folders : [];
		return folders.filter((f) => f.state === 'confirm' && f.reason !== 'suspect' && f.confirm).map((f) => ({ id: f.id, name: str(f.name), count: num(f.confirm.count), total: num(f.confirm.total), mode: f.mode, from: f.confirm.from === 'drive' ? 'drive' : 'pc' }));
	}

	/** The folders where many files changed in an unusual way → [{ id, name, count, sample, why }] */
	function suspects(st) {
		const folders = st && Array.isArray(st.folders) ? st.folders : [];
		return folders.filter((f) => f.state === 'confirm' && f.reason === 'suspect' && f.suspect).map((f) => ({
			id: f.id, name: str(f.name), count: num(f.suspect.count),
			sample: (Array.isArray(f.suspect.sample) ? f.suspect.sample : []).map(str).filter(Boolean).slice(0, 5),
			why: f.suspect.why === 'extension' ? 'extension' : 'entropy',
		}));
	}

	/** Can the dialog "Ordner hinzufügen" add? { ok, code } */
	function addCheck(draft) {
		const d = draft || {};
		if (!d.path) return { ok: false, code: 'path' };
		if (!MODES.includes(d.mode)) return { ok: false, code: 'mode' };
		if (d.mode === 'sync' && !(Number.isSafeInteger(d.targetId) && d.targetId > 0)) return { ok: false, code: 'target' };
		return { ok: true, code: null };
	}

	/** The error text of a failed call (drive.sync.err.* first, then Drive's own texts). */
	function errorText(r, t) {
		const code = str(r && r.code);
		const own = ['overlap', 'in_drive', 'folder_missing', 'not_a_folder', 'drive_root', 'too_many', 'target_taken', 'forbidden', 'no_home', 'no_network', 'invalid', 'offline', 'network', 'timeout', 'not_found'];
		if (own.includes(code)) return t(`drive.sync.err.${code === 'network' || code === 'timeout' ? 'offline' : code}`);
		return t('drive.sync.err.generic', { code: code || '?' });
	}

	return {
		KNOWN,
		MODES,
		RATES,
		SIZES,
		GB,
		ago,
		formatBytes,
		rateLabel,
		sizeLabel,
		options,
		reasonText,
		folderView,
		summary,
		knownRows,
		otherFolders,
		confirms,
		suspects,
		addCheck,
		errorText,
	};
});
