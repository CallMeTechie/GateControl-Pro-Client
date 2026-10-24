/**
 * GateControl -- Vault view state (renderer, no DOM access)
 *
 * Pure helpers for the page "Vault" (plugin gatecontrol-vault, the end-to-end
 * encrypted password manager) and its quick search window (Strg+Alt+P):
 * the fields of the six entry types, list filters and sections, the quick
 * search ranking and its keys, letter avatars, header / footer texts, the
 * edit draft (entry JSON v1 ↔ form), strength, error texts, emergency access
 * texts, roles, the import summary and where a push message leads. Loaded as
 * a plain script before vault-view.js / vault-quick.js (window.GCVaultState)
 * and required by the node tests (test/vault-state.test.js).
 *
 * Inputs are what window.gatecontrol.vault returns (core VaultService: lists
 * carry titles, user names and metadata — no secrets); `t` is the i18n
 * function (keys vault.* of the app locales). The same file is used by Pro
 * and Community.
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCVaultState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const TYPES = ['login', 'totp', 'note', 'card', 'wifi', 'identity'];
	const ROLES = ['read', 'write', 'manage'];
	const AUTO_LOCK = [0, 1, 5, 15, 60];
	const WAIT_CHOICES = [24, 48, 168, 336, 720];
	const APP_ROUTE = 'plg-gatecontrol-vault';
	const TOPIC_PREFIX = 'plugin:gatecontrol-vault:';
	const PUSH_TOPICS = ['share', 'emergency'];
	const PUSH_EVENTS = ['shared', 'requested', 'denied', 'granted', 'released'];
	const ID_RE = /^[A-Za-z0-9_-]{16,40}$/;
	const EMERGENCY_ID_RE = /^[0-9a-f]{24}$/;
	const MIN_MASTER = 12;
	const MAX_IMPORT_BYTES = 20 * 1024 * 1024;

	/**
	 * Fields per type, in the order of the detail page and the edit form
	 * (entry JSON v1, core utils/vault.js normalizeEntry). secret: masked,
	 * revealed only on request; multiline: a text area.
	 */
	const FIELDS = {
		login: [{ key: 'username' }, { key: 'password', secret: true }, { key: 'totp', secret: true, totp: true }],
		totp: [{ key: 'totp', secret: true, totp: true }],
		note: [],
		card: [{ key: 'holder' }, { key: 'number', secret: true }, { key: 'expiry' }, { key: 'cvc', secret: true }, { key: 'pin', secret: true }],
		wifi: [{ key: 'ssid' }, { key: 'password', secret: true }, { key: 'security' }],
		identity: [{ key: 'name' }, { key: 'email' }, { key: 'phone' }, { key: 'address', multiline: true }, { key: 'birthday' }],
	};

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const pad = (n) => String(n).padStart(2, '0');
	const localeTag = (locale) => (locale === 'en' ? 'en-GB' : 'de-DE');
	const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

	/** t() of a counted text: `${key}.one` / `${key}.other` with {{ count }}. */
	function plural(t, key, n) {
		const count = Number(n) || 0;
		return t(`${key}.${count === 1 ? 'one' : 'other'}`, { count });
	}

	// ── Avatars ──────────────────────────────────────────────

	/** First letter or digit of a title, upper case ('#' without one). */
	function letter(title) {
		const m = /[\p{L}\p{N}]/u.exec(str(title));
		return m ? m[0].toLocaleUpperCase('de-DE') : '#';
	}

	/** Java's String.hashCode (the Android app picks the same tone). */
	function hashCode(s) {
		let h = 0;
		for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
		return h;
	}

	/** One of five tones (0 blue, 1 red, 2 green, 3 amber, 4 violet) by title. */
	function tone(title) {
		const h = hashCode(str(title).toLowerCase());
		return ((h % 5) + 5) % 5;
	}

	// ── Times ────────────────────────────────────────────────

	const msOf = (v) => {
		if (Number.isFinite(v)) return v;
		const ms = Date.parse(str(v));
		return Number.isFinite(ms) ? ms : null;
	};
	const dayKey = (d) => `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;

	/** '07:42' */
	function clockOf(ms) {
		const d = new Date(ms);
		return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
	}

	/** ISO / ms → 'heute 07:42' / 'gestern 18:03' / '20.10.2026'. '' when unknown. */
	function when(v, t, locale, now = Date.now()) {
		const ms = msOf(v);
		if (ms === null) return '';
		const d = new Date(ms);
		const today = new Date(now);
		const yesterday = new Date(now);
		yesterday.setDate(yesterday.getDate() - 1);
		if (dayKey(d) === dayKey(today)) return t('vault.time.today', { time: clockOf(ms) });
		if (dayKey(d) === dayKey(yesterday)) return t('vault.time.yesterday', { time: clockOf(ms) });
		return d.toLocaleDateString(localeTag(locale), { day: '2-digit', month: '2-digit', year: 'numeric' });
	}

	/** Seconds → '4:12'. */
	function minSec(totalSeconds) {
		const s = Math.max(0, Math.ceil(Number(totalSeconds) || 0));
		return `${Math.floor(s / 60)}:${pad(s % 60)}`;
	}

	// ── Header, footer ───────────────────────────────────────

	/** '214 Einträge · 3 Tresore · abgeglichen 07:42' (+ offline / pending). */
	function headerText(t, { entries = 0, vaults = 0, status = null } = {}, locale = 'de', now = Date.now()) {
		const parts = [plural(t, 'vault.head.entries', entries), plural(t, 'vault.head.vaults', vaults)];
		const st = status || {};
		const sync = st.sync || {};
		if (sync.state === 'running') parts.push(t('vault.head.syncing'));
		else if (sync.state === 'offline') parts.push(t('vault.head.offline'));
		else if (sync.state === 'error') parts.push(t('vault.head.syncError'));
		else if (Number.isFinite(st.lastSyncAt)) {
			const ms = st.lastSyncAt;
			const sameDay = dayKey(new Date(ms)) === dayKey(new Date(now));
			parts.push(t('vault.head.synced', { time: sameDay ? clockOf(ms) : when(ms, t, locale, now) }));
		}
		if (st.pending > 0) parts.push(plural(t, 'vault.head.pending', st.pending));
		return parts.join(' · ');
	}

	/**
	 * Footer: 'Vault entsperrt · sperrt in 4:12 min' while unlocked (auto-lock
	 * after the last activity), else 'Vault gesperrt'.
	 */
	function lockText(t, status, lastActivity, now = Date.now()) {
		const st = status || {};
		if (!st.unlocked) return t('vault.foot.locked');
		const m = Number(st.autoLockMinutes);
		if (m === 0) return t('vault.foot.unlockedHidden');
		if (!(m > 0) || !Number.isFinite(lastActivity)) return t('vault.foot.unlocked');
		const left = (m * 60000 - (now - lastActivity)) / 1000;
		return t('vault.foot.unlockedIn', { time: minSec(left) });
	}

	// ── Lists ────────────────────────────────────────────────

	/** Vault names by id ('…' while a name cannot be read). */
	function vaultNames(vaults, t) {
		const out = new Map();
		for (const v of vaults || []) out.set(v.id, v.name || (v.personal && t ? t('vault.vaults.personal') : '…'));
		return out;
	}

	/** Second line of a list row: 'admin · nas.gc.internal' (never a secret). */
	function rowSub(e) {
		const parts = [];
		const sub = str(e && e.subtitle);
		if (sub) parts.push(sub);
		const host = str(e && e.host);
		if (host && host !== sub) parts.push(host);
		return parts.join(' · ');
	}

	const fold = (s) => str(s).toLocaleLowerCase('de-DE').normalize('NFD').replace(/[̀-ͯ]/g, '');

	/** Does a summary match the search text (every word in title, sub, user name, host or a web address)? */
	function matches(e, query) {
		const words = fold(query).split(/\s+/).filter(Boolean);
		if (!words.length) return true;
		const hay = fold([e.title, e.subtitle, e.username, e.host, ...(Array.isArray(e.urls) ? e.urls : []), ...(Array.isArray(e.tags) ? e.tags : [])].join('\n'));
		return words.every((w) => hay.includes(w));
	}

	/** The list of the page: one vault (or all) and the search text. */
	function filterEntries(entries, { vaultId = null, query = '' } = {}) {
		return (entries || []).filter((e) => (!vaultId || e.vaultId === vaultId) && matches(e, query));
	}

	/** Sections: favourites first (when there are some and no search), then all A–Z. */
	function sections(entries, { query = '' } = {}) {
		const list = entries || [];
		const favs = list.filter((e) => e.fav);
		if (!favs.length || str(query).trim()) return [{ key: 'all', items: list }];
		return [{ key: 'favorites', items: favs }, { key: 'all', items: list }];
	}

	/** Filter chips: 'Alle · 214', then each vault with its count. */
	function filterChips(vaults, t) {
		const list = vaults || [];
		const total = list.reduce((n, v) => n + (Number(v.count) || 0), 0);
		const names = vaultNames(list, t);
		return [{ id: null, label: t('vault.filter.count', { name: t('vault.filter.all'), count: total }) }]
			.concat(list.map((v) => ({ id: v.id, label: t('vault.filter.count', { name: names.get(v.id), count: Number(v.count) || 0 }) })));
	}

	// ── Quick search (Strg+Alt+P) ────────────────────────────

	/** Ranked hits: title starts with › a word of the title starts with › title contains › elsewhere; favourites first within. */
	function quickSearch(entries, query, limit = 8) {
		const q = fold(query).trim();
		if (!q) return [];
		const scored = [];
		for (const e of entries || []) {
			if (e.trashed || !matches(e, q)) continue;
			const title = fold(e.title);
			let score = 3;
			if (title.startsWith(q)) score = 0;
			else if (title.split(/[\s\-_.()/]+/).some((w) => w.startsWith(q))) score = 1;
			else if (title.includes(q)) score = 2;
			scored.push({ e, score: score * 2 + (e.fav ? 0 : 1) });
		}
		scored.sort((a, b) => a.score - b.score || str(a.e.title).localeCompare(str(b.e.title), 'de', { sensitivity: 'base' }));
		return scored.slice(0, limit).map((x) => x.e);
	}

	/**
	 * A key in the quick search → its action: 'down', 'up', 'close', 'password'
	 * (Enter), 'username' (Strg+B), 'totp' (Strg+T), 'url' (Strg+O), else null.
	 * k: { key, ctrlKey, altKey, shiftKey, metaKey, isComposing }
	 */
	function quickKey(k) {
		if (!k || k.isComposing) return null;
		const key = str(k.key);
		const mod = !!(k.ctrlKey || k.metaKey);
		if (k.altKey) return null;
		if (!mod && !k.shiftKey) {
			if (key === 'ArrowDown') return 'down';
			if (key === 'ArrowUp') return 'up';
			if (key === 'Escape') return 'close';
			if (key === 'Enter') return 'password';
			return null;
		}
		if (mod && !k.shiftKey) {
			const c = key.toLowerCase();
			if (c === 'b') return 'username';
			if (c === 't') return 'totp';
			if (c === 'o') return 'url';
			if (c === 'n' || key === 'ArrowDown') return 'down';
			if (c === 'p' || key === 'ArrowUp') return 'up';
		}
		if (k.shiftKey && !mod && key === 'Tab') return 'up';
		return null;
	}

	/**
	 * What an action does with a hit: { kind: 'copy', field } | { kind: 'open', url }
	 * | null (the hit has nothing for it). Enter copies the password, a 2FA-only
	 * entry its code, otherwise the user name.
	 */
	function quickCommand(action, hit) {
		if (!hit) return null;
		const url = Array.isArray(hit.urls) ? hit.urls.map(openableUrl).find(Boolean) : null;
		switch (action) {
			case 'password':
				if (hit.hasPassword) return { kind: 'copy', field: 'password' };
				if (hit.hasTotp) return { kind: 'copy', field: 'totp' };
				if (hit.username) return { kind: 'copy', field: 'username' };
				return null;
			case 'username': return hit.username ? { kind: 'copy', field: 'username' } : null;
			case 'totp': return hit.hasTotp ? { kind: 'copy', field: 'totp' } : null;
			case 'url': return url ? { kind: 'open', url } : null;
			default: return null;
		}
	}

	/** Selection after 'up' / 'down' (wraps around). */
	function moveSelection(index, action, count) {
		if (!(count > 0)) return 0;
		const i = Number.isInteger(index) ? index : 0;
		if (action === 'down') return (i + 1) % count;
		if (action === 'up') return (i - 1 + count) % count;
		return Math.min(Math.max(i, 0), count - 1);
	}

	/** '482913' → '482 913' (8 digits: 4 + 4). */
	function prettyCode(code) {
		const c = str(code);
		if (c.length === 6) return `${c.slice(0, 3)} ${c.slice(3)}`;
		if (c.length === 8) return `${c.slice(0, 4)} ${c.slice(4)}`;
		return c;
	}

	// ── Detail ───────────────────────────────────────────────

	/** Label key of a field. */
	const fieldLabel = (key) => `vault.field.${key}`;

	/**
	 * Rows of the detail page from an entry ({ type, data }) → [{ key, label,
	 * secret, totp, multiline, copy (field name for vault:copy), hasValue }].
	 * Values are not part of the rows: the view reads plain ones from the
	 * entry and shows secret ones only when revealed.
	 */
	function detailRows(entry) {
		const data = (entry && entry.data) || {};
		const fields = isObj(data.fields) ? data.fields : {};
		const type = TYPES.includes(data.type) ? data.type : 'note';
		const rows = [];
		for (const f of FIELDS[type]) {
			if (!str(fields[f.key])) continue;
			rows.push({ key: f.key, label: fieldLabel(f.key), secret: !!f.secret, totp: !!f.totp, multiline: !!f.multiline, copy: f.key });
		}
		// identity: e-mail as user name of the type 'login' is not repeated
		return rows;
	}

	/** Masked text of a secret: dots, at most 14. */
	const mask = (value) => '•'.repeat(Math.min(Math.max(str(value).length, 8), 14));

	/** A card number shown masked: '•••• 1234'. */
	function maskedNumber(value) {
		const n = str(value).replace(/\D/g, '');
		return n.length >= 4 ? `•••• ${n.slice(-4)}` : mask(value);
	}

	/** 'Persönlich · geändert gestern 18:03 auf „Büro-PC“'. */
	function changedText(t, summary, vaultName, locale, now = Date.now()) {
		const w = when(summary && summary.updatedAt, t, locale, now);
		const vault = str(vaultName);
		if (!w) return vault;
		if (summary.device) return t('vault.changed', { vault, when: w, device: summary.device });
		return t('vault.changedShort', { vault, when: w });
	}

	// ── Edit draft ───────────────────────────────────────────

	/** A new entry's draft (title from a 2FA link's label when given). */
	function emptyDraft(type, vaultId) {
		const tp = TYPES.includes(type) ? type : 'login';
		return { id: null, vaultId: vaultId || null, type: tp, title: '', fav: false, notes: '', urls: tp === 'login' ? [''] : [], apps: [], fields: {}, custom: [], extra: {} };
	}

	const KNOWN = new Set(['v', 'type', 'title', 'fav', 'notes', 'urls', 'apps', 'fields', 'custom']);

	/** An entry ({ id, vaultId, data }) → draft (unknown keys kept in `extra`). */
	function draftFrom(entry) {
		const d = (entry && entry.data) || {};
		const extra = {};
		for (const [k, v] of Object.entries(d)) if (!KNOWN.has(k)) extra[k] = v;
		const type = TYPES.includes(d.type) ? d.type : 'login';
		const urls = Array.isArray(d.urls) ? d.urls.map(str) : [];
		return {
			id: entry && entry.id ? entry.id : null,
			vaultId: entry && entry.vaultId ? entry.vaultId : null,
			type,
			title: str(d.title),
			fav: d.fav === true,
			notes: str(d.notes),
			urls: type === 'login' && !urls.length ? [''] : urls,
			apps: Array.isArray(d.apps) ? d.apps.map(str) : [],
			fields: isObj(d.fields) ? Object.fromEntries(Object.entries(d.fields).map(([k, v]) => [k, str(v)])) : {},
			custom: Array.isArray(d.custom) ? d.custom.filter(isObj).map((c) => ({ name: str(c.name), value: str(c.value), secret: c.secret === true })) : [],
			extra,
		};
	}

	/**
	 * Draft → entry JSON v1 for vault:save. Fields of other types stay (a
	 * changed type keeps what it had), empty values and empty custom rows go.
	 */
	function draftToData(draft) {
		const d = draft || emptyDraft('login');
		const fields = {};
		for (const [k, v] of Object.entries(d.fields || {})) {
			const val = str(v);
			if (val.trim() !== '') fields[k] = k === 'totp' ? val.trim() : val;
		}
		const out = { ...(d.extra || {}), v: 1, type: d.type, title: str(d.title).trim() };
		if (d.fav) out.fav = true;
		if (str(d.notes).trim()) out.notes = str(d.notes);
		out.urls = (d.urls || []).map((u) => str(u).trim()).filter(Boolean);
		out.apps = (d.apps || []).map((u) => str(u).trim()).filter(Boolean);
		out.fields = fields;
		out.custom = (d.custom || []).map((c) => ({ name: str(c.name).trim(), value: str(c.value), secret: c.secret === true }))
			.filter((c) => c.name !== '' || c.value !== '');
		return out;
	}

	/** null when the draft can be saved, else the i18n key of what is missing. */
	function draftError(draft) {
		if (!draft || !TYPES.includes(draft.type)) return 'vault.err.invalid';
		if (!str(draft.title).trim()) return 'vault.edit.titleRequired';
		if (!draft.vaultId) return 'vault.err.invalid';
		return null;
	}

	/** Did the person change anything (discard question)? */
	function draftChanged(a, b) {
		return JSON.stringify(draftToData(a)) !== JSON.stringify(draftToData(b)) || str(a && a.vaultId) !== str(b && b.vaultId);
	}

	/** Web address with a scheme for "Öffnen" (https:// added to a bare host), or null. */
	function openableUrl(url) {
		const u = str(url).trim();
		if (!u || /\s/.test(u)) return null;
		if (/^https?:\/\//i.test(u)) return u;
		// a scheme (javascript:, file:, mailto: …) is not opened; 'nas.local:5000' is a host with a port
		if (/^[a-z][a-z0-9+.-]*:(?!\d+(\/|$))/i.test(u)) return null;
		return /^[\w-]+(\.[\w-]+)+(:\d+)?(\/.*)?$/.test(u) ? `https://${u}` : null;
	}

	// ── Strength ─────────────────────────────────────────────

	const STRENGTH = { weak: 1, fair: 2, strong: 3, very_strong: 4 };

	/** vault:strength / vault:generate answer → { level 0–4, cls, label, detail }. */
	function strengthView(res, password, t) {
		const pw = str(password);
		if (!pw || !res || !res.ok) return { level: 0, cls: '', label: '', detail: '' };
		const level = STRENGTH[res.strength] || 1;
		return {
			level,
			cls: ['', 'is-weak', 'is-fair', 'is-strong', 'is-very'][level],
			label: t(`vault.strength.${res.strength in STRENGTH ? res.strength : 'weak'}`),
			detail: Number(res.words) > 1
				? t('vault.strength.detail', { chars: Array.from(pw).length, words: Number(res.words) })
				: t('vault.strength.chars', { chars: Array.from(pw).length }),
		};
	}

	/** Master password form: { ok, hint key } (≥ 12 characters, not weak, both the same). */
	function masterCheck(password, repeat, res) {
		const pw = str(password);
		if (!pw) return { ok: false, hint: null };
		if (Array.from(pw).length < MIN_MASTER || !(res && res.ok && res.good)) return { ok: false, hint: 'vault.setup.pwRule' };
		if (!str(repeat)) return { ok: false, hint: null };
		if (pw !== str(repeat)) return { ok: false, hint: 'vault.setup.pwMismatch' };
		return { ok: true, hint: 'vault.setup.pwMatch' };
	}

	/** 'K7QF-2MXP-…' → ['K7QF', '2MXP', …]. */
	function recoveryGroups(key) {
		return str(key).toUpperCase().split(/[\s-]+/).filter(Boolean);
	}

	/** A typed recovery key with 56 characters (ignoring blanks and dashes)? */
	function recoveryComplete(text) {
		return str(text).replace(/[\s-]/g, '').length === 56;
	}

	// ── Errors ───────────────────────────────────────────────

	const ERROR_KEYS = {
		network: 'vault.err.offline', timeout: 'vault.err.offline', not_configured: 'vault.err.offline', offline: 'vault.err.offline',
		locked: 'vault.err.locked', wrong_password: 'vault.err.wrongPassword', recovery_key: 'vault.err.recoveryKey',
		weak_password: 'vault.err.weakPassword', read_only: 'vault.err.readOnly', forbidden: 'vault.err.forbidden',
		too_large: 'vault.err.tooLarge', last_manager: 'vault.err.lastManager', rekeying: 'vault.err.rekeying',
		limit: 'vault.err.limit', exists: 'vault.err.exists', not_found: 'vault.err.notFound', no_account: 'vault.err.noAccount',
		empty: 'vault.err.empty', unsupported: 'vault.err.unsupported', remember_failed: 'vault.err.rememberFailed',
		not_remembered: 'vault.err.rememberFailed', import_encrypted: 'vault.import.encrypted', import_unknown: 'vault.import.unknown',
		no_import: 'vault.import.unknown', no_setup: 'vault.err.setupGone', conflict: 'vault.err.conflict', invalid: 'vault.err.invalid',
	};

	/** A failed answer ({ ok: false, code }) → one line for the page. */
	function errorText(res, t) {
		const code = str(res && res.code) || 'failed';
		const key = ERROR_KEYS[code];
		return key ? t(key) : t('vault.err.generic', { code });
	}

	// ── Wi-Fi networks nearby (Wi-Fi entries) ────────────────

	const WIFI_SECURITY = ['WPA3', 'WPA2/WPA3', 'WPA2', 'WPA', 'WEP', 'Offen'];
	const WIFI_ERRORS = {
		no_adapter: 'vault.wifi.err.noAdapter', service_off: 'vault.wifi.err.serviceOff', radio_off: 'vault.wifi.err.radioOff',
		location_denied: 'vault.wifi.err.location', failed: 'vault.wifi.err.failed',
	};

	/**
	 * Answer of vault.wifiScan() → what the panel shows:
	 * { kind: 'list', networks } | { kind: 'empty' } | { kind: 'error', code, title, text, settings }
	 * (settings: offer Windows' location settings). Networks keep only well-formed rows.
	 */
	function wifiScanView(res, t) {
		if (!res || res.ok !== true) {
			const code = str(res && res.code) || 'failed';
			const key = WIFI_ERRORS[code];
			return {
				kind: 'error',
				code,
				title: code === 'location_denied' ? t('vault.wifi.err.locationTitle') : null,
				text: key ? t(key) : errorText(res, t),
				settings: code === 'location_denied',
			};
		}
		const networks = (Array.isArray(res.networks) ? res.networks : [])
			.filter((n) => isObj(n) && typeof n.ssid === 'string' && n.ssid !== '')
			.map((n) => ({
				ssid: n.ssid,
				security: WIFI_SECURITY.includes(n.security) ? n.security : '',
				signal: Math.max(0, Math.min(100, Math.round(Number(n.signal) || 0))),
				connected: n.connected === true,
			}));
		return networks.length ? { kind: 'list', networks } : { kind: 'empty' };
	}

	/** Signal 0–100 → arcs of the Wi-Fi icon (0–3). */
	function wifiBars(signal) {
		const s = Number(signal) || 0;
		return s >= 75 ? 3 : s >= 50 ? 2 : s >= 25 ? 1 : 0;
	}

	/** Security for display: 'Offen' in the locale, '' → 'Sicherheit unbekannt'. */
	function wifiSecurityLabel(security, t) {
		if (security === 'Offen') return t('vault.wifi.open');
		return security || t('vault.wifi.unknown');
	}

	/** Second line of a row: 'WPA2 · Signal 78 %'. */
	function wifiRowSub(net, t) {
		return `${wifiSecurityLabel(net && net.security, t)} · ${t('vault.wifi.signal', { percent: (net && net.signal) || 0 })}`;
	}

	/** A picked network → the draft: name, security (when known), title while still empty. */
	function applyWifi(draft, net) {
		if (!draft || !net || !net.ssid) return draft;
		draft.fields = { ...(draft.fields || {}), ssid: net.ssid };
		if (net.security) draft.fields.security = net.security;
		if (!str(draft.title).trim()) draft.title = net.ssid;
		return draft;
	}

	// ── 2FA key from a QR code ("QR-Code scannen") ───────────

	const QR_SOURCES = ['screen', 'clipboard', 'file'];
	const QR_BUSY = { screen: 'vault.qr.busyScreen', clipboard: 'vault.qr.busyClipboard', file: 'vault.qr.busyFile' };
	const QR_NONE = { screen: 'vault.qr.err.noneScreen', clipboard: 'vault.qr.err.noneClipboard', file: 'vault.qr.err.noneFile' };
	const QR_ERRORS = {
		hotp: 'vault.qr.err.hotp', invalid_code: 'vault.qr.err.invalid', no_image: 'vault.qr.err.noImage', failed: 'vault.qr.err.failed',
	};

	const uriPart = (s) => { try { return decodeURIComponent(s); } catch { return s; } };

	/** An otpauth://totp URI → { issuer, account } (issuer parameter, else the label's "Issuer:" prefix). */
	function totpQrInfo(uri) {
		const m = /^otpauth:\/\/totp\/?([^?#]*)(?:\?([^#]*))?/i.exec(str(uri).trim());
		if (!m) return { issuer: '', account: '' };
		const label = uriPart(m[1]);
		let issuer = '';
		for (const kv of str(m[2]).split('&')) {
			const i = kv.indexOf('=');
			if (i > 0 && kv.slice(0, i).toLowerCase() === 'issuer') { issuer = uriPart(kv.slice(i + 1).replace(/\+/g, ' ')).trim(); break; }
		}
		const c = label.indexOf(':');
		return { issuer: issuer || (c >= 0 ? label.slice(0, c).trim() : ''), account: (c >= 0 ? label.slice(c + 1) : label).trim() };
	}

	/** An e-mail address or a user name (no blanks, no ':'), worth putting into an empty user name field. */
	function looksLikeUser(account) {
		const a = str(account).trim();
		return /^[^\s@:]+@[^\s@:]+\.[^\s@:]+$/.test(a) || /^[A-Za-z0-9][\w.+-]{1,63}$/.test(a);
	}

	/** Busy text of a scan. */
	function totpQrBusy(source, t) {
		return t(QR_BUSY[source] || QR_BUSY.screen);
	}

	/**
	 * Answer of vault.totpQr(source) → what the dialog shows:
	 * { kind: 'list', codes: [{ uri, issuer, account, title, sub }] } | { kind: 'error', code, text } | { kind: 'cancelled' }.
	 * Only otpauth://totp URIs are kept (deduplicated); title / sub are for display (textContent only).
	 */
	function totpQrView(res, source, t) {
		const none = () => ({ kind: 'error', code: 'none_found', text: t(QR_NONE[source] || QR_NONE.screen) });
		if (!res || res.ok !== true) {
			const code = str(res && res.code) || 'failed';
			if (code === 'cancelled') return { kind: 'cancelled' };
			if (code === 'none_found') return none();
			if (code === 'unsupported') return { kind: 'error', code, text: t(source === 'file' ? 'vault.qr.err.unsupportedFile' : 'vault.qr.err.unsupportedScreen') };
			const key = QR_ERRORS[code];
			return { kind: 'error', code, text: key ? t(key) : errorText(res, t) };
		}
		const seen = new Set();
		const codes = [];
		for (const u of Array.isArray(res.uris) ? res.uris : []) {
			const uri = str(u).trim();
			if (!/^otpauth:\/\/totp[/?]/i.test(uri) || uri.length > 2048 || seen.has(uri)) continue;
			seen.add(uri);
			const { issuer, account } = totpQrInfo(uri);
			codes.push({ uri, issuer, account, title: issuer || account || t('vault.qr.unnamed'), sub: issuer && account !== issuer ? account : '' });
		}
		return codes.length ? { kind: 'list', codes } : none();
	}

	/**
	 * A picked code → the draft: the whole URI into the 2FA field (digits, period and algorithm stay in it), the
	 * title from issuer / account while empty, for logins the user name from the account while empty (when it looks
	 * like an e-mail address or user name).
	 */
	function applyTotpQr(draft, uri) {
		const u = str(uri).trim();
		if (!draft || !/^otpauth:\/\/totp[/?]/i.test(u)) return draft;
		const { issuer, account } = totpQrInfo(u);
		draft.fields = { ...(draft.fields || {}), totp: u };
		if (!str(draft.title).trim()) draft.title = issuer || account;
		if (draft.type === 'login' && !str(draft.fields.username).trim() && account && account.toLowerCase() !== issuer.toLowerCase() && looksLikeUser(account)) {
			draft.fields.username = account;
		}
		return draft;
	}

	// ── Vaults, roles, people ────────────────────────────────

	const roleLabel = (role) => `vault.role.${ROLES.includes(role) ? role : 'read'}`;
	const roleHint = (role) => `vault.roleHint.${ROLES.includes(role) ? role : 'read'}`;

	/** Vaults the person may save into (writable), personal first. */
	function writableVaults(vaults) {
		return (vaults || []).filter((v) => v.canWrite);
	}

	/** People one can add to a vault: not a member yet; with Vault first, then by name. */
	function candidates(people, members) {
		const inVault = new Set((members || []).map((m) => m.userId));
		return (people || []).filter((p) => !inVault.has(p.id))
			.sort((a, b) => (a.hasVault === b.hasVault ? str(a.name).localeCompare(str(b.name), 'de', { sensitivity: 'base' }) : a.hasVault ? -1 : 1));
	}

	/** 'Oma Ruth' → 'R'. */
	const initial = (name) => letter(name);

	// ── Emergency access ─────────────────────────────────────

	/** 48 → '48 Stunden', 168 → '7 Tage'. */
	function waitText(t, hours) {
		const h = Number(hours) || 0;
		if (h >= 48 && h % 24 === 0) return plural(t, 'vault.em.days', h / 24);
		return plural(t, 'vault.em.hours', h);
	}

	/** Time until `releaseAt` → '41 Std. 12 Min.' ('0 Std. 0 Min.' when past). */
	function remainingText(t, releaseAt, now = Date.now()) {
		const ms = msOf(releaseAt);
		const left = ms === null ? 0 : Math.max(0, ms - now);
		const min = Math.floor(left / 60000);
		return t('vault.em.remaining', { hours: Math.floor(min / 60), minutes: min % 60 });
	}

	const emStatusKey = (status) => `vault.em.status.${['ready', 'requested', 'granted'].includes(status) ? status : 'ready'}`;

	// ── Import ───────────────────────────────────────────────

	/** vault:import:parse answer → chips ['172 Logins', '21 mit 2FA', …] (zero counts left out). */
	function importChips(t, counts) {
		const c = counts || {};
		const out = [];
		for (const [k, key] of [['logins', 'vault.import.logins'], ['withTotp', 'vault.import.totp'], ['notes', 'vault.import.notes'], ['cards', 'vault.import.cards']]) {
			if (Number(c[k]) > 0) out.push(plural(t, key, Number(c[k])));
		}
		return out;
	}

	/** Entries that would be saved (duplicates skipped). */
	const importCount = (res) => Math.max(0, (Number(res && res.counts && res.counts.total) || 0) - (Number(res && res.duplicates) || 0));

	// ── Settings ─────────────────────────────────────────────

	/** Auto-lock choices as labels. */
	function autoLockChoices(t, choices) {
		return (Array.isArray(choices) && choices.length ? choices : AUTO_LOCK).map((m) => ({
			minutes: m,
			label: m === 0 ? t('vault.settings.autoLockNow') : plural(t, 'vault.settings.autoLockAfter', m),
		}));
	}

	// ── Push ─────────────────────────────────────────────────

	/**
	 * Where a Vault push (vault:push, or the context of a toast click) leads:
	 * { page: 'emergency' | 'vault' | 'home', vaultId, emergencyId }.
	 */
	function pushTarget(ctx) {
		const c = isObj(ctx) ? ctx : {};
		const vaultId = ID_RE.test(str(c.vaultId)) ? c.vaultId : null;
		const emergencyId = EMERGENCY_ID_RE.test(str(c.emergencyId)) ? c.emergencyId : null;
		if (c.page === 'emergency' || c.topic === 'emergency') return { page: 'emergency', vaultId: null, emergencyId };
		if (c.topic === 'share' && vaultId) return { page: 'vault', vaultId, emergencyId: null };
		return { page: 'home', vaultId, emergencyId: null };
	}

	/** An inbox entry from Vault → push context (like core utils/vault.js pushContext), else null. */
	function entryContext(n) {
		if (!isObj(n)) return null;
		const topic = str(n.topic);
		const data = isObj(n.data) ? n.data : {};
		if (!topic.startsWith(TOPIC_PREFIX) && data.route !== APP_ROUTE) return null;
		const v = isObj(data.vault) ? data.vault : {};
		const fromTopic = topic.startsWith(TOPIC_PREFIX) ? topic.slice(TOPIC_PREFIX.length) : '';
		const tp = PUSH_TOPICS.includes(fromTopic) ? fromTopic : PUSH_TOPICS.includes(v.topic) ? v.topic : null;
		return {
			topic: tp,
			event: PUSH_EVENTS.includes(v.event) ? v.event : null,
			vaultId: ID_RE.test(str(v.vault)) ? v.vault : null,
			emergencyId: EMERGENCY_ID_RE.test(str(v.emergency)) ? v.emergency : null,
			page: tp === 'emergency' ? 'emergency' : 'home',
		};
	}

	/** Screen of the page from status(): what the person sees first. */
	function gate(status) {
		const st = status || {};
		if (st.state === 'unavailable') return 'unavailable';
		if (st.state !== 'available') return st.state === 'error' ? 'error' : 'loading';
		if (st.setupPending) return 'setup';
		if (st.account === 'none') return 'intro';
		if (st.account !== 'ready') return 'loading';
		if (!st.unlocked) return 'unlock';
		if (st.recovering) return 'newpw';
		return 'home';
	}

	return {
		TYPES, ROLES, AUTO_LOCK, WAIT_CHOICES, FIELDS, APP_ROUTE, MIN_MASTER, MAX_IMPORT_BYTES,
		plural, letter, tone, hashCode, when, clockOf, minSec, headerText, lockText,
		vaultNames, rowSub, matches, filterEntries, sections, filterChips,
		quickSearch, quickKey, quickCommand, moveSelection, prettyCode,
		fieldLabel, detailRows, mask, maskedNumber, changedText,
		emptyDraft, draftFrom, draftToData, draftError, draftChanged, openableUrl,
		strengthView, masterCheck, recoveryGroups, recoveryComplete,
		errorText, wifiScanView, wifiBars, wifiSecurityLabel, wifiRowSub, applyWifi,
		QR_SOURCES, totpQrInfo, looksLikeUser, totpQrBusy, totpQrView, applyTotpQr,
		roleLabel, roleHint, writableVaults, candidates, initial,
		waitText, remainingText, emStatusKey, importChips, importCount, autoLockChoices,
		pushTarget, entryContext, gate,
	};
});
