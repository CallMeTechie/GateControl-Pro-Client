/**
 * GateControl -- Drucken: view logic (renderer, no DOM access)
 *
 * The page "Drucken" and the print dialog (plugin gatecontrol-print): which
 * files Drive offers "Drucken …" for, the printers with their state, what
 * the dialog shows for the printer chosen (colour and double-sided only
 * where the printer can, paper and tray as it names them, the person's
 * page limit, the office hint), the printer and options used last, the
 * rows of the job list (jobs in the making with their upload, the jobs of
 * the server with their four stations, stop and wait reasons, what can be
 * done with each), when an open job is asked for again, and the texts of
 * errors. Pure helpers for print-view.js, loaded as a plain script
 * (window.GCPrintState) and required by the node tests
 * (test/print-state.test.js).
 *
 * Inputs are what window.gatecontrol.print returns (core PrintService,
 * already cleaned); `t` is the i18n function (keys print.*).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCPrintState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const LAST_KEY = 'gc.print.last';
	const TOPIC_DONE = 'plugin:gatecontrol-print:print_done';
	const TOPIC_FAILED = 'plugin:gatecontrol-print:print_failed';
	const MAX_BYTES = 50 * 1024 * 1024;
	const MAX_COPIES = 99;
	const MIN = 60000;
	/** A job is followed at most this long (24 h on the server, plus a margin). */
	const TRACK_MAX_MS = 25 * 60 * MIN;
	/** A job the server does not know any more for this many answers is not asked again. */
	const MISSING_MAX = 3;

	const OFFICE_EXT = ['docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp', 'rtf'];
	const EXT_KIND = { pdf: 'pdf', jpg: 'image', jpeg: 'image', png: 'image', webp: 'image', heic: 'image', heif: 'image', txt: 'text' };
	for (const e of OFFICE_EXT) EXT_KIND[e] = 'office';
	const MIME_KIND = { 'application/pdf': 'pdf', 'image/jpeg': 'image', 'image/jpg': 'image', 'image/png': 'image', 'image/webp': 'image', 'image/heic': 'image', 'image/heif': 'image', 'text/plain': 'text' };

	/** Why the printer stopped while printing (`printing` + `message`). */
	const STOP = {
		'media-empty': 'paper', 'media-needed': 'paper', 'media-jam': 'jam', 'door-open': 'open', 'cover-open': 'open', 'toner-empty': 'ink', 'marker-supply-empty': 'ink',
		'input-tray-missing': 'tray', 'output-area-full': 'full', held: 'held', paused: 'stopped', stopped: 'stopped',
	};
	const WAIT = { printer_busy: 'busy', printer_not_accepting: 'notAccepting', cert_changed: 'cert', office_starting: 'office' };
	const FAIL = {
		format_unsupported: 'format', convert_failed: 'convert', convert_too_large: 'convertLarge', office_failed: 'office', office_timeout: 'officeTimeout', printer_rejected: 'rejected',
		canceled_at_printer: 'atPrinter', aborted_at_printer: 'atPrinter', expired: 'expired', printer_offline: 'expired', not_a_printer: 'device', device_not_allowed: 'device',
	};
	/** Error codes (plugin, the core's upload, the app) → the key below print.err. */
	const ERR = {
		network: 'network', timeout: 'timeout', not_configured: 'not_configured', too_large: 'too_large', http_413: 'too_large', format: 'format', unsupported_type: 'format',
		damaged: 'damaged', printer_format: 'printer_format', gateway_update: 'gateway_update', convert_off: 'convert_off', office_off: 'office_off', office_missing: 'office_missing',
		quota_exceeded: 'quota', infected: 'infected', quarantined: 'infected', scan_blocked: 'infected', scan_pending: 'scan', scan_unavailable: 'scan', no_right: 'no_right', forbidden: 'no_right',
		missing: 'read', read: 'read', empty: 'empty', folder: 'folder', too_many: 'too_many', unavailable: 'unavailable', drive_unavailable: 'read', offline: 'offline', cert_changed: 'cert_changed',
		not_found: 'not_found', busy: 'busy', vault_locked: 'vault_locked', vault_decrypt: 'read', vault_invalid: 'read', source_gone: 'source_gone', not_picked: 'source_gone', invalid: 'invalid',
	};
	const PAPER = {
		iso_a3_297x420mm: 'a3', iso_a4_210x297mm: 'a4', iso_a5_148x210mm: 'a5', iso_a6_105x148mm: 'a6', 'na_letter_8.5x11in': 'letter', 'na_legal_8.5x14in': 'legal',
		'na_index-4x6_4x6in': 'photo10x15', na_5x7_5x7in: 'photo13x18', 'oe_photo-l_3.5x5in': 'photo9x13',
	};
	const TRAY = { auto: 'auto', main: 'main', manual: 'manual', photo: 'photo', 'by-pass-tray': 'bypass', bypass: 'bypass', envelope: 'envelope', top: 'top', middle: 'middle', bottom: 'bottom', rear: 'rear', side: 'side', alternate: 'bypass' };

	const str = (v) => (v === null || v === undefined ? '' : String(v));
	const isNum = (v) => typeof v === 'number' && Number.isFinite(v);

	function plural(t, key, n, params) {
		const count = Number(n) || 0;
		return t(`${key}.${count === 1 ? 'one' : 'other'}`, { ...(params || {}), count });
	}

	// ── Files ────────────────────────────────────────────

	function extOf(name) {
		const m = /\.([A-Za-z0-9]{1,8})$/.exec(str(name));
		return m ? m[1].toLowerCase() : '';
	}

	/** 'pdf' | 'image' | 'text' | 'office' of a file by its name, else by its type; null: the plugin does not print it. */
	function kindOfName(name, mime) {
		return EXT_KIND[extOf(name)] || MIME_KIND[str(mime).toLowerCase().split(';')[0].trim()] || null;
	}

	/**
	 * Does Drive offer "Drucken …" for this node? A file of a type the plugin prints, at most 50 MB, its name readable
	 * (not a file of a vault this PC has no key for) and not blocked by the virus scan.
	 */
	function printable(n) {
		if (!n || n.isDir || n.deleted) return false;
		if (n.encrypted && n.locked) return false;
		if (n.scan && (n.scan.blocked === true || n.scan.removed === true)) return false;
		if (isNum(n.size) && n.size > MAX_BYTES) return false;
		return !!kindOfName(n.name, n.encrypted ? null : n.mime);
	}

	/** "184 KB", "3,8 MB" */
	function sizeText(bytes, locale) {
		const b = Number(bytes) || 0;
		const fmt = (v, digits) => new Intl.NumberFormat(locale === 'en' ? 'en-GB' : 'de-DE', { maximumFractionDigits: digits }).format(v);
		if (b < 1024) return `${fmt(b, 0)} B`;
		if (b < 1024 * 1024) return `${fmt(b / 1024, 0)} KB`;
		return `${fmt(b / (1024 * 1024), 1)} MB`;
	}

	/** "PDF", "Word-Datei", … */
	function kindText(file, t) {
		const f = file || {};
		if (f.kind === 'office') {
			const e = extOf(f.name);
			return t(`print.kind.${OFFICE_EXT.includes(e) ? e : 'office'}`);
		}
		return t(`print.kind.${['pdf', 'image', 'text'].includes(f.kind) ? f.kind : 'office'}`);
	}

	/** "PDF · 2 Seiten · 184 KB · aus Drive" */
	function fileLine(file, t, locale) {
		const f = file || {};
		return [
			kindText(f, t),
			isNum(f.pages) && f.pages > 0 && f.kind !== 'image' ? plural(t, 'print.meta.pages', f.pages) : '',
			sizeText(f.size, locale),
			t(f.vault ? 'print.from.vault' : f.from === 'drive' ? 'print.from.drive' : 'print.from.pc'),
		].filter(Boolean).join(' · ');
	}

	/** What a pick / drop could not take, in words — the first with its reason, the others counted; '' when nothing. */
	function rejectedText(rejected, t) {
		const list = Array.isArray(rejected) ? rejected.filter((r) => r && r.code !== 'vault_confirm') : [];
		if (!list.length) return '';
		const first = list[0];
		const reason = errorText({ code: first.code }, t);
		const head = first.name ? t('print.rejected.one', { name: first.name, reason }) : reason;
		return list.length > 1 ? `${head} ${plural(t, 'print.rejected.more', list.length - 1)}` : head;
	}

	// ── Printers ─────────────────────────────────────────

	/** Why a printer is not ready right now: 'cert' | 'off' | 'stopped' | 'busy' | null (ready). */
	function printerNote(p) {
		if (!p) return null;
		if (p.problem === 'cert_changed') return 'cert';
		if (!p.online || p.state === 'offline') return 'off';
		if (p.state === 'stopped') return 'stopped';
		if (p.state === 'processing') return 'busy';
		return null;
	}

	/** The chip of a printer → { text, tone: 'ok' | 'mute' | 'info' | 'warn' } */
	function printerChip(p, t) {
		const n = printerNote(p);
		if (n === 'cert') return { text: t('print.printer.cert'), tone: 'warn' };
		if (n === 'off') return { text: t('print.printer.off'), tone: 'mute' };
		if (n === 'stopped') return { text: t('print.printer.stopped'), tone: 'warn' };
		if (n === 'busy') return { text: t('print.printer.busy'), tone: 'info' };
		return { text: t('print.printer.ready'), tone: 'ok' };
	}

	/** "Wohnzimmer · Farbe, beidseitig" — in the dialog a printer that is not ready says what happens instead. */
	function printerSub(p, t, { dialog = false } = {}) {
		const n = printerNote(p);
		const caps = [t(p.color ? 'print.printer.color' : 'print.printer.bw'), p.duplex ? t('print.printer.duplex') : ''].filter(Boolean).join(', ');
		const second = dialog && n ? t(`print.printer.note.${n}`) : caps;
		return [p.location, second].filter(Boolean).join(' · ');
	}

	/** The banners above the printers → [{ tone, title, text }] : no printer on; a changed certificate per printer. */
	function printerBanners(printers, t) {
		const list = Array.isArray(printers) ? printers : [];
		const out = [];
		if (list.length && list.every((p) => printerNote(p) === 'off' || printerNote(p) === 'cert') && list.some((p) => printerNote(p) === 'off')) {
			out.push({ key: 'allOff', tone: 'info', title: t('print.banner.allOff.title'), text: t('print.banner.allOff.text') });
		}
		for (const p of list) if (printerNote(p) === 'cert') out.push({ key: `cert:${p.id}`, tone: 'warn', title: `${p.name}:`, text: t('print.banner.cert') });
		return out;
	}

	// ── Paper and tray ───────────────────────────────────

	/** "A4", "Foto 10 × 15 cm", else the size the PWG name carries ("100 × 150 mm"). */
	function paperLabel(pwg, t) {
		const k = PAPER[str(pwg)];
		if (k) return t(`print.paper.${k}`);
		const m = /_([0-9.]+)x([0-9.]+)(mm|in)$/.exec(str(pwg));
		return m ? t('print.paper.size', { w: m[1], h: m[2], unit: m[3] }) : str(pwg);
	}

	/** "Hauptfach", "Fach 2", else the printer's own word. */
	function trayLabel(src, t) {
		const s = str(src);
		if (TRAY[s]) return t(`print.tray.${TRAY[s]}`);
		const m = /^tray-(\d{1,2})$/.exec(s);
		return m ? t('print.tray.number', { n: m[1] }) : s;
	}

	// ── The printer and options used last ────────────────

	function parseLast(text) {
		let v = null;
		try { v = JSON.parse(str(text) || 'null'); } catch { v = null; }
		const o = v && typeof v === 'object' && !Array.isArray(v) ? v : {};
		const s = (x, max) => (typeof x === 'string' && x.length <= max ? x : null);
		return { deviceId: s(o.deviceId, 120), color: o.color !== false, duplex: o.duplex === true, media: s(o.media, 64), source: s(o.source, 40) };
	}

	function serializeLast(sel) {
		const s = sel || {};
		return JSON.stringify({ deviceId: s.deviceId || null, color: s.color !== false, duplex: s.duplex === true, media: s.media || null, source: s.source || null });
	}

	const colorAllowed = (printer, rights) => !!(printer && printer.color) && !(rights && rights.bwOnly);

	/** The printer to start with: the one used last while it is there, else the first that is ready, else the first. */
	function startPrinter(printers, wanted) {
		const list = Array.isArray(printers) ? printers : [];
		return list.find((p) => p.id === wanted) || list.find((p) => !printerNote(p)) || list[0] || null;
	}

	/**
	 * The dialog's choice fitted to a printer: what the printer cannot do is off, paper and tray are ones it names
	 * (else its default), copies within its range. `sel`: { deviceId, copies, color, duplex, media, source }.
	 */
	function fitSelection(sel, printers, rights) {
		const s = sel || {};
		const p = startPrinter(printers, s.deviceId);
		if (!p) return { deviceId: null, copies: 1, color: false, duplex: false, media: null, source: null };
		const copies = Math.min(p.copiesMax || MAX_COPIES, Math.max(1, Math.floor(Number(s.copies) || 1)));
		const m = p.media || { sizes: [], sources: [] };
		return {
			deviceId: p.id,
			copies,
			color: colorAllowed(p, rights) && s.color !== false,
			duplex: !!p.duplex && s.duplex === true,
			media: m.sizes.includes(s.media) ? s.media : (m.default || m.sizes[0] || null),
			source: m.sources.includes(s.source) ? s.source : (m.sourceDefault || m.sources[0] || null),
		};
	}

	/**
	 * What the print dialog shows → { sel, printer, printers, copies, color, duplex, paper, tray, banners, left,
	 * need, canSubmit, submit }. Colour is a choice only where printer and rights allow (else the reason);
	 * double-sided only where the printer can; paper as the printer names it (one size: shown, not a choice); the
	 * tray only with more than one. `need`: pages × copies of all files (a file whose pages are not known counts 1).
	 * `submit`: what goes to print.submit() — paper and tray only when they differ from the printer's default.
	 */
	function dialogModel({ files, printers, rights, pagesLeft, sel, t }) {
		const list = Array.isArray(printers) ? printers : [];
		const fs = Array.isArray(files) ? files : [];
		const s = fitSelection(sel, list, rights);
		const p = list.find((x) => x.id === s.deviceId) || null;
		const m = (p && p.media) || { sizes: [], default: null, sources: [], sourceDefault: null };
		const canColor = colorAllowed(p, rights);
		const exact = fs.every((f) => isNum(f.pages) && f.pages > 0);
		const need = fs.reduce((a, f) => a + (isNum(f.pages) && f.pages > 0 ? f.pages : 1), 0) * s.copies;
		const banners = [];
		const office = fs.some((f) => f.kind === 'office');
		let ok = !!p && fs.length > 0;
		if (!p) banners.push({ key: 'noPrinter', tone: 'err', title: '', text: t('print.dialog.noPrinter') });
		if (p && p.problem === 'cert_changed') { ok = false; banners.push({ key: 'cert', tone: 'warn', title: '', text: t('print.dialog.cert') }); }
		if (p && office && !p.office) { ok = false; banners.push({ key: 'office', tone: 'warn', title: t('print.dialog.office.title'), text: t('print.dialog.office.text') }); }
		const limited = isNum(pagesLeft);
		if (limited && need > pagesLeft) { ok = false; banners.push({ key: 'limit', tone: 'err', title: '', text: t(exact ? 'print.dialog.limit' : 'print.dialog.limitAtLeast', { pages: need, left: pagesLeft }) }); }
		const mediaLabel = (v) => (v === m.default ? t('print.paper.default', { name: paperLabel(v, t) }) : paperLabel(v, t));
		const trayText = (v) => (v === m.sourceDefault ? t('print.tray.default', { name: trayLabel(v, t) }) : trayLabel(v, t));
		const submit = p ? { deviceId: p.id, copies: s.copies, color: s.color, duplex: s.duplex } : null;
		if (submit && s.media && s.media !== m.default) submit.media = s.media;
		if (submit && s.source && s.source !== m.sourceDefault && m.sources.length > 1) submit.source = s.source;
		return {
			sel: s,
			printer: p,
			printers: list.map((x) => ({ id: x.id, name: x.name, sub: printerSub(x, t, { dialog: true }), chip: printerChip(x, t), on: !!p && x.id === p.id })),
			copies: { value: s.copies, min: 1, max: p ? p.copiesMax : 1, hint: t('print.dialog.copiesMax', { max: p ? p.copiesMax : 1 }) },
			color: { value: s.color, disabled: !canColor, hint: canColor ? '' : t(p && !p.color ? 'print.dialog.bwPrinter' : 'print.dialog.bwOnly') },
			duplex: { show: !!(p && p.duplex), value: s.duplex, text: t(s.duplex ? 'print.dialog.duplexOn' : 'print.dialog.duplexOff') },
			paper: { show: m.sizes.length > 0, disabled: m.sizes.length < 2, value: s.media, options: m.sizes.map((v) => ({ value: v, label: mediaLabel(v) })) },
			tray: { show: m.sources.length > 1, value: s.source, options: m.sources.map((v) => ({ value: v, label: trayText(v) })) },
			banners,
			left: limited && rights && rights.pagesPerDay > 0 ? t('print.dialog.left', { left: pagesLeft, total: rights.pagesPerDay }) : '',
			need,
			canSubmit: ok,
			submit,
		};
	}

	// ── Times ────────────────────────────────────────────

	const loc = (locale) => (locale === 'en' ? 'en-GB' : 'de-DE');
	const clock = (ms, locale) => new Intl.DateTimeFormat(loc(locale), { hour: 'numeric', minute: '2-digit' }).format(new Date(ms));
	const dayStart = (ms) => { const d = new Date(ms); d.setHours(0, 0, 0, 0); return d.getTime(); };
	const dayDiff = (ms, now) => Math.round((dayStart(ms) - dayStart(now)) / 86400000);

	/** When a job was made or ended: "gerade eben", "17:49", "gestern, 20:12", "Mo., 9:41", "02.11., 9:41". */
	function whenText(ms, now, locale, t) {
		if (!isNum(ms)) return '';
		const time = clock(ms, locale);
		if (now - ms >= 0 && now - ms < MIN) return t('print.meta.justNow');
		const d = dayDiff(ms, now);
		if (d === 0) return time;
		if (d === -1) return t('print.meta.yesterday', { time });
		const day = d > -7 && d < 0
			? new Intl.DateTimeFormat(loc(locale), { weekday: 'short' }).format(new Date(ms))
			: new Intl.DateTimeFormat(loc(locale), { day: '2-digit', month: '2-digit' }).format(new Date(ms));
		return `${day}, ${time}`;
	}

	/** Until when a job is tried: "heute, 17:41 Uhr", "morgen, 17:41 Uhr", "Fr., 17:41 Uhr". */
	function untilText(ms, now, locale, t) {
		if (!isNum(ms)) return '';
		const time = clock(ms, locale);
		const d = dayDiff(ms, now);
		if (d === 0) return t('print.meta.today', { time });
		if (d === 1) return t('print.meta.tomorrow', { time });
		return t('print.meta.at', { day: new Intl.DateTimeFormat(loc(locale), { weekday: 'short' }).format(new Date(ms)), time });
	}

	// ── Jobs ─────────────────────────────────────────────

	/** Why the printer stopped while printing → the key below print.stop, null when it prints. */
	function stopReason(job) {
		return job && job.state === 'printing' && job.message && STOP[job.message] ? STOP[job.message] : null;
	}

	/** 'running' | 'waiting' | 'stopped' | 'done' | 'failed' | 'canceled' — unknown states count as running. */
	function phase(job) {
		const s = job && job.state;
		if (s === 'done') return 'done';
		if (s === 'failed' || s === 'expired') return 'failed';
		if (s === 'canceled') return 'canceled';
		if (s === 'waiting') return 'waiting';
		return stopReason(job) ? 'stopped' : 'running';
	}

	const isFinal = (job) => ['done', 'failed', 'canceled'].includes(phase(job));

	/**
	 * The four stations of an open job (GateControl, Gateway, Drucker, Gedruckt) → ['done' | 'current' | 'hold' | 'todo' × 4],
	 * or null for a job that is through (its chip says how it ended). `current`: where the job is; `hold`: stopped there.
	 */
	function steps(job) {
		const ph = phase(job);
		if (ph === 'failed' || ph === 'canceled' || ph === 'done') return null;
		if (ph === 'waiting') return ['done', 'current', 'todo', 'todo'];
		if (ph === 'stopped') return ['done', 'done', 'hold', 'todo'];
		if (job.state === 'printing') return ['done', 'done', 'current', 'todo'];
		if (job.state === 'sending' && job.message !== 'converting' && job.message !== 'converting_office') return ['done', 'done', 'current', 'todo'];
		return ['done', 'current', 'todo', 'todo'];
	}

	/** The chip of a job → { text, tone } */
	function jobChip(job, t) {
		const ph = phase(job);
		if (ph === 'done') return { text: t(job.message === 'unconfirmed' ? 'print.state.doneUnconfirmed' : 'print.state.done'), tone: 'ok' };
		if (ph === 'failed') return { text: t(job.state === 'expired' ? 'print.state.expired' : 'print.state.failed'), tone: 'err' };
		if (ph === 'canceled') return { text: t('print.state.canceled'), tone: 'mute' };
		if (ph === 'waiting') return { text: t('print.state.waiting'), tone: 'mute' };
		if (ph === 'stopped') return { text: t('print.state.stopped'), tone: 'warn' };
		if (job.state === 'printing') return { text: t('print.state.printing'), tone: 'info' };
		if (job.state === 'sending') {
			return { text: t(job.message === 'converting' ? 'print.state.converting' : job.message === 'converting_office' ? 'print.state.convertingOffice' : 'print.state.sending'), tone: 'info' };
		}
		return { text: t('print.state.queued'), tone: 'info' };
	}

	/** "HP OfficeJet 8020 · 2 Seiten · beidseitig · 17:49" — pages × copies, colour, paper and tray when chosen. */
	function jobMeta(job, { now, locale, t }) {
		const pages = plural(t, 'print.meta.pages', job.pages || 1);
		const amount = job.copies > 1 ? t('print.meta.times', { pages, copies: plural(t, 'print.meta.copies', job.copies) }) : pages;
		const paper = [job.media ? paperLabel(job.media, t) : '', job.source ? trayLabel(job.source, t) : ''].filter(Boolean).join(', ');
		return [
			job.device || '',
			amount,
			paper,
			job.color ? t('print.meta.color') : t('print.meta.bw'),
			job.duplex ? t('print.meta.duplex') : '',
			whenText(job.doneAt || job.at, now, locale, t),
		].filter(Boolean).join(' · ');
	}

	/** The line below a job: why it waits (and until when), why it stopped, why it failed; '' when there is nothing to say. */
	function jobWhy(job, { now, locale, t }) {
		const ph = phase(job);
		if (ph === 'stopped') return `${t(`print.stop.${stopReason(job)}`)} ${t('print.stop.resume')}`;
		if (ph === 'waiting') {
			const reason = t(`print.wait.${WAIT[job.error] || 'off'}`);
			return isNum(job.expiresAt) && job.expiresAt > now ? t('print.wait.until', { reason, when: untilText(job.expiresAt, now, locale, t) }) : t('print.wait.plain', { reason });
		}
		if (ph === 'failed') return t(`print.fail.${FAIL[job.error || (job.state === 'expired' ? 'expired' : '')] || 'failed'}`);
		if (ph === 'done' && job.message === 'unconfirmed') return t('print.done.unconfirmed');
		return '';
	}

	/**
	 * A job of the server as a row → { key, kind: 'job', id, name, chip, tone, meta, why, steps, bar, actions, open }.
	 * actions: 'cancel' while it is on its way home, waits or stopped at the printer; 'again' for one that ended
	 * without being printed, when its file is still known (`sources`).
	 */
	function jobRow(job, o) {
		const ph = phase(job);
		const acts = [];
		if (ph === 'waiting' || ph === 'stopped' || job.state === 'queued') acts.push('cancel');
		if ((ph === 'failed' || ph === 'canceled') && o.sources && o.sources.has(job.id)) acts.push('again');
		let why = jobWhy(job, o);
		if (o.stale && !isFinal(job) && isNum(o.fetchedAt)) why = [why, o.t('print.jobs.stale', { time: clock(o.fetchedAt, o.locale) })].filter(Boolean).join(' ');
		return {
			key: `j:${job.id}`, kind: 'job', id: job.id, name: job.name, chip: jobChip(job, o.t), tone: ph === 'stopped' ? 'warn' : ph === 'failed' ? 'err' : '',
			meta: jobMeta(job, o), why, steps: steps(job), bar: null, actions: acts, open: !isFinal(job),
		};
	}

	/** The upload of a job in the making in per cent (0 … 100). */
	function percent(tr) {
		const total = Number(tr && tr.total) || 0;
		return total > 0 ? Math.max(0, Math.min(100, Math.round(((Number(tr.sent) || 0) / total) * 100))) : 0;
	}

	/** The chip of a job in the making → { text, tone } */
	function transferChip(tr, t) {
		if (tr.phase === 'failed') return { text: t('print.state.notSent'), tone: 'err' };
		if (tr.phase === 'loading') return { text: t('print.state.loading'), tone: 'info' };
		if (tr.phase === 'uploading') return { text: t('print.state.uploading', { percent: percent(tr) }), tone: 'info' };
		if (tr.phase === 'sending') return { text: t('print.state.creating'), tone: 'info' };
		return { text: t('print.state.queuedLocal'), tone: 'mute' };
	}

	/** A job in the making (core PrintService transfer) as a row; a failed one keeps its reason, "Erneut drucken" and "Entfernen". */
	function transferRow(tr, o) {
		const failed = tr.phase === 'failed';
		const meta = [
			tr.device || '',
			plural(o.t, 'print.meta.copies', tr.copies || 1),
			tr.color ? o.t('print.meta.color') : o.t('print.meta.bw'),
			tr.duplex ? o.t('print.meta.duplex') : '',
			whenText(tr.at, o.now, o.locale, o.t),
		].filter(Boolean).join(' · ');
		return {
			key: `t:${tr.id}`, kind: 'transfer', id: tr.id, name: tr.name, chip: transferChip(tr, o.t), tone: failed ? 'err' : '', meta,
			why: failed ? errorText(tr, o.t) : '', steps: null, bar: failed ? null : (tr.phase === 'uploading' || tr.phase === 'sending' ? percent(tr) : 0),
			actions: failed ? ['again', 'remove'] : ['cancel'], open: !failed,
		};
	}

	/**
	 * The rows of the job list: the jobs in the making (newest first), then the jobs of the server, newest first.
	 * @param {{ jobs: object[], transfers: object[], sources: Set, now: number, locale: string, t: Function, stale?: boolean, fetchedAt?: number }} o
	 */
	function rows(o) {
		const trs = (Array.isArray(o.transfers) ? o.transfers : []).slice().reverse().map((tr) => transferRow(tr, o));
		const jobs = (Array.isArray(o.jobs) ? o.jobs : []).slice().sort((a, b) => (b.at || 0) - (a.at || 0)).map((j) => jobRow(j, o));
		return [...trs, ...jobs];
	}

	/** Open jobs for the entry's number: jobs in the making that did not fail, and jobs of the server that are not through. */
	function openCount(jobs, transfers) {
		return (Array.isArray(transfers) ? transfers : []).filter((x) => x.phase !== 'failed').length
			+ (Array.isArray(jobs) ? jobs : []).filter((j) => !isFinal(j)).length;
	}

	/** The jobs shown: the overview's, with newer answers of single jobs on top (by id) and jobs made since in front. */
	function mergeJobs(overviewJobs, fresh) {
		const out = [];
		const seen = new Set();
		const f = fresh instanceof Map ? fresh : new Map();
		for (const j of Array.isArray(overviewJobs) ? overviewJobs : []) {
			const n = f.get(j.id);
			out.push(n && (n.updatedAt || 0) >= (j.updatedAt || 0) ? n : j);
			seen.add(j.id);
		}
		for (const [id, j] of f) if (!seen.has(id)) out.unshift(j);
		return out;
	}

	// ── Asking again ─────────────────────────────────────

	/**
	 * How long until an open job is asked for again: often right after sending (it usually prints within a minute),
	 * then less often; a waiting job (printer off) every 2 minutes — the gateway tries no more often.
	 */
	function pollDelay(job, elapsedMs) {
		const ph = phase(job);
		if (ph === 'waiting') return 2 * MIN;
		if (ph === 'stopped') return 15000;
		if (elapsedMs < 2 * MIN) return 5000;
		if (elapsedMs < 15 * MIN) return 20000;
		return MIN;
	}

	/** After `fails` answers that did not come: 5 s, 10 s, 20 s … at most 5 minutes. */
	function backoff(fails) {
		return Math.min(5 * MIN, 5000 * (2 ** Math.max(0, Math.min(10, (Number(fails) || 1) - 1))));
	}

	/** Is this job still followed? Open, and made less than 25 hours ago. */
	function tracked(job, now) {
		return !isFinal(job) && (!isNum(job.at) || now - job.at < TRACK_MAX_MS);
	}

	// ── Errors, notifications ────────────────────────────

	/** A failed call or a failed job in the making ({ code, error, left, pages }) in words. */
	function errorText(res, t) {
		const r = res || {};
		const code = str(r.code);
		if (code === 'limit') return isNum(r.left) && isNum(r.pages) ? t('print.err.limit', { pages: r.pages, left: r.left }) : t('print.err.limitPlain');
		if (ERR[code]) return t(`print.err.${ERR[code]}`);
		// a code the app has no words for: the plugin's own sentence when it sent one
		if (typeof r.error === 'string' && r.error && r.error !== code && r.status && !/^HTTP \d+$/.test(r.error)) return r.error;
		return t('print.err.failed');
	}

	/** The print context of an inbox entry ("Druck fertig" / "Druck fehlgeschlagen") → { type, kind, jobId } or null. */
	function entryContext(entry) {
		if (!entry || typeof entry !== 'object') return null;
		const topic = str(entry.topic);
		if (topic !== TOPIC_DONE && topic !== TOPIC_FAILED) return null;
		const m = /(?:^|:)print-([A-Za-z0-9_-]{1,80})$/.exec(str(entry.collapse_key));
		return { type: 'print', kind: topic === TOPIC_DONE ? 'done' : 'failed', jobId: m ? m[1] : null };
	}

	/** What the page shows instead of the list: 'unavailable' | 'noRight' | 'noPrinter' | 'error' | null (the list). */
	function gate(status, overview, error) {
		if (status && status.state === 'unavailable') return 'unavailable';
		if (error && (error.code === 'unavailable' || error.status === 404)) return 'unavailable';
		if (error && !overview) return 'error';
		if (!overview) return null;
		if (!overview.rights || !overview.rights.print) return 'noRight';
		if (!overview.printers.length) return 'noPrinter';
		return null;
	}

	return {
		LAST_KEY, MAX_BYTES, MAX_COPIES, TRACK_MAX_MS, MISSING_MAX,
		plural, extOf, kindOfName, printable, sizeText, kindText, fileLine, rejectedText,
		printerNote, printerChip, printerSub, printerBanners, paperLabel, trayLabel,
		parseLast, serializeLast, colorAllowed, startPrinter, fitSelection, dialogModel,
		whenText, untilText, stopReason, phase, isFinal, steps, jobChip, jobMeta, jobWhy, jobRow,
		percent, transferChip, transferRow, rows, openCount, mergeJobs,
		pollDelay, backoff, tracked, errorText, entryContext, gate,
	};
});
