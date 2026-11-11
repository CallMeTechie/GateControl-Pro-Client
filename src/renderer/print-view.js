/**
 * GateControl -- Drucken (renderer view of the plugin gatecontrol-print)
 *
 * The page "Drucken": printing on the printers at home through GateControl
 * — with or without the VPN.
 * - The page: the drop area ("Datei hierher ziehen", files from the
 *   Explorer or rows dragged out of Drive) with "Datei drucken …", the
 *   printers with their state, and the person's jobs: jobs in the making
 *   with the progress of their upload, the jobs of the server with their
 *   four stations (GateControl, Gateway, Drucker, Gedruckt), the reason a
 *   printer stopped or a job waits (and until when), "Abbrechen" and
 *   "Erneut drucken". Open jobs are asked for again one by one while the
 *   window is visible — less often the longer they take, with a pause that
 *   grows while the server does not answer; nothing is asked when no job is
 *   open.
 * - The print dialog ("Zu Hause drucken"): the files, the printers (the
 *   one used last first), copies, colour, double-sided, paper and tray —
 *   only what the printer chosen can do —, the person's pages left today,
 *   the hint for office files and the page limit. It opens from the page,
 *   from Drive ("Drucken …" in the row menu and the menu of a selection,
 *   Strg+P, the button in the viewers) and from files dropped on the page or
 *   on the entry "Drucken" in the side bar. A file of a vault is printed
 *   only after the person said yes (it leaves the vault decrypted).
 * - States: no printer found, no right to print, the plugin not there for
 *   the apps, no connection (the last list with its time).
 *
 * The page never names a file by its path: the core answers tokens for
 * files picked, dropped or chosen in Drive (window.gatecontrol.print, core
 * PrintService over IPC). Texts: print.* of the core locales; view logic
 * without DOM: print-state.js (window.GCPrintState).
 *
 * Note: server text only ever goes into textContent / attributes; icons are
 * built from static path data with createElementNS (no innerHTML).
 */
(function (root) {
	'use strict';

	const PS = root.GCPrintState;
	const NS = 'http://www.w3.org/2000/svg';
	const DRIVE_DRAG = 'application/x-gc-drive-nodes';
	const ICONS = {
		printer: 'M6 9V3h12v6|M6 17H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-2|M6 14h12v7H6z',
		refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8|M21 3v5h-5',
		alert: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 8v5M12 16h.01',
		info: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M12 11v5M12 8h.01',
		warn: 'M12 4l9 16H3z|M12 10v4M12 17h.01',
		upload: 'M12 16V4|M7 9l5-5 5 5|M5 20h14',
		file: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z|M14 3v5h5',
		files: 'M9 7V5a2 2 0 0 1 2-2h5l4 4v9a2 2 0 0 1-2 2h-2|M4 9a2 2 0 0 1 2-2h7l3 3v9a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z',
		image: 'M4 5h16v14H4z|M4 16l5-5 4 4 3-3 4 4|M15 9h.01',
		minus: 'M5 12h14',
		plus: 'M12 5v14M5 12h14',
		lock: 'M6 11h12v9H6z|M8 11V8a4 4 0 0 1 8 0v3',
		cloudOff: 'M3 3l18 18|M8 8a5 5 0 0 0-2 9h11|M10 5a7 7 0 0 1 9 6 4 4 0 0 1 1 7',
		ban: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18|M5.6 5.6l12.8 12.8',
	};

	function icon(name, size = 16, stroke = '2') {
		const s = document.createElementNS(NS, 'svg');
		s.setAttribute('viewBox', '0 0 24 24');
		s.setAttribute('width', String(size));
		s.setAttribute('height', String(size));
		s.setAttribute('fill', 'none');
		s.setAttribute('stroke', 'currentColor');
		s.setAttribute('stroke-width', stroke);
		s.setAttribute('stroke-linecap', 'round');
		s.setAttribute('stroke-linejoin', 'round');
		s.setAttribute('aria-hidden', 'true');
		for (const d of String(ICONS[name] || ICONS.alert).split('|')) {
			const p = document.createElementNS(NS, 'path');
			p.setAttribute('d', d);
			s.appendChild(p);
		}
		return s;
	}

	/** el('div', { class, text, on: { click }, attrs… }, [children]) — text only via textContent. */
	function el(tag, attrs, kids) {
		const n = document.createElement(tag);
		for (const [k, v] of Object.entries(attrs || {})) {
			if (v === null || v === undefined || v === false) continue;
			if (k === 'text') n.textContent = String(v);
			else if (k === 'class') n.className = v;
			else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
			else n.setAttribute(k, v === true ? '' : String(v));
		}
		for (const c of kids || []) if (c !== null && c !== undefined && c !== false && c !== '') n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
		return n;
	}
	const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };

	let seq = 0;
	const nextId = (p) => `${p}-${++seq}`;
	const fail = (err) => ({ ok: false, code: 'failed', error: (err && err.message) || 'failed' });

	/**
	 * @param {object} o
	 * @param {HTMLElement} o.root - the page section (empty)
	 * @param {object} o.api - window.gatecontrol.print
	 * @param {Function} o.t - i18n
	 * @param {() => string} o.getLocale
	 * @param {(msg: string, type?: string) => void} [o.toast]
	 * @param {(st: object) => void} [o.onStatus] - availability (nav entry)
	 * @param {(n: number) => void} [o.onCount] - open jobs (the number at the nav entry)
	 * @param {HTMLElement} [o.navEl] - the nav entry "Drucken": files and Drive rows can be dropped on it
	 * @param {HTMLElement} [o.dialogHost] - where the dialogs go (default: document.body)
	 * @param {() => boolean} [o.isShown] - is the page "Drucken" the one shown?
	 * @param {() => void} [o.openPortal] - the portal's tab "Drucken & Scannen" (older jobs)
	 * @param {() => number} [o.now]
	 * @returns {{ show(), hide(), open(ctx), relabel(), status(), canPrint(node), printDrive(ids), printDropped(files), pick() }}
	 */
	function mount(o) {
		const api = o.api;
		const t = o.t;
		const now = typeof o.now === 'function' ? o.now : () => Date.now();
		const locale = () => o.getLocale();
		const toast = (msg, type) => { if (typeof o.toast === 'function') o.toast(msg, type || 'info'); };
		const host = o.dialogHost || document.body;
		const call = (fn) => Promise.resolve().then(fn).catch(fail);
		const storage = (() => { try { return root.localStorage || null; } catch { return null; } })();

		const S = {
			status: null,
			shown: false,
			overview: null,       // the last answer of api.overview()
			error: null,          // the last one that failed
			loading: false,
			fresh: new Map(),     // job id → a newer answer than the overview's (a job made here, one asked for)
			transfers: [],        // jobs in the making (core)
			sources: new Set(),   // jobs whose file is still known ("Erneut drucken")
			track: new Map(),     // job id → { since, nextAt, missing }
			fails: 0,             // answers in a row that did not come
			timer: null,
			busy: new Set(),      // row keys with a running action
			focusJob: null,       // the job a push pointed at
			count: -1,
		};

		// ── Skeleton ─────────────────────────────────────────
		const refs = {};
		const rootEl = el('div', { class: 'pv' });
		o.root.appendChild(rootEl);
		refs.h = el('h1', { class: 'pv-h', text: t('print.title') });
		refs.sub = el('span', { class: 'pv-sub', text: t('print.sub') });
		refs.refresh = el('button', { type: 'button', class: 'pv-ib', title: t('print.refresh'), 'aria-label': t('print.refresh'), on: { click: () => load(true) } }, [icon('refresh', 16)]);
		refs.pickLabel = el('span', { text: t('print.pick') });
		refs.pick = el('button', { type: 'button', class: 'btn btn-pri pv-pick', 'data-k': 'pick', on: { click: () => pick() } }, [icon('printer', 15), refs.pickLabel]);
		refs.body = el('div', { class: 'pv-body scroll' });
		rootEl.append(
			el('div', { class: 'pv-head' }, [
				el('div', { class: 'pv-head-tx' }, [refs.h, refs.sub]),
				refs.refresh,
				refs.pick,
			]),
			refs.body,
		);

		// ── Data ─────────────────────────────────────────────
		const gate = () => PS.gate(S.status, S.overview, S.error);
		/** Printing is offered (menus, viewers, the dialog): the plugin is there and the person may print. */
		const usable = () => !!S.status && S.status.state === 'available' && !['unavailable', 'noRight'].includes(gate());
		const jobsNow = () => PS.mergeJobs(S.overview ? S.overview.jobs : [], S.fresh);

		function setStatus(st) {
			S.status = st && typeof st === 'object' ? st : null;
			if (typeof o.onStatus === 'function') o.onStatus(S.status);
			// the rights are needed before the page is opened: Drive's "Drucken …" shows only for someone who may print
			if (S.status && S.status.state === 'available' && !S.overview && !S.loading) load(false);
			else render();
		}

		async function load(refresh) {
			if (S.loading) return;
			S.loading = true;
			refs.refresh.classList.add('is-busy');
			refs.refresh.disabled = true;
			const r = await call(() => api.overview({ refresh: !!refresh }));
			if (r && r.ok) {
				S.overview = r;
				// the last copy without a connection: whatever the server said (502, 503 …), the page shows "no connection"
				S.error = r.stale ? { ok: false, code: 'network' } : null;
				// what the list now knows as well is taken from it again
				for (const j of r.jobs) { const f = S.fresh.get(j.id); if (f && (j.updatedAt || 0) >= (f.updatedAt || 0)) S.fresh.delete(j.id); }
				if (!r.stale) S.fails = 0;
			} else {
				S.error = r || fail();
			}
			const src = await call(() => api.sources());
			if (src && src.ok && Array.isArray(src.ids)) S.sources = new Set(src.ids);
			S.loading = false;
			refs.refresh.classList.remove('is-busy');
			refs.refresh.disabled = false;
			render();
			schedule();
		}

		/** The overview for a dialog: the one at hand while it is young, else asked again. */
		async function ensureOverview() {
			if (!S.overview || S.error || now() - (S.overview.fetchedAt || 0) > 30000) await load(true);
			return S.overview;
		}

		// ── Asking for open jobs again ───────────────────────
		const hidden = () => typeof document.visibilityState === 'string' && document.visibilityState !== 'visible';

		function schedule() {
			clearTimeout(S.timer);
			S.timer = null;
			const at = now();
			const open = jobsNow().filter((j) => PS.tracked(j, at) && !(S.track.get(j.id) && S.track.get(j.id).missing >= PS.MISSING_MAX));
			for (const id of [...S.track.keys()]) if (!open.some((j) => j.id === id)) S.track.delete(id);
			// nothing open, or nobody looks: nothing is asked
			if (!open.length || hidden()) return;
			let next = Infinity;
			for (const j of open) {
				let tr = S.track.get(j.id);
				if (!tr) {
					const since = j.at || at;
					tr = { since, nextAt: at + PS.pollDelay(j, at - since), missing: 0 };
					S.track.set(j.id, tr);
				}
				next = Math.min(next, tr.nextAt);
			}
			S.timer = setTimeout(pollDue, Math.max(1000, next - at));
		}

		async function pollDue() {
			S.timer = null;
			if (hidden()) return;
			let ended = false;
			let changed = false;
			for (const j of jobsNow()) {
				const tr = S.track.get(j.id);
				if (!tr || tr.nextAt > now() + 250) continue;
				const r = await call(() => api.job(j.id));
				const at = now();
				if (!r || !r.ok) {
					// no answer: every open job waits longer — 5 s, 10 s, 20 s … 5 min
					S.fails += 1;
					for (const x of S.track.values()) x.nextAt = at + PS.backoff(S.fails);
					break;
				}
				S.fails = 0;
				if (r.job) {
					tr.missing = 0;
					if (JSON.stringify(r.job) !== JSON.stringify(j)) changed = true;
					S.fresh.set(r.job.id, r.job);
					if (PS.isFinal(r.job)) ended = true;
					tr.nextAt = at + PS.pollDelay(r.job, at - tr.since);
				} else {
					tr.missing += 1;
					tr.nextAt = at + PS.pollDelay(j, at - tr.since);
				}
			}
			// a job ended: the list, the pages left and the printers are asked again
			if (ended) { await load(true); return; }
			if (changed) render();
			schedule();
		}

		document.addEventListener('visibilitychange', () => {
			if (hidden()) { clearTimeout(S.timer); S.timer = null; return; }
			if (S.shown || S.track.size) load(true);
		});

		function onTransfers(list) {
			const before = S.transfers;
			S.transfers = Array.isArray(list) ? list : [];
			// one that just failed, while another page is shown: its reason as a toast
			if (!S.shown) {
				for (const tr of S.transfers) {
					const old = before.find((x) => x.id === tr.id);
					if (tr.phase === 'failed' && (!old || old.phase !== 'failed')) toast(`${tr.name}: ${PS.errorText(tr, t)}`, 'error');
				}
			}
			const same = before.length === S.transfers.length && S.transfers.every((tr, i) => before[i].id === tr.id && before[i].phase === tr.phase);
			if (same && S.shown) paintTransfers();
			else render();
		}

		function onJob(e) {
			const job = e && e.job;
			if (!job || !job.id) return;
			S.fresh.set(job.id, job);
			S.sources.add(job.id);
			if (S.overview && typeof e.pagesLeft === 'number') S.overview = { ...S.overview, pagesLeft: e.pagesLeft };
			render();
			schedule();
		}

		function onPush(ctx) {
			if (ctx && ctx.jobId) S.focusJob = ctx.jobId;
			load(true);
		}

		// ── Rendering ────────────────────────────────────────
		function banner(b) {
			return el('div', { class: `pv-note is-${b.tone}`, role: b.tone === 'err' ? 'alert' : 'note', 'data-banner': b.key }, [
				icon(b.tone === 'info' ? 'info' : b.tone === 'err' ? 'alert' : 'warn', 16),
				el('div', {}, [b.title ? el('b', { text: `${b.title} ` }) : null, b.text]),
			]);
		}

		function state(kind, ic, extra) {
			return el('div', { class: `pv-state${kind === 'error' ? ' is-error' : ''}`, 'data-state': kind }, [
				icon(ic, 34, '1.6'),
				el('strong', { text: t(`print.empty.${kind}.title`) }),
				kind === 'error' ? el('span', { text: PS.errorText(S.error, t) }) : el('span', { text: t(`print.empty.${kind}.text`) }),
				...(extra || []),
			]);
		}

		const retryBtn = () => el('button', { type: 'button', class: 'btn btn-sec btn-sm', 'data-k': 'retry', text: t('print.retry'), on: { click: () => { call(() => api.check()); load(true); } } });

		function stepsEl(steps) {
			const names = ['gc', 'gateway', 'printer', 'done'].map((k) => t(`print.steps.${k}`));
			const at = Math.max(steps.lastIndexOf('current'), steps.lastIndexOf('hold'), steps.lastIndexOf('done'));
			const line = el('div', { class: 'pv-steps', role: 'img', 'aria-label': t('print.steps.label', { n: at + 1, name: names[at] }) });
			steps.forEach((s, i) => {
				if (i) line.appendChild(el('u', { class: steps[i] !== 'todo' ? 'is-done' : '' }));
				line.appendChild(el('i', { class: `is-${s}` }));
			});
			return [line, el('div', { class: 'pv-leg', 'aria-hidden': 'true' }, names.map((n) => el('span', { text: n })))];
		}

		/** The upload's progress. */
		function barEl(r) {
			const fill = el('i');
			fill.style.width = `${r.bar}%`;
			return el('div', { class: 'pv-bar', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(r.bar), 'aria-label': r.chip.text }, [fill]);
		}

		function rowEl(r) {
			const busy = S.busy.has(r.key);
			const acts = r.actions.map((a) => {
				const label = a === 'cancel' ? 'print.jobs.cancel' : a === 'again' ? 'print.jobs.again' : 'print.jobs.remove';
				return el('button', {
					type: 'button', class: 'btn btn-sec btn-sm', 'data-k': `${r.key}:${a}`, 'data-act': a, disabled: busy, text: t(label), 'aria-label': t(`${label}Of`, { name: r.name }),
					on: { click: () => rowAction(r, a) },
				});
			});
			return el('div', {
				class: `pv-job${r.tone ? ` is-${r.tone}` : ''}${S.focusJob && r.kind === 'job' && r.id === S.focusJob ? ' is-focus' : ''}`, role: 'listitem',
				'data-row': r.key, 'data-kind': r.kind, 'data-id': r.id,
			}, [
				icon(r.kind === 'transfer' ? 'upload' : 'file', 18),
				el('div', { class: 'pv-job-tx' }, [
					el('div', { class: 'pv-job-n' }, [el('b', { text: r.name }), el('span', { class: `pv-chip is-${r.chip.tone}`, 'data-chip': '', text: r.chip.text })]),
					el('div', { class: 'pv-meta', text: r.meta }),
					r.bar !== null ? barEl(r) : null,
					...(r.steps ? stepsEl(r.steps) : []),
					r.why ? el('div', { class: 'pv-why', text: r.why }) : null,
				]),
				acts.length ? el('div', { class: 'pv-btns' }, acts) : null,
			]);
		}

		function rowsNow() {
			return PS.rows({
				jobs: jobsNow(), transfers: S.transfers, sources: S.sources, now: now(), locale: locale(), t,
				stale: !!(S.overview && S.overview.stale), fetchedAt: S.overview ? S.overview.fetchedAt : null,
			});
		}

		function setCount() {
			const n = PS.openCount(jobsNow(), S.transfers);
			if (n === S.count) return;
			S.count = n;
			if (typeof o.onCount === 'function') o.onCount(n);
		}

		/** Only the progress of the jobs in the making (several times a second while a file goes up). */
		function paintTransfers() {
			const opts = { now: now(), locale: locale(), t };
			for (const tr of S.transfers) {
				const row = refs.body.querySelector(`[data-row="t:${tr.id}"]`);
				if (!row) { render(); return; }
				const r = PS.transferRow(tr, opts);
				const chip = row.querySelector('[data-chip]');
				if (chip) chip.textContent = r.chip.text;
				const bar = row.querySelector('.pv-bar');
				if (bar && r.bar !== null) {
					bar.setAttribute('aria-valuenow', String(r.bar));
					bar.setAttribute('aria-label', r.chip.text);
					bar.firstChild.style.width = `${r.bar}%`;
				}
			}
		}

		function render() {
			setCount();
			if (!S.shown) return;
			// keep the focus on the same control across a re-render
			const act = document.activeElement;
			const keep = act && refs.body.contains(act) ? act.getAttribute('data-k') : null;
			const g = gate();
			const ov = S.overview;
			const kids = [];
			refs.pick.hidden = !!g || !ov;
			refs.pick.disabled = !!S.error;
			if (g === 'unavailable') {
				kids.push(el('div', { class: 'pv-card' }, [state('unavailable', 'ban', [retryBtn()])]));
			} else if (!ov && !S.error) {
				kids.push(el('div', { class: 'pv-loading', role: 'status', text: t('print.loading') }));
			} else if (g === 'error') {
				kids.push(el('div', { class: 'pv-card' }, [state('error', 'cloudOff', [retryBtn()])]));
			} else {
				// no connection: the last list with its time
				if (S.error) {
					const time = ov && ov.fetchedAt ? new Intl.DateTimeFormat(locale() === 'en' ? 'en-GB' : 'de-DE', { hour: 'numeric', minute: '2-digit' }).format(new Date(ov.fetchedAt)) : '';
					kids.push(el('div', { class: 'pv-note is-err', role: 'alert', 'data-banner': 'offline' }, [
						icon('cloudOff', 16),
						el('div', {}, [el('b', { text: `${t('print.banner.offline.title')} ` }), time ? t('print.banner.offline.text', { time }) : t('print.banner.offline.noCopy')]),
						retryBtn(),
					]));
				}
				if (g === 'noRight') {
					kids.push(el('div', { class: 'pv-card' }, [state('noRight', 'lock')]));
				} else if (g === 'noPrinter') {
					kids.push(el('div', { class: 'pv-card' }, [state('noPrinter', 'printer', [retryBtn()])]), el('div', { class: 'pv-foot', text: t('print.empty.noPrinter.foot') }));
				} else {
					for (const b of PS.printerBanners(ov.printers, t)) kids.push(banner(b));
					const allOff = ov.printers.every((p) => PS.printerNote(p) === 'off' || PS.printerNote(p) === 'cert');
					const left = typeof ov.pagesLeft === 'number' && ov.rights.pagesPerDay > 0 ? t('print.drop.left', { left: ov.pagesLeft, total: ov.rights.pagesPerDay }) : '';
					refs.drop = el('div', { class: 'pv-drop', 'data-drop': '' }, [
						icon('upload', 26, '1.7'),
						el('div', { class: 'pv-drop-tx' }, [
							el('b', { 'data-drop-title': '', text: t('print.drop.title') }),
							el('span', { text: [t('print.drop.types'), left, allOff ? t('print.drop.waits') : ''].filter(Boolean).join(' ') }),
						]),
					]);
					kids.push(refs.drop);
					const pid = nextId('pv-prn');
					kids.push(
						el('h2', { id: pid, class: 'pv-h2 pv-sr', text: t('print.printers.title') }),
						el('div', { class: 'pv-prns', role: 'list', 'aria-labelledby': pid }, ov.printers.map((p) => {
							const c = PS.printerChip(p, t);
							return el('div', { class: 'pv-prn', role: 'listitem', 'data-printer': p.id }, [
								icon('printer', 18),
								el('div', { class: 'pv-prn-tx' }, [el('b', { text: p.name }), el('span', { text: PS.printerSub(p, t) })]),
								el('span', { class: `pv-chip is-${c.tone}`, text: c.text }),
							]);
						})),
					);
				}
				// the jobs — also without the right to print: earlier jobs stay visible
				const list = rowsNow();
				const open = PS.openCount(jobsNow(), S.transfers);
				const jid = nextId('pv-jobs');
				const time = ov && ov.fetchedAt ? new Intl.DateTimeFormat(locale() === 'en' ? 'en-GB' : 'de-DE', { hour: 'numeric', minute: '2-digit' }).format(new Date(ov.fetchedAt)) : '';
				if (ov && (list.length || !g)) {
					kids.push(el('div', { class: 'pv-jobs-h' }, [
						el('h2', { id: jid, class: 'pv-h2', text: t('print.jobs.title') }),
						el('span', { 'data-jobs-sub': '', text: [open ? PS.plural(t, 'print.jobs.open', open) : t('print.jobs.none'), time ? t('print.jobs.updated', { time }) : ''].filter(Boolean).join(' · ') }),
					]));
					if (list.length) kids.push(el('div', { class: 'pv-jobs', role: 'list', 'aria-labelledby': jid }, list.map(rowEl)));
					else kids.push(el('div', { class: 'pv-empty', text: t('print.jobs.empty') }));
					const n = jobsNow().length;
					kids.push(el('div', { class: 'pv-foot' }, [
						n ? `${PS.plural(t, 'print.jobs.foot', n)} ` : '',
						`${t('print.jobs.footPortal')} `,
						typeof o.openPortal === 'function' ? el('button', { type: 'button', class: 'pv-link', 'data-k': 'portal', text: t('print.jobs.portal'), on: { click: () => o.openPortal() } }) : null,
					]));
				}
			}
			clear(refs.body);
			refs.body.append(...kids);
			if (keep) {
				const again = refs.body.querySelector(`[data-k="${keep}"]`);
				if (again && !again.disabled) again.focus();
			}
			if (S.focusJob) {
				const row = refs.body.querySelector(`[data-kind="job"][data-id="${S.focusJob}"]`);
				if (row) { row.scrollIntoView({ block: 'nearest' }); S.focusJob = null; }
			}
		}

		// ── Actions of a row ─────────────────────────────────
		async function rowAction(r, a) {
			if (S.busy.has(r.key)) return;
			if (a === 'remove' || (a === 'cancel' && r.kind === 'transfer')) {
				await call(() => api.cancelTransfer(r.id));
				return;
			}
			if (a === 'again') {
				const res = await call(() => api.again(r.kind === 'transfer' ? { transferId: r.id } : { jobId: r.id }));
				if (!res || !res.ok) { toast(PS.errorText(res, t), 'error'); return; }
				const job = r.kind === 'job' ? jobsNow().find((j) => j.id === r.id) : null;
				const preset = res.options || (job ? { deviceId: job.deviceId, copies: job.copies, color: job.color, duplex: job.duplex, media: job.media, source: job.source } : null);
				openPrint(res.files, res.rejected, { preset, replaces: r.kind === 'transfer' ? r.id : null });
				return;
			}
			S.busy.add(r.key);
			render();
			const res = await call(() => api.cancel(r.id));
			S.busy.delete(r.key);
			if (res && res.ok) toast(t(res.canceled ? 'print.jobs.canceled' : 'print.jobs.cancelLate'), res.canceled ? 'success' : 'info');
			else toast(PS.errorText(res, t), 'error');
			await load(true);
		}

		// ── Dialogs ──────────────────────────────────────────
		const M = { open: false, busy: false, error: '', render: null, cancel: null, prevFocus: null, titleId: nextId('pv-dlg-h') };
		M.box = el('div', { class: 'pv-dlg', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': M.titleId, tabindex: '-1' });
		M.scrim = el('div', { class: 'pv-scrim', hidden: true, on: { mousedown: (e) => { if (e.target === M.scrim && !M.busy) closeModal(true); } } }, [M.box]);
		M.scrim.addEventListener('keydown', (e) => {
			if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); if (!M.busy) closeModal(true); }
			if (e.key === 'Tab') trapFocus(e);
		});
		host.appendChild(M.scrim);

		function trapFocus(e) {
			const items = [...M.box.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled])')].filter((n) => n.offsetParent !== null && n.getAttribute('tabindex') !== '-1');
			if (!items.length) return;
			const first = items[0];
			const last = items[items.length - 1];
			if (e.shiftKey && (document.activeElement === first || document.activeElement === M.box)) { e.preventDefault(); last.focus(); }
			else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
		}

		/** `render()` fills M.box; `cancel()` runs when the dialog is closed without its action. */
		function openModal(renderFn, cancelFn) {
			if (M.open) closeModal(true);
			Object.assign(M, { open: true, busy: false, error: '', render: renderFn, cancel: cancelFn || null, prevFocus: document.activeElement });
			M.scrim.hidden = false;
			renderModal();
			const first = M.box.querySelector('[data-first]') || M.box.querySelector('button:not([disabled])');
			setTimeout(() => { if (M.open) (first || M.box).focus(); }, 0);
		}

		function closeModal(canceled) {
			if (!M.open) return;
			M.open = false;
			M.scrim.hidden = true;
			clear(M.box);
			const cancelFn = M.cancel;
			M.cancel = null;
			M.render = null;
			if (canceled && cancelFn) cancelFn();
			const back = M.prevFocus && M.prevFocus.isConnected && M.prevFocus.offsetParent !== null ? M.prevFocus : null;
			M.prevFocus = null;
			if (back && back.focus) { try { back.focus(); } catch { /* gone */ } }
		}

		function renderModal() {
			if (!M.open) return;
			const act = document.activeElement;
			const keep = act && M.box.contains(act) ? act.getAttribute('data-k') : null;
			const kids = M.render();
			clear(M.box);
			M.box.append(...kids.filter(Boolean));
			if (keep) {
				const again = M.box.querySelector(`[data-k="${keep}"]`);
				if (again && !again.disabled) again.focus();
				else M.box.focus();
			}
		}

		/** "Aus dem Tresor drucken?" → true when the person said yes. */
		function askVault() {
			return new Promise((resolve) => {
				let answered = false;
				const done = (yes) => { if (answered) return; answered = true; closeModal(false); resolve(yes); };
				openModal(() => [
					el('h2', { id: M.titleId, class: 'pv-dlg-h', text: t('print.vault.title') }),
					el('div', { class: 'pv-note is-warn', role: 'note' }, [icon('lock', 16), el('div', { text: t('print.vault.text') })]),
					el('div', { class: 'pv-dlg-acts' }, [
						el('span', { class: 'pv-grow' }),
						el('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'data-k': 'cancel', 'data-first': '', text: t('print.cancel'), on: { click: () => done(false) } }),
						el('button', { type: 'button', class: 'btn btn-danger btn-sm', 'data-k': 'vault-yes', text: t('print.vault.go'), on: { click: () => done(true) } }),
					]),
				], () => { if (!answered) { answered = true; resolve(false); } });
			});
		}

		const lastSel = () => PS.parseLast(storage ? (() => { try { return storage.getItem(PS.LAST_KEY); } catch { return null; } })() : null);
		const saveLast = (sel) => { if (!storage) return; try { storage.setItem(PS.LAST_KEY, PS.serializeLast(sel)); } catch { /* storage unavailable */ } };

		/**
		 * The print dialog for files the core answered tokens for.
		 * @param {object[]} files @param {object[]} [rejected] - what could not be taken (shown as a hint)
		 * @param {{ preset?: object, replaces?: string }} [opts] - "Erneut drucken": the options of the job; the failed job in the making it replaces
		 */
		async function openPrint(files, rejected, opts = {}) {
			const list = Array.isArray(files) ? files : [];
			const tokens = list.map((f) => f.token);
			const forget = () => { if (tokens.length) call(() => api.forget(tokens)); };
			if (!list.length) {
				const why = PS.rejectedText(rejected, t);
				toast(why || t('print.menu.none'), 'error');
				return;
			}
			const ov = await ensureOverview();
			const g = gate();
			// no connection (the list is an old copy), no right, no printer, the plugin gone: said, no dialog
			if (!ov || g || S.error) {
				forget();
				toast(g === 'noRight' ? t('print.err.no_right') : g === 'noPrinter' ? t('print.empty.noPrinter.title') : g === 'unavailable' ? t('print.err.unavailable') : PS.errorText(S.error, t), 'error');
				return;
			}
			const last = lastSel();
			const sel = { ...last, copies: 1, ...(opts.preset || {}) };
			const ids = { printer: nextId('pv-l'), copies: nextId('pv-l'), color: nextId('pv-l'), duplex: nextId('pv-l'), paper: nextId('pv-l'), tray: nextId('pv-l') };
			const model = () => PS.dialogModel({ files: list, printers: S.overview.printers, rights: S.overview.rights, pagesLeft: S.overview.pagesLeft, sel, t });
			const set = (patch) => { Object.assign(sel, patch); Object.assign(sel, model().sel); M.error = ''; renderModal(); };
			const rejectedNote = PS.rejectedText(rejected, t);

			async function submit() {
				const m = model();
				if (!m.canSubmit || M.busy) return;
				M.busy = true;
				M.error = '';
				renderModal();
				const r = await call(() => api.submit({ tokens, ...m.submit }));
				M.busy = false;
				if (!M.open) return;
				if (r && r.ok) {
					saveLast(m.sel);
					if (opts.replaces) call(() => api.cancelTransfer(opts.replaces));
					closeModal(false);
					if (!S.shown) toast(PS.plural(t, 'print.jobs.sent', list.length), 'success');
					return;
				}
				M.error = PS.errorText(r, t);
				renderModal();
			}

			/**
			 * The banners, the stepper and the print button follow the copies typed — without building the dialog again
			 * (a rebuild while the field loses the focus would swallow the click that took it).
			 */
			function paintStatus() {
				const m = model();
				const zone = M.box.querySelector('[data-banners]');
				if (zone) { clear(zone); zone.append(...m.banners.map(banner)); }
				const go = M.box.querySelector('[data-k="submit"]');
				if (go) go.disabled = M.busy || !m.canSubmit;
				const less = M.box.querySelector('[data-k="less"]');
				if (less) less.disabled = M.busy || m.copies.value <= m.copies.min;
				const more = M.box.querySelector('[data-k="more"]');
				if (more) more.disabled = M.busy || m.copies.value >= m.copies.max;
			}

			function radios(m) {
				const move = (e, i) => {
					const d = e.key === 'ArrowDown' || e.key === 'ArrowRight' ? 1 : e.key === 'ArrowUp' || e.key === 'ArrowLeft' ? -1 : 0;
					if (!d) return;
					e.preventDefault();
					const next = m.printers[(i + d + m.printers.length) % m.printers.length];
					set({ deviceId: next.id });
					const b = M.box.querySelector(`[data-k="prn:${next.id}"]`);
					if (b) b.focus();
				};
				return el('div', { class: 'pv-opts', role: 'radiogroup', 'aria-labelledby': ids.printer }, m.printers.map((p, i) => el('button', {
					type: 'button', class: `pv-opt${p.on ? ' is-on' : ''}`, role: 'radio', 'aria-checked': p.on ? 'true' : 'false', tabindex: p.on ? '0' : '-1', 'data-k': `prn:${p.id}`,
					'data-first': p.on ? '' : null, disabled: M.busy, on: { click: () => set({ deviceId: p.id }), keydown: (e) => move(e, i) },
				}, [
					el('span', { class: 'pv-radio', 'aria-hidden': 'true' }),
					el('span', { class: 'pv-opt-tx' }, [el('b', { text: p.name }), el('span', { text: p.sub })]),
					el('span', { class: `pv-chip is-${p.chip.tone}`, text: p.chip.text }),
				])));
			}

			function copiesRow(m) {
				const c = m.copies;
				const input = el('input', {
					type: 'text', inputmode: 'numeric', class: 'pv-num', 'data-k': 'copies', 'aria-labelledby': ids.copies, value: String(c.value), maxlength: '2', autocomplete: 'off', disabled: M.busy,
					on: {
						input: () => {
							const n = Number(String(input.value).replace(/\D/g, ''));
							if (n >= c.min && n <= c.max) { sel.copies = n; paintStatus(); }
						},
						// leaving the field: what was typed becomes a number the printer takes (in place, see paintStatus)
						change: () => {
							sel.copies = Math.min(c.max, Math.max(c.min, Number(String(input.value).replace(/\D/g, '')) || 1));
							input.value = String(sel.copies);
							paintStatus();
						},
						keydown: (e) => {
							if (e.key === 'ArrowUp') { e.preventDefault(); set({ copies: Math.min(c.max, sel.copies + 1) }); }
							else if (e.key === 'ArrowDown') { e.preventDefault(); set({ copies: Math.max(c.min, sel.copies - 1) }); }
							else if (e.key === 'Enter') { e.preventDefault(); set({ copies: Number(String(input.value).replace(/\D/g, '')) || 1 }); submit(); }
						},
					},
				});
				return el('div', { class: 'pv-inline' }, [
					el('span', { class: 'pv-stepper' }, [
						el('button', { type: 'button', 'data-k': 'less', 'aria-label': t('print.dialog.less'), title: t('print.dialog.less'), disabled: M.busy || c.value <= c.min, on: { click: () => set({ copies: sel.copies - 1 }) } }, [icon('minus', 14)]),
						input,
						el('button', { type: 'button', 'data-k': 'more', 'aria-label': t('print.dialog.more'), title: t('print.dialog.more'), disabled: M.busy || c.value >= c.max, on: { click: () => set({ copies: sel.copies + 1 }) } }, [icon('plus', 14)]),
					]),
					el('span', { text: c.hint }),
				]);
			}

			function select(id, key, field, model1) {
				const s = el('select', { class: 'inp pv-sel', 'data-k': key, 'aria-labelledby': id, disabled: M.busy || model1.disabled === true, on: { change: () => set({ [field]: s.value }) } },
					model1.options.map((x) => el('option', { value: x.value, text: x.label, selected: x.value === model1.value })));
				return s;
			}

			openModal(() => {
				const m = model();
				const one = list.length === 1 ? list[0] : null;
				const row = (id, label, control) => [el('div', { id, class: 'pv-lab', text: label }), el('div', { class: 'pv-ctl' }, [control])];
				return [
					el('h2', { id: M.titleId, class: 'pv-dlg-h', text: t('print.dialog.title') }),
					el('div', { class: 'pv-file', 'data-files': String(list.length) }, [
						icon(one ? (one.kind === 'image' ? 'image' : 'file') : 'files', 22, '1.7'),
						el('div', { class: 'pv-file-tx' }, one
							? [el('b', { text: one.name, title: one.name }), el('span', { text: PS.fileLine(one, t, locale()) })]
							: [el('b', { text: PS.plural(t, 'print.dialog.files', list.length) }), el('span', { class: 'pv-file-names', text: list.map((f) => f.name).join(', ') }), el('span', { text: t('print.dialog.each') })]),
					]),
					rejectedNote ? el('div', { class: 'pv-note is-warn', role: 'note', 'data-rejected': '' }, [icon('warn', 16), el('div', { text: rejectedNote })]) : null,
					el('div', { class: 'pv-grid' }, [
						...row(ids.printer, t('print.dialog.printer'), radios(m)),
						...row(ids.copies, t('print.dialog.copies'), copiesRow(m)),
						...row(ids.color, t('print.dialog.color'), el('div', { class: 'pv-inline' }, [
							el('div', { class: 'seg pv-seg', role: 'group', 'aria-labelledby': ids.color }, [
								el('button', { type: 'button', class: m.color.value ? 'on' : '', 'data-k': 'color-on', 'aria-pressed': m.color.value ? 'true' : 'false', disabled: M.busy || m.color.disabled, text: t('print.dialog.colorOn'), on: { click: () => set({ color: true }) } }),
								el('button', { type: 'button', class: m.color.value ? '' : 'on', 'data-k': 'color-off', 'aria-pressed': m.color.value ? 'false' : 'true', disabled: M.busy || m.color.disabled, text: t('print.dialog.colorOff'), on: { click: () => set({ color: false }) } }),
							]),
							m.color.hint ? el('span', { 'data-color-hint': '', text: m.color.hint }) : null,
						])),
						...(m.duplex.show ? row(ids.duplex, t('print.dialog.duplex'), el('div', { class: 'pv-inline' }, [
							el('button', { type: 'button', class: `sw${m.duplex.value ? ' on' : ''}`, role: 'switch', 'aria-checked': m.duplex.value ? 'true' : 'false', 'aria-labelledby': ids.duplex, 'data-k': 'duplex', disabled: M.busy, on: { click: () => set({ duplex: !sel.duplex }) } }, [el('span')]),
							el('span', { text: m.duplex.text }),
						])) : []),
						...(m.paper.show ? row(ids.paper, t('print.dialog.paper'), select(ids.paper, 'paper', 'media', m.paper)) : []),
						...(m.tray.show ? row(ids.tray, t('print.dialog.tray'), select(ids.tray, 'tray', 'source', m.tray)) : []),
					]),
					el('div', { class: 'pv-note is-info', role: 'note' }, [icon('info', 16), el('div', { text: t('print.dialog.info') })]),
					el('div', { class: 'pv-banners', 'data-banners': '' }, m.banners.map(banner)),
					M.error ? el('div', { class: 'pv-dlg-err', role: 'alert', text: M.error }) : null,
					el('div', { class: 'pv-dlg-acts' }, [
						el('span', { class: 'pv-left', text: m.left }),
						el('button', { type: 'button', class: 'btn btn-ghost btn-sm', 'data-k': 'cancel', text: t('print.cancel'), disabled: M.busy, on: { click: () => closeModal(true) } }),
						el('button', { type: 'button', class: 'btn btn-pri btn-sm', 'data-k': 'submit', disabled: M.busy || !m.canSubmit, on: { click: () => submit() } }, [icon('printer', 14), el('span', { text: t(M.busy ? 'print.dialog.sending' : 'print.dialog.go') })]),
					]),
				];
			}, forget);
		}

		// ── Ways into the dialog ─────────────────────────────
		/** "Datei drucken …": the file dialog of the main process. */
		async function pick() {
			if (!usable()) return;
			const r = await call(() => api.pick());
			if (!r || !r.ok) { if (r && r.code !== 'cancelled') toast(PS.errorText(r, t), 'error'); return; }
			await openPrint(r.files, r.rejected);
		}

		/** Files dropped from the Explorer (File objects; the preload reads their paths) — `pending`: the core's answer on its way. */
		async function printDropped(fileList, pending) {
			if (!usable() || !fileList || !fileList.length) return;
			const r = await (pending || call(() => api.addDropped(fileList)));
			if (!r || !r.ok) { toast(PS.errorText(r, t), 'error'); return; }
			await openPrint(r.files, r.rejected);
		}

		/** Files of Drive by their node ids; a file of a vault only after the person said yes. */
		async function printDrive(ids) {
			const list = (Array.isArray(ids) ? ids : []).filter((x) => Number.isSafeInteger(x) && x > 0);
			if (!usable() || !list.length) return;
			let r = await call(() => api.addDrive(list));
			if (!r || !r.ok) { toast(PS.errorText(r, t), 'error'); return; }
			if (r.rejected.some((x) => x.code === 'vault_confirm')) {
				const yes = await askVault();
				if (r.files.length) call(() => api.forget(r.files.map((f) => f.token)));
				if (!yes) return;
				r = await call(() => api.addDrive(list, { vault: true }));
				if (!r || !r.ok) { toast(PS.errorText(r, t), 'error'); return; }
			}
			await openPrint(r.files, r.rejected);
		}

		// ── Dropping files: the page, and the entry in the side bar ──
		const dragKind = (e) => {
			const types = e.dataTransfer ? Array.from(e.dataTransfer.types || []) : [];
			return types.includes(DRIVE_DRAG) ? 'drive' : types.includes('Files') ? 'files' : null;
		};

		function dropZone(node, mark) {
			let depth = 0;
			const off = () => { depth = 0; mark(false); };
			node.addEventListener('dragenter', (e) => { if (!usable() || !dragKind(e)) return; e.preventDefault(); depth++; mark(true); });
			node.addEventListener('dragover', (e) => {
				if (!usable() || !dragKind(e)) return;
				e.preventDefault();
				e.stopPropagation();
				if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
				mark(true);
			});
			node.addEventListener('dragleave', (e) => { if (e.relatedTarget && node.contains(e.relatedTarget)) return; depth = Math.max(0, depth - 1); if (!depth) off(); });
			node.addEventListener('drop', (e) => {
				const kind = usable() ? dragKind(e) : null;
				off();
				if (!kind) return;
				e.preventDefault();
				e.stopPropagation();
				if (kind === 'drive') {
					let ids = [];
					try { ids = JSON.parse(e.dataTransfer.getData(DRIVE_DRAG) || '[]'); } catch { ids = []; }
					printDrive(Array.isArray(ids) ? ids : []);
				} else {
					// the files are read while the event is alive: its list is empty once the handler returns
					const files = Array.from(e.dataTransfer.files || []);
					let pending = null;
					try { pending = files.length ? Promise.resolve(api.addDropped(files)).catch(fail) : null; } catch (err) { pending = Promise.resolve(fail(err)); }
					printDropped(files, pending);
				}
			});
			document.addEventListener('dragend', off);
		}

		dropZone(rootEl, (on) => {
			const d = refs.drop && refs.drop.isConnected ? refs.drop : null;
			if (!d) return;
			d.classList.toggle('is-over', on);
			const title = d.querySelector('[data-drop-title]');
			if (title) title.textContent = t(on ? 'print.drop.active' : 'print.drop.title');
		});
		if (o.navEl) dropZone(o.navEl, (on) => { o.navEl.classList.toggle('is-drop', on); if (on) o.navEl.setAttribute('title', t('print.drop.nav')); else o.navEl.removeAttribute('title'); });

		// ── Wiring ───────────────────────────────────────────
		if (typeof api.onState === 'function') api.onState(setStatus);
		if (typeof api.onPush === 'function') api.onPush(onPush);
		if (typeof api.onTransfers === 'function') api.onTransfers(onTransfers);
		if (typeof api.onJob === 'function') api.onJob(onJob);
		call(() => api.status()).then((st) => { if (st && st.state) setStatus(st); });
		call(() => api.transfers()).then((r) => { if (r && r.ok && Array.isArray(r.transfers)) onTransfers(r.transfers); });

		return {
			show() {
				S.shown = true;
				render();
				load(true);
			},
			hide() {
				S.shown = false;
			},
			/** A push target ({ type: 'print', kind, jobId }): the job is marked once the list has it. */
			open(ctx) {
				if (ctx && ctx.jobId) S.focusJob = ctx.jobId;
				if (S.shown) load(true);
			},
			relabel() {
				refs.h.textContent = t('print.title');
				refs.sub.textContent = t('print.sub');
				refs.pickLabel.textContent = t('print.pick');
				refs.refresh.title = t('print.refresh');
				refs.refresh.setAttribute('aria-label', t('print.refresh'));
				// the number at the entry is read out in the new language
				S.count = -1;
				render();
				renderModal();
			},
			status: () => S.status,
			/** Does Drive offer "Drucken …" for this node (the plugin is there, the person may print, the type fits)? */
			canPrint: (n) => usable() && PS.printable(n),
			usable,
			printDrive,
			printDropped,
			pick,
		};
	}

	root.GCPrintView = { mount };
})(typeof self !== 'undefined' ? self : this);
