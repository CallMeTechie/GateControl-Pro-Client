/**
 * GateControl -- Drive: AI in Drive, Drive 1.14 (renderer view)
 *
 * Only with the features `me` reports; the AI only suggests, the person takes it:
 * - "Fristen" (D2): the deadlines of every file the person reads by month — kind, day and "in N Tagen", the file
 *   (opens its details), "In den Familienkalender" / "Im Familienkalender ✓" ('deadlineCalendar') and the reminder.
 * - "Ablegen" (D4): after a document went up and Drive recognised it ('docAi'), a bar "Vorschlag · Ablegen als … in
 *   …" with "An die Zahlung am … erinnern", "Übernehmen", "Anderer Ordner" and ✕. It waits for the recognition up to a
 *   minute (Drive's live event or a look every few seconds), else it stays away.
 * - "In Dokument umwandeln" (D5, 'scanDocs'): "Scan prüfen" for one or more pictures — "Erkannt: Tabelle", the formats
 *   (PDF · Word · Excel · Nur Bild), the preview, name and folder (Drive's suggestion first), "Original-Scan behalten",
 *   the cost line, "Als Excel-Datei speichern" …; printed text becomes a searchable PDF on this PC (Windows OCR).
 * - Questions (D1, 'docAsk'): the answer card in the list — the answer, "Frist in den Familienkalender" when a source
 *   has a deadline, the sources with their quotes (open the file), "nichts gefunden" with what was searched.
 *
 * Data: window.gatecontrol.drive (calendar, ask, scan.*, insight, applyInsight, remind, deadlines); logic:
 * drive-ki-state.js (window.GCDriveKiState); texts: drive.ki.*. Server text only via textContent.
 */
(function (root) {
	'use strict';

	const KS = root.GCDriveKiState;
	const DD = root.GCDriveDocsState;
	const KEEP_KEY = 'gc.drive.scan.keep';

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive
	 * @param {Function} o.t
	 * @param {() => string} o.getLocale
	 * @param {object} o.ui - { el, icon, clear, openDialog } of drive-view.js
	 * @param {HTMLElement} o.host
	 * @param {Function} o.toast
	 * @param {Function} o.errorText - (res, t) → text
	 * @param {() => object} o.getMe
	 * @param {() => object[]} o.getAreas
	 * @param {(areaId: string) => string} o.areaLabel
	 * @param {Function} o.pickFolder - drive-view.js pickFolder (opts) → { folderId, path } | null
	 * @param {Function} o.folderPath - (folderId) → Promise<string> "Meine Dateien › Haus"
	 * @param {(folderId: number) => string|null} o.areaOfFolder - the area a folder of the page lies in
	 * @param {(nodeId: number) => void} o.openFile
	 * @param {(node) => void} [o.details] - "Details" of a file
	 * @param {() => void} o.changed - something moved / was made: the page reloads what it shows
	 * @param {() => number} [o.now]
	 */
	function create(o) {
		const { el, icon, clear, openDialog } = o.ui;
		const t = o.t;
		const api = o.api;
		const now = typeof o.now === 'function' ? o.now : () => Date.now();
		const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed' });
		const feats = () => KS.features(o.getMe());
		const store = (() => { try { return root.localStorage || null; } catch { return null; } })();

		// ── D2: "Fristen" ──────────────────────────────

		function reminderSelect(d, title) {
			const v = DD.deadlineView(d, { t, locale: o.getLocale(), now: now() });
			const sel = el('select', { class: 'dv-input dv-dl-remind', 'aria-label': t('drive.deadline.remind.label', { what: title }) });
			for (const opt of DD.reminderOptions(t)) sel.appendChild(el('option', { value: opt.value, text: opt.label }));
			sel.value = v.value;
			sel.disabled = v.past;
			sel.classList.toggle('is-set', !!v.value);
			sel.addEventListener('change', async () => {
				sel.disabled = true;
				const r = await Promise.resolve(api.remind(d.id, DD.reminderDays(sel.value))).catch(fail);
				sel.disabled = false;
				if (r && r.ok) {
					Object.assign(d, r.deadline);
					sel.classList.toggle('is-set', !!sel.value);
					o.toast(DD.reminderDays(sel.value) === null ? t('drive.deadline.remind.off') : t('drive.deadline.remind.set'), 'success');
				} else {
					sel.value = v.value;
					o.toast(o.errorText(r, t), 'error');
				}
			});
			return sel;
		}

		/** "In den Familienkalender" of deadline `d` → the button (it turns into "Im Familienkalender ✓"). */
		function calendarBtn(d, card, onDone) {
			const b = el('button', { type: 'button', class: 'btn btn-sec btn-sm dv-ki-cal' });
			const paint = () => {
				const v = KS.calendarButton(card, t);
				clear(b);
				b.classList.toggle('is-done', v.done);
				b.disabled = v.done;
				b.append(icon(v.done ? 'check' : 'calendar', 14), el('span', { text: v.label }));
			};
			paint();
			b.addEventListener('click', async () => {
				if (card.calendar) return;
				b.disabled = true;
				const r = await Promise.resolve(api.calendar(d.id)).catch(fail);
				if (r && r.ok) {
					Object.assign(d, r.deadline);
					card.calendar = true;
					o.toast(t('drive.ki.dl.added'), 'success');
					if (onDone) onDone(r.deadline);
				} else {
					o.toast(r && r.code === 'familie_unavailable' ? t('drive.err.familieUnavailable') : o.errorText(r, t), 'error');
				}
				paint();
			});
			return b;
		}

		/** "Fristen" into `list` (the page's list): by month, each a card. */
		async function renderDeadlines(list, { onOpen } = {}) {
			clear(list);
			list.appendChild(el('div', { class: 'dv-empty', text: t('drive.loading') }));
			const r = await Promise.resolve(api.deadlines()).catch(fail);
			clear(list);
			if (!r || !r.ok) {
				list.appendChild(el('div', { class: 'dv-empty' }, [icon('alert', 26, '1.6'), el('span', { text: o.errorText(r, t) })]));
				return r;
			}
			const months = KS.deadlineMonths(r.deadlines, { t, locale: o.getLocale(), now: now(), calendar: feats().calendar });
			if (!months.length) {
				list.appendChild(el('div', { class: 'dv-empty' }, [icon('calendar', 28, '1.6'), el('span', { text: t('drive.deadline.empty') })]));
				return r;
			}
			const byId = new Map(r.deadlines.map((d) => [d.id, d]));
			list.appendChild(el('p', { class: 'dv-ki-note', text: t('drive.ki.dl.note') }));
			for (const m of months) {
				list.appendChild(el('div', { class: 'dv-dl-group lbl', 'data-month': m.key, text: m.title }));
				for (const c of m.items) {
					const d = byId.get(c.id);
					const file = el('button', { type: 'button', class: 'dv-dl-file', title: t('drive.doc.details'), on: { click: () => (onOpen ? onOpen(c.node) : o.details && o.details(c.node)) } }, [icon('file', 13), el('span', { text: c.file })]);
					list.appendChild(el('div', { class: `dv-dl dv-ki-dl${c.urgent ? ' is-urgent' : ''}${c.past ? ' is-past' : ''}`, 'data-deadline': String(c.id), role: 'group', 'aria-label': `${c.tag}: ${c.title}` }, [
						el('div', { class: 'dv-ki-dl-top' }, [
							el('span', { class: 'dv-ki-tag', text: c.tag }),
							el('span', { class: 'dv-dl-date', text: [c.day, c.when].filter(Boolean).join(' · ') }),
						]),
						el('span', { class: 'dv-ki-dl-title', text: c.title }),
						file,
						el('div', { class: 'dv-ki-acts' }, [
							c.canCalendar || c.calendar ? calendarBtn(d, c) : null,
							reminderSelect(d, c.title),
						]),
					]));
				}
			}
			return r;
		}

		// ── D4: "Ablegen" after an upload ──────────────

		const bar = el('div', { class: 'dv-ki-bar', role: 'region', 'aria-label': t('drive.ki.file.region'), hidden: true });
		const seen = new Set();
		let primed = false;
		let watch = null;     // { nodeId, name, until, timer, busy }

		function hideBar() {
			bar.hidden = true;
			clear(bar);
		}

		function stopWatch() {
			if (watch && watch.timer) clearTimeout(watch.timer);
			watch = null;
		}

		/** The rows of the transfer list: a document that went up just now is watched for Drive's suggestion. */
		function onTransfers(rows) {
			if (!primed) { primed = true; for (const r of rows || []) if (r && r.state === 'done') seen.add(r.id); return; }
			const up = KS.newUpload(rows, seen, { me: o.getMe() });
			if (!up) return;
			const area = (o.getAreas() || []).find((a) => a.id === o.areaOfFolder(up.folderId)) || null;
			if (area && area.docAi === false) return;
			stopWatch();
			hideBar();
			watch = { ...up, until: now() + KS.WATCH_MS, timer: null, busy: false };
			look();
		}

		/** Drive changed (live event): look now. */
		function onRemote() {
			if (watch && !watch.busy) { clearTimeout(watch.timer); look(); }
		}

		async function look() {
			const w = watch;
			if (!w) return;
			w.busy = true;
			const r = await Promise.resolve(api.insight(w.nodeId)).catch(fail);
			w.busy = false;
			if (watch !== w) return;
			const st = r && r.ok && r.insight ? r.insight.status : null;
			if (st === 'ready') {
				stopWatch();
				showBar(w, r.insight, { id: w.nodeId, name: w.name, parentId: w.folderId, areaId: o.areaOfFolder(w.folderId) });
				return;
			}
			if (st === 'off' || st === 'failed' || (r && !r.ok && r.code !== 'network' && r.code !== 'offline') || now() >= w.until) { stopWatch(); return; }
			w.timer = setTimeout(look, 5000);
		}

		function showBar(w, ins, node) {
			const v = KS.fileBar(ins, node, { areaLabel: o.areaLabel, t, locale: o.getLocale() });
			if (!v) return;
			clear(bar);
			const remind = v.payment ? el('input', { type: 'checkbox', class: 'dv-ki-remind', checked: true }) : null;
			const take = async (btn, folderId) => {
				btn.disabled = true;
				let r = null;
				if (folderId) {
					r = v.renamed ? await Promise.resolve(api.applyInsight(node.id, { name: true })).catch(fail) : { ok: true };
					if (r && r.ok) r = await Promise.resolve(api.move(node.id, folderId)).catch(fail);
				} else {
					r = await Promise.resolve(api.applyInsight(node.id, { name: v.renamed, folder: v.folder })).catch(fail);
				}
				if (!r || !r.ok) { btn.disabled = false; o.toast(o.errorText(r, t), 'error'); return; }
				if (remind && remind.checked) {
					const rr = await Promise.resolve(api.remind(v.payment.id, 3)).catch(fail);
					if (!rr || !rr.ok) o.toast(o.errorText(rr, t), 'error');
				}
				hideBar();
				o.toast(t('drive.ki.file.done'), 'success');
				o.changed();
			};
			const ok = el('button', { type: 'button', class: 'btn btn-pri btn-sm dv-ki-take', text: t('drive.ki.file.take') });
			ok.addEventListener('click', () => take(ok, null));
			const other = el('button', { type: 'button', class: 'btn btn-sec btn-sm dv-ki-other', text: t('drive.ki.file.other') });
			other.addEventListener('click', async () => {
				const to = await o.pickFolder({ title: t('drive.ki.file.otherTitle'), confirm: t('drive.moveHere'), remember: false });
				if (to && to.folderId) take(other, to.folderId);
			});
			bar.append(
				el('span', { class: 'dv-ki-bar-h' }, [icon('folder', 15), el('span', { text: t('drive.ki.file.suggestion') })]),
				el('div', { class: 'dv-ki-bar-tx' }, [
					el('span', { class: 'dv-ki-d', text: t('drive.ki.file.as') }),
					el('span', { class: 'dv-ki-t dv-ki-name', text: v.name }),
					v.path ? el('span', { class: 'dv-ki-d', text: t('drive.ki.file.in') }) : null,
					v.path ? el('span', { class: 'dv-ki-t dv-ki-path', text: v.path }) : null,
				]),
				remind ? el('label', { class: 'dv-ki-check' }, [remind, el('span', { text: t('drive.ki.file.remind', { day: v.payment.day }) })]) : null,
				el('div', { class: 'dv-ki-bar-acts' }, [
					ok,
					other,
					el('button', { type: 'button', class: 'dv-ib dv-ki-x', 'aria-label': t('drive.ki.file.dismiss'), title: t('drive.ki.file.dismiss'), on: { click: () => hideBar() } }, [icon('close', 15)]),
				]),
			);
			bar.hidden = false;
		}

		// ── D5: "Scan prüfen" ──────────────────────────

		/** "In Dokument umwandeln" of the pictures `items` (one scan, its pages in this order). */
		function scanDialog(items) {
			const pages = items.length;
			const dlg = openDialog({ title: t('drive.ki.scan.title'), host: o.host, wide: true, closeLabel: t('drive.close'), onClose: () => { if (S.scan && !S.saved) Promise.resolve(api.scan.discard(S.scan.scanId)).catch(() => {}); } });
			dlg.box.classList.add('dv-ki-scan');
			const S = { scan: null, fmt: null, name: '', folderId: null, folderPath: '', keep: true, saved: false };
			try { S.keep = !store || store.getItem(KEEP_KEY) !== '0'; } catch { S.keep = true; }
			const body = el('div', { class: 'dv-ki-scan-body' }, [el('div', { class: 'dv-pick-note', text: t('drive.ki.scan.reading', { count: pages }) })]);
			const errEl = el('span', { class: 'dv-dlg-err', role: 'alert' });
			const save = el('button', { type: 'button', class: 'btn btn-pri dv-ki-save', disabled: true, text: t('drive.ki.scan.save.pdf') });
			dlg.body.appendChild(body);
			dlg.foot.append(errEl, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), save);
			const first = items[0];
			// the picture of the first page (the scan itself)
			const shot = el('span', { class: 'dv-ki-shot' }, [icon('image', 22, '1.6')]);
			const pic = el('div', { class: 'dv-ki-pic' }, [icon('image', 30, '1.4')]);
			if (first.mediaId) {
				Promise.resolve(api.preview(first.mediaId, { large: true })).then((r) => {
					if (!r || !r.ok || !r.data) return;
					const u = URL.createObjectURL(new Blob([r.data], { type: r.mime || 'image/jpeg' }));
					shot.classList.add('has-img');
					shot.appendChild(el('img', { src: u, alt: '' }));
					pic.classList.add('has-img');
					clear(pic).appendChild(el('img', { src: u, alt: '' }));
				}).catch(() => {});
			}

			function render() {
				const v = KS.scanView(S.scan, S.fmt, t);
				S.fmt = v.format;
				clear(body);
				body.appendChild(el('div', { class: 'dv-ki-card dv-ki-kind' }, [
					shot,
					el('div', { class: 'dv-ki-kind-tx' }, [
						el('span', { class: 'dv-ki-ok', 'data-kind': v.kind }, [icon(v.kind === 'table' ? 'table' : 'file', 15), el('span', { text: v.title })]),
						v.summary ? el('span', { class: 'dv-ki-t', text: v.summary }) : null,
						el('span', { class: 'dv-ki-d', text: pages > 1 ? `${t('drive.ki.scan.pages', { count: pages })} · ${v.ask}` : v.ask }),
					]),
				]));
				const chips = el('div', { class: 'dv-ki-chips', role: 'radiogroup', 'aria-label': t('drive.ki.scan.format.label') });
				for (const c of v.chips) {
					chips.appendChild(el('button', { type: 'button', role: 'radio', 'aria-checked': c.on ? 'true' : 'false', class: `dv-chip${c.on ? ' is-on' : ''}`, 'data-format': c.key, text: c.label, on: { click: () => { S.fmt = c.key; render(); } } }));
				}
				body.appendChild(chips);
				body.appendChild(el('div', { class: 'dv-ki-card dv-ki-preview', 'data-format': v.format }, [
					el('span', { class: 'dv-ki-d', text: t('drive.ki.scan.preview.label') }),
					el('div', { class: `dv-ki-pv is-${v.format}` }, [pic, v.format !== 'image' && v.format !== 'pdf' ? el('span', { class: 'dv-ki-pv-badge', text: v.format === 'xlsx' ? 'XLSX' : 'DOCX' }) : null]),
					el('span', { class: 'dv-ki-d', text: v.preview }),
				]));
				const nameId = `dv-ki-name-${Math.random().toString(36).slice(2, 8)}`;
				const input = el('input', { id: nameId, type: 'text', class: 'dv-input dv-ki-name-in', maxlength: '240', spellcheck: 'false', value: S.name });
				input.addEventListener('input', () => { S.name = input.value; check(); });
				const ext = KS.scanExt(v.format, first.name);
				body.appendChild(el('div', { class: 'dv-ki-card dv-ki-where' }, [
					el('div', { class: 'dv-ki-row' }, [
						el('label', { class: 'dv-ki-d', for: nameId, text: t('drive.ki.scan.name') }),
						el('div', { class: 'dv-ki-name-row' }, [input, el('span', { class: 'dv-ki-ext', text: ext })]),
					]),
					el('div', { class: 'dv-ki-row is-line' }, [
						el('span', { class: 'dv-ki-row-tx' }, [el('span', { class: 'dv-ki-d', text: t('drive.ki.scan.folder') }), el('span', { class: 'dv-ki-t dv-ki-folder', text: S.folderPath || '…' })]),
						el('button', { type: 'button', class: 'btn btn-sec btn-sm dv-ki-change', text: t('drive.ki.scan.change'), on: { click: () => changeFolder() } }),
					]),
					v.format === 'image' ? null : el('label', { class: 'dv-ki-row is-line' }, [
						el('span', { class: 'dv-ki-t', text: t('drive.ki.scan.keep') }),
						switchEl(S.keep, (on) => { S.keep = on; try { if (store) store.setItem(KEEP_KEY, on ? '1' : '0'); } catch { /* private */ } }),
					]),
				]));
				body.appendChild(el('span', { class: 'dv-ki-d dv-ki-cost', text: v.cost }));
				save.textContent = v.save;
				check();
			}

			function switchEl(on, fn) {
				const sw = el('button', { type: 'button', class: `sw dv-ki-keep${on ? ' on' : ''}`, role: 'switch', 'aria-checked': on ? 'true' : 'false', 'aria-label': t('drive.ki.scan.keep') }, [el('span')]);
				sw.addEventListener('click', (e) => {
					e.preventDefault();
					const next = sw.getAttribute('aria-checked') !== 'true';
					sw.setAttribute('aria-checked', next ? 'true' : 'false');
					sw.classList.toggle('on', next);
					fn(next);
				});
				return sw;
			}

			function check() {
				const name = String(S.name || '').trim();
				const e = name ? root.GCDriveState.nameError(name + KS.scanExt(S.fmt, first.name), t) : t('drive.ki.scan.noName');
				errEl.textContent = name ? (e || '') : '';
				save.disabled = !S.scan || !!e || !S.folderId;
			}

			async function changeFolder() {
				const to = await o.pickFolder({ title: t('drive.ki.scan.folderTitle'), confirm: t('drive.picker.here'), startId: S.folderId || undefined });
				if (!to || !to.folderId) return;
				S.folderId = to.folderId;
				S.folderPath = to.path;
				render();
			}

			save.addEventListener('click', async () => {
				save.disabled = true;
				errEl.textContent = '';
				const target = S.fmt;
				const r = await Promise.resolve(api.scan.save(S.scan.scanId, { target, folderId: S.folderId, name: String(S.name).trim(), keepOriginal: S.keep })).catch(fail);
				if (!r || !r.ok) { save.disabled = false; errEl.textContent = o.errorText(r, t); return; }
				S.saved = true;
				dlg.close(r);
				o.toast(t('drive.ki.scan.saved', { name: r.node.name }), 'success');
				o.changed();
			});

			(async () => {
				const r = await Promise.resolve(api.scan.prepare(items.map((n) => n.id))).catch(fail);
				if (dlg.closed) { if (r && r.ok) Promise.resolve(api.scan.discard(r.scanId)).catch(() => {}); return; }
				if (!r || !r.ok) {
					clear(body);
					body.appendChild(el('div', { class: 'dv-dlg-err', text: r && r.code === 'not_picture' ? t('drive.err.notPicture') : o.errorText(r, t) }));
					return;
				}
				S.scan = r;
				const start = KS.scanStart(r);
				S.name = start.name;
				S.folderId = start.folderId;
				S.fmt = KS.scanDefault(r.kind, r.pages);
				S.folderPath = start.folderPath !== null && start.folderId
					? [o.areaLabel(r.areaId), ...String(start.folderPath).split('/').filter(Boolean)].join(' › ')
					: await Promise.resolve(o.folderPath(S.folderId)).catch(() => '');
				if (!dlg.closed) render();
			})();
			return dlg;
		}

		// ── D1: the answer card ────────────────────────

		/** The answer of `state` ({ q, loading, answer, error }) into `list`. */
		function renderAnswer(list, state) {
			clear(list);
			const wrap = el('div', { class: 'dv-ki-ask' });
			list.appendChild(wrap);
			if (state.loading) {
				wrap.appendChild(el('div', { class: 'dv-empty' }, [icon('search', 26, '1.6'), el('span', { text: t('drive.ki.ask.loading') })]));
				return;
			}
			if (state.error) {
				const rl = state.error.code === 'rate_limited' || state.error.code === 'http_429';
				wrap.appendChild(el('div', { class: 'dv-empty' }, [icon('alert', 26, '1.6'), el('span', { text: rl ? t('drive.ki.ask.limited') : o.errorText(state.error, t) })]));
				return;
			}
			const a = state.answer;
			const v = KS.answerView(a, { t, areas: o.getAreas(), areaLabel: (ar) => o.areaLabel(ar.id) });
			const card = el('div', { class: `dv-ki-card dv-ki-answer${v.found ? '' : ' is-none'}`, role: 'status' });
			card.appendChild(el('p', { class: `dv-ki-answer-tx${v.found ? '' : ' dv-ki-t'}`, text: v.text }));
			if (v.found) {
				const acts = el('div', { class: 'dv-ki-acts' });
				card.appendChild(acts);
				if (feats().calendar) {
					Promise.resolve(api.deadlines()).then((r) => {
						const d = r && r.ok ? KS.answerDeadline(a, r.deadlines, now()) : null;
						if (!d || !card.isConnected) return;
						const c = KS.deadlineCard(d, { t, locale: o.getLocale(), now: now(), calendar: true });
						const b = calendarBtn(d, c);
						b.querySelector('span').textContent = t('drive.ki.ask.toCalendar');
						b.title = `${c.tag}: ${c.title} · ${c.day}`;
						acts.appendChild(b);
					}).catch(() => {});
				}
				card.appendChild(el('div', { class: 'dv-ki-d dv-ki-src-n', text: v.count }));
				for (const s of v.sources) {
					card.appendChild(el('button', { type: 'button', class: 'dv-ki-src', 'data-node': String(s.nodeId), title: t('drive.openFile'), on: { click: () => o.openFile(s.nodeId) } }, [
						el('span', { class: 'dv-row-ic' }, [icon('file', 16)]),
						el('span', { class: 'dv-ki-src-tx' }, [
							el('span', { class: 'dv-ki-t', text: s.name }),
							s.where ? el('span', { class: 'dv-ki-d', text: s.where }) : null,
							s.quote ? el('span', { class: 'dv-ki-quote', text: s.quote }) : null,
						]),
					]));
				}
			} else if (v.searched) {
				card.appendChild(el('span', { class: 'dv-ki-d', text: v.searched }));
			}
			wrap.appendChild(card);
			wrap.appendChild(el('p', { class: 'dv-ki-d dv-ki-hint', text: t('drive.ki.ask.hint') }));
		}

		return { renderDeadlines, bar, onTransfers, onRemote, hideBar, scanDialog, renderAnswer, available: (items, writable) => KS.scanAvailable(items, { me: o.getMe(), writable }) };
	}

	root.GCDriveKiView = { create };
})(typeof self !== 'undefined' ? self : this);
