/**
 * GateControl -- Notizen & Aufgaben: view logic without DOM (renderer)
 *
 * Dates as the lists show them (heute, morgen, Fr. 13. Nov.), the line under a task or an item, the chips of the quick
 * entry (the plugin's own ui/quickparse.js: vendor/notizen, window.GCQuickParse), the repeat choices, where tapping an
 * item of another plugin leads (contract docs/notes-sources-contract.md § 5: Mail's mail, Drive's deadline, Schule —
 * the other plugins' portal tab), texts of failures, of the Tresor states and of an import. window.GCNotesState.
 */
(function (root) {
	'use strict';

	const RP = () => root.GCRepeat;
	const QP = () => root.GCQuickParse;
	const SOURCE_TONE = {
		'gatecontrol-mail': 'info', 'gatecontrol-drive': 'ok', 'gatecontrol-schule': 'pro', 'gatecontrol-familie': 'warn', 'gatecontrol-alltag': 'neutral',
	};
	const COLORS = ['none', 'yellow', 'green', 'blue', 'pink', 'grey', 'orange', 'purple'];

	const str = (v) => (typeof v === 'string' ? v : '');
	const pad = (n) => (n < 10 ? '0' : '') + n;

	/** 'heute' | 'morgen' | 'gestern' | 'Fr. 13. Nov.' (with the year when it is another one). */
	function dayText(date, today, t) {
		if (!date) return '';
		const R = RP();
		if (date === today) return t('notes.w.today');
		if (date === R.addDays(today, 1)) return t('notes.w.tomorrow');
		if (date === R.addDays(today, -1)) return t('notes.w.yesterday');
		const p = date.split('-');
		return `${t(`notes.wd.${R.weekday(date)}`)} ${Number(p[2])}. ${t(`notes.mo.${Number(p[1])}`)}${p[0] !== String(today || '').slice(0, 4) ? ` ${p[0]}` : ''}`;
	}

	/** 'Sonntag, 8. November' */
	function longDate(date, t) {
		if (!date) return '';
		const p = date.split('-');
		return `${t(`notes.wdl.${RP().weekday(date)}`)}, ${Number(p[2])}. ${t(`notes.mol.${Number(p[1])}`)}`;
	}

	/** The time a row shows on the right ('9:00' today, 'bis morgen' for homework, else the day). */
	function whenText(x, today, t) {
		const d = x && (x.show || x.due);
		if (!d) return '';
		const time = d.time ? d.time.replace(/^0/, '') : '';
		if (time && d.date === today) return time;
		if (x.type === 'source' && x.kind === 'homework' && x.due && x.due.date === RP().addDays(today, 1)) return t('notes.w.untilTomorrow');
		return dayText(d.date, today, t) + (time ? ` ${time}` : '');
	}

	/** The chip of a row's source ('Mail · Zu tun', 'Drive · Frist') → { text, tone } or null. */
	function sourceChip(x, t) {
		if (!x || !x.source) return null;
		const plugin = x.source.plugin;
		const label = x.type === 'source' ? x.source.label : t(`notes.src.${plugin}`);
		const kind = x.type === 'source' && ['deadline', 'homework', 'exam'].includes(x.kind) ? ` · ${t(`notes.kind.${x.kind}`)}` : '';
		return { text: label + kind, tone: SOURCE_TONE[plugin] || 'neutral' };
	}

	/** The grey line under a row's title → [text]. */
	function metaLine(x, ctx, t) {
		const out = [];
		const me = ctx && ctx.userId;
		if (x.type === 'source') {
			if (x.subtitle) out.push(x.subtitle);
			if (x.meta && x.meta.amount) out.push(String(x.meta.amount));
			if (x.assignee && x.assignee.name && x.assignee.id !== me) out.push(x.assignee.name);
			if (x.meta && x.meta.stars) out.push(t('notes.stars', { n: x.meta.stars }));
		} else {
			const l = ctx && ctx.lists ? ctx.lists.find((y) => y.id === x.listId) : null;
			if (l && !(ctx && ctx.inList)) out.push(`${t(`notes.area.${l.area}`)} › ${l.name}`);
			if (x.assignee && x.assignee.id !== me && x.assignee.name) out.push(x.assignee.name);
			if (x.repeatText) out.push(`↻ ${x.repeatText}`);
			if (x.hasNote) out.push(t('notes.hasNote'));
			if (x.attachments) out.push(t('notes.attachmentsN', { n: x.attachments }));
		}
		if (x.progress && x.progress.total) out.push(x.type === 'task' ? t('notes.subtasksN', { done: x.progress.done, total: x.progress.total }) : `${x.progress.done}/${x.progress.total}`);
		return out;
	}

	/** A section's title ("Erledigt heute" in Mein Tag). */
	const SECTIONS = ['events', 'overdue', 'today', 'upcoming', 'done', 'tomorrow', 'week', 'later', 'open', 'important', 'assigned', 'tasks'];
	function sectionTitle(s, viewId, t) {
		if (s.id === 'done' && viewId === 'myday') return t('notes.v.doneToday');
		// the app's language for the plugin's own sections; a source's groups (an account, a child) as the source names them
		return SECTIONS.includes(s.id) ? t(`notes.v.${s.id}`) : s.title || '';
	}

	/** What the quick entry gets to read a line: today, the time, the lists, the people, the words for the day's times. */
	function quickCtx(me, nav, people) {
		return {
			today: me && me.today, now: me && me.time,
			lists: ((nav && nav.lists) || []).map((l) => ({ id: l.id, name: l.name })),
			people: (people || []).map((p) => ({ id: p.id, name: p.name })),
			times: me && me.prefs ? me.prefs.times : undefined,
		};
	}

	/** The line of the quick entry, read on this PC with the plugin's parser → its result (null for an empty line). */
	function quickParse(text, ctx) {
		const s = str(text).trim();
		if (!s || !ctx || !ctx.today || !QP()) return null;
		try { return QP().parse(s, ctx); } catch { return null; }
	}

	/** The chips under the quick entry ("Erkannt – tippen zum Ändern") → [{ kind, text, plain }]. */
	function quickChips(p, ctx, area, t, lang) {
		if (!p) return [];
		const out = [];
		if (p.date) out.push({ kind: 'date', text: dayText(p.date, ctx.today, t) + (p.time ? `, ${p.time}` : '') });
		if (p.remind) out.push({ kind: 'remind', text: t('notes.quick.remind', { time: p.remind.time }) });
		if (p.repeat) out.push({ kind: 'repeat', text: `↻ ${RP().describe(p.repeat, lang === 'en' ? 'en' : 'de')}` });
		if (p.important) out.push({ kind: 'important', text: t('notes.important') });
		if (p.list) out.push({ kind: 'list', text: t('notes.quick.list', { name: p.list.name }) });
		else if (p.listName) out.push({ kind: 'list', text: t('notes.quick.newList', { name: p.listName }), plain: true });
		if (p.assignee) out.push({ kind: 'person', text: `@${p.assignee.name}` });
		else if (p.assigneeName) out.push({ kind: 'person', text: t('notes.quick.unknownPerson', { name: p.assigneeName }), plain: true });
		out.push({ kind: 'area', text: t(`notes.area.${area === 'work' ? 'work' : 'private'}`), plain: true });
		return out;
	}

	/** The body of POST tasks for the quick entry in the current view. */
	function quickBody(text, p, view, area) {
		const body = { text: str(text).trim(), area, createList: !!(p && p.listName && !p.list) };
		if (view && view.kind === 'list' && !(p && (p.list || p.listName))) body.listId = view.id;
		if (view && view.kind === 'smart' && view.id === 'myday') body.myDay = true;
		if (view && view.kind === 'smart' && view.id === 'important') body.important = true;
		return body;
	}

	/** The choices of "Wiederholen" for a task → { options: [{ value, label, rule }], value } */
	function repeatOptions(task, today, t, lang) {
		const R = RP();
		const wd = R.weekday((task && task.due && task.due.date) || today);
		const opts = [
			{ value: 'none', label: t('notes.r.none'), rule: null },
			{ value: 'daily', label: t('notes.r.daily'), rule: { type: 'daily', interval: 1 } },
			{ value: 'workdays', label: t('notes.r.workdays'), rule: { type: 'weekly', interval: 1, days: [1, 2, 3, 4, 5] } },
			{ value: 'weekly', label: t('notes.r.weekly', { day: t(`notes.wdl.${wd}`) }), rule: { type: 'weekly', interval: 1, days: [wd] } },
			{ value: 'biweekly', label: t('notes.r.biweekly', { day: t(`notes.wdl.${wd}`) }), rule: { type: 'weekly', interval: 2, days: [wd] } },
			{ value: 'monthly', label: t('notes.r.monthly'), rule: { type: 'monthly', interval: 1 } },
			{ value: 'yearly', label: t('notes.r.yearly'), rule: { type: 'yearly', interval: 1 } },
			{ value: 'after', label: t('notes.r.after'), rule: 'after' },
		];
		const cur = task && task.repeat;
		let value = 'none';
		if (cur) {
			const same = opts.find((o) => o.rule && o.rule !== 'after' && JSON.stringify(R.normalize(o.rule)) === JSON.stringify(R.normalize(cur)));
			value = same ? same.value : 'custom';
			if (value === 'custom') opts.push({ value: 'custom', label: R.describe(cur, lang === 'en' ? 'en' : 'de'), rule: cur });
		}
		return { options: opts, value };
	}

	/**
	 * Where tapping an item of another plugin leads (its `open`): a page of this app — Mail's mail, Drive's deadline,
	 * Schule — { page, context }; a note of the hub { page: 'notizen', note }; else the plugin's portal tab
	 * { portal: '/portal#plg-<plugin>' } (the portal link cannot carry the route: the plugin's start screen opens).
	 */
	function openTarget(open, pages) {
		if (!open || typeof open.plugin !== 'string' || !/^gatecontrol-[a-z0-9-]{1,40}$/.test(open.plugin)) return null;
		const route = str(open.route);
		const has = (p) => !pages || pages.includes(p);
		const parts = route.split('/');
		if (open.plugin === 'gatecontrol-mail' && has('mail')) {
			return { page: 'mail', context: parts[0] === 'message' && /^[1-9]\d{0,14}$/.test(str(parts[1])) ? { kind: 'message', messageId: Number(parts[1]), accountId: null } : null };
		}
		if (open.plugin === 'gatecontrol-drive' && has('drive')) {
			return { page: 'drive', context: parts[0] === 'node' && /^[1-9]\d{0,14}$/.test(str(parts[1])) ? { kind: 'deadline', nodeId: Number(parts[1]), deadlineId: null } : null };
		}
		if (open.plugin === 'gatecontrol-schule' && has('schule')) return { page: 'schule', context: null };
		if (open.plugin === 'gatecontrol-notizen') {
			const m = /^note\/([1-9]\d{0,14})$/.exec(route);
			return m ? { page: 'notizen', note: Number(m[1]) } : { page: 'notizen', note: null };
		}
		return { portal: `/portal#plg-${open.plugin}` };
	}

	/** A failure → its text. */
	function errText(res, t) {
		const code = (res && res.code) || 'failed';
		if (res && res.reason === 'read_only') return t('notes.err.read_only');
		if (res && res.reason === 'vaults_off') return t('notes.err.vaults_off');
		const k = `notes.err.${code}`;
		const s = t(k);
		return s && s !== k ? s : t('notes.err.failed', { code });
	}

	/** What a Tresor's state on this PC means → { text, actions: ['unlock' | 'ask' | 'recover'] } */
	function vaultLocked(state, t) {
		if (state === 'unsupported') return { text: t('notes.vault.unsupported'), actions: [] };
		if (state === 'pending') return { text: t('notes.vault.pending'), actions: ['recover'] };
		if (state === 'locked' || state === 'approved') return { text: t('notes.vault.lockedText'), actions: ['unlock', 'recover'] };
		return { text: t('notes.vault.newDevice'), actions: ['ask', 'recover'] };
	}

	/** The title of a note in a list (a Tresor's: its decrypted title, else "Tresor-Notiz"). */
	function noteTitle(n, t) {
		if (n.encrypted && (n.locked || !n.title)) return t('notes.vaultNote');
		return n.title || str(n.snippet).split(' · ')[0].slice(0, 80) || t('notes.untitled');
	}

	/** The name of a notebook in the menu. */
	function notebookName(b, t) {
		if (b.vault) return b.name || t('notes.vault.lockedName');
		if (b.bound) return `${b.name} (${b.bound.label})`;
		return b.name || '';
	}

	/** A date of ms → 'YYYY-MM-DD' (local). */
	function isoDay(ms) {
		const d = new Date(ms);
		return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
	}

	function formatBytes(n, lang) {
		const v = Number(n) || 0;
		const loc = lang === 'en' ? 'en-US' : 'de-DE';
		if (v >= 1073741824) return `${(v / 1073741824).toLocaleString(loc, { maximumFractionDigits: 1 })} GB`;
		if (v >= 1048576) return `${Math.round(v / 1048576).toLocaleString(loc)} MB`;
		if (v >= 1024) return `${Math.round(v / 1024).toLocaleString(loc)} KB`;
		return `${v} B`;
	}

	/** An import event → the line under the progress bar. */
	function importText(e, t) {
		if (!e) return '';
		if (e.state === 'done') return t('notes.import.dsDone', { notes: e.notes || 0, skipped: (e.skipped || 0) + (e.protectedSkipped || 0) }) + (e.protectedSkipped ? ` ${t('notes.import.protSkipped', { n: e.protectedSkipped })}` : '');
		if (e.state === 'failed') return t('notes.import.failed', { code: e.code || 'failed' });
		if (e.state === 'cancelled') return t('notes.import.cancelled');
		return t('notes.import.progress', { done: e.done || 0, total: e.total || 0 });
	}

	/** The key of a group's choice in prefs ('<plugin>|<group id>'). */
	function groupKey(plugin, id) {
		return `${plugin}|${id}`;
	}

	/** 'YYYY-MM-DDTHH:MM' for <input type="datetime-local"> of an ISO time with offset (its wall clock). */
	function localInput(iso) {
		const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(str(iso));
		return m ? `${m[1]}T${m[2]}` : '';
	}

	root.GCNotesState = {
		COLORS, SOURCE_TONE, dayText, longDate, whenText, sourceChip, metaLine, sectionTitle, quickCtx, quickParse, quickChips, quickBody,
		repeatOptions, openTarget, errText, vaultLocked, noteTitle, notebookName, isoDay, formatBytes, importText, groupKey, localInput,
	};
})(typeof self !== 'undefined' ? self : this);
