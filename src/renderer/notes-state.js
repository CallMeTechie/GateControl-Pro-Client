/**
 * GateControl -- Notizen & Aufgaben: view logic without DOM (renderer)
 *
 * Dates as the lists show them (heute, morgen, Fr. 13. Nov.), the line under a task or an item, the chips of the quick
 * entry (the plugin's own ui/quickparse.js: vendor/notizen, window.GCQuickParse), the repeat choices, where tapping an
 * item of another plugin leads (contract docs/notes-sources-contract.md § 5: Mail's mail, Drive's deadline, Schule —
 * the other plugins' portal tab), texts of failures, of the Tresor states and of an import. Plugin 1.3.0, told by the
 * words in `me.features` only (never a version): a task's marks (Erinnerung, Später: …, im Kalender), the calendar chip of
 * the quick entry and the card „Gestern offen geblieben“ of Mein Tag. Plugin 1.4.0 (`shoppingLists`, `taskList`): the
 * shopping lists of the menu, a list's items (open first), who it is shared with, the mark „Einkauf 0/8“ of a task, the
 * choices of „Angehängte Liste“, the chip of the quick entry and „Alles abgehakt“. window.GCNotesState.
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

	// ── plugin 1.3.0: reminders, the calendar, „Gestern offen geblieben“ ──

	/** Does the plugin offer this (a word of `me.features`)? Nothing known yet counts as no. */
	function offers(me, feature) {
		return !!(me && Array.isArray(me.features) && me.features.includes(feature));
	}

	/**
	 * The name of the calendar in Mail the person's tasks with a time go into, or null: only when Mail offers it, the
	 * administrator switched it on and the person did not switch it off (`me.calendar`: available, enabled, mine).
	 */
	function calendarName(me) {
		const c = me && me.calendar;
		return offers(me, 'taskCalendar') && c && c.available === true && c.enabled === true && c.mine === true ? str(c.name) : null;
	}

	/** The wall clock of an ISO time with offset as a row shows it ('19:00' today, 'morgen 9:00'). */
	function clockText(iso, today, t) {
		const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(str(iso));
		if (!m) return '';
		const time = m[2].replace(/^0/, '');
		return m[1] === today ? time : `${dayText(m[1], today, t)} ${time}`;
	}

	/**
	 * The small marks of a task → [{ kind: 'reminder' | 'calendar', text, title?, long? }]: a reminder is still to come
	 * („Erinnerung“, put off: „Später: …“), the task stands in the person's calendar („im Kalender“).
	 */
	function taskMarks(x, me, t) {
		const out = [];
		if (!x || x.type !== 'task') return out;
		if (offers(me, 'reminderActions') && x.reminder && !x.done) {
			const when = x.snoozed ? clockText(x.reminder.at, me.today, t) : '';
			out.push({ kind: 'reminder', text: when ? t('notes.mark.later', { when }) : t('notes.mark.reminder') });
		}
		// plugin 1.4.0: the shopping list the task carries and how far it is ticked off („Einkauf 0/8“)
		if (offers(me, 'taskList') && x.attachedList) {
			const l = x.attachedList;
			out.push({ kind: 'list', text: `${l.name} ${l.done}/${l.total}`, title: t('notes.shop.openList'), uid: l.uid });
		}
		const name = calendarName(me);
		if (name !== null && x.calendar && x.calendar.mine === true) {
			const pending = x.calendar.state === 'pending';
			out.push({ kind: 'calendar', text: t('notes.mark.calendar'), title: pending ? t('notes.mark.calendarPending') : t('notes.mark.calendarHint', { name }), long: pending ? t('notes.mark.calendarPending') : t('notes.mark.calendarIn', { name }) });
		}
		return out;
	}

	/**
	 * The card „Gestern offen geblieben“ of Mein Tag → { title, items, moveOptions } or null (an older plugin, another
	 * view, nothing open). It stands above „Heute“ until every row is decided.
	 */
	function yesterdayCard(view, me) {
		const y = view && view.view === 'myday' ? view.yesterday : null;
		if (!offers(me, 'yesterdayOpen') || !y || !Array.isArray(y.items) || !y.items.length) return null;
		return { day: y.day || null, items: y.items, moveOptions: Array.isArray(y.moveOptions) ? y.moveOptions : [] };
	}

	/** The sections of a view without the rows the card shows (they stay in „Überfällig“ for older apps). */
	function sectionsWithout(sections, card) {
		if (!card) return sections || [];
		const hide = new Set(card.items.map((x) => x.uid));
		return (sections || []).map((s) => {
			if (s.id !== 'overdue') return s;
			const items = s.items.filter((x) => !hide.has(x.uid));
			return items.length === s.items.length ? s : { ...s, items, count: items.length };
		});
	}

	/** The choices of „Verschieben“ → [{ to, label }] (the server's days; without them the two it always has). */
	function moveChoices(options, t) {
		const list = (options || []).filter((o) => o && typeof o.to === 'string' && o.to !== 'today');
		const base = list.length ? list : [{ to: 'tomorrow' }, { to: 'weekend' }];
		return base.map((o) => ({ to: o.to, label: o.to === 'tomorrow' || o.to === 'weekend' ? t(`notes.y.${o.to}`) : str(o.label) || o.to }));
	}

	/** The tasks a button of the morning hint asks about: what it named and is still open (it named none: all open). */
	function askedIds(named, open) {
		const ids = [...new Set((named || []).filter((n) => Number.isSafeInteger(n) && n > 0))];
		if (!Array.isArray(open)) return ids;
		return ids.length ? ids.filter((n) => open.includes(n)) : open.slice();
	}

	// ── plugin 1.4.0: shopping lists, a list at a task ──

	/** The shopping lists of the menu for an area: what the page holds (with what waits to be sent), else the menu's. */
	function shopNav(shop, nav, area) {
		if (shop && Array.isArray(shop.lists)) return shop.lists.filter((l) => l.area === area);
		return (nav && Array.isArray(nav.shopping) ? nav.shopping : []).slice();
	}

	/** A shopping list of what the page holds, by its text id. */
	function shopList(shop, uid) {
		return (shop && Array.isArray(shop.lists) ? shop.lists : []).find((l) => l.id === uid) || null;
	}

	/** The items of a list as the page shows them: open ones first, each group in the order they were written. */
	function shopItems(shop, uid) {
		const all = (shop && Array.isArray(shop.items) ? shop.items : []).filter((i) => i.listId === uid);
		return [...all.filter((i) => !i.checked), ...all.filter((i) => i.checked)];
	}

	/** Who a shopping list is shared with: „Familie“, „nur ich“, else the names of the others. */
	function shopWith(l, meId, t) {
		if (!l) return '';
		if (l.family) return t('notes.shop.family');
		if (!l.shared) return t('notes.shop.onlyMe');
		const names = [l.owner, ...(l.members || [])].filter((p) => p && p.id !== meId && p.name).map((p) => p.name);
		return names.length ? names.join(', ') : t('notes.shared');
	}

	/** A list in the choice „Angehängte Liste“: „Einkauf · Familie · 8 offen“. */
	function shopChoice(l, meId, t) {
		return `${l.name} · ${shopWith(l, meId, t)} · ${t('notes.shop.openN', { n: l.open })}`;
	}

	/** The line above a list's items: „gehört zu ‚Bei Lidl einkaufen‘ · 3 von 8“ → { text, taskId } or null. */
	function shopBelongs(l, t) {
		const tasks = l && Array.isArray(l.tasks) ? l.tasks : [];
		if (!tasks.length) return null;
		const done = l.total - l.open;
		const key = tasks.length > 1 ? 'notes.shop.belongsMore' : 'notes.shop.belongs';
		return { text: t(key, { title: tasks[0].title, n: tasks.length - 1, done, total: l.total }), taskId: tasks[0].id };
	}

	/** „Alles abgehakt. ‚Bei Lidl einkaufen‘ ist erledigt.“ for the tasks a list completed. */
	function allTickedText(completed, t) {
		const list = (completed || []).filter((c) => c && c.taskId);
		if (!list.length) return '';
		return list.length === 1 ? t('notes.shop.allTicked', { title: list[0].title }) : t('notes.shop.allTickedN', { n: list.length });
	}

	/**
	 * The quick entry's list: what the server suggested for the line (`attach` of POST parse) and what the person did
	 * with the chip → { list (the one to attach or null), lists (to choose from), tag (the line names it with #) } or
	 * null (nothing suggested, an older plugin). `choice`: undefined (untouched), null (taken away) or a list's number.
	 */
	function quickAttach(attach, choice) {
		if (!attach || !Array.isArray(attach.lists) || !attach.lists.length) return null;
		const lists = attach.lists;
		const list = choice === null ? null : (choice !== undefined && lists.find((l) => l.id === choice)) || (choice === undefined ? attach.list || null : null);
		return { list, lists, tag: attach.via === 'tag' };
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

	/**
	 * The chips under the quick entry ("Erkannt – tippen zum Ändern") → [{ kind, text, plain }]. `qa` (quickAttach): the
	 * line names a shopping list with # — that word is no task list to be made.
	 */
	function quickChips(p, ctx, area, t, lang, me, qa) {
		if (!p) return [];
		const out = [];
		if (p.date) out.push({ kind: 'date', text: dayText(p.date, ctx.today, t) + (p.time ? `, ${p.time}` : '') });
		if (p.remind) out.push({ kind: 'remind', text: t('notes.quick.remind', { time: p.remind.time }) });
		// plugin 1.3.0: a task with a day and a time also becomes an event in the person's calendar in Mail — a hint only
		const cal = p.date && p.time ? calendarName(me) : null;
		if (cal !== null) out.push({ kind: 'calendar', text: t('notes.quick.calendar', { name: cal }), title: t('notes.quick.calendarHint', { name: cal }) });
		if (p.repeat) out.push({ kind: 'repeat', text: `↻ ${RP().describe(p.repeat, lang === 'en' ? 'en' : 'de')}` });
		if (p.important) out.push({ kind: 'important', text: t('notes.important') });
		if (p.list) out.push({ kind: 'list', text: t('notes.quick.list', { name: p.list.name }) });
		else if (p.listName && !(qa && qa.tag && qa.list)) out.push({ kind: 'list', text: t('notes.quick.newList', { name: p.listName }), plain: true });
		if (p.assignee) out.push({ kind: 'person', text: `@${p.assignee.name}` });
		else if (p.assigneeName) out.push({ kind: 'person', text: t('notes.quick.unknownPerson', { name: p.assigneeName }), plain: true });
		out.push({ kind: 'area', text: t(`notes.area.${area === 'work' ? 'work' : 'private'}`), plain: true });
		return out;
	}

	/**
	 * The body of POST tasks for the quick entry in the current view. `qa` (quickAttach, plugin 1.4.0): the chip stayed →
	 * attachedListId; taken away → no field; `'auto'` — the suggestion for this line has not come yet: the server attaches
	 * the list when exactly one fits.
	 */
	function quickBody(text, p, view, area, qa) {
		const body = { text: str(text).trim(), area, createList: !!(p && p.listName && !p.list) };
		if (qa === 'auto') body.attach = 'auto';
		else if (qa && qa.list) {
			body.attachedListId = qa.list.id;
			if (qa.tag) body.createList = false;
		}
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
		COLORS, SOURCE_TONE, dayText, longDate, whenText, offers, calendarName, clockText, taskMarks, yesterdayCard, sectionsWithout, moveChoices, askedIds,
		shopNav, shopList, shopItems, shopWith, shopChoice, shopBelongs, allTickedText, quickAttach, sourceChip, metaLine, sectionTitle, quickCtx, quickParse, quickChips, quickBody,
		repeatOptions, openTarget, errText, vaultLocked, noteTitle, notebookName, isoDay, formatBytes, importText, groupKey, localInput,
	};
})(typeof self !== 'undefined' ? self : this);
