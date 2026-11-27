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
 * choices of „Angehängte Liste“, the chip of the quick entry and „Alles abgehakt“. Plugin 1.5.0 (`places`, `placeSearch`):
 * the mark and the line „Ort“ of a task, what the dialog „Welcher …?“ sends (`place` of POST / PATCH tasks), where a search
 * is made near (this PC has no position: near one of the person's places), the chip of the quick entry (the server's
 * suggestion — the parser on this PC is untouched) and the hints (consent, „in der Nähe“). The phone reminds, not the PC.
 * Plugin 1.6.0 (`taskTurns`, `taskStars`, `familyTasks`, `doneFeedback`, `placeMine`): whose turn („Reihum · du bist
 * dran“, „Wer zuerst“), the stars and „Erledigt von …“ at a row, what the typed line says about several people (the
 * plugin's second module after the parser: vendor/notizen/turnwords.js, window.GCTurnWords) with the choice „Wer ist
 * dran?“, what the details send (`turn`, `people`, `stars`), what a parent and a child may in the family's list, and who
 * is asked to accept a place (`place.canConsent`; without `placeMine` as before). Plugin 1.7.0 (`driveDeadlines`): a task
 * that reminds of a deadline of a file in Drive — „Frist 30. Nov. · Versicherungsschein.pdf · 3 Tage vorher“ at the row,
 * the file and the hints in the details. And who only reads a list (the list's `canEdit`, a task's `canEdit`).
 * Plugin 1.9.0 (`calendarEvents`): „Termin“ in the quick entry — the line read in event mode, the chips (Tag, Zeit /
 * Ganztägig, Ort as text, Kalender, Erinnerung), the question „Als Termin anlegen?“ (a date and a time in task mode;
 * the app never switches by itself), the body of POST events (calendar and reminder only when chosen), the card „Kein
 * Kalender“, an event's row (the calendar's colour, no tick box, never overdue), where it opens (Mail's event) and the
 * switches „Termine aus dem Kalender“. The event is stored in Mail's calendar only.
 * window.GCNotesState.
 */
(function (root) {
	'use strict';

	const RP = () => root.GCRepeat;
	const QP = () => root.GCQuickParse;
	const TW = () => root.GCTurnWords;
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
		// plugin 1.6.0: whose turn it is, the stars of a task of the family's list, who it was ticked off for
		const turn = turnText(x, me, t);
		if (turn && !x.done) out.push({ kind: 'turn', text: turn, first: x.turn === 'first' });
		if (starsShown(me, x.listId) && x.stars > 0) out.push({ kind: 'stars', text: starsText(x.stars, t) });
		const by = doneByText(x, me, t);
		if (by) out.push({ kind: 'doneby', text: by });
		if (offers(me, 'reminderActions') && x.reminder && !x.done) {
			const when = x.snoozed ? clockText(x.reminder.at, me.today, t) : '';
			out.push({ kind: 'reminder', text: when ? t('notes.mark.later', { when }) : t('notes.mark.reminder') });
		}
		// plugin 1.4.0: the shopping list the task carries and how far it is ticked off („Einkauf 0/8“)
		if (offers(me, 'taskList') && x.attachedList) {
			const l = x.attachedList;
			out.push({ kind: 'list', text: `${l.name} ${l.done}/${l.total}`, title: t('notes.shop.openList'), uid: l.uid });
		}
		// plugin 1.5.0: the place the task hangs on (the phone reminds there; here it is shown)
		if (offers(me, 'places') && x.place) out.push({ kind: 'place', text: x.place.name, title: placeSummary(x.place, t) });
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

	// ── plugin 1.5.0: a task at a place ──

	/** „Baumarkt Nord · beim Ankommen“ */
	function placeSummary(p, t) {
		return p ? `${p.name} · ${t(p.trigger === 'exit' ? 'notes.place.onExit' : 'notes.place.onEnter')}` : '';
	}

	/** „2,4 km“ / „300 m“ ('' without a distance). */
	function distText(m, lang) {
		if (m === null || m === undefined || !Number.isFinite(m)) return '';
		if (m < 950) return `${Math.max(50, Math.round(m / 50) * 50)} m`;
		const km = (m / 1000).toFixed(1);
		return `${lang === 'en' ? km : km.replace('.', ',')} km`;
	}

	/** May the page offer the search now (`me.places.search.state` — the one field to ask)? → 'on' | 'off' | 'unavailable' */
	function searchState(me) {
		if (!offers(me, 'places') || !offers(me, 'placeSearch') || !me.places) return 'off';
		const st = me.places.search && me.places.search.state;
		return st === 'on' || st === 'unavailable' ? st : 'off';
	}

	/**
	 * The places a search can be made near — a PC has no position of its own: the places of the family („Zuhause“ first),
	 * then „Meine Orte“ → [{ value, label }].
	 */
	function nearOptions(all) {
		const a = all || {};
		return [
			...(a.family || []).map((f) => ({ value: `f:${f.familyId}`, label: f.name })),
			...(a.places || []).map((x) => ({ value: `p:${x.id}`, label: x.name })),
		];
	}

	/** A choice of nearOptions → the part of the search's body ({ nearFamilyId } | { nearPlaceId } | {}). */
	function nearArg(value) {
		const v = str(value);
		if (v.startsWith('f:') && v.length > 2) return { nearFamilyId: v.slice(2) };
		const id = v.startsWith('p:') ? Number(v.slice(2)) : NaN;
		return Number.isSafeInteger(id) && id > 0 ? { nearPlaceId: id } : {};
	}

	/**
	 * What the dialog „Welcher …?“ sends as `place` of POST / PATCH tasks. `sel`: { type: 'hit', hit } (a search hit — its
	 * fields go back unchanged; an own place by its number) | { type: 'own', placeId } | { type: 'family', familyId } |
	 * { type: 'any' } („Jeder Lidl“) | null (only the trigger changes). `o`: { trigger, key, label, remember }.
	 */
	function placeChoiceArg(sel, o) {
		const base = { trigger: o && o.trigger === 'exit' ? 'exit' : 'enter' };
		if (!sel) return base;
		const key = (o && o.key) || null;
		const label = (o && o.label) || null;
		if (sel.type === 'family') return { ...base, familyId: sel.familyId, key: null };
		if (sel.type === 'any') return key ? { ...base, any: true, key, ...(label ? { label } : {}) } : base;
		if (key) Object.assign(base, { key }, label ? { label } : {}, o.remember === true ? { remember: true } : {});
		else base.key = null;
		if (sel.type === 'own') return { ...base, placeId: sel.placeId };
		const x = sel.hit || {};
		if (x.placeId) return { ...base, placeId: x.placeId };
		return { ...base, ...(x.ref ? { ref: x.ref } : {}), name: x.name, ...(x.address ? { address: x.address } : {}), lat: x.lat, lon: x.lon };
	}

	/**
	 * plugin 1.8.0 (`profilePlaces`): a place of „Meine Orte“ goes by its reference — { ref: 'profile:<id>' } in place of
	 * { placeId } (the trigger, key and „merken“ stay). Anything else (a hit, Familie's, an older plugin) as it is.
	 */
	function profileArg(arg, places) {
		if (!arg || arg.placeId == null) return arg;
		const p = (places || []).find((x) => x && x.id === arg.placeId);
		if (!p || typeof p.ref !== 'string' || !/^profile:[1-9]\d{0,15}$/.test(p.ref)) return arg;
		const { placeId, ...rest } = arg;
		return { ...rest, ref: p.ref };
	}

	/** The name of what the dialog chose (for a chip, a toast). */
	function placeChoiceText(sel, o, all, t) {
		if (!sel) return '';
		if (sel.type === 'hit') return str(sel.hit && sel.hit.name);
		if (sel.type === 'any') return t('notes.place.any', { label: (o && o.label) || '' });
		if (sel.type === 'family') return str((((all && all.family) || []).find((f) => f.familyId === sel.familyId) || {}).name);
		return str((((all && all.places) || []).find((x) => x.id === sel.placeId) || {}).name);
	}

	/** The grey line under a place in „Meine Orte“: „Gartenweg 5 · gemerkt für ‚Baumarkt‘“. */
	function placeSub(x, t) {
		const favs = (x.favFor || []).map((f) => t('notes.place.favFor', { label: f.label })).join(', ');
		return [x.address, favs].filter(Boolean).join(' · ');
	}

	/**
	 * What the details say under the line „Ort“ → { kind: 'consentMe' | 'consentWait' | 'declined' | 'needsSearch' | 'nearby',
	 * text, ask } or null. `ask`: this person is asked to accept or decline (someone else set the place at their task).
	 */
	function placeHint(task, me, t) {
		const p = task && task.place;
		if (!p || !offers(me, 'places')) return null;
		const meId = me.user && me.user.id;
		// plugin 1.6.0 (`placeMine`): the server says who may answer — everybody else only sees the state. Without the
		// field (an older plugin) as before: the person the task belongs to, when someone else set the place
		const told = offers(me, 'placeMine') && typeof p.canConsent === 'boolean';
		if (p.consent === 'pending') {
			// the phone of the person the task belongs to watches the place: assigned, else who did not set the place
			const mine = told ? p.canConsent : (task.assignee ? task.assignee.id === meId : p.by !== meId) && p.by !== meId;
			return mine ? { kind: 'consentMe', text: t('notes.place.consentMe'), ask: true } : { kind: 'consentWait', text: t('notes.place.consentWait'), ask: false };
		}
		if (p.consent === 'declined') return { kind: 'declined', text: t('notes.place.consentNo'), ask: told && p.canConsent === true };
		const search = searchState(me);
		if (p.mode === 'any' && search !== 'on') return { kind: 'needsSearch', text: t('notes.place.needsSearch'), ask: false };
		if (p.nearby && me.places && me.places.nearby && search === 'on') return { kind: 'nearby', text: t('notes.place.nearbyHint', { label: p.label || '' }), ask: false };
		return null;
	}

	/**
	 * The quick entry's place: what the server found in the line (`place` of POST parse) and what the person did with
	 * the chip → { state, text, title, plain, arg, hint } or null (the line names no place, an older plugin). `choice`:
	 * undefined (untouched), null (taken away) or { arg, text } (chosen in the dialog).
	 *   state 'set'     — a place stands: `arg` goes with the task (`place` of POST tasks)
	 *   state 'ask'     — a kind or a name without a place yet („Ort: Baumarkt …“): the dialog searches when it is opened
	 *   state 'choose'  — the search is off or the line names an address: „Ort wählen“
	 *   state 'maybe'   — not surely meant („Apotheke anrufen“): a suggestion, nothing is set
	 *   state 'off'     — taken away with ×
	 */
	function quickPlace(sug, choice, t) {
		if (!sug) return null;
		const hint = { key: sug.key || null, label: sug.label || null, query: sug.query || sug.label || '', trigger: sug.trigger === 'exit' ? 'exit' : 'enter' };
		const label = sug.label || sug.query || '';
		if (choice === null) return { state: 'off', text: t('notes.place.chipOff'), title: t('notes.place.chipAdd'), plain: true, arg: null, hint };
		if (choice && choice.arg) {
			return { state: 'set', text: t('notes.place.chipSet', { name: choice.text || label, when: t(choice.arg.trigger === 'exit' ? 'notes.place.onExit' : 'notes.place.onEnter') }), title: t('notes.place.chipTitle'), plain: false, arg: choice.arg, hint };
		}
		const pl = sug.place;
		if (pl && sug.certain) {
			const arg = pl.familyId ? { familyId: pl.familyId, trigger: hint.trigger } : { placeId: pl.id, ...(sug.key ? { key: sug.key } : {}), trigger: hint.trigger };
			const usual = sug.key && sug.uses > 0 ? t('notes.place.usual', { label, n: sug.uses }) : t('notes.place.chipTitle');
			return { state: 'set', text: t('notes.place.chipSet', { name: pl.name, when: t(hint.trigger === 'exit' ? 'notes.place.onExit' : 'notes.place.onEnter') }), title: usual, plain: false, arg, hint };
		}
		if (!sug.certain) return { state: 'maybe', text: t('notes.place.chipMaybe', { label: (pl && pl.name) || label }), title: t('notes.place.chipTitle'), plain: true, arg: null, hint };
		if (sug.key && sug.search === 'on') return { state: 'ask', text: t('notes.place.chip', { label }), title: t('notes.place.chipTitle'), plain: true, arg: null, hint };
		return { state: 'choose', text: t('notes.place.choose'), title: t('notes.place.chipTitle'), plain: true, arg: null, hint };
	}

	// ── plugin 1.6.0: whose turn, stars, the family's list ──

	/**
	 * What `me.familyTasks` means for the page → { bound, listId, parent, stars, starsMax, moved } — all off without the
	 * word `familyTasks`, without the move or for a person outside the family.
	 */
	function familyInfo(me) {
		const f = offers(me, 'familyTasks') && me.familyTasks && me.familyTasks.bound === true && me.familyTasks.listId ? me.familyTasks : null;
		if (!f) return { bound: false, listId: null, parent: false, stars: false, starsMax: 10, moved: null };
		return { bound: true, listId: f.listId, parent: f.parent === true, stars: f.stars === true && offers(me, 'taskStars'), starsMax: f.starsMax >= 1 && f.starsMax <= 10 ? f.starsMax : 10, moved: f.moved || null };
	}

	/** Is this the family's list? */
	function isFamilyList(me, listId) {
		const f = familyInfo(me);
		return f.bound && !!listId && f.listId === listId;
	}

	/** Are stars shown at a task of this list (the family's list, while the Familie plugin counts them)? */
	function starsShown(me, listId) {
		return isFamilyList(me, listId) && familyInfo(me).stars;
	}

	/** May this person give stars there (a parent of the family)? */
	function mayStar(me, listId) {
		return starsShown(me, listId) && familyInfo(me).parent;
	}

	/** „1 Stern“ / „3 Sterne“ */
	function starsText(n, t) {
		return n === 1 ? t('notes.turn.star1') : t('notes.stars', { n });
	}

	/** Whose turn a task is: „Reihum · du bist dran“ / „Reihum · Lena ist dran“ / „Wer zuerst“ ('' for an ordinary task). */
	function turnText(x, me, t) {
		if (!x || !offers(me, 'taskTurns') || !x.turn) return '';
		if (x.turn === 'first') return t('notes.turn.first');
		const a = x.assignee;
		if (!a) return t('notes.turn.rotate');
		return a.id === (me.user && me.user.id) ? t('notes.turn.rotateMe') : t('notes.turn.rotateWho', { name: firstName(a.name) });
	}

	/** „Erledigt von Lena“ — for a task ticked off for somebody else, or one that was for several ('' otherwise). */
	function doneByText(x, me, t) {
		if (!x || !x.done || !x.doneBy || !(offers(me, 'familyTasks') || offers(me, 'taskTurns'))) return '';
		const meId = me.user && me.user.id;
		if (x.doneBy.id === meId && x.turn !== 'first') return '';
		return t('notes.turn.doneBy', { name: x.doneBy.id === meId ? t('notes.turn.byMe') : firstName(x.doneBy.name) });
	}

	const firstName = (name) => str(name).trim().split(/\s+/)[0] || str(name);

	/** The choices of „Sterne“ in a task's details: keine, 1 … starsMax → [{ value, label }]. */
	function starChoices(me, t) {
		const out = [{ value: 0, label: t('notes.turn.starsNone') }];
		for (let n = 1; n <= familyInfo(me).starsMax; n++) out.push({ value: n, label: starsText(n, t) });
		return out;
	}

	/**
	 * What the choice „Wer ist dran?“ of a task's details sends (PATCH tasks/<id>): `to` 'one' | 'rotate' | 'first',
	 * `people` the ids chosen under „Wer macht mit“ → the body, or null when it needs two people and has fewer.
	 */
	function turnPatch(task, to, people) {
		if (to === 'one') return { turn: null };
		const ids = [...new Set((people || []).filter((n) => Number.isSafeInteger(n) && n > 0))];
		if (ids.length < 2) return null;
		const body = { turn: to === 'first' ? 'first' : 'rotate', people: ids };
		// „reihum“: who is on now stays on when they take part, else the first one
		if (body.turn === 'rotate' && task && task.assignee && ids.includes(task.assignee.id)) body.assigneeId = task.assignee.id;
		return body;
	}

	/** Who takes part when „Reihum“ / „Wer zuerst“ is chosen first: who did already, else every member of the list. */
	function turnPeople(task, members) {
		const have = (task && task.people ? task.people : []).map((p) => p.id);
		return have.length >= 2 ? have : (members || []).map((m) => m.id);
	}

	/**
	 * What the typed line says about several people, „reihum“ / „wer zuerst“ and stars — the plugin's ui/turnwords.js
	 * applied to what the parser read → { title, people, turn, stars } or null (an older plugin, no line). Stars are read
	 * only when the person may give them and the task goes into the family's list (the open list, or the one named
	 * with #): „Hotel 4 Sterne buchen“ stays what it is.
	 */
	function quickWords(parsed, ctx, me, view) {
		if (!parsed || !TW() || !offers(me, 'taskTurns')) return null;
		const target = parsed.list ? parsed.list.id : parsed.listName ? null : view && view.kind === 'list' ? view.id : null;
		try {
			const w = TW().apply(parsed, { people: (ctx && ctx.people) || [], stars: mayStar(me, target) });
			return { title: w.title, people: w.people || [], turn: w.turn || null, stars: w.stars || null };
		} catch { return null; }
	}

	/**
	 * „Wer ist dran?“ of the quick entry (from two people on): what the line says and what the person chose instead →
	 * { value: 'one' | 'rotate' | 'first', said } or null. `choice`: undefined (untouched) or one of the three.
	 */
	function quickTurn(words, choice) {
		if (!words || words.people.length < 2) return null;
		const said = words.turn || 'one';
		return { value: choice === 'one' || choice === 'rotate' || choice === 'first' ? choice : said, said };
	}

	// ── plugin 1.7.0: a task that reminds of a deadline of a file in Drive ──

	/** „3 Tage vorher“ / „1 Tag vorher“ / „Erinnerung am Tag selbst“ — what the person chose in Drive ('' when unknown). */
	function deadlineBefore(days, t) {
		if (!Number.isInteger(days) || days < 0) return '';
		return days === 0 ? t('notes.dl.before0') : days === 1 ? t('notes.dl.before1') : t('notes.dl.beforeN', { n: days });
	}

	/**
	 * The deadline a task reminds of → { line: 'Frist 30. Nov.', file, before: '3 Tage vorher', open } or null (every
	 * other task, an older plugin). `open`: the file's `open` when it names a place to go to, else null.
	 */
	function deadlineInfo(x, me, t) {
		const d = x && x.type === 'task' ? x.deadline : null;
		if (!d || !offers(me, 'driveDeadlines')) return null;
		const open = d.open && typeof d.open.plugin === 'string' && str(d.open.route) ? d.open : null;
		return { line: d.date ? t('notes.dl.line', { date: dayText(d.date, me && me.today, t) }) : '', file: str(d.file), before: deadlineBefore(d.daysBefore, t), open };
	}

	/** May the person add to and change the tasks of this list? (A member who only reads may not; no list: yes.) */
	function listWritable(list, me) {
		return !(me && me.readOnly) && !(list && list.canEdit === false);
	}

	/** The chip of a row's source ('Mail · Zu tun', 'Drive · Frist') → { text, tone } or null. */
	function sourceChip(x, t) {
		if (!x || !x.source) return null;
		// plugin 1.9.0: an event of the calendar does not name „Mail“ as where it comes from
		if (isEvent(x)) return null;
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
			// „reihum“ names who is on in its own mark
			if (x.assignee && x.assignee.id !== me && x.assignee.name && !x.turn) out.push(x.assignee.name);
			// plugin 1.7.0: the deadline in Drive this task reminds of — the day, the file, how many days before
			const dl = deadlineInfo(x, ctx && ctx.me, t);
			if (dl) out.push(...[dl.line, dl.file, x.done ? '' : dl.before].filter(Boolean));
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
	function quickChips(p, ctx, area, t, lang, me, qa, words, qt) {
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
		// plugin 1.6.0: several people („Mia, Jonas“), whose turn („Reihum · zuerst Mia“, „Wer zuerst“), the stars
		if (words && words.people.length > 1) {
			out.push({ kind: 'person', text: words.people.map((x) => firstName(x.name)).join(', ') });
			const turn = qt ? qt.value : words.turn || 'one';
			if (turn === 'rotate') out.push({ kind: 'turn', text: t('notes.turn.rotateFirst', { name: firstName(words.people[0].name) }) });
			else if (turn === 'first') out.push({ kind: 'turn', text: t('notes.turn.first') });
		} else if (p.assignee) out.push({ kind: 'person', text: `@${p.assignee.name}` });
		else if (p.assigneeName) out.push({ kind: 'person', text: t('notes.quick.unknownPerson', { name: p.assigneeName }), plain: true });
		if (words && words.stars) out.push({ kind: 'stars', text: starsText(words.stars, t) });
		out.push({ kind: 'area', text: t(`notes.area.${area === 'work' ? 'work' : 'private'}`), plain: true });
		return out;
	}

	/**
	 * The body of POST tasks for the quick entry in the current view. `qa` (quickAttach, plugin 1.4.0): the chip stayed →
	 * attachedListId; taken away → no field; `'auto'` — the suggestion for this line has not come yet: the server attaches
	 * the list when exactly one fits. `qp` (quickPlace, plugin 1.5.0): a place stands → `place`; taken away or not chosen →
	 * no field (the title then stays whole); `'auto'` — the suggestion has not come yet: the server sets the place when it
	 * is decided and surely meant. `words` / `qt` (quickWords, quickTurn — plugin 1.6.0): the choice „Wer ist dran?“.
	 */
	function quickBody(text, p, view, area, qa, qp, words, qt) {
		const body = { text: str(text).trim(), area, createList: !!(p && p.listName && !p.list) };
		// plugin 1.6.0: „Wer ist dran?“ chosen other than the line says — it goes with the task explicitly; „Eine Person“
		// is `turn: null` (the first person is assigned then). Untouched: the server reads the line as this PC did
		if (words && qt && qt.value !== qt.said) {
			if (qt.value === 'one') body.turn = null;
			else { body.turn = qt.value; body.people = words.people.map((x) => x.id); }
		}
		if (qp === 'auto') body.place = 'auto';
		else if (qp && qp.arg) body.place = qp.arg;
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
			// plugin 1.9.0: an event of the calendar (event/<id>[/<occurrence>]) opens Mail's own event page
			if (parts[0] === 'event' && /^[1-9]\d{0,14}$/.test(str(parts[1]))) {
				return { page: 'mail', context: { kind: 'event', eventId: Number(parts[1]), occurrence: parts[2] && /^[A-Za-z0-9:._-]{1,80}$/.test(parts[2]) ? parts[2] : null } };
			}
			if (parts[0] === 'calendar') return { page: 'mail', context: { kind: 'calendar' } };
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
		// plugin 1.6.0: what a child may not, what the Familie plugin decides, stars outside the family's list
		if (res && res.reason === 'parents_only') return t('notes.err.parents_only');
		if (res && res.reason === 'family') return t(code === 'invalid' ? 'notes.err.stars_family' : 'notes.err.family_list');
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

	// ── plugin 1.9.0: „Termin“ ──

	const EV_PERMANENT = ['no_mail', 'mail_old', 'feature_off', 'not_allowed', 'not_licensed', 'no_seat', 'no_calendar'];
	const REM_TIMED = [0, 5, 10, 15, 30, 60, 120, 1440];
	const REM_ALLDAY = [360, 720, 1800];

	/** May the quick entry offer „Termin“ (the word `calendarEvents`)? */
	function eventsOn(me) {
		return offers(me, 'calendarEvents');
	}

	/** The card „Kein Kalender“: 'mail' | 'off' | 'none' | 'unreachable' for a reason. */
	function eventWhy(reason) {
		if (reason === 'no_mail' || reason === 'mail_old') return 'mail';
		if (['feature_off', 'not_allowed', 'not_licensed', 'no_seat'].includes(reason)) return 'off';
		if (reason === 'no_calendar') return 'none';
		return 'unreachable';
	}

	/** Why no event can be made now (a reason that does not pass), or null — the calendars are the newer word. */
	function eventBlocked(me, cals) {
		let r = null;
		if (cals) r = cals.state === 'ok' ? null : cals.reason || 'no_calendar';
		else if (me && me.events && me.events.available === false) r = me.events.reason || 'no_calendar';
		return r && EV_PERMANENT.includes(r) ? r : null;
	}

	/** „Das sieht wie ein Termin aus“: task mode, the line names a date and a time, not waved away. */
	function eventAsk(p, me, mode, kept) {
		return mode === 'task' && !kept && eventsOn(me) && !!(p && p.looksLikeEvent);
	}

	const plusHour = (time) => `${pad((Number(time.slice(0, 2)) + 1) % 24)}:${time.slice(3, 5)}`;

	/**
	 * The event the chips show: the parser's line in event mode with the person's choices on top (`ch`: date, time,
	 * endTime, allDay, location — '' / null takes it off —, calendarId, reminder: minutes | false). No date: today; the
	 * calendar: the default one; the reminder: the calendar's own (only shown — it is not sent unless chosen).
	 */
	function eventDraft(p, ch, cals, today) {
		const c = ch || {};
		const base = p || {};
		const allDay = c.allDay !== undefined ? !!c.allDay : !base.time;
		const time = allDay ? null : (c.time || base.time || '09:00');
		let endTime = allDay ? null : (c.endTime || (c.time ? null : base.endTime) || null);
		if (time && !endTime) endTime = plusHour(time);
		const title = str(base.title).trim();
		const location = c.location !== undefined ? (str(c.location).trim() || null) : base.location || null;
		const calChosen = c.calendarId != null && cals && cals.targets && cals.targets.includes(c.calendarId);
		const calendarId = calChosen ? c.calendarId : (cals ? cals.defaultId : null);
		const remChosen = c.reminder !== undefined;
		const shownRem = remChosen ? (c.reminder === false ? null : c.reminder) : (cals && cals.reminders ? (allDay ? cals.reminders.allDay : cals.reminders.timed) : null);
		return {
			title, date: c.date || base.date || today || null, time, endTime, allDay, location, calendarId, calendarChosen: !!calChosen,
			reminder: shownRem, reminderChosen: remChosen, repeat: base.repeat && base.repeat.type !== 'after' ? base.repeat : null,
			// „Ort: <Titel>?“ — no place word in the line: the title may be taken as the place (one click)
			placeSuggest: !location && c.location === undefined && title ? title : null,
		};
	}

	/** The draft → the body of notes:event:create (calendarId and reminder only when chosen; no time: all day). */
	function eventBody(d) {
		const b = { title: str(d.title).trim().slice(0, 255), date: d.date };
		if (!d.allDay && d.time) { b.time = d.time; if (d.endTime) b.endTime = d.endTime; }
		if (d.location) b.location = d.location.slice(0, 255);
		if (d.calendarChosen && d.calendarId) b.calendarId = d.calendarId;
		if (d.reminderChosen) b.reminder = d.reminder === null ? false : d.reminder;
		if (d.repeat) b.repeat = d.repeat;
		return b;
	}

	/** „15 Min. vorher“, „1 Std. vorher“, „Vortag, 18:00“, „Keine Erinnerung“ — minutes before (all day: before midnight). */
	function reminderText(min, allDay, t) {
		if (min === null || min === undefined || min === false) return t('notes.ev.remNone');
		if (allDay) {
			const days = Math.ceil(min / 1440);
			const at = days * 1440 - min;
			const time = `${pad(Math.floor(at / 60))}:${pad(at % 60)}`;
			return days === 1 ? t('notes.ev.remDayBefore', { time }) : t('notes.ev.remDaysBefore', { n: days, time });
		}
		if (min === 0) return t('notes.ev.remAtStart');
		if (min % 1440 === 0) return t('notes.ev.remDays', { n: min / 1440 });
		if (min % 60 === 0) return t('notes.ev.remHours', { n: min / 60 });
		return t('notes.ev.remMinutes', { n: min });
	}

	/** The choices of the chip „Erinnerung“ → [{ value: minutes | false, label }] (the shown one included). */
	function reminderChoices(allDay, current, t) {
		const list = (allDay ? REM_ALLDAY : REM_TIMED).slice();
		if (Number.isInteger(current) && !list.includes(current)) list.push(current);
		list.sort((a, b) => a - b);
		return [...list.map((m) => ({ value: m, label: reminderText(m, allDay, t) })), { value: false, label: t('notes.ev.remNone') }];
	}

	/** The chips of event mode → [{ kind, text, plain?, suggest? }] (the view makes them buttons). */
	function eventChips(d, cals, t, today, lang) {
		if (!d) return [];
		const out = [{ kind: 'date', text: dayText(d.date, today, t) }];
		out.push({ kind: 'time', text: d.allDay ? t('notes.ev.allDay') : `${d.time}–${d.endTime}` });
		if (d.location) out.push({ kind: 'place', text: t('notes.ev.place', { place: d.location }) });
		else if (d.placeSuggest) out.push({ kind: 'place', text: t('notes.ev.placeSuggest', { place: d.placeSuggest }), suggest: true, plain: true });
		const cal = cals && (cals.calendars || []).find((c) => c.id === d.calendarId);
		if (cal) out.push({ kind: 'calendar', text: t('notes.ev.calendar', { name: cal.name }), color: cal.color });
		out.push({ kind: 'reminder', text: reminderText(d.reminder, d.allDay, t), plain: d.reminder === null });
		if (d.repeat) out.push({ kind: 'repeat', text: `↻ ${RP().describe(d.repeat, lang === 'en' ? 'en' : 'de')}` });
		return out;
	}

	/** A row of the overview that is an event of a calendar in Mail (plugin 1.9.0; Schule / Alltag have no `event`). */
	function isEvent(x) {
		return !!(x && x.type === 'source' && x.event);
	}

	/** The grey line of an event's row: „Ort · Kalender“ (all day: „ganztägig“), waiting: „wartet auf Verbindung“. */
	function eventMeta(x, today, t) {
		const out = [];
		const d = x.show || x.due;
		if (d && d.date !== today) out.push(dayText(d.date, today, t));
		if (x.event.location) out.push(x.event.location);
		else if (x.subtitle && !x.pending) out.push(x.subtitle);
		if (x.allDay) out.push(t('notes.ev.allDayShort'));
		if (x.event.calendar && x.event.calendar.name) out.push(x.event.calendar.name);
		if (x.pending) out.push(t('notes.ev.pending'));
		return out;
	}

	/** The time on the right of an event's row („14:00“, all day: nothing). */
	function eventWhen(x) {
		const d = x.show || x.due;
		return d && d.time && !x.allDay ? d.time.replace(/^0/, '') : '';
	}

	/** „Termine aus dem Kalender“: the line under a calendar's name, its switch's default, the choice to save. */
	function calendarSub(c, t) {
		if (c.isDefault) return t('notes.ev.cal.default');
		return t(`notes.ev.cal.${c.kind}`);
	}
	const calendarDefault = (c) => !['subscribed', 'tasks'].includes(c && c.kind);
	function calendarChoice(c, on) {
		return { [groupKey('gatecontrol-mail', c.key)]: on === calendarDefault(c) ? null : on ? 'show' : 'hide' };
	}

	/**
	 * „Mehr Angaben …“: what Mail's form of a new event is filled in with (calendar-view openEditor's prefill) — start
	 * and end as this PC's wall clock, the reminder the chip shows ([] for none), the rule in Mail's form.
	 */
	function eventPrefill(d) {
		const at = (date, time) => { const [y, m, dd] = date.split('-').map(Number); const [h, mi] = (time || '00:00').split(':').map(Number); return new Date(y, m - 1, dd, h, mi, 0, 0).getTime(); };
		const start = at(d.date, d.allDay ? '00:00' : d.time);
		let end = d.allDay ? start : at(d.date, d.endTime || plusHour(d.time));
		if (!d.allDay && end <= start) end += 86400000;
		const days = ['MO', 'TU', 'WE', 'TH', 'FR', 'SA', 'SU'];
		const r = d.repeat;
		const recurrence = r ? { freq: r.type, interval: r.interval || 1, ...(r.type === 'weekly' && r.days ? { byDay: r.days.map((x) => days[x - 1]) } : {}) } : null;
		return {
			title: d.title, start, end, allDay: !!d.allDay, startDate: d.date, endDate: d.date, calendarId: d.calendarId || null,
			location: d.location || '', reminders: d.reminder === null || d.reminder === undefined ? [] : [d.reminder], recurrence,
		};
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
		shopNav, shopList, shopItems, shopWith, shopChoice, shopBelongs, allTickedText, quickAttach,
		familyInfo, isFamilyList, starsShown, mayStar, starsText, turnText, doneByText, starChoices, turnPatch, turnPeople, quickWords, quickTurn,
		deadlineBefore, deadlineInfo, listWritable,
		placeSummary, distText, searchState, nearOptions, nearArg, placeChoiceArg, profileArg, placeChoiceText, placeSub, placeHint, quickPlace, sourceChip, metaLine, sectionTitle, quickCtx, quickParse, quickChips, quickBody,
		repeatOptions, openTarget, errText, vaultLocked, noteTitle, notebookName, isoDay, formatBytes, importText, groupKey, localInput,
		eventsOn, eventWhy, eventBlocked, eventAsk, eventDraft, eventBody, reminderText, reminderChoices, eventChips, isEvent, eventMeta, eventWhen,
		calendarSub, calendarDefault, calendarChoice, eventPrefill,
	};
})(typeof self !== 'undefined' ? self : this);
