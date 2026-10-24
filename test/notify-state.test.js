'use strict';

// View logic of "Mitteilungen" and Settings → Benachrichtigungen
// (src/renderer/notify-state.js, no DOM), plus how the page loads it.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const NS = require('../src/renderer/notify-state');

const ROOT = path.join(__dirname, '..');
// Minimal t(): returns the key with its parameters, enough to see what is shown.
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);

const TOPICS = [
  { id: 'security', label: 'Sicherheit' },
  { id: 'devices', label: 'Geräte & Gateways' },
  { id: 'admin_notice', label: 'Hinweise vom Admin' },
  { id: 'plugin:skoda:charging', label: 'Fahrzeug · Laden abgeschlossen' },
];

const NOW = new Date(2026, 9, 10, 22, 0, 0).getTime();
const at = (h, m, dayOffset = 0) => new Date(2026, 9, 10 + dayOffset, h, m).toISOString();

function entry(o = {}) {
  return {
    id: 45, seq: 123, topic: 'devices', priority: 'critical', state: 'delivered',
    title: 'Gateway „Zuhause“ ist offline', body: 'Seit 2 Minuten kein Lebenszeichen',
    created_at: at(21, 42), received_at: at(21, 42), via: 'tunnel', data: null, actions: [],
    ...o,
  };
}

const PTOPICS = [
  ...TOPICS,
  { id: 'plugin:gatecontrol-skoda:trip', label: 'Fahrzeuge · Fahrt erfasst (Fahrtenbuch)' },
  { id: 'plugin:gatecontrol-gatedrop:received', label: 'GateDrop · Empfangen' },
  { id: 'plugin:gatecontrol-gatedrop:link', label: 'GateDrop · Link geladen' },
  { id: 'plugin:gatecontrol-synology:storage', label: 'NAS (Synology) · NAS-Speicher (beeinträchtigt, fast voll)' },
  { id: 'plugin:gatecontrol-door:default', label: 'Tür & Kamera' },
];

describe('inbox list', () => {
  const items = [
    entry(),
    entry({ id: 46, seq: 124, topic: 'security', priority: 'normal', state: 'read' }),
    entry({ id: 47, seq: 125, topic: 'devices', priority: 'info', state: 'read' }),
  ];

  it('filters: read state × source (and the older single values)', () => {
    const mixed = [
      ...items,
      entry({ id: 48, topic: 'plugin:gatecontrol-skoda:trip', state: 'delivered' }),
      entry({ id: 49, topic: 'plugin:gatecontrol-gatedrop:received', state: 'read' }),
      entry({ id: 50, topic: 'plugin:gatecontrol-gatedrop:link', state: 'delivered' }),
      entry({ id: 51, topic: null, state: 'read' }),
    ];
    const ids = (f) => NS.filterItems(mixed, f).map((e) => e.id);
    assert.equal(NS.filterItems(mixed, { read: 'all', source: '' }).length, 7);
    assert.deepEqual(ids({ read: 'unread', source: '' }), [45, 48, 50]);
    assert.deepEqual(ids({ read: 'all', source: 'src:system' }), [45, 46, 47, 51]);
    assert.deepEqual(ids({ read: 'all', source: 'src:plugin:gatecontrol-gatedrop' }), [49, 50]);
    assert.deepEqual(ids({ read: 'unread', source: 'src:plugin:gatecontrol-gatedrop' }), [50]);
    assert.deepEqual(ids({ read: 'all', source: 'topic:security' }), [46]);
    // 'system' the core topic is not "System" the source
    assert.deepEqual(ids({ read: 'all', source: 'topic:system' }), []);
    assert.equal(NS.filterItems(items, 'all').length, 3);
    assert.deepEqual(NS.filterItems(items, 'unread').map((e) => e.id), [45]);
    assert.deepEqual(NS.filterItems(items, 'security').map((e) => e.id), [46]);
    assert.deepEqual(NS.filterItems(null, { read: 'all' }), []);
  });

  it('a saved filter is cleaned: broken values become the default', () => {
    assert.deepEqual(NS.normalizeFilter(null), { read: 'all', source: '' });
    assert.deepEqual(NS.normalizeFilter({ read: 'unread', source: 'src:plugin:gatecontrol-skoda' }), { read: 'unread', source: 'src:plugin:gatecontrol-skoda' });
    assert.deepEqual(NS.normalizeFilter({ read: 'x', source: 'security' }), { read: 'all', source: '' });
    assert.deepEqual(NS.normalizeFilter({ source: 'src:evil' }), { read: 'all', source: '' });
    assert.equal(NS.isDefaultFilter({ read: 'all', source: '' }), true);
    assert.equal(NS.isDefaultFilter({ read: 'unread', source: '' }), false);
  });

  it('sources: System first, then plugins in server order, topics indented when there are several', () => {
    const list = [
      entry({ id: 1, topic: 'plugin:gatecontrol-synology:storage', state: 'read' }),
      entry({ id: 2, topic: 'plugin:gatecontrol-skoda:trip' }),
      entry({ id: 3, topic: 'plugin:gatecontrol-skoda:trip' }),
      entry({ id: 4, topic: 'plugin:gatecontrol-gatedrop:received', state: 'read' }),
      entry({ id: 5, topic: 'plugin:gatecontrol-gatedrop:link' }),
      entry({ id: 6, topic: 'security', state: 'read' }),
      entry({ id: 7, topic: 'plugin:gatecontrol-door:default', state: 'read' }),
      entry({ id: 8, topic: 'plugin:unknown-plugin:alert', state: 'read' }),
    ];
    const opts = NS.sourceOptions(list, PTOPICS, '', t);
    assert.deepEqual(opts.map((o) => [o.value, o.label, o.depth, o.unread]), [
      ['', 'ui.inbox.sourceAll', 0, 3],
      ['src:system', 'ui.inbox.system', 0, 0],
      ['src:plugin:gatecontrol-skoda', 'Fahrzeuge', 0, 2],
      ['src:plugin:gatecontrol-gatedrop', 'GateDrop', 0, 1],
      ['topic:plugin:gatecontrol-gatedrop:received', 'Empfangen', 1, 0],
      ['topic:plugin:gatecontrol-gatedrop:link', 'Link geladen', 1, 1],
      ['src:plugin:gatecontrol-synology', 'NAS (Synology)', 0, 0],
      ['src:plugin:gatecontrol-door', 'Tür & Kamera', 0, 0],
      ['src:plugin:unknown-plugin', 'unknown-plugin', 0, 0],
    ]);
    assert.equal(NS.optionText(opts[2], t), 'Fahrzeuge · ui.inbox.newCount(2)');
    assert.equal(NS.optionText(opts[4], t), '    Empfangen');
    // the active choice stays even without entries; a single active topic shows under its source
    const act = NS.sourceOptions([], PTOPICS, 'topic:plugin:gatecontrol-skoda:trip', t);
    assert.deepEqual(act.map((o) => o.value), ['', 'src:plugin:gatecontrol-skoda', 'topic:plugin:gatecontrol-skoda:trip']);
    assert.deepEqual(NS.sourceOptions([], PTOPICS, 'src:system', t).map((o) => o.value), ['', 'src:system']);
  });

  it('topic labels: from the server, readable fallback; split into source and topic', () => {
    assert.equal(NS.topicLabel(TOPICS, 'devices'), 'Geräte & Gateways');
    assert.equal(NS.topicLabel([], 'plugin:skoda:charging'), 'skoda · charging');
    assert.equal(NS.topicLabel(TOPICS, null), '');
    assert.deepEqual(NS.topicParts(PTOPICS, 'plugin:gatecontrol-skoda:trip', t), { source: 'Fahrzeuge', topic: 'Fahrt erfasst (Fahrtenbuch)' });
    assert.deepEqual(NS.topicParts(PTOPICS, 'plugin:gatecontrol-door:default', t), { source: 'Tür & Kamera', topic: '' });
    assert.deepEqual(NS.topicParts(PTOPICS, 'devices', t), { source: 'ui.inbox.system', topic: 'Geräte & Gateways' });
    assert.equal(NS.sourceKey('plugin:a-b:c'), 'plugin:a-b');
    assert.equal(NS.sourceKey('security'), 'system');
    assert.equal(NS.sourceKey(null), 'system');
  });

  it('source badges: known icons, else the initial', () => {
    assert.ok(NS.sourceBadge('security', 'System').paths.length);
    assert.ok(NS.sourceBadge('plugin:gatecontrol-skoda:trip', 'Fahrzeuge').paths.length);
    assert.deepEqual(NS.sourceBadge('plugin:other:x', 'Übersicht'), { paths: null, initial: 'Ü' });
    assert.deepEqual(NS.sourceBadge('plugin:other:x', '  (Synology)'), { paths: null, initial: 'S' });
    assert.deepEqual(NS.sourceBadge('plugin:other:x', '·'), { paths: null, initial: '?' });
  });

  it('rows: source label, time, title and the message text as preview', () => {
    const trip = entry({
      topic: 'plugin:gatecontrol-skoda:trip', priority: 'info', title: 'Elroq: Fahrt erfasst',
      body: '7 km, 07:12–07:23 → Am Grenzgraben 8\n– privat oder geschäftlich?', created_at: at(9, 27),
    });
    const v = NS.rowView(trip, PTOPICS, t);
    assert.equal(v.label, 'Fahrzeuge');
    assert.equal(v.labelTitle, 'Fahrzeuge › Fahrt erfasst (Fahrtenbuch)');
    assert.equal(v.time, '09:27');
    assert.equal(v.title, 'Elroq: Fahrt erfasst');
    assert.equal(v.preview, '7 km, 07:12–07:23 → Am Grenzgraben 8 – privat oder geschäftlich?');
    assert.equal(v.unread, true);
    assert.equal(v.priority, null);
    // System: the topic is the label; no body → the topic as preview; priority pill for high/critical
    const sys = NS.rowView(entry({ body: '', state: 'read' }), PTOPICS, t);
    assert.equal(sys.label, 'Geräte & Gateways');
    assert.equal(sys.preview, 'Geräte & Gateways');
    assert.equal(sys.unread, false);
    assert.deepEqual(sys.priority, { label: 'push.priority.critical', cls: 'c-err' });
    assert.equal(NS.rowView(entry({ priority: 'high' }), TOPICS, t).priority.cls, 'c-warn');
    assert.equal(NS.rowView(entry({ title: '' }), TOPICS, t).title, '—');
  });

  it('days: Heute, Gestern, weekday, date; groups keep the list order', () => {
    const o = { now: NOW, locale: 'de' };
    assert.equal(NS.dayLabel(at(9, 5), t, o), 'ui.inbox.today');
    assert.equal(NS.dayLabel(at(23, 59, -1), t, o), 'ui.inbox.yesterdayDay');
    assert.equal(NS.dayLabel(at(9, 5, -3), t, o), 'Mittwoch');
    assert.equal(NS.dayLabel(at(9, 5, -30), t, o), '10. September');
    assert.equal(NS.dayLabel(new Date(2025, 11, 24, 9).toISOString(), t, o), '24. Dezember 2025');
    assert.equal(NS.dayLabel('kaputt', t, o), 'ui.inbox.earlier');
    const groups = NS.groupByDay([
      entry({ id: 1, created_at: at(21, 0) }), entry({ id: 2, created_at: at(8, 0) }),
      entry({ id: 3, created_at: at(20, 0, -1) }), entry({ id: 4, created_at: null, received_at: at(7, 0, -1) }),
      entry({ id: 5, created_at: at(9, 0, -8) }),
    ], t, o);
    assert.deepEqual(groups.map((g) => [g.label, g.items.map((e) => e.id)]), [
      ['ui.inbox.today', [1, 2]], ['ui.inbox.yesterdayDay', [3, 4]], ['2. Oktober', [5]],
    ]);
    assert.deepEqual(NS.groupByDay(null, t, o), []);
  });

  it('time: clock today, "gestern", weekday, date', () => {
    assert.equal(NS.formatTime(at(9, 5), t, { now: NOW }), '09:05');
    assert.equal(NS.formatTime(at(9, 5, -1), t, { now: NOW }), 'ui.inbox.yesterday');
    assert.equal(NS.formatTime(at(9, 5, -3), t, { now: NOW, locale: 'de' }), 'Mittwoch');
    assert.match(NS.formatTime(at(9, 5, -30), t, { now: NOW, locale: 'de' }), /^10\.09\.2026$/);
    assert.equal(NS.formatTime('kaputt', t, { now: NOW }), '');
  });

  it('keyboard: up / down step through the list, Home / End jump', () => {
    const ids = [5, 9, 12];
    assert.equal(NS.stepSelection(ids, 9, 'ArrowDown'), 12);
    assert.equal(NS.stepSelection(ids, 12, 'ArrowDown'), 12);
    assert.equal(NS.stepSelection(ids, 9, 'ArrowUp'), 5);
    assert.equal(NS.stepSelection(ids, 5, 'ArrowUp'), 5);
    assert.equal(NS.stepSelection(ids, null, 'ArrowDown'), 5);
    assert.equal(NS.stepSelection(ids, 9, 'Home'), 5);
    assert.equal(NS.stepSelection(ids, 9, 'End'), 12);
    assert.equal(NS.stepSelection(ids, 9, 'a'), null);
    assert.equal(NS.stepSelection([], 9, 'ArrowDown'), null);
  });

  it('nav badge text', () => {
    assert.equal(NS.badgeText(0), '');
    assert.equal(NS.badgeText(2), '2');
    assert.equal(NS.badgeText(250), '99+');
  });
});

describe('inbox detail', () => {
  it('breadcrumb: source › topic', () => {
    const c = NS.breadcrumb(entry({ topic: 'plugin:gatecontrol-skoda:trip' }), PTOPICS, t);
    assert.equal(c.source, 'Fahrzeuge');
    assert.equal(c.topic, 'Fahrt erfasst (Fahrtenbuch)');
    assert.ok(c.badge.paths);
    assert.deepEqual(NS.breadcrumb(entry({ topic: null }), PTOPICS, t).topic, '');
  });

  it('received line: day, clock and the path', () => {
    assert.equal(NS.receivedLine(entry(), t, { now: NOW }), 'ui.inbox.receivedAt(ui.inbox.today, 21:42 · push.via.tunnel)');
    assert.equal(NS.receivedLine(entry({ via: null, received_at: at(8, 15, -1) }), t, { now: NOW }), 'ui.inbox.receivedAt(ui.inbox.yesterdayDay, 08:15)');
    assert.equal(NS.receivedLine(entry({ received_at: null, created_at: null }), t, { now: NOW }), '');
  });

  it('facts: data.facts from the server, cleaned and capped at 6', () => {
    const e = entry({
      data: { facts: [{ label: 'Letztes Lebenszeichen', value: '21:40' }, { label: 'Betroffene Routen', value: 6 }, { label: '', value: 'x' }, 'junk'] },
    });
    assert.deepEqual(NS.entryFacts(e), [
      { label: 'Letztes Lebenszeichen', value: '21:40' },
      { label: 'Betroffene Routen', value: '6' },
    ]);
    const facts = Array.from({ length: 10 }, (_, i) => ({ label: `L${i}`, value: `V${i}` }));
    assert.equal(NS.entryFacts(entry({ data: { facts } })).length, 6);
    assert.deepEqual(NS.entryFacts(entry()), []);
  });

  it('buttons: answer buttons are equal and the given answer is marked; else the first is primary', () => {
    const answers = [
      { id: 'private', label: 'Privat', type: 'callback' },
      { id: 'business', label: 'Geschäftlich', type: 'callback' },
    ];
    assert.deepEqual(NS.actionButtons(entry({ actions: answers })), {
      buttons: [
        { id: 'private', label: 'Privat', cls: 'btn-sec', chosen: false },
        { id: 'business', label: 'Geschäftlich', cls: 'btn-sec', chosen: false },
      ],
      answered: '',
    });
    const done = NS.actionButtons(entry({ actions: answers, acted: 'business' }));
    assert.deepEqual(done.buttons.map((b) => [b.cls, b.chosen]), [['btn-sec', false], ['btn-pri', true]]);
    assert.equal(done.answered, 'Geschäftlich');
    const plain = NS.actionButtons(entry({ acted: 'mute_1h', actions: [
      { id: 'details', label: 'Details', type: 'open_app_route' }, { id: 'mute_1h', label: '1 h stumm', type: 'mute_1h' },
    ] }));
    assert.deepEqual(plain.buttons.map((b) => [b.cls, b.chosen]), [['btn-pri', false], ['btn-sec', false]]);
    assert.equal(plain.answered, '');
    assert.deepEqual(NS.actionButtons(entry({ actions: null })), { buttons: [], answered: '' });
  });
});

describe('inbox empty states and hints', () => {
  const base = { prefs: { enabled: true }, total: 0, shown: 0, filter: 'all', error: false };

  it('switched off, old server, not set up, error, filter, empty', () => {
    assert.equal(NS.emptyState({ ...base, prefs: { enabled: false }, status: {} }), 'off');
    assert.equal(NS.emptyState({ ...base, status: { state: 'disabled', reason: 'unsupported' } }), 'unsupported');
    assert.equal(NS.emptyState({ ...base, status: { state: 'disabled', reason: 'push_disabled' } }), 'unsupported');
    assert.equal(NS.emptyState({ ...base, status: { state: 'disabled', reason: 'not_configured' } }), 'notConfigured');
    assert.equal(NS.emptyState({ ...base, status: { state: 'connected' }, error: true }), 'error');
    assert.equal(NS.emptyState({ ...base, status: { state: 'connected' }, total: 3, filter: 'unread' }), 'filtered');
    assert.equal(NS.emptyState({ ...base, status: { state: 'connected' }, total: 3, filter: { read: 'unread', source: '' } }), 'filtered');
    assert.equal(NS.emptyState({ ...base, status: { state: 'connected' }, total: 3, filter: { read: 'all', source: 'src:system' } }), 'filtered');
    assert.equal(NS.emptyState({ ...base, status: { state: 'connected' }, total: 0, filter: { read: 'all', source: '' } }), 'empty');
    assert.equal(NS.emptyState({ ...base, status: { state: 'connected' } }), 'empty');
    assert.equal(NS.emptyState({ ...base, status: { state: 'connected' }, total: 3, shown: 3 }), null);
  });

  it('cached entries stay visible with a calm hint when the server cannot push', () => {
    assert.equal(NS.listHint({ state: 'disabled', reason: 'unsupported', enabled: true }), 'push.reason.unsupported');
    assert.equal(NS.listHint({ state: 'error', reason: 'network', enabled: true }), 'push.reason.network');
    assert.equal(NS.listHint({ state: 'connected', enabled: true }), null);
    assert.equal(NS.listHint({ state: 'disabled', reason: 'off', enabled: false }), null);
  });

  it('navigation from toasts and the tray', () => {
    const pages = ['status', 'rdp', 'services', 'inbox', 'logs', 'settings', 'setup'];
    assert.deepEqual(NS.navigateTarget({ route: 'inbox', id: 45 }, pages), { page: 'inbox', id: 45 });
    assert.deepEqual(NS.navigateTarget({ route: 'inbox', id: null }, pages), { page: 'inbox', id: null });
    assert.deepEqual(NS.navigateTarget({ route: 'services', id: 45 }, pages), { page: 'services', id: null });
    assert.deepEqual(NS.navigateTarget({ route: 'vpn', id: 45 }, pages), { page: 'status', id: null });
    // routes without a page here (gateways, plugin pages) open the entry
    assert.deepEqual(NS.navigateTarget({ route: 'gateways', id: 45 }, pages), { page: 'inbox', id: 45 });
    assert.deepEqual(NS.navigateTarget({ route: 'plg-skoda', id: 7 }, pages), { page: 'inbox', id: 7 });
    // the messenger's route opens the chats page when the app has it
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-messenger', id: 7 }, [...pages, 'chats']), { page: 'chats', id: null });
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-messenger', id: 7 }, pages.filter((p) => p !== 'chats')), { page: 'inbox', id: 7 });
    // Schule: a toast the core claimed opens the page with its context (child / day / message)
    const ctx = { kind: 'changes', studentId: 3, date: '2026-10-20', messageId: null };
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-schule', id: 7, context: ctx }, [...pages, 'schule']), { page: 'schule', id: null, context: ctx });
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-schule', id: 7 }, [...pages, 'schule']), { page: 'schule', id: null, context: null });
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-schule', id: 7, context: ctx }, pages), { page: 'inbox', id: 7 });
    // GateDrop: a received send opens the page on Empfangen / Links
    const gctx = { tab: 'received', sendId: '41' };
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-gatedrop', id: 8, context: gctx }, [...pages, 'gatedrop']), { page: 'gatedrop', id: null, context: gctx });
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-gatedrop', id: 8, context: gctx }, pages), { page: 'inbox', id: 8 });
    assert.deepEqual(NS.routeTarget('plg-gatecontrol-gatedrop/links', [...pages, 'gatedrop']), { page: 'gatedrop', context: { tab: 'links', sendId: null } });
    assert.deepEqual(NS.routeTarget('plg-gatecontrol-gatedrop', [...pages, 'gatedrop']), { page: 'gatedrop', context: null });
    // Vault: a toast click carries the core's context (emergency access, a shared vault)
    const vctx = { topic: 'emergency', event: 'requested', vaultId: null, emergencyId: 'a'.repeat(24), page: 'emergency' };
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-vault', id: 9, context: vctx }, [...pages, 'vault']), { page: 'vault', id: null, context: vctx });
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-vault', id: 9, context: vctx }, pages), { page: 'inbox', id: 9 });
    assert.deepEqual(NS.routeTarget('plg-gatecontrol-vault', [...pages, 'vault']), { page: 'vault', context: null });
    assert.equal(NS.routeTarget('plg-gatecontrol-vault/emergency', [...pages, 'vault']).context.page, 'emergency');
    assert.equal(NS.routeTarget('plg-gatecontrol-vault', pages), null);
  });
});

describe('settings: Benachrichtigungen', () => {
  it('status card', () => {
    const since = new Date(2026, 9, 10, 6, 12).toISOString();
    assert.deepEqual(NS.statusView({ state: 'connected', via: 'tunnel', since, serverHost: 'gc.example.de', dnd: { active: false } }), {
      tone: 'ok', stateKey: 'push.state.connected', reasonKey: null, server: 'gc.example.de',
      viaKey: 'push.via.tunnel', since: '06:12', dnd: null,
    });
    const old = NS.statusView({ state: 'disabled', reason: 'unsupported', serverHost: 'gc.example.de' });
    assert.equal(old.tone, 'off');
    assert.equal(old.reasonKey, 'push.reason.unsupported');
    assert.equal(old.viaKey, null);
    assert.equal(NS.statusView({ state: 'error', reason: 'network' }).tone, 'err');
    assert.equal(NS.statusView({ state: 'connecting' }).tone, 'warn');
    assert.equal(NS.statusView(null).stateKey, 'push.state.stopped');
    const until = new Date(2026, 9, 10, 23, 5).getTime();
    assert.equal(NS.statusView({ state: 'connected', dnd: { active: true, until } }).dnd, '23:05');
  });

  it('topics on this PC: on = not muted; toggling updates mutedTopics', () => {
    const rows = NS.topicRows(TOPICS, ['plugin:skoda:charging']);
    assert.deepEqual(rows.map((r) => [r.id, r.on]), [
      ['security', true], ['devices', true], ['admin_notice', true], ['plugin:skoda:charging', false],
    ]);
    assert.deepEqual(NS.toggleTopic(['plugin:skoda:charging'], 'security', false), ['plugin:skoda:charging', 'security']);
    assert.deepEqual(NS.toggleTopic(['plugin:skoda:charging'], 'plugin:skoda:charging', true), []);
    assert.deepEqual(NS.topicRows(null, null), []);
  });

  it('kill-switch note: warning when push only works through the tunnel', () => {
    assert.equal(NS.killSwitchNote({ killSwitch: { active: false, tunnelOnly: false } }), null);
    assert.deepEqual(NS.killSwitchNote({ killSwitch: { active: true, tunnelOnly: true } }), { tone: 'warn', key: 'push.tunnelOnly' });
    assert.deepEqual(NS.killSwitchNote({ killSwitch: { active: true, tunnelOnly: false } }), { tone: 'ok', key: 'push.killSwitchOk' });
    assert.equal(NS.killSwitchNote({}), null);
  });
});

describe('renderer wiring', () => {
  const html = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'index.html'), 'utf8');
  const renderer = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'renderer.js'), 'utf8');

  it('shows the quiet hours and opens the portal tab for changing them', () => {
    assert.ok(html.includes('id="notify-quiet-value"'));
    assert.ok(html.includes('id="notify-quiet-detail"'));
    assert.match(renderer, /NS\.quietView\(inbox\.status\)/);
    assert.match(renderer, /notifyApi\.quiet\(\{ refresh: true \}\)/);
    assert.match(renderer, /notifyApi\.openQuietHours\(\)/);
    assert.match(renderer, /portal\.open\(\{ next: '\/portal#benachrichtigungen' \}\)/);
  });

  it('loads notify-state.js before renderer.js', () => {
    assert.ok(html.indexOf('<script src="notify-state.js"></script>') > -1);
    assert.ok(html.indexOf('notify-state.js') < html.indexOf('renderer.js'));
  });

  it('has the nav entry with badge, the page and the settings tab', () => {
    assert.match(html, /id="nav-inbox"[^>]*data-page="inbox"/);
    assert.match(html, /id="inbox-badge"/);
    assert.match(html, /id="page-inbox"/);
    assert.match(html, /data-tab="notify"/);
    assert.match(html, /id="set-notify"/);
    for (const id of ['notify-enabled', 'notify-direct', 'notify-toasts', 'notify-critical', 'notify-topics', 'notify-test', 'notify-ks-note', 'notify-quiet-portal']) {
      assert.ok(html.includes(`id="${id}"`), id);
    }
  });

  it('uses the notify bridge and follows its events', () => {
    for (const fn of ['list(', 'read(', 'action(', 'getPrefs(', 'setPrefs(', 'test(', 'status(', 'dnd(', 'onNew(', 'onUpdate(', 'onStatus(', 'onNavigate(']) {
      assert.ok(renderer.includes(`notifyApi.${fn}`), fn);
    }
  });

  it('one compact filter row (Alle | Ungelesen + Quelle) and a keyboard list', () => {
    assert.match(html, /id="inbox-read-seg"/);
    assert.match(html, /data-read="all"/);
    assert.match(html, /data-read="unread"/);
    assert.match(html, /<select[^>]*id="inbox-source"/);
    assert.match(html, /id="inbox-list"[^>]*role="listbox"/);
    assert.doesNotMatch(html, /fchip/);
    assert.match(renderer, /sessionStorage/);
    assert.match(renderer, /NS\.stepSelection\(/);
    assert.match(renderer, /NS\.groupByDay\(/);
  });

  it('builds entries with textContent only (server text is never HTML)', () => {
    const block = renderer.slice(renderer.indexOf('//  NOTIFICATIONS'), renderer.indexOf('// Initial paint'));
    assert.ok(block.length > 1000);
    assert.doesNotMatch(block, /innerHTML|insertAdjacentHTML|outerHTML/);
  });
});

describe('quietView', () => {
  it('unknown (older server, not connected yet) → nothing shown', () => {
    assert.equal(NS.quietView(null), null);
    assert.equal(NS.quietView({ state: 'connected', quiet: null, quietKnown: false }), null);
    assert.equal(NS.quietView({ known: false, quiet: null }), null);
  });

  it('known without quiet hours', () => {
    assert.deepEqual(NS.quietView({ quietKnown: true, quiet: null }), { key: 'ui.notify.quietNone', params: null, detailKey: null });
  });

  it('range with time zone and the critical rule', () => {
    const v = NS.quietView({ quietKnown: true, quiet: { from: '22:00', to: '07:00', tz: 'Europe/Berlin', criticalBypass: true } });
    assert.equal(t(v.key, v.params), 'ui.notify.quietRangeTz(22:00,07:00,Europe/Berlin)');
    assert.equal(v.detailKey, 'ui.notify.quietCriticalBypass');
    const w = NS.quietView({ known: true, quiet: { from: '23:30', to: '06:00', tz: null, criticalBypass: false } });
    assert.equal(t(w.key, w.params), 'ui.notify.quietRange(23:30,06:00)');
    assert.equal(w.detailKey, 'ui.notify.quietCriticalSilent');
  });

  it('malformed times are not shown as a range', () => {
    assert.equal(NS.quietView({ quietKnown: true, quiet: { from: '<b>', to: '07:00' } }).key, 'ui.notify.quietNone');
  });
});
