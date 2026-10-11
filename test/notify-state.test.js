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

describe('inbox list', () => {
  const items = [
    entry(),
    entry({ id: 46, seq: 124, topic: 'security', priority: 'normal', state: 'read' }),
    entry({ id: 47, seq: 125, topic: 'devices', priority: 'info', state: 'read' }),
  ];

  it('filters: all, unread, topic', () => {
    assert.equal(NS.filterItems(items, 'all').length, 3);
    assert.deepEqual(NS.filterItems(items, 'unread').map((e) => e.id), [45]);
    assert.deepEqual(NS.filterItems(items, 'security').map((e) => e.id), [46]);
    assert.deepEqual(NS.filterItems(null, 'all'), []);
  });

  it('filter chips: Alle, Ungelesen, then topics with entries in server order', () => {
    const opts = NS.filterOptions(items, TOPICS, 'all', t);
    assert.deepEqual(opts.map((o) => o.id), ['all', 'unread', 'security', 'devices']);
    assert.deepEqual(opts.map((o) => o.count), [3, 1, 1, 2]);
    assert.equal(opts[2].label, 'Sicherheit');
    // the active topic stays even when it has no entries any more
    assert.deepEqual(NS.filterOptions([], TOPICS, 'admin_notice', t).map((o) => o.id), ['all', 'unread', 'admin_notice']);
  });

  it('topic labels: from the server, readable fallback for plugin topics', () => {
    assert.equal(NS.topicLabel(TOPICS, 'devices'), 'Geräte & Gateways');
    assert.equal(NS.topicLabel([], 'plugin:skoda:charging'), 'skoda · charging');
    assert.equal(NS.topicLabel(TOPICS, null), '');
  });

  it('row meta: coloured priority only for high/critical, topic and time', () => {
    const meta = NS.rowMeta(entry(), TOPICS, t, { now: NOW });
    assert.deepEqual(meta.priority, { label: 'push.priority.critical', cls: 'c-err' });
    assert.equal(meta.text, 'Geräte & Gateways · 21:42');
    assert.equal(NS.rowMeta(entry({ priority: 'normal' }), TOPICS, t, { now: NOW }).priority, null);
    assert.equal(NS.rowMeta(entry({ priority: 'high' }), TOPICS, t, { now: NOW }).priority.cls, 'c-warn');
  });

  it('time: clock today, "gestern", weekday, date', () => {
    assert.equal(NS.formatTime(at(9, 5), t, { now: NOW }), '09:05');
    assert.equal(NS.formatTime(at(9, 5, -1), t, { now: NOW }), 'ui.inbox.yesterday');
    assert.equal(NS.formatTime(at(9, 5, -3), t, { now: NOW, locale: 'de' }), 'Mittwoch');
    assert.match(NS.formatTime(at(9, 5, -30), t, { now: NOW, locale: 'de' }), /^10\.09\.2026$/);
    assert.equal(NS.formatTime('kaputt', t, { now: NOW }), '');
  });

  it('nav badge text', () => {
    assert.equal(NS.badgeText(0), '');
    assert.equal(NS.badgeText(2), '2');
    assert.equal(NS.badgeText(250), '99+');
  });
});

describe('inbox detail', () => {
  it('pill: priority · topic', () => {
    assert.deepEqual(NS.detailPill(entry(), TOPICS, t), { label: 'push.priority.critical · Geräte & Gateways', cls: 'c-err' });
    assert.deepEqual(NS.detailPill(entry({ priority: 'info', topic: null }), TOPICS, t), { label: 'push.priority.info', cls: '' });
  });

  it('facts: data.facts from the server plus when and how it arrived', () => {
    const e = entry({
      data: { facts: [{ label: 'Letztes Lebenszeichen', value: '21:40' }, { label: 'Betroffene Routen', value: 6 }, { label: '', value: 'x' }, 'junk'] },
    });
    assert.deepEqual(NS.entryFacts(e, t, { now: NOW }), [
      { label: 'Letztes Lebenszeichen', value: '21:40' },
      { label: 'Betroffene Routen', value: '6' },
      { label: 'ui.inbox.received', value: '21:42 · push.via.tunnel' },
    ]);
    const old = NS.entryFacts(entry({ via: null, received_at: at(8, 15, -1) }), t, { now: NOW });
    assert.deepEqual(old, [{ label: 'ui.inbox.received', value: 'ui.inbox.yesterday 08:15' }]);
  });

  it('facts are capped (at most 6 from the server)', () => {
    const facts = Array.from({ length: 10 }, (_, i) => ({ label: `L${i}`, value: `V${i}` }));
    assert.equal(NS.entryFacts(entry({ data: { facts } }), t, { now: NOW }).length, 7);
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
      assert.match(html, new RegExp(`id="${id}"`), id);
    }
  });

  it('uses the notify bridge and follows its events', () => {
    for (const fn of ['list(', 'read(', 'action(', 'getPrefs(', 'setPrefs(', 'test(', 'status(', 'dnd(', 'onNew(', 'onUpdate(', 'onStatus(', 'onNavigate(']) {
      assert.ok(renderer.includes(`notifyApi.${fn}`), fn);
    }
  });

  it('builds entries with textContent only (server text is never HTML)', () => {
    const block = renderer.slice(renderer.indexOf('//  NOTIFICATIONS'), renderer.indexOf('// Initial paint'));
    assert.ok(block.length > 1000);
    assert.doesNotMatch(block, /innerHTML|insertAdjacentHTML|outerHTML/);
  });
});
