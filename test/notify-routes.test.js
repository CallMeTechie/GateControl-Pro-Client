'use strict';

// "Wo Mitteilungen erscheinen" (src/renderer/notify-routes.js): choices per
// kind (GateControl / family chat only with canFamily / own chat), locked
// kinds, no sink, refusal texts, and how the pages load it.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const NR = require('../src/renderer/notify-routes');
const NS = require('../src/renderer/notify-state');

const ROOT = path.join(__dirname, '..');
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);

const schule = { source: 'plugin:gatecontrol-schule', label: 'Schule', topics: [
  { id: 'plugin:gatecontrol-schule:messages', label: 'Nachrichten der Schule', dest: 'family', locked: false, familySetBy: 'Marc' },
  { id: 'plugin:gatecontrol-schule:changes', label: 'Vertretungen', dest: 'own', locked: false, familySetBy: null },
] };
const core = { source: 'core', label: 'GateControl', topics: [
  { id: 'security', label: 'Sicherheit', dest: 'inbox', locked: true, familySetBy: null },
  { id: 'devices', label: 'Geräte', dest: 'inbox', locked: false, familySetBy: null },
] };
const routes = (extra = {}) => ({ sink: true, canFamily: true, groups: [core, schule], ...extra });

describe('notify-routes view logic', () => {
  it('choices: GateControl always, family chat only for those who may set it, own chat with a sink', () => {
    const [sec, dev] = core.topics;
    const [msgs, changes] = schule.topics;
    assert.deepEqual(NR.options(routes(), dev), ['inbox', 'family', 'own']);
    assert.deepEqual(NR.options(routes({ canFamily: false }), dev), ['inbox', 'own']);
    // set by an adult: shown, but not changeable for a child
    assert.deepEqual(NR.options(routes({ canFamily: false }), msgs), ['inbox', 'family', 'own']);
    assert.equal(NR.editable(routes({ canFamily: false }), msgs), false);
    assert.equal(NR.editable(routes({ canFamily: false }), changes), true);
    // locked kinds and no sink: GateControl only
    assert.deepEqual(NR.options(routes(), sec), ['inbox']);
    assert.equal(NR.editable(routes(), sec), false);
    assert.deepEqual(NR.options(routes({ sink: false }), changes), ['inbox']);
    assert.equal(NR.effective(routes({ sink: false }), changes), 'inbox');
    assert.equal(NR.editable(routes({ sink: false }), changes), false);
  });

  it('texts: destinations, hints (family for everyone, set by, locked), own chat named after its source', () => {
    const [sec] = core.topics;
    const [msgs, changes] = schule.topics;
    assert.equal(NR.destLabel('own', schule, t), 'push.routes.dest.own(Schule)');
    assert.equal(NR.optionLabel('family', schule, t), 'push.routes.option.family');
    assert.equal(NR.optionLabel('own', schule, t), 'push.routes.option.own(Schule)');
    assert.equal(NR.hint(routes(), sec, core, t), '', 'the lock says it');
    assert.equal(NR.hint(routes(), msgs, schule, t), 'push.routes.hint.family · push.routes.familySetBy(Marc)');
    assert.equal(NR.hint(routes({ canFamily: false }), { ...msgs, familySetBy: null }, schule, t), 'push.routes.familySet · push.routes.familyOnlyAdults');
    assert.equal(NR.hint(routes(), changes, schule, t), 'push.routes.hint.own(Schule)');
    assert.equal(NR.hint(routes({ sink: false }), changes, schule, t), 'push.routes.hint.inbox');
  });

  it('a choice is shown at once; the family setter goes away with another choice', () => {
    const next = NR.withDest(routes(), 'plugin:gatecontrol-schule:messages', 'own');
    const tp = next.groups[1].topics[0];
    assert.deepEqual([tp.dest, tp.familySetBy], ['own', null]);
    assert.equal(routes().groups[1].topics[0].dest, 'family', 'not changed in place');
  });

  it('refusals in words; older servers hide the page', () => {
    assert.equal(NR.errorKey('family_not_allowed'), 'push.routes.err.family');
    assert.equal(NR.errorKey('locked'), 'push.routes.err.locked');
    assert.equal(NR.errorKey('no_sink'), 'push.routes.err.noSink');
    assert.equal(NR.errorKey('no_user'), 'push.routes.err.forbidden');
    assert.equal(NR.errorKey('unknown_topic'), 'push.routes.err.unknownTopic');
    assert.equal(NR.errorKey('push_disabled'), 'push.routes.err.pushDisabled');
    assert.equal(NR.errorKey('ECONNREFUSED'), 'push.routes.err.network');
    assert.equal(NR.errorKey('http_500'), 'push.routes.err.failed');
    assert.deepEqual(NR.viewState({ ok: false, error: 'unsupported' }).state, 'unsupported');
    assert.deepEqual(NR.viewState({ ok: false, error: 'push_disabled' }).state, 'error');
    assert.deepEqual(NR.viewState({ ok: true, routes: { sink: true, canFamily: false, groups: [] } }).state, 'empty');
    assert.deepEqual(NR.viewState({ ok: true, routes: routes() }).state, 'ready');
    assert.deepEqual(NR.viewState(null).state, 'error');
    assert.equal(NR.supported({ routes() {}, setRoute() {} }), true);
    assert.equal(NR.supported({ routes() {} }), false, 'an older core without setRoute');
    assert.equal(NR.supported(null), false);
  });
});

describe('the own chat of a choice (GateControl 1.192)', () => {
  const chat = (created) => ({ source: 'plugin:gatecontrol-schule', label: 'Schule', conversationId: '42', created });

  it('says whether the own chat was created or is the existing one; nothing without a chat', () => {
    assert.equal(NR.chatNotice({ ok: true, routes: routes(), chat: chat(true) }, 'own', t), 'push.routes.chatCreated(Schule)');
    assert.equal(NR.chatNotice({ ok: true, routes: routes(), chat: chat(false) }, 'own', t), 'push.routes.chatExisting(Schule)');
    assert.equal(NR.chatNotice({ ok: true, routes: routes(), chat: null }, 'own', t), '', 'older server or failure');
    assert.equal(NR.chatNotice({ ok: true, routes: routes() }, 'own', t), '', 'older core');
    assert.equal(NR.chatNotice({ ok: true, routes: routes(), chat: chat(true) }, 'inbox', t), '');
    assert.equal(NR.chatNotice({ ok: false, error: 'no_sink', chat: chat(true) }, 'own', t), '');
    assert.equal(NR.chatNotice({ ok: true, chat: { label: '' } }, 'own', t), '');
    assert.equal(NR.chatNotice(null, 'own', t), '');
  });

  /** A tiny DOM: enough for mount() (elements, attributes, children, change events). */
  function fakeDom() {
    const node = (tag) => {
      const n = {
        tagName: tag, children: [], attrs: {}, listeners: {}, textContent: '', className: '', value: '',
        get firstChild() { return n.children[0] || null; },
        setAttribute(k, v) { n.attrs[k] = v; },
        removeAttribute(k) { delete n.attrs[k]; },
        addEventListener(ev, fn) { (n.listeners[ev] = n.listeners[ev] || []).push(fn); },
        appendChild(c) { n.children.push(c); return c; },
        removeChild(c) { n.children.splice(n.children.indexOf(c), 1); return c; },
        all(pred, out = []) { for (const c of n.children) { if (pred(c)) out.push(c); if (c.all) c.all(pred, out); } return out; },
      };
      return n;
    };
    return { createElement: node, createElementNS: (_, tag) => node(tag), createTextNode: (text) => ({ text }) };
  }

  /** notify-routes.js with `document` (its factory takes the global of the page). */
  function withDom(fn) {
    const file = require.resolve('../src/renderer/notify-routes');
    const had = Object.prototype.hasOwnProperty.call(globalThis, 'self');
    const prev = globalThis.self;
    const document = fakeDom();
    globalThis.self = { document };
    delete require.cache[file];
    try { return fn(require(file), document); } finally {
      delete require.cache[file];
      if (had) globalThis.self = prev; else delete globalThis.self;
    }
  }

  async function choose(answer, dest) {
    const toasts = [];
    const chats = [];
    const api = { routes: async () => ({ ok: true, routes: routes() }), setRoute: async () => answer };
    const view = withDom((M, document) => {
      const host = document.createElement('div');
      return { host, page: M.mount(host, { api, t, toast: (msg, type) => toasts.push([msg, type]), onChat: (c) => chats.push(c) }) };
    });
    await view.page.load();
    const sel = view.host.all((n) => n.tagName === 'select' && n.attrs['data-topic'] === 'devices')[0];
    sel.value = dest;
    for (const fn of sel.listeners.change) fn();
    await new Promise((r) => setImmediate(r));
    return { toasts, chats };
  }

  it('after "own": the toast and a reload of the chat list; "inbox": neither', async () => {
    const created = await choose({ ok: true, routes: routes(), chat: chat(true) }, 'own');
    assert.deepEqual(created.toasts, [['push.routes.chatCreated(Schule)', 'success']]);
    assert.deepEqual(created.chats, [chat(true)]);
    const existing = await choose({ ok: true, routes: routes(), chat: chat(false) }, 'own');
    assert.deepEqual(existing.toasts, [['push.routes.chatExisting(Schule)', 'success']]);
    assert.equal(existing.chats.length, 1);
    const older = await choose({ ok: true, routes: routes() }, 'own');
    assert.deepEqual([older.toasts, older.chats], [[], []]);
    const inbox = await choose({ ok: true, routes: routes({ groups: [{ ...core, topics: [core.topics[0], { ...core.topics[1], dest: 'own' }] }, schule] }), chat: null }, 'inbox');
    assert.deepEqual([inbox.toasts, inbox.chats], [[], []]);
    const refused = await choose({ ok: false, error: 'no_sink' }, 'own');
    assert.deepEqual([refused.toasts, refused.chats], [[['push.routes.err.noSink', 'error']], []]);
  });

  it('both pages reload the chat list after it (chat settings and Einstellungen)', () => {
    const renderer = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'renderer.js'), 'utf8');
    const settings = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'chat-settings.js'), 'utf8');
    const view = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'chat-view.js'), 'utf8');
    assert.match(renderer, /onChat: \(\) => \{ chatView\?\.refreshList\(\{ server: true \}\); \}/);
    assert.match(settings, /kit\.refreshList\(\{ server: true \}\)/);
    assert.match(settings, /GCNotifyRoutes\.mount\(host, \{[^}]*onChat/);
    assert.equal((view.match(/refreshList: \(opts\) => refreshList\(opts\)/g) || []).length, 2, 'in the kit and the public view');
  });
});

describe('card links in chats (notify-state routeTarget)', () => {
  const pages = ['status', 'inbox', 'chats', 'schule', 'settings'];

  it('Schule on its tab or message, the messenger on the chats; others → the portal (null)', () => {
    assert.deepEqual(NS.routeTarget('plg-gatecontrol-schule/messages/4711', pages), { page: 'schule', context: { kind: 'messages', studentId: null, date: null, messageId: 4711 } });
    assert.deepEqual(NS.routeTarget('plg-gatecontrol-schule/absences', pages), { page: 'schule', context: { kind: 'absences', studentId: null, date: null, messageId: null } });
    assert.deepEqual(NS.routeTarget('plg-gatecontrol-schule', pages), { page: 'schule', context: null });
    assert.deepEqual(NS.routeTarget('plg-gatecontrol-messenger', pages), { page: 'chats', context: null });
    assert.equal(NS.routeTarget('plg-gatecontrol-door', pages), null);
    assert.equal(NS.routeTarget('plg-gatecontrol-schule/messages/1', ['status', 'inbox']), null, 'no Schule page now');
    assert.equal(NS.routeTarget(null, pages), null);
  });
});

describe('pages with "Wo Mitteilungen erscheinen"', () => {
  const html = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'index.html'), 'utf8');
  const renderer = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'renderer.js'), 'utf8');
  const settings = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'chat-settings.js'), 'utf8');
  const src = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'notify-routes.js'), 'utf8');

  it('loads notify-routes.js before the chat settings and renderer.js; the settings card starts hidden', () => {
    const a = html.indexOf('<script src="notify-routes.js">');
    assert.ok(a > 0 && a < html.indexOf('<script src="chat-settings.js">') && a < html.indexOf('<script src="renderer.js">'));
    assert.match(html, /id="notify-routes-card"[^>]*hidden/);
    assert.ok(html.includes('id="notify-routes"'));
    assert.match(renderer, /GCNotifyRoutes\.mount\(\$\('#notify-routes'\)/);
    assert.match(settings, /GCNotifyRoutes\.mount\(host/);
  });

  it('never writes server text as HTML', () => {
    assert.doesNotMatch(src, /\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write\(/);
  });

  it('every push.routes.* key exists in the core locales (de + en)', (tctx) => {
    let dir = null;
    for (const d of [path.join(ROOT, 'node_modules', '@gatecontrol', 'client-core'), path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) {
      if (fs.existsSync(path.join(d, 'src', 'i18n', 'locales', 'de.json'))) { dir = d; break; }
    }
    if (!dir) { tctx.skip('core not available'); return; }
    const flat = (obj, p = '', out = {}) => { for (const [k, v] of Object.entries(obj)) { const key = p ? `${p}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(fs.readFileSync(path.join(dir, 'src', 'i18n', 'locales', 'de.json'), 'utf8')));
    const en = flat(JSON.parse(fs.readFileSync(path.join(dir, 'src', 'i18n', 'locales', 'en.json'), 'utf8')));
    const keys = new Set();
    for (const s of [src, settings, html]) for (const m of s.matchAll(/['"`](push\.routes\.[A-Za-z0-9_.]+[A-Za-z0-9_])['"`]/g)) keys.add(m[1]);
    assert.ok(keys.size > 25, `only ${keys.size} keys found`);
    for (const key of keys) {
      assert.ok(key in de, `de: ${key}`);
      assert.ok(key in en, `en: ${key}`);
    }
  });
});
