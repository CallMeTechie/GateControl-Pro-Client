'use strict';

// View logic of the page "Vault" and its quick search (src/renderer/vault-state.js,
// no DOM): fields per type, list filter / sections / chips, quick search ranking
// and its keys (Enter, Strg+B / T / O, ↑ ↓, Esc), the edit draft ↔ entry JSON v1,
// header / footer texts, strength and master password rule, errors, emergency
// texts, import summary, push targets; that the page loads the Vault scripts,
// that the views never use innerHTML, and that every vault.* key they use
// exists in both app locales.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const VS = require('../src/renderer/vault-state');

const ROOT = path.join(__dirname, '..');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const at = (y, mo, d, h, m) => new Date(y, mo - 1, d, h, m).getTime();
const NOW = at(2026, 10, 23, 9, 30);

const sum = (o = {}) => ({
  id: 'e'.repeat(20), vaultId: 'v'.repeat(20), rev: 1, type: 'login', title: 'GitHub', subtitle: 'marc', username: 'marc',
  urls: ['https://github.com'], host: 'github.com', fav: false, tags: [], hasPassword: true, hasTotp: false,
  trashed: false, updatedAt: null, device: null, pending: false, ...o,
});
const key = (k, mods = {}) => ({ key: k, ctrlKey: false, altKey: false, shiftKey: false, metaKey: false, ...mods });

describe('quick search keys (Strg+Alt+P window)', () => {
  it('maps the keys of the mockup W2', () => {
    assert.equal(VS.quickKey(key('Enter')), 'password');
    assert.equal(VS.quickKey(key('b', { ctrlKey: true })), 'username');
    assert.equal(VS.quickKey(key('B', { ctrlKey: true })), 'username', 'caps lock');
    assert.equal(VS.quickKey(key('t', { ctrlKey: true })), 'totp');
    assert.equal(VS.quickKey(key('o', { ctrlKey: true })), 'url');
    assert.equal(VS.quickKey(key('Escape')), 'close');
    assert.equal(VS.quickKey(key('ArrowDown')), 'down');
    assert.equal(VS.quickKey(key('ArrowUp')), 'up');
    assert.equal(VS.quickKey(key('n', { ctrlKey: true })), 'down');
    assert.equal(VS.quickKey(key('p', { ctrlKey: true })), 'up');
  });

  it('leaves typing and other shortcuts alone', () => {
    assert.equal(VS.quickKey(key('b')), null, 'plain letters are search text');
    assert.equal(VS.quickKey(key('a', { ctrlKey: true })), null, 'select all');
    assert.equal(VS.quickKey(key('v', { ctrlKey: true })), null, 'paste');
    assert.equal(VS.quickKey(key('p', { ctrlKey: true, altKey: true })), null, 'the global shortcut itself / AltGr');
    assert.equal(VS.quickKey(key('Enter', { shiftKey: true })), null);
    assert.equal(VS.quickKey(key('Enter', { isComposing: true })), null, 'IME composition');
    assert.equal(VS.quickKey(null), null);
  });

  it('turns an action into a copy / open for the selected hit', () => {
    const login = sum({ hasTotp: true, urls: ['http://nas.local:5000', 'https://x'] });
    assert.deepEqual(VS.quickCommand('password', login), { kind: 'copy', field: 'password' });
    assert.deepEqual(VS.quickCommand('username', login), { kind: 'copy', field: 'username' });
    assert.deepEqual(VS.quickCommand('totp', login), { kind: 'copy', field: 'totp' });
    assert.deepEqual(VS.quickCommand('url', login), { kind: 'open', url: 'http://nas.local:5000' });
    const code = sum({ type: 'totp', hasPassword: false, hasTotp: true, username: '', urls: [] });
    assert.deepEqual(VS.quickCommand('password', code), { kind: 'copy', field: 'totp' }, 'Enter on a 2FA-only entry copies the code');
    assert.equal(VS.quickCommand('username', code), null);
    assert.equal(VS.quickCommand('url', code), null);
    assert.equal(VS.quickCommand('url', sum({ urls: ['javascript:alert(1)', 'ftp://x'] })), null, 'only http(s) opens');
    const note = sum({ type: 'note', hasPassword: false, username: '', urls: [] });
    assert.equal(VS.quickCommand('password', note), null);
    assert.equal(VS.quickCommand('password', null), null);
  });

  it('moves the selection around the hits', () => {
    assert.equal(VS.moveSelection(0, 'down', 3), 1);
    assert.equal(VS.moveSelection(2, 'down', 3), 0);
    assert.equal(VS.moveSelection(0, 'up', 3), 2);
    assert.equal(VS.moveSelection(5, null, 3), 2, 'list got shorter');
    assert.equal(VS.moveSelection(1, 'down', 0), 0);
  });

  it('ranks hits: title start, word start, title, elsewhere; favourites first; no trash', () => {
    const list = [
      sum({ id: 'a'.repeat(20), title: 'Bausparkasse', subtitle: 'Vertrag' }),
      sum({ id: 'b'.repeat(20), title: 'Sparkasse (Anna)', subtitle: 'anna' }),
      sum({ id: 'c'.repeat(20), title: 'Sparkasse', subtitle: 'marc', fav: true }),
      sum({ id: 'd'.repeat(20), title: 'Online-Banking', subtitle: 'sparkasse-user' }),
      sum({ id: 'e'.repeat(20), title: 'Meine Sparkasse' }),
      sum({ id: 'f'.repeat(20), title: 'Sparkasse alt', trashed: true }),
    ];
    assert.deepEqual(VS.quickSearch(list, 'spark').map((e) => e.title), ['Sparkasse', 'Sparkasse (Anna)', 'Meine Sparkasse', 'Bausparkasse', 'Online-Banking']);
    assert.deepEqual(VS.quickSearch(list, '  '), []);
    assert.equal(VS.quickSearch(list, 'spark', 2).length, 2);
    assert.deepEqual(VS.quickSearch([sum({ title: 'Müller GmbH' })], 'mul').map((e) => e.title), ['Müller GmbH'], 'umlauts fold');
  });
});

describe('list', () => {
  const list = [
    sum({ id: 'a'.repeat(20), title: 'Amazon', subtitle: 'marc@x', host: 'amazon.de', vaultId: 'p'.repeat(20) }),
    sum({ id: 'b'.repeat(20), title: 'Netflix', subtitle: 'familie@x', host: 'netflix.com', vaultId: 's'.repeat(20), fav: true }),
    sum({ id: 'c'.repeat(20), title: 'DS218+ (NAS)', subtitle: 'admin', host: 'nas.gc.internal', urls: ['https://nas.gc.internal:5001'], vaultId: 'p'.repeat(20) }),
  ];

  it('filters by vault and every search word', () => {
    assert.equal(VS.filterEntries(list, { vaultId: 'p'.repeat(20) }).length, 2);
    assert.deepEqual(VS.filterEntries(list, { query: 'nas admin' }).map((e) => e.title), ['DS218+ (NAS)']);
    assert.deepEqual(VS.filterEntries(list, { query: 'gc.internal' }).map((e) => e.title), ['DS218+ (NAS)']);
    assert.equal(VS.filterEntries(list, { query: 'nothing' }).length, 0);
  });

  it('favourites first unless searching', () => {
    assert.deepEqual(VS.sections(list).map((s) => [s.key, s.items.length]), [['favorites', 1], ['all', 3]]);
    assert.deepEqual(VS.sections(list, { query: 'n' }).map((s) => s.key), ['all']);
    assert.deepEqual(VS.sections([list[0]]).map((s) => s.key), ['all']);
  });

  it('row text and chips', () => {
    assert.equal(VS.rowSub(list[2]), 'admin · nas.gc.internal');
    assert.equal(VS.rowSub(sum({ subtitle: '', host: null })), '');
    const vaults = [{ id: 'p'.repeat(20), name: 'Persönlich', personal: true, count: 168 }, { id: 's'.repeat(20), name: null, count: 15 }];
    assert.deepEqual(VS.filterChips(vaults, t).map((c) => c.label), [
      'vault.filter.count(name=vault.filter.all,count=183)', 'vault.filter.count(name=Persönlich,count=168)', 'vault.filter.count(name=…,count=15)',
    ]);
  });

  it('letter avatars with the Android tones', () => {
    assert.equal(VS.letter('ds218+'), 'D');
    assert.equal(VS.letter('  (ärger)'), 'Ä');
    assert.equal(VS.letter('—'), '#');
    assert.equal(VS.hashCode('hello'), 99162322, 'Java String.hashCode');
    assert.equal(VS.tone('Hello'), 99162322 % 5, 'by the lower-case title');
    for (const s of ['a', 'Netflix', 'Sparkasse', '']) assert.ok(VS.tone(s) >= 0 && VS.tone(s) <= 4);
  });
});

describe('texts', () => {
  it('header: entries · vaults · synced', () => {
    const st = { sync: { state: 'done' }, lastSyncAt: at(2026, 10, 23, 7, 42), pending: 0 };
    assert.equal(VS.headerText(t, { entries: 214, vaults: 3, status: st }, 'de', NOW), 'vault.head.entries.other(count=214) · vault.head.vaults.other(count=3) · vault.head.synced(time=07:42)');
    assert.equal(VS.headerText(t, { entries: 1, vaults: 1, status: { sync: { state: 'offline' }, pending: 2 } }, 'de', NOW), 'vault.head.entries.one(count=1) · vault.head.vaults.one(count=1) · vault.head.offline · vault.head.pending.other(count=2)');
    assert.match(VS.headerText(t, { entries: 0, vaults: 1, status: { sync: { state: 'idle' }, lastSyncAt: at(2026, 10, 22, 18, 3) } }, 'de', NOW), /vault\.time\.yesterday\(time=18:03\)/);
  });

  it('footer: auto-lock countdown', () => {
    const st = { unlocked: true, autoLockMinutes: 5 };
    assert.equal(VS.lockText(t, st, NOW - 48000, NOW), 'vault.foot.unlockedIn(time=4:12)');
    assert.equal(VS.lockText(t, st, NOW - 600000, NOW), 'vault.foot.unlockedIn(time=0:00)');
    assert.equal(VS.lockText(t, { unlocked: true, autoLockMinutes: 0 }, NOW, NOW), 'vault.foot.unlockedHidden');
    assert.equal(VS.lockText(t, { unlocked: false }, NOW, NOW), 'vault.foot.locked');
  });

  it('changed on device / relative days', () => {
    const s = sum({ updatedAt: new Date(at(2026, 10, 22, 18, 3)).toISOString(), device: 'Büro-PC' });
    assert.equal(VS.changedText(t, s, 'Persönlich', 'de', NOW), 'vault.changed(vault=Persönlich,when=vault.time.yesterday(time=18:03),device=Büro-PC)');
    assert.equal(VS.changedText(t, sum(), 'Persönlich', 'de', NOW), 'Persönlich');
    assert.equal(VS.when(at(2026, 10, 1, 8, 0), t, 'de', NOW), '01.10.2026');
    assert.equal(VS.when('nonsense', t, 'de', NOW), '');
  });

  it('errors: known codes and the rest', () => {
    assert.equal(VS.errorText({ ok: false, code: 'network' }, t), 'vault.err.offline');
    assert.equal(VS.errorText({ ok: false, code: 'wrong_password' }, t), 'vault.err.wrongPassword');
    assert.equal(VS.errorText({ ok: false, code: 'import_encrypted' }, t), 'vault.import.encrypted');
    assert.equal(VS.errorText({ ok: false, code: 'no_setup' }, t), 'vault.err.setupGone');
    assert.equal(VS.errorText({ ok: false, code: 'http_502' }, t), 'vault.err.generic(code=http_502)');
    assert.equal(VS.errorText(null, t), 'vault.err.generic(code=failed)');
  });

  it('emergency: waiting time and what is left', () => {
    assert.equal(VS.waitText(t, 48), 'vault.em.days.other(count=2)');
    assert.equal(VS.waitText(t, 24), 'vault.em.hours.other(count=24)');
    assert.equal(VS.waitText(t, 168), 'vault.em.days.other(count=7)');
    assert.equal(VS.waitText(t, 1), 'vault.em.hours.one(count=1)');
    assert.equal(VS.remainingText(t, new Date(NOW + (41 * 60 + 12) * 60000 + 5000).toISOString(), NOW), 'vault.em.remaining(hours=41,minutes=12)');
    assert.equal(VS.remainingText(t, new Date(NOW - 1000).toISOString(), NOW), 'vault.em.remaining(hours=0,minutes=0)');
    assert.equal(VS.emStatusKey('granted'), 'vault.em.status.granted');
    assert.equal(VS.emStatusKey('weird'), 'vault.em.status.ready');
  });

  it('import summary', () => {
    const res = { counts: { total: 186, logins: 172, withTotp: 21, notes: 9, cards: 0 }, duplicates: 4 };
    assert.deepEqual(VS.importChips(t, res.counts), ['vault.import.logins.other(count=172)', 'vault.import.totp.other(count=21)', 'vault.import.notes.other(count=9)']);
    assert.equal(VS.importCount(res), 182);
    assert.equal(VS.importCount(null), 0);
  });

  it('auto-lock choices', () => {
    assert.deepEqual(VS.autoLockChoices(t, [0, 1, 5, 15, 60]).map((c) => c.label), [
      'vault.settings.autoLockNow', 'vault.settings.autoLockAfter.one(count=1)', 'vault.settings.autoLockAfter.other(count=5)',
      'vault.settings.autoLockAfter.other(count=15)', 'vault.settings.autoLockAfter.other(count=60)',
    ]);
  });
});

describe('detail and edit draft', () => {
  it('rows per type, secrets marked, empty fields left out', () => {
    const rows = (type, fields) => VS.detailRows({ data: { type, fields } }).map((r) => `${r.key}${r.secret ? '*' : ''}${r.totp ? '#' : ''}`);
    assert.deepEqual(rows('login', { username: 'a', password: 'b', totp: 'JBSWY3DPEHPK3PXP' }), ['username', 'password*', 'totp*#']);
    assert.deepEqual(rows('login', { username: 'a' }), ['username']);
    assert.deepEqual(rows('card', { holder: 'M', number: '4111111111111111', expiry: '12/29', cvc: '123', pin: '0000' }), ['holder', 'number*', 'expiry', 'cvc*', 'pin*']);
    assert.deepEqual(rows('wifi', { ssid: 'Home', password: 'x', security: 'WPA2' }), ['ssid', 'password*', 'security']);
    assert.deepEqual(rows('identity', { name: 'M', email: 'm@x', phone: '1', address: 'A\nB', birthday: '1.1.' }), ['name', 'email', 'phone', 'address', 'birthday']);
    assert.deepEqual(rows('note', { password: 'stray' }), []);
    assert.deepEqual(rows('unknown', {}), []);
  });

  it('masks', () => {
    assert.equal(VS.maskedNumber('4111 1111 1111 1234'), '•••• 1234');
    assert.equal(VS.mask('abc'), '••••••••');
    assert.equal(VS.mask('x'.repeat(40)).length, 14);
    assert.equal(VS.prettyCode('482913'), '482 913');
    assert.equal(VS.prettyCode('12345678'), '1234 5678');
  });

  it('entry → draft → entry JSON v1 keeps unknown keys and drops empty values', () => {
    const entry = {
      id: 'e'.repeat(20), vaultId: 'v'.repeat(20),
      data: { v: 1, type: 'login', title: ' GitHub ', fav: true, notes: '', urls: ['https://github.com'], apps: [], fields: { username: 'marc', password: 'p w ', totp: ' otpauth://totp/x?secret=JBSWY3DPEHPK3PXP ' }, custom: [{ name: 'PIN', value: '1', secret: true }], tags: ['dev'], future: { x: 1 } },
    };
    const d = VS.draftFrom(entry);
    assert.equal(d.id, entry.id);
    assert.deepEqual(d.extra, { tags: ['dev'], future: { x: 1 } });
    d.custom.push({ name: '', value: '', secret: false });
    d.urls.push('  ');
    const out = VS.draftToData(d);
    assert.deepEqual(out, {
      tags: ['dev'], future: { x: 1 }, v: 1, type: 'login', title: 'GitHub', fav: true, urls: ['https://github.com'], apps: [],
      fields: { username: 'marc', password: 'p w ', totp: 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP' }, custom: [{ name: 'PIN', value: '1', secret: true }],
    });
    assert.equal(VS.draftChanged(d, VS.draftFrom(entry)), false, 'empty rows are no change');
    d.fields.password = 'new';
    assert.equal(VS.draftChanged(d, VS.draftFrom(entry)), true);
  });

  it('new drafts and what blocks a save', () => {
    const d = VS.emptyDraft('login', 'v'.repeat(20));
    assert.deepEqual(d.urls, ['']);
    assert.equal(VS.draftError(d), 'vault.edit.titleRequired');
    d.title = 'X';
    assert.equal(VS.draftError(d), null);
    assert.equal(VS.draftError({ ...d, vaultId: null }), 'vault.err.invalid');
    assert.equal(VS.emptyDraft('weird').type, 'login');
    assert.deepEqual(VS.emptyDraft('note').urls, []);
    assert.deepEqual(VS.draftToData(VS.emptyDraft('wifi', 'v')).fields, {});
  });

  it('web addresses that open', () => {
    assert.equal(VS.openableUrl('https://nas.gc.internal:5001'), 'https://nas.gc.internal:5001');
    assert.equal(VS.openableUrl('amazon.de/login'), 'https://amazon.de/login');
    assert.equal(VS.openableUrl('javascript:alert(1)'), null);
    assert.equal(VS.openableUrl('file:///C:/x'), null);
    assert.equal(VS.openableUrl('not a url'), null);
    assert.equal(VS.openableUrl(''), null);
  });
});

describe('master password, recovery key', () => {
  it('needs 12+ characters, not weak, both the same', () => {
    const good = { ok: true, good: true };
    assert.deepEqual(VS.masterCheck('', '', null), { ok: false, hint: null });
    assert.deepEqual(VS.masterCheck('short', '', { ok: true, good: false }), { ok: false, hint: 'vault.setup.pwRule' });
    assert.deepEqual(VS.masterCheck('aaaaaaaaaaaa', '', { ok: true, good: false }), { ok: false, hint: 'vault.setup.pwRule' });
    assert.deepEqual(VS.masterCheck('Sonne-Kanu-Turm-47', '', good), { ok: false, hint: null });
    assert.deepEqual(VS.masterCheck('Sonne-Kanu-Turm-47', 'Sonne-Kanu-Turm-48', good), { ok: false, hint: 'vault.setup.pwMismatch' });
    assert.deepEqual(VS.masterCheck('Sonne-Kanu-Turm-47', 'Sonne-Kanu-Turm-47', good), { ok: true, hint: 'vault.setup.pwMatch' });
  });

  it('strength view', () => {
    assert.deepEqual(VS.strengthView({ ok: true, strength: 'strong', words: 4 }, 'Sonne-Kanu-Turm-47', t), { level: 3, cls: 'is-strong', label: 'vault.strength.strong', detail: 'vault.strength.detail(chars=18,words=4)' });
    assert.equal(VS.strengthView(null, 'x', t).level, 0);
    assert.equal(VS.strengthView({ ok: true, strength: 'very_strong', words: 0 }, 'x', t).cls, 'is-very');
  });

  it('recovery key groups and length', () => {
    const k = 'K7QF-2MXP-9TRA-WD4B-H6NC-3ZLE-8VYU-P5SG-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF';
    assert.equal(VS.recoveryGroups(k).length, 14);
    assert.equal(VS.recoveryComplete(k), true);
    assert.equal(VS.recoveryComplete(k.toLowerCase().replace(/-/g, ' ')), true);
    assert.equal(VS.recoveryComplete(k.slice(0, -1)), false);
  });
});

describe('screens and push targets', () => {
  it('gate from status()', () => {
    assert.equal(VS.gate(null), 'loading');
    assert.equal(VS.gate({ state: 'unavailable' }), 'unavailable');
    assert.equal(VS.gate({ state: 'error' }), 'error');
    assert.equal(VS.gate({ state: 'available', account: 'unknown' }), 'loading');
    assert.equal(VS.gate({ state: 'available', account: 'none' }), 'intro');
    assert.equal(VS.gate({ state: 'available', account: 'none', setupPending: true }), 'setup');
    assert.equal(VS.gate({ state: 'available', account: 'ready', unlocked: false }), 'unlock');
    assert.equal(VS.gate({ state: 'available', account: 'ready', unlocked: true, recovering: true }), 'newpw');
    assert.equal(VS.gate({ state: 'available', account: 'ready', unlocked: true }), 'home');
  });

  it('push context → sub page', () => {
    const v = 'V'.repeat(20);
    assert.deepEqual(VS.pushTarget({ topic: 'emergency', event: 'requested', emergencyId: 'a'.repeat(24), page: 'emergency' }), { page: 'emergency', vaultId: null, emergencyId: 'a'.repeat(24) });
    assert.deepEqual(VS.pushTarget({ topic: 'share', event: 'shared', vaultId: v, page: 'home' }), { page: 'vault', vaultId: v, emergencyId: null });
    assert.deepEqual(VS.pushTarget({ topic: 'share', vaultId: 'bad' }), { page: 'home', vaultId: null, emergencyId: null });
    assert.deepEqual(VS.pushTarget(null), { page: 'home', vaultId: null, emergencyId: null });
  });

  it('inbox entries from Vault (like core pushContext)', () => {
    const v = 'V'.repeat(20);
    assert.deepEqual(VS.entryContext({ topic: 'plugin:gatecontrol-vault:share', data: { vault: { event: 'shared', vault: v } } }), { topic: 'share', event: 'shared', vaultId: v, emergencyId: null, page: 'home' });
    assert.equal(VS.entryContext({ topic: 'plugin:gatecontrol-vault:emergency', data: {} }).page, 'emergency');
    assert.equal(VS.entryContext({ topic: 'system' }), null);
    assert.equal(VS.entryContext(null), null);
  });

  it('people one can add: not yet a member, with Vault first', () => {
    const people = [{ id: 1, name: 'Klara', hasVault: false }, { id: 2, name: 'Oma Ruth', hasVault: true }, { id: 3, name: 'Jonas', hasVault: true }, { id: 4, name: 'Anna', hasVault: true }];
    assert.deepEqual(VS.candidates(people, [{ userId: 4 }]).map((p) => p.name), ['Jonas', 'Oma Ruth', 'Klara']);
    assert.equal(VS.roleHint('manage'), 'vault.roleHint.manage');
    assert.equal(VS.roleLabel('owner'), 'vault.role.read');
  });
});

describe('page wiring', () => {
  const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

  it('index.html loads state before view, the quick window has its own page', () => {
    const html = read('src', 'renderer', 'index.html');
    const a = html.indexOf('src="vault-state.js"');
    const b = html.indexOf('src="vault-view.js"');
    assert.ok(a > 0 && b > a && b < html.indexOf('src="renderer.js"'));
    assert.match(html, /href="styles\/vault\.css"/);
    assert.match(html, /id="nav-vault"[^>]*hidden/);
    const quick = read('src', 'renderer', 'vault-quick.html');
    assert.ok(quick.indexOf('src="vault-state.js"') < quick.indexOf('src="vault-quick.js"'));
    assert.match(quick, /script-src 'self'/);
  });

  it('views never use innerHTML / insertAdjacentHTML / eval', () => {
    for (const f of ['vault-view.js', 'vault-quick.js', 'vault-state.js']) {
      const src = read('src', 'renderer', f);
      assert.doesNotMatch(src, /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/, f);
    }
  });

  it('every vault.* key the views use exists in de and en', () => {
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const keys = new Set();
    const files = ['vault-view.js', 'vault-quick.js', 'vault-state.js'].map((f) => read('src', 'renderer', f)).join('\n') + read('src', 'renderer', 'renderer.js') + read('src', 'renderer', 'index.html');
    for (const m of files.matchAll(/['"`](vault\.[A-Za-z0-9_.]+)['"`]/g)) if (!m[1].endsWith('.')) keys.add(m[1]);
    // built at runtime
    for (const tp of VS.TYPES) { keys.add(`vault.type.${tp}`); keys.add(`vault.newType.${tp}`); }
    for (const f of Object.values(VS.FIELDS).flat()) keys.add(VS.fieldLabel(f.key));
    for (const r of VS.ROLES) { keys.add(VS.roleLabel(r)); keys.add(VS.roleHint(r)); }
    for (const s of ['ready', 'requested', 'granted']) keys.add(VS.emStatusKey(s));
    for (const s of ['weak', 'fair', 'strong', 'very_strong']) keys.add(`vault.strength.${s}`);
    for (const s of ['conflict', 'limit', 'refused']) keys.add(`vault.notice.${s}`);
    for (const s of ['favorites', 'all']) keys.add(`vault.section.${s}`);
    for (const p of ['vault.head.entries', 'vault.head.vaults', 'vault.head.pending', 'vault.unreadable', 'vault.em.hours', 'vault.em.days', 'vault.import.found',
      'vault.import.logins', 'vault.import.totp', 'vault.import.notes', 'vault.import.cards', 'vault.import.dupes', 'vault.import.button', 'vault.import.done',
      'vault.settings.autoLockAfter', 'vault.vaults.members']) { keys.add(`${p}.one`); keys.add(`${p}.other`); }
    for (const k of ['kbdEnter', 'kbdB', 'kbdT', 'kbdO', 'password', 'username', 'totp', 'url']) keys.add(`vault.quick.${k}`);
    // errorText table
    const state = read('src', 'renderer', 'vault-state.js');
    for (const m of state.matchAll(/'(vault\.(?:err|import)\.[A-Za-z]+)'/g)) keys.add(m[1]);
    const plurals = new Set(['vault.head.entries', 'vault.head.vaults', 'vault.head.pending', 'vault.unreadable', 'vault.em.hours', 'vault.em.days', 'vault.import.found', 'vault.import.logins', 'vault.import.totp', 'vault.import.notes', 'vault.import.cards', 'vault.import.dupes', 'vault.import.button', 'vault.import.done', 'vault.settings.autoLockAfter', 'vault.vaults.members']);
    assert.ok(keys.size > 200, `only ${keys.size} keys found`);
    for (const k of keys) {
      if (plurals.has(k)) continue;
      assert.ok(k in de, `de: ${k}`);
      assert.ok(k in en, `en: ${k}`);
    }
  });
});
