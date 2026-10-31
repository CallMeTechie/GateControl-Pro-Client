'use strict';

// Mail (plugin gatecontrol-mail, Phase 1): the pure helpers of the page (src/renderer/mail-state.js — times,
// initials, folders, titles, quick actions, AI chips, Drive suggestions, recipients, "Senden planen", providers,
// errors) and the wiring of the page (index.html, renderer, main: the gcmail: scheme, the sandboxed frames, texts).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const MS = require('../src/renderer/mail-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, params) => (params ? `${key}(${Object.entries(params).map(([k, v]) => `${k}=${v}`).join(',')})` : key);

describe('mail-state', () => {
  it('accounts as in the Outlook app: the provider\'s mark without a picture, the address below the name', () => {
    assert.deepEqual(MS.accountMark({ provider: 'outlook' }), { text: 'O', bg: '#0F6CBD', fg: '#FFFFFF' });
    assert.deepEqual(MS.accountMark({ provider: 'm365' }).tiles, ['#F25022', '#7FBA00', '#00A4EF', '#FFB900']);
    assert.equal(MS.accountMark({ provider: 'gmail' }).text, 'G');
    assert.equal(MS.accountMark({ provider: 'gmx' }).text, 'GMX');
    assert.equal(MS.accountMark({ provider: 'webde' }).text, 'W');
    assert.equal(MS.accountMark({ provider: 'tonline' }).text, 'T');
    assert.deepEqual(MS.accountMark({ provider: 'imap', color: '#B79CFF' }), { text: '@', bg: '#B79CFF', fg: '#0D1015' });
    assert.equal(MS.accountMark(null).text, '@');
    const m = MS.accountMark({ provider: 'gmail' });
    m.text = 'x';
    assert.equal(MS.accountMark({ provider: 'gmail' }).text, 'G', 'a copy');
    assert.equal(MS.accountSub({ name: 'Firma', email: 'max@firma.de' }), 'max@firma.de');
    assert.equal(MS.accountSub({ name: 'Max@Firma.de', email: 'max@firma.de' }), null, 'no name: the address once');
    assert.equal(MS.accountSub(null), null);
  });

  it('loading later (Mail 1.1.2): busy with retryAfter, the event of the open mail', () => {
    assert.deepEqual(MS.busyRetry({ ok: false, code: 'busy', detail: { reason: 'loading', retryAfter: 5 } }), { loading: true, waitMs: 5000 });
    assert.deepEqual(MS.busyRetry({ ok: false, code: 'busy' }), { loading: false, waitMs: 5000 });
    assert.deepEqual(MS.busyRetry({ ok: false, code: 'busy', detail: { retryAfter: 900 } }), { loading: false, waitMs: 60000 });
    assert.equal(MS.busyRetry({ ok: false, code: 'not_found' }), null);
    assert.equal(MS.busyRetry({ ok: true }), null);
    assert.equal(MS.busyRetry(null), null);
    assert.ok(MS.BUSY_RETRIES >= 1 && MS.BUSY_RETRIES <= 5);
    const m = { id: 42, threadId: 9 };
    assert.equal(MS.bringsBody({ messageId: 42 }, m), true);
    assert.equal(MS.bringsBody({ messageId: null, threadId: 9 }, m), true);
    assert.equal(MS.bringsBody({ accountId: 1, folderId: 10, messageId: null, threadId: null }, m), false);
    assert.equal(MS.bringsBody({ messageId: 43 }, { id: 42, threadId: null }), false);
    assert.equal(MS.bringsBody(null, m), false);
  });

  it('times of the list: today, yesterday, this week, this year, older', () => {
    const now = new Date(2026, 10, 4, 10, 0).getTime();   // Wed 4.11.2026
    assert.equal(MS.timeLabel(new Date(2026, 10, 4, 9, 42).getTime(), now, 'de', t), '09:42');
    assert.equal(MS.timeLabel(new Date(2026, 10, 3, 23, 0).getTime(), now, 'de', t), 'mail.time.yesterday');
    assert.match(MS.timeLabel(new Date(2026, 10, 1, 12, 0).getTime(), now, 'de', t), /^So/);
    assert.equal(MS.timeLabel(new Date(2026, 2, 7).getTime(), now, 'de', t), '07.03.');
    assert.equal(MS.timeLabel(new Date(2026, 2, 7).getTime(), now, 'en', t), '07/03');
    assert.equal(MS.timeLabel(new Date(2025, 2, 7).getTime(), now, 'de', t), '07.03.25');
    assert.equal(MS.timeLabel(null, now, 'de', t), '');
  });

  it('names, initials, sizes and attachment tags', () => {
    assert.equal(MS.initials({ name: 'Sabine Keller' }), 'SK');
    assert.equal(MS.initials({ name: 'Stadtwerke' }), 'S');
    assert.equal(MS.initials({ name: '"Öko" Strom GmbH' }), 'ÖS');
    assert.equal(MS.initials({ email: 'max@gmx.de' }), 'M');
    assert.equal(MS.senderName({ name: null, email: 'a@b.de' }, t), 'a@b.de');
    assert.equal(MS.senderName(null, t), 'mail.unknownSender');
    assert.equal(MS.bytes(212000, 'de'), '207 KB');
    assert.equal(MS.bytes(46e6, 'de'), '43,9 MB');
    assert.deepEqual(MS.fileTag('Rechnung.PDF'), { tag: 'PDF', tone: 'err' });
    assert.deepEqual(MS.fileTag('Preisliste 2027.xlsx'), { tag: 'XLS', tone: 'acc' });
    assert.deepEqual(MS.fileTag('scan', 'image/jpeg'), { tag: 'IMG', tone: 'pro' });
    assert.deepEqual(MS.fileTag('datei.weird-ext'), { tag: 'FILE', tone: 'muted' });
  });

  it('folders as a tree: roles first, children below their parent, the inbox shows Relevant / Sonstige', () => {
    const folders = { accounts: [{ accountId: 1, folders: [
      { id: 15, name: 'Rechnungen', role: null, parentId: 14 },
      { id: 13, name: 'Papierkorb', role: 'trash', parentId: null },
      { id: 16, name: 'Alt', role: null, parentId: null },
      { id: 14, name: 'Archiv', role: 'archive', parentId: null },
      { id: 11, name: 'INBOX', role: 'inbox', parentId: null },
      { id: 12, name: 'Sent', role: 'sent', parentId: null },
      { id: 17, name: 'Schleife', role: null, parentId: 17 },
    ] }] };
    assert.deepEqual(MS.folderTree(folders.accounts[0].folders).map((x) => [x.folder.id, x.depth]), [[11, 0], [12, 0], [14, 0], [15, 1], [13, 0], [16, 0], [17, 0]]);
    assert.equal(MS.folderName({ role: 'sent', name: 'Sent Items' }, t), 'mail.role.sent');
    assert.equal(MS.roleFolder(folders, 1, 'trash').id, 13);
    assert.equal(MS.isInbox({ kind: 'box', box: 'all' }, folders), true);
    assert.equal(MS.isInbox({ kind: 'box', box: 1, folderId: 11 }, folders), true);
    assert.equal(MS.isInbox({ kind: 'box', box: 1, folderId: 12 }, folders), false);
    assert.deepEqual(MS.listQuery({ kind: 'box', box: 1, folderId: 12 }, folders, 'other', { unread: true }), { box: 1, limit: 50, folder: 12, unread: true });
    assert.deepEqual(MS.listQuery({ kind: 'box', box: 'all' }, folders, 'other', {}), { box: 'all', limit: 50, tab: 'other' });
  });

  it('title and subtitle of what is shown', () => {
    const me = { accounts: [{ id: 1, name: 'Privat · GMX' }, { id: 2, name: 'Firma' }, { id: 3, name: 'Gmail' }], unread: { all: 4, byAccount: { 1: 2 } } };
    assert.deepEqual(MS.viewTitle({ kind: 'box', box: 'all' }, me, null, t), { title: 'mail.allInboxes', sub: 'mail.accounts.other(count=3) · mail.unreadCount(count=4)' });
    assert.deepEqual(MS.viewTitle({ kind: 'box', box: 1 }, me, null, t), { title: 'mail.role.inbox', sub: 'Privat · GMX · mail.unreadCount(count=2)' });
    assert.equal(MS.viewTitle({ kind: 'filing' }, me, null, t).title, 'mail.filing.title');
    assert.deepEqual(MS.mergeItems([{ id: 1 }, { id: 2 }], [{ id: 2 }, { id: 3 }]).map((m) => m.id), [1, 2, 3]);
  });

  it('quick actions of a row follow the swipe settings', () => {
    assert.deepEqual(MS.rowActions({ swipeLeft: 'archive', swipeRight: 'read' }, { unread: true }).map((a) => [a.action, a.key]), [['read', 'mail.act.markRead'], ['archive', 'mail.act.archive']]);
    assert.deepEqual(MS.rowActions({ swipeLeft: 'none', swipeRight: 'delete' }, {}).map((a) => a.action), ['delete']);
    assert.deepEqual(MS.rowActions({ swipeLeft: 'delete', swipeRight: 'delete' }, {}).map((a) => a.action), ['delete']);
    assert.deepEqual(MS.actionCall('read', { unread: true }), { flags: { unread: false } });
    assert.deepEqual(MS.actionCall('flag', { flagged: true }), { flags: { flagged: false } });
    assert.deepEqual(MS.actionCall('archive', {}), { act: 'archive' });
    assert.equal(MS.actionCall('explode', {}), null);
  });

  it('AI chips: deadlines and events into the family calendar only when it is there', () => {
    const ai = { status: 'done', todos: [{ kind: 'deadline', text: 'Abbuchung 28.11.', date: '2026-11-28' }, { kind: 'event', text: 'Treffen' }, { kind: 'question', text: 'Passt Dienstag?' }] };
    assert.deepEqual(MS.todoChips(ai, ['mail', 'familyCalendar']).map((c) => c.calendar), [true, false, false]);
    assert.deepEqual(MS.todoChips(ai, ['mail']).map((c) => c.calendar), [false, false, false]);
    assert.deepEqual(MS.todoChips({ status: 'none' }, []), []);
    assert.equal(MS.suggestionLine({ path: 'Finanzen › Strom', confidence: 0.95, reason: 'learned' }, t), 'mail.drive.inWhere(where=Finanzen › Strom) · mail.drive.reason.learned');
    assert.equal(MS.suggestionLine({ path: 'Team › Projekte', confidence: 0.64, reason: 'ai' }, t), 'mail.drive.inWhere(where=Team › Projekte) · mail.drive.sure(pct=64)');
  });

  it('recipients as typed, signature, reply all', () => {
    assert.deepEqual(MS.parseRecipients('Tim Brandt <tim@firma.de>; "Keller, Sabine" <sabine@firma.de>, tim@firma.de, kaputt@'), {
      list: [{ name: 'Tim Brandt', email: 'tim@firma.de' }, { name: 'Keller, Sabine', email: 'sabine@firma.de' }], bad: ['kaputt@'],
    });
    assert.equal(MS.recipientLabel({ name: null, email: 'a@b.de' }), 'a@b.de');
    assert.equal(MS.signatureHtml('Max <Muster>\nTel. 123'), '<p><br></p><p class="gc-sig">-- <br>Max &lt;Muster&gt;<br>Tel. 123</p>');
    assert.equal(MS.signatureHtml('  '), '');
    assert.equal(MS.textToHtml('Danke!\n\nGruß\nMax'), '<p>Danke!</p><p>Gruß<br>Max</p>');
    const me = { accounts: [{ email: 'max@gmx.de' }] };
    assert.equal(MS.canReplyAll({ from: { email: 'a@b.de' }, to: [{ email: 'max@gmx.de' }], cc: [] }, me), false);
    assert.equal(MS.canReplyAll({ from: { email: 'a@b.de' }, to: [{ email: 'max@gmx.de' }, { email: 'c@d.de' }], cc: [] }, me), true);
    assert.equal(MS.attachmentBytes([{ size: 10 }, { size: 5, as: 'link' }, { size: 3, as: 'copy' }]), 13);
  });

  it('"Senden planen" and the undo countdown', () => {
    const morning = new Date(2026, 10, 4, 10, 0).getTime();   // Wednesday
    const p = MS.sendPresets(morning);
    assert.deepEqual(p.map((x) => x.key), ['mail.schedule.tonight', 'mail.schedule.tomorrow', 'mail.schedule.monday']);
    assert.equal(new Date(p[0].at).getHours(), 18);
    assert.equal(new Date(p[2].at).getDay(), 1);
    const sunday = new Date(2026, 10, 8, 19, 0).getTime();
    assert.deepEqual(MS.sendPresets(sunday).map((x) => x.key), ['mail.schedule.tomorrow'], 'tomorrow already is Monday');
    assert.equal(MS.localInputMs(MS.localInputValue(morning + 3600e3), morning), morning + 3600e3);
    assert.equal(MS.localInputMs(MS.localInputValue(morning - 3600e3), morning), null);
    assert.equal(MS.localInputMs('morgen', morning), null);
    assert.equal(MS.undoLeft(morning + 9100, morning), 10);
    assert.equal(MS.undoLeft(morning - 1, morning), 0);
  });

  it('providers: Microsoft first, greyed without a client id; storage; errors with the server\'s hint', () => {
    const providers = [
      { id: 'gmx', label: 'GMX', auth: 'password', hint: { de: 'IMAP erlauben', en: 'Allow IMAP' }, help: null },
      { id: 'm365', label: 'Microsoft 365', auth: 'microsoft', hint: null, help: null },
    ];
    const rows = MS.providerRows(providers, ['mail'], 'en');
    assert.deepEqual(rows.map((r) => [r.id, r.disabled]), [['m365', true], ['gmx', false]]);
    assert.equal(rows[1].hint, 'Allow IMAP');
    assert.equal(MS.providerRows(providers, ['mail', 'microsoft'], 'de')[0].disabled, false);
    assert.equal(MS.freeColor({ accounts: [{ color: '#F5B544' }] }), '#79B8FF');
    assert.deepEqual(MS.quotaView({ quotaBytes: 1000, usedBytes: 950 }, 'de', t), { used: 950, total: 1000, pct: 95, text: 'mail.settings.storage(used=950 B,total=1000 B)' });
    assert.equal(MS.quotaView({}, 'de', t), null);
    assert.equal(MS.errorText({ code: 'auth_failed', detail: { hint: { de: 'App-Passwort nötig.', en: 'App password needed.' } } }, t, 'de'), 'mail.err.auth_failed App-Passwort nötig.');
    assert.equal(MS.errorText({ code: 'network' }, t, 'de'), 'mail.err.offline');
    assert.equal(MS.errorText({ code: 'http_503' }, t, 'de'), 'mail.err.offline');
    assert.equal(MS.errorText({ code: 'weird' }, t, 'de'), 'mail.err.failed');
    for (const c of ['microsoft_off', 'attachments_unsupported', 'images_blocked', 'images_off', 'drive_unavailable', 'no_folder', 'not_waiting', 'not_allowed']) assert.equal(MS.errorText({ code: c }, t, 'de'), `mail.err.${c}`);
  });
});

describe('mail page wiring', () => {
  it('index.html: state before view, nav entry hidden, styles, CSP lets gcmail: pictures in', () => {
    const html = read('src', 'renderer', 'index.html');
    const a = html.indexOf('src="mail-state.js"');
    const b = html.indexOf('src="mail-view.js"');
    assert.ok(a > html.indexOf('src="drive-view.js"') && b > a && b < html.indexOf('src="renderer.js"'));
    assert.match(html, /href="styles\/mail\.css"/);
    assert.match(html, /id="nav-mail"[^>]*hidden/);
    assert.match(html, /id="page-mail"/);
    assert.match(html, /img-src 'self' data: blob: gcmail:;/);
    assert.doesNotMatch(html, /script-src[^;]*(unsafe-inline|gcmail)/);
  });

  it('the frames are sandboxed without scripts; the views never write HTML into the page', () => {
    const view = read('src', 'renderer', 'mail-view.js');
    const sandboxes = [...view.matchAll(/sandbox: editable \? '([^']*)' : '([^']*)'/g)];
    assert.equal(sandboxes.length, 1);
    for (const s of sandboxes[0].slice(1)) assert.doesNotMatch(s, /allow-scripts|allow-top-navigation|allow-forms|allow-modals/);
    for (const f of ['mail-view.js', 'mail-state.js']) {
      const src = read('src', 'renderer', f);
      assert.doesNotMatch(src, /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/, f);
    }
  });

  it('main registers the gcmail: scheme before the app is ready and serves it through MailService', () => {
    const main = read('src', 'main', 'main.js');
    const reg = main.indexOf('protocol.registerSchemesAsPrivileged([{ scheme: MailService.SCHEME');
    assert.ok(reg > 0 && reg < main.indexOf("app.on('ready'"));
    assert.match(main, /protocol\.handle\(MailService\.SCHEME, \(req\) => mail\.handleProtocol\(req\)\)/);
    assert.match(main, /\n    mail,\n/, 'mail goes to registerBaseHandlers');
  });

  it('a wide mail fits: the zoom of #gc-fit from its width and what it holds', () => {
    assert.equal(MS.fitZoom(600, 600), 1, 'fits');
    assert.equal(MS.fitZoom(600, 601), 1, '1 px of rounding');
    assert.equal(MS.fitZoom(400, 600), 0.666);
    assert.equal(MS.fitZoom(100, 5000), MS.FIT_MIN, 'never below the minimum');
    assert.equal(MS.fitZoom(0, 600), 1);
    assert.equal(MS.fitZoom(undefined, 600), 1);
  });

  it('mails in the dark: only while the app is dark, the setting is on and the mail is not shown light', () => {
    assert.equal(MS.showDark(true, true, false), true);
    assert.equal(MS.showDark(true, true, true), false, '"Hell anzeigen"');
    assert.equal(MS.showDark(true, false, false), false, '"Mails dunkel darstellen" off');
    assert.equal(MS.showDark(false, true, false), false, 'the app is light');
    // the setting is on unless switched off
    assert.equal(MS.darkSetting(null), true);
    assert.equal(MS.darkSetting('1'), true);
    assert.equal(MS.darkSetting('0'), false);
    assert.equal(MS.DARK_KEY, 'gc.mail.darkMails');
    // the core's documents: docDark only when dark and there, else the original
    assert.equal(MS.frameDoc({ doc: 'L', docDark: 'D' }, true), 'D');
    assert.equal(MS.frameDoc({ doc: 'L', docDark: 'D' }, false), 'L');
    assert.equal(MS.frameDoc({ doc: 'L' }, true), 'L', 'an older core without docDark');
    assert.equal(MS.frameDoc(null, true), '');
    // the page: the frame shows docDark while dark, the sun in the bar, the setting under "Darstellung"
    const view = read('src', 'renderer', 'mail-view.js');
    assert.match(view, /mailFrame\(MS\.frameDoc\(R, R\.frameDark\)/);
    assert.match(view, /mail\.read\.showLight/);
    assert.match(view, /mail\.settings\.darkMails/);
    assert.ok(!/allow-scripts/.test(view), 'the frames never run a script');
  });

  it('the menu: an account\'s folders open or close with a tap, each account for itself, for the session', () => {
    const folds = new Map();
    const view = { kind: 'box', box: 1, folderId: null };
    assert.equal(MS.foldOpen(folds, 1, view), true, 'the account shown starts open');
    assert.equal(MS.foldOpen(folds, 2, view), false);
    MS.toggleFold(folds, 1, view);
    assert.equal(MS.foldOpen(folds, 1, view), false, 'the open one closes again');
    MS.toggleFold(folds, 2, view);
    assert.equal(MS.foldOpen(folds, 2, view), true);
    assert.equal(MS.foldOpen(folds, 1, { kind: 'box', box: 1, folderId: 12 }), false, 'kept when another box is shown');
    assert.equal(MS.foldOpen(new Map(), 1, { kind: 'search', q: 'x' }), false);
  });

  it('a conversation around the open mail: older above, newer below, oldest first; its senders once', () => {
    const m = (id, date, email = 'a@b.de', name = 'Anna') => ({ id, date, from: { name, email } });
    const items = [m(3, 300), m(1, 100), m(2, 200, 'tim@b.de', 'Tim'), m(4, 400), m(4, 400)];
    const c = MS.conversation(items, 2);
    assert.deepEqual(c.older.map((x) => x.id), [1]);
    assert.deepEqual(c.newer.map((x) => x.id), [3, 4]);
    assert.deepEqual(MS.conversation(items, 99).older.map((x) => x.id), [1, 2, 3, 4]);
    assert.deepEqual(MS.conversation(null, 1), { older: [], newer: [] });
    assert.deepEqual(MS.participants(items, t), ['Anna', 'Tim']);
    assert.deepEqual(MS.participants([m(1, 1, 'x@y.de', '')], t), ['x@y.de']);
  });

  it('a sender: exactly that address, the name from a person in the contacts', () => {
    const items = [{ id: 1, from: { email: 'anna@b.de' } }, { id: 2, from: { email: 'hanna@b.de' } }, { id: 3, from: { email: 'ANNA@b.de' } }];
    assert.deepEqual(MS.fromSender(items, ' anna@b.de').map((x) => x.id), [1, 3]);
    const contacts = [{ name: 'Recent', email: 'anna@b.de', source: 'recent' }, { name: 'Anna Müller', email: 'Anna@b.de', source: 'person' }];
    assert.equal(MS.contactOf(contacts, 'anna@b.de').name, 'Anna Müller');
    assert.equal(MS.contactOf(contacts.slice(0, 1), 'anna@b.de'), null);
    assert.equal(MS.contactOf([{ name: '', email: 'anna@b.de', source: 'person' }], 'anna@b.de'), null);
  });

  it('every mail.* key the views use exists in de and en', () => {
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const src = ['mail-view.js', 'mail-state.js', 'renderer.js', 'index.html'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set();
    for (const m of src.matchAll(/['"](mail\.[A-Za-z0-9_.]+)['"]/g)) if (!m[1].endsWith('.')) keys.add(m[1]);
    // built at runtime
    for (const r of ['inbox', 'sent', 'drafts', 'archive', 'junk', 'trash']) keys.add(`mail.role.${r}`);
    for (const s of ['ok', 'syncing', 'auth_failed', 'unreachable']) keys.add(`mail.state.${s}`);
    for (const s of ['archive', 'delete', 'read', 'none']) keys.add(`mail.swipe.${s}`);
    for (const a of ['password', 'app_password', 'microsoft', 'imap']) keys.add(`mail.add.auth.${a}`);
    for (const a of ['tls', 'starttls']) keys.add(`mail.add.sec.${a}`);
    for (const f of ['unread', 'flagged', 'attachments']) keys.add(`mail.filter.${f}`);
    for (const w of ['password', 'too_large', 'no_subject']) keys.add(`mail.warn.${w}`);
    for (const a of ['archive', 'delete', 'junk']) keys.add(`mail.done.${a}`);
    for (const m of ['reply', 'replyAll', 'forward']) keys.add(`mail.compose.${m}`);
    for (const a of ['off', 'suggest', 'auto']) keys.add(`mail.settings.attachments.${a}`);
    for (const r of ['rule', 'learned']) keys.add(`mail.drive.reason.${r}`);
    for (const p of ['one', 'other']) keys.add(`mail.accounts.${p}`);
    const errs = new Set();
    for (const m of read('src', 'renderer', 'mail-state.js').matchAll(/:\s*'([a-z_]+)'/g)) errs.add(m[1]);
    for (const e of errs) if (`mail.err.${e}` in de || e === 'failed') keys.add(`mail.err.${e}`);
    keys.add('mail.err.failed');
    keys.delete('mail.accounts');
    assert.ok(keys.size > 250, `only ${keys.size} keys found`);
    for (const k of keys) {
      assert.ok(k in de, `de: ${k}`);
      assert.ok(k in en, `en: ${k}`);
    }
  });
});
