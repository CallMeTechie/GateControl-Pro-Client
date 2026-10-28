'use strict';

// Drive 1.8 / 1.9 on the page "Drive" (no DOM): the row menu (drive-state.js: "Details" only with 'docAi', "Im
// Browser bearbeiten / ansehen" only with 'office' and for docx/xlsx/pptx/odt/ods/odp/csv, never for a vault's
// file; a vault's nodes without links, moves, time travel; without the key no name), the kind of document in the
// list, "Erkannt" / suggestion / deadlines / reminders (drive-docs-state.js), the vault card, devices, the recovery
// key (drive-vault-state.js), the push target of a deadline (notify-state.js); that the page loads the new scripts,
// never uses innerHTML there, and that every key they use exists in de and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const DS = require('../src/renderer/drive-state');
const DD = require('../src/renderer/drive-docs-state');
const VS = require('../src/renderer/drive-vault-state');
const NS = require('../src/renderer/notify-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const at = (y, mo, d, h = 0, m = 0) => new Date(y, mo - 1, d, h, m).getTime();
const NOW = at(2026, 10, 28, 9, 30);

describe('the row menu and the list (drive-state.js)', () => {
  const me = { features: ['docAi', 'office', 'vault', 'timeTravel', 'links'], links: { node: 'https://x/{id}' } };
  it('details with docAi, office for office documents (edit / view), nothing of it for a vault', () => {
    const pdf = { id: 1, name: 'Brief.pdf', isDir: false };
    const xl = { id: 2, name: 'Plan.XLSX', isDir: false };
    assert.equal(DS.actionsFor(pdf, true, me).details, true);
    assert.equal(DS.actionsFor(pdf, true, { features: [] }).details, false);
    assert.equal(DS.actionsFor(pdf, true, me).office, null);
    assert.equal(DS.actionsFor(xl, true, me).office, 'edit');
    assert.equal(DS.actionsFor(xl, false, me).office, 'view');
    assert.equal(DS.actionsFor(xl, true, { features: ['docAi'] }).office, null);
    for (const ext of ['docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp', 'csv']) assert.equal(DS.officeMode({ name: `a.${ext}` }, true, me), 'edit', ext);
    assert.equal(DS.officeMode({ name: 'a.doc' }, true, me), null);
    const enc = { ...xl, encrypted: true, vaultId: 'v', locked: false };
    const a = DS.actionsFor(enc, true, me);
    assert.deepEqual([a.office, a.details, a.share, a.move, a.open, a.rename, a.remove], [null, false, false, false, true, true, true]);
    const lockedDir = { id: 3, isDir: true, encrypted: true, locked: true, vaultRoot: true, name: 'f'.repeat(32) };
    const l = DS.actionsFor(lockedDir, true, me);
    assert.deepEqual([l.open, l.rename, l.timeTravel, l.share, l.remove], [false, false, false, false, true]);
  });

  it('rows: the kind of document while ready, vault folders and locked names', () => {
    const base = { id: 5, name: 'Rechnung.pdf', isDir: false, size: 10, mtime: NOW };
    assert.equal(DS.rowView({ ...base, insight: { status: 'ready', kind: 'invoice' } }, { t, locale: 'de', now: NOW }).doc, 'invoice');
    assert.equal(DS.rowView({ ...base, insight: { status: 'pending', kind: null } }, { t, locale: 'de', now: NOW }).doc, null);
    assert.equal(DS.rowView({ ...base, encrypted: true, insight: { status: 'ready', kind: 'invoice' } }, { t, locale: 'de', now: NOW }).doc, null);
    const v = DS.rowView({ id: 6, isDir: true, name: 'f'.repeat(32), encrypted: true, locked: true, vaultRoot: true }, { t, locale: 'de', now: NOW });
    assert.deepEqual([v.name, v.kind, v.vault, v.locked], ['drive.vault.lockedVault', 'vault', true, true]);
    assert.equal(DS.rowView({ id: 7, name: 'a'.repeat(32), encrypted: true, locked: true }, { t, locale: 'de', now: NOW }).name, 'drive.vault.lockedFile');
    assert.equal(DS.rowView({ id: 8, name: 'Steuer', isDir: true, encrypted: true, locked: false, vaultRoot: true }, { t, locale: 'de', now: NOW }).name, 'Steuer');
    assert.equal(DS.rowView({ ...base, preview: true, mediaId: 'm', encrypted: true }, { t, locale: 'de', now: NOW }).preview, false);
    assert.deepEqual(DS.crumbs({ crumbs: [{ id: 1, name: 'x' }, { id: 2, name: 'f'.repeat(32), locked: true }] }, null, t).map((c) => c.name), ['x', 'drive.vault.lockedFolder']);
  });

  it('the folder picker never offers vault folders; the error texts', () => {
    const f = { writable: true, node: { id: 1 }, items: [{ id: 2, isDir: true, name: 'A' }, { id: 3, isDir: true, name: 'B', encrypted: true }] };
    assert.deepEqual(DS.pickerFolders(f).map((n) => n.id), [2]);
    assert.equal(DS.canPick({ writable: true, node: { id: 3, encrypted: true } }), false);
    for (const [code, key] of [['encrypted', 'encrypted'], ['office_unavailable', 'officeUnavailable'], ['vault_locked', 'vaultLocked'], ['recovery_key', 'recoveryKey'], ['safety', 'safety'], ['feature_off', 'featureOff']]) {
      assert.equal(DS.errorText({ code }, t), `drive.err.${key}`);
    }
  });
});

describe('AI for documents and deadlines (drive-docs-state.js)', () => {
  const ins = {
    status: 'ready', kind: 'invoice', title: 'Stadtwerke Rechnung', date: '2026-03-14', sender: 'Stadtwerke', amount: 89.5, currency: 'EUR',
    suggestion: { folderId: 10, folderPath: 'Rechnungen/2026', name: '2026-03-14 Stadtwerke.pdf' }, deadlines: [],
  };
  it('"Erkannt": kind, title, date, sender, amount; the states', () => {
    const v = DD.insightView(ins, { t, locale: 'de' });
    assert.deepEqual(v.fields.map((f) => [f.key, f.value]), [['kind', 'drive.doc.kind.invoice'], ['title', 'Stadtwerke Rechnung'], ['date', '14.03.2026'], ['sender', 'Stadtwerke'], ['amount', '89,50 €']]);
    assert.equal(v.statusText, '');
    assert.equal(DD.insightView({ status: 'pending' }, { t, locale: 'de' }).statusText, 'drive.doc.pending');
    assert.equal(DD.insightView({ status: 'failed', error: 'no_text' }, { t, locale: 'de' }).statusText, 'drive.doc.failed(reason=drive.doc.reason.no_text)');
    assert.equal(DD.insightView({ status: 'off' }, { t }).fields.length, 0);
    assert.equal(DD.amountText(12, null, 'en'), '12.00');
    assert.equal(DD.amountText(5, 'XYZ1', 'de'), '5,00 XYZ1');
  });

  it('the suggestion: a name, a folder below the area', () => {
    assert.deepEqual(DD.suggestionView(ins, 'Meine Dateien', t), { name: '2026-03-14 Stadtwerke.pdf', folder: true, folderText: 'Meine Dateien › Rechnungen › 2026' });
    assert.deepEqual(DD.suggestionView({ status: 'ready', suggestion: { folderId: 1, folderPath: '', name: null } }, 'Familie', t), { name: null, folder: true, folderText: 'Familie' });
    assert.equal(DD.suggestionView({ status: 'pending', suggestion: ins.suggestion }, 'x', t), null);
    assert.equal(DD.suggestionView({ status: 'ready', suggestion: null }, 'x', t), null);
  });

  it('deadlines, "Erinnern N Tage vorher", the overview', () => {
    const d = { id: 3, kind: 'payment', date: '2026-10-31', label: 'Zahlung', reminder: { at: 1, daysBefore: 3, sent: false } };
    const v = DD.deadlineView(d, { t, locale: 'de', now: NOW });
    assert.deepEqual([v.title, v.date, v.when, v.urgent, v.past, v.value, v.reminder], ['drive.deadline.kind.payment', '31.10.2026', 'drive.deadline.inDays(count=3)', true, false, '3', 'drive.deadline.remind.other(count=3)']);
    assert.equal(DD.deadlineView({ ...d, date: '2026-10-27', reminder: null }, { t, locale: 'de', now: NOW }).when, 'drive.deadline.ago.one(count=1)');
    assert.equal(DD.deadlineView({ ...d, date: '2026-10-28' }, { t, now: NOW }).when, 'drive.deadline.today');
    assert.deepEqual(DD.reminderOptions(t).map((o) => o.value), ['', '0', '1', '3', '7', '14', '30']);
    assert.equal(DD.reminderDays(''), null);
    assert.equal(DD.reminderDays('7'), 7);
    assert.equal(DD.reminderDays('91'), null);
    const groups = DD.deadlineGroups([
      { ...d, node: { id: 12, name: 'Brief.pdf', parentId: 10 } },
      { ...d, id: 4, date: '2027-05-01', node: { id: 13, name: 'Vertrag.pdf', parentId: 10 } },
      { ...d, id: 5, date: '2026-10-01', node: { id: 14, name: 'Alt.pdf', parentId: 10 } },
      { ...d, id: 6, node: null },
    ], { t, locale: 'de', now: NOW });
    assert.deepEqual(groups.map((g) => [g.key, g.items.map((i) => i.file)]), [['soon', ['Brief.pdf']], ['later', ['Vertrag.pdf']], ['past', ['Alt.pdf']]]);
    assert.equal(DD.recognizeError({ code: 'unsupported', reason: 'media_disabled' }, t), 'drive.doc.reason.media_disabled');
    assert.equal(DD.recognizeError({ code: 'forbidden' }, t), null);
  });
});

describe('vault folders (drive-vault-state.js)', () => {
  it('only with the feature and DPAPI; the card by state', () => {
    assert.equal(VS.vaultAvailable({ features: ['vault'] }, { ok: true, supported: true }), true);
    assert.equal(VS.vaultAvailable({ features: ['vault'] }, { ok: true, supported: false }), false);
    assert.equal(VS.vaultAvailable({ features: [] }, { ok: true, supported: true }), false);
    assert.deepEqual(VS.gateView('none', { t }), { key: 'none', text: 'drive.vault.gate.none', ask: true, recover: true, safetyNumber: null });
    assert.deepEqual(VS.gateView('pending', { t, safetyNumber: '44626 75008 87340 28578' }).safetyNumber, '44626 75008 87340 28578');
    assert.equal(VS.gateView('pending', { t }).ask, false);
    assert.equal(VS.gateView('revoked', { t }).text, 'drive.vault.gate.revoked');
    assert.equal(VS.gateView('unsupported', { t }).recover, false);
  });

  it('devices, the recovery key, the safety number, the note', () => {
    const rows = VS.deviceRows([
      { deviceId: 'a', state: 'pending', name: 'Pixel', platform: 'android', safetyNumber: '1 2 3 4' },
      { deviceId: 'b', state: 'approved', name: null, platform: 'windows', mine: true, via: 'recovery' },
      { deviceId: 'c', state: 'revoked', name: 'Alt' },
    ], { t });
    assert.deepEqual(rows.pending.map((r) => [r.name, r.platform, r.safetyNumber]), [['Pixel', 'Android', '1 2 3 4']]);
    assert.deepEqual(rows.approved.map((r) => [r.name, r.mine, r.via]), [['drive.vault.device.unnamed', true, 'drive.vault.device.viaRecovery']]);
    const key = 'R30W-5GY4-RQ3C-FJ69-SB5W-SKEE-SZ8D-3MPK-TKAX-DNYR-V7DD-QQ6X-VVFJ-63ZJ';
    assert.equal(VS.recoveryKeyShape(key), true);
    assert.equal(VS.recoveryKeyShape(key.toLowerCase().replace(/-/g, ' ').replace(/0/g, 'o')), true);
    assert.equal(VS.recoveryKeyShape(key.slice(0, -1)), false);
    assert.deepEqual(VS.recoveryKeyLines(key), ['R30W-5GY4-RQ3C-FJ69', 'SB5W-SKEE-SZ8D-3MPK', 'TKAX-DNYR-V7DD-QQ6X', 'VVFJ-63ZJ']);
    assert.equal(VS.safetyMatches('44626 75008 87340 28578', '44626-75008-87340-28578'), true);
    assert.equal(VS.safetyMatches('44626 75008 87340 2857', '44626 75008 87340 28578'), false);
    assert.equal(VS.folderNote({ pending: 2, needsRotation: true }, { t }), 'drive.vault.note · drive.vault.pending.other(count=2) · drive.vault.needsRotation');
  });
});

describe('push targets and the page', () => {
  it('a Drive push opens the Drive page with its context', () => {
    const ctx = { kind: 'deadline', nodeId: 12, deadlineId: 3 };
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-drive', id: 9, context: ctx }, ['drive', 'inbox']), { page: 'drive', id: null, context: ctx });
    assert.deepEqual(NS.navigateTarget({ route: 'plg-gatecontrol-drive', id: 9, context: ctx }, ['inbox']), { page: 'inbox', id: 9 });
  });

  it('the page loads the new scripts before drive-view.js; no innerHTML; every key in de and en', () => {
    const html = read('src', 'renderer', 'index.html');
    const pos = (f) => html.indexOf(`<script src="${f}"></script>`);
    for (const f of ['drive-docs-state.js', 'drive-docs-view.js', 'drive-vault-state.js', 'drive-vault-view.js']) {
      assert.ok(pos(f) > 0 && pos(f) < pos('drive-view.js'), f);
      assert.doesNotMatch(read('src', 'renderer', f), /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(|new Function\(/, f);
    }
    const flat = (o, pre = '', out = {}) => { for (const [k, v] of Object.entries(o)) { const key = pre ? `${pre}.${k}` : k; if (v && typeof v === 'object') flat(v, key, out); else out[key] = v; } return out; };
    const de = flat(JSON.parse(read('src', 'i18n', 'de.json')));
    const en = flat(JSON.parse(read('src', 'i18n', 'en.json')));
    const src = ['drive-view.js', 'drive-state.js', 'drive-docs-view.js', 'drive-docs-state.js', 'drive-vault-view.js', 'drive-vault-state.js'].map((f) => read('src', 'renderer', f)).join('\n');
    const keys = new Set();
    for (const m of src.matchAll(/['"`](drive\.(?:doc|deadline|vault|office|import|err)\.[A-Za-z0-9_.]+)['"`]/g)) if (!m[1].endsWith('.')) keys.add(m[1]);
    for (const k of DD.DOC_KINDS) keys.add(`drive.doc.kind.${k}`);
    for (const k of DD.DEADLINE_KINDS) keys.add(`drive.deadline.kind.${k}`);
    for (const k of ['no_text', 'media_disabled', 'ai_budget', 'ai_capability', 'ai_invalid', 'ai_timeout', 'ai_provider', 'other']) keys.add(`drive.doc.reason.${k}`);
    for (const k of ['kind', 'title', 'date', 'sender', 'amount']) keys.add(`drive.doc.field.${k}`);
    for (const k of Object.values(DS.ERROR_CODES)) keys.add(`drive.err.${k}`);
    for (const k of ['one', 'other']) { keys.add(`drive.vault.pending.${k}`); keys.add(`drive.deadline.ago.${k}`); }
    for (const k of keys) {
      assert.ok(typeof de[k] === 'string' && de[k], `de: ${k}`);
      assert.ok(typeof en[k] === 'string' && en[k], `en: ${k}`);
    }
  });
});

describe('"KI für Dokumente" of an area (drive-state.js docAiSwitch)', () => {
  const me = { features: ['docAi'] };
  const ar = (o = {}) => ({ id: 'family:1', kind: 'family', label: 'Familie', writable: true, archived: false, docAi: true, ...o });
  const folder = { node: { id: 2, areaId: 'family:1', encrypted: false }, vault: null };

  it('with the write right while the Drive reports docAi and the area\'s state', () => {
    assert.deepEqual(DS.docAiSwitch(ar(), folder, me), { areaId: 'family:1', on: true });
    assert.deepEqual(DS.docAiSwitch(ar({ docAi: false }), folder, me), { areaId: 'family:1', on: false });
    assert.deepEqual(DS.docAiSwitch(ar(), null, me), { areaId: 'family:1', on: true });
  });

  it('not without the feature, the write right or the area\'s state; archived areas neither', () => {
    assert.equal(DS.docAiSwitch(ar(), folder, { features: ['office'] }), null);
    assert.equal(DS.docAiSwitch(ar(), folder, null), null);
    assert.equal(DS.docAiSwitch(ar({ writable: false }), folder, me), null);
    assert.equal(DS.docAiSwitch(ar({ archived: true }), folder, me), null);
    assert.equal(DS.docAiSwitch(ar({ docAi: null }), folder, me), null);
    assert.equal(DS.docAiSwitch(null, folder, me), null);
  });

  it('never in a vault folder', () => {
    assert.equal(DS.docAiSwitch(ar(), { node: { id: 30, encrypted: true }, vault: { id: 'v', state: 'open' } }, me), null);
    assert.equal(DS.docAiSwitch(ar(), { node: { id: 30, encrypted: true }, vault: null }, me), null);
    assert.equal(DS.docAiSwitch(ar(), { node: { id: 31 }, vault: { id: 'v', state: 'none' } }, me), null);
  });

  it('the areas after the switch: only that one changes', () => {
    const list = [ar({ id: 'mine:2', kind: 'mine' }), ar()];
    const next = DS.withDocAi(list, 'family:1', false);
    assert.deepEqual(next.map((a) => a.docAi), [true, false]);
    assert.equal(next[0], list[0]);
    assert.equal(list[1].docAi, true);
    assert.deepEqual(DS.withDocAi(null, 'x', true), []);
  });

  it('Drive 1.11: the Drive settings show it per area and send PATCH areas/<id> { docAi } (setDocAi), texts in de and en', () => {
    const v = read('src', 'renderer', 'drive-settings-view.js');
    assert.match(v, /MS\.docAiAreas\(p\.areas, p\.me\)/);
    assert.match(v, /api\.setDocAi\(x\.areaId, !x\.on\)/);
    assert.match(v, /role: 'switch'/);
    assert.doesNotMatch(read('src', 'renderer', 'drive-view.js'), /docAiToggle/, 'no longer in the bar');
    const de = JSON.parse(read('src', 'i18n', 'de.json')).drive.docAi;
    const en = JSON.parse(read('src', 'i18n', 'en.json')).drive.docAi;
    assert.equal(de.label, 'KI für Dokumente');
    assert.equal(en.label, 'AI for documents');
    for (const k of ['hint', 'onDone', 'offDone']) assert.ok(de[k] && en[k], k);
  });
});
