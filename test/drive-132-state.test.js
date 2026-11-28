'use strict';

// Drive plugin 1.32 'vaultLocal' („Tresor: Nur auf diesem Gerät“) on the page "Drive" (no DOM), only shown on Windows:
// a vault folder whose content lies only on one device is a greyed placeholder „Nur auf Pixel 8“ with the date it went
// there and no size; its menu only "Info" and (own, after "Rückgängig") "Platzhalter entfernen …"; nothing is dropped
// into it; the refusals 409 local_only / local_moving name the device. Without `local` (older Drive) all as before.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const DS = require('../src/renderer/drive-state');
const BS = require('../src/renderer/drive-bulk-state');

const ROOT = path.join(__dirname, '..');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);
const SINCE = new Date(2026, 10, 27, 10, 0).getTime();

const folder = (local, extra = {}) => ({
  id: 41, areaId: 'mine:2', parentId: 40, name: 'Steuer 2025', isDir: true, encrypted: true, vaultId: 'Vt9bJm0n2QwErTyUiOpAsD', locked: false,
  mtime: SINCE - 86400000 * 30, ...(local ? { local } : {}), ...extra,
});
const L = (o = {}) => ({ deviceName: 'Pixel 8', platform: 'android', state: 'local', since: SINCE, mine: true, undo: false, purgeAt: null, ...o });

describe('Drive 1.32: a placeholder in the vault list', () => {
  it('greyed: „Nur auf Pixel 8“, the date it went there, no size, the phone', () => {
    const v = DS.rowView(folder(L()), { t, locale: 'de', now: SINCE + 86400000 * 2 });
    assert.equal(v.local.placeholder, true);
    assert.equal(v.local.badge, 'drive.local.badge(device=Pixel 8)');
    assert.equal(v.date, 'drive.local.since(date=27.11.2026)');
    assert.equal(v.size, '–');
    assert.equal(v.local.icon, 'phone');
    assert.equal(DS.localView(folder(L({ platform: 'windows' })), { t }).icon, 'device');
    assert.equal(DS.localView(folder(L({ deviceName: null })), { t }).device, 'drive.local.otherDevice');
  });

  it('without local (an older Drive), a file or outside a vault: as before', () => {
    const v = DS.rowView(folder(null), { t, locale: 'de', now: SINCE });
    assert.equal(v.local, undefined);
    assert.equal(v.size, '');
    assert.equal(DS.localView({ ...folder(L()), encrypted: false }, { t }), null);
    assert.equal(DS.localView({ ...folder(L()), isDir: false }, { t }), null);
    assert.equal(DS.localView(folder(L({ state: 'other' })), { t }), null);
    assert.equal(DS.actionsFor(folder(null), true, { features: ['offline'] }).rename, true);
  });

  it('the menu: only Info and — own, "Rückgängig" over — "Platzhalter entfernen"', () => {
    const a = DS.actionsFor(folder(L()), true, { features: ['offline', 'timeTravel', 'links'] });
    assert.equal(a.local, true);
    assert.equal(a.info, true);
    assert.equal(a.forget, true);
    for (const k of ['open', 'saveAs', 'share', 'rename', 'move', 'versions', 'remove', 'portal', 'timeTravel', 'details', 'offline']) assert.equal(!!a[k], false, k);
    assert.equal(DS.actionsFor(folder(L({ undo: true })), true, null).forget, false, 'within the 24 hours: not yet');
    assert.equal(DS.actionsFor(folder(L({ undo: null })), true, null).forget, false);
    assert.equal(DS.actionsFor(folder(L({ mine: false })), true, null).forget, false);
    // being moved to the device: still opens (read only), nothing else
    const m = DS.actionsFor(folder(L({ state: 'moving' })), true, null);
    assert.equal(m.open, true);
    assert.equal(m.forget, false);
    assert.equal(m.remove, false);
  });

  it('the note (W2): where, since when, how it comes back; later when "Rückgängig" still runs', () => {
    const lv = DS.localView(folder(L()), { t, locale: 'de' });
    assert.equal(lv.title, 'drive.local.title(name=Steuer 2025,device=Pixel 8)');
    assert.equal(lv.text, 'drive.local.text(device=Pixel 8,kind=drive.local.kind.phone,date=27.11.2026)');
    assert.equal(lv.more, 'drive.local.more.phone');
    assert.equal(lv.canForget, true);
    const early = DS.localView(folder(L({ undo: true, purgeAt: SINCE + 86400000 })), { t, locale: 'de' });
    assert.equal(early.canForget, false);
    assert.match(early.more, /drive\.local\.forgetLater\(date=/);
    const moving = DS.localView(folder(L({ state: 'moving' })), { t, locale: 'de' });
    assert.equal(moving.placeholder, false);
    assert.equal(moving.badge, 'drive.local.badgeMoving(device=Pixel 8)');
    assert.equal(moving.more, '');
  });

  it('nothing is dropped into a placeholder, also not while it moves', () => {
    assert.equal(DS.canDropFiles(folder(L()), { inVault: true }), false);
    assert.equal(DS.canDropFiles(folder(L({ state: 'moving' })), { inVault: true }), false);
    assert.equal(DS.canDropFiles(folder(null), { inVault: true }), true);
  });

  it('the refusals name the device; a job names placeholders', () => {
    assert.equal(DS.errorText({ ok: false, code: 'local_only', deviceName: 'Pixel 8' }, t), 'drive.err.localOnly(device=Pixel 8)');
    assert.equal(DS.errorText({ ok: false, code: 'local_moving', deviceName: 'Pixel 8' }, t), 'drive.err.localMoving(device=Pixel 8)');
    assert.equal(DS.errorText({ ok: false, code: 'local_only' }, t), 'drive.err.localOnly(device=drive.local.otherDevice)');
    assert.match(DS.errorText({ ok: false, code: 'conflict', reason: 'purge_pending', purgeAt: '2026-11-29T10:00:00.000Z' }, t), /^drive\.local\.forgetLater\(date=/);
    assert.ok(BS.REASONS.includes('local_only') && BS.REASONS.includes('local_moving'));
  });

  it('a selection with a placeholder: not moved, renamed or put into the trash', () => {
    const me = { features: ['bulk'] };
    const a = BS.actions([folder(L()), { id: 50, isDir: false, encrypted: true, name: 'a.pdf' }], { me, writable: true, vault: true });
    assert.deepEqual(a.move, { on: false, why: 'drive.bulk.why.local' });
    assert.deepEqual(a.trash, { on: false, why: 'drive.bulk.why.local' });
    assert.equal(BS.actions([folder(L())], { me, writable: true, vault: true }).rename.why, 'drive.bulk.why.local');
    assert.equal(BS.actions([folder(null)], { me, writable: true, vault: true }).trash.on, true);
  });

  it('every text in both languages', () => {
    const de = JSON.parse(fs.readFileSync(path.join(ROOT, 'src', 'i18n', 'de.json'), 'utf8'));
    const en = JSON.parse(fs.readFileSync(path.join(ROOT, 'src', 'i18n', 'en.json'), 'utf8'));
    const get = (o, k) => k.split('.').reduce((x, p) => (x && typeof x === 'object' ? x[p] : undefined), o);
    const keys = ['badge', 'badgeMoving', 'badgeReturning', 'since', 'title', 'titleMoving', 'text', 'textNoDate', 'textMoving', 'textReturning',
      'more.phone', 'more.pc', 'more.other', 'moreOther', 'forgetLater', 'forgetLaterAny', 'menuHead', 'menuHeadMoving', 'info', 'infoSub', 'openSub',
      'uploadHere', 'forget', 'forgetSub', 'forgetTitle', 'forgetText', 'forgetGo', 'forgotten', 'otherDevice', 'kind.phone', 'kind.pc', 'kind.other']
      .map((k) => `drive.local.${k}`).concat(['drive.err.localOnly', 'drive.err.localMoving', 'drive.err.localNested', 'drive.bulk.reason.local_only', 'drive.bulk.reason.local_moving', 'drive.bulk.why.local']);
    for (const k of keys) {
      assert.equal(typeof get(de, k), 'string', `de ${k}`);
      assert.equal(typeof get(en, k), 'string', `en ${k}`);
    }
    assert.equal(get(de, 'drive.local.badge'), 'Nur auf {{device}}');
  });
});
