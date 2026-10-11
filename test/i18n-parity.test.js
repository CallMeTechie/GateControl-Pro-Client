'use strict';

// German and English stay in step: the Pro strings have the same keys in
// both languages, and every key the notification UI uses exists in the Pro
// or the core locale files (core: push.*).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CORE_PKG = '@gatecontrol/client-core';

function flatten(obj, prefix = '', out = {}) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
    else out[key] = String(v);
  }
  return out;
}

const read = (file) => flatten(JSON.parse(fs.readFileSync(file, 'utf8')));
const de = read(path.join(ROOT, 'src', 'i18n', 'de.json'));
const en = read(path.join(ROOT, 'src', 'i18n', 'en.json'));

function coreLocales() {
  let dir = null;
  try {
    dir = path.dirname(require.resolve(`${CORE_PKG}/package.json`, { paths: [ROOT] }));
  } catch {
    for (const d of [path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) {
      if (fs.existsSync(path.join(d, 'src', 'i18n', 'locales', 'de.json'))) { dir = d; break; }
    }
  }
  if (!dir) return null;
  return {
    de: read(path.join(dir, 'src', 'i18n', 'locales', 'de.json')),
    en: read(path.join(dir, 'src', 'i18n', 'locales', 'en.json')),
  };
}

const placeholders = (s) => [...s.matchAll(/\{\{\s*(\w+)\s*\}\}/g)].map((m) => m[1]).sort();

describe('i18n parity (de / en)', () => {
  it('same keys in both languages', () => {
    const onlyDe = Object.keys(de).filter((k) => !(k in en));
    const onlyEn = Object.keys(en).filter((k) => !(k in de));
    assert.deepEqual(onlyDe, [], 'missing in en.json');
    assert.deepEqual(onlyEn, [], 'missing in de.json');
  });

  it('same placeholders and no empty notification strings', () => {
    for (const key of Object.keys(de)) {
      assert.deepEqual(placeholders(en[key] || ''), placeholders(de[key]), key);
      if (key.startsWith('ui.inbox.') || key.startsWith('ui.notify.')) {
        assert.ok(de[key].trim() && en[key].trim(), `${key} is empty`);
      }
    }
  });

  const core = coreLocales();
  it('every key of the notification UI resolves (app or core, both languages)', { skip: core ? false : 'core not available' }, () => {
    const html = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'index.html'), 'utf8');
    const renderer = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'renderer.js'), 'utf8');
    const main = fs.readFileSync(path.join(ROOT, 'src', 'main', 'main.js'), 'utf8');
    const keys = new Set();
    for (const m of html.matchAll(/data-i18n(?:-[a-z-]+)?="((?:ui\.inbox|ui\.notify|push)\.[^"]+)"/g)) keys.add(m[1]);
    for (const m of (renderer + main).matchAll(/t\('((?:ui\.inbox|ui\.notify|push)\.[A-Za-z0-9_.]+)'/g)) keys.add(m[1]);
    // built from the empty state / status (renderer + notify-state.js)
    for (const s of ['empty', 'filtered', 'off', 'notConfigured', 'error', 'unsupported']) keys.add(`ui.inbox.${s}.title`);
    for (const s of ['empty', 'filtered', 'off', 'notConfigured', 'error']) keys.add(`ui.inbox.${s}.hint`);
    for (const s of ['off', 'error']) keys.add(`ui.inbox.${s}.action`);
    for (const s of ['connected', 'connecting', 'disabled', 'error', 'stopped']) keys.add(`push.state.${s}`);
    for (const s of ['info', 'normal', 'high', 'critical']) keys.add(`push.priority.${s}`);
    for (const s of ['direct', 'tunnel']) keys.add(`push.via.${s}`);
    for (const s of ['tunnelOnly', 'killSwitchOk', 'tray.inbox', 'tray.inboxUnread', 'tray.dnd1h', 'tray.dndOff']) keys.add(`push.${s}`);
    assert.ok(keys.size > 40, `only ${keys.size} keys found`);
    for (const key of keys) {
      assert.ok(key in de || key in core.de, `de: ${key}`);
      assert.ok(key in en || key in core.en, `en: ${key}`);
    }
  });
});
