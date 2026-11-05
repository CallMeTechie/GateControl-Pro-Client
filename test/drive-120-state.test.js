'use strict';

// Drive 1.20 'offline' on the page "Drive": the row menu offers "Auf Mobilgeräten offline verfügbar" (a mark of the
// person for files and folders — the phones keep them, the home gateway holds them first; this PC keeps no copy for
// it, that stays "Immer auf diesem Gerät behalten" of "Dateien bei Bedarf") only when Drive reports 'offline', never
// for a locked vault node; the page loads the marks, toggles them over the bridge, and every key it uses exists in
// de and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const DS = require('../src/renderer/drive-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

describe('Drive 1.20: offline verfügbar', () => {
  it('the row menu: only with the feature, files and folders, not for a locked vault node', () => {
    const me = { features: ['offline'] };
    assert.equal(DS.actionsFor({ id: 1, name: 'Brief.pdf', isDir: false }, true, me).offline, true);
    assert.equal(DS.actionsFor({ id: 2, name: 'Urlaub', isDir: true }, false, me).offline, true);
    assert.equal(DS.actionsFor({ id: 1, name: 'Brief.pdf', isDir: false }, true, { features: ['vault'] }).offline, false);
    assert.equal(DS.actionsFor({ id: 3, name: 'x', encrypted: true, locked: true }, true, me).offline, false);
    assert.equal(DS.actionsFor({ id: 4, name: 'x', encrypted: true, locked: false }, true, me).offline, true);
  });

  it('the page: loads the marks, toggles them over the bridge, the texts exist in de and en', () => {
    const view = read('src', 'renderer', 'drive-view.js');
    assert.match(view, /api\.offline\(\)/);
    assert.match(view, /api\.setOffline\(n\.id, on\)/);
    assert.match(view, /acts\.offline/);
    const keys = [...new Set([...view.matchAll(/'(drive\.offline\.[A-Za-z]+)'/g)].map((m) => m[1]))];
    assert.deepEqual(keys.sort(), ['drive.offline.added', 'drive.offline.max', 'drive.offline.menuOff', 'drive.offline.menuOn', 'drive.offline.removed']);
    for (const lang of ['de', 'en']) {
      const j = JSON.parse(read('src', 'i18n', `${lang}.json`));
      for (const k of keys) {
        const v = k.split('.').reduce((o, x) => (o ? o[x] : undefined), j);
        assert.equal(typeof v, 'string', `${lang}: ${k}`);
      }
    }
    // the core's bridge carries the calls (client-core ≥ the commit core.ref names)
    const bridge = (() => { try { return read('node_modules', '@gatecontrol', 'client-core', 'src', 'preload', 'bridge.js'); } catch { return null; } })();
    if (bridge) assert.match(bridge, /setOffline:/);
  });
});
