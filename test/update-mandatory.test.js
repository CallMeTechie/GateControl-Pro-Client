'use strict';

// Server-controlled updates in the Pro client: channel display (read-only,
// assigned by the server) and the non-dismissable "Update erforderlich"
// notice for mandatory updates. The decision logic lives in
// src/renderer/update-state.js (no DOM), the wiring is checked statically.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const { updateCardState, channelLabelKey } = require('../src/renderer/update-state');

describe('updateCardState', () => {
  it('hidden without a ready update', () => {
    assert.equal(updateCardState(null, { mandatory: true }, false).visible, false);
  });

  it('optional update can be dismissed', () => {
    const s = updateCardState({ version: '1.2.0' }, { mandatory: false, minVersion: null }, false);
    assert.deepEqual(s, { visible: true, mandatory: false, dismissable: true, version: '1.2.0', minVersion: null });
    assert.equal(updateCardState({ version: '1.2.0' }, null, true).visible, false);
  });

  it('mandatory update stays visible even after "later" and is not dismissable', () => {
    const s = updateCardState({ version: '1.2.0' }, { mandatory: true, minVersion: '1.1.5' }, true);
    assert.deepEqual(s, { visible: true, mandatory: true, dismissable: false, version: '1.2.0', minVersion: '1.1.5' });
  });

  it('the newest policy wins over the flag of the ready event', () => {
    assert.equal(updateCardState({ version: '1.2.0', mandatory: true }, { mandatory: false }, false).mandatory, false);
    assert.equal(updateCardState({ version: '1.2.0', mandatory: true, minVersion: '1.1.0' }, null, false).mandatory, true);
  });

  it('channel labels', () => {
    assert.equal(channelLabelKey('beta'), 'update.channelBeta');
    assert.equal(channelLabelKey('stable'), 'update.channelStable');
    assert.equal(channelLabelKey(null), 'update.channelUnknown');
    assert.equal(channelLabelKey('nightly'), 'update.channelUnknown');
  });
});

describe('wiring', () => {
  const html = read('src/renderer/index.html');
  const renderer = read('src/renderer/renderer.js');
  const main = read('src/main/main.js');

  it('loads the helper before renderer.js (CSP: self only)', () => {
    assert.ok(html.indexOf('<script src="update-state.js"></script>') > -1);
    assert.ok(html.indexOf('update-state.js') < html.indexOf('renderer.js'));
  });

  it('the mandatory banner has an install button and no dismiss button', () => {
    const m = /<div class="banner banner-err" id="update-required-banner"[\s\S]*?\n\t{5}<\/div>/.exec(html);
    assert.ok(m, 'banner markup');
    assert.match(m[0], /id="update-required-install"/);
    assert.doesNotMatch(m[0], /dismiss/);
    assert.match(renderer, /\$\('#update-required-install'\)\.addEventListener\('click', \(\) => update\.install\(\)\)/);
  });

  it('shows the channel read-only in Settings → About', () => {
    assert.match(html, /id="update-channel"/);
    assert.doesNotMatch(html, /<select[^>]*id="update-channel"/);
    assert.match(renderer, /update\.onPolicy\(/);
  });

  it('main: product for the server, mandatory tray entry, no silent install', () => {
    assert.match(main, /clientType: 'pro',\n\s*\}\);/);
    assert.match(main, /updateMenuItems\(\{/);
    assert.match(main, /mandatory: !!updater\?\.isMandatory\(\)/);
    assert.match(main, /onPolicyChange:/);
    // installUpdate() is only reached from user actions (tray, IPC, banner)
    const calls = main.match(/installUpdate\(\)/g) || [];
    assert.ok(!/release\.mandatory[^\n]*installUpdate\(\)/.test(main));
    assert.ok(calls.length >= 2);
  });

  it('i18n keys used by the notice exist in core (de/en)', () => {
    const core = path.dirname(require.resolve('@gatecontrol/client-core/package.json'));
    for (const lang of ['de', 'en']) {
      const loc = JSON.parse(fs.readFileSync(path.join(core, 'src', 'i18n', 'locales', `${lang}.json`), 'utf8'));
      for (const k of ['required', 'requiredDesc', 'requiredDescNoMin', 'requiredTunnelHint', 'channel', 'channelHint',
        'channelStable', 'channelBeta', 'channelUnknown', 'installRequired', 'install']) {
        assert.equal(typeof loc.update[k], 'string', `${lang}: update.${k}`);
      }
    }
  });
});
