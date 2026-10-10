'use strict';

// recoverKillSwitch() itself lives in core (src/lifecycle/killswitch-startup.js,
// unit-tested there); this checks how main.js wires it up.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

describe('main.js kill-switch wiring', () => {
  const main = fs.readFileSync(path.join(ROOT, 'src', 'main', 'main.js'), 'utf8');

  it('uses the shared core implementation', () => {
    assert.doesNotMatch(main, /require\('\.\/killswitch-startup'\)/);
    assert.match(main, /recoverKillSwitch[\s\S]*?require\('@gatecontrol\/client-core[^']*'\)/);
  });

  it('runs the startup recovery before auto-connect', () => {
    assert.match(main, /recoverKillSwitch\(\{ killSwitch: killSwitchSvc, store, wgService, log \}\)/);
    assert.match(main, /await killSwitchRecovery;\s*try \{\s*await connectTunnel\(\)/);
  });

  it('does not rely on an async will-quit handler (Electron does not await it)', () => {
    assert.doesNotMatch(main, /app\.on\('will-quit',\s*async/);
    assert.match(main, /app\.on\('before-quit', \(e\) => \{[\s\S]*?e\.preventDefault\(\);[\s\S]*?releaseFirewallOnQuit\(\)/);
  });

  it('keeps the kill-switch preference on quit', () => {
    assert.doesNotMatch(main, /store\.set\('tunnel\.killSwitch',\s*false\)/);
  });
});
