'use strict';

// The e2e test mode (test key for update signatures, stubbed services,
// installer launch recorder) must never be reachable in a packaged build.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { isE2eMode, loadE2eHooks } = require('../src/main/e2e-guard');

/** env whose every read fails the test — proves it is not even consulted. */
const untouchableEnv = new Proxy({}, {
  get(_t, prop) { throw new Error(`env.${String(prop)} must not be read`); },
  has(_t, prop) { throw new Error(`env.${String(prop)} must not be read`); },
});

describe('e2e guard', () => {
  it('is only active for an unpackaged app with GC_E2E=1', () => {
    assert.equal(isE2eMode({ isPackaged: false, env: { GC_E2E: '1' } }), true);
    assert.equal(isE2eMode({ isPackaged: true, env: { GC_E2E: '1' } }), false);
    assert.equal(isE2eMode({ isPackaged: undefined, env: { GC_E2E: '1' } }), false);
    assert.equal(isE2eMode({ isPackaged: false, env: {} }), false);
    assert.equal(isE2eMode({ isPackaged: false, env: { GC_E2E: 'true' } }), false);
    assert.equal(isE2eMode({ isPackaged: false, env: { GC_E2E: '0' } }), false);
    assert.equal(isE2eMode({ isPackaged: false }), false);
    assert.equal(isE2eMode(), false);
  });

  it('ignores GC_E2E / GC_E2E_UPDATE_PUBKEY in a packaged app without loading the hooks', () => {
    let loaded = false;
    const result = loadE2eHooks({
      app: { isPackaged: true },
      env: { GC_E2E: '1', GC_E2E_UPDATE_PUBKEY: '/tmp/attacker.pub', GC_E2E_DIR: '/tmp/x' },
      load: () => { loaded = true; return { install: () => ({}) }; },
    });
    assert.equal(result, null);
    assert.equal(loaded, false);
  });

  it('does not even read the environment in a packaged app', () => {
    const result = loadE2eHooks({
      app: { isPackaged: true },
      env: untouchableEnv,
      load: () => { throw new Error('hooks must not be loaded'); },
    });
    assert.equal(result, null);
  });

  it('does nothing without GC_E2E=1 in development', () => {
    const result = loadE2eHooks({
      app: { isPackaged: false },
      env: { GC_E2E_UPDATE_PUBKEY: '/tmp/test.pub' },
      load: () => { throw new Error('hooks must not be loaded'); },
    });
    assert.equal(result, null);
  });

  it('installs the hooks for `electron .` with GC_E2E=1', () => {
    const app = { isPackaged: false };
    const env = { GC_E2E: '1' };
    let args = null;
    const result = loadE2eHooks({ app, env, load: () => ({ install: (a) => { args = a; return 'hooks'; } }) });
    assert.equal(result, 'hooks');
    assert.equal(args.app, app);
    assert.equal(args.env, env);
  });

  it('the hooks themselves refuse to run in a packaged app', () => {
    const { install } = require('./e2e/support/app-hooks');
    assert.throws(() => install({ app: { isPackaged: true }, env: { GC_E2E: '1', GC_E2E_DIR: '/tmp/x' } }), /packaged/);
  });

  it('the hooks are not part of the packaged app', () => {
    const pkg = require('../package.json');
    for (const pattern of pkg.build.files) {
      assert.ok(!/^!?test(\/|$)/.test(pattern) && !pattern.startsWith('**'), `build.files must not ship test/: ${pattern}`);
    }
    for (const res of pkg.build.extraResources || []) {
      assert.ok(!String(res.from).startsWith('test'), `extraResources must not ship test/: ${res.from}`);
    }
  });

  it('main.js installs the hooks via the guard before any core service is required', () => {
    const main = fs.readFileSync(path.join(ROOT, 'src', 'main', 'main.js'), 'utf8');
    const guardIdx = main.indexOf("require('./e2e-guard').loadE2eHooks({ app })");
    const coreIdx = main.indexOf("require('@gatecontrol/client-core");
    assert.ok(guardIdx > 0, 'main.js must call loadE2eHooks({ app })');
    assert.ok(coreIdx > guardIdx, 'hooks must be installed before core is required');
    assert.ok(!/GC_E2E/.test(main), 'main.js must not read GC_E2E* itself (only through the guard)');
  });
});
