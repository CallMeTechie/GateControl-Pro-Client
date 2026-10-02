'use strict';

/**
 * E2E test mode guard.
 *
 * The Playwright suite (test/e2e) starts the unpackaged app (`electron .`)
 * with GC_E2E=1. Only then are the test hooks from test/e2e/support loaded:
 * isolated user-data dir, stubbed WireGuard/kill-switch/RDP/firewall
 * services, a throwaway update signing key and a recorder instead of the
 * installer launch.
 *
 * A packaged build never loads them: app.isPackaged is checked first and the
 * environment is not even read. The hooks are not part of the package either
 * (build.files only ships src/** and package.json), and they refuse to run in
 * a packaged app themselves. test/e2e-guard.test.js covers this.
 */

const HOOKS_MODULE = '../../test/e2e/support/app-hooks';

/** True only for an unpackaged app started with GC_E2E=1. */
function isE2eMode({ isPackaged, env } = {}) {
  if (isPackaged !== false) return false;
  return !!env && env.GC_E2E === '1';
}

/**
 * Installs the e2e hooks when isE2eMode() holds, otherwise does nothing.
 * Must run before the core services are required.
 * @returns {object|null} the hooks, or null outside of e2e mode
 */
function loadE2eHooks({ app, env = process.env, load = () => require(HOOKS_MODULE) } = {}) {
  if (!app || !isE2eMode({ isPackaged: app.isPackaged, env })) return null;
  return load().install({ app, env });
}

module.exports = { isE2eMode, loadE2eHooks };
