'use strict';

/**
 * The plugin gatecontrol-vault for the e2e mock server: the core's in-memory
 * Vault server (gatecontrol-client-core test/fixtures/vault-server.js — the
 * contract of the plugin's README "App-API", shapes and revisions checked,
 * nothing decrypted) behind HTTP. The app is user 3 ("Marc"); 2 Anna and
 * 4 Lena are the other people.
 *
 *   const v = mock.setVault();      // v.srv → the core fake (accounts, vaults, items, calls)
 */

const path = require('path');

function coreDir() {
  const root = path.join(__dirname, '..', '..', '..');
  try {
    return path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [root] }));
  } catch {
    return path.join(root, '..', 'gatecontrol-client-core');
  }
}

const BASE = 'plugins/gatecontrol-vault/api/';
const ME = 3;

function createVault(opts = {}) {
  const dir = coreDir();
  const { vaultServer } = require(path.join(dir, 'test', 'fixtures', 'vault-server.js'));
  const srv = vaultServer(opts);
  const transport = srv.transport(ME, 'e2e');
  return {
    srv,
    entry: () => ({ id: 'gatecontrol-vault', name: 'Vault', version: '1.0.0', tab: null }),
    /** → true when the request was ours (answered asynchronously). */
    handle({ method, route, query, raw }, json) {
      if (!route.startsWith(BASE)) return false;
      let body;
      try { body = raw && raw.length ? JSON.parse(raw.toString('utf8')) : undefined; } catch { body = undefined; }
      transport._call(method, `/api/v1/client/${route}`, { body, params: query })
        .then((r) => json(200, r))
        .catch((err) => json(err.status || 400, err.body || { ok: false, code: err.code || 'invalid', error: err.message }));
      return true;
    },
  };
}

module.exports = { createVault };
