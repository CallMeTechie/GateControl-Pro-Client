'use strict';

// Pro IPC wiring on top of the hardened core handlers: every channel is
// registered exactly once, and the setup-code paths (settings field, setup
// assistant, setup QR, server:test) work with ApiClientPro.
//
// Needs @gatecontrol/client-core: node_modules (CI clones it to .core) or a
// sibling checkout ../gatecontrol-client-core (local development). The private
// config-hash package and jsQR are replaced by stubs.

const { describe, it, before, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');
const fs = require('node:fs');

const ROOT = path.join(__dirname, '..');
const CORE_PKG = '@gatecontrol/client-core';

function findCore() {
  try {
    return path.dirname(require.resolve(`${CORE_PKG}/package.json`, { paths: [ROOT] }));
  } catch { /* not installed */ }
  for (const dir of [path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) {
    if (fs.existsSync(path.join(dir, 'src', 'ipc', 'base-handlers.js'))) return dir;
  }
  return null;
}

const coreDir = findCore();
let coreUsable = !!coreDir;

if (coreDir) {
  const realResolve = Module._resolveFilename;
  Module._resolveFilename = function (request, ...rest) {
    if (request === '@callmetechie/gatecontrol-config-hash') return path.join(__dirname, 'fixtures', 'config-hash-stub.js');
    if (request === 'jsqr') return path.join(__dirname, 'fixtures', 'jsqr-stub.js');
    if (request === CORE_PKG || request.startsWith(`${CORE_PKG}/`)) {
      try {
        return realResolve.call(this, request, ...rest);
      } catch {
        return realResolve.call(this, path.join(coreDir, request.slice(CORE_PKG.length) || 'src/index.js'), ...rest);
      }
    }
    return realResolve.call(this, request, ...rest);
  };
  try {
    require.resolve('axios', { paths: [coreDir] });
  } catch {
    coreUsable = false; // core present but its dependencies are not installed
  }
}

const skip = coreUsable ? false : 'gatecontrol-client-core (with dependencies) not available';

const CODE = 'AB12-CD34-EF56-7890';
const VALID_CONFIG = '[Interface]\nPrivateKey = x\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = y\nEndpoint = gate.example.com:51820';

describe('Pro IPC on core handlers', { skip }, () => {
  let registerProIpc, ApiClient, ApiClientPro, axios;
  before(() => {
    ({ registerProIpc } = require('../src/main/ipc-pro'));
    ApiClient = require(`${CORE_PKG}/src/services/api-client`);
    ApiClientPro = require('../src/services/api-client-pro');
    axios = require(require.resolve('axios', { paths: [coreDir] }));
  });

  function setup(extra = {}) {
    const handlers = {};
    const ipcMain = {
      handle(ch, fn) {
        if (handlers[ch]) throw new Error(`Attempted to register a second handler for '${ch}'`);
        handlers[ch] = fn;
      },
      on() {},
    };
    const stored = { 'server.url': '', 'server.apiKey': '' };
    const written = [];
    const calls = { dialogs: 0, opened: [], shown: [], autostart: [], connect: 0, updater: [] };
    const updater = {
      configure: (u, k) => calls.updater.push({ u, k }),
      check: async () => ({ version: '2.0.0' }),
      getUpdateInfo: () => null,
    };
    const apiClient = new ApiClientPro('', '', { info() {}, warn() {}, error() {}, debug() {} }, null, { clientVersion: '1.21.0' });
    apiClient.register = async () => { calls.register = (calls.register || 0) + 1; return { peerId: 42 }; };
    const ctx = {
      app: { getVersion: () => '1.21.0', setLoginItemSettings() { throw new Error('Pro uses schtasks'); } },
      dialog: {
        showMessageBox: async () => { calls.dialogs++; return { response: extra.dialogResponse ?? 0 }; },
        showOpenDialog: async () => ({ canceled: true }),
      },
      getMainWindow: () => ({}),
      store: { set: (k, v) => { stored[k] = v; }, get: (k, d) => (k in stored ? stored[k] : d), store: stored },
      wgService: { writeConfig: async (file, content) => { written.push({ file, content }); } },
      apiClient,
      ApiClientClass: ApiClientPro,
      killSwitch: {},
      getUpdater: () => updater,
      log: {
        info() {}, warn() {}, error() {}, debug() {},
        transports: { file: { getFile: () => ({ path: 'C:\\ProgramData\\gc\\main.log' }) } },
      },
      shell: {
        openExternal: async (u) => { calls.opened.push(u); },
        showItemInFolder: (p) => { calls.shown.push(p); },
      },
      connectTunnel: async () => { calls.connect++; },
      disconnectTunnel: async () => {},
      toggleKillSwitch: async () => {},
      toggleRdpAllow: async () => {},
      installUpdate: async () => {},
      getTunnelState: () => ({ connected: false }),
      wgConfigFile: 'C:\\gc\\gatecontrol0.conf',
      setLocale() {}, getLocale: () => 'de',
      checkSystemDns: async () => ({ connected: false }),
      setAutostart: async (on) => { calls.autostart.push(on); },
      rdpManager: { refreshServices: async () => [], getActiveSessions: () => [], startStatusPolling() {}, stopStatusPolling() {} },
      rdpWolClient: { wake: async () => true },
    };
    const registered = registerProIpc(ipcMain, ctx);
    return { handlers, stored, written, calls, registered, apiClient };
  }

  let originalRedeem, originalGet, redeemed;
  beforeEach(() => {
    originalRedeem = ApiClient.redeemSetupCode;
    originalGet = axios.get;
    redeemed = [];
    ApiClient.redeemSetupCode = async (url, code, opts) => {
      redeemed.push({ url, code, opts });
      return { ok: true, token: 'gc_minted_token', peerId: 17, config: VALID_CONFIG };
    };
    delete globalThis.__qrPayload;
  });
  afterEach(() => {
    ApiClient.redeemSetupCode = originalRedeem;
    axios.get = originalGet;
  });

  it('registers core and Pro channels exactly once', () => {
    const { handlers, registered } = setup();
    assert.equal(new Set(registered).size, registered.length);
    for (const ch of [
      // from core
      'server:setup', 'server:test', 'config:set', 'config:import-file', 'config:import-qr',
      'shell:open-external', 'logs:get', 'logs:export', 'logs:show', 'tunnel:connect', 'tunnel:status',
      // Pro-specific / overrides
      'autostart:set', 'dns:leak-test', 'dns:check-system', 'peer:info', 'update:check',
      'panel:open', 'panel:close', 'rdp:list', 'rdp:connect', 'rdp:disconnect', 'rdp:detail',
      'rdp:wol', 'rdp:status', 'rdp:active-sessions', 'rdp:pin-toggle', 'locale:set', 'locale:get',
    ]) {
      assert.equal(typeof handlers[ch], 'function', ch);
    }
  });

  it('every channel the Pro preload invokes is handled', () => {
    const preload = fs.readFileSync(path.join(ROOT, 'src', 'main', 'preload.js'), 'utf8');
    const invoked = [...preload.matchAll(/ipcRenderer\.invoke\('([^']+)'/g)].map((m) => m[1]);
    const { handlers } = setup();
    for (const ch of invoked) assert.equal(typeof handlers[ch], 'function', ch);
  });

  it('settings: a setup code in the key field enrolls via ApiClientPro and stores token + config', async () => {
    const { handlers, stored, written, calls, apiClient } = setup();
    const res = await handlers['server:setup']({}, { url: 'gate.example.com', apiKey: 'ab12cd34ef567890' });
    assert.deepEqual(res, { success: true, peerId: 17, enrolled: true });
    assert.equal(redeemed.length, 1);
    assert.equal(redeemed[0].url, 'https://gate.example.com');
    assert.equal(redeemed[0].code, CODE);
    assert.equal(redeemed[0].opts.clientVersion, '1.21.0');
    // what connectTunnel needs: server.url + server.apiKey (fetchConfig) or configPath
    assert.equal(stored['server.url'], 'https://gate.example.com');
    assert.equal(stored['server.apiKey'], 'gc_minted_token');
    assert.equal(stored['server.peerId'], '17');
    assert.equal(stored['tunnel.configPath'], 'C:\\gc\\gatecontrol0.conf');
    assert.deepEqual(written, [{ file: 'C:\\gc\\gatecontrol0.conf', content: VALID_CONFIG }]);
    assert.equal(apiClient.apiKey, 'gc_minted_token');
    assert.equal(apiClient.serverUrl, 'https://gate.example.com');
    assert.equal(apiClient.peerId, 17);
    assert.deepEqual(calls.updater, [{ u: 'https://gate.example.com', k: 'gc_minted_token' }]);
    assert.equal(calls.register || 0, 0, 'the code brought its peer');
    await handlers['tunnel:connect']({});
    assert.equal(calls.connect, 1);
  });

  it('setup assistant: https:// URL + code', async () => {
    const { handlers, stored } = setup();
    const res = await handlers['server:setup']({}, { url: 'https://gate.example.com/', apiKey: CODE });
    assert.equal(res.success, true);
    assert.equal(res.enrolled, true);
    assert.equal(stored['server.apiKey'], 'gc_minted_token');
  });

  it('a server config failing validation is not written', async () => {
    ApiClient.redeemSetupCode = async () => ({ ok: true, token: 'gc_t', peerId: 1, config: 'garbage' });
    const { handlers, written, stored } = setup();
    const res = await handlers['server:setup']({}, { url: 'gate.example.com', apiKey: CODE });
    assert.equal(res.success, true);
    assert.deepEqual(written, []);
    assert.equal(stored['tunnel.configPath'], undefined);
  });

  it('setup QR: asks first, then enrolls; the scan loop is told to stop', async () => {
    globalThis.__qrPayload = `gatecontrol://enroll?url=${encodeURIComponent('https://gate.example.com')}&code=${CODE}`;
    const { handlers, stored, written, calls } = setup();
    const res = await handlers['config:import-qr']({}, { data: [0, 0, 0, 0], width: 1, height: 1 });
    assert.equal(calls.dialogs, 1);
    assert.equal(res.enrollment, true);
    assert.equal(res.success, true);
    assert.equal(stored['server.apiKey'], 'gc_minted_token');
    assert.equal(written.length, 1);
    assert.notEqual(written[0].content, globalThis.__qrPayload, 'the link is never written as WG config');
  });

  it('setup QR: cancelling the dialog redeems nothing', async () => {
    globalThis.__qrPayload = `gatecontrol://enroll?url=https://gate.example.com&code=${CODE}`;
    const { handlers, stored, written } = setup({ dialogResponse: 1 });
    const res = await handlers['config:import-qr']({}, { data: [], width: 1, height: 1 });
    assert.deepEqual(res, { success: false, cancelled: true, enrollment: true });
    assert.equal(redeemed.length, 0);
    assert.equal(stored['server.apiKey'], '');
    assert.deepEqual(written, []);
  });

  it('QR with an invalid WireGuard config is rejected', async () => {
    globalThis.__qrPayload = 'not a config';
    const { handlers, written } = setup();
    const res = await handlers['config:import-qr']({}, { data: [], width: 1, height: 1 });
    assert.equal(res.success, false);
    assert.deepEqual(written, []);
  });

  it('server:test with a code only pings (does not spend the code)', async () => {
    const urls = [];
    axios.get = async (url, opts) => {
      urls.push({ url, headers: opts && opts.headers });
      const err = new Error('401'); err.response = { status: 401 }; throw err;
    };
    const { handlers } = setup();
    const res = await handlers['server:test']({}, { url: 'gate.example.com', apiKey: CODE });
    assert.deepEqual(res, { success: true });
    assert.deepEqual(urls, [{ url: 'https://gate.example.com/api/v1/client/ping', headers: undefined }]);
    assert.equal(redeemed.length, 0);
  });

  it('API key setup over http is refused', async () => {
    const { handlers, stored } = setup();
    const res = await handlers['server:setup']({}, { url: 'http://gate.example.com', apiKey: 'gc_abc' });
    assert.equal(res.success, false);
    assert.equal(stored['server.apiKey'], '');
  });

  it('config:set only takes allowlisted keys', async () => {
    const { handlers, stored } = setup();
    await handlers['config:set']({}, 'server.url', 'https://evil.example');
    await handlers['config:set']({}, 'tunnel.configPath', 'C:\\evil.conf');
    await handlers['config:set']({}, 'tunnel.autoConnect', false);
    assert.equal(stored['server.url'], '');
    assert.equal(stored['tunnel.configPath'], undefined);
    assert.equal(stored['tunnel.autoConnect'], false);
  });

  it('shell:open-external only opens http(s); logs:show reveals the log file', async () => {
    const { handlers, calls } = setup();
    assert.equal(await handlers['shell:open-external']({}, 'file:///C:/Windows/System32/cmd.exe'), false);
    assert.equal(await handlers['shell:open-external']({}, 'https://nas.example.com'), true);
    assert.deepEqual(calls.opened, ['https://nas.example.com']);
    assert.equal(await handlers['logs:show']({}), true);
    assert.deepEqual(calls.shown, ['C:\\ProgramData\\gc\\main.log']);
  });

  it('Pro overrides: schtasks autostart and active update check', async () => {
    const { handlers, stored, calls } = setup();
    assert.equal(await handlers['autostart:set']({}, true), true);
    assert.deepEqual(calls.autostart, [true]);
    assert.equal(stored['app.startWithWindows'], true);
    assert.deepEqual(await handlers['update:check']({}), { version: '2.0.0' });
  });
});
