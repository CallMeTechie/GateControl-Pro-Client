'use strict';

/**
 * E2E hooks, loaded into the Electron main process by src/main/e2e-guard.js
 * (only for `electron .` with GC_E2E=1, never in a packaged build).
 *
 * Runs before main.js requires the core services and
 *   - moves userData/logs into GC_E2E_DIR (isolated per test),
 *   - trusts the mock server's self-signed certificate (GC_E2E_CA),
 *   - replaces WireGuard, kill switch, RDP allow, DNS policy and the RDP
 *     trust migration with in-memory stubs (no tunnel, no firewall, no
 *     registry changes, no admin rights needed),
 *   - loads the throwaway update public key from GC_E2E_UPDATE_PUBKEY
 *     instead of build/update-signing.pub,
 *   - keeps the real Updater (signature, hash and download checks run
 *     unchanged) but downloads into GC_E2E_DIR and exposes the instance,
 *   - records shell.openPath (the installer launch) instead of starting the
 *     file, plus quit and service calls, in GC_E2E_DIR/events.jsonl and on
 *     globalThis.__gcE2E (reachable via electronApp.evaluate()).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const tls = require('tls');
const Module = require('module');

const APP_ROOT = path.join(__dirname, '..', '..', '..');

function stubModule(file, exports) {
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  m.exports = exports;
  m.loaded = true;
  require.cache[file] = m;
}

function sha256File(file) {
  try {
    const buf = fs.readFileSync(file);
    return { sha256: crypto.createHash('sha256').update(buf).digest('hex'), size: buf.length };
  } catch {
    return { sha256: null, size: null };
  }
}

function install({ app, env }) {
  // Defense in depth: e2e-guard already checks this before loading us.
  if (!app || app.isPackaged !== false) {
    throw new Error('E2E hooks must never run in a packaged app');
  }
  const dir = env.GC_E2E_DIR;
  if (!dir || !path.isAbsolute(dir)) throw new Error('GC_E2E_DIR (absolute path) is required in e2e mode');
  fs.mkdirSync(dir, { recursive: true });

  const eventsFile = path.join(dir, 'events.jsonl');
  const state = { dir, events: [], trayMenu: null, updater: null };

  function record(type, data = {}) {
    const event = { type, t: Date.now(), ...data };
    state.events.push(event);
    try { fs.appendFileSync(eventsFile, JSON.stringify(event) + '\n'); } catch { /* best effort */ }
  }

  // ── Isolated profile ────────────────────────────────────
  app.setPath('userData', path.join(dir, 'userData'));
  app.setAppLogsPath(path.join(dir, 'logs'));

  // ── Mock server TLS trust (test CA only, added to the defaults) ──
  if (env.GC_E2E_CA) {
    const ca = fs.readFileSync(env.GC_E2E_CA, 'utf8');
    tls.setDefaultCACertificates([...tls.getCACertificates('default'), ca]);
  }

  // ── Service stubs ───────────────────────────────────────
  const coreFile = (p) => require.resolve(`@gatecontrol/client-core/${p}`, { paths: [APP_ROOT] });

  class FakeWireGuardService {
    constructor() { this.connected = false; }
    async writeConfig(configPath, content) {
      await fs.promises.mkdir(path.dirname(configPath), { recursive: true });
      await fs.promises.writeFile(configPath, content, { mode: 0o600 });
      record('wg.writeConfig');
    }
    async readConfig(configPath) { return fs.promises.readFile(configPath, 'utf8'); }
    async connect() {
      record('wg.connect');
      throw new Error('E2E: WireGuard tunnel is stubbed');
    }
    async disconnect() { record('wg.disconnect'); this.connected = false; }
    async isConnected() { return false; }
    async isInstalled() { return true; }
    async getVersion() { return 'e2e-stub'; }
    async getStats() { return null; }
  }

  class FakeKillSwitch {
    constructor() { this.enabled = false; }
    async enable() { record('killswitch.enable'); this.enabled = true; }
    async disable() { record('killswitch.disable'); this.enabled = false; }
    async recoverStaleState() { record('killswitch.recover'); return 'none'; }
    async isActive() { return this.enabled; }
  }

  class FakeRdpAllow {
    constructor() { this.enabled = false; }
    async enable() { record('rdpallow.enable'); this.enabled = true; }
    async disable() { record('rdpallow.disable'); this.enabled = false; }
    async isActive() { return this.enabled; }
    async reconcile() { record('rdpallow.reconcile'); this.enabled = false; return false; }
    async removeLegacyRule() { return false; }
  }

  class FakeDnsPolicy {
    async add() { record('dnspolicy.add'); return true; }
    async remove() { return true; }
    async removeAll() { return true; }
  }

  stubModule(coreFile('src/services/wireguard-native'), FakeWireGuardService);
  stubModule(coreFile('src/services/killswitch'), FakeKillSwitch);
  stubModule(coreFile('src/services/rdp-allow'), FakeRdpAllow);
  stubModule(coreFile('src/services/dns-policy'), FakeDnsPolicy);

  // Pro: one-time registry/cert-store cleanup of old versions — skipped.
  const migrationFile = require.resolve(path.join(APP_ROOT, 'src', 'services', 'rdp', 'rdp-trust-migration'));
  stubModule(migrationFile, {
    ...require(migrationFile),
    runRdpTrustMigration: async () => { record('rdpTrustMigration.skipped'); return 'skipped'; },
  });

  // ── Update key: throwaway test key instead of build/update-signing.pub ──
  const keyFile = coreFile('src/utils/update-public-key');
  const keyModule = require(keyFile);
  const testKey = env.GC_E2E_UPDATE_PUBKEY ? fs.readFileSync(env.GC_E2E_UPDATE_PUBKEY, 'utf8') : null;
  stubModule(keyFile, { ...keyModule, loadUpdatePublicKey: () => testKey });

  // ── Real updater, isolated download dir, instance exposed ──
  const updaterFile = coreFile('src/services/updater');
  const RealUpdater = require(updaterFile);
  class E2EUpdater extends RealUpdater {
    constructor(opts) {
      super({ ...opts, downloadDir: path.join(dir, 'updates') });
      state.updater = this;
    }
  }
  stubModule(updaterFile, E2EUpdater);

  // ── Electron side effects → recorder ──
  const { shell, Tray } = require('electron');
  shell.openPath = async (target) => {
    record('shell.openPath', { path: target, ...sha256File(target) });
    return '';
  };
  shell.openExternal = async (url) => { record('shell.openExternal', { url }); };

  const setContextMenu = Tray.prototype.setContextMenu;
  Tray.prototype.setContextMenu = function e2eSetContextMenu(menu) {
    state.trayMenu = menu;
    return setContextMenu.call(this, menu);
  };

  // Native message boxes (e.g. the support bundle confirmation): answered
  // from a queue the test fills (state.dialogAnswers); without a queued
  // answer the real dialog is shown.
  const { dialog } = require('electron');
  const realShowMessageBox = dialog.showMessageBox.bind(dialog);
  state.dialogAnswers = [];
  state.dialogs = [];
  dialog.showMessageBox = async (...args) => {
    if (!state.dialogAnswers.length) return realShowMessageBox(...args);
    const opts = args[args.length - 1] || {};
    state.dialogs.push({ message: opts.message, detail: opts.detail, buttons: opts.buttons });
    record('dialog.messageBox', { message: opts.message });
    return { response: state.dialogAnswers.shift(), checkboxChecked: false };
  };

  app.on('before-quit', () => record('app.before-quit'));

  state.record = record;
  state.trayLabels = () => (state.trayMenu ? state.trayMenu.items.map((i) => i.label) : []);
  state.clickTrayItem = (pattern) => {
    const re = new RegExp(pattern);
    const item = state.trayMenu && state.trayMenu.items.find((i) => re.test(i.label));
    if (!item) return false;
    item.click();
    return true;
  };

  globalThis.__gcE2E = state;
  record('e2e.installed', { pid: process.pid });
  return state;
}

module.exports = { install };
