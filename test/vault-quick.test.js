'use strict';

// The Vault quick search window (src/main/vault-quick.js) with fake Electron
// objects: Strg+Alt+P only while the server offers Vault, a frameless
// always-on-top window with its own preload and the main window's isolation,
// toggle / hide on blur / Esc from its own page only, and clean up on quit.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');

const { setupVaultQuick, ACCELERATOR } = require('../src/main/vault-quick');

function fakes() {
  const shortcuts = new Map();
  const ipc = new EventEmitter();
  const windows = [];
  class FakeWindow extends EventEmitter {
    constructor(opts) {
      super();
      this.opts = opts;
      this.visible = false;
      this.destroyed = false;
      this.sent = [];
      this.loaded = null;
      this.onTop = null;
      this.protected = false;
      this.bounds = null;
      this.webContents = Object.assign(new EventEmitter(), {
        send: (ch, p) => this.sent.push([ch, p]),
        isLoading: () => false,
        setWindowOpenHandler: (fn) => { this.openHandler = fn; },
      });
      windows.push(this);
    }
    loadFile(f) { this.loaded = f; }
    setAlwaysOnTop(on, level) { this.onTop = [on, level]; }
    setContentProtection(on) { this.protected = on; }
    setBounds(b) { this.bounds = b; }
    setBackgroundColor(c) { this.bg = c; }
    show() { this.visible = true; }
    focus() {}
    hide() { this.visible = false; }
    isVisible() { return this.visible; }
    isDestroyed() { return this.destroyed; }
    destroy() { this.destroyed = true; }
  }
  const vault = Object.assign(new EventEmitter(), { st: { state: 'unknown' }, status() { return this.st; } });
  const o = {
    BrowserWindow: FakeWindow,
    globalShortcut: {
      register: (acc, fn) => { if (shortcuts.has(acc)) return false; shortcuts.set(acc, fn); return true; },
      unregister: (acc) => shortcuts.delete(acc),
    },
    screen: {
      getCursorScreenPoint: () => ({ x: 2500, y: 300 }),
      getDisplayNearestPoint: () => ({ workArea: { x: 1920, y: 0, width: 1920, height: 1040 } }),
    },
    ipcMain: ipc,
    vault,
    preload: '/app/src/main/vault-quick-preload.js',
    html: '/app/src/renderer/vault-quick.html',
    getTheme: () => 'light',
    getLocale: () => 'en',
    log: { info() {}, warn() {}, debug() {}, error() {} },
  };
  return { o, shortcuts, ipc, windows, vault };
}

describe('Vault quick search window', () => {
  it('Strg+Alt+P only while the server offers Vault', () => {
    const { o, shortcuts, vault } = fakes();
    const q = setupVaultQuick(o);
    q.start();
    assert.equal(shortcuts.size, 0, 'not before the plugin is known');
    vault.st = { state: 'available' };
    vault.emit('state', vault.st);
    assert.ok(shortcuts.has(ACCELERATOR));
    assert.equal(ACCELERATOR, 'Control+Alt+P');
    vault.emit('state', { state: 'unavailable' });
    assert.equal(shortcuts.size, 0, 'released when the plugin goes');
    vault.emit('state', { state: 'available' });
    q.stop();
    assert.equal(shortcuts.size, 0, 'released on quit');
    assert.equal(vault.listenerCount('state'), 0);
  });

  it('a shortcut taken by another program is not an error', () => {
    const { o, shortcuts, vault } = fakes();
    shortcuts.set(ACCELERATOR, () => {});
    vault.st = { state: 'available' };
    const q = setupVaultQuick(o);
    q.start();
    assert.equal(q.isRegistered(), false);
  });

  it('opens a frameless, always-on-top, isolated window on the cursor\'s screen and toggles', () => {
    const { o, shortcuts, windows, vault } = fakes();
    vault.st = { state: 'available' };
    const q = setupVaultQuick(o);
    q.start();
    shortcuts.get(ACCELERATOR)();
    assert.equal(windows.length, 1);
    const w = windows[0];
    assert.equal(w.opts.frame, false);
    assert.equal(w.opts.alwaysOnTop, true);
    assert.equal(w.opts.skipTaskbar, true);
    assert.equal(w.opts.webPreferences.contextIsolation, true);
    assert.equal(w.opts.webPreferences.nodeIntegration, false);
    assert.equal(w.opts.webPreferences.sandbox, false, 'like the main window');
    assert.equal(w.opts.webPreferences.preload, o.preload);
    assert.equal(w.loaded, o.html);
    assert.equal(w.protected, true, 'hidden from screen capture');
    assert.deepEqual(w.openHandler(), { action: 'deny' });
    assert.ok(w.visible);
    assert.deepEqual(w.sent.at(-1), ['vault-quick:show', { theme: 'light', locale: 'en' }]);
    assert.equal(w.bounds.x, 1920 + (1920 - 640) / 2, 'centred on the screen with the cursor');
    shortcuts.get(ACCELERATOR)();
    assert.equal(w.visible, false, 'the shortcut again closes it');
    assert.deepEqual(w.sent.at(-1), ['vault-quick:hide', undefined]);
    shortcuts.get(ACCELERATOR)();
    assert.equal(windows.length, 1, 'the window is kept');
    w.emit('blur');
    assert.equal(w.visible, false, 'hides when another window gets the focus');
  });

  it('Esc from its own page hides it; other pages cannot; closing only hides', () => {
    const { o, ipc, windows, vault } = fakes();
    vault.st = { state: 'available' };
    const q = setupVaultQuick(o);
    q.start();
    q.show();
    const w = windows[0];
    ipc.emit('vault-quick:hide', { sender: {} });
    assert.ok(w.visible, 'another window cannot hide it');
    ipc.emit('vault-quick:hide', { sender: w.webContents });
    assert.equal(w.visible, false);
    q.show();
    let prevented = false;
    w.emit('close', { preventDefault: () => { prevented = true; } });
    assert.ok(prevented);
    assert.equal(w.visible, false);
    q.stop();
    assert.ok(w.destroyed);
    assert.equal(ipc.listenerCount('vault-quick:hide'), 0);
  });
});
