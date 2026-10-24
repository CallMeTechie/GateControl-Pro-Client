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
  ipc.handlers = new Map();
  ipc.handle = (ch, fn) => { if (ipc.handlers.has(ch)) throw new Error(`second handler for ${ch}`); ipc.handlers.set(ch, fn); };
  ipc.removeHandler = (ch) => ipc.handlers.delete(ch);
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

  it('auto-lock "immediately": locks after the quick search hides while the main window is not on screen', async () => {
    const { o, shortcuts, vault } = fakes();
    vault.st = { state: 'available' };
    let minutes = 0;
    let mainVisible = false;
    let locks = 0;
    vault.settings = () => ({ autoLockMinutes: minutes });
    vault.windowHidden = () => { locks++; };
    const q = setupVaultQuick({ ...o, hiddenLockMs: 20, isMainVisible: () => mainVisible });
    q.start();
    const toggle = shortcuts.get(ACCELERATOR);
    toggle(); toggle();
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(locks, 1, 'hidden, main window in the tray: locks');
    toggle(); toggle(); toggle();
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(locks, 1, 'shown again before the time: no lock');
    toggle();
    mainVisible = true;
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(locks, 1, 'main window on screen: it decides');
    mainVisible = false;
    minutes = 5;
    toggle(); toggle();
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(locks, 1, 'other auto-lock settings use their own timer');
    q.stop();
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

  it('Windows Hello from its own page: steps back for the dialog (not on top, no hide on blur), then to the front', async () => {
    const { o, ipc, windows, vault } = fakes();
    const q = setupVaultQuick(o);
    q.start();
    vault.st = { state: 'available' };
    vault.emit('state', vault.st);
    q.show();
    const w = windows[0];
    const seen = [];
    let release;
    vault.unlockHello = () => {
      seen.push([w.onTop[0], q.helloPrompting()]);
      w.emit('blur');
      return new Promise((r) => { release = r; });
    };
    const handler = ipc.handlers.get('vault-quick:hello');
    assert.deepEqual(await handler({ sender: {} }), { ok: false, code: 'invalid' }, 'only the quick window itself');
    const p = handler({ sender: w.webContents });
    assert.deepEqual(seen, [[false, true]]);
    assert.equal(w.visible, true, 'the Hello dialog taking the focus does not hide the window');
    assert.deepEqual(await handler({ sender: w.webContents }), { ok: false, code: 'busy' });
    release({ unlocked: true });
    assert.deepEqual(await p, { ok: true, status: { unlocked: true } });
    assert.deepEqual(w.onTop, [true, 'pop-up-menu']);
    assert.equal(q.helloPrompting(), false);
    vault.unlockHello = async () => { throw Object.assign(new Error('x'), { code: 'hello_cancelled' }); };
    assert.deepEqual(await handler({ sender: w.webContents }), { ok: false, code: 'hello_cancelled' });
    w.emit('blur');
    assert.equal(w.visible, false, 'blur hides again afterwards');
    q.stop();
    assert.equal(ipc.handlers.has('vault-quick:hello'), false);
  });
});
