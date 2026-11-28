'use strict';

// „Auf diesem PC“ and the open mode of Remotedesktop (src/renderer/rdp-local-state.js, no DOM): what the server's
// route permits, a local choice only ever restricts it, and where "Verbinden" opens (setting, per host, per
// click, RemoteApp and a missing gc-rdp-host → Windows-Remotedesktop).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const L = require('../src/renderer/rdp-local-state');

const route = (x = {}) => ({ id: 7, name: 'Buchhaltung-PC', host: '10.0.0.21', port: 3389, ...x });

describe('rdp-local-state: allowed', () => {
  it('reads the server flags as 0/1, booleans and missing (clipboard on by default, the rest off)', () => {
    assert.deepEqual(L.allowed(route()), { clipboard: true, drives: false, printers: false, smartcards: false, multimon: false, audio: ['local', 'remote', 'off'], remoteApp: false });
    const a = L.allowed(route({ redirect_clipboard: 0, redirect_drives: 1, redirect_printers: true, redirect_smartcard: '1', multi_monitor: 1, audio_mode: 'remote', remote_app: '||calc' }));
    assert.equal(a.clipboard, false);
    assert.equal(a.drives, true);
    assert.equal(a.printers, true);
    assert.equal(a.smartcards, true);
    assert.equal(a.multimon, true);
    assert.deepEqual(a.audio, ['remote', 'off']);
    assert.equal(a.remoteApp, true);
  });

  it('audio "off" on the server leaves only off', () => {
    assert.deepEqual(L.allowed(route({ audio_mode: 'off' })).audio, ['off']);
    assert.deepEqual(L.allowed(route({ audio_mode: 'bogus' })).audio, ['local', 'remote', 'off']);
  });
});

describe('rdp-local-state: a local choice only restricts', () => {
  it('drops unknown keys and values', () => {
    assert.deepEqual(L.sanitizeLocal({ open: 'x', display: 'fullscreen', clipboard: 'yes', drives: false, evil: 1, audio: 'off' }), { display: 'fullscreen', drives: false, audio: 'off' });
    assert.deepEqual(L.sanitizeLocal(null), {});
  });

  it('cannot switch on drives, clipboard, all monitors or more audio than the server permits', () => {
    const r = route({ redirect_clipboard: 0, redirect_drives: 0, multi_monitor: 0, audio_mode: 'off' });
    assert.deepEqual(L.restrictLocal(r, { clipboard: true, drives: true, display: 'multimon', audio: 'local' }), {});
    const e = L.effective(r, { clipboard: true, drives: true, display: 'multimon', audio: 'local' });
    assert.equal(e.redirect.clipboard, false);
    assert.equal(e.redirect.drives, false);
    assert.equal(e.redirect.audio, 'off');
    assert.notEqual(e.display.mode, 'multimon');
    assert.deepEqual(e.allow, { clipboard: false, drives: false });
  });

  it('can switch off what the server permits', () => {
    const r = route({ redirect_clipboard: 1, redirect_drives: 1, audio_mode: 'local' });
    const e = L.effective(r, { clipboard: false, drives: false, audio: 'remote' });
    assert.equal(e.redirect.clipboard, false);
    assert.equal(e.redirect.drives, false);
    assert.equal(e.redirect.audio, 'remote');
    assert.deepEqual(e.allow, { clipboard: true, drives: true });
    // without a local choice: the server's values
    const s = L.effective(r, {});
    assert.equal(s.redirect.clipboard, true);
    assert.equal(s.redirect.drives, true);
    assert.equal(s.redirect.audio, 'local');
  });

  it('display and resolution follow the server unless chosen; fixed sizes from the route', () => {
    assert.equal(L.effective(route({ resolution_mode: 'fullscreen' }), {}).display.mode, 'fullscreen');
    assert.equal(L.effective(route({ resolution_mode: 'dynamic' }), {}).display.mode, 'window');
    assert.equal(L.effective(route({ resolution_mode: 'dynamic', multi_monitor: 1 }), {}).display.mode, 'multimon');
    assert.equal(L.effective(route({ resolution_mode: 'dynamic', multi_monitor: 1 }), { display: 'window' }).display.mode, 'window');
    const f = L.effective(route({ resolution_mode: 'fixed', resolution_width: 1600, resolution_height: 900 }), { display: 'window' }).display;
    assert.deepEqual(f, { mode: 'window', resolution: 'fixed', width: 1600, height: 900, colorDepth: 32 });
    assert.equal(L.effective(route({ resolution_mode: 'fixed' }), { resolution: 'dynamic' }).display.resolution, 'dynamic');
    assert.equal(L.effective(route(), { keyboard: 'never' }).keyboard, 'never');
    assert.equal(L.effective(route(), {}).keyboard, 'fullscreen');
  });
});

describe('rdp-local-state: openMode', () => {
  it('standard is the GateControl window', () => {
    assert.deepEqual(L.openMode({ route: route() }), { mode: 'window', reason: 'standard' });
  });

  it('the app setting, then the host, then the click decide', () => {
    assert.deepEqual(L.openMode({ global: 'mstsc', route: route() }), { mode: 'mstsc', reason: 'setting' });
    assert.deepEqual(L.openMode({ global: 'mstsc', local: { open: 'window' }, route: route() }), { mode: 'window', reason: 'host' });
    assert.deepEqual(L.openMode({ global: 'window', local: { open: 'mstsc' }, route: route() }), { mode: 'mstsc', reason: 'host' });
    assert.deepEqual(L.openMode({ via: 'window', global: 'mstsc', local: { open: 'mstsc' }, route: route() }), { mode: 'window', reason: 'choice' });
    assert.deepEqual(L.openMode({ via: 'mstsc', route: route() }), { mode: 'mstsc', reason: 'choice' });
    assert.deepEqual(L.openMode({ via: 'bogus', global: 'bogus', route: route() }), { mode: 'window', reason: 'standard' });
  });

  it('RemoteApp routes and a missing host fall back to Windows-Remotedesktop', () => {
    assert.deepEqual(L.openMode({ via: 'window', route: route({ remote_app: '||notepad' }) }), { mode: 'mstsc', reason: 'remoteapp' });
    assert.deepEqual(L.openMode({ route: route(), hostAvailable: false }), { mode: 'mstsc', reason: 'host-missing' });
    // asked for mstsc anyway: no fallback reason
    assert.deepEqual(L.openMode({ via: 'mstsc', route: route({ remote_app: 'x' }), hostAvailable: false }), { mode: 'mstsc', reason: 'choice' });
  });
});
