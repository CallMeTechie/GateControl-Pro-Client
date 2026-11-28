'use strict';

// Route → connect message of gc-rdp-host.exe (src/services/rdp/rdp-host-config.js): the same target as the
// .rdp file, credentials only in the message, the local choice only restricting, plain language for a disconnect.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const C = require('../src/services/rdp/rdp-host-config');

const base = {
  id: 7, name: 'Buchhaltung-PC', host: '10.0.0.21', port: 3389, access_mode: 'internal', peer_fqdn: 'buchhaltung.gc.internal',
  resolution_mode: 'dynamic', color_depth: 24, redirect_clipboard: 1, redirect_drives: 0, redirect_printers: 1, audio_mode: 'local',
  nla_enabled: 1, network_profile: 'lan',
};

describe('rdp-host-config: target', () => {
  it('internal: the FQDN, the IP as the fallback', () => {
    assert.deepEqual(C.targetOf(base), { server: 'buchhaltung.gc.internal', fallbackServer: '10.0.0.21', port: 3389 });
    assert.deepEqual(C.targetOf({ ...base, peer_fqdn: null }), { server: '10.0.0.21', fallbackServer: null, port: 3389 });
  });

  it('gateway and external: the server-resolved connect address, no FQDN', () => {
    assert.deepEqual(C.targetOf({ ...base, access_mode: 'gateway', connect_address: 'gw.invalid', connect_port: 13389 }), { server: 'gw.invalid', fallbackServer: null, port: 13389 });
    assert.deepEqual(C.targetOf({ ...base, access_mode: 'external', external_hostname: 'ext.invalid', external_port: 3390 }), { server: 'ext.invalid', fallbackServer: null, port: 3390 });
  });
});

describe('rdp-host-config: buildConnect', () => {
  it('carries the credentials, the effective settings and what the server permits', () => {
    const m = C.buildConnect(base, { username: 'anna', password: 'geheim', domain: 'BUERO' }, { drives: true, clipboard: false }, { theme: 'light', texts: { retry: 'R' } });
    assert.equal(m.type, 'connect');
    assert.equal(m.username, 'anna');
    assert.equal(m.domain, 'BUERO');
    assert.equal(m.password, 'geheim');
    assert.equal(m.promptForCredentials, false);
    assert.equal(m.server, 'buchhaltung.gc.internal');
    assert.equal(m.address, '10.0.0.21:3389');
    assert.equal(m.redirect.clipboard, false);
    assert.equal(m.redirect.drives, false, 'drives stay off: the server does not permit them');
    assert.equal(m.redirect.printers, true);
    assert.deepEqual(m.allow, { clipboard: true, drives: false });
    assert.equal(m.display.colorDepth, 24);
    assert.equal(m.display.mode, 'window');
    assert.equal(m.theme, 'light');
    assert.deepEqual(m.texts, { retry: 'R' });
    assert.equal(m.performance.connectionType, 7);
    assert.equal(m.gateway, null);
  });

  it('without a password the window asks (promptForCredentials)', () => {
    const m = C.buildConnect(base, { username: 'anna' }, {});
    assert.equal(m.password, null);
    assert.equal(m.promptForCredentials, true);
  });

  it('a gateway route shows no address of the server, an RD gateway is passed on', () => {
    const m = C.buildConnect({ ...base, access_mode: 'gateway', connect_address: 'gw.invalid', connect_port: 13389, gateway_host: 'rdg.invalid' }, {}, {});
    assert.equal(m.address, '');
    assert.equal(m.gateway_route, true);
    assert.deepEqual(m.gateway, { host: 'rdg.invalid', port: 443 });
  });

  it('redact never shows the password', () => {
    const m = C.buildConnect(base, { username: 'anna', password: 'geheim' }, {});
    const r = JSON.stringify(C.redact(m));
    assert.ok(!r.includes('geheim'));
    assert.ok(r.includes('"password":"***"'));
  });
});

describe('rdp-host-config: texts and disconnects', () => {
  const t = (k) => `T:${k}`;

  it('hostTexts takes the window texts of the app', () => {
    const x = C.hostTexts(t);
    assert.equal(x.retry, 'T:rdpWindow.host.retry');
    assert.equal(Object.keys(x).length, C.TEXT_KEYS.length);
    assert.deepEqual(C.hostTexts((k) => k), {});
  });

  it('describeDisconnect knows the usual reasons, else the control text', () => {
    assert.equal(C.describeDisconnect(3, 5, null, t).kind, 'replaced');
    assert.equal(C.describeDisconnect(3, 5, null, t).title, 'T:rdpWindow.err.replaced.title');
    assert.equal(C.describeDisconnect(3, 3, null, t).kind, 'idle');
    assert.equal(C.describeDisconnect(2055, 0, null, t).kind, 'logon');
    assert.equal(C.describeDisconnect(516, 0, null, t).kind, 'unreachable');
    assert.equal(C.describeDisconnect(2308, 0, null, t).kind, 'network');
    const g = C.describeDisconnect(4242, 0, ' Der Fehler ', t);
    assert.equal(g.kind, 'generic');
    assert.equal(g.text, 'Der Fehler');
  });

  it('endReasonOf for the audit', () => {
    assert.equal(C.endReasonOf({ byUser: true, reason: 1 }), 'normal');
    assert.equal(C.endReasonOf({ reason: 3, ext: 5 }), 'replaced');
    assert.equal(C.endReasonOf({ reason: 3, ext: 3 }), 'idle_timeout');
    assert.equal(C.endReasonOf({ reason: 3, ext: 0 }), 'server');
    assert.equal(C.endReasonOf({ reason: 516, ext: 0 }), 'error');
  });
});
