'use strict';

// „Namen im VPN“: Remote Desktop uses the name in the chosen zone
// (peer_fqdn_primary) only when a DNS rule of this app covers that zone,
// otherwise the name in the old zone (peer_fqdn).

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { pickPeerFqdn } = require('../src/services/rdp/rdp-peer-name');
const RdpConfigBuilder = require('../src/services/rdp/rdp-config-builder');
const DnsPolicy = require('@gatecontrol/client-core/src/services/dns-policy');

const route = (extra = {}) => ({
  host: '10.8.0.5', port: 3389,
  peer_hostname: 'laptop-buero',
  peer_fqdn: 'laptop-buero.gc.internal',
  peer_fqdn_primary: 'laptop-buero.vpn.example.com',
  ...extra,
});
const rulesFor = (...zones) => (name) => zones.some((zone) => name.endsWith('.' + zone));

describe('pickPeerFqdn', () => {
  it('the name in the chosen zone when a rule covers it', () => {
    assert.equal(pickPeerFqdn(route(), rulesFor('vpn.example.com', 'gc.internal')), 'laptop-buero.vpn.example.com');
  });

  it('the old name without a rule for the chosen zone', () => {
    assert.equal(pickPeerFqdn(route(), rulesFor('gc.internal')), 'laptop-buero.gc.internal');
    assert.equal(pickPeerFqdn(route(), () => false), 'laptop-buero.gc.internal');
  });

  it('an older server sends only peer_fqdn', () => {
    const old = route();
    delete old.peer_fqdn_primary;
    assert.equal(pickPeerFqdn(old, () => true), 'laptop-buero.gc.internal');
    assert.equal(pickPeerFqdn(route({ peer_fqdn_primary: null }), () => true), 'laptop-buero.gc.internal');
  });

  it('no name at all stays no name', () => {
    assert.equal(pickPeerFqdn(route({ peer_fqdn: null, peer_fqdn_primary: null }), () => true), null);
    assert.equal(pickPeerFqdn(route({ peer_fqdn: null }), () => true), null);
    assert.equal(pickPeerFqdn(null, () => true), null);
  });

  it('a primary that is no text, or a failing check, falls back to the old name', () => {
    assert.equal(pickPeerFqdn(route({ peer_fqdn_primary: { toString: () => 'x.vpn.example.com' } }), () => true), 'laptop-buero.gc.internal');
    assert.equal(pickPeerFqdn(route(), () => { throw new Error('no policy'); }), 'laptop-buero.gc.internal');
    assert.equal(pickPeerFqdn(route(), () => 'yes'), 'laptop-buero.gc.internal');
  });

  it('with the rules of the core: only names of a zone with an installed rule', async () => {
    const policy = new DnsPolicy({ info() {}, warn() {}, debug() {} });
    policy._runPs = async () => ({ err: null });
    const covers = (name) => policy.coversName(name);

    assert.equal(pickPeerFqdn(route(), covers), 'laptop-buero.gc.internal');
    await policy.sync(DnsPolicy.rulesFor({
      internalDns: { domain: 'gc.internal', server: '10.8.0.1', domains: ['vpn.example.com', 'gc.internal'], primary: 'vpn.example.com' },
    }), { force: true });
    assert.equal(pickPeerFqdn(route(), covers), 'laptop-buero.vpn.example.com');
    // not a DNS name: never into the .rdp file or the credential target
    assert.equal(pickPeerFqdn(route({ peer_fqdn_primary: 'x\r\nfull address:s:evil.vpn.example.com' }), covers), 'laptop-buero.gc.internal');
    // the admin went back to the old zone alone
    await policy.sync(DnsPolicy.rulesFor({ internalDns: { domain: 'gc.internal', server: '10.8.0.1', domains: ['gc.internal'], primary: 'gc.internal' } }));
    assert.equal(pickPeerFqdn(route({ peer_fqdn_primary: 'laptop-buero.gc.internal' }), covers), 'laptop-buero.gc.internal');
    assert.equal(pickPeerFqdn(route(), covers), 'laptop-buero.gc.internal');
  });
});

describe('.rdp file with the picked name', () => {
  const builder = new RdpConfigBuilder({ info() {}, warn() {}, error() {}, debug() {} });
  const files = [];
  after(() => { for (const f of files) { try { fs.unlinkSync(f); } catch { /* gone */ } } });
  const settings = {
    resolution_mode: 'fullscreen', color_depth: 32, nla_enabled: 1,
    redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0,
    redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local',
  };
  const build = async (data, covers) => {
    const file = await builder.build({ ...data, peer_fqdn: pickPeerFqdn(data, covers) });
    files.push(file);
    return fs.readFileSync(file, 'utf-8');
  };

  it('full address is the name in the chosen zone, the IP stays the alternate', async () => {
    const content = await build(route(settings), rulesFor('vpn.example.com', 'gc.internal'));
    assert.ok(content.includes('full address:s:laptop-buero.vpn.example.com:3389'));
    assert.ok(content.includes('alternate full address:s:10.8.0.5:3389'));
  });

  it('full address stays the old name without a rule for the chosen zone', async () => {
    const content = await build(route(settings), rulesFor('gc.internal'));
    assert.ok(content.includes('full address:s:laptop-buero.gc.internal:3389'));
    assert.ok(!content.includes('vpn.example.com'));
  });
});
