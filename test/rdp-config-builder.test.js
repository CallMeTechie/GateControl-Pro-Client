'use strict';

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const RdpConfigBuilder = require('../src/services/rdp/rdp-config-builder');

describe('RdpConfigBuilder', () => {
  const builder = new RdpConfigBuilder({ info: () => {}, warn: () => {}, error: () => {}, debug: () => {} });
  const tempFiles = [];

  after(() => {
    for (const f of tempFiles) {
      try { fs.unlinkSync(f); } catch {}
    }
  });

  it('generates .rdp file with basic settings', async () => {
    const route = {
      host: '192.168.1.50',
      port: 3389,
      resolution_mode: 'fullscreen',
      color_depth: 32,
      nla_enabled: 1,
      redirect_clipboard: 1,
      redirect_printers: 0,
      redirect_drives: 0,
      redirect_usb: 0,
      redirect_smartcard: 0,
      audio_mode: 'local',
    };
    const rdpPath = await builder.build(route);
    tempFiles.push(rdpPath);

    assert.ok(fs.existsSync(rdpPath));
    assert.ok(rdpPath.endsWith('.rdp'));

    const content = fs.readFileSync(rdpPath, 'utf-8');
    assert.ok(content.includes('full address:s:192.168.1.50:3389'));
    assert.ok(content.includes('session bpp:i:32'));
    assert.ok(content.includes('redirectclipboard:i:1'));
    assert.ok(content.includes('redirectprinters:i:0'));
  });

  it('handles custom port', async () => {
    const route = { host: '10.0.0.1', port: 3392, resolution_mode: 'fullscreen', color_depth: 32, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = await builder.build(route);
    tempFiles.push(rdpPath);
    const content = fs.readFileSync(rdpPath, 'utf-8');
    assert.ok(content.includes('full address:s:10.0.0.1:3392'));
  });

  it('handles fixed resolution', async () => {
    const route = { host: '10.0.0.1', port: 3389, resolution_mode: 'fixed', resolution_width: 1920, resolution_height: 1080, color_depth: 24, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = await builder.build(route);
    tempFiles.push(rdpPath);
    const content = fs.readFileSync(rdpPath, 'utf-8');
    assert.ok(content.includes('desktopwidth:i:1920'));
    assert.ok(content.includes('desktopheight:i:1080'));
    assert.ok(content.includes('session bpp:i:24'));
  });

  it('handles multi-monitor', async () => {
    const route = { host: '10.0.0.1', port: 3389, resolution_mode: 'fullscreen', color_depth: 32, multi_monitor: 1, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = await builder.build(route);
    tempFiles.push(rdpPath);
    const content = fs.readFileSync(rdpPath, 'utf-8');
    assert.ok(content.includes('use multimon:i:1'));
  });

  it('handles admin session', async () => {
    const route = { host: '10.0.0.1', port: 3389, resolution_mode: 'fullscreen', color_depth: 32, admin_session: 1, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = await builder.build(route);
    tempFiles.push(rdpPath);
    const content = fs.readFileSync(rdpPath, 'utf-8');
    assert.ok(content.includes('administrative session:i:1'));
  });

  it('handles gateway', async () => {
    const route = { host: '10.0.0.1', port: 3389, gateway_host: 'gw.example.com', gateway_port: 443, resolution_mode: 'fullscreen', color_depth: 32, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = await builder.build(route);
    tempFiles.push(rdpPath);
    const content = fs.readFileSync(rdpPath, 'utf-8');
    assert.ok(content.includes('gatewayhostname:s:gw.example.com'));
  });

  it('uses peer FQDN when available (internal_dns feature)', async () => {
    const route = {
      host: '10.8.0.5', port: 3389, peer_fqdn: 'desktop-8f36qk8.gc.internal',
      resolution_mode: 'fullscreen', color_depth: 32, nla_enabled: 1,
      redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0,
      redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local',
    };
    const rdpPath = await builder.build(route);
    tempFiles.push(rdpPath);
    const content = fs.readFileSync(rdpPath, 'utf-8');
    // primary address is the FQDN
    assert.ok(content.includes('full address:s:desktop-8f36qk8.gc.internal:3389'),
      'expected FQDN as primary address');
    // IP is the alternate / fallback
    assert.ok(content.includes('alternate full address:s:10.8.0.5:3389'),
      'expected IP as alternate fallback');
  });

  it('ignores FQDN when access_mode is external', async () => {
    const route = {
      host: '10.8.0.5', port: 3389, peer_fqdn: 'desktop.gc.internal',
      external_hostname: 'rdp.example.com', external_port: 3389,
      access_mode: 'external',
      resolution_mode: 'fullscreen', color_depth: 32, nla_enabled: 1,
      redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0,
      redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local',
    };
    const rdpPath = await builder.build(route);
    tempFiles.push(rdpPath);
    const content = fs.readFileSync(rdpPath, 'utf-8');
    assert.ok(content.includes('full address:s:rdp.example.com:3389'));
    assert.ok(!content.includes('desktop.gc.internal'),
      'internal FQDN must not leak into external-mode .rdp');
  });

  it('gateway route uses connect_address:connect_port as full address', async () => {
    const rdpPath = await builder.build({
      name: 'gw', access_mode: 'gateway',
      host: '192.168.2.100', port: 3389,
      connect_address: 'gc.example.com', connect_port: 13389,
    });
    tempFiles.push(rdpPath);
    const content = fs.readFileSync(rdpPath, 'utf8');
    assert.match(content, /full address:s:gc\.example\.com:13389/);
  });

  it('cleanup removes temp files', async () => {
    const route = { host: '10.0.0.1', port: 3389, resolution_mode: 'fullscreen', color_depth: 32, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = await builder.build(route);
    assert.ok(fs.existsSync(rdpPath));
    builder.cleanup(rdpPath);
    assert.ok(!fs.existsSync(rdpPath));
  });

  it('invokes signer.sign() after writing the file', async () => {
    const calls = [];
    const fakeSigner = {
      sign: async (filePath) => { calls.push(filePath); return true; },
    };
    const signedBuilder = new RdpConfigBuilder(
      { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
      fakeSigner,
    );
    const route = { host: '10.0.0.2', port: 3389, resolution_mode: 'fullscreen', color_depth: 32, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = await signedBuilder.build(route);
    tempFiles.push(rdpPath);

    assert.equal(calls.length, 1, 'signer.sign should be called exactly once');
    assert.equal(calls[0], rdpPath, 'signer.sign should receive the generated file path');
  });

  it('still returns the file when signer.sign rejects (graceful fallback)', async () => {
    const failingSigner = { sign: async () => { throw new Error('rdpsign explosion'); } };
    const signedBuilder = new RdpConfigBuilder(
      { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
      failingSigner,
    );
    const route = { host: '10.0.0.3', port: 3389, resolution_mode: 'fullscreen', color_depth: 32, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = await signedBuilder.build(route);
    tempFiles.push(rdpPath);
    assert.ok(fs.existsSync(rdpPath), 'connect must still work even when signing fails');
  });
});
