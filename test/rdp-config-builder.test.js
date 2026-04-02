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

  it('generates .rdp file with basic settings', () => {
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
    const rdpPath = builder.build(route);
    tempFiles.push(rdpPath);

    assert.ok(fs.existsSync(rdpPath));
    assert.ok(rdpPath.endsWith('.rdp'));

    const content = fs.readFileSync(rdpPath, 'utf-8');
    assert.ok(content.includes('full address:s:192.168.1.50:3389'));
    assert.ok(content.includes('session bpp:i:32'));
    assert.ok(content.includes('redirectclipboard:i:1'));
    assert.ok(content.includes('redirectprinters:i:0'));
  });

  it('handles custom port', () => {
    const route = { host: '10.0.0.1', port: 3392, resolution_mode: 'fullscreen', color_depth: 32, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = builder.build(route);
    tempFiles.push(rdpPath);
    const content = fs.readFileSync(rdpPath, 'utf-8');
    assert.ok(content.includes('full address:s:10.0.0.1:3392'));
  });

  it('handles fixed resolution', () => {
    const route = { host: '10.0.0.1', port: 3389, resolution_mode: 'fixed', resolution_width: 1920, resolution_height: 1080, color_depth: 24, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = builder.build(route);
    tempFiles.push(rdpPath);
    const content = fs.readFileSync(rdpPath, 'utf-8');
    assert.ok(content.includes('desktopwidth:i:1920'));
    assert.ok(content.includes('desktopheight:i:1080'));
    assert.ok(content.includes('session bpp:i:24'));
  });

  it('handles multi-monitor', () => {
    const route = { host: '10.0.0.1', port: 3389, resolution_mode: 'fullscreen', color_depth: 32, multi_monitor: 1, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = builder.build(route);
    tempFiles.push(rdpPath);
    const content = fs.readFileSync(rdpPath, 'utf-8');
    assert.ok(content.includes('use multimon:i:1'));
  });

  it('handles admin session', () => {
    const route = { host: '10.0.0.1', port: 3389, resolution_mode: 'fullscreen', color_depth: 32, admin_session: 1, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = builder.build(route);
    tempFiles.push(rdpPath);
    const content = fs.readFileSync(rdpPath, 'utf-8');
    assert.ok(content.includes('administrative session:i:1'));
  });

  it('handles gateway', () => {
    const route = { host: '10.0.0.1', port: 3389, gateway_host: 'gw.example.com', gateway_port: 443, resolution_mode: 'fullscreen', color_depth: 32, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = builder.build(route);
    tempFiles.push(rdpPath);
    const content = fs.readFileSync(rdpPath, 'utf-8');
    assert.ok(content.includes('gatewayhostname:s:gw.example.com'));
  });

  it('cleanup removes temp files', () => {
    const route = { host: '10.0.0.1', port: 3389, resolution_mode: 'fullscreen', color_depth: 32, nla_enabled: 1, redirect_clipboard: 1, redirect_printers: 0, redirect_drives: 0, redirect_usb: 0, redirect_smartcard: 0, audio_mode: 'local' };
    const rdpPath = builder.build(route);
    assert.ok(fs.existsSync(rdpPath));
    builder.cleanup(rdpPath);
    assert.ok(!fs.existsSync(rdpPath));
  });
});
