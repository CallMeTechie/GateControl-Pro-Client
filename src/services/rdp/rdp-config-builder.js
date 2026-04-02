'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

/**
 * Generates temporary .rdp files from server-provided settings.
 * Each file is written to %TEMP% with a random suffix for parallel session support.
 */
class RdpConfigBuilder {
  constructor(log) {
    this.log = log;
  }

  /**
   * Build a .rdp file from route settings and return the file path.
   * @param {object} route - RDP route settings from the server
   * @returns {string} Absolute path to the generated .rdp file
   */
  build(route) {
    const lines = [];

    // ── Connection ─────────────────────────────────────────
    const host = route.external_hostname && route.access_mode !== 'internal'
      ? route.external_hostname
      : route.host;
    const port = route.external_port && route.access_mode !== 'internal'
      ? route.external_port
      : (route.port || 3389);

    lines.push(`full address:s:${host}:${port}`);
    lines.push(`server port:i:${port}`);

    // ── Authentication ────────────────────────────────────
    if (route.username) {
      const user = route.domain
        ? `${route.domain}\\${route.username}`
        : route.username;
      lines.push(`username:s:${user}`);
    }
    if (route.domain) {
      lines.push(`domain:s:${route.domain}`);
    }

    // NLA (Network Level Authentication)
    lines.push(`enablecredsspsupport:i:${route.nla_enabled !== false ? 1 : 0}`);
    lines.push(`authentication level:i:${route.nla_enabled !== false ? 2 : 0}`);

    // ── Display ───────────────────────────────────────────
    if (route.resolution_mode === 'fullscreen') {
      lines.push('screen mode id:i:2');
      lines.push('desktopwidth:i:0');
      lines.push('desktopheight:i:0');
      lines.push('use multimon:i:0');
      lines.push('smart sizing:i:0');
    } else if (route.resolution_mode === 'fixed') {
      lines.push('screen mode id:i:1');
      lines.push(`desktopwidth:i:${route.resolution_width || 1920}`);
      lines.push(`desktopheight:i:${route.resolution_height || 1080}`);
      lines.push('smart sizing:i:1');
    } else if (route.resolution_mode === 'dynamic') {
      lines.push('screen mode id:i:2');
      lines.push('dynamic resolution:i:1');
      lines.push('smart sizing:i:1');
    }

    // Multi-Monitor
    if (route.multi_monitor) {
      lines.push('use multimon:i:1');
    }

    // Color Depth
    const depthMap = { 15: 15, 16: 16, 24: 24, 32: 32 };
    lines.push(`session bpp:i:${depthMap[route.color_depth] || 32}`);

    // ── Redirects ─────────────────────────────────────────
    // Clipboard
    lines.push(`redirectclipboard:i:${route.redirect_clipboard !== false ? 1 : 0}`);

    // Printers
    lines.push(`redirectprinters:i:${route.redirect_printers ? 1 : 0}`);

    // Drives
    if (route.redirect_drives) {
      lines.push('redirectdrives:i:1');
      lines.push('drivestoredirect:s:*');
    } else {
      lines.push('redirectdrives:i:0');
    }

    // USB
    if (route.redirect_usb) {
      lines.push('devicestoredirect:s:*');
      lines.push('usbdevicestoredirect:s:*');
    }

    // Smart Card
    lines.push(`redirectsmartcards:i:${route.redirect_smartcard ? 1 : 0}`);

    // Audio
    const audioMap = { local: 0, remote: 1, off: 2 };
    lines.push(`audiomode:i:${audioMap[route.audio_mode] ?? 0}`);
    lines.push(`audiocapturemode:i:0`);

    // ── Performance ───────────────────────────────────────
    const profileMap = {
      modem:     1,
      broadband: 2,
      lan:       7,
      auto:      7,
    };
    lines.push(`connection type:i:${profileMap[route.network_profile] || 7}`);
    lines.push(`networkautodetect:i:${route.network_profile === 'auto' ? 1 : 0}`);

    // Visual effects
    if (route.disable_wallpaper) lines.push('disable wallpaper:i:1');
    if (route.disable_themes) lines.push('disable themes:i:1');
    if (route.disable_animations) {
      lines.push('disable menu anims:i:1');
      lines.push('disable cursor setting:i:1');
    }

    // Bandwidth limit
    if (route.bandwidth_limit) {
      lines.push(`bandwidthautodetect:i:0`);
    } else {
      lines.push(`bandwidthautodetect:i:1`);
    }

    // ── Admin Session ─────────────────────────────────────
    if (route.admin_session) {
      lines.push('administrative session:i:1');
    }

    // ── RemoteApp ─────────────────────────────────────────
    if (route.remote_app) {
      lines.push('remoteapplicationmode:i:1');
      lines.push(`remoteapplicationprogram:s:${route.remote_app}`);
      lines.push('remoteapplicationname:s:RemoteApp');
      lines.push('disableremoteappcapscheck:i:1');
    }

    // ── Start Program ─────────────────────────────────────
    if (route.start_program && !route.remote_app) {
      lines.push(`alternate shell:s:${route.start_program}`);
      lines.push('shell working directory:s:');
    }

    // ── Gateway ───────────────────────────────────────────
    if (route.gateway_host) {
      lines.push('gatewayusagemethod:i:1');
      lines.push(`gatewayhostname:s:${route.gateway_host}:${route.gateway_port || 443}`);
      lines.push('gatewaycredentialssource:i:0');
      lines.push('gatewayprofileusagemethod:i:1');
    } else {
      lines.push('gatewayusagemethod:i:0');
    }

    // ── General ───────────────────────────────────────────
    lines.push('autoreconnection enabled:i:1');
    lines.push('prompt for credentials:i:0');
    lines.push('negotiate security layer:i:1');
    lines.push('promptcredentialonce:i:1');

    // ── Write File ────────────────────────────────────────
    const suffix = crypto.randomBytes(8).toString('hex');
    const filePath = path.join(os.tmpdir(), `gatecontrol_rdp_${suffix}.rdp`);
    const content = lines.join('\r\n') + '\r\n';

    fs.writeFileSync(filePath, content, { encoding: 'utf-8' });
    this.log.info(`RDP config written: ${filePath}`);

    return filePath;
  }

  /**
   * Delete a temporary .rdp file.
   * @param {string} filePath - Path to the .rdp file
   */
  cleanup(filePath) {
    try {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        this.log.debug(`RDP config deleted: ${filePath}`);
      }
    } catch (err) {
      this.log.warn(`Failed to delete RDP config: ${filePath}`, err.message);
    }
  }

  /**
   * Delete ALL gatecontrol .rdp temp files (crash cleanup).
   */
  cleanupAll() {
    try {
      const tmpDir = os.tmpdir();
      const files = fs.readdirSync(tmpDir).filter(f => f.startsWith('gatecontrol_rdp_') && f.endsWith('.rdp'));
      for (const file of files) {
        try {
          fs.unlinkSync(path.join(tmpDir, file));
        } catch {}
      }
      if (files.length > 0) {
        this.log.info(`Cleaned up ${files.length} stale RDP config files`);
      }
    } catch (err) {
      this.log.warn('Failed to cleanup RDP configs:', err.message);
    }
  }
}

module.exports = RdpConfigBuilder;
