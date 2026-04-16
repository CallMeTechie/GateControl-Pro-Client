'use strict';

const { execFile } = require('child_process');
const net = require('net');
const path = require('path');
const EventEmitter = require('events');

const RdpConfigBuilder = require('./rdp-config-builder');
const RdpCredentialHandler = require('./rdp-credential');
const RdpMonitor = require('./rdp-monitor');

/**
 * RDP Manager -- Orchestrates the full RDP connection lifecycle.
 *
 * Lifecycle:
 *   1. Pre-flight checks (VPN active, TCP reachability, maintenance, expiry)
 *   2. Credential retrieval (E2EE decryption or password prompt)
 *   3. .rdp file generation
 *   4. cmdkey credential storage
 *   5. mstsc.exe launch
 *   6. Process monitoring + heartbeats
 *   7. Cleanup on exit (credentials, temp files, audit)
 *
 * Events:
 *   'session-start'   - { routeId, pid }
 *   'session-end'     - { routeId, pid, duration, exitCode }
 *   'session-error'   - { routeId, error }
 *   'progress'        - { routeId, step, status }
 *   'services-update' - rdpServices[]
 */
class RdpManager extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClientPro instance
   * @param {object} opts.log - electron-log instance
   * @param {object} [opts.store] - electron-store instance for config
   * @param {function} opts.getTunnelState - Returns current tunnel state { connected }
   * @param {function} opts.getPeerInfo - Returns peer info { expiresAt }
   */
  constructor({ apiClient, log, store, getTunnelState, getPeerInfo }) {
    super();
    this.api = apiClient;
    this.log = log;
    this.store = store;
    this.getTunnelState = getTunnelState;
    this.getPeerInfo = getPeerInfo;
    this.requireE2ee = store?.get('security.requireE2ee', false) || false;

    this.configBuilder = new RdpConfigBuilder(log);
    this.credentialHandler = new RdpCredentialHandler(log);
    this.monitor = new RdpMonitor({ apiClient, log });

    // Active sessions: Map<routeId, { pid, rdpFile, host, startTime, process }>
    this.activeSessions = new Map();

    // Cached RDP services list
    this.rdpServices = [];

    // Status polling
    this._statusPollInterval = null;
    this._statusPollMs = 30000; // 30 seconds

    // Forward monitor events
    this.monitor.on('session-timeout', (data) => {
      this.log.warn(`RDP session timeout for route ${data.routeId}`);
      this._handleSessionTimeout(data);
    });
  }

  // ══════════════════════════════════════════════════════════
  //  PUBLIC API
  // ══════════════════════════════════════════════════════════

  /**
   * Fetch and cache RDP services from server.
   * @returns {Array} List of RDP services
   */
  async refreshServices() {
    try {
      this.rdpServices = await this.api.getRdpServices();
      this.emit('services-update', this.rdpServices);
      return this.rdpServices;
    } catch (err) {
      this.log.warn('Failed to refresh RDP services:', err.message);
      return this.rdpServices;
    }
  }

  /**
   * Get cached RDP services.
   * @returns {Array}
   */
  getServices() {
    return this.rdpServices;
  }

  /**
   * Start periodic polling of RDP host status.
   * Fetches bulk status and merges into cached services.
   * Emits 'services-update' only when status changes.
   */
  startStatusPolling() {
    this.stopStatusPolling();
    this.log.info(`RDP status polling started (${this._statusPollMs / 1000}s interval)`);

    this._statusPollInterval = setInterval(async () => {
      try {
        const statuses = await this.api.getRdpBulkStatus();
        if (!statuses || typeof statuses !== 'object') return;

        let changed = false;
        for (const svc of this.rdpServices) {
          const newStatus = statuses[svc.id];
          if (!newStatus) continue;

          const wasOnline = svc.status?.online;
          const isOnline = newStatus.online;

          if (wasOnline !== isOnline) {
            svc.status = { ...svc.status, ...newStatus };
            changed = true;
            this.log.info(`RDP route ${svc.id} (${svc.name}): ${wasOnline ? 'online' : 'offline'} → ${isOnline ? 'online' : 'offline'}`);
          }
        }

        if (changed) {
          this.emit('services-update', this.rdpServices);
        }
      } catch (err) {
        this.log.debug('RDP status poll failed:', err.message);
      }
    }, this._statusPollMs);
  }

  /**
   * Stop periodic status polling.
   */
  stopStatusPolling() {
    if (this._statusPollInterval) {
      clearInterval(this._statusPollInterval);
      this._statusPollInterval = null;
      this.log.debug('RDP status polling stopped');
    }
  }

  /**
   * Connect to an RDP host. Full lifecycle orchestration.
   *
   * @param {number} routeId - RDP route ID
   * @param {object} [opts] - Optional overrides
   * @param {string} [opts.password] - Manual password (for user_only credential mode)
   * @param {boolean} [opts.forceMaintenanceBypass] - Connect despite maintenance window
   * @returns {Promise<{ success: boolean, error?: string, needsPassword?: boolean, maintenanceWarning?: object }>}
   */
  async connect(routeId, opts = {}) {
    // Re-read E2EE enforcement setting (may have changed since construction)
    this.requireE2ee = this.store?.get('security.requireE2ee', false) || false;
    this.log.info(`RDP connect requested for route ${routeId} (requireE2ee=${this.requireE2ee})`);

    try {
      // ── Step 1: Pre-Flight Checks ───────────────────────
      this._emitProgress(routeId, 'preflight', 'active');

      // 1a. VPN tunnel must be active
      const tunnelState = this.getTunnelState();
      if (!tunnelState || !tunnelState.connected) {
        this._emitProgress(routeId, 'preflight', 'error');
        return { success: false, error: 'VPN-Tunnel ist nicht aktiv. Bitte zuerst verbinden.' };
      }
      this._emitProgress(routeId, 'vpn-check', 'done');

      // 1b. Get connection details from server (with E2EE)
      this.log.info(`Fetching connection data for route ${routeId}...`);
      const { publicKey: ecdhPublicKey } = this.credentialHandler.generateKeyPair();
      const connectData = await this.api.getRdpConnect(routeId, { ecdhPublicKey });
      this.log.info(`Connection data received: host=${connectData?.host}, port=${connectData?.port}, mode=${connectData?.credential_mode}, e2ee=${!!connectData?.credentials_e2ee}`);
      if (!connectData || !connectData.host) {
        this.log.error('No connection data received from server:', JSON.stringify(connectData));
        return { success: false, error: 'Keine Verbindungsdaten vom Server erhalten.' };
      }

      const route = connectData;
      const host = route.host;
      const port = route.port || 3389;
      // credTarget = what we hand to cmdkey /generic. If the peer has an
      // internal FQDN, use that — matches the CredSSP SPN the server
      // presents via its cert CN and avoids the "credentials did not
      // work" dialog on hosts whose cert CN differs from the VPN IP.
      const credTarget = (route.access_mode !== 'external' && route.peer_fqdn) ? route.peer_fqdn : host;
      this.log.info(`RDP target: ${host}:${port}${credTarget !== host ? ` (credSSP target: ${credTarget})` : ''}`);

      // 1c. Maintenance window check
      if (route.maintenance_enabled && route.maintenance_active && !opts.forceMaintenanceBypass) {
        this._emitProgress(routeId, 'maintenance', 'warning');
        return {
          success: false,
          maintenanceWarning: {
            schedule: route.maintenance_schedule,
            active: true,
          },
        };
      }

      // 1d. Peer expiry check (warn if < 3 days)
      try {
        const peerInfo = await this.getPeerInfo();
        if (peerInfo?.expiresAt) {
          const daysLeft = (new Date(peerInfo.expiresAt) - Date.now()) / (1000 * 60 * 60 * 24);
          if (daysLeft < 3 && daysLeft > 0) {
            this.log.warn(`Peer expires in ${Math.round(daysLeft)} days`);
            // Non-blocking warning -- proceed anyway
          } else if (daysLeft <= 0) {
            return { success: false, error: 'Peer ist abgelaufen. Bitte Konfiguration erneuern.' };
          }
        }
      } catch {}

      // 1e. TCP port check
      this.log.info(`TCP check: ${host}:${port}...`);
      const reachable = await this._tcpCheck(host, port, 5000);
      this.log.info(`TCP check result: ${reachable ? 'reachable' : 'unreachable'}`);

      if (!reachable) {
        // Check if WoL is available
        if (route.wol_enabled && route.wol_mac_address) {
          this._emitProgress(routeId, 'wol', 'active');
          const wolResult = await this._performWol(routeId, host, port);
          if (!wolResult) {
            this._emitProgress(routeId, 'wol', 'error');
            return { success: false, error: `Host ${host}:${port} ist nicht erreichbar. Wake-on-LAN fehlgeschlagen.` };
          }
          this._emitProgress(routeId, 'wol', 'done');
        } else {
          this._emitProgress(routeId, 'tcp-check', 'error');
          return { success: false, error: `Host ${host}:${port} ist nicht erreichbar.` };
        }
      }
      this._emitProgress(routeId, 'tcp-check', 'done');

      // ── Step 2: Credentials ─────────────────────────────
      this._emitProgress(routeId, 'credentials', 'active');

      let username = null;
      let password = null;
      let domain = null;

      if (route.credential_mode === 'full') {
        if (route.credentials_e2ee) {
          // E2EE path: decrypt ECDH-encrypted credential blob
          try {
            const creds = this.credentialHandler.decryptCredentials(route.credentials_e2ee);
            username = creds.username;
            password = creds.password;
            domain = creds.domain || null;
            this.log.info('Credentials decrypted successfully (ECDH E2EE)');
            this._emitProgress(routeId, 'credentials', 'done');
          } catch (err) {
            this.log.error('E2EE credential decryption failed:', err.message);
            if (this.requireE2ee) {
              this._emitProgress(routeId, 'credentials', 'error');
              return { success: false, error: 'E2EE required but decryption failed.' };
            }
            this._emitProgress(routeId, 'credentials', 'fallback');
          }
        } else if (route.username && route.password) {
          // Plaintext fallback (server did not receive ecdhPublicKey or E2EE failed)
          if (this.requireE2ee) {
            this.log.error('E2EE enforcement: rejecting plaintext credentials');
            this._emitProgress(routeId, 'credentials', 'error');
            return { success: false, error: 'E2EE required but server sent plaintext credentials.' };
          }
          username = route.username;
          password = route.password;
          domain = route.domain || null;
          this.log.warn('Credentials received as plain-text (E2EE unavailable)');
          this._emitProgress(routeId, 'credentials', 'done');
        } else {
          this.log.warn('credential_mode is full but no credentials received from server');
          this._emitProgress(routeId, 'credentials', 'fallback');
        }
      } else if (route.credential_mode === 'user_only') {
        // user_only: username may arrive via E2EE or plaintext
        if (route.credentials_e2ee) {
          try {
            const creds = this.credentialHandler.decryptCredentials(route.credentials_e2ee);
            username = creds.username;
            domain = creds.domain || null;
          } catch (err) {
            this.log.warn('E2EE decryption failed for user_only:', err.message);
            if (this.requireE2ee) {
              this._emitProgress(routeId, 'credentials', 'error');
              return { success: false, error: 'E2EE required but decryption failed.' };
            }
            this.log.warn('Falling back to plaintext username');
            username = route.username;
            domain = route.domain;
          }
        } else {
          if (this.requireE2ee) {
            this.log.error('E2EE enforcement: rejecting plaintext username');
            this._emitProgress(routeId, 'credentials', 'error');
            return { success: false, error: 'E2EE required but server sent plaintext credentials.' };
          }
          username = route.username;
          domain = route.domain;
        }

        if (!opts.password) {
          // Need password from user
          this._emitProgress(routeId, 'credentials', 'needs-password');
          return {
            success: false,
            needsPassword: true,
            username: domain ? `${domain}\\${username}` : username,
          };
        }
        password = opts.password;
        this._emitProgress(routeId, 'credentials', 'done');
      } else {
        // credential_mode: 'none' -- mstsc will prompt
        this._emitProgress(routeId, 'credentials', 'skip');
      }

      // ── Step 3: Generate .rdp file ──────────────────────
      this._emitProgress(routeId, 'rdp-file', 'active');
      this.log.info('Building .rdp file...');
      const rdpFile = this.configBuilder.build(route);
      this.log.info(`RDP file created: ${rdpFile}`);
      this._emitProgress(routeId, 'rdp-file', 'done');

      // ── Step 4: Store credentials via cmdkey ────────────
      if (username && password) {
        this._emitProgress(routeId, 'cmdkey', 'active');
        try {
          this.credentialHandler.storeCredentials(credTarget, username, password, domain);
          // When using FQDN, ALSO store under IP as a fallback — some
          // scenarios (e.g. first connect before DNS propagation) may
          // have mstsc fall back to the alternate address.
          if (credTarget !== host) {
            try { this.credentialHandler.storeCredentials(host, username, password, domain); } catch {}
          }
          this._emitProgress(routeId, 'cmdkey', 'done');
        } catch (err) {
          this.log.error('cmdkey failed:', err.message);
          // Continue anyway -- mstsc may still prompt
        }
      }

      // Clear password from memory
      password = null;

      // ── Step 4b: Suppress RDP "unknown publisher" warning ──
      await this._ensureRdpRegistryKeys();

      // ── Step 5: Start mstsc.exe ─────────────────────────
      this._emitProgress(routeId, 'mstsc', 'active');

      // Notify server: session start (audit)
      let sessionData;
      try {
        sessionData = await this.api.startRdpSession(routeId);
      } catch (err) {
        this.log.warn('Failed to register session start:', err.message);
      }

      // Launch mstsc.exe
      this.log.info(`Launching mstsc.exe with file: ${rdpFile}`);
      const mstscArgs = [rdpFile];
      if (route.admin_session) {
        mstscArgs.push('/admin');
      }

      return new Promise((resolve) => {
        const startTime = Date.now();

        const proc = execFile('mstsc.exe', mstscArgs, {
          windowsHide: false,
        }, (err) => {
          // mstsc.exe has exited
          const duration = Math.floor((Date.now() - startTime) / 1000);
          const exitCode = err ? err.code : 0;

          this.log.info(`mstsc.exe exited for route ${routeId} (duration: ${duration}s, exit: ${exitCode})`);

          // ── Step 6: Cleanup ───────────────────────────
          this._cleanupSession(routeId, host, rdpFile, duration, exitCode, credTarget);
        });

        if (!proc.pid) {
          this.log.error('Failed to start mstsc.exe');
          this.configBuilder.cleanup(rdpFile);
          this.credentialHandler.clearCredentials(credTarget);
          if (credTarget !== host) {
            try { this.credentialHandler.clearCredentials(host); } catch {}
          }
          resolve({ success: false, error: 'mstsc.exe konnte nicht gestartet werden.' });
          return;
        }

        // Track active session
        this.activeSessions.set(routeId, {
          pid: proc.pid,
          rdpFile,
          host,
          credTarget,
          startTime,
          process: proc,
          sessionTimeout: route.session_timeout || null,
          serverSessionId: sessionData?.session?.id || null,
        });

        // Start monitoring
        this.monitor.startTracking(routeId, proc.pid, route.session_timeout);

        this._emitProgress(routeId, 'mstsc', 'done');
        this.emit('session-start', { routeId, pid: proc.pid });

        this.log.info(`mstsc.exe started for route ${routeId} (PID: ${proc.pid})`);
        resolve({ success: true });
      });

    } catch (err) {
      this.log.error(`RDP connect failed for route ${routeId}:`, err.message);
      this.emit('session-error', { routeId, error: err.message });
      return { success: false, error: err.message };
    }
  }

  /**
   * Disconnect an active RDP session.
   * @param {number} routeId
   */
  disconnect(routeId) {
    const session = this.activeSessions.get(routeId);
    if (!session) {
      this.log.debug(`No active session for route ${routeId}`);
      return;
    }

    this.log.info(`Disconnecting RDP session for route ${routeId} (PID: ${session.pid})`);

    try {
      // Kill mstsc.exe process
      process.kill(session.pid, 'SIGTERM');
    } catch (err) {
      this.log.debug(`Failed to kill PID ${session.pid}:`, err.message);
      // Process may have already exited
    }

    // Cleanup will happen in the execFile callback
  }

  /**
   * Get active session info for a route.
   * @param {number} routeId
   * @returns {object|null}
   */
  getActiveSession(routeId) {
    const session = this.activeSessions.get(routeId);
    if (!session) return null;

    return {
      routeId,
      pid: session.pid,
      host: session.host,
      duration: Math.floor((Date.now() - session.startTime) / 1000),
    };
  }

  /**
   * Get all active sessions.
   * @returns {Array}
   */
  getActiveSessions() {
    const sessions = [];
    for (const [routeId, session] of this.activeSessions) {
      sessions.push({
        routeId,
        pid: session.pid,
        host: session.host,
        duration: Math.floor((Date.now() - session.startTime) / 1000),
      });
    }
    return sessions;
  }

  /**
   * Check if a route has an active session.
   * @param {number} routeId
   * @returns {boolean}
   */
  isSessionActive(routeId) {
    return this.activeSessions.has(routeId);
  }

  /**
   * Cleanup everything on app exit / crash.
   * Called from main process before-quit handler.
   */
  cleanupAll() {
    this.log.info('RDP Manager: cleaning up all sessions...');

    // Kill all active mstsc processes
    for (const [routeId, session] of this.activeSessions) {
      try {
        process.kill(session.pid, 'SIGTERM');
      } catch {}

      // Cleanup temp files
      this.configBuilder.cleanup(session.rdpFile);

      // Clear credentials — under both the FQDN and the IP if we stored
      // both during connect.
      this.credentialHandler.clearCredentials(session.host);
      if (session.credTarget && session.credTarget !== session.host) {
        try { this.credentialHandler.clearCredentials(session.credTarget); } catch {}
      }

      // End session on server
      const duration = Math.floor((Date.now() - session.startTime) / 1000);
      this.api.endRdpSession(routeId, { duration, status: 'app_exit' }).catch(() => {});
    }

    this.activeSessions.clear();
    this.monitor.stopAll();
    this.stopStatusPolling();

    // Cleanup any orphaned temp files
    this.configBuilder.cleanupAll();

    // Clear any lingering TERMSRV credentials
    this.credentialHandler.clearAllGateControlCredentials();
  }

  // ══════════════════════════════════════════════════════════
  //  PRIVATE METHODS
  // ══════════════════════════════════════════════════════════

  /**
   * Perform TCP port check to verify host is reachable.
   * @param {string} host
   * @param {number} port
   * @param {number} timeout - ms
   * @returns {Promise<boolean>}
   */
  _tcpCheck(host, port, timeout = 5000) {
    return new Promise((resolve) => {
      const socket = new net.Socket();

      socket.setTimeout(timeout);

      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });

      socket.on('error', () => {
        socket.destroy();
        resolve(false);
      });

      socket.connect(port, host);
    });
  }

  /**
   * Send WoL and poll for host availability (max 60s).
   * @param {number} routeId
   * @param {string} host
   * @param {number} port
   * @returns {Promise<boolean>}
   */
  async _performWol(routeId, host, port) {
    try {
      await this.api.sendWol(routeId);
      this.log.info(`WoL magic packet sent for route ${routeId}`);
    } catch (err) {
      this.log.error('WoL send failed:', err.message);
      return false;
    }

    // Poll for availability (max 60 seconds, check every 3 seconds)
    const maxAttempts = 20;
    for (let i = 0; i < maxAttempts; i++) {
      await this._sleep(3000);

      const reachable = await this._tcpCheck(host, port, 3000);
      if (reachable) {
        this.log.info(`Host ${host}:${port} is now reachable after WoL (attempt ${i + 1})`);
        return true;
      }

      this._emitProgress(routeId, 'wol', `polling-${i + 1}`);
    }

    return false;
  }

  /**
   * Cleanup after mstsc.exe exits.
   */
  _cleanupSession(routeId, host, rdpFile, duration, exitCode, credTarget) {
    // Stop monitoring
    this.monitor.stopTracking(routeId);

    // Delete temp .rdp file
    this.configBuilder.cleanup(rdpFile);

    // Clear credentials from Credential Manager — under both the
    // FQDN and the IP, if different, so no stale TERMSRV/* entry
    // lingers after the session ends.
    this.credentialHandler.clearCredentials(host);
    if (credTarget && credTarget !== host) {
      try { this.credentialHandler.clearCredentials(credTarget); } catch {}
    }

    // Notify server: session end
    const session = this.activeSessions.get(routeId);
    const endReason = exitCode === 0 ? 'normal' : 'error';
    this.api.endRdpSession(routeId, {
      sessionId: session?.serverSessionId,
      endReason,
      duration,
      exitCode,
    }).catch(() => {});

    // Remove from active sessions
    this.activeSessions.delete(routeId);

    // Emit event
    this.emit('session-end', { routeId, duration, exitCode });

    this.log.info(`RDP session cleanup complete for route ${routeId}`);
  }

  /**
   * Handle session timeout from monitor.
   */
  async _handleSessionTimeout(data) {
    const session = this.activeSessions.get(data.routeId);
    if (!session) return;

    // Send notification to renderer
    this.emit('session-timeout-warning', {
      routeId: data.routeId,
      gracePeriod: 120, // 2 minutes
    });

    // Wait grace period (2 minutes)
    await this._sleep(120 * 1000);

    // Check if session is still active (user may have disconnected)
    if (this.activeSessions.has(data.routeId)) {
      this.log.warn(`Session timeout: killing mstsc for route ${data.routeId}`);
      this.disconnect(data.routeId);
    }
  }

  /**
   * Emit a progress event for the UI.
   */
  _emitProgress(routeId, step, status) {
    this.emit('progress', { routeId, step, status });
  }

  /**
   * Ensure registry keys are set to suppress the "unknown publisher" RDP warning.
   * Sets HKCU\SOFTWARE\Microsoft\Terminal Server Client\AuthenticationLevelOverride = 0
   */
  async _ensureRdpRegistryKeys() {
    try {
      await new Promise((resolve, reject) => {
        execFile('reg', [
          'add',
          'HKCU\\SOFTWARE\\Microsoft\\Terminal Server Client',
          '/v', 'AuthenticationLevelOverride',
          '/t', 'REG_DWORD',
          '/d', '0',
          '/f',
        ], { timeout: 5000 }, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      this.log.debug('RDP registry key set (AuthenticationLevelOverride=0)');
    } catch (err) {
      this.log.warn('Failed to set RDP registry key:', err.message);
      // Non-fatal: mstsc will still work, just with the warning dialog
    }
  }

  /**
   * Sleep helper.
   * @param {number} ms
   * @returns {Promise<void>}
   */
  _sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

module.exports = RdpManager;
