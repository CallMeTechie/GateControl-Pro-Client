'use strict';

const { execFile } = require('child_process');
const net = require('net');
const fs = require('fs');
const EventEmitter = require('events');

const RdpConfigBuilder = require('./rdp-config-builder');
const RdpCredentialHandler = require('./rdp-credential');
const RdpMonitor = require('./rdp-monitor');
const { pickPeerFqdn } = require('./rdp-peer-name');
const RdpHostSession = require('./rdp-host-session');
const { buildConnect, redact, hostTexts, describeDisconnect, endReasonOf } = require('./rdp-host-config');
const GCRdpLocal = require('../../renderer/rdp-local-state');

/**
 * RDP Manager -- Orchestrates the full RDP connection lifecycle.
 *
 * Lifecycle:
 *   1. Pre-flight checks (VPN active, TCP reachability, maintenance, expiry)
 *   2. Credential retrieval (E2EE decryption or password prompt)
 *   3. Where it opens (GCRdpLocal.openMode): the GateControl window (standard) or Windows-Remotedesktop
 *   Window (gc-rdp-host.exe, one process per session):
 *     4w. start the host, credentials only over its stdin (no .rdp file, no cmdkey)
 *     5w. audit start, the host's 'disconnected' / exit ends the session and its audit
 *     If the host does not start (missing, no ready line): on to the mstsc way, with a notice.
 *   Windows-Remotedesktop (the previous way, also for RemoteApp routes):
 *     4. .rdp file generation
 *     5. cmdkey credential storage
 *     6. mstsc.exe launch
 *   Then: process monitoring + heartbeats, cleanup on exit (credentials, temp files, audit)
 *
 * Events:
 *   'session-start'   - { routeId, pid, via }
 *   'session-end'     - { routeId, pid, duration, exitCode, via }
 *   'session-error'   - { routeId, error }
 *   'progress'        - { routeId, step, status }   step 'mode': status 'window' | 'mstsc', reason
 *   'notice'          - { routeId, kind }           host-failed | remoteapp | host-missing
 *   'host-action'     - { routeId, action }         reconnect | mstsc (buttons of the window's error view)
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
   * @param {function} [opts.hasDnsRuleFor] - (name) => whether a DNS rule of this app covers the zone of the name
   * @param {string}   [opts.hostExePath] - gc-rdp-host.exe (resources\rdp-host in the package)
   * @param {function} [opts.spawnHost]   - child_process.spawn for the host (tests: a fake)
   * @param {function} [opts.hostExists]  - (path) => boolean
   * @param {string}   [opts.platform]    - process.platform (the window needs Windows)
   * @param {object}   [opts.mstsc]       - { launch(args, done), store(target, u, p, d), clear(target) } (tests)
   * @param {function} [opts.getTheme]    - () => 'dark' | 'light'
   * @param {function} [opts.t]           - i18n of the app (texts of the window)
   */
  constructor({ apiClient, log, store, getTunnelState, getPeerInfo, hasDnsRuleFor, hostExePath, spawnHost, hostExists, platform, mstsc, getTheme, t }) {
    super();
    this.api = apiClient;
    this.log = log;
    this.store = store;
    this.getTunnelState = getTunnelState;
    this.getPeerInfo = getPeerInfo;
    // (name) => boolean: an NRPT rule of this app covers the zone of `name`
    this.hasDnsRuleFor = typeof hasDnsRuleFor === 'function' ? hasDnsRuleFor : () => false;
    this.requireE2ee = store?.get('security.requireE2ee', false) || false;

    this.configBuilder = new RdpConfigBuilder(log);
    this.credentialHandler = new RdpCredentialHandler(log);
    this.monitor = new RdpMonitor({ apiClient, log });

    // Active sessions: Map<routeId, { pid, rdpFile, host, startTime, process, via, hostSession? }>
    this.activeSessions = new Map();

    // GateControl window: Map<routeId, RdpHostSession> — also after the session ended while the window
    // shows its error view ("Erneut verbinden" uses the same window)
    this.hostSessions = new Map();
    this.hostExePath = hostExePath || null;
    this.spawnHost = spawnHost || null;
    this.hostExists = typeof hostExists === 'function' ? hostExists : (p) => { try { return !!p && fs.existsSync(p); } catch { return false; } };
    this.platform = platform || process.platform;
    this.getTheme = typeof getTheme === 'function' ? getTheme : () => 'dark';
    this.t = typeof t === 'function' ? t : null;
    const creds = this.credentialHandler;
    this.mstsc = {
      launch: (args, done) => execFile('mstsc.exe', args, { windowsHide: false }, done),
      store: (target, u, p, d) => creds.storeCredentials(target, u, p, d),
      clear: (target) => creds.clearCredentials(target),
      ...(mstsc || {}),
    };

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
    this.log.info(`RDP connect requested for route ${routeId} (requireE2ee=${this.requireE2ee}${opts.via ? `, via=${opts.via}` : ''})`);

    // A session in the GateControl window is running: bring its window to the front instead.
    const running = this.activeSessions.get(routeId);
    if (running && running.via === 'window' && opts.via !== 'mstsc') {
      running.hostSession.send({ type: 'focus' });
      return { success: true, via: 'window', focused: true };
    }

    try {
      // ── Step 1: Pre-Flight Checks ───────────────────────
      this._emitProgress(routeId, 'preflight', 'active');

      // 1a. Get connection details from server (with E2EE) FIRST.
      // The connect API call goes to the GateControl server and does not need
      // the WG tunnel. We fetch it before the VPN check because gateway-mode
      // routes reach the public server endpoint (connect_address) and need no
      // tunnel — and we need the server-resolved access_mode to decide.
      this.log.info(`Fetching connection data for route ${routeId}...`);
      const { publicKey: ecdhPublicKey } = this.credentialHandler.generateKeyPair();
      const connectData = await this.api.getRdpConnect(routeId, { ecdhPublicKey });
      this.log.info(`Connection data received: host=${connectData?.host}, port=${connectData?.port}, mode=${connectData?.credential_mode}, e2ee=${!!connectData?.credentials_e2ee}`);
      if (!connectData || !connectData.host) {
        this.log.error('No connection data received from server:', JSON.stringify(connectData));
        return { success: false, error: 'Keine Verbindungsdaten vom Server erhalten.' };
      }

      // peer_fqdn from here on is the name this PC can resolve: the one in the
      // chosen zone (peer_fqdn_primary) when there is a DNS rule for it, else
      // the one in the old zone. .rdp file and credential target use the same.
      const route = { ...connectData, peer_fqdn: pickPeerFqdn(connectData, this.hasDnsRuleFor) };
      const isGateway = route.access_mode === 'gateway';
      // host/port = the LAN target. Used only for server-side WoL routing,
      // logging, the cmdkey fallback entry, and session bookkeeping — NOT as the
      // address the client connects to. The real connect target is checkHost/
      // checkPort below (for gateway routes that is the public connect_address,
      // not this LAN host). The manager intentionally does not fall back to
      // external_hostname for gateway; the server always sends connect_address there.
      const host = route.host;
      const port = route.port || 3389;
      // Effective endpoint the client actually connects to. For gateway routes
      // this is the public <server>:<listen_port> (connect_address), not the LAN
      // host. Used for the reachability check; the .rdp full address (B1) and the
      // credTarget below use the same value so cmdkey matches mstsc.
      const checkHost = route.connect_address || host;
      const checkPort = route.connect_port != null ? route.connect_port : port;
      // credTarget = what we hand to cmdkey /generic; it MUST match the .rdp
      // "full address". For gateway that is connect_address; otherwise prefer the
      // internal FQDN (matches the CredSSP SPN from the server cert CN).
      const credTarget = isGateway
        ? (route.connect_address || host)
        : ((route.access_mode !== 'external' && route.peer_fqdn) ? route.peer_fqdn : host);
      this.log.info(`RDP target: ${checkHost}:${checkPort}${credTarget !== checkHost ? ` (credSSP target: ${credTarget})` : ''}`);

      // 1b. VPN tunnel must be active — EXCEPT gateway routes, whose endpoint
      // is the public server:listen_port (reachable without the tunnel).
      if (!isGateway) {
        const tunnelState = this.getTunnelState();
        if (!tunnelState || !tunnelState.connected) {
          this._emitProgress(routeId, 'preflight', 'error');
          return { success: false, error: 'VPN-Tunnel ist nicht aktiv. Bitte zuerst verbinden.' };
        }
      }
      this._emitProgress(routeId, 'vpn-check', 'done');

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
      this.log.info(`TCP check: ${checkHost}:${checkPort}...`);
      const reachable = await this._tcpCheck(checkHost, checkPort, 5000);
      this.log.info(`TCP check result: ${reachable ? 'reachable' : 'unreachable'}`);

      if (!reachable) {
        // Check if WoL is available
        if (route.wol_enabled && route.wol_mac_address) {
          this._emitProgress(routeId, 'wol', 'active');
          const wolResult = await this._performWol(routeId, checkHost, checkPort);
          if (!wolResult) {
            this._emitProgress(routeId, 'wol', 'error');
            return { success: false, error: `Host ${checkHost}:${checkPort} ist nicht erreichbar. Wake-on-LAN fehlgeschlagen.` };
          }
          this._emitProgress(routeId, 'wol', 'done');
        } else {
          this._emitProgress(routeId, 'tcp-check', 'error');
          return { success: false, error: `Host ${checkHost}:${checkPort} ist nicht erreichbar.` };
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

      // ── Step 3: GateControl window or Windows-Remotedesktop ──
      const local = this.getLocalSettings(routeId);
      const mode = GCRdpLocal.openMode({
        via: opts.via, local, global: this.getOpenIn(), route, hostAvailable: this.isHostAvailable(),
      });
      this.log.info(`RDP route ${routeId} opens in ${mode.mode} (${mode.reason})`);
      this.emit('progress', { routeId, step: 'mode', status: mode.mode, reason: mode.reason });
      if (mode.mode === 'mstsc' && (mode.reason === 'remoteapp' || mode.reason === 'host-missing')) {
        const wanted = GCRdpLocal.openMode({ via: opts.via, local, global: this.getOpenIn(), route: {}, hostAvailable: true });
        if (wanted.mode === 'window') this.emit('notice', { routeId, kind: mode.reason });
      }
      if (mode.mode === 'window') {
        const result = await this._connectWindow(routeId, route, { username, password, domain }, local, opts);
        if (!result.fallback) {
          password = null;
          return result;
        }
        this.log.warn(`gc-rdp-host did not start (${result.error}) — opening with Windows-Remotedesktop`);
        this.emit('notice', { routeId, kind: 'host-failed' });
        this.emit('progress', { routeId, step: 'mode', status: 'mstsc', reason: 'host-failed' });
      }

      // ── Step 4: Generate .rdp file ──────────────────────
      this._emitProgress(routeId, 'rdp-file', 'active');
      this.log.info('Building .rdp file...');
      const rdpFile = await this.configBuilder.build(route);
      this.log.info(`RDP file created: ${rdpFile}`);
      this._emitProgress(routeId, 'rdp-file', 'done');

      // ── Step 4: Store credentials via cmdkey ────────────
      if (username && password) {
        this._emitProgress(routeId, 'cmdkey', 'active');
        try {
          this.mstsc.store(credTarget, username, password, domain);
          // When using FQDN, ALSO store under IP as a fallback — some
          // scenarios (e.g. first connect before DNS propagation) may
          // have mstsc fall back to the alternate address.
          if (credTarget !== host) {
            try { this.mstsc.store(host, username, password, domain); } catch {}
          }
          this._emitProgress(routeId, 'cmdkey', 'done');
        } catch (err) {
          this.log.error('cmdkey failed:', err.message);
          // Continue anyway -- mstsc may still prompt
        }
      }

      // Clear password from memory
      password = null;

      // Server authentication is configured per connection in the .rdp
      // file ("authentication level", see RdpConfigBuilder). Never touch the
      // global AuthenticationLevelOverride — it affects every mstsc
      // connection of the user, not just GateControl's.

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

        const proc = this.mstsc.launch(mstscArgs, (err) => {
          // mstsc.exe has exited
          const duration = Math.floor((Date.now() - startTime) / 1000);
          const exitCode = err ? err.code : 0;

          this.log.info(`mstsc.exe exited for route ${routeId} (duration: ${duration}s, exit: ${exitCode})`);

          // ── Step 6: Cleanup ───────────────────────────
          this._cleanupSession(routeId, host, rdpFile, duration, exitCode, credTarget);
        });

        if (!proc || !proc.pid) {
          this.log.error('Failed to start mstsc.exe');
          this.configBuilder.cleanup(rdpFile);
          this.mstsc.clear(credTarget);
          if (credTarget !== host) {
            try { this.mstsc.clear(host); } catch {}
          }
          resolve({ success: false, error: 'mstsc.exe konnte nicht gestartet werden.' });
          return;
        }

        // Track active session
        this.activeSessions.set(routeId, {
          pid: proc.pid,
          rdpFile,
          host,
          name: this._routeName(routeId, route),
          credTarget,
          startTime,
          process: proc,
          via: 'mstsc',
          sessionTimeout: route.session_timeout || null,
          serverSessionId: sessionData?.session?.id || null,
        });

        // Start monitoring
        this.monitor.startTracking(routeId, proc.pid, route.session_timeout);

        this._emitProgress(routeId, 'mstsc', 'done');
        this.emit('session-start', { routeId, pid: proc.pid, via: 'mstsc' });

        this.log.info(`mstsc.exe started for route ${routeId} (PID: ${proc.pid})`);
        resolve({ success: true, via: 'mstsc' });
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

    if (session.via === 'window') {
      // the window disconnects (audit through its 'disconnected'), killed when it does not end in time
      session.hostSession.close();
      return;
    }

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
      name: session.name || this._routeName(routeId),
      via: session.via || 'mstsc',
      duration: Math.floor((Date.now() - session.startTime) / 1000),
    };
  }

  /**
   * The name of a route (the connect data, else the cached services list), null without one —
   * the tray and the session lists show it instead of the host.
   * @param {number} routeId
   * @param {object} [route]
   * @returns {string|null}
   */
  _routeName(routeId, route) {
    const own = typeof route?.name === 'string' ? route.name.trim() : '';
    if (own) return own;
    const svc = (this.rdpServices || []).find((r) => String(r.id) === String(routeId));
    const name = typeof svc?.name === 'string' ? svc.name.trim() : '';
    return name || null;
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
        name: session.name || this._routeName(routeId),
        via: session.via || 'mstsc',
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

  // ══════════════════════════════════════════════════════════
  //  GATECONTROL WINDOW (gc-rdp-host.exe)
  // ══════════════════════════════════════════════════════════

  /** gc-rdp-host.exe is there and this is Windows. */
  isHostAvailable() {
    return this.platform === 'win32' && !!this.hostExePath && this.hostExists(this.hostExePath);
  }

  /** The app setting "Remotedesktop öffnen in": 'window' (standard) | 'mstsc'. */
  getOpenIn() {
    const v = this.store?.get('rdp.openIn', 'window');
    return v === 'mstsc' ? 'mstsc' : 'window';
  }

  setOpenIn(v) {
    const mode = v === 'mstsc' ? 'mstsc' : 'window';
    this.store?.set('rdp.openIn', mode);
    return mode;
  }

  /** The local choice of a host ("Auf diesem PC"), restricted by its route as far as it is known. */
  getLocalSettings(routeId) {
    const all = this.store?.get('rdp.hosts', {}) || {};
    const raw = all && typeof all === 'object' ? all[String(routeId)] : null;
    return GCRdpLocal.restrictLocal(this._routeOf(routeId), raw);
  }

  /**
   * Changes the local choice of a host. Only known keys; what the route does not permit is dropped
   * (a local setting can only restrict). null for a key = back to the server's value.
   */
  setLocalSettings(routeId, patch) {
    const key = String(routeId);
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(key)) return {};
    const all = { ...(this.store?.get('rdp.hosts', {}) || {}) };
    const merged = { ...(all[key] || {}) };
    for (const [k, v] of Object.entries(patch || {})) {
      if (v === null) delete merged[k]; else merged[k] = v;
    }
    const next = GCRdpLocal.restrictLocal(this._routeOf(routeId), merged);
    if (Object.keys(next).length) all[key] = next; else delete all[key];
    this.store?.set('rdp.hosts', all);
    return next;
  }

  _routeOf(routeId) {
    return this.rdpServices.find((s) => String(s.id) === String(routeId)) || {};
  }

  /** "Fenster anzeigen": the session window of a route to the front. */
  focusWindow(routeId) {
    const hs = this.hostSessions.get(routeId);
    return hs ? hs.send({ type: 'focus' }) : false;
  }

  /** The app's design changed: the bars of all windows follow. */
  setTheme(theme) {
    for (const hs of this.hostSessions.values()) hs.send({ type: 'theme', theme: theme === 'light' ? 'light' : 'dark' });
  }

  /**
   * Starts (or reuses, for "Erneut verbinden") the window of a route and connects it.
   * @returns {Promise<{success: boolean, via?: string, fallback?: boolean, error?: string}>}
   */
  async _connectWindow(routeId, route, creds, local, opts) {
    this._emitProgress(routeId, 'window', 'active');
    let hs = this.hostSessions.get(routeId);
    if (hs && hs.exited) { this.hostSessions.delete(routeId); hs = null; }
    if (!hs) {
      hs = new RdpHostSession({ exePath: this.hostExePath, spawn: this.spawnHost, log: this.log });
      try {
        const ready = await hs.start();
        this.log.info(`gc-rdp-host ready for route ${routeId} (pid ${ready.pid}, host ${ready.version}, mstscax ${ready.mstscax})`);
      } catch (err) {
        return { success: false, fallback: true, error: err.code || err.message };
      }
      this.hostSessions.set(routeId, hs);
      this._wireHost(routeId, hs);
    }

    // Notify server: session start (audit)
    let sessionData;
    try {
      sessionData = await this.api.startRdpSession(routeId);
    } catch (err) {
      this.log.warn('Failed to register session start:', err.message);
    }

    const msg = buildConnect(route, creds, local, { theme: this.getTheme(), texts: hostTexts(this.t) });
    creds.password = null;
    this.log.info(`gc-rdp-host connect: ${JSON.stringify(redact(msg))}`);
    const sent = hs.send(msg);
    msg.password = null;
    if (!sent) {
      this.api.endRdpSession(routeId, { sessionId: sessionData?.session?.id, endReason: 'error', duration: 0 }).catch(() => {});
      this._emitProgress(routeId, 'window', 'error');
      return { success: false, error: 'gc-rdp-host' };
    }

    this.activeSessions.set(routeId, {
      pid: hs.pid,
      host: route.host,
      name: this._routeName(routeId, route),
      startTime: Date.now(),
      via: 'window',
      hostSession: hs,
      sessionTimeout: route.session_timeout || null,
      serverSessionId: sessionData?.session?.id || null,
    });
    if (hs.pid) this.monitor.startTracking(routeId, hs.pid, route.session_timeout);
    this._emitProgress(routeId, 'window', 'done');
    this.emit('session-start', { routeId, pid: hs.pid, via: 'window' });
    return { success: true, via: 'window' };
  }

  _wireHost(routeId, hs) {
    hs.on('disconnected', (d) => {
      this.log.info(`gc-rdp-host route ${routeId}: disconnected (reason ${d.reason}, ext ${d.ext}${d.byUser ? ', by the user' : ''})`);
      this._endWindowSession(routeId, hs, d);
      if (!d.byUser) {
        const ex = describeDisconnect(d.reason, d.ext, d.text, this.t);
        hs.send({ type: 'explain', title: ex.title, text: ex.text });
      }
    });
    hs.on('state', (m) => this.emit('window-state', { routeId, state: m.state }));
    hs.on('action', (m) => {
      this.log.info(`gc-rdp-host route ${routeId}: ${m.action}`);
      if (m.action === 'mstsc') hs.close();
      this.emit('host-action', { routeId, action: m.action });
    });
    hs.on('setting', (m) => {
      // the bar's "Laufwerke": kept per host, never beyond what the server permits
      if (m.key === 'drives') this.setLocalSettings(routeId, { drives: m.value });
    });
    hs.on('warning', (m) => this.log.warn(`gc-rdp-host route ${routeId}: warning ${m.kind || ''} ${m.code}`));
    hs.on('error', (m) => this.log.warn(`gc-rdp-host route ${routeId}: error ${m.code} ${m.text || ''}`));
    hs.on('log', (m) => this.log[m.level === 'info' ? 'info' : 'warn'](`gc-rdp-host route ${routeId}: ${m.msg}`));
    hs.on('exit', ({ code }) => {
      this.log.info(`gc-rdp-host route ${routeId} exited (${code})`);
      this._endWindowSession(routeId, hs, { reason: 0, ext: 0, byUser: code === 0 });
      if (this.hostSessions.get(routeId) === hs) this.hostSessions.delete(routeId);
    });
  }

  /** The session of a window ended: monitor, audit, event (once). */
  _endWindowSession(routeId, hs, d) {
    const session = this.activeSessions.get(routeId);
    if (!session || session.hostSession !== hs) return;
    this.activeSessions.delete(routeId);
    this.monitor.stopTracking(routeId);
    const duration = Math.floor((Date.now() - session.startTime) / 1000);
    const endReason = endReasonOf(d);
    this.api.endRdpSession(routeId, { sessionId: session.serverSessionId, endReason, duration, exitCode: d.reason }).catch(() => {});
    this.emit('session-end', { routeId, duration, exitCode: d.reason, via: 'window', endReason });
  }

  /**
   * Cleanup everything on app exit / crash.
   * Called from main process before-quit handler.
   */
  cleanupAll() {
    this.log.info('RDP Manager: cleaning up all sessions...');

    // Kill all active mstsc processes; the windows disconnect and exit when their stdin ends
    for (const [routeId, session] of this.activeSessions) {
      if (session.via === 'window') {
        session.hostSession.end();
        const duration = Math.floor((Date.now() - session.startTime) / 1000);
        this.api.endRdpSession(routeId, { sessionId: session.serverSessionId, endReason: 'app_exit', duration }).catch(() => {});
        continue;
      }
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

    for (const hs of this.hostSessions.values()) hs.end();
    this.hostSessions.clear();
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
    this.mstsc.clear(host);
    if (credTarget && credTarget !== host) {
      try { this.mstsc.clear(credTarget); } catch {}
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
    this.emit('session-end', { routeId, duration, exitCode, via: 'mstsc' });

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
   * Sleep helper.
   * @param {number} ms
   * @returns {Promise<void>}
   */
  _sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

module.exports = RdpManager;
