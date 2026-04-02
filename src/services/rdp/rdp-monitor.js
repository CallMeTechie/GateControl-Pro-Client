'use strict';

const EventEmitter = require('events');

/**
 * Tracks active RDP sessions: watches process existence,
 * sends heartbeats to server, handles session timeout.
 */
class RdpMonitor extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClientPro instance
   * @param {object} opts.log - electron-log instance
   */
  constructor({ apiClient, log }) {
    super();
    this.api = apiClient;
    this.log = log;

    // Tracked sessions: Map<routeId, { pid, intervalId, timeoutId, startTime }>
    this._tracked = new Map();
  }

  /**
   * Start tracking an RDP session.
   * @param {number} routeId - Route ID
   * @param {number} pid - mstsc.exe process ID
   * @param {number|null} sessionTimeout - Session timeout in seconds, null = no timeout
   */
  startTracking(routeId, pid, sessionTimeout = null) {
    // Stop any existing tracking for this route
    this.stopTracking(routeId);

    const startTime = Date.now();

    // Heartbeat every 60 seconds
    const intervalId = setInterval(async () => {
      // Check if process is still running
      const alive = this._isProcessAlive(pid);
      if (!alive) {
        this.log.info(`mstsc.exe PID ${pid} is no longer running (route ${routeId})`);
        this.stopTracking(routeId);
        return;
      }

      // Send heartbeat to server
      const duration = Math.floor((Date.now() - startTime) / 1000);
      try {
        await this.api.updateRdpSession(routeId, { duration, pid });
      } catch (err) {
        this.log.debug(`Heartbeat failed for route ${routeId}:`, err.message);
      }
    }, 60 * 1000);

    // Session timeout
    let timeoutId = null;
    if (sessionTimeout && sessionTimeout > 0) {
      timeoutId = setTimeout(() => {
        this.log.warn(`Session timeout reached for route ${routeId} (${sessionTimeout}s)`);
        this.emit('session-timeout', { routeId, pid });
      }, sessionTimeout * 1000);
    }

    this._tracked.set(routeId, { pid, intervalId, timeoutId, startTime });
    this.log.info(`Started tracking RDP session for route ${routeId} (PID: ${pid})`);
  }

  /**
   * Stop tracking an RDP session.
   * @param {number} routeId
   */
  stopTracking(routeId) {
    const tracked = this._tracked.get(routeId);
    if (!tracked) return;

    clearInterval(tracked.intervalId);
    if (tracked.timeoutId) clearTimeout(tracked.timeoutId);

    this._tracked.delete(routeId);
    this.log.debug(`Stopped tracking RDP session for route ${routeId}`);
  }

  /**
   * Stop all tracking (app exit).
   */
  stopAll() {
    for (const [routeId] of this._tracked) {
      this.stopTracking(routeId);
    }
  }

  /**
   * Get all tracked sessions.
   * @returns {Array<{ routeId: number, pid: number, duration: number }>}
   */
  getTracked() {
    const result = [];
    for (const [routeId, data] of this._tracked) {
      result.push({
        routeId,
        pid: data.pid,
        duration: Math.floor((Date.now() - data.startTime) / 1000),
        alive: this._isProcessAlive(data.pid),
      });
    }
    return result;
  }

  /**
   * Check if a process is still running.
   * @param {number} pid
   * @returns {boolean}
   */
  _isProcessAlive(pid) {
    try {
      process.kill(pid, 0); // Signal 0 = check if process exists
      return true;
    } catch {
      return false;
    }
  }
}

module.exports = RdpMonitor;
