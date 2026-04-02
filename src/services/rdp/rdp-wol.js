'use strict';

const net = require('net');

/**
 * Wake-on-LAN client that calls the server WoL API
 * and polls for host availability.
 */
class RdpWolClient {
  /**
   * @param {object} opts
   * @param {object} opts.apiClient - ApiClientPro instance
   * @param {object} opts.log - electron-log instance
   */
  constructor({ apiClient, log }) {
    this.api = apiClient;
    this.log = log;
  }

  /**
   * Send WoL magic packet via server API and poll for host availability.
   * @param {number} routeId - RDP route ID
   * @param {string} host - Target host IP/hostname
   * @param {number} port - Target RDP port
   * @param {object} [opts]
   * @param {number} [opts.maxWaitSeconds=60] - Max time to wait for host
   * @param {number} [opts.pollIntervalMs=3000] - Poll interval
   * @param {function} [opts.onProgress] - Progress callback(attempt, maxAttempts)
   * @returns {Promise<{ success: boolean, waitedSeconds: number }>}
   */
  async wakeAndWait(routeId, host, port, opts = {}) {
    const maxWait = (opts.maxWaitSeconds || 60) * 1000;
    const pollInterval = opts.pollIntervalMs || 3000;
    const maxAttempts = Math.ceil(maxWait / pollInterval);
    const startTime = Date.now();

    // Step 1: Send WoL via server
    try {
      await this.api.sendWol(routeId);
      this.log.info(`WoL sent for route ${routeId}, waiting for ${host}:${port}...`);
    } catch (err) {
      this.log.error(`WoL API call failed for route ${routeId}:`, err.message);
      return { success: false, waitedSeconds: 0 };
    }

    // Step 2: Poll for TCP reachability
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      await this._sleep(pollInterval);

      if (opts.onProgress) {
        opts.onProgress(attempt, maxAttempts);
      }

      const reachable = await this._tcpCheck(host, port, 3000);
      if (reachable) {
        const waited = Math.round((Date.now() - startTime) / 1000);
        this.log.info(`Host ${host}:${port} reachable after ${waited}s (WoL)`);
        return { success: true, waitedSeconds: waited };
      }
    }

    const waited = Math.round((Date.now() - startTime) / 1000);
    this.log.warn(`Host ${host}:${port} not reachable after ${waited}s WoL wait`);
    return { success: false, waitedSeconds: waited };
  }

  /**
   * Just send WoL without waiting (fire-and-forget).
   * @param {number} routeId
   * @returns {Promise<boolean>}
   */
  async wake(routeId) {
    try {
      await this.api.sendWol(routeId);
      this.log.info(`WoL sent for route ${routeId}`);
      return true;
    } catch (err) {
      this.log.error(`WoL failed for route ${routeId}:`, err.message);
      return false;
    }
  }

  /**
   * Check WoL status via server API.
   * @param {number} routeId
   * @returns {Promise<object|null>}
   */
  async checkStatus(routeId) {
    return this.api.getWolStatus(routeId);
  }

  // ── Private ──────────────────────────────────────────────

  _tcpCheck(host, port, timeout = 3000) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(timeout);
      socket.on('connect', () => { socket.destroy(); resolve(true); });
      socket.on('timeout', () => { socket.destroy(); resolve(false); });
      socket.on('error', () => { socket.destroy(); resolve(false); });
      socket.connect(port, host);
    });
  }

  _sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

module.exports = RdpWolClient;
