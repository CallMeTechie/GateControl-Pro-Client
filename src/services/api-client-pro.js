'use strict';

const ApiClient = require('../../node_modules/@gatecontrol/client-core/src/services/api-client');

/**
 * GateControl Pro API Client
 * Extends the core ApiClient with RDP-specific endpoints.
 */
class ApiClientPro extends ApiClient {
  constructor(serverUrl, apiKey, log, peerId = null) {
    super(serverUrl, apiKey, log, peerId);
  }

  // ── RDP Services ────────────────────────────────────────

  /**
   * Get all RDP services available to this token.
   * GET /api/v1/client/rdp
   */
  async getRdpServices() {
    if (!this.client) return [];
    try {
      const { data } = await this.client.get('/api/v1/client/rdp');
      return data?.routes || [];
    } catch (err) {
      this.log.warn('RDP services fetch failed:', err.message);
      return [];
    }
  }

  /**
   * Get connection details + credentials for a specific RDP route.
   * GET /api/v1/client/rdp/:id/connect
   * @param {number} id - RDP route ID
   * @param {object} [opts]
   * @param {string} [opts.ecdhPublicKey] - Base64-encoded ECDH public key for E2EE
   * @returns {{ host, port, credentials_e2ee?, username?, password?, ... }}
   */
  async getRdpConnect(id, opts = {}) {
    if (!this.client) throw new Error('Server nicht konfiguriert');
    const params = {};
    if (opts.ecdhPublicKey) {
      params.ecdhPublicKey = opts.ecdhPublicKey;
    }
    const { data } = await this.client.get(`/api/v1/client/rdp/${id}/connect`, { params });
    return data?.connection || data;
  }

  /**
   * Start an RDP session (audit trail).
   * POST /api/v1/client/rdp/:id/session
   */
  async startRdpSession(id) {
    if (!this.client) throw new Error('Server nicht konfiguriert');
    const { data } = await this.client.post(`/api/v1/client/rdp/${id}/session`, {
      timestamp: new Date().toISOString(),
      hostname: require('os').hostname(),
    });
    return data;
  }

  /**
   * Send heartbeat for an active RDP session.
   * PATCH /api/v1/client/rdp/:id/session
   */
  async updateRdpSession(id, details = {}) {
    if (!this.client) return;
    try {
      await this.client.patch(`/api/v1/client/rdp/${id}/session`, {
        timestamp: new Date().toISOString(),
        ...details,
      });
    } catch (err) {
      this.log.debug('RDP session heartbeat failed:', err.message);
    }
  }

  /**
   * End an RDP session (audit trail).
   * DELETE /api/v1/client/rdp/:id/session
   */
  async endRdpSession(id, details = {}) {
    if (!this.client) return;
    try {
      await this.client.delete(`/api/v1/client/rdp/${id}/session`, {
        data: {
          sessionId: details.sessionId,
          endReason: details.endReason || 'normal',
        },
      });
    } catch (err) {
      this.log.debug('RDP session end failed:', err.message);
    }
  }

  /**
   * Send Wake-on-LAN magic packet via server.
   * POST /api/v1/rdp/:id/wol
   */
  async sendWol(id) {
    if (!this.client) throw new Error('Server nicht konfiguriert');
    const { data } = await this.client.post(`/api/v1/rdp/${id}/wol`);
    return data;
  }

  /**
   * Check WoL status / host reachability after WoL.
   * GET /api/v1/rdp/:id/wol/status
   */
  async getWolStatus(id) {
    if (!this.client) return null;
    try {
      const { data } = await this.client.get(`/api/v1/rdp/${id}/wol/status`);
      return data;
    } catch (err) {
      this.log.debug('WoL status check failed:', err.message);
      return null;
    }
  }

  /**
   * Get RDP host online/offline status.
   * GET /api/v1/rdp/:id/status
   */
  async getRdpStatus(id) {
    if (!this.client) return null;
    try {
      const { data } = await this.client.get(`/api/v1/rdp/${id}/status`);
      return data;
    } catch (err) {
      this.log.debug('RDP status check failed:', err.message);
      return null;
    }
  }

  /**
   * Get bulk status for all RDP routes.
   * GET /api/v1/rdp/status
   */
  async getRdpBulkStatus() {
    if (!this.client) return {};
    try {
      const { data } = await this.client.get('/api/v1/rdp/status');
      return data?.statuses || {};
    } catch (err) {
      this.log.debug('RDP bulk status check failed:', err.message);
      return {};
    }
  }

  /**
   * Get server public key for E2EE credential exchange.
   * GET /api/v1/rdp/pubkey
   */
  async getServerPublicKey() {
    if (!this.client) throw new Error('Server nicht konfiguriert');
    const { data } = await this.client.get('/api/v1/rdp/pubkey');
    return data?.publicKey || null;
  }
}

module.exports = ApiClientPro;
