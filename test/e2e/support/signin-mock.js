'use strict';

/**
 * Company sign-in of the mock server ("Mit Firmenkonto anmelden",
 * GateControl ≥ 1.201.0):
 *
 *   GET  /api/v1/client/signin            → offered methods
 *   POST /api/v1/client/signin/password   → { username, password, totp? } → { ok, code }
 *   POST /api/v1/client/signin/handoff    → { handoff, verifier } → { ok, code }
 *
 * The browser part of "Mit Microsoft anmelden" is played by the test:
 * issueHandoff(challenge) stands for the server after a Microsoft sign-in,
 * the test then calls the app's loopback redirect URI itself. Every issued
 * setup code is listed in `issued` (the app redeems it at /enroll).
 */

const crypto = require('crypto');

function createSignin({
  password = { enabled: true, hint: 'Firmenkonto (corp.local): mit dem Windows-Passwort anmelden' },
  microsoft = [{ id: 7, label: 'Contoso' }],
  user = 'anna@corp.local',
  secret = 'Sommer-2026!',
  totp = null,
} = {}) {
  const issued = [];
  const handoffs = new Map(); // handoff → challenge
  const attempts = [];

  const newCode = () => {
    const hex = crypto.randomBytes(8).toString('hex').toUpperCase();
    const code = `${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}-${hex.slice(12)}`;
    issued.push(code);
    return { ok: true, code, expiresAt: new Date(Date.now() + 600000).toISOString() };
  };

  function handle({ method, route, raw }, json) {
    if (route === 'signin' && method === 'GET') {
      json(200, { ok: true, version: 1, password, microsoft });
      return true;
    }
    const fail = (status, error) => { json(status, { ok: false, error }); return true; };
    let body = {};
    try { body = JSON.parse(raw.toString('utf8') || '{}'); } catch { /* empty */ }
    if (route === 'signin/password' && method === 'POST') {
      attempts.push({ username: body.username, totp: body.totp || null, hostname: body.hostname, platform: body.platform });
      if (body.username !== user || body.password !== secret) return fail(401, 'invalid_credentials');
      if (totp && !body.totp) return fail(401, 'totp_required');
      if (totp && body.totp !== totp) return fail(401, 'totp_invalid');
      json(200, newCode());
      return true;
    }
    if (route === 'signin/handoff' && method === 'POST') {
      const challenge = handoffs.get(body.handoff);
      handoffs.delete(body.handoff);
      const sent = typeof body.verifier === 'string' ? crypto.createHash('sha256').update(body.verifier).digest('base64url') : null;
      if (!challenge || sent !== challenge) return fail(400, 'invalid_or_expired');
      json(200, newCode());
      return true;
    }
    return false;
  }

  return {
    handle,
    issued,
    attempts,
    /** One-time handoff bound to the challenge (what the server redirects the browser with). */
    issueHandoff(challenge) {
      const handoff = crypto.randomBytes(24).toString('base64url');
      handoffs.set(handoff, challenge);
      return handoff;
    },
  };
}

module.exports = { createSignin };
