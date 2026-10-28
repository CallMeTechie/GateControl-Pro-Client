'use strict';

/**
 * A Windows Hello provider for the e2e runs (core services/windows-hello.js
 * interface: available, create, sign, remove). Keys are node RSA 2048 keys
 * that sign with PKCS#1 v1.5 / SHA-256 like Windows; the next prompts'
 * answers come from `answers` ('ok' | 'cancelled' | 'prefers_password' |
 * 'locked' | 'failed'), every prompt is listed in `prompts`. The real crypto
 * of the core (wrapping, record, DPAPI through safeStorage) runs unchanged.
 */

const crypto = require('crypto');

function createFakeHello() {
  const f = { answers: [], prompts: [], keys: new Map(), avail: { available: true, reason: null } };
  const answer = () => (f.answers.length ? f.answers.shift() : 'ok');
  const sign = (key, data) => crypto.sign('sha256', data, { key: key.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING });
  f.provider = {
    kind: 'e2e-fake',
    available: async () => ({ ...f.avail }),
    async create(name, challenge) {
      f.prompts.push('create');
      const a = answer();
      if (a !== 'ok') return { status: a };
      const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const key = { privateKey, spki: publicKey.export({ type: 'spki', format: 'der' }) };
      f.keys.set(name, key);
      return { status: 'ok', publicKey: Buffer.from(key.spki), signature: sign(key, challenge) };
    },
    async sign(name, challenge) {
      const key = f.keys.get(name);
      if (!key) return { status: 'not_found' };
      f.prompts.push('sign');
      const a = answer();
      if (a !== 'ok') return { status: a };
      return { status: 'ok', signature: sign(key, challenge) };
    },
    async remove(name) {
      return { status: f.keys.delete(name) ? 'ok' : 'not_found' };
    },
  };
  return f;
}

/**
 * Windows Hello as a confirmation (core createConsentVerifier: available, verify) for the Drive vault lock: the next
 * answers from `answers` ('verified' | 'cancelled' | 'not_set_up' | …), `avail` what CheckAvailability says, every
 * dialog in `prompts` ({ message, window: true when the app window owned it }).
 */
function createFakeConsent() {
  const f = { answers: [], prompts: [], avail: { available: true, reason: null } };
  f.provider = {
    kind: 'e2e-fake-consent',
    available: async () => ({ ...f.avail }),
    async verify(message, { window = null } = {}) {
      if (!f.avail.available) return { status: f.avail.reason || 'unavailable' };
      f.prompts.push({ message, window: !!window });
      return { status: f.answers.length ? f.answers.shift() : 'verified' };
    },
  };
  return f;
}

module.exports = { createFakeHello, createFakeConsent };
