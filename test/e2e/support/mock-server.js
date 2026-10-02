'use strict';

/**
 * Minimal GateControl server for the e2e suite (HTTPS on 127.0.0.1 with a
 * self-signed certificate that only the app under test trusts).
 *
 * Answers what the client needs: ping, register, enroll, config, heartbeat/
 * status, permissions/services/peer info, the client policy, and /api/v1/client/update/check
 * with an Ed25519-signed update manifest plus the installer download.
 *
 * The update offer is configurable per test (`server.setUpdate(...)`), all
 * requests are recorded (`server.requests`).
 */

const https = require('https');
const crypto = require('crypto');
const selfsigned = require('selfsigned');

const API_TOKEN = 'gc_e2e_test_token';
const PEER_ID = 4242;

async function createCertificate() {
  const notAfter = new Date(Date.now() + 2 * 24 * 3600 * 1000);
  const pems = await selfsigned.generate([{ name: 'commonName', value: '127.0.0.1' }], {
    keyType: 'ec',
    curve: 'P-256',
    algorithm: 'sha256',
    notAfterDate: notAfter,
    extensions: [
      { name: 'basicConstraints', cA: true },
      { name: 'keyUsage', digitalSignature: true, keyCertSign: true },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName', altNames: [{ type: 7, ip: '127.0.0.1' }, { type: 2, value: 'localhost' }] },
    ],
  });
  return { cert: pems.cert, key: pems.private };
}

/**
 * Builds an update offer the way the release pipeline does
 * (scripts/sign-update.js): canonical JSON manifest, Ed25519 signature over
 * its exact bytes, base64.
 *
 * @param {object} o
 * @param {string} o.product - 'pro' | 'community'
 * @param {string} o.version
 * @param {Buffer} o.installer - bytes served as the installer
 * @param {crypto.KeyObject} o.privateKey
 * @param {'valid'|'tampered-manifest'|'wrong-key'|'bad-download'} [o.mode]
 */
function buildUpdateOffer({ product, version, installer, privateKey, mode = 'valid' }) {
  const fileName = `GateControl.E2E.Setup.${version}.exe`;
  const sha256 = crypto.createHash('sha256').update(installer).digest('hex');
  let manifest = JSON.stringify({ schema: 1, product, version, fileName, sha256, size: installer.length });
  let signer = privateKey;
  if (mode === 'wrong-key') signer = crypto.generateKeyPairSync('ed25519').privateKey;
  const signature = crypto.sign(null, Buffer.from(manifest, 'utf8'), signer).toString('base64');
  if (mode === 'tampered-manifest') {
    // Signed manifest, then the hash is swapped (e.g. a compromised mirror).
    const evil = crypto.createHash('sha256').update('evil').digest('hex');
    manifest = manifest.replace(sha256, evil);
  }
  let served = installer;
  if (mode === 'bad-download') served = Buffer.concat([installer.subarray(0, installer.length - 1), Buffer.from([0x00])]);
  return { version, fileName, sha256, manifest, signature, served };
}

async function startMockServer() {
  const { cert, key } = await createCertificate();
  const requests = [];
  let update = null; // { version, fileName, manifest, signature, served }
  let policy = null; // client policy (GET /api/v1/client/policy), null = old server (404)

  const server = https.createServer({ cert, key }, (req, res) => {
    const url = new URL(req.url, 'https://127.0.0.1');
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      requests.push({ method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), token: req.headers['x-api-token'] || null });
      const json = (status, obj) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(obj));
      };

      if (url.pathname.startsWith('/download/')) {
        if (!update || url.pathname !== `/download/${update.fileName}`) return json(404, { ok: false });
        res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': update.served.length });
        return res.end(update.served);
      }

      if (!url.pathname.startsWith('/api/v1/client/')) return json(404, { ok: false });
      const route = url.pathname.slice('/api/v1/client/'.length);

      if (route === 'enroll') {
        return json(200, { ok: true, token: API_TOKEN, peerId: PEER_ID, config: null });
      }
      if (req.headers['x-api-token'] !== API_TOKEN) return json(401, { ok: false, error: 'unauthorized' });

      switch (route) {
        case 'ping': return json(200, { ok: true });
        case 'register': return json(200, { ok: true, peerId: PEER_ID, hash: null, config: null });
        case 'config': return json(200, { ok: true, config: null, hash: null });
        case 'config/check': return json(200, { ok: true, changed: false });
        case 'heartbeat': return json(200, { ok: true });
        case 'status': return json(200, { ok: true });
        case 'permissions': return json(200, { ok: true, permissions: {}, portalUrl: null, autoOpenPortal: false });
        case 'services': return json(200, { ok: true, services: [] });
        case 'policy':
          if (!policy) return json(404, { ok: false });
          return json(200, { ok: true, version: 'e2e0000000000001', managed: true, policy, sources: {} });
        case 'peer-info': return json(200, { ok: true, peer: { id: PEER_ID, name: 'e2e', enabled: true } });
        case 'traffic': return json(200, { ok: true, traffic: {} });
        case 'dns-check': return json(200, { ok: true });
        case 'update/check': {
          if (!update) return json(200, { ok: true, available: false });
          const port = server.address().port;
          return json(200, {
            ok: true,
            available: true,
            version: update.version,
            downloadUrl: `https://127.0.0.1:${port}/download/${update.fileName}`,
            releaseNotes: 'E2E test release',
            manifest: update.manifest,
            signature: update.signature,
          });
        }
        default:
          if (route.startsWith('rdp')) return json(200, { ok: true, services: [], routes: [] });
          return json(200, { ok: true });
      }
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  return {
    url: `https://127.0.0.1:${port}`,
    caPem: cert,
    token: API_TOKEN,
    peerId: PEER_ID,
    requests,
    setUpdate(offer) { update = offer; },
    setPolicy(p) { policy = p; },
    count(pathname) { return requests.filter((r) => r.path === pathname).length; },
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

module.exports = { startMockServer, buildUpdateOffer, API_TOKEN };
