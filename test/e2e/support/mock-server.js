'use strict';

/**
 * Minimal GateControl server for the e2e suite (HTTPS on 127.0.0.1 with a
 * self-signed certificate that only the app under test trusts).
 *
 * Answers what the client needs: ping, register, enroll, config, heartbeat/
 * status, permissions/services/peer info, the client policy, support-bundle
 * upload, and /api/v1/client/update/check
 * with an Ed25519-signed update manifest plus the installer download.
 *
 * Push (notification center): without `server.setPush(...)` the push routes
 * answer 404 like a server from before the feature. With it, GET
 * /api/v1/client/push is an SSE stream (hello + queued notifications; with
 * `quiet` / `state` in setPush() also hello.quiet and hello.state like a
 * server with control events, pushControl() sends `event: control`), plus
 * inbox, ack, prefs and test (contract: gatecontrol
 * docs/feature-notification-center.md).
 *
 * Chats: without `server.setMessenger()` GET /api/v1/client/plugins lists no
 * plugin (no "Chats" in the app). With it, the Messenger plugin answers
 * (support/messenger-mock.js) and its realtime events go to the open push
 * streams as `event: plugin`; `pushChat(payload)` sends a chat notification
 * (`kind: "message"`, never part of the inbox).
 *
 * Schule: without `server.setSchool()` the plugin list has no
 * `gatecontrol-schule`. With it (support/school-mock.js) the list names it
 * and app/timetable, app/changes (and with plugin 1.4.0 app/messages,
 * app/absences) answer from the test's data.
 *
 * Drive: without `await server.setDrive()` the plugin list has no
 * `gatecontrol-drive`. With it (support/drive-mock.js) the list names it and
 * its routes go to the core's fake Drive server.
 *
 * Mail: without `await server.setMail()` the plugin list has no
 * `gatecontrol-mail`. With it (support/mail-mock.js) the list names it and
 * its routes go to the core's fake Mail server.
 *
 * Map ("Standort senden"): /osm/<z>/<x>/<y>.png answers a PNG tile and
 * /nominatim/search, /nominatim/reverse canned addresses (`setGeocode()`)
 * — the app's MapService points there in e2e mode (GC_E2E_MAP_URL).
 *
 * Company sign-in: without `server.setSignin()` /api/v1/client/signin*
 * answers 404 like a server before GateControl 1.201.0. With it,
 * support/signin-mock.js answers (methods, password with optional 2FA,
 * handoff with PKCE check).
 *
 * The update offer is configurable per test (`server.setUpdate(...)`), all
 * requests are recorded (`server.requests`).
 */

const https = require('https');
const crypto = require('crypto');
const selfsigned = require('selfsigned');
const { createMessenger } = require('./messenger-mock');
const { createSchool } = require('./school-mock');
const { createVault } = require('./vault-mock');
const { createDrive } = require('./drive-mock');
const { createMail } = require('./mail-mock');
const { createSignin } = require('./signin-mock');

const API_TOKEN = 'gc_e2e_test_token';
// 1 × 1 PNG, served for every map tile
const TILE_PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');
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
  let policyVersion = 'e2e0000000000001'; // opaque 16-hex version (ETag)
  let push = null; // { topics, items: [notification + state], quiet?, state? }, null = old server (404)
  const streams = new Set();
  let messenger = null; // support/messenger-mock.js, null = no Messenger plugin
  let school = null; // support/school-mock.js, null = no Schule plugin
  let vault = null; // support/vault-mock.js, null = no Vault plugin
  let drive = null; // support/drive-mock.js, null = no Drive plugin
  let mail = null; // support/mail-mock.js, null = no Mail plugin
  let signin = null; // support/signin-mock.js, null = server before company sign-in (404)
  const acks = [];
  const prefs = [];
  let geocode = {
    search: [{ lat: '48.137154', lon: '11.576124', display_name: 'Marienplatz, Altstadt, München, Bayern, 80331, Deutschland', address: { road: 'Marienplatz', postcode: '80331', city: 'München' } }],
    reverse: { display_name: 'Am Bahnhof 1, 85435 Erding, Deutschland', address: { road: 'Am Bahnhof', house_number: '1', postcode: '85435', town: 'Erding' } },
  };

  const sse = (res, event, data, id) => {
    res.write(`${id ? `id: ${id}\n` : ''}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };
  const unread = () => (push ? push.items.filter((n) => n.state === 'delivered').length : 0);
  function addNotification(n) {
    const seq = push.items.reduce((m, x) => Math.max(m, x.seq), 100) + 1;
    const entry = {
      seq, id: n.id || seq, event_id: 'e2e', topic: 'system', priority: 'normal', title: 'E2E', body: '',
      created_at: new Date().toISOString(), expires_at: null, collapse_key: null, silent: false, data: null,
      ...n, state: 'delivered',
    };
    push.items.unshift(entry);
    const { state, ...payload } = entry;
    for (const res of streams) sse(res, 'notification', payload, entry.seq);
    return entry;
  }

  const server = https.createServer({ cert, key }, (req, res) => {
    const url = new URL(req.url, 'https://127.0.0.1');
    const chunks = [];
    req.on('data', (c) => { chunks.push(c); });
    req.on('end', () => {
      const raw = Buffer.concat(chunks);
      requests.push({
        method: req.method,
        path: url.pathname,
        query: Object.fromEntries(url.searchParams),
        token: req.headers['x-api-token'] || null,
        contentType: req.headers['content-type'] || null,
        raw,
      });
      const json = (status, obj) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(obj));
      };

      if (url.pathname.startsWith('/download/')) {
        if (!update || url.pathname !== `/download/${update.fileName}`) return json(404, { ok: false });
        res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': update.served.length });
        return res.end(update.served);
      }

      if (url.pathname.startsWith('/osm/')) {
        if (!/^\/osm\/\d+\/\d+\/\d+\.png$/.test(url.pathname)) return json(404, { ok: false });
        res.writeHead(200, { 'Content-Type': 'image/png', 'Content-Length': TILE_PNG.length });
        return res.end(TILE_PNG);
      }
      if (url.pathname === '/nominatim/search') return json(200, geocode.search);
      if (url.pathname === '/nominatim/reverse') return json(200, geocode.reverse);

      if (!url.pathname.startsWith('/api/v1/client/')) return json(404, { ok: false });
      const route = url.pathname.slice('/api/v1/client/'.length);

      if (route === 'push' || route.startsWith('push/')) {
        if (req.headers['x-api-token'] !== API_TOKEN) return json(401, { ok: false, error: 'unauthorized' });
        if (!push) return json(404, { ok: false, error: 'not_found' });
        if (route === 'push' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
          streams.add(res);
          res.on('close', () => streams.delete(res));
          sse(res, 'hello', {
            server_time: new Date().toISOString(), keepalive_s: 25, retention_h: 72, via: 'direct',
            unread: unread(), topics: push.topics,
            // newer servers: quiet hours (1.156) and control-event state
            ...(push.quiet !== undefined ? { quiet: push.quiet } : {}),
            ...(push.state ? { state: push.state } : {}),
          });
          const since = Number(req.headers['last-event-id'] || url.searchParams.get('since') || 0);
          for (const n of [...push.items].reverse()) {
            if (n.seq > since && n.state === 'delivered') {
              const { state, ...payload } = n;
              sse(res, 'notification', payload, n.seq);
            }
          }
          return undefined;
        }
        if (route === 'push/inbox') {
          return json(200, { ok: true, items: push.items.slice(0, Number(url.searchParams.get('limit')) || 100), unread: unread() });
        }
        if (route === 'push/ack') {
          const body = JSON.parse(raw.toString('utf8') || '{}');
          acks.push(body);
          if (body.state === 'read' || body.state === 'dismissed') {
            const ids = [];
            for (const n of push.items) if (body.seqs.includes(n.seq)) { n.state = body.state; ids.push(n.id); }
            for (const r of streams) sse(r, 'read', { ids });
          }
          return json(200, { ok: true });
        }
        if (route === 'push/prefs' && req.method === 'GET') {
          return json(200, {
            ok: true, enabled: true, mode: null, muted_topics: [], restricted: false,
            ...(push.quiet !== undefined ? { quiet: push.quiet } : {}),
          });
        }
        if (route === 'push/prefs') {
          prefs.push(JSON.parse(raw.toString('utf8') || '{}'));
          return json(200, { ok: true });
        }
        if (route === 'push/test') {
          const n = addNotification({ topic: 'system', priority: 'info', title: 'Testnachricht', body: 'Benachrichtigungen kommen auf diesem Gerät an.' });
          return json(200, { ok: true, seq: n.seq });
        }
        return json(404, { ok: false, error: 'not_found' });
      }

      // Company sign-in: public like enroll, 404 on servers without it.
      if (route === 'signin' || route.startsWith('signin/')) {
        if (signin && signin.handle({ method: req.method, route, raw }, json)) return undefined;
        return json(404, { ok: false, error: 'not_found' });
      }

      if (route === 'enroll') {
        return json(200, { ok: true, token: API_TOKEN, peerId: PEER_ID, config: null });
      }
      if (req.headers['x-api-token'] !== API_TOKEN) return json(401, { ok: false, error: 'unauthorized' });

      if (mail) {
        // The plugin list names every plugin that is set.
        if (route === 'plugins') {
          const list = messenger ? [{ id: 'gatecontrol-messenger', name: 'Messenger', version: '1.0.0', tab: { label: 'Chats', icon: 'M0 0' } }] : [];
          return json(200, { ok: true, plugins: [...list, ...(school ? [school.entry()] : []), ...(vault ? [vault.entry()] : []), ...(drive ? [drive.entry()] : []), mail.entry()] });
        }
        if (mail.handle({ method: req.method, url, raw, headers: req.headers }, res)) return undefined;
      }

      if (drive) {
        // The plugin list names every plugin that is set.
        if (route === 'plugins') {
          const list = messenger ? [{ id: 'gatecontrol-messenger', name: 'Messenger', version: '1.0.0', tab: { label: 'Chats', icon: 'M0 0' } }] : [];
          return json(200, { ok: true, plugins: [...list, ...(school ? [school.entry()] : []), ...(vault ? [vault.entry()] : []), drive.entry()] });
        }
        if (drive.handle({ method: req.method, url, raw, headers: req.headers }, res)) return undefined;
      }

      if (vault) {
        // The plugin list names the other plugins too when they are set.
        if (route === 'plugins') {
          const list = messenger ? [{ id: 'gatecontrol-messenger', name: 'Messenger', version: '1.0.0', tab: { label: 'Chats', icon: 'M0 0' } }] : [];
          return json(200, { ok: true, plugins: [...list, ...(school ? [school.entry()] : []), vault.entry()] });
        }
        if (vault.handle({ method: req.method, route, query: Object.fromEntries(url.searchParams), raw }, json)) return undefined;
      }

      if (school) {
        const ctx = { method: req.method, route, query: Object.fromEntries(url.searchParams), raw };
        // The plugin list names both plugins when both are set.
        if (route === 'plugins') {
          const list = messenger ? [{ id: 'gatecontrol-messenger', name: 'Messenger', version: '1.0.0', tab: { label: 'Chats', icon: 'M0 0' } }] : [];
          return json(200, { ok: true, plugins: [...list, school.entry()] });
        }
        if (school.handle(ctx, json)) return undefined;
      }

      if (messenger) {
        const sendRaw = (status, type, data) => {
          res.writeHead(status, { 'Content-Type': type, 'Content-Length': data.length });
          res.end(data);
        };
        const ctx = { method: req.method, route, query: Object.fromEntries(url.searchParams), raw, headers: req.headers };
        if (messenger.handle(ctx, json, sendRaw)) return undefined;
      }

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
          return json(200, { ok: true, version: policyVersion, managed: true, policy, sources: {} });
        case 'peer-info': return json(200, { ok: true, peer: { id: PEER_ID, name: 'e2e', enabled: true } });
        case 'traffic': return json(200, { ok: true, traffic: {} });
        case 'dns-check': return json(200, { ok: true });
        case 'support-bundle': return json(201, { ok: true, bundle: { id: 1, created_at: '2026-10-02 10:00:00', size_bytes: raw.length } });
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
    setPolicy(p, version = 'e2e0000000000001') { policy = p; policyVersion = version; },
    /** Enables push: { topics: [{ id, label }], items: [notification payloads] } (newest first). */
    setPush(p) {
      push = { topics: p.topics || [], items: [], quiet: p.quiet, state: p.state || null };
      for (const n of [...(p.items || [])].reverse()) addNotification(n);
    },
    /** Sends a notification to the open streams (and the inbox). */
    pushNotification: (n) => addNotification(n),
    pushStreams: () => streams.size,
    /** Enables the Messenger plugin ({ features } as `GET me` lists them); returns its in-memory state (support/messenger-mock.js). */
    setMessenger(opts = {}) {
      messenger = createMessenger({ ...opts, emit: (type, data) => { for (const r of streams) sse(r, 'plugin', { plugin: 'gatecontrol-messenger', type, data }); } });
      return messenger;
    },
    /** Enables the Schule plugin (support/school-mock.js); returns its state. */
    setSchool(opts = {}) {
      school = createSchool(opts);
      return school;
    },
    /** Enables the Drive plugin (support/drive-mock.js, the core's fake server on its own port); returns it. */
    async setDrive(opts = {}) {
      drive = await createDrive(opts);
      return drive;
    },
    /** Enables the Mail plugin (support/mail-mock.js, the core's fake server on its own port); returns it. */
    async setMail(opts = {}) {
      mail = await createMail(opts);
      return mail;
    },
    /** Enables the Vault plugin (support/vault-mock.js, the core's fake server); returns its state. */
    setVault(opts = {}) {
      vault = createVault(opts);
      return vault;
    },
    /** A chat notification (kind "message") to the open streams — not stored in the inbox. */
    pushChat(n) {
      const seq = push.items.reduce((m, x) => Math.max(m, x.seq), 100) + 1 + (push.chatSeq = (push.chatSeq || 0) + 1) * 1000;
      const payload = {
        seq, id: seq, event_id: 'plugin:gatecontrol-messenger:message', topic: 'plugin:gatecontrol-messenger:message', priority: 'normal',
        kind: 'message', created_at: new Date().toISOString(), expires_at: null, silent: false, ...n,
      };
      for (const r of streams) sse(r, 'notification', payload, seq);
      return payload;
    },
    /** Sends `event: control` (no id) to the open streams, e.g. { type: 'policy_changed', policy_version: 2 }. */
    pushControl(c) { for (const res of streams) sse(res, 'control', c); },
    acks: () => acks.slice(),
    /** Canned Nominatim answers: { search: [results], reverse: result }. */
    setGeocode(g) { geocode = { ...geocode, ...g }; },
    pushPrefs: () => prefs.slice(),
    /** Enables company sign-in (support/signin-mock.js); returns its state (issued codes, issueHandoff). */
    setSignin(opts = {}) {
      signin = createSignin(opts);
      return signin;
    },
    count(pathname) { return requests.filter((r) => r.path === pathname).length; },
    close: () => new Promise((resolve) => {
      if (drive) drive.close().catch(() => {});
      if (mail) mail.close().catch(() => {});
      for (const res of streams) res.end();
      streams.clear();
      server.closeAllConnections?.();
      server.close(() => resolve());
    }),
  };
}

module.exports = { startMockServer, buildUpdateOffer, API_TOKEN };
