'use strict';

/**
 * The plugin gatecontrol-gatedrop for the e2e mock server: the core's fake
 * GateDrop server (gatecontrol-client-core test/fixtures/gatedrop-server.js —
 * the plugin's README "App-API": targets, presence, sends, inbox, pending,
 * opened, transfers, media) on its own local port; the mock server forwards
 * `…/plugins/gatecontrol-gatedrop/…` there unchanged (the fake's device token
 * instead of the app's).
 *
 *   const g = await mock.setGateDrop({ version: '1.5.0' });  // g.srv → the core fake (state.inbox, sends, opened …)
 *   GateDrop 1.5 (version ≥ 1.5.0): `pickedAt`, `removed`, `limits.retention` as the plugin answers them.
 */

const http = require('http');
const path = require('path');

function coreDir() {
  const root = path.join(__dirname, '..', '..', '..');
  try {
    return path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [root] }));
  } catch {
    return path.join(root, '..', 'gatecontrol-client-core');
  }
}

const PREFIX = '/api/v1/client/plugins/gatecontrol-gatedrop/';
const FORWARD = ['content-type', 'content-range'];

async function createGateDrop(opts = {}) {
  const { gatedropServer } = require(path.join(coreDir(), 'test', 'fixtures', 'gatedrop-server.js'));
  const version = opts.version || '1.5.0';
  const srv = await gatedropServer({ ...opts, version });
  return {
    srv,
    entry: () => ({ id: 'gatecontrol-gatedrop', name: 'GateDrop', version, tab: null }),
    /** → true when the request was ours (answered asynchronously). */
    handle({ method, url, raw, headers }, res) {
      if (!url.pathname.startsWith(PREFIX)) return false;
      const h = { 'x-api-token': 'gc_token', 'content-length': String(raw.length) };
      for (const k of FORWARD) if (headers[k]) h[k] = headers[k];
      const fwd = http.request(`${srv.url}${url.pathname}${url.search}`, { method, headers: h }, (r) => {
        const out = {};
        for (const k of ['content-type', 'content-length', 'retry-after']) if (r.headers[k]) out[k] = r.headers[k];
        res.writeHead(r.statusCode, out);
        r.pipe(res);
      });
      fwd.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
      fwd.end(raw);
      return true;
    },
    close: () => srv.close(),
  };
}

module.exports = { createGateDrop };
