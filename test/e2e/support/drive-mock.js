'use strict';

/**
 * The plugin gatecontrol-drive for the e2e mock server: the core's fake Drive
 * server (gatecontrol-client-core test/fixtures/drive-server.js — the plugin's
 * README "API": me / areas, a small tree, uploads/check + commit, versions,
 * trash, search, links, and the core media routes) on its own local port; the
 * mock server forwards `…/plugins/gatecontrol-drive/…` there unchanged (the
 * fake's device token instead of the app's).
 *
 *   const d = await mock.setDrive({ seat, licence });   // d.srv → the core fake (state.nodes, links, requests)
 *   mock.setDrive({ features: ['vault', 'vaultsApart'] })   // Drive 1.11: vault folders left out of children,
 *                                                           // children?dirs=1 with hasDirs (d.srv.state.dirCalls),
 *                                                           // a new vault always in the area's top folder
 *   mock.setDrive({ version: '1.11.0' })                    // the version the plugin list reports
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

const PREFIX = '/api/v1/client/plugins/gatecontrol-drive/';
const FORWARD = ['content-type', 'content-range'];

async function createDrive(opts = {}) {
  const { driveServer } = require(path.join(coreDir(), 'test', 'fixtures', 'drive-server.js'));
  const srv = await driveServer(opts);
  return {
    srv,
    entry: () => ({ id: 'gatecontrol-drive', name: 'Drive', version: opts.version || '1.4.0', tab: null }),
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

module.exports = { createDrive };
