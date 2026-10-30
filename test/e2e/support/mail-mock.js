'use strict';

/**
 * The plugin gatecontrol-mail for the e2e mock server: the core's fake Mail
 * server (gatecontrol-client-core test/fixtures/mail-server.js — the client
 * API "C2": me, accounts, folders, lists, a mail with pictures, drafts, send
 * with undo, AI, Drive, and the core media routes) on its own local port; the
 * mock server forwards `…/plugins/gatecontrol-mail/…` there unchanged (the
 * fake's device token instead of the app's).
 *
 *   const m = await mock.setMail({ features });   // m.srv → the core fake (state.messages, drafts, outbox, requests)
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

const PREFIX = '/api/v1/client/plugins/gatecontrol-mail/';
const FORWARD = ['content-type', 'content-range'];

async function createMail(opts = {}) {
  const { mailServer } = require(path.join(coreDir(), 'test', 'fixtures', 'mail-server.js'));
  const srv = await mailServer(opts);
  return {
    srv,
    entry: () => ({ id: 'gatecontrol-mail', name: 'Mail', version: opts.version || '1.0.0', tab: { label: 'Mail' } }),
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

module.exports = { createMail };
