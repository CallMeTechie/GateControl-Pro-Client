'use strict';

/**
 * The SSH terminal of „Fernzugriff“ (stage 3) for the e2e mock server: the core's test server
 * (gatecontrol-client-core test/fixtures/term-server.js — the plugin's devices, tmux and connect, the core's
 * term-token and the WebSocket /api/v1/remote/ssh-tunnel with gc-term.v1) on its own local port; the mock server
 * forwards `…/plugins/gatecontrol-remote/…`, `…/remote/term-token` and the WebSocket upgrade there unchanged.
 *
 *   const term = await mock.setTerm();   // term.srv → the core fake (connects, tokens, sockets, received, onHello)
 */

const http = require('http');
const net = require('net');
const path = require('path');

function coreDir() {
  const root = path.join(__dirname, '..', '..', '..');
  try {
    return path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [root] }));
  } catch {
    return path.join(root, '..', 'gatecontrol-client-core');
  }
}

const PLUGIN = '/api/v1/client/plugins/gatecontrol-remote/';
const TOKEN = '/api/v1/client/remote/term-token';
const WS = '/api/v1/remote/ssh-tunnel';

async function createTerm() {
  const { termServer } = require(path.join(coreDir(), 'test', 'fixtures', 'term-server.js'));
  const srv = await termServer();
  const port = Number(new URL(srv.url).port);
  const piped = new Set();
  return {
    srv,
    entry: () => ({ id: 'gatecontrol-remote', name: 'Fernzugriff', version: '1.5.0', tab: null }),
    /** → true when the request was ours (answered asynchronously). */
    handle({ method, url, raw }, res) {
      if (!url.pathname.startsWith(PLUGIN) && url.pathname !== TOKEN) return false;
      const fwd = http.request(`${srv.url}${url.pathname}${url.search}`, { method, headers: { 'content-type': 'application/json', 'content-length': String(raw.length) } }, (r) => {
        res.writeHead(r.statusCode, { 'content-type': r.headers['content-type'] || 'application/json' });
        r.pipe(res);
      });
      fwd.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
      fwd.end(raw);
      return true;
    },
    /** The WebSocket upgrade of the terminal: piped to the core fake as it came. */
    upgrade(req, socket, head) {
      if (req.url !== WS) return false;
      const up = net.connect(port, '127.0.0.1', () => {
        const lines = [`${req.method} ${req.url} HTTP/1.1`];
        for (let i = 0; i < req.rawHeaders.length; i += 2) lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
        up.write(lines.join('\r\n') + '\r\n\r\n');
        if (head && head.length) up.write(head);
        up.pipe(socket);
        socket.pipe(up);
      });
      piped.add(socket);
      piped.add(up);
      up.on('error', () => socket.destroy());
      socket.on('error', () => up.destroy());
      return true;
    },
    close: () => {
      for (const x of piped) x.destroy();
      return srv.close();
    },
  };
}

module.exports = { createTerm };
