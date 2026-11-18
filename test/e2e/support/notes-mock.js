'use strict';

/**
 * The plugin gatecontrol-notizen for the e2e mock server: the core's fake Notizen & Aufgaben server
 * (gatecontrol-client-core test/fixtures/notes-server.js — me, nav, the views, the quick entry with the plugin's own
 * parser, tasks, items of the other plugins, notebooks, notes, attachments, the Tresor routes, the moves from
 * Microsoft To Do and DS Note) on its own local port; the mock server forwards `…/plugins/gatecontrol-notizen/…` and
 * the signed media URLs `/plugin-media/<token>` there unchanged (the fake's device token instead of the app's).
 *
 *   const n = await mock.setNotes({ features, plugin, allowed });   // n.srv → the core fake (state.tasks, notes, …)
 *
 * Plugin 1.8.0 (`profilePlaces`, the fake's STAGE6): a task's place of „Meine Orte“ comes as { ref: 'profile:<id>' }.
 * The fake keeps the profile's places under the same ids but takes a place only as { placeId } — the body is handed on
 * with the id (what the app sent stays in the mock server's `requests`).
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

const PREFIX = '/api/v1/client/plugins/gatecontrol-notizen/';
const FORWARD = ['content-type', 'content-range'];

/** A task's place { ref: 'profile:<id>' } (plugin 1.8.0) → { placeId: <id> } for the fake; anything else unchanged. */
function profileRefAsId(pathname, raw) {
  if (!/\/api\/tasks(?:\/\d+)?$/.test(pathname) || !raw || !raw.length) return raw;
  let body;
  try { body = JSON.parse(raw.toString('utf8')); } catch { return raw; }
  const pl = body && body.place;
  const m = pl && typeof pl.ref === 'string' && pl.lat === undefined ? /^profile:([1-9]\d{0,15})$/.exec(pl.ref) : null;
  if (!m) return raw;
  const { ref, ...rest } = pl;
  return Buffer.from(JSON.stringify({ ...body, place: { ...rest, placeId: Number(m[1]) } }), 'utf8');
}

async function createNotes(opts = {}) {
  const { notesServer } = require(path.join(coreDir(), 'test', 'fixtures', 'notes-server.js'));
  const srv = await notesServer(opts);
  return {
    srv,
    // a plugin without its licence is not listed by GateControl at all (srv.state.plugin = false)
    entry: () => (srv.state.plugin ? { id: 'gatecontrol-notizen', name: 'Notizen & Aufgaben', version: opts.version || '1.0.0', tab: null } : null),
    /** → true when the request was ours (answered asynchronously). */
    handle({ method, url, raw: sent, headers }, res) {
      if (!url.pathname.startsWith(PREFIX) && !url.pathname.startsWith('/plugin-media/')) return false;
      const raw = profileRefAsId(url.pathname, sent);
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

module.exports = { createNotes };
