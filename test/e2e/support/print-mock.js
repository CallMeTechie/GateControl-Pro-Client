'use strict';

/**
 * The plugin gatecontrol-print ("Drucken & Scannen") for the e2e mock server
 * — the part the Windows app uses (plugin README "API", plugin 1.1.1) and
 * the core's media upload for it:
 *
 *   GET  overview                 rights, pagesLeft, printers, the last 10 jobs
 *   PUT  …/media                  the file (raw body) → { mediaId, mime, bytes }
 *   POST print { deviceId, mediaId, copies, color, duplex, name, media?, source? } → { job, pagesLeft }
 *   GET  jobs/<id>                → { job }   (not with `jobRoute: false`: a plugin before 1.1.0)
 *   POST jobs/<id>/cancel         → { canceled }   (queued / waiting only)
 *
 *   const pr = mock.setPrint({
 *     version: '1.1.1',
 *     rights: { print: true, scan: true, pagesPerDay: 20, bwOnly: false }, pagesLeft: 14,
 *     printers: [...], jobs: [...],          // as `overview` answers them
 *     jobRoute: true,                        // false: no GET jobs/<id> (plugin < 1.1.0)
 *     times: true,                           // false: jobs without expiresAt / doneAt (plugin < 1.1.1)
 *   });
 *   pr.listed = false       // the plugin is not in the plugin list (not installed / licensed / for the apps)
 *   pr.gone = true          // its routes answer 404 (stopped while the app runs)
 *   pr.down = true          // the server answers 503 (no connection to the plugin)
 *   pr.refuse.print = { status: 409, code: 'limit', left: 14, pages: 25 }   // the next POST print
 *   pr.refuse.upload = { status: 423, code: 'quarantined' }                 // the next upload
 *   pr.holdUploads = true; … pr.releaseUploads()                            // uploads that take their time
 *   pr.setJob('j1', { state: 'done', doneAt: '…' })   // what the gateway reports
 *   pr.log → [{ method, route, body }], pr.uploads → [{ mediaId, mime, bytes, head }]
 */

const crypto = require('crypto');

const API = 'plugins/gatecontrol-print/api/';
const MEDIA = 'plugins/gatecontrol-print/media';
const OPEN = ['queued', 'sending', 'printing', 'waiting'];

function createPrint({ version = '1.1.1', rights = { print: true, scan: true, pagesPerDay: 0, bwOnly: false }, pagesLeft = null, printers = [], jobs = [], jobRoute = true, times = true } = {}) {
  const state = { version, rights, pagesLeft, printers, jobs, jobRoute, times, listed: true, gone: false, down: false, refuse: { print: null, upload: null }, log: [], uploads: [], clock: null, seq: 0, holdUploads: false, held: [] };
  state.now = () => (typeof state.clock === 'number' ? state.clock : Date.now());
  const iso = (ms) => new Date(ms).toISOString();

  state.entry = () => (state.listed ? { id: 'gatecontrol-print', name: 'Drucken & Scannen', version: state.version, tab: null } : null);

  /** A job as the plugin answers it (without the times a plugin before 1.1.1 does not name). */
  const view = (j) => {
    const out = { kind: 'print', user: 2, userName: 'Anna', via: 'app', error: null, message: null, media: null, source: null, pages: 1, copies: 1, color: false, duplex: false, ...j, open: OPEN.includes(j.state) };
    if (!state.times) { delete out.expiresAt; delete out.doneAt; }
    return out;
  };

  state.releaseUploads = () => { state.holdUploads = false; for (const fn of state.held.splice(0)) fn(); };

  state.setJob = (id, patch) => {
    const j = state.jobs.find((x) => x.id === id);
    if (j) Object.assign(j, patch, { updatedAt: iso(state.now()) });
    return j;
  };

  /** → true when the request was ours (answered). */
  state.handle = ({ method, route, raw, headers }, json) => {
    if (route !== MEDIA && !route.startsWith(API)) return false;
    if (state.down) { json(503, { ok: false, error: 'unavailable' }); return true; }
    if (state.gone || !state.listed) { json(404, { ok: false, error: 'not_found' }); return true; }
    const refuse = (status, code, extra = {}) => { json(status, { ok: false, code, error: code, ...extra }); return true; };

    if (route === MEDIA) {
      if (method !== 'PUT') return refuse(405, 'method');
      const mime = String((headers && headers['content-type']) || '').split(';')[0];
      state.log.push({ method, route: 'media', body: { mime, bytes: raw.length } });
      if (state.refuse.upload) {
        const { status, code, ...extra } = state.refuse.upload;
        state.refuse.upload = null;
        return refuse(status, code, extra);
      }
      const mediaId = crypto.randomBytes(16).toString('hex');
      state.uploads.push({ mediaId, mime, bytes: raw.length, head: raw.subarray(0, 16).toString('latin1') });
      const answer = () => json(200, { ok: true, mediaId, mime, bytes: raw.length });
      // holdUploads: the answer waits until the test calls releaseUploads() (a file that is still going up)
      if (state.holdUploads) state.held.push(answer); else answer();
      return true;
    }

    const path = route.slice(API.length);
    let body = {};
    try { body = raw && raw.length ? JSON.parse(raw.toString('utf8')) : {}; } catch { body = {}; }
    state.log.push({ method, route: path, body });

    if (path === 'overview' && method === 'GET') {
      json(200, {
        ok: true, rights: state.rights, pagesLeft: state.rights.print && state.rights.pagesPerDay ? state.pagesLeft : null,
        printers: state.rights.print ? state.printers : [], scanners: [], drive: true, ai: false, ocr: false,
        target: { area: 'mine', folder: 'Scans' }, jobs: state.jobs.slice(0, 10).map(view), scan: null, defaultName: 'Scan',
      });
      return true;
    }

    if (path === 'print' && method === 'POST') {
      if (!state.rights.print) return refuse(403, 'no_right');
      if (state.refuse.print) {
        const { status, code, ...extra } = state.refuse.print;
        state.refuse.print = null;
        return refuse(status, code, extra);
      }
      const p = state.printers.find((x) => x.id === body.deviceId);
      const up = state.uploads.find((u) => u.mediaId === body.mediaId);
      if (!p || !up) return refuse(404, 'not_found');
      const copies = Number.isInteger(body.copies) ? body.copies : 1;
      const now = state.now();
      const job = {
        id: `job${++state.seq}`, device: p.name, deviceId: p.id, name: body.name || 'GateControl', pages: 1, copies, color: body.color === true && !state.rights.bwOnly,
        duplex: body.duplex === true, media: body.media || null, source: body.source || null, state: p.online ? 'queued' : 'waiting', error: p.online ? null : 'printer_offline',
        at: iso(now), updatedAt: iso(now), expiresAt: iso(now + 86400000), doneAt: null,
      };
      state.jobs.unshift(job);
      if (typeof state.pagesLeft === 'number') state.pagesLeft = Math.max(0, state.pagesLeft - copies);
      json(200, { ok: true, job: view(job), pagesLeft: state.rights.pagesPerDay ? state.pagesLeft : null });
      return true;
    }

    const m = /^jobs\/([A-Za-z0-9_-]{1,80})(\/cancel)?$/.exec(path);
    if (m && !m[2] && method === 'GET') {
      if (!state.jobRoute) return refuse(404, 'not_found');
      const j = state.jobs.find((x) => x.id === m[1]);
      if (!j) return refuse(404, 'not_found');
      json(200, { ok: true, job: view(j) });
      return true;
    }
    if (m && m[2] && method === 'POST') {
      const j = state.jobs.find((x) => x.id === m[1]);
      if (!j) return refuse(404, 'not_found');
      const can = j.state === 'queued' || j.state === 'waiting';
      if (can) Object.assign(j, { state: 'canceled', error: null, message: null, updatedAt: iso(state.now()), doneAt: iso(state.now()) });
      json(200, { ok: true, canceled: can });
      return true;
    }
    return refuse(404, 'not_found');
  };

  return state;
}

module.exports = { createPrint };
