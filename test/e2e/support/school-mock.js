'use strict';

/**
 * The plugin gatecontrol-schule for the e2e mock server (contract: the
 * plugin's README "API"): app/timetable?from&to (≤ 14 days, every date of
 * the range), app/changes?days, and from plugin 1.4.0 app/messages?days and
 * app/absences?days (older versions answer 404 NOT_FOUND like the plugin).
 *
 *   const sc = mock.setSchool({
 *     version: '1.4.0',
 *     students: [{ id: 3, name: 'Lena', klasse: '5b', color: '#2FBF71' }],
 *     day: (studentId, date) => ({ lessons: [...], exams?, homework?, holiday? }) | null,
 *     changes: [...], messages: [...], absences: [...],
 *   });
 *   sc.log → [{ route, query }]
 */

const BASE = 'plugins/gatecontrol-schule/api/';
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function dates(from, to) {
  const out = [];
  const d = new Date(`${from}T12:00:00Z`);
  const end = new Date(`${to}T12:00:00Z`);
  while (d <= end && out.length < 31) {
    out.push(d.toISOString().slice(0, 10));
    d.setUTCDate(d.getUTCDate() + 1);
  }
  return out;
}

function createSchool({ version = '1.4.0', students = [], day = () => null, changes = [], messages = [], absences = [], updatedAt = Date.now(), drive = false } = {}) {
  // drive (1.7.0): app/messages says `drive: true`; POST app/messages/<id>/attachments/<attId>/drive answers
  // { saved } (state.driveSaves: [{ messageId, attachmentId, body }])
  const state = { version, students, day, changes, messages, absences, updatedAt, log: [], drive, driveSaves: [] };
  const has14 = () => {
    const [a, b] = String(state.version).split('.').map(Number);
    return a > 1 || (a === 1 && b >= 4);
  };

  state.entry = () => ({ id: 'gatecontrol-schule', name: 'Schule', version: state.version, tab: null });

  /** → true when the request was ours (answered). */
  state.handle = ({ method, route, query, raw }, json) => {
    if (!route.startsWith(BASE)) return false;
    const path = route.slice(BASE.length);
    state.log.push({ route: path, query });
    const save = /^app\/messages\/([^/]+)\/attachments\/([^/]+)\/drive$/.exec(path);
    if (save && method === 'POST' && state.drive) {
      let body = {};
      try { body = raw && raw.length ? JSON.parse(raw.toString('utf8')) : {}; } catch { body = {}; }
      state.driveSaves.push({ messageId: decodeURIComponent(save[1]), attachmentId: decodeURIComponent(save[2]), body });
      const msg = state.messages.find((m) => String(m.id) === decodeURIComponent(save[1]));
      const att = msg && (msg.attachments || []).find((a) => String(a.id) === decodeURIComponent(save[2]));
      if (!att) return json(404, { ok: false, code: 'SCHULE_ATTACHMENT_NOT_FOUND' }), true;
      return json(200, { ok: true, saved: { nodeId: 900, name: att.name, where: `Familie › Schule › Lena › ${att.name}` } }), true;
    }
    if (method !== 'GET') return json(404, { ok: false, code: 'NOT_FOUND' }), true;
    if (path === 'app/timetable') {
      const { from, to } = query;
      if (!DATE_RE.test(from || '') || !DATE_RE.test(to || '') || to < from || dates(from, to).length > 14) return json(400, { ok: false, code: 'INVALID' }), true;
      const list = state.students.map((s) => ({
        id: s.id, name: s.name, userId: s.userId || null, klasse: s.klasse || null, color: s.color || '#64748B',
        ...(s.avatarUrl ? { avatarUrl: s.avatarUrl } : {}),
        days: dates(from, to).map((date) => ({ date, lessons: [], ...(state.day(s.id, date) || {}) })),
      }));
      return json(200, { ok: true, updatedAt: state.updatedAt, students: list }), true;
    }
    if (path === 'app/changes') return json(200, { ok: true, changes: state.changes }), true;
    if (path === 'app/messages' && has14()) return json(200, { ok: true, messages: state.messages, ...(state.drive ? { drive: true } : {}) }), true;
    if (path === 'app/absences' && has14()) return json(200, { ok: true, absences: state.absences }), true;
    return json(404, { ok: false, code: 'NOT_FOUND' }), true;
  };

  return state;
}

module.exports = { createSchool };
