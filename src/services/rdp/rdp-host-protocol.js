'use strict';

/**
 * The line protocol between the app and gc-rdp-host.exe (rdp-host/Program.cs): one JSON message per
 * line, UTF-8, over the host's stdin / stdout. Pure functions, covered by test/rdp-host-protocol.test.js.
 *
 *   App -> Host: connect | disconnect | close | focus | fullscreen | cad | clipboard | theme | explain
 *   Host -> App: ready | state | network | warning | error | disconnected | action | setting | log | closed
 */

const TO_HOST = new Set(['connect', 'disconnect', 'close', 'focus', 'fullscreen', 'cad', 'clipboard', 'theme', 'explain']);
const STATES = new Set(['connecting', 'connected', 'loggedin', 'reconnecting']);
const ACTIONS = new Set(['reconnect', 'mstsc']);
const SETTINGS = new Set(['drives', 'clipboard']);
// a line longer than this is not a message of ours (the host's messages are short)
const MAX_LINE = 64 * 1024;

/** One message for the host as a line. Unknown types are refused (programming error). */
function encode(msg) {
  if (!msg || typeof msg !== 'object' || !TO_HOST.has(msg.type)) throw new Error(`rdp-host: unknown message ${msg && msg.type}`);
  // JSON.stringify escapes line breaks inside strings, so one message is exactly one line
  return `${JSON.stringify(msg)}\n`;
}

const int = (v) => (Number.isInteger(v) ? v : null);
const str = (v, max = 500) => (typeof v === 'string' ? v.slice(0, max) : null);

/**
 * A message of the host, reduced to the known fields of its type; null for anything else.
 * The host is ours, but its output is still treated as input: nothing unknown reaches the app.
 */
function parseHostMessage(obj) {
  if (!obj || typeof obj !== 'object' || typeof obj.type !== 'string') return null;
  switch (obj.type) {
    case 'ready': return { type: 'ready', pid: int(obj.pid), version: str(obj.version, 40), mstscax: str(obj.mstscax, 60) };
    case 'state':
      if (!STATES.has(obj.state)) return null;
      return { type: 'state', state: obj.state, attempt: int(obj.attempt), max: int(obj.max) };
    case 'network': return { type: 'network', quality: int(obj.quality), rttMs: int(obj.rttMs), bandwidthKbps: int(obj.bandwidthKbps) };
    case 'warning': return { type: 'warning', code: int(obj.code), kind: str(obj.kind, 20) };
    case 'error': return { type: 'error', code: int(obj.code), text: str(obj.text) };
    case 'disconnected':
      return { type: 'disconnected', reason: int(obj.reason) ?? 0, ext: int(obj.ext) ?? 0, text: str(obj.text), byUser: obj.byUser === true };
    case 'action': return ACTIONS.has(obj.action) ? { type: 'action', action: obj.action } : null;
    case 'setting':
      if (!SETTINGS.has(obj.key) || typeof obj.value !== 'boolean') return null;
      return { type: 'setting', key: obj.key, value: obj.value };
    case 'log': return { type: 'log', level: obj.level === 'info' ? 'info' : 'warn', msg: str(obj.msg) };
    case 'closed': return { type: 'closed' };
    default: return null;
  }
}

/** Splits a byte stream into lines and hands each parsed message on; garbage is reported, not thrown. */
class LineDecoder {
  constructor(onMessage, onGarbage = () => {}) {
    this.buf = '';
    this.onMessage = onMessage;
    this.onGarbage = onGarbage;
  }

  push(chunk) {
    this.buf += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    let i;
    while ((i = this.buf.indexOf('\n')) >= 0) {
      const line = this.buf.slice(0, i).replace(/\r$/, '');
      this.buf = this.buf.slice(i + 1);
      this._line(line);
    }
    if (this.buf.length > MAX_LINE) {
      this.onGarbage('line too long');
      this.buf = '';
    }
  }

  _line(line) {
    if (!line.trim()) return;
    let obj;
    try { obj = JSON.parse(line); } catch { this.onGarbage('invalid json'); return; }
    const msg = parseHostMessage(obj);
    if (msg) this.onMessage(msg); else this.onGarbage(`unknown message ${obj && obj.type}`);
  }
}

module.exports = { encode, parseHostMessage, LineDecoder, TO_HOST, MAX_LINE };
