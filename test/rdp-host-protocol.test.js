'use strict';

// The line protocol between the app and gc-rdp-host.exe (src/services/rdp/rdp-host-protocol.js): one message
// per line, only known messages each way, the host's output reduced to known fields.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { encode, parseHostMessage, LineDecoder, MAX_LINE } = require('../src/services/rdp/rdp-host-protocol');

describe('rdp-host-protocol', () => {
  it('encodes one message as exactly one line, even with line breaks in its strings', () => {
    const line = encode({ type: 'connect', name: 'a\nb', password: 'p\r\nw' });
    assert.equal(line.split('\n').length, 2);
    assert.ok(line.endsWith('\n'));
    assert.deepEqual(JSON.parse(line), { type: 'connect', name: 'a\nb', password: 'p\r\nw' });
  });

  it('refuses unknown messages to the host', () => {
    assert.throws(() => encode({ type: 'exec', cmd: 'x' }));
    assert.throws(() => encode(null));
    for (const type of ['connect', 'disconnect', 'close', 'focus', 'fullscreen', 'cad', 'clipboard', 'theme', 'explain']) encode({ type });
  });

  it('parses the host messages to their known fields only', () => {
    assert.deepEqual(parseHostMessage({ type: 'ready', pid: 12, version: '1.0.0', mstscax: '10.0.26100.1', extra: 'x' }), { type: 'ready', pid: 12, version: '1.0.0', mstscax: '10.0.26100.1' });
    assert.deepEqual(parseHostMessage({ type: 'state', state: 'reconnecting', attempt: 2, max: 20 }), { type: 'state', state: 'reconnecting', attempt: 2, max: 20 });
    assert.equal(parseHostMessage({ type: 'state', state: 'pwned' }), null);
    assert.deepEqual(parseHostMessage({ type: 'disconnected', reason: 3, ext: 5, text: 'x', byUser: false }), { type: 'disconnected', reason: 3, ext: 5, text: 'x', byUser: false });
    assert.deepEqual(parseHostMessage({ type: 'disconnected', byUser: 'yes' }), { type: 'disconnected', reason: 0, ext: 0, text: null, byUser: false });
    assert.deepEqual(parseHostMessage({ type: 'action', action: 'mstsc' }), { type: 'action', action: 'mstsc' });
    assert.equal(parseHostMessage({ type: 'action', action: 'shell' }), null);
    assert.deepEqual(parseHostMessage({ type: 'setting', key: 'drives', value: true }), { type: 'setting', key: 'drives', value: true });
    assert.equal(parseHostMessage({ type: 'setting', key: 'openIn', value: true }), null);
    assert.equal(parseHostMessage({ type: 'setting', key: 'drives', value: 'true' }), null);
    assert.deepEqual(parseHostMessage({ type: 'closed' }), { type: 'closed' });
    assert.equal(parseHostMessage({ type: 'nope' }), null);
    assert.equal(parseHostMessage('ready'), null);
    assert.equal(parseHostMessage({ type: 'log', level: 'error', msg: 'x'.repeat(900) }).msg.length, 500);
  });

  it('splits chunks into lines, across chunk borders, and reports garbage', () => {
    const got = [];
    const bad = [];
    const d = new LineDecoder((m) => got.push(m), (why) => bad.push(why));
    d.push('{"type":"ready","pid":1}\n{"type":"st');
    d.push(Buffer.from('ate","state":"connecting"}\r\nnot json\n\n{"type":"x"}\n'));
    assert.deepEqual(got.map((m) => m.type), ['ready', 'state']);
    assert.deepEqual(bad, ['invalid json', 'unknown message x']);
    d.push('x'.repeat(MAX_LINE + 1));
    assert.equal(bad.at(-1), 'line too long');
    assert.equal(d.buf, '');
  });
});
