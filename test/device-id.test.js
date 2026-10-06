'use strict';

// Short device ID (first 8 hex of the machine fingerprint) for Settings →
// About and the support bundle. Pure module, no Electron or core needed.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { shortDeviceId, withDeviceId } = require('../src/main/device-id');

const FP = '0123abcd' + 'f'.repeat(56);

describe('device ID', () => {
  it('returns the first 8 lowercase hex characters', () => {
    assert.equal(shortDeviceId(() => FP), '0123abcd');
    assert.equal(shortDeviceId(() => FP.toUpperCase()), '0123abcd');
    assert.equal(shortDeviceId(() => ` ${FP}\n`), '0123abcd');
  });

  it('returns null for a failing or malformed fingerprint and logs without the value', () => {
    const logged = [];
    const log = { warn: (...a) => logged.push(a.join(' ')) };
    assert.equal(shortDeviceId(() => { throw new Error('machine-id failed'); }, log), null);
    assert.equal(shortDeviceId(() => null, log), null);
    assert.equal(shortDeviceId(() => FP.slice(0, 40), log), null);
    assert.equal(shortDeviceId(() => `${FP.slice(0, 63)}g`, log), null);
    assert.equal(shortDeviceId(() => { throw new Error('x'); }), null); // no logger
    assert.equal(logged.length, 4);
    for (const line of logged) assert.ok(!line.includes(FP.slice(0, 8)), line);
  });

  it('adds client.deviceId (short form) to the support bundle', async () => {
    const collect = async (ctx, opts) => ({ client: { version: '1.0.0' }, reason: opts.reason });
    const bundle = await withDeviceId(collect, () => shortDeviceId(() => FP))({}, { reason: 'user' });
    assert.equal(bundle.client.deviceId, '0123abcd');
    assert.equal(bundle.reason, 'user');
    assert.ok(!JSON.stringify(bundle).includes(FP));
  });

  it('support bundle: deviceId is null when unavailable, collection still succeeds', async () => {
    const collect = async () => ({ client: {} });
    const a = await withDeviceId(collect, () => shortDeviceId(() => { throw new Error('x'); }))({}, {});
    assert.equal(a.client.deviceId, null);
    const b = await withDeviceId(collect, () => { throw new Error('x'); })({}, {});
    assert.equal(b.client.deviceId, null);
  });
});
