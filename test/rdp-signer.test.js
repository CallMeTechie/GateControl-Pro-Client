'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RdpSigner = require('../src/services/rdp/rdp-signer');

const FAKE_THUMBPRINT = 'A1B2C3D4E5F60718293A4B5C6D7E8F9001020304';
const silentLog = { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} };

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'rdp-signer-test-'));
}

describe('RdpSigner', () => {
  let certDir;

  beforeEach(() => { certDir = makeTempDir(); });
  afterEach(() => {
    try { fs.rmSync(certDir, { recursive: true, force: true }); } catch {}
  });

  it('throws when constructed without certDir', () => {
    assert.throws(() => new RdpSigner({ log: silentLog }), /certDir/);
  });

  it('creates a cert and persists the thumbprint on first call', async () => {
    const calls = [];
    const runCmd = async (file, args) => {
      calls.push({ file, args });
      // first invocation = create. Output the thumbprint.
      return { stdout: FAKE_THUMBPRINT + '\n', stderr: '' };
    };
    const signer = new RdpSigner({ log: silentLog, certDir, runCmd });
    const tp = await signer.ensureCertificate();

    assert.equal(tp, FAKE_THUMBPRINT);
    assert.equal(calls.length, 1, 'no cached thumbprint -> exactly one PowerShell create call');
    assert.equal(calls[0].file, 'powershell.exe');
    const persisted = fs.readFileSync(path.join(certDir, 'thumbprint.txt'), 'utf-8').trim();
    assert.equal(persisted, FAKE_THUMBPRINT);
  });

  it('reuses cached thumbprint when cert is still in store', async () => {
    fs.writeFileSync(path.join(certDir, 'thumbprint.txt'), FAKE_THUMBPRINT);
    const calls = [];
    const runCmd = async (file, args) => {
      calls.push({ file, args });
      // _certExistsInStore probe
      return { stdout: 'yes\n', stderr: '' };
    };
    const signer = new RdpSigner({ log: silentLog, certDir, runCmd });
    const tp = await signer.ensureCertificate();

    assert.equal(tp, FAKE_THUMBPRINT);
    assert.equal(calls.length, 1, 'one probe call, no recreation');
    assert.ok(calls[0].args.some(a => a.includes('Test-Path')), 'should be the existence probe');
  });

  it('recreates cert when cached thumbprint no longer exists in store', async () => {
    fs.writeFileSync(path.join(certDir, 'thumbprint.txt'), FAKE_THUMBPRINT);
    const NEW_TP = '0123456789ABCDEF0123456789ABCDEF01234567';
    let call = 0;
    const runCmd = async () => {
      call += 1;
      if (call === 1) return { stdout: 'no\n', stderr: '' };       // probe
      if (call === 2) return { stdout: NEW_TP + '\n', stderr: '' }; // create
      throw new Error('unexpected call');
    };
    const signer = new RdpSigner({ log: silentLog, certDir, runCmd });
    const tp = await signer.ensureCertificate();

    assert.equal(tp, NEW_TP);
    const persisted = fs.readFileSync(path.join(certDir, 'thumbprint.txt'), 'utf-8').trim();
    assert.equal(persisted, NEW_TP);
  });

  it('returns null and stays non-fatal when PowerShell fails', async () => {
    const runCmd = async () => { throw new Error('powershell missing'); };
    const signer = new RdpSigner({ log: silentLog, certDir, runCmd });
    const tp = await signer.ensureCertificate();

    assert.equal(tp, null);
  });

  it('rejects malformed PowerShell output', async () => {
    const runCmd = async () => ({ stdout: 'not-a-thumbprint', stderr: '' });
    const signer = new RdpSigner({ log: silentLog, certDir, runCmd });
    const tp = await signer.ensureCertificate();
    assert.equal(tp, null);
  });

  it('sign() invokes rdpsign.exe with /sha256 + thumbprint + path', async () => {
    fs.writeFileSync(path.join(certDir, 'thumbprint.txt'), FAKE_THUMBPRINT);
    const calls = [];
    const runCmd = async (file, args) => {
      calls.push({ file, args });
      const base = path.basename(file).toLowerCase();
      if (base === 'powershell.exe') return { stdout: 'yes\n', stderr: '' };
      if (base === 'rdpsign.exe') return { stdout: '', stderr: '' };
      throw new Error(`unexpected: ${file}`);
    };
    const signer = new RdpSigner({ log: silentLog, certDir, runCmd });
    const ok = await signer.sign('C:/tmp/foo.rdp');

    assert.equal(ok, true);
    const signCall = calls.find(c => path.basename(c.file).toLowerCase() === 'rdpsign.exe');
    assert.ok(signCall, 'rdpsign.exe should have been invoked');
    // Resolved to an absolute Windows path so WoW64 redirection can't
    // hide rdpsign.exe in SysWOW64 (where it doesn't ship).
    assert.ok(/^[A-Z]:\\.*\\(System32|Sysnative)\\rdpsign\.exe$/i.test(signCall.file),
      `expected absolute System32/Sysnative path, got: ${signCall.file}`);
    assert.deepEqual(signCall.args, ['/sha256', FAKE_THUMBPRINT, 'C:/tmp/foo.rdp']);
  });

  it('sign() returns false on rdpsign failure (non-fatal)', async () => {
    fs.writeFileSync(path.join(certDir, 'thumbprint.txt'), FAKE_THUMBPRINT);
    const runCmd = async (file) => {
      if (file === 'powershell.exe') return { stdout: 'yes\n', stderr: '' };
      throw new Error('rdpsign explosion');
    };
    const signer = new RdpSigner({ log: silentLog, certDir, runCmd });
    const ok = await signer.sign('C:/tmp/foo.rdp');
    assert.equal(ok, false);
  });

  it('concurrent ensureCertificate() calls share the same in-flight promise', async () => {
    let createInvocations = 0;
    const runCmd = async () => {
      createInvocations += 1;
      // Yield to event loop so concurrent callers actually overlap.
      await new Promise(r => setImmediate(r));
      return { stdout: FAKE_THUMBPRINT + '\n', stderr: '' };
    };
    const signer = new RdpSigner({ log: silentLog, certDir, runCmd });
    const [a, b, c] = await Promise.all([
      signer.ensureCertificate(),
      signer.ensureCertificate(),
      signer.ensureCertificate(),
    ]);
    assert.equal(a, FAKE_THUMBPRINT);
    assert.equal(b, FAKE_THUMBPRINT);
    assert.equal(c, FAKE_THUMBPRINT);
    assert.equal(createInvocations, 1, 'cert creation must not race');
  });
});
