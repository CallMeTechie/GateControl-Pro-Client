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

// fs facade that defaults to the real fs and lets a test override which paths
// claim to exist (extraExists) plus optionally readdirSync/copyFileSync.
// Used so the existing signing tests pass on Linux CI even though
// C:\Windows\System32\rdpsign.exe doesn't actually exist there — without this,
// resolveRdpsignPath() returns null and sign() short-circuits to false.
function fsMock(opts) {
  const o = opts || {};
  const extraExists = o.extraExists || (() => false);
  return {
    existsSync: (p) => extraExists(p) || fs.existsSync(p),
    mkdirSync: o.mkdirSync || ((p, ...a) => fs.mkdirSync(p, ...a)),
    readFileSync: (p, ...a) => fs.readFileSync(p, ...a),
    writeFileSync: (p, ...a) => fs.writeFileSync(p, ...a),
    copyFileSync: o.copyFileSync || ((s, d) => fs.copyFileSync(s, d)),
    readdirSync: o.readdirSync || ((p, ...a) => fs.readdirSync(p, ...a)),
  };
}

// Pretends C:\Windows\System32\rdpsign.exe (or Sysnative) exists, regardless
// of host OS. Used by the legacy signing tests — they only care about the
// rdpsign invocation, not the resolver path.
const fsWithSystemRdpsign = () =>
  fsMock({ extraExists: (p) => /[\\/](System32|Sysnative)[\\/]rdpsign\.exe$/i.test(p) });

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
    // path.win32.basename so this passes on Linux CI too — the source
    // resolves rdpsign.exe to a Windows-style absolute path regardless
    // of the runtime platform.
    const runCmd = async (file, args) => {
      calls.push({ file, args });
      const base = path.win32.basename(file).toLowerCase();
      if (base === 'powershell.exe') return { stdout: 'yes\n', stderr: '' };
      if (base === 'rdpsign.exe') return { stdout: '', stderr: '' };
      throw new Error(`unexpected: ${file}`);
    };
    const signer = new RdpSigner({
      log: silentLog, certDir, runCmd, fsImpl: fsWithSystemRdpsign(),
    });
    const ok = await signer.sign('C:/tmp/foo.rdp');

    assert.equal(ok, true);
    const signCall = calls.find(c => path.win32.basename(c.file).toLowerCase() === 'rdpsign.exe');
    assert.ok(signCall, 'rdpsign.exe should have been invoked');
    // Absolute Windows path so WoW64 redirection can't hide rdpsign.exe
    // in SysWOW64 (where it doesn't ship).
    assert.ok(/^[A-Z]:\\.*\\(System32|Sysnative)\\rdpsign\.exe$/i.test(signCall.file),
      `expected absolute System32/Sysnative path, got: ${signCall.file}`);
    assert.deepEqual(signCall.args, ['/sha256', FAKE_THUMBPRINT, 'C:/tmp/foo.rdp']);
  });

  it('sign() returns false on rdpsign failure (non-fatal)', async () => {
    fs.writeFileSync(path.join(certDir, 'thumbprint.txt'), FAKE_THUMBPRINT);
    const runCmd = async (file) => {
      const base = path.win32.basename(file).toLowerCase();
      if (base === 'powershell.exe') return { stdout: 'yes\n', stderr: '' };
      throw new Error('rdpsign explosion');
    };
    const signer = new RdpSigner({
      log: silentLog, certDir, runCmd, fsImpl: fsWithSystemRdpsign(),
    });
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

  // ── resolveRdpsignPath() — the new path resolver ───────────────

  it('resolveRdpsignPath() prefers System32 when present', async () => {
    const signer = new RdpSigner({
      log: silentLog, certDir, binDir: path.join(certDir, 'bin'),
      fsImpl: fsWithSystemRdpsign(),
    });
    const p = await signer.resolveRdpsignPath();
    assert.ok(p && /[\\/](System32|Sysnative)[\\/]rdpsign\.exe$/i.test(p),
      `expected System32 path, got: ${p}`);
    assert.equal(signer.signingUnavailableReason, null);
  });

  it('resolveRdpsignPath() returns the cached binDir copy when System32 is empty', async () => {
    const binDir = path.join(certDir, 'bin');
    fs.mkdirSync(binDir, { recursive: true });
    const cachedExe = path.join(binDir, 'rdpsign.exe');
    fs.writeFileSync(cachedExe, 'fake-rdpsign');
    const signer = new RdpSigner({ log: silentLog, certDir, binDir });
    const p = await signer.resolveRdpsignPath();
    assert.equal(p, cachedExe);
    assert.equal(signer.signingUnavailableReason, null);
  });

  it('resolveRdpsignPath() restores newest WinSxS copy when System32 is empty', async () => {
    const winDir = makeTempDir();          // pretend C:\Windows
    const binDir = path.join(certDir, 'bin');
    const winsxs = path.join(winDir, 'WinSxS');
    // Stage three on-disk packages; only the file itself in candidate dirs
    // matters because the resolver checks per-file existence.
    const pkgs = [
      'amd64_microsoft-windows-t..lishing-wmiprovider_31bf3856ad364e35_10.0.26100.1150_none_d11fa90f43730842',
      'amd64_microsoft-windows-t..lishing-wmiprovider_31bf3856ad364e35_10.0.26100.8328_none_d1065f634386ad38',
      'amd64_microsoft-windows-t..lishing-wmiprovider_31bf3856ad364e35_10.0.26100.8115_none_d11b434943770f1c',
      // Unrelated entry that must be ignored even though it's amd64_*.
      'amd64_unrelated-package_31bf3856ad364e35_10.0.26100.9999_none_xxxx',
    ];
    for (const pkg of pkgs) {
      const dir = path.join(winsxs, pkg);
      fs.mkdirSync(dir, { recursive: true });
      // Don't stage rdpsign.exe in the unrelated package — it would fail
      // the regex anyway, but staging adds noise.
      if (!pkg.startsWith('amd64_unrelated')) {
        fs.writeFileSync(path.join(dir, 'rdpsign.exe'), `version-${pkg}`);
      }
    }
    const signer = new RdpSigner({ log: silentLog, certDir, winDir, binDir });
    const p = await signer.resolveRdpsignPath();
    assert.equal(p, path.join(binDir, 'rdpsign.exe'),
      'resolver should return the cache path it just populated');
    assert.ok(fs.existsSync(p), 'cache file must be present after restore');
    // Newest = 8328 — verify content was copied from THAT package, not 1150 or 8115.
    const restored = fs.readFileSync(p, 'utf-8');
    assert.match(restored, /10\.0\.26100\.8328/);
    assert.equal(signer.signingUnavailableReason, null);

    // Cleanup the staged WinSxS tree (binDir is under certDir parent so it
    // gets reaped indirectly when the test temp dir is torn down).
    try { fs.rmSync(winDir, { recursive: true, force: true }); } catch {}
  });

  it('resolveRdpsignPath() memoizes — second call hits no fs', async () => {
    const signer = new RdpSigner({
      log: silentLog, certDir, binDir: path.join(certDir, 'bin'),
      fsImpl: fsWithSystemRdpsign(),
    });
    const a = await signer.resolveRdpsignPath();
    // Now switch in an fsImpl that throws on every call. If the resolver
    // were to re-walk, the test would explode.
    signer.fs = { existsSync: () => { throw new Error('should not be called'); } };
    const b = await signer.resolveRdpsignPath();
    assert.equal(a, b);
  });

  it('resolveRdpsignPath() returns null and emits "unavailable" once when nothing found', async () => {
    // Empty winDir → no System32, no WinSxS, no cache → total miss.
    const winDir = makeTempDir();
    const events = [];
    const signer = new RdpSigner({
      log: silentLog, certDir, winDir, binDir: path.join(certDir, 'bin'),
    });
    signer.on('unavailable', (data) => events.push(data));

    const p1 = await signer.resolveRdpsignPath();
    const p2 = await signer.resolveRdpsignPath();    // memoized — must NOT re-emit
    assert.equal(p1, null);
    assert.equal(p2, null);
    assert.equal(events.length, 1, 'unavailable event must fire exactly once');
    assert.equal(events[0].reason, 'missing');
    assert.equal(signer.signingUnavailableReason, 'missing');

    try { fs.rmSync(winDir, { recursive: true, force: true }); } catch {}
  });

  it('sign() returns false (no rdpsign call) when path resolves to null', async () => {
    fs.writeFileSync(path.join(certDir, 'thumbprint.txt'), FAKE_THUMBPRINT);
    const winDir = makeTempDir();    // empty — nothing to find
    const calls = [];
    const runCmd = async (file, args) => {
      calls.push({ file, args });
      if (path.win32.basename(file).toLowerCase() === 'powershell.exe') {
        return { stdout: 'yes\n', stderr: '' };
      }
      throw new Error(`rdpsign should not have been invoked, got: ${file}`);
    };
    const signer = new RdpSigner({
      log: silentLog, certDir, runCmd, winDir, binDir: path.join(certDir, 'bin'),
    });
    const ok = await signer.sign('C:/tmp/foo.rdp');
    assert.equal(ok, false);
    assert.ok(!calls.some(c => path.win32.basename(c.file).toLowerCase() === 'rdpsign.exe'),
      'rdpsign.exe must not be invoked when path resolution failed');

    try { fs.rmSync(winDir, { recursive: true, force: true }); } catch {}
  });

  it('_compareWinSxsVersions sorts ascending by embedded build number', () => {
    const signer = new RdpSigner({ log: silentLog, certDir });
    const names = [
      'amd64_microsoft-windows-t..lishing-wmiprovider_x_10.0.26100.8328_y_z',
      'amd64_microsoft-windows-t..lishing-wmiprovider_x_10.0.26100.1150_y_z',
      'amd64_microsoft-windows-t..lishing-wmiprovider_x_10.0.26100.8115_y_z',
      'no_version_string_here',
    ];
    names.sort((a, b) => signer._compareWinSxsVersions(a, b));
    // Versionless entry sorts first, then ascending build numbers.
    assert.match(names[0], /no_version/);
    assert.match(names[1], /26100\.1150/);
    assert.match(names[2], /26100\.8115/);
    assert.match(names[3], /26100\.8328/);
  });
});
