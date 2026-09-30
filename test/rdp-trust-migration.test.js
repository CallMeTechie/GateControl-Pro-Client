'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const {
  runRdpTrustMigration,
  removeGlobalAuthLevelOverride,
  removeLegacySigningCert,
  buildCertCleanupScript,
  parseRegDword,
  STORE_KEY_OVERRIDE,
  STORE_KEY_CERT,
} = require('../src/services/rdp/rdp-trust-migration');

const silentLog = { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} };
const TSC_KEY = 'HKCU\\SOFTWARE\\Microsoft\\Terminal Server Client';
const THUMB = 'A1B2C3D4E5F60718293A4B5C6D7E8F9001020304';
const USERDATA = path.join('/fake', 'userData');

function regQueryOutput(type, data) {
  return `\r\n${TSC_KEY}\r\n    AuthenticationLevelOverride    ${type}    ${data}\r\n\r\n`;
}

function regNotFound() {
  const err = new Error('ERROR: The system was unable to find the specified registry key or value.');
  err.code = 1;
  return err;
}

// Records every call; `handler(file, args)` returns {stdout} or throws.
function mockRunCmd(handler) {
  const calls = [];
  const fn = async (file, args, opts) => {
    calls.push({ file, args, opts });
    return handler(file, args);
  };
  fn.calls = calls;
  return fn;
}

function mockStore(initial = {}) {
  const data = { ...initial };
  return {
    data,
    get: (k, d) => (k in data ? data[k] : d),
    set: (k, v) => { data[k] = v; },
  };
}

function mockFs(files = {}) {
  const existing = new Map(Object.entries(files));
  const removed = [];
  return {
    removed,
    existsSync: (p) => existing.has(p),
    readFileSync: (p) => {
      if (!existing.has(p)) throw new Error('ENOENT');
      return existing.get(p);
    },
    rmSync: (p) => { removed.push(p); existing.delete(p); },
  };
}

describe('parseRegDword', () => {
  it('parses hex DWORD output of reg query', () => {
    assert.equal(parseRegDword(regQueryOutput('REG_DWORD', '0x0'), 'AuthenticationLevelOverride'), 0);
    assert.equal(parseRegDword(regQueryOutput('REG_DWORD', '0x2'), 'AuthenticationLevelOverride'), 2);
  });
  it('returns null for other types', () => {
    assert.equal(parseRegDword(regQueryOutput('REG_SZ', '0'), 'AuthenticationLevelOverride'), null);
  });
});

describe('removeGlobalAuthLevelOverride', () => {
  it('deletes the value when it is REG_DWORD 0 (the value old versions wrote)', async () => {
    const run = mockRunCmd((file, args) => {
      if (args[0] === 'query') return { stdout: regQueryOutput('REG_DWORD', '0x0') };
      return { stdout: 'The operation completed successfully.' };
    });
    const res = await removeGlobalAuthLevelOverride({ runCmd: run, log: silentLog });
    assert.equal(res, 'removed');
    assert.equal(run.calls.length, 2);
    assert.deepEqual(run.calls[1].args, ['delete', TSC_KEY, '/v', 'AuthenticationLevelOverride', '/f']);
    assert.equal(run.calls[1].file, 'reg');
  });

  it('keeps a non-zero value (not set by GateControl)', async () => {
    const run = mockRunCmd(() => ({ stdout: regQueryOutput('REG_DWORD', '0x2') }));
    const res = await removeGlobalAuthLevelOverride({ runCmd: run, log: silentLog });
    assert.equal(res, 'kept');
    assert.equal(run.calls.length, 1);
    assert.equal(run.calls[0].args[0], 'query');
  });

  it('keeps a value of a different type', async () => {
    const run = mockRunCmd(() => ({ stdout: regQueryOutput('REG_SZ', '0') }));
    assert.equal(await removeGlobalAuthLevelOverride({ runCmd: run, log: silentLog }), 'kept');
    assert.equal(run.calls.length, 1);
  });

  it('does nothing when the value does not exist', async () => {
    const run = mockRunCmd(() => { throw regNotFound(); });
    assert.equal(await removeGlobalAuthLevelOverride({ runCmd: run, log: silentLog }), 'absent');
    assert.equal(run.calls.length, 1);
  });

  it('never writes the override', async () => {
    const run = mockRunCmd((file, args) => {
      if (args[0] === 'query') return { stdout: regQueryOutput('REG_DWORD', '0x0') };
      return { stdout: '' };
    });
    await removeGlobalAuthLevelOverride({ runCmd: run, log: silentLog });
    assert.ok(run.calls.every((c) => c.args[0] !== 'add'));
  });
});

describe('buildCertCleanupScript', () => {
  it('matches exact subject, self-signed issuer, code-signing EKU and thumbprint', () => {
    const s = buildCertCleanupScript(THUMB);
    assert.match(s, /\$subject = 'CN=GateControl RDP Signing'/);
    assert.match(s, /\$_.Subject -ceq \$subject -and \$_.Issuer -ceq \$subject/);
    assert.match(s, /\$eku = '1\.3\.6\.1\.5\.5\.7\.3\.3'/);
    assert.match(s, new RegExp(`\\$tp = '${THUMB}'`));
    assert.match(s, /'Root','TrustedPublisher','My'/);
    assert.match(s, /X509Store\(\$name, 'CurrentUser'\)/);
    assert.doesNotMatch(s, /LocalMachine/);
  });

  it('falls back to subject/EKU match without thumbprint', () => {
    assert.match(buildCertCleanupScript(null), /\$tp = \$null/);
  });

  it('rejects anything that is not a hex thumbprint (no script injection)', () => {
    assert.throws(() => buildCertCleanupScript("x'; Remove-Item C:\\ -Recurse; '"), /invalid thumbprint/);
  });
});

describe('removeLegacySigningCert', () => {
  const thumbFile = path.join(USERDATA, 'rdp-signing', 'thumbprint.txt');

  it('uses the recorded thumbprint and removes leftover files', async () => {
    const fsImpl = mockFs({
      [thumbFile]: THUMB.toLowerCase() + '\n',
      [path.join(USERDATA, 'rdp-signing')]: '',
      [path.join(USERDATA, 'bin', 'rdpsign.exe')]: '',
    });
    const run = mockRunCmd(() => ({ stdout: `removed Root ${THUMB}\r\nremoved TrustedPublisher ${THUMB}\r\nremoved My ${THUMB}\r\ntotal 3\r\n` }));
    const n = await removeLegacySigningCert({ runCmd: run, fsImpl, userDataDir: USERDATA, log: silentLog });
    assert.equal(n, 3);
    assert.equal(run.calls[0].file, 'powershell.exe');
    const script = run.calls[0].args[run.calls[0].args.length - 1];
    assert.match(script, new RegExp(`\\$tp = '${THUMB}'`));
    assert.deepEqual(fsImpl.removed.sort(), [
      path.join(USERDATA, 'bin', 'rdpsign.exe'),
      path.join(USERDATA, 'rdp-signing'),
    ].sort());
  });

  it('ignores a malformed thumbprint file', async () => {
    const fsImpl = mockFs({ [thumbFile]: 'garbage' });
    const run = mockRunCmd(() => ({ stdout: 'total 0' }));
    await removeLegacySigningCert({ runCmd: run, fsImpl, userDataDir: USERDATA, log: silentLog });
    assert.match(run.calls[0].args.at(-1), /\$tp = \$null/);
  });

  it('throws on unexpected PowerShell output', async () => {
    const run = mockRunCmd(() => ({ stdout: 'boom' }));
    await assert.rejects(
      removeLegacySigningCert({ runCmd: run, fsImpl: mockFs(), userDataDir: USERDATA, log: silentLog }),
      /unexpected cleanup output/,
    );
  });
});

describe('runRdpTrustMigration', () => {
  function happyRun() {
    return mockRunCmd((file, args) => {
      if (file === 'reg' && args[0] === 'query') return { stdout: regQueryOutput('REG_DWORD', '0x0') };
      if (file === 'reg') return { stdout: '' };
      return { stdout: 'total 1' };
    });
  }

  it('is a no-op on non-Windows platforms', async () => {
    const run = happyRun();
    const store = mockStore();
    await runRdpTrustMigration({ store, log: silentLog, userDataDir: USERDATA, platform: 'linux', runCmd: run, fsImpl: mockFs() });
    assert.equal(run.calls.length, 0);
    assert.deepEqual(store.data, {});
  });

  it('runs both steps once and records them', async () => {
    const run = happyRun();
    const store = mockStore();
    await runRdpTrustMigration({ store, log: silentLog, userDataDir: USERDATA, platform: 'win32', runCmd: run, fsImpl: mockFs() });
    assert.equal(store.data[STORE_KEY_OVERRIDE], true);
    assert.equal(store.data[STORE_KEY_CERT], true);
    assert.equal(run.calls.length, 3);

    await runRdpTrustMigration({ store, log: silentLog, userDataDir: USERDATA, platform: 'win32', runCmd: run, fsImpl: mockFs() });
    assert.equal(run.calls.length, 3, 'second start must not touch registry or cert store again');
  });

  it('does not mark a failed step as done and never throws', async () => {
    const run = mockRunCmd((file) => {
      if (file === 'reg') { const e = new Error('access denied'); e.code = 5; throw e; }
      throw new Error('powershell missing');
    });
    const store = mockStore();
    await runRdpTrustMigration({ store, log: silentLog, userDataDir: USERDATA, platform: 'win32', runCmd: run, fsImpl: mockFs() });
    assert.equal(store.data[STORE_KEY_OVERRIDE], undefined);
    assert.equal(store.data[STORE_KEY_CERT], undefined);
  });
});
