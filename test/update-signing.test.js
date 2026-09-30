'use strict';

// Signed auto-updates: the public key comes from build/update-signing.pub
// (single source of truth, shipped via extraResources), the placeholder keeps
// the updater disabled, main.js hands key + product to the core Updater, and
// scripts/sign-update.js produces a manifest the core accepts.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const PRODUCT = 'pro';
const SETUP_PREFIX = 'GateControl Pro Client Setup';
const { loadUpdatePublicKey, PLACEHOLDER } = require('../src/main/update-public-key');
const pkg = require('../package.json');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'gc-sign-test-'));
}

function keyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    pub: publicKey.export({ type: 'spki', format: 'pem' }),
    priv: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

function runSign(args, env = {}) {
  const e = { ...process.env, ...env };
  delete e.GITHUB_OUTPUT;
  if (!('UPDATE_SIGNING_KEY' in env)) delete e.UPDATE_SIGNING_KEY;
  return spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'sign-update.js'), ...args], { env: e, encoding: 'utf8' });
}

function findCore() {
  try {
    return path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [ROOT] }));
  } catch { /* not installed */ }
  for (const dir of [path.join(ROOT, '.core'), path.join(ROOT, '..', 'gatecontrol-client-core')]) {
    if (fs.existsSync(path.join(dir, 'src', 'services', 'updater.js'))) return dir;
  }
  return null;
}

describe('update public key', () => {
  it('the committed key file is either the placeholder or an Ed25519 SPKI PEM', () => {
    const text = fs.readFileSync(path.join(ROOT, 'build', 'update-signing.pub'), 'utf8');
    if (text.includes(PLACEHOLDER)) {
      assert.equal(loadUpdatePublicKey(), null, 'placeholder must disable the updater');
    } else {
      assert.equal(crypto.createPublicKey(text).asymmetricKeyType, 'ed25519');
      assert.equal(loadUpdatePublicKey(), text);
    }
  });

  it('loads a real key and treats placeholder / missing / non-PEM as no key', () => {
    const dir = tmpDir();
    const { pub } = keyPair();
    fs.writeFileSync(path.join(dir, 'real.pub'), pub);
    fs.writeFileSync(path.join(dir, 'placeholder.pub'), `${PLACEHOLDER}\n`);
    fs.writeFileSync(path.join(dir, 'junk.pub'), 'hello');
    assert.equal(loadUpdatePublicKey([path.join(dir, 'real.pub')]), pub);
    assert.equal(loadUpdatePublicKey([path.join(dir, 'missing.pub'), path.join(dir, 'real.pub')]), pub);
    assert.equal(loadUpdatePublicKey([path.join(dir, 'placeholder.pub')]), null);
    assert.equal(loadUpdatePublicKey([path.join(dir, 'junk.pub')]), null);
    assert.equal(loadUpdatePublicKey([path.join(dir, 'missing.pub')]), null);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('ships build/update-signing.pub as resources/update-signing.pub', () => {
    assert.ok(pkg.build.extraResources.some((r) => r.from === 'build/update-signing.pub' && r.to === 'update-signing.pub'));
  });

  it('main.js hands the public key and product to the Updater', () => {
    const main = fs.readFileSync(path.join(ROOT, 'src', 'main', 'main.js'), 'utf8');
    const call = main.match(/new Updater\(\{([\s\S]*?)\}\)/);
    assert.ok(call, 'new Updater({...}) not found');
    assert.match(call[1], /publicKey:\s*loadUpdatePublicKey\(\)/);
    assert.match(call[1], new RegExp(`product:\\s*'${PRODUCT}'`));
    assert.match(main, /require\('\.\/update-public-key'\)/);
  });

  it('the release workflow signs, gates on the key and uploads manifest + signature', () => {
    const wf = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
    assert.match(wf, new RegExp(`sign-update\\.js --product ${PRODUCT} --check`));
    assert.match(wf, new RegExp(`sign-update\\.js --product ${PRODUCT} --dist dist`));
    assert.match(wf, /UPDATE_SIGNING_KEY: \$\{\{ secrets\.UPDATE_SIGNING_KEY \}\}/);
    assert.match(wf, /dist\/update-manifest\.json\.sig/);
    assert.match(wf, /dist\/\$\{\{ steps\.sign\.outputs\.fileName \}\}/);
    // the gate runs before the version bump is pushed, and the push only
    // happens after the build was signed (no tag without a release)
    const push = wf.indexOf('git push --atomic origin HEAD:master');
    assert.ok(push > 0, 'atomic push of commit + tag');
    assert.ok(wf.indexOf('--check') < push);
    assert.ok(wf.indexOf(`--product ${PRODUCT} --dist dist`) < push);
    assert.ok(push < wf.indexOf('name: Create GitHub Release'));
    assert.ok(!wf.includes('git push origin master --tags'), 'no push before the build');
  });
});

describe('scripts/sign-update.js', () => {
  function fixture() {
    const dir = tmpDir();
    const dist = path.join(dir, 'dist');
    fs.mkdirSync(dist);
    const installer = Buffer.from(`installer ${Math.random()}`.repeat(500));
    fs.writeFileSync(path.join(dist, `${SETUP_PREFIX} ${pkg.version}.exe`), installer);
    fs.writeFileSync(path.join(dist, `${SETUP_PREFIX} ${pkg.version}.exe.blockmap`), 'x');
    const keys = keyPair();
    fs.writeFileSync(path.join(dir, 'update-signing.pub'), keys.pub);
    return { dir, dist, installer, keys, pubFile: path.join(dir, 'update-signing.pub') };
  }

  it('fails without the secret', () => {
    const f = fixture();
    const r = runSign(['--product', PRODUCT, '--dist', f.dist, '--pub', f.pubFile]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /UPDATE_SIGNING_KEY fehlt/);
    const c = runSign(['--product', PRODUCT, '--check', '--pub', f.pubFile], { UPDATE_SIGNING_KEY: '' });
    assert.equal(c.status, 1);
  });

  it('fails while the committed public key is still the placeholder', () => {
    const f = fixture();
    fs.writeFileSync(f.pubFile, `${PLACEHOLDER}\n`);
    const r = runSign(['--product', PRODUCT, '--check', '--pub', f.pubFile], { UPDATE_SIGNING_KEY: f.keys.priv });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Platzhalter/);
  });

  it('fails when secret and public key do not belong together', () => {
    const f = fixture();
    const r = runSign(['--product', PRODUCT, '--check', '--pub', f.pubFile], { UPDATE_SIGNING_KEY: keyPair().priv });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /passt nicht/);
  });

  it('renames the installer to its asset name and writes a verifiable canonical manifest', () => {
    const f = fixture();
    const check = runSign(['--product', PRODUCT, '--check', '--pub', f.pubFile], { UPDATE_SIGNING_KEY: f.keys.priv });
    assert.equal(check.status, 0, check.stderr);

    const r = runSign(['--product', PRODUCT, '--dist', f.dist, '--pub', f.pubFile], { UPDATE_SIGNING_KEY: f.keys.priv });
    assert.equal(r.status, 0, r.stderr);
    const fileName = `${SETUP_PREFIX.replace(/ /g, '.')}.${pkg.version}.exe`;
    assert.ok(r.stdout.includes(`fileName=${fileName}`), r.stdout);
    assert.ok(fs.existsSync(path.join(f.dist, fileName)));

    const manifest = fs.readFileSync(path.join(f.dist, 'update-manifest.json'), 'utf8');
    const sig = fs.readFileSync(path.join(f.dist, 'update-manifest.json.sig'), 'utf8');
    const expected = JSON.stringify({
      schema: 1, product: PRODUCT, version: pkg.version, fileName,
      sha256: crypto.createHash('sha256').update(f.installer).digest('hex'), size: f.installer.length,
    });
    assert.equal(manifest, expected);
    assert.ok(crypto.verify(null, Buffer.from(manifest), f.keys.pub, Buffer.from(sig, 'base64')));

    // Accepted by the core updater's verifier when that core version has it.
    const coreDir = findCore();
    if (coreDir) {
      const realResolve = Module._resolveFilename;
      Module._resolveFilename = function (request, ...rest) {
        if (request === 'electron') return path.join(__dirname, 'fixtures', 'electron-stub.js');
        return realResolve.call(this, request, ...rest);
      };
      try {
        const Updater = require(path.join(coreDir, 'src', 'services', 'updater.js'));
        if (typeof Updater.verifyUpdateManifest === 'function') {
          const res = Updater.verifyUpdateManifest({
            manifest, signature: sig, publicKey: f.keys.pub, product: PRODUCT,
            offeredVersion: pkg.version, currentVersion: '0.0.1',
          });
          assert.equal(res.ok, true, res.reason);
        }
      } catch (err) {
        if (!/Cannot find module 'axios'/.test(err.message)) throw err;
      } finally {
        Module._resolveFilename = realResolve;
      }
    }
    fs.rmSync(f.dir, { recursive: true, force: true });
  });

  it('refuses a dist folder without exactly one installer', () => {
    const f = fixture();
    fs.writeFileSync(path.join(f.dist, `${SETUP_PREFIX} 0.0.0.exe`), 'second');
    const r = runSign(['--product', PRODUCT, '--dist', f.dist, '--pub', f.pubFile], { UPDATE_SIGNING_KEY: f.keys.priv });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /genau ein/);
  });
});
