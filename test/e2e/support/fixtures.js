'use strict';

/**
 * Playwright fixtures: mock server, throwaway update signing key and a
 * launcher for the unpackaged app in e2e mode (GC_E2E=1, see
 * src/main/e2e-guard.js and test/e2e/support/app-hooks.js).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const base = require('@playwright/test');
const { _electron: electron } = require('@playwright/test');
const { startMockServer, buildUpdateOffer } = require('./mock-server');

const APP_ROOT = path.join(__dirname, '..', '..', '..');
const PRODUCT = 'pro';
const OFFERED_VERSION = '99.0.0';

function readEvents(dir) {
  try {
    return fs.readFileSync(path.join(dir, 'events.jsonl'), 'utf8')
      .split('\n').filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

const test = base.test.extend({
  // eslint-disable-next-line no-empty-pattern
  mock: async ({}, use) => {
    const server = await startMockServer();
    await use(server);
    await server.close();
  },

  // eslint-disable-next-line no-empty-pattern
  updateKey: async ({}, use, testInfo) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const pubFile = testInfo.outputPath('update-signing.test.pub');
    fs.mkdirSync(path.dirname(pubFile), { recursive: true });
    fs.writeFileSync(pubFile, publicKey.export({ type: 'spki', format: 'pem' }));
    await use({ privateKey, pubFile });
  },

  /** Offers a signed update (or a broken one, see buildUpdateOffer modes). */
  offerUpdate: async ({ mock, updateKey }, use) => {
    await use((mode = 'valid') => {
      const installer = Buffer.concat([Buffer.from('MZ'), crypto.randomBytes(64 * 1024)]);
      const offer = buildUpdateOffer({
        product: PRODUCT, version: OFFERED_VERSION, installer, privateKey: updateKey.privateKey, mode,
      });
      mock.setUpdate(offer);
      return offer;
    });
  },

  launchApp: async ({ mock, updateKey }, use, testInfo) => {
    const launched = [];
    await use(async () => {
      const dir = testInfo.outputPath(`app-${launched.length}`);
      fs.mkdirSync(dir, { recursive: true });
      const caFile = path.join(dir, 'mock-ca.pem');
      fs.writeFileSync(caFile, mock.caPem);

      const env = {
        ...process.env,
        GC_E2E: '1',
        GC_E2E_DIR: dir,
        GC_E2E_CA: caFile,
        GC_E2E_UPDATE_PUBKEY: updateKey.pubFile,
        ELECTRON_ENABLE_LOGGING: '1',
      };
      delete env.ELECTRON_RUN_AS_NODE;

      const args = [APP_ROOT];
      if (process.platform === 'linux') args.push('--no-sandbox');
      const app = await electron.launch({ args, env, cwd: APP_ROOT, timeout: 60000 });

      const logFile = path.join(dir, 'main-process.log');
      const logStream = fs.createWriteStream(logFile);
      app.process().stdout.on('data', (d) => logStream.write(d));
      app.process().stderr.on('data', (d) => logStream.write(d));

      const exited = new Promise((resolve) => app.process().once('exit', (code) => resolve(code)));
      const entry = { app, proc: app.process(), dir, logFile, logStream, exited };
      launched.push(entry);

      await app.context().tracing.start({ screenshots: true, snapshots: true });

      const page = await app.firstWindow();
      entry.page = page;
      await page.waitForLoadState('domcontentloaded');
      // Start minimized is the default — open the window like the tray does.
      await app.evaluate(({ BrowserWindow }) => {
        const w = BrowserWindow.getAllWindows()[0];
        w.show();
        w.focus();
      });

      return {
        app,
        page,
        dir,
        exited,
        events: () => readEvents(dir),
        /** Runs the periodic update check now (same path as the 6h timer). */
        runScheduledUpdateCheck: () => app.evaluate(() => globalThis.__gcE2E.updater._check()),
        /** Queues answers (button index) for the next native message boxes. */
        answerDialogs: (answers) => app.evaluate((_e, a) => { globalThis.__gcE2E.dialogAnswers.push(...a); }, answers),
        dialogs: () => app.evaluate(() => globalThis.__gcE2E.dialogs),
        trayLabels: () => app.evaluate(() => globalThis.__gcE2E.trayLabels()),
        clickTrayItem: (pattern) => app.evaluate((_e, p) => globalThis.__gcE2E.clickTrayItem(p), pattern),
      };
    });

    const failed = testInfo.status !== testInfo.expectedStatus;
    for (const entry of launched) {
      const name = path.basename(entry.dir);
      if (entry.proc.exitCode === null) {
        if (failed) {
          if (entry.page && !entry.page.isClosed()) {
            await entry.page.screenshot({ path: testInfo.outputPath(`${name}-failure.png`) }).catch(() => {});
          }
          await entry.app.context().tracing.stop({ path: testInfo.outputPath(`${name}-trace.zip`) }).catch(() => {});
        }
        await Promise.race([
          entry.app.close().catch(() => {}),
          new Promise((r) => setTimeout(r, 10000)),
        ]);
        if (entry.proc.exitCode === null) entry.proc.kill();
      }
      entry.logStream.end();
      if (failed) {
        await testInfo.attach(`main-process-${name}.log`, { path: entry.logFile, contentType: 'text/plain' }).catch(() => {});
        const ev = path.join(entry.dir, 'events.jsonl');
        if (fs.existsSync(ev)) await testInfo.attach(`events-${name}.jsonl`, { path: ev, contentType: 'text/plain' });
      }
    }
  },
});

module.exports = { test, expect: base.expect, readEvents, PRODUCT, OFFERED_VERSION, APP_ROOT };
