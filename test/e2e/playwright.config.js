'use strict';

// E2E suite for the unpackaged app (`electron .` in GC_E2E mode).
// Run: npm run test:e2e   (Linux needs a display, e.g. xvfb-run)
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: __dirname,
  testMatch: '*.spec.js',
  outputDir: 'test-results',
  // One Electron instance at a time (single-instance lock, tray, timing).
  workers: 1,
  fullyParallel: false,
  timeout: 90000,
  expect: { timeout: 15000 },
  retries: 0,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI
    ? [['list'], ['html', { outputFolder: 'playwright-report', open: 'never' }], ['github']]
    : [['list']],
});
