'use strict';

// UI steps of the Pro client shared by the specs (selectors by id, so the
// tests do not depend on the UI language).
const { expect } = require('@playwright/test');

/** First-run setup assistant with an API key against the mock server. */
async function setupWithApiKey(page, mock) {
  await expect(page.locator('#page-setup')).toHaveClass(/active/);
  await page.locator('#setup-opt-code').click();
  await page.locator('#setup-url').fill(mock.url);
  await page.locator('#setup-key').fill(mock.token);
  await page.locator('#setup-submit').click();
  await expect(page.locator('#setup-done')).toHaveClass(/active/);
  await page.locator('#setup-later').click();
  await expect(page.locator('#page-status')).toHaveClass(/active/);
}

async function openSettingsTab(page, tab) {
  await page.locator('#nav-settings').click();
  await expect(page.locator('#page-settings')).toHaveClass(/active/);
  await page.locator(`#settings-tabs [data-tab="${tab}"]`).click();
  await expect(page.locator(`#set-${tab}`)).toHaveClass(/active/);
}

/** Settings → About → "Check for updates". */
async function checkForUpdatesManually(page) {
  await openSettingsTab(page, 'about');
  await page.locator('#nav-update').click();
}

const updateBanner = (page) => page.locator('#update-card');
const updateInstallButton = (page) => page.locator('#update-install');

module.exports = { setupWithApiKey, openSettingsTab, checkForUpdatesManually, updateBanner, updateInstallButton };
