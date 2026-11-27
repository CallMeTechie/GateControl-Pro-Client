'use strict';

// Medien (Medien-Plugin W2): the app signed in to the mock server with the plugin Medien set (support/medien-mock.js)
// — the sources come from the server, nothing is set up on the PC. `tunnel`: the fake tunnel comes up when Medien
// starts it (the plugin's network rule: the fake Jellyfin and WebDAV are "away", only through the VPN).

const { setupWithApiKey } = require('./ui');

async function launchWithMedien({ launchApp, mock, jf = null, dav = null, tunnel = true, tab = true, version = null }) {
  const md = mock.setMedien({ jf, dav });
  md.tab = tab;
  if (version) md.version = version;
  const launched = await launchApp();
  if (tunnel) await launched.app.evaluate(() => { globalThis.__gcE2E.tunnelWorks = true; });
  await setupWithApiKey(launched.page, mock);
  return { ...launched, md };
}

module.exports = { launchWithMedien };
