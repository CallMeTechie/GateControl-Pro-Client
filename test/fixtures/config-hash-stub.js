'use strict';
// Test stand-in for the private @callmetechie/gatecontrol-config-hash package
// (GitHub Packages, needs a token): only validateWgConfig is used by the IPC
// handlers under test.
module.exports = {
  validateWgConfig: (text) => {
    const ok = /\[Interface\]/.test(String(text)) && /\[Peer\]/.test(String(text));
    return { ok, errors: ok ? [] : ['missing [Interface]/[Peer]'], warnings: [] };
  },
};
