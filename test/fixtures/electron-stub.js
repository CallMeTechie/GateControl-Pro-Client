'use strict';

// Minimal electron double for loading core modules in the node --test runner.
module.exports = {
  app: { getName: () => 'GateControl Pro Client', getVersion: () => '0.0.1' },
  shell: { openPath: async () => '' },
};
