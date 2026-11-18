'use strict';

/**
 * „Mein Profil › Meine Orte“ (GateControl 1.299) for the e2e mock server: the core's fake (gatecontrol-client-core
 * test/fixtures/places-server.js — GET / POST …/me/profile/places, GET / PATCH / DELETE …/:id with 409 IN_USE unless
 * ?force=1, POST …/:id/used, GET …/me/places/search with SEARCH_OFF) mounted into the mock server with srv.handle().
 * Names and addresses are made up.
 *
 *   const pl = await mock.setPlaces({ search: 'osm' | 'off', family, places });   // pl.srv.state.places, pl.srv.calls
 */

const path = require('path');

function coreDir() {
  const root = path.join(__dirname, '..', '..', '..');
  try {
    return path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [root] }));
  } catch {
    return path.join(root, '..', 'gatecontrol-client-core');
  }
}

async function createPlaces(opts = {}) {
  const { placesServer } = require(path.join(coreDir(), 'test', 'fixtures', 'places-server.js'));
  const srv = await placesServer(opts);
  return {
    srv,
    /** → true when the request was one of „Meine Orte“ (answered). */
    handle: (req, res, raw) => srv.handle(req, res, raw),
    close: () => srv.close(),
  };
}

module.exports = { createPlaces };
