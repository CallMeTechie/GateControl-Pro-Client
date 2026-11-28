'use strict';

// What the app shows for a target (src/renderer/target-label.js, no DOM): the name only, the address only as
// the fallback without a name — Dienste page, Fernzugriff (list, detail head, dialogs), the running sessions
// (sidebar, Fernzugriff card) and the tray menu "RDP Sessions".

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const L = require('../src/renderer/target-label');

describe('target-label: services', () => {
  it('a service with a name: only its name, never its domain or URL', () => {
    const svc = { name: 'Wiki', domain: 'wiki.lan', url: 'https://wiki.lan:8443/start' };
    assert.equal(L.serviceLabel(svc), 'Wiki');
    assert.ok(!L.serviceLabel(svc).includes('wiki.lan'));
  });

  it('without a name: the domain, else the host of the URL', () => {
    assert.equal(L.serviceLabel({ name: '  ', domain: 'wiki.lan', url: 'https://x.lan/' }), 'wiki.lan');
    assert.equal(L.serviceLabel({ url: 'https://wiki.lan:8443/start' }), 'wiki.lan:8443');
    assert.equal(L.serviceLabel({ url: 'wiki.lan/start' }), 'wiki.lan');
    assert.equal(L.serviceLabel({}), '');
    assert.equal(L.serviceLabel(null), '');
  });

  it('the initial follows the label, ? without one', () => {
    assert.equal(L.initial('Wiki'), 'W');
    assert.equal(L.initial(' Ärzte'), 'Ä');
    assert.equal(L.initial(''), '?');
    assert.equal(L.initial(undefined), '?');
  });
});

describe('target-label: Fernzugriff', () => {
  const route = { id: 7, name: 'Buchhaltung-PC', host: '10.0.0.21', port: 3389 };

  it('a host with a name: only the name, no "IP:Port"', () => {
    assert.equal(L.rdpLabel(route), 'Buchhaltung-PC');
    assert.ok(!L.rdpLabel(route).includes('10.0.0.21'));
  });

  it('without a name: host:port (3389 when missing)', () => {
    assert.equal(L.rdpLabel({ ...route, name: '' }), '10.0.0.21:3389');
    assert.equal(L.rdpLabel({ host: '10.0.0.22', port: 3390 }), '10.0.0.22:3390');
    assert.equal(L.rdpLabel({ host: '10.0.0.23' }), '10.0.0.23:3389');
    assert.equal(L.rdpAddress({}), '');
    assert.equal(L.rdpLabel(null), '');
  });

  it('a running session (tray, sidebar): its name, the route\'s name, else its host or route id', () => {
    assert.equal(L.sessionLabel({ routeId: 7, host: '10.0.0.21', name: 'Buchhaltung-PC' }), 'Buchhaltung-PC');
    assert.equal(L.sessionLabel({ routeId: 7, host: '10.0.0.21' }, route), 'Buchhaltung-PC');
    assert.equal(L.sessionLabel({ routeId: 7, host: '10.0.0.21', name: null }), '10.0.0.21');
    assert.equal(L.sessionLabel({ routeId: 7 }), '7');
    assert.equal(L.sessionLabel(null), '');
  });
});
