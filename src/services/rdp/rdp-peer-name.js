'use strict';

/**
 * Which name of the target PC a Remote Desktop connection uses.
 *
 * The server answers device names in two zones („Namen im VPN“): the one the
 * admin chose (`peer_fqdn_primary`, e.g. laptop.vpn.example.com) and the old
 * one (`peer_fqdn`, e.g. laptop.gc.internal). Windows resolves a name
 * reliably only when a DNS rule of this app pins its zone to the VPN
 * resolver — so the chosen zone is used only then, otherwise the old name
 * (servers before 1.271 send only that one).
 *
 * @param {object} route - answer of GET /client/rdp/:id/connect
 * @param {(name: string) => boolean} hasDnsRuleFor - a rule of this app covers the zone of the name
 * @returns {string|null|undefined} the name to connect to, as `peer_fqdn` was before
 */
function pickPeerFqdn(route, hasDnsRuleFor) {
  if (!route) return null;
  const primary = route.peer_fqdn_primary;
  if (route.peer_fqdn && typeof primary === 'string' && primary && primary !== route.peer_fqdn) {
    let covered = false;
    try { covered = hasDnsRuleFor(primary) === true; } catch { covered = false; }
    if (covered) return primary;
  }
  return route.peer_fqdn;
}

module.exports = { pickPeerFqdn };
