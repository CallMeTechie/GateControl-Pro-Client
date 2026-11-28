/**
 * GateControl -- what the app shows for a target (no DOM, no Electron)
 *
 * Targets (a service of the Dienste page, a host of Fernzugriff, a running RDP session) are shown by
 * their name only — the address is not shown where a name is there. Without a name the address is
 * the fallback, so the line is never empty:
 *
 *   hostOf(url)            the host part of a URL ("https://wiki.lan:8443/x" → "wiki.lan:8443")
 *   serviceLabel(svc)      a service: its name, else its domain, else the host of its URL
 *   rdpAddress(route)      a host of Fernzugriff: "host:port" (port 3389 when missing), '' without a host
 *   rdpLabel(route)        a host of Fernzugriff: its name, else rdpAddress(route)
 *   sessionLabel(s, route) a running RDP session: its name, the name of its route, else its host
 *   initial(label)         the first character of a label for the round initial, '?' when empty
 *
 * Input forms (the address the person types in Einstellungen / Setup) and the Diagnose / Protokoll page
 * keep showing addresses; this module is only for the places that show a target.
 *
 * Loaded as a plain script by the renderer (window.GCTargetLabel), required by the main process (tray menu,
 * src/main/main.js) and by the node tests (test/target-label.test.js).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCTargetLabel = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const text = (v) => (typeof v === 'string' ? v.trim() : (typeof v === 'number' ? String(v) : ''));

	function hostOf(url) {
		const u = text(url);
		if (!u) return '';
		try { return new URL(u).host || u; } catch { return u.replace(/^https?:\/\//i, '').replace(/\/.*$/, ''); }
	}

	function serviceLabel(svc) {
		if (!svc) return '';
		return text(svc.name) || text(svc.domain) || hostOf(svc.url);
	}

	function rdpAddress(route) {
		const host = text(route && route.host);
		if (!host) return '';
		return `${host}:${text(route.port) || 3389}`;
	}

	function rdpLabel(route) {
		if (!route) return '';
		return text(route.name) || rdpAddress(route);
	}

	function sessionLabel(s, route) {
		if (!s) return '';
		return text(s.name) || text(route && route.name) || text(s.host) || text(s.routeId);
	}

	function initial(label) {
		return Array.from(text(label))[0] || '?';
	}

	return { hostOf, serviceLabel, rdpAddress, rdpLabel, sessionLabel, initial };
});
