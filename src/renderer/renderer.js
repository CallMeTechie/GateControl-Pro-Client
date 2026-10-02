/**
 * GateControl Pro Client -- Renderer
 * UI logic and state for the sidebar layout: overview, remote desktops,
 * services, log, settings and the setup assistant.
 *
 * Note: innerHTML is used ONLY for static SVG icon literals (no user data).
 * All user-facing text uses textContent for XSS safety.
 */

const {
	tunnel, server, config, killSwitch, rdpAllow, autostart, logs, update,
	services, traffic, dns, shell, peer, permissions, onPortalUrl, getVersion,
	window: win, rdp, onNavigate, locale,
} = window.gatecontrol;
const { t } = window.gatecontrol.i18n;

// ── Helpers ─────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

/** Create an element with optional class list and text content. */
function h(tag, cls, text) {
	const node = document.createElement(tag);
	if (cls) node.className = cls;
	if (text !== undefined && text !== null) node.textContent = text;
	return node;
}

function formatBytes(bytes) {
	if (!bytes || bytes <= 0) return '0 B';
	const units = ['B', 'KB', 'MB', 'GB', 'TB'];
	const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
	const val = (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0);
	return `${val} ${units[i]}`;
}

function formatSpeed(bytesPerSec) {
	if (!bytesPerSec || bytesPerSec < 1) return '0 B/s';
	if (bytesPerSec < 1024) return `${Math.round(bytesPerSec)} B/s`;
	if (bytesPerSec < 1048576) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
	return `${(bytesPerSec / 1048576).toFixed(1)} MB/s`;
}

function formatDuration(totalSeconds) {
	const n = Math.max(0, Math.floor(totalSeconds));
	const hh = Math.floor(n / 3600);
	const mm = Math.floor(n / 60) % 60;
	const ss = n % 60;
	return [hh, mm, ss].map((x) => String(x).padStart(2, '0')).join(':');
}

function hostOf(url) {
	if (!url) return '';
	try { return new URL(url).host || url; } catch { return String(url).replace(/^https?:\/\//i, '').replace(/\/.*$/, ''); }
}

function parseTags(tags) {
	if (Array.isArray(tags)) return tags;
	if (!tags) return [];
	try { const p = JSON.parse(tags); return Array.isArray(p) ? p : []; } catch { return []; }
}

// Static SVG icon constants (safe string literals, no user data)
const SVG_ICONS = {
	monitor: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
	play: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M7 4v16l13-8z"/></svg>',
	wol: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/></svg>',
	external: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>',
	trash: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></svg>',
	close: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>',
	stepIcons: '<svg class="si-done" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>'
		+ '<svg class="si-active spin" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-9-9"/></svg>'
		+ '<svg class="si-error" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>',
};

/**
 * Sets innerHTML with a static SVG icon. Only use with SVG_ICONS constants above.
 * NEVER pass user data to this function.
 */
function setStaticIcon(element, iconKey) {
	// eslint-disable-next-line no-unsanitized/property -- static SVG constants only
	element.innerHTML = SVG_ICONS[iconKey]; // SAFE: static string literal from SVG_ICONS
}

/** Button with a static icon and a text label. */
function iconButton(cls, iconKey, label, iconFirst = true) {
	const btn = h('button', cls);
	btn.type = 'button';
	const icon = h('span');
	icon.style.display = 'contents';
	setStaticIcon(icon, iconKey); // SAFE: static SVG
	const text = h('span', null, label);
	if (iconFirst) { btn.appendChild(icon); btn.appendChild(text); } else { btn.appendChild(text); btn.appendChild(icon); }
	return btn;
}

// ── Toasts ──────────────────────────────────────────────
function showToast(message, type = 'error', duration = 5000) {
	const host = $('#toasts');
	const toast = h('div', `toast toast-${type}`);
	toast.setAttribute('role', 'status');
	toast.appendChild(h('span', 'dot'));
	toast.appendChild(h('span', 'toast-text', message));
	const closeBtn = h('button', 'btn btn-ghost');
	closeBtn.type = 'button';
	closeBtn.setAttribute('aria-label', t('ui.close'));
	setStaticIcon(closeBtn, 'close'); // SAFE: static SVG
	toast.appendChild(closeBtn);

	const dismiss = () => {
		toast.classList.remove('show');
		setTimeout(() => toast.remove(), 300);
	};
	closeBtn.addEventListener('click', dismiss);
	host.appendChild(toast);
	requestAnimationFrame(() => toast.classList.add('show'));
	setTimeout(dismiss, duration);
}

// ── Switches (button[role=switch]) ──────────────────────
function setSwitch(sw, on) {
	if (!sw) return;
	sw.classList.toggle('on', !!on);
	sw.setAttribute('aria-checked', on ? 'true' : 'false');
}

function isSwitchOn(sw) {
	return !!sw && sw.classList.contains('on');
}

function bindSwitch(sw, onChange) {
	if (!sw) return;
	sw.addEventListener('click', () => {
		const next = !isSwitchOn(sw);
		setSwitch(sw, next);
		onChange(next);
	});
}

/** Segmented control: marks the clicked button as selected and reports its data-<attr> value. */
const camel = (attr) => attr.replace(/-([a-z])/g, (_, c) => c.toUpperCase());

function bindSeg(seg, attr, onPick) {
	if (!seg) return;
	seg.addEventListener('click', (e) => {
		const btn = e.target.closest(`[data-${attr}]`);
		if (!btn || !seg.contains(btn)) return;
		const value = btn.dataset[camel(attr)];
		selectSeg(seg, attr, value);
		onPick(value);
	});
}

function selectSeg(seg, attr, value) {
	if (!seg) return;
	seg.querySelectorAll(`[data-${attr}]`).forEach((b) => {
		const on = b.dataset[camel(attr)] === value;
		b.classList.toggle('on', on);
		b.setAttribute(b.getAttribute('role') === 'tab' ? 'aria-selected' : 'aria-pressed', on ? 'true' : 'false');
	});
}

// ── i18n DOM update ─────────────────────────────────────
function updateDOM() {
	$$('[data-i18n]').forEach((node) => { node.textContent = t(node.dataset.i18n); });
	$$('[data-i18n-placeholder]').forEach((node) => { node.placeholder = t(node.dataset.i18nPlaceholder); });
	$$('[data-i18n-title]').forEach((node) => { node.title = t(node.dataset.i18nTitle); });
	$$('[data-i18n-aria-label]').forEach((node) => { node.setAttribute('aria-label', t(node.dataset.i18nAriaLabel)); });
	document.documentElement.lang = window.gatecontrol.i18n.getLocale();
}

/** Re-render everything that is built from translated strings at runtime. */
function refreshTexts() {
	updateDOM();
	updateUI();
	renderRdp();
	renderServices();
	renderTraffic();
	renderSplit();
	renderLogs();
	renderSetupProgress();
	renderUpdateCard();
	renderExpiry();
	renderAbout();
}

// ── State ───────────────────────────────────────────────
let state = { status: 'disconnected', connected: false };
let activePermissions = { services: true, traffic: true, dns: true };
let rdpServices = [];
let rdpSessions = [];
let rdpFilter = 'all';
let selectedRdpId = null;
let currentRdpRoute = null; // route being viewed/connected
let currentPortalUrl = null; // pushed from main on connect/disconnect
let currentPage = 'status';
let appVersion = '';
let serverUrl = '';
let servicesList = [];
let trafficData = null;
let usagePeriod = 'last7d';
let pendingUpdate = null;
let updateCardHidden = false;
// Server policy (channel / minimum version / mandatory) from the core updater.
// Channel and minimum version are assigned by the server, read-only here.
let updatePolicy = null;
let expiryInfo = null;
let expiryHidden = false;
let logText = '';
let logLevel = 'all';
let logPeriod = 'all';
let splitSaved = { enabled: false, routes: [] };
let splitDraft = { enabled: false, routes: [] };
let setupStep = 'choose';
let setupDone = null;

// ── DOM Elements ────────────────────────────────────────
const el = {
	connSwitch:      $('#conn-switch'),
	connLabel:       $('#conn-label'),
	connSub:         $('#conn-sub'),
	statusLabel:     $('#status-label'),
	heroSub:         $('#hero-sub'),
	heroErrorText:   $('#hero-error-text'),
	connectBtn:      $('#connect-btn'),
	disconnectBtn:   $('#disconnect-btn'),
	portalBtn:       $('#portal-btn'),
	statEndpoint:    $('#stat-endpoint'),
	statHandshake:   $('#stat-handshake'),
	statSince:       $('#stat-since'),
	statRx:          $('#stat-rx'),
	statTx:          $('#stat-tx'),
	statRxSpeed:     $('#stat-rx-speed'),
	statTxSpeed:     $('#stat-tx-speed'),
	killswitchQuick: $('#killswitch-quick'),
	killswitchToggle: $('#killswitch-toggle'),
	rdpAllowToggle:  $('#rdp-allow-toggle'),
	serverUrl:       $('#server-url'),
	apiKey:          $('#api-key'),
	serverStatus:    $('#server-status'),
	optAutostart:    $('#opt-autostart'),
	optMinimized:    $('#opt-minimized'),
	optAutoconnect:  $('#opt-autoconnect'),
	optCheckInterval: $('#opt-check-interval'),
	optPollInterval: $('#opt-poll-interval'),
	splitRoutesSection: $('#split-routes-section'),
	logRows:         $('#log-rows'),
	logEmpty:        $('#log-empty'),
};

// ── Locale initialization ───────────────────────────────
let localeReady = false;

locale.get().then((loc) => {
	if (loc) locale.set(loc);
	const selectEl = $('#locale-select');
	if (selectEl) selectEl.value = loc || 'de';
	refreshTexts();
	localeReady = true;
}).catch(() => { localeReady = true; });

locale.onChange((loc) => {
	if (!localeReady) return; // skip initial set echo
	const selectEl = $('#locale-select');
	if (selectEl) selectEl.value = loc;
	refreshTexts();
});

$('#locale-select')?.addEventListener('change', (e) => {
	locale.set(e.target.value);
});

// ── Version ─────────────────────────────────────────────
getVersion().then((v) => {
	appVersion = v || '';
	$('#app-version').textContent = appVersion ? `v${appVersion}` : '';
	renderAbout();
});

function renderAbout() {
	const aboutEl = $('#about-version');
	if (aboutEl) aboutEl.textContent = appVersion ? t('ui.about.version', { version: appVersion }) : '';
}

// ══════════════════════════════════════════════════════════
//  THEME  (app.theme: 'dark' | 'light' | 'system')
// ══════════════════════════════════════════════════════════
let themeMode = 'dark';
const darkQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

function resolvedTheme() {
	if (themeMode === 'system') return darkQuery && !darkQuery.matches ? 'light' : 'dark';
	return themeMode === 'light' ? 'light' : 'dark';
}

function applyTheme(mode) {
	themeMode = ['light', 'dark', 'system'].includes(mode) ? mode : 'dark';
	if (resolvedTheme() === 'light') {
		document.documentElement.setAttribute('data-theme', 'light');
	} else {
		document.documentElement.removeAttribute('data-theme');
	}
	selectSeg($('#theme-seg'), 'theme-mode', themeMode);
}

function setTheme(mode) {
	applyTheme(mode);
	config.set('app.theme', themeMode);
}

darkQuery?.addEventListener?.('change', () => { if (themeMode === 'system') applyTheme('system'); });

config.get('app.theme').then((theme) => applyTheme(theme || 'dark'));

$('#theme-toggle').addEventListener('click', () => setTheme(resolvedTheme() === 'light' ? 'dark' : 'light'));
bindSeg($('#theme-seg'), 'theme-mode', (mode) => setTheme(mode));

// ══════════════════════════════════════════════════════════
//  TITLEBAR
// ══════════════════════════════════════════════════════════
$('#btn-minimize').addEventListener('click', () => win.minimize());
$('#btn-close').addEventListener('click', () => win.close());

// ══════════════════════════════════════════════════════════
//  NAVIGATION
// ══════════════════════════════════════════════════════════
const PAGES = ['status', 'rdp', 'services', 'logs', 'settings', 'setup'];

function navigateTo(page, opts = {}) {
	if (page === 'overview') page = 'status';
	if (!PAGES.includes(page)) return;
	const prev = currentPage;
	currentPage = page;

	$$('.nav[data-page]').forEach((b) => b.classList.toggle('on', b.dataset.page === page));
	$$('.nav[data-page]').forEach((b) => {
		if (b.dataset.page === page) b.setAttribute('aria-current', 'page');
		else b.removeAttribute('aria-current');
	});
	$$('.page').forEach((p) => p.classList.toggle('active', p.id === `page-${page}`));
	document.body.classList.toggle('setup-mode', page === 'setup');

	// Remote Desktops: status polling runs only while the page is visible
	if (page === 'rdp' && prev !== 'rdp') {
		rdp.panelOpen();
		loadRdpServices();
	} else if (prev === 'rdp' && page !== 'rdp') {
		rdp.panelClose();
	}

	if (page === 'logs') refreshLogs();
	if (page === 'settings' && opts.tab) showSettingsTab(opts.tab);
	if (page === 'setup' && prev !== 'setup') resetSetup();
	if (prev === 'setup' && page !== 'setup') stopQRScan();
}

$$('.nav[data-page]').forEach((btn) => {
	btn.addEventListener('click', () => navigateTo(btn.dataset.page));
});

// Navigation from main process
onNavigate((page) => navigateTo(page));

$('#services-all-btn').addEventListener('click', () => navigateTo('services'));
$('#hero-log-btn').addEventListener('click', () => navigateTo('logs'));
$('#routing-btn').addEventListener('click', () => navigateTo('settings', { tab: 'split' }));

// ══════════════════════════════════════════════════════════
//  TUNNEL STATE
// ══════════════════════════════════════════════════════════
function connState() {
	const { status, connected } = state;
	if (connected || status === 'connected') return 'connected';
	if (status === 'connecting' || status === 'reconnecting') return 'connecting';
	if (status === 'error') return 'error';
	return 'disconnected';
}

function connectedSeconds() {
	if (!state.connectedSince) return 0;
	const since = new Date(state.connectedSince).getTime();
	return Number.isFinite(since) ? (Date.now() - since) / 1000 : 0;
}

tunnel.onState((newState) => {
	state = { ...state, ...newState };
	updateUI();
});

// Initial status
tunnel.getStatus().then(async (s) => {
	if (s) {
		state = { ...state, ...s };
		updateUI();
		if (s.connected) {
			await loadPermissions();
			applyPermissions();
		}
	}
});

function updateUI() {
	const cs = connState();
	const { status, endpoint, handshake, rxBytes, txBytes, rxSpeed, txSpeed } = state;
	const connected = cs === 'connected';
	const host = hostOf(endpoint || serverUrl);
	document.body.dataset.conn = cs;

	// Labels
	let label;
	if (cs === 'connected') label = t('status.connected');
	else if (cs === 'connecting') label = t(status === 'reconnecting' ? 'status.reconnecting' : 'status.connecting');
	else if (cs === 'error') label = t('ui.status.error');
	else label = t('status.disconnected');
	el.connLabel.textContent = label;
	$('#sb-conn-label').textContent = label;

	el.connSub.textContent = connected ? `${formatDuration(connectedSeconds())} · ${host}` : host;
	setSwitch(el.connSwitch, cs === 'connected' || cs === 'connecting');
	el.connSwitch.disabled = cs === 'connecting';

	// Hero
	const titles = {
		connected: t('ui.hero.protected'),
		connecting: label,
		error: t('ui.hero.failed'),
		disconnected: t('ui.hero.disconnected'),
	};
	el.statusLabel.textContent = titles[cs];
	el.heroSub.textContent = cs === 'connected' ? t('ui.hero.subOn', { host: host || '—' })
		: cs === 'connecting' ? t('ui.hero.subConnecting')
		: cs === 'error' ? ''
		: t('ui.hero.subOff');
	el.heroErrorText.textContent = cs === 'error' ? (state.error || '') : '';
	$('#overview-sub').textContent = host;

	// Stats
	el.statEndpoint.textContent = endpoint ? hostOf(endpoint) : '—';
	el.statHandshake.textContent = handshake || '—';
	el.statSince.textContent = connected && state.connectedSince ? formatDuration(connectedSeconds()) : '—';
	el.statRx.textContent = formatBytes(rxBytes || 0);
	el.statTx.textContent = formatBytes(txBytes || 0);

	// Speed + Graph
	const showTraffic = connected && activePermissions.traffic;
	if (showTraffic) {
		el.statRxSpeed.textContent = formatSpeed(rxSpeed || 0);
		el.statTxSpeed.textContent = formatSpeed(txSpeed || 0);
		updateBandwidthGraph(rxSpeed || 0, txSpeed || 0);
	} else {
		el.statRxSpeed.textContent = '—';
		el.statTxSpeed.textContent = '—';
		if (!connected) { bwHistory.rx = []; bwHistory.tx = []; }
	}
	$('#bw-chart').hidden = !showTraffic;
	$('#bw-empty').hidden = showTraffic;
	$('#bandwidth-section').hidden = connected && !activePermissions.traffic;

	// Kill-Switch / RDP allow
	setSwitch(el.killswitchToggle, !!state.killSwitch);
	setSwitch(el.killswitchQuick, !!state.killSwitch);
	const ksChip = $('#ks-chip');
	ksChip.classList.toggle('c-ok', !!state.killSwitch);
	ksChip.classList.toggle('c-warn', !state.killSwitch);
	setSwitch(el.rdpAllowToggle, !!state.rdpAllow);

	// Status bar
	$('#sb-endpoint').textContent = host;
	$('#sb-ks').textContent = t(state.killSwitch ? 'ui.statusbar.ksOn' : 'ui.statusbar.ksOff');
	$('#sb-rate').textContent = showTraffic ? `↓ ${formatSpeed(rxSpeed || 0)}  ↑ ${formatSpeed(txSpeed || 0)}` : '';

	// Services depend on the tunnel
	$$('.svc-open').forEach((b) => { b.disabled = !connected; });
	$('#services-empty').hidden = !(connected && servicesList.length === 0);

	togglePortalBtn();
}

// Tick the "connected since" counters once per second
setInterval(() => {
	if (connState() !== 'connected') return;
	const secs = connectedSeconds();
	el.statSince.textContent = state.connectedSince ? formatDuration(secs) : '—';
	el.connSub.textContent = `${formatDuration(secs)} · ${hostOf(state.endpoint || serverUrl)}`;
}, 1000);

// ── Connect / Disconnect ────────────────────────────────
async function doConnect() {
	if (connState() === 'connecting') return;
	await tunnel.connect();
}

async function doDisconnect() {
	await tunnel.disconnect();
}

el.connectBtn.addEventListener('click', doConnect);
$('#retry-btn').addEventListener('click', doConnect);
$('#services-connect-btn').addEventListener('click', doConnect);
el.disconnectBtn.addEventListener('click', doDisconnect);
el.connSwitch.addEventListener('click', () => {
	const cs = connState();
	if (cs === 'connecting') return;
	if (cs === 'connected') doDisconnect(); else doConnect();
});

// ── Portal Button ───────────────────────────────────────
function togglePortalBtn() {
	const show = !!(currentPortalUrl && state.connected);
	el.portalBtn?.toggleAttribute('hidden', !show);
}

onPortalUrl?.((url) => {
	currentPortalUrl = url;
	togglePortalBtn();
});

el.portalBtn?.addEventListener('click', () => {
	if (currentPortalUrl && /^https:\/\//i.test(currentPortalUrl)) shell.openExternal(currentPortalUrl);
});

// ── Kill-Switch / RDP allow ─────────────────────────────
function setKillSwitch(enabled) {
	state.killSwitch = enabled;
	killSwitch.toggle(enabled);
	updateUI();
}
bindSwitch(el.killswitchQuick, setKillSwitch);
bindSwitch(el.killswitchToggle, setKillSwitch);

bindSwitch(el.rdpAllowToggle, (enabled) => {
	state.rdpAllow = enabled;
	rdpAllow.toggle(enabled);
});

// ══════════════════════════════════════════════════════════
//  BANDWIDTH GRAPH (SVG)
// ══════════════════════════════════════════════════════════
const BW_HISTORY_LEN = 60;
const bwHistory = { rx: [], tx: [] };

function updateBandwidthGraph(rxSpeed, txSpeed) {
	bwHistory.rx.push(rxSpeed);
	bwHistory.tx.push(txSpeed);
	if (bwHistory.rx.length > BW_HISTORY_LEN) bwHistory.rx.shift();
	if (bwHistory.tx.length > BW_HISTORY_LEN) bwHistory.tx.shift();

	const W = 600;
	const H = 150;
	const maxVal = Math.max(...bwHistory.rx, ...bwHistory.tx, 1024) * 1.15;
	const pts = (data) => data.map((v, i) => {
		const x = ((BW_HISTORY_LEN - data.length + i) / (BW_HISTORY_LEN - 1)) * W;
		const y = H - (v / maxVal) * (H - 10);
		return `${x.toFixed(1)},${y.toFixed(1)}`;
	}).join(' ');

	const rxPts = pts(bwHistory.rx);
	$('#bw-rx-line').setAttribute('points', rxPts);
	$('#bw-tx-line').setAttribute('points', pts(bwHistory.tx));
	if (bwHistory.rx.length > 1) {
		const firstX = rxPts.split(' ')[0].split(',')[0];
		$('#bw-rx-area').setAttribute('d', `M${firstX},${H} L${rxPts.split(' ').join(' L')} L${W},${H} Z`);
	} else {
		$('#bw-rx-area').setAttribute('d', '');
	}
	$('#bw-max').textContent = formatSpeed(maxVal);
}

// ══════════════════════════════════════════════════════════
//  PERMISSIONS, SERVICES, TRAFFIC, DNS
// ══════════════════════════════════════════════════════════
async function loadPermissions() {
	try {
		const perms = await permissions.get();
		if (perms) activePermissions = { ...perms, _loaded: true };
	} catch {}
}

function applyPermissions() {
	if (activePermissions.services) {
		loadServices();
	} else {
		servicesList = [];
		renderServices();
	}

	if (activePermissions.traffic) {
		loadTraffic();
	} else {
		trafficData = null;
		renderTraffic();
	}

	const dnsSection = $('.dns-section');
	if (dnsSection) dnsSection.style.display = activePermissions.dns === false ? 'none' : 'flex';
	updateUI();
}

// Reload permissions + services on connect
tunnel.onState(async (s) => {
	if (s.connected || s.status === 'connected') {
		if (!activePermissions._loaded) {
			await loadPermissions();
			applyPermissions();
		}
	} else {
		activePermissions._loaded = false;
	}
});

// ── Services ────────────────────────────────────────────
async function loadServices() {
	try {
		servicesList = (await services.list()) || [];
	} catch {
		servicesList = [];
	}
	renderServices();
}

function openService(svc) {
	if (svc?.url && state.connected) shell.openExternal(svc.url);
}

function renderServices() {
	const connected = connState() === 'connected';
	const quick = $('#services-list');
	const grid = $('#services-grid');
	quick.textContent = '';
	grid.textContent = '';

	$('#services-section').hidden = servicesList.length === 0;
	$('#services-empty').hidden = !(connected && servicesList.length === 0);

	servicesList.slice(0, 4).forEach((svc) => {
		const tile = h('button', 'row card svc-tile svc-open');
		tile.type = 'button';
		tile.disabled = !connected;
		tile.appendChild(h('span', 'svc-initial', (svc.name || '?').trim().charAt(0)));
		const meta = h('span', 'svc-meta');
		meta.appendChild(h('span', 'svc-name', svc.name));
		meta.appendChild(h('span', 'svc-host', svc.domain || hostOf(svc.url)));
		tile.appendChild(meta);
		tile.addEventListener('click', () => openService(svc));
		quick.appendChild(tile);
	});

	servicesList.forEach((svc) => {
		const card = h('div', 'card svc-card');
		const top = h('div', 'svc-card-top');
		top.appendChild(h('span', 'svc-initial lg', (svc.name || '?').trim().charAt(0)));
		const meta = h('div', 'svc-meta');
		meta.appendChild(h('div', 'svc-name', svc.name));
		meta.appendChild(h('div', 'svc-host', svc.domain || hostOf(svc.url)));
		top.appendChild(meta);
		card.appendChild(top);

		const bottom = h('div', 'svc-card-bottom');
		bottom.appendChild(h('span', 'chip', svc.protocol || 'HTTPS'));
		if (svc.hasAuth) bottom.appendChild(h('span', 'chip c-info', t('ui.services.auth')));
		bottom.appendChild(h('span', 'grow'));
		const openBtn = iconButton('btn btn-sec btn-sm svc-open', 'external', t('ui.services.open'), false);
		openBtn.disabled = !connected;
		openBtn.addEventListener('click', () => openService(svc));
		bottom.appendChild(openBtn);
		card.appendChild(bottom);
		grid.appendChild(card);
	});
}

// ── Traffic Usage ───────────────────────────────────────
async function loadTraffic() {
	try {
		trafficData = await traffic.stats();
	} catch {
		trafficData = null;
	}
	renderTraffic();
}

function renderTraffic() {
	const section = $('#traffic-usage');
	if (!trafficData) { section.hidden = true; return; }
	section.hidden = false;
	const p = trafficData[usagePeriod] || {};
	const rx = p.rx || 0;
	const tx = p.tx || 0;
	const total = rx + tx;
	$('#usage-total').textContent = formatBytes(total);
	$('#usage-rx').textContent = formatBytes(rx);
	$('#usage-tx').textContent = formatBytes(tx);
	const rxPct = total > 0 ? Math.round((rx / total) * 100) : 0;
	$('#usage-rx-bar').style.width = `${rxPct}%`;
	$('#usage-tx-bar').style.width = total > 0 ? `${100 - rxPct}%` : '0';
}

bindSeg($('#usage-seg'), 'usage', (period) => {
	usagePeriod = period;
	renderTraffic();
});

// ── DNS Leak Test ───────────────────────────────────────
const dnsBtn = $('#dns-test-btn');
const dnsResult = $('#dns-result');
const dnsResultText = $('#dns-result-text');

function setDnsResult(kind, text) {
	dnsResult.classList.remove('ok', 'warn', 'fail');
	if (kind) dnsResult.classList.add(kind);
	// Detach the idle i18n key once a real result is shown
	delete dnsResultText.dataset.i18n;
	dnsResultText.textContent = text;
}

dnsBtn.addEventListener('click', async () => {
	dnsBtn.disabled = true;
	dnsBtn.textContent = t('dns.testing');
	setDnsResult(null, t('dns.testing'));

	try {
		const [serverInfo, sysCheck] = await Promise.all([
			dns.leakTest(),
			dns.checkSystem(),
		]);

		const { connected, killSwitch: ksActive, dnsServer, resolveOk } = sysCheck || {};
		const vpnDns = serverInfo?.vpnDns || '';
		const expectedDns = vpnDns.split(',').map((s) => s.trim()).filter(Boolean);

		if (!connected) {
			setDnsResult('fail', t('dns.leakNotConnected'));
		} else if (!resolveOk) {
			setDnsResult('fail', t('dns.resolveFailed'));
		} else if (ksActive) {
			const info = dnsServer ? ` DNS: ${dnsServer}` : '';
			setDnsResult('ok', t('dns.noLeakKillSwitch') + info);
		} else if (dnsServer && expectedDns.includes(dnsServer)) {
			setDnsResult('ok', t('dns.noLeakDetail', { servers: dnsServer }));
		} else {
			const info = dnsServer ? ` ${t('dns.activeDns')}: ${dnsServer}` : '';
			setDnsResult('warn', t('dns.leakNoKillSwitch') + info);
		}
	} catch {
		setDnsResult('fail', t('dns.testFailed'));
	}

	dnsBtn.disabled = false;
	dnsBtn.textContent = t('ui.dns.run');
});

// ══════════════════════════════════════════════════════════
//  REMOTE DESKTOPS
// ══════════════════════════════════════════════════════════
async function loadRdpServices() {
	try {
		const list = await rdp.list();
		rdpServices = list || [];
	} catch {
		rdpServices = [];
	}
	await loadRdpSessions();
	renderRdp();
}

async function loadRdpSessions() {
	try {
		const list = await rdp.activeSessions();
		const now = Date.now();
		rdpSessions = (list || []).map((s) => ({ ...s, startedAt: now - (s.duration || 0) * 1000 }));
	} catch {
		rdpSessions = [];
	}
	renderSessions();
}

function sessionFor(svc) {
	return rdpSessions.find((s) => String(s.routeId) === String(svc.id));
}

function rdpStatus(svc) {
	if (svc.status?.online) return { key: 'online', label: t('rdp.statusOnline'), chip: 'c-ok', dot: 'dot-online' };
	if (svc.maintenance_active) return { key: 'maint', label: t('rdp.statusMaintenance'), chip: 'c-warn', dot: 'dot-maint' };
	return { key: 'offline', label: t('rdp.statusOffline'), chip: '', dot: 'dot-offline' };
}

function filteredRdp() {
	const filterText = ($('#rdp-filter-input').value || '').toLowerCase();
	return rdpServices.filter((svc) => {
		if (filterText) {
			const searchable = [svc.name, svc.host, ...parseTags(svc.tags)].join(' ').toLowerCase();
			if (!searchable.includes(filterText)) return false;
		}
		if (rdpFilter === 'online' && !svc.status?.online) return false;
		if (rdpFilter === 'offline' && svc.status?.online) return false;
		return true;
	});
}

function updateRdpBadge() {
	const badge = $('#rdp-badge');
	const onlineCount = rdpServices.filter((s) => s.status?.online).length;
	badge.textContent = String(onlineCount);
	badge.setAttribute('aria-label', `${onlineCount} online`);
	badge.hidden = onlineCount === 0;
}

function renderRdp() {
	updateRdpBadge();
	const list = $('#rdp-list');
	list.textContent = '';
	const filtered = filteredRdp();
	const onlineCount = rdpServices.filter((s) => s.status?.online).length;
	$('#rdp-count').textContent = t('ui.rdp.summary', { total: rdpServices.length, online: onlineCount });

	// Empty states
	const noHosts = rdpServices.length === 0;
	$('#rdp-list-empty').hidden = filtered.length > 0;
	$('#rdp-list-empty-title').textContent = t(noHosts ? 'ui.rdp.noHosts' : 'ui.rdp.empty');
	$('#rdp-list-empty-hint').textContent = t(noHosts ? 'ui.rdp.noHostsHint' : 'ui.rdp.emptyHint');
	$('#rdp-reset-filter').hidden = noHosts;

	if (selectedRdpId !== null && !rdpServices.some((s) => String(s.id) === String(selectedRdpId))) selectedRdpId = null;
	if (selectedRdpId === null && filtered.length > 0) selectedRdpId = filtered[0].id;

	filtered.forEach((svc) => list.appendChild(createRdpRow(svc)));
	renderRdpDetail();
}

function createRdpRow(svc) {
	const st = rdpStatus(svc);
	const selected = String(svc.id) === String(selectedRdpId);
	const row = h('button', `row${selected ? ' sel' : ''}`);
	row.type = 'button';
	if (selected) row.setAttribute('aria-current', 'true');
	row.addEventListener('click', () => {
		selectedRdpId = svc.id;
		renderRdp();
	});

	const icon = h('span', 'host-icon');
	setStaticIcon(icon, 'monitor'); // SAFE: static SVG
	icon.appendChild(h('span', `dot ${st.dot}`));
	row.appendChild(icon);

	const text = h('span', 'host-text');
	const nameLine = h('span', 'host-name-line');
	nameLine.appendChild(h('span', 'host-name', svc.name));
	if (sessionFor(svc)) nameLine.appendChild(h('span', 'chip c-ok chip-sm', t('ui.rdp.sessionActive')));
	text.appendChild(nameLine);
	text.appendChild(h('span', 'host-addr', `${svc.host}:${svc.port || 3389}`));
	row.appendChild(text);

	row.appendChild(h('span', `chip ${st.chip}`, st.label));
	return row;
}

function infoCard(label, value, opts = {}) {
	const card = h('div', 'card info-card');
	card.appendChild(h('div', 'lbl', label));
	const val = h('div', `info-val${opts.mono ? ' mono' : ''}`, value);
	if (opts.color) val.style.color = opts.color;
	card.appendChild(val);
	return card;
}

let wolTimer = null;
const wolSentIds = new Set();

function renderRdpDetail() {
	const detail = $('#rdp-detail');
	detail.textContent = '';
	const svc = rdpServices.find((s) => String(s.id) === String(selectedRdpId));
	$('#rdp-detail-empty').hidden = !!svc || rdpServices.length === 0;
	if (!svc) return;

	const st = rdpStatus(svc);
	const online = !!svc.status?.online;

	// Header
	const head = h('div', 'rdp-detail-head');
	const titleBlock = h('div', 'grow');
	titleBlock.style.minWidth = '0';
	const titleLine = h('div', 'rdp-detail-title');
	titleLine.appendChild(h('h2', 'disp rdp-detail-name', svc.name));
	titleLine.appendChild(h('span', `chip ${st.chip}`, st.label));
	titleBlock.appendChild(titleLine);
	const addr = h('p', 'mono muted', `${svc.host}:${svc.port || 3389}`);
	addr.style.marginTop = '4px';
	titleBlock.appendChild(addr);
	head.appendChild(titleBlock);

	if (!online && svc.wol_mac) {
		const sent = wolSentIds.has(svc.id);
		const wolBtn = iconButton('btn btn-sec', 'wol', sent ? t('rdp.wolSent') : t('ui.rdp.wake'));
		wolBtn.disabled = sent;
		wolBtn.title = svc.wol_mac;
		wolBtn.addEventListener('click', () => {
			rdp.wol(svc.id);
			wolSentIds.add(svc.id);
			renderRdpDetail();
			clearTimeout(wolTimer);
			wolTimer = setTimeout(() => { wolSentIds.delete(svc.id); renderRdpDetail(); }, 5000);
		});
		head.appendChild(wolBtn);
	}

	const connectBtn = iconButton('btn btn-pri', 'play', t('rdp.connect'));
	connectBtn.disabled = !online && !svc.maintenance_active;
	connectBtn.addEventListener('click', () => startRdpConnect(svc));
	head.appendChild(connectBtn);
	detail.appendChild(head);

	// Hints
	if (!online && !svc.maintenance_active && !svc.wol_mac) {
		detail.appendChild(h('div', 'note note-neutral', t('ui.rdp.offlineHint')));
	}
	if (svc.maintenance_active) {
		const note = h('div', 'note note-warn');
		note.appendChild(h('strong', null, `${t('rdp.maintenance')}: ${t('rdp.maintenanceActive')}`));
		if (svc.maintenance_window) note.appendChild(document.createTextNode(` · ${svc.maintenance_window}`));
		detail.appendChild(note);
	}

	// Info grid
	const grid = h('div', 'info-grid');
	grid.appendChild(infoCard(t('rdp.access'), svc.access_type === 'external' ? t('rdp.accessExternal') : t('rdp.accessInternalOnly')));
	const credText = svc.credential_mode === 'full' ? t('rdp.credentialsFull')
		: svc.credential_mode === 'user_only' ? t('rdp.credentialsUserOnly') : t('rdp.credentialsNone');
	grid.appendChild(infoCard(t('rdp.credentials'), credText));
	grid.appendChild(infoCard(t('rdp.resolution'), svc.resolution || t('rdp.resolutionFullscreen')));
	grid.appendChild(infoCard('NLA', svc.nla ? t('rdp.nlaEnforced') : t('rdp.nlaOptional')));
	grid.appendChild(infoCard('Domain', svc.domain || '—', { mono: true }));
	if (svc.redirects) grid.appendChild(infoCard(t('rdp.redirects'), String(svc.redirects)));
	if (svc.timeout_minutes) grid.appendChild(infoCard(t('rdp.timeout'), t('rdp.timeoutMin', { minutes: svc.timeout_minutes })));
	if (svc.maintenance_window && !svc.maintenance_active) grid.appendChild(infoCard(t('rdp.maintenance'), svc.maintenance_window));
	if (!online && svc.wol_mac) grid.appendChild(infoCard('Wake-on-LAN', svc.wol_mac, { mono: true }));
	detail.appendChild(grid);

	// Tags
	const tags = parseTags(svc.tags);
	if (tags.length > 0) {
		const row = h('div', 'tags');
		tags.forEach((tg) => row.appendChild(h('span', 'chip', tg)));
		detail.appendChild(row);
	}

	// Notes
	if (svc.notes) {
		const card = h('div', 'card');
		card.style.cssText = 'padding:16px;display:flex;flex-direction:column;gap:6px';
		card.appendChild(h('div', 'lbl', t('rdp.notes')));
		const p = h('p', 'muted', svc.notes);
		p.style.whiteSpace = 'pre-wrap';
		card.appendChild(p);
		detail.appendChild(card);
	}
}

function sessionName(s) {
	const svc = rdpServices.find((x) => String(x.id) === String(s.routeId));
	return svc ? svc.name : (s.host || String(s.routeId));
}

function sessionMinutes(s) {
	return Math.max(0, Math.floor((Date.now() - s.startedAt) / 60000));
}

function renderSessions() {
	// Sidebar
	const side = $('#side-sessions');
	const sideList = $('#side-sessions-list');
	sideList.textContent = '';
	side.hidden = rdpSessions.length === 0;
	rdpSessions.forEach((s) => {
		const btn = h('button', 'nav side-session');
		btn.type = 'button';
		btn.appendChild(h('span', 'dot'));
		const text = h('span', 'side-session-text');
		text.appendChild(h('span', 'side-session-name', sessionName(s)));
		text.appendChild(h('span', 'side-session-sub', t('ui.rdp.runningFor', { minutes: sessionMinutes(s) })));
		btn.appendChild(text);
		btn.addEventListener('click', () => {
			selectedRdpId = s.routeId;
			navigateTo('rdp');
			renderRdp();
		});
		sideList.appendChild(btn);
	});

	// RDP page card
	const card = $('#rdp-sessions-card');
	const list = $('#rdp-sessions-list');
	list.textContent = '';
	card.hidden = rdpSessions.length === 0;
	rdpSessions.forEach((s) => {
		const row = h('div', 'sess-row');
		row.appendChild(h('span', 'dot'));
		row.appendChild(h('span', null, sessionName(s))).style.fontWeight = '600';
		row.appendChild(h('span', 'muted grow', t('ui.rdp.runningFor', { minutes: sessionMinutes(s) })));
		const endBtn = h('button', 'btn btn-ghost btn-xs', t('ui.rdp.endSession'));
		endBtn.type = 'button';
		endBtn.addEventListener('click', async () => {
			await rdp.disconnect(s.routeId);
			loadRdpSessions().then(renderRdp);
		});
		row.appendChild(endBtn);
		list.appendChild(row);
	});
}

// Keep "running for" labels fresh
setInterval(() => { if (rdpSessions.length) renderSessions(); }, 30000);

// Filters
$('#rdp-filter-input').addEventListener('input', () => renderRdp());
bindSeg($('#rdp-filter-seg'), 'filter', (f) => {
	rdpFilter = f;
	renderRdp();
});
$('#rdp-reset-filter').addEventListener('click', () => {
	rdpFilter = 'all';
	$('#rdp-filter-input').value = '';
	selectSeg($('#rdp-filter-seg'), 'filter', 'all');
	renderRdp();
});

// ── RDP dialog ──────────────────────────────────────────
function showRdpView(view) {
	const dialog = $('#rdp-dialog');
	$$('.dlg-view').forEach((v) => v.classList.remove('active'));
	if (!view) {
		dialog.hidden = true;
		return;
	}
	const target = $(`#rdp-view-${view}`);
	if (target) target.classList.add('active');
	dialog.hidden = false;
}

function closeRdpDialog() { showRdpView(null); }

document.addEventListener('keydown', (e) => {
	if (e.key === 'Escape' && !$('#rdp-dialog').hidden) closeRdpDialog();
});

async function startRdpConnect(svc, opts = {}) {
	currentRdpRoute = svc;

	// Show progress view BEFORE starting connect
	showConnectingProgress(svc);

	try {
		const result = await rdp.connect(svc.id, opts);

		if (result && result.needsPassword) {
			showPasswordPrompt(svc);
			return;
		}

		if (result && result.maintenanceWarning) {
			showMaintenanceWarning(svc, result.maintenanceWindow);
			return;
		}

		// Connection started successfully — progress updates come via IPC events
		if (result && result.success !== false) {
			$('#rdp-connecting-status').textContent = t('rdp.connectionActive');
		}
	} catch (err) {
		setConnectingChip('error');
		$('#rdp-connecting-status').textContent = err.message || t('rdp.connectionError');
	}
}

// ── Password Prompt ─────────────────────────────────────
function showPasswordPrompt(svc) {
	$('#rdp-password-title').textContent = svc.name;
	const username = svc.username || '';
	const domain = svc.domain || 'WORKGROUP';
	$('#rdp-password-user').textContent = t('rdp.user', { user: `${domain}\\${username}` });
	$('#rdp-password-input').value = '';
	showRdpView('password');
	$('#rdp-password-input').focus();
}

$('#rdp-password-cancel').addEventListener('click', closeRdpDialog);

$('#rdp-password-submit').addEventListener('click', () => {
	const password = $('#rdp-password-input').value;
	if (!password || !currentRdpRoute) return;
	startRdpConnect(currentRdpRoute, { password });
});

$('#rdp-password-input').addEventListener('keydown', (e) => {
	if (e.key === 'Enter') $('#rdp-password-submit').click();
});

// ── Maintenance Warning ─────────────────────────────────
function showMaintenanceWarning(svc, windowText) {
	$('#rdp-maintenance-title').textContent = svc.name;
	$('#rdp-maintenance-window').textContent = windowText
		? t('rdp.scheduledMaintenance', { window: windowText })
		: t('rdp.outsideMaintenanceConnect');
	showRdpView('maintenance');
}

$('#rdp-maintenance-cancel').addEventListener('click', closeRdpDialog);

$('#rdp-maintenance-force').addEventListener('click', () => {
	if (!currentRdpRoute) return;
	startRdpConnect(currentRdpRoute, { forceMaintenanceBypass: true });
});

// ── Connecting Progress ─────────────────────────────────
function getProgressSteps() {
	return [
		{ id: 'vpn-check',   label: t('rdpProgress.vpnCheck') },
		{ id: 'tcp-check',   label: t('rdpProgress.tcpCheck') },
		{ id: 'credentials', label: t('rdpProgress.credentials') },
		{ id: 'rdp-file',    label: t('rdpProgress.rdpFile') },
		{ id: 'mstsc',       label: t('rdpProgress.mstsc') },
	];
}

function setConnectingChip(kind) {
	const chip = $('#rdp-connecting-chip');
	chip.classList.remove('c-warn', 'c-ok', 'c-err');
	if (kind === 'done') { chip.classList.add('c-ok'); chip.textContent = t('status.connected'); }
	else if (kind === 'error') { chip.classList.add('c-err'); chip.textContent = t('rdp.connectionError'); }
	else { chip.classList.add('c-warn'); chip.textContent = t('rdp.connecting'); }
}

function showConnectingProgress(svc) {
	$('#rdp-connecting-title').textContent = svc.name;
	$('#rdp-connecting-status').textContent = t('rdp.connectionEstablishing');
	setConnectingChip('running');

	const stepsContainer = $('#rdp-progress-steps');
	stepsContainer.textContent = '';

	getProgressSteps().forEach((step) => {
		const stepEl = h('li', 'step');
		stepEl.id = `rdp-step-${step.id}`;
		const icon = h('span', 'step-icon');
		setStaticIcon(icon, 'stepIcons'); // SAFE: static SVG
		stepEl.appendChild(icon);
		stepEl.appendChild(h('span', null, step.label));
		stepsContainer.appendChild(stepEl);
	});

	showRdpView('connecting');
}

function updateProgressStep(stepId, status) {
	const stepEl = $(`#rdp-step-${stepId}`);
	if (!stepEl) return;
	stepEl.classList.remove('done', 'active', 'error');
	if (status === 'done') stepEl.classList.add('done');
	else if (status === 'active') stepEl.classList.add('active');
	else if (status === 'error') {
		stepEl.classList.add('error');
		setConnectingChip('error');
	}
}

$('#rdp-connecting-back').addEventListener('click', closeRdpDialog);

// ══════════════════════════════════════════════════════════
//  IPC EVENT BINDINGS (RDP)
// ══════════════════════════════════════════════════════════
rdp.onProgress((data) => {
	if (data.step && data.status) {
		// Treat 'skip', 'fallback' as done
		const normalizedStatus = ['skip', 'fallback'].includes(data.status) ? 'done' : data.status;
		updateProgressStep(data.step, normalizedStatus);

		const statusMessages = {
			'vpn-check': t('rdpProgress.vpnCheckActive'),
			'tcp-check': t('rdpProgress.tcpCheckActive'),
			'credentials': t('rdpProgress.credentialsActive'),
			'rdp-file': t('rdpProgress.rdpFileActive'),
			'mstsc': t('rdpProgress.mstscActive'),
			'cmdkey': t('rdpProgress.cmdkeyActive'),
		};
		if (data.status === 'active' && statusMessages[data.step]) {
			$('#rdp-connecting-status').textContent = statusMessages[data.step];
		}
		if (data.status === 'done' && data.step === 'mstsc') {
			$('#rdp-connecting-status').textContent = t('rdp.connectionActive');
			setConnectingChip('done');
			$('#rdp-connecting-back').textContent = t('ui.rdp.done');
		}
	}
	if (data.message) {
		$('#rdp-connecting-status').textContent = data.message;
	}
});

rdp.onSessionStart(() => {
	loadRdpSessions().then(renderRdp);
});

rdp.onSessionEnd(() => {
	loadRdpSessions().then(renderRdp);
	// If the progress dialog is still open, close it
	if ($('#rdp-view-connecting').classList.contains('active')) closeRdpDialog();
});

rdp.onSessionError((data) => {
	if (data.step) updateProgressStep(data.step, 'error');
	setConnectingChip('error');
	const msg = data.message || data.error;
	if (msg) $('#rdp-connecting-status').textContent = msg;
});

rdp.onServicesUpdate((data) => {
	rdpServices = data || [];
	renderRdp();
});

// Badge on start-up (without starting the status polling)
rdp.list().then((list) => { rdpServices = list || []; renderRdp(); }).catch(() => {});
loadRdpSessions();

// ══════════════════════════════════════════════════════════
//  SETTINGS
// ══════════════════════════════════════════════════════════
function showSettingsTab(tab) {
	$$('#settings-tabs [data-tab]').forEach((b) => {
		const on = b.dataset.tab === tab;
		b.classList.toggle('on', on);
		if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
	});
	$$('.set-tab').forEach((p) => p.classList.toggle('active', p.id === `set-${tab}`));
}

$$('#settings-tabs [data-tab]').forEach((b) => b.addEventListener('click', () => showSettingsTab(b.dataset.tab)));

// Load settings
config.getAll().then((cfg) => {
	if (!cfg) return;
	serverUrl = cfg.server?.url || '';
	el.serverUrl.value = serverUrl;
	el.apiKey.value = cfg.server?.apiKey || '';
	setSwitch(el.optAutostart, cfg.app?.startWithWindows ?? true);
	setSwitch(el.optMinimized, cfg.app?.startMinimized ?? true);
	applyTheme(cfg.app?.theme || 'dark');
	setSwitch(el.optAutoconnect, cfg.tunnel?.autoConnect ?? true);
	el.optCheckInterval.value = cfg.app?.checkInterval ?? 30;
	el.optPollInterval.value = cfg.app?.configPollInterval ?? 300;
	splitSaved = {
		enabled: cfg.tunnel?.splitTunnel ?? false,
		routes: parseRoutes(cfg.tunnel?.splitRoutes || ''),
	};
	splitDraft = { enabled: splitSaved.enabled, routes: [...splitSaved.routes] };
	renderSplit();
	updateUI();

	// First start: nothing configured yet → open the setup assistant
	if (!cfg.server?.url && !cfg.tunnel?.configPath) navigateTo('setup');
});

// API-Key toggle
$('#toggle-api-key').addEventListener('click', () => {
	const input = el.apiKey;
	input.type = input.type === 'password' ? 'text' : 'password';
});

function showStatus(target, message, type) {
	target.hidden = false;
	target.textContent = message;
	target.className = `field-status ${type}`;
	if (type === 'success') {
		setTimeout(() => { target.hidden = true; }, 5000);
	}
}

function showServerStatus(message, type) {
	showStatus(el.serverStatus, message, type);
}

// Server test
$('#btn-test-server').addEventListener('click', async () => {
	showServerStatus(t('server.testInProgress'), 'info');
	const url = el.serverUrl.value.trim();
	const key = el.apiKey.value.trim();
	if (!url || !key) {
		showServerStatus(t('server.urlAndKeyRequired'), 'error');
		return;
	}
	const result = await server.test({ url, apiKey: key });
	if (result.success) {
		showServerStatus(t('server.testSuccess'), 'success');
	} else {
		showServerStatus(t('server.testError', { error: result.error }), 'error');
	}
});

// Server save
$('#btn-save-server').addEventListener('click', async () => {
	const url = el.serverUrl.value.trim();
	const key = el.apiKey.value.trim();
	if (!url || !key) {
		showServerStatus(t('server.urlAndKeyRequired'), 'error');
		return;
	}
	showServerStatus(t('server.registering'), 'info');
	const result = await server.setup({ url, apiKey: key });
	if (result.success) {
		serverUrl = url;
		showServerStatus(t(result.enrolled ? 'server.enrolled' : 'server.registered', { peerId: result.peerId }), 'success');
		reloadServerFields();
	} else {
		showServerStatus(t('server.testError', { error: result.error }), 'error');
	}
});

/** A setup code is swapped for an API key by the core; show what was stored. */
function reloadServerFields() {
	config.getAll().then((cfg) => {
		if (!cfg) return;
		serverUrl = cfg.server?.url || serverUrl;
		el.serverUrl.value = serverUrl;
		el.apiKey.value = cfg.server?.apiKey || '';
		updateUI();
	}).catch(() => {});
}

$('#btn-open-setup').addEventListener('click', () => navigateTo('setup'));

// App settings
bindSwitch(el.optAutostart, (on) => {
	autostart.set(on);
	config.set('app.startWithWindows', on);
});

bindSwitch(el.optMinimized, (on) => {
	config.set('app.startMinimized', on);
});

bindSwitch(el.optAutoconnect, (on) => {
	config.set('tunnel.autoConnect', on);
});

el.optCheckInterval.addEventListener('change', (e) => {
	const val = Math.max(5, Math.min(300, parseInt(e.target.value, 10) || 30));
	e.target.value = val;
	config.set('app.checkInterval', val);
});

el.optPollInterval.addEventListener('change', (e) => {
	const val = Math.max(30, Math.min(3600, parseInt(e.target.value, 10) || 300));
	e.target.value = val;
	config.set('app.configPollInterval', val);
});

// ── Split-Tunneling ─────────────────────────────────────
function parseRoutes(text) {
	return String(text || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
}

function routeKind(value) {
	if (/^[\d.]+\/\d+$/.test(value) || /^[0-9a-f:]+\/\d+$/i.test(value)) return t('ui.split.kindSubnet');
	if (/^[\d.]+$/.test(value) || /^[0-9a-f:]+$/i.test(value)) return t('ui.split.kindIp');
	return t('ui.split.kindDomain');
}

function splitIsDirty() {
	return splitDraft.enabled !== splitSaved.enabled
		|| splitDraft.routes.join('\n') !== splitSaved.routes.join('\n');
}

function renderSplit() {
	const all = $('#split-mode-all');
	const only = $('#split-mode-split');
	all.classList.toggle('sel', !splitDraft.enabled);
	only.classList.toggle('sel', splitDraft.enabled);
	all.setAttribute('aria-pressed', String(!splitDraft.enabled));
	only.setAttribute('aria-pressed', String(splitDraft.enabled));
	el.splitRoutesSection.hidden = !splitDraft.enabled;

	const list = $('#split-route-list');
	list.textContent = '';
	splitDraft.routes.forEach((value, i) => {
		const item = h('div', 'route-item');
		item.appendChild(h('span', 'chip', routeKind(value)));
		item.appendChild(h('span', 'mono', value));
		const rm = h('button', 'btn btn-ghost');
		rm.type = 'button';
		rm.setAttribute('aria-label', t('ui.split.remove', { value }));
		rm.title = t('ui.split.remove', { value });
		setStaticIcon(rm, 'trash'); // SAFE: static SVG
		rm.addEventListener('click', () => {
			splitDraft.routes.splice(i, 1);
			renderSplit();
		});
		item.appendChild(rm);
		list.appendChild(item);
	});
	$('#split-route-count').textContent = t('ui.split.count', { count: splitDraft.routes.length });

	const dirty = splitIsDirty();
	$('#btn-save-split').disabled = !dirty;
	$('#split-dirty').hidden = !dirty;
	$('#split-add-btn').disabled = !$('#split-new-route').value.trim();

	// Overview routing label reflects the saved (active) setting
	$('#routing-btn').textContent = splitSaved.enabled
		? t('ui.protection.splitCount', { count: splitSaved.routes.length })
		: t('ui.protection.fullTunnel');
}

$('#split-mode-all').addEventListener('click', () => { splitDraft.enabled = false; renderSplit(); });
$('#split-mode-split').addEventListener('click', () => { splitDraft.enabled = true; renderSplit(); });

function addRoute() {
	const input = $('#split-new-route');
	const values = parseRoutes(input.value.replace(/[,;\s]+/g, '\n'));
	values.forEach((v) => { if (!splitDraft.routes.includes(v)) splitDraft.routes.push(v); });
	input.value = '';
	renderSplit();
	input.focus();
}

$('#split-add-btn').addEventListener('click', addRoute);
$('#split-new-route').addEventListener('input', () => {
	$('#split-add-btn').disabled = !$('#split-new-route').value.trim();
});
$('#split-new-route').addEventListener('keydown', (e) => {
	if (e.key === 'Enter' && e.target.value.trim()) addRoute();
});

$('#btn-save-split').addEventListener('click', async () => {
	const modeChanged = splitDraft.enabled !== splitSaved.enabled;
	const routes = splitDraft.routes.join('\n');
	config.set('tunnel.splitTunnel', splitDraft.enabled);
	config.set('tunnel.splitRoutes', routes);
	splitSaved = { enabled: splitDraft.enabled, routes: [...splitDraft.routes] };
	renderSplit();

	if (splitDraft.enabled && !routes) {
		showSplitStatus(t('split.noRoutes'), 'warn');
		return;
	}
	const count = splitDraft.routes.length;
	if (state.connected) {
		if (!splitDraft.enabled) showSplitStatus(t('split.fullTunnelOnReconnect'), 'info');
		else showSplitStatus(modeChanged ? t('split.activateOnReconnect') : t('split.routesSaved', { count }), 'info');
		await tunnel.disconnect();
		await tunnel.connect();
	} else if (splitDraft.enabled) {
		showSplitStatus(t('split.routesSavedPending', { count }), 'info');
	}
});

let splitStatusTimer = null;
function showSplitStatus(msg, type) {
	const statusEl = $('#split-status');
	if (!statusEl) return;
	statusEl.hidden = false;
	statusEl.textContent = msg;
	statusEl.className = `field-status ${type === 'warn' ? 'warn' : 'success'}`;
	clearTimeout(splitStatusTimer);
	splitStatusTimer = setTimeout(() => { statusEl.hidden = true; }, 5000);
}

// ══════════════════════════════════════════════════════════
//  SETUP ASSISTANT
// ══════════════════════════════════════════════════════════
const SETUP_ORDER = { choose: 1, code: 2, qr: 2, done: 3 };

function showSetupStep(step) {
	setupStep = step;
	$$('.setup-step').forEach((s) => s.classList.toggle('active', s.id === `setup-${step}`));
	renderSetupProgress();
}

function renderSetupProgress() {
	const n = SETUP_ORDER[setupStep] || 1;
	$$('#setup-dots span').forEach((dot, i) => dot.classList.toggle('on', i < n));
	$('#setup-step-label').textContent = t('ui.setup.step', { n, total: 3 });
	if (setupDone) $('#setup-done-desc').textContent = t(setupDone.key, setupDone.params);
}

function resetSetup() {
	setupDone = null;
	$('#setup-choose-status').hidden = true;
	$('#setup-status').hidden = true;
	showSetupStep('choose');
}

function finishSetup(key, params) {
	setupDone = { key, params };
	reloadServerFields();
	showSetupStep('done');
}

$('#setup-cancel').addEventListener('click', () => navigateTo('status'));
$$('.setup-back').forEach((b) => b.addEventListener('click', () => showSetupStep('choose')));
$('#setup-later').addEventListener('click', () => navigateTo('status'));
$('#setup-connect').addEventListener('click', () => {
	navigateTo('status');
	doConnect();
});

$('#setup-opt-code').addEventListener('click', () => {
	const urlInput = $('#setup-url');
	if (!urlInput.value) urlInput.value = el.serverUrl.value || '';
	updateSetupSubmit();
	showSetupStep('code');
	(urlInput.value ? $('#setup-key') : urlInput).focus();
});

function updateSetupSubmit() {
	$('#setup-submit').disabled = !$('#setup-url').value.trim() || $('#setup-key').value.trim().length < 4;
}
$('#setup-url').addEventListener('input', updateSetupSubmit);
$('#setup-key').addEventListener('input', updateSetupSubmit);
$('#setup-key').addEventListener('keydown', (e) => {
	if (e.key === 'Enter' && !$('#setup-submit').disabled) $('#setup-submit').click();
});

$('#setup-submit').addEventListener('click', async () => {
	const statusEl = $('#setup-status');
	const submit = $('#setup-submit');
	let url = $('#setup-url').value.trim();
	const key = $('#setup-key').value.trim();
	if (!url || !key) {
		showStatus(statusEl, t('server.urlAndKeyRequired'), 'error');
		return;
	}
	if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
	submit.disabled = true;
	showStatus(statusEl, t('server.registering'), 'info');
	try {
		const result = await server.setup({ url, apiKey: key });
		if (result.success) {
			serverUrl = url;
			statusEl.hidden = true;
			$('#setup-key').value = '';
			finishSetup(result.enrolled ? 'server.enrolled' : 'server.registered', { peerId: result.peerId });
		} else if (!result.cancelled) {
			showStatus(statusEl, t('server.testError', { error: result.error }), 'error');
		} else {
			statusEl.hidden = true;
		}
	} catch (err) {
		showStatus(statusEl, t('server.testError', { error: err.message }), 'error');
	}
	updateSetupSubmit();
});

// Config import (.conf)
$('#btn-import-file').addEventListener('click', async () => {
	const result = await config.importFile();
	if (result.success) {
		finishSetup('server.configImported', { path: result.path });
	} else if (result.error) {
		showStatus($('#setup-choose-status'), t('server.importError', { error: result.error }), 'error');
	}
});

// QR-Code scanner
let qrStream = null;
let qrTimeout = null;

$('#btn-import-qr').addEventListener('click', async () => {
	const video = $('#qr-video');
	try {
		qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
		video.srcObject = qrStream;
		showSetupStep('qr');
		scanQR();
		clearTimeout(qrTimeout);
		qrTimeout = setTimeout(() => {
			if (qrStream) {
				stopQRScan();
				showSetupStep('choose');
				showStatus($('#setup-choose-status'), t('server.qrTimeout'), 'error');
			}
		}, 60000);
	} catch (err) {
		showStatus($('#setup-choose-status'), t('server.cameraError', { error: err.message }), 'error');
	}
});

$('#btn-qr-cancel').addEventListener('click', () => {
	stopQRScan();
	showSetupStep('choose');
});

function stopQRScan() {
	clearTimeout(qrTimeout);
	if (qrStream) {
		qrStream.getTracks().forEach((tr) => tr.stop());
		qrStream = null;
	}
	const video = $('#qr-video');
	if (video) video.srcObject = null;
}

async function scanQR() {
	const video = $('#qr-video');
	const canvas = $('#qr-canvas');
	const ctx = canvas.getContext('2d');

	const scan = async () => {
		if (!qrStream) return;
		if (video.readyState === video.HAVE_ENOUGH_DATA) {
			canvas.width = video.videoWidth;
			canvas.height = video.videoHeight;
			ctx.drawImage(video, 0, 0);
			const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
			const result = await config.importQR({
				data: Array.from(imageData.data),
				width: canvas.width,
				height: canvas.height,
			});
			// Setup QR ("App einrichten"): core asked the user and redeemed it —
			// stop scanning either way, or the next frame would ask again.
			if (result.enrollment) {
				stopQRScan();
				if (result.success) {
					finishSetup('server.enrolled', { peerId: result.peerId });
				} else {
					showSetupStep('choose');
					if (!result.cancelled) showStatus($('#setup-choose-status'), result.error, 'error');
				}
				return;
			}
			if (result.success) {
				stopQRScan();
				finishSetup('server.qrSuccess');
				return;
			}
		}
		requestAnimationFrame(scan);
	};
	scan();
}

// ══════════════════════════════════════════════════════════
//  LOGS
// ══════════════════════════════════════════════════════════
const LOG_LINE = /^\[(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?\]\s*(?:\[([^\]]+)\]\s*)?(?:\[(\w+)\]\s*)?(.*)$/;
const LOG_LEVELS = {
	error: { key: 'ui.logs.error', cls: 'c-err', group: 'error' },
	warn: { key: 'ui.logs.warn', cls: 'c-warn', group: 'warn' },
	warning: { key: 'ui.logs.warn', cls: 'c-warn', group: 'warn' },
	info: { key: 'ui.logs.info', cls: 'c-info', group: 'info' },
	debug: { key: 'ui.logs.debug', cls: '', group: 'info' },
	verbose: { key: 'ui.logs.debug', cls: '', group: 'info' },
	silly: { key: 'ui.logs.debug', cls: '', group: 'info' },
};
const MAX_LOG_ROWS = 1500;

function parseLogLine(line) {
	const m = line.match(LOG_LINE);
	if (!m) return { time: '', level: null, msg: line };
	// electron-log: "[date time] [level] msg" – the optional scope comes first in some formats
	let level = (m[4] || m[3] || '').toLowerCase();
	let msg = m[5];
	if (!LOG_LEVELS[level]) {
		if (m[3] && !m[4]) msg = `[${m[3]}] ${msg}`;
		level = null;
	}
	return { time: `${m[1]} ${m[2]}`, level, msg };
}

async function refreshLogs() {
	el.logRows.textContent = '';
	el.logEmpty.hidden = false;
	el.logEmpty.textContent = t('logs.loading');
	logText = (await logs.get({ period: logPeriod })) || '';
	renderLogs();
	$('#log-output').scrollTop = 0; // newest on top
}

function renderLogs() {
	if (!el.logRows) return;
	const query = ($('#log-search').value || '').toLowerCase();
	const entries = logText.split('\n').filter((l) => l.trim()).map(parseLogLine);
	const filtered = entries.filter((e) => {
		if (logLevel !== 'all') {
			if (!e.level || LOG_LEVELS[e.level].group !== logLevel) return false;
		}
		if (query && !`${e.msg} ${e.time}`.toLowerCase().includes(query)) return false;
		return true;
	});

	el.logRows.textContent = '';
	const frag = document.createDocumentFragment();
	filtered.slice(0, MAX_LOG_ROWS).forEach((e) => {
		const row = h('div', 'log-row');
		row.setAttribute('role', 'row');
		const time = h('span', 'log-time', e.time);
		time.setAttribute('role', 'cell');
		row.appendChild(time);
		const lvl = h('span', 'log-level');
		lvl.setAttribute('role', 'cell');
		if (e.level) lvl.appendChild(h('span', `chip chip-sm ${LOG_LEVELS[e.level].cls}`, t(LOG_LEVELS[e.level].key)));
		row.appendChild(lvl);
		const msg = h('span', 'log-msg', e.msg);
		msg.setAttribute('role', 'cell');
		row.appendChild(msg);
		frag.appendChild(row);
	});
	el.logRows.appendChild(frag);

	$('#log-count').textContent = t('ui.logs.count', { count: filtered.length });
	el.logEmpty.hidden = filtered.length > 0;
	el.logEmpty.textContent = entries.length === 0 ? t('logs.empty') : t('ui.logs.noMatch');
}

$('#btn-refresh-logs').addEventListener('click', refreshLogs);
$('#log-search').addEventListener('input', renderLogs);
bindSeg($('#log-level-filter'), 'level', (lvl) => { logLevel = lvl; renderLogs(); });
bindSeg($('#log-period-filter'), 'period', (period) => { logPeriod = period; refreshLogs(); });

// Log export
// Shows the log file in Explorer (shell:open-external only takes http(s)).
async function exportLogs() {
	await logs.show();
}
$('#btn-export-logs').addEventListener('click', exportLogs);
$('#btn-export-logs-adv').addEventListener('click', exportLogs);

// ══════════════════════════════════════════════════════════
//  AUTO-UPDATE UI
// ══════════════════════════════════════════════════════════
function showUpdateBanner(info) {
	pendingUpdate = info;
	updateCardHidden = false;
	renderUpdateCard();
}

function renderUpdateCard() {
	const state = window.GCUpdateState.updateCardState(pendingUpdate, updatePolicy, updateCardHidden);
	const card = $('#update-card');
	card.hidden = !state.visible;
	card.classList.toggle('mandatory', state.mandatory);
	$('#update-later').hidden = !state.dismissable;

	// Persistent banner on the overview (no dismiss button)
	const banner = $('#update-required-banner');
	banner.hidden = !state.mandatory;

	if (pendingUpdate) {
		const requiredDesc = state.minVersion
			? t('update.requiredDesc', { minVersion: state.minVersion, version: state.version })
			: t('update.requiredDescNoMin', { version: state.version });
		$('#update-title').textContent = state.mandatory ? t('update.required') : t('ui.update.ready', { version: state.version });
		$('#update-desc').textContent = state.mandatory
			? `${requiredDesc} ${t('update.requiredTunnelHint')}`
			: t('ui.update.readyDesc');
		$('#update-status-title').textContent = state.mandatory ? t('update.required') : t('update.available', { version: state.version });
		$('#update-status-desc').textContent = state.mandatory ? requiredDesc : t('update.readyToInstall');
		$('#update-required-text').textContent = `${requiredDesc} ${t('update.requiredTunnelHint')}`;
	}

	const channel = $('#update-channel');
	if (channel) {
		const ch = updatePolicy && updatePolicy.channel;
		channel.textContent = t(window.GCUpdateState.channelLabelKey(ch));
		channel.classList.toggle('c-warn', ch === 'beta');
	}
}

function applyUpdatePolicy(policy) {
	updatePolicy = policy || null;
	renderUpdateCard();
}

$('#update-install').addEventListener('click', () => update.install());
$('#update-required-install').addEventListener('click', () => update.install());
$('#update-later').addEventListener('click', () => { updateCardHidden = true; renderUpdateCard(); });

update.onReady((info) => showUpdateBanner(info));
update.onPolicy((policy) => applyUpdatePolicy(policy));
update.check().then((info) => { if (info) showUpdateBanner(info); }).catch(() => {});
update.policy().then((policy) => applyUpdatePolicy(policy)).catch(() => {});

// ── Manual Update Check Button (Settings → About) ───────
$('#nav-update')?.addEventListener('click', async () => {
	const btn = $('#nav-update');
	btn.disabled = true;
	btn.textContent = t('ui.about.checking');
	try {
		const info = await update.check();
		update.policy().then((policy) => applyUpdatePolicy(policy)).catch(() => {});
		if (info) {
			showUpdateBanner(info);
		} else {
			$('#update-status-title').textContent = t('ui.about.upToDate');
			$('#update-status-desc').textContent = t('update.noUpdate');
			showToast(t('update.noUpdate'), 'success');
		}
	} catch {
		$('#update-status-desc').textContent = t('update.checkFailed');
		showToast(t('update.checkFailed'), 'error');
	} finally {
		btn.disabled = false;
		btn.textContent = t('update.checkBtn');
	}
});

// ── Peer Expiry Warning ─────────────────────────────────
peer.onExpiry((info) => {
	expiryInfo = info;
	expiryHidden = false;
	renderExpiry();
});

function renderExpiry() {
	const banner = $('#expiry-banner');
	if (!expiryInfo || expiryHidden) { banner.hidden = true; return; }
	let msg;
	let critical = false;
	if (expiryInfo.daysLeft <= 0) { msg = t('peer.expired'); critical = true; }
	else if (expiryInfo.daysLeft <= 1) { msg = t('peer.expiresToday'); critical = true; }
	else msg = t('peer.expiresInDays', { days: expiryInfo.daysLeft });
	banner.classList.toggle('banner-err', critical);
	banner.classList.toggle('banner-warn', !critical);
	$('#expiry-text').textContent = msg;
	banner.hidden = false;
}

$('#expiry-dismiss').addEventListener('click', () => { expiryHidden = true; renderExpiry(); });

// Initial paint (before the locale round-trip finishes)
updateDOM();
updateUI();
renderSplit();
renderSetupProgress();
