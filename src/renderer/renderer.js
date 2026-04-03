/**
 * GateControl Pro Client -- Renderer
 * UI logic, state management, and RDP panel controller.
 *
 * Note: innerHTML is used ONLY for static SVG icon literals (no user data).
 * All user-facing text uses textContent for XSS safety.
 */

const {
	tunnel, server, config, killSwitch, autostart, logs, update,
	services, traffic, dns, shell, peer, permissions, getVersion,
	window: win, rdp, onNavigate,
} = window.gatecontrol;

// ── Helpers ─────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function showToast(message, type = 'error', duration = 5000) {
	const toast = document.createElement('div');
	toast.className = `toast toast-${type}`;
	toast.textContent = message;
	toast.style.cssText = 'position:fixed;top:16px;left:16px;z-index:200;padding:10px 16px;border-radius:var(--radius-sm);font-size:12px;max-width:320px;opacity:0;transition:opacity 0.3s ease;pointer-events:auto;cursor:pointer';
	if (type === 'error') {
		toast.style.background = 'rgba(239,68,68,0.95)';
		toast.style.color = '#fff';
	} else if (type === 'success') {
		toast.style.background = 'rgba(34,197,94,0.95)';
		toast.style.color = '#fff';
	} else {
		toast.style.background = 'var(--bg-3)';
		toast.style.color = 'var(--text-1)';
		toast.style.border = '1px solid var(--border-2)';
	}
	toast.addEventListener('click', () => {
		toast.style.opacity = '0';
		setTimeout(() => toast.remove(), 300);
	});
	document.body.appendChild(toast);
	requestAnimationFrame(() => { toast.style.opacity = '1'; });
	setTimeout(() => {
		toast.style.opacity = '0';
		setTimeout(() => toast.remove(), 300);
	}, duration);
}

function formatBytes(bytes) {
	if (!bytes || bytes <= 0) return '0 B';
	const units = ['B', 'KB', 'MB', 'GB', 'TB'];
	const i = Math.floor(Math.log(bytes) / Math.log(1024));
	const val = (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0);
	return `${val} ${units[i]}`;
}

function formatSpeed(bytesPerSec) {
	if (bytesPerSec < 1) return '';
	if (bytesPerSec < 1024) return `${Math.round(bytesPerSec)} B/s`;
	if (bytesPerSec < 1048576) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
	return `${(bytesPerSec / 1048576).toFixed(1)} MB/s`;
}

// Static SVG icon constants (safe string literals, no user data)
const SVG_ICONS = {
	connected: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
	connecting: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>',
	disconnected: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18.36 6.64A9 9 0 015.64 18.36M5.64 5.64A9 9 0 0118.36 18.36"/></svg>',
	play: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
	playLarge: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
	wol: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="11" height="11"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
	globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/></svg>',
	stepPending: '<svg viewBox="0 0 24 24" fill="none" stroke="var(--text-4)" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>',
	stepDone: '<svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
	stepActive: '<svg viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>',
	stepError: '<svg viewBox="0 0 24 24" fill="none" stroke="var(--error)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
};

/**
 * Sets innerHTML with a static SVG icon. Only use with SVG_ICONS constants above.
 * NEVER pass user data to this function.
 */
function setStaticIcon(element, iconKey) {
	// eslint-disable-next-line no-unsanitized/property -- static SVG constants only
	element.innerHTML = SVG_ICONS[iconKey]; // SAFE: static string literal from SVG_ICONS
}

// ── State ────────────────────────────────────────────────
let state = { status: 'disconnected', connected: false };
let activePermissions = { services: true, traffic: true, dns: true };
let rdpServices = [];
let panelOpen = false;
let pinned = false;
let currentRdpRoute = null; // route being viewed/connected

// ── DOM Elements ─────────────────────────────────────────
const el = {
	ringFill:        $('#ring-fill'),
	ringContainer:   $('#ring-container'),
	statusIcon:      $('#status-icon'),
	statusLabel:     $('#status-label'),
	connectBtn:      $('#connect-btn'),
	statEndpoint:    $('#stat-endpoint'),
	statHandshake:   $('#stat-handshake'),
	statRx:          $('#stat-rx'),
	statTx:          $('#stat-tx'),
	statRxSpeed:     $('#stat-rx-speed'),
	statTxSpeed:     $('#stat-tx-speed'),
	killswitchToggle: $('#killswitch-toggle'),
	serverUrl:       $('#server-url'),
	apiKey:          $('#api-key'),
	serverStatus:    $('#server-status'),
	optAutostart:    $('#opt-autostart'),
	optMinimized:    $('#opt-minimized'),
	optAutoconnect:  $('#opt-autoconnect'),
	optCheckInterval: $('#opt-check-interval'),
	optPollInterval: $('#opt-poll-interval'),
	optSplitTunnel:  $('#opt-split-tunnel'),
	optSplitRoutes:  $('#opt-split-routes'),
	splitRoutesSection: $('#split-routes-section'),
	logOutput:       $('#log-output'),
};

// ── Version ──────────────────────────────────────────────
getVersion().then(v => {
	const verEl = $('#app-version');
	if (verEl) verEl.textContent = `v${v}`;
});

// ══════════════════════════════════════════════════════════
//  THEME
// ══════════════════════════════════════════════════════════
config.get('app.theme').then(theme => applyTheme(theme || 'dark'));

function applyTheme(theme) {
	if (theme === 'light') {
		document.documentElement.setAttribute('data-theme', 'light');
	} else {
		document.documentElement.removeAttribute('data-theme');
	}
	$$('.theme-btn').forEach(btn => {
		btn.classList.toggle('active', btn.dataset.theme === theme);
	});
}

// Theme toggle in titlebar
$$('#theme-toggle .theme-btn').forEach(btn => {
	btn.addEventListener('click', () => {
		const theme = btn.dataset.theme;
		applyTheme(theme);
		config.set('app.theme', theme);
	});
});

// ══════════════════════════════════════════════════════════
//  TITLEBAR
// ══════════════════════════════════════════════════════════
$('#btn-minimize').addEventListener('click', () => win.minimize());
$('#btn-close').addEventListener('click', () => win.close());

// ══════════════════════════════════════════════════════════
//  NAVIGATION
// ══════════════════════════════════════════════════════════
function navigateTo(page) {
	// Update page nav buttons (exclude RDP button)
	$$('.nav-btn[data-page]').forEach(b => b.classList.remove('active'));
	const targetBtn = $(`.nav-btn[data-page="${page}"]`);
	if (targetBtn) targetBtn.classList.add('active');

	// Show page
	$$('.page').forEach(p => p.classList.remove('active'));
	const pageEl = $(`#page-${page}`);
	if (pageEl) pageEl.classList.add('active');

	// If not pinned, close RDP panel on page change
	if (!pinned && panelOpen) {
		closeRdpPanel();
	}

	// Load logs when switching to that tab
	if (page === 'logs') refreshLogs();
}

// Page nav buttons
$$('.nav-btn[data-page]').forEach(btn => {
	btn.addEventListener('click', () => navigateTo(btn.dataset.page));
});

// RDP button toggles panel
$('#nav-rdp').addEventListener('click', () => toggleRdpPanel());

// Navigation from main process
onNavigate((page) => navigateTo(page));

// ══════════════════════════════════════════════════════════
//  RDP PANEL - SLIDE OUT
// ══════════════════════════════════════════════════════════
function toggleRdpPanel() {
	if (panelOpen && !pinned) {
		closeRdpPanel();
	} else if (!panelOpen) {
		openRdpPanel();
	}
}

function openRdpPanel() {
	panelOpen = true;
	document.body.classList.add('panel-open');
	$('#rdp-panel').classList.add('open');
	$('#nav-rdp').classList.add('rdp-active');
	showRdpView('list');
	rdp.panelOpen();
	loadRdpServices();
}

function closeRdpPanel() {
	panelOpen = false;
	document.body.classList.remove('panel-open');
	$('#rdp-panel').classList.remove('open');
	$('#nav-rdp').classList.remove('rdp-active');
	rdp.panelClose();
}

// Close button
$('#rdp-close-btn').addEventListener('click', () => closeRdpPanel());

// ── Pin behavior ─────────────────────────────────────────
function togglePin() {
	pinned = !pinned;
	const btn = $('#rdp-pin-btn');
	const navBtn = $('#nav-rdp');
	if (pinned) {
		btn.classList.add('pinned');
		btn.title = 'Panel abdocken';
		navBtn.classList.add('rdp-pinned');
	} else {
		btn.classList.remove('pinned');
		btn.title = 'Panel andocken';
		navBtn.classList.remove('rdp-pinned');
	}
	rdp.pinToggle(pinned);
}

$('#rdp-pin-btn').addEventListener('click', () => togglePin());

// ── Panel view switching ─────────────────────────────────
function showRdpView(view) {
	$$('.rdp-panel-view').forEach(v => v.classList.remove('active'));
	const target = $(`#rdp-view-${view}`);
	if (target) target.classList.add('active');
}

// ══════════════════════════════════════════════════════════
//  RDP SERVICES - LOADING & RENDERING
// ══════════════════════════════════════════════════════════
async function loadRdpServices() {
	try {
		const list = await rdp.list();
		rdpServices = list || [];
		renderRdpCards(rdpServices);
		updateRdpBadge();
	} catch (err) {
		rdpServices = [];
		renderRdpCards([]);
	}
}

function updateRdpBadge() {
	const badge = $('#rdp-badge');
	const onlineCount = rdpServices.filter(s => s.status?.online).length;
	if (onlineCount > 0) {
		badge.style.display = '';
	} else {
		badge.style.display = 'none';
	}
}

function renderRdpCards(svcList) {
	const container = $('#rdp-list');
	const countEl = $('#rdp-count');
	container.textContent = '';

	// Apply filters
	const filterText = ($('#rdp-filter-input').value || '').toLowerCase();
	const filterStatus = $('#rdp-filter-select').value;

	const filtered = svcList.filter(svc => {
		// Text filter
		if (filterText) {
			const searchable = [
				svc.name, svc.host, ...(svc.tags || []),
			].join(' ').toLowerCase();
			if (!searchable.includes(filterText)) return false;
		}
		// Status filter
		if (filterStatus === 'online' && !svc.status?.online) return false;
		if (filterStatus === 'offline' && svc.status?.online) return false;
		return true;
	});

	countEl.textContent = `${filtered.length} Host${filtered.length !== 1 ? 's' : ''}`;

	filtered.forEach(svc => {
		const card = createRdpCard(svc);
		container.appendChild(card);
	});
}

function createRdpCard(svc) {
	const card = document.createElement('div');
	card.className = 'rdp-card';
	if (svc.maintenance_active) card.classList.add('maintenance');
	card.addEventListener('click', () => showRdpDetail(svc));

	// Top row: name + status tag
	const top = document.createElement('div');
	top.className = 'rdp-card-top';

	const nameBlock = document.createElement('div');
	const name = document.createElement('div');
	name.className = 'rdp-card-name';
	name.textContent = svc.name;
	nameBlock.appendChild(name);

	const host = document.createElement('div');
	host.className = 'rdp-card-host';
	host.textContent = `${svc.host}:${svc.port || 3389}`;
	nameBlock.appendChild(host);

	top.appendChild(nameBlock);

	const statusTag = document.createElement('span');
	statusTag.className = 'tag';
	if (svc.status?.online) {
		statusTag.classList.add('tag-online');
		statusTag.textContent = 'Online';
	} else if (svc.maintenance_active) {
		statusTag.classList.add('tag-warn');
		statusTag.textContent = 'Wartung';
	} else {
		statusTag.classList.add('tag-offline');
		statusTag.textContent = 'Offline';
	}
	top.appendChild(statusTag);
	card.appendChild(top);

	// Tags
	if (svc.tags && svc.tags.length > 0) {
		const tagsRow = document.createElement('div');
		tagsRow.className = 'rdp-card-tags';
		svc.tags.forEach(t => {
			const tag = document.createElement('span');
			tag.className = 'tag tag-neutral';
			tag.textContent = t;
			tagsRow.appendChild(tag);
		});
		card.appendChild(tagsRow);
	}

	// Meta
	const meta = document.createElement('div');
	meta.className = 'rdp-card-meta';

	// Access type
	const accessRow = document.createElement('div');
	accessRow.className = 'rdp-card-meta-row';
	const accessLabel = document.createElement('span');
	accessLabel.textContent = 'Zugriff';
	accessRow.appendChild(accessLabel);
	const accessTag = document.createElement('span');
	accessTag.className = 'tag';
	accessTag.style.fontSize = '9px';
	if (svc.access_type === 'external') {
		accessTag.classList.add('tag-purple');
		accessTag.textContent = 'Extern+Intern';
	} else {
		accessTag.classList.add('tag-blue');
		accessTag.textContent = 'Intern';
	}
	accessRow.appendChild(accessTag);
	meta.appendChild(accessRow);

	// Credentials
	const credRow = document.createElement('div');
	credRow.className = 'rdp-card-meta-row';
	const credLabel = document.createElement('span');
	credLabel.textContent = 'Credentials';
	credRow.appendChild(credLabel);
	const credValue = document.createElement('span');
	if (svc.credential_mode === 'full') {
		credValue.style.color = 'var(--accent)';
		credValue.textContent = 'Vollständig';
	} else if (svc.credential_mode === 'user_only') {
		credValue.style.color = 'var(--warn)';
		credValue.textContent = 'Nur Username';
	} else {
		credValue.style.color = 'var(--text-3)';
		credValue.textContent = 'Keine';
	}
	credRow.appendChild(credValue);
	meta.appendChild(credRow);

	// WoL for offline hosts
	if (!svc.status?.online && svc.wol_mac) {
		const wolRow = document.createElement('div');
		wolRow.className = 'rdp-card-meta-row';
		const wolLabel = document.createElement('span');
		wolLabel.textContent = 'WoL';
		wolRow.appendChild(wolLabel);
		const wolMac = document.createElement('span');
		wolMac.style.fontFamily = 'var(--font-mono)';
		wolMac.style.fontSize = '10px';
		wolMac.textContent = svc.wol_mac;
		wolRow.appendChild(wolMac);
		meta.appendChild(wolRow);
	}

	// Maintenance info
	if (svc.maintenance_window) {
		const maintRow = document.createElement('div');
		maintRow.className = 'rdp-card-meta-row';
		const maintLabel = document.createElement('span');
		maintLabel.textContent = 'Wartung';
		maintRow.appendChild(maintLabel);
		const maintValue = document.createElement('span');
		if (svc.maintenance_active) {
			maintValue.style.color = 'var(--warn)';
			maintValue.textContent = 'Aktiv';
		} else {
			maintValue.textContent = svc.maintenance_window;
		}
		maintRow.appendChild(maintValue);
		meta.appendChild(maintRow);
	}

	card.appendChild(meta);

	// Actions
	const actions = document.createElement('div');
	actions.className = 'rdp-card-actions';

	// WoL button for offline hosts
	if (!svc.status?.online && svc.wol_mac) {
		const wolBtn = document.createElement('button');
		wolBtn.className = 'btn btn-wol';
		setStaticIcon(wolBtn, 'wol'); // SAFE: static SVG
		wolBtn.appendChild(document.createTextNode('WoL'));
		wolBtn.addEventListener('click', (e) => {
			e.stopPropagation();
			rdp.wol(svc.id);
			wolBtn.textContent = 'Gesendet';
			wolBtn.disabled = true;
			setTimeout(() => { wolBtn.disabled = false; wolBtn.textContent = 'WoL'; }, 5000);
		});
		actions.appendChild(wolBtn);
	}

	// Connect button
	const connectBtn = document.createElement('button');
	connectBtn.className = 'btn btn-connect';
	if (!svc.status?.online && !svc.maintenance_active) {
		connectBtn.disabled = true;
	}
	const playSpan = document.createElement('span');
	setStaticIcon(playSpan, 'play'); // SAFE: static SVG
	connectBtn.appendChild(playSpan);
	connectBtn.appendChild(document.createTextNode('Verbinden'));
	connectBtn.addEventListener('click', (e) => {
		e.stopPropagation();
		startRdpConnect(svc);
	});
	actions.appendChild(connectBtn);

	card.appendChild(actions);
	return card;
}

// Filter event listeners
$('#rdp-filter-input').addEventListener('input', () => renderRdpCards(rdpServices));
$('#rdp-filter-select').addEventListener('change', () => renderRdpCards(rdpServices));

// ══════════════════════════════════════════════════════════
//  RDP DETAIL VIEW
// ══════════════════════════════════════════════════════════
function showRdpDetail(svc) {
	currentRdpRoute = svc;
	$('#rdp-detail-title').textContent = svc.name;

	// Status tag
	const statusEl = $('#rdp-detail-status');
	statusEl.className = 'tag';
	if (svc.status?.online) {
		statusEl.classList.add('tag-online');
		statusEl.textContent = 'Online';
	} else if (svc.maintenance_active) {
		statusEl.classList.add('tag-warn');
		statusEl.textContent = 'Wartung';
	} else {
		statusEl.classList.add('tag-offline');
		statusEl.textContent = 'Offline';
	}

	// Build detail body
	const body = $('#rdp-detail-body');
	body.textContent = '';

	// Detail grid
	const grid = document.createElement('div');
	grid.className = 'rdp-detail-grid';

	const fields = [
		{ label: 'Host', value: `${svc.host}:${svc.port || 3389}`, mono: true },
		{ label: 'Zugriff', value: svc.access_type === 'external' ? 'Extern+Intern' : 'Nur intern', tag: svc.access_type === 'external' ? 'tag-purple' : 'tag-blue' },
		{ label: 'Credentials', value: svc.credential_mode === 'full' ? 'Vollständig' : svc.credential_mode === 'user_only' ? 'Nur Username' : 'Keine', color: svc.credential_mode === 'full' ? 'var(--accent)' : svc.credential_mode === 'user_only' ? 'var(--warn)' : null },
		{ label: 'Domain', value: svc.domain || '-', mono: true },
		{ label: 'Auflösung', value: svc.resolution || 'Vollbild' },
		{ label: 'NLA', value: svc.nla ? 'Erzwungen' : 'Optional', color: svc.nla ? 'var(--accent)' : null },
	];

	if (svc.redirects) {
		fields.push({ label: 'Redirects', value: svc.redirects });
	}
	if (svc.timeout_minutes) {
		fields.push({ label: 'Timeout', value: `${svc.timeout_minutes} Min` });
	}
	if (svc.maintenance_window) {
		fields.push({ label: 'Wartung', value: svc.maintenance_window, full: true });
	}
	if (svc.notes) {
		fields.push({ label: 'Notizen', value: svc.notes, full: true, dim: true });
	}

	fields.forEach(f => {
		const item = document.createElement('div');
		item.className = 'rdp-detail-item';
		if (f.full) item.classList.add('rdp-detail-full');

		const label = document.createElement('div');
		label.className = 'rdp-detail-label';
		label.textContent = f.label;
		item.appendChild(label);

		const val = document.createElement('div');
		val.className = 'rdp-detail-value';
		if (f.mono) val.classList.add('mono');
		if (f.dim) {
			val.style.color = 'var(--text-2)';
			val.style.fontWeight = '400';
			val.style.fontSize = '10px';
		}

		if (f.tag) {
			const tagSpan = document.createElement('span');
			tagSpan.className = `tag ${f.tag}`;
			tagSpan.style.fontSize = '9px';
			tagSpan.textContent = f.value;
			val.appendChild(tagSpan);
		} else {
			if (f.color) val.style.color = f.color;
			val.textContent = f.value;
		}

		item.appendChild(val);
		grid.appendChild(item);
	});

	body.appendChild(grid);

	// Tags
	if (svc.tags && svc.tags.length > 0) {
		const tagsRow = document.createElement('div');
		tagsRow.className = 'rdp-card-tags';
		svc.tags.forEach(t => {
			const tag = document.createElement('span');
			tag.className = 'tag tag-neutral';
			tag.textContent = t;
			tagsRow.appendChild(tag);
		});
		body.appendChild(tagsRow);
	}

	// Connect button
	const connectBtn = document.createElement('button');
	connectBtn.className = 'btn btn-connect';
	connectBtn.style.cssText = 'width:100%;padding:11px;font-size:13px';
	if (!svc.status?.online && !svc.maintenance_active) {
		connectBtn.disabled = true;
	}
	const playIcon = document.createElement('span');
	setStaticIcon(playIcon, 'playLarge'); // SAFE: static SVG
	connectBtn.appendChild(playIcon);
	connectBtn.appendChild(document.createTextNode('Remote Desktop verbinden'));
	connectBtn.addEventListener('click', () => startRdpConnect(svc));
	body.appendChild(connectBtn);

	showRdpView('detail');
}

// Detail back button
$('#rdp-detail-back').addEventListener('click', () => showRdpView('list'));

// ══════════════════════════════════════════════════════════
//  RDP CONNECT FLOW
// ══════════════════════════════════════════════════════════
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
			$('#rdp-connecting-status').textContent = 'Remote Desktop Verbindung aktiv';
		}
	} catch (err) {
		$('#rdp-connecting-status').textContent = err.message || 'Verbindungsfehler';
	}
}

// ── Password Prompt ──────────────────────────────────────
function showPasswordPrompt(svc) {
	$('#rdp-password-title').textContent = svc.name;
	const userEl = $('#rdp-password-user');
	const username = svc.username || '';
	const domain = svc.domain || 'WORKGROUP';
	userEl.textContent = `Benutzer: ${domain}\\${username}`;
	$('#rdp-password-input').value = '';
	showRdpView('password');
	$('#rdp-password-input').focus();
}

$('#rdp-password-back').addEventListener('click', () => showRdpView('list'));
$('#rdp-password-cancel').addEventListener('click', () => showRdpView('list'));

$('#rdp-password-submit').addEventListener('click', async () => {
	const password = $('#rdp-password-input').value;
	if (!password || !currentRdpRoute) return;
	startRdpConnect(currentRdpRoute, { password });
});

// Submit on Enter
$('#rdp-password-input').addEventListener('keydown', (e) => {
	if (e.key === 'Enter') $('#rdp-password-submit').click();
});

// ── Maintenance Warning ──────────────────────────────────
function showMaintenanceWarning(svc, windowText) {
	$('#rdp-maintenance-title').textContent = svc.name;
	$('#rdp-maintenance-window').textContent =
		windowText ? `Geplante Wartung: ${windowText}. Trotzdem verbinden?`
		           : 'Ausserhalb des Wartungsfensters. Trotzdem verbinden?';
	showRdpView('maintenance');
}

$('#rdp-maintenance-back').addEventListener('click', () => showRdpView('list'));
$('#rdp-maintenance-cancel').addEventListener('click', () => showRdpView('list'));

$('#rdp-maintenance-force').addEventListener('click', () => {
	if (!currentRdpRoute) return;
	startRdpConnect(currentRdpRoute, { forceMaintenanceBypass: true });
});

// ── Connecting Progress ──────────────────────────────────
const PROGRESS_STEPS = [
	{ id: 'vpn-check',   label: 'VPN-Tunnel aktiv' },
	{ id: 'tcp-check',   label: 'Host erreichbar (TCP-Check)' },
	{ id: 'credentials', label: 'Credentials verarbeitet' },
	{ id: 'rdp-file',    label: 'RDP-Konfiguration erstellt' },
	{ id: 'mstsc',       label: 'Remote Desktop wird gestartet...' },
];

function showConnectingProgress(svc) {
	$('#rdp-connecting-title').textContent = svc.name;
	$('#rdp-connecting-status').textContent = 'Verbindung wird hergestellt...';

	const stepsContainer = $('#rdp-progress-steps');
	stepsContainer.textContent = '';

	PROGRESS_STEPS.forEach(step => {
		const stepEl = document.createElement('div');
		stepEl.className = 'rdp-step';
		stepEl.id = `rdp-step-${step.id}`;

		const icon = document.createElement('div');
		icon.className = 'rdp-step-icon';
		setStaticIcon(icon, 'stepPending'); // SAFE: static SVG
		stepEl.appendChild(icon);

		stepEl.appendChild(document.createTextNode(step.label));
		stepsContainer.appendChild(stepEl);
	});

	showRdpView('connecting');
}

function updateProgressStep(stepId, status) {
	const stepEl = $(`#rdp-step-${stepId}`);
	if (!stepEl) return;

	const icon = stepEl.querySelector('.rdp-step-icon');
	stepEl.classList.remove('rdp-step-done', 'rdp-step-active', 'rdp-step-error');

	if (status === 'done') {
		stepEl.classList.add('rdp-step-done');
		setStaticIcon(icon, 'stepDone'); // SAFE: static SVG
	} else if (status === 'active') {
		stepEl.classList.add('rdp-step-active');
		setStaticIcon(icon, 'stepActive'); // SAFE: static SVG
	} else if (status === 'error') {
		stepEl.classList.add('rdp-step-error');
		setStaticIcon(icon, 'stepError'); // SAFE: static SVG
	}
}

$('#rdp-connecting-back').addEventListener('click', () => showRdpView('list'));

// ══════════════════════════════════════════════════════════
//  IPC EVENT BINDINGS (RDP)
// ══════════════════════════════════════════════════════════
rdp.onProgress((data) => {
	if (data.step && data.status) {
		// Treat 'skip', 'fallback' as done
		const normalizedStatus = ['skip', 'fallback'].includes(data.status) ? 'done' : data.status;
		updateProgressStep(data.step, normalizedStatus);

		// Update status text based on current step
		const statusMessages = {
			'vpn-check': 'VPN-Tunnel wird geprüft...',
			'tcp-check': 'Host-Erreichbarkeit wird geprüft...',
			'credentials': 'Credentials werden verarbeitet...',
			'rdp-file': 'RDP-Konfiguration wird erstellt...',
			'mstsc': 'Remote Desktop wird gestartet...',
			'cmdkey': 'Credentials werden gespeichert...',
		};
		if (data.status === 'active' && statusMessages[data.step]) {
			$('#rdp-connecting-status').textContent = statusMessages[data.step];
		}
		if (data.status === 'done' && data.step === 'mstsc') {
			$('#rdp-connecting-status').textContent = 'Remote Desktop Verbindung aktiv';
		}
	}
	if (data.message) {
		$('#rdp-connecting-status').textContent = data.message;
	}
});

rdp.onSessionStart((data) => {
	// Refresh the card list to show active session
	loadRdpServices();
});

rdp.onSessionEnd((data) => {
	loadRdpServices();
	// If we're on connecting view, go back to list
	if ($('#rdp-view-connecting').classList.contains('active')) {
		showRdpView('list');
	}
});

rdp.onSessionError((data) => {
	if (data.step) {
		updateProgressStep(data.step, 'error');
	}
	if (data.message) {
		$('#rdp-connecting-status').textContent = data.message;
	}
});

rdp.onServicesUpdate((data) => {
	rdpServices = data || [];
	if (panelOpen && $('#rdp-view-list').classList.contains('active')) {
		renderRdpCards(rdpServices);
	}
	updateRdpBadge();
});

// ══════════════════════════════════════════════════════════
//  TUNNEL STATE UPDATES
// ══════════════════════════════════════════════════════════
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
	const { status, connected, endpoint, handshake, rxBytes, txBytes, rxSpeed, txSpeed, killSwitch: ks } = state;

	// Ring
	el.ringFill.classList.remove('connected', 'connecting');
	el.statusIcon.classList.remove('connected', 'connecting');

	if (connected || status === 'connected') {
		el.ringFill.classList.add('connected');
		el.statusIcon.classList.add('connected');
		setStaticIcon(el.statusIcon, 'connected'); // SAFE: static SVG
		el.statusLabel.textContent = 'Verbunden';
		el.statusLabel.style.color = 'var(--accent)';

		el.connectBtn.classList.add('connected');
		el.connectBtn.classList.remove('connecting');
		el.connectBtn.querySelector('.connect-btn-text').textContent = 'Trennen';

	} else if (status === 'connecting' || status === 'reconnecting') {
		el.ringFill.classList.add('connecting');
		el.statusIcon.classList.add('connecting');
		setStaticIcon(el.statusIcon, 'connecting'); // SAFE: static SVG
		el.statusLabel.textContent = status === 'reconnecting' ? 'Reconnecting...' : 'Verbinde...';
		el.statusLabel.style.color = 'var(--warn)';

		el.connectBtn.classList.remove('connected');
		el.connectBtn.classList.add('connecting');

	} else {
		setStaticIcon(el.statusIcon, 'disconnected'); // SAFE: static SVG
		el.statusLabel.textContent = 'Getrennt';
		el.statusLabel.style.color = 'var(--text-3)';

		el.connectBtn.classList.remove('connected', 'connecting');
		el.connectBtn.querySelector('.connect-btn-text').textContent = 'Verbinden';
	}

	// Stats
	el.statEndpoint.textContent = endpoint || '\u2014';
	el.statHandshake.textContent = handshake || '\u2014';
	el.statRx.textContent = formatBytes(rxBytes || 0);
	el.statTx.textContent = formatBytes(txBytes || 0);

	// Speed + Graph
	if (connected && activePermissions.traffic && (rxSpeed || txSpeed)) {
		el.statRxSpeed.textContent = formatSpeed(rxSpeed || 0);
		el.statTxSpeed.textContent = formatSpeed(txSpeed || 0);
		updateBandwidthGraph(rxSpeed || 0, txSpeed || 0);
	} else {
		el.statRxSpeed.textContent = '';
		el.statTxSpeed.textContent = '';
	}

	// Bandwidth graph visibility
	const bwSection = $('#bandwidth-section');
	if (bwSection) bwSection.style.display = (connected && activePermissions.traffic) ? '' : 'none';

	// Kill-Switch
	el.killswitchToggle.checked = ks || false;
}

// ── Connect Button ───────────────────────────────────────
el.connectBtn.addEventListener('click', async () => {
	if (state.status === 'connecting') return;
	if (state.connected) {
		await tunnel.disconnect();
	} else {
		await tunnel.connect();
	}
});

// ── Kill-Switch Toggle ───────────────────────────────────
el.killswitchToggle.addEventListener('change', (e) => {
	killSwitch.toggle(e.target.checked);
});

// ══════════════════════════════════════════════════════════
//  BANDWIDTH GRAPH (Canvas)
// ══════════════════════════════════════════════════════════
const BW_HISTORY_LEN = 60;
const bwHistory = { rx: [], tx: [] };

function updateBandwidthGraph(rxSpeed, txSpeed) {
	bwHistory.rx.push(rxSpeed);
	bwHistory.tx.push(txSpeed);
	if (bwHistory.rx.length > BW_HISTORY_LEN) bwHistory.rx.shift();
	if (bwHistory.tx.length > BW_HISTORY_LEN) bwHistory.tx.shift();

	const canvas = document.getElementById('bandwidth-canvas');
	if (!canvas) return;

	const ctx = canvas.getContext('2d');
	const dpr = window.devicePixelRatio || 1;
	const w = canvas.clientWidth;
	const h = canvas.clientHeight;

	const newW = w * dpr;
	const newH = h * dpr;
	if (canvas.width !== newW || canvas.height !== newH) {
		canvas.width = newW;
		canvas.height = newH;
	}
	ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
	ctx.clearRect(0, 0, w, h);

	const allValues = [...bwHistory.rx, ...bwHistory.tx];
	const maxVal = Math.max(...allValues, 1024);

	// Grid lines
	const style = getComputedStyle(document.documentElement);
	const gridColor = style.getPropertyValue('--canvas-grid').trim();
	ctx.strokeStyle = gridColor;
	ctx.lineWidth = 1;
	for (let i = 1; i < 4; i++) {
		const y = (h / 4) * i;
		ctx.beginPath();
		ctx.moveTo(0, y);
		ctx.lineTo(w, y);
		ctx.stroke();
	}

	// Scale label
	const isLight = document.documentElement.getAttribute('data-theme') === 'light';
	ctx.fillStyle = isLight ? 'rgba(0,0,0,0.3)' : 'rgba(255,255,255,0.2)';
	ctx.font = '9px monospace';
	ctx.fillText(formatSpeed(maxVal), 2, 10);

	function drawLine(data, lineColor, fillColor) {
		if (data.length < 2) return;
		const step = w / (BW_HISTORY_LEN - 1);

		ctx.beginPath();
		ctx.moveTo(0, h);
		for (let i = 0; i < data.length; i++) {
			const x = (BW_HISTORY_LEN - data.length + i) * step;
			const y = h - (data[i] / maxVal) * (h - 12);
			ctx.lineTo(x, y);
		}
		ctx.lineTo((BW_HISTORY_LEN - 1) * step, h);
		ctx.closePath();
		ctx.fillStyle = fillColor;
		ctx.fill();

		ctx.beginPath();
		for (let i = 0; i < data.length; i++) {
			const x = (BW_HISTORY_LEN - data.length + i) * step;
			const y = h - (data[i] / maxVal) * (h - 12);
			i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
		}
		ctx.strokeStyle = lineColor;
		ctx.lineWidth = 1.5;
		ctx.stroke();
	}

	const lineRx = style.getPropertyValue('--canvas-line').trim();
	const fillRx = style.getPropertyValue('--canvas-fill').trim();
	const lineTx = style.getPropertyValue('--canvas-line2').trim();
	const fillTx = style.getPropertyValue('--canvas-fill2').trim();

	drawLine(bwHistory.tx, lineTx, fillTx);
	drawLine(bwHistory.rx, lineRx, fillRx);
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
	const servicesSection = $('#services-section');
	const trafficSection = $('#traffic-usage');
	const bandwidthSection = $('#bandwidth-section');
	const dnsSection = $('.dns-section');

	if (activePermissions.services) {
		loadServices();
	} else if (servicesSection) {
		servicesSection.style.display = 'none';
	}

	if (activePermissions.traffic) {
		loadTraffic();
	} else {
		if (trafficSection) trafficSection.style.display = 'none';
		if (bandwidthSection) bandwidthSection.style.display = 'none';
	}

	if (!activePermissions.dns && dnsSection) {
		dnsSection.style.display = 'none';
	} else if (dnsSection) {
		dnsSection.style.display = '';
	}
}

async function loadServices() {
	const list = await services.list();
	const section = $('#services-section');
	const container = $('#services-list');
	if (!list || list.length === 0) {
		if (section) section.style.display = 'none';
		return;
	}

	section.style.display = '';
	container.textContent = '';

	list.forEach((svc) => {
		const item = document.createElement('div');
		item.className = 'service-item';
		item.addEventListener('click', () => shell.openExternal(svc.url));

		const icon = document.createElement('div');
		icon.className = 'service-icon';
		setStaticIcon(icon, 'globe'); // SAFE: static SVG
		item.appendChild(icon);

		const info = document.createElement('div');
		info.className = 'service-info';
		const nameEl = document.createElement('div');
		nameEl.className = 'service-name';
		nameEl.textContent = svc.name;
		info.appendChild(nameEl);
		const domain = document.createElement('div');
		domain.className = 'service-domain';
		domain.textContent = svc.domain;
		info.appendChild(domain);
		item.appendChild(info);

		if (svc.hasAuth || svc.protocol) {
			const badge = document.createElement('span');
			badge.className = 'tag tag-online';
			badge.style.fontSize = '9px';
			badge.textContent = svc.protocol || 'HTTPS';
			item.appendChild(badge);
		}

		container.appendChild(item);
	});
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

// ── Traffic Usage ────────────────────────────────────────
async function loadTraffic() {
	const data = await traffic.stats();
	const section = $('#traffic-usage');
	const grid = $('#traffic-grid');
	if (!data || !section || !grid) return;

	section.style.display = '';
	grid.textContent = '';

	const periods = [
		{ label: '24h', data: data.last24h },
		{ label: '7 Tage', data: data.last7d },
		{ label: '30 Tage', data: data.last30d },
		{ label: 'Gesamt', data: data.total },
	];

	for (const p of periods) {
		const card = document.createElement('div');
		card.className = 'traffic-card';

		const period = document.createElement('div');
		period.className = 'traffic-period';
		period.textContent = p.label;
		card.appendChild(period);

		const value = document.createElement('div');
		value.className = 'traffic-value';
		const rx = p.data?.rx || 0;
		const tx = p.data?.tx || 0;
		value.textContent = formatBytes(rx + tx);
		card.appendChild(value);

		const sub = document.createElement('div');
		sub.className = 'traffic-sub';
		sub.textContent = `\u2193 ${formatBytes(rx)} / \u2191 ${formatBytes(tx)}`;
		card.appendChild(sub);

		grid.appendChild(card);
	}
}

// ── DNS Leak Test ────────────────────────────────────────
const dnsBtn = $('#dns-test-btn');
const dnsResult = $('#dns-result');

if (dnsBtn) {
	dnsBtn.addEventListener('click', async () => {
		dnsBtn.disabled = true;
		dnsBtn.textContent = 'Teste...';
		dnsResult.style.display = 'none';

		try {
			const result = await dns.leakTest();
			dnsResult.style.display = '';
			dnsResult.textContent = '';

			if (result.passed) {
				dnsResult.className = 'dns-result pass';
				const title = document.createElement('div');
				title.style.fontWeight = '600';
				title.textContent = 'Kein DNS-Leak erkannt';
				dnsResult.appendChild(title);

				const detail = document.createElement('div');
				detail.style.marginTop = '4px';
				detail.textContent = `Dein Traffic läuft über den VPN-Tunnel. DNS: ${(result.dnsServers || []).join(', ')}`;
				dnsResult.appendChild(detail);
			} else {
				dnsResult.className = 'dns-result fail';
				const title = document.createElement('div');
				title.style.fontWeight = '600';
				title.textContent = 'DNS-Leak möglich';
				dnsResult.appendChild(title);

				const detail = document.createElement('div');
				detail.style.marginTop = '4px';
				detail.textContent = `DNS-Anfragen gehen möglicherweise am VPN vorbei. Aktiviere den Kill-Switch. DNS: ${(result.dnsServers || []).join(', ')}`;
				dnsResult.appendChild(detail);
			}
		} catch {
			showToast('DNS-Leak-Test fehlgeschlagen — Verbindung prüfen.', 'error', 5000);
		}

		dnsBtn.disabled = false;
		dnsBtn.textContent = 'DNS-Leak-Test';
	});
}

// ══════════════════════════════════════════════════════════
//  SETTINGS
// ══════════════════════════════════════════════════════════
// Load settings
config.getAll().then(cfg => {
	if (!cfg) return;
	el.serverUrl.value = cfg.server?.url || '';
	el.apiKey.value = cfg.server?.apiKey || '';
	el.optAutostart.checked = cfg.app?.startWithWindows ?? true;
	el.optMinimized.checked = cfg.app?.startMinimized ?? true;
	applyTheme(cfg.app?.theme || 'dark');
	el.optAutoconnect.checked = cfg.tunnel?.autoConnect ?? true;
	el.optCheckInterval.value = cfg.app?.checkInterval ?? 30;
	el.optPollInterval.value = cfg.app?.configPollInterval ?? 300;
	el.optSplitTunnel.checked = cfg.tunnel?.splitTunnel ?? false;
	el.optSplitRoutes.value = cfg.tunnel?.splitRoutes || '';
	el.splitRoutesSection.style.display = el.optSplitTunnel.checked ? '' : 'none';
});

// API-Key toggle
$('#toggle-api-key').addEventListener('click', () => {
	const input = el.apiKey;
	input.type = input.type === 'password' ? 'text' : 'password';
});

// Server test
$('#btn-test-server').addEventListener('click', async () => {
	showServerStatus('Teste Verbindung...', 'info');
	const url = el.serverUrl.value.trim();
	const key = el.apiKey.value.trim();
	if (!url || !key) {
		showServerStatus('URL und API-Key erforderlich', 'error');
		return;
	}
	const result = await server.test({ url, apiKey: key });
	if (result.success) {
		showServerStatus('Verbindung erfolgreich!', 'success');
	} else {
		showServerStatus(`Fehler: ${result.error}`, 'error');
	}
});

// Server save
$('#btn-save-server').addEventListener('click', async () => {
	const url = el.serverUrl.value.trim();
	const key = el.apiKey.value.trim();
	if (!url || !key) {
		showServerStatus('URL und API-Key erforderlich', 'error');
		return;
	}
	showServerStatus('Registriere Client...', 'info');
	const result = await server.setup({ url, apiKey: key });
	if (result.success) {
		showServerStatus(`Registriert! Peer-ID: ${result.peerId}`, 'success');
	} else {
		showServerStatus(`Fehler: ${result.error}`, 'error');
	}
});

function showServerStatus(message, type) {
	el.serverStatus.hidden = false;
	el.serverStatus.textContent = message;
	el.serverStatus.className = `field-status ${type}`;
	if (type === 'success') {
		setTimeout(() => { el.serverStatus.hidden = true; }, 5000);
	}
}

// Config import
$('#btn-import-file').addEventListener('click', async () => {
	const result = await config.importFile();
	if (result.success) {
		showServerStatus(`Config importiert: ${result.path}`, 'success');
	} else if (result.error) {
		showServerStatus(`Import-Fehler: ${result.error}`, 'error');
	}
});

// QR-Code scanner
let qrStream = null;

$('#btn-import-qr').addEventListener('click', async () => {
	const preview = $('#qr-preview');
	const video = $('#qr-video');
	try {
		qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
		video.srcObject = qrStream;
		preview.hidden = false;
		scanQR();
		setTimeout(() => {
			if (qrStream) {
				stopQRScan();
				showServerStatus('QR-Scan Timeout \u2014 kein Code erkannt.', 'error');
			}
		}, 60000);
	} catch (err) {
		showServerStatus(`Kamera-Fehler: ${err.message}`, 'error');
	}
});

$('#btn-qr-cancel').addEventListener('click', stopQRScan);

function stopQRScan() {
	if (qrStream) {
		qrStream.getTracks().forEach(t => t.stop());
		qrStream = null;
	}
	$('#qr-preview').hidden = true;
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
			if (result.success) {
				stopQRScan();
				showServerStatus('QR-Code erkannt! Config importiert.', 'success');
				return;
			}
		}
		requestAnimationFrame(scan);
	};
	scan();
}

// App settings
el.optAutostart.addEventListener('change', (e) => {
	autostart.set(e.target.checked);
	config.set('app.startWithWindows', e.target.checked);
});

el.optMinimized.addEventListener('change', (e) => {
	config.set('app.startMinimized', e.target.checked);
});

el.optAutoconnect.addEventListener('change', (e) => {
	config.set('tunnel.autoConnect', e.target.checked);
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

// Split-Tunneling
el.optSplitTunnel.addEventListener('change', async (e) => {
	config.set('tunnel.splitTunnel', e.target.checked);
	el.splitRoutesSection.style.display = e.target.checked ? '' : 'none';
	if (state.connected) {
		showSplitStatus(e.target.checked
			? 'Split-Tunneling wird nach Neuverbindung aktiv.'
			: 'Full-Tunnel wird nach Neuverbindung aktiv.', 'info');
		await tunnel.disconnect();
		await tunnel.connect();
	}
});

$('#btn-save-split').addEventListener('click', async () => {
	const routes = el.optSplitRoutes.value.trim();
	config.set('tunnel.splitRoutes', routes);
	if (!routes) {
		showSplitStatus('Keine Routen eingetragen.', 'warn');
		return;
	}
	const count = routes.split('\n').filter(l => l.trim()).length;
	showSplitStatus(`${count} Route(n) gespeichert. Verbindung wird neu aufgebaut...`, 'info');
	if (state.connected) {
		await tunnel.disconnect();
		await tunnel.connect();
	} else {
		showSplitStatus(`${count} Route(n) gespeichert. Wird beim nächsten Verbinden aktiv.`, 'info');
	}
});

function showSplitStatus(msg, type) {
	const statusEl = $('#split-status');
	if (!statusEl) return;
	statusEl.style.display = '';
	statusEl.textContent = msg;
	statusEl.style.color = type === 'warn' ? 'var(--warn)' : 'var(--accent)';
	statusEl.style.background = type === 'warn' ? 'rgba(245,158,11,0.1)' : 'rgba(34,197,94,0.1)';
	setTimeout(() => { statusEl.style.display = 'none'; }, 5000);
}

// ══════════════════════════════════════════════════════════
//  LOGS
// ══════════════════════════════════════════════════════════
async function refreshLogs() {
	el.logOutput.textContent = 'Lade Logs...';
	const logText = await logs.get();
	el.logOutput.textContent = logText || 'Keine Logs verfügbar';
	el.logOutput.scrollTop = el.logOutput.scrollHeight;
}

$('#btn-refresh-logs').addEventListener('click', refreshLogs);

// ══════════════════════════════════════════════════════════
//  AUTO-UPDATE UI
// ══════════════════════════════════════════════════════════
function showUpdateBanner(info) {
	const existing = $('#update-banner');
	if (existing) existing.remove();

	const banner = document.createElement('div');
	banner.id = 'update-banner';
	banner.style.cssText = 'position:fixed;bottom:0;left:0;right:0;padding:12px 16px;background:var(--bg-3);border-top:1px solid var(--accent);display:flex;align-items:center;gap:12px;z-index:100';

	const text = document.createElement('div');
	text.style.cssText = 'flex:1;font-size:12px;color:var(--text-1)';
	const strong = document.createElement('strong');
	strong.textContent = `Update v${info.version}`;
	text.appendChild(strong);
	text.appendChild(document.createTextNode(' bereit zur Installation'));
	banner.appendChild(text);

	const laterBtn = document.createElement('button');
	laterBtn.textContent = 'Später';
	laterBtn.style.cssText = 'padding:6px 12px;font-size:11px;background:transparent;color:var(--text-3);border:1px solid var(--border-2);border-radius:var(--radius-sm);cursor:pointer';
	laterBtn.addEventListener('click', () => banner.remove());
	banner.appendChild(laterBtn);

	const installBtn = document.createElement('button');
	installBtn.textContent = 'Jetzt neustarten';
	installBtn.style.cssText = 'padding:6px 12px;font-size:11px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-weight:600';
	installBtn.addEventListener('click', () => update.install());
	banner.appendChild(installBtn);

	document.body.appendChild(banner);
}

update.onReady((info) => showUpdateBanner(info));
update.check().then((info) => { if (info) showUpdateBanner(info); });

// ── Peer Expiry Warning ──────────────────────────────────
peer.onExpiry((info) => {
	const existing = $('#expiry-banner');
	if (existing) existing.remove();

	const banner = document.createElement('div');
	banner.id = 'expiry-banner';

	let msg, color;
	if (info.daysLeft <= 0) {
		msg = 'Dein VPN-Zugang ist abgelaufen!';
		color = 'var(--error)';
	} else if (info.daysLeft <= 1) {
		msg = 'Dein VPN-Zugang läuft heute ab!';
		color = 'var(--error)';
	} else {
		msg = `Dein VPN-Zugang läuft in ${info.daysLeft} Tagen ab`;
		color = info.daysLeft <= 3 ? 'var(--warn)' : 'var(--text-2)';
	}

	banner.style.cssText = `padding:8px 12px;margin-top:8px;border-radius:var(--radius-sm);font-size:11px;text-align:center;border:1px solid ${color};color:${color};background:rgba(0,0,0,0.2)`;
	banner.textContent = msg;

	const statsGrid = $('#stats-grid');
	if (statsGrid) statsGrid.parentNode.insertBefore(banner, statsGrid.nextSibling);
});
