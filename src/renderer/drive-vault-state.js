/**
 * GateControl -- Drive: vault folders (renderer, no DOM access)
 *
 * Drive 1.9 'vault': folders end-to-end encrypted on the devices. The keys and
 * the crypto stay in the main process (core services/drive-vault.js); the page
 * shows the state of this PC for a vault ("Zugriff anfragen", waiting for an
 * approval with this PC's safety number, open), the requests of other devices
 * with their safety numbers, the recovery key (once, after making a vault or
 * a new key) and the field to type it. Pure helpers for drive-vault-view.js,
 * loaded as a plain script (window.GCDriveVaultState) and required by the
 * node tests (test/drive-18-state.test.js).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCDriveVaultState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	const CROCKFORD = /^[0-9A-HJKMNP-TV-Z]{56}$/;
	const str = (v) => (v === null || v === undefined ? '' : String(v));

	/** May this page offer vaults? (the Drive reports 'vault' and this PC keeps keys with DPAPI) */
	function vaultAvailable(me, status) {
		return !!(me && Array.isArray(me.features) && me.features.includes('vault') && status && status.ok && status.supported);
	}

	/**
	 * The card of a vault this PC cannot open yet → { key, text, ask, recover, safetyNumber } — state 'none' (never
	 * asked, or declined): "Zugriff anfragen"; 'pending': waiting (the safety number to compare); 'revoked' like 'none';
	 * 'unsupported': this PC keeps no keys.
	 */
	function gateView(state, { t, safetyNumber = null } = {}) {
		if (state === 'unsupported') return { key: 'unsupported', text: t('drive.vault.gate.unsupported'), ask: false, recover: false, safetyNumber: null };
		if (state === 'pending') {
			return { key: 'pending', text: t('drive.vault.gate.pending'), ask: false, recover: true, safetyNumber: safetyNumber || null };
		}
		return { key: 'none', text: t(state === 'revoked' ? 'drive.vault.gate.revoked' : 'drive.vault.gate.none'), ask: true, recover: true, safetyNumber: null };
	}

	/**
	 * The devices of a vault → { pending: [row], approved: [row] } — row: { deviceId, name, platform, safetyNumber,
	 * mine, via, when }. Revoked ones are left out.
	 */
	function deviceRows(devices, { t } = {}) {
		const rows = (Array.isArray(devices) ? devices : []).filter((d) => d && d.state !== 'revoked').map((d) => ({
			deviceId: d.deviceId,
			state: d.state,
			name: str(d.name) || t('drive.vault.device.unnamed'),
			platform: d.platform === 'windows' ? 'Windows' : d.platform === 'android' ? 'Android' : d.platform === 'ios' ? 'iOS' : d.platform ? str(d.platform) : t('drive.vault.device.portal'),
			safetyNumber: str(d.safetyNumber),
			mine: !!d.mine,
			via: d.via === 'recovery' ? t('drive.vault.device.viaRecovery') : '',
		}));
		return { pending: rows.filter((r) => r.state === 'pending'), approved: rows.filter((r) => r.state === 'approved') };
	}

	/** Normalised form of a typed recovery key (upper case, no spaces / dashes, O → 0, I/L → 1). */
	function recoveryKeyClean(text) {
		return str(text).toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
	}

	/** Does the typed text have the shape of a recovery key (56 Crockford characters)? The check bytes are the core's. */
	function recoveryKeyShape(text) {
		return CROCKFORD.test(recoveryKeyClean(text));
	}

	/** "R30W-5GY4-…" in lines of 4 groups for showing it */
	function recoveryKeyLines(text) {
		const groups = str(text).split('-').filter(Boolean);
		const out = [];
		for (let i = 0; i < groups.length; i += 4) out.push(groups.slice(i, i + 4).join('-'));
		return out;
	}

	/** Does the typed safety number equal the shown one (spaces ignored)? */
	function safetyMatches(typed, shown) {
		const a = str(typed).replace(/\D/g, '');
		const b = str(shown).replace(/\D/g, '');
		return a.length === 20 && a === b;
	}

	/** The bar note in a vault folder: "Ende-zu-Ende verschlüsselt" (+ requests waiting / a new key needed) */
	function folderNote(vault, { t } = {}) {
		const v = vault || {};
		const parts = [t('drive.vault.note')];
		if (v.pending) parts.push(t(v.pending === 1 ? 'drive.vault.pending.one' : 'drive.vault.pending.other', { count: v.pending }));
		if (v.needsRotation) parts.push(t('drive.vault.needsRotation'));
		return parts.join(' · ');
	}

	return { vaultAvailable, gateView, deviceRows, recoveryKeyClean, recoveryKeyShape, recoveryKeyLines, safetyMatches, folderNote };
});
