/**
 * GateControl -- Update notice state (renderer, no DOM access)
 *
 * Decides how the sidebar update card, the "Update erforderlich" banner and
 * the channel display look. Loaded as a plain script before renderer.js
 * (window.GCUpdateState) and required by the node tests.
 *
 * mandatory comes from the core updater (getUpdatePolicy / onReady): it is
 * only true while a verified, strictly newer update is ready. A mandatory
 * notice cannot be dismissed; installing still goes through update.install()
 * (the updater re-hashes the installer right before starting it).
 */
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api;
	else root.GCUpdateState = api;
})(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	/**
	 * @param {object|null} pendingUpdate - { version, mandatory?, minVersion? }
	 * @param {object|null} policy - updater.getUpdatePolicy() (newest wins)
	 * @param {boolean} hiddenByUser - "Später" was clicked
	 */
	function updateCardState(pendingUpdate, policy, hiddenByUser) {
		if (!pendingUpdate || !pendingUpdate.version) {
			return { visible: false, mandatory: false, dismissable: false, version: null, minVersion: null };
		}
		const mandatory = policy ? policy.mandatory === true : pendingUpdate.mandatory === true;
		const minVersion = (policy && policy.minVersion) || pendingUpdate.minVersion || null;
		return {
			visible: mandatory || !hiddenByUser,
			mandatory,
			dismissable: !mandatory,
			version: pendingUpdate.version,
			minVersion,
		};
	}

	/** i18n key for the channel chip in Settings → About. */
	function channelLabelKey(channel) {
		if (channel === 'beta') return 'update.channelBeta';
		if (channel === 'stable') return 'update.channelStable';
		return 'update.channelUnknown';
	}

	return { updateCardState, channelLabelKey };
});
