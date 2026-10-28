/**
 * GateControl -- Drive: vault folders (renderer view)
 *
 * Drive 1.9 'vault' on the page "Drive" (only while `me` reports the feature
 * and this PC keeps keys under DPAPI): "Neuer Tresor-Ordner" (the recovery key
 * shown once, to be written down), the card of a vault this PC cannot open
 * yet ("Zugriff anfragen" — then this PC's safety number to compare on the
 * approving device — or "Mit Wiederherstellungsschlüssel öffnen"), "Geräte"
 * (requests of other devices with their safety numbers: approve only after
 * comparing, decline) and "Neuen Schlüssel erzeugen" when Drive asks for one.
 * Keys and crypto stay in the main process (core services/drive-vault.js).
 *
 * Data: window.gatecontrol.drive.vault; logic: drive-vault-state.js
 * (window.GCDriveVaultState); texts: drive.vault.*. Server text only via
 * textContent.
 */
(function (root) {
	'use strict';

	const VS = root.GCDriveVaultState;
	const DS = root.GCDriveState;

	/**
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive
	 * @param {Function} o.t
	 * @param {object} o.ui - { el, icon, clear, openDialog }
	 * @param {HTMLElement} o.host
	 * @param {Function} o.toast
	 * @param {Function} o.errorText
	 * @param {() => void} o.changed - the page reloads what it shows
	 */
	function create(o) {
		const { el, icon, openDialog } = o.ui;
		const t = o.t;
		const vapi = o.api.vault;
		const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed' });
		let nid = 0;
		const nextId = (p) => `${p}-v${++nid}`;

		/** The recovery key, shown once: copy, "Ich habe ihn notiert" before the dialog closes. */
		function showRecoveryKey(dlg, text, { intro }) {
			while (dlg.body.firstChild) dlg.body.removeChild(dlg.body.firstChild);
			while (dlg.foot.firstChild) dlg.foot.removeChild(dlg.foot.firstChild);
			const id = nextId('dv-rk-ok');
			const check = el('input', { id, type: 'checkbox' });
			const done = el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.close'), disabled: true });
			check.addEventListener('change', () => { done.disabled = !check.checked; });
			done.addEventListener('click', () => dlg.close(true));
			dlg.body.append(
				el('p', { class: 'dv-p', text: intro }),
				el('div', { class: 'dv-rk', 'aria-label': t('drive.vault.recovery.label') }, VS.recoveryKeyLines(text).map((l) => el('code', { text: l }))),
				el('div', { class: 'dv-note is-warn', text: t('drive.vault.recovery.warn') }),
				el('label', { class: 'dv-check', for: id }, [check, el('span', { text: t('drive.vault.recovery.kept') })]),
			);
			const copy = el('button', { type: 'button', class: 'btn btn-sec' }, [icon('copy', 14), el('span', { text: t('drive.share.copy') })]);
			copy.addEventListener('click', () => {
				if (root.navigator && navigator.clipboard) navigator.clipboard.writeText(text).then(() => o.toast(t('drive.share.copied'), 'success')).catch(() => o.toast(t('drive.err.copy'), 'error'));
			});
			dlg.foot.append(el('span', { class: 'dv-grow' }), copy, done);
			setTimeout(() => check.focus(), 0);
		}

		/** "Neuer Tresor-Ordner" in folder `parentId`. */
		function createDialog(parentId) {
			const dlg = openDialog({ title: t('drive.vault.create.title'), host: o.host, closeLabel: t('drive.close') });
			dlg.box.classList.add('dv-vault-dlg');
			const id = nextId('dv-vname');
			const input = el('input', { id, type: 'text', class: 'dv-input', maxlength: '255', spellcheck: 'false' });
			const errEl = el('span', { class: 'dv-field-err', role: 'alert' });
			const ok = el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.vault.create.ok'), disabled: true });
			const check = () => { const e = DS.nameError(input.value, t); errEl.textContent = input.value ? (e || '') : ''; ok.disabled = !!e; return !e; };
			const submit = async () => {
				if (!check()) return;
				ok.disabled = true;
				const r = await Promise.resolve(vapi.create(parentId, input.value.trim())).catch(fail);
				if (!r || !r.ok) { ok.disabled = false; errEl.textContent = o.errorText(r, t); return; }
				o.changed();
				dlg.setTitle(t('drive.vault.recovery.title'));
				showRecoveryKey(dlg, r.recoveryKey, { intro: t('drive.vault.recovery.intro', { name: r.node.name }) });
			};
			input.addEventListener('input', check);
			input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
			ok.addEventListener('click', submit);
			dlg.body.append(
				el('p', { class: 'dv-p', text: t('drive.vault.create.intro') }),
				el('label', { class: 'lbl', for: id, text: t('drive.name.label') }), input, errEl,
			);
			dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), ok);
			setTimeout(() => input.focus(), 0);
			return dlg;
		}

		/** "Mit Wiederherstellungsschlüssel öffnen" → resolves true when opened. */
		function recoverDialog(vaultId) {
			return new Promise((resolve) => {
				const dlg = openDialog({ title: t('drive.vault.recover.title'), host: o.host, closeLabel: t('drive.close'), onClose: (v) => resolve(v === true) });
				const id = nextId('dv-rk-in');
				const input = el('textarea', { id, class: 'dv-input dv-rk-in', rows: '3', spellcheck: 'false', autocomplete: 'off', placeholder: 'XXXX-XXXX-…' });
				const errEl = el('span', { class: 'dv-field-err', role: 'alert' });
				const ok = el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.vault.recover.ok'), disabled: true });
				input.addEventListener('input', () => { ok.disabled = !VS.recoveryKeyShape(input.value); errEl.textContent = ''; });
				ok.addEventListener('click', async () => {
					ok.disabled = true;
					const r = await Promise.resolve(vapi.recover(vaultId, input.value)).catch(fail);
					if (r && r.ok) { o.toast(t('drive.vault.opened'), 'success'); dlg.close(true); o.changed(); return; }
					ok.disabled = false;
					errEl.textContent = o.errorText(r, t);
				});
				dlg.body.append(el('p', { class: 'dv-p', text: t('drive.vault.recover.intro') }), el('label', { class: 'lbl', for: id, text: t('drive.vault.recovery.label') }), input, errEl);
				dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), ok);
				setTimeout(() => input.focus(), 0);
			});
		}

		/**
		 * The card of a vault this PC cannot open (state 'none' | 'pending' | 'revoked' | 'unsupported') → an element with
		 * "Zugriff anfragen" / "Mit Wiederherstellungsschlüssel öffnen"; after a request this PC's safety number.
		 */
		function gate(vaultId, state, { safetyNumber = null } = {}) {
			const box = el('div', { class: 'dv-vgate', role: 'status' });
			const draw = (st, sn) => {
				while (box.firstChild) box.removeChild(box.firstChild);
				const v = VS.gateView(st, { t, safetyNumber: sn });
				box.append(
					el('span', { class: 'dv-vgate-ic' }, [icon('vault', 22)]),
					el('div', { class: 'dv-vgate-tx' }, [
						el('b', { text: t('drive.vault.gate.title') }),
						el('p', { class: 'dv-p', text: v.text }),
						v.safetyNumber ? el('div', { class: 'dv-safety' }, [el('span', { class: 'lbl', text: t('drive.vault.safety.mine') }), el('code', { class: 'dv-safety-n', text: v.safetyNumber })]) : null,
					]),
				);
				const acts = el('div', { class: 'dv-vgate-acts' });
				if (v.ask) {
					const ask = el('button', { type: 'button', class: 'btn btn-pri btn-sm dv-vault-ask', text: t('drive.vault.gate.ask') });
					ask.addEventListener('click', async () => {
						ask.disabled = true;
						const r = await Promise.resolve(vapi.request(vaultId)).catch(fail);
						if (!r || !r.ok) { ask.disabled = false; o.toast(o.errorText(r, t), 'error'); return; }
						if (r.state === 'open') { o.changed(); return; }
						draw(r.state, r.safetyNumber);
					});
					acts.appendChild(ask);
				}
				if (st === 'pending') {
					const again = el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.vault.gate.check') });
					again.addEventListener('click', async () => {
						again.disabled = true;
						const r = await Promise.resolve(vapi.open(vaultId)).catch(fail);
						again.disabled = false;
						if (r && r.ok && r.state === 'open') { o.toast(t('drive.vault.opened'), 'success'); o.changed(); return; }
						o.toast(r && r.ok ? t('drive.vault.gate.stillPending') : o.errorText(r, t), 'info');
					});
					acts.appendChild(again);
				}
				if (v.recover) acts.appendChild(el('button', { type: 'button', class: 'btn btn-ghost btn-sm dv-vault-recover', text: t('drive.vault.gate.recover'), on: { click: () => recoverDialog(vaultId) } }));
				box.appendChild(acts);
			};
			draw(state, safetyNumber);
			return box;
		}

		/** "Geräte": requests (approve after comparing the safety number, decline) and the approved devices. */
		function devicesDialog(vaultId, { onRotate = null } = {}) {
			const dlg = openDialog({ title: t('drive.vault.devices.title'), host: o.host, wide: true, closeLabel: t('drive.close') });
			dlg.box.classList.add('dv-vault-dlg');
			const box = el('div', { class: 'dv-vdev' });
			dlg.body.appendChild(box);
			dlg.foot.append(el('span', { class: 'dv-grow' }), el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.close'), on: { click: () => dlg.close(null) } }));
			const row = (d, kids) => el('div', { class: 'dv-vdev-row', 'data-device': d.deviceId }, [
				el('span', { class: 'dv-row-ic' }, [icon('device', 16)]),
				el('div', { class: 'dv-link-tx' }, [
					el('span', { class: 'dv-link-name', text: d.mine ? t('drive.vault.device.this', { name: d.name }) : d.name }),
					el('span', { class: 'dv-row-sub', text: [d.platform, d.via].filter(Boolean).join(' · ') }),
					...(kids || []),
				]),
			]);
			async function load() {
				while (box.firstChild) box.removeChild(box.firstChild);
				box.appendChild(el('div', { class: 'dv-pick-note', text: t('drive.loading') }));
				const r = await Promise.resolve(vapi.devices(vaultId)).catch(fail);
				while (box.firstChild) box.removeChild(box.firstChild);
				if (!r || !r.ok) { box.appendChild(el('div', { class: 'dv-dlg-err', text: o.errorText(r, t) })); return; }
				const rows = VS.deviceRows(r.devices, { t });
				if (r.vault && r.vault.needsRotation && onRotate) {
					const rot = el('button', { type: 'button', class: 'btn btn-sec btn-sm', text: t('drive.vault.rotate.button') });
					rot.addEventListener('click', () => { dlg.close(null); onRotate(); });
					box.appendChild(el('div', { class: 'dv-note is-warn' }, [el('span', { text: t('drive.vault.rotate.why') }), ' ', rot]));
				}
				box.appendChild(el('span', { class: 'lbl', text: t('drive.vault.devices.pending') }));
				if (!rows.pending.length) box.appendChild(el('p', { class: 'dv-p', text: t('drive.vault.devices.noPending') }));
				for (const d of rows.pending) {
					const id = nextId('dv-sn');
					const cmp = el('input', { id, type: 'checkbox' });
					const ok = el('button', { type: 'button', class: 'btn btn-pri btn-sm dv-vault-approve', text: t('drive.vault.devices.approve'), disabled: true });
					const no = el('button', { type: 'button', class: 'btn btn-ghost btn-sm dv-danger', text: t('drive.vault.devices.decline') });
					cmp.addEventListener('change', () => { ok.disabled = !cmp.checked; });
					ok.addEventListener('click', async () => {
						ok.disabled = true;
						const x = await Promise.resolve(vapi.approve(vaultId, d.deviceId, d.safetyNumber)).catch(fail);
						if (x && x.ok) { o.toast(t('drive.vault.devices.approved'), 'success'); load(); return; }
						ok.disabled = false;
						o.toast(o.errorText(x, t), 'error');
					});
					no.addEventListener('click', async () => {
						no.disabled = true;
						const x = await Promise.resolve(vapi.decline(vaultId, d.deviceId)).catch(fail);
						if (x && x.ok) { o.toast(t('drive.vault.devices.declined'), 'success'); load(); return; }
						no.disabled = false;
						o.toast(o.errorText(x, t), 'error');
					});
					box.appendChild(row(d, [
						el('div', { class: 'dv-safety' }, [el('span', { class: 'lbl', text: t('drive.vault.safety.other') }), el('code', { class: 'dv-safety-n', text: d.safetyNumber })]),
						el('label', { class: 'dv-check', for: id }, [cmp, el('span', { text: t('drive.vault.safety.same') })]),
						el('div', { class: 'dv-vdev-acts' }, [ok, no]),
					]));
				}
				box.appendChild(el('span', { class: 'lbl', text: t('drive.vault.devices.approvedH') }));
				for (const d of rows.approved) box.appendChild(row(d));
			}
			load();
			return dlg;
		}

		/** "Neuen Schlüssel erzeugen" (someone lost the area): a new recovery key is shown when Drive asked for one. */
		function rotateDialog(vaultId) {
			const dlg = openDialog({ title: t('drive.vault.rotate.title'), host: o.host, closeLabel: t('drive.close') });
			const errEl = el('span', { class: 'dv-dlg-err', role: 'alert' });
			const ok = el('button', { type: 'button', class: 'btn btn-pri', text: t('drive.vault.rotate.ok') });
			ok.addEventListener('click', async () => {
				ok.disabled = true;
				const r = await Promise.resolve(vapi.rotate(vaultId)).catch(fail);
				if (!r || !r.ok) { ok.disabled = false; errEl.textContent = o.errorText(r, t); return; }
				o.toast(t('drive.vault.rotate.done'), 'success');
				o.changed();
				if (r.recoveryKey) { dlg.setTitle(t('drive.vault.recovery.title')); showRecoveryKey(dlg, r.recoveryKey, { intro: t('drive.vault.recovery.newIntro') }); } else dlg.close(true);
			});
			dlg.body.appendChild(el('p', { class: 'dv-p', text: t('drive.vault.rotate.intro') }));
			dlg.foot.append(errEl, el('button', { type: 'button', class: 'btn btn-sec', text: t('drive.cancel'), on: { click: () => dlg.close(null) } }), ok);
			return dlg;
		}

		return { createDialog, recoverDialog, gate, devicesDialog, rotateDialog };
	}

	root.GCDriveVaultView = { create };
})(typeof self !== 'undefined' ? self : this);
