/**
 * GateControl -- Medien › Quellen (renderer view, Stufe 4f; Medien-Plugin W2: display only)
 *
 * The sources come from the GateControl server (plugin "Medien", core media-server-sources.js): the admin sets them up
 * once, this PC gets the list and its access by itself. This page only shows them — no "Quelle hinzufügen", no
 * dialog, no "Gerät anmelden", no "Abmelden" per source:
 *   - the note "Quellen richtet der Admin im Server ein" with the age of the list ("vom Server, vor 3 Min."), the notes of
 *     the server (Medien off / no licence, long without the server, the sources of this PC taken over once);
 *   - each source with its state: signed in as … (this PC's name in Jellyfin), the way now (Zuhause · unterwegs über VPN
 *     · unterwegs direkt · nur über VPN), the admin's matter in plain words (no Jellyfin user linked, Quick Connect off),
 *     a share's "SMB zu Hause, WebDAV unterwegs", "SMB geprüft", WebDAV because of Windows' error 1219;
 *   - the settings of this PC: "Immer Original" and "Weiterschauen auf der Übersicht".
 *
 * Built by media-view.js (window.GCMediaSources.mount); data: window.gatecontrol.media; pure logic in media-state.js.
 * Server text only into textContent.
 */
(function (root) {
	'use strict';

	const MS = root.GCMediaState;
	const DISMISS_KEY = 'gc.media.noticeSeen';

	function mount(o) {
		const api = o.api;
		const t = o.t;
		const el = o.el;
		const icon = o.icon;
		const toast = typeof o.toast === 'function' ? o.toast : () => {};
		const fail = (err) => ({ ok: false, code: (err && err.code) || 'failed', error: err && err.message });
		const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };
		const storage = o.storage || null;

		const S = { shown: false };

		const rootEl = el('div', { class: 'md md-sources' });
		o.root.appendChild(rootEl);

		function status() { return o.getStatus ? o.getStatus() : null; }

		function seen(key) {
			try { return !!storage && storage.getItem(DISMISS_KEY) === key; } catch { return false; }
		}

		function dismiss(key) {
			try { if (storage) storage.setItem(DISMISS_KEY, key); } catch { /* storage unavailable */ }
			render();
		}

		// ── The page ─────────────────────────────────────────

		function render() {
			clear(rootEl);
			const st = status();
			const server = st && st.server;
			const { all, jellyfin } = MS.sourcesOf(st);
			rootEl.appendChild(el('div', { class: 'md-head' }, [
				el('button', { type: 'button', class: 'btn btn-ghost btn-sm btn-icon md-back', title: t('media.sources.back'), 'aria-label': t('media.sources.back'), on: { click: () => o.onBack() } }, [icon('left', 18)]),
				el('h1', { class: 'md-h', text: t('media.sources.title') }),
				el('span', { class: 'md-grow' }),
			]));
			const body = el('div', { class: 'md-srcbody scroll' });
			rootEl.appendChild(body);
			if (st && st.supported === false) body.appendChild(el('div', { class: 'note note-warn', text: t('media.unsupported.text') }));

			// "Quellen richtet der Admin im Server ein" · vom Server, vor 3 Min.
			const age = MS.fetchedLabel(server, t);
			body.appendChild(el('div', { class: 'note note-neutral md-managed' }, [
				el('span', { text: t('media.sources.managed') }),
				age ? el('small', { class: 'md-fetched', text: ` · ${age}` }) : null,
			]));
			for (const n of MS.serverNotes(server, t)) {
				if (n.key && seen(n.key)) continue;
				body.appendChild(el('div', { class: `note ${n.cls} md-server-note`, role: 'status' }, [
					el('span', { class: 'md-grow', text: n.text }),
					n.key ? el('button', { type: 'button', class: 'btn btn-ghost btn-xs md-note-ok', text: t('media.server.ok'), on: { click: () => dismiss(n.key) } }) : null,
				]));
			}

			const listEl = el('div', { class: 'md-srclist' });
			if (!all.length) listEl.appendChild(el('div', { class: 'md-card md-card-empty' }, [el('div', { class: 'md-card-tx' }, [el('b', { text: t('media.sources.none') }), el('small', { text: t('media.empty.managed') })])]));
			for (const s of all) listEl.appendChild(sourceCard(s, st));
			body.appendChild(listEl);

			// "Immer Original" (all Jellyfin sources) — a setting of this PC
			if (jellyfin.length) {
				const on = MS.alwaysOriginal(st);
				body.appendChild(switchCard(t('media.original.title'), t('media.original.text'), on, 'md-sw-original', async () => {
					for (const s of jellyfin) {
						let r;
						try { r = await api.setAlwaysOriginal(s.id, !on); } catch (err) { r = fail(err); }
						if (!r || !r.ok) { toast(MS.errorText(r && r.code, t), 'error'); break; }
					}
					await o.reloadStatus();
				}));
			}
			// "Weiterschauen" on the app's overview (this PC)
			const homeOn = (() => { try { return MS.homeCardOn(storage ? storage.getItem(MS.HOME_CARD_KEY) : null); } catch { return true; } })();
			body.appendChild(switchCard(t('media.homeCard.title'), t('media.homeCard.text'), homeOn, 'md-sw-home', () => {
				try { if (storage) storage.setItem(MS.HOME_CARD_KEY, homeOn ? 'off' : 'on'); } catch { /* storage unavailable */ }
				if (o.onHomeCard) o.onHomeCard();
				render();
			}));
		}

		function switchCard(title, text, on, cls, onToggle) {
			const sw = el('button', { type: 'button', class: `sw${on ? ' on' : ''}`, role: 'switch', 'aria-checked': on ? 'true' : 'false', 'aria-label': title, on: { click: () => onToggle() } }, [el('span')]);
			return el('div', { class: `md-card ${cls}` }, [el('div', { class: 'md-card-tx' }, [el('b', { text: title }), el('small', { text })]), sw]);
		}

		function sourceCard(s, st) {
			const jelly = s.kind === 'jellyfin';
			const pill = MS.sourcePill(s, t);
			const rule = MS.awayRule(s, t);
			return el('div', { class: 'md-card md-srccard', 'data-id': s.id, 'data-kind': s.kind }, [
				el('span', { class: `md-card-ic${jelly ? '' : ' is-info'}` }, [icon(jelly ? 'film' : 'folder', 18, '1.9')]),
				el('div', { class: 'md-card-tx' }, [
					el('b', { text: MS.sourceChip(s, t) }),
					el('small', { text: MS.sourceSub(s, t, jelly ? st && st.deviceName : null) }),
					rule ? el('small', { class: 'md-rule', text: rule }) : null,
				]),
				el('span', { class: `md-pill md-src-state ${pill.cls}`, text: pill.text }),
			]);
		}

		return {
			show() { S.shown = true; render(); },
			hide() { S.shown = false; },
			render() { if (S.shown) render(); },
		};
	}

	root.GCMediaSources = { mount };
})(typeof window !== 'undefined' ? window : globalThis);
