/**
 * GateControl -- Drive: the viewer of vault files (renderer view, Drive plugin 1.22)
 *
 * A file of a vault folder opens here instead of in another program: pictures, PDFs, texts and Markdown, videos and
 * sound. The main process (core services/drive-vault-view.js) keeps only the ciphertext on the disk and serves the
 * plaintext through gcvault://v/<token>, decrypted chunk by chunk in memory:
 *   * pictures, videos, sound: <img> / <video> / <audio> on that URL — no file, no blob;
 *   * PDF: fetch() of the URL into memory, pdf.js (vendor/pdfjs, Apache-2.0, a module worker of this app — no CDN)
 *     draws the pages on <canvas>; no scripts or forms of the PDF, no network;
 *   * text and Markdown: fetch() as text, shown as text nodes (Markdown: headings, lists, code — never HTML).
 * While it shows, the window has content protection (no screenshot, no recording, no thumbnail). Closing, the vault
 * lock (drive:vault-lock, also when the window is hidden or Windows locks) and leaving the page close it: the token is
 * revoked (the main process forgets the file key and deletes the ciphertext), canvases are emptied, buffers zeroed,
 * the media elements emptied. Office files and the like get a note; "Mit anderem Programm öffnen" and "Speichern unter
 * …" stay the explicit way out — the first asks before (the copy is not encrypted).
 *
 * Data: window.gatecontrol.drive.vault.view / viewClose / protect / touch / onLock; texts: drive.vv.*.
 *
 * createDoc(): the same viewer for the PDFs, texts and Markdown of the normal files of Drive (not of a vault) — the
 * same pages (pdf.js on <canvas>, text nodes), but the content is the file as "Öffnen" loads it anyway (core
 * DriveService.docView: the copy in the temp folder, else a download; window.gatecontrol.drive.docView → a PDF's bytes,
 * a text decoded). No content protection, no lock, a text can be selected and copied; "Mit anderem Programm öffnen"
 * (no question: nothing of a vault) and "Speichern unter …" stay in the viewer. Too large ones say so, nothing loaded.
 */
(function (root) {
	'use strict';

	const MB = 1048576;
	const PDF_LIB = 'vendor/pdfjs/pdf.min.mjs';
	const PDF_WORKER = 'vendor/pdfjs/pdf.worker.min.mjs';
	let pdfjs = null; // a promise of the pdf.js module (loaded the first time a PDF opens)

	function loadPdfjs() {
		if (!pdfjs) {
			pdfjs = import(`./${PDF_LIB}`).then((lib) => {
				lib.GlobalWorkerOptions.workerSrc = new URL(PDF_WORKER, document.baseURI).href;
				return lib;
			});
			pdfjs.catch(() => { pdfjs = null; });
		}
		return pdfjs;
	}

	// ── Markdown as DOM (text nodes only) ────────────────────

	function inline(el, text) {
		const out = [];
		const re = /(`[^`]+`|\*\*[^*]+\*\*|__[^_]+__|\*[^*\s][^*]*\*|_[^_\s][^_]*_)/g;
		let last = 0;
		let m;
		while ((m = re.exec(text))) {
			if (m.index > last) out.push(document.createTextNode(text.slice(last, m.index)));
			const s = m[0];
			if (s[0] === '`') out.push(el('code', { text: s.slice(1, -1) }));
			else if (s.startsWith('**') || s.startsWith('__')) out.push(el('strong', { text: s.slice(2, -2) }));
			else out.push(el('em', { text: s.slice(1, -1) }));
			last = m.index + s.length;
		}
		if (last < text.length) out.push(document.createTextNode(text.slice(last)));
		return out;
	}

	/** Markdown → elements: headings, lists, quotes, code blocks, rules, paragraphs; links stay text. */
	function markdown(el, src) {
		const lines = String(src).replace(/\r\n?/g, '\n').split('\n');
		const out = [];
		let para = [];
		const flush = () => { if (para.length) { out.push(el('p', {}, inline(el, para.join(' ')))); para = []; } };
		for (let i = 0; i < lines.length;) {
			const l = lines[i];
			const fence = /^\s*(```|~~~)/.exec(l);
			if (fence) {
				flush();
				const code = [];
				i++;
				while (i < lines.length && !lines[i].trim().startsWith(fence[1])) { code.push(lines[i]); i++; }
				i++;
				out.push(el('pre', { class: 'dv-vv-code', text: code.join('\n') }));
				continue;
			}
			const hd = /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(l);
			if (hd) { flush(); out.push(el(`h${Math.min(6, hd[1].length + 1)}`, {}, inline(el, hd[2]))); i++; continue; }
			if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(l)) { flush(); out.push(el('hr')); i++; continue; }
			const li = /^\s*([-*+]|\d{1,9}[.)])\s+(.*)$/.exec(l);
			if (li) {
				flush();
				const ordered = /\d/.test(li[1]);
				const list = el(ordered ? 'ol' : 'ul');
				while (i < lines.length) {
					const x = /^\s*([-*+]|\d{1,9}[.)])\s+(.*)$/.exec(lines[i]);
					if (!x || /\d/.test(x[1]) !== ordered) break;
					list.appendChild(el('li', {}, inline(el, x[2].replace(/^\[( |x|X)\]\s+/, (_, c) => (c === ' ' ? '☐ ' : '☑ ')))));
					i++;
				}
				out.push(list);
				continue;
			}
			if (/^\s*>/.test(l)) {
				flush();
				const q = [];
				while (i < lines.length && /^\s*>/.test(lines[i])) { q.push(lines[i].replace(/^\s*>\s?/, '')); i++; }
				out.push(el('blockquote', {}, inline(el, q.join(' '))));
				continue;
			}
			if (!l.trim()) { flush(); i++; continue; }
			para.push(l.trim());
			i++;
		}
		flush();
		return out;
	}

	/**
	 * The vault's viewer.
	 * @param {object} o
	 * @param {object} o.api - window.gatecontrol.drive
	 * @param {Function} o.t
	 * @param {object} o.ui - { el, icon, openDialog }
	 * @param {HTMLElement} o.host
	 * @param {Function} o.toast
	 * @param {Function} o.errorText
	 * @param {(n) => void} o.openWith - "Mit anderem Programm öffnen" (asked here first)
	 * @param {(n) => void} [o.saveAs] - "Speichern unter …"
	 * @param {(title, text, confirm, run) => void} o.confirm - a question before the way out
	 */
	function create(o) {
		return make(o, true);
	}

	/**
	 * The viewer of PDFs, texts and Markdown of normal Drive files (window.gatecontrol.drive.docView).
	 * @param {object} o - as create(), without `confirm`: o.openWith opens at once (nothing of a vault)
	 */
	function createDoc(o) {
		return make(o, false);
	}

	function make(o, vault) {
		const { api, t, host } = o;
		const { el, icon, openDialog } = o.ui;
		const vapi = vault ? api.vault : null;
		let cur = null;

		const touch = () => { if (!vapi) return; try { vapi.touch(); } catch { /* gone */ } };

		/** Closes the viewer: the token revoked, what it showed dropped. */
		function close() {
			const s = cur;
			if (!s) return false;
			cur = null;
			s.closed = true;
			for (const fn of s.cleanups.splice(0).reverse()) { try { fn(); } catch { /* best effort */ } }
			if (vapi) {
				if (s.token) Promise.resolve(vapi.viewClose(s.token)).catch(() => {});
				Promise.resolve(vapi.protect(false)).catch(() => {});
			}
			if (s.dlg && !s.dlg.closed) s.dlg.close();
			return true;
		}

		// the vaults locked (time without use, window hidden, Windows locked, by hand): the viewer closes
		if (vapi && typeof vapi.onLock === 'function') vapi.onLock((e) => { if (e && e.locked) close(); });
		root.addEventListener('beforeunload', () => close());

		function note(text, warn) {
			return el('div', { class: `dv-vv-note${warn ? ' is-warn' : ''}` }, [icon(warn ? 'alert' : 'lock', 18), el('p', { text })]);
		}

		function wayOut(s) {
			const acts = [];
			acts.push(el('button', { type: 'button', class: 'btn btn-ghost btn-sm dv-vv-openwith', text: t('drive.vv.openWith'), on: { click: () => {
				if (!vault) { close(); o.openWith(s.n); return; }
				o.confirm(t('drive.vv.openWithTitle'), t('drive.vv.openWithText'), t('drive.vv.openWithGo'), () => { close(); o.openWith(s.n); });
			} } }));
			if (o.saveAs) acts.push(el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('drive.saveAs'), on: { click: () => { close(); o.saveAs(s.n); } } }));
			return acts;
		}

		/** What the page shows of `n`: the vault's gcvault: address (decrypted in memory), else the file's bytes / text. */
		async function load(n, versionId) {
			if (vault) return vapi.view(n.id, versionId || null);
			return api.docView(n.id);
		}

		/** Opens file `n` (of a vault: a version `versionId`). */
		async function open(n, versionId) {
			close();
			const s = { n, closed: false, token: null, cleanups: [] };
			cur = s;
			const dlg = openDialog({ title: n.name, host, wide: true, closeLabel: t('drive.close'), onClose: () => { if (cur === s) close(); } });
			s.dlg = dlg;
			dlg.box.classList.add('dv-vv');
			dlg.box.setAttribute(vault ? 'data-vault-viewer' : 'data-doc-viewer', '1');
			const tools = el('div', { class: 'dv-vv-tools' }, vault ? [
				el('span', { class: 'dv-vv-mem', text: t('drive.vv.inMemory') }),
				el('span', { class: 'dv-grow' }),
				el('button', { type: 'button', class: 'dv-ib dv-vv-lock', title: t('drive.vv.lock'), 'aria-label': t('drive.vv.lock'), on: { click: () => { close(); Promise.resolve(vapi.lock()).catch(() => {}); } } }, [icon('lock', 16)]),
			] : [el('span', { class: 'dv-grow' })]);
			const stage = el('div', { class: 'dv-vv-stage', 'aria-live': 'polite' }, [el('div', { class: 'dv-vv-wait' }, [el('span', { class: 'dv-vv-spin' }), el('span', { text: t(vault ? 'drive.vv.decrypting' : 'drive.vv.loading') })])]);
			dlg.body.append(tools, stage);
			if (vault) {
				for (const ev of ['pointerdown', 'keydown', 'wheel', 'scroll']) dlg.box.addEventListener(ev, touch, { capture: true, passive: true });
				dlg.box.addEventListener('contextmenu', (e) => e.preventDefault());
				dlg.box.addEventListener('dragstart', (e) => e.preventDefault());
				Promise.resolve(vapi.protect(true)).catch(() => {});
			}
			let r;
			try {
				r = await load(n, versionId);
			} catch (err) {
				r = { ok: false, code: (err && err.code) || 'failed' };
			}
			if (s.closed) { if (vapi && r && r.token) Promise.resolve(vapi.viewClose(r.token)).catch(() => {}); return; }
			stage.replaceChildren();
			if (!r || !r.ok) {
				stage.append(note(o.errorText ? o.errorText(r, t) : t('drive.vv.failed'), true));
				dlg.foot.append(...wayOut(s));
				return;
			}
			if (r.note) {
				const key = !vault && r.note === 'too_large' ? 'drive.vv.docTooLarge'
					: { office: 'drive.vv.office', heic: 'drive.vv.heic', other: 'drive.vv.other', too_large: 'drive.vv.tooLarge' }[r.note] || 'drive.vv.other';
				stage.append(note(t(key, { max: r.limitMb || 0 }), r.note === 'too_large' || !vault));
				dlg.foot.append(...wayOut(s));
				return;
			}
			s.token = r.token || null;
			try {
				if (vault && r.kind === 'image') showImage(s, stage, r);
				else if (vault && (r.kind === 'video' || r.kind === 'audio')) showMedia(s, stage, r);
				else if (r.kind === 'pdf') await showPdf(s, stage, vault ? await bytesOf(s, r, 200 * MB) : r.data);
				else if (r.kind === 'text' || r.kind === 'markdown') showText(s, stage, vault ? await textOf(s, r) : r.text, r.kind === 'markdown');
				else throw new Error(`no page for ${r.kind}`);
			} catch (err) {
				if (s.closed) return;
				// the reason only (never content of the file)
				console.warn(`${vault ? 'Vault' : 'Drive'} viewer: ${(err && err.name) || 'Error'}: ${(err && err.message) || ''}`.slice(0, 300));
				stage.replaceChildren(note(t('drive.vv.failed'), true));
			}
			if (!s.closed) dlg.foot.append(...wayOut(s));
		}

		function showImage(s, stage, r) {
			const img = el('img', { class: 'dv-vv-img', alt: s.n.name, draggable: 'false' });
			img.src = r.url;
			let zoom = 0;
			const label = el('span', { class: 'dv-vv-zoom', text: t('drive.vv.fit') });
			const apply = () => {
				if (!zoom) { img.style.width = ''; img.classList.remove('is-zoomed'); label.textContent = t('drive.vv.fit'); return; }
				img.classList.add('is-zoomed');
				img.style.width = `${Math.round((img.naturalWidth || 800) * zoom)}px`;
				label.textContent = `${Math.round(zoom * 100)} %`;
			};
			const fitted = () => (img.naturalWidth ? img.getBoundingClientRect().width / img.naturalWidth : 1);
			const step = (f) => { zoom = Math.max(0.05, Math.min(8, (zoom || fitted()) * f)); apply(); };
			img.addEventListener('dblclick', () => { zoom = zoom ? 0 : 1; apply(); });
			const wrap = el('div', { class: 'dv-vv-pic' }, [img]);
			wrap.addEventListener('wheel', (e) => { if (!e.ctrlKey) return; e.preventDefault(); step(e.deltaY < 0 ? 1.15 : 1 / 1.15); }, { passive: false });
			const tools = s.dlg.body.querySelector('.dv-vv-tools');
			tools.insertBefore(el('span', { class: 'dv-vv-zoombar' }, [
				el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: '−', title: t('drive.vv.zoomOut'), 'aria-label': t('drive.vv.zoomOut'), on: { click: () => step(1 / 1.25) } }),
				label,
				el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: '+', title: t('drive.vv.zoomIn'), 'aria-label': t('drive.vv.zoomIn'), on: { click: () => step(1.25) } }),
				el('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('drive.vv.fit'), on: { click: () => { zoom = 0; apply(); } } }),
			]), tools.querySelector('.dv-grow'));
			stage.append(wrap);
			s.cleanups.push(() => { img.removeAttribute('src'); img.src = ''; img.remove(); });
		}

		function showMedia(s, stage, r) {
			const m = el(r.kind === 'audio' ? 'audio' : 'video', { class: 'dv-vv-video', controls: true, preload: 'metadata', controlsList: 'nodownload noremoteplayback', disablePictureInPicture: true });
			m.src = r.url;
			// watching counts as use of the vault (it would lock in the middle of a film otherwise)
			let timer = null;
			m.addEventListener('play', () => { touch(); clearInterval(timer); timer = setInterval(() => { if (!m.paused) touch(); }, 30000); });
			m.addEventListener('pause', () => { clearInterval(timer); timer = null; });
			stage.append(m);
			s.cleanups.push(() => { clearInterval(timer); m.pause(); m.removeAttribute('src'); m.load(); m.remove(); });
		}

		async function bytesOf(s, r, max) {
			const res = await fetch(r.url, { cache: 'no-store' });
			if (!res.ok) throw new Error(`status ${res.status}`);
			const len = Number(res.headers.get('content-length')) || r.size || 0;
			if (len > max) throw new Error('too large');
			return new Uint8Array(await res.arrayBuffer());
		}

		/** `bytes` (a Uint8Array) as pages on <canvas>; for a vault file they are zeroed when it closes. */
		async function showPdf(s, stage, input) {
			const lib = await loadPdfjs();
			const bytes = input instanceof Uint8Array ? input : new Uint8Array(input || []);
			if (s.closed) { if (vault) bytes.fill(0); return; }
			const task = lib.getDocument({
				data: bytes, isEvalSupported: false, enableXfa: false, disableAutoFetch: true, disableStream: true, disableRange: true,
				useSystemFonts: true, stopAtErrors: false, verbosity: 0,
			});
			const canvases = [];
			let doc = null;
			s.cleanups.push(() => {
				try { task.destroy(); } catch { /* gone */ }
				try { if (doc) doc.destroy(); } catch { /* gone */ }
				if (vault) { try { if (bytes.buffer.byteLength) bytes.fill(0); } catch { /* handed to the worker */ } }
				for (const c of canvases) { c.width = 0; c.height = 0; }
				canvases.length = 0;
			});
			try {
				doc = await task.promise;
			} catch (err) {
				if (s.closed) return;
				stage.replaceChildren(note(err && err.name === 'PasswordException' ? t('drive.vv.pdfPassword') : t('drive.vv.failed'), true));
				return;
			}
			if (s.closed) return;
			const pages = el('div', { class: 'dv-vv-pages' });
			stage.append(pages);
			const tools = s.dlg.body.querySelector('.dv-vv-tools');
			tools.insertBefore(el('span', { class: 'dv-vv-zoom', text: t('drive.vv.pages', { n: doc.numPages }) }), tools.querySelector('.dv-grow'));
			const width = Math.max(320, Math.min(1600, (pages.clientWidth || 860) - 16));
			const ratio = Math.min(2, root.devicePixelRatio || 1);
			const slots = [];
			let chain = Promise.resolve();
			const render = (i) => {
				if (slots[i].done) return;
				slots[i].done = true;
				chain = chain.then(async () => {
					if (s.closed) return;
					const page = await doc.getPage(i + 1);
					if (s.closed) return;
					const base = page.getViewport({ scale: 1 });
					const vp = page.getViewport({ scale: (width / base.width) * ratio });
					const c = el('canvas', { class: 'dv-vv-page', role: 'img', 'aria-label': t('drive.vv.page', { n: i + 1 }) });
					c.width = Math.floor(vp.width);
					c.height = Math.floor(vp.height);
					c.style.width = `${Math.floor(vp.width / ratio)}px`;
					canvases.push(c);
					slots[i].el.replaceChildren(c);
					slots[i].el.style.minHeight = '';
					await page.render({ canvasContext: c.getContext('2d'), viewport: vp, annotationMode: lib.AnnotationMode ? lib.AnnotationMode.ENABLE : 1 }).promise;
					page.cleanup();
				}).catch(() => { /* a page that cannot be shown */ });
			};
			for (let i = 0; i < doc.numPages; i++) {
				const slot = el('div', { class: 'dv-vv-slot', 'data-page': String(i + 1) });
				slot.style.minHeight = `${Math.round(width * 1.3)}px`;
				slots.push({ el: slot, done: false });
				pages.append(slot);
			}
			const io = new IntersectionObserver((entries) => {
				for (const e of entries) {
					if (!e.isIntersecting) continue;
					const k = Number(e.target.getAttribute('data-page')) - 1;
					for (let j = k; j <= Math.min(doc.numPages - 1, k + 2); j++) render(j);
				}
			}, { root: s.dlg.box.closest('.dv-scrim') || null, rootMargin: '400px 0px' });
			for (const x of slots) io.observe(x.el);
			s.cleanups.push(() => io.disconnect());
			for (let k = 0; k < Math.min(doc.numPages, 3); k++) render(k);
			await chain;
		}

		/** A vault text: fetched into memory, decoded, the bytes zeroed. */
		async function textOf(s, r) {
			const bytes = await bytesOf(s, r, 8 * MB);
			if (s.closed) { bytes.fill(0); return ''; }
			const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
			bytes.fill(0);
			return text;
		}

		function showText(s, stage, text, md) {
			if (s.closed) return;
			const box = md ? el('div', { class: 'dv-vv-md' }, markdown(el, text)) : el('pre', { class: 'dv-vv-text', text });
			stage.append(box);
			s.cleanups.push(() => { box.replaceChildren(); box.remove(); });
		}

		return { open, close, isOpen: () => !!cur };
	}

	root.GCDriveVaultViewer = { create, createDoc, markdown };
}(typeof window !== 'undefined' ? window : globalThis));
