'use strict';

// Drive 1.21 — the large view of pictures and videos (drive-viewer-state.js, drive-viewer.js, the lightbox of
// drive-photos-view.js): which files of a folder it goes through (pictures and videos, never a vault's), the zoom
// (held in view), where a video was left, the hint for a type the PC rarely plays; the page wiring (scripts, CSP
// gcdrive:, "Dateien" opens the view, gcdrive: registered with the core's DriveStreamService), and every key in de
// and en.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const VS = require('../src/renderer/drive-viewer-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const de = require('../src/i18n/de.json');
const en = require('../src/i18n/en.json');
const node = (id, name, mime, o = {}) => ({ id, name, mime, isDir: false, size: 10, mediaId: `m${id}`, rev: 1, ...o });

describe('Drive 1.21: the large view', () => {
	it('kindOf: pictures and videos, by type or (unknown type) by name; no folder, vault, SVG or document', () => {
		assert.equal(VS.kindOf(node(1, 'a.jpg', 'image/jpeg')), 'image');
		assert.equal(VS.kindOf(node(2, 'b.mov', 'video/quicktime')), 'video');
		assert.equal(VS.kindOf(node(3, 'c.mkv', 'application/octet-stream')), 'video');
		assert.equal(VS.kindOf(node(4, 'd.heic', null)), 'image');
		assert.equal(VS.kindOf(node(5, 'e.pdf', 'application/pdf')), null);
		assert.equal(VS.kindOf(node(6, 'Fotos', null, { isDir: true })), null);
		assert.equal(VS.kindOf(node(7, 'x', 'image/jpeg', { encrypted: true })), null, 'a vault file is ciphertext');
		assert.equal(VS.kindOf(node(8, 'logo.svg', 'image/svg+xml')), null);
	});

	it('viewerList: the pictures and videos of the folder from the one clicked, as items of the view', () => {
		const items = [node(1, 'Ordner', null, { isDir: true }), node(2, 'a.jpg', 'image/jpeg', { mtime: 5 }), node(3, 'Brief.pdf', 'application/pdf'), node(4, 'b.mp4', 'video/mp4'), node(5, 'c.png', 'image/png')];
		const { list, start } = VS.viewerList(items, items[3]);
		assert.deepEqual(list.map((x) => x.id), [2, 4, 5]);
		assert.equal(start, 1);
		assert.deepEqual(list.map((x) => x.kind), ['image', 'video', 'image']);
		assert.equal(list[0].takenAt, 5, 'the date of the photos: takenAt, else the file time');
		const gone = node(9, 'z.jpg', 'image/jpeg');
		assert.deepEqual(VS.viewerList(items, gone).list.map((x) => x.id), [9]);
		assert.deepEqual(VS.viewerList(null, gone).start, 0);
	});

	it('zoom: between 1× and 8×, about the pointer, held in view; back to 1× resets the shift', () => {
		let z = { s: 1, x: 0, y: 0 };
		z = VS.zoomBy(z, 2, 100, 0, { w: 800, h: 600 });
		assert.equal(z.s, 2);
		assert.equal(z.x, -100, 'the point under the pointer stays');
		z = VS.zoomBy(z, 100, 0, 0, { w: 800, h: 600 });
		assert.equal(z.s, VS.ZOOM_MAX);
		assert.deepEqual(VS.clamp({ s: 2, x: 9999, y: -9999 }, { w: 800, h: 600 }), { s: 2, x: 400, y: -300 });
		assert.deepEqual(VS.zoomBy({ s: 2, x: 50, y: 50 }, 0.1), { s: 1, x: 0, y: 0 });
		assert.equal(VS.transform({ s: 1, x: 0, y: 0 }), '');
		assert.equal(VS.transform({ s: 1.5, x: 10.4, y: -3 }), 'translate(10px, -3px) scale(1.5)');
	});

	it('places: kept after 5 s, not near the end, per revision, the last ones only', () => {
		const p = VS.places(2);
		const a = node(1, 'a.mp4', 'video/mp4');
		p.keep(a, 3, 60);
		assert.equal(p.get(a), null);
		p.keep(a, 30, 60);
		assert.equal(p.get(a), 30);
		assert.equal(p.get({ ...a, rev: 2 }), null, 'a new revision starts from the beginning');
		p.keep(a, 57, 60);
		assert.equal(p.get(a), null, 'near the end: from the beginning next time');
		p.keep(a, 20, NaN);
		assert.equal(p.get(a), 20, 'a length not known yet');
		p.keep(node(2, 'b.mp4'), 10, 60);
		p.keep(node(3, 'c.mp4'), 10, 60);
		assert.equal(p.get(a), null, 'the oldest goes');
		assert.equal(p.size, 2);
		p.forget(node(3, 'c.mp4'));
		assert.equal(p.size, 1);
	});

	it('the hint first for a type the PC rarely plays; MediaError codes', () => {
		assert.equal(VS.rareType('video/x-matroska', () => ''), true);
		assert.equal(VS.rareType('video/x-matroska', () => 'maybe'), false, 'this PC says it can');
		assert.equal(VS.rareType('video/mp4', () => ''), false, 'MP4 is tried (an error says it then)');
		assert.equal(VS.rareType('video/x-msvideo'), true);
		assert.equal(VS.typeName(node(1, 'Konzert.mkv', 'video/x-matroska')), 'MKV');
		assert.equal(VS.typeName(node(2, 'ohne', 'video/mp4')), 'video/mp4');
		assert.equal(VS.trouble(4), 'cannot');
		assert.equal(VS.trouble(3), 'cannot');
		assert.equal(VS.trouble(2), 'network');
		assert.equal(VS.trouble(1), 'other');
	});

	it('the page: scripts in order, CSP gcdrive: for pictures and videos, "Dateien" opens the view', () => {
		const html = read('src', 'renderer', 'index.html');
		const at = (f) => html.indexOf(`<script src="${f}"></script>`);
		assert.ok(at('drive-viewer-state.js') > 0 && at('drive-viewer-state.js') < at('drive-viewer.js') && at('drive-viewer.js') < at('drive-photos-view.js'));
		const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
		assert.match(csp, /img-src [^;]*\bgcdrive:/);
		assert.match(csp, /media-src [^;]*\bgcdrive:/);
		assert.doesNotMatch(csp, /script-src [^;]*gcdrive:/);
		const view = read('src', 'renderer', 'drive-view.js');
		assert.match(view, /VS\.kindOf\(n\) && typeof api\.stream === 'function'/);
		assert.match(view, /photosView\.lightbox\(list, start\)/);
		const photos = read('src', 'renderer', 'drive-photos-view.js');
		assert.match(photos, /viewer\.video\(stage, p/);
		assert.match(photos, /viewer\.picture\(stage, p/);
		assert.match(photos, /cur\.destroy\(\)/, 'a video stops and its address ends when the view moves on or closes');
	});

	it('the main process: gcdrive: privileged with the other schemes, served by the core DriveStreamService', () => {
		const main = read('src', 'main', 'main.js');
		assert.match(main, /schemes\.push\(\{ scheme: DriveStreamService\.SCHEME, privileges: \{ \.\.\.DriveStreamService\.SCHEME_PRIVILEGES \} \}\)/);
		assert.equal((main.match(/registerSchemesAsPrivileged\(/g) || []).length, 1, 'Electron takes them in one call');
		assert.match(main, /protocol\.handle\(DriveStreamService\.SCHEME, \(req\) => driveStream\.handleProtocol\(req\)\)/);
		assert.match(main, /new DriveStreamService\(\{ drive, log \}\)/);
		assert.match(main, /\n\s+driveStream,\n/, 'handed to registerBaseHandlers (drive:stream, reset on server:setup)');
	});

	it('every key of the view exists in de and en', () => {
		const src = read('src', 'renderer', 'drive-viewer.js') + read('src', 'renderer', 'drive-photos-view.js');
		const keys = [...new Set([...src.matchAll(/t\('(drive\.viewer\.[A-Za-z]+)'/g)].map((m) => m[1]))];
		assert.ok(keys.length >= 10);
		const get = (o, k) => k.split('.').reduce((x, p) => (x ? x[p] : undefined), o);
		for (const k of keys) {
			assert.equal(typeof get(de, k), 'string', `de ${k}`);
			assert.equal(typeof get(en, k), 'string', `en ${k}`);
		}
		assert.match(de.drive.viewer.cannotPlay, /\{\{type\}\}/);
		assert.match(en.drive.viewer.cannotPlay, /\{\{type\}\}/);
	});
});
