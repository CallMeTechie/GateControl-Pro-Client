'use strict';

// Drive plugin 1.31 'framePhotos' on the page "Drive" › "Fotos" (no DOM): „Für Fotorahmen freigeben“ / „Aus Fotorahmen
// entfernen“ for the photos selected and in the large view — only with the feature and with pictures among them; the
// toast names the photos left out and why; 403 { field: 'frame' }: this account may not share photos.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const PS = require('../src/renderer/drive-photos-state');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const t = (key, p) => (p ? `${key}(${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')})` : key);

const pic = (id) => ({ id, kind: 'image', mime: 'image/jpeg', name: `IMG_${id}.jpg` });
const vid = (id) => ({ id, kind: 'video', mime: 'video/mp4', name: `VID_${id}.mp4` });

describe('Drive 1.31: photos for the photo frame', () => {
  it('only with the feature framePhotos', () => {
    assert.equal(PS.framePhotosOn({ features: ['photos', 'albums', 'framePhotos'] }), true);
    assert.equal(PS.framePhotosOn({ features: ['photos', 'albums', 'frame'] }), false);
    assert.equal(PS.framePhotosOn(null), false);
  });

  it('the menu: share what is not in the frame, remove what is; nothing with videos only', () => {
    const inFrame = new Set([2]);
    assert.deepEqual(PS.frameChoice([pic(1), pic(2), vid(3)], inFrame), { pictures: [1, 2], add: [1, 3], remove: [2] });
    assert.deepEqual(PS.frameChoice([pic(2)], inFrame), { pictures: [2], add: [], remove: [2] });
    assert.deepEqual(PS.frameChoice([vid(3), vid(4)], inFrame), { pictures: [], add: [], remove: [] });
    assert.deepEqual(PS.frameChoice([pic(5)], null), { pictures: [5], add: [5], remove: [] });
    // a video known by its mime alone is no picture either
    assert.deepEqual(PS.frameChoice([{ id: 6, mime: 'video/quicktime' }], null).pictures, []);
    assert.deepEqual(PS.frameChoice(null, null).pictures, []);
  });

  it('what is in the frame: GET ?ids= sets those asked, POST / DELETE give all', () => {
    let f = new Set([1, 2]);
    f = PS.frameMerge(f, { ok: true, ids: [3] }, [2, 3]);
    assert.deepEqual([...f].sort(), [1, 3]);
    f = PS.frameMerge(f, { ok: true, ids: [7, 8] }, null);
    assert.deepEqual([...f], [7, 8]);
    assert.deepEqual([...PS.frameMerge(f, { ok: false, code: 'network' }, [7])], [7, 8]);
  });

  it('the toast: how many, the photos left out with their reason, 403, errors', () => {
    assert.deepEqual(PS.frameToast({ ok: true, added: 3, skipped: [] }, { t }), { text: 'drive.photos.frame.added.other(count=3)', tone: 'success' });
    const r = PS.frameToast({ ok: true, added: 1, skipped: [
      { id: 2, reason: 'not_image' }, { id: 3, reason: 'not_image' }, { id: 4, reason: 'vault' }, { id: 5, reason: 'blocked' },
      { id: 6, reason: 'child' }, { id: 7, reason: 'not_found' }, { id: 8, reason: 'unknown' },
    ] }, { t });
    assert.equal(r.tone, 'success');
    assert.equal(r.text, 'drive.photos.frame.added.one(count=1) drive.photos.frame.skipped.other(why=drive.photos.frame.why.not_image.other(count=2), '
      + 'drive.photos.frame.why.vault.one(count=1), drive.photos.frame.why.blocked.one(count=1), drive.photos.frame.why.child.one(count=1), '
      + 'drive.photos.frame.why.not_found.one(count=1), drive.photos.frame.why.other.one(count=1),count=7)');
    // nothing shared: a hint, not a success
    assert.equal(PS.frameToast({ ok: true, added: 0, skipped: [{ id: 2, reason: 'not_image' }] }, { t }).tone, 'info');
    assert.deepEqual(PS.frameToast({ ok: true, removed: 2 }, { t, remove: true }), { text: 'drive.photos.frame.removed.other(count=2)', tone: 'success' });
    assert.deepEqual(PS.frameToast({ ok: false, code: 'forbidden', status: 403, field: 'frame' }, { t }), { text: 'drive.photos.frame.forbidden', tone: 'error' });
    assert.deepEqual(PS.frameToast({ ok: false, code: 'network' }, { t, errorText: () => 'offline' }), { text: 'offline', tone: 'error' });
    assert.deepEqual(PS.frameToast(null, { t }), { text: 'drive.photos.frame.failed', tone: 'error' });
  });

  it('the strings exist in de and en (every reason)', () => {
    const de = JSON.parse(read('src', 'i18n', 'de.json')).drive.photos.frame;
    const en = JSON.parse(read('src', 'i18n', 'en.json')).drive.photos.frame;
    for (const f of [de, en]) {
      for (const k of ['add', 'remove', 'badge', 'forbidden', 'failed']) assert.equal(typeof f[k], 'string', k);
      for (const k of ['added', 'removed', 'skipped']) assert.ok(f[k].one && f[k].other, k);
      for (const k of [...PS.FRAME_REASONS, 'other']) assert.ok(f.why[k] && f.why[k].one && f.why[k].other, k);
    }
    assert.match(de.why.not_image.one, /Video/);
    assert.match(de.forbidden, /Konto/);
  });

  it('the view: entries in the bar and the large view, a mark on the tiles, the icon', () => {
    const v = read('src', 'renderer', 'drive-photos-view.js');
    assert.match(v, /frameBtn\(false\)/);
    assert.match(v, /fc && fc\.remove\.length \? frameBtn\(true\)/);
    assert.match(v, /api\.framePhotos\(asked\)/);
    assert.match(v, /api\.addToFrame\(part\)/);
    assert.match(v, /api\.removeFromFrame\(part\)/);
    assert.match(v, /dpv-frame-btn/);
    assert.match(v, /dpv-framed/);
    assert.match(read('src', 'renderer', 'drive-view.js'), /\bframe: 'M3 4h18v16H3z/);
    assert.match(read('src', 'renderer', 'styles', 'drive.css'), /\.dpv-framed \{/);
  });
});
