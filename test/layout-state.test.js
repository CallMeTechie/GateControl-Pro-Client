'use strict';

// The sizes of the dividers (src/renderer/layout-state.js, no DOM): what is stored per page on this PC, the limits,
// the standard sizes (Mitteilungen 40 % within 380–520 px, the details of a note 520 px), the window limiting what is
// shown without touching what is stored, the keys, the badge; and how the page loads the scripts (gc-split.js after
// layout-state.js, before the views that use it), that gc-split.js builds no HTML from text, and that every
// layout.split.* key it uses exists in German and English.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const LS = require('../src/renderer/layout-state');

const ROOT = path.join(__dirname, '..');
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);

describe('layout-state: stored per page', () => {
  it('names a divider by page and path', () => {
    assert.deepEqual(LS.parseKey('notes.w.detail'), { page: 'notes', path: ['w', 'detail'] });
    assert.deepEqual(LS.parseKey('mail.h.list'), { page: 'mail', path: ['h', 'list'] });
    for (const bad of ['', 'notes', 'x.w.list', 'mail.x.list', 'mail.w.list.more', 'mail.w.__proto__', null]) assert.equal(LS.parseKey(bad), null, String(bad));
    assert.equal(LS.storageKey('inbox'), 'gc.layout.inbox');
  });

  it('reads what is stored, never throws', () => {
    assert.deepEqual(LS.readPage(null), {});
    assert.deepEqual(LS.readPage('{nope'), {});
    assert.deepEqual(LS.readPage('[1,2]'), {});
    assert.deepEqual(LS.readPage('"x"'), {});
    assert.deepEqual(LS.readPage('{"w":{"list":400}}'), { w: { list: 400 } });
  });

  it('a stored size within its limits, else nothing', () => {
    assert.equal(LS.sizeOf({ w: { list: 400 } }, 'inbox.w.list'), 400);
    assert.equal(LS.sizeOf({ w: { list: 9000 } }, 'inbox.w.list'), 640);
    assert.equal(LS.sizeOf({ w: { list: 10 } }, 'inbox.w.list'), 320);
    assert.equal(LS.sizeOf({ w: { list: '400' } }, 'inbox.w.list'), null);
    assert.equal(LS.sizeOf({ w: 3 }, 'inbox.w.list'), null);
    assert.equal(LS.sizeOf({}, 'inbox.w.list'), null);
    assert.equal(LS.sizeOf({ h: { list: 0.9 } }, 'mail.h.list'), 0.7);
    assert.equal(LS.sizeOf({ w: { list: 400 } }, 'inbox.w.nope'), null);
  });

  it('sets and removes a size as a copy; resetting keeps the rest', () => {
    const p = { reading: 'bottom', w: { folders: 200 } };
    const q = LS.withSize(p, 'mail.w.list', 412.4);
    assert.deepEqual(q, { reading: 'bottom', w: { folders: 200, list: 412 } });
    assert.deepEqual(p, { reading: 'bottom', w: { folders: 200 } });
    assert.deepEqual(LS.withSize(q, 'mail.h.list', 0.41234), { reading: 'bottom', w: { folders: 200, list: 412 }, h: { list: 0.412 } });
    assert.deepEqual(LS.withSize(LS.withSize(q, 'mail.w.list', null), 'mail.w.folders', null), { reading: 'bottom' });
    assert.deepEqual(LS.withoutSizes({ reading: 'off', w: { list: 1 }, h: { list: 0.5 } }), { reading: 'off' });
  });
});

describe('layout-state: sizes shown', () => {
  it('the standard sizes of the mockup', () => {
    assert.equal(LS.standard('mail.w.folders'), 224);
    assert.equal(LS.standard('mail.w.list'), 360);
    assert.equal(LS.standard('notes.w.side'), 232);
    assert.equal(LS.standard('notes.w.detail'), 460);
    assert.equal(LS.standard('notes.w.detail', { note: true }), 520);
    // Mitteilungen: 40 % of the room, 380–520 px
    assert.equal(LS.standard('inbox.w.list', { room: 1199 }), 480);
    assert.equal(LS.standard('inbox.w.list', { room: 759 }), 380);
    assert.equal(LS.standard('inbox.w.list', { room: 2000 }), 520);
    // Mail's list below: 42 % of the height
    assert.equal(LS.standard('mail.h.list', { room: 1000 }), 420);
  });

  it('the bounds: the other side keeps its least', () => {
    assert.deepEqual(LS.bounds('inbox.w.list', 1199), { min: 320, max: 640 });
    assert.deepEqual(LS.bounds('inbox.w.list', 759), { min: 320, max: 339 });
    // less room than both need: the pane keeps its least
    assert.deepEqual(LS.bounds('inbox.w.list', 500), { min: 320, max: 320 });
    assert.deepEqual(LS.bounds('notes.w.side', 300), { min: 190, max: 320 });
    assert.deepEqual(LS.bounds('mail.h.list', 1000), { min: 300, max: 700 });
    assert.deepEqual(LS.bounds('mail.h.list', 600), { min: 180, max: 380 });
  });

  it('a stored size is only limited by the window, the standard too', () => {
    assert.deepEqual(LS.shown('inbox.w.list', 352, 1199), { px: 352, limited: false });
    assert.deepEqual(LS.shown('inbox.w.list', 352, 759), { px: 339, limited: true });
    assert.deepEqual(LS.shown('inbox.w.list', null, 1199), { px: 480, limited: false });
    assert.deepEqual(LS.shown('notes.w.detail', null, 806, { note: true }), { px: 446, limited: true });
    assert.deepEqual(LS.shown('mail.h.list', 0.5, 800), { px: 400, limited: false });
    assert.deepEqual(LS.shown('mail.h.list', null, 800), { px: 336, limited: false });
    assert.equal(LS.toStored('mail.h.list', 400, 800), 0.5);
    assert.equal(LS.toStored('mail.h.list', 400, 0), null);
    assert.equal(LS.toStored('inbox.w.list', 412.6, 999), 413);
  });

  it('the keys of a focused divider', () => {
    const b = { min: 300, max: 640 };
    const k = (key, shiftKey = false) => ({ key, shiftKey });
    assert.equal(LS.keyStep(k('ArrowRight'), 360, b), 376);
    assert.equal(LS.keyStep(k('ArrowLeft'), 360, b), 344);
    assert.equal(LS.keyStep(k('ArrowRight', true), 360, b), 424);
    assert.equal(LS.keyStep(k('ArrowLeft', true), 320, b), 300);
    assert.equal(LS.keyStep(k('Home'), 360, b), 300);
    assert.equal(LS.keyStep(k('End'), 360, b), 640);
    assert.equal(LS.keyStep(k('Enter'), 360, b), 'reset');
    assert.equal(LS.keyStep(k('a'), 360, b), null);
    assert.equal(LS.keyStep(k('ArrowUp'), 360, b), null);
    // the pane after the divider (details on the right): ← makes it wider
    assert.equal(LS.keyStep(k('ArrowLeft'), 360, b, { end: true }), 376);
    assert.equal(LS.keyStep(k('ArrowRight'), 360, b, { end: true }), 344);
    // across (Mail's list below): ↓ makes the list taller
    assert.equal(LS.keyStep(k('ArrowDown'), 360, b, { h: true }), 376);
    assert.equal(LS.keyStep(k('ArrowUp'), 360, b, { h: true }), 344);
    assert.equal(LS.keyStep(k('ArrowRight'), 360, b, { h: true }), null);
  });

  it('dragging and the badge', () => {
    assert.equal(LS.dragSize(360, 52), 412);
    assert.equal(LS.dragSize(460, -60, { end: true }), 520);
    const b = { min: 300, max: 640 };
    assert.equal(LS.badgeText('mail.w.list', 412, b, 1000, t, false), '412 px');
    assert.equal(LS.badgeText('mail.w.list', 300, b, 1000, t, true), 'layout.split.w.min(300 px)');
    assert.equal(LS.badgeText('mail.w.list', 640, b, 1000, t, true), 'layout.split.w.max(640 px)');
    assert.equal(LS.badgeText('mail.h.list', 420, { min: 300, max: 700 }, 1000, t, false), '42 %');
    assert.equal(LS.badgeText('mail.h.list', 700, { min: 300, max: 700 }, 1000, t, true), 'layout.split.h.max(70 %)');
  });
});

describe('layout-state: the page', () => {
  const html = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'index.html'), 'utf8');
  const split = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'gc-split.js'), 'utf8');

  it('loads layout-state.js, then gc-split.js, before the views that use it', () => {
    const at = (f) => html.indexOf(`<script src="${f}"></script>`);
    for (const f of ['layout-state.js', 'gc-split.js', 'mail-view.js', 'notes-view.js', 'renderer.js']) assert.ok(at(f) > 0, f);
    assert.ok(at('layout-state.js') < at('gc-split.js'));
    assert.ok(at('gc-split.js') < at('mail-view.js'));
    assert.ok(at('gc-split.js') < at('notes-view.js'));
  });

  it('gc-split.js builds no HTML from text', () => {
    assert.doesNotMatch(split, /innerHTML|insertAdjacentHTML|outerHTML/);
  });

  it('every layout.split.* text exists in German and English', () => {
    const de = JSON.parse(fs.readFileSync(path.join(ROOT, 'src', 'i18n', 'de.json'), 'utf8'));
    const en = JSON.parse(fs.readFileSync(path.join(ROOT, 'src', 'i18n', 'en.json'), 'utf8'));
    const get = (o, k) => k.split('.').reduce((x, p) => (x && typeof x === 'object' ? x[p] : undefined), o);
    const used = new Set();
    for (const f of ['gc-split.js', 'layout-state.js', 'renderer.js', 'notes-view.js', 'mail-view.js']) {
      const src = fs.readFileSync(path.join(ROOT, 'src', 'renderer', f), 'utf8');
      for (const m of src.matchAll(/'(layout\.split\.[a-zA-Z.]+)'/g)) used.add(m[1]);
    }
    for (const ax of ['w', 'h']) for (const k of ['drag', 'hint', 'min', 'max']) used.add(`layout.split.${ax}.${k}`);
    assert.ok(used.size >= 11);
    for (const k of used) {
      assert.equal(typeof get(de, k), 'string', `de ${k}`);
      assert.equal(typeof get(en, k), 'string', `en ${k}`);
    }
  });
});

describe('layout-state: Mail „Ansicht“', () => {
  it('what is stored, else the standard (right, full, normal, the AI line on)', () => {
    assert.deepEqual(LS.mailView(null), { reading: 'right', folders: 'full', density: 'normal', ai: true });
    assert.deepEqual(LS.mailView({ reading: 'bottom', folders: 'narrow', density: 'compact', ai: false }), { reading: 'bottom', folders: 'narrow', density: 'compact', ai: false });
    assert.deepEqual(LS.mailView({ reading: 'left', folders: 1, density: 'tiny', ai: 'no' }), { reading: 'right', folders: 'full', density: 'normal', ai: true });
  });

  it('one choice changed; the sizes stay, unknown choices change nothing', () => {
    const p = { w: { list: 400 }, h: { list: 0.5 } };
    assert.deepEqual(LS.withMailView(p, 'reading', 'off'), { w: { list: 400 }, h: { list: 0.5 }, reading: 'off' });
    assert.deepEqual(LS.withMailView(p, 'ai', false), { w: { list: 400 }, h: { list: 0.5 }, ai: false });
    assert.deepEqual(LS.withMailView(p, 'reading', 'sideways'), p);
    assert.deepEqual(LS.withMailView(p, 'ai', 'off'), p);
    assert.deepEqual(LS.withMailView(p, 'w', 3), p);
    assert.deepEqual(p, { w: { list: 400 }, h: { list: 0.5 } });
    assert.deepEqual(LS.withoutSizes(LS.withMailView(p, 'density', 'compact')), { density: 'compact' });
  });

  it('the folder bar narrow for the time being below 1100 px, full in Kalender / Kontakte', () => {
    assert.deepEqual(LS.mailFolders('full', { width: 1440 }), { folders: 'full', auto: false });
    assert.deepEqual(LS.mailFolders('full', { width: 1099 }), { folders: 'narrow', auto: true });
    assert.deepEqual(LS.mailFolders('full', { width: 1100 }), { folders: 'full', auto: false });
    assert.deepEqual(LS.mailFolders('off', { width: 1000 }), { folders: 'off', auto: false });
    assert.deepEqual(LS.mailFolders('narrow', { width: 1440 }), { folders: 'narrow', auto: false });
    assert.deepEqual(LS.mailFolders('off', { width: 1000, area: true }), { folders: 'full', auto: false });
    assert.deepEqual(LS.mailFolders('bogus', { width: 1440 }), { folders: 'full', auto: false });
  });

  it('Mail keeps its dividers and the menu wired: keys in backticks (not texts), the button beside the search', () => {
    const src = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'mail-view.js'), 'utf8');
    for (const k of ['mail.w.folders', 'mail.w.list', 'mail.h.list']) assert.ok(src.includes(`key: \`${k}\``), k);
    assert.match(src, /class: 'ml-search-row' \}, \[el\('label', \{ class: 'ml-search' \}, \[icon\('search', 15\), searchIn\]\), viewButton\(\)\]\)/);
    for (const k of ['title', 'button', 'reading', 'right', 'bottom', 'off', 'folders', 'foldersFull', 'foldersNarrow', 'foldersOff', 'density', 'normal', 'compact', 'ai', 'reset', 'note', 'kbd', 'autoNarrow', 'back', 'colFrom', 'colSubject', 'colDate']) {
      assert.ok(src.includes(`'mail.view.${k}'`) || src.includes(`mail.view.\${k}`), k);
    }
  });
});
