'use strict';

// The viewer of PDFs, texts and Markdown of normal Drive files (drive-vault-viewer.js createDoc, core
// DriveService.docView): which files it takes (drive-viewer-state.js docKindOf), that the page routes them there
// (another program only on purpose), and what the viewer shows — a text as text, Markdown as elements, a note for one
// too large, "Mit anderem Programm öffnen" without the vault's question, nothing of the vault (no protection, no lock).
// The e2e suite (test/e2e/drive-doc-viewer.spec.js) shows a PDF drawn by pdf.js in the app.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const VS = require('../src/renderer/drive-viewer-state.js');

/** A minimal DOM: elements with children, text, classes, attributes and listeners. */
function fakeDom() {
  const mk = (tag) => {
    const n = {
      tag, children: [], attrs: {}, text: '', listeners: {}, classes: new Set(),
      classList: { add: (c) => n.classes.add(c), remove: (c) => n.classes.delete(c) },
      append(...k) { for (const c of k) if (c) n.children.push(c); },
      appendChild(c) { n.children.push(c); return c; },
      replaceChildren(...k) { n.children = k.filter(Boolean); },
      remove() {},
      setAttribute(k, v) { n.attrs[k] = v; },
      addEventListener(ev, fn) { (n.listeners[ev] = n.listeners[ev] || []).push(fn); },
      querySelector(sel) { return find(n, (x) => sel.startsWith('.') && String(x.attrs.class || '').split(' ').includes(sel.slice(1))); },
      closest() { return null; },
    };
    return n;
  };
  const find = (n, ok) => {
    for (const c of n.children || []) {
      if (ok(c)) return c;
      const d = find(c, ok);
      if (d) return d;
    }
    return null;
  };
  const el = (tag, a, kids) => {
    const n = mk(tag);
    for (const [k, v] of Object.entries(a || {})) {
      if (k === 'text') n.text = String(v);
      else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
      else n.attrs[k] = v;
    }
    for (const k of kids || []) if (k) n.children.push(k);
    return n;
  };
  const text = (n) => (n.tag === '#text' ? n.text : n.text + (n.children || []).map(text).join(''));
  const dialogs = [];
  const openDialog = (o) => {
    const d = { title: o.title, box: mk('div'), body: mk('div'), foot: mk('div'), closed: false, close() { d.closed = true; o.onClose && o.onClose(); } };
    dialogs.push(d);
    return d;
  };
  return { el, mk, find, text, dialogs, openDialog, icon: (name) => mk(`icon:${name}`) };
}

function load() {
  global.window = global;
  global.document = { createTextNode: (t) => ({ tag: '#text', text: t }) };
  global.addEventListener = () => {};
  delete require.cache[require.resolve('../src/renderer/drive-vault-viewer.js')];
  require('../src/renderer/drive-vault-viewer.js');
  return global.GCDriveVaultViewer;
}

const t = (k, v) => (v && v.max != null ? `${k}:${v.max}` : k);
const flush = () => new Promise((r) => setImmediate(r));

describe('drive document viewer: which files', () => {
  it('PDFs, texts and Markdown by name, else by type; no pictures, videos, Office, folders, vault files', () => {
    assert.equal(VS.docKindOf({ name: 'Brief.pdf', mime: 'application/pdf' }), 'pdf');
    assert.equal(VS.docKindOf({ name: 'Scan', mime: 'application/pdf' }), 'pdf');
    assert.equal(VS.docKindOf({ name: 'notiz.txt' }), 'text');
    assert.equal(VS.docKindOf({ name: 'README', mime: 'text/plain; charset=utf-8' }), 'text');
    assert.equal(VS.docKindOf({ name: 'Plan.MD' }), 'markdown');
    assert.equal(VS.docKindOf({ name: 'Notes', mime: 'text/markdown' }), 'markdown');
    assert.equal(VS.docKindOf({ name: 'Bericht.docx', mime: 'text/plain' }), null, 'Office by its name');
    assert.equal(VS.docKindOf({ name: 'Foto.jpg', mime: 'image/jpeg' }), null, 'the large view');
    assert.equal(VS.docKindOf({ name: 'clip.ts', mime: 'video/mp2t' }), null, 'a video, not TypeScript');
    assert.equal(VS.docKindOf({ name: 'Ordner', isDir: true }), null);
    assert.equal(VS.docKindOf({ name: 'geheim.pdf', encrypted: true }), null, 'the vault has its own viewer');
    assert.equal(VS.docKindOf({ name: 'seite', mime: 'text/html' }), null);
    assert.equal(VS.docKindOf(null), null);
  });

  it('the page: a document into the viewer, another program only on purpose; the viewer wired with docView', () => {
    const view = read('src', 'renderer', 'drive-view.js');
    assert.match(view, /if \(docViewer && !external && VS && VS\.docKindOf\(n\)\) \{ docViewer\.open\(n\); return; \}/);
    assert.match(view, /GCDriveVaultViewer\.createDoc\(\{/);
    assert.match(view, /typeof api\.docView === 'function'/);
    // a blocked file still says why before anything else, a marked one asks first
    const i = (s) => view.indexOf(s);
    assert.ok(i('SCAN.isBlocked(n.scan)') < i('docViewer.open(n)'));
    assert.ok(i('SCAN.isWarning(n.scan)') < i('docViewer.open(n)'));
  });

  it('texts in both languages', () => {
    const de = JSON.parse(read('src', 'i18n', 'de.json')).drive.vv;
    const en = JSON.parse(read('src', 'i18n', 'en.json')).drive.vv;
    for (const k of ['loading', 'docTooLarge', 'openWith', 'failed', 'pdfPassword']) assert.ok(de[k] && en[k], k);
    assert.match(de.docTooLarge, /\{\{max\}\} MB/);
  });
});

describe('drive document viewer: what it shows', () => {
  function setup(answer) {
    const V = load();
    const dom = fakeDom();
    const calls = { docView: [], openWith: [], saveAs: [], protect: 0 };
    const api = {
      docView: async (id) => { calls.docView.push(id); return typeof answer === 'function' ? answer(id) : answer; },
      vault: { protect: () => { calls.protect++; }, onLock() {}, view() { throw new Error('not the vault'); } },
    };
    const v = V.createDoc({
      api, t, ui: { el: dom.el, icon: dom.icon, openDialog: dom.openDialog }, host: dom.mk('div'), toast() {}, errorText: (r) => `err:${r.code}`,
      openWith: (n) => calls.openWith.push(n.id), saveAs: (n) => calls.saveAs.push(n.id),
    });
    return { v, dom, calls };
  }

  it('a text: decoded by the core, shown as text (selectable — no vault protection, no lock)', async () => {
    const { v, dom, calls } = setup({ ok: true, kind: 'text', name: 'Notiz.txt', size: 5, text: 'Grüße <b>roh</b>' });
    await v.open({ id: 21, name: 'Notiz.txt' });
    await flush();
    const d = dom.dialogs[0];
    assert.deepEqual(calls.docView, [21]);
    assert.equal(d.box.attrs['data-doc-viewer'], '1');
    assert.equal(d.box.listeners.contextmenu, undefined, 'copying is allowed');
    assert.equal(calls.protect, 0, 'no content protection');
    const pre = dom.find(d.body, (x) => x.tag === 'pre');
    assert.equal(pre.text, 'Grüße <b>roh</b>', 'stays text');
    assert.equal(dom.find(d.body, (x) => String(x.attrs.class || '').includes('dv-vv-lock')), null);
    assert.equal(dom.find(d.body, (x) => String(x.attrs.class || '').includes('dv-vv-mem')), null);
    // "Mit anderem Programm öffnen": at once (no vault question), the viewer closes
    const btn = dom.find(d.foot, (x) => String(x.attrs.class || '').includes('dv-vv-openwith'));
    assert.equal(btn.text, 'drive.vv.openWith');
    btn.listeners.click[0]();
    assert.deepEqual(calls.openWith, [21]);
    assert.equal(d.closed, true);
    assert.equal(v.isOpen(), false);
  });

  it('Markdown as elements', async () => {
    const { v, dom } = setup({ ok: true, kind: 'markdown', name: 'Plan.md', size: 9, text: '# Plan\n- **eins**' });
    await v.open({ id: 22, name: 'Plan.md' });
    await flush();
    const md = dom.find(dom.dialogs[0].body, (x) => x.attrs.class === 'dv-vv-md');
    assert.deepEqual(md.children.map((c) => c.tag), ['h2', 'ul']);
  });

  it('too large: the note with the limit, the ways out; a failure says why', async () => {
    const { v, dom, calls } = setup((id) => (id === 23 ? { ok: true, kind: 'pdf', name: 'Riesig.pdf', note: 'too_large', limitMb: 100 } : { ok: false, code: 'offline' }));
    await v.open({ id: 23, name: 'Riesig.pdf' });
    await flush();
    const d = dom.dialogs[0];
    assert.match(dom.text(d.body), /drive\.vv\.docTooLarge:100/);
    const save = dom.find(d.foot, (x) => x.text === 'drive.saveAs');
    save.listeners.click[0]();
    assert.deepEqual(calls.saveAs, [23]);
    await v.open({ id: 24, name: 'Weg.txt' });
    await flush();
    assert.match(dom.text(dom.dialogs[1].body), /err:offline/);
    assert.ok(dom.find(dom.dialogs[1].foot, (x) => String(x.attrs.class || '').includes('dv-vv-openwith')));
  });

  it('closed while loading: nothing is shown', async () => {
    let release;
    const { v, dom } = setup(() => new Promise((r) => { release = r; }));
    const p = v.open({ id: 25, name: 'Lang.txt' });
    await flush();
    v.close();
    release({ ok: true, kind: 'text', name: 'Lang.txt', size: 1, text: 'spät' });
    await p;
    assert.equal(dom.find(dom.dialogs[0].body, (x) => x.tag === 'pre'), null);
  });
});
