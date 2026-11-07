'use strict';

// Drive plugin 1.22: the viewer of vault files (src/renderer/drive-vault-viewer.js) — wired into the page (script
// order, CSP only for gcvault: pictures, media and fetch, never scripts), the scheme registered with the core's
// privileges, pdf.js vendored with its licence (no CDN), text only through text nodes, Markdown never as HTML.
// The e2e suite (test/e2e/drive-vault-viewer.spec.js) shows it working in the app.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
/** The host names of every http(s) address in `text` (parsed with URL, not matched by a pattern). */
const hostsIn = (text) => (String(text).match(/\bhttps?:\/\/[^\s'"`)<>;]+/g) || []).map((u) => new URL(u).hostname);

describe('drive-vault-viewer (Drive plugin 1.22)', () => {
  const html = read('src', 'renderer', 'index.html');
  const viewer = read('src', 'renderer', 'drive-vault-viewer.js');
  const view = read('src', 'renderer', 'drive-view.js');
  const main = read('src', 'main', 'main.js');

  it('index.html: before drive-view.js; CSP lets gcvault: only into pictures, media and fetch', () => {
    const i = (s) => html.indexOf(s);
    assert.ok(i('<script src="drive-vault-viewer.js">') > 0);
    assert.ok(i('<script src="drive-vault-viewer.js">') < i('<script src="drive-view.js">'));
    const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
    assert.match(csp, /img-src [^;]*gcvault:/);
    assert.match(csp, /media-src [^;]*gcvault:/);
    assert.match(csp, /connect-src 'self' gcvault:/);
    assert.doesNotMatch(csp, /(script|default|style|font)-src[^;]*gcvault/);
    assert.deepEqual(hostsIn(csp), [], 'no CDN');
  });

  it('main.js: the scheme with the core\'s privileges, served by the core', () => {
    assert.match(main, /VaultViews\.SCHEME_PRIVILEGES/);
    assert.match(main, /protocol\.handle\(DriveService\.VaultViews\.SCHEME, \(req\) => drive\.handleVaultProtocol\(req\)\)/);
  });

  it('pdf.js vendored with its licence, loaded from the app only', () => {
    for (const f of ['pdf.min.mjs', 'pdf.worker.min.mjs', 'LICENSE']) assert.ok(fs.existsSync(path.join(ROOT, 'src', 'renderer', 'vendor', 'pdfjs', f)), f);
    assert.match(read('src', 'renderer', 'vendor', 'pdfjs', 'LICENSE'), /Apache License/);
    assert.match(viewer, /import\(`\.\/\$\{PDF_LIB\}`\)/);
    assert.match(viewer, /isEvalSupported: false/);
    assert.deepEqual(hostsIn(viewer), [], 'no address of the internet');
  });

  it('nothing through innerHTML, no blob: or object URL, no storage; the page opens vault files in it', () => {
    const code = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.doesNotMatch(code(viewer), /innerHTML|insertAdjacentHTML|outerHTML|document\.write|\beval\(|new Function\(/);
    assert.doesNotMatch(code(viewer), /createObjectURL|localStorage|sessionStorage|indexedDB|caches\./);
    assert.match(viewer, /vapi\.onLock\(\(e\) => \{ if \(e && e\.locked\) close\(\); \}\)/, 'the lock closes it');
    assert.match(viewer, /vapi\.viewClose\(s\.token\)/, 'closing revokes the token');
    assert.match(viewer, /vapi\.protect\(true\)/);
    assert.match(view, /if \(n\.encrypted && vaultViewer && !external\) \{ vaultViewer\.open\(n\); return; \}/);
  });

  it('Markdown: headings, lists, code and quotes as elements; HTML of the file stays text', () => {
    // a minimal DOM: elements with children and text nodes
    const mk = (tag) => ({ tag, children: [], attrs: {}, text: '', appendChild(c) { this.children.push(c); return c; } });
    global.document = { createTextNode: (t) => ({ tag: '#text', text: t }) };
    const el = (tag, a, kids) => { const n = mk(tag); if (a && a.text != null) n.text = String(a.text); if (a && a.class) n.attrs.class = a.class; for (const k of kids || []) n.children.push(k); return n; };
    const text = (n) => (n.tag === '#text' ? n.text : n.text + n.children.map(text).join(''));
    global.window = global;
    delete require.cache[require.resolve('../src/renderer/drive-vault-viewer.js')];
    require('../src/renderer/drive-vault-viewer.js');
    const out = global.GCDriveVaultViewer.markdown(el, '# Titel\n\nmit **fett** <img src=x onerror=alert(1)>\n\n1. eins\n2. [x] zwei\n\n```\n<b>roh</b>\n```\n> Zitat');
    assert.deepEqual(out.map((n) => n.tag), ['h2', 'p', 'ol', 'pre', 'blockquote']);
    assert.ok(text(out[1]).includes('<img src=x onerror=alert(1)>'), 'stays text');
    assert.equal(out[1].children.find((c) => c.tag === 'strong').text, 'fett');
    assert.equal(text(out[2]), 'eins☑ zwei');
    assert.equal(out[3].text, '<b>roh</b>');
    delete global.document;
  });

  it('texts in both languages', () => {
    const de = JSON.parse(read('src', 'i18n', 'de.json')).drive.vv;
    const en = JSON.parse(read('src', 'i18n', 'en.json')).drive.vv;
    assert.deepEqual(Object.keys(de).sort(), Object.keys(en).sort());
    for (const k of viewer.matchAll(/t\('drive\.vv\.([A-Za-z]+)'/g)) assert.ok(de[k[1]] && en[k[1]], k[1]);
    assert.match(de.openWithText, /unverschlüsselt/);
  });
});
