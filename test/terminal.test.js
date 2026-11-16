'use strict';

// Fernzugriff stage 3 (SSH terminal): the main process side (./src/main/terminal.js) with a fake RemoteTerm, a fake
// window and ipcMain — the terminal window's messages only from that window, the recording hint before a recorded
// start, closing with running sessions asks first, errors reach the renderer as codes; plus the window's state
// (src/renderer/terminal-state.js) and the details of an SSH device (src/renderer/remote-term-state.js).

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const { setupTerminal, TEXT_KEYS, ERROR_KEYS } = require('../src/main/terminal');
const TS = require('../src/renderer/terminal-state');
const RTS = require('../src/renderer/remote-term-state');

function fakeTerm() {
  const rt = new EventEmitter();
  rt.sessions = new Map();
  rt.calls = [];
  let n = 0;
  rt.list = () => [...rt.sessions.values()];
  rt.devices = async () => ({ devices: [{ id: 2, name: 'pi-werkstatt' }], sshRight: true });
  rt.tmux = async (id) => { if (id === 9) throw Object.assign(new Error('x'), { code: 'host_key_mismatch' }); return { sessions: [], tmux: 'tmux' }; };
  rt.open = async (o) => {
    rt.calls.push(['open', o]);
    if (o.deviceId === 7) throw Object.assign(new Error('refused'), { code: 'recording_unavailable' });
    const s = { id: 'term_' + (++n), deviceId: o.deviceId, deviceName: o.deviceName, tmux: o.tmux ? o.tmux.attach || o.tmux.create : 'tmux', state: 'connecting', recording: o.record };
    rt.sessions.set(s.id, s);
    return s;
  };
  rt.input = (id, d) => { rt.calls.push(['input', id, d]); return true; };
  rt.resize = (...a) => rt.calls.push(['resize', ...a]);
  rt.trust = (...a) => rt.calls.push(['trust', ...a]);
  rt.reconnect = (id) => rt.calls.push(['reconnect', id]);
  rt.close = (id) => { rt.calls.push(['close', id]); rt.sessions.delete(id); };
  rt.closeAll = () => { rt.calls.push(['closeAll']); rt.sessions.clear(); };
  return rt;
}

function setup() {
  const rt = fakeTerm();
  const handlers = new Map();
  const ipcMain = { handle: (ch, fn) => { assert.ok(!handlers.has(ch), 'once: ' + ch); handlers.set(ch, fn); } };
  const wins = [];
  class FakeWindow extends EventEmitter {
    constructor(opts) {
      super();
      this.opts = opts;
      this.sent = [];
      this.destroyed = false;
      this.webContents = Object.assign(new EventEmitter(), { send: (c, p) => this.sent.push([c, p]), setWindowOpenHandler: (fn) => { this.openHandler = fn; } });
      wins.push(this);
    }
    loadFile(f) { this.file = f; return Promise.resolve(); }
    once(ev, fn) { if (ev === 'ready-to-show') fn(); else super.once(ev, fn); return this; }
    show() { this.shown = true; }
    focus() {}
    isMinimized() { return false; }
    restore() {}
    removeMenu() {}
    isDestroyed() { return this.destroyed; }
    close() { const e = { defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } }; this.emit('close', e); if (!e.defaultPrevented) { this.destroyed = true; this.emit('closed'); } }
    destroy() { this.destroyed = true; this.emit('closed'); }
  }
  const data = new Map();
  const store = { get: (k, d) => (data.has(k) ? data.get(k) : d), set: (k, v) => data.set(k, v) };
  const mainSent = [];
  const mainWin = { webContents: { send: (c, p) => mainSent.push([c, p]) }, isDestroyed: () => false };
  let clip = 'line one\nline two';
  const clipboard = { readText: () => clip, writeText: (x) => { clip = x; } };
  const term = setupTerminal({ core: {}, term: rt, apiClient: {}, log: { warn() {}, info() {} }, store, t: (k) => `«${k}»`, BrowserWindow: FakeWindow,
    ipcMain, clipboard, preload: 'p.js', html: 'terminal.html', getMainWindow: () => mainWin, getTheme: () => 'light' });
  const fromWin = () => ({ sender: wins[wins.length - 1].webContents });
  const call = (ch, ...a) => handlers.get(ch)(fromWin(), ...a);
  return { rt, term, handlers, wins, store, mainSent, call, clipboard, getClip: () => clip };
}

test('open without a recording hint: a session, the window, sandboxed and without Node', async () => {
  const { rt, term, wins, call, mainSent } = setup();
  const r = await term.channels['remote-term:open']({}, { deviceId: 2, deviceName: 'pi-werkstatt', tmux: { attach: 'tmux' }, recording: 'off', record: true });
  assert.equal(r.session.id, 'term_1');
  assert.deepEqual(rt.calls[0], ['open', { deviceId: 2, deviceName: 'pi-werkstatt', tmux: { attach: 'tmux' }, recording: 'off', record: true, cols: 100, rows: 28 }]);
  assert.equal(wins.length, 1);
  const wp = wins[0].opts.webPreferences;
  assert.deepEqual([wp.contextIsolation, wp.sandbox, wp.nodeIntegration], [true, true, false]);
  assert.equal(wins[0].file, 'terminal.html');
  assert.deepEqual(wins[0].openHandler(), { action: 'deny' });
  const init = await call('term:ready');
  assert.equal(init.theme, 'light');
  assert.equal(init.sessions.length, 1);
  assert.equal(init.texts.hkTrust, '«terminal.hkTrust»');
  assert.equal(init.texts.errors.shell_refused, '«terminal.errors.shell_refused»');
  assert.equal(init.fontPx, 14);
  rt.emit('status', { id: 'term_1', state: 'ready' });
  assert.ok(wins[0].sent.some(([c, p]) => c === 'term:status' && p.state === 'ready'));
  assert.ok(mainSent.some(([c]) => c === 'remote-term:sessions'));
  rt.emit('data', { id: 'term_1', data: new Uint8Array([104, 105]) });
  assert.ok(wins[0].sent.some(([c]) => c === 'term:data'));
});

test('the window\'s channels: only from the window; input, resize, trust, font, clipboard', async () => {
  const { rt, term, handlers, call, store, getClip } = setup();
  await term.channels['remote-term:open']({}, { deviceId: 2, recording: 'off' });
  await call('term:ready');
  await assert.rejects(async () => handlers.get('term:input')({ sender: {} }, 'term_1', 'x'), /not the terminal window/);
  assert.equal(await call('term:input', 'term_1', 'ls\r'), true);
  assert.equal(await call('term:input', 'term_1', 42), false);
  await call('term:resize', 'term_1', 90, 25);
  await call('term:trust', 'term_1', true);
  assert.deepEqual(rt.calls.slice(1), [['input', 'term_1', 'ls\r'], ['resize', 'term_1', 90, 25], ['trust', 'term_1', true]]);
  assert.equal(await call('term:font', 30), 14, 'out of range: kept');
  assert.equal(await call('term:font', 18), 18);
  assert.equal(store.get('terminal.fontPx'), 18);
  assert.equal(await call('term:clip-read'), 'line one\nline two');
  await call('term:clip-write', 'copied');
  assert.equal(getClip(), 'copied');
  await call('term:ask-paste', false);
  assert.equal(store.get('terminal.askPaste'), false);
});

test('a recorded start: the hint in the window first, record: true only after „Verstanden, verbinden“', async () => {
  const { rt, term, wins, call } = setup();
  const r = await term.channels['remote-term:open']({}, { deviceId: 2, deviceName: 'pi', recording: 'always' });
  assert.match(r.pending, /^pending_/);
  assert.equal(rt.calls.length, 0, 'no ticket before the hint');
  const init = await call('term:ready');
  assert.deepEqual(init.pending, [{ pendingId: r.pending, deviceName: 'pi', always: true }]);
  assert.equal(await call('term:confirm', r.pending, false), null);
  assert.equal(rt.calls.length, 0, 'cancelled: nothing');
  const again = await term.channels['remote-term:open']({}, { deviceId: 2, deviceName: 'pi', recording: 'optional', record: true });
  const ok = await call('term:confirm', again.pending, true);
  assert.equal(ok.session.id, 'term_1');
  assert.equal(rt.calls[0][1].record, true);
  // a refusal after the hint reaches the window as a code
  const bad = await term.channels['remote-term:open']({}, { deviceId: 7, recording: 'always' });
  assert.deepEqual(await call('term:confirm', bad.pending, true), { error: 'recording_unavailable' });
  assert.equal(wins.length, 1);
});

test('closing the window with running sessions asks first; bad input; errors as codes', async () => {
  const { rt, term, wins, call } = setup();
  await term.channels['remote-term:open']({}, { deviceId: 2, recording: 'off' });
  await call('term:ready');
  wins[0].close();
  assert.equal(wins[0].destroyed, false);
  assert.deepEqual(wins[0].sent.find(([c]) => c === 'term:closing')[1], { count: 1 });
  await call('term:close-all');
  assert.equal(wins[0].destroyed, true);
  assert.ok(rt.calls.some(([c]) => c === 'closeAll'));
  assert.deepEqual(await term.channels['remote-term:open']({}, { deviceId: 'x' }), { error: 'invalid' });
  assert.deepEqual(await term.channels['remote-term:open']({}, { deviceId: 2, tmux: { attach: 'a.b' } }), { error: 'invalid' });
  assert.deepEqual(await term.channels['remote-term:tmux']({}, 9), { error: 'host_key_mismatch' });
  assert.equal((await term.channels['remote-term:devices']()).devices.length, 1);
});

test('every text of the window exists in German and English', () => {
  for (const lang of ['de', 'en']) {
    const d = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'src', 'i18n', `${lang}.json`), 'utf8'));
    for (const k of TEXT_KEYS) assert.equal(typeof d.terminal[k], 'string', `${lang} terminal.${k}`);
    for (const k of ERROR_KEYS) assert.equal(typeof d.terminal.errors[k], 'string', `${lang} terminal.errors.${k}`);
    assert.equal(d.ui.nav.remote, lang === 'de' ? 'Fernzugriff' : 'Remote access');
  }
});

test('terminal window: CSP default-src self, xterm 5.5.0 from the app package', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', 'terminal.html'), 'utf8');
  assert.match(html, /content="default-src 'self'"/);
  assert.doesNotMatch(html, /https?:\/\//);
  assert.doesNotMatch(html, /<script>(?!<\/script>)/, 'no inline script');
  const x = fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', 'vendor', 'xterm', 'xterm.js'), 'utf8');
  assert.ok(x.length > 200000 && !/sourceMappingURL/.test(x));
});

const T = {
  connected: 'Verbunden', connecting: 'Verbinde …', reconnecting: 'Verbinde neu …', offline: 'Keine Verbindung', ended: 'Beendet', viewOnly: 'Nur ansehen',
  connectingTo: 'Verbinde mit {{ name }} …', lostTitle: 'Verbindung unterbrochen', lostText: 'Neuer Versuch in {{ s }} s ({{ n }} von 5).',
  tmuxKeeps: 'tmux „{{ tmux }}“ läuft weiter.', tryNow: 'Jetzt versuchen', disconnect: 'Trennen', reconnect: 'Neu verbinden', closeTab: 'Tab schließen',
  offlineTitle: 'Keine Verbindung zu {{ name }}', offlineText: 'Fünf Versuche ohne Erfolg.', offlineTmux: 'x', exitTitle: 'Sitzung beendet',
  exitAdmin: 'Ein Administrator hat die Sitzung beendet.', exitTmux: 'tmux beendet', exitShell: 'Shell beendet', exitLost: 'abgerissen',
  errors: { shell_refused: 'Das Gerät hat die Shell abgelehnt.', auth: 'Anmeldung fehlgeschlagen.', other: 'Fehler ({{ code }})', limit: 'Zu viele' },
};

test('terminal state: overlays, tones, texts', () => {
  const base = { id: 'a', deviceName: 'pi', tmux: 'tmux', cols: 118, rows: 28 };
  assert.equal(TS.overlay({ ...base, state: 'connecting', attempt: 0 }, T).text, 'Verbinde mit pi …');
  const lost = TS.overlay({ ...base, state: 'reconnecting', attempt: 3, at: 4000 }, T, 0);
  assert.equal(lost.text, 'Neuer Versuch in 4 s (3 von 5). tmux „tmux“ läuft weiter.');
  assert.deepEqual(lost.actions.map((a) => a.act), ['disconnect', 'try']);
  const admin = TS.overlay({ ...base, state: 'exited', reason: 'ended_by_plugin' }, T);
  assert.equal(admin.text, T.exitAdmin);
  assert.deepEqual(admin.actions.map((a) => a.act), ['close'], 'no reconnect after an administrator ended it');
  assert.deepEqual(TS.overlay({ ...base, state: 'exited', reason: 'closed' }, T).actions.map((a) => a.act), ['close', 'reconnect']);
  assert.equal(TS.overlay({ ...base, state: 'failed', code: 'shell_refused', verdict: 'final' }, T).text, T.errors.shell_refused);
  assert.equal(TS.overlay({ ...base, state: 'failed', code: 'auth_failed', verdict: 'final' }, T).text, T.errors.auth);
  assert.equal(TS.overlay({ ...base, state: 'failed', code: 'weird', verdict: 'final' }, T).text, 'Fehler (weird)');
  assert.deepEqual(TS.overlay({ ...base, state: 'failed', code: 'host_key_mismatch', verdict: 'locked' }, T), { kind: 'locked' });
  assert.equal(TS.overlay({ ...base, state: 'ready' }, T), null);
  assert.equal(TS.tone({ state: 'ready' }), 'ok');
  assert.equal(TS.tone({ state: 'reconnecting' }), 'warn');
  assert.equal(TS.tone({ state: 'failed', verdict: 'locked' }), 'err');
  assert.equal(TS.meta({ ...base }), 'tmux: tmux · 118×28');
  assert.equal(TS.tabLabel(base), 'pi · tmux');
  assert.equal(TS.stateText({ state: 'ready', view: true }, T), 'Nur ansehen');
  assert.equal(TS.canType({ state: 'ready' }), true);
  assert.equal(TS.canType({ state: 'reconnecting' }), false);
});

test('pasting: lines, control characters, the font range', () => {
  assert.equal(TS.pasteLines('ls -la\n'), 1);
  assert.equal(TS.pasteLines('a\r\nb\nc'), 3);
  assert.equal(TS.pasteText('a\nb\u001b[201~c\u0007'), 'a\rb[201~c');
  assert.equal(TS.clampFont(40), 28);
  assert.equal(TS.clampFont(3), 9);
});

test('details of an SSH device: choices, preselection, the button, what is opened', () => {
  const dev = { id: 2, name: 'pi-werkstatt', tmux: 'tmux', recording: 'optional', native: true };
  const list = { sessions: [{ name: 'tmux', windows: 3, attached: 0, activity: 2 }, { name: 'build', windows: 1, attached: 1, activity: 1 }], hidden: 1, tmux: 'tmux', hostKey: 'pinned' };
  const c = RTS.choices(dev, { list }, false);
  assert.deepEqual(c.options.map((o) => o.key), ['resume:tmux', 'resume:build', 'default', 'new']);
  assert.equal(c.options[3].suggestion, 'tmux-2');
  assert.equal(c.hidden, 1);
  assert.equal(RTS.initialPick(c), 'resume:tmux');
  assert.equal(RTS.buttonKey(c, 'resume:tmux'), 'remoteTerm.resumeBtn');
  assert.equal(RTS.buttonKey(c, 'default'), 'remoteTerm.connect');
  assert.deepEqual(RTS.openParams(dev, 'resume:build', null, true), { deviceId: 2, deviceName: 'pi-werkstatt', tmux: { attach: 'build' }, recording: 'optional', record: true });
  assert.equal(RTS.openParams(dev, 'new', 'bad name', false), null);
  assert.deepEqual(RTS.openParams(dev, 'new', 'tmux-2', false).tmux, { create: 'tmux-2' });
  assert.equal(RTS.openParams(dev, 'default', null, false).tmux, null);
  assert.equal(RTS.choices(dev, { list: { sessions: [], hostKey: 'unpinned', tmux: 'tmux' } }).notice, 'first');
  assert.deepEqual(RTS.choices(dev, { error: 'tmux_unavailable' }).options.map((o) => o.key), ['plain']);
  assert.equal(RTS.buttonKey(RTS.choices(dev, { error: 'tmux_unavailable' }), 'plain'), 'remoteTerm.anyway');
  assert.equal(RTS.choices(dev, { error: 'host_key_mismatch' }).kind, 'locked');
  assert.equal(RTS.choices(dev, {}, true).kind, 'locked');
  assert.deepEqual(RTS.choices({ ...dev, tmux: null }, null).options.map((o) => o.key), ['plain']);
  assert.equal(RTS.choices(dev, { loading: true }).kind, 'loading');
  assert.equal(RTS.minutesAgo(Date.now() - 120000), 2);
});
