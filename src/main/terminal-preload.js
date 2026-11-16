/**
 * GateControl -- preload of the SSH terminal window (./terminal.js)
 *
 * Exposes only the terminal's channels (window.gcTerm): its bytes and states, what is typed, the size, the answers
 * to the host key and the recording hint, the font size, the clipboard. No Node, no other channel.
 */

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

const on = (ch, cb) => ipcRenderer.on(ch, (_e, payload) => cb(payload));

contextBridge.exposeInMainWorld('gcTerm', {
  ready: () => ipcRenderer.invoke('term:ready'),
  input: (id, data) => ipcRenderer.invoke('term:input', id, data),
  resize: (id, cols, rows) => ipcRenderer.invoke('term:resize', id, cols, rows),
  trust: (id, yes) => ipcRenderer.invoke('term:trust', id, yes === true),
  reconnect: (id) => ipcRenderer.invoke('term:reconnect', id),
  close: (id) => ipcRenderer.invoke('term:close', id),
  closeAll: () => ipcRenderer.invoke('term:close-all'),
  confirm: (pendingId, yes) => ipcRenderer.invoke('term:confirm', pendingId, yes === true),
  font: (px) => ipcRenderer.invoke('term:font', px),
  askPaste: (on) => ipcRenderer.invoke('term:ask-paste', on === true),
  clipRead: () => ipcRenderer.invoke('term:clip-read'),
  clipWrite: (text) => ipcRenderer.invoke('term:clip-write', text),
  select: (id) => ipcRenderer.invoke('term:select', id),
  add: () => ipcRenderer.invoke('term:add'),
  onStatus: (cb) => on('term:status', cb),
  onData: (cb) => on('term:data', cb),
  onPending: (cb) => on('term:pending', cb),
  onClosing: (cb) => on('term:closing', cb),
  onFocus: (cb) => on('term:focus', cb),
});
