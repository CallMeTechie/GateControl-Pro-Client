/**
 * GateControl -- preload of the bar at the top while "Bildschirm teilen" runs (./screen-bar.js)
 *
 * Exposes only the state of the session (who, view or control, since when; texts resolved by the main process) and
 * the two buttons "Nur ansehen" and "Beenden" (window.gcBar).
 */

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('gcBar', {
  onState: (cb) => { ipcRenderer.on('screen-bar:state', (_e, s) => cb(s)); ipcRenderer.send('screen-bar:ready'); },
  stop: () => ipcRenderer.send('screen-bar:stop'),
  viewOnly: () => ipcRenderer.send('screen-bar:view-only'),
});
