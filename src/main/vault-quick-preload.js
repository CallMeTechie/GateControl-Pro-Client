/**
 * GateControl -- preload of the Vault quick search window (Strg+Alt+P)
 *
 * Exposes only what the window needs (window.gcQuick): Vault status, unlock
 * (master password, Windows Hello or the kept sign-in), the list of entries (titles, user
 * names, web addresses — no secrets), copy through main (cleared after 30 s),
 * 2FA codes, opening a website (http/https, checked in main), activity and
 * hiding the window. Texts: the app's vault.* strings (core i18n).
 */

const { contextBridge, ipcRenderer } = require('electron');
const i18n = require('@gatecontrol/client-core/src/i18n');

i18n.registerTranslations('de', require('../i18n/de.json'));
i18n.registerTranslations('en', require('../i18n/en.json'));

const invoke = (channel, arg) => ipcRenderer.invoke(channel, arg);

contextBridge.exposeInMainWorld('gcQuick', {
  status: () => invoke('vault:status'),
  unlock: (password) => invoke('vault:unlock', { password }),
  unlockRemembered: () => invoke('vault:unlockRemembered'),
  // Windows Hello through the quick search's main side (the window steps back for the dialog)
  unlockHello: () => invoke('vault-quick:hello'),
  entries: () => invoke('vault:entries', {}),
  copy: (id, field) => invoke('vault:copy', { id, field }),
  totp: (id) => invoke('vault:totp', { id }),
  touch: () => invoke('vault:touch'),
  openUrl: (url) => invoke('shell:open-external', url),
  hide: () => ipcRenderer.send('vault-quick:hide'),
  onShow: (cb) => {
    ipcRenderer.on('vault-quick:show', (_e, p) => {
      const payload = p && typeof p === 'object' ? p : {};
      if (payload.locale) i18n.setLocale(payload.locale);
      cb({ theme: payload.theme === 'light' ? 'light' : 'dark', locale: i18n.getLocale() });
    });
  },
  onHide: (cb) => { ipcRenderer.on('vault-quick:hide', () => cb()); },
  t: (key, params) => i18n.t(key, params),
});
