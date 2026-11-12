'use strict';

const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// DNS-Schutz (the DNS filter of the VPN devices, plugin gatecontrol-dns,
// server from 1.264.0): the card on "Übersicht" and the tray entries exist
// only while GET permissions reports `vpnDns`; active with the durations the
// server allows, paused with the time left, "Wieder einschalten" and "+30
// Min.", the filter down with a Windows notification, pausing not allowed,
// a plugin in trouble and one that is switched off. Selectors by id / class /
// data attributes; texts in both languages.

// The pinned core (core.ref) may be older than the DNS protection: nothing to test then.
const coreDir = (() => {
  try { return path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [path.join(__dirname, '..', '..')] })); } catch { return null; }
})();
const HAS_CORE = !!coreDir && fs.existsSync(path.join(coreDir, 'src', 'services', 'dns-protect.js'));

const CARD = '#dns-protect';
const TOP = '#dns-protect-top';
const sent = (dns, method, route) => dns.log.filter((r) => r.method === method && r.route === route);
const refresh = (page) => page.evaluate(() => window.gatecontrol.dnsProtect.refresh());
const trayDns = async (app) => (await app.trayLabels()).filter((l) => /DNS/.test(l));
/** Labels (and "enabled") of the submenu of "DNS-Schutz unterbrechen". */
const submenu = (app) => app.app.evaluate(() => {
  const item = globalThis.__gcE2E.trayMenu.items.find((i) => i.submenu && /DNS/.test(i.label));
  return item ? item.submenu.items.filter((i) => i.type !== 'separator').map((i) => [i.label, i.enabled]) : null;
});
const clickSubmenu = (app, pattern) => app.app.evaluate((_e, p) => {
  const item = globalThis.__gcE2E.trayMenu.items.find((i) => i.submenu && /DNS/.test(i.label));
  const hit = item && item.submenu.items.find((i) => new RegExp(p).test(i.label));
  if (!hit) return false;
  hit.click();
  return true;
}, pattern);

async function open(launchApp, mock) {
  const launched = await launchApp();
  await setupWithApiKey(launched.page, mock);
  return launched;
}

test.describe('dns-schutz', () => {
  test.skip(!HAS_CORE, 'core without DNS-Schutz (core.ref before services/dns-protect.js)');

  test('a server without DNS protection: no card, no tray entry, no error', async ({ launchApp, mock }) => {
    // before 1.264.0: permissions has no `vpnDns` at all
    const old = await open(launchApp, mock);
    await expect.poll(() => mock.count('/api/v1/client/permissions')).toBeGreaterThan(0);
    await expect(old.page.locator(CARD)).toBeHidden();
    await expect(old.page.locator(TOP)).toBeHidden();
    expect(await trayDns(old)).toEqual([]);
    await expect(old.page.locator('.toast-error')).toHaveCount(0);
  });

  test('no plugin / switched off (`vpnDns: null`): no card, the plugin is not asked', async ({ launchApp, mock }) => {
    const dns = mock.setDns({ filter: null });
    const { page, trayLabels } = await open(launchApp, mock);
    await expect.poll(() => mock.count('/api/v1/client/permissions')).toBeGreaterThan(0);
    await expect(page.locator(CARD)).toBeHidden();
    expect((await trayLabels()).filter((l) => /DNS/.test(l))).toEqual([]);
    expect(dns.log).toEqual([]);
  });

  test('active: counters, the allowed durations, pause, "+30 Min.", "Wieder einschalten"', async ({ launchApp, mock }) => {
    const dns = mock.setDns();
    const { page } = await open(launchApp, mock);
    const card = page.locator(CARD);
    await expect(card).toBeVisible();
    await expect(card).toHaveAttribute('data-state', 'active');
    await expect(card.locator('.h-card')).toHaveText(/DNS-Schutz|DNS protection/);
    await expect(card.locator('.dnsp-t .desc')).toHaveText(/Werbung und Schadseiten werden gesperrt|Ads and malicious sites are blocked/);
    await expect(card.locator('[data-chip="active"]')).toHaveText(/^(aktiv|active)$/);
    await expect(card.locator('[data-kv="queries"] dd')).toHaveText(/^2[.,]106$/);
    await expect(card.locator('[data-kv="blocked"] dd')).toHaveText('318');
    await expect(card.locator('[data-kv="percent"] dd')).toHaveText(/^15[.,]1\s?%$/);
    // the plugin is asked in the app's language
    expect(['de', 'en']).toContain(sent(dns, 'GET', 'status')[0].lang);

    // 5 / 30 / 60 as the server offers them, no "4 Std.", "Bis ich wieder einschalte" greyed
    await expect(card.locator('[data-act^="pause-"]')).toHaveCount(4);
    for (const m of [5, 30, 60]) await expect(card.locator(`[data-act="pause-${m}"]`)).toBeEnabled();
    await expect(card.locator('[data-act="pause-forever"]')).toBeDisabled();
    await expect(card).toContainText(/hat dein Admin nicht freigegeben|Your admin has not enabled/);

    // next to it: the top blocked domains
    const top = page.locator(TOP);
    await expect(top).toBeVisible();
    await expect(top.locator('li')).toHaveCount(3);
    await expect(top.locator('li').first()).toHaveText(/googlesyndication\.com\s*74/);

    // pause for 30 minutes: one call, the card follows the answer
    await card.locator('[data-act="pause-30"]').click();
    await expect(card).toHaveAttribute('data-state', 'paused');
    expect(sent(dns, 'POST', 'pause').map((r) => r.body)).toEqual([{ minutes: 30 }]);
    await expect(card.locator('[data-chip="paused"]')).toHaveText(/^(unterbrochen|paused)·(29:5\d|30:00)$/);
    await expect(card.locator('.dnsp-t .desc')).toHaveText(/Unterbrochen bis \d\d:\d\d Uhr · schaltet sich von selbst ein|Paused until \d\d:\d\d · switches itself back on/);
    await expect(card.locator('[data-note="pause"]')).toHaveText(/Unterbrochen von dir um \d\d:\d\d für 30 Minuten\. Solange wird auf diesem Gerät nichts gesperrt\.|Paused by you at \d\d:\d\d for 30 minutes\. Nothing is blocked on this device meanwhile\./);
    await expect(page.locator('#toasts .toast-success')).toContainText(/DNS-Schutz unterbrochen|DNS protection paused/);
    // the time left counts down
    const first = await card.locator('.dnsp-cd [data-cd]').textContent();
    await expect.poll(() => card.locator('.dnsp-cd [data-cd]').textContent(), { timeout: 5000 }).not.toBe(first);

    // "+30 Min.": from the end of the running pause; a second one is longer than the server allows
    await card.locator('[data-act="extend"]').click();
    await expect(card.locator('[data-chip="paused"]')).toHaveText(/·(59:\d\d|1:00:00)$/);
    expect(sent(dns, 'POST', 'pause').at(-1).body).toEqual({ extend: 30 });
    await card.locator('[data-act="extend"]').click();
    await expect(page.locator('#toasts .toast-error')).toContainText('Länger als 60 Minuten ist nicht erlaubt.');
    await expect(card).toHaveAttribute('data-state', 'paused');

    // back on
    await card.locator('[data-act="resume"]').click();
    await expect(card).toHaveAttribute('data-state', 'active');
    expect(sent(dns, 'POST', 'resume')).toHaveLength(1);
    await expect(card.locator('[data-act="pause-30"]')).toBeEnabled();
  });

  test('keyboard: the buttons are reached by Tab and the focus stays on the card after a change', async ({ launchApp, mock }) => {
    mock.setDns();
    const { page } = await open(launchApp, mock);
    const card = page.locator(CARD);
    await card.locator('[data-act="pause-5"]').focus();
    await page.keyboard.press('Tab');
    await expect(card.locator('[data-act="pause-30"]')).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(card).toHaveAttribute('data-state', 'paused');
    expect(await page.evaluate(() => !!document.activeElement.closest('#dns-protect'))).toBe(true);
    await expect(card.locator('[data-act="resume"]')).toBeFocused();
  });

  test('tray: the state, "DNS-Schutz unterbrechen" with the durations, "wieder einschalten"', async ({ launchApp, mock }) => {
    const dns = mock.setDns();
    const launched = await open(launchApp, mock);
    const { page } = launched;
    await expect(page.locator(CARD)).toHaveAttribute('data-state', 'active');
    await expect.poll(() => trayDns(launched)).toEqual(expect.arrayContaining([expect.stringMatching(/^(DNS-Schutz: aktiv|DNS protection: active)$/), expect.stringMatching(/^(DNS-Schutz unterbrechen|Pause DNS protection)$/)]));
    expect(await trayDns(launched)).toHaveLength(2);
    const sub = await submenu(launched);
    expect(sub.map((x) => x[0])).toEqual([
      expect.stringMatching(/^5 (Minuten|minutes)$/), expect.stringMatching(/^30 (Minuten|minutes)$/), expect.stringMatching(/^1 (Stunde|hour)$/),
      expect.stringMatching(/^(Bis ich wieder einschalte|Until I switch it back on)$/),
    ]);
    expect(sub.map((x) => x[1])).toEqual([true, true, true, false]);

    // a duration from the tray: the card in the window follows
    expect(await clickSubmenu(launched, '^30 ')).toBe(true);
    await expect(page.locator(CARD)).toHaveAttribute('data-state', 'paused');
    expect(sent(dns, 'POST', 'pause').map((r) => r.body)).toEqual([{ minutes: 30 }]);
    await expect.poll(() => trayDns(launched)).toEqual([
      expect.stringMatching(/^(DNS-Schutz: unterbrochen bis|DNS protection: paused until) \d\d:\d\d$/),
      expect.stringMatching(/^(DNS-Schutz wieder einschalten|Switch DNS protection back on)$/),
    ]);
    expect(await launched.clickTrayItem('wieder einschalten|back on')).toBe(true);
    await expect(page.locator(CARD)).toHaveAttribute('data-state', 'active');
    await expect.poll(() => trayDns(launched)).toHaveLength(2);
  });

  test('an admin\'s server: "4 Std." and "Bis ich wieder einschalte" are offered', async ({ launchApp, mock }) => {
    const dns = mock.setDns({ may: { durations: [5, 30, 60, 240], maxMinutes: 10080, forever: true } });
    const launched = await open(launchApp, mock);
    const card = launched.page.locator(CARD);
    await expect(card.locator('[data-act^="pause-"]')).toHaveCount(5);
    await expect(card.locator('[data-act="pause-240"]')).toBeEnabled();
    expect((await submenu(launched)).map((x) => x[1])).toEqual([true, true, true, true, true]);
    await card.locator('[data-act="pause-forever"]').click();
    await expect(card).toHaveAttribute('data-state', 'paused');
    expect(sent(dns, 'POST', 'pause').at(-1).body).toEqual({ forever: true });
    // no end: no time left, no "+30 Min."
    await expect(card.locator('.dnsp-t .desc')).toHaveText(/Unterbrochen, bis du wieder einschaltest|Paused until you switch it back on/);
    await expect(card.locator('[data-cd]')).toHaveCount(0);
    await expect(card.locator('[data-act="extend"]')).toHaveCount(0);
    await expect(card.locator('[data-act="resume"]')).toBeVisible();
    await expect.poll(() => trayDns(launched)).toEqual([expect.stringMatching(/^(DNS-Schutz: unterbrochen|DNS protection: paused)$/), expect.stringMatching(/einschalten|back on/)]);
  });

  test('the filter fails: the warning, no buttons, one tray line and a Windows notification', async ({ launchApp, mock }) => {
    const dns = mock.setDns();
    const launched = await open(launchApp, mock);
    const { page, app } = launched;
    const card = page.locator(CARD);
    await expect(card).toHaveAttribute('data-state', 'active');

    dns.filter = 'fallback';
    await refresh(page);
    await expect(card).toHaveAttribute('data-state', 'fallback');
    await expect(card.locator('[data-chip="fallback"]')).toHaveText(/^(ungefiltert|unfiltered)$/);
    await expect(card.locator('.dnsp-t .desc')).toHaveText(/Ausgefallen seit \d\d:\d\d Uhr|Down since \d\d:\d\d/);
    await expect(card.locator('.banner-err')).toContainText(/Der Filter auf dem Server antwortet nicht\.|The filter on the server is not answering\./);
    await expect(card.locator('button')).toHaveCount(0);
    await expect(card.locator('[data-kv]')).toHaveCount(3);
    await expect.poll(() => trayDns(launched)).toEqual([expect.stringMatching(/^(DNS-Schutz: ausgefallen \(ungefiltert\)|DNS protection: down \(unfiltered\))$/)]);
    // announced once, by the app (the plugin tells only admins)
    const toasts = () => app.evaluate(() => globalThis.__gcE2E.toasts.map((x) => x.text).filter((x) => /Filter ausgefallen|filter down/.test(x)));
    await expect.poll(toasts).toHaveLength(1);
    await refresh(page);
    expect(await toasts()).toHaveLength(1);

    // it runs again: the card is back to normal
    dns.filter = 'filtering';
    await refresh(page);
    await expect(card).toHaveAttribute('data-state', 'active');
    await expect(card.locator('[data-act="pause-30"]')).toBeEnabled();
  });

  test('pausing not allowed: the state and the reason, no button, no tray entry to pause', async ({ launchApp, mock }) => {
    const dns = mock.setDns({ may: { reason: 'profile' } });
    const launched = await open(launchApp, mock);
    const card = launched.page.locator(CARD);
    await expect(card).toHaveAttribute('data-state', 'active');
    await expect(card.locator('.banner-info')).toContainText(/Unterbrechen nicht erlaubt\..*Für dein Profil hat der Admin das Unterbrechen gesperrt\.|Pausing is not allowed\..*The admin has locked pausing for your profile\./);
    await expect(card.locator('button')).toHaveCount(0);
    await expect.poll(() => trayDns(launched)).toEqual([expect.stringMatching(/^(DNS-Schutz: aktiv|DNS protection: active)$/)]);

    dns.may.reason = 'admins_only';
    await refresh(launched.page);
    await expect(card.locator('.banner-info')).toContainText(/Unterbrechen dürfen hier nur Admins\.|Only admins may pause here\./);
    await expect(card.locator('button')).toHaveCount(0);
  });

  test('a device with its own DNS server: "nicht gefiltert", nothing to pause', async ({ launchApp, mock }) => {
    mock.setDns({ device: { peerId: 21, name: 'Annas Laptop', platform: 'windows', state: 'ownDns', ownDns: '1.1.1.1' } });
    const launched = await open(launchApp, mock);
    const card = launched.page.locator(CARD);
    await expect(card).toHaveAttribute('data-state', 'unfiltered');
    await expect(card.locator('.dnsp-t .desc')).toContainText('1.1.1.1');
    await expect(card.locator('button')).toHaveCount(0);
    await expect(card.locator('[data-kv]')).toHaveCount(0);
    await expect(launched.page.locator(TOP)).toBeHidden();
    await expect.poll(() => trayDns(launched)).toHaveLength(1);
  });

  test('the plugin in trouble: the last state with a note; never reached: "nicht erreichbar" and "Erneut versuchen"', async ({ launchApp, mock }) => {
    const dns = mock.setDns();
    dns.fail = { status: 503, code: 'not_running' };
    const { page } = await open(launchApp, mock);
    const card = page.locator(CARD);
    await expect(card).toHaveAttribute('data-state', 'error');
    await expect(card.locator('.dnsp-t .desc')).toHaveText(/Der DNS-Schutz ist gerade nicht erreichbar\.|DNS protection cannot be reached right now\./);
    await expect(card.locator('[data-kv]')).toHaveCount(0);
    await expect(page.locator(TOP)).toBeHidden();

    dns.fail = null;
    await card.locator('[data-act="retry"]').click();
    await expect(card).toHaveAttribute('data-state', 'active');

    // trouble later: the card stays with what it showed, and says so
    dns.fail = { status: 502, code: 'plugin_error' };
    await refresh(page);
    await expect(card).toHaveAttribute('data-state', 'active');
    await expect(card).toContainText(/du siehst den zuletzt geladenen Stand|you are seeing the last loaded state/);
    // a change then fails with the app's own sentence, not a code
    await card.locator('[data-act="pause-5"]').click();
    await expect(page.locator('#toasts .toast-error')).toContainText(/Der Filter-Dienst antwortet gerade nicht|The filter service is not answering right now/);
    await expect(card).toHaveAttribute('data-state', 'active');
  });

  test('switched off while the app runs: the card and the tray entries go', async ({ launchApp, mock }) => {
    const dns = mock.setDns();
    const launched = await open(launchApp, mock);
    const card = launched.page.locator(CARD);
    await expect(card).toHaveAttribute('data-state', 'active');
    dns.filter = null; // permissions: vpnDns null; the plugin: 409 off
    await card.locator('[data-act="pause-5"]').click();
    await expect(card).toBeHidden();
    await expect(launched.page.locator(TOP)).toBeHidden();
    await expect.poll(() => trayDns(launched)).toEqual([]);
  });
});
