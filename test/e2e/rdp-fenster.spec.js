'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey, openSettingsTab } = require('./support/ui');

// Remotedesktop im GateControl-Fenster — the app's side with a fake gc-rdp-host (support/rdp-host-fake.js: the
// line protocol of rdp-host/Program.cs, no window, no RDP control) and a recorded Windows-Remotedesktop way
// (no .rdp launch, no cmdkey):
//   - "Verbinden" opens the window by default: the host started without arguments, the credentials only in its
//     connect message, "Fenster anzeigen" and the sidebar ("im Fenster"), the audit start / end;
//   - the arrow at "Verbinden": both ways, "Mit Windows-Remotedesktop öffnen";
//   - Settings → Anwendung „Remotedesktop öffnen in“ (standard GateControl-Fenster) and per host „Öffnen in“;
//   - „Auf diesem PC“: what the server does not permit is locked, switching off reaches the next connect;
//   - the window's error view: plain text, „Erneut verbinden“ (same window), „Mit Windows-Remotedesktop öffnen“;
//   - fallback to Windows-Remotedesktop: the host does not start, a RemoteApp route.
// The server's routes: gateway routes to the mock (no tunnel, its port answers the TCP check). Made-up names.

const ROUTES = [
  { id: 7, name: 'Buchhaltung-PC', host: '10.0.0.21', port: 3389, access_mode: 'gateway', credential_mode: 'full', resolution_mode: 'dynamic',
    redirect_clipboard: 1, redirect_drives: 0, redirect_printers: 0, multi_monitor: 0, audio_mode: 'local', nla_enabled: 1, tags: '[]' },
  { id: 8, name: 'Werkstatt-Server', host: '10.0.0.22', port: 3389, access_mode: 'gateway', credential_mode: 'full', resolution_mode: 'fullscreen',
    redirect_clipboard: 1, redirect_drives: 1, multi_monitor: 1, audio_mode: 'local', nla_enabled: 1, remote_app: '||notepad', tags: '[]' },
];

const fake = (app) => app.evaluate(() => {
  const f = globalThis.__gcE2E.rdpHostFake;
  return { spawns: f.spawns, received: f.received, mstsc: f.mstsc, stored: f.stored, children: f.children.map((c) => ({ pid: c.pid, exited: c.exited })) };
});
const events = (app, type) => app.evaluate((t) => globalThis.__gcE2E.events.filter((e) => e.type === t), type);

async function openRemote(page, id) {
  await page.evaluate(() => window.gatecontrol.locale.set('de'));
  await page.locator('#nav-rdp').click();
  await expect(page.locator('#page-rdp')).toHaveClass(/active/);
  await page.locator(`#rdp-list [data-rdp="${id}"]`).click();
  await expect(page.locator('#rdp-detail .rdp-detail-name')).toHaveText(ROUTES.find((r) => r.id === id).name);
}

test.describe('Remotedesktop im GateControl-Fenster', () => {
  test('Verbinden opens the window: credentials only over stdin, Fenster anzeigen, sidebar, audit', async ({ launchApp, mock }) => {
    const rdp = mock.setRdp({ routes: ROUTES });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await openRemote(page, 7);

    await page.locator('#rdp-connect').click();
    await expect.poll(async () => (await fake(app)).received.filter((m) => m.type === 'connect').length).toBe(1);
    const f = await fake(app);
    expect(f.spawns).toHaveLength(1);
    expect(f.spawns[0].args).toEqual([]);
    expect(JSON.stringify(f.spawns)).not.toContain('e2e-pass-1');
    const connect = f.received.find((m) => m.type === 'connect');
    expect(connect.password).toBe('e2e-pass-1');
    expect(connect.username).toBe('anna');
    expect(connect.name).toBe('Buchhaltung-PC');
    expect(connect.redirect.drives).toBe(false);
    expect(connect.allow).toEqual({ clipboard: true, drives: false });
    expect(connect.texts.retry).toBe('Erneut verbinden');
    expect(f.mstsc).toHaveLength(0);
    expect(f.stored).toHaveLength(0);
    expect(await events(app, 'mstsc.launch')).toHaveLength(0);
    await expect.poll(() => rdp.sessions.filter((s) => s.op === 'start').length).toBe(1);

    // the dialog closes by itself, the window does the rest
    await expect(page.locator('#rdp-dialog')).toBeHidden();
    const show = page.locator('#rdp-show-window');
    await expect(show).toBeVisible();
    await expect(page.locator('#side-sessions-list')).toContainText('im Fenster');
    await page.screenshot({ path: test.info().outputPath('fenster-sitzung-aktiv.png') });
    await show.click();
    await expect.poll(async () => (await fake(app)).received.filter((m) => m.type === 'focus').length).toBe(1);

    // "Verbinden" again: the same window to the front, no second one
    await page.locator('#rdp-connect').click();
    await expect.poll(async () => (await fake(app)).received.filter((m) => m.type === 'focus').length).toBe(2);
    expect((await fake(app)).spawns).toHaveLength(1);

    // the person disconnects in the window: the session ends, audit "normal"
    await app.evaluate(() => globalThis.__gcE2E.rdpHostFake.disconnect(1, 0, true));
    await expect(page.locator('#rdp-show-window')).toHaveCount(0);
    await expect.poll(() => rdp.sessions.find((s) => s.op === 'end')?.endReason).toBe('normal');
  });

  test('menu at Verbinden, the setting „Remotedesktop öffnen in“, per host „Öffnen in“', async ({ launchApp, mock }) => {
    mock.setRdp({ routes: ROUTES });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await openRemote(page, 7);

    // the menu: both ways, the window marked as the standard
    await page.locator('#rdp-connect-more').click();
    const menu = page.locator('#rdp-connect-menu');
    await expect(menu).toBeVisible();
    await expect(menu.locator('[data-via="window"]')).toContainText('Im GateControl-Fenster');
    await expect(menu.locator('[data-via="window"]')).toContainText('Standard');
    await expect(menu.locator('[data-via="window"]')).toHaveClass(/hl/);
    await expect(menu.locator('[data-via="mstsc"]')).toContainText('Mit Windows-Remotedesktop öffnen');
    await page.screenshot({ path: test.info().outputPath('verbinden-menue.png') });
    await menu.locator('[data-via="mstsc"]').click();
    await expect.poll(async () => (await fake(app)).mstsc.length).toBe(1);
    expect((await fake(app)).spawns).toHaveLength(0);
    expect((await fake(app)).stored.length).toBeGreaterThan(0); // the previous way: cmdkey (recorded)
    await app.evaluate(() => globalThis.__gcE2E.rdpHostFake.endMstsc());
    await expect(page.locator('#rdp-dialog')).toBeHidden();

    // Settings → Anwendung: standard GateControl-Fenster, switched to Windows-Remotedesktop
    await openSettingsTab(page, 'app');
    const seg = page.locator('#rdp-openin-seg');
    await expect(seg.locator('[data-open-in="window"]')).toHaveAttribute('aria-pressed', 'true');
    await seg.locator('[data-open-in="mstsc"]').click();
    await expect(seg.locator('[data-open-in="mstsc"]')).toHaveAttribute('aria-pressed', 'true');
    await page.locator('#rdp-openin-row').screenshot({ path: test.info().outputPath('einstellung-oeffnen-in.png') });

    await openRemote(page, 7);
    await page.locator('#rdp-connect').click();
    await expect.poll(async () => (await fake(app)).mstsc.length).toBe(2);
    expect((await fake(app)).spawns).toHaveLength(0);
    await app.evaluate(() => globalThis.__gcE2E.rdpHostFake.endMstsc());
    await expect(page.locator('#rdp-dialog')).toBeHidden();

    // per host: „Öffnen in: Fenster“ wins over the setting
    const card = page.locator('#rdp-local');
    await card.locator('[data-seg="open"] [data-v="window"]').click();
    await expect(card.locator('[data-seg="open"] [data-v="window"]')).toHaveClass(/on/);
    await page.locator('#rdp-connect').click();
    await expect.poll(async () => (await fake(app)).spawns.length).toBe(1);
    expect((await fake(app)).mstsc).toHaveLength(2);
  });

  test('„Auf diesem PC“: locked where the server does not permit, a switched-off clipboard reaches the connect', async ({ launchApp, mock }) => {
    mock.setRdp({ routes: ROUTES });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await openRemote(page, 7);

    const card = page.locator('#rdp-local');
    await expect(card).toContainText('Auf diesem PC');
    const drives = card.locator('[data-switch="drives"]');
    await expect(drives).toBeDisabled();
    await expect(card.locator('[data-local="drives"]')).toContainText('Vom Administrator nicht freigegeben');
    await expect(card.locator('[data-seg="display"] [data-v="multimon"]')).toBeDisabled();
    const clip = card.locator('[data-switch="clipboard"]');
    await expect(clip).toHaveAttribute('aria-checked', 'true');
    await card.screenshot({ path: test.info().outputPath('auf-diesem-pc.png') });

    // the main process refuses a widening, too
    const widened = await page.evaluate(() => window.gatecontrol.rdp.localSet(7, { drives: true, display: 'multimon' }));
    expect(widened).toEqual({});

    await clip.click();
    await expect(clip).toHaveAttribute('aria-checked', 'false');
    await card.locator('[data-seg="keyboard"] [data-v="always"]').click();
    await expect(card.locator('[data-seg="keyboard"] [data-v="always"]')).toHaveClass(/on/);
    await page.locator('#rdp-connect').click();
    await expect.poll(async () => (await fake(app)).received.filter((m) => m.type === 'connect').length).toBe(1);
    const connect = (await fake(app)).received.find((m) => m.type === 'connect');
    expect(connect.redirect.clipboard).toBe(false);
    expect(connect.keyboard).toBe('always');
    expect(connect.allow.clipboard).toBe(true);
  });

  test('error view of the window: plain text, Erneut verbinden in the same window, Windows-Remotedesktop', async ({ launchApp, mock }) => {
    const rdp = mock.setRdp({ routes: ROUTES });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await openRemote(page, 7);

    await page.locator('#rdp-connect').click();
    await expect(page.locator('#rdp-show-window')).toBeVisible();

    // the server ends the session (someone else signed in): plain text for the window, audit "replaced"
    await app.evaluate(() => globalThis.__gcE2E.rdpHostFake.disconnect(3, 5, false));
    await expect.poll(async () => (await fake(app)).received.filter((m) => m.type === 'explain').length).toBe(1);
    const explain = (await fake(app)).received.find((m) => m.type === 'explain');
    expect(explain.title).toBe('Die Sitzung wurde vom Remote-PC beendet');
    expect(explain.text).toContain('jemand anderes angemeldet');
    await expect.poll(() => rdp.sessions.find((s) => s.op === 'end')?.endReason).toBe('replaced');
    await expect(page.locator('#rdp-show-window')).toHaveCount(0);

    // „Erneut verbinden“: the app connects again (fresh credentials), in the same window
    await app.evaluate(() => globalThis.__gcE2E.rdpHostFake.action('reconnect'));
    await expect.poll(async () => (await fake(app)).received.filter((m) => m.type === 'connect').length).toBe(2);
    expect((await fake(app)).spawns).toHaveLength(1);
    await expect(page.locator('#rdp-show-window')).toBeVisible();
    await expect.poll(() => rdp.sessions.filter((s) => s.op === 'start').length).toBe(2);

    // once more, then „Mit Windows-Remotedesktop öffnen“: the window closes, mstsc opens
    await app.evaluate(() => globalThis.__gcE2E.rdpHostFake.disconnect(3, 0, false));
    await expect(page.locator('#rdp-show-window')).toHaveCount(0);
    await app.evaluate(() => globalThis.__gcE2E.rdpHostFake.action('mstsc'));
    await expect.poll(async () => (await fake(app)).mstsc.length).toBe(1);
    await expect.poll(async () => (await fake(app)).children[0].exited).toBe(true);
  });

  test('fallback to Windows-Remotedesktop: the window does not start, a RemoteApp route', async ({ launchApp, mock }) => {
    mock.setRdp({ routes: ROUTES });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await openRemote(page, 7);

    await app.evaluate(() => { globalThis.__gcE2E.rdpHostFake.failStart = 'exit'; });
    await page.locator('#rdp-connect').click();
    await expect.poll(async () => (await fake(app)).mstsc.length).toBe(1);
    await expect(page.locator('#toasts')).toContainText('ließ sich nicht starten');
    await app.evaluate(() => globalThis.__gcE2E.rdpHostFake.endMstsc());
    await expect(page.locator('#rdp-dialog')).toBeHidden();

    // RemoteApp: Windows-Remotedesktop, the window's menu entry disabled
    await app.evaluate(() => { globalThis.__gcE2E.rdpHostFake.failStart = null; });
    await openRemote(page, 8);
    await page.locator('#rdp-connect-more').click();
    await expect(page.locator('#rdp-connect-menu [data-via="window"]')).toBeDisabled();
    await page.keyboard.press('Escape');
    await page.locator('#rdp-connect').click();
    await expect.poll(async () => (await fake(app)).mstsc.length).toBe(2);
    await expect(page.locator('#toasts')).toContainText('RemoteApp');
    expect((await fake(app)).spawns).toHaveLength(1); // only the failed start of the first part
  });
});
