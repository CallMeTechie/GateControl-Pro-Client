'use strict';

const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// GateDrop 1.5 on the page "GateDrop" (the plugin is the core's fake GateDrop server, support/gatedrop-mock.js):
//   - Gesendet: "bereitgestellt" (provided, not picked up yet), "empfangen" / "abgeholt" with `pickedAt`,
//     "vom Admin entfernt" instead of "abgelaufen", "nicht alle Dateien angekommen" (error `incomplete`);
//   - "Empfangenes bleibt … auf dem Server" from the administrator's retention (`limits.retention`);
//   - an older plugin (no pickedAt, no retention): "zugestellt", 7 days — as before;
//   - a send received through a push is acknowledged (POST sends/<id>/opened) as soon as it is saved.
// Texts in both languages.

const HOUR = 3600000;
const iso = (ms) => new Date(ms).toISOString();

/** A send of GET inbox?kind=sent as the plugin answers it. */
function sentSend(id, name, deliveries, extra = {}) {
  const at = Date.now() - HOUR;
  return {
    id, role: 'sent', createdAt: iso(at), expiresAt: iso(at + 14 * 24 * HOUR), expired: false,
    from: { userId: 2, name: 'Marc', deviceId: '42', deviceName: 'Laptop', own: true },
    text: null, link: null, note: null,
    items: [{ index: 0, mediaId: null, name, mime: 'application/pdf', bytes: 2048, local: false, available: false }],
    deliveries, ...extra,
  };
}
const delivery = (id, kind, target, label, status, via, extra = {}) => ({ id, kind, target, label, status, via, at: iso(Date.now() - HOUR), error: null, openedAt: null, ...extra });

async function openGateDrop(page) {
  await expect(page.locator('#nav-gatedrop')).toBeVisible();
  await page.locator('#nav-gatedrop').click();
  await expect(page.locator('#page-gatedrop')).toHaveClass(/active/);
  return page.locator('#page-gatedrop');
}

async function openSent(root) {
  await root.locator('.gd-tabs [data-tab="sent"]').click();
  await expect(root.locator('.gd-list .gd-row').first()).toBeVisible();
}

const chips = (root, id) => root.locator(`.gd-row[data-id="${id}"] .gd-st`);

test.describe('GateDrop 1.5', () => {
  test('Gesendet: bereitgestellt / empfangen / abgeholt, vom Admin entfernt, nicht alle Dateien; retention of the admin', async ({ launchApp, mock }) => {
    const g = await mock.setGateDrop({ version: '1.5.0' });
    Object.assign(g.srv.state.targets.limits, { retentionDays: 14, retention: { afterPickupDays: 1, unpickedDays: 14 } });
    const now = Date.now();
    g.srv.state.inbox.sent = [
      sentSend('a'.repeat(24), 'Angebot.pdf', [
        delivery(1, 'device', '43', 'Pixel', 'delivered', 'server', { pickedAt: null }),
        delivery(2, 'person', '8', 'Anna', 'delivered', 'server', { pickedAt: iso(now - 600000) }),
      ]),
      sentSend('b'.repeat(24), 'Video.mp4', [delivery(3, 'device', '44', 'Tablet', 'delivered', 'direct', { pickedAt: iso(now - 300000) })]),
      sentSend('c'.repeat(24), 'Alt.zip', [delivery(4, 'device', '43', 'Pixel', 'expired', null, { error: 'removed', pickedAt: null })],
        { expired: true, removed: true, removedAt: iso(now - 120000), pickedAt: null }),
      sentSend('d'.repeat(24), 'Fotos.zip', [delivery(5, 'device', '45', 'Surface', 'failed', null, { error: 'incomplete', pickedAt: null })]),
    ];
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openGateDrop(page);

    await expect(root.locator('.gd-retention')).toHaveText(/Empfangenes bleibt nach der Abholung 1 Tag, sonst 14 Tage auf dem Server\.|Received items stay on the server for 1 day after they are picked up, otherwise for 14 days\./);

    await openSent(root);
    await expect(chips(root, 'a'.repeat(24))).toHaveText([
      /^Pixel: (bereitgestellt · über den Server|provided · through the server)$/,
      /^Anna: (abgeholt · über den Server|picked up · through the server)$/,
    ]);
    await expect(chips(root, 'b'.repeat(24))).toHaveText([/^Tablet: (empfangen · direkt im WLAN|received · directly over Wi-Fi)$/]);
    await expect(chips(root, 'c'.repeat(24))).toHaveText([/^Pixel: (vom Admin entfernt|removed by the admin)$/]);
    await expect(root.locator(`.gd-row[data-id="${'c'.repeat(24)}"] .gd-row-meta`)).toHaveText(/^(Vom Admin entfernt|Removed by the admin) · /);
    await expect(chips(root, 'd'.repeat(24))).toHaveText([/^Surface: (fehlgeschlagen – nicht alle Dateien angekommen|failed – not all files arrived)$/]);
    await page.screenshot({ path: test.info().outputPath('gatedrop-sent-15.png') });
  });

  test('an older plugin (no pickedAt, no retention): "zugestellt" and 7 days as before', async ({ launchApp, mock }) => {
    const g = await mock.setGateDrop({ version: '1.4.1' });
    g.srv.state.inbox.sent = [sentSend('e'.repeat(24), 'Plan.pdf', [delivery(1, 'device', '43', 'Pixel', 'delivered', 'server'), delivery(2, 'device', '44', 'Tablet', 'expired', null)])];
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openGateDrop(page);
    await expect(root.locator('.gd-retention')).toHaveText(/Empfangenes bleibt 7 Tage auf dem Server\.|Received items stay on the server for 7 days\./);
    await openSent(root);
    await expect(chips(root, 'e'.repeat(24))).toHaveText([
      /^Pixel: (zugestellt · über den Server|delivered · through the server)$/,
      /^Tablet: (abgelaufen|expired)$/,
    ]);
  });

  test('a send received through a push is acknowledged as soon as it is saved (not only by GET pending)', async ({ launchApp, mock }, testInfo) => {
    mock.setPush({ topics: [{ id: 'plugin:gatecontrol-gatedrop:received', label: 'GateDrop · Empfangen' }], items: [] });
    const g = await mock.setGateDrop({ version: '1.5.0' });
    const { page, answerOpenDialogs } = await launchApp();
    await setupWithApiKey(page, mock);
    const root = await openGateDrop(page);

    // received files go to a folder of the test ("Speicherort für empfangene Dateien")
    const folder = testInfo.outputPath('empfangen');
    fs.mkdirSync(folder, { recursive: true });
    await answerOpenDialogs([folder]);
    await root.locator('.gd-side-acts .btn', { hasText: /^(Ändern …|Change …)$/ }).click();
    await expect(root.locator('.gd-side-sub', { hasText: folder })).toBeVisible();

    // the start's GET pending is done (nothing waits) and the push stream is open
    await expect.poll(() => g.srv.state.pendingCalls).toBeGreaterThan(0);
    await expect.poll(() => mock.pushStreams()).toBeGreaterThan(0);
    const polls = g.srv.state.pendingCalls;

    const send = g.srv.addSend({ from: { name: 'Anna' }, items: [{ name: 'Einkauf.txt', data: Buffer.from('Milch, Brot') }] }, { pending: true });
    mock.pushNotification({ topic: 'plugin:gatecontrol-gatedrop:received', title: 'Anna hat dir eine Datei geschickt', body: 'Einkauf.txt', data: { gatedrop: { send: send.id } } });

    await expect.poll(() => g.srv.state.opened).toContain(send.id);
    expect(fs.readFileSync(path.join(folder, 'Einkauf.txt'), 'utf8')).toBe('Milch, Brot');
    expect(g.srv.state.pendingCalls, 'acknowledged by the push path, not by a later GET pending').toBe(polls);
    // the plugin now has it picked up: the sender's view says "empfangen"
    const own = g.srv.view(g.srv.state.sends.get(send.id), 'sent').deliveries[0];
    expect(own.status).toBe('opened');
    expect(own.pickedAt).toBeTruthy();
  });
});
