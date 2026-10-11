'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey, openSettingsTab } = require('./support/ui');

// Notification center: push stream from the mock server → "Mitteilungen"
// (nav badge, list, detail, actions, read sync), Settings → Benachrichtigungen
// and the tray entries. Texts are matched in both languages (the app follows
// the system locale of the runner).

const TOPICS = [
  { id: 'security', label: 'Sicherheit' },
  { id: 'devices', label: 'Geräte & Gateways' },
  { id: 'admin_notice', label: 'Hinweise vom Admin' },
  { id: 'plugin:skoda:charging', label: 'Fahrzeug · Laden abgeschlossen' },
];

const GATEWAY_OFFLINE = {
  id: 45,
  topic: 'devices',
  priority: 'critical',
  title: 'Gateway „Zuhause“ ist offline',
  body: 'Seit 2 Minuten kommt kein Lebenszeichen vom Gateway.',
  collapse_key: 'gateway:3',
  data: {
    route: 'gateways',
    facts: [{ label: 'Letztes Lebenszeichen', value: '21:40' }, { label: 'Betroffene Routen', value: 6 }],
    actions: [
      { id: 'details', label: 'Details', type: 'open_app_route', target: 'services' },
      { id: 'mute_1h', label: '1 h stumm', type: 'mute_1h' },
    ],
  },
};

const INBOX_UNREAD = /^(Mitteilungen · 1 neu|Notifications · 1 new)$/;

test.describe('notification center', () => {
  test('a push message shows up in the inbox, the badge and the tray; reading syncs back', async ({ launchApp, mock }) => {
    mock.setPush({ topics: TOPICS, items: [GATEWAY_OFFLINE] });
    const { page, trayLabels } = await launchApp();
    await setupWithApiKey(page, mock);

    // server:setup restarts the stream; hello + the queued message arrive
    await expect(page.locator('#inbox-badge')).toHaveText('1');
    await expect.poll(trayLabels).toContainEqual(expect.stringMatching(INBOX_UNREAD));
    await expect.poll(() => mock.acks().some((a) => a.state === 'delivered')).toBe(true);

    await page.locator('#nav-inbox').click();
    await expect(page.locator('#page-inbox')).toHaveClass(/active/);
    const rows = page.locator('#inbox-list .inbox-row');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toHaveClass(/unread/);
    await expect(page.locator('#inbox-filters .fchip')).toHaveCount(3); // all, unread, devices

    await rows.first().click();
    await expect(page.locator('#inbox-detail .inbox-detail-title')).toHaveText('Gateway „Zuhause“ ist offline');
    await expect(page.locator('#inbox-detail .chip')).toHaveText(/Geräte & Gateways/);
    // two facts from the server + "Empfangen … · direkt über HTTPS"
    await expect(page.locator('#inbox-detail .info-card')).toHaveCount(3);
    await expect(page.locator('#inbox-detail .inbox-actions .btn')).toHaveText(['Details', '1 h stumm']);

    // opening marks it read here and on the server (other devices follow)
    await expect.poll(() => mock.acks().some((a) => a.state === 'read' && a.seqs.length === 1)).toBe(true);
    await expect(page.locator('#inbox-badge')).toBeHidden();
    await expect.poll(trayLabels).not.toContainEqual(expect.stringMatching(INBOX_UNREAD));

    // action button: local mute + ack with the action id
    await page.locator('#inbox-detail [data-action="mute_1h"]').click();
    await expect.poll(() => mock.acks().some((a) => a.action === 'mute_1h')).toBe(true);
  });

  test('new messages while open, filters and "Alle gelesen"', async ({ launchApp, mock }) => {
    mock.setPush({ topics: TOPICS, items: [] });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.pushStreams()).toBe(1);

    await page.locator('#nav-inbox').click();
    await expect(page.locator('#inbox-empty')).toBeVisible();

    mock.pushNotification({ topic: 'security', priority: 'high', title: '4 IPs durch WAF gesperrt' });
    mock.pushNotification({ topic: 'admin_notice', priority: 'normal', title: 'Wartung heute Abend' });
    await expect(page.locator('#inbox-list .inbox-row')).toHaveCount(2);
    await expect(page.locator('#inbox-badge')).toHaveText('2');

    await page.locator('#inbox-filters [data-filter="security"]').click();
    await expect(page.locator('#inbox-list .inbox-row')).toHaveCount(1);
    await expect(page.locator('#inbox-list .inbox-row-title')).toHaveText('4 IPs durch WAF gesperrt');
    await page.locator('#inbox-filters [data-filter="all"]').click();

    await page.locator('#inbox-read-all').click();
    await expect(page.locator('#inbox-badge')).toBeHidden();
    await expect(page.locator('#inbox-list .inbox-row.unread')).toHaveCount(0);
    await expect.poll(() => mock.acks().some((a) => a.state === 'read' && a.seqs.length === 2)).toBe(true);

    await page.locator('#inbox-filters [data-filter="unread"]').click();
    await expect(page.locator('#inbox-empty')).toBeVisible();
  });

  test('settings tab: status, topics, test message, switching off', async ({ launchApp, mock }) => {
    mock.setPush({ topics: TOPICS, items: [] });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.pushStreams()).toBe(1);

    await openSettingsTab(page, 'notify');
    await expect(page.locator('#notify-state')).toHaveClass(/ok/);
    await expect(page.locator('#notify-state-label')).toHaveText(/Empfangsbereit|Ready to receive/);
    await expect(page.locator('#notify-server')).toHaveText(new URL(mock.url).host);
    await expect(page.locator('#notify-via')).toHaveText(/direkt über HTTPS|directly via HTTPS/);
    await expect(page.locator('#notify-enabled')).toHaveAttribute('aria-checked', 'true');
    await expect(page.locator('#notify-ks-note')).toBeHidden();

    // topics of the server; switching one off goes to the server prefs
    const topic = page.locator('#notify-topics [data-topic="plugin:skoda:charging"]');
    await expect(page.locator('#notify-topics .sw')).toHaveCount(4);
    await topic.click();
    await expect(topic).toHaveAttribute('aria-checked', 'false');
    await expect.poll(() => mock.pushPrefs().some((p) => (p.muted_topics || []).includes('plugin:skoda:charging'))).toBe(true);

    // "Testnachricht anfordern" → server sends one → inbox
    await page.locator('#notify-test').click();
    await expect(page.locator('#notify-test-status')).toHaveClass(/success/);
    await expect(page.locator('#inbox-badge')).toHaveText('1');
    expect(mock.count('/api/v1/client/push/test')).toBe(1);

    // switching off closes the stream and the inbox explains it calmly
    await page.locator('#notify-enabled').click();
    await expect(page.locator('#notify-enabled')).toHaveAttribute('aria-checked', 'false');
    await expect(page.locator('#notify-direct')).toBeDisabled();
    await expect(page.locator('#notify-state-label')).toHaveText(/^(Aus|Off)$/);
    await expect.poll(() => mock.pushStreams()).toBe(0);
  });

  test('an old server without push: calm hints, nothing breaks', async ({ launchApp, mock }) => {
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.count('/api/v1/client/push')).toBeGreaterThanOrEqual(1);

    await page.locator('#nav-inbox').click();
    await expect(page.locator('#inbox-empty')).toBeVisible();
    await expect(page.locator('#inbox-empty-hint')).toHaveText(/unterstützt noch keine Benachrichtigungen|does not support notifications yet/);
    await expect(page.locator('#inbox-badge')).toBeHidden();

    await openSettingsTab(page, 'notify');
    await expect(page.locator('#notify-state-label')).toHaveText(/^(Aus|Off)$/);
    await expect(page.locator('#notify-reason')).toBeVisible();
    await expect(page.locator('#notify-test')).toBeDisabled();
  });

  test('tray: "Nicht stören für 1 Stunde" and "Mitteilungen" open the inbox', async ({ launchApp, mock }) => {
    mock.setPush({ topics: TOPICS, items: [] });
    const { page, trayLabels, clickTrayItem } = await launchApp();
    await setupWithApiKey(page, mock);

    await expect.poll(trayLabels).toContainEqual(expect.stringMatching(/^(Nicht stören für 1 Stunde|Do not disturb for 1 hour)$/));
    expect(await clickTrayItem('^(Nicht stören für 1 Stunde|Do not disturb for 1 hour)$')).toBe(true);
    await expect.poll(trayLabels).toContainEqual(expect.stringMatching(/^(Nicht stören beenden|End do not disturb)$/));
    await openSettingsTab(page, 'notify');
    await expect(page.locator('#notify-dnd-text')).toHaveText(/Nicht stören bis|Do not disturb until/);

    expect(await clickTrayItem('^(Mitteilungen|Notifications)')).toBe(true);
    await expect(page.locator('#page-inbox')).toHaveClass(/active/);
  });

  test('server with control events: quiet hours, pushed policy change and support request', async ({ launchApp, mock }) => {
    mock.setPolicy({ killSwitch: 'user', autoConnect: 'user', autostart: 'user', lockSettings: false, lockServer: false });
    mock.setPush({
      topics: TOPICS, items: [],
      quiet: { from: '22:00', to: '07:00', tz: 'Europe/Berlin', critical_bypass: true },
      state: { policy_version: 'e2e0000000000001', peer_enabled: true, support_bundle_requested: false, support_bundle_requested_at: null, config_hash: null },
    });
    const { page, answerDialogs, dialogs } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.pushStreams()).toBe(1);

    // Settings → Benachrichtigungen shows the quiet hours of the server (read-only)
    await openSettingsTab(page, 'notify');
    await expect(page.locator('#notify-quiet-value')).toHaveText(/22:00 – 07:00.*Europe\/Berlin/);
    await expect(page.locator('#notify-quiet-detail')).toHaveText(/Kritische Meldungen kommen trotzdem|Critical messages still sound/);

    // policy_changed: fetched right away (the poll would wait 30 min now)
    await expect.poll(() => mock.count('/api/v1/client/policy')).toBeGreaterThanOrEqual(1);
    const before = mock.count('/api/v1/client/policy');
    mock.setPolicy({ killSwitch: 'required', autoConnect: 'user', autostart: 'user', lockSettings: false, lockServer: false }, 'e2e0000000000002');
    mock.pushControl({ type: 'policy_changed', policy_version: 'e2e0000000000002' });
    await expect.poll(() => mock.count('/api/v1/client/policy')).toBeGreaterThan(before);
    await openSettingsTab(page, 'sec');
    await expect(page.locator('#killswitch-toggle')).toBeDisabled();

    // support_bundle_requested: the same confirmation as for an admin request, once per request
    await answerDialogs([0]);
    mock.pushControl({ type: 'support_bundle_requested', requested_at: '2026-10-11 10:00:00' });
    await expect.poll(() => mock.count('/api/v1/client/support-bundle')).toBe(1);
    mock.pushControl({ type: 'support_bundle_requested', requested_at: '2026-10-11 10:00:00' });
    await page.waitForTimeout(1000);
    expect((await dialogs()).length).toBe(1);
    expect(mock.count('/api/v1/client/support-bundle')).toBe(1);
  });

  test('server with quiet hours but without control events: quiet hours shown, nothing else changes', async ({ launchApp, mock }) => {
    mock.setPush({ topics: TOPICS, items: [], quiet: null });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.pushStreams()).toBe(1);
    await openSettingsTab(page, 'notify');
    await expect(page.locator('#notify-quiet-value')).toHaveText(/Keine Ruhezeiten eingestellt|No quiet hours set/);
    await expect(page.locator('#notify-quiet-detail')).toBeHidden();
    await expect(page.locator('#notify-quiet-portal')).toBeDisabled(); // no portal URL without the VPN
  });
});
