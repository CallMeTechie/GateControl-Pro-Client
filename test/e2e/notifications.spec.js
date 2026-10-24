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

const OVERVIEW_TOPICS = [
  ...TOPICS,
  { id: 'plugin:gatecontrol-skoda:trip', label: 'Fahrzeuge · Fahrt erfasst (Fahrtenbuch)' },
  { id: 'plugin:gatecontrol-door:door', label: 'Tür & Kamera · Tür & Schloss (offen, blockiert, Batterie, Nacht)' },
  { id: 'plugin:gatecontrol-synology:storage', label: 'NAS (Synology) · NAS-Speicher (beeinträchtigt, fast voll)' },
  { id: 'plugin:gatecontrol-gatedrop:received', label: 'GateDrop · Empfangen' },
  { id: 'plugin:gatecontrol-gatedrop:link', label: 'GateDrop · Link geladen' },
  { id: 'plugin:gatecontrol-schule:changes', label: 'Schule · Stundenplan-Änderungen' },
];

// Screenshots of the page (GC_E2E_SHOTS=<dir>).
const SHOTS = process.env.GC_E2E_SHOTS || null;
const shot = async (page, name) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` }); };

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
    // one source (System) with one topic: all sources + System, no topic below it
    await expect(page.locator('#inbox-source option')).toHaveCount(2);
    await expect(page.locator('#inbox-list .inbox-day-label')).toHaveText([/^(Heute|Today)$/]);

    await rows.first().click();
    await expect(page.locator('#inbox-detail .inbox-detail-title')).toHaveText('Gateway „Zuhause“ ist offline');
    await expect(page.locator('#inbox-detail .inbox-crumb')).toHaveText(/System.*Geräte & Gateways/);
    await expect(page.locator('#inbox-detail .inbox-crumb .chip')).toHaveText(/Kritisch|Critical/);
    // two facts from the server; "Empfangen: Heute, … · direkt über HTTPS" as a line
    await expect(page.locator('#inbox-detail .info-card')).toHaveCount(2);
    await expect(page.locator('#inbox-detail .inbox-when')).toHaveText(/(Empfangen|Received): (Heute|Today), \d\d:\d\d · (direkt über HTTPS|directly via HTTPS)/);
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

    await page.locator('#inbox-source').selectOption('topic:security');
    await expect(page.locator('#inbox-list .inbox-row')).toHaveCount(1);
    await expect(page.locator('#inbox-list .inbox-row-title')).toHaveText('4 IPs durch WAF gesperrt');
    await page.locator('#inbox-source').selectOption('');

    await page.locator('#inbox-read-all').click();
    await expect(page.locator('#inbox-badge')).toBeHidden();
    await expect(page.locator('#inbox-list .inbox-row.unread')).toHaveCount(0);
    await expect.poll(() => mock.acks().some((a) => a.state === 'read' && a.seqs.length === 2)).toBe(true);

    await page.locator('#inbox-read-seg [data-read="unread"]').click();
    await expect(page.locator('#inbox-empty')).toBeVisible();
    await page.locator('#inbox-empty-action').click(); // "Filter zurücksetzen"
    await expect(page.locator('#inbox-list .inbox-row')).toHaveCount(2);
  });

  test('overview: day groups, message text in the rows, source filter, keyboard, answer buttons', async ({ launchApp, mock }) => {
    const ago = (days, h, m) => { const d = new Date(); d.setDate(d.getDate() - days); d.setHours(h, m, 0, 0); return d.toISOString(); };
    const trip = (id, days, h, m, body) => ({
      id, topic: 'plugin:gatecontrol-skoda:trip', priority: 'info', title: 'Elroq: Fahrt erfasst', body, created_at: ago(days, h, m),
      data: { trip: { id }, actions: [
        { type: 'callback', id: 'private', label: 'Privat' },
        { type: 'callback', id: 'business', label: 'Geschäftlich' },
        { type: 'callback', id: 'commute', label: 'Arbeitsweg' },
      ] },
    });
    mock.setPush({ topics: OVERVIEW_TOPICS, items: [
      trip(301, 0, 0, 27, '7 km, 07:12–07:23 → Am Grenzgraben 8 – privat oder geschäftlich?'),
      { id: 302, topic: 'plugin:gatecontrol-door:door', priority: 'high', title: 'Haustür <b>offen</b>', body: 'Seit 10 Minuten offen – Schloss nicht verriegelt.', created_at: ago(0, 0, 20) },
      trip(303, 0, 0, 10, '12 km, 06:58–07:20 → Industriestraße 4 – privat oder geschäftlich? Ein sehr langer Zusatz, damit die Vorschau sicher gekürzt werden muss und nicht umbricht.'),
      { id: 304, topic: 'plugin:gatecontrol-synology:storage', priority: 'critical', title: 'Volume 1 fast voll', body: '92 % belegt (3,7 von 4 TB). Bitte Platz schaffen.', created_at: ago(1, 22, 41), data: { facts: [{ label: 'Belegt', value: '92 %' }, { label: 'Frei', value: '0,3 TB' }] } },
      { id: 305, topic: 'plugin:gatecontrol-gatedrop:received', title: 'Datei empfangen', body: 'Anna hat dir „Urlaub.zip“ geschickt (240 MB).', created_at: ago(1, 18, 10) },
      trip(306, 1, 17, 46, '23 km, 17:12–17:44 → Am Grenzgraben 8 – privat oder geschäftlich?'),
      { id: 307, topic: 'plugin:gatecontrol-schule:changes', title: 'Stundenplan geändert', body: 'Mia, Klasse 5b: 3. Stunde Mathe entfällt.', created_at: ago(1, 6, 30) },
      { id: 308, topic: 'security', priority: 'high', title: '4 IPs durch WAF gesperrt', body: 'Wiederholte Anmeldeversuche auf das Portal.', created_at: ago(3, 14, 3) },
      { id: 309, topic: 'plugin:gatecontrol-gatedrop:link', title: 'Link geladen', body: '„Fotos Sommer“ wurde heruntergeladen.', created_at: ago(9, 11, 0) },
    ] });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect(page.locator('#inbox-badge')).toHaveText('9');
    await page.locator('#nav-inbox').click();

    // grouped by day, newest first; the row shows the message itself
    const rows = page.locator('#inbox-list .inbox-row');
    await expect(rows).toHaveCount(9);
    await expect(page.locator('#inbox-list .inbox-day-label')).toHaveCount(4);
    await expect(page.locator('#inbox-list .inbox-day-label').nth(0)).toHaveText(/^(Heute|Today)$/);
    await expect(page.locator('#inbox-list .inbox-day-label').nth(1)).toHaveText(/^(Gestern|Yesterday)$/);
    await expect(rows.nth(0).locator('.inbox-row-body')).toHaveText(/^7 km, 07:12–07:23/);
    await expect(rows.nth(0).locator('.inbox-row-src')).toHaveText('Fahrzeuge');
    await expect(rows.nth(0).locator('.inbox-row-time')).toHaveText('00:27');
    await expect(rows.nth(1).locator('.inbox-row-title')).toHaveText('Haustür <b>offen</b>'); // text, never HTML
    await expect(page.locator('#inbox-list b')).toHaveCount(0);
    await expect(rows.nth(7).locator('.inbox-row-src')).toHaveText(/(Hoch|High) · Sicherheit/);

    // one "Quelle" select: System, the plugins, topics of GateDrop indented, unread counts
    const source = page.locator('#inbox-source');
    await expect(source.locator('option[value="src:plugin:gatecontrol-skoda"]')).toHaveText(/^Fahrzeuge · 3 (neu|new)$/);
    await expect(source.locator('option[value="topic:plugin:gatecontrol-gatedrop:link"]')).toHaveText(/Link geladen · 1 (neu|new)$/);
    await expect(source.locator('option[value="src:system"]')).toHaveText(/^System · 1 (neu|new)$/);

    // keyboard: the first entry, then down and up again (each one shown is read)
    await rows.nth(0).click();
    await expect(rows.nth(0)).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('ArrowDown');
    await expect(rows.nth(1)).toHaveAttribute('aria-selected', 'true');
    await expect(rows.nth(1)).toBeFocused();
    await expect(page.locator('#inbox-detail .inbox-detail-title')).toHaveText('Haustür <b>offen</b>');
    await page.keyboard.press('ArrowUp');
    await expect(rows.nth(0)).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#inbox-badge')).toHaveText('7');
    await expect(page.locator('#inbox-list .inbox-row.unread')).toHaveCount(7);

    // detail: Quelle › Thema, text, the answer buttons of the Fahrtenbuch
    await expect(page.locator('#inbox-detail .inbox-crumb')).toHaveText(/Fahrzeuge\s*›\s*Fahrt erfasst \(Fahrtenbuch\)/);
    await expect(page.locator('#inbox-detail .inbox-body')).toHaveText(/Am Grenzgraben 8/);
    await expect(page.locator('#inbox-detail .inbox-actions .btn')).toHaveText(['Privat', 'Geschäftlich', 'Arbeitsweg']);

    // screenshots: wide and the minimum width, dark and light
    const setTheme = (th) => page.evaluate((x) => { if (x === 'light') document.documentElement.setAttribute('data-theme', 'light'); else document.documentElement.removeAttribute('data-theme'); }, th);
    const setSize = (w, h) => app.evaluate(({ BrowserWindow }, s) => { const win = BrowserWindow.getAllWindows()[0]; win.unmaximize(); win.setSize(s.w, s.h); }, { w, h });
    const noOverflow = () => page.evaluate(() => [...document.querySelectorAll('#page-inbox, #page-inbox .rdp-list-col, #page-inbox .inbox-list-col, #inbox-list, #inbox-detail, .inbox-tools')]
      .every((n) => n.scrollWidth <= n.clientWidth + 1));
    for (const [w, h, name] of [[1440, 900, 'wide'], [1000, 680, 'narrow']]) {
      await setSize(w, h);
      await expect.poll(() => page.evaluate(() => window.innerWidth)).toBeLessThanOrEqual(w);
      expect(await noOverflow()).toBe(true);
      for (const th of ['dark', 'light']) {
        await setTheme(th);
        await shot(page, `mitteilungen-${name}-${th}`);
      }
    }
    await setTheme('dark');

    // an answer: acked with its id, marked here
    await page.locator('#inbox-detail [data-action="business"]').click();
    await expect.poll(() => mock.acks().some((a) => a.action === 'business')).toBe(true);
    await expect(page.locator('#inbox-detail [data-action="business"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('#inbox-detail .inbox-answered')).toHaveText(/(Deine Antwort|Your answer): Geschäftlich/);

    // filters: unread × Fahrzeuge; kept when coming back and after a reload (this session)
    await page.locator('#inbox-read-seg [data-read="unread"]').click();
    await source.selectOption('src:plugin:gatecontrol-skoda');
    await expect(rows).toHaveCount(2);
    await expect(page.locator('#inbox-list .inbox-row-body').first()).toHaveText(/^12 km/);
    await shot(page, 'mitteilungen-narrow-filter-dark');
    await page.locator('#nav-logs').click();
    await page.locator('#nav-inbox').click();
    await expect(rows).toHaveCount(2);
    await page.reload();
    await page.locator('#nav-inbox').click();
    await expect(page.locator('#inbox-source')).toHaveValue('src:plugin:gatecontrol-skoda');
    await expect(page.locator('#inbox-read-seg [data-read="unread"]')).toHaveClass(/on/);
    await expect(rows).toHaveCount(2);
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
