'use strict';

const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Familie (plugin gatecontrol-familie, "Internet zu Hause"): the entry only
// for members of a family; parents see a card per child in its states
// (Internet an, pausiert, heute länger, nicht gefiltert) with the dialogs
// "Pausieren" and "Heute länger" and the note "Pausiert von der Regel …";
// "Regeln" as a list with the dialog of the action "Internet zu Hause" (the
// other actions of a rule stay); "Meine Anwesenheit" with "WLAN-Erkennung
// verwenden" and one's own devices; a child sees its own card, read only.
// Selectors by id/class; texts in both languages.

// Wednesday, 11 November 2026, 17:52 in Berlin
const NOW = Date.parse('2026-11-11T16:52:10Z');
const at = (hhmm, day = 11) => `2026-11-${String(day).padStart(2, '0')}T${hhmm}:00Z`;

const SCHEDULE = { from: at('20:00'), to: at('06:00', 12), block: 'categories', categories: ['social', 'games', 'video'], active: false };

function children() {
  return [
    {
      userId: 4, name: 'Lea', avatarUrl: null, color: 'amber', colorHex: '#EAB308', initials: 'LE',
      presence: { state: 'home', since: at('15:40'), source: 'wifi' },
      paused: null, pausedBy: null, extended: null, extendedBy: null,
      nextSchedule: { ...SCHEDULE }, profile: 'Kinder', devices: 2, filtered: true, error: null,
    },
    {
      userId: 5, name: 'Tim', avatarUrl: null, color: 'orange', colorHex: '#F97316', initials: 'TI',
      presence: { state: 'home', since: at('16:05'), source: 'app' },
      paused: at('17:30'), pausedBy: { userId: 2, name: 'Anna', at: at('16:30'), rule: { id: 12, title: 'Abendessen <b>' } },
      extended: null, extendedBy: null, nextSchedule: null, profile: 'Kinder', devices: 2, filtered: true, error: null,
    },
    {
      userId: 6, name: 'Mia', avatarUrl: null, color: 'pink', colorHex: '#EC4899', initials: 'MI',
      presence: { state: 'away', since: at('14:10'), source: 'app' },
      paused: null, pausedBy: null, extended: at('20:30'), extendedBy: { userId: 3, name: 'Marc', at: at('15:50'), rule: null },
      nextSchedule: { ...SCHEDULE, block: 'all', categories: [] }, profile: 'Kleine', devices: 1, filtered: true, error: null,
    },
    {
      userId: 7, name: 'Ben', avatarUrl: null, color: 'violet', colorHex: '#A855F7', initials: 'BE',
      presence: { state: 'not_shared', since: null, source: null },
      paused: null, pausedBy: null, extended: null, extendedBy: null, nextSchedule: null, profile: null, devices: 0, filtered: false, error: null,
    },
  ];
}

const KIDS = [
  { userId: 4, name: 'Lea', avatarUrl: null, color: 'amber', colorHex: '#EAB308', initials: 'LE' },
  { userId: 5, name: 'Tim', avatarUrl: null, color: 'orange', colorHex: '#F97316', initials: 'TI' },
  { userId: 6, name: 'Mia', avatarUrl: null, color: 'pink', colorHex: '#EC4899', initials: 'MI' },
];

function familieData(over = {}) {
  return {
    me: { userId: 2, name: 'Anna', role: 'parent' },
    modules: { rules: true, presence: true },
    internet: { available: true, manage: true, children: children() },
    rules: [
      {
        id: 12, title: 'Abendessen <b>', scope: 'house', active: true, kind: 'reminder', trigger: { type: 'schedule', weekdays: [1, 2, 3, 4, 5, 6, 7], time: '18:00' },
        conditions: { time: null, afterSunset: false, device: [], calendar: null },
        actions: [
          { type: 'internet', op: 'pause', userId: 5, minutes: 30 },
          { type: 'quick_action', plugin: 'gatecontrol-smarthome', id: 'lamp.kitchen', actionId: 'gatecontrol-smarthome/lamp.kitchen', title: 'Küchenlicht', state: 'on', kind: 'toggle', verb: 'Einschalten', available: true, needsTarget: false },
          { type: 'internet', op: 'pause', userId: 4, until: '18:30' },
          { type: 'notify', to: [5, 4], text: 'Abendessen ist fertig', facts: false, buttons: [] },
        ],
        ownerId: 2, ownerName: 'Anna', editable: true, pausable: true,
      },
      {
        id: 13, title: 'Mia kommt heim', scope: 'house', active: true, kind: 'presence', trigger: { type: 'person_home', userId: 6 },
        actions: [{ type: 'internet', op: 'resume', userId: 6 }], ownerId: 3, ownerName: 'Marc', editable: true, pausable: true,
      },
      {
        id: 14, title: 'Schlafenszeit Jonas', scope: 'house', active: false, kind: 'reminder', trigger: { type: 'schedule', weekdays: [1, 2, 3, 4, 5], time: '20:00' },
        actions: [{ type: 'internet', op: 'pause', userId: 9, name: 'Jonas', minutes: 60 }], ownerId: 2, ownerName: 'Anna', editable: true, pausable: true,
      },
    ],
    options: {
      people: [{ userId: 2, name: 'Anna', role: 'parent' }, { userId: 3, name: 'Marc', role: 'parent' }, ...KIDS.map((k) => ({ userId: k.userId, name: k.name, role: 'child' }))],
      internet: { available: true, reason: null, children: KIDS },
    },
    presence: {
      members: [{ userId: 2, name: 'Anna', role: 'parent', state: 'home', home: true, since: at('15:40'), source: 'wifi' }],
      me: { share: true, places: false, wifi: true },
    },
    wifi: {
      available: true, consent: true, since: at('09:12', 1),
      devices: [
        { id: 41, name: 'Annas Handy', lastSeen: at('16:50'), counts: true, gateway: 'Pi Keller' },
        { id: 42, name: 'Annas Laptop', lastSeen: at('11:03'), counts: false, gateway: 'Pi Keller' },
      ],
    },
    ...over,
  };
}

function setFamilie(mock, over) {
  const fam = mock.setFamilie(familieData(over));
  fam.clock = NOW;
  return fam;
}

async function openFamilie(page, mock) {
  await setupWithApiKey(page, mock);
  await expect(page.locator('#nav-familie')).toBeVisible();
  await page.locator('#nav-familie').click();
  await expect(page.locator('#page-familie')).toHaveClass(/active/);
  return page.locator('#page-familie');
}

const card = (root, id) => root.locator(`.fv-card[data-child="${id}"]`);
const sent = (fam, method, route) => fam.log.filter((r) => r.method === method && r.route === route);

test.describe('familie', () => {
  test('no Familie plugin, or not a member of a family: no "Familie" entry', async ({ launchApp, mock }) => {
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.count('/api/v1/client/plugins')).toBeGreaterThan(0);
    await expect(page.locator('#nav-familie')).toBeHidden();
  });

  test('the plugin is there but the person is no member: no entry, no error', async ({ launchApp, mock }) => {
    const fam = setFamilie(mock, { me: null });
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => sent(fam, 'GET', 'me').length).toBeGreaterThan(0);
    await expect(page.locator('#nav-familie')).toBeHidden();
    await expect(page.locator('.toast-error')).toHaveCount(0);
  });

  test('parents: the cards in their states, "Pausieren", "Heute länger", "Fortsetzen"', async ({ launchApp, mock }) => {
    const fam = setFamilie(mock);
    const { page } = await launchApp();
    const root = await openFamilie(page, mock);

    // between "Schule" and "GateDrop"; three tabs
    await expect(page.locator('#nav-schule + #nav-familie + #nav-gatedrop')).toHaveCount(1);
    await expect(root.locator('.fv-tabs button')).toHaveCount(3);
    await expect(root.locator('.fv-sub').first()).toContainText('Anna');
    await expect(root.locator('.fv-card')).toHaveCount(4);

    // Lea: Internet an, zu Hause · WLAN, the next blocked time and the number of devices
    const lea = card(root, 4);
    await expect(lea).toHaveClass(/is-normal/);
    await expect(lea.locator('.fv-chip.is-ok')).toHaveText(/^(Internet an|Internet on)$/);
    await expect(lea.locator('.fv-chip.is-mute')).toHaveText(/WLAN|Wi-Fi/);
    await expect(lea.locator('.fv-kid .fv-sub')).toContainText('21:00');
    await expect(lea.locator('.fv-kid .fv-sub')).toContainText(/2 (Geräte|devices)/);
    await expect(lea.locator('.fv-btns .btn')).toHaveCount(2);

    // Tim: paused by a rule — the note names the rule, its owner and the time; server text stays text
    const tim = card(root, 5);
    await expect(tim).toHaveClass(/is-paused/);
    await expect(tim.locator('.fv-chip.is-warn')).toContainText('18:30');
    await expect(tim.locator('.fv-note b')).toContainText('Abendessen <b>');
    await expect(tim.locator('.fv-note')).toContainText('Anna');
    await expect(tim.locator('.fv-note')).toContainText('17:30');
    await expect(tim.locator('.fv-btns .btn')).toHaveCount(2);
    await expect(tim.locator('.fv-btns .btn-pri')).toHaveCount(1);

    // Mia: longer today, away; Ben: not filtered, no buttons, no presence
    const mia = card(root, 6);
    await expect(mia).toHaveClass(/is-extended/);
    await expect(mia.locator('.fv-chip.is-info')).toContainText('21:30');
    await expect(mia.locator('.fv-kid .fv-sub')).toContainText('Marc');
    await expect(mia.locator('.fv-btns .btn')).toHaveCount(3);
    const ben = card(root, 7);
    await expect(ben).toHaveClass(/is-unfiltered/);
    await expect(ben.locator('.fv-chip')).toHaveCount(1);
    await expect(ben.locator('.fv-btns')).toHaveCount(0);
    await expect(root.locator('.fv-foot')).toBeVisible();
    await page.screenshot({ path: test.info().outputPath('familie-01-uebersicht.png') });

    // "Pausieren" for Lea: the dialog, "bis Uhrzeit" shows the time field; Escape closes and gives the focus back
    const pauseBtn = lea.locator('[data-k="pause-4"]');
    await pauseBtn.click();
    const dlg = root.locator('.fv-dlg');
    await expect(dlg).toBeVisible();
    await expect(dlg.locator('.fv-opt')).toHaveCount(4);
    await expect(dlg.locator('.fv-opt[aria-pressed="true"]')).toBeFocused();
    await expect(dlg.locator('.fv-dlg-hint')).toContainText('18:22');
    await dlg.locator('.fv-opt').nth(3).click();
    await expect(dlg.locator('input[type="time"]')).toHaveValue('18:30');
    await dlg.locator('input[type="time"]').fill('19:00');
    await expect(dlg.locator('.fv-dlg-hint')).toContainText('19:00');
    await expect(dlg.locator('.fv-dlg-hint')).toContainText('Lea');
    await page.screenshot({ path: test.info().outputPath('familie-02-dialog-pausieren.png') });
    await page.keyboard.press('Escape');
    await expect(dlg).toBeHidden();
    await expect(pauseBtn).toBeFocused();
    expect(sent(fam, 'POST', 'internet/4/pause')).toHaveLength(0);

    // 30 minutes with the keyboard: Enter on the button, Tab stays inside the dialog
    await page.keyboard.press('Enter');
    await expect(dlg).toBeVisible();
    await page.keyboard.press('Shift+Tab');
    await expect(dlg.locator('[data-k="submit"]')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(dlg.locator('.fv-opt').first()).toBeFocused();
    await dlg.locator('[data-k="submit"]').click();
    await expect(dlg).toBeHidden();
    await expect(lea).toHaveClass(/is-paused/);
    await expect(lea.locator('.fv-chip.is-warn')).toContainText('18:22');
    expect(sent(fam, 'POST', 'internet/4/pause').at(-1).body).toEqual({ minutes: 30 });
    // by hand: the person, no rule note
    await expect(lea.locator('.fv-note')).toHaveCount(0);
    await expect(lea.locator('.fv-kid .fv-sub')).toContainText('Anna');

    // "+30 Min." and "Fortsetzen"
    await lea.locator('[data-k="add30-4"]').click();
    await expect(lea.locator('.fv-chip.is-warn')).toContainText('18:52');
    expect(sent(fam, 'POST', 'internet/4/pause').at(-1).body).toEqual({ add: 30 });
    await lea.locator('[data-k="resume-4"]').click();
    await expect(lea).toHaveClass(/is-normal/);
    expect(sent(fam, 'POST', 'internet/4/resume')).toHaveLength(1);

    // "Heute länger": counts from the start of the blocked time (21:00) or from now
    await lea.locator('[data-k="extend-4"]').click();
    await expect(dlg.locator('.fv-opts')).toHaveCount(2);
    await expect(dlg.locator('.fv-opts').nth(1).locator('.fv-opt').first()).toContainText('21:00');
    await expect(dlg.locator('.fv-dlg-hint')).toContainText('21:30');
    await page.screenshot({ path: test.info().outputPath('familie-03-dialog-heute-laenger.png') });
    await dlg.locator('.fv-opts').nth(1).locator('.fv-opt').nth(1).click();
    await expect(dlg.locator('.fv-dlg-hint')).toContainText('18:22');
    await dlg.locator('.fv-opts').nth(1).locator('.fv-opt').first().click();
    await dlg.locator('[data-k="submit"]').click();
    await expect(lea).toHaveClass(/is-extended/);
    await expect(lea.locator('.fv-chip.is-info')).toContainText('21:30');
    expect(sent(fam, 'POST', 'internet/4/extend').at(-1).body).toEqual({ minutes: 30 });

    // extra time: "+30 Min." and "Extra-Zeit beenden"
    await lea.locator('[data-k="extend30-4"]').click();
    await expect(lea.locator('.fv-chip.is-info')).toContainText('22:00');
    await lea.locator('[data-k="endExtra-4"]').click();
    await expect(lea).toHaveClass(/is-normal/);
    expect(sent(fam, 'POST', 'internet/4/extend').at(-1).body).toEqual({ minutes: 0 });

    // a refusal is told, the card stays
    fam.internet.available = false;
    await card(root, 5).locator('[data-k="resume-5"]').click();
    await expect(page.locator('.toast-error')).toBeVisible();
  });

  test('rules: list, "Regel öffnen", the action dialog keeps the other actions', async ({ launchApp, mock }) => {
    const fam = setFamilie(mock);
    const { page } = await launchApp();
    const root = await openFamilie(page, mock);

    // "Regel öffnen" on Tim's card leads to the rule
    await card(root, 5).locator('.fv-link').click();
    await expect(root.locator('.fv-tabs button.on')).toHaveText(/^(Regeln|Rules)$/);
    const rows = root.locator('.fv-li');
    await expect(rows).toHaveCount(3);
    await expect(root.locator('.fv-li.is-focus')).toHaveAttribute('data-rule', '12');
    await expect(rows.nth(0).locator('.fv-li-tx b')).toHaveText('Abendessen <b>');
    await expect(rows.nth(0).locator('.fv-li-tx > span').first()).toContainText('18:00');
    await expect(rows.nth(0).locator('.fv-li-tx > span').first()).toContainText('Tim');
    await expect(rows.nth(0).locator('.fv-li-tx > span').first()).toContainText('18:30');
    await expect(rows.nth(0).locator('.fv-li-tx > span').first()).toContainText('Küchenlicht');
    // a child that is no minor of the family any more
    await expect(rows.nth(2).locator('.fv-chip.is-warn')).toBeVisible();
    await expect(rows.nth(2).locator('.sw')).toHaveAttribute('aria-checked', 'false');
    await page.screenshot({ path: test.info().outputPath('familie-04-regeln.png') });

    // the switch
    await rows.nth(1).locator('.sw').click();
    await expect(rows.nth(1).locator('.sw')).toHaveAttribute('aria-checked', 'false');
    expect(sent(fam, 'PATCH', 'rules/13').at(-1).body).toEqual({ active: false });

    // "Bearbeiten": the dialog of the action "Internet zu Hause", first action preselected
    await rows.nth(0).locator('[data-k="edit-12"]').click();
    const dlg = root.locator('.fv-dlg');
    await expect(dlg).toBeVisible();
    const groups = dlg.locator('.fv-opts');
    await expect(groups).toHaveCount(4); // which action, for whom, what, how long
    await expect(groups.nth(0).locator('.fv-opt')).toHaveCount(3); // two actions + "Neue Aktion"
    await expect(groups.nth(1).locator('.fv-opt[aria-pressed="true"] > span:last-child')).toHaveText('Tim');
    await expect(groups.nth(3).locator('.fv-opt[aria-pressed="true"]')).toHaveText(/^30 /);
    await expect(dlg.locator('.fv-dlg-hint')).toContainText('Anna');
    await page.screenshot({ path: test.info().outputPath('familie-05-dialog-regel-aktion.png') });

    // 1 hour instead of 30 minutes: only this action changes
    await groups.nth(3).locator('.fv-opt').nth(1).click();
    await dlg.locator('[data-k="submit"]').click();
    await expect(dlg).toBeHidden();
    expect(sent(fam, 'PATCH', 'rules/12').at(-1).body).toEqual({
      actions: [
        { type: 'internet', op: 'pause', userId: 5, minutes: 60 },
        { type: 'quick_action', actionId: 'gatecontrol-smarthome/lamp.kitchen', title: 'Küchenlicht', state: 'on' },
        { type: 'internet', op: 'pause', userId: 4, until: '18:30' },
        { type: 'notify', to: [5, 4], text: 'Abendessen ist fertig' },
      ],
    });
    await expect(rows.nth(0).locator('.fv-li-tx > span').first()).toContainText(/1 (Std\.|h)/);

    // the second action: "bis Uhrzeit" → "Fortsetzen"
    await rows.nth(0).locator('[data-k="edit-12"]').click();
    await groups.nth(0).locator('.fv-opt').nth(1).click();
    await expect(groups.nth(1).locator('.fv-opt[aria-pressed="true"] > span:last-child')).toHaveText('Lea');
    await expect(dlg.locator('input[type="time"]')).toHaveValue('18:30');
    await groups.nth(2).locator('.fv-opt').nth(1).click();
    await expect(dlg.locator('input[type="time"]')).toHaveCount(0);
    await dlg.locator('[data-k="submit"]').click();
    await expect(dlg).toBeHidden();
    expect(sent(fam, 'PATCH', 'rules/12').at(-1).body.actions[2]).toEqual({ type: 'internet', op: 'resume', userId: 4 });
    expect(sent(fam, 'PATCH', 'rules/12').at(-1).body.actions).toHaveLength(4);

    // a new action for Mia, then removed again
    await rows.nth(0).locator('[data-k="edit-12"]').click();
    await groups.nth(0).locator('.fv-opt').nth(2).click();
    await groups.nth(1).locator('.fv-opt').nth(2).click();
    await dlg.locator('[data-k="submit"]').click();
    await expect(dlg).toBeHidden();
    expect(sent(fam, 'PATCH', 'rules/12').at(-1).body.actions.at(-1)).toEqual({ type: 'internet', op: 'pause', userId: 6, minutes: 30 });
    await rows.nth(0).locator('[data-k="edit-12"]').click();
    await groups.nth(0).locator('.fv-opt').nth(2).click();
    await dlg.locator('[data-k="remove"]').click();
    await expect(dlg).toBeHidden();
    expect(sent(fam, 'PATCH', 'rules/12').at(-1).body.actions).toHaveLength(4);

    // a refused action: the dialog stays and says so; the only action cannot be removed
    await rows.nth(2).locator('[data-k="edit-14"]').click();
    await expect(dlg.locator('[data-k="remove"]')).toBeDisabled();
    await expect(dlg.locator('[data-k="submit"]')).toBeDisabled(); // Jonas is not offered any more
    await groups.nth(0).locator('.fv-opt').nth(1).click(); // "Neue Aktion"
    fam.options.internet.children = [];
    await dlg.locator('[data-k="submit"]').click();
    await expect(dlg.locator('.fv-dlg-err')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(dlg).toBeHidden();
  });

  test('"Meine Anwesenheit": Wi-Fi detection, source and own devices', async ({ launchApp, mock }) => {
    const fam = setFamilie(mock);
    const { page } = await launchApp();
    const root = await openFamilie(page, mock);
    await root.locator('.fv-tabs button').nth(2).click();

    const share = root.locator('[data-sw="share"]');
    const wifi = root.locator('[data-sw="wifi"]');
    await expect(share).toHaveAttribute('aria-checked', 'true');
    await expect(wifi).toHaveAttribute('aria-checked', 'true');
    await expect(root.locator('.fv-list').first().locator('.fv-li').nth(2)).toContainText('16:40');
    await expect(root.locator('.fv-list').first().locator('.fv-chip.is-ok')).toContainText(/WLAN|Wi-Fi/);
    const devs = root.locator('.fv-devs .fv-li');
    await expect(devs).toHaveCount(2);
    await expect(devs.nth(0)).toContainText('Annas Handy');
    await expect(devs.nth(0)).toContainText('Pi Keller');
    await expect(devs.nth(1).locator('.sw')).toHaveAttribute('aria-checked', 'false');
    await page.screenshot({ path: test.info().outputPath('familie-06-meine-anwesenheit.png') });

    // a device counts; the switch keeps the keyboard focus
    await devs.nth(1).locator('.sw').focus();
    await page.keyboard.press('Space');
    await expect(devs.nth(1).locator('.sw')).toHaveAttribute('aria-checked', 'true');
    await expect(devs.nth(1).locator('.sw')).toBeFocused();
    expect(sent(fam, 'PUT', 'presence/wifi/devices/42').at(-1).body).toEqual({ counts: true });

    // Wi-Fi detection off: the devices go, the source is the app
    await wifi.click();
    await expect(wifi).toHaveAttribute('aria-checked', 'false');
    expect(sent(fam, 'PUT', 'presence/wifi').at(-1).body).toEqual({ enabled: false });
    await expect(root.locator('.fv-devs')).toHaveCount(0);
    await expect(root.locator('.fv-list').first().locator('.fv-chip.is-ok')).toContainText(/App|app/);
    await share.click();
    await expect(share).toHaveAttribute('aria-checked', 'false');
    expect(sent(fam, 'PUT', 'presence/consent').at(-1).body).toEqual({ share: false });
  });

  test('a server without Wi-Fi detection: no switch; modules off: no tabs', async ({ launchApp, mock }) => {
    const data = familieData();
    data.presence.me.wifi = null;
    data.wifi = null;
    data.modules = { rules: false, presence: true };
    const fam = mock.setFamilie(data);
    fam.clock = NOW;
    const { page } = await launchApp();
    const root = await openFamilie(page, mock);
    await expect(root.locator('.fv-tabs button')).toHaveCount(2);
    // no rule tab: the note names the rule, without a link
    await expect(card(root, 5).locator('.fv-note')).toBeVisible();
    await expect(card(root, 5).locator('.fv-link')).toHaveCount(0);
    await root.locator('.fv-tabs button').nth(1).click();
    await expect(root.locator('[data-sw="share"]')).toBeVisible();
    await expect(root.locator('[data-sw="wifi"]')).toHaveCount(0);
    await expect(root.locator('.fv-devs')).toHaveCount(0);
  });

  test('a child: its own card, read only; "Pause vorbei" opens the page', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [{ id: 'plugin:gatecontrol-familie:internet', label: 'Familie · Internet zu Hause' }], items: [] });
    const tim = children()[1];
    const fam = setFamilie(mock, {
      me: { userId: 5, name: 'Tim', role: 'child' },
      internet: { available: true, manage: false, children: [{ ...tim, paused: null, pausedBy: null, nextSchedule: { ...SCHEDULE } }] },
    });
    const { app, page } = await launchApp();
    const root = await openFamilie(page, mock);
    await expect(root.locator('.fv-tabs')).toBeHidden();
    await expect(root.locator('.fv-card')).toHaveCount(1);
    await expect(card(root, 5).locator('.fv-chip.is-ok')).toBeVisible();
    await expect(root.locator('.fv-card .btn')).toHaveCount(0);
    await expect(root.locator('.fv-foot')).toHaveText(/Eltern|parents/);
    await page.screenshot({ path: test.info().outputPath('familie-07-kind.png') });

    // a pause set by a parent arrives as a push: the card follows
    fam.internet.children[0].paused = at('17:30');
    fam.internet.children[0].pausedBy = { userId: 2, name: 'Anna', at: at('16:52'), rule: null };
    mock.pushNotification({
      topic: 'plugin:gatecontrol-familie:internet', title: 'Internet-Pause bis 18:30', body: 'Anna hat das Internet zu Hause pausiert.',
      data: { route: 'plg-gatecontrol-familie', familie: { type: 'internet', kind: 'pause', userId: 5, until: at('17:30'), by: 2 } },
    });
    await expect(card(root, 5)).toHaveClass(/is-paused/);
    await expect(root.locator('.fv-card .btn')).toHaveCount(0);

    // "Pause vorbei": the inbox entry opens the page …
    fam.internet.children[0].paused = null;
    fam.internet.children[0].pausedBy = null;
    mock.pushNotification({
      topic: 'plugin:gatecontrol-familie:internet', title: 'Pause vorbei', body: 'Das Internet zu Hause geht wieder.',
      data: { route: 'plg-gatecontrol-familie', familie: { type: 'internet', kind: 'pause_over', userId: 5, until: null, by: null } },
    });
    await expect(card(root, 5)).toHaveClass(/is-normal/);
    await page.locator('#nav-inbox').click();
    await page.locator('#inbox-list .inbox-row').first().click();
    await page.locator('#inbox-detail .btn-pri').first().click();
    await expect(page.locator('#page-familie')).toHaveClass(/active/);
    await expect(card(root, 5)).toHaveClass(/is-focus/);

    // … and so does a click on its toast the core claimed (notify:navigate with the Familie route)
    await page.locator('.nav[data-page="status"]').click();
    await app.evaluate(({ BrowserWindow }, ctx) => {
      BrowserWindow.getAllWindows()[0].webContents.send('notify:navigate', { route: 'plg-gatecontrol-familie', id: 1, context: ctx });
    }, { type: 'internet', kind: 'pause_over', userId: 5, until: null, ruleId: null });
    await expect(page.locator('#page-familie')).toHaveClass(/active/);
    // another topic of Familie keeps the inbox
    await app.evaluate(({ BrowserWindow }) => {
      BrowserWindow.getAllWindows()[0].webContents.send('notify:navigate', { route: 'plg-gatecontrol-familie', id: 2 });
    });
    await expect(page.locator('#page-inbox')).toHaveClass(/active/);
  });

  test('no "Internet zu Hause" on the server, and an older plugin: a hint, no error', async ({ launchApp, mock }) => {
    const fam = setFamilie(mock, { internet: { available: false, manage: true, children: [] } });
    const { page } = await launchApp();
    const root = await openFamilie(page, mock);
    await expect(root.locator('.fv-state strong')).toHaveText(/Internet zu Hause|Internet at home/);
    await expect(root.locator('.fv-state.is-error')).toHaveCount(0);
    await expect(root.locator('.fv-tabs button')).toHaveCount(3);
    await page.screenshot({ path: test.info().outputPath('familie-08-kein-internet-zu-hause.png') });

    // plugin before 1.18.0: the route is missing
    fam.internet = null;
    fam.version = '1.17.0';
    await root.locator('.fv-ib').click();
    await expect.poll(() => sent(fam, 'GET', 'internet').length).toBeGreaterThan(1);
    await expect(root.locator('.fv-state strong')).toBeVisible();
    await expect(root.locator('.fv-state.is-error')).toHaveCount(0);
    await expect(page.locator('.toast-error')).toHaveCount(0);
  });
});
