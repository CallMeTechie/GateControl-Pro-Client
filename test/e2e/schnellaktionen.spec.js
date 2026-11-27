'use strict';

const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');
const { actions, PLUGIN, ICON } = require('./support/actions-fixtures');

// Schnellaktionen der Plugins auf der Startseite („Angeheftet“): the dialog
// pins a device as a card, the card shows value, valve badge, readings,
// status, the day bar (with the mark for now; a broken one is left out),
// stepper / slider / choice (a choice without a selection shows none),
// disabled controls send nothing, a 409 control_disabled says so and asks the
// list again, buttons and toggles run (a logic chain asks first), parts can be
// hidden, × loosens the card, and what is pinned is kept in gc.home.pins.
// A server before quick actions shows neither cards nor the button.

// The pinned core (core.ref) may be older than the quick actions: nothing to test then.
const coreDir = (() => {
  try { return path.dirname(require.resolve('@gatecontrol/client-core/package.json', { paths: [path.join(__dirname, '..', '..')] })); } catch { return null; }
})();
const HAS_CORE = !!coreDir && fs.existsSync(path.join(coreDir, 'src', 'services', 'quick-actions.js'));

const PINS = '#home-pins';
const card = (page, device) => page.locator(`${PINS} .qa-card[data-device="${PLUGIN}/${device}"]`);
const runs = (qa) => qa.log.map((r) => [r.id, r.body]);

async function open(launchApp, mock, opts = {}) {
  const qa = mock.setActions({ actions: actions(), ...opts });
  const launched = await launchApp();
  await setupWithApiKey(launched.page, mock);
  return { ...launched, qa };
}

/** Pins devices through the dialog "Schnellaktionen anheften". */
async function pin(page, ...devices) {
  await page.locator('#home-qa-open').click();
  const dlg = page.locator('.qa-pick');
  await expect(dlg).toBeVisible();
  for (const d of devices) {
    const row = dlg.locator(`.qp-groups .qa-pick-row[data-device="${PLUGIN}/${d}"]`);
    await row.locator('.sw').click();
    await expect(row).toHaveClass(/is-on/);
  }
  return dlg;
}

/** "Teile" of a pinned device in the dialog. */
async function openParts(dlg, device) {
  const btn = dlg.locator(`.qp-pins .qa-pick-row[data-device="${PLUGIN}/${device}"] [data-qp-fk="parts"]`);
  await btn.click();
  await expect(btn).toHaveAttribute('aria-expanded', 'true');
}

test.describe('schnellaktionen', () => {
  test.skip(!HAS_CORE, 'core without quick actions (core.ref before services/quick-actions.js)');

  test('a server before quick actions: no button, no section, no error', async ({ launchApp, mock }) => {
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.count('/api/v1/client/actions')).toBeGreaterThan(0);
    await expect(page.locator('#home-qa-open')).toHaveCount(0);
    await expect(page.locator(PINS)).toBeHidden();
    await expect(page.locator('.toast-error')).toHaveCount(0);
  });

  test('the dialog lists the devices by plugin; a pinned room shows value, badge, readings, status, day bar, controls and buttons', async ({ launchApp, mock }) => {
    const { page } = await open(launchApp, mock);
    const dlg = await pin(page, 'heat:3');
    await expect(dlg.locator('.qa-pick-h')).toHaveText([/^(Angeheftet|Pinned)$/, 'Smart Home']);
    await expect(dlg.locator('.qp-groups .qa-pick-row')).toHaveCount(5);
    await expect(dlg.locator('.qp-pins .qa-pick-row')).toHaveCount(1);
    // the parts of the pinned room under "Teile" (the action carrying the widget is the card itself, no button of its own)
    await openParts(dlg, 'heat:3');
    await expect(dlg.locator(`.qp-pins .qa-parts[data-device="${PLUGIN}/heat:3"] .qa-part`)).toHaveText(['Ist', 'Feuchte', 'Batterie', /Statuszeile|Status line/, /Tagesbalken|Day bar/, 'Soll', 'Preset', 'Zurück zum Plan']);
    await dlg.locator('.ml-dlg-foot .btn-pri').click();
    await expect(dlg).toHaveCount(0);

    const c = card(page, 'heat:3');
    await expect(c).toBeVisible();
    await expect(c.locator('.qa-title')).toHaveText('Arbeitszimmer');
    await expect(c.locator('.qa-badge')).toHaveText(/^25 %$/);
    await expect(c.locator('.qa-badge')).toHaveAttribute('aria-label', 'Ventil: 25 %');
    await expect(c.locator('.qa-temp')).toHaveText(/^21[,.]2 °C$/);
    await expect(c.locator('.qa-reading')).toHaveText(['48 %', '80 %']);
    await expect(c.locator('.qa-status')).toHaveText('Von Hand bis 16:00, dann Eco 18 °C');
    // the day bar: five segments, the mark for now at 6:52, the axis
    await expect(c.locator('.qa-tl-seg')).toHaveCount(5);
    await expect(c.locator('.qa-tl-axis span')).toHaveText(['0', '6', '12', '18', '24']);
    const now = await c.locator('.qa-tl-now').evaluate((n) => n.style.left);
    expect(parseFloat(now)).toBeCloseTo((6.87 / 24) * 100, 1);
    await expect(c.locator('.qa-tl')).toHaveAttribute('aria-label', /0:00–6:00 Nacht.*6:52/);
    // the stepper with one decimal; the choice without a selection (set by hand)
    await expect(c.locator('[data-control="sp"] .qa-ctl-v')).toHaveText(/^22[,.]0 °C$/);
    await expect(c.locator('[data-control="preset"] .qa-opt')).toHaveCount(4);
    await expect(c.locator('[data-control="preset"] .qa-opt[aria-checked="true"]')).toHaveCount(0);
    await expect(c.locator('.qa-act')).toHaveText(['Zurück zum Plan']);
    await expect(c.locator('.qa-act[data-action="heat:room:3"]')).toHaveCount(0);
    // kept on this PC
    const stored = await page.evaluate(() => JSON.parse(localStorage.getItem('gc.home.pins')));
    expect(stored.actions).toEqual([{ device: `${PLUGIN}/heat:3`, anchor: `${PLUGIN}/heat:room:3`, title: 'Arbeitszimmer', hidden: [] }]);
  });

  test('stepper (one request for + + +), choice, button and the plugin\'s new widget', async ({ launchApp, mock }) => {
    const { page, qa } = await open(launchApp, mock);
    await pin(page, 'heat:3');
    await page.keyboard.press('Escape');
    const c = card(page, 'heat:3');
    const plus = c.locator('[data-control="sp"] .qa-ib').nth(1);
    await plus.click();
    await plus.click();
    await plus.click();
    await expect(c.locator('[data-control="sp"] .qa-ctl-v')).toHaveText(/^23[,.]5 °C$/);
    await expect.poll(() => runs(qa)).toEqual([['heat:room:3', { source: 'app', control: 'sp', value: 23.5 }]]);
    // the focus stays on "+" when the card is drawn with the answer
    await expect(c.locator('[data-control="sp"] .qa-ctl-v')).toHaveText(/^23[,.]5 °C$/);
    await expect(plus).toBeFocused();
    await c.locator('[data-control="preset"] .qa-opt[data-option="eco"]').click();
    await expect.poll(() => runs(qa).at(-1)).toEqual(['heat:room:3', { source: 'app', control: 'preset', value: 'eco' }]);
    await expect(c.locator('[data-control="preset"] .qa-opt[aria-checked="true"]')).toHaveAttribute('data-option', 'eco');
    await c.locator('.qa-act[data-action="heat:plan:3"]').click();
    await expect.poll(() => runs(qa).at(-1)).toEqual(['heat:plan:3', { source: 'app' }]);
    await expect(page.locator('#toasts .toast-success')).toHaveText(/Zurück zum Plan/);
  });

  test('disabled controls are faded and send nothing; 409 control_disabled says so and asks the list again', async ({ launchApp, mock }) => {
    const { page, qa } = await open(launchApp, mock);
    await pin(page, 'heat:5', 'heat:3');
    await page.keyboard.press('Escape');
    const bed = card(page, 'heat:5');
    await expect(bed.locator('[data-control="sp"]')).toHaveClass(/is-disabled/);
    await expect(bed.locator('[data-control="sp"] .qa-ib').first()).toBeDisabled();
    await expect(bed.locator('[data-control="preset"] .qa-opt').first()).toBeDisabled();
    await expect(bed.locator('[data-control="preset"] .qa-opt[aria-checked="true"]')).toHaveAttribute('data-option', 'frost');
    await bed.locator('[data-control="sp"]').click({ force: true });
    // the broken day bar is left out, the rest of the card stays
    await expect(bed.locator('.qa-tl')).toHaveCount(0);
    await expect(bed.locator('.qa-status')).toHaveText(/Fenster offen/);
    await expect(bed.locator('.qa-reading.is-icon.is-warn')).toHaveAttribute('aria-label', 'Fenster offen');
    await expect(bed.locator('.qa-badge.is-crit')).toHaveText(/^5 %$/);
    expect(qa.log).toEqual([]);

    // the plugin disabled the room meanwhile: the host refuses, the app says so and asks again
    qa.onRun = (plugin, id, body) => (body.control ? { status: 409, body: { ok: false, error: 'control_disabled' } } : null);
    const listed = qa.listed;
    qa.actions[0].widget.controls[0].disabled = true;
    await card(page, 'heat:3').locator('[data-control="sp"] .qa-ib').first().click();
    await expect(page.locator('#toasts .toast-error')).toHaveText(/Arbeitszimmer.*(lässt sich gerade nicht ändern|can’t be changed right now)/);
    await expect.poll(() => qa.listed).toBeGreaterThan(listed);
    await expect(card(page, 'heat:3').locator('[data-control="sp"]')).toHaveClass(/is-disabled/);
    await expect(card(page, 'heat:3').locator('[data-control="sp"] .qa-ctl-v')).toHaveText(/^22[,.]0 °C$/);
  });

  test('toggles, a logic chain that asks first, a lamp with its switch and slider', async ({ launchApp, mock }) => {
    const { page, qa } = await open(launchApp, mock);
    await pin(page, '@heat:away', '@chain:night', 'light:1');
    await page.keyboard.press('Escape');
    // "abwesend": a switch in the head; switching on asks first (confirmWhen: on)
    const away = card(page, '@heat:away');
    await expect(away.locator('.qa-sub')).toHaveText('Alle Räume auf Eco');
    await away.locator('.qa-sw').click();
    const confirm = page.locator('.qa-confirm');
    await expect(confirm).toBeVisible();
    await confirm.locator('.ml-dlg-foot .btn-ghost').click();
    await expect(away.locator('.qa-sw')).toHaveAttribute('aria-checked', 'false');
    expect(qa.log).toEqual([]);
    await away.locator('.qa-sw').click();
    await confirm.locator('[data-qa-confirm]').click();
    await expect.poll(() => runs(qa)).toEqual([['heat:away', { source: 'app', state: 'on' }]]);
    await expect(away.locator('.qa-sw')).toHaveAttribute('aria-checked', 'true');
    // the chain: a button that asks first
    const chain = card(page, '@chain:night');
    await chain.locator('.qa-act').click();
    await page.locator('.qa-confirm [data-qa-confirm]').click();
    await expect.poll(() => runs(qa).at(-1)).toEqual(['chain:night', { source: 'app' }]);
    // the lamp: its power switch in the head, the slider sends when let go
    const lamp = card(page, 'light:1');
    await expect(lamp.locator('.qa-sw')).toHaveAttribute('aria-checked', 'true');
    await lamp.locator('.qa-range').fill('80');
    await expect.poll(() => runs(qa).at(-1)).toEqual(['light:1', { source: 'app', control: 'bri', value: 80 }]);
    await expect(lamp.locator('[data-control="bri"] .qa-ctl-v')).toHaveText('80 %');
    await lamp.locator('.qa-sw').click();
    await expect.poll(() => runs(qa).at(-1)).toEqual(['light:1', { source: 'app', state: 'off' }]);
  });

  test('a toggle carrying the widget that is not the power switch stays a button and a part', async ({ launchApp, mock }) => {
    const fanDev = { id: 'fan:1', title: 'Lüfter', icon: ICON.bulb };
    const list = [
      {
        plugin: PLUGIN, pluginName: 'Smart Home', id: 'fan:1', kind: 'toggle', title: 'Lüfter', state: 'off', device: fanDev,
        widget: { power: false, status: 'Aus seit 7:10', readings: [], controls: [] },
      },
      { plugin: PLUGIN, pluginName: 'Smart Home', id: 'fan:boost', kind: 'button', title: 'Stoßlüften', device: fanDev },
    ];
    const { page, qa } = await open(launchApp, mock, { actions: list });
    const dlg = await pin(page, 'fan:1');
    await openParts(dlg, 'fan:1');
    await expect(dlg.locator(`.qp-pins .qa-parts[data-device="${PLUGIN}/fan:1"] .qa-part`)).toHaveText([/Statuszeile|Status line/, 'Lüfter', 'Stoßlüften']);
    await page.keyboard.press('Escape');
    const c = card(page, 'fan:1');
    // no switch in the head (widget.power false), the toggle is in the row of buttons
    await expect(c.locator('.qa-sw')).toHaveCount(0);
    await expect(c.locator('.qa-act')).toHaveText(['Lüfter', 'Stoßlüften']);
    const fan = c.locator('.qa-act[data-action="fan:1"]');
    await expect(fan).toHaveAttribute('aria-checked', 'false');
    await fan.click();
    await expect.poll(() => runs(qa)).toEqual([['fan:1', { source: 'app', state: 'on' }]]);
    await expect(c.locator('.qa-act[data-action="fan:1"]')).toHaveAttribute('aria-checked', 'true');
  });

  test('parts hidden in the dialog, × loosens the card, gone actions say so', async ({ launchApp, mock }) => {
    const { page, qa } = await open(launchApp, mock);
    const dlg = await pin(page, 'heat:3');
    await openParts(dlg, 'heat:3');
    const row = dlg.locator(`.qp-pins .qa-parts[data-device="${PLUGIN}/heat:3"]`);
    await row.locator('[data-part="timeline"]').uncheck();
    await row.locator('[data-part="reading:hum"]').uncheck();
    await page.keyboard.press('Escape');
    const c = card(page, 'heat:3');
    await expect(c.locator('.qa-tl')).toHaveCount(0);
    await expect(c.locator('.qa-reading')).toHaveText(['80 %']);
    const stored = await page.evaluate(() => JSON.parse(localStorage.getItem('gc.home.pins')));
    expect(stored.actions[0].hidden).toEqual(['timeline', 'reading:hum']);
    // the plugin no longer lists the room: the card says so (its name kept), × loosens it
    qa.actions = qa.actions.filter((a) => a.device?.id !== 'heat:3');
    // (opening the dialog asks the list again)
    await page.locator('#home-qa-open').click();
    await expect(page.locator(`.qa-pick .qp-groups .qa-pick-row[data-device="${PLUGIN}/heat:3"]`)).toHaveCount(0);
    // still pinned: "Angeheftet" keeps it (its name) and says it is gone; its switch loosens it there
    const gone = page.locator(`.qa-pick .qp-pins .qa-pick-row[data-device="${PLUGIN}/heat:3"]`);
    await expect(gone).toHaveClass(/is-gone/);
    await expect(gone.locator('.qa-sub')).toHaveText(/Nicht mehr verfügbar|No longer available/);
    await page.keyboard.press('Escape');
    await expect(c.locator('.qa-status')).toHaveText(/Nicht mehr verfügbar|No longer available/);
    await expect(c.locator('.qa-title, .qa-name')).toHaveText(['Arbeitszimmer']);
    await c.hover();
    await c.locator('.home-x').click();
    await expect(page.locator(`${PINS} .qa-card`)).toHaveCount(0);
    expect((await page.evaluate(() => JSON.parse(localStorage.getItem('gc.home.pins')))).actions).toEqual([]);
  });

  test('the dialog: a switch changes only its rows (place and focus stay, also when the list comes late); search, groups, order, the limit of 12', async ({ launchApp, mock }) => {
    const R = 'gatecontrol-raumklima';
    const rooms = Array.from({ length: 16 }, (_, i) => ({
      plugin: R, pluginName: 'Raumklima', id: `room:${i + 1}`, kind: 'toggle', title: `Raum ${i + 1}`, subtitle: `Heizung · Etage ${i % 3}`, state: 'off', icon: ICON.thermo,
    }));
    const qa = mock.setActions({ actions: [...actions(), ...rooms] });
    const { app, page } = await launchApp();
    await setupWithApiKey(page, mock);
    await app.evaluate(({ BrowserWindow }) => { const win = BrowserWindow.getAllWindows()[0]; win.unmaximize(); win.setSize(1440, 900); });
    await expect(page.locator('#home-qa-open')).toBeVisible();
    // the list the dialog asks for comes late: it is used meanwhile
    qa.listDelay = 3000;
    const listed = qa.listed;
    await page.locator('#home-qa-open').click();
    const dlg = page.locator('.qa-pick');
    const body = dlg.locator('.qp-body');
    const room = (n) => dlg.locator(`.qp-groups .qa-pick-row[data-device="${R}/@room:${n}"]`);
    await expect(dlg.locator('[data-qp-n]')).toHaveText(/^0 (von|of) 12/);
    await expect(dlg.locator('.qp-pins .qp-empty')).toBeVisible();
    await expect(dlg.locator('.qp-groups .qa-pick-h')).toHaveText(['Smart Home', 'Raumklima']);
    await expect(dlg.locator('.qp-group[data-g="gatecontrol-raumklima"] .qp-gc')).toHaveText(/^0 (von|of) 16$/);

    // scrolled down, a room pinned: the row stays where it is, the focus on its switch
    await room(9).evaluate((r) => { const b = r.closest('.qp-body'); b.scrollTop += r.getBoundingClientRect().top - b.getBoundingClientRect().top - 220; });
    const at = () => room(9).evaluate((r) => Math.round(r.getBoundingClientRect().top));
    const scrollTop = () => body.evaluate((b) => b.scrollTop);
    const top0 = await at();
    const st0 = await scrollTop();
    expect(st0).toBeGreaterThan(100);
    await room(9).locator('.sw').click();
    await expect(room(9)).toHaveClass(/is-on/);
    await expect(room(9).locator('.qp-tag')).toBeVisible();
    await expect(room(9).locator('.sw')).toBeFocused();
    expect(Math.abs((await at()) - top0)).toBeLessThanOrEqual(1);
    expect(await scrollTop()).toBeGreaterThan(st0);
    await expect(dlg.locator('.qp-pins .qa-pick-row')).toHaveCount(1);
    await expect(dlg.locator('.qp-pins .qa-pick-row .qa-title')).toHaveText(['Raum 9']);
    await expect(dlg.locator('[data-qp-n]')).toHaveText(/^1 (von|of) 12/);
    await expect(dlg.locator('.qp-group[data-g="gatecontrol-raumklima"] .qp-gc')).toHaveText(/^1 (von|of) 16$/);

    // the late list (a new name): only the name changes, nothing moves, the focus stays
    qa.actions.find((a) => a.id === 'room:8').title = 'Raum 8 (Gäste)';
    const top1 = await at();
    const st1 = await scrollTop();
    await expect.poll(() => qa.listed, { timeout: 10000 }).toBeGreaterThan(listed);
    await expect(room(8).locator('.qa-title')).toHaveText('Raum 8 (Gäste)');
    expect(await at()).toBe(top1);
    expect(await scrollTop()).toBe(st1);
    await expect(room(9).locator('.sw')).toBeFocused();
    qa.listDelay = 0;

    // search: name, room line or plugin; the hit marked, groups without one hidden
    await dlg.locator('[data-qp-q]').fill('zimmer');
    await expect(dlg.locator('.qp-groups .qa-pick-row:visible .qa-title')).toHaveText(['Arbeitszimmer', 'Schlafzimmer']);
    await expect(dlg.locator('.qp-group[data-g="gatecontrol-raumklima"]')).toBeHidden();
    await expect(dlg.locator('.qp-groups mark').first()).toHaveText('zimmer');
    await dlg.locator('[data-qp-q]').fill('Etage 2');
    await expect(dlg.locator('.qp-groups .qa-pick-row:visible')).toHaveCount(5);
    await dlg.locator('[data-qp-q]').fill('xyz');
    await expect(dlg.locator('.qp-none')).toHaveText(/^(Nichts gefunden für „xyz“\.|Nothing found for “xyz”\.)$/);
    await dlg.locator('[data-qp-q]').fill('');
    await expect(dlg.locator('.qp-none')).toBeHidden();

    // a group folds and opens again
    const head = dlg.locator('[data-qp-g="gatecontrol-smarthome"]');
    await head.click();
    await expect(head).toHaveAttribute('aria-expanded', 'false');
    await expect(dlg.locator('.qp-groups .qa-pick-row[data-device^="gatecontrol-smarthome/"]').first()).toBeHidden();
    await head.click();
    await expect(head).toHaveAttribute('aria-expanded', 'true');

    // the order of "Angeheftet": Alt+↑/↓ on the grip, dragged by the grip
    for (const n of [1, 2, 3]) await room(n).locator('.sw').click();
    const pinRow = (n) => dlg.locator(`.qp-pins .qa-pick-row[data-device="${R}/@room:${n}"]`);
    const order = () => page.evaluate(() => JSON.parse(localStorage.getItem('gc.home.pins')).actions.map((p) => p.title));
    expect(await order()).toEqual(['Raum 9', 'Raum 1', 'Raum 2', 'Raum 3']);
    await pinRow(3).locator('.qp-grip').focus();
    await page.keyboard.press('Alt+ArrowUp');
    await page.keyboard.press('Alt+ArrowUp');
    expect(await order()).toEqual(['Raum 9', 'Raum 3', 'Raum 1', 'Raum 2']);
    await expect(dlg.locator('.qp-pins .qp-pos')).toHaveText(['1', '2', '3', '4']);
    await expect(dlg.locator('.qp-pins .qa-pick-row .qa-title')).toHaveText(['Raum 9', 'Raum 3', 'Raum 1', 'Raum 2']);
    await expect(pinRow(3).locator('.qp-grip')).toBeFocused();
    await pinRow(2).locator('.qp-grip').dragTo(pinRow(9), { targetPosition: { x: 20, y: 4 } });
    await expect.poll(order).toEqual(['Raum 2', 'Raum 9', 'Raum 3', 'Raum 1']);
    await expect(dlg.locator('.qp-pins .qa-pick-row .qa-title')).toHaveText(['Raum 2', 'Raum 9', 'Raum 3', 'Raum 1']);
    // the cards on Start follow the order
    // a pinned row loosened in "Angeheftet": the focus goes to the next one
    await pinRow(3).locator('.sw').click();
    await expect(pinRow(3)).toHaveCount(0);
    await expect(room(3)).not.toHaveClass(/is-on/);
    await expect(pinRow(1).locator('.sw')).toBeFocused();

    // the limit of 12: the count turns yellow, the hint, the other switches greyed out with the reason
    for (const n of [4, 5, 6, 7, 8, 10, 11, 12, 13]) await room(n).locator('.sw').click();
    await expect(dlg.locator('[data-qp-n]')).toHaveText(/^12 (von|of) 12/);
    await expect(dlg.locator('.qp-count')).toHaveClass(/is-full/);
    await expect(dlg.locator('.qp-hint-full')).toBeVisible();
    await expect(room(14).locator('.sw')).toBeDisabled();
    await expect(room(14).locator('.sw')).toHaveAttribute('title', /12/);
    await expect(room(13).locator('.sw')).toBeEnabled();
    await room(13).locator('.sw').click();
    await expect(dlg.locator('.qp-hint-full')).toBeHidden();
    await expect(room(14).locator('.sw')).toBeEnabled();
    if (process.env.GC_E2E_SHOTS) {
      await body.evaluate((b) => { b.scrollTop = 0; });
      for (const th of ['dark', 'light']) {
        await page.evaluate((x) => { if (x === 'light') document.documentElement.setAttribute('data-theme', 'light'); else document.documentElement.removeAttribute('data-theme'); }, th);
        await page.mouse.move(0, 0);
        await page.screenshot({ path: `${process.env.GC_E2E_SHOTS}/schnellaktionen-${th}.png` });
      }
    }
    await page.keyboard.press('Escape');
    await expect(page.locator(`${PINS} .qa-card`)).toHaveCount(11);
  });
});
