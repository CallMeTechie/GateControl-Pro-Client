'use strict';

const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');
const { actions, PLUGIN } = require('./support/actions-fixtures');

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
    const row = dlg.locator(`.qa-pick-row[data-device="${PLUGIN}/${d}"]`);
    await row.locator('.sw').click();
    await expect(row).toHaveClass(/is-on/);
  }
  return dlg;
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
    await expect(dlg.locator('.qa-pick-h')).toHaveText(['Smart Home']);
    await expect(dlg.locator('.qa-pick-row')).toHaveCount(5);
    // the parts of the pinned room (the action carrying the widget is a button like the others, as on Android)
    await expect(dlg.locator(`.qa-pick-row[data-device="${PLUGIN}/heat:3"] .qa-part`)).toHaveText(['Ist', 'Feuchte', 'Batterie', /Statuszeile|Status line/, /Tagesbalken|Day bar/, 'Soll', 'Preset', 'Arbeitszimmer', 'Zurück zum Plan']);
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
    await expect(c.locator('.qa-act')).toHaveText(['Arbeitszimmer', 'Zurück zum Plan']);
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

  test('parts hidden in the dialog, × loosens the card, gone actions say so', async ({ launchApp, mock }) => {
    const { page, qa } = await open(launchApp, mock);
    const dlg = await pin(page, 'heat:3');
    const row = dlg.locator(`.qa-pick-row[data-device="${PLUGIN}/heat:3"]`);
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
    await expect(page.locator(`.qa-pick .qa-pick-row[data-device="${PLUGIN}/heat:3"]`)).toHaveCount(0);
    await page.keyboard.press('Escape');
    await expect(c.locator('.qa-status')).toHaveText(/Nicht mehr verfügbar|No longer available/);
    await expect(c.locator('.qa-title, .qa-name')).toHaveText(['Arbeitszimmer']);
    await c.hover();
    await c.locator('.home-x').click();
    await expect(page.locator(`${PINS} .qa-card`)).toHaveCount(0);
    expect((await page.evaluate(() => JSON.parse(localStorage.getItem('gc.home.pins')))).actions).toEqual([]);
  });
});
