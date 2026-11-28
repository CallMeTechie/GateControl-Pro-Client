'use strict';

// View logic of the plugins' quick actions on the start page
// (src/renderer/quick-actions-state.js, no DOM): devices and their parts (as
// on Android), the pins of this PC, numbers, a stepper's grid, the day bar,
// asking first, the texts of a failure; how the page loads the scripts, that
// the view never uses innerHTML, how main hands the core service to the IPC,
// and that every home.qa.* key that is used exists in German and English.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const QS = require('../src/renderer/quick-actions-state');

const ROOT = path.join(__dirname, '..');
const P = 'gatecontrol-smarthome';
const t = (key, p) => (p ? `${key}(${Object.values(p).join(',')})` : key);

const room = { id: 'heat:3', title: 'Arbeitszimmer', subtitle: null, icon: 'M1 1h2' };
const carrier = {
  plugin: P, pluginName: 'Smart Home', id: 'heat:room:3', kind: 'button', title: 'Arbeitszimmer', device: room,
  widget: {
    label: 'Ist', value: 21.2, unit: '°C', status: 'Von Hand', state: 'warn', power: true, badge: null,
    readings: [{ id: 'hum', label: 'Feuchte', value: 48, unit: '%' }],
    controls: [{ id: 'sp', kind: 'stepper', label: 'Soll', value: 22, min: 5, max: 30, step: 0.5, unit: '°C', disabled: false }],
    timeline: { from: 0, to: 24, now: 6.87, segments: [{ from: 0, to: 6, tone: null, color: '#6366f1', label: 'Nacht' }, { from: 6, to: 8, tone: 'warn', color: null, label: null }] },
  },
};
const plan = { plugin: P, pluginName: 'Smart Home', id: 'heat:plan:3', kind: 'button', title: 'Zurück zum Plan', device: room };
const away = { plugin: P, pluginName: 'Smart Home', id: 'heat:away', kind: 'toggle', title: 'Heizung abwesend', state: 'off', confirmWhen: 'on', device: null };
const lamp = {
  plugin: P, pluginName: 'Smart Home', id: 'light:1', kind: 'toggle', title: 'Stehlampe', state: 'on', device: { id: 'light:1', title: 'Stehlampe' },
  widget: { state: 'on', power: true, readings: [], controls: [{ id: 'bri', kind: 'slider', value: 60, min: 0, max: 100, step: 10, unit: '%' }], timeline: null },
};

describe('quick-actions-state – devices', () => {
  it('groups by device in the order the actions come; a lone action is its own device', () => {
    const d = QS.group([carrier, away, plan, lamp]);
    assert.deepEqual(d.map((x) => x.key), [`${P}/heat:3`, `${P}/@heat:away`, `${P}/light:1`]);
    assert.deepEqual(d[0].actions.map((a) => a.id), ['heat:room:3', 'heat:plan:3']);
    assert.equal(d[0].carrier, carrier);
    assert.equal(d[0].power, null, 'a button carrying the widget is no power switch');
    assert.equal(d[1].title, 'Heizung abwesend');
    assert.equal(d[2].power, lamp, 'a toggle carrying the widget is its power switch');
  });

  it('the parts like Android: the carrier is no button of its own, a toggle carrying the widget stays the power switch', () => {
    const [heat, , light] = QS.group([carrier, away, plan, lamp]);
    assert.deepEqual(QS.parts(heat).map((p) => p.id), ['value', 'reading:hum', 'status', 'timeline', 'control:sp', 'action:heat:plan:3']);
    assert.deepEqual(QS.parts(light).map((p) => [p.id, p.kind]), [['action:light:1', 'power'], ['control:bri', 'control']]);
    const shown = QS.shownParts(heat, { hidden: ['timeline', 'reading:hum'] });
    assert.equal(shown.has('timeline'), false);
    assert.equal(shown.has('reading:hum'), false);
    assert.equal(shown.has('control:sp'), true);
    assert.equal(shown.has('action:heat:room:3'), false, 'the carrier is never shown as a button');
    assert.equal(shown.has('action:heat:plan:3'), true);
  });

  it('an old pin that hid the carrier keeps working: nothing else hidden, the entry stays as it was', () => {
    const [heat] = QS.group([carrier, plan]);
    const pins = [{ device: heat.key, anchor: `${P}/heat:room:3`, title: 'Arbeitszimmer', hidden: ['action:heat:room:3', 'timeline'] }];
    const shown = QS.shownParts(heat, pins[0]);
    assert.deepEqual([...shown], ['value', 'reading:hum', 'status', 'control:sp', 'action:heat:plan:3']);
    assert.equal(QS.syncPins(pins, [heat]), pins, 'unchanged');
    assert.deepEqual(QS.setHidden(pins, heat.key, 'timeline', false)[0].hidden, ['action:heat:room:3']);
  });
});

describe('quick-actions-state – a toggle carrying the widget without being the power switch', () => {
  const fan = {
    plugin: P, pluginName: 'Smart Home', id: 'fan:1', kind: 'toggle', title: 'Lüfter', state: 'off', device: { id: 'fan:1', title: 'Lüfter' },
    widget: { power: false, status: 'Aus', readings: [], controls: [], timeline: null },
  };
  const boost = { plugin: P, pluginName: 'Smart Home', id: 'fan:boost', kind: 'button', title: 'Stoßlüften', device: { id: 'fan:1', title: 'Lüfter' } };

  it('is no power switch but stays a button and a part of the card', () => {
    const [d] = QS.group([fan, boost]);
    assert.equal(d.carrier, fan);
    assert.equal(d.power, null);
    assert.equal(QS.asButton(d, fan), true);
    assert.equal(QS.asButton(d, boost), true);
    assert.deepEqual(QS.parts(d).map((p) => [p.id, p.kind]), [['status', 'status'], ['action:fan:1', 'action'], ['action:fan:boost', 'action']]);
    assert.equal(QS.shownParts(d, { hidden: [] }).has('action:fan:1'), true);
    assert.equal(QS.shownParts(d, { hidden: ['action:fan:1'] }).has('action:fan:1'), false, 'it can still be hidden');
  });

  it('a plain button carrying the widget and the power switch are no buttons', () => {
    const [heat, , light] = QS.group([carrier, away, plan, lamp]);
    assert.equal(QS.asButton(heat, carrier), false);
    assert.equal(QS.asButton(heat, plan), true);
    assert.equal(QS.asButton(light, lamp), false);
  });
});

describe('quick-actions-state – pins', () => {
  const devices = QS.group([carrier, plan, away]);

  it('pin, keep the place and the hidden parts, loosen; at most 12', () => {
    let pins = QS.pinDevice([], devices[0], true);
    assert.deepEqual(pins, [{ device: `${P}/heat:3`, anchor: `${P}/heat:room:3`, title: 'Arbeitszimmer', hidden: [] }]);
    pins = QS.pinDevice(pins, devices[1], true);
    pins = QS.setHidden(pins, `${P}/heat:3`, 'timeline', true);
    pins = QS.pinDevice(pins, devices[0], true);
    assert.deepEqual(pins.map((p) => [p.device, p.hidden]), [[`${P}/heat:3`, ['timeline']], [`${P}/@heat:away`, []]]);
    pins = QS.setHidden(pins, `${P}/heat:3`, 'timeline', false);
    assert.deepEqual(pins[0].hidden, []);
    assert.deepEqual(QS.pinDevice(pins, devices[0], false).map((p) => p.device), [`${P}/@heat:away`]);
    let many = [];
    for (let i = 0; i < 14; i += 1) many = QS.pinDevice(many, { key: `p-x/d${i}`, title: `D${i}`, actions: [{ plugin: 'p-x', id: `a${i}` }] }, true);
    assert.equal(many.length, QS.MAX_PINS);
  });

  it('a device whose id changed is found by its anchor; the pin follows it', () => {
    const pins = [{ device: `${P}/heat:old`, anchor: `${P}/heat:room:3`, title: 'Büro', hidden: ['status'] }];
    assert.equal(QS.resolve(pins[0], devices).key, `${P}/heat:3`);
    const synced = QS.syncPins(pins, devices);
    assert.deepEqual(synced, [{ device: `${P}/heat:3`, anchor: `${P}/heat:room:3`, title: 'Arbeitszimmer', hidden: ['status'] }]);
    assert.equal(QS.syncPins(synced, devices), synced, 'nothing changed: the same array');
    assert.equal(QS.resolve({ device: `${P}/gone`, anchor: `${P}/gone:1` }, devices), null);
  });
});

describe('quick-actions-state – numbers, controls, the day bar', () => {
  it('numbers with at most one decimal in the app language; a control with the decimals of its step', () => {
    assert.equal(QS.formatNumber(21.25, 'de'), '21,3');
    assert.equal(QS.formatNumber(21.5, 'en'), '21.5');
    assert.equal(QS.formatNumber(1234, 'de'), '1234');
    const sp = carrier.widget.controls[0];
    assert.equal(QS.controlText(22, sp, 'de'), '22,0 °C');
    assert.equal(QS.controlText(60, lamp.widget.controls[0], 'en'), '60 %');
    assert.equal(QS.valueText('offen', 'de'), 'offen');
    assert.equal(QS.valueText(null, 'de'), null);
    assert.equal(QS.readingText({ value: 48, unit: '%' }, 'de'), '48 %');
    assert.equal(QS.readingText({ value: null, icon: 'M0 0' }, 'de'), '');
  });

  it('snap: onto the grid and into the range', () => {
    const sp = carrier.widget.controls[0];
    assert.equal(QS.snap(22.3, sp), 22.5);
    assert.equal(QS.snap(30.5, sp), 30);
    assert.equal(QS.snap(4, sp), 5);
    assert.equal(QS.snap(0.1 + 0.2 + 21.7, sp), 22);
    assert.equal(QS.snap(57, lamp.widget.controls[0]), 60);
  });

  it('temperatures; tones; glyphs of common options', () => {
    assert.equal(QS.isTemperature('°C'), true);
    assert.equal(QS.isTemperature('℉'), true);
    assert.equal(QS.isTemperature('%'), false);
    assert.equal(QS.tone('on'), 'good');
    assert.equal(QS.tone('crit'), 'crit');
    assert.equal(QS.tone('off'), null);
    assert.ok(QS.optionGlyph({ id: 'cool' }));
    assert.equal(QS.optionGlyph({ id: 'comfort' }), null);
    assert.equal(QS.optionGlyph({ id: 'x', icon: 'M0 0h1' }), 'M0 0h1');
    assert.equal(QS.optionGlyph({ id: 'constructor' }), null);
  });

  it('the day bar: percent of the bar, the mark for now, the axis, what a screen reader hears', () => {
    const v = QS.timelineView(carrier.widget.timeline, 'de');
    assert.deepEqual(v.segments.map((s) => [s.left, Math.round(s.width * 1000) / 1000, s.color, s.tone]), [[0, 25, '#6366f1', null], [25, 8.333, null, 'warn']]);
    assert.ok(Math.abs(v.now - (6.87 / 24) * 100) < 1e-9);
    assert.deepEqual(v.ticks, ['0', '6', '12', '18', '24']);
    assert.equal(v.spoken, '0:00–6:00 Nacht, 6:00–8:00');
    assert.equal(v.nowText, '6:52');
    const other = QS.timelineView({ from: 0, to: 100, now: null, segments: [{ from: 10, to: 35.5 }] }, 'de');
    assert.deepEqual(other.ticks, ['0', '25', '50', '75', '100']);
    assert.equal(other.spoken, '10–35,5');
    assert.equal(other.now, null);
  });

  it('layout: choices up to 5 in a row, buttons up to 3 (4 as 2 + 2)', () => {
    assert.deepEqual([2, 4, 5, 6, 7, 8].map(QS.choicePerRow), [2, 4, 5, 3, 4, 4]);
    assert.deepEqual([1, 2, 3, 4, 5].map(QS.buttonsPerRow), [1, 2, 3, 2, 3]);
  });
});

describe('quick-actions-state – running', () => {
  it('a toggle goes to the other state; it asks first only towards confirmWhen, a button when confirm is set', () => {
    assert.equal(QS.target(away), 'on');
    assert.equal(QS.target({ ...away, state: 'on' }), 'off');
    assert.equal(QS.target({ ...away, state: null }), 'on');
    assert.equal(QS.target(plan), null);
    assert.equal(QS.needsConfirm(away), true);
    assert.equal(QS.needsConfirm({ ...away, state: 'on' }), false);
    assert.equal(QS.needsConfirm({ ...plan, confirm: true }), true);
    assert.equal(QS.needsConfirm(plan), false);
  });

  it('the look and icon of a toggle\'s state', () => {
    const lock = { ...away, icon: 'M0 0h1', look: { on: { icon: 'M1 1h1', tone: 'good' }, off: { icon: null, tone: 'crit' } } };
    assert.deepEqual(QS.currentLook(lock), { icon: null, tone: 'crit' });
    assert.equal(QS.displayIcon(lock), 'M0 0h1');
    assert.equal(QS.displayIcon({ ...lock, state: 'on' }), 'M1 1h1');
    assert.equal(QS.displayIcon(plan), QS.BOLT);
  });

  it('the text of a failure: the plugin\'s sentence, else the reason; refusals that ask the list again', () => {
    assert.equal(QS.failureText({ ok: false, reason: 'failed', message: 'Fenster offen' }, 'Bad', t), 'home.qa.error.message(Bad,Fenster offen)');
    assert.equal(QS.failureText({ ok: false, reason: 'control_disabled' }, 'Bad', t), 'home.qa.error.control_disabled(Bad)');
    for (const r of ['gone', 'no_user', 'busy', 'timeout', 'network', 'state_unknown', 'not_configured']) assert.equal(QS.failureText({ reason: r }, 'X', t), `home.qa.error.${r}(X)`);
    assert.equal(QS.failureText({ reason: 'invalid' }, 'X', t), 'home.qa.error.failed(X)');
    assert.equal(QS.failureText({ reason: '__proto__' }, 'X', t), 'home.qa.error.failed(X)');
    assert.equal(QS.failureText(null, 'X', t), 'home.qa.error.failed(X)');
    assert.equal(QS.reloadAfter({ reason: 'control_disabled' }), true);
    assert.equal(QS.reloadAfter({ reason: 'gone' }), true);
    assert.equal(QS.reloadAfter({ reason: 'busy' }), false);
  });
});

describe('quick actions – wiring, texts, safety', () => {
  const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');

  it('the page loads state and view before home-view.js, and its stylesheet', () => {
    const html = read('src/renderer/index.html');
    const at = (s) => html.indexOf(s);
    assert.ok(at('<script src="quick-actions-state.js"></script>') > at('<script src="mail-view.js"></script>'));
    assert.ok(at('<script src="quick-actions-state.js"></script>') < at('<script src="quick-actions-view.js"></script>'));
    assert.ok(at('<script src="quick-actions-view.js"></script>') < at('<script src="home-view.js"></script>'));
    assert.ok(at('<link rel="stylesheet" href="styles/quick-actions.css">') > 0);
  });

  it('server text only into textContent / attributes', () => {
    for (const f of ['src/renderer/quick-actions-view.js', 'src/renderer/quick-actions-state.js']) {
      assert.doesNotMatch(read(f), /innerHTML|outerHTML|insertAdjacentHTML|document\.write/, f);
    }
  });

  it('main creates the core service and hands it to the IPC (absent in an older core)', () => {
    const main = read('src/main/main.js');
    assert.match(main, /\(\{ QuickActionsService \} = require\('@gatecontrol\/client-core'\)\)/);
    assert.match(main, /quickActions = QuickActionsService \? new QuickActionsService\(\{ apiClient, log, getLocale: \(\) => getLocale\(\) \}\) : null;/);
    assert.match(main, /\n\s+quickActions,\n/);
  });

  it('every home.qa.* key used exists in German and English', () => {
    const flatten = (obj, prefix = '', out = {}) => {
      for (const [k, v] of Object.entries(obj)) {
        const key = prefix ? `${prefix}.${k}` : k;
        if (v && typeof v === 'object') flatten(v, key, out);
        else out[key] = v;
      }
      return out;
    };
    const de = flatten(JSON.parse(read('src/i18n/de.json')));
    const en = flatten(JSON.parse(read('src/i18n/en.json')));
    const src = read('src/renderer/quick-actions-view.js') + read('src/renderer/home-view.js') + read('src/renderer/quick-actions-state.js');
    const used = new Set([...src.matchAll(/'(home\.qa\.[a-zA-Z_.]+)'/g)].map((m) => m[1]));
    for (const r of ['failed', 'control_disabled', 'gone', 'no_user', 'busy', 'timeout', 'network', 'state_unknown', 'not_configured']) used.add(`home.qa.error.${r}`);
    assert.ok(used.size > 20);
    for (const k of used) {
      assert.ok(de[k], `de: ${k}`);
      assert.ok(en[k], `en: ${k}`);
    }
  });
});

describe('quick actions: the dialog "Schnellaktionen anheften"', () => {
  const dev = (plugin, pluginName, id, title, subtitle = null) => ({ key: `${plugin}/${id}`, plugin, pluginName, title, subtitle, actions: [] });
  const devices = [
    dev('sh', 'Smart Home', 'licht', 'Wohnzimmer Licht', 'Schalter · Wohnzimmer'),
    dev('rk', 'Raumklima', 'kind', 'Kinderzimmer', 'Heizung · 20,0 °C'),
    dev('sh', 'Smart Home', 'tuer', 'Haustür', 'Schloss · Eingang'),
    dev('rk', 'Raumklima', 'arbeit', 'Arbeitszimmer', 'Heizung · 21,5 °C'),
  ];
  const pins = [{ device: 'rk/arbeit' }, { device: 'sh/tuer' }, { device: 'rk/kind' }];

  it('groups the devices by plugin in the order they come, with the pinned count', () => {
    assert.deepEqual(QS.pickGroups(devices, pins).map((g) => [g.plugin, g.name, g.devices.map((d) => d.title), g.pinned, g.total]), [
      ['sh', 'Smart Home', ['Wohnzimmer Licht', 'Haustür'], 1, 2],
      ['rk', 'Raumklima', ['Kinderzimmer', 'Arbeitszimmer'], 2, 2],
    ]);
    assert.deepEqual(QS.pickGroups([], pins), []);
  });

  it('the search: name, the line below (room) and the plugin, any case', () => {
    assert.equal(QS.matches(devices[0], ''), true);
    assert.equal(QS.matches(devices[0], '  '), true);
    assert.equal(QS.matches(devices[0], 'WOHN'), true);
    assert.equal(QS.matches(devices[2], 'eingang'), true);
    assert.equal(QS.matches(devices[1], 'raumklima'), true);
    assert.equal(QS.matches(devices[1], 'licht'), false);
    assert.deepEqual(QS.highlight('Arbeitszimmer', 'ZIMMER'), [{ text: 'Arbeits', hit: false }, { text: 'zimmer', hit: true }]);
    assert.deepEqual(QS.highlight('Haustür', 'haus'), [{ text: 'Haus', hit: true }, { text: 'tür', hit: false }]);
    assert.deepEqual(QS.highlight('Haustür', 'x'), [{ text: 'Haustür', hit: false }]);
    assert.deepEqual(QS.highlight('Haustür', ''), [{ text: 'Haustür', hit: false }]);
  });

  it('moves a pin up and down (Alt+↑/↓) and orders them after a drag', () => {
    assert.deepEqual(QS.movePin(pins, 'sh/tuer', -1).map((p) => p.device), ['sh/tuer', 'rk/arbeit', 'rk/kind']);
    assert.deepEqual(QS.movePin(pins, 'sh/tuer', 1).map((p) => p.device), ['rk/arbeit', 'rk/kind', 'sh/tuer']);
    assert.equal(QS.movePin(pins, 'rk/arbeit', -1), pins);
    assert.equal(QS.movePin(pins, 'rk/kind', 1), pins);
    assert.equal(QS.movePin(pins, 'nope', 1), pins);
    assert.deepEqual(pins.map((p) => p.device), ['rk/arbeit', 'sh/tuer', 'rk/kind']);
    assert.deepEqual(QS.orderPins(pins, ['rk/kind', 'rk/arbeit', 'sh/tuer']).map((p) => p.device), ['rk/kind', 'rk/arbeit', 'sh/tuer']);
    // keys not pinned are ignored, pins not named stay at the end
    assert.deepEqual(QS.orderPins(pins, ['x', 'sh/tuer']).map((p) => p.device), ['sh/tuer', 'rk/arbeit', 'rk/kind']);
  });

  it('the dialog is built again only when the devices change (not for new names)', () => {
    const a = QS.pickShape('ok', devices);
    assert.equal(QS.pickShape('ok', devices.map((d) => ({ ...d, title: `${d.title}!` }))), a);
    assert.notEqual(QS.pickShape('ok', devices.slice(1)), a);
    assert.notEqual(QS.pickShape('loading', devices), a);
  });

  it('the view changes rows in place: no fillPicker() from a switch, refresh() only syncs', () => {
    const view = fs.readFileSync(path.join(ROOT, 'src', 'renderer', 'quick-actions-view.js'), 'utf8');
    assert.match(view, /if \(dialog && !dialog\.closed\) syncPicker\(\);/);
    const toggle = view.slice(view.indexOf('function togglePin('), view.indexOf('function unpinFrom('));
    assert.doesNotMatch(toggle, /fillPicker|clear\(dialog\.body\)/);
  });
});
