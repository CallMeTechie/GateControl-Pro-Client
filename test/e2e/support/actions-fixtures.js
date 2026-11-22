'use strict';

// Quick actions as a server lists them (fields up to 1.317.1) for the e2e
// specs: heating rooms (value, valve badge, readings, status, day bar,
// stepper, a choice — once without a selection —, disabled controls), the
// buttons of a room, a toggle "abwesend", a logic chain that asks first and a
// lamp with its power switch and a slider. Names and values are made up.

const P = 'gatecontrol-smarthome';
const ICON = {
  thermo: 'M14 14.8V4a2 2 0 0 0-4 0v10.8a4 4 0 1 0 4 0z',
  flame: 'M12 2c2.5 3.5 6 6 6 11a6 6 0 0 1-12 0c0-2.5 1.2-4.4 3-6 0 2 1 3.5 3 4 0-3-1-6 0-9z',
  drop: 'M12 3c3.5 4.5 6 7.7 6 11a6 6 0 0 1-12 0c0-3.3 2.5-6.5 6-11z',
  battery: 'M3 8h15v8H3z M21 11v2',
  window: 'M4 3h16v18H4z M12 3v18 M4 12h16',
  sun: 'M12 8a4 4 0 1 0 0 8a4 4 0 0 0 0-8 M12 2v2 M12 20v2 M2 12h2 M20 12h2',
  leaf: 'M5 21c0-9 5-14 15-16-1 10-6 15-15 16z M5 21l7-7',
  moon: 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z',
  snow: 'M12 2v20 M4 6l16 12 M4 18L20 6',
  clock: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18 M12 7v5l3 2',
  away: 'M3 11l9-7 9 7 M5 10v10h14V10',
  night: 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z',
  bulb: 'M9 18h6 M10 22h4 M12 2a7 7 0 0 0-4 12.7V17h8v-2.3A7 7 0 0 0 12 2z',
};

const PRESETS = [
  { id: 'comfort', label: 'Komfort', icon: ICON.sun },
  { id: 'eco', label: 'Eco', icon: ICON.leaf },
  { id: 'night', label: 'Nacht', icon: ICON.moon },
  { id: 'frost', label: 'Frost', icon: ICON.snow },
];

const plan = (now) => ({
  from: 0, to: 24, now,
  segments: [
    { from: 0, to: 6, color: '#6366f1', label: 'Nacht' },
    { from: 6, to: 8, tone: 'warn', label: 'Komfort' },
    { from: 8, to: 16, tone: 'good', label: 'Eco' },
    { from: 16, to: 22.5, tone: 'warn', label: 'Komfort' },
    { from: 22.5, to: 24, color: '#6366f1', label: 'Nacht' },
  ],
});

function actions() {
  const room = { id: 'heat:3', title: 'Arbeitszimmer', icon: ICON.thermo };
  const bed = { id: 'heat:5', title: 'Schlafzimmer', icon: ICON.snow };
  const lamp = { id: 'light:1', title: 'Stehlampe', icon: ICON.bulb };
  return [
    {
      plugin: P, pluginName: 'Smart Home', id: 'heat:room:3', kind: 'button', title: 'Arbeitszimmer', device: room,
      widget: {
        label: 'Ist', value: 21.2, unit: '°C', status: 'Von Hand bis 16:00, dann Eco 18 °C', state: 'warn',
        badge: { icon: ICON.flame, value: 25, unit: '%', label: 'Ventil' },
        readings: [
          { id: 'hum', label: 'Feuchte', value: 48, unit: '%', icon: ICON.drop },
          { id: 'bat', label: 'Batterie', value: 80, unit: '%', icon: ICON.battery, state: 'good' },
        ],
        controls: [
          { id: 'sp', kind: 'stepper', label: 'Soll', value: 22, min: 5, max: 30, step: 0.5, unit: '°C' },
          // set by hand: no preset is active
          { id: 'preset', kind: 'choice', label: 'Preset', value: null, options: PRESETS },
        ],
        timeline: plan(6.87),
      },
    },
    { plugin: P, pluginName: 'Smart Home', id: 'heat:plan:3', kind: 'button', title: 'Zurück zum Plan', icon: ICON.clock, device: room },
    {
      plugin: P, pluginName: 'Smart Home', id: 'heat:room:5', kind: 'button', title: 'Schlafzimmer', device: bed,
      widget: {
        label: 'Ist', value: 16.4, unit: '°C', status: 'Fenster offen: Frostschutz, danach wieder Nacht 17 °C', state: 'warn',
        badge: { icon: ICON.battery, value: 5, unit: '%', state: 'crit', label: 'Batterie' },
        readings: [{ id: 'win', label: 'Fenster offen', icon: ICON.window, state: 'warn' }],
        controls: [
          { id: 'sp', kind: 'stepper', label: 'Soll', value: 7, min: 5, max: 30, step: 0.5, unit: '°C', disabled: true },
          { id: 'preset', kind: 'choice', label: 'Preset', value: 'frost', options: PRESETS, disabled: true },
        ],
        // a broken day bar (overlapping segments): only the bar is missing
        timeline: { segments: [{ from: 0, to: 8 }, { from: 6, to: 24 }] },
      },
    },
    {
      plugin: P, pluginName: 'Smart Home', id: 'heat:away', kind: 'toggle', title: 'Heizung abwesend', subtitle: 'Alle Räume auf Eco',
      icon: ICON.away, state: 'off', targets: true, verbs: { on: 'Abwesend', off: 'Zu Hause' }, confirmWhen: 'on',
    },
    { plugin: P, pluginName: 'Smart Home', id: 'chain:night', kind: 'button', title: 'Gute Nacht', subtitle: 'Logikkette: Lichter aus, Heizung Nacht', icon: ICON.night, confirm: true },
    {
      plugin: P, pluginName: 'Smart Home', id: 'light:1', kind: 'toggle', title: 'Stehlampe', state: 'on', device: lamp,
      widget: { state: 'on', status: 'An seit 18:04', controls: [{ id: 'bri', kind: 'slider', label: 'Helligkeit', value: 60, min: 0, max: 100, step: 10, unit: '%' }] },
    },
  ];
}

module.exports = { actions, PLUGIN: P, ICON };
