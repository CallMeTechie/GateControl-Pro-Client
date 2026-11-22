'use strict';

/**
 * The plugins' quick actions of the mock server (GET /api/v1/client/actions,
 * POST /api/v1/client/actions/<plugin>/<id>; server src/routes/api/client/actions.js,
 * fields up to 1.317.1). Without `server.setActions()` the routes answer 404
 * like a server before quick actions.
 *
 * The state is the test's: `actions` (the list as the server lists it, changed
 * by runs), `log` (every run: { plugin, id, body }) and `onRun(plugin, id, body)`
 * — return { status, body } to answer a run yourself, or nothing for the
 * default: a control of the widget takes the value (409 control_disabled while
 * it is disabled, 400 for an unknown control / value), a toggle the state, a
 * button answers ok; 404 for an action that is not listed.
 */

function createActions({ actions = [], onRun = null } = {}) {
  const state = { actions: JSON.parse(JSON.stringify(actions)), log: [], onRun, listed: 0 };

  function run(plugin, id, body) {
    state.log.push({ plugin, id, body });
    if (state.onRun) {
      const r = state.onRun(plugin, id, body);
      if (r) return r;
    }
    const a = state.actions.find((x) => x.plugin === plugin && x.id === id);
    if (!a) return { status: 404, body: { ok: false, error: 'not_found' } };
    if (body.control != null) {
      const c = a.widget && (a.widget.controls || []).find((x) => x.id === body.control);
      if (!c) return { status: 400, body: { ok: false, error: 'invalid_control' } };
      if (c.disabled === true) return { status: 409, body: { ok: false, error: 'control_disabled' } };
      if (c.kind === 'choice' ? !c.options.some((o) => o.id === body.value) : typeof body.value !== 'number') return { status: 400, body: { ok: false, error: 'invalid_value' } };
      c.value = body.value;
      return { status: 200, body: { ok: true, message: null, state: null, widget: a.widget, unchanged: false } };
    }
    if (body.state != null) {
      if (a.kind !== 'toggle') return { status: 400, body: { ok: false, error: 'invalid_state' } };
      a.state = body.state;
      return { status: 200, body: { ok: true, message: null, state: a.state, widget: a.widget || null, unchanged: false } };
    }
    if (a.kind === 'toggle') a.state = a.state === 'on' ? 'off' : 'on';
    return { status: 200, body: { ok: true, message: null, state: a.kind === 'toggle' ? a.state : null, widget: a.widget || null, unchanged: false } };
  }

  return {
    state,
    /** GET /api/v1/client/actions → { status, body } */
    list() {
      state.listed += 1;
      return { status: 200, body: { ok: true, actions: state.actions } };
    },
    run,
  };
}

module.exports = { createActions };
