'use strict';

const { describe, it, beforeEach, afterEach, mock } = require('node:test');
const assert = require('node:assert/strict');
const RdpMonitor = require('../src/services/rdp/rdp-monitor');

function createMonitor() {
  const apiClient = {
    updateRdpSession: mock.fn(async () => ({})),
  };
  const log = {
    info: () => {},
    debug: () => {},
    warn: () => {},
  };
  const monitor = new RdpMonitor({ apiClient, log });
  return { monitor, apiClient };
}

describe('RdpMonitor', () => {
  let monitor;
  let apiClient;

  beforeEach(() => {
    ({ monitor, apiClient } = createMonitor());
  });

  afterEach(() => {
    monitor.stopAll();
  });

  describe('startTracking / stopTracking', () => {
    it('tracks a session by routeId', () => {
      monitor.startTracking(1, process.pid); // use own PID (known alive)
      const tracked = monitor.getTracked();
      assert.equal(tracked.length, 1);
      assert.equal(tracked[0].routeId, 1);
      assert.equal(tracked[0].pid, process.pid);
      assert.equal(tracked[0].alive, true);
    });

    it('stops tracking a session', () => {
      monitor.startTracking(1, process.pid);
      monitor.stopTracking(1);
      assert.equal(monitor.getTracked().length, 0);
    });

    it('replaces existing tracking for same routeId', () => {
      monitor.startTracking(1, 1234);
      monitor.startTracking(1, 5678);
      const tracked = monitor.getTracked();
      assert.equal(tracked.length, 1);
      assert.equal(tracked[0].pid, 5678);
    });

    it('tracks multiple sessions independently', () => {
      monitor.startTracking(1, process.pid);
      monitor.startTracking(2, process.pid);
      assert.equal(monitor.getTracked().length, 2);

      monitor.stopTracking(1);
      const remaining = monitor.getTracked();
      assert.equal(remaining.length, 1);
      assert.equal(remaining[0].routeId, 2);
    });

    it('stopTracking is safe for unknown routeId', () => {
      assert.doesNotThrow(() => monitor.stopTracking(999));
    });
  });

  describe('stopAll', () => {
    it('clears all tracked sessions', () => {
      monitor.startTracking(1, process.pid);
      monitor.startTracking(2, process.pid);
      monitor.startTracking(3, process.pid);
      monitor.stopAll();
      assert.equal(monitor.getTracked().length, 0);
    });

    it('is safe when no sessions tracked', () => {
      assert.doesNotThrow(() => monitor.stopAll());
    });
  });

  describe('getTracked', () => {
    it('returns duration in seconds', () => {
      monitor.startTracking(1, process.pid);
      const tracked = monitor.getTracked();
      assert.equal(typeof tracked[0].duration, 'number');
      assert.ok(tracked[0].duration >= 0);
    });

    it('returns empty array when nothing tracked', () => {
      assert.deepEqual(monitor.getTracked(), []);
    });

    it('detects dead processes', () => {
      // PID 999999 should not exist
      monitor.startTracking(1, 999999);
      const tracked = monitor.getTracked();
      assert.equal(tracked[0].alive, false);
    });
  });

  describe('_isProcessAlive', () => {
    it('returns true for own process', () => {
      assert.equal(monitor._isProcessAlive(process.pid), true);
    });

    it('returns false for non-existent PID', () => {
      assert.equal(monitor._isProcessAlive(999999), false);
    });
  });

  describe('session-timeout event', () => {
    it('emits session-timeout after configured delay', (t, done) => {
      monitor.on('session-timeout', (data) => {
        assert.equal(data.routeId, 1);
        assert.equal(data.pid, process.pid);
        monitor.stopAll();
        done();
      });

      // 100ms timeout for test speed
      monitor.startTracking(1, process.pid, 0.1);
    });

    it('does not emit timeout when sessionTimeout is null', (t, done) => {
      let emitted = false;
      monitor.on('session-timeout', () => { emitted = true; });

      monitor.startTracking(1, process.pid, null);

      setTimeout(() => {
        assert.equal(emitted, false);
        done();
      }, 200);
    });
  });
});
