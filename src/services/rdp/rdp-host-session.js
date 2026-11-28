'use strict';

const EventEmitter = require('events');
const { encode, LineDecoder } = require('./rdp-host-protocol');

/**
 * One gc-rdp-host.exe process (one session window). Started without arguments — credentials only
 * ever go over its stdin in the connect message. Emits every message of the host by its type
 * ('state', 'disconnected', 'action', …) plus 'exit' { code } once the process is gone.
 *
 *   const s = new RdpHostSession({ exePath, spawn, log });
 *   const ready = await s.start();      // { pid, version, mstscax } or throws (no exe, no ready in time)
 *   s.send({ type: 'connect', … });
 */
class RdpHostSession extends EventEmitter {
  constructor({ exePath, spawn, log, readyTimeoutMs = 15000, killAfterMs = 8000 }) {
    super();
    this.exePath = exePath;
    this.spawn = spawn || require('child_process').spawn;
    this.log = log || { info() {}, warn() {}, debug() {} };
    this.readyTimeoutMs = readyTimeoutMs;
    this.killAfterMs = killAfterMs;
    this.proc = null;
    this.pid = null;
    this.ready = null;
    this.exited = false;
    this._killTimer = null;
  }

  /** Starts the process and waits for its ready line. */
  start() {
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.kill();
        reject(err);
      };
      let proc;
      try {
        proc = this.spawn(this.exePath, [], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: false });
      } catch (err) {
        reject(err);
        return;
      }
      this.proc = proc;
      this.pid = proc.pid || null;
      const timer = setTimeout(() => fail(Object.assign(new Error('gc-rdp-host: no ready line in time'), { code: 'host_timeout' })), this.readyTimeoutMs);

      const decoder = new LineDecoder((msg) => {
        if (msg.type === 'ready' && !settled) {
          settled = true;
          clearTimeout(timer);
          this.ready = msg;
          if (msg.pid) this.pid = msg.pid;
          resolve(msg);
          return;
        }
        this.emit('message', msg);
        this.emit(msg.type, msg);
      }, (why) => this.log.warn(`gc-rdp-host: ${why}`));

      proc.stdout.on('data', (d) => decoder.push(d));
      if (proc.stderr) proc.stderr.on('data', (d) => this.log.debug(`gc-rdp-host stderr: ${String(d).slice(0, 300)}`));
      if (proc.stdin) proc.stdin.on('error', () => {}); // the host already gone: its exit says the rest
      proc.on('error', (err) => {
        if (!settled) fail(err);
        else this.log.warn(`gc-rdp-host: ${err.message}`);
      });
      proc.on('exit', (code) => {
        this.exited = true;
        clearTimeout(this._killTimer);
        if (!settled) fail(Object.assign(new Error(`gc-rdp-host exited (${code}) before ready`), { code: 'host_exit' }));
        this.emit('exit', { code });
      });
    });
  }

  /** One message to the host. False when it is gone. */
  send(msg) {
    if (!this.proc || this.exited || !this.proc.stdin || this.proc.stdin.destroyed) return false;
    try {
      this.proc.stdin.write(encode(msg));
      return true;
    } catch (err) {
      this.log.warn(`gc-rdp-host send ${msg && msg.type}: ${err.message}`);
      return false;
    }
  }

  /** Disconnect and close the window; killed when it does not end in time. */
  close() {
    this.send({ type: 'close' });
    this._scheduleKill();
  }

  /** The app quits: closing stdin makes the host disconnect and exit by itself. */
  end() {
    try { if (this.proc && this.proc.stdin && !this.proc.stdin.destroyed) this.proc.stdin.end(); } catch { /* gone */ }
    this._scheduleKill();
  }

  _scheduleKill() {
    if (this.exited || this._killTimer) return;
    this._killTimer = setTimeout(() => this.kill(), this.killAfterMs);
    if (this._killTimer.unref) this._killTimer.unref();
  }

  kill() {
    if (!this.proc || this.exited) return;
    try { this.proc.kill(); } catch { /* gone */ }
  }
}

module.exports = RdpHostSession;
