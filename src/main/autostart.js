/**
 * Autostart with Windows (Pro).
 *
 * The app runs with requireAdministrator, and Windows does not start
 * elevated programs from the Run key (login items) → a Task Scheduler task
 * with a logon trigger. The task comes from a task XML (core
 * utils/autostart-task): no 3-day execution time limit, starts and keeps
 * running on battery, normal priority. Called on every start while "start
 * with Windows" is on; /F replaces the existing task, so installations with
 * the old task (Task Scheduler defaults) get the corrected one on their next
 * start or update.
 */

'use strict';

const AUTOSTART_TASK = 'GateControlProAutostart';

/**
 * @param {object} o
 * @param {object} o.autostartTask - core utils/autostart-task
 * @param {(file: string, args: string[], opts?: object) => Promise<any>} o.execFile
 * @param {() => string} o.getExePath - app.getPath('exe')
 * @param {() => string} o.getTempPath - app.getPath('temp') (only without %ProgramData%)
 * @param {NodeJS.ProcessEnv} [o.env]
 * @param {object} o.log
 * @returns {(enabled: boolean) => Promise<void>}
 */
function createAutostart(o) {
  const env = o.env || process.env;
  const run = (file, args) => o.execFile(file, args, { windowsHide: true });

  return async function setAutostartTask(enabled) {
    if (enabled) {
      const exePath = o.getExePath();
      const mode = await o.autostartTask.registerAutostartTask({
        taskName: AUTOSTART_TASK,
        command: exePath,
        userId: o.autostartTask.currentUserId(env),
        description: 'Starts GateControl Pro Client when you sign in to Windows.',
        // The task XML goes into a new folder there (owned by the
        // administrators); in the user's temp folder a normal process could
        // swap the file before the elevated schtasks reads it.
        dir: env.ProgramData || o.getTempPath(),
        execFile: run,
        log: o.log,
      });
      o.log.info(`Autostart enabled: ${exePath} (task ${mode})`);
    } else {
      await run('schtasks', o.autostartTask.schtasksDeleteArgs(AUTOSTART_TASK));
      o.log.info('Autostart disabled');
    }
  };
}

module.exports = { createAutostart, AUTOSTART_TASK };
