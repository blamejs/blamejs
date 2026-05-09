"use strict";
/**
 * b.daemon — PID-file + signal-handling glue around b.appShutdown plus a
 * cross-platform detached spawn for `start({ command, args })`.
 *
 * Two operator paths:
 *
 *   1. Foreground service mode (no `command`):
 *
 *        var d = b.daemon.start({
 *          pidFile:    "/var/run/myapp.pid",
 *          logFile:    "/var/log/myapp.log",
 *          signals:    ["SIGTERM", "SIGINT", "SIGHUP"],
 *        });
 *        // Process now owns the pidFile, redirects stdout/stderr to logFile,
 *        // and shutdown signals route through b.appShutdown.
 *
 *   2. Detached fork mode (`command` + `args`):
 *
 *        var d = b.daemon.start({
 *          pidFile:  "/var/run/myapp.pid",
 *          logFile:  "/var/log/myapp.log",
 *          command:  process.execPath,
 *          args:     ["/srv/myapp/index.js"],
 *        });
 *        // Spawns the child, writes its PID to pidFile, returns
 *        // immediately. Parent exits via process.exit(0) at caller's
 *        // discretion. stdout/stderr of the child are redirected to
 *        // logFile.
 *
 * Stop:
 *
 *   var r = await b.daemon.stop({
 *     pidFile: "/var/run/myapp.pid",
 *     signal:  "SIGTERM",                              // default
 *   });
 *   // Sends SIGTERM, waits up to 30s for exit, then SIGKILL.
 *   // Returns { stopped: true|false, pid }.
 *
 * Stale-PID handling: when pidFile exists but the recorded PID is no
 * longer alive, daemon cleans up the file and emits
 * `daemon.stale_pid_cleaned` before continuing. Cross-process linkage
 * uses b.appShutdown.pidLock under the hood, which adds the standard
 * O_EXCL atomic-create + signal-0 liveness probe + reap-on-stale flow.
 *
 * Audit: every state change emits via b.audit.safeEmit:
 *   - daemon.started           pidFile + logFile + commandKind + pid
 *   - daemon.stopped           pidFile + signal + waitMs
 *   - daemon.stale_pid_cleaned pidFile + stalePid
 */

var fs = require("fs");
var path = require("path");
var nb = require("./numeric-bounds");
var appShutdown = require("./app-shutdown");
var processSpawn = require("./process-spawn");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var atomicFile = require("./atomic-file");
var validateOpts = require("./validate-opts");
var C = require("./constants");
var { boot } = require("./log");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var DaemonError = defineClass("DaemonError", { alwaysPermanent: true });
var log = boot("daemon");

// Tunables. Operator overrides via opts on stop(); for start() the
// defaults are baked in so the operator surface stays minimal.
var DEFAULT_STOP_TIMEOUT_MS = C.TIME.seconds(30);
var DEFAULT_STOP_SIGNAL     = "SIGTERM";
var DEFAULT_POLL_MS         = 100;
var DEFAULT_LOG_FILE_MODE   = 0o600;

function _safeAuditEmit(action, outcome, metadata) {
  try {
    audit().safeEmit({
      action:   action,
      outcome:  outcome || "success",
      metadata: metadata || {},
    });
  } catch (_e) { /* drop-silent — by design */ }
}

function _isLivePid(pid) {
  if (typeof pid !== "number" || !isFinite(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (e) { return e && e.code === "EPERM"; }
}

function _readPidFile(pidFile) {
  try {
    var raw = fs.readFileSync(pidFile, "utf8");
    var pid = parseInt(String(raw).trim(), 10);
    return isFinite(pid) && pid > 0 ? pid : null;
  } catch (_e) { return null; }
}

function _validateStartOpts(opts) {
  validateOpts.requireObject(opts, "daemon.start", DaemonError, "daemon/bad-opts");
  validateOpts.requireNonEmptyString(opts.pidFile,
    "daemon.start: opts.pidFile (absolute path recommended)",
    DaemonError, "daemon/bad-pid-file");
  validateOpts.optionalNonEmptyString(opts.logFile,
    "daemon.start: opts.logFile", DaemonError, "daemon/bad-log-file");
  validateOpts.optionalNonEmptyStringArray(opts.signals,
    "daemon.start: opts.signals", DaemonError, "daemon/bad-signals");
  if (Array.isArray(opts.signals) && opts.signals.length === 0) {
    throw new DaemonError("daemon/bad-signals",
      "daemon.start: opts.signals must be a non-empty array of POSIX signal names");
  }
  validateOpts.optionalNonEmptyString(opts.command,
    "daemon.start: opts.command (path to executable)",
    DaemonError, "daemon/bad-command");
  if (opts.args !== undefined && !Array.isArray(opts.args)) {
    throw new DaemonError("daemon/bad-args",
      "daemon.start: opts.args must be an array of strings when present");
  }
  if (opts.command === undefined && opts.args !== undefined) {
    throw new DaemonError("daemon/bad-args",
      "daemon.start: opts.args requires opts.command");
  }
}

function _validateStopOpts(opts) {
  validateOpts.requireObject(opts, "daemon.stop", DaemonError, "daemon/bad-opts");
  validateOpts.requireNonEmptyString(opts.pidFile,
    "daemon.stop: opts.pidFile", DaemonError, "daemon/bad-pid-file");
  validateOpts.optionalNonEmptyString(opts.signal,
    "daemon.stop: opts.signal", DaemonError, "daemon/bad-signal");
  nb.requirePositiveFiniteIntIfPresent(opts.timeoutMs,
    "daemon.stop: opts.timeoutMs", DaemonError, "daemon/bad-timeout");
  nb.requirePositiveFiniteIntIfPresent(opts.pollMs,
    "daemon.stop: opts.pollMs", DaemonError, "daemon/bad-poll");
}

function _maybeReapStale(pidFile) {
  var existing = _readPidFile(pidFile);
  if (existing === null) return false;
  if (_isLivePid(existing) && existing !== process.pid) {
    // Live owner — caller will receive a daemon/already-running below.
    return false;
  }
  if (existing === process.pid) return false;
  // Stale: PID is gone (or signal-0 returned ESRCH). Reap + audit.
  try { fs.unlinkSync(pidFile); } catch (_e) { /* race: another reaper */ }
  _safeAuditEmit("daemon.stale_pid_cleaned", "success", {
    pidFile:  pidFile,
    stalePid: existing,
  });
  return true;
}

// Open the log file (append mode, 0o600) and return the fd.
// Used both by detached-spawn (passed via stdio) and by foreground
// redirect of the current process' stdout/stderr.
function _openLogFd(logFile) {
  if (typeof logFile !== "string" || logFile.length === 0) return null;
  atomicFile.ensureDir(path.dirname(logFile));
  var fd = fs.openSync(logFile, "a", DEFAULT_LOG_FILE_MODE);
  return fd;
}

// Redirect the current process's stdout/stderr file descriptors at the
// given fd. Implemented via fs.writeSync streams: Node doesn't expose a
// portable dup2, so we replace process.stdout.write / process.stderr.write
// with a writer that pushes to the log fd. This is the standard
// pattern for foreground daemons that don't want to lose output when
// detached from a terminal.
function _redirectStdio(fd) {
  if (typeof fd !== "number") return;
  function _writer(chunk, encOrCb, maybeCb) {
    var enc = typeof encOrCb === "string" ? encOrCb : "utf8";
    var cb  = typeof encOrCb === "function" ? encOrCb : maybeCb;
    var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), enc);
    try { fs.writeSync(fd, buf); }
    catch (_e) { /* log fd closed underneath us — drop */ }
    if (typeof cb === "function") cb();
    return true;
  }
  process.stdout.write = _writer;
  process.stderr.write = _writer;
}

// Track foreground orchestrators per pidFile so stop() / repeat
// start() in the same process don't double-install signals.
var _foregroundOrchestrators = Object.create(null);

function start(opts) {
  _validateStartOpts(opts);
  var pidFile = opts.pidFile;
  var logFile = opts.logFile || null;
  var signals = Array.isArray(opts.signals) && opts.signals.length > 0
    ? opts.signals.slice()
    : ["SIGTERM", "SIGINT", "SIGHUP"];

  // Reap a stale pidfile if present, then attempt acquire.
  _maybeReapStale(pidFile);

  // Detached-fork mode — caller wants us to spawn the child, write its
  // PID into pidFile, and return without taking the lock ourselves.
  if (typeof opts.command === "string" && opts.command.length > 0) {
    var existingLive = _readPidFile(pidFile);
    if (existingLive !== null && _isLivePid(existingLive)) {
      throw new DaemonError("daemon/already-running",
        "daemon.start: pidFile '" + pidFile + "' held by live PID " + existingLive);
    }
    var logFd = logFile ? _openLogFd(logFile) : "ignore";
    var child;
    try {
      child = processSpawn.spawn(opts.command, opts.args || [], {
        detached: true,
        stdio:    ["ignore", logFd, logFd],
        cwd:      typeof opts.cwd === "string" ? opts.cwd : undefined,
      });
    } catch (e) {
      try { if (typeof logFd === "number") fs.closeSync(logFd); }
      catch (_c) { /* best-effort */ }
      throw new DaemonError("daemon/spawn-failed",
        "daemon.start: spawn failed: " + ((e && e.message) || String(e)));
    }
    // Write the child's PID via atomic temp+rename so a concurrent
    // observer never sees a half-written pidFile.
    atomicFile.ensureDir(path.dirname(pidFile));
    var pidStr = String(child.pid) + "\n";
    atomicFile.writeSync(pidFile, pidStr, { fileMode: 0o600 });
    // Detach so the child survives parent exit.
    try { child.unref(); } catch (_u) { /* best-effort */ }
    if (typeof logFd === "number") {
      // Parent doesn't need its handle to the log; child inherited it.
      try { fs.closeSync(logFd); } catch (_c) { /* best-effort */ }
    }
    _safeAuditEmit("daemon.started", "success", {
      pidFile:     pidFile,
      logFile:     logFile,
      commandKind: "detached-fork",
      pid:         child.pid,
    });
    log("daemon started (detached) pid=" + child.pid + " pidFile=" + pidFile);
    return { pid: child.pid, pidFile: pidFile, logFile: logFile, mode: "detached" };
  }

  // Foreground mode — current process owns pidFile + signals.
  var lock = appShutdown.pidLock(pidFile);
  try { lock.acquire(); }
  catch (e) {
    if (e && /pidlock-held/.test(e.code || "")) {
      throw new DaemonError("daemon/already-running",
        "daemon.start: pidFile '" + pidFile + "' already held: " + e.message);
    }
    throw new DaemonError("daemon/pid-acquire-failed",
      "daemon.start: failed to acquire pidFile '" + pidFile + "': " +
      ((e && e.message) || String(e)));
  }

  var logFdForeground = null;
  if (logFile) {
    try {
      logFdForeground = _openLogFd(logFile);
      _redirectStdio(logFdForeground);
    } catch (e) {
      try { lock.release(); } catch (_r) { /* best-effort */ }
      throw new DaemonError("daemon/log-open-failed",
        "daemon.start: failed to open logFile '" + logFile + "': " +
        ((e && e.message) || String(e)));
    }
  }

  var orchestrator = appShutdown.create({
    signals:               signals,
    installSignalHandlers: true,
    phases: [
      {
        name: "pidLock-release",
        run:  function () {
          try { lock.release(); } catch (_e) { /* best-effort */ }
          if (logFdForeground !== null) {
            try { fs.closeSync(logFdForeground); } catch (_c) { /* best-effort */ }
          }
        },
        timeoutMs: C.TIME.seconds(2),
      },
    ],
  });
  _foregroundOrchestrators[pidFile] = orchestrator;

  _safeAuditEmit("daemon.started", "success", {
    pidFile:     pidFile,
    logFile:     logFile,
    commandKind: "foreground",
    pid:         process.pid,
    signals:     signals,
  });
  log("daemon started (foreground) pid=" + process.pid + " pidFile=" + pidFile);

  return {
    pid:           process.pid,
    pidFile:       pidFile,
    logFile:       logFile,
    mode:          "foreground",
    orchestrator:  orchestrator,
    addPhase:      orchestrator.addPhase,
    shutdown:      orchestrator.shutdown,
  };
}

async function stop(opts) {
  _validateStopOpts(opts);
  var pidFile   = opts.pidFile;
  var signal    = opts.signal || DEFAULT_STOP_SIGNAL;
  var timeoutMs = typeof opts.timeoutMs === "number" ? opts.timeoutMs : DEFAULT_STOP_TIMEOUT_MS;
  var pollMs    = typeof opts.pollMs    === "number" ? opts.pollMs    : DEFAULT_POLL_MS;

  var pid = _readPidFile(pidFile);
  if (pid === null) {
    return { stopped: false, pid: null, reason: "no-pidfile" };
  }
  if (!_isLivePid(pid)) {
    // Stale — clean up and report.
    try { fs.unlinkSync(pidFile); } catch (_e) { /* best-effort */ }
    _safeAuditEmit("daemon.stale_pid_cleaned", "success", { pidFile: pidFile, stalePid: pid });
    return { stopped: false, pid: pid, reason: "stale" };
  }

  var t0 = Date.now();
  // First signal — typically SIGTERM. Wait up to timeoutMs for exit.
  try { process.kill(pid, signal); }
  catch (e) {
    if (e && e.code === "ESRCH") {
      // Died between read and kill — cleanup + report.
      try { fs.unlinkSync(pidFile); } catch (_u) { /* best-effort */ }
      _safeAuditEmit("daemon.stopped", "success", {
        pidFile: pidFile, signal: signal, waitMs: Date.now() - t0, escalated: false,
      });
      return { stopped: true, pid: pid, signal: signal };
    }
    throw new DaemonError("daemon/kill-failed",
      "daemon.stop: kill(" + pid + ", " + signal + ") failed: " + e.message);
  }

  var deadline = t0 + timeoutMs;
  while (Date.now() < deadline) {
    if (!_isLivePid(pid)) {
      try { fs.unlinkSync(pidFile); } catch (_u) { /* best-effort */ }
      _safeAuditEmit("daemon.stopped", "success", {
        pidFile: pidFile, signal: signal, waitMs: Date.now() - t0, escalated: false,
      });
      return { stopped: true, pid: pid, signal: signal };
    }
    await safeAsync.sleep(pollMs, { signal: opts.abortSignal });
  }

  // Timed out — escalate to SIGKILL.
  try { process.kill(pid, "SIGKILL"); }
  catch (e) {
    if (!(e && e.code === "ESRCH")) {
      throw new DaemonError("daemon/kill-failed",
        "daemon.stop: SIGKILL escalation failed for pid " + pid + ": " + e.message);
    }
  }
  // Wait briefly for the kernel to reap.
  var killDeadline = Date.now() + C.TIME.seconds(2);
  while (Date.now() < killDeadline) {
    if (!_isLivePid(pid)) break;
    await safeAsync.sleep(pollMs, { signal: opts.abortSignal });
  }
  try { fs.unlinkSync(pidFile); } catch (_u) { /* best-effort */ }
  _safeAuditEmit("daemon.stopped", "success", {
    pidFile: pidFile, signal: "SIGKILL", waitMs: Date.now() - t0, escalated: true,
  });
  return { stopped: true, pid: pid, signal: "SIGKILL", escalated: true };
}

// Test-only — drop process-wide foreground orchestrator state so smoke
// tests can re-run start() in the same process without leaking signal
// handlers across cases.
function _resetForTest() {
  var keys = Object.keys(_foregroundOrchestrators);
  for (var i = 0; i < keys.length; i++) {
    try { _foregroundOrchestrators[keys[i]]._resetForTest(); } catch (_e) { /* best-effort */ }
  }
  _foregroundOrchestrators = Object.create(null);
}

module.exports = {
  start:                start,
  stop:                 stop,
  DaemonError:          DaemonError,
  DEFAULT_STOP_SIGNAL:  DEFAULT_STOP_SIGNAL,
  DEFAULT_STOP_TIMEOUT_MS: DEFAULT_STOP_TIMEOUT_MS,
  _resetForTest:        _resetForTest,
};
