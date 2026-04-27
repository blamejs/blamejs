"use strict";
/**
 * log — structured JSON application logger with request-id correlation.
 *
 * Distinct concern from lib/logger.js: logger.js is the framework's
 * own boot/operational chatter to console with `[blamejs:<name>] `
 * prefix (humans watching `npm start`). lib/log.js is the app-level
 * structured logger meant to be ingested by a log aggregator.
 *
 * Each line is one JSON object on a single line, terminated with `\n`.
 * Levels: debug (0) < info (1) < warn (2) < error (3) < fatal (4).
 * info-and-below routes to stdout; warn-and-up routes to stderr.
 *
 *   var log = b.log.create({
 *     level:   "info",            // env LOG_LEVEL > opts.level > "info"
 *     base:    { service: "myapp", version: "1.2.3" },
 *     redact:  true,              // run extras through lib/redact
 *   });
 *
 *   log.info("user logged in", { userId: "u-1" });
 *   log.error("payment failed", { orderId, err: e.message });
 *
 *   // Child with bound context
 *   var authLog = log.bind({ component: "auth" });
 *   authLog.info("password verified", { userId: "u-1" });
 *
 *   // Request correlation via AsyncLocalStorage (Node async context)
 *   await log.runWithRequestId("req-abc", async function () {
 *     log.info("inside request");   // → ..., "requestId": "req-abc"
 *   });
 *
 *   // Router middleware that allocates a requestId and binds it for
 *   // the entire request async chain
 *   r.use(log.middleware());
 *
 * Field merge order (last wins):
 *   1. base context from create()
 *   2. bound context from bind() (each ancestor up the chain)
 *   3. requestId from ALS (if set)
 *   4. extra arg from .info(msg, extra)
 *   5. core fields: timestamp, level, message
 *
 * Core fields cannot be overwritten by extras — log.info("hi", { level: "X" })
 * keeps level: "info" in the emitted line, with an _overwriteAttempt
 * flag if the operator tried to clobber.
 */

var redact = require("./redact");
var { FrameworkError } = require("./framework-error");
var { AsyncLocalStorage } = require("node:async_hooks");

var LEVELS = { debug: 0, info: 1, warn: 2, error: 3, fatal: 4 };
var LEVEL_NAMES = Object.keys(LEVELS);

class LogError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "LogError";
    this.permanent = true;
    this.isLogError = true;
  }
}

// Single ALS shared across all log instances so request-id propagates
// regardless of which instance emitted the line. Keyed map so
// operators can attach more than just requestId (e.g. tenantId).
var _als = new AsyncLocalStorage();

function _getStore() { return _als.getStore() || null; }

function _normalizeDestination(d, fallback) {
  if (d === "stdout") return process.stdout;
  if (d === "stderr") return process.stderr;
  if (d && typeof d.write === "function") return d;
  if (typeof d === "function") return { write: d };
  if (d === undefined || d === null) return fallback;
  throw new LogError("log/bad-destination",
    "destination must be 'stdout', 'stderr', a stream with .write, or a function");
}

function _normalizeLevel(level) {
  if (typeof level === "number") {
    if (level < 0 || level > 4 || !Number.isFinite(level)) {
      throw new LogError("log/bad-level", "numeric level must be 0-4");
    }
    return level;
  }
  if (typeof level === "string") {
    if (LEVELS[level] === undefined) {
      throw new LogError("log/bad-level",
        "level must be one of " + LEVEL_NAMES.join(", "));
    }
    return LEVELS[level];
  }
  throw new LogError("log/bad-level", "level must be a string or number");
}

var _CORE_FIELDS = ["timestamp", "level", "message", "requestId"];

function _mergeExtras(into, extras, redactExtras) {
  if (!extras || typeof extras !== "object") return false;
  var src = redactExtras ? redact.redact(extras) : extras;
  var keys = Object.keys(src);
  var clobberAttempt = false;
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    if (_CORE_FIELDS.indexOf(k) !== -1) {
      // Operator tried to overwrite a core field — preserve the core
      // value but flag it so misconfig surfaces in the line.
      clobberAttempt = true;
      continue;
    }
    into[k] = src[k];
  }
  return clobberAttempt;
}

function create(opts) {
  opts = opts || {};

  // Resolve initial level: env > opts > default
  var envLevel = process.env.LOG_LEVEL;
  var level;
  if (envLevel && LEVELS[envLevel] !== undefined) {
    level = LEVELS[envLevel];
  } else if (opts.level !== undefined) {
    level = _normalizeLevel(opts.level);
  } else {
    level = LEVELS.info;
  }

  var stdoutDest = _normalizeDestination(opts.destination, process.stdout);
  var stderrDest = _normalizeDestination(opts.errorDestination, process.stderr);

  var format    = opts.format || "json"; // reserved for future formats
  if (format !== "json") {
    throw new LogError("log/bad-format",
      "only 'json' format is supported (got '" + format + "')");
  }
  var redactOn  = opts.redact !== false;
  var base      = opts.base ? Object.assign({}, opts.base) : {};

  // Clock injection lets tests pin timestamps deterministically.
  var clock = typeof opts.clock === "function" ? opts.clock : function () { return new Date(); };

  function _emit(levelName, message, extras, boundChain) {
    if (LEVELS[levelName] < level) return;

    var entry = {};
    entry.timestamp = clock().toISOString();
    entry.level     = levelName;
    entry.message   = typeof message === "string" ? message : String(message);

    // Merge base, then each ancestor's bound context (root → leaf)
    Object.assign(entry, base);
    if (boundChain) {
      for (var i = 0; i < boundChain.length; i++) Object.assign(entry, boundChain[i]);
    }

    // Request id from ALS — overrides only if not already set by base/bound
    var store = _getStore();
    if (store && store.requestId && entry.requestId === undefined) {
      entry.requestId = store.requestId;
    }
    // Merge any other ALS-bound fields (operator may have set tenantId etc.)
    if (store && store._extra) {
      var ekeys = Object.keys(store._extra);
      for (var j = 0; j < ekeys.length; j++) {
        var ek = ekeys[j];
        if (entry[ek] === undefined) entry[ek] = store._extra[ek];
      }
    }

    // Re-stamp core fields — entries from base/bound context cannot
    // overwrite timestamp/level/message
    entry.timestamp = clock().toISOString();
    entry.level     = levelName;
    entry.message   = typeof message === "string" ? message : String(message);

    var clobbered = _mergeExtras(entry, extras, redactOn);
    if (clobbered) entry._overwriteAttempt = true;

    var line;
    try { line = JSON.stringify(entry) + "\n"; }
    catch (_e) {
      // Circular ref or non-serializable extra — emit a fallback line.
      line = JSON.stringify({
        timestamp: entry.timestamp,
        level:     levelName,
        message:   entry.message,
        _logError: "extras not serializable",
      }) + "\n";
    }

    var dest = (LEVELS[levelName] >= LEVELS.error) ? stderrDest : stdoutDest;
    try { dest.write(line); }
    catch (_e) { /* destination write best-effort — never throw out of a log call */ }
  }

  function _makeInstance(boundChain) {
    function child(extra) {
      if (!extra || typeof extra !== "object") {
        throw new LogError("log/bad-bind", "bind(extra) requires an object");
      }
      // Preserve frozen ancestor chain; append a copy so callers can
      // mutate their original without affecting the bound logger.
      var nextChain = boundChain.concat([Object.assign({}, extra)]);
      return _makeInstance(nextChain);
    }

    function level_in(name)  { return LEVELS[name] !== undefined && LEVELS[name] >= level; }
    function setLevel(l)     { level = _normalizeLevel(l); }
    function getLevel()      { return LEVEL_NAMES[level]; }

    function debug(msg, extra) { _emit("debug", msg, extra, boundChain); }
    function info(msg, extra)  { _emit("info",  msg, extra, boundChain); }
    function warn(msg, extra)  { _emit("warn",  msg, extra, boundChain); }
    function error(msg, extra) { _emit("error", msg, extra, boundChain); }
    function fatal(msg, extra) { _emit("fatal", msg, extra, boundChain); }

    function runWithRequestId(id, fn) {
      var store = { requestId: id || null, _extra: {} };
      return _als.run(store, fn);
    }
    function runWithContext(ctx, fn) {
      var existing = _getStore();
      var rid = (ctx && ctx.requestId) || (existing && existing.requestId) || null;
      var extra = Object.assign({},
        existing && existing._extra ? existing._extra : {},
        ctx || {});
      delete extra.requestId;
      return _als.run({ requestId: rid, _extra: extra }, fn);
    }
    function getRequestId() {
      var s = _getStore();
      return s ? s.requestId : null;
    }

    function middleware(mwOpts) {
      mwOpts = mwOpts || {};
      var headerName = (mwOpts.headerName || "x-request-id").toLowerCase();
      var setOnRes   = mwOpts.setHeader !== false;
      var generate   = typeof mwOpts.generate === "function"
        ? mwOpts.generate
        : function () {
          // 16 random hex chars — short, sufficient correlation entropy
          return require("crypto").randomBytes(8).toString("hex");
        };
      return function logRequestIdMiddleware(req, res, next) {
        var inbound = req.headers && req.headers[headerName];
        var id = (typeof inbound === "string" && inbound.length > 0 && inbound.length <= 200)
          ? inbound
          : generate();
        // Strip CRLF defensively before reflecting back into a header
        id = String(id).replace(/[\r\n]/g, "");
        req.id = id;
        if (setOnRes && typeof res.setHeader === "function") {
          try { res.setHeader("X-Request-Id", id); } catch (_e) { /* header may be locked */ }
        }
        runWithRequestId(id, function () { next(); });
      };
    }

    return {
      debug:            debug,
      info:             info,
      warn:             warn,
      error:            error,
      fatal:            fatal,
      bind:             child,
      setLevel:         setLevel,
      getLevel:         getLevel,
      isLevelEnabled:   level_in,
      runWithRequestId: runWithRequestId,
      runWithContext:   runWithContext,
      getRequestId:     getRequestId,
      middleware:       middleware,
    };
  }

  return _makeInstance([]);
}

module.exports = {
  create:           create,
  LEVELS:           LEVELS,
  LogError:         LogError,
  // Module-level helpers for code paths that don't have a logger
  // instance handy but still need to read ALS state.
  getRequestId:     function () { var s = _getStore(); return s ? s.requestId : null; },
  runWithRequestId: function (id, fn) { return _als.run({ requestId: id || null, _extra: {} }, fn); },
};
