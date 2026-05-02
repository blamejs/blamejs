"use strict";
/**
 * Log streaming dispatcher — operational logs to one or many sinks with
 * redaction and bidirectional command channel.
 *
 * Same dispatcher pattern: backends configured per-name with a protocol
 * + protocol-specific options. Built-in protocols:
 *
 *   local    — append-only file with rotation
 *   webhook  — generic HTTP POST; covers Splunk HEC, Datadog, Sumo
 *              Logic, Loki, custom collectors that ingest JSON
 *   otlp     — OpenTelemetry Protocol over HTTP/JSON; ResourceLogs
 *              envelope with severity mapping per OTel Logs Data
 *              Model. Operators with an OTel collector running
 *              (k8s, cloud) get standard log forwarding without a
 *              vendor-specific adapter.
 *   cloudwatch — AWS CloudWatch Logs (PutLogEvents) over HTTPS with
 *              SigV4. Operator pre-creates the log group + log stream;
 *              the framework signs and POSTs batches respecting the
 *              10K-event / 1 MiB / 256 KiB-per-event AWS caps. Honors
 *              IAM role + STS session tokens.
 *
 * Adapters listed as deferred and surfacing a clear error when
 * selected:
 *
 *   syslog — RFC 5424 syslog over TLS
 *
 * Every emit goes through lib/redact.js BEFORE any sink sees it. PHI/PCI
 * never reaches operational logs even on a misconfigured field name —
 * pattern detectors catch credit-card-shaped values, JWTs, PEM blocks,
 * AWS access keys, vault-sealed strings, SSN-shaped values, etc.
 *
 * Bidirectional command channel:
 *   logStream.onIncoming(handler) registers a handler for inbound events.
 *   Operators wire their HTTP route (or other transport — webhook receiver,
 *   SSE, message-queue subscriber) to call logStream.deliverIncoming(payload)
 *   which invokes registered handlers. The framework doesn't prescribe the
 *   transport — it provides the dispatch.
 *
 * Public API:
 *   logStream.init({ sinks: { name: { protocol, ... } }, classification? })
 *   logStream.emit(level, message, meta?)         (sync — non-blocking)
 *   logStream.info(msg, meta?) / .warn / .error / .debug
 *   logStream.onIncoming(handler)                 (handler returns Promise)
 *   logStream.deliverIncoming(payload, opts?)
 *   logStream.shutdown()
 *   logStream.listSinks()                         → [{ name, protocol, stats }]
 */
var localProto      = require("./log-stream-local");
var webhookProto    = require("./log-stream-webhook");
var otlpProto       = require("./log-stream-otlp");
var cloudwatchProto = require("./log-stream-cloudwatch");
var redactor        = require("./redact");
var lazyRequire     = require("./lazy-require");
var protocolDispatcher = require("./protocol-dispatcher");
var { LogStreamError } = require("./framework-error");

var dispatcher = protocolDispatcher.create({
  name:       "log-stream",
  errorClass: LogStreamError,
  protocols:  {
    "local":      localProto,
    "webhook":    webhookProto,
    "otlp":       otlpProto,
    "cloudwatch": cloudwatchProto,
  },
  deferred:   {
    "syslog":     { description: "RFC 5424 syslog over TLS" },
  },
  fallbackProtocol: "local",
});

var LEVELS = ["debug", "info", "warn", "error"];
var LEVEL_PRIORITY = { debug: 10, info: 20, warn: 30, error: 40 };

var _err = LogStreamError.factory;

var audit = lazyRequire(function () { return require("./audit"); });

var initialized = false;
var sinks = {};
var minLevel = "info";
var incomingHandlers = [];

function init(opts) {
  if (initialized) return;
  if (!opts || !opts.sinks) throw new Error("logStream.init({ sinks }) is required");

  sinks = {};
  for (var name in opts.sinks) {
    var cfg = opts.sinks[name];
    var proto = dispatcher.resolve(cfg.protocol);
    sinks[name] = {
      name:     name,
      protocol: cfg.protocol,
      raw:      proto.create(cfg),
      levelFilter: cfg.minLevel || null,
    };
  }

  minLevel = (opts.minLevel || "info").toLowerCase();
  initialized = true;
}

function _shouldEmit(level, sinkLevelFilter) {
  var threshold = sinkLevelFilter ? LEVEL_PRIORITY[sinkLevelFilter] : LEVEL_PRIORITY[minLevel];
  return LEVEL_PRIORITY[level] >= threshold;
}

function emit(level, message, meta) {
  if (!initialized) return;
  if (LEVELS.indexOf(level) === -1) {
    throw _err("INVALID_LEVEL", "log level must be one of " + LEVELS.join(", "), true);
  }
  // Build the record. Redact metadata BEFORE distribution to any sink.
  var record = {
    ts:      Date.now(),
    level:   level,
    message: message == null ? null : String(message),
  };
  if (meta) {
    record.meta = redactor.redact(meta);
  }

  // Fire-and-forget to all sinks. Sink errors don't bubble — they're
  // captured by audit (system.log.sink-failure) so an external sink
  // outage doesn't take down the app's request handlers.
  Object.keys(sinks).forEach(function (name) {
    var sink = sinks[name];
    if (!_shouldEmit(level, sink.levelFilter)) return;
    Promise.resolve()
      .then(function () { return sink.raw.emit(record); })
      .catch(function (e) {
        audit().safeEmit({
          action:   "system.log.sink-failure",
          outcome:  "failure",
          reason:   (e && e.message) || String(e),
          metadata: { sink: name, level: level },
        });
      });
  });
}

function debug(message, meta) { emit("debug", message, meta); }
function info(message, meta)  { emit("info",  message, meta); }
function warn(message, meta)  { emit("warn",  message, meta); }
function error(message, meta) { emit("error", message, meta); }

// ---- Bidirectional incoming command channel ----

function onIncoming(handler) {
  if (typeof handler !== "function") {
    throw _err("INVALID_HANDLER", "onIncoming requires a function handler", true);
  }
  incomingHandlers.push(handler);
  return function () {
    var idx = incomingHandlers.indexOf(handler);
    if (idx >= 0) incomingHandlers.splice(idx, 1);
  };
}

async function deliverIncoming(payload, opts) {
  opts = opts || {};
  var redacted = redactor.redact(payload);
  // Audit-log the inbound command BEFORE invoking handlers — even handler
  // exceptions don't lose the receipt.
  audit().safeEmit({
    actor:    opts.actor || {},
    action:   "system.log.incoming",
    metadata: { payload: redacted, source: opts.source || null },
  });

  var results = [];
  for (var i = 0; i < incomingHandlers.length; i++) {
    try {
      results.push({ ok: true, value: await incomingHandlers[i](payload, opts) });
    } catch (e) {
      results.push({ ok: false, error: (e && e.message) || String(e) });
    }
  }
  return results;
}

async function shutdown() {
  if (!initialized) return;
  for (var name in sinks) {
    try {
      if (typeof sinks[name].raw.close === "function") await sinks[name].raw.close();
    } catch (_e) { /* best effort on shutdown */ }
  }
  sinks = {};
  incomingHandlers = [];
  initialized = false;
}

function listSinks() {
  if (!initialized) return [];
  return Object.keys(sinks).map(function (name) {
    var s = sinks[name];
    var stats = (typeof s.raw.stats === "function") ? s.raw.stats() : null;
    return { name: name, protocol: s.protocol, stats: stats };
  });
}

// ---- bootFromEnv ----
//
// Operator-friendly env-driven init that mirrors b.network.bootFromEnv.
// Reads BLAMEJS_LOG_STREAM_* env vars and constructs a single-sink
// configuration matching the operator's choice. Skipped silently when
// BLAMEJS_LOG_STREAM_PROTOCOL isn't set (operators using the in-code
// init() path keep their existing wiring).
//
// Recognised env vars:
//   BLAMEJS_LOG_STREAM_PROTOCOL    "local" | "webhook" | "otlp" | "cloudwatch"
//   BLAMEJS_LOG_STREAM_MIN_LEVEL   "debug" | "info" | "warn" | "error"
//
//   webhook + otlp shared:
//     BLAMEJS_LOG_STREAM_URL
//     BLAMEJS_LOG_STREAM_TOKEN              (auth: bearer)
//   otlp-only:
//     BLAMEJS_LOG_STREAM_SERVICE_NAME
//     BLAMEJS_LOG_STREAM_SERVICE_VERSION
//   cloudwatch-only (AWS_* are standard):
//     AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
//     BLAMEJS_LOG_STREAM_CLOUDWATCH_LOG_GROUP
//     BLAMEJS_LOG_STREAM_CLOUDWATCH_LOG_STREAM
//   local-only:
//     BLAMEJS_LOG_STREAM_PATH
function bootFromEnv(opts) {
  opts = opts || {};
  var env = opts.env || process.env;
  var proto = env.BLAMEJS_LOG_STREAM_PROTOCOL;
  if (!proto) return false;
  var sink = { protocol: proto };
  if (proto === "webhook") {
    sink.url = env.BLAMEJS_LOG_STREAM_URL;
    if (env.BLAMEJS_LOG_STREAM_TOKEN) {
      sink.auth  = "bearer";
      sink.token = env.BLAMEJS_LOG_STREAM_TOKEN;
    }
  } else if (proto === "otlp") {
    sink.url            = env.BLAMEJS_LOG_STREAM_URL;
    sink.serviceName    = env.BLAMEJS_LOG_STREAM_SERVICE_NAME    || "blamejs";
    sink.serviceVersion = env.BLAMEJS_LOG_STREAM_SERVICE_VERSION || null;
    if (env.BLAMEJS_LOG_STREAM_TOKEN) {
      sink.auth  = "bearer";
      sink.token = env.BLAMEJS_LOG_STREAM_TOKEN;
    }
  } else if (proto === "cloudwatch") {
    sink.region          = env.AWS_REGION;
    sink.accessKeyId     = env.AWS_ACCESS_KEY_ID;
    sink.secretAccessKey = env.AWS_SECRET_ACCESS_KEY;
    sink.sessionToken    = env.AWS_SESSION_TOKEN || null;
    sink.logGroupName    = env.BLAMEJS_LOG_STREAM_CLOUDWATCH_LOG_GROUP;
    sink.logStreamName   = env.BLAMEJS_LOG_STREAM_CLOUDWATCH_LOG_STREAM;
  } else if (proto === "local") {
    sink.path = env.BLAMEJS_LOG_STREAM_PATH;
  } else {
    throw _err("BAD_OPT",
      "BLAMEJS_LOG_STREAM_PROTOCOL='" + proto + "' is not one of " +
      "local | webhook | otlp | cloudwatch (or a custom backend wired via init())");
  }
  init({
    sinks:    { primary: sink },
    minLevel: env.BLAMEJS_LOG_STREAM_MIN_LEVEL || undefined,
  });
  return true;
}

function _resetForTest() {
  Object.keys(sinks).forEach(function (n) {
    try { if (sinks[n].raw.close) sinks[n].raw.close(); } catch (_e) {}
  });
  sinks = {};
  incomingHandlers = [];
  initialized = false;
  audit.reset();
}

module.exports = {
  init:               init,
  bootFromEnv:        bootFromEnv,
  emit:               emit,
  debug:              debug,
  info:               info,
  warn:               warn,
  error:              error,
  onIncoming:         onIncoming,
  deliverIncoming:    deliverIncoming,
  shutdown:           shutdown,
  listSinks:          listSinks,
  LEVELS:             LEVELS,
  PROTOCOLS:          dispatcher.protocols,
  DEFERRED_PROTOCOLS: dispatcher.deferred,
  _resetForTest:      _resetForTest,
};
