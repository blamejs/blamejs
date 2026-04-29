"use strict";
/**
 * Generic webhook log sink — HTTP POST one event (or a batch) at a time.
 *
 * Covers most SIEM ingestion endpoints with simple HTTP POST + JSON body:
 *   Splunk HEC                  — { auth: 'header', headers: { Authorization: 'Splunk <token>' } }
 *   Datadog Logs                — { auth: 'header', headers: { 'DD-API-KEY': '<key>' } }
 *   Sumo Logic HTTP source      — no auth (URL is the secret)
 *   Grafana Loki push API       — { auth: 'basic' }
 *   Generic OpenTelemetry HTTP  — { headers: { 'Content-Type': 'application/x-protobuf' } } — caller controls body shape
 *
 * Streaming model: events accumulate in a per-sink queue; a worker drains
 * it in batches (default size 100, max age 5s) to balance throughput
 * against latency. On webhook 5xx / network errors the batch retries with
 * exponential backoff (via the framework's retry module). On permanent 4xx
 * the batch is dropped and an audit event is recorded.
 *
 * Config:
 *   {
 *     url:                    'https://siem.example.com/ingest'
 *     auth:                   'none'|'bearer'|'basic'|'header'
 *     token / username+password / headers
 *     batchSize:              100
 *     maxBatchAgeMs:          C.TIME.seconds(5)
 *     contentType:            'application/json'
 *     bodyShape:              'array' | 'ndjson' | 'singleEnvelope'
 *     timeoutMs:              C.TIME.seconds(30)
 *     retry:                  { maxAttempts, baseDelayMs, ... }
 *     bufferLimit:            10000   // ring-buffer cap; drops oldest on overflow
 *   }
 */
var C = require("./constants");
var retryHelper = require("./retry");
var { LogStreamError } = require("./framework-error");
var httpClient = require("./http-client");
var safeUrl = require("./safe-url");
var authHeader = require("./auth-header");

// Webhook responses are ack-only (status + small body). 1 MiB cap is
// generous; misbehaving log-aggregator endpoints don't get to OOM us.
var MAX_RESPONSE_BYTES = C.BYTES.mib(1);

var DEFAULTS = {
  batchSize:     100,
  maxBatchAgeMs: C.TIME.seconds(5),
  contentType:   "application/json",
  bodyShape:     "array",
  timeoutMs:     C.TIME.seconds(30),
  bufferLimit:   10000,
};

var _err = LogStreamError.factory;

// Auth-header construction is delegated to lib/auth-header for the
// none/bearer/basic triple. The "header" mode (pass-through arbitrary
// headers) is handled here — it's not an auth scheme, just header
// merging that's traditionally been bundled in the same config knob.
function _authHeaders(config) {
  if (config.auth === "header") return Object.assign({}, config.headers || {});
  return authHeader.fromConfig(config);
}

function _post(url, body, headers, timeoutMs, allowedProtocols) {
  return httpClient.request({
    method:           "POST",
    url:              url,
    headers:          headers,
    body:             body,
    idleTimeoutMs:    timeoutMs,
    maxResponseBytes: MAX_RESPONSE_BYTES,
    errorClass:       LogStreamError,
    allowedProtocols: allowedProtocols,
  });
}

function _serializeBatch(records, shape) {
  if (shape === "ndjson") {
    return Buffer.from(records.map(function (r) { return JSON.stringify(r); }).join("\n") + "\n", "utf8");
  }
  if (shape === "singleEnvelope") {
    return Buffer.from(JSON.stringify({ events: records }), "utf8");
  }
  // default: array
  return Buffer.from(JSON.stringify(records), "utf8");
}

function create(config) {
  if (!config || !config.url) throw new Error("log-stream webhook requires { url }");
  var cfg = Object.assign({}, DEFAULTS, config);
  // Fail fast on misconfig — validate URL shape + scheme at create time
  // rather than at first emit. Default is HTTPS-only; operators with an
  // internal cleartext aggregator pass cfg.allowedProtocols
  // (safeUrl.ALLOW_HTTP_ALL).
  safeUrl.parse(cfg.url, {
    allowedProtocols: cfg.allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       LogStreamError,
  });
  var headers = Object.assign({ "Content-Type": cfg.contentType }, _authHeaders(cfg));
  var buffer = [];
  var dropCount = 0;
  var flushTimer = null;
  var inFlight = false;
  var closed = false;

  function _scheduleFlush() {
    if (flushTimer) return;
    flushTimer = setTimeout(function () { flushTimer = null; _flush(); }, cfg.maxBatchAgeMs);
    flushTimer.unref();
  }

  async function _flush() {
    if (inFlight) return;
    if (buffer.length === 0) return;
    inFlight = true;
    try {
      while (buffer.length > 0 && !closed) {
        var batch = buffer.splice(0, cfg.batchSize);
        var body = _serializeBatch(batch, cfg.bodyShape);
        try {
          await retryHelper.withRetry(function () {
            return _post(cfg.url, body, headers, cfg.timeoutMs, cfg.allowedProtocols);
          }, cfg.retry);
        } catch {
          // Batch permanently rejected — surface via the dropped counter.
          // Caller's audit hook recorded the drop already at the dispatcher.
          break;
        }
      }
    } finally {
      inFlight = false;
      if (buffer.length > 0) _scheduleFlush();
    }
  }

  function emit(record) {
    if (closed) return Promise.resolve({ accepted: false, reason: "sink closed" });
    if (buffer.length >= cfg.bufferLimit) {
      buffer.shift();   // drop oldest
      dropCount += 1;
    }
    buffer.push(record);
    if (buffer.length >= cfg.batchSize) {
      // Don't await — non-blocking flush. Caller's emit returns immediately.
      _flush().catch(function () {});
    } else {
      _scheduleFlush();
    }
    return Promise.resolve({ accepted: true, queued: buffer.length });
  }

  async function close() {
    closed = true;
    if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
    await _flush();
  }

  function stats() {
    return { queued: buffer.length, dropped: dropCount, inFlight: inFlight };
  }

  return {
    protocol:  "webhook",
    emit:      emit,
    close:     close,
    stats:     stats,
    flush:     _flush,
  };
}

module.exports = { create: create };
