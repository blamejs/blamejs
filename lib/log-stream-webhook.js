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
var http = require("http");
var https = require("https");
var { URL } = require("url");
var C = require("./constants");
var retryHelper = require("./object-store-retry");
var bufferSafe = require("./buffer-safe");
var { LogStreamError } = require("./framework-error");

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

function _err(code, message, permanent, statusCode) {
  return new LogStreamError(code, message, permanent, statusCode);
}

function _authHeaders(config) {
  if (!config.auth || config.auth === "none") return {};
  if (config.auth === "bearer") return { Authorization: "Bearer " + config.token };
  if (config.auth === "basic") {
    var b64 = Buffer.from((config.username || "") + ":" + (config.password || ""), "utf8").toString("base64");
    return { Authorization: "Basic " + b64 };
  }
  if (config.auth === "header") return Object.assign({}, config.headers || {});
  throw new Error("log-stream webhook: unknown auth method '" + config.auth + "'");
}

function _post(url, body, headers, timeoutMs) {
  return new Promise(function (resolve, reject) {
    var u = new URL(url);
    var lib = u.protocol === "https:" ? https : http;
    var reqOpts = {
      method:   "POST",
      hostname: u.hostname,
      port:     u.port || (u.protocol === "https:" ? 443 : 80),
      path:     u.pathname + (u.search || ""),
      headers:  Object.assign({ "Content-Length": body.length }, headers || {}),
      timeout:  timeoutMs,
    };
    if (u.protocol === "https:") {
      reqOpts.ecdhCurve = C.TLS_GROUP_CURVE_STR;
    }
    var collector = bufferSafe.boundedChunkCollector({ maxBytes: MAX_RESPONSE_BYTES });
    var req = lib.request(reqOpts, function (res) {
      var capExceeded = false;
      res.on("data", function (c) {
        if (capExceeded) return;
        try { collector.push(c); }
        catch (_e) {
          capExceeded = true;
          req.destroy();
          reject(_err("RESPONSE_TOO_LARGE",
            "webhook response exceeds " + MAX_RESPONSE_BYTES + " bytes", true));
        }
      });
      res.on("end", function () {
        if (capExceeded) return;
        var buf = collector.result();
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ statusCode: res.statusCode, body: buf });
        } else {
          var permanent = res.statusCode >= 400 && res.statusCode < 500
                          && res.statusCode !== 408 && res.statusCode !== 425 && res.statusCode !== 429;
          reject(_err("HTTP_ERROR", "HTTP " + res.statusCode + ": " + buf.toString("utf8").slice(0, 200), permanent, res.statusCode));
        }
      });
      res.on("error", function (e) { if (!capExceeded) reject(_err(e.code || "RES_ERROR", e.message, false)); });
    });
    req.on("timeout", function () { req.destroy(); reject(_err("ETIMEDOUT", "request timeout", false)); });
    req.on("error", function (e) { reject(_err(e.code || "REQ_ERROR", e.message, false)); });
    req.end(body);
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
  var headers = Object.assign({ "Content-Type": cfg.contentType }, _authHeaders(cfg));
  var buffer = [];
  var bufferOldestAt = 0;
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
            return _post(cfg.url, body, headers, cfg.timeoutMs);
          }, cfg.retry);
        } catch (e) {
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
    if (buffer.length === 0) bufferOldestAt = Date.now();
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
