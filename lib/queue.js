"use strict";
/**
 * Queue dispatcher — pluggable job queue with retry, lease semantics, and
 * graceful shutdown.
 *
 * Same dispatcher pattern as object-store: backends are configured per-name,
 * each with a protocol + protocol-specific options. The built-in 'local'
 * protocol is SQLite-backed (baked into the framework's main DB).
 * External protocols (redis, sqs, amqp, nats) are listed as deferred and
 * surface a clear error when selected.
 *
 * Public API:
 *   queue.init({ backends: { name: { protocol: 'local' } }, defaultBackend? })
 *   queue.enqueue(queueName, payload, opts?)
 *                                       → { jobId, queueName, ... }
 *   queue.consume(queueName, handler, opts?)
 *                                       → consumer handle (with cancel())
 *   queue.size(queueName, opts?)        → number (pending + inflight)
 *   queue.purge(queueName, opts?)       → number deleted
 *   queue.shutdown(opts?)               → drain handlers gracefully
 *   queue.listBackends()                → [{ name, protocol }]
 *
 * Job lifecycle:
 *   enqueued (status='pending')
 *     ↓ availableAt reached + consumer leases
 *   inflight (status='inflight', lease expires after leaseDurationMs)
 *     ↓ handler returns                 ↓ handler throws
 *   done (status='done')              if attempts < maxAttempts:
 *                                       pending (with backoff)
 *                                     else:
 *                                       failed (status='failed')
 */
var localProto = require("./queue-local");
var retryHelper = require("./object-store-retry");
var asyncSafe = require("./safe-async");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var { QueueError } = require("./framework-error");

var PROTOCOLS = {
  "local": localProto,
};

var DEFERRED_PROTOCOLS = {
  "redis":  { description: "Redis Streams (XADD/XREADGROUP/XACK/XCLAIM)" },
  "sqs":    { description: "AWS SQS (and S3-compatible queue endpoints) via SigV4" },
  "amqp":   { description: "AMQP 0-9-1 (RabbitMQ etc.)" },
  "nats":   { description: "NATS JetStream" },
};

function _err(code, message, permanent) {
  return new QueueError(code, message, permanent);
}

var audit = lazyRequire(function () { return require("./audit"); });

var initialized = false;
var backends = {};
var defaultBackend = null;
var consumers = [];   // [{ queueName, backendName, cancel(), running, inFlight: Set }]
var sweepTimer = null;

function init(opts) {
  if (initialized) return;
  if (!opts || !opts.backends) throw new Error("queue.init({ backends }) is required");

  backends = {};
  for (var name in opts.backends) {
    var cfg = opts.backends[name];
    if (DEFERRED_PROTOCOLS[cfg.protocol]) {
      var d = DEFERRED_PROTOCOLS[cfg.protocol];
      throw _err(
        "PROTOCOL_NOT_IMPLEMENTED",
        "queue protocol '" + cfg.protocol + "' (" + d.description +
        ") is not yet implemented. Use protocol: 'local'.",
        true
      );
    }
    var proto = PROTOCOLS[cfg.protocol];
    if (!proto) throw _err("UNKNOWN_PROTOCOL", "unknown queue protocol: '" + cfg.protocol + "'", true);
    var raw = proto.create(cfg);
    var breaker = new retryHelper.CircuitBreaker(
      "queue:" + name,
      cfg.breaker
    );

    // Wrap mutating ops with retry + breaker (idempotent only — enqueue and
    // complete are safe to retry; lease isn't because partial-double-lease
    // is dangerous, so it goes through the breaker but not retry).
    function wrapWithRetry(fn) {
      return function () {
        var args = Array.prototype.slice.call(arguments);
        return retryHelper.withRetry(function () {
          return breaker.wrap(function () { return fn.apply(raw, args); });
        }, cfg.retry);
      };
    }
    function wrapBreakerOnly(fn) {
      return function () {
        var args = Array.prototype.slice.call(arguments);
        return breaker.wrap(function () { return fn.apply(raw, args); });
      };
    }

    backends[name] = {
      name:          name,
      protocol:      cfg.protocol,
      breaker:       breaker,
      raw:           raw,
      enqueue:       wrapWithRetry(raw.enqueue),
      lease:         wrapBreakerOnly(raw.lease),
      complete:      wrapWithRetry(raw.complete),
      fail:          wrapWithRetry(raw.fail),
      sweepExpired:  raw.sweepExpired ? wrapBreakerOnly(raw.sweepExpired) : null,
      size:          wrapWithRetry(raw.size),
      purge:         wrapWithRetry(raw.purge),
    };
  }

  defaultBackend = opts.defaultBackend || Object.keys(backends)[0];

  // Sweep expired leases periodically (every 30s) so crashed-handler jobs
  // get re-pended.
  sweepTimer = setInterval(function () {
    Object.keys(backends).forEach(function (n) {
      if (backends[n].sweepExpired) {
        backends[n].sweepExpired().catch(function () { /* best effort */ });
      }
    });
  }, 30000);
  sweepTimer.unref();

  initialized = true;
}

function _backendFor(opts) {
  opts = opts || {};
  var name = opts.backend || defaultBackend;
  var b = backends[name];
  if (!b) throw _err("UNKNOWN_BACKEND", "no backend named '" + name + "'", true);
  return b;
}

// ---- Public API ----

function enqueue(queueName, payload, opts) {
  _requireInit();
  if (!queueName) throw _err("MISSING_QUEUE", "enqueue requires queueName", true);
  opts = opts || {};
  var b = _backendFor(opts);
  return b.enqueue(queueName, payload, opts).then(function (result) {
    _emit("system.queue.enqueue", {
      metadata: {
        queue:          queueName,
        backend:        b.name,
        jobId:          result.jobId,
        classification: result.classification,
        traceId:        opts.traceId,
        delaySeconds:   opts.delaySeconds || 0,
      },
    });
    return result;
  });
}

function consume(queueName, handler, opts) {
  _requireInit();
  if (!queueName) throw _err("MISSING_QUEUE", "consume requires queueName", true);
  if (typeof handler !== "function") throw _err("INVALID_HANDLER", "handler must be a function", true);
  opts = opts || {};
  var b = _backendFor(opts);
  var concurrency      = opts.concurrency      || 1;
  var leaseDurationMs  = opts.leaseDurationMs  || 30000;
  var pollIntervalMs   = opts.pollIntervalMs   || 1000;
  var fastPollMs       = opts.fastPollMs       || 50;

  // Each consumer has its own AbortController so cancel() unblocks any
  // in-flight poll-sleep immediately rather than waiting up to
  // pollIntervalMs (default 1s) for the next while-loop iteration.
  var abortCtrl = new AbortController();
  var state = {
    queueName:    queueName,
    backendName:  b.name,
    cancelled:    false,
    inFlight:     new Set(),
    abortCtrl:    abortCtrl,
    cancel:       function () {
      state.cancelled = true;
      try { abortCtrl.abort(); } catch (_e) {}
    },
  };
  consumers.push(state);

  (async function loop() {
    // Helper — sleep with cancellation. On abort, returns instead of
    // rejecting so the next while-iteration sees `state.cancelled` and
    // exits cleanly.
    async function _pollSleep(ms) {
      try { await asyncSafe.sleep(ms, { signal: abortCtrl.signal }); }
      catch (_e) { /* aborted — loop condition will catch it */ }
    }
    while (!state.cancelled) {
      // Don't lease more than (concurrency - inFlight) at a time
      var slots = concurrency - state.inFlight.size;
      if (slots <= 0) {
        await _pollSleep(fastPollMs);
        continue;
      }
      var jobs;
      try { jobs = await b.lease(queueName, leaseDurationMs, slots); }
      catch (e) {
        // Backend down (breaker open, etc.) — back off
        await _pollSleep(pollIntervalMs);
        continue;
      }
      if (!jobs || jobs.length === 0) {
        await _pollSleep(pollIntervalMs);
        continue;
      }
      for (var i = 0; i < jobs.length; i++) {
        (function (job) {
          state.inFlight.add(job.jobId);
          _emit("system.queue.consume.start", {
            metadata: { queue: queueName, backend: b.name, jobId: job.jobId, attempt: job.attempts, traceId: job.traceId },
          });
          Promise.resolve()
            .then(function () { return handler(job); })
            .then(function () {
              return b.complete(job.jobId).then(function () {
                _emit("system.queue.consume.success", {
                  metadata: { queue: queueName, backend: b.name, jobId: job.jobId, attempt: job.attempts, traceId: job.traceId },
                });
              });
            }, function (err) {
              var msg = (err && err.message) || String(err);
              return b.fail(job.jobId, msg, { retryDelayMs: _backoffDelay(job.attempts) })
                .then(function () {
                  _emit("system.queue.consume.failure", {
                    metadata: {
                      queue:    queueName, backend: b.name, jobId: job.jobId,
                      attempt:  job.attempts, traceId: job.traceId,
                      maxAttempts: job.maxAttempts, willRetry: job.attempts < job.maxAttempts,
                    },
                    reason:   msg,
                    outcome:  "failure",
                  });
                });
            })
            .catch(function (_e) { /* lifecycle errors swallowed — operator sees via audit */ })
            .then(function () { state.inFlight.delete(job.jobId); });
        })(jobs[i]);
      }
      await _pollSleep(fastPollMs);
    }
  })();

  return state;
}

function _backoffDelay(attempt) {
  // Exponential with cap: 1s * 2^(attempt-1), max 5min
  var ms = C.TIME.seconds(1) * Math.pow(2, attempt - 1);
  return Math.min(ms, C.TIME.minutes(5));
}

function size(queueName, opts) {
  _requireInit();
  return _backendFor(opts).size(queueName);
}

function purge(queueName, opts) {
  _requireInit();
  var b = _backendFor(opts);
  return b.purge(queueName).then(function (n) {
    _emit("system.queue.purge", {
      metadata: { queue: queueName, backend: b.name, deleted: n },
    });
    return n;
  });
}

async function shutdown(opts) {
  if (!initialized) return;
  opts = opts || {};
  var timeoutMs = opts.timeoutMs != null ? opts.timeoutMs : C.TIME.seconds(30);
  // Signal all consumers to stop
  consumers.forEach(function (c) { c.cancel(); });
  // Wait for in-flight handlers to complete
  var deadline = Date.now() + timeoutMs;
  while (consumers.some(function (c) { return c.inFlight.size > 0; })) {
    if (Date.now() > deadline) break;
    await asyncSafe.sleep(50);
  }
  consumers = [];
  if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }
}

function listBackends() {
  _requireInit();
  return Object.keys(backends).map(function (name) {
    return { name: name, protocol: backends[name].protocol, breakerState: backends[name].breaker.getState() };
  });
}

function _emit(action, info) {
  try { audit().emit({
    actor:    info.actor || {},
    action:   action,
    resource: info.resource || null,
    outcome:  info.outcome || "success",
    reason:   info.reason || null,
    metadata: info.metadata || null,
  }); } catch (_e) { /* audit best-effort */ }
}

function _requireInit() {
  if (!initialized) throw _err("NOT_INITIALIZED", "queue.init() must be called first", true);
}

function _resetForTest() {
  if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }
  consumers.forEach(function (c) { c.cancel(); });
  consumers = [];
  backends = {};
  defaultBackend = null;
  initialized = false;
  audit.reset();
}

module.exports = {
  init:               init,
  enqueue:            enqueue,
  consume:            consume,
  size:               size,
  purge:              purge,
  shutdown:           shutdown,
  listBackends:       listBackends,
  PROTOCOLS:          Object.keys(PROTOCOLS),
  DEFERRED_PROTOCOLS: DEFERRED_PROTOCOLS,
  _resetForTest:      _resetForTest,
};
