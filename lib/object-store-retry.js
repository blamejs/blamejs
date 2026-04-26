"use strict";
/**
 * Retry policy + circuit breaker for object-store operations.
 *
 * Two layers:
 *
 *   1. PER-CALL retry — exponential backoff with jitter, retries idempotent
 *      operations (GET, HEAD, PUT-with-key) on transient errors. Non-
 *      idempotent failures (4xx other than 408/425/429, AEAD/integrity
 *      errors, classification violations) are NOT retried — they're
 *      permanent and must surface to the caller.
 *
 *   2. PER-BACKEND circuit breaker — N consecutive failures opens the
 *      circuit (further calls fail-fast for the cooldown window). After
 *      cooldown the breaker enters half-open: a single probe call
 *      determines whether to fully reopen.
 *
 * Why both: retry handles transient blips (network jitter, brief 503).
 * Circuit breaker handles sustained outages (backend genuinely down) so
 * the framework doesn't pile up retry storms against a dead backend.
 */

// ---- Retry policy ----

var C = require("./constants");

var DEFAULT_RETRY = Object.freeze({
  maxAttempts:    5,                   // total attempts incl. the first try
  baseDelayMs:    100,                 // initial backoff (sub-second; ms literal is clearest)
  maxDelayMs:     C.TIME.seconds(10),  // cap between attempts
  jitterFactor:   0.5,                 // 0 = no jitter, 1 = full jitter
});

// Errors that are permanently fatal — do NOT retry.
// Authentication failures, classification violations, integrity failures,
// 4xx (except a few specific transient codes), and explicit cancellation.
var NON_RETRYABLE_HTTP_STATUS = new Set([400, 401, 403, 404, 405, 409, 410, 411, 412, 413, 414, 415, 416, 417, 422, 451, 501, 505]);

// Errors that should be retried — transient by nature.
var RETRYABLE_HTTP_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);

// Network errors from Node's net layer that map to "retry" semantics.
var RETRYABLE_NET_ERRORS = new Set([
  "ECONNRESET", "ECONNREFUSED", "ECONNABORTED", "ETIMEDOUT",
  "EPIPE", "EAGAIN", "ENOTFOUND", "ENETUNREACH",
]);

function isRetryable(err) {
  if (!err) return false;
  if (err.isObjectStoreError && err.permanent) return false;
  if (typeof err.statusCode === "number") {
    if (RETRYABLE_HTTP_STATUS.has(err.statusCode)) return true;
    if (NON_RETRYABLE_HTTP_STATUS.has(err.statusCode)) return false;
    // Unknown 5xx → assume retryable
    if (err.statusCode >= 500) return true;
    return false;
  }
  if (err.code && RETRYABLE_NET_ERRORS.has(err.code)) return true;
  // Other errors default to NOT-retryable to avoid masking bugs
  return false;
}

function backoffDelay(attempt, opts) {
  opts = opts || DEFAULT_RETRY;
  var base = opts.baseDelayMs * Math.pow(2, attempt - 1);
  var capped = Math.min(base, opts.maxDelayMs);
  var jitter = capped * opts.jitterFactor * Math.random();
  return Math.floor(capped - jitter);
}

async function withRetry(fn, opts) {
  opts = Object.assign({}, DEFAULT_RETRY, opts || {});
  // opts.isRetryable lets callers override the default classifier.
  // Default classifier (isRetryable) targets HTTP/network errors and
  // is intentionally conservative (unknown errors → NOT retryable, to
  // avoid masking bugs). Callers like the handlers primitive whose
  // flush failures are operator-defined (not network-shaped) pass
  // `isRetryable: function () { return true; }` to retry on any error.
  var classify = (typeof opts.isRetryable === "function") ? opts.isRetryable : isRetryable;
  var lastErr = null;
  for (var attempt = 1; attempt <= opts.maxAttempts; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      lastErr = err;
      if (!classify(err) || attempt === opts.maxAttempts) {
        throw err;
      }
      var delay = backoffDelay(attempt, opts);
      if (typeof opts.onRetry === "function") {
        try { opts.onRetry({ attempt: attempt, delay: delay, error: err }); } catch (_e) {}
      }
      await new Promise(function (r) { setTimeout(r, delay); });
    }
  }
  throw lastErr;
}

// ---- Circuit breaker ----

var STATE_CLOSED = "closed";       // normal — calls go through
var STATE_OPEN   = "open";         // failing — calls fail fast
var STATE_HALF   = "half-open";    // probing — one call goes through

var DEFAULT_BREAKER = Object.freeze({
  failureThreshold:  10,                  // consecutive failures to open
  cooldownMs:        C.TIME.seconds(30),  // time in OPEN before HALF_OPEN probe
  successThreshold:  2,                   // consecutive HALF probes that close it
});

class CircuitBreaker {
  constructor(name, opts) {
    this.name = name || "unnamed";
    this.opts = Object.assign({}, DEFAULT_BREAKER, opts || {});
    this.state = STATE_CLOSED;
    this.consecutiveFailures = 0;
    this.consecutiveSuccesses = 0;
    this.openedAt = 0;
  }

  // Wrap an async function. The breaker observes outcomes and may fail-fast.
  async wrap(fn) {
    if (this.state === STATE_OPEN) {
      if (Date.now() - this.openedAt >= this.opts.cooldownMs) {
        this.state = STATE_HALF;
      } else {
        var err = new Error("circuit breaker '" + this.name + "' is OPEN");
        err.code = "CIRCUIT_OPEN";
        err.permanent = false;     // still transient
        err.isObjectStoreError = true;
        throw err;
      }
    }
    try {
      var result = await fn();
      this._onSuccess();
      return result;
    } catch (e) {
      this._onFailure(e);
      throw e;
    }
  }

  _onSuccess() {
    if (this.state === STATE_HALF) {
      this.consecutiveSuccesses += 1;
      if (this.consecutiveSuccesses >= this.opts.successThreshold) {
        this.state = STATE_CLOSED;
        this.consecutiveFailures = 0;
        this.consecutiveSuccesses = 0;
      }
    } else {
      this.consecutiveFailures = 0;
    }
  }

  _onFailure(err) {
    // Don't trip the breaker on permanent errors (4xx, classification
    // violation) — those are caller bugs, not backend health issues.
    if (err && err.permanent) return;
    if (err && err.isObjectStoreError && err.code === "CIRCUIT_OPEN") return;

    this.consecutiveFailures += 1;
    this.consecutiveSuccesses = 0;
    if (this.state === STATE_HALF) {
      this.state = STATE_OPEN;
      this.openedAt = Date.now();
    } else if (this.state === STATE_CLOSED && this.consecutiveFailures >= this.opts.failureThreshold) {
      this.state = STATE_OPEN;
      this.openedAt = Date.now();
    }
  }

  getState() { return this.state; }
  reset() {
    this.state = STATE_CLOSED;
    this.consecutiveFailures = 0;
    this.consecutiveSuccesses = 0;
    this.openedAt = 0;
  }
}

module.exports = {
  withRetry:               withRetry,
  isRetryable:             isRetryable,
  backoffDelay:            backoffDelay,
  CircuitBreaker:          CircuitBreaker,
  DEFAULT_RETRY:           DEFAULT_RETRY,
  DEFAULT_BREAKER:         DEFAULT_BREAKER,
  RETRYABLE_HTTP_STATUS:   Array.from(RETRYABLE_HTTP_STATUS),
  NON_RETRYABLE_HTTP_STATUS: Array.from(NON_RETRYABLE_HTTP_STATUS),
  RETRYABLE_NET_ERRORS:    Array.from(RETRYABLE_NET_ERRORS),
  STATES:                  { CLOSED: STATE_CLOSED, OPEN: STATE_OPEN, HALF_OPEN: STATE_HALF },
};
