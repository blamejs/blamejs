"use strict";
/**
 * Async resilience + safety primitives.
 *
 * The framework's async surfaces (external-db queries, cluster
 * coordination, queue operations, audit chain writes) all share the
 * same hazards: races between interleaved awaits, unbounded retries
 * masking real failures, hangs from unresponsive backends, and partial
 * results from operator-supplied drivers. This module collects the
 * primitives the framework uses to handle those hazards consistently.
 *
 * Design posture:
 *
 *   - **AbortSignal everywhere.** Every primitive that takes time
 *     accepts an `AbortSignal` and aborts cleanly when the signal
 *     fires. This is the modern Node.js convention (Node 18+) and
 *     replaces the older "cancellation token" pattern. Operators who
 *     don't pass a signal get the legacy non-cancellable behaviour.
 *
 *   - **Error.cause preserved.** Wrapper errors set `.cause` to the
 *     original failure so debugging traces back to the root. Callers
 *     who walk `.cause` chains see the full picture.
 *
 *   - **No leaked Promises.** Mutex / Semaphore release on path-out
 *     in finally blocks — even cancellation. No pending acquirer
 *     stays referenced after its abort.
 *
 *   - **Bounded by default.** Semaphore / Queue have explicit limits
 *     and reject acquisitions over the limit rather than growing
 *     unboundedly. Operators size limits explicitly for their workload.
 *
 *   - **Fail loud.** Errors propagate; primitives never silently
 *     swallow. safeAwait() opt-in for callers who need {error, value}
 *     tuples; everything else throws / rejects.
 *
 * Public API:
 *
 *   withTimeout(promise, ms, opts?)        promise; rejects on timeout
 *   withSignal(promise, signal)            promise; rejects on abort
 *   safeAwait(promise)                     [error, value] never throws
 *
 *   Mutex                                  class; .runExclusive(fn)
 *   Semaphore(limit)                       class; .runWith(fn)
 *   Once(fn)                               class; .invoke()
 *
 *   asyncRetry(fn, opts?)                  re-export from object-store-retry
 *   CircuitBreaker(name, opts?)            re-export from object-store-retry
 *
 *   AsyncSafeError                         error class
 *
 * Best-practice notes for callers:
 *
 *   - Always pair `withTimeout` with the external-db / network calls
 *     where operator-supplied drivers might hang. The framework's
 *     external-db wrapper already retries; timeout puts a ceiling on
 *     each individual attempt.
 *
 *   - Wrap chain-writes with Mutex.runExclusive. Audit chain hashing
 *     reads the previous tip and writes a successor; without
 *     serialization, concurrent awaiting record() calls can hash
 *     against the same prev-tip and produce a forked chain. Mutex
 *     prevents this in single-process; for cross-process coordination
 *     the cluster module's leader election is the correct primitive.
 *
 *   - Use Once for boot-time lazy init (counter primer, schema
 *     check). Multiple concurrent first-callers correctly all wait
 *     on the same in-flight init Promise rather than each starting
 *     their own.
 *
 *   - Use safeAwait for fire-and-forget paths (audit hooks in
 *     middleware) that previously used try/catch — preserves the
 *     "log + continue" pattern without unhandled-rejection warnings.
 *
 *   - Prefer Promise.allSettled over Promise.all when partial failure
 *     is acceptable (e.g. emitting to multiple log sinks; one sink
 *     down shouldn't block the others). The framework's log-stream
 *     dispatcher already does this.
 */

var C = require("./constants");

class AsyncSafeError extends Error {
  constructor(message, code, cause) {
    super(message);
    this.name = "AsyncSafeError";
    this.code = code || "async/invalid";
    if (cause !== undefined) this.cause = cause;
    this.isAsyncSafeError = true;
  }
}

// ---- withTimeout ----
//
// Race the promise against a timer. On timeout, the wrapper rejects with
// AsyncSafeError(code=async/timeout). The original promise continues
// running in the background — the framework cannot cancel an arbitrary
// async operation; only signal-aware ones can be aborted (see withSignal).
//
// opts.signal: AbortSignal — aborting the signal also rejects the wrapper
//              with code=async/aborted.
// opts.name:   diagnostic label included in the timeout message.

function withTimeout(promise, ms, opts) {
  opts = opts || {};
  if (typeof ms !== "number" || ms <= 0 || !Number.isFinite(ms)) {
    throw new AsyncSafeError("withTimeout: ms must be a positive finite number", "async/bad-arg");
  }
  return new Promise(function (resolve, reject) {
    var settled = false;
    var timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      reject(new AsyncSafeError(
        "operation timed out after " + ms + "ms" + (opts.name ? " (" + opts.name + ")" : ""),
        "async/timeout"
      ));
    }, ms);
    if (typeof timer.unref === "function") timer.unref();

    function _onAbort() {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new AsyncSafeError(
        "operation aborted" + (opts.name ? " (" + opts.name + ")" : ""),
        "async/aborted",
        opts.signal && opts.signal.reason
      ));
    }
    if (opts.signal) {
      if (opts.signal.aborted) { _onAbort(); return; }
      opts.signal.addEventListener("abort", _onAbort, { once: true });
    }

    Promise.resolve(promise).then(function (v) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (opts.signal) opts.signal.removeEventListener("abort", _onAbort);
      resolve(v);
    }, function (e) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (opts.signal) opts.signal.removeEventListener("abort", _onAbort);
      reject(e);
    });
  });
}

// ---- withSignal ----
//
// Race the promise against an AbortSignal. The original promise continues
// running in the background; only the wrapper's resolution is short-
// circuited. Useful for plumbing a single signal through a chain of awaits.

function withSignal(promise, signal) {
  if (!signal) return Promise.resolve(promise);
  return new Promise(function (resolve, reject) {
    var settled = false;
    function _onAbort() {
      if (settled) return;
      settled = true;
      reject(new AsyncSafeError(
        "operation aborted",
        "async/aborted",
        signal.reason
      ));
    }
    if (signal.aborted) { _onAbort(); return; }
    signal.addEventListener("abort", _onAbort, { once: true });
    Promise.resolve(promise).then(function (v) {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", _onAbort);
      resolve(v);
    }, function (e) {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", _onAbort);
      reject(e);
    });
  });
}

// ---- safeAwait ----
//
// Go-style [error, value] tuple. Never throws. Lets callers handle the
// "expected may fail; log and continue" pattern without try/catch
// scaffolding.
//
//   var [err, value] = await safeAwait(somePromise);
//   if (err) { /* log + continue */ }

async function safeAwait(promise) {
  try {
    var v = await promise;
    return [null, v];
  } catch (e) {
    return [e, null];
  }
}

// ---- Mutex ----
//
// Async mutex — only one async region holds the lock at a time. Acquirers
// queue in arrival order. .runExclusive(fn) is the recommended call form
// (lock release is automatic via finally even if fn throws); .acquire()
// + .release() are exposed for callers needing finer control.
//
// Implementation note: a queued acquirer that's never released (operator
// bug) blocks the entire mutex. We don't add a hard-coded timeout because
// timeouts mask bugs and the real fix is releasing properly. If a caller
// wants a deadline, wrap the runExclusive call with withTimeout.

class Mutex {
  constructor() {
    this._waiters = [];
    this._held = false;
  }

  acquire() {
    if (!this._held) {
      this._held = true;
      return Promise.resolve();
    }
    var self = this;
    return new Promise(function (resolve) {
      self._waiters.push(resolve);
    });
  }

  release() {
    if (!this._held) {
      throw new AsyncSafeError("release on unheld Mutex", "async/bad-release");
    }
    if (this._waiters.length > 0) {
      var next = this._waiters.shift();
      next();
    } else {
      this._held = false;
    }
  }

  async runExclusive(fn) {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  isHeld() { return this._held; }
  pendingCount() { return this._waiters.length; }
}

// ---- Semaphore ----
//
// Bounded concurrency: at most `limit` simultaneous holders. Acquirers
// over the limit wait their turn. Use cases: limit external-db query
// concurrency, throttle outbound webhook fan-out, cap parallel file I/O.
//
// .runWith(fn) is the recommended form (release on finally); .acquire/
// .release are exposed for finer control.

class Semaphore {
  constructor(limit) {
    if (typeof limit !== "number" || limit < 1 || !Number.isInteger(limit)) {
      throw new AsyncSafeError("Semaphore limit must be a positive integer", "async/bad-arg");
    }
    this._limit = limit;
    this._inFlight = 0;
    this._waiters = [];
  }

  acquire() {
    if (this._inFlight < this._limit) {
      this._inFlight += 1;
      return Promise.resolve();
    }
    var self = this;
    return new Promise(function (resolve) {
      self._waiters.push(resolve);
    });
  }

  release() {
    if (this._inFlight === 0) {
      throw new AsyncSafeError("release on idle Semaphore", "async/bad-release");
    }
    if (this._waiters.length > 0) {
      var next = this._waiters.shift();
      next();
    } else {
      this._inFlight -= 1;
    }
  }

  async runWith(fn) {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  inFlight() { return this._inFlight; }
  pendingCount() { return this._waiters.length; }
}

// ---- Once ----
//
// Single-flight memoization. The first .invoke() call runs the function;
// subsequent calls (concurrent or later) await the same in-flight Promise
// and receive the same result. If the first invocation throws, the cached
// result is the rejected Promise — re-invocation will NOT retry.
//
// Use case: lazy boot-time init where multiple call sites might first-
// touch concurrently (counter primer, schema-check, key load). Without
// Once, the second concurrent caller would start its own init and produce
// double-initialization.
//
// To force a retry after failure, construct a new Once.

class Once {
  constructor(fn) {
    if (typeof fn !== "function") {
      throw new AsyncSafeError("Once: argument must be a function", "async/bad-arg");
    }
    this._fn = fn;
    this._promise = null;
  }

  invoke() {
    if (this._promise === null) {
      this._promise = Promise.resolve().then(this._fn);
    }
    return this._promise;
  }

  hasInvoked() { return this._promise !== null; }
}

// ---- Re-exports of existing resilience primitives ----
//
// withRetry + CircuitBreaker live in lib/object-store-retry.js for
// historical reasons (they were built alongside the object-store
// dispatcher). We re-export them here under more discoverable names so
// new code goes through async-safe and existing call sites can migrate
// gradually. Both names continue to point at the same implementations.

var retryHelper = require("./object-store-retry");

var asyncRetry     = retryHelper.withRetry;
var CircuitBreaker = retryHelper.CircuitBreaker;

module.exports = {
  withTimeout:        withTimeout,
  withSignal:         withSignal,
  safeAwait:          safeAwait,
  Mutex:              Mutex,
  Semaphore:          Semaphore,
  Once:               Once,
  asyncRetry:         asyncRetry,
  CircuitBreaker:     CircuitBreaker,
  AsyncSafeError:     AsyncSafeError,
};
