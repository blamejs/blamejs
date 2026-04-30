"use strict";
/**
 * Rate-limit middleware — pluggable backend, default in-memory.
 *
 * Per-IP by default; key extractor is configurable (per-user, per-API-key,
 * per-route). Two built-in backends:
 *
 *   - 'memory' (default) — token-bucket, in-process. Each key gets
 *     `burst` tokens up front; tokens refill at `refillPerSecond`;
 *     each request costs 1 token. Single-process accuracy only.
 *
 *   - 'cluster' — fixed-window counter shared across the cluster
 *     via `_blamejs_rate_limit_counters`. Atomic INSERT...ON CONFLICT
 *     increments per key within a window and rolls over when the
 *     window advances. Multi-process / multi-node accurate.
 *
 *     Cluster opt-in switches the algorithm shape from token-bucket
 *     to fixed-window because that's what models cleanly in SQL —
 *     the operator-facing config keys change accordingly.
 *
 * Operators can also pass a custom `{ take, reset }` object as the
 * backend for Redis / Memcached / etc.
 *
 * Options:
 *   {
 *     keyFn:           (req) → 'rate-key'    (default: client IP)
 *     statusOnLimit:   429
 *     bodyOnLimit:     'Too Many Requests'
 *     header:          true                    // set X-RateLimit-* response headers
 *     skipPaths:       []                      // string-prefix or regex matchers
 *     scope:           'global' | 'per-route'  (default 'global')
 *     backend:         'memory' (default) | 'cluster' | { take, reset, gc? }
 *
 *     // Memory-backend tuning (token bucket):
 *     burst:           60                       // initial token bucket size
 *     refillPerSecond: 10                       // sustained throughput
 *
 *     // Cluster-backend tuning (fixed window):
 *     limit:           60                       // max requests per window
 *     windowMs:        C.TIME.minutes(1)        // window duration
 *     pruneIntervalMs: C.TIME.minutes(5)        // how often the leader prunes expired rows
 *   }
 *
 * Audit: every limit hit emits system.ratelimit.block with the key + path.
 */
var C = require("../constants");
var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var clusterStorage = require("../cluster-storage");

var audit  = lazyRequire(function () { return require("../audit"); });
var logger = lazyRequire(function () { return require("../log").boot("rate-limit"); });

function _clientIp(req) {
  var fwd = req.headers && req.headers["x-forwarded-for"];
  if (fwd) return String(fwd).split(",")[0].trim();
  return (req.socket && req.socket.remoteAddress) || "unknown";
}

// ---- Memory backend (token bucket) ----

function _memoryBackend(opts) {
  var burst = opts.burst || 60;
  var refillPerSecond = opts.refillPerSecond || 10;
  var buckets = new Map();

  // Periodic GC of stale buckets so the map doesn't grow unbounded.
  var gcInterval = setInterval(function () {
    var cutoff = Date.now() - C.TIME.hours(1);
    for (var k of buckets.keys()) {
      if (buckets.get(k).lastRefillAt < cutoff) buckets.delete(k);
    }
  }, C.TIME.minutes(5));
  if (typeof gcInterval.unref === "function") gcInterval.unref();

  // Memory backend returns verdicts SYNCHRONOUSLY — no awaitable.
  // The middleware checks `.then` to decide whether to chain. Keeping
  // the hot path synchronous means single-process apps pay no
  // microtask cost per request.
  function take(key, _cost) {
    var now = Date.now();
    var b = buckets.get(key);
    if (!b) {
      b = { tokens: burst, lastRefillAt: now };
      buckets.set(key, b);
    } else {
      var elapsed = (now - b.lastRefillAt) / 1000;
      b.tokens = Math.min(burst, b.tokens + elapsed * refillPerSecond);
      b.lastRefillAt = now;
    }
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return {
        allowed:    true,
        limit:      burst,
        remaining:  Math.floor(b.tokens),
        retryAfter: 0,
      };
    }
    var deficit = 1 - b.tokens;
    var waitMs = Math.ceil((deficit / refillPerSecond) * 1000);
    return {
      allowed:    false,
      limit:      burst,
      remaining:  0,
      retryAfter: Math.ceil(waitMs / 1000),
    };
  }

  function reset(key) {
    buckets.delete(key);
  }

  function close() {
    try { clearInterval(gcInterval); } catch (_e) {}
    buckets.clear();
  }

  return { take: take, reset: reset, close: close };
}

// ---- Cluster backend (fixed-window counter, SQL-backed) ----

function _clusterBackend(opts) {
  var limit    = opts.limit    || 60;
  var windowMs = opts.windowMs || C.TIME.minutes(1);
  var pruneIntervalMs = opts.pruneIntervalMs || C.TIME.minutes(5);
  var lastPruneAt = 0;

  // Best-effort prune of expired window rows. Rate-limited at the
  // call site so we don't hammer the DB on every request.
  function _maybePrune() {
    var now = Date.now();
    if (now - lastPruneAt < pruneIntervalMs) return;
    lastPruneAt = now;
    var cutoff = now - windowMs;
    clusterStorage.execute(
      "DELETE FROM _blamejs_rate_limit_counters WHERE windowStart < ?",
      [cutoff]
    ).catch(function (e) {
      try {
        logger().warn("rate-limit prune failed: " + ((e && e.message) || String(e)));
      } catch (_e) { /* logger best-effort */ }
    });
  }

  async function take(key, _cost) {
    var now = Date.now();
    var windowStart = Math.floor(now / windowMs) * windowMs;

    // Atomic increment: a fresh window resets count to 1; an existing
    // row in the same window gets count + 1. Postgres + SQLite both
    // support ON CONFLICT...DO UPDATE...RETURNING.
    var result = await clusterStorage.execute(
      "INSERT INTO _blamejs_rate_limit_counters (key, windowStart, count) " +
      "VALUES (?, ?, 1) " +
      "ON CONFLICT (key) DO UPDATE SET " +
      "  count = CASE " +
      "    WHEN excluded.windowStart > _blamejs_rate_limit_counters.windowStart " +
      "    THEN 1 " +
      "    ELSE _blamejs_rate_limit_counters.count + 1 " +
      "  END, " +
      "  windowStart = CASE " +
      "    WHEN excluded.windowStart > _blamejs_rate_limit_counters.windowStart " +
      "    THEN excluded.windowStart " +
      "    ELSE _blamejs_rate_limit_counters.windowStart " +
      "  END " +
      "RETURNING count, windowStart",
      [key, windowStart]
    );
    var row = result.rows && result.rows[0];
    var count = row ? row.count : 1;
    var rowWindow = row ? row.windowStart : windowStart;

    _maybePrune();

    if (count <= limit) {
      return {
        allowed:    true,
        limit:      limit,
        remaining:  Math.max(0, limit - count),
        retryAfter: 0,
      };
    }
    var retryMs = (rowWindow + windowMs) - now;
    return {
      allowed:    false,
      limit:      limit,
      remaining:  0,
      retryAfter: Math.max(1, Math.ceil(retryMs / 1000)),
    };
  }

  async function reset(key) {
    await clusterStorage.execute(
      "DELETE FROM _blamejs_rate_limit_counters WHERE key = ?",
      [key]
    );
  }

  function close() { /* no resources to release */ }

  return { take: take, reset: reset, close: close };
}

// ---- Backend resolution ----

function _resolveBackend(opts) {
  var requested = opts.backend;
  if (requested && typeof requested === "object" && typeof requested.take === "function") {
    return requested;  // operator-supplied custom backend
  }
  if (requested === "cluster") return _clusterBackend(opts);
  if (!requested || requested === "memory") return _memoryBackend(opts);
  throw new Error("rate-limit: unknown backend '" + requested +
                  "' (must be 'memory', 'cluster', or { take, reset })");
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "keyFn", "statusOnLimit", "bodyOnLimit", "header", "skipPaths", "scope",
    "backend",
    // memory backend
    "burst", "refillPerSecond",
    // cluster backend
    "limit", "windowMs", "pruneIntervalMs",
  ], "middleware.rateLimit");
  var keyFn = opts.keyFn || _clientIp;
  var statusOnLimit = opts.statusOnLimit || 429;
  var bodyOnLimit = opts.bodyOnLimit !== undefined ? opts.bodyOnLimit : "Too Many Requests";
  var emitHeaders = opts.header !== false;
  var skipPaths = opts.skipPaths || [];
  var scope = opts.scope || "global";

  var backend = _resolveBackend(opts);

  function _shouldSkip(req) {
    var path = req.pathname || req.url || "/";
    for (var i = 0; i < skipPaths.length; i++) {
      if (typeof skipPaths[i] === "string" ? path.indexOf(skipPaths[i]) === 0 : skipPaths[i].test(path)) {
        return true;
      }
    }
    return false;
  }

  function _writeBlocked(req, res, k, verdict) {
    if (emitHeaders && typeof res.setHeader === "function") {
      res.setHeader("X-RateLimit-Limit", String(verdict.limit));
      res.setHeader("X-RateLimit-Remaining", String(verdict.remaining));
      if (verdict.retryAfter > 0) res.setHeader("Retry-After", String(verdict.retryAfter));
    }
    try {
      // Override `ip` with the x-forwarded-for-aware client IP so the
      // audit event carries the proxied origin even when extractActorContext
      // would have read the socket address.
      audit().emit({
        actor:    requestHelpers.extractActorContext(req, { ip: _clientIp(req) }),
        action:   "system.ratelimit.block",
        outcome:  "denied",
        reason:   "rate limit exceeded",
        metadata: { key: k, method: req.method, path: req.pathname || req.url, retryAfter: verdict.retryAfter },
        requestId: req.requestId,
      });
    } catch (_e) {}
    if (typeof res.writeHead === "function") {
      res.writeHead(statusOnLimit, { "Content-Type": "text/plain" });
      res.end(bodyOnLimit);
    }
  }

  var middleware = function rateLimit(req, res, next) {
    if (_shouldSkip(req)) return next();
    var k = keyFn(req);
    if (scope === "per-route") k = (req.method || "GET") + ":" + (req.pathname || req.url || "/") + "|" + k;

    function _handle(verdict) {
      if (emitHeaders && typeof res.setHeader === "function") {
        res.setHeader("X-RateLimit-Limit", String(verdict.limit));
        res.setHeader("X-RateLimit-Remaining", String(verdict.remaining));
      }
      if (!verdict.allowed) return _writeBlocked(req, res, k, verdict);
      next();
    }
    function _onErr(e) {
      // Fail-open on backend errors. The framework's job is to throttle
      // attackers, not to crash the request path. Surface the error to
      // ops via boot logger; the next request retries.
      try {
        logger().error("rate-limit backend take() failed: " + ((e && e.message) || String(e)));
      } catch (_e) { /* best-effort */ }
      next();
    }

    // Memory backend returns sync; cluster / custom backends return a
    // Promise. Detect via `.then` so the hot path stays synchronous.
    var verdictOrPromise;
    try {
      verdictOrPromise = backend.take(k, 1);
    } catch (e) { return _onErr(e); }

    if (verdictOrPromise && typeof verdictOrPromise.then === "function") {
      verdictOrPromise.then(_handle, _onErr);
    } else {
      _handle(verdictOrPromise);
    }
  };

  // Expose a couple of operator hooks on the middleware function.
  middleware.reset = function (key) { return backend.reset(key); };
  middleware.close = function ()    { return backend.close && backend.close(); };

  return middleware;
}

module.exports = {
  create:           create,
  // Backends exported for tests + advanced operator wiring.
  _memoryBackend:   _memoryBackend,
  _clusterBackend:  _clusterBackend,
};
