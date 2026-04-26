"use strict";
/**
 * Rate-limit middleware — token-bucket per-key, in-memory.
 *
 * Per-IP by default; key extractor is configurable (per-user, per-API-key,
 * per-route). Token bucket model: each key gets `burst` tokens up front;
 * tokens refill at `refillPerSecond`; each request costs 1 token.
 *
 * In-memory only — the fast path for single-process deployments. For
 * multi-process setups a cross-process backend (Redis, the framework's
 * own SQLite via _blamejs_counters, etc.) is needed; this module does
 * not currently expose a backend pluggability seam, so multi-process
 * accuracy is not provided.
 *
 * Options:
 *   {
 *     keyFn:           (req) → 'rate-key'    (default: client IP)
 *     burst:           60                     // initial token bucket size
 *     refillPerSecond: 10                     // sustained throughput
 *     statusOnLimit:   429
 *     bodyOnLimit:     'Too Many Requests'
 *     header:          true                    // set X-RateLimit-* response headers
 *     skipPaths:       []                      // string-prefix or regex matchers
 *     scope:           'global' | 'per-route'  (default 'global')
 *   }
 *
 * Audit: every limit hit emits system.ratelimit.block with the key + path.
 */
var C = require("../constants");

var _audit = null;
function audit() { if (!_audit) _audit = require("../audit"); return _audit; }

function _clientIp(req) {
  var fwd = req.headers && req.headers["x-forwarded-for"];
  if (fwd) return String(fwd).split(",")[0].trim();
  return (req.socket && req.socket.remoteAddress) || "unknown";
}

function create(opts) {
  opts = opts || {};
  var keyFn = opts.keyFn || _clientIp;
  var burst = opts.burst || 60;
  var refillPerSecond = opts.refillPerSecond || 10;
  var statusOnLimit = opts.statusOnLimit || 429;
  var bodyOnLimit = opts.bodyOnLimit !== undefined ? opts.bodyOnLimit : "Too Many Requests";
  var emitHeaders = opts.header !== false;
  var skipPaths = opts.skipPaths || [];
  var scope = opts.scope || "global";

  // Map of key → { tokens, lastRefillAt }
  var buckets = new Map();

  // Periodic GC of stale buckets so the map doesn't grow without bound.
  var gcInterval = setInterval(function () {
    var cutoff = Date.now() - C.TIME.hours(1);
    for (var k of buckets.keys()) {
      if (buckets.get(k).lastRefillAt < cutoff) buckets.delete(k);
    }
  }, C.TIME.minutes(5));
  gcInterval.unref();

  function _shouldSkip(req) {
    var path = req.pathname || req.url || "/";
    for (var i = 0; i < skipPaths.length; i++) {
      if (typeof skipPaths[i] === "string" ? path.indexOf(skipPaths[i]) === 0 : skipPaths[i].test(path)) {
        return true;
      }
    }
    return false;
  }

  function _take(key) {
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
      return { allowed: true, remaining: Math.floor(b.tokens), retryAfter: 0 };
    }
    var deficit = 1 - b.tokens;
    var waitMs = Math.ceil((deficit / refillPerSecond) * 1000);
    return { allowed: false, remaining: 0, retryAfter: Math.ceil(waitMs / 1000) };
  }

  return function rateLimit(req, res, next) {
    if (_shouldSkip(req)) return next();
    var k = keyFn(req);
    if (scope === "per-route") k = (req.method || "GET") + ":" + (req.pathname || req.url || "/") + "|" + k;
    var verdict = _take(k);

    if (emitHeaders && typeof res.setHeader === "function") {
      res.setHeader("X-RateLimit-Limit", String(burst));
      res.setHeader("X-RateLimit-Remaining", String(verdict.remaining));
      if (verdict.retryAfter > 0) res.setHeader("Retry-After", String(verdict.retryAfter));
    }

    if (!verdict.allowed) {
      try {
        audit().record({
          actor:    { ip: _clientIp(req), userAgent: req.headers && req.headers["user-agent"] },
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
      return;
    }
    next();
  };
}

module.exports = { create: create };
