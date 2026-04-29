"use strict";
/**
 * b.cache — operator-facing cache primitive.
 *
 *   var cache = b.cache.create({
 *     namespace:   "session.user",
 *     backend:     "memory",
 *     ttlMs:       C.TIME.minutes(5),
 *     maxEntries:  10000,
 *     audit:       b.audit,           // optional
 *   });
 *
 *   await cache.set("u-42", record);
 *   var hit = await cache.get("u-42");
 *
 *   // Memoize / read-through:
 *   var profile = await cache.wrap("u-42", function () {
 *     return db.users.findOne({ _id: "u-42" });
 *   });
 *
 * Surface (returned by create):
 *
 *   get(key)                  → value | undefined
 *   set(key, value, opts?)    → void                  (opts: { ttlMs })
 *   del(key)                  → boolean (existed)
 *   has(key)                  → boolean (does NOT bump LRU recency)
 *   clear(opts?)              → number (purged)        (opts: { req, context })
 *   size()                    → number
 *   wrap(key, fn, opts?)      → fn's return value      (opts: { ttlMs, singleFlight })
 *   close()                   → void
 *
 * Backends:
 *
 *   "memory" (default) — Map + LRU eviction (maxEntries) + periodic
 *     sweep timer (sweepIntervalMs). Single-process accuracy only.
 *
 *   "cluster" — _blamejs_cache table via cluster-storage. PRIMARY KEY
 *     is "<namespace>:<key>" so one table serves every CacheInstance.
 *     UPSERT via ON CONFLICT for atomic set; DELETE WHERE expiresAt
 *     for sweep. JSON-only value serialization.
 *
 *   { get, set, del, clear, size, close } — operator-supplied custom
 *     backend (Redis, Memcached, …). All methods async.
 *
 * Validation tiers:
 *
 *   - create() opts                       → Tier A (throw at boot)
 *   - get/set/del/has/wrap key arg type   → Tier A (throw — programming bug)
 *   - set value type                      → C (operator decides what to store)
 *   - per-call ttlMs override             → Tier A (throw — bad ttl is silent footgun)
 *   - audit / observability emit failures → Tier B (drop silent)
 *   - method called after close()         → Tier A (throw BAD_STATE)
 *
 * Security defaults:
 *
 *   - auditClear: true     — mass purge is operator-action shaped (can hide forensics)
 *   - auditFailures: true  — backend errors are signal
 *   - hot-path get/set/hit/miss/eviction → observability only (audit chain
 *     would drown at any reasonable QPS)
 *
 * The cache supports single-flight wrap (concurrent calls collapse),
 * stale-while-revalidate, LRU eviction on the memory backend, a shared
 * cluster backend, and a custom-backend escape hatch.
 *
 * Distributed pubsub invalidation, tag-based invalidation, and
 * compression for the cluster backend are not built in — the cluster
 * backend is always-fresh-by-shared-table, memory caches go
 * stale-on-other-nodes by design, and read-through is what `wrap()`
 * is for.
 */

var clusterStorage = require("./cluster-storage");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var requestHelpers = require("./request-helpers");
var { CacheError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });

var _err = CacheError.factory;

var DEFAULTS = Object.freeze({
  backend:                 "memory",
  ttlMs:                   C.TIME.minutes(5),
  maxEntries:              10000,
  sweepIntervalMs:         C.TIME.minutes(1),
  staleWhileRevalidate:    false,
  auditFailures:           true,
  auditClear:              true,
});

// ---- Tier-A validation helpers ----

function _isFiniteNonNegative(n) {
  return typeof n === "number" && isFinite(n) && n >= 0;
}

function _isPositiveInt(n) {
  return typeof n === "number" && isFinite(n) && n >= 1 && Math.floor(n) === n;
}

// ttlMs accepts: any non-negative finite number OR Infinity. NaN, negative,
// or non-number is rejected.
function _validateTtl(name, value) {
  if (value === Infinity) return;
  if (typeof value !== "number" || isNaN(value) || !isFinite(value) || value < 0) {
    throw _err("BAD_OPT", name + " must be a non-negative finite number or Infinity, got " +
      (typeof value) + " " + JSON.stringify(value));
  }
}

function _validateMaxEntries(value) {
  if (value === Infinity) return;
  if (!_isPositiveInt(value)) {
    throw _err("BAD_OPT", "cache.create: maxEntries must be a positive integer or Infinity, got " +
      JSON.stringify(value));
  }
}

function _validateBackendObject(backend) {
  var required = ["get", "set", "del", "clear", "size", "close"];
  if (typeof backend !== "object" || backend === null) {
    throw _err("BAD_OPT", "cache.create: custom backend must be an object");
  }
  for (var i = 0; i < required.length; i++) {
    if (typeof backend[required[i]] !== "function") {
      throw _err("BAD_OPT", "cache.create: custom backend missing method '" + required[i] +
        "' (required: " + required.join(", ") + ")");
    }
  }
}

function _validateCreateOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("BAD_OPT", "cache.create: opts must be an object");
  }
  if (typeof opts.namespace !== "string" || opts.namespace.length === 0) {
    throw _err("BAD_OPT", "cache.create: namespace must be a non-empty string (cache identity for observability + audit)");
  }
  // Composite cluster-key separator is ":" — namespace must not contain it
  // or two namespaces could collide ("a:b" + "c" = "a:b:c" = "a" + "b:c").
  if (opts.namespace.indexOf(":") !== -1) {
    throw _err("BAD_OPT", "cache.create: namespace must not contain ':' (used as cluster-key separator), got " +
      JSON.stringify(opts.namespace));
  }
  if (opts.backend !== undefined) {
    if (typeof opts.backend === "string") {
      if (opts.backend !== "memory" && opts.backend !== "cluster") {
        throw _err("BAD_OPT", "cache.create: backend string must be 'memory' or 'cluster', got " +
          JSON.stringify(opts.backend));
      }
    } else {
      _validateBackendObject(opts.backend);
    }
  }
  if (opts.ttlMs !== undefined) _validateTtl("cache.create: ttlMs", opts.ttlMs);
  if (opts.maxEntries !== undefined) _validateMaxEntries(opts.maxEntries);
  if (opts.sweepIntervalMs !== undefined) {
    if (!_isFiniteNonNegative(opts.sweepIntervalMs) || opts.sweepIntervalMs < 1000) {
      throw _err("BAD_OPT", "cache.create: sweepIntervalMs must be a finite number ≥ 1000ms, got " +
        JSON.stringify(opts.sweepIntervalMs));
    }
  }
  if (opts.staleWhileRevalidate !== undefined && typeof opts.staleWhileRevalidate !== "boolean") {
    throw _err("BAD_OPT", "cache.create: staleWhileRevalidate must be a boolean");
  }
  if (opts.auditFailures !== undefined && typeof opts.auditFailures !== "boolean") {
    throw _err("BAD_OPT", "cache.create: auditFailures must be a boolean");
  }
  if (opts.auditClear !== undefined && typeof opts.auditClear !== "boolean") {
    throw _err("BAD_OPT", "cache.create: auditClear must be a boolean");
  }
  if (opts.audit !== undefined && opts.audit !== null) {
    if (typeof opts.audit !== "object" || typeof opts.audit.safeEmit !== "function") {
      throw _err("BAD_OPT", "cache.create: audit must be a b.audit-shaped object (safeEmit fn)");
    }
  }
  if (opts.observability !== undefined && opts.observability !== null) {
    if (typeof opts.observability !== "object" ||
        typeof opts.observability.event !== "function") {
      throw _err("BAD_OPT", "cache.create: observability must be a b.observability-shaped object (event fn)");
    }
  }
  if (opts.clock !== undefined && typeof opts.clock !== "function") {
    throw _err("BAD_OPT", "cache.create: clock must be a function");
  }
}

function _validateKey(key, ctx) {
  if (typeof key !== "string" || key.length === 0) {
    throw _err("BAD_KEY", ctx + ": key must be a non-empty string, got " +
      (typeof key) + " " + JSON.stringify(key));
  }
}

// ---- Memory backend ----
// LRU realized by Map insertion order (Node Map iterates in insertion order;
// re-inserting a key on hit moves it to the most-recent position).

function _memoryBackend(cfg) {
  var entries = new Map();    // key → { value, expiresAt }
  var maxEntries = cfg.maxEntries;
  var clock = cfg.clock;
  var emitObs = cfg.emitObs;
  var namespace = cfg.namespace;
  var sweepTimer = null;

  function _isExpired(entry, now) {
    return entry.expiresAt !== Infinity && entry.expiresAt <= now;
  }

  function _evictOldestIfFull() {
    if (maxEntries === Infinity) return;
    while (entries.size > maxEntries) {
      var oldest = entries.keys().next().value;
      entries.delete(oldest);
      emitObs("cache.eviction.size", { namespace: namespace });
    }
  }

  async function get(key) {
    var now = clock();
    var entry = entries.get(key);
    if (!entry) return undefined;
    if (_isExpired(entry, now)) {
      entries.delete(key);
      emitObs("cache.eviction.expired", { namespace: namespace });
      return undefined;
    }
    // LRU recency bump: re-insert moves to the most-recent slot.
    entries.delete(key);
    entries.set(key, entry);
    return entry.value;
  }

  async function set(key, value, expiresAt) {
    // Existing key replacement: delete first so re-insert lands at the
    // most-recent position (LRU on overwrite).
    entries.delete(key);
    entries.set(key, { value: value, expiresAt: expiresAt });
    _evictOldestIfFull();
  }

  async function del(key) {
    return entries.delete(key);
  }

  async function has(key) {
    var entry = entries.get(key);
    if (!entry) return false;
    if (_isExpired(entry, clock())) {
      entries.delete(key);
      emitObs("cache.eviction.expired", { namespace: namespace });
      return false;
    }
    return true;
  }

  async function clear() {
    var n = entries.size;
    entries.clear();
    return n;
  }

  async function size() {
    // Lazy purge: count only non-expired so size() reflects "live" entries.
    var now = clock();
    var live = 0;
    for (var entry of entries.values()) {
      if (!_isExpired(entry, now)) live++;
    }
    return live;
  }

  function _sweep() {
    var now = clock();
    var purged = 0;
    for (var k of Array.from(entries.keys())) {
      var e = entries.get(k);
      if (_isExpired(e, now)) {
        entries.delete(k);
        purged++;
      }
    }
    if (purged > 0) {
      // Single observability event per sweep cycle is enough — operators
      // see "purge happened with N evictions" via labels in dashboards.
      for (var i = 0; i < purged; i++) emitObs("cache.eviction.expired", { namespace: namespace });
    }
  }

  function _startSweep(intervalMs) {
    if (sweepTimer) return;
    sweepTimer = setInterval(_sweep, intervalMs);
    if (typeof sweepTimer.unref === "function") sweepTimer.unref();
  }

  async function close() {
    if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }
    entries.clear();
  }

  return {
    name:         "memory",
    get:          get,
    set:          set,
    del:          del,
    has:          has,
    clear:        clear,
    size:         size,
    close:        close,
    _startSweep:  _startSweep,
    // Test hook: raw entries map for state inspection
    _entries:     entries,
  };
}

// ---- Cluster backend ----
// Single _blamejs_cache table; cacheKey = "<namespace>:<key>". JSON-only
// value serialization. UPSERT via ON CONFLICT for atomic set.

function _clusterBackend(cfg) {
  var namespace = cfg.namespace;
  var clock = cfg.clock;
  var emitObs = cfg.emitObs;

  // Composite cluster key. Namespace was validated to not contain ":"
  // at create time, so the split is unambiguous.
  function _composedKey(key) { return namespace + ":" + key; }

  async function get(key) {
    var now = clock();
    var result = await clusterStorage.execute(
      "SELECT valueJson, expiresAt FROM _blamejs_cache WHERE cacheKey = ?",
      [_composedKey(key)]
    );
    if (!result || !result.rows || result.rows.length === 0) return undefined;
    var row = result.rows[0];
    if (row.expiresAt <= now) {
      // Lazy purge: opportunistic delete on stale read.
      try {
        await clusterStorage.execute(
          "DELETE FROM _blamejs_cache WHERE cacheKey = ? AND expiresAt <= ?",
          [_composedKey(key), now]
        );
      } catch (_e) { /* sweeper will catch it next pass */ }
      emitObs("cache.eviction.expired", { namespace: namespace });
      return undefined;
    }
    try { return JSON.parse(row.valueJson); }
    catch (_e) { return undefined; }
  }

  async function set(key, value, expiresAt) {
    var json = JSON.stringify(value);
    var storedExpires = (expiresAt === Infinity) ? Number.MAX_SAFE_INTEGER : expiresAt;
    var now = clock();
    // SQLite + Postgres both honor ON CONFLICT (cacheKey) DO UPDATE.
    await clusterStorage.execute(
      "INSERT INTO _blamejs_cache (cacheKey, valueJson, expiresAt, updatedAt) " +
      "VALUES (?, ?, ?, ?) " +
      "ON CONFLICT (cacheKey) DO UPDATE SET " +
      "valueJson = ?, expiresAt = ?, updatedAt = ?",
      [_composedKey(key), json, storedExpires, now, json, storedExpires, now]
    );
  }

  async function del(key) {
    var result = await clusterStorage.execute(
      "DELETE FROM _blamejs_cache WHERE cacheKey = ?",
      [_composedKey(key)]
    );
    return !!(result && result.rowCount && result.rowCount > 0);
  }

  async function has(key) {
    // Existence check without recency bump — cluster backend doesn't
    // track LRU at all, so "without bumping" is automatic. Honors
    // expiresAt the same as get().
    var now = clock();
    var result = await clusterStorage.execute(
      "SELECT expiresAt FROM _blamejs_cache WHERE cacheKey = ? AND expiresAt > ?",
      [_composedKey(key), now]
    );
    return !!(result && result.rows && result.rows.length > 0);
  }

  async function clear() {
    // Namespace-scoped wipe so two CacheInstance instances sharing the
    // table don't cross-purge each other.
    var like = namespace + ":%";
    var result = await clusterStorage.execute(
      "DELETE FROM _blamejs_cache WHERE cacheKey LIKE ?",
      [like]
    );
    return (result && result.rowCount) || 0;
  }

  async function size() {
    var now = clock();
    var like = namespace + ":%";
    var result = await clusterStorage.execute(
      "SELECT COUNT(*) AS n FROM _blamejs_cache WHERE cacheKey LIKE ? AND expiresAt > ?",
      [like, now]
    );
    if (!result || !result.rows || result.rows.length === 0) return 0;
    return result.rows[0].n || 0;
  }

  async function _sweep() {
    var now = clock();
    var like = namespace + ":%";
    await clusterStorage.execute(
      "DELETE FROM _blamejs_cache WHERE cacheKey LIKE ? AND expiresAt <= ?",
      [like, now]
    );
  }

  function _startSweep(intervalMs) {
    var t = setInterval(function () {
      _sweep().catch(function () { /* sweeper best-effort; next pass picks it up */ });
    }, intervalMs);
    if (typeof t.unref === "function") t.unref();
    cfg._sweepTimer = t;
  }

  async function close() {
    if (cfg._sweepTimer) { clearInterval(cfg._sweepTimer); cfg._sweepTimer = null; }
  }

  return {
    name:         "cluster",
    get:          get,
    set:          set,
    del:          del,
    has:          has,
    clear:        clear,
    size:         size,
    close:        close,
    _startSweep:  _startSweep,
  };
}

// ---- Custom backend wrapper ----
// Operator-supplied { get, set, del, clear, size, close } — wrap to
// uniform-shape (no _startSweep, _entries). The operator is responsible
// for their own expiration; we pass expiresAt to set().

function _customBackend(operatorBackend, cfg) {
  return {
    name:         "custom",
    get:          function (key) { return operatorBackend.get(key); },
    set:          function (key, value, expiresAt) { return operatorBackend.set(key, value, expiresAt); },
    del:          function (key) { return operatorBackend.del(key); },
    has:          function (key) {
      // Optional has() — fall back to get-and-coerce if operator didn't
      // implement it.
      if (typeof operatorBackend.has === "function") return operatorBackend.has(key);
      return Promise.resolve(operatorBackend.get(key)).then(function (v) { return v !== undefined; });
    },
    clear:        function () { return operatorBackend.clear(); },
    size:         function () { return operatorBackend.size(); },
    close:        function () { return operatorBackend.close(); },
    _startSweep:  function () { /* operator backend manages its own sweep */ },
  };
}

// ---- Public create ----

function create(opts) {
  _validateCreateOpts(opts);

  var namespace        = opts.namespace;
  var backendKind      = opts.backend || DEFAULTS.backend;
  var defaultTtlMs     = (opts.ttlMs            === undefined) ? DEFAULTS.ttlMs            : opts.ttlMs;
  var maxEntries       = (opts.maxEntries       === undefined) ? DEFAULTS.maxEntries       : opts.maxEntries;
  var sweepIntervalMs  = (opts.sweepIntervalMs  === undefined) ? DEFAULTS.sweepIntervalMs  : opts.sweepIntervalMs;
  var staleRevalidate  = (opts.staleWhileRevalidate === undefined) ? DEFAULTS.staleWhileRevalidate : opts.staleWhileRevalidate;
  var auditFailures    = (opts.auditFailures    === undefined) ? DEFAULTS.auditFailures    : opts.auditFailures;
  var auditClear       = (opts.auditClear       === undefined) ? DEFAULTS.auditClear       : opts.auditClear;
  var audit            = opts.audit || null;
  var operatorObs      = opts.observability || null;
  var clock            = opts.clock || function () { return Date.now(); };

  function emitObs(name, labels) {
    try {
      if (operatorObs) operatorObs.event(name, 1, labels || {});
      else observability().event(name, 1, labels || {});
    } catch (_e) { /* Tier B: hot-path observability sink */ }
  }

  function emitAudit(action, info) {
    if (!audit) return;
    try { audit.safeEmit(Object.assign({ action: action }, info || {})); }
    catch (_e) { /* audit best-effort */ }
  }

  function _actor(callerOpts) {
    var override = {};
    if (callerOpts && callerOpts.context && typeof callerOpts.context === "object") {
      for (var k in callerOpts.context) {
        if (Object.prototype.hasOwnProperty.call(callerOpts.context, k)) {
          override[k] = callerOpts.context[k];
        }
      }
    }
    return requestHelpers.extractActorContext(callerOpts && callerOpts.req, override);
  }

  function _backendFailedAudit(op, err) {
    if (!auditFailures) return;
    emitAudit("cache.backend.failed", {
      actor:    requestHelpers.extractActorContext(null),
      resource: { kind: "cache", id: namespace },
      outcome:  "failure",
      reason:   "backend-error",
      metadata: { op: op, code: (err && err.code) || null, message: (err && err.message) || String(err) },
    });
  }

  // Resolve backend
  var cfg = {
    namespace:    namespace,
    maxEntries:   maxEntries,
    clock:        clock,
    emitObs:      emitObs,
    _sweepTimer:  null,
  };
  var backend;
  if (backendKind === "memory") {
    backend = _memoryBackend(cfg);
  } else if (backendKind === "cluster") {
    backend = _clusterBackend(cfg);
  } else {
    backend = _customBackend(opts.backend, cfg);
  }

  backend._startSweep(sweepIntervalMs);

  var closed = false;
  function _ensureOpen(method) {
    if (closed) {
      throw _err("BAD_STATE", "cache." + method + ": cache instance has been closed");
    }
  }

  // Single-flight inflight map for wrap()
  var inflight = new Map();

  // Stale-while-revalidate tracking (per-instance, in-memory). When SWR
  // is on, wrap() stores entries with a HARD TTL of 2× ttlMs and tracks
  // the SOFT expiration here. Reads after soft but before hard return
  // the cached value AND kick off a background refresh; reads after
  // hard fall through to a normal miss + compute. The soft-TTL map is
  // memory-only even when the backend is cluster — refreshes are a
  // best-effort optimization, not a correctness invariant, so a cache
  // miss after restart (no soft data) just means we serve fresh once.
  var softExpiry = new Map();    // key → softExpiresAt
  var swrInflight = new Map();   // key → background-refresh promise
  var SWR_HARD_MULTIPLIER = 2;

  // ---- Public methods ----

  function _resolveTtl(callerOpts, methodName) {
    if (callerOpts && callerOpts.ttlMs !== undefined) {
      _validateTtl("cache." + methodName + ": ttlMs", callerOpts.ttlMs);
      return callerOpts.ttlMs;
    }
    return defaultTtlMs;
  }

  async function get(key) {
    _ensureOpen("get");
    _validateKey(key, "cache.get");
    var v;
    try { v = await backend.get(key); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "get" });
      _backendFailedAudit("get", e);
      throw e;
    }
    if (v === undefined) emitObs("cache.miss", { namespace: namespace });
    else emitObs("cache.hit", { namespace: namespace });
    return v;
  }

  async function set(key, value, callerOpts) {
    _ensureOpen("set");
    _validateKey(key, "cache.set");
    var ttlMs = _resolveTtl(callerOpts, "set");
    if (ttlMs === 0) return;    // 0 means "do not cache"
    var expiresAt = (ttlMs === Infinity) ? Infinity : (clock() + ttlMs);
    try { await backend.set(key, value, expiresAt); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "set" });
      _backendFailedAudit("set", e);
      throw e;
    }
    emitObs("cache.set", { namespace: namespace });
  }

  async function del(key) {
    _ensureOpen("del");
    _validateKey(key, "cache.del");
    var existed;
    try { existed = await backend.del(key); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "del" });
      _backendFailedAudit("del", e);
      throw e;
    }
    if (existed) emitObs("cache.del", { namespace: namespace });
    softExpiry.delete(key);
    return existed;
  }

  async function has(key) {
    _ensureOpen("has");
    _validateKey(key, "cache.has");
    try { return await backend.has(key); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "has" });
      _backendFailedAudit("has", e);
      throw e;
    }
  }

  async function clear(callerOpts) {
    _ensureOpen("clear");
    var purged;
    try { purged = await backend.clear(); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "clear" });
      _backendFailedAudit("clear", e);
      throw e;
    }
    emitObs("cache.clear", { namespace: namespace });
    if (auditClear) {
      emitAudit("cache.cleared", {
        actor:    _actor(callerOpts),
        resource: { kind: "cache", id: namespace },
        outcome:  "success",
        metadata: { itemCount: purged },
      });
    }
    // Drop any in-flight wrap promises — operator clear means "consumers
    // should re-fetch", and in-flight resolves would seed stale entries
    // post-clear.
    inflight.clear();
    swrInflight.clear();
    softExpiry.clear();
    return purged;
  }

  async function size() {
    _ensureOpen("size");
    try { return await backend.size(); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "size" });
      _backendFailedAudit("size", e);
      throw e;
    }
  }

  function _backgroundRefresh(key, fn, ttlMs) {
    if (swrInflight.has(key)) return;     // already refreshing
    var p = (async function () {
      var startedAt = clock();
      var computed;
      try { computed = await fn(); }
      finally {
        emitObs("cache.wrap.compute", { namespace: namespace, ms: clock() - startedAt });
      }
      var expiresAt = _writeWithSwr(key, computed, ttlMs);
      void expiresAt;
      return computed;
    })();
    swrInflight.set(key, p);
    p.then(
      function () { swrInflight.delete(key); },
      function (_e) {
        swrInflight.delete(key);
        // Background refresh failed; stale value already served. Surface
        // via observability so operators see it without breaking the
        // request that triggered the refresh.
        emitObs("cache.refresh.failed", { namespace: namespace });
      }
    );
  }

  function _writeWithSwr(key, value, ttlMs) {
    if (ttlMs === 0) return null;     // 0 means "do not cache"
    var now = clock();
    var hardTtlMs = (ttlMs === Infinity)
      ? Infinity
      : (staleRevalidate ? ttlMs * SWR_HARD_MULTIPLIER : ttlMs);
    var expiresAt = (hardTtlMs === Infinity) ? Infinity : (now + hardTtlMs);
    if (staleRevalidate && ttlMs !== Infinity) {
      softExpiry.set(key, now + ttlMs);
    } else {
      softExpiry.delete(key);
    }
    // Backend write — failure surfaces via observability + audit but
    // doesn't bubble (caller already has the computed value).
    backend.set(key, value, expiresAt).catch(function (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "set" });
      _backendFailedAudit("set", e);
    });
    return expiresAt;
  }

  async function wrap(key, fn, callerOpts) {
    _ensureOpen("wrap");
    _validateKey(key, "cache.wrap");
    if (typeof fn !== "function") {
      throw _err("BAD_OPT", "cache.wrap: fn must be a function, got " + typeof fn);
    }
    var ttlMs = _resolveTtl(callerOpts, "wrap");
    var singleFlight = !(callerOpts && callerOpts.singleFlight === false);

    var existing;
    try { existing = await backend.get(key); }
    catch (e) {
      emitObs("cache.backend.failed", { namespace: namespace, op: "get" });
      _backendFailedAudit("get", e);
      throw e;
    }

    if (existing !== undefined) {
      // SWR: served from backend, but might be stale (past soft TTL).
      var soft = softExpiry.get(key);
      var now = clock();
      if (staleRevalidate && soft !== undefined && soft <= now) {
        emitObs("cache.hit", { namespace: namespace });
        _backgroundRefresh(key, fn, ttlMs);
        return existing;
      }
      emitObs("cache.hit", { namespace: namespace });
      return existing;
    }
    emitObs("cache.miss", { namespace: namespace });

    if (singleFlight && inflight.has(key)) {
      emitObs("cache.wrap.singleflight.collapsed", { namespace: namespace });
      return inflight.get(key);
    }

    var promise = (async function () {
      var startedAt = clock();
      var computed;
      try { computed = await fn(); }
      finally {
        emitObs("cache.wrap.compute", { namespace: namespace, ms: clock() - startedAt });
      }
      if (ttlMs !== 0) {
        if (staleRevalidate) {
          _writeWithSwr(key, computed, ttlMs);
        } else {
          var expiresAt = (ttlMs === Infinity) ? Infinity : (clock() + ttlMs);
          try { await backend.set(key, computed, expiresAt); }
          catch (e) {
            emitObs("cache.backend.failed", { namespace: namespace, op: "set" });
            _backendFailedAudit("set", e);
            // Failed write doesn't fail the wrap — caller still gets the
            // computed value; cache just didn't persist.
          }
        }
      }
      return computed;
    })();
    if (singleFlight) {
      inflight.set(key, promise);
      promise.then(
        function () { inflight.delete(key); },
        function () { inflight.delete(key); }
      );
    }
    return promise;
  }

  async function close() {
    if (closed) return;
    closed = true;
    inflight.clear();
    swrInflight.clear();
    softExpiry.clear();
    try { await backend.close(); }
    catch (_e) { /* close best-effort */ }
  }

  return {
    get:                    get,
    set:                    set,
    del:                    del,
    has:                    has,
    clear:                  clear,
    size:                   size,
    wrap:                   wrap,
    close:                  close,
    namespace:              namespace,
    // Test hooks
    _backend:               backend,
    _inflight:              inflight,
  };
}

module.exports = {
  create:        create,
  CacheError:    CacheError,
  DEFAULTS:      DEFAULTS,
};
