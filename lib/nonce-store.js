"use strict";
/**
 * nonce-store — pluggable replay-protection store.
 *
 * The api-encrypt middleware and any other surface that needs
 * "first-time-only" semantics for a request-supplied nonce uses this
 * primitive. The store is shaped around two operations:
 *
 *   await store.checkAndInsert(nonce, expireAt) → boolean
 *     Returns true if the nonce was unseen (and is now recorded);
 *     returns false if it was already present (= replay attempt).
 *     The check + insert MUST be atomic — checking first and
 *     inserting second would race on concurrent requests carrying
 *     the same nonce.
 *
 *   await store.purgeExpired() → number
 *     Removes entries past their expireAt. Called periodically by the
 *     middleware that uses the store. Returns the count purged.
 *
 *   store.close()
 *     Releases any timer / pool resources. Memory backend stops its
 *     periodic sweep; cluster backend is a no-op (table prune is
 *     called explicitly).
 *
 * Backends:
 *
 *   'memory' (default) — Map-backed; periodic sweep evicts expired
 *     entries. Single-process accuracy only — a request hitting
 *     node A and a replay hitting node B will NOT be caught.
 *
 *   { checkAndInsert, purgeExpired, close } — operator-supplied
 *     custom backend (Redis SETNX, Memcached add, etc.). Cluster
 *     deployments wire one of these instead of relying on memory —
 *     the framework intentionally does not bundle a SQL-backed
 *     cluster store here so the api-encrypt hot path stays free of
 *     a cross-node DB round-trip per request.
 *
 * Sweep cadence: memory backend sweeps every opts.sweepIntervalMs
 * (default 5 minutes). Custom backends are responsible for their
 * own retention.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");

var logger = lazyRequire(function () { return require("./log").boot("nonce-store"); });

var NonceStoreError = defineClass("NonceStoreError");

var DEFAULT_SWEEP_INTERVAL_MS = C.TIME.minutes(5);

function _err(code, message) {
  return new NonceStoreError(code, message, true);
}

// ---- Memory backend ----

function _memoryBackend(opts) {
  var sweepIntervalMs = opts.sweepIntervalMs || DEFAULT_SWEEP_INTERVAL_MS;
  var seen = new Map();   // nonce -> expireAt

  var sweepTimer = setInterval(function () {
    var now = Date.now();
    for (var entry of seen) {
      if (entry[1] <= now) seen.delete(entry[0]);
    }
  }, sweepIntervalMs);
  if (typeof sweepTimer.unref === "function") sweepTimer.unref();

  function checkAndInsert(nonce, expireAt) {
    if (typeof nonce !== "string" || nonce.length === 0) {
      return Promise.reject(_err("INVALID_NONCE", "nonce must be a non-empty string"));
    }
    if (typeof expireAt !== "number" || !Number.isFinite(expireAt)) {
      return Promise.reject(_err("INVALID_EXPIRE", "expireAt must be a finite number (unix ms)"));
    }
    var existing = seen.get(nonce);
    if (existing !== undefined && existing > Date.now()) {
      return Promise.resolve(false);   // replay
    }
    seen.set(nonce, expireAt);
    return Promise.resolve(true);
  }

  function purgeExpired() {
    var now = Date.now();
    var removed = 0;
    for (var entry of seen) {
      if (entry[1] <= now) { seen.delete(entry[0]); removed++; }
    }
    return Promise.resolve(removed);
  }

  function close() {
    if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }
    seen.clear();
  }

  return {
    name:            "memory",
    checkAndInsert:  checkAndInsert,
    purgeExpired:    purgeExpired,
    close:           close,
    // Test hook — direct read of the underlying Map size
    _size:           function () { return seen.size; },
  };
}

// ---- Resolution ----

function create(opts) {
  opts = opts || {};
  var backend = opts.backend;
  if (backend && typeof backend === "object" && typeof backend.checkAndInsert === "function") {
    // Operator-supplied custom backend (Redis, Memcached, etc.). Fill
    // in any missing optional methods so the rest of the framework
    // can call them unconditionally.
    return Object.assign({
      name:         "custom",
      purgeExpired: function () { return Promise.resolve(0); },
      close:        function () {},
    }, backend);
  }
  if (!backend || backend === "memory") return _memoryBackend(opts);
  throw _err("UNKNOWN_BACKEND",
    "nonce-store: unknown backend '" + backend +
    "' (must be 'memory' or { checkAndInsert, purgeExpired, close })");
}

module.exports = {
  create:           create,
  NonceStoreError:  NonceStoreError,
  _memoryBackend:   _memoryBackend,
};
