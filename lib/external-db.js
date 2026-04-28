"use strict";
/**
 * External database service — pluggable wrapper for app-data DB connections.
 *
 * Framework state (audit_log, consent_log, _blamejs_*) stays in the local
 * SQLite via b.db. This module is for APP DATA — when an operator wants to
 * keep their app's domain tables in Postgres / MySQL / MongoDB / libsql /
 * etc., they configure a backend here and use b.externalDb.query() instead
 * of b.db.from() for those tables.
 *
 * Bring-your-own-client design (per "zero npm runtime deps" rule):
 *   The operator supplies the actual DB driver via the backend's connect/
 *   query/close functions. The framework adds:
 *     - Connection pooling (lazy-create, reuse across queries)
 *     - Retry on transient errors (5xx-equivalent + network)
 *     - Circuit breaker per-backend
 *     - Classification routing (which backend serves which data class)
 *     - Residency enforcement (boot-time validation against
 *       db.getDataResidency().region)
 *     - Audit hooks (system.externaldb.{query,transaction,connect.failure})
 *
 * Built-in protocol adapters (native pg-wire, libsql-HTTP, MongoDB wire)
 * are not currently bundled — operators supply `connect`/`query`/`close`
 * directly using their wire client of choice. When framework-bundled
 * adapters land they will be available as `b.externalDb.adapters.pg`,
 * `.libsqlHttp`, etc., but the bring-your-own-client API is the
 * permanent surface.
 *
 * Public API:
 *   externalDb.init({ backends: { name: { connect, query, close?, ... } },
 *                     defaultBackend? })
 *   externalDb.query(sql, params?, opts?)         → { rows, rowCount }
 *   externalDb.transaction(fn, opts?)             → fn's return value
 *   externalDb.healthCheck(backendName?)          → backend status
 *   externalDb.listBackends()
 *   externalDb.shutdown()
 *
 * Backend config:
 *   {
 *     connect():  async () → client (returns operator's DB client)
 *     query(client, sql, params): async → { rows, rowCount }
 *     close(client): async → void
 *     ping(client): async → bool                  (optional health check)
 *     beginTx(client): async → void               (optional; default 'BEGIN')
 *     commit(client): async → void                (optional; default 'COMMIT')
 *     rollback(client): async → void              (optional; default 'ROLLBACK')
 *     pool: { min: 1, max: 10, idleTimeoutMs: C.TIME.minutes(1) }
 *     classifications: ['personal' | 'operational' | 'public' | <custom>]
 *     residencyTag: 'EU' | 'US' | ...
 *     retry, breaker
 *   }
 */
var retryHelper = require("./object-store/retry");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var { ExternalDbError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
var db    = lazyRequire(function () { return require("./db"); });

var _err = ExternalDbError.factory;

var initialized = false;
var backends = {};
var defaultBackend = null;

// ---- Pool ----
//
// Per-backend pool with lazy creation + LRU-ish reuse. Connections returned
// to the pool when query/transaction completes; idle connections expire.

class Pool {
  constructor(name, config) {
    this.name = name;
    this.config = Object.assign({ min: 1, max: 10, idleTimeoutMs: C.TIME.minutes(1) }, config.pool || {});
    this.connect = config.connect;
    this.close = config.close || function () { return Promise.resolve(); };
    this.idle = [];     // [{ client, lastUsedAt }]
    this.active = 0;    // count of in-use clients
    this.waiters = [];  // queued acquisitions when at max
    this._reaper = setInterval(this._reapIdle.bind(this), C.TIME.seconds(10));
    this._reaper.unref();
  }

  async acquire() {
    if (this.idle.length > 0) {
      var entry = this.idle.pop();
      this.active += 1;
      return entry.client;
    }
    if (this.active < this.config.max) {
      this.active += 1;
      try {
        return await this.connect();
      } catch (e) {
        this.active -= 1;
        throw e;
      }
    }
    // At max — wait for a release
    return new Promise((function (self) {
      return function (resolve, reject) {
        var entry = { resolve: resolve, reject: reject };
        self.waiters.push(entry);
      };
    })(this));
  }

  release(client) {
    this.active -= 1;
    if (this.waiters.length > 0) {
      var w = this.waiters.shift();
      this.active += 1;
      w.resolve(client);
      return;
    }
    this.idle.push({ client: client, lastUsedAt: Date.now() });
  }

  async destroy(client) {
    this.active -= 1;
    try { await this.close(client); } catch (_e) { /* best effort */ }
    if (this.waiters.length > 0) {
      var w = this.waiters.shift();
      this.acquire().then(w.resolve, w.reject);
    }
  }

  _reapIdle() {
    var now = Date.now();
    var keep = [];
    var self = this;
    this.idle.forEach(function (entry) {
      if ((now - entry.lastUsedAt) >= self.config.idleTimeoutMs) {
        Promise.resolve().then(function () { return self.close(entry.client); }).catch(function () {});
      } else {
        keep.push(entry);
      }
    });
    this.idle = keep;
  }

  async drain() {
    if (this._reaper) { clearInterval(this._reaper); this._reaper = null; }
    var idleClients = this.idle.map(function (e) { return e.client; });
    this.idle = [];
    var self = this;
    await Promise.all(idleClients.map(function (c) {
      return Promise.resolve().then(function () { return self.close(c); }).catch(function () {});
    }));
    this.waiters.forEach(function (w) { w.reject(_err("POOL_DRAINED", "pool is shutting down", true)); });
    this.waiters = [];
  }

  stats() {
    return { active: this.active, idle: this.idle.length, waiters: this.waiters.length };
  }
}

// ---- Init ----

function init(opts) {
  if (initialized) return;
  if (!opts || !opts.backends) throw new Error("externalDb.init({ backends }) is required");

  backends = {};
  for (var name in opts.backends) {
    var cfg = opts.backends[name];
    if (typeof cfg.connect !== "function") {
      throw _err("INVALID_CONFIG", "backend '" + name + "' missing connect() function", true);
    }
    if (typeof cfg.query !== "function") {
      throw _err("INVALID_CONFIG", "backend '" + name + "' missing query() function", true);
    }
    backends[name] = {
      name:            name,
      pool:            new Pool(name, cfg),
      query:           cfg.query,
      ping:            cfg.ping || null,
      beginTx:         cfg.beginTx  || function (client) { return cfg.query(client, "BEGIN", []); },
      commit:          cfg.commit   || function (client) { return cfg.query(client, "COMMIT", []); },
      rollback:        cfg.rollback || function (client) { return cfg.query(client, "ROLLBACK", []); },
      classifications: Array.isArray(cfg.classifications) && cfg.classifications.length > 0
                         ? cfg.classifications.slice()
                         : ["*"],
      residencyTag:    cfg.residencyTag || "unrestricted",
      breaker:         new retryHelper.CircuitBreaker("externalDb:" + name, cfg.breaker),
      retryConfig:     cfg.retry || null,
    };
  }

  defaultBackend = opts.defaultBackend || Object.keys(backends)[0];
  _validateResidency();
  initialized = true;
}

function _validateResidency() {
  var residency;
  try { residency = db().getDataResidency(); } catch (_e) { residency = null; }
  if (!residency || !residency.region) return;

  var allowed = [residency.region].concat(residency.allowedStorageRegions || []);
  for (var name in backends) {
    var b = backends[name];
    var serves = b.classifications.indexOf("*") !== -1 || b.classifications.indexOf("personal") !== -1;
    if (!serves) continue;
    if (allowed.indexOf(b.residencyTag) === -1) {
      throw _err("RESIDENCY_VIOLATION",
        "externalDb backend '" + name + "' serves 'personal' data with residencyTag '" +
        b.residencyTag + "' but app's dataResidency.region is '" + residency.region + "'",
        true);
    }
  }
}

// ---- Backend selection ----

function _pickBackend(opts) {
  opts = opts || {};
  if (opts.backend) {
    var b = backends[opts.backend];
    if (!b) throw _err("UNKNOWN_BACKEND", "no backend named '" + opts.backend + "'", true);
    if (opts.classification && !_servesClassification(b, opts.classification)) {
      throw _err("CLASSIFICATION_MISMATCH",
        "backend '" + opts.backend + "' does not serve classification '" + opts.classification + "'", true);
    }
    return b;
  }
  var classification = opts.classification;
  if (classification) {
    for (var name in backends) {
      if (_servesClassification(backends[name], classification)) return backends[name];
    }
    throw _err("NO_BACKEND_FOR_CLASSIFICATION",
      "no backend serves classification '" + classification + "'", true);
  }
  return backends[defaultBackend] || null;
}

function _servesClassification(b, cls) {
  return b.classifications.indexOf("*") !== -1 || b.classifications.indexOf(cls) !== -1;
}

// ---- Public API ----

async function query(sql, params, opts) {
  _requireInit();
  opts = opts || {};
  var b = _pickBackend(opts);

  var t0 = Date.now();
  try {
    var result = await retryHelper.withRetry(function () {
      return b.breaker.wrap(async function () {
        var client = await b.pool.acquire();
        try {
          var res = await b.query(client, sql, params || []);
          b.pool.release(client);
          return res;
        } catch (e) {
          // Connection-level errors → destroy the client; query errors →
          // release back to the pool. Heuristic: any error with a code
          // looking like a network/connection issue → destroy.
          if (e && (e.code === "ECONNRESET" || e.code === "ECONNREFUSED" ||
                    e.code === "ETIMEDOUT" || e.code === "ENOTFOUND" ||
                    e.code === "EPIPE")) {
            await b.pool.destroy(client);
          } else {
            b.pool.release(client);
          }
          throw e;
        }
      });
    }, b.retryConfig);

    _emit("system.externaldb.query", "success", {
      backend:        b.name,
      durationMs:     Date.now() - t0,
      classification: opts.classification || null,
      rowCount:       result && result.rowCount,
      // SQL is NOT logged by default — may contain sensitive literal values
      // even in parameterized queries. Operators who want SQL in audit
      // metadata pass opts.includeSqlInAudit: true (then sealed via
      // field-crypto on the audit row).
      sql:            opts.includeSqlInAudit ? sql : null,
    });
    return result;
  } catch (e) {
    _emit("system.externaldb.query", "failure", {
      backend:        b.name,
      durationMs:     Date.now() - t0,
      classification: opts.classification || null,
      errorCode:      e.code || null,
    }, (e && e.message) || String(e));
    throw e;
  }
}

async function transaction(fn, opts) {
  _requireInit();
  if (typeof fn !== "function") throw _err("INVALID_FN", "transaction requires a function", true);
  opts = opts || {};
  var b = _pickBackend(opts);

  var t0 = Date.now();
  return await b.breaker.wrap(async function () {
    var client = await b.pool.acquire();
    var txClient = {
      query: function (sql, params) { return b.query(client, sql, params || []); },
    };
    var committed = false;
    try {
      await b.beginTx(client);
      var result = await fn(txClient);
      await b.commit(client);
      committed = true;
      _emit("system.externaldb.transaction", "success", {
        backend: b.name, durationMs: Date.now() - t0, classification: opts.classification || null,
      });
      return result;
    } catch (e) {
      try { if (!committed) await b.rollback(client); } catch (_e) { /* best effort */ }
      _emit("system.externaldb.transaction", "failure", {
        backend: b.name, durationMs: Date.now() - t0, classification: opts.classification || null,
        errorCode: e.code || null,
      }, (e && e.message) || String(e));
      throw e;
    } finally {
      b.pool.release(client);
    }
  });
}

async function healthCheck(backendName) {
  _requireInit();
  if (backendName) {
    return _pingBackend(backends[backendName]);
  }
  var out = {};
  for (var name in backends) {
    out[name] = await _pingBackend(backends[name]);
  }
  return out;
}

async function _pingBackend(b) {
  if (!b) return { ok: false, error: "unknown backend" };
  try {
    var client = await b.pool.acquire();
    try {
      if (b.ping) await b.ping(client);
      else        await b.query(client, "SELECT 1", []);
      b.pool.release(client);
      return { ok: true, breakerState: b.breaker.getState(), pool: b.pool.stats() };
    } catch (e) {
      await b.pool.destroy(client);
      return { ok: false, error: e.message, breakerState: b.breaker.getState() };
    }
  } catch (e) {
    return { ok: false, error: e.message, breakerState: b.breaker.getState() };
  }
}

function listBackends() {
  if (!initialized) return [];
  return Object.keys(backends).map(function (name) {
    var b = backends[name];
    return {
      name:            name,
      classifications: b.classifications.slice(),
      residencyTag:    b.residencyTag,
      breakerState:    b.breaker.getState(),
      pool:            b.pool.stats(),
    };
  });
}

async function shutdown() {
  if (!initialized) return;
  for (var name in backends) {
    try { await backends[name].pool.drain(); } catch (_e) { /* best effort */ }
  }
  backends = {};
  defaultBackend = null;
  initialized = false;
}

// Fire-and-forget audit emission. We CANNOT await this in cluster mode:
// audit storage routes back through external-db when cluster mode is
// active, so awaiting would create a recursive dependency (every audit
// row insert triggers an external-db query which would await another
// audit row insert). Tests that need audit-row durability before reading
// audit_log should flush microtasks explicitly.
function _emit(action, outcome, metadata, reason) {
  audit().safeEmit({ action: action, outcome: outcome, reason: reason, metadata: metadata });
}

function _requireInit() {
  if (!initialized) throw _err("NOT_INITIALIZED", "externalDb.init() must be called first", true);
}

function _resetForTest() {
  Object.keys(backends).forEach(function (n) {
    try { backends[n].pool.drain(); } catch (_e) {}
  });
  backends = {};
  defaultBackend = null;
  initialized = false;
  audit.reset();
  db.reset();
}

module.exports = {
  init:           init,
  query:          query,
  transaction:    transaction,
  healthCheck:    healthCheck,
  listBackends:   listBackends,
  shutdown:       shutdown,
  Pool:           Pool,
  _resetForTest:  _resetForTest,
};
