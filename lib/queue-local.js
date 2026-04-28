"use strict";
/**
 * Local-protocol queue adapter — DB-backed, dialect-portable.
 *
 * Single-node: backed by the framework's main DB (_blamejs_jobs in
 * local SQLite, baked into FRAMEWORK_SCHEMA).
 * Cluster mode: backed by external-db (_blamejs_jobs created via
 * frameworkSchema.ensureSchema). cluster-storage.execute routes the
 * same SQL to the right place based on cluster.isClusterMode().
 *
 * Lease semantics:
 *   enqueue → INSERT status='pending'
 *   lease   → atomic UPDATE pending→inflight (single statement with
 *             RETURNING; no transaction needed — the WHERE clause's
 *             subquery + Postgres's row-lock-then-recheck behavior
 *             makes concurrent leasers safe automatically. The unlucky
 *             leaser sees zero rows and tries again on the next tick.)
 *   complete→ UPDATE inflight→done
 *   fail    → single UPDATE with CASE WHEN attempts < maxAttempts
 *             (retry) ELSE (final failure) — collapsed into one
 *             statement so the same code path works in both single-
 *             node and cluster mode without a cross-dialect
 *             transaction primitive.
 *   sweep   → orphaned 'inflight' rows whose lease expired → 'pending'
 *
 * Field-crypto integration: payload + lastError are sealed columns
 * (declared in db.js's FRAMEWORK_SCHEMA registration). enqueue seals
 * before INSERT; lease unseals the leased rows before returning to
 * the caller. cluster-storage's RETURNING clause hands back sealed
 * blobs which we run through cryptoField.unsealRow explicitly.
 */
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var { generateToken } = require("./crypto");
var cryptoField = require("./crypto-field");
var safeJson = require("./safe-json");
var lazyRequire = require("./lazy-require");
var { QueueError } = require("./framework-error");

var _err = QueueError.factory;

// vault is lazy-required because some flows (sealed lastError) only
// touch it on retry-with-error paths, and the import order
// (queue-local → vault → db → audit → cluster) tolerates the late bind.
var vault = lazyRequire(function () { return require("./vault"); });

// Column order kept as a constant so the placeholders + values lists
// stay in sync. Mirrors db.js's FRAMEWORK_SCHEMA for _blamejs_jobs.
var JOB_COLS = [
  "_id", "queueName", "payload", "status",
  "enqueuedAt", "availableAt", "leasedAt", "leaseExpiresAt",
  "attempts", "maxAttempts", "lastError", "finishedAt",
  "traceId", "classification",
];

// Columns returned by lease() / used by RETURNING. Subset of JOB_COLS
// — only what callers need; fewer bytes over the wire in cluster mode.
var LEASE_RETURN_COLS = [
  "_id", "queueName", "payload",
  "attempts", "maxAttempts", "traceId", "classification",
  "enqueuedAt", "leaseExpiresAt",
];

function _quotedList(cols) {
  return cols.map(function (c) { return '"' + c + '"'; }).join(", ");
}

function _placeholders(cols) {
  return cols.map(function () { return "?"; }).join(", ");
}

function _shapeLeasedRow(raw) {
  // raw is a row coming back from RETURNING — payload is sealed if
  // present. Run through cryptoField's unseal pipeline so the caller
  // gets cleartext.
  var unsealed = cryptoField.unsealRow("_blamejs_jobs", raw);
  return {
    jobId:          unsealed._id,
    queueName:      unsealed.queueName,
    payload:        unsealed.payload ? safeJson.parse(unsealed.payload) : null,
    attempts:       Number(unsealed.attempts),
    maxAttempts:    Number(unsealed.maxAttempts),
    traceId:        unsealed.traceId,
    classification: unsealed.classification,
    enqueuedAt:     Number(unsealed.enqueuedAt),
    leaseExpiresAt: Number(unsealed.leaseExpiresAt),
  };
}

function create(_config) {
  // No protocol-level config — uses cluster-storage which dispatches
  // to the framework's main DB (single-node) or external-db (cluster).

  async function enqueue(queueName, payload, opts) {
    cluster.requireLeader();
    opts = opts || {};
    var nowMs = Date.now();
    var availableAt = nowMs + (opts.delaySeconds ? opts.delaySeconds * 1000 : 0);

    var row = {
      _id:             generateToken(16),
      queueName:       queueName,
      payload:         payload === undefined ? null : JSON.stringify(payload),
      status:          "pending",
      enqueuedAt:      nowMs,
      availableAt:     availableAt,
      leasedAt:        null,
      leaseExpiresAt:  null,
      attempts:        0,
      maxAttempts:     opts.maxAttempts != null ? opts.maxAttempts : 5,
      lastError:       null,
      finishedAt:      null,
      traceId:         opts.traceId || null,
      classification:  opts.classification || null,
    };
    var sealed = cryptoField.sealRow("_blamejs_jobs", row);
    var values = JOB_COLS.map(function (c) { return c in sealed ? sealed[c] : null; });

    await clusterStorage.execute(
      "INSERT INTO _blamejs_jobs (" + _quotedList(JOB_COLS) + ") " +
      "VALUES (" + _placeholders(JOB_COLS) + ")",
      values
    );
    return {
      jobId:          row._id,
      queueName:      queueName,
      enqueuedAt:     nowMs,
      availableAt:    availableAt,
      classification: row.classification,
    };
  }

  async function lease(queueName, leaseMs, count) {
    cluster.requireLeader();
    var nowMs = Date.now();
    var leaseExpiresAt = nowMs + leaseMs;
    var maxRows = count != null ? count : 1;

    // Single-statement atomic lease. The IN-subquery picks the head of
    // the queue; the outer UPDATE locks those rows and only updates
    // rows that still match status='pending' after the lock acquires
    // (Postgres EvalPlanQual; SQLite is single-writer so the same row
    // can't be picked twice). RETURNING hands back the leased columns
    // so we don't need a separate SELECT after the UPDATE.
    var sql =
      "UPDATE _blamejs_jobs " +
      "SET status = 'inflight', leasedAt = ?, leaseExpiresAt = ?, attempts = attempts + 1 " +
      "WHERE _id IN (" +
      "  SELECT _id FROM _blamejs_jobs " +
      "  WHERE queueName = ? AND status = 'pending' AND availableAt <= ? " +
      "  ORDER BY availableAt ASC, enqueuedAt ASC " +
      "  LIMIT ?" +
      ") " +
      "RETURNING " + _quotedList(LEASE_RETURN_COLS);
    var result = await clusterStorage.execute(
      sql,
      [nowMs, leaseExpiresAt, queueName, nowMs, maxRows]
    );
    var leased = [];
    for (var i = 0; i < result.rows.length; i++) {
      leased.push(_shapeLeasedRow(result.rows[i]));
    }
    return leased;
  }

  // extendLease — push the lease expiry forward for a long-running job.
  // Handler context exposes this as `ctx.extendLease(ms)`. The job must
  // still be in 'inflight' status (i.e. not yet swept by sweepExpired);
  // otherwise the call no-ops and returns false.
  async function extendLease(jobId, additionalMs) {
    cluster.requireLeader();
    if (typeof additionalMs !== "number" || additionalMs <= 0) {
      throw _err("INVALID_LEASE_EXTENSION",
        "extendLease: additionalMs must be a positive number", true);
    }
    var newExpiry = Date.now() + additionalMs;
    var result = await clusterStorage.execute(
      "UPDATE _blamejs_jobs SET leaseExpiresAt = ? " +
      "WHERE _id = ? AND status = 'inflight'",
      [newExpiry, jobId]
    );
    return (result.rowCount || 0) > 0;
  }

  async function complete(jobId) {
    cluster.requireLeader();
    await clusterStorage.execute(
      "UPDATE _blamejs_jobs SET status = 'done', finishedAt = ?, leaseExpiresAt = NULL " +
      "WHERE _id = ? AND status = 'inflight'",
      [Date.now(), jobId]
    );
    return true;
  }

  async function fail(jobId, errorMessage, opts) {
    cluster.requireLeader();
    opts = opts || {};
    var retryDelayMs = opts.retryDelayMs != null ? opts.retryDelayMs : 0;
    var nowMs = Date.now();
    var sealedErr = errorMessage ? vault().seal(String(errorMessage)) : null;

    // Single-statement decision: retry vs final failure based on the
    // row's current attempts/maxAttempts. CASE expressions split the
    // status / availableAt / finishedAt updates per branch — same
    // semantics as the previous SELECT-then-UPDATE-in-transaction
    // path, but no cross-dialect transaction primitive needed.
    await clusterStorage.execute(
      "UPDATE _blamejs_jobs SET " +
      "  status = CASE WHEN attempts < maxAttempts THEN 'pending' ELSE 'failed' END, " +
      "  lastError = ?, " +
      "  leaseExpiresAt = NULL, " +
      "  availableAt = CASE WHEN attempts < maxAttempts THEN ? ELSE availableAt END, " +
      "  finishedAt  = CASE WHEN attempts < maxAttempts THEN NULL ELSE ? END " +
      "WHERE _id = ?",
      [sealedErr, nowMs + retryDelayMs, nowMs, jobId]
    );
    return true;
  }

  async function sweepExpired() {
    cluster.requireLeader();
    var result = await clusterStorage.execute(
      "UPDATE _blamejs_jobs SET status = 'pending', leaseExpiresAt = NULL " +
      "WHERE status = 'inflight' AND leaseExpiresAt < ?",
      [Date.now()]
    );
    return result.rowCount || 0;
  }

  async function size(queueName) {
    var row = await clusterStorage.executeOne(
      "SELECT COUNT(*) AS n FROM _blamejs_jobs " +
      "WHERE queueName = ? AND (status = 'pending' OR status = 'inflight')",
      [queueName]
    );
    return row ? Number(row.n) : 0;
  }

  // ---- DLQ (dead-letter queue) ----
  //
  // Jobs that exhausted their retry budget land in status='failed' with
  // finishedAt set + lastError sealed. dlqList surfaces them for
  // operator review; dlqRetry resets a job back to 'pending' so it can
  // be reprocessed (operator-driven — never automatic).

  async function dlqList(queueName, opts) {
    opts = opts || {};
    var limit = (typeof opts.limit === "number" && opts.limit > 0) ? opts.limit : 100;
    var rows = await clusterStorage.executeAll(
      "SELECT _id, queueName, payload, status, enqueuedAt, finishedAt, " +
      "       attempts, maxAttempts, lastError, traceId, classification " +
      "FROM _blamejs_jobs " +
      "WHERE queueName = ? AND status = 'failed' " +
      "ORDER BY finishedAt DESC LIMIT ?",
      [queueName, limit]
    );
    return rows.map(function (row) {
      var unsealed = cryptoField.unsealRow("_blamejs_jobs", row);
      return {
        jobId:       row._id,
        queueName:   row.queueName,
        payload:     unsealed.payload ? JSON.parse(unsealed.payload) : null,
        status:      row.status,
        enqueuedAt:  Number(row.enqueuedAt),
        finishedAt:  row.finishedAt ? Number(row.finishedAt) : null,
        attempts:    Number(row.attempts),
        maxAttempts: Number(row.maxAttempts),
        lastError:   unsealed.lastError || null,
        traceId:     row.traceId || null,
        classification: row.classification || null,
      };
    });
  }

  async function dlqRetry(jobId) {
    cluster.requireLeader();
    var nowMs = Date.now();
    var result = await clusterStorage.execute(
      "UPDATE _blamejs_jobs SET " +
      "  status = 'pending', " +
      "  attempts = 0, " +
      "  availableAt = ?, " +
      "  finishedAt = NULL, " +
      "  leasedAt = NULL, " +
      "  leaseExpiresAt = NULL, " +
      "  lastError = NULL " +
      "WHERE _id = ? AND status = 'failed'",
      [nowMs, jobId]
    );
    return (result.rowCount || 0) > 0;
  }

  async function dlqSize(queueName) {
    var row = await clusterStorage.executeOne(
      "SELECT COUNT(*) AS n FROM _blamejs_jobs " +
      "WHERE queueName = ? AND status = 'failed'",
      [queueName]
    );
    return row ? Number(row.n) : 0;
  }

  async function purge(queueName) {
    cluster.requireLeader();
    var result = await clusterStorage.execute(
      "DELETE FROM _blamejs_jobs WHERE queueName = ?",
      [queueName]
    );
    return result.rowCount || 0;
  }

  return {
    protocol:       "local",
    enqueue:        enqueue,
    lease:          lease,
    extendLease:    extendLease,
    complete:       complete,
    fail:           fail,
    sweepExpired:   sweepExpired,
    size:           size,
    purge:          purge,
    dlqList:        dlqList,
    dlqRetry:       dlqRetry,
    dlqSize:        dlqSize,
  };
}

module.exports = { create: create };
