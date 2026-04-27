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
 *             (retry) ELSE (final failure) — was a transaction in
 *             v0.1.50 and earlier; collapsed into one statement so the
 *             same code path works in both single-node and cluster
 *             mode without a cross-dialect transaction primitive.
 *   sweep   → orphaned 'inflight' rows whose lease expired → 'pending'
 *
 * Field-crypto integration: payload + lastError are sealed columns
 * (declared in db.js's FRAMEWORK_SCHEMA registration). enqueue seals
 * before INSERT; lease unseals the leased rows before returning to
 * the caller. cluster-storage's RETURNING clause hands back sealed
 * blobs which we run through fieldCrypto.unsealRow explicitly.
 */
var { generateToken } = require("./crypto");
var jsonSafe = require("./safe-json");
var clusterStorage = require("./cluster-storage");
var cluster = require("./cluster");
var fieldCrypto = require("./crypto-field");
var lazyRequire = require("./lazy-require");
var { QueueError } = require("./framework-error");

function _err(code, message, permanent) {
  return new QueueError(code, message, permanent);
}

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
  // present. Run through fieldCrypto's unseal pipeline so the caller
  // gets cleartext.
  var unsealed = fieldCrypto.unsealRow("_blamejs_jobs", raw);
  return {
    jobId:          unsealed._id,
    queueName:      unsealed.queueName,
    payload:        unsealed.payload ? jsonSafe.parse(unsealed.payload) : null,
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
    var sealed = fieldCrypto.sealRow("_blamejs_jobs", row);
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
    complete:       complete,
    fail:           fail,
    sweepExpired:   sweepExpired,
    size:           size,
    purge:          purge,
  };
}

module.exports = { create: create };
