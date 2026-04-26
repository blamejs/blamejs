"use strict";
/**
 * Local SQLite-backed queue protocol adapter.
 *
 * Backed by the framework's own DB via the _blamejs_jobs table (baked into
 * FRAMEWORK_SCHEMA). All operations go through SQLite; no separate process,
 * no network. Suitable for single-host deployments and as a fallback when
 * an external queue (Redis, SQS, AMQP, NATS) isn't yet configured.
 *
 * Lease semantics:
 *   enqueue → INSERT status='pending'
 *   lease   → atomic UPDATE pending→inflight, returns the leased rows
 *   complete→ UPDATE inflight→done
 *   fail    → if attempts < maxAttempts: pending again with backoff
 *             else                     : status='failed'
 *   sweep   → orphaned 'inflight' rows whose lease expired return to 'pending'
 *
 * Field-crypto integration: payload + lastError are sealed columns; written
 * sealed, returned plaintext on lease (via the framework's sealRow / unsealRow
 * pipeline). Job IDs are not subject IDs, so no derived-hash tracking.
 */
var { generateToken } = require("./crypto");
var jsonSafe = require("./json-safe");
var ha = require("./ha");

function _err(code, message, permanent) {
  var e = new Error(message);
  e.code = code;
  e.permanent = !!permanent;
  e.isQueueError = true;
  return e;
}

var _db = null;
function db() { if (!_db) _db = require("./db"); return _db; }

var _fieldCrypto = null;
function fieldCrypto() { if (!_fieldCrypto) _fieldCrypto = require("./field-crypto"); return _fieldCrypto; }

function create(_config) {
  // No protocol-level config — uses the framework's main DB.

  function enqueue(queueName, payload, opts) {
    ha.requireLeader();
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
    var sealed = fieldCrypto().sealRow("_blamejs_jobs", row);

    var allCols = [
      "_id", "queueName", "payload", "status",
      "enqueuedAt", "availableAt", "leasedAt", "leaseExpiresAt",
      "attempts", "maxAttempts", "lastError", "finishedAt",
      "traceId", "classification",
    ];
    var placeholders = allCols.map(function () { return "?"; }).join(", ");
    var quoted = allCols.map(function (c) { return '"' + c + '"'; }).join(", ");
    var values = allCols.map(function (c) { return c in sealed ? sealed[c] : null; });
    var stmt = db().prepare("INSERT INTO _blamejs_jobs (" + quoted + ") VALUES (" + placeholders + ")");
    stmt.run.apply(stmt, values);

    return Promise.resolve({
      jobId:          row._id,
      queueName:      queueName,
      enqueuedAt:     nowMs,
      availableAt:    availableAt,
      classification: row.classification,
    });
  }

  // Atomically lease up to `count` pending jobs whose availableAt <= now.
  // Returns the leased rows (decrypted via the field-crypto pipeline).
  function lease(queueName, leaseMs, count) {
    ha.requireLeader();
    var nowMs = Date.now();
    var leaseExpiresAt = nowMs + leaseMs;
    var maxRows = count != null ? count : 1;

    // Run the candidate select + update inside a transaction so the lease
    // is atomic vs other consumers competing on the same queue.
    var leasedRows = [];
    db().transaction(function (txDb) {
      var rowIds = txDb.prepare(
        'SELECT _id FROM _blamejs_jobs ' +
        'WHERE queueName = ? AND status = ? AND availableAt <= ? ' +
        'ORDER BY availableAt ASC, enqueuedAt ASC LIMIT ?'
      ).all(queueName, "pending", nowMs, maxRows).map(function (r) { return r._id; });

      if (rowIds.length === 0) return;

      var placeholders = rowIds.map(function () { return "?"; }).join(", ");
      var updStmt = txDb.prepare(
        'UPDATE _blamejs_jobs SET status = ?, leasedAt = ?, leaseExpiresAt = ?, attempts = attempts + 1 ' +
        'WHERE _id IN (' + placeholders + ')'
      );
      updStmt.run.apply(updStmt, ["inflight", nowMs, leaseExpiresAt].concat(rowIds));

      // Read back the leased rows (decrypted via from() pipeline)
      for (var i = 0; i < rowIds.length; i++) {
        var leased = txDb.from("_blamejs_jobs").where({ _id: rowIds[i] }).first();
        if (leased) {
          leasedRows.push({
            jobId:          leased._id,
            queueName:      leased.queueName,
            payload:        leased.payload ? jsonSafe.parse(leased.payload) : null,
            attempts:       leased.attempts,
            maxAttempts:    leased.maxAttempts,
            traceId:        leased.traceId,
            classification: leased.classification,
            enqueuedAt:     leased.enqueuedAt,
            leaseExpiresAt: leased.leaseExpiresAt,
          });
        }
      }
    });
    return Promise.resolve(leasedRows);
  }

  function complete(jobId) {
    ha.requireLeader();
    db().prepare(
      'UPDATE _blamejs_jobs SET status = ?, finishedAt = ?, leaseExpiresAt = NULL ' +
      'WHERE _id = ? AND status = ?'
    ).run("done", Date.now(), jobId, "inflight");
    return Promise.resolve(true);
  }

  function fail(jobId, errorMessage, opts) {
    ha.requireLeader();
    opts = opts || {};
    var retryDelayMs = opts.retryDelayMs != null ? opts.retryDelayMs : 0;
    var nowMs = Date.now();
    db().transaction(function (txDb) {
      var row = txDb.from("_blamejs_jobs").where({ _id: jobId }).first();
      if (!row) return;
      var sealedErr = errorMessage ? require("./vault").seal(String(errorMessage)) : null;
      if (row.attempts < row.maxAttempts) {
        // Retry — back to pending
        txDb.prepare(
          'UPDATE _blamejs_jobs SET status = ?, lastError = ?, leaseExpiresAt = NULL, availableAt = ? ' +
          'WHERE _id = ?'
        ).run("pending", sealedErr, nowMs + retryDelayMs, jobId);
      } else {
        // Final failure
        txDb.prepare(
          'UPDATE _blamejs_jobs SET status = ?, lastError = ?, leaseExpiresAt = NULL, finishedAt = ? ' +
          'WHERE _id = ?'
        ).run("failed", sealedErr, nowMs, jobId);
      }
    });
    return Promise.resolve(true);
  }

  // Re-pending jobs whose lease has expired (consumer crashed mid-handler).
  function sweepExpired() {
    ha.requireLeader();
    var nowMs = Date.now();
    var info = db().prepare(
      'UPDATE _blamejs_jobs SET status = ?, leaseExpiresAt = NULL ' +
      'WHERE status = ? AND leaseExpiresAt < ?'
    ).run("pending", "inflight", nowMs);
    return Promise.resolve(info.changes);
  }

  function size(queueName) {
    var row = db().prepare(
      'SELECT COUNT(*) AS n FROM _blamejs_jobs WHERE queueName = ? AND status IN (?, ?)'
    ).get(queueName, "pending", "inflight");
    return Promise.resolve(row ? row.n : 0);
  }

  function purge(queueName) {
    ha.requireLeader();
    var info = db().prepare('DELETE FROM _blamejs_jobs WHERE queueName = ?').run(queueName);
    return Promise.resolve(info.changes);
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
