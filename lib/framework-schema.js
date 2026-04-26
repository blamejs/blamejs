"use strict";
/**
 * Framework state schema for cluster-mode external storage.
 *
 * When cluster mode is active, the framework's audit chain + consent
 * log + audit checkpoints + audit tip live in the operator's external-db
 * (configured via b.externalDb.init). This module owns the DDL for
 * those tables and exposes a single idempotent ensureSchema() entry
 * point that operators (or the framework's leader-acquire hook in a
 * later release) call to create them.
 *
 * In external-db the framework tables are prefixed with `_blamejs_`
 * to avoid collision with the operator's app data:
 *
 *   audit_log          local-SQLite name
 *   _blamejs_audit_log external-db name
 *
 * The mapping is exposed via tableName(local) so write-dispatch code
 * (next release) can use a single name reference.
 *
 * Dialects: Postgres + SQLite. Both support CREATE TABLE IF NOT EXISTS,
 * CREATE INDEX IF NOT EXISTS, and the same column types modulo
 * INTEGER/BIGINT and BLOB/BYTEA differences. MySQL is not yet
 * supported — operators on MySQL must wait for that adapter.
 *
 * What ensureSchema does NOT do:
 *   - Migrate existing audit_log rows from local SQLite into external-db.
 *     That migration belongs to a separate operator-driven tool.
 *   - Verify chain integrity in external-db. That happens at boot via
 *     the audit module's regular verify() path once dispatch lands.
 *   - Install append-only triggers. Trigger syntax differs across
 *     dialects and is being deferred to the next release.
 *
 * Public API:
 *   await frameworkSchema.ensureSchema({ externalDbBackend, dialect })
 *   frameworkSchema.tableName(localName)   external table name lookup
 *   frameworkSchema.LOCAL_TO_EXTERNAL      mapping (read-only)
 *   frameworkSchema.FrameworkSchemaError   error class
 */

var externalDb = require("./external-db");
var { FrameworkError } = require("./framework-error");

class FrameworkSchemaError extends FrameworkError {
  constructor(message, code) {
    super(message);
    this.name = "FrameworkSchemaError";
    this.code = code || "framework-schema/invalid";
    this.isFrameworkSchemaError = true;
  }
}

// Local-SQLite name → external-db name. The prefix protects against
// operator-app-table collision when the framework writes alongside
// app tables in the same database.
var LOCAL_TO_EXTERNAL = Object.freeze({
  audit_log:          "_blamejs_audit_log",
  consent_log:        "_blamejs_consent_log",
  audit_checkpoints:  "_blamejs_audit_checkpoints",
  // No local equivalent — only exists in external-db. Coordinates with
  // the cluster module's lease + fencing-token guard.
  _blamejs_audit_tip: "_blamejs_audit_tip",
});

function tableName(localName) {
  if (Object.prototype.hasOwnProperty.call(LOCAL_TO_EXTERNAL, localName)) {
    return LOCAL_TO_EXTERNAL[localName];
  }
  // For framework-internal tables that are already prefixed locally
  // (e.g. _blamejs_sessions in a future release), keep the same name.
  return localName;
}

// ---- Dialect-specific column types ----
// TEXT and BOOLEAN are identical across both. INTEGER and BLOB diverge.

function _types(dialect) {
  if (dialect === "postgres") {
    return { INT: "BIGINT", BLOB: "BYTEA" };
  }
  if (dialect === "sqlite") {
    return { INT: "INTEGER", BLOB: "BLOB" };
  }
  throw new FrameworkSchemaError(
    "unsupported dialect '" + dialect + "' (postgres or sqlite)",
    "framework-schema/unsupported-dialect"
  );
}

// ---- Table DDL builders ----
//
// Each builder returns { create: <CREATE TABLE SQL>, indexes: [<CREATE INDEX SQL>, ...] }.
// All DDL uses IF NOT EXISTS so re-running is idempotent.

function _auditLogDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL.audit_log;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  _id                  TEXT PRIMARY KEY," +
      "  recordedAt           " + t.INT + " NOT NULL," +
      "  monotonicCounter     " + t.INT + " NOT NULL," +
      "  actorUserId          TEXT," +
      "  actorUserIdHash      TEXT," +
      "  actorIp              TEXT," +
      "  actorUserAgent       TEXT," +
      "  actorSessionId       TEXT," +
      "  action               TEXT NOT NULL," +
      "  resourceKind         TEXT," +
      "  resourceId           TEXT," +
      "  resourceIdHash       TEXT," +
      "  outcome              TEXT NOT NULL," +
      "  reason               TEXT," +
      "  metadata             TEXT," +
      "  requestId            TEXT," +
      "  prevHash             TEXT NOT NULL," +
      "  rowHash              TEXT NOT NULL," +
      "  nonce                " + t.BLOB + " NOT NULL," +
      "  fencingToken         " + t.INT + " NOT NULL DEFAULT 0" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_actorUserIdHash ON " + name + " (actorUserIdHash)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_resourceIdHash ON " + name + " (resourceIdHash)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_recordedAt ON " + name + " (recordedAt)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_action ON " + name + " (action)",
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_" + name + "_monotonic ON " + name + " (monotonicCounter)",
    ],
  };
}

function _consentLogDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL.consent_log;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  _id                  TEXT PRIMARY KEY," +
      "  recordedAt           " + t.INT + " NOT NULL," +
      "  monotonicCounter     " + t.INT + " NOT NULL," +
      "  subjectId            TEXT NOT NULL," +
      "  subjectIdHash        TEXT NOT NULL," +
      "  purpose              TEXT NOT NULL," +
      "  lawfulBasis          TEXT NOT NULL," +
      "  action               TEXT NOT NULL," +
      "  scope                TEXT," +
      "  channel              TEXT NOT NULL," +
      "  evidenceRef          TEXT," +
      "  prevHash             TEXT NOT NULL," +
      "  rowHash              TEXT NOT NULL," +
      "  nonce                " + t.BLOB + " NOT NULL," +
      "  fencingToken         " + t.INT + " NOT NULL DEFAULT 0" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_subjectIdHash ON " + name + " (subjectIdHash)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_recordedAt ON " + name + " (recordedAt)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_purpose ON " + name + " (purpose)",
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_" + name + "_monotonic ON " + name + " (monotonicCounter)",
    ],
  };
}

function _auditCheckpointsDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL.audit_checkpoints;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  _id                  TEXT PRIMARY KEY," +
      "  createdAt            " + t.INT + " NOT NULL," +
      "  atMonotonicCounter   " + t.INT + " NOT NULL," +
      "  atRowHash            TEXT NOT NULL," +
      "  signature            " + t.BLOB + " NOT NULL," +
      "  publicKeyFingerprint TEXT NOT NULL," +
      "  fencingToken         " + t.INT + " NOT NULL DEFAULT 0" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_createdAt ON " + name + " (createdAt)",
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_" + name + "_chkpt_counter ON " + name + " (atMonotonicCounter)",
    ],
  };
}

// audit_tip is single-row coordination state for cluster-mode rollback
// detection. The CHECK constraint on fencingToken is the canonical
// fencing-token guard from the cluster spec — enforced at the DB
// level so a partitioned old leader can't insert rows behind a new
// leader's back regardless of application-layer state.
//
// Postgres and SQLite both honour CHECK constraints. The single-row
// invariant is enforced via PRIMARY KEY on the constant-valued
// `scope` column.
function _auditTipDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_audit_tip;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  scope                TEXT PRIMARY KEY," +
      "  atMonotonicCounter   " + t.INT + " NOT NULL," +
      "  rowHash              TEXT," +
      "  signedAt             TEXT," +
      "  fencingToken         " + t.INT + " NOT NULL DEFAULT 0," +
      "  CHECK (scope = 'audit')" +
      ")",
    indexes: [],
  };
}

// ---- ensureSchema ----

async function ensureSchema(opts) {
  if (!opts || !opts.externalDbBackend) {
    throw new FrameworkSchemaError(
      "ensureSchema requires { externalDbBackend: <name> }",
      "framework-schema/invalid-config"
    );
  }
  var dialect = (opts.dialect || "postgres").toLowerCase();
  if (dialect !== "postgres" && dialect !== "sqlite") {
    throw new FrameworkSchemaError(
      "unsupported dialect '" + dialect + "' (postgres or sqlite)",
      "framework-schema/unsupported-dialect"
    );
  }

  var ddls = [
    _auditLogDDL(dialect),
    _consentLogDDL(dialect),
    _auditCheckpointsDDL(dialect),
    _auditTipDDL(dialect),
  ];

  var created = [];
  for (var i = 0; i < ddls.length; i++) {
    var d = ddls[i];
    await externalDb.query(d.create, [], { backend: opts.externalDbBackend });
    for (var j = 0; j < d.indexes.length; j++) {
      await externalDb.query(d.indexes[j], [], { backend: opts.externalDbBackend });
    }
    created.push(d.create.match(/CREATE TABLE IF NOT EXISTS\s+(\S+)/)[1]);
  }
  return { tables: created };
}

module.exports = {
  ensureSchema:           ensureSchema,
  tableName:              tableName,
  LOCAL_TO_EXTERNAL:      LOCAL_TO_EXTERNAL,
  FrameworkSchemaError:   FrameworkSchemaError,
};
