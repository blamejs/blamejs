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
  _blamejs_audit_tip:   "_blamejs_audit_tip",
  // Same shape and purpose as _blamejs_audit_tip but for consent_log.
  // Single-row coordination state recording the tip of the consent
  // chain so a new leader (or any boot) can detect external-db
  // rollback against the consent chain too.
  _blamejs_consent_tip: "_blamejs_consent_tip",
  // Single-row anchor recording the boundary of the most recent
  // audit-tools.purge(). After a purge, audit-chain.verifyChain reads
  // this row to set its starting prevHash to lastPurgedRowHash and skip
  // rows whose monotonicCounter ≤ lastPurgedCounter — without it the
  // chain math breaks the moment the row referenced by survivors'
  // prevHash is gone.
  _blamejs_audit_purge_anchor: "_blamejs_audit_purge_anchor",
  // Scheduler tick-claim table: closes the once-globally gap during
  // cluster leader hand-offs (where two leaders briefly coexist) by
  // making each fire claim a row before dispatching. UNIQUE on the
  // composite tickKey (name + ":" + scheduledAtUnix) — loser of the
  // INSERT race skips the tick.
  _blamejs_scheduler_ticks:    "_blamejs_scheduler_ticks",
  // Rate-limit cluster-shared backend storage — fixed-window counter
  // per key. The middleware atomically INSERT...ON CONFLICT increments
  // count within the current window and rolls over when the window
  // advances. Created in cluster mode by ensureSchema; mirrored in
  // single-node SQLite by db.js's FRAMEWORK_SCHEMA so the same SQL
  // works on either side of cluster-storage's dispatch.
  _blamejs_rate_limit_counters: "_blamejs_rate_limit_counters",
  // WebSocket channel-hub cluster fan-out — publish() writes a row,
  // other nodes poll for new ids and dispatch to their local
  // subscribers. Same dual-storage shape as sessions / jobs / etc.
  _blamejs_ws_messages:        "_blamejs_ws_messages",
  _blamejs_api_encrypt_nonces: "_blamejs_api_encrypt_nonces",
  // _blamejs_sessions exists in both local SQLite (single-node mode,
  // created by db.js's FRAMEWORK_SCHEMA at boot) and external-db
  // (cluster mode, created by ensureSchema below). Same name in both
  // places — cluster-storage.execute routes the SQL to the right DB
  // based on cluster.isClusterMode().
  _blamejs_sessions:  "_blamejs_sessions",
  // _blamejs_jobs — same dual-storage pattern as sessions. The local-
  // protocol queue (lib/queue-local.js) routes through cluster-storage
  // so writes/reads land in the leader's external-db when cluster
  // mode is active and any node can observe the queue state.
  _blamejs_jobs:      "_blamejs_jobs",
});

function tableName(localName) {
  if (Object.prototype.hasOwnProperty.call(LOCAL_TO_EXTERNAL, localName)) {
    return LOCAL_TO_EXTERNAL[localName];
  }
  // For framework-internal tables that are already prefixed locally
  // (any name starting with _blamejs_), keep the same name.
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

// Same shape + invariants as audit_tip but for the consent chain.
// Updated on every consent.grant / consent.withdraw write so the boot-
// time rollback check can detect external-db rollback against the
// consent chain (previously only the audit chain had this protection).
function _consentTipDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_consent_tip;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  scope                TEXT PRIMARY KEY," +
      "  atMonotonicCounter   " + t.INT + " NOT NULL," +
      "  rowHash              TEXT," +
      "  signedAt             TEXT," +
      "  fencingToken         " + t.INT + " NOT NULL DEFAULT 0," +
      "  CHECK (scope = 'consent')" +
      ")",
    indexes: [],
  };
}

// _blamejs_audit_purge_anchor — single-row chain-origin anchor written
// by audit-tools.purge(). Holds the lastRowHash of the most recently
// purged range so verifyChain can ground its walk at the new origin.
// Single-row invariant via PRIMARY KEY on the constant-valued `scope`
// column (matches _blamejs_audit_tip pattern).
function _auditPurgeAnchorDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_audit_purge_anchor;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  scope             TEXT PRIMARY KEY," +
      "  lastPurgedCounter " + t.INT + " NOT NULL," +
      "  lastPurgedRowHash TEXT NOT NULL," +
      "  archiveBundleId   TEXT NOT NULL," +
      "  purgedAt          " + t.INT + " NOT NULL," +
      "  CHECK (scope = 'audit')" +
      ")",
    indexes: [],
  };
}

// _blamejs_scheduler_ticks — exactly-once tick-claim table. PRIMARY KEY
// on composite tickKey makes concurrent INSERTs race; the loser skips
// the tick. claimedBy carries the node id for diagnostic.
function _schedulerTicksDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_scheduler_ticks;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  tickKey         TEXT PRIMARY KEY," +
      "  name            TEXT NOT NULL," +
      "  scheduledAtUnix " + t.INT + " NOT NULL," +
      "  claimedAtUnix   " + t.INT + " NOT NULL," +
      "  claimedBy       TEXT" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_scheduledAt ON " + name + " (scheduledAtUnix)",
    ],
  };
}

// _blamejs_rate_limit_counters — fixed-window counter table for the
// cluster-shared rate-limit backend. PRIMARY KEY on the rate-limit
// key lets INSERT...ON CONFLICT atomically increment within a window
// and roll over on window advance. The windowStart index supports
// retention sweeps of expired windows.
function _rateLimitCountersDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_rate_limit_counters;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  key         TEXT PRIMARY KEY," +
      "  windowStart " + t.INT + " NOT NULL," +
      "  count       " + t.INT + " NOT NULL DEFAULT 0" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_windowStart ON " + name + " (windowStart)",
    ],
  };
}

// _blamejs_ws_messages — cluster fan-out for the WebSocket channel
// hub. publish() on any node writes a row; the other nodes poll for
// new ids past their last seen and dispatch to local subscribers.
// Auto-incrementing id is essential — postgres needs BIGSERIAL,
// sqlite gets INTEGER PRIMARY KEY (which auto-increments implicitly).
function _wsMessagesDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_ws_messages;
  var idCol = dialect === "postgres"
    ? "id          BIGSERIAL PRIMARY KEY"
    : "id          INTEGER PRIMARY KEY AUTOINCREMENT";
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  " + idCol + "," +
      "  channel     TEXT NOT NULL," +
      "  payload     TEXT NOT NULL," +
      "  publishedAt " + t.INT + " NOT NULL," +
      "  publishedBy TEXT NOT NULL" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_publishedAt ON " + name + " (publishedAt)",
    ],
  };
}

function _apiEncryptNoncesDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_api_encrypt_nonces;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  nonce    TEXT PRIMARY KEY," +
      "  expireAt " + t.INT + " NOT NULL" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_expireAt ON " + name + " (expireAt)",
    ],
  };
}

// _blamejs_sessions — DB-backed session store. Mirrors the local-SQLite
// schema in db.js's FRAMEWORK_SCHEMA so single-node and cluster-mode
// behavior is identical at the column level. Sealed columns (userId,
// data) are stored vault-sealed; sidHash is the PRIMARY KEY (the raw
// session id never lands here).
function _sessionsDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_sessions;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  sidHash         TEXT PRIMARY KEY," +
      "  userId          TEXT NOT NULL," +
      "  userIdHash      TEXT NOT NULL," +
      "  data            TEXT," +
      "  createdAt       " + t.INT + " NOT NULL," +
      "  expiresAt       " + t.INT + " NOT NULL," +
      "  lastActivity    " + t.INT + " NOT NULL" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_userIdHash ON " + name + " (userIdHash)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_expiresAt ON " + name + " (expiresAt)",
    ],
  };
}

// _blamejs_jobs — local-protocol queue jobs. Mirrors db.js's
// FRAMEWORK_SCHEMA for the same table; sealed columns (payload,
// lastError) are stored vault-sealed. Indexes target the lease
// hot-path (queueName + status + availableAt) and lease-expiry
// sweep (leaseExpiresAt).
function _jobsDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_jobs;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  _id              TEXT PRIMARY KEY," +
      "  queueName        TEXT NOT NULL," +
      "  payload          TEXT," +
      "  status           TEXT NOT NULL," +
      "  enqueuedAt       " + t.INT + " NOT NULL," +
      "  availableAt      " + t.INT + " NOT NULL," +
      "  leasedAt         " + t.INT + "," +
      "  leaseExpiresAt   " + t.INT + "," +
      "  attempts         " + t.INT + " NOT NULL DEFAULT 0," +
      "  maxAttempts      " + t.INT + " NOT NULL DEFAULT 5," +
      "  lastError        TEXT," +
      "  finishedAt       " + t.INT + "," +
      "  traceId          TEXT," +
      "  classification   TEXT" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_lease ON " + name + " (queueName, status, availableAt)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_leaseExpiresAt ON " + name + " (leaseExpiresAt)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_finishedAt ON " + name + " (finishedAt)",
    ],
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
    _consentTipDDL(dialect),
    _auditPurgeAnchorDDL(dialect),
    _schedulerTicksDDL(dialect),
    _rateLimitCountersDDL(dialect),
    _wsMessagesDDL(dialect),
    _apiEncryptNoncesDDL(dialect),
    _sessionsDDL(dialect),
    _jobsDDL(dialect),
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
