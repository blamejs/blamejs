"use strict";
/**
 * Default cluster-coordination provider — DB-row-based leader election.
 *
 * Uses an externalDb backend (already configured via b.externalDb.init)
 * as the coordination point. A single row in `_blamejs_leader` holds
 * the current lease; acquireLease is `INSERT ... ON CONFLICT ... DO
 * UPDATE WHERE expiresAt < now() RETURNING ...`, which is atomic in
 * Postgres and SQLite.
 *
 * Fencing tokens: every successful acquire bumps a monotonic integer.
 * Leader-only DB writes include the current token; the audit-tip row's
 * CHECK constraint rejects any incoming token below the stored one,
 * which fences out a partitioned old leader even if its application-
 * layer `_requireLeader()` gate somehow allowed the call through.
 *
 * Dialects: Postgres and SQLite use identical surface SQL. MySQL's
 * `ON DUPLICATE KEY UPDATE` doesn't support a WHERE clause; a MySQL
 * fallback (SELECT ... FOR UPDATE inside an explicit transaction) is
 * not yet implemented and operators on MySQL must supply their own
 * provider until it lands.
 *
 * Public API:
 *   create({ externalDbBackend, dialect? }) → provider instance
 *
 * Provider instance:
 *   ensureSchema()                       async; idempotent CREATE TABLE
 *   acquireLease(nodeId, leaseTtlMs)     async; → Lease | null
 *   renewLease(lease)                    async; → Lease (throws on takeover)
 *   releaseLease(lease)                  async; → void
 *   currentLeader()                      async; → { nodeId, leaseExpiresAt,
 *                                                   fencingToken } | null
 */
var { generateToken } = require("./crypto");
var externalDb = require("./external-db");
var { ClusterProviderError } = require("./framework-error");

function _err(code, message, permanent) {
  return new ClusterProviderError(code, message, permanent);
}

function create(config) {
  if (!config || !config.externalDbBackend) {
    throw _err("INVALID_CONFIG",
      "cluster-provider-db requires { externalDbBackend: <name> }", true);
  }
  var backendName = config.externalDbBackend;
  var dialect = (config.dialect || "postgres").toLowerCase();
  if (dialect !== "postgres" && dialect !== "sqlite") {
    throw _err("UNSUPPORTED_DIALECT",
      "cluster-provider-db dialect must be 'postgres' or 'sqlite' (got: " + dialect + ")",
      true);
  }

  // Postgres uses $1/$2 placeholders; SQLite accepts the same so we use
  // them uniformly. If a future dialect needs ?-placeholders, swap here.
  function _placeholder(n) { return "$" + n; }

  function _q(sql, params) {
    return externalDb.query(sql, params || [], { backend: backendName });
  }

  async function ensureSchema() {
    // Postgres: BIGINT for ms-precision timestamps. SQLite: INTEGER works
    // for either; pick INTEGER so the same DDL parses on both.
    var intType = dialect === "postgres" ? "BIGINT" : "INTEGER";

    await _q(
      "CREATE TABLE IF NOT EXISTS _blamejs_leader (" +
      "  scope         TEXT PRIMARY KEY," +
      "  nodeId        TEXT NOT NULL," +
      "  leaseId       TEXT NOT NULL," +
      "  acquiredAt    " + intType + " NOT NULL," +
      "  expiresAt     " + intType + " NOT NULL," +
      "  fencingToken  " + intType + " NOT NULL," +
      "  CHECK (scope = 'leader')" +
      ")"
    );
  }

  async function acquireLease(nodeId, leaseTtlMs) {
    if (!nodeId) throw _err("INVALID_NODE_ID", "nodeId required", true);
    if (typeof leaseTtlMs !== "number" || leaseTtlMs <= 0) {
      throw _err("INVALID_TTL", "leaseTtlMs must be a positive number", true);
    }
    var leaseId = generateToken(16);
    var nowMs = Date.now();
    var expiresAt = nowMs + leaseTtlMs;

    // Atomic acquire: insert if no row, OR steal if existing row's
    // expiresAt has passed. Bump fencingToken on every successful
    // mutation. RETURNING gives us the post-write state — which we
    // compare to our nodeId to know whether we won.
    var sql =
      "INSERT INTO _blamejs_leader " +
      "  (scope, nodeId, leaseId, acquiredAt, expiresAt, fencingToken) " +
      "VALUES " +
      "  ('leader', " + _placeholder(1) + ", " + _placeholder(2) + ", " +
      "   " + _placeholder(3) + ", " + _placeholder(4) + ", 1) " +
      "ON CONFLICT (scope) DO UPDATE SET " +
      "  nodeId       = EXCLUDED.nodeId," +
      "  leaseId      = EXCLUDED.leaseId," +
      "  acquiredAt   = EXCLUDED.acquiredAt," +
      "  expiresAt    = EXCLUDED.expiresAt," +
      "  fencingToken = _blamejs_leader.fencingToken + 1 " +
      "WHERE _blamejs_leader.expiresAt < " + _placeholder(5) + " " +
      "RETURNING nodeId, leaseId, acquiredAt, expiresAt, fencingToken";

    var result = await _q(sql, [nodeId, leaseId, nowMs, expiresAt, nowMs]);

    if (!result.rows || result.rows.length === 0) {
      // The WHERE clause excluded the row — someone else still holds.
      return null;
    }
    var row = result.rows[0];
    if (row.nodeId !== nodeId || row.leaseId !== leaseId) {
      // Another node won the race (RETURNING showed their values, not ours).
      return null;
    }
    return {
      nodeId:        row.nodeId,
      leaseId:       row.leaseId,
      acquiredAt:    Number(row.acquiredAt),
      expiresAt:     Number(row.expiresAt),
      fencingToken:  Number(row.fencingToken),
    };
  }

  async function renewLease(lease) {
    if (!lease || !lease.leaseId) throw _err("INVALID_LEASE", "lease required", true);
    var nowMs = Date.now();
    var newExpiresAt = nowMs + (lease.expiresAt - lease.acquiredAt);

    // Match on (nodeId, leaseId) so a takeover is detectable: if our
    // leaseId is no longer in the row, 0 rows update and we throw
    // NotLeader. Don't bump fencingToken on renewal — only on a fresh
    // acquire.
    var sql =
      "UPDATE _blamejs_leader SET " +
      "  expiresAt = " + _placeholder(1) + " " +
      "WHERE scope = 'leader' AND nodeId = " + _placeholder(2) +
      "  AND leaseId = " + _placeholder(3) + " " +
      "RETURNING nodeId, leaseId, acquiredAt, expiresAt, fencingToken";

    var result = await _q(sql, [newExpiresAt, lease.nodeId, lease.leaseId]);
    if (!result.rows || result.rows.length === 0) {
      throw _err("LEASE_LOST",
        "lease for node '" + lease.nodeId + "' was taken over (renewal rejected)",
        false);
    }
    var row = result.rows[0];
    return {
      nodeId:        row.nodeId,
      leaseId:       row.leaseId,
      acquiredAt:    Number(row.acquiredAt),
      expiresAt:     Number(row.expiresAt),
      fencingToken:  Number(row.fencingToken),
    };
  }

  async function releaseLease(lease) {
    if (!lease || !lease.leaseId) return;
    // Clear our row so the next acquire wins immediately. Match on
    // leaseId so a takeover-then-release race doesn't clear someone
    // else's lease.
    var sql =
      "UPDATE _blamejs_leader SET " +
      "  expiresAt = 0 " +
      "WHERE scope = 'leader' AND nodeId = " + _placeholder(1) +
      "  AND leaseId = " + _placeholder(2);
    await _q(sql, [lease.nodeId, lease.leaseId]);
  }

  async function currentLeader() {
    var result = await _q(
      "SELECT nodeId, expiresAt, fencingToken FROM _blamejs_leader " +
      "WHERE scope = 'leader'"
    );
    if (!result.rows || result.rows.length === 0) return null;
    var row = result.rows[0];
    if (Number(row.expiresAt) < Date.now()) return null;
    return {
      nodeId:           row.nodeId,
      leaseExpiresAt:   Number(row.expiresAt),
      fencingToken:     Number(row.fencingToken),
    };
  }

  return {
    kind:           "db",
    backendName:    backendName,
    dialect:        dialect,
    ensureSchema:   ensureSchema,
    acquireLease:   acquireLease,
    renewLease:     renewLease,
    releaseLease:   releaseLease,
    currentLeader: currentLeader,
  };
}

module.exports = {
  create: create,
};
