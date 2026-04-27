"use strict";
/**
 * Session store — DB-backed, vault-sealed, sid-hashed-at-rest.
 *
 * Single-node: stored in the framework's main DB under `_blamejs_sessions`
 * (baked into db.js's FRAMEWORK_SCHEMA — apps cannot opt out).
 * Cluster mode: stored in external-db under the same name (via
 * frameworkSchema.ensureSchema). cluster-storage.execute routes the SQL
 * to the right place based on cluster.isClusterMode(); session.js itself
 * doesn't branch on mode.
 *
 * Token discipline:
 *   - The session id (sid) is a 32-byte random value returned to the caller
 *     once. The caller stores it in a cookie / authorization header / etc.
 *   - The DB primary key is sha3('bj-session:' || sid) — the sid itself
 *     never lands in the database. DB exfiltration alone cannot impersonate
 *     a session: the attacker would also need the original sid (which only
 *     the user has).
 *   - data is vault-sealed JSON; userId is sealed; userIdHash indexes for
 *     destroyAllForUser without unsealing every row.
 *
 * Public API:
 *
 *   session.create({ userId, data?, ttlMs? })  → { token, expiresAt }
 *   session.verify(token)                      → { userId, data, createdAt, expiresAt, lastActivity } or null
 *   session.destroy(token)                     → boolean
 *   session.destroyAllForUser(userId)          → number deleted
 *   session.touch(token, { extendBy? })        → boolean (updates lastActivity, optionally extends expiresAt)
 *   session.purgeExpired()                     → number deleted
 *   session.count()                            → number of active (non-expired) sessions
 *
 * Cluster posture per blamejs-cluster-spec.md:
 *   create / destroy / destroyAllForUser / touch / purgeExpired
 *     — leader-only (cluster.requireLeader gate at call entry)
 *   verify / count
 *     — anywhere (any node can read shared session state)
 */
var { generateToken, sha3Hash } = require("./crypto");
var safeJson = require("./safe-json");
var cryptoField = require("./crypto-field");
var clusterStorage = require("./cluster-storage");
var cluster = require("./cluster");
var C = require("./constants");

var DEFAULT_TTL_MS = C.TIME.days(7);
var SID_NAMESPACE  = "bj-session:";

// Column order used for INSERT — kept as a constant so the placeholders
// list and the values list stay in sync. Must match _blamejs_sessions's
// schema in db.js (single-node) and framework-schema.js (cluster mode).
var SESSION_COLS = ["sidHash", "userId", "userIdHash", "data", "createdAt", "expiresAt", "lastActivity"];

function _hashSid(sid) {
  return sha3Hash(SID_NAMESPACE + sid);
}

// Build a sealed row object with all SESSION_COLS keys present (null
// where not set). The cryptoField.sealRow call seals userId/data and
// produces userIdHash from userId.
function _sealForInsert(row) {
  var sealed = cryptoField.sealRow("_blamejs_sessions", row);
  for (var i = 0; i < SESSION_COLS.length; i++) {
    if (!(SESSION_COLS[i] in sealed)) sealed[SESSION_COLS[i]] = null;
  }
  return sealed;
}

// ---- Public API ----

async function create(opts) {
  cluster.requireLeader();
  if (!opts || !opts.userId) {
    throw new Error("session.create requires { userId }");
  }
  var ttl = typeof opts.ttlMs === "number" ? opts.ttlMs : DEFAULT_TTL_MS;
  if (ttl <= 0) throw new Error("session.create: ttlMs must be > 0");

  var sid       = generateToken(32);             // 64 hex chars; only place the plaintext sid lives
  var sidHash   = _hashSid(sid);
  var nowMs     = Date.now();
  var expiresAt = nowMs + ttl;

  var sealed = _sealForInsert({
    sidHash:      sidHash,
    userId:       opts.userId,
    data:         opts.data ? JSON.stringify(opts.data) : null,
    createdAt:    nowMs,
    expiresAt:    expiresAt,
    lastActivity: nowMs,
  });
  var values = SESSION_COLS.map(function (c) { return sealed[c]; });
  var placeholders = SESSION_COLS.map(function () { return "?"; }).join(", ");
  var quoted = SESSION_COLS.map(function (c) { return '"' + c + '"'; }).join(", ");
  await clusterStorage.execute(
    "INSERT INTO _blamejs_sessions (" + quoted + ") VALUES (" + placeholders + ")",
    values
  );

  return { token: sid, expiresAt: expiresAt };
}

async function verify(token) {
  if (typeof token !== "string" || token.length === 0) return null;
  var sidHash = _hashSid(token);

  var row = await clusterStorage.executeOne(
    "SELECT sidHash, userId, userIdHash, data, createdAt, expiresAt, lastActivity " +
    "FROM _blamejs_sessions WHERE sidHash = ?",
    [sidHash]
  );
  if (!row) return null;
  if (Number(row.expiresAt) < Date.now()) {
    // Expired — clean up and return null. Cleanup is leader-only;
    // verify is anywhere, so a follower observing an expired row
    // skips the cleanup (next leader-side call will purge it).
    if (cluster.isLeader()) {
      try { await _deleteBySidHash(sidHash); } catch (_e) { /* best-effort */ }
    }
    return null;
  }
  // Unseal sealed columns (userId, data) using the cryptoField pipeline
  // so we return cleartext to the caller — same shape as the previous
  // db().from(...).first() path delivered.
  var unsealed = cryptoField.unsealRow("_blamejs_sessions", row);
  var data = null;
  if (unsealed.data) {
    try { data = safeJson.parse(unsealed.data); } catch (_e) { data = null; }
  }
  return {
    userId:       unsealed.userId,
    data:         data,
    createdAt:    Number(unsealed.createdAt),
    expiresAt:    Number(unsealed.expiresAt),
    lastActivity: Number(unsealed.lastActivity),
  };
}

async function destroy(token) {
  cluster.requireLeader();
  if (typeof token !== "string" || token.length === 0) return false;
  return await _deleteBySidHash(_hashSid(token));
}

async function _deleteBySidHash(sidHash) {
  var result = await clusterStorage.execute(
    "DELETE FROM _blamejs_sessions WHERE sidHash = ?",
    [sidHash]
  );
  return (result.rowCount || 0) > 0;
}

async function destroyAllForUser(userId) {
  cluster.requireLeader();
  if (!userId) throw new Error("session.destroyAllForUser requires a userId");
  // userId is sealed; look up via derived userIdHash.
  var lookup = cryptoField.lookupHash("_blamejs_sessions", "userId", userId);
  if (!lookup) {
    throw new Error("_blamejs_sessions schema is missing the userIdHash derived hash — framework misconfigured");
  }
  var result = await clusterStorage.execute(
    "DELETE FROM _blamejs_sessions WHERE userIdHash = ?",
    [lookup.value]
  );
  return result.rowCount || 0;
}

async function touch(token, opts) {
  cluster.requireLeader();
  opts = opts || {};
  if (typeof token !== "string" || token.length === 0) return false;
  var sidHash = _hashSid(token);
  var nowMs = Date.now();
  // Two SQL paths so the SET list stays static (no dynamic column
  // assembly) and matches the call shape clusterStorage expects.
  // extendBy resets expiresAt relative to NOW, not relative to the
  // current expiresAt — a soaked session with continuous traffic
  // shouldn't accumulate unbounded expiry.
  if (typeof opts.extendBy === "number" && opts.extendBy > 0) {
    var newExpires = nowMs + opts.extendBy;
    var result = await clusterStorage.execute(
      "UPDATE _blamejs_sessions SET lastActivity = ?, expiresAt = ? " +
      "WHERE sidHash = ? AND expiresAt >= ?",
      [nowMs, newExpires, sidHash, nowMs]
    );
    return (result.rowCount || 0) > 0;
  }
  var result2 = await clusterStorage.execute(
    "UPDATE _blamejs_sessions SET lastActivity = ? " +
    "WHERE sidHash = ? AND expiresAt >= ?",
    [nowMs, sidHash, nowMs]
  );
  return (result2.rowCount || 0) > 0;
}

async function purgeExpired() {
  cluster.requireLeader();
  var result = await clusterStorage.execute(
    "DELETE FROM _blamejs_sessions WHERE expiresAt < ?",
    [Date.now()]
  );
  return result.rowCount || 0;
}

async function count() {
  var row = await clusterStorage.executeOne(
    "SELECT COUNT(*) AS c FROM _blamejs_sessions WHERE expiresAt >= ?",
    [Date.now()]
  );
  return row ? Number(row.c) : 0;
}

function _resetForTest() { /* no module state to reset; clusterStorage and cryptoField own theirs */ }

module.exports = {
  create:               create,
  verify:               verify,
  destroy:              destroy,
  destroyAllForUser:    destroyAllForUser,
  touch:                touch,
  purgeExpired:         purgeExpired,
  count:                count,
  DEFAULT_TTL_MS:       DEFAULT_TTL_MS,
  _resetForTest:        _resetForTest,
};
