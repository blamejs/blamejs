"use strict";
/**
 * Session store — DB-backed, vault-sealed, sid-hashed-at-rest.
 *
 * Stored in the framework's main DB under `_blamejs_sessions` (baked into
 * FRAMEWORK_SCHEMA — apps cannot opt out). Sessions persist across restarts;
 * apps that want ephemeral semantics can call session.purgeAll() at boot.
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
 * Public API (all sync — backed by node:sqlite):
 *
 *   session.create({ userId, data?, ttlMs? })  → { token, expiresAt }
 *   session.verify(token)                      → { userId, data, createdAt, expiresAt, lastActivity } or null
 *   session.destroy(token)                     → boolean
 *   session.destroyAllForUser(userId)          → number deleted
 *   session.touch(token, { extendBy? })        → boolean (updates lastActivity, optionally extends expiresAt)
 *   session.purgeExpired()                     → number deleted
 *   session.count()                            → number of active (non-expired) sessions
 */
var { generateToken, sha3Hash } = require("./crypto");
var jsonSafe = require("./json-safe");
var fieldCrypto = require("./field-crypto");
var cluster = require("./cluster");
var C = require("./constants");
var lazyRequire = require("./lazy-require");

var DEFAULT_TTL_MS = C.TIME.days(7);
var SID_NAMESPACE  = "bj-session:";

var db = lazyRequire(function () { return require("./db"); });

function _hashSid(sid) {
  return sha3Hash(SID_NAMESPACE + sid);
}

// ---- Public API ----

function create(opts) {
  cluster.requireLeader();
  if (!opts || !opts.userId) {
    throw new Error("session.create requires { userId }");
  }
  var ttl     = typeof opts.ttlMs === "number" ? opts.ttlMs : DEFAULT_TTL_MS;
  if (ttl <= 0) throw new Error("session.create: ttlMs must be > 0");

  var sid       = generateToken(32);             // 64 hex chars; only place the plaintext sid lives
  var sidHash   = _hashSid(sid);
  var nowMs     = Date.now();
  var expiresAt = nowMs + ttl;

  // Direct INSERT (not via query builder) because _blamejs_sessions has
  // sidHash as PK, not _id — the builder's auto-_id helper would inject a
  // column that doesn't exist on this table.
  var sealed = fieldCrypto.sealRow("_blamejs_sessions", {
    sidHash:      sidHash,
    userId:       opts.userId,
    data:         opts.data ? JSON.stringify(opts.data) : null,
    createdAt:    nowMs,
    expiresAt:    expiresAt,
    lastActivity: nowMs,
  });
  // Materialize null entries for any expected column not present
  var allCols = ["sidHash", "userId", "userIdHash", "data", "createdAt", "expiresAt", "lastActivity"];
  for (var i = 0; i < allCols.length; i++) {
    if (!(allCols[i] in sealed)) sealed[allCols[i]] = null;
  }
  var placeholders = allCols.map(function () { return "?"; }).join(", ");
  var quoted = allCols.map(function (c) { return '"' + c + '"'; }).join(", ");
  var values = allCols.map(function (c) { return sealed[c]; });
  var stmt = db().prepare("INSERT INTO _blamejs_sessions (" + quoted + ") VALUES (" + placeholders + ")");
  stmt.run.apply(stmt, values);

  return { token: sid, expiresAt: expiresAt };
}

function verify(token) {
  if (typeof token !== "string" || token.length === 0) return null;
  var sidHash = _hashSid(token);

  // Direct query — sidHash is raw (not sealed); userId/data come back sealed
  // and field-crypto unseals via from().where().first() pipeline.
  var row = db().from("_blamejs_sessions").where({ sidHash: sidHash }).first();
  if (!row) return null;
  if (row.expiresAt < Date.now()) {
    // Expired — clean up and return null
    _deleteBySidHash(sidHash);
    return null;
  }
  var data = null;
  if (row.data) {
    try { data = jsonSafe.parse(row.data); } catch (_e) { data = null; }
  }
  return {
    userId:       row.userId,
    data:         data,
    createdAt:    row.createdAt,
    expiresAt:    row.expiresAt,
    lastActivity: row.lastActivity,
  };
}

function destroy(token) {
  cluster.requireLeader();
  if (typeof token !== "string" || token.length === 0) return false;
  return _deleteBySidHash(_hashSid(token));
}

function _deleteBySidHash(sidHash) {
  return db().from("_blamejs_sessions").where({ sidHash: sidHash }).deleteOne();
}

function destroyAllForUser(userId) {
  cluster.requireLeader();
  if (!userId) throw new Error("session.destroyAllForUser requires a userId");
  // userId is sealed; look up via derived userIdHash
  var hash = db().hashFor("_blamejs_sessions", "userId", userId);
  if (!hash) {
    throw new Error("_blamejs_sessions schema is missing the userIdHash derived hash — framework misconfigured");
  }
  return db().from("_blamejs_sessions").where({ userIdHash: hash }).deleteMany();
}

function touch(token, opts) {
  cluster.requireLeader();
  opts = opts || {};
  if (typeof token !== "string" || token.length === 0) return false;
  var sidHash = _hashSid(token);
  var nowMs = Date.now();
  var changes = { lastActivity: nowMs };
  if (typeof opts.extendBy === "number" && opts.extendBy > 0) {
    // Extend expiry by the specified ms relative to now (NOT relative to current expiry —
    // a soaked session with high traffic shouldn't accumulate unbounded expiry).
    changes.expiresAt = nowMs + opts.extendBy;
  }
  var ok = db().from("_blamejs_sessions")
    .where({ sidHash: sidHash })
    .where("expiresAt", ">=", nowMs)
    .updateOne(changes);
  return ok === true;
}

function purgeExpired() {
  cluster.requireLeader();
  return db().from("_blamejs_sessions").where("expiresAt", "<", Date.now()).deleteMany();
}

function count() {
  return db().from("_blamejs_sessions").where("expiresAt", ">=", Date.now()).count();
}

function _resetForTest() { db.reset(); }

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
