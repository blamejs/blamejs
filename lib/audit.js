"use strict";
/**
 * Audit log — tamper-evident, append-only record of every privileged action.
 *
 * audit_log table is baked into db.js's schema runner — apps cannot opt out.
 * Every row is hash-chained (lib/audit-chain.js); the chain is verified at
 * boot in db.init(); a chain break refuses-to-boot per the compliance stance.
 *
 * Action namespaces (per Q3=B):
 *   - Framework owns: 'auth.*', 'system.*', 'audit.*', 'consent.*', 'subject.*'
 *   - Apps register their own via audit.registerNamespace('orders'), then
 *     can record 'orders.created', 'orders.shipped', etc.
 *   - Unregistered namespaces are rejected — prevents typos becoming silent
 *     unobservable events.
 *
 * Hash chain:
 *   - rowHash is computed over the *sealed* form of the row + the nonce.
 *     The sealed form is what's stored on disk; verification recomputes
 *     directly from disk without unsealing anything (faster + lets auditors
 *     verify integrity even without the vault key).
 *
 * Public API:
 *   audit.registerNamespace(name)
 *   audit.record({ actor, action, resource, outcome, reason, metadata, requestId }) → row
 *   audit.query({ from, to, actorUserId, action, resourceKind, resourceId, limit, offset }) → rows
 *   audit.verify(opts?) → { ok, rowsVerified, breakAt? }
 */
var { generateToken, generateBytes } = require("./crypto");
var auditChain = require("./audit-chain");
var fieldCrypto = require("./field-crypto");

var FRAMEWORK_NAMESPACES = ["auth", "system", "audit", "consent", "subject"];
var registeredNamespaces = new Set(FRAMEWORK_NAMESPACES);

// All hashable columns of audit_log (everything in the table except the chain
// bookkeeping itself). This list MUST match what's actually written by INSERT
// and what's read back by verify; the canonicalizer needs the same key set
// at both ends or the hash will mismatch on missing-vs-null keys.
var HASHABLE_COLS = [
  "_id", "recordedAt", "monotonicCounter",
  "actorUserId", "actorUserIdHash",
  "actorIp",
  "actorUserAgent", "actorSessionId",
  "action", "resourceKind",
  "resourceId", "resourceIdHash",
  "outcome", "reason", "metadata", "requestId",
];

// Lazy db ref — avoids circular require (db -> audit -> db on init paths).
var _db = null;
function db() {
  if (!_db) _db = require("./db");
  return _db;
}

// In-process monotonic counter; lazily initialized from MAX(monotonicCounter)
// at first record(). Single-writer SQLite serializes inserts, so a fresh
// initialization at boot is sufficient — no concurrent process can race past
// our value before our first insert.
var _counterInitialized = false;
var _nextCounter = 1;

function _initCounter() {
  if (_counterInitialized) return;
  var row = db().prepare("SELECT MAX(monotonicCounter) AS m FROM audit_log").get();
  _nextCounter = (row && row.m ? row.m : 0) + 1;
  _counterInitialized = true;
}

// ---- Public API ----

function registerNamespace(name) {
  if (typeof name !== "string" || !/^[a-z][a-z0-9_]*$/.test(name)) {
    throw new Error("audit namespace must match [a-z][a-z0-9_]* — got: " + name);
  }
  if (FRAMEWORK_NAMESPACES.indexOf(name) !== -1) return;
  registeredNamespaces.add(name);
}

function _validateAction(action) {
  if (typeof action !== "string" || !/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(action)) {
    throw new Error(
      "audit action must be 'namespace.verb[.qualifier...]' (lowercase, dot-separated) — got: " + action
    );
  }
  var ns = action.split(".")[0];
  if (!registeredNamespaces.has(ns)) {
    throw new Error(
      "audit namespace '" + ns + "' is not registered. " +
      "Call audit.registerNamespace('" + ns + "') at app bootstrap before recording '" + action + "'."
    );
  }
}

function record(event) {
  if (!event || typeof event !== "object") {
    throw new Error("audit.record requires an event object");
  }
  _validateAction(event.action);
  if (!event.outcome || ["success", "failure", "denied"].indexOf(event.outcome) === -1) {
    throw new Error("audit.record outcome must be 'success', 'failure', or 'denied'");
  }
  _initCounter();

  var actor    = event.actor    || {};
  var resource = event.resource || {};

  var counter = _nextCounter++;
  var nowMs   = Date.now();
  var nonce   = generateBytes(16);

  // Plaintext logical row (gets sealed below)
  var logical = {
    _id:               generateToken(16),
    recordedAt:        nowMs,
    monotonicCounter:  counter,
    actorUserId:       actor.userId    || null,
    actorIp:           actor.ip        || null,
    actorUserAgent:    actor.userAgent || null,
    actorSessionId:    actor.sessionId || null,
    action:            event.action,
    resourceKind:      resource.kind   || null,
    resourceId:        resource.id     || null,
    outcome:           event.outcome,
    reason:            event.reason    || null,
    metadata:          event.metadata ? JSON.stringify(event.metadata) : null,
    requestId:         event.requestId || null,
  };

  // Seal the row (sealed columns get vault.seal'd, derived hashes computed)
  var sealed = fieldCrypto.sealRow("audit_log", logical);

  // Materialize null entries for every hashable column the schema expects,
  // so canonicalize at record time and at verify time see the same key set.
  // (DB read returns null for missing columns; record-time row may lack a
  // derived-hash column when its source was null. Canonicalize as JSON
  // distinguishes missing-key from key:null — we must not.)
  for (var hci = 0; hci < HASHABLE_COLS.length; hci++) {
    if (!(HASHABLE_COLS[hci] in sealed)) sealed[HASHABLE_COLS[hci]] = null;
  }

  // Compute rowHash over the *sealed* row's content fields (everything we
  // intend to write to disk EXCEPT the chain bookkeeping itself).
  var tip = db().prepare(
    "SELECT rowHash FROM audit_log ORDER BY monotonicCounter DESC LIMIT 1"
  ).get();
  var prevHash = tip ? tip.rowHash : auditChain.ZERO_HASH;

  var rowHash = auditChain.computeRowHash(prevHash, sealed, nonce);

  sealed.prevHash = prevHash;
  sealed.rowHash  = rowHash;
  sealed.nonce    = nonce;

  // Write the row. Use direct SQL (not the query builder) to control which
  // columns are present and to write the chain fields explicitly.
  var allCols = [
    "_id", "recordedAt", "monotonicCounter",
    "actorUserId", "actorUserIdHash",
    "actorIp",
    "actorUserAgent", "actorSessionId",
    "action", "resourceKind",
    "resourceId", "resourceIdHash",
    "outcome", "reason", "metadata", "requestId",
    "prevHash", "rowHash", "nonce",
  ];
  var placeholders = allCols.map(function () { return "?"; }).join(", ");
  var quoted = allCols.map(function (c) { return '"' + c + '"'; }).join(", ");
  var values = allCols.map(function (c) { return c in sealed ? sealed[c] : null; });
  var stmt = db().prepare("INSERT INTO audit_log (" + quoted + ") VALUES (" + placeholders + ")");
  stmt.run.apply(stmt, values);

  return Object.assign({ rowHash: rowHash, prevHash: prevHash }, logical);
}

// ---- Query ----
//
// Plain-field criteria translate into derived-hash equality where the column
// is sealed. Returns unsealed rows for the auditor's view.
function query(criteria) {
  criteria = criteria || {};
  var q = db().from("audit_log");

  if (criteria.from)            q = q.where("recordedAt", ">=", _toMs(criteria.from));
  if (criteria.to)              q = q.where("recordedAt", "<=", _toMs(criteria.to));
  if (criteria.actorUserId)     q = q.where({ actorUserId: criteria.actorUserId });
  if (criteria.resourceId)      q = q.where({ resourceId: criteria.resourceId });
  if (criteria.action)          q = q.where({ action: criteria.action });
  if (criteria.resourceKind)    q = q.where({ resourceKind: criteria.resourceKind });
  if (criteria.outcome)         q = q.where({ outcome: criteria.outcome });

  q.orderBy("monotonicCounter", "asc");
  if (criteria.limit  != null)  q.limit(criteria.limit);
  if (criteria.offset != null)  q.offset(criteria.offset);

  return q.all();
}

function _toMs(value) {
  if (typeof value === "number") return value;
  if (value instanceof Date)     return value.getTime();
  if (typeof value === "string") {
    var ms = Date.parse(value);
    if (isNaN(ms)) throw new Error("invalid date: " + value);
    return ms;
  }
  throw new Error("invalid date value");
}

// ---- Verify ----

function verify(opts) {
  return auditChain.verifyChain({ prepare: function (sql) { return db().prepare(sql); } }, "audit_log", opts);
}

// ---- Test helpers ----

function _resetForTest() {
  registeredNamespaces = new Set(FRAMEWORK_NAMESPACES);
  _counterInitialized = false;
  _nextCounter = 1;
  _db = null;
}

module.exports = {
  registerNamespace:    registerNamespace,
  record:               record,
  query:                query,
  verify:               verify,
  FRAMEWORK_NAMESPACES: FRAMEWORK_NAMESPACES,
  _resetForTest:        _resetForTest,
};
