"use strict";
/**
 * Consent log — GDPR Art. 6/7 lawful-basis tracking with hash chain.
 *
 * consent_log is baked into db.js's schema runner alongside audit_log.
 * Same tamper-evidence design: per-row SHA3-512 hash chain, append-only,
 * verified at boot.
 *
 * Lawful-basis consistency: any audit-recorded operation declared under
 * `lawfulBasis: 'consent'` should reference a current consent_log entry.
 * The framework records consent grants/withdrawals here; enforcement of
 * consent before processing is the app's responsibility — query
 * `consent.isActive(subjectId, purpose)` at the trust boundary.
 *
 * Public API:
 *   consent.grant({ subjectId, purpose, lawfulBasis, scope?, channel, evidenceRef? })
 *   consent.withdraw({ subjectId, purpose, reason? })
 *   consent.isGranted({ subjectId, purpose }) → boolean
 *   consent.history(subjectId) → array of consent_log rows (decrypted)
 *   consent.verify() → { ok, rowsVerified, breakAt? }
 */
var { generateToken, generateBytes } = require("./crypto");
var auditChain = require("./audit-chain");
var fieldCrypto = require("./field-crypto");
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");

var LAWFUL_BASES = ["consent", "contract", "legal_obligation", "vital_interests", "public_task", "legitimate_interests"];
var ACTIONS = ["granted", "withdrawn", "expired", "superseded"];

var HASHABLE_COLS = [
  "_id", "recordedAt", "monotonicCounter",
  "subjectId", "subjectIdHash",
  "purpose", "lawfulBasis", "action",
  "scope", "channel", "evidenceRef",
];

var _db = null;
function db() { if (!_db) _db = require("./db"); return _db; }

var _counterInitialized = false;
var _nextCounter = 1;

function _initCounter() {
  if (_counterInitialized) return;
  var row = db().prepare("SELECT MAX(monotonicCounter) AS m FROM consent_log").get();
  _nextCounter = (row && row.m ? row.m : 0) + 1;
  _counterInitialized = true;
}

// ---- Public API ----

function grant(opts) {
  cluster.requireLeader();
  if (!opts || !opts.subjectId || !opts.purpose || !opts.lawfulBasis || !opts.channel) {
    throw new Error("consent.grant requires { subjectId, purpose, lawfulBasis, channel }");
  }
  if (LAWFUL_BASES.indexOf(opts.lawfulBasis) === -1) {
    throw new Error("invalid lawfulBasis: '" + opts.lawfulBasis + "' (must be one of " + LAWFUL_BASES.join(", ") + ")");
  }
  return _appendConsentRow({
    subjectId:    opts.subjectId,
    purpose:      opts.purpose,
    lawfulBasis:  opts.lawfulBasis,
    action:       "granted",
    scope:        opts.scope ? JSON.stringify(opts.scope) : null,
    channel:      opts.channel,
    evidenceRef:  opts.evidenceRef || null,
  });
}

function withdraw(opts) {
  cluster.requireLeader();
  if (!opts || !opts.subjectId || !opts.purpose) {
    throw new Error("consent.withdraw requires { subjectId, purpose }");
  }
  return _appendConsentRow({
    subjectId:    opts.subjectId,
    purpose:      opts.purpose,
    lawfulBasis:  "consent",
    action:       "withdrawn",
    scope:        null,
    channel:      opts.channel || "api",
    evidenceRef:  opts.reason ? "reason:" + opts.reason : null,
  });
}

function isGranted(opts) {
  if (!opts || !opts.subjectId || !opts.purpose) {
    throw new Error("consent.isGranted requires { subjectId, purpose }");
  }
  // Find the most recent consent row for this (subjectId, purpose).
  // subjectId is sealed → look up via subjectIdHash (derived).
  var hash = db().hashFor("consent_log", "subjectId", opts.subjectId);
  if (!hash) {
    throw new Error("consent_log subjectId is missing a derived hash — schema misconfigured");
  }
  var row = db().prepare(
    "SELECT action FROM consent_log WHERE subjectIdHash = ? AND purpose = ? " +
    "ORDER BY monotonicCounter DESC LIMIT 1"
  ).get(hash, opts.purpose);
  if (!row) return false;
  return row.action === "granted";
}

function history(subjectId) {
  if (!subjectId) throw new Error("consent.history requires a subjectId");
  var hash = db().hashFor("consent_log", "subjectId", subjectId);
  if (!hash) {
    throw new Error("consent_log subjectId is missing a derived hash — schema misconfigured");
  }
  var rows = db().from("consent_log")
    .where({ subjectIdHash: hash })
    .orderBy("monotonicCounter", "asc")
    .all();
  return rows;
}

async function verify(opts) {
  return await auditChain.verifyChain(
    function (sql, params) { return clusterStorage.executeAll(sql, params || []); },
    "consent_log",
    opts
  );
}

// ---- Internal: append a chain-linked row ----

function _appendConsentRow(fields) {
  if (ACTIONS.indexOf(fields.action) === -1) {
    throw new Error("invalid consent action: " + fields.action);
  }
  _initCounter();

  var counter = _nextCounter++;
  var nonce   = generateBytes(16);
  var nowMs   = Date.now();

  var logical = {
    _id:              generateToken(16),
    recordedAt:       nowMs,
    monotonicCounter: counter,
    subjectId:        fields.subjectId,
    purpose:          fields.purpose,
    lawfulBasis:      fields.lawfulBasis,
    action:           fields.action,
    scope:            fields.scope,
    channel:          fields.channel,
    evidenceRef:      fields.evidenceRef,
  };

  var sealed = fieldCrypto.sealRow("consent_log", logical);

  // Materialize null entries for every hashable column so record-time and
  // verify-time canonicalization see the same key set.
  for (var hci = 0; hci < HASHABLE_COLS.length; hci++) {
    if (!(HASHABLE_COLS[hci] in sealed)) sealed[HASHABLE_COLS[hci]] = null;
  }

  var tip = db().prepare(
    "SELECT rowHash FROM consent_log ORDER BY monotonicCounter DESC LIMIT 1"
  ).get();
  var prevHash = tip ? tip.rowHash : auditChain.ZERO_HASH;
  var rowHash = auditChain.computeRowHash(prevHash, sealed, nonce);

  sealed.prevHash = prevHash;
  sealed.rowHash  = rowHash;
  sealed.nonce    = nonce;

  var allCols = [
    "_id", "recordedAt", "monotonicCounter",
    "subjectId", "subjectIdHash",
    "purpose", "lawfulBasis", "action",
    "scope", "channel", "evidenceRef",
    "prevHash", "rowHash", "nonce",
  ];
  var placeholders = allCols.map(function () { return "?"; }).join(", ");
  var quoted = allCols.map(function (c) { return '"' + c + '"'; }).join(", ");
  var values = allCols.map(function (c) { return c in sealed ? sealed[c] : null; });
  var stmt = db().prepare("INSERT INTO consent_log (" + quoted + ") VALUES (" + placeholders + ")");
  stmt.run.apply(stmt, values);

  return Object.assign({ rowHash: rowHash, prevHash: prevHash }, logical);
}

// ---- Test helpers ----

function _resetForTest() {
  _counterInitialized = false;
  _nextCounter = 1;
  _db = null;
}

module.exports = {
  grant:         grant,
  withdraw:      withdraw,
  isGranted:     isGranted,
  history:       history,
  verify:        verify,
  LAWFUL_BASES:  LAWFUL_BASES,
  ACTIONS:       ACTIONS,
  _resetForTest: _resetForTest,
};
