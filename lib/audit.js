"use strict";
/**
 * Audit log — tamper-evident, append-only record of every privileged action.
 *
 * audit_log table is baked into db.js's schema runner — apps cannot opt out.
 * Every row is hash-chained (lib/audit-chain.js); the chain is verified at
 * boot in db.init(); a chain break refuses-to-boot per the compliance stance.
 *
 * Action namespaces:
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
 *   audit.query(criteria) → rows  [auto-self-logs an 'audit.read' event before returning]
 *   audit.verify(opts?) → { ok, rowsVerified, breakAt? }
 *   audit.beginTrace() → traceId (32 hex chars)
 *
 * Conventions for `metadata` (apps SHOULD follow these keys for cross-app
 * tooling and RoPA correlation; framework's own subject.* events do):
 *   traceId        — cross-request correlation; same value across linked events
 *   parentEventId  — immediate parent event in the causation chain
 *   before         — state before a change (object), for change events
 *   after          — state after the change
 *   evidenceRef    — pointer to evidence (signed PDF hash, ticket URL, etc.)
 *   App-defined keys are also welcome; don't shadow these reserved ones.
 */
var { generateToken, generateBytes } = require("./crypto");
var auditChain = require("./audit-chain");
var fieldCrypto = require("./field-crypto");
var auditSign = require("./audit-sign");
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var asyncSafe = require("./async-safe");
var handlers = require("./handlers");
var chainWriter = require("./chain-writer");
var lazyRequire = require("./lazy-require");

// Per-operation timeout for framework-state SQL. A misbehaving
// external-db driver hanging on a query shouldn't hang audit forever.
// 30s is generous for genuinely slow networks while still bounding
// the worst case.
var FRAMEWORK_SQL_TIMEOUT_MS = 30 * 1000;

// ---- Resilience-wrapped SQL operations (audit-specific reads) ----
// Chain APPEND lives in chain-writer (race-safe via mutex, retry, timeout).
// The wrappers below cover audit-specific reads/writes that aren't part
// of the chain append: checkpoint queries, verifyCheckpoints reads,
// audit-tip cluster-row updates.

async function _readLastCheckpointCounter() {
  return await asyncSafe.withTimeout(
    asyncSafe.asyncRetry(function () {
      return clusterStorage.executeOne(
        "SELECT atMonotonicCounter FROM audit_checkpoints " +
        "ORDER BY atMonotonicCounter DESC LIMIT 1"
      );
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.readLastCheckpoint" }
  );
}

async function _readAllAuditRowsAsc() {
  return await asyncSafe.withTimeout(
    asyncSafe.asyncRetry(function () {
      return clusterStorage.executeAll(
        'SELECT * FROM "audit_log" ORDER BY monotonicCounter ASC'
      );
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.readAllRowsAsc" }
  );
}

async function _readAllCheckpointsAsc() {
  return await asyncSafe.withTimeout(
    asyncSafe.asyncRetry(function () {
      return clusterStorage.executeAll(
        "SELECT * FROM audit_checkpoints ORDER BY atMonotonicCounter ASC"
      );
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.readAllCheckpoints" }
  );
}

async function _readAuditRowHashAtCounter(counter) {
  return await asyncSafe.withTimeout(
    asyncSafe.asyncRetry(function () {
      return clusterStorage.executeOne(
        "SELECT rowHash FROM audit_log WHERE monotonicCounter = ?",
        [counter]
      );
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.readRowHashAtCounter" }
  );
}

async function _insertAuditRow(allCols, values) {
  // No retry — non-idempotent. Timeout only.
  var placeholders = allCols.map(function () { return "?"; }).join(", ");
  var quoted = allCols.map(function (c) { return '"' + c + '"'; }).join(", ");
  return await asyncSafe.withTimeout(
    clusterStorage.execute(
      "INSERT INTO audit_log (" + quoted + ") VALUES (" + placeholders + ")",
      values
    ),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.insertRow" }
  );
}

async function _insertCheckpoint(values) {
  return await asyncSafe.withTimeout(
    clusterStorage.execute(
      "INSERT INTO audit_checkpoints (_id, createdAt, atMonotonicCounter, atRowHash, signature, publicKeyFingerprint, fencingToken) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?)",
      values
    ),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.insertCheckpoint" }
  );
}

async function _upsertAuditTip(counter, rowHash, signedAt, fencingToken) {
  // Cluster-mode only. UPDATE-then-INSERT-if-missing — not atomic, but
  // safe because cluster.requireLeader() above ensures only one writer
  // is active at a time.
  await asyncSafe.withTimeout(
    clusterStorage.execute(
      "UPDATE _blamejs_audit_tip SET atMonotonicCounter = ?, rowHash = ?, signedAt = ?, fencingToken = ? WHERE scope = 'audit'",
      [counter, rowHash, signedAt, fencingToken]
    ),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.updateAuditTip" }
  );
  var existing = await asyncSafe.withTimeout(
    clusterStorage.executeOne(
      "SELECT scope FROM _blamejs_audit_tip WHERE scope = 'audit'"
    ),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.checkAuditTipExists" }
  );
  if (!existing) {
    await asyncSafe.withTimeout(
      clusterStorage.execute(
        "INSERT INTO _blamejs_audit_tip (scope, atMonotonicCounter, rowHash, signedAt, fencingToken) VALUES ('audit', ?, ?, ?, ?)",
        [counter, rowHash, signedAt, fencingToken]
      ),
      FRAMEWORK_SQL_TIMEOUT_MS,
      { name: "audit.insertAuditTip" }
    );
  }
}

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
var db = lazyRequire(function () { return require("./db"); });

// Chain-writer instance owns the race-safe chain append: counter primer,
// chain mutex, prev-tip read, hash compute, INSERT. Per the framework
// rule that repeated tasks become primitives, the audit_log and
// consent_log chains both consume chain-writer.
var _chainWriter = chainWriter.create({
  table:           "audit_log",
  hashableColumns: HASHABLE_COLS,
  columnsForInsert: [
    "_id", "recordedAt", "monotonicCounter",
    "actorUserId", "actorUserIdHash",
    "actorIp",
    "actorUserAgent", "actorSessionId",
    "action", "resourceKind",
    "resourceId", "resourceIdHash",
    "outcome", "reason", "metadata", "requestId",
    "prevHash", "rowHash", "nonce", "fencingToken",
  ],
});

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

async function record(event) {
  if (!event || typeof event !== "object") {
    throw new Error("audit.record requires an event object");
  }
  _validateAction(event.action);
  if (!event.outcome || ["success", "failure", "denied"].indexOf(event.outcome) === -1) {
    throw new Error("audit.record outcome must be 'success', 'failure', or 'denied'");
  }

  // Build the audit-specific logical row; chain-writer handles _id /
  // recordedAt / monotonicCounter / sealing / null-fill / hashing /
  // insert / fencing-token / chain mutex / counter primer.
  var actor    = event.actor    || {};
  var resource = event.resource || {};
  var logical = {
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
  return await _chainWriter.append(logical);
}

// ---- Query ----
//
// Plain-field criteria translate into derived-hash equality where the column
// is sealed. Returns unsealed rows for the auditor's view.
//
// Self-logging (PCI DSS 10.2.3): every read of audit_log is itself recorded
// as an 'audit.read' event before the query runs, so an exfiltration attempt
// is forensically visible. The recursion guard (_selfLogging flag) prevents
// the audit.read recording from triggering its own self-log; queries
// SPECIFICALLY filtering for action='audit.read' don't auto-log either
// (otherwise legitimate audit auditing produces a Russell-set spiral).
var _selfLogging = false;

async function query(criteria) {
  criteria = criteria || {};
  if (!_selfLogging && criteria.action !== "audit.read") {
    _selfLogging = true;
    try {
      await record({
        actor:    criteria.actor || {},
        action:   "audit.read",
        outcome:  "success",
        metadata: {
          criteria: _redactCriteria(criteria),
          traceId:  criteria.traceId || null,
        },
      });
    } finally {
      _selfLogging = false;
    }
  }

  // In single-node mode the query builder gives us field-crypto unsealing
  // for free. In cluster mode we read raw rows from external-db and
  // unseal manually.
  if (cluster.isClusterMode()) {
    return await _queryCluster(criteria);
  }

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

async function _queryCluster(criteria) {
  var conds = [];
  var params = [];
  if (criteria.from) {
    conds.push("recordedAt >= ?");
    params.push(_toMs(criteria.from));
  }
  if (criteria.to) {
    conds.push("recordedAt <= ?");
    params.push(_toMs(criteria.to));
  }
  if (criteria.actorUserId) {
    var auh = fieldCrypto.lookupHash("audit_log", "actorUserId", criteria.actorUserId);
    if (auh) { conds.push(auh.field + " = ?"); params.push(auh.value); }
  }
  if (criteria.resourceId) {
    var rh = fieldCrypto.lookupHash("audit_log", "resourceId", criteria.resourceId);
    if (rh) { conds.push(rh.field + " = ?"); params.push(rh.value); }
  }
  if (criteria.action)        { conds.push("action = ?");        params.push(criteria.action); }
  if (criteria.resourceKind)  { conds.push("resourceKind = ?");  params.push(criteria.resourceKind); }
  if (criteria.outcome)       { conds.push("outcome = ?");       params.push(criteria.outcome); }

  var sql = "SELECT * FROM audit_log";
  if (conds.length > 0) sql += " WHERE " + conds.join(" AND ");
  sql += " ORDER BY monotonicCounter ASC";
  if (criteria.limit != null)  { sql += " LIMIT ?";  params.push(criteria.limit); }
  if (criteria.offset != null) { sql += " OFFSET ?"; params.push(criteria.offset); }

  var rows = await clusterStorage.executeAll(sql, params);
  return rows.map(function (row) { return fieldCrypto.unsealRow("audit_log", row); });
}

// Audit-readable summary of the criteria without storing raw subject IDs
// in plaintext anywhere outside the sealed columns of audit_log itself.
function _redactCriteria(c) {
  return {
    from:          c.from || null,
    to:            c.to   || null,
    action:        c.action || null,
    resourceKind:  c.resourceKind || null,
    outcome:       c.outcome || null,
    hasUserFilter: !!c.actorUserId,
    hasResourceFilter: !!c.resourceId,
    limit:         c.limit  != null ? c.limit  : null,
    offset:        c.offset != null ? c.offset : null,
  };
}

// Generate a fresh trace id apps can thread through their request handlers
// and pass into audit.record() / consent.grant() / etc. via the metadata
// field. 32 hex chars matches the W3C traceparent trace-id format width.
function beginTrace() {
  return generateToken(16);
}

// ---- Checkpoints (tamper-proof external anchor) ----

// Build the canonical bytes that get signed for a checkpoint at a given
// chain tip. Keep this format stable across the framework's lifetime —
// changing it invalidates every prior checkpoint signature.
var CHECKPOINT_FORMAT = "blamejs-audit-checkpoint-v1";
function _checkpointPayload(atMonotonicCounter, atRowHash, createdAt) {
  // Use a fixed multi-line layout. Avoids JSON serializer quirks; portable
  // to any verifier reading the same column triple from the DB.
  return Buffer.from(
    CHECKPOINT_FORMAT + "\n" +
    String(atMonotonicCounter) + "\n" +
    atRowHash + "\n" +
    String(createdAt),
    "utf8"
  );
}

// Anchor the current chain tip with a fresh ML-DSA-87 signature. Inserts
// a row into audit_checkpoints. Updates <dataDir>/audit.tip for boot-time
// rollback detection.
//
// opts:
//   skipIfUnchanged: bool — return null without inserting if the chain tip
//                           hasn't advanced since the most recent checkpoint
async function checkpoint(opts) {
  cluster.requireLeader();
  opts = opts || {};

  var tip = await asyncSafe.withTimeout(
    asyncSafe.asyncRetry(function () {
      return clusterStorage.executeOne(
        "SELECT _id, monotonicCounter, rowHash FROM audit_log " +
        "ORDER BY monotonicCounter DESC LIMIT 1"
      );
    }),
    FRAMEWORK_SQL_TIMEOUT_MS,
    { name: "audit.checkpoint.readTip" }
  );

  if (!tip) return null; // empty audit log; nothing to anchor

  if (opts.skipIfUnchanged) {
    var lastCkpt = await _readLastCheckpointCounter();
    if (lastCkpt && Number(lastCkpt.atMonotonicCounter) >= Number(tip.monotonicCounter)) {
      return null; // already anchored at this tip
    }
  }

  var createdAt = Date.now();
  var counter = Number(tip.monotonicCounter);
  var payload = _checkpointPayload(counter, tip.rowHash, createdAt);
  var signature = auditSign.sign(payload);
  var pubFp = auditSign.getPublicKeyFingerprint();

  var ckptId = generateToken(16);
  var fencingToken = cluster.fencingToken();
  await _insertCheckpoint(
    [ckptId, createdAt, counter, tip.rowHash, signature, pubFp, fencingToken]
  );

  // Update rollback-detection sidecar (single-node) or audit-tip row
  // (cluster mode). Best-effort — sidecar failure must not block
  // checkpointing.
  if (cluster.isClusterMode()) {
    try { await _upsertAuditTip(counter, tip.rowHash, String(createdAt), fencingToken); }
    catch (_e) { /* best effort */ }
  } else {
    try {
      db()._writeAuditTip({
        atMonotonicCounter:  counter,
        atRowHash:           tip.rowHash,
        anchoredAt:          createdAt,
        checkpointId:        ckptId,
        publicKeyFingerprint: pubFp,
        version:             1,
      });
    } catch (_e) { /* best effort */ }
  }

  return {
    _id:                ckptId,
    createdAt:          createdAt,
    atMonotonicCounter: counter,
    atRowHash:          tip.rowHash,
    publicKeyFingerprint: pubFp,
  };
}

// Walk every checkpoint, verify its signature against the current public
// key (or one matching the row's stored fingerprint). Also confirms the
// audit_log row at atMonotonicCounter still has the recorded rowHash.
//
// Returns { ok, checkpointsVerified, breakAt? }.
async function verifyCheckpoints() {
  var rows = await _readAllCheckpointsAsc();

  if (rows.length === 0) return { ok: true, checkpointsVerified: 0 };

  var currentFp = auditSign.getPublicKeyFingerprint();
  var currentPub = auditSign.getPublicKey();

  for (var i = 0; i < rows.length; i++) {
    var c = rows[i];
    // Public key check: only the current key is accepted — there is no
    // key-history table, so any rotation requires re-signing existing
    // checkpoints. A fingerprint mismatch fails verification.
    if (c.publicKeyFingerprint !== currentFp) {
      return {
        ok:                  false,
        checkpointsVerified: i,
        breakAt:             i,
        checkpointId:        c._id,
        reason:              "public key fingerprint mismatch (key rotated without history?)",
        expected:            currentFp,
        actual:              c.publicKeyFingerprint,
      };
    }
    var payload = _checkpointPayload(Number(c.atMonotonicCounter), c.atRowHash, Number(c.createdAt));
    var sigBuf = Buffer.isBuffer(c.signature) ? c.signature : Buffer.from(c.signature);
    if (!auditSign.verify(payload, sigBuf, currentPub)) {
      return {
        ok:                  false,
        checkpointsVerified: i,
        breakAt:             i,
        checkpointId:        c._id,
        reason:              "ML-DSA-87 signature failed",
      };
    }
    // Also confirm the audit row at atMonotonicCounter still matches the
    // anchored rowHash. If someone tampered with audit_log AND recomputed
    // hashes (requiring vault key), this catches them via the off-chain
    // signature anchor.
    var anchored = await _readAuditRowHashAtCounter(c.atMonotonicCounter);
    if (!anchored) {
      return {
        ok:                  false,
        checkpointsVerified: i,
        breakAt:             i,
        checkpointId:        c._id,
        reason:              "anchored audit_log row missing (counter=" + c.atMonotonicCounter + ")",
      };
    }
    if (anchored.rowHash !== c.atRowHash) {
      return {
        ok:                  false,
        checkpointsVerified: i,
        breakAt:             i,
        checkpointId:        c._id,
        reason:              "anchored rowHash mismatch — audit_log was tampered with",
        expected:            c.atRowHash,
        actual:              anchored.rowHash,
      };
    }
  }
  return { ok: true, checkpointsVerified: rows.length };
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

async function verify(opts) {
  // verifyChain just needs an executeAll; route through the same
  // resilience-wrapped reader the rest of audit uses.
  return await auditChain.verifyChain(
    function (sql, params) {
      return asyncSafe.withTimeout(
        asyncSafe.asyncRetry(function () {
          return clusterStorage.executeAll(sql, params || []);
        }),
        FRAMEWORK_SQL_TIMEOUT_MS,
        { name: "audit.verifyChain" }
      );
    },
    "audit_log",
    opts
  );
}

// ---- Test helpers ----

function _resetForTest() {
  registeredNamespaces = new Set(FRAMEWORK_NAMESPACES);
  db.reset();
  _chainWriter._resetForTest();
  _auditHandler = null;
}

// ---- Handler-backed emit + flush ----
//
// emit() is the call-site API for fire-and-forget audit emission from
// middleware / log-stream / external-db hooks / queue / storage / subject.
// It is SYNCHRONOUS, NEVER throws, and NEVER returns a Promise — request-
// path code can call it without await and without try/catch.
//
// Internally events queue in an AsyncHandler. flush() drains the queue
// to the audit chain (single writer in-process, serialized via the
// chain mutex). Tests, shutdown, and any code that needs audit-row
// durability before reading audit_log calls await audit.flush().
//
// Why this beats fire-and-forget Promises:
//   - No leaked Promises across test/shutdown boundaries
//   - Errors go through a single onError hook (visible to operators)
//   - Recursive emits during flush land in the buffer for the next
//     drain cycle — no infinite loop in cluster-mode dispatchers
//   - Tests have a deterministic "audit is durable now" point
var _auditHandler = null;

function _ensureHandler() {
  if (_auditHandler) return _auditHandler;
  _auditHandler = handlers.create({
    name:  "audit",
    flush: async function (batch) {
      // Drain by serially writing each event through record(). The chain
      // mutex inside record() further serializes vs concurrent direct
      // record() callers.
      for (var i = 0; i < batch.length; i++) {
        try { await record(batch[i]); }
        catch (e) {
          // Per-item failure shouldn't drop the whole batch; log and
          // continue. The handler's onError gets called for batch-
          // wide failures only.
          if (typeof console !== "undefined") {
            console.error("[blamejs:audit] flush dropped event: " +
              (e && e.message ? e.message : String(e)) +
              " (action=" + (batch[i] && batch[i].action) + ")");
          }
        }
      }
    },
  });
  return _auditHandler;
}

function emit(event) {
  _ensureHandler().emit(event);
}

async function flush() {
  if (!_auditHandler) return;
  await _auditHandler.drain();
}

module.exports = {
  registerNamespace:    registerNamespace,
  record:               record,
  emit:                 emit,
  flush:                flush,
  query:                query,
  verify:               verify,
  beginTrace:           beginTrace,
  checkpoint:           checkpoint,
  verifyCheckpoints:    verifyCheckpoints,
  CHECKPOINT_FORMAT:    CHECKPOINT_FORMAT,
  FRAMEWORK_NAMESPACES: FRAMEWORK_NAMESPACES,
  _resetForTest:        _resetForTest,
};
