"use strict";
/**
 * Audit hash chain — tamper-evidence math.
 *
 * Per the compliance spec ("Tamper evidence (the chain + checkpoint signing)"
 * in the roadmap):
 *
 *   rowHash = SHA3-512(
 *     prevHash || canonicalize(row-fields-except-hash) || nonce
 *   )
 *
 * Each row's prevHash equals the previous row's rowHash (in monotonic-counter
 * order). The first row uses ZERO_HASH as prevHash. Verification walks the
 * chain forward; any row whose prevHash doesn't match the running hash, or
 * whose rowHash recomputes differently, breaks the chain.
 *
 * Checkpoint signing (ML-DSA-87 over (atRow || atRowHash)) lives in
 * lib/audit-sign.js. This module owns the chain hash math only;
 * verification is O(n) and walks every row at boot.
 */
var { sha3Hash } = require("./crypto");

// All-zero SHA3-512 (128 hex chars) — sentinel prevHash for the first row.
var ZERO_HASH = "0".repeat(128);

// Canonicalize a row for hashing. Excludes the hash/nonce columns themselves
// and any caller-specified columns. Sorted keys, JSON-encoded values; Buffer
// values converted to hex for stable byte serialization.
//
// Deeply walks the value tree so non-plain types reject cleanly instead of
// silently round-tripping as `{}` (Map / Set / RegExp), as `{"0":97,…}`
// (Buffer / typed-array nested inside arrays / objects), or as missing
// keys (Symbol / function). BigInt converts to its decimal string —
// large account IDs / monotonic counters from external-DB drivers
// frequently land as BigInt, and crashing the audit emit on those would
// turn them into availability incidents. Circular refs throw a clean
// framework Error rather than the raw JSON.stringify message.
function _scrub(value, seen) {
  if (value === null || typeof value === "undefined") return null;
  var t = typeof value;
  if (t === "string" || t === "boolean" || t === "number") return value;
  if (t === "bigint") return String(value);
  if (t === "symbol" || t === "function") {
    throw new Error("audit-chain canonicalize: " + t + " value is not " +
      "serialisable; convert to a string before emit");
  }
  if (Buffer.isBuffer(value))            return value.toString("hex");
  if (value instanceof Uint8Array)       return Buffer.from(value).toString("hex");
  if (value instanceof Date)             return value.toISOString();
  // After the primitives + Buffer + Date, any remaining "object" must be
  // a plain object or array. Map / Set / RegExp / class instances all
  // reject with a clear constructor name in the error so operators see
  // exactly which audit metadata field is the culprit.
  if (value instanceof Map || value instanceof Set || value instanceof RegExp) {
    throw new Error("audit-chain canonicalize: " + value.constructor.name +
      " is not serialisable; convert to a plain primitive / array / object first");
  }
  seen = seen || new WeakSet();
  if (seen.has(value)) {
    throw new Error("audit-chain canonicalize: circular reference in audit row");
  }
  seen.add(value);
  if (Array.isArray(value)) return value.map(function (v) { return _scrub(v, seen); });
  var keys = Object.keys(value).sort();
  var out = {};
  for (var i = 0; i < keys.length; i++) {
    out[keys[i]] = _scrub(value[keys[i]], seen);
  }
  return out;
}

function canonicalize(row, excludeKeys) {
  var ex = new Set(excludeKeys || []);
  var keys = Object.keys(row).filter(function (k) { return !ex.has(k); }).sort();
  var pairs = {};
  for (var i = 0; i < keys.length; i++) {
    pairs[keys[i]] = _scrub(row[keys[i]]);
  }
  return JSON.stringify(pairs);
}

// Compute a row's hash given its predecessor's hash, the row's logical fields
// (already excluding prevHash, rowHash, nonce), and the row's nonce buffer.
function computeRowHash(prevHash, rowFields, nonce) {
  if (typeof prevHash !== "string" || prevHash.length !== 128) {
    throw new Error("prevHash must be a 128-char hex string (SHA3-512); got length " +
      (prevHash && prevHash.length));
  }
  if (!Buffer.isBuffer(nonce) || nonce.length === 0) {
    throw new Error("nonce must be a non-empty Buffer");
  }
  var canonical = canonicalize(rowFields);
  var input = Buffer.concat([
    Buffer.from(prevHash, "hex"),
    Buffer.from(canonical, "utf8"),
    nonce,
  ]);
  return sha3Hash(input);
}

// Read the current chain tip (last row's rowHash + monotonicCounter) for a
// given audit table. Async to accommodate operator-supplied external-db
// drivers; queryOneAsync is `async (sql, params?) → row | null`.
async function getChainTip(queryOneAsync, tableName) {
  var row = await queryOneAsync(
    'SELECT rowHash, monotonicCounter FROM "' + tableName + '" ' +
    "ORDER BY monotonicCounter DESC LIMIT 1"
  );
  if (!row) return { prevHash: ZERO_HASH, counter: 0 };
  return { prevHash: row.rowHash, counter: row.monotonicCounter };
}

// Walk the entire chain forward, recomputing each row's hash. Returns an
// object describing the result; callers decide how to react (refuse-to-boot,
// log warning, etc.). queryAllAsync is `async (sql, params?) → rows`.
//
// audit_log only: if a `_blamejs_audit_purge_anchor` row exists, the walk
// starts at lastPurgedCounter+1 with prevHash = lastPurgedRowHash. The
// anchor is written by audit-tools.purge() after a successful archive,
// and lets the chain math survive deletion of historical rows without
// the bundle as the source of truth.
async function verifyChain(queryAllAsync, tableName, opts) {
  opts = opts || {};

  var prevHash = ZERO_HASH;
  var skipBeforeCounter = 0;
  if (tableName === "audit_log") {
    var anchor;
    try {
      anchor = await queryAllAsync(
        "SELECT lastPurgedCounter, lastPurgedRowHash FROM _blamejs_audit_purge_anchor " +
        "WHERE scope = 'audit'"
      );
    } catch (_e) {
      // Anchor table may not exist on a deployment that has never been
      // through a purge. Treat as no anchor.
      anchor = [];
    }
    if (Array.isArray(anchor) && anchor.length > 0) {
      prevHash = anchor[0].lastPurgedRowHash;
      skipBeforeCounter = Number(anchor[0].lastPurgedCounter);
    }
  }

  var rows = await queryAllAsync(
    'SELECT * FROM "' + tableName + '" ORDER BY monotonicCounter ASC'
  );
  if (skipBeforeCounter > 0) {
    rows = rows.filter(function (r) {
      return Number(r.monotonicCounter) > skipBeforeCounter;
    });
  }

  if (rows.length === 0) {
    return { ok: true, table: tableName, rowsVerified: 0, lastHash: prevHash };
  }
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    if (row.prevHash !== prevHash) {
      return {
        ok:           false,
        table:        tableName,
        rowsVerified: i,
        breakAt:      i,
        breakRowId:   row._id,
        reason:       "prevHash mismatch",
        expected:     prevHash,
        actual:       row.prevHash,
      };
    }
    var fields = Object.assign({}, row);
    delete fields.prevHash;
    delete fields.rowHash;
    delete fields.nonce;
    // fencingToken is cluster-coordination bookkeeping — orthogonal to
    // tamper-evidence. Excluded from chain hash inputs so deployments
    // upgrading from a pre-cluster schema (no fencingToken column) verify
    // identically before and after the ALTER TABLE.
    delete fields.fencingToken;
    var nonceBuf = Buffer.isBuffer(row.nonce) ? row.nonce : Buffer.from(row.nonce);
    var computed = computeRowHash(prevHash, fields, nonceBuf);
    if (computed !== row.rowHash) {
      return {
        ok:           false,
        table:        tableName,
        rowsVerified: i,
        breakAt:      i,
        breakRowId:   row._id,
        reason:       "rowHash mismatch",
        expected:     computed,
        actual:       row.rowHash,
      };
    }
    prevHash = row.rowHash;

    if (opts.maxRows && i >= opts.maxRows - 1) break;
  }
  return { ok: true, table: tableName, rowsVerified: rows.length, lastHash: prevHash };
}

module.exports = {
  ZERO_HASH:      ZERO_HASH,
  canonicalize:   canonicalize,
  computeRowHash: computeRowHash,
  getChainTip:    getChainTip,
  verifyChain:    verifyChain,
};
