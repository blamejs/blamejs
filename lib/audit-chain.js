// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.auditChain
 * @nav    Observability
 * @title  Audit Chain Primitives
 *
 * @intro
 *   Low-level audit-chain hash + verify primitives — `b.audit` composes
 *   on top of these so operators rarely call them directly. Every audit
 *   row carries `prevHash` + `rowHash` + `nonce` and the chain math is:
 *
 *     rowHash = SHA3-512(
 *       prevHash || canonicalize(row-fields-except-hash) || nonce
 *     )
 *
 *   Each row's `prevHash` equals the previous row's `rowHash` in
 *   monotonic-counter order. The first row uses `ZERO_HASH` as the
 *   anchor. `verifyChain` walks every row forward, recomputing each
 *   hash; any mismatch returns `{ ok: false, reason, breakAt, ... }`
 *   and the caller (audit boot, `b.cli verify-chain`, restore-rollback,
 *   forensic snapshot) decides whether to refuse-to-boot or just log.
 *
 *   Checkpoint signing (SLH-DSA-SHAKE-256f over `(atRow || atRowHash)`)
 *   lives in `b.auditSign`. This module owns the chain hash math only;
 *   verification is O(n) over `audit_log` rows.
 *
 *   Operators reach for `b.auditChain.verifyChain` directly when
 *   restoring from backup (verify the restored DB before promoting it),
 *   when running a forensic offline check, or when extending the chain
 *   primitive into a custom append-only table. Day-to-day appends go
 *   through `b.audit.record` / `b.audit.safeEmit`.
 *
 * @card
 *   Low-level audit-chain hash + verify primitives — `b.audit` composes on top of these so operators rarely call them directly.
 */
var auditSign = require("./audit-sign");
var canonicalJson = require("./canonical-json");
var C = require("./constants");
var clusterStorage = require("./cluster-storage");
var frameworkSchema = require("./framework-schema");
var numericBounds = require("./numeric-bounds");
var sql = require("./sql");
var safeSql = require("./safe-sql");
var safeBuffer = require("./safe-buffer");
var { sha3Hash } = require("./crypto");

// b.sql opts for the chain read SQL these primitives compose. The reader
// (queryAllAsync / queryOneAsync, normally clusterStorage.execute*) rewrites
// the bare framework table name + translates `?` placeholders at dispatch,
// but the IDENTIFIER QUOTING + ORDER-BY column reference are baked into the
// b.sql output at build time — so they must carry the ACTIVE backend dialect
// (clusterStorage.dialect() — "sqlite" single-node, "postgres" | "mysql" in
// cluster mode). Defaulting to "sqlite" double-quotes `monotonicCounter`,
// which MySQL reads as a STRING LITERAL: `ORDER BY '<constant>'` imposes no
// ordering, so verifyChain walks the rows out of order and falsely reports a
// chain break. Backtick-quoting on MySQL makes it an identifier again.
function _sqlOpts() { return { dialect: clusterStorage.dialect() }; }

// SHA3-512 outputs 64 bytes; routed through C.BYTES so the file's byte
// arithmetic has one source of truth. Hex-encoded width is twice the
// byte count.
var SHA3_512_BYTES   = C.BYTES.bytes(64);
var SHA3_512_HEX_LEN = SHA3_512_BYTES * 2;

// All-zero SHA3-512 sentinel prevHash for the first row.
var ZERO_HASH = "0".repeat(SHA3_512_HEX_LEN);

/**
 * @primitive b.auditChain.canonicalize
 * @signature b.auditChain.canonicalize(row, excludeKeys)
 * @since     0.6.67
 * @related   b.auditChain.computeRowHash
 *
 * RFC 8785 (JSON Canonicalization Scheme) serialization of an audit
 * row's logical fields, used as the middle slice of the row-hash
 * preimage. Sorted keys, Buffer values rendered as hex, every other
 * value passed through the shared `lib/canonical-json` walker so the
 * four canonicalize sites in the framework (chain, audit-tools,
 * config-drift, pagination) emit byte-identical output.
 *
 * @example
 *   var bytes = b.auditChain.canonicalize(
 *     { actor: "u-42", action: "auth.login.success", recordedAt: 1700000000000 },
 *     ["prevHash", "rowHash", "nonce"]
 *   );
 *   // → '{"action":"auth.login.success","actor":"u-42","recordedAt":1700000000000}'
 */
function canonicalize(row, excludeKeys) {
  var ex = new Set(excludeKeys || []);
  var keys = Object.keys(row).filter(function (k) { return !ex.has(k); }).sort();
  var pairs = {};
  for (var i = 0; i < keys.length; i++) {
    pairs[keys[i]] = row[keys[i]];
  }
  return canonicalJson.stringify(pairs);
}

/**
 * @primitive b.auditChain.computeRowHash
 * @signature b.auditChain.computeRowHash(prevHash, rowFields, nonce)
 * @since     0.4.0
 * @related   b.auditChain.verifyChain, b.auditChain.canonicalize
 *
 * Compute a row's `rowHash` given its predecessor's hash, the row's
 * logical fields (already excluding `prevHash` / `rowHash` / `nonce`),
 * and the row's nonce buffer. The hash is `SHA3-512(prevHashBytes ||
 * canonicalize(rowFields) || nonce)`, returned as a 128-char lowercase
 * hex string.
 *
 * `prevHash` must be the 128-char hex form (use `b.auditChain.ZERO_HASH`
 * for the chain anchor). `nonce` must be a non-empty Buffer; the
 * framework writes 16 random bytes per row.
 *
 * @example
 *   var rowHash = b.auditChain.computeRowHash(
 *     b.auditChain.ZERO_HASH,
 *     { action: "system.boot", recordedAt: 1700000000000, outcome: "success" },
 *     Buffer.from("0123456789abcdef0123456789abcdef", "hex")
 *   );
 *   // → "<128-char SHA3-512 hex>"
 */
function computeRowHash(prevHash, rowFields, nonce) {
  if (typeof prevHash !== "string" || prevHash.length !== SHA3_512_HEX_LEN) {
    throw new Error("prevHash must be a " + SHA3_512_HEX_LEN +
      "-char hex string (SHA3-512); got length " +
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

/**
 * @primitive b.auditChain.getChainTip
 * @signature b.auditChain.getChainTip(queryOneAsync, tableName, opts?)
 * @since     0.4.0
 * @related   b.auditChain.verifyChain, b.auditChain.computeRowHash
 *
 * Read the current chain tip (last row's `rowHash` + `monotonicCounter`)
 * for a given audit table. Empty tables return
 * `{ prevHash: ZERO_HASH, counter: 0 }` so callers can treat first-row
 * insert and append uniformly. Async so operator-supplied external-db
 * drivers can use any await-able query function of the shape
 * `async (sql, params?) -> row | null`.
 *
 * Pass `{ chainKey, keyValue }` to scope the tip to one partition of a
 * multi-chain table (one chain per account / device / tenant) — the tip read
 * filters `WHERE <chainKey> = ?` with the value bound, never interpolated.
 *
 * @opts
 *   chainKey:  string,   // partition column for a multi-chain table
 *   keyValue:  any,      // the partition value to scope the tip to (bound)
 *
 * @example
 *   async function queryOne(sql) {
 *     var rows = await myDriver.query(sql);
 *     return rows[0] || null;
 *   }
 *   var tip = await b.auditChain.getChainTip(queryOne, "audit_log");
 *   // → { prevHash: "<128-char hex>", counter: 4217 }
 */
async function getChainTip(queryOneAsync, tableName, opts) {
  opts = opts || {};
  // Emit a BARE logical table name — the operator-supplied reader routes
  // through clusterStorage, which rewrites bare framework names to the
  // configured-prefix form and placeholderizes. b.sql quotes the camelCase
  // columns + runs the output validator. A chainKey scopes the tip to one
  // partition; the key value binds as a ? placeholder.
  var q = sql.select(tableName, _sqlOpts())
    .columns(["rowHash", "monotonicCounter"])
    .orderBy("monotonicCounter", "desc")
    .limit(1);
  if (opts.chainKey) {
    safeSql.validateIdentifier(opts.chainKey);
    q = q.where(opts.chainKey, opts.keyValue);
  }
  var built = q.toSql();
  var row = await queryOneAsync(built.sql, built.params);
  if (!row) return { prevHash: ZERO_HASH, counter: 0 };
  // Normalize driver shape (Postgres returns BIGINT monotonicCounter as a
  // string) so callers get a numeric counter on every backend.
  frameworkSchema.coerceRow(row);
  return { prevHash: row.rowHash, counter: row.monotonicCounter };
}

/**
 * @primitive b.auditChain.verifyChain
 * @signature b.auditChain.verifyChain(queryAllAsync, tableName, opts)
 * @since     0.4.0
 * @related   b.auditChain.getChainTip, b.audit.verify, b.auditTools.archive
 *
 * Walk the entire chain forward, recomputing each row's hash and
 * comparing against the stored `prevHash` / `rowHash`. Returns
 * `{ ok: true, table, rowsVerified, lastHash }` on a clean walk, or
 * `{ ok: false, table, rowsVerified, breakAt, breakRowId, reason,
 * expected, actual }` on the first mismatch. Callers decide how to
 * react — `b.audit.verify` refuses-to-boot, `b.cli verify-chain`
 * exits non-zero, `b.restoreRollback` blocks promotion.
 *
 * For `audit_log`: if a `_blamejs_audit_purge_anchor` row exists, the
 * walk starts at `lastPurgedCounter+1` with `prevHash =
 * lastPurgedRowHash`. The anchor is written by `b.auditTools.purge`
 * after a successful archive and lets the chain math survive deletion
 * of historical rows without the archive bundle as source of truth.
 *
 * Pass `{ chainKey }` to verify a MULTI-chain table partitioned by a key
 * column (one chain per account / device / tenant): each key's sub-chain is
 * walked independently from `ZERO_HASH`, and the first break in any key returns
 * `{ ok:false, chainKey, breakAt, ... }`. Under `chainKey`, `maxRows` is
 * per-sub-chain and `maxChains` bounds the partition fan-out, failing closed
 * when exceeded. The `audit_log` purge-anchor logic is single-chain-only and
 * is skipped when a `chainKey` is given.
 *
 * @opts
 *   maxRows:   number,   // stop after N rows per (sub-)chain (default: walk every row)
 *   chainKey:  string,   // partition column — verify each sub-chain independently
 *   maxChains: number,   // max partitions to verify under chainKey (default 100000; fails closed)
 *   from:      number,   // single-chain only: verify rows with monotonicCounter >= from, anchored at the predecessor's rowHash (incremental verify after a known-good checkpoint)
 *   to:        number,   // single-chain only: verify rows with monotonicCounter <= to
 *
 * @example
 *   async function queryAll(sql) { return await myDriver.query(sql); }
 *   var result = await b.auditChain.verifyChain(queryAll, "audit_log", {});
 *   // → { ok: true, table: "audit_log", rowsVerified: 4217, lastHash: "<hex>" }
 */
// Walk one (sub-)chain forward from startPrevHash, recomputing each row's
// hash. Returns the same { ok, table, rowsVerified, lastHash | breakAt... }
// shape verifyChain documents. Shared by the single-chain path and each
// per-key partition.
function _walkRows(rows, tableName, startPrevHash, opts) {
  var prevHash = startPrevHash;
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
  // Report the count ACTUALLY walked, not rows.length — under maxRows the walk
  // stops early, so rows.length would over-report coverage (a caller reading
  // rowsVerified to judge how much of the chain was checked must see the real
  // number, not be told the whole table verified when only maxRows did).
  var verifiedCount = opts.maxRows ? Math.min(rows.length, opts.maxRows) : rows.length;
  return { ok: true, table: tableName, rowsVerified: verifiedCount, lastHash: prevHash };
}

async function verifyChain(queryAllAsync, tableName, opts) {
  opts = opts || {};

  // Multi-chain table: verify each partition independently. Each key's
  // sub-chain anchors at ZERO_HASH and is walked in monotonic-counter order;
  // the first break in ANY key returns { ok:false, chainKey, ... }. maxRows is
  // per-sub-chain; maxChains bounds the partition fan-out (fails closed when
  // exceeded). The audit_log purge-anchor logic is single-chain-only, so it is
  // skipped under a chainKey.
  if (opts.chainKey) {
    safeSql.validateIdentifier(opts.chainKey);
    var keysBuilt = sql.select(tableName, _sqlOpts())
      .distinct()
      .columns([opts.chainKey])
      .orderBy(opts.chainKey, "asc")
      .toSql();
    // coerce so a Postgres INTEGER/BIGINT chainKey is type-stable in the
    // reported break-shape and the per-key WHERE bind, matching SQLite.
    var keyRows = frameworkSchema.coerceRows(await queryAllAsync(keysBuilt.sql, keysBuilt.params));
    // Partition fan-out cap; a non-finite / <= 0 / non-integer value (Infinity
    // would make the `keyRows.length > maxChains` cap unsatisfiable) falls back
    // to the bounded default rather than disabling the cap.
    var maxChains = numericBounds.isPositiveFiniteInt(opts.maxChains) ? opts.maxChains : 100000;
    if (keyRows.length > maxChains) {
      return {
        ok:           false,
        table:        tableName,
        rowsVerified: 0,
        reason:       "too many chains: " + keyRows.length + " partitions exceeds maxChains " + maxChains,
      };
    }
    var totalVerified = 0;
    var lastHashByKey = {};
    for (var ki = 0; ki < keyRows.length; ki++) {
      var keyValue = keyRows[ki][opts.chainKey];
      var rowsBuiltK = sql.select(tableName, _sqlOpts())
        .where(opts.chainKey, keyValue)
        .orderBy("monotonicCounter", "asc")
        .toSql();
      var rowsK = frameworkSchema.coerceRows(await queryAllAsync(rowsBuiltK.sql, rowsBuiltK.params));
      var resK = _walkRows(rowsK, tableName, ZERO_HASH, opts);
      if (!resK.ok) { resK.chainKey = keyValue; return resK; }
      totalVerified += resK.rowsVerified;
      lastHashByKey[String(keyValue)] = resK.lastHash;
    }
    return {
      ok:           true,
      table:        tableName,
      rowsVerified: totalVerified,
      chains:       keyRows.length,
      lastHashByKey: lastHashByKey,
    };
  }

  var prevHash = ZERO_HASH;
  var skipBeforeCounter = 0;
  var purgeAnchorHonored = false;
  var purgeAnchorTrustedUnverified = false;
  if (tableName === "audit_log") {
    var anchor;
    try {
      // External-only table whose LOGICAL name IS the `_blamejs_`-prefixed
      // name (self-mapped in LOCAL_TO_EXTERNAL), passed bare so the reader's
      // clusterStorage rewrites it; the 'audit' scope binds as a ? param.
      // allow:hand-rolled-sql — bare logical key.
      anchor = await _readPurgeAnchor(queryAllAsync,
        ["lastPurgedCounter", "lastPurgedRowHash", "archiveBundleId",
         "purgedAt", "signature", "publicKeyFingerprint"]);
    } catch (_e) {
      // The signature columns do not exist on a volume purged before they were
      // added, and a verifier reading the file directly never runs the schema
      // migration that would add them. Falling straight through to "no anchor"
      // would verify a legitimately purged chain from ZERO_HASH and report it
      // TAMPERED — the loudest possible wrong answer, on a volume whose
      // operator did nothing.
      //
      // So try the original columns. If THEY read, this is a legacy unsigned
      // anchor and it gets the explicit refusal that says so. Only when even
      // those fail is there genuinely no anchor table, which is the ordinary
      // state of a deployment that has never purged.
      try {
        anchor = await _readPurgeAnchor(queryAllAsync,
          ["lastPurgedCounter", "lastPurgedRowHash", "archiveBundleId", "purgedAt"]);
      } catch (_e2) {
        anchor = [];
      }
    }
    if (Array.isArray(anchor) && anchor.length > 0) {
      var aHash = anchor[0].lastPurgedRowHash;
      var aCounter = Number(anchor[0].lastPurgedCounter);
      // A corrupted / tampered purge anchor (non-hex lastPurgedRowHash or a
      // non-numeric lastPurgedCounter) must fail CLOSED with a clear reason.
      // Passing a garbage prevHash into _walkRows → computeRowHash would THROW
      // ("prevHash must be a 128-char hex"), turning a defensive verify into an
      // uncaught exception; a NaN counter would skip nothing and surface as an
      // opaque chain-break. Detect it here and return { ok:false }.
      if (!safeBuffer.isHex(aHash, SHA3_512_HEX_LEN) || !isFinite(aCounter) || aCounter < 0) {
        return { ok: false, table: tableName, rowsVerified: 0, reason: "corrupted purge anchor" };
      }

      // The anchor decides which rows are allowed to be missing, so it is only
      // believed when it proves it was written by something holding the audit
      // signing key. Shape was the whole of the old test — 128 hex characters
      // and a finite number — and shape is exactly what an attacker supplies.
      var anchorSigVerdict = _verifyPurgeAnchorSignature(anchor[0], opts.resolvePublicKey);
      // A deployment that turned audit signing off has no key and never will.
      // It has no checkpoints either — it opted out of signature-based tamper
      // evidence entirely — so the anchor is taken as it always was, and the
      // result says plainly that the gap was trusted rather than verified.
      // Refusing here would break a volume for declining a protection it never
      // had; claiming verification would be the false statement this exists to
      // remove.
      if (!anchorSigVerdict.ok && opts.allowUnsignedPurgeAnchor === true) {
        prevHash = aHash;
        skipBeforeCounter = aCounter;
        purgeAnchorHonored = true;
        purgeAnchorTrustedUnverified = true;
        anchorSigVerdict = { ok: true };
      }
      if (!anchorSigVerdict.ok) {
        return {
          ok: false, table: tableName, rowsVerified: 0,
          reason: "purge anchor " + anchorSigVerdict.reason + " — refusing to treat " +
            "rows at or below counter " + aCounter + " as legitimately purged",
          // "we could not check" is not "this is forged", and a caller has to
          // be able to tell them apart: one is a verifier missing its key, the
          // other is a volume to take offline. Both refuse, and only one is an
          // incident.
          purgeAnchorUnchecked: anchorSigVerdict.unresolved === true,
        };
      }
      prevHash = aHash;
      skipBeforeCounter = aCounter;
      purgeAnchorHonored = true;
    }
  }

  // Incremental verify (b.audit.verify { from, to }): verify only rows whose
  // monotonicCounter is in [from, to]. `from` must anchor on the rowHash of the
  // row immediately BEFORE it, so the scoped walk chains correctly — otherwise
  // the first in-range row's prevHash (= the predecessor's rowHash) wouldn't
  // match ZERO_HASH and a good chain would falsely report a break.
  var fromCounter = (opts.from != null && isFinite(Number(opts.from))) ? Number(opts.from) : null;
  var toCounter   = (opts.to != null && isFinite(Number(opts.to)))   ? Number(opts.to)   : null;

  var rowsBuilt = sql.select(tableName, _sqlOpts())
    .orderBy("monotonicCounter", "asc")
    .toSql();
  var rows = await queryAllAsync(rowsBuilt.sql, rowsBuilt.params);
  // Normalize driver shape before hashing: node-postgres returns BIGINT
  // columns (recordedAt / monotonicCounter) as strings, which would hash
  // differently from the numbers the chain-writer signed — the chain only
  // verified on SQLite without this. coerceRow makes the recompute
  // type-stable across backends (no-op on already-numeric SQLite rows).
  rows = frameworkSchema.coerceRows(rows);

  // Resolve the incremental-verify anchor: the highest row strictly below
  // `from` (derived from the already-read rows, no extra query). Raise
  // skipBeforeCounter to it and adopt its rowHash as the chain anchor.
  if (fromCounter != null && fromCounter > skipBeforeCounter + 1) {
    var pred = null;
    for (var pi = 0; pi < rows.length; pi++) {
      var pc = Number(rows[pi].monotonicCounter);
      if (pc < fromCounter && pc > skipBeforeCounter) pred = rows[pi]; else if (pc >= fromCounter) break;
    }
    if (pred) {
      if (!safeBuffer.isHex(pred.rowHash, SHA3_512_HEX_LEN)) {
        return { ok: false, table: tableName, rowsVerified: 0, reason: "incremental-verify anchor row has a corrupt rowHash" };
      }
      prevHash = pred.rowHash;
      skipBeforeCounter = Math.max(skipBeforeCounter, Number(pred.monotonicCounter));
    }
  }

  if (skipBeforeCounter > 0 || toCounter != null) {
    rows = rows.filter(function (r) {
      var c = Number(r.monotonicCounter);
      if (c <= skipBeforeCounter) return false;
      if (toCounter != null && c > toCounter) return false;
      return true;
    });
  }

  var walked = _walkRows(rows, tableName, prevHash, opts);
  // Say whether a gap was excused, and on what. A caller that reports "a
  // verified archive removed these rows" when all that happened was a counter
  // being believed is stating a verification nobody performed.
  if (walked && walked.ok && purgeAnchorHonored) {
    walked.purgeAnchor = {
      honored:         true,
      belowCounter:    skipBeforeCounter,
      // False when the gap was taken on trust because this deployment has
      // audit signing turned off. The distinction is the whole point: a caller
      // must never describe an unverified gap as a verified one.
      signatureVerified: !purgeAnchorTrustedUnverified,
      // The archive itself was NOT resolved. Nothing in the framework knows
      // where a consumer's bundles live, so the identifier is recorded, never
      // fetched. A caller must not describe this as a verified archive.
      archiveResolved: false,
    };
  }
  return walked;
}

/**
 * @primitive b.auditChain.purgeAnchorPayload
 * @signature b.auditChain.purgeAnchorPayload(anchor)
 * @since     0.18.56
 * @status    stable
 * @related   b.auditChain.verifyChain, b.auditSign.verify, b.auditTools.purge
 *
 * The exact bytes a purge anchor's signature covers.
 *
 * A purge anchor records where a retention purge removed rows, and verification
 * discards everything at or below the counter it names. That makes it a claim
 * about the chain, so it is signed, and this builds the payload the signature is
 * made over. Every field that decides what the anchor licenses is included:
 * change the counter, the adopted row hash, the archive it names or when it was
 * written, and the signature stops matching.
 *
 * Use it to check an anchor out of band — against an archived copy of the
 * volume, or from a verifier that holds the public key and never ran `init()`.
 *
 * @example
 *   var anchor = {
 *     lastPurgedCounter: 4096,
 *     lastPurgedRowHash: "9f4e2c3a",
 *     archiveBundleId:   "2026-Q1-audit",
 *     purgedAt:          1750000000000
 *   };
 *   var ok = b.auditSign.verify(
 *     b.auditChain.purgeAnchorPayload(anchor), anchor.signature, publicKeyPem);
 *   // → true when the anchor is the one the purge wrote
 */
function purgeAnchorPayload(anchor) {
  return Buffer.from(canonicalJson.stringify({
    v:                 1,
    scope:             "audit",
    lastPurgedCounter: Number(anchor.lastPurgedCounter),
    lastPurgedRowHash: String(anchor.lastPurgedRowHash),
    archiveBundleId:   String(anchor.archiveBundleId),
    purgedAt:          Number(anchor.purgedAt),
  }), "utf8");
}

// External-only table whose LOGICAL name IS the `_blamejs_`-prefixed name
// (self-mapped in LOCAL_TO_EXTERNAL), passed bare so the reader's
// clusterStorage rewrites it; the 'audit' scope binds as a ? param.
function _readPurgeAnchor(queryAllAsync, columns) {
  // allow:hand-rolled-sql — bare logical key.
  var built = sql.select("_blamejs_audit_purge_anchor", _sqlOpts())   // allow:hand-rolled-sql
    .columns(columns)
    .where("scope", "audit")
    .toSql();
  return queryAllAsync(built.sql, built.params);
}

// Never throws — the caller branches on the verdict, the way checkpoint
// verification does. A forged anchor must produce a refusal, not a stack.
function _verifyPurgeAnchorSignature(anchor, resolvePublicKey) {
  if (!anchor.signature) {
    return { ok: false, reason: "carries no signature" };
  }

  // How the key is found is the caller's to supply, because not every verifier
  // has initialized signing state. `blamejs audit verify-chain` opens a SQLite
  // file directly and never calls auditSign.init, so asking the module would
  // throw not-initialized, and swallowing that would report every VALID anchor
  // as unresolvable — a false alarm on a healthy volume, which is its own kind
  // of wrong answer. A verifier that holds only a public key passes a resolver
  // that returns it.
  var resolve = typeof resolvePublicKey === "function"
    ? resolvePublicKey
    : function (fp) { return auditSign.getPublicKeyByFingerprint(fp); };

  var pub = null;
  var resolveFailed = false;
  try { pub = resolve(anchor.publicKeyFingerprint); }
  catch (_e) { pub = null; resolveFailed = true; }
  if (!pub) {
    return {
      ok: false,
      reason: resolveFailed
        ? "could not be checked — no audit-signing key material is available to this " +
          "verifier (pass opts.resolvePublicKey, or run where b.auditSign is initialized)"
        : "names no audit-signing key on record (fingerprint " +
          String(anchor.publicKeyFingerprint || "<absent>").slice(0, 32) + ")",
      unresolved: resolveFailed,
    };
  }

  var sigBuf = Buffer.isBuffer(anchor.signature)
    ? anchor.signature
    : Buffer.from(anchor.signature);
  var okSig = false;
  try { okSig = auditSign.verify(purgeAnchorPayload(anchor), sigBuf, pub); }
  catch (_e) { okSig = false; }
  return okSig ? { ok: true } : { ok: false, reason: "signature does not verify" };
}

module.exports = {
  ZERO_HASH:          ZERO_HASH,
  canonicalize:       canonicalize,
  computeRowHash:     computeRowHash,
  getChainTip:        getChainTip,
  verifyChain:        verifyChain,
  purgeAnchorPayload: purgeAnchorPayload,
};
