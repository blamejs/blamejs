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
var validateOpts = require("./validate-opts");
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

// ---- Purge anchor: the one statement that licenses missing rows ----

// The anchor is the only thing in the chain that says rows are ALLOWED to be
// absent. Every other tamper check compares a stored hash against a recomputed
// one, so an attacker who deletes rows is caught by the gap; the anchor closes
// that gap by declaration. Left unsigned it is a hole shaped exactly like the
// defence: delete the rows, delete the checkpoints covering them, write an
// anchor naming any hash and counter, and the chain verifies clean. That is
// fewer steps than the relink-and-forge attack the chain already refuses, and
// it erases more, so the anchor has to carry a signature over every field a
// reader acts on.
//
// Distinct from the b.auditSign checkpoint and consumer-anchor formats on
// purpose: a signature minted for one can never be replayed as another.
var PURGE_ANCHOR_FORMAT = "blamejs-purge-anchor-v1";

// Same newline-delimited layout as the b.auditSign consumer anchor, and the
// same reason for refusing the delimiter inside a field: `archiveBundleId` is
// the one operator-influenced string here, and a newline in it would let its
// content migrate across a field boundary without changing the signed bytes,
// so one signature would verify two different readings. Refused at BOTH sign
// time (no ambiguous signature is ever minted) and verify time (a hand-written
// ambiguous row is refused rather than accepted).
var PURGE_ANCHOR_DELIMITER = "\n";

/**
 * @primitive b.auditChain.purgeAnchorPayload
 * @signature b.auditChain.purgeAnchorPayload(anchor, opts?)
 * @since     0.18.58
 * @status    stable
 * @related   b.auditChain.verifyPurgeAnchor, b.auditSign.sign, b.auditTools.purge
 *
 * Canonical signed bytes for a purge anchor. Every field a reader acts on is
 * covered: the boundary counter and row hash the chain walk adopts, the
 * archive identifier an operator would follow to recover the deleted rows, the
 * time it happened, and the scope, so an anchor cannot be lifted into a
 * different scope's row.
 *
 * Throws `TypeError` if a string field contains a newline — see
 * `b.auditChain.verifyPurgeAnchor` for why that is refused rather than escaped.
 *
 * @opts
 *   includeRange: boolean,  // default: true. `false` reproduces the layout from before the range start was covered — for VERIFYING an anchor written by an earlier build, never for signing a new one
 *
 * @example
 *   var sig = b.auditSign.sign(b.auditChain.purgeAnchorPayload(anchor));
 */
function purgeAnchorPayload(anchor, opts) {
  if (!anchor || typeof anchor !== "object") {
    throw new TypeError("purgeAnchorPayload: anchor must be an object");
  }
  var scope  = anchor.scope == null ? "audit" : String(anchor.scope);
  var hash   = String(anchor.lastPurgedRowHash);
  var bundle = String(anchor.archiveBundleId);
  var strings = [["scope", scope], ["lastPurgedRowHash", hash], ["archiveBundleId", bundle]];
  for (var i = 0; i < strings.length; i += 1) {
    if (strings[i][1].indexOf(PURGE_ANCHOR_DELIMITER) !== -1) {
      throw new TypeError("purgeAnchorPayload: " + strings[i][0] +
        " must not contain a newline");
    }
  }
  // Refused at signing time too, so no ambiguous signature is ever minted —
  // the same reason the newline is refused above.
  var counter = Number(anchor.lastPurgedCounter);
  var purgedAt = Number(anchor.purgedAt);
  if (!numericBounds.isIncrementableSafeInt(counter)) {
    throw new TypeError("purgeAnchorPayload: lastPurgedCounter must be a whole " +
      "non-negative number the chain can resume above while staying below 2^53 " +
      "— at or past that, two distinct stored values render identically and one " +
      "signature would cover both, and the first counter after the boundary " +
      "would alias another");
  }
  if (!Number.isSafeInteger(purgedAt)) {
    throw new TypeError("purgeAnchorPayload: purgedAt must be a whole number below 2^53");
  }
  // The fencing token is covered because it is acted on: a purge refuses to
  // proceed when the stored token is above its own. Leaving it outside the
  // signature would let someone who can edit the row lower it without
  // invalidating anything, and a superseded leader would then pass both the
  // pre-check and the fenced write — defeating the single-writer guarantee
  // with a change the signature was happy to ignore.
  var fencingToken = Number(anchor.fencingToken == null ? 0 : anchor.fencingToken);
  if (!numericBounds.isNonNegativeSafeInt(fencingToken)) {
    throw new TypeError("purgeAnchorPayload: fencingToken must be a whole " +
      "non-negative number below 2^53");
  }
  // The start of the licensed range. 0 means "from the beginning of the
  // chain", which is also what an anchor pinned from before this field
  // existed can honestly claim — nothing recorded where that purge began.
  var firstPurgedCounter = Number(
    anchor.firstPurgedCounter == null ? 0 : anchor.firstPurgedCounter);
  if (!numericBounds.isNonNegativeSafeInt(firstPurgedCounter)) {
    throw new TypeError("purgeAnchorPayload: firstPurgedCounter must be a whole " +
      "non-negative number below 2^53");
  }
  var head =
    PURGE_ANCHOR_FORMAT + "\n" +
    scope + "\n" +
    String(counter) + "\n" +
    hash + "\n" +
    bundle + "\n" +
    String(purgedAt) + "\n" +
    String(fencingToken);
  // `includeRange: false` reproduces the layout from before the range start
  // was covered. NOTHING is ever signed that way — the public primitive always
  // includes it — but verification can retry against it for an anchor written
  // by a build that predates the field. See verifyPurgeAnchor for why that
  // retry is safe and why it is limited to a range start of 0.
  if (opts && opts.includeRange === false) return Buffer.from(head, "utf8");
  return Buffer.from(head + "\n" + String(firstPurgedCounter), "utf8");
}

/**
 * @primitive b.auditChain.verifyPurgeAnchor
 * @signature b.auditChain.verifyPurgeAnchor(row, opts?)
 * @since     0.18.58
 * @status    stable
 * @related   b.auditChain.purgeAnchorPayload, b.auditChain.verifyChain, b.auditTools.purge
 *
 * Decide whether a purge-anchor row may be believed. Returns a `status`
 * rather than a boolean, because the three ways an anchor can fail to verify
 * call for three different reactions and collapsing them produces either a
 * false alarm on a healthy volume or a silent pass on a tampered one:
 *
 * - `absent` — no anchor row. Nothing was purged; verify from `ZERO_HASH`.
 * - `valid` — the signature covers the fields, under a key on record.
 * - `unsigned` — no signature. Refused unless the caller acknowledges it
 *   (see `allowUnsigned`), because an unsigned anchor is what the attack
 *   writes AND what an installation purged by an older version already has.
 * - `forged` — a signature that does not verify, or names a key nothing on
 *   this volume knows. Someone edited the anchor.
 * - `unchecked` — a signature that could not be checked at all, because this
 *   process holds no signing key. A verifier opening a database file directly
 *   is in exactly this position, and reporting its anchor as forged would
 *   raise an alarm about a volume nobody touched.
 * - `corrupt` — the fields are not the right shape to act on.
 *
 * Pass `resolvePublicKey(fingerprint)` when the caller holds the key material
 * itself, which offline verification does; without it the anchor is checked
 * against `b.auditSign`'s own keys and public-key history.
 *
 * @opts
 *   resolvePublicKey: function, // (fingerprint) => PEM | null — offline key source
 *   resolveArchive:   function, // (archiveBundleId, { firstCounter, lastCounter, lastRowHash }) => truthy if the archive can still be produced; an anchor naming one that cannot is refused. Several slices can share the checkpoint that covers them, so the id alone does not name one bundle — match the range too
 *   allowUnsignedPurgeAnchor:  boolean, // default: false — accept an anchor written before signing existed
 *   allowUncheckedPurgeAnchor: boolean, // default: false — accept an anchor whose signature could not be checked at all; only for a caller with no signing posture, and the result still reports signatureVerified: false
 *   allowUnsigned:    boolean,  // default: false — accept a pre-signing anchor
 *
 * @example
 *   var v = b.auditChain.verifyPurgeAnchor(row);
 *   if (v.status !== "valid") throw new Error(v.reason);
 */
function verifyPurgeAnchor(row, opts) {
  opts = opts || {};
  if (row == null) return { status: "absent", reason: "no purge anchor" };
  if (typeof row !== "object") {
    return { status: "corrupt", reason: "purge anchor is not a row" };
  }

  // Shape first — a signature over unusable fields is still unusable, and the
  // numbers below are what the walk acts on.
  var hash    = row.lastPurgedRowHash;
  var counter = Number(row.lastPurgedCounter);
  if (!safeBuffer.isHex(hash, SHA3_512_HEX_LEN)) {
    return { status: "corrupt", reason: "corrupted purge anchor: lastPurgedRowHash is not a SHA3-512 hex digest" };
  }
  // Safe-integer, not merely whole. The column is a BIGINT and the signature
  // covers `String(Number(...))`, so two distinct stored values above 2^53
  // render as the same string: an attacker could move the boundary between
  // aliased counters and the signature would still verify, changing which rows
  // are skipped. Refusing the range where Number stops being able to tell them
  // apart closes that without the anchor needing a different numeric type.
  if (!numericBounds.isIncrementableSafeInt(counter)) {
    return { status: "corrupt", reason: "corrupted purge anchor: lastPurgedCounter is not a whole non-negative number the chain can resume above while staying below 2^53" };
  }

  // Stored as a BLOB, matching audit_checkpoints — the signature never becomes
  // text, so there is no encoding step to disagree about between the writer and
  // the reader. Every driver hands a BLOB back as a Buffer; a string is
  // tolerated for a caller that assembled the row itself.
  var signature   = row.signature;
  var fingerprint = row.publicKeyFingerprint;
  var signatureEmpty = signature == null ||
    (Buffer.isBuffer(signature) ? signature.length === 0 : String(signature) === "");
  var fingerprintEmpty = fingerprint == null || String(fingerprint) === "";

  // Exactly one of the two present is not a pre-signing anchor — nothing ever
  // wrote one, and the only way to reach this state is that something removed
  // half of a signature. Calling it "unsigned" would route it onto the
  // compatibility path, where an acknowledgement would pin its boundary
  // permanently and a deployment running without signing would trust it
  // outright. Only a row with NEITHER field is eligible to be treated as
  // written before signing existed.
  if (signatureEmpty !== fingerprintEmpty) {
    return { status: "corrupt", counter: counter, hash: hash,
      reason: "corrupted purge anchor: it carries " +
        (signatureEmpty ? "a key fingerprint but no signature"
                        : "a signature but no key fingerprint") +
        " — half of a signature was removed" };
  }

  if (signatureEmpty) {
    if (opts.allowUnsigned) {
      return { status: "unsigned", accepted: true, counter: counter, hash: hash,
        reason: "purge anchor carries no signature and was accepted by explicit acknowledgement" };
    }
    return { status: "unsigned", accepted: false, counter: counter, hash: hash,
      reason: "purge anchor carries no signature — it licenses " + counter +
        " missing rows and nothing proves this framework wrote it" };
  }

  // An ambiguous field split is refused here as well as at signing time, so a
  // row written by hand cannot exploit a layout the signer would never mint.
  var payload;
  try { payload = purgeAnchorPayload(row); }
  catch (e) { return { status: "corrupt", reason: "corrupted purge anchor: " + e.message }; }

  var publicKeyPem = null, resolveFailed = false;
  try {
    publicKeyPem = typeof opts.resolvePublicKey === "function"
      ? opts.resolvePublicKey(String(fingerprint))
      : auditSign.getPublicKeyByFingerprint(String(fingerprint));
  } catch (_e) {
    // No signing key in this process at all — `b.auditSign` throws rather than
    // returning null when it was never initialized. That is "could not check",
    // NOT "the key is unknown to this volume", and the two must not merge.
    resolveFailed = true;
  }
  if (resolveFailed) {
    return { status: "unchecked", counter: counter, hash: hash,
      reason: "purge anchor signature could not be checked: no audit-signing key is available to this process" };
  }
  if (!publicKeyPem) {
    return { status: "forged", counter: counter, hash: hash,
      reason: "purge anchor is signed under a key this volume has no record of" };
  }

  // The anchor names the key it was signed under, and that name is a hash of
  // the key's own text — so the key about to verify it has to hash to the name.
  // Checking it HERE rather than trusting the lookup is the difference between
  // a guarantee and a convention: `resolvePublicKey` is a documented extension
  // point, so without this the binding holds only while every resolver anyone
  // writes is careful. One that returned a key the anchor does not name would
  // produce a signature that verifies and a boundary attributed to a key that
  // never signed it — which is the whole claim this function makes.
  var resolvedFingerprint = null;
  try { resolvedFingerprint = auditSign.fingerprintOf(publicKeyPem); }
  catch (_e) { resolvedFingerprint = null; }
  if (resolvedFingerprint !== String(fingerprint)) {
    return { status: "forged", counter: counter, hash: hash,
      reason: "purge anchor names key " + String(fingerprint).slice(0, 16) +
        "... but the key resolved for that name hashes to " +
        (resolvedFingerprint === null ? "nothing readable" : resolvedFingerprint.slice(0, 16) + "...") +
        " — the signature would have been checked against a key the anchor does not name" };
  }

  var ok = false;
  try { ok = auditSign.verify(payload, signature, publicKeyPem); }
  catch (_e) { ok = false; }

  // One retry, against the layout from before the range start was covered.
  //
  // An anchor written by a build that predates that field has a signature over
  // the shorter bytes, and the additive migration fills the column with 0 —
  // so rebuilding the current layout produces different bytes and the anchor
  // reads as forged. Refusing it would strand a volume nobody touched.
  //
  // Limited to a stored range start of ZERO, which is the only value such an
  // anchor can have, and which means the same thing in both layouts: the
  // licensed range begins at the start of the chain. An anchor claiming a
  // non-zero start gets no second chance, so this cannot become a way to drop
  // the field from an anchor that has one. Producing either signature still
  // requires the signing key, so nothing is admitted that was not written by
  // something holding it.
  if (!ok && Number(row.firstPurgedCounter == null ? 0 : row.firstPurgedCounter) === 0) {
    try {
      ok = auditSign.verify(
        purgeAnchorPayload(row, { includeRange: false }), signature, publicKeyPem);
    } catch (_e2) { ok = false; }
  }

  if (!ok) {
    return { status: "forged", counter: counter, hash: hash,
      reason: "purge anchor signature does not cover its own fields — the anchor was edited after it was written" };
  }
  return { status: "valid", counter: counter, hash: hash,
    firstCounter: Number(row.firstPurgedCounter == null ? 0 : row.firstPurgedCounter),
    fingerprint: String(fingerprint) };
}

// Columns the anchor has carried since it was first written, and the two added
// when it became signed. They are read in two steps rather than one `SELECT *`
// because a purge performed by an earlier version leaves a row with no
// signature columns at all, and a verifier that opens a database file directly
// never runs the migration that would add them. Asking for a column the table
// does not have is an ERROR on both SQLite and Postgres, and treating that
// error as "no anchor here" would verify a legitimately purged chain from
// ZERO_HASH and report it tampered — the loudest possible wrong answer about a
// volume nobody touched. So: ask for the signed shape, and on any failure ask
// for the legacy shape before concluding the anchor is absent. A missing TABLE
// fails both and is correctly read as absent.
var PURGE_ANCHOR_LEGACY_COLUMNS = ["scope", "lastPurgedCounter", "lastPurgedRowHash",
  "archiveBundleId", "purgedAt"];
// fencingToken is in the SIGNED set, not the legacy one: it arrived with the
// signature columns, and it is covered by the signature, so a projection that
// omitted it would rebuild the payload with a default of 0 and report every
// anchor written under a nonzero token — every anchor written in cluster
// mode — as forged.
var PURGE_ANCHOR_SIGNED_COLUMNS = PURGE_ANCHOR_LEGACY_COLUMNS
  .concat(["signature", "publicKeyFingerprint", "fencingToken", "firstPurgedCounter"]);

// The projections are tried widest first and narrowed ONE step at a time, so a
// column the table happens to lack never costs a column it has. Dropping
// straight to the oldest shape on any missing column would omit `signature`
// from a table that has one, and the anchor would then read as unsigned —
// which is a weaker claim about a stronger record, and on a deployment that
// acknowledges unsigned anchors it would be believed rather than refused.
var PURGE_ANCHOR_PROJECTIONS = [
  PURGE_ANCHOR_SIGNED_COLUMNS,
  PURGE_ANCHOR_LEGACY_COLUMNS.concat(["signature", "publicKeyFingerprint", "fencingToken"]),
  PURGE_ANCHOR_LEGACY_COLUMNS.concat(["signature", "publicKeyFingerprint"]),
  PURGE_ANCHOR_LEGACY_COLUMNS,
];

async function _selectPurgeAnchor(queryAllAsync, columns) {
  // External-only table whose LOGICAL name IS the `_blamejs_`-prefixed name
  // (self-mapped in LOCAL_TO_EXTERNAL), passed bare so the reader's
  // clusterStorage rewrites it; the 'audit' scope binds as a ? param.
  // allow:hand-rolled-sql — bare logical key.
  var built = sql.select("_blamejs_audit_purge_anchor", _sqlOpts())   // allow:hand-rolled-sql
    .columns(columns)
    .where("scope", "audit")
    .toSql();
  var rows = await queryAllAsync(built.sql, built.params);
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

// The two ways this read is allowed to come back empty-handed: the table is
// not there (a deployment that has never purged), or it is there without the
// signature columns (one that purged before they existed). Every OTHER
// failure — a timeout, a dropped connection, a permission error — says
// nothing about whether an anchor exists, and answering it with "there is no
// anchor" is the difference between a purged chain being verified against its
// boundary and being verified from ZERO_HASH and reported clean.
//
// Matching on the message is not lovely, and it is what the three engines
// give: SQLite says "no such table", Postgres "does not exist" with SQLSTATE
// 42P01, MySQL error 1146. A message this does not recognize propagates, so
// an unfamiliar failure stops the verify rather than passing for an absence.
// Postgres words a missing COLUMN and a missing TABLE the same way apart from
// the noun — `column "signature" does not exist` against `relation "x" does
// not exist` — so a bare "does not exist" here would classify a legacy volume,
// whose table is present without the signature columns, as having no table at
// all. It would then skip the fallback that reads the older shape, and a fully
// purged legacy chain would verify from ZERO_HASH with its anchor unread.
function _isMissingRelation(e) {
  var msg = (e && e.message) || "";
  return /no such table|relation .* does not exist|undefined table|42P01|1146/i.test(msg);
}
function _isMissingColumn(e) {
  var msg = (e && e.message) || "";
  return /no such column|column .* does not exist|unknown column|42703|1054/i.test(msg);
}

async function _readPurgeAnchorRow(queryAllAsync) {
  var lastMissingColumn = null;
  for (var i = 0; i < PURGE_ANCHOR_PROJECTIONS.length; i += 1) {
    try {
      return await _selectPurgeAnchor(queryAllAsync, PURGE_ANCHOR_PROJECTIONS[i]);
    } catch (e) {
      // A missing TABLE is answered immediately: every narrower read would
      // fail the same way, and the fallbacks exist for a table that is
      // present but older, not for one that is absent.
      if (_isMissingRelation(e)) return null;
      // Anything that is not a missing column says nothing about the table's
      // shape — a timeout or a permission error must stop the read rather
      // than be retried as though the schema were older than it is.
      if (!_isMissingColumn(e)) throw e;
      lastMissingColumn = e;
    }
  }
  // Even the oldest shape was refused for a missing column, so this is not a
  // table this framework wrote. Reporting it as "no anchor" would license
  // every missing row below it.
  throw lastMissingColumn;
}

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
 * For `audit_log`: if a `_blamejs_audit_purge_anchor` row exists and its
 * signature verifies, the walk starts at `lastPurgedCounter+1` with
 * `prevHash = lastPurgedRowHash`. The anchor is written by
 * `b.auditTools.purge` after a successful archive and lets the chain math
 * survive deletion of historical rows without the archive bundle as source
 * of truth.
 *
 * The signature proves this framework wrote the anchor. It does not prove the
 * archive it names still exists or holds those rows, and nothing here can
 * check that — only the consumer knows where bundles live. Pass
 * `resolveArchive(archiveBundleId, range)` to supply that check: an anchor
 * naming an archive that cannot be produced then STOPS the verify rather than
 * licensing the gap. The `range` carries the counters and row hash the anchor
 * covers, because several archived slices can share the checkpoint that covers
 * them and so share the identifier — matching on the identifier alone would
 * accept an older sibling as proof the anchored bundle is still there. Without
 * a resolver the walk proceeds and the result reports
 * `purgeAnchor.archiveResolved: false`, so a caller is never told an archive
 * was verified when none was looked for.
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

  // Both resolvers are consulted only when callable, so a present-but-wrong
  // value does not fail — it removes a check the caller asked for and returns
  // a clean verify. That reads as "the archive is fine" / "the signature was
  // checked" when neither happened, which is the one answer this function must
  // never give by accident. Refuse the shape instead.
  ["resolveArchive", "resolvePublicKey"].forEach(function (name) {
    var badShape = validateOpts.definedFunctionMessage(
      opts[name], "verifyChain: opts." + name);
    if (badShape) throw new TypeError(badShape);
  });

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
  var anchorReport = null;
  if (tableName === "audit_log") {
    var anchorRow = await _readPurgeAnchorRow(queryAllAsync);
    var verdict = verifyPurgeAnchor(anchorRow, {
      resolvePublicKey: opts.resolvePublicKey,
      allowUnsigned:    opts.allowUnsignedPurgeAnchor === true,
    });
    // "Could not check" is normally a refusal. A caller running without any
    // signing posture at all can say it is expected — see the option's note —
    // and the report then still records that no signature was verified.
    var uncheckedAccepted = verdict.status === "unchecked" &&
      opts.allowUncheckedPurgeAnchor === true;
    if (verdict.status !== "absent") {
      // A corrupt anchor must fail CLOSED with a clear reason rather than
      // reaching the walk: a garbage prevHash makes computeRowHash THROW
      // ("prevHash must be a 128-char hex"), turning a defensive verify into an
      // uncaught exception, and a NaN counter skips nothing and surfaces as an
      // opaque chain break.
      if (verdict.status !== "valid" &&
          !(verdict.status === "unsigned" && verdict.accepted) &&
          !uncheckedAccepted) {
        var out = { ok: false, table: tableName, rowsVerified: 0, reason: verdict.reason };
        // "Could not check" is not "was tampered with". A verifier holding no
        // key still has to report SOMETHING, and it must be distinguishable, or
        // an operator running an offline check on a healthy volume reads a
        // forgery alarm.
        if (verdict.status === "unchecked") out.purgeAnchorUnchecked = true;
        return out;
      }
      // The anchor names an archive, and a signature proves only that this
      // framework wrote the name — not that the bundle exists or holds the
      // rows. Nothing here can check that: only the consumer knows where
      // bundles live. So the caller may supply the check, and when they do, an
      // anchor naming an archive that cannot be produced stops the verify
      // instead of licensing the gap. When they do not, the result says the
      // archive was not resolved rather than letting a clean walk imply the
      // deleted rows were seen again.
      var archiveResolved = false;
      if (typeof opts.resolveArchive === "function") {
        var producible;
        try {
          // The range goes with the identifier because the identifier alone
          // does not name one bundle: several archived slices can share the
          // checkpoint that covers them, and so share the id the anchor
          // records. A resolver given only the id would then accept an older
          // sibling as proof that the anchored one is still there.
          producible = await opts.resolveArchive(String(anchorRow.archiveBundleId), {
            firstCounter: Number(anchorRow.firstPurgedCounter || 0),
            lastCounter:  Number(anchorRow.lastPurgedCounter),
            lastRowHash:  String(anchorRow.lastPurgedRowHash),
          });
        } catch (e) {
          return { ok: false, table: tableName, rowsVerified: 0,
            reason: "purge anchor's archive '" + anchorRow.archiveBundleId +
              "' could not be resolved: " + ((e && e.message) || String(e)) };
        }
        if (!producible) {
          return { ok: false, table: tableName, rowsVerified: 0,
            reason: "purge anchor names archive '" + anchorRow.archiveBundleId +
              "', which could not be produced — the rows it accounts for are " +
              "missing and nothing can show what they were" };
        }
        archiveResolved = true;
      }

      prevHash = verdict.hash;
      skipBeforeCounter = verdict.counter;
      anchorReport = {
        honored:           true,
        belowCounter:      verdict.counter,
        signatureVerified: verdict.status === "valid",
        archiveResolved:   archiveResolved,
        archiveBundleId:   String(anchorRow.archiveBundleId),
        // The range the NAMED archive covers, which after several contiguous
        // purges is only the newest slice of what the boundary licenses: each
        // purge replaces the anchor, so earlier bundles are no longer named
        // anywhere. Resolving this one says nothing about them, and a report
        // that let `archiveResolved` stand for the whole licensed range would
        // claim recoverability it never checked.
        archiveCoversFrom: Number(anchorRow.firstPurgedCounter || 0),
        archiveCoversTo:   verdict.counter,
        licensedFrom:      0,
      };
      if (verdict.fingerprint) anchorReport.publicKeyFingerprint = verdict.fingerprint;
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
  // Report the anchor the walk actually relied on, and on which terms. The
  // counter is the ANCHOR's own, not `skipBeforeCounter`, which an incremental
  // verify raises to the row before its range — reporting that would say an
  // anchor authorizing a purge through 10 authorized one through 149.
  if (anchorReport) walked.purgeAnchor = anchorReport;
  return walked;
}

module.exports = {
  ZERO_HASH:          ZERO_HASH,
  canonicalize:       canonicalize,
  computeRowHash:     computeRowHash,
  getChainTip:        getChainTip,
  purgeAnchorPayload: purgeAnchorPayload,
  verifyChain:        verifyChain,
  verifyPurgeAnchor:  verifyPurgeAnchor,
};
