// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.auditTools
 * @nav    Observability
 * @title  Audit Tools
 *
 * @intro
 *   Operator-side audit-chain inspection / export — verify chain
 *   integrity end-to-end, export RFC 8785 canonical-JSON slices,
 *   format rows for downstream SIEM (CADF / DMTF DSP0262), and generate
 *   tamper-evident compliance-evidence bundles auditors can verify
 *   off-line.
 *
 *   Four core operations on top of the live `audit_log` chain:
 *
 *     archive(opts)      Bundle rows older than `before` into a
 *                        PQC-encrypted archive with chain proof + a
 *                        covering signed checkpoint. Live rows are
 *                        untouched until a separate `purge()` call.
 *     exportSlice(opts)  Auditor-shaped slice (date range / action
 *                        filter) with chain proof — deliver evidence
 *                        to an external auditor without surrendering
 *                        the whole log.
 *     verifyBundle(opts) Round-trip integrity: decrypt the bundle,
 *                        walk chain math across the contained rows,
 *                        verify the covering checkpoint's ML-DSA
 *                        signature (archive bundles only).
 *     purge(opts)        Confirmation-gated deletion of live rows
 *                        already captured in a verified archive
 *                        bundle. Inserts a purge-anchor so
 *                        `b.audit.verify()` keeps working post-purge.
 *
 *   Bundle layout (POSIX-flat directory; matches the backup-bundle
 *   shape so operators see one mental model for "encrypted blamejs
 *   bundle"):
 *
 *     <out>/manifest.json   Canonical-JSON manifest (format / kind /
 *                           range / rowCount / per-blob salts /
 *                           framework version; archive bundles also
 *                           carry the covering checkpoint summary).
 *     <out>/rows.enc        PQC-encrypted JSONL of audit rows in
 *                           sealed form so rowHash stays computable
 *                           from disk bytes byte-for-byte.
 *     <out>/checkpoint.enc  Archive-only. PQC-encrypted JSON of the
 *                           covering audit_checkpoints row.
 *
 *   `kind="archive"` bundles always include a covering checkpoint
 *   (atMonotonicCounter >= lastCounter) so the off-chain signature
 *   tamper-evidences the whole archive. `kind="export"` bundles are
 *   auditor evidence; the chain math is self-contained, with the
 *   upstream signature anchor optional.
 *
 * @card
 *   Operator-side audit-chain inspection / export — verify chain integrity end-to-end, export RFC 8785 canonical-JSON slices, format rows for downstream SIEM (CADF / DMTF DSP0262), and generate tamper-evident compliance-evidence bundles auditors can verify off-line.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var pkg = require("../package.json");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var auditChain = require("./audit-chain");
var canonicalJson = require("./canonical-json");
var auditSign = require("./audit-sign");
var backupCrypto = require("./backup/crypto");
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var frameworkFiles = require("./framework-files");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var safeJson = require("./safe-json");
var sql = require("./sql");
var { defineClass } = require("./framework-error");

var FRAMEWORK_VERSION = (pkg && pkg.version) || "unknown";

// Lazy `db` — db requires audit at top-of-file, audit transitively
// reaches into audit-tools via the operator-supplied default fns,
// so importing db at audit-tools' top would close the cycle. Lazy
// keeps the load order one-way.
var db = lazyRequire(function () { return require("./db"); });
var audit = lazyRequire(function () { return require("./audit"); });

var AuditToolsError = defineClass("AuditToolsError", { alwaysPermanent: true });

// b.sql opts for every framework-table statement: thread the ACTIVE backend
// dialect (clusterStorage.dialect() — "sqlite" single-node, "postgres" |
// "mysql" in cluster mode) so the emitted identifier quoting + dialect
// idioms (ON CONFLICT vs ON DUPLICATE KEY) match the backend the SQL
// dispatches to. Defaulting to "sqlite" works on Postgres only by accident
// (both double-quote identifiers) and emits the wrong quoting on MySQL.
// clusterStorage.execute still rewrites table names + translates `?`
// placeholders at dispatch; this controls only the builder-side quoting +
// idiom selection.
function _sqlOpts() { return { dialect: clusterStorage.dialect() }; }

// Dual-control gate constants for the audit_log physical purge. The
// purge erases signed audit history, so when an operator has declared
// audit_log under b.db.declareRequireDualControl the deletion requires
// a consumed m-of-n grant whose action matches AUDIT_LOG_PURGE_ACTION —
// the same separation-of-duties control b.db.eraseHard enforces (NIST
// SP 800-53 AU-9 + AC-5, HIPAA 45 CFR 164.312(b), PCI-DSS v4.0 10.5.1 /
// 10.7, SEC 17a-4(f), CWE-778).
var AUDIT_LOG_GATE_TABLE   = "audit_log";
var AUDIT_LOG_PURGE_ACTION = "auditTools.purge";

function _resolveDualControlGate(opts) {
  var checker = typeof opts.checkDualControlGate === "function"
    ? opts.checkDualControlGate
    : function (t) { return db()._checkDualControlGate(t); };
  try { return checker(AUDIT_LOG_GATE_TABLE); }
  catch (_e) { return null; }
}

function _emitPurgeDenied(gate, reason) {
  try {
    audit().safeEmit({
      action:   "auditTools.purge.denied",
      outcome:  "denied",
      reason:   reason,
      metadata: { table: AUDIT_LOG_GATE_TABLE, m: gate.m, n: gate.n, posture: gate.posture || null },
    });
  } catch (_e) { /* drop-silent — denial audit is best-effort */ }
}

var BUNDLE_FORMAT  = "blamejs-audit-bundle-v1";
var KIND_ARCHIVE   = "archive";
var KIND_EXPORT    = "export";
var VALID_KINDS    = { archive: true, export: true };

// ---- Helpers ----

function _toMs(value) {
  if (value == null) return null;
  if (typeof value === "number") return value;
  if (value instanceof Date)     return value.getTime();
  if (typeof value === "string") {
    var ms = Date.parse(value);
    if (isNaN(ms)) {
      throw new AuditToolsError("audit-tools/bad-date",
        "invalid date value: " + value);
    }
    return ms;
  }
  throw new AuditToolsError("audit-tools/bad-date",
    "date must be a number, Date, or parseable string");
}

function _requirePassphrase(passphrase) {
  if (!Buffer.isBuffer(passphrase) && typeof passphrase !== "string") {
    throw new AuditToolsError("audit-tools/no-passphrase",
      "opts.passphrase is required (Buffer or string)");
  }
  if (passphrase.length === 0) {
    throw new AuditToolsError("audit-tools/no-passphrase",
      "opts.passphrase must be non-empty");
  }
}

function _requireOutDir(outDir, kind) {
  if (typeof outDir !== "string" || outDir.length === 0) {
    throw new AuditToolsError("audit-tools/no-outdir",
      kind + ": opts.out is required");
  }
  if (nodeFs.existsSync(outDir)) {
    throw new AuditToolsError("audit-tools/outdir-exists",
      kind + ": out already exists: " + outDir +
      " (refusing to overwrite — pick a fresh path)");
  }
}

// Canonical-JSON via the shared lib/canonical-json walker — same bytes
// as audit-chain.canonicalize, config-drift._stableStringify, and
// pagination._canonicalize for the same input. Pre-v0.6.67 each site
// had its own copy of the walk, all carrying the same silent-loss bug
// for Date / Buffer / Map / Set / BigInt / circular renodeFs.
function _canonicalize(value) { return canonicalJson.stringify(value); }

// Convert a single audit_log row to its on-disk-canonical JSON shape.
// Buffers become hex strings (matches audit-chain.canonicalize). Used
// so JSONL written into rows.enc has the exact bytes a verifier needs
// to recompute rowHash.
function _rowToWireForm(row) {
  var out = {};
  var keys = Object.keys(row);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var v = row[k];
    if (Buffer.isBuffer(v))                out[k] = "hex:" + v.toString("hex");
    else if (v instanceof Uint8Array)      out[k] = "hex:" + Buffer.from(v).toString("hex");
    else if (v === undefined)              out[k] = null;
    else                                   out[k] = v;
  }
  return out;
}

// Operator-facing wire helper that surfaces recordedAt as
// ISO-8601 / RFC 3339 alongside the existing Unix-ms integer.
// Auditors comparing rows against external SIEM events expect ISO
// with explicit Z; the framework's primary ms storage stays
// unchanged AND _rowToWireForm (which the chain-hash canonicalizes
// over) doesn't change its bytes — so chain verify continues to
// match. Operators call this on retrieved rows for export.
/**
 * @primitive b.auditTools.withRecordedAtIso
 * @signature b.auditTools.withRecordedAtIso(row)
 * @since     0.7.30
 * @related   b.auditTools.exportSlice, b.auditTools.exportCadf
 *
 * Surface `recordedAt` as ISO-8601 / RFC 3339 (with explicit `Z`)
 * alongside the framework's primary Unix-ms integer. Auditors
 * comparing rows against external SIEM events expect ISO; the chain
 * hash is unaffected because the canonical wire form used for
 * hashing doesn't include the derived `recordedAtIso` field.
 *
 * Returns a shallow copy with `recordedAtIso` added when
 * `recordedAt` is a finite number / bigint; otherwise returns the
 * input unchanged.
 *
 * @example
 *   var row = { _id: "evt-1", recordedAt: 1762560000000, action: "auth.login" };
 *   var formatted = b.auditTools.withRecordedAtIso(row);
 *   // → { _id: "evt-1", recordedAt: 1762560000000,
 *   //     recordedAtIso: "2025-11-08T00:00:00.000Z", action: "auth.login" }
 */
function withRecordedAtIso(row) {
  if (!row) return row;
  var out = Object.assign({}, row);
  if (typeof row.recordedAt === "number" || typeof row.recordedAt === "bigint") {
    var ms = typeof row.recordedAt === "bigint" ? Number(row.recordedAt) : row.recordedAt;
    if (isFinite(ms)) out.recordedAtIso = new Date(ms).toISOString();
  }
  return out;
}

function _wireFormToRow(wire) {
  var out = {};
  var keys = Object.keys(wire);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var v = wire[k];
    if (typeof v === "string" && v.indexOf("hex:") === 0) {
      out[k] = Buffer.from(v.slice(4), "hex");
    } else {
      out[k] = v;
    }
  }
  return out;
}

// Walk a slice of audit rows recomputing their hash chain. Returns
// { ok, rowsVerified, breakAt? }. The starting prevHash is the caller's
// responsibility — for archive/export slices it's the row preceding the
// slice's first row (which is itself in the bundle's manifest as a
// witness, or ZERO_HASH for slices that start at counter=1).
function _verifyChainSlice(rows, startPrevHash) {
  var prevHash = startPrevHash;
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    if (row.prevHash !== prevHash) {
      return {
        ok: false, rowsVerified: i, breakAt: i,
        reason: "prevHash mismatch",
        expected: prevHash,
        actual:   row.prevHash,
      };
    }
    var fields = Object.assign({}, row);
    delete fields.prevHash;
    delete fields.rowHash;
    delete fields.nonce;
    delete fields.fencingToken;
    var nonceBuf = Buffer.isBuffer(row.nonce) ? row.nonce : Buffer.from(row.nonce);
    var computed = auditChain.computeRowHash(prevHash, fields, nonceBuf);
    if (computed !== row.rowHash) {
      return {
        ok: false, rowsVerified: i, breakAt: i,
        reason: "rowHash mismatch",
        expected: computed,
        actual:   row.rowHash,
      };
    }
    prevHash = row.rowHash;
  }
  return { ok: true, rowsVerified: rows.length, lastHash: prevHash };
}

// Read all audit rows from the operator's reader. Defaults to a
// cluster-storage reader so the tooling works in both single-node and
// cluster deployments without the caller knowing which mode is active.
async function _defaultReadRows(criteria) {
  // Compose the criteria onto a b.sql SELECT with a BARE logical table name
  // (clusterStorage rewrites the framework name + placeholderizes); b.sql
  // quotes the camelCase columns + binds every value.
  var qb = sql.select("audit_log", _sqlOpts());
  if (criteria.fromMs != null)       qb.whereOp("recordedAt", ">=", criteria.fromMs);
  if (criteria.toMs != null)         qb.whereOp("recordedAt", "<=", criteria.toMs);
  if (criteria.beforeMs != null)     qb.whereOp("recordedAt", "<", criteria.beforeMs);
  if (criteria.action)               qb.where("action", criteria.action);
  if (criteria.firstCounter != null) qb.whereOp("monotonicCounter", ">=", criteria.firstCounter);
  if (criteria.lastCounter != null)  qb.whereOp("monotonicCounter", "<=", criteria.lastCounter);
  qb.orderBy("monotonicCounter", "asc");
  var built = qb.toSql();
  return clusterStorage.executeAll(built.sql, built.params);
}

async function _defaultReadCoveringCheckpoint(lastCounter) {
  var built = sql.select("audit_checkpoints", _sqlOpts())
    .whereOp("atMonotonicCounter", ">=", lastCounter)
    .orderBy("atMonotonicCounter", "asc")
    .limit(1)
    .toSql();
  return clusterStorage.executeOne(built.sql, built.params);
}

async function _defaultReadPredecessorRowHash(firstCounter) {
  if (firstCounter <= 1) return auditChain.ZERO_HASH;
  var rowBuilt = sql.select("audit_log", _sqlOpts())
    .columns(["rowHash"])
    .where("monotonicCounter", firstCounter - 1)
    .toSql();
  var row = await clusterStorage.executeOne(rowBuilt.sql, rowBuilt.params);
  if (!row) {
    // First row of the slice is right after a purged range. Read the
    // purge anchor's lastRowHash instead. The anchor is an external-only
    // table whose LOGICAL name IS the `_blamejs_`-prefixed name (it maps
    // to itself in LOCAL_TO_EXTERNAL); b.sql must receive it bare so
    // clusterStorage rewrites it. allow:hand-rolled-sql — bare logical key.
    var anchor = await _defaultReadPurgeAnchor();
    if (anchor && Number(anchor.lastPurgedCounter) === firstCounter - 1) {
      // This hash becomes the ground of the NEXT archive's proof, so an
      // unverified one launders a forged boundary into a signed bundle. Same
      // check as the purge path and the verify path, for the same reason.
      var policy = _anchorVerifyOpts();
      var verdict = auditChain.verifyPurgeAnchor(anchor, policy);
      if (!_anchorBelievable(verdict, policy)) {
        throw new AuditToolsError("audit-tools/anchor-not-verified",
          "predecessor row at counter=" + (firstCounter - 1) +
          " is covered by a purge anchor that cannot be believed — " + verdict.reason);
      }
      return anchor.lastPurgedRowHash;
    }
    throw new AuditToolsError("audit-tools/no-predecessor",
      "predecessor row at counter=" + (firstCounter - 1) + " missing — chain proof would be ungrounded");
  }
  return row.rowHash;
}

// ---- Bundle writer ----

// Assemble the encrypted bundle entirely in memory: returns the
// manifest plus an ordered { filename: Buffer } map. Pure — no
// filesystem touch — so it backs both the on-disk writer and the
// returnBytes / serverless path. The bundle is always the same 2-3
// files (rows.enc, optional checkpoint.enc, manifest.json) whether it
// lands on disk or ships as bytes.
async function _buildBundle(args) {
  var kind         = args.kind;
  var rows         = args.rows;
  // Verification witnesses: the rows between the purgeable slice's tip and
  // the covering checkpoint's anchored counter. They ride the bundle so the
  // chain can be walked up to the SIGNED atRowHash, but they are NOT part of
  // the purgeable range (the manifest range below is computed from `rows`,
  // and purge() only deletes [first..lastCounter]).
  var witnessRows  = args.witnessRows || [];
  var checkpoint   = args.checkpoint || null;
  var passphrase   = args.passphrase;
  var predecessorRowHash = args.predecessorRowHash;

  var firstRow = rows[0];
  var lastRow  = rows[rows.length - 1];
  var files = {};

  // 1. Encrypt the rows JSONL — purgeable slice followed by any witnesses
  // (contiguous, ascending) so the verifier walks one unbroken chain.
  var jsonl = rows.concat(witnessRows).map(function (r) {
    return JSON.stringify(_rowToWireForm(r));
  }).join("\n") + "\n";
  var rowsEnc = await backupCrypto.encryptWithFreshSalt(jsonl, passphrase);
  files[frameworkFiles.fileName("rowsEnc")] = rowsEnc.encrypted;

  // 2. (archive) Encrypt the checkpoint JSON
  var checkpointSalt = null;
  var checkpointEncrypted = null;
  if (checkpoint) {
    var ckptJson = _canonicalize(_rowToWireForm(checkpoint));
    var ckptEnc = await backupCrypto.encryptWithFreshSalt(ckptJson, passphrase);
    files[frameworkFiles.fileName("checkpointEnc")] = ckptEnc.encrypted;
    checkpointSalt = ckptEnc.salt;
    checkpointEncrypted = ckptEnc.encrypted;
  }

  // 3. Build manifest — checksums computed from the in-memory buffers
  // (no read-back of what we just wrote).
  var manifest = {
    format:         BUNDLE_FORMAT,
    kind:           kind,
    createdAt:      Date.now(),
    frameworkVersion: FRAMEWORK_VERSION,
    rowCount:       rows.length,
    range: {
      firstCounter:    Number(firstRow.monotonicCounter),
      lastCounter:     Number(lastRow.monotonicCounter),
      firstRecordedAt: Number(firstRow.recordedAt),
      lastRecordedAt:  Number(lastRow.recordedAt),
      firstRowHash:    String(firstRow.rowHash),
      lastRowHash:     String(lastRow.rowHash),
      predecessorRowHash: String(predecessorRowHash),
    },
    salts: {
      rows:       rowsEnc.salt,
      checkpoint: checkpointSalt,
    },
    checksum: {
      rowsSha3_512:       backupCrypto.checksum(rowsEnc.encrypted),
      checkpointSha3_512: checkpointEncrypted
        ? backupCrypto.checksum(checkpointEncrypted)
        : null,
    },
  };
  if (checkpoint) {
    manifest.checkpoint = {
      atMonotonicCounter:   Number(checkpoint.atMonotonicCounter),
      atRowHash:            String(checkpoint.atRowHash),
      publicKeyFingerprint: String(checkpoint.publicKeyFingerprint),
      checkpointId:         String(checkpoint._id),
    };
  }
  files["manifest.json"] = Buffer.from(_canonicalize(manifest), "utf8");
  return { manifest: manifest, files: files };
}

async function _writeBundle(args) {
  var outDir = args.outDir;
  var built  = await _buildBundle(args);

  atomicFile.ensureDir(outDir);
  atomicFile.writeSync(nodePath.join(outDir, frameworkFiles.fileName("rowsEnc")), built.files[frameworkFiles.fileName("rowsEnc")], { fileMode: 0o600 });
  if (built.files[frameworkFiles.fileName("checkpointEnc")]) {
    atomicFile.writeSync(nodePath.join(outDir, frameworkFiles.fileName("checkpointEnc")), built.files[frameworkFiles.fileName("checkpointEnc")], { fileMode: 0o600 });
  }
  var manifestPath = nodePath.join(outDir, "manifest.json");
  atomicFile.writeSync(manifestPath, built.files["manifest.json"], { fileMode: 0o600 });
  return { manifest: built.manifest, manifestPath: manifestPath };
}

// ---- Bundle reader ----

async function _readBundle(inDir, passphrase) {
  if (typeof inDir !== "string" || !nodeFs.existsSync(inDir)) {
    throw new AuditToolsError("audit-tools/no-bundle",
      "bundle directory does not exist: " + inDir);
  }
  var manifestPath = nodePath.join(inDir, "manifest.json");
  // Capped fd-bound read (no existsSync check-then-read window): an externally-
  // supplied bundle manifest is parsed before verification, so an oversized
  // manifest.json would OOM the verifier before safeJson sees it. 4 MiB is far
  // above any real manifest.
  var manifest = safeJson.parse(atomicFile.fdSafeReadSync(manifestPath, {
    maxBytes: C.BYTES.mib(4), encoding: "utf8",
    errorFor: function (kind, detail) {
      if (kind === "enoent") return new AuditToolsError("audit-tools/no-manifest", "manifest.json missing in " + inDir);
      if (kind === "too-large") return new AuditToolsError("audit-tools/bad-format", "manifest.json too large (" + detail.size + " > " + detail.max + ")");
      return new AuditToolsError("audit-tools/bad-format", "manifest.json unreadable: " + kind);
    },
  }), { maxBytes: C.BYTES.mib(4) });
  if (!manifest || manifest.format !== BUNDLE_FORMAT) {
    throw new AuditToolsError("audit-tools/bad-format",
      "manifest.format is not " + BUNDLE_FORMAT);
  }
  if (!Object.prototype.hasOwnProperty.call(VALID_KINDS, manifest.kind)) {
    throw new AuditToolsError("audit-tools/bad-kind",
      "manifest.kind must be one of " + Object.keys(VALID_KINDS).join(", "));
  }

  var rowsEncPath = nodePath.join(inDir, frameworkFiles.fileName("rowsEnc"));
  // Capped fd-bound read: rows.enc is the PQC-encrypted archived audit slice
  // (can be large); a hostile multi-GB blob would be read + decrypted in memory
  // before the checksum check. 512 MiB ceiling bounds it (opt-tunable).
  var rowsEnc = atomicFile.fdSafeReadSync(rowsEncPath, {
    maxBytes: C.BYTES.mib(512),
    errorFor: function (kind) {
      if (kind === "enoent") return new AuditToolsError("audit-tools/no-rows-blob", "rows.enc missing in " + inDir);
      if (kind === "too-large") return new AuditToolsError("audit-tools/rows-too-large", "rows.enc exceeds the bundle size cap");
      return new AuditToolsError("audit-tools/no-rows-blob", "rows.enc unreadable: " + kind);
    },
  });
  if (manifest.checksum && manifest.checksum.rowsSha3_512 &&
      backupCrypto.checksum(rowsEnc) !== manifest.checksum.rowsSha3_512) {
    throw new AuditToolsError("audit-tools/rows-checksum-mismatch",
      "rows.enc checksum does not match manifest — bundle was tampered with");
  }
  var rowsPlainBuf = await backupCrypto.decryptWithPassphrase(rowsEnc, passphrase, manifest.salts.rows);
  var rowsPlain = rowsPlainBuf.toString("utf8");
  var lines = rowsPlain.split("\n").filter(function (l) { return l.length > 0; });
  var rows = lines.map(function (l) { return _wireFormToRow(safeJson.parse(l)); });

  var checkpoint = null;
  if (manifest.kind === KIND_ARCHIVE) {
    var ckptPath = nodePath.join(inDir, frameworkFiles.fileName("checkpointEnc"));
    // Capped fd-bound read: checkpoint.enc is a single PQC-encrypted
    // audit_checkpoints row (a few KiB); 4 MiB bounds a hostile blob.
    var ckptEnc = atomicFile.fdSafeReadSync(ckptPath, {
      maxBytes: C.BYTES.mib(4),
      errorFor: function (kind) {
        if (kind === "enoent") return new AuditToolsError("audit-tools/no-checkpoint-blob", "checkpoint.enc missing in " + inDir + " (archive bundles must include the covering checkpoint)");
        if (kind === "too-large") return new AuditToolsError("audit-tools/checkpoint-too-large", "checkpoint.enc exceeds the cap");
        return new AuditToolsError("audit-tools/no-checkpoint-blob", "checkpoint.enc unreadable: " + kind);
      },
    });
    if (manifest.checksum && manifest.checksum.checkpointSha3_512 &&
        backupCrypto.checksum(ckptEnc) !== manifest.checksum.checkpointSha3_512) {
      throw new AuditToolsError("audit-tools/checkpoint-checksum-mismatch",
        "checkpoint.enc checksum does not match manifest");
    }
    var ckptPlain = (await backupCrypto.decryptWithPassphrase(ckptEnc, passphrase, manifest.salts.checkpoint))
      .toString("utf8");
    checkpoint = _wireFormToRow(safeJson.parse(ckptPlain));
  }

  return { manifest: manifest, rows: rows, checkpoint: checkpoint };
}

// ---- Public ops ----

/**
 * @primitive b.auditTools.archive
 * @signature b.auditTools.archive(opts)
 * @since     0.7.30
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related   b.auditTools.verifyBundle, b.auditTools.purge, b.audit.checkpoint
 *
 * Bundle every audit row older than `opts.before` into a
 * PQC-encrypted archive (XChaCha20-Poly1305 + Argon2id-derived key)
 * containing a chain proof and the covering ML-DSA-87 checkpoint.
 * Live rows are untouched — call `b.auditTools.purge` separately
 * once the archive is verified.
 *
 * Refuses if `opts.out` exists, no rows match, or no signed
 * checkpoint covers the slice (run `b.audit.checkpoint()` first).
 *
 * Pass `returnBytes: true` instead of `out` for the bundle as an
 * in-memory `{ filename: Buffer }` map (`rows.enc` + `checkpoint.enc`
 * + `manifest.json`) — the read-only / serverless path. `out` and
 * `returnBytes` are mutually exclusive.
 *
 * @opts
 *   out:        string,         // fresh directory path (omit when returnBytes)
 *   returnBytes:boolean,        // true → return { manifest, files } in memory, no disk
 *   before:     number|Date|string,  // archive rows recordedAt < this
 *   passphrase: Buffer|string,  // bundle-encryption passphrase
 *
 * @example
 *   var ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000;
 *   var result = await b.auditTools.archive({
 *     out:        "/var/audit/2026-Q1.bundle",
 *     before:     ninetyDaysAgo,
 *     passphrase: process.env.AUDIT_BUNDLE_PASSPHRASE,
 *   });
 *   // → { rowCount: 14823, range: { firstCounter: 1, lastCounter: 14823, ... },
 *   //     manifestPath: "/var/audit/2026-Q1.bundle/manifest.json", ... }
 */
async function archive(opts) {
  opts = opts || {};
  _requirePassphrase(opts.passphrase);
  var returnBytes = opts.returnBytes === true;
  if (returnBytes && opts.out !== undefined) {
    throw new AuditToolsError("audit-tools/out-and-return-bytes",
      "archive: specify either opts.out (write to disk) or opts.returnBytes (in-memory bytes), not both");
  }
  if (!returnBytes) _requireOutDir(opts.out, "archive");
  var beforeMs = _toMs(opts.before);
  if (beforeMs == null) {
    throw new AuditToolsError("audit-tools/no-before",
      "archive: opts.before is required (date older than which rows are archived)");
  }
  var readRows = opts.readRows || _defaultReadRows;
  var readCovering = opts.readCoveringCheckpoint || _defaultReadCoveringCheckpoint;
  var readPredecessorHash = opts.readPredecessorRowHash || _defaultReadPredecessorRowHash;

  var rows = await readRows({ beforeMs: beforeMs });
  if (rows.length === 0) {
    throw new AuditToolsError("audit-tools/empty",
      "archive: no audit rows match (before=" + new Date(beforeMs).toISOString() + ")");
  }
  var lastCounter = Number(rows[rows.length - 1].monotonicCounter);
  var firstCounter = Number(rows[0].monotonicCounter);

  var checkpoint = await readCovering(lastCounter);
  if (!checkpoint) {
    throw new AuditToolsError("audit-tools/no-covering-checkpoint",
      "archive: no signed checkpoint covers counter=" + lastCounter +
      " — run audit.checkpoint() before archiving so the bundle has an off-chain anchor");
  }

  var predecessorRowHash = await readPredecessorHash(firstCounter);

  // The signed checkpoint is the bundle's only unforgeable anchor; it commits
  // the row at checkpoint.atMonotonicCounter. When that counter sits BEYOND
  // the purgeable slice's tip (the operator archived a subset older than the
  // last checkpoint), carry the in-between rows as verification witnesses so
  // verifyBundle can chain-walk up to the anchored row and bind atRowHash to
  // it. Without them an attacker could pair any genuine high-counter
  // checkpoint with a wholly fabricated slice. The witnesses are NOT purged.
  var anchorCounter = Number(checkpoint.atMonotonicCounter);
  var witnessRows = [];
  if (anchorCounter > lastCounter) {
    witnessRows = await readRows({ firstCounter: lastCounter + 1, lastCounter: anchorCounter });
    var witnessTip = witnessRows.length ? Number(witnessRows[witnessRows.length - 1].monotonicCounter) : null;
    if (witnessTip !== anchorCounter) {
      throw new AuditToolsError("audit-tools/anchor-rows-missing",
        "archive: covering checkpoint anchors counter=" + anchorCounter +
        " but the rows up to it are not all available (read up to " + witnessTip +
        ") — cannot prove the slice chains to the signed anchor");
    }
  }

  if (returnBytes) {
    var built = await _buildBundle({
      kind:       KIND_ARCHIVE,
      rows:       rows,
      witnessRows: witnessRows,
      checkpoint: checkpoint,
      passphrase: opts.passphrase,
      predecessorRowHash: predecessorRowHash,
    });
    return {
      manifest: built.manifest,
      files:    built.files,
      rowCount: rows.length,
      range:    built.manifest.range,
    };
  }

  var written = await _writeBundle({
    outDir:     opts.out,
    kind:       KIND_ARCHIVE,
    rows:       rows,
    witnessRows: witnessRows,
    checkpoint: checkpoint,
    passphrase: opts.passphrase,
    predecessorRowHash: predecessorRowHash,
  });

  return {
    manifest:     written.manifest,
    manifestPath: written.manifestPath,
    outDir:       opts.out,
    rowCount:     rows.length,
    range:        written.manifest.range,
  };
}

/**
 * @primitive b.auditTools.exportSlice
 * @signature b.auditTools.exportSlice(opts)
 * @since     0.7.30
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.auditTools.archive, b.auditTools.verifyBundle, b.auditTools.exportCadf
 *
 * Auditor-shaped slice — bundle the audit rows in `[from, to]`
 * (optionally filtered by exact `action`) into a PQC-encrypted
 * directory carrying chain-proof material. Refuses non-contiguous
 * slices because chain verification cannot ground a sequence with
 * gaps in `monotonicCounter`.
 *
 * Use date-range filters that cover every row in the range; an
 * action filter that drops intermediate counters is rejected with
 * `audit-tools/non-contiguous`.
 *
 * Pass `returnBytes: true` instead of `out` to get the bundle as an
 * in-memory `{ filename: Buffer }` map (`rows.enc` + `manifest.json`)
 * with no filesystem touch — the read-only / serverless path; ship it
 * to object storage or over the wire. `out` and `returnBytes` are
 * mutually exclusive.
 *
 * @opts
 *   out:        string,                // fresh directory path (omit when returnBytes)
 *   returnBytes:boolean,               // true → return { manifest, files } in memory, no disk
 *   from:       number|Date|string,    // recordedAt >= this (inclusive)
 *   to:         number|Date|string,    // recordedAt <= this (inclusive)
 *   action:     string,                // exact action match (optional)
 *   passphrase: Buffer|string,         // bundle-encryption passphrase
 *
 * @example
 *   var bundle = await b.auditTools.exportSlice({
 *     out:        "/tmp/audit-2026-q1.bundle",
 *     from:       "2026-01-01T00:00:00Z",
 *     to:         "2026-03-31T23:59:59Z",
 *     passphrase: process.env.AUDIT_BUNDLE_PASSPHRASE,
 *   });
 *   // → { rowCount: 4218, manifest: { kind: "export", ... }, ... }
 */
async function exportSlice(opts) {
  opts = opts || {};
  _requirePassphrase(opts.passphrase);
  var returnBytes = opts.returnBytes === true;
  if (returnBytes && opts.out !== undefined) {
    throw new AuditToolsError("audit-tools/out-and-return-bytes",
      "export: specify either opts.out (write to disk) or opts.returnBytes (in-memory bytes), not both");
  }
  if (!returnBytes) _requireOutDir(opts.out, "export");
  var fromMs = _toMs(opts.from);
  var toMs   = _toMs(opts.to);
  var readRows = opts.readRows || _defaultReadRows;
  var readPredecessorHash = opts.readPredecessorRowHash || _defaultReadPredecessorRowHash;

  var criteria = {};
  if (fromMs != null) criteria.fromMs = fromMs;
  if (toMs   != null) criteria.toMs   = toMs;
  if (opts.action) criteria.action = opts.action;

  var rows = await readRows(criteria);
  if (rows.length === 0) {
    throw new AuditToolsError("audit-tools/empty",
      "export: no audit rows match criteria");
  }
  // For an export the slice may be non-contiguous in counter space (e.g.
  // filtered by action). Reject non-contiguous slices because chain
  // verification can't ground a non-contiguous sequence.
  for (var i = 1; i < rows.length; i++) {
    var prev = Number(rows[i - 1].monotonicCounter);
    var cur  = Number(rows[i].monotonicCounter);
    if (cur !== prev + 1) {
      throw new AuditToolsError("audit-tools/non-contiguous",
        "export: slice is non-contiguous in monotonicCounter (" + prev + " → " + cur + "). " +
        "Filtered exports break chain proof; use date-range filters that cover all rows in the range.");
    }
  }
  var firstCounter = Number(rows[0].monotonicCounter);
  var predecessorRowHash = await readPredecessorHash(firstCounter);

  if (returnBytes) {
    var built = await _buildBundle({
      kind:       KIND_EXPORT,
      rows:       rows,
      checkpoint: null,
      passphrase: opts.passphrase,
      predecessorRowHash: predecessorRowHash,
    });
    return {
      manifest: built.manifest,
      files:    built.files,
      rowCount: rows.length,
      range:    built.manifest.range,
    };
  }

  var written = await _writeBundle({
    outDir:     opts.out,
    kind:       KIND_EXPORT,
    rows:       rows,
    checkpoint: null,
    passphrase: opts.passphrase,
    predecessorRowHash: predecessorRowHash,
  });

  return {
    manifest:     written.manifest,
    manifestPath: written.manifestPath,
    outDir:       opts.out,
    rowCount:     rows.length,
    range:        written.manifest.range,
  };
}

/**
 * @primitive b.auditTools.verifyBundle
 * @signature b.auditTools.verifyBundle(opts)
 * @since     0.7.30
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related   b.auditTools.archive, b.auditTools.exportSlice, b.auditTools.purge
 *
 * Round-trip integrity check on a bundle directory: decrypt
 * `rows.enc`, walk the prevHash → rowHash chain across the contained
 * rows starting from the manifest's `predecessorRowHash` witness,
 * confirm `firstRowHash` / `lastRowHash` match, and (archive only)
 * verify the covering checkpoint's ML-DSA-87 signature against the
 * locally-loaded audit-sign public key (or `opts.verifySignature`
 * for cross-machine auditors).
 *
 * Returns `{ ok: true, kind, rowsVerified, range, manifest }` on
 * success or `{ ok: false, reason, breakAt? }` at the first break.
 *
 * @opts
 *   in:                          string,               // bundle directory
 *   passphrase:                  Buffer|string,        // decryption passphrase
 *   verifyCheckpointSignature:   boolean,              // default true
 *   verifySignature:             function(checkpoint), // override the default verifier
 *   includeRows:                 boolean,              // attach decrypted rows to result
 *
 * @example
 *   var result = await b.auditTools.verifyBundle({
 *     in:         "/var/audit/2026-Q1.bundle",
 *     passphrase: process.env.AUDIT_BUNDLE_PASSPHRASE,
 *   });
 *   if (!result.ok) {
 *     console.error("bundle integrity break:", result.reason);
 *     process.exit(1);
 *   }
 *   // → { ok: true, kind: "archive", rowsVerified: 14823, range: { ... } }
 */
async function verifyBundle(opts) {
  opts = opts || {};
  _requirePassphrase(opts.passphrase);
  if (typeof opts.in !== "string") {
    throw new AuditToolsError("audit-tools/no-indir",
      "verifyBundle: opts.in is required (bundle directory)");
  }
  var read = await _readBundle(opts.in, opts.passphrase);

  // 1. Walk the chain math across the slice.
  var chainResult = _verifyChainSlice(read.rows, read.manifest.range.predecessorRowHash);
  if (!chainResult.ok) {
    return {
      ok:             false,
      kind:           read.manifest.kind,
      rowsVerified:   chainResult.rowsVerified,
      breakAt:        chainResult.breakAt,
      reason:         "chain " + chainResult.reason +
                      " (counter=" + Number(read.rows[chainResult.breakAt].monotonicCounter) + ")",
      expected:       chainResult.expected,
      actual:         chainResult.actual,
    };
  }

  // 2. Confirm the stored firstRowHash + lastRowHash match the PURGEABLE
  // slice boundary. The slice tip is the row at range.lastCounter — not
  // necessarily the physical last row, which may be a verification witness
  // carried past the slice so the chain can reach the signed checkpoint.
  var lastCounterN = Number(read.manifest.range.lastCounter);
  var sliceLastRow = null;
  for (var ri = 0; ri < read.rows.length; ri++) {
    if (Number(read.rows[ri].monotonicCounter) === lastCounterN) { sliceLastRow = read.rows[ri]; break; }
  }
  if (read.rows[0].rowHash !== read.manifest.range.firstRowHash) {
    return {
      ok: false, kind: read.manifest.kind, rowsVerified: read.rows.length,
      reason: "manifest.range.firstRowHash does not match first row's rowHash",
    };
  }
  if (!sliceLastRow || sliceLastRow.rowHash !== read.manifest.range.lastRowHash) {
    return {
      ok: false, kind: read.manifest.kind, rowsVerified: read.rows.length,
      reason: "manifest.range.lastRowHash does not match the slice row at lastCounter",
    };
  }

  // 3. (archive only) verify the covering checkpoint signature AND bind its
  // anchored rowHash to the slice. The signature alone proves only that a
  // checkpoint exists for some (counter, rowHash); without binding atRowHash
  // to the archived rows, any genuine high-counter checkpoint could be paired
  // with a wholly fabricated slice. The row at checkpoint.atMonotonicCounter
  // must be present in the bundle (slice or witness) and its rowHash must
  // equal checkpoint.atRowHash — mirroring b.audit.verifyCheckpoints against
  // the live table.
  if (read.manifest.kind === KIND_ARCHIVE) {
    if (!read.checkpoint) {
      return { ok: false, kind: KIND_ARCHIVE, reason: "checkpoint missing from archive bundle" };
    }
    if (Number(read.checkpoint.atMonotonicCounter) < lastCounterN) {
      return {
        ok: false, kind: KIND_ARCHIVE,
        reason: "checkpoint atMonotonicCounter (" + read.checkpoint.atMonotonicCounter +
                ") < archive lastCounter (" + read.manifest.range.lastCounter + ")",
      };
    }
    if (opts.verifyCheckpointSignature !== false) {
      var verifier = opts.verifySignature || _defaultVerifyCheckpointSignature;
      var sigOk = verifier(read.checkpoint);
      if (!sigOk) {
        return {
          ok: false, kind: KIND_ARCHIVE,
          reason: "checkpoint ML-DSA signature verification failed (auditor's audit-sign public key may differ from archive's; pass opts.verifySignature to override)",
        };
      }
    }
    // Bind: the row the signature anchors must be in the bundle and match.
    var anchorCounterN = Number(read.checkpoint.atMonotonicCounter);
    var anchoredRow = null;
    for (var ai = 0; ai < read.rows.length; ai++) {
      if (Number(read.rows[ai].monotonicCounter) === anchorCounterN) { anchoredRow = read.rows[ai]; break; }
    }
    if (!anchoredRow) {
      return {
        ok: false, kind: KIND_ARCHIVE,
        reason: "checkpoint anchors counter=" + anchorCounterN +
                " but no such row is present in the bundle — checkpoint not bound to the archived slice",
      };
    }
    if (anchoredRow.rowHash !== read.checkpoint.atRowHash) {
      return {
        ok: false, kind: KIND_ARCHIVE,
        reason: "checkpoint atRowHash does not match the bundle row at counter=" + anchorCounterN +
                " — the signed anchor does not bind this slice",
        expected: read.checkpoint.atRowHash,
        actual:   anchoredRow.rowHash,
      };
    }
  }

  return {
    ok:           true,
    kind:         read.manifest.kind,
    rowsVerified: read.rows.length,
    range:        read.manifest.range,
    manifest:     read.manifest,
    rows:         opts.includeRows ? read.rows : undefined,
  };
}

function _defaultVerifyCheckpointSignature(checkpoint) {
  // Use the locally-loaded audit-sign keypair. Auditors verifying an
  // archive on a different machine will need to pass opts.verifySignature
  // with their own loaded public key. The framework deliberately doesn't
  // ship public keys inside the bundle — the public key fingerprint in
  // the checkpoint row is the verifier's lookup key.
  try {
    var pub = auditSign.getPublicKey();
    var fp  = auditSign.getPublicKeyFingerprint();
    if (fp !== checkpoint.publicKeyFingerprint) return false;
    var payload = Buffer.from(
      "blamejs-audit-checkpoint-v1\n" +
      String(checkpoint.atMonotonicCounter) + "\n" +
      checkpoint.atRowHash + "\n" +
      String(checkpoint.createdAt),
      "utf8"
    );
    var sig = Buffer.isBuffer(checkpoint.signature) ? checkpoint.signature : Buffer.from(checkpoint.signature);
    return auditSign.verify(payload, sig, pub);
  } catch (_e) { return false; }
}

/**
 * @primitive b.auditTools.purge
 * @signature b.auditTools.purge(opts)
 * @since     0.7.30
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404
 * @related   b.auditTools.archive, b.auditTools.verifyBundle, b.audit.verify
 *
 * Confirmation-gated deletion of live audit rows already captured in
 * a verified archive bundle. Refuses unless `opts.confirm === true`,
 * the bundle verifies clean as `kind="archive"`, and the bundle's
 * `firstCounter` / `predecessorRowHash` match the next contiguous
 * purge point on disk. Inserts a `_blamejs_audit_purge_anchor` row
 * so `b.audit.verify()` keeps chaining post-purge — the anchor's
 * `lastPurgedRowHash` becomes the new chain origin.
 *
 * @opts
 *   confirm:          true,               // exact `true` required
 *   archive:          string,             // path to a verified archive bundle
 *   passphrase:       Buffer|string,      // bundle decryption passphrase
 *   verifySignature:  function(checkpoint),// auditor pubkey override
 *   dualControlGrant: object,             // required when audit_log is declared under b.db.declareRequireDualControl — from b.dualControl.consume({ action: "auditTools.purge" })
 *
 * @example
 *   var result = await b.auditTools.purge({
 *     confirm:    true,
 *     archive:    "/var/audit/2026-Q1.bundle",
 *     passphrase: process.env.AUDIT_BUNDLE_PASSPHRASE,
 *   });
 *   // → { purged: true, rowsDeleted: 14823, lastPurgedCounter: 14823, ... }
 */
async function purge(opts) {
  opts = opts || {};
  if (opts.confirm !== true) {
    throw new AuditToolsError("audit-tools/no-confirm",
      "purge: opts.confirm must be exactly true — destructive operation requires explicit acknowledgement");
  }
  if (typeof opts.archive !== "string") {
    throw new AuditToolsError("audit-tools/no-archive",
      "purge: opts.archive is required (path to a verified archive bundle)");
  }
  _requirePassphrase(opts.passphrase);

  // 1. Verify the archive bundle. Refuses with a clear reason if not ok.
  var v = await verifyBundle({
    in:         opts.archive,
    passphrase: opts.passphrase,
    verifySignature: opts.verifySignature, // auditor pubkey override
  });
  if (!v.ok) {
    throw new AuditToolsError("audit-tools/archive-not-ok",
      "purge: archive failed verification: " + v.reason);
  }
  if (v.kind !== KIND_ARCHIVE) {
    throw new AuditToolsError("audit-tools/wrong-kind",
      "purge: bundle kind is '" + v.kind + "', must be 'archive'");
  }

  // Dual-control gate. When audit_log is declared under
  // b.db.declareRequireDualControl, the physical purge requires a
  // consumed m-of-n grant — confirm:true alone is not enough. Mirrors
  // b.db.eraseHard, and additionally binds the grant's action so a
  // grant minted for a different operation can't be replayed here.
  var dcGate = _resolveDualControlGate(opts);
  if (dcGate) {
    var grant = opts.dualControlGrant;
    if (!grant) {
      _emitPurgeDenied(dcGate, "no-grant");
      throw new AuditToolsError("audit-tools/dual-control-required",
        "purge: audit_log is under dual control (m=" + dcGate.m + ", n=" + dcGate.n +
        "); pass opts.dualControlGrant from b.dualControl.consume({ action: \"" +
        AUDIT_LOG_PURGE_ACTION + "\" }).");
    }
    if (grant.ready !== true) {
      _emitPurgeDenied(dcGate, "grant-not-ready");
      throw new AuditToolsError("audit-tools/dual-control-grant-not-ready",
        "purge: opts.dualControlGrant.ready must be true (a consumed m-of-n grant)");
    }
    if (grant.action !== AUDIT_LOG_PURGE_ACTION) {
      _emitPurgeDenied(dcGate, "grant-action-mismatch");
      throw new AuditToolsError("audit-tools/dual-control-grant-mismatch",
        "purge: dualControlGrant.action is '" + grant.action + "', must be '" +
        AUDIT_LOG_PURGE_ACTION + "'");
    }
  }

  // 2 and 3, under one lock. Reading the anchor, deciding the new boundary is
  // contiguous with it, and writing that boundary are a single decision: split
  // them and two overlapping purges both read the same anchor, both find
  // themselves contiguous with it, and the second overwrites the first's
  // boundary with one that would have been refused had it been checked against
  // what was actually there. Rows past the surviving anchor are then gone with
  // nothing accounting for them, and — because the anchor is what licenses
  // absence — verification reports the result clean.
  //
  // The lock is the audit chain's own append lock, so appends are excluded for
  // the same span, which is also what keeps a row from linking to a hash the
  // anchor is about to replace.
  var readAnchor = opts.readAnchor || _defaultReadPurgeAnchor;
  var apply = opts.apply || _defaultApplyPurge;
  var applyArgs = {
    lastPurgedCounter:    Number(v.range.lastCounter),
    lastPurgedRowHash:    v.range.lastRowHash,
    archiveBundleId:      v.manifest.checkpoint && v.manifest.checkpoint.checkpointId
                          || ("manifest:" + v.range.lastCounter),
    purgedAt:             Date.now(),
  };

  var result = await audit().withChainLock(async function () {
    // The mutex above is this process's. In cluster mode that is not enough on
    // its own: two nodes could both read the same anchor, both find themselves
    // contiguous with it, and both delete and overwrite it, leaving a signed
    // boundary that does not account for everything that was removed.
    //
    // Appends already require leadership (chain-writer does this before every
    // row), so making the purge leader-only puts every writer of this chain on
    // one node, where the mutex orders them. Checked inside the lock so the
    // answer cannot go stale between the check and the deletion it guards.
    cluster.requireLeader();

    var anchor = await readAnchor();

    // The prior anchor has to be believed before it can be extended, and it is
    // believed HERE as well as at verify time, because extending it launders
    // it. Write an unsigned anchor carrying the real predecessor hash, wait for
    // a legitimate purge of the next archive, and that purge signs a boundary
    // that swallows the earlier deletion — permanently, under a valid
    // signature. The check that catches the forgery has to run before the
    // signature that would bless it.
    if (anchor) {
      var priorPolicy = _anchorVerifyOpts();
      var priorVerdict = auditChain.verifyPurgeAnchor(anchor, priorPolicy);
      if (!_anchorBelievable(priorVerdict, priorPolicy)) {
        throw new AuditToolsError("audit-tools/prior-anchor-not-verified",
          "purge: the existing purge anchor cannot be extended — " + priorVerdict.reason +
          ". Extending it would sign a boundary that covers whatever it already claims.");
      }
    }

    // Check the fence BEFORE anything is deleted. The anchor write is fenced
    // too, but that fires after `purgeAuditChain` has already removed the
    // rows — leaving them gone with the boundary still describing the previous
    // range. Reading the stored token first turns "deleted, then refused" into
    // "refused, nothing touched". The write-time fence stays as the
    // authoritative one: this read can go stale between here and there, and
    // only the database can decide the race it is in.
    if (anchor && Number(anchor.fencingToken || 0) > cluster.fencingToken()) {
      throw new AuditToolsError("audit-tools/fenced-out",
        "purge refused before deleting anything: the stored purge anchor carries " +
        "fencingToken=" + anchor.fencingToken + ", above this node's " +
        cluster.fencingToken() + " — a higher-token leader has superseded it.");
    }

    // Re-running the SAME archive against the boundary it already produced is
    // a retry, not a second purge. The anchor is written before the rows are
    // deleted, so a deletion that fails leaves exactly this state: the
    // boundary recorded, the rows still present and now skipped by
    // verification. Treating that as non-contiguous — which it is, read
    // literally — would make the only repair the operator has the one thing
    // the guard refuses, and the rows would stay hidden permanently.
    //
    // The archive has already been verified above, and the anchor it matches
    // was verified as this framework's own, so there is nothing an attacker
    // gains here: replaying an archive whose range is already purged deletes
    // rows that are already gone.
    var isRetryOfAnchoredRange = !!anchor &&
      Number(anchor.lastPurgedCounter) === Number(v.range.lastCounter) &&
      anchor.lastPurgedRowHash === v.range.lastRowHash;

    if (!isRetryOfAnchoredRange) {
      // Refuse if the archive doesn't start at the next purge point. Keeps the
      // chain anchor monotonic — operators can't jump-purge a middle range.
      var expectedFirstCounter = anchor ? Number(anchor.lastPurgedCounter) + 1 : 1;
      if (Number(v.range.firstCounter) !== expectedFirstCounter) {
        throw new AuditToolsError("audit-tools/non-monotonic-purge",
          "purge: archive's firstCounter=" + v.range.firstCounter +
          " does not match expected next-purge counter=" + expectedFirstCounter +
          " (purges must be contiguous from the chain origin or last anchor)");
      }
      if (anchor && v.range.predecessorRowHash !== anchor.lastPurgedRowHash) {
        throw new AuditToolsError("audit-tools/anchor-mismatch",
          "purge: archive's predecessorRowHash does not match the prior purge anchor's lastPurgedRowHash");
      }
    }

    // Sign before deleting. The signature is over data that is already
    // settled, so signing it later would buy nothing and risk everything: if
    // the key is unavailable at that point the rows are already gone and what
    // remains is an unsigned anchor over an unrecoverable deletion — the exact
    // state a reader is required to refuse. Failing here costs nothing; the
    // archive is on disk and the purge can be re-run.
    _signPurgeAnchorInto(applyArgs);

    return await apply(applyArgs);
  });

  return {
    purged:               true,
    rowsDeleted:          result.rowsDeleted,
    checkpointsDeleted:   result.checkpointsDeleted,
    lastPurgedCounter:    Number(v.range.lastCounter),
    lastPurgedRowHash:    v.range.lastRowHash,
    archiveBundleId:      result.archiveBundleId,
    dualControlConsumed:  !!dcGate,
  };
}

/**
 * @primitive b.auditTools.signExistingPurgeAnchor
 * @signature b.auditTools.signExistingPurgeAnchor()
 * @since     0.18.58
 * @status    stable
 * @related   b.auditChain.verifyPurgeAnchor, b.auditTools.purge
 *
 * Sign the purge anchor a previous version left unsigned, pinning the boundary
 * it already claims so it can never be moved again. Returns
 * `{ signed: false, reason }` when there is nothing to do — no anchor, an
 * anchor that is already signed, or a deployment running without audit
 * signing — and `{ signed: true, lastPurgedCounter, publicKeyFingerprint }`
 * when it wrote one.
 *
 * This is the upgrade path, and it exists because refusing an unsigned anchor
 * would otherwise strand the installation that has one: re-running the purge
 * is turned away by the contiguity guard, which requires an archive starting
 * one counter past the recorded boundary, and the boundary is exactly what is
 * in question. Reached through `b.db.init({ acceptUnsignedPurgeAnchor: true })`
 * once, after which the flag does nothing and should be removed.
 *
 * It pins what is already there rather than proving it. An operator who wants
 * the boundary PROVEN verifies the retained archive against the chain with
 * `b.auditTools.verifyBundle` before running this; nothing here can tell a
 * boundary a previous version wrote from one somebody else did, which is the
 * whole reason the signature exists.
 *
 * @example
 *   var r = await b.auditTools.signExistingPurgeAnchor();
 *   // → { signed: true, lastPurgedCounter: 4200, publicKeyFingerprint: "<hex>" }
 */
async function signExistingPurgeAnchor() {
  if (_purgeAnchorSigningDisabled()) {
    return { signed: false, reason: "audit signing is not configured" };
  }
  // Same critical section as purge, for the same reason: this reads an anchor,
  // decides it is the one to pin, and writes it back. A purge landing between
  // the read and the write would have its boundary silently replaced by the
  // older one being pinned here.
  return await audit().withChainLock(async function () {
    // Writes the anchor, so it belongs on the same node as every other writer
    // of this chain — see the purge path for why.
    cluster.requireLeader();

    var anchor = await _defaultReadPurgeAnchor();
    if (!anchor) return { signed: false, reason: "no purge anchor" };

    var verdict = auditChain.verifyPurgeAnchor(anchor, { allowUnsigned: true });
    if (verdict.status === "valid") {
      return { signed: false, reason: "purge anchor is already signed" };
    }
    if (verdict.status !== "unsigned") {
      // A corrupt or forged anchor is not something to pin. Signing it would
      // convert a detectable problem into a permanent one.
      throw new AuditToolsError("audit-tools/anchor-not-signable",
        "signExistingPurgeAnchor: " + verdict.reason);
    }

    var args = {
      lastPurgedCounter: Number(anchor.lastPurgedCounter),
      lastPurgedRowHash: anchor.lastPurgedRowHash,
      archiveBundleId:   String(anchor.archiveBundleId),
      purgedAt:          Number(anchor.purgedAt),
    };
    _signPurgeAnchorInto(args);
    await _writePurgeAnchor(args);
    return {
      signed:               true,
      lastPurgedCounter:    args.lastPurgedCounter,
      publicKeyFingerprint: args.publicKeyFingerprint,
    };
  });
}

// A deployment that opted out of audit signing (`b.db.init({ auditSigning:
// false })`) has no key to sign an anchor with. The writer has to allow exactly
// what the verifier allows, or purge throws for that configuration and the
// documented opt-out becomes an opt-out of purging too. `getMode()` reports
// null when signing was never initialized and never throws, so this reads the
// live posture rather than a flag that could disagree with it.
// Deliberately takes no argument. A caller-supplied opt-out would let a purge
// delete rows permanently and then write an anchor the same deployment refuses
// at its next boot, recoverable only through the legacy repair path — a
// security default behind a flag, and one whose cost lands after the rows are
// already gone. The live signing mode is the only thing that decides.
function _purgeAnchorSigningDisabled() {
  return auditSign.getMode() == null;
}

// The terms on which THIS deployment may believe an anchor, as settled at boot.
// Read rather than re-derived: an operation running after boot that works the
// answer out for itself will eventually disagree with the boot that let the
// process start, and the volume is then accepted at startup and refused an
// hour later by the next purge or archive.
function _anchorVerifyOpts() {
  var policy = audit().getPurgeAnchorPolicy();
  return {
    resolvePublicKey: policy.resolvePublicKey,
    allowUnsigned:    policy.allowUnsigned || _purgeAnchorSigningDisabled(),
    allowUnchecked:   policy.allowUnchecked,
  };
}

// Whether a verdict lets this deployment act on the anchor. One reading, so
// the purge path and the archive path cannot differ about it.
function _anchorBelievable(verdict, policy) {
  if (verdict.status === "valid") return true;
  if (verdict.status === "unsigned" && verdict.accepted) return true;
  return verdict.status === "unchecked" && policy.allowUnchecked === true;
}

// Attach the signature over the anchor's own fields. Mutates `args` so the
// signed bytes and the written row are built from one object — a second
// construction is a second chance for them to differ, and a signature over
// fields that are not the stored ones verifies nothing.
function _signPurgeAnchorInto(args) {
  if (_purgeAnchorSigningDisabled()) return args;
  args.scope = "audit";
  // The token is part of the signed bytes, so it has to be settled before the
  // signature rather than added by the writer afterwards — otherwise the row
  // stored and the row signed differ in the one field the fence turns on.
  if (args.fencingToken == null) args.fencingToken = cluster.fencingToken();
  args.signature = auditSign.sign(auditChain.purgeAnchorPayload(args));
  args.publicKeyFingerprint = auditSign.getPublicKeyFingerprint();
  return args;
}

async function _defaultReadPurgeAnchor() {
  // External-only table — its logical name IS the `_blamejs_`-prefixed name
  // (self-mapped in LOCAL_TO_EXTERNAL); b.sql receives it bare so
  // clusterStorage rewrites it. allow:hand-rolled-sql — bare logical key.
  var built = sql.select("_blamejs_audit_purge_anchor", _sqlOpts())   // allow:hand-rolled-sql
    .where("scope", "audit")
    .toSql();
  return clusterStorage.executeOne(built.sql, built.params);
}

// Runs inside the chain lock purge() holds — it does not take one itself, and
// must not: the lock is not reentrant, and the span that has to be indivisible
// starts at the anchor read, not here.
//
// The anchor is claimed BEFORE the rows are deleted, and the order is the
// whole point. The two writes cannot be one transaction — the deletion goes
// through the local database's trigger dance on a single node and through
// cluster-storage on a cluster — so one of them happens first, and the two
// orders fail differently:
//
//   delete first  — a fence refused afterwards (a leader superseded between
//                   the pre-check and here) leaves the rows gone with the
//                   boundary still describing the previous range. Nothing
//                   accounts for them, and nothing can: re-running the purge
//                   is refused as non-contiguous.
//   anchor first  — a fence refused means nothing was deleted at all. If the
//                   deletion then fails, the boundary claims rows that are
//                   still present, so verification skips rows it could have
//                   checked. That is a weaker guarantee about rows that still
//                   exist, rather than a missing account of rows that do not.
//
// The second is recoverable and the first is not, so the fence is claimed
// first and a failed deletion is reported as the specific state it leaves.
async function _defaultApplyPurge(args) {
  await _writePurgeAnchor(args);

  // Delete only what the anchor that SURVIVED licenses. Between the write
  // above and here, a higher-token leader can replace the row — including with
  // a smaller boundary — and this callback is already running with its own
  // larger one. Deleting that larger range would put rows outside the
  // surviving anchor, which is the single state nothing can account for
  // afterwards. Reading the boundary back and taking the lower of the two
  // makes the destructive step conditional on the row that is actually there.
  var surviving = await _defaultReadPurgeAnchor();
  var licensed = surviving ? Number(surviving.lastPurgedCounter) : -1;
  if (licensed < 0) {
    throw new AuditToolsError("audit-tools/anchor-vanished",
      "the purge anchor was removed between recording the boundary and deleting " +
      "the rows it covers; nothing was deleted.");
  }

  // The surviving anchor has to be the one this purge wrote. If a higher-token
  // leader replaced it in between, the boundary now in force is theirs, and
  // deleting through it would be correct while REPORTING this purge's range
  // would not: an operator told their range was purged may discard the archive
  // for it, and rows above the surviving boundary are still live. Refuse
  // rather than return a result that is true about the deletion and false
  // about what it covered.
  if (licensed !== Number(args.lastPurgedCounter) ||
      String(surviving.lastPurgedRowHash) !== String(args.lastPurgedRowHash)) {
    throw new AuditToolsError("audit-tools/anchor-superseded",
      "the purge anchor recorded at counter=" + args.lastPurgedCounter +
      " was replaced before its rows were deleted; the boundary now in force is " +
      licensed + ". Nothing was deleted by this call. Keep the archive — the " +
      "range it covers has not been purged — and reconcile against the anchor " +
      "the surviving leader wrote.");
  }
  var deleteThrough = Math.min(Number(args.lastPurgedCounter), licensed);

  var del;
  try {
    del = await db().purgeAuditChain({ lastPurgedCounter: deleteThrough });
  } catch (e) {
    throw new AuditToolsError("audit-tools/purge-incomplete",
      "the purge boundary at counter=" + args.lastPurgedCounter + " was recorded, " +
      "but deleting the rows it covers failed: " + ((e && e.message) || String(e)) +
      ". Those rows are still present and verification will skip them until they " +
      "are removed. Re-run this purge with the same archive once the cause is fixed.");
  }
  return {
    rowsDeleted:        del.rowsDeleted,
    checkpointsDeleted: del.checkpointsDeleted,
    archiveBundleId:    args.archiveBundleId,
  };
}

async function _writePurgeAnchor(args) {
  // UPSERT the single-row anchor via b.sql ON CONFLICT(scope) DO UPDATE
  // (SQLite + Postgres). The anchor is external-only; its logical name IS
  // the `_blamejs_`-prefixed name (self-mapped), passed bare so
  // clusterStorage rewrites + placeholderizes. b.sql quotes the camelCase
  // columns + binds 'audit'. allow:hand-rolled-sql — bare logical key.
  // Fenced, because leadership alone does not serialize this across nodes. A
  // superseded leader still holds a working handle, and during a handoff two
  // nodes can both believe they hold it — both read the same anchor, both find
  // themselves contiguous with it, and the later write replaces a boundary
  // that already accounted for rows it does not cover. The stored token is the
  // only thing that can say whose turn it is; a write below it is refused by
  // the database rather than by agreement between processes.
  //
  // Every column the signature covers is written together. Leaving one behind
  // would pair a new boundary with an old signature, which reads as a forgery
  // — correctly, since that row is not what anyone signed.
  // Settled by _signPurgeAnchorInto when signing is on, so the signed bytes
  // and the stored row carry the same token. With signing off there is no
  // signature to agree with and the live token is taken directly.
  var fencingToken = args.fencingToken == null ? cluster.fencingToken() : args.fencingToken;
  var fence = await clusterStorage.fencedUpsert({
    table:      "_blamejs_audit_purge_anchor",   // allow:hand-rolled-sql — bare logical key
    keyColumns: ["scope"],
    label:      "auditTools.writePurgeAnchor",
    // The BOUNDARY is fenced as well as the token, because a boundary may only
    // ever advance. Without that, a leader holding a higher token could lower
    // it — legitimately, by its own lights, purging a smaller range — while
    // another node was midway through deleting a larger one, and the rows
    // above the surviving boundary would then be gone with nothing accounting
    // for them. Which is precisely the state the anchor exists to make
    // impossible. Enforced by the database, so no ordering between the two
    // nodes has to be reasoned about.
    fenceColumns: ["fencingToken", "lastPurgedCounter"],
    values: {
      scope:             "audit",
      lastPurgedCounter: args.lastPurgedCounter,
      lastPurgedRowHash: args.lastPurgedRowHash,
      archiveBundleId:   args.archiveBundleId,
      purgedAt:          args.purgedAt,
      // Null under `auditSigning: false`, which the reader accepts only for a
      // deployment configured that way.
      signature:            args.signature == null ? null : args.signature,
      publicKeyFingerprint: args.publicKeyFingerprint == null ? null : args.publicKeyFingerprint,
      fencingToken:         fencingToken,
    },
  });
  if (fence.fenced) {
    throw new AuditToolsError("audit-tools/fenced-out",
      "purge anchor write rejected: fencingToken=" + fencingToken +
      " is below the stored token — a higher-token leader has superseded this " +
      "node. The rows for this range may already be deleted; do not re-run the " +
      "purge from here, and reconcile against the anchor the surviving leader wrote.");
  }
  // The boundary just changed. Whatever the chain writer cached about where an
  // emptied chain resumes is now the previous answer — and the purge that just
  // ran is very likely the thing that emptied it.
  audit().invalidateChainOrigin();
}

/**
 * @primitive b.auditTools.forensicSnapshot
 * @signature b.auditTools.forensicSnapshot(opts)
 * @since     0.8.40
 * @compliance hipaa, pci-dss, gdpr, soc2, sox-404, dora, nis2
 * @related   b.auditTools.exportSlice, b.auditTools.archive
 *
 * Post-compromise composer that bundles an audit slice (from
 * `since` → now) plus operator-supplied incident metadata
 * (incidentId, reason, actor) and runtime fingerprint (Node version
 * / platform / pid / uptime) into a single tamper-evident artifact
 * for legal / regulators / the IR team. Emits an
 * `audit.forensic_snapshot.composed` audit event so the act of
 * composing the snapshot is itself on-chain.
 *
 * Pass `returnBytes: true` instead of `out` for the snapshot as an
 * in-memory `{ filename: Buffer }` map (the slice's `rows.enc` +
 * `manifest.json` plus `forensic-snapshot.json`) — the read-only /
 * serverless path. `out` and `returnBytes` are mutually exclusive.
 *
 * @opts
 *   out:        string,               // fresh directory path (omit when returnBytes)
 *   returnBytes:boolean,              // true → return { ...manifest, files } in memory, no disk
 *   since:      number|Date|string,   // include rows recordedAt >= this (windowed since → now)
 *   passphrase: Buffer|string,        // bundle-encryption passphrase
 *   reason:     string,               // required incident-context reason
 *   incidentId: string,               // optional ticket / incident id
 *   actor:      { id, role },         // optional incident-commander identity
 *
 * @example
 *   var snap = await b.auditTools.forensicSnapshot({
 *     out:        "/forensics/2026-05-08-inc-42",
 *     since:      Date.now() - 7 * 24 * 60 * 60 * 1000,
 *     passphrase: process.env.AUDIT_BUNDLE_PASSPHRASE,
 *     incidentId: "inc-2026-05-08-42",
 *     reason:     "ATO investigation: 14 failed MFA from new geo, user u-42",
 *     actor:      { id: "alice@ops.example.com", role: "incident-commander" },
 *   });
 *   // → { snapshotKind: "forensic", incidentId: "inc-2026-05-08-42", ... }
 */
async function forensicSnapshot(opts) {
  opts = opts || {};
  _requirePassphrase(opts.passphrase);
  var returnBytes = opts.returnBytes === true;
  if (returnBytes && opts.out !== undefined) {
    throw new AuditToolsError("audit-tools/out-and-return-bytes",
      "forensicSnapshot: specify either opts.out (write to disk) or opts.returnBytes (in-memory bytes), not both");
  }
  if (!returnBytes) _requireOutDir(opts.out, "forensicSnapshot");
  var sinceMs = _toMs(opts.since);
  if (sinceMs == null) {
    throw new AuditToolsError("audit-tools/no-since",
      "forensicSnapshot: opts.since is required");
  }
  validateOpts.requireNonEmptyString(opts.reason, "reason", AuditToolsError, "audit-tools/no-reason");
  // exportSlice windows by from/to — pass the requested `since` as `from`
  // and now as `to` so the snapshot captures only the incident window
  // rather than the entire audit history.
  var sliceResult = await exportSlice({
    out:         returnBytes ? undefined : opts.out,
    returnBytes: returnBytes,
    from:        sinceMs,
    to:          Date.now(),
    passphrase:  opts.passphrase,
    readRows:    opts.readRows,
    readCoveringCheckpoint: opts.readCoveringCheckpoint,
  });
  // Compose snapshot manifest with operator-supplied IR context. The
  // audit slice lands as rows.enc inside the bundle either way.
  var manifest = {
    snapshotKind:      "forensic",
    incidentId:        opts.incidentId || null,
    reason:            opts.reason,
    actor:             opts.actor || null,
    composedAt:        new Date().toISOString(),
    auditSliceFile:    returnBytes ? frameworkFiles.fileName("rowsEnc") : (sliceResult && sliceResult.manifestPath),
    auditSliceCount:   sliceResult && sliceResult.rowCount,
    runtime: {
      nodeVersion: process.version,
      platform:    process.platform,
      arch:        process.arch,
      pid:         process.pid,
      uptimeSec:   Math.round(process.uptime()),
    },
  };
  var manifestBytes = Buffer.from(_canonicalize(manifest), "utf8");
  var manifestPath = null;
  if (!returnBytes) {
    manifestPath = nodePath.join(opts.out, "forensic-snapshot.json");
    atomicFile.writeSync(manifestPath, manifestBytes, { fileMode: 0o600 });
  }
  try {
    require("./audit").safeEmit({
      action:  "audit.forensic_snapshot.composed",
      outcome: "success",
      metadata: {
        out:               returnBytes ? null : opts.out,
        incidentId:        manifest.incidentId,
        reason:            opts.reason,
        actor:             opts.actor || null,
        rowCount:          manifest.auditSliceCount || 0,
      },
    });
  } catch (_e) { /* audit best-effort */ }
  if (returnBytes) {
    // Mirror the on-disk layout: the slice's files plus the IR wrapper.
    var files = Object.assign({}, sliceResult.files);
    files["forensic-snapshot.json"] = manifestBytes;
    return Object.assign({}, manifest, { files: files });
  }
  return Object.assign({}, manifest, { manifestPath: manifestPath });
}

// CADF (Cloud Auditing Data Federation, DMTF DSP0262) is the
// OpenStack/FedRAMP-tier cloud-audit envelope auditors increasingly
// expect for federated tooling (cross-tenant SIEM, CSP reporting).
//
// We map blamejs audit fields onto CADF attributes:
//
//   blamejs                CADF
//   ---------------------- ----------------------------------
//   _id                    eventid (UUID-ish)
//   action                 action (typed verb namespace)
//   outcome                outcome (success | failure | unknown | pending)
//   actorUserId            initiator.id (typed via initiator.typeURI)
//   resourceKind+resourceId target.id + target.typeURI
//   recordedAt             eventTime (ISO-8601)
//   reason                 reason.reasonCode + reason.policyType
//   metadata               attachments[] (operator-supplied free-form)
//   prevHash/rowHash       observer.id link to chain anchor
//
// CADF requires every event to declare its observer (the auditing
// system). We declare blamejs as the observer with a typeURI of
// service/audit. The framework version pins observer.id so an auditor
// can correlate envelope-level events back to a deployment.
function _toCadfOutcome(outcome) {
  if (outcome === "success") return "success";
  if (outcome === "failure" || outcome === "denied") return "failure";
  if (outcome === "warning") return "unknown";
  return outcome || "unknown";
}

function _toCadfEvent(row) {
  var meta = null;
  if (row.metadata) {
    try { meta = typeof row.metadata === "string" ? safeJson.parse(row.metadata) : row.metadata; }
    catch (_e) { meta = { raw: String(row.metadata) }; }
  }
  var ev = {
    typeURI:   "http://schemas.dmtf.org/cloud/audit/1.0/event",
    eventType: "activity",
    id:        row._id,
    eventTime: new Date(Number(row.recordedAt)).toISOString(),
    action:    row.action,
    outcome:   _toCadfOutcome(row.outcome),
    initiator: {
      id:      row.actorUserIdHash || row.actorUserId || "unknown",
      typeURI: "service/security/account/user",
      addresses: row.actorIp ? [{ url: row.actorIp, name: "actorIp" }] : undefined,
      name:    row.actorSessionId || undefined,
    },
    target: {
      id:      row.resourceIdHash || row.resourceId || row.resourceKind || "n/a",
      typeURI: row.resourceKind ? ("service/storage/" + row.resourceKind) : "service/security",
    },
    observer: {
      id:      "blamejs:" + (pkg.version || "unknown"),
      typeURI: "service/security/audit",
      name:    "blamejs.audit",
    },
    reason: row.reason ? {
      reasonCode: String(row.reason).slice(0, 256),                                // reason cap
      policyType: "blamejs.audit-chain",
    } : undefined,
    attachments: meta ? [{
      contentType: "application/json",
      content:     JSON.stringify(meta),
      name:        "blamejs.metadata",
    }] : undefined,
    // Custom CADF extension — anchors back into the audit chain.
    "blamejs:chain": {
      monotonicCounter: Number(row.monotonicCounter),
      prevHash:         row.prevHash,
      rowHash:          row.rowHash,
    },
  };
  return ev;
}

/**
 * @primitive b.auditTools.exportCadf
 * @signature b.auditTools.exportCadf(opts)
 * @since     0.7.30
 * @compliance soc2, pci-dss, gdpr
 * @related   b.auditTools.exportAudit, b.auditTools.exportSlice
 *
 * Format an audit slice as a CADF event-batch (Cloud Auditing Data
 * Federation, DMTF DSP0262) — the FedRAMP / OpenStack
 * envelope cross-tenant SIEMs and CSP reporting tools expect for
 * federated tooling. Maps blamejs fields onto CADF attributes
 * (initiator / target / observer / outcome / reason) and embeds a
 * `blamejs:chain` extension carrying `monotonicCounter` / prevHash /
 * rowHash so auditors can correlate the envelope back to the chain.
 *
 * Returns an object with `events: [...]` ready to ship as JSON.
 *
 * @opts
 *   format:   "cadf",                // optional — defaults to "cadf"
 *   from:     number|Date|string,    // recordedAt >= this
 *   to:       number|Date|string,    // recordedAt <= this
 *   action:   string,                // exact action filter
 *
 * @example
 *   var batch = await b.auditTools.exportCadf({
 *     from:   "2026-05-01T00:00:00Z",
 *     to:     "2026-05-08T00:00:00Z",
 *     action: "auth.login",
 *   });
 *   // → { typeURI: ".../event-batch", framework: "blamejs", events: [...] }
 */
async function exportCadf(opts) {
  opts = opts || {};
  if (opts.format !== undefined && opts.format !== "cadf") {
    throw new AuditToolsError("audit-tools/bad-format",
      "audit.export: format must be 'cadf' for exportCadf");
  }
  var fromMs = _toMs(opts.from);
  var toMs   = _toMs(opts.to);
  var readRows = opts.readRows || _defaultReadRows;
  var criteria = {};
  if (fromMs != null) criteria.fromMs = fromMs;
  if (toMs   != null) criteria.toMs   = toMs;
  if (opts.action) criteria.action = opts.action;
  var rows = await readRows(criteria);
  var events = new Array(rows.length);
  for (var i = 0; i < rows.length; i++) {
    events[i] = _toCadfEvent(rows[i]);
  }
  return {
    typeURI:        "http://schemas.dmtf.org/cloud/audit/1.0/event-batch",
    framework:      "blamejs",
    frameworkVersion: pkg.version,
    range: {
      from: fromMs != null ? new Date(fromMs).toISOString() : null,
      to:   toMs   != null ? new Date(toMs).toISOString()   : null,
    },
    events: events,
  };
}

// Operator-facing dispatcher — `b.audit.export({ format })`. Future
// formats register here.
/**
 * @primitive b.auditTools.exportAudit
 * @signature b.auditTools.exportAudit(opts)
 * @since     0.7.30
 * @compliance soc2, pci-dss, gdpr
 * @related   b.auditTools.exportCadf, b.auditTools.exportSlice
 *
 * Format dispatcher for downstream-SIEM exports. Reads `opts.format`
 * (default `"cadf"`) and delegates to the matching formatter. Future
 * envelope formats (CEF / OCSF / etc.) register here so callers stay
 * on a stable signature even when the framework adds formats.
 *
 * @opts
 *   format:   "cadf",                // selector — defaults to "cadf"
 *   from:     number|Date|string,    // recordedAt >= this
 *   to:       number|Date|string,    // recordedAt <= this
 *   action:   string,                // exact action filter
 *
 * @example
 *   var batch = await b.auditTools.exportAudit({
 *     format: "cadf",
 *     from:   "2026-05-01T00:00:00Z",
 *     to:     "2026-05-08T00:00:00Z",
 *   });
 *   // → { typeURI: ".../event-batch", framework: "blamejs", events: [...] }
 */
async function exportAudit(opts) {
  opts = opts || {};
  var format = opts.format || "cadf";
  if (format === "cadf") return await exportCadf(opts);
  throw new AuditToolsError("audit-tools/bad-format",
    "audit.export: format must be one of: cadf (got '" + format + "')");
}

module.exports = {
  archive:           archive,
  exportSlice:       exportSlice,
  exportAudit:       exportAudit,
  exportCadf:        exportCadf,
  forensicSnapshot:  forensicSnapshot,
  verifyBundle:      verifyBundle,
  purge:             purge,
  signExistingPurgeAnchor: signExistingPurgeAnchor,
  withRecordedAtIso: withRecordedAtIso,
  BUNDLE_FORMAT:    BUNDLE_FORMAT,
  KIND_ARCHIVE:     KIND_ARCHIVE,
  KIND_EXPORT:      KIND_EXPORT,
  AuditToolsError:  AuditToolsError,
};
