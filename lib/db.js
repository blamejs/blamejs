"use strict";
/**
 * Database orchestrator — encrypted-at-rest SQLite backed by node:sqlite.
 *
 * At-rest modes (default 'encrypted' per modernity stance; 'plain' is opt-out
 * only and emits a console warning at boot):
 *
 *   encrypted (default):
 *     - DB file lives in tmpfs (/dev/shm by default; configurable via
 *       db.init({ tmpDir }) or BLAMEJS_TMPDIR env var) at runtime.
 *     - On boot: <dataDir>/db.enc → decrypt → tmpDir/blamejs-<token>.db
 *     - Periodic re-encrypt every 5 minutes back to <dataDir>/db.enc.
 *     - On shutdown: final encrypt + remove plaintext from tmpfs.
 *     - DB encryption key sealed by vault, persisted at <dataDir>/db.key.enc.
 *     - Refuses to boot if neither a tmpDir nor /dev/shm is available.
 *
 *   plain (opt-out):
 *     - DB file lives directly at <dataDir>/db (plain SQLite on disk).
 *     - No periodic encryption. Field-level encryption (field-crypto.js)
 *       still protects sealed columns, but schema and row counts are visible.
 *     - Boot warning printed.
 *
 * Public API:
 *
 *   await db.init({
 *     dataDir,                         // required — where db.enc + db.key.enc live
 *     tmpDir,                          // optional — override (default /dev/shm)
 *     atRest: 'encrypted' | 'plain',   // default 'encrypted'
 *     schema: [ { name, columns, indexes, sealedFields, derivedHashes }, ... ],
 *     migrationDir,                    // optional — path to ./migrations/ (run-once)
 *   });
 *
 *   db.from(tableName)                 → Query (chainable)
 *   db.prepare(sql)                    → SQLite Statement (raw escape hatch)
 *   db.runSql(sql)                     → raw SQL execution (DDL, BEGIN/COMMIT)
 *   db.transaction(function (db) {…})  → wraps in BEGIN/COMMIT/ROLLBACK
 *   db.hashFor(table, field, value)    → derived-hash lookup helper
 *   db.close()                         → final encrypt + close (idempotent)
 */
var fs = require("fs");
var path = require("path");
var { DatabaseSync } = require("node:sqlite");
var vault = require("./vault");
var fieldCrypto = require("./field-crypto");
var { Query } = require("./db-query");
var dbSchema = require("./db-schema");
var { generateToken, generateBytes, encryptPacked, decryptPacked, sha3Hash } = require("./crypto");
var C = require("./constants");

var runSql = dbSchema.runSql;

// Module-local state, populated by init()
var database  = null;       // the SQLite handle
var dbPath    = null;       // plaintext DB file path (tmpfs in encrypted mode, dataDir/db in plain mode)
var encPath   = null;       // encrypted-at-rest path (null in plain mode)
var encKey    = null;       // 32-byte DB encryption key (null in plain mode)
var encTimer  = null;       // periodic encrypt interval handle
var atRest    = null;       // 'encrypted' or 'plain'
var dataDir   = null;
var initialized = false;
var dataResidency = null;   // operator's declared region config (validated by storage backends)
var subjectTables = [];     // [{ name, subjectField, personalDataCategories }] — for subject.export/erase

// ---- Framework-baked tables ----
//
// audit_log + consent_log + _blamejs_subject_restrictions + _blamejs_subject_erasures
// are provisioned by the framework before app schema reconciles. Apps cannot
// opt out, override, or rename them. An app schema entry colliding with any of
// these names is refused at init.
var RESERVED_TABLE_NAMES = new Set([
  "audit_log",
  "consent_log",
  "_blamejs_subject_restrictions",
  "_blamejs_subject_erasures",
  "_blamejs_migrations",
  "_blamejs_counters",
]);

var FRAMEWORK_SCHEMA = [
  {
    name: "audit_log",
    columns: {
      _id:               "TEXT PRIMARY KEY",
      recordedAt:        "INTEGER NOT NULL",
      monotonicCounter:  "INTEGER NOT NULL",
      actorUserId:       "TEXT",
      actorUserIdHash:   "TEXT",
      actorIp:           "TEXT",
      actorUserAgent:    "TEXT",
      actorSessionId:    "TEXT",
      action:            "TEXT NOT NULL",
      resourceKind:      "TEXT",
      resourceId:        "TEXT",
      resourceIdHash:    "TEXT",
      outcome:           "TEXT NOT NULL",
      reason:            "TEXT",
      metadata:          "TEXT",
      requestId:         "TEXT",
      prevHash:          "TEXT NOT NULL",
      rowHash:           "TEXT NOT NULL",
      nonce:             "BLOB NOT NULL",
    },
    indexes: [
      "actorUserIdHash", "resourceIdHash", "recordedAt", "action",
      { name: "idx_audit_monotonic", columns: "monotonicCounter", unique: true },
    ],
    sealedFields:  ["actorUserId", "actorIp", "actorUserAgent", "actorSessionId", "resourceId", "reason", "metadata"],
    derivedHashes: {
      actorUserIdHash: { from: "actorUserId" },
      resourceIdHash:  { from: "resourceId" },
    },
  },
  {
    name: "consent_log",
    columns: {
      _id:               "TEXT PRIMARY KEY",
      recordedAt:        "INTEGER NOT NULL",
      monotonicCounter:  "INTEGER NOT NULL",
      subjectId:         "TEXT NOT NULL",
      subjectIdHash:     "TEXT NOT NULL",
      purpose:           "TEXT NOT NULL",
      lawfulBasis:       "TEXT NOT NULL",
      action:            "TEXT NOT NULL",
      scope:             "TEXT",
      channel:           "TEXT NOT NULL",
      evidenceRef:       "TEXT",
      prevHash:          "TEXT NOT NULL",
      rowHash:           "TEXT NOT NULL",
      nonce:             "BLOB NOT NULL",
    },
    indexes: [
      "subjectIdHash", "recordedAt", "purpose",
      { name: "idx_consent_monotonic", columns: "monotonicCounter", unique: true },
    ],
    sealedFields:  ["subjectId", "scope", "evidenceRef"],
    derivedHashes: {
      subjectIdHash: { from: "subjectId" },
    },
  },
  {
    name: "_blamejs_subject_restrictions",
    columns: {
      subjectIdHash: "TEXT PRIMARY KEY",
      since:         "INTEGER NOT NULL",
      reason:        "TEXT",
    },
    sealedFields: ["reason"],
  },
  {
    name: "_blamejs_subject_erasures",
    columns: {
      subjectIdHash: "TEXT PRIMARY KEY",
      erasedAt:      "INTEGER NOT NULL",
    },
  },
];

function log(msg) { console.log("[blamejs:db] " + msg); }
function logErr(msg) { console.error("[blamejs:db] " + msg); }

// ---- Tmpfs detection ----

function resolveTmpDir(optsTmpDir) {
  if (optsTmpDir) return optsTmpDir;
  if (process.env.BLAMEJS_TMPDIR) return process.env.BLAMEJS_TMPDIR;
  if (fs.existsSync("/dev/shm")) return "/dev/shm";
  return null;
}

// ---- DB encryption key management ----

function loadOrCreateDbKey(dataDirPath) {
  var keyPath = path.join(dataDirPath, "db.key.enc");
  if (fs.existsSync(keyPath)) {
    var sealed = fs.readFileSync(keyPath, "utf8").trim();
    var b64 = vault.unseal(sealed);
    if (!b64) {
      logErr("FATAL: db.key.enc unseal returned empty — vault may not be initialized or key file corrupted");
      process.exit(1);
    }
    return Buffer.from(b64, "base64");
  }
  // First run — generate, seal, persist
  var raw = generateBytes(32);
  var sealedKey = vault.seal(raw.toString("base64"));
  fs.writeFileSync(keyPath, sealedKey, { mode: 0o600 });
  log("generated DB encryption key at " + keyPath);
  return raw;
}

function decryptToTmp() {
  if (!encPath || !fs.existsSync(encPath)) return;
  // If a plaintext file already exists in tmpfs from a prior process, prefer
  // the newer mtime (crash recovery — operator's most recent state wins).
  if (fs.existsSync(dbPath)) {
    var plainStat = fs.statSync(dbPath);
    var encStat = fs.statSync(encPath);
    if (plainStat.mtimeMs > encStat.mtimeMs && plainStat.size > 0) {
      log("plaintext is newer than encrypted — keeping plaintext (crash recovery)");
      return;
    }
  }
  var packed = fs.readFileSync(encPath);
  if (packed.length < 26) return; // too short to be a valid envelope
  fs.writeFileSync(dbPath, decryptPacked(packed, encKey));
}

function encryptToDisk() {
  if (!encPath) return;
  // Force WAL checkpoint so the .db file holds all committed transactions.
  try { runSql(database, "PRAGMA wal_checkpoint(TRUNCATE)"); } catch (_e) { /* best effort */ }
  if (!fs.existsSync(dbPath)) return;
  fs.writeFileSync(encPath, encryptPacked(fs.readFileSync(dbPath), encKey));
}

// Remove the plaintext DB + WAL/SHM sidecar files. On Windows these can't be
// unlinked while the SQLite handle is open, so this MUST be called after
// database.close().
function removePlaintextFiles() {
  if (!dbPath) return;
  try { fs.unlinkSync(dbPath); } catch (_e) { /* cleanup */ }
  try { fs.unlinkSync(dbPath + "-wal"); } catch (_e) { /* cleanup */ }
  try { fs.unlinkSync(dbPath + "-shm"); } catch (_e) { /* cleanup */ }
}

// Clean up stale plaintext DB files left by previously-crashed processes.
// Anything matching blamejs-*.db that isn't our current process's file is
// stale (no other process should write to /dev/shm with our prefix).
function cleanStaleTmpDbs(tmpDir) {
  try {
    var entries = fs.readdirSync(tmpDir);
    for (var i = 0; i < entries.length; i++) {
      var f = entries[i];
      if (!f.startsWith("blamejs-") || !f.endsWith(".db")) continue;
      var full = path.join(tmpDir, f);
      if (full === dbPath) continue;
      try { fs.unlinkSync(full); } catch (_e) { /* concurrent cleanup */ }
      try { fs.unlinkSync(full + "-wal"); } catch (_e) { /* may not exist */ }
      try { fs.unlinkSync(full + "-shm"); } catch (_e) { /* may not exist */ }
    }
  } catch (_e) { /* tmpDir may not exist on first run */ }
}

// ---- Init dispatch ----

async function init(opts) {
  if (initialized) return;
  if (!opts || !opts.dataDir) {
    throw new Error("db.init({ dataDir }) is required");
  }
  if (!Array.isArray(opts.schema)) {
    throw new Error("db.init({ schema }) must be an array of table definitions");
  }

  atRest = (opts.atRest || "encrypted").toLowerCase();
  if (atRest !== "encrypted" && atRest !== "plain") {
    throw new Error("db.init: atRest must be 'encrypted' or 'plain', got: " + opts.atRest);
  }
  dataDir = opts.dataDir;
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

  if (atRest === "encrypted") {
    var tmpDir = resolveTmpDir(opts.tmpDir);
    if (!tmpDir) {
      logErr("FATAL: atRest: 'encrypted' (default) requires tmpfs but none was found.");
      logErr("  Provide opts.tmpDir or set BLAMEJS_TMPDIR, or pass atRest: 'plain' (with warning).");
      process.exit(1);
    }
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });

    encPath = path.join(dataDir, "db.enc");
    dbPath  = path.join(tmpDir, "blamejs-" + generateToken(16) + ".db");
    encKey  = loadOrCreateDbKey(dataDir);

    cleanStaleTmpDbs(tmpDir);
    decryptToTmp();
  } else {
    // plain mode
    console.warn(
      "[blamejs:db] WARNING: atRest: 'plain' — DB structure and row counts visible on disk.\n" +
      "             Field-level encryption (sealedFields) still protects sealed columns,\n" +
      "             but the simpler at-rest model is opt-out only. Default is 'encrypted'."
    );
    dbPath = path.join(dataDir, "blamejs.db");
    encPath = null;
    encKey = null;
  }

  // Open the database
  database = new DatabaseSync(dbPath);

  // Performance pragmas (same tuning as HermitStash precedent)
  runSql(database, "PRAGMA journal_mode=WAL");
  runSql(database, "PRAGMA synchronous=NORMAL");
  runSql(database, "PRAGMA cache_size=-8000");
  runSql(database, "PRAGMA temp_store=MEMORY");
  runSql(database, "PRAGMA busy_timeout=5000");
  runSql(database, "PRAGMA mmap_size=268435456");
  runSql(database, "PRAGMA auto_vacuum=INCREMENTAL");

  // Refuse app schema entries that collide with framework-reserved names
  for (var ri = 0; ri < opts.schema.length; ri++) {
    if (RESERVED_TABLE_NAMES.has(opts.schema[ri].name)) {
      throw new Error(
        "table name '" + opts.schema[ri].name + "' is reserved by the framework. " +
        "Pick a different name (the framework provisions audit_log, consent_log, " +
        "and _blamejs_* tables automatically)."
      );
    }
  }

  // Track subject schema for subject.export/erase walks
  subjectTables = [];
  for (var si = 0; si < opts.schema.length; si++) {
    var st = opts.schema[si];
    if (st.subjectField) {
      subjectTables.push({
        name:                   st.name,
        subjectField:           st.subjectField,
        personalDataCategories: st.personalDataCategories || {},
      });
    }
  }

  // Build the full schema = framework-baked tables + app tables.
  // Framework tables come FIRST so audit_log/consent_log exist before any
  // app migration can reference them.
  var fullSchema = FRAMEWORK_SCHEMA.concat(opts.schema);

  // Register schema with field-crypto (framework tables included)
  for (var i = 0; i < fullSchema.length; i++) {
    var t = fullSchema[i];
    fieldCrypto.registerTable(t.name, {
      sealedFields:   t.sealedFields,
      derivedHashes:  t.derivedHashes,
      hashNamespaces: t.hashNamespaces,
    });
  }

  // Declarative schema reconcile (framework + app tables)
  dbSchema.reconcile(database, fullSchema);

  // Imperative migrations (run once each, in order)
  if (opts.migrationDir) {
    var result = dbSchema.runMigrations(database, opts.migrationDir);
    if (result.applied.length > 0) {
      log("applied " + result.applied.length + " migration(s): " + result.applied.join(", "));
    }
  }

  // dataResidency — operator's declared region. Stored for downstream backends
  // (storage, mail, log destinations) to validate against in subsequent phases.
  // No backends to validate against in v0.0.4; the value is registered for use.
  dataResidency = opts.dataResidency || null;

  // Mark initialized BEFORE the chain verify so audit/consent.verify() can
  // call db.prepare() through the public surface. If verify fails, we
  // process.exit() — initialized state is moot at that point.
  initialized = true;

  // ---- Refuse-to-boot on chain break (per Q1=A) ----
  // Verify both the audit and consent chains end-to-end. A broken chain
  // means tamper-evidence has been compromised — the framework refuses
  // to continue under any circumstances. Operators with chain-recovery
  // tooling (Phase 7) will be able to recover; v0.0.4 ships detect-and-fail.
  var audit = require("./audit");
  var consent = require("./consent");
  var auditResult = audit.verify();
  if (!auditResult.ok) {
    logErr("FATAL: audit_log chain integrity broken at row " + auditResult.breakAt + " (" + auditResult.reason + ")");
    logErr("  break row _id: " + auditResult.breakRowId);
    logErr("  expected: " + auditResult.expected);
    logErr("  actual:   " + auditResult.actual);
    logErr("Refusing to boot. Compliance requires that any tamper-detection signal halt service.");
    logErr("(Phase 7 will provide a recovery CLI; for now, restore from backup or rebuild the audit chain manually.)");
    process.exit(1);
  }
  var consentResult = consent.verify();
  if (!consentResult.ok) {
    logErr("FATAL: consent_log chain integrity broken at row " + consentResult.breakAt + " (" + consentResult.reason + ")");
    logErr("  break row _id: " + consentResult.breakRowId);
    logErr("Refusing to boot.");
    process.exit(1);
  }
  log("audit chain ok (" + auditResult.rowsVerified + " rows), consent chain ok (" + consentResult.rowsVerified + " rows)");

  // Start periodic encrypt timer (encrypted mode only)
  if (atRest === "encrypted") {
    encTimer = setInterval(function () {
      try { encryptToDisk(); } catch (e) {
        logErr("periodic encrypt failed: " + e.message);
      }
    }, C.TIME.FIVE_MIN);
    encTimer.unref();

    // Final encrypt on process exit. We don't try to unlink the plaintext
    // here — the SQLite handle may still be open, and the OS reclaims tmpfs
    // on reboot anyway. close() does the orderly shutdown.
    process.on("exit", function () {
      try { encryptToDisk(); } catch (_e) { /* exit handler — silent */ }
    });
  }

  log("ready (mode: " + atRest + ", path: " + dbPath + ")");
}

// ---- Public API ----

function from(tableName) {
  _requireInit();
  return new Query(database, tableName);
}

function prepare(sql) {
  _requireInit();
  return database.prepare(sql);
}

function execRaw(sql) {
  _requireInit();
  return runSql(database, sql);
}

function transaction(fn) {
  _requireInit();
  if (typeof fn !== "function") throw new Error("transaction requires a function");
  runSql(database, "BEGIN");
  try {
    var result = fn(module.exports);
    runSql(database, "COMMIT");
    return result;
  } catch (e) {
    try { runSql(database, "ROLLBACK"); } catch (_e) { /* ignore — already error */ }
    throw e;
  }
}

function hashFor(table, field, value) {
  _requireInit();
  var lookup = fieldCrypto.lookupHash(table, field, value);
  return lookup ? lookup.value : null;
}

function close() {
  if (!initialized) return;
  if (encTimer) {
    clearInterval(encTimer);
    encTimer = null;
  }
  // Order: encrypt while the DB is still open (so the file is consistent),
  // then close the SQLite handle (releases the file lock on Windows),
  // THEN unlink the plaintext sidecar files.
  try { encryptToDisk(); } catch (e) {
    logErr("close: final encrypt failed: " + e.message);
  }
  try { database.close(); } catch (_e) { /* already closed */ }
  if (atRest === "encrypted") removePlaintextFiles();
  database = null;
  initialized = false;
}

function _requireInit() {
  if (!initialized) {
    throw new Error("db.init() must be awaited before using db API");
  }
}

// Test helpers — not part of public contract
function _resetForTest() {
  if (encTimer) { clearInterval(encTimer); encTimer = null; }
  try { if (database) database.close(); } catch (_e) {}
  database = null;
  dbPath = null;
  encPath = null;
  encKey = null;
  atRest = null;
  dataDir = null;
  initialized = false;
  fieldCrypto.clearForTest();
}

module.exports = {
  init:                init,
  from:                from,
  prepare:             prepare,
  runSql:              execRaw,
  transaction:         transaction,
  hashFor:             hashFor,
  close:               close,
  // Diagnostic accessors
  getMode:             function () { return atRest; },
  getDbPath:           function () { return dbPath; },
  getDataResidency:    function () { return dataResidency; },
  // Internal accessors used by audit / subject / consent modules.
  // Not part of the public contract — apps should not depend on them.
  _getSubjectTables:   function () { return subjectTables.slice(); },
  RESERVED_TABLE_NAMES: RESERVED_TABLE_NAMES,
  FRAMEWORK_SCHEMA:    FRAMEWORK_SCHEMA,
  // Testing
  _resetForTest:       function () {
    _resetForTest();
    subjectTables = [];
    dataResidency = null;
    // Cascade reset to chain-stateful modules so a fresh init() works.
    try { require("./audit")._resetForTest(); } catch (_e) {}
    try { require("./consent")._resetForTest(); } catch (_e) {}
    try { require("./subject")._resetForTest(); } catch (_e) {}
  },
};
