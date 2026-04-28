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
var atomicFile = require("./atomic-file");
var audit = require("./audit");
var auditSign = require("./audit-sign");
var cluster = require("./cluster");
var events = require("./events");
var consent = require("./consent");
var C = require("./constants");
var { generateToken, generateBytes, encryptPacked, decryptPacked, sha3Hash } = require("./crypto");
var cryptoField = require("./crypto-field");
var { Query } = require("./db-query");
var dbSchema = require("./db-schema");
var { createLogger } = require("./logger");
var safeEnv = require("./parsers/safe-env");
var safeJson = require("./safe-json");
var vault = require("./vault");

var AUDIT_TIP_SCHEMA = {
  type: "object",
  required: ["atMonotonicCounter"],
  properties: {
    atMonotonicCounter: { type: "number" },
    rowHash:            { type: "string" },
    signedAt:           { type: "string" },
  },
};

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
var tableMetadata = {};     // table name → metadata snapshot (PK/FK/sealed/derived) for getTableMetadata

// ---- Framework-baked tables ----
//
// audit_log + consent_log + _blamejs_subject_restrictions + _blamejs_subject_erasures
// are provisioned by the framework before app schema reconciles. Apps cannot
// opt out, override, or rename them. An app schema entry colliding with any of
// these names is refused at init.
var RESERVED_TABLE_NAMES = new Set([
  "audit_log",
  "audit_checkpoints",
  "consent_log",
  "_blamejs_subject_restrictions",
  "_blamejs_subject_erasures",
  "_blamejs_sessions",
  "_blamejs_jobs",
  "_blamejs_migrations",
  "_blamejs_counters",
  "_blamejs_audit_purge_anchor",
  "_blamejs_scheduler_ticks",
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
      fencingToken:      "INTEGER NOT NULL DEFAULT 0",
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
      fencingToken:      "INTEGER NOT NULL DEFAULT 0",
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
  {
    name: "audit_checkpoints",
    columns: {
      _id:                  "TEXT PRIMARY KEY",
      createdAt:            "INTEGER NOT NULL",
      atMonotonicCounter:   "INTEGER NOT NULL",
      atRowHash:            "TEXT NOT NULL",
      signature:            "BLOB NOT NULL",
      publicKeyFingerprint: "TEXT NOT NULL",
      fencingToken:         "INTEGER NOT NULL DEFAULT 0",
    },
    indexes: [
      "createdAt",
      { name: "idx_chkpt_counter", columns: "atMonotonicCounter", unique: true },
    ],
    sealedFields: [],
  },
  {
    name: "_blamejs_audit_purge_anchor",
    columns: {
      scope:             "TEXT PRIMARY KEY",
      lastPurgedCounter: "INTEGER NOT NULL",
      lastPurgedRowHash: "TEXT NOT NULL",
      archiveBundleId:   "TEXT NOT NULL",
      purgedAt:          "INTEGER NOT NULL",
    },
    sealedFields: [],
  },
  {
    // Scheduler exactly-once-globally claim table. Each fire claims a
    // (name, scheduledAtUnix) row before dispatching; UNIQUE on the
    // composite tickKey (name + ":" + scheduledAtUnix) means a concurrent
    // leader's INSERT loses with a constraint violation, and that node
    // skips the tick. Closes the once-globally gap during cluster
    // leader hand-offs where two leaders briefly coexist.
    name: "_blamejs_scheduler_ticks",
    columns: {
      tickKey:         "TEXT PRIMARY KEY",
      name:            "TEXT NOT NULL",
      scheduledAtUnix: "INTEGER NOT NULL",
      claimedAtUnix:   "INTEGER NOT NULL",
      claimedBy:       "TEXT",
    },
    indexes: ["scheduledAtUnix"],
    sealedFields: [],
  },
  {
    name: "_blamejs_sessions",
    columns: {
      sidHash:       "TEXT PRIMARY KEY",
      userId:        "TEXT NOT NULL",
      userIdHash:    "TEXT NOT NULL",
      data:          "TEXT",
      createdAt:     "INTEGER NOT NULL",
      expiresAt:     "INTEGER NOT NULL",
      lastActivity:  "INTEGER NOT NULL",
    },
    indexes: ["userIdHash", "expiresAt"],
    sealedFields:  ["userId", "data"],
    derivedHashes: { userIdHash: { from: "userId" } },
  },
  {
    name: "_blamejs_jobs",
    columns: {
      _id:             "TEXT PRIMARY KEY",
      queueName:       "TEXT NOT NULL",
      payload:         "TEXT",
      status:          "TEXT NOT NULL",
      enqueuedAt:      "INTEGER NOT NULL",
      availableAt:     "INTEGER NOT NULL",
      leasedAt:        "INTEGER",
      leaseExpiresAt:  "INTEGER",
      attempts:        "INTEGER NOT NULL DEFAULT 0",
      maxAttempts:     "INTEGER NOT NULL DEFAULT 5",
      lastError:       "TEXT",
      finishedAt:      "INTEGER",
      traceId:         "TEXT",
      classification:  "TEXT",
    },
    indexes: [
      { name: "idx_jobs_lease",    columns: ["queueName", "status", "availableAt"] },
      "leaseExpiresAt",
      "finishedAt",
    ],
    sealedFields:  ["payload", "lastError"],
  },
];

var log = createLogger("db");

// ---- Tmpfs detection ----

function resolveTmpDir(optsTmpDir) {
  if (optsTmpDir) return optsTmpDir;
  var envTmp = safeEnv.readVar("BLAMEJS_TMPDIR");
  if (envTmp) return envTmp;
  if (fs.existsSync("/dev/shm")) return "/dev/shm";
  return null;
}

// ---- DB encryption key management ----

function loadOrCreateDbKey(dataDirPath) {
  var keyPath = path.join(dataDirPath, "db.key.enc");
  if (fs.existsSync(keyPath)) {
    var sealed = atomicFile.readSync(keyPath, { encoding: "utf8" }).trim();
    var b64 = vault.unseal(sealed);
    if (!b64) {
      log.error("FATAL: db.key.enc unseal returned empty — vault may not be initialized or key file corrupted");
      process.exit(1);
    }
    return Buffer.from(b64, "base64");
  }
  // First run — generate, seal, persist (atomic)
  var raw = generateBytes(32);
  var sealedKey = vault.seal(raw.toString("base64"));
  atomicFile.writeSync(keyPath, sealedKey, { fileMode: 0o600 });
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
  atomicFile.writeSync(dbPath, decryptPacked(packed, encKey));
}

function encryptToDisk() {
  if (!encPath) return;
  // Force WAL checkpoint so the .db file holds all committed transactions.
  try { runSql(database, "PRAGMA wal_checkpoint(TRUNCATE)"); } catch (_e) { /* best effort */ }
  if (!fs.existsSync(dbPath)) return;
  atomicFile.writeSync(encPath, encryptPacked(fs.readFileSync(dbPath), encKey));
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
  var entries = atomicFile.listDir(tmpDir, {
    filter: function (name) { return name.startsWith("blamejs-") && name.endsWith(".db"); },
  });
  for (var i = 0; i < entries.length; i++) {
    var full = entries[i].fullPath;
    if (full === dbPath) continue;
    try { fs.unlinkSync(full); } catch (_e) { /* concurrent cleanup */ }
    try { fs.unlinkSync(full + "-wal"); } catch (_e) { /* may not exist */ }
    try { fs.unlinkSync(full + "-shm"); } catch (_e) { /* may not exist */ }
  }
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
      log.error("FATAL: atRest: 'encrypted' (default) requires tmpfs but none was found.");
      log.error("  Provide opts.tmpDir or set BLAMEJS_TMPDIR, or pass atRest: 'plain' (with warning).");
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
    log.warn("WARNING: atRest: 'plain' — DB structure and row counts visible on disk.");
    log.warn("         Field-level encryption (sealedFields) still protects sealed columns,");
    log.warn("         but the simpler at-rest model is opt-out only. Default is 'encrypted'.");
    dbPath = path.join(dataDir, "blamejs.db");
    encPath = null;
    encKey = null;
  }

  // Open the database
  database = new DatabaseSync(dbPath);

  // Performance pragmas
  runSql(database, "PRAGMA journal_mode=WAL");
  runSql(database, "PRAGMA synchronous=NORMAL");
  runSql(database, "PRAGMA cache_size=-8000");
  runSql(database, "PRAGMA temp_store=MEMORY");
  runSql(database, "PRAGMA busy_timeout=5000");
  runSql(database, "PRAGMA mmap_size=268435456");
  runSql(database, "PRAGMA auto_vacuum=INCREMENTAL");
  // Foreign-key enforcement is OFF by default in SQLite. Turn it ON so
  // structured `foreignKeys` declarations actually constrain writes.
  runSql(database, "PRAGMA foreign_keys=ON");

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

  // Register schema with field-crypto + capture table metadata snapshot
  // (framework tables included so getTableMetadata covers everything).
  tableMetadata = {};
  for (var i = 0; i < fullSchema.length; i++) {
    var t = fullSchema[i];
    cryptoField.registerTable(t.name, {
      sealedFields:   t.sealedFields,
      derivedHashes:  t.derivedHashes,
      hashNamespaces: t.hashNamespaces,
    });
    tableMetadata[t.name] = {
      primaryKey:             _normalizePk(t),
      foreignKeys:            Array.isArray(t.foreignKeys) ? t.foreignKeys.slice() : [],
      columns:                Object.assign({}, t.columns),
      indexes:                Array.isArray(t.indexes) ? t.indexes.slice() : [],
      sealedFields:           Array.isArray(t.sealedFields) ? t.sealedFields.slice() : [],
      derivedHashes:          Object.assign({}, t.derivedHashes || {}),
      subjectField:           t.subjectField || null,
      personalDataCategories: Object.assign({}, t.personalDataCategories || {}),
    };
  }

  // Declarative schema reconcile (framework + app tables)
  dbSchema.reconcile(database, fullSchema);

  // Append-only enforcement on audit_log + consent_log via SQLite triggers.
  // Apps cannot UPDATE or DELETE these tables; the framework's audit.record /
  // consent.grant only INSERT. This is a SQL-level guard against bug-induced
  // or malicious tampering — independent of the API surface's discipline.
  // Operator-driven retention purge (when implemented) must drop these
  // triggers explicitly inside a transaction, perform the purge, and
  // recreate them.
  _installAppendOnlyTriggers(database);

  // Imperative migrations (run once each, in order)
  if (opts.migrationDir) {
    var result = dbSchema.runMigrations(database, opts.migrationDir);
    if (result.applied.length > 0) {
      log("applied " + result.applied.length + " migration(s): " + result.applied.join(", "));
    }
  }

  // dataResidency — operator's declared region. Registered here for
  // downstream backends (storage, mail, log destinations) to validate
  // against; backends opt in by reading this value via getDataResidency().
  dataResidency = opts.dataResidency || null;

  // Mark initialized BEFORE the chain verify so audit/consent.verify() can
  // call db.prepare() through the public surface. If verify fails, we
  // process.exit() — initialized state is moot at that point.
  initialized = true;

  // ---- Refuse-to-boot on chain break ----
  // Verify both the audit and consent chains end-to-end. A broken chain
  // means tamper-evidence has been compromised — the framework refuses
  // to continue under any circumstances. Recovery is operator-driven
  // (restore from backup or manual chain rebuild); the framework only
  // detects-and-fails.
  var auditResult = await audit.verify();
  if (!auditResult.ok) {
    log.error("FATAL: audit_log chain integrity broken at row " + auditResult.breakAt + " (" + auditResult.reason + ")");
    log.error("  break row _id: " + auditResult.breakRowId);
    log.error("  expected: " + auditResult.expected);
    log.error("  actual:   " + auditResult.actual);
    log.error("Refusing to boot. Compliance requires that any tamper-detection signal halt service.");
    log.error("Recovery is manual: restore from backup, or rebuild the audit chain from a verified earlier snapshot.");
    // Fire the breach event BEFORE exit so operator listeners get one
    // last chance at sync I/O (file flag, console alert) before the
    // process is gone.
    events.emit(events.EVENTS.AUDIT_CHAIN_BREAK, { table: "audit_log", result: auditResult });
    process.exit(1);
  }
  var consentResult = await consent.verify();
  if (!consentResult.ok) {
    log.error("FATAL: consent_log chain integrity broken at row " + consentResult.breakAt + " (" + consentResult.reason + ")");
    log.error("  break row _id: " + consentResult.breakRowId);
    log.error("Refusing to boot.");
    events.emit(events.EVENTS.AUDIT_CHAIN_BREAK, { table: "consent_log", result: consentResult });
    process.exit(1);
  }
  log("audit chain ok (" + auditResult.rowsVerified + " rows), consent chain ok (" + consentResult.rowsVerified + " rows)");

  // ---- Rollback detection (audit.tip sidecar) ----
  // The framework writes <dataDir>/audit.tip on each checkpoint. At boot we
  // compare current MAX(monotonicCounter) to the recorded tip. If current
  // is BELOW tip — the DB was rolled back to an older snapshot. Refuse boot.
  _checkRollback(dataDir);

  // ---- Audit-signing key + checkpoint subsystem ----
  // Default mode 'wrapped' (passphrase-required, separate from vault). Apps
  // that want a quick-start dev path can pass auditSigning: { mode: 'plaintext' }
  // — same warning pattern as vault.
  // opts.auditSigning.algorithm picks the keypair algorithm at first-run
  // generation. Default = SLH-DSA-SHAKE-256f (matches the framework's
  // SHAKE-family hash posture); ML-DSA-87 is the throughput-focused
  // opt-in. Existing key files take their algorithm from disk; this
  // option only matters on first generation.
  var auditSigningMode = (opts.auditSigning && opts.auditSigning.mode)
    ? opts.auditSigning.mode
    : safeEnv.readVar("BLAMEJS_AUDIT_SIGNING_MODE", {
        default: "wrapped",
        enum:    ["wrapped", "plaintext"],
      });
  var auditSigningAlg = opts.auditSigning && opts.auditSigning.algorithm
    ? opts.auditSigning.algorithm
    : null;
  await auditSign.init({
    dataDir:   dataDir,
    mode:      auditSigningMode,
    algorithm: auditSigningAlg || undefined,
  });

  // Verify all existing checkpoint signatures (defense against signature
  // forgery attempt + key-rotation gone wrong). Refuse to boot on failure.
  var ckptResult = await audit.verifyCheckpoints();
  if (!ckptResult.ok) {
    log.error("FATAL: audit checkpoint verification failed at row " +
      ckptResult.breakAt + " (" + ckptResult.reason + ")");
    log.error("  checkpoint _id: " + ckptResult.checkpointId);
    log.error("Refusing to boot. Either the audit-signing key was rotated " +
      "without retaining the prior pubkey, or a forged checkpoint was inserted.");
    events.emit(events.EVENTS.AUDIT_CHECKPOINT_BREAK, { result: ckptResult });
    process.exit(1);
  }
  log("audit checkpoints ok (" + ckptResult.checkpointsVerified + " signed)");

  // Anchor a fresh checkpoint at boot if there's any new audit activity
  // since the last checkpoint (else no-op).
  await audit.checkpoint({ skipIfUnchanged: true });

  // ---- NTP drift check ----
  // Best-effort; unreachable NTP doesn't fail boot, but >= 1hr drift does
  // (unless BLAMEJS_NTP_STRICT=0 / BLAMEJS_SKIP_NTP_CHECK=1).
  await _runNtpBootCheck(opts);

  // Start periodic encrypt timer (encrypted mode only)
  if (atRest === "encrypted") {
    encTimer = setInterval(function () {
      try { encryptToDisk(); } catch (e) {
        log.error("periodic encrypt failed: " + e.message);
      }
    }, C.TIME.minutes(5));
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
  var lookup = cryptoField.lookupHash(table, field, value);
  return lookup ? lookup.value : null;
}

function close() {
  if (!initialized) return;
  if (encTimer) {
    clearInterval(encTimer);
    encTimer = null;
  }
  // Best-effort final checkpoint before shutdown so the audit.tip sidecar
  // anchors the most recent state. Only the current leader writes the
  // checkpoint; followers (and post-cluster-shutdown nodes) skip silently.
  if (cluster.isLeader()) {
    // Fire-and-forget. close() stays sync so callers don't have to
    // await it across the test/shutdown lifecycle. Operators who need
    // a guaranteed-flushed checkpoint should call audit.checkpoint()
    // explicitly before invoking close().
    audit.checkpoint({ skipIfUnchanged: true }).catch(function (e) {
      log.error("close: final checkpoint failed: " + e.message);
    });
  }
  // Order: encrypt while the DB is still open (so the file is consistent),
  // then close the SQLite handle (releases the file lock on Windows),
  // THEN unlink the plaintext sidecar files.
  try { encryptToDisk(); } catch (e) {
    log.error("close: final encrypt failed: " + e.message);
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

// Normalize the primary-key declaration. Accepts an explicit `primaryKey`
// property OR derives from inline "PRIMARY KEY" in the column DDL string.
function _normalizePk(tableSpec) {
  if (tableSpec.primaryKey) {
    return Array.isArray(tableSpec.primaryKey) ? tableSpec.primaryKey.slice() : [tableSpec.primaryKey];
  }
  var inline = [];
  for (var col in tableSpec.columns) {
    if (/PRIMARY\s+KEY/i.test(tableSpec.columns[col])) inline.push(col);
  }
  return inline; // empty array if none declared (rowid PK)
}

// Install BEFORE-DELETE / BEFORE-UPDATE triggers on audit_log + consent_log
// that RAISE(ABORT) the operation. INSERT remains permitted (that's what
// audit.record / consent.grant do).
function _installAppendOnlyTriggers(database) {
  var tables = ["audit_log", "consent_log", "audit_checkpoints"];
  for (var i = 0; i < tables.length; i++) {
    var t = tables[i];
    runSql(database,
      'CREATE TRIGGER IF NOT EXISTS "no_delete_' + t + '" ' +
      'BEFORE DELETE ON "' + t + '" ' +
      'BEGIN ' +
      "  SELECT RAISE(ABORT, '" + t + " is append-only — DELETE prohibited'); " +
      'END'
    );
    runSql(database,
      'CREATE TRIGGER IF NOT EXISTS "no_update_' + t + '" ' +
      'BEFORE UPDATE ON "' + t + '" ' +
      'BEGIN ' +
      "  SELECT RAISE(ABORT, '" + t + " is append-only — UPDATE prohibited'); " +
      'END'
    );
  }
}

// Read the audit.tip sidecar file in dataDir and compare to the current
// audit_log MAX(monotonicCounter). Refuse boot on rollback (current < tip).
function _checkRollback(dataDirPath) {
  var tipPath = path.join(dataDirPath, "audit.tip");
  if (!fs.existsSync(tipPath)) {
    log("no audit.tip sidecar — skipping rollback check (first boot or operator-cleared)");
    return;
  }
  var tip;
  try {
    tip = safeJson.parse(atomicFile.readSync(tipPath), { schema: AUDIT_TIP_SCHEMA });
  } catch (e) {
    log.error("FATAL: audit.tip unreadable or schema-invalid at " + tipPath + " — " + e.message);
    log.error("Either delete it (forfeits rollback protection until next checkpoint) " +
      "or restore from operator backup.");
    process.exit(1);
  }
  var current = database.prepare("SELECT MAX(monotonicCounter) AS m FROM audit_log").get();
  var currentMax = current && current.m ? current.m : 0;
  if (currentMax < tip.atMonotonicCounter) {
    log.error("FATAL: audit-log rollback detected.");
    log.error("  audit.tip recorded counter: " + tip.atMonotonicCounter);
    log.error("  current DB max counter:     " + currentMax);
    log.error("Either the DB was restored from an older snapshot, or audit_log " +
      "rows have been deleted. Investigate before continuing.");
    events.emit(events.EVENTS.AUDIT_ROLLBACK_DETECTED, {
      tipCounter:    tip.atMonotonicCounter,
      currentMax:    currentMax,
      tipPath:       tipPath,
    });
    process.exit(1);
  }
  log("rollback check ok (tip counter " + tip.atMonotonicCounter +
    ", current " + currentMax + ")");
}

// Run an SNTP boot-time clock-drift check. Synchronous-from-the-init's-view:
// init() is async so we can `await` here. Severity policy:
//   info     → log line, continue
//   warning  → log warning, continue (audit-log it)
//   fatal    → log fatal, exit(1) — audit-log the attempt before exit
async function _runNtpBootCheck(opts) {
  if (safeEnv.readVar("BLAMEJS_SKIP_NTP_CHECK", { default: "" }) === "1") return;
  var ntpCheck;
  try { ntpCheck = require("./ntp-check"); }
  catch (_e) { return; /* module not present — skip silently */ }

  var result;
  try {
    result = await ntpCheck.bootCheck({
      servers:   opts && opts.ntpServers,
      timeoutMs: opts && opts.ntpTimeoutMs,
    });
  } catch (e) {
    log.error("ntp boot check threw unexpectedly: " + e.message + " (continuing)");
    return;
  }

  if (result.severity === "info") {
    log("ntp: " + result.message);
  } else if (result.severity === "warning") {
    log.error("ntp warning: " + result.message);
    events.emit(events.EVENTS.NTP_DRIFT, {
      severity: "warning",
      driftMs:  result.driftMs,
      server:   result.server,
      message:  result.message,
    });
  } else if (result.severity === "fatal") {
    log.error("FATAL: ntp clock drift exceeds threshold: " + result.message);
    events.emit(events.EVENTS.NTP_DRIFT, {
      severity: "fatal",
      driftMs:  result.driftMs,
      server:   result.server,
      message:  result.message,
    });
    if (safeEnv.readVar("BLAMEJS_NTP_STRICT", { default: "1" }) !== "0") {
      log.error("Refuse to boot. Investigate NTP / RTC / container time sync.");
      log.error("Override: BLAMEJS_NTP_STRICT=0 to continue (NOT recommended for production).");
      process.exit(1);
    }
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
  cryptoField.clearForTest();
}

module.exports = {
  init:                init,
  from:                from,
  prepare:             prepare,
  runSql:              execRaw,
  transaction:         transaction,
  hashFor:             hashFor,
  close:               close,
  // flushToDisk — force the live tmpfs SQLite to be re-encrypted to
  // <dataDir>/db.enc immediately. In encrypted-at-rest mode the
  // framework already does this every ~5 min and at clean shutdown,
  // but operators running a backup need a freshly-flushed db.enc as
  // the snapshot source. Safe to call any time; no-op when no encPath
  // (plain mode) or when the plaintext DB doesn't exist.
  flushToDisk:         encryptToDisk,
  // purgeAuditChain — narrow-purpose DELETE for audit-tools.purge.
  // Drops the BEFORE-DELETE append-only trigger inside a transaction,
  // executes the deletion, then re-installs the trigger so the
  // append-only invariant resumes. Cluster mode delegates to
  // cluster-storage (no triggers in external-db).
  //
  //   await b.db.purgeAuditChain({ lastPurgedCounter: N })
  //     → { rowsDeleted, checkpointsDeleted }
  //
  // Caller is responsible for verifying purge legitimacy (audit-tools
  // does this via verifyBundle before invoking).
  purgeAuditChain:     async function (args) {
    var lastPurgedCounter = Number(args && args.lastPurgedCounter);
    if (!Number.isFinite(lastPurgedCounter) || lastPurgedCounter < 0) {
      throw new Error("purgeAuditChain: lastPurgedCounter must be a non-negative number");
    }
    var c = require("./cluster");
    if (c.isClusterMode()) {
      // External-db has no append-only triggers; ordinary DELETE works.
      var cs = require("./cluster-storage");
      var d = await cs.execute(
        "DELETE FROM audit_log WHERE monotonicCounter <= ?", [lastPurgedCounter]
      );
      var dc = await cs.execute(
        "DELETE FROM audit_checkpoints WHERE atMonotonicCounter <= ?", [lastPurgedCounter]
      );
      return { rowsDeleted: d.rowCount || 0, checkpointsDeleted: dc.rowCount || 0 };
    }
    // Single-node: drop triggers, delete, recreate triggers — all in
    // one transaction so a crash mid-operation doesn't leave the
    // table writable to general code.
    var rowsDeleted = 0;
    var checkpointsDeleted = 0;
    transaction(function () {
      runSql(database, 'DROP TRIGGER IF EXISTS "no_delete_audit_log"');
      runSql(database, 'DROP TRIGGER IF EXISTS "no_delete_audit_checkpoints"');
      var d = database.prepare(
        "DELETE FROM audit_log WHERE monotonicCounter <= ?"
      ).run(lastPurgedCounter);
      rowsDeleted = (d && d.changes) || 0;
      var dc = database.prepare(
        "DELETE FROM audit_checkpoints WHERE atMonotonicCounter <= ?"
      ).run(lastPurgedCounter);
      checkpointsDeleted = (dc && dc.changes) || 0;
      _installAppendOnlyTriggers(database);
    });
    return { rowsDeleted: rowsDeleted, checkpointsDeleted: checkpointsDeleted };
  },
  // Diagnostic accessors
  getMode:             function () { return atRest; },
  getDbPath:           function () { return dbPath; },
  getDataResidency:    function () { return dataResidency; },
  // Reflective metadata: PK columns, FK relationships, sealed/derived fields,
  // subject mapping. Useful for tooling, RoPA generation, and admin dashboards.
  // Returns a deep-copied snapshot; mutations don't affect framework state.
  getTableMetadata:    function (name) {
    if (!name) return JSON.parse(JSON.stringify(tableMetadata));
    var m = tableMetadata[name];
    return m ? JSON.parse(JSON.stringify(m)) : null;
  },
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
    tableMetadata = {};
    // Cascade reset to stateful modules so a fresh init() works.
    try { require("./audit")._resetForTest(); }      catch (_e) {}
    try { require("./consent")._resetForTest(); }    catch (_e) {}
    try { require("./subject")._resetForTest(); }    catch (_e) {}
    try { require("./session")._resetForTest(); }    catch (_e) {}
    try { require("./storage")._resetForTest(); }    catch (_e) {}
    try { require("./audit-sign")._resetForTest(); } catch (_e) {}
    try { require("./queue")._resetForTest(); } catch (_e) {}
    try { require("./log-stream")._resetForTest(); } catch (_e) {}
    try { require("./redact")._resetForTest(); } catch (_e) {}
    try { require("./external-db")._resetForTest(); } catch (_e) {}
  },
  // Helper for audit.checkpoint to write the rollback-detection sidecar
  _writeAuditTip: function (tip) {
    if (!dataDir) return;
    var tipPath = path.join(dataDir, "audit.tip");
    atomicFile.writeSync(tipPath, JSON.stringify(tip, null, 2), { fileMode: 0o600 });
  },
};
