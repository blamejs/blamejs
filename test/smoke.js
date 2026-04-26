"use strict";
/**
 * Smoke test — orchestrator + Layer 0–5 test invocations.
 *
 * Run: `npm test` (or `node test/smoke.js`)
 *
 * Tests run in dependency order (per
 * .claude/memory/feedback_test_dependency_order.md):
 *
 *   Layer 0 — pure primitives
 *   Layer 1 — framework-state-dependent but isolated
 *   Layer 2 — needs db
 *   Layer 3 — uses db + chain-writer + cluster-storage
 *   Layer 4 — uses audit (consumer modules)
 *   Layer 5 — operator-facing integration
 *
 * Shared infrastructure (b binding, check(), setup/teardown helpers,
 * fake drivers, mock req/res, cluster-gate fixture) lives in
 * test/_helpers.js. This file currently keeps test FUNCTION
 * DEFINITIONS inline — they will move to per-layer files
 * (test/00-primitives.js, test/10-state.js, ...) in subsequent
 * v0.1.16+ commits.
 */
var assert = require("assert");
var helpers = require("./_helpers");
var b           = helpers.b;
var fs          = helpers.fs;
var os          = helpers.os;
var path        = helpers.path;
var check       = helpers.check;
var setupTestDb = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var setupTestDbForMW = helpers.setupTestDbForMW;
var teardownMW       = helpers.teardownMW;
var _makeFakeDriver         = helpers._makeFakeDriver;
var _makeSqliteDriver       = helpers._makeSqliteDriver;
var _makeFakeServiceAccount = helpers._makeFakeServiceAccount;
var _mockReq                = helpers._mockReq;
var _mockRes                = helpers._mockRes;
var _setupClusterGateFixture = helpers._setupClusterGateFixture;
var _expectNotLeaderError    = helpers._expectNotLeaderError;

// Layer-file imports (populated incrementally; see commit log v0.1.16+)
var primitivesLayer = require("./00-primitives");
var stateLayer      = require("./10-state");
var dbLayer         = require("./20-db");
var chainLayer      = require("./30-chain");
var consumersLayer  = require("./40-consumers");

console.log("blamejs v" + b.version + " — smoke test");

// =====================================================================
// Phase 0 — crypto + router + constants
// =====================================================================

// 1. Public API surface
check("crypto namespace present",     typeof b.crypto === "object");
check("router namespace present",     typeof b.router === "object");
check("constants namespace present",  typeof b.constants === "object");
check("vault namespace present",      typeof b.vault === "object");
check("vaultWrap namespace present",  typeof b.vaultWrap === "object");
check("passphraseSource present",     typeof b.passphraseSource === "object");
check("version is a string",          typeof b.version === "string");
check("version matches package.json", b.version === require("../package.json").version);

// 2. Constants surface
check("ENVELOPE_MAGIC = 0xE1",        b.constants.ENVELOPE_MAGIC === 0xE1);
check("ACTIVE.KEM is hybrid",         b.constants.ACTIVE.KEM === b.constants.KEM_IDS.ML_KEM_1024_P384);
check("ACTIVE.CIPHER is XChaCha20",   b.constants.ACTIVE.CIPHER === b.constants.CIPHER_IDS.XCHACHA20_POLY1305);
check("ACTIVE.KDF is SHAKE256",       b.constants.ACTIVE.KDF === b.constants.KDF_IDS.SHAKE256);
check("TIME.days(1) = 86400000",      b.constants.TIME.days(1) === 86400000);
check("TIME.minutes(45) = 2700000",   b.constants.TIME.minutes(45) === 2700000);
check("TIME.hours(2) = 7200000",      b.constants.TIME.hours(2) === 7200000);
check("BYTES.mib(64) = 67108864",     b.constants.BYTES.mib(64) === 67108864);
check("BYTES.kib(4) = 4096",          b.constants.BYTES.kib(4) === 4096);
check("TLS prefers PQ hybrid first",  b.constants.TLS_GROUP_PREFERENCE[0] === "SecP384r1MLKEM1024");

// 3. Envelope encrypt/decrypt round-trip
var keys = b.crypto.generateEncryptionKeyPair();
check("encryption keypair has all four members",
      typeof keys.publicKey === "string" && typeof keys.privateKey === "string" &&
      typeof keys.ecPublicKey === "string" && typeof keys.ecPrivateKey === "string");

var plaintext = "hello blamejs " + b.version + " 🔐";
var envelope = b.crypto.encrypt(plaintext, keys);
check("encrypt() returns base64 string",     typeof envelope === "string");

var decrypted = b.crypto.decrypt(envelope, keys);
check("decrypt() round-trip preserves UTF-8", decrypted === plaintext);

// 4. Envelope header bytes match active algorithm IDs
var envBytes = Buffer.from(envelope, "base64");
check("envelope byte 0 = magic",         envBytes[0] === b.constants.ENVELOPE_MAGIC);
check("envelope byte 1 = active KEM",    envBytes[1] === b.constants.ACTIVE.KEM);
check("envelope byte 2 = active cipher", envBytes[2] === b.constants.ACTIVE.CIPHER);
check("envelope byte 3 = active KDF",    envBytes[3] === b.constants.ACTIVE.KDF);

// 5. Tampered envelope fails to decrypt
var tampered = Buffer.from(envelope, "base64");
tampered[tampered.length - 1] ^= 0x01;
var tamperedRejected = false;
try { b.crypto.decrypt(tampered.toString("base64"), keys); }
catch (_) { tamperedRejected = true; }
check("tampered envelope is rejected", tamperedRejected);

// 6. Wrong-key decrypt fails
var otherKeys = b.crypto.generateEncryptionKeyPair();
var wrongKeyRejected = false;
try { b.crypto.decrypt(envelope, otherKeys); }
catch (_) { wrongKeyRejected = true; }
check("wrong-key decrypt is rejected", wrongKeyRejected);

// 7. timingSafeEqual
check("timingSafeEqual matches identical",      b.crypto.timingSafeEqual("foo", "foo"));
check("timingSafeEqual rejects different",      !b.crypto.timingSafeEqual("foo", "bar"));
check("timingSafeEqual rejects length-mismatch", !b.crypto.timingSafeEqual("foo", "foobar"));

// 8. Token / random bytes
check("generateToken default = 64 hex chars (32 bytes)",  b.crypto.generateToken().length === 64);
check("generateBytes returns 16 bytes",                   b.crypto.generateBytes(16).length === 16);

// 9. SHA3-512 hash determinism
var h1 = b.crypto.sha3Hash("blamejs");
var h2 = b.crypto.sha3Hash("blamejs");
check("sha3Hash is deterministic",            h1 === h2);
check("sha3Hash is 128 hex chars (512 bits)", h1.length === 128);

// 10. Symmetric buffer encrypt/decrypt round-trip
var symKey = b.crypto.generateBytes(32);
var bufPlain = Buffer.from("symmetric round-trip", "utf8");
var bufPacked = b.crypto.encryptPacked(bufPlain, symKey);
check("encryptPacked produces non-empty buffer", bufPacked.length > 0);
check("encryptPacked starts with format byte 0x02", bufPacked[0] === b.constants.FORMAT.XCHACHA20_POLY1305);
var bufRoundTripped = b.crypto.decryptPacked(bufPacked, symKey);
check("decryptPacked round-trip preserves bytes", bufRoundTripped.equals(bufPlain));

// 11. Signing keypair + sign/verify round-trip
var signKeys = b.crypto.generateSigningKeyPair();
check("signing keypair has public + private",
      typeof signKeys.publicKey === "string" && typeof signKeys.privateKey === "string");
var msg = Buffer.from("sign-me-" + b.version);
var sig = b.crypto.sign(msg, signKeys.privateKey);
check("sign() returns Buffer of non-zero length", Buffer.isBuffer(sig) && sig.length > 0);
check("verify() accepts valid signature",         b.crypto.verify(msg, sig, signKeys.publicKey));
check("verify() rejects tampered message",        !b.crypto.verify(Buffer.from("tamper"), sig, signKeys.publicKey));

// 12. Router constructs and registers
var r = new b.router.Router();
r.get("/test", function (_req, _res) {});
r.post("/api/items", function (_req, _res) {});
r.use(function (_req, _res, next) { next(); });
check("router registers GET route",  r.routes.some(rt => rt.method === "GET" && rt.pattern === "/test"));
check("router registers POST route", r.routes.some(rt => rt.method === "POST" && rt.pattern === "/api/items"));
check("router stores middleware",    r.middleware.length === 1);

// 13. Router exposes serveStatic
check("serveStatic is a function", typeof b.router.serveStatic === "function");

// =====================================================================
// Phase 1a — vault-wrap + passphrase-source + vault
// =====================================================================

// 14. vault-wrap format constants
check("vault-wrap MAGIC = 0xE2",          b.vaultWrap.MAGIC === 0xE2);
check("vault-wrap FORMAT_VERSION = 1",    b.vaultWrap.FORMAT_VERSION === 0x01);
check("vault-wrap NONCE_LENGTH = 24",     b.vaultWrap.NONCE_LENGTH === 24);
check("vault-wrap default Argon2 params present",
      b.vaultWrap.DEFAULT_ARGON2 && b.vaultWrap.DEFAULT_ARGON2.memoryCost > 0);

// 15. vault-wrap round-trip with low params (fast)
//     We pass overridden params so smoke test stays sub-second; the production
//     paths use DEFAULT_ARGON2 (~1s derivation).
// 16. passphrase-source env var names follow BLAMEJS_ prefix
check("passphraseSource ENV_PASSPHRASE = BLAMEJS_VAULT_PASSPHRASE",
      b.passphraseSource.ENV_PASSPHRASE === "BLAMEJS_VAULT_PASSPHRASE");
check("passphraseSource ENV_PASSPHRASE_FILE = BLAMEJS_VAULT_PASSPHRASE_FILE",
      b.passphraseSource.ENV_PASSPHRASE_FILE === "BLAMEJS_VAULT_PASSPHRASE_FILE");
check("passphraseSource ENV_PASSPHRASE_SRC = BLAMEJS_VAULT_PASSPHRASE_SOURCE",
      b.passphraseSource.ENV_PASSPHRASE_SRC === "BLAMEJS_VAULT_PASSPHRASE_SOURCE");

// 17. passphrase-source env reading + auto-strip
// 18. vault plaintext mode round-trip on a temp directory
// 19. vault rejects mode-vs-state mismatches
// 20. vault.init({ dataDir }) is required
// 20b. End-to-end wrapped-mode round-trip — exercises the production path
//      (default Argon2 params, real wrap format, persistence across reinit).
//      Slower (~2s) but verifies the framework's default boot mode actually
//      works. Skip with BLAMEJS_SKIP_WRAPPED_E2E=1 for fast local iteration.
// =====================================================================
// Phase 1b — db + query builder + field-crypto + migrations
// =====================================================================

// 21. db namespace + diagnostic accessors
check("db namespace present",            typeof b.db === "object");
check("db.from is a function",           typeof b.db.from === "function");
check("db.transaction is a function",    typeof b.db.transaction === "function");
check("db.hashFor is a function",        typeof b.db.hashFor === "function");
check("fieldCrypto namespace present",   typeof b.fieldCrypto === "object");

// setupTestDb / teardownTestDb live in ./_helpers.js (imported above).

// 22. db.init creates tables, indexes, basic round-trip
// 23. update / delete round-trips
// 24. where on sealed column without derived hash throws
// 25. transaction commit + rollback
// 26. Persistence across init/close cycles
// 27. ALTER TABLE additive — adding a column on second init doesn't break
// 28. Imperative migrations: numbered files run once
// =====================================================================
// Phase 1c — audit, consent, subject rights
// =====================================================================

// 29. Module surface
check("audit namespace present",         typeof b.audit === "object");
check("auditChain namespace present",    typeof b.auditChain === "object");
check("consent namespace present",       typeof b.consent === "object");
check("subject namespace present",       typeof b.subject === "object");
check("db.getDataResidency present",     typeof b.db.getDataResidency === "function");

// 30. audit_log + consent_log baked into framework schema
// 31. App schema cannot collide with reserved table names
// 32. audit.record / query / verify round-trip
// 33. audit.verify() detects a manually broken chain
// 34. consent: grant / isGranted / withdraw / history / verify
// 35. subject: export / rectify / erase (with acknowledgements) / restrict
// 36. dataResidency stored
// =====================================================================
// Phase 1d-1 — session + storage (local backend)
// =====================================================================

// 37. Module surface
check("session namespace present",          typeof b.session === "object");
check("storage namespace present",          typeof b.storage === "object");
check("session.create is a function",       typeof b.session.create === "function");
check("storage.saveFile is a function",     typeof b.storage.saveFile === "function");

// 38. session: create / verify / destroy / TTL / lifecycle
// 39. storage: saveFile / getFileBuffer / getFileStream / round-trip
// =====================================================================
// v0.0.7 — traceability hardening (append-only triggers, FKs, metadata,
//          audit self-logging, beginTrace)
// =====================================================================

// =====================================================================
// v0.0.8 — tamper-proofing (signed checkpoints, rollback detection)
// =====================================================================

// =====================================================================
// v0.0.9 — multi-backend storage, classification routing, retry/breaker
// =====================================================================

// =====================================================================
// v0.0.10 — sigv4 protocol adapter
// =====================================================================

// =====================================================================
// v0.0.11 — gcs + azure-blob protocol adapters
// =====================================================================

// _makeFakeServiceAccount lives in ./_helpers.js (imported above).

// =====================================================================
// v0.0.12 — queue dispatcher + local SQLite-backed protocol
// =====================================================================

// =====================================================================
// v0.0.13 — log streaming + redaction
// =====================================================================

// =====================================================================
// v0.0.14 — external DB (bring-your-own-client dispatcher)
// =====================================================================

// _makeFakeDriver lives in ./_helpers.js (imported above).

// =====================================================================
// v0.0.15 — HTTP middleware
// =====================================================================

// Mock req/res factories — minimal Node http.IncomingMessage / ServerResponse
// surface that the middleware uses. No real HTTP server.
// _mockReq / _mockRes live in ./_helpers.js (imported above).

// setupTestDbForMW / teardownMW live in ./_helpers.js (imported above).

// =====================================================================
// env-load — consumer of env-parse + atomicFile primitives
//
// Layer 0 primitives (atomic-file, parsers/*, redact) extracted to
// ./00-primitives.js. What's left in this section is the env-load
// orchestration on top of env-parse (load(), diff, breaking-change
// detection, schema/typo guidance).
// =====================================================================

// async-safe + handlers + sql-safe + chain-writer + json-safe test
// definitions all live in ./00-primitives.js (Layer 0). Smoke runner
// calls primitivesLayer.run() once for the entire group.

// =====================================================================
// Cluster coordination — leader election + fencing tokens
// =====================================================================

// _makeSqliteDriver lives in ./_helpers.js (imported above).

// ----- Cluster write-gate test fixtures -----
//
// Each gate test sets up the full framework (vault + db) for the
// framework's own state, plus an external-db backend that the cluster
// module uses for leader-election coordination. We init cluster, then
// immediately shut it down — that flips the `terminated` state so
// isLeader() returns false. Then we try framework writes and expect
// NotLeaderError.

// _setupClusterGateFixture / _expectNotLeaderError live in ./_helpers.js.

async function testClusterGatesAuditAndConsent() {
  var fx = await _setupClusterGateFixture();
  try {
    _expectNotLeaderError("audit.record on follower", async function () {
      await b.audit.record({
        actor: { kind: "user", id: "u1" },
        action: "auth.login",
        outcome: "success",
      });
    });
    _expectNotLeaderError("audit.checkpoint on follower", async function () {
      await b.audit.checkpoint();
    });
    _expectNotLeaderError("consent.grant on follower", async function () {
      await b.consent.grant({
        subjectId:   "subj-1",
        purpose:     "marketing",
        lawfulBasis: "consent",
        channel:     "web-form",
      });
    });
    _expectNotLeaderError("consent.withdraw on follower", async function () {
      await b.consent.withdraw({ subjectId: "subj-1", purpose: "marketing" });
    });
  } finally {
    await fx.teardown();
  }
}

async function testClusterGatesSession() {
  var fx = await _setupClusterGateFixture();
  try {
    _expectNotLeaderError("session.create on follower", function () {
      b.session.create({ userId: "u1" });
    });
    _expectNotLeaderError("session.destroy on follower", function () {
      b.session.destroy("any-token");
    });
    _expectNotLeaderError("session.purgeExpired on follower", function () {
      b.session.purgeExpired();
    });
  } finally {
    await fx.teardown();
  }
}

async function testClusterGatesSubject() {
  var fx = await _setupClusterGateFixture();
  try {
    _expectNotLeaderError("subject.rectify on follower", function () {
      b.subject.rectify("subj-1", {
        table: "users", id: "u1", changes: { email: "a@b.c" }, reason: "test",
      });
    });
    _expectNotLeaderError("subject.erase on follower", function () {
      b.subject.erase("subj-1", {
        reason: "test",
        acknowledgements: ["no-litigation-hold", "no-statutory-retention-required"],
      });
    });
    _expectNotLeaderError("subject.restrict on follower", function () {
      b.subject.restrict("subj-1", { on: true, reason: "test" });
    });
    _expectNotLeaderError("subject.recordObjection on follower", function () {
      b.subject.recordObjection("subj-1", { purpose: "marketing", reason: "test" });
    });
  } finally {
    await fx.teardown();
  }
}

async function testClusterGatesQueue() {
  var fx = await _setupClusterGateFixture();
  try {
    b.queue.init({ backends: { "default": { protocol: "local" } } });
    var threwEnqueue = null;
    try { await b.queue.enqueue("test-q", { x: 1 }); }
    catch (e) { threwEnqueue = e; }
    check("queue.enqueue on follower throws NotLeaderError",
          threwEnqueue && threwEnqueue.code === "NOT_LEADER");

    var threwPurge = null;
    try { await b.queue.purge("test-q"); }
    catch (e) { threwPurge = e; }
    check("queue.purge on follower throws NotLeaderError",
          threwPurge && threwPurge.code === "NOT_LEADER");
    try { await b.queue.shutdown(); } catch (_e) {}
  } finally {
    await fx.teardown();
  }
}

async function testClusterGatesObjectStoreLocal() {
  var fx = await _setupClusterGateFixture();
  try {
    var localProto = require(path.join(__dirname, "..", "lib", "object-store-local"));
    var rootDir = path.join(fx.tmpDir, "obj");
    var backend = localProto.create({ rootDir: rootDir });

    var threwPut = null;
    try { await backend.put("foo/bar", Buffer.from("hi")); }
    catch (e) { threwPut = e; }
    check("object-store-local.put on follower throws",
          threwPut && threwPut.code === "NOT_LEADER");

    var threwDelete = null;
    try { await backend.delete("foo/bar"); }
    catch (e) { threwDelete = e; }
    check("object-store-local.delete on follower throws",
          threwDelete && threwDelete.code === "NOT_LEADER");

    // Reads remain anywhere — no gate. Set up a non-existent key for
    // a clean error type comparison (NOT_FOUND, not NOT_LEADER).
    var threwGet = null;
    try { await backend.get("nope"); }
    catch (e) { threwGet = e; }
    check("object-store-local.get not gated by cluster",
          threwGet && threwGet.code === "NOT_FOUND");
  } finally {
    await fx.teardown();
  }
}

// =====================================================================
// Run async tests
// =====================================================================

(async function () {
  // ===================================================================
  // LAYER 0 — pure primitives (no framework state, no I/O dependencies)
  // ===================================================================
  // If any of these fail, every consumer test below would also fail.
  // Run them first so the FIRST red light is the actual root cause.

  // crypto + envelope (already covered by inline checks above smoke
  // body; nothing async here)

  // All Layer 0 primitives (async-safe, handlers, sql-safe, chain-writer,
  // json-safe, atomic-file, parsers/*, redact) live in test/00-primitives.js.
  // primitivesLayer.run() invokes them in dependency order.
  // chain-writer's race-safety test includes setupTestDb internally
  // (Layer 3 dependency disclosed in the primitive's own test) — kept
  // colocated with chain-writer so the resilience claim sits next to
  // the primitive being claimed about.
  await primitivesLayer.run();

  // ===================================================================
  // LAYER 1 — framework-state-dependent but isolated
  // ===================================================================
  // vault + cluster + framework-schema primitives all live in
  // test/10-state.js. stateLayer.run() invokes them in dependency order.
  await stateLayer.run();

  // ===================================================================
  // LAYER 2 — needs db
  // ===================================================================
  // db basic + framework-schema reserved-table protection live in
  // test/20-db.js. dbLayer.run() invokes them in dependency order.
  await dbLayer.run();

  // ===================================================================
  // LAYER 3 — uses db + chain-writer + cluster-storage
  // ===================================================================
  // cluster-storage + audit + consent + subject + append-only + checkpoint
  // all live in test/30-chain.js. chainLayer.run() invokes them in order.
  // chain-writer tests live in test/00-primitives.js (Layer 0 primitive);
  // primitivesLayer.run() above already ran them.
  await chainLayer.run();

  // ===================================================================
  // LAYER 4 — uses audit (consumer modules)
  // ===================================================================
  // session + storage + queue + log-stream + external-db + middleware +
  // env-load all live in test/40-consumers.js. consumersLayer.run()
  // invokes them in dependency order.
  await consumersLayer.run();

  // ===================================================================
  // LAYER 5 — operator-facing integration / cross-module flows
  // ===================================================================

  // Cluster gates — write-side gates across framework subsystems
  await testClusterGatesAuditAndConsent();
  await testClusterGatesSession();
  await testClusterGatesSubject();
  await testClusterGatesQueue();
  await testClusterGatesObjectStoreLocal();

  console.log("OK — " + helpers.getChecks() + " checks passed");
})().catch(function (err) {
  console.error("SMOKE TEST FAILED:", err.message);
  console.error(err.stack);
  process.exit(1);
});
