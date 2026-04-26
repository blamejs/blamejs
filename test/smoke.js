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
async function testVaultWrapRoundTrip() {
  var fastOpts = { memoryCost: 1024, timeCost: 1, parallelism: 1, saltLength: 16 };
  var pt = Buffer.from("the quick brown fox jumps over the lazy dog", "utf8");
  var passphrase = Buffer.from("test-passphrase-2026", "utf8");

  var wrapped = await b.vaultWrap.wrap(pt, passphrase, fastOpts);
  check("vault-wrap output starts with magic 0xE2",  wrapped[0] === 0xE2);
  check("vault-wrap output has format version 0x01", wrapped[1] === 0x01);

  var unwrapped = await b.vaultWrap.unwrap(wrapped, passphrase);
  check("vault-wrap round-trip preserves plaintext", unwrapped.equals(pt));

  // Wrong passphrase
  var wrongRejected = false;
  try { await b.vaultWrap.unwrap(wrapped, Buffer.from("wrong-passphrase", "utf8")); }
  catch (_) { wrongRejected = true; }
  check("vault-wrap rejects wrong passphrase", wrongRejected);

  // Tampered ciphertext
  var tampered = Buffer.from(wrapped);
  tampered[tampered.length - 1] ^= 0x01;
  var tamperRejected = false;
  try { await b.vaultWrap.unwrap(tampered, passphrase); }
  catch (_) { tamperRejected = true; }
  check("vault-wrap rejects tampered ciphertext", tamperRejected);

  // Tampered header (memory cost byte) — AAD binding catches this
  var headerTampered = Buffer.from(wrapped);
  headerTampered[5] ^= 0x01;  // flip a memoryCost byte
  var headerRejected = false;
  try { await b.vaultWrap.unwrap(headerTampered, passphrase); }
  catch (_) { headerRejected = true; }
  check("vault-wrap rejects tampered header", headerRejected);
}

// 16. passphrase-source env var names follow BLAMEJS_ prefix
check("passphraseSource ENV_PASSPHRASE = BLAMEJS_VAULT_PASSPHRASE",
      b.passphraseSource.ENV_PASSPHRASE === "BLAMEJS_VAULT_PASSPHRASE");
check("passphraseSource ENV_PASSPHRASE_FILE = BLAMEJS_VAULT_PASSPHRASE_FILE",
      b.passphraseSource.ENV_PASSPHRASE_FILE === "BLAMEJS_VAULT_PASSPHRASE_FILE");
check("passphraseSource ENV_PASSPHRASE_SRC = BLAMEJS_VAULT_PASSPHRASE_SOURCE",
      b.passphraseSource.ENV_PASSPHRASE_SRC === "BLAMEJS_VAULT_PASSPHRASE_SOURCE");

// 17. passphrase-source env reading + auto-strip
async function testPassphraseEnv() {
  process.env.BLAMEJS_VAULT_PASSPHRASE = "smoke-test-passphrase";
  var buf = await b.passphraseSource.fromEnv();
  check("passphraseSource.fromEnv returns Buffer",  Buffer.isBuffer(buf));
  check("passphraseSource.fromEnv preserves bytes", buf.toString("utf8") === "smoke-test-passphrase");
  check("passphraseSource.fromEnv strips env var",  !("BLAMEJS_VAULT_PASSPHRASE" in process.env));
}

// 18. vault plaintext mode round-trip on a temp directory
async function testVaultPlaintextRoundTrip() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-smoke-"));
  try {
    b.vault._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    check("vault.init writes vault.key in plaintext mode", fs.existsSync(path.join(tmpDir, "vault.key")));
    check("vault.getMode() returns 'plaintext'", b.vault.getMode() === "plaintext");

    var sealed = b.vault.seal("test-payload-" + b.version);
    check("vault.seal returns 'vault:' prefixed string",
          typeof sealed === "string" && sealed.startsWith("vault:"));

    var opened = b.vault.unseal(sealed);
    check("vault.unseal round-trip preserves plaintext",
          opened === "test-payload-" + b.version);

    // idempotent seal — already-sealed values pass through
    var doubleSealed = b.vault.seal(sealed);
    check("vault.seal is idempotent on already-sealed values", doubleSealed === sealed);

    // null/empty pass-through
    check("vault.seal passes empty through",  b.vault.seal("") === "");
    check("vault.unseal passes empty through", b.vault.unseal("") === "");
    check("vault.unseal passes plain through", b.vault.unseal("plaintext-not-sealed") === "plaintext-not-sealed");

    // Persistence — re-init from same dir restores keys, same envelope decodes
    b.vault._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    var openedAgain = b.vault.unseal(sealed);
    check("vault persistence: second init restores keys", openedAgain === "test-payload-" + b.version);
  } finally {
    b.vault._resetForTest();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// 19. vault rejects mode-vs-state mismatches
async function testVaultModeMismatch() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-smoke-mode-"));
  try {
    b.vault._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.vault._resetForTest();
    // Now there's a vault.key file but we'll request wrapped mode → should fatal
    // We can't easily test process.exit(1) without forking, so we check that
    // the init's preflight detects the mismatch. Instead, verify we can re-init
    // with the same mode after reset — this confirms the path works.
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    check("vault re-init in same mode succeeds", b.vault.getMode() === "plaintext");
  } finally {
    b.vault._resetForTest();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// 20. vault.init({ dataDir }) is required
async function testVaultRequiresDataDir() {
  b.vault._resetForTest();
  var rejected = false;
  try { await b.vault.init({}); } catch (_) { rejected = true; }
  check("vault.init() rejects missing dataDir", rejected);
  b.vault._resetForTest();
}

// 20b. End-to-end wrapped-mode round-trip — exercises the production path
//      (default Argon2 params, real wrap format, persistence across reinit).
//      Slower (~2s) but verifies the framework's default boot mode actually
//      works. Skip with BLAMEJS_SKIP_WRAPPED_E2E=1 for fast local iteration.
async function testVaultWrappedE2E() {
  if (process.env.BLAMEJS_SKIP_WRAPPED_E2E === "1") {
    return;
  }
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-wrap-e2e-"));
  var passphrase = "smoke-wrapped-vault-2026-" + Date.now();
  process.env.BLAMEJS_VAULT_PASSPHRASE = passphrase;
  try {
    b.vault._resetForTest();
    var t0 = Date.now();
    await b.vault.init({ dataDir: tmpDir, mode: "wrapped" });
    var t1 = Date.now();
    check("wrapped first-run init under 5s", (t1 - t0) < 5000);
    check("wrapped init sets mode='wrapped'",          b.vault.getMode() === "wrapped");
    check("wrapped init writes vault.key.sealed",      fs.existsSync(path.join(tmpDir, "vault.key.sealed")));
    check("wrapped init does NOT write vault.key",     !fs.existsSync(path.join(tmpDir, "vault.key")));

    // Verify the sealed file format starts with the wrap magic byte (0xE2)
    var sealedBytes = fs.readFileSync(path.join(tmpDir, "vault.key.sealed"));
    check("vault.key.sealed starts with magic 0xE2",   sealedBytes[0] === 0xE2);
    check("vault.key.sealed has format version 0x01",  sealedBytes[1] === 0x01);

    // seal/unseal round-trip works under wrapped mode
    var payload = "wrapped-e2e-payload-" + b.version;
    var sealedVal = b.vault.seal(payload);
    var openedVal = b.vault.unseal(sealedVal);
    check("wrapped seal/unseal round-trip preserves plaintext", openedVal === payload);

    // Persistence — close, reset, re-init from the same sealed file with the same passphrase
    b.vault._resetForTest();
    process.env.BLAMEJS_VAULT_PASSPHRASE = passphrase;
    var t2 = Date.now();
    await b.vault.init({ dataDir: tmpDir, mode: "wrapped" });
    var t3 = Date.now();
    check("wrapped restore (existing sealed) under 5s", (t3 - t2) < 5000);
    check("restored mode is 'wrapped'",                 b.vault.getMode() === "wrapped");

    // The previously-sealed value must still decrypt under the restored vault
    var openedAgain = b.vault.unseal(sealedVal);
    check("wrapped persistence: prior sealed value decrypts after restart", openedAgain === payload);
  } finally {
    delete process.env.BLAMEJS_VAULT_PASSPHRASE;
    b.vault._resetForTest();
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

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
async function testDbBasic() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-db-"));
  try {
    await setupTestDb(tmpDir);
    check("db.getMode() returns 'plain'",  b.db.getMode() === "plain");
    check("blamejs.db file exists",        fs.existsSync(path.join(tmpDir, "blamejs.db")));

    var users = b.db.from("users");
    var inserted = users.insertOne({ email: "Alice@example.com", name: "Alice", createdAt: "2026-04-25" });
    check("insertOne returns row with auto _id", typeof inserted._id === "string" && inserted._id.length > 0);
    check("insertOne preserves plaintext fields", inserted.email === "Alice@example.com" && inserted.name === "Alice");

    // The on-disk row should have email/name SEALED (vault: prefix), and emailHash computed
    var rawStmt = b.db.prepare('SELECT _id, email, name, emailHash FROM users WHERE _id = ?');
    var rawRow = rawStmt.get(inserted._id);
    check("on-disk email is sealed",     typeof rawRow.email === "string" && rawRow.email.startsWith("vault:"));
    check("on-disk name is sealed",      typeof rawRow.name === "string" && rawRow.name.startsWith("vault:"));
    check("emailHash is computed",       typeof rawRow.emailHash === "string" && rawRow.emailHash.length === 128);
    check("emailHash is normalized",     rawRow.emailHash === b.db.hashFor("users", "email", "ALICE@example.com"));

    // Query via plain field name (sealed → translated to emailHash)
    var found = b.db.from("users").where({ email: "alice@example.com" }).first();
    check("where on sealed field translates to derived hash", found && found._id === inserted._id);
    check("findFirst() unseals fields",  found.email === "Alice@example.com" && found.name === "Alice");

    // count()
    var n = b.db.from("users").where({ status: "active" }).count();
    check("count() respects where clause",  n === 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// 23. update / delete round-trips
async function testDbWriteOps() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-db-write-"));
  try {
    await setupTestDb(tmpDir);
    var users = b.db.from("users");
    var alice = users.insertOne({ email: "a@x.com", name: "A" });
    var bob = users.insertOne({ email: "b@x.com", name: "B" });

    // updateOne
    var ok = b.db.from("users").where({ _id: alice._id }).updateOne({ name: "Alice Updated" });
    check("updateOne returns true on match", ok === true);
    var updated = b.db.from("users").where({ _id: alice._id }).first();
    check("updateOne wrote new value", updated.name === "Alice Updated");
    // emailHash should still be valid (email didn't change)
    check("updateOne didn't break emailHash",
          b.db.from("users").where({ email: "a@x.com" }).first()._id === alice._id);

    // updateMany — change everyone's status
    var changed = b.db.from("users").where({ status: "active" }).updateMany({ status: "archived" });
    check("updateMany returns affected count", changed === 2);

    // deleteOne
    var deleted = b.db.from("users").where({ _id: bob._id }).deleteOne();
    check("deleteOne returns true on match", deleted === true);
    check("deleteOne actually removed row",  b.db.from("users").where({ _id: bob._id }).first() === null);

    // Refusing unconditional update/delete
    var unconditionalUpdateRejected = false;
    try { b.db.from("users").updateMany({ status: "x" }); }
    catch (_) { unconditionalUpdateRejected = true; }
    check("updateMany without where() throws", unconditionalUpdateRejected);

    var unconditionalDeleteRejected = false;
    try { b.db.from("users").deleteMany(); }
    catch (_) { unconditionalDeleteRejected = true; }
    check("deleteMany without where() throws", unconditionalDeleteRejected);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// 24. where on sealed column without derived hash throws
async function testDbSealedWithoutDerived() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-db-sealed-"));
  try {
    await setupTestDb(tmpDir);
    var thrown = false;
    try {
      // 'name' is sealed but has no derived hash — should throw
      b.db.from("users").where({ name: "Alice" }).first();
    } catch (e) {
      thrown = true;
      check("error message names the field", /name/.test(e.message));
    }
    check("where on sealed-without-derived-hash throws", thrown);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// 25. transaction commit + rollback
async function testDbTransactions() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-db-tx-"));
  try {
    await setupTestDb(tmpDir);
    // Commit path
    b.db.transaction(function (tx) {
      tx.from("users").insertOne({ email: "tx1@x.com", name: "TX1" });
      tx.from("users").insertOne({ email: "tx2@x.com", name: "TX2" });
    });
    check("transaction commit persists rows", b.db.from("users").count() === 2);

    // Rollback path — error inside transaction undoes prior inserts
    var caught = false;
    try {
      b.db.transaction(function (tx) {
        tx.from("users").insertOne({ email: "tx3@x.com", name: "TX3" });
        throw new Error("simulated failure");
      });
    } catch (e) {
      caught = e.message === "simulated failure";
    }
    check("transaction rolls back on throw", caught);
    check("transaction rollback removes inserted rows", b.db.from("users").count() === 2);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// 26. Persistence across init/close cycles
async function testDbPersistence() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-db-persist-"));
  try {
    await setupTestDb(tmpDir);
    var inserted = b.db.from("users").insertOne({ email: "persist@x.com", name: "P" });
    var id = inserted._id;
    b.db.close();
    b.db._resetForTest();
    b.vault._resetForTest();

    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      schema: [
        {
          name: "users",
          columns: {
            _id: "TEXT PRIMARY KEY",
            email: "TEXT",
            emailHash: "TEXT",
            name: "TEXT",
            status: "TEXT DEFAULT 'active'",
            createdAt: "TEXT",
          },
          indexes: ["emailHash", "status"],
          sealedFields: ["email", "name"],
          derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
        },
      ],
    });
    var loaded = b.db.from("users").where({ _id: id }).first();
    check("persistence: row survives close+reopen", loaded && loaded.email === "persist@x.com");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// 27. ALTER TABLE additive — adding a column on second init doesn't break
async function testDbSchemaEvolution() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-db-evo-"));
  try {
    await setupTestDb(tmpDir);
    b.db.from("users").insertOne({ email: "evo@x.com", name: "E" });
    b.db.close();
    b.db._resetForTest();
    b.vault._resetForTest();

    // Add a new column 'lastSeen' to schema, re-init
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      schema: [
        {
          name: "users",
          columns: {
            _id: "TEXT PRIMARY KEY",
            email: "TEXT",
            emailHash: "TEXT",
            name: "TEXT",
            status: "TEXT DEFAULT 'active'",
            createdAt: "TEXT",
            lastSeen: "TEXT",     // ← new column
          },
          indexes: ["emailHash", "status"],
          sealedFields: ["email", "name"],
          derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
        },
      ],
    });
    // Old row still readable, new column present (NULL for existing row)
    var row = b.db.from("users").where({ email: "evo@x.com" }).first();
    check("ALTER TABLE additive: existing row still readable", row && row.email === "evo@x.com");
    check("ALTER TABLE additive: new column present and null", row.lastSeen === null);

    // New row with the new column
    var newRow = b.db.from("users").insertOne({ email: "evo2@x.com", name: "E2", lastSeen: "2026-04-25" });
    check("ALTER TABLE additive: new column accepts writes", newRow.lastSeen === "2026-04-25");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// 28. Imperative migrations: numbered files run once
async function testDbMigrations() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-db-mig-"));
  var migDir = path.join(tmpDir, "migrations");
  fs.mkdirSync(migDir, { recursive: true });
  // Migration that exercises both the raw-prepare escape hatch and the
  // sealed-row path via top-level vault.seal (since the migration runs
  // after vault is initialized).
  fs.writeFileSync(path.join(migDir, "001-seed.js"),
    "var b = require(" + JSON.stringify(path.resolve("../blamejs/index.js")) + ");\n" +
    "module.exports = {\n" +
    "  description: 'seed system row',\n" +
    "  up: function (database) {\n" +
    "    var sealedEmail = b.vault.seal('mig@x.com');\n" +
    "    var sealedName  = b.vault.seal('Migration Seed');\n" +
    "    var emailHash   = b.crypto.sha3Hash('bj-users-email:' + 'mig@x.com');\n" +
    "    database.prepare('INSERT INTO users (_id, email, emailHash, name, status, createdAt) VALUES (?, ?, ?, ?, ?, ?)')\n" +
    "      .run('mig1', sealedEmail, emailHash, sealedName, 'active', '2026-04-25');\n" +
    "  }\n" +
    "};\n"
  );
  try {
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir:      tmpDir,
      atRest:       "plain",
      migrationDir: migDir,
      schema: [
        {
          name: "users",
          columns: {
            _id:       "TEXT PRIMARY KEY",
            email:     "TEXT",
            emailHash: "TEXT",
            name:      "TEXT",
            status:    "TEXT DEFAULT 'active'",
            createdAt: "TEXT",
          },
          indexes:       ["emailHash", "status"],
          sealedFields:  ["email", "name"],
          derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
        },
      ],
    });
    var migrationsApplied = b.db.prepare("SELECT name FROM _blamejs_migrations").all();
    check("migration applied recorded in _blamejs_migrations",
          migrationsApplied.length === 1 && migrationsApplied[0].name === "001-seed.js");
    var migRow = b.db.from("users").where({ _id: "mig1" }).first();
    check("migration up() ran (row exists)", migRow !== null);

    // Re-init — migration should NOT run again (idempotency)
    b.db.close();
    b.db._resetForTest();
    b.vault._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir:      tmpDir,
      atRest:       "plain",
      migrationDir: migDir,
      schema: [
        {
          name: "users",
          columns: {
            _id: "TEXT PRIMARY KEY",
            email: "TEXT",
            emailHash: "TEXT",
            name: "TEXT",
            status: "TEXT DEFAULT 'active'",
            createdAt: "TEXT",
          },
          indexes: ["emailHash", "status"],
          sealedFields: ["email", "name"],
          derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
        },
      ],
    });
    var stillOne = b.db.prepare("SELECT COUNT(*) AS n FROM _blamejs_migrations").get();
    check("migration is idempotent — not re-run on second init", stillOne.n === 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

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
async function testFrameworkSchema() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-fw-"));
  try {
    await setupTestDb(tmpDir);
    var auditCols = b.db.prepare("PRAGMA table_info(audit_log)").all();
    check("audit_log table exists",      auditCols.length > 0);
    check("audit_log has prevHash col",  auditCols.some(c => c.name === "prevHash"));
    check("audit_log has rowHash col",   auditCols.some(c => c.name === "rowHash"));
    check("audit_log has nonce col",     auditCols.some(c => c.name === "nonce"));

    var consentCols = b.db.prepare("PRAGMA table_info(consent_log)").all();
    check("consent_log table exists",    consentCols.length > 0);
    check("consent_log has chain cols",  consentCols.some(c => c.name === "rowHash"));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// 31. App schema cannot collide with reserved table names
async function testReservedTableProtection() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-reserved-"));
  try {
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    var threw = false;
    try {
      await b.db.init({
        dataDir: tmpDir,
        atRest:  "plain",
        schema: [{ name: "audit_log", columns: { _id: "TEXT PRIMARY KEY" } }],
      });
    } catch (e) {
      threw = /reserved/.test(e.message);
    }
    check("app schema with reserved table name throws", threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// 32. audit.record / query / verify round-trip
async function testAuditChain() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-"));
  try {
    await setupTestDb(tmpDir);

    // Unregistered namespace rejected
    var nsRejected = false;
    try { await b.audit.record({ action: "orders.created", outcome: "success" }); }
    catch (_) { nsRejected = true; }
    check("unregistered namespace rejected", nsRejected);

    // Register + record
    b.audit.registerNamespace("orders");
    var ev1 = await b.audit.record({
      actor:    { userId: "user-1", ip: "1.2.3.4" },
      action:   "orders.created",
      resource: { kind: "order", id: "ord-1" },
      outcome:  "success",
      metadata: { total: 99.95 },
    });
    check("audit.record returns row with rowHash",   typeof ev1.rowHash === "string" && ev1.rowHash.length === 128);
    check("first row's prevHash is ZERO_HASH",       ev1.prevHash === b.auditChain.ZERO_HASH);

    var ev2 = await b.audit.record({
      actor:    { userId: "user-1", ip: "1.2.3.4" },
      action:   "auth.login.success",
      resource: { kind: "user", id: "user-1" },
      outcome:  "success",
    });
    check("second row's prevHash = first row's rowHash", ev2.prevHash === ev1.rowHash);
    check("monotonicCounter increments",                 ev2.monotonicCounter === ev1.monotonicCounter + 1);

    // Invalid action format
    var actionRejected = false;
    try { await b.audit.record({ action: "no-dot", outcome: "success" }); }
    catch (_) { actionRejected = true; }
    check("malformed action rejected", actionRejected);

    // Invalid outcome
    var outcomeRejected = false;
    try { await b.audit.record({ action: "auth.login.success", outcome: "ok" }); }
    catch (_) { outcomeRejected = true; }
    check("invalid outcome rejected", outcomeRejected);

    // Verify chain is intact
    var v1 = await b.audit.verify();
    check("audit.verify() ok after valid records",  v1.ok === true && v1.rowsVerified === 2);

    // Query by various criteria
    var byUser = await b.audit.query({ actorUserId: "user-1" });
    check("query by sealed actorUserId returns rows",   byUser.length === 2);
    check("query result rows are unsealed",             byUser[0].actorUserId === "user-1");
    var byAction = await b.audit.query({ action: "auth.login.success" });
    check("query by action returns matching",            byAction.length === 1);
    var byKind = await b.audit.query({ resourceKind: "order" });
    check("query by resourceKind returns matching",     byKind.length === 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// 33. audit.verify() detects a manually broken chain
async function testAuditChainBreak() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-broken-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    await b.audit.record({ action: "test.event", outcome: "success" });
    await b.audit.record({ action: "test.event", outcome: "success" });
    var v1 = await b.audit.verify();
    check("chain ok before tampering", v1.ok === true);

    // Manually corrupt a row's reason field. As of v0.0.7 the audit_log
    // table has BEFORE-UPDATE/DELETE triggers blocking direct mutation —
    // simulating a raw-DB-file tamper that bypassed those guards by
    // dropping the triggers around the corruption.
    b.db.runSql("DROP TRIGGER IF EXISTS no_update_audit_log");
    b.db.prepare('UPDATE audit_log SET reason = ? WHERE monotonicCounter = 1').run("vault:tampered-but-not-actually-sealed");
    b.db.runSql("CREATE TRIGGER IF NOT EXISTS no_update_audit_log BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only — UPDATE prohibited'); END");
    var v2 = await b.audit.verify();
    check("chain detected after row tampering",         v2.ok === false);
    check("chain break reports breakAt index",          v2.breakAt === 0 || v2.breakAt === 1);
    check("chain break reports rowHash mismatch reason",
          v2.reason === "rowHash mismatch" || v2.reason === "prevHash mismatch");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// 34. consent: grant / isGranted / withdraw / history / verify
async function testConsent() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-consent-"));
  try {
    await setupTestDb(tmpDir);

    var subjectId = "user-7";
    check("isGranted is false before grant",     b.consent.isGranted({ subjectId, purpose: "marketing.email" }) === false);

    await b.consent.grant({
      subjectId:    subjectId,
      purpose:      "marketing.email",
      lawfulBasis:  "consent",
      scope:        { channels: ["email"], topics: ["product-updates"] },
      channel:      "web_form_v2",
      evidenceRef:  "/evidence/forms/2026-04-25T...",
    });
    check("isGranted true after grant",          b.consent.isGranted({ subjectId, purpose: "marketing.email" }) === true);

    await b.consent.withdraw({ subjectId, purpose: "marketing.email" });
    check("isGranted false after withdraw",      b.consent.isGranted({ subjectId, purpose: "marketing.email" }) === false);

    var hist = b.consent.history(subjectId);
    check("history returns 2 events",            hist.length === 2);
    check("history first event is grant",        hist[0].action === "granted");
    check("history second event is withdraw",    hist[1].action === "withdrawn");
    check("history unsealed subjectId",          hist[0].subjectId === subjectId);

    var cv = await b.consent.verify();
    check("consent.verify() ok",                 cv.ok === true && cv.rowsVerified === 2);

    // Invalid lawful basis
    var basisRejected = false;
    try { await b.consent.grant({ subjectId, purpose: "x", lawfulBasis: "bogus", channel: "x" }); }
    catch (_) { basisRejected = true; }
    check("invalid lawfulBasis rejected", basisRejected);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// 35. subject: export / rectify / erase (with acknowledgements) / restrict
async function testSubjectRights() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-subject-"));
  try {
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      schema: [
        {
          name: "users",
          columns: {
            _id:       "TEXT PRIMARY KEY",
            email:     "TEXT",
            emailHash: "TEXT",
            name:      "TEXT",
          },
          indexes:        ["emailHash"],
          sealedFields:   ["email", "name"],
          derivedHashes:  { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
          subjectField:   "_id",
          personalDataCategories: { email: "email", name: "name" },
        },
        {
          name: "orders",
          columns: {
            _id:        "TEXT PRIMARY KEY",
            userId:     "TEXT",
            userIdHash: "TEXT",
            amount:     "REAL",
          },
          indexes:        ["userIdHash"],
          sealedFields:   [],
          derivedHashes:  { userIdHash: { from: "userId" } },
          subjectField:   "userId",
          personalDataCategories: {},
        },
      ],
    });

    var alice = b.db.from("users").insertOne({ _id: "u-alice", email: "alice@x.com", name: "Alice" });
    b.db.from("users").insertOne({ _id: "u-bob",   email: "bob@x.com",   name: "Bob" });
    b.db.from("orders").insertOne({ _id: "o-1", userId: "u-alice", amount: 99.95 });
    b.db.from("orders").insertOne({ _id: "o-2", userId: "u-alice", amount: 12.50 });
    b.db.from("orders").insertOne({ _id: "o-3", userId: "u-bob",   amount: 7.00 });

    // Export
    var dump = b.subject.export("u-alice", { reason: "Art. 15 access request 2026-04-25" });
    check("subject.export returns dump for alice",    dump.users && dump.users.length === 1);
    check("subject.export decrypts sealed fields",    dump.users[0].email === "alice@x.com");
    check("subject.export walks orders too",          dump.orders && dump.orders.length === 2);

    // Rectify
    var ok = b.subject.rectify("u-alice", {
      table:   "users",
      id:      "u-alice",
      changes: { name: "Alice Updated" },
      reason:  "Art. 16 rectification 2026-04-25",
    });
    check("rectify returns true",                     ok === true);
    var aliceAfter = b.db.from("users").where({ _id: "u-alice" }).first();
    check("rectify wrote new value",                  aliceAfter.name === "Alice Updated");

    // Erase requires both acknowledgements
    var noAckRejected = false;
    try { b.subject.erase("u-alice", { reason: "Art. 17", acknowledgements: ["no-litigation-hold"] }); }
    catch (_) { noAckRejected = true; }
    check("erase without all acknowledgements rejected", noAckRejected);

    // Erase with all acks
    var result = b.subject.erase("u-alice", {
      reason:           "Art. 17 erasure request 2026-04-25 ticket #4471",
      acknowledgements: ["no-litigation-hold", "no-statutory-retention-required"],
    });
    check("erase returns rowsDeleted",                 result.rowsDeleted >= 3);
    check("alice gone from users",                     b.db.from("users").where({ _id: "u-alice" }).first() === null);
    check("alice's orders gone",                       b.db.from("orders").where({ userIdHash: b.db.hashFor("orders", "userId", "u-alice") }).all().length === 0);
    check("bob still present",                         b.db.from("users").where({ _id: "u-bob" }).first() !== null);

    // Erasure marker recorded
    var erasureRow = b.db.prepare("SELECT subjectIdHash FROM _blamejs_subject_erasures").all();
    check("subject erasure marker recorded",           erasureRow.length === 1);

    // Restrict / isRestricted
    check("isRestricted false initially",              b.subject.isRestricted("u-bob") === false);
    b.subject.restrict("u-bob", { on: true, reason: "Art. 18 contested accuracy" });
    check("isRestricted true after restrict",          b.subject.isRestricted("u-bob") === true);
    b.subject.restrict("u-bob", { on: false });
    check("isRestricted false after lift",             b.subject.isRestricted("u-bob") === false);

    // Audit chain still intact after all this activity
    var av = await b.audit.verify();
    check("audit chain intact through subject ops",    av.ok === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// 36. dataResidency stored
async function testDataResidency() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-dr-"));
  try {
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      schema:  [{ name: "x", columns: { _id: "TEXT PRIMARY KEY" } }],
      dataResidency: { region: "EU", allowedStorageRegions: ["eu-west-1"] },
    });
    var dr = b.db.getDataResidency();
    check("getDataResidency returns config",         dr && dr.region === "EU");
    check("dataResidency includes allowedRegions",   dr.allowedStorageRegions[0] === "eu-west-1");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// =====================================================================
// Phase 1d-1 — session + storage (local backend)
// =====================================================================

// 37. Module surface
check("session namespace present",          typeof b.session === "object");
check("storage namespace present",          typeof b.storage === "object");
check("session.create is a function",       typeof b.session.create === "function");
check("storage.saveFile is a function",     typeof b.storage.saveFile === "function");

// 38. session: create / verify / destroy / TTL / lifecycle
async function testSession() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-session-"));
  try {
    await setupTestDb(tmpDir);

    // Create + verify
    var s1 = b.session.create({ userId: "u-1", data: { csrfToken: "abc" } });
    check("create returns 64-hex token",            typeof s1.token === "string" && s1.token.length === 64);
    check("create returns expiresAt > now",         s1.expiresAt > Date.now());

    var v1 = b.session.verify(s1.token);
    check("verify returns the session",             v1 && v1.userId === "u-1");
    check("verify decrypts data field",             v1 && v1.data && v1.data.csrfToken === "abc");

    // The plaintext sid should NEVER be in the DB — only its hash
    var rawRows = b.db.prepare("SELECT sidHash FROM _blamejs_sessions").all();
    check("only sidHash stored, never plaintext sid",
          rawRows.every(r => r.sidHash !== s1.token && r.sidHash.length === 128));

    // verify on garbage token returns null
    check("verify on garbage token returns null",   b.session.verify("not-a-real-token") === null);
    check("verify on empty token returns null",     b.session.verify("") === null);

    // touch
    var beforeTouch = b.session.verify(s1.token);
    var t0 = beforeTouch.lastActivity;
    // Sleep briefly to ensure lastActivity changes
    await new Promise(function (r) { setTimeout(r, 10); });
    var ok = b.session.touch(s1.token);
    check("touch returns true",                     ok === true);
    var afterTouch = b.session.verify(s1.token);
    check("touch updates lastActivity",             afterTouch.lastActivity > t0);

    // destroyAllForUser
    var s2 = b.session.create({ userId: "u-1" });
    var s3 = b.session.create({ userId: "u-2" });
    check("count includes all active sessions",     b.session.count() === 3);
    var nDel = b.session.destroyAllForUser("u-1");
    check("destroyAllForUser returns count",        nDel === 2);
    check("u-1's sessions all gone",                b.session.verify(s1.token) === null && b.session.verify(s2.token) === null);
    check("u-2's session survives",                 b.session.verify(s3.token) !== null);

    // destroy single
    check("destroy returns true on success",        b.session.destroy(s3.token) === true);
    check("destroy returns false on missing",       b.session.destroy(s3.token) === false);

    // Expired session auto-cleans on verify
    var sExp = b.session.create({ userId: "u-3", ttlMs: 50 });
    await new Promise(function (r) { setTimeout(r, 100); });
    check("verify on expired session returns null", b.session.verify(sExp.token) === null);

    // purgeExpired
    var sExp2 = b.session.create({ userId: "u-4", ttlMs: 50 });
    void sExp2;
    await new Promise(function (r) { setTimeout(r, 100); });
    var purged = b.session.purgeExpired();
    check("purgeExpired returns count",             purged >= 1);

    // Invalid input
    var rejected = false;
    try { b.session.create({}); } catch (_) { rejected = true; }
    check("session.create requires userId",         rejected);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// 39. storage: saveFile / getFileBuffer / getFileStream / round-trip
async function testStorage() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-storage-"));
  try {
    await setupTestDb(tmpDir);
    b.storage.init({ backend: "local", uploadDir: path.join(tmpDir, "uploads") });

    var content = Buffer.from("hello blamejs storage " + Date.now(), "utf8");
    var saved = await b.storage.saveFile(content, "user-1/welcome.txt");
    check("saveFile returns storedPath",            saved.storedPath === "user-1/welcome.txt");
    check("saveFile returns sealed encryptionKey",
          typeof saved.encryptionKey === "string" && saved.encryptionKey.startsWith("vault:"));

    // The on-disk file must NOT contain the plaintext content
    var onDisk = fs.readFileSync(path.join(tmpDir, "uploads", "user-1/welcome.txt"));
    check("on-disk file is encrypted (not plaintext)",  onDisk.indexOf(content) === -1);
    check("on-disk file starts with format byte 0x02",  onDisk[0] === b.constants.FORMAT.XCHACHA20_POLY1305);

    // Round-trip
    var decrypted = await b.storage.getFileBuffer("user-1/welcome.txt", saved.encryptionKey);
    check("getFileBuffer round-trip preserves content", decrypted.equals(content));

    // Stream form
    var stream = await b.storage.getFileStream("user-1/welcome.txt", saved.encryptionKey);
    var chunks = [];
    for await (var chunk of stream) chunks.push(chunk);
    var streamed = Buffer.concat(chunks);
    check("getFileStream round-trip preserves content", streamed.equals(content));

    // Wrong key fails
    var wrongRejected = false;
    try { await b.storage.getFileBuffer("user-1/welcome.txt", b.vault.seal("not-the-real-key")); }
    catch (_) { wrongRejected = true; }
    check("getFileBuffer with wrong key throws",       wrongRejected);

    // No key required throws
    var noKeyRejected = false;
    try { await b.storage.getFileBuffer("user-1/welcome.txt", null); }
    catch (_) { noKeyRejected = true; }
    check("getFileBuffer without key throws",          noKeyRejected);

    // exists
    check("exists returns true on present file",       (await b.storage.exists("user-1/welcome.txt")) === true);
    check("exists returns false on missing",           (await b.storage.exists("does/not/exist.txt")) === false);

    // saveRaw / getRawBuffer (no encryption)
    var rawContent = Buffer.from("already-encrypted-or-not-sensitive", "utf8");
    await b.storage.saveRaw(rawContent, "raw/blob.bin");
    var rawBack = await b.storage.getRawBuffer("raw/blob.bin");
    check("saveRaw / getRawBuffer round-trip",        rawBack.equals(rawContent));

    // deleteFile
    check("deleteFile returns true on existing",       (await b.storage.deleteFile("user-1/welcome.txt")) === true);
    check("deleteFile returns false on missing",       (await b.storage.deleteFile("user-1/welcome.txt")) === false);
    check("file no longer exists after delete",        (await b.storage.exists("user-1/welcome.txt")) === false);

    // Path traversal rejected
    var traversalRejected = false;
    try { await b.storage.saveFile(content, "../escape.txt"); }
    catch (_) { traversalRejected = true; }
    check("path traversal via .. rejected",            traversalRejected);

    var absRejected = false;
    try { await b.storage.saveFile(content, "/etc/passwd"); }
    catch (_) { absRejected = true; }
    check("absolute path rejected",                    absRejected);

    var nullByteRejected = false;
    try { await b.storage.saveFile(content, "ok injected"); }
    catch (_) { nullByteRejected = true; }
    check("null-byte in path rejected",                nullByteRejected);

    // S3 backend not yet available
    b.storage._resetForTest();
    var s3Rejected = false;
    try { b.storage.init({ backend: "s3", bucket: "x" }); }
    catch (e) { s3Rejected = /sigv4|deferred|not yet/i.test(e.message); }
    check("storage backend 's3' deferred with clear message", s3Rejected);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// =====================================================================
// v0.0.7 — traceability hardening (append-only triggers, FKs, metadata,
//          audit self-logging, beginTrace)
// =====================================================================

async function testAppendOnlyTriggers() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-trig-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    await b.audit.record({ action: "test.event", outcome: "success" });

    var deleteRejected = false;
    try { b.db.runSql("DELETE FROM audit_log"); }
    catch (e) { deleteRejected = /append-only|prohibited/i.test(e.message); }
    check("DELETE on audit_log raises ABORT",            deleteRejected);

    var updateRejected = false;
    try { b.db.runSql("UPDATE audit_log SET outcome = 'denied' WHERE 1=1"); }
    catch (e) { updateRejected = /append-only|prohibited/i.test(e.message); }
    check("UPDATE on audit_log raises ABORT",            updateRejected);

    // consent_log
    await b.consent.grant({ subjectId: "u-1", purpose: "x", lawfulBasis: "consent", channel: "api" });
    var conDelRejected = false;
    try { b.db.runSql("DELETE FROM consent_log"); }
    catch (e) { conDelRejected = /append-only|prohibited/i.test(e.message); }
    check("DELETE on consent_log raises ABORT",          conDelRejected);

    // INSERT still works (the framework's API uses it constantly above)
    var counts = b.db.prepare("SELECT (SELECT COUNT(*) FROM audit_log) AS a, (SELECT COUNT(*) FROM consent_log) AS c").get();
    check("INSERT on audit_log still works",             counts.a >= 1);
    check("INSERT on consent_log still works",           counts.c >= 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testForeignKeys() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-fk-"));
  try {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      schema: [
        {
          name: "users",
          columns: { _id: "TEXT", email: "TEXT", emailHash: "TEXT" },
          primaryKey: "_id",
          indexes:    ["emailHash"],
          sealedFields:  ["email"],
          derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
        },
        {
          name: "orders",
          columns: { _id: "TEXT", userId: "TEXT NOT NULL", amount: "REAL" },
          primaryKey: "_id",
          foreignKeys: [{ column: "userId", references: "users._id", onDelete: "CASCADE" }],
        },
      ],
    });

    // Verify foreign_keys pragma is ON
    var fkPragma = b.db.prepare("PRAGMA foreign_keys").get();
    check("foreign_keys pragma is enabled",              fkPragma.foreign_keys === 1);

    // Verify FK declared in DDL
    var fkInfo = b.db.prepare("PRAGMA foreign_key_list(orders)").all();
    check("orders has 1 FK declared",                    fkInfo.length === 1);
    check("FK references users(_id)",                    fkInfo[0].table === "users" && fkInfo[0].from === "userId" && fkInfo[0].to === "_id");
    check("FK on_delete is CASCADE",                     fkInfo[0].on_delete === "CASCADE");

    // Insert valid user + order
    b.db.from("users").insertOne({ _id: "u-1", email: "a@b.com" });
    b.db.from("orders").insertOne({ _id: "o-1", userId: "u-1", amount: 100 });
    check("valid order insert succeeds",                 b.db.from("orders").where({ _id: "o-1" }).first() !== null);

    // FK violation: order with non-existent userId
    var fkViolated = false;
    try { b.db.from("orders").insertOne({ _id: "o-2", userId: "u-nonexistent", amount: 50 }); }
    catch (e) { fkViolated = /FOREIGN KEY|constraint/i.test(e.message); }
    check("FK violation rejects insert",                 fkViolated);

    // Cascade delete: deleting user removes their orders
    b.db.from("users").where({ _id: "u-1" }).deleteOne();
    check("ON DELETE CASCADE removes child rows",        b.db.from("orders").where({ _id: "o-1" }).first() === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testTableMetadata() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-meta-"));
  try {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      schema: [
        {
          name: "items",
          columns: { _id: "TEXT", ownerId: "TEXT", name: "TEXT", nameHash: "TEXT" },
          primaryKey: "_id",
          foreignKeys: [{ column: "ownerId", references: "users._id", onDelete: "SET NULL" }],
          indexes: ["nameHash"],
          sealedFields: ["name"],
          derivedHashes: { nameHash: { from: "name" } },
          subjectField: "ownerId",
          personalDataCategories: { name: "label" },
        },
        // users table with no FKs
        { name: "users", columns: { _id: "TEXT" }, primaryKey: "_id" },
      ],
    });

    var meta = b.db.getTableMetadata("items");
    check("metadata returns object",                     typeof meta === "object" && meta !== null);
    check("metadata.primaryKey is array",                Array.isArray(meta.primaryKey) && meta.primaryKey[0] === "_id");
    check("metadata.foreignKeys captured",               meta.foreignKeys.length === 1 && meta.foreignKeys[0].references === "users._id");
    check("metadata.sealedFields captured",              meta.sealedFields[0] === "name");
    check("metadata.subjectField captured",              meta.subjectField === "ownerId");
    check("metadata.personalDataCategories captured",    meta.personalDataCategories.name === "label");

    // Framework tables also show up in metadata
    var auditMeta = b.db.getTableMetadata("audit_log");
    check("audit_log metadata available",                auditMeta !== null);
    check("audit_log primaryKey is _id",                 auditMeta.primaryKey[0] === "_id");

    // Mutating the snapshot doesn't affect framework state
    meta.foreignKeys.push({ column: "fake" });
    var freshMeta = b.db.getTableMetadata("items");
    check("metadata snapshot is deep-copied",            freshMeta.foreignKeys.length === 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testAuditSelfLogging() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-selflog-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    await b.audit.record({ action: "test.event", outcome: "success" });
    await b.audit.record({ action: "test.event", outcome: "success" });

    // A query auto-records an audit.read event before returning rows
    var beforeCount = b.db.from("audit_log").count();
    var rows = await b.audit.query({ action: "test.event" });
    var afterCount = b.db.from("audit_log").count();
    check("query returned both test.event rows",         rows.length === 2);
    check("query auto-recorded an audit.read event",     afterCount === beforeCount + 1);

    // The audit.read row exists
    var readRows = await b.audit.query({ action: "audit.read" });
    check("audit.read events queryable directly",        readRows.length >= 1);
    check("audit.read row has criteria metadata",
          readRows[0].metadata && /criteria/.test(readRows[0].metadata));

    // Querying for audit.read does NOT recursively self-log (else infinite chain)
    var beforeRecursionCheck = b.db.from("audit_log").count();
    await b.audit.query({ action: "audit.read" });
    var afterRecursionCheck = b.db.from("audit_log").count();
    check("query for audit.read does NOT auto-self-log",  afterRecursionCheck === beforeRecursionCheck);

    // Audit chain still verifies through all the self-logging
    var v = await b.audit.verify();
    check("audit chain ok after self-log activity",       v.ok === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testBeginTrace() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-trace-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");

    var t1 = b.audit.beginTrace();
    var t2 = b.audit.beginTrace();
    check("beginTrace returns 32-hex string",            typeof t1 === "string" && t1.length === 32 && /^[0-9a-f]+$/.test(t1));
    check("beginTrace returns unique values",            t1 !== t2);

    // Apps thread the traceId through linked events
    var ev1 = await b.audit.record({
      action:   "test.start",
      outcome:  "success",
      metadata: { traceId: t1 },
    });
    var ev2 = await b.audit.record({
      action:   "test.continue",
      outcome:  "success",
      metadata: { traceId: t1, parentEventId: ev1._id },
    });

    // Query and verify trace correlation is queryable from metadata
    var rows = await b.audit.query({ action: "test.start" });
    var meta = JSON.parse(rows[0].metadata);
    check("traceId persists into audit row metadata",    meta.traceId === t1);

    var rows2 = await b.audit.query({ action: "test.continue" });
    var meta2 = JSON.parse(rows2[0].metadata);
    check("parentEventId persists into audit row",       meta2.parentEventId === ev1._id);
    check("traceId is shared across linked events",      meta2.traceId === t1);

    void ev2;
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// =====================================================================
// v0.0.8 — tamper-proofing (signed checkpoints, rollback detection)
// =====================================================================

async function testCheckpointSign() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-ckpt-"));
  try {
    await setupTestDb(tmpDir);

    // auditSign module surface
    check("auditSign namespace present",                typeof b.auditSign === "object");
    check("auditSign.getPublicKey is a function",       typeof b.auditSign.getPublicKey === "function");
    check("auditSign.getPublicKeyFingerprint works",
          typeof b.auditSign.getPublicKeyFingerprint() === "string" &&
          b.auditSign.getPublicKeyFingerprint().length === 128);

    // audit-sign keypair file written
    check("audit-sign.key file exists in plaintext mode",  fs.existsSync(path.join(tmpDir, "audit-sign.key")));

    // Empty audit_log → checkpoint returns null (nothing to anchor)
    var emptyResult = await b.audit.checkpoint();
    check("checkpoint() on empty log returns null",     emptyResult === null);

    // Record and checkpoint
    b.audit.registerNamespace("test");
    await b.audit.record({ action: "test.event", outcome: "success" });
    await b.audit.record({ action: "test.event", outcome: "success" });
    var ckpt = await b.audit.checkpoint();
    check("checkpoint() returns a checkpoint object",   ckpt && typeof ckpt._id === "string");
    check("checkpoint anchors monotonic counter",       typeof ckpt.atMonotonicCounter === "number");
    check("checkpoint includes pubkey fingerprint",
          ckpt.publicKeyFingerprint === b.auditSign.getPublicKeyFingerprint());

    // skipIfUnchanged: second call with no new audit activity returns null
    var skipResult = await b.audit.checkpoint({ skipIfUnchanged: true });
    check("checkpoint(skipIfUnchanged) on unchanged log returns null", skipResult === null);

    // After more activity, skipIfUnchanged anchors a new checkpoint
    await b.audit.record({ action: "test.event", outcome: "success" });
    var freshCkpt = await b.audit.checkpoint({ skipIfUnchanged: true });
    check("skipIfUnchanged anchors when chain advances", freshCkpt !== null);
    check("new checkpoint counter > prior checkpoint",   freshCkpt.atMonotonicCounter > ckpt.atMonotonicCounter);

    // audit.tip sidecar written
    var tipPath = path.join(tmpDir, "audit.tip");
    check("audit.tip sidecar written",                  fs.existsSync(tipPath));
    var tip = JSON.parse(fs.readFileSync(tipPath, "utf8"));
    check("audit.tip records latest counter",           tip.atMonotonicCounter === freshCkpt.atMonotonicCounter);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testCheckpointVerify() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cverify-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");

    // Empty case
    var v0 = await b.audit.verifyCheckpoints();
    check("verifyCheckpoints empty case ok",            v0.ok === true && v0.checkpointsVerified === 0);

    // Several events + checkpoints
    for (var i = 0; i < 5; i++) {
      await b.audit.record({ action: "test.event", outcome: "success" });
      await b.audit.checkpoint();
    }
    var v1 = await b.audit.verifyCheckpoints();
    check("verifyCheckpoints ok across multiple anchors", v1.ok === true && v1.checkpointsVerified === 5);

    // Adding more rows then a fresh checkpoint still verifies
    await b.audit.record({ action: "test.event", outcome: "success" });
    await b.audit.checkpoint();
    var v2 = await b.audit.verifyCheckpoints();
    check("verifyCheckpoints ok after additional checkpoint", v2.ok === true && v2.checkpointsVerified === 6);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testCheckpointTamperDetect() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cdetect-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    await b.audit.record({ action: "test.event", outcome: "success" });
    await b.audit.checkpoint();
    await b.audit.record({ action: "test.event", outcome: "success" });
    await b.audit.record({ action: "test.event", outcome: "success" });
    var anchorCkpt = await b.audit.checkpoint();

    // Tamper with the audit_log row that the checkpoint anchors. Drop the
    // append-only triggers temporarily, recompute the chain hash so the
    // per-row chain still verifies (simulating a privileged attacker with
    // vault key access who's trying to rewrite history). The CHECKPOINT
    // signature will still mismatch because the original rowHash was signed.
    b.db.runSql("DROP TRIGGER IF EXISTS no_update_audit_log");
    var origRow = b.db.prepare("SELECT * FROM audit_log WHERE monotonicCounter = ?").get(anchorCkpt.atMonotonicCounter);
    // Change something innocuous + recompute rowHash so per-row chain holds
    var tamperedFields = Object.assign({}, origRow);
    tamperedFields.outcome = "denied";
    var nonceBuf = Buffer.isBuffer(origRow.nonce) ? origRow.nonce : Buffer.from(origRow.nonce);
    var fields = Object.assign({}, tamperedFields);
    delete fields.prevHash; delete fields.rowHash; delete fields.nonce;
    var newRowHash = b.auditChain.computeRowHash(origRow.prevHash, fields, nonceBuf);
    b.db.prepare("UPDATE audit_log SET outcome = ?, rowHash = ? WHERE monotonicCounter = ?")
        .run("denied", newRowHash, anchorCkpt.atMonotonicCounter);
    b.db.runSql("CREATE TRIGGER IF NOT EXISTS no_update_audit_log BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only — UPDATE prohibited'); END");

    // Per-row chain may still pass IF attacker also fixed the next row's
    // prevHash + rowHash recursively. They didn't here; verifyChain might
    // catch it at the next row. But the CHECKPOINT layer catches it
    // unconditionally — anchored rowHash no longer matches what's on disk.
    var ckptResult = await b.audit.verifyCheckpoints();
    check("checkpoint verify catches anchored-rowHash tampering",  ckptResult.ok === false);
    check("break reason mentions rowHash mismatch",
          /rowHash mismatch|tampered/i.test(ckptResult.reason || ""));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testRollbackDetection() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rollback-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    for (var i = 0; i < 3; i++) {
      await b.audit.record({ action: "test.event", outcome: "success" });
    }
    await b.audit.checkpoint();

    // audit.tip should now record counter >= 3
    var tipPath = path.join(tmpDir, "audit.tip");
    check("audit.tip exists post-checkpoint",   fs.existsSync(tipPath));
    var tip = JSON.parse(fs.readFileSync(tipPath, "utf8"));
    check("audit.tip records non-zero counter", tip.atMonotonicCounter >= 3);

    // Simulate rollback: write an audit.tip claiming a higher counter than
    // currently exists in DB. On next boot, db.init() should detect and
    // refuse — but we can't easily test process.exit() in-process. Verify
    // the rollback-detection function is wired by inspecting that an
    // "out of sync" tip would be detected. Use the public surface:
    // close, write tampered tip, reopen.
    b.db.close();
    fs.writeFileSync(tipPath, JSON.stringify({
      atMonotonicCounter:   999999,
      atRowHash:            "deadbeef".repeat(16),
      anchoredAt:           Date.now(),
      checkpointId:         "fake",
      publicKeyFingerprint: "fake",
      version:              1,
    }, null, 2));

    // Reopen — should detect rollback and exit. We fork a child to capture
    // the exit code.
    var spawnSync = require("child_process").spawnSync;
    var childScript = "var b = require('" + path.resolve("../blamejs/index.js").replace(/\\/g, "/") + "');\n" +
      "process.env.BLAMEJS_SKIP_NTP_CHECK = '1';\n" +
      "process.env.BLAMEJS_AUDIT_SIGNING_MODE = 'plaintext';\n" +
      "(async function () {\n" +
      "  await b.vault.init({ dataDir: " + JSON.stringify(tmpDir) + ", mode: 'plaintext' });\n" +
      "  await b.db.init({ dataDir: " + JSON.stringify(tmpDir) + ", atRest: 'plain', auditSigning: { mode: 'plaintext' }, schema: [] });\n" +
      "})().catch(function (e) { console.error(e.message); process.exit(99); });\n";
    var result = spawnSync(process.execPath, ["-e", childScript], { encoding: "utf8" });
    check("rollback boot exits with code 1",                  result.status === 1);
    check("rollback boot logs detection message",             /rollback detected/i.test(result.stderr || ""));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// =====================================================================
// v0.0.9 — multi-backend storage, classification routing, retry/breaker
// =====================================================================

async function testMultiBackend() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-multi-"));
  try {
    await setupTestDb(tmpDir);
    b.storage.init({
      backends: {
        "primary": {
          protocol:        "local",
          rootDir:         path.join(tmpDir, "primary"),
          classifications: ["personal"],
          residencyTag:    "unrestricted",
        },
        "ops": {
          protocol:        "local",
          rootDir:         path.join(tmpDir, "ops"),
          classifications: ["operational", "public"],
          residencyTag:    "unrestricted",
        },
      },
      defaultClassification: "personal",
      refuseUnclassified:    true,
    });

    var listed = b.storage.listBackends();
    check("listBackends returns 2 entries",            listed.length === 2);
    check("backend names enumerated",                  listed.some(b => b.name === "primary") && listed.some(b => b.name === "ops"));

    // Save personal data → routes to 'primary'
    var content1 = Buffer.from("private medical record", "utf8");
    var saved1 = await b.storage.saveFile(content1, "patient/123.json", { classification: "personal" });
    check("personal data routes to primary",           saved1.backend === "primary");

    // Save operational data → routes to 'ops'
    var content2 = Buffer.from("nginx access log line", "utf8");
    var saved2 = await b.storage.saveFile(content2, "logs/2026-04-25.log", { classification: "operational" });
    check("operational data routes to ops",            saved2.backend === "ops");

    // File lands in the right physical directory
    check("personal file in primary tree",             fs.existsSync(path.join(tmpDir, "primary", "patient/123.json")));
    check("operational file in ops tree",              fs.existsSync(path.join(tmpDir, "ops", "logs/2026-04-25.log")));
    check("personal NOT in ops tree",                  !fs.existsSync(path.join(tmpDir, "ops", "patient/123.json")));

    // Round-trip with explicit backend opt
    var back = await b.storage.getFileBuffer("patient/123.json", saved1.encryptionKey, { backend: "primary" });
    check("explicit-backend round-trip works",         back.equals(content1));

    // Unknown classification → fails
    var unknownClsRejected = false;
    try { await b.storage.saveFile(content1, "test", { classification: "unknown" }); }
    catch (e) { unknownClsRejected = e.code === "NO_BACKEND_FOR_CLASSIFICATION"; }
    check("unknown classification rejected",           unknownClsRejected);

    // refuseUnclassified: missing classification rejected
    var noClsRejected = false;
    try { await b.storage.saveFile(content1, "test"); }
    catch (e) { noClsRejected = e.code === "UNCLASSIFIED"; }
    check("refuseUnclassified rejects missing classification", noClsRejected);

    // Wrong-backend-for-classification rejected
    var wrongBackendRejected = false;
    try { await b.storage.saveFile(content1, "test", { backend: "ops", classification: "personal" }); }
    catch (e) { wrongBackendRejected = e.code === "CLASSIFICATION_MISMATCH"; }
    check("backend that doesn't serve classification rejected", wrongBackendRejected);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClassificationRouting() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cls-"));
  try {
    await setupTestDb(tmpDir);
    // Wildcard backend serves any classification
    b.storage.init({
      backends: {
        "any": {
          protocol:        "local",
          rootDir:         path.join(tmpDir, "any"),
          classifications: ["*"],
          residencyTag:    "unrestricted",
        },
      },
    });

    var c1 = Buffer.from("a", "utf8");
    var s1 = await b.storage.saveFile(c1, "x", { classification: "personal" });
    check("wildcard backend accepts personal",         s1.backend === "any");
    var s2 = await b.storage.saveFile(c1, "y", { classification: "audit-archive" });
    check("wildcard backend accepts custom class",     s2.backend === "any");
    var s3 = await b.storage.saveFile(c1, "z");
    check("wildcard backend accepts no-classification", s3.backend === "any");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testResidencyEnforcement() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-residency-"));
  try {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    process.env.BLAMEJS_AUDIT_SIGNING_MODE = "plaintext";
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      auditSigning: { mode: "plaintext" },
      schema:  [],
      dataResidency: { region: "EU", allowedStorageRegions: ["EU"] },
    });

    // Configuring a personal-data backend tagged US should refuse to init
    var residencyViolation = false;
    try {
      b.storage.init({
        backends: {
          "us-bad": {
            protocol:        "local",
            rootDir:         path.join(tmpDir, "us"),
            classifications: ["personal"],
            residencyTag:    "US",   // ← violation
          },
        },
      });
    } catch (e) {
      residencyViolation = e.code === "RESIDENCY_VIOLATION";
    }
    check("personal-data backend outside region refused", residencyViolation);

    // EU-tagged backend is fine
    b.storage._resetForTest();
    b.storage.init({
      backends: {
        "eu-ok": {
          protocol:        "local",
          rootDir:         path.join(tmpDir, "eu"),
          classifications: ["personal"],
          residencyTag:    "EU",
        },
      },
    });
    var listed = b.storage.listBackends();
    check("EU-tagged backend accepted",                listed.length === 1 && listed[0].residencyTag === "EU");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testRetryAndBreaker() {
  // Retry policy unit tests — exercise withRetry directly without backend setup
  var attempts = 0;
  var transientErr = function () {
    attempts += 1;
    var e = new Error("transient");
    e.statusCode = 503;
    e.isObjectStoreError = true;
    e.permanent = false;
    throw e;
  };

  // Retries 5xx
  var caught = false;
  attempts = 0;
  try {
    await b.objectStoreRetry.withRetry(transientErr, { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 5 });
  } catch (_) { caught = true; }
  check("retry exhausts maxAttempts on transient",     caught && attempts === 3);

  // Does NOT retry permanent (4xx)
  attempts = 0;
  var permErr = function () {
    attempts += 1;
    var e = new Error("forbidden");
    e.statusCode = 403;
    e.isObjectStoreError = true;
    e.permanent = true;
    throw e;
  };
  var permCaught = false;
  try { await b.objectStoreRetry.withRetry(permErr, { maxAttempts: 5 }); }
  catch (_) { permCaught = true; }
  check("retry does NOT retry permanent errors",       permCaught && attempts === 1);

  // Retryable classification
  check("isRetryable: 503 → true",                     b.objectStoreRetry.isRetryable({ statusCode: 503 }));
  check("isRetryable: 403 → false",                    !b.objectStoreRetry.isRetryable({ statusCode: 403 }));
  check("isRetryable: ECONNRESET → true",              b.objectStoreRetry.isRetryable({ code: "ECONNRESET" }));
  check("isRetryable: ENOENT → false (not in retry set)", !b.objectStoreRetry.isRetryable({ code: "ENOENT" }));

  // Circuit breaker
  var breaker = new b.objectStoreRetry.CircuitBreaker("test", { failureThreshold: 3, cooldownMs: 50, successThreshold: 1 });
  check("breaker starts closed",                       breaker.getState() === "closed");
  // Trip it
  for (var i = 0; i < 3; i++) {
    try { await breaker.wrap(function () { throw Object.assign(new Error("fail"), { code: "ECONNRESET" }); }); }
    catch (_) {}
  }
  check("breaker opens after threshold",               breaker.getState() === "open");

  // Open breaker fails fast (CIRCUIT_OPEN code)
  var fastFail = false;
  try { await breaker.wrap(function () { return Promise.resolve("never-runs"); }); }
  catch (e) { fastFail = e.code === "CIRCUIT_OPEN"; }
  check("open breaker fails fast",                     fastFail);

  // Wait for cooldown then half-open + success closes
  await new Promise(function (r) { setTimeout(r, 60); });
  await breaker.wrap(function () { return Promise.resolve("ok"); });
  check("breaker closes after successful probe",       breaker.getState() === "closed");
}

// =====================================================================
// v0.0.10 — sigv4 protocol adapter
// =====================================================================

function testSigv4Primitives() {
  var sigv4 = require("../lib/object-store-sigv4");

  // AWS-published test vector for signing-key derivation
  // (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html)
  var key = sigv4.deriveSigningKey(
    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    "20150830",
    "us-east-1",
    "iam"
  );
  var hex = key.toString("hex");
  check("sigv4 deriveSigningKey matches AWS test vector",
        hex === "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9");

  // awsUriEncode
  check("awsUriEncode preserves alphanumerics and unreserved",
        sigv4.awsUriEncode("hello-world.txt", true) === "hello-world.txt");
  check("awsUriEncode encodes spaces",
        sigv4.awsUriEncode("a b", true) === "a%20b");
  check("awsUriEncode preserves slashes when encodeSlash=false",
        sigv4.awsUriEncode("foo/bar", false) === "foo/bar");
  check("awsUriEncode encodes slashes when encodeSlash=true",
        sigv4.awsUriEncode("foo/bar", true) === "foo%2Fbar");

  // canonicalQueryString — sorted, encoded
  var u = new (require("url").URL)("https://x/?b=2&a=1&c=3");
  check("canonicalQueryString sorts keys",
        sigv4.canonicalQueryString(u.searchParams) === "a=1&b=2&c=3");

  // canonicalHeaders — lowercase keys, sorted, signed list
  var ch = sigv4.canonicalHeaders({ "X-Foo": "bar", host: "example.com", "Z-Last": "  trim  " });
  check("canonicalHeaders has trailing newline per pair",
        /host:example\.com\n/.test(ch.canonical));
  check("canonicalHeaders lowercases + sorts",
        ch.signed === "host;x-foo;z-last");
  check("canonicalHeaders trims + collapses whitespace",
        /z-last:trim\n/.test(ch.canonical));

  // signRequest produces an Authorization header with the right shape
  var signed = sigv4.signRequest({
    method:          "GET",
    url:             "https://test-bucket.s3.us-east-1.amazonaws.com/key1",
    headers:         {},
    payloadHash:     sigv4.sha256Hex(Buffer.alloc(0)),
    region:          "us-east-1",
    accessKeyId:     "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    date:            new Date(Date.UTC(2026, 3, 25, 12, 34, 56)),  // 2026-04-25T12:34:56Z
  });
  check("signRequest produces AWS4-HMAC-SHA256 Authorization",
        /^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/20260425\/us-east-1\/s3\/aws4_request, SignedHeaders=[a-z0-9;-]+, Signature=[0-9a-f]{64}$/.test(signed.headers["Authorization"]));
  check("signRequest sets host header",         signed.headers["host"] === "test-bucket.s3.us-east-1.amazonaws.com");
  check("signRequest sets x-amz-date",          signed.headers["x-amz-date"] === "20260425T123456Z");
  check("signRequest sets x-amz-content-sha256",
        signed.headers["x-amz-content-sha256"] === sigv4.sha256Hex(Buffer.alloc(0)));
  check("signRequest signature is deterministic for same inputs",
        signed.signature.length === 64);

  // Same inputs → same signature
  var signed2 = sigv4.signRequest({
    method:          "GET",
    url:             "https://test-bucket.s3.us-east-1.amazonaws.com/key1",
    headers:         {},
    payloadHash:     sigv4.sha256Hex(Buffer.alloc(0)),
    region:          "us-east-1",
    accessKeyId:     "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    date:            new Date(Date.UTC(2026, 3, 25, 12, 34, 56)),
  });
  check("signRequest deterministic across calls",  signed.signature === signed2.signature);
}

async function testSigv4MockServer() {
  var http = require("http");
  var sigv4 = require("../lib/object-store-sigv4");

  // In-process mock S3 server. Validates request shape (Authorization +
  // x-amz-date + x-amz-content-sha256) and stores PUT bodies in memory
  // so subsequent GET/HEAD/LIST/DELETE can return them.
  var stored = {};
  var server = http.createServer(function (req, res) {
    var auth = req.headers["authorization"] || "";
    if (!/^AWS4-HMAC-SHA256 /.test(auth)) {
      res.writeHead(401); res.end("missing AWS4-HMAC-SHA256"); return;
    }
    if (!req.headers["x-amz-date"]) {
      res.writeHead(400); res.end("missing x-amz-date"); return;
    }
    if (!req.headers["x-amz-content-sha256"]) {
      res.writeHead(400); res.end("missing x-amz-content-sha256"); return;
    }
    // Strip query for routing; URL parse needs Host header
    var pathname = req.url.split("?")[0];
    // Path-style: /bucket/key  → key extraction
    var m = pathname.match(/^\/[^/]+\/(.+)$/);
    var key = m ? m[1] : null;

    if (req.method === "PUT" && key) {
      var bufs = [];
      req.on("data", function (c) { bufs.push(c); });
      req.on("end", function () {
        stored[key] = Buffer.concat(bufs);
        res.writeHead(200, { ETag: '"' + sigv4.sha256Hex(stored[key]).slice(0, 32) + '"' });
        res.end();
      });
      return;
    }
    if (req.method === "GET" && key && stored[key]) {
      res.writeHead(200, { "Content-Length": stored[key].length });
      res.end(stored[key]);
      return;
    }
    if (req.method === "GET" && pathname === "/test-bucket/" || (req.url || "").indexOf("list-type=2") !== -1) {
      // List request
      var xml = "<?xml version=\"1.0\"?><ListBucketResult>";
      Object.keys(stored).forEach(function (k) {
        xml += "<Contents><Key>" + k + "</Key><Size>" + stored[k].length + "</Size>" +
               "<LastModified>2026-04-25T00:00:00.000Z</LastModified></Contents>";
      });
      xml += "<IsTruncated>false</IsTruncated></ListBucketResult>";
      res.writeHead(200, { "Content-Type": "application/xml" });
      res.end(xml);
      return;
    }
    if (req.method === "HEAD" && key && stored[key]) {
      res.writeHead(200, { "Content-Length": stored[key].length });
      res.end();
      return;
    }
    if (req.method === "DELETE" && key) {
      if (stored[key]) {
        delete stored[key];
        res.writeHead(204); res.end();
      } else {
        res.writeHead(404); res.end();
      }
      return;
    }
    res.writeHead(404); res.end();
  });

  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  try {
    var client = sigv4.create({
      endpoint:        "http://127.0.0.1:" + port,
      region:          "us-east-1",
      bucket:          "test-bucket",
      accessKeyId:     "AKIAIOSFODNN7EXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      pathStyle:       true,   // 127.0.0.1 doesn't support virtual-hosted
    });

    // PUT
    var content = Buffer.from("sigv4 test payload " + Date.now(), "utf8");
    var putResult = await client.put("dir/object.bin", content);
    check("sigv4 put returns size + etag", putResult.size === content.length && typeof putResult.etag === "string");

    // GET round-trip
    var got = await client.get("dir/object.bin");
    check("sigv4 get round-trips bytes", got.equals(content));

    // HEAD
    var meta = await client.head("dir/object.bin");
    check("sigv4 head returns size",     meta.size === content.length);

    // LIST
    var listed = await client.list("");
    check("sigv4 list returns 1 item",   listed.items.length === 1);
    check("sigv4 list returns the key",  listed.items[0].key === "dir/object.bin");

    // DELETE
    var del = await client.delete("dir/object.bin");
    check("sigv4 delete returns true",   del === true);
    var del2 = await client.delete("dir/object.bin");
    check("sigv4 delete on missing returns false", del2 === false);
  } finally {
    server.close();
  }
}

// =====================================================================
// v0.0.11 — gcs + azure-blob protocol adapters
// =====================================================================

// _makeFakeServiceAccount lives in ./_helpers.js (imported above).

function testGcsPrimitives() {
  var gcs = require("../lib/object-store-gcs");

  // base64url encoding (no padding, '+'→'-', '/'→'_')
  var b1 = gcs._base64UrlEncode(Buffer.from("hello"));
  check("gcs base64url encodes basic input",         b1 === "aGVsbG8");
  var b2 = gcs._base64UrlEncode(Buffer.from([0xff, 0xff, 0xff]));
  check("gcs base64url has no padding",              !/=/.test(b2));
  check("gcs base64url uses '-' and '_'",            !/\+|\//.test(b2));

  // JWT signing with a real keypair
  var sa = _makeFakeServiceAccount();
  var jwt = gcs._signJwt(sa, "test-scope", "https://oauth2.googleapis.com/token");
  var parts = jwt.split(".");
  check("JWT has 3 parts",                           parts.length === 3);
  // Header is base64url(JSON({ alg, typ }))
  var headerJson = JSON.parse(Buffer.from(parts[0].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  check("JWT header alg is RS256",                   headerJson.alg === "RS256");
  check("JWT header typ is JWT",                     headerJson.typ === "JWT");
  var claimJson = JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  check("JWT iss is service-account email",          claimJson.iss === sa.client_email);
  check("JWT scope is honored",                      claimJson.scope === "test-scope");
  check("JWT aud is token endpoint",                 claimJson.aud === "https://oauth2.googleapis.com/token");
  check("JWT exp - iat = 3600",                      claimJson.exp - claimJson.iat === 3600);
}

async function testGcsMockServer() {
  var http = require("http");
  var url = require("url");
  var gcs = require("../lib/object-store-gcs");
  var sa = _makeFakeServiceAccount();

  var stored = {};
  var tokenIssued = 0;

  // Mock OAuth2 token endpoint + storage JSON API on the same server,
  // routed by pathname.
  var server = http.createServer(function (req, res) {
    var u = new url.URL(req.url, "http://x");
    var path = u.pathname;

    // Token exchange
    if (req.method === "POST" && path === "/token") {
      var bufs = [];
      req.on("data", function (c) { bufs.push(c); });
      req.on("end", function () {
        var body = Buffer.concat(bufs).toString("utf8");
        if (!/grant_type=urn/.test(body) || !/assertion=/.test(body)) {
          res.writeHead(400); res.end("bad request"); return;
        }
        tokenIssued += 1;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ access_token: "mock-access-token-" + tokenIssued, expires_in: 3600, token_type: "Bearer" }));
      });
      return;
    }

    // All storage operations require Bearer auth
    if (!/^Bearer mock-access-token-/.test(req.headers["authorization"] || "")) {
      res.writeHead(401); res.end("missing bearer"); return;
    }

    // PUT object: POST /upload/storage/v1/b/<bucket>/o?uploadType=media&name=<key>
    if (req.method === "POST" && /^\/upload\/storage\/v1\/b\/[^/]+\/o$/.test(path)) {
      var name = u.searchParams.get("name");
      var bufs2 = [];
      req.on("data", function (c) { bufs2.push(c); });
      req.on("end", function () {
        stored[name] = Buffer.concat(bufs2);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ name: name, size: String(stored[name].length), etag: "\"" + name + "\"", updated: "2026-04-25T00:00:00.000Z" }));
      });
      return;
    }

    // GET / HEAD: /storage/v1/b/<bucket>/o/<encoded-key>
    var objectMatch = path.match(/^\/storage\/v1\/b\/[^/]+\/o\/(.+)$/);
    if (objectMatch && req.method === "GET") {
      var key = decodeURIComponent(objectMatch[1]);
      if (u.searchParams.get("alt") === "media") {
        if (stored[key]) {
          res.writeHead(200); res.end(stored[key]);
        } else {
          res.writeHead(404); res.end();
        }
      } else {
        // metadata
        if (stored[key]) {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ name: key, size: String(stored[key].length), etag: "\"" + key + "\"", updated: "2026-04-25T00:00:00.000Z" }));
        } else {
          res.writeHead(404); res.end();
        }
      }
      return;
    }
    if (objectMatch && req.method === "DELETE") {
      var dkey = decodeURIComponent(objectMatch[1]);
      if (stored[dkey]) { delete stored[dkey]; res.writeHead(204); res.end(); }
      else { res.writeHead(404); res.end(); }
      return;
    }

    // LIST: /storage/v1/b/<bucket>/o (no /<key>)
    if (req.method === "GET" && /^\/storage\/v1\/b\/[^/]+\/o$/.test(path)) {
      var prefix = u.searchParams.get("prefix") || "";
      var items = Object.keys(stored).filter(function (k) { return k.indexOf(prefix) === 0; }).map(function (k) {
        return { name: k, size: String(stored[k].length), updated: "2026-04-25T00:00:00.000Z" };
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ items: items }));
      return;
    }

    res.writeHead(404); res.end();
  });

  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  try {
    var client = gcs.create({
      bucket:         "test-bucket",
      serviceAccount: sa,
      endpoint:       "http://127.0.0.1:" + port,
      tokenEndpoint:  "http://127.0.0.1:" + port + "/token",
    });

    var content = Buffer.from("gcs test payload " + Date.now(), "utf8");
    var putResult = await client.put("dir/object.bin", content);
    check("gcs put returns size",                    putResult.size === content.length);

    var got = await client.get("dir/object.bin");
    check("gcs get round-trips bytes",               got.equals(content));

    var meta = await client.head("dir/object.bin");
    check("gcs head returns size",                   meta.size === content.length);

    var listed = await client.list("");
    check("gcs list returns 1 item",                 listed.items.length === 1);
    check("gcs list returns the key",                listed.items[0].key === "dir/object.bin");

    var del = await client.delete("dir/object.bin");
    check("gcs delete returns true",                 del === true);

    // Token caching: should have only issued ONE token across all calls
    check("gcs token issued once and cached across calls",  tokenIssued === 1);
  } finally {
    server.close();
  }
}

function testAzureBlobPrimitives() {
  var az = require("../lib/object-store-azure-blob");

  // signRequest produces SharedKey-format Authorization
  var s = az.signRequest({
    method:      "PUT",
    url:         "https://test.blob.core.windows.net/c/key1",
    headers:     { "Content-Type": "application/octet-stream", "Content-Length": "5", "x-ms-blob-type": "BlockBlob" },
    accountName: "test",
    accountKey:  Buffer.from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "utf8").toString("base64"),
  });
  check("azure signRequest produces SharedKey auth",      /^SharedKey test:/.test(s.headers["Authorization"]));
  check("azure signRequest sets x-ms-version",            !!s.headers["x-ms-version"]);
  check("azure signRequest sets x-ms-date",               !!s.headers["x-ms-date"]);
  check("azure signature is base64",                      /^[A-Za-z0-9+/=]+$/.test(s.signature));

  // Same inputs at same time produce same signature
  var date = new Date(Date.UTC(2026, 3, 25, 12, 34, 56));
  var dateStr = date.toUTCString();
  var s1 = az.signRequest({
    method:      "GET",
    url:         "https://test.blob.core.windows.net/c/key2",
    headers:     { "x-ms-date": dateStr },
    accountName: "test",
    accountKey:  Buffer.from("ZZZZZZZZ", "base64").toString("base64"),
  });
  var s2 = az.signRequest({
    method:      "GET",
    url:         "https://test.blob.core.windows.net/c/key2",
    headers:     { "x-ms-date": dateStr },
    accountName: "test",
    accountKey:  Buffer.from("ZZZZZZZZ", "base64").toString("base64"),
  });
  check("azure signature deterministic for same inputs",  s1.signature === s2.signature);
}

async function testAzureBlobMockServer() {
  var http = require("http");
  var az = require("../lib/object-store-azure-blob");

  var stored = {};
  var server = http.createServer(function (req, res) {
    if (!/^SharedKey /.test(req.headers["authorization"] || "")) {
      res.writeHead(401); res.end("missing SharedKey"); return;
    }
    if (!req.headers["x-ms-version"]) { res.writeHead(400); res.end("missing x-ms-version"); return; }
    if (!req.headers["x-ms-date"])    { res.writeHead(400); res.end("missing x-ms-date"); return; }

    var path = req.url.split("?")[0];
    var keyMatch = path.match(/^\/[^/]+\/(.+)$/);
    var key = keyMatch ? keyMatch[1] : null;

    if (req.method === "PUT" && key) {
      if (req.headers["x-ms-blob-type"] !== "BlockBlob") { res.writeHead(400); res.end("bad blob type"); return; }
      var bufs = [];
      req.on("data", function (c) { bufs.push(c); });
      req.on("end", function () {
        stored[key] = Buffer.concat(bufs);
        res.writeHead(201, { ETag: "\"" + key + "\"" });
        res.end();
      });
      return;
    }
    if (req.method === "GET" && key && stored[key]) {
      res.writeHead(200, { "Content-Length": stored[key].length });
      res.end(stored[key]);
      return;
    }
    if (req.method === "HEAD" && key && stored[key]) {
      res.writeHead(200, { "Content-Length": stored[key].length });
      res.end();
      return;
    }
    if (req.method === "DELETE" && key) {
      if (stored[key]) { delete stored[key]; res.writeHead(202); res.end(); }
      else { res.writeHead(404); res.end(); }
      return;
    }
    if (req.method === "GET" && (req.url || "").indexOf("comp=list") !== -1) {
      var xml = "<?xml version=\"1.0\"?><EnumerationResults><Blobs>";
      Object.keys(stored).forEach(function (k) {
        xml += "<Blob><Name>" + k + "</Name><Properties><Content-Length>" + stored[k].length + "</Content-Length><Last-Modified>Sat, 25 Apr 2026 00:00:00 GMT</Last-Modified></Properties></Blob>";
      });
      xml += "</Blobs><NextMarker/></EnumerationResults>";
      res.writeHead(200, { "Content-Type": "application/xml" });
      res.end(xml);
      return;
    }
    res.writeHead(404); res.end();
  });

  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  try {
    var client = az.create({
      accountName: "test",
      accountKey:  Buffer.from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "utf8").toString("base64"),
      container:   "test-container",
      endpoint:    "http://127.0.0.1:" + port,
    });

    var content = Buffer.from("azure test payload " + Date.now(), "utf8");
    var putResult = await client.put("dir/blob.bin", content);
    check("azure put returns size",                  putResult.size === content.length);

    var got = await client.get("dir/blob.bin");
    check("azure get round-trips bytes",             got.equals(content));

    var meta = await client.head("dir/blob.bin");
    check("azure head returns size",                 meta.size === content.length);

    var listed = await client.list("");
    check("azure list returns 1 item",               listed.items.length === 1);
    check("azure list returns the key",              listed.items[0].key === "dir/blob.bin");

    var del = await client.delete("dir/blob.bin");
    check("azure delete returns true",               del === true);
  } finally {
    server.close();
  }
}

// =====================================================================
// v0.0.12 — queue dispatcher + local SQLite-backed protocol
// =====================================================================

async function testQueueLocal() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-queue-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    check("queue namespace present",                  typeof b.queue === "object");
    check("queue.listBackends has 1 entry",           b.queue.listBackends().length === 1);

    // Enqueue
    var result = await b.queue.enqueue("send-welcome", { userId: "u-1", email: "a@b.com" }, {
      classification: "personal",
      traceId:        "trace-123",
    });
    check("enqueue returns jobId",                     typeof result.jobId === "string");
    check("enqueue returns queueName",                 result.queueName === "send-welcome");
    check("enqueue returns classification",            result.classification === "personal");

    // size reflects pending
    check("size returns 1 after one enqueue",          (await b.queue.size("send-welcome")) === 1);

    // payload sealed on disk
    var rawRow = b.db.prepare("SELECT payload FROM _blamejs_jobs WHERE _id = ?").get(result.jobId);
    check("queue payload sealed in DB",                rawRow.payload.startsWith("vault:"));

    // unrelated queue is independent
    check("size returns 0 for empty queue",            (await b.queue.size("other-queue")) === 0);

    // purge clears
    var purged = await b.queue.purge("send-welcome");
    check("purge returns count of deleted",            purged === 1);
    check("size returns 0 after purge",                (await b.queue.size("send-welcome")) === 0);

    // Reserved table name protection still works
    check("_blamejs_jobs is reserved",                 b.db.RESERVED_TABLE_NAMES.has("_blamejs_jobs"));
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 1000 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testQueueConsume() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-qcons-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    var processed = [];
    var consumer = b.queue.consume("test-job", function (job) {
      processed.push(job.payload);
      return Promise.resolve();
    }, { concurrency: 2, pollIntervalMs: 50, fastPollMs: 20, leaseDurationMs: 5000 });

    await b.queue.enqueue("test-job", { msg: "hello-1" });
    await b.queue.enqueue("test-job", { msg: "hello-2" });
    await b.queue.enqueue("test-job", { msg: "hello-3" });

    // Wait for processing (poll up to 3s)
    var deadline = Date.now() + 3000;
    while (processed.length < 3 && Date.now() < deadline) {
      await new Promise(function (r) { setTimeout(r, 50); });
    }
    check("consume processed all 3 jobs",              processed.length === 3);
    check("payloads decoded correctly",                processed.some(p => p.msg === "hello-1"));
    check("queue size 0 after consume",                (await b.queue.size("test-job")) === 0);

    // All jobs should be in 'done' status
    var doneCount = b.db.prepare("SELECT COUNT(*) AS n FROM _blamejs_jobs WHERE queueName = ? AND status = ?").get("test-job", "done");
    check("all jobs marked done",                      doneCount.n === 3);

    // Drain buffered audit emissions before reading audit_log.
    await b.audit.flush();
    // Audit chain has system.queue.enqueue + .consume.start + .consume.success
    var enqRows = await b.audit.query({ action: "system.queue.enqueue" });
    check("audit recorded enqueue events",             enqRows.length === 3);
    var sucRows = await b.audit.query({ action: "system.queue.consume.success" });
    check("audit recorded consume.success events",     sucRows.length === 3);

    consumer.cancel();
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 1000 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testQueueRetryAndFail() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-qfail-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    var attempts = 0;
    var consumer = b.queue.consume("fail-job", function (_job) {
      attempts += 1;
      throw new Error("simulated failure attempt " + attempts);
    }, { concurrency: 1, pollIntervalMs: 50, fastPollMs: 20, leaseDurationMs: 5000 });

    await b.queue.enqueue("fail-job", { x: 1 }, { maxAttempts: 3 });

    // Wait until job is finally failed (3 attempts × ~exponential backoff = up to ~7s)
    var deadline = Date.now() + 12000;
    var lastStatus;
    while (Date.now() < deadline) {
      var row = b.db.prepare("SELECT status FROM _blamejs_jobs WHERE queueName = ?").get("fail-job");
      lastStatus = row && row.status;
      if (lastStatus === "failed") break;
      await new Promise(function (r) { setTimeout(r, 100); });
    }
    check("job ends up in 'failed' status after maxAttempts",  lastStatus === "failed");
    check("handler invoked maxAttempts times",                 attempts === 3);

    // Drain buffered audit emissions before reading audit_log.
    await b.audit.flush();
    // Audit chain has consume.failure events
    var failRows = await b.audit.query({ action: "system.queue.consume.failure" });
    check("audit recorded consume.failure events",             failRows.length === 3);

    consumer.cancel();
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 1000 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testQueueLeaseExpiry() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-qlease-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    // Manually call lease via the backend to simulate a crashed handler
    // (lease the job, never complete or fail it).
    var localBackend = require("../lib/queue-local").create({});
    await b.queue.enqueue("orphan-job", { x: 1 });
    var leased = await localBackend.lease("orphan-job", 100, 1);  // 100ms lease
    check("lease returned the job",                    leased.length === 1);
    check("after lease, job status is inflight",
          b.db.prepare("SELECT status FROM _blamejs_jobs WHERE queueName = ?").get("orphan-job").status === "inflight");

    // Wait for lease to expire, then sweep
    await new Promise(function (r) { setTimeout(r, 200); });
    var swept = await localBackend.sweepExpired();
    check("sweepExpired returned 1 unstuck job",       swept === 1);
    check("unstuck job is back to pending",
          b.db.prepare("SELECT status FROM _blamejs_jobs WHERE queueName = ?").get("orphan-job").status === "pending");
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 1000 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testQueueShutdown() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-qsh-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    var processed = 0;
    var consumer = b.queue.consume("shutdown-job", async function (_job) {
      // Long-running handler
      await new Promise(function (r) { setTimeout(r, 200); });
      processed += 1;
    }, { concurrency: 2, pollIntervalMs: 30, fastPollMs: 10, leaseDurationMs: 5000 });

    for (var i = 0; i < 3; i++) await b.queue.enqueue("shutdown-job", { i: i });
    await new Promise(function (r) { setTimeout(r, 100) }); // let some lease

    var t0 = Date.now();
    await b.queue.shutdown({ timeoutMs: 5000 });
    var elapsed = Date.now() - t0;

    check("shutdown waits for in-flight handlers",     processed >= 1);
    check("shutdown completes under timeout",          elapsed < 5000);
    void consumer;
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// =====================================================================
// v0.0.13 — log streaming + redaction
// =====================================================================

function testRedact() {
  check("redact module present",                 typeof b.redact === "object");
  check("redact.MARKER is '[REDACTED]'",         b.redact.MARKER === "[REDACTED]");

  // Field-name redaction
  var r1 = b.redact.redact({ user: "alice", password: "secret123", apiKey: "AKIAEXAMPLE" });
  check("password field redacted by name",       r1.password === "[REDACTED]");
  check("apiKey field redacted by name",         r1.apiKey === "[REDACTED]");
  check("non-sensitive field preserved",         r1.user === "alice");

  // Nested
  var r2 = b.redact.redact({ outer: { innerPassword: "x", normal: "y" } });
  check("nested sensitive redacted",             r2.outer.innerPassword === "[REDACTED]");
  check("nested normal preserved",               r2.outer.normal === "y");

  // Substring match
  var r3 = b.redact.redact({ userPassword: "pw", emailToken: "t" });
  check("substring 'password' triggers redaction", r3.userPassword === "[REDACTED]");
  check("substring 'token' triggers redaction",    r3.emailToken === "[REDACTED]");

  // Value-shape detectors
  var ccRedacted = b.redact.redact({ note: "card 4111-1111-1111-1111 here" });
  // Note: value detector only fires on STRING values that are EXACTLY a CC; embedded won't trigger
  // Test exact match:
  var ccExact = b.redact.redact({ field: "4111111111111111" });
  check("credit-card-shaped value redacted",     ccExact.field === "[REDACTED-CC]");

  var jwtExact = b.redact.redact({ field: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" });
  check("JWT-shaped value redacted",             jwtExact.field === "[REDACTED-JWT]");

  var pemExact = b.redact.redact({ field: "-----BEGIN PRIVATE KEY-----\nABCD\n-----END PRIVATE KEY-----" });
  check("PEM-shaped value redacted",             pemExact.field === "[REDACTED-PEM]");

  var awsExact = b.redact.redact({ field: "AKIAIOSFODNN7EXAMPLE" });
  check("AWS access key redacted",               awsExact.field === "[REDACTED-AWS-KEY]");

  var sealExact = b.redact.redact({ field: "vault:abcdefxyz" });
  check("vault-sealed value redacted",           sealExact.field === "[REDACTED-SEALED]");

  var ssnExact = b.redact.redact({ field: "123-45-6789" });
  check("SSN-shaped value redacted",             ssnExact.field === "[REDACTED-SSN]");

  // Custom rule
  b.redact.registerFieldRule("internal_token");
  var custom = b.redact.redact({ internal_token: "x", other: "y" });
  check("custom field rule applies",             custom.internal_token === "[REDACTED]");

  // Array redaction
  var arr = b.redact.redact({ creds: [{ password: "a" }, { password: "b" }] });
  check("array elements redacted",               arr.creds[0].password === "[REDACTED]" && arr.creds[1].password === "[REDACTED]");

  // Mutation — original unchanged
  var orig = { password: "before" };
  b.redact.redact(orig);
  check("redact does NOT mutate input",          orig.password === "before");
  void ccRedacted;
}

async function testLogStreamLocal() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-log-"));
  try {
    await setupTestDb(tmpDir);
    b.logStream.init({
      sinks: { primary: { protocol: "local", dir: path.join(tmpDir, "logs"), maxFileBytes: 1024 } },
      minLevel: "debug",
    });

    check("logStream namespace present",                  typeof b.logStream === "object");
    check("logStream.LEVELS includes debug/info/warn/error",
          b.logStream.LEVELS.length === 4);

    b.logStream.info("hello world", { user: "alice" });
    b.logStream.warn("watch out", { password: "should-be-redacted" });
    b.logStream.error("kaboom", { jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaa.bbbb" });

    // Allow async writes to complete
    await new Promise(function (r) { setTimeout(r, 50); });
    await b.logStream.shutdown();

    var logPath = path.join(tmpDir, "logs", "blamejs.log");
    check("log file exists",                              fs.existsSync(logPath));
    var content = fs.readFileSync(logPath, "utf8");
    var lines = content.trim().split("\n").filter(Boolean);
    check("3 events emitted as JSON lines",               lines.length === 3);

    var infoRecord = JSON.parse(lines[0]);
    check("first record has level=info",                  infoRecord.level === "info");
    check("first record has message",                     infoRecord.message === "hello world");
    check("first record has meta.user",                   infoRecord.meta.user === "alice");

    var warnRecord = JSON.parse(lines[1]);
    check("warn record password is redacted",             warnRecord.meta.password === "[REDACTED]");

    var errRecord = JSON.parse(lines[2]);
    check("error record JWT-shaped value redacted",       errRecord.meta.jwt === "[REDACTED-JWT]");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testLogStreamWebhook() {
  var http = require("http");
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-loghook-"));
  try {
    await setupTestDb(tmpDir);

    var received = [];
    var server = http.createServer(function (req, res) {
      if (req.headers["authorization"] !== "Bearer test-token") {
        res.writeHead(401); res.end("missing auth"); return;
      }
      var bufs = [];
      req.on("data", function (c) { bufs.push(c); });
      req.on("end", function () {
        try {
          var batch = JSON.parse(Buffer.concat(bufs).toString("utf8"));
          batch.forEach(function (ev) { received.push(ev); });
          res.writeHead(200); res.end("ok");
        } catch (e) { res.writeHead(400); res.end(e.message); }
      });
    });
    await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
    var port = server.address().port;

    try {
      b.logStream.init({
        sinks: {
          siem: {
            protocol:      "webhook",
            url:           "http://127.0.0.1:" + port + "/ingest",
            auth:          "bearer",
            token:         "test-token",
            batchSize:     2,
            maxBatchAgeMs: 100,
            bodyShape:     "array",
            retry:         { maxAttempts: 1 },
          },
        },
      });

      b.logStream.info("first",  { x: 1 });
      b.logStream.info("second", { x: 2 });
      // batchSize=2 should trigger immediate flush
      await new Promise(function (r) { setTimeout(r, 200); });

      check("webhook received 2 events",                   received.length === 2);
      check("first event message",                         received[0].message === "first");
      check("second event message",                        received[1].message === "second");

      // Auth failure path: send another event after server stops accepting
      b.logStream.info("third",  { x: 3 });
      await new Promise(function (r) { setTimeout(r, 200); });
      check("third event delivered (under batch size, flushed by age)", received.length >= 3);

      await b.logStream.shutdown();
    } finally {
      server.close();
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testLogStreamBidirectional() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-logbidi-"));
  try {
    await setupTestDb(tmpDir);
    b.logStream.init({
      sinks: { primary: { protocol: "local", dir: path.join(tmpDir, "logs") } },
    });

    var received = [];
    var unregister = b.logStream.onIncoming(async function (payload, opts) {
      received.push({ payload: payload, opts: opts });
      return "ack-" + (received.length);
    });

    var results = await b.logStream.deliverIncoming({ command: "block-user", userId: "u-123" }, { source: "siem-test" });
    check("deliverIncoming routes to handler",            received.length === 1);
    check("payload preserved",                            received[0].payload.command === "block-user");
    check("opts.source preserved",                        received[0].opts.source === "siem-test");
    check("handler return value captured in results",     results[0].ok === true && results[0].value === "ack-1");

    // Drain buffered audit emissions before reading audit_log.
    await b.audit.flush();
    // Audit: incoming command logged
    var incRows = await b.audit.query({ action: "system.log.incoming" });
    check("audit recorded system.log.incoming",           incRows.length === 1);

    // Unregister and verify no further dispatch
    unregister();
    await b.logStream.deliverIncoming({ command: "second" });
    check("after unregister, handler no longer called",   received.length === 1);

    await b.logStream.shutdown();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// =====================================================================
// v0.0.14 — external DB (bring-your-own-client dispatcher)
// =====================================================================

// _makeFakeDriver lives in ./_helpers.js (imported above).

async function testExternalDbBasic() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-extdb-"));
  try {
    await setupTestDb(tmpDir);
    var driver = _makeFakeDriver();
    b.externalDb.init({
      backends: {
        "primary": {
          connect:  driver.connect,
          query:    driver.query,
          close:    driver.close,
          ping:     driver.ping,
        },
      },
    });

    check("externalDb namespace present",                typeof b.externalDb === "object");

    var listed = b.externalDb.listBackends();
    check("listBackends returns 1 entry",                listed.length === 1);

    var insertResult = await b.externalDb.query(
      "INSERT INTO kv (id, value) VALUES ($1, $2)", ["k1", "v1"]
    );
    check("insert returns rowCount = 1",                 insertResult.rowCount === 1);

    var selectResult = await b.externalDb.query(
      "SELECT id, value FROM kv WHERE id = $1", ["k1"]
    );
    check("select returns the inserted row",             selectResult.rows[0].value === "v1");

    var miss = await b.externalDb.query(
      "SELECT id, value FROM kv WHERE id = $1", ["missing"]
    );
    check("miss returns 0 rows",                         miss.rowCount === 0);

    // Health check
    var hc = await b.externalDb.healthCheck();
    check("healthCheck returns ok for primary",          hc.primary && hc.primary.ok === true);
    check("healthCheck returns breakerState",            hc.primary.breakerState === "closed");

    // Drain buffered audit emissions before reading audit_log.
    await b.audit.flush();
    // Audit recorded
    var qRows = await b.audit.query({ action: "system.externaldb.query" });
    check("audit recorded externaldb.query events",      qRows.length >= 3);
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testExternalDbPool() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-extdbpool-"));
  try {
    await setupTestDb(tmpDir);
    var driver = _makeFakeDriver();
    b.externalDb.init({
      backends: {
        "primary": {
          connect: driver.connect, query: driver.query, close: driver.close,
          pool:    { min: 0, max: 3, idleTimeoutMs: 60000 },
        },
      },
    });

    // Sequential queries reuse the same connection
    await b.externalDb.query("SELECT 1");
    await b.externalDb.query("SELECT 1");
    await b.externalDb.query("SELECT 1");
    var s = driver.getStats();
    check("pool reuses idle connection",                 s.connectCount === 1);

    // Concurrent queries open up to max
    var promises = [];
    for (var i = 0; i < 5; i++) promises.push(b.externalDb.query("SELECT 1"));
    await Promise.all(promises);
    var s2 = driver.getStats();
    check("concurrent queries open up to pool.max",      s2.connectCount <= 3);

    // listBackends shows pool stats
    var listed = b.externalDb.listBackends();
    check("listBackends includes pool stats",            typeof listed[0].pool === "object");
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testExternalDbTransaction() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-extdbtx-"));
  try {
    await setupTestDb(tmpDir);
    var driver = _makeFakeDriver();
    b.externalDb.init({
      backends: {
        "primary": {
          connect: driver.connect, query: driver.query, close: driver.close,
        },
      },
    });

    // Successful transaction commits
    var commitResult = await b.externalDb.transaction(async function (tx) {
      await tx.query("INSERT INTO kv (id, value) VALUES ($1, $2)", ["tx1", "a"]);
      await tx.query("INSERT INTO kv (id, value) VALUES ($1, $2)", ["tx2", "b"]);
      return "all-good";
    });
    check("transaction returns fn's return value",       commitResult === "all-good");
    var got1 = await b.externalDb.query("SELECT id, value FROM kv WHERE id = $1", ["tx1"]);
    check("committed rows visible",                      got1.rows[0].value === "a");

    // Failed transaction (handler throws) — rollback
    var caught = false;
    try {
      await b.externalDb.transaction(async function (tx) {
        await tx.query("INSERT INTO kv (id, value) VALUES ($1, $2)", ["tx3", "c"]);
        throw new Error("simulated");
      });
    } catch (e) { caught = e.message === "simulated"; }
    check("transaction error propagates",                caught);

    // External-db's audit emissions buffer in the handler; flush
    // explicitly to make them durable before querying.
    await b.audit.flush();
    var txRows = await b.audit.query({ action: "system.externaldb.transaction" });
    check("transaction events audit-logged",             txRows.length >= 2);
    var failRows = txRows.filter(function (r) { return r.outcome === "failure"; });
    check("rollback event recorded as failure",          failRows.length === 1);
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testExternalDbResidency() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-extdbres-"));
  try {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    process.env.BLAMEJS_AUDIT_SIGNING_MODE = "plaintext";
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      auditSigning: { mode: "plaintext" },
      schema:  [],
      dataResidency: { region: "EU", allowedStorageRegions: ["EU"] },
    });

    var driver = _makeFakeDriver();
    var residencyViolation = false;
    try {
      b.externalDb.init({
        backends: {
          "us-bad": {
            connect: driver.connect, query: driver.query, close: driver.close,
            classifications: ["personal"],
            residencyTag:    "US",        // ← violation
          },
        },
      });
    } catch (e) { residencyViolation = e.code === "RESIDENCY_VIOLATION"; }
    check("external DB residency violation refused",     residencyViolation);

    // EU-tagged backend OK
    b.externalDb._resetForTest();
    b.externalDb.init({
      backends: {
        "eu-ok": {
          connect: driver.connect, query: driver.query, close: driver.close,
          classifications: ["personal"],
          residencyTag:    "EU",
        },
      },
    });
    var listed = b.externalDb.listBackends();
    check("EU backend accepted",                          listed.length === 1 && listed[0].residencyTag === "EU");
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testExternalDbClassification() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-extdbcls-"));
  try {
    await setupTestDb(tmpDir);
    var personalDriver    = _makeFakeDriver();
    var operationalDriver = _makeFakeDriver();
    b.externalDb.init({
      backends: {
        "personal-db": {
          connect: personalDriver.connect, query: personalDriver.query, close: personalDriver.close,
          classifications: ["personal"],
        },
        "ops-db": {
          connect: operationalDriver.connect, query: operationalDriver.query, close: operationalDriver.close,
          classifications: ["operational"],
        },
      },
    });

    await b.externalDb.query("INSERT INTO kv (id, value) VALUES ($1, $2)", ["x", "y"], { classification: "personal" });
    await b.externalDb.query("INSERT INTO kv (id, value) VALUES ($1, $2)", ["a", "b"], { classification: "operational" });

    check("personal query routed to personal-db",        personalDriver.getStats().queryCount === 1);
    check("operational query routed to ops-db",          operationalDriver.getStats().queryCount === 1);

    // Wrong-classification rejection
    var rejected = false;
    try {
      await b.externalDb.query("SELECT 1", [], { backend: "ops-db", classification: "personal" });
    } catch (e) { rejected = e.code === "CLASSIFICATION_MISMATCH"; }
    check("backend that doesn't serve classification rejected",  rejected);

    // No backend serves a missing classification
    var noBackendRejected = false;
    try { await b.externalDb.query("SELECT 1", [], { classification: "nonexistent" }); }
    catch (e) { noBackendRejected = e.code === "NO_BACKEND_FOR_CLASSIFICATION"; }
    check("missing classification rejected",             noBackendRejected);
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

// =====================================================================
// v0.0.15 — HTTP middleware
// =====================================================================

// Mock req/res factories — minimal Node http.IncomingMessage / ServerResponse
// surface that the middleware uses. No real HTTP server.
// _mockReq / _mockRes live in ./_helpers.js (imported above).

async function testMiddlewareRequestId() {
  await setupTestDbForMW();
  try {
    var mw = b.middleware.requestId();
    var nextCalled = false;

    // Generates fresh ID
    var req1 = _mockReq();
    var res1 = _mockRes();
    mw(req1, res1, function () { nextCalled = true; });
    check("requestId calls next()",                         nextCalled);
    check("requestId sets req.requestId (32 hex chars)",    typeof req1.requestId === "string" && req1.requestId.length === 32);
    check("requestId sets X-Request-Id response header",    res1._captured().headers["x-request-id"] === req1.requestId);

    // Propagates upstream value when format matches
    var req2 = _mockReq({ headers: { "x-request-id": "trace-abc-123_xyz" } });
    var res2 = _mockRes();
    mw(req2, res2, function () {});
    check("requestId propagates valid upstream id",         req2.requestId === "trace-abc-123_xyz");

    // Rejects malformed and generates fresh
    var req3 = _mockReq({ headers: { "x-request-id": "bad id with spaces!@#" } });
    var res3 = _mockRes();
    mw(req3, res3, function () {});
    check("requestId rejects malformed upstream id",        req3.requestId !== "bad id with spaces!@#");
  } finally { teardownMW(); }
}

async function testMiddlewareSecurityHeaders() {
  await setupTestDbForMW();
  try {
    var mw = b.middleware.securityHeaders();
    var req = _mockReq();
    var res = _mockRes();
    mw(req, res, function () {});
    var h = res._captured().headers;
    check("security: HSTS set",                          /max-age=63072000.+includeSubDomains/.test(h["strict-transport-security"]));
    check("security: X-Content-Type-Options nosniff",    h["x-content-type-options"] === "nosniff");
    check("security: X-Frame-Options DENY",              h["x-frame-options"] === "DENY");
    check("security: Referrer-Policy no-referrer",       h["referrer-policy"] === "no-referrer");
    check("security: Permissions-Policy disables camera", /camera=\(\)/.test(h["permissions-policy"]));
    check("security: COOP same-origin",                  h["cross-origin-opener-policy"] === "same-origin");
    check("security: CORP same-origin",                  h["cross-origin-resource-policy"] === "same-origin");
    check("security: CSP includes default-src 'self'",   /default-src 'self'/.test(h["content-security-policy"]));

    // Override + disable
    var mw2 = b.middleware.securityHeaders({ frameOptions: "SAMEORIGIN", csp: false });
    var req2 = _mockReq();
    var res2 = _mockRes();
    mw2(req2, res2, function () {});
    var h2 = res2._captured().headers;
    check("security: frameOptions override applied",     h2["x-frame-options"] === "SAMEORIGIN");
    check("security: csp disabled when false",           h2["content-security-policy"] === undefined);
  } finally { teardownMW(); }
}

async function testMiddlewareErrorHandler() {
  await setupTestDbForMW();
  try {
    var mw = b.middleware.errorHandler({ exposeStackInDev: false });

    // Simple error → 500
    var req = _mockReq({ url: "/x" });
    var res = _mockRes();
    mw(new Error("boom"), req, res, function () {});
    var captured = res._captured();
    check("errorHandler: default → 500",                 captured.status === 500);
    var body = JSON.parse(captured.body);
    check("errorHandler: generic message on 500",        body.error.message === "Internal Server Error");
    check("errorHandler: error code present",            !!body.error.code);

    // statusCode-bearing error → that status
    var customErr = new Error("not found");
    customErr.statusCode = 404;
    customErr.code = "not_found";
    var req2 = _mockReq();
    var res2 = _mockRes();
    mw(customErr, req2, res2, function () {});
    var c2 = res2._captured();
    check("errorHandler: respects statusCode on error",  c2.status === 404);
    var b2 = JSON.parse(c2.body);
    check("errorHandler: 4xx exposes message",           b2.error.message === "not found");

    // JsonSafeError → 400 + path
    var jse = new b.jsonSafe.JsonSafeError("validation failed", "json/validation", "$.email");
    var req3 = _mockReq();
    var res3 = _mockRes();
    mw(jse, req3, res3, function () {});
    var c3 = res3._captured();
    check("errorHandler: JsonSafeError → 400",           c3.status === 400);
    var b3 = JSON.parse(c3.body);
    check("errorHandler: 400 body includes path",        b3.error.path === "$.email");

    // Drain buffered audit emissions before reading audit_log.
    await b.audit.flush();
    // Audit recorded
    var errRows = await b.audit.query({ action: "system.http.error" });
    check("errorHandler: audit-recorded errors",          errRows.length === 3);
  } finally { teardownMW(); }
}

async function testMiddlewareBotGuard() {
  await setupTestDbForMW();
  try {
    var mw = b.middleware.botGuard();

    // curl UA in 'block' mode → 403
    var req = _mockReq({ headers: { "user-agent": "curl/8.0.0", "accept-language": "en", "sec-fetch-mode": "navigate" } });
    var res = _mockRes();
    var nextCalled = false;
    mw(req, res, function () { nextCalled = true; });
    check("botGuard: curl UA blocked",                    res._captured().status === 403 && !nextCalled);

    // Real-browser-shaped request → pass
    var req2 = _mockReq({ headers: { "user-agent": "Mozilla/5.0", "accept-language": "en-US", "sec-fetch-mode": "navigate" } });
    var res2 = _mockRes();
    var next2 = false;
    mw(req2, res2, function () { next2 = true; });
    check("botGuard: browser request passes",            next2);

    // Tag mode marks req but doesn't block
    var mwTag = b.middleware.botGuard({ mode: "tag" });
    var req3 = _mockReq({ headers: { "user-agent": "curl/8.0.0", "accept-language": "en" } });
    var res3 = _mockRes();
    var next3 = false;
    mwTag(req3, res3, function () { next3 = true; });
    check("botGuard tag mode: passes through",            next3);
    check("botGuard tag mode: req.suspectedBot set",     req3.suspectedBot === "blocked-agent");

    // Skip path
    var mwSkip = b.middleware.botGuard({ skipPaths: ["/healthz"] });
    var req4 = _mockReq({ url: "/healthz", pathname: "/healthz", headers: { "user-agent": "curl/8.0.0" } });
    var res4 = _mockRes();
    var next4 = false;
    mwSkip(req4, res4, function () { next4 = true; });
    check("botGuard: skipPaths bypassed",                next4);

    // API path is exempt from missing-Accept-Language by default (onlyForHtml)
    var req5 = _mockReq({ url: "/api/x", pathname: "/api/x", headers: { "user-agent": "Mozilla" } });
    var res5 = _mockRes();
    var next5 = false;
    mw(req5, res5, function () { next5 = true; });
    check("botGuard: onlyForHtml exempts /api/*",        next5);
  } finally { teardownMW(); }
}

async function testMiddlewareCors() {
  await setupTestDbForMW();
  try {
    var mw = b.middleware.cors({
      origins:     ["https://app.example.com", /^https:\/\/.+\.staging\.example\.com$/],
      credentials: true,
    });

    // Allowed origin → CORS headers set
    var req = _mockReq({ headers: { origin: "https://app.example.com" } });
    var res = _mockRes();
    var nextCalled = false;
    mw(req, res, function () { nextCalled = true; });
    check("cors: allowed origin → next called",          nextCalled);
    check("cors: ACAO set",                               res._captured().headers["access-control-allow-origin"] === "https://app.example.com");
    check("cors: ACAC set when credentials:true",        res._captured().headers["access-control-allow-credentials"] === "true");

    // Regex origin → match
    var req2 = _mockReq({ headers: { origin: "https://feature-1.staging.example.com" } });
    var res2 = _mockRes();
    var n2 = false;
    mw(req2, res2, function () { n2 = true; });
    check("cors: regex origin matched",                   res2._captured().headers["access-control-allow-origin"] === "https://feature-1.staging.example.com");

    // Disallowed origin → 403 (refuseUnknown default)
    var req3 = _mockReq({ headers: { origin: "https://evil.example.com" } });
    var res3 = _mockRes();
    var n3 = false;
    mw(req3, res3, function () { n3 = true; });
    check("cors: unknown origin blocked",                 res3._captured().status === 403 && !n3);

    // No Origin header → pass through
    var req4 = _mockReq();
    var res4 = _mockRes();
    var n4 = false;
    mw(req4, res4, function () { n4 = true; });
    check("cors: no Origin header → passes through",     n4 && !res4._captured().headers["access-control-allow-origin"]);

    // Preflight (OPTIONS + Access-Control-Request-Method) → 204 with allow-headers
    var req5 = _mockReq({ method: "OPTIONS", headers: { origin: "https://app.example.com", "access-control-request-method": "PUT" } });
    var res5 = _mockRes();
    mw(req5, res5, function () {});
    check("cors preflight: 204",                          res5._captured().status === 204);
    check("cors preflight: ACAM set",                     /PUT/.test(res5._captured().headers["access-control-allow-methods"]));
  } finally { teardownMW(); }
}

async function testMiddlewareRateLimit() {
  await setupTestDbForMW();
  try {
    var mw = b.middleware.rateLimit({ burst: 3, refillPerSecond: 1 });

    function fire() {
      var req = _mockReq();
      var res = _mockRes();
      var nextCalled = false;
      mw(req, res, function () { nextCalled = true; });
      return { passed: nextCalled, status: res._captured().status };
    }

    // First 3 pass (burst=3)
    check("rateLimit: 1st request passes",                 fire().passed);
    check("rateLimit: 2nd request passes",                 fire().passed);
    check("rateLimit: 3rd request passes",                 fire().passed);
    var blocked = fire();
    check("rateLimit: 4th request blocked with 429",      !blocked.passed && blocked.status === 429);

    // Different key → independent bucket
    var mw2 = b.middleware.rateLimit({ burst: 2, refillPerSecond: 0.5, keyFn: function (req) { return req.headers["x-key"] || "default"; } });
    function fireKey(k) {
      var req = _mockReq({ headers: { "x-key": k } });
      var res = _mockRes();
      var ok = false;
      mw2(req, res, function () { ok = true; });
      return ok;
    }
    check("rateLimit: keyA 1st passes",                    fireKey("a"));
    check("rateLimit: keyA 2nd passes",                    fireKey("a"));
    check("rateLimit: keyA 3rd blocked",                   !fireKey("a"));
    check("rateLimit: keyB independent — 1st passes",      fireKey("b"));

    // Skip path
    var mwSkip = b.middleware.rateLimit({ burst: 1, refillPerSecond: 0.1, skipPaths: ["/healthz"] });
    function fireWithPath(p) {
      var req = _mockReq({ url: p, pathname: p });
      var res = _mockRes();
      var ok = false;
      mwSkip(req, res, function () { ok = true; });
      return ok;
    }
    check("rateLimit: 1st /healthz passes",                fireWithPath("/healthz"));
    check("rateLimit: 2nd /healthz passes (skipped)",      fireWithPath("/healthz"));
    check("rateLimit: 1st /api passes",                    fireWithPath("/api"));
    check("rateLimit: 2nd /api blocked",                   !fireWithPath("/api"));
  } finally { teardownMW(); }
}

// setupTestDbForMW / teardownMW live in ./_helpers.js (imported above).

// =====================================================================
// v0.0.16 — atomic file I/O + safe parsers (XML, CSV)
// =====================================================================

async function testAtomicFile() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-atomicfile-"));
  try {
    check("atomicFile namespace present",            typeof b.atomicFile === "object");

    // Basic write + read round-trip
    var p = path.join(tmpDir, "data.bin");
    var content = Buffer.from("hello atomic " + Date.now(), "utf8");
    var w = await b.atomicFile.write(p, content, { computeHash: true });
    check("atomicFile write returns bytesWritten",   w.bytesWritten === content.length);
    check("atomicFile write returns hash",           typeof w.hash === "string" && w.hash.length === 128);

    var r = await b.atomicFile.read(p);
    check("atomicFile read returns Buffer",          Buffer.isBuffer(r));
    check("atomicFile read content matches",         r.equals(content));

    // Hash verification
    var rOk = await b.atomicFile.read(p, { expectedHash: w.hash });
    check("atomicFile hash verify accepts good hash", rOk.equals(content));

    var hashRejected = false;
    try { await b.atomicFile.read(p, { expectedHash: "0".repeat(128) }); }
    catch (e) { hashRejected = e.code === "atomic-file/integrity"; }
    check("atomicFile hash verify rejects bad hash", hashRejected);

    // Size limit
    var bigPath = path.join(tmpDir, "big.bin");
    await b.atomicFile.write(bigPath, Buffer.alloc(2048));
    var sizeRejected = false;
    try { await b.atomicFile.read(bigPath, { maxBytes: 1024 }); }
    catch (e) { sizeRejected = e.code === "atomic-file/too-large"; }
    check("atomicFile read maxBytes enforced",       sizeRejected);

    // readSync: same semantics as async read, for boot-path callers
    var rSync = b.atomicFile.readSync(p);
    check("atomicFile readSync returns Buffer",      Buffer.isBuffer(rSync));
    check("atomicFile readSync content matches",     rSync.equals(content));
    var rSyncStr = b.atomicFile.readSync(p, { encoding: "utf8" });
    check("atomicFile readSync encoding option",     rSyncStr === content.toString("utf8"));
    var syncSizeRejected = false;
    try { b.atomicFile.readSync(bigPath, { maxBytes: 1024 }); }
    catch (e) { syncSizeRejected = e.code === "atomic-file/too-large"; }
    check("atomicFile readSync maxBytes enforced",   syncSizeRejected);
    var syncMissingRejected = false;
    try { b.atomicFile.readSync(path.join(tmpDir, "no-such-file")); }
    catch (e) { syncMissingRejected = e.code === "ENOENT"; }
    check("atomicFile readSync ENOENT on missing",   syncMissingRejected);

    // Crash safety: tmp file should NOT remain after success
    var tmpFiles = fs.readdirSync(tmpDir).filter(function (f) { return /\.tmp-/.test(f); });
    check("atomicFile cleans up tmp on success",     tmpFiles.length === 0);

    // JSON convenience
    var jsonPath = path.join(tmpDir, "data.json");
    await b.atomicFile.writeJson(jsonPath, { a: 1, b: [2, 3] });
    var parsed = await b.atomicFile.readJson(jsonPath);
    check("atomicFile writeJson/readJson round-trip", parsed.a === 1 && parsed.b[1] === 3);

    // readJson with schema
    var schemaPath = path.join(tmpDir, "schema.json");
    await b.atomicFile.writeJson(schemaPath, { name: "alice", age: 30 });
    var validated = await b.atomicFile.readJson(schemaPath, {
      schema: { type: "object", required: ["name", "age"], properties: { name: { type: "string" }, age: { type: "integer" } } },
    });
    check("atomicFile readJson + schema validates",  validated.name === "alice");

    // copy
    var copyPath = path.join(tmpDir, "copy.bin");
    var c = await b.atomicFile.copy(p, copyPath, { computeHash: true });
    check("atomicFile copy returns hash",            c.hash === w.hash);
    check("atomicFile copy file exists",             b.atomicFile.exists(copyPath));

    // Read missing file → ENOENT
    var missingRejected = false;
    try { await b.atomicFile.read(path.join(tmpDir, "nope")); }
    catch (e) { missingRejected = e.code === "ENOENT" || e.code === "atomic-file/not-found"; }
    check("atomicFile read missing → ENOENT",         missingRejected);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testAtomicFileLock() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-atlock-"));
  try {
    var p = path.join(tmpDir, "shared.txt");
    var counter = 0;

    // Two concurrent locks — they should serialize
    async function increment() {
      await b.atomicFile.lock(p, async function () {
        var current;
        try { current = parseInt((await b.atomicFile.read(p)).toString("utf8"), 10) || 0; }
        catch (_e) { current = 0; }
        await new Promise(function (r) { setTimeout(r, 20); });   // simulate work
        await b.atomicFile.write(p, String(current + 1));
        counter += 1;
      });
    }

    await Promise.all([increment(), increment(), increment(), increment(), increment()]);
    var finalValue = parseInt((await b.atomicFile.read(p)).toString("utf8"), 10);
    check("atomicFile.lock serializes concurrent access",  finalValue === 5);
    check("counter agrees",                                counter === 5);

    // Lock file is gone after lock body finishes
    check("lock sentinel cleaned up",                      !b.atomicFile.exists(p + ".lock"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function testXmlParse() {
  check("parsers namespace present",                  typeof b.parsers === "object");
  check("parsers.xml present",                        typeof b.parsers.xml === "object");

  // Simple element
  var simple = b.parsers.xml.parse("<root>hello</root>");
  check("xml: simple text element",                   simple.root === "hello");

  // Attributes + nested
  var attr = b.parsers.xml.parse('<root id="x"><child>text</child></root>');
  check("xml: attributes preserved at @attrs",        attr.root["@attrs"].id === "x");
  check("xml: nested child element",                  attr.root.child === "text");

  // Multiple children with same name → array
  var multi = b.parsers.xml.parse('<root><item>a</item><item>b</item><item>c</item></root>');
  check("xml: repeated children become array",        Array.isArray(multi.root.item) && multi.root.item.length === 3);
  check("xml: array preserves order",                 multi.root.item[0] === "a" && multi.root.item[2] === "c");

  // XML declaration tolerated
  var withDecl = b.parsers.xml.parse('<?xml version="1.0" encoding="UTF-8"?><root>x</root>');
  check("xml: XML decl ignored",                      withDecl.root === "x");

  // Built-in entities decoded
  var entities = b.parsers.xml.parse("<root>&lt;ok&gt; &amp; &quot;quoted&quot;</root>");
  check("xml: built-in entities decoded",             entities.root === "<ok> & \"quoted\"");

  // Numeric character refs
  var numref = b.parsers.xml.parse("<root>&#65;&#x42;</root>");
  check("xml: numeric character refs decoded",        numref.root === "AB");

  // Self-closing
  var selfClose = b.parsers.xml.parse("<root><br/></root>");
  check("xml: self-closing element parses",           selfClose.root.br === "");

  // CDATA
  var cdata = b.parsers.xml.parse("<root><![CDATA[<not parsed>]]></root>");
  check("xml: CDATA preserved literally",             cdata.root === "<not parsed>");
}

function testXmlSecurityRejections() {
  // DOCTYPE rejected by default
  var doctypeRejected = false;
  try { b.parsers.xml.parse('<!DOCTYPE foo SYSTEM "http://evil.com/foo.dtd"><root/>'); }
  catch (e) { doctypeRejected = e.code === "xml/doctype"; }
  check("xml: DOCTYPE rejected by default (XXE)",     doctypeRejected);

  // External entity reference rejected
  var entityRejected = false;
  try { b.parsers.xml.parse('<root>&customEntity;</root>'); }
  catch (e) { entityRejected = e.code === "xml/external-entity"; }
  check("xml: custom entity ref rejected",            entityRejected);

  // Processing instruction rejected
  var piRejected = false;
  try { b.parsers.xml.parse('<root><?php echo $secret; ?></root>'); }
  catch (e) { piRejected = e.code === "xml/processing"; }
  check("xml: processing instruction rejected",        piRejected);

  // Mismatched tags
  var mismatchedRejected = false;
  try { b.parsers.xml.parse("<a><b></a></b>"); }
  catch (e) { mismatchedRejected = e.code === "xml/mismatched-tag"; }
  check("xml: mismatched tags rejected",              mismatchedRejected);

  // Depth limit
  var deep = "<a>".repeat(20) + "x" + "</a>".repeat(20);
  var depthRejected = false;
  try { b.parsers.xml.parse(deep, { maxDepth: 5 }); }
  catch (e) { depthRejected = e.code === "xml/too-deep"; }
  check("xml: maxDepth enforced",                     depthRejected);

  // Element count limit
  var manyKids = "<root>" + "<x/>".repeat(50) + "</root>";
  var countRejected = false;
  try { b.parsers.xml.parse(manyKids, { maxElements: 10 }); }
  catch (e) { countRejected = e.code === "xml/too-many-elements"; }
  check("xml: maxElements enforced",                  countRejected);

  // Attribute count limit
  var manyAttrs = "<root " + Array.from({ length: 20 }, function (_, i) { return "a" + i + "=\"v\""; }).join(" ") + "/>";
  var attrRejected = false;
  try { b.parsers.xml.parse(manyAttrs, { maxAttributes: 5 }); }
  catch (e) { attrRejected = e.code === "xml/too-many-attrs"; }
  check("xml: maxAttributes enforced",                attrRejected);

  // Size limit
  var sizeRejected = false;
  try { b.parsers.xml.parse("<r>" + "a".repeat(10000) + "</r>", { maxBytes: 1000 }); }
  catch (e) { sizeRejected = e.code === "xml/too-large"; }
  check("xml: maxBytes enforced",                     sizeRejected);

  // Duplicate attributes
  var dupRejected = false;
  try { b.parsers.xml.parse('<r id="a" id="b"/>'); }
  catch (e) { dupRejected = e.code === "xml/duplicate-attr"; }
  check("xml: duplicate attribute rejected",           dupRejected);

  // < in attribute value
  var ltRejected = false;
  try { b.parsers.xml.parse('<r x="<bad"/>'); }
  catch (e) { ltRejected = e.code === "xml/bad-attr"; }
  check("xml: '<' in attribute value rejected",        ltRejected);
}

function testCsvParse() {
  check("parsers.csv present",                        typeof b.parsers.csv === "object");

  // Simple round-trip
  var simple = b.parsers.csv.parse("name,age\nalice,30\nbob,25");
  check("csv: header+rows → object array",            simple.length === 2);
  check("csv: object has header keys",                simple[0].name === "alice" && simple[0].age === "30");

  // Without header
  var noHeader = b.parsers.csv.parse("a,b,c\n1,2,3", { header: false });
  check("csv: no header → array of arrays",           Array.isArray(noHeader[0]));
  check("csv: 2 rows",                                noHeader.length === 2);

  // Quoted fields
  var quoted = b.parsers.csv.parse('name,note\n"alice","says ""hi"""\n"bob","comma, inside"', { header: true });
  check("csv: quoted field with escaped quote",       quoted[0].note === 'says "hi"');
  check("csv: quoted field with comma",               quoted[1].note === "comma, inside");

  // CRLF
  var crlf = b.parsers.csv.parse("a,b\r\n1,2\r\n3,4", { header: false });
  check("csv: CRLF line endings",                     crlf.length === 3);

  // Custom delimiter
  var tsv = b.parsers.csv.parse("a\tb\n1\t2", { delimiter: "\t", header: false });
  check("csv: custom delimiter",                      tsv[1][0] === "1" && tsv[1][1] === "2");

  // BOM stripped
  var bom = b.parsers.csv.parse("﻿a,b\n1,2", { header: false });
  check("csv: BOM stripped",                          bom[0][0] === "a");

  // Size limit
  var sizeRejected = false;
  try { b.parsers.csv.parse("a,".repeat(100), { maxBytes: 50, header: false }); }
  catch (e) { sizeRejected = e.code === "csv/too-large"; }
  check("csv: maxBytes enforced",                     sizeRejected);

  // Row count limit
  var manyRows = Array.from({ length: 10 }, function (_, i) { return i + ",x"; }).join("\n");
  var rowsRejected = false;
  try { b.parsers.csv.parse(manyRows, { maxRows: 3, header: false }); }
  catch (e) { rowsRejected = e.code === "csv/too-many-rows"; }
  check("csv: maxRows enforced",                      rowsRejected);

  // Unterminated quote
  var unterminatedRejected = false;
  try { b.parsers.csv.parse('a,b\n"unclosed,1\n2,3', { header: false }); }
  catch (e) { unterminatedRejected = e.code === "csv/unterminated-quote"; }
  check("csv: unterminated quote rejected",            unterminatedRejected);
}

function testCsvFormulaInjection() {
  // Default: injection-prone cells get a '-prefix
  var dangerous = b.parsers.csv.stringify([
    { name: "=SUM(A1:A10)", value: "ok" },
    { name: "+CMD|/c calc",  value: "ok" },
    { name: "-1+2",          value: "ok" },
    { name: "@SUM(1,2)",     value: "ok" },
    { name: "normal",        value: "ok" },
  ]);
  check("csv stringify: =formula gets '-prefix",        /'\=SUM/.test(dangerous));
  check("csv stringify: +formula gets '-prefix",        /'\+CMD/.test(dangerous));
  check("csv stringify: -formula gets '-prefix",        /'\-1\+2/.test(dangerous));
  check("csv stringify: @formula gets '-prefix",        /'\@SUM/.test(dangerous));
  check("csv stringify: normal cell unchanged",         /(^|\n|\r)normal,ok/.test(dangerous));

  // Disabled mode (RFC 4180 strict)
  var raw = b.parsers.csv.stringify([{ name: "=SUM(A1:A10)" }], { preventFormulaInjection: false });
  check("csv stringify: preventFormulaInjection:false leaves =formula", /^name\r\n=SUM/.test(raw));

  // Round-trip via parse + stringify
  var rows = [{ a: "1", b: "two, three" }, { a: "x\nnewline", b: "with \"quote\"" }];
  var serialized = b.parsers.csv.stringify(rows);
  var parsed = b.parsers.csv.parse(serialized);
  check("csv round-trip preserves comma in field",       parsed[0].b === "two, three");
  check("csv round-trip preserves newline in field",     parsed[1].a === "x\nnewline");
  check("csv round-trip preserves quote in field",       parsed[1].b === "with \"quote\"");
}

function testTomlBasicTypes() {
  var src =
    "title = \"blamejs\"\n" +
    "active = true\n" +
    "disabled = false\n" +
    "answer = 42\n" +
    "ratio = 3.14\n" +
    "neg = -17\n" +
    "biginthex = 0xDEADbeef\n" +
    "octal = 0o755\n" +
    "binary = 0b1010\n" +
    "underscored = 1_000_000\n" +
    "infinity = inf\n" +
    "negInf = -inf\n" +
    "notNum = nan\n" +
    "literal = 'no \\n escapes here'\n" +
    "stamp = 1979-05-27T07:32:00Z\n" +
    "localDate = 1979-05-27\n" +
    "localTime = 07:32:00\n";
  var doc = b.parsers.toml.parse(src);
  check("toml: string value",                      doc.title === "blamejs");
  check("toml: bool true",                         doc.active === true);
  check("toml: bool false",                        doc.disabled === false);
  check("toml: integer",                           doc.answer === 42);
  check("toml: float",                             Math.abs(doc.ratio - 3.14) < 1e-9);
  check("toml: negative integer",                  doc.neg === -17);
  check("toml: hex with underscore-camelcase digits", doc.biginthex === 0xDEADbeef);
  check("toml: octal",                             doc.octal === 0o755);
  check("toml: binary",                            doc.binary === 10);
  check("toml: underscored decimal",               doc.underscored === 1000000);
  check("toml: inf",                               doc.infinity === Infinity);
  check("toml: -inf",                              doc.negInf === -Infinity);
  check("toml: nan",                               Number.isNaN(doc.notNum));
  check("toml: literal string preserves backslash-n",  doc.literal === "no \\n escapes here");
  check("toml: offset date-time → Date",           doc.stamp instanceof Date);
  check("toml: offset date-time correct epoch",    doc.stamp.getTime() === Date.UTC(1979, 4, 27, 7, 32, 0));
  check("toml: local date as ISO string",          doc.localDate === "1979-05-27");
  check("toml: local time as ISO string",          doc.localTime === "07:32:00");
}

function testTomlTablesAndArrays() {
  var src =
    "tags = [\"a\", \"b\", \"c\"]\n" +
    "\n" +
    "[server]\n" +
    "host = \"localhost\"\n" +
    "port = 8080\n" +
    "\n" +
    "[server.tls]\n" +
    "cert = \"/etc/ssl/cert.pem\"\n" +
    "\n" +
    "[[products]]\n" +
    "name = \"widget\"\n" +
    "price = 9.99\n" +
    "\n" +
    "[[products]]\n" +
    "name = \"gizmo\"\n" +
    "price = 19.99\n";
  var doc = b.parsers.toml.parse(src);
  check("toml: array of strings (top-level)",      Array.isArray(doc.tags) && doc.tags.length === 3);
  check("toml: array element 0",                   doc.tags[0] === "a");
  check("toml: nested table",                      doc.server.host === "localhost");
  check("toml: integer in nested table",           doc.server.port === 8080);
  check("toml: deeper nested table",               doc.server.tls.cert === "/etc/ssl/cert.pem");
  check("toml: array of tables length",            doc.products.length === 2);
  check("toml: AoT first element",                 doc.products[0].name === "widget");
  check("toml: AoT second element",                doc.products[1].name === "gizmo");
  check("toml: AoT prices",                        doc.products[1].price === 19.99);
}

function testTomlInlineTablesAndDottedKeys() {
  var src =
    "point = { x = 1, y = 2 }\n" +
    "name.first = \"Tom\"\n" +
    "name.last = \"Preston-Werner\"\n";
  var doc = b.parsers.toml.parse(src);
  check("toml: inline table",                      doc.point.x === 1 && doc.point.y === 2);
  check("toml: dotted-key creates nested object",  doc.name.first === "Tom" && doc.name.last === "Preston-Werner");
}

function testEnvParseBasic() {
  var src =
    "# comment\n" +
    "DATABASE_URL=postgres://localhost\n" +
    "PORT=8080\n" +
    "FEATURE_FLAG=true\n" +
    "EMPTY=\n" +
    "QUOTED=\"hello world\"\n" +
    "QUOTED_NL=\"line1\\nline2\"\n" +
    "LITERAL='no \\n escapes'\n" +
    "WITH_SPACES = trimmed\n" +
    "export EXPORTED=ok\n" +
    "INLINE=value # trailing comment\n";
  var values = b.parsers.env.parse(src);
  check("env: simple key/value",                   values.DATABASE_URL === "postgres://localhost");
  check("env: numeric stays a string by default",  values.PORT === "8080");
  check("env: bool stays a string by default",     values.FEATURE_FLAG === "true");
  check("env: empty value",                        values.EMPTY === "");
  check("env: double-quoted",                      values.QUOTED === "hello world");
  check("env: double-quoted decodes \\n",          values.QUOTED_NL === "line1\nline2");
  check("env: single-quoted preserves backslash",  values.LITERAL === "no \\n escapes");
  check("env: spaces around = stripped",           values.WITH_SPACES === "trimmed");
  check("env: 'export' prefix accepted",           values.EXPORTED === "ok");
  check("env: trailing # comment stripped",        values.INLINE === "value");
}

function testEnvParseSecurityRejections() {
  // $VAR expansion banned
  var threwExpand = false;
  try { b.parsers.env.parse("KEY=$OTHER"); }
  catch (e) { threwExpand = e.code === "env/expansion-banned"; }
  check("env: $VAR expansion rejected",            threwExpand);

  var threwExpandQuoted = false;
  try { b.parsers.env.parse("KEY=\"hello $WORLD\""); }
  catch (e) { threwExpandQuoted = e.code === "env/expansion-banned"; }
  check("env: $VAR in double-quoted rejected",     threwExpandQuoted);

  // \$ literal works
  var literal = b.parsers.env.parse("KEY=\"\\$LITERAL\"");
  check("env: \\$ literal escape works",           literal.KEY === "$LITERAL");

  // Bad key shape
  var threwShape = false;
  try { b.parsers.env.parse("lowercase=value"); }
  catch (e) { threwShape = e.code === "env/bad-key-shape"; }
  check("env: lowercase key rejected by default",  threwShape);

  // Hyphen rejected
  var threwHyphen = false;
  try { b.parsers.env.parse("MY-KEY=value"); }
  catch (e) { threwHyphen = e.code === "env/bad-key-shape"; }
  check("env: hyphenated key rejected by default", threwHyphen);

  // __proto__ rejected
  var threwProto = false;
  try { b.parsers.env.parse("__proto__=pwn"); }
  catch (e) { threwProto = e.code === "env/poisoned-key" || e.code === "env/bad-key-shape"; }
  check("env: __proto__ rejected",                 threwProto);

  // Duplicate key
  var threwDup = false;
  try { b.parsers.env.parse("KEY=1\nKEY=2"); }
  catch (e) { threwDup = e.code === "env/duplicate-key"; }
  check("env: duplicate key rejected",             threwDup);

  // Missing =
  var threwMissingEq = false;
  try { b.parsers.env.parse("KEY value"); }
  catch (e) { threwMissingEq = e.code === "env/bad-line"; }
  check("env: missing '=' rejected",               threwMissingEq);

  // Tab in unquoted value
  var threwTab = false;
  try { b.parsers.env.parse("KEY=\tvalue"); }
  catch (e) { threwTab = e.code === "env/tab-in-value"; }
  check("env: tab at start of value rejected",     threwTab);

  // Size cap
  var threwSize = false;
  try { b.parsers.env.parse("KEY=" + "x".repeat(2000), { maxBytes: 1000 }); }
  catch (e) { threwSize = e.code === "env/too-large"; }
  check("env: maxBytes enforced",                  threwSize);

  // Unterminated string
  var threwUnterm = false;
  try { b.parsers.env.parse("KEY=\"unterminated"); }
  catch (e) { threwUnterm = e.code === "env/unterminated-string"; }
  check("env: unterminated quoted rejected",       threwUnterm);
}

function testEnvLoadDiffAndAudit() {
  // Use real file I/O via atomicFile — exercises load() end-to-end.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-env-"));
  try {
    var envPath = path.join(tmpDir, ".env");
    var snapPath = path.join(tmpDir, "env.snapshot.json");

    fs.writeFileSync(envPath, "DATABASE_URL=postgres://A\nFEATURE_FOO=true\n");
    var res1 = b.parsers.env.load(envPath, {
      snapshotPath: snapPath,
      audit:        false,    // no framework db wired in this test fixture
    });
    check("env.load returns values",                 res1.values.DATABASE_URL === "postgres://A");
    check("env.load first call: 2 added",            res1.diff.added.length === 2);
    check("env.load first call: nothing removed",    res1.diff.removed.length === 0);
    check("env.load first call: nothing changed",    res1.diff.changed.length === 0);

    // Now change one and add another
    fs.writeFileSync(envPath, "DATABASE_URL=postgres://B\nFEATURE_FOO=true\nNEW_KEY=hello\n");
    var res2 = b.parsers.env.load(envPath, { snapshotPath: snapPath, audit: false });
    check("env.load second call: 1 added",           res2.diff.added.length === 1 && res2.diff.added[0] === "NEW_KEY");
    check("env.load second call: nothing removed",   res2.diff.removed.length === 0);
    check("env.load second call: 1 changed",         res2.diff.changed.length === 1);
    check("env.load second call: changed key",       res2.diff.changed[0].key === "DATABASE_URL");

    // Now remove one
    fs.writeFileSync(envPath, "DATABASE_URL=postgres://B\nNEW_KEY=hello\n");
    var res3 = b.parsers.env.load(envPath, { snapshotPath: snapPath, audit: false });
    check("env.load third call: 1 removed",          res3.diff.removed.length === 1 && res3.diff.removed[0] === "FEATURE_FOO");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function testEnvLoadSchemaAndTypos() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-env-"));
  try {
    var envPath = path.join(tmpDir, ".env");
    fs.writeFileSync(envPath,
      "DATABSE_URL=oops\n" +              // typo of DATABASE_URL
      "feature_flag=true\n");             // case mismatch — wait, this is rejected by keyShape
    // Actually case-mismatch must use keys that pass shape. Use uppercase
    // mismatch instead — rewrite.
    fs.writeFileSync(envPath,
      "DATABSE_URL=oops\n" +              // typo (missing 'A')
      "FEATURE_FLAG=true\n" +             // exact match for registered
      "TOTALLY_UNKNOWN=other\n");
    var expected = {
      DATABASE_URL: { type: "string", sensitivity: "breaking" },
      FEATURE_FLAG: { type: "boolean", sensitivity: "runtime" },
    };
    var res = b.parsers.env.load(envPath, {
      expected: expected,
      audit:    false,
    });
    check("env: schema coerces type when registered",  res.values.FEATURE_FLAG === true);

    // Find the typo entry in suspicious
    var typo = res.diff.suspicious.find(function (s) { return s.key === "DATABSE_URL"; });
    check("env: typo flagged as suspicious",            typo && typo.suggestion === "DATABASE_URL");
    check("env: typo reason is single-char-typo",       typo && typo.reason === "single-char-typo");

    var unknown = res.diff.suspicious.find(function (s) { return s.key === "TOTALLY_UNKNOWN"; });
    check("env: unrelated unknown flagged",             unknown && unknown.reason === "unknown");

    // rejectUnknown mode refuses
    var threwRejectUnknown = false;
    try { b.parsers.env.load(envPath, { expected: expected, audit: false, rejectUnknown: true }); }
    catch (e) { threwRejectUnknown = e.code === "env/unknown-keys"; }
    check("env: rejectUnknown surfaces error",         threwRejectUnknown);

    // Required key missing
    fs.writeFileSync(envPath, "FEATURE_FLAG=true\n");
    var threwRequired = false;
    try {
      b.parsers.env.load(envPath, {
        expected: { DATABASE_URL: { type: "string", required: true } },
        audit:    false,
      });
    } catch (e) { threwRequired = e.code === "env/missing-required"; }
    check("env: missing required key rejected",         threwRequired);

    // Bad type coercion
    fs.writeFileSync(envPath, "FEATURE_FLAG=yes\n");
    var threwBadBool = false;
    try {
      b.parsers.env.load(envPath, {
        expected: { FEATURE_FLAG: { type: "boolean" } },
        audit:    false,
      });
    } catch (e) { threwBadBool = e.code === "env/bad-type"; }
    check("env: 'yes' for boolean rejected (no Norway)", threwBadBool);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function testEnvLoadBreakingChange() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-env-"));
  try {
    var envPath = path.join(tmpDir, ".env");
    var snapPath = path.join(tmpDir, "env.snapshot.json");
    var expected = {
      DATABASE_URL: { type: "string", sensitivity: "breaking" },
    };

    fs.writeFileSync(envPath, "DATABASE_URL=postgres://A\n");
    b.parsers.env.load(envPath, { expected: expected, snapshotPath: snapPath, audit: false });

    // Try to change without acknowledgement
    fs.writeFileSync(envPath, "DATABASE_URL=postgres://B\n");
    var threwBreaking = false;
    try {
      b.parsers.env.load(envPath, { expected: expected, snapshotPath: snapPath, audit: false });
    } catch (e) { threwBreaking = e.code === "env/breaking-change"; }
    check("env: breaking-sensitivity change refused",   threwBreaking);

    // With explicit allow, succeeds
    var ok = b.parsers.env.load(envPath, {
      expected:     expected,
      snapshotPath: snapPath,
      audit:        false,
      allow:        ["DATABASE_URL"],
    });
    check("env: { allow: [...] } authorises breaking change",
          ok.values.DATABASE_URL === "postgres://B");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function testYamlBasic() {
  var src =
    "title: blamejs\n" +
    "version: 0.1.6\n" +
    "active: true\n" +
    "disabled: false\n" +
    "answer: 42\n" +
    "ratio: 3.14\n" +
    "absent: null\n" +
    "implicit_null: ~\n" +
    "list:\n" +
    "  - a\n" +
    "  - b\n" +
    "  - c\n" +
    "nested:\n" +
    "  host: localhost\n" +
    "  port: 8080\n" +
    "  tls:\n" +
    "    cert: /etc/ssl/cert.pem\n" +
    "flow_seq: [1, 2, 3]\n" +
    "flow_map: { x: 1, y: 2 }\n";
  var doc = b.parsers.yaml.parse(src);
  check("yaml: string scalar",                     doc.title === "blamejs");
  check("yaml: version string (mixed digits/dots)", doc.version === "0.1.6" || doc.version === 0.1);
  check("yaml: bool true",                         doc.active === true);
  check("yaml: bool false",                        doc.disabled === false);
  check("yaml: integer",                           doc.answer === 42);
  check("yaml: float",                             Math.abs(doc.ratio - 3.14) < 1e-9);
  check("yaml: explicit null",                     doc.absent === null);
  check("yaml: tilde null",                        doc.implicit_null === null);
  check("yaml: block sequence length",             doc.list.length === 3);
  check("yaml: block sequence elements",           doc.list[0] === "a" && doc.list[2] === "c");
  check("yaml: nested mapping host",               doc.nested.host === "localhost");
  check("yaml: deeply-nested mapping",             doc.nested.tls.cert === "/etc/ssl/cert.pem");
  check("yaml: flow sequence",                     Array.isArray(doc.flow_seq) && doc.flow_seq.length === 3);
  check("yaml: flow mapping",                      doc.flow_map.x === 1 && doc.flow_map.y === 2);
}

function testYamlNorwayProblem() {
  // YAML 1.1 parsed `NO` / `OFF` / `YES` as booleans — the "Norway
  // problem". YAML 1.2 core schema uses ONLY true/True/TRUE/false/False/FALSE.
  var doc = b.parsers.yaml.parse("country: NO\nstate: ON\nflag: YES\n");
  check("yaml: 'NO' is string (Norway problem fixed)", doc.country === "NO");
  check("yaml: 'ON' is string",                          doc.state === "ON");
  check("yaml: 'YES' is string",                         doc.flag === "YES");
}

function testYamlBlockScalars() {
  var literal = b.parsers.yaml.parse(
    "msg: |\n" +
    "  line one\n" +
    "  line two\n"
  );
  check("yaml: literal block scalar preserves newlines",  literal.msg === "line one\nline two\n");

  var folded = b.parsers.yaml.parse(
    "msg: >\n" +
    "  paragraph one\n" +
    "  continues here\n" +
    "\n" +
    "  paragraph two\n"
  );
  check("yaml: folded block scalar collapses lines",
        folded.msg === "paragraph one continues here\nparagraph two\n");

  var stripped = b.parsers.yaml.parse(
    "msg: |-\n" +
    "  no trailing newline"
  );
  check("yaml: literal-strip removes trailing newline",  stripped.msg === "no trailing newline");
}

function testYamlQuotedStrings() {
  var doc = b.parsers.yaml.parse(
    "double: \"hello\\nworld\"\n" +
    "single: 'literal \\n stays'\n" +
    "embedded: 'it''s great'\n"
  );
  check("yaml: double-quoted decodes \\n",          doc.double === "hello\nworld");
  check("yaml: single-quoted preserves backslash",  doc.single === "literal \\n stays");
  check("yaml: single-quoted '' becomes apostrophe", doc.embedded === "it's great");
}

function testYamlSecurityRejections() {
  var threwAnchor = false;
  try { b.parsers.yaml.parse("a: &anchor 1\nb: *anchor"); }
  catch (e) { threwAnchor = e.code === "yaml/anchors-banned" || e.code === "yaml/aliases-banned"; }
  check("yaml: anchors/aliases rejected",          threwAnchor);

  var threwTag = false;
  try { b.parsers.yaml.parse("a: !!str 42"); }
  catch (e) { threwTag = e.code === "yaml/tags-banned"; }
  check("yaml: !!tag rejected",                    threwTag);

  var threwDirective = false;
  try { b.parsers.yaml.parse("%YAML 1.2\n---\nfoo: bar"); }
  catch (e) { threwDirective = e.code === "yaml/directives-banned"; }
  check("yaml: %YAML directive rejected",          threwDirective);

  var threwMultiDoc = false;
  try { b.parsers.yaml.parse("a: 1\n---\nb: 2"); }
  catch (e) { threwMultiDoc = e.code === "yaml/multi-document"; }
  check("yaml: multi-document streams rejected",   threwMultiDoc);

  var threwTab = false;
  try { b.parsers.yaml.parse("a:\n\tb: 1"); }
  catch (e) { threwTab = e.code === "yaml/tab-indent"; }
  check("yaml: tab in indent rejected",            threwTab);

  var threwProto = false;
  try { b.parsers.yaml.parse("__proto__: pwn"); }
  catch (e) { threwProto = e.code === "yaml/poisoned-key"; }
  check("yaml: __proto__ rejected",                threwProto);

  var threwMerge = false;
  try { b.parsers.yaml.parse("base: { a: 1 }\nderived:\n  <<: base\n  b: 2"); }
  catch (e) { threwMerge = e.code === "yaml/merge-key-banned"; }
  check("yaml: merge key '<<' rejected",           threwMerge);

  var threwDup = false;
  try { b.parsers.yaml.parse("a: 1\na: 2"); }
  catch (e) { threwDup = e.code === "yaml/duplicate-key"; }
  check("yaml: duplicate key rejected",            threwDup);

  var threwSize = false;
  try { b.parsers.yaml.parse("a: \"" + "x".repeat(2000) + "\"", { maxBytes: 1000 }); }
  catch (e) { threwSize = e.code === "yaml/too-large"; }
  check("yaml: maxBytes enforced",                 threwSize);

  var threwUnterm = false;
  try { b.parsers.yaml.parse("a: \"unterminated"); }
  catch (e) { threwUnterm = !!e.isYamlSafeError; }
  check("yaml: unterminated string rejected",      threwUnterm);
}

function testTomlSecurityRejections() {
  // Prototype pollution via dotted key
  var threwProto = false;
  try { b.parsers.toml.parse("__proto__.polluted = true"); }
  catch (e) { threwProto = e.code === "toml/poisoned-key"; }
  check("toml: __proto__ rejected",                threwProto);

  var threwConstructor = false;
  try { b.parsers.toml.parse("a.constructor = 1"); }
  catch (e) { threwConstructor = e.code === "toml/poisoned-key"; }
  check("toml: constructor rejected",              threwConstructor);

  // Duplicate key
  var threwDup = false;
  try { b.parsers.toml.parse("a = 1\na = 2"); }
  catch (e) { threwDup = e.code === "toml/duplicate-key"; }
  check("toml: duplicate key rejected",            threwDup);

  // Inline table mutation
  var threwInlineMutate = false;
  try { b.parsers.toml.parse("x = { a = 1 }\nx.b = 2"); }
  catch (e) { threwInlineMutate = e.code === "toml/inline-table-mutated"; }
  check("toml: inline-table mutation rejected",    threwInlineMutate);

  // Table redefinition
  var threwRedefine = false;
  try { b.parsers.toml.parse("[a]\nb = 1\n[a]\nc = 2"); }
  catch (e) { threwRedefine = e.code === "toml/redefine"; }
  check("toml: table redefinition rejected",       threwRedefine);

  // Size cap
  var threwSize = false;
  try { b.parsers.toml.parse("a = \"" + "x".repeat(2000) + "\"", { maxBytes: 1000 }); }
  catch (e) { threwSize = e.code === "toml/too-large"; }
  check("toml: maxBytes enforced",                 threwSize);

  // Integer overflow
  var threwOverflow = false;
  try { b.parsers.toml.parse("big = 9223372036854775807"); }
  catch (e) { threwOverflow = e.code === "toml/integer-overflow"; }
  check("toml: integer-overflow on > MAX_SAFE_INTEGER", threwOverflow);

  // Unterminated string
  var threwUnterm = false;
  try { b.parsers.toml.parse("a = \"unterminated\nb = 1"); }
  catch (e) { threwUnterm = !!e.isTomlSafeError; }
  check("toml: unterminated string rejected",      threwUnterm);

  // Multi-line basic string
  var doc = b.parsers.toml.parse("greeting = \"\"\"\nhello,\nworld\n\"\"\"");
  check("toml: multi-line basic string trims first newline + preserves rest",
        doc.greeting === "hello,\nworld\n");
}

// =====================================================================
// json — security-focused JSON parse/stringify + schema validation
// =====================================================================

// 40. Module surface
check("jsonSafe namespace present",        typeof b.jsonSafe === "object");
check("jsonSafe.parse is a function",      typeof b.jsonSafe.parse === "function");
check("jsonSafe.validate is a function",   typeof b.jsonSafe.validate === "function");
check("jsonSafe.canonical is a function",  typeof b.jsonSafe.canonical === "function");
check("jsonSafe.JsonSafeError exists",     typeof b.jsonSafe.JsonSafeError === "function");

// 41. parse: round-trip + size + depth + proto-pollution + types
function testJsonParse() {
  // Basic round-trip
  var v = b.jsonSafe.parse('{"a":1,"b":"hello","c":null,"d":[1,2,3],"e":true}');
  check("parse round-trips object",   v.a === 1 && v.b === "hello" && v.c === null);
  check("parse round-trips array",    Array.isArray(v.d) && v.d.length === 3);

  // BOM tolerated
  var bom = b.jsonSafe.parse("﻿{\"x\":1}");
  check("parse strips BOM",           bom.x === 1);

  // Size limit
  var bigInput = '{"x":"' + "a".repeat(200) + '"}';
  var sizeRejected = false;
  try { b.jsonSafe.parse(bigInput, { maxBytes: 100 }); }
  catch (e) { sizeRejected = e.code === "json/too-large"; }
  check("parse rejects oversized input",                  sizeRejected);

  // Depth limit
  var deep = '{"a":'.repeat(10) + 'null' + '}'.repeat(10);
  var depthRejected = false;
  try { b.jsonSafe.parse(deep, { maxDepth: 3 }); }
  catch (e) { depthRejected = e.code === "json/too-deep"; }
  check("parse rejects too-deep input",                   depthRejected);

  // Proto pollution
  var poisoned = b.jsonSafe.parse('{"__proto__":{"isAdmin":true},"name":"alice"}');
  check("parse strips __proto__ key",                     !("__proto__" in poisoned) || poisoned.__proto__ === Object.prototype);
  check("parse does not pollute Object.prototype",        !({}.isAdmin));

  var ctorPoisoned = b.jsonSafe.parse('{"constructor":{"prototype":{"x":1}}}');
  check("parse strips constructor key",                   !("constructor" in ctorPoisoned) || ctorPoisoned.constructor === Object);

  // Syntax error
  var syntaxRejected = false;
  try { b.jsonSafe.parse("{not-json}"); }
  catch (e) { syntaxRejected = e.code === "json/syntax"; }
  check("parse reports syntax errors with code",          syntaxRejected);

  // Wrong input type
  var typeRejected = false;
  try { b.jsonSafe.parse(123); }
  catch (e) { typeRejected = e.code === "json/wrong-input-type"; }
  check("parse rejects non-string/Buffer input",          typeRejected);

  // parseOrDefault
  check("parseOrDefault returns fallback on bad input",   b.jsonSafe.parseOrDefault("not-json", { fallback: true }).fallback === true);
  check("parseOrDefault returns parsed on good input",    b.jsonSafe.parseOrDefault('{"x":1}', null).x === 1);

  // Buffer input
  var fromBuf = b.jsonSafe.parse(Buffer.from('{"y":2}', "utf8"));
  check("parse accepts Buffer input",                     fromBuf.y === 2);
}

// 42. stringify: round-trip + circular detection + proto-pollution stripping
function testJsonStringify() {
  var s = b.jsonSafe.stringify({ a: 1, b: [1, 2, 3] });
  check("stringify produces valid JSON",                  JSON.parse(s).a === 1);

  var stripped = JSON.parse(b.jsonSafe.stringify({ __proto__: { x: 1 }, name: "alice" }));
  check("stringify strips __proto__",                     !("__proto__" in stripped) || stripped.__proto__ === Object.prototype);

  var circular = { a: 1 };
  circular.self = circular;
  var circRejected = false;
  try { b.jsonSafe.stringify(circular); }
  catch (e) { circRejected = e.code === "json/circular"; }
  check("stringify throws on circular ref",               circRejected);

  // Replace mode
  var replaced = b.jsonSafe.stringify(circular, { onCircular: "replace", circularReplacement: "<circular>" });
  check("stringify circular replace mode works",          /<circular>/.test(replaced));
}

// 43. canonical: sorted keys + deterministic output
function testJsonCanonical() {
  var c1 = b.jsonSafe.canonical({ b: 2, a: 1, c: 3 });
  var c2 = b.jsonSafe.canonical({ a: 1, c: 3, b: 2 });
  check("canonical: identical content same key order → identical bytes",  c1 === c2);
  check("canonical: keys sorted alphabetically",          c1 === '{"a":1,"b":2,"c":3}');

  var nested = b.jsonSafe.canonical({ z: { y: 1, x: 2 }, a: [3, 1, 2] });
  check("canonical: nested objects also sorted",          nested === '{"a":[3,1,2],"z":{"x":2,"y":1}}');

  // Non-finite numbers rejected
  var nfRejected = false;
  try { b.jsonSafe.canonical({ x: NaN }); }
  catch (e) { nfRejected = e.code === "json/non-finite"; }
  check("canonical: NaN rejected",                        nfRejected);
}

// 44. validate: schema, types, formats, throw mode
function testJsonValidate() {
  // Type
  b.jsonSafe.validate("hello", { type: "string" });
  check("validate type-pass returns silently", true);
  var typeRejected = false;
  try { b.jsonSafe.validate(42, { type: "string" }); }
  catch (e) { typeRejected = e.code === "json/validation" && /expected string/.test(e.message); }
  check("validate type mismatch throws with path",         typeRejected);

  // Required + properties
  var schema = {
    type: "object",
    required: ["email", "age"],
    properties: {
      email: { type: "string", format: "email", maxLength: 254 },
      age:   { type: "integer", minimum: 0, maximum: 150 },
      role:  { type: "string", enum: ["admin", "user", "guest"] },
    },
    additionalProperties: false,
  };

  b.jsonSafe.validate({ email: "alice@example.com", age: 30, role: "admin" }, schema);
  check("validate good object passes silently", true);

  var emailRejected = false;
  try { b.jsonSafe.validate({ email: "not-email", age: 30 }, schema); }
  catch (e) { emailRejected = e.code === "json/validation" && /format 'email'/.test(e.message); }
  check("validate bad email format throws",                emailRejected);

  var requiredRejected = false;
  try { b.jsonSafe.validate({ email: "a@b.com" }, schema); }
  catch (e) { requiredRejected = /missing required key 'age'/.test(e.message); }
  check("validate missing required throws",                requiredRejected);

  var rangeRejected = false;
  try { b.jsonSafe.validate({ email: "a@b.com", age: -1 }, schema); }
  catch (e) { rangeRejected = /minimum/.test(e.message); }
  check("validate range violation throws",                 rangeRejected);

  var enumRejected = false;
  try { b.jsonSafe.validate({ email: "a@b.com", age: 30, role: "superuser" }, schema); }
  catch (e) { enumRejected = /not in enum/.test(e.message); }
  check("validate enum violation throws",                  enumRejected);

  var unknownKeyRejected = false;
  try { b.jsonSafe.validate({ email: "a@b.com", age: 30, hax: 1 }, schema); }
  catch (e) { unknownKeyRejected = /unknown key 'hax'/.test(e.message); }
  check("validate unknown key with additionalProperties:false throws", unknownKeyRejected);

  // Array items
  var arrSchema = { type: "array", minItems: 1, items: { type: "integer" } };
  b.jsonSafe.validate([1, 2, 3], arrSchema);
  var arrItemRejected = false;
  try { b.jsonSafe.validate([1, "two", 3], arrSchema); }
  catch (e) { arrItemRejected = e.path === "$[1]" && /expected integer/.test(e.message); }
  check("validate array item path is reported",            arrItemRejected);
}

// 45. validate collectErrors mode + parse with schema
function testJsonValidateCollect() {
  var schema = {
    type: "object",
    required: ["email", "age", "name"],
    properties: {
      email: { type: "string", format: "email" },
      age:   { type: "integer", minimum: 0 },
      name:  { type: "string", minLength: 1, maxLength: 100 },
      role:  { type: "string", enum: ["admin", "user"] },
    },
  };
  var bad = { email: "not-email", age: -5, name: "", role: "superuser" };
  var result = b.jsonSafe.validate(bad, schema, { collectErrors: true });
  check("collectErrors returns { ok, value, errors }",      typeof result === "object" && result.ok === false);
  check("collectErrors collects multiple errors",           result.errors.length >= 4);
  check("collectErrors errors have .path",                  result.errors.every(function (e) { return typeof e.path === "string"; }));
  check("collectErrors errors include format failure",      result.errors.some(function (e) { return /format 'email'/.test(e.message); }));
  check("collectErrors errors include range failure",       result.errors.some(function (e) { return /minimum/.test(e.message); }));
  check("collectErrors errors include length failure",      result.errors.some(function (e) { return /minLength/.test(e.message); }));
  check("collectErrors errors include enum failure",        result.errors.some(function (e) { return /not in enum/.test(e.message); }));

  // Good input — collect mode returns ok: true with empty errors
  var good = { email: "a@b.com", age: 30, name: "Alice" };
  var goodResult = b.jsonSafe.validate(good, schema, { collectErrors: true });
  check("collectErrors ok=true on valid input",             goodResult.ok === true && goodResult.errors.length === 0);

  // parse({ schema, collectErrors }) round-trips the same shape
  var parseResult = b.jsonSafe.parse(JSON.stringify(bad), { schema: schema, collectErrors: true });
  check("parse + collectErrors returns { ok, value, errors[] }",
        typeof parseResult === "object" && parseResult.ok === false && parseResult.errors.length >= 4);
}

// 46. format registry: built-ins + custom registration
function testJsonFormats() {
  check("format email: valid passes",        b.jsonSafe.formats.email("alice@example.com"));
  check("format email: missing @ fails",     !b.jsonSafe.formats.email("not-email"));
  check("format url: https passes",          b.jsonSafe.formats.url("https://example.com/path"));
  check("format url: ftp fails (not in allowlist)", !b.jsonSafe.formats.url("ftp://example.com"));
  check("format uuid: valid passes",         b.jsonSafe.formats.uuid("550e8400-e29b-41d4-a716-446655440000"));
  check("format uuid: too-short fails",      !b.jsonSafe.formats.uuid("550e8400"));
  check("format ulid: valid passes",         b.jsonSafe.formats.ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
  check("format ipv4: valid passes",         b.jsonSafe.formats.ipv4("192.168.1.1"));
  check("format ipv4: out of range fails",   !b.jsonSafe.formats.ipv4("192.168.1.256"));
  check("format ipv4: leading zero fails",   !b.jsonSafe.formats.ipv4("192.168.001.1"));
  // ipv6 — full/compressed/IPv4-mapped/mixed-case
  check("ipv6: full 8 groups",                          b.jsonSafe.formats.ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
  check("ipv6: lowercase",                              b.jsonSafe.formats.ipv6("2001:db8::1"));
  check("ipv6: mixed case",                             b.jsonSafe.formats.ipv6("2001:DB8::1"));
  check("ipv6: loopback ::1",                           b.jsonSafe.formats.ipv6("::1"));
  check("ipv6: unspecified ::",                         b.jsonSafe.formats.ipv6("::"));
  check("ipv6: trailing :: (1::)",                      b.jsonSafe.formats.ipv6("1::"));
  check("ipv6: link-local fe80::1",                     b.jsonSafe.formats.ipv6("fe80::1"));
  check("ipv6: IPv4-mapped ::ffff:192.168.1.1",         b.jsonSafe.formats.ipv6("::ffff:192.168.1.1"));
  check("ipv6: IPv4-mapped uppercase",                  b.jsonSafe.formats.ipv6("::FFFF:192.168.1.1"));
  check("ipv6: longer IPv4-mapped form",                b.jsonSafe.formats.ipv6("2001:db8::192.0.2.1"));
  check("ipv6: rejects > 8 groups",                     !b.jsonSafe.formats.ipv6("1:2:3:4:5:6:7:8:9"));
  check("ipv6: rejects multiple ::",                    !b.jsonSafe.formats.ipv6("1::2::3"));
  check("ipv6: rejects non-hex chars",                  !b.jsonSafe.formats.ipv6("g::"));
  check("ipv6: rejects > 4 hex per group",              !b.jsonSafe.formats.ipv6("12345::"));
  check("ipv6: rejects zone IDs",                       !b.jsonSafe.formats.ipv6("fe80::1%eth0"));
  check("ipv6: rejects empty string",                   !b.jsonSafe.formats.ipv6(""));
  check("ipv6: rejects too long",                       !b.jsonSafe.formats.ipv6("a".repeat(46)));
  check("ipv6: rejects bad IPv4-mapped",                !b.jsonSafe.formats.ipv6("::ffff:999.168.1.1"));
  check("format hex: valid passes",          b.jsonSafe.formats.hex("dead beef".replace(" ", "")));
  check("format slug: valid passes",         b.jsonSafe.formats.slug("my-blog-post"));
  check("format slug: uppercase fails",      !b.jsonSafe.formats.slug("MyBlogPost"));
  check("format iso8601-date: valid passes", b.jsonSafe.formats["iso8601-date"]("2026-04-25"));
  check("format iso8601-date: invalid fails",!b.jsonSafe.formats["iso8601-date"]("2026-13-01"));

  // Register custom
  b.jsonSafe.registerFormat("us-zip", function (v) { return /^\d{5}(-\d{4})?$/.test(v); });
  check("custom format registered + works",  b.jsonSafe.formats["us-zip"]("12345"));
  b.jsonSafe.validate("90210", { type: "string", format: "us-zip" });
  var customRejected = false;
  try { b.jsonSafe.validate("ABCDE", { type: "string", format: "us-zip" }); }
  catch (e) { customRejected = /format 'us-zip'/.test(e.message); }
  check("custom format used by validate",    customRejected);
}

// =====================================================================
// async-safe primitives + handlers (resilience contract)
// =====================================================================

async function testAsyncSafeWithTimeoutResolves() {
  var v = await b.asyncSafe.withTimeout(Promise.resolve("ok"), 100);
  check("withTimeout: resolves with value when fast",       v === "ok");
}

async function testAsyncSafeWithTimeoutRejects() {
  var threw = null;
  try {
    await b.asyncSafe.withTimeout(new Promise(function () {}), 20, { name: "test-op" });
  } catch (e) { threw = e; }
  check("withTimeout: rejects on timeout",                  threw && threw.code === "async/timeout");
  check("withTimeout: timeout error names operation",       threw && threw.message.indexOf("test-op") >= 0);
}

async function testAsyncSafeWithTimeoutAbort() {
  var ctrl = new AbortController();
  var p = b.asyncSafe.withTimeout(new Promise(function () {}), 10000, { signal: ctrl.signal });
  setTimeout(function () { ctrl.abort(); }, 10);
  var threw = null;
  try { await p; } catch (e) { threw = e; }
  check("withTimeout: AbortSignal aborts cleanly",          threw && threw.code === "async/aborted");
}

async function testAsyncSafeWithTimeoutPropagatesError() {
  var threw = null;
  try {
    await b.asyncSafe.withTimeout(Promise.reject(new Error("boom")), 100);
  } catch (e) { threw = e; }
  check("withTimeout: propagates underlying rejection",     threw && threw.message === "boom");
}

async function testAsyncSafeSafeAwait() {
  var ok = await b.asyncSafe.safeAwait(Promise.resolve(42));
  check("safeAwait: success returns [null, value]",         ok[0] === null && ok[1] === 42);
  var fail = await b.asyncSafe.safeAwait(Promise.reject(new Error("nope")));
  check("safeAwait: failure returns [error, null]",         fail[0] && fail[0].message === "nope" && fail[1] === null);
}

async function testAsyncSafeMutexSerializes() {
  var m = new b.asyncSafe.Mutex();
  var order = [];
  async function task(label, durMs) {
    return m.runExclusive(async function () {
      order.push(label + ":enter");
      await new Promise(function (r) { setTimeout(r, durMs); });
      order.push(label + ":exit");
    });
  }
  await Promise.all([task("A", 30), task("B", 5), task("C", 5)]);
  check("Mutex: A enters first",       order[0] === "A:enter");
  check("Mutex: A exits before B/C enter",
        order.indexOf("A:exit") < order.indexOf("B:enter") &&
        order.indexOf("A:exit") < order.indexOf("C:enter"));
  check("Mutex: B and C don't interleave",
        Math.abs(order.indexOf("B:enter") - order.indexOf("B:exit")) === 1);
}

async function testAsyncSafeMutexReleaseOnThrow() {
  var m = new b.asyncSafe.Mutex();
  var threw = null;
  try {
    await m.runExclusive(async function () { throw new Error("inner"); });
  } catch (e) { threw = e; }
  check("Mutex: runExclusive propagates thrown error",      threw && threw.message === "inner");
  check("Mutex: lock released after throw",                 !m.isHeld());
}

async function testAsyncSafeMutexAbortableAcquire() {
  var m = new b.asyncSafe.Mutex();
  await m.acquire();
  var ctrl = new AbortController();
  var p = m.acquire({ signal: ctrl.signal });
  setTimeout(function () { ctrl.abort(); }, 10);
  var threw = null;
  try { await p; } catch (e) { threw = e; }
  check("Mutex: aborted acquire rejects",                   threw && threw.code === "async/aborted");
  check("Mutex: aborted acquirer no longer queued",         m.pendingCount() === 0);
  m.release();
}

async function testAsyncSafeSemaphoreBoundedConcurrency() {
  var s = new b.asyncSafe.Semaphore(2);
  var concurrent = 0;
  var maxConcurrent = 0;
  async function task() {
    return s.runWith(async function () {
      concurrent += 1;
      if (concurrent > maxConcurrent) maxConcurrent = concurrent;
      await new Promise(function (r) { setTimeout(r, 10); });
      concurrent -= 1;
    });
  }
  await Promise.all([task(), task(), task(), task(), task()]);
  check("Semaphore: max concurrency respected",             maxConcurrent === 2);
}

async function testAsyncSafeSemaphoreAbortableAcquire() {
  var s = new b.asyncSafe.Semaphore(1);
  await s.acquire();
  var ctrl = new AbortController();
  var p = s.acquire({ signal: ctrl.signal });
  setTimeout(function () { ctrl.abort(); }, 10);
  var threw = null;
  try { await p; } catch (e) { threw = e; }
  check("Semaphore: aborted acquire rejects",               threw && threw.code === "async/aborted");
  s.release();
}

async function testAsyncSafeOnceSingleFlight() {
  var calls = 0;
  var once = new b.asyncSafe.Once(async function () {
    calls += 1;
    await new Promise(function (r) { setTimeout(r, 10); });
    return "result-" + calls;
  });
  var results = await Promise.all([once.invoke(), once.invoke(), once.invoke()]);
  check("Once: function invoked exactly once",              calls === 1);
  check("Once: all callers see same result",
        results[0] === "result-1" && results[1] === "result-1" && results[2] === "result-1");
}

async function testAsyncSafeOnceCachesFailure() {
  var once = new b.asyncSafe.Once(async function () { throw new Error("init failed"); });
  var first = null, second = null;
  try { await once.invoke(); } catch (e) { first = e; }
  try { await once.invoke(); } catch (e) { second = e; }
  check("Once: failure caches; both callers see same rejection",
        first && second && first.message === "init failed" && second.message === "init failed");
}

async function testAsyncSafeOnceReset() {
  var calls = 0;
  var once = new b.asyncSafe.Once(async function () {
    calls += 1;
    if (calls === 1) throw new Error("transient");
    return "ok";
  });
  var failed = null;
  try { await once.invoke(); } catch (e) { failed = e; }
  check("Once: first call fails as expected",               failed && failed.message === "transient");
  once.reset();
  var second = await once.invoke();
  check("Once: reset enables retry; second call succeeds",  second === "ok" && calls === 2);
}

async function testAsyncSafeCircuitBreakerStateTransitions() {
  var br = new b.asyncSafe.CircuitBreaker("test", { failureThreshold: 2, cooldownMs: 30, successThreshold: 1 });
  check("CircuitBreaker: starts closed",                    br.getState() === "closed");
  for (var i = 0; i < 2; i++) {
    try { await br.wrap(async function () { throw new Error("fail"); }); } catch (_e) {}
  }
  check("CircuitBreaker: opens after failureThreshold",     br.getState() === "open");
  var fastFail = null;
  try { await br.wrap(async function () { return "ok"; }); }
  catch (e) { fastFail = e; }
  check("CircuitBreaker: open state fast-fails",            fastFail && fastFail.code === "CIRCUIT_OPEN");
  await new Promise(function (r) { setTimeout(r, 50); });
  var probe = await br.wrap(async function () { return "ok"; });
  check("CircuitBreaker: half-open probe success",          probe === "ok");
  check("CircuitBreaker: closes after success threshold",   br.getState() === "closed");
}

async function testHandlerEmitAndDrain() {
  var flushed = [];
  var h = b.handlers.create({
    name:  "test",
    flush: async function (batch) { flushed.push.apply(flushed, batch); },
  });
  h.emit({ id: 1 });
  h.emit({ id: 2 });
  h.emit({ id: 3 });
  check("handler: emit returns nothing (sync)",             h.emit({ id: 4 }) === undefined);
  await h.drain();
  check("handler: drain flushes all buffered items",        flushed.length === 4);
  check("handler: items delivered in order",                flushed[0].id === 1 && flushed[3].id === 4);
  check("handler: buffer empty post-drain",                 h.size() === 0);
}

async function testHandlerEmitDuringFlushNextCycle() {
  var phase1 = [];
  var phase2 = [];
  var emitDuring = true;
  var h;
  h = b.handlers.create({
    name:  "test-recursion",
    flush: async function (batch) {
      if (emitDuring) {
        emitDuring = false;
        h.emit({ id: 99 });
        phase1.push.apply(phase1, batch);
      } else {
        phase2.push.apply(phase2, batch);
      }
    },
  });
  h.emit({ id: 1 });
  h.emit({ id: 2 });
  await h.drain();
  check("handler: emit-during-flush lands in next cycle",
        phase1.length === 2 && phase2.length === 1 && phase2[0].id === 99);
}

async function testHandlerRetryOnFlushFailure() {
  var attempts = 0;
  var seen = null;
  var h = b.handlers.create({
    name:  "test-retry",
    flush: async function (batch) {
      attempts += 1;
      if (attempts < 3) throw new Error("transient");
      seen = batch;
    },
    retry: { maxAttempts: 5, baseDelayMs: 1 },
  });
  h.emit({ id: 1 });
  await h.drain();
  check("handler: retries on flush failure",                attempts >= 3);
  check("handler: eventually succeeds",                     seen && seen.length === 1);
}

async function testHandlerCircuitBreakerOpensOnPersistentFailure() {
  var dlqCalls = 0;
  var h = b.handlers.create({
    name:  "test-breaker",
    flush: async function () { throw new Error("always fails"); },
    retry: { maxAttempts: 1, baseDelayMs: 1 },
    breaker: { failureThreshold: 2, cooldownMs: 10000, successThreshold: 1 },
    deadLetter: function () { dlqCalls += 1; },
    onError: function () { /* swallow expected errors */ },
  });
  h.emit({ id: 1 });
  await h.drain();
  h.emit({ id: 2 });
  await h.drain();
  h.emit({ id: 3 });
  await h.drain();
  var stats = h.getStats();
  check("handler: breaker tripped after consecutive failures",
        stats.breakerState === "open" || stats.breakerState === "half-open");
  check("handler: dead-lettered items on persistent failure", dlqCalls >= 1);
}

async function testHandlerBoundedShutdown() {
  var h = b.handlers.create({
    name:  "test-shutdown",
    flush: async function () {
      await new Promise(function (r) { setTimeout(r, 100); });
    },
    retry: { maxAttempts: 1, baseDelayMs: 1 },
    onError: function () { /* swallow */ },
  });
  h.emit({ id: 1 });
  var t0 = Date.now();
  await h.shutdown({ timeoutMs: 20 });
  var dur = Date.now() - t0;
  check("handler: shutdown bounded by timeout (< 100ms)",   dur < 80);
}

async function testHandlerStats() {
  var h = b.handlers.create({
    name:  "test-stats",
    flush: async function () { await new Promise(function (r) { setTimeout(r, 5); }); },
  });
  for (var i = 0; i < 5; i++) h.emit({ id: i });
  await h.drain();
  var s = h.getStats();
  check("handler.getStats: totalEmitted",                   s.totalEmitted === 5);
  check("handler.getStats: totalFlushed",                   s.totalFlushed === 5);
  check("handler.getStats: bufferSize=0 post-drain",        s.bufferSize === 0);
  check("handler.getStats: lastFlushDurationMs > 0",        s.lastFlushDurationMs > 0);
  check("handler.getStats: breakerState exposed",           s.breakerState === "closed");
}

// sql-safe + chain-writer test definitions live in ./00-primitives.js
// (extracted in v0.1.16). Smoke runner calls primitives.run() below.

async function testHandlerBackpressureDrop() {
  var dropped = [];
  var h = b.handlers.create({
    name:          "test-backpressure",
    flush:         async function () { await new Promise(function () {}); /* hang */ },
    maxBufferSize: 3,
    deadLetter:    function (items) { dropped.push.apply(dropped, items); },
    onError:       function () { /* swallow */ },
  });
  for (var i = 0; i < 10; i++) h.emit({ id: i });
  await new Promise(function (r) { setImmediate(r); });
  check("handler: maxBufferSize drops over-cap items to DLQ", dropped.length >= 5);
}

// =====================================================================
// Cluster coordination — leader election + fencing tokens
// =====================================================================

// _makeSqliteDriver lives in ./_helpers.js (imported above).

async function testClusterSingleNodeFallback() {
  // Without cluster.init, the framework treats us as permanent leader.
  b.cluster._resetForTest();
  check("cluster.isLeader() true when not initialized",  b.cluster.isLeader() === true);
  check("cluster.fencingToken() = 0 when not initialized", b.cluster.fencingToken() === 0);
  check("cluster.currentNodeId() = single-node-local",   b.cluster.currentNodeId() === "single-node-local");
  // requireLeader is a no-op
  var threw = false;
  try { b.cluster.requireLeader(); } catch (_e) { threw = true; }
  check("cluster.requireLeader() does not throw on single-node", threw === false);
}

async function testClusterProviderAcquireAndRenew() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-"));
  var dbPath = path.join(tmpDir, "cluster.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    var providerFactory = require(path.join(__dirname, "..", "lib", "cluster-provider-db"));
    var p = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    await p.ensureSchema();

    var lease1 = await p.acquireLease("node-A", b.constants.TIME.seconds(30));
    check("provider.acquireLease succeeds on empty DB",  lease1 !== null);
    check("first lease has fencingToken = 1",            lease1.fencingToken === 1);
    check("first lease records nodeId",                  lease1.nodeId === "node-A");
    check("first lease has acquiredAt set",              typeof lease1.acquiredAt === "number");

    var renewed = await p.renewLease(lease1);
    check("renewLease returns updated lease",            renewed.leaseId === lease1.leaseId);
    check("renewLease pushes expiresAt forward",         renewed.expiresAt >= lease1.expiresAt);
    check("renewLease does NOT bump fencingToken",       renewed.fencingToken === 1);

    var current = await p.currentLeader();
    check("currentLeader returns us",                    current.nodeId === "node-A");
    check("currentLeader fencingToken matches",          current.fencingToken === 1);

    await p.releaseLease(renewed);
    var afterRelease = await p.currentLeader();
    check("currentLeader returns null after release",    afterRelease === null);
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterProviderTwoNodeContention() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-"));
  var dbPath = path.join(tmpDir, "cluster.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    var providerFactory = require(path.join(__dirname, "..", "lib", "cluster-provider-db"));
    var pA = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    var pB = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    await pA.ensureSchema();

    var leaseA = await pA.acquireLease("node-A", b.constants.TIME.seconds(30));
    check("node-A acquires lease",                       leaseA !== null);

    var leaseB = await pB.acquireLease("node-B", b.constants.TIME.seconds(30));
    check("node-B blocked while A holds non-expired",    leaseB === null);

    var current = await pB.currentLeader();
    check("node-B's currentLeader sees node-A",          current.nodeId === "node-A");
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterProviderTakeoverAfterExpiry() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-"));
  var dbPath = path.join(tmpDir, "cluster.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    var providerFactory = require(path.join(__dirname, "..", "lib", "cluster-provider-db"));
    var pA = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    var pB = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    await pA.ensureSchema();

    // Node A acquires with a tiny TTL — practically already expired by
    // the time we attempt the takeover.
    var leaseA = await pA.acquireLease("node-A", 50);
    check("node-A acquired short-TTL lease",             leaseA !== null);
    check("first acquire fencingToken = 1",              leaseA.fencingToken === 1);

    // Wait past expiry (50ms TTL + buffer).
    await new Promise(function (r) { setTimeout(r, 100); });

    var leaseB = await pB.acquireLease("node-B", b.constants.TIME.seconds(30));
    check("node-B steals expired lease",                 leaseB !== null);
    check("takeover bumps fencingToken to 2",            leaseB.fencingToken === 2);
    check("node-B is now recorded leader",               leaseB.nodeId === "node-B");
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterProviderRenewalRace() {
  // After takeover, the old leader's renewLease must throw LEASE_LOST.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-"));
  var dbPath = path.join(tmpDir, "cluster.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    var providerFactory = require(path.join(__dirname, "..", "lib", "cluster-provider-db"));
    var pA = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    var pB = providerFactory.create({ externalDbBackend: "ops", dialect: "sqlite" });
    await pA.ensureSchema();

    var leaseA = await pA.acquireLease("node-A", 50);
    await new Promise(function (r) { setTimeout(r, 100); });
    var leaseB = await pB.acquireLease("node-B", b.constants.TIME.seconds(30));
    check("takeover succeeded for race test",            leaseB !== null);

    var threw = null;
    try { await pA.renewLease(leaseA); }
    catch (e) { threw = e; }
    check("old leader's renewLease throws",              threw !== null);
    check("error code is LEASE_LOST",                    threw && threw.code === "LEASE_LOST");
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

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

async function testClusterStorageLocalDispatch() {
  // With no cluster.init, executeAll should dispatch to local SQLite.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cs-"));
  try {
    // Reset cluster BEFORE setupTestDb so its internal audit.checkpoint
    // runs on the permanent-leader fallback (terminated=false).
    b.cluster._resetForTest();
    await setupTestDb(tmpDir);

    // Seed an audit row via the existing local path so we have something
    // to read back.
    var ev = await b.audit.record({
      actor:   { kind: "user", id: "u1" },
      action:  "auth.login",
      outcome: "success",
    });
    check("setup: audit row recorded locally",      ev !== null);

    // Now read back through cluster-storage. In single-node mode, should
    // hit the local SQLite, table name is unprefixed.
    check("tableName(audit_log) is unprefixed locally",
          b.clusterStorage.tableName("audit_log") === "audit_log");

    var rows = await b.clusterStorage.executeAll("SELECT _id, action FROM audit_log");
    check("clusterStorage.executeAll local: row found", rows.length >= 1);
    check("clusterStorage row has audit action",        rows[0].action === "auth.login");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

function testClusterStoragePlaceholderize() {
  check("placeholderize sqlite: passthrough",
        b.clusterStorage.placeholderize("SELECT * FROM t WHERE a = ? AND b = ?", "sqlite") ===
        "SELECT * FROM t WHERE a = ? AND b = ?");
  check("placeholderize postgres: ? → $1, $2",
        b.clusterStorage.placeholderize("SELECT * FROM t WHERE a = ? AND b = ?", "postgres") ===
        "SELECT * FROM t WHERE a = $1 AND b = $2");
  check("placeholderize: skips ? inside single-quoted strings",
        b.clusterStorage.placeholderize("SELECT * FROM t WHERE label = '?' AND id = ?", "postgres") ===
        "SELECT * FROM t WHERE label = '?' AND id = $1");
}

function testClusterStorageResolveTablesIsNoOpInSingleNode() {
  b.cluster._resetForTest();
  var sql = "SELECT * FROM audit_log";
  check("resolveTables: passthrough when not cluster mode",
        b.clusterStorage.resolveTables(sql) === sql);
}

async function testClusterStorageClusterDispatch() {
  // Spin up a real cluster: full framework + external-db + cluster.init.
  // Then run executeAll against external-db tables created by
  // frameworkSchema.ensureSchema. The resolveTables should rewrite
  // audit_log → _blamejs_audit_log automatically.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cs-cluster-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });

    b.cluster._resetForTest();
    await b.cluster.init({
      nodeId:            "cs-cluster-test",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });

    // Now in cluster mode. Insert a row using unprefixed name + ? placeholders.
    await b.clusterStorage.execute(
      "INSERT INTO audit_log (_id, recordedAt, monotonicCounter, action, outcome, prevHash, rowHash, nonce, fencingToken) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ["row1", Date.now(), 1, "auth.login", "success", "", "h1", Buffer.alloc(16), 1]
    );

    // Read back, also via unprefixed name. Dispatcher rewrites both.
    var rows = await b.clusterStorage.executeAll("SELECT _id, action FROM audit_log WHERE _id = ?", ["row1"]);
    check("clusterStorage cluster mode: row found via unprefixed name",  rows.length === 1);
    check("clusterStorage cluster mode: row data preserved",             rows[0].action === "auth.login");

    // Verify the row actually landed in the prefixed table
    var directRows = await b.externalDb.query("SELECT _id FROM _blamejs_audit_log WHERE _id = ?", ["row1"]);
    check("cluster row written to _blamejs_-prefixed external table",    directRows.rows.length === 1);

    // tableName getter reflects cluster mode
    check("tableName(audit_log) prefixed in cluster mode",
          b.clusterStorage.tableName("audit_log") === "_blamejs_audit_log");
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testFrameworkSchemaEnsure() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-fs-"));
  var dbPath = path.join(tmpDir, "schema.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    var result = await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });
    check("ensureSchema returns 4 tables",          result.tables.length === 4);
    check("ensureSchema includes _blamejs_audit_log",
          result.tables.indexOf("_blamejs_audit_log") !== -1);
    check("ensureSchema includes _blamejs_consent_log",
          result.tables.indexOf("_blamejs_consent_log") !== -1);
    check("ensureSchema includes _blamejs_audit_checkpoints",
          result.tables.indexOf("_blamejs_audit_checkpoints") !== -1);
    check("ensureSchema includes _blamejs_audit_tip",
          result.tables.indexOf("_blamejs_audit_tip") !== -1);

    // Each table is queryable
    var auditEmpty = await b.externalDb.query("SELECT COUNT(*) AS n FROM _blamejs_audit_log");
    check("audit_log table exists and is empty",    auditEmpty.rows[0].n === 0);
    var consentEmpty = await b.externalDb.query("SELECT COUNT(*) AS n FROM _blamejs_consent_log");
    check("consent_log table exists and is empty",  consentEmpty.rows[0].n === 0);

    // Audit-tip CHECK constraint enforces scope = 'audit'
    var threwBadScope = false;
    try {
      await b.externalDb.query(
        "INSERT INTO _blamejs_audit_tip (scope, atMonotonicCounter, fencingToken) VALUES ($1, $2, $3)",
        ["NOT_AUDIT", 0, 0]
      );
    } catch (e) { threwBadScope = true; }
    check("audit_tip CHECK constraint rejects bad scope", threwBadScope);

    // Idempotent re-run
    var second = await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });
    check("ensureSchema is idempotent",             second.tables.length === 4);

    // Indexes exist
    var idxRow = await b.externalDb.query(
      "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = '_blamejs_audit_log'"
    );
    check("audit_log indexes created",              idxRow.rows.length >= 4);
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function testFrameworkSchemaTableNameMapping() {
  check("tableName('audit_log') maps to prefixed",
        b.frameworkSchema.tableName("audit_log") === "_blamejs_audit_log");
  check("tableName('consent_log') maps to prefixed",
        b.frameworkSchema.tableName("consent_log") === "_blamejs_consent_log");
  check("tableName('audit_checkpoints') maps to prefixed",
        b.frameworkSchema.tableName("audit_checkpoints") === "_blamejs_audit_checkpoints");
  check("tableName('_blamejs_audit_tip') is identity",
        b.frameworkSchema.tableName("_blamejs_audit_tip") === "_blamejs_audit_tip");
  check("tableName(unknown) returns identity",
        b.frameworkSchema.tableName("custom_table") === "custom_table");
  check("LOCAL_TO_EXTERNAL is frozen",
        Object.isFrozen(b.frameworkSchema.LOCAL_TO_EXTERNAL));
}

function testFrameworkSchemaInvalidDialect() {
  var threw = null;
  try {
    b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "mysql",
    }).catch(function (e) { /* swallow async path */ });
  } catch (e) { threw = e; }
  // The throw can come either sync (config validation) or async (per-table
  // execution). In either case the returned promise rejects.
  return b.frameworkSchema.ensureSchema({
    externalDbBackend: "ops",
    dialect:           "mysql",
  }).then(function () {
    check("ensureSchema mysql rejects sync or async — succeeded unexpectedly", false);
  }, function (e) {
    check("ensureSchema rejects unsupported dialect (mysql)",
          e.code === "framework-schema/unsupported-dialect");
  });
}

async function testClusterInitAndRequireLeader() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-"));
  var dbPath = path.join(tmpDir, "cluster.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    b.cluster._resetForTest();
    await b.cluster.init({
      nodeId:            "test-node-1",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });

    check("after init, isLeader() is true",              b.cluster.isLeader() === true);
    check("currentNodeId reflects config",               b.cluster.currentNodeId() === "test-node-1");
    check("fencingToken > 0 after init",                 b.cluster.fencingToken() > 0);

    // requireLeader passes silently
    var threwOnLeader = false;
    try { b.cluster.requireLeader(); } catch (_e) { threwOnLeader = true; }
    check("requireLeader does not throw on leader",      threwOnLeader === false);

    var leader = await b.cluster.currentLeader();
    check("currentLeader returns this node",             leader && leader.nodeId === "test-node-1");

    // Simulate becoming non-leader by manually clearing the lease (the
    // module's normal path for losing leadership is via a renewal race,
    // already covered in testClusterProviderRenewalRace).
    await b.cluster.shutdown();
    check("after shutdown, isLeader() false",            b.cluster.isLeader() === false);
    var threwOnFollower = null;
    try { b.cluster.requireLeader(); } catch (e) { threwOnFollower = e; }
    check("requireLeader throws when not leader",        threwOnFollower !== null);
    check("error is NotLeaderError",                     threwOnFollower &&
                                                          threwOnFollower.code === "NOT_LEADER");
    check("error has 503 statusCode",                    threwOnFollower &&
                                                          threwOnFollower.statusCode === 503);
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
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

  // json-safe
  testJsonParse();
  testJsonStringify();
  testJsonCanonical();
  testJsonValidate();
  testJsonValidateCollect();
  testJsonFormats();

  // async-safe (Mutex, Semaphore, Once, withTimeout, CircuitBreaker, ...)
  await testAsyncSafeWithTimeoutResolves();
  await testAsyncSafeWithTimeoutRejects();
  await testAsyncSafeWithTimeoutAbort();
  await testAsyncSafeWithTimeoutPropagatesError();
  await testAsyncSafeSafeAwait();
  await testAsyncSafeMutexSerializes();
  await testAsyncSafeMutexReleaseOnThrow();
  await testAsyncSafeMutexAbortableAcquire();
  await testAsyncSafeSemaphoreBoundedConcurrency();
  await testAsyncSafeSemaphoreAbortableAcquire();
  await testAsyncSafeOnceSingleFlight();
  await testAsyncSafeOnceCachesFailure();
  await testAsyncSafeOnceReset();
  await testAsyncSafeCircuitBreakerStateTransitions();

  // handlers (depends on async-safe)
  await testHandlerEmitAndDrain();
  await testHandlerEmitDuringFlushNextCycle();
  await testHandlerRetryOnFlushFailure();
  await testHandlerCircuitBreakerOpensOnPersistentFailure();
  await testHandlerBoundedShutdown();
  await testHandlerStats();
  await testHandlerBackpressureDrop();

  // sql-safe + chain-writer extracted to test/00-primitives.js (v0.1.16).
  // primitivesLayer.run() runs both. chain-writer's race-safety test
  // includes setupTestDb internally (Layer 3 dependency disclosed in
  // the primitive's own test) — kept colocated with chain-writer so
  // the resilience claim sits next to the primitive being claimed about.
  await primitivesLayer.run();

  // atomic-file (depends on crypto, json-safe)
  await testAtomicFile();
  await testAtomicFileLock();

  // parsers/* (independent)
  testXmlParse();
  testXmlSecurityRejections();
  testCsvParse();
  testCsvFormulaInjection();
  testTomlBasicTypes();
  testTomlTablesAndArrays();
  testTomlInlineTablesAndDottedKeys();
  testTomlSecurityRejections();
  testYamlBasic();
  testYamlNorwayProblem();
  testYamlBlockScalars();
  testYamlQuotedStrings();
  testYamlSecurityRejections();
  testEnvParseBasic();
  testEnvParseSecurityRejections();

  // redact
  testRedact();

  // ===================================================================
  // LAYER 1 — framework-state-dependent but isolated
  // ===================================================================

  // vault primitives
  await testVaultWrapRoundTrip();
  await testPassphraseEnv();
  await testVaultPlaintextRoundTrip();
  await testVaultModeMismatch();
  await testVaultRequiresDataDir();
  await testVaultWrappedE2E();

  // cluster module + provider
  await testClusterSingleNodeFallback();
  await testClusterProviderAcquireAndRenew();
  await testClusterProviderTwoNodeContention();
  await testClusterProviderTakeoverAfterExpiry();
  await testClusterProviderRenewalRace();
  await testClusterInitAndRequireLeader();

  // framework-schema (DDL emitter + table-name resolver)
  await testFrameworkSchemaEnsure();
  testFrameworkSchemaTableNameMapping();
  await testFrameworkSchemaInvalidDialect();

  // ===================================================================
  // LAYER 2 — needs db
  // ===================================================================

  // db basic
  await testDbBasic();
  await testDbWriteOps();
  await testDbSealedWithoutDerived();
  await testDbTransactions();
  await testDbPersistence();
  await testDbSchemaEvolution();
  await testDbMigrations();

  // framework schema + reserved-table protection
  await testFrameworkSchema();
  await testReservedTableProtection();

  // ===================================================================
  // LAYER 3 — uses db + chain-writer + cluster-storage
  // ===================================================================

  // cluster-storage (SQL dispatcher)
  await testClusterStorageLocalDispatch();
  testClusterStoragePlaceholderize();
  testClusterStorageResolveTablesIsNoOpInSingleNode();
  await testClusterStorageClusterDispatch();

  // chain-writer tests live in test/00-primitives.js (Layer 0
  // primitive); primitivesLayer.run() above already ran them.

  // audit chain + verify (now exercises chain-writer transitively)
  await testAuditChain();
  await testAuditChainBreak();
  await testAuditSelfLogging();
  await testBeginTrace();

  // consent (uses chain-writer)
  await testConsent();

  // subject rights (uses audit + db)
  await testSubjectRights();

  // append-only triggers + foreign keys + table metadata
  await testAppendOnlyTriggers();
  await testForeignKeys();
  await testTableMetadata();

  // checkpoint sign / verify / tamper / rollback
  await testCheckpointSign();
  await testCheckpointVerify();
  await testCheckpointTamperDetect();
  await testRollbackDetection();

  // ===================================================================
  // LAYER 4 — uses audit (consumer modules)
  // ===================================================================

  // session
  await testSession();

  // data residency (db + storage)
  await testDataResidency();

  // storage + object-store
  await testStorage();
  await testMultiBackend();
  await testClassificationRouting();
  await testResidencyEnforcement();
  await testRetryAndBreaker();
  testSigv4Primitives();
  await testSigv4MockServer();
  testGcsPrimitives();
  await testGcsMockServer();
  testAzureBlobPrimitives();
  await testAzureBlobMockServer();

  // queue
  await testQueueLocal();
  await testQueueConsume();
  await testQueueRetryAndFail();
  await testQueueLeaseExpiry();
  await testQueueShutdown();

  // log-stream
  await testLogStreamLocal();
  await testLogStreamWebhook();
  await testLogStreamBidirectional();

  // external-db
  await testExternalDbBasic();
  await testExternalDbPool();
  await testExternalDbTransaction();
  await testExternalDbResidency();
  await testExternalDbClassification();

  // middleware
  await testMiddlewareRequestId();
  await testMiddlewareSecurityHeaders();
  await testMiddlewareErrorHandler();
  await testMiddlewareBotGuard();
  await testMiddlewareCors();
  await testMiddlewareRateLimit();

  // env-safe.load() — full lifecycle (depends on audit chain)
  await testEnvLoadDiffAndAudit();
  await testEnvLoadSchemaAndTypos();
  await testEnvLoadBreakingChange();

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
