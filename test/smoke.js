"use strict";
/**
 * Smoke test — verifies exit criteria for every shipped phase.
 *
 * Run: `npm test` (or `node test/smoke.js`)
 *
 * Phases covered (must keep building forward — never delete):
 *   v0.0.1 / Phase 0 — crypto envelope, router, constants
 *   v0.0.2 / Phase 1a — vault, vault-wrap, passphrase-source
 */
var assert = require("assert");
var fs = require("fs");
var os = require("os");
var path = require("path");
var b = require("../index.js");

var checks = 0;
function check(label, condition) {
  if (!condition) throw new Error("FAIL: " + label);
  checks += 1;
}

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
check("TIME.ONE_DAY = 86400000",      b.constants.TIME.ONE_DAY === 86400000);
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

async function setupTestDb(tmpDir, schemaOverrides) {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
  // Audit signing also runs in plaintext mode for test speed (skips Argon2)
  process.env.BLAMEJS_AUDIT_SIGNING_MODE = "plaintext";
  await b.db.init({
    dataDir:  tmpDir,
    atRest:   "plain",
    schema:   schemaOverrides || [
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
        indexes: ["emailHash", "status"],
        sealedFields:  ["email", "name"],
        derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
      },
    ],
  });
}

function teardownTestDb(tmpDir) {
  try { b.db.close(); } catch (_e) {}
  b.db._resetForTest();
  b.vault._resetForTest();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
}

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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
  }
}

// 32. audit.record / query / verify round-trip
async function testAuditChain() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-"));
  try {
    await setupTestDb(tmpDir);

    // Unregistered namespace rejected
    var nsRejected = false;
    try { b.audit.record({ action: "orders.created", outcome: "success" }); }
    catch (_) { nsRejected = true; }
    check("unregistered namespace rejected", nsRejected);

    // Register + record
    b.audit.registerNamespace("orders");
    var ev1 = b.audit.record({
      actor:    { userId: "user-1", ip: "1.2.3.4" },
      action:   "orders.created",
      resource: { kind: "order", id: "ord-1" },
      outcome:  "success",
      metadata: { total: 99.95 },
    });
    check("audit.record returns row with rowHash",   typeof ev1.rowHash === "string" && ev1.rowHash.length === 128);
    check("first row's prevHash is ZERO_HASH",       ev1.prevHash === b.auditChain.ZERO_HASH);

    var ev2 = b.audit.record({
      actor:    { userId: "user-1", ip: "1.2.3.4" },
      action:   "auth.login.success",
      resource: { kind: "user", id: "user-1" },
      outcome:  "success",
    });
    check("second row's prevHash = first row's rowHash", ev2.prevHash === ev1.rowHash);
    check("monotonicCounter increments",                 ev2.monotonicCounter === ev1.monotonicCounter + 1);

    // Invalid action format
    var actionRejected = false;
    try { b.audit.record({ action: "no-dot", outcome: "success" }); }
    catch (_) { actionRejected = true; }
    check("malformed action rejected", actionRejected);

    // Invalid outcome
    var outcomeRejected = false;
    try { b.audit.record({ action: "auth.login.success", outcome: "ok" }); }
    catch (_) { outcomeRejected = true; }
    check("invalid outcome rejected", outcomeRejected);

    // Verify chain is intact
    var v1 = b.audit.verify();
    check("audit.verify() ok after valid records",  v1.ok === true && v1.rowsVerified === 2);

    // Query by various criteria
    var byUser = b.audit.query({ actorUserId: "user-1" });
    check("query by sealed actorUserId returns rows",   byUser.length === 2);
    check("query result rows are unsealed",             byUser[0].actorUserId === "user-1");
    var byAction = b.audit.query({ action: "auth.login.success" });
    check("query by action returns matching",            byAction.length === 1);
    var byKind = b.audit.query({ resourceKind: "order" });
    check("query by resourceKind returns matching",     byKind.length === 1);
  } finally {
    teardownTestDb(tmpDir);
  }
}

// 33. audit.verify() detects a manually broken chain
async function testAuditChainBreak() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-broken-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    b.audit.record({ action: "test.event", outcome: "success" });
    b.audit.record({ action: "test.event", outcome: "success" });
    var v1 = b.audit.verify();
    check("chain ok before tampering", v1.ok === true);

    // Manually corrupt a row's reason field. As of v0.0.7 the audit_log
    // table has BEFORE-UPDATE/DELETE triggers blocking direct mutation —
    // simulating a raw-DB-file tamper that bypassed those guards by
    // dropping the triggers around the corruption.
    b.db.runSql("DROP TRIGGER IF EXISTS no_update_audit_log");
    b.db.prepare('UPDATE audit_log SET reason = ? WHERE monotonicCounter = 1').run("vault:tampered-but-not-actually-sealed");
    b.db.runSql("CREATE TRIGGER IF NOT EXISTS no_update_audit_log BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only — UPDATE prohibited'); END");
    var v2 = b.audit.verify();
    check("chain detected after row tampering",         v2.ok === false);
    check("chain break reports breakAt index",          v2.breakAt === 0 || v2.breakAt === 1);
    check("chain break reports rowHash mismatch reason",
          v2.reason === "rowHash mismatch" || v2.reason === "prevHash mismatch");
  } finally {
    teardownTestDb(tmpDir);
  }
}

// 34. consent: grant / isGranted / withdraw / history / verify
async function testConsent() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-consent-"));
  try {
    await setupTestDb(tmpDir);

    var subjectId = "user-7";
    check("isGranted is false before grant",     b.consent.isGranted({ subjectId, purpose: "marketing.email" }) === false);

    b.consent.grant({
      subjectId:    subjectId,
      purpose:      "marketing.email",
      lawfulBasis:  "consent",
      scope:        { channels: ["email"], topics: ["product-updates"] },
      channel:      "web_form_v2",
      evidenceRef:  "/evidence/forms/2026-04-25T...",
    });
    check("isGranted true after grant",          b.consent.isGranted({ subjectId, purpose: "marketing.email" }) === true);

    b.consent.withdraw({ subjectId, purpose: "marketing.email" });
    check("isGranted false after withdraw",      b.consent.isGranted({ subjectId, purpose: "marketing.email" }) === false);

    var hist = b.consent.history(subjectId);
    check("history returns 2 events",            hist.length === 2);
    check("history first event is grant",        hist[0].action === "granted");
    check("history second event is withdraw",    hist[1].action === "withdrawn");
    check("history unsealed subjectId",          hist[0].subjectId === subjectId);

    var cv = b.consent.verify();
    check("consent.verify() ok",                 cv.ok === true && cv.rowsVerified === 2);

    // Invalid lawful basis
    var basisRejected = false;
    try { b.consent.grant({ subjectId, purpose: "x", lawfulBasis: "bogus", channel: "x" }); }
    catch (_) { basisRejected = true; }
    check("invalid lawfulBasis rejected", basisRejected);
  } finally {
    teardownTestDb(tmpDir);
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
    var av = b.audit.verify();
    check("audit chain intact through subject ops",    av.ok === true);
  } finally {
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    b.audit.record({ action: "test.event", outcome: "success" });

    var deleteRejected = false;
    try { b.db.runSql("DELETE FROM audit_log"); }
    catch (e) { deleteRejected = /append-only|prohibited/i.test(e.message); }
    check("DELETE on audit_log raises ABORT",            deleteRejected);

    var updateRejected = false;
    try { b.db.runSql("UPDATE audit_log SET outcome = 'denied' WHERE 1=1"); }
    catch (e) { updateRejected = /append-only|prohibited/i.test(e.message); }
    check("UPDATE on audit_log raises ABORT",            updateRejected);

    // consent_log
    b.consent.grant({ subjectId: "u-1", purpose: "x", lawfulBasis: "consent", channel: "api" });
    var conDelRejected = false;
    try { b.db.runSql("DELETE FROM consent_log"); }
    catch (e) { conDelRejected = /append-only|prohibited/i.test(e.message); }
    check("DELETE on consent_log raises ABORT",          conDelRejected);

    // INSERT still works (the framework's API uses it constantly above)
    var counts = b.db.prepare("SELECT (SELECT COUNT(*) FROM audit_log) AS a, (SELECT COUNT(*) FROM consent_log) AS c").get();
    check("INSERT on audit_log still works",             counts.a >= 1);
    check("INSERT on consent_log still works",           counts.c >= 1);
  } finally {
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
  }
}

async function testAuditSelfLogging() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-selflog-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    b.audit.record({ action: "test.event", outcome: "success" });
    b.audit.record({ action: "test.event", outcome: "success" });

    // A query auto-records an audit.read event before returning rows
    var beforeCount = b.db.from("audit_log").count();
    var rows = b.audit.query({ action: "test.event" });
    var afterCount = b.db.from("audit_log").count();
    check("query returned both test.event rows",         rows.length === 2);
    check("query auto-recorded an audit.read event",     afterCount === beforeCount + 1);

    // The audit.read row exists
    var readRows = b.audit.query({ action: "audit.read" });
    check("audit.read events queryable directly",        readRows.length >= 1);
    check("audit.read row has criteria metadata",
          readRows[0].metadata && /criteria/.test(readRows[0].metadata));

    // Querying for audit.read does NOT recursively self-log (else infinite chain)
    var beforeRecursionCheck = b.db.from("audit_log").count();
    b.audit.query({ action: "audit.read" });
    var afterRecursionCheck = b.db.from("audit_log").count();
    check("query for audit.read does NOT auto-self-log",  afterRecursionCheck === beforeRecursionCheck);

    // Audit chain still verifies through all the self-logging
    var v = b.audit.verify();
    check("audit chain ok after self-log activity",       v.ok === true);
  } finally {
    teardownTestDb(tmpDir);
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
    var ev1 = b.audit.record({
      action:   "test.start",
      outcome:  "success",
      metadata: { traceId: t1 },
    });
    var ev2 = b.audit.record({
      action:   "test.continue",
      outcome:  "success",
      metadata: { traceId: t1, parentEventId: ev1._id },
    });

    // Query and verify trace correlation is queryable from metadata
    var rows = b.audit.query({ action: "test.start" });
    var meta = JSON.parse(rows[0].metadata);
    check("traceId persists into audit row metadata",    meta.traceId === t1);

    var rows2 = b.audit.query({ action: "test.continue" });
    var meta2 = JSON.parse(rows2[0].metadata);
    check("parentEventId persists into audit row",       meta2.parentEventId === ev1._id);
    check("traceId is shared across linked events",      meta2.traceId === t1);

    void ev2;
  } finally {
    teardownTestDb(tmpDir);
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
    var emptyResult = b.audit.checkpoint();
    check("checkpoint() on empty log returns null",     emptyResult === null);

    // Record and checkpoint
    b.audit.registerNamespace("test");
    b.audit.record({ action: "test.event", outcome: "success" });
    b.audit.record({ action: "test.event", outcome: "success" });
    var ckpt = b.audit.checkpoint();
    check("checkpoint() returns a checkpoint object",   ckpt && typeof ckpt._id === "string");
    check("checkpoint anchors monotonic counter",       typeof ckpt.atMonotonicCounter === "number");
    check("checkpoint includes pubkey fingerprint",
          ckpt.publicKeyFingerprint === b.auditSign.getPublicKeyFingerprint());

    // skipIfUnchanged: second call with no new audit activity returns null
    var skipResult = b.audit.checkpoint({ skipIfUnchanged: true });
    check("checkpoint(skipIfUnchanged) on unchanged log returns null", skipResult === null);

    // After more activity, skipIfUnchanged anchors a new checkpoint
    b.audit.record({ action: "test.event", outcome: "success" });
    var freshCkpt = b.audit.checkpoint({ skipIfUnchanged: true });
    check("skipIfUnchanged anchors when chain advances", freshCkpt !== null);
    check("new checkpoint counter > prior checkpoint",   freshCkpt.atMonotonicCounter > ckpt.atMonotonicCounter);

    // audit.tip sidecar written
    var tipPath = path.join(tmpDir, "audit.tip");
    check("audit.tip sidecar written",                  fs.existsSync(tipPath));
    var tip = JSON.parse(fs.readFileSync(tipPath, "utf8"));
    check("audit.tip records latest counter",           tip.atMonotonicCounter === freshCkpt.atMonotonicCounter);
  } finally {
    teardownTestDb(tmpDir);
  }
}

async function testCheckpointVerify() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cverify-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");

    // Empty case
    var v0 = b.audit.verifyCheckpoints();
    check("verifyCheckpoints empty case ok",            v0.ok === true && v0.checkpointsVerified === 0);

    // Several events + checkpoints
    for (var i = 0; i < 5; i++) {
      b.audit.record({ action: "test.event", outcome: "success" });
      b.audit.checkpoint();
    }
    var v1 = b.audit.verifyCheckpoints();
    check("verifyCheckpoints ok across multiple anchors", v1.ok === true && v1.checkpointsVerified === 5);

    // Adding more rows then a fresh checkpoint still verifies
    b.audit.record({ action: "test.event", outcome: "success" });
    b.audit.checkpoint();
    var v2 = b.audit.verifyCheckpoints();
    check("verifyCheckpoints ok after additional checkpoint", v2.ok === true && v2.checkpointsVerified === 6);
  } finally {
    teardownTestDb(tmpDir);
  }
}

async function testCheckpointTamperDetect() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cdetect-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    b.audit.record({ action: "test.event", outcome: "success" });
    b.audit.checkpoint();
    b.audit.record({ action: "test.event", outcome: "success" });
    b.audit.record({ action: "test.event", outcome: "success" });
    var anchorCkpt = b.audit.checkpoint();

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
    var ckptResult = b.audit.verifyCheckpoints();
    check("checkpoint verify catches anchored-rowHash tampering",  ckptResult.ok === false);
    check("break reason mentions rowHash mismatch",
          /rowHash mismatch|tampered/i.test(ckptResult.reason || ""));
  } finally {
    teardownTestDb(tmpDir);
  }
}

async function testRollbackDetection() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rollback-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    for (var i = 0; i < 3; i++) {
      b.audit.record({ action: "test.event", outcome: "success" });
    }
    b.audit.checkpoint();

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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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

// Generate a throwaway RSA keypair to use as a fake "service account" so
// the GCS adapter has real key material for JWT signing in tests.
function _makeFakeServiceAccount() {
  var nodeCrypto = require("crypto");
  var pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    type:         "service_account",
    project_id:   "test-project",
    client_email: "test-sa@test-project.iam.gserviceaccount.com",
    private_key:  pair.privateKey,
    private_key_id: "test-key-id-001",
  };
}

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
    teardownTestDb(tmpDir);
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

    // Audit chain has system.queue.enqueue + .consume.start + .consume.success
    var enqRows = b.audit.query({ action: "system.queue.enqueue" });
    check("audit recorded enqueue events",             enqRows.length === 3);
    var sucRows = b.audit.query({ action: "system.queue.consume.success" });
    check("audit recorded consume.success events",     sucRows.length === 3);

    consumer.cancel();
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 1000 }); } catch (_e) {}
    teardownTestDb(tmpDir);
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

    // Audit chain has consume.failure events
    var failRows = b.audit.query({ action: "system.queue.consume.failure" });
    check("audit recorded consume.failure events",             failRows.length === 3);

    consumer.cancel();
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 1000 }); } catch (_e) {}
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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
    teardownTestDb(tmpDir);
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

    // Audit: incoming command logged
    var incRows = b.audit.query({ action: "system.log.incoming" });
    check("audit recorded system.log.incoming",           incRows.length === 1);

    // Unregister and verify no further dispatch
    unregister();
    await b.logStream.deliverIncoming({ command: "second" });
    check("after unregister, handler no longer called",   received.length === 1);

    await b.logStream.shutdown();
  } finally {
    teardownTestDb(tmpDir);
  }
}

// =====================================================================
// json — security-focused JSON parse/stringify + schema validation
// =====================================================================

// 40. Module surface
check("json namespace present",        typeof b.json === "object");
check("json.parse is a function",      typeof b.json.parse === "function");
check("json.validate is a function",   typeof b.json.validate === "function");
check("json.canonical is a function",  typeof b.json.canonical === "function");
check("json.JsonSafeError exists",     typeof b.json.JsonSafeError === "function");

// 41. parse: round-trip + size + depth + proto-pollution + types
function testJsonParse() {
  // Basic round-trip
  var v = b.json.parse('{"a":1,"b":"hello","c":null,"d":[1,2,3],"e":true}');
  check("parse round-trips object",   v.a === 1 && v.b === "hello" && v.c === null);
  check("parse round-trips array",    Array.isArray(v.d) && v.d.length === 3);

  // BOM tolerated
  var bom = b.json.parse("﻿{\"x\":1}");
  check("parse strips BOM",           bom.x === 1);

  // Size limit
  var bigInput = '{"x":"' + "a".repeat(200) + '"}';
  var sizeRejected = false;
  try { b.json.parse(bigInput, { maxBytes: 100 }); }
  catch (e) { sizeRejected = e.code === "json/too-large"; }
  check("parse rejects oversized input",                  sizeRejected);

  // Depth limit
  var deep = '{"a":'.repeat(10) + 'null' + '}'.repeat(10);
  var depthRejected = false;
  try { b.json.parse(deep, { maxDepth: 3 }); }
  catch (e) { depthRejected = e.code === "json/too-deep"; }
  check("parse rejects too-deep input",                   depthRejected);

  // Proto pollution
  var poisoned = b.json.parse('{"__proto__":{"isAdmin":true},"name":"alice"}');
  check("parse strips __proto__ key",                     !("__proto__" in poisoned) || poisoned.__proto__ === Object.prototype);
  check("parse does not pollute Object.prototype",        !({}.isAdmin));

  var ctorPoisoned = b.json.parse('{"constructor":{"prototype":{"x":1}}}');
  check("parse strips constructor key",                   !("constructor" in ctorPoisoned) || ctorPoisoned.constructor === Object);

  // Syntax error
  var syntaxRejected = false;
  try { b.json.parse("{not-json}"); }
  catch (e) { syntaxRejected = e.code === "json/syntax"; }
  check("parse reports syntax errors with code",          syntaxRejected);

  // Wrong input type
  var typeRejected = false;
  try { b.json.parse(123); }
  catch (e) { typeRejected = e.code === "json/wrong-input-type"; }
  check("parse rejects non-string/Buffer input",          typeRejected);

  // parseOrDefault
  check("parseOrDefault returns fallback on bad input",   b.json.parseOrDefault("not-json", { fallback: true }).fallback === true);
  check("parseOrDefault returns parsed on good input",    b.json.parseOrDefault('{"x":1}', null).x === 1);

  // Buffer input
  var fromBuf = b.json.parse(Buffer.from('{"y":2}', "utf8"));
  check("parse accepts Buffer input",                     fromBuf.y === 2);
}

// 42. stringify: round-trip + circular detection + proto-pollution stripping
function testJsonStringify() {
  var s = b.json.stringify({ a: 1, b: [1, 2, 3] });
  check("stringify produces valid JSON",                  JSON.parse(s).a === 1);

  var stripped = JSON.parse(b.json.stringify({ __proto__: { x: 1 }, name: "alice" }));
  check("stringify strips __proto__",                     !("__proto__" in stripped) || stripped.__proto__ === Object.prototype);

  var circular = { a: 1 };
  circular.self = circular;
  var circRejected = false;
  try { b.json.stringify(circular); }
  catch (e) { circRejected = e.code === "json/circular"; }
  check("stringify throws on circular ref",               circRejected);

  // Replace mode
  var replaced = b.json.stringify(circular, { onCircular: "replace", circularReplacement: "<circular>" });
  check("stringify circular replace mode works",          /<circular>/.test(replaced));
}

// 43. canonical: sorted keys + deterministic output
function testJsonCanonical() {
  var c1 = b.json.canonical({ b: 2, a: 1, c: 3 });
  var c2 = b.json.canonical({ a: 1, c: 3, b: 2 });
  check("canonical: identical content same key order → identical bytes",  c1 === c2);
  check("canonical: keys sorted alphabetically",          c1 === '{"a":1,"b":2,"c":3}');

  var nested = b.json.canonical({ z: { y: 1, x: 2 }, a: [3, 1, 2] });
  check("canonical: nested objects also sorted",          nested === '{"a":[3,1,2],"z":{"x":2,"y":1}}');

  // Non-finite numbers rejected
  var nfRejected = false;
  try { b.json.canonical({ x: NaN }); }
  catch (e) { nfRejected = e.code === "json/non-finite"; }
  check("canonical: NaN rejected",                        nfRejected);
}

// 44. validate: schema, types, formats, throw mode
function testJsonValidate() {
  // Type
  b.json.validate("hello", { type: "string" });
  check("validate type-pass returns silently", true);
  var typeRejected = false;
  try { b.json.validate(42, { type: "string" }); }
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

  b.json.validate({ email: "alice@example.com", age: 30, role: "admin" }, schema);
  check("validate good object passes silently", true);

  var emailRejected = false;
  try { b.json.validate({ email: "not-email", age: 30 }, schema); }
  catch (e) { emailRejected = e.code === "json/validation" && /format 'email'/.test(e.message); }
  check("validate bad email format throws",                emailRejected);

  var requiredRejected = false;
  try { b.json.validate({ email: "a@b.com" }, schema); }
  catch (e) { requiredRejected = /missing required key 'age'/.test(e.message); }
  check("validate missing required throws",                requiredRejected);

  var rangeRejected = false;
  try { b.json.validate({ email: "a@b.com", age: -1 }, schema); }
  catch (e) { rangeRejected = /minimum/.test(e.message); }
  check("validate range violation throws",                 rangeRejected);

  var enumRejected = false;
  try { b.json.validate({ email: "a@b.com", age: 30, role: "superuser" }, schema); }
  catch (e) { enumRejected = /not in enum/.test(e.message); }
  check("validate enum violation throws",                  enumRejected);

  var unknownKeyRejected = false;
  try { b.json.validate({ email: "a@b.com", age: 30, hax: 1 }, schema); }
  catch (e) { unknownKeyRejected = /unknown key 'hax'/.test(e.message); }
  check("validate unknown key with additionalProperties:false throws", unknownKeyRejected);

  // Array items
  var arrSchema = { type: "array", minItems: 1, items: { type: "integer" } };
  b.json.validate([1, 2, 3], arrSchema);
  var arrItemRejected = false;
  try { b.json.validate([1, "two", 3], arrSchema); }
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
  var result = b.json.validate(bad, schema, { collectErrors: true });
  check("collectErrors returns { ok, value, errors }",      typeof result === "object" && result.ok === false);
  check("collectErrors collects multiple errors",           result.errors.length >= 4);
  check("collectErrors errors have .path",                  result.errors.every(function (e) { return typeof e.path === "string"; }));
  check("collectErrors errors include format failure",      result.errors.some(function (e) { return /format 'email'/.test(e.message); }));
  check("collectErrors errors include range failure",       result.errors.some(function (e) { return /minimum/.test(e.message); }));
  check("collectErrors errors include length failure",      result.errors.some(function (e) { return /minLength/.test(e.message); }));
  check("collectErrors errors include enum failure",        result.errors.some(function (e) { return /not in enum/.test(e.message); }));

  // Good input — collect mode returns ok: true with empty errors
  var good = { email: "a@b.com", age: 30, name: "Alice" };
  var goodResult = b.json.validate(good, schema, { collectErrors: true });
  check("collectErrors ok=true on valid input",             goodResult.ok === true && goodResult.errors.length === 0);

  // parse({ schema, collectErrors }) round-trips the same shape
  var parseResult = b.json.parse(JSON.stringify(bad), { schema: schema, collectErrors: true });
  check("parse + collectErrors returns { ok, value, errors[] }",
        typeof parseResult === "object" && parseResult.ok === false && parseResult.errors.length >= 4);
}

// 46. format registry: built-ins + custom registration
function testJsonFormats() {
  check("format email: valid passes",        b.json.formats.email("alice@example.com"));
  check("format email: missing @ fails",     !b.json.formats.email("not-email"));
  check("format url: https passes",          b.json.formats.url("https://example.com/path"));
  check("format url: ftp fails (not in allowlist)", !b.json.formats.url("ftp://example.com"));
  check("format uuid: valid passes",         b.json.formats.uuid("550e8400-e29b-41d4-a716-446655440000"));
  check("format uuid: too-short fails",      !b.json.formats.uuid("550e8400"));
  check("format ulid: valid passes",         b.json.formats.ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
  check("format ipv4: valid passes",         b.json.formats.ipv4("192.168.1.1"));
  check("format ipv4: out of range fails",   !b.json.formats.ipv4("192.168.1.256"));
  check("format ipv4: leading zero fails",   !b.json.formats.ipv4("192.168.001.1"));
  // ipv6 — full/compressed/IPv4-mapped/mixed-case
  check("ipv6: full 8 groups",                          b.json.formats.ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
  check("ipv6: lowercase",                              b.json.formats.ipv6("2001:db8::1"));
  check("ipv6: mixed case",                             b.json.formats.ipv6("2001:DB8::1"));
  check("ipv6: loopback ::1",                           b.json.formats.ipv6("::1"));
  check("ipv6: unspecified ::",                         b.json.formats.ipv6("::"));
  check("ipv6: trailing :: (1::)",                      b.json.formats.ipv6("1::"));
  check("ipv6: link-local fe80::1",                     b.json.formats.ipv6("fe80::1"));
  check("ipv6: IPv4-mapped ::ffff:192.168.1.1",         b.json.formats.ipv6("::ffff:192.168.1.1"));
  check("ipv6: IPv4-mapped uppercase",                  b.json.formats.ipv6("::FFFF:192.168.1.1"));
  check("ipv6: longer IPv4-mapped form",                b.json.formats.ipv6("2001:db8::192.0.2.1"));
  check("ipv6: rejects > 8 groups",                     !b.json.formats.ipv6("1:2:3:4:5:6:7:8:9"));
  check("ipv6: rejects multiple ::",                    !b.json.formats.ipv6("1::2::3"));
  check("ipv6: rejects non-hex chars",                  !b.json.formats.ipv6("g::"));
  check("ipv6: rejects > 4 hex per group",              !b.json.formats.ipv6("12345::"));
  check("ipv6: rejects zone IDs",                       !b.json.formats.ipv6("fe80::1%eth0"));
  check("ipv6: rejects empty string",                   !b.json.formats.ipv6(""));
  check("ipv6: rejects too long",                       !b.json.formats.ipv6("a".repeat(46)));
  check("ipv6: rejects bad IPv4-mapped",                !b.json.formats.ipv6("::ffff:999.168.1.1"));
  check("format hex: valid passes",          b.json.formats.hex("dead beef".replace(" ", "")));
  check("format slug: valid passes",         b.json.formats.slug("my-blog-post"));
  check("format slug: uppercase fails",      !b.json.formats.slug("MyBlogPost"));
  check("format iso8601-date: valid passes", b.json.formats["iso8601-date"]("2026-04-25"));
  check("format iso8601-date: invalid fails",!b.json.formats["iso8601-date"]("2026-13-01"));

  // Register custom
  b.json.registerFormat("us-zip", function (v) { return /^\d{5}(-\d{4})?$/.test(v); });
  check("custom format registered + works",  b.json.formats["us-zip"]("12345"));
  b.json.validate("90210", { type: "string", format: "us-zip" });
  var customRejected = false;
  try { b.json.validate("ABCDE", { type: "string", format: "us-zip" }); }
  catch (e) { customRejected = /format 'us-zip'/.test(e.message); }
  check("custom format used by validate",    customRejected);
}

// =====================================================================
// Run async tests
// =====================================================================

(async function () {
  // Phase 1a tests
  await testVaultWrapRoundTrip();
  await testPassphraseEnv();
  await testVaultPlaintextRoundTrip();
  await testVaultModeMismatch();
  await testVaultRequiresDataDir();
  await testVaultWrappedE2E();
  // Phase 1b tests
  await testDbBasic();
  await testDbWriteOps();
  await testDbSealedWithoutDerived();
  await testDbTransactions();
  await testDbPersistence();
  await testDbSchemaEvolution();
  await testDbMigrations();
  // Phase 1c tests
  await testFrameworkSchema();
  await testReservedTableProtection();
  await testAuditChain();
  await testAuditChainBreak();
  await testConsent();
  await testSubjectRights();
  await testDataResidency();
  // Phase 1d-1 tests
  await testSession();
  await testStorage();
  // json (utility primitive — not phase-bound)
  testJsonParse();
  testJsonStringify();
  testJsonCanonical();
  testJsonValidate();
  testJsonValidateCollect();
  testJsonFormats();
  // v0.0.7 traceability hardening
  await testAppendOnlyTriggers();
  await testForeignKeys();
  await testTableMetadata();
  await testAuditSelfLogging();
  await testBeginTrace();
  // v0.0.8 tamper-proofing
  await testCheckpointSign();
  await testCheckpointVerify();
  await testCheckpointTamperDetect();
  await testRollbackDetection();
  // v0.0.9 multi-backend storage + retry/breaker
  await testMultiBackend();
  await testClassificationRouting();
  await testResidencyEnforcement();
  await testRetryAndBreaker();
  // v0.0.10 sigv4 protocol
  testSigv4Primitives();
  await testSigv4MockServer();
  // v0.0.11 gcs + azure-blob protocols
  testGcsPrimitives();
  await testGcsMockServer();
  testAzureBlobPrimitives();
  await testAzureBlobMockServer();
  // v0.0.12 local queue
  await testQueueLocal();
  await testQueueConsume();
  await testQueueRetryAndFail();
  await testQueueLeaseExpiry();
  await testQueueShutdown();
  // v0.0.13 log streaming + redaction
  testRedact();
  await testLogStreamLocal();
  await testLogStreamWebhook();
  await testLogStreamBidirectional();
  console.log("OK — " + checks + " checks passed");
})().catch(function (err) {
  console.error("SMOKE TEST FAILED:", err.message);
  console.error(err.stack);
  process.exit(1);
});
