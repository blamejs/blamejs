"use strict";
/**
 * Layer 2 — db + framework-schema integration.
 *
 * (Layer 2: needs db). These tests
 * exercise the SQLite-backed db module and the framework-schema enforcer
 * (reserved-table protection).
 *
 *   db                — basic / write-ops / sealed-without-derived /
 *                       transactions / persistence / schema-evolution /
 *                       migrations
 *   framework-schema  — internal table emission + reserved-name protection
 *
 * Layers 0 + 1 must run first.
 *
 * Usage from smoke.js:
 *   var dbLayer = require("./20-db");
 *   await dbLayer.run();
 */

var helpers = require("./_helpers");
var b      = helpers.b;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;
var check  = helpers.check;
var setupTestDb              = helpers.setupTestDb;
var teardownTestDb           = helpers.teardownTestDb;

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

// ---- run() ----

async function run() {
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
}

module.exports = {
  name: "Layer 2 — db (db basic + framework-schema reserved-table protection)",
  run:  run,
  testDbBasic:                              testDbBasic,
  testDbWriteOps:                           testDbWriteOps,
  testDbSealedWithoutDerived:               testDbSealedWithoutDerived,
  testDbTransactions:                       testDbTransactions,
  testDbPersistence:                        testDbPersistence,
  testDbSchemaEvolution:                    testDbSchemaEvolution,
  testDbMigrations:                         testDbMigrations,
  testFrameworkSchema:                      testFrameworkSchema,
  testReservedTableProtection:              testReservedTableProtection,
};
