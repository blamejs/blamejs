"use strict";
/**
 * Layer 3 — chain-writing modules (audit, consent, subject, checkpoint)
 *           + cluster-storage (SQL dispatcher).
 *
 * Per feedback_test_dependency_order.md (Layer 3: uses db + chain-writer +
 * cluster-storage). Hash-chained log tables and the framework write-path
 * primitives that consume them.
 *
 *   cluster-storage   — SQL dispatcher (placeholderize, resolveTables,
 *                       local + cluster dispatch)
 *   audit             — chain append + verify + self-logging + begin-trace
 *   consent           — chain append (uses chain-writer)
 *   subject           — DSAR (export + delete) using audit + db
 *   append-only       — INSERT-only trigger guards + foreign keys +
 *                       table metadata reflection
 *   checkpoint        — sign + verify + tamper detect + rollback detect
 *
 * Layers 0, 1, 2 must run first. Each test sets up its own tmpDir + db.
 *
 * Usage from smoke.js:
 *   var chainLayer = require("./30-chain");
 *   await chainLayer.run();
 */

var helpers = require("./_helpers");
var b      = helpers.b;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;
var check  = helpers.check;
var setupTestDb              = helpers.setupTestDb;
var teardownTestDb           = helpers.teardownTestDb;
var _makeSqliteDriver        = helpers._makeSqliteDriver;

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

// ---- run() ----

async function run() {
  // cluster-storage (SQL dispatcher)
  await testClusterStorageLocalDispatch();
  testClusterStoragePlaceholderize();
  testClusterStorageResolveTablesIsNoOpInSingleNode();
  await testClusterStorageClusterDispatch();

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
}

module.exports = {
  name: "Layer 3 — chain (cluster-storage + audit + consent + subject + checkpoint)",
  run:  run,
  testClusterStorageLocalDispatch:                     testClusterStorageLocalDispatch,
  testClusterStoragePlaceholderize:                    testClusterStoragePlaceholderize,
  testClusterStorageResolveTablesIsNoOpInSingleNode:   testClusterStorageResolveTablesIsNoOpInSingleNode,
  testClusterStorageClusterDispatch:                   testClusterStorageClusterDispatch,
  testAuditChain:                                      testAuditChain,
  testAuditChainBreak:                                 testAuditChainBreak,
  testAuditSelfLogging:                                testAuditSelfLogging,
  testBeginTrace:                                      testBeginTrace,
  testConsent:                                         testConsent,
  testSubjectRights:                                   testSubjectRights,
  testAppendOnlyTriggers:                              testAppendOnlyTriggers,
  testForeignKeys:                                     testForeignKeys,
  testTableMetadata:                                   testTableMetadata,
  testCheckpointSign:                                  testCheckpointSign,
  testCheckpointVerify:                                testCheckpointVerify,
  testCheckpointTamperDetect:                          testCheckpointTamperDetect,
  testRollbackDetection:                               testRollbackDetection,
};
