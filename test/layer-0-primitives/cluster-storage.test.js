// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * cluster-storage — cluster-aware framework-state SQL dispatch.
 *
 * Focus: the transaction() primitive (added v0.13.38) — atomic commit,
 * rollback-on-throw, and single-node serialization so a concurrent
 * execute() can't interleave a statement into an open transaction on the
 * shared SQLite connection.
 *
 * Run standalone: `node test/layer-0-primitives/cluster-storage.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var fs      = require("node:fs");
var os      = require("node:os");
var path    = require("node:path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

var SCHEMA = [{ name: "cs_tx_t", columns: { k: "TEXT PRIMARY KEY", v: "INTEGER" } }];
var FENCE_SCHEMA = [{
  name: "cs_fence_t",
  columns: {
    scope:        "TEXT PRIMARY KEY",
    v:            "INTEGER",
    fencingToken: "INTEGER NOT NULL DEFAULT 0",
  },
}];

function testSurface() {
  check("clusterStorage namespace",      typeof b.clusterStorage === "object");
  check("clusterStorage.transaction fn", typeof b.clusterStorage.transaction === "function");
}

async function testTransactionCommits() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cs-tx-commit-"));
  try {
    await setupTestDb(tmp, SCHEMA);
    var cs = b.clusterStorage;
    await cs.transaction(async function (tx) {
      await tx.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["a", 1]);
      await tx.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["b", 2]);
      var seen = await tx.executeOne("SELECT COUNT(*) AS n FROM cs_tx_t");
      check("tx: rows visible inside the transaction", seen.n === 2);
    });
    var after = await cs.executeOne("SELECT COUNT(*) AS n FROM cs_tx_t");
    check("tx: commit persisted both rows", after.n === 2);
  } finally {
    b.db._resetForTest();
    await teardownTestDb(tmp);
  }
}

async function testTransactionRollsBackOnThrow() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cs-tx-rollback-"));
  try {
    await setupTestDb(tmp, SCHEMA);
    var cs = b.clusterStorage;
    await cs.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["keep", 1]);
    var threw = null;
    try {
      await cs.transaction(async function (tx) {
        await tx.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["gone", 2]);
        throw new Error("boom");
      });
    } catch (e) { threw = e; }
    check("tx: throw propagates to caller",       threw && threw.message === "boom");
    var rows = await cs.executeAll("SELECT k FROM cs_tx_t ORDER BY k");
    check("tx: rolled-back row absent",            rows.length === 1 && rows[0].k === "keep");
  } finally {
    b.db._resetForTest();
    await teardownTestDb(tmp);
  }
}

async function testTransactionSerializesExecute() {
  // A concurrent execute() must NOT interleave a statement into an open
  // single-node transaction on the shared connection — it waits until the
  // transaction commits.
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cs-tx-serial-"));
  try {
    await setupTestDb(tmp, SCHEMA);
    var cs = b.clusterStorage;
    var order = [];
    var txP = cs.transaction(async function (tx) {
      order.push("tx-begin");
      await tx.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["d", 4]);
      await helpers.passiveObserve(40, "cluster-storage tx: hold the transaction open");
      order.push("tx-end");
    });
    var exP = cs.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["e", 5])
      .then(function () { order.push("exec-done"); });
    await Promise.all([txP, exP]);
    check("tx: concurrent execute waited for commit (no mid-tx interleave)",
          order.join(",") === "tx-begin,tx-end,exec-done");
    var n = await cs.executeOne("SELECT COUNT(*) AS n FROM cs_tx_t");
    check("tx: both writes landed", n.n === 2);
  } finally {
    b.db._resetForTest();
    await teardownTestDb(tmp);
  }
}

async function testTransactionRejectsBadArg() {
  var threw = null;
  try { await b.clusterStorage.transaction("not-a-fn"); } catch (e) { threw = e; }
  check("tx: non-function arg rejected", threw && threw.code === "cluster-storage/bad-arg");
}

// A WITH (CTE) read must reach the caller's row set. The local-exec method
// choice keyed on a leading "SELECT" mis-routed "WITH c AS (...) SELECT ..." to
// .run(), which on node:sqlite returns only a changes count and SILENTLY DROPS
// the rows — the caller saw an empty result. The classifier now resolves the
// CTE's effective verb so the read uses .all().
async function testCteReadReturnsRows() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cs-cte-read-"));
  try {
    await setupTestDb(tmp, SCHEMA);
    var cs = b.clusterStorage;
    await cs.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["a", 1]);
    await cs.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["b", 2]);

    // Plain SELECT control — already worked.
    var plain = await cs.execute("SELECT k, v FROM cs_tx_t ORDER BY k");
    check("plain SELECT returns both rows", plain.rows.length === 2);

    // CTE read — the regression. Was: rows.length === 0 (rows dropped by .run()).
    var cte = await cs.execute(
      "WITH picked AS (SELECT k, v FROM cs_tx_t WHERE v >= ?) SELECT k, v FROM picked ORDER BY k", [1]);
    check("WITH (CTE) read returns rows (not silently dropped)", cte.rows.length === 2);
    check("WITH (CTE) read returns the actual data", cte.rows[0].k === "a" && cte.rows[1].k === "b");

    // executeOne over a CTE read resolves the single row too.
    var one = await cs.executeOne(
      "WITH t AS (SELECT COUNT(*) AS n FROM cs_tx_t) SELECT n FROM t");
    check("executeOne over a CTE read resolves the row", one && one.n === 2);

    // A WITH (CTE) write still applies its changes (not mis-read as a query).
    await cs.execute(
      "WITH src AS (SELECT 'c' AS k, 3 AS v) INSERT INTO cs_tx_t (k, v) SELECT k, v FROM src");
    var after = await cs.executeOne("SELECT COUNT(*) AS n FROM cs_tx_t");
    check("WITH (CTE) write persisted its row", after.n === 3);
  } finally {
    b.db._resetForTest();
    await teardownTestDb(tmp);
  }
}

// A single-writer table stays single-writer across processes only because the
// stored token says whose turn it is. A superseded leader still holds a
// working handle and can still issue writes; nothing in this process knows it
// has been replaced, so the refusal has to come from the database.
async function testFencedUpsertRefusesAStaleToken() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cs-fence-"));
  try {
    await setupTestDb(tmp, FENCE_SCHEMA);
    var cs = b.clusterStorage;

    var first = await cs.fencedUpsert({
      table: "cs_fence_t", keyColumns: ["scope"], label: "test.fence",
      values: { scope: "s", v: 1, fencingToken: 5 },
    });
    check("fencedUpsert: the first write is not fenced", first.fenced === false);
    check("fencedUpsert: and it landed",
      (await cs.executeOne("SELECT v FROM cs_fence_t WHERE scope = 's'")).v === 1);

    var higher = await cs.fencedUpsert({
      table: "cs_fence_t", keyColumns: ["scope"], label: "test.fence",
      values: { scope: "s", v: 2, fencingToken: 6 },
    });
    check("fencedUpsert: a higher token proceeds", higher.fenced === false);
    check("fencedUpsert: and replaces the row",
      (await cs.executeOne("SELECT v FROM cs_fence_t WHERE scope = 's'")).v === 2);

    var equal = await cs.fencedUpsert({
      table: "cs_fence_t", keyColumns: ["scope"], label: "test.fence",
      values: { scope: "s", v: 3, fencingToken: 6 },
    });
    check("fencedUpsert: an EQUAL token proceeds — the same leader writing twice",
      equal.fenced === false);

    var stale = await cs.fencedUpsert({
      table: "cs_fence_t", keyColumns: ["scope"], label: "test.fence",
      values: { scope: "s", v: 99, fencingToken: 4 },
    });
    check("fencedUpsert: a lower token is fenced", stale.fenced === true);
    check("fencedUpsert: and changes nothing",
      (await cs.executeOne("SELECT v FROM cs_fence_t WHERE scope = 's'")).v === 3,
      "a fenced write must not be a partial write");

    // More than one column can be fenced, and then ALL of them must be
    // non-decreasing. A value that may only ever advance — a purge boundary, a
    // high-water mark — is safest held that way by the database, rather than
    // by whoever happens to write next holding the right token: a legitimate
    // higher-token writer can still be proposing a lower boundary.
    var advanced = await cs.fencedUpsert({
      table: "cs_fence_t", keyColumns: ["scope"], label: "test.fence",
      fenceColumns: ["fencingToken", "v"],
      values: { scope: "s", v: 10, fencingToken: 6 },
    });
    check("fencedUpsert: advancing both fenced columns proceeds", advanced.fenced === false);

    var backwards = await cs.fencedUpsert({
      table: "cs_fence_t", keyColumns: ["scope"], label: "test.fence",
      fenceColumns: ["fencingToken", "v"],
      values: { scope: "s", v: 4, fencingToken: 99 },
    });
    check("fencedUpsert: a HIGHER token cannot move a fenced value backwards",
      backwards.fenced === true, "a monotonic column is not the token's to lower");
    check("fencedUpsert: and the stored value stands",
      (await cs.executeOne("SELECT v FROM cs_fence_t WHERE scope = 's'")).v === 10);
  } finally {
    try { await helpers.teardownTestDb(tmp); } catch (_e) { /* best-effort */ }
  }
}

async function run() {
  testSurface();
  await testTransactionCommits();
  await testTransactionRollsBackOnThrow();
  await testTransactionSerializesExecute();
  await testTransactionRejectsBadArg();
  await testCteReadReturnsRows();
  await testFencedUpsertRefusesAStaleToken();
  testMissingRelationAndColumnCodes();
}

// Every reader that has to tell "the table is not there yet" from "the query
// failed" was answering it from the error MESSAGE, and MySQL words a missing
// table with a contraction — "Table 'db.X' doesn't exist" — that the SQLite
// and Postgres wordings do not cover. The driver's own fields say it plainly
// and in every locale, so they are what gets asked, through one predicate
// rather than a spelling per caller.
function testMissingRelationAndColumnCodes() {
  var mysqlTable = Object.assign(new Error("Table 'blamejs.audit_log' doesn't exist"),
    { errno: 1146, code: "ER_NO_SUCH_TABLE", sqlState: "42S02" });
  var pgTable = Object.assign(new Error('relation "audit_log" does not exist'),
    { code: "42P01" });
  // The docker-exec shim and ANSI drivers carry the SQLSTATE alone, with a
  // message that names nothing recognizable.
  var ansiTable = Object.assign(new Error("SQL execution failed"), { sqlState: "42S02" });
  check("missingRelationCode: mysql2's own fields",
    b.clusterStorage.missingRelationCode(mysqlTable) === true);
  check("missingRelationCode: postgres SQLSTATE",
    b.clusterStorage.missingRelationCode(pgTable) === true);
  check("missingRelationCode: a SQLSTATE with no recognizable message",
    b.clusterStorage.missingRelationCode(ansiTable) === true);

  var mysqlColumn = Object.assign(new Error("Unknown column 'signature' in 'field list'"),
    { errno: 1054, code: "ER_BAD_FIELD_ERROR", sqlState: "42S22" });
  var pgColumn = Object.assign(new Error('column "signature" does not exist'),
    { code: "42703" });
  check("missingColumnCode: mysql2's own fields",
    b.clusterStorage.missingColumnCode(mysqlColumn) === true);
  check("missingColumnCode: postgres SQLSTATE",
    b.clusterStorage.missingColumnCode(pgColumn) === true);

  // The two must not answer each other's question: a reader that ends the
  // read on an absent table and falls back to an older projection on an
  // absent column would do the wrong one either way round.
  check("missingRelationCode: an absent COLUMN is not an absent table",
    b.clusterStorage.missingRelationCode(pgColumn) === false &&
    b.clusterStorage.missingRelationCode(mysqlColumn) === false);
  check("missingColumnCode: an absent TABLE is not an absent column",
    b.clusterStorage.missingColumnCode(pgTable) === false &&
    b.clusterStorage.missingColumnCode(mysqlTable) === false);

  // And the control the whole predicate exists for: a failure that says
  // nothing about the schema must be neither. Reading "absent" from a timeout
  // or a permission error is how a purged chain gets verified from ZERO_HASH
  // and reported clean.
  var denied = Object.assign(new Error("SELECT command denied to user 'app'"),
    { errno: 1142, code: "ER_TABLEACCESS_DENIED_ERROR", sqlState: "42000" });
  var timedOut = Object.assign(new Error("connection terminated unexpectedly"),
    { code: "ETIMEDOUT" });
  check("neither predicate reads a permission error as a missing schema object",
    b.clusterStorage.missingRelationCode(denied) === false &&
    b.clusterStorage.missingColumnCode(denied) === false);
  check("neither reads a dropped connection as one",
    b.clusterStorage.missingRelationCode(timedOut) === false &&
    b.clusterStorage.missingColumnCode(timedOut) === false);
  check("neither answers true for a missing error",
    b.clusterStorage.missingRelationCode(null) === false &&
    b.clusterStorage.missingColumnCode(undefined) === false);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cluster-storage] OK — " + helpers.getChecks() + " checks passed"); },
    // Rethrow rather than console.error(e.stack): this test seeds a vault
    // passphrase via setupTestDb, and logging the error object trips
    // CodeQL's clear-text-logging taint (passphrase -> error -> log). The
    // rethrow lets Node print the uncaught error + stack itself and exit
    // non-zero, with no logging sink for the taint to reach.
    function (e) { process.exitCode = 1; throw e; }
  );
}
