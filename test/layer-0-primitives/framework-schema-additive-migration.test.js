// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.frameworkSchema.ensureSchema — the additive ADD COLUMN pass.
 *
 * `CREATE TABLE IF NOT EXISTS` is a no-op against a table that is already
 * there, so a column added to a framework table's declaration reaches fresh
 * deployments only. Every existing one keeps the old shape, its live schema
 * drifts from the declaration, and the first write naming the new column fails
 * at a customer rather than here.
 *
 * The purge anchor gained `signature`, `publicKeyFingerprint` and
 * `fencingToken` in 0.18.58, and a cluster deployment gets them ONLY from this
 * pass — the local-SQLite path goes through dbSchema.reconcile instead. So the
 * migration running is the difference between an upgraded cluster being able
 * to purge and its first purge failing.
 *
 * Drives the real external-db path with the shared sqlite driver rather than a
 * rolled mock, so the DDL under test is the DDL an operator's backend gets.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs    = helpers.fs;
var os    = helpers.os;
var path  = helpers.path;

// The purge anchor as a deployment that ran before 0.18.58 has it: no
// signature, no key fingerprint, no fencing token.
var PRE_0_18_58_ANCHOR =
  'CREATE TABLE "_blamejs_audit_purge_anchor" (' +
  '  "scope" TEXT PRIMARY KEY,' +
  '  "lastPurgedCounter" INTEGER NOT NULL,' +
  '  "lastPurgedRowHash" TEXT NOT NULL,' +
  '  "archiveBundleId" TEXT NOT NULL,' +
  '  "purgedAt" INTEGER NOT NULL' +
  ')';

// Read through `pragma_table_info` as a SELECT rather than a bare PRAGMA: the
// driver returns rows only for statements it recognizes as reads, and a bare
// PRAGMA comes back with none. That produced an empty column list, which made
// the "these columns are absent" assertion below pass for the wrong reason —
// an emptiness that says nothing is not the same as a table that lacks them.
async function _columnsOf(driver, client, table) {
  var res = await driver.query(client,
    "SELECT name FROM pragma_table_info('" + table + "')", []);
  var list = (res && res.rows) ? res.rows : res;
  if (!list || list.length === 0) {
    throw new Error("_columnsOf read no columns for " + table +
      " — the table is missing, or this read is not returning rows");
  }
  return list.map(function (r) { return r.name; });
}

// Two statements of one fact drift apart silently. `wormGuardIsAnchorBounded`
// says which dialects decide a DELETE against the purge anchor, and its own
// `@example` block says the same thing a second time — where it went wrong: the
// example claimed SQLite was unbounded while the function answered that it was,
// and the operator reading the docs and the caller reading the return value
// would have taken opposite paths. So the example is not read as prose here, it
// is EXECUTED against the function it documents.
function testWormGuardExampleAgreesWithTheFunction() {
  var src = fs.readFileSync(path.join(__dirname, "..", "..", "lib", "framework-schema.js"), "utf8");
  var block = src.split("@primitive b.frameworkSchema.wormGuardIsAnchorBounded")[1];
  check("the predicate's comment block is findable", typeof block === "string" && block.length > 0);
  var example = block.split("@example")[1].split("*/")[0];
  // Each ` *   expr;  // → value` line is one claim to check.
  var claims = example.split("\n")
    .map(function (line) { return line.replace(/^\s*\*?\s?/, "").trim(); })
    .filter(function (line) { return line.indexOf("wormGuardIsAnchorBounded(") !== -1; });
  check("the example makes at least one claim", claims.length > 0, String(claims.length));
  for (var i = 0; i < claims.length; i += 1) {
    var m = /wormGuardIsAnchorBounded\(\s*"([a-z]+)"\s*\)\s*;?\s*\/\/\s*→\s*(true|false)/.exec(claims[i]);
    check("claim " + i + " is in the documented shape", m !== null, claims[i]);
    if (!m) continue;
    var documented = m[2] === "true";
    var actual = b.frameworkSchema.wormGuardIsAnchorBounded(m[1]);
    check("the example's answer for " + m[1] + " is what the function returns",
      actual === documented, "documented " + documented + ", returns " + actual);
  }

  // The answers themselves, grounded in what this module's own installer
  // writes: Postgres and MySQL carry the condition in the trigger body, SQLite
  // in a WHEN clause, and all three read the anchor's recorded boundary. An
  // unknown dialect is not assumed to be bounded.
  check("postgres is anchor-bounded",
    b.frameworkSchema.wormGuardIsAnchorBounded("postgres") === true);
  check("mysql is anchor-bounded",
    b.frameworkSchema.wormGuardIsAnchorBounded("mysql") === true);
  check("sqlite is anchor-bounded, through a WHEN clause rather than a body",
    b.frameworkSchema.wormGuardIsAnchorBounded("sqlite") === true);
  check("an unknown dialect is not claimed to be bounded",
    b.frameworkSchema.wormGuardIsAnchorBounded("oracle") === false &&
    b.frameworkSchema.wormGuardIsAnchorBounded("") === false &&
    b.frameworkSchema.wormGuardIsAnchorBounded(undefined) === false);
  // Grounding, so the three claims above are not just restating the function:
  // this module's SQLite installer really does emit the anchor-reading WHEN.
  check("the module's SQLite delete trigger reads the anchor in a WHEN clause",
    /WHEN NOT COALESCE\(OLD\./.test(src) && /lastPurgedCounter/.test(src));
}

// The suspension primitive advertised `postgres | mysql | sqlite` and used
// postgres in its own example, while refusing postgres outright — and postgres
// was also the DEFAULT, so calling it the documented way, or without naming a
// dialect at all, could only throw. A refusal can be the right answer; naming
// the refused dialect as the example is not.
//
// Compared against the source rather than restated, so a dialect added to the
// doc without an implementation fails here.
async function testSuspensionDialectSurfaceAgreesWithTheDoc() {
  var src = fs.readFileSync(path.join(__dirname, "..", "..", "lib", "framework-schema.js"), "utf8");
  var block = src.split("@primitive b.frameworkSchema.withDeleteTriggersSuspended")[1];
  check("the primitive's comment block is findable",
    typeof block === "string" && block.length > 0);
  var docBlock = block.split("*/")[0];

  // Every dialect the @opts line offers must be one the function accepts.
  var optsLine = /dialect:\s*string,\s*\/\/\s*([a-z |]+)/.exec(docBlock);
  check("the @opts line names the dialects it accepts", optsLine !== null,
    String(optsLine));
  var documented = optsLine
    ? optsLine[1].split("|").map(function (s) { return s.trim(); }).filter(Boolean)
    : [];
  check("at least one dialect is documented", documented.length > 0,
    JSON.stringify(documented));

  for (var i = 0; i < documented.length; i += 1) {
    var err = null;
    try {
      // No backend is configured here, so a supported dialect gets PAST the
      // config checks and fails later on the store. What must not happen is a
      // refusal of the dialect itself.
      await b.frameworkSchema.withDeleteTriggersSuspended(
        { externalDbBackend: "nope", dialect: documented[i] },
        async function () { return null; });
    } catch (e) { err = e; }
    check("the documented dialect " + documented[i] + " is not refused as unsupported",
      !err || err.code !== "framework-schema/unsupported-dialect",
      documented[i] + " → " + String(err && (err.code || err.message)));
  }

  // And every dialect named in the @example must be documented in @opts.
  var exampleDialects = [];
  var exampleText = docBlock.split("@example")[1] || "";
  var reDialect = /dialect:\s*"([a-z]+)"/g;
  var m;
  while ((m = reDialect.exec(exampleText)) !== null) exampleDialects.push(m[1]);
  check("the example names a dialect", exampleDialects.length > 0,
    JSON.stringify(exampleDialects));
  exampleDialects.forEach(function (d) {
    check("the example's dialect " + d + " is one @opts offers",
      documented.indexOf(d) !== -1, d + " not in " + JSON.stringify(documented));
  });

  // An omitted dialect must say so rather than pick one for the caller. It
  // defaulted to postgres, which this refuses — so the default call could only
  // fail, and the message blamed the dialect the caller never chose.
  var omitted = null;
  try {
    await b.frameworkSchema.withDeleteTriggersSuspended(
      { externalDbBackend: "nope" }, async function () { return null; });
  } catch (e) { omitted = e; }
  check("omitting the dialect is refused as a config error, not defaulted",
    omitted !== null && omitted.code === "framework-schema/invalid-config" &&
    /dialect/.test(omitted.message || ""),
    String(omitted && (omitted.code + " :: " + omitted.message)));

  // Postgres stays refused, and says why — its guard is one trigger FUNCTION
  // shared by every WORM table, so dropping and restoring is not symmetric.
  var pg = null;
  try {
    await b.frameworkSchema.withDeleteTriggersSuspended(
      { externalDbBackend: "nope", dialect: "postgres" }, async function () { return null; });
  } catch (e) { pg = e; }
  check("postgres is refused with a code that names the reason",
    pg !== null && pg.code === "framework-schema/unsupported-dialect",
    String(pg && (pg.code + " :: " + pg.message)));
}

async function run() {
  testWormGuardExampleAgreesWithTheFunction();
  await testSuspensionDialectSurfaceAgreesWithTheDoc();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-fs-migrate-"));
  var driver = null;
  try {
    var driverObj = helpers._makeSqliteDriver(path.join(tmpDir, "ext.db"));
    driver = driverObj;
    var client = await driverObj.connect();

    // A volume that predates the columns.
    await driverObj.query(client, PRE_0_18_58_ANCHOR, []);
    var before = await _columnsOf(driverObj, client, "_blamejs_audit_purge_anchor");
    check("the pre-upgrade anchor has none of the new columns",
      before.indexOf("signature") === -1 &&
      before.indexOf("publicKeyFingerprint") === -1 &&
      before.indexOf("fencingToken") === -1,
      before.join(","));

    b.externalDb.init({
      backends: { ops: {
        connect: driverObj.connect, query: driverObj.query, close: driverObj.close,
      } },
    });
    await b.frameworkSchema.ensureSchema({ externalDbBackend: "ops", dialect: "sqlite" });

    var after = await _columnsOf(driverObj, client, "_blamejs_audit_purge_anchor");
    check("ensureSchema adds the signature column to the existing table",
      after.indexOf("signature") !== -1, after.join(","));
    check("ensureSchema adds the key fingerprint column",
      after.indexOf("publicKeyFingerprint") !== -1, after.join(","));
    check("ensureSchema adds the fencing token column",
      after.indexOf("fencingToken") !== -1, after.join(","));

    // The columns the table already had are untouched — the pass is additive,
    // and a migration that rebuilt the table would take the rows with it.
    check("and leaves the columns that were already there",
      after.indexOf("lastPurgedCounter") !== -1 &&
      after.indexOf("lastPurgedRowHash") !== -1 &&
      after.indexOf("archiveBundleId") !== -1 &&
      after.indexOf("purgedAt") !== -1,
      after.join(","));

    // Re-running is the normal case — every boot calls this. The engine
    // answers a column that is already present with an error, and treating
    // that as a failure would refuse the second start of every deployment.
    var second = null;
    try {
      await b.frameworkSchema.ensureSchema({ externalDbBackend: "ops", dialect: "sqlite" });
    } catch (e) { second = e; }
    check("ensureSchema is idempotent — a second pass is not an error",
      second === null, String(second && second.message));

    var third = await _columnsOf(driverObj, client, "_blamejs_audit_purge_anchor");
    check("and the column set is unchanged by it",
      third.join(",") === after.join(","), third.join(","));

    // A row written before the upgrade survives it, which is the whole point:
    // the boundary it records is what the operator has to be able to keep.
    await driverObj.query(client,
      'INSERT INTO "_blamejs_audit_purge_anchor" ' +
      '("scope", "lastPurgedCounter", "lastPurgedRowHash", "archiveBundleId", "purgedAt") ' +
      "VALUES ('audit', 7, '" + "a".repeat(128) + "', 'legacy-archive', 1750000000000)", []);
    var readBack = await driverObj.query(client,
      'SELECT * FROM "_blamejs_audit_purge_anchor"', []);
    var row = ((readBack && readBack.rows) ? readBack.rows : readBack)[0];
    check("a pre-upgrade anchor row reads back with its boundary intact",
      Number(row.lastPurgedCounter) === 7 && row.archiveBundleId === "legacy-archive",
      JSON.stringify(row));
    check("and its new columns are empty rather than invented",
      row.signature == null && row.publicKeyFingerprint == null,
      JSON.stringify(row));
    check("with the fencing token defaulted, so the fence has something to compare",
      Number(row.fencingToken) === 0, String(row.fencingToken));

    // Only a column that is ALREADY THERE is swallowed. This loop is the last
    // thing standing between a declared column and a table that silently never
    // gets it, so a failure meaning anything else — no disk, no permission, a
    // lock — has to stop the boot rather than leave the schema half-migrated
    // and the first write to fail at a customer.
    await b.externalDb.shutdown();
    var refusals = 0;
    b.externalDb.init({
      backends: { ops: {
        connect: driverObj.connect,
        query: async function (client, sql, params) {
          if (/ALTER TABLE/i.test(sql)) {
            refusals += 1;
            throw new Error("SQLITE_READONLY: attempt to write a readonly database");
          }
          return driverObj.query(client, sql, params);
        },
        close: driverObj.close,
      } },
    });
    var propagated = null;
    try {
      await b.frameworkSchema.ensureSchema({ externalDbBackend: "ops", dialect: "sqlite" });
    } catch (e) { propagated = e; }
    check("an ALTER failure that is not a duplicate column stops ensureSchema",
      propagated !== null && /readonly database/.test(propagated.message || ""),
      String(propagated && propagated.message));
    check("and it reached the alters at all",
      refusals > 0, "refusals=" + refusals);

    // The append-only guard, and the one operation allowed to step around it.
    //
    // On SQLite a trigger cannot read session state, so the guard genuinely
    // comes off for the deletion and goes back afterwards. What must not
    // happen is it staying off — a failed purge that left the audit table
    // writable would remove the protection the whole design rests on.
    await b.externalDb.shutdown();
    b.externalDb.init({
      backends: { ops: {
        connect: driverObj.connect, query: driverObj.query, close: driverObj.close,
      } },
    });
    // A volume upgraded from a build whose guard was unconditional already has
    // a trigger by this name. `CREATE TRIGGER IF NOT EXISTS` would leave that
    // old body in place, and since a purge no longer takes the guard off, the
    // old body refuses every purge on an upgraded volume — a database that
    // boots fine and can never purge again. Standing in for that here by
    // installing the old shape first and requiring ensureSchema to replace it.
    await driverObj.query(client,
      'DROP TRIGGER IF EXISTS "no_delete__blamejs_audit_log"', []);
    await driverObj.query(client,
      'CREATE TRIGGER "no_delete__blamejs_audit_log" BEFORE DELETE ON ' +
      '"_blamejs_audit_log" BEGIN SELECT RAISE(ABORT, ' +
      "'_blamejs_audit_log is append-only'); END", []);
    await b.frameworkSchema.ensureSchema({ externalDbBackend: "ops", dialect: "sqlite" });
    var upgraded = await driverObj.query(client,
      "SELECT sql FROM sqlite_master WHERE type = 'trigger' " +
      "AND name = 'no_delete__blamejs_audit_log'", []);
    var upgradedRows = (upgraded && upgraded.rows) ? upgraded.rows : upgraded;
    check("ensureSchema replaces an older unconditional delete guard",
      (upgradedRows || []).length === 1 &&
      /lastPurgedCounter/.test(String(upgradedRows[0].sql)),
      String(upgradedRows && upgradedRows[0] && upgradedRows[0].sql).slice(0, 160));

    var sawSuspended = false;
    var bodyThrew = null;
    try {
      await b.frameworkSchema.withDeleteTriggersSuspended(
        { externalDbBackend: "ops", dialect: "sqlite" },
        async function () {
          var trg = await driverObj.query(client,
            "SELECT name FROM sqlite_master WHERE type = 'trigger' " +
            "AND name = 'no_delete__blamejs_audit_log'", []);
          var rows = (trg && trg.rows) ? trg.rows : trg;
          sawSuspended = (rows || []).length === 0;
          throw new Error("the purge failed after the guard came off");
        });
    } catch (e) { bodyThrew = e; }

    check("withDeleteTriggersSuspended runs its body with the DELETE guard off",
      sawSuspended === true);
    check("and propagates the body's failure rather than swallowing it",
      bodyThrew !== null && /purge failed/.test(bodyThrew.message || ""),
      String(bodyThrew && bodyThrew.message));

    var restored = await driverObj.query(client,
      "SELECT name FROM sqlite_master WHERE type = 'trigger' " +
      "AND name = 'no_delete__blamejs_audit_log'", []);
    var restoredRows = (restored && restored.rows) ? restored.rows : restored;
    // Restoring the NAME is not restoring the GUARD. The guard is bounded by
    // the purge anchor, so a restore that rebuilt it without the boundary
    // column would put back a different trigger wearing the same name — one
    // that refuses the very deletion the anchor licenses.
    var restoredSql = await driverObj.query(client,
      "SELECT sql FROM sqlite_master WHERE type = 'trigger' " +
      "AND name = 'no_delete__blamejs_audit_log'", []);
    var restoredSqlRows = (restoredSql && restoredSql.rows) ? restoredSql.rows : restoredSql;
    check("and restores the anchor-bounded guard, not a bare one",
      (restoredSqlRows || []).length === 1 &&
      /monotonicCounter/.test(String(restoredSqlRows[0].sql)) &&
      /lastPurgedCounter/.test(String(restoredSqlRows[0].sql)),
      String(restoredSqlRows && restoredSqlRows[0] && restoredSqlRows[0].sql).slice(0, 160));

    check("and restores it even when the body threw",
      (restoredRows || []).length === 1,
      "a failed purge must not leave the audit table writable");

    // The UPDATE guard is never touched: a purge removes rows, it never
    // edits them, and taking off a protection the operation does not need
    // would widen the window for nothing.
    var updateGuard = await driverObj.query(client,
      "SELECT name FROM sqlite_master WHERE type = 'trigger' " +
      "AND name = 'no_update__blamejs_audit_log'", []);
    var updateRows = (updateGuard && updateGuard.rows) ? updateGuard.rows : updateGuard;
    check("and never touches the UPDATE guard", (updateRows || []).length === 1);

    // Nor any guard on a table the purge does not touch. Restoring by
    // re-running the full installer would drop and recreate every trigger on
    // every WORM table, so putting one delete guard back would briefly remove
    // consent_log's — a window this operation never needed.
    var consentGuards = await driverObj.query(client,
      "SELECT name FROM sqlite_master WHERE type = 'trigger' " +
      "AND name LIKE '%_blamejs_consent_log'", []);
    var consentRows = (consentGuards && consentGuards.rows)
      ? consentGuards.rows : consentGuards;
    check("and leaves the guards on tables the purge does not touch",
      (consentRows || []).length === 2,
      (consentRows || []).map(function (r) { return r.name; }).join(","));

    // If restoring one guard fails, the rest are still attempted. Stopping at
    // the first error would turn one unrestorable trigger into several tables
    // left writable — the opposite of what restoring is for. The failure is
    // reported, naming what could not be put back.
    await b.externalDb.shutdown();
    var failFor = null;
    b.externalDb.init({
      backends: { ops: {
        connect: driverObj.connect,
        query: async function (client2, sql, params) {
          if (failFor && sql.indexOf(failFor) !== -1 && /CREATE TRIGGER/i.test(sql)) {
            throw new Error("cannot recreate the guard on " + failFor);
          }
          return driverObj.query(client2, sql, params);
        },
        close: driverObj.close,
      } },
    });

    failFor = "_blamejs_audit_log";
    var restoreErr = null;
    try {
      await b.frameworkSchema.withDeleteTriggersSuspended(
        { externalDbBackend: "ops", dialect: "sqlite" },
        async function () { return "purged"; });
    } catch (e) { restoreErr = e; }
    failFor = null;

    check("a guard that cannot be restored is reported, naming the table",
      restoreErr !== null &&
      restoreErr.code === "framework-schema/worm-guard-not-restored" &&
      /_blamejs_audit_log/.test(restoreErr.message || ""),
      String(restoreErr && (restoreErr.code || restoreErr.message)));

    // The OTHER table's guard was still put back, which is the point.
    var checkpointGuard = await driverObj.query(client,
      "SELECT name FROM sqlite_master WHERE type = 'trigger' " +
      "AND name = 'no_delete__blamejs_audit_checkpoints'", []);
    var cpRows = (checkpointGuard && checkpointGuard.rows)
      ? checkpointGuard.rows : checkpointGuard;
    check("and the guards after it were restored anyway",
      (cpRows || []).length === 1,
      "one table that cannot be restored must not cost the others");
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) { /* best-effort */ }
    try { if (driver && driver._close) driver._close(); } catch (_e) { /* best-effort */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () {
      console.log("[framework-schema-additive-migration] OK — " +
        helpers.getChecks() + " checks passed");
    },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
