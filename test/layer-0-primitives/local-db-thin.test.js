// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.localDb.thin — lightweight node:sqlite wrapper for desktop daemons.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;

async function run() {
  // ---- _validateOpts ----
  var threw;
  try { b.localDb.thin(); } catch (e) { threw = e; }
  check("localDb.thin: missing opts throws",
    threw && threw.code === "localdb-thin/bad-opts" &&
    threw instanceof b.frameworkError.LocalDbThinError);

  threw = null;
  try { b.localDb.thin({ schemaSql: "CREATE TABLE x(id INTEGER)" }); } catch (e) { threw = e; }
  check("localDb.thin: missing file throws",
    threw && threw.code === "localdb-thin/bad-file");

  threw = null;
  try { b.localDb.thin({ file: "x.db" }); } catch (e) { threw = e; }
  check("localDb.thin: missing schemaSql throws",
    threw && threw.code === "localdb-thin/bad-schema-sql");

  threw = null;
  try { b.localDb.thin({ file: "x.db", schemaSql: "S", recovery: "wat" }); } catch (e) { threw = e; }
  check("localDb.thin: bad recovery throws",
    threw && threw.code === "localdb-thin/bad-recovery");

  threw = null;
  try { b.localDb.thin({ file: "x.db", schemaSql: "S", pragmas: [] }); } catch (e) { threw = e; }
  check("localDb.thin: array pragmas throws",
    threw && threw.code === "localdb-thin/bad-pragmas");

  // ---- happy path: open / schema / prepare-cache / run / query / close ----
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-localdb-"));
  var dbPath = path.join(tmpDir, "thin.db");
  try {
    var handle = b.localDb.thin({
      file:      dbPath,
      schemaSql: "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);",
      audit:     false,
    });
    check("localDb.thin: returns operator surface",
      typeof handle.prepare === "function" &&
      typeof handle.run === "function" &&
      typeof handle.query === "function" &&
      typeof handle.close === "function" &&
      handle.file === dbPath);

    handle.run("INSERT INTO notes (body) VALUES (?)", "alpha");
    handle.run("INSERT INTO notes (body) VALUES (?)", "beta");
    var rows = handle.query("SELECT body FROM notes ORDER BY id");
    check("localDb.thin: run + query round-trip",
      rows.length === 2 && rows[0].body === "alpha" && rows[1].body === "beta");

    // Prepared-statement cache: same SQL string returns same prepared
    // handle on second prepare().
    var s1 = handle.prepare("SELECT 1 AS v");
    var s2 = handle.prepare("SELECT 1 AS v");
    check("localDb.thin: prepare cache returns same handle", s1 === s2);

    // WAL mode is enforced.
    var modeRow = handle.db.prepare("PRAGMA journal_mode").get();
    check("localDb.thin: PRAGMA journal_mode=WAL",
      modeRow && String(modeRow.journal_mode).toLowerCase() === "wal");

    // ---- #320: SQLITE_LIMIT_LENGTH parity (sqlLength cap) ----
    // The thin path now opens with the same 1 MiB sqlLength cap as b.db / the
    // CLI: a >1 MiB raw statement is rejected at parse time. The builder/run
    // path parameterizes values, so this guards prepare()/exec() of raw SQL.
    var hugeSql = "SELECT '" + "x".repeat(1024 * 1024 + 64) + "'";
    threw = null;
    try { handle.prepare(hugeSql); } catch (e) { threw = e; }
    check("localDb.thin: raw statement over the 1 MiB sqlLength cap is rejected at parse",
      threw !== null);
    // A normal statement is unaffected.
    check("localDb.thin: a small statement still prepares", !!handle.prepare("SELECT 2 AS v"));

    handle.close();

    // bad limits shape throws at validation.
    threw = null;
    try {
      b.localDb.thin({ file: path.join(tmpDir, "lim.db"),
        schemaSql: "CREATE TABLE t(x)", audit: false, limits: "nope" });
    } catch (e) { threw = e; }
    check("localDb.thin: non-object limits throws", threw && threw.code === "localdb-thin/bad-limits");

    // opts.limits raises the cap — a statement that the default rejects now
    // prepares under a 2 MiB sqlLength.
    var raised = b.localDb.thin({ file: path.join(tmpDir, "raised.db"),
      schemaSql: "CREATE TABLE t(x)", audit: false, limits: { sqlLength: 2 * 1024 * 1024 } });
    check("localDb.thin: opts.limits raises sqlLength (over-default statement prepares)",
      !!raised.prepare(hugeSql));
    raised.close();

    // After close, prepare/run/query must throw.
    threw = null;
    try { handle.run("SELECT 1"); } catch (e) { threw = e; }
    check("localDb.thin: post-close run throws",
      threw && threw.code === "localdb-thin/closed");

    // Idempotent close.
    handle.close();
    check("localDb.thin: close() idempotent", true);

    // ---- recovery: refuse vs rename-and-recreate ----
    // Corrupt the file in place.
    fs.writeFileSync(dbPath, "this-is-not-a-sqlite-file");
    threw = null;
    try {
      b.localDb.thin({
        file:      dbPath,
        schemaSql: "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY);",
        audit:     false,
      });
    } catch (e) { threw = e; }
    check("localDb.thin: refuse on corrupt (default) throws",
      threw && threw.code === "localdb-thin/corrupt");

    // Now with rename-and-recreate it must auto-recover.
    var recovered = b.localDb.thin({
      file:      dbPath,
      schemaSql: "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);",
      recovery:  "rename-and-recreate",
      audit:     false,
    });
    check("localDb.thin: rename-and-recreate recovers",
      recovered.recovered === true && typeof recovered.recoveredTo === "string");

    // The renamed-aside file exists on disk.
    check("localDb.thin: corrupt file is renamed aside",
      fs.existsSync(recovered.recoveredTo));

    // The fresh DB is usable.
    recovered.run("INSERT INTO notes (body) VALUES (?)", "fresh");
    var freshRows = recovered.query("SELECT body FROM notes");
    check("localDb.thin: fresh DB usable after recovery",
      freshRows.length === 1 && freshRows[0].body === "fresh");

    recovered.close();

    // ---- pragma allowlist: bad name rejected ----
    threw = null;
    try {
      b.localDb.thin({
        file:      path.join(tmpDir, "p.db"),
        schemaSql: "CREATE TABLE x(id INTEGER);",
        pragmas:   { "drop-table": "ON" },
        audit:     false,
      });
    } catch (e) { threw = e; }
    check("localDb.thin: bad pragma name rejected",
      threw && threw.code === "localdb-thin/bad-pragma-name");

    // ---- a refused open closes the handle it opened ----
    // `_attemptOpen` closed the database only on the integrity_check branch, so
    // a throw from `_runPragmas` or from `schemaSql` left it open with no handle
    // for the caller to close. On Windows that locks the file. The two legs need
    // different assertions: /proc/self/fd exists only on Linux, and rename
    // succeeds there even with the handle open, so neither signal alone covers
    // both platforms.
    function _fdsOn(file) {
      if (process.platform === "win32") return null;
      var n = 0;
      try {
        fs.readdirSync("/proc/self/fd").forEach(function (entry) {
          var target;
          try { target = fs.readlinkSync(path.join("/proc/self/fd", entry)); }
          catch (_e) { return; }
          if (target === file) n += 1;
        });
      } catch (_e) { return null; }
      return n;
    }
    [
      { label: "a refused pragma",
        opts: { pragmas: { journal_mode: "WAL", "not-a-real-pragma": 1 },
                schemaSql: "CREATE TABLE x(id INTEGER);" },
        code: "localdb-thin/pragma-not-overridable" },
      { label: "schema SQL that does not parse",
        opts: { schemaSql: "CREATE TABLE ((((" },
        code: null },
    ].forEach(function (c, ci) {
      var leakDir = fs.mkdtempSync(path.join(os.tmpdir(), "thin-leak-"));
      var leakFile = path.join(leakDir, "t" + ci + ".db");
      var baseline = _fdsOn(leakFile);
      var leakThrew = null;
      try {
        b.localDb.thin(Object.assign({ file: leakFile, audit: false }, c.opts));
      } catch (e) { leakThrew = e; }
      check("localDb.thin refuses " + c.label, leakThrew !== null);
      if (c.code) {
        check("  with " + c.code, leakThrew && leakThrew.code === c.code,
          "code=" + (leakThrew && leakThrew.code));
      }
      if (baseline !== null) {
        check("  and leaves no open descriptor on the file",
          _fdsOn(leakFile) === baseline,
          "baseline=" + baseline + " after=" + _fdsOn(leakFile));
      }
      // Removable only when nothing holds the file, so on Windows this is the
      // same assertion by another route.
      var removed = true;
      try { fs.rmSync(leakDir, { recursive: true, force: true }); }
      catch (_e) { removed = false; }
      check("  and its directory can be removed", removed);
    });

    // ---- caller pragmas are applied where they can still take effect ----
    // `auto_vacuum` only takes on a database that has no tables yet, and
    // `journal_mode=WAL` writes the header, so applying the caller's pragmas
    // after WAL left `PRAGMA auto_vacuum` at 0: a session store could not
    // reclaim pages with `incremental_vacuum` and needed a full VACUUM.
    // Measured on node:sqlite: WAL then auto_vacuum reads 0, the other order 2.
    var av = b.localDb.thin({
      file:      path.join(tmpDir, "av.db"),
      schemaSql: "CREATE TABLE x(id INTEGER);",
      pragmas:   { auto_vacuum: "INCREMENTAL" },
      audit:     false,
    });
    var avMode = av.query("PRAGMA auto_vacuum")[0];
    check("localDb.thin: a caller's auto_vacuum takes effect",
      avMode && Number(avMode.auto_vacuum) === 2,
      "auto_vacuum=" + JSON.stringify(avMode));
    var jm = av.query("PRAGMA journal_mode")[0];
    check("localDb.thin: journal_mode is still WAL alongside it",
      jm && String(jm.journal_mode).toLowerCase() === "wal",
      "journal_mode=" + JSON.stringify(jm));
    av.close();

    // The fixed set is not the caller's to lower, and a value it would overwrite
    // is refused rather than accepted and discarded. Applying the caller first
    // and the fixed set after would have left this one silently dropped.
    ["journal_mode", "foreign_keys", "secure_delete", "trusted_schema",
     "cell_size_check"].forEach(function (name) {
      var opts = {
        file:      path.join(tmpDir, "floor-" + name + ".db"),
        schemaSql: "CREATE TABLE x(id INTEGER);",
        pragmas:   {},
        audit:     false,
      };
      opts.pragmas[name] = "OFF";
      var refused = null;
      try { b.localDb.thin(opts); } catch (e) { refused = e; }
      check("localDb.thin: " + name + " is refused rather than silently dropped",
        refused !== null && refused.code === "localdb-thin/pragma-not-overridable",
        "code=" + (refused && refused.code));
    });

    // Tuning knobs are the caller's. These are applied as defaults only when
    // the caller says nothing, so an operator who raised busy_timeout for a
    // contended store, or chose synchronous=FULL for durability, keeps both.
    var tuned = b.localDb.thin({
      file:      path.join(tmpDir, "tuned.db"),
      schemaSql: "CREATE TABLE x(id INTEGER);",
      pragmas:   { busy_timeout: 30000, synchronous: "FULL" },
      audit:     false,
    });
    var bt = tuned.query("PRAGMA busy_timeout")[0];
    var sy = tuned.query("PRAGMA synchronous")[0];
    check("localDb.thin: a caller's busy_timeout survives",
      bt && Number(bt.timeout) === 30000, "busy_timeout=" + JSON.stringify(bt));
    check("localDb.thin: a caller's synchronous survives",
      sy && Number(sy.synchronous) === 2, "synchronous=" + JSON.stringify(sy));
    var tunedJm = tuned.query("PRAGMA journal_mode")[0];
    check("localDb.thin: and the fixed set still holds alongside them",
      tunedJm && String(tunedJm.journal_mode).toLowerCase() === "wal",
      "journal_mode=" + JSON.stringify(tunedJm));
    tuned.close();

    // The control: with no pragmas the framework's own defaults apply.
    var plain = b.localDb.thin({
      file:      path.join(tmpDir, "plain.db"),
      schemaSql: "CREATE TABLE x(id INTEGER);",
      audit:     false,
    });
    var plainBt = plain.query("PRAGMA busy_timeout")[0];
    var plainSy = plain.query("PRAGMA synchronous")[0];
    check("localDb.thin: the defaults apply when the caller sets nothing",
      plainBt && Number(plainBt.timeout) === 5000 &&
      plainSy && Number(plainSy.synchronous) === 1,
      "busy_timeout=" + JSON.stringify(plainBt) + " synchronous=" + JSON.stringify(plainSy));
    plain.close();
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }

  check("localDb.LocalDbThinError class registered",
    typeof b.localDb.LocalDbThinError === "function" &&
    b.localDb.LocalDbThinError === b.frameworkError.LocalDbThinError);

  await _testIntegrityCheckThatCannotRun();
}

// PRAGMA integrity_check answers in three ways and only two of them mean the
// file is damaged: it reports "ok", it lists what it found, or it fails to run.
// The third was read as corruption, so a database that still answered ordinary
// queries was renamed aside and replaced with an empty one, and the sqlite error
// that led there was discarded rather than reported.
//
// Real corruption is what is drivable here, and it is also what the fix could
// break: a classifier that stops calling a damaged file damaged would be worse
// than the bug. These assert that the corrupt path is intact and now says why,
// and that a file still readable through sqlite_schema survives the judgement.
async function _testIntegrityCheckThatCannotRun() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-thin-verdict-"));
  try {
    var schemaSql = "CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY, body TEXT NOT NULL);";

    // A file of bytes that is not a database at all. sqlite raises
    // "file is not a database", which is corruption and must stay corruption.
    var notDb = path.join(dir, "garbage.db");
    fs.writeFileSync(notDb, Buffer.alloc(8192, 0x41));
    var refused = null;
    try { b.localDb.thin({ file: notDb, schemaSql: schemaSql, audit: false }); }
    catch (e) { refused = e; }
    check("a file that is not a database is still refused as corrupt",
      refused !== null && refused.code === "localdb-thin/corrupt",
      refused ? String(refused.code) + ": " + refused.message : "no throw");
    check("and the refusal now carries the sqlite error that led to it",
      refused !== null && /not a database|encrypted|malformed/i.test(String(refused.message || "")),
      refused ? String(refused.message) : "no throw");

    // The same file under rename-and-recreate is still set aside and replaced,
    // and the audit event now records why. `audit` here is a boolean, so the
    // row is read back out of the real chain rather than from a capture sink.
    await helpers.setupTestDb(dir);
    var recovered = b.localDb.thin({
      file: notDb, schemaSql: schemaSql, recovery: "rename-and-recreate",
      audit: true,
    });
    check("rename-and-recreate still recovers a genuinely corrupt file",
      recovered.recovered === true && typeof recovered.recoveredTo === "string",
      JSON.stringify({ recovered: recovered.recovered, to: recovered.recoveredTo }));
    var aside = fs.readdirSync(dir).filter(function (n) {
      return n.indexOf(".corrupt-") !== -1;
    });
    check("and the damaged bytes are kept aside rather than deleted",
      aside.length === 1, JSON.stringify(aside));
    recovered.close();
    await b.audit.flush();
    var rows = await b.audit.query({ action: "localdb.thin.recovered" });
    var meta = rows.length
      ? (typeof rows[0].metadata === "string" ? JSON.parse(rows[0].metadata) : rows[0].metadata)
      : null;
    check("the recovery audit row says why the file was replaced",
      meta !== null && typeof meta.reason === "string" && meta.reason.length > 0,
      "rows=" + rows.length + " " + JSON.stringify(meta));

    // The control for the classifier: an ordinary healthy database is not
    // caught by any of the above, so the stricter reading did not widen into
    // refusing good files.
    var good = path.join(dir, "good.db");
    var h = b.localDb.thin({ file: good, schemaSql: schemaSql, audit: false });
    h.run("INSERT INTO notes VALUES (?, ?)", "a", "hello");
    h.close();
    var reopened = b.localDb.thin({ file: good, schemaSql: schemaSql, audit: false });
    check("a healthy database still opens, with its rows",
      reopened.query("SELECT id FROM notes").length === 1 &&
      reopened.recovered !== true,
      JSON.stringify({ recovered: reopened.recovered }));
    reopened.close();
  } finally {
    try { await helpers.teardownTestDb(dir); } catch (_e) { /* best-effort */ }
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[local-db-thin] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
