// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Both SQLite migration runners (b.migrations and the migrationDir option of
 * b.db.init) run each step inside a synchronous transaction. A step whose
 * up() or down() returns a promise must be refused and rolled back, not
 * recorded as applied while its body is still running, and its rejection
 * must not escape as an unhandled rejection.
 */

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var { DatabaseSync } = require("node:sqlite");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

var RAN_FLAG = "__blamejsAsyncMigrationBodyRan";

var ASYNC_UP = [
  "module.exports = {",
  "  up: async function (db) {",
  "    globalThis." + RAN_FLAG + " = true;",
  "    db['exec'](\"CREATE TABLE before_await (id INTEGER)\");",
  "    await null;",
  "    db['exec'](\"CREATE TABLE after_await (id INTEGER)\");",
  "    throw new Error('async up failed');",
  "  },",
  "  down: function (db) {},",
  "};",
].join("\n");

var SYNC_UP_ASYNC_DOWN = [
  "module.exports = {",
  "  up: function (db) { db['exec'](\"CREATE TABLE widgets (id INTEGER PRIMARY KEY)\"); },",
  "  down: async function (db) {",
  "    globalThis." + RAN_FLAG + " = true;",
  "    db['exec'](\"DROP TABLE widgets\");",
  "    await null;",
  "    db['exec'](\"CREATE TABLE down_after_await (id INTEGER)\");",
  "    throw new Error('async down failed');",
  "  },",
  "};",
].join("\n");

var PROMISE_RETURNING_UP = [
  "module.exports = {",
  "  up: function (db) {",
  "    db['exec'](\"CREATE TABLE sync_part (id INTEGER)\");",
  "    return Promise.reject(new Error('promise-returning up failed'));",
  "  },",
  "  down: function (db) {},",
  "};",
].join("\n");

function _tables(db) {
  return db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all()
    .map(function (r) { return r.name; });
}

function _resetRanFlag() { delete globalThis[RAN_FLAG]; }

function _fixture() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mig-async-"));
  var migDir = path.join(dir, "migrations");
  fs.mkdirSync(migDir, { recursive: true });
  return {
    dir: dir,
    migDir: migDir,
    write: function (file, content) { fs.writeFileSync(path.join(migDir, file), content); },
    cleanup: function () { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ } },
  };
}

function _trackUnhandled() {
  var seen = [];
  function onUnhandled(e) { seen.push((e && e.message) || String(e)); }
  process.on("unhandledRejection", onUnhandled);
  return {
    seen: seen,
    stop: function () { process.removeListener("unhandledRejection", onUnhandled); },
  };
}

async function testMigrationsRefusesAsyncUp() {
  var fx = _fixture();
  var db = new DatabaseSync(path.join(fx.dir, "test.db"));
  var tracker = _trackUnhandled();
  _resetRanFlag();
  try {
    fx.write("0001-async-up.js", ASYNC_UP);
    var migs = b.migrations.create({ db: db, dir: fx.migDir });
    var threw = null;
    try { migs.up(); } catch (e) { threw = e; }
    await helpers.passiveObserve(50, "migrations async up: a rejection would surface in this window");
    check("b.migrations: an async up() is refused",
      threw !== null && threw.code === "migrations/up-failed");
    check("b.migrations: the refusal names the synchronous contract",
      threw !== null && /synchronous/.test(threw.message));
    check("b.migrations: an async up() is not called", globalThis[RAN_FLAG] !== true);
    var tables = _tables(db);
    check("b.migrations: an async up() writes nothing before its first await",
      tables.indexOf("before_await") === -1);
    check("b.migrations: an async up() writes nothing after its first await",
      tables.indexOf("after_await") === -1);
    var st = migs.status();
    check("b.migrations: a refused async up() is not recorded as applied",
      st.applied.length === 0 && st.pending.indexOf("0001-async-up.js") !== -1);
    check("b.migrations: the async up() rejection is not unhandled", tracker.seen.length === 0);
  } finally {
    _resetRanFlag();
    tracker.stop();
    try { db.close(); } catch (_e) { /* best-effort */ }
    fx.cleanup();
  }
}

async function testMigrationsRefusesAsyncDown() {
  var fx = _fixture();
  var db = new DatabaseSync(path.join(fx.dir, "test.db"));
  var tracker = _trackUnhandled();
  _resetRanFlag();
  try {
    fx.write("0001-async-down.js", SYNC_UP_ASYNC_DOWN);
    var migs = b.migrations.create({ db: db, dir: fx.migDir });
    migs.up();
    var threw = null;
    try { migs.down(); } catch (e) { threw = e; }
    await helpers.passiveObserve(50, "migrations async down: a rejection would surface in this window");
    check("b.migrations: an async down() is refused",
      threw !== null && threw.code === "migrations/down-failed");
    check("b.migrations: an async down() is not called", globalThis[RAN_FLAG] !== true);
    var tables = _tables(db);
    check("b.migrations: an async down() writes nothing before its first await",
      tables.indexOf("widgets") !== -1);
    check("b.migrations: an async down() writes nothing after its first await",
      tables.indexOf("down_after_await") === -1);
    check("b.migrations: a refused async down() leaves the migration recorded",
      migs.status().applied.some(function (r) { return r.name === "0001-async-down.js"; }));
    check("b.migrations: the async down() rejection is not unhandled", tracker.seen.length === 0);
  } finally {
    _resetRanFlag();
    tracker.stop();
    try { db.close(); } catch (_e) { /* best-effort */ }
    fx.cleanup();
  }
}

async function testDbInitMigrationDirRefusesAsyncUp() {
  var fx = _fixture();
  var tracker = _trackUnhandled();
  _resetRanFlag();
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  process.env.BLAMEJS_VAULT_PASSPHRASE = "blamejs-test-passphrase-not-secret";
  process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = "blamejs-test-passphrase-not-secret";
  try {
    fx.write("0001-async-up.js", ASYNC_UP);
    b.cluster._resetForTest();
    b.audit._resetForTest();
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: fx.dir });
    var threw = null;
    try {
      await b.db.init({
        dataDir: fx.dir,
        tmpDir: path.join(fx.dir, "tmpfs"),
        allowNonTmpfsTmpDir: true,
        schema: [],
        migrationDir: fx.migDir,
      });
    } catch (e) { threw = e; }
    await helpers.passiveObserve(50, "db.init async up: a rejection would surface in this window");
    check("b.db.init migrationDir: an async up() is refused",
      threw !== null && /synchronous/.test(threw.message));
    check("b.db.init migrationDir: an async up() is not called", globalThis[RAN_FLAG] !== true);
    check("b.db.init migrationDir: the async up() rejection is not unhandled", tracker.seen.length === 0);
  } finally {
    _resetRanFlag();
    tracker.stop();
    try { await b.db.close(); } catch (_e) { /* best-effort */ }
    b.db._resetForTest();
    b.vault._resetForTest();
    fx.cleanup();
  }
}

async function testMigrationsRefusesPromiseReturningUp() {
  var fx = _fixture();
  var db = new DatabaseSync(path.join(fx.dir, "test.db"));
  var tracker = _trackUnhandled();
  try {
    fx.write("0001-promise-up.js", PROMISE_RETURNING_UP);
    var migs = b.migrations.create({ db: db, dir: fx.migDir });
    var threw = null;
    try { migs.up(); } catch (e) { threw = e; }
    await helpers.passiveObserve(50, "migrations promise-returning up: a rejection would surface in this window");
    check("b.migrations: a plain up() that returns a promise is refused",
      threw !== null && threw.code === "migrations/up-failed" && /synchronous/.test(threw.message));
    check("b.migrations: a refused promise-returning up() has its synchronous writes rolled back",
      _tables(db).indexOf("sync_part") === -1);
    check("b.migrations: a refused promise-returning up() is not recorded as applied",
      migs.status().applied.length === 0);
    check("b.migrations: the promise-returning up() rejection is not unhandled", tracker.seen.length === 0);
  } finally {
    tracker.stop();
    try { db.close(); } catch (_e) { /* best-effort */ }
    fx.cleanup();
  }
}

async function run() {
  await testMigrationsRefusesAsyncUp();
  await testMigrationsRefusesAsyncDown();
  await testMigrationsRefusesPromiseReturningUp();
  await testDbInitMigrationDirRefusesAsyncUp();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[migrations-async-step] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
