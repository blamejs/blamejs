// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.frameworkSchema additive-column migrations.
 *
 * Every table DDL is CREATE TABLE IF NOT EXISTS, which does nothing at all to a
 * table that already exists. So a column added after a deployment's first boot
 * never arrives on its own: re-running schema setup leaves the old table as it
 * was, and the first write naming the new column fails on a database the
 * operator believes they just upgraded.
 *
 * The purge anchor is where that bit. It gained `signature` and
 * `publicKeyFingerprint` so a purge can record which rows it removed and prove
 * who removed them; without the columns a purge cannot write its anchor at all.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

var DIALECTS = ["postgres", "sqlite", "mysql"];

async function run() {
  var gen = b.frameworkSchema._additiveColumnDDLForTest;

  DIALECTS.forEach(function (dialect) {
    var stmts = gen(dialect);
    check("framework-schema: " + dialect + " emits additive-column statements",
      Array.isArray(stmts) && stmts.length >= 2, JSON.stringify(stmts));

    var joined = stmts.join("\n");
    check("framework-schema: " + dialect + " migrates the anchor signature",
      /ALTER TABLE\s+\S*audit_purge_anchor[\s\S]*signature/i.test(joined), joined);
    check("framework-schema: " + dialect + " migrates the anchor key fingerprint",
      /publicKeyFingerprint/.test(joined), joined);

    stmts.forEach(function (s) {
      check("framework-schema: " + dialect + " statement is an ADD COLUMN",
        /^ALTER TABLE\s+\S+\s+ADD COLUMN\s/.test(s), s);
    });

    // Idempotence is dialect-specific and the difference is load-bearing:
    // Postgres can say IF NOT EXISTS, SQLite and MySQL cannot and instead
    // report a duplicate column, which ensureSchema swallows as the intended
    // end state. Emitting IF NOT EXISTS to those two would be a syntax error.
    if (dialect === "postgres") {
      check("framework-schema: postgres uses IF NOT EXISTS",
        stmts.every(function (s) { return /ADD COLUMN IF NOT EXISTS/.test(s); }), joined);
    } else {
      check("framework-schema: " + dialect + " does NOT emit IF NOT EXISTS",
        stmts.every(function (s) { return !/IF NOT EXISTS/.test(s); }), joined);
    }
  });

  // The column type has to be the dialect's own binary type — a signature is
  // bytes, and Postgres spells that BYTEA while MySQL spells it LONGBLOB.
  var pg = gen("postgres").join("\n");
  var my = gen("mysql").join("\n");
  check("framework-schema: postgres signature column is BYTEA", /BYTEA/i.test(pg), pg);
  check("framework-schema: mysql signature column is LONGBLOB", /LONGBLOB/i.test(my), my);

  // Control: the three dialects must not all render identically, or the checks
  // above would pass on a generator that ignored its argument.
  check("framework-schema: the dialects render differently",
    pg !== my, "postgres and mysql produced identical DDL");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[framework-schema-migrations] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
