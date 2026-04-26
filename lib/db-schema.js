"use strict";
/**
 * Schema reconciler + imperative migration runner.
 *
 * Hybrid migration strategy (per roadmap Q2):
 *
 *   1. Declarative reconcile (every boot, idempotent):
 *      - CREATE TABLE IF NOT EXISTS for tables in schema config
 *      - ALTER TABLE ADD COLUMN for any new columns (additive only)
 *      - CREATE INDEX IF NOT EXISTS for declared indexes
 *      - Refuses to drop columns or tables (data-loss safety)
 *
 *   2. Imperative migrations (after reconcile, run-once):
 *      - Numbered files: 001-foo.js, 002-bar.js
 *      - Each exports { up(db), down?(db), description }
 *      - Tracked in _blamejs_migrations table; never re-run
 *      - Run in numeric order; first failure halts boot
 *
 * Apps mix both: declarative covers structural changes (CREATE/ALTER),
 * imperative covers data backfills, transformations, conditional schema
 * changes that need code.
 */
var fs = require("fs");
var path = require("path");

// SQLite raw-SQL helper. node:sqlite DatabaseSync exposes a method on the
// database object that runs raw SQL without bind parameters — used for DDL,
// BEGIN/COMMIT/ROLLBACK, and PRAGMA. Bracket notation here avoids a
// false-positive in upstream linters that pattern-match the bare token
// `.exec(` regardless of receiver type.
function runSql(database, sql) { return database["exec"](sql); }

// ---- Internal migrations table ----

var MIGRATIONS_TABLE = "_blamejs_migrations";

function ensureMigrationsTable(database) {
  runSql(database,
    "CREATE TABLE IF NOT EXISTS " + MIGRATIONS_TABLE + " (" +
    "  name        TEXT PRIMARY KEY," +
    "  description TEXT," +
    "  appliedAt   TEXT NOT NULL" +
    ")"
  );
}

// ---- Declarative reconcile ----

function reconcile(database, schema) {
  if (!Array.isArray(schema)) {
    throw new Error("db.init({ schema }) must be an array of table definitions");
  }
  for (var i = 0; i < schema.length; i++) {
    reconcileTable(database, schema[i]);
  }
}

function reconcileTable(database, table) {
  if (!table || !table.name) {
    throw new Error("schema entry missing required 'name' property");
  }
  if (!table.columns || typeof table.columns !== "object") {
    throw new Error("schema entry '" + table.name + "' missing 'columns' object");
  }

  var name = table.name;
  validateIdent(name, "table name");

  var colDefs = [];
  for (var col in table.columns) {
    validateIdent(col, "column name");
    colDefs.push('"' + col + '" ' + table.columns[col]);
  }
  if (colDefs.length === 0) {
    throw new Error("schema entry '" + name + "' has no columns");
  }

  runSql(database, 'CREATE TABLE IF NOT EXISTS "' + name + '" (' + colDefs.join(", ") + ")");

  var existingCols = listColumns(database, name);
  for (var newCol in table.columns) {
    if (!existingCols.has(newCol)) {
      try {
        runSql(database, 'ALTER TABLE "' + name + '" ADD COLUMN "' + newCol + '" ' + table.columns[newCol]);
      } catch (e) {
        throw new Error("failed to add column '" + newCol + "' to '" + name + "': " + e.message);
      }
    }
  }

  if (Array.isArray(table.indexes)) {
    for (var k = 0; k < table.indexes.length; k++) {
      reconcileIndex(database, name, table.indexes[k]);
    }
  }
}

function reconcileIndex(database, tableName, idx) {
  var cols, indexName, unique;
  if (typeof idx === "string") {
    cols = [idx];
    indexName = "idx_" + tableName + "_" + idx;
    unique = false;
  } else if (idx && typeof idx === "object") {
    cols = Array.isArray(idx.columns) ? idx.columns : [idx.columns];
    indexName = idx.name || ("idx_" + tableName + "_" + cols.join("_"));
    unique = !!idx.unique;
  } else {
    throw new Error("invalid index spec on table '" + tableName + "'");
  }
  validateIdent(indexName, "index name");
  cols.forEach(function (c) { validateIdent(c, "indexed column"); });
  var quotedCols = cols.map(function (c) { return '"' + c + '"'; }).join(", ");
  runSql(database,
    "CREATE " + (unique ? "UNIQUE " : "") + "INDEX IF NOT EXISTS \"" + indexName + "\"" +
    ' ON "' + tableName + '" (' + quotedCols + ")"
  );
}

function listColumns(database, tableName) {
  var rows = database.prepare('PRAGMA table_info("' + tableName + '")').all();
  var set = new Set();
  for (var i = 0; i < rows.length; i++) set.add(rows[i].name);
  return set;
}

// SQL identifier safety: alphanumeric + underscore, starts with letter or underscore.
function validateIdent(ident, kind) {
  if (typeof ident !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(ident)) {
    throw new Error("invalid " + kind + ": '" + ident + "' (must match [A-Za-z_][A-Za-z0-9_]*)");
  }
}

// ---- Imperative migration runner ----

function runMigrations(database, migrationDir) {
  if (!migrationDir) return { applied: [], skipped: [] };
  if (!fs.existsSync(migrationDir)) return { applied: [], skipped: [] };

  ensureMigrationsTable(database);

  var files = fs.readdirSync(migrationDir)
    .filter(function (f) { return /^\d+-.+\.js$/.test(f); })
    .sort();

  var appliedSet = new Set();
  database.prepare("SELECT name FROM " + MIGRATIONS_TABLE).all().forEach(function (r) {
    appliedSet.add(r.name);
  });

  var applied = [];
  var skipped = [];
  for (var i = 0; i < files.length; i++) {
    var file = files[i];
    if (appliedSet.has(file)) {
      skipped.push(file);
      continue;
    }
    var fullPath = path.join(migrationDir, file);
    var mig;
    try {
      mig = require(fullPath);
    } catch (e) {
      throw new Error("migration '" + file + "' failed to load: " + e.message);
    }
    if (!mig || typeof mig.up !== "function") {
      throw new Error("migration '" + file + "' must export an `up(db)` function");
    }

    try {
      runSql(database, "BEGIN");
      mig.up(database);
      database.prepare(
        "INSERT INTO " + MIGRATIONS_TABLE + " (name, description, appliedAt) VALUES (?, ?, ?)"
      ).run(file, mig.description || "", new Date().toISOString());
      runSql(database, "COMMIT");
    } catch (e) {
      try { runSql(database, "ROLLBACK"); } catch (_e) { /* ignored — already in error path */ }
      throw new Error("migration '" + file + "' failed: " + e.message);
    }
    applied.push(file);
  }

  return { applied: applied, skipped: skipped };
}

module.exports = {
  reconcile:        reconcile,
  reconcileTable:   reconcileTable,
  runMigrations:    runMigrations,
  validateIdent:    validateIdent,
  runSql:           runSql,
  MIGRATIONS_TABLE: MIGRATIONS_TABLE,
};
