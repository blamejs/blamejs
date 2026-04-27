"use strict";
/**
 * vault-rotate — vault key rotation primitives (diagnostics).
 *
 * This slice ships the read-only diagnostic surface that any rotation
 * workflow needs upstream of the actual rotation:
 *
 *   - validateSchemaMatch(db, opts)
 *       Compare the registered field-crypto schema against the live
 *       DB. Surfaces three failure modes:
 *         · table_missing      — schema declares a table the DB lacks
 *         · sealed_col_missing — schema declares a sealed column the
 *                                live table lacks
 *         · drift              — a real column the schema does NOT
 *                                declare sealed has vault-prefixed
 *                                values in at least one sampled row
 *
 *   - verify({ keys, db, oldKeys?, sampleMin?, samplePercent? })
 *       Walk every registered sealed column, sample rows, attempt to
 *       decrypt with `keys`. Reports failures + (if oldKeys passed)
 *       regressions: rows that still decrypt under oldKeys, indicating
 *       rotation didn't take effect.
 *
 *   - formatValidationResult(result)
 *       Render the validation result for a CLI / log line.
 *
 * The actual rotation pipeline (rotateDataDirectory) ships as the next
 * slice. Diagnostics ship first because operators run them whether or
 * not they're rotating: post-deploy schema-drift smoke tests, post-
 * incident "did anything get unrotated?" sweeps, etc.
 *
 * Generic by design: no hardcoded list of "infrastructure columns" —
 * the drift detector treats every column not declared in the schema's
 * sealedFields / derivedHashes as a candidate, samples rows, and only
 * flags those that actually contain vault-prefixed values. Operators
 * with framework tables that legitimately hold a vault-prefixed string
 * in an undeclared column pass them via opts.infraColumns so the
 * sampler skips them.
 */

var C = require("./constants");
var fieldCrypto = require("./field-crypto");
var cryptoLib = require("./crypto");
var { FrameworkError } = require("./framework-error");

class VaultRotateError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "VaultRotateError";
    this.permanent = true;
    this.isVaultRotateError = true;
  }
}

var VAULT_PREFIX = C.VAULT_PREFIX;
var DEFAULT_DRIFT_SAMPLE_LIMIT = 100;
var DEFAULT_VERIFY_SAMPLE_MIN  = 5;
var DEFAULT_VERIFY_SAMPLE_FRAC = 0.01;

function _listLiveTables(db) {
  return db.prepare(
    "SELECT name FROM sqlite_master " +
    "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
  ).all().map(function (r) { return r.name; });
}

function _listLiveColumns(db, table) {
  // PRAGMA table_info — table name comes from sqlite_master so it's
  // already validated as an existing identifier.
  return db.prepare("PRAGMA table_info(\"" + table.replace(/"/g, '""') + "\")").all()
    .map(function (c) { return c.name; });
}

function _knownColumnsFor(schema, infraColumns) {
  var set = Object.create(null);
  if (Array.isArray(infraColumns)) {
    for (var i = 0; i < infraColumns.length; i++) set[infraColumns[i]] = true;
  }
  if (schema && Array.isArray(schema.sealedFields)) {
    for (var s = 0; s < schema.sealedFields.length; s++) set[schema.sealedFields[s]] = true;
  }
  if (schema && schema.derivedHashes) {
    for (var dk in schema.derivedHashes) {
      if (Object.prototype.hasOwnProperty.call(schema.derivedHashes, dk)) set[dk] = true;
      // Source field is also "known" — it's the unsealed input
      var spec = schema.derivedHashes[dk];
      if (spec && spec.from) set[spec.from] = true;
    }
  }
  return set;
}

function validateSchemaMatch(db, opts) {
  opts = opts || {};
  var sampleLimit = typeof opts.driftSampleLimit === "number" && opts.driftSampleLimit > 0
    ? opts.driftSampleLimit : DEFAULT_DRIFT_SAMPLE_LIMIT;
  var infraColumns = Array.isArray(opts.infraColumns) ? opts.infraColumns : [];
  // Tables to consider — by default, every table the framework's
  // field-crypto registry knows about. Operator can pass an explicit
  // tables list to scope the check.
  var tablesToCheck = Array.isArray(opts.tables) && opts.tables.length > 0
    ? opts.tables.slice()
    : null;

  var warnings = [];
  var errors   = [];

  var liveTables = _listLiveTables(db);
  var liveTableSet = Object.create(null);
  for (var lt = 0; lt < liveTables.length; lt++) liveTableSet[liveTables[lt]] = true;

  // If no tables list passed, derive it from the live DB. Tables
  // unknown to fieldCrypto will be reported as drift candidates if
  // they have vault-prefixed columns.
  var allTables = tablesToCheck || liveTables;

  for (var t = 0; t < allTables.length; t++) {
    var table = allTables[t];

    if (!liveTableSet[table]) {
      // Schema declared a table the DB doesn't have. Non-fatal —
      // rotation skips it (nothing to rotate).
      warnings.push({
        kind:    "table_missing",
        table:   table,
        message: "schema lists table '" + table + "' but the live DB has no such table (skipped during rotation)",
      });
      continue;
    }

    var schema = fieldCrypto.getSchema(table); // null if not registered
    var liveCols = _listLiveColumns(db, table);
    var liveColSet = Object.create(null);
    for (var c = 0; c < liveCols.length; c++) liveColSet[liveCols[c]] = true;

    // Schema-declared sealed columns missing from live → warning
    if (schema && Array.isArray(schema.sealedFields)) {
      for (var sf = 0; sf < schema.sealedFields.length; sf++) {
        var col = schema.sealedFields[sf];
        if (!liveColSet[col]) {
          warnings.push({
            kind:    "sealed_col_missing",
            table:   table,
            column:  col,
            message: "schema lists '" + table + "." + col + "' as sealed but the live table has no such column (skipped during rotation)",
          });
        }
      }
    }

    // Drift detection: real columns that aren't in the schema's
    // sealedFields, derivedHashes, or the operator's infraColumns
    // allowlist. Sample up to driftSampleLimit rows; flag any column
    // that holds a vault-prefixed string.
    var known = _knownColumnsFor(schema, infraColumns);
    var unknown = [];
    for (var lc = 0; lc < liveCols.length; lc++) {
      if (!known[liveCols[lc]]) unknown.push(liveCols[lc]);
    }
    if (unknown.length === 0) continue;

    var quotedCols = unknown.map(function (n) { return '"' + n.replace(/"/g, '""') + '"'; }).join(", ");
    var sampleSql = "SELECT " + quotedCols +
      " FROM \"" + table.replace(/"/g, '""') + "\" LIMIT " + sampleLimit;
    var sampled;
    try {
      sampled = db.prepare(sampleSql).all();
    } catch (e) {
      warnings.push({
        kind:    "sample_failed",
        table:   table,
        message: "could not sample '" + table + "' for drift detection: " + ((e && e.message) || String(e)),
      });
      continue;
    }

    var flagged = Object.create(null);
    for (var r = 0; r < sampled.length; r++) {
      var row = sampled[r];
      for (var u = 0; u < unknown.length; u++) {
        var uname = unknown[u];
        if (flagged[uname]) continue;
        var v = row[uname];
        if (typeof v === "string" && v.indexOf(VAULT_PREFIX) === 0) {
          flagged[uname] = true;
          errors.push({
            kind:    "drift",
            table:   table,
            column:  uname,
            message: "live DB has vault-prefixed value in '" + table + "." + uname +
              "' but the schema does NOT declare it sealed. Rotating now would leave " +
              "this column encrypted under the OLD key, unreadable post-rotation. " +
              "Either add '" + uname + "' to the schema's sealedFields, or pass it " +
              "via opts.infraColumns if it's intentionally unsealed in the framework's tables.",
          });
        }
      }
    }
  }

  return { warnings: warnings, errors: errors };
}

function formatValidationResult(result) {
  var lines = [];
  if (result.warnings.length === 0 && result.errors.length === 0) {
    return "[vault-rotate] schema match: OK";
  }
  if (result.warnings.length > 0) {
    lines.push("[vault-rotate] schema warnings (" + result.warnings.length + ", non-fatal):");
    for (var w = 0; w < result.warnings.length; w++) lines.push("  - " + result.warnings[w].message);
  }
  if (result.errors.length > 0) {
    lines.push("[vault-rotate] schema errors (" + result.errors.length + ", FATAL — rotation refused):");
    for (var e = 0; e < result.errors.length; e++) lines.push("  - " + result.errors[e].message);
  }
  return lines.join("\n");
}

// verify — sample sealed columns, decrypt with `keys`, report results.
//
// When opts.oldKeys is supplied, also flag rows whose sampled values
// STILL decrypt under oldKeys — that's a regression: rotation didn't
// take effect for those rows.
function verify(opts) {
  opts = opts || {};
  if (!opts.keys) {
    throw new VaultRotateError("vault-rotate/no-keys",
      "verify: opts.keys is required (the keypair to decrypt with)");
  }
  if (!opts.db || typeof opts.db.prepare !== "function") {
    throw new VaultRotateError("vault-rotate/no-db",
      "verify: opts.db is required (a node:sqlite handle)");
  }
  var keys       = opts.keys;
  var db         = opts.db;
  var oldKeys    = opts.oldKeys || null;
  var sampleMin  = typeof opts.sampleMin === "number" && opts.sampleMin >= 1
    ? Math.floor(opts.sampleMin) : DEFAULT_VERIFY_SAMPLE_MIN;
  var samplePct  = typeof opts.samplePercent === "number" && opts.samplePercent > 0
    ? opts.samplePercent : DEFAULT_VERIFY_SAMPLE_FRAC;
  var tablesArg  = Array.isArray(opts.tables) && opts.tables.length > 0
    ? opts.tables.slice() : null;

  var passed      = [];
  var failures    = [];
  var regressions = [];

  var liveTables = _listLiveTables(db);
  var liveTableSet = Object.create(null);
  for (var lt = 0; lt < liveTables.length; lt++) liveTableSet[liveTables[lt]] = true;
  var tables = tablesArg || liveTables;

  for (var ti = 0; ti < tables.length; ti++) {
    var table = tables[ti];
    if (!liveTableSet[table]) continue;
    var schema = fieldCrypto.getSchema(table);
    if (!schema || !Array.isArray(schema.sealedFields) || schema.sealedFields.length === 0) continue;

    var totalRow = db.prepare('SELECT COUNT(*) AS n FROM "' + table.replace(/"/g, '""') + '"').get();
    var total = totalRow ? totalRow.n : 0;
    if (total === 0) continue;

    var sampleN = Math.max(sampleMin, Math.ceil(total * samplePct));
    if (sampleN > total) sampleN = total;

    // RANDOM() is fine for a sampler — we're picking representative rows,
    // not building cryptographic randomness.
    var sampled = db.prepare(
      'SELECT * FROM "' + table.replace(/"/g, '""') + '" ORDER BY RANDOM() LIMIT ?'
    ).all(sampleN);

    var foundOldFail = !oldKeys; // when no oldKeys supplied, this check is N/A
    var verifiedRows = 0;

    for (var r = 0; r < sampled.length; r++) {
      var row = sampled[r];
      var rowFailed = false;

      for (var sf = 0; sf < schema.sealedFields.length; sf++) {
        var col = schema.sealedFields[sf];
        var v = row[col];
        if (typeof v !== "string" || v.indexOf(VAULT_PREFIX) !== 0) continue;
        var payload = v.substring(VAULT_PREFIX.length);

        try { cryptoLib.decrypt(payload, keys); }
        catch (e) {
          rowFailed = true;
          failures.push({
            table:  table,
            column: col,
            _id:    row._id,
            error:  (e && e.message) || String(e),
          });
        }

        if (oldKeys && !foundOldFail) {
          try {
            cryptoLib.decrypt(payload, oldKeys);
            regressions.push({
              table:  table,
              column: col,
              _id:    row._id,
              error:  "old keys still decrypt this value — rotation did not take effect",
            });
          } catch (_e) {
            foundOldFail = true; // at least one row no longer decrypts under old keys → rotation effective
          }
        }
      }

      if (!rowFailed) verifiedRows++;
    }

    passed.push({ table: table, sampled: sampled.length, verified: verifiedRows });
  }

  return {
    ok:          failures.length === 0 && regressions.length === 0,
    passed:      passed,
    failures:    failures,
    regressions: regressions,
  };
}

module.exports = {
  validateSchemaMatch:    validateSchemaMatch,
  formatValidationResult: formatValidationResult,
  verify:                 verify,
  VaultRotateError:       VaultRotateError,
  // Constants exposed so operators / tests can reference the same defaults
  DEFAULT_DRIFT_SAMPLE_LIMIT: DEFAULT_DRIFT_SAMPLE_LIMIT,
  DEFAULT_VERIFY_SAMPLE_MIN:  DEFAULT_VERIFY_SAMPLE_MIN,
  DEFAULT_VERIFY_SAMPLE_FRAC: DEFAULT_VERIFY_SAMPLE_FRAC,
};
