// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.cryptoField.getSealedFields — the sealed-column accessor storage
 * backends consult to know which columns to wrap in vault.seal on write
 * and vault.unseal on read.
 *
 * Uses uniquely-named tables (no clearForTest) so the shared per-table
 * schema registry other smoke tests populate is left intact.
 *
 * Run standalone: `node test/layer-0-primitives/crypto-field.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testReturnsDeclaredSealedFields() {
  b.cryptoField.registerTable("cf_getsealed_patients", {
    sealedFields: ["ssn", "diagnosis"],
    derivedHashes: {
      ssnHash: { from: "ssn", normalize: function (s) { return String(s).replace(/-/g, ""); } },
    },
  });
  var fields = b.cryptoField.getSealedFields("cf_getsealed_patients");
  check("getSealedFields returns an array", Array.isArray(fields));
  check("getSealedFields returns exactly the declared sealed columns",
    fields.length === 2 && fields[0] === "ssn" && fields[1] === "diagnosis");

  // Agrees with the fuller getSchema() record's sealedFields.
  var schema = b.cryptoField.getSchema("cf_getsealed_patients");
  check("getSealedFields agrees with getSchema().sealedFields",
    JSON.stringify(schema.sealedFields) === JSON.stringify(fields));
}

function testUnregisteredTableIsEmpty() {
  // A table that was never registered → empty array (not null/undefined),
  // so a backend can iterate the result unconditionally.
  var fields = b.cryptoField.getSealedFields("cf_getsealed_never_registered");
  check("getSealedFields returns [] for an unregistered table",
    Array.isArray(fields) && fields.length === 0);
}

function testTableWithNoSealedColumns() {
  // A registered table that seals nothing → empty array.
  b.cryptoField.registerTable("cf_getsealed_public", { sealedFields: [] });
  var fields = b.cryptoField.getSealedFields("cf_getsealed_public");
  check("getSealedFields returns [] for a table sealing no columns",
    Array.isArray(fields) && fields.length === 0);
}

function testPreservesDeclarationOrder() {
  // The accessor preserves the operator's declared column order, which the
  // seal/unseal call sites depend on for stable column mapping.
  b.cryptoField.registerTable("cf_getsealed_order", {
    sealedFields: ["zeta", "alpha", "mu"],
  });
  var fields = b.cryptoField.getSealedFields("cf_getsealed_order");
  check("getSealedFields preserves declared column order",
    fields.join(",") === "zeta,alpha,mu");
}

function run() {
  testReturnsDeclaredSealedFields();
  testUnregisteredTableIsEmpty();
  testTableWithNoSealedColumns();
  testPreservesDeclarationOrder();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[crypto-field] OK"); }
  catch (e) { console.error(e); process.exit(1); }
}
