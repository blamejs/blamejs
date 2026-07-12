// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.cryptoField — sealed-column accessors + the seal / unseal seam.
 *
 * getSealedFields is the sealed-column accessor storage backends consult to
 * know which columns to wrap in vault.seal on write and vault.unseal on read.
 *
 * The seal/unseal seam tests drive the adversarial + defensive branches an
 * operator's data actually exercises: an empty-string sealed field (the three
 * envelope branches — plain / aad / K_row — must agree, never crash), the
 * type-fidelity codec (Buffer / object / array preserved through a sealed
 * column), the AAD cross-row / cross-column / cross-table copy-protection (a
 * relocated or tampered cell must be refused, not surfaced), and the
 * config-time refusals when the rowId term of the AAD binding is missing.
 *
 * Uses uniquely-named tables (no clearForTest) so the shared per-table schema
 * registry other smoke tests populate is left intact.
 *
 * Run standalone: `node test/layer-0-primitives/crypto-field.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs      = require("fs");
var os      = require("os");
var path    = require("path");
var { setupTestDb, teardownTestDb } = require("../helpers/db");

// Capture-or-value helper: returns { ok:true, value } when fn() returns, or
// { ok:false, err } when it throws — so a check can assert BOTH "did not throw"
// and "returned the right value" in one stable expression (a raw throw would
// otherwise abort the whole run before the assertion counts).
function _try(fn) {
  try { return { ok: true, value: fn() }; }
  catch (e) { return { ok: false, err: e }; }
}

// ---- getSealedFields accessor ----

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

// ---- seal / unseal seam (vault-backed, no db) ----

async function testSealUnsealSeams() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-seam-"));
  try {
    try { b.vault._resetForTest(); } catch (_e) { /* fresh init below */ }
    await b.vault.init({ dataDir: tmp, mode: "plaintext" });
    b.cryptoField.clearRateCapForTest();

    // --- empty-string sealed field: the three envelope branches must agree ---
    // vault.seal returns an empty string unchanged (falsy pass-through) and the
    // K_row branch encrypts an empty buffer fine, but vault.aad.seal REFUSES an
    // empty plaintext (throws vault-aad/bad-input). sealRow must not let that
    // divergence crash a write whose sealed column happens to hold "" — an
    // operator sealing a sometimes-empty column (notes / middleName) would
    // otherwise crash the insert only on aad tables.
    b.cryptoField.registerTable("cf_seam_aad_empty", {
      aad: true, sealedFields: ["secret"], rowIdField: "id",
    });
    var aadEmpty = _try(function () {
      var sealedEmpty = b.cryptoField.sealRow("cf_seam_aad_empty", { id: "r1", secret: "" });
      return b.cryptoField.unsealRow("cf_seam_aad_empty", sealedEmpty, "seam").secret;
    });
    check("aad table: an empty-string sealed field seals + round-trips to '' (no throw)",
      aadEmpty.ok === true && aadEmpty.value === "");

    // Plain + K_row branches agree on the same empty-string round-trip.
    b.cryptoField.registerTable("cf_seam_plain_empty", { sealedFields: ["secret"] });
    var plainEmpty = _try(function () {
      var sealedEmpty = b.cryptoField.sealRow("cf_seam_plain_empty", { secret: "" });
      return b.cryptoField.unsealRow("cf_seam_plain_empty", sealedEmpty, "seam").secret;
    });
    check("plain table: an empty-string sealed field round-trips to '' (no throw)",
      plainEmpty.ok === true && plainEmpty.value === "");

    // A null / undefined sealed field is still skipped (pre-existing contract).
    var nullField = b.cryptoField.sealRow("cf_seam_plain_empty", { secret: null });
    check("a null sealed field is left null (skipped, not sealed)", nullField.secret === null);

    // --- type-fidelity codec: Buffer / object / array / number / boolean ---
    b.cryptoField.registerTable("cf_seam_types", {
      sealedFields: ["blob", "obj", "arr", "num", "flag", "selfesc"],
    });
    var blob = Buffer.from([0, 1, 2, 250, 255]);   // non-ASCII bytes, no literals
    var sealedTypes = b.cryptoField.sealRow("cf_seam_types", {
      blob: blob,
      obj:  { a: 1, b: [2, 3], s: "x" },
      arr:  [1, "two", 3],
      num:  42,
      flag: false,
      selfesc: "\x00bjsv1:evil",   // a string that itself begins with the codec sentinel
    });
    check("a Buffer sealed field is stored as a vault: envelope",
      typeof sealedTypes.blob === "string" && sealedTypes.blob.indexOf("vault:") === 0);
    var readTypes = b.cryptoField.unsealRow("cf_seam_types", Object.assign({}, sealedTypes), "seam");
    check("a Buffer round-trips byte-for-byte through a sealed column",
      Buffer.isBuffer(readTypes.blob) && readTypes.blob.equals(blob));
    check("an object round-trips through a sealed column",
      readTypes.obj && JSON.stringify(readTypes.obj) === JSON.stringify({ a: 1, b: [2, 3], s: "x" }));
    check("an array round-trips through a sealed column",
      Array.isArray(readTypes.arr) && JSON.stringify(readTypes.arr) === JSON.stringify([1, "two", 3]));
    check("a number keeps the String() contract through a sealed column", readTypes.num === "42");
    check("a boolean keeps the String() contract through a sealed column", readTypes.flag === "false");
    check("a string that itself begins with the codec sentinel round-trips verbatim (self-escape)",
      readTypes.selfesc === "\x00bjsv1:evil");

    // --- AAD copy-protection: cross-row / cross-column / cross-table refusal ---
    // The confidentiality guarantee: a cell AEAD-bound to (table,row,column)
    // can NEVER be unsealed under a different context. A seam that surfaced a
    // relocated cell would be a copy-paste confidentiality break.
    b.cryptoField.registerTable("cf_seam_ctx", {
      aad: true, sealedFields: ["c1", "c2"], rowIdField: "id",
    });
    b.cryptoField.registerTable("cf_seam_ctx_other", {
      aad: true, sealedFields: ["c1"], rowIdField: "id",
    });
    var sealed = b.cryptoField.sealRow("cf_seam_ctx", { id: "rowA", c1: "secret-c1", c2: "secret-c2" });
    check("an aad cell is stored as a vault.aad: envelope",
      typeof sealed.c1 === "string" && sealed.c1.indexOf("vault.aad:") === 0);

    var okRead = b.cryptoField.unsealRow("cf_seam_ctx", Object.assign({}, sealed), "seam");
    check("the correct (table,row,column) context decrypts both cells",
      okRead.c1 === "secret-c1" && okRead.c2 === "secret-c2");

    // Relocate c1's ciphertext into column c2 (same row): AAD column term differs.
    var wrongCol = b.cryptoField.unsealRow("cf_seam_ctx", { id: "rowA", c2: sealed.c1 }, "seam");
    check("a cell relocated to a DIFFERENT column is refused (nulled, never surfaced)",
      wrongCol.c2 === null);

    // Relocate c1's ciphertext onto a different rowId: AAD rowId term differs.
    var wrongRow = b.cryptoField.unsealRow("cf_seam_ctx", { id: "rowB", c1: sealed.c1 }, "seam");
    check("a cell relocated to a DIFFERENT row is refused (nulled)", wrongRow.c1 === null);

    // Read the same cell through a DIFFERENT table: AAD table term differs.
    var wrongTable = b.cryptoField.unsealRow("cf_seam_ctx_other", { id: "rowA", c1: sealed.c1 }, "seam");
    check("a cell read through a DIFFERENT table is refused (nulled)", wrongTable.c1 === null);

    // --- tamper: a single flipped ciphertext char fails AEAD verification ---
    var tamperedCell = sealed.c1.slice(0, -1) + (sealed.c1.slice(-1) === "A" ? "B" : "A");
    var tampered = b.cryptoField.unsealRow("cf_seam_ctx",
      { id: "rowA", c1: tamperedCell, c2: sealed.c2 }, "seam");
    check("a tampered aad cell fails verification and is nulled (never surfaces plaintext)",
      tampered.c1 === null);
    check("an untampered sibling cell on the same row still decrypts",
      tampered.c2 === "secret-c2");

    // --- config-time refusals: the rowId term of the AAD binding is required ---
    var aadNoRowId = _try(function () {
      return b.cryptoField.sealRow("cf_seam_ctx", { c1: "x" });   // no id column
    });
    check("sealRow refuses an aad table when the rowId column is missing",
      aadNoRowId.ok === false && aadNoRowId.err &&
      aadNoRowId.err.code === "crypto-field/seal-row-aad-rowid-missing");

    var kRowNoRowId = _try(function () {
      // K_row seal with no rowId / _id — cannot build the (table,rowId,column) AAD.
      return b.cryptoField.sealRow("cf_seam_plain_empty", { secret: "v" }, { kRow: Buffer.alloc(32) });
    });
    check("sealRow refuses a K_row seal with no rowId",
      kRowNoRowId.ok === false && kRowNoRowId.err &&
      kRowNoRowId.err.code === "crypto-field/seal-row-krow-rowid-missing");

    b.cryptoField.clearRateCapForTest();
  } finally {
    try { b.vault._resetForTest(); } catch (_e) { /* leave vault state clean for siblings */ }
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

// ---- the REAL consumer path: b.db insert/read across envelope types ----

async function testConsumerPathEmptyAndKRow() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-seam-db-"));
  try {
    await setupTestDb(dir, [
      {
        name:    "cf_seam_aad_db",
        columns: { _id: "TEXT PRIMARY KEY", secret: "TEXT", note: "TEXT" },
        aad:     true,
        sealedFields: ["secret", "note"],
        rowIdField:   "_id",
      },
      {
        name:    "cf_seam_krow_db",
        columns: { _id: "TEXT PRIMARY KEY", subjectId: "TEXT", ssn: "TEXT" },
        sealedFields: ["ssn"],
        subjectField: "subjectId",
      },
    ]);
    b.cryptoField.clearResidencyForTest();
    b.cryptoField.declarePerRowKey("cf_seam_krow_db", { keySize: 32 });

    // aad table, real write boundary: an empty-string sealed field must not
    // crash the insert (the pre-fix vault.aad.seal("") throw surfaced here).
    var insAad = _try(function () {
      return b.db.from("cf_seam_aad_db").insertOne({ _id: "a1", secret: "", note: "present" });
    });
    check("b.db.insertOne on an aad table does NOT crash on an empty-string sealed field",
      insAad.ok === true);
    if (insAad.ok) {
      var gotA = b.db.from("cf_seam_aad_db").where({ _id: "a1" }).first();
      check("aad-table insert round-trips the empty sealed field to ''", gotA && gotA.secret === "");
      check("aad-table insert round-trips the non-empty sibling sealed field", gotA && gotA.note === "present");
    }

    // per-row-key table, real write boundary: empty-string field round-trips too.
    var insKRow = _try(function () {
      return b.db.from("cf_seam_krow_db").insertOne({ _id: "k1", subjectId: "s1", ssn: "" });
    });
    check("b.db.insertOne on a per-row-key table does NOT crash on an empty-string sealed field",
      insKRow.ok === true);
    if (insKRow.ok) {
      var gotK = b.db.from("cf_seam_krow_db").where({ _id: "k1" }).first();
      check("per-row-key insert round-trips the empty sealed field to ''", gotK && gotK.ssn === "");
    }

    // control: a non-empty aad value is stored as a vault.aad: envelope on disk
    // and round-trips — the empty-string fix does not weaken real sealing.
    b.db.from("cf_seam_aad_db").insertOne({ _id: "a2", secret: "top-secret", note: "n" });
    var rawA2 = b.db.prepare('SELECT "secret" AS s FROM "cf_seam_aad_db" WHERE _id = ?').get("a2");
    check("a non-empty aad sealed value is stored as a vault.aad: envelope on disk",
      rawA2 && typeof rawA2.s === "string" && rawA2.s.indexOf("vault.aad:") === 0);
    var gotA2 = b.db.from("cf_seam_aad_db").where({ _id: "a2" }).first();
    check("a non-empty aad sealed value round-trips through the real read path",
      gotA2 && gotA2.secret === "top-secret");
  } finally {
    try { b.cryptoField.clearResidencyForTest(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(dir);
  }
}

async function run() {
  testReturnsDeclaredSealedFields();
  testUnregisteredTableIsEmpty();
  testTableWithNoSealedColumns();
  testPreservesDeclarationOrder();
  await testSealUnsealSeams();
  await testConsumerPathEmptyAndKRow();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("[crypto-field] OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
