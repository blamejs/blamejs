"use strict";
/**
 * b.cryptoField per-row key (K_row) crypto-shred substrate.
 *
 * declarePerRowKey opts a table into per-row keying. On INSERT the write
 * boundary materializes a fresh CSPRNG row-secret, derives K_row from it,
 * stores the SECRET (never K_row) AAD-sealed in _blamejs_per_row_keys, and
 * seals the row's sealed columns under K_row as vault.row: cells. Reads
 * fetch + unwrap the secret, re-derive K_row, and decrypt. Destroying the
 * wrapped secret (b.subject.eraseHard / b.retention) leaves WAL / replica
 * residual ciphertext mathematically undecryptable — the crypto-shred.
 *
 * Regression for the v0.14.25 critical class:
 *   - pre-fix K_row derived from the PLAINTEXT-on-disk derivedHash salt,
 *     so an attacker with disk access re-derived it and deleting the wrap
 *     shred NOTHING. The row-secret is now random.
 *   - pre-fix the wrap was sealed WITHOUT AAD despite a copy-protection
 *     claim. The wrap + the cells are now AAD-bound to (table, rowId,
 *     column, schemaVersion).
 *   - pre-fix materializePerRowKey was NEVER called on INSERT (dead
 *     surface). It is now wired at the db-query write boundary.
 *
 * Pins: materialize-rowId == destroy-rowId == _id; the residency-tag
 * column is NEVER K_row-sealed; a copied cell fails Poly1305; a vault
 * keypair rotation reseals the wrapped secret old-root -> new-root.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var fs     = require("fs");
var os     = require("os");
var path   = require("path");
var check  = helpers.check;
var { setupTestDb, teardownTestDb } = require("../helpers/db");

var ROW_PREFIX = require("../../lib/constants").ROW_PREFIX;

// App table opted into per-row keying. `subjectId` is the plaintext
// subject column eraseHard matches on; `dataRegion` is the plaintext
// residency tag (declarePerRowResidency) that must NEVER be K_row-sealed;
// `ssn` / `note` are the sealed columns that become vault.row: cells.
var KEYED_SCHEMA = [{
  name: "pr_keyed",
  columns: {
    _id:        "TEXT PRIMARY KEY",
    subjectId:  "TEXT",
    dataRegion: "TEXT",
    ssn:        "TEXT",
    note:       "TEXT",
  },
  indexes: ["subjectId"],
  sealedFields: ["ssn", "note"],
  subjectField: "subjectId",
}];

function _perRowKeyCount(rowId) {
  var row = b.db.prepare(
    'SELECT COUNT(*) AS n FROM "_blamejs_per_row_keys" WHERE tableName = ? AND rowId = ?'
  ).get("pr_keyed", rowId);
  return row ? row.n : 0;
}

function _rawCell(rowId, col) {
  var row = b.db.prepare('SELECT "' + col + '" AS v FROM "pr_keyed" WHERE _id = ?').get(rowId);
  return row ? row.v : null;
}

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-prk-"));
  try {
    await setupTestDb(dir, KEYED_SCHEMA);
    b.cryptoField.clearResidencyForTest();
    b.cryptoField.declarePerRowKey("pr_keyed", { keySize: 32 });
    b.cryptoField.declarePerRowResidency("pr_keyed", {
      residencyColumn: "dataRegion",
      allowedTags:     ["eu", "us", "global"],
    });
    check("hasPerRowKey true after declare", b.cryptoField.hasPerRowKey("pr_keyed") === true);

    // ---- INSERT: materialize + K_row-seal at the write boundary ----
    var inserted = b.db.from("pr_keyed").insertOne({
      _id: "row-1", subjectId: "subj-A", dataRegion: "eu", ssn: "123-45-6789", note: "patient note one",
    });
    check("insertOne returns plaintext _id", inserted._id === "row-1");

    // A _blamejs_per_row_keys entry appears for this row's _id.
    check("per-row-keys registry row created for _id", _perRowKeyCount("row-1") === 1);

    // The stored wrapped secret is AAD-sealed (vault.aad: prefix).
    var wrapRow = b.db.prepare(
      'SELECT wrappedKey FROM "_blamejs_per_row_keys" WHERE tableName = ? AND rowId = ?'
    ).get("pr_keyed", "row-1");
    check("wrapped secret stored AAD-sealed (vault.aad:)",
      typeof wrapRow.wrappedKey === "string" && wrapRow.wrappedKey.indexOf("vault.aad:") === 0);

    // Sealed columns on disk carry the vault.row: prefix (K_row cells) —
    // asserted via the public b.cryptoField.isRowSealed primitive.
    check("ssn column is a vault.row: cell", b.cryptoField.isRowSealed(_rawCell("row-1", "ssn")));
    check("note column is a vault.row: cell", b.cryptoField.isRowSealed(_rawCell("row-1", "note")));
    check("ROW_PREFIX is the vault.row: envelope isRowSealed detects",
      String(_rawCell("row-1", "ssn")).indexOf(ROW_PREFIX) === 0);

    // PIN: the residency-tag column stays plaintext (never K_row-sealed);
    // isRowSealed is false for a plaintext cell.
    check("residency tag column stays plaintext", _rawCell("row-1", "dataRegion") === "eu");
    check("isRowSealed false for the plaintext residency tag",
      b.cryptoField.isRowSealed(_rawCell("row-1", "dataRegion")) === false);

    // ---- READ: round-trips to plaintext ----
    var got = b.db.from("pr_keyed").where({ _id: "row-1" }).first();
    check("read round-trips ssn", got.ssn === "123-45-6789");
    check("read round-trips note", got.note === "patient note one");
    check("read surfaces residency tag verbatim", got.dataRegion === "eu");

    // all() path round-trips too.
    var all = b.db.from("pr_keyed").where({ subjectId: "subj-A" }).all();
    check("all() round-trips one keyed row", all.length === 1 && all[0].ssn === "123-45-6789");

    // ---- COPY-ROW ATTACK: paste another row's cell ----
    b.db.from("pr_keyed").insertOne({
      _id: "row-2", subjectId: "subj-B", dataRegion: "us", ssn: "999-88-7777", note: "patient note two",
    });
    var row2Ssn = _rawCell("row-2", "ssn");   // a valid vault.row: cell, but bound to row-2
    // Overwrite row-1's ssn cell with row-2's ciphertext via raw SQL (a
    // DB-write attacker). row-1's K_row + AAD differ, so Poly1305 fails.
    b.db.prepare('UPDATE "pr_keyed" SET "ssn" = ? WHERE _id = ?').run(row2Ssn, "row-1");
    var tampered = b.db.from("pr_keyed").where({ _id: "row-1" }).first();
    check("copied cell from another row fails to decrypt (null)", tampered.ssn === null);
    check("untouched cell on the same row still decrypts", tampered.note === "patient note one");
    // Restore a valid row-1 ssn cell for the erase/rotation phases.
    b.db.from("pr_keyed").where({ _id: "row-1" }).updateOne({ ssn: "123-45-6789" });
    check("re-seal under K_row round-trips after update",
      b.db.from("pr_keyed").where({ _id: "row-1" }).first().ssn === "123-45-6789");

    // ---- ERASE-HARD: crypto-shred ----
    var result = b.subject.eraseHard("subj-A", {
      reason: "test-crypto-shred",
      acknowledgements: ["no-litigation-hold", "no-statutory-retention-required"],
    });
    check("eraseHard destroyed 1 per-row key", result.perRowKeysDestroyed === 1);
    check("eraseHard deleted the row", result.perTable.pr_keyed === 1);
    check("per-row-keys registry row gone after shred", _perRowKeyCount("row-1") === 0);
    // The row itself was DELETEd by eraseHard; assert the wrapped secret
    // is gone (the residual-ciphertext shred). A post-shred re-insert of
    // the SAME _id would mint a NEW random secret — the old WAL cell would
    // never decrypt under it.
    check("subj-B row still present + decrypts (shred is row-scoped)",
      b.db.from("pr_keyed").where({ _id: "row-2" }).first().ssn === "999-88-7777");

    // ---- POST-DESTROY read-absent: a vault.row: cell with no wrap ----
    // Re-create a wrap-less keyed cell: insert, then destroy ONLY its
    // wrapped secret (simulating WAL residue after shred). The read must
    // null the field, not crash.
    b.db.from("pr_keyed").insertOne({
      _id: "row-3", subjectId: "subj-C", dataRegion: "global", ssn: "111-22-3333", note: "n3",
    });
    b.cryptoField.destroyPerRowKey("pr_keyed", "row-3", b.db);
    check("destroyPerRowKey removed the wrap", _perRowKeyCount("row-3") === 0);
    var shredded = b.db.from("pr_keyed").where({ _id: "row-3" }).first();
    check("shredded cell reads as absent (null), no crash", shredded.ssn === null && shredded.note === null);

    await teardownTestDb(dir);

    // ---- ROTATION ROUND-TRIP ----
    await _rotationRoundTrip();
  } finally {
    try { b.cryptoField.clearResidencyForTest(); } catch (_e) {}
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
  console.log("OK — crypto-field per-row-key tests");
}

// A vault keypair rotation must reseal the wrapped row-secret in
// _blamejs_per_row_keys old-root -> new-root (registerTable({aad:true})
// wires rotate._rotateColumn). After the swap, the wrap unwraps under the
// new root, K_row re-derives, and a vault.row: data cell still decrypts.
async function _rotationRoundTrip() {
  var dirNew  = fs.mkdtempSync(path.join(os.tmpdir(), "prk-vr-new-"));
  var dirA    = fs.mkdtempSync(path.join(os.tmpdir(), "prk-vr-a-"));
  var staging = path.join(os.tmpdir(), "prk-vr-stg-" + process.pid + "-" + Date.now());

  async function _reset() {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    b.cluster._resetForTest();
    b.audit._resetForTest();
    b.vault._resetForTest();
    b.db._resetForTest();
  }

  try {
    // Fresh keypair to rotate INTO.
    await _reset();
    await b.vault.init({ dataDir: dirNew, mode: "plaintext" });
    var newKeys = JSON.parse(b.vault.getKeysJson());
    b.vault._resetForTest();

    // Live deployment with a per-row-key table + one keyed row.
    await _reset();
    await b.vault.init({ dataDir: dirA, mode: "plaintext" });
    var oldKeys = JSON.parse(b.vault.getKeysJson());
    check("rotation: old and new keypairs differ",
      JSON.stringify(oldKeys) !== JSON.stringify(newKeys));
    await b.db.init({
      dataDir: dirA, tmpDir: path.join(dirA, "tmpfs"), atRest: "encrypted",
      auditSigning: false, schema: KEYED_SCHEMA,
    });
    b.cryptoField.clearResidencyForTest();
    b.cryptoField.declarePerRowKey("pr_keyed", { keySize: 32 });
    b.cryptoField.declarePerRowResidency("pr_keyed", {
      residencyColumn: "dataRegion", allowedTags: ["eu", "us", "global"],
    });

    b.db.from("pr_keyed").insertOne({
      _id: "rot-1", subjectId: "s1", dataRegion: "eu", ssn: "555-44-3333", note: "rotate me",
    });
    check("rotation: keyed cell sealed as vault.row:",
      String(_rawCell("rot-1", "ssn")).indexOf(ROW_PREFIX) === 0);
    await b.db.flushToDisk();
    await b.db.close();

    // Rotate the keypair old -> new. externalAadResealed:true: this
    // deployment uses none of the operator-supplied external AAD stores.
    var rot = await b.vaultRotate.rotate({
      dataDir: dirA, stagingDir: staging, oldKeys: oldKeys, newKeys: newKeys,
      mode: "plaintext", externalAadResealed: true,
    });
    check("rotation: internal verify ok (AAD cells decrypt under new root)",
      !!rot.verifyResult && rot.verifyResult.ok === true);
    check("rotation: processed at least the wrapped-secret + the data cell",
      rot.totalRowsProcessed >= 1);

    // Swap staging -> dataDir, re-open under the NEW keypair.
    ["db.enc", "db.key.enc", "vault.key"].forEach(function (f) {
      var s = path.join(staging, f);
      if (fs.existsSync(s)) fs.copyFileSync(s, path.join(dirA, f));
    });
    try { fs.rmSync(path.join(dirA, "tmpfs"), { recursive: true, force: true }); } catch (_e) {}

    await _reset();
    await b.vault.init({ dataDir: dirA, mode: "plaintext" });
    check("rotation: vault now live under the NEW keypair",
      JSON.stringify(JSON.parse(b.vault.getKeysJson())) === JSON.stringify(newKeys));
    await b.db.init({
      dataDir: dirA, tmpDir: path.join(dirA, "tmpfs"), atRest: "encrypted",
      auditSigning: false, schema: KEYED_SCHEMA,
    });
    b.cryptoField.clearResidencyForTest();
    b.cryptoField.declarePerRowKey("pr_keyed", { keySize: 32 });
    b.cryptoField.declarePerRowResidency("pr_keyed", {
      residencyColumn: "dataRegion", allowedTags: ["eu", "us", "global"],
    });

    var got = b.db.from("pr_keyed").where({ _id: "rot-1" }).first();
    check("rotation: vault.row: cell decrypts after rotation under the new keypair",
      !!got && got.ssn === "555-44-3333" && got.note === "rotate me");
    await b.db.close();
  } finally {
    await _reset();
    try { b.cryptoField.clearResidencyForTest(); } catch (_e) {}
    [dirNew, dirA, staging].forEach(function (d) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch (_e) {}
    });
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
