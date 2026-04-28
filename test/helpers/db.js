"use strict";
/**
 * Full-framework setup/teardown for tests that need a working DB +
 * vault + audit chain. setupTestDb wires plaintext vault + plain at-
 * rest storage so tests don't pay for sealed-disk ceremony; production
 * apps run with the secure defaults.
 */

var fs = require("fs");
var os = require("os");
var path = require("path");
var b = require("../../index.js");

async function setupTestDb(tmpDir, schemaOverrides) {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
  process.env.BLAMEJS_AUDIT_SIGNING_MODE = "plaintext";
  await b.db.init({
    dataDir: tmpDir,
    atRest:  "plain",
    schema:  schemaOverrides || [
      {
        name: "users",
        columns: {
          _id:       "TEXT PRIMARY KEY",
          email:     "TEXT",
          emailHash: "TEXT",
          name:      "TEXT",
          status:    "TEXT DEFAULT 'active'",
          createdAt: "TEXT",
        },
        indexes: ["emailHash", "status"],
        sealedFields:  ["email", "name"],
        derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
      },
    ],
  });
}

async function teardownTestDb(tmpDir) {
  // Drain audit handler buffered emissions BEFORE close so pending
  // rows land in audit_log rather than leaking into the next test's DB.
  try { await b.audit.flush(); } catch (_e) {}
  try { b.db.close(); } catch (_e) {}
  b.audit._resetForTest();
  b.db._resetForTest();
  b.vault._resetForTest();
  b.cluster._resetForTest();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
}

// Lightweight middleware-fixture setup: db boots with no app schema.
// For tests that don't need any app-level tables.
async function setupTestDbForMW() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mw-"));
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  process.env.BLAMEJS_AUDIT_SIGNING_MODE = "plaintext";
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
  await b.db.init({
    dataDir: tmpDir,
    atRest:  "plain",
    auditSigning: { mode: "plaintext" },
    schema:  [],
  });
  global._mwTmpDir = tmpDir;
}

function teardownMW() {
  try { b.db.close(); } catch (_e) {}
  b.db._resetForTest();
  b.vault._resetForTest();
  if (global._mwTmpDir) {
    try { fs.rmSync(global._mwTmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

module.exports = {
  setupTestDb:      setupTestDb,
  teardownTestDb:   teardownTestDb,
  setupTestDbForMW: setupTestDbForMW,
  teardownMW:       teardownMW,
};
