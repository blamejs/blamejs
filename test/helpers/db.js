// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Full-framework setup/teardown for tests that need a working DB +
 * vault + audit chain.
 *
 * Tests run with the same secure modes operators use in production —
 * wrapped vault (Argon2id-derived AEAD wrap), encrypted at-rest db
 * (tmpfs working copy, sealed db.enc on durable disk), wrapped audit-
 * signing key. The earlier "plain mode for test speed" pattern hid
 * the same class of bug as feedback_test_to_security_not_security_to_test.md
 * warns about; the production path is what should be exercised.
 *
 * The test passphrase is hard-coded — these tests are local-only and
 * the surface that matters is wrap/unwrap behaviour, not passphrase
 * secrecy. Real deployments source it from BLAMEJS_VAULT_PASSPHRASE.
 */

var fs = require("fs");
var os = require("os");
var path = require("path");
var b = require("../../index.js");

var TEST_PASSPHRASE = "blamejs-test-passphrase-not-secret";

function _setTestEnv() {
  process.env.BLAMEJS_VAULT_PASSPHRASE         = TEST_PASSPHRASE;
  process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = TEST_PASSPHRASE;
  delete process.env.BLAMEJS_AUDIT_SIGNING_MODE;
}

// The init options every fixture opens with. One definition, so a reopen
// cannot drift from the original open — a reopen that differed in any of these
// would be testing a different database than the one the test built.
function _initOpts(tmpDir, schemaOverrides, extra) {
  var o = {
    dataDir: tmpDir,
    tmpDir:  path.join(tmpDir, "tmpfs"),
    // Test scratch dir is a plain directory, not a real tmpfs mount, and may
    // live under the repo-local .test-output (outside the /tmp heuristic) for
    // tests that corrupt their working file in place. Encrypted mode now
    // refuses a non-tmpfs tmpDir by default (v0.15.0); the fixture knowingly
    // uses one, so opt out explicitly.
    allowNonTmpfsTmpDir: true,
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
  };
  if (extra) Object.keys(extra).forEach(function (k) { o[k] = extra[k]; });
  return o;
}

async function setupTestDb(tmpDir, schemaOverrides) {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  _setTestEnv();
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  await b.db.init(_initOpts(tmpDir, schemaOverrides));
}

// Close and open the SAME data directory again — what an operator restarting
// the process does. Distinct from teardown-then-setup, which removes the
// directory and hands back an empty database: a test that checks a boot
// against one of those passes without ever loading the state it means to test.
// Anything that only goes wrong on the second open (state written by the first
// run, subsystem ordering at startup) is invisible without this.
async function reopenTestDb(tmpDir, schemaOverrides, initExtras) {
  try { await b.audit.flush(); } catch (_e) { /* best-effort drain */ }
  try { b.db.close(); } catch (_e) { /* best-effort close */ }
  b.audit._resetForTest();
  b.db._resetForTest();
  b.vault._resetForTest();
  b.cluster._resetForTest();
  _setTestEnv();
  await b.vault.init({ dataDir: tmpDir });
  await b.db.init(_initOpts(tmpDir, schemaOverrides, initExtras));
}

async function teardownTestDb(tmpDir) {
  // Drain audit handler buffered emissions BEFORE close so pending
  // rows land in audit_log rather than leaking into the next test's DB.
  try { await b.audit.flush(); } catch (_e) {}
  // Anchor the final checkpoint synchronously while this db is still open, so
  // close()'s own fire-and-forget checkpoint no-ops (skipIfUnchanged) and no
  // detached checkpoint promise straddles the db boundary into the next test.
  try { await b.audit.checkpoint({ skipIfUnchanged: true }); } catch (_e) {}
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
  _setTestEnv();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  await b.db.init({
    dataDir: tmpDir,
    tmpDir:  path.join(tmpDir, "tmpfs"),
    // Plain scratch directory, not a real tmpfs mount — opt out of the
    // v0.15.0 encrypted-mode non-tmpfs refusal for the test fixture.
    allowNonTmpfsTmpDir: true,
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

// setupVaultOnly — minimal vault.init for tests that exercise primitives
// keyed off the vault master (b.agent.tenant.derivedKey,
// b.agent.postureChain envelope MAC, b.agent.orchestrator salted FNV,
// b.agent.snapshot signer/sealer). No db / audit-chain bootstrap, so
// teardown is also lightweight.
async function setupVaultOnly(tmpDir) {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  _setTestEnv();
  b.vault._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  // Flush memoized salt / MAC keys so a vault re-init between tests
  // forces re-derivation under the new keypair.
  if (b.agent && b.agent.orchestrator && b.agent.orchestrator._resetForTest) {
    b.agent.orchestrator._resetForTest();
  }
  if (b.agent && b.agent.postureChain && b.agent.postureChain._resetForTest) {
    b.agent.postureChain._resetForTest();
  }
}

function teardownVaultOnly(tmpDir) {
  b.vault._resetForTest();
  if (b.agent && b.agent.orchestrator && b.agent.orchestrator._resetForTest) {
    b.agent.orchestrator._resetForTest();
  }
  if (b.agent && b.agent.postureChain && b.agent.postureChain._resetForTest) {
    b.agent.postureChain._resetForTest();
  }
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
}

module.exports = {
  setupTestDb:       setupTestDb,
  reopenTestDb:      reopenTestDb,
  teardownTestDb:    teardownTestDb,
  setupTestDbForMW:  setupTestDbForMW,
  teardownMW:        teardownMW,
  setupVaultOnly:    setupVaultOnly,
  teardownVaultOnly: teardownVaultOnly,
  // Exported so tests that close + re-open the vault (persistence,
  // schema-evolution) can re-supply the passphrase. The framework's
  // passphrase source strips env after reading (security feature),
  // so each fresh vault.init needs a fresh env set.
  setTestPassphraseEnv: _setTestEnv,
  TEST_PASSPHRASE:      TEST_PASSPHRASE,
};
