// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * vault.getCurrentPassphrase — returns the Buffer the vault was unsealed
 * with on this boot (wrapped mode), or null in plaintext mode.
 *
 * Uses the shared vault-only fixture (wrapped, Argon2id-derived AEAD wrap
 * with the test passphrase from BLAMEJS_VAULT_PASSPHRASE) and a direct
 * plaintext init for the null path.
 *
 * Run standalone: `node test/layer-0-primitives/vault.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b                 = helpers.b;
var fs                = helpers.fs;
var os                = helpers.os;
var path              = helpers.path;
var check             = helpers.check;
var setupVaultOnly    = helpers.setupVaultOnly;
var teardownVaultOnly = helpers.teardownVaultOnly;
var TEST_PASSPHRASE   = helpers.TEST_PASSPHRASE;

async function testGetCurrentPassphraseWrapped() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault-wrapped-"));
  await setupVaultOnly(tmpDir);
  try {
    check("vault mode is wrapped after fixture init", b.vault.getMode() === "wrapped");
    var pass = b.vault.getCurrentPassphrase();
    check("vault.getCurrentPassphrase returns a Buffer in wrapped mode",
          Buffer.isBuffer(pass));
    check("vault.getCurrentPassphrase Buffer decodes to the unseal passphrase",
          pass.toString("utf8") === TEST_PASSPHRASE);
  } finally {
    teardownVaultOnly(tmpDir);
  }
}

async function testGetCurrentPassphrasePlaintext() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault-plaintext-"));
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  b.vault._resetForTest();
  try {
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    check("vault mode is plaintext after plaintext init", b.vault.getMode() === "plaintext");
    check("vault.getCurrentPassphrase is null in plaintext mode",
          b.vault.getCurrentPassphrase() === null);
  } finally {
    b.vault._resetForTest();
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

function testGetCurrentPassphraseBeforeInit() {
  b.vault._resetForTest();
  check("vault.getCurrentPassphrase is null before init", b.vault.getCurrentPassphrase() === null);
}

// Unsealing derives the wrapping key with Argon2id, which now waits on the
// process-wide gate, so an unseal can fail because the gate is full rather than
// because the passphrase is wrong. The catch-all around the unwrap rewrote any
// error into `vault/unwrap-failed`, "passphrase rejected or sealed file
// corrupted" — the message that sends an operator to their backups — for an
// intact file and the right passphrase. Same shape on the wrap side.
async function testGateRefusalIsNotACorruptVault() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault-gate-"));
  await setupVaultOnly(tmpDir);
  var P = b.auth.password;
  var hold = null;
  try {
    var sealed = await b.vaultWrap.wrap("the-plaintext", TEST_PASSPHRASE, {
      memoryCost: b.constants.BYTES.kib(1), timeCost: 1, parallelism: 1,
    });
    check("the blob unwraps with the gate open",
      (await b.vaultWrap.unwrap(sealed, TEST_PASSPHRASE)).toString("utf8") === "the-plaintext");

    P.gate(1, { maxQueued: 0 });
    hold = P.hash("occupant", {
      memoryCost: b.constants.BYTES.kib(16), timeCost: 2, parallelism: 1,
    });
    var unwrapRefused = null;
    try { await b.vaultWrap.unwrap(sealed, TEST_PASSPHRASE); }
    catch (e) { unwrapRefused = e; }
    check("vaultWrap.unwrap raises the gate's refusal, not a corrupt-file error",
      unwrapRefused !== null && unwrapRefused.code === "argon2/busy",
      "code=" + (unwrapRefused && unwrapRefused.code) +
      " msg=" + (unwrapRefused && unwrapRefused.message));

    var wrapRefused = null;
    try {
      await b.vaultWrap.wrap("more", TEST_PASSPHRASE, {
        memoryCost: b.constants.BYTES.kib(1), timeCost: 1, parallelism: 1,
      });
    } catch (e) { wrapRefused = e; }
    check("and vaultWrap.wrap raises it too",
      wrapRefused !== null && wrapRefused.code === "argon2/busy",
      "code=" + (wrapRefused && wrapRefused.code));

    // `b.vault.init` is where it mattered: its catch-all rewrote whatever came
    // out of the unwrap into `vault/unwrap-failed`, so a boot-time unseal that
    // merely met a full gate reported the sealed file corrupted.
    var initRefused = null;
    process.env.BLAMEJS_VAULT_PASSPHRASE = TEST_PASSPHRASE;
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    try {
      b.vault._resetForTest();
      await b.vault.init({ dataDir: tmpDir, mode: "wrapped" });
    } catch (e) { initRefused = e; }
    check("vault.init surfaces the gate's refusal instead of reporting a corrupt file",
      initRefused !== null && initRefused.code === "argon2/busy",
      "code=" + (initRefused && initRefused.code) +
      " msg=" + String(initRefused && initRefused.message).slice(0, 120));

    await hold;
    hold = null;

    // The control: a genuinely wrong passphrase still reads as a wrong
    // passphrase, so the assertions above read the gate and not every failure.
    P.gate(8, { maxQueued: Infinity, waitTimeoutMs: 0 });
    var wrongPass = null;
    try { await b.vaultWrap.unwrap(sealed, "not-the-passphrase"); }
    catch (e) { wrongPass = e; }
    check("a wrong passphrase still fails as a rejected passphrase",
      wrongPass !== null && wrongPass.code !== "argon2/busy" &&
      /passphrase/i.test(wrongPass.message || ""),
      "code=" + (wrongPass && wrongPass.code) + " msg=" + (wrongPass && wrongPass.message));

    var initWrongPass = null;
    process.env.BLAMEJS_VAULT_PASSPHRASE = "not-the-passphrase-at-all";
    try {
      b.vault._resetForTest();
      await b.vault.init({ dataDir: tmpDir, mode: "wrapped" });
    } catch (e) { initWrongPass = e; }
    process.env.BLAMEJS_VAULT_PASSPHRASE = TEST_PASSPHRASE;
    check("and vault.init still reports a wrong passphrase as one",
      initWrongPass !== null && initWrongPass.code === "vault/unwrap-failed",
      "code=" + (initWrongPass && initWrongPass.code));
  } finally {
    if (hold !== null) { try { await hold; } catch (_e) { /* released below */ } }
    P.gate(8, { maxQueued: Infinity, waitTimeoutMs: 0 });
    teardownVaultOnly(tmpDir);
  }
}

async function run() {
  testGetCurrentPassphraseBeforeInit();
  await testGateRefusalIsNotACorruptVault();
  await testGetCurrentPassphraseWrapped();
  await testGetCurrentPassphrasePlaintext();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[vault] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
