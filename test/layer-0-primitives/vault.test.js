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

// A full gate refuses with `argon2/busy`, which is transient and which
// b.retry.isRetryable accepts, so the refusal invites the operator to call
// init again. The passphrase source read BLAMEJS_VAULT_PASSPHRASE with
// strip: true before the derivation ran, so by the time the refusal arrived
// the variable was gone and the retry the refusal invited could not find a
// passphrase at all. The unseal path and the first-run create path resolve
// the passphrase the same way, so both are driven here. The assertion is
// that the retry PROCEEDS, deliberately not that the variable survives: the
// variable is one way to make the retry work and not the only one.
async function testATransientRefusalLeavesTheRetryAbleToProceed() {
  var P = b.auth.password;
  var HOLD = { memoryCost: b.constants.BYTES.kib(16), timeCost: 2, parallelism: 1 };

  async function _refuseThenRetry(label, tmpDir) {
    var hold = null;
    try {
      process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
      process.env.BLAMEJS_VAULT_PASSPHRASE = TEST_PASSPHRASE;
      b.vault._resetForTest();

      P.gate(1, { maxQueued: 0 });
      hold = P.hash("occupant", HOLD);

      var refused = null;
      try { await b.vault.init({ dataDir: tmpDir, mode: "wrapped" }); }
      catch (e) { refused = e; }
      check(label + ": a full gate refuses with argon2/busy",
        refused !== null && refused.code === "argon2/busy",
        "code=" + (refused && refused.code));
      check(label + ": and the refusal is one b.retry would retry",
        refused !== null && b.retry.isRetryable(refused) === true);

      await hold;
      hold = null;
      P.gate(8, { maxQueued: Infinity, waitTimeoutMs: 0 });

      // The retry the refusal invited. The operator sets nothing again:
      // their environment is exactly as they left it.
      var retryThrew = null;
      try { await b.vault.init({ dataDir: tmpDir, mode: "wrapped" }); }
      catch (e) { retryThrew = e; }
      check(label + ": the retry proceeds once the gate is free",
        retryThrew === null,
        "code=" + (retryThrew && retryThrew.code) +
        " msg=" + String(retryThrew && retryThrew.message).slice(0, 120));
      check(label + ": and the vault is usable after it",
        retryThrew === null && b.vault.getMode() === "wrapped");
    } finally {
      if (hold !== null) { try { await hold; } catch (_e) { /* released below */ } }
      P.gate(8, { maxQueued: Infinity, waitTimeoutMs: 0 });
    }
  }

  // The unseal path: a sealed vault already on disk.
  var sealedDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault-retry-unseal-"));
  await setupVaultOnly(sealedDir);
  try {
    await _refuseThenRetry("unseal", sealedDir);
  } finally {
    teardownVaultOnly(sealedDir);
  }

  // The first-run create path: nothing on disk yet, so init generates and
  // wraps the keypair. It resolves the passphrase through the same source.
  var freshDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault-retry-create-"));
  try {
    await _refuseThenRetry("first-run create", freshDir);
  } finally {
    teardownVaultOnly(freshDir);
  }
}

// Consumers zero the buffer they were handed — audit-sign does it at three
// sites, and vault's test reset does it to currentPassphrase. What the source
// keeps for a retry has to survive that, or the retry derives from a buffer of
// zeros and reports a wrong passphrase for a passphrase that was right.
async function testZeroingAReadPassphraseDoesNotZeroWhatTheRetryWillUse() {
  var source = require("../../lib/vault/passphrase-source");
  var VAR = "BLAMEJS_TEST_HELD_PASSPHRASE";
  var plain = { envVars: { value: VAR, file: VAR + "_FILE", source: VAR + "_SOURCE" } };
  var opts = Object.assign({ _holdForRetry: true }, plain);
  try {
    // A caller that has not asked for the retry window keeps today's
    // behavior: the variable is consumed and no copy outlives the buffer it
    // was handed, so its own zeroing is the end of the secret.
    process.env[VAR] = "a-standalone-read";
    var standalone = await source.fromEnv(plain);
    check("a plain read returns the variable's bytes",
      standalone.toString("utf8") === "a-standalone-read");
    b.safeBuffer.secureZero(standalone);
    var noHeldCopy = null;
    try { await source.fromEnv(plain); } catch (e) { noHeldCopy = e; }
    check("  and leaves nothing behind for a second read to find",
      noHeldCopy !== null, "a second read resolved from a retained copy");
    check("  with no source left to resolve",
      source.sourceKind(plain) !== "env", "kind=" + source.sourceKind(plain));
    // Asked with the retry window on, which is what would see a copy if one
    // had been kept: the read gate alone would hide an unconditional store.
    check("  and no copy was stored for anyone to find",
      source.sourceKind(opts) !== "env", "kind=" + source.sourceKind(opts));

    process.env[VAR] = "the-correct-passphrase";
    var first = await source.fromEnv(opts);
    check("fromEnv returns the variable's bytes",
      first.toString("utf8") === "the-correct-passphrase");
    check("  and strips the variable from the environment",
      process.env[VAR] === undefined);

    // What every consumer does with it once the derivation is done.
    b.safeBuffer.secureZero(first);

    var second = await source.fromEnv(opts);
    check("a retry after the variable was consumed still reads the passphrase",
      second.toString("utf8") === "the-correct-passphrase",
      "got=" + JSON.stringify(second.toString("utf8")));

    // A corrected variable has to win over what is held, or an operator who
    // fixes a typo keeps deriving from the wrong bytes.
    process.env[VAR] = "the-corrected-passphrase";
    var third = await source.fromEnv(opts);
    check("a variable set again overrides the held passphrase",
      third.toString("utf8") === "the-corrected-passphrase",
      "got=" + JSON.stringify(third.toString("utf8")));
  } finally {
    source._clearHeldEnvPassphrase(VAR);
    delete process.env[VAR];
  }
}

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
  await testATransientRefusalLeavesTheRetryAbleToProceed();
  await testZeroingAReadPassphraseDoesNotZeroWhatTheRetryWillUse();
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
